"""
Aegis SOAR Playbook Executor
============================
Executes containment actions, preserves evidence, logs audit trails, and pushes
decisions, alerts, and detailed AI analysis to the SOC Dashboard.
"""

import json
import logging
import time
import uuid
import requests
from config import DASHBOARD_API_URL, AEGIS_INTERNAL_TOKEN

logger = logging.getLogger("soar-engine.executor")


class PlaybookExecutor:
    """Executes SOAR playbook response actions and syncs with the SOC dashboard."""

    def __init__(self):
        self.headers = {
            "Content-Type": "application/json",
            "X-Aegis-Internal-Key": AEGIS_INTERNAL_TOKEN
        }
        # Initialize interfaces for guardrails
        try:
            from config import REDIS_URL
            from rate_limiter import RedisTokenBucketRateLimiter
            self.rate_limiter = RedisTokenBucketRateLimiter(redis_url=REDIS_URL)
        except Exception:
            self.rate_limiter = None

        try:
            from policy_evaluator import OpaPolicyEvaluator
            self.policy_evaluator = OpaPolicyEvaluator()
        except Exception:
            self.policy_evaluator = None

    def execute_decision(self, decision: dict) -> None:
        """
        Processes a Layer 2 decision, executes containment/floor actions,
        publishes a SecurityEvent, and pushes detailed analysis to the dashboard.
        """
        logger.info(f"Executing L2 Orchestrator Decision for incident: {decision['input_summary'].get('incident_id')}")

        # 1. Generate unique event ID for dashboard correlation
        event_uuid = str(uuid.uuid4())
        short_id = event_uuid[:8]

        # 2. Extract key entities
        verified_case = decision.get("verified_case", {})
        entities = verified_case.get("entities", {})
        ips = entities.get("ips", [])
        source_ip = ips[0] if ips else "127.0.0.1"
        
        # 3. Determine if Auto-Containment Gate is active
        autopilot_active = decision.get("automation_control", {}).get("soc_autopilot_enabled", False)
        execution_window_ok = decision.get("automation_control", {}).get("execution_window", {}).get("in_window", False)
        eligible = decision.get("automation_control", {}).get("auto_containment_eligible", False)
        
        should_execute_containment = autopilot_active and execution_window_ok and eligible
        logger.info(f"Containment execution policy: autopilot={autopilot_active}, window={execution_window_ok}, eligible={eligible} -> execute={should_execute_containment}")

        # 4. Process and execute actions
        actions = decision.get("actions", [])
        executed_actions_summary = []
        suggested_actions_summary = []

        for action in actions:
            action_type = action.get("action_type")
            target = action.get("target", {})
            target_value = target.get("value_masked")
            phase = action.get("phase")
            approval_mode = action.get("approval_mode")

            # Determine whether to run or suggest
            if phase in ("preserve", "hunt", "notify"):
                # Non-disruptive actions are always executed.
                run_action = True
            elif phase == "contain" or action_type in ("block_ip", "block_domain", "quarantine_host", "disable_account"):
                # Containment executes only if the automation gates pass.
                run_action = approval_mode == "AUTO" and should_execute_containment
            else:
                run_action = approval_mode == "AUTO"

            if run_action:
                # Apply safety gate checks
                from safety_gate import evaluate_action_safety, acquire_action_rate_limits, verify_action_authorization
                allowed, reason = evaluate_action_safety(self.policy_evaluator, action, decision)
                if not allowed:
                    logger.error(f"[LEGACY EXECUTOR SAFETY BLOCKED] {action_type} on {target_value}: {reason}")
                    action["status"] = "failed"
                    action["rationale"] = f"{action.get('rationale', '')} | Blocked by Safety Gate: {reason}"
                    continue
                verified, verify_reason = verify_action_authorization(self.policy_evaluator, action, decision)
                if not verified:
                    logger.critical(f"[OPA TOCTOU BLOCKED] {action_type} on {target_value}: {verify_reason}")
                    action["status"] = "failed"
                    continue

                is_dry_run = decision.get("dry_run", False)
                if not is_dry_run:
                    rate_allowed, rate_reason = acquire_action_rate_limits(self.rate_limiter, action, timeout_seconds=15.0)
                    if not rate_allowed:
                        logger.error(f"[LEGACY EXECUTOR RATE LIMIT BLOCKED] {action_type} on {target_value}: {rate_reason}")
                        action["status"] = "failed"
                        action["rationale"] = f"{action.get('rationale', '')} | Rate Limiter Timeout"
                        continue

                # Translate SOAR action to Dashboard action
                dashboard_action_type = self._map_action_type(action_type)
                
                # Execute action via Dashboard API
                success, details = self._call_dashboard_perform_action(
                    actor="SOAR Engine",
                    action_type=dashboard_action_type,
                    target=target_value,
                    message=action.get("rationale", "")
                )
                
                if success:
                    action["status"] = "executed"
                    executed_actions_summary.append(f"{action_type} on {target_value}")
                    logger.info(f"Executed action: {action_type} on {target_value}")
                else:
                    action["status"] = "failed"
                    logger.error(f"Failed to execute action: {action_type} on {target_value}: {details}")
            else:
                action["status"] = "suggested"
                suggested_actions_summary.append(f"{action_type} on {target_value}")
                logger.info(f"Suggested action (requires approval): {action_type} on {target_value}")

        # Update lists in the decision dict
        decision["output_and_notification"]["executed_actions"] = executed_actions_summary
        decision["output_and_notification"]["suggested_actions"] = suggested_actions_summary

        # 5. Create a SecurityEvent payload and publish to Kafka (via caller main.py)
        # This will register as an alert on the dashboard.
        security_status = "BLOCKED" if should_execute_containment else "DETECTED"
        
        # We return the event payload to let main.py publish it to Kafka
        event_payload = {
            "eventId": event_uuid,
            "timestamp": decision.get("timestamp"),
            "attackType": verified_case.get("title", "SOC Security Incident"),
            "endpoint": entities.get("api_endpoints", ["/"])[0] if entities.get("api_endpoints") else "/",
            "payload": verified_case.get("summary", ""),
            "status": security_status,
            "clientIp": source_ip,
            "description": f"Risk Score: {decision['scoring'].get('final_risk_score_0_10')} - {decision['decision'].get('justification')}",
            "sourceService": "SOAR-Engine"
        }

        # 6. Push AI Analysis Details to Go Dashboard in background
        # Since Kafka consumption is async, we wait 2 seconds for the Go consumer to ingest the event and generate the alert
        # then we query the alerts API, find the alert ID, and post the L2 analysis report
        self._async_push_analysis(short_id, decision, event_uuid)

        # 7. Push full L2 decision payload to internal SOAR gateway
        self._push_l2_decision_to_gateway(decision)

        return event_payload

    def _push_l2_decision_to_gateway(self, decision: dict) -> None:
        """Pushes the full L2 decision payload to the internal SOAR gateway."""
        from config import DASHBOARD_API_URL
        url = f"{DASHBOARD_API_URL}/internal/soar/decision"
        try:
            logger.info(f"Pushing full L2 Decision payload to internal SOAR gateway: {url}")
            res = requests.post(url, headers=self.headers, json=decision, timeout=10)
            if res.status_code == 200:
                logger.info(f"Successfully pushed L2 Decision to internal gateway. Response: {res.json()}")
            else:
                logger.error(f"Failed to push L2 Decision to gateway. HTTP {res.status_code}: {res.text}")
        except Exception as e:
            logger.error(f"Error pushing L2 Decision to gateway: {e}")

    def _map_action_type(self, soar_action: str) -> str:
        mapping = {
            "block_ip": "Block IP",
            "quarantine_host": "Isolate Host",
            "force_logout": "Force Logout",
            "disable_account": "Revoke Credentials",
            "limit_network": "Isolate Host",
            "deploy_waf_rule": "Deploy WAF Rule",
            "deploy_waf_virtual_patch": "Deploy WAF Rule",
            "preserve_logs": "Preserve Logs",
            "open_ticket": "Open Ticket",
            "notify_soc": "Notify SOC"
        }
        return mapping.get(soar_action, "Other Action")

    def _call_dashboard_perform_action(self, actor: str, action_type: str, target: str, message: str) -> tuple:
        url = f"{DASHBOARD_API_URL}/actions"
        payload = {
            "actor": actor,
            "actionType": action_type,
            "target": target,
            "message": message
        }
        try:
            res = requests.post(url, headers=self.headers, json=payload, timeout=5)
            if res.status_code == 200:
                return True, "Success"
            return False, f"HTTP {res.status_code}: {res.text}"
        except Exception as e:
            return False, str(e)

    def _async_push_analysis(self, short_id: str, decision: dict, event_uuid: str):
        """Finds the generated alert on the dashboard and pushes the AI analysis."""
        import threading

        def worker():
            time.sleep(3)  # Wait for Go consumer to insert alert
            url_alerts = f"{DASHBOARD_API_URL}/alerts"
            
            alert_id = None
            try:
                # Query recent alerts to find the one matching our rule or event_uuid
                res = requests.get(url_alerts, headers=self.headers, timeout=5)
                if res.status_code == 200:
                    alerts = res.json()
                    expected_rule_id = f"rule-kafka-{short_id}"
                    
                    for a in alerts:
                        if a.get("ruleId") == expected_rule_id or event_uuid in a.get("rawLog", ""):
                            alert_id = a.get("id")
                            break
            except Exception as e:
                logger.error(f"Failed to query alerts from dashboard: {e}")

            if not alert_id:
                logger.warning(f"Could not correlate alert ID for ruleId rule-kafka-{short_id}. AI Analysis detail not posted.")
                return

            # Format AIAnalysis structure matching Go models.AIAnalysis
            scoring = decision.get("scoring", {})
            verified_case = decision.get("verified_case", {})
            remediation = [a.get("rationale") for a in decision.get("actions", []) if a.get("rationale")]
            if not remediation:
                remediation = ["Monitor host telemetry", "Verify credentials logs"]

            analysis_payload = {
                "alertId": alert_id,
                "summary": verified_case.get("summary", "AI Orchestration analysis completed."),
                "threatActor": decision.get("predictive_defense", {}).get("predicted_techniques", [{}])[0].get("technique_name", "Unknown Threat Group") if decision.get("predictive_defense", {}).get("predicted_techniques") else "Unknown Threat Group",
                "confidence": int(100 - (scoring.get("final_risk_score_0_10", 5) * 4)), # simple heuristic mapping
                "impactRating": scoring.get("priority", "Medium").capitalize(),
                "technicalDetail": f"Playbook(s) Activated: {', '.join([p.get('playbook_id') for p in decision.get('playbook_routing', {}).get('activated_playbooks', []) if p.get('playbook_id')])}. Risk score is {scoring.get('final_risk_score_0_10')} (Base score: {scoring.get('base_threat_score_0_10')}). Log Verification: {decision.get('l2_independent_verification', {}).get('verification_strength')}.",
                "remediationSteps": remediation
            }

            url_analysis = f"{DASHBOARD_API_URL}/alerts/{alert_id}/analysis"
            try:
                res = requests.post(url_analysis, headers=self.headers, json=analysis_payload, timeout=5)
                if res.status_code == 200:
                    logger.info(f"Successfully posted AI analysis for alert {alert_id}")
                else:
                    logger.error(f"Failed to post AI analysis to {url_analysis}: {res.status_code} - {res.text}")
            except Exception as e:
                logger.error(f"Error posting AI analysis: {e}")

        # Run in a background thread to prevent blocking the main event-consumer thread
        threading.Thread(target=worker, daemon=True).start()
