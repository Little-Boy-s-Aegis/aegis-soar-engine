import json
import logging
import time
import uuid
import requests
try:
    import redis
except ImportError:
    redis = None
from config import (
    KAFKA_BROKERS, SOAR_DECISIONS_TOPIC, SOAR_QUEUED_ACTIONS_TOPIC,
    DASHBOARD_EVENTS_TOPIC, ACTION_EXECUTION_DELAY_SECONDS, DASHBOARD_API_URL,
    REDIS_URL
)
from playbook_executor import PlaybookExecutor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soar-action-worker")

class SoarActionWorker:
    def __init__(self):
        self.executor = PlaybookExecutor()
        self.producer = None
        
        # Initialize Redis State Database connection
        try:
            if redis:
                self.redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
                logger.info(f"Connected to Redis State Database at {REDIS_URL}")
            else:
                logger.warning("Redis client library not installed. Running without Redis state database.")
                self.redis = None
        except Exception as re:
            logger.error(f"Failed to connect to Redis State Database: {re}")
            self.redis = None

        # Initialize Fortinet Firewall Connector
        try:
            from connectors.fortinet import FortinetConnector
            self.fortinet = FortinetConnector()
            logger.info("Fortinet Firewall Connector initialized successfully.")
        except Exception as fe:
            logger.error(f"Failed to initialize Fortinet Firewall Connector: {fe}")
            self.fortinet = None

        # Initialize Active Directory Connector
        try:
            from connectors.active_directory import ActiveDirectoryConnector
            self.ad = ActiveDirectoryConnector()
            logger.info("Active Directory / Entra ID Connector initialized successfully.")
        except Exception as ae:
            logger.error(f"Failed to initialize Active Directory Connector: {ae}")
            self.ad = None

        # Initialize CrowdStrike Connector
        try:
            from connectors.crowdstrike import CrowdStrikeConnector
            self.crowdstrike = CrowdStrikeConnector()
            logger.info("CrowdStrike EDR Connector initialized successfully.")
        except Exception as ce:
            logger.error(f"Failed to initialize CrowdStrike Connector: {ce}")
            self.crowdstrike = None

        # Initialize AWS WAF Connector
        try:
            from connectors.waf import WafConnector
            self.waf = WafConnector()
            logger.info("AWS WAF API Connector initialized successfully.")
        except Exception as we:
            logger.error(f"Failed to initialize AWS WAF Connector: {we}")
            self.waf = None

        # Initialize Rate Limiter
        try:
            from rate_limiter import RedisTokenBucketRateLimiter
            self.rate_limiter = RedisTokenBucketRateLimiter(redis_url=REDIS_URL)
            logger.info("Token Bucket Rate Limiter initialized successfully.")
        except Exception as rle:
            logger.error(f"Failed to initialize Rate Limiter: {rle}")
            self.rate_limiter = None

        # Initialize OPA Policy Evaluator
        try:
            from policy_evaluator import OpaPolicyEvaluator
            self.policy_evaluator = OpaPolicyEvaluator()
            logger.info("OPA Policy Evaluator client initialized successfully.")
        except Exception as oepa:
            logger.error(f"Failed to initialize OPA Policy Evaluator: {oepa}")
            self.policy_evaluator = None

        # Initialize Dry-run Mode configuration
        import os
        self.dry_run = os.getenv("SOAR_DRY_RUN", "false").lower() == "true"
        if self.dry_run:
            logger.info("[DRY RUN ACTIVE] SOAR Engine initialized in global dry-run simulation mode.")
        
    def start(self):
        logger.info("==================================================")
        logger.info("    AEGIS SOAR ACTION WORKER (MESSAGE QUEUE)      ")
        logger.info("==================================================")
        logger.info(f"Kafka Brokers: {KAFKA_BROKERS}")
        logger.info(f"Execution Delay: {ACTION_EXECUTION_DELAY_SECONDS}s")

        # Initialize producer
        for attempt in range(5):
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BROKERS,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8")
                )
                logger.info("Producer connected to Kafka successfully.")
                break
            except Exception as e:
                logger.warning(f"Failed to connect producer to Kafka: {e}")
                time.sleep(3)

        if not self.producer:
            logger.error("Could not initialize Kafka producer. Exiting.")
            return

        # Start rate-limited execution thread in background
        import threading
        threading.Thread(target=self.start_rate_limited_executor, daemon=True).start()

        # Start consumer loop for L2 decisions
        self.consume_decisions_loop()

    def consume_decisions_loop(self):
        consumer = None
        for attempt in range(5):
            try:
                consumer = KafkaConsumer(
                    SOAR_DECISIONS_TOPIC,
                    bootstrap_servers=KAFKA_BROKERS,
                    group_id="aegis-soar-action-worker-decisions",
                    auto_offset_reset="latest"
                )
                logger.info(f"Subscribed to topic: {SOAR_DECISIONS_TOPIC}")
                break
            except Exception as e:
                logger.warning(f"Failed to initialize Kafka consumer: {e}")
                time.sleep(3)

        if not consumer:
            logger.error("Could not initialize decisions consumer. Exiting.")
            return

        for msg in consumer:
            try:
                decision = json.loads(msg.value.decode("utf-8"))
                logger.info(f"[ACTION WORKER] Received L2 decision for incident: {decision['input_summary'].get('incident_id')}")
                
                # 1. Queue all actions to the message queue topic (soar.actions.queued)
                actions = decision.get("actions", [])
                logger.info(f"[ACTION WORKER] Queueing {len(actions)} actions into message queue...")
                for action in actions:
                    # Envelop the action with decision context
                    action_envelope = {
                        "incident_id": decision["input_summary"].get("incident_id"),
                        "decision": decision,
                        "action": action
                    }
                    self.producer.send(SOAR_QUEUED_ACTIONS_TOPIC, action_envelope)
                self.producer.flush()
                logger.info(f"[ACTION WORKER] All actions for incident {decision['input_summary'].get('incident_id')} queued successfully.")
                
                # Update status in Redis
                if self.redis:
                    redis_key = f"aegis:playbook:status:{decision['input_summary'].get('incident_id')}"
                    self.redis.hset(redis_key, "status", "QUEUED")
                    self.redis.hset(redis_key, "updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                    logger.info(f"[REDIS STATE] Updated status of incident {decision['input_summary'].get('incident_id')} to QUEUED")
                
            except Exception as e:
                logger.error(f"Error handling decision message: {e}")

    def start_rate_limited_executor(self):
        """Consumes actions from the queue and executes them at a rate-limited speed."""
        consumer = None
        for attempt in range(5):
            try:
                consumer = KafkaConsumer(
                    SOAR_QUEUED_ACTIONS_TOPIC,
                    bootstrap_servers=KAFKA_BROKERS,
                    group_id="aegis-soar-action-worker-executor",
                    auto_offset_reset="latest"
                )
                logger.info(f"Rate-limited executor subscribed to queue: {SOAR_QUEUED_ACTIONS_TOPIC}")
                break
            except Exception as e:
                logger.warning(f"Failed to initialize queue consumer: {e}")
                time.sleep(3)

        if not consumer:
            logger.error("Could not initialize rate-limited executor. Exiting thread.")
            return

        for msg in consumer:
            try:
                envelope = json.loads(msg.value.decode("utf-8"))
                incident_id = envelope.get("incident_id")
                action = envelope.get("action")
                decision = envelope.get("decision")
                
                action_type = action.get("action_type")
                target_value = action.get("target", {}).get("value_masked")
                
                logger.info(f"[ACTION EXECUTOR QUEUE] Processing queued action: {action_type} on {target_value} (Incident: {incident_id})")
                
                # Update status in Redis to EXECUTING
                if self.redis:
                    redis_key = f"aegis:playbook:status:{incident_id}"
                    self.redis.hset(redis_key, "status", "EXECUTING")
                    self.redis.hset(redis_key, "updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                    
                    # Update individual action status in actions_status map
                    try:
                        actions_status_json = self.redis.hget(redis_key, "actions_status")
                        if actions_status_json:
                            actions_status = json.loads(actions_status_json)
                            key = f"{action_type}:{target_value}"
                            actions_status[key] = "executing"
                            self.redis.hset(redis_key, "actions_status", json.dumps(actions_status))
                    except Exception as re:
                        logger.error(f"Failed to update action status in Redis: {re}")

                # Apply delay to throttle execution and avoid system overload
                logger.info(f"[ACTION EXECUTOR QUEUE] Enforcing {ACTION_EXECUTION_DELAY_SECONDS}s delay rate limit...")
                time.sleep(ACTION_EXECUTION_DELAY_SECONDS)
                
                # Execute action using PlaybookExecutor mechanisms
                autopilot_active = decision.get("automation_control", {}).get("soc_autopilot_enabled", False)
                execution_window_ok = decision.get("automation_control", {}).get("execution_window", {}).get("in_window", False)
                eligible = decision.get("automation_control", {}).get("auto_containment_eligible", False)
                should_execute_containment = autopilot_active and execution_window_ok and eligible
                
                phase = action.get("phase")
                approval_mode = action.get("approval_mode")
                
                run_action = False
                if phase in ("preserve", "hunt", "notify") or approval_mode == "AUTO":
                    run_action = True
                elif phase == "contain" and should_execute_containment:
                    run_action = True
                
                is_dry_run = self.dry_run or decision.get("dry_run", False)
                if is_dry_run:
                    logger.info(f"[DRY RUN ACTIVE] Simulating action execution workflow for {action_type} on {target_value}")

                if run_action:
                    # Check safety policies with Open Policy Agent (OPA)
                    if self.policy_evaluator:
                        risk_score = decision.get("scoring", {}).get("final_risk_score_0_10", 0.0)
                        allowed, reason = self.policy_evaluator.is_action_allowed(
                            action_type=action_type,
                            target=target_value,
                            phase=phase,
                            approval_mode=approval_mode,
                            risk_score=risk_score
                        )
                        if not allowed:
                            logger.error(f"[OPA BLOCKED] Action {action_type} on {target_value} blocked by OPA: {reason}")
                            action["status"] = "failed"
                            action["rationale"] = f"{action.get('rationale', '')} | OPA Blocked: {reason}"
                            
                            if self.redis:
                                redis_key = f"aegis:playbook:status:{incident_id}"
                                self.redis.hincrby(redis_key, "failed_actions", 1)
                            self.sync_execution_progress(decision, action, incident_id)
                            continue

                    if is_dry_run:
                        logger.info(f"[DRY RUN SIMULATION] Action {action_type} on {target_value} passed OPA/Whitelist Guardrails. Bypassing execution.")
                        action["status"] = "simulated"
                        action["rationale"] = f"{action.get('rationale', '')} | [DRY RUN] Simulated execution successfully."
                    else:
                        # Enforce Rate Limiting per target system
                        target_system = None
                        if action_type in ("block_ip", "block_domain"):
                            target_system = "fortinet"
                        elif action_type in ("disable_account", "reset_password"):
                            target_system = "active_directory"
                        elif action_type in ("quarantine_host", "lift_isolation"):
                            target_system = "crowdstrike"
                            
                        if target_system and self.rate_limiter:
                            logger.info(f"[RATE LIMITER] Acquiring token for {target_system}...")
                            token_acquired = self.rate_limiter.acquire_token(target_system, timeout_seconds=15.0)
                            if not token_acquired:
                                logger.error(f"[RATE LIMITER EXCEEDED] Timeout acquiring token for {target_system}. Action will fail and trigger retry.")
                                action["status"] = "failed"
                                action["rationale"] = f"{action.get('rationale', '')} | Rate Limiter Timeout for {target_system}"
                                
                                if self.redis:
                                    redis_key = f"aegis:playbook:status:{incident_id}"
                                    self.redis.hincrby(redis_key, "failed_actions", 1)
                                self.sync_execution_progress(decision, action, incident_id)
                                continue

                        # Trigger Fortinet Firewall API Connector if it's an IP/Domain block
                        if self.fortinet:
                            if action_type == "block_ip":
                                fw_success, fw_msg = self.fortinet.block_ip(target_value)
                                if fw_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | Fortinet Block: {fw_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | Fortinet Block Failed: {fw_msg}"
                            elif action_type == "block_domain":
                                fw_success, fw_msg = self.fortinet.block_domain(target_value)
                                if fw_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | Fortinet Block: {fw_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | Fortinet Block Failed: {fw_msg}"

                        # Trigger Active Directory / Entra ID API Connector if it's account management
                        if self.ad:
                            if action_type == "disable_account":
                                ad_success, ad_msg = self.ad.disable_account(target_value)
                                if ad_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | AD Action: {ad_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | AD Action Failed: {ad_msg}"
                            elif action_type == "reset_password":
                                ad_success, ad_msg = self.ad.reset_password(target_value)
                                if ad_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | AD Action: {ad_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | AD Action Failed: {ad_msg}"

                        # Trigger CrowdStrike EDR API Connector if it's host isolation
                        if self.crowdstrike:
                            if action_type == "quarantine_host":
                                cs_success, cs_msg = self.crowdstrike.isolate_host(target_value)
                                if cs_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | CrowdStrike Isolation: {cs_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | CrowdStrike Isolation Failed: {cs_msg}"
                            elif action_type == "lift_isolation":
                                cs_success, cs_msg = self.crowdstrike.lift_isolation(target_value)
                                if cs_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | CrowdStrike Isolation: {cs_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | CrowdStrike Isolation Failed: {cs_msg}"

                        # Trigger AWS WAF API Connector for IP/Domain containment & custom signatures
                        if self.waf:
                            if action_type == "block_ip":
                                waf_success, waf_msg = self.waf.block_ip(target_value)
                                if waf_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | AWS WAF: {waf_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | AWS WAF Failed: {waf_msg}"
                            elif action_type == "deploy_waf_rule":
                                # Target value represents attack type (e.g. SQLi), rationale might contain the URL pattern
                                url_pattern = action.get("target", {}).get("value_masked", "/")
                                waf_success, waf_msg = self.waf.deploy_mitigation_rule(target_value, url_pattern)
                                if waf_success:
                                    action["rationale"] = f"{action.get('rationale', '')} | AWS WAF Rule: {waf_msg}"
                                else:
                                    action["rationale"] = f"{action.get('rationale', '')} | AWS WAF Rule Failed: {waf_msg}"

                        dashboard_action_type = self.executor._map_action_type(action_type)
                        
                        # 1. Retry Loop
                        max_attempts = action.get("retry", {}).get("max_attempts", 1)
                        delay_seconds = action.get("retry", {}).get("delay_seconds", 2.0)
                        success = False
                        details = "No execution attempt made"
                        
                        for attempt in range(max_attempts):
                            if attempt > 0:
                                logger.info(f"[ACTION RETRY] Retrying {action_type} on {target_value} (Attempt {attempt+1}/{max_attempts}) in {delay_seconds}s...")
                                time.sleep(delay_seconds)
                                
                            success, details = self.executor._call_dashboard_perform_action(
                                actor="SOAR Action Worker",
                                action_type=dashboard_action_type,
                                target=target_value,
                                message=action.get("rationale", "")
                            )
                            if success:
                                break
                        
                        if success:
                            action["status"] = "executed"
                            logger.info(f"[ACTION EXECUTOR QUEUE] EXECUTED: {action_type} on {target_value} successfully.")
                        else:
                            action["status"] = "failed"
                            logger.error(f"[ACTION EXECUTOR QUEUE] FAILED after {max_attempts} attempts: {action_type} on {target_value}: {details}")
                            
                            # 2. Trigger Fallback Action if defined
                            fallback_step = action.get("fallback_step")
                            if fallback_step:
                                logger.warning(f"[ACTION FALLBACK] Triggering fallback step {fallback_step.get('step_id')} (Type: {fallback_step.get('action_type')})")
                                self.execute_fallback_action(fallback_step, target_value, incident_id, decision)
                else:
                    action["status"] = "suggested"
                    logger.info(f"[ACTION EXECUTOR QUEUE] SKIPPED (Suggested Only): {action_type} on {target_value}.")

                # Update Redis with execution results
                if self.redis:
                    redis_key = f"aegis:playbook:status:{incident_id}"
                    try:
                        actions_status_json = self.redis.hget(redis_key, "actions_status")
                        if actions_status_json:
                            actions_status = json.loads(actions_status_json)
                            key = f"{action_type}:{target_value}"
                            actions_status[key] = action["status"]
                            self.redis.hset(redis_key, "actions_status", json.dumps(actions_status))
                        
                        # Increment counters
                        if action["status"] in ("executed", "simulated"):
                            self.redis.hincrby(redis_key, "executed_actions", 1)
                        elif action["status"] == "failed":
                            self.redis.hincrby(redis_key, "failed_actions", 1)
                        
                        # Check if all completed
                        total = int(self.redis.hget(redis_key, "total_actions") or 0)
                        executed = int(self.redis.hget(redis_key, "executed_actions") or 0)
                        failed = int(self.redis.hget(redis_key, "failed_actions") or 0)
                        
                        if executed + failed >= total:
                            final_status = "COMPLETED" if failed == 0 else "FAILED"
                            self.redis.hset(redis_key, "status", final_status)
                            self.redis.hset(redis_key, "completed_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                            logger.info(f"[REDIS STATE] Playbook for incident {incident_id} finished execution with status {final_status}")
                        else:
                            self.redis.hset(redis_key, "updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                    except Exception as re:
                        logger.error(f"Failed to complete state tracking in Redis: {re}")

                # Synchronize execution progress back to dashboard and gateway
                self.sync_execution_progress(decision, action, incident_id)
                
            except Exception as e:
                logger.error(f"Error executing queued action: {e}")

    def execute_fallback_action(self, fallback_step: dict, original_target: str, incident_id: str, decision: dict):
        """Executes a fallback action when a primary playbook action fails."""
        fallback_action_type = fallback_step.get("action_type")
        fallback_target = fallback_step.get("target")
        
        target_value = original_target
        if fallback_target == "soc_team":
            target_value = "SOC_Security_Team"
            
        logger.info(f"[FALLBACK RUNNER] Executing fallback action {fallback_action_type} on {target_value} for incident {incident_id}")
        
        dashboard_action_type = self.executor._map_action_type(fallback_action_type)
        success, details = self.executor._call_dashboard_perform_action(
            actor="SOAR Action Worker (Fallback)",
            action_type=dashboard_action_type,
            target=target_value,
            message=fallback_step.get("rationale", "Fallback execution due to primary action failure.")
        )
        
        fallback_action = {
            "action_id": fallback_step.get("step_id", "act-fallback"),
            "action_type": fallback_action_type,
            "phase": "notify" if fallback_action_type in ("notify_soc", "open_ticket") else "contain",
            "status": "executed" if success else "failed",
            "rationale": fallback_step.get("rationale", ""),
            "target": {
                "type": "ACCOUNT" if fallback_target == "soc_team" else "IP",
                "value_masked": target_value
            },
            "approval_mode": "AUTO"
        }
        
        # Sync this fallback event to Kafka and Go backend Gateway
        self.sync_execution_progress(decision, fallback_action, incident_id)
        
        # Update Redis actions_status map if Redis is active
        if self.redis:
            redis_key = f"aegis:playbook:status:{incident_id}"
            try:
                actions_status_json = self.redis.hget(redis_key, "actions_status")
                if actions_status_json:
                    actions_status = json.loads(actions_status_json)
                    key = f"fallback:{fallback_action_type}:{target_value}"
                    actions_status[key] = fallback_action["status"]
                    self.redis.hset(redis_key, "actions_status", json.dumps(actions_status))
            except Exception as e:
                logger.error(f"Failed to update fallback action in Redis: {e}")

    def sync_execution_progress(self, decision: dict, action: dict, incident_id: str):
        """Synchronizes execution status with the Go API Gateway and Dashboard."""
        try:
            # 1. Publish to aegis.security.events Kafka topic
            event_uuid = str(uuid.uuid4())
            verified_case = decision.get("verified_case", {})
            entities = verified_case.get("entities", {})
            ips = entities.get("ips", [])
            source_ip = ips[0] if ips else "127.0.0.1"
            
            security_status = "BLOCKED" if action.get("status") == "executed" else "DETECTED"
            
            event_payload = {
                "eventId": event_uuid,
                "timestamp": decision.get("timestamp"),
                "attackType": f"{verified_case.get('title', 'SOC Incident')} - {action.get('action_type').upper()}",
                "endpoint": entities.get("api_endpoints", ["/"])[0] if entities.get("api_endpoints") else "/",
                "payload": f"Queued action execution: {action.get('status')}. Rationale: {action.get('rationale')}",
                "status": security_status,
                "clientIp": source_ip,
                "description": f"Incident: {incident_id} | Status: {action.get('status')} | Target: {action.get('target', {}).get('value_masked')}",
                "sourceService": "SOAR-Action-Worker"
            }
            
            self.producer.send(DASHBOARD_EVENTS_TOPIC, event_payload)
            self.producer.flush()
            logger.info(f"[SYNC] Published execution event for action {action.get('action_type')} to dashboard.")

            # 2. Push full decision payload update to the Go backend `/api/internal/soar/decision`
            self.executor._push_l2_decision_to_gateway(decision)

        except Exception as e:
            logger.error(f"Failed to sync execution progress: {e}")

if __name__ == "__main__":
    worker = SoarActionWorker()
    worker.start()
