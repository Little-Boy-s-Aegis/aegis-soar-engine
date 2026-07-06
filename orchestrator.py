"""
Aegis SOAR Orchestrator
=======================
Implements Layer 2 decision logic by invoking Qwen 3 Plus with independent 
verifications and offline risk tables as context, and outputting validated L2 JSON.
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from openai import OpenAI
from config import (
    DASHSCOPE_API_KEY, QWEN_MODEL_NAME, QWEN_BASE_URL,
    SYSTEM_PROMPT_PATH, RISK_SCORING_DIR, LLM_TIMEOUT_SECONDS, LLM_ENABLED
)
from schema_validator import L2OrchestratorDecision

logger = logging.getLogger("soar-engine.orchestrator")


class RiskTableParser:
    """Parses offline markdown risk score tables for lookup and prompt enrichment."""

    def __init__(self):
        self.attack_scores = {}
        self.capec_scores = {}
        self._load_tables()

    def _load_tables(self):
        # 1. Parse ATT&CK scores
        attack_file = os.path.join(RISK_SCORING_DIR, "attack_vector_risk_scores.md")
        if os.path.exists(attack_file):
            try:
                self.attack_scores = self._parse_md_table(attack_file, key_col="attack_id")
                logger.info(f"Loaded {len(self.attack_scores)} ATT&CK base risk scores from offline KB.")
            except Exception as e:
                logger.error(f"Failed to parse attack_vector_risk_scores.md: {e}")

        # 2. Parse CAPEC scores
        capec_file = os.path.join(RISK_SCORING_DIR, "capec_risk_scores.md")
        if os.path.exists(capec_file):
            try:
                self.capec_scores = self._parse_md_table(capec_file, key_col="capec_id")
                logger.info(f"Loaded {len(self.capec_scores)} CAPEC base risk scores from offline KB.")
            except Exception as e:
                logger.error(f"Failed to parse capec_risk_scores.md: {e}")

    def _parse_md_table(self, file_path: str, key_col: str) -> dict:
        """Parses a markdown table into a dictionary keyed by key_col."""
        results = {}
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        headers = []
        for line in lines:
            line = line.strip()
            if not line.startswith("|"):
                continue

            parts = [p.strip() for p in line.split("|")[1:-1]]
            
            # Identify header row
            if not headers:
                if key_col in parts:
                    headers = parts
                continue
                
            # Skip separator row (|---|---|...)
            if all(re.match(r"^:?-+:?$", p) for p in parts):
                continue
                
            # Parse data row
            if len(parts) == len(headers):
                row_dict = dict(zip(headers, parts))
                key_val = row_dict.get(key_col)
                if key_val:
                    results[key_val] = row_dict
                    
        return results

    def lookup_attack(self, attack_id: str) -> dict:
        return self.attack_scores.get(attack_id, {})

    def lookup_capec(self, capec_id: str) -> dict:
        return self.capec_scores.get(capec_id, {})


class SoarOrchestrator:
    """Invokes Qwen 3 Plus security agent using Layer 2 prompt engineering."""

    def __init__(self):
        self.risk_kb = RiskTableParser()
        self.client = None
        self.system_prompt = ""

        # Load L2 standalone system prompt
        if os.path.exists(SYSTEM_PROMPT_PATH):
            with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
                self.system_prompt = f.read()
            logger.info("Loaded Layer 2 Orchestrator system prompt.")
        else:
            logger.error(f"System prompt file not found at: {SYSTEM_PROMPT_PATH}")

        # Initialize OpenAI client pointing to DashScope/Qwen
        if LLM_ENABLED and DASHSCOPE_API_KEY:
            self.client = OpenAI(
                api_key=DASHSCOPE_API_KEY,
                base_url=QWEN_BASE_URL
            )
            logger.info(f"Qwen API Client initialized: {QWEN_BASE_URL} (Model: {QWEN_MODEL_NAME})")
        else:
            logger.warning("LLM disabled or DASHSCOPE_API_KEY not set. Operating in Suggest-Only Local Fallback mode.")

        # Initialize structured Playbook Runner
        from playbook_runner import PlaybookRunner
        self.playbook_runner = PlaybookRunner()

    def run_orchestration(self, findings: list, verified_logs: list) -> dict:
        """
        Runs correlation, verifications lookup, and calls the Qwen Orchestrator.
        
        Args:
            findings: List of L1 findings (Pydantic objects or dicts)
            verified_logs: List of matched Postgres clean log records
            
        Returns:
            dict matching littleboy.soc.layer2.orchestrator_decision.v7
        """
        # 1. Lookup Offline Risk Scores for prompt enrichment
        enriched_risk_context = []
        for f in findings:
            attack_id = f.get("mitre_attack_id", "")
            capec_id = f.get("capec_id", "")
            
            if attack_id:
                score_row = self.risk_kb.lookup_attack(attack_id)
                if score_row:
                    enriched_risk_context.append(f"MITRE ATT&CK {attack_id} Base Risk Row:\n{json.dumps(score_row, indent=2)}")
            if capec_id:
                score_row = self.risk_kb.lookup_capec(capec_id)
                if score_row:
                    enriched_risk_context.append(f"CAPEC {capec_id} Base Risk Row:\n{json.dumps(score_row, indent=2)}")

        risk_context_str = "\n\n".join(enriched_risk_context)

        # 2. Build User Prompt
        user_prompt = f"""
### INPUTS FOR LAYER 2 DECISION ENGINE

1. **Layer 1 EDR/WAF/UEBA/ATM Agent Findings**:
{json.dumps(findings, indent=2)}

2. **Layer 2 Independent Log Verification (Query from PostgreSQL log_entries)**:
{json.dumps(verified_logs, indent=2)}

3. **Authoritative Offline Risk Scoring References**:
{risk_context_str}

Please correlate the findings, verify the logs, look up the base threat scores, calculate final risk scores, apply red-line security policies, and output a valid JSON decision conforming to schema version `littleboy.soc.layer2.orchestrator_decision.v7`.
"""

        # 3. Call LLM (with Timeout Guard)
        if self.client and LLM_ENABLED:
            try:
                logger.info(f"Calling Qwen API for L2 Orchestration (Timeout: {LLM_TIMEOUT_SECONDS}s)...")
                
                response = self.client.chat.completions.create(
                    model=QWEN_MODEL_NAME,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"},
                    timeout=LLM_TIMEOUT_SECONDS
                )
                
                raw_response = response.choices[0].message.content
                logger.info("Successfully received response from Qwen Orchestrator.")
                
                # Parse and validate response
                decision_dict = json.loads(raw_response)
                
                # Strip markdown codeblocks if LLM returned them inside JSON or string format
                if isinstance(decision_dict, str):
                    decision_dict = self._clean_json_string(decision_dict)
                
                # Resolve actions structurally via PlaybookRunner
                activated_playbooks = decision_dict.get("playbook_routing", {}).get("activated_playbooks", [])
                if activated_playbooks:
                    playbook_id = activated_playbooks[0].get("playbook_id")
                    logger.info(f"LLM activated playbook: {playbook_id}. Resolving actions structurally via PlaybookRunner...")
                    structured_actions = self.playbook_runner.execute_playbook(playbook_id, decision_dict)
                    if structured_actions:
                        # Enrich each resolved action with metadata expected by v7 schema
                        for a in structured_actions:
                            a["ttl_minutes"] = 60 if a["phase"] == "contain" else None
                            a["rollback_plan"] = "Revert firewall block" if a["action_type"] == "block_ip" else "Restore network interfaces" if a["action_type"] == "quarantine_host" else "None"
                            a["playbook_source"] = playbook_id
                            a["risk_if_wrong"] = "medium" if a["phase"] == "contain" else "low"
                        decision_dict["actions"] = structured_actions
                
                # Validate output matches v7 schema using Pydantic
                validated_decision = L2OrchestratorDecision(**decision_dict)
                return validated_decision.model_dump(by_alias=False, exclude_none=True)

            except Exception as e:
                logger.error(f"Qwen L2 Orchestration failed or timed out: {e}. Triggering local fallback.")
                return self._generate_fallback_decision(findings, verified_logs, f"Orchestrator failure: {str(e)}")
        else:
            return self._generate_fallback_decision(findings, verified_logs, "LLM client disabled or api key missing")

    def _clean_json_string(self, text: str) -> dict:
        # Strip markdown ```json ... ``` blocks
        cleaned = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        return json.loads(cleaned.strip())

    def _generate_fallback_decision(self, findings: list, verified_logs: list, error_reason: str) -> dict:
        """Fallback to a safe Suggest-Only decision matching v7 schema when Qwen fails."""
        logger.info("Generating local fallback suggest-only decision.")
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Simple rule-based logic for fallback
        has_threat = any(f.get("threat_detected", False) for f in findings)
        primary_finding = findings[0] if findings else {}
        primary_attack_id = primary_finding.get("mitre_attack_id", "T1059")
        primary_capec_id = primary_finding.get("capec_id", "")
        
        # Base score lookup
        base_score = 5.0
        if primary_attack_id:
            row = self.risk_kb.lookup_attack(primary_attack_id)
            base_score = float(row.get("base_threat_score_0_10", 5.0))
        elif primary_capec_id:
            row = self.risk_kb.lookup_capec(primary_capec_id)
            base_score = float(row.get("base_threat_score_0_10", 5.0))

        # Verification
        verified = len(verified_logs) > 0
        v_state = "confirmed" if (verified and has_threat) else "insufficient"
        v_strength = "supported" if verified else "none"
        risk_cap = 7.0 if verified else 5.5
        final_score = min(base_score, risk_cap)
        priority = "high" if final_score >= 7.0 else "medium"

        # Determine the best fallback playbook and execute via PlaybookRunner
        fallback_playbook_id = "PB-WEB-EDGE"
        if "ransom" in primary_attack_id.lower() or primary_attack_id in ["T1486", "T1490", "T1489", "T1485"]:
            fallback_playbook_id = "PB-RANSOM-IMPACT"
        elif "cred" in primary_attack_id.lower() or primary_attack_id in ["T1003", "T1110"]:
            fallback_playbook_id = "PB-CRED"
            
        source_ip = primary_finding.get("entities", {}).get("ips", ["127.0.0.1"])[0] if primary_finding.get("entities") else "127.0.0.1"
        users_list = primary_finding.get("entities", {}).get("users", ["Administrator"]) if primary_finding.get("entities") else ["Administrator"]
        hosts_list = primary_finding.get("entities", {}).get("hosts", ["WEB-PROD-FALLBACK"]) if primary_finding.get("entities") else ["WEB-PROD-FALLBACK"]
        accounts_list = primary_finding.get("entities", {}).get("accounts_masked", ["admin_masked"]) if primary_finding.get("entities") else ["admin_masked"]
        
        context_for_runner = {
            "scoring": {
                "final_risk_score_0_10": final_score
            },
            "verified_case": {
                "threat_confirmed": has_threat and verified,
                "entities": {
                    "ips": [source_ip],
                    "users": users_list,
                    "hosts": hosts_list,
                    "accounts_masked": accounts_list
                }
            }
        }
        
        actions = self.playbook_runner.execute_playbook(fallback_playbook_id, context_for_runner)
        
        # Format the resolved actions to match fallback expected properties
        for a in actions:
            a["ttl_minutes"] = 60 if a["phase"] == "contain" else None
            a["rollback_plan"] = "Revert firewall block" if a["action_type"] == "block_ip" else "Restore interfaces" if a["action_type"] == "quarantine_host" else "None"
            a["playbook_source"] = fallback_playbook_id
            a["risk_if_wrong"] = "medium" if a["phase"] == "contain" else "low"
            
            # Set action status based on verification state
            if not verified:
                a["status"] = "suggested"
            else:
                if a["phase"] == "preserve":
                    a["status"] = "executed"
                else:
                    a["status"] = "queued_for_approval"

        fallback_decision = {
            "schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
            "timestamp": timestamp,
            "orchestrator": {
                "orchestrator_id": "layer2_orchestrator_soar",
                "orchestrator_name": "Layer 2 - Orchestrator / SOAR Decision Engine (Local Fallback)",
                "mode": "correlation_context_policy_playbook_execution"
            },
            "input_summary": {
                "incident_id": f"INC-FALLBACK-{int(time.time())}",
                "source_topic": "l1.agent.findings",
                "output_topic": "aegis.security.events",
                "layer1_schema_version": "littleboy.soc.layer1.agent_finding.v4",
                "findings": findings
            },
            "correlation": {
                "correlation_state": "confirmed" if len(findings) > 1 else "none",
                "same_attack_assessment": len(findings) > 1,
                "correlated_agent_ids": [f.get("agent_id") for f in findings if f.get("agent_id")],
                "correlation_keys": {
                    "entities": [source_ip],
                    "time_window": {"start": timestamp, "end": timestamp},
                    "mitre_attack_ids": [f.get("mitre_attack_id") for f in findings if f.get("mitre_attack_id")],
                    "capec_ids": [f.get("capec_id") for f in findings if f.get("capec_id")],
                    "evidence_terms": ["fallback"]
                },
                "correlation_rationale": ["Local rule-based fallback triggered due to LLM timeout/error."]
            },
            "l2_independent_verification": {
                "performed": True,
                "required": True,
                "verification_state": v_state,
                "verification_sources": [
                    {
                        "source_type": "database",
                        "source_ref": "log_entries",
                        "matched_observation": f"Found {len(verified_logs)} corroborating log entries in database verifier."
                    }
                ] if verified else [],
                "confirmed_entities": [source_ip] if verified else [],
                "verification_strength": v_strength,
                "rationale": [f"Fallback verification logic executed. Status: {v_state}"]
            },
            "verified_case": {
                "threat_confirmed": has_threat and verified,
                "title": f"Local Fallback - Suspicious Activity involving {primary_attack_id}",
                "summary": f"Local SOAR fallback analyzed finding due to error: {error_reason}",
                "verified_techniques": [primary_attack_id] if primary_attack_id else [],
                "expanded_techniques": [primary_attack_id] if primary_attack_id else [],
                "verified_tactics": [],
                "verified_capec": [primary_capec_id] if primary_capec_id else [],
                "entities": {"ips": [source_ip]},
            },
            "scoring": {
                "score_source": "fallback",
                "base_threat_score_0_10": base_score,
                "asset_criticality_multiplier": 1.0,
                "raw_context_risk_0_10": base_score,
                "risk_cap_applied": True,
                "risk_cap_0_10": risk_cap,
                "risk_cap_reason": f"Fallback cap applied: strength is {v_strength}",
                "final_risk_score_0_10": final_score,
                "priority": priority,
                "response_mode": "CONTAIN_AND_HUNT" if verified else "MONITOR",
                "score_rationale": [f"Fallback score computed due to orchestrator error: {error_reason}"]
            },
            "banking_impact": {
                "swift_or_payment_involved": "swift" in primary_finding.get("raw_evidence", "").lower(),
                "core_banking_involved": "core" in primary_finding.get("raw_evidence", "").lower(),
                "customer_data_involved": "customer" in primary_finding.get("raw_evidence", "").lower(),
                "atm_or_hsm_involved": "atm" in primary_finding.get("raw_evidence", "").lower() or "hsm" in primary_finding.get("raw_evidence", "").lower(),
                "privileged_identity_involved": False,
                "business_criticality": "medium"
            },
            "policy_guardrails": {
                "opa_required": True,
                "opa_result": "allow",
                "manual_only_reasons": ["LLM Fallback Mode"],
                "time_bound_required": True,
                "rollback_required": True
            },
            "automation_control": {
                "soc_autopilot_enabled": False,
                "mode": "suggest_only",
                "default_mode": "suggest_only",
                "auto_containment_path": "none",
                "execution_window": {
                    "enabled": False,
                    "timezone": "Asia/Ho_Chi_Minh",
                    "start_local": "08:00",
                    "end_local": "20:00",
                    "in_window": True
                },
                "next_review_minutes": 60,
                "auto_containment_eligible": False,
                "containment_gate_rationale": ["Fallback mode requires human analyst confirmation."]
            },
            "playbook_routing": {
                "activated_playbooks": [
                    {
                        "playbook_id": "PB-FALLBACK",
                        "trigger_type": "anomaly",
                        "trigger_value": primary_attack_id,
                        "mode": "MONITOR",
                        "rationale": "Orchestrator fallback playbook"
                    }
                ]
            },
            "decision": {
                "final_decision": "queue_approval" if verified else "suggest_only",
                "execution_mode": "suggest_only",
                "risk_response_floor": {
                    "triggered": final_score > 6.0,
                    "completed": True,
                    "required_actions": ["preserve_logs", "open_ticket", "notify_soc"],
                    "performed_actions": ["preserve_logs"]
                },
                "justification": f"Fallback alert created due to orchestrator error: {error_reason}"
            },
            "actions": actions,
            "predictive_defense": {
                "predicted_techniques": []
            },
            "output_and_notification": {
                "ticket_payload": {
                    "title": f"Fallback alert - {primary_attack_id}",
                    "priority": priority,
                    "body": f"Local SOAR fallback analyzed findings. Primary finding details: {primary_finding.get('raw_evidence')}"
                }
            },
            "soc_feedback_controls": {
                "allowed_actions": ["confirm", "undo", "rollback"]
            },
            "audit": {
                "audit_events": [
                    {
                        "event_type": "decision",
                        "details": f"Local fallback triggered: {error_reason}"
                    }
                ]
            },
            "safety": {},
            "quality": {
                "limitations": [f"LLM call failed/timed out. Local fallback used: {error_reason}"]
            }
        }
        
        return fallback_decision
