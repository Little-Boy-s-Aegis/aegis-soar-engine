"""
Aegis SOAR Orchestrator
=======================
Implements Layer 2 decision logic by invoking Qwen 3 Plus with independent 
verifications and offline risk tables as context, and outputting validated L2 JSON.
"""

import json
import hashlib
import logging
import math
import os
import random
import re
import time
from datetime import datetime
from openai import OpenAI
import redis
from config import (
    DASHSCOPE_API_KEY, QWEN_MODEL_NAME, QWEN_BASE_URL,
    SYSTEM_PROMPT_PATH, RISK_SCORING_DIR, LLM_TIMEOUT_SECONDS, LLM_ENABLED,
    REDIS_URL
)
from schema_validator import L2OrchestratorDecision

logger = logging.getLogger("soar-engine.orchestrator")


def _stable_mock_embedding(text, size=1024):
    seed = int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")
    rng = random.Random(seed)
    vector = [rng.uniform(-1.0, 1.0) for _ in range(size)]
    norm = math.sqrt(sum(x * x for x in vector)) or 1.0
    return [x / norm for x in vector]


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


class RiskScoreCalculator:
    @staticmethod
    def calculate_raw_risk(base_score: float, asset_criticality: str) -> tuple[float, float]:
        multipliers = {
            "high": 1.5,
            "medium": 1.0,
            "low": 0.8
        }
        mult = multipliers.get(str(asset_criticality).lower(), 1.0)
        raw_risk = base_score * mult
        return min(max(raw_risk, 0.0), 10.0), mult


class IncidentStateMachine:
    def __init__(self, redis_client=None):
        self.redis = redis_client

    def transition_incident(self, incident_id: str, to_state: str, details: str = ""):
        allowed_states = ["NEW", "ANALYZED", "MITIGATED", "CONTAINED", "CLOSED"]
        if to_state not in allowed_states:
            logger.error(f"Invalid state transition target: {to_state}")
            return None
            
        current_state = "NEW"
        if self.redis:
            try:
                key = f"incident:{incident_id}:state"
                current_state = self.redis.get(key) or "NEW"
                self.redis.set(key, to_state)
            except Exception as e:
                logger.warning(f"Redis get/set failed: {e}")
                
        # Persist to database & file log via SoarAuditLogger
        from audit_logger import SoarAuditLogger
        try:
            SoarAuditLogger.log_event("STATE_TRANSITION", incident_id, {
                "from_state": current_state,
                "to_state": to_state,
                "details": details
            })
        except Exception as e:
            logger.error(f"Failed to log state transition to audit trail: {e}")
            
        logger.info(f"Incident {incident_id} state transition: {current_state} -> {to_state} ({details})")
        return to_state


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

        # Initialize Redis State Database connection and state machine
        try:
            self.redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            self.state_machine = IncidentStateMachine(self.redis)
            logger.info("Connected to Redis State Database in Orchestrator.")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis for state machine: {e}")
            self.redis = None
            self.state_machine = IncidentStateMachine(None)

    def _query_vector_db_playbooks(self, text: str) -> str:
        """Query Qdrant to get related playbooks for Layer 2 decision context."""
        qdrant_url = os.getenv("QDRANT_URL", "http://qdrant:6333")
        api_key = DASHSCOPE_API_KEY
            
        try:
            import requests
            vector = _stable_mock_embedding(text)
            if api_key and not api_key.startswith("mock"):
                url = f"{QWEN_BASE_URL}/embeddings"
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": "text-embedding-v3",
                    "input": text
                }
                resp = requests.post(url, json=payload, headers=headers, timeout=3)
                if resp.status_code == 200:
                    vector = resp.json()["data"][0]["embedding"]
            
            # Step 2: Query Qdrant
            qdrant_search_url = f"{qdrant_url.rstrip('/')}/collections/l2_playbooks/points/search"
            search_payload = {
                "vector": vector,
                "limit": 2,
                "with_payload": True
            }
            search_resp = requests.post(qdrant_search_url, json=search_payload, timeout=3)
            if search_resp.status_code != 200:
                return ""
                
            results = search_resp.json().get("result", [])
            if not results:
                return ""
                
            context_blocks = []
            for r in results:
                payload = r.get("payload", {})
                context_blocks.append(
                    f"Playbook: {payload.get('playbook_id')} - {payload.get('name')}\n"
                    f"Steps:\n{json.dumps(payload.get('steps'), indent=2)}"
                )
            return "\n\n4. **Relevant Playbooks from Vector DB**:\n" + "\n\n".join(context_blocks)
        except Exception:
            return ""

    def run_orchestration(self, findings: list, verified_logs: list) -> dict:
        """
        Runs correlation, verifications lookup, and calls the Qwen Orchestrator.
        
        Args:
            findings: List of L1 findings (Pydantic objects or dicts)
            verified_logs: List of matched Postgres clean log records
            
        Returns:
            dict matching littleboy.soc.layer2.orchestrator_decision.v7
        """
        # Determine incident ID
        incident_id = None
        for f in findings:
            if f.get("incident_id"):
                incident_id = f.get("incident_id")
                break
        if not incident_id:
            incident_id = f"INC-AI-{int(time.time())}"

        # Transition to NEW state
        self.state_machine.transition_incident(incident_id, "NEW", "Incident received at Layer 2 SOAR Orchestrator")

        # Determine primary threat parameters
        has_threat = any(f.get("threat_detected", False) for f in findings)
        primary_finding = findings[0] if findings else {}
        primary_attack_id = primary_finding.get("mitre_attack_id", "")
        primary_capec_id = primary_finding.get("capec_id", "")

        # Base score lookup
        base_score = 5.0
        if primary_attack_id:
            row = self.risk_kb.lookup_attack(primary_attack_id)
            base_score = float(row.get("base_threat_score_0_10", 5.0))
        elif primary_capec_id:
            row = self.risk_kb.lookup_capec(primary_capec_id)
            base_score = float(row.get("base_threat_score_0_10", 5.0))

        # Determine asset criticality from verified logs
        asset_crit = "medium"
        for log in verified_logs:
            crit = log.get("assetCritical") or log.get("asset_criticality")
            if crit:
                crit_lower = str(crit).lower()
                if crit_lower in ["high", "medium", "low"]:
                    if crit_lower == "high" or (crit_lower == "medium" and asset_crit == "low"):
                        asset_crit = crit_lower

        # Calculate raw risk & multiplier
        raw_risk, mult = RiskScoreCalculator.calculate_raw_risk(base_score, asset_crit)

        # Verification Status & Cap
        verified = len(verified_logs) > 0
        v_strength = "supported" if verified else "none"
        risk_cap = 7.0 if verified else 5.5
        final_score = min(raw_risk, risk_cap)
        priority = "high" if final_score >= 7.0 else "medium"

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

        # 1.5. Query Vector DB for relevant Playbooks
        query_text = f"mitre_attack_id: {primary_attack_id}, capec_id: {primary_capec_id}, evidence: {primary_finding.get('raw_evidence', '')}"
        playbook_context = self._query_vector_db_playbooks(query_text)

        # 2. Build User Prompt
        user_prompt = f"""
### INPUTS FOR LAYER 2 DECISION ENGINE

1. **Layer 1 EDR/WAF/UEBA/ATM Agent Findings**:
{json.dumps(findings, indent=2)}

2. **Layer 2 Independent Log Verification (Query from PostgreSQL log_entries)**:
{json.dumps(verified_logs, indent=2)}

3. **Authoritative Offline Risk Scoring References**:
{risk_context_str}
{playbook_context}

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

                # Dynamically recalculate/verify risk scoring
                scoring = decision_dict.get("scoring", {})
                scoring["score_source"] = "soar_calculator"
                scoring["base_threat_score_0_10"] = base_score
                scoring["asset_criticality_multiplier"] = mult
                scoring["raw_context_risk_0_10"] = raw_risk
                scoring["risk_cap_applied"] = True
                scoring["risk_cap_0_10"] = risk_cap
                scoring["risk_cap_reason"] = f"Verification strength is {v_strength}"
                scoring["final_risk_score_0_10"] = final_score
                scoring["priority"] = priority
                decision_dict["scoring"] = scoring

                # Log AI Decision to audit trail
                from audit_logger import SoarAuditLogger
                incident_id = decision_dict.get("input_summary", {}).get("incident_id", incident_id)
                SoarAuditLogger.log_ai_decision(incident_id, user_prompt, raw_response, decision_dict)
                
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
                
                # Transition state machine to ANALYZED, and CONTAINED if actions executed
                has_executed = any(a.get("status") == "executed" for a in decision_dict.get("actions", []))
                final_state = "CONTAINED" if has_executed else "ANALYZED"
                self.state_machine.transition_incident(incident_id, final_state, f"Incident processed successfully. Final State: {final_state}")

                return validated_decision.model_dump(by_alias=False, exclude_none=True)

            except Exception as e:
                logger.error(f"Qwen L2 Orchestration failed or timed out: {e}. Triggering local fallback.")
                return self._generate_fallback_decision(
                    findings, verified_logs, f"Orchestrator failure: {str(e)}",
                    incident_id=incident_id, base_score=base_score, mult=mult,
                    raw_risk=raw_risk, risk_cap=risk_cap, final_score=final_score,
                    priority=priority, has_threat=has_threat, primary_attack_id=primary_attack_id,
                    primary_capec_id=primary_capec_id
                )
        else:
            return self._generate_fallback_decision(
                findings, verified_logs, "LLM client disabled or api key missing",
                incident_id=incident_id, base_score=base_score, mult=mult,
                raw_risk=raw_risk, risk_cap=risk_cap, final_score=final_score,
                priority=priority, has_threat=has_threat, primary_attack_id=primary_attack_id,
                primary_capec_id=primary_capec_id
            )

    def _clean_json_string(self, text: str) -> dict:
        # Strip markdown ```json ... ``` blocks
        cleaned = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        return json.loads(cleaned.strip())

    def _generate_fallback_decision(self, findings: list, verified_logs: list, error_reason: str,
                                    incident_id: str = None, base_score: float = None, mult: float = None,
                                    raw_risk: float = None, risk_cap: float = None, final_score: float = None,
                                    priority: str = None, has_threat: bool = None, primary_attack_id: str = None,
                                    primary_capec_id: str = None) -> dict:
        """Fallback to a safe Suggest-Only decision matching v7 schema when Qwen fails."""
        logger.info("Generating local fallback suggest-only decision.")
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Simple rule-based logic for fallback
        if has_threat is None:
            has_threat = any(f.get("threat_detected", False) for f in findings)
        primary_finding = findings[0] if findings else {}
        if primary_attack_id is None:
            primary_attack_id = primary_finding.get("mitre_attack_id", "T1059")
        if primary_capec_id is None:
            primary_capec_id = primary_finding.get("capec_id", "")
        if incident_id is None:
            incident_id = f"INC-FALLBACK-{int(time.time())}"
            
        # Determine asset criticality from verified logs
        asset_crit = "medium"
        for log in verified_logs:
            crit = log.get("assetCritical") or log.get("asset_criticality")
            if crit:
                crit_lower = str(crit).lower()
                if crit_lower in ["high", "medium", "low"]:
                    if crit_lower == "high" or (crit_lower == "medium" and asset_crit == "low"):
                        asset_crit = crit_lower

        if base_score is None:
            base_score = 5.0
            if primary_attack_id:
                row = self.risk_kb.lookup_attack(primary_attack_id)
                base_score = float(row.get("base_threat_score_0_10", 5.0))
            elif primary_capec_id:
                row = self.risk_kb.lookup_capec(primary_capec_id)
                base_score = float(row.get("base_threat_score_0_10", 5.0))

        if mult is None:
            multipliers = {"high": 1.5, "medium": 1.0, "low": 0.8}
            mult = multipliers.get(asset_crit, 1.0)
            
        if raw_risk is None:
            raw_risk = min(max(base_score * mult, 0.0), 10.0)

        verified = len(verified_logs) > 0
        v_state = "confirmed" if (verified and has_threat) else "insufficient"
        v_strength = "supported" if verified else "none"
        
        if risk_cap is None:
            risk_cap = 7.0 if verified else 5.5
            
        if final_score is None:
            final_score = min(raw_risk, risk_cap)
            
        if priority is None:
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

        # Transition state machine to ANALYZED state
        self.state_machine.transition_incident(incident_id, "ANALYZED", f"Fallback due to: {error_reason}")

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
