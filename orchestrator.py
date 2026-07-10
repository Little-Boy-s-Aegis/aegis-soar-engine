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
from urllib.parse import urlparse
from datetime import datetime, timedelta
from openai import OpenAI
import redis
from config import (
    LLM_PROVIDER, DASHSCOPE_API_KEY, QWEN_MODEL_NAME, QWEN_BASE_URL,
    BEDROCK_MODEL_ID, BEDROCK_REGION, SYSTEM_PROMPT_PATH, RISK_SCORING_DIR,
    LLM_TIMEOUT_SECONDS, LLM_MAX_TOKENS, LLM_ENABLED,
    REDIS_URL, SOC_AUTOPILOT_ENABLED, DEFAULT_EXECUTION_WINDOW_START,
    DEFAULT_EXECUTION_WINDOW_END, DEFAULT_TIMEZONE
)
from embedding_provider import get_text_embedding, stable_mock_embedding
from schema_validator import L2OrchestratorDecision

logger = logging.getLogger("soar-engine.orchestrator")

L2_SCHEMA_VERSION = "littleboy.soc.layer2.orchestrator_decision.v8"
L1_SCHEMA_VERSION = "littleboy.soc.layer1.agent_finding.v4"
RISK_FLOOR_THRESHOLD = 5.0


def _utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_list(value) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def _log_value(log, *keys):
    if isinstance(log, dict):
        for key in keys:
            value = log.get(key)
            if value not in (None, ""):
                return value
    return None


def _entity_lists_from_finding(finding: dict) -> dict:
    entities = finding.get("entities", {}) or {}
    ips = []
    for key in ("ips", "source_ip", "destination_ip"):
        ips.extend(_as_list(entities.get(key)))
    users = []
    for key in ("users", "username"):
        users.extend(_as_list(entities.get(key)))
    hosts = []
    for key in ("hosts", "hostname"):
        hosts.extend(_as_list(entities.get(key)))
    accounts = []
    for key in ("accounts_masked", "account_ref"):
        accounts.extend(_as_list(entities.get(key)))
    endpoints = []
    for key in ("api_endpoints", "endpoint", "url"):
        endpoints.extend(_as_list(entities.get(key)))

    return {
        "users": list(dict.fromkeys(users)),
        "accounts_masked": list(dict.fromkeys(accounts)),
        "hosts": list(dict.fromkeys(hosts)),
        "ips": list(dict.fromkeys(ips)),
        "sessions": _as_list(entities.get("sessions")),
        "api_endpoints": list(dict.fromkeys(endpoints)),
        "transactions_masked": _as_list(entities.get("transactions_masked")),
        "devices": _as_list(entities.get("devices")),
        "data_objects_masked": _as_list(entities.get("data_objects_masked")),
    }


def _merge_entity_lists(findings: list[dict], verified_logs: list[dict] | None = None) -> dict:
    merged = {
        "users": [],
        "accounts_masked": [],
        "hosts": [],
        "ips": [],
        "sessions": [],
        "api_endpoints": [],
        "transactions_masked": [],
        "devices": [],
        "data_objects_masked": [],
    }
    for finding in findings:
        extracted = _entity_lists_from_finding(finding)
        for key, values in extracted.items():
            merged[key].extend(values)

    for log in verified_logs or []:
        source_ip = _log_value(log, "source_ip")
        ecs_url = _log_value(log, "ecs_url_original")
        if source_ip:
            merged["ips"].append(str(source_ip))
        if ecs_url:
            merged["api_endpoints"].append(str(ecs_url))

    return {key: list(dict.fromkeys(values)) for key, values in merged.items()}


def _summarize_findings(findings: list[dict]) -> list[dict]:
    return [
        {
            "agent_id": finding.get("agent_id"),
            "threat_detected": bool(finding.get("threat_detected", False)),
            "capec_id": _primary_capec_id(finding),
            "mitre_attack_id": _primary_attack_id(finding),
            "raw_evidence": str(finding.get("raw_evidence", "")),
        }
        for finding in findings
    ]


def _primary_attack_id(finding: dict) -> str:
    attack_mapping = finding.get("attack_mapping", {}) or {}
    attack_vector_prediction = finding.get("attack_vector_prediction", {}) or {}
    return str(
        finding.get("mitre_attack_id")
        or attack_mapping.get("mitre_technique")
        or attack_vector_prediction.get("attack_id")
        or attack_vector_prediction.get("mitre_attack_id")
        or ""
    ).strip()


def _primary_capec_id(finding: dict) -> str:
    attack_mapping = finding.get("attack_mapping", {}) or {}
    capec_prediction = finding.get("capec_attack_pattern_prediction", {}) or {}
    return str(
        finding.get("capec_id")
        or attack_mapping.get("capec_pattern")
        or capec_prediction.get("capec_id")
        or ""
    ).strip()


def _priority_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _response_mode_from_score(score: float, verified: bool) -> str:
    if score >= 9.0 and verified:
        return "CRISIS"
    if score > RISK_FLOOR_THRESHOLD and verified:
        return "CONTAIN_AND_HUNT"
    if score > RISK_FLOOR_THRESHOLD:
        return "CONTAIN"
    return "MONITOR"


def _target_type_for_action(action_type: str, target_type: str | None = None) -> str:
    normalized = str(target_type or "").lower()
    allowed = {
        "ip", "domain", "host", "user", "account", "session",
        "api_endpoint", "waf_rule", "ticket", "dashboard", "other",
    }
    if normalized in allowed:
        return normalized
    if action_type in ("block_ip",):
        return "ip"
    if action_type in ("block_domain",):
        return "domain"
    if action_type in ("quarantine_host",):
        return "host"
    if action_type in ("force_logout",):
        return "user"
    if action_type in ("disable_account", "revoke_access"):
        return "account"
    if action_type in ("open_ticket",):
        return "ticket"
    if action_type in ("notify_soc",):
        return "dashboard"
    if action_type in ("deploy_waf_virtual_patch",):
        return "waf_rule"
    return "other"


def _stable_mock_embedding(text, size=1024):
    return stable_mock_embedding(text, size=size)


def _vector_db_provider():
    provider = os.getenv("VECTOR_DB_PROVIDER", "").strip().lower()
    if provider:
        return provider
    if os.getenv("OPENSEARCH_ENDPOINT", "").strip():
        return "opensearch"
    return "qdrant"


def _aws_signed_request(method, url, body=None, service=None, timeout=3):
    import requests
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.session import Session

    payload = json.dumps(body) if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    request = AWSRequest(method=method, url=url, data=payload, headers=headers)
    region = os.getenv("AWS_REGION", "us-east-1")
    parsed = urlparse(url)
    inferred_service = "aoss" if ".aoss." in parsed.netloc else "es"
    credentials = Session().get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials are not available for OpenSearch request signing")
    SigV4Auth(credentials.get_frozen_credentials(), service or os.getenv("OPENSEARCH_SERVICE", inferred_service), region).add_auth(request)
    return requests.request(method, url, data=payload, headers=dict(request.headers), timeout=timeout)


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
        self.llm_provider = LLM_PROVIDER
        self.system_prompt = ""

        # Load L2 standalone system prompt
        if os.path.exists(SYSTEM_PROMPT_PATH):
            with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
                self.system_prompt = f.read()
            logger.info("Loaded Layer 2 Orchestrator system prompt.")
        else:
            logger.error(f"System prompt file not found at: {SYSTEM_PROMPT_PATH}")

        if LLM_ENABLED and self.llm_provider == "bedrock":
            from botocore.config import Config
            from botocore.session import Session

            self.client = Session().create_client(
                "bedrock-runtime",
                region_name=BEDROCK_REGION,
                config=Config(
                    connect_timeout=min(LLM_TIMEOUT_SECONDS, 10),
                    read_timeout=LLM_TIMEOUT_SECONDS,
                    retries={"max_attempts": 2, "mode": "standard"},
                ),
            )
            logger.info(f"Bedrock Qwen client initialized: {BEDROCK_MODEL_ID} ({BEDROCK_REGION})")
        elif LLM_ENABLED and DASHSCOPE_API_KEY:
            self.client = OpenAI(
                api_key=DASHSCOPE_API_KEY,
                base_url=QWEN_BASE_URL
            )
            logger.info(f"DashScope Qwen client initialized: {QWEN_BASE_URL} (Model: {QWEN_MODEL_NAME})")
        else:
            logger.warning("LLM disabled or credentials/provider not configured. Operating in Suggest-Only Local Fallback mode.")

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

    def _invoke_bedrock_qwen(self, user_prompt: str) -> str:
        payload = {
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"{user_prompt}\n\nReturn only a valid JSON object."},
            ],
            "max_tokens": LLM_MAX_TOKENS,
            "temperature": 0,
        }
        response = self.client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        data = json.loads(response["body"].read())
        return self._extract_bedrock_text(data)

    def _extract_bedrock_text(self, data: dict) -> str:
        candidates = [
            data.get("output_text"),
            data.get("text"),
            data.get("response"),
        ]

        output_message = data.get("output", {}).get("message", {})
        for item in output_message.get("content", []) if isinstance(output_message, dict) else []:
            if isinstance(item, dict):
                candidates.append(item.get("text"))

        for item in data.get("content", []) if isinstance(data.get("content"), list) else []:
            if isinstance(item, dict):
                candidates.append(item.get("text"))

        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
            candidates.append(message.get("content") or choices[0].get("text"))

        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        raise ValueError(f"Could not extract text from Bedrock response keys: {list(data.keys())}")

    def _invoke_llm(self, user_prompt: str) -> str:
        if self.llm_provider == "bedrock":
            return self._invoke_bedrock_qwen(user_prompt)

        response = self.client.chat.completions.create(
            model=QWEN_MODEL_NAME,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            timeout=LLM_TIMEOUT_SECONDS
        )
        return response.choices[0].message.content

    def _query_vector_db_playbooks(self, text: str) -> str:
        """Query Qdrant to get related playbooks for Layer 2 decision context."""
        provider = _vector_db_provider()
        if provider == "disabled":
            return ""

        qdrant_url = os.getenv("QDRANT_URL", "http://qdrant:6333")
        opensearch_endpoint = os.getenv("OPENSEARCH_ENDPOINT", "").rstrip("/")
            
        try:
            import requests
            vector = get_text_embedding(text, dashscope_api_key=DASHSCOPE_API_KEY)

            if provider == "opensearch":
                if not opensearch_endpoint:
                    return ""
                index_name = os.getenv("OPENSEARCH_L2_INDEX", "l2-playbooks")
                search_payload = {
                    "size": 2,
                    "query": {
                        "knn": {
                            "embedding": {
                                "vector": vector,
                                "k": 2
                            }
                        }
                    },
                    "_source": True
                }
                search_resp = _aws_signed_request(
                    "POST",
                    f"{opensearch_endpoint}/{index_name}/_search",
                    body=search_payload,
                    timeout=3,
                )
                if search_resp.status_code not in (200, 201):
                    return ""
                hits = search_resp.json().get("hits", {}).get("hits", [])
                results = [{"payload": hit.get("_source", {}).get("payload", hit.get("_source", {}))} for hit in hits]
            else:
                if not qdrant_url:
                    return ""
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
            dict matching littleboy.soc.layer2.orchestrator_decision.v8
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
        primary_attack_id = _primary_attack_id(primary_finding)
        primary_capec_id = _primary_capec_id(primary_finding)

        # Base score lookup
        base_score = 5.0
        score_source = "fallback"
        score_source_ref = primary_attack_id or primary_capec_id or None
        if primary_attack_id:
            row = self.risk_kb.lookup_attack(primary_attack_id)
            if row:
                base_score = float(row.get("base_threat_score_0_10", 5.0))
                score_source = "risk_scoring/attack_vector_risk_scores.md"
        elif primary_capec_id:
            row = self.risk_kb.lookup_capec(primary_capec_id)
            if row:
                base_score = float(row.get("base_threat_score_0_10", 5.0))
                score_source = "risk_scoring/capec_risk_scores.md"

        # Determine asset criticality from verified logs
        asset_crit = "medium"
        for log in verified_logs:
            crit = _log_value(log, "assetCritical", "asset_criticality")
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
        priority = _priority_from_score(final_score)
        response_mode = _response_mode_from_score(final_score, verified)

        # 1. Lookup Offline Risk Scores for prompt enrichment
        enriched_risk_context = []
        for f in findings:
            attack_id = _primary_attack_id(f)
            capec_id = _primary_capec_id(f)
            
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
        query_text = (
            f"mitre_attack_id: {primary_attack_id}, capec_id: {primary_capec_id}, "
            f"evidence: {primary_finding.get('raw_evidence', '')}, "
            f"prediction: {json.dumps(primary_finding.get('attack_pattern_prediction', {}), ensure_ascii=False)}"
        )
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

Please correlate the findings, verify the logs, look up the base threat scores, calculate final risk scores, apply red-line security policies, and output a valid JSON decision conforming to schema version `{L2_SCHEMA_VERSION}`.
"""

        # 3. Call LLM (with Timeout Guard)
        if self.client and LLM_ENABLED:
            try:
                logger.info(f"Calling {self.llm_provider} Qwen for L2 Orchestration (Timeout: {LLM_TIMEOUT_SECONDS}s)...")
                raw_response = self._invoke_llm(user_prompt)
                logger.info("Successfully received response from Qwen Orchestrator.")
                
                # Parse and validate response
                decision_dict = json.loads(raw_response)
                
                # Strip markdown codeblocks if LLM returned them inside JSON or string format
                if isinstance(decision_dict, str):
                    decision_dict = self._clean_json_string(decision_dict)

                # Dynamically recalculate/verify risk scoring
                scoring = decision_dict.get("scoring", {})
                scoring["score_source"] = score_source
                scoring["score_source_ref"] = score_source_ref
                scoring.setdefault("score_table_calibration_reason", "Runtime SOAR recalculation from offline risk table and independent verification state.")
                scoring["base_threat_score_0_10"] = base_score
                scoring["asset_criticality_multiplier"] = mult
                scoring["raw_context_risk_0_10"] = raw_risk
                scoring["risk_cap_applied"] = True
                scoring["risk_cap_0_10"] = risk_cap
                scoring["risk_cap_reason"] = f"Verification strength is {v_strength}"
                scoring["final_risk_score_0_10"] = final_score
                scoring["priority"] = priority
                scoring["response_mode"] = response_mode
                scoring.setdefault("score_rationale", [])
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
                        # Enrich each resolved action with metadata expected by v8 schema
                        for a in structured_actions:
                            a["timestamp"] = a.get("timestamp") or _utc_now()
                            a["priority"] = a.get("priority") or priority
                            a["ttl_minutes"] = 60 if a.get("phase") == "contain" else None
                            a["expires_at"] = a.get("expires_at")
                            a["rollback_plan"] = "Revert firewall block" if a["action_type"] == "block_ip" else "Restore network interfaces" if a["action_type"] == "quarantine_host" else "None"
                            a["playbook_source"] = playbook_id
                            a["risk_if_wrong"] = "medium" if a.get("phase") == "contain" else "low"
                            a["evidence_refs"] = a.get("evidence_refs", [])
                            target = a.get("target", {})
                            target["type"] = _target_type_for_action(a.get("action_type"), target.get("type"))
                            a["target"] = target
                            if a.get("status") == "pending":
                                a["status"] = "ready_for_execution" if a.get("approval_mode") == "AUTO" else "queued_for_approval"
                        decision_dict["actions"] = structured_actions
                
                decision_dict = self._coerce_v8_decision(
                    decision_dict, findings, verified_logs, incident_id, priority,
                    final_score, response_mode, v_strength
                )

                # Validate output matches v8 schema using Pydantic
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
                    primary_capec_id=primary_capec_id, score_source=score_source,
                    score_source_ref=score_source_ref, response_mode=response_mode
                )
        else:
            return self._generate_fallback_decision(
                findings, verified_logs, "LLM client disabled or api key missing",
                incident_id=incident_id, base_score=base_score, mult=mult,
                raw_risk=raw_risk, risk_cap=risk_cap, final_score=final_score,
                priority=priority, has_threat=has_threat, primary_attack_id=primary_attack_id,
                primary_capec_id=primary_capec_id, score_source=score_source,
                score_source_ref=score_source_ref, response_mode=response_mode
            )

    def _clean_json_string(self, text: str) -> dict:
        # Strip markdown ```json ... ``` blocks
        cleaned = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        return json.loads(cleaned.strip())

    def _coerce_v8_decision(self, decision: dict, findings: list, verified_logs: list,
                            incident_id: str, priority: str, final_score: float,
                            response_mode: str, verification_strength: str) -> dict:
        timestamp = decision.get("timestamp") or _utc_now()
        verified_entities = _merge_entity_lists(findings, verified_logs)

        decision["schema_version"] = L2_SCHEMA_VERSION
        decision["timestamp"] = timestamp
        decision["orchestrator"] = {
            "orchestrator_id": "layer2_orchestrator_soar",
            "orchestrator_name": "Layer 2 - Orchestrator / SOAR Decision Engine",
            "mode": "correlation_context_policy_playbook_execution",
        }

        decision["input_summary"] = {
            "incident_id": decision.get("input_summary", {}).get("incident_id", incident_id),
            "source_topic": decision.get("input_summary", {}).get("source_topic", "l1.agent.findings"),
            "output_topic": decision.get("input_summary", {}).get("output_topic", "soar.decisions"),
            "layer1_schema_version": L1_SCHEMA_VERSION,
            "findings": _summarize_findings(findings),
        }

        correlation = decision.setdefault("correlation", {})
        correlation.setdefault("correlation_state", "confirmed" if len(findings) > 1 else "none")
        correlation.setdefault("same_attack_assessment", len(findings) > 1)
        correlation.setdefault("correlated_agent_ids", [f.get("agent_id") for f in findings if f.get("agent_id")])
        correlation.setdefault("conflicting_agent_ids", [])
        correlation.setdefault("unrelated_findings", [])
        correlation.setdefault("correlation_rationale", ["Layer 2 normalized correlation record."])
        correlation_keys = correlation.setdefault("correlation_keys", {})
        correlation_keys.setdefault("entities", verified_entities["ips"] + verified_entities["users"] + verified_entities["hosts"])
        correlation_keys.setdefault("time_window", {"start": timestamp, "end": timestamp})
        correlation_keys.setdefault("mitre_attack_ids", [_primary_attack_id(f) for f in findings if _primary_attack_id(f)])
        correlation_keys.setdefault("capec_ids", [_primary_capec_id(f) for f in findings if _primary_capec_id(f)])
        correlation_keys.setdefault("evidence_terms", ["runtime_normalized"])

        verification = decision.setdefault("l2_independent_verification", {})
        verification.setdefault("performed", True)
        verification.setdefault("required", True)
        verification.setdefault("verification_state", "confirmed" if verified_logs else "insufficient")
        verification.setdefault("log_queries_or_refs", ["postgres://log_entries"] if verified_logs else [])
        verification.setdefault("confirmed_entities", verified_entities["ips"] + verified_entities["users"] + verified_entities["hosts"])
        verification.setdefault("contradicting_evidence", [])
        verification.setdefault("verification_strength", verification_strength)
        verification.setdefault("rationale", ["Independent verification normalized by SOAR runtime."])
        normalized_sources = []
        allowed_source_types = {
            "clean_log", "raw_log", "siem", "edr", "waf", "api_gateway", "iam",
            "network", "database", "threat_intel", "vector_db", "asset_inventory",
            "opa", "other",
        }
        for source in verification.get("verification_sources", []):
            source_type = source.get("source_type", "database")
            if source_type not in allowed_source_types:
                source_type = "other"
            normalized_sources.append({
                "source_type": source_type,
                "source_ref": source.get("source_ref"),
                "matched_observation": source.get("matched_observation"),
                "query_status": source.get("query_status", "matched"),
                "freshness_seconds": source.get("freshness_seconds"),
                "last_seen_at": source.get("last_seen_at"),
                "error_ref": source.get("error_ref"),
            })
        if not normalized_sources and verified_logs:
            normalized_sources = [
                {
                    "source_type": "database",
                    "source_ref": "postgres://log_entries",
                    "matched_observation": f"Found {len(verified_logs)} corroborating clean log record(s).",
                    "query_status": "matched",
                    "freshness_seconds": None,
                    "last_seen_at": verified_logs[0].get("timestamp"),
                    "error_ref": None,
                }
            ]
        verification["verification_sources"] = normalized_sources

        verified_case = decision.setdefault("verified_case", {})
        verified_case.setdefault("threat_confirmed", bool(verified_logs))
        verified_case.setdefault("title", "Layer 2 Runtime Decision")
        verified_case.setdefault("summary", "Layer 2 normalized decision from available findings and verification context.")
        verified_case.setdefault("verified_techniques", [_primary_attack_id(f) for f in findings if _primary_attack_id(f)])
        verified_case.setdefault("expanded_techniques", verified_case.get("verified_techniques", []))
        verified_case.setdefault("verified_tactics", [])
        verified_case.setdefault("verified_capec", [_primary_capec_id(f) for f in findings if _primary_capec_id(f)])
        existing_entities = verified_case.get("entities", {}) if isinstance(verified_case.get("entities", {}), dict) else {}
        verified_case["entities"] = _merge_entity_lists([], [])
        for key in verified_case["entities"].keys():
            verified_case["entities"][key] = _as_list(existing_entities.get(key))
        for key, values in verified_entities.items():
            if not verified_case["entities"].get(key):
                verified_case["entities"][key] = values
        verified_case.setdefault("evidence_refs", ["postgres://log_entries"] if verified_logs else [])
        verified_case.setdefault("assumptions", [])

        scoring = decision.setdefault("scoring", {})
        scoring.setdefault("score_source", "fallback")
        scoring.setdefault("score_source_ref", None)
        scoring.setdefault("score_table_calibration_reason", "Runtime normalized fallback scoring.")
        scoring.setdefault("base_threat_score_0_10", final_score)
        scoring.setdefault("asset_criticality_multiplier", 1.0)
        scoring.setdefault("raw_context_risk_0_10", final_score)
        scoring.setdefault("risk_cap_applied", False)
        scoring.setdefault("risk_cap_0_10", None)
        scoring.setdefault("risk_cap_reason", None)
        scoring.setdefault("final_risk_score_0_10", final_score)
        scoring.setdefault("priority", priority)
        scoring.setdefault("response_mode", response_mode)
        scoring.setdefault("score_rationale", [])

        banking_impact = decision.setdefault("banking_impact", {})
        for key in (
            "swift_or_payment_involved", "core_banking_involved", "customer_data_involved",
            "atm_or_hsm_involved", "privileged_identity_involved", "backup_or_recovery_involved",
            "security_control_involved", "fraud_control_involved",
        ):
            banking_impact.setdefault(key, False)
        banking_impact.setdefault("business_criticality", "medium")
        banking_impact.setdefault("impact_rationale", [])

        policy = decision.setdefault("policy_guardrails", {})
        policy.setdefault("opa_required", True)
        policy.setdefault("opa_result", "not_evaluated")
        policy.setdefault("policy_decision_refs", [])
        policy.setdefault("red_lines_triggered", [])
        policy.setdefault("whitelist_hits", [])
        policy.setdefault("manual_only_reasons", [])
        policy.setdefault("time_bound_required", True)
        policy.setdefault("rollback_required", True)

        actions = []
        allowed_statuses = {
            "suggested", "ready_for_execution", "executed", "queued_for_policy_check",
            "queued_for_approval", "blocked_by_policy", "manual_only",
            "not_applicable", "failed", "rolled_back",
        }
        allowed_approval_modes = {"AUTO", "APPROVAL_REQUIRED", "MANUAL_ONLY"}
        for action in decision.get("actions", []):
            action_type = action.get("action_type", "other")
            if action_type == "deploy_waf_rule":
                action_type = "deploy_waf_virtual_patch"
            phase = action.get("phase", "contain")
            target = action.get("target", {}) if isinstance(action.get("target", {}), dict) else {}
            status = action.get("status", "suggested")
            if status == "pending":
                status = "ready_for_execution" if action.get("approval_mode") == "AUTO" else "queued_for_approval"
            if status not in allowed_statuses:
                status = "suggested"
            approval_mode = action.get("approval_mode", "APPROVAL_REQUIRED")
            if approval_mode not in allowed_approval_modes:
                approval_mode = "APPROVAL_REQUIRED"
            actions.append({
                "action_id": action.get("action_id"),
                "timestamp": action.get("timestamp") or timestamp,
                "priority": action.get("priority") or priority,
                "phase": phase,
                "action_type": action_type if action_type in {
                    "preserve_logs", "add_watchlist", "raise_monitoring", "create_hunt",
                    "block_ip", "block_domain", "deploy_waf_virtual_patch", "quarantine_host",
                    "force_logout", "disable_account", "limit_network", "revoke_access",
                    "open_ticket", "notify_soc", "other",
                } else "other",
                "target": {
                    "type": _target_type_for_action(action_type, target.get("type")),
                    "value_masked": target.get("value_masked"),
                },
                "approval_mode": approval_mode,
                "status": status,
                "ttl_minutes": action.get("ttl_minutes"),
                "expires_at": action.get("expires_at"),
                "rollback_plan": action.get("rollback_plan"),
                "evidence_refs": action.get("evidence_refs", []),
                "playbook_source": action.get("playbook_source"),
                "rationale": action.get("rationale"),
                "risk_if_wrong": action.get("risk_if_wrong", "medium" if phase == "contain" else "low"),
            })
        decision["actions"] = actions

        automation = decision.setdefault("automation_control", {})
        execution_window = automation.setdefault("execution_window", {})
        execution_window.setdefault("enabled", True)
        execution_window.setdefault("timezone", DEFAULT_TIMEZONE)
        execution_window.setdefault("start_local", DEFAULT_EXECUTION_WINDOW_START)
        execution_window.setdefault("end_local", DEFAULT_EXECUTION_WINDOW_END)
        execution_window.setdefault("in_window", False)
        execution_window.setdefault("outside_window_behavior", "suggest_only_and_report")
        
        autopilot_enabled = SOC_AUTOPILOT_ENABLED
        try:
            from config import DATABASE_URL
            import psycopg2
            conn = psycopg2.connect(DATABASE_URL)
            with conn.cursor() as cursor:
                cursor.execute("SELECT value FROM system_settings WHERE key = 'soc_autopilot_enabled'")
                row = cursor.fetchone()
                if row:
                    autopilot_enabled = (row[0].strip().lower() == "true")
            conn.close()
        except Exception as dbe:
            logger.warning(f"Failed to fetch dynamic autopilot setting from PostgreSQL: {dbe}")

        automation.setdefault("soc_autopilot_enabled", autopilot_enabled)
        automation.setdefault("mode", "execute" if autopilot_enabled else "suggest_only")
        automation.setdefault("default_mode", "suggest_only")
        automation.setdefault("auto_containment_path", "l2_verified" if verified_case.get("threat_confirmed") else "none")
        automation.setdefault("next_review_minutes", 60)
        automation.setdefault("auto_unblock_after_mins", None)
        automation.setdefault("rollback_support", True)
        containment_actions = [a for a in actions if a.get("phase") == "contain"]
        gates = {
            "threat_confirmed": bool(verified_case.get("threat_confirmed")),
            "l2_verification_performed": bool(verification.get("performed")),
            "verification_confirmed": verification.get("verification_state") == "confirmed",
            "verification_supported_or_strong": verification.get("verification_strength") in ("supported", "strong"),
            "risk_above_floor": final_score > RISK_FLOOR_THRESHOLD,
            "opa_allow": policy.get("opa_result") == "allow",
            "soc_autopilot_on": bool(automation.get("soc_autopilot_enabled")),
            "execution_window_open": bool(execution_window.get("in_window")),
            "action_scoped_timebound_reversible": bool(containment_actions) and all(a.get("ttl_minutes") is not None and a.get("rollback_plan") for a in containment_actions),
            "rollback_available": bool(automation.get("rollback_support")),
            "dangerous_now_behavior": bool(verified_case.get("threat_confirmed")) and final_score > RISK_FLOOR_THRESHOLD,
            "verified_target_entity": bool(verified_entities["ips"] or verified_entities["hosts"] or verified_entities["users"]),
        }
        automation["auto_containment_gates"] = {**automation.get("auto_containment_gates", {}), **gates}
        automation["auto_containment_eligible"] = all(automation["auto_containment_gates"].values())
        automation.setdefault("containment_gate_rationale", [])

        playbook_routing = decision.setdefault("playbook_routing", {})
        playbook_routing.setdefault("activated_playbooks", [])
        playbook_routing["not_selected"] = [
            item if isinstance(item, dict) else {"playbook_id": str(item), "reason": "Not selected"}
            for item in playbook_routing.get("not_selected", [])
        ]

        decision_summary = decision.setdefault("decision", {})
        floor = decision_summary.setdefault("risk_response_floor", {})
        floor.setdefault("triggered", final_score > RISK_FLOOR_THRESHOLD)
        floor.setdefault("threshold", RISK_FLOOR_THRESHOLD)
        floor.setdefault("completed", bool(actions) or final_score <= RISK_FLOOR_THRESHOLD)
        floor.setdefault("required_actions", ["preserve_logs", "raise_monitoring", "open_ticket", "notify_soc"])
        floor.setdefault("performed_actions", [])
        floor.setdefault("blocked_actions", [])
        floor.setdefault("rationale", [])
        floor.setdefault("execution_note", None)
        decision_summary.setdefault("final_decision", "queue_approval" if final_score > RISK_FLOOR_THRESHOLD else "suggest_only")
        decision_summary.setdefault("execution_mode", "suggest_only")
        decision_summary.setdefault("justification", "Layer 2 runtime normalized the decision to v8.")
        decision_summary.setdefault("summary_for_soc", verified_case.get("summary"))

        predictive = decision.setdefault("predictive_defense", {})
        predictive.setdefault("predicted_techniques", [])
        predictive.setdefault("temporary_detections", [])
        predictive.setdefault("watch_for_next", [])

        output = decision.setdefault("output_and_notification", {})
        output.setdefault("suggested_actions", [])
        output.setdefault("executed_actions", [])
        output.setdefault("notification_targets", [])
        output.setdefault("ticket_payload", {
            "title": verified_case.get("title"),
            "priority": priority,
            "body": verified_case.get("summary"),
            "labels": [],
        })
        output["ticket_payload"].setdefault("labels", [])

        feedback = decision.setdefault("soc_feedback_controls", {})
        feedback.setdefault("allowed_actions", ["confirm", "undo", "rollback", "extend_investigation", "comment"])
        feedback.setdefault("callback_required", True)
        feedback.setdefault("callback_channel", "api_call")

        audit = decision.setdefault("audit", {})
        audit.setdefault("immutable_log_required", True)
        audit_events = []
        for event in audit.get("audit_events", []):
            audit_events.append({
                "event_type": event.get("event_type", "decision"),
                "event_time": event.get("event_time") or timestamp,
                "actor": event.get("actor", "layer2_orchestrator_soar"),
                "command_signature_ref": event.get("command_signature_ref"),
                "details": event.get("details"),
                "result": event.get("result"),
            })
        audit["audit_events"] = audit_events
        audit.setdefault("compliance_tags", ["ISO27001", "PCI-DSS"])

        safety = decision.setdefault("safety", {})
        safety.setdefault("prompt_injection_observed", False)
        safety.setdefault("prompt_injection_evidence_masked", [])
        safety.setdefault("log_instruction_ignored", True)
        safety.setdefault("sensitive_values_masked", True)
        safety.setdefault("no_destructive_action_selected", True)

        quality = decision.setdefault("quality", {})
        quality.setdefault("missing_fields", [])
        quality.setdefault("limitations", [])
        quality.setdefault("requires_human_review", False)

        return decision

    def _generate_fallback_decision(self, findings: list, verified_logs: list, error_reason: str,
                                    incident_id: str = None, base_score: float = None, mult: float = None,
                                    raw_risk: float = None, risk_cap: float = None, final_score: float = None,
                                    priority: str = None, has_threat: bool = None, primary_attack_id: str = None,
                                    primary_capec_id: str = None, score_source: str = "fallback",
                                    score_source_ref: str = None, response_mode: str = None) -> dict:
        """Fallback to a safe Suggest-Only decision matching v8 schema when Qwen fails."""
        logger.info("Generating local fallback suggest-only decision.")
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Simple rule-based logic for fallback
        if has_threat is None:
            has_threat = any(f.get("threat_detected", False) for f in findings)
        primary_finding = findings[0] if findings else {}
        if primary_attack_id is None:
            primary_attack_id = _primary_attack_id(primary_finding) or "T1059"
        if primary_capec_id is None:
            primary_capec_id = _primary_capec_id(primary_finding)
        if incident_id is None:
            incident_id = f"INC-FALLBACK-{int(time.time())}"
            
        # Determine asset criticality from verified logs
        asset_crit = "medium"
        for log in verified_logs:
            crit = _log_value(log, "assetCritical", "asset_criticality")
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
            priority = _priority_from_score(final_score)
        if response_mode is None:
            response_mode = _response_mode_from_score(final_score, verified)

        # Determine the best fallback playbook and execute via PlaybookRunner
        fallback_playbook_id = "PB-WEB-EDGE"
        if "ransom" in primary_attack_id.lower() or primary_attack_id in ["T1486", "T1490", "T1489", "T1485"]:
            fallback_playbook_id = "PB-RANSOM-IMPACT"
        elif "cred" in primary_attack_id.lower() or primary_attack_id in ["T1003", "T1110"]:
            fallback_playbook_id = "PB-CRED"
            
        merged_entities = _merge_entity_lists(findings, verified_logs)
        source_ip = merged_entities["ips"][0] if merged_entities["ips"] else "127.0.0.1"
        users_list = merged_entities["users"] or ["Administrator"]
        hosts_list = merged_entities["hosts"] or ["WEB-PROD-FALLBACK"]
        accounts_list = merged_entities["accounts_masked"] or ["admin_masked"]
        
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
            "schema_version": L2_SCHEMA_VERSION,
            "timestamp": timestamp,
            "orchestrator": {
                "orchestrator_id": "layer2_orchestrator_soar",
                "orchestrator_name": "Layer 2 - Orchestrator / SOAR Decision Engine",
                "mode": "correlation_context_policy_playbook_execution"
            },
            "input_summary": {
                "incident_id": incident_id,
                "source_topic": "l1.agent.findings",
                "output_topic": "soar.decisions",
                "layer1_schema_version": L1_SCHEMA_VERSION,
                "findings": _summarize_findings(findings)
            },
            "correlation": {
                "correlation_state": "confirmed" if len(findings) > 1 else "none",
                "same_attack_assessment": len(findings) > 1,
                "correlated_agent_ids": [f.get("agent_id") for f in findings if f.get("agent_id")],
                "conflicting_agent_ids": [],
                "correlation_keys": {
                    "entities": [source_ip],
                    "time_window": {"start": timestamp, "end": timestamp},
                    "mitre_attack_ids": [_primary_attack_id(f) for f in findings if _primary_attack_id(f)],
                    "capec_ids": [_primary_capec_id(f) for f in findings if _primary_capec_id(f)],
                    "evidence_terms": ["fallback"]
                },
                "unrelated_findings": [],
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
                        "matched_observation": f"Found {len(verified_logs)} corroborating log entries in database verifier.",
                        "query_status": "matched",
                        "freshness_seconds": None,
                        "last_seen_at": verified_logs[0].get("timestamp") if verified_logs else None,
                        "error_ref": None
                    }
                ] if verified else [],
                "log_queries_or_refs": ["postgres://log_entries"] if verified else [],
                "confirmed_entities": [source_ip] if verified else [],
                "contradicting_evidence": [],
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
                "entities": merged_entities,
                "evidence_refs": ["postgres://log_entries"] if verified else [],
                "assumptions": []
            },
            "scoring": {
                "score_source": score_source,
                "score_source_ref": score_source_ref or primary_attack_id or primary_capec_id or None,
                "score_table_calibration_reason": "Local fallback recalculated risk from offline risk table and verification cap.",
                "base_threat_score_0_10": base_score,
                "asset_criticality_multiplier": mult,
                "raw_context_risk_0_10": raw_risk,
                "risk_cap_applied": True,
                "risk_cap_0_10": risk_cap,
                "risk_cap_reason": f"Fallback cap applied: strength is {v_strength}",
                "final_risk_score_0_10": final_score,
                "priority": priority,
                "response_mode": response_mode,
                "score_rationale": [f"Fallback score computed due to orchestrator error: {error_reason}"]
            },
            "banking_impact": {
                "swift_or_payment_involved": "swift" in primary_finding.get("raw_evidence", "").lower(),
                "core_banking_involved": "core" in primary_finding.get("raw_evidence", "").lower(),
                "customer_data_involved": "customer" in primary_finding.get("raw_evidence", "").lower(),
                "atm_or_hsm_involved": "atm" in primary_finding.get("raw_evidence", "").lower() or "hsm" in primary_finding.get("raw_evidence", "").lower(),
                "privileged_identity_involved": False,
                "backup_or_recovery_involved": False,
                "security_control_involved": False,
                "fraud_control_involved": False,
                "business_criticality": "medium",
                "impact_rationale": ["Local fallback inferred banking impact from masked evidence text."]
            },
            "policy_guardrails": {
                "opa_required": True,
                "opa_result": "allow",
                "policy_decision_refs": [],
                "red_lines_triggered": [],
                "whitelist_hits": [],
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
                    "in_window": True,
                    "outside_window_behavior": "suggest_only_and_report"
                },
                "next_review_minutes": 60,
                "auto_containment_gates": {
                    "threat_confirmed": False,
                    "l2_verification_performed": True,
                    "verification_confirmed": False,
                    "verification_supported_or_strong": False,
                    "risk_above_floor": final_score > RISK_FLOOR_THRESHOLD,
                    "opa_allow": True,
                    "soc_autopilot_on": False,
                    "execution_window_open": True,
                    "action_scoped_timebound_reversible": False,
                    "rollback_available": True,
                    "dangerous_now_behavior": False,
                    "verified_target_entity": bool(source_ip),
                },
                "auto_containment_eligible": False,
                "containment_gate_rationale": ["Fallback mode requires human analyst confirmation."],
                "auto_unblock_after_mins": None,
                "rollback_support": True
            },
            "playbook_routing": {
                "activated_playbooks": [
                    {
                        "playbook_id": fallback_playbook_id,
                        "trigger_type": "anomaly",
                        "trigger_value": primary_attack_id,
                        "mode": response_mode,
                        "rationale": "Local fallback selected the closest structured playbook."
                    }
                ],
                "not_selected": []
            },
            "decision": {
                "final_decision": "queue_approval" if verified else "suggest_only",
                "execution_mode": "suggest_only",
                "risk_response_floor": {
                    "triggered": final_score > RISK_FLOOR_THRESHOLD,
                    "threshold": RISK_FLOOR_THRESHOLD,
                    "completed": True,
                    "required_actions": ["preserve_logs", "open_ticket", "notify_soc"],
                    "performed_actions": ["preserve_logs"] if verified else [],
                    "blocked_actions": [],
                    "rationale": ["Fallback preserves and reports but does not auto-contain."],
                    "execution_note": None
                },
                "justification": f"Fallback alert created due to orchestrator error: {error_reason}",
                "summary_for_soc": f"Local SOAR fallback analyzed finding for {primary_attack_id}."
            },
            "actions": actions,
            "predictive_defense": {
                "predicted_techniques": [],
                "temporary_detections": [],
                "watch_for_next": []
            },
            "output_and_notification": {
                "suggested_actions": [],
                "executed_actions": [],
                "notification_targets": ["soc_dashboard"],
                "ticket_payload": {
                    "title": f"Fallback alert - {primary_attack_id}",
                    "priority": priority,
                    "body": f"Local SOAR fallback analyzed findings. Primary finding details: {primary_finding.get('raw_evidence')}",
                    "labels": [fallback_playbook_id, "fallback"]
                }
            },
            "soc_feedback_controls": {
                "allowed_actions": ["confirm", "undo", "rollback", "extend_investigation", "comment"],
                "callback_required": True,
                "callback_channel": "api_call"
            },
            "audit": {
                "immutable_log_required": True,
                "audit_events": [
                    {
                        "event_type": "decision",
                        "event_time": timestamp,
                        "actor": "layer2_orchestrator_soar",
                        "command_signature_ref": None,
                        "details": f"Local fallback triggered: {error_reason}"
                    }
                ],
                "compliance_tags": ["ISO27001", "PCI-DSS"]
            },
            "safety": {
                "prompt_injection_observed": False,
                "prompt_injection_evidence_masked": [],
                "log_instruction_ignored": True,
                "sensitive_values_masked": True,
                "no_destructive_action_selected": True
            },
            "quality": {
                "missing_fields": [],
                "limitations": [f"LLM call failed/timed out. Local fallback used: {error_reason}"],
                "requires_human_review": True
            }
        }
        
        return self._coerce_v8_decision(
            fallback_decision, findings, verified_logs, incident_id, priority,
            final_score, response_mode, v_strength
        )
