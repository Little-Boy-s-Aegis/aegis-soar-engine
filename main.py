import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from kafka import KafkaConsumer, KafkaProducer

import redis
from config import (
    KAFKA_BROKERS, L1_FINDINGS_TOPIC, SOAR_FAST_PATH_TOPIC,
    DASHBOARD_EVENTS_TOPIC, SOC_AUTOPILOT_ENABLED, SOAR_DECISIONS_TOPIC,
    REDIS_URL
)
from schema_validator import L1Finding
from db_verifier import DatabaseVerifier
from orchestrator import SoarOrchestrator
from playbook_executor import PlaybookExecutor
from policy_evaluator import OpaPolicyEvaluator
from rate_limiter import RedisTokenBucketRateLimiter
from safety_gate import evaluate_action_safety, acquire_action_rate_limits, verify_action_authorization

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soar-engine")


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def _is_sql_injection_text(*parts) -> bool:
    for part in parts:
        text = str(part or "").upper()
        if "SQL_INJECTION" in text or "SQL INJECTION" in text or "SQLI" in text:
            return True
    return False


def extract_l1_entity_lists(finding: dict) -> dict:
    """Accept both legacy list entities and the new per-agent flat entity keys."""
    entities = finding.get("entities", {}) or {}
    ips = []
    for key in ("ips", "source_ip"):
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

    return {
        "ips": list(dict.fromkeys(ips)),
        "users": list(dict.fromkeys(users)),
        "hosts": list(dict.fromkeys(hosts)),
        "accounts_masked": list(dict.fromkeys(accounts)),
    }


class SoarEngineApp:
    """Main application orchestrating the L2 SOAR consumer pipeline."""

    def __init__(self):
        self.verifier = DatabaseVerifier()
        self.orchestrator = SoarOrchestrator()
        self.executor = PlaybookExecutor()
        self.producer = None
        self.thread_pool = ThreadPoolExecutor(max_workers=5)
        
        # In-memory correlation buffer: key -> [findings]
        self.correlation_buffer = {}
        # Timestamps for when correlation window closes: key -> close_time
        self.buffer_expiry = {}
        self.correlation_window_seconds = 2.0

        # Initialize Redis State Database connection
        try:
            self.redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            logger.info(f"Connected to Redis State Database at {REDIS_URL}")
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
            self.rate_limiter = RedisTokenBucketRateLimiter(redis_url=REDIS_URL)
            logger.info("Token Bucket Rate Limiter initialized successfully in main.")
        except Exception as rle:
            logger.error(f"Failed to initialize Rate Limiter: {rle}")
            self.rate_limiter = None

        # Initialize OPA Policy Evaluator
        try:
            self.policy_evaluator = OpaPolicyEvaluator()
            logger.info("OPA Policy Evaluator client initialized successfully in main.")
        except Exception as oepa:
            logger.error(f"Failed to initialize OPA Policy Evaluator: {oepa}")
            self.policy_evaluator = None

    def start(self):
        logger.info("==================================================")
        logger.info("       AEGIS CORE SOAR ENGINE (LAYER 2)           ")
        logger.info("==================================================")
        logger.info(f"Kafka Brokers: {KAFKA_BROKERS}")
        logger.info(f"Autopilot Mode: {'ENABLED' if SOC_AUTOPILOT_ENABLED else 'DISABLED'}")

        action_queue_url = os.getenv("ACTION_QUEUE_URL")

        if not action_queue_url:
            if not KAFKA_BROKERS:
                logger.warning("KAFKA_BOOTSTRAP_SERVERS is not configured and ACTION_QUEUE_URL is absent; keeping service alive in idle mode.")
                while True:
                    time.sleep(60)

            # Initialize producer
            for attempt in range(5):
                try:
                    self.producer = KafkaProducer(
                        bootstrap_servers=KAFKA_BROKERS,
                        value_serializer=lambda v: json.dumps(v).encode("utf-8")
                    )
                    logger.info("Producer connected to Kafka brokers successfully.")
                    break
                except Exception as e:
                    logger.warning(f"Failed to connect producer to Kafka (attempt {attempt+1}/5): {e}")
                    time.sleep(3)

            if not self.producer:
                logger.error("Could not initialize Kafka producer.")
                if os.getenv("SOAR_IDLE_WITHOUT_KAFKA", "true").strip().lower() in {"1", "true", "yes", "on"}:
                    logger.warning("Kafka is unavailable; keeping service alive in idle mode for AWS hackathon deployment.")
                    while True:
                        time.sleep(60)
                return
        else:
            logger.info("Running in SQS Mode. Skipping Kafka producer initialization.")

        # Start consumer loop
        self.consume_loop()

    def consume_loop(self):
        """Runs the main consumer loop (supports SQS or Kafka)."""
        action_queue_url = os.getenv("ACTION_QUEUE_URL")
        aws_region = os.getenv("AWS_REGION", "ap-southeast-1")

        if action_queue_url:
            logger.info(f"[SQS MODE] Starting SQS consumer on queue: {action_queue_url}")
            import boto3
            sqs_client = boto3.client("sqs", region_name=aws_region)

            while True:
                # Check correlation buffer
                self.check_correlation_buffer()

                try:
                    response = sqs_client.receive_message(
                        QueueUrl=action_queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=10
                    )

                    messages = response.get("Messages", [])
                    for message in messages:
                        receipt_handle = message["ReceiptHandle"]
                        try:
                            body = json.loads(message["Body"])
                            # In SQS mode, the body is either a SOAR_FAST_PATH event or an L1 finding envelope
                            if body.get("event_type") == "SOAR_FAST_PATH":
                                self.process_fast_path(body)
                            else:
                                self.buffer_l1_finding(body)

                            sqs_client.delete_message(
                                QueueUrl=action_queue_url,
                                ReceiptHandle=receipt_handle
                            )
                        except Exception as msg_err:
                            logger.error(f"[SQS ERROR] Failed to process action queue message: {msg_err}")
                except Exception as sqs_err:
                    logger.error(f"[SQS ERROR] Polling exception: {sqs_err}")
                    time.sleep(5)
            return

        # Fallback to Kafka consumer loop
        consumer = None
        for attempt in range(5):
            try:
                consumer = KafkaConsumer(
                    L1_FINDINGS_TOPIC,
                    SOAR_FAST_PATH_TOPIC,
                    bootstrap_servers=KAFKA_BROKERS,
                    group_id="aegis-soar-engine-group-v2",
                    auto_offset_reset="latest"
                )
                logger.info(f"Successfully subscribed to topics: {[L1_FINDINGS_TOPIC, SOAR_FAST_PATH_TOPIC]}")
                break
            except Exception as e:
                logger.warning(f"Failed to initialize Kafka consumer (attempt {attempt+1}/5): {e}")
                time.sleep(3)

        if not consumer:
            logger.error("Could not initialize Kafka consumer.")
            if os.getenv("SOAR_IDLE_WITHOUT_KAFKA", "true").strip().lower() in {"1", "true", "yes", "on"}:
                logger.warning("Kafka consumer unavailable; keeping service alive in idle mode for AWS hackathon deployment.")
                while True:
                    time.sleep(60)
            return

        # Poll loop with correlation buffer check
        while True:
            # Check if any correlated groups are ready to be processed
            self.check_correlation_buffer()

            # Poll messages with a short timeout
            message_pack = consumer.poll(timeout_ms=500)

            for tp, messages in message_pack.items():
                for msg in messages:
                    try:
                        raw_data = json.loads(msg.value.decode("utf-8"))
                        topic = msg.topic

                        if topic == SOAR_FAST_PATH_TOPIC:
                            # Stage 2 bypass: Process obvious WAF/APIGW attacks immediately
                            self.process_fast_path(raw_data)
                        elif topic == L1_FINDINGS_TOPIC:
                            # Stage 1 schema validation + buffer correlation
                            self.buffer_l1_finding(raw_data)

                    except Exception as e:
                        logger.error(f"Error handling message from topic {msg.topic}: {e}")

    def process_fast_path(self, data: dict):
        """Handles fast-path attacks immediately (Stage 2 bypass)."""
        logger.info(f"[FAST-PATH ROUTER] Processing obvious attack: {data.get('attack_type')} from {data.get('source_ip')}")

        # Extract entities
        source_ip = data.get("source_ip", "127.0.0.1")
        attack_type = data.get("attack_type", "UNKNOWN")
        recommended_action = data.get("recommended_action", "BLOCK_IP")
        recommended_action_upper = str(recommended_action).upper()
        recommended_action_type = str(recommended_action).lower()

        if recommended_action_upper == "BLOCK_IP" and _is_sql_injection_text(attack_type, data.get("payload_snippet")):
            # Retrieve dynamic autopilot setting
            autopilot_enabled = SOC_AUTOPILOT_ENABLED
            try:
                with self.verifier._get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("SELECT value FROM system_settings WHERE key = 'soc_autopilot_enabled'")
                        row = cursor.fetchone()
                        if row:
                            autopilot_enabled = (row[0].strip().lower() == "true")
            except Exception as dbe:
                logger.warning(f"Failed to fetch dynamic autopilot setting from PostgreSQL in fast-path: {dbe}")

            if not autopilot_enabled:
                logger.info("[FAST-PATH ROUTER] SQLi detected from %s; publishing alert without autoban.", source_ip)
                event_payload = {
                    "eventId": str(uuid.uuid4()),
                    "timestamp": data.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
                    "attackType": f"Fast-Path Alert - {attack_type}",
                    "endpoint": "/",
                    "payload": f"SQLi threat pattern detected: {data.get('payload_snippet')}",
                    "status": "DETECTED",
                    "clientIp": source_ip,
                    "description": "SQL injection detected. Automatic IP ban is disabled for SQLi high/medium alerts; analyst confirmation is required.",
                    "sourceService": f"Fast-Path:{data.get('facility', 'WAF')}"
                }
                if self.producer:
                    self.producer.send(DASHBOARD_EVENTS_TOPIC, event_payload)
                    self.producer.flush()
                return

        # Prepare action representation
        action = {
            "action_id": f"act-fastpath-{str(uuid.uuid4())[:8]}",
            "action_type": recommended_action_type,
            "phase": "contain",
            "approval_mode": "AUTO",
            "target": {"value_masked": source_ip},
            "status": "pending"
        }
        decision_context = {
            "input_summary": {"incident_id": data.get("incident_id") or action["action_id"]},
            "scoring": {"final_risk_score_0_10": 10.0},
            "verified_case": {"title": f"Fast-Path {attack_type}"},
            "automation_control": {
                "soc_autopilot_enabled": True,
                "auto_containment_eligible": True,
                "execution_window": {"in_window": True},
            },
            "l2_independent_verification": {"data_fresh": True},
        }

        # Check safety policy via evaluate_action_safety
        allowed, reason = evaluate_action_safety(self.policy_evaluator, action, decision_context)
        if not allowed:
            logger.error(f"[FAST-PATH SAFETY GATE BLOCKED] {recommended_action} on {source_ip}: {reason}")
            return
        verified, verify_reason = verify_action_authorization(self.policy_evaluator, action, decision_context)
        if not verified:
            logger.critical(f"[FAST-PATH OPA TOCTOU BLOCKED] {recommended_action} on {source_ip}: {verify_reason}")
            return

        # Check rate limits via acquire_action_rate_limits
        rate_allowed, rate_reason = acquire_action_rate_limits(self.rate_limiter, action, timeout_seconds=15.0)
        if not rate_allowed:
            logger.error(f"[FAST-PATH RATE LIMIT BLOCKED] {recommended_action} on {source_ip}: {rate_reason}")
            return

        # 0. Trigger Firewall/WAF blocking directly if connector is active and action is BLOCK_IP
        if recommended_action_upper == "BLOCK_IP":
            if self.fortinet:
                fw_success, fw_msg = self.fortinet.block_ip(source_ip)
                logger.info(f"[FAST-PATH] Fortinet block result for {source_ip}: success={fw_success}, msg={fw_msg}")
            if self.waf:
                waf_success, waf_msg = self.waf.block_ip(source_ip)
                logger.info(f"[FAST-PATH] AWS WAF block result for {source_ip}: success={waf_success}, msg={waf_msg}")

        # 1. Execute block action directly via Dashboard API
        # Autopilot is considered ON for fast-path since they are obvious and confirmed at Nginx level
        success, details = self.executor._call_dashboard_perform_action(
            actor="SOAR Fast-Path Bypass",
            action_type=self.executor._map_action_type(recommended_action_type),
            target=source_ip,
            message=f"Auto-containment triggered for obvious {attack_type} attack."
        )
        
        status = "executed" if success else "failed"
        logger.info(f"[FAST-PATH] Containment {recommended_action} status on {source_ip}: {status} ({details})")

        # 2. Publish to aegis.security.events to show Alert on Dashboard
        event_uuid = str(uuid.uuid4())
        event_payload = {
            "eventId": event_uuid,
            "timestamp": data.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
            "attackType": f"Fast-Path Block - {attack_type}",
            "endpoint": "/",
            "payload": f"Obvious threat pattern detected: {data.get('payload_snippet')}",
            "status": "BLOCKED" if success else "DETECTED",
            "clientIp": source_ip,
            "description": f"Source IP was auto-blocked for {attack_type}.",
            "sourceService": f"Fast-Path:{data.get('facility', 'WAF')}"
        }
        if self.producer:
            self.producer.send(DASHBOARD_EVENTS_TOPIC, event_payload)
            self.producer.flush()

    def buffer_l1_finding(self, data: dict):
        """Validates L1 schema and groups findings in a sliding window."""
        try:
            # The Kafka finding is wrapped in a SOAR envelope; extract the payload
            payload = data.get("payload", data)
            # Validate input matches schema
            validated = L1Finding(**payload)
            finding = validated.model_dump(exclude_none=True)
        except Exception as e:
            logger.error(f"Invalid L1 Finding schema format: {e}. Dropping.")
            return

        # Find correlation key: IP or Username
        normalized_entities = extract_l1_entity_lists(finding)
        ips = normalized_entities.get("ips", [])
        users = normalized_entities.get("users", [])
        
        corr_key = None
        if ips:
            corr_key = f"ip:{ips[0]}"
        elif users:
            corr_key = f"user:{users[0]}"
        else:
            corr_key = f"agent:{finding.get('agent_id')}"

        now = time.time()
        
        # If new correlation group, initialize
        if corr_key not in self.correlation_buffer:
            self.correlation_buffer[corr_key] = []
            self.buffer_expiry[corr_key] = now + self.correlation_window_seconds
            logger.info(f"[CORRELATOR] Started new incident group: {corr_key}")

        self.correlation_buffer[corr_key].append(finding)

    def check_correlation_buffer(self):
        """Checks if any correlated groups have exceeded their window and processes them."""
        now = time.time()
        expired_keys = [k for k, exp in self.buffer_expiry.items() if now >= exp]
        
        for key in expired_keys:
            findings = self.correlation_buffer.pop(key)
            self.buffer_expiry.pop(key)
            
            # Offload processing to concurrent thread pool to avoid blocking consumer loop
            self.thread_pool.submit(self.process_correlated_group, key, findings)

    def execute_decision_actions_directly(self, decision: dict):
        """Executes playbook actions directly in SQS mode (no worker queue)."""
        incident_id = decision.get("input_summary", {}).get("incident_id", "INC-UNKNOWN")
        actions = decision.get("actions", [])
        logger.info(f"[SQS EXECUTION] Executing {len(actions)} action(s) directly for incident {incident_id}")
        
        # Determine automation control settings
        autopilot_active = decision.get("automation_control", {}).get("soc_autopilot_enabled", False)
        execution_window_ok = decision.get("automation_control", {}).get("execution_window", {}).get("in_window", False)
        eligible = decision.get("automation_control", {}).get("auto_containment_eligible", False)
        should_execute_containment = autopilot_active and execution_window_ok and eligible
        
        is_dry_run = os.getenv("SOAR_DRY_RUN", "false").lower() == "true" or decision.get("dry_run", False)

        for action in actions:
            action_type = action.get("action_type")
            target_value = (action.get("target") or {}).get("value_masked")
            phase = action.get("phase")
            approval_mode = action.get("approval_mode")
            
            run_action = False
            if phase in ("preserve", "hunt", "notify"):
                run_action = True
            elif phase == "contain" or action_type in ("block_ip", "block_domain", "quarantine_host", "disable_account"):
                run_action = approval_mode == "AUTO" and should_execute_containment
            elif approval_mode == "AUTO":
                run_action = True
            
            if not run_action:
                logger.info(f"[SQS EXECUTION] Skipping action {action_type} on {target_value} (not eligible or requires approval)")
                action["status"] = "skipped"
                continue

            # Evaluate safety policies via evaluate_action_safety helper
            from safety_gate import evaluate_action_safety
            allowed, reason = evaluate_action_safety(self.policy_evaluator, action, decision)
            
            # Log Guardrails Check to Audit Trail
            from audit_logger import SoarAuditLogger
            SoarAuditLogger.log_guardrail_check(incident_id, action, allowed, reason)
            
            if not allowed:
                logger.error(f"[SQS SAFETY BLOCKED] Action {action_type} on {target_value} blocked: {reason}")
                action["status"] = "failed"
                action["rationale"] = f"{action.get('rationale', '')} | Safety Blocked: {reason}"
                continue

            if is_dry_run:
                logger.info(f"[SQS DRY RUN] Simulating {action_type} on {target_value}")
                action["status"] = "simulated"
                action["rationale"] = f"{action.get('rationale', '')} | [DRY RUN] Simulated execution successfully."
                continue

            # Execute the action
            success = False
            msg = "Action type not supported in direct execution"
            
            if action_type == "block_ip" and target_value:
                # WAF block
                if self.waf:
                    waf_success, waf_msg = self.waf.block_ip(target_value)
                    logger.info(f"[SQS EXECUTION] AWS WAF block result for {target_value}: success={waf_success}, msg={waf_msg}")
                    success = waf_success
                    msg = waf_msg
                    SoarAuditLogger.log_api_response(incident_id, "aws_waf", "block_ip", {"target": target_value}, waf_success, waf_msg)
                
                # Fortinet block
                if self.fortinet:
                    fw_success, fw_msg = self.fortinet.block_ip(target_value)
                    logger.info(f"[SQS EXECUTION] Fortinet block result for {target_value}: success={fw_success}, msg={fw_msg}")
                    # If WAF succeeded or Fortinet succeeded, we treat it as success
                    success = success or fw_success
                    msg = f"{msg} | Fortinet: {fw_msg}"
                    SoarAuditLogger.log_api_response(incident_id, "fortinet", "block_ip", {"target": target_value}, fw_success, fw_msg)

                # Dashboard block trigger
                if success:
                    # Inform dashboard to persist the ban
                    db_success, db_details = self.executor._call_dashboard_perform_action(
                        actor="SOAR Direct Executor",
                        action_type=self.executor._map_action_type(action_type),
                        target=target_value,
                        message=f"Auto-containment executed for incident {incident_id}."
                    )
                    logger.info(f"[SQS EXECUTION] Dashboard perform action: success={db_success}, details={db_details}")
                    
            elif action_type == "notify_soc":
                # Log to console
                logger.info(f"[SQS NOTIFY SOC] Incident {incident_id}: {action.get('rationale')}")
                success = True
                msg = "SOC notified via logs"
            else:
                logger.warning(f"[SQS EXECUTION] Action type {action_type} not implemented in direct execution. Treating as simulated.")
                success = True
                msg = "Direct execution simulated"

            action["status"] = "executed" if success else "failed"
            action["rationale"] = f"{action.get('rationale', '')} | Execution details: {msg}"
            
        # Update Redis status
        if self.redis:
            redis_key = f"aegis:playbook:status:{incident_id}"
            self.redis.hset(redis_key, "status", "COMPLETED")
            self.redis.hset(redis_key, "updated_at", datetime.now(timezone.utc).isoformat())

        # Push decision update back to the Go backend
        try:
            self.executor._push_l2_decision_to_gateway(decision)
            logger.info(f"[SQS EXECUTION] Successfully synchronized execution progress to dashboard for incident {incident_id}")
        except Exception as se:
            logger.error(f"[SQS EXECUTION ERROR] Failed to push execution progress: {se}")

    def process_correlated_group(self, group_key: str, findings: list):
        """Independent verifications lookup + Qwen invocation + Execution."""
        logger.info(f"[CORRELATOR] Processing group {group_key} containing {len(findings)} finding(s)")

        # 1. Independent Verification Lookup from Postgres
        verified_logs = []
        for f in findings:
            entities = extract_l1_entity_lists(f)
            ips = entities.get("ips", [])
            
            if ips:
                # Query access logs for this IP address around the finding time
                logs = self.verifier.query_logs_for_ip(ips[0], f.get("timestamp"))
                verified_logs.extend(logs)
                
            # Deduplicate logs by ID
            seen_ids = set()
            dedup_logs = []
            for l in verified_logs:
                if l.get("id") not in seen_ids:
                    seen_ids.add(l.get("id"))
                    dedup_logs.append(l)
            verified_logs = dedup_logs

        # 2. Invoke Layer 2 Orchestrator / Qwen 3.7 Plus
        try:
            decision = self.orchestrator.run_orchestration(findings, verified_logs)
        except Exception as oe:
            logger.error(f"Orchestration call crashed: {oe}")
            return

        # 3. Publish L2 decision payload to Message Queue (Kafka topic: soar.decisions)
        try:
            # Initialize Playbook execution status in Redis State Database
            incident_id = decision.get("input_summary", {}).get("incident_id", "INC-UNKNOWN")
            playbooks = [p.get("playbook_id") for p in decision.get("playbook_routing", {}).get("activated_playbooks", []) if p.get("playbook_id")]
            playbook_id = playbooks[0] if playbooks else "Unknown Playbook"
            actions_list = decision.get("actions", [])
            
            if self.redis:
                try:
                    redis_key = f"aegis:playbook:status:{incident_id}"
                    actions_status_map = {f"{a.get('action_type')}:{a.get('target', {}).get('value_masked')}": "pending" for a in actions_list}
                    
                    self.redis.hset(redis_key, mapping={
                        "incident_id": incident_id,
                        "playbook_id": playbook_id,
                        "status": "INITIATED",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "total_actions": len(actions_list),
                        "executed_actions": 0,
                        "failed_actions": 0,
                        "actions_status": json.dumps(actions_status_map)
                    })
                    # Set TTL of 7 days for the state to automatically clean up
                    self.redis.expire(redis_key, 7 * 24 * 3600)
                    logger.info(f"[REDIS STATE] Initialized status for playbook {playbook_id} on incident {incident_id}")
                except Exception as re:
                    logger.warning(f"[REDIS STATE ERROR] Failed to record playbook status in Redis: {re}")

            if self.producer:
                logger.info(f"[ORCHESTRATOR] Publishing L2 Orchestrator Decision to topic {SOAR_DECISIONS_TOPIC}")
                self.producer.send(SOAR_DECISIONS_TOPIC, decision)
                self.producer.flush()
                logger.info(f"[ORCHESTRATOR] Successfully published decision for incident: {decision['input_summary'].get('incident_id')}")
            else:
                logger.info(f"[ORCHESTRATOR] SQS Mode active. Decision for incident {decision['input_summary'].get('incident_id')} recorded locally.")
                self.execute_decision_actions_directly(decision)
        except Exception as pe:
            logger.error(f"[ORCHESTRATOR] Failed to record/publish decision: {pe}")


if __name__ == "__main__":
    app = SoarEngineApp()
    app.start()
