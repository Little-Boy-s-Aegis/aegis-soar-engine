import os
import json
import logging
import time
import hashlib

logger = logging.getLogger("soar-engine.audit-logger")

_audit_chan = None
_last_log_hash = None

def get_last_log_hash():
    global _last_log_hash
    if _last_log_hash is not None:
        return _last_log_hash
    
    # Try to read the last line of the log file to resume the hash chain
    current_path = os.getenv("SOAR_AUDIT_LOG_PATH", "soar_audit.log")
    if os.path.exists(current_path):
        try:
            with open(current_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if "AUDIT: " in last_line:
                        json_str = last_line.split("AUDIT: ")[1].strip()
                        payload = json.loads(json_str)
                        _last_log_hash = payload.get("hash", "0" * 64)
                        return _last_log_hash
        except Exception:
            pass
            
    _last_log_hash = "0" * 64
    return _last_log_hash

def get_audit_logger():
    global _audit_chan
    current_path = os.getenv("SOAR_AUDIT_LOG_PATH", "soar_audit.log")
    
    # Check if handlers need to be reloaded/re-created (e.g. during test setup)
    if _audit_chan is not None:
        for h in list(_audit_chan.handlers):
            if isinstance(h, logging.FileHandler) and h.baseFilename.endswith(current_path):
                return _audit_chan
        _audit_chan.handlers.clear()
        
    _audit_chan = logging.getLogger("soar-audit")
    _audit_chan.setLevel(logging.INFO)
    _audit_chan.propagate = False
    
    try:
        dir_name = os.path.dirname(current_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
            
        audit_formatter = logging.Formatter("%(asctime)s [%(levelname)s] AUDIT: %(message)s")
        file_handler = logging.FileHandler(current_path, encoding="utf-8")
        file_handler.setFormatter(audit_formatter)
        _audit_chan.addHandler(file_handler)
    except Exception as e:
        logger.error(f"Failed to initialize file audit logger: {e}")
        
    return _audit_chan

_db_table_initialized = False

def init_db_table():
    global _db_table_initialized
    db_enabled = os.getenv("SOAR_AUDIT_DB_ENABLED", "true").lower() == "true"
    if not db_enabled:
        return
        
    try:
        import psycopg2
        from config import DATABASE_URL
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soar_audit_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                    event_type VARCHAR(50) NOT NULL,
                    incident_id VARCHAR(100) NOT NULL,
                    details JSONB NOT NULL,
                    hash CHAR(64),
                    prev_hash CHAR(64)
                );
            """)
            cursor.execute("ALTER TABLE soar_audit_logs ADD COLUMN IF NOT EXISTS hash CHAR(64);")
            cursor.execute("ALTER TABLE soar_audit_logs ADD COLUMN IF NOT EXISTS prev_hash CHAR(64);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_audit_logs_event_type ON soar_audit_logs(event_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_audit_logs_incident_id ON soar_audit_logs(incident_id);")
            conn.commit()
        conn.close()
        _db_table_initialized = True
        logger.info("[AUDIT DB] Centralized PostgreSQL audit log table initialized successfully.")
    except Exception as e:
        logger.warning(f"[AUDIT DB] Centralized PostgreSQL storage initialization failed: {e}")

class SoarAuditLogger:
    """Unified audit logging utility for tracking AI decisions, guardrail checks, and API connector responses."""

    @staticmethod
    def log_event(event_type: str, incident_id: str, payload: dict):
        """Logs an audit event to file, stdout, and Redis if available with cryptographic integrity chain."""
        global _db_table_initialized, _last_log_hash
        
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        prev_hash = get_last_log_hash()
        
        # Prepare deterministic payload structure for hashing
        hash_payload = {
            "timestamp": now_str,
            "eventType": event_type,
            "incidentId": incident_id,
            "details": payload,
            "prevHash": prev_hash
        }
        
        # Ensure canonical (sorted keys) serialization
        canonical_str = json.dumps(hash_payload, sort_keys=True)
        current_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        
        # Build complete signed payload
        audit_payload = hash_payload.copy()
        audit_payload["hash"] = current_hash
        
        _last_log_hash = current_hash
        log_str = json.dumps(audit_payload)
        
        # 1. Log to dedicated audit file
        audit_chan = get_audit_logger()
        if audit_chan:
            audit_chan.info(log_str)
            
        # 2. Log to stdout with [AUDIT] prefix for log collectors (like Fluent Bit)
        print(f"[AUDIT] {log_str}", flush=True)

        # 3. Log to centralized PostgreSQL database for post-mortem analysis
        db_enabled = os.getenv("SOAR_AUDIT_DB_ENABLED", "true").lower() == "true"
        if db_enabled:
            if not _db_table_initialized:
                init_db_table()
            
            if _db_table_initialized:
                try:
                    import psycopg2
                    from config import DATABASE_URL
                    conn = psycopg2.connect(DATABASE_URL)
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "INSERT INTO soar_audit_logs (timestamp, event_type, incident_id, details, hash, prev_hash) VALUES (%s, %s, %s, %s, %s, %s)",
                            (now_str, event_type, incident_id, json.dumps(payload), current_hash, prev_hash)
                        )
                        conn.commit()
                    conn.close()
                except Exception as dbe:
                    logger.warning(f"[AUDIT DB ERROR] Failed to push audit log to database: {dbe}")

    @staticmethod
    def log_ai_decision(incident_id: str, input_prompt: str, raw_output: str, parsed_decision: dict):
        """Logs AI prompt, raw response, and parsed decision payload."""
        SoarAuditLogger.log_event("AI_DECISION", incident_id, {
            "inputPrompt": input_prompt,
            "rawOutput": raw_output,
            "parsedDecision": parsed_decision
        })

    @staticmethod
    def log_guardrail_check(incident_id: str, action: dict, allowed: bool, reason: str):
        """Logs the action parameters and safety guardrails check outcome."""
        SoarAuditLogger.log_event("GUARDRAILS_CHECK", incident_id, {
            "action": action,
            "allowed": allowed,
            "reason": reason
        })

    @staticmethod
    def log_api_response(incident_id: str, target_system: str, action_type: str, request_params: dict, success: bool, response_msg: str):
        """Logs API calls to firewalls, active directory, EDR, and WAF connectors."""
        SoarAuditLogger.log_event("API_CONNECTOR", incident_id, {
            "targetSystem": target_system,
            "actionType": action_type,
            "requestParams": request_params,
            "success": success,
            "responseMessage": response_msg
        })
