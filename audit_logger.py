import os
import json
import logging
import time

logger = logging.getLogger("soar-engine.audit-logger")

_audit_chan = None

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

class SoarAuditLogger:
    """Unified audit logging utility for tracking AI decisions, guardrail checks, and API connector responses."""

    @staticmethod
    def log_event(event_type: str, incident_id: str, payload: dict):
        """Logs an audit event to file, stdout, and Redis if available."""
        audit_payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "eventType": event_type,
            "incidentId": incident_id,
            "details": payload
        }
        
        log_str = json.dumps(audit_payload)
        
        # 1. Log to dedicated audit file
        audit_chan = get_audit_logger()
        if audit_chan:
            audit_chan.info(log_str)
            
        # 2. Log to stdout with [AUDIT] prefix for log collectors (like Fluent Bit)
        print(f"[AUDIT] {log_str}", flush=True)

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
