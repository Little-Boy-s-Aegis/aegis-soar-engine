import logging
from datetime import datetime, timezone

logger = logging.getLogger("soar-engine.safety-gate")

def evaluate_action_safety(policy_evaluator, action: dict, decision_context: dict):
    """
    Evaluates safety policies for an action using the provided OPA Policy Evaluator.
    If the policy evaluator is not available, defaults to fail-closed for containment actions.
    """
    action_type = action.get("action_type")
    target = action.get("target", {})
    target_value = target.get("value_masked") if isinstance(target, dict) else target
    phase = action.get("phase")
    approval_mode = action.get("approval_mode")
    risk_score = decision_context.get("scoring", {}).get("final_risk_score_0_10", 0.0)
    autopilot_mode = bool(decision_context.get("automation_control", {}).get("soc_autopilot_enabled", False))

    # Phase one changes Autopilot only; analyst/manual authorization remains unchanged.
    if not autopilot_mode and approval_mode != "AUTO":
        return True, "Manual action: Autopilot OPA gate not applicable"

    # In case target_value is missing
    if not target_value:
        logger.error(f"[SAFETY GATE] Missing target value for action {action_type}.")
        return False, "FAIL-CLOSED: Missing target value for containment action."

    if not policy_evaluator:
        # Fail-closed for containment action if OPA evaluator is missing
        if phase == "contain" or action_type in ("block_ip", "block_domain", "quarantine_host", "disable_account"):
            logger.error("[SAFETY GATE] Policy evaluator not initialized. Fail-closed enforced.")
            return False, "FAIL-CLOSED: Policy evaluator not available for containment action."
        return True, "Policy evaluator not available, but action is non-containment."

    try:
        action.setdefault("_intent_created_at", datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
        authorization = policy_evaluator.authorize(action, decision_context)
        action["_policy_authorization"] = {k: v for k, v in authorization.items() if k != "intent"}
        try:
            from audit_logger import SoarAuditLogger
            SoarAuditLogger.log_policy_decision(
                str(decision_context.get("input_summary", {}).get("incident_id") or "unknown"),
                authorization,
            )
        except Exception as audit_error:
            logger.error("[SAFETY GATE] Failed to persist policy audit: %s", audit_error)
        allowed = authorization["allow"]
        reason = ",".join(authorization["reasons"])
        return allowed, reason
    except Exception as e:
        logger.error(f"[SAFETY GATE] Exception in policy evaluation: {e}")
        # Fail-closed on error for containment
        if phase == "contain" or action_type in ("block_ip", "block_domain", "quarantine_host", "disable_account"):
            return False, f"FAIL-CLOSED: Policy evaluation failed with error: {e}"
        return True, f"Policy evaluation error ignored for non-containment: {e}"


def verify_action_authorization(policy_evaluator, action: dict, decision_context: dict):
    """TOCTOU guard called immediately before any connector side effect."""
    authorization = action.get("_policy_authorization")
    if not policy_evaluator or not policy_evaluator.verify_authorization(action, decision_context, authorization):
        logger.critical("[SAFETY GATE] Action changed after authorization or has no valid OPA allow.")
        return False, "OPA authorization hash verification failed"
    return True, "OPA authorization hash verified"

def acquire_action_rate_limits(rate_limiter, action: dict, timeout_seconds: float = 15.0):
    """
    Acquires rate limit tokens for the action's target system using the provided rate limiter.
    """
    action_type = action.get("action_type")
    
    target_system = None
    if action_type in ("block_ip", "block_domain"):
        target_system = "fortinet"
    elif action_type in ("disable_account", "reset_password"):
        target_system = "active_directory"
    elif action_type in ("quarantine_host", "lift_isolation"):
        target_system = "crowdstrike"

    if not target_system:
        return True, "No rate limiting required for this action type."

    if not rate_limiter:
        logger.error("[RATE LIMITER] Rate limiter not available.")
        return False, "FAIL-CLOSED: Rate limiter not available."

    try:
        token_acquired = rate_limiter.acquire_token(target_system, timeout_seconds=timeout_seconds)
        if not token_acquired:
            return False, f"Rate Limiter Timeout for {target_system}"
        return True, "Token acquired successfully."
    except Exception as e:
        logger.error(f"[RATE LIMITER] Exception acquiring token: {e}")
        return False, f"FAIL-CLOSED: Rate limiter failed with error: {e}"
