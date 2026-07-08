import logging

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
        allowed, reason = policy_evaluator.is_action_allowed(
            action_type=action_type,
            target=target_value,
            phase=phase,
            approval_mode=approval_mode,
            risk_score=risk_score
        )
        return allowed, reason
    except Exception as e:
        logger.error(f"[SAFETY GATE] Exception in policy evaluation: {e}")
        # Fail-closed on error for containment
        if phase == "contain" or action_type in ("block_ip", "block_domain", "quarantine_host", "disable_account"):
            return False, f"FAIL-CLOSED: Policy evaluation failed with error: {e}"
        return True, f"Policy evaluation error ignored for non-containment: {e}"

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
