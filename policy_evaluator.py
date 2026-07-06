import os
import logging
import requests

logger = logging.getLogger("soar-engine.policy-evaluator")

class OpaPolicyEvaluator:
    """Evaluates security actions against Open Policy Agent (OPA) engine for safety guardrails."""

    def __init__(self):
        self.opa_enabled = os.getenv("OPA_ENABLED", "false").lower() == "true"
        self.opa_url = os.getenv("OPA_URL", "http://opa:8181")
        # Path maps to the package name in Rego: package aegis.soar.policy
        self.endpoint = f"{self.opa_url}/v1/data/aegis/soar/policy"

        if self.opa_enabled:
            logger.info(f"[OPA EVALUATOR] Open Policy Agent is enabled. Server: {self.opa_url}")
        else:
            logger.info("[OPA EVALUATOR] Open Policy Agent is disabled. Running local safety rules.")

    def is_action_allowed(self, action_type: str, target: str, phase: str, approval_mode: str, risk_score: float) -> tuple:
        """
        Queries OPA to verify if an action violates safety policies.
        Returns (allowed, reason).
        """
        # Critical resources list for local fallback enforcement
        critical_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.254"]
        critical_hosts = ["DB-PROD-01", "DC-PROD-AD", "CORE-BANK-GW"]

        # Local policy fallback evaluation
        def evaluate_local():
            if action_type == "block_ip" and target in critical_ips:
                return False, f"LOCAL GATE: Denied block_ip on critical IP: {target}"
            if action_type == "quarantine_host" and target in critical_hosts:
                return False, f"LOCAL GATE: Denied quarantine_host on critical host: {target}"
            if phase == "contain" and approval_mode == "AUTO" and risk_score < 5.0:
                return False, f"LOCAL GATE: Auto containment denied for low risk score: {risk_score}"
            return True, "LOCAL GATE: Action approved."

        if not self.opa_enabled:
            return evaluate_local()

        # OPA REST API query
        payload = {
            "input": {
                "action_type": action_type,
                "target": target,
                "phase": phase,
                "approval_mode": approval_mode,
                "risk_score": risk_score
            }
        }

        try:
            res = requests.post(self.endpoint, json=payload, timeout=3)
            if res.status_code == 200:
                result = res.json().get("result", {})
                allowed = result.get("allow", False)
                reason = "OPA: Action approved." if allowed else "OPA: Action denied by safety policy."
                logger.info(f"[OPA EVALUATOR] Decision: {allowed} for {action_type} on {target} ({reason})")
                return allowed, reason
            else:
                logger.warning(f"[OPA EVALUATOR] OPA returned HTTP {res.status_code}. Falling back to local safety rules.")
                return evaluate_local()
        except Exception as e:
            logger.error(f"[OPA EVALUATOR ERROR] Failed to connect to OPA: {e}. Falling back to local safety rules.")
            return evaluate_local()
