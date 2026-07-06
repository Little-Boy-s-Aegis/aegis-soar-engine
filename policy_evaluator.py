import os
import logging
import json
import requests

logger = logging.getLogger("soar-engine.policy-evaluator")

class OpaPolicyEvaluator:
    """Evaluates security actions against Open Policy Agent (OPA) engine for safety guardrails."""

    def __init__(self, whitelist_path="whitelist.json"):
        self.opa_enabled = os.getenv("OPA_ENABLED", "false").lower() == "true"
        self.opa_url = os.getenv("OPA_URL", "http://opa:8181")
        self.endpoint = f"{self.opa_url}/v1/data/aegis/soar/policy"

        # Resolve whitelist path relative to this script
        if not os.path.isabs(whitelist_path):
            dir_path = os.path.dirname(os.path.realpath(__file__))
            whitelist_path = os.path.join(dir_path, whitelist_path)
        self.whitelist_path = whitelist_path

        self.whitelist = {}
        try:
            if os.path.exists(whitelist_path):
                with open(whitelist_path, "r", encoding="utf-8") as f:
                    self.whitelist = json.load(f)
                logger.info(f"[OPA EVALUATOR] Loaded whitelist containing {len(self.whitelist.get('ips', []))} IPs, {len(self.whitelist.get('hosts', []))} Hosts, and {len(self.whitelist.get('domains', []))} Domains.")
            else:
                logger.warning(f"[OPA EVALUATOR] Whitelist path {whitelist_path} not found.")
        except Exception as e:
            logger.error(f"[OPA EVALUATOR] Failed to load whitelist.json: {e}")

        if self.opa_enabled:
            logger.info(f"[OPA EVALUATOR] Open Policy Agent is enabled. Server: {self.opa_url}")
        else:
            logger.info("[OPA EVALUATOR] Open Policy Agent is disabled. Running local safety rules.")

        # Initialize Asset Inventory sync configurations
        self.inventory_url = os.getenv("ASSET_INVENTORY_API_URL", "http://asset-inventory:8083/api/v1/assets/critical")
        self.internal_token = os.getenv("AEGIS_INTERNAL_TOKEN", "")  # I-01 fix: no hardcoded fallback
        
        # Initial sync from Asset Inventory
        self.sync_whitelist_from_inventory()

        # Start periodic sync thread in background
        import threading
        self.sync_thread = threading.Thread(target=self._run_periodic_sync, daemon=True)
        self.sync_thread.start()

    def is_whitelisted(self, target: str, action_type: str) -> bool:
        """Checks if a target is present in the static whitelist."""
        target = target.strip().lower()
        
        # Check IPs
        if action_type == "block_ip":
            ip_clean = target.split("/")[0]
            if ip_clean in [ip.lower() for ip in self.whitelist.get("ips", [])]:
                return True
                
        # Check Hosts
        if action_type == "quarantine_host":
            if target in [h.lower() for h in self.whitelist.get("hosts", [])]:
                return True
                
        # Check Domains
        if action_type in ("block_domain", "block_ip"):
            for domain in self.whitelist.get("domains", []):
                domain_lower = domain.lower()
                if target == domain_lower or target.endswith("." + domain_lower):
                    return True
                    
        return False

    def is_action_allowed(self, action_type: str, target: str, phase: str, approval_mode: str, risk_score: float) -> tuple:
        """
        Queries OPA to verify if an action violates safety policies.
        Returns (allowed, reason).
        """
        # 1. Enforce static Whitelist guardrail
        if self.is_whitelisted(target, action_type):
            reason = f"WHITELIST SECURITY VIOLATION: Denied action {action_type} on protected resource: {target}"
            logger.error(f"[OPA EVALUATOR] {reason}")
            return False, reason

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

        headers = {
            "Authorization": f"Bearer {self.internal_token}"
        }
        try:
            res = requests.post(self.endpoint, json=payload, headers=headers, timeout=3)
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

    def _run_periodic_sync(self):
        """Runs the periodic asset inventory synchronization loop in background."""
        import time
        while True:
            # Sync every 10 minutes (600 seconds)
            time.sleep(600)
            self.sync_whitelist_from_inventory()

    def sync_whitelist_from_inventory(self):
        """Fetches the latest critical assets list from Asset Inventory API and updates whitelist.json."""
        if not self.inventory_url:
            return
            
        logger.info(f"[ASSET SYNC] Fetching critical assets from {self.inventory_url}...")
        headers = {
            "Authorization": f"Bearer {self.internal_token}"
        }
        try:
            res = requests.get(self.inventory_url, headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                critical_assets = data.get("critical_assets", {})
                
                # Validate response structure
                if "ips" in critical_assets or "hosts" in critical_assets or "domains" in critical_assets:
                    # Update local whitelist structure
                    self.whitelist = {
                        "ips": list(set(critical_assets.get("ips", []))),
                        "hosts": list(set(critical_assets.get("hosts", []))),
                        "domains": list(set(critical_assets.get("domains", [])))
                    }
                    
                    # Persist back to whitelist.json
                    try:
                        with open(self.whitelist_path, "w", encoding="utf-8") as f:
                            json.dump(self.whitelist, f, indent=2)
                        logger.info(f"[ASSET SYNC SUCCESS] Whitelist updated. Total: {len(self.whitelist['ips'])} IPs, {len(self.whitelist['hosts'])} Hosts, {len(self.whitelist['domains'])} Domains.")
                    except Exception as we:
                        logger.error(f"[ASSET SYNC] Failed to write updated whitelist to disk: {we}")
                else:
                    logger.warning("[ASSET SYNC] Received invalid response structure from Asset Inventory.")
            else:
                logger.warning(f"[ASSET SYNC] Asset Inventory API returned HTTP {res.status_code}. Using current whitelist.")
        except Exception as e:
            logger.warning(f"[ASSET SYNC WARNING] Failed to connect to Asset Inventory API: {e}. Using current whitelist.")
