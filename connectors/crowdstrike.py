import logging
import requests
import os
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.crowdstrike")

class CrowdStrikeConnector:
    """API Connector for CrowdStrike Falcon EDR to isolate and remediate endpoints."""

    def __init__(self):
        self.client_id = os.getenv("CROWDSTRIKE_CLIENT_ID", "mock-crowdstrike-client-id")
        self.client_secret = secrets.get_secret("CROWDSTRIKE_CLIENT_SECRET", "mock-crowdstrike-client-secret")
        self.base_url = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
        self.verify_ssl = os.getenv("CROWDSTRIKE_VERIFY_SSL", "false").lower() == "true"

    def _get_access_token(self) -> str:
        """Authenticates with CrowdStrike Falcon OAuth2 API."""
        if self.client_secret == "mock-crowdstrike-client-secret":
            return "mock-falcon-token"
            
        url = f"{self.base_url}/oauth2/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        res = requests.post(url, data=payload, verify=self.verify_ssl, timeout=10)
        if res.status_code == 201:
            return res.json().get("access_token")
        raise Exception(f"Failed to get CrowdStrike token: HTTP {res.status_code} - {res.text}")

    def _get_device_aid(self, hostname: str, token: str) -> str:
        """Queries CrowdStrike device list to resolve hostname to Falcon Agent ID (AID)."""
        if token == "mock-falcon-token":
            return f"mock-aid-{hostname}"
            
        url = f"{self.base_url}/devices/queries/devices/v1"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        params = {
            "filter": f"hostname:'{hostname}'"
        }
        res = requests.get(url, headers=headers, params=params, verify=self.verify_ssl, timeout=10)
        if res.status_code == 200:
            resources = res.json().get("resources", [])
            if resources:
                return resources[0] # Return the first matching Agent ID
        return None

    def isolate_host(self, hostname: str) -> tuple:
        """
        Isolates (contains) an endpoint from the internal network.
        Returns (success, message).
        """
        logger.info(f"[CROWDSTRIKE] Request to isolate endpoint: {hostname}")
        
        try:
            token = self._get_access_token()
            aid = self._get_device_aid(hostname, token)
            if not aid:
                return False, f"Device with hostname '{hostname}' not found in CrowdStrike console."
                
            if token == "mock-falcon-token":
                logger.info(f"[CROWDSTRIKE-SIMULATION] Host {hostname} (AID: {aid}) isolated successfully.")
                return True, f"[SIMULATION] Host {hostname} isolated via CrowdStrike Falcon EDR."
                
            url = f"{self.base_url}/devices/entities/devices-actions/v2?action_name=contain"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            payload = {
                "ids": [aid]
            }
            res = requests.post(url, headers=headers, json=payload, verify=self.verify_ssl, timeout=10)
            if res.status_code in (200, 202):
                return True, f"Host {hostname} successfully isolated via CrowdStrike Falcon EDR (AID: {aid})."
            else:
                return False, f"Failed to isolate host: HTTP {res.status_code} - {res.text}"
                
        except Exception as e:
            logger.error(f"[CROWDSTRIKE ERROR] Isolate host failed: {e}")
            return False, f"CrowdStrike connection error: {str(e)}"

    def lift_isolation(self, hostname: str) -> tuple:
        """
        Removes (lifts) containment from an endpoint.
        Returns (success, message).
        """
        logger.info(f"[CROWDSTRIKE] Request to lift isolation on endpoint: {hostname}")
        
        try:
            token = self._get_access_token()
            aid = self._get_device_aid(hostname, token)
            if not aid:
                return False, f"Device with hostname '{hostname}' not found in CrowdStrike console."
                
            if token == "mock-falcon-token":
                logger.info(f"[CROWDSTRIKE-SIMULATION] Containment lifted for host {hostname} (AID: {aid}) successfully.")
                return True, f"[SIMULATION] Host {hostname} containment lifted via CrowdStrike Falcon EDR."
                
            url = f"{self.base_url}/devices/entities/devices-actions/v2?action_name=lift"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            payload = {
                "ids": [aid]
            }
            res = requests.post(url, headers=headers, json=payload, verify=self.verify_ssl, timeout=10)
            if res.status_code in (200, 202):
                return True, f"Host {hostname} containment successfully lifted (AID: {aid})."
            else:
                return False, f"Failed to lift containment: HTTP {res.status_code} - {res.text}"
                
        except Exception as e:
            logger.error(f"[CROWDSTRIKE ERROR] Lift isolation failed: {e}")
            return False, f"CrowdStrike connection error: {str(e)}"
