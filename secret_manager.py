import os
import logging
import requests

logger = logging.getLogger("soar-engine.secret-manager")

class SecretManager:
    """Manages secure retrieval of credentials from HashiCorp Vault or environment fallback."""

    def __init__(self):
        self.vault_enabled = os.getenv("VAULT_ENABLED", "false").lower() == "true"
        self.vault_addr = os.getenv("VAULT_ADDR", "http://vault:8200")
        self.vault_token = os.getenv("VAULT_TOKEN", "aegis-vault-root-token")
        self.secret_path = os.getenv("VAULT_SECRET_PATH", "secret/data/aegis/soar")
        self._cached_secrets = {}

        if self.vault_enabled:
            logger.info(f"[SECRET MANAGER] Vault is enabled. Connecting to {self.vault_addr}...")
            self._load_secrets_from_vault()
        else:
            logger.info("[SECRET MANAGER] Vault is disabled. Using environment variables.")

    def _load_secrets_from_vault(self):
        """Loads secrets from Vault KV V2 Engine using REST API."""
        url = f"{self.vault_addr}/v1/{self.secret_path}"
        headers = {
            "X-Vault-Token": self.vault_token,
            "Content-Type": "application/json"
        }
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                body = res.json()
                # Vault KV V2 payload structure: data -> data -> key-value
                self._cached_secrets = body.get("data", {}).get("data", {})
                logger.info(f"[SECRET MANAGER] Successfully loaded {len(self._cached_secrets)} secrets from Vault.")
            else:
                logger.warning(f"[SECRET MANAGER] Failed to fetch secrets from Vault: HTTP {res.status_code} - {res.text}. Falling back to env.")
        except Exception as e:
            logger.error(f"[SECRET MANAGER] Error connecting to Vault: {e}. Falling back to env.")

    def get_secret(self, key: str, default: str = None) -> str:
        """Retrieves a secret. Checks Vault cache first, then falls back to OS environment."""
        if self.vault_enabled and key in self._cached_secrets:
            return self._cached_secrets[key]
        return os.getenv(key, default)

# Singleton instance
secrets = SecretManager()
