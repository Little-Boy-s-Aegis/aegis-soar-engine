import unittest
import os
from secret_manager import SecretManager

class TestSecretManager(unittest.TestCase):
    def test_environment_fallback(self):
        # Disable Vault mode
        os.environ["VAULT_ENABLED"] = "false"
        os.environ["TEST_SECRET_KEY"] = "my-env-secret"
        
        manager = SecretManager()
        secret_val = manager.get_secret("TEST_SECRET_KEY")
        self.assertEqual(secret_val, "my-env-secret")
        
        # Test default fallback
        self.assertEqual(manager.get_secret("NON_EXISTENT_KEY", "default-val"), "default-val")

    def test_vault_cache_lookup(self):
        manager = SecretManager()
        # Mock cached secrets dictionary
        manager.vault_enabled = True
        manager._cached_secrets = {"VAULT_API_KEY": "vault-secure-token-abc"}
        
        secret_val = manager.get_secret("VAULT_API_KEY")
        self.assertEqual(secret_val, "vault-secure-token-abc")
        
        # Test environment fallback when not in Vault cache
        os.environ["VAULT_FALLBACK_KEY"] = "fallback-env"
        self.assertEqual(manager.get_secret("VAULT_FALLBACK_KEY"), "fallback-env")

if __name__ == "__main__":
    unittest.main()
