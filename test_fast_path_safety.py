import sys
from unittest.mock import MagicMock

sys.modules['redis'] = MagicMock()
sys.modules['kafka'] = MagicMock()

import unittest
import os
from main import SoarEngineApp

class TestFastPathSafety(unittest.TestCase):
    def setUp(self):
        os.environ["ASSET_INVENTORY_API_URL"] = ""

    def test_fast_path_blocked_by_guardrails(self):
        app = SoarEngineApp()
        app.fortinet = MagicMock()
        app.waf = MagicMock()
        app.producer = MagicMock()
        app.executor = MagicMock()
        app.policy_evaluator = MagicMock()
        
        # Deny the fast-path action (e.g. whitelist violation)
        app.policy_evaluator.authorize.return_value = {
            "allow": False, "reasons": ["protected_target"], "intent": {},
            "intent_hash": "hash", "policy_revision": "aegis-autopilot-v1"
        }
        
        data = {
            "source_ip": "10.0.0.1",
            "attack_type": "SQLi",
            "recommended_action": "BLOCK_IP",
            "timestamp": "2026-07-09T06:00:00Z"
        }
        
        app.process_fast_path(data)
        
        # Verify that blocking was NOT triggered
        app.fortinet.block_ip.assert_not_called()
        app.waf.block_ip.assert_not_called()
        app.executor._call_dashboard_perform_action.assert_not_called()

    def test_fast_path_allowed_and_rate_limited(self):
        app = SoarEngineApp()
        app.fortinet = MagicMock()
        app.waf = MagicMock()
        app.producer = MagicMock()
        app.executor = MagicMock()
        app.policy_evaluator = MagicMock()
        app.rate_limiter = MagicMock()
        
        # Allowed by OPA
        app.policy_evaluator.authorize.return_value = {
            "allow": True, "reasons": ["allowed"], "intent": {},
            "intent_hash": "hash", "policy_revision": "aegis-autopilot-v1"
        }
        app.policy_evaluator.verify_authorization.return_value = True
        # Denied by rate limiter (timeout)
        app.rate_limiter.acquire_token.return_value = False
        
        data = {
            "source_ip": "192.168.1.100",
            "attack_type": "Brute Force",
            "recommended_action": "BLOCK_IP",
            "timestamp": "2026-07-09T06:00:00Z"
        }
        
        app.process_fast_path(data)
        
        # Verify that blocking was NOT triggered due to rate limit timeout
        app.fortinet.block_ip.assert_not_called()
        app.waf.block_ip.assert_not_called()
        app.executor._call_dashboard_perform_action.assert_not_called()

    def test_fast_path_executed_successfully(self):
        app = SoarEngineApp()
        app.fortinet = MagicMock()
        app.waf = MagicMock()
        app.producer = MagicMock()
        app.executor = MagicMock()
        app.policy_evaluator = MagicMock()
        app.rate_limiter = MagicMock()
        
        # Allowed by OPA
        app.policy_evaluator.authorize.return_value = {
            "allow": True, "reasons": ["allowed"], "intent": {},
            "intent_hash": "hash", "policy_revision": "aegis-autopilot-v1"
        }
        app.policy_evaluator.verify_authorization.return_value = True
        # Allowed by rate limiter
        app.rate_limiter.acquire_token.return_value = True
        
        app.fortinet.block_ip.return_value = (True, "Blocked on firewall")
        app.waf.block_ip.return_value = (True, "Blocked on WAF")
        app.executor._call_dashboard_perform_action.return_value = (True, "Dashboard action success")
        
        data = {
            "source_ip": "198.51.100.55",
            "attack_type": "Brute Force",
            "recommended_action": "BLOCK_IP",
            "timestamp": "2026-07-09T06:00:00Z"
        }
        
        app.process_fast_path(data)
        
        # Verify that blocking WAS triggered
        app.fortinet.block_ip.assert_called_once_with("198.51.100.55")
        app.waf.block_ip.assert_called_once_with("198.51.100.55")
        app.executor._call_dashboard_perform_action.assert_called_once()

    def test_fast_path_sqli_alert_only_no_autoban(self):
        app = SoarEngineApp()
        app.fortinet = MagicMock()
        app.waf = MagicMock()
        app.producer = MagicMock()
        app.executor = MagicMock()
        app.policy_evaluator = MagicMock()
        app.rate_limiter = MagicMock()

        data = {
            "source_ip": "198.51.100.56",
            "attack_type": "SQLi",
            "recommended_action": "block_ip",
            "payload_snippet": "' OR '1'='1",
            "timestamp": "2026-07-09T06:00:00Z"
        }

        app.process_fast_path(data)

        app.fortinet.block_ip.assert_not_called()
        app.waf.block_ip.assert_not_called()
        app.executor._call_dashboard_perform_action.assert_not_called()
        app.producer.send.assert_called_once()
        payload = app.producer.send.call_args.args[1]
        self.assertEqual(payload["status"], "DETECTED")
        self.assertIn("SQL injection detected", payload["description"])

if __name__ == "__main__":
    unittest.main()
