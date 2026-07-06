import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock redis module if not installed in the host python environment
try:
    import redis
except ImportError:
    redis_mock = MagicMock()
    sys.modules['redis'] = redis_mock

# Add current path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rollback_action import rollback_single_action, rollback_by_incident

class TestSoarRollback(unittest.TestCase):
    
    @patch('connectors.fortinet.FortinetConnector.unblock_ip')
    @patch('connectors.waf.WafConnector.unblock_ip')
    def test_rollback_block_ip(self, mock_waf_unblock, mock_fn_unblock):
        mock_fn_unblock.return_value = (True, "mock-unblocked-fn")
        mock_waf_unblock.return_value = (True, "mock-unblocked-waf")
        
        success, msg = rollback_single_action("block_ip", "10.0.0.1")
        
        self.assertTrue(success)
        mock_fn_unblock.assert_called_once_with("10.0.0.1")
        mock_waf_unblock.assert_called_once_with("10.0.0.1")

    @patch('connectors.active_directory.ActiveDirectoryConnector.enable_account')
    def test_rollback_disable_account(self, mock_ad_enable):
        mock_ad_enable.return_value = (True, "mock-enabled-ad")
        
        success, msg = rollback_single_action("disable_account", "john_doe")
        
        self.assertTrue(success)
        mock_ad_enable.assert_called_once_with("john_doe")

    @patch('connectors.crowdstrike.CrowdStrikeConnector.lift_isolation')
    def test_rollback_isolate_host(self, mock_cs_lift):
        mock_cs_lift.return_value = (True, "mock-lifted-cs")
        
        success, msg = rollback_single_action("quarantine_host", "Web-Prod-01")
        
        self.assertTrue(success)
        mock_cs_lift.assert_called_once_with("Web-Prod-01")

    @patch('redis.Redis.from_url')
    @patch('rollback_action.rollback_single_action')
    def test_rollback_by_incident(self, mock_rollback_single, mock_redis_from_url):
        mock_redis = MagicMock()
        mock_redis_from_url.return_value = mock_redis
        
        # Mock actions_status stored in Redis
        mock_redis.hget.return_value = '{"block_ip:10.0.0.1": "executed", "disable_account:john_doe": "executed"}'
        mock_rollback_single.return_value = (True, "Success")
        
        success, msg = rollback_by_incident("inc-test-123")
        
        self.assertTrue(success)
        self.assertEqual(mock_rollback_single.call_count, 2)
        mock_rollback_single.assert_any_call("block_ip", "10.0.0.1", "inc-test-123")
        mock_rollback_single.assert_any_call("disable_account", "john_doe", "inc-test-123")
        
        # Verify redis updates status to ROLLED_BACK
        mock_redis.hset.assert_any_call("aegis:playbook:status:inc-test-123", "status", "ROLLED_BACK")

if __name__ == '__main__':
    unittest.main()
