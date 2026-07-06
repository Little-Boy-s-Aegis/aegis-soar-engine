import unittest
import os
from policy_evaluator import OpaPolicyEvaluator

class TestPolicyEvaluator(unittest.TestCase):
    def test_local_safety_critical_ip_block(self):
        # Disable OPA to test local fallback safety checks
        os.environ["OPA_ENABLED"] = "false"
        evaluator = OpaPolicyEvaluator()
        
        # 1. Critical IP blocking should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="192.168.1.1", # critical DNS/Gateway
            phase="contain",
            approval_mode="AUTO",
            risk_score=9.0
        )
        self.assertFalse(allowed)
        self.assertTrue("critical IP" in reason or "WHITELIST" in reason)
        
        # 2. Non-critical IP blocking should be allowed
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="198.51.100.5",
            phase="contain",
            approval_mode="AUTO",
            risk_score=9.0
        )
        self.assertTrue(allowed)

    def test_local_safety_critical_host_isolation(self):
        os.environ["OPA_ENABLED"] = "false"
        evaluator = OpaPolicyEvaluator()
        
        # 1. Critical host quarantine should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="quarantine_host",
            target="DB-PROD-01",
            phase="contain",
            approval_mode="APPROVAL_REQUIRED",
            risk_score=9.5
        )
        self.assertFalse(allowed)
        self.assertTrue("critical host" in reason or "WHITELIST" in reason)
        
        # 2. Non-critical host quarantine should be allowed
        allowed, reason = evaluator.is_action_allowed(
            action_type="quarantine_host",
            target="USER-LAPTOP-12",
            phase="contain",
            approval_mode="APPROVAL_REQUIRED",
            risk_score=9.5
        )
        self.assertTrue(allowed)

    def test_local_safety_low_risk_auto_containment(self):
        os.environ["OPA_ENABLED"] = "false"
        evaluator = OpaPolicyEvaluator()
        
        # 1. Auto containment with low risk score should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="198.51.100.5",
            phase="contain",
            approval_mode="AUTO",
            risk_score=3.5
        )
        self.assertFalse(allowed)
        self.assertIn("low risk score", reason)

        # 2. Auto containment with high risk score should be allowed
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="198.51.100.5",
            phase="contain",
            approval_mode="AUTO",
            risk_score=7.0
        )
        self.assertTrue(allowed)

    def test_static_whitelist(self):
        evaluator = OpaPolicyEvaluator()
        
        # 1. Whitelisted IP should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="10.0.0.1",
            phase="contain",
            approval_mode="AUTO",
            risk_score=9.9
        )
        self.assertFalse(allowed)
        self.assertIn("WHITELIST SECURITY VIOLATION", reason)

        # 2. Whitelisted IP with CIDR mask should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="192.168.1.254/32",
            phase="contain",
            approval_mode="AUTO",
            risk_score=9.9
        )
        self.assertFalse(allowed)
        self.assertIn("WHITELIST SECURITY VIOLATION", reason)

        # 3. Whitelisted Host should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="quarantine_host",
            target="DC-PROD-AD",
            phase="contain",
            approval_mode="AUTO",
            risk_score=9.9
        )
        self.assertFalse(allowed)
        self.assertIn("WHITELIST SECURITY VIOLATION", reason)

        # 4. Whitelisted Domain should be denied
        allowed, reason = evaluator.is_action_allowed(
            action_type="block_ip",
            target="sub.aegisbank.local",
            phase="contain",
            approval_mode="AUTO",
            risk_score=9.9
        )
        self.assertFalse(allowed)
        self.assertIn("WHITELIST SECURITY VIOLATION", reason)

if __name__ == "__main__":
    unittest.main()
