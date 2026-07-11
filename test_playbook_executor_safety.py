import sys
from unittest.mock import MagicMock

sys.modules['redis'] = MagicMock()
sys.modules['kafka'] = MagicMock()

import unittest
import os
from playbook_executor import PlaybookExecutor

class TestPlaybookExecutorSafety(unittest.TestCase):
    def setUp(self):
        os.environ["ASSET_INVENTORY_API_URL"] = ""

    def test_legacy_executor_blocked_by_guardrails(self):
        executor = PlaybookExecutor()
        executor.policy_evaluator = MagicMock()
        executor.rate_limiter = MagicMock()
        executor._call_dashboard_perform_action = MagicMock()
        executor._async_push_analysis = MagicMock()
        executor._push_l2_decision_to_gateway = MagicMock()

        # Deny by safety policy
        executor.policy_evaluator.authorize.return_value = {"allow": False, "reasons": ["protected_target"], "intent": {}}

        decision = {
            "input_summary": {"incident_id": "inc-legacy-01"},
            "verified_case": {"title": "SQLi Attempt", "entities": {"ips": ["10.0.0.1"]}},
            "automation_control": {"soc_autopilot_enabled": True, "execution_window": {"in_window": True}, "auto_containment_eligible": True},
            "scoring": {"final_risk_score_0_10": 9.5},
            "decision": {"justification": "Threat score too high"},
            "output_and_notification": {},
            "actions": [
                {
                    "action_id": "act-legacy-01",
                    "action_type": "block_ip",
                    "phase": "contain",
                    "approval_mode": "AUTO",
                    "target": {"value_masked": "10.0.0.1"},
                    "status": "pending"
                }
            ]
        }

        executor.execute_decision(decision)

        # Check action status updated to failed
        self.assertEqual(decision["actions"][0]["status"], "failed")
        self.assertIn("Blocked by Safety Gate", decision["actions"][0]["rationale"])
        executor._call_dashboard_perform_action.assert_not_called()

    def test_legacy_executor_rate_limited(self):
        executor = PlaybookExecutor()
        executor.policy_evaluator = MagicMock()
        executor.rate_limiter = MagicMock()
        executor._call_dashboard_perform_action = MagicMock()
        executor._async_push_analysis = MagicMock()
        executor._push_l2_decision_to_gateway = MagicMock()

        # Allowed by safety policy, but rate limited (timeout)
        executor.policy_evaluator.authorize.return_value = {"allow": True, "reasons": ["allowed"], "intent": {}}
        executor.policy_evaluator.verify_authorization.return_value = True
        executor.rate_limiter.acquire_token.return_value = False

        decision = {
            "input_summary": {"incident_id": "inc-legacy-02"},
            "verified_case": {"title": "SQLi Attempt", "entities": {"ips": ["192.168.1.1"]}},
            "automation_control": {"soc_autopilot_enabled": True, "execution_window": {"in_window": True}, "auto_containment_eligible": True},
            "scoring": {"final_risk_score_0_10": 8.0},
            "decision": {"justification": "Risk limit exceeded"},
            "output_and_notification": {},
            "actions": [
                {
                    "action_id": "act-legacy-02",
                    "action_type": "block_ip",
                    "phase": "contain",
                    "approval_mode": "AUTO",
                    "target": {"value_masked": "192.168.1.1"},
                    "status": "pending"
                }
            ]
        }

        executor.execute_decision(decision)

        # Check action status updated to failed
        self.assertEqual(decision["actions"][0]["status"], "failed")
        self.assertIn("Rate Limiter Timeout", decision["actions"][0]["rationale"])
        executor._call_dashboard_perform_action.assert_not_called()

    def test_legacy_executor_success(self):
        executor = PlaybookExecutor()
        executor.policy_evaluator = MagicMock()
        executor.rate_limiter = MagicMock()
        executor._call_dashboard_perform_action = MagicMock()
        executor._call_dashboard_perform_action.return_value = (True, "Success")
        executor._async_push_analysis = MagicMock()
        executor._push_l2_decision_to_gateway = MagicMock()

        # Allowed by policy and rate limiter
        executor.policy_evaluator.authorize.return_value = {"allow": True, "reasons": ["allowed"], "intent": {}}
        executor.policy_evaluator.verify_authorization.return_value = True
        executor.rate_limiter.acquire_token.return_value = True

        decision = {
            "input_summary": {"incident_id": "inc-legacy-03"},
            "verified_case": {"title": "SQLi Attempt", "entities": {"ips": ["192.168.1.200"]}},
            "automation_control": {"soc_autopilot_enabled": True, "execution_window": {"in_window": True}, "auto_containment_eligible": True},
            "scoring": {"final_risk_score_0_10": 8.0},
            "decision": {"justification": "Risk limit exceeded"},
            "output_and_notification": {},
            "actions": [
                {
                    "action_id": "act-legacy-03",
                    "action_type": "block_ip",
                    "phase": "contain",
                    "approval_mode": "AUTO",
                    "target": {"value_masked": "192.168.1.200"},
                    "status": "pending"
                }
            ]
        }

        executor.execute_decision(decision)

        # Check action status updated to executed
        self.assertEqual(decision["actions"][0]["status"], "executed")
        executor._call_dashboard_perform_action.assert_called_once()

if __name__ == "__main__":
    unittest.main()
