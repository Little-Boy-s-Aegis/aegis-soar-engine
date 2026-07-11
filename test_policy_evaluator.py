import os
import time
import unittest
from unittest.mock import MagicMock, patch

from policy_evaluator import OpaPolicyEvaluator


def action():
    return {
        "action_id": "act-1", "created_at": "2026-07-11T00:00:00Z",
        "action_type": "block_ip", "phase": "contain", "approval_mode": "AUTO",
        "target": {"value_masked": "198.51.100.7"}, "reversible": True,
    }


def context():
    return {
        "input_summary": {"incident_id": "inc-1", "tenant_id": "bank"},
        "orchestrator": {"orchestrator_id": "layer2_orchestrator_soar"},
        "automation_control": {
            "soc_autopilot_enabled": True, "auto_containment_eligible": True,
            "execution_window": {"in_window": True},
        },
        "scoring": {"final_risk_score_0_10": 9.0},
        "l2_independent_verification": {"data_fresh": True},
    }


class TestPolicyEvaluator(unittest.TestCase):
    def setUp(self):
        os.environ.update({
            "OPA_ENABLED": "true", "OPA_POLICY_REVISION": "aegis-autopilot-v1",
            "OPA_ALLOW_CACHE_TTL_SECONDS": "30", "OPA_CALLER_ID": "soar-action-worker",
        })

    def response(self, allow=True, revision="aegis-autopilot-v1"):
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"result": {
            "allow": allow, "decision_id": "opa-1", "policy_revision": revision,
            "reasons": ["allowed" if allow else "protected_target"],
        }}
        return response

    @patch("policy_evaluator.requests.post")
    def test_allow_and_hash_verification(self, post):
        post.return_value = self.response(True)
        evaluator = OpaPolicyEvaluator()
        result = evaluator.authorize(action(), context())
        self.assertTrue(result["allow"])
        self.assertTrue(evaluator.verify_authorization(action(), context(), result))

    @patch("policy_evaluator.requests.post")
    def test_denial_is_not_cached(self, post):
        post.return_value = self.response(False)
        evaluator = OpaPolicyEvaluator()
        denied = evaluator.authorize(action(), context())
        self.assertFalse(denied["allow"])
        post.side_effect = TimeoutError("down")
        self.assertFalse(evaluator.authorize(action(), context())["allow"])

    @patch("policy_evaluator.requests.post")
    def test_exact_cached_allow_is_single_use(self, post):
        post.return_value = self.response(True)
        evaluator = OpaPolicyEvaluator()
        evaluator.authorize(action(), context())
        post.side_effect = TimeoutError("down")
        cached = evaluator.authorize(action(), context())
        self.assertTrue(cached["allow"])
        self.assertEqual(cached["cache_status"], "consumed")
        self.assertFalse(evaluator.authorize(action(), context())["allow"])

    @patch("policy_evaluator.requests.post")
    def test_cache_rejects_changed_target(self, post):
        post.return_value = self.response(True)
        evaluator = OpaPolicyEvaluator()
        evaluator.authorize(action(), context())
        post.side_effect = TimeoutError("down")
        changed = action()
        changed["target"]["value_masked"] = "198.51.100.8"
        self.assertFalse(evaluator.authorize(changed, context())["allow"])

    @patch("policy_evaluator.requests.post")
    def test_invalid_and_revision_mismatch_fail_closed(self, post):
        post.return_value = self.response(True, "old-policy")
        evaluator = OpaPolicyEvaluator()
        self.assertFalse(evaluator.authorize(action(), context())["allow"])
        post.return_value.json.return_value = {"result": {"allow": "yes"}}
        self.assertFalse(evaluator.authorize(action(), context())["allow"])


if __name__ == "__main__":
    unittest.main()
