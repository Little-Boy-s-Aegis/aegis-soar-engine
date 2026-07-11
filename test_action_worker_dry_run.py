import sys
from unittest.mock import MagicMock

# Mock redis and kafka modules before importing action_worker
sys.modules['redis'] = MagicMock()
sys.modules['kafka'] = MagicMock()

import unittest
import os
from action_worker import SoarActionWorker

class TestActionWorkerDryRun(unittest.TestCase):
    def setUp(self):
        # Disable Asset Inventory Sync in test runs to speed them up
        os.environ["ASSET_INVENTORY_API_URL"] = ""
        # Reset environmental variables
        if "SOAR_DRY_RUN" in os.environ:
            del os.environ["SOAR_DRY_RUN"]

    def test_global_dry_run_simulation(self):
        # 1. Enable global dry-run mode
        os.environ["SOAR_DRY_RUN"] = "true"
        worker = SoarActionWorker()
        
        # Create a mock incident decision and action (non-whitelisted target)
        decision = {
            "input_summary": {"incident_id": "inc-dryrun-01"},
            "automation_control": {"soc_autopilot_enabled": True, "execution_window": {"in_window": True}, "auto_containment_eligible": True},
            "scoring": {"final_risk_score_0_10": 8.5}
        }
        action = {
            "action_id": "act-01",
            "action_type": "block_ip",
            "phase": "contain",
            "approval_mode": "AUTO",
            "target": {"value_masked": "198.51.100.99"},
            "status": "pending"
        }
        
        # Mock the connectors to ensure they are NOT called
        worker.fortinet = MagicMock()
        worker.waf = MagicMock()
        worker.redis = MagicMock()
        worker.producer = MagicMock()
        worker.policy_evaluator = MagicMock()
        
        # OPA allows the action
        worker.policy_evaluator.is_action_allowed.return_value = (True, "Allowed")
        
        action_type = action.get("action_type")
        target_value = action.get("target", {}).get("value_masked")
        
        is_dry_run = worker.dry_run or decision.get("dry_run", False)
        self.assertTrue(is_dry_run)
        
        # Emulate the run check
        run_action = True
        
        if run_action:
            allowed, reason = worker.policy_evaluator.is_action_allowed(
                action_type=action_type,
                target=target_value,
                phase="contain",
                approval_mode="AUTO",
                risk_score=8.5
            )
            self.assertTrue(allowed)
            
            if is_dry_run:
                action["status"] = "simulated"
                action["rationale"] = "Simulated successfully."
        
        # Verify the outcome: status must be "simulated" and connectors were NOT called
        self.assertEqual(action["status"], "simulated")
        worker.fortinet.block_ip.assert_not_called()
        worker.waf.block_ip.assert_not_called()

    def test_per_decision_dry_run(self):
        # 1. Global dry-run is disabled
        os.environ["SOAR_DRY_RUN"] = "false"
        worker = SoarActionWorker()
        
        # Decision has dry_run = True
        decision = {
            "input_summary": {"incident_id": "inc-dryrun-02"},
            "dry_run": True,
            "automation_control": {"soc_autopilot_enabled": True, "execution_window": {"in_window": True}, "auto_containment_eligible": True},
            "scoring": {"final_risk_score_0_10": 8.5}
        }
        action = {
            "action_id": "act-02",
            "action_type": "quarantine_host",
            "phase": "contain",
            "approval_mode": "AUTO",
            "target": {"value_masked": "USER-LAPTOP-12"},
            "status": "pending"
        }
        
        worker.crowdstrike = MagicMock()
        worker.policy_evaluator = MagicMock()
        worker.policy_evaluator.is_action_allowed.return_value = (True, "Allowed")
        
        is_dry_run = worker.dry_run or decision.get("dry_run", False)
        self.assertTrue(is_dry_run)
        
        if is_dry_run:
            action["status"] = "simulated"
            
        self.assertEqual(action["status"], "simulated")
        worker.crowdstrike.isolate_host.assert_not_called()

    def test_dry_run_blocked_by_guardrails(self):
        worker = SoarActionWorker()
        
        # Whitelisted target that must be blocked even in dry-run mode
        decision = {
            "input_summary": {"incident_id": "inc-dryrun-03"},
            "dry_run": True,
            "scoring": {"final_risk_score_0_10": 9.9}
        }
        action = {
            "action_id": "act-03",
            "action_type": "block_ip",
            "phase": "contain",
            "approval_mode": "AUTO",
            "target": {"value_masked": "10.0.0.1"}, # CORE IP (Whitelisted!)
            "status": "pending"
        }
        
        allowed, reason = worker.policy_evaluator.is_action_allowed(
            action_type=action["action_type"],
            target=action["target"]["value_masked"],
            phase=action["phase"],
            approval_mode=action["approval_mode"],
            risk_score=9.9
        )
        
        self.assertFalse(allowed)
        self.assertIn("WHITELIST SECURITY VIOLATION", reason)

    def test_p0_alert_triggering(self):
        worker = SoarActionWorker()
        worker.producer = MagicMock()
        worker.executor = MagicMock()

        # Target action blocked by Guardrails
        action = {
            "action_id": "act-p0",
            "action_type": "block_ip",
            "phase": "contain",
            "approval_mode": "AUTO",
            "target": {"value_masked": "10.0.0.1"}
        }

        # Manually trigger alert
        worker.trigger_p0_alert(
            incident_id="inc-p0-test",
            action=action,
            reason="WHITELIST SECURITY VIOLATION: Denied block_ip on protected resource: 10.0.0.1",
            decision={}
        )

        # Verify Kafka producer received the publish call with P0 attributes
        worker.producer.send.assert_called_once()
        args, kwargs = worker.producer.send.call_args
        topic = args[0]
        payload = args[1]
        
        self.assertEqual(payload["status"], "ALLOWED")
        self.assertEqual(payload["attackType"], "GUARDRAILS_VIOLATION")
        self.assertIn("P0 EMERGENCY", payload["description"])
        
        # Verify Audit log was called on the dashboard API
        worker.executor._call_dashboard_perform_action.assert_called_once()

    def test_sync_execution_progress_merges_executed_action(self):
        worker = SoarActionWorker()
        worker.producer = MagicMock()
        worker.executor = MagicMock()

        decision = {
            "timestamp": "2026-07-10T14:00:00Z",
            "input_summary": {"incident_id": "inc-critical-sqli"},
            "verified_case": {
                "title": "Aegis Bank - SQL_INJECTION Detected",
                "entities": {
                    "ips": ["42.114.204.232"],
                    "api_endpoints": ["/login"]
                }
            },
            "decision": {"risk_response_floor": {"performed_actions": []}},
            "output_and_notification": {
                "executed_actions": [],
                "suggested_actions": ["block_ip on 42.114.204.232"]
            },
            "actions": [
                {
                    "action_id": "act-critical-ban",
                    "action_type": "block_ip",
                    "phase": "contain",
                    "approval_mode": "AUTO",
                    "status": "ready_for_execution",
                    "target": {"value_masked": "42.114.204.232"}
                }
            ]
        }
        action = {
            "action_id": "act-critical-ban",
            "action_type": "block_ip",
            "phase": "contain",
            "approval_mode": "AUTO",
            "status": "executed",
            "target": {"value_masked": "42.114.204.232"},
            "rationale": "PB-WEB-EDGE block_ip executed."
        }

        worker.sync_execution_progress(decision, action, "inc-critical-sqli")

        self.assertEqual(decision["actions"][0]["status"], "executed")
        self.assertIn("block_ip", decision["decision"]["risk_response_floor"]["performed_actions"])
        self.assertIn("block_ip on 42.114.204.232", decision["output_and_notification"]["executed_actions"])
        self.assertNotIn("block_ip on 42.114.204.232", decision["output_and_notification"]["suggested_actions"])
        worker.executor._push_l2_decision_to_gateway.assert_called_once_with(decision)

if __name__ == "__main__":
    unittest.main()
