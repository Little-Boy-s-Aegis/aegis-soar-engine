import unittest
import os
import json
from tune_guardrails import tune_system

class TestTuneGuardrails(unittest.TestCase):
    def setUp(self):
        self.test_whitelist = "test_tuning_whitelist.json"
        self.test_history = "test_tuning_history.log"
        
        # Initialize test whitelist
        initial_whitelist = {
            "ips": ["10.0.0.1"],
            "hosts": ["DB-PROD"],
            "domains": ["aegis.com"]
        }
        with open(self.test_whitelist, "w", encoding="utf-8") as f:
            json.dump(initial_whitelist, f, indent=2)

    def tearDown(self):
        for path in (self.test_whitelist, self.test_history):
            if os.path.exists(path):
                os.remove(path)

    def test_false_positive_tuning(self):
        # Tune an IP that was blocked as a false positive
        success = tune_system(
            feedback_type="FP",
            target="192.168.1.99",
            action_type="block_ip",
            incident_id="inc-fp-101",
            reason="Internal dev scanning, not a real threat.",
            whitelist_path=self.test_whitelist,
            log_path=self.test_history
        )
        
        self.assertTrue(success)
        
        # Verify whitelist change
        with open(self.test_whitelist, "r", encoding="utf-8") as f:
            w = json.load(f)
            self.assertIn("192.168.1.99", w["ips"])
            
        # Verify log entry exists
        self.assertTrue(os.path.exists(self.test_history))
        with open(self.test_history, "r", encoding="utf-8") as f:
            log_lines = f.readlines()
            self.assertEqual(len(log_lines), 1)
            payload = json.loads(log_lines[0])
            self.assertEqual(payload["incident_id"], "inc-fp-101")
            self.assertEqual(payload["feedback_type"], "FP")
            self.assertIn("checksum", payload)

    def test_false_negative_tuning(self):
        # Tune an IP that was allowed because it was on the whitelist, but was actually a threat (False Negative)
        success = tune_system(
            feedback_type="FN",
            target="10.0.0.1",
            action_type="block_ip",
            incident_id="inc-fn-202",
            reason="Host compromised, must be removed from whitelist to allow blocks.",
            whitelist_path=self.test_whitelist,
            log_path=self.test_history
        )
        
        self.assertTrue(success)
        
        # Verify whitelist change: 10.0.0.1 should be removed
        with open(self.test_whitelist, "r", encoding="utf-8") as f:
            w = json.load(f)
            self.assertNotIn("10.0.0.1", w["ips"])

if __name__ == "__main__":
    unittest.main()
