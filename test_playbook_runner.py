import unittest
import json
import os
from playbook_runner import PlaybookRunner

class TestPlaybookRunner(unittest.TestCase):
    def setUp(self):
        # We will write a temporary playbooks file for testing
        self.test_playbooks = {
            "PB-TEST-CONDITIONAL": {
                "playbook_id": "PB-TEST-CONDITIONAL",
                "name": "Test Conditional Playbook",
                "steps": [
                    {
                        "step_id": "step-1",
                        "type": "if_else",
                        "condition": "risk_score > 5.0",
                        "then_steps": [
                            {
                                "step_id": "step-then",
                                "type": "action",
                                "action_type": "block_ip",
                                "target": "entities.ips",
                                "loop": True,
                                "approval_mode": "AUTO"
                            }
                        ],
                        "else_steps": [
                            {
                                "step_id": "step-else",
                                "type": "action",
                                "action_type": "notify_soc",
                                "target": "soc_team",
                                "loop": False,
                                "approval_mode": "AUTO"
                            }
                        ]
                    }
                ]
            },
            "PB-TEST-PARALLEL": {
                "playbook_id": "PB-TEST-PARALLEL",
                "name": "Test Parallel Playbook",
                "steps": [
                    {
                        "step_id": "step-parallel",
                        "type": "parallel",
                        "parallel_steps": [
                            {
                                "step_id": "step-p1",
                                "type": "action",
                                "action_type": "force_logout",
                                "target": "entities.users",
                                "loop": True,
                                "approval_mode": "AUTO"
                            },
                            {
                                "step_id": "step-p2",
                                "type": "action",
                                "action_type": "quarantine_host",
                                "target": "entities.hosts",
                                "loop": True,
                                "approval_mode": "APPROVAL_REQUIRED"
                            }
                        ]
                    }
                ]
            },
            "PB-TEST-RETRY": {
                "playbook_id": "PB-TEST-RETRY",
                "name": "Test Retry Playbook",
                "steps": [
                    {
                        "step_id": "step-retry",
                        "type": "action",
                        "action_type": "block_ip",
                        "target": "1.1.1.1",
                        "loop": False,
                        "approval_mode": "AUTO",
                        "retry": {
                            "max_attempts": 3,
                            "delay_seconds": 2
                        },
                        "fallback_step": {
                            "step_id": "step-fallback",
                            "type": "action",
                            "action_type": "notify_soc",
                            "target": "soc_team",
                            "loop": False,
                            "approval_mode": "AUTO"
                        }
                    }
                ]
            }
        }
        self.filename = "test_playbooks.json"
        with open(self.filename, "w", encoding="utf-8") as f:
            json.dump(self.test_playbooks, f)
            
        self.runner = PlaybookRunner(playbooks_path=self.filename)

    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)

    def test_conditional_then_branch(self):
        context = {
            "scoring": {
                "final_risk_score_0_10": 7.5
            },
            "verified_case": {
                "threat_confirmed": True,
                "entities": {
                    "ips": ["198.51.100.1", "198.51.100.2"]
                }
            }
        }
        
        actions = self.runner.execute_playbook("PB-TEST-CONDITIONAL", context)
        # Should execute the then branch: 2 block_ip actions
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["action_type"], "block_ip")
        self.assertEqual(actions[0]["target"]["value_masked"], "198.51.100.1")
        self.assertEqual(actions[1]["target"]["value_masked"], "198.51.100.2")

    def test_conditional_else_branch(self):
        context = {
            "scoring": {
                "final_risk_score_0_10": 3.0
            },
            "verified_case": {
                "threat_confirmed": False,
                "entities": {
                    "ips": ["198.51.100.1"]
                }
            }
        }
        
        actions = self.runner.execute_playbook("PB-TEST-CONDITIONAL", context)
        # Should execute the else branch: 1 notify_soc action
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action_type"], "notify_soc")
        self.assertEqual(actions[0]["target"]["value_masked"], "soc_team")

    def test_parallel_and_loop_steps(self):
        context = {
            "verified_case": {
                "entities": {
                    "users": ["alice", "bob"],
                    "hosts": ["host-01"]
                }
            }
        }
        
        actions = self.runner.execute_playbook("PB-TEST-PARALLEL", context)
        # Should execute parallel steps, combining loop outputs:
        # 2 force_logout actions (loop) + 1 quarantine_host action (loop) = 3 total actions
        self.assertEqual(len(actions), 3)
        
        action_types = [a["action_type"] for a in actions]
        self.assertEqual(action_types.count("force_logout"), 2)
        self.assertEqual(action_types.count("quarantine_host"), 1)

    def test_retry_and_fallback_extraction(self):
        context = {}
        actions = self.runner.execute_playbook("PB-TEST-RETRY", context)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action_type"], "block_ip")
        self.assertEqual(actions[0]["retry"]["max_attempts"], 3)
        self.assertEqual(actions[0]["retry"]["delay_seconds"], 2)
        self.assertEqual(actions[0]["fallback_step"]["action_type"], "notify_soc")
        self.assertEqual(actions[0]["fallback_step"]["target"], "soc_team")

    def test_unsafe_conditions(self):
        # We will add a playbook with an unsafe condition
        self.test_playbooks["PB-TEST-UNSAFE"] = {
            "playbook_id": "PB-TEST-UNSAFE",
            "name": "Unsafe Condition Playbook",
            "steps": [
                {
                    "step_id": "step-1",
                    "type": "if_else",
                    "condition": "risk_score > 5.0 and [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings']",
                    "then_steps": [
                        {
                            "step_id": "step-then",
                            "type": "action",
                            "action_type": "block_ip",
                            "target": "1.1.1.1",
                            "loop": False,
                            "approval_mode": "AUTO"
                        }
                    ],
                    "else_steps": [
                        {
                            "step_id": "step-else",
                            "type": "action",
                            "action_type": "notify_soc",
                            "target": "soc_team",
                            "loop": False,
                            "approval_mode": "AUTO"
                        }
                    ]
                }
            ]
        }
        with open(self.filename, "w", encoding="utf-8") as f:
            json.dump(self.test_playbooks, f)
            
        runner = PlaybookRunner(playbooks_path=self.filename)
        context = {
            "scoring": {
                "final_risk_score_0_10": 9.0
            }
        }
        actions = runner.execute_playbook("PB-TEST-UNSAFE", context)
        # Should evaluate to False because of unsafe sanitization, running else branch (1 notify_soc action)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action_type"], "notify_soc")

if __name__ == "__main__":
    unittest.main()
