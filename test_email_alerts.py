import unittest
from unittest.mock import MagicMock, patch
import os
import json

# Setup environment to allow imports
os.environ["SMTP_HOST"] = "mock-smtp-host"

from notification_dispatcher import NotificationDispatcher
from action_worker import SoarActionWorker

class TestEmailAlerts(unittest.TestCase):
    @patch("notification_dispatcher._EmailConnector.send")
    def test_notification_dispatcher_immediate_alert_email(self, mock_send):
        mock_send.return_value = (True, "Email sent successfully.")
        dispatcher = NotificationDispatcher()
        dispatcher._enabled.add("email")
        
        alert_critical = {
            "severity": "CRITICAL",
            "title": "Critical Alert Title",
            "summary": "This is a critical security incident details."
        }
        dispatcher.dispatch_immediate_alert(alert_critical)
        
        mock_send.assert_called()
        subject, body = mock_send.call_args[0]
        self.assertIn("CRITICAL", subject)
        self.assertIn("Critical Alert Title", subject)
        self.assertIn("This is a critical security incident details.", body)
        
        mock_send.reset_mock()
        
        alert_low = {
            "severity": "LOW",
            "title": "Low Alert Title",
            "summary": "This is a low security incident."
        }
        dispatcher.dispatch_immediate_alert(alert_low)
        mock_send.assert_not_called()

    @patch("connectors.email_connector.EmailConnector.send_alert_email")
    @patch("action_worker.SoarActionWorker.sync_execution_progress")
    @patch("playbook_executor.PlaybookExecutor._call_dashboard_perform_action")
    def test_action_worker_notify_soc_email(self, mock_perform_action, mock_sync_progress, mock_send_email):
        mock_send_email.return_value = (True, "Email sent successfully.")
        mock_perform_action.return_value = (True, "Success")
        
        worker = SoarActionWorker()
        worker.dry_run = False
        worker.redis = None
        
        action = {
            "action_id": "act-test-notify",
            "action_type": "notify_soc",
            "phase": "notify",
            "approval_mode": "AUTO",
            "target": {"value_masked": "soc-team@aegis.bank"},
            "rationale": "High risk detected. Alerting SOC."
        }
        decision = {
            "input_summary": {"incident_id": "INC-12345"},
            "automation_control": {
                "soc_autopilot_enabled": True,
                "execution_window": {"in_window": True},
                "auto_containment_eligible": True
            }
        }
        
        self.assertIsNotNone(worker.email)
        
        msg_value = {
            "incident_id": "INC-12345",
            "decision": decision,
            "action": action
        }
        
        class MockMessage:
            def __init__(self, val):
                self.value = json.dumps(val).encode('utf-8')
        
        with patch("action_worker.KafkaConsumer") as mock_consumer:
            mock_consumer.return_value = [MockMessage(msg_value)]
            worker.start_rate_limited_executor()
            
        mock_send_email.assert_called_once()
        subject, body_html = mock_send_email.call_args[0]
        self.assertIn("INC-12345", subject)
        self.assertIn("Alerting SOC.", body_html)

    @patch("connectors.email_connector.EmailConnector.send_alert_email")
    def test_action_worker_p0_alert_email(self, mock_send_email):
        mock_send_email.return_value = (True, "Email sent successfully.")
        worker = SoarActionWorker()
        
        action = {
            "action_type": "block_ip",
            "target": {"value_masked": "198.51.100.4"}
        }
        
        worker.trigger_p0_alert("INC-9999", action, "Unsafe action on core system", {})
        
        mock_send_email.assert_called_once()
        subject, body_html = mock_send_email.call_args[0]
        self.assertIn("P0 EMERGENCY", subject)
        self.assertIn("INC-9999", subject)
        self.assertIn("Unsafe action on core system", body_html)

if __name__ == "__main__":
    unittest.main()
