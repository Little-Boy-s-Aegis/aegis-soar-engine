import unittest
import os
import json
import sys
from unittest.mock import patch, MagicMock

# Mock psycopg2 module if not installed in the test environment
try:
    import psycopg2
except ImportError:
    psycopg2_mock = MagicMock()
    sys.modules['psycopg2'] = psycopg2_mock

from audit_logger import SoarAuditLogger

class TestSoarAuditLogger(unittest.TestCase):
    def setUp(self):
        # Set clean log environment for tests
        self.test_log_path = "test_audit_trail.log"
        os.environ["SOAR_AUDIT_LOG_PATH"] = self.test_log_path
        os.environ["SOAR_AUDIT_DB_ENABLED"] = "false"
        
        # Close existing file handlers to prevent locks
        from audit_logger import get_audit_logger
        logger = get_audit_logger()
        if logger:
            for h in list(logger.handlers):
                h.close()
                logger.removeHandler(h)
        
        # Clean any existing file
        if os.path.exists(self.test_log_path):
            try:
                os.remove(self.test_log_path)
            except Exception:
                pass

    def tearDown(self):
        # Close active file handlers
        from audit_logger import get_audit_logger
        logger = get_audit_logger()
        if logger:
            for h in list(logger.handlers):
                h.close()
                logger.removeHandler(h)
                
        # Clean test log file
        if os.path.exists(self.test_log_path):
            try:
                os.remove(self.test_log_path)
            except Exception:
                pass

    def test_log_ai_decision(self):
        # Log AI Decision
        SoarAuditLogger.log_ai_decision(
            incident_id="inc-test-ai",
            input_prompt="Detect anomalies",
            raw_output='{"decision": "block"}',
            parsed_decision={"decision": "block"}
        )
        
        # Verify log file was created and contains the logged values
        self.assertTrue(os.path.exists(self.test_log_path))
        with open(self.test_log_path, "r", encoding="utf-8") as f:
            log_line = f.readline()
            self.assertIn("AUDIT:", log_line)
            
            # Extract JSON payload from audit format
            json_str = log_line.split("AUDIT: ")[1].strip()
            payload = json.loads(json_str)
            
            self.assertEqual(payload["eventType"], "AI_DECISION")
            self.assertEqual(payload["incidentId"], "inc-test-ai")
            self.assertEqual(payload["details"]["inputPrompt"], "Detect anomalies")
            self.assertEqual(payload["details"]["rawOutput"], '{"decision": "block"}')

    def test_log_guardrail_check(self):
        action = {"action_type": "quarantine_host", "target": "DB-PROD"}
        SoarAuditLogger.log_guardrail_check(
            incident_id="inc-test-guard",
            action=action,
            allowed=False,
            reason="Blocked by static Whitelist"
        )
        
        with open(self.test_log_path, "r", encoding="utf-8") as f:
            log_line = f.readline()
            json_str = log_line.split("AUDIT: ")[1].strip()
            payload = json.loads(json_str)
            
            self.assertEqual(payload["eventType"], "GUARDRAILS_CHECK")
            self.assertEqual(payload["incidentId"], "inc-test-guard")
            self.assertFalse(payload["details"]["allowed"])
            self.assertEqual(payload["details"]["reason"], "Blocked by static Whitelist")

    def test_log_api_response(self):
        SoarAuditLogger.log_api_response(
            incident_id="inc-test-api",
            target_system="fortinet",
            action_type="block_ip",
            request_params={"ip": "10.0.0.1"},
            success=True,
            response_msg="IP added to address group successfully"
        )
        
        with open(self.test_log_path, "r", encoding="utf-8") as f:
            log_line = f.readline()
            json_str = log_line.split("AUDIT: ")[1].strip()
            payload = json.loads(json_str)
            
            self.assertEqual(payload["eventType"], "API_CONNECTOR")
            self.assertEqual(payload["incidentId"], "inc-test-api")
            self.assertEqual(payload["details"]["targetSystem"], "fortinet")
            self.assertTrue(payload["details"]["success"])
            self.assertEqual(payload["details"]["responseMessage"], "IP added to address group successfully")

    @patch('psycopg2.connect')
    def test_centralized_db_audit_logging(self, mock_connect):
        # Enable database logging for this test
        os.environ["SOAR_AUDIT_DB_ENABLED"] = "true"
        
        # Reset table initialization flag to trigger init_db_table
        import audit_logger
        audit_logger._db_table_initialized = False

        # Set up mock database connection
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        # Log AI Decision
        SoarAuditLogger.log_ai_decision(
            incident_id="inc-db-test",
            input_prompt="Detect anomalies",
            raw_output='{"decision": "block"}',
            parsed_decision={"decision": "block"}
        )

        # Assert table creation and indices creation query were executed
        # Check that CREATE TABLE and INSERT INTO were called
        mock_cursor.execute.assert_any_call(
            "\n                CREATE TABLE IF NOT EXISTS soar_audit_logs (\n                    id SERIAL PRIMARY KEY,\n                    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,\n                    event_type VARCHAR(50) NOT NULL,\n                    incident_id VARCHAR(100) NOT NULL,\n                    details JSONB NOT NULL,\n                    hash CHAR(64),\n                    prev_hash CHAR(64)\n                );\n            "
        )
        
        # Verify database insert query
        mock_cursor.execute.assert_any_call(
            "INSERT INTO soar_audit_logs (timestamp, event_type, incident_id, details, hash, prev_hash) VALUES (%s, %s, %s, %s, %s, %s)",
            unittest.mock.ANY
        )
        
        mock_conn.commit.assert_called()

if __name__ == "__main__":
    from unittest.mock import patch, MagicMock
    unittest.main()
