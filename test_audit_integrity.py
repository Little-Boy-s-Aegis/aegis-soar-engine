import unittest
import os
import json
import shutil
from audit_logger import SoarAuditLogger
from verify_audit_integrity import verify_file_integrity

class TestAuditIntegrity(unittest.TestCase):
    def setUp(self):
        self.test_log_path = "test_integrity_trail.log"
        os.environ["SOAR_AUDIT_LOG_PATH"] = self.test_log_path
        os.environ["SOAR_AUDIT_DB_ENABLED"] = "false"
        
        # Reset local hash chain
        import audit_logger
        audit_logger._last_log_hash = None
        
        # Close existing file handlers to prevent locks
        from audit_logger import get_audit_logger
        audit_chan = get_audit_logger()
        for h in list(audit_chan.handlers):
            h.close()
            audit_chan.removeHandler(h)
            
        # Remove file if exists
        if os.path.exists(self.test_log_path):
            os.remove(self.test_log_path)

    def tearDown(self):
        from audit_logger import get_audit_logger
        audit_chan = get_audit_logger()
        for h in list(audit_chan.handlers):
            h.close()
            audit_chan.removeHandler(h)
            
        if os.path.exists(self.test_log_path):
            os.remove(self.test_log_path)

    def test_log_chain_integrity(self):
        # 1. Write some valid logs
        SoarAuditLogger.log_event("TEST_EVENT", "inc-1", {"val": 100})
        SoarAuditLogger.log_event("TEST_EVENT", "inc-2", {"val": 200})
        SoarAuditLogger.log_event("TEST_EVENT", "inc-3", {"val": 300})
        
        # 2. Verify integrity is valid
        self.assertTrue(verify_file_integrity(self.test_log_path))
        
    def test_log_chain_tampering_detection(self):
        # 1. Write logs
        SoarAuditLogger.log_event("TEST_EVENT", "inc-1", {"val": 100})
        SoarAuditLogger.log_event("TEST_EVENT", "inc-2", {"val": 200})
        SoarAuditLogger.log_event("TEST_EVENT", "inc-3", {"val": 300})
        
        # Read the logs
        with open(self.test_log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # 2. Tamper with the second line details value
        tampered_line = lines[1].replace('"val": 200', '"val": 999')
        lines[1] = tampered_line
        
        # Write tampered logs back
        with open(self.test_log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        # 3. Verify integrity detection fails
        self.assertFalse(verify_file_integrity(self.test_log_path))

if __name__ == "__main__":
    unittest.main()
