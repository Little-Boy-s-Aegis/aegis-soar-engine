import unittest
import os
from generate_weekly_report import generate_weekly_report

class TestWeeklyReport(unittest.TestCase):
    def setUp(self):
        self.test_log_path = "test_weekly_audit.log"
        self.test_report_path = "test_weekly_report.md"
        
        # Cleanup
        for path in (self.test_log_path, self.test_report_path):
            if os.path.exists(path):
                os.remove(path)

    def tearDown(self):
        for path in (self.test_log_path, self.test_report_path):
            if os.path.exists(path):
                os.remove(path)

    def test_report_generation(self):
        # Create empty log file to test fallback paths
        with open(self.test_log_path, "w", encoding="utf-8") as f:
            f.write("")
            
        success, out_path = generate_weekly_report(self.test_log_path, self.test_report_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.test_report_path))
        
        # Verify content
        with open(self.test_report_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("# Aegis SOAR Weekly Executive Report", content)
            self.assertIn("Key Performance Indicators (KPIs)", content)
            self.assertIn("Automated Containment Actions Log", content)

if __name__ == "__main__":
    unittest.main()
