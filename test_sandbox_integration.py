import unittest
import os
import sys
import time
import requests
import subprocess
import signal

# Add path for connectors
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from connectors.fortinet import FortinetConnector
from connectors.active_directory import ActiveDirectoryConnector
from connectors.crowdstrike import CrowdStrikeConnector

class TestSandboxIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 8096
        # Start Sandbox Server in background
        sandbox_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "staging-sandbox", "app.py")
        
        # Configure port
        os.environ["SANDBOX_PORT"] = str(cls.port)
        cls.process = subprocess.Popen(
            [sys.executable, sandbox_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for sandbox server to boot up
        time.sleep(2)
        
        # Set environment variables for Connectors to point to sandbox
        os.environ["FORTINET_BASE_URL"] = f"http://localhost:{cls.port}/api/v2"
        os.environ["FORTINET_FIREWALL_IP"] = f"localhost:{cls.port}"
        os.environ["FORTINET_API_TOKEN"] = "sandbox-token-xyz"
        
        os.environ["ENTRA_TOKEN_URL"] = f"http://localhost:{cls.port}/oauth2/v2.0/token"
        os.environ["ENTRA_GRAPH_URL"] = f"http://localhost:{cls.port}"
        os.environ["ENTRA_CLIENT_SECRET"] = "sandbox-secret-123"
        
        os.environ["CROWDSTRIKE_BASE_URL"] = f"http://localhost:{cls.port}"
        os.environ["CROWDSTRIKE_CLIENT_SECRET"] = "sandbox-cs-secret"

    @classmethod
    def tearDownClass(cls):
        # Shut down Sandbox Server
        if cls.process:
            cls.process.terminate()
            cls.process.wait()

    def test_e2e_sandbox_fortinet_block(self):
        # Trigger firewall block
        connector = FortinetConnector()
        success, msg = connector.block_ip("192.168.5.5")
        
        self.assertTrue(success)
        
        # Query sandbox state to verify update
        res = requests.get(f"http://localhost:{self.port}/")
        self.assertEqual(res.status_code, 200)
        
        # Verify IP is blocked in simulator state
        state_res = requests.post(f"http://localhost:{self.port}/api/v2/cmdb/firewall/addrgrp/Blocked_IPs_Group", json={"member": []})
        self.assertEqual(state_res.status_code, 200)

    def test_e2e_sandbox_ad_disable(self):
        # Trigger AD disable
        connector = ActiveDirectoryConnector()
        success, msg = connector.disable_account("john_doe")
        
        self.assertTrue(success)

    def test_e2e_sandbox_crowdstrike_isolate(self):
        # Trigger host isolation
        connector = CrowdStrikeConnector()
        success, msg = connector.isolate_host("WEB-PROD-01")
        
        self.assertTrue(success)

if __name__ == "__main__":
    unittest.main()
