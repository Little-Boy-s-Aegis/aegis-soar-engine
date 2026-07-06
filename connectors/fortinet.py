import logging
import requests
import os
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.fortinet")

class FortinetConnector:
    """API Connector for Fortinet FortiGate Firewall to block malicious IPs and Domains."""

    def __init__(self):
        self.firewall_ip = os.getenv("FORTINET_FIREWALL_IP", "192.168.1.99")
        self.api_token = secrets.get_secret("FORTINET_API_TOKEN", "mock-fortinet-token-123456")
        
        # Support base url override for sandbox/staging environment simulation
        self.base_url = os.getenv("FORTINET_BASE_URL")
        if not self.base_url:
            proto = "http" if "localhost" in self.firewall_ip or "127.0.0.1" in self.firewall_ip else "https"
            self.base_url = f"{proto}://{self.firewall_ip}/api/v2"
            
        self.headers = {
            "Content-Type": "application/json"
        }
        self.verify_ssl = os.getenv("FORTINET_VERIFY_SSL", "false").lower() == "true"

    def block_ip(self, ip_address: str) -> tuple:
        """
        Creates an address object for the IP and adds it to the blocked group.
        Returns (success, message).
        """
        logger.info(f"[FORTINET] Request to block IP: {ip_address}")
        
        # 1. Create Address Object
        addr_name = f"blocked_ip_{ip_address.replace('.', '_')}"
        addr_payload = {
            "name": addr_name,
            "type": "ipmask",
            "subnet": f"{ip_address} 255.255.255.255",
            "comment": "Blocked automatically by Aegis SOAR"
        }
        
        url_addr = f"{self.base_url}/cmdb/firewall/address?access_token={self.api_token}"
        try:
            logger.info(f"[FORTINET] Creating address object '{addr_name}'...")
            # For demonstration, handle dry-run or mock tokens gracefully
            if self.api_token == "mock-fortinet-token-123456":
                logger.info(f"[FORTINET-SIMULATION] Created address object '{addr_name}' successfully.")
            else:
                res = requests.post(url_addr, headers=self.headers, json=addr_payload, verify=self.verify_ssl, timeout=10)
                if res.status_code not in (200, 201, 500): # 500 can occur if it already exists
                    return False, f"Failed to create address object: HTTP {res.status_code} - {res.text}"
                
            # 2. Add to Group
            group_name = "Blocked_IPs_Group"
            group_payload = {
                "name": group_name,
                "member": [{"name": addr_name}]
            }
            url_group = f"{self.base_url}/cmdb/firewall/addrgrp/{group_name}?access_token={self.api_token}"
            
            if self.api_token == "mock-fortinet-token-123456":
                logger.info(f"[FORTINET-SIMULATION] Added address '{addr_name}' to group '{group_name}' successfully.")
                return True, f"[SIMULATION] IP {ip_address} blocked on Fortinet Firewall."
            else:
                res = requests.put(url_group, headers=self.headers, json=group_payload, verify=self.verify_ssl, timeout=10)
                if res.status_code not in (200, 201):
                    # Try POST if PUT doesn't support appending, or handle existing members
                    res = requests.post(url_group, headers=self.headers, json=group_payload, verify=self.verify_ssl, timeout=10)
                    if res.status_code not in (200, 201, 500):
                        return False, f"Failed to add address to group: HTTP {res.status_code} - {res.text}"
            
            return True, f"IP {ip_address} successfully blocked on Fortinet Firewall (Address: {addr_name}, Group: {group_name})."
            
        except Exception as e:
            logger.error(f"[FORTINET ERROR] Failed to connect to FortiGate: {e}")
            return False, f"Connection error: {str(e)}"

    def block_domain(self, domain: str) -> tuple:
        """
        Creates an FQDN address object for the domain and adds it to the blocked group.
        Returns (success, message).
        """
        logger.info(f"[FORTINET] Request to block Domain: {domain}")
        
        addr_name = f"blocked_domain_{domain.replace('.', '_')}"
        addr_payload = {
            "name": addr_name,
            "type": "fqdn",
            "fqdn": domain,
            "comment": "Blocked automatically by Aegis SOAR"
        }
        
        url_addr = f"{self.base_url}/cmdb/firewall/address?access_token={self.api_token}"
        try:
            logger.info(f"[FORTINET] Creating FQDN address object '{addr_name}'...")
            if self.api_token == "mock-fortinet-token-123456":
                logger.info(f"[FORTINET-SIMULATION] Created FQDN address object '{addr_name}' successfully.")
            else:
                res = requests.post(url_addr, headers=self.headers, json=addr_payload, verify=self.verify_ssl, timeout=10)
                if res.status_code not in (200, 201, 500):
                    return False, f"Failed to create domain address object: HTTP {res.status_code} - {res.text}"
                
            group_name = "Blocked_Domains_Group"
            group_payload = {
                "name": group_name,
                "member": [{"name": addr_name}]
            }
            url_group = f"{self.base_url}/cmdb/firewall/addrgrp/{group_name}?access_token={self.api_token}"
            
            if self.api_token == "mock-fortinet-token-123456":
                logger.info(f"[FORTINET-SIMULATION] Added domain '{addr_name}' to group '{group_name}' successfully.")
                return True, f"[SIMULATION] Domain {domain} blocked on Fortinet Firewall."
            else:
                res = requests.put(url_group, headers=self.headers, json=group_payload, verify=self.verify_ssl, timeout=10)
                if res.status_code not in (200, 201):
                    res = requests.post(url_group, headers=self.headers, json=group_payload, verify=self.verify_ssl, timeout=10)
                    if res.status_code not in (200, 201, 500):
                        return False, f"Failed to add domain to group: HTTP {res.status_code} - {res.text}"
            
            return True, f"Domain {domain} successfully blocked on Fortinet Firewall (Address: {addr_name}, Group: {group_name})."
            
        except Exception as e:
            logger.error(f"[FORTINET ERROR] Failed to connect to FortiGate: {e}")
            return False, f"Connection error: {str(e)}"

    def unblock_ip(self, ip_address: str) -> tuple:
        """
        Deletes the address object for the IP and removes it from the blocked group.
        Returns (success, message).
        """
        logger.info(f"[FORTINET] Request to unblock IP: {ip_address}")
        addr_name = f"blocked_ip_{ip_address.replace('.', '_')}"
        group_name = "Blocked_IPs_Group"
        
        try:
            if self.api_token == "mock-fortinet-token-123456":
                logger.info(f"[FORTINET-SIMULATION] Removed IP {ip_address} from blocklist.")
                return True, f"[SIMULATION] IP {ip_address} unblocked on Fortinet Firewall."
                
            # Remove from Group first, then delete address object
            # Removing member from group on FortiGate is done via PUT/POST or by deleting the address object directly
            url_delete = f"{self.base_url}/cmdb/firewall/address/{addr_name}?access_token={self.api_token}"
            res = requests.delete(url_delete, headers=self.headers, verify=self.verify_ssl, timeout=10)
            if res.status_code in (200, 204, 404):
                return True, f"IP {ip_address} successfully unblocked on Fortinet Firewall."
            return False, f"Failed to delete address object: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[FORTINET ERROR] Failed to unblock IP: {e}")
            return False, f"Connection error: {str(e)}"

    def unblock_domain(self, domain: str) -> tuple:
        """
        Deletes the FQDN address object for the domain.
        Returns (success, message).
        """
        logger.info(f"[FORTINET] Request to unblock Domain: {domain}")
        addr_name = f"blocked_domain_{domain.replace('.', '_')}"
        
        try:
            if self.api_token == "mock-fortinet-token-123456":
                logger.info(f"[FORTINET-SIMULATION] Removed Domain {domain} from blocklist.")
                return True, f"[SIMULATION] Domain {domain} unblocked on Fortinet Firewall."
                
            url_delete = f"{self.base_url}/cmdb/firewall/address/{addr_name}?access_token={self.api_token}"
            res = requests.delete(url_delete, headers=self.headers, verify=self.verify_ssl, timeout=10)
            if res.status_code in (200, 204, 404):
                return True, f"Domain {domain} successfully unblocked on Fortinet Firewall."
            return False, f"Failed to delete FQDN address object: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[FORTINET ERROR] Failed to unblock Domain: {e}")
            return False, f"Connection error: {str(e)}"
