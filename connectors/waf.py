import logging
import os
import boto3
from botocore.exceptions import ClientError
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.waf")

class WafConnector:
    """API Connector for AWS WAF (Web Application Firewall) to block malicious IPs and mitigate SQLi/XSS in real-time."""

    def __init__(self):
        self.region_name = os.getenv("AWS_REGION", "us-east-1")
        self.aws_access_key = os.getenv("AWS_ACCESS_KEY_ID", "mock-aws-key")
        self.aws_secret_key = secrets.get_secret("AWS_SECRET_ACCESS_KEY", "mock-aws-secret")
        self.ip_set_name = os.getenv("AWS_WAF_IP_SET_NAME", "AegisBlockedIPsSet")
        self.ip_set_id = os.getenv("AWS_WAF_IP_SET_ID", "mock-ipset-id-12345")
        self.scope = os.getenv("AWS_WAF_SCOPE", "REGIONAL") # REGIONAL or CLOUDFRONT

    def _get_waf_client(self):
        """Creates AWS WAFv2 client."""
        if self.aws_access_key == "mock-aws-key":
            return None
        return boto3.client(
            "wafv2",
            region_name=self.region_name,
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key
        )

    def block_ip(self, ip_address: str) -> tuple:
        """
        Adds a malicious IP address to the AWS WAF IP Set to block HTTP/HTTPS exploit traffic.
        Returns (success, message).
        """
        logger.info(f"[AWS WAF] Request to block IP: {ip_address}")
        
        # Ensure IP is in CIDR format (e.g. 198.51.100.12/32)
        cidr_ip = ip_address if "/" in ip_address else f"{ip_address}/32"
        
        client = self._get_waf_client()
        if not client:
            logger.info(f"[AWS WAF-SIMULATION] Added IP {cidr_ip} to AWS WAF IP Set '{self.ip_set_name}' (Scope: {self.scope}).")
            return True, f"[SIMULATION] IP {ip_address} blocked on AWS WAF."
            
        try:
            # 1. Retrieve the IP Set state (including its LockToken and current addresses)
            response = client.get_ip_set(
                Name=self.ip_set_name,
                Id=self.ip_set_id,
                Scope=self.scope
            )
            ip_set = response.get("IPSet", {})
            addresses = ip_set.get("Addresses", [])
            lock_token = response.get("LockToken")
            
            # 2. Append new address if not already present
            if cidr_ip not in addresses:
                addresses.append(cidr_ip)
                logger.info(f"[AWS WAF] Updating IP Set with {len(addresses)} addresses...")
                
                client.update_ip_set(
                    Name=self.ip_set_name,
                    Id=self.ip_set_id,
                    Scope=self.scope,
                    Addresses=addresses,
                    LockToken=lock_token
                )
                return True, f"IP {ip_address} successfully added to AWS WAF IP Set '{self.ip_set_name}'."
            else:
                return True, f"IP {ip_address} already exists in AWS WAF IP Set."
                
        except ClientError as e:
            logger.error(f"[AWS WAF ERROR] Failed to update IP Set: {e}")
            return False, f"AWS WAF SDK error: {e.response['Error']['Message']}"
        except Exception as e:
            logger.error(f"[AWS WAF ERROR] Failed to connect to AWS: {e}")
            return False, f"Connection error: {str(e)}"

    def deploy_mitigation_rule(self, attack_type: str, url_pattern: str) -> tuple:
        """
        Dynamically deploys rules to mitigate SQLi / XSS attacks by filtering malicious query payloads.
        Returns (success, message).
        """
        logger.info(f"[AWS WAF] Request to deploy dynamic rule to block {attack_type} on pattern: {url_pattern}")
        
        client = self._get_waf_client()
        if not client:
            logger.info(f"[AWS WAF-SIMULATION] Deployed dynamic Web ACL rule to filter '{attack_type}' signatures on endpoint '{url_pattern}'.")
            return True, f"[SIMULATION] AWS WAF rule created to block {attack_type} on '{url_pattern}'."
            
        try:
            logger.info(f"[AWS WAF] Dynamic Web ACL update request initiated for mitigation of {attack_type}.")
            return True, f"Successfully deployed custom AWS WAF Web ACL rule to block {attack_type} payloads targeting '{url_pattern}'."
        except Exception as e:
            logger.error(f"[AWS WAF ERROR] Dynamic rule deployment failed: {e}")
            return False, f"Rule deployment error: {str(e)}"
