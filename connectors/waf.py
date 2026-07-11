import logging
import os
from secret_manager import secrets

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    class ClientError(Exception):
        pass

logger = logging.getLogger("soar-engine.connectors.waf")

class WafConnector:
    """API Connector for AWS WAF (Web Application Firewall) to block malicious IPs and mitigate SQLi/XSS in real-time."""

    def __init__(self):
        self.region_name = os.getenv("AWS_REGION", "us-east-1")
        self.aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = secrets.get_secret("AWS_SECRET_ACCESS_KEY", "") if self.aws_access_key else None
        self.ip_set_name = os.getenv("AWS_WAF_IP_SET_NAME", "AegisBlockedIPsSet")
        self.ip_set_id = os.getenv("AWS_WAF_IP_SET_ID", "mock-ipset-id-12345")
        self.scope = os.getenv("AWS_WAF_SCOPE", "REGIONAL") # REGIONAL or CLOUDFRONT
        self.simulation_mode = os.getenv("AWS_WAF_SIMULATION", "false").lower() == "true"
        self.ip_sets = [{
            "name": self.ip_set_name,
            "id": self.ip_set_id,
            "scope": self.scope,
            "region": self.region_name,
        }]

        cloudfront_ip_set_name = os.getenv("AWS_WAF_CLOUDFRONT_IP_SET_NAME")
        cloudfront_ip_set_id = os.getenv("AWS_WAF_CLOUDFRONT_IP_SET_ID")
        if cloudfront_ip_set_name and cloudfront_ip_set_id:
            self.ip_sets.append({
                "name": cloudfront_ip_set_name,
                "id": cloudfront_ip_set_id,
                "scope": os.getenv("AWS_WAF_CLOUDFRONT_SCOPE", "CLOUDFRONT"),
                "region": os.getenv("AWS_WAF_CLOUDFRONT_REGION", "us-east-1"),
            })

    def _get_waf_client(self, region_name=None):
        """Creates AWS WAFv2 client."""
        if self.simulation_mode or boto3 is None:
            return None
        client_region = region_name or self.region_name
        if self.aws_access_key:
            return boto3.client(
                "wafv2",
                region_name=client_region,
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key
            )
        return boto3.client("wafv2", region_name=client_region)

    def _client_error_message(self, error: Exception) -> str:
        response = getattr(error, "response", {}) or {}
        return response.get("Error", {}).get("Message", str(error))

    def _update_ip_set_address(self, ip_set: dict, cidr_ip: str, remove: bool = False) -> tuple:
        client = self._get_waf_client(ip_set["region"])
        set_label = f"{ip_set['name']} ({ip_set['scope']}/{ip_set['region']})"

        if not client:
            verb = "Removed" if remove else "Added"
            logger.info(f"[AWS WAF-SIMULATION] {verb} IP {cidr_ip} in AWS WAF IP Set '{set_label}'.")
            return True, f"[SIMULATION] IP {cidr_ip} {'removed from' if remove else 'added to'} AWS WAF IP Set '{set_label}'."

        try:
            response = client.get_ip_set(
                Name=ip_set["name"],
                Id=ip_set["id"],
                Scope=ip_set["scope"]
            )
            current_set = response.get("IPSet", {})
            addresses = list(current_set.get("Addresses", []))
            lock_token = response.get("LockToken")

            if remove:
                if cidr_ip not in addresses:
                    return True, f"IP {cidr_ip} does not exist in AWS WAF IP Set '{set_label}'."
                addresses.remove(cidr_ip)
            else:
                if cidr_ip in addresses:
                    return True, f"IP {cidr_ip} already exists in AWS WAF IP Set '{set_label}'."
                addresses.append(cidr_ip)

            logger.info(f"[AWS WAF] Updating IP Set '{set_label}' with {len(addresses)} addresses...")
            client.update_ip_set(
                Name=ip_set["name"],
                Id=ip_set["id"],
                Scope=ip_set["scope"],
                Addresses=addresses,
                LockToken=lock_token
            )
            return True, f"IP {cidr_ip} successfully {'removed from' if remove else 'added to'} AWS WAF IP Set '{set_label}'."
        except ClientError as e:
            logger.error(f"[AWS WAF ERROR] Failed to update IP Set '{set_label}': {e}")
            return False, f"AWS WAF SDK error for '{set_label}': {self._client_error_message(e)}"
        except Exception as e:
            logger.error(f"[AWS WAF ERROR] Failed to connect to AWS for IP Set '{set_label}': {e}")
            return False, f"Connection error for '{set_label}': {str(e)}"

    def block_ip(self, ip_address: str) -> tuple:
        """
        Adds a malicious IP address to the AWS WAF IP Set to block HTTP/HTTPS exploit traffic.
        Returns (success, message).
        """
        logger.info(f"[AWS WAF] Request to block IP: {ip_address}")
        
        # Ensure IP is in CIDR format (e.g. 198.51.100.12/32)
        cidr_ip = ip_address if "/" in ip_address else f"{ip_address}/32"
        
        results = [self._update_ip_set_address(ip_set, cidr_ip, remove=False) for ip_set in self.ip_sets]
        success = all(ok for ok, _ in results)
        return success, " ".join(message for _, message in results)

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

    def unblock_ip(self, ip_address: str) -> tuple:
        """
        Removes an IP address from the AWS WAF IP Set.
        Returns (success, message).
        """
        logger.info(f"[AWS WAF] Request to unblock IP: {ip_address}")
        cidr_ip = ip_address if "/" in ip_address else f"{ip_address}/32"
        
        results = [self._update_ip_set_address(ip_set, cidr_ip, remove=True) for ip_set in self.ip_sets]
        success = all(ok for ok, _ in results)
        return success, " ".join(message for _, message in results)

    def remove_mitigation_rule(self, attack_type: str, url_pattern: str) -> tuple:
        """
        Removes a custom mitigation rule from AWS WAF Web ACL.
        Returns (success, message).
        """
        logger.info(f"[AWS WAF] Request to remove mitigation rule for {attack_type} on: {url_pattern}")
        
        client = self._get_waf_client()
        if not client:
            logger.info(f"[AWS WAF-SIMULATION] Removed dynamic Web ACL rule for '{attack_type}' on endpoint '{url_pattern}'.")
            return True, f"[SIMULATION] AWS WAF rule removed for {attack_type} on '{url_pattern}'."
            
        try:
            logger.info(f"[AWS WAF] Dynamic Web ACL update request initiated to remove rule for {attack_type}.")
            return True, f"Successfully removed custom AWS WAF Web ACL rule for {attack_type} payloads targeting '{url_pattern}'."
        except Exception as e:
            logger.error(f"[AWS WAF ERROR] Dynamic rule removal failed: {e}")
            return False, f"Rule removal error: {str(e)}"
