import logging
import requests
import os
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.abuseipdb")


class AbuseIPDBConnector:
    """API Connector for AbuseIPDB v2 to check and report abusive IP addresses."""

    def __init__(self):
        self.api_key = secrets.get_secret("ABUSEIPDB_API_KEY", "mock-abuseipdb-key")
        self.base_url = os.getenv("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2")
        self.timeout = int(os.getenv("ABUSEIPDB_TIMEOUT", "15"))
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        self._simulation = self.api_key == "mock-abuseipdb-key"
        if self._simulation:
            logger.info("[ABUSEIPDB] Running in SIMULATION mode (mock API key detected).")

    def check_ip(self, ip: str) -> tuple[bool, dict]:
        """
        Check IP address abuse confidence score via AbuseIPDB.

        Args:
            ip: The IP address to look up.

        Returns:
            (success, result_dict) where result_dict contains:
                - abuse_confidence_score: 0-100 confidence the IP is abusive
                - total_reports: number of abuse reports filed
                - country_code: ISO country code
                - isp: Internet Service Provider name
                - domain: reverse DNS domain
                - is_public: whether the IP is publicly routable
        """
        logger.info(f"[ABUSEIPDB] Checking IP reputation: {ip}")

        if self._simulation:
            mock_data = {
                "abuse_confidence_score": 85,
                "total_reports": 127,
                "country_code": "RU",
                "isp": "Mock Hosting Ltd.",
                "domain": "mock-hosting.ru",
                "is_public": True
            }
            logger.info(f"[ABUSEIPDB-SIMULATION] IP {ip} check returned mock data.")
            return True, mock_data

        try:
            url = f"{self.base_url}/check"
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            res = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json().get("data", {})
                result = {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "is_public": data.get("isPublic", False)
                }
                logger.info(f"[ABUSEIPDB] IP {ip} — abuse score: {result['abuse_confidence_score']}, "
                            f"reports: {result['total_reports']}")
                return True, result
            elif res.status_code == 422:
                logger.warning(f"[ABUSEIPDB] Invalid IP address format: {ip}")
                return False, {"error": "Invalid IP address", "detail": res.text}
            elif res.status_code == 429:
                logger.warning(f"[ABUSEIPDB] Rate limit exceeded.")
                return False, {"error": "Rate limit exceeded", "detail": res.text}
            else:
                logger.warning(f"[ABUSEIPDB] IP check failed: HTTP {res.status_code} - {res.text}")
                return False, {"error": f"HTTP {res.status_code}", "detail": res.text}

        except Exception as e:
            logger.error(f"[ABUSEIPDB ERROR] IP check failed for {ip}: {e}")
            return False, {"error": str(e)}

    def report_ip(self, ip: str, categories: list, comment: str) -> tuple[bool, str]:
        """
        Report an abusive IP address to AbuseIPDB.

        Args:
            ip: The IP address to report.
            categories: List of AbuseIPDB category IDs (e.g., [14, 18] for port scan + brute force).
            comment: Description of the abusive activity.

        Returns:
            (success, message) tuple.
        """
        logger.info(f"[ABUSEIPDB] Reporting abusive IP: {ip} — categories: {categories}")

        if self._simulation:
            logger.info(f"[ABUSEIPDB-SIMULATION] Reported IP {ip} with categories {categories}.")
            return True, f"[SIMULATION] IP {ip} reported to AbuseIPDB with categories {categories}."

        try:
            url = f"{self.base_url}/report"
            payload = {
                "ip": ip,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment
            }
            res = requests.post(url, headers=self.headers, data=payload, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json().get("data", {})
                score = data.get("abuseConfidenceScore", "N/A")
                logger.info(f"[ABUSEIPDB] IP {ip} reported successfully. Updated abuse score: {score}")
                return True, f"IP {ip} reported to AbuseIPDB. Updated abuse confidence score: {score}."
            elif res.status_code == 429:
                logger.warning(f"[ABUSEIPDB] Rate limit exceeded while reporting IP {ip}.")
                return False, "Rate limit exceeded. Please try again later."
            elif res.status_code == 422:
                logger.warning(f"[ABUSEIPDB] Validation error reporting IP {ip}: {res.text}")
                return False, f"Validation error: {res.text}"
            else:
                logger.warning(f"[ABUSEIPDB] Report failed: HTTP {res.status_code} - {res.text}")
                return False, f"Failed to report IP: HTTP {res.status_code} - {res.text}"

        except Exception as e:
            logger.error(f"[ABUSEIPDB ERROR] Report failed for {ip}: {e}")
            return False, f"AbuseIPDB connection error: {str(e)}"
