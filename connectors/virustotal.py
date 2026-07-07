import logging
import requests
import os
import base64
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.virustotal")


class VirusTotalConnector:
    """API Connector for VirusTotal v3 to check IP, file hash, and URL reputations."""

    def __init__(self):
        self.api_key = secrets.get_secret("VIRUSTOTAL_API_KEY", "mock-vt-api-key")
        self.base_url = os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3")
        self.timeout = int(os.getenv("VIRUSTOTAL_TIMEOUT", "15"))
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self._simulation = self.api_key == "mock-vt-api-key"
        if self._simulation:
            logger.info("[VIRUSTOTAL] Running in SIMULATION mode (mock API key detected).")

    def check_ip(self, ip: str) -> tuple[bool, dict]:
        """
        Check IP address reputation via VirusTotal.

        Args:
            ip: The IP address to look up.

        Returns:
            (success, result_dict) where result_dict contains:
                - malicious_count: number of engines flagging as malicious
                - suspicious_count: number of engines flagging as suspicious
                - harmless_count: number of engines flagging as harmless
                - reputation_score: community reputation score
                - country: country code
                - as_owner: autonomous system owner
        """
        logger.info(f"[VIRUSTOTAL] Checking IP reputation: {ip}")

        if self._simulation:
            mock_data = {
                "malicious_count": 3,
                "suspicious_count": 1,
                "harmless_count": 65,
                "reputation_score": -15,
                "country": "CN",
                "as_owner": "Mock ISP Inc."
            }
            logger.info(f"[VIRUSTOTAL-SIMULATION] IP {ip} check returned mock data.")
            return True, mock_data

        try:
            url = f"{self.base_url}/ip_addresses/{ip}"
            res = requests.get(url, headers=self.headers, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                analysis = data.get("last_analysis_stats", {})
                result = {
                    "malicious_count": analysis.get("malicious", 0),
                    "suspicious_count": analysis.get("suspicious", 0),
                    "harmless_count": analysis.get("harmless", 0),
                    "reputation_score": data.get("reputation", 0),
                    "country": data.get("country", "N/A"),
                    "as_owner": data.get("as_owner", "N/A")
                }
                logger.info(f"[VIRUSTOTAL] IP {ip} — malicious: {result['malicious_count']}, "
                            f"suspicious: {result['suspicious_count']}")
                return True, result
            else:
                logger.warning(f"[VIRUSTOTAL] IP check failed: HTTP {res.status_code} - {res.text}")
                return False, {"error": f"HTTP {res.status_code}", "detail": res.text}

        except Exception as e:
            logger.error(f"[VIRUSTOTAL ERROR] IP check failed for {ip}: {e}")
            return False, {"error": str(e)}

    def check_hash(self, file_hash: str) -> tuple[bool, dict]:
        """
        Check file hash (MD5, SHA-1, or SHA-256) reputation via VirusTotal.

        Args:
            file_hash: The file hash to look up.

        Returns:
            (success, result_dict) where result_dict contains:
                - malicious_count: number of engines flagging as malicious
                - engines_detected: list of engine names that detected the file
                - file_type: detected file type description
                - sha256: SHA-256 hash of the file
        """
        logger.info(f"[VIRUSTOTAL] Checking file hash: {file_hash}")

        if self._simulation:
            mock_data = {
                "malicious_count": 42,
                "engines_detected": ["CrowdStrike", "Kaspersky", "Symantec", "McAfee", "ESET-NOD32"],
                "file_type": "Win32 EXE",
                "sha256": file_hash if len(file_hash) == 64 else "aabb" * 16
            }
            logger.info(f"[VIRUSTOTAL-SIMULATION] Hash {file_hash} check returned mock data.")
            return True, mock_data

        try:
            url = f"{self.base_url}/files/{file_hash}"
            res = requests.get(url, headers=self.headers, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                analysis = data.get("last_analysis_stats", {})
                analysis_results = data.get("last_analysis_results", {})

                detected_engines = [
                    engine for engine, detail in analysis_results.items()
                    if detail.get("category") == "malicious"
                ]

                result = {
                    "malicious_count": analysis.get("malicious", 0),
                    "engines_detected": detected_engines,
                    "file_type": data.get("type_description", "N/A"),
                    "sha256": data.get("sha256", file_hash)
                }
                logger.info(f"[VIRUSTOTAL] Hash {file_hash} — malicious: {result['malicious_count']}, "
                            f"detected by: {len(detected_engines)} engines")
                return True, result
            elif res.status_code == 404:
                logger.info(f"[VIRUSTOTAL] Hash {file_hash} not found in VirusTotal database.")
                return True, {"malicious_count": 0, "engines_detected": [], "file_type": "unknown", "sha256": file_hash}
            else:
                logger.warning(f"[VIRUSTOTAL] Hash check failed: HTTP {res.status_code} - {res.text}")
                return False, {"error": f"HTTP {res.status_code}", "detail": res.text}

        except Exception as e:
            logger.error(f"[VIRUSTOTAL ERROR] Hash check failed for {file_hash}: {e}")
            return False, {"error": str(e)}

    def check_url(self, url_to_check: str) -> tuple[bool, dict]:
        """
        Check URL reputation via VirusTotal.

        The URL is submitted as a base64-encoded identifier per the VT v3 API spec.

        Args:
            url_to_check: The URL to scan/check.

        Returns:
            (success, result_dict) where result_dict contains:
                - malicious_count: number of engines flagging as malicious
                - positives: total positive (malicious + suspicious) detections
                - scan_date: last analysis date
        """
        logger.info(f"[VIRUSTOTAL] Checking URL reputation: {url_to_check}")

        if self._simulation:
            mock_data = {
                "malicious_count": 5,
                "positives": 7,
                "scan_date": "2026-07-07T00:00:00Z"
            }
            logger.info(f"[VIRUSTOTAL-SIMULATION] URL check returned mock data.")
            return True, mock_data

        try:
            # VT v3 uses base64url-encoded URL as the identifier (no padding)
            url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().rstrip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
            res = requests.get(endpoint, headers=self.headers, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                analysis = data.get("last_analysis_stats", {})
                malicious = analysis.get("malicious", 0)
                suspicious = analysis.get("suspicious", 0)

                result = {
                    "malicious_count": malicious,
                    "positives": malicious + suspicious,
                    "scan_date": data.get("last_analysis_date", "N/A")
                }
                logger.info(f"[VIRUSTOTAL] URL scan — malicious: {malicious}, positives: {result['positives']}")
                return True, result
            elif res.status_code == 404:
                logger.info(f"[VIRUSTOTAL] URL not previously scanned in VirusTotal.")
                return True, {"malicious_count": 0, "positives": 0, "scan_date": "N/A"}
            else:
                logger.warning(f"[VIRUSTOTAL] URL check failed: HTTP {res.status_code} - {res.text}")
                return False, {"error": f"HTTP {res.status_code}", "detail": res.text}

        except Exception as e:
            logger.error(f"[VIRUSTOTAL ERROR] URL check failed: {e}")
            return False, {"error": str(e)}
