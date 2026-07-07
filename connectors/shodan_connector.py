import logging
import requests
import os
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.shodan")


class ShodanConnector:
    """API Connector for Shodan to look up host information and search for exposed services."""

    def __init__(self):
        self.api_key = secrets.get_secret("SHODAN_API_KEY", "mock-shodan-key")
        self.base_url = os.getenv("SHODAN_BASE_URL", "https://api.shodan.io")
        self.timeout = int(os.getenv("SHODAN_TIMEOUT", "15"))
        self._simulation = self.api_key == "mock-shodan-key"
        if self._simulation:
            logger.info("[SHODAN] Running in SIMULATION mode (mock API key detected).")

    def lookup_host(self, ip: str) -> tuple[bool, dict]:
        """
        Get all available information about a host from Shodan.

        Args:
            ip: The IP address to look up.

        Returns:
            (success, result_dict) where result_dict contains:
                - ports: list of open ports
                - os: detected operating system
                - organization: organization owning the IP
                - isp: Internet Service Provider
                - country_name: country where the host is located
                - vulns: list of known CVE vulnerabilities
                - hostnames: list of hostnames associated with the IP
        """
        logger.info(f"[SHODAN] Looking up host: {ip}")

        if self._simulation:
            mock_data = {
                "ports": [22, 80, 443, 8080, 3306],
                "os": "Linux 5.4",
                "organization": "Mock Cloud Hosting",
                "isp": "Mock ISP Global",
                "country_name": "United States",
                "vulns": ["CVE-2021-44228", "CVE-2023-27350"],
                "hostnames": [f"host-{ip.replace('.', '-')}.mock-cloud.com"]
            }
            logger.info(f"[SHODAN-SIMULATION] Host {ip} lookup returned mock data.")
            return True, mock_data

        try:
            url = f"{self.base_url}/shodan/host/{ip}"
            params = {"key": self.api_key}
            res = requests.get(url, params=params, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json()
                result = {
                    "ports": data.get("ports", []),
                    "os": data.get("os", "N/A"),
                    "organization": data.get("org", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "country_name": data.get("country_name", "N/A"),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", [])
                }
                logger.info(f"[SHODAN] Host {ip} — ports: {result['ports']}, "
                            f"vulns: {len(result['vulns'])}")
                return True, result
            elif res.status_code == 404:
                logger.info(f"[SHODAN] No information found for host {ip}.")
                return True, {
                    "ports": [], "os": "N/A", "organization": "N/A",
                    "isp": "N/A", "country_name": "N/A", "vulns": [], "hostnames": []
                }
            else:
                logger.warning(f"[SHODAN] Host lookup failed: HTTP {res.status_code} - {res.text}")
                return False, {"error": f"HTTP {res.status_code}", "detail": res.text}

        except Exception as e:
            logger.error(f"[SHODAN ERROR] Host lookup failed for {ip}: {e}")
            return False, {"error": str(e)}

    def search(self, query: str, limit: int = 10) -> tuple[bool, list]:
        """
        Search Shodan for hosts matching the given query.

        Args:
            query: Shodan search query string (e.g., 'apache port:8080 country:US').
            limit: Maximum number of results to return (default: 10, max: 100).

        Returns:
            (success, results_list) where each result dict contains:
                - ip_str: IP address of the host
                - port: open port
                - org: organization
                - hostnames: associated hostnames
                - os: detected operating system
                - product: detected product/service
                - location: country and city information
        """
        logger.info(f"[SHODAN] Searching: '{query}' (limit: {limit})")

        if self._simulation:
            mock_results = [
                {
                    "ip_str": "203.0.113.10",
                    "port": 8080,
                    "org": "Mock Corp",
                    "hostnames": ["web1.mock-corp.com"],
                    "os": "Linux",
                    "product": "Apache httpd",
                    "location": {"country_name": "United States", "city": "San Francisco"}
                },
                {
                    "ip_str": "198.51.100.25",
                    "port": 443,
                    "org": "Mock Hosting",
                    "hostnames": ["secure.mock-hosting.io"],
                    "os": "Ubuntu",
                    "product": "nginx",
                    "location": {"country_name": "Germany", "city": "Frankfurt"}
                }
            ]
            logger.info(f"[SHODAN-SIMULATION] Search returned {len(mock_results)} mock results.")
            return True, mock_results[:limit]

        try:
            url = f"{self.base_url}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": query,
                "minify": True
            }
            res = requests.get(url, params=params, timeout=self.timeout)

            if res.status_code == 200:
                data = res.json()
                matches = data.get("matches", [])
                results = []
                for match in matches[:limit]:
                    results.append({
                        "ip_str": match.get("ip_str", "N/A"),
                        "port": match.get("port", 0),
                        "org": match.get("org", "N/A"),
                        "hostnames": match.get("hostnames", []),
                        "os": match.get("os", "N/A"),
                        "product": match.get("product", "N/A"),
                        "location": match.get("location", {})
                    })
                logger.info(f"[SHODAN] Search returned {len(results)} results.")
                return True, results
            elif res.status_code == 401:
                logger.warning("[SHODAN] Authentication failed — invalid API key.")
                return False, []
            else:
                logger.warning(f"[SHODAN] Search failed: HTTP {res.status_code} - {res.text}")
                return False, []

        except Exception as e:
            logger.error(f"[SHODAN ERROR] Search failed for query '{query}': {e}")
            return False, []
