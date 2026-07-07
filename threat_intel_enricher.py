import json
import logging
import redis
from config import REDIS_URL
from connectors.virustotal import VirusTotalConnector
from connectors.abuseipdb import AbuseIPDBConnector
from connectors.shodan_connector import ShodanConnector

logger = logging.getLogger("soar-engine.threat_intel_enricher")


class ThreatIntelEnricher:
    """
    Threat Intelligence Enrichment Orchestrator.

    Queries multiple TI sources (VirusTotal, AbuseIPDB, Shodan) and caches
    results in Redis for fast lookups. Provides graceful degradation when
    individual sources are unavailable.
    """

    # Redis key pattern: aegis:ti:{source}:{indicator}
    CACHE_KEY_PREFIX = "aegis:ti"
    DEFAULT_TTL = 86400  # 24 hours

    def __init__(self):
        """Initialize all threat intel connectors and Redis client."""
        logger.info("[TI-ENRICHER] Initializing Threat Intelligence Enrichment Orchestrator...")

        # Initialize connectors
        self.vt = VirusTotalConnector()
        self.abuseipdb = AbuseIPDBConnector()
        self.shodan = ShodanConnector()

        # Initialize Redis client
        try:
            self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            self.redis_client.ping()
            self._redis_available = True
            logger.info("[TI-ENRICHER] Redis connection established for TI caching.")
        except Exception as e:
            self._redis_available = False
            self.redis_client = None
            logger.warning(f"[TI-ENRICHER] Redis unavailable — caching disabled: {e}")

    def enrich_ip(self, ip: str) -> dict:
        """
        Enrich an IP address with data from all three TI sources.

        Checks Redis cache first; if miss, queries VirusTotal, AbuseIPDB,
        and Shodan in sequence. Results are cached individually per source
        and returned as a combined dict.

        Args:
            ip: The IP address to enrich.

        Returns:
            Combined enrichment dict with keys: virustotal, abuseipdb, shodan,
            plus metadata (ip, enriched_sources, failed_sources).
        """
        logger.info(f"[TI-ENRICHER] Enriching IP: {ip}")

        result = {
            "ip": ip,
            "virustotal": None,
            "abuseipdb": None,
            "shodan": None,
            "enriched_sources": [],
            "failed_sources": []
        }

        # --- VirusTotal ---
        vt_cache_key = f"{self.CACHE_KEY_PREFIX}:virustotal:{ip}"
        cached = self._cache_get(vt_cache_key)
        if cached:
            result["virustotal"] = cached
            result["enriched_sources"].append("virustotal")
            logger.info(f"[TI-ENRICHER] VirusTotal cache HIT for {ip}")
        else:
            try:
                success, vt_data = self.vt.check_ip(ip)
                if success:
                    result["virustotal"] = vt_data
                    result["enriched_sources"].append("virustotal")
                    self._cache_set(vt_cache_key, vt_data)
                else:
                    result["failed_sources"].append("virustotal")
                    logger.warning(f"[TI-ENRICHER] VirusTotal check failed for {ip}: {vt_data}")
            except Exception as e:
                result["failed_sources"].append("virustotal")
                logger.error(f"[TI-ENRICHER] VirusTotal exception for {ip}: {e}")

        # --- AbuseIPDB ---
        abuse_cache_key = f"{self.CACHE_KEY_PREFIX}:abuseipdb:{ip}"
        cached = self._cache_get(abuse_cache_key)
        if cached:
            result["abuseipdb"] = cached
            result["enriched_sources"].append("abuseipdb")
            logger.info(f"[TI-ENRICHER] AbuseIPDB cache HIT for {ip}")
        else:
            try:
                success, abuse_data = self.abuseipdb.check_ip(ip)
                if success:
                    result["abuseipdb"] = abuse_data
                    result["enriched_sources"].append("abuseipdb")
                    self._cache_set(abuse_cache_key, abuse_data)
                else:
                    result["failed_sources"].append("abuseipdb")
                    logger.warning(f"[TI-ENRICHER] AbuseIPDB check failed for {ip}: {abuse_data}")
            except Exception as e:
                result["failed_sources"].append("abuseipdb")
                logger.error(f"[TI-ENRICHER] AbuseIPDB exception for {ip}: {e}")

        # --- Shodan ---
        shodan_cache_key = f"{self.CACHE_KEY_PREFIX}:shodan:{ip}"
        cached = self._cache_get(shodan_cache_key)
        if cached:
            result["shodan"] = cached
            result["enriched_sources"].append("shodan")
            logger.info(f"[TI-ENRICHER] Shodan cache HIT for {ip}")
        else:
            try:
                success, shodan_data = self.shodan.lookup_host(ip)
                if success:
                    result["shodan"] = shodan_data
                    result["enriched_sources"].append("shodan")
                    self._cache_set(shodan_cache_key, shodan_data)
                else:
                    result["failed_sources"].append("shodan")
                    logger.warning(f"[TI-ENRICHER] Shodan lookup failed for {ip}: {shodan_data}")
            except Exception as e:
                result["failed_sources"].append("shodan")
                logger.error(f"[TI-ENRICHER] Shodan exception for {ip}: {e}")

        logger.info(f"[TI-ENRICHER] IP {ip} enrichment complete — "
                    f"sources: {result['enriched_sources']}, "
                    f"failed: {result['failed_sources']}")
        return result

    def enrich_hash(self, file_hash: str) -> dict:
        """
        Enrich a file hash with VirusTotal data.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of the file.

        Returns:
            Enrichment dict with keys: file_hash, virustotal, enriched_sources,
            failed_sources.
        """
        logger.info(f"[TI-ENRICHER] Enriching file hash: {file_hash}")

        result = {
            "file_hash": file_hash,
            "virustotal": None,
            "enriched_sources": [],
            "failed_sources": []
        }

        cache_key = f"{self.CACHE_KEY_PREFIX}:virustotal:hash:{file_hash}"
        cached = self._cache_get(cache_key)
        if cached:
            result["virustotal"] = cached
            result["enriched_sources"].append("virustotal")
            logger.info(f"[TI-ENRICHER] VirusTotal hash cache HIT for {file_hash}")
            return result

        try:
            success, vt_data = self.vt.check_hash(file_hash)
            if success:
                result["virustotal"] = vt_data
                result["enriched_sources"].append("virustotal")
                self._cache_set(cache_key, vt_data)
            else:
                result["failed_sources"].append("virustotal")
                logger.warning(f"[TI-ENRICHER] VirusTotal hash check failed: {vt_data}")
        except Exception as e:
            result["failed_sources"].append("virustotal")
            logger.error(f"[TI-ENRICHER] VirusTotal hash exception: {e}")

        return result

    def get_threat_score(self, ip: str) -> float:
        """
        Calculate a combined threat score (0.0–10.0) for an IP address
        based on all available TI sources.

        Scoring algorithm:
          - VirusTotal: malicious ratio × 4.0 (max 4.0)
          - AbuseIPDB: abuse_confidence_score / 100 × 4.0 (max 4.0)
          - Shodan: 1.0 per known vulnerability (max 2.0)
        Total max: 10.0

        If a source is unavailable, its contribution is scored as 0 and
        does not penalize the final score (graceful degradation).

        Args:
            ip: The IP address to score.

        Returns:
            A float threat score between 0.0 and 10.0.
        """
        logger.info(f"[TI-ENRICHER] Calculating threat score for IP: {ip}")

        enrichment = self.enrich_ip(ip)
        score = 0.0

        # VirusTotal component (max 4.0)
        vt_data = enrichment.get("virustotal")
        if vt_data:
            malicious = vt_data.get("malicious_count", 0)
            harmless = vt_data.get("harmless_count", 0)
            total = malicious + vt_data.get("suspicious_count", 0) + harmless
            if total > 0:
                vt_ratio = malicious / total
                vt_score = min(vt_ratio * 4.0, 4.0)
            else:
                vt_score = 0.0
            score += vt_score
            logger.debug(f"[TI-ENRICHER] VT score component: {vt_score:.2f}")

        # AbuseIPDB component (max 4.0)
        abuse_data = enrichment.get("abuseipdb")
        if abuse_data:
            confidence = abuse_data.get("abuse_confidence_score", 0)
            abuse_score = min((confidence / 100.0) * 4.0, 4.0)
            score += abuse_score
            logger.debug(f"[TI-ENRICHER] AbuseIPDB score component: {abuse_score:.2f}")

        # Shodan component (max 2.0)
        shodan_data = enrichment.get("shodan")
        if shodan_data:
            vulns = shodan_data.get("vulns", [])
            shodan_score = min(len(vulns) * 1.0, 2.0)
            score += shodan_score
            logger.debug(f"[TI-ENRICHER] Shodan score component: {shodan_score:.2f}")

        final_score = round(min(score, 10.0), 2)
        logger.info(f"[TI-ENRICHER] Threat score for {ip}: {final_score}/10.0")
        return final_score

    def _cache_get(self, key: str) -> dict | None:
        """
        Look up a cached result from Redis.

        Args:
            key: The Redis key to look up.

        Returns:
            The cached dict, or None if not found or Redis is unavailable.
        """
        if not self._redis_available or not self.redis_client:
            return None

        try:
            raw = self.redis_client.get(key)
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.warning(f"[TI-ENRICHER] Redis cache GET error for key '{key}': {e}")

        return None

    def _cache_set(self, key: str, data: dict, ttl: int = 86400) -> None:
        """
        Store a result in Redis with a TTL.

        Args:
            key: The Redis key to store under.
            data: The dict to cache (will be JSON-serialized).
            ttl: Time-to-live in seconds (default: 86400 = 24 hours).
        """
        if not self._redis_available or not self.redis_client:
            return

        try:
            self.redis_client.setex(key, ttl, json.dumps(data))
            logger.debug(f"[TI-ENRICHER] Cached key '{key}' with TTL {ttl}s.")
        except Exception as e:
            logger.warning(f"[TI-ENRICHER] Redis cache SET error for key '{key}': {e}")
