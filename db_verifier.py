"""
Aegis SOAR Database Verifier
============================
Connects to PostgreSQL log_entries to perform independent Layer 2 verification
of Layer 1 findings.
"""

import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import urllib.parse
from config import DATABASE_URL

logger = logging.getLogger("soar-engine.db_verifier")


class DatabaseVerifier:
    """Queries Postgres logs to verify L1 evidence independently."""

    def __init__(self):
        self.enabled = False
        try:
            # Test connection
            conn = self._get_connection()
            conn.close()
            self.enabled = True
            logger.info("Database verifier connected to PostgreSQL successfully.")
        except Exception as e:
            logger.warning(f"Database verifier offline. PostgreSQL unavailable: {e}")

    def _get_connection(self):
        # Convert postgres:// URL if needed by psycopg2
        url = DATABASE_URL
        if url.startswith("postgres://") or url.startswith("postgresql://"):
            # psycopg2 accepts postgresql:// standard DSN strings
            pass
        return psycopg2.connect(url)

    def query_logs_for_ip(self, ip_address: str, event_time_str: str, window_minutes: int = 10) -> list:
        """
        Query log_entries around the event time matching the target IP.
        
        Args:
            ip_address: Source IP to search
            event_time_str: ISO8601 string of the event timestamp
            window_minutes: Search window around the event time (+/-)
            
        Returns:
            list of dicts containing matching log entries.
        """
        if not self.enabled or not ip_address:
            return []

        try:
            # Parse event time
            # Truncate timezone info if present to keep it simple, or parse standard ISO8601
            clean_time_str = event_time_str.replace("Z", "+00:00")
            dt_event = datetime.fromisoformat(clean_time_str)
            dt_start = dt_event - timedelta(minutes=window_minutes)
            dt_end = dt_event + timedelta(minutes=window_minutes)
        except ValueError as ve:
            logger.error(f"Failed to parse timestamp {event_time_str}: {ve}")
            return []

        query = """
            SELECT id, timestamp, facility, severity, message, source_ip, status_code, ecs_url_original
            FROM log_entries
            WHERE (source_ip = %s OR message LIKE %s)
              AND timestamp BETWEEN %s AND %s
            ORDER BY timestamp DESC
            LIMIT 15
        """

        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Search for direct IP matches or IP within message text
                cursor.execute(query, (ip_address, f"%{ip_address}%", dt_start, dt_end))
                records = cursor.fetchall()
            conn.close()

            # Clean and serialize datetime objects for LLM consumption
            for r in records:
                if isinstance(r.get("timestamp"), datetime):
                    r["timestamp"] = r["timestamp"].isoformat()
            return records

        except Exception as e:
            logger.error(f"PostgreSQL query failed: {e}")
            # Try to reconnect next time if connection dropped
            return []

    def query_logs_for_endpoint(self, endpoint_keyword: str, event_time_str: str, window_minutes: int = 10) -> list:
        """Query logs containing a specific endpoint keyword (e.g. '/swift' or '/transfer')."""
        if not self.enabled or not endpoint_keyword:
            return []

        try:
            clean_time_str = event_time_str.replace("Z", "+00:00")
            dt_event = datetime.fromisoformat(clean_time_str)
            dt_start = dt_event - timedelta(minutes=window_minutes)
            dt_end = dt_event + timedelta(minutes=window_minutes)
        except ValueError:
            return []

        query = """
            SELECT id, timestamp, facility, severity, message, source_ip, status_code, ecs_url_original
            FROM log_entries
            WHERE (message LIKE %s OR ecs_url_original LIKE %s)
              AND timestamp BETWEEN %s AND %s
            ORDER BY timestamp DESC
            LIMIT 15
        """

        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                keyword_wildcard = f"%{endpoint_keyword}%"
                cursor.execute(query, (keyword_wildcard, keyword_wildcard, dt_start, dt_end))
                records = cursor.fetchall()
            conn.close()

            for r in records:
                if isinstance(r.get("timestamp"), datetime):
                    r["timestamp"] = r["timestamp"].isoformat()
            return records
        except Exception as e:
            logger.error(f"PostgreSQL query failed: {e}")
            return []
