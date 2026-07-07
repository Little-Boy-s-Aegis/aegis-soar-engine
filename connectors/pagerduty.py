import logging
import requests
import os
import json
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.pagerduty")


class PagerDutyConnector:
    """API Connector for PagerDuty Events API v2 to create and manage incidents."""

    EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self):
        self.routing_key = secrets.get_secret("PAGERDUTY_ROUTING_KEY", "mock-pagerduty-key")

    def _is_simulation(self) -> bool:
        """Returns True if running in simulation/mock mode."""
        return self.routing_key == "mock-pagerduty-key"

    def _send_event(self, payload: dict) -> tuple[bool, str]:
        """
        Internal helper to send an event to PagerDuty Events API v2.
        Returns (success, message).
        """
        if self._is_simulation():
            event_action = payload.get("event_action", "unknown")
            summary = payload.get("payload", {}).get("summary", "N/A")
            dedup_key = payload.get("dedup_key", "N/A")
            logger.info(
                f"[PAGERDUTY-SIMULATION] Event '{event_action}' sent "
                f"(summary: {summary}, dedup_key: {dedup_key})."
            )
            return True, f"[SIMULATION] PagerDuty event '{event_action}' sent (dedup_key: {dedup_key})."

        try:
            res = requests.post(
                self.EVENTS_API_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if res.status_code == 202:
                result = res.json()
                dedup_key = result.get("dedup_key", "unknown")
                logger.info(f"[PAGERDUTY] Event accepted (dedup_key: {dedup_key}).")
                return True, f"PagerDuty event accepted (dedup_key: {dedup_key})."
            else:
                logger.error(f"[PAGERDUTY] HTTP {res.status_code}: {res.text}")
                return False, f"PagerDuty API failed: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[PAGERDUTY ERROR] Failed to send event: {e}")
            return False, f"PagerDuty connection error: {str(e)}"

    def create_incident(
        self, title: str, severity: str, source: str, details: dict
    ) -> tuple[bool, str]:
        """
        Creates a new incident (trigger event) via PagerDuty Events API v2.
        Severity must be one of: critical, error, warning, info.
        Returns (success, message).
        """
        logger.info(f"[PAGERDUTY] Creating incident: {title} (severity={severity}, source={source})")

        valid_severities = ("critical", "error", "warning", "info")
        if severity.lower() not in valid_severities:
            severity = "error"
            logger.warning(f"[PAGERDUTY] Invalid severity provided, defaulting to 'error'.")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "severity": severity.lower(),
                "source": source,
                "custom_details": details,
            },
        }

        return self._send_event(payload)

    def resolve_incident(self, dedup_key: str) -> tuple[bool, str]:
        """
        Resolves an existing PagerDuty incident using the deduplication key.
        Returns (success, message).
        """
        logger.info(f"[PAGERDUTY] Resolving incident with dedup_key: {dedup_key}")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }

        return self._send_event(payload)

    def acknowledge_incident(self, dedup_key: str) -> tuple[bool, str]:
        """
        Acknowledges an existing PagerDuty incident using the deduplication key.
        Returns (success, message).
        """
        logger.info(f"[PAGERDUTY] Acknowledging incident with dedup_key: {dedup_key}")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "acknowledge",
            "dedup_key": dedup_key,
        }

        return self._send_event(payload)
