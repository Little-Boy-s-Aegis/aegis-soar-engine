"""
Aegis SOAR - Notification Dispatcher
=====================================
Central notification routing engine that dispatches alerts, recovery notices,
and periodic digests to the appropriate channels based on severity level.

Routing rules:
    CRITICAL  → PagerDuty + Telegram + MQTT + JIRA
    HIGH      → PagerDuty + Telegram + JIRA
    MEDIUM    → Telegram + JIRA
    LOW       → Telegram only

Recovery notifications → Telegram + Email + Webhook
Digests               → Email + Telegram
"""

import logging
import os
import time
from datetime import datetime

import requests

from secret_manager import secrets

logger = logging.getLogger("soar-engine.notification_dispatcher")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NOTIFICATION_CHANNELS_ENABLED = os.getenv(
    "NOTIFICATION_CHANNELS_ENABLED", "telegram,pagerduty,jira,email,mqtt,webhook"
).lower().split(",")


# ============================================================================
# Lightweight connector helpers
# ============================================================================
# Each connector follows the project convention of returning (bool, str).

class _TelegramConnector:
    """Send messages via Telegram Bot API."""

    def __init__(self):
        self.bot_token = secrets.get_secret("TELEGRAM_BOT_TOKEN", "mock-telegram-token")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "mock-chat-id")
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self._simulation = self.bot_token == "mock-telegram-token"

    def send_message(self, text: str) -> tuple[bool, str]:
        """Send a plain-text message to the configured chat."""
        if self._simulation:
            logger.info(f"[TELEGRAM-SIMULATION] Message sent: {text[:120]}…")
            return True, "[SIMULATION] Telegram message sent."
        try:
            resp = requests.post(
                f"{self.base_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
            if resp.status_code == 200:
                return True, "Telegram message sent."
            return False, f"Telegram HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            logger.error(f"[TELEGRAM ERROR] {exc}")
            return False, str(exc)


class _PagerDutyConnector:
    """Trigger / resolve PagerDuty incidents via Events API v2."""

    def __init__(self):
        self.routing_key = secrets.get_secret("PAGERDUTY_ROUTING_KEY", "mock-pd-key")
        self.events_url = os.getenv(
            "PAGERDUTY_EVENTS_URL", "https://events.pagerduty.com/v2/enqueue"
        )
        self._simulation = self.routing_key == "mock-pd-key"

    def trigger(self, summary: str, severity: str = "critical", dedup_key: str = None) -> tuple[bool, str]:
        if self._simulation:
            logger.info(f"[PAGERDUTY-SIMULATION] Incident triggered: {summary[:120]}…")
            return True, "[SIMULATION] PagerDuty incident triggered."
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key or f"aegis-{int(time.time())}",
            "payload": {
                "summary": summary,
                "severity": severity,
                "source": "aegis-soar-engine",
            },
        }
        try:
            resp = requests.post(self.events_url, json=payload, timeout=10)
            if resp.status_code == 202:
                return True, "PagerDuty incident triggered."
            return False, f"PagerDuty HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            logger.error(f"[PAGERDUTY ERROR] {exc}")
            return False, str(exc)


class _JiraConnector:
    """Create issues in Jira via REST API."""

    def __init__(self):
        self.base_url = os.getenv("JIRA_BASE_URL", "https://jira.example.com")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "SOC")
        self.user = secrets.get_secret("JIRA_USER", "mock-jira-user")
        self.api_token = secrets.get_secret("JIRA_API_TOKEN", "mock-jira-token")
        self._simulation = self.api_token == "mock-jira-token"

    def create_issue(self, summary: str, description: str, priority: str = "High") -> tuple[bool, str]:
        if self._simulation:
            logger.info(f"[JIRA-SIMULATION] Issue created: {summary[:120]}…")
            return True, "[SIMULATION] JIRA issue created."
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Incident"},
                "priority": {"name": priority},
            }
        }
        try:
            resp = requests.post(
                f"{self.base_url}/rest/api/2/issue",
                json=payload,
                auth=(self.user, self.api_token),
                timeout=10,
            )
            if resp.status_code in (200, 201):
                return True, f"JIRA issue created: {resp.json().get('key', '?')}"
            return False, f"JIRA HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            logger.error(f"[JIRA ERROR] {exc}")
            return False, str(exc)


class _EmailConnector:
    """Send email notifications via a configurable SMTP relay / HTTP gateway."""

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "mock-smtp-host")
        self.from_addr = os.getenv("EMAIL_FROM", "soar@aegis.local")
        self.to_addr = os.getenv("EMAIL_SOC_TO", "soc-team@aegis.local")
        self._simulation = self.smtp_host == "mock-smtp-host"

    def send(self, subject: str, body: str) -> tuple[bool, str]:
        if self._simulation:
            logger.info(f"[EMAIL-SIMULATION] Email sent: subject='{subject}'")
            return True, "[SIMULATION] Email sent."
        try:
            import smtplib
            from email.mime.text import MIMEText

            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = self.to_addr
            port = int(os.getenv("SMTP_PORT", "587"))
            with smtplib.SMTP(self.smtp_host, port, timeout=10) as server:
                server.ehlo()
                smtp_user = secrets.get_secret("SMTP_USER", "")
                smtp_pass = secrets.get_secret("SMTP_PASS", "")
                if smtp_user and smtp_pass:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                server.sendmail(self.from_addr, [self.to_addr], msg.as_string())
            return True, "Email sent successfully."
        except Exception as exc:
            logger.error(f"[EMAIL ERROR] {exc}")
            return False, str(exc)


class _MqttConnector:
    """Publish messages to an MQTT broker for machine-to-machine alerting."""

    def __init__(self):
        self.broker_url = os.getenv("MQTT_BROKER_URL", "mock-mqtt-broker")
        self.topic = os.getenv("MQTT_ALERT_TOPIC", "aegis/alerts")
        self._simulation = self.broker_url == "mock-mqtt-broker"

    def publish(self, message: str) -> tuple[bool, str]:
        if self._simulation:
            logger.info(f"[MQTT-SIMULATION] Published to '{self.topic}': {message[:120]}…")
            return True, "[SIMULATION] MQTT message published."
        try:
            import paho.mqtt.client as mqtt

            client = mqtt.Client()
            host, _, port_str = self.broker_url.partition(":")
            port = int(port_str) if port_str else 1883
            client.connect(host, port, keepalive=10)
            info = client.publish(self.topic, message, qos=1)
            info.wait_for_publish(timeout=5)
            client.disconnect()
            return True, "MQTT message published."
        except ImportError:
            logger.warning("[MQTT] paho-mqtt not installed – skipping MQTT publish.")
            return False, "paho-mqtt package not installed."
        except Exception as exc:
            logger.error(f"[MQTT ERROR] {exc}")
            return False, str(exc)


class _WebhookConnector:
    """POST JSON payloads to an arbitrary webhook URL."""

    def __init__(self):
        self.url = os.getenv("WEBHOOK_NOTIFICATION_URL", "mock-webhook-url")
        self._simulation = self.url == "mock-webhook-url"

    def post(self, payload: dict) -> tuple[bool, str]:
        if self._simulation:
            logger.info(f"[WEBHOOK-SIMULATION] Payload sent to webhook.")
            return True, "[SIMULATION] Webhook delivered."
        try:
            resp = requests.post(self.url, json=payload, timeout=10)
            if resp.status_code in (200, 201, 202, 204):
                return True, f"Webhook delivered (HTTP {resp.status_code})."
            return False, f"Webhook HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            logger.error(f"[WEBHOOK ERROR] {exc}")
            return False, str(exc)


# ============================================================================
# Notification Dispatcher
# ============================================================================

class NotificationDispatcher:
    """Central notification routing engine for the Aegis SOAR platform.

    Initialises lightweight connector helpers for each supported channel and
    routes messages according to severity-based rules.  Any individual
    connector failure is logged and does **not** block delivery to the
    remaining channels (graceful degradation).
    """

    def __init__(self):
        """Initialise all notification connectors."""
        self.telegram = _TelegramConnector()
        self.pagerduty = _PagerDutyConnector()
        self.jira = _JiraConnector()
        self.email = _EmailConnector()
        self.mqtt = _MqttConnector()
        self.webhook = _WebhookConnector()
        self._enabled = set(ch.strip() for ch in NOTIFICATION_CHANNELS_ENABLED)
        logger.info(f"[NOTIFY] Dispatcher initialised. Enabled channels: {self._enabled}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_enabled(self, channel: str) -> bool:
        """Return True if *channel* is in the enabled list."""
        return channel in self._enabled

    def _safe_dispatch(self, channel_name: str, fn, *args, **kwargs) -> tuple[bool, str]:
        """Call *fn* inside a try/except so one failure never breaks the chain."""
        try:
            ok, msg = fn(*args, **kwargs)
            if ok:
                logger.info(f"[NOTIFY] {channel_name}: success – {msg}")
            else:
                logger.warning(f"[NOTIFY] {channel_name}: failed – {msg}")
            return ok, msg
        except Exception as exc:
            logger.error(f"[NOTIFY] {channel_name}: exception – {exc}")
            return False, str(exc)

    # ------------------------------------------------------------------
    # Message formatters
    # ------------------------------------------------------------------

    @staticmethod
    def _format_alert_message(alert: dict) -> str:
        """Format an alert dict into a human-readable string.

        Args:
            alert: Dict with at least *severity*, *title*, *summary*,
                   and optionally *incident_id*, *source_ip*, *mitre_id*.
        """
        severity = alert.get("severity", "UNKNOWN").upper()
        title = alert.get("title", "Untitled Alert")
        summary = alert.get("summary", "No details available.")
        incident_id = alert.get("incident_id", "N/A")
        source_ip = alert.get("source_ip", "N/A")
        mitre_id = alert.get("mitre_id", "")
        timestamp = alert.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

        lines = [
            f"🚨 *[{severity}] SECURITY ALERT*",
            f"*Title:* {title}",
            f"*Incident:* {incident_id}",
            f"*Severity:* {severity}",
            f"*Source IP:* {source_ip}",
        ]
        if mitre_id:
            lines.append(f"*MITRE ATT&CK:* {mitre_id}")
        lines += [
            f"*Time:* {timestamp}",
            f"*Summary:* {summary}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _format_recovery_message(recovery: dict) -> str:
        """Format a recovery notification into a human-readable string.

        Args:
            recovery: Dict with *incident_id*, *action_type*, *target*,
                      and optionally *details*.
        """
        incident_id = recovery.get("incident_id", "N/A")
        action_type = recovery.get("action_type", "unknown")
        target = recovery.get("target", "N/A")
        details = recovery.get("details", "Containment action has been rolled back.")
        timestamp = recovery.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

        return (
            f"✅ *RECOVERY NOTIFICATION*\n"
            f"*Incident:* {incident_id}\n"
            f"*Action Reverted:* {action_type}\n"
            f"*Target:* {target}\n"
            f"*Time:* {timestamp}\n"
            f"*Details:* {details}"
        )

    # ------------------------------------------------------------------
    # Public dispatch methods
    # ------------------------------------------------------------------

    def dispatch_immediate_alert(self, alert: dict) -> None:
        """Route an immediate alert based on severity.

        Routing rules:
            CRITICAL → PagerDuty + Telegram + MQTT + JIRA
            HIGH     → PagerDuty + Telegram + JIRA
            MEDIUM   → Telegram + JIRA
            LOW      → Telegram only

        Args:
            alert: Alert dict containing at minimum *severity*, *title*,
                   and *summary*.
        """
        severity = alert.get("severity", "LOW").upper()
        message = self._format_alert_message(alert)
        title = alert.get("title", "Security Alert")
        summary = alert.get("summary", "")
        channels_used: list[str] = []
        failures: list[str] = []

        # Telegram – all severities
        if self._is_enabled("telegram"):
            ok, msg = self._safe_dispatch("Telegram", self.telegram.send_message, message)
            channels_used.append("telegram")
            if not ok:
                failures.append(f"telegram: {msg}")

        # JIRA – MEDIUM and above
        if severity in ("CRITICAL", "HIGH", "MEDIUM") and self._is_enabled("jira"):
            ok, msg = self._safe_dispatch(
                "JIRA",
                self.jira.create_issue,
                f"[{severity}] {title}",
                f"{summary}\n\n{message}",
                "Highest" if severity == "CRITICAL" else severity.capitalize(),
            )
            channels_used.append("jira")
            if not ok:
                failures.append(f"jira: {msg}")

        # PagerDuty – HIGH and above
        if severity in ("CRITICAL", "HIGH") and self._is_enabled("pagerduty"):
            pd_sev = "critical" if severity == "CRITICAL" else "error"
            ok, msg = self._safe_dispatch(
                "PagerDuty",
                self.pagerduty.trigger,
                f"[{severity}] {title}: {summary}",
                pd_sev,
            )
            channels_used.append("pagerduty")
            if not ok:
                failures.append(f"pagerduty: {msg}")

        # MQTT – CRITICAL only
        if severity == "CRITICAL" and self._is_enabled("mqtt"):
            ok, msg = self._safe_dispatch("MQTT", self.mqtt.publish, message)
            channels_used.append("mqtt")
            if not ok:
                failures.append(f"mqtt: {msg}")

        logger.info(
            f"[NOTIFY] Immediate alert dispatched (severity={severity}). "
            f"Channels={channels_used}. Failures={failures or 'none'}."
        )

    def dispatch_recovery_notification(self, recovery: dict) -> None:
        """Route a recovery / rollback notification.

        Channels: Telegram + Email + Webhook.

        Args:
            recovery: Dict with *incident_id*, *action_type*, *target*, etc.
        """
        message = self._format_recovery_message(recovery)
        channels_used: list[str] = []
        failures: list[str] = []

        if self._is_enabled("telegram"):
            ok, msg = self._safe_dispatch("Telegram", self.telegram.send_message, message)
            channels_used.append("telegram")
            if not ok:
                failures.append(f"telegram: {msg}")

        if self._is_enabled("email"):
            incident_id = recovery.get("incident_id", "N/A")
            ok, msg = self._safe_dispatch(
                "Email",
                self.email.send,
                f"[RECOVERY] Incident {incident_id} – action reverted",
                message,
            )
            channels_used.append("email")
            if not ok:
                failures.append(f"email: {msg}")

        if self._is_enabled("webhook"):
            ok, msg = self._safe_dispatch("Webhook", self.webhook.post, recovery)
            channels_used.append("webhook")
            if not ok:
                failures.append(f"webhook: {msg}")

        logger.info(
            f"[NOTIFY] Recovery notification dispatched. "
            f"Channels={channels_used}. Failures={failures or 'none'}."
        )

    def dispatch_digest(self, digest: dict) -> None:
        """Route an aggregated digest report.

        Channels: Email + Telegram.

        Args:
            digest: Dict with *period*, *total_alerts*, *by_severity*,
                    *top_alerts* (list), and optionally *summary*.
        """
        period = digest.get("period", "last 15 minutes")
        total = digest.get("total_alerts", 0)
        by_severity = digest.get("by_severity", {})
        top_alerts = digest.get("top_alerts", [])
        summary_text = digest.get("summary", "")

        lines = [
            f"📊 *SOAR ALERT DIGEST – {period}*",
            f"*Total alerts:* {total}",
        ]
        for sev, count in by_severity.items():
            lines.append(f"  • {sev}: {count}")
        if top_alerts:
            lines.append("\n*Top alerts:*")
            for idx, a in enumerate(top_alerts[:5], 1):
                lines.append(f"  {idx}. {a.get('title', 'Untitled')} ({a.get('severity', '?')})")
        if summary_text:
            lines.append(f"\n{summary_text}")

        body = "\n".join(lines)
        channels_used: list[str] = []
        failures: list[str] = []

        if self._is_enabled("email"):
            ok, msg = self._safe_dispatch(
                "Email", self.email.send, f"Aegis SOAR Digest – {period}", body
            )
            channels_used.append("email")
            if not ok:
                failures.append(f"email: {msg}")

        if self._is_enabled("telegram"):
            ok, msg = self._safe_dispatch("Telegram", self.telegram.send_message, body)
            channels_used.append("telegram")
            if not ok:
                failures.append(f"telegram: {msg}")

        logger.info(
            f"[NOTIFY] Digest dispatched (period='{period}', total={total}). "
            f"Channels={channels_used}. Failures={failures or 'none'}."
        )
