import logging
import requests
import os
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.telegram")


class TelegramConnector:
    """API Connector for Telegram Bot API to send security alerts and notifications."""

    def __init__(self):
        self.bot_token = secrets.get_secret("TELEGRAM_BOT_TOKEN", "mock-telegram-token")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.server_chat_id = os.getenv("TELEGRAM_SERVER_CHAT_ID", "")
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"

    def _is_simulation(self) -> bool:
        """Returns True if running in simulation/mock mode."""
        return self.bot_token == "mock-telegram-token"

    def _send_message(self, chat_id: str, text: str, parse_mode: str = "HTML") -> tuple[bool, str]:
        """
        Internal helper to send a message to a specific Telegram chat.
        Returns (success, message).
        """
        if not chat_id:
            return False, "No chat_id configured for Telegram notification."

        if self._is_simulation():
            logger.info(f"[TELEGRAM-SIMULATION] Message sent to chat {chat_id}: {text[:100]}...")
            return True, f"[SIMULATION] Telegram message sent to chat {chat_id}."

        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
        }

        try:
            res = requests.post(url, json=payload, timeout=10)
            if res.status_code == 200:
                result = res.json()
                if result.get("ok"):
                    message_id = result.get("result", {}).get("message_id", "unknown")
                    logger.info(f"[TELEGRAM] Message sent successfully (message_id: {message_id}).")
                    return True, f"Telegram message sent successfully (message_id: {message_id})."
                else:
                    description = result.get("description", "Unknown error")
                    logger.error(f"[TELEGRAM] API returned error: {description}")
                    return False, f"Telegram API error: {description}"
            else:
                logger.error(f"[TELEGRAM] HTTP {res.status_code}: {res.text}")
                return False, f"Telegram API failed: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[TELEGRAM ERROR] Failed to send message: {e}")
            return False, f"Telegram connection error: {str(e)}"

    def send_alert(self, message: str, severity: str = "medium", parse_mode: str = "HTML") -> tuple[bool, str]:
        """
        Sends a security alert message to the configured Telegram chat.
        Severity is prepended as an emoji indicator.
        Returns (success, message).
        """
        logger.info(f"[TELEGRAM] Sending alert (severity={severity}) to chat {self.chat_id}")

        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }
        icon = severity_icons.get(severity.lower(), "⚠️")
        formatted_message = f"{icon} <b>SOAR Alert [{severity.upper()}]</b>\n\n{message}"

        return self._send_message(self.chat_id, formatted_message, parse_mode)

    def send_recovery(self, message: str) -> tuple[bool, str]:
        """
        Sends a recovery notification to the configured Telegram chat.
        Returns (success, message).
        """
        logger.info(f"[TELEGRAM] Sending recovery notification to chat {self.chat_id}")

        formatted_message = f"✅ <b>SOAR Recovery</b>\n\n{message}"
        return self._send_message(self.chat_id, formatted_message)

    def send_to_group(self, message: str) -> tuple[bool, str]:
        """
        Sends a message to the Telegram group chat (TELEGRAM_CHAT_ID).
        Returns (success, message).
        """
        logger.info(f"[TELEGRAM] Sending message to group chat {self.chat_id}")
        return self._send_message(self.chat_id, message)

    def send_to_server(self, message: str) -> tuple[bool, str]:
        """
        Sends a message to the Telegram server channel (TELEGRAM_SERVER_CHAT_ID).
        Returns (success, message).
        """
        logger.info(f"[TELEGRAM] Sending message to server channel {self.server_chat_id}")
        return self._send_message(self.server_chat_id, message)
