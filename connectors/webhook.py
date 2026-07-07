import logging
import requests
import os
import json
import hmac
import hashlib
import time
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.webhook")


class WebhookConnector:
    """Generic Webhook Dispatcher with HMAC-SHA256 signatures and retry logic."""

    def __init__(self):
        webhook_urls_raw = os.getenv("WEBHOOK_URLS", "mock-webhook-url")
        self.webhook_urls = [
            url.strip() for url in webhook_urls_raw.split(",") if url.strip()
        ]
        self.webhook_secret = secrets.get_secret("WEBHOOK_SECRET", "mock-webhook-secret")

    def _is_simulation(self) -> bool:
        """Returns True if running in simulation/mock mode."""
        if not self.webhook_urls:
            return True
        return len(self.webhook_urls) == 1 and self.webhook_urls[0] == "mock-webhook-url"

    def _compute_signature(self, payload_bytes: bytes) -> str:
        """Computes HMAC-SHA256 signature for the payload using the webhook secret."""
        return hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

    def _send_with_retry(
        self, url: str, payload: dict, headers: dict, max_retries: int = 3
    ) -> tuple[bool, str]:
        """
        Sends a POST request to the given URL with exponential backoff retry logic.
        Returns (success, message).
        """
        for attempt in range(1, max_retries + 1):
            try:
                res = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10,
                )
                if res.status_code in (200, 201, 202, 204):
                    logger.info(f"[WEBHOOK] Successfully delivered to {url} (attempt {attempt}).")
                    return True, f"Webhook delivered to {url} (HTTP {res.status_code})."

                logger.warning(
                    f"[WEBHOOK] Attempt {attempt}/{max_retries} to {url} "
                    f"returned HTTP {res.status_code}: {res.text[:200]}"
                )

                # Don't retry on client errors (4xx) except 429 (rate limit)
                if 400 <= res.status_code < 500 and res.status_code != 429:
                    return False, f"Webhook delivery failed to {url}: HTTP {res.status_code} - {res.text}"

            except requests.exceptions.Timeout:
                logger.warning(f"[WEBHOOK] Attempt {attempt}/{max_retries} to {url} timed out.")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"[WEBHOOK] Attempt {attempt}/{max_retries} to {url} connection error: {e}")
            except Exception as e:
                logger.error(f"[WEBHOOK ERROR] Unexpected error on attempt {attempt}: {e}")
                return False, f"Webhook unexpected error: {str(e)}"

            # Exponential backoff before next retry
            if attempt < max_retries:
                wait_time = 2 ** (attempt - 1)
                logger.info(f"[WEBHOOK] Retrying in {wait_time}s...")
                time.sleep(wait_time)

        return False, f"Webhook delivery to {url} failed after {max_retries} attempts."

    def dispatch(self, payload: dict, event_type: str = "security_alert") -> tuple[bool, str]:
        """
        Dispatches a JSON payload to all configured webhook URLs.
        Each request includes an HMAC-SHA256 signature in the X-Webhook-Signature header.
        Returns (success, message) with aggregated results.
        """
        logger.info(f"[WEBHOOK] Dispatching '{event_type}' to {len(self.webhook_urls)} webhook(s)")

        if self._is_simulation():
            logger.info(
                f"[WEBHOOK-SIMULATION] Dispatched '{event_type}' event to "
                f"{len(self.webhook_urls)} webhook URL(s): {self.webhook_urls}"
            )
            return True, (
                f"[SIMULATION] Webhook '{event_type}' dispatched to "
                f"{len(self.webhook_urls)} URL(s)."
            )

        # Compute HMAC-SHA256 signature
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = self._compute_signature(payload_bytes)

        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Signature": f"sha256={signature}",
            "X-Webhook-Event": event_type,
        }

        results = []
        all_success = True
        for url in self.webhook_urls:
            success, msg = self._send_with_retry(url, payload, headers)
            results.append(msg)
            if not success:
                all_success = False

        summary = "; ".join(results)
        if all_success:
            return True, f"All webhooks delivered successfully: {summary}"
        else:
            return False, f"Some webhooks failed: {summary}"
