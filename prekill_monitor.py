"""
Aegis SOAR - PRE-KILL Timeout Monitor
=======================================
Monitors containment actions (IP blocks, host isolations, account disables)
that have been executed with a time-to-live (TTL).  When an action exceeds
its TTL without being explicitly extended or resolved, the monitor
automatically triggers a rollback via the ``rollback_action`` module.

Redis Key Layout:
    aegis:prekill:{incident_id}:{action_type}:{target}
        → JSON hash with registration timestamp, TTL, and metadata.

The monitor runs a background thread that wakes every
``PREKILL_CHECK_INTERVAL_S`` seconds to scan for expired actions.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime

import redis

from config import REDIS_URL

logger = logging.getLogger("soar-engine.prekill_monitor")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PREKILL_ENABLED = os.getenv("PREKILL_ENABLED", "true").lower() == "true"
PREKILL_DEFAULT_TTL_MINUTES = int(os.getenv("PREKILL_DEFAULT_TTL_MINUTES", "60"))
PREKILL_CHECK_INTERVAL_S = int(os.getenv("PREKILL_CHECK_INTERVAL_S", "60"))

# Redis key prefix
_KEY_PREFIX = "aegis:prekill"


class PreKillMonitor:
    """PRE-KILL timeout monitor for auto-rollback of containment actions.

    Containment actions (block_ip, quarantine_host, disable_account, …)
    are registered with a TTL.  A background thread periodically checks
    whether any registered actions have exceeded their TTL and triggers
    an automatic rollback through the ``rollback_action`` module.

    All rollback events are written to the audit trail.
    """

    def __init__(self):
        """Connect to Redis and load configuration."""
        self._redis: redis.Redis | None = None
        self._running: bool = False
        self._thread: threading.Thread | None = None

        try:
            self._redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            self._redis.ping()
            logger.info("[PREKILL] Connected to Redis for action TTL tracking.")
        except Exception as exc:
            logger.error(f"[PREKILL] Failed to connect to Redis: {exc}")
            self._redis = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background monitoring loop."""
        if not PREKILL_ENABLED:
            logger.info("[PREKILL] Monitor is disabled via PREKILL_ENABLED=false.")
            return

        if self._running:
            logger.warning("[PREKILL] Monitor is already running.")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="prekill-monitor"
        )
        self._thread.start()
        logger.info(
            f"[PREKILL] Monitor started (check interval={PREKILL_CHECK_INTERVAL_S}s, "
            f"default TTL={PREKILL_DEFAULT_TTL_MINUTES}min)."
        )

    def stop(self) -> None:
        """Stop the background monitoring loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=PREKILL_CHECK_INTERVAL_S + 2)
        logger.info("[PREKILL] Monitor stopped.")

    # ------------------------------------------------------------------
    # Action registration
    # ------------------------------------------------------------------

    def register_action(
        self,
        incident_id: str,
        action_type: str,
        target: str,
        ttl_minutes: int = None,
    ) -> None:
        """Register a containment action for TTL-based monitoring.

        Args:
            incident_id: The incident that triggered this action.
            action_type: Type of action (e.g. ``block_ip``, ``quarantine_host``).
            target: The target of the action (IP, hostname, username, etc.).
            ttl_minutes: Time-to-live in minutes before auto-rollback.
                         Defaults to ``PREKILL_DEFAULT_TTL_MINUTES``.
        """
        if not self._redis:
            logger.warning("[PREKILL] Redis unavailable – cannot register action.")
            return

        if ttl_minutes is None:
            ttl_minutes = PREKILL_DEFAULT_TTL_MINUTES

        key = f"{_KEY_PREFIX}:{incident_id}:{action_type}:{target}"
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        action_info = {
            "incident_id": incident_id,
            "action_type": action_type,
            "target": target,
            "registered_at": now_iso,
            "ttl_minutes": ttl_minutes,
            "expires_at_epoch": time.time() + (ttl_minutes * 60),
            "status": "active",
        }

        try:
            self._redis.set(key, json.dumps(action_info))
            logger.info(
                f"[PREKILL] Registered action: {action_type} on '{target}' "
                f"(incident={incident_id}, TTL={ttl_minutes}min)."
            )
        except Exception as exc:
            logger.error(f"[PREKILL] Failed to register action in Redis: {exc}")

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Background thread: wake every ``PREKILL_CHECK_INTERVAL_S`` seconds
        and check for expired actions."""
        while self._running:
            try:
                self._check_expired_actions()
            except Exception as exc:
                logger.error(f"[PREKILL] Error in monitor loop: {exc}")

            time.sleep(PREKILL_CHECK_INTERVAL_S)

    def _check_expired_actions(self) -> None:
        """Scan all registered actions and trigger rollback for expired ones."""
        if not self._redis:
            return

        try:
            # Scan for all prekill keys
            cursor = 0
            pattern = f"{_KEY_PREFIX}:*"
            now_epoch = time.time()

            while True:
                cursor, keys = self._redis.scan(cursor=cursor, match=pattern, count=100)
                for key in keys:
                    raw = self._redis.get(key)
                    if not raw:
                        continue

                    try:
                        action_info = json.loads(raw)
                    except json.JSONDecodeError:
                        logger.warning(f"[PREKILL] Corrupt data in key '{key}' – skipping.")
                        continue

                    # Skip already rolled-back or resolved actions
                    if action_info.get("status") in ("rolled_back", "resolved", "expired"):
                        continue

                    expires_at = action_info.get("expires_at_epoch", 0)
                    if now_epoch >= expires_at:
                        incident_id = action_info.get("incident_id", "unknown")
                        action_type = action_info.get("action_type", "unknown")
                        target = action_info.get("target", "unknown")
                        ttl = action_info.get("ttl_minutes", PREKILL_DEFAULT_TTL_MINUTES)

                        logger.warning(
                            f"[PREKILL] Action expired: {action_type} on '{target}' "
                            f"(incident={incident_id}, TTL={ttl}min). Triggering auto-rollback…"
                        )

                        success = self._rollback_action(incident_id, action_info)

                        # Update status in Redis
                        action_info["status"] = "rolled_back" if success else "rollback_failed"
                        action_info["rolled_back_at"] = datetime.utcnow().strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        )
                        self._redis.set(key, json.dumps(action_info))

                if cursor == 0:
                    break

        except Exception as exc:
            logger.error(f"[PREKILL] Error scanning expired actions: {exc}")

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def _rollback_action(self, incident_id: str, action_info: dict) -> bool:
        """Execute a rollback for an expired action via the rollback_action module.

        Args:
            incident_id: The originating incident ID.
            action_info: Dict with at least *action_type* and *target*.

        Returns:
            ``True`` if the rollback succeeded.
        """
        action_type = action_info.get("action_type", "unknown")
        target = action_info.get("target", "unknown")

        try:
            from rollback_action import rollback_single_action

            success, message = rollback_single_action(action_type, target, incident_id)

            if success:
                logger.info(
                    f"[PREKILL] Auto-rollback succeeded: {action_type} on '{target}' "
                    f"(incident={incident_id}). Details: {message}"
                )
            else:
                logger.error(
                    f"[PREKILL] Auto-rollback FAILED: {action_type} on '{target}' "
                    f"(incident={incident_id}). Details: {message}"
                )

            # Log to audit trail
            self._log_to_audit(incident_id, action_type, target, success, message)

            return success

        except ImportError:
            logger.error(
                "[PREKILL] rollback_action module not available – cannot execute rollback."
            )
            return False
        except Exception as exc:
            logger.error(f"[PREKILL] Unexpected error during rollback: {exc}")
            self._log_to_audit(incident_id, action_type, target, False, str(exc))
            return False

    @staticmethod
    def _log_to_audit(
        incident_id: str,
        action_type: str,
        target: str,
        success: bool,
        message: str,
    ) -> None:
        """Write a rollback event to the SOAR audit trail."""
        try:
            from audit_logger import SoarAuditLogger

            SoarAuditLogger.log_api_response(
                incident_id=incident_id,
                target_system="prekill_monitor",
                action_type=f"auto_rollback_{action_type}",
                request_params={"target": target},
                success=success,
                response_msg=f"PRE-KILL auto-rollback: {message}",
            )
        except Exception as exc:
            logger.error(f"[PREKILL] Failed to write audit log: {exc}")

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_active_actions(self) -> list[dict]:
        """Return a list of all currently monitored (active) actions.

        Returns:
            List of action info dicts that have status ``active``.
        """
        active: list[dict] = []

        if not self._redis:
            logger.warning("[PREKILL] Redis unavailable – cannot list active actions.")
            return active

        try:
            cursor = 0
            pattern = f"{_KEY_PREFIX}:*"

            while True:
                cursor, keys = self._redis.scan(cursor=cursor, match=pattern, count=100)
                for key in keys:
                    raw = self._redis.get(key)
                    if not raw:
                        continue
                    try:
                        info = json.loads(raw)
                        if info.get("status") == "active":
                            info["redis_key"] = key
                            remaining_s = info.get("expires_at_epoch", 0) - time.time()
                            info["remaining_minutes"] = round(max(remaining_s, 0) / 60, 1)
                            active.append(info)
                    except json.JSONDecodeError:
                        continue

                if cursor == 0:
                    break

        except Exception as exc:
            logger.error(f"[PREKILL] Error listing active actions: {exc}")

        logger.info(f"[PREKILL] Currently monitoring {len(active)} active action(s).")
        return active
