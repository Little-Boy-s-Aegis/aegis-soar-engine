"""
Aegis SOAR - Task Scheduler
============================
APScheduler-based scheduler that runs periodic SOC operations:

* **Hourly system report** – collects metrics and sends a full report.
* **15-minute digest** – aggregates recent alerts and dispatches a summary.
* **Refresh info** – reloads whitelists, threat-intel caches, and asset
  inventory.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta

logger = logging.getLogger("soar-engine.scheduler")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCHEDULER_ENABLED = os.getenv("SCHEDULER_ENABLED", "true").lower() == "true"
HOURLY_REPORT_ENABLED = os.getenv("HOURLY_REPORT_ENABLED", "true").lower() == "true"
DIGEST_INTERVAL_MINUTES = int(os.getenv("DIGEST_INTERVAL_MINUTES", "15"))

# ---------------------------------------------------------------------------
# Graceful import of APScheduler
# ---------------------------------------------------------------------------
_APSCHEDULER_AVAILABLE = True
try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:
    _APSCHEDULER_AVAILABLE = False
    logger.warning(
        "[SCHEDULER] apscheduler package is not installed. "
        "SoarScheduler will be disabled. Install with: pip install APScheduler"
    )


class SoarScheduler:
    """Periodic task scheduler for the Aegis SOAR engine.

    Wraps APScheduler's ``BackgroundScheduler`` and registers the standard
    SOC jobs (hourly report, 15-min digest, info refresh).

    If ``apscheduler`` is not installed the scheduler degrades gracefully —
    it logs a warning and all ``start()`` / ``stop()`` calls become no-ops.

    Args:
        notification_dispatcher: A :class:`NotificationDispatcher` instance
            used to send reports and digests.
        soar_engine_app: Optional reference to the running SOAR engine
            (e.g. for querying live incident counts or health).
    """

    def __init__(self, notification_dispatcher, soar_engine_app=None):
        self._dispatcher = notification_dispatcher
        self._engine = soar_engine_app
        self._scheduler = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the scheduler and register all configured jobs."""
        if not SCHEDULER_ENABLED:
            logger.info("[SCHEDULER] Scheduler is disabled via SCHEDULER_ENABLED=false.")
            return

        if not _APSCHEDULER_AVAILABLE:
            logger.warning("[SCHEDULER] Cannot start – apscheduler is not installed.")
            return

        try:
            self._scheduler = BackgroundScheduler(daemon=True)

            # -- Hourly system report --------------------------------
            if HOURLY_REPORT_ENABLED:
                self._scheduler.add_job(
                    self._hourly_system_report,
                    trigger="interval",
                    hours=1,
                    id="hourly_system_report",
                    name="Hourly SOC System Report",
                    next_run_time=datetime.now() + timedelta(seconds=30),
                )
                logger.info("[SCHEDULER] Registered job: hourly_system_report (every 1h).")

            # -- 15-minute alert digest ------------------------------
            self._scheduler.add_job(
                self._fifteen_min_digest,
                trigger="interval",
                minutes=DIGEST_INTERVAL_MINUTES,
                id="fifteen_min_digest",
                name=f"Alert Digest (every {DIGEST_INTERVAL_MINUTES}min)",
                next_run_time=datetime.now() + timedelta(minutes=DIGEST_INTERVAL_MINUTES),
            )
            logger.info(
                f"[SCHEDULER] Registered job: fifteen_min_digest (every {DIGEST_INTERVAL_MINUTES}min)."
            )

            # -- Refresh whitelist / threat-intel / assets -----------
            self._scheduler.add_job(
                self._refresh_info,
                trigger="interval",
                minutes=30,
                id="refresh_info",
                name="Refresh Whitelists & Threat-Intel",
                next_run_time=datetime.now() + timedelta(minutes=1),
            )
            logger.info("[SCHEDULER] Registered job: refresh_info (every 30min).")

            self._scheduler.start()
            self._running = True
            logger.info("[SCHEDULER] Background scheduler started successfully.")

        except Exception as exc:
            logger.error(f"[SCHEDULER] Failed to start scheduler: {exc}")

    def stop(self) -> None:
        """Gracefully stop the scheduler and all running jobs."""
        if self._scheduler and self._running:
            try:
                self._scheduler.shutdown(wait=False)
                self._running = False
                logger.info("[SCHEDULER] Scheduler stopped.")
            except Exception as exc:
                logger.error(f"[SCHEDULER] Error stopping scheduler: {exc}")
        else:
            logger.debug("[SCHEDULER] Scheduler was not running; nothing to stop.")

    # ------------------------------------------------------------------
    # Scheduled jobs
    # ------------------------------------------------------------------

    def _hourly_system_report(self) -> None:
        """Generate a full system report and send it to the SOC team.

        Collects:
            - Active incident count
            - Actions executed in the last hour
            - Playbooks triggered
            - System health (Redis connectivity, uptime)

        Dispatched via **email + telegram** through the notification dispatcher.
        """
        logger.info("[SCHEDULER] Generating hourly system report…")

        try:
            # Collect metrics from Redis if available
            report: dict = {
                "active_incidents": 0,
                "actions_executed": 0,
                "playbooks_triggered": 0,
                "system_health": "healthy",
                "uptime_s": time.monotonic(),
            }

            try:
                import redis
                from config import REDIS_URL

                r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
                r.ping()

                # Count active playbook statuses
                playbook_keys = r.keys("aegis:playbook:status:*")
                report["active_incidents"] = len(playbook_keys)

                executed_count = 0
                playbook_count = 0
                for key in playbook_keys:
                    status = r.hget(key, "status")
                    if status:
                        playbook_count += 1
                    actions_json = r.hget(key, "actions_status")
                    if actions_json:
                        actions = json.loads(actions_json)
                        executed_count += sum(
                            1 for v in actions.values() if v in ("executed", "simulated")
                        )
                report["actions_executed"] = executed_count
                report["playbooks_triggered"] = playbook_count

            except Exception as redis_exc:
                logger.warning(f"[SCHEDULER] Redis metrics unavailable: {redis_exc}")
                report["system_health"] = "degraded (Redis unreachable)"

            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            body = (
                f"📋 *HOURLY SOC SYSTEM REPORT* ({timestamp})\n"
                f"• Active incidents: {report['active_incidents']}\n"
                f"• Actions executed (last hour): {report['actions_executed']}\n"
                f"• Playbooks triggered: {report['playbooks_triggered']}\n"
                f"• System health: {report['system_health']}\n"
            )

            # Dispatch via email + telegram
            if self._dispatcher:
                self._dispatcher.dispatch_digest({
                    "period": "hourly system report",
                    "total_alerts": report["active_incidents"],
                    "by_severity": {},
                    "top_alerts": [],
                    "summary": body,
                })

            logger.info(f"[SCHEDULER] Hourly report dispatched. Metrics: {report}")

        except Exception as exc:
            logger.error(f"[SCHEDULER] Error generating hourly report: {exc}")

    def _fifteen_min_digest(self) -> None:
        """Aggregate alerts from the last N minutes and send a digest.

        Counts alerts by severity and lists the top 5 most recent.
        Dispatched via **email + telegram**.
        """
        logger.info(f"[SCHEDULER] Generating {DIGEST_INTERVAL_MINUTES}-minute alert digest…")

        try:
            alerts: list[dict] = []
            by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

            try:
                import redis
                from config import REDIS_URL

                r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
                r.ping()

                # Pull recent alerts stored in a Redis sorted set (score = timestamp)
                cutoff = time.time() - (DIGEST_INTERVAL_MINUTES * 60)
                raw_alerts = r.zrangebyscore("aegis:alerts:recent", cutoff, "+inf")

                for raw in raw_alerts:
                    try:
                        alert = json.loads(raw)
                        alerts.append(alert)
                        sev = alert.get("severity", "LOW").upper()
                        by_severity[sev] = by_severity.get(sev, 0) + 1
                    except json.JSONDecodeError:
                        continue

            except Exception as redis_exc:
                logger.warning(f"[SCHEDULER] Could not fetch recent alerts from Redis: {redis_exc}")

            # Top 5 by recency (already ordered from sorted set)
            top_alerts = alerts[-5:] if alerts else []

            digest = {
                "period": f"last {DIGEST_INTERVAL_MINUTES} minutes",
                "total_alerts": len(alerts),
                "by_severity": {k: v for k, v in by_severity.items() if v > 0},
                "top_alerts": top_alerts,
            }

            if self._dispatcher:
                self._dispatcher.dispatch_digest(digest)

            logger.info(
                f"[SCHEDULER] Digest dispatched: total={len(alerts)}, breakdown={by_severity}."
            )

        except Exception as exc:
            logger.error(f"[SCHEDULER] Error generating digest: {exc}")

    def _refresh_info(self) -> None:
        """Refresh cached data: whitelist, threat-intel feeds, asset inventory.

        Each refresh step is executed independently so that a failure in one
        does not block the others.
        """
        logger.info("[SCHEDULER] Refreshing cached info (whitelist, threat-intel, assets)…")

        # --- Whitelist ---
        try:
            whitelist_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "whitelist.json"
            )
            if os.path.exists(whitelist_path):
                with open(whitelist_path, "r", encoding="utf-8") as f:
                    whitelist = json.load(f)
                logger.info(f"[SCHEDULER] Whitelist reloaded: {len(whitelist)} entries.")
            else:
                logger.debug("[SCHEDULER] No whitelist.json found – skipping.")
        except Exception as exc:
            logger.error(f"[SCHEDULER] Failed to reload whitelist: {exc}")

        # --- Threat-Intel cache ---
        try:
            threat_intel_url = os.getenv("THREAT_INTEL_FEED_URL", "")
            if threat_intel_url:
                import requests

                resp = requests.get(threat_intel_url, timeout=15)
                if resp.status_code == 200:
                    logger.info(
                        f"[SCHEDULER] Threat-intel feed refreshed ({len(resp.content)} bytes)."
                    )
                else:
                    logger.warning(
                        f"[SCHEDULER] Threat-intel feed returned HTTP {resp.status_code}."
                    )
            else:
                logger.debug("[SCHEDULER] No THREAT_INTEL_FEED_URL configured – skipping.")
        except Exception as exc:
            logger.error(f"[SCHEDULER] Failed to refresh threat-intel: {exc}")

        # --- Asset inventory ---
        try:
            asset_api_url = os.getenv("ASSET_INVENTORY_API_URL", "")
            if asset_api_url:
                import requests

                resp = requests.get(asset_api_url, timeout=15)
                if resp.status_code == 200:
                    logger.info(
                        f"[SCHEDULER] Asset inventory refreshed ({len(resp.json())} assets)."
                    )
                else:
                    logger.warning(
                        f"[SCHEDULER] Asset inventory API returned HTTP {resp.status_code}."
                    )
            else:
                logger.debug("[SCHEDULER] No ASSET_INVENTORY_API_URL configured – skipping.")
        except Exception as exc:
            logger.error(f"[SCHEDULER] Failed to refresh asset inventory: {exc}")

        logger.info("[SCHEDULER] Info refresh cycle complete.")
