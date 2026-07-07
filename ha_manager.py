"""
Aegis SOAR - High Availability Manager
=======================================
Implements an Active/Standby HA pattern using Redis for leader election,
heartbeat publishing, and automatic failover detection.

Redis Key Layout:
    aegis:ha:leader             - Current leader node_id (TTL-based lock)
    aegis:ha:heartbeat:{node}   - Heartbeat timestamp per node
    aegis:ha:metrics:{node}     - JSON performance metrics per node
    aegis:ha:nodes              - Set of all registered node IDs
"""

import json
import logging
import os
import threading
import time
import uuid

import redis

from config import REDIS_URL

logger = logging.getLogger("soar-engine.ha_manager")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HA_HEALTH_CHECK_INTERVAL_MS = int(os.getenv("HA_HEALTH_CHECK_INTERVAL_MS", "5000"))
HA_LEADERSHIP_TTL_S = int(os.getenv("HA_LEADERSHIP_TTL_S", "15"))

# Redis key constants
_KEY_LEADER = "aegis:ha:leader"
_KEY_HEARTBEAT = "aegis:ha:heartbeat:{node_id}"
_KEY_METRICS = "aegis:ha:metrics:{node_id}"
_KEY_NODES = "aegis:ha:nodes"


class HAManager:
    """Orchestrator High Availability Manager (Active/Standby).

    Uses Redis SETNX-based leader election with TTL so that if the active
    node crashes, standby nodes can acquire leadership automatically after
    the TTL expires.
    """

    def __init__(self, node_id: str = None):
        """Initialise the HA Manager.

        Args:
            node_id: Optional unique identifier for this node.  If *None*,
                     a UUID-based ID is generated automatically.
        """
        self.node_id: str = node_id or f"soar-node-{uuid.uuid4().hex[:8]}"
        self._running: bool = False
        self._thread: threading.Thread | None = None
        self._redis: redis.Redis | None = None

        try:
            self._redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            self._redis.ping()
            # Register ourselves in the cluster node set
            self._redis.sadd(_KEY_NODES, self.node_id)
            logger.info(
                f"[HA] Node '{self.node_id}' connected to Redis and registered in cluster."
            )
        except Exception as exc:
            logger.error(f"[HA] Failed to connect to Redis: {exc}")
            self._redis = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background health-check loop."""
        if self._running:
            logger.warning("[HA] Health-check loop is already running.")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._health_check_loop, daemon=True, name="ha-health-check"
        )
        self._thread.start()
        logger.info(
            f"[HA] Health-check loop started (interval={HA_HEALTH_CHECK_INTERVAL_MS}ms)."
        )

    def stop(self) -> None:
        """Stop the background health-check loop and release leadership."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=HA_HEALTH_CHECK_INTERVAL_MS / 1000 + 2)
        self.release_leadership()
        logger.info(f"[HA] Node '{self.node_id}' stopped.")

    # ------------------------------------------------------------------
    # Leadership
    # ------------------------------------------------------------------

    def try_acquire_leadership(self) -> bool:
        """Attempt to become the ACTIVE leader using Redis SETNX with TTL.

        Returns:
            ``True`` if this node successfully acquired leadership.
        """
        if not self._redis:
            logger.warning("[HA] Redis unavailable – cannot acquire leadership.")
            return False

        try:
            acquired = self._redis.set(
                _KEY_LEADER, self.node_id, nx=True, ex=HA_LEADERSHIP_TTL_S
            )
            if acquired:
                logger.info(f"[HA] Node '{self.node_id}' acquired leadership.")
                return True
            return False
        except Exception as exc:
            logger.error(f"[HA] Error acquiring leadership: {exc}")
            return False

    def renew_leadership(self) -> bool:
        """Extend the TTL of the leadership key (must be current leader).

        Returns:
            ``True`` if the renewal succeeded.
        """
        if not self._redis:
            return False

        try:
            # Only renew if we are still the leader (compare-and-extend)
            current_leader = self._redis.get(_KEY_LEADER)
            if current_leader == self.node_id:
                self._redis.expire(_KEY_LEADER, HA_LEADERSHIP_TTL_S)
                return True
            logger.warning(
                f"[HA] Cannot renew – current leader is '{current_leader}', not '{self.node_id}'."
            )
            return False
        except Exception as exc:
            logger.error(f"[HA] Error renewing leadership: {exc}")
            return False

    def release_leadership(self) -> None:
        """Release leadership if this node currently holds it."""
        if not self._redis:
            return

        try:
            current_leader = self._redis.get(_KEY_LEADER)
            if current_leader == self.node_id:
                self._redis.delete(_KEY_LEADER)
                logger.info(f"[HA] Node '{self.node_id}' released leadership.")
        except Exception as exc:
            logger.error(f"[HA] Error releasing leadership: {exc}")

    def is_leader(self) -> bool:
        """Check whether this node is the current ACTIVE leader."""
        if not self._redis:
            return False

        try:
            return self._redis.get(_KEY_LEADER) == self.node_id
        except Exception as exc:
            logger.error(f"[HA] Error checking leadership: {exc}")
            return False

    def get_leader_info(self) -> dict | None:
        """Return information about the current leader, or ``None``."""
        if not self._redis:
            return None

        try:
            leader_id = self._redis.get(_KEY_LEADER)
            if not leader_id:
                return None

            heartbeat_key = _KEY_HEARTBEAT.format(node_id=leader_id)
            heartbeat_ts = self._redis.get(heartbeat_key)

            metrics_key = _KEY_METRICS.format(node_id=leader_id)
            raw_metrics = self._redis.get(metrics_key)
            metrics = json.loads(raw_metrics) if raw_metrics else {}

            return {
                "node_id": leader_id,
                "last_heartbeat": heartbeat_ts,
                "metrics": metrics,
            }
        except Exception as exc:
            logger.error(f"[HA] Error getting leader info: {exc}")
            return None

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _health_check_loop(self) -> None:
        """Background thread that runs every ``HA_HEALTH_CHECK_INTERVAL_MS`` ms.

        *  **Leader path** – renew leadership, publish heartbeat, sync metrics.
        *  **Standby path** – check leader health; attempt takeover if stale.
        """
        interval_s = HA_HEALTH_CHECK_INTERVAL_MS / 1000.0

        while self._running:
            try:
                if self.is_leader():
                    # Leader duties
                    self.renew_leadership()
                    self._publish_heartbeat()
                    self._sync_metrics({
                        "uptime_s": time.monotonic(),
                        "role": "active",
                        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })
                else:
                    # Standby duties
                    leader_alive = self._check_leader_health()
                    if not leader_alive:
                        logger.info(
                            f"[HA] Leader appears down. Node '{self.node_id}' attempting takeover…"
                        )
                        if self.try_acquire_leadership():
                            logger.info(
                                f"[HA] Node '{self.node_id}' has taken over as ACTIVE leader."
                            )
                            self._publish_heartbeat()
            except Exception as exc:
                logger.error(f"[HA] Error in health-check loop: {exc}")

            time.sleep(interval_s)

    # ------------------------------------------------------------------
    # Heartbeat & metrics
    # ------------------------------------------------------------------

    def _publish_heartbeat(self) -> None:
        """Store a heartbeat timestamp in Redis for this node."""
        if not self._redis:
            return

        try:
            key = _KEY_HEARTBEAT.format(node_id=self.node_id)
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # Keep heartbeat key alive slightly longer than TTL so staleness is detectable
            self._redis.set(key, timestamp, ex=HA_LEADERSHIP_TTL_S * 2)
            logger.debug(f"[HA] Heartbeat published for '{self.node_id}' at {timestamp}.")
        except Exception as exc:
            logger.error(f"[HA] Error publishing heartbeat: {exc}")

    def _sync_metrics(self, metrics: dict) -> None:
        """Sync performance metrics for this node to Redis.

        Args:
            metrics: Arbitrary dict of performance counters/gauges.
        """
        if not self._redis:
            return

        try:
            key = _KEY_METRICS.format(node_id=self.node_id)
            self._redis.set(key, json.dumps(metrics), ex=HA_LEADERSHIP_TTL_S * 2)
        except Exception as exc:
            logger.error(f"[HA] Error syncing metrics: {exc}")

    def _check_leader_health(self) -> bool:
        """Check whether the current leader's heartbeat is fresh (< 15 s).

        Returns:
            ``True`` if the leader heartbeat is recent, ``False`` otherwise.
        """
        if not self._redis:
            return False

        try:
            leader_id = self._redis.get(_KEY_LEADER)
            if not leader_id:
                # No leader registered at all
                return False

            heartbeat_key = _KEY_HEARTBEAT.format(node_id=leader_id)
            heartbeat_ts = self._redis.get(heartbeat_key)
            if not heartbeat_ts:
                return False

            # Parse ISO timestamp and compare
            heartbeat_epoch = time.mktime(time.strptime(heartbeat_ts, "%Y-%m-%dT%H:%M:%SZ"))
            age_s = time.time() - heartbeat_epoch
            if age_s > HA_LEADERSHIP_TTL_S:
                logger.warning(
                    f"[HA] Leader '{leader_id}' heartbeat is stale ({age_s:.1f}s old)."
                )
                return False
            return True
        except Exception as exc:
            logger.error(f"[HA] Error checking leader health: {exc}")
            return False

    # ------------------------------------------------------------------
    # Cluster introspection
    # ------------------------------------------------------------------

    def get_cluster_status(self) -> dict:
        """Return a summary of the HA cluster state.

        Returns:
            Dict with keys *active_node*, *standby_nodes*, *last_heartbeat*,
            and *metrics*.
        """
        result: dict = {
            "active_node": None,
            "standby_nodes": [],
            "last_heartbeat": None,
            "metrics": {},
        }

        if not self._redis:
            logger.warning("[HA] Redis unavailable – cannot retrieve cluster status.")
            return result

        try:
            leader_id = self._redis.get(_KEY_LEADER)
            all_nodes = self._redis.smembers(_KEY_NODES)

            result["active_node"] = leader_id
            result["standby_nodes"] = [n for n in all_nodes if n != leader_id]

            if leader_id:
                hb_key = _KEY_HEARTBEAT.format(node_id=leader_id)
                result["last_heartbeat"] = self._redis.get(hb_key)

                metrics_key = _KEY_METRICS.format(node_id=leader_id)
                raw = self._redis.get(metrics_key)
                result["metrics"] = json.loads(raw) if raw else {}
        except Exception as exc:
            logger.error(f"[HA] Error getting cluster status: {exc}")

        return result
