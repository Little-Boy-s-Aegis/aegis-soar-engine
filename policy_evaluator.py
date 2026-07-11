"""Mandatory OPA authorization client for Autopilot actions."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid

import requests

from action_intent import build_action_intent, cache_ttl_seconds, intent_hash

logger = logging.getLogger("soar-engine.policy-evaluator")


class OpaPolicyEvaluator:
    """Authorize immutable ActionIntents and fail closed except for exact cached allows."""

    def __init__(self, whitelist_path="whitelist.json", redis_client=None):
        self.opa_enabled = os.getenv("OPA_ENABLED", "true").lower() == "true"
        self.opa_url = os.getenv("OPA_URL", "http://opa:8181")
        self.endpoint = f"{self.opa_url}/v1/data/aegis/autopilot/decision"
        self.internal_token = os.getenv("AEGIS_INTERNAL_TOKEN", "")
        self.redis = redis_client
        self._cache = {}
        self._cache_lock = threading.Lock()
        self.metrics = {}

    def _cache_key(self, digest: str) -> str:
        return f"aegis:opa:allow:{digest}"

    def _store_allow(self, digest: str, result: dict) -> None:
        record = json.dumps({"expires_at": time.time() + cache_ttl_seconds(), "decision": result})
        if self.redis is not None:
            self.redis.setex(self._cache_key(digest), cache_ttl_seconds(), record)
            return
        with self._cache_lock:
            self._cache[digest] = record

    def _consume_allow(self, digest: str) -> dict | None:
        key = self._cache_key(digest)
        record = None
        if self.redis is not None:
            try:
                record = self.redis.getdel(key)
            except AttributeError:
                pipe = self.redis.pipeline()
                pipe.get(key)
                pipe.delete(key)
                record = pipe.execute()[0]
        else:
            with self._cache_lock:
                record = self._cache.pop(digest, None)
        if not record:
            return None
        try:
            parsed = json.loads(record)
            if parsed["expires_at"] < time.time():
                return None
            result = parsed["decision"]
            if result.get("policy_revision") != os.getenv("OPA_POLICY_REVISION", "aegis-autopilot-v1"):
                return None
            return result
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _record_metrics(self, outcome: dict) -> None:
        fields = [f"decision:{'allow' if outcome.get('allow') else 'deny'}"]
        fields.extend(f"reason:{reason}" for reason in outcome.get("reasons", []))
        if outcome.get("cache_status") == "consumed":
            fields.append("cache:consumed")
        for field in fields:
            self.metrics[field] = self.metrics.get(field, 0) + 1
            if self.redis is not None:
                try:
                    self.redis.hincrby("aegis:opa:metrics", field, 1)
                except Exception as exc:
                    logger.warning("[OPA METRICS] Redis counter update failed: %s", exc)

    def authorize(self, action: dict, decision_context: dict) -> dict:
        intent = build_action_intent(action, decision_context)
        digest = intent_hash(intent)
        started = time.monotonic()
        outcome = {
            "allow": False,
            "decision_id": str(uuid.uuid4()),
            "policy_revision": intent["execution"]["policy_revision"],
            "reasons": ["opa_unavailable"],
            "intent_hash": digest,
            "cache_status": "none",
        }

        try:
            if not self.opa_enabled:
                raise RuntimeError("OPA is disabled")
            response = requests.post(
                self.endpoint,
                json={"input": intent},
                headers={"Authorization": f"Bearer {self.internal_token}"},
                timeout=float(os.getenv("OPA_TIMEOUT_SECONDS", "3")),
            )
            response.raise_for_status()
            result = response.json().get("result")
            if not isinstance(result, dict) or type(result.get("allow")) is not bool:
                raise ValueError("OPA returned an invalid decision")
            if result.get("policy_revision") != intent["execution"]["policy_revision"]:
                raise ValueError("OPA policy revision mismatch")
            outcome.update({
                "allow": result["allow"],
                "decision_id": str(result.get("decision_id") or outcome["decision_id"]),
                "reasons": list(result.get("reasons") or (["allowed"] if result["allow"] else ["policy_denied"])),
                "cache_status": "stored" if result["allow"] else "none",
            })
            if outcome["allow"]:
                self._store_allow(digest, outcome)
        except Exception as exc:
            cached = self._consume_allow(digest)
            if cached:
                outcome.update(cached)
                outcome["cache_status"] = "consumed"
                outcome["reasons"] = ["cached_allow_opa_unavailable"]
                logger.critical("[OPA CACHE] Single-use cached authorization consumed for %s: %s", digest, exc)
            else:
                outcome["reasons"] = ["opa_unavailable_no_valid_cache"]
                logger.error("[OPA] Autopilot action denied because policy evaluation failed: %s", exc)

        outcome["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
        outcome["intent"] = intent
        self._record_metrics(outcome)
        return outcome

    def verify_authorization(self, action: dict, decision_context: dict, authorization: dict) -> bool:
        if not authorization or not authorization.get("allow"):
            return False
        if authorization.get("policy_revision") != os.getenv("OPA_POLICY_REVISION", "aegis-autopilot-v1"):
            return False
        return authorization.get("intent_hash") == intent_hash(build_action_intent(action, decision_context))

    def is_action_allowed(self, action_type: str, target: str, phase: str, approval_mode: str, risk_score: float) -> tuple:
        """Compatibility adapter; still routes through the mandatory ActionIntent endpoint."""
        action = {
            "action_id": str(uuid.uuid4()), "action_type": action_type,
            "target": {"value_masked": target}, "phase": phase,
            "approval_mode": approval_mode, "reversible": True,
        }
        decision = {
            "input_summary": {"incident_id": f"legacy-{uuid.uuid4()}"},
            "automation_control": {
                "soc_autopilot_enabled": True, "auto_containment_eligible": True,
                "execution_window": {"in_window": True},
            },
            "scoring": {"final_risk_score_0_10": risk_score},
        }
        result = self.authorize(action, decision)
        return result["allow"], ",".join(result["reasons"])
