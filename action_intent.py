"""Canonical, immutable policy input for SOAR action authorization."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def intent_hash(intent: dict) -> str:
    return hashlib.sha256(_canonical(intent).encode("utf-8")).hexdigest()


def build_action_intent(action: dict, decision: dict) -> dict:
    """Build a stable policy document without retaining mutable caller objects."""
    summary = decision.get("input_summary", {})
    automation = decision.get("automation_control", {})
    scoring = decision.get("scoring", {})
    verification = decision.get("l2_independent_verification", {})
    target = action.get("target", {})
    if not isinstance(target, dict):
        target = {"value_masked": target}

    incident_id = str(summary.get("incident_id") or decision.get("incident_id") or "")
    action_id = str(action.get("action_id") or "")
    created_at = str(action.get("created_at") or action.get("_intent_created_at") or decision.get("created_at") or _iso_now())
    policy_revision = os.getenv("OPA_POLICY_REVISION", "aegis-autopilot-v1")

    intent = {
        "request": {
            "action_id": action_id,
            "incident_id": incident_id,
            "tenant_id": str(summary.get("tenant_id") or decision.get("tenant_id") or "default"),
            "correlation_id": str(summary.get("correlation_id") or incident_id),
            "created_at": created_at,
            "idempotency_key": str(action.get("idempotency_key") or action_id or f"{incident_id}:{action.get('action_type', '')}"),
        },
        "execution": {
            "mode": "autopilot",
            "orchestrator_id": str(decision.get("orchestrator", {}).get("orchestrator_id") or "layer2_orchestrator_soar"),
            "environment": os.getenv("AEGIS_ENVIRONMENT", "development"),
            "policy_revision": policy_revision,
            "service_claims": {"subject": os.getenv("OPA_CALLER_ID", "soar-action-worker")},
        },
        "action": {
            "type": str(action.get("action_type") or "").strip().lower(),
            "target": deepcopy(target),
            "parameters": deepcopy(action.get("parameters") or {}),
            "scope": deepcopy(action.get("scope") or {}),
            "duration_seconds": action.get("duration_seconds"),
            "reversible": bool(action.get("reversible", action.get("rollback_action") is not None)),
            "phase": str(action.get("phase") or "").strip().lower(),
            "approval_mode": str(action.get("approval_mode") or "").strip().upper(),
        },
        "evidence": {
            "layer2_eligible": bool(automation.get("auto_containment_eligible", False)),
            "autopilot_enabled": bool(automation.get("soc_autopilot_enabled", False)),
            "execution_window_ok": bool(automation.get("execution_window", {}).get("in_window", False)),
            "risk_score": scoring.get("final_risk_score_0_10"),
            "structural_agreement": scoring.get("structural_agreement", verification.get("structural_agreement")),
            "detection_confidence": scoring.get("detection_confidence", verification.get("detection_confidence")),
            "contributing_agents": deepcopy(verification.get("contributing_agents") or summary.get("contributing_agents") or []),
            "evidence_refs": deepcopy(action.get("evidence_refs") or verification.get("evidence_refs") or []),
            "asset_criticality": scoring.get("asset_criticality"),
            "data_fresh": bool(verification.get("data_fresh", True)),
        },
        "guardrails": {
            "protected_assets": deepcopy(decision.get("guardrails", {}).get("protected_assets") or []),
            "denied_targets": deepcopy(decision.get("guardrails", {}).get("denied_targets") or []),
            "allowed_targets": deepcopy(decision.get("guardrails", {}).get("allowed_targets") or []),
            "action_rate_count": int(decision.get("guardrails", {}).get("action_rate_count") or 0),
            "prior_actions": deepcopy(decision.get("guardrails", {}).get("prior_actions") or []),
        },
    }
    return intent


def cache_ttl_seconds() -> int:
    return max(1, int(os.getenv("OPA_ALLOW_CACHE_TTL_SECONDS", "30")))
