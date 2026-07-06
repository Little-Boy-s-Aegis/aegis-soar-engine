"""
Aegis SOAR Schema Validator
===========================
Validates input Layer 1 findings and output Layer 2 orchestrator decisions.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ==========================================
# Input Schema: littleboy.soc.layer1.agent_finding.v4
# ==========================================
class L1Safety(BaseModel):
    prompt_injection_observed: bool = False
    evidence_masked: bool = False


class L1Finding(BaseModel):
    schema_version: str = "littleboy.soc.layer1.agent_finding.v4"
    timestamp: str
    agent_id: str
    agent_name: str
    agent_type: str
    threat_detected: bool
    finding_type: str  # confirmed_threat | suspected_threat | anomaly_no_mapping | no_threat | prompt_injection_attempt
    capec_id: str = ""
    mitre_attack_id: str = ""
    raw_evidence: str
    safety: L1Safety

    # Optional fields
    banking_domain_observed: Optional[Dict[str, Any]] = None
    entities: Optional[Dict[str, Any]] = None
    attack_mapping: Optional[Dict[str, Any]] = None
    surfaces_and_context: Optional[Dict[str, Any]] = None
    quality: Optional[Dict[str, Any]] = None


# ==========================================
# Output Schema: littleboy.soc.layer2.orchestrator_decision.v7
# ==========================================
class L2Orchestrator(BaseModel):
    orchestrator_id: str = "layer2_orchestrator_soar"
    orchestrator_name: str = "Layer 2 - Orchestrator / SOAR Decision Engine"
    mode: str = "correlation_context_policy_playbook_execution"


class L2InputSummary(BaseModel):
    incident_id: Optional[str] = None
    source_topic: str = "sensor-results-topic"
    output_topic: str = "incidents-topic"
    layer1_schema_version: str = "littleboy.soc.layer1.agent_finding.v4"
    findings: List[Dict[str, Any]]


class L2TimeWindow(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None


class L2CorrelationKeys(BaseModel):
    entities: List[str] = []
    time_window: L2TimeWindow
    mitre_attack_ids: List[str] = []
    capec_ids: List[str] = []
    evidence_terms: List[str] = []


class L2Correlation(BaseModel):
    correlation_state: str  # confirmed | partial | conflict | none
    same_attack_assessment: bool
    correlated_agent_ids: List[str] = []
    conflicting_agent_ids: List[str] = []
    correlation_keys: L2CorrelationKeys
    correlation_rationale: List[str] = []


class L2VerificationSource(BaseModel):
    source_type: str  # clean_log | raw_log | siem | edr ...
    source_ref: Optional[str] = None
    matched_observation: Optional[str] = None


class L2IndependentVerification(BaseModel):
    performed: bool
    required: bool
    verification_state: str  # confirmed | not_confirmed | contradicted | insufficient | not_required
    verification_sources: List[L2VerificationSource] = []
    log_queries_or_refs: List[str] = []
    confirmed_entities: List[str] = []
    contradicting_evidence: List[str] = []
    verification_strength: str  # strong | supported | weak | none | contradicted
    rationale: List[str] = []


class L2VerifiedCase(BaseModel):
    threat_confirmed: bool
    title: Optional[str] = None
    summary: Optional[str] = None
    verified_techniques: List[str] = []
    expanded_techniques: List[str] = []
    verified_tactics: List[str] = []
    verified_capec: List[str] = []
    entities: Dict[str, List[str]]
    evidence_refs: List[str] = []
    assumptions: List[str] = []


class L2Scoring(BaseModel):
    score_source: str
    score_source_ref: Optional[str] = None
    score_table_calibration_reason: Optional[str] = None
    base_threat_score_0_10: float
    asset_criticality_multiplier: float
    raw_context_risk_0_10: float
    risk_cap_applied: bool
    risk_cap_0_10: Optional[float] = None
    risk_cap_reason: Optional[str] = None
    final_risk_score_0_10: float
    priority: str  # critical | high | medium | low | info
    response_mode: str  # MONITOR | CONTAIN | CONTAIN_AND_HUNT | CRISIS
    score_rationale: List[str] = []


class L2BankingImpact(BaseModel):
    swift_or_payment_involved: bool = False
    core_banking_involved: bool = False
    customer_data_involved: bool = False
    atm_or_hsm_involved: bool = False
    privileged_identity_involved: bool = False
    backup_or_recovery_involved: bool = False
    security_control_involved: bool = False
    fraud_control_involved: bool = False
    business_criticality: str  # critical | high | medium | low | unknown
    impact_rationale: List[str] = []


class L2PolicyGuardrails(BaseModel):
    opa_required: bool = True
    opa_result: str  # allow | deny | partial | not_evaluated
    policy_decision_refs: List[str] = []
    red_lines_triggered: List[str] = []
    whitelist_hits: List[str] = []
    manual_only_reasons: List[str] = []
    time_bound_required: bool = True
    rollback_required: bool = True


class L2ExecutionWindow(BaseModel):
    enabled: bool = False
    timezone: str = "Asia/Ho_Chi_Minh"
    start_local: str = "08:00"
    end_local: str = "20:00"
    in_window: bool = False
    outside_window_behavior: str = "suggest_only_and_report"


class L2AutomationControl(BaseModel):
    soc_autopilot_enabled: bool = False
    mode: str = "suggest_only"
    default_mode: str = "suggest_only"
    auto_containment_path: str = "none"
    execution_window: L2ExecutionWindow
    next_review_minutes: int = 120
    auto_containment_eligible: bool = False
    containment_gate_rationale: List[str] = []
    auto_unblock_after_mins: Optional[int] = None
    rollback_support: bool = True


class L2PlaybookInstance(BaseModel):
    playbook_id: Optional[str]
    trigger_type: str  # technique | parent_technique | tactic | banking_flag ...
    trigger_value: Optional[str]
    mode: str  # MONITOR | CONTAIN | CONTAIN_AND_HUNT | CRISIS
    rationale: Optional[str] = None


class L2PlaybookRouting(BaseModel):
    activated_playbooks: List[L2PlaybookInstance]
    not_selected: List[str] = []


class L2RiskResponseFloor(BaseModel):
    triggered: bool
    threshold: float = 6.0
    completed: bool
    required_actions: List[str]
    performed_actions: List[str] = []
    blocked_actions: List[str] = []
    rationale: List[str] = []
    execution_note: Optional[str] = None


class L2DecisionSummary(BaseModel):
    final_decision: str  # no_action | suggest_only | auto_execute | queue_approval | manual_escalation | needs_more_evidence
    execution_mode: str  # suggest_only | execute
    risk_response_floor: L2RiskResponseFloor
    justification: Optional[str] = None
    summary_for_soc: Optional[str] = None


class L2Target(BaseModel):
    type: str  # ip | domain | host | user | account | session ...
    value_masked: Optional[str] = None


class L2Action(BaseModel):
    action_id: Optional[str]
    phase: str  # preserve | contain | hunt | recover | notify | predict
    action_type: str  # preserve_logs | add_watchlist ...
    target: L2Target
    approval_mode: str  # AUTO | APPROVAL_REQUIRED | MANUAL_ONLY
    status: str  # suggested | ready_for_execution | executed ...
    ttl_minutes: Optional[int] = None
    expires_at: Optional[str] = None
    rollback_plan: Optional[str] = None
    evidence_refs: List[str] = []
    playbook_source: Optional[str] = None
    rationale: Optional[str] = None
    risk_if_wrong: str  # low | medium | high | critical


class L2PredictedTechnique(BaseModel):
    technique_id: Optional[str]
    technique_name: Optional[str]
    source: str  # mitre_prediction_chain | same_capec_family | generic_kill_chain
    why_likely: Optional[str] = None
    priority: str  # high | medium | low


class L2PredictiveDefense(BaseModel):
    predicted_techniques: List[L2PredictedTechnique] = []
    temporary_detections: List[str] = []
    watch_for_next: List[str] = []


class L2TicketPayload(BaseModel):
    title: Optional[str]
    priority: Optional[str]
    body: Optional[str]
    labels: List[str] = []


class L2OutputAndNotification(BaseModel):
    suggested_actions: List[str] = []
    executed_actions: List[str] = []
    notification_targets: List[str] = []
    ticket_payload: L2TicketPayload


class L2SocFeedbackControls(BaseModel):
    allowed_actions: List[str]
    callback_required: bool = True
    callback_channel: str = "api_call"


class L2AuditEvent(BaseModel):
    event_type: str  # decision | policy_check | action | rollback ...
    event_time: Optional[str] = None
    actor: str = "layer2_orchestrator_soar"
    command_signature_ref: Optional[str] = None
    details: Optional[str] = None
    result: Optional[str] = None


class L2Audit(BaseModel):
    immutable_log_required: bool = True
    audit_events: List[L2AuditEvent]
    compliance_tags: List[str] = ["ISO27001", "PCI-DSS"]


class L2Safety(BaseModel):
    prompt_injection_observed: bool = False
    prompt_injection_evidence_masked: List[str] = []
    log_instruction_ignored: bool = True
    sensitive_values_masked: bool = True
    no_destructive_action_selected: bool = True


class L2Quality(BaseModel):
    missing_fields: List[str] = []
    limitations: List[str] = []
    requires_human_review: bool = False


class L2OrchestratorDecision(BaseModel):
    schema_version: str = "littleboy.soc.layer2.orchestrator_decision.v7"
    timestamp: str
    orchestrator: L2Orchestrator
    input_summary: L2InputSummary
    correlation: L2Correlation
    l2_independent_verification: L2IndependentVerification
    verified_case: L2VerifiedCase
    scoring: L2Scoring
    banking_impact: L2BankingImpact
    policy_guardrails: L2PolicyGuardrails
    automation_control: L2AutomationControl
    playbook_routing: L2PlaybookRouting
    decision: L2DecisionSummary
    actions: List[L2Action]
    predictive_defense: L2PredictiveDefense
    output_and_notification: L2OutputAndNotification
    soc_feedback_controls: L2SocFeedbackControls
    audit: L2Audit
    safety: L2Safety
    quality: L2Quality
