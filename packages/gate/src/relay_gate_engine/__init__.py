"""Relay gate evaluation pipeline (Python; W8.1).

Public surface for w8.1:

- :class:`GateEvaluator` -- the deterministic three-gate evaluator that
  consumes a :class:`GateDecisionDraft` and produces a
  :class:`DraftOutcome`. Conditions on each gate's policy are evaluated
  through the W6 :class:`relay_contracts.RelayCelEvaluator`; assertions
  are sorted ``P0 > P1 > P2 > P3`` and short-circuit on the first failing
  P0 when ``cascade_on_block`` is true (VAL-W8-004). Pipeline order is
  fixed scrutiny -> structural-review -> testing (VAL-W8-001).
- :class:`GatePipeline` -- the three-gate orchestrator that enforces
  fixed evaluation order across rounds.
- :class:`DraftLock` -- the in-memory concurrent-draft conflict guard
  keyed on ``(gate_id, scope_type, scope_id, round)``; second submitter
  receives ``RELAY-GATE-014`` per VAL-W8-007.
- :class:`AntiBypassGuard` -- W2.5 mirror; refuses drafts whose declared
  command (resolved via the manifest's ``command_hash -> command_line``
  map) contains any banned bypass flag (VAL-W8-041).
- :func:`is_draft_expired` -- TTL helper (VAL-W8-006).
- Provider protocols :class:`EvidenceBundleProvider`,
  :class:`ManifestCommandResolver`, :class:`AssertionLoader` -- the gate
  engine consumes evidence by id (VAL-W8-003), commands by hash
  (CLAUDE.md keystone invariant 3), and assertions by id; concrete
  storage backends land in W8.2.

Spec anchors: A.2 / A.3 / A.4 / A.5, C, D.3, K.
Eng plan anchors: W8 (line 382), Lane D (line 398).
CLAUDE.md anchors: keystone invariants 1, 2, 4, 5; banned pattern 8;
the gate-decision-ownership / gate-restart / stale-handoff /
evidence-pairing / manifest-source-of-truth / anti-bypass guard tests.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .admin_actions import (
    ADMIN_ROLES,
    AUDIT_ACTION_REOPEN,
    AUDIT_ACTION_TERMINATE,
    EVENT_ADMIN_REOPEN,
    EVENT_ADMIN_TERMINATE,
    INITIATED_BY_ADMIN_OVERRIDE,
    MAX_REASON_BYTES,
    SCHEMA_AUDIT_LOG_ENTRY,
    SCHEMA_X_RELAY_EXTENSION,
    X_RELAY_ADMIN_TERMINATE_NS,
    AdminActionService,
    AdminActor,
    AdminReasonError,
    ReopenResult,
    StalledStateAlreadyTerminatedError,
    StalledStateMissingError,
    TerminateResult,
    fetch_audit_entry,
)
from .circuit_breaker import (
    DEFAULT_REMEDIATION_ROUND_CAP,
    EVENT_GATE_STALLED,
    EVENT_GATE_TERMINAL_BLOCK,
    EVENT_KIND_VALIDATION_CIRCUIT_BREAKER,
    REMEDIATION_ROUND_CAP_MAX,
    REMEDIATION_ROUND_CAP_MIN,
    STALLED_REASON_ADMIN_TERMINATED,
    STALLED_REASON_CAP_EXCEEDED,
    CircuitBreaker,
    GateConfig,
    TerminalBlockResult,
    TripResult,
    load_gate_config,
    validate_remediation_round_cap,
)
from .db_grants import (
    NON_ENGINE_ROLES,
    POSTGRES_GATE_DECISIONS_GRANTS,
    ROLE_ANTI_BYPASS,
    ROLE_EVAL_WORKER,
    ROLE_GATE_ENGINE,
    ROLE_REPLAY_WORKER,
    ROLE_RETENTION_ARCHIVE,
    ROLE_SDK,
    ROLE_STATE_ENGINE,
    ROLE_WORKER,
    assert_role_token,
    role_update_sql,
)
from .decision_writer import (
    CANONICAL_ANCHOR_ORDER,
    DECIDED_BY_GATE_ENGINE,
    EVENT_DECISION_WRITTEN,
    EVENT_REJECTED_HANDOFF,
    HANDOFF_REASON_TO_MISMATCHED_ANCHOR,
    RELAY_GATE_021,
    SCHEMA_EVENT_LOG,
    SCHEMA_EVIDENCE_BUNDLE,
    SCHEMA_GATE_DECISION,
    SCHEMA_GATE_ROUND,
    DecisionWriteResult,
    EvidenceBundleInputs,
    GateDecisionInputs,
    GateDecisionWriter,
    HandoffPayload,
    recompute_bundle_digest,
)
from .draft_lock import DraftLock, DraftLockConflictError
from .errors import (
    AdminAuthorizationError,
    AntiBypassRejectedError,
    DraftTtlExpiredError,
    GateEngineError,
    GateOrderingError,
    StaleHandoffError,
    StalledScopeRejectedError,
)
from .evaluator import (
    BANNED_BYPASS_TOKENS,
    AntiBypassGuard,
    AssertionLoader,
    DraftOutcome,
    EvidenceBundleProvider,
    GateAssertion,
    GateEvaluator,
    GatePolicy,
    ManifestCommandResolver,
    is_draft_expired,
)
from .metric_catalog import (
    CANONICAL_TABLES,
    CATALOG_PATH,
    CATALOG_SCHEMA_PATH,
    SOURCE_SENTINEL_AGGREGATION_BLOCK,
    SPEC_METRIC_NAMES,
    SPEC_MISSING_DATA,
    SPEC_UNITS,
    BaselineDefinition,
    GateMetricCatalog,
    MetricCompiler,
    MetricCompilerError,
    MetricDefinition,
    extract_cte_names,
    extract_tables_from_source,
    load_catalog,
    load_catalog_schema,
)
from .metric_catalog import (
    SCHEMA_VERSION as METRIC_CATALOG_SCHEMA_VERSION,
)
from .pipeline import (
    GATE_ORDER,
    GateDecisionDraft,
    GateName,
    GatePipeline,
    PipelineResult,
)
from .restart_pipeline import (
    CANCELLATION_REASON_SUPERSEDED,
    EVENT_GATE_RESTARTED,
    EVENT_KIND_GATE_RESTARTED,
    INITIATED_BY_REMEDIATION,
    RemediationDirectiveCheck,
    RestartCoordinator,
    RestartResult,
    ResubmissionGuardResult,
    UnchangedResubmissionError,
    compute_inputs_digest,
    validate_remediation_directive,
)
from .signed_decision import (
    SigningKey,
    canonical_decision_payload,
    canonical_json_bytes,
    resolve_signing_key,
    sha256_wire,
    sign_payload,
    verify_payload,
)

__all__ = [
    "ADMIN_ROLES",
    "AUDIT_ACTION_REOPEN",
    "AUDIT_ACTION_TERMINATE",
    "AdminActionService",
    "AdminActor",
    "AdminAuthorizationError",
    "AdminReasonError",
    "AntiBypassGuard",
    "AntiBypassRejectedError",
    "AssertionLoader",
    "BANNED_BYPASS_TOKENS",
    "BaselineDefinition",
    "CANCELLATION_REASON_SUPERSEDED",
    "CANONICAL_ANCHOR_ORDER",
    "CANONICAL_TABLES",
    "CATALOG_PATH",
    "CATALOG_SCHEMA_PATH",
    "CircuitBreaker",
    "DECIDED_BY_GATE_ENGINE",
    "DEFAULT_REMEDIATION_ROUND_CAP",
    "DecisionWriteResult",
    "DraftLock",
    "DraftLockConflictError",
    "DraftOutcome",
    "DraftTtlExpiredError",
    "EVENT_ADMIN_REOPEN",
    "EVENT_ADMIN_TERMINATE",
    "EVENT_DECISION_WRITTEN",
    "EVENT_GATE_RESTARTED",
    "EVENT_GATE_STALLED",
    "EVENT_GATE_TERMINAL_BLOCK",
    "EVENT_KIND_GATE_RESTARTED",
    "EVENT_KIND_VALIDATION_CIRCUIT_BREAKER",
    "EVENT_REJECTED_HANDOFF",
    "EvidenceBundleInputs",
    "EvidenceBundleProvider",
    "GATE_ORDER",
    "GateAssertion",
    "GateConfig",
    "GateDecisionDraft",
    "GateDecisionInputs",
    "GateDecisionWriter",
    "GateEngineError",
    "GateEvaluator",
    "GateMetricCatalog",
    "GateName",
    "GateOrderingError",
    "GatePipeline",
    "GatePolicy",
    "HANDOFF_REASON_TO_MISMATCHED_ANCHOR",
    "HandoffPayload",
    "INITIATED_BY_ADMIN_OVERRIDE",
    "INITIATED_BY_REMEDIATION",
    "MAX_REASON_BYTES",
    "METRIC_CATALOG_SCHEMA_VERSION",
    "ManifestCommandResolver",
    "MetricCompiler",
    "MetricCompilerError",
    "MetricDefinition",
    "NON_ENGINE_ROLES",
    "POSTGRES_GATE_DECISIONS_GRANTS",
    "PipelineResult",
    "RELAY_GATE_021",
    "REMEDIATION_ROUND_CAP_MAX",
    "REMEDIATION_ROUND_CAP_MIN",
    "ROLE_ANTI_BYPASS",
    "ROLE_EVAL_WORKER",
    "ROLE_GATE_ENGINE",
    "ROLE_REPLAY_WORKER",
    "ROLE_RETENTION_ARCHIVE",
    "ROLE_SDK",
    "ROLE_STATE_ENGINE",
    "ROLE_WORKER",
    "RemediationDirectiveCheck",
    "ReopenResult",
    "RestartCoordinator",
    "RestartResult",
    "ResubmissionGuardResult",
    "STALLED_REASON_ADMIN_TERMINATED",
    "STALLED_REASON_CAP_EXCEEDED",
    "SCHEMA_AUDIT_LOG_ENTRY",
    "SCHEMA_EVENT_LOG",
    "SCHEMA_EVIDENCE_BUNDLE",
    "SCHEMA_GATE_DECISION",
    "SCHEMA_GATE_ROUND",
    "SCHEMA_X_RELAY_EXTENSION",
    "SOURCE_SENTINEL_AGGREGATION_BLOCK",
    "SPEC_METRIC_NAMES",
    "SPEC_MISSING_DATA",
    "SPEC_UNITS",
    "SigningKey",
    "StaleHandoffError",
    "StalledScopeRejectedError",
    "StalledStateAlreadyTerminatedError",
    "StalledStateMissingError",
    "TerminalBlockResult",
    "TerminateResult",
    "TripResult",
    "UnchangedResubmissionError",
    "X_RELAY_ADMIN_TERMINATE_NS",
    "assert_role_token",
    "canonical_decision_payload",
    "canonical_json_bytes",
    "compute_inputs_digest",
    "extract_cte_names",
    "extract_tables_from_source",
    "fetch_audit_entry",
    "is_draft_expired",
    "load_catalog",
    "load_catalog_schema",
    "load_gate_config",
    "recompute_bundle_digest",
    "resolve_signing_key",
    "role_update_sql",
    "sha256_wire",
    "sign_payload",
    "validate_remediation_directive",
    "validate_remediation_round_cap",
    "verify_payload",
]
