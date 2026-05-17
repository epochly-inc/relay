"""W2.4 sidecar state engine -- canonical control-plane write path.

Per CLAUDE.md keystone invariant #1 (the control plane writes the result),
invariant #4 (three-anchor handoff), and invariant #8 (atomic persistence
via four primitives), this module is the ONLY path in the local sidecar
that writes ``scope_state``, ``run_results``, ``gate_decisions``, and
``event_log_entries`` (state-transition rows).

Public surface:

  - ``compare_and_set_state`` -- the spec C.4 primitive, atomic compare-and-
    set on (scope_kind, scope_id) with epoch optimistic concurrency, emitting
    exactly one ``event_log_entries`` row per successful transition.
  - ``init_scope`` -- insert a fresh ``scope_state`` row at the canonical
    initial state for a scope kind.
  - ``validate_three_anchor_handoff`` -- spec C.5 three-anchor handoff
    validator (scope_id, actor_identity_hash, manifest_commit_hash).
  - ``TRANSITION_TABLE`` -- the canonical machine-readable extract of spec
    C.3, loaded from packages/schemas/raw/state-transition-table.yaml.

VAL-W2-024 + VAL-W2-058 grep guards enforce "this module is the only
writer" at the source-tree level: ``grep -rn "INSERT INTO run_results|UPDATE
run_results|INSERT INTO scope_state|UPDATE scope_state|INSERT INTO
event_log_entries|UPDATE event_log_entries" apps/local-sidecar/`` MUST
return matches only inside this directory (plus the migrations directory).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .compare_and_set import (
    ACTOR_NOT_ALLOWED,
    EXPECTED_FROM_MISMATCH,
    GUARD_FAILED,
    INVALID_TRANSITION,
    INVALID_TRANSITION_EVENT_TYPE,
    TERMINAL_STATE,
    UNKNOWN_SCOPE,
    ActorRef,
    StateTransitionResult,
    compare_and_set_state,
    init_scope,
    init_scope_on_conn,
)
from .handoff import (
    ACTOR_NOT_REGISTERED,
    MANIFEST_NOT_ACTIVE,
    SCOPE_ID_MISMATCH,
    HandoffResult,
    validate_three_anchor_handoff,
)
from .transitions import (
    TRANSITION_TABLE,
    ScopeKindSpec,
    Transition,
    TransitionTable,
    load_transition_table,
)

__all__ = [
    "ACTOR_NOT_ALLOWED",
    "ACTOR_NOT_REGISTERED",
    "ActorRef",
    "EXPECTED_FROM_MISMATCH",
    "GUARD_FAILED",
    "HandoffResult",
    "INVALID_TRANSITION",
    "INVALID_TRANSITION_EVENT_TYPE",
    "MANIFEST_NOT_ACTIVE",
    "SCOPE_ID_MISMATCH",
    "ScopeKindSpec",
    "StateTransitionResult",
    "TERMINAL_STATE",
    "TRANSITION_TABLE",
    "Transition",
    "TransitionTable",
    "UNKNOWN_SCOPE",
    "compare_and_set_state",
    "init_scope",
    "init_scope_on_conn",
    "load_transition_table",
    "validate_three_anchor_handoff",
]
