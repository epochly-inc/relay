"""Relay eval runner primitives (Python; W9.1).

Public surface for w9.1:

- :class:`EvalRunner` -- single-process eval runner that consumes
  :class:`EvalCase` rows, invokes a user-supplied evaluator callable,
  binds each outcome to the five evidence anchors required by
  CLAUDE.md keystone invariant #2 (artifact hash, command id + exit
  code, span ids, manifest commit hash, assertion id), writes per-case
  ``eval_results`` rows, and finalises the canonical ``eval_runs``
  aggregate with status / score / passed per VAL-W9-002.
- :func:`compute_eval_delta` -- deterministic eval-delta classifier
  that writes ``eval_run_deltas`` rows (append-only, idempotent via a
  deterministic ``delta_id``) per VAL-W9-003 / VAL-W9-004. Supports
  configurable ``flake_window_n`` (default 5; VAL-W9-005).
- :func:`apply_migrations` -- applies the bundled SQLite migration so
  callers can stand up the schema in tests and standalone CLI runs.
- :func:`validate_binding` / :class:`EvidenceBinding` -- the
  evidence-binding contract (VAL-W9-007).

Spec anchors: A line 1899 (eval_runs), AM.3 line 5876 (eval-delta), K
(evidence binding), AM.6 (tier-3 budget).
Eng plan anchors: W9 line 127-128, A6 line 290-291 (tier-3 matrix).
CLAUDE.md anchors: keystone invariants 1, 2, 3, 8; the RunResult
ownership guard; the Evidence pairing guard.

Contract assertions: VAL-W9-001 .. VAL-W9-008, VAL-W9-021.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .delta import (
    DEFAULT_FLAKE_WINDOW_N,
    DELTA_BASELINE_ABSENT,
    DELTA_CLASSES,
    DELTA_FLAKY,
    DELTA_NET_NEW_FAILURE,
    DELTA_NET_NEW_SUCCESS,
    DELTA_UNCHANGED_FAILURE,
    DELTA_UNCHANGED_PASS,
    MAX_FLAKE_WINDOW_N,
    DeltaComputeResult,
    compute_eval_delta,
)
from .evidence import (
    MALFORMED_ARTIFACT_HASH,
    MALFORMED_MANIFEST_COMMIT_HASH,
    MISSING_ARTIFACT_HASH,
    MISSING_ASSERTION_ID,
    MISSING_COMMAND_ID,
    MISSING_EXIT_CODE,
    MISSING_MANIFEST_COMMIT_HASH,
    MISSING_SPAN_IDS,
    EvidenceBinding,
    EvidenceValidation,
    render_invalid_reason,
    validate_binding,
)
from .runner import (
    EvalCase,
    EvalCaseOutcome,
    EvalCaseResult,
    EvalRunner,
    EvalRunSummary,
)
from .storage import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect_file,
    connect_memory,
    eval_transaction,
)

__all__ = [
    # runner
    "EvalRunner",
    "EvalCase",
    "EvalCaseOutcome",
    "EvalCaseResult",
    "EvalRunSummary",
    # delta
    "compute_eval_delta",
    "DeltaComputeResult",
    "DEFAULT_FLAKE_WINDOW_N",
    "MAX_FLAKE_WINDOW_N",
    "DELTA_CLASSES",
    "DELTA_NET_NEW_FAILURE",
    "DELTA_NET_NEW_SUCCESS",
    "DELTA_UNCHANGED_PASS",
    "DELTA_UNCHANGED_FAILURE",
    "DELTA_FLAKY",
    "DELTA_BASELINE_ABSENT",
    # evidence
    "EvidenceBinding",
    "EvidenceValidation",
    "validate_binding",
    "render_invalid_reason",
    "MISSING_ARTIFACT_HASH",
    "MISSING_COMMAND_ID",
    "MISSING_EXIT_CODE",
    "MISSING_SPAN_IDS",
    "MISSING_MANIFEST_COMMIT_HASH",
    "MISSING_ASSERTION_ID",
    "MALFORMED_ARTIFACT_HASH",
    "MALFORMED_MANIFEST_COMMIT_HASH",
    # storage
    "apply_migrations",
    "eval_transaction",
    "connect_memory",
    "connect_file",
    "DEFAULT_MIGRATIONS_DIR",
]
