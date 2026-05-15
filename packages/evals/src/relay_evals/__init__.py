"""Relay eval runner primitives + assertion-template library (Python).

Public surface:

W9.1 -- runner + delta + storage + evidence binding:

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

W9.2 -- assertion template library:

- :func:`coverage_assertion_template`     (VAL-W9-013)
- :func:`tool_arg_assertion_template`     (VAL-W9-014)
- :func:`schema_match_assertion_template` (VAL-W9-015)
- :func:`get_template` / :func:`invoke_template` / :func:`list_template_names`
  / :func:`load_template_from_path` -- signed registry surface
  (VAL-W9-009, VAL-W9-012).
- :class:`RelayTemplateInputError`, :class:`RelayTemplateLoaderError`,
  :class:`RelayManifestUnknownToolError`, :class:`RelaySchemaNotFoundError`
  -- structured exception types (VAL-W9-010).
- :func:`derive_assertion_id` / :data:`ASSERTION_ID_PATTERN` --
  deterministic id derivation (VAL-W9-011).

W9.3 -- LLM-as-judge evaluator stub (DEFERRED to month 4+):

- :func:`llm_judge_evaluator`            stub entry point; validates
  the canonical EvalAssertion shape then raises NotImplementedError
  with the deferred-to-month-4+ message (VAL-W9-016 .. VAL-W9-018).
- :data:`LLM_JUDGE_EVALUATOR_KIND`       canonical evaluator.kind
  token; schema-level reservation only (VAL-W9-019).
- :data:`LLM_JUDGE_DEFERRED_MESSAGE`     exact deferred phrase
  surfaced in the NotImplementedError (VAL-W9-018).
- :data:`LLM_JUDGE_DEFERRED_CODE`        wire token routing to CLI
  exit code 8 (VAL-W9-019).
- :data:`EVAL_ASSERTION_SCHEMA_ID`       canonical
  relay.assertion.eval.v1 schema id (spec D.5).
- :data:`ACTIVE_EVALUATORS` / :func:`list_active_evaluator_kinds`
  active-evaluator introspection; v0.1 returns the empty mapping
  (VAL-W9-019).

Spec anchors: A line 1899 (eval_runs), AM.3 line 5876 (eval-delta), K
(evidence binding), AM.6 (tier-3 budget), D.5 (EvalAssertion),
D.6 (CoverageOwner), F (manifest source of truth), B.7 (schema
versioning), S (Malicious assertion template upload mitigation),
AM.7 line 5947 (LLM-as-judge deferred).
Eng plan anchors: W9 line 127-128, A6 line 290-291 (tier-3 matrix).
CLAUDE.md anchors: keystone invariants 1, 2, 3, 8, 10; the RunResult
ownership guard; the Evidence pairing guard;
"No placeholders, no compromises" -- the W9.3 stub is the documented
exception (slot reserved at schema level; runtime refuses).

Contract assertions: VAL-W9-001 .. VAL-W9-008, VAL-W9-009 .. VAL-W9-015,
VAL-W9-016 .. VAL-W9-020, VAL-W9-021.

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
from .llm_judge import (
    ACTIVE_EVALUATORS,
    EVAL_ASSERTION_SCHEMA_ID,
    LLM_JUDGE_DEFERRED_CODE,
    LLM_JUDGE_DEFERRED_MESSAGE,
    LLM_JUDGE_EVALUATOR_KIND,
    list_active_evaluator_kinds,
    llm_judge_evaluator,
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
from .templates import (
    ASSERTION_ID_PATTERN,
    ASSERTION_ID_RE,
    COVERAGE_TEMPLATE_NAME,
    COVERAGE_TEMPLATE_SCHEMA,
    KNOWN_SCHEMA_IDS,
    REGISTERED_TEMPLATES,
    SCHEMA_MATCH_TEMPLATE_NAME,
    SCHEMA_MATCH_TEMPLATE_SCHEMA,
    SIGNED_BUNDLED_MARKER,
    TOOL_ARG_TEMPLATE_NAME,
    TOOL_ARG_TEMPLATE_SCHEMA,
    CoverageTemplateResult,
    RegisteredTemplate,
    RelayManifestUnknownToolError,
    RelaySchemaNotFoundError,
    RelayTemplateError,
    RelayTemplateInputError,
    RelayTemplateLoaderError,
    SchemaMatchTemplateResult,
    ToolArgTemplateResult,
    coverage_assertion_template,
    derive_assertion_id,
    get_template,
    invoke_template,
    list_template_names,
    load_template_from_path,
    schema_match_assertion_template,
    tool_arg_assertion_template,
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
    # templates: ids
    "ASSERTION_ID_PATTERN",
    "ASSERTION_ID_RE",
    "derive_assertion_id",
    # templates: errors
    "RelayManifestUnknownToolError",
    "RelaySchemaNotFoundError",
    "RelayTemplateError",
    "RelayTemplateInputError",
    "RelayTemplateLoaderError",
    # templates: coverage
    "COVERAGE_TEMPLATE_NAME",
    "COVERAGE_TEMPLATE_SCHEMA",
    "CoverageTemplateResult",
    "coverage_assertion_template",
    # templates: tool_arg
    "TOOL_ARG_TEMPLATE_NAME",
    "TOOL_ARG_TEMPLATE_SCHEMA",
    "ToolArgTemplateResult",
    "tool_arg_assertion_template",
    # templates: schema_match
    "KNOWN_SCHEMA_IDS",
    "SCHEMA_MATCH_TEMPLATE_NAME",
    "SCHEMA_MATCH_TEMPLATE_SCHEMA",
    "SchemaMatchTemplateResult",
    "schema_match_assertion_template",
    # templates: registry
    "REGISTERED_TEMPLATES",
    "RegisteredTemplate",
    "SIGNED_BUNDLED_MARKER",
    "get_template",
    "invoke_template",
    "list_template_names",
    "load_template_from_path",
    # llm_judge (W9.3 stub; DEFERRED to month 4+)
    "ACTIVE_EVALUATORS",
    "EVAL_ASSERTION_SCHEMA_ID",
    "LLM_JUDGE_DEFERRED_CODE",
    "LLM_JUDGE_DEFERRED_MESSAGE",
    "LLM_JUDGE_EVALUATOR_KIND",
    "list_active_evaluator_kinds",
    "llm_judge_evaluator",
]
