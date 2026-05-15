"""W9.3 LLM-as-judge evaluator stub (DEFERRED to month 4+).

Per the relay-v0.1-oss-wedge contract (VAL-W9-016 .. VAL-W9-020), v0.1
ships ONLY a structurally-typed placeholder for the LLM-as-judge
evaluator. The PRESENCE of the entry point is asserted; its
IMPLEMENTATION is NOT. The full evaluator (judge model selection,
prompt scaffolding, structured-output enforcement, cassette-mode
replay binding) lands in month 4+ alongside the cassette-first replay
hardening described in spec section AM.7.

Public surface:

  - :func:`llm_judge_evaluator`        the stub entry point. Validates
    its input against the canonical EvalAssertion shape (spec D.5,
    line 3860). On valid input the stub raises ``NotImplementedError``
    carrying the canonical deferred-to-month-4+ message; on invalid
    input the stub raises ``RelayTemplateInputError`` BEFORE the
    NotImplementedError fires (VAL-W9-017 precedence).
  - :data:`LLM_JUDGE_EVALUATOR_KIND`   canonical ``evaluator.kind``
    token (``"llm_judge"``). Schema-level reservation; runtime refuses
    to register (VAL-W9-019).
  - :data:`LLM_JUDGE_DEFERRED_MESSAGE` exact deferred-to-month-4+ phrase
    surfaced in the NotImplementedError message (VAL-W9-018).
  - :data:`LLM_JUDGE_DEFERRED_CODE`    wire token for the CLI-routing
    layer (``"RELAY-EVAL-EVALUATOR-DEFERRED"``). Mapped to CLI exit
    code 8 in ``packages/sdk-python/relay/exit_codes.py``.
  - :data:`EVAL_ASSERTION_SCHEMA_ID`   the canonical
    ``relay.assertion.eval.v1`` schema id the stub accepts on input
    (spec D.5 line 3860).
  - :data:`ACTIVE_EVALUATORS`          frozenmapping of registered
    EVALUATOR kinds. v0.1 ships ZERO active evaluators -- the
    code-evaluator that the W9.1 EvalRunner accepts is dispatched by
    user-supplied callable, not by ``evaluator.kind``. The map is the
    introspection surface returned by future
    ``rly eval evaluators list``; the W9.3 stub is NOT in it.
  - :func:`list_active_evaluator_kinds` introspection accessor.

Why a stub (and not a feature flag):

The schema slot is reserved at v0.1 so customers can author
EvalAssertion documents today that round-trip through the eval-delta
machinery (status ``invalid`` with code
``RELAY-EVAL-EVALUATOR-DEFERRED``). A live feature flag would risk
the slot being mistaken for a forthcoming-in-v0.1 feature; the
explicit ``NotImplementedError`` + zero-registration combination
makes the deferred status unmistakable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final, NoReturn

from .templates.errors import RelayTemplateInputError

# Logger name is bound to the module dotted path so tests can capture
# only this stub's records (test_w9_3_llm_judge.py).
_LOG: Final[logging.Logger] = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Public constants
# -----------------------------------------------------------------------------

# Canonical EvalAssertion schema id (spec D.5 line 3860). The stub
# refuses any other ``schema_version`` on input; future revisions
# (relay.assertion.eval.v2 etc.) MUST add new schema ids per spec B.7
# rather than mutating v1.
EVAL_ASSERTION_SCHEMA_ID: Final[str] = "relay.assertion.eval.v1"

# Canonical ``evaluator.kind`` token. The schema slot is reserved but
# the runtime refuses to register the stub as an active evaluator
# (VAL-W9-019).
LLM_JUDGE_EVALUATOR_KIND: Final[str] = "llm_judge"

# The exact deferred-to-month-4+ message surfaced in the
# NotImplementedError. VAL-W9-018 binds tests to this exact phrase.
# Changing this string is a public-API change requiring a contract
# amendment.
LLM_JUDGE_DEFERRED_MESSAGE: Final[str] = (
    "LLM-as-judge evaluator deferred to month 4+; see docs/roadmap.md "
    "for the tracking issue and target horizon."
)

# Wire-format token for CLI / SDK routing. Mapped to CLI exit code 8 in
# ``packages/sdk-python/relay/exit_codes.py`` (EXIT_EVAL_DEFERRED).
# Note: this token does NOT match the ``RELAY-{AREA}-NNN`` grammar from
# VAL-W1-029; it is an EXCEPTION inherited from the contract preamble
# canonical exit-code table. The W9.3 stub re-exports it here so the
# CLI eval-runner integration (future work) has one import site to
# bind to.
LLM_JUDGE_DEFERRED_CODE: Final[str] = "RELAY-EVAL-EVALUATOR-DEFERRED"

# Active-evaluator registry. v0.1 ships ZERO active evaluators -- the
# slot is reserved for month 4+ work. The W9.1 EvalRunner dispatches
# by user-supplied callable rather than by ``evaluator.kind``, so the
# absence of any entry here is not a regression on existing eval
# semantics. The map is a frozen MappingProxyType so callers cannot
# add the stub kind at runtime.
_ACTIVE_EVALUATORS_INNER: dict[str, str] = {}
ACTIVE_EVALUATORS: Final[Mapping[str, str]] = MappingProxyType(
    _ACTIVE_EVALUATORS_INNER
)


def list_active_evaluator_kinds() -> tuple[str, ...]:
    """Return the sorted tuple of active evaluator kinds.

    v0.1 always returns an empty tuple. The function exists so the
    future ``rly eval evaluators list`` CLI command has a single
    library-level call site to bind to. VAL-W9-019 evidence pairs to
    this function's output (CLI stdout JSON listing).
    """
    return tuple(sorted(ACTIVE_EVALUATORS.keys()))


# -----------------------------------------------------------------------------
# Input validation (spec D.5 EvalAssertion, line 3860)
# -----------------------------------------------------------------------------

# Top-level required keys per the EvalAssertion schema. Unknown
# top-level keys are NOT rejected by the stub (additionalProperties is
# permissive at this surface; the v0.1 stub validates only the
# minimum needed to identify a well-formed payload). The schema's full
# enforcement (additionalProperties: false, nested constraints) lands
# with the real evaluator alongside the codegen pipeline that emits a
# JSON schema from spec D.5.
_REQUIRED_TOP_LEVEL: Final[tuple[str, ...]] = (
    "schema_version",
    "assertion_id",
    "evaluator",
)

# Required keys on the nested ``evaluator`` mapping. The runtime only
# binds to ``evaluator.kind`` in v0.1; ``evaluator.config`` is
# accepted but not introspected.
_REQUIRED_EVALUATOR_KEYS: Final[tuple[str, ...]] = ("kind",)

# VAL-W1-029 sha256 sanity check (not enforced here; included for
# parity with the contract preamble's evidence-binding rule).
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^sha256-[0-9a-f]{64}$")


def _raise_input(message: str, *, json_path: str) -> NoReturn:
    """Raise ``RelayTemplateInputError`` carrying the JSON-Schema path.

    Mirrors the W9.2 input-error convention: tests bind to
    ``payload["json_path"]`` directly; the CLI renders it as
    ``Input validation failed at <json_path>: <message>``.
    """
    raise RelayTemplateInputError(
        message,
        payload={"json_path": json_path},
    )


def _validate_input(payload: Any) -> Mapping[str, Any]:
    """Validate the EvalAssertion shape; return the original payload.

    Failure semantics (VAL-W9-017):

      - top-level non-Mapping            -> json_path '$'
      - missing required top-level field -> json_path '$.<field>'
      - wrong schema_version             -> json_path '$.schema_version'
      - evaluator not a Mapping          -> json_path '$.evaluator'
      - evaluator.kind missing/wrong     -> json_path '$.evaluator.kind'

    The check order matches the JSON-Schema path order so the error
    a customer sees corresponds to the FIRST violation, not an
    arbitrary one.
    """
    if not isinstance(payload, Mapping):
        _raise_input(
            f"EvalAssertion input MUST be a Mapping; got "
            f"{type(payload).__name__}",
            json_path="$",
        )

    for field in _REQUIRED_TOP_LEVEL:
        if field not in payload:
            _raise_input(
                f"EvalAssertion missing required field {field!r}",
                json_path=f"$.{field}",
            )

    schema_version = payload["schema_version"]
    if schema_version != EVAL_ASSERTION_SCHEMA_ID:
        _raise_input(
            f"EvalAssertion.schema_version MUST equal "
            f"{EVAL_ASSERTION_SCHEMA_ID!r}; got {schema_version!r}",
            json_path="$.schema_version",
        )

    evaluator = payload["evaluator"]
    if not isinstance(evaluator, Mapping):
        _raise_input(
            f"EvalAssertion.evaluator MUST be a Mapping; got "
            f"{type(evaluator).__name__}",
            json_path="$.evaluator",
        )

    for field in _REQUIRED_EVALUATOR_KEYS:
        if field not in evaluator:
            _raise_input(
                f"EvalAssertion.evaluator missing required field {field!r}",
                json_path=f"$.evaluator.{field}",
            )

    kind = evaluator["kind"]
    if kind != LLM_JUDGE_EVALUATOR_KIND:
        _raise_input(
            f"llm_judge_evaluator stub binds only to "
            f"evaluator.kind={LLM_JUDGE_EVALUATOR_KIND!r}; got {kind!r}",
            json_path="$.evaluator.kind",
        )

    return payload


# -----------------------------------------------------------------------------
# Public entry point
# -----------------------------------------------------------------------------


def llm_judge_evaluator(payload: Mapping[str, Any]) -> NoReturn:
    """LLM-as-judge evaluator stub (DEFERRED to month 4+).

    VAL-W9-016: public symbol at ``relay_evals.llm_judge_evaluator``.
    VAL-W9-017: accepts the canonical EvalAssertion schema input; raises
        :class:`RelayTemplateInputError` on schema breakage (BEFORE the
        deferred raise) so customers can distinguish "input shape
        breakage" from "not implemented yet".
    VAL-W9-018: on valid input raises :class:`NotImplementedError`
        carrying the canonical deferred-to-month-4+ message. The stub
        MUST NOT return a fake pass, MUST NOT return a fake score, and
        MUST NOT silently succeed.
    VAL-W9-019: NOT in :data:`ACTIVE_EVALUATORS` and NOT in
        ``REGISTERED_TEMPLATES``. Future ``rly eval evaluators list``
        omits ``llm_judge``.

    The stub deliberately emits no INFO+ log records carrying
    "evaluated", "passed", or "score" tokens (VAL-W9-018 log-capture
    assertion). A DEBUG-level record noting the deferred raise is
    permitted for triage but is NOT relied upon.
    """
    # Validate first. VAL-W9-017 precedence: schema breakage surfaces
    # explicitly before the deferred raise.
    _validate_input(payload)

    # Permitted DEBUG-level breadcrumb. The tokens "evaluated"/"passed"/
    # "score" MUST NOT appear at INFO+ per VAL-W9-018; this record stays
    # at DEBUG and uses the neutral phrase "deferred raise".
    _LOG.debug(
        "llm_judge_evaluator deferred raise (schema=%s; kind=%s)",
        EVAL_ASSERTION_SCHEMA_ID,
        LLM_JUDGE_EVALUATOR_KIND,
    )

    raise NotImplementedError(LLM_JUDGE_DEFERRED_MESSAGE)


__all__ = [
    "ACTIVE_EVALUATORS",
    "EVAL_ASSERTION_SCHEMA_ID",
    "LLM_JUDGE_DEFERRED_CODE",
    "LLM_JUDGE_DEFERRED_MESSAGE",
    "LLM_JUDGE_EVALUATOR_KIND",
    "list_active_evaluator_kinds",
    "llm_judge_evaluator",
]
