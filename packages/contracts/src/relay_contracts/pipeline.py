"""Relay contract DSL publish + runtime evaluation pipeline.

w6.4 ships two stages:

  - :func:`publish_contract` -- publish-time validation. For documents
    whose ``expression`` is a CEL string (behavioral / eval kinds with
    string expression), the parser MUST compile the expression through
    the Relay CEL profile (VAL-W6-042). Profile violations
    (``dyn(...)``, native ``timestamp``/``duration``, RE2-incompatible
    regex, malformed syntax, unregistered UDFs) are rejected at publish,
    not at first evaluation, with a ``RELAY-CONTRACT-004`` envelope
    identifying the offending ``assertion_id`` and ``cel_token``.

  - :func:`evaluate_assertion` -- runtime path. Evaluates the parsed
    expression and returns a structured outcome envelope binding:
    ``assertion_id``, ``expression_digest``, ``udfs_invoked``,
    ``udf_outputs_jcs``, ``wall_time_ms``, ``outcome`` in
    ``{pass, fail, error}``. Missing any field raises
    :class:`RelayContractOutcomeError` per VAL-W6-045 -- the outcome
    MUST NOT be treated as ``pass`` when its evidence is incomplete
    (CLAUDE.md keystone invariant 2).

M6 WS-I: the single wasm CEL engine is the only backend. ``udfs_invoked``
is derived from the engine's ``udf_trace`` forensic field (the RAN set,
VAL-CWC-P1HOST-014); the publish-time statically-referenced callee set
comes from the minimal host callee parser
(:mod:`relay_contracts.callee_parser`, ADR Revisions section 3); and
publish-time malformed-syntax rejection routes through the engine's
authoritative compiler via ``probe_compile``. No host-side CEL AST exists
anywhere on this path.

Spec anchors: D, B.4 (closed error envelope).
Eng plan anchors: CQ1 lines 145-157.
CLAUDE.md anchors: keystone invariant 2 (pass without evidence is not a
pass), keystone invariant 6 (UDF purity).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from typing import Any

from relay_schemas.error_codes import RelayErrorCode

from .callee_parser import extract_bare_callees
from .canonical import jcs_canonicalize
from .dsl_parser import ContractParseError, ParsedContract
from .engine import make_cel_evaluator
from .errors import (
    SUBTYPE_ENGINE_COMPILE,
    RelayCelEngineError,
    RelayCelError,
)
from .udf import PureUdf

# Required outcome envelope keys per VAL-W6-045.
_REQUIRED_OUTCOME_KEYS = (
    "assertion_id",
    "expression_digest",
    "udfs_invoked",
    "udf_outputs_jcs",
    "wall_time_ms",
    "outcome",
)


class RelayContractOutcomeError(Exception):
    """Raised when an outcome envelope is incomplete (VAL-W6-045).

    The runtime MUST surface this error rather than emit a partial
    envelope. CLAUDE.md keystone invariant 2: pass without evidence is
    not a pass; an envelope missing the binding fields is treated as
    invalid, not accepted.
    """

    def __init__(self, message: str, *, missing: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = RelayErrorCode.RELAY_CONTRACT_005
        self.missing = list(missing or [])


def _validate_outcome_envelope(envelope: Mapping[str, Any]) -> None:
    missing = [k for k in _REQUIRED_OUTCOME_KEYS if k not in envelope]
    if missing:
        raise RelayContractOutcomeError(
            f"Outcome envelope missing required fields: {missing}",
            missing=missing,
        )


# CEL builtin functions that are NOT UDFs and must be excluded from the
# "unregistered UDF" check at publish time. Anything else in
# function-call position is treated as a UDF -- if it's not in the
# evaluator's registered UDF set, publish raises RELAY-CONTRACT-004.
_CEL_BUILTIN_FUNCTIONS: frozenset[str] = frozenset({
    "size", "type", "contains", "endsWith", "startsWith", "matches",
    "getDate", "getDayOfMonth", "getDayOfWeek", "getDayOfYear",
    "getFullYear", "getMonth", "getHours", "getMilliseconds",
    "getMinutes", "getSeconds", "bool", "bytes", "double", "duration",
    "int", "list", "map", "null_type", "string", "timestamp", "uint",
    "has",
})


def publish_contract(
    parsed: ParsedContract,
    *,
    extra_udfs: Iterable[PureUdf] = (),
) -> None:
    """Publish-time validation (VAL-W6-042).

    For behavioral / eval kinds with a string ``expression``, validate via
    the Relay CEL profile. Profile violations, malformed syntax, and
    unregistered UDF calls are rejected here (not at first evaluate) with
    :class:`ContractParseError` carrying ``RELAY-CONTRACT-004`` plus a
    payload identifying ``assertion_id`` and the offending ``cel_token``.

    For documents whose body is a structured tree (D.1 op/args form, D.2
    JSON Schema body, D.4 args_schema, D.5 evaluator block, D.3 gate
    conditions) there is no CEL text to compile -- the parser already
    validated the envelope and digested the body.
    """

    # Only compile if the body field is "expression" AND it is a string.
    if parsed.body_field_name != "expression":
        return
    expression = parsed.expression
    if not isinstance(expression, str):
        return  # structured op/args tree -- no CEL compilation

    udfs = tuple(extra_udfs)
    # Construct via the engine factory (the ONLY RELAY_CEL_ENGINE read site is
    # engine.py; pipeline.py never reads the env). A caller-supplied
    # non-allowlist UDF is rejected fail-closed at construction
    # (RelayCelUnsupportedUdfError / RELAY-CEL-004-UDF-UNREGISTERED), which is
    # the correct publish-time rejection (VAL-CWC-P1HOST-016): the wasm hosts
    # only the 3 native relay.* UDFs and has no registration slot.
    evaluator = make_cel_evaluator(udfs=udfs)
    try:
        evaluator.compile(expression)
    except RelayCelError as exc:
        # Surface the structured CEL error (regex-backref pre-screen or the
        # static profile screen) as a contract publish error so the gate
        # runner sees the canonical RELAY-CONTRACT-004 code.
        raise ContractParseError(
            f"CEL profile violation in assertion {parsed.assertion_id!r}: "
            f"{exc.message}",
            code=RelayErrorCode.RELAY_CONTRACT_004,
            payload={
                "assertion_id": parsed.assertion_id,
                "cel_token": exc.subtype or exc.code,
                "cel_code": exc.code,
            },
        ) from exc

    # Malformed-syntax rejection routes through the WASM ENGINE ITSELF (the
    # authoritative compiler): probe_compile raises the structured
    # RELAY-CEL-009 / RELAY-CEL-ENGINE-COMPILE error for a compile-cause
    # engine envelope. Publish-time syntax rejection MUST be structured (the
    # M5 flip regression guard, bf4572c lineage): translate the engine
    # compile failure into the SAME ContractParseError / RELAY-CONTRACT-004
    # the legacy path produced. Non-compile probe causes (exec on the empty
    # probe bindings, request, panic, timeout) never raise here -- they are
    # deferred to evaluation by probe_compile itself. A late profile
    # rejection from the probe (defense in depth behind the static screen)
    # is wrapped as the profile-violation publish error above would be.
    try:
        evaluator.probe_compile(expression)
    except RelayCelEngineError as exc:
        if exc.subtype == SUBTYPE_ENGINE_COMPILE:
            raise ContractParseError(
                f"Malformed CEL syntax in assertion {parsed.assertion_id!r}: "
                f"{exc.message}",
                code=RelayErrorCode.RELAY_CONTRACT_004,
                payload={
                    "assertion_id": parsed.assertion_id,
                    "cel_token": "RELAY-CEL-SYNTAX",
                    "reason": "cel-parse-error",
                },
            ) from exc
        raise  # pragma: no cover -- probe_compile only raises compile/profile
    except RelayCelError as exc:
        raise ContractParseError(
            f"CEL profile violation in assertion {parsed.assertion_id!r}: "
            f"{exc.message}",
            code=RelayErrorCode.RELAY_CONTRACT_004,
            payload={
                "assertion_id": parsed.assertion_id,
                "cel_token": exc.subtype or exc.code,
                "cel_code": exc.code,
            },
        ) from exc

    # Pre-flight UDF presence: every BARE callee in function-call position
    # MUST be either a registered UDF or a CEL builtin. Anything else is
    # rejected at publish per VAL-W6-042 ("unregistered UDF MUST be rejected
    # at publish, not at first evaluation"). The callee set comes from the
    # minimal host callee parser (ADR Revisions section 3) -- the replacement
    # for the legacy AST walk; like that walk, it yields only BARE callees
    # (dotted relay.* calls are member calls and are validated by the engine
    # itself at evaluation).
    registered = {udf.name for udf in udfs}
    callees = extract_bare_callees(expression)
    unknown_callees = sorted(
        name for name in callees
        if name not in registered and name not in _CEL_BUILTIN_FUNCTIONS
    )
    if unknown_callees:
        raise ContractParseError(
            f"Unregistered UDF call(s) in assertion {parsed.assertion_id!r}: "
            f"{unknown_callees}",
            code=RelayErrorCode.RELAY_CONTRACT_004,
            payload={
                "assertion_id": parsed.assertion_id,
                "cel_token": unknown_callees[0],
                "unknown_callees": unknown_callees,
            },
        )


def _classify_outcome(value: Any) -> str:
    """Map a CEL evaluation result to {pass, fail, error}.

    A boolean True -> pass; False -> fail. Any non-boolean result is
    treated as ``error`` -- contract assertions MUST evaluate to bool;
    a non-bool result is a contract authoring bug, not a silent pass.

    The wasm codec decodes a CEL boolean to a native Python ``bool``
    (``wasm_codec.typed_to_py``), so the TYPE check (never truthiness
    coercion) is exactly ``isinstance(value, bool)``.
    """
    if isinstance(value, bool):
        return "pass" if value else "fail"
    return "error"


def _evaluate_with_trace(
    expression: str,
    extra_udfs: tuple[PureUdf, ...],
    bindings: Mapping[str, Any] | None,
) -> tuple[dict[str, list[Any]], list[str], str, float]:
    """Evaluate via the wasm engine; reconstruct outputs from ``udf_trace``.

    The evaluator surfaces ``udf_trace`` (a per-UDF-name list of
    typed-canonical values in CALL ORDER) directly from the wasm response, so
    there is NO host-side AST walk on the hot path (VAL-CWC-P1HOST-014).
    ``udfs_invoked`` is derived from the ``udf_trace`` keys (sorted --
    matching the wasm BTreeMap key order); ``udf_outputs`` is the trace
    itself (already typed-canonical), so the JCS bytes are the single
    typed-canonical contract (VAL-CWC-P1HOST-015).

    A caller-supplied non-allowlist UDF was already rejected at construction
    (the factory builds a ``WasmCelEvaluator`` which raises
    ``RelayCelUnsupportedUdfError`` -- the wasm has no registration slot). The
    3 native relay.* UDFs are baked into the wasm.
    """
    evaluator = make_cel_evaluator(udfs=extra_udfs)

    t0 = time.perf_counter()
    udf_trace: dict[str, list[Any]] = {}
    try:
        value, udf_trace = evaluator.evaluate_with_trace(
            expression, dict(bindings or {})
        )
        outcome = _classify_outcome(value)
    except RelayCelError:
        outcome = "error"
        udf_trace = {}
    wall_time_ms = (time.perf_counter() - t0) * 1000.0

    # udfs_invoked from the udf_trace keys (sorted); udf_outputs is the trace
    # (already a per-name list of typed-canonical values in call order).
    udfs_invoked = sorted(udf_trace.keys())
    udf_outputs = {name: udf_trace[name] for name in udfs_invoked}
    return udf_outputs, udfs_invoked, outcome, wall_time_ms


def evaluate_assertion(
    parsed: ParsedContract,
    *,
    bindings: Mapping[str, Any] | None = None,
    extra_udfs: Iterable[PureUdf] = (),
) -> dict[str, Any]:
    """Evaluate a parsed assertion at runtime; return outcome envelope.

    Envelope keys per VAL-W6-045:

      - ``assertion_id`` -- from the parsed document.
      - ``expression_digest`` -- from the parsed document
        (JCS-SHA-256 of the body field, see :class:`ParsedContract`).
      - ``udfs_invoked`` -- sorted list of UDF names that actually RAN
        (the engine ``udf_trace`` keys; a short-circuited branch is never
        recorded).
      - ``udf_outputs_jcs`` -- JCS-canonical JSON string of
        ``{udf_name: [typed-canonical return values in call order]}`` for
        the invoked UDFs. Pure UDFs (the only allowed kind) make this
        deterministic.
      - ``wall_time_ms`` -- evaluator wall-clock time in milliseconds.
      - ``outcome`` -- one of ``pass``, ``fail``, ``error``.

    For non-evaluable kinds (schema_contract, tool_arg, gate_policy,
    eval) the runtime MUST be invoked through the per-kind evaluator
    in W6.5+. This function is the CEL-driven path used by behavioral
    assertions with a string expression. Calling it on other kinds
    raises ``RelayContractOutcomeError``.

    Engine selection lives in the factory (engine.py -- the ONLY
    RELAY_CEL_ENGINE read site). pipeline.py NEVER reads the env var
    (preserving the VAL-W8-005 / VAL-CWC-P4DUALRUN-008 determinism grep).
    """

    if parsed.body_field_name != "expression" or not isinstance(parsed.expression, str):
        raise RelayContractOutcomeError(
            f"evaluate_assertion only supports CEL-string expressions; "
            f"assertion {parsed.assertion_id!r} kind {parsed.kind!r} "
            f"requires a kind-specific evaluator."
        )

    extra_udfs_tuple = tuple(extra_udfs)
    expression: str = parsed.expression  # type: ignore[assignment]

    udf_outputs, udfs_invoked, outcome, wall_time_ms = _evaluate_with_trace(
        expression, extra_udfs_tuple, bindings
    )

    # Single typed-canonical contract for udf_outputs_jcs
    # (VAL-CWC-P1HOST-015): ``udf_outputs`` is a per-UDF-name list of
    # typed-canonical ``{"t":...,"v":...}`` entries in call order, so the JCS
    # bytes are deterministic for the same logical outputs.
    udf_outputs_jcs_bytes = jcs_canonicalize(udf_outputs)
    udf_outputs_jcs_str = udf_outputs_jcs_bytes.decode("utf-8")

    envelope: dict[str, Any] = {
        "assertion_id": parsed.assertion_id,
        "expression_digest": parsed.expression_digest,
        "udfs_invoked": udfs_invoked,
        "udf_outputs_jcs": udf_outputs_jcs_str,
        "wall_time_ms": wall_time_ms,
        "outcome": outcome,
    }
    _validate_outcome_envelope(envelope)
    return envelope


__all__ = [
    "RelayContractOutcomeError",
    "evaluate_assertion",
    "publish_contract",
]
