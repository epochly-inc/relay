"""Relay contract DSL publish + runtime evaluation pipeline.

w6.4 ships two stages:

  - :func:`publish_contract` -- publish-time validation. For documents
    whose ``expression`` is a CEL string (behavioral / eval kinds with
    string expression), the parser MUST compile the expression through
    the Relay CEL profile (VAL-W6-042). Profile violations
    (``dyn(...)``, native ``timestamp``/``duration``, RE2-incompatible
    regex, unregistered UDFs) are rejected at publish, not at first
    evaluation, with a ``RELAY-CONTRACT-004`` envelope identifying the
    offending ``assertion_id`` and ``cel_token``.

  - :func:`evaluate_assertion` -- runtime path. Evaluates the parsed
    expression and returns a structured outcome envelope binding:
    ``assertion_id``, ``expression_digest``, ``udfs_invoked``,
    ``udf_outputs_jcs``, ``wall_time_ms``, ``outcome`` in
    ``{pass, fail, error}``. Missing any field raises
    :class:`RelayContractOutcomeError` per VAL-W6-045 -- the outcome
    MUST NOT be treated as ``pass`` when its evidence is incomplete
    (CLAUDE.md keystone invariant 2).

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

from celpy.celparser import CELParseError
from relay_schemas.error_codes import RelayErrorCode

from .canonical import jcs_canonicalize
from .dsl_parser import ContractParseError, ParsedContract
from .engine import make_cel_evaluator
from .errors import RelayCelError
from .udf import PureUdf
from .wasm_codec import py_to_typed

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


def _walk_function_call_idents(node: Any) -> Iterable[str]:
    """Yield IDENT names that appear in a function-call position.

    cel-python's grammar exposes ``ident_arg`` nodes for ``ident(args)``
    and ``member_dot_arg`` for ``x.method(args)``. We surface only the
    callee identifier; bare-name references (variable lookups) are NOT
    UDF calls and must not be flagged as such.
    """
    data = getattr(node, "data", None)
    if data == "ident_arg":
        for c in node.children:
            if hasattr(c, "type") and getattr(c, "type", None) == "IDENT":
                yield str(c)
                break
    children = getattr(node, "children", None) or []
    for child in children:
        yield from _walk_function_call_idents(child)


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

    For behavioral / eval kinds with a string ``expression``, compile via
    the Relay CEL profile. Profile violations and unregistered UDF calls
    are rejected here (not at first evaluate) with
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
    # engine.py; pipeline.py never reads the env). On the wasm engine a
    # caller-supplied non-allowlist UDF is rejected fail-closed at construction
    # (RelayCelUnsupportedUdfError / RELAY-CEL-004-UDF-UNREGISTERED), which is
    # the correct publish-time rejection on that path (VAL-CWC-P1HOST-016): the
    # wasm hosts only the 3 native relay.* UDFs and has no registration slot.
    evaluator = make_cel_evaluator(udfs=udfs)
    try:
        compiled = evaluator.compile(expression)
    except RelayCelError as exc:
        # Surface the structured CEL error as a contract publish error
        # so the gate runner sees the canonical RELAY-CONTRACT-004 code.
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

    # Pre-flight UDF presence: every callee in function-call position
    # MUST be either a registered UDF or a CEL builtin. Anything else
    # is rejected at publish per VAL-W6-042 ("unregistered UDF MUST be
    # rejected at publish, not at first evaluation").
    #
    # This reparse obtains the celpy AST for the callee walk. It runs OUTSIDE
    # the ``evaluator.compile`` structured-error translation above, so a
    # MALFORMED-SYNTAX expression -- which the wasm host pre-screens do NOT
    # full-parse (WasmCelEvaluator.compile returns the expression unchanged on
    # a celpy parse failure, deferring to the wasm's authoritative compiler) --
    # raises a RAW celpy ``CELParseError`` here. Under the celpy engine
    # ``RelayCelEvaluator.compile`` already wraps that parse failure into a
    # structured ``RelayCelError`` caught above; under the wasm default the raw
    # error would leak. Publish-time syntax rejection MUST be engine-invariant
    # (M5 flip regression bf4572c), so translate the celpy parse failure into
    # the SAME structured ``ContractParseError`` / RELAY-CONTRACT-004 the celpy
    # path produces -- consistent with the other publish-time raises here.
    registered = {udf.name for udf in udfs}
    try:
        ast = evaluator._env.compile(expression)  # noqa: SLF001 -- internal AST access
    except CELParseError as exc:
        raise ContractParseError(
            f"Malformed CEL syntax in assertion {parsed.assertion_id!r}: "
            f"{exc}",
            code=RelayErrorCode.RELAY_CONTRACT_004,
            payload={
                "assertion_id": parsed.assertion_id,
                "cel_token": "RELAY-CEL-SYNTAX",
                "reason": "cel-parse-error",
            },
        ) from exc
    callees = set(_walk_function_call_idents(ast))
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

    _ = compiled  # compilation cached on the evaluator instance


def _classify_outcome(value: Any) -> str:
    """Map a CEL evaluation result to {pass, fail, error}.

    A boolean True -> pass; False -> fail. Any non-boolean result is
    treated as ``error`` -- contract assertions MUST evaluate to bool;
    a non-bool result is a contract authoring bug, not a silent pass.

    cel-python returns ``celpy.celtypes.BoolType`` (subclass of int, NOT
    bool), so we accept both Python bool and the cel-python BoolType.
    Detection is by class-name to avoid importing celtypes here -- the
    pipeline is intentionally decoupled from the evaluator's internals.
    """
    if isinstance(value, bool):
        return "pass" if value else "fail"
    if type(value).__name__ == "BoolType":
        return "pass" if int(value) == 1 else "fail"
    return "error"


def _evaluate_celpy_path(
    expression: str,
    extra_udfs: tuple[PureUdf, ...],
    bindings: Mapping[str, Any] | None,
) -> tuple[dict[str, list[Any]], list[str], str, float]:
    """Evaluate via the cel-python engine; capture UDF outputs typed-canonical.

    Wraps each UDF callable to capture its return value PER INVOCATION in
    CEL-evaluation order (Round-3 P1 fix #3: a UDF may be called multiple
    times in one expression; every call is recorded, not just the last). The
    captured raw cel-python results are converted to the wasm typed-canonical
    ``{"t":...,"v":...}`` form via ``py_to_typed`` so the celpy and wasm
    ``udf_outputs_jcs`` bytes are IDENTICAL (VAL-CWC-P1HOST-015: typed-canonical
    is the single contract).

    ``udfs_invoked`` is derived from the UDF names that ACTUALLY fired (the
    wrapper-capture keys), matching the wasm path's "derive from udf_trace
    keys" semantics -- not from an AST walk. This also fixes dotted-name UDFs
    (``relay.coverage``) that the bare-IDENT AST walk could not detect as
    callees. The list is sorted (the existing contract semantics and the wasm
    BTreeMap key order agree on alphabetical order).

    The capture closure is scoped to THIS call (no process global); concurrent
    evaluations on different threads each get their own ``captured_outputs``.
    """
    from .udf import register_udf

    captured_outputs: dict[str, list[Any]] = {}
    wrapped_udfs: list[PureUdf] = []

    for udf in extra_udfs:
        original = udf.fn

        def _make_wrapper(name: str, fn: Any) -> Any:
            def _wrapper(*args: Any, **kwargs: Any) -> Any:
                result = fn(*args, **kwargs)
                # Convert eagerly to typed-canonical so the per-name list is
                # the SAME shape the wasm udf_trace carries (byte-parity).
                captured_outputs.setdefault(name, []).append(py_to_typed(result))
                return result
            return _wrapper

        wrapped = register_udf(
            udf.name, _make_wrapper(udf.name, original), pure=True, arity=udf.arity
        )
        wrapped_udfs.append(wrapped)

    evaluator = make_cel_evaluator(udfs=wrapped_udfs)

    t0 = time.perf_counter()
    try:
        value = evaluator.evaluate(expression, dict(bindings or {}))
        outcome = _classify_outcome(value)
    except RelayCelError:
        outcome = "error"
    wall_time_ms = (time.perf_counter() - t0) * 1000.0

    # udfs_invoked / udf_outputs from the UDFs that actually fired, in sorted
    # name order. A short-circuited UDF branch never fires the wrapper, so it
    # is not recorded -- consistent with the wasm udf_trace (never records a
    # short-circuited call).
    udfs_invoked = sorted(captured_outputs.keys())
    udf_outputs = {name: captured_outputs[name] for name in udfs_invoked}
    return udf_outputs, udfs_invoked, outcome, wall_time_ms


def _evaluate_wasm_path(
    expression: str,
    extra_udfs: tuple[PureUdf, ...],
    bindings: Mapping[str, Any] | None,
) -> tuple[dict[str, list[Any]], list[str], str, float]:
    """Evaluate via the wasm engine; reconstruct outputs from ``udf_trace``.

    The wasm evaluator surfaces ``udf_trace`` (a per-UDF-name list of
    typed-canonical values in CALL ORDER) directly from the wasm response, so
    there is NO cel-python ``_env`` AST walk on the wasm hot path
    (VAL-CWC-P1HOST-014). ``udfs_invoked`` is derived from the ``udf_trace``
    keys (sorted -- matching the wasm BTreeMap key order and the celpy path's
    sorted semantics); ``udf_outputs`` is the trace itself (already
    typed-canonical), so the JCS bytes match the celpy path byte-for-byte.

    A caller-supplied non-allowlist UDF was already rejected at construction
    (the factory builds a ``WasmCelEvaluator`` which raises
    ``RelayCelUnsupportedUdfError`` -- the wasm has no registration slot). The
    3 native relay.* UDFs are baked into the wasm.
    """
    evaluator = make_cel_evaluator(udfs=extra_udfs)
    # Detected via capability in the caller; assert the method exists so a
    # mis-detection is a loud failure rather than a silent wrong-path eval.
    evaluate_with_trace = evaluator.evaluate_with_trace  # type: ignore[attr-defined]

    t0 = time.perf_counter()
    udf_trace: dict[str, list[Any]] = {}
    try:
        value, udf_trace = evaluate_with_trace(expression, dict(bindings or {}))
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
      - ``udfs_invoked`` -- sorted list of UDF names referenced in the
        expression's call positions (intersection with ``extra_udfs``).
      - ``udf_outputs_jcs`` -- JCS-canonical JSON string of
        ``{udf_name: udf_return_value}`` for the invoked UDFs. Captured
        via wrapper functions; pure UDFs (the only allowed kind) make
        this deterministic.
      - ``wall_time_ms`` -- evaluator wall-clock time in milliseconds.
      - ``outcome`` -- one of ``pass``, ``fail``, ``error``.

    For non-evaluable kinds (schema_contract, tool_arg, gate_policy,
    eval) the runtime MUST be invoked through the per-kind evaluator
    in W6.5+. This function is the CEL-driven path used by behavioral
    assertions with a string expression. Calling it on other kinds
    raises ``RelayContractOutcomeError``.
    """

    if parsed.body_field_name != "expression" or not isinstance(parsed.expression, str):
        raise RelayContractOutcomeError(
            f"evaluate_assertion only supports CEL-string expressions; "
            f"assertion {parsed.assertion_id!r} kind {parsed.kind!r} "
            f"requires a kind-specific evaluator."
        )

    extra_udfs_tuple = tuple(extra_udfs)
    expression: str = parsed.expression  # type: ignore[assignment]

    # Engine selection lives in the factory (engine.py -- the ONLY
    # RELAY_CEL_ENGINE read site). pipeline.py NEVER reads the env var; it
    # detects the active path by the evaluator's CAPABILITY, not by ambient
    # process state (preserving the VAL-W8-005 / VAL-CWC-P4DUALRUN-008
    # determinism grep). The wasm evaluator exposes ``evaluate_with_trace``
    # (it can surface the wasm ``udf_trace`` response field); the celpy
    # evaluator does not, so ``hasattr`` discriminates the two paths without
    # importing either concrete class here.
    #
    # On the wasm engine, a caller-supplied non-allowlist UDF is rejected
    # fail-closed at construction (RelayCelUnsupportedUdfError /
    # RELAY-CEL-004-UDF-UNREGISTERED) -- the wasm hosts only the 3 native
    # relay.* UDFs (VAL-CWC-P1HOST-016). The 3 native relay.* UDFs are
    # accepted on both engines.
    if hasattr(make_cel_evaluator(udfs=()), "evaluate_with_trace"):
        udf_outputs, udfs_invoked, outcome, wall_time_ms = (
            _evaluate_wasm_path(expression, extra_udfs_tuple, bindings)
        )
    else:
        udf_outputs, udfs_invoked, outcome, wall_time_ms = (
            _evaluate_celpy_path(expression, extra_udfs_tuple, bindings)
        )

    # Single typed-canonical contract for udf_outputs_jcs across BOTH engines
    # (VAL-CWC-P1HOST-015): ``udf_outputs`` is already a per-UDF-name list of
    # typed-canonical ``{"t":...,"v":...}`` entries in call order on either
    # path, so the JCS bytes are byte-identical for the same logical outputs.
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
