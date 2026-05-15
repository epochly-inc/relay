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

from relay_schemas.error_codes import RelayErrorCode

from .canonical import jcs_canonicalize
from .dsl_parser import ContractParseError, ParsedContract
from .errors import RelayCelError
from .evaluator import RelayCelEvaluator
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


def _walk_idents(node: Any) -> Iterable[str]:
    """Yield every IDENT token in a lark Tree (used for UDF discovery).

    cel-python returns a lark.Tree from Environment.compile; identifier
    leaves carry ``type == 'IDENT'``. We collect every IDENT name so the
    pipeline can pre-flight UDF presence at publish time.
    """
    if hasattr(node, "type") and getattr(node, "type", None) == "IDENT":
        yield str(node)
        return
    children = getattr(node, "children", None)
    if children is None:
        return
    for child in children:
        yield from _walk_idents(child)


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
    evaluator = RelayCelEvaluator(udfs=udfs)
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
    registered = {udf.name for udf in udfs}
    ast = evaluator._env.compile(expression)  # noqa: SLF001 -- internal AST access
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
    # Wrap each UDF callable so we can capture its return value for the
    # envelope without mutating the underlying PureUdf object.
    captured_outputs: dict[str, Any] = {}
    wrapped_udfs: list[PureUdf] = []
    from .udf import register_udf

    for udf in extra_udfs_tuple:
        original = udf.fn

        def _make_wrapper(name: str, fn: Any) -> Any:
            def _wrapper(*args: Any, **kwargs: Any) -> Any:
                result = fn(*args, **kwargs)
                captured_outputs[name] = result
                return result
            return _wrapper

        wrapped = register_udf(
            udf.name, _make_wrapper(udf.name, original), pure=True, arity=udf.arity
        )
        wrapped_udfs.append(wrapped)

    evaluator = RelayCelEvaluator(udfs=wrapped_udfs)
    expression: str = parsed.expression  # type: ignore[assignment]

    # Discover which UDF callees actually appear in the AST (not just
    # what the caller registered). udfs_invoked = registered ∩ AST.
    ast = evaluator._env.compile(expression)  # noqa: SLF001 -- internal AST access
    ast_callees = set(_walk_function_call_idents(ast))
    registered_names = {u.name for u in wrapped_udfs}
    udfs_invoked = sorted(ast_callees & registered_names)

    t0 = time.perf_counter()
    try:
        value = evaluator.evaluate(expression, dict(bindings or {}))
        outcome = _classify_outcome(value)
    except RelayCelError:
        outcome = "error"
        value = None
    wall_time_ms = (time.perf_counter() - t0) * 1000.0

    # Build a JCS-canonical JSON string of the captured UDF outputs.
    # Only includes the UDFs actually invoked during this evaluation.
    invoked_outputs = {name: captured_outputs.get(name) for name in udfs_invoked}
    udf_outputs_jcs_bytes = jcs_canonicalize(invoked_outputs)
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
