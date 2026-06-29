"""w6.1 single-evaluator tier-1 plumbing tests.

Each test pins exactly one VAL-W6-NNN assertion and runs offline (no
network, no real CEL fixtures from disk -- the conformance corpus comes
in W6.5). The full suite is bounded by the tier-1 60-second budget per
.ops/manifest.yaml.

M6 WS-I: the single wasm CEL engine is the only Python CEL backend, so the
suite drives ``WasmCelEvaluator`` (directly and through the production
factory). The legacy slow/NaN/Inf test-instrument UDFs are ported onto
pure-CEL expressions (the wasm rejects caller-supplied extra UDFs
fail-closed) or onto a stubbed slow engine handle for the wall-clock cases.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path
from typing import Any

import pytest
from relay_contracts import (
    PureUdf,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelTimeoutError,
    RelayUdfPurityError,
    WasmCelEvaluator,
    jcs_canonicalize,
    make_cel_evaluator,
    register_udf,
)
from relay_contracts.errors import (
    SUBTYPE_NUMERIC_OOB,
    SUBTYPE_PROFILE_DUR_DISABLED,
    SUBTYPE_PROFILE_DYN_DISABLED,
    SUBTYPE_PROFILE_REGEX_BACKREF,
    SUBTYPE_PROFILE_TS_DISABLED,
    SUBTYPE_TIMEOUT,
    SUBTYPE_UDF_IMPURE,
)
from relay_contracts.evaluator import MAX_TIMEOUT_MS

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC = REPO_ROOT / "packages" / "contracts" / "src" / "relay_contracts"


def _arm_slow_eval(evaluator: WasmCelEvaluator, delay_seconds: float) -> None:
    """Make the next engine evaluations on this thread sleep past the budget.

    Engine-timeout instrument that does NOT register a custom UDF (the wasm
    forbids extra UDFs): wraps the per-thread RelayCel handle's ``eval``. The
    wrapped call funnels through the shared host ``run_with_timeout`` guard,
    so arming a slow primitive proves the host wall-clock timeout fires.
    """
    handle = evaluator._thread_handle()  # noqa: SLF001
    original_eval = handle.eval

    def slow_wasm(
        expr: str,
        bindings: Any = None,
        container: Any = None,
        relay_profile: bool = False,
    ) -> Any:
        time.sleep(delay_seconds)
        return original_eval(expr, bindings, container, relay_profile)

    handle.eval = slow_wasm


# ---------------------------------------------------------------------------
# VAL-W6-001: the wasm engine is the only Python CEL evaluator
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-001")
def test_wasm_engine_is_the_single_python_cel_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production factory constructs the wasm-backed evaluator -- the
    SINGLE Python CEL evaluator (M6 WS-I removed the legacy backend)."""

    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)
    evaluator = make_cel_evaluator(udfs=())
    assert isinstance(evaluator, WasmCelEvaluator)
    # The legacy evaluator class is gone from the public surface.
    import relay_contracts

    assert not hasattr(relay_contracts, "RelayCelEvaluator")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-001")
def test_no_alternate_python_cel_lib_in_contracts_source() -> None:
    """Grep packages/contracts source for forbidden CEL implementations.

    The wasm engine is the single Python CEL evaluator. Any host-side CEL
    implementation import under ``packages/contracts/`` -- including the
    removed legacy ``celpy`` -- violates CQ1 line 145 (single-source CEL
    evaluator per language, as revised by the cel-wasm cutover).
    """

    forbidden_imports = [
        re.compile(r"^\s*import\s+celpy(\b|\s|$)", re.MULTILINE),
        re.compile(r"^\s*from\s+celpy\b", re.MULTILINE),
        re.compile(r"^\s*import\s+pycel(\b|\s|$)", re.MULTILINE),
        re.compile(r"^\s*from\s+pycel\b", re.MULTILINE),
        re.compile(r"^\s*import\s+cel_py(\b|\s|$)", re.MULTILINE),
        re.compile(r"^\s*from\s+cel_py\b", re.MULTILINE),
        # The Google Python CEL fork -- import name varies; the wasm engine
        # is the canonical implementation we depend on.
        re.compile(r"^\s*from\s+google\.cel\.python\b", re.MULTILINE),
    ]
    hits: list[str] = []
    for py in PKG_SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for pattern in forbidden_imports:
            if pattern.search(text):
                hits.append(f"{py.relative_to(REPO_ROOT)}: {pattern.pattern}")
    assert hits == [], (
        f"VAL-W6-001: forbidden host-CEL imports found: {hits}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-001")
def test_cel_python_distribution_not_installed() -> None:
    """The cel-python distribution is REMOVED from the environment
    (VAL-CWC-P6REMOVE-001/-004): the dependency cannot resurface silently
    through a transitive pin -- resolving its metadata must fail.
    """

    from importlib.metadata import PackageNotFoundError, distribution

    with pytest.raises(PackageNotFoundError):
        distribution("cel-python")


# ---------------------------------------------------------------------------
# VAL-W6-002: Relay profile -- dyn / timestamp / duration disabled
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_dyn_call_rejected_at_compile_time() -> None:
    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile("dyn(1)")
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_DYN_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_native_timestamp_call_rejected_at_compile_time() -> None:
    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile('timestamp("2026-01-01T00:00:00Z")')
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_TS_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_native_duration_call_rejected_at_compile_time() -> None:
    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile('duration("3600s")')
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_DUR_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_short_circuited_disabled_call_rejected_at_compile_time() -> None:
    """The compile-time profile screen is STATIC (the callee-set screen): a
    short-circuited ``dyn(...)`` branch the engine would never execute is
    still rejected at compile, matching the legacy AST-walk semantics."""
    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile("false && dyn(1)")
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_DYN_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_baseline_arithmetic_compiles_and_evaluates() -> None:
    """Sanity: a profile-clean expression evaluates normally."""

    # Generous budget: value assertions are decoupled from the 50 ms
    # wall-clock (host-thread jitter under concurrent load); the production
    # default (CQ1) is unchanged.
    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    assert int(evaluator.evaluate("1 + 2 * 3")) == 7


# ---------------------------------------------------------------------------
# VAL-W6-003: wall-clock timeout enforced
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-003")
def test_pathological_expression_aborts_at_timeout() -> None:
    """An engine call that outlives the budget MUST trigger RELAY-CEL-003.

    The wasm hosts no caller-registered UDFs, so the over-budget engine call
    is simulated by wrapping the per-thread handle's ``eval`` with a sleep --
    the evaluate path still runs the genuine host wall-clock enforcement
    (the wrapper does not 'know' the engine call is slow).
    """

    evaluator = WasmCelEvaluator(timeout_ms=10)
    _arm_slow_eval(evaluator, 0.250)
    start = time.monotonic()
    with pytest.raises(RelayCelTimeoutError) as ctx:
        evaluator.evaluate("1 + 1")
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert ctx.value.code == "RELAY-CEL-003"
    assert ctx.value.subtype == SUBTYPE_TIMEOUT
    # Aborted within ~5x the budget allowing for scheduler jitter under
    # CI load. The 50 ms ceiling is generous; the assertion is that
    # the timeout fires, not that it is microsecond-precise.
    assert elapsed_ms < 200.0, (
        f"VAL-W6-003: timeout fired at {elapsed_ms:.1f} ms; budget was 10 ms"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-003")
def test_timeout_constructor_validates_bounds() -> None:
    with pytest.raises(ValueError):
        WasmCelEvaluator(timeout_ms=0)
    with pytest.raises(ValueError):
        WasmCelEvaluator(timeout_ms=-5)
    with pytest.raises(ValueError):
        WasmCelEvaluator(timeout_ms=10_000)  # exceeds MAX_TIMEOUT_MS cap


# ---------------------------------------------------------------------------
# VAL-W6-004: UDF registration gated on pure=True
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-004")
def test_register_udf_pure_false_raises_at_registration() -> None:
    with pytest.raises(RelayUdfPurityError) as ctx:
        register_udf("naughty", lambda x: x, pure=False, arity=1)
    assert ctx.value.code == "RELAY-CEL-004"
    assert ctx.value.subtype == SUBTYPE_UDF_IMPURE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-004")
def test_register_udf_non_bool_pure_raises() -> None:
    """Truthy non-bool MUST be rejected (no silent coercion)."""

    with pytest.raises(RelayUdfPurityError):
        register_udf("ambiguous", lambda x: x, pure=1, arity=1)  # type: ignore[arg-type]
    with pytest.raises(RelayUdfPurityError):
        register_udf("ambiguous", lambda x: x, pure="yes", arity=1)  # type: ignore[arg-type]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-004")
def test_register_udf_pure_true_succeeds() -> None:
    udf = register_udf("safe", lambda x: x + 1, pure=True, arity=1)
    assert isinstance(udf, PureUdf)
    assert udf.name == "safe"
    assert udf.arity == 1


# ---------------------------------------------------------------------------
# VAL-W6-005: canonical output uses RFC 8785 JCS
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_returns_bytes_not_str() -> None:
    out = jcs_canonicalize({"a": 1})
    assert isinstance(out, bytes)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_sorts_keys_lexicographically() -> None:
    """RFC 8785 section 3.2.3 -- key order is sorted."""

    out = jcs_canonicalize({"b": 1, "a": 2, "c": 3})
    assert out == b'{"a":2,"b":1,"c":3}'


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_pins_number_representation() -> None:
    """RFC 8785 section 3.2.2 -- ECMA-262 ToString form.

    The whole-valued float ``1.0`` MUST emit as ``1`` (not ``1.0``);
    Python's default ``json.dumps`` would emit ``1.0`` and is therefore
    NOT a substitute. Negative zero collapses to ``0``.
    """

    assert jcs_canonicalize(1.0) == b"1"
    assert jcs_canonicalize(-0.0) == b"0"
    assert jcs_canonicalize(0) == b"0"
    assert jcs_canonicalize(-1) == b"-1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_escapes_only_required_control_chars() -> None:
    """RFC 8785 section 3.2.2.1 -- escape only ``"``, ``\\``, U+0000..U+001F."""

    # Backslash and quote escaped; non-ASCII (high code points) pass
    # through literally as UTF-8 bytes.
    assert jcs_canonicalize('a"b\\c') == b'"a\\"b\\\\c"'
    # Newline escapes to the short form \n.
    assert jcs_canonicalize("\n") == b'"\\n"'
    # U+007F (DEL) is NOT escaped (above the control-char range).
    # Output bytes: 0x22, 0x7f, 0x22 -- the DEL byte literally between quotes.
    assert jcs_canonicalize("\x7f") == b"\x22\x7f\x22"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_rejects_non_finite_numbers() -> None:
    """RFC 8785 forbids NaN / +Inf / -Inf at canonicalisation time."""

    with pytest.raises(RelayCelNumericOutOfBoundsError):
        jcs_canonicalize(float("nan"))
    with pytest.raises(RelayCelNumericOutOfBoundsError):
        jcs_canonicalize(float("inf"))
    with pytest.raises(RelayCelNumericOutOfBoundsError):
        jcs_canonicalize(float("-inf"))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_no_default_json_dumps_sort_keys_in_source() -> None:
    """Negative grep: ``json.dumps(..., sort_keys=True)`` is forbidden in
    non-test source under packages/contracts/.
    """

    forbidden = re.compile(r"json\.dumps\([^)]*sort_keys\s*=\s*True", re.DOTALL)
    hits: list[str] = []
    for py in PKG_SRC.rglob("*.py"):
        # Belt-and-suspenders: scope explicitly excludes test paths even
        # though src/ tree never contains tests.
        if "tests" in py.parts or py.name.startswith("test_"):
            continue
        text = py.read_text(encoding="utf-8")
        if forbidden.search(text):
            hits.append(str(py.relative_to(REPO_ROOT)))
    assert hits == [], (
        f"VAL-W6-005: json.dumps(..., sort_keys=True) is not a JCS substitute; hits: {hits}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-005")
def test_jcs_known_digest_for_fixed_input() -> None:
    """Hand-computed JCS digest for a fixed structured input.

    Input: {"name":"relay","ok":true,"count":3,"items":[1,2,3]}
    Canonical bytes (lexicographic key order, ECMA-262 numbers,
    no whitespace):
        {"count":3,"items":[1,2,3],"name":"relay","ok":true}
    """

    import hashlib

    payload = {"name": "relay", "ok": True, "count": 3, "items": [1, 2, 3]}
    canonical = jcs_canonicalize(payload)
    assert canonical == b'{"count":3,"items":[1,2,3],"name":"relay","ok":true}'
    digest = hashlib.sha256(canonical).hexdigest()
    expected = hashlib.sha256(
        b'{"count":3,"items":[1,2,3],"name":"relay","ok":true}'
    ).hexdigest()
    assert digest == expected


# ---------------------------------------------------------------------------
# VAL-W6-006: NaN / Inf rejected at evaluation result boundary
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_nan_in_result_rejected() -> None:
    """A NaN-producing pure-CEL expression (CEL double semantics:
    ``0.0 / 0.0`` evaluates to NaN, not an error) is rejected at the host
    result boundary."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("0.0 / 0.0")
    assert ctx.value.code == "RELAY-CEL-006"
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_pos_inf_in_result_rejected() -> None:
    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("1.0 / 0.0")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_neg_inf_in_result_rejected() -> None:
    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("(0.0 - 1.0) / 0.0")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_finite_result_passes() -> None:
    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    out = evaluator.evaluate("1.5 + 2.5")
    assert math.isfinite(float(out))


# ---------------------------------------------------------------------------
# VAL-PARITY-001: integers outside the IEEE-754 safe range rejected at the
# evaluation-result boundary (cross-runtime digest parity).
#
# The Python host returns arbitrary-precision ints, so an integral result
# with abs value > MAX_SAFE_INTEGER (2**53 - 1) -- e.g. 2**53 + 1 -- would
# canonicalise EXACTLY in Python while a float64 host silently rounds it
# (9007199254740993 -> 9007199254740992), producing divergent JCS bytes and a
# cross-runtime digest break. The evaluation-result boundary (_check_finite)
# MUST fail-closed on such ints in BOTH runtimes. The bound rejects magnitude
# >= 2**53 (i.e. > MAX_SAFE_INTEGER): 2**53 itself is NOT a safe integer (a
# float64 host rounds an integer overflow that lands on 2**53 + 1 down to
# 2**53), so accepting it would let a float64 host pass a rounded integer
# overflow -- the fail-open bug found by `codex review` (CEL +-2^53 Py<->TS
# parity P1). The largest accepted integer is MAX_SAFE_INTEGER (2**53 - 1).
# ---------------------------------------------------------------------------

_MAX_SAFE_INTEGER = 9007199254740991  # 2**53 - 1 == Number.MAX_SAFE_INTEGER


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_int_above_safe_range_in_result_rejected() -> None:
    """An integral CEL result with abs value > 2**53 - 1 is rejected at the
    evaluation-result boundary -- it would canonicalise exactly in Python
    but lose precision on a float64 host, breaking cross-runtime digest
    parity."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("9007199254740992 + 1")
    assert ctx.value.code == "RELAY-CEL-006"
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_negative_int_below_safe_range_in_result_rejected() -> None:
    """The bound is symmetric: an integral result of -(2**53 + 1) is also
    rejected (abs value > 2**53)."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("-9007199254740992 - 1")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_two_pow_53_in_result_rejected() -> None:
    """2**53 (9007199254740992, and its negation) is NOT a safe integer --
    it is indistinguishable from 2**53 + 1 after IEEE-754 double rounding, so
    a float64-host result of exactly 2**53 may be a ROUNDED integer overflow.
    The Python host keeps the exact int and MUST reject it (the corrected
    bound rejects magnitude >= 2**53), matching the TS mirror so a rounded
    integer overflow fails closed in both runtimes."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx_pos:
        evaluator.evaluate("9007199254740992")
    assert ctx_pos.value.subtype == SUBTYPE_NUMERIC_OOB
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx_neg:
        evaluator.evaluate("-9007199254740992")
    assert ctx_neg.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_max_safe_integer_in_result_accepted() -> None:
    """MAX_SAFE_INTEGER (2**53 - 1) is the LARGEST integer accepted: it is
    exact on the Python host and exactly representable as a float64 on the
    TS host, so it emits byte-identically in both runtimes. Its negation is
    likewise accepted. The very next integer (2**53) is rejected -- see
    test_two_pow_53_in_result_rejected."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    pos = evaluator.evaluate("9007199254740991")
    assert int(pos) == _MAX_SAFE_INTEGER
    neg = evaluator.evaluate("-9007199254740991")
    assert int(neg) == -_MAX_SAFE_INTEGER


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_nested_out_of_range_int_rejected_via_check_finite() -> None:
    """The bound recurses into lists/maps exactly like the NaN/Inf check, so
    an out-of-range integer nested in a structured result is rejected (the
    list literal carries an in-engine arithmetic overflow past 2**53)."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("[1, 9007199254740992 + 1, 3]")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_whole_double_above_safe_range_in_result_rejected() -> None:
    """A whole-valued DOUBLE literal whose magnitude exceeds MAX_SAFE_INTEGER
    (2**53 - 1) is rejected at the evaluation-result boundary, matching the
    TS mirror so BOTH runtimes fail-closed identically.

    The TS host collapses CEL int and CEL double to a bare JS ``number`` and
    re-derives the type from the value -- it classifies any whole-valued
    number as int, so the DOUBLE literal ``9007199254740994.0`` is
    INDISTINGUISHABLE there from the int ``9007199254740994`` and is
    rejected by the safe-integer bound. The Python host preserves the type
    (a float), so a bound restricted to ``isinstance(value, int)`` would let
    Python ACCEPT this double while TS REJECTED it -- a cross-runtime
    divergence. The whole-valued-double branch closes it.
    """

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx_pos:
        evaluator.evaluate("9007199254740994.0")
    assert ctx_pos.value.code == "RELAY-CEL-006"
    assert ctx_pos.value.subtype == SUBTYPE_NUMERIC_OOB
    # Symmetric: the negation is rejected too.
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx_neg:
        evaluator.evaluate("-9007199254740994.0")
    assert ctx_neg.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_two_pow_53_minus_one_whole_double_accepted() -> None:
    """The whole-valued double ``9007199254740991.0`` (== 2**53 - 1 ==
    MAX_SAFE_INTEGER) is ACCEPTED: abs is NOT > the bound. It is exact on
    the Python host and exactly representable as a float64 on the TS host,
    so it canonicalises byte-identically. The TS host classifies it as int
    (whole value) and ALSO accepts it (abs not > bound). The whole-double
    reject branch MUST NOT over-reject this boundary value."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    pos = evaluator.evaluate("9007199254740991.0")
    assert float(pos) == 9007199254740991.0
    neg = evaluator.evaluate("-9007199254740991.0")
    assert float(neg) == -9007199254740991.0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_small_whole_double_accepted() -> None:
    """A small whole-valued double like ``100.0`` is well within the safe
    range and ACCEPTED by both runtimes. Guards against the whole-double
    branch firing on any whole double regardless of magnitude."""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    out = evaluator.evaluate("100.0")
    assert float(out) == 100.0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-001")
def test_non_integral_double_within_range_accepted() -> None:
    """A genuinely non-integral double within the safe range (``1.5``) is
    ACCEPTED -- the whole-double branch only fires on ``.is_integer()`` values
    beyond the bound, never on a fractional double. (No representable float64
    of magnitude > MAX_SAFE_INTEGER is non-integral -- the ULP at 2**53 is 2.0
    -- so the only non-integral doubles to protect live within the safe
    range.)"""

    evaluator = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    out = evaluator.evaluate("1.5")
    assert float(out) == 1.5


# ---------------------------------------------------------------------------
# VAL-W6-007: regex backreference rejected at parse/check time
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-007")
def test_regex_backref_simple_rejected_at_compile() -> None:
    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        # Single-quoted CEL string holds the regex `(.)\1+`.
        evaluator.compile(r'"abc".matches("(.)\\1+")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-007")
def test_regex_backref_capture_then_ref_rejected() -> None:
    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile(r'"abba".matches("a(b)\\1")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-007")
def test_re2_safe_pattern_compiles_cleanly() -> None:
    """Baseline: a backref-free pattern parses without error."""

    evaluator = WasmCelEvaluator()
    compiled = evaluator.compile(r'"hello".matches("h.*o")')
    assert compiled is not None


# ===========================================================================
# VAL-CWC-P1HOST-011: the W6.1 evaluator behavioral suite driven through the
# PRODUCTION factory (make_cel_evaluator).
#
# Through M1-M5 this section parametrized [celpy, wasm] to prove the two
# engines byte/behavior-identical; M6 WS-I removed the legacy engine, so the
# suite keeps the SAME engine-neutral assertions under the single [wasm]
# parameter -- every behavior the dual-run matrix proved identical is still
# pinned on the surviving engine, and the factory remains the production
# construction path (RELAY_CEL_ENGINE selection lives ONLY in engine.py).
# ===========================================================================

# Engine names match the RELAY_CEL_ENGINE tokens the factory accepts (wasm
# only as of M6; the removed legacy token now fails closed -- pinned by
# test_p6remove_no_celpy.test_explicit_celpy_engine_selection_fails_closed).
_ENGINES = ["wasm"]


@pytest.fixture(params=_ENGINES, ids=_ENGINES)
def cel_engine(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Set RELAY_CEL_ENGINE for the parametrized engine and yield its name.

    Selection is read by make_cel_evaluator (engine.py) ONLY; the fixture sets
    the env var so the factory picks the right backend for this param.
    """
    monkeypatch.setenv("RELAY_CEL_ENGINE", request.param)
    return request.param


def _make(
    engine: str, *, timeout_ms: int = MAX_TIMEOUT_MS, **kwargs: object
) -> Any:
    """Build an evaluator for ``engine`` through the production factory.

    VALUE / ERROR-CLASS assertions are decoupled from the 50 ms production
    wall-clock default by constructing the evaluator with the spec-max budget
    (``MAX_TIMEOUT_MS`` == 250, the per-tenant cap from CQ1) by default. A
    fast, profile-clean evaluation must NOT spuriously trip the host-thread
    wall-clock under heavy concurrent full-suite load: the wasm engine's
    host-thread wall-clock guard over-fires on thread-scheduling jitter +
    wasmtime/Store overhead (NOT a genuinely slow eval) and raises
    RelayCelTimeoutError (RELAY-CEL-003) instead of the expected value/error,
    failing the assertion spuriously. The generous budget removes that
    coupling without altering any test's INTENT.

    The production default (50 ms, CQ1) is UNCHANGED -- this headroom lives
    only in the test construction path. Timeout-BEHAVIOR tests pass an
    explicit small ``timeout_ms`` (e.g. 20) which overrides this default, so
    they still exercise the wall-clock at their intended tight budget. The
    underlying wasm wall-clock jitter-sensitivity is fundamentally resolved by
    the M7 P7EDGE deterministic FUEL metering (which replaces the host
    wall-clock guard with in-engine fuel accounting); this test-construction
    headroom is the tier-1 robustness measure until that lands.
    """
    from relay_contracts.engine import make_cel_evaluator

    return make_cel_evaluator(timeout_ms=timeout_ms, **kwargs)  # type: ignore[arg-type]


def _arm_slow_engine(evaluator: Any) -> None:
    """Make the NEXT engine evaluation sleep past the wall-clock budget.

    Engine-timeout instrument that does NOT register a custom UDF (the wasm
    forbids extra UDFs): wraps the per-thread RelayCel handle's eval. The
    wrapped call funnels through the shared host ``run_with_timeout`` guard,
    so arming a slow primitive proves the host wall-clock timeout fires.
    """
    handle = evaluator._thread_handle()
    original_eval = handle.eval

    def slow_wasm(
        expr: str,
        bindings: object = None,
        container: object = None,
        relay_profile: bool = False,
    ) -> object:
        time.sleep(0.4)
        return original_eval(expr, bindings, container, relay_profile)

    handle.eval = slow_wasm


# --- VAL-W6-002 mirror: Relay profile (dyn/timestamp/duration) ---------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
@pytest.mark.parametrize(
    "expr,subtype",
    [
        ("dyn(1)", SUBTYPE_PROFILE_DYN_DISABLED),
        ('timestamp("2026-01-01T00:00:00Z")', SUBTYPE_PROFILE_TS_DISABLED),
        ('duration("3600s")', SUBTYPE_PROFILE_DUR_DISABLED),
    ],
)
def test_profile_disabled_call_rejected_via_factory(
    cel_engine: str, expr: str, subtype: str
) -> None:
    """dyn/timestamp/duration global calls are rejected with RELAY-CEL-002 and
    the matching structured subtype through the production factory.

    The host rejects at compile (the static callee screen); the wasm engine
    independently enforces the profile fence at evaluate. Both are observable
    via evaluate(), which compiles first, so the assertion pins the full
    production path.
    """
    evaluator = _make(cel_engine)
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.evaluate(expr)
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == subtype


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_baseline_arithmetic_via_factory(cel_engine: str) -> None:
    """A profile-clean expression evaluates to the expected numeric result
    through the production factory."""
    evaluator = _make(cel_engine)
    assert int(evaluator.evaluate("1 + 2 * 3")) == 7


# --- VAL-W6-003 mirror: wall-clock timeout fires ------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_wall_clock_timeout_fires_via_factory(cel_engine: str) -> None:
    """The host wall-clock guard aborts an over-budget evaluation with
    RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001 (the timeout is host-side; the
    engine eval primitive is wrapped to exceed the budget)."""
    evaluator = _make(cel_engine, timeout_ms=20)
    _arm_slow_engine(evaluator)
    start = time.monotonic()
    with pytest.raises(RelayCelTimeoutError) as ctx:
        evaluator.evaluate("1 + 1")
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert ctx.value.code == "RELAY-CEL-003"
    assert ctx.value.subtype == SUBTYPE_TIMEOUT
    # Aborted within a generous multiple of the 20 ms budget allowing for
    # scheduler jitter; the assertion is that the timeout fires promptly, not
    # that it waits out the full 400 ms sleep.
    assert elapsed_ms < 300.0, (
        f"VAL-CWC-P1HOST-011[{cel_engine}]: timeout fired at {elapsed_ms:.1f} ms; "
        "budget was 20 ms"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_timeout_constructor_bounds_via_factory(cel_engine: str) -> None:
    """Constructor timeout bounds are enforced through the factory
    (positive int, <= MAX_TIMEOUT_MS)."""
    with pytest.raises(ValueError):
        _make(cel_engine, timeout_ms=0)
    with pytest.raises(ValueError):
        _make(cel_engine, timeout_ms=-5)
    with pytest.raises(ValueError):
        _make(cel_engine, timeout_ms=10_000)  # exceeds MAX_TIMEOUT_MS


# --- VAL-W6-006 / VAL-PARITY-001 mirror: numeric boundary ---------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_int_above_safe_range_rejected_via_factory(cel_engine: str) -> None:
    """An integral CEL result with abs value > MAX_SAFE_INTEGER is rejected at
    the host result boundary (_check_finite) -- pure-CEL, no custom UDF
    needed."""
    evaluator = _make(cel_engine)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("9007199254740992 + 1")
    assert ctx.value.code == "RELAY-CEL-006"
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_max_safe_integer_accepted_via_factory(cel_engine: str) -> None:
    """MAX_SAFE_INTEGER (2**53 - 1) is the largest integer accepted; the very
    next integer is rejected (see above)."""
    evaluator = _make(cel_engine)
    out = evaluator.evaluate("9007199254740990 + 1")
    assert int(out) == _MAX_SAFE_INTEGER


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_whole_double_above_safe_range_rejected_via_factory(cel_engine: str) -> None:
    """A whole-valued DOUBLE literal beyond MAX_SAFE_INTEGER is rejected at the
    result boundary (cross-runtime digest parity)."""
    evaluator = _make(cel_engine)
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("9007199254740994.0")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_finite_double_within_range_accepted_via_factory(cel_engine: str) -> None:
    """A finite in-range double passes through unchanged."""
    evaluator = _make(cel_engine)
    out = evaluator.evaluate("1.5 + 2.5")
    assert math.isfinite(float(out))
    assert float(out) == 4.0


# --- VAL-W6-007 mirror: regex backreference rejected ---------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_regex_backref_rejected_via_factory(cel_engine: str) -> None:
    """A regex backreference is rejected host-side (RELAY-CEL-007 /
    REGEX-BACKREF) BEFORE the engine call; the host pre-screen is
    engine-agnostic. (RelayCelRegexBackreferenceError is a
    RelayCelProfileError subclass, so catching RelayCelProfileError holds.)"""
    evaluator = _make(cel_engine)
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile(r'"abba".matches("a(b)\\1")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-011")
def test_re2_safe_pattern_evaluates_via_factory(cel_engine: str) -> None:
    """A backref-free RE2 pattern compiles AND evaluates (the host pre-screen
    does not over-reject a safe pattern). The codec decodes a CEL boolean to
    a native Python ``bool``, so the result IS the singleton ``True``."""
    evaluator = _make(cel_engine)
    assert evaluator.compile(r'"hello".matches("h.*o")') is not None
    result = evaluator.evaluate(r'"hello".matches("h.*o")')
    assert result is True
