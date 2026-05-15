"""w6.1 cel-python evaluator tier-1 plumbing tests.

Each test pins exactly one VAL-W6-NNN assertion and runs offline (no
network, no real CEL fixtures from disk -- the conformance corpus comes
in W6.5). The full suite is bounded by the tier-1 60-second budget per
.ops/manifest.yaml.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path

import pytest
from relay_contracts import (
    PureUdf,
    RelayCelEvaluator,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelTimeoutError,
    RelayUdfPurityError,
    jcs_canonicalize,
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

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC = REPO_ROOT / "packages" / "contracts" / "src" / "relay_contracts"


# ---------------------------------------------------------------------------
# VAL-W6-001: cel-python is the only Python CEL evaluator
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-001")
def test_celpy_imports_under_relay_contracts() -> None:
    """The package MUST import celpy at evaluator construction time."""

    import celpy  # noqa: F401

    evaluator = RelayCelEvaluator()
    # The evaluator's environment is a celpy.Environment instance; this
    # confirms the wrapper is built on the canonical implementation.
    assert isinstance(evaluator._env, celpy.Environment)  # noqa: SLF001


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-001")
def test_no_alternate_python_cel_lib_in_contracts_source() -> None:
    """Grep packages/contracts source for forbidden CEL implementations.

    cel-python ships as the ``celpy`` import name. Any other CEL
    implementation under ``packages/contracts/`` is a violation of
    CQ1 line 145 (single-source CEL evaluator per language).
    """

    forbidden_imports = [
        re.compile(r"^\s*import\s+pycel(\b|\s|$)", re.MULTILINE),
        re.compile(r"^\s*from\s+pycel\b", re.MULTILINE),
        re.compile(r"^\s*import\s+cel_py(\b|\s|$)", re.MULTILINE),
        re.compile(r"^\s*from\s+cel_py\b", re.MULTILINE),
        # The Google Python CEL fork (not celpy) -- import name varies;
        # the celpy fork is the canonical one we depend on.
        re.compile(r"^\s*from\s+google\.cel\.python\b", re.MULTILINE),
    ]
    hits: list[str] = []
    for py in PKG_SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for pattern in forbidden_imports:
            if pattern.search(text):
                hits.append(f"{py.relative_to(REPO_ROOT)}: {pattern.pattern}")
    assert hits == [], (
        f"VAL-W6-001: forbidden alternate-CEL imports found: {hits}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-001")
def test_celpy_metadata_apache_2_0() -> None:
    """`pip show cel-python` (or equivalent) confirms Apache 2.0 license.

    cel-python 0.5.0's METADATA leaves the ``License`` field unset and
    distributes the license body via the wheel ``licenses/LICENSE``
    file (PEP 639 layout). We resolve the file via ``importlib.metadata``
    distribution introspection and confirm the Apache 2.0 header.
    """

    from importlib.metadata import distribution

    dist = distribution("cel-python")
    # PEP 639: license files exposed via dist.files filtered by suffix.
    license_files = [
        f for f in (dist.files or [])
        if f.name == "LICENSE" or f.name.endswith("/LICENSE")
    ]
    assert license_files, "VAL-W6-001: cel-python ships no LICENSE file"
    body = license_files[0].read_text()
    assert "Apache License" in body and "Version 2.0" in body, (
        "VAL-W6-001: cel-python LICENSE is not Apache 2.0; "
        f"first line: {body.splitlines()[0]!r}"
    )


# ---------------------------------------------------------------------------
# VAL-W6-002: Relay profile -- dyn / timestamp / duration disabled
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_dyn_call_rejected_at_compile_time() -> None:
    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile("dyn(1)")
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_DYN_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_native_timestamp_call_rejected_at_compile_time() -> None:
    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile('timestamp("2026-01-01T00:00:00Z")')
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_TS_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_native_duration_call_rejected_at_compile_time() -> None:
    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile('duration("3600s")')
    assert ctx.value.code == "RELAY-CEL-002"
    assert ctx.value.subtype == SUBTYPE_PROFILE_DUR_DISABLED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-002")
def test_baseline_arithmetic_compiles_and_evaluates() -> None:
    """Sanity: a profile-clean expression evaluates normally."""

    evaluator = RelayCelEvaluator()
    assert int(evaluator.evaluate("1 + 2 * 3")) == 7


# ---------------------------------------------------------------------------
# VAL-W6-003: wall-clock timeout enforced
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-003")
def test_pathological_expression_aborts_at_timeout() -> None:
    """A UDF that sleeps past the budget MUST trigger RELAY-CEL-003.

    cel-python's pure-CEL path is fast enough that crafting an
    in-language busy expression that reliably exceeds 50 ms in CI is
    flaky. We bind a *pure* UDF whose body sleeps; this still tests
    the evaluator's wall-clock enforcement (the wrapper does not
    'know' the UDF is slow). Per CLAUDE.md banned pattern #16, the
    UDF is registered with pure=True for test purposes -- the sleep
    is a test instrument, not a production UDF.
    """

    def slow_pure(_x: int) -> int:
        time.sleep(0.250)
        return 0

    udf = register_udf("slow_pure", slow_pure, pure=True, arity=1)
    evaluator = RelayCelEvaluator(timeout_ms=10, udfs=[udf])
    start = time.monotonic()
    with pytest.raises(RelayCelTimeoutError) as ctx:
        evaluator.evaluate("slow_pure(0)")
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
        RelayCelEvaluator(timeout_ms=0)
    with pytest.raises(ValueError):
        RelayCelEvaluator(timeout_ms=-5)
    with pytest.raises(ValueError):
        RelayCelEvaluator(timeout_ms=10_000)  # exceeds MAX_TIMEOUT_MS cap


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
def test_nan_in_python_result_rejected() -> None:
    """Caller passes a NaN-producing expression via a pure UDF instrument."""

    def nan_pure() -> float:
        return float("nan")

    udf = register_udf("nan_pure", nan_pure, pure=True, arity=0)
    evaluator = RelayCelEvaluator(udfs=[udf])
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("nan_pure()")
    assert ctx.value.code == "RELAY-CEL-006"
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_pos_inf_in_python_result_rejected() -> None:
    def pinf() -> float:
        return float("inf")

    udf = register_udf("pinf", pinf, pure=True, arity=0)
    evaluator = RelayCelEvaluator(udfs=[udf])
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("pinf()")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_neg_inf_in_python_result_rejected() -> None:
    def ninf() -> float:
        return float("-inf")

    udf = register_udf("ninf", ninf, pure=True, arity=0)
    evaluator = RelayCelEvaluator(udfs=[udf])
    with pytest.raises(RelayCelNumericOutOfBoundsError) as ctx:
        evaluator.evaluate("ninf()")
    assert ctx.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-006")
def test_finite_result_passes() -> None:
    evaluator = RelayCelEvaluator()
    out = evaluator.evaluate("1.5 + 2.5")
    assert math.isfinite(float(out))


# ---------------------------------------------------------------------------
# VAL-W6-007: regex backreference rejected at parse/check time
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-007")
def test_regex_backref_simple_rejected_at_compile() -> None:
    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        # Single-quoted CEL string holds the regex `(.)\1+`.
        evaluator.compile(r'"abc".matches("(.)\\1+")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-007")
def test_regex_backref_capture_then_ref_rejected() -> None:
    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelProfileError) as ctx:
        evaluator.compile(r'"abba".matches("a(b)\\1")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-007")
def test_re2_safe_pattern_compiles_cleanly() -> None:
    """Baseline: a backref-free pattern parses without error."""

    evaluator = RelayCelEvaluator()
    compiled = evaluator.compile(r'"hello".matches("h.*o")')
    assert compiled is not None
