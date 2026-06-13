"""WasmCelEvaluator host facade -- the central evaluator facade (M1 P1HOST).

The wasm-backed CEL evaluator is the SINGLE Python CEL evaluator behind
``CelEvaluatorProtocol`` (M6 WS-I removed the legacy engine): ``__init__(*,
timeout_ms, udfs)`` with the canonical bounds, plus the ``compile`` /
``probe_compile`` / ``evaluate`` / ``evaluate_with_trace`` surface. It routes
the expression through the single wasm CEL engine
(``RelayCel.eval(..., relay_profile=True)``) but keeps the engine-agnostic host
guards host-side:

  - regex-backreference pre-screen (RELAY-CEL-007) runs BEFORE the wasm call
  - the static callee-set profile screen (RELAY-CEL-002) rejects disabled
    builtins at compile time
  - extra-UDF rejection (RELAY-CEL-004 / UNREGISTERED) is fail-closed BEFORE eval
  - ``_check_finite`` (RELAY-CEL-006 / NUMERIC-OOB) runs host-side on the
    ``typed_to_py``-converted result
  - the wall-clock timeout + orphan-thread cap use the engine-agnostic
    ``run_with_timeout`` helper

A wasm ``{"ok": false}`` engine envelope (the wasm's OWN 001 compile / 004 exec
/ 006 request codes + the RELAY-CEL-PANIC trap marker) is translated to the
DISTINCT RELAY-CEL-009 engine error per cause -- never the host 004/006.

Threading: a per-thread ``RelayCel`` handle over a SHARED Engine+Module (the
loader's Store is not thread-safe). A host timeout that orphans a worker thread
quarantines that thread's Store so the NEXT evaluate on the same thread starts
clean.

Covers VAL-CWC-P1HOST-003..008. tier-1 plumbing.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from relay_contracts.errors import (
    SUBTYPE_ENGINE_COMPILE,
    SUBTYPE_ENGINE_EXEC,
    SUBTYPE_ENGINE_PANIC,
    SUBTYPE_ENGINE_REQUEST,
    SUBTYPE_NUMERIC_OOB,
    SUBTYPE_PROFILE_DUR_DISABLED,
    SUBTYPE_PROFILE_DYN_DISABLED,
    SUBTYPE_PROFILE_TS_DISABLED,
    SUBTYPE_TIMEOUT,
    SUBTYPE_UDF_IMPURE,
    SUBTYPE_UDF_UNREGISTERED,
    RelayCelEngineError,
    RelayCelError,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelRegexBackreferenceError,
    RelayCelTimeoutError,
    RelayCelUnsupportedUdfError,
)
from relay_contracts.evaluator import MAX_TIMEOUT_MS
from relay_contracts.udf import register_udf
from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-003: the single-evaluator facade + canonical timeout bounds
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_facade_exposes_single_evaluator_surface():
    ev = WasmCelEvaluator(timeout_ms=50, udfs=())
    # The CelEvaluatorProtocol facade (M6: probe_compile + evaluate_with_trace
    # replace the removed legacy _env attribute).
    assert callable(ev.compile)
    assert callable(ev.probe_compile)
    assert callable(ev.evaluate)
    assert callable(ev.evaluate_with_trace)
    assert ev.timeout_ms == 50
    # The legacy AST environment attribute is GONE (no host-side CEL AST).
    assert not hasattr(ev, "_env")


@pytest.mark.plumbing
def test_default_construction_accepts_udfs_keyword():
    # Empty udfs tuple is accepted (the wasm hosts the 3 relay.* UDFs natively).
    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    assert ev.evaluate("1 + 2") == 3


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_timeout", [0, -1, MAX_TIMEOUT_MS + 1, 10000])
def test_timeout_bounds_rejected_canonical(bad_timeout):
    # The canonical bounds (positive int <= MAX_TIMEOUT_MS) are enforced by the
    # shared validate_timeout_ms host helper.
    with pytest.raises(ValueError):
        WasmCelEvaluator(timeout_ms=bad_timeout)


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_timeout", ["50", 50.0, None])
def test_timeout_non_int_rejected(bad_timeout):
    with pytest.raises(ValueError):
        WasmCelEvaluator(timeout_ms=bad_timeout)


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-004: routes through RelayCel.eval(relay_profile=True)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_baseline_arithmetic_through_wasm():
    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    result = ev.evaluate("1 + 2")
    assert result == 3
    # typed_to_py returns the native Python int (M6 type layer).
    assert type(result) is int


@pytest.mark.plumbing
def test_baseline_with_bindings():
    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    out = ev.evaluate("x + y", {"x": 5, "y": 7})
    assert out == 12
    assert type(out) is int


@pytest.mark.plumbing
def test_none_and_empty_bindings():
    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    assert ev.evaluate("1 + 1", None) == 2
    assert ev.evaluate("2 + 2", {}) == 4


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "expr,subtype",
    [
        ("dyn(1)", SUBTYPE_PROFILE_DYN_DISABLED),
        ('timestamp("2020-01-01T00:00:00Z")', SUBTYPE_PROFILE_TS_DISABLED),
        ('duration("1s")', SUBTYPE_PROFILE_DUR_DISABLED),
    ],
)
def test_profile_disabled_global_call_rejected_via_structured_subtype(expr, subtype):
    ev = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as exc:
        ev.evaluate(expr)
    assert exc.value.code == "RELAY-CEL-002"
    assert exc.value.subtype == subtype


# ---------------------------------------------------------------------------
# FINDING D: WasmCelEvaluator.compile() runs the SAME profile check at COMPILE
# time as RelayCelEvaluator.compile(). Before the fix compile() only ran
# _check_regex_backref and returned, so dyn()/timestamp()/duration() slipped
# through pipeline.publish_contract() under RELAY_CEL_ENGINE=wasm (the wasm only
# rejected them at EVAL). publish_contract calls evaluator.compile(); the wasm
# path MUST reject at publish exactly like the celpy path.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize(
    "expr,subtype",
    [
        ("dyn(1)", SUBTYPE_PROFILE_DYN_DISABLED),
        ('timestamp("2020-01-01T00:00:00Z")', SUBTYPE_PROFILE_TS_DISABLED),
        ('duration("1s")', SUBTYPE_PROFILE_DUR_DISABLED),
    ],
)
def test_profile_disabled_call_rejected_at_compile_not_only_evaluate(expr, subtype):
    ev = WasmCelEvaluator()
    # The disabled-builtin call MUST be rejected at compile() (the publish path),
    # with the SAME structured RELAY-CEL-002 PROFILE subtype the celpy path
    # surfaces -- not deferred to evaluate().
    with pytest.raises(RelayCelProfileError) as exc:
        ev.compile(expr)
    assert exc.value.code == "RELAY-CEL-002"
    assert exc.value.subtype == subtype


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "expr,subtype",
    [
        ("dyn(1)", SUBTYPE_PROFILE_DYN_DISABLED),
        ('timestamp("2020-01-01T00:00:00Z")', SUBTYPE_PROFILE_TS_DISABLED),
        ('duration("1s")', SUBTYPE_PROFILE_DUR_DISABLED),
    ],
)
def test_wasm_compile_profile_rejection_matches_engine_eval_rejection(expr, subtype):
    # M6 WS-I port of the legacy engine-invariance arm: the host compile()
    # STATIC profile rejection MUST carry the SAME code + subtype the wasm
    # engine itself emits for the same expression at eval (the structured
    # RELAY-CEL-002 envelope), so publish-time rejection is consistent with
    # the engine's own profile fence.
    compile_ev = WasmCelEvaluator()
    eval_ev = WasmCelEvaluator()
    with pytest.raises(RelayCelProfileError) as compile_exc:
        compile_ev.compile(expr)
    with pytest.raises(RelayCelProfileError) as eval_exc:
        eval_ev.evaluate(expr)
    assert compile_exc.value.code == eval_exc.value.code == "RELAY-CEL-002"
    assert compile_exc.value.subtype == eval_exc.value.subtype == subtype


@pytest.mark.plumbing
def test_wasm_compile_accepts_valid_expression():
    # A VALID expression still compiles (the profile check only rejects the
    # disabled builtins; it must not break normal compilation). compile()
    # returns the expression unchanged on the wasm path.
    ev = WasmCelEvaluator()
    assert ev.compile("1 + 2") == "1 + 2"
    assert ev.compile('"a".size() > 0') == '"a".size() > 0'


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-005: host guards retained on the wasm path
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_regex_backref_rejected_host_side_at_compile():
    ev = WasmCelEvaluator()
    # The host regex-backref pre-screen catches this at compile() BEFORE the
    # wasm call (RELAY-CEL-007 / REGEX-BACKREF), not as a leaked wasm exec error.
    with pytest.raises(RelayCelRegexBackreferenceError) as exc:
        ev.compile('"x".matches("(a)\\1")')
    assert exc.value.code == "RELAY-CEL-007"


@pytest.mark.plumbing
def test_regex_backref_rejected_on_evaluate_too():
    ev = WasmCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError):
        ev.evaluate('"x".matches("(a)\\1")')


@pytest.mark.plumbing
def test_numeric_oob_rejected_host_side_on_result():
    # Error-class (RELAY-CEL-006) assertion reached AFTER the eval runs through
    # the wasm wall-clock guard; decoupled from the 50 ms default so host-thread
    # jitter under concurrent load cannot replace the expected 006 with a
    # spurious RELAY-CEL-003 timeout. Production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    # The wasm returns the exact int 9007199254740993 (> 2**53 - 1); the host
    # _check_finite runs on the typed_to_py result and rejects it.
    with pytest.raises(RelayCelNumericOutOfBoundsError) as exc:
        ev.evaluate("9007199254740992 + 1")
    assert exc.value.code == "RELAY-CEL-006"
    assert exc.value.subtype == SUBTYPE_NUMERIC_OOB


@pytest.mark.plumbing
def test_in_range_large_int_accepted():
    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    # 2**53 - 1 == 9007199254740991 is the inclusive bound -- accepted.
    assert ev.evaluate("9007199254740990 + 1") == 9007199254740991


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-006: extra UDFs fail-closed BEFORE eval
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_extra_udf_rejected_at_construction():
    extra = register_udf("my_check", lambda *a: True, pure=True, arity=1)
    with pytest.raises(RelayCelUnsupportedUdfError) as exc:
        WasmCelEvaluator(udfs=(extra,))
    assert exc.value.code == "RELAY-CEL-004"
    assert exc.value.subtype == SUBTYPE_UDF_UNREGISTERED
    # Distinct from the purity subtype that shares code 004.
    assert exc.value.subtype != SUBTYPE_UDF_IMPURE


@pytest.mark.plumbing
def test_allowlist_udfs_accepted():
    # The 3 hardcoded relay.* UDFs are allowed (they are native to the wasm).
    from relay_contracts import RELAY_UDFS

    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(udfs=RELAY_UDFS, timeout_ms=MAX_TIMEOUT_MS)
    assert ev.evaluate("1 + 2") == 3


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-007: wasm {ok:false} -> RELAY-CEL-009 (no 004/006 collision)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_wasm_exec_failure_maps_to_009_engine_exec():
    # Engine error-class (RELAY-CEL-009) assertion reached AFTER the eval runs
    # through the wasm wall-clock guard; decoupled from the 50 ms default so
    # host-thread jitter under concurrent load cannot replace the expected 009
    # with a spurious RELAY-CEL-003 timeout. Production 50 ms default (CQ1)
    # unchanged; root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    # 1 / 0 -> the wasm returns {"ok": false, "code": "RELAY-CEL-004"} (exec).
    with pytest.raises(RelayCelEngineError) as exc:
        ev.evaluate("1 / 0")
    err = exc.value
    assert err.code == "RELAY-CEL-009"
    assert err.subtype == SUBTYPE_ENGINE_EXEC
    # The wasm's exec 004 NEVER surfaces as the host UDF-IMPURE 004.
    assert err.subtype != SUBTYPE_UDF_IMPURE
    assert isinstance(err, RelayCelError)


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "wasm_code,expected_subtype",
    [
        ("RELAY-CEL-001", SUBTYPE_ENGINE_COMPILE),
        ("RELAY-CEL-004", SUBTYPE_ENGINE_EXEC),
        ("RELAY-CEL-006", SUBTYPE_ENGINE_REQUEST),
        ("RELAY-CEL-PANIC", SUBTYPE_ENGINE_PANIC),
    ],
)
def test_wasm_false_envelope_each_cause_maps_to_009(monkeypatch, wasm_code, expected_subtype):
    # Engine error-class (RELAY-CEL-009 per cause) assertion reached AFTER the
    # eval runs through the wasm wall-clock guard; decoupled from the 50 ms
    # default so host-thread jitter under concurrent load cannot replace the
    # expected 009 subtype with a spurious RELAY-CEL-003 timeout. Production
    # 50 ms default (CQ1) unchanged; root cause resolved by M7 P7EDGE fuel
    # metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)

    def fake_eval(expr, bindings=None, container=None, relay_profile=False):
        return {"ok": False, "error": "engine said no", "code": wasm_code}

    # Replace the per-thread handle's eval with a fake returning the target
    # wasm envelope, so each engine-failure cause is exercised structurally.
    monkeypatch.setattr(ev._thread_handle(), "eval", fake_eval)
    with pytest.raises(RelayCelEngineError) as exc:
        ev.evaluate("1 + 1")
    err = exc.value
    assert err.code == "RELAY-CEL-009"
    assert err.subtype == expected_subtype
    # Wasm exec(004)/request(006) must NEVER carry the host 004/006 subtypes.
    assert err.subtype != SUBTYPE_UDF_IMPURE
    assert err.subtype != SUBTYPE_NUMERIC_OOB
    assert isinstance(err, RelayCelError)


@pytest.mark.plumbing
def test_wasm_request_failure_does_not_surface_as_host_numeric_oob(monkeypatch):
    # Engine error-class (RELAY-CEL-009 / ENGINE-REQUEST) assertion reached AFTER
    # the eval runs through the wasm wall-clock guard; decoupled from the 50 ms
    # default so host-thread jitter under concurrent load cannot replace the
    # expected 009 with a spurious RELAY-CEL-003 timeout. Production 50 ms default
    # (CQ1) unchanged; root cause resolved by M7 P7EDGE fuel metering.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)

    def fake_eval(expr, bindings=None, container=None, relay_profile=False):
        return {"ok": False, "error": "bad request", "code": "RELAY-CEL-006"}

    monkeypatch.setattr(ev._thread_handle(), "eval", fake_eval)
    with pytest.raises(RelayCelEngineError) as exc:
        ev.evaluate("1 + 1")
    assert exc.value.code == "RELAY-CEL-009"
    assert exc.value.subtype == SUBTYPE_ENGINE_REQUEST
    assert not isinstance(exc.value, RelayCelNumericOutOfBoundsError)


# ---------------------------------------------------------------------------
# VAL-CWC-P7EDGE-008 (Python cross-host parity): a wasm RELAY-CEL-003
# fuel-exhaustion envelope decodes to RelayCelTimeoutError -- the SAME class +
# code + subtype the host wall-clock kill throws -- NOT RelayCelEngineError/009.
# Mirrors the TS decodeWasmEnvelope fix (commit 873b171) for behavioral parity.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_decode_wasm_003_envelope_maps_to_timeout_not_engine_009():
    """A {ok:false, code:RELAY-CEL-003, subtype:RELAY-CEL-TIMEOUT-001} wasm
    envelope (the in-engine fuel-budget exhaustion path) must decode to
    RelayCelTimeoutError with code RELAY-CEL-003 / subtype RELAY-CEL-TIMEOUT-001,
    indistinguishable from the host wall-clock timeout -- NOT the generic
    RelayCelEngineError (RELAY-CEL-009)."""
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    envelope = {
        "ok": False,
        "code": "RELAY-CEL-003",
        "subtype": "RELAY-CEL-TIMEOUT-001",
        "error": "fuel budget exhausted",
    }
    with pytest.raises(RelayCelTimeoutError) as exc:
        ev._decode_envelope(envelope)
    err = exc.value
    assert err.code == "RELAY-CEL-003", err.code
    assert err.subtype == SUBTYPE_TIMEOUT, err.subtype
    assert err.subtype == "RELAY-CEL-TIMEOUT-001", err.subtype
    # It is the timeout class, never the generic engine-009 class.
    assert isinstance(err, RelayCelError)
    assert not isinstance(err, RelayCelEngineError)


@pytest.mark.plumbing
def test_decode_wasm_003_envelope_through_evaluate_maps_to_timeout(monkeypatch):
    """End-to-end through evaluate(): a fuel-exhaustion 003 envelope returned by
    the wasm handle surfaces as RelayCelTimeoutError, not RelayCelEngineError --
    so a fuel-derived timeout is downstream-identical to the host wall-clock kill
    (cross-host parity with the TS path)."""
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)

    def fake_eval(expr, bindings=None, container=None, relay_profile=False):
        return {
            "ok": False,
            "code": "RELAY-CEL-003",
            "subtype": "RELAY-CEL-TIMEOUT-001",
            "error": "fuel budget exhausted",
        }

    monkeypatch.setattr(ev._thread_handle(), "eval", fake_eval)
    with pytest.raises(RelayCelTimeoutError) as exc:
        ev.evaluate("1 + 1")
    assert exc.value.code == "RELAY-CEL-003"
    assert exc.value.subtype == SUBTYPE_TIMEOUT
    assert not isinstance(exc.value, RelayCelEngineError)


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_subtype", [None, "", "RELAY-CEL-PROFILE-DYN-DISABLED"])
def test_decode_wasm_003_envelope_without_timeout_subtype_is_engine_anomaly(bad_subtype):
    """Parity with the TS subtype guard: a RELAY-CEL-003 envelope that lacks the
    structured RELAY-CEL-TIMEOUT-001 subtype is an engine-request anomaly
    (RELAY-CEL-009), NOT a blindly-trusted timeout -- a malformed 003 must never
    masquerade as a benign timeout downstream."""
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    envelope: dict[str, Any] = {
        "ok": False,
        "code": "RELAY-CEL-003",
        "error": "malformed timeout envelope",
    }
    if bad_subtype is not None:
        envelope["subtype"] = bad_subtype
    with pytest.raises(RelayCelEngineError) as exc:
        ev._decode_envelope(envelope)
    assert exc.value.code == "RELAY-CEL-009"
    assert exc.value.subtype == SUBTYPE_ENGINE_REQUEST
    assert not isinstance(exc.value, RelayCelTimeoutError)


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-008: per-thread handle + Store quarantine + concurrency
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_per_thread_handle_is_distinct_across_threads():
    ev = WasmCelEvaluator()
    handles: dict[str, Any] = {}

    def grab(label):
        handles[label] = ev._thread_handle()

    t1 = threading.Thread(target=grab, args=("a",))
    t2 = threading.Thread(target=grab, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    # Two different threads get two different RelayCel handles (distinct Stores).
    assert handles["a"] is not handles["b"]
    # ... but they share the SAME underlying Engine+Module.
    assert handles["a"]._engine is handles["b"]._engine
    assert handles["a"]._module is handles["b"]._module


@pytest.mark.plumbing
def test_store_quarantine_after_timeout_does_not_corrupt_next_evaluate(monkeypatch):
    from relay_contracts.errors import RelayCelTimeoutError

    ev = WasmCelEvaluator(timeout_ms=20)
    # Prime the per-thread handle so we can observe it being quarantined.
    assert ev.evaluate("1 + 1") == 2
    poisoned = ev._thread_handle()

    # Make exactly the NEXT wasm eval on this handle block past the wall-clock
    # budget, orphaning the worker thread inside this Store. A one-shot block:
    # the orphaned worker eventually completes, but the host has already timed
    # out and must NOT reuse this (possibly mid-flight) Store.
    blocked = {"armed": True}

    def block_once(expr, bindings=None, container=None, relay_profile=False):
        if blocked["armed"]:
            blocked["armed"] = False
            time.sleep(0.4)  # >> 20 ms timeout
        return {"ok": True, "value": {"t": "int", "v": "0"}}

    monkeypatch.setattr(poisoned, "eval", block_once)
    with pytest.raises(RelayCelTimeoutError):
        ev.evaluate("2 + 2")

    # The orphaned worker is still running in `poisoned`'s Store. The NEXT
    # evaluate on THIS thread MUST start from a FRESH handle (quarantine) and
    # return the correct result -- the poisoned handle is discarded.
    ev.timeout_ms = 200
    fresh = ev._thread_handle()
    assert fresh is not poisoned, "timed-out handle must be quarantined"
    assert ev.evaluate("3 + 4") == 7


@pytest.mark.plumbing
def test_concurrent_evaluate_correct_per_thread_results():
    # This is a per-thread VALUE-correctness assertion (8 threads x 25 fast
    # evals must each return the right int), NOT a timeout-behavior test. It is
    # decoupled from the 50 ms production wall-clock default by constructing the
    # evaluator with the spec-max budget (MAX_TIMEOUT_MS == 250, the per-tenant
    # cap from CQ1). Under heavy concurrent full-suite load the wasm host-thread
    # wall-clock guard over-fires on thread-scheduling jitter + wasmtime/Store
    # overhead (NOT a genuinely slow eval) and raises RELAY-CEL-003 instead of
    # the correct value, failing this assertion spuriously. The generous budget
    # removes that coupling without altering the test's INTENT. The production
    # default (50 ms, CQ1) is UNCHANGED. The underlying wasm wall-clock
    # jitter-sensitivity is fundamentally resolved by the M7 P7EDGE
    # deterministic FUEL metering (in-engine fuel accounting replaces the host
    # wall-clock guard); this headroom is the tier-1 robustness measure until
    # that lands.
    ev = WasmCelEvaluator(timeout_ms=MAX_TIMEOUT_MS)
    results: dict[int, Any] = {}
    errors: dict[int, str] = {}

    def worker(i):
        try:
            for _ in range(25):
                out = ev.evaluate(f"{i} * 1000 + {i}")
                assert out == i * 1000 + i, out
            results[i] = "ok"
        except Exception as exc:  # noqa: BLE001 -- surfaced to the assert below
            errors[i] = repr(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == {}, errors
    assert results == {i: "ok" for i in range(1, 9)}
