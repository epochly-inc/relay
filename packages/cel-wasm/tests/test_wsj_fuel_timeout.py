"""WS-J (P7EDGE): Python wasm-loader fuel budget yields the portable RELAY-CEL-003
in-engine timeout verdict (VAL-CWC-P7EDGE-008).

The Python wasm loader (`packages/cel-wasm/python/relay_cel_wasm.py`) exposes a
`fuel_budget` parameter on `RelayCel.eval` and forwards it (as a positive int)
into the wasm eval request. The crate's in-wasm deterministic fuel counter caps
the evaluated-node count; on exhaustion it returns a structured
`{"ok": False, "code": "RELAY-CEL-003", "subtype": "RELAY-CEL-TIMEOUT-001"}`
envelope -- the SAME (code, subtype) the TS Workers fuel path and the Node
worker-thread wall-clock timeout surface (VAL-CWC-P7EDGE-006/007). This test is
the Python host parity proof of that cross-host contract: a tenant gets the same
timeout determinism regardless of host.

It asserts, driving the real loader against the real (pinned) `.wasm`:
  - a fuel-EXHAUSTING expression+budget -> ok==False, code RELAY-CEL-003,
    subtype RELAY-CEL-TIMEOUT-001 (the portable in-engine timeout);
  - the SAME expression with a generous budget -> ok==True with a value
    (the cap is a fuel limit, not a hard rejection of the expression);
  - fuel-off forms (None / 0 / negative) do NOT falsely trip the budget;
  - determinism: the same expr+budget twice yields the byte-identical verdict
    envelope (the in-wasm counter is reproducible, never host/time-dependent).

The expression and the exhausting budget mirror the crate's own native
`fuel_tests` (crate/src/lib.rs): a triple-nested `.map` comprehension whose
10*10*10 inner iterations far exceed a budget of 8.

tier-1 plumbing (runs offline against the committed pinned wasm; the default
loader path resolves the crate/target release wasm, identical sha256 to the
package-data pin `431d966b...`). Set CEL_WASM to override the wasm path.
"""
from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

C = RelayCel()

# A pathological expression: a triple-nested `.map` comprehension. 10*10*10 inner
# iterations, each re-entering value resolution several times, far exceed a fuel
# budget of 8 -- so a small budget reliably exhausts. Mirrors PATHOLOGICAL_EXPR in
# the crate's native fuel_tests so the Python-host and native verdicts agree by
# construction (both drive the same engine code path; the wasm ships it verbatim).
_PATHOLOGICAL = (
    "[0,1,2,3,4,5,6,7,8,9].map(x, "
    "[0,1,2,3,4,5,6,7,8,9].map(y, "
    "[0,1,2,3,4,5,6,7,8,9].map(z, x + y + z)))"
)

# The exhausting budget: small enough that the pathological comprehension cannot
# finish, matching the crate's `Some(8)` exhaustion case.
_EXHAUSTING_BUDGET = 8

# A generous budget the same expression finishes under, matching the crate's
# `Some(1_000_000)` non-exhausting case.
_GENEROUS_BUDGET = 1_000_000

# The cross-host (code, subtype) timeout contract (crate codes::TIMEOUT /
# subtypes::TIMEOUT). MUST be identical to the TS Workers fuel path and the Node
# worker-thread RelayCelTimeoutError -- no new timeout code, no divergent subtype.
_TIMEOUT_CODE = "RELAY-CEL-003"
_TIMEOUT_SUBTYPE = "RELAY-CEL-TIMEOUT-001"


@pytest.mark.plumbing
def test_fuel_exhausting_budget_yields_relay_cel_003_timeout():
    """The Evidence case: a fuel-exhausting expr+budget through the Python loader
    returns ok==False with code RELAY-CEL-003 / subtype RELAY-CEL-TIMEOUT-001."""
    r = C.eval(_PATHOLOGICAL, fuel_budget=_EXHAUSTING_BUDGET)
    assert r["ok"] is False, f"exhausting budget must fail the eval: {r}"
    assert r["code"] == _TIMEOUT_CODE, f"must surface RELAY-CEL-003: {r}"
    assert r["subtype"] == _TIMEOUT_SUBTYPE, f"must carry the TIMEOUT subtype: {r}"
    # No value on the timeout envelope -- it is a structured failure, not a result.
    assert "value" not in r, f"a timeout envelope carries no value: {r}"


@pytest.mark.plumbing
def test_generous_budget_yields_ok_with_value():
    """The SAME expression with a generous budget returns ok==True with a value --
    proving the cap is a fuel limit, not a hard rejection of the expression, and
    that a large budget does NOT falsely trip the timeout."""
    r = C.eval(_PATHOLOGICAL, fuel_budget=_GENEROUS_BUDGET)
    assert r["ok"] is True, f"generous budget must let the expr finish: {r}"
    assert "value" in r, f"a successful eval carries a value: {r}"
    assert "code" not in r, f"a success carries no error code: {r}"
    assert "subtype" not in r, f"a success carries no timeout subtype: {r}"


@pytest.mark.plumbing
@pytest.mark.parametrize("budget", [None, 0, -1])
def test_fuel_off_forms_do_not_falsely_trip(budget):
    """Fuel-off forms (absent / 0 disabled sentinel / negative) impose NO limit:
    the same pathological expr evaluates unbounded to ok==True. This proves a
    None/0/negative budget never falsely surfaces RELAY-CEL-003."""
    r = C.eval(_PATHOLOGICAL, fuel_budget=budget)
    assert r["ok"] is True, f"fuel-off (budget={budget!r}) must be unbounded: {r}"
    assert "value" in r, f"fuel-off eval carries a value: {r}"
    assert r.get("code") != _TIMEOUT_CODE, f"fuel-off must not trip RELAY-CEL-003: {r}"


@pytest.mark.plumbing
def test_fuel_off_is_value_identical_to_no_budget():
    """The disabled-sentinel forms (None / 0) produce the identical successful
    verdict as omitting fuel entirely -- the field is additive and absent-or-zero
    is byte-identical to the no-fuel form (loader adds it only for a positive int)."""
    no_arg = C.eval(_PATHOLOGICAL)
    none_arg = C.eval(_PATHOLOGICAL, fuel_budget=None)
    zero_arg = C.eval(_PATHOLOGICAL, fuel_budget=0)
    assert no_arg == none_arg == zero_arg, (
        "fuel None / 0 must match the no-fuel eval verdict exactly: "
        f"{no_arg!r} {none_arg!r} {zero_arg!r}"
    )


@pytest.mark.plumbing
def test_fuel_timeout_verdict_is_deterministic():
    """Determinism: the same expr+exhausting budget twice yields the byte-identical
    timeout envelope (the in-wasm fuel counter is reproducible, never host/time/
    iteration-order dependent). The full dict equality covers every field the
    envelope exposes -- ok, error, code, subtype -- so any accounting drift fails."""
    first = C.eval(_PATHOLOGICAL, fuel_budget=_EXHAUSTING_BUDGET)
    second = C.eval(_PATHOLOGICAL, fuel_budget=_EXHAUSTING_BUDGET)
    assert first == second, (
        f"same expr+budget twice must be identical: {first!r} != {second!r}"
    )
    # And the deterministic verdict is the timeout envelope, not a stale/random one.
    assert first["code"] == _TIMEOUT_CODE and first["subtype"] == _TIMEOUT_SUBTYPE, first

    # A bounded successful run is likewise identical run-to-run.
    ok1 = C.eval(_PATHOLOGICAL, fuel_budget=_GENEROUS_BUDGET)
    ok2 = C.eval(_PATHOLOGICAL, fuel_budget=_GENEROUS_BUDGET)
    assert ok1 == ok2, f"same expr+generous budget twice must be identical: {ok1!r}"
    assert ok1["ok"] is True, ok1
