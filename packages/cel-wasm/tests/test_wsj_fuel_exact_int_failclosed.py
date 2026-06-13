"""WS-J (P7EDGE): the Python wasm loader fails CLOSED on a non-int fuel_budget
(roborev 56941c7 MED), symmetric to the TS loader fix.

The loader forwards `fuel_budget` into the wasm eval request only when it is an
EXACT positive int in u64 range. The wasm reads the field with serde
`as_u64().unwrap_or(0)`: a positive NON-int value (`8.0`, `1.5`, `True`) JSON-
serializes as `8.0` / `8.0` / `true`, which `as_u64()` cannot read, so it
returns None and `unwrap_or(0)` SILENTLY DISABLES the budget -- fail-open,
turning a "budget set" misconfig into "unbounded" and letting a fuel-exhausting
expression run without the timeout. The loader must surface the misconfig
(raise ValueError) rather than mask it.

Fail-closed contract this test pins:
  - a NON-int positive budget (`8.0`, `1.5`, `True`) -> ValueError (NOT silent
    disable). `type(fuel_budget) is int` excludes bool (`type(True) is bool`)
    and float;
  - an in-range positive int (`8`) -> forwarded + caps the eval (the timeout
    still fires);
  - the disabled sentinels (`0`, `None`) -> no field, byte-identical to the
    no-fuel form (NOT a ValueError -- a disabled budget is a valid config);
  - an out-of-u64 positive int (`2**64`) -> ValueError (the pre-existing u64
    range guard, now preceded by the exact-int type check).

tier-1 plumbing (offline, against the committed pinned wasm).
"""
from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

C = RelayCel()

# The pathological expr + exhausting budget from the sibling fuel test: a small
# in-range int budget reliably trips the in-engine timeout, proving the forward
# path still works after the exact-int guard.
_PATHOLOGICAL = (
    "[0,1,2,3,4,5,6,7,8,9].map(x, "
    "[0,1,2,3,4,5,6,7,8,9].map(y, "
    "[0,1,2,3,4,5,6,7,8,9].map(z, x + y + z)))"
)
_EXHAUSTING_BUDGET = 8

_TIMEOUT_CODE = "RELAY-CEL-003"
_TIMEOUT_SUBTYPE = "RELAY-CEL-TIMEOUT-001"


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_budget", [8.0, 1.5, True])
def test_non_int_positive_budget_fails_closed(bad_budget):
    """FAIL CLOSED: a positive NON-int budget (float 8.0 / 1.5, bool True) raises
    ValueError BEFORE the field is added. Such a value JSON-serializes as
    8.0/1.5/true; the wasm's serde as_u64() reads None and unwrap_or(0) SILENTLY
    DISABLES the budget (fail-open). The loader surfaces the misconfig instead.

    type(fuel_budget) is int excludes bool (type(True) is bool, not int) and
    float -- so only a real int is forwarded."""
    with pytest.raises(ValueError, match="(?i)fuel"):
        C.eval(_PATHOLOGICAL, fuel_budget=bad_budget)


@pytest.mark.plumbing
def test_in_range_int_budget_still_forwards_and_caps():
    """No false rejection: an ordinary in-range int budget (8) STILL forwards
    after the exact-int guard and trips the in-engine timeout."""
    r = C.eval(_PATHOLOGICAL, fuel_budget=_EXHAUSTING_BUDGET)
    assert r["ok"] is False, f"an in-range int budget must still cap the eval: {r}"
    assert r["code"] == _TIMEOUT_CODE, f"must surface RELAY-CEL-003: {r}"
    assert r["subtype"] == _TIMEOUT_SUBTYPE, f"must carry the TIMEOUT subtype: {r}"


@pytest.mark.plumbing
@pytest.mark.parametrize("disabled", [0, None])
def test_disabled_sentinels_are_no_field_not_valueerror(disabled):
    """A disabled budget (0 sentinel / None) is a VALID config -- no field, NOT a
    ValueError. The disabled form is byte-identical to omitting fuel entirely, so
    the pathological expr evaluates unbounded to ok==True."""
    r = C.eval(_PATHOLOGICAL, fuel_budget=disabled)
    assert r["ok"] is True, f"disabled budget ({disabled!r}) must be unbounded: {r}"
    assert "value" in r, f"disabled-budget eval carries a value: {r}"
    assert r.get("code") != _TIMEOUT_CODE, f"disabled must not trip a timeout: {r}"


@pytest.mark.plumbing
def test_out_of_u64_positive_int_still_fails_closed():
    """The pre-existing u64-range guard survives, now PRECEDED by the exact-int
    type check: an out-of-u64 positive int (2**64) still raises ValueError."""
    with pytest.raises(ValueError, match="(?i)fuel"):
        C.eval(_PATHOLOGICAL, fuel_budget=2**64)
