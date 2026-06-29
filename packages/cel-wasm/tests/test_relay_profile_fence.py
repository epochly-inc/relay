"""Relay CEL profile call-fence + structured subtype envelope (WS4 step 2).

The wasm registers dyn()/timestamp()/duration() as working builtins so the
cel-spec conformance corpus (which uses them as legitimate spec calls) stays
green. The Relay PROFILE forbids those CALL forms -- the host's _check_profile
rejects them at compile. This moves that fence INTO the wasm, FLAG-GATED on
`relay_profile` so Python and TS reject the identical set by construction while
conformance (flag off) is unchanged. Rejections carry a structured `subtype`
(the (code, subtype) cross-runtime contract) so the host stops parsing message
strings.

tier-1 plumbing (runs against the real wasm).
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

C = RelayCel()

_DISABLED_CALLS = [
    ("dyn(1)", "RELAY-CEL-PROFILE-DYN-DISABLED"),
    ("timestamp('2009-02-13T23:31:30Z')", "RELAY-CEL-PROFILE-TS-DISABLED"),
    ("duration('60s')", "RELAY-CEL-PROFILE-DUR-DISABLED"),
]


@pytest.mark.plumbing
@pytest.mark.parametrize("expr,_subtype", _DISABLED_CALLS)
def test_disabled_calls_work_without_profile(expr, _subtype):
    # Flag OFF (conformance mode): the calls evaluate as spec builtins.
    r = C.eval(expr)
    assert r["ok"], f"{expr} unexpectedly rejected without profile: {r}"


@pytest.mark.plumbing
@pytest.mark.parametrize("expr,subtype", _DISABLED_CALLS)
def test_disabled_calls_rejected_under_profile(expr, subtype):
    # Flag ON: rejected with RELAY-CEL-002 + the matching subtype.
    r = C.eval(expr, relay_profile=True)
    assert r["ok"] is False, r
    assert r["code"] == "RELAY-CEL-002", r
    assert r["subtype"] == subtype, r


@pytest.mark.plumbing
def test_struct_fence_always_on_with_subtype():
    # Struct/message construction panics in cel 0.13 -> fenced ALWAYS (both flag
    # states), now carrying the STRUCT subtype.
    for profile in (False, True):
        r = C.eval("Foo{a: 1}", relay_profile=profile)
        assert r["ok"] is False, r
        assert r["code"] == "RELAY-CEL-002", r
        assert r["subtype"] == "RELAY-CEL-PROFILE-STRUCT-DISABLED", r


@pytest.mark.plumbing
def test_non_profile_errors_have_no_subtype():
    # A plain compile error carries no subtype field (only profile rejections do).
    r = C.eval("1 +", relay_profile=True)
    assert r["ok"] is False
    assert r["code"] == "RELAY-CEL-001", r
    assert "subtype" not in r, r


@pytest.mark.plumbing
def test_profile_does_not_disable_normal_constructs():
    # Arithmetic, comparison, UDFs, and timestamp/duration VALUE bindings (not
    # calls) stay valid under the profile -- only the global CALL form is fenced.
    assert C.eval("1 + 2", relay_profile=True) == {"ok": True, "value": {"t": "int", "v": "3"}}
    assert C.eval(
        'relay.coverage({"steps": [{"name": "a"}]}, "a")', relay_profile=True
    )["value"] == {
        "t": "bool", "v": True,
    }
    ts = {"t": "timestamp", "v": "2009-02-13T23:31:30Z"}
    assert C.eval("x == x", {"x": ts}, relay_profile=True)["value"] == {"t": "bool", "v": True}
    dur = {"t": "duration", "v": "60.000000000"}
    assert C.eval("x == x", {"x": dur}, relay_profile=True)["value"] == {"t": "bool", "v": True}


@pytest.mark.plumbing
def test_disabled_call_nested_in_expression_is_caught():
    # The fence walks the whole AST, not just the top node.
    r = C.eval("[1, dyn(2), 3]", relay_profile=True)
    assert r["ok"] is False and r["subtype"] == "RELAY-CEL-PROFILE-DYN-DISABLED", r
    r2 = C.eval('size(duration("1h")) > 0 || true', relay_profile=True)
    assert r2["ok"] is False and r2["subtype"] == "RELAY-CEL-PROFILE-DUR-DISABLED", r2
