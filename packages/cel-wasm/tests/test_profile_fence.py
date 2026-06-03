"""Tier-1 plumbing tests for relay-cel-wasm: the G1 proto/struct fence and the
WS2 easy shims, driven through the actual wasm via the Python loader.

The G1 fence is the load-bearing SAFETY property: cel 0.13 PANICS (wasm trap)
on struct/message construction (objects.rs `Expr::Struct(_) => todo!()`,
map StructField `panic!("WAT?")`). A panic in an evidence-grade evaluator is a
P0 DoS surface. These tests assert that every such input returns a CLEAN
RELAY-CEL-002 error envelope, NOT an ENGINE_PANIC.

Run:  pytest packages/cel-wasm/tests -v
(requires the wasm built: cargo build --release --target wasm32-unknown-unknown)
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

# Tier-1 plumbing: offline, deterministic, runs against the local wasm in <1s.
pytestmark = pytest.mark.plumbing


@pytest.fixture(scope="module")
def cel():
    wasm = os.path.normpath(
        os.path.join(
            _HERE,
            "..",
            "crate",
            "target",
            "wasm32-unknown-unknown",
            "release",
            "relay_cel_wasm.wasm",
        )
    )
    if not os.path.exists(wasm):
        pytest.skip(
            "wasm not built: run "
            "`cargo build --release --target wasm32-unknown-unknown` "
            "in packages/cel-wasm/crate"
        )
    return RelayCel(wasm)


# --------------------------------------------------------------------------
# G1: proto/struct construction must be FENCED to a clean error, never a panic.
# --------------------------------------------------------------------------

PROFILE_REJECTED = [
    # The two cases the WS2 brief names explicitly.
    "google.protobuf.BoolValue{value: true} == true",
    "Foo{a: 1}",
    # The non-proto message-construction panic root (Value{...}).
    "google.protobuf.Value{}",
    # Struct embedded as a list element.
    "[Foo{a: 1}]",
    # Struct embedded as a map key (the `panic!(\"WAT?\")` path).
    "{Foo{}: 1}",
    # Struct as a function argument / nested in a comprehension range.
    "size(Foo{a: 1})",
]


@pytest.mark.parametrize("expr", PROFILE_REJECTED)
def test_struct_construction_is_fenced_not_panicked(cel, expr):
    out = cel.eval(expr)
    # Must be a structured error, not a value and not a panic.
    assert out["ok"] is False, f"{expr!r} should be rejected, got {out!r}"
    assert out.get("code") == "RELAY-CEL-002", f"{expr!r} -> {out!r}"
    assert (
        out.get("error") != "ENGINE_PANIC"
    ), f"{expr!r} TRAPPED the engine (G1 regression): {out!r}"
    assert "STRUCT-DISABLED" in out.get("error", ""), out


def test_no_panic_marker_anywhere_in_fence(cel):
    """A panic would surface as ENGINE_PANIC with code RELAY-CEL-PANIC. None of
    the fenced inputs may produce it."""
    for expr in PROFILE_REJECTED:
        out = cel.eval(expr)
        assert out.get("code") != "RELAY-CEL-PANIC", (expr, out)


# --------------------------------------------------------------------------
# G2: dyn(x) = x identity shim.
# --------------------------------------------------------------------------


def test_dyn_identity_int(cel):
    out = cel.eval("dyn(1)")
    assert out["ok"] is True
    assert out["value"] == {"t": "int", "v": "1"}


def test_dyn_identity_list(cel):
    out = cel.eval("dyn([1, 2, 3])")
    assert out["ok"] is True
    assert out["value"]["t"] == "list"


# --------------------------------------------------------------------------
# G9: double -> string canonical (Go strconv 'g') format.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr,expected",
    [
        ("double(1000000000000)", "1e+12"),
        ("1e6", "1e+06"),
        ("100000.0", "100000.0"),
        ("999999.0", "999999.0"),
        ("0.0001", "0.0001"),
        ("1e-5", "1e-05"),
        ("1.5", "1.5"),
        ("3.0", "3.0"),
    ],
)
def test_double_canonical_format(cel, expr, expected):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "double", "v": expected}, (expr, out)


# --------------------------------------------------------------------------
# G11: size() counts Unicode code points, not UTF-8 bytes (for strings).
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr,n",
    [
        ("size('abc')", 3),  # ASCII
        ("size('ÿ')", 1),  # U+00FF is 2 UTF-8 bytes, 1 code point
        ("size('αβγ')", 3),  # 3 Greek letters, 6 UTF-8 bytes
        ("size(b'\\x00\\xff')", 2),  # bytes keep byte count
        ("size([1, 2, 3])", 3),  # list keeps element count
        ("'ÿ'.size()", 1),  # method form still code points
    ],
)
def test_size_code_points(cel, expr, n):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "int", "v": str(n)}, (expr, out)


# --------------------------------------------------------------------------
# G12: idempotent conversion overloads.
# --------------------------------------------------------------------------


def test_bytes_idempotent(cel):
    out = cel.eval("bytes(b'abc')")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bytes", "v": "616263"}


def test_duration_idempotent(cel):
    out = cel.eval("duration(duration('100s'))")
    assert out["ok"] is True, out
    assert out["value"]["t"] == "duration"


def test_timestamp_idempotent(cel):
    out = cel.eval("timestamp(timestamp('2009-02-13T23:31:30Z'))")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "timestamp", "v": "2009-02-13T23:31:30Z"}


# --------------------------------------------------------------------------
# G14: timestamp -> string canonical uses 'Z' UTC suffix, not '+00:00'.
# --------------------------------------------------------------------------


def test_timestamp_z_suffix(cel):
    out = cel.eval("timestamp('2009-02-13T23:31:30Z')")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "timestamp", "v": "2009-02-13T23:31:30Z"}
    assert "+00:00" not in out["value"]["v"]


# --------------------------------------------------------------------------
# Sanity: ordinary CEL still evaluates (no regression from the shims).
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr,value",
    [
        ("1 + 2", {"t": "int", "v": "3"}),
        ("'a' + 'b'", {"t": "string", "v": "ab"}),
        ("[1, 2, 3].map(x, x * 2)", None),  # checked below
        ("[1, 2, 3].exists(x, x > 2)", {"t": "bool", "v": True}),
    ],
)
def test_basic_cel_unbroken(cel, expr, value):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    if value is not None:
        assert out["value"] == value, (expr, out)


# --------------------------------------------------------------------------
# Bindings round-trip through the typed protocol.
# --------------------------------------------------------------------------


def test_bindings_typed(cel):
    out = cel.eval("x + 1", {"x": {"t": "int", "v": "41"}})
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "42"}
