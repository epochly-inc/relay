"""G3: the CEL type-value model (cel-rust-relay fork), driven through the wasm.

cel 0.13 had no `type()` builtin and left the type identifiers (`int`, `uint`,
...) unbound, so `type(1)` was an UndeclaredReference and the ~33 cel-spec
`conversions`/`timestamps` type cases all failed. The fork adds a first-class
`Value::Type` (vendor/cel objects.rs + common/types/type_value.rs, marked
`Relay fork (G3)`) and qualified-name resolution in `Expr::Select`; the wrapper
(crate/src/lib.rs) registers `type(x)` and binds the type identifiers.

CEL type semantics asserted here (ground truth = the cel-go oracle, which emits
`{"t":"type","v": ref.Val.TypeName()}` for a `*types.Type`):

  - `type(x)` -> the type value of x's runtime type, by canonical NAME:
    int/uint/double/bool/string/bytes/null_type/list/map, the proto-qualified
    google.protobuf.{Timestamp,Duration}, and `type` for a type value (the
    meta-type).
  - type identifiers are themselves type values: bare `int` == `type(0)`.
  - type values compare by NAME: type(7) == type(7u) is false; type(0.0) ==
    type(-0.0) is true (both `double`); list/map types are monomorphic.
  - the runtime type of a type value is `type`: type(type(1)) == type.

Tier-1 plumbing; runs against the actual release wasm.
Run:  pytest packages/cel-wasm/tests -v
(requires `cargo build --release --target wasm32-unknown-unknown` in crate/)
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

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


def _type(name):
    return {"t": "type", "v": name}


def _val(cel, expr):
    r = cel.eval(expr)
    assert r["ok"], f"{expr!r} unexpectedly rejected: {r}"
    return r["value"]


def _bool(cel, expr):
    v = _val(cel, expr)
    assert v["t"] == "bool", f"{expr!r} -> {v}"
    return v["v"]


# --------------------------------------------------------------------------
# type(x): the runtime type of a value, as a type value with the cel-go name.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "expr,name",
    [
        ("type(0)", "int"),
        ("type(-7)", "int"),
        ("type(64u)", "uint"),
        ("type(3.14)", "double"),
        ("type(0.0)", "double"),
        ("type(true)", "bool"),
        ("type(false)", "bool"),
        ("type('foo')", "string"),
        ("type('')", "string"),
        (r"type(b'\xff')", "bytes"),
        ("type(null)", "null_type"),
        ("type([1, 2, 3])", "list"),
        ("type([])", "list"),
        ("type({4: 16})", "map"),
        ("type({})", "map"),
        # dyn() erasure does not change the runtime type.
        ("type(dyn([1, 'one']))", "list"),
        # the proto-qualified scalar names (cel-go TypeName()).
        ("type(timestamp('2009-02-13T23:31:30Z'))", "google.protobuf.Timestamp"),
        ("type(duration('1000000s'))", "google.protobuf.Duration"),
        # type of a type value is the meta-type `type`.
        ("type(type(1))", "type"),
        ("type(type(type(1)))", "type"),
    ],
)
def test_type_of_value(cel, expr, name):
    assert _val(cel, expr) == _type(name)


# --------------------------------------------------------------------------
# Type denotations: a bare type identifier resolves to its type value, and
# equals type(<a value of that type>).
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ident",
    ["int", "uint", "double", "bool", "string", "bytes", "list", "map",
     "null_type", "type"],
)
def test_type_denotation_resolves(cel, ident):
    assert _val(cel, ident) == _type(ident)


@pytest.mark.parametrize(
    "expr,ident",
    [
        ("type(0)", "int"),
        ("type(0u)", "uint"),
        ("type(0.0)", "double"),
        ("type(true)", "bool"),
        ("type('x')", "string"),
        (r"type(b'\x00')", "bytes"),
        ("type([0])", "list"),
        ("type({0: 0})", "map"),
        ("type(null)", "null_type"),
        ("type(type(0))", "type"),
    ],
)
def test_type_of_equals_denotation(cel, expr, ident):
    assert _bool(cel, f"{expr} == {ident}") is True


def test_dotted_type_denotations(cel):
    # google.protobuf.Timestamp / Duration resolve via the fork's qualified-name
    # lookup in Expr::Select.
    assert _val(cel, "google.protobuf.Timestamp") == _type(
        "google.protobuf.Timestamp"
    )
    assert _val(cel, "google.protobuf.Duration") == _type(
        "google.protobuf.Duration"
    )
    assert (
        _bool(
            cel,
            "google.protobuf.Timestamp == "
            "type(timestamp('2009-02-13T23:31:30Z'))",
        )
        is True
    )
    assert (
        _bool(
            cel,
            "google.protobuf.Duration == type(duration('1000000s'))",
        )
        is True
    )


# --------------------------------------------------------------------------
# Equality of type values is BY NAME.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "expr,expected",
    [
        # same type -> equal
        ("type(true) == type(false)", True),
        ("type(1) == type(2)", True),
        ("type('a') == type('bb')", True),
        # 0.0 and -0.0 are both `double`
        ("type(0.0) != type(-0.0)", False),
        # distinct numeric types are distinct type values
        ("type(7) == type(7u)", False),
        ("type(0.0) != type(0)", True),
        ("type(1) == type(1.0)", False),
        ("type(1) == type(1u)", False),
        # list / map types are monomorphic (element types are erased)
        ("type([1, 2, 3]) == type(['one', 'two', 'three'])", True),
        ("type({'one': 1}) == type({1: 'one'})", True),
        # meta: the type of two type values is the same `type`
        ("type(type(7)) == type(type(7u))", True),
        ("type(type(1)) == type", True),
        # a type value never equals a non-type value
        ("int == 1", False),
        ("type(1) == 'int'", False),
        ("type(1) == 1", False),
    ],
)
def test_type_equality_by_name(cel, expr, expected):
    assert _bool(cel, expr) is expected


# --------------------------------------------------------------------------
# A type value round-trips through a binding (serializer + deserializer
# symmetry; load-bearing for cross-host byte-parity).
# --------------------------------------------------------------------------
def test_type_value_binding_round_trip(cel):
    r = cel.eval("t == type(0)", {"t": {"t": "type", "v": "int"}})
    assert r["ok"], r
    assert r["value"] == {"t": "bool", "v": True}

    r2 = cel.eval("t == type(0)", {"t": {"t": "type", "v": "uint"}})
    assert r2["ok"], r2
    assert r2["value"] == {"t": "bool", "v": False}


# --------------------------------------------------------------------------
# Regression guard: G3 must not break the G6 cross-numeric core or the dyn
# shim (the type cases were built on top of both).
# --------------------------------------------------------------------------
def test_no_regression_g6_g2(cel):
    assert _bool(cel, "1.0 == 1") is True
    assert _bool(cel, "dyn(1) == dyn(1u)") is True
    assert _val(cel, "1 + 2") == {"t": "int", "v": "3"}
