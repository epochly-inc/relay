"""Tier-1 plumbing tests for G16 container / namespace resolution, driven
through the actual wasm via the loader.

Closes the namespace ex-proto tail against the cel-go oracle / cel-spec
namespace.textproto ground truth. CEL name resolution order (cel-go
containers.ResolveCandidateNames + comprehension scoping):

  1. A comprehension/lambda iteration variable SHADOWS the namespace: inside
     exists(y, ...), a bare `y` is the iteration value, and `y.z` is field
     selection on it -- even when a `y.z` binding exists at the root.
  2. A leading-dot name (`.y`) is ABSOLUTE: it escapes the container AND any
     comprehension scope, resolving at the root only.
  3. With a container `C = a.b`, a name `n` resolves most-qualified to least:
     `a.b.n`, `a.n`, then bare `n`. A container-qualified binding takes
     precedence over the bare name.

The container is now forwarded into the wasm via the request `container` field.
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
            _HERE, "..", "crate", "target", "wasm32-unknown-unknown",
            "release", "relay_cel_wasm.wasm",
        )
    )
    if not os.path.exists(wasm) and not os.environ.get("CEL_WASM"):
        pytest.skip("wasm not built")
    return RelayCel(wasm)


# --- container resolution (bare ident, most-qualified to least) -----------

def test_container_lookup_prefers_qualified(cel):
    # container 'x', bindings x.y=true, y="false"; bare y -> x.y (true).
    out = cel.eval(
        "y",
        {"x.y": {"t": "bool", "v": True}, "y": {"t": "string", "v": "false"}},
        container="x",
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_container_lookup_dotted_container(cel):
    # container 'com.example', bindings com.example.y=true, y="string".
    out = cel.eval(
        "y",
        {"com.example.y": {"t": "bool", "v": True},
         "y": {"t": "string", "v": "string"}},
        container="com.example",
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_container_falls_back_to_bare(cel):
    # No container-qualified binding -> the bare y is used.
    out = cel.eval("y", {"y": {"t": "int", "v": "7"}}, container="x")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "7"}, out


def test_no_container_uses_bare(cel):
    out = cel.eval("y", {"y": {"t": "int", "v": "7"}})
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "7"}, out


# --- comprehension variable shadows the namespace -------------------------

def test_comprehension_var_shadows_container(cel):
    # [0].exists(y, y == 0), container com.example, com.example.y=42.
    # y is the iteration value (0), not com.example.y.
    out = cel.eval(
        "[0].exists(y, y == 0)",
        {"com.example.y": {"t": "int", "v": "42"}},
        container="com.example",
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_comprehension_var_shadows_selector(cel):
    # [{'z':0}].exists(y, y.z==0) with y.z=42 binding: y is {'z':0}, y.z=0.
    out = cel.eval(
        "[{'z': 0}].exists(y, y.z == 0)",
        {"y.z": {"t": "int", "v": "42"}},
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


# --- leading-dot is absolute (escapes comprehension + container) ----------

def test_leading_dot_escapes_comprehension(cel):
    # ['compre'].exists(y, .y == 'y'); .y is the ROOT binding y="y", not the
    # iteration variable y='compre'.
    out = cel.eval(
        "['compre'].exists(y, .y == 'y')",
        {"y": {"t": "string", "v": "y"}},
        container="com.example",
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_leading_dot_root(cel):
    out = cel.eval(".y", {"y": {"t": "string", "v": "root"}})
    assert out["ok"] is True, out
    assert out["value"] == {"t": "string", "v": "root"}, out


def test_leading_dot_qualified_absolute(cel):
    # [{'z':'compre'}].exists(y, .y.z == 'y.z'), container com.example,
    # bindings com.example.y.z and y.z. The leading dot is ABSOLUTE: .y.z is the
    # ROOT binding y.z='y.z' (NOT com.example.y.z, NOT the iteration var y).
    out = cel.eval(
        "[{'z': 'compre'}].exists(y, .y.z == 'y.z')",
        {"com.example.y.z": {"t": "string", "v": "com.example.y.z"},
         "y.z": {"t": "string", "v": "y.z"}},
        container="com.example",
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


# --- regression: qualified TYPE denotations + plain x.y bindings -----------

def test_qualified_type_denotation_unchanged(cel):
    out = cel.eval("type(timestamp(0)) == google.protobuf.Timestamp")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_qualified_binding_unchanged(cel):
    out = cel.eval("x.y", {"x.y": {"t": "bool", "v": True}})
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_plain_comprehension_no_shadow(cel):
    out = cel.eval("[0].exists(y, y == 0)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out
