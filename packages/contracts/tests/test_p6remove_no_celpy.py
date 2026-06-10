"""M6 WS-I guards: cel-python is fully excised from packages/contracts.

VAL-CWC-P6REMOVE-001: the cel-python runtime dependency is removed from
``packages/contracts/pyproject.toml``.
VAL-CWC-P6REMOVE-002: no live ``celpy`` import / reference remains in any
``relay_contracts`` source file; the wasm engine is the only Python CEL
backend; the legacy evaluator class is gone from the public surface.
VAL-CWC-P6REMOVE-003: the typed-canonical codec decodes to NATIVE Python
types (plus the minimal tagged wrappers) -- not celpy celtypes classes.

These guards are the structural fence against re-introduction: a future PR
that re-adds a celpy import, the dependency pin, or the legacy evaluator
fails tier-1.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.plumbing

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_DIR = REPO_ROOT / "packages" / "contracts"
PKG_SRC = PKG_DIR / "src" / "relay_contracts"

# The evidence-grep token set for VAL-CWC-P6REMOVE-001/-002 (contract.md):
# 'celpy|cel-python|cel_python'.
_REMOVAL_TOKEN = re.compile(r"celpy|cel-python|cel_python")


# ---------------------------------------------------------------------------
# VAL-CWC-P6REMOVE-001: dependency removed from pyproject.toml
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-001")
def test_pyproject_declares_no_cel_python_dependency() -> None:
    text = (PKG_DIR / "pyproject.toml").read_text(encoding="utf-8")
    hits = [
        f"line {lineno}: {line.rstrip()}"
        for lineno, line in enumerate(text.splitlines(), start=1)
        if _REMOVAL_TOKEN.search(line)
    ]
    assert hits == [], (
        "VAL-CWC-P6REMOVE-001: packages/contracts/pyproject.toml still "
        "references cel-python/celpy:\n  " + "\n  ".join(hits)
    )


# ---------------------------------------------------------------------------
# VAL-CWC-P6REMOVE-002: no live celpy import anywhere under relay_contracts
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-002")
def test_no_celpy_import_in_any_relay_contracts_module() -> None:
    """AST-level scan: no module under relay_contracts/ (including udfs/ and
    the vendored _wasm/ loader) imports celpy."""
    offenders: list[str] = []
    for py in sorted(PKG_SRC.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root == "celpy":
                        offenders.append(f"{py.relative_to(REPO_ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root == "celpy":
                    offenders.append(f"{py.relative_to(REPO_ROOT)}:{node.lineno}")
    assert offenders == [], (
        "VAL-CWC-P6REMOVE-002: live celpy import(s) remain:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-002")
def test_decisive_grep_scope_top_level_modules_token_free() -> None:
    """The evidence command is a TEXT grep over relay_contracts/*.py: even a
    comment containing 'celpy' / 'cel-python' / 'cel_python' fails it. Mirror
    that exactly (top-level glob, not recursive)."""
    hits: list[str] = []
    for py in sorted(PKG_SRC.glob("*.py")):
        for lineno, line in enumerate(
            py.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if _REMOVAL_TOKEN.search(line):
                hits.append(f"{py.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
    assert hits == [], (
        "VAL-CWC-P6REMOVE-002: removal-token match(es) in the decisive grep "
        "scope:\n  " + "\n  ".join(hits)
    )


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-002")
def test_legacy_evaluator_class_removed_from_public_surface() -> None:
    import relay_contracts

    assert not hasattr(relay_contracts, "RelayCelEvaluator"), (
        "VAL-CWC-P6REMOVE-002: the legacy celpy evaluator class is still "
        "exported from relay_contracts"
    )
    assert "RelayCelEvaluator" not in relay_contracts.__all__


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-002")
def test_explicit_celpy_engine_selection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The M5 rollback escape hatch is CLOSED at M6: an explicit legacy-engine
    selection is an unknown engine and fails closed with the factory's
    structured ValueError naming the (wasm-only) allowed set -- never a
    silent fallback and never the deleted class."""
    from relay_contracts import make_cel_evaluator

    monkeypatch.setenv("RELAY_CEL_ENGINE", "celpy")
    with pytest.raises(ValueError) as ctx:
        make_cel_evaluator(udfs=())
    msg = str(ctx.value)
    assert "wasm" in msg, f"allowed set not named: {msg}"
    assert "RELAY_CEL_ENGINE" in msg, f"env var not named: {msg}"


# ---------------------------------------------------------------------------
# VAL-CWC-P6REMOVE-003 (codec type layer): native Python decode targets
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-002")
def test_codec_decodes_to_native_python_types() -> None:
    """``typed_to_py`` returns NATIVE Python types (exact classes), with the
    minimal tagged wrappers only where natives cannot discriminate (uint).
    The wire form is unchanged; only the host-side type layer moved off
    celtypes."""
    from relay_contracts.wasm_codec import CelUint, typed_to_py

    decoded_int = typed_to_py({"t": "int", "v": "7"})
    assert type(decoded_int) is int, type(decoded_int).__name__

    decoded_bool = typed_to_py({"t": "bool", "v": True})
    assert type(decoded_bool) is bool, type(decoded_bool).__name__

    decoded_str = typed_to_py({"t": "string", "v": "x"})
    assert type(decoded_str) is str, type(decoded_str).__name__

    decoded_double = typed_to_py({"t": "double", "v": "1.5"})
    assert type(decoded_double) is float, type(decoded_double).__name__

    decoded_uint = typed_to_py({"t": "uint", "v": "7"})
    assert type(decoded_uint) is CelUint, type(decoded_uint).__name__


@pytest.mark.fulfills("VAL-CWC-P6REMOVE-002")
def test_codec_uint_round_trip_preserves_wire_tag() -> None:
    """The uint wrapper exists exactly so the round-trip keeps the distinct
    wire tag (an undiscriminated native int would re-encode as 'int' and
    change the engine-side bytes)."""
    from relay_contracts.wasm_codec import py_to_typed, typed_to_py

    wire = {"t": "uint", "v": "18446744073709551615"}
    assert py_to_typed(typed_to_py(wire)) == wire
