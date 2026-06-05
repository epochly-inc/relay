"""Guard test: ``wasmtime`` declared as a pinned runtime dependency.

Verifies VAL-CWC-P1HOST-012: ``packages/contracts/pyproject.toml`` declares
``wasmtime`` as a real dependency under ``[project].dependencies`` (not only in
a dev/optional group), pinned to a tested version range, so a fresh install of
packages/contracts can construct ``WasmCelEvaluator`` without an undeclared
import.

Two assertions (both must hold simultaneously):

  (a) METADATA assertion: ``importlib.metadata.requires('epochly-relay-contracts')``
      lists a ``wasmtime`` requirement that carries a version constraint. This
      bites as soon as anyone deletes the ``wasmtime`` line from pyproject.toml
      (because uv regenerates the installed metadata from pyproject.toml).

  (b) RUNTIME assertion: ``import wasmtime`` succeeds in the environment AND
      ``WasmCelEvaluator(timeout_ms=50, udfs=())`` constructs without error,
      proving the declared dependency is present and the facade is wirable.

This test is ``pytestmark = pytest.mark.plumbing`` so it runs under
``-m plumbing`` and is NEVER deselected. It carries no network calls, no
side effects, and no I/O beyond in-process imports.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.metadata
import re

import pytest

pytestmark = pytest.mark.plumbing

_DIST_NAME = "epochly-relay-contracts"

# ---------------------------------------------------------------------------
# (a) Metadata assertion: wasmtime present as a runtime requirement with a
#     version constraint under [project].dependencies.
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P1HOST-012")
def test_wasmtime_declared_as_runtime_dependency_with_version_constraint() -> None:
    """``importlib.metadata.requires`` for the contracts package lists a
    ``wasmtime`` requirement carrying a version constraint.

    If someone deletes the wasmtime line from pyproject.toml the installed
    metadata regenerates without it and this test fails immediately on the
    next ``uv sync`` cycle.
    """
    reqs = importlib.metadata.requires(_DIST_NAME)
    assert reqs is not None, (
        f"Distribution '{_DIST_NAME}' has no requirements list; "
        "it may not be installed or may be missing metadata."
    )

    # Find any requirement whose bare name is 'wasmtime' (case-insensitive
    # per PEP 508 normalized names).
    wasmtime_reqs = [r for r in reqs if re.match(r"(?i)^wasmtime\b", r.strip())]
    assert wasmtime_reqs, (
        f"No 'wasmtime' requirement found in "
        f"importlib.metadata.requires('{_DIST_NAME}').\n"
        f"Current requirements: {reqs}\n"
        "Add 'wasmtime>=...,<...' under [project].dependencies in "
        "packages/contracts/pyproject.toml."
    )

    # The requirement must carry a version constraint (not just 'wasmtime').
    # A bare 'wasmtime' with no specifier would not constitute a pinned dep.
    wasmtime_req = wasmtime_reqs[0]
    has_version_constraint = bool(re.search(r"[><=!]", wasmtime_req))
    assert has_version_constraint, (
        f"wasmtime requirement '{wasmtime_req}' has no version constraint. "
        "Pin it, e.g. 'wasmtime>=45,<46', under [project].dependencies."
    )


# ---------------------------------------------------------------------------
# (b) Runtime assertion: import wasmtime + WasmCelEvaluator constructs.
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P1HOST-012")
def test_wasmtime_importable_and_wasm_evaluator_constructs() -> None:
    """``import wasmtime`` succeeds AND ``WasmCelEvaluator(timeout_ms=50,
    udfs=())`` constructs without error.

    This confirms the declared dependency resolves to a working package and
    the wasm-backed evaluator facade wires up cleanly.
    """
    import wasmtime  # noqa: F401  (imported for side-effect: raises ImportError if absent)
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    evaluator = WasmCelEvaluator(timeout_ms=50, udfs=())
    assert evaluator is not None, "WasmCelEvaluator(timeout_ms=50, udfs=()) returned None"
    assert evaluator.timeout_ms == 50, (
        f"Expected timeout_ms=50, got {evaluator.timeout_ms}"
    )
