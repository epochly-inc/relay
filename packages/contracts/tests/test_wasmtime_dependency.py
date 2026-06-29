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
from packaging.requirements import Requirement

pytestmark = pytest.mark.plumbing

_DIST_NAME = "epochly-relay-contracts"

# The PEP 508 environment marker variable `extra` rendered by ``str(Marker)``
# always appears as a BARE identifier token (a comparison operand), never inside
# a quoted string. This pattern matches the `extra` VARIABLE while NOT matching
# the string VALUE "extra" (e.g. the contrived ``sys_platform == "extra"``),
# because a quoted value is preceded/followed by a quote character.
_EXTRA_MARKER_VARIABLE = re.compile(r"""(?<!['"\w])extra(?!['"\w])""")


def _requires_extra(req: Requirement) -> bool:
    """True if ``req``'s marker references the ``extra`` variable (optional dep).

    A runtime dependency under ``[project].dependencies`` carries no
    ``extra == "..."`` marker; an optional / extras dependency (declared under
    ``[project.optional-dependencies]``) DOES.

    Detection uses the public ``str(Marker)`` rendering (a stable, documented
    form) and matches the ``extra`` marker VARIABLE token -- not a quoted string
    value that merely happens to be the word ``extra``. An ``evaluate``-based
    probe is insufficient because it requires guessing the exact extra name the
    marker gates on; scanning the rendered marker for the variable token catches
    ANY extra-gated requirement regardless of the extra's name.
    """
    marker = req.marker
    if marker is None:
        return False
    return bool(_EXTRA_MARKER_VARIABLE.search(str(marker)))

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

    # Parse every Requires-Dist with PEP 508 semantics (packaging.Requirement)
    # rather than a prefix regex. The prefix regex `^wasmtime\b` accepted ANY
    # wasmtime line -- including one carrying an `extra == "..."` marker -- so
    # moving wasmtime to an OPTIONAL dependency group would have slipped past.
    # We require a TRUE runtime dependency: name == 'wasmtime' (PEP 503
    # normalized, case-insensitive), a NON-EMPTY version specifier, AND NO
    # `extra` marker (an extra-gated requirement is optional, not runtime).
    parsed: list[Requirement] = []
    for raw in reqs:
        try:
            parsed.append(Requirement(raw))
        except Exception as exc:  # noqa: BLE001 -- surface the offending line
            pytest.fail(f"Unparseable Requires-Dist {raw!r}: {exc}")

    def _normalized(name: str) -> str:
        # PEP 503 name normalization (lowercase; runs of -_. collapse to -).
        import re as _re  # noqa: PLC0415 -- local helper

        return _re.sub(r"[-_.]+", "-", name).lower()

    runtime_wasmtime = [
        r
        for r in parsed
        if _normalized(r.name) == "wasmtime" and not _requires_extra(r)
    ]
    assert runtime_wasmtime, (
        "No RUNTIME 'wasmtime' requirement (name == 'wasmtime', no `extra` "
        "marker) found in importlib.metadata.requires"
        f"('{_DIST_NAME}').\n"
        f"Current requirements: {reqs}\n"
        "Declare 'wasmtime>=...,<...' under [project].dependencies (NOT under "
        "[project.optional-dependencies]) in packages/contracts/pyproject.toml."
    )

    # The runtime requirement must carry a NON-EMPTY version specifier; a bare
    # 'wasmtime' with no specifier is not a pinned dependency.
    wasmtime_req = runtime_wasmtime[0]
    assert len(wasmtime_req.specifier) > 0, (
        f"wasmtime requirement '{wasmtime_req}' has no version specifier. "
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
