"""Local-sidecar dependency-surface guards.

The sidecar is the local control-plane process (loopback HTTP, single-writer
SQLite, the file-based event log, the three-anchor handoff validator). It is
published as ``epochly-relay-sidecar`` and is also consumed as a workspace
dependency by the SDK, the CLI, the gate engine, and the replay-proxy.

Two invariants this module locks:

1. The sidecar MUST NOT runtime-depend on ``epochly-relay`` (the SDK).
   The SDK already runtime-depends on the sidecar
   (``relay_sidecar.spawn.acquire_or_attach``); a reciprocal sidecar -> SDK
   runtime edge forms a package-level cycle. The only historical reason for
   the edge -- the server-side ReDoS budget enforcement reusing
   ``relay.redaction_budget.evaluate_matcher_budget`` -- went away when
   ``redaction_budget`` was relocated to ``relay_schemas`` (already a sidecar
   dependency). Re-introducing the SDK edge would re-create the cycle and
   needlessly re-pin the sidecar's standalone floor to the SDK's
   CVE-2024-4032 floor.

2. The sidecar reuses the ReDoS budget from ``relay_schemas.redaction_budget``,
   not a forked copy and not the old ``relay.redaction_budget`` path.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SIDECAR_DIR = REPO_ROOT / "apps" / "local-sidecar"
SIDECAR_PYPROJECT = SIDECAR_DIR / "pyproject.toml"
SIDECAR_PKG = SIDECAR_DIR / "relay_sidecar"


def _runtime_dep_names() -> set[str]:
    data = tomllib.loads(SIDECAR_PYPROJECT.read_text(encoding="utf-8"))
    out: set[str] = set()
    for spec in data["project"]["dependencies"]:
        name = spec
        for sep in ("[", ";", "<", ">", "=", "!", "~", "(", " "):
            name = name.split(sep, 1)[0]
        out.add(name.strip().lower())
    return out


@pytest.mark.plumbing
def test_sidecar_does_not_runtime_depend_on_sdk() -> None:
    """``epochly-relay`` (the SDK) MUST NOT be a sidecar runtime dependency.

    A sidecar -> SDK runtime edge re-creates the SDK <-> sidecar package
    cycle (the SDK already depends on the sidecar). ``epochly-relay-schemas``
    is the correct lower-layer home for the shared ReDoS budget.
    """
    deps = _runtime_dep_names()
    assert "epochly-relay" not in deps, (
        "epochly-relay (the SDK) must NOT be a sidecar runtime dependency "
        "(it forms a package cycle and over-pins the standalone floor); "
        f"got {sorted(deps)!r}"
    )
    # The schemas package -- the correct home for the shared budget -- must
    # remain a runtime dependency.
    assert "epochly-relay-schemas" in deps, (
        "epochly-relay-schemas must stay a sidecar runtime dependency; "
        f"got {sorted(deps)!r}"
    )


@pytest.mark.plumbing
def test_sidecar_production_does_not_import_sdk() -> None:
    """No production sidecar module may import the SDK (``relay``) at runtime."""
    offenders: list[str] = []
    for py in sorted(SIDECAR_PKG.rglob("*.py")):
        for lineno, raw in enumerate(
            py.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = raw.strip()
            if stripped.startswith("#"):
                continue
            # Match the SDK package `relay` but NOT relay_sidecar / relay_schemas
            # / relay_cli / relay_contracts etc.
            if re.match(r"^(import relay|from relay)(\s|\.|$)", stripped):
                offenders.append(f"{py.relative_to(REPO_ROOT)}:{lineno}: {stripped}")
    assert not offenders, (
        "production sidecar code must not import the SDK (relay) at runtime; "
        "found:\n" + "\n".join(offenders)
    )


@pytest.mark.plumbing
def test_sidecar_uses_relay_schemas_redaction_budget() -> None:
    """The ReDoS budget MUST be imported from ``relay_schemas.redaction_budget``.

    Locks the relocation that made the SDK runtime edge removable: if a future
    edit re-points this back to ``relay.redaction_budget`` the sidecar would
    again hard-depend on the SDK.
    """
    runtime_py = SIDECAR_PKG / "runtime.py"
    text = runtime_py.read_text(encoding="utf-8")
    assert "from relay_schemas.redaction_budget import" in text, (
        "sidecar runtime.py must import the ReDoS budget from "
        "relay_schemas.redaction_budget"
    )
    # The old SDK path must not reappear as a real import.
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        assert not re.match(
            r"^(from relay\.redaction_budget|import relay\.redaction_budget)",
            stripped,
        ), f"runtime.py:{lineno} still imports the relocated SDK path: {stripped}"
