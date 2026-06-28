"""W7 replay-proxy dependency-surface guards.

The localhost replay harness (``relay_replay_proxy``) is consumed in two
distinct ways:

* PRODUCTION: ``rly replay run`` spawns the harness to serve recorded
  cassette responses. Production code imports ``relay_sidecar`` (the
  ``local_atomic_file_write`` primitive for the CA cert/key, and the
  ``relay_sidecar.cassette`` parser/digest). It does NOT import
  ``relay_cli`` -- the cli<->replay-proxy import cycle was broken by
  relocating the cassette parser into ``relay_sidecar``.
* TEST-ONLY: the W7.5 exit-code / side-effect contract tests import the
  CLI's constants (``relay_cli.exit_codes``, ``relay_cli.commands.replay``)
  to assert cross-package contract parity.

Therefore ``epochly-relay-sidecar`` is a runtime dependency and
``epochly-relay-cli`` is a TEST-ONLY extra. Declaring the CLI in runtime
``[project.dependencies]`` would overstate the shipped dependency surface:
``pip install epochly-relay-replay-proxy`` would pull the entire CLI into a
production install that never imports it.

This guard locks that surface in place so a future edit cannot silently
re-broaden the runtime footprint. ASCII-only per CLAUDE.md "ASCII-Safe
Source".
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_DIR = REPO_ROOT / "apps" / "replay-proxy"
PROXY_PYPROJECT = PROXY_DIR / "pyproject.toml"
PROXY_PKG = PROXY_DIR / "relay_replay_proxy"


def _load() -> dict:
    return tomllib.loads(PROXY_PYPROJECT.read_text(encoding="utf-8"))


def _runtime_deps() -> list[str]:
    return list(_load()["project"]["dependencies"])


def _optional_deps() -> dict[str, list[str]]:
    return dict(_load()["project"].get("optional-dependencies", {}))


def _names(entries: list[str]) -> set[str]:
    """Reduce dependency specifiers to their bare distribution names."""
    out: set[str] = set()
    for entry in entries:
        # Strip version/marker/extras specifiers: name is everything up to
        # the first of [ ; < > = ! ~ ( space.
        name = entry
        for sep in ("[", ";", "<", ">", "=", "!", "~", "(", " "):
            name = name.split(sep, 1)[0]
        out.add(name.strip().lower())
    return out


@pytest.mark.plumbing
def test_sidecar_is_runtime_dependency() -> None:
    """``epochly-relay-sidecar`` MUST be a runtime dependency.

    Production code (cert_authority.py, cassette_server.py) imports
    ``relay_sidecar`` at module load, so it cannot be relegated to an extra.
    """
    assert "epochly-relay-sidecar" in _names(_runtime_deps()), (
        "epochly-relay-sidecar must stay in [project.dependencies]; "
        f"got {_runtime_deps()!r}"
    )


@pytest.mark.plumbing
def test_cli_is_not_a_runtime_dependency() -> None:
    """``epochly-relay-cli`` MUST NOT be in runtime ``[project.dependencies]``.

    Production ``relay_replay_proxy`` does not import ``relay_cli`` (only
    docstrings/comments reference it). Keeping it in runtime deps overstates
    the shipped surface.
    """
    assert "epochly-relay-cli" not in _names(_runtime_deps()), (
        "epochly-relay-cli must NOT be a runtime dependency (it is test-only); "
        f"got {_runtime_deps()!r}"
    )


@pytest.mark.plumbing
def test_cli_is_declared_in_test_extra() -> None:
    """``epochly-relay-cli`` MUST be declared in the ``test`` extra.

    The W7.5 contract tests import ``relay_cli`` constants, so the package
    must still pull the CLI when installed with ``[test]``.
    """
    test_extra = _optional_deps().get("test", [])
    assert "epochly-relay-cli" in _names(test_extra), (
        "epochly-relay-cli must be declared under "
        f"[project.optional-dependencies.test]; got {test_extra!r}"
    )


@pytest.mark.plumbing
def test_production_modules_do_not_import_relay_cli() -> None:
    """No production module may import ``relay_cli`` at runtime.

    Justifies the test-only placement: a real ``import relay_cli`` /
    ``from relay_cli ...`` statement anywhere under ``relay_replay_proxy/``
    would make the CLI a genuine runtime dependency and break the surface
    assertion above. Comment/docstring mentions are allowed.
    """
    offenders: list[str] = []
    for py in sorted(PROXY_PKG.rglob("*.py")):
        for lineno, raw in enumerate(
            py.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = raw.strip()
            if stripped.startswith("#"):
                continue
            if stripped.startswith("import relay_cli") or stripped.startswith(
                "from relay_cli"
            ):
                rel = py.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{lineno}: {stripped}")
    assert not offenders, (
        "production replay-proxy code must not import relay_cli at runtime; "
        "found:\n" + "\n".join(offenders)
    )
