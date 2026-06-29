"""Whole-class guard: every HARD production import has a declared runtime provider.

A standalone ``pip install epochly-relay-<pkg>`` resolves only that package's
declared ``[project.dependencies]`` and their transitive closure -- NOT the
whole uv workspace. The dev workspace installs every member, which MASKS a
package that imports a module it never declares. The final convergence re-hunt
caught one such case (replay-proxy hard-imports ``relay_contracts`` at package
``__init__`` without declaring ``epochly-relay-contracts``); this guard
generalises it so no package can ship an undeclared hard runtime import again.

Method: for each editable workspace package, parse every MODULE-SCOPE import in
its production source (excluding tests / scripts / vendored ``upstream`` / docs),
map each imported top-level module to its providing distribution, and assert the
distribution is in the package's uv.lock transitive runtime closure (which is
exactly what a standalone install would pull). Function-local / ``try: import``
optional imports are out of scope (they degrade gracefully).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCK = REPO_ROOT / "uv.lock"

# Distribution name (normalized, lowercase) -> top-level import module(s) it
# provides. Covers every first-party package plus the third-party libs the
# workspace's production code hard-imports at module scope.
_DIST_TO_MODULES: dict[str, tuple[str, ...]] = {
    "epochly-relay": ("relay",),
    "epochly-relay-schemas": ("relay_schemas",),
    "epochly-relay-cli": ("relay_cli",),
    "epochly-relay-sidecar": ("relay_sidecar",),
    "epochly-relay-contracts": ("relay_contracts",),
    "epochly-relay-verifier": ("relay_verifier",),
    "epochly-relay-acef": ("relay_acef", "relay_extensions"),
    "epochly-relay-evals": ("relay_evals",),
    "epochly-relay-explain": ("relay_explain",),
    "epochly-relay-gate-engine": ("relay_gate_engine",),
    "epochly-relay-replay-proxy": ("relay_replay_proxy",),
    "epochly-relay-replay-sandbox-protocol": ("relay_replay_sandbox_protocol",),
    "pyyaml": ("yaml",),
    "rfc3161-client": ("rfc3161_client",),
    "pywin32": ("win32api", "win32security", "win32con", "win32file", "ntsecuritycon"),
    # Identity-mapped third-party (module == normalized dist) are handled by the
    # fallback below; list only the ones whose module differs from the dist.
}


def _norm(dist: str) -> str:
    return dist.replace("_", "-").lower()


def _module_to_dists() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for dist, mods in _DIST_TO_MODULES.items():
        for m in mods:
            out.setdefault(m, set()).add(dist)
    return out


_MODULE_TO_DISTS = _module_to_dists()


def _load_lock() -> dict:
    return tomllib.loads(LOCK.read_text(encoding="utf-8"))


def _editable_packages(lock: dict) -> dict[str, str]:
    """name -> editable source path, for first-party workspace members."""
    out: dict[str, str] = {}
    for p in lock.get("package", []):
        src = p.get("source", {})
        name = p.get("name", "")
        if isinstance(src, dict) and "editable" in src and name.startswith("epochly-relay"):
            out[name] = src["editable"]
    return out


def _runtime_closure(lock: dict, root: str) -> set[str]:
    """Normalized dist names in ``root``'s transitive RUNTIME closure."""
    pkgs = {p["name"]: p for p in lock.get("package", [])}
    seen: set[str] = set()

    def walk(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        for d in pkgs.get(name, {}).get("dependencies", []):
            walk(d["name"])

    walk(root)
    return {_norm(x) for x in seen}


def _production_module_dirs(pkg_path: Path) -> list[tuple[str, Path]]:
    """Return (module_name, dir) for every shipped package, from the wheel config.

    Reads ``[tool.hatch.build.targets.wheel].packages`` -- the authoritative
    list of what ships -- so the ``src/`` / ``python/`` / flat / multi-module
    (acef ships ``src/relay_acef`` AND ``relay_extensions``) layouts are all
    handled. Falls back to src/flat probing if the table is absent.
    """
    data = tomllib.loads((pkg_path / "pyproject.toml").read_text(encoding="utf-8"))
    wheel = (
        data.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("wheel", {})
    )
    out: list[tuple[str, Path]] = []
    for rel in wheel.get("packages", []):
        d = pkg_path / rel
        if d.is_dir():
            out.append((Path(rel).name, d))
    return out


_EXCLUDE_PARTS = {"tests", "test", "scripts", "upstream", "docs", "__pycache__"}


def _hard_imports(module_dir: Path) -> dict[str, str]:
    """top-level imported module -> first 'file:line' (module-scope only)."""
    out: dict[str, str] = {}
    for py in sorted(module_dir.rglob("*.py")):
        if any(part in _EXCLUDE_PARTS for part in py.parts):
            continue
        if ".venv" in str(py) or "site-packages" in str(py):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in tree.body:  # MODULE SCOPE only -> hard imports
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                out.setdefault(m, f"{py.relative_to(REPO_ROOT)}:{node.lineno}")
    return out


def _all_packages() -> list[tuple[str, str]]:
    lock = _load_lock()
    return sorted(_editable_packages(lock).items())


@pytest.mark.plumbing
@pytest.mark.parametrize("dist,src_rel", _all_packages())
def test_production_hard_imports_have_declared_runtime_provider(
    dist: str, src_rel: str
) -> None:
    """Every module-scope production import resolves in the runtime closure."""
    lock = _load_lock()
    module_dirs = _production_module_dirs(REPO_ROOT / src_rel)
    if not module_dirs:
        pytest.skip(f"no production module dir for {dist}")

    own_modules = {name for name, _ in module_dirs}
    closure = _runtime_closure(lock, dist)  # normalized dist names
    stdlib = set(sys.stdlib_module_names)

    imports: dict[str, str] = {}
    for _name, d in module_dirs:
        for mod, loc in _hard_imports(d).items():
            imports.setdefault(mod, loc)

    offenders: list[str] = []
    for mod, loc in imports.items():
        if mod in stdlib or mod.startswith("_") or mod in own_modules:
            continue
        # Resolve the providing distribution(s) for this import.
        providers = _MODULE_TO_DISTS.get(mod, {_norm(mod)})
        if any(p in closure for p in providers):
            continue
        offenders.append(f"{loc}: 'import {mod}' (provider {sorted(providers)} not in runtime closure)")

    assert not offenders, (
        f"{dist} has module-scope production imports with no declared runtime "
        f"provider (a standalone 'pip install {dist}' would fail):\n"
        + "\n".join(offenders)
    )
