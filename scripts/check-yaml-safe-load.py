#!/usr/bin/env python3
"""VAL-V3M5-011 lint: reject unqualified ``yaml.load(...)`` calls.

CLAUDE.md banned patterns + spec section AI.1 (line 5659) and PyYAML's
own security advisory require that every ``yaml.load(...)`` call uses an
explicit safe loader. Plain ``yaml.load(stream)`` defaults to ``yaml.Loader``
which permits arbitrary Python object construction -- a remote-code-execution
class vulnerability on attacker-controlled YAML.

This script AST-parses every ``.py`` file under ``packages/``, ``apps/``,
and ``scripts/`` (or a single ``--root`` directory for unit-test use) and
verifies that every ``yaml.load`` callsite either:

  1. Passes a ``Loader=`` keyword argument whose value resolves to
     ``yaml.SafeLoader`` or ``yaml.CSafeLoader`` (or the same names bound
     via ``from yaml import SafeLoader as ...``).
  2. Is itself ``yaml.safe_load`` -- a different call that does not need
     the kwarg.

Exit codes:
  0 -- every callsite passes.
  1 -- at least one offender found; rejected paths printed to stdout with
       line numbers and the offending call source.

Per the boundaries document (CLAUDE.md section "No Files in Project Root")
this script writes NOTHING -- its sole side effect is the exit code. It is
read-only.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterable
from pathlib import Path

# Repo root anchored on this file (scripts/check-yaml-safe-load.py).
_REPO_ROOT = Path(__file__).resolve().parent.parent

# Default scan roots per VAL-V3M5-011. Relative to repo root.
_DEFAULT_SCAN_DIRS: tuple[str, ...] = ("packages", "apps", "scripts")

# Directories to skip even when nested under a scan root. Build artefacts,
# generated trees, virtual envs, vendored upstream code, and __pycache__.
# Vendored upstream (e.g., packages/acef/upstream/) is governed by its own
# upstream lint policy; relay's lint must not regress it.
_SKIP_DIRS: frozenset[str] = frozenset({
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "upstream",
    "_generated",
})

# Loader-identifier suffixes that are considered safe. The lint matches on
# the final attribute name (so ``yaml.SafeLoader``, ``yaml.CSafeLoader``,
# and a bare ``SafeLoader`` imported via ``from yaml import SafeLoader``
# all qualify). Anything else (yaml.Loader, yaml.FullLoader,
# yaml.UnsafeLoader, custom Loader subclasses) is rejected.
_SAFE_LOADER_NAMES: frozenset[str] = frozenset({
    "SafeLoader",
    "CSafeLoader",
})


def _is_safe_loader_node(node: ast.AST) -> bool:
    """Return True if ``node`` refers to a known safe loader.

    Accepts:
      - ``ast.Attribute`` whose ``attr`` is in :data:`_SAFE_LOADER_NAMES`
        (e.g., ``yaml.SafeLoader``).
      - ``ast.Name`` whose ``id`` is in :data:`_SAFE_LOADER_NAMES`
        (e.g., ``SafeLoader`` imported directly).
    """
    if isinstance(node, ast.Attribute):
        return node.attr in _SAFE_LOADER_NAMES
    if isinstance(node, ast.Name):
        return node.id in _SAFE_LOADER_NAMES
    return False


def _is_yaml_load_call(node: ast.Call) -> bool:
    """Return True if ``node`` is a ``yaml.load(...)`` call (NOT safe_load).

    Matches ``yaml.load(...)`` (attribute access on a name ``yaml``) only.
    Excludes ``yaml.safe_load(...)`` because that function does not take a
    Loader kwarg. Excludes bare ``load(...)`` because too many unrelated
    libraries expose a ``load`` symbol (e.g., pickle, json, custom
    loaders); matching that name would produce false positives. Per
    VAL-V3M5-011 the spec contract is the fully-qualified
    ``yaml\\.load\\s*\\(`` form.
    """
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "load"
        and isinstance(func.value, ast.Name)
        and func.value.id == "yaml"
    )


def _call_has_safe_loader_kwarg(node: ast.Call) -> bool:
    """Return True if the call carries ``Loader=<safe loader>``."""
    return any(
        kw.arg == "Loader" and _is_safe_loader_node(kw.value)
        for kw in node.keywords
    )


def _scan_file(path: Path) -> list[dict[str, object]]:
    """AST-scan a single .py file. Return a list of violation dicts."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Unreadable file is not an offender; skip silently.
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        # Syntax-broken files are out of scope for this lint.
        return []
    violations: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_yaml_load_call(node):
            continue
        if _call_has_safe_loader_kwarg(node):
            continue
        # Extract the source snippet for the offending line, if possible.
        snippet = ""
        try:
            snippet = ast.unparse(node)
        except Exception:  # noqa: BLE001 - unparse can fail on exotic AST
            snippet = "yaml.load(...)"
        violations.append({
            "path": str(path),
            "lineno": node.lineno,
            "col": node.col_offset,
            "call": snippet,
        })
    return violations


def _iter_py_files(roots: Iterable[Path]) -> Iterable[Path]:
    """Yield every .py file under ``roots`` excluding skip dirs."""
    for root in roots:
        if not root.exists():
            continue
        # rglob walks the whole subtree; we filter skip dirs by checking
        # path parts.
        for p in root.rglob("*.py"):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if not p.is_file():
                continue
            yield p


def _resolve_scan_roots(repo_root: Path) -> list[Path]:
    """Default scan roots: packages/, apps/, scripts/ under repo root."""
    return [repo_root / d for d in _DEFAULT_SCAN_DIRS]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "VAL-V3M5-011 lint: reject unqualified yaml.load(...) calls."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=(
            "Override the scan root. When provided, the lint walks this "
            "directory exclusively. When omitted, the default scan roots "
            "(packages/, apps/, scripts/) under the repo are used."
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the pass summary line; violations still printed.",
    )
    args = parser.parse_args(argv)

    scan_roots = (
        [args.root.resolve()] if args.root is not None
        else _resolve_scan_roots(_REPO_ROOT)
    )

    violations: list[dict[str, object]] = []
    files_scanned = 0
    for path in _iter_py_files(scan_roots):
        files_scanned += 1
        violations.extend(_scan_file(path))

    if violations:
        print(
            f"[FAIL] check-yaml-safe-load: {len(violations)} offender(s) "
            f"across {files_scanned} files."
        )
        for v in violations:
            print(
                f"  {v['path']}:{v['lineno']}:{v['col']}: {v['call']}"
            )
        return 1

    if not args.quiet:
        print(
            f"[OK] check-yaml-safe-load: {files_scanned} files scanned; "
            f"0 unqualified yaml.load(...) calls."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
