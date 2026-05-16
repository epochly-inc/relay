"""W17.4 weak-form idiom-coverage analyzer.

Per VAL-W17-019 and gap #4 reconciliation, the v0.1 scope of this
analyzer is the WEAK form: scan ``relay/packages/contracts/`` for
CEL expression strings, extract the set of UDFs referenced (calls of
the form ``relay.<udf>(...)``), and return the set. The test that
consumes this analyzer asserts every found UDF has a corresponding
case directory under ``tests/conformance/cel/relay-udfs/``.

The full CEL-idiom taxonomy (every operator, builtin, type coercion,
comprehension, regex pattern) is deferred to v0.2 -- see
``README.md`` in this directory for rationale.

Scan surface:
  - All ``*.py`` files under ``relay/packages/contracts/`` (source + tests).
  - All ``*.ts`` files under ``relay/packages/contracts-typescript/``.

UDF extraction regex matches identifiers of the form ``relay.NAME(``
where ``NAME`` is one or more word characters. Match positions are
preserved for diagnostic output.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Match any reference to a Relay UDF callsite: ``relay.<name>(``.
# Anchored to a word boundary on the left to avoid matching
# unrelated dotted identifiers (e.g. ``my_relay.coverage`` is not a
# Relay UDF call).
_UDF_CALL_RE = re.compile(r"(?<![A-Za-z0-9_])relay\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass(frozen=True)
class UdfReference:
    """A single textual reference to a Relay UDF call site."""

    udf: str
    path: Path
    line: int


def _iter_source_files(root: Path, packages: Iterable[str]) -> list[Path]:
    """Return every source file under each named package directory."""

    files: list[Path] = []
    for pkg in packages:
        pkg_root = root / "packages" / pkg
        if not pkg_root.exists():
            continue
        for path in pkg_root.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            if "node_modules" in path.parts:
                continue
            # Skip TypeScript build output -- the analyzer scans
            # source files, not generated dist/.
            if "dist" in path.parts:
                continue
            if path.suffix in (".py", ".ts", ".tsx", ".mts", ".cts"):
                files.append(path)
    return files


def find_udf_references(repo_root: Path) -> list[UdfReference]:
    """Return every Relay UDF call-site reference reachable from
    ``packages/contracts/`` and ``packages/contracts-typescript/``."""

    refs: list[UdfReference] = []
    packages = ("contracts", "contracts-typescript")
    for path in _iter_source_files(repo_root, packages):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _UDF_CALL_RE.finditer(line):
                name = m.group("name")
                refs.append(
                    UdfReference(
                        udf=f"relay.{name}",
                        path=path,
                        line=lineno,
                    )
                )
    return refs


def find_referenced_udfs(repo_root: Path) -> set[str]:
    """Return the set of distinct UDF dotted names referenced from
    packages/contracts/ + packages/contracts-typescript/."""

    return {r.udf for r in find_udf_references(repo_root)}


__all__ = [
    "UdfReference",
    "find_referenced_udfs",
    "find_udf_references",
]
