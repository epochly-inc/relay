#!/usr/bin/env python3
"""AST lint: no network awaits inside DB transaction blocks (VAL-W2-021).

Static analysis MUST find zero ``await httpx.*`` /
``await asyncio.open_connection`` / any other network primitive inside the
body of an ``async with conn.transaction()`` block in
``apps/local-sidecar/``.

This sidecar uses an explicit BEGIN IMMEDIATE / COMMIT idiom (not aiosqlite's
``conn.transaction()`` context manager), so this lint generalises to ANY
identifier-flow that pairs an ``await conn.execute("BEGIN IMMEDIATE")`` with a
subsequent ``await conn.execute("COMMIT" | "ROLLBACK")``. We treat the entire
async function body as the transaction-bearing region whenever it contains
both a BEGIN IMMEDIATE call AND a COMMIT/ROLLBACK call on the same identifier.

Implementation:

  1. Parse each .py file under the sidecar package.
  2. For every async function:
     a. Find every ``await CONN.execute("BEGIN IMMEDIATE")`` call.
     b. Find every ``await CONN.execute("COMMIT")`` /
        ``await CONN.execute("ROLLBACK")`` call.
     c. Find every ``async with CONN.transaction():`` block.
     d. Inside the begin..commit/rollback region (or transaction block),
        scan for banned ``await`` targets.

Banned await targets (dotted-name regex matched against ast.unparse):
    httpx.*
    asyncio.open_connection
    asyncio.start_server
    socket.*
    urllib.*
    requests.*
    aiohttp.*

Exit code:
  0 -> zero violations
  1 -> at least one violation; details printed to stderr

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Banned dotted-name prefixes for await targets. We match by prefix because
# the surface is open (httpx.AsyncClient.post, httpx.get, ...).
BANNED_PREFIXES: tuple[str, ...] = (
    "httpx.",
    "asyncio.open_connection",
    "asyncio.start_server",
    "socket.",
    "urllib.",
    "requests.",
    "aiohttp.",
)


@dataclass(frozen=True)
class Violation:
    file: Path
    line: int
    column: int
    function: str
    target: str
    detail: str


def _dotted(node: ast.expr) -> str | None:
    """Return the dotted-name representation of ``node``, if statically known."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        if head is None:
            return None
        return f"{head}.{node.attr}"
    return None


def _is_banned(dotted: str) -> bool:
    """Return True if ``dotted`` matches a banned prefix."""
    return any(dotted.startswith(p) for p in BANNED_PREFIXES)


def _const_str_arg(call: ast.Call) -> str | None:
    """Return the lower-cased string constant argument at position 0, if any."""
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.strip().lower()
    return None


_BEGIN_IMMEDIATE_RE = re.compile(r"^\s*begin\s+immediate\b")
_COMMIT_RE = re.compile(r"^\s*commit\b")
_ROLLBACK_RE = re.compile(r"^\s*rollback\b")


def _is_begin_immediate_call(call: ast.Call) -> bool:
    """``conn.execute("BEGIN IMMEDIATE")`` -> True."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
        return False
    arg = _const_str_arg(call)
    return arg is not None and bool(_BEGIN_IMMEDIATE_RE.match(arg))


def _is_commit_or_rollback_call(call: ast.Call) -> bool:
    """``conn.execute("COMMIT")`` / ``conn.execute("ROLLBACK")`` -> True."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
        return False
    arg = _const_str_arg(call)
    if arg is None:
        return False
    return bool(_COMMIT_RE.match(arg) or _ROLLBACK_RE.match(arg))


def _is_transaction_async_with(node: ast.AsyncWith) -> bool:
    """``async with CONN.transaction():`` -> True."""
    for item in node.items:
        ctx = item.context_expr
        if isinstance(ctx, ast.Call):
            ctx = ctx.func
        dotted = _dotted(ctx) if isinstance(ctx, ast.Attribute | ast.Name) else None
        if dotted is not None and dotted.endswith(".transaction"):
            return True
    return False


def _walk_async_function(
    func: ast.AsyncFunctionDef,
    path: Path,
) -> list[Violation]:
    """Walk one async function looking for banned awaits inside txn regions."""
    violations: list[Violation] = []

    # Collect line numbers of BEGIN IMMEDIATE and COMMIT/ROLLBACK calls.
    begin_lines: list[int] = []
    end_lines: list[int] = []
    transaction_blocks: list[tuple[int, int]] = []  # (start_line, end_line)

    for child in ast.walk(func):
        if isinstance(child, ast.Await) and isinstance(child.value, ast.Call):
            call = child.value
            if _is_begin_immediate_call(call):
                begin_lines.append(call.lineno)
            elif _is_commit_or_rollback_call(call):
                end_lines.append(call.lineno)
        elif isinstance(child, ast.AsyncWith) and _is_transaction_async_with(child):
            start = child.lineno
            end = max((getattr(stmt, "end_lineno", start) for stmt in child.body), default=start)
            transaction_blocks.append((start, end))

    # Pair every begin with the NEXT end (lexically). Unpaired begins
    # extend to the end of the function body (assume catch-all-rollback in
    # an except handler).
    function_end = getattr(func, "end_lineno", func.lineno)
    txn_regions: list[tuple[int, int]] = list(transaction_blocks)
    begin_lines_sorted = sorted(begin_lines)
    end_lines_sorted = sorted(end_lines)
    used_ends: set[int] = set()
    for b in begin_lines_sorted:
        chosen: int | None = None
        for i, e in enumerate(end_lines_sorted):
            if i in used_ends:
                continue
            if e >= b:
                chosen = e
                used_ends.add(i)
                break
        txn_regions.append((b, chosen if chosen is not None else function_end))

    if not txn_regions:
        return violations

    # Scan for banned awaits whose line falls inside any txn region.
    for child in ast.walk(func):
        if not isinstance(child, ast.Await):
            continue
        target_node = child.value
        if isinstance(target_node, ast.Call):
            target_node = target_node.func
        dotted = _dotted(target_node)
        if dotted is None or not _is_banned(dotted):
            continue
        line = getattr(child, "lineno", 0)
        col = getattr(child, "col_offset", 0)
        for start, end in txn_regions:
            if start <= line <= end:
                violations.append(
                    Violation(
                        file=path,
                        line=line,
                        column=col,
                        function=func.name,
                        target=dotted,
                        detail=(
                            f"network await inside DB transaction region "
                            f"(lines {start}..{end})"
                        ),
                    )
                )
                break

    return violations


def lint_paths(paths: Iterable[Path]) -> list[Violation]:
    """Run the lint over every ``.py`` file under the given roots."""
    violations: list[Violation] = []
    for root in paths:
        if root.is_file() and root.suffix == ".py":
            files = [root]
        elif root.is_dir():
            files = sorted(root.rglob("*.py"))
        else:
            continue
        for f in files:
            try:
                tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
            except SyntaxError as e:
                print(
                    f"[lint-network-in-db-tx] syntax-error {f}: {e}",
                    file=sys.stderr,
                )
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.AsyncFunctionDef):
                    violations.extend(_walk_async_function(node, f))
    return violations


def _default_roots() -> list[Path]:
    """Default scan roots: the sidecar package source tree."""
    here = Path(__file__).resolve()
    sidecar = here.parent.parent / "relay_sidecar"
    return [sidecar]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "AST lint for network awaits inside DB transaction regions "
            "(VAL-W2-021)."
        )
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help=(
            "Files or directories to scan. Defaults to "
            "apps/local-sidecar/relay_sidecar/."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit violations as JSON on stdout.",
    )
    args = parser.parse_args(argv)

    roots = args.paths if args.paths else _default_roots()
    violations = lint_paths(roots)

    if args.json:
        import json

        payload = [
            {
                "file": str(v.file),
                "line": v.line,
                "column": v.column,
                "function": v.function,
                "target": v.target,
                "detail": v.detail,
            }
            for v in violations
        ]
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        for v in violations:
            print(
                f"{v.file}:{v.line}:{v.column}: "
                f"function={v.function} target={v.target}: {v.detail}",
                file=sys.stderr,
            )

    if violations:
        print(
            f"[lint-network-in-db-tx] FAIL: {len(violations)} violation(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
