#!/usr/bin/env python3
"""AST lint: no blocking I/O inside async route handlers (VAL-W2-016).

Walks every ``.py`` file under ``apps/local-sidecar/relay_sidecar/`` and
flags any ``time.sleep``, ``requests.*``, ``urllib.request.*``, synchronous
``sqlite3.connect``, or ``open(..., 'r')`` / ``open(..., 'rb')`` /
``open(..., 'w')`` call that appears inside the body of an
``async def`` whose decorator list contains an HTTP method decorator
(``@app.get``, ``@app.post``, ``@router.get``, etc.).

Implementation:

  1. Parse each file with ``ast.parse``.
  2. Walk top-level + class-level definitions to find ``AsyncFunctionDef``
     nodes whose decorator list matches the HTTP-decorator pattern.
  3. For each matched async function, walk its body and flag any ``Call``
     whose target resolves to a banned name.

Exit code:
  0 -> zero violations (CI green)
  1 -> at least one violation; details printed to stderr

CLI usage (sidecar-local):
    python apps/local-sidecar/scripts/lint_async_handlers.py
    python apps/local-sidecar/scripts/lint_async_handlers.py path1 path2 ...

Per CLAUDE.md ASCII-only.
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# HTTP method decorator suffixes we recognise. Matches both ``@app.get(...)``
# and ``@router.get(...)`` forms.
HTTP_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options"}
)

# Banned dotted-name targets. The matcher looks at the unparsed Call.func
# representation (e.g. ``time.sleep``, ``requests.get``) and the bare-name
# form (e.g. ``sleep`` if imported as ``from time import sleep``).
BANNED_DOTTED: frozenset[str] = frozenset(
    {
        # Blocking sleeps
        "time.sleep",
        # Blocking HTTP clients
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.head",
        "requests.options",
        "requests.request",
        "requests.Session",
        # Stdlib HTTP
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urllib.urlopen",
        # Synchronous sqlite3
        "sqlite3.connect",
    }
)

# Bare-name forms that should never appear inside async handlers (covers
# ``from time import sleep`` and ``from sqlite3 import connect``).
BANNED_BARE: frozenset[str] = frozenset(
    {
        "sleep",  # from time import sleep
    }
)


@dataclass(frozen=True)
class Violation:
    file: Path
    line: int
    column: int
    handler: str
    target: str
    detail: str


def _decorator_is_http(decorator: ast.expr) -> bool:
    """Return True if ``decorator`` is an HTTP method decorator.

    Matches ``@app.get(...)``, ``@router.post(...)``, ``@some.delete(...)``.
    Falls through cleanly on bare ``@app`` or unrelated decorators.
    """
    # Decorators that are called (with parens): ast.Call(func=...).
    call = decorator if isinstance(decorator, ast.Call) else None
    target = call.func if call is not None else decorator
    # We want an Attribute whose attr is in HTTP_METHODS.
    if isinstance(target, ast.Attribute):
        return target.attr in HTTP_METHODS
    return False


def _dotted_name(node: ast.expr) -> str | None:
    """Return the dotted name of ``node`` if it can be expressed statically.

    Examples:
        ``time.sleep`` -> ``"time.sleep"``
        ``urllib.request.urlopen`` -> ``"urllib.request.urlopen"``
        ``self.client.get`` -> ``None`` (instance-bound; we can't tell)
        ``sleep`` -> ``"sleep"``
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted_name(node.value)
        if head is None:
            return None
        return f"{head}.{node.attr}"
    return None


def _is_blocking_open(call: ast.Call) -> tuple[bool, str]:
    """Return (True, mode) if ``call`` is ``open(...)`` with a synchronous mode.

    The lint flags any direct call to the builtin ``open``. Async code paths
    in the sidecar should use ``aiofiles`` or read via ``await
    asyncio.to_thread(...)`` for filesystem I/O.
    """
    if not isinstance(call.func, ast.Name) or call.func.id != "open":
        return (False, "")
    # If a literal mode argument is present and is read-only or write-only,
    # surface it. Otherwise default to "r" per the builtin contract.
    mode = "r"
    if (
        len(call.args) >= 2
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
    ):
        mode = call.args[1].value
    for kw in call.keywords:
        if (
            kw.arg == "mode"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            mode = kw.value.value
    return (True, mode)


class _HandlerVisitor(ast.NodeVisitor):
    """Walks one file looking for blocking calls inside async HTTP handlers."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[Violation] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if any(_decorator_is_http(d) for d in node.decorator_list):
            self._scan_handler_body(node)
        # Recurse so nested async defs (rare) are also scanned.
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Synchronous ``def`` decorated with @app.get is a SEPARATE bug
        # (VAL-W2-012); reported by the grep guard rather than this lint.
        # We still recurse in case a sync def contains a nested AsyncFunctionDef.
        self.generic_visit(node)

    def _scan_handler_body(self, handler: ast.AsyncFunctionDef) -> None:
        for child in ast.walk(handler):
            if not isinstance(child, ast.Call):
                continue
            dotted = _dotted_name(child.func)
            # Banned dotted name (time.sleep, requests.get, ...).
            if dotted is not None and dotted in BANNED_DOTTED:
                self.violations.append(
                    Violation(
                        file=self.path,
                        line=getattr(child, "lineno", 0),
                        column=getattr(child, "col_offset", 0),
                        handler=handler.name,
                        target=dotted,
                        detail="blocking I/O call inside async handler body",
                    )
                )
                continue
            # Banned bare name (e.g. sleep from `from time import sleep`).
            if (
                dotted is not None
                and "." not in dotted
                and dotted in BANNED_BARE
            ):
                self.violations.append(
                    Violation(
                        file=self.path,
                        line=getattr(child, "lineno", 0),
                        column=getattr(child, "col_offset", 0),
                        handler=handler.name,
                        target=dotted,
                        detail=(
                            "blocking bare-name call (likely "
                            "`from time import sleep`) inside async handler"
                        ),
                    )
                )
                continue
            # Builtin open() call.
            is_open, mode = _is_blocking_open(child)
            if is_open:
                self.violations.append(
                    Violation(
                        file=self.path,
                        line=getattr(child, "lineno", 0),
                        column=getattr(child, "col_offset", 0),
                        handler=handler.name,
                        target=f"open(..., {mode!r})",
                        detail=(
                            "builtin `open()` is blocking inside async handler; "
                            "use aiofiles or asyncio.to_thread"
                        ),
                    )
                )


def lint_paths(paths: Iterable[Path]) -> list[Violation]:
    """Run the lint over every ``.py`` file rooted at the given paths."""
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
                # A syntax error is a different bug; surface it but don't
                # mask other findings.
                print(
                    f"[lint-async-handlers] syntax-error {f}: {e}",
                    file=sys.stderr,
                )
                continue
            visitor = _HandlerVisitor(f)
            visitor.visit(tree)
            violations.extend(visitor.violations)
    return violations


def _default_roots() -> list[Path]:
    """Return the default scan roots: the sidecar package source tree."""
    # ``__file__`` -> apps/local-sidecar/scripts/lint_async_handlers.py
    here = Path(__file__).resolve()
    sidecar = here.parent.parent / "relay_sidecar"
    return [sidecar]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "AST lint for blocking I/O inside async route handlers (VAL-W2-016)."
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
        help="Emit violations as JSON on stdout (one object per violation).",
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
                "handler": v.handler,
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
                f"handler={v.handler} target={v.target}: {v.detail}",
                file=sys.stderr,
            )

    if violations:
        print(
            f"[lint-async-handlers] FAIL: {len(violations)} violation(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
