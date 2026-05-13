"""VAL-W2-012: every FastAPI route handler in the sidecar is ``async def``.

A static grep over ``apps/local-sidecar/`` MUST find zero synchronous
handler defs (a ``def`` line immediately after an ``@app.get`` /
``@router.post`` / etc. decorator). All handlers MUST be ``async def``.

We implement the grep in Python (regex over the raw source) so the test
runs portably on the macOS + Linux + Windows matrix without depending on
ripgrep being installed in CI. The pattern matches the literal contract
expression: ``@app.<method>(...)\\n\\s*def `` (no ``async`` prefix).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SIDECAR_ROOT = Path(__file__).resolve().parent.parent / "relay_sidecar"
HTTP_DECORATOR_RE = re.compile(
    r"@(app|router)\.(get|post|put|delete|patch|head|options)\b"
    r"[^\n]*\n\s*def\s+",
    re.MULTILINE,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-012")
def test_no_sync_handler_definitions_in_sidecar() -> None:
    """Zero ``def `` (non-``async``) lines immediately after @app/@router HTTP decorators."""
    offenders: list[tuple[Path, int, str]] = []
    for path in sorted(SIDECAR_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in HTTP_DECORATOR_RE.finditer(text):
            # Compute the line number of the decorator for clearer reporting.
            line = text.count("\n", 0, match.start()) + 1
            snippet = text[match.start() : match.end()].strip()
            offenders.append((path, line, snippet))
    assert not offenders, (
        "Found synchronous handler def (must be `async def`):\n  "
        + "\n  ".join(f"{p}:{ln}: {snip}" for p, ln, snip in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-012")
def test_every_http_decorator_is_followed_by_async_def() -> None:
    """Positive coverage: every HTTP-decorator site has an `async def` next."""
    decorator_re = re.compile(
        r"@(app|router)\.(get|post|put|delete|patch|head|options)\b", re.MULTILINE
    )
    found = 0
    for path in sorted(SIDECAR_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in decorator_re.finditer(text):
            # Slice the next ~200 characters and assert ``async def`` shows up
            # before any unrelated ``def``.
            tail = text[match.end() : match.end() + 400]
            async_idx = tail.find("async def")
            sync_idx = tail.find("\n    def ")
            assert async_idx != -1, (
                f"{path}: HTTP decorator at offset {match.end()} has no "
                f"`async def` follower:\n{tail[:200]}"
            )
            if sync_idx != -1:
                assert async_idx < sync_idx, (
                    f"{path}: a `def ` precedes `async def` after decorator"
                )
            found += 1
    # The W2.2 surface has at least /health, /health/nonce, /diagnostics/sqlite,
    # /diagnostics/runtime. Assert a positive lower bound so a refactor that
    # accidentally removes routes is loud.
    assert found >= 4, f"expected >= 4 HTTP decorators in sidecar, found {found}"
