"""VAL-W2-016: AST lint flags blocking I/O inside async handlers.

Three test cases:

  1. The lint passes (exit 0) on the current ``relay_sidecar/`` source.
  2. A synthesised module with ``time.sleep(...)`` inside an
     ``@app.get`` async handler EXITS NON-ZERO and prints a violation
     line citing the offending function.
  3. A synthesised module with ``requests.get(...)`` inside an
     ``@app.post`` async handler EXITS NON-ZERO.
  4. A synthesised module with ``open(path)`` (default-mode read) inside
     an ``@app.get`` handler EXITS NON-ZERO.
  5. Synchronous (non-async) calls to ``time.sleep`` outside any handler
     do NOT trip the lint (scope discipline).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SIDECAR_ROOT = Path(__file__).resolve().parent.parent
LINT_SCRIPT = SIDECAR_ROOT / "scripts" / "lint_async_handlers.py"


def _run_lint(*paths: Path, json_mode: bool = False) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(LINT_SCRIPT)]
    if json_mode:
        cmd.append("--json")
    cmd.extend(str(p) for p in paths)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_passes_on_current_sidecar_source() -> None:
    """Production source has zero violations; lint exits 0."""
    result = _run_lint()
    assert result.returncode == 0, (
        f"lint failed unexpectedly.\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert result.stderr.strip() == ""


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_flags_time_sleep_inside_async_handler(tmp_path: Path) -> None:
    """Planted ``time.sleep`` inside an async @app.get handler trips the lint."""
    bad = tmp_path / "bad_time_sleep.py"
    bad.write_text(
        textwrap.dedent(
            """
            import time
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/bad")
            async def bad_handler():
                time.sleep(1)
                return {"ok": True}
            """
        ).strip(),
        encoding="utf-8",
    )
    result = _run_lint(bad)
    assert result.returncode == 1, (
        f"lint should have failed.\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "time.sleep" in result.stderr
    assert "bad_handler" in result.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_flags_requests_get_inside_async_handler(tmp_path: Path) -> None:
    """Planted ``requests.get`` inside an async @app.post handler trips the lint."""
    bad = tmp_path / "bad_requests.py"
    bad.write_text(
        textwrap.dedent(
            """
            import requests
            from fastapi import FastAPI

            app = FastAPI()

            @app.post("/proxy")
            async def proxy_handler():
                r = requests.get("https://example.invalid")
                return {"status": r.status_code}
            """
        ).strip(),
        encoding="utf-8",
    )
    result = _run_lint(bad, json_mode=True)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(v["target"] == "requests.get" for v in payload), payload
    assert any(v["handler"] == "proxy_handler" for v in payload), payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_flags_open_inside_async_handler(tmp_path: Path) -> None:
    """Planted builtin ``open(path)`` inside an async @app.get handler trips."""
    bad = tmp_path / "bad_open.py"
    bad.write_text(
        textwrap.dedent(
            """
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/log")
            async def read_log():
                with open("/tmp/relay.log") as f:
                    return {"head": f.read(100)}
            """
        ).strip(),
        encoding="utf-8",
    )
    result = _run_lint(bad)
    assert result.returncode == 1
    assert "open" in result.stderr
    assert "read_log" in result.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_flags_sqlite3_connect_inside_async_handler(tmp_path: Path) -> None:
    """Planted synchronous ``sqlite3.connect`` inside an async handler trips."""
    bad = tmp_path / "bad_sqlite.py"
    bad.write_text(
        textwrap.dedent(
            """
            import sqlite3
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/db")
            async def read_db():
                conn = sqlite3.connect(":memory:")
                return {"ok": True}
            """
        ).strip(),
        encoding="utf-8",
    )
    result = _run_lint(bad)
    assert result.returncode == 1
    assert "sqlite3.connect" in result.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_does_not_flag_blocking_call_outside_handler(tmp_path: Path) -> None:
    """A non-handler async helper using ``time.sleep`` is not flagged.

    The lint scopes to handler bodies only (decorated with @app.<method>
    / @router.<method>). A helper async function that legitimately blocks
    (or one that is run in a thread pool) is out of scope.
    """
    ok = tmp_path / "ok_helper.py"
    ok.write_text(
        textwrap.dedent(
            """
            import time

            async def some_helper():
                time.sleep(0.001)  # not a handler; not flagged.
                return 1
            """
        ).strip(),
        encoding="utf-8",
    )
    result = _run_lint(ok)
    assert result.returncode == 0, (
        f"lint should have passed.\nstdout={result.stdout}\nstderr={result.stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-016")
def test_lint_flags_bare_sleep_from_time_import(tmp_path: Path) -> None:
    """``from time import sleep`` then bare ``sleep(...)`` is flagged."""
    bad = tmp_path / "bad_bare_sleep.py"
    bad.write_text(
        textwrap.dedent(
            """
            from time import sleep
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/sleepy")
            async def sleepy():
                sleep(1)
                return {"ok": True}
            """
        ).strip(),
        encoding="utf-8",
    )
    result = _run_lint(bad)
    assert result.returncode == 1
    assert "sleep" in result.stderr
    assert "sleepy" in result.stderr
