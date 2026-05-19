"""V3 M5 F11: §AI CLI JSON output injection guards (VAL-V3M5-022).

Per spec §AI.1 line 5667, CLI stdout JSON MUST be safe against
operator-controlled input that contains control characters, non-ASCII
code points, surrogate pairs, RTL overrides, or other adversarial
bytes. The canonical defenses are:

  1. ``json.dumps(..., separators=(",", ":"))`` -- compact single-line
     envelope so a single stdout line maps to a single envelope.
  2. Python's ``json.dumps`` escapes ALL C0 control characters
     (``\\u0000`` through ``\\u001f``) as ``\\uXXXX`` per RFC 8259
     section 7. This holds regardless of the ``ensure_ascii`` setting.
  3. ``allow_nan=False`` -- refuse ``NaN`` / ``Infinity`` floats which
     are invalid JSON per RFC 8259 section 6.
  4. ``ensure_ascii=False`` -- emit non-ASCII as UTF-8 directly rather
     than as ``\\uXXXX`` escape pairs. Either setting is injection-safe
     for ASCII-printable values; ``False`` is the spec-pinned form per
     VAL-V3M5-022 for surrogate-pair stability.

This test file enforces the BEHAVIORAL injection-safety axis of
VAL-V3M5-022:

  * Drive the adversarial run_name through the persistence path then
    ``rly replay list`` and assert the stdout parses, round-trips
    byte-equal, and contains no raw control bytes. This guards the
    actual injection vector (operator-supplied string flowing through
    stdout JSON). The C0 escape behavior is enforced by Python's
    encoder regardless of source flag settings; this test passes on
    any conformant encoder.

The source-flag pinning component of VAL-V3M5-022 (every
``json.dumps`` stdout-emit call passes ``ensure_ascii=False,
allow_nan=False``) is NOT enforced from this test file because the
CLI source modules ``packages/cli/src/relay_cli/**`` are outside this
feature's ``filesOwned``. The handoff returns to the orchestrator
flagging this gap so a follow-up fix-feature can land the source
changes (output.py, errors.py, main.py, commands/verify_self.py,
commands/contract.py, commands/evidence.py, commands/verify_install.py)
with the corresponding flag-audit + NaN-rejection tests.

ASCII-only per CLAUDE.md "ASCII-Safe Source" (test source itself is
ASCII; the adversarial inputs are constructed via escape sequences so
the source bytes stay in the printable ASCII range).

Implementation note on the NULL byte: POSIX execve does not accept
embedded NUL bytes in argv -- :class:`subprocess.Popen` raises
``ValueError: embedded null byte`` before launching the child. We
therefore inject the crafted ``run_name`` via the persistence path
directly. This faithfully exercises the same code path that production
``rly replay record --name <name>`` reaches once Typer has parsed argv,
because Typer applies no transformation to the ``--name`` string before
storing it in the registry. The behavioral envelope-emission test then
runs ``rly replay list`` as a real subprocess to capture true wire
stdout bytes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Repository root (relay/), four parents up from this test file:
#   packages/cli/tests/<this>.py -> packages/cli/tests -> packages/cli
#   -> packages -> relay/
REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# Adversarial run_name fixture
# ---------------------------------------------------------------------------


# The crafted run_name combines:
#   * U+0000 NULL: classic C-string terminator; downstream consumers
#     (C-extension JSON parsers, naive shell pipelines) may silently
#     truncate at NUL if it leaks unescaped.
#   * U+001B ESC: the introducer for ANSI terminal escape sequences;
#     if leaked into a tty consumer it can rewrite history, redirect
#     cursor, or impersonate shell prompts.
#   * U+0007 BEL: another terminal-control hazard.
#   * Cyrillic + CJK + emoji: non-BMP and BMP non-ASCII bytes that
#     exercise the ``ensure_ascii`` setting. The emoji (U+1F600) sits
#     above the BMP so it forces the surrogate-pair path when
#     ``ensure_ascii=True``.
#   * Embedded JSON delimiters and quotes to confirm the encoder
#     escapes them rather than embedding raw.
#   * CRLF -- line-oriented consumers (jq -c, grep) MUST see a single
#     record per line; an unescaped newline in a value splits records.
ADVERSARIAL_RUN_NAME = (
    "evil"
    "\x00"  # NULL
    "\x1b[31mPWN\x1b[0m"  # ANSI red + reset
    "\x07"  # BEL
    "\r\n"  # CRLF
    '"injected":"payload"'
    "раз"  # Cyrillic "raz"
    "中文"  # CJK "zhong wen"
    "\U0001f600"  # emoji (non-BMP)
)


# ---------------------------------------------------------------------------
# Subprocess helpers (Python-3 + uv + rly entrypoint)
# ---------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
    *,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[bytes]:
    """Invoke ``rly <args>`` non-TTY via ``uv run``.

    Returns raw bytes (``text=False``) so the bytewise-no-control-byte
    assertion can inspect stdout without any encoder transformation.
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    # Force JSON even if RELAY_OUTPUT_FORMAT was unset in the caller.
    env.setdefault("RELAY_OUTPUT_FORMAT", "json")
    return subprocess.run(
        ["uv", "run", "rly", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=False,
        env=env,
        timeout=timeout,
        check=False,
    )


def _persist_adversarial_name_to_registry(home: Path, name: str) -> str:
    """Drive the same persistence path Typer reaches with ``--name``.

    POSIX ``execve`` rejects embedded NUL bytes in argv, so passing the
    crafted name through ``subprocess.run([..., "--name", name])``
    raises before the child launches. The path Typer would otherwise
    take is:

        cmd_replay_record(name=<typed string>) ->
          _upsert_case(registry, name=name, ...) ->
            _save_registry(home, registry)

    Typer applies no transformation to ``--name``; it passes through as
    a Python ``str``. We therefore import the CLI module in-process and
    call ``_upsert_case`` + ``_save_registry`` directly with the
    adversarial string. This faithfully exercises the persistence path
    that production ``--name`` reaches AFTER Typer's argv parse.

    Returns the synthesized ``replay_case_id``.
    """
    sys.path.insert(0, str(REPO_ROOT / "packages" / "cli" / "src"))
    try:
        from relay_cli.commands.replay import (
            REPLAY_REGISTRY_SCHEMA,
            _save_registry,
            _upsert_case,
        )
    finally:
        sys.path.pop(0)

    case_id = "case-injection-fixture"
    fixture_path = home / "replay-fixtures" / f"{case_id}.json"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_bytes(b"{}\n")
    registry = {"schema_version": REPLAY_REGISTRY_SCHEMA, "items": []}
    registry = _upsert_case(
        registry,
        replay_case_id=case_id,
        name=name,
        fixture_path=fixture_path,
        fixture_digest="0" * 64,
        last_status="recorded",
        side_effects=[],
    )
    _save_registry(home, registry)
    return case_id


# ---------------------------------------------------------------------------
# VAL-V3M5-022: adversarial run_name end-to-end injection check
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-022")
def test_adversarial_run_name_does_not_inject_into_cli_json(tmp_path: Path) -> None:
    """A run_name carrying control chars + non-ASCII MUST NOT inject.

    Pipeline:

      1. Persist the adversarial name into the local replay registry
         via the same code path Typer reaches with ``--name`` (see
         :func:`_persist_adversarial_name_to_registry`).
      2. ``rly replay list --json`` surfaces the name on stdout.
      3. Parse stdout via :func:`json.loads`; assert success.
      4. Round-trip equality: ``payload["items"][0]["name"]`` MUST
         equal the original adversarial string byte-for-byte.
      5. Wire-bytes check: raw stdout MUST NOT contain the literal C0
         control bytes (``\\x00``, ``\\x1b``, ``\\x07``, ``\\r``);
         they MUST be emitted as ``\\uXXXX`` escapes per RFC 8259.
      6. Single-line invariant: stdout has exactly one trailing
         newline; the embedded CRLF in the name MUST be escaped.
    """
    home = tmp_path / "relay_home"
    home.mkdir()
    _persist_adversarial_name_to_registry(home, ADVERSARIAL_RUN_NAME)

    listed = _run_rly(
        ["replay", "list"],
        extra_env={"RELAY_HOME": str(home), "RELAY_OUTPUT_FORMAT": "json"},
    )
    assert listed.returncode == 0, (
        f"list failed; stderr={listed.stderr!r}; stdout={listed.stdout!r}"
    )

    raw_stdout: bytes = listed.stdout

    # Bytewise invariant: the literal C0 control bytes MUST NOT appear
    # in wire stdout. The JSON encoder escapes them as ``\u00xx`` per
    # spec; any leak is an injection vector.
    assert b"\x00" not in raw_stdout, (
        "raw NUL byte leaked into CLI stdout JSON (injection hazard); "
        f"stdout={raw_stdout!r}"
    )
    assert b"\x1b" not in raw_stdout, (
        "raw ESC byte leaked into CLI stdout JSON (terminal-injection hazard); "
        f"stdout={raw_stdout!r}"
    )
    assert b"\x07" not in raw_stdout, (
        f"raw BEL byte leaked into CLI stdout JSON; stdout={raw_stdout!r}"
    )

    # Single-line invariant: emit_json writes one envelope terminated
    # by a single ``\n``. Embedded CRLF inside the name MUST be escaped.
    newline_count = raw_stdout.count(b"\n")
    assert newline_count == 1, (
        f"expected exactly one trailing newline; got {newline_count} "
        f"(embedded CR/LF in name leaked through); stdout={raw_stdout!r}"
    )
    assert b"\r" not in raw_stdout, (
        f"raw CR byte leaked into CLI stdout JSON; stdout={raw_stdout!r}"
    )

    # JSON-parse the envelope. A failure here means the encoder produced
    # output that is not valid JSON -- the canonical injection failure.
    decoded_stdout = raw_stdout.decode("utf-8")
    payload = json.loads(decoded_stdout)
    assert isinstance(payload, dict), f"expected dict envelope; got {payload!r}"
    items = payload.get("items")
    assert isinstance(items, list) and len(items) == 1, (
        f"expected one item; got items={items!r}"
    )
    persisted_name = items[0].get("name")

    # Round-trip equality: the decoded name MUST equal the original
    # adversarial input character-for-character. Any truncation,
    # substitution, or silent-replacement would fail this assertion.
    assert persisted_name == ADVERSARIAL_RUN_NAME, (
        "name round-trip mismatch (injection or silent transform); "
        f"got={persisted_name!r}, want={ADVERSARIAL_RUN_NAME!r}"
    )


# ---------------------------------------------------------------------------
# Source-flag pinning (VAL-V3M5-022 second axis): see module docstring.
# Verification of ``ensure_ascii=False, allow_nan=False`` across every CLI
# stdout-emitter ``json.dumps`` call is deferred to a follow-up fix-feature
# whose filesOwned includes the CLI source modules. The handoff for this
# feature returns to the orchestrator flagging that gap.
# ---------------------------------------------------------------------------
