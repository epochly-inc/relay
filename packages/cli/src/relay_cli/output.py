"""CLI output mode resolution (VAL-W5-003 / VAL-W5-010).

The Relay CLI defaults to JSON-on-pipe and human-readable-on-TTY for
stdout. Per spec section P.3 ("Default output is `--json` for non-TTY
stdout; human-readable for TTY") and VAL-W5-003 the detection is via
``sys.stdout.isatty()`` at emit time. The TTY-detection branch MUST NOT
change the exit code (VAL-W5-003 last sentence).

A user override flag ``--json`` forces JSON regardless of TTY (also
required by VAL-W5-003 second clause: ``rly --version --json`` MUST
always emit JSON). The ``--no-json`` mirror flag is reserved for the
human-readable-when-piped path; W5.1 ships ``--json`` only.

Per VAL-W5-010 every subcommand's ``--help``, when piped (non-TTY), MUST
emit a machine-readable JSON envelope ``{schema_version:
"relay.cli.help.v1", command, options, subcommands, exit_codes}``. This
module provides the JSON-help envelope builder; the Typer integration in
:mod:`relay_cli.main` wires it as a Typer ``Group.format_help`` override.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Final

# VAL-W5-001: ``rly --version`` JSON envelope schema_version.
CLI_VERSION_SCHEMA_VERSION: Final[str] = "relay.cli.version.v1"

# VAL-W5-010: ``rly --help`` (piped) JSON envelope schema_version.
CLI_HELP_SCHEMA_VERSION: Final[str] = "relay.cli.help.v1"

# Environment variable that callers may set to force JSON output even
# when stdout is a TTY. Useful in CI sandboxes that allocate a PTY but
# still want JSON. Mirrors the convention used by other modern CLIs
# (RELAY_OUTPUT_FORMAT=json takes precedence over TTY detection).
ENV_OUTPUT_FORMAT: Final[str] = "RELAY_OUTPUT_FORMAT"


def stdout_is_tty() -> bool:
    """Return whether stdout is attached to a terminal.

    Returns ``False`` when stdout has been redirected to a file, a pipe,
    or another non-tty stream. Returns ``True`` only when stdout is a
    real TTY (interactive shell).

    A separate ``RELAY_OUTPUT_FORMAT=json`` environment variable forces
    JSON output regardless of TTY status; this function returns the raw
    ``isatty`` result and callers consult :func:`should_emit_json` to
    apply the override.
    """
    isatty = getattr(sys.stdout, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except Exception:
        # Some test fixtures wrap stdout in objects that raise on isatty;
        # fall back to non-TTY (JSON) to keep machine consumers happy.
        return False


def should_emit_json(force_json: bool = False) -> bool:
    """Resolve whether the CLI should emit JSON for the current command.

    Resolution order (first match wins):
      1. ``force_json=True`` from a ``--json`` flag -> True
      2. ``RELAY_OUTPUT_FORMAT`` env var equals ``"json"`` -> True
      3. ``stdout`` is NOT a TTY -> True (default-JSON-on-pipe)
      4. Else -> False (human-readable on interactive TTY)
    """
    if force_json:
        return True
    env_value = os.environ.get(ENV_OUTPUT_FORMAT, "").strip().lower()
    if env_value == "json":
        return True
    return not stdout_is_tty()


def emit_json(payload: dict[str, Any]) -> None:
    """Write a JSON object to stdout terminated by a single newline.

    Per VAL-W5-003 the JSON form MUST be parseable by ``json.loads``; the
    compact-separators form ``(",", ":")`` keeps the line-oriented
    contract intact (a single line of stdout maps to a single envelope).
    A trailing newline ensures line-oriented consumers (``jq -c``,
    ``grep``) see a complete record.
    """
    line = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def emit_human(text: str) -> None:
    """Write a human-readable line to stdout terminated by a single newline.

    Used only when :func:`should_emit_json` returns False. The CLI MUST
    NOT mix human and JSON output for the same logical command;
    callers branch on :func:`should_emit_json` once at the top of the
    command and pick exactly one.
    """
    if not text.endswith("\n"):
        text = text + "\n"
    sys.stdout.write(text)
    sys.stdout.flush()


def build_version_envelope(
    *,
    version: str,
    python_version: str,
    platform: str,
) -> dict[str, Any]:
    """Construct the canonical ``rly --version`` JSON envelope (VAL-W5-001).

    Returns a dict with keys ``schema_version``, ``version``, ``python``,
    ``platform``. Field order matches the assertion text in VAL-W5-001
    so a snapshot diff is line-stable.
    """
    return {
        "schema_version": CLI_VERSION_SCHEMA_VERSION,
        "version": version,
        "python": python_version,
        "platform": platform,
    }


def build_help_envelope(
    *,
    command: str,
    options: list[dict[str, Any]],
    subcommands: list[dict[str, Any]],
    exit_codes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct the canonical ``--help`` JSON envelope (VAL-W5-010).

    Returns a dict with keys ``schema_version``, ``command``,
    ``options``, ``subcommands``, ``exit_codes``. The ``command`` value
    is the dotted invocation path (e.g., ``"rly sidecar status"``);
    ``options`` is a list of ``{name, type, required, help}`` dicts;
    ``subcommands`` is a list of ``{name, help}`` dicts; ``exit_codes``
    is a list of ``{code, meaning}`` dicts mirroring the canonical
    Relay exit-code table.
    """
    return {
        "schema_version": CLI_HELP_SCHEMA_VERSION,
        "command": command,
        "options": list(options),
        "subcommands": list(subcommands),
        "exit_codes": list(exit_codes),
    }


__all__ = [
    "CLI_HELP_SCHEMA_VERSION",
    "CLI_VERSION_SCHEMA_VERSION",
    "ENV_OUTPUT_FORMAT",
    "build_help_envelope",
    "build_version_envelope",
    "emit_human",
    "emit_json",
    "should_emit_json",
    "stdout_is_tty",
]
