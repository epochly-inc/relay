"""CLI exit-code mapping (VAL-W5-006).

Re-exports the canonical Relay exit-code table from the SDK module
:mod:`relay.exit_codes` so the CLI never declares its own copy of the
mapping. Single source of truth lives in
``packages/sdk-python/relay/exit_codes.py``; this module is a thin
import facade so the CLI can write::

    from relay_cli.exit_codes import exit_code_for_relay_error

without coupling test fixtures to the SDK package layout.

VAL-W5-006 cross-language parity is asserted via
``tests/conformance/cli-exit-codes/parity_fixtures.json`` (lands with the
W17 conformance corpus); this re-export module guarantees the Py CLI
always evaluates the same table the SDK does.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from relay.exit_codes import (
    CANONICAL_EXIT_CODE_TABLE,
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_4XX_BLOCK,
    EXIT_4XX_REMEDIATE,
    EXIT_5XX_TRANSIENT,
    EXIT_CASSETTE_MISS,
    EXIT_CLI_USAGE,
    EXIT_EVAL_DEFERRED,
    EXIT_GATE_TTL_EXPIRED,
    EXIT_SUCCESS,
    EXIT_UNCAUGHT_INTERNAL,
    EXIT_WAL_STORAGE,
    exit_code_for_code_and_status,
    exit_code_for_relay_error,
)

# POSIX convention for terminal-induced interrupt exits. SIGINT
# (signal 2) -> 128 + 2 = 130. The CLI emits this on Ctrl-C
# (VAL-W5-007). Listed here so callers do not hand-import signal
# semantics; the constant is identical to what /bin/sh records in
# ``$?`` after a Ctrl-C-terminated foreground process.
EXIT_SIGINT_INTERRUPTED: int = 130


__all__ = [
    "CANONICAL_EXIT_CODE_TABLE",
    "EXIT_4XX_AUTH_HANDOFF",
    "EXIT_4XX_BLOCK",
    "EXIT_4XX_REMEDIATE",
    "EXIT_5XX_TRANSIENT",
    "EXIT_CASSETTE_MISS",
    "EXIT_CLI_USAGE",
    "EXIT_EVAL_DEFERRED",
    "EXIT_GATE_TTL_EXPIRED",
    "EXIT_SIGINT_INTERRUPTED",
    "EXIT_SUCCESS",
    "EXIT_UNCAUGHT_INTERNAL",
    "EXIT_WAL_STORAGE",
    "exit_code_for_code_and_status",
    "exit_code_for_relay_error",
]
