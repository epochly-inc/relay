"""CLI exit-code mapping (VAL-W5-006 + M07 w7-exit-codes / VAL-V2M07-028).

Re-exports the canonical Relay exit-code table from the SDK module
:mod:`relay.exit_codes` with one M07 v0.2 OSS-completeness exception:
**exit code 7 (EXIT_GATE_TTL_EXPIRED, RELAY-GATE-024) is removed from
the CLI's canonical table** and the wire code RELAY-GATE-024 is remapped
to exit code 4 (transient / cassette-miss bucket) per VAL-V2M07-016.

Per the M07 contract (lines 3192-3206) the historical exit-code-7
allocation for "gate TTL expired" was an OSS-only divergence from the
spec section P.1 canonical table. The spec's §P.1 table allocates only
{0, 1, 2, 3, 4, 64, 70, 130} as primary exit codes; OSS-internal extras
(5 = 5xx, 6 = WAL/storage, 8 = LLM-judge deferred) remain because they
are still referenced by internal sidecar code paths, but the spurious 7
is dropped because RELAY-GATE-024 belongs with the other transient/TTL
conditions in the code-4 bucket.

The SDK module's :data:`relay.exit_codes.CANONICAL_EXIT_CODE_TABLE`
still lists EXIT_GATE_TTL_EXPIRED for cross-language parity with the
TypeScript SDK; that parity is a different invariant
(``tests/conformance/cli-exit-codes/parity_fixtures.json``) that lives
above the CLI's user-facing surface. This re-export module is the
CLI-facing table.

VAL-V2M07-029 enforces the deletion via a grep guard test at
``tests/contract/cli/test_exit_code_7_removed.py``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Final

from relay.errors import RelayError
from relay.exit_codes import (
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_4XX_BLOCK,
    EXIT_4XX_REMEDIATE,
    EXIT_5XX_TRANSIENT,
    EXIT_CASSETTE_MISS,
    EXIT_CLI_USAGE,
    EXIT_EVAL_DEFERRED,
    EXIT_SUCCESS,
    EXIT_UNCAUGHT_INTERNAL,
    EXIT_WAL_STORAGE,
)
from relay.exit_codes import (
    exit_code_for_code_and_status as _sdk_exit_code_for_code_and_status,
)
from relay.exit_codes import (
    exit_code_for_relay_error as _sdk_exit_code_for_relay_error,
)

# POSIX convention for terminal-induced interrupt exits. SIGINT
# (signal 2) -> 128 + 2 = 130. The CLI emits this on Ctrl-C
# (VAL-W5-007). Listed here so callers do not hand-import signal
# semantics; the constant is identical to what /bin/sh records in
# ``$?`` after a Ctrl-C-terminated foreground process.
EXIT_SIGINT_INTERRUPTED: Final[int] = 130


def exit_code_for_code_and_status(
    code: str,
    http_status: int | None,
    retry_advice_mode: str | None = None,
) -> int:
    """Resolve the canonical CLI exit code for a wire ``code`` + ``http_status``.

    Wraps the SDK's resolution function with one override: per
    VAL-V2M07-016 the wire code ``RELAY-GATE-024`` (draft TTL expired)
    maps to exit code 4 (transient / cassette-miss bucket) instead of
    the SDK's historical exit code 7. The SDK keeps 7 for cross-language
    parity; the CLI's user-facing exit table follows the §P.1 canonical
    column.
    """
    if code == "RELAY-GATE-024":
        return EXIT_CASSETTE_MISS
    return _sdk_exit_code_for_code_and_status(code, http_status, retry_advice_mode)


def exit_code_for_relay_error(error: RelayError) -> int:
    """Resolve the CLI exit code for an SDK :class:`RelayError` instance.

    Per VAL-V2M07-016 the RELAY-GATE-024 override applies here too.
    Other codes pass through to the SDK's resolution.
    """
    if error.code == "RELAY-GATE-024":
        return EXIT_CASSETTE_MISS
    return _sdk_exit_code_for_relay_error(error)


# Programmatic dump of the CLI's canonical exit-code table per
# VAL-V2M07-028. Mirrors the SDK's CANONICAL_EXIT_CODE_TABLE with
# EXIT_GATE_TTL_EXPIRED removed. Consumers of this table get the
# CLI-facing view; consumers of the SDK table get the cross-language
# parity view.
CANONICAL_EXIT_CODE_TABLE: dict[str, int] = {
    "EXIT_SUCCESS": EXIT_SUCCESS,
    "EXIT_4XX_BLOCK": EXIT_4XX_BLOCK,
    "EXIT_4XX_REMEDIATE": EXIT_4XX_REMEDIATE,
    "EXIT_4XX_AUTH_HANDOFF": EXIT_4XX_AUTH_HANDOFF,
    "EXIT_CASSETTE_MISS": EXIT_CASSETTE_MISS,
    "EXIT_5XX_TRANSIENT": EXIT_5XX_TRANSIENT,
    "EXIT_WAL_STORAGE": EXIT_WAL_STORAGE,
    "EXIT_EVAL_DEFERRED": EXIT_EVAL_DEFERRED,
    "EXIT_CLI_USAGE": EXIT_CLI_USAGE,
    "EXIT_UNCAUGHT_INTERNAL": EXIT_UNCAUGHT_INTERNAL,
    "EXIT_SIGINT_INTERRUPTED": EXIT_SIGINT_INTERRUPTED,
}


__all__ = [
    "CANONICAL_EXIT_CODE_TABLE",
    "EXIT_4XX_AUTH_HANDOFF",
    "EXIT_4XX_BLOCK",
    "EXIT_4XX_REMEDIATE",
    "EXIT_5XX_TRANSIENT",
    "EXIT_CASSETTE_MISS",
    "EXIT_CLI_USAGE",
    "EXIT_EVAL_DEFERRED",
    "EXIT_SIGINT_INTERRUPTED",
    "EXIT_SUCCESS",
    "EXIT_UNCAUGHT_INTERNAL",
    "EXIT_WAL_STORAGE",
    "exit_code_for_code_and_status",
    "exit_code_for_relay_error",
]
