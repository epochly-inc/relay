"""Relay canonical exit-code table (W4.4 / VAL-W4-031 parity).

Single source of truth for the process exit code that any Relay CLI or
adapter MUST emit when terminating due to a :class:`relay.errors.RelayError`.
The table below is byte-identical to the TS parity in
``packages/sdk-typescript/src/exit_codes.ts`` and to the W5 CLI mapping
(VAL-W5-006). The cross-language fixture lives at
``tests/conformance/cli-exit-codes/parity_fixtures.json``.

Mapping (per contract.md VAL-W4-031, orchestrator decision EXIT CODE
TABLE):

    exit 0  = success (2xx)
    exit 1  = 4xx with action=block
    exit 2  = 4xx with action=remediate
    exit 3  = 4xx auth/handoff (RELAY-GATE-021, RELAY-AUTH-*)
    exit 4  = cassette miss (RELAY-CASSETTE-MISS)
    exit 5  = 5xx + network transient
    exit 6  = WAL/storage error (RELAY-SIDECAR-STORAGE-*)
    exit 7  = gate TTL expired (RELAY-GATE-024)
    exit 8  = LLM-judge deferred (RELAY-EVAL-EVALUATOR-DEFERRED)
    exit 64 = wrong-flag (CLI usage error)
    exit 70 = uncaught internal

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Final

from .errors import RelayError

# -----------------------------------------------------------------------------
# Canonical exit-code constants (parity with TS module).
# -----------------------------------------------------------------------------

EXIT_SUCCESS: Final[int] = 0
EXIT_4XX_BLOCK: Final[int] = 1
EXIT_4XX_REMEDIATE: Final[int] = 2
EXIT_4XX_AUTH_HANDOFF: Final[int] = 3
EXIT_CASSETTE_MISS: Final[int] = 4
EXIT_5XX_TRANSIENT: Final[int] = 5
EXIT_WAL_STORAGE: Final[int] = 6
EXIT_GATE_TTL_EXPIRED: Final[int] = 7
EXIT_EVAL_DEFERRED: Final[int] = 8
EXIT_CLI_USAGE: Final[int] = 64
EXIT_UNCAUGHT_INTERNAL: Final[int] = 70


# Exact-code map. Wire codes that bind to a single exit code regardless
# of http_status. Mirrors EXACT_CODE_TO_EXIT in the TS module.
_EXACT_CODE_TO_EXIT: dict[str, int] = {
    "RELAY-GATE-021": EXIT_4XX_AUTH_HANDOFF,
    "RELAY-CASSETTE-MISS": EXIT_CASSETTE_MISS,
    "RELAY-GATE-024": EXIT_GATE_TTL_EXPIRED,
    "RELAY-EVAL-EVALUATOR-DEFERRED": EXIT_EVAL_DEFERRED,
    "RELAY-CLI-070": EXIT_UNCAUGHT_INTERNAL,
}

# Prefix-match table. Order matters; the TS module scans this list in
# the same order so the byte-equality of the cross-language fixture
# holds even if a code matches multiple prefixes (none currently do).
_PREFIX_TO_EXIT: list[tuple[str, int]] = [
    ("RELAY-AUTH-", EXIT_4XX_AUTH_HANDOFF),
    ("RELAY-SIDECAR-STORAGE-", EXIT_WAL_STORAGE),
    ("RELAY-SQLITE-", EXIT_WAL_STORAGE),
]


def exit_code_for_code_and_status(
    code: str,
    http_status: int | None,
    retry_advice_mode: str | None = None,
) -> int:
    """Resolve the canonical exit code for a wire ``code`` + ``http_status``.

    Algorithm (mirrors the TS implementation byte-for-byte):

        1. Exact-code map first.
        2. Prefix-match table second.
        3. 5xx http_status -> exit 5.
        4. 4xx http_status:
              - retry_advice mode in {after_state_change, retryable,
                after_retry_after} -> exit 2 (remediate).
              - else -> exit 1 (block).
        5. 2xx http_status -> exit 0.
        6. Otherwise -> exit 70.
    """
    exact = _EXACT_CODE_TO_EXIT.get(code)
    if exact is not None:
        return exact
    for prefix, exit_value in _PREFIX_TO_EXIT:
        if code.startswith(prefix):
            return exit_value
    if isinstance(http_status, int):
        if 500 <= http_status < 600:
            return EXIT_5XX_TRANSIENT
        if 400 <= http_status < 500:
            if retry_advice_mode in (
                "after_state_change",
                "retryable",
                "after_retry_after",
            ):
                return EXIT_4XX_REMEDIATE
            return EXIT_4XX_BLOCK
        if 200 <= http_status < 300:
            return EXIT_SUCCESS
    return EXIT_UNCAUGHT_INTERNAL


def exit_code_for_relay_error(error: RelayError) -> int:
    """Convenience wrapper for callers that hold a :class:`RelayError`."""
    advice = getattr(error, "retry_advice_dict", None)
    mode: str | None = None
    if isinstance(advice, dict):
        candidate = advice.get("mode")
        if isinstance(candidate, str):
            mode = candidate
    return exit_code_for_code_and_status(error.code, error.http_status, mode)


# Programmatic dump of the canonical exit-code table. Used by the
# cross-language parity fixture generator.
CANONICAL_EXIT_CODE_TABLE: dict[str, int] = {
    "EXIT_SUCCESS": EXIT_SUCCESS,
    "EXIT_4XX_BLOCK": EXIT_4XX_BLOCK,
    "EXIT_4XX_REMEDIATE": EXIT_4XX_REMEDIATE,
    "EXIT_4XX_AUTH_HANDOFF": EXIT_4XX_AUTH_HANDOFF,
    "EXIT_CASSETTE_MISS": EXIT_CASSETTE_MISS,
    "EXIT_5XX_TRANSIENT": EXIT_5XX_TRANSIENT,
    "EXIT_WAL_STORAGE": EXIT_WAL_STORAGE,
    "EXIT_GATE_TTL_EXPIRED": EXIT_GATE_TTL_EXPIRED,
    "EXIT_EVAL_DEFERRED": EXIT_EVAL_DEFERRED,
    "EXIT_CLI_USAGE": EXIT_CLI_USAGE,
    "EXIT_UNCAUGHT_INTERNAL": EXIT_UNCAUGHT_INTERNAL,
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
    "EXIT_GATE_TTL_EXPIRED",
    "EXIT_SUCCESS",
    "EXIT_UNCAUGHT_INTERNAL",
    "EXIT_WAL_STORAGE",
    "exit_code_for_code_and_status",
    "exit_code_for_relay_error",
]
