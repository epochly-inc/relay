/**
 * Relay canonical exit-code table (W4.4 / VAL-W4-031).
 *
 * Single source of truth for the process exit code that ANY Relay CLI or
 * adapter MUST emit when terminating due to a ``RelayError``. The table
 * below is byte-identical to the Python parity in
 * ``packages/sdk-python/relay/exit_codes.py`` and to the W5 CLI mapping
 * (VAL-W5-006). The cross-language fixture lives at
 * ``tests/conformance/cli-exit-codes/parity_fixtures.json``.
 *
 * Mapping (per contract.md VAL-W4-031, orchestrator decision EXIT CODE
 * TABLE):
 *
 *   exit 0  = success (2xx)
 *   exit 1  = 4xx with action=block
 *   exit 2  = 4xx with action=remediate
 *   exit 3  = 4xx auth/handoff (RELAY-GATE-021, RELAY-AUTH-*)
 *   exit 4  = cassette miss (RELAY-CASSETTE-MISS)
 *   exit 5  = 5xx + network transient
 *   exit 6  = WAL/storage error (RELAY-SIDECAR-STORAGE-*)
 *   exit 7  = gate TTL expired (RELAY-GATE-024)
 *   exit 8  = LLM-judge deferred (RELAY-EVAL-EVALUATOR-DEFERRED)
 *   exit 64 = wrong-flag (CLI usage error)
 *   exit 70 = uncaught internal
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import type { RelayError } from "./errors.js";

/**
 * Symbolic identifiers for each row of the canonical exit-code table.
 * Snake_case to match the Python parity constants byte-for-byte (parity
 * fixture cross-checks the value mapping, not the identifier name, so
 * the names are kept identical for human reviewers).
 */
export const EXIT_SUCCESS = 0;
export const EXIT_4XX_BLOCK = 1;
export const EXIT_4XX_REMEDIATE = 2;
export const EXIT_4XX_AUTH_HANDOFF = 3;
export const EXIT_CASSETTE_MISS = 4;
export const EXIT_5XX_TRANSIENT = 5;
export const EXIT_WAL_STORAGE = 6;
export const EXIT_GATE_TTL_EXPIRED = 7;
export const EXIT_EVAL_DEFERRED = 8;
export const EXIT_CLI_USAGE = 64;
export const EXIT_UNCAUGHT_INTERNAL = 70;

/**
 * Wire-code prefix or exact match keys that route to a specific exit
 * code. Order matters at lookup time: exact-code matches take precedence
 * over prefix matches; longer prefixes are scanned before shorter ones.
 *
 * The mapping intentionally mirrors the Python parity in
 * ``packages/sdk-python/relay/exit_codes.py``.
 */
const EXACT_CODE_TO_EXIT: Readonly<Record<string, number>> = {
  // 4xx auth + handoff -> exit 3.
  "RELAY-GATE-021": EXIT_4XX_AUTH_HANDOFF,
  // Cassette miss -> exit 4.
  "RELAY-CASSETTE-MISS": EXIT_CASSETTE_MISS,
  // Gate TTL expired -> exit 7.
  "RELAY-GATE-024": EXIT_GATE_TTL_EXPIRED,
  // LLM-judge deferred -> exit 8.
  "RELAY-EVAL-EVALUATOR-DEFERRED": EXIT_EVAL_DEFERRED,
  // CLI usage error (the SDK never raises this; the CLI binary owns it).
  "RELAY-CLI-070": EXIT_UNCAUGHT_INTERNAL,
};

const PREFIX_TO_EXIT: ReadonlyArray<readonly [string, number]> = [
  // Auth namespace -> exit 3.
  ["RELAY-AUTH-", EXIT_4XX_AUTH_HANDOFF],
  // WAL/storage -> exit 6 (sidecar storage subnamespace).
  ["RELAY-SIDECAR-STORAGE-", EXIT_WAL_STORAGE],
  // Generic SQLite -> exit 6 (storage layer).
  ["RELAY-SQLITE-", EXIT_WAL_STORAGE],
];

/**
 * Resolve the canonical exit code for a wire ``code`` + ``http_status``.
 *
 * Algorithm (mirrors Python):
 *   1. If the code is in the exact-code map, return that exit code.
 *   2. If the code matches a known prefix, return that exit code.
 *   3. If 5xx http_status -> exit 5.
 *   4. If 4xx http_status:
 *        - retry_advice mode 'after_state_change' or 'retryable' -> exit 2
 *          (remediate).
 *        - else -> exit 1 (block).
 *   5. If 2xx -> exit 0 (success; SDK never raises a RelayError for 2xx
 *      but the table covers it for completeness).
 *   6. Else -> exit 70 (uncaught internal).
 */
export function exitCodeForCodeAndStatus(
  code: string,
  httpStatus: number | undefined,
  retryAdviceMode?: string,
): number {
  const exact = EXACT_CODE_TO_EXIT[code];
  if (exact !== undefined) return exact;
  for (const [prefix, exit] of PREFIX_TO_EXIT) {
    if (code.startsWith(prefix)) return exit;
  }
  if (typeof httpStatus === "number") {
    if (httpStatus >= 500 && httpStatus < 600) return EXIT_5XX_TRANSIENT;
    if (httpStatus >= 400 && httpStatus < 500) {
      if (
        retryAdviceMode === "after_state_change" ||
        retryAdviceMode === "retryable" ||
        retryAdviceMode === "after_retry_after"
      ) {
        return EXIT_4XX_REMEDIATE;
      }
      return EXIT_4XX_BLOCK;
    }
    if (httpStatus >= 200 && httpStatus < 300) return EXIT_SUCCESS;
  }
  return EXIT_UNCAUGHT_INTERNAL;
}

/**
 * Convenience wrapper for callers that hold a ``RelayError`` instance.
 * Reads ``code``, ``httpStatus``, and ``retryAdvice.mode`` from the
 * exception and routes through :func:`exitCodeForCodeAndStatus`.
 */
export function exitCodeForRelayError(error: RelayError): number {
  return exitCodeForCodeAndStatus(
    error.code,
    error.httpStatus,
    typeof error.retryAdvice?.mode === "string" ? error.retryAdvice.mode : undefined,
  );
}

/**
 * Programmatic dump of the canonical exit-code table. Used by the
 * cross-language parity fixture generator to assert that Py and TS share
 * the same set of symbolic values.
 */
export const CANONICAL_EXIT_CODE_TABLE: Readonly<Record<string, number>> = {
  EXIT_SUCCESS,
  EXIT_4XX_BLOCK,
  EXIT_4XX_REMEDIATE,
  EXIT_4XX_AUTH_HANDOFF,
  EXIT_CASSETTE_MISS,
  EXIT_5XX_TRANSIENT,
  EXIT_WAL_STORAGE,
  EXIT_GATE_TTL_EXPIRED,
  EXIT_EVAL_DEFERRED,
  EXIT_CLI_USAGE,
  EXIT_UNCAUGHT_INTERNAL,
};
