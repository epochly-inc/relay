/**
 * W4.4 -- canonical exit-code mapping (VAL-W4-031).
 *
 * Asserts:
 *   1. The TS exit-code constants byte-equal the contract VAL-W4-031 table.
 *   2. The TS resolver agrees with the cross-language fixture at
 *      ``tests/conformance/cli-exit-codes/parity_fixtures.json``
 *      row-by-row, proving Py / TS parity (mirrored to W5 VAL-W5-006).
 *   3. The CANONICAL_EXIT_CODE_TABLE export matches the corpus's embedded
 *      canonical table.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
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
  exitCodeForCodeAndStatus,
  exitCodeForRelayError,
} from "../src/exit_codes.js";
import {
  RelayHandoffIncomplete,
  RelayRateLimitError,
  RelayUnknownError,
} from "../src/errors.js";

interface ExitCodeFixture {
  readonly name: string;
  readonly wire_code: string;
  readonly http_status: number | null;
  readonly retry_advice_mode: string | null;
  readonly expected_exit: number;
}

interface ExitCodeCorpus {
  readonly schema_version: string;
  readonly canonical_exit_code_table: Record<string, number>;
  readonly fixtures: ReadonlyArray<ExitCodeFixture>;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const CORPUS_PATH = path.join(
  REPO_ROOT,
  "tests",
  "conformance",
  "cli-exit-codes",
  "parity_fixtures.json",
);

function loadCorpus(): ExitCodeCorpus {
  return JSON.parse(fs.readFileSync(CORPUS_PATH, "utf8")) as ExitCodeCorpus;
}

const corpus = loadCorpus();

describe("VAL-W4-031: canonical exit-code constants", () => {
  it("exit-code constants byte-equal the contract VAL-W4-031 table", () => {
    expect(EXIT_SUCCESS).toBe(0);
    expect(EXIT_4XX_BLOCK).toBe(1);
    expect(EXIT_4XX_REMEDIATE).toBe(2);
    expect(EXIT_4XX_AUTH_HANDOFF).toBe(3);
    expect(EXIT_CASSETTE_MISS).toBe(4);
    expect(EXIT_5XX_TRANSIENT).toBe(5);
    expect(EXIT_WAL_STORAGE).toBe(6);
    expect(EXIT_GATE_TTL_EXPIRED).toBe(7);
    expect(EXIT_EVAL_DEFERRED).toBe(8);
    expect(EXIT_CLI_USAGE).toBe(64);
    expect(EXIT_UNCAUGHT_INTERNAL).toBe(70);
  });

  it("CANONICAL_EXIT_CODE_TABLE has exactly 11 named entries", () => {
    expect(Object.keys(CANONICAL_EXIT_CODE_TABLE).length).toBe(11);
    expect(CANONICAL_EXIT_CODE_TABLE.EXIT_SUCCESS).toBe(0);
    expect(CANONICAL_EXIT_CODE_TABLE.EXIT_UNCAUGHT_INTERNAL).toBe(70);
  });
});

describe("VAL-W4-031: TS resolver parity with Py corpus", () => {
  it("corpus loads with the expected schema_version", () => {
    expect(corpus.schema_version).toBe("relay.cli_exit_code_parity.v1");
    expect(corpus.fixtures.length).toBeGreaterThanOrEqual(12);
  });

  it("corpus canonical_exit_code_table byte-equals TS constants", () => {
    expect(corpus.canonical_exit_code_table).toEqual(CANONICAL_EXIT_CODE_TABLE);
  });

  for (const fixture of corpus.fixtures) {
    it(`fixture '${fixture.name}': TS resolver agrees with corpus expected_exit`, () => {
      const actual = exitCodeForCodeAndStatus(
        fixture.wire_code,
        fixture.http_status === null ? undefined : fixture.http_status,
        fixture.retry_advice_mode === null ? undefined : fixture.retry_advice_mode,
      );
      expect(
        actual,
        `row '${fixture.name}' TS mismatch: got ${actual}, expected ${fixture.expected_exit}`,
      ).toBe(fixture.expected_exit);
    });
  }
});

describe("VAL-W4-031: targeted resolver behaviors", () => {
  it("RELAY-AUTH-* prefix routes every code to exit 3 (auth/handoff)", () => {
    for (const code of ["RELAY-AUTH-001", "RELAY-AUTH-014", "RELAY-AUTH-999"]) {
      expect(exitCodeForCodeAndStatus(code, 401, "no_retry")).toBe(
        EXIT_4XX_AUTH_HANDOFF,
      );
    }
  });

  it("RELAY-GATE-021 routes to exit 3 even when the prefix would say otherwise", () => {
    expect(exitCodeForCodeAndStatus("RELAY-GATE-021", 422, "after_state_change")).toBe(
      EXIT_4XX_AUTH_HANDOFF,
    );
  });

  it("4xx with remediate-style retry advice routes to exit 2", () => {
    for (const mode of ["after_state_change", "retryable", "after_retry_after"]) {
      expect(exitCodeForCodeAndStatus("RELAY-ING-001", 422, mode)).toBe(
        EXIT_4XX_REMEDIATE,
      );
    }
  });

  it("4xx with no_retry routes to exit 1 (block)", () => {
    expect(exitCodeForCodeAndStatus("RELAY-ING-001", 422, "no_retry")).toBe(
      EXIT_4XX_BLOCK,
    );
  });

  it("5xx without storage prefix routes to exit 5; storage prefix routes to exit 6", () => {
    expect(exitCodeForCodeAndStatus("RELAY-SIDECAR-013", 503)).toBe(
      EXIT_5XX_TRANSIENT,
    );
    expect(exitCodeForCodeAndStatus("RELAY-SIDECAR-STORAGE-001", 500)).toBe(
      EXIT_WAL_STORAGE,
    );
    expect(exitCodeForCodeAndStatus("RELAY-SQLITE-001", 500)).toBe(EXIT_WAL_STORAGE);
  });

  it("RELAY-CASSETTE-MISS routes to exit 4 regardless of http_status", () => {
    expect(exitCodeForCodeAndStatus("RELAY-CASSETTE-MISS", 422)).toBe(
      EXIT_CASSETTE_MISS,
    );
    expect(exitCodeForCodeAndStatus("RELAY-CASSETTE-MISS", undefined)).toBe(
      EXIT_CASSETTE_MISS,
    );
  });

  it("RELAY-GATE-024 routes to exit 7 (gate TTL expired)", () => {
    expect(exitCodeForCodeAndStatus("RELAY-GATE-024", 422)).toBe(
      EXIT_GATE_TTL_EXPIRED,
    );
  });

  it("RELAY-EVAL-EVALUATOR-DEFERRED routes to exit 8 (LLM-judge deferred)", () => {
    expect(exitCodeForCodeAndStatus("RELAY-EVAL-EVALUATOR-DEFERRED", 422)).toBe(
      EXIT_EVAL_DEFERRED,
    );
  });

  it("unknown code with no http_status falls through to exit 70", () => {
    expect(exitCodeForCodeAndStatus("RELAY-FUTURE-999", undefined)).toBe(
      EXIT_UNCAUGHT_INTERNAL,
    );
  });

  it("unknown code with out-of-band http_status (999) falls through to exit 70", () => {
    expect(exitCodeForCodeAndStatus("RELAY-FUTURE-999", 999)).toBe(
      EXIT_UNCAUGHT_INTERNAL,
    );
  });
});

describe("VAL-W4-031: exitCodeForRelayError extracts mode from RetryAdvice dict", () => {
  it("reads retryAdvice.mode from a RelayError instance", () => {
    const err = new RelayRateLimitError("rate limit", { code: "RELAY-RATE-001" });
    // Default retry_advice for RelayRateLimitError is "after_retry_after".
    expect(exitCodeForRelayError(err)).toBe(EXIT_4XX_REMEDIATE);
  });

  it("RELAY-GATE-021 -> exit 3 via the typed leaf", () => {
    const err = new RelayHandoffIncomplete("stale", {
      code: "RELAY-GATE-021",
      retryAdvice: "after_state_change",
    });
    expect(exitCodeForRelayError(err)).toBe(EXIT_4XX_AUTH_HANDOFF);
  });

  it("RELAY-FUTURE-999 RelayUnknownError -> exit 5 (5xx) per its default http_status", () => {
    const err = new RelayUnknownError("future", { code: "RELAY-FUTURE-999" });
    // RelayUnknownError default http_status is 500 -> 5xx -> exit 5.
    expect(exitCodeForRelayError(err)).toBe(EXIT_5XX_TRANSIENT);
  });
});
