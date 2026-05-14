/**
 * W4.4 -- TS error envelope parity (VAL-W4-026..028, VAL-W4-030).
 *
 * Covers:
 *   VAL-W4-026: RelayError base class fields.
 *   VAL-W4-027: RetryAdvice is a discriminated union (NOT boolean).
 *   VAL-W4-028: Every spec error code maps to exactly one TS subclass.
 *   VAL-W4-030: Unknown sidecar code -> RelayUnknownError with raw fields
 *               preserved + structured warning on stderr.
 *
 * Cross-language byte-equal round-trip (VAL-W4-029) lives in
 * ``w4_4_cross_language_parity.test.ts``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  coerceRetryAdvice,
  RelayAuthError,
  RelayCanonicalStatusForbidden,
  RelayConfigError,
  RelayError,
  RelayEvidenceError,
  RelayEvidenceIncomplete,
  RelayGateError,
  RelayHandoffIncomplete,
  RelayIngestError,
  RelayLifecycleInvalid,
  RelayPolicyError,
  RelayRateLimitError,
  RelayReplayError,
  RelayReplayPrecondition,
  RelaySchemaError,
  RelaySdkError,
  RelaySidecarAuthError,
  RelaySidecarError,
  RelaySidecarNotReachable,
  RelaySidecarVersionMismatch,
  RelaySQLiteError,
  RelayUnknownError,
  resolveClassForCode,
  type RetryAdvice,
} from "../src/errors.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -----------------------------------------------------------------------------
// VAL-W4-026: RelayError base-class fields
// -----------------------------------------------------------------------------

describe("VAL-W4-026: RelayError base class exposes spec-required fields", () => {
  it("RelayError instance carries every required readonly property", () => {
    const err = new RelayIngestError("ingest envelope rejected", {
      code: "RELAY-ING-001",
      requestId: "req_abc",
      traceId: "trace_xyz",
      details: { observed: "rejected_field" },
    });
    expect(typeof err.code).toBe("string");
    expect(typeof err.errorClass).toBe("string");
    expect(typeof err.httpStatus).toBe("number");
    expect(typeof err.blockedSurface).toBe("string");
    expect(typeof err.documentationUrl).toBe("string");
    expect(typeof err.retryAdvice).toBe("object");
    expect(typeof err.retryAdvice.mode).toBe("string");
    expect(err.requestId).toBe("req_abc");
    expect(err.traceId).toBe("trace_xyz");
    expect(err.details).toEqual({ observed: "rejected_field" });
    expect(err instanceof Error).toBe(true);
    expect(err instanceof RelayError).toBe(true);
  });

  it("envelope schema_version is pinned to relay.sdk_error.v1", () => {
    const err = new RelayIngestError("x", { code: "RELAY-ING-001" });
    expect(err.toEnvelope().schema_version).toBe("relay.sdk_error.v1");
  });

  it("documentationUrl defaults to the canonical docs prefix + code", () => {
    const err = new RelayIngestError("x", { code: "RELAY-ING-014" });
    expect(err.documentationUrl).toBe(
      "https://relay.epochly.com/docs/errors/RELAY-ING-014",
    );
  });

  it("toEnvelope returns all 11 canonical fields", () => {
    const err = new RelayHandoffIncomplete("stale handoff", {
      code: "RELAY-GATE-021",
      requestId: "req_g21",
      traceId: "trace_g21",
      details: { mismatched_anchor: "manifest_commit_hash" },
    });
    const envelope = err.toEnvelope();
    const keys = Object.keys(envelope).sort();
    expect(keys).toEqual([
      "blocked_surface",
      "code",
      "details",
      "documentation_url",
      "error_class",
      "http_status",
      "message",
      "request_id",
      "retry_advice",
      "schema_version",
      "trace_id",
    ]);
  });
});

// -----------------------------------------------------------------------------
// VAL-W4-027: RetryAdvice discriminated union (NOT boolean)
// -----------------------------------------------------------------------------

describe("VAL-W4-027: retryAdvice is a discriminated union, NOT a boolean", () => {
  it("boolean true coerces to {mode: 'no_retry'}, never preserved as boolean", () => {
    const advice = coerceRetryAdvice(true);
    expect(typeof advice).toBe("object");
    expect(advice.mode).toBe("no_retry");
    expect(typeof advice.mode).toBe("string");
  });

  it("boolean false coerces to {mode: 'no_retry'}, never preserved as boolean", () => {
    const advice = coerceRetryAdvice(false);
    expect(typeof advice).toBe("object");
    expect(advice.mode).toBe("no_retry");
  });

  it("known wire enum strings map to structured dict shapes", () => {
    expect(coerceRetryAdvice("do_not_retry")).toEqual({ mode: "no_retry" });
    expect(coerceRetryAdvice("after_fix")).toEqual({ mode: "after_state_change" });
    expect(coerceRetryAdvice("after_retry_after")).toEqual({
      mode: "after_retry_after",
    });
    expect(coerceRetryAdvice("after_split")).toEqual({ mode: "after_state_change" });
    expect(coerceRetryAdvice("after_recapture")).toEqual({
      mode: "after_state_change",
    });
    expect(coerceRetryAdvice("after_re_auth")).toEqual({
      mode: "after_state_change",
    });
  });

  it("SDK mode strings round-trip as {mode}", () => {
    for (const mode of [
      "no_retry",
      "retryable",
      "after_state_change",
      "after_retry_after",
    ] as const) {
      expect(coerceRetryAdvice(mode)).toEqual({ mode });
    }
  });

  it("unknown string falls closed to {mode: 'no_retry', raw}", () => {
    expect(coerceRetryAdvice("definitely_not_a_mode")).toEqual({
      mode: "no_retry",
      raw: "definitely_not_a_mode",
    });
  });

  it("dict input preserves extra keys when mode is known", () => {
    const advice = coerceRetryAdvice({
      mode: "after_retry_after",
      delay_seconds: 30,
      max_attempts: 5,
    });
    expect(advice.mode).toBe("after_retry_after");
    expect(advice.delay_seconds).toBe(30);
    expect(advice.max_attempts).toBe(5);
  });

  it("rate-limit error default retry_advice is after_retry_after (not boolean)", () => {
    const err = new RelayRateLimitError("rate limit", { code: "RELAY-RATE-001" });
    expect(err.retryAdvice.mode).toBe("after_retry_after");
    expect(typeof err.retryAdvice.mode).toBe("string");
  });

  it("CI grep guard: retryable as boolean is absent from src/", () => {
    const SRC_DIR = path.resolve(__dirname, "..", "src");
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.isFile() && /\.(ts|tsx|mts|cts)$/.test(entry.name)) {
          const text = fs.readFileSync(full, "utf8");
          if (/retryable\s*:\s*(true|false|boolean)/.test(text)) {
            offenders.push(full);
          }
        }
      }
    };
    walk(SRC_DIR);
    expect(offenders, `retryable boolean shape found in: ${offenders.join(", ")}`).toEqual(
      [],
    );
  });
});

// -----------------------------------------------------------------------------
// VAL-W4-028: every spec error code maps to exactly one TS subclass
// -----------------------------------------------------------------------------

describe("VAL-W4-028: every spec error code maps to exactly one TS subclass", () => {
  // Each row: [wire_code, expected_class_constructor, expected_class_name].
  const cases: ReadonlyArray<readonly [string, typeof RelayError, string]> = [
    ["RELAY-ING-001", RelayIngestError, "RelayIngestError"],
    ["RELAY-ING-014", RelayIngestError, "RelayIngestError"],
    ["RELAY-ING-021", RelayIngestError, "RelayIngestError"],
    ["RELAY-ING-031", RelayCanonicalStatusForbidden, "RelayCanonicalStatusForbidden"],
    ["RELAY-ING-022", RelayHandoffIncomplete, "RelayHandoffIncomplete"],
    ["RELAY-ING-032", RelayPolicyError, "RelayPolicyError"],
    ["RELAY-AUTH-001", RelayAuthError, "RelayAuthError"],
    ["RELAY-AUTH-014", RelayAuthError, "RelayAuthError"],
    ["RELAY-RATE-001", RelayRateLimitError, "RelayRateLimitError"],
    ["RELAY-RATE-014", RelayRateLimitError, "RelayRateLimitError"],
    ["RELAY-GATE-001", RelayGateError, "RelayGateError"],
    ["RELAY-GATE-014", RelayGateError, "RelayGateError"],
    ["RELAY-GATE-021", RelayHandoffIncomplete, "RelayHandoffIncomplete"],
    ["RELAY-EVID-001", RelayEvidenceError, "RelayEvidenceError"],
    ["RELAY-EVID-014", RelayEvidenceError, "RelayEvidenceError"],
    ["RELAY-EVID-002", RelayEvidenceIncomplete, "RelayEvidenceIncomplete"],
    ["RELAY-REPLAY-001", RelayReplayError, "RelayReplayError"],
    ["RELAY-REPLAY-014", RelayReplayError, "RelayReplayError"],
    ["RELAY-REPLAY-002", RelayReplayPrecondition, "RelayReplayPrecondition"],
    ["RELAY-SCHEMA-014", RelaySchemaError, "RelaySchemaError"],
    ["RELAY-SIDECAR-002", RelaySidecarError, "RelaySidecarError"],
    ["RELAY-SQLITE-001", RelaySQLiteError, "RelaySQLiteError"],
    ["RELAY-SDK-001", RelayConfigError, "RelayConfigError"],
    ["RELAY-SDK-002", RelaySidecarVersionMismatch, "RelaySidecarVersionMismatch"],
    ["RELAY-SDK-003", RelaySidecarNotReachable, "RelaySidecarNotReachable"],
    ["RELAY-SDK-004", RelaySidecarAuthError, "RelaySidecarAuthError"],
    ["RELAY-SDK-006", RelayLifecycleInvalid, "RelayLifecycleInvalid"],
    ["RELAY-SDK-007", RelayHandoffIncomplete, "RelayHandoffIncomplete"],
    ["RELAY-SDK-008", RelayEvidenceIncomplete, "RelayEvidenceIncomplete"],
    ["RELAY-SDK-009", RelayReplayPrecondition, "RelayReplayPrecondition"],
    ["RELAY-SDK-010", RelayPolicyError, "RelayPolicyError"],
  ];

  for (const [code, ctor, name] of cases) {
    it(`code ${code} resolves to ${name}`, () => {
      const cls = resolveClassForCode(code);
      expect(cls, `resolveClassForCode(${code}) returned ${cls.name}`).toBe(ctor);

      // And constructing an envelope with that code yields an instanceof match.
      const err = RelayError.fromEnvelope({
        code,
        message: "test",
        http_status: 422,
      });
      expect(err instanceof ctor, `${code} did not instanceof ${name}`).toBe(true);
      expect(err.code).toBe(code);
    });
  }

  it("the assertion matrix covers >= 16 distinct codes (VAL-W4-028 spec table)", () => {
    const codes = new Set(cases.map(([c]) => c));
    expect(codes.size).toBeGreaterThanOrEqual(16);
  });
});

// -----------------------------------------------------------------------------
// VAL-W4-030: unknown sidecar code -> RelayUnknownError + structured warning
// -----------------------------------------------------------------------------

describe("VAL-W4-030: unknown sidecar code -> RelayUnknownError, raw fields preserved", () => {
  // Direct monkey-patch of process.stderr.write to capture warning lines
  // without depending on vitest's MockInstance (which has overload-shape
  // mismatches with the Node stderr signature).
  let originalWrite: typeof process.stderr.write | null = null;
  let captured: string[] = [];

  beforeEach(() => {
    captured = [];
    originalWrite = process.stderr.write.bind(process.stderr);
    // The monkey-patched function intentionally narrows the overload set
    // to the single (chunk: string) signature exercised by the warning
    // emitter. Any other internal stderr writer that hits this path
    // during a test will be observed verbatim.
    (process.stderr as unknown as { write: (chunk: string) => boolean }).write = (
      chunk: string,
    ) => {
      captured.push(chunk);
      return true;
    };
  });

  afterEach(() => {
    if (originalWrite !== null) {
      (process.stderr as unknown as { write: typeof process.stderr.write }).write =
        originalWrite;
    }
    originalWrite = null;
    captured = [];
  });

  it("a forged RELAY-FUTURE-999 code instantiates as RelayUnknownError", () => {
    const err = RelayError.fromEnvelope({
      code: "RELAY-FUTURE-999",
      message: "unknown forward-compat code",
      http_status: 500,
      request_id: "req_999",
      trace_id: "trace_999",
      details: { raw_payload: { forward: true } },
    });
    expect(err instanceof RelayUnknownError).toBe(true);
    expect(err.code).toBe("RELAY-FUTURE-999");
  });

  it("emits a structured warning to stderr in the relay.error.v1 shape", () => {
    RelayError.fromEnvelope({
      code: "RELAY-FUTURE-999",
      message: "unknown forward-compat code",
      http_status: 500,
    });
    // At least one captured stderr line carries the structured warning.
    const warningLine = captured.find((c) => c.includes("RELAY-FUTURE-999"));
    expect(warningLine, "no structured warning emitted to stderr").toBeDefined();
    if (warningLine === undefined) return;
    const parsed = JSON.parse(warningLine.trimEnd()) as Record<string, unknown>;
    expect(parsed["schema_version"]).toBe("relay.error.v1");
    expect(parsed["level"]).toBe("warn");
    expect(parsed["code"]).toBe("RELAY-FUTURE-999");
    expect(parsed["observed_envelope"]).toMatchObject({
      code: "RELAY-FUTURE-999",
      message: "unknown forward-compat code",
      http_status: 500,
    });
  });

  it("does NOT emit the structured warning for known typed-leaf codes", () => {
    RelayError.fromEnvelope({
      code: "RELAY-ING-031",
      message: "canonical-result fields rejected",
      http_status: 422,
    });
    const offenders = captured.filter((c) => c.includes("RELAY-ING-031"));
    expect(
      offenders,
      "structured warning emitted for a known code (must be silent)",
    ).toEqual([]);
  });

  it("all original envelope fields are preserved verbatim", () => {
    const wireEnvelope = {
      code: "RELAY-FUTURE-999",
      message: "unknown forward-compat code",
      http_status: 500,
      request_id: "req_999",
      trace_id: "trace_999",
      blocked_surface: "POST /v1/hypothetical",
      documentation_url: "https://example.com/docs/RELAY-FUTURE-999",
      details: { raw_payload: { forward: true } },
    };
    const err = RelayError.fromEnvelope(wireEnvelope);
    expect(err.code).toBe(wireEnvelope.code);
    expect(err.message).toBe(wireEnvelope.message);
    expect(err.httpStatus).toBe(wireEnvelope.http_status);
    expect(err.requestId).toBe(wireEnvelope.request_id);
    expect(err.traceId).toBe(wireEnvelope.trace_id);
    expect(err.blockedSurface).toBe(wireEnvelope.blocked_surface);
    expect(err.documentationUrl).toBe(wireEnvelope.documentation_url);
    expect(err.details).toEqual(wireEnvelope.details);
  });

  it("an entirely-novel namespace (RELAY-FUTUREZZZ-001) also maps to RelayUnknownError", () => {
    const err = RelayError.fromEnvelope({
      code: "RELAY-FUTUREZZZ-001",
      message: "novel namespace",
    });
    expect(err instanceof RelayUnknownError).toBe(true);
    expect(err.code).toBe("RELAY-FUTUREZZZ-001");
  });

  it("RelayUnknownError carries error_class RELAY-UNKNOWN-ERROR by default", () => {
    const err = new RelayUnknownError("synthesized", { code: "RELAY-FUTURE-999" });
    expect(err.errorClass).toBe("RELAY-UNKNOWN-ERROR");
  });

  it("RelayUnknownError round-trips through toEnvelope and fromEnvelope", () => {
    const original = new RelayUnknownError("future", {
      code: "RELAY-FUTURE-999",
      requestId: "req_999",
      traceId: "trace_999",
      details: { foo: "bar" },
    });
    const env = original.toEnvelope();
    const reborn = RelayError.fromEnvelope(env);
    expect(reborn instanceof RelayUnknownError).toBe(true);
    expect(reborn.code).toBe(original.code);
    expect(reborn.requestId).toBe(original.requestId);
    expect(reborn.traceId).toBe(original.traceId);
    expect(reborn.details).toEqual(original.details);
  });
});

// -----------------------------------------------------------------------------
// Hierarchy invariants (parity with the Python W3.4 hierarchy guard).
// -----------------------------------------------------------------------------

describe("RelayError hierarchy invariants (W3.4 / W4.4 parity)", () => {
  it("every typed leaf subclasses a namespace intermediate which subclasses RelayError", () => {
    const checks: Array<[typeof RelayError, typeof RelayError]> = [
      [RelayCanonicalStatusForbidden, RelayIngestError],
      [RelayHandoffIncomplete, RelayIngestError],
      [RelayPolicyError, RelayIngestError],
      [RelaySidecarAuthError, RelayAuthError],
      [RelayEvidenceIncomplete, RelayEvidenceError],
      [RelayReplayPrecondition, RelayReplayError],
      [RelaySidecarVersionMismatch, RelaySidecarError],
      [RelaySidecarNotReachable, RelaySidecarError],
      [RelayConfigError, RelaySdkError],
      [RelayLifecycleInvalid, RelaySdkError],
    ];
    for (const [leaf, intermediate] of checks) {
      const inst = new leaf("x", { code: "RELAY-ING-001" });
      expect(
        inst instanceof intermediate,
        `${leaf.name} not instanceof ${intermediate.name}`,
      ).toBe(true);
      expect(inst instanceof RelayError, `${leaf.name} not instanceof RelayError`).toBe(
        true,
      );
    }
  });

  it("RetryAdvice mode field is always one of the four canonical values for known modes", () => {
    const known: ReadonlyArray<RetryAdvice> = [
      { mode: "no_retry" },
      { mode: "retryable" },
      { mode: "after_state_change" },
      { mode: "after_retry_after" },
    ];
    for (const advice of known) {
      const re = coerceRetryAdvice(advice);
      expect(re.mode).toBe(advice.mode);
    }
  });
});
