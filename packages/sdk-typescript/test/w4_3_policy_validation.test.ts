/**
 * W4.3 SDK-side redaction policy validation tests.
 *
 * Covers VAL-W4-022 (raw_capture without DPA -> typed refusal) and
 * VAL-W4-024 (policy parse error fails closed). Mirrors Python parity
 * tests in packages/sdk-python/tests/test_redaction.py VAL-W3-025 and
 * VAL-W3-026.
 *
 * Per CLAUDE.md keystone invariant #7 + banned pattern #11, the SDK
 * refuses to even attempt to construct a policy that would permit raw
 * plaintext capture without DPA + approver. The check happens
 * synchronously in the SDK constructor, before any HTTP call.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { loadRedactionPolicy, RedactionEngine } from "../src/redaction.js";
import {
  RelayPolicyError,
  RelayRedactionPolicyError,
  RelayRedactionRawCaptureDeniedError,
} from "../src/index.js";

const VALID_POLICY = {
  schema_version: "relay.redaction.v1",
  policy_version: "2026-05-12.001",
  raw_capture: false,
  dpa_ref: null,
  approver_user_id: null,
  matchers: [
    {
      id: "api_key",
      kind: "regex",
      pattern: "(sk-|key_)[A-Za-z0-9]{20,}",
      action: "redact",
    },
  ],
  action_policy: {
    hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3" },
    redact: { placeholder: "<redacted>" },
    drop: { placeholder: null },
  },
};

// -----------------------------------------------------------------------------
// VAL-W4-022 -- raw_capture without DPA + approver is refused.
// -----------------------------------------------------------------------------

describe("VAL-W4-022: raw_capture: true without DPA -> RelayRedactionRawCaptureDeniedError", () => {
  it("raw_capture=true with dpa_ref=null is refused with the specific typed error", () => {
    const bad = {
      ...VALID_POLICY,
      raw_capture: true,
      dpa_ref: null,
      approver_user_id: "8c7c2ec6-3a2b-4dba-9d36-5d8c2c1f64ed",
    };
    let caught: unknown = null;
    try {
      loadRedactionPolicy(bad);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayRedactionRawCaptureDeniedError);
    expect(caught).toBeInstanceOf(RelayRedactionPolicyError); // narrower-than parent
    expect(caught).toBeInstanceOf(RelayPolicyError); // backward-compat parent
    const err = caught as RelayRedactionRawCaptureDeniedError;
    expect(err.code).toBe("RELAY-SDK-016");
    expect(err.errorClass).toBe("RELAY-SDK-RAW-CAPTURE-DENIED");
    expect(err.details["reason"]).toBe("raw-capture-missing-dpa-or-approver");
    expect(err.details["missing"]).toEqual(["dpa_ref"]);
  });

  it("raw_capture=true with approver_user_id=null is refused", () => {
    const bad = {
      ...VALID_POLICY,
      raw_capture: true,
      dpa_ref: "dpa-12345",
      approver_user_id: null,
    };
    expect(() => loadRedactionPolicy(bad)).toThrowError(
      RelayRedactionRawCaptureDeniedError,
    );
  });

  it("raw_capture=true with neither dpa_ref nor approver_user_id lists both as missing", () => {
    const bad = {
      ...VALID_POLICY,
      raw_capture: true,
      dpa_ref: null,
      approver_user_id: null,
    };
    let caught: RelayRedactionRawCaptureDeniedError | null = null;
    try {
      loadRedactionPolicy(bad);
    } catch (e) {
      caught = e as RelayRedactionRawCaptureDeniedError;
    }
    expect(caught).not.toBeNull();
    expect((caught as RelayRedactionRawCaptureDeniedError).details["missing"]).toEqual([
      "dpa_ref",
      "approver_user_id",
    ]);
  });

  it("raw_capture=true with empty-string dpa_ref still fails (truthy check)", () => {
    const bad = {
      ...VALID_POLICY,
      raw_capture: true,
      dpa_ref: "",
      approver_user_id: "8c7c2ec6-3a2b-4dba-9d36-5d8c2c1f64ed",
    };
    expect(() => loadRedactionPolicy(bad)).toThrowError(
      RelayRedactionRawCaptureDeniedError,
    );
  });

  it("raw_capture=true with both dpa_ref AND approver_user_id loads cleanly", () => {
    const ok = {
      ...VALID_POLICY,
      raw_capture: true,
      dpa_ref: "dpa-2026-05-12",
      approver_user_id: "8c7c2ec6-3a2b-4dba-9d36-5d8c2c1f64ed",
    };
    const policy = loadRedactionPolicy(ok);
    expect(policy.rawCapture).toBe(true);
    expect(policy.dpaRef).toBe("dpa-2026-05-12");
    expect(policy.approverUserId).toBe("8c7c2ec6-3a2b-4dba-9d36-5d8c2c1f64ed");
  });

  it("VAL-W4-022 evidence: rejected policy never produces a usable engine", () => {
    const bad = {
      ...VALID_POLICY,
      raw_capture: true,
      dpa_ref: null,
      approver_user_id: null,
    };
    let policy: ReturnType<typeof loadRedactionPolicy> | null = null;
    try {
      policy = loadRedactionPolicy(bad);
    } catch {
      // expected
    }
    expect(policy).toBeNull();
    // No engine bound to a real policy exists, therefore no plaintext
    // can be redacted-and-shipped through the SDK -- the construction
    // of any engine using ``policy`` (which is null) is statically
    // impossible without a non-null assertion. The CONTRACT guarantee
    // is "no outbound HTTP attempt"; the structural enforcement is
    // that ``loadRedactionPolicy`` threw before any engine could be
    // built. Reference: redaction.ts:loadRedactionPolicy line 282-340.
  });
});

// -----------------------------------------------------------------------------
// VAL-W4-024 -- policy parse error fails closed.
// -----------------------------------------------------------------------------

describe("VAL-W4-024: policy parse error -> RelayRedactionPolicyError, fails closed", () => {
  it("malformed regex raises RelayRedactionPolicyError synchronously at load", () => {
    const bad = {
      ...VALID_POLICY,
      matchers: [
        {
          id: "bad",
          kind: "regex",
          pattern: "(unterminated[",
          action: "redact",
        },
      ],
    };
    let caught: unknown = null;
    try {
      loadRedactionPolicy(bad);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayRedactionPolicyError);
    expect(caught).toBeInstanceOf(RelayPolicyError); // backward-compat
    const err = caught as RelayRedactionPolicyError;
    expect(err.code).toBe("RELAY-SDK-010");
    expect(err.errorClass).toBe("RELAY-SDK-REDACTION-POLICY");
    expect(err.details["reason"]).toBe("bad_regex");
  });

  it("unknown matcher kind fails closed", () => {
    const bad = {
      ...VALID_POLICY,
      matchers: [{ id: "x", kind: "telepathy", pattern: "x", action: "redact" }],
    };
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("unknown action fails closed", () => {
    const bad = {
      ...VALID_POLICY,
      matchers: [{ id: "x", kind: "regex", pattern: "x", action: "obliterate" }],
    };
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("missing schema_version fails closed", () => {
    const bad: Record<string, unknown> = { ...VALID_POLICY };
    delete bad["schema_version"];
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("wrong schema_version literal fails closed", () => {
    const bad = { ...VALID_POLICY, schema_version: "relay.redaction.v0" };
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("non-object policy body fails closed", () => {
    expect(() => loadRedactionPolicy(null)).toThrowError(RelayRedactionPolicyError);
    expect(() => loadRedactionPolicy("not a policy")).toThrowError(RelayRedactionPolicyError);
    expect(() => loadRedactionPolicy([])).toThrowError(RelayRedactionPolicyError);
  });

  it("policy with unsupported hash algorithm fails closed", () => {
    const bad = {
      ...VALID_POLICY,
      action_policy: {
        ...VALID_POLICY.action_policy,
        hash: { algorithm: "sha256", salt_ref: "tenant_salt_v3" },
      },
    };
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("policy with empty hash salt_ref fails closed", () => {
    const bad = {
      ...VALID_POLICY,
      action_policy: {
        ...VALID_POLICY.action_policy,
        hash: { algorithm: "hmac-sha256", salt_ref: "" },
      },
    };
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("policy with non-bool raw_capture fails closed", () => {
    const bad = { ...VALID_POLICY, raw_capture: "true" as unknown as boolean };
    expect(() => loadRedactionPolicy(bad)).toThrowError(RelayRedactionPolicyError);
  });

  it("VAL-W4-024 evidence: a rejected policy never produces an engine", () => {
    const bad = {
      ...VALID_POLICY,
      matchers: [{ id: "bad", kind: "regex", pattern: "(unterminated[", action: "redact" }],
    };
    let policy: ReturnType<typeof loadRedactionPolicy> | null = null;
    try {
      policy = loadRedactionPolicy(bad);
    } catch {
      // expected
    }
    expect(policy).toBeNull();
  });
});
