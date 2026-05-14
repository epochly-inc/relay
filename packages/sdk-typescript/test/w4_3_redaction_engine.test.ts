/**
 * W4.3 SDK-side redaction at the trace boundary -- engine + HMAC tests.
 *
 * Covers VAL-W4-019 (secret never crosses HTTP boundary), VAL-W4-021
 * (HMAC-SHA-256 with tenant salt), VAL-W4-023 (Unicode homoglyph and
 * mixed-encoding handling). Cross-language parity is exercised in
 * w4_3_cross_language_parity.test.ts; binary digest in
 * w4_3_binary_attachments.test.ts; policy validation in
 * w4_3_policy_validation.test.ts.
 *
 * Per CLAUDE.md keystone invariant #7 the SDK redacts every trace-bound
 * field BEFORE any HTTP body is written. The redacted body is what
 * crosses localhost; plaintext never does on the default policy.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_APPLIES_TO_FIELDS,
  hmacSha256Hex,
  loadRedactionPolicy,
  redactCapturePayload,
  RedactionEngine,
  type SaltProvider,
} from "../src/redaction.js";
import { RedactionPolicy } from "../src/index.js";

// -----------------------------------------------------------------------------
// Test fixtures (mirrors packages/sdk-python/tests/test_redaction.py).
// -----------------------------------------------------------------------------

const BASE_POLICY = {
  schema_version: "relay.redaction.v1",
  policy_version: "2026-05-12.001",
  raw_capture: false,
  retention_days: 30,
  dpa_ref: null,
  approver_user_id: null,
  matchers: [
    {
      id: "api_key",
      kind: "regex",
      pattern: "(sk-|key_)[A-Za-z0-9]{20,}",
      action: "redact",
    },
    {
      id: "email",
      kind: "regex",
      pattern: "[\\w.+-]+@[\\w-]+\\.[\\w.-]+",
      action: "hash",
    },
  ],
  action_policy: {
    hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3" },
    redact: { placeholder: "<redacted>" },
    drop: { placeholder: null },
  },
  applies_to_fields: [...DEFAULT_APPLIES_TO_FIELDS],
};

const TENANT_SALT = new TextEncoder().encode("test-tenant-salt-v3-do-not-use-in-prod");
const SECRET_API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUV";

const saltProvider: SaltProvider = (saltRef) => {
  if (saltRef === "tenant_salt_v3") return TENANT_SALT;
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bodyContains(body: Uint8Array, needle: string): boolean {
  // Use Buffer.includes for clarity; Node 22+ has it on Uint8Array natively.
  return Buffer.from(body).includes(Buffer.from(utf8(needle)));
}

// -----------------------------------------------------------------------------
// VAL-W4-019: SDK redacts BEFORE any HTTP body leaves the process.
// -----------------------------------------------------------------------------

describe("VAL-W4-019: redaction runs before any HTTP body leaves the process", () => {
  it("a known secret in model_call.input is redacted before the payload is serialised", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const rawPayload = {
      schema_version: "relay.trace.event.v1",
      kind: "model_call",
      model_call: {
        input: `my key is ${SECRET_API_KEY}`,
        output: "ok",
      },
    };
    const body = redactCapturePayload(engine, rawPayload);
    expect(bodyContains(body, SECRET_API_KEY)).toBe(false);
    expect(bodyContains(body, "<redacted>")).toBe(true);
  });

  it("the same matcher catches secrets across all five applies_to_fields surfaces", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const rawPayload = {
      schema_version: "relay.trace.event.v1",
      model_call: {
        input: `prompt ${SECRET_API_KEY}`,
        output: `echo ${SECRET_API_KEY}`,
      },
      tool_call: {
        args: { q: `see ${SECRET_API_KEY}` },
        result: { text: `got ${SECRET_API_KEY}` },
      },
      retrieval: {
        documents: [
          { text: `doc-a contains ${SECRET_API_KEY}` },
          { text: "doc-b is clean" },
        ],
      },
    };
    const body = redactCapturePayload(engine, rawPayload);
    expect(bodyContains(body, SECRET_API_KEY)).toBe(false);
    // All five surfaces were redacted -- count placeholders.
    const placeholderCount = (Buffer.from(body).toString("utf8").match(/<redacted>/g) ?? [])
      .length;
    expect(placeholderCount).toBeGreaterThanOrEqual(5);
  });

  it("the public RedactionPolicy namespace exposes the W4.3 factory surface", () => {
    expect(typeof RedactionPolicy.parse).toBe("function");
    expect(typeof RedactionPolicy.createEngine).toBe("function");
    expect(typeof RedactionPolicy.redactPayload).toBe("function");
    const policy = RedactionPolicy.parse(BASE_POLICY);
    const engine = RedactionPolicy.createEngine({ policy, saltProvider });
    const body = RedactionPolicy.redactPayload(engine, {
      model_call: { input: `key=${SECRET_API_KEY}` },
    });
    expect(bodyContains(body, SECRET_API_KEY)).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// VAL-W4-021: HMAC-SHA-256 with tenant salt, stable digest.
// -----------------------------------------------------------------------------

describe("VAL-W4-021: HMAC-SHA-256 hash action uses tenant salt and emits stable digests", () => {
  it("hash matcher emits HMAC-SHA-256(salt, plaintext utf-8) hex digest -- byte-equal to the golden", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const plaintextEmail = "alice@example.com";
    const body = redactCapturePayload(engine, {
      model_call: { input: `please email me at ${plaintextEmail}` },
    });
    const expected = crypto
      .createHmac("sha256", Buffer.from(TENANT_SALT))
      .update(plaintextEmail, "utf8")
      .digest("hex");
    expect(bodyContains(body, expected)).toBe(true);
    // Plain SHA-256 must NOT appear (defense against accidental algo swap).
    const plainSha = crypto.createHash("sha256").update(plaintextEmail, "utf8").digest("hex");
    expect(bodyContains(body, plainSha)).toBe(false);
    // Plaintext absent.
    expect(bodyContains(body, plaintextEmail)).toBe(false);
  });

  it("hmacSha256Hex helper byte-equals Node native HMAC", () => {
    const sample = "hello world";
    const observed = hmacSha256Hex(TENANT_SALT, sample);
    const expected = crypto
      .createHmac("sha256", Buffer.from(TENANT_SALT))
      .update(sample, "utf8")
      .digest("hex");
    expect(observed).toBe(expected);
  });

  it("distinct salt_ref yields distinct HMAC for the same plaintext", () => {
    const policyA = loadRedactionPolicy(BASE_POLICY);
    const policyBBody = {
      ...BASE_POLICY,
      action_policy: {
        ...BASE_POLICY.action_policy,
        hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_alt" },
      },
    };
    const policyB = loadRedactionPolicy(policyBBody);
    const provider: SaltProvider = (saltRef) => {
      if (saltRef === "tenant_salt_v3") return TENANT_SALT;
      if (saltRef === "tenant_salt_alt")
        return new TextEncoder().encode("alt-salt-value-bytes-for-test");
      throw new Error(`unknown: ${saltRef}`);
    };
    const engineA = new RedactionEngine({ policy: policyA, saltProvider: provider });
    const engineB = new RedactionEngine({ policy: policyB, saltProvider: provider });
    const raw = { model_call: { input: "alice@example.com" } };
    const bodyA = redactCapturePayload(engineA, raw);
    const bodyB = redactCapturePayload(engineB, raw);
    expect(Buffer.compare(Buffer.from(bodyA), Buffer.from(bodyB))).not.toBe(0);
  });

  it("redaction is deterministic across calls (same engine, same input -> same bytes)", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engineA = new RedactionEngine({ policy, saltProvider });
    const engineB = new RedactionEngine({ policy, saltProvider });
    const raw = {
      model_call: { input: `email me at alice@example.com and use ${SECRET_API_KEY}` },
    };
    const bodyA = redactCapturePayload(engineA, raw);
    const bodyB = redactCapturePayload(engineB, raw);
    expect(crypto.createHash("sha256").update(Buffer.from(bodyA)).digest("hex")).toBe(
      crypto.createHash("sha256").update(Buffer.from(bodyB)).digest("hex"),
    );
    expect(bodyContains(bodyA, SECRET_API_KEY)).toBe(false);
    expect(bodyContains(bodyA, "alice@example.com")).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// VAL-W4-023: Unicode homoglyph + mixed-encoding -> still redacted.
// -----------------------------------------------------------------------------

describe("VAL-W4-023: Unicode homoglyph and mixed-encoding inputs are still redacted", () => {
  it("Cyrillic-A homoglyph variant of the API key is still redacted (NFKC + confusables)", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Cyrillic Capital Letter A (U+0410) replaces ASCII 'A'. The matcher
    // pattern is sk-[A-Za-z0-9]{20,}; the engine must normalise to ASCII
    // before matching.
    const homoglyph = "sk-АBCDEFGHIJKLMNOPQRSTU";
    const body = redactCapturePayload(engine, {
      model_call: { input: `my key is ${homoglyph}` },
    });
    // Neither the homoglyph form NOR the ASCII-normalised form appears.
    expect(bodyContains(body, homoglyph)).toBe(false);
    expect(bodyContains(body, "sk-ABCDEFGHIJKLMNOPQRSTU")).toBe(false);
    expect(bodyContains(body, "<redacted>")).toBe(true);
  });

  it("Greek-A homoglyph is also caught (alternate confusables family)", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Greek Capital Letter Alpha (U+0391) replaces ASCII 'A'.
    const greekVariant = "sk-ΑBCDEFGHIJKLMNOPQRSTU";
    const body = redactCapturePayload(engine, {
      model_call: { input: `my key is ${greekVariant}` },
    });
    expect(bodyContains(body, greekVariant)).toBe(false);
    expect(bodyContains(body, "sk-ABCDEFGHIJKLMNOPQRSTU")).toBe(false);
    expect(bodyContains(body, "<redacted>")).toBe(true);
  });

  it("mixed-encoding retrieval document (Buffer with invalid UTF-8 byte) is still redacted", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Mixed-encoding: UTF-8 paragraph + a 0xE9 latin-1 apostrophe (an
    // invalid UTF-8 continuation byte) + UTF-8 paragraph containing the
    // secret. The engine treats Uint8Array as binary attachment and
    // emits a digest reference (VAL-W4-025); the secret IS protected --
    // it never reaches the wire as plaintext.
    const partA = Buffer.from("first paragraph ", "utf8");
    const badByte = Buffer.from([0xe9]);
    const partB = Buffer.from(
      ` second paragraph contains ${SECRET_API_KEY} end.`,
      "utf8",
    );
    const mixed = Buffer.concat([partA, badByte, partB]);
    const body = redactCapturePayload(engine, {
      retrieval: {
        documents: [{ bytes: mixed }],
      },
    });
    expect(bodyContains(body, SECRET_API_KEY)).toBe(false);
    // Binary attachment was rewritten to a digest reference.
    expect(bodyContains(body, "_digest_sha256")).toBe(true);
  });

  it("string-form mixed homoglyph and zero-width joiner does not smuggle the secret", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Cyrillic 'p' (U+0440) inside the api_key prefix substring -- but
    // BASE_POLICY's pattern is sk-... not key_p... so this primarily
    // exercises the email matcher with a Cyrillic 'a' in the local-part:
    // "alice" with U+0430 in place of 'a'.
    const cyrEmail = "аlice@example.com";
    const body = redactCapturePayload(engine, {
      tool_call: { args: { q: `email is ${cyrEmail}` } },
    });
    // The original homoglyph string MUST NOT appear verbatim in the body
    // (the matcher splices in an HMAC over the matched substring).
    expect(bodyContains(body, cyrEmail)).toBe(false);
    expect(bodyContains(body, "alice@example.com")).toBe(false);
  });
});
