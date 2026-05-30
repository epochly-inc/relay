/**
 * VAL-REDACT-001 (HIGH / security; TS parity gap).
 *
 * The PYTHON SDK fixed the json_pointer single-segment ``*`` wildcard
 * (relay/packages/sdk-python/relay/redaction.py ``_json_pointer_matches`` /
 * ``_find_json_pointer_match``). The TS SDK ``findJsonPointerMatch``
 * (packages/sdk-typescript/src/redaction.ts) still used exact membership
 * ``matcher.jsonPaths.includes(pointer)``.
 *
 * The hosted default policy declares the json_pointer matcher
 * "/messages/<star>/content/text" (a single-segment wildcard). Real chat
 * payloads produce array-indexed leaf pointers like
 * "/messages/0/content/text". With exact membership the literal-wildcard
 * matcher path NEVER matched the indexed pointer, so the TS SDK
 * UNDER-REDACTED -- prompt content (SSNs, etc.) was emitted VERBATIM. That is
 * the live VAL-REDACT-001 bug, still present on TS.
 *
 * Fix: the TS ``jsonPointerMatches`` interprets a wildcard ("*") reference
 * token in a ``json_pointer`` matcher path as a single-segment wildcard
 * matching any one array index or object key, mirroring Python token-by-token:
 * equal segment count required (no recursive-descent glob), a wildcard-free
 * path reduces to exact equality, and a literal-wildcard object key in the
 * payload is matched by the wildcard (redacts more -- safe).
 *
 * Keystone invariant #7 (default-deny raw capture): Python and TS MUST agree
 * byte-for-byte. The Python<->TS byte-equality is proven in the Python parity
 * suite (packages/sdk-python/tests/test_redaction_parity.py) via a live Node
 * subprocess; this file proves the TS-side behavior.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, it, expect } from "vitest";
import {
  loadRedactionPolicy,
  RedactionEngine,
  redactCapturePayload,
} from "../src/redaction.js";

// The hosted default policy matcher set (single source of truth lives in
// packages/schemas/raw/redaction-policy.default.v1.yaml and the Python
// HOSTED_DEFAULT_POLICY constant). The TS SDK does not export a default-policy
// constant; inline it to exercise the exact shipping shape, including the
// json_pointer ``/messages/*/content/text`` matcher under test.
const HOSTED_DEFAULT_POLICY: Record<string, unknown> = {
  schema_version: "relay.redaction.v1",
  policy_version: "hosted-default.v1",
  raw_capture: false,
  dpa_ref: null,
  approver_user_id: null,
  matchers: [
    { id: "prompt-content", kind: "json_pointer", paths: ["/messages/*/content/text"], action: "redact" },
    { id: "output-content", kind: "json_pointer", paths: ["/output/text"], action: "redact" },
    { id: "password-field", kind: "regex", pattern: "(?i)password", action: "redact" },
    { id: "api-key-field", kind: "regex", pattern: "(?i)api[_-]?key", action: "redact" },
    { id: "secret-field", kind: "regex", pattern: "(?i)secret", action: "redact" },
    { id: "token-field", kind: "regex", pattern: "(?i)token", action: "redact" },
  ],
  action_policy: {
    hash: { algorithm: "hmac-sha256", salt_ref: "hosted_default_salt" },
    redact: { placeholder: "<redacted>" },
    drop: { placeholder: null },
  },
};

const HOSTED_SALT = new Uint8Array([
  104, 111, 115, 116, 101, 100, 45, 100, 101, 102, 97, 117, 108, 116, 45, 115,
  97, 108, 116,
]); // "hosted-default-salt" as ASCII bytes.
const saltProvider = (saltRef: string): Uint8Array => {
  if (saltRef === "hosted_default_salt") return HOSTED_SALT;
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

function hostedEngine(): RedactionEngine {
  const policy = loadRedactionPolicy(HOSTED_DEFAULT_POLICY);
  return new RedactionEngine({ policy, saltProvider });
}

describe("VAL-REDACT-001 TS parity: json_pointer single-segment * wildcard", () => {
  it("redacts the SSN at /messages/0/content/text (the contract trigger)", () => {
    const engine = hostedEngine();
    const payload = {
      messages: [{ content: { text: "my SSN is 123-45-6789" } }],
    };
    const body = Buffer.from(redactCapturePayload(engine, payload));
    const text = body.toString("utf8");
    // RED at base: TS exact-membership never matched the indexed pointer, so
    // the SSN leaked verbatim into the wire body.
    expect(text).not.toContain("123-45-6789");
    expect(text).toContain("<redacted>");
  });

  it("the * wildcard matches ANY single array index, not just 0", () => {
    const engine = hostedEngine();
    // Inputs deliberately avoid the regex matchers (password/api_key/secret/
    // token) so the assertion isolates the json_pointer wildcard behavior: a
    // pointer match replaces the WHOLE leaf with the placeholder. Full-
    // structure toEqual is used (matching the v3m5_json_path_matcher style) so
    // ``noUncheckedIndexedAccess`` does not force non-null assertions.
    const redacted = engine.redact({
      messages: [
        { content: { text: "first ssn 111-11-1111" } },
        { content: { text: "second ssn 222-22-2222" } },
        { content: { text: "third ssn 333-33-3333" } },
      ],
    });
    expect(redacted).toEqual({
      messages: [
        { content: { text: "<redacted>" } },
        { content: { text: "<redacted>" } },
        { content: { text: "<redacted>" } },
      ],
    });
  });

  it("a *-free matcher path (/output/text) still matches by exact equality", () => {
    const engine = hostedEngine();
    const redacted = engine.redact({
      output: { text: "agent said 444-44-4444" },
    });
    expect(redacted).toEqual({ output: { text: "<redacted>" } });
  });

  it("does NOT over-match a deeper pointer (extra intervening segment)", () => {
    const engine = hostedEngine();
    // /messages/0/extra/content/text has an extra segment vs the matcher
    // /messages/*/content/text. A single-segment wildcard must NOT span it.
    const redacted = engine.redact({
      messages: [{ extra: { content: { text: "plain value here" } } }],
    });
    expect(redacted).toEqual({
      messages: [{ extra: { content: { text: "plain value here" } } }],
    });
  });

  it("does NOT over-match a shallower pointer (missing trailing segment)", () => {
    const engine = hostedEngine();
    // /messages/0/content has fewer segments than /messages/*/content/text.
    const redacted = engine.redact({
      messages: [{ content: "plain string not under text" }],
    });
    expect(redacted).toEqual({
      messages: [{ content: "plain string not under text" }],
    });
  });

  it("a literal '*' object key in the payload IS matched by the wildcard (safe: redacts more)", () => {
    const engine = hostedEngine();
    // The concrete segment is the literal object key "*". The wildcard token
    // matches any single key, including a literal "*", so this redacts (the
    // conservative, more-redaction direction).
    const redacted = engine.redact({
      messages: { "*": { content: { text: "literal star key 555-55-5555" } } },
    });
    expect(redacted).toEqual({
      messages: { "*": { content: { text: "<redacted>" } } },
    });
  });
});
