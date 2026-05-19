/**
 * VAL-V3M5-018: KNOWN_MATCHER_KINDS includes 'json_path' (TypeScript parity).
 *
 * Mirrors packages/sdk-python/tests/test_v3m5_json_path_matcher.py. The SDK
 * accepts a third matcher kind, ``json_path``, alongside the existing
 * ``regex`` and ``json_pointer`` kinds. The matcher's ``paths`` list contains
 * JSONPath selectors (RFC 9535 subset) of the form ``$.foo.bar`` and
 * ``$.foo[N]``. The cross-runtime parity case asserts the same selector
 * applied to the same payload produces the same redacted dict on Python and
 * TypeScript -- byte-for-byte equality is not promised because the engines
 * differ in container types, but the JSON-shape equality (deep-equal) IS
 * promised and is the assertion the VAL is built on.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import {
  loadRedactionPolicy,
  RedactionEngine,
  type SaltProvider,
} from "../src/redaction.js";
import { RelayRedactionPolicyError } from "../src/errors.js";

const TENANT_SALT = new TextEncoder().encode(
  "test-tenant-salt-v3m5-f08-do-not-use-in-prod",
);

const saltProvider: SaltProvider = (saltRef: string): Uint8Array => {
  if (saltRef === "tenant_salt_v3m5_f08") return TENANT_SALT;
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

function buildPolicy(paths: string[]) {
  return loadRedactionPolicy({
    schema_version: "relay.redaction.v1",
    policy_version: "v3m5-f08.001",
    raw_capture: false,
    matchers: [
      {
        id: "json_path_redactor",
        kind: "json_path",
        paths,
        action: "redact",
      },
    ],
    action_policy: {
      hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3m5_f08" },
      redact: { placeholder: "<redacted-v3m5-f08>" },
      drop: { placeholder: null },
    },
  });
}

describe("VAL-V3M5-018: KNOWN_MATCHER_KINDS includes json_path", () => {
  it("accepts 'json_path' as a matcher kind", () => {
    // The constant is not exported; the public contract is that a policy
    // declaring kind='json_path' loads without throwing. (Mirrors how the
    // Python side validates via the constant; the TS side validates via the
    // policy load behavior, which is the equivalent observable surface.)
    const policy = buildPolicy(["$.foo.bar"]);
    expect(policy.matchers.length).toBe(1);
    const matcher = policy.matchers[0];
    if (matcher === undefined) throw new Error("matcher missing");
    expect(matcher.kind).toBe("json_path");
  });

  it("$.foo.bar selector matches nested dict path", () => {
    const policy = buildPolicy(["$.foo.bar"]);
    const engine = new RedactionEngine({ policy, saltProvider });
    const out = engine.redact({ foo: { bar: "SECRET", baz: "keep" } });
    expect(out).toEqual({ foo: { bar: "<redacted-v3m5-f08>", baz: "keep" } });
  });

  it("$.foo[0] selector matches array index", () => {
    const policy = buildPolicy(["$.foo[0]"]);
    const engine = new RedactionEngine({ policy, saltProvider });
    const out = engine.redact({ foo: ["SECRET", "keep1", "keep2"] });
    expect(out).toEqual({ foo: ["<redacted-v3m5-f08>", "keep1", "keep2"] });
  });

  it("selector whose path is absent passes through unchanged", () => {
    const policy = buildPolicy(["$.missing.path"]);
    const engine = new RedactionEngine({ policy, saltProvider });
    const out = engine.redact({ foo: { bar: "keep" } });
    expect(out).toEqual({ foo: { bar: "keep" } });
  });

  it("json_path matcher with empty paths is rejected at load", () => {
    expect(() =>
      loadRedactionPolicy({
        schema_version: "relay.redaction.v1",
        policy_version: "v3m5-f08.002",
        raw_capture: false,
        matchers: [
          {
            id: "bad",
            kind: "json_path",
            paths: [],
            action: "redact",
          },
        ],
        action_policy: {
          hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3m5_f08" },
          redact: { placeholder: "<redacted>" },
          drop: { placeholder: null },
        },
      }),
    ).toThrow(RelayRedactionPolicyError);
  });

  it("cross-runtime parity corpus: same selector + payload -> same redacted dict", () => {
    // Identical fixture to the Python test
    // ``test_json_path_cross_runtime_parity_corpus``. The two engines must
    // agree on this exact output (deep-equal).
    const policy = buildPolicy(["$.user.email", "$.tokens[0]"]);
    const engine = new RedactionEngine({ policy, saltProvider });
    const payload = {
      user: { email: "alice@example.com", name: "Alice" },
      tokens: ["sk-AAA", "sk-BBB"],
      other: "untouched",
    };
    const expected = {
      user: { email: "<redacted-v3m5-f08>", name: "Alice" },
      tokens: ["<redacted-v3m5-f08>", "sk-BBB"],
      other: "untouched",
    };
    expect(engine.redact(payload)).toEqual(expected);
  });
});
