/**
 * VAL-REDACT-003: TS regex matcher must accept the supported Python inline
 * flag subset and reject Python named groups consistently with the Python SDK.
 *
 * Bug: ``loadRedactionPolicy`` compiled every regex matcher with
 * ``new RegExp(rawPattern, "g")``. JavaScript ``RegExp`` does NOT accept
 * Python-style leading inline scoped flags ``(?i)``/``(?s)``/``(?m)`` (it
 * raises 'Invalid regular expression: ... Invalid group') and never sets the
 * case-insensitive flag. Python compiles the same pattern with
 * ``re.compile(raw_pattern)`` -- so a policy whose matcher uses ``(?i)password``
 * (the DEFAULT policy does) THREW at load in TS while loading and matching in
 * Python. The two SDKs diverged and TS failed to load valid policies.
 *
 * Fix: translate a leading inline-flag prefix ``(?i)``/``(?s)``/``(?m)`` (and
 * combined forms like ``(?ims)``) to the JS flags string before compiling
 * (always include ``g``), strip the prefix from the pattern body, and reject
 * Python named groups ``(?P<...>)`` CONSISTENTLY on both SDKs. The pinned
 * dialect mirrors Python's "global flags at the start of the expression" rule.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { loadRedactionPolicy, RedactionEngine } from "../src/redaction.js";
import { RelayRedactionPolicyError, RelayPolicyError } from "../src/index.js";

// The hosted default policy matcher set (single source of truth lives in
// packages/schemas/raw/redaction-policy.default.v1.yaml and the Python
// HOSTED_DEFAULT_POLICY constant). Inlined here because the TS SDK does not
// export a default-policy constant; the regex matchers all use leading
// Python inline flags, which is exactly the construct under test.
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

const TENANT_SALT = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const saltProvider = (saltRef: string): Uint8Array => {
  if (saltRef === "tenant_salt_v3" || saltRef === "hosted_default_salt") {
    return TENANT_SALT;
  }
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

function policyWithRegex(pattern: string): Record<string, unknown> {
  return {
    schema_version: "relay.redaction.v1",
    policy_version: "2026-05-29.flags",
    raw_capture: false,
    dpa_ref: null,
    approver_user_id: null,
    matchers: [{ id: "m", kind: "regex", pattern, action: "redact" }],
    action_policy: {
      hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3" },
      redact: { placeholder: "<redacted>" },
      drop: { placeholder: null },
    },
  };
}

// -----------------------------------------------------------------------------
// Leading inline flags load AND match like Python.
// -----------------------------------------------------------------------------

describe("VAL-REDACT-003: leading Python inline flags load in TS", () => {
  it("(?i)password loads without throwing", () => {
    expect(() => loadRedactionPolicy(policyWithRegex("(?i)password"))).not.toThrow();
  });

  it("(?i)password matches case-insensitively like Python re.IGNORECASE", () => {
    const policy = loadRedactionPolicy(policyWithRegex("(?i)password"));
    const engine = new RedactionEngine({ policy, saltProvider });
    const out = engine.redact({ model_call: { input: "my PASSWORD is here" } }) as {
      model_call: { input: string };
    };
    // The uppercase PASSWORD must be redacted (case-insensitive).
    expect(out.model_call.input).not.toContain("PASSWORD");
    expect(out.model_call.input).toContain("<redacted>");
  });

  it("(?s)/(?m) and combined (?ims) load without throwing", () => {
    expect(() => loadRedactionPolicy(policyWithRegex("(?s)foo.bar"))).not.toThrow();
    expect(() => loadRedactionPolicy(policyWithRegex("(?m)^line"))).not.toThrow();
    expect(() => loadRedactionPolicy(policyWithRegex("(?ims)alpha"))).not.toThrow();
  });

  it("(?s) honours DOTALL: dot matches a newline", () => {
    const policy = loadRedactionPolicy(policyWithRegex("(?s)foo.bar"));
    const engine = new RedactionEngine({ policy, saltProvider });
    const out = engine.redact({ model_call: { input: "foo\nbar tail" } }) as {
      model_call: { input: string };
    };
    expect(out.model_call.input).toContain("<redacted>");
    expect(out.model_call.input).not.toContain("foo\nbar");
  });

  it("the HOSTED_DEFAULT_POLICY (uses (?i)password etc.) loads and redacts", () => {
    const policy = loadRedactionPolicy(HOSTED_DEFAULT_POLICY as Record<string, unknown>);
    const engine = new RedactionEngine({ policy, saltProvider });
    const out = engine.redact({ model_call: { note: "the PASSWORD and API_KEY" } }) as {
      model_call: { note: string };
    };
    expect(out.model_call.note).not.toContain("PASSWORD");
    expect(out.model_call.note).not.toContain("API_KEY");
  });
});

// -----------------------------------------------------------------------------
// Named groups (?P<...>) rejected consistently with the Python SDK.
// -----------------------------------------------------------------------------

describe("VAL-REDACT-003: Python named groups (?P<...>) rejected consistently", () => {
  it("(?P<x>...) raises RelayRedactionPolicyError with reason named_group_unsupported", () => {
    let caught: unknown = null;
    try {
      loadRedactionPolicy(policyWithRegex("(?P<word>password)"));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayRedactionPolicyError);
    expect(caught).toBeInstanceOf(RelayPolicyError);
    const err = caught as RelayRedactionPolicyError;
    expect(err.details["reason"]).toBe("named_group_unsupported");
  });

  it("(?P=name) backreference is also rejected as named-group syntax", () => {
    expect(() => loadRedactionPolicy(policyWithRegex("(?P<a>x)(?P=a)"))).toThrowError(
      RelayRedactionPolicyError,
    );
  });
});

// -----------------------------------------------------------------------------
// Pinned dialect: mid-pattern inline flags rejected (mirrors Python's
// "global flags must be at the start of the expression" rule).
// -----------------------------------------------------------------------------

describe("VAL-REDACT-003: pinned dialect rejects mid-pattern global flags", () => {
  it("mid-pattern (?i) fails closed like Python", () => {
    let caught: unknown = null;
    try {
      loadRedactionPolicy(policyWithRegex("foo(?i)bar"));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayRedactionPolicyError);
    const err = caught as RelayRedactionPolicyError;
    expect(["bad_regex", "inline_flags_not_at_start"]).toContain(err.details["reason"]);
  });

  it("an ordinary regex with no inline flags still loads", () => {
    expect(() => loadRedactionPolicy(policyWithRegex("(sk-|key_)[A-Za-z0-9]{20,}"))).not.toThrow();
  });
});

// -----------------------------------------------------------------------------
// codex P2 follow-up: Python-only inline flags (a/u/x/L) are rejected on TS,
// mirroring the Python SDK. Python's ``re`` accepts the scoped ``(?a:...)`` /
// ``(?u:...)`` / ``(?x:...)`` groups and the global ``(?a)`` / ``(?u)`` /
// ``(?x)`` forms, but JavaScript ``RegExp`` cannot compile any of them. The
// Python SDK now rejects them too; this test pins that TS already rejects them
// consistently so the two SDKs agree on accept/reject for the same policy.
// -----------------------------------------------------------------------------

describe("codex P2: Python-only inline flags (a/u/x/L) rejected on TS too", () => {
  const PYTHON_ONLY_INLINE_FLAG_PATTERNS = [
    "(?a:password)",
    "(?u:password)",
    "(?x:password)",
    "(?a)password",
    "(?u)password",
    "(?x)password",
    "(?L:password)",
    "(?L)password",
  ];

  for (const pattern of PYTHON_ONLY_INLINE_FLAG_PATTERNS) {
    it(`${pattern} is rejected with a RelayRedactionPolicyError`, () => {
      let caught: unknown = null;
      try {
        loadRedactionPolicy(policyWithRegex(pattern));
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(RelayRedactionPolicyError);
      expect(caught).toBeInstanceOf(RelayPolicyError);
      const err = caught as RelayRedactionPolicyError;
      // The rejection lands on an existing dialect-rejection reason; the
      // scoped forms fail JS RegExp compilation (bad_regex) while the global
      // forms are caught as unsupported leading inline flags. Either way the
      // policy is rejected, agreeing with the Python SDK on accept/reject.
      expect(["bad_regex", "unsupported_inline_flag"]).toContain(
        err.details["reason"],
      );
    });
  }

  it("the supported (?i)foo still loads (no over-rejection)", () => {
    expect(() => loadRedactionPolicy(policyWithRegex("(?i)foo"))).not.toThrow();
  });
});
