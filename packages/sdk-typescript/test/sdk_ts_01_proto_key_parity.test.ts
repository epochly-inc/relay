/**
 * sdk-ts-01: own ``__proto__`` key Py<->TS byte-parity regression.
 *
 * A model/tool can emit tool-call arguments JSON with an own ``__proto__``
 * key, e.g. ``{"__proto__": {"api_key": "sk-secret"}, "a": 1}``. When that
 * string is ``JSON.parse``d, the result has an OWN enumerable ``__proto__``
 * property (JSON.parse does not invoke the prototype setter). Python's
 * ``json.loads`` yields a plain dict whose ``"__proto__"`` is an ordinary
 * string key.
 *
 * The TS RedactionEngine and the adapter ``scrubSecretShape`` rebuild
 * objects key-by-key. If they rebuild into a plain ``{}`` with
 * ``out[key] = ...`` then the ``"__proto__"`` assignment sets the object's
 * prototype instead of creating an own enumerable property, so the field
 * VANISHES from the redacted output. Python keeps it. The canonical wire
 * bodies then diverge -- a P2 Py<->TS byte-parity bug.
 *
 * These tests assert the TS side preserves an own ``"__proto__"`` key
 * (with its redacted value) so the canonical bytes match Python's.
 *
 * Python reference (verified): a dict round-trips ``"__proto__"`` as a
 * normal key. For the secret-shape scrub path the inner ``api_key`` value
 * is masked, giving canonical bytes
 * ``{"__proto__":{"api_key":"[REDACTED]"},"a":1}``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import {
  _canonicalJsonStringify,
  loadRedactionPolicy,
  RedactionEngine,
  DEFAULT_APPLIES_TO_FIELDS,
  type SaltProvider,
} from "../src/redaction.js";
import { scrubSecretShape } from "../src/adapters/openai.js";

// Minimal real policy (mirrors the structure used by w4_3_redaction_engine).
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
  ],
  action_policy: {
    hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3" },
    redact: { placeholder: "<redacted>" },
    drop: { placeholder: null },
  },
  applies_to_fields: [...DEFAULT_APPLIES_TO_FIELDS],
};

const TENANT_SALT = new TextEncoder().encode("test-tenant-salt-v3-do-not-use-in-prod");

const saltProvider: SaltProvider = (saltRef) => {
  if (saltRef === "tenant_salt_v3") return TENANT_SALT;
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

/**
 * Build an object with an OWN enumerable ``__proto__`` key, exactly as
 * ``JSON.parse`` produces from a wire string containing that key. Using a
 * plain object literal would set the prototype instead, so go through
 * JSON.parse to get the same shape the adapters see on the live path.
 */
function objWithOwnProtoKey(): Record<string, unknown> {
  return JSON.parse('{"__proto__": {"api_key": "sk-secret"}, "a": 1}') as Record<
    string,
    unknown
  >;
}

describe("sdk-ts-01: own __proto__ key survives redaction (Py<->TS parity)", () => {
  it("the source object actually carries an OWN __proto__ key (precondition)", () => {
    const src = objWithOwnProtoKey();
    expect(Object.prototype.hasOwnProperty.call(src, "__proto__")).toBe(true);
    expect(Object.keys(src).sort()).toEqual(["__proto__", "a"]);
  });

  it("RedactionEngine.redact preserves an own __proto__ key", () => {
    const policy = loadRedactionPolicy(BASE_POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Secret value is matcher-length (pattern requires 20+ chars after
    // "sk-") so the engine's regex matcher fires inside the nested object.
    const src = JSON.parse(
      '{"__proto__": {"api_key": "sk-ABCDEFGHIJKLMNOPQRSTUV"}, "a": 1}',
    ) as Record<string, unknown>;
    const out = engine.redact(src);
    // Python keeps "__proto__" as a normal key; TS must too.
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(true);
    expect(Object.keys(out).sort()).toEqual(["__proto__", "a"]);
    // The nested secret under "__proto__" is still walked and redacted.
    const nested = (out as Record<string, unknown>)["__proto__"] as Record<
      string,
      unknown
    >;
    expect(Object.prototype.hasOwnProperty.call(nested, "api_key")).toBe(true);
    expect(nested["api_key"]).toBe("<redacted>");
    // Canonical bytes (JCS) match the Python-equivalent output.
    expect(_canonicalJsonStringify(out)).toBe(
      '{"__proto__":{"api_key":"<redacted>"},"a":1}',
    );
  });

  it("scrubSecretShape (adapter tool-arg path) preserves an own __proto__ key", () => {
    const out = scrubSecretShape(objWithOwnProtoKey()) as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(true);
    expect(Object.keys(out).sort()).toEqual(["__proto__", "a"]);
    const nested = out["__proto__"] as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(nested, "api_key")).toBe(true);
    // "api_key" is a secret KEY -> masked with the adapter "[REDACTED]" token.
    expect(nested["api_key"]).toBe("[REDACTED]");
    // Canonical bytes match the Python _scrub-equivalent output exactly.
    expect(_canonicalJsonStringify(out)).toBe(
      '{"__proto__":{"api_key":"[REDACTED]"},"a":1}',
    );
  });

  it("a __proto__ key whose value is a secret STRING is preserved and redacted", () => {
    // Distinct shape: own __proto__ key mapped directly to a secret value.
    const src = JSON.parse('{"__proto__": "sk-leak", "b": 2}') as Record<
      string,
      unknown
    >;
    const out = scrubSecretShape(src) as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(true);
    expect(out["__proto__"]).toBe("[REDACTED]");
    expect(_canonicalJsonStringify(out)).toBe(
      '{"__proto__":"[REDACTED]","b":2}',
    );
  });
});
