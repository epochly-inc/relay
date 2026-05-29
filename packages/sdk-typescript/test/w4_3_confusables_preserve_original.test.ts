/**
 * W4.3 SDK-side redaction -- confusables fold is a DETECTION aid only
 * (VAL-REDACT-007). The emitted output for any UNMATCHED region MUST be the
 * ORIGINAL code points, never the NFKC + confusables-folded ASCII look-alikes.
 *
 * Pre-fix ``applyMatchersToClampedString`` in ``src/redaction.ts`` emitted the
 * folded string itself -- even when NO matcher fired -- silently
 * transliterating legitimate non-secret Cyrillic/Greek content (e.g. a Russian
 * sentence) into ASCII homoglyphs on the wire via ``CONFUSABLES_MAP``. The fix
 * matches on the folded surface (so homograph-disguised secrets are still
 * detected) but reconstructs output from the ORIGINAL string via
 * ``foldWithOrigin``.
 *
 * Mirrors the Python tests in
 * ``packages/sdk-python/tests/test_redaction.py`` (VAL-REDACT-007) and keeps
 * Python<->TypeScript byte-equality on these inputs.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source": Unicode test inputs are built
 * from explicit code points.
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_APPLIES_TO_FIELDS,
  loadRedactionPolicy,
  RedactionEngine,
  type SaltProvider,
} from "../src/redaction.js";

const TENANT_SALT = new TextEncoder().encode("test-tenant-salt-v3-do-not-use-in-prod");
const saltProvider: SaltProvider = (saltRef) => {
  if (saltRef === "tenant_salt_v3") return TENANT_SALT;
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

// Build a string from explicit code points (keeps source ASCII-clean).
const u = (...cps: number[]): string => String.fromCodePoint(...cps);

const SECRET_API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUV";

const BASE_POLICY = {
  schema_version: "relay.redaction.v1",
  policy_version: "2026-05-29.redact007",
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

// "Privet, mir" in Cyrillic: a non-secret sentence whose 'p', 'e', 'o'
// letters are confusable with ASCII (fold to ASCII under CONFUSABLES_MAP).
// U+041F PE, U+0440 ER->p, U+0438 I, U+0432 VE, U+0435 IE->e, U+0442 TE,
// then ", ", then U+043C EM, U+0438 I, U+0440 ER->p.
const CYRILLIC_SENTENCE =
  u(0x041f, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442) + ", " + u(0x043c, 0x0438, 0x0440);

const mkEngine = (body: object = BASE_POLICY): RedactionEngine =>
  new RedactionEngine({ policy: loadRedactionPolicy(body), saltProvider });

const redactInput = (engine: RedactionEngine, input: string): string => {
  const out = engine.redact({ model_call: { input } }) as {
    model_call: { input: string };
  };
  return out.model_call.input;
};

describe("VAL-REDACT-007: confusables fold preserves unmatched original code points", () => {
  it("round-trips a non-secret Cyrillic leaf byte-for-byte (no transliteration)", () => {
    const out = redactInput(mkEngine(), CYRILLIC_SENTENCE);
    expect(out).toBe(CYRILLIC_SENTENCE);
    // The folded ASCII look-alikes did NOT replace the Cyrillic code points.
    expect(out).toContain(u(0x0440)); // Cyrillic ER preserved, not 'p'.
    expect(out).toContain(u(0x0435)); // Cyrillic IE preserved, not 'e'.
    expect(out).not.toContain("p");
    expect(out).not.toContain("e");
  });

  it("redacts an embedded ASCII secret while preserving surrounding Cyrillic context", () => {
    const prefix = u(0x041f, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442) + ": ";
    const suffix = " " + u(0x043a, 0x043e, 0x043d, 0x0435, 0x0446); // "konets"
    const leaf = prefix + SECRET_API_KEY + suffix;
    const out = redactInput(mkEngine(), leaf);
    expect(out).toBe(prefix + "<redacted>" + suffix);
    expect(out).not.toContain(SECRET_API_KEY);
    expect(out).toContain(u(0x0440)); // Cyrillic ER preserved.
    expect(out).toContain(u(0x0435)); // Cyrillic IE preserved.
  });

  it("still detects and redacts a homograph-disguised secret (detection guard)", () => {
    // "sk-" + Cyrillic Capital A (U+0410) + 20 ASCII chars; folds to
    // "sk-ABCDEFGHIJKLMNOPQRSTU" which the api_key matcher catches.
    const homoglyph = "sk-" + u(0x0410) + "BCDEFGHIJKLMNOPQRSTU";
    const out = redactInput(mkEngine(), homoglyph);
    expect(out).toBe("<redacted>");
    expect(out).not.toContain(u(0x0410));
    expect(out).not.toContain("sk-");
  });

  it("does not leak a fragment when a combining mark precedes a matched secret", () => {
    // "u" + COMBINING DIAERESIS (U+0308) NFKC-collapses to a single U+00FC,
    // placed before an ASCII secret. The combining-mark prefix is non-secret
    // and must round-trip; the secret must be fully redacted.
    const leaf = "u" + u(0x0308) + " " + SECRET_API_KEY;
    const out = redactInput(mkEngine(), leaf);
    expect(out).toBe("u" + u(0x0308) + " " + "<redacted>");
    expect(out).not.toContain(SECRET_API_KEY);
    expect(out).not.toContain("TUV");
  });
});
