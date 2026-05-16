/**
 * W4.3 SDK-side redaction -- NFKC combining-mark splice parity (Bug 4 P1).
 *
 * The TS engine ``applyMatchersToString`` in ``src/redaction.ts`` (lines
 * 707-761) normalises the input with ``value.normalize("NFKC")``, runs
 * regex matchers on the normalised form, then splices match offsets
 * back into the ORIGINAL string. NFKC is NOT length-preserving for
 * combining marks: ``"u" + U+0308`` (length 2) composes to U+00FC
 * (length 1). Spliced offsets point to the wrong positions in the
 * original; a fragment of the matched plaintext leaks past the
 * placeholder.
 *
 * This test asserts the corrected behaviour: matching and splicing
 * MUST operate on the same form so the entire match span is
 * replaced.
 *
 * Mirrors the Python parity test
 * ``packages/sdk-python/tests/test_redaction_parity.py::
 * test_walk_combining_mark_redaction_no_offset_error``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source": Unicode test inputs
 * use ``\\uXXXX`` escapes.
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

// U+0308 = COMBINING DIAERESIS. U+00FC = LATIN SMALL LETTER U WITH DIAERESIS.
const COMBINING_DIAERESIS = "\u0308";
const U_WITH_DIAERESIS = "\u00fc";

describe("Bug 4 (P1): NFKC combining-mark splice does not leak trailing fragment", () => {
  it("matches the composed form and replaces the entire span (no trailing 'd' leak)", () => {
    // Pattern targets the COMPOSED form 'passw' + u-with-diaeresis + 'rd'.
    const pattern = "passw" + U_WITH_DIAERESIS + "rd";
    const policyBody = {
      schema_version: "relay.redaction.v1",
      policy_version: "2026-05-12.001",
      raw_capture: false,
      dpa_ref: null,
      approver_user_id: null,
      matchers: [
        {
          id: "passw",
          kind: "regex",
          pattern,
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
    const policy = loadRedactionPolicy(policyBody);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Input is the DECOMPOSED form: 'u' + COMBINING DIAERESIS.
    const decomposed = "my passw" + "u" + COMBINING_DIAERESIS + "rd is here";
    const out = engine.redact({ model_call: { input: decomposed } }) as {
      model_call: { input: string };
    };
    const result = out.model_call.input;
    // Composed form of the entire secret must NOT survive.
    expect(result).not.toContain("passw" + U_WITH_DIAERESIS + "rd");
    // Trailing fragment 'd' adjacent to the placeholder is the precise
    // pre-fix leak; this MUST not appear.
    expect(result).not.toContain("<redacted>d");
    // Exact expected output after the fix.
    expect(result).toBe("my <redacted> is here");
  });
});
