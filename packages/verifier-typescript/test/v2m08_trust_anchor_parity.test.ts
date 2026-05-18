// Cross-language parity tests for the w8-trust-anchor enforcement
// fields ported from Python `relay_verifier.bundle_validator`:
//
//   * VAL-V2M08-041: MAX_BUNDLE_SIGNATURES = 4 cap + RELAY-EVID-SIGCOUNT-EXCEEDED
//   * VAL-V2M08-043: RELAY-EVID-MISSING-TRUST-ANCHOR fail-closed rejection
//   * VAL-V2M08-044: trust_anchor_class enum (relay_inc | untrusted_local | byo)
//
// These are unit-tier tests scoped to the TypeScript verifier; the
// cross-language conformance corpus extension is a follow-up. The 2026-05-17
// whole-codebase audit surfaced the TS verifier was silently skipping all
// three behaviors -- this suite enforces parity inside the TS runtime.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  MAX_BUNDLE_SIGNATURES,
  RELAY_EVID_MISSING_TRUST_ANCHOR,
  RELAY_EVID_SIGCOUNT_EXCEEDED,
  TRUST_ANCHOR_CLASS_BYO,
  TRUST_ANCHOR_CLASS_RELAY_INC,
  TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL,
  TRUST_ANCHOR_LOCAL_DEV,
  classifyTrustAnchor,
  validateBundle,
} from "../src/index.js";

// ----------------------------------------------------------------------------
// VAL-V2M08-041: 4-signature cap (parity with Python MAX_BUNDLE_SIGNATURES)
// ----------------------------------------------------------------------------

describe("VAL-V2M08-041 MAX_BUNDLE_SIGNATURES cap", () => {
  test("constant equals 4 (spec L.5 line 4481)", () => {
    expect(MAX_BUNDLE_SIGNATURES).toBe(4);
  });

  test("bundle with 5 signatures is rejected fail-closed with RELAY-EVID-SIGCOUNT-EXCEEDED", () => {
    const dummySig = {
      kid: "k1",
      alg: "EdDSA",
      protected_b64u: "x",
      signature_b64u: "y",
    };
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
      signatures: [dummySig, dummySig, dummySig, dummySig, dummySig],
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    // Wire count surfaced regardless.
    expect(out.signatures_present).toBe(5);
    // Per-signature verification did NOT run -- signatures_checked stays empty.
    expect(out.signatures_checked).toEqual([]);
    // Structured error present with the canonical wire code.
    const sigCountErr = out.errors.find(
      (e) => e["code"] === RELAY_EVID_SIGCOUNT_EXCEEDED,
    );
    expect(sigCountErr).toBeDefined();
    expect(sigCountErr?.["reason"]).toBe("signature_count_exceeded");
    expect(out.overall).toBe("fail");
  });

  test("bundle with exactly 4 signatures is NOT capped (boundary)", () => {
    const dummySig = {
      kid: "k1",
      alg: "EdDSA",
      protected_b64u: "x",
      signature_b64u: "y",
    };
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
      signatures: [dummySig, dummySig, dummySig, dummySig],
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.signatures_present).toBe(4);
    // The cap check did NOT fire. Per-signature verification ran (and
    // each sig fails crypto since the JWKS is empty), but the over-cap
    // wire code is absent.
    const sigCountErr = out.errors.find(
      (e) => e["code"] === RELAY_EVID_SIGCOUNT_EXCEEDED,
    );
    expect(sigCountErr).toBeUndefined();
  });

  test("bundle with no signatures field surfaces signatures_present=0", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.signatures_present).toBe(0);
  });
});

// ----------------------------------------------------------------------------
// VAL-V2M08-043: missing trust_anchor fail-closed rejection
// ----------------------------------------------------------------------------

describe("VAL-V2M08-043 RELAY-EVID-MISSING-TRUST-ANCHOR", () => {
  test("bundle with no trust_anchor field is rejected", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    const err = out.errors.find(
      (e) => e["code"] === RELAY_EVID_MISSING_TRUST_ANCHOR,
    );
    expect(err).toBeDefined();
    expect(err?.["reason"]).toBe("trust_anchor_missing");
    expect(out.overall).toBe("fail");
    // Echo defaults to empty string.
    expect(out.trust_anchor).toBe("");
    // Classification empty when missing.
    expect(out.trust_anchor_class).toBe("");
  });

  test("bundle with trust_anchor='' (empty string) is rejected", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    const err = out.errors.find(
      (e) => e["code"] === RELAY_EVID_MISSING_TRUST_ANCHOR,
    );
    expect(err).toBeDefined();
    expect(out.trust_anchor_class).toBe("");
  });

  test("bundle with trust_anchor=null (non-string) is rejected", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: null,
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    const err = out.errors.find(
      (e) => e["code"] === RELAY_EVID_MISSING_TRUST_ANCHOR,
    );
    expect(err).toBeDefined();
  });

  test("bundle WITH trust_anchor does NOT emit missing-trust-anchor error", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    const err = out.errors.find(
      (e) => e["code"] === RELAY_EVID_MISSING_TRUST_ANCHOR,
    );
    expect(err).toBeUndefined();
  });
});

// ----------------------------------------------------------------------------
// VAL-V2M08-044: trust_anchor_class classification
// ----------------------------------------------------------------------------

describe("VAL-V2M08-044 classifyTrustAnchor", () => {
  test.each([
    // [input, expected]
    ["https://relay.epochly.com/.well-known/jwks.json", TRUST_ANCHOR_CLASS_RELAY_INC],
    ["HTTPS://Relay.Epochly.Com/.well-known/jwks.json", TRUST_ANCHOR_CLASS_RELAY_INC],
    [TRUST_ANCHOR_LOCAL_DEV, TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL],
    ["https://relay.epochly.com/evil", TRUST_ANCHOR_CLASS_BYO],
    ["https://attacker.example/.well-known/jwks.json", TRUST_ANCHOR_CLASS_BYO],
    ["fork.example", TRUST_ANCHOR_CLASS_BYO],
    ["", ""],
  ] as Array<[string, string]>)(
    "classifyTrustAnchor(%j) === %j",
    (input, expected) => {
      expect(classifyTrustAnchor(input)).toBe(expected);
    },
  );

  test.each([[null], [undefined], [42], [{}], [["a"]]] as Array<[unknown]>)(
    "non-string input %j classifies as ''",
    (input) => {
      expect(classifyTrustAnchor(input)).toBe("");
    },
  );

  test("validateBundle surfaces trust_anchor_class for relay_inc URL", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.trust_anchor_class).toBe(TRUST_ANCHOR_CLASS_RELAY_INC);
  });

  test("validateBundle classifies local_dev as untrusted_local even under Relay-Inc default anchor", () => {
    // Load-bearing parity guarantee: OSS cannot auto-promote into
    // Relay-Inc trust just because the verifier is configured with the
    // Relay-Inc default JWKS URL.
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "local_dev",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.trust_anchor_class).toBe(TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL);
  });

  test("validateBundle classifies fork URL as byo", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://fork.example/jwks",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.trust_anchor_class).toBe(TRUST_ANCHOR_CLASS_BYO);
  });
});
