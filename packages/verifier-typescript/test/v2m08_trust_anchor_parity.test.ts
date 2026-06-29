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
  SIGNER_ROLE_CONTROL_PLANE,
  SIGNER_ROLE_LOCAL_DEV,
  SIGNER_ROLE_UNKNOWN,
  TRUST_ANCHOR_CLASS_BYO,
  TRUST_ANCHOR_CLASS_RELAY_INC,
  TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL,
  TRUST_ANCHOR_LOCAL_DEV,
  classifySignerRole,
  classifyTrustAnchor,
  jcsCanonicalize,
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

// ----------------------------------------------------------------------------
// Bug verifier-ts-2: classifyTrustAnchor MUST match Python urlparse semantics.
//
// Two divergences from Python's urlparse that the WHATWG `new URL()` path
// introduced:
//   (1) WHATWG URL NORMALIZES a backslash to a slash, so a backslash-crafted
//       trust_anchor like
//       "https://relay.epochly.com\\evil/.well-known/jwks.json" is
//       over-classified relay_inc in TS but byo in Python (urlparse keeps the
//       backslash inside the authority, yielding host != relay.epochly.com).
//   (2) the path must be matched by EXACT equality against
//       "/.well-known/jwks.json", never endsWith -- an attacker subpath like
//       "https://relay.epochly.com/attacker/path/.well-known/jwks.json" is byo.
// Python urlparse is the parity reference for both.
// ----------------------------------------------------------------------------

describe("verifier-ts-2 classifyTrustAnchor Python-urlparse parity", () => {
  test("backslash-crafted authority does NOT over-classify relay_inc", () => {
    // Python urlparse keeps the backslash in the authority, so the host is
    // NOT exactly relay.epochly.com -> byo. WHATWG URL would normalize the
    // backslash to a slash and split host=relay.epochly.com -> relay_inc.
    const backslashUrl = "https://relay.epochly.com\\evil/.well-known/jwks.json";
    expect(classifyTrustAnchor(backslashUrl)).toBe(TRUST_ANCHOR_CLASS_BYO);
    expect(classifyTrustAnchor(backslashUrl)).not.toBe(
      TRUST_ANCHOR_CLASS_RELAY_INC,
    );
  });

  test.each([
    "https://relay.epochly.com/attacker/path/.well-known/jwks.json",
    "https://relay.epochly.com/evil/.well-known/jwks.json",
  ])("attacker subpath %j classifies as byo (exact-path, not endsWith)", (url) => {
    expect(classifyTrustAnchor(url)).toBe(TRUST_ANCHOR_CLASS_BYO);
    expect(classifyTrustAnchor(url)).not.toBe(TRUST_ANCHOR_CLASS_RELAY_INC);
  });

  test("canonical Relay-Inc URL still classifies relay_inc (regression guard)", () => {
    expect(
      classifyTrustAnchor("https://relay.epochly.com/.well-known/jwks.json"),
    ).toBe(TRUST_ANCHOR_CLASS_RELAY_INC);
  });

  test("non-URL string classifies byo (urlparse empty hostname)", () => {
    // Python urlparse('fork.example').hostname == '' -> byo. The TS port
    // must agree (empty host -> not relay.epochly.com -> byo).
    expect(classifyTrustAnchor("fork.example")).toBe(TRUST_ANCHOR_CLASS_BYO);
  });

  // Bug verifier-ts-2b (roborev 7feb671 MEDIUM): a NON-NUMERIC port must not
  // break host/path extraction. Python urlparse keeps host and path for a
  // host:abc authority (the `.port` validator is never accessed by
  // classify_trust_anchor), so it classifies relay_inc. The TS `_RAW_URL_RE`
  // previously required `[0-9]*` for the port, so `:abc` failed the whole match
  // -> empty host -> byo: a verifier-output / signer_role parity break.
  test("non-numeric port keeps host+path (relay_inc, urlparse parity)", () => {
    expect(
      classifyTrustAnchor("https://relay.epochly.com:abc/.well-known/jwks.json"),
    ).toBe(TRUST_ANCHOR_CLASS_RELAY_INC);
  });

  test("numeric port keeps host+path (relay_inc regression guard)", () => {
    expect(
      classifyTrustAnchor("https://relay.epochly.com:443/.well-known/jwks.json"),
    ).toBe(TRUST_ANCHOR_CLASS_RELAY_INC);
  });

  test("non-numeric port on a non-Relay host stays byo", () => {
    expect(
      classifyTrustAnchor("https://attacker.example:abc/.well-known/jwks.json"),
    ).toBe(TRUST_ANCHOR_CLASS_BYO);
  });
});

// ----------------------------------------------------------------------------
// Bug verifier-ts-1: the TS output envelope MUST emit `signer_role` on every
// return path (Python always does). signer_role derives ONLY from
// trust_anchor_class: relay_inc->control_plane, untrusted_local->local_dev,
// byo/missing->unknown. Its absence breaks Py<->TS JCS byte-parity because
// signer_role sorts between signer_key_revoked_at and structure_ok.
// ----------------------------------------------------------------------------

describe("verifier-ts-1 signer_role envelope field + classifier", () => {
  test("classifySignerRole maps trust_anchor_class deterministically", () => {
    expect(classifySignerRole(TRUST_ANCHOR_CLASS_RELAY_INC)).toBe(
      SIGNER_ROLE_CONTROL_PLANE,
    );
    expect(classifySignerRole(TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL)).toBe(
      SIGNER_ROLE_LOCAL_DEV,
    );
    expect(classifySignerRole(TRUST_ANCHOR_CLASS_BYO)).toBe(SIGNER_ROLE_UNKNOWN);
    expect(classifySignerRole("")).toBe(SIGNER_ROLE_UNKNOWN);
  });

  test("relay_inc bundle reports signer_role=control_plane", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.signer_role).toBe(SIGNER_ROLE_CONTROL_PLANE);
  });

  test("local_dev bundle reports signer_role=local_dev", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "local_dev",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.signer_role).toBe(SIGNER_ROLE_LOCAL_DEV);
  });

  test("byo bundle reports signer_role=unknown", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      trust_anchor: "https://fork.example/jwks",
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.signer_role).toBe(SIGNER_ROLE_UNKNOWN);
  });

  test("missing trust_anchor reports signer_role=unknown on the early-return path", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      claims: [{ id: "c1", payload: { v: 1 } }],
      decided_at: "2026-05-15T12:00:00Z",
    };
    const out = validateBundle({ bundle, jwks: { keys: [] } });
    expect(out.signer_role).toBe(SIGNER_ROLE_UNKNOWN);
  });

  test("signer_role populated even on the over-cap signature early-return path", () => {
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
    // Over-cap early return ran (signatures_checked empty) yet signer_role is
    // still set (matches Python placement BEFORE the over-cap early return).
    expect(out.signatures_checked).toEqual([]);
    expect(out.signer_role).toBe(SIGNER_ROLE_CONTROL_PLANE);
  });

  // Full-envelope JCS byte-parity against a Python-produced golden. Locks
  // field-level parity for the signer_role envelope field (it sorts between
  // signer_key_revoked_at and structure_ok). The golden was produced by the
  // Python orchestrator (relay_verifier.validate_bundle + jcs_canonicalize)
  // for the identical over-cap bundle below.
  //
  // The bundle carries 5 signatures so BOTH engines take the over-cap
  // early-return path (signatures_present > MAX_BUNDLE_SIGNATURES): this
  // isolates the signer_role field by avoiding per-signature error-message
  // text (which is built by each language's base64 library and is not part
  // of the trust-anchor cluster), and additionally proves signer_role is
  // populated on the early-return path. The single error is built from a
  // shared template so its bytes are identical across runtimes.
  test("validateBundle JCS bytes are byte-identical to the Python golden", () => {
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
    const out = validateBundle({
      bundle,
      jwks: { keys: [] },
      trust_anchor_source: "",
    });
    const tsBytes = Buffer.from(jcsCanonicalize(out)).toString("utf-8");
    const pythonGolden =
      '{"bundle_digest_sha256":' +
      '"9a1ccab9acbf704e3640e052ef758748ad141891fa7ac02add2572b1e0661698",' +
      '"bundle_path":"","claims_count":1,"digest_ok":false,"errors":' +
      '[{"code":"RELAY-EVID-SIGCOUNT-EXCEEDED","message":"bundle carries 5 ' +
      'signatures; the maximum supported is 4 per spec section L.5 line ' +
      '4481 cross-signing cap","reason":"signature_count_exceeded"}],' +
      '"log_inclusion":"absent","merkle_check":"absent","overall":"fail",' +
      '"schema_version":"relay.verifier.output.v1","signatures_checked":[],' +
      '"signatures_ok":false,"signatures_present":5,"signer_key_revoked":' +
      'false,"signer_key_revoked_at":null,"signer_role":"control_plane",' +
      '"structure_ok":false,"subject_resolution":"unknown","trust_anchor":' +
      '"https://relay.epochly.com/.well-known/jwks.json","trust_anchor_class":' +
      '"relay_inc","trust_anchor_source":"","tsa_check":"missing",' +
      '"warnings":[]}';
    expect(tsBytes).toBe(pythonGolden);
  });
});
