// W17.2 RFC 7515 Appendix A conformance corpus (TS verifier mirror).
//
// Cross-language parity for W17.2: this vitest suite loads the same
// corpus file as the Python test
// (tests/conformance/jws/rfc7515_appendix_a.json) and asserts the TS
// verifier (`@epochly/relay-verifier`) produces identical verdicts.
// The corpus is single-source-of-truth; any drift between Py and TS
// must surface here.
//
// Coverage:
//   - VAL-W17-006: pinned corpus + transcript SHA-256 in the
//     accompanying .upstream-pins.json
//   - VAL-W17-007a: test-only HS verifier helper (TS mirror) confirms
//     HS256+HS512 HMAC math against the same shared keys as Python.
//   - VAL-W17-007b: production verifier rejects HS*, none, ES512;
//     accepts kid-augmented RS256+ES256; rejects tampered asymmetric.
//   - VAL-W17-008: alg allow-list enforced; A.5 (alg=none) and
//     constructed forged-payload alg=none both rejected.
//   - VAL-W17-009: detached form verifies for RS256+ES256; tamper
//     detection on detached payload.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  RELAY_VERIFY_UNSUPPORTED_ALG,
  type SignatureCheck,
  verifyJwsCompact,
  verifyJwsDetached,
} from "../src/index.js";

import {
  UnsupportedHsAlgError,
  verifyHsCompact,
} from "./_test_only_hs_verifier.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");
const CORPUS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "jws",
  "rfc7515_appendix_a.json",
);
const PINS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "jws",
  ".upstream-pins.json",
);

const SCHEMA_ID = "relay.conformance.jws.rfc7515-appendix-a.v1";
const HEX_64 = /^[0-9a-f]{64}$/;
const IETF_DATATRACKER_URL = "https://datatracker.ietf.org/doc/html/rfc7515";

interface CompactCase {
  name: string;
  kind: "compact";
  alg: string;
  input: string;
  hs_shared_key_b64u?: string;
  expected_hs_math?: { ok: boolean; alg: string };
  expected_production: {
    ok: boolean;
    alg?: string;
    kid?: string;
    code?: string;
    reason_substring?: string;
  };
  _source: string;
}

interface DetachedCase {
  name: string;
  kind: "detached";
  alg: string;
  input: {
    protected_b64u: string;
    payload_b64u: string;
    signature_b64u: string;
  };
  expected_production: {
    ok: boolean;
    alg?: string;
    kid?: string;
    code?: string;
    reason_substring?: string;
  };
  _source: string;
}

type CorpusCase = CompactCase | DetachedCase;

interface Corpus {
  schema: string;
  source: { url: string; rfc: string };
  case_counts: Record<string, number>;
  jwks: { keys: Array<Record<string, unknown>> };
  cases: CorpusCase[];
}

interface Pins {
  source_url: string;
  rfc: string;
  transcript_sha256: string;
  transcript_byte_length: number;
  appendix_subsections_covered: string[];
}

function loadCorpus(): Corpus {
  if (!existsSync(CORPUS_PATH)) {
    throw new Error(
      `W17.2 corpus missing at ${CORPUS_PATH}; regenerate via ` +
        "`uv run python scripts/generate-jws-rfc7515-appendix-a-corpus.py`.",
    );
  }
  return JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as Corpus;
}

function loadPins(): Pins {
  if (!existsSync(PINS_PATH)) {
    throw new Error(
      `W17.2 pins missing at ${PINS_PATH}; regenerate via the generator script.`,
    );
  }
  return JSON.parse(readFileSync(PINS_PATH, "utf-8")) as Pins;
}

function b64uDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const std = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(std, "base64"));
}

function findCase<T extends CorpusCase>(
  corpus: Corpus,
  name: string,
  expectedKind: T["kind"],
): T {
  const c = corpus.cases.find((c) => c.name === name);
  if (!c) {
    throw new Error(`corpus case not found: ${name}`);
  }
  if (c.kind !== expectedKind) {
    throw new Error(
      `corpus case ${name} kind ${c.kind} != expected ${expectedKind}`,
    );
  }
  return c as T;
}

// ---------------------------------------------------------------------------
// VAL-W17-006: corpus pinned to RFC 7515 Appendix A by SHA-256
// ---------------------------------------------------------------------------

describe("VAL-W17-006: corpus pinned to RFC 7515", () => {
  test("schema id matches v1", () => {
    const corpus = loadCorpus();
    expect(corpus.schema).toBe(SCHEMA_ID);
  });

  test("pins reference IETF datatracker URL", () => {
    const pins = loadPins();
    expect(pins.source_url).toBe(IETF_DATATRACKER_URL);
    expect(pins.rfc).toBe("RFC 7515");
    expect(pins.transcript_sha256).toMatch(HEX_64);
    expect(pins.transcript_byte_length).toBeGreaterThan(0);
  });

  test("pins enumerate appendix subsections covered", () => {
    const pins = loadPins();
    const required = ["A.1 HS256", "A.2 RS256", "A.3 ES256", "A.4 ES512"];
    for (const req of required) {
      expect(pins.appendix_subsections_covered).toContain(req);
    }
  });

  test("every case name is unique", () => {
    const corpus = loadCorpus();
    const seen = new Set<string>();
    for (const c of corpus.cases) {
      expect(seen.has(c.name)).toBe(false);
      seen.add(c.name);
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-007a: HS256/HS512 vectors verify under the test-only HS helper
// ---------------------------------------------------------------------------

describe("VAL-W17-007a: HS helper math (TS mirror)", () => {
  test("A.1 HS256 literal verifies under TS HS helper", () => {
    const corpus = loadCorpus();
    const hs256 = findCase<CompactCase>(corpus, "appendix-a1-hs256", "compact");
    expect(hs256.hs_shared_key_b64u).toBeTruthy();
    const key = b64uDecode(hs256.hs_shared_key_b64u as string);
    expect(verifyHsCompact(hs256.input, key)).toBe(true);
  });

  test("constructed HS512 verifies under TS HS helper", () => {
    const corpus = loadCorpus();
    const hs512 = findCase<CompactCase>(
      corpus,
      "appendix-a2-hs512-constructed",
      "compact",
    );
    expect(hs512.hs_shared_key_b64u).toBeTruthy();
    const key = b64uDecode(hs512.hs_shared_key_b64u as string);
    expect(verifyHsCompact(hs512.input, key)).toBe(true);
  });

  test("TS HS helper rejects RS256 (boundary)", () => {
    // Construct a minimal RS256 token; helper should throw before
    // attempting any signature work.
    const header = Buffer.from(
      JSON.stringify({ alg: "RS256", kid: "x" }),
    ).toString("base64url");
    const payload = "eyJ4IjoxfQ";
    const sig = "AAAA";
    expect(() => verifyHsCompact(`${header}.${payload}.${sig}`, Buffer.from(""))).toThrow(
      UnsupportedHsAlgError,
    );
  });

  test("TS HS helper rejects tampered HMAC", () => {
    const corpus = loadCorpus();
    const hs256 = findCase<CompactCase>(corpus, "appendix-a1-hs256", "compact");
    const parts = hs256.input.split(".");
    const headerB64u = parts[0] as string;
    const payloadB64u = parts[1] as string;
    const sigB64u = parts[2] as string;
    const sigBytes = b64uDecode(sigB64u);
    const lastIdx = sigBytes.length - 1;
    sigBytes[lastIdx] = (sigBytes[lastIdx] as number) ^ 0x01;
    const tamperedSig = Buffer.from(sigBytes).toString("base64url");
    const tamperedToken = `${headerB64u}.${payloadB64u}.${tamperedSig}`;
    const key = b64uDecode(hs256.hs_shared_key_b64u as string);
    expect(verifyHsCompact(tamperedToken, key)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-007b: production verifier behavior on Appendix A vectors
// ---------------------------------------------------------------------------

function verifyCompact(c: CompactCase, jwks: Corpus["jwks"]): SignatureCheck {
  return verifyJwsCompact(c.input, jwks);
}

function verifyDetached(c: DetachedCase, jwks: Corpus["jwks"]): SignatureCheck {
  // The detached payload is the b64u-encoded ASCII bytes of the payload
  // (RFC 7515 sec 3.1 signing input convention).
  return verifyJwsDetached({
    protectedB64u: c.input.protected_b64u,
    payloadBytes: Buffer.from(c.input.payload_b64u, "ascii"),
    signatureB64u: c.input.signature_b64u,
    jwks,
  });
}

describe("VAL-W17-007b: production verifier on Appendix A vectors", () => {
  test("rejects A.1 HS256 literal with RELAY-VERIFY-UNSUPPORTED-ALG", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(corpus, "appendix-a1-hs256", "compact");
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(false);
    expect(r.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
  });

  test("rejects constructed HS512", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a2-hs512-constructed",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(false);
    expect(r.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
  });

  test("accepts kid-augmented RS256", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a2-rs256-kid-augmented",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(true);
    expect(r.alg).toBe("RS256");
  });

  test("accepts kid-augmented ES256", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a3-es256-kid-augmented",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(true);
    expect(r.alg).toBe("ES256");
  });

  test("rejects tampered RS256 payload", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a2-rs256-kid-augmented-tampered-payload",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(false);
  });

  test("rejects tampered ES256 signature", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a3-es256-kid-augmented-tampered-signature",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-008: algorithm restriction
// ---------------------------------------------------------------------------

describe("VAL-W17-008: alg restriction", () => {
  test("rejects A.5 unsecured (alg=none)", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a5-unsecured-none",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(false);
    expect(r.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
  });

  test("rejects forged alg=none with attacker payload", () => {
    const corpus = loadCorpus();
    const c = findCase<CompactCase>(
      corpus,
      "appendix-a5-forged-alg-none-attacker-payload",
      "compact",
    );
    const r = verifyCompact(c, corpus.jwks);
    expect(r.ok).toBe(false);
    expect(r.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
  });

  test("rejects ES512 (literal + kid-augmented) by allow-list", () => {
    const corpus = loadCorpus();
    for (const name of [
      "appendix-a4-es512-literal",
      "appendix-a4-es512-kid-augmented",
    ]) {
      const c = findCase<CompactCase>(corpus, name, "compact");
      const r = verifyCompact(c, corpus.jwks);
      expect(r.ok).toBe(false);
      expect(r.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
    }
  });

  test("every disallowed-alg vector is rejected with the canonical code", () => {
    const corpus = loadCorpus();
    const disallowed = new Set(["HS256", "HS512", "ES512", "none"]);
    const failures: string[] = [];
    for (const c of corpus.cases) {
      if (c.kind !== "compact") continue;
      if (!disallowed.has(c.alg)) continue;
      const r = verifyCompact(c as CompactCase, corpus.jwks);
      if (r.ok || r.code !== RELAY_VERIFY_UNSUPPORTED_ALG) {
        failures.push(
          `${c.name}: alg=${c.alg} ok=${r.ok} code=${r.code} reason=${r.reason}`,
        );
      }
    }
    expect(failures).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-009: detached-payload JWS
// ---------------------------------------------------------------------------

describe("VAL-W17-009: detached JWS", () => {
  test("detached RS256 verifies", () => {
    const corpus = loadCorpus();
    const c = findCase<DetachedCase>(
      corpus,
      "appendix-a2-rs256-kid-augmented-detached",
      "detached",
    );
    const r = verifyDetached(c, corpus.jwks);
    expect(r.ok).toBe(true);
    expect(r.alg).toBe("RS256");
  });

  test("detached ES256 verifies", () => {
    const corpus = loadCorpus();
    const c = findCase<DetachedCase>(
      corpus,
      "appendix-a3-es256-kid-augmented-detached",
      "detached",
    );
    const r = verifyDetached(c, corpus.jwks);
    expect(r.ok).toBe(true);
    expect(r.alg).toBe("ES256");
  });

  test("compact + detached share the same signature bytes", () => {
    const corpus = loadCorpus();
    const pairs: Array<[string, string]> = [
      [
        "appendix-a2-rs256-kid-augmented",
        "appendix-a2-rs256-kid-augmented-detached",
      ],
      [
        "appendix-a3-es256-kid-augmented",
        "appendix-a3-es256-kid-augmented-detached",
      ],
    ];
    for (const [compactName, detachedName] of pairs) {
      const compact = findCase<CompactCase>(corpus, compactName, "compact");
      const detached = findCase<DetachedCase>(
        corpus,
        detachedName,
        "detached",
      );
      const compactSig = compact.input.split(".").slice(-1)[0];
      expect(compactSig).toBe(detached.input.signature_b64u);
    }
  });

  test("tampered detached payload fails verification", () => {
    const corpus = loadCorpus();
    const c = findCase<DetachedCase>(
      corpus,
      "appendix-a2-rs256-kid-augmented-detached",
      "detached",
    );
    const tampered = Buffer.from(c.input.payload_b64u, "ascii");
    const lastIdx = tampered.length - 1;
    tampered[lastIdx] = (tampered[lastIdx] as number) ^ 0x01;
    const r = verifyJwsDetached({
      protectedB64u: c.input.protected_b64u,
      payloadBytes: tampered,
      signatureB64u: c.input.signature_b64u,
      jwks: corpus.jwks,
    });
    expect(r.ok).toBe(false);
  });
});
