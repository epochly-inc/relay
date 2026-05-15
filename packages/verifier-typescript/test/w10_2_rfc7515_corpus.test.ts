// VAL-W10-010 / VAL-W10-011 / VAL-W10-012 / VAL-W10-013 / VAL-W10-014:
//
// Loads the same conformance corpus as the Python verifier
// (tests/conformance/jws/rfc7515_corpus.json) and asserts the TS verifier
// produces the expected verdict for every case. Cross-language parity
// (VAL-W10-015) is enforced separately by the parity test, which compares
// the JCS-canonicalised verdict-envelope digest to the Python-side table.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync } from "node:fs";

import {
  RELAY_EVID_014,
  RELAY_VERIFY_ALG_MISMATCH,
  RELAY_VERIFY_UNSUPPORTED_ALG,
  type SignatureCheck,
  verifyDetachedClaimSignature,
  verifyJwsCompact,
  verifyMultiSignatures,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");
const CORPUS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "jws",
  "rfc7515_corpus.json",
);

interface CorpusCase {
  name: string;
  kind: "compact" | "detached" | "multisig";
  input: unknown;
  expected: {
    ok: boolean;
    kid?: string;
    alg?: string;
    error_code?: string;
    aggregate?: string;
    verdicts?: Array<{ kid: string; alg: string; ok: boolean }>;
  };
}

interface Corpus {
  schema: string;
  jwks: { keys: Array<Record<string, unknown>> };
  cases: CorpusCase[];
}

function loadCorpus(): Corpus {
  if (!existsSync(CORPUS_PATH)) {
    throw new Error(
      `VAL-W10-010 corpus missing at ${CORPUS_PATH}. Regenerate with ` +
        "`uv run python scripts/generate-jws-rfc7515-corpus.py`.",
    );
  }
  return JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as Corpus;
}

interface Verdict {
  ok: boolean;
  kid: string;
  alg: string;
  code: string;
  aggregate?: string;
  verdicts?: Array<{ kid: string; alg: string; ok: boolean; code: string }>;
}

function runCase(c: CorpusCase, jwks: Corpus["jwks"]): Verdict {
  if (c.kind === "compact") {
    const sc = verifyJwsCompact(c.input as string, jwks);
    return { ok: sc.ok, kid: sc.kid, alg: sc.alg, code: sc.code };
  }
  if (c.kind === "detached") {
    const inp = c.input as { protected_b64u: string; signature_b64u: string; claim: unknown };
    const sc = verifyDetachedClaimSignature({
      protectedB64u: inp.protected_b64u,
      signatureB64u: inp.signature_b64u,
      claim: inp.claim,
      jwks,
    });
    return { ok: sc.ok, kid: sc.kid, alg: sc.alg, code: sc.code };
  }
  // multisig
  const inp = c.input as { payload: unknown; signatures: Array<{ alg: string; kid: string; signature_b64u: string }> };
  const r = verifyMultiSignatures({
    payload: inp.payload,
    signatures: inp.signatures,
    jwks,
  });
  return {
    ok: r.ok,
    kid: "<multi>",
    alg: "<multi>",
    code: "",
    aggregate: r.aggregate,
    verdicts: r.signaturesChecked.map((sc: SignatureCheck) => ({
      kid: sc.kid, alg: sc.alg, ok: sc.ok, code: sc.code,
    })),
  };
}

describe("W10.2 RFC 7515 conformance corpus", () => {
  const corpus = loadCorpus();
  const jwks = corpus.jwks;

  test("VAL-W10-010 corpus contains >= 12 cases", () => {
    expect(corpus.schema).toBe("relay.conformance.jws.v1");
    expect(corpus.cases.length).toBeGreaterThanOrEqual(12);
  });

  for (const c of corpus.cases) {
    test(`VAL-W10-010 ${c.name} matches expected verdict`, () => {
      const actual = runCase(c, jwks);
      expect(actual.ok).toBe(c.expected.ok);
    });
  }

  test("VAL-W10-010 positive cases carry corpus-declared kid + alg", () => {
    for (const c of corpus.cases) {
      if (!c.expected.ok) continue;
      const actual = runCase(c, jwks);
      if (c.kind === "multisig") {
        const expectedVerdicts = c.expected.verdicts ?? [];
        expect(actual.verdicts).toBeDefined();
        const v = actual.verdicts ?? [];
        expect(v.length).toBe(expectedVerdicts.length);
        for (let i = 0; i < expectedVerdicts.length; i++) {
          const ev = expectedVerdicts[i];
          const av = v[i];
          if (ev === undefined || av === undefined) {
            throw new Error(`verdict missing at index ${i}`);
          }
          expect(av.kid).toBe(ev.kid);
          expect(av.alg).toBe(ev.alg);
          expect(av.ok).toBe(true);
        }
      } else {
        expect(actual.kid).toBe(c.expected.kid);
        expect(actual.alg).toBe(c.expected.alg);
      }
    }
  });
});

describe("W10.2 VAL-W10-011 alg-substitution attacks", () => {
  const corpus = loadCorpus();
  const jwks = corpus.jwks;

  test("alg=none (empty + garbage) rejected with RELAY-VERIFY-011", () => {
    for (const name of ["neg-alg-none-empty-sig", "neg-alg-none-garbage-sig"]) {
      const c = corpus.cases.find(x => x.name === name);
      expect(c, `corpus case missing: ${name}`).toBeDefined();
      const actual = runCase(c!, jwks);
      expect(actual.ok).toBe(false);
      expect(actual.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
      expect(actual.alg).toBe("none");
    }
  });

  test("HS256 over RSA / EdDSA public key rejected with RELAY-VERIFY-011", () => {
    for (const name of [
      "neg-alg-hs256-over-rsa-public-key",
      "neg-alg-hs256-over-eddsa-public-key",
    ]) {
      const c = corpus.cases.find(x => x.name === name);
      expect(c).toBeDefined();
      const actual = runCase(c!, jwks);
      expect(actual.ok).toBe(false);
      expect(actual.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
      expect(actual.alg).toBe("HS256");
    }
  });

  test("alg-mismatch (kty disagrees with allow-listed alg) yields RELAY-VERIFY-010", () => {
    const corpus2 = loadCorpus();
    const rsaJwk = corpus2.jwks.keys.find(k => k.kty === "RSA");
    expect(rsaJwk).toBeDefined();
    const forgedJwks = {
      keys: [
        { ...rsaJwk!, kid: "kid-mismatch", alg: "ES256" },
      ],
    };
    const header = JSON.stringify({ alg: "ES256", kid: "kid-mismatch", typ: "JWT" });
    const headerSorted = JSON.stringify({ alg: "ES256", kid: "kid-mismatch", typ: "JWT" });
    const headerB64 = Buffer.from(headerSorted).toString("base64url");
    const payloadB64 = Buffer.from('{"x":1}').toString("base64url");
    const sigB64 = Buffer.from(new Uint8Array(64)).toString("base64url");
    const token = `${headerB64}.${payloadB64}.${sigB64}`;
    const sc = verifyJwsCompact(token, forgedJwks);
    expect(sc.ok).toBe(false);
    expect(sc.code).toBe(RELAY_VERIFY_ALG_MISMATCH);
    expect(sc.reason).toContain("alg-mismatch");
    // Quiet unused-variable lint via reference
    void header;
  });
});

describe("W10.2 VAL-W10-012 detached payload binding", () => {
  const corpus = loadCorpus();
  const jwks = corpus.jwks;

  test("detached positive passes", () => {
    const c = corpus.cases.find(x => x.name === "detached-positive-eddsa");
    expect(c).toBeDefined();
    const actual = runCase(c!, jwks);
    expect(actual.ok).toBe(true);
  });

  test("detached tampered claim emits RELAY-EVID-014", () => {
    const c = corpus.cases.find(x => x.name === "detached-negative-tampered-claim");
    expect(c).toBeDefined();
    const actual = runCase(c!, jwks);
    expect(actual.ok).toBe(false);
    expect(actual.code).toBe(RELAY_EVID_014);
  });
});

describe("W10.2 VAL-W10-013 multi-signature verdicts", () => {
  const corpus = loadCorpus();
  const jwks = corpus.jwks;

  test("N=2 both valid yields all_valid", () => {
    const c = corpus.cases.find(x => x.name === "multisig-n2-both-valid");
    expect(c).toBeDefined();
    const actual = runCase(c!, jwks);
    expect(actual.ok).toBe(true);
    expect(actual.aggregate).toBe("all_valid");
    const v = actual.verdicts ?? [];
    expect(v.length).toBe(2);
    expect(v.every(x => x.ok)).toBe(true);
  });

  test("N=2 mixed reports per-signature verdicts", () => {
    const c = corpus.cases.find(x => x.name === "multisig-n2-mixed");
    expect(c).toBeDefined();
    const actual = runCase(c!, jwks);
    expect(actual.ok).toBe(false);
    expect(actual.aggregate).toBe("mixed");
    const v = actual.verdicts ?? [];
    expect(v.length).toBe(2);
    const v0 = v[0];
    const v1 = v[1];
    expect(v0).toBeDefined();
    expect(v1).toBeDefined();
    expect(v0!.ok).toBe(true);
    expect(v0!.alg).toBe("EdDSA");
    expect(v1!.ok).toBe(false);
    expect(v1!.alg).toBe("ES256");
  });

  test("N=6 all valid (no hard cap)", () => {
    const c = corpus.cases.find(x => x.name === "multisig-n6-all-valid");
    expect(c).toBeDefined();
    const actual = runCase(c!, jwks);
    expect(actual.ok).toBe(true);
    expect(actual.aggregate).toBe("all_valid");
    const v = actual.verdicts ?? [];
    expect(v.length).toBe(6);
    expect(v.every(x => x.ok)).toBe(true);
  });
});

describe("W10.2 VAL-W10-014 algorithm allow-list", () => {
  const corpus = loadCorpus();
  const jwks = corpus.jwks;

  const disallowed: Array<[string, string]> = [
    ["neg-alg-rs1-disallowed", "RS1"],
    ["neg-alg-vendor-disallowed", "vendor.custom-1"],
    ["neg-alg-missing", "<unknown>"],
    ["neg-alg-none-empty-sig", "none"],
    ["neg-alg-hs256-over-rsa-public-key", "HS256"],
  ];
  for (const [name, expectedAlg] of disallowed) {
    test(`disallowed alg rejected: ${name}`, () => {
      const c = corpus.cases.find(x => x.name === name);
      expect(c).toBeDefined();
      const actual = runCase(c!, jwks);
      expect(actual.ok).toBe(false);
      expect(actual.code).toBe(RELAY_VERIFY_UNSUPPORTED_ALG);
      expect(actual.alg).toBe(expectedAlg);
    });
  }

  const allowed: Array<[string, string]> = [
    ["positive-eddsa", "EdDSA"],
    ["positive-es256", "ES256"],
    ["positive-rs256", "RS256"],
  ];
  for (const [name, expectedAlg] of allowed) {
    test(`allow-list accepts canonical alg: ${name}`, () => {
      const c = corpus.cases.find(x => x.name === name);
      expect(c).toBeDefined();
      const actual = runCase(c!, jwks);
      expect(actual.ok).toBe(true);
      expect(actual.alg).toBe(expectedAlg);
      expect(actual.code).toBe("");
    });
  }
});
