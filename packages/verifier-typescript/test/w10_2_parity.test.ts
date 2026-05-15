// VAL-W10-015 cross-language verdict parity (TS side).
//
// Loads tests/conformance/jws/rfc7515_corpus.json AND
// tests/conformance/jws/py_verdict_digests.json (written by the Python
// test in packages/verifier/tests/test_w10_2_rfc7515_corpus.py).
// For every corpus case, projects the TS verifier outcome into the
// SAME canonical-JSON verdict envelope used by the Python side, hashes
// it (SHA-256), and asserts the TS digest equals the Python digest.
//
// A divergent digest means Python and TypeScript produced a different
// verdict envelope for the same input -- VAL-W10-015 fails CI.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";

import {
  canonicalJsonBytes,
  type SignatureCheck,
  verifyDetachedClaimSignature,
  verifyJwsCompact,
  verifyMultiSignatures,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");
const CORPUS_PATH = resolve(REPO_ROOT, "tests", "conformance", "jws", "rfc7515_corpus.json");
const PY_DIGEST_PATH = resolve(REPO_ROOT, "tests", "conformance", "jws", "py_verdict_digests.json");

interface CorpusCase {
  name: string;
  kind: "compact" | "detached" | "multisig";
  input: unknown;
  expected: { ok: boolean };
}
interface Corpus { schema: string; jwks: { keys: Array<Record<string, unknown>> }; cases: CorpusCase[] }
interface PyDigests { schema: string; digests: Record<string, string> }

function loadJson<T>(path: string, what: string): T {
  if (!existsSync(path)) {
    throw new Error(`VAL-W10-015 ${what} missing at ${path}.`);
  }
  return JSON.parse(readFileSync(path, "utf-8")) as T;
}

function tsVerdictEnvelope(c: CorpusCase, jwks: Corpus["jwks"]): Record<string, unknown> {
  if (c.kind === "compact") {
    const sc = verifyJwsCompact(c.input as string, jwks);
    return verdictEnv(c.name, c.kind, sc);
  }
  if (c.kind === "detached") {
    const inp = c.input as { protected_b64u: string; signature_b64u: string; claim: unknown };
    const sc = verifyDetachedClaimSignature({
      protectedB64u: inp.protected_b64u,
      signatureB64u: inp.signature_b64u,
      claim: inp.claim,
      jwks,
    });
    return verdictEnv(c.name, c.kind, sc);
  }
  const inp = c.input as { payload: unknown; signatures: Array<{ alg: string; kid: string; signature_b64u: string }> };
  const r = verifyMultiSignatures({
    payload: inp.payload,
    signatures: inp.signatures,
    jwks,
  });
  return {
    name: c.name,
    kind: c.kind,
    ok: Boolean(r.ok),
    aggregate: r.aggregate,
    verdicts: r.signaturesChecked.map((sc: SignatureCheck) => ({
      kid: String(sc.kid),
      alg: String(sc.alg),
      ok: Boolean(sc.ok),
      code: String(sc.code),
    })),
  };
}

function verdictEnv(name: string, kind: string, sc: SignatureCheck): Record<string, unknown> {
  return {
    name,
    kind,
    ok: Boolean(sc.ok),
    kid: String(sc.kid),
    alg: String(sc.alg),
    code: String(sc.code),
  };
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("W10.2 VAL-W10-015 cross-language verdict parity", () => {
  const corpus = loadJson<Corpus>(CORPUS_PATH, "corpus");
  const pyTable = loadJson<PyDigests>(PY_DIGEST_PATH, "Python digest table");
  const jwks = corpus.jwks;

  test("Python digest table covers every corpus case", () => {
    for (const c of corpus.cases) {
      expect(
        pyTable.digests[c.name],
        `Python digest table missing entry for case ${c.name}; ` +
          `regenerate with \`uv run pytest packages/verifier/tests/test_w10_2_rfc7515_corpus.py\``,
      ).toBeDefined();
    }
  });

  for (const c of corpus.cases) {
    test(`parity: ${c.name}`, () => {
      const env = tsVerdictEnvelope(c, jwks);
      const tsDigest = sha256Hex(canonicalJsonBytes(env));
      const pyDigest = pyTable.digests[c.name];
      expect(pyDigest, `case ${c.name} missing from Python digest table`).toBeDefined();
      expect(
        tsDigest,
        `VAL-W10-015 parity failure for case ${c.name}: ` +
          `TS verdict envelope sha256=${tsDigest} differs from Python sha256=${pyDigest}. ` +
          `TS envelope: ${JSON.stringify(env)}`,
      ).toBe(pyDigest);
    });
  }
});
