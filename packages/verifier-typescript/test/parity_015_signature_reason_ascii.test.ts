// Parity 015 -- signature-path reason byte parity (roborev HIGH follow-on).
//
// The round-2 #4 ascii()-escape fix (commit fff7465) only covered the
// bundle_validator operands (claim_namespace_unknown / artifact ids /
// digests). The signature-path failure reasons in verify_bundle /
// verifyBundleSignature, verify_jws_compact / verifyJwsCompact,
// verify_jws_detached / verifyJwsDetached, and verify_multi_signatures /
// verifyMultiSignatures still interpolated attacker-controlled `alg` /
// `kid` with RAW template literals in TS (`'${alg}'`) while Python used
// `{alg!r}` (CPython repr). A signature whose `alg` (or `kid`) carries an
// interior non-printable non-ASCII code point (U+200B ZWSP) -- or a
// PRINTABLE non-ASCII one (U+4E2D) that repr keeps verbatim but ascii()
// escapes -- produced NON-IDENTICAL SignatureCheck.reason bytes between
// the Python and TS verifiers for the same wire input. That is a P0
// Py<->TS parity break on attacker-controllable verifier output.
//
// Fix (parity-by-construction): route EVERY signature-path reason that
// interpolates alg/kid through the SAME CPython ascii() rule both runtimes
// now use in bundle_validator -- Python `_py_ascii(...)` (the builtin
// ascii()), TS `pyReprStr(...)`. Both escape ALL non-ASCII by the same
// pure code-point-range rule (cp<=0xff -> \xNN, <=0xffff -> \uNNNN, else
// \U + 8 hex), so they agree by construction. For ASCII alg/kid the output
// is byte-identical to the prior single-quote form, so existing ASCII
// parity tests are unaffected.
//
// These tests drive the REAL Python verifier and the REAL TS verifier over
// the same wire input and assert byte-identical SignatureCheck.reason.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  verifyBundleSignature,
  verifyJwsCompact,
  verifyMultiSignatures,
  canonicalJsonBytes,
  b64uEncode,
  type JWKS,
  type SignatureCheck,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity015-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
  );
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 120_000,
    });
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status ?? -1 };
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

function pyJson<T = unknown>(code: string): T {
  const r = runPython(code);
  if (r.status !== 0) {
    throw new Error(`python helper failed (status=${r.status}): ${r.stderr}\n${r.stdout}`);
  }
  const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(line) as T;
}

// Empty trust anchor: every signature path that interpolates `kid` is the
// "no JWK in trust anchor matches kid" branch when the JWKS is empty.
const EMPTY_JWKS: JWKS = { keys: [] };

// ===========================================================================
// verify_bundle / verifyBundleSignature: unsupported-alg reason
// ===========================================================================

// A bundle with a single signature whose `alg` is unsupported but carries an
// interior non-ASCII code point. Both verifiers reject it with the
// unsupported-alg reason; the alg operand must escape identically.
function bundleWithAlgKid(alg: string, kid: string): Record<string, unknown> {
  return {
    schema_version: "relay.evidence_bundle.v1",
    trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
    decided_at: "2026-05-15T12:00:00Z",
    claims: [{ id: "c1" }],
    signatures: [
      {
        alg,
        kid,
        signing_input_b64u: "eyJ4IjoxfQ",
        signature_b64u: "AA",
      },
    ],
  };
}

// A bundle whose single signature carries the CORRECT signing_input_b64u for
// the payload (so the signing-input-drift / tamper check passes and the
// verifier reaches the kid lookup). `alg` is supported (EdDSA), so the next
// failure is "no JWK in trust anchor matches kid <kid>" under an empty JWKS.
function bundleWithValidSigningInput(kid: string): Record<string, unknown> {
  const base = {
    schema_version: "relay.evidence_bundle.v1",
    trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
    decided_at: "2026-05-15T12:00:00Z",
    claims: [{ id: "c1" }],
  };
  const signingInputB64u = b64uEncode(canonicalJsonBytes(base));
  return {
    ...base,
    signatures: [
      {
        alg: "EdDSA",
        kid,
        signing_input_b64u: signingInputB64u,
        signature_b64u: "AA",
      },
    ],
  };
}

function pyBundleReasons(bundle: Record<string, unknown>): Array<Record<string, unknown>> {
  return pyJson<Array<Record<string, unknown>>>(`
import json, sys
from relay_verifier.verifier import verify_bundle
bundle = json.loads(${JSON.stringify(JSON.stringify(bundle))})
res = verify_bundle(bundle, {"keys": []})
sys.stdout.write(json.dumps([
    {"kid": c.kid, "alg": c.alg, "ok": c.ok, "reason": c.reason, "code": c.code}
    for c in res.signature_checks
]))
`);
}

function tsBundleReasons(bundle: Record<string, unknown>): Array<Record<string, unknown>> {
  const sigs = bundle["signatures"] as Array<Record<string, unknown>>;
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(bundle)) {
    if (k !== "signatures") payload[k] = v;
  }
  const expected = canonicalJsonBytes(payload);
  return sigs.map((sig, idx) => {
    const sc = verifyBundleSignature({
      signature: sig,
      expectedCanonicalBytes: expected,
      jwks: EMPTY_JWKS,
      signatureIndex: idx,
    });
    return { kid: sc.kid, alg: sc.alg, ok: sc.ok, reason: sc.reason, code: sc.code };
  });
}

describe("parity-015 verifyBundleSignature reason bytes match Python", () => {
  test("unsupported alg with interior U+200B: reason byte-identical", () => {
    // alg is NOT in the allow-list and carries a zero-width space.
    const alg = "HS\u200b256";
    const bundle = bundleWithAlgKid(alg, "k1");

    const pyChecks = pyBundleReasons(bundle);
    const tsChecks = tsBundleReasons(bundle);

    expect(pyChecks[0]).toBeDefined();
    expect(tsChecks[0]).toBeDefined();
    expect(tsChecks[0]!["reason"]).toBe(pyChecks[0]!["reason"]);
    // ZWSP must render escaped, never as the literal byte.
    expect(String(tsChecks[0]!["reason"])).toContain("'HS\\u200b256'");
  });

  test("printable non-ASCII U+4E2D in alg: reason byte-identical (ascii() rule)", () => {
    // repr() keeps U+4E2D verbatim; ascii() escapes it. Both runtimes MUST
    // escape -- this is the case the bundle_validator fix proved cannot be
    // mirrored under repr().
    const alg = "HS\u4e2d256";
    const bundle = bundleWithAlgKid(alg, "k1");

    const pyChecks = pyBundleReasons(bundle);
    const tsChecks = tsBundleReasons(bundle);

    expect(tsChecks[0]!["reason"]).toBe(pyChecks[0]!["reason"]);
    expect(String(tsChecks[0]!["reason"])).toContain("'HS\\u4e2d256'");
  });

  test("unknown kid with interior U+200B (supported alg): reason byte-identical", () => {
    // alg IS supported (EdDSA) and the signing_input_b64u matches the payload,
    // so the verifier passes the tamper check and reaches the kid lookup; with
    // an empty JWKS the failure is "no JWK ... matches kid <kid>".
    const kid = "key\u200bid";
    const bundle = bundleWithValidSigningInput(kid);

    const pyChecks = pyBundleReasons(bundle);
    const tsChecks = tsBundleReasons(bundle);

    expect(String(pyChecks[0]!["reason"])).toContain("no JWK in trust anchor matches kid");
    expect(tsChecks[0]!["reason"]).toBe(pyChecks[0]!["reason"]);
    expect(String(tsChecks[0]!["reason"])).toContain("'key\\u200bid'");
  });

  test("ASCII alg/kid: reason unchanged (single-quote form preserved)", () => {
    const bundle = bundleWithAlgKid("HS256", "k1");
    const pyChecks = pyBundleReasons(bundle);
    const tsChecks = tsBundleReasons(bundle);
    expect(tsChecks[0]!["reason"]).toBe(pyChecks[0]!["reason"]);
    expect(String(tsChecks[0]!["reason"])).toBe("unsupported alg: 'HS256'");
  });
});

// ===========================================================================
// verify_jws_compact / verifyJwsCompact: unsupported-alg + unknown-kid reasons
// ===========================================================================

function compactToken(header: Record<string, unknown>): string {
  const headerB64 = b64uEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = b64uEncode(new TextEncoder().encode("{}"));
  const sigB64 = b64uEncode(new Uint8Array([0]));
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

function pyCompactReason(token: string): Record<string, unknown> {
  return pyJson<Record<string, unknown>>(`
import json, sys
from relay_verifier.verifier import verify_jws_compact
token = json.loads(${JSON.stringify(JSON.stringify(token))})
sc = verify_jws_compact(token, {"keys": []})
sys.stdout.write(json.dumps({"kid": sc.kid, "alg": sc.alg, "ok": sc.ok, "reason": sc.reason, "code": sc.code}))
`);
}

function tsCompactReason(token: string): Record<string, unknown> {
  const sc: SignatureCheck = verifyJwsCompact(token, EMPTY_JWKS);
  return { kid: sc.kid, alg: sc.alg, ok: sc.ok, reason: sc.reason, code: sc.code };
}

describe("parity-015 verifyJwsCompact reason bytes match Python", () => {
  test("unsupported alg with interior U+200B: reason byte-identical", () => {
    const token = compactToken({ alg: "HS\u200b256", kid: "k1" });
    const py = pyCompactReason(token);
    const ts = tsCompactReason(token);
    expect(ts["reason"]).toBe(py["reason"]);
    expect(String(ts["reason"])).toContain("'HS\\u200b256'");
  });

  test("unknown kid with interior U+200B: reason byte-identical", () => {
    const token = compactToken({ alg: "EdDSA", kid: "key\u200bid" });
    const py = pyCompactReason(token);
    const ts = tsCompactReason(token);
    expect(ts["reason"]).toBe(py["reason"]);
    expect(String(ts["reason"])).toContain("'key\\u200bid'");
  });
});

// ===========================================================================
// verify_multi_signatures / verifyMultiSignatures: unsupported-alg + unknown-kid
// ===========================================================================

function pyMultiReasons(
  payload: Record<string, unknown>,
  signatures: Array<Record<string, unknown>>,
): Array<Record<string, unknown>> {
  return pyJson<Array<Record<string, unknown>>>(`
import json, sys
from relay_verifier.verifier import verify_multi_signatures
payload = json.loads(${JSON.stringify(JSON.stringify(payload))})
signatures = json.loads(${JSON.stringify(JSON.stringify(signatures))})
res = verify_multi_signatures(payload=payload, signatures=signatures, jwks={"keys": []})
sys.stdout.write(json.dumps([
    {"kid": c.kid, "alg": c.alg, "ok": c.ok, "reason": c.reason, "code": c.code}
    for c in res.signatures_checked
]))
`);
}

function tsMultiReasons(
  payload: Record<string, unknown>,
  signatures: Array<{ alg?: unknown; kid?: unknown; signature_b64u?: unknown }>,
): Array<Record<string, unknown>> {
  const r = verifyMultiSignatures({ payload, signatures, jwks: EMPTY_JWKS });
  return r.signaturesChecked.map((sc) => ({
    kid: sc.kid,
    alg: sc.alg,
    ok: sc.ok,
    reason: sc.reason,
    code: sc.code,
  }));
}

describe("parity-015 verifyMultiSignatures reason bytes match Python", () => {
  test("unsupported alg with interior U+200B: reason byte-identical", () => {
    const payload = { a: 1 };
    const sigs = [{ alg: "HS\u200b256", kid: "k1", signature_b64u: "AA" }];
    const py = pyMultiReasons(payload, sigs);
    const ts = tsMultiReasons(payload, sigs);
    expect(ts[0]!["reason"]).toBe(py[0]!["reason"]);
    expect(String(ts[0]!["reason"])).toContain("'HS\\u200b256'");
  });

  test("unknown kid with interior U+200B: reason byte-identical", () => {
    const payload = { a: 1 };
    const sigs = [{ alg: "EdDSA", kid: "key\u200bid", signature_b64u: "AA" }];
    const py = pyMultiReasons(payload, sigs);
    const ts = tsMultiReasons(payload, sigs);
    expect(ts[0]!["reason"]).toBe(py[0]!["reason"]);
    expect(String(ts[0]!["reason"])).toContain("'key\\u200bid'");
  });
});
