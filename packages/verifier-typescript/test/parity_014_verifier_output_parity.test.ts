// Parity 014 -- verifier-output byte parity (convergence re-hunt #2/#8/#11).
//
// The Python verifier is the source-of-truth; the TS verifier MUST emit the
// same structured discriminators (reason/code/path_violation/offending_path)
// and the same human-readable `message` bytes for the same wire input.
//
// #2  (HIGH) tsa skew: Python sets reason="tsa_skew_exceeded"; TS used to set
//     a long descriptive message AS the reason -> structured-discriminator
//     divergence.
// #8  (MED)  path-traversal error: Python appends path_violation +
//     offending_path discriminator keys; TS omitted them.
// #11 (LOW)  message quoting: Python formats interpolated identifiers with !r
//     (single-quote repr); TS used JSON.stringify (double quotes) -> the
//     message bytes diverged for artifact_unavailable / artifact_digest_mismatch
//     / path_violation.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import { validateBundle, validateTsaToken } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity014-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
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

// Placeholder signature required so structure_ok=true in BOTH runtimes and the
// per-claim artifact screen runs (gated on structure_ok). See audit_r3_parity.
const PLACEHOLDER_SIG = {
  kid: "placeholder",
  alg: "EdDSA",
  signing_input_b64u: "eyJ4IjoxfQ",
  signature_b64u: "AA",
};

function bundleWithRef(artifactId: string, digest: string): Record<string, unknown> {
  return {
    schema_version: "relay.evidence_bundle.v1",
    trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
    decided_at: "2026-05-15T12:00:00Z",
    claims: [{ id: "c1", evidence_refs: [{ artifact_id: artifactId, digest }] }],
    signatures: [PLACEHOLDER_SIG],
  };
}

// Run the Python validate_bundle over the same wire bundle + a resolver map
// (artifact_id -> utf-8 string body, or null for "unavailable"), returning the
// errors array.
function pyValidateErrors(
  bundle: Record<string, unknown>,
  resolverMap: Record<string, string | null>,
): Array<Record<string, unknown>> {
  return pyJson<Array<Record<string, unknown>>>(`
import json, sys
from relay_verifier.bundle_validator import validate_bundle, ValidateBundleOptions
bundle = json.loads(${JSON.stringify(JSON.stringify(bundle))})
resolver_map = json.loads(${JSON.stringify(JSON.stringify(resolverMap))})
def resolver(aid):
    v = resolver_map.get(aid)
    if v is None:
        return None
    return v.encode("utf-8")
out = validate_bundle(
    bundle=bundle,
    jwks={"keys": []},
    options=ValidateBundleOptions(artifact_resolver=resolver),
)
sys.stdout.write(json.dumps(out["errors"]))
`);
}

function tsValidateErrors(
  bundle: Record<string, unknown>,
  resolverMap: Record<string, string | null>,
): Array<Record<string, unknown>> {
  const resolver = (aid: string): Uint8Array | null => {
    const v = resolverMap[aid];
    if (v === null || v === undefined) return null;
    return new TextEncoder().encode(v);
  };
  const out = validateBundle({
    bundle,
    jwks: { keys: [] },
    options: { artifact_resolver: resolver },
  });
  return out.errors as Array<Record<string, unknown>>;
}

function findByReason(
  errors: Array<Record<string, unknown>>,
  reason: string,
): Record<string, unknown> | undefined {
  return errors.find((e) => e["reason"] === reason);
}

// ===========================================================================
// #8 + #11: path_violation discriminator keys + message quoting parity
// ===========================================================================

describe("parity-014 path_violation discriminators + message bytes match Python", () => {
  test("relative_traversal artifact_id: structured keys + message byte-identical", () => {
    const badId = "../../etc/passwd";
    const bundle = bundleWithRef(badId, "deadbeef");
    const resolverMap = { [badId]: "never-read" };

    const pyErr = findByReason(pyValidateErrors(bundle, resolverMap), "path_violation");
    const tsErr = findByReason(tsValidateErrors(bundle, resolverMap), "path_violation");

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    // Structured discriminators (#8): TS must carry path_violation + offending_path.
    expect(tsErr!["path_violation"]).toBe(pyErr!["path_violation"]);
    expect(tsErr!["offending_path"]).toBe(pyErr!["offending_path"]);
    expect(tsErr!["offending_path"]).toBe(badId);
    expect(tsErr!["code"]).toBe(pyErr!["code"]);
    // Message bytes (#11): single-quote repr, identical to Python.
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
  });
});

// ===========================================================================
// #11: artifact_unavailable + artifact_digest_mismatch message parity
// ===========================================================================

describe("parity-014 resolver-stage error messages match Python byte-for-byte", () => {
  test("artifact_unavailable message uses single-quote repr like Python", () => {
    const goodId = "artifacts/test.log";
    const bundle = bundleWithRef(goodId, "deadbeef");
    const resolverMap = { [goodId]: null }; // unavailable

    const pyErr = findByReason(pyValidateErrors(bundle, resolverMap), "artifact_unavailable");
    const tsErr = findByReason(tsValidateErrors(bundle, resolverMap), "artifact_unavailable");

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
    expect(String(tsErr!["message"])).toContain("'artifacts/test.log'");
  });

  test("artifact_digest_mismatch message uses single-quote repr like Python", () => {
    const goodId = "artifacts/test.log";
    // declared digest deliberately != sha256("hello").
    const bundle = bundleWithRef(goodId, "deadbeef");
    const resolverMap = { [goodId]: "hello" };

    const pyErr = findByReason(
      pyValidateErrors(bundle, resolverMap),
      "artifact_digest_mismatch",
    );
    const tsErr = findByReason(
      tsValidateErrors(bundle, resolverMap),
      "artifact_digest_mismatch",
    );

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
    // declared='deadbeef' recomputed='<sha256(hello)>' -- single-quoted.
    expect(String(tsErr!["message"])).toContain("declared='deadbeef'");
  });
});

// ===========================================================================
// HIGH #4: non-ASCII operand escaping parity (claim_namespace_unknown).
//
// The Python verifier interpolated identifiers with !r (CPython repr), which
// keeps PRINTABLE non-ASCII verbatim but ESCAPES non-printable non-ASCII
// (C1 controls, U+00A0, format/separator chars like U+200B/U+2028/U+FEFF, and
// non-BMP non-printables). The TS pyReprStr only escaped cp<0x20 and 0x7f,
// emitting every non-ASCII byte verbatim -> the message bytes diverged for any
// operand carrying an interior non-printable non-ASCII code point. Namespace
// keys are attacker-controllable, so the divergence is reachable on the wire.
//
// Fix (parity-by-construction): BOTH sides now escape EVERY non-ASCII code
// point by the CPython ascii() rule (cp<=0xff -> \xNN, <=0xffff -> \uNNNN,
// else \U + 8 hex). For a printable non-ASCII char (U+4E2D, U+1F600) the two
// runtimes still agree because both now escape it. These tests drive the REAL
// Python validate_bundle and the REAL TS validateBundle over the same wire
// bundle and assert byte-identical claim_namespace_unknown messages.
// ===========================================================================

function bundleWithNamespaceKey(key: string): Record<string, unknown> {
  return {
    schema_version: "relay.evidence_bundle.v1",
    trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
    decided_at: "2026-05-15T12:00:00Z",
    claims: [{ id: "c1", namespaces: { [key]: {} } }],
    signatures: [PLACEHOLDER_SIG],
  };
}

describe("parity-014 claim_namespace_unknown non-ASCII operand bytes match Python", () => {
  test("interior U+200B (ZWSP) in a namespace key: message byte-identical", () => {
    // A printable label with an embedded zero-width space -- repr() would
    // escape it as \u200b while the old TS emitted the literal ZWSP.
    const key = "x\u200ba";
    const bundle = bundleWithNamespaceKey(key);

    const pyErr = findByReason(
      pyValidateErrors(bundle, {}),
      "claim_namespace_unknown",
    );
    const tsErr = findByReason(
      tsValidateErrors(bundle, {}),
      "claim_namespace_unknown",
    );

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
    // Both must render the ZWSP escaped, never as the literal byte.
    expect(String(tsErr!["message"])).toContain("'x\\u200ba'");
  });

  test("non-BMP U+1F600 in a namespace key: structured non_canonicalizable_bundle rejection (Py<->TS parity)", () => {
    // A supplementary-plane object KEY cannot be canonicalised to identical
    // bytes across runtimes (RFC 8785 sorts object keys by UTF-16 code unit;
    // Python sorts by code point), so the JCS encoder fails-closed. BOTH
    // verifiers therefore refuse the bundle with a STRUCTURED
    // non_canonicalizable_bundle error (keystone invariant #11) BEFORE
    // namespace evaluation -- rather than (divergently) canonicalising it and
    // surfacing claim_namespace_unknown. Keystone invariant #16: the reason,
    // code, and message bytes are identical across runtimes.
    const key = "x\u{1f600}y";
    const bundle = bundleWithNamespaceKey(key);

    const pyErrors = pyValidateErrors(bundle, {});
    const tsErrors = tsValidateErrors(bundle, {});

    const pyErr = findByReason(pyErrors, "non_canonicalizable_bundle");
    const tsErr = findByReason(tsErrors, "non_canonicalizable_bundle");

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    // Structured discriminators byte-identical across runtimes (the
    // keystone-#16 parity proof: same non-BMP-key bundle, same rejection).
    expect(pyErr!["code"]).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(tsErr!["code"]).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
    // The bundle is refused at canonicalisation, so the old
    // claim_namespace_unknown path is unreachable for a non-BMP key.
    expect(findByReason(pyErrors, "claim_namespace_unknown")).toBeUndefined();
    expect(findByReason(tsErrors, "claim_namespace_unknown")).toBeUndefined();
  });

  test("C1 control U+0080 and U+00A0 in a namespace key: message byte-identical", () => {
    const key = "x\u0080\u00a0z";
    const bundle = bundleWithNamespaceKey(key);

    const pyErr = findByReason(
      pyValidateErrors(bundle, {}),
      "claim_namespace_unknown",
    );
    const tsErr = findByReason(
      tsValidateErrors(bundle, {}),
      "claim_namespace_unknown",
    );

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
    expect(String(tsErr!["message"])).toContain("'x\\x80\\xa0z'");
  });
});

// ===========================================================================
// Precedence: a non-canonicalisable (non-BMP-key) bundle that is ALSO over the
// signature cap MUST return non_canonicalizable_bundle, NOT
// signature_count_exceeded. The over-cap branch canonicalises for a diagnostic
// digest inside a swallow-all guard (Python contextlib.suppress(ValueError),
// which JCSEncodeError subclasses; TS try/catch), so if it ran first the
// fundamental non-canonicalisability failure would be masked. Both runtimes
// run the non-BMP screen BEFORE the over-cap check (keystone invariant #11/#16;
// roborev follow-on on the F1 fix).
// ===========================================================================

describe("parity-014 non-BMP key outranks over-cap signature count (Py<->TS)", () => {
  test("over-cap AND non-BMP namespace key => non_canonicalizable_bundle on both", () => {
    const key = "x\u{1f600}y";
    // 5 signatures (> MAX_BUNDLE_SIGNATURES = 4) AND a supplementary-plane
    // object key in the signed payload.
    const bundle: Record<string, unknown> = {
      schema_version: "relay.evidence_bundle.v1",
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
      claims: [{ id: "c1", namespaces: { [key]: {} } }],
      signatures: [
        PLACEHOLDER_SIG,
        PLACEHOLDER_SIG,
        PLACEHOLDER_SIG,
        PLACEHOLDER_SIG,
        PLACEHOLDER_SIG,
      ],
    };

    const pyErrors = pyValidateErrors(bundle, {});
    const tsErrors = tsValidateErrors(bundle, {});

    const pyErr = findByReason(pyErrors, "non_canonicalizable_bundle");
    const tsErr = findByReason(tsErrors, "non_canonicalizable_bundle");

    expect(pyErr).toBeDefined();
    expect(tsErr).toBeDefined();
    // The non-canonicalisable rejection wins on BOTH runtimes, byte-identical.
    expect(pyErr!["code"]).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(tsErr!["code"]).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(tsErr!["message"]).toBe(pyErr!["message"]);
    // The over-cap reason must NOT appear on either runtime.
    expect(findByReason(pyErrors, "signature_count_exceeded")).toBeUndefined();
    expect(findByReason(tsErrors, "signature_count_exceeded")).toBeUndefined();
  });
});

// ===========================================================================
// #2: TSA gen_time skew reason is the structured "tsa_skew_exceeded"
// ===========================================================================

describe("parity-014 tsa skew reason is the structured discriminator", () => {
  test("a >300s skew yields reason='tsa_skew_exceeded' (parity with Python)", () => {
    // A matching message_imprint lets the token pass the imprint-binding step
    // and reach the skew check; no tsr_der_b64u is needed because the skew
    // outcome fires BEFORE the cryptographic TSA verification in both runtimes.
    const token = {
      message_imprint: { hash_algorithm: "sha256", hashed_message_hex: "00".repeat(32) },
      gen_time: "2026-05-15T12:10:00Z", // +600s from decided_at
    };
    const r = validateTsaToken({
      token,
      bundleDigestHex: "00".repeat(32),
      decidedAt: "2026-05-15T12:00:00Z",
      chainCerts: null,
      extraTrustedRootsPem: null,
    });
    expect(r.outcome).toBe("skew");
    expect(r.reason).toBe("tsa_skew_exceeded");
    expect(r.skew_seconds).toBe(600);
  });
});
