// Audit Round 3 — TS verifier parity bug fixes (C1, C2, C3, C4).
//
// C1: path-traversal screen MUST fire BEFORE the artifact resolver.
// C2: canonicalJsonBytes MUST emit RFC 8785 literal UTF-8 (not \uXXXX
//     escapes). Same wire bundle with non-ASCII string must hash to the
//     same sha256 under both Python and TS verifiers.
// C3: bundle signature wire field is `signing_input_b64u` (with
//     `protected_b64u` as legacy alias) -- NOT a JWS detached header.
// C4: post-C2, bundle-level digest and per-claim digest paths agree.
//
// The Python verifier is the source-of-truth; this suite shells out to
// `python3 -c "..."` to produce reference values, then asserts the TS
// runtime produces byte-equal outputs.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  RELAY_EVID_024_PATH,
  bundleDigest,
  canonicalJsonBytes,
  checkArtifactPath,
  jcsCanonicalize,
  validateBundle,
  verifyBundleSignature,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): {
  stdout: string;
  stderr: string;
  status: number;
} {
  const tmpFile = resolve(
    tmpdir(),
    `relay-audit-r3-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
  );
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 60_000,
    });
    return {
      stdout: r.stdout ?? "",
      stderr: r.stderr ?? "",
      status: r.status ?? -1,
    };
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

function pyJson<T = unknown>(code: string): T {
  const r = runPython(code);
  if (r.status !== 0) {
    throw new Error(
      `python helper failed (status=${r.status}): ${r.stderr}\n` +
        `--- stdout ---\n${r.stdout}`,
    );
  }
  const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(line) as T;
}

// ============================================================================
// BUG-C2 / C4: JCS canonicalization parity for non-ASCII string fields
// ============================================================================

describe("BUG-C2 canonicalJsonBytes uses RFC 8785 JCS literal UTF-8", () => {
  test("non-ASCII string hashes identically under Python and TS", () => {
    const claim = { name: "café", note: "naive: é" };
    // TS side.
    const tsBytes = canonicalJsonBytes(claim);
    const tsDigest = createHash("sha256").update(tsBytes).digest("hex");
    // Python side.
    const py = pyJson<{ digest: string; bytes_len: number }>(`
import hashlib, json, sys
from relay_verifier.canonical import jcs_canonicalize
obj = json.loads(${JSON.stringify(JSON.stringify(claim))})
b = jcs_canonicalize(obj)
print(json.dumps({"digest": hashlib.sha256(b).hexdigest(), "bytes_len": len(b)}))
`);
    expect(tsDigest).toBe(py.digest);
    expect(tsBytes.length).toBe(py.bytes_len);
  });

  test("ASCII-only claim still hashes identically (regression guard)", () => {
    const claim = { id: "c1", payload: { v: 1 } };
    const tsDigest = createHash("sha256")
      .update(canonicalJsonBytes(claim))
      .digest("hex");
    const py = pyJson<{ digest: string }>(`
import hashlib, json
from relay_verifier.canonical import jcs_canonicalize
obj = json.loads(${JSON.stringify(JSON.stringify(claim))})
print(json.dumps({"digest": hashlib.sha256(jcs_canonicalize(obj)).hexdigest()}))
`);
    expect(tsDigest).toBe(py.digest);
  });

  test("canonicalJsonBytes and jcsCanonicalize agree byte-for-byte", () => {
    const v = { z: 1, a: "hello", nested: { y: true, x: null } };
    const a = canonicalJsonBytes(v);
    const b = jcsCanonicalize(v);
    expect(a.length).toBe(b.length);
    for (let i = 0; i < a.length; i++) {
      expect(a[i]).toBe(b[i]);
    }
  });

  test("bundleDigest path agrees with canonicalJsonBytes path (BUG-C4)", () => {
    // Before C2, bundleDigest used jcsCanonicalize while
    // verifyDetachedClaimSignature used canonicalJsonBytes (ensure_ascii).
    // Post-fix both routes must produce the same sha256 for any value.
    const claim = { id: "c1", name: "señor" };
    const viaCanonical = createHash("sha256")
      .update(canonicalJsonBytes(claim))
      .digest("hex");
    const viaBundle = bundleDigest(claim, { stripSignatures: false });
    expect(viaCanonical).toBe(viaBundle);
  });
});

// ============================================================================
// BUG-C1: path-traversal screen fires BEFORE the artifact resolver
// ============================================================================

describe("BUG-C1 path-traversal hardening (parity with Python)", () => {
  test("checkArtifactPath rejects '../../etc/passwd' as relative_traversal", () => {
    const result = checkArtifactPath("../../etc/passwd");
    expect(result).not.toBeNull();
    expect(result?.code).toBe("RELAY-EVID-024");
    expect(result?.path_violation).toBe("relative_traversal");
  });

  test("checkArtifactPath rejects '/etc/passwd' as absolute_path", () => {
    const result = checkArtifactPath("/etc/passwd");
    expect(result).not.toBeNull();
    expect(result?.path_violation).toBe("absolute_path");
  });

  test("checkArtifactPath rejects Windows drive 'C:\\evil' as absolute_path", () => {
    const result = checkArtifactPath("C:\\evil");
    expect(result).not.toBeNull();
    expect(result?.path_violation).toBe("absolute_path");
  });

  test("checkArtifactPath rejects UNC '\\\\host\\share' as absolute_path", () => {
    const result = checkArtifactPath("\\\\host\\share");
    expect(result).not.toBeNull();
    expect(result?.path_violation).toBe("absolute_path");
  });

  test("checkArtifactPath rejects NFD-form name as non_nfc_name", () => {
    // U+0065 LATIN SMALL LETTER E + U+0301 COMBINING ACUTE ACCENT
    // (NFD form of é).
    const result = checkArtifactPath("café.txt");
    expect(result).not.toBeNull();
    expect(result?.path_violation).toBe("non_nfc_name");
  });

  test("checkArtifactPath rejects empty string", () => {
    const result = checkArtifactPath("");
    expect(result).not.toBeNull();
  });

  test("checkArtifactPath rejects NUL byte in path", () => {
    const result = checkArtifactPath("foo\0bar");
    expect(result).not.toBeNull();
    expect(result?.path_violation).toBe("invalid_utf8_name");
  });

  test("checkArtifactPath rejects > 1024-byte path", () => {
    const longPath = "a".repeat(1025);
    const result = checkArtifactPath(longPath);
    expect(result).not.toBeNull();
  });

  test("checkArtifactPath accepts a well-formed NFC path", () => {
    expect(checkArtifactPath("artifacts/test.log")).toBeNull();
    expect(checkArtifactPath("nested/dir/file.txt")).toBeNull();
    // Single dots inside a filename are fine.
    expect(checkArtifactPath("my.file.txt")).toBeNull();
    // ".." as a literal substring inside a segment (not standalone) is OK.
    expect(checkArtifactPath("my..file.txt")).toBeNull();
  });

  // Round-... re-hunt HIGH: the whitespace screen MUST match CPython
  // str.strip() EXACTLY, not JS String.trim(). Python strips the C0/C1
  // separators \x1c-\x1f and \x85 (NEL) that trim() does NOT, so a
  // control-char-bracketed artifact_id previously slipped the TS screen while
  // Python rejected it (a verdict split + path-screen weakening). And Python
  // does NOT strip ﻿ (which trim() does), so it must stay ACCEPTED.
  test("checkArtifactPath rejects C0/C1-separator-bracketed names (Python str.strip parity)", () => {
    for (const ws of ["\x1c", "\x1d", "\x1e", "\x1f", "\x85"]) {
      expect(checkArtifactPath(`${ws}foo.txt`)).not.toBeNull();
      expect(checkArtifactPath(`${ws}foo.txt`)?.path_violation).toBe("invalid_utf8_name");
      expect(checkArtifactPath(`foo.txt${ws}`)).not.toBeNull();
    }
    // Unicode whitespace Python AND trim both strip -> still rejected.
    for (const ws of ["\xa0", " ", "　"]) {
      expect(checkArtifactPath(`${ws}foo.txt`)).not.toBeNull();
    }
    // ﻿ (ZWNBSP) is NOT Python whitespace -> must be ACCEPTED (a leading
    // BOM is not NFC-changing/absolute/traversal), matching the Python verifier
    // -- using JS trim() here would have wrongly REJECTED it.
    expect(checkArtifactPath("﻿foo.txt")).toBeNull();
    // A newline INSIDE the name (not leading/trailing) is not stripped -> OK.
    expect(checkArtifactPath("a\nb.txt")).toBeNull();
  });

  test("validateBundle wires path screen BEFORE the resolver", () => {
    // A resolver that throws if it is ever called — the screen MUST
    // short-circuit before the resolver is touched.
    let resolverCalled = false;
    const trapResolver = (_artifactId: string): Uint8Array | null => {
      resolverCalled = true;
      throw new Error("resolver MUST NOT be invoked for screened paths");
    };
    const bundle = {
      schema_version: "relay.evidence_bundle.v1",
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
      claims: [
        {
          id: "c1",
          evidence_refs: [
            { artifact_id: "../../etc/passwd", digest: "deadbeef" },
          ],
        },
      ],
      // A placeholder signature is REQUIRED to reach the per-claim path screen:
      // that screen is gated on structure_ok in BOTH runtimes (TS
      // bundle_validator.ts; Python validate_bundle gates it on structure_ok),
      // and structure_ok requires a non-empty `signatures` array (verifier.py
      // sets it only after the signatures-present check). The entry need not
      // verify (structure_ok only requires presence; signatures_ok stays false).
      // Without it Python ALSO skips the screen, so an unsigned bundle here would
      // be a FALSE parity test (re-hunt verifier-structure-parity-1/-2).
      signatures: [
        {
          kid: "placeholder",
          alg: "EdDSA",
          signing_input_b64u: "eyJ4IjoxfQ",
          signature_b64u: "AA",
        },
      ],
    };
    const out = validateBundle({
      bundle,
      jwks: { keys: [] },
      options: { artifact_resolver: trapResolver },
    });
    expect(resolverCalled).toBe(false);
    const pathErr = out.errors.find(
      (e) =>
        e["code"] === RELAY_EVID_024_PATH && e["reason"] === "path_violation",
    );
    expect(pathErr).toBeDefined();
    expect(out.digest_ok).toBe(false);
    expect(out.overall).toBe("fail");
  });

  test("validateBundle still surfaces multiple path violations in a single pass", () => {
    let resolverCalled = false;
    const trapResolver = (_artifactId: string): Uint8Array | null => {
      resolverCalled = true;
      return null;
    };
    const bundle = {
      schema_version: "relay.evidence_bundle.v1",
      trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
      decided_at: "2026-05-15T12:00:00Z",
      claims: [
        {
          id: "c1",
          evidence_refs: [
            { artifact_id: "/etc/passwd", digest: "d1" },
            { artifact_id: "../escape", digest: "d2" },
          ],
        },
      ],
      // Placeholder signature so structure_ok=true and the per-claim path screen
      // runs (gated on structure_ok in both runtimes) -- see the note in the
      // preceding test. Without it, an unsigned bundle skips the screen in BOTH
      // Python and TS, making this a false parity test.
      signatures: [
        {
          kid: "placeholder",
          alg: "EdDSA",
          signing_input_b64u: "eyJ4IjoxfQ",
          signature_b64u: "AA",
        },
      ],
    };
    const out = validateBundle({
      bundle,
      jwks: { keys: [] },
      options: { artifact_resolver: trapResolver },
    });
    expect(resolverCalled).toBe(false);
    const pathErrs = out.errors.filter(
      (e) => e["reason"] === "path_violation",
    );
    expect(pathErrs.length).toBe(2);
  });
});

// ============================================================================
// BUG-C3: bundle signature wire shape uses `signing_input_b64u`
// ============================================================================

describe("BUG-C3 bundle signature wire field parity", () => {
  test("verifyBundleSignature accepts canonical `signing_input_b64u` and verifies under JWK", () => {
    // Generate an Ed25519 signed bundle via the Python local signer.
    const py = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(`
import json
from relay_verifier.local_signer import build_local_dev_bundle
b = build_local_dev_bundle(
    claims=[{"id": "c1", "payload": {"v": 1}}],
    signer_kid="local-dev-key-1",
    decided_at="2026-05-15T12:00:00Z",
    signed_at="2026-05-15T12:00:00Z",
)
print(json.dumps({"bundle": b.bundle, "jwks": b.jwks}))
`);
    const bundle = py.bundle;
    const jwks = py.jwks as unknown as {
      keys: Array<{ kid?: unknown; kty?: unknown; [k: string]: unknown }>;
    };
    // Sanity: the bundle's signatures[].* fields use signing_input_b64u
    // (NOT protected_b64u).
    const sigs = bundle["signatures"] as Array<Record<string, unknown>>;
    expect(Array.isArray(sigs)).toBe(true);
    expect(typeof sigs[0]?.["signing_input_b64u"]).toBe("string");

    // Recompute the expected canonical bytes (bundle minus signatures).
    const stripped: Record<string, unknown> = {};
    for (const k of Object.keys(bundle)) {
      if (k === "signatures") continue;
      stripped[k] = bundle[k];
    }
    const expectedCanonicalBytes = jcsCanonicalize(stripped);

    const check = verifyBundleSignature({
      signature: sigs[0] as Record<string, unknown>,
      expectedCanonicalBytes,
      jwks: jwks as unknown as { keys: Array<{ kid?: unknown }> },
      signatureIndex: 0,
    });
    expect(check.ok).toBe(true);
    expect(check.alg).toBe("EdDSA");
    expect(check.kid).toBe("local-dev-key-1");
  });

  test("validateBundle accepts a Python-signed local_dev bundle end-to-end (overall pass-or-explained-fail)", () => {
    const py = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(`
import json
from relay_verifier.local_signer import build_local_dev_bundle
b = build_local_dev_bundle(
    claims=[{"id": "c1", "payload": {"v": 1}}],
    signer_kid="local-dev-key-1",
    decided_at="2026-05-15T12:00:00Z",
    signed_at="2026-05-15T12:00:00Z",
)
print(json.dumps({"bundle": b.bundle, "jwks": b.jwks}))
`);
    const out = validateBundle({
      bundle: py.bundle,
      jwks: py.jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });
    // The local-dev bundle does not carry a TSA token; structure/digest
    // and signatures MUST verify clean even if overall=fail due to TSA.
    expect(out.signatures_ok).toBe(true);
    expect(out.digest_ok).toBe(true);
    expect(out.structure_ok).toBe(true);
    expect(out.signatures_checked.length).toBe(1);
    expect(out.signatures_checked[0]?.ok).toBe(true);
  });

  test("verifyBundleSignature REJECTS a legacy `protected_b64u`-only entry (Py<->TS parity)", () => {
    // Build a signed bundle on the Python side, then move the
    // signing_input_b64u value into the legacy protected_b64u field. The TS
    // verifier must NOT accept the legacy alias -- Python verify_bundle reads
    // only signing_input_b64u, so accepting it here was a verdict split. Both
    // runtimes now reject with `signature missing 'signing_input_b64u'`.
    const py = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(`
import json
from relay_verifier.local_signer import build_local_dev_bundle
b = build_local_dev_bundle(
    claims=[{"id": "c1", "payload": {"v": 1}}],
    signer_kid="local-dev-key-1",
)
print(json.dumps({"bundle": b.bundle, "jwks": b.jwks}))
`);
    const bundle = py.bundle;
    const sigs = bundle["signatures"] as Array<Record<string, unknown>>;
    // Move signing_input_b64u -> protected_b64u to simulate legacy fixture.
    const legacySig: Record<string, unknown> = { ...sigs[0] };
    legacySig["protected_b64u"] = legacySig["signing_input_b64u"];
    delete legacySig["signing_input_b64u"];

    const stripped: Record<string, unknown> = {};
    for (const k of Object.keys(bundle)) {
      if (k === "signatures") continue;
      stripped[k] = bundle[k];
    }
    const expectedCanonicalBytes = jcsCanonicalize(stripped);

    const check = verifyBundleSignature({
      signature: legacySig,
      expectedCanonicalBytes,
      jwks: py.jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });
    expect(check.ok).toBe(false);
    expect(check.reason).toBe("signature missing 'signing_input_b64u'");

    // Cross-check: the Python verifier rejects the SAME legacy-field bundle
    // with the identical reason (signatures_ok=False).
    const legacyBundle: Record<string, unknown> = { ...bundle, signatures: [legacySig] };
    const pyVerdict = pyJson<{ signatures_ok: boolean; reason: string }>(`
import json
from relay_verifier.verifier import verify_bundle
bundle = json.loads(${JSON.stringify(JSON.stringify(legacyBundle))})
jwks = json.loads(${JSON.stringify(JSON.stringify(py.jwks))})
res = verify_bundle(bundle, jwks)
reason = res.signature_checks[0].reason if res.signature_checks else ""
print(json.dumps({"signatures_ok": res.signatures_ok, "reason": reason}))
`);
    expect(pyVerdict.signatures_ok).toBe(false);
    expect(pyVerdict.reason).toBe("signature missing 'signing_input_b64u'");
  });

  test("verifyBundleSignature rejects signature missing both wire fields", () => {
    const check = verifyBundleSignature({
      signature: { kid: "k1", alg: "EdDSA", signature_b64u: "AAAA" },
      expectedCanonicalBytes: new Uint8Array([1, 2, 3]),
      jwks: { keys: [] } as unknown as { keys: Array<{ kid?: unknown }> },
    });
    expect(check.ok).toBe(false);
    expect(check.reason).toContain("signing_input_b64u");
  });

  test("verifyBundleSignature flags signing_input drift (recorded bytes != expected)", () => {
    const py = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(`
import json
from relay_verifier.local_signer import build_local_dev_bundle
b = build_local_dev_bundle(
    claims=[{"id": "c1", "payload": {"v": 1}}],
    signer_kid="local-dev-key-1",
)
print(json.dumps({"bundle": b.bundle, "jwks": b.jwks}))
`);
    const sigs = py.bundle["signatures"] as Array<Record<string, unknown>>;
    // Feed a DIFFERENT expected canonical -> drift.
    const expectedCanonicalBytes = jcsCanonicalize({ tampered: true });
    const check = verifyBundleSignature({
      signature: sigs[0] as Record<string, unknown>,
      expectedCanonicalBytes,
      jwks: py.jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });
    expect(check.ok).toBe(false);
    expect(check.reason).toContain("signing_input drift");
  });
});
