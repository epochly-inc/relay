// VAL-PARITY-003: validateBundle must enforce the evidence-ref manifest-binding
// rule (spec K line 4428 / VAL-V3M1-019).
//
// Bug: Python `validate_bundle` rejects a bundle whose claim
// `evidence_refs[].digest` is absent from the bundle's declared `manifest`
// digest set (reason `evidence_ref_artifact_missing_from_manifest`,
// code RELAY-EVID-014, overall='fail'). The TypeScript `validateBundle`
// was MISSING this gate, so TS accepted a bundle Python rejected.
//
// This suite builds a REAL Ed25519-signed bundle (so `structure_ok` is true
// on BOTH runtimes -- Python only sets structure_ok when a non-empty
// signatures array is present) and asserts:
//   1. negative case: a claim digest absent from the manifest is rejected by
//      TS with RELAY-EVID-014 + overall='fail' (RED before the fix), and
//      Python rejects the SAME bundle the SAME way (cross-language parity).
//   2. positive control: a claim digest PRESENT in the manifest produces no
//      manifest-binding error on either runtime (parity on accept).
//
// The bundle is constructed + signed entirely on the Python side via the
// verifier package's own signer so the JWS verifies clean; the same
// {bundle, jwks} object is then handed to the TS verifier.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import { RELAY_EVID_014, validateBundle } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity003-pyhelper-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
  );
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 60_000,
    });
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status ?? -1 };
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

function pyJson<T = unknown>(code: string): T {
  const r = runPython(code);
  if (r.status !== 0) {
    throw new Error(`python helper failed (status=${r.status}): ${r.stderr}`);
  }
  const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(line) as T;
}

// Builds + signs a bundle on the Python side. `manifestDigest` is the single
// digest declared in the bundle's top-level `manifest`; `refDigest` is the
// digest carried by the claim's evidence_refs[0]. When refDigest !=
// manifestDigest the manifest-binding gate MUST fire.
const PY_BUILD = (manifestDigest: string, refDigest: string): string => `
import json, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_verifier.verifier import (
    jwk_from_ed25519_public_key,
    sign_payload_ed25519,
    canonical_json_bytes,
)
from relay_verifier.merkle import compute_merkle_root
from relay_verifier.canonical import bundle_digest

# Deterministic key (test-only seed).
seed = bytes(range(32))
sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
jwk = jwk_from_ed25519_public_key(
    sk.public_key(),
    kid="parity-003-key",
    not_before="2026-01-01T00:00:00Z",
    not_after="2028-01-01T00:00:00Z",
)
jwks = {"keys": [jwk]}

claims = [
    {
        "claim_id": "c1",
        "kind": "command_evidence",
        "evidence_refs": [{"artifact_id": "a1", "digest": ${JSON.stringify(refDigest)}}],
    }
]
core = {
    "schema_version": "relay.evidence_bundle.v1",
    "evidence_bundle_id": "bundle-parity-003",
    "trust_anchor": "local_dev",
    "decided_at": "2026-05-15T12:00:00Z",
    "signed_at": "2026-05-15T12:00:00Z",
    "manifest": [{"digest": ${JSON.stringify(manifestDigest)}}],
    "claims": claims,
    "merkle_root_hex": compute_merkle_root([bundle_digest(c) for c in claims]),
}
sig = sign_payload_ed25519(core, sk, kid="parity-003-key")
bundle = dict(core)
bundle["signatures"] = [sig]
print(json.dumps({"bundle": bundle, "jwks": jwks}))
`;

const PY_VALIDATE = (bundleJson: string, jwksJson: string): string => `
import json, sys
from relay_verifier.bundle_validator import validate_bundle
bundle = json.loads(${JSON.stringify(bundleJson)})
jwks = json.loads(${JSON.stringify(jwksJson)})
out = validate_bundle(bundle=bundle, jwks=jwks)
sys.stdout.write(json.dumps({
    "overall": out["overall"],
    "structure_ok": out["structure_ok"],
    "reasons": sorted(e.get("reason", "") for e in out["errors"]),
    "codes": sorted({e.get("code", "") for e in out["errors"]}),
}))
`;

const MANIFEST_DIGEST = "aa".repeat(32);
const ABSENT_DIGEST = "bb".repeat(32);

describe("VAL-PARITY-003 evidence-ref manifest-binding parity", () => {
  test("TS rejects a claim digest absent from the manifest with RELAY-EVID-014 (RED before fix)", () => {
    const { bundle, jwks } = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(PY_BUILD(MANIFEST_DIGEST, ABSENT_DIGEST));

    const out = validateBundle({
      bundle,
      jwks: jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });

    // Sanity: the bundle is structurally valid + signature verifies, so we
    // actually reach the manifest-binding gate (it runs under structure_ok).
    expect(out.structure_ok).toBe(true);
    expect(out.signatures_ok).toBe(true);

    const reasons = new Set(out.errors.map((e) => String(e["reason"])));
    const codes = new Set(out.errors.map((e) => String(e["code"] ?? "")));
    expect(reasons.has("evidence_ref_artifact_missing_from_manifest")).toBe(true);
    expect(codes.has(RELAY_EVID_014)).toBe(true);
    expect(out.overall).toBe("fail");
  });

  test("Python and TypeScript AGREE (both reject) on the absent-digest bundle", () => {
    const { bundle, jwks } = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(PY_BUILD(MANIFEST_DIGEST, ABSENT_DIGEST));

    const tsOut = validateBundle({
      bundle,
      jwks: jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });

    const py = pyJson<{
      overall: string;
      structure_ok: boolean;
      reasons: string[];
      codes: string[];
    }>(PY_VALIDATE(JSON.stringify(bundle), JSON.stringify(jwks)));

    // Both runtimes must reach the gate (structure_ok) and both must reject.
    expect(py.structure_ok).toBe(true);
    expect(tsOut.structure_ok).toBe(true);
    expect(py.overall).toBe("fail");
    expect(tsOut.overall).toBe("fail");

    // Both must emit the SAME manifest-binding reason + code.
    expect(py.reasons).toContain("evidence_ref_artifact_missing_from_manifest");
    expect(new Set(tsOut.errors.map((e) => String(e["reason"])))).toContain(
      "evidence_ref_artifact_missing_from_manifest",
    );
    expect(py.codes).toContain(RELAY_EVID_014);
    expect(new Set(tsOut.errors.map((e) => String(e["code"] ?? "")))).toContain(RELAY_EVID_014);
  });

  test("positive control: a claim digest PRESENT in the manifest produces no binding error (Py<->TS agree)", () => {
    const { bundle, jwks } = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(PY_BUILD(MANIFEST_DIGEST, MANIFEST_DIGEST));

    const tsOut = validateBundle({
      bundle,
      jwks: jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });
    const py = pyJson<{
      overall: string;
      structure_ok: boolean;
      reasons: string[];
      codes: string[];
    }>(PY_VALIDATE(JSON.stringify(bundle), JSON.stringify(jwks)));

    const tsReasons = new Set(tsOut.errors.map((e) => String(e["reason"])));
    expect(tsReasons.has("evidence_ref_artifact_missing_from_manifest")).toBe(false);
    expect(py.reasons).not.toContain("evidence_ref_artifact_missing_from_manifest");
  });
});
