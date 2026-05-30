// VAL-PARITY-008: validateBundle must enforce the namespace closed-set check
// (VAL-V3M1-022 / code RELAY-EVID-NAMESPACE-UNKNOWN).
//
// Bug: Python `validate_bundle` restricts each claim's `namespaces` field to
// the closed set {x-relay}; any other top-level key (e.g. `x-attacker`) is
// rejected with reason `claim_namespace_unknown`, code
// RELAY-EVID-NAMESPACE-UNKNOWN, overall='fail' (bundle_validator.py:749-767,
// _ALLOWED_NAMESPACE_KEYS at line 204). The TypeScript `validateBundle`
// implemented NO namespace check and did not define the code, so TS ACCEPTED a
// bundle Python rejects.
//
// This suite builds a REAL Ed25519-signed bundle (so `structure_ok` is true on
// BOTH runtimes -- Python only sets structure_ok when a non-empty signatures
// array verifies) and asserts:
//   1. negative case: a claim carrying namespaces:{'x-attacker':{}} is rejected
//      by TS with RELAY-EVID-NAMESPACE-UNKNOWN + overall='fail' (RED before the
//      fix), and Python rejects the SAME bundle the SAME way (cross-language
//      parity).
//   2. positive control: a claim with the allowed namespaces:{'x-relay':{}}
//      produces no namespace error on either runtime (parity on accept).
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

import { RELAY_EVID_NAMESPACE_UNKNOWN, validateBundle } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity008-pyhelper-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
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

// Builds + signs a bundle on the Python side. `namespaceKey` is the single
// top-level key declared in the claim's `namespaces` dict. When namespaceKey is
// outside the closed set {x-relay} the namespace gate MUST fire on both
// runtimes; when it is "x-relay" the gate stays silent.
const PY_BUILD = (namespaceKey: string): string => `
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_verifier.verifier import (
    jwk_from_ed25519_public_key,
    sign_payload_ed25519,
)
from relay_verifier.merkle import compute_merkle_root
from relay_verifier.canonical import bundle_digest

# Deterministic key (test-only seed).
seed = bytes(range(32))
sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
jwk = jwk_from_ed25519_public_key(
    sk.public_key(),
    kid="parity-008-key",
    not_before="2026-01-01T00:00:00Z",
    not_after="2028-01-01T00:00:00Z",
)
jwks = {"keys": [jwk]}

claims = [
    {
        "claim_id": "c1",
        "kind": "command_evidence",
        "namespaces": {${JSON.stringify(namespaceKey)}: {}},
    }
]
core = {
    "schema_version": "relay.evidence_bundle.v1",
    "evidence_bundle_id": "bundle-parity-008",
    "trust_anchor": "local_dev",
    "decided_at": "2026-05-15T12:00:00Z",
    "signed_at": "2026-05-15T12:00:00Z",
    "claims": claims,
    "merkle_root_hex": compute_merkle_root([bundle_digest(c) for c in claims]),
}
sig = sign_payload_ed25519(core, sk, kid="parity-008-key")
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

const ALLOWED_NAMESPACE = "x-relay";
const UNKNOWN_NAMESPACE = "x-attacker";

describe("VAL-PARITY-008 namespace closed-set parity", () => {
  test("TS rejects a claim with an unknown namespace key (RELAY-EVID-NAMESPACE-UNKNOWN, RED before fix)", () => {
    const { bundle, jwks } = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(PY_BUILD(UNKNOWN_NAMESPACE));

    const out = validateBundle({
      bundle,
      jwks: jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });

    // Sanity: the bundle is structurally valid + signature verifies, so we
    // actually reach the namespace gate (it runs under structure_ok).
    expect(out.structure_ok).toBe(true);
    expect(out.signatures_ok).toBe(true);

    const reasons = new Set(out.errors.map((e) => String(e["reason"])));
    const codes = new Set(out.errors.map((e) => String(e["code"] ?? "")));
    expect(reasons.has("claim_namespace_unknown")).toBe(true);
    expect(codes.has(RELAY_EVID_NAMESPACE_UNKNOWN)).toBe(true);
    expect(out.overall).toBe("fail");
  });

  test("Python and TypeScript AGREE (both reject) on the unknown-namespace bundle", () => {
    const { bundle, jwks } = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(PY_BUILD(UNKNOWN_NAMESPACE));

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

    // Both must emit the SAME namespace reason + code.
    expect(py.reasons).toContain("claim_namespace_unknown");
    expect(new Set(tsOut.errors.map((e) => String(e["reason"])))).toContain(
      "claim_namespace_unknown",
    );
    expect(py.codes).toContain(RELAY_EVID_NAMESPACE_UNKNOWN);
    expect(new Set(tsOut.errors.map((e) => String(e["code"] ?? "")))).toContain(
      RELAY_EVID_NAMESPACE_UNKNOWN,
    );
  });

  test("positive control: a claim with the allowed x-relay namespace produces no namespace error (Py<->TS agree)", () => {
    const { bundle, jwks } = pyJson<{
      bundle: Record<string, unknown>;
      jwks: { keys: Array<Record<string, unknown>> };
    }>(PY_BUILD(ALLOWED_NAMESPACE));

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
    const tsCodes = new Set(tsOut.errors.map((e) => String(e["code"] ?? "")));
    expect(tsReasons.has("claim_namespace_unknown")).toBe(false);
    expect(tsCodes.has(RELAY_EVID_NAMESPACE_UNKNOWN)).toBe(false);
    expect(py.reasons).not.toContain("claim_namespace_unknown");
    expect(py.codes).not.toContain(RELAY_EVID_NAMESPACE_UNKNOWN);
  });
});
