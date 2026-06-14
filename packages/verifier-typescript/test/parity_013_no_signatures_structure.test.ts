// VAL-PARITY-013: a NO-SIGNATURES bundle MUST produce a byte-identical
// validate_bundle output across the Python and TypeScript verifiers.
//
// Re-hunt verifier-structure-parity-1 / -2 (P1, keystone JCS-byte parity):
// Python `verify_bundle` returns EARLY for an absent/empty `signatures` array
// (verifier.py:362-365) -- BEFORE computing the bundle digest, structure_ok,
// digest_ok, or claims_count -- so all four stay at their defaults
// (structure_ok=false, digest_ok=false, claims_count=0, bundle_digest_sha256="").
// The TS `_verifyBundle` previously set all four BEFORE the signature gate, so a
// no-signatures bundle diverged Py<->TS on every one of those fields AND, because
// the per-claim namespace / manifest-binding / artifact-digest checks are gated
// on structure_ok, TS ran checks (e.g. claim_namespace_unknown) that Python
// skips -- a divergent structured-error set. This suite proves the two runtimes
// now agree on a no-signatures bundle (including one carrying an unknown
// namespace key, the exact finding-2 trigger).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { validateBundle } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity013-pyhelper-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
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

// A bundle with claims + a valid trust_anchor but NO `signatures` field, whose
// single claim carries an UNKNOWN namespace key (x-attacker) -- the exact
// finding-2 trigger. Returned by Python so both runtimes validate the identical
// wire object.
const PY_BUILD = `
import json
bundle = {
    "schema_version": "relay.evidence.bundle.v1",
    "claims": [{"id": "c1", "namespaces": {"x-attacker": {"foo": 1}}}],
    "trust_anchor": "https://relay.epochly.com/.well-known/jwks.json",
    "decided_at": "2026-05-15T12:00:00Z",
}
print(json.dumps({"bundle": bundle}))
`;

const PY_VALIDATE = (bundleJson: string): string => `
import json, sys
from relay_verifier.bundle_validator import validate_bundle
bundle = json.loads(${JSON.stringify(bundleJson)})
out = validate_bundle(bundle=bundle, jwks={"keys": []})
sys.stdout.write(json.dumps({
    "overall": out["overall"],
    "structure_ok": out["structure_ok"],
    "digest_ok": out["digest_ok"],
    "signatures_ok": out["signatures_ok"],
    "claims_count": out["claims_count"],
    "bundle_digest_sha256": out["bundle_digest_sha256"],
    "reasons": sorted(e.get("reason", "") for e in out["errors"]),
}))
`;

interface ValidateSnapshot {
  overall: string;
  structure_ok: boolean;
  digest_ok: boolean;
  signatures_ok: boolean;
  claims_count: number;
  bundle_digest_sha256: string;
  reasons: string[];
}

function tsSnapshot(bundle: Record<string, unknown>): ValidateSnapshot {
  const out = validateBundle({ bundle, jwks: { keys: [] } });
  return {
    overall: out.overall,
    structure_ok: out.structure_ok,
    digest_ok: out.digest_ok,
    signatures_ok: out.signatures_ok,
    claims_count: out.claims_count,
    bundle_digest_sha256: out.bundle_digest_sha256,
    reasons: [...out.errors.map((e) => String((e as { reason?: unknown }).reason ?? ""))].sort(),
  };
}

describe("VAL-PARITY-013 no-signatures bundle structure parity", () => {
  test("TS no-signatures output matches Python defaults (structure_ok=false, digest_ok=false, claims_count=0, digest='')", () => {
    const { bundle } = pyJson<{ bundle: Record<string, unknown> }>(PY_BUILD);

    const ts = tsSnapshot(bundle);
    // The four fields Python leaves at their defaults for a no-signatures bundle.
    expect(ts.structure_ok).toBe(false);
    expect(ts.digest_ok).toBe(false);
    expect(ts.signatures_ok).toBe(false);
    expect(ts.claims_count).toBe(0);
    expect(ts.bundle_digest_sha256).toBe("");
    // structure_ok is false, so the per-claim namespace gate MUST NOT run: the
    // unknown-namespace key must NOT appear as an error (finding-2).
    expect(ts.reasons).not.toContain("claim_namespace_unknown");
  });

  test("Python and TypeScript agree field-for-field on the no-signatures bundle", () => {
    const { bundle } = pyJson<{ bundle: Record<string, unknown> }>(PY_BUILD);
    const py = pyJson<ValidateSnapshot>(PY_VALIDATE(JSON.stringify(bundle)));
    const ts = tsSnapshot(bundle);

    expect(ts.structure_ok).toBe(py.structure_ok);
    expect(ts.digest_ok).toBe(py.digest_ok);
    expect(ts.signatures_ok).toBe(py.signatures_ok);
    expect(ts.claims_count).toBe(py.claims_count);
    expect(ts.bundle_digest_sha256).toBe(py.bundle_digest_sha256);
    expect(ts.overall).toBe(py.overall);
    // Same structured-error reason set (the finding-2 divergence: TS must not
    // carry claim_namespace_unknown that Python skips).
    expect(ts.reasons).toEqual(py.reasons);
  });

  // roborev 8b805fc: a no-signatures bundle whose `claims` is ALSO missing /
  // non-array must STILL return the all-default result (digest=""), matching
  // Python which returns before computing the digest. The digest-then-claims
  // order left bundle_digest_sha256 populated on this path.
  test("no-signatures bundle with non-array/missing claims returns all-default (digest empty)", () => {
    const bundles: Array<Record<string, unknown>> = [
      {
        schema_version: "relay.evidence.bundle.v1",
        claims: "not-an-array",
        trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
        decided_at: "2026-05-15T12:00:00Z",
      },
      {
        schema_version: "relay.evidence.bundle.v1",
        // claims entirely absent
        trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
        decided_at: "2026-05-15T12:00:00Z",
      },
      {
        schema_version: "relay.evidence.bundle.v1",
        claims: { not: "an array" },
        trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
        decided_at: "2026-05-15T12:00:00Z",
      },
    ];
    for (const bundle of bundles) {
      const ts = tsSnapshot(bundle);
      expect(ts.structure_ok).toBe(false);
      expect(ts.digest_ok).toBe(false);
      expect(ts.signatures_ok).toBe(false);
      expect(ts.claims_count).toBe(0);
      expect(ts.bundle_digest_sha256).toBe("");
      // And field-for-field with Python on the same wire object.
      const py = pyJson<ValidateSnapshot>(PY_VALIDATE(JSON.stringify(bundle)));
      expect(ts.bundle_digest_sha256).toBe(py.bundle_digest_sha256);
      expect(ts.structure_ok).toBe(py.structure_ok);
      expect(ts.claims_count).toBe(py.claims_count);
    }
  });
});
