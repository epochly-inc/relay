// Parity 016 (F3): every public verifier signature entrypoint that
// canonicalises attacker-controllable signed-payload data fails closed
// IDENTICALLY across Python and TypeScript for BOTH cross-runtime
// canonicalisation hazards -- a supplementary-plane (non-BMP, >= U+10000)
// object KEY, and an out-of-safe-range integer VALUE (abs > 2**53 - 1).
//
// Before F3 the screens were wired into validate_bundle only;
// verify_detached_claim_signature / verifyDetachedClaimSignature and
// verify_multi_signatures / verifyMultiSignatures canonicalised their
// claim/payload with no screen, so a hazardous input raised uncaught (non-BMP)
// or produced Python-exact vs TS-rounded canonical bytes (unsafe integer) -- a
// cross-runtime verify split (keystone invariant #11/#16). F3 routes every
// entrypoint through the shared canonicalisability screen.
//
// This file drives the REAL Python implementation (subprocess) and the REAL
// TypeScript implementation over IDENTICAL inputs and asserts byte-identical
// fail-closed verdicts (ok / code / message) per entrypoint.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  verifyDetachedClaimSignature,
  verifyMultiSignatures,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

// {"alg":"EdDSA","kid":"k"} -- the screen fires BEFORE the protected header is
// decoded, so any well-formed string suffices.
const PROTECTED_B64U = "eyJhbGciOiJFZERTQSIsImtpZCI6ImsifQ";
const SIG_B64U = "AA";
const DUMMY_SIGS = [{ alg: "EdDSA", kid: "k", signature_b64u: "AA" }];

// U+1F600 supplementary-plane key, and 2**53 + 2 (exactly representable as a
// float64, so it round-trips through JSON.stringify -> Python json.loads
// unambiguously while still exceeding MAX_SAFE_INTEGER).
const NON_BMP_KEY = "a" + String.fromCodePoint(0x1f600);
const UNSAFE_INT = 9007199254740994;

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity016-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
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

interface PyCheck {
  ok: boolean;
  code: string;
  reason: string;
}

function pyDetached(claim: unknown): PyCheck {
  return pyJson<PyCheck>(`
import json, sys
from relay_verifier import verify_detached_claim_signature
claim = json.loads(${JSON.stringify(JSON.stringify(claim))})
c = verify_detached_claim_signature(
    protected_b64u=${JSON.stringify(PROTECTED_B64U)},
    signature_b64u=${JSON.stringify(SIG_B64U)},
    claim=claim,
    jwks={"keys": []},
)
sys.stdout.write(json.dumps({"ok": c.ok, "code": c.code, "reason": c.reason}))
`);
}

interface PyMulti {
  ok: boolean;
  aggregate: string;
  checks: PyCheck[];
}

function pyMulti(payload: unknown): PyMulti {
  return pyJson<PyMulti>(`
import json, sys
from relay_verifier import verify_multi_signatures
payload = json.loads(${JSON.stringify(JSON.stringify(payload))})
r = verify_multi_signatures(
    payload=payload,
    signatures=json.loads(${JSON.stringify(JSON.stringify(DUMMY_SIGS))}),
    jwks={"keys": []},
)
sys.stdout.write(json.dumps({
    "ok": r.ok,
    "aggregate": r.aggregate,
    "checks": [{"ok": c.ok, "code": c.code, "reason": c.reason} for c in r.signatures_checked],
}))
`);
}

describe("parity-016 verify_detached_claim_signature canon screen (Py<->TS)", () => {
  test("non-BMP key claim -> identical RELAY-CANON-NON-BMP-KEY fail-closed", () => {
    const claim = { [NON_BMP_KEY]: 1 };
    const py = pyDetached(claim);
    const ts = verifyDetachedClaimSignature({
      protectedB64u: PROTECTED_B64U,
      signatureB64u: SIG_B64U,
      claim,
      jwks: { keys: [] },
    });
    expect(py.ok).toBe(false);
    expect(ts.ok).toBe(false);
    expect(py.code).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(ts.code).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(ts.reason).toBe(py.reason); // byte-identical message
  });

  test("unsafe-integer claim -> identical RELAY-CANON-UNSAFE-INTEGER fail-closed", () => {
    const claim = { count: UNSAFE_INT };
    const py = pyDetached(claim);
    const ts = verifyDetachedClaimSignature({
      protectedB64u: PROTECTED_B64U,
      signatureB64u: SIG_B64U,
      claim,
      jwks: { keys: [] },
    });
    expect(py.ok).toBe(false);
    expect(ts.ok).toBe(false);
    expect(py.code).toBe("RELAY-CANON-UNSAFE-INTEGER");
    expect(ts.code).toBe("RELAY-CANON-UNSAFE-INTEGER");
    expect(ts.reason).toBe(py.reason);
  });
});

describe("parity-016 verify_multi_signatures canon screen (Py<->TS)", () => {
  test("non-BMP key payload -> identical RELAY-CANON-NON-BMP-KEY fail-closed", () => {
    const payload = { [NON_BMP_KEY]: 1 };
    const py = pyMulti(payload);
    const ts = verifyMultiSignatures({
      payload,
      signatures: DUMMY_SIGS,
      jwks: { keys: [] },
    });
    expect(py.ok).toBe(false);
    expect(ts.ok).toBe(false);
    expect(py.aggregate).toBe("all_invalid");
    expect(ts.aggregate).toBe("all_invalid");
    expect(ts.signaturesChecked.length).toBe(py.checks.length);
    expect(ts.signaturesChecked[0]!.code).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(py.checks[0]!.code).toBe("RELAY-CANON-NON-BMP-KEY");
    expect(ts.signaturesChecked[0]!.reason).toBe(py.checks[0]!.reason);
  });

  test("unsafe-integer payload -> identical RELAY-CANON-UNSAFE-INTEGER fail-closed", () => {
    const payload = { count: UNSAFE_INT };
    const py = pyMulti(payload);
    const ts = verifyMultiSignatures({
      payload,
      signatures: DUMMY_SIGS,
      jwks: { keys: [] },
    });
    expect(py.ok).toBe(false);
    expect(ts.ok).toBe(false);
    expect(py.aggregate).toBe("all_invalid");
    expect(ts.aggregate).toBe("all_invalid");
    expect(ts.signaturesChecked.length).toBe(py.checks.length);
    expect(ts.signaturesChecked[0]!.code).toBe("RELAY-CANON-UNSAFE-INTEGER");
    expect(py.checks[0]!.code).toBe("RELAY-CANON-UNSAFE-INTEGER");
    expect(ts.signaturesChecked[0]!.reason).toBe(py.checks[0]!.reason);
  });
});
