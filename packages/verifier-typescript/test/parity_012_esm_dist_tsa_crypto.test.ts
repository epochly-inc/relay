// REGRESSION (codex-review crypto P1, "ESM-require-crash"): the published
// package builds to ESM (package.json `"type": "module"`, exports
// `import: ./dist/index.js`). A `require("node:crypto").createHash(...)` call
// on the real-TSA-roots crypto path (src/tsa.ts) is `undefined` in ESM, so the
// BUILT artifact threw `ReferenceError: require is not defined` BEFORE it could
// emit a fail-closed `tsa_check` envelope -- the offline verifier CRASHED
// instead of failing closed (keystone-#8/#11 violation: the trust root MUST
// fail closed, never crash-open).
//
// IMPORTANT: this regression CANNOT be caught by importing the dist from inside
// the vitest worker -- vitest's module environment provides a `require` shim
// even for ESM `dist/*.js`, so the broken `require(...)` silently resolves
// there (this is exactly why the pre-existing TSA crypto tests passed against
// the broken artifact). To exercise the REAL ESM runtime we spawn a separate
// plain `node` process that imports the BUILT `dist/index.js` and drives it
// down the TSA crypto path. A `require is not defined` ReferenceError makes
// that child process exit non-zero with the error on stderr.
//
// The fixture is built by the Python builder (conftest_w10_4.py) using an
// EPHEMERAL in-process TSA key (no committed key material), mirroring
// v3m5_tsa_crypto.test.ts.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");
const DIST_INDEX = resolve(PKG_ROOT, "dist", "index.js");
const DIST_URL = pathToFileURL(DIST_INDEX).href;

// ---------------------------------------------------------------------------
// Ensure the dist is built. The validate flow runs `npm run build` first; this
// keeps the test self-contained when run in isolation.
// ---------------------------------------------------------------------------

beforeAll(() => {
  if (!existsSync(DIST_INDEX)) {
    const b = spawnSync("npm", ["run", "build"], {
      cwd: PKG_ROOT,
      encoding: "utf-8",
      timeout: 300_000,
    });
    if (b.status !== 0) {
      throw new Error(`npm run build failed (status=${b.status}): ${b.stderr}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Python fixture builder bridge (ephemeral in-process TSA chain).
// ---------------------------------------------------------------------------

interface BuiltFixture {
  token: Record<string, unknown>;
  bundle_digest_hex: string;
  decided_at: string;
  tsa_root_pem: string;
}

const DECIDED_AT = "2026-05-15T12:34:56Z";

function buildFixture(opts: { bundleDigestHex?: string } = {}): BuiltFixture {
  const decidedAt = DECIDED_AT;
  const digestHex = opts.bundleDigestHex ?? "0".repeat(64);
  const code = `import datetime, json, sys
sys.path.insert(0, ${JSON.stringify(resolve(REPO_ROOT, "packages", "verifier", "tests"))})
from conftest_w10_4 import _make_test_tsa_chain, _build_tsa_token
from cryptography.hazmat.primitives import serialization

decided_at = ${JSON.stringify(decidedAt)}
digest_hex = ${JSON.stringify(digestHex)}
dt = datetime.datetime.fromisoformat(decided_at[:-1] + "+00:00")
gen_time = dt.astimezone(datetime.UTC).isoformat().replace("+00:00", "Z")
leaf_sk, leaf_cert, root_cert = _make_test_tsa_chain()
token = _build_tsa_token(bundle_digest_hex=digest_hex, gen_time=gen_time, leaf_sk=leaf_sk, leaf_cert=leaf_cert)
root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
sys.stdout.write(json.dumps({
    "token": token,
    "bundle_digest_hex": digest_hex,
    "decided_at": decided_at,
    "tsa_root_pem": root_pem,
}))
`;
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity012-tsa-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
  );
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 120_000,
    });
    if (r.status !== 0) {
      throw new Error(`fixture builder failed (status=${r.status}): ${r.stderr}`);
    }
    const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
    return JSON.parse(line) as BuiltFixture;
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

// ---------------------------------------------------------------------------
// Run the BUILT ESM dist under a fresh plain `node` process (the real ESM
// runtime, no vitest require-shim) and return parsed JSON {ok, ...}.
// ---------------------------------------------------------------------------

interface ChildResult {
  status: number | null;
  stdout: string;
  stderr: string;
  parsed: Record<string, unknown> | null;
}

function runInPlainNode(driverSource: string, fixture: BuiltFixture): ChildResult {
  const driverFile = resolve(
    tmpdir(),
    `relay-parity012-driver-${process.pid}-${Math.random().toString(36).slice(2)}.mjs`,
  );
  const fixtureFile = resolve(
    tmpdir(),
    `relay-parity012-fx-${process.pid}-${Math.random().toString(36).slice(2)}.json`,
  );
  writeFileSync(fixtureFile, JSON.stringify(fixture), "utf-8");
  writeFileSync(driverFile, driverSource, "utf-8");
  try {
    const r = spawnSync(process.execPath, [driverFile, fixtureFile], {
      encoding: "utf-8",
      timeout: 120_000,
    });
    let parsed: Record<string, unknown> | null = null;
    const lastLine = (r.stdout ?? "").trim().split(/\r?\n/).pop() ?? "";
    try {
      parsed = lastLine ? (JSON.parse(lastLine) as Record<string, unknown>) : null;
    } catch {
      parsed = null;
    }
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", parsed };
  } finally {
    rmSync(driverFile, { force: true });
    rmSync(fixtureFile, { force: true });
  }
}

const VALIDATE_TSA_DRIVER = `
import { readFileSync } from "node:fs";
import { validateTsaToken } from ${JSON.stringify(DIST_URL)};
const fx = JSON.parse(readFileSync(process.argv[2], "utf-8"));
try {
  const r = validateTsaToken({
    token: fx.token,
    bundleDigestHex: fx.bundle_digest_hex,
    decidedAt: fx.decided_at,
    chainCerts: null,
    extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
  });
  process.stdout.write(JSON.stringify({ ok: true, outcome: r.outcome, reason: r.reason }));
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, name: e && e.constructor ? e.constructor.name : "Error", message: String(e && e.message) }));
  process.exitCode = 7;
}
`;

// The bundle whose validateBundle path we exercise. Its binding digest
// (sha256 of the verifier-canonical JSON minus signatures/tsa_token/
// log_inclusion_proof) is what the TSA message_imprint must equal for the
// crypto path (and the broken require call) to be reached.
const BUNDLE_FOR_TSA = {
  trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
  decided_at: DECIDED_AT,
};

// Compute the bundle binding digest in plain node using the SAME exported
// canonicalizer the validator uses (canonicalJsonBytes), so the minted token's
// message_imprint matches and validateBundle reaches the TSA crypto path
// (line ~378 -- the broken require). Printed as the last stdout line.
const BINDING_DIGEST_DRIVER = `
import { createHash } from "node:crypto";
import { canonicalJsonBytes } from ${JSON.stringify(DIST_URL)};
const bundle = ${JSON.stringify(BUNDLE_FOR_TSA)};
const stripped = {};
for (const k of Object.keys(bundle)) {
  if (k === "signatures" || k === "tsa_token" || k === "log_inclusion_proof") continue;
  stripped[k] = bundle[k];
}
const hex = createHash("sha256").update(canonicalJsonBytes(stripped)).digest("hex");
process.stdout.write(JSON.stringify({ ok: true, binding_digest_hex: hex }));
`;

const VALIDATE_BUNDLE_DRIVER = `
import { readFileSync } from "node:fs";
import { validateBundle } from ${JSON.stringify(DIST_URL)};
const fx = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const bundle = {
  trust_anchor: "https://relay.epochly.com/.well-known/jwks.json",
  decided_at: fx.decided_at,
  tsa_token: fx.token,
};
try {
  const out = validateBundle({
    bundle,
    jwks: { keys: [] },
    options: { tsa_skip_bundled_chain: true, tsa_extra_trusted_roots_pem: Buffer.from(fx.tsa_root_pem, "utf-8") },
  });
  process.stdout.write(JSON.stringify({ ok: true, tsa_check: out.tsa_check }));
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, name: e && e.constructor ? e.constructor.name : "Error", message: String(e && e.message) }));
  process.exitCode = 7;
}
`;

// ===========================================================================
// Built ESM artifact MUST NOT crash on the real-TSA-roots crypto path.
// ===========================================================================

describe("ESM dist TSA crypto path does not ReferenceError under plain node", () => {
  test("validateTsaToken on built ESM dist (plain node) returns outcome=ok, no ReferenceError", () => {
    const fx = buildFixture();
    const child = runInPlainNode(VALIDATE_TSA_DRIVER, fx);
    // A crash (e.g. `ReferenceError: require is not defined`) makes the child
    // exit non-zero and prints to stderr. Surface it for a clear failure.
    expect(
      child.stderr.includes("require is not defined"),
      `child stderr: ${child.stderr}`,
    ).toBe(false);
    expect(child.parsed, `child stdout: ${child.stdout}; stderr: ${child.stderr}`).not.toBeNull();
    expect(child.parsed?.["ok"]).toBe(true);
    expect(child.parsed?.["outcome"]).toBe("ok");
    expect(child.status).toBe(0);
  });

  test("validateBundle on built ESM dist (plain node) reaches the TSA crypto path -> tsa_check=ok, no crash", () => {
    // Compute the bundle's binding digest with the SAME exported canonicalizer
    // the validator uses, then mint the TSA token over THAT digest so
    // validateBundle's message_imprint check passes and the crypto path
    // (line ~378, the broken require) is actually reached. Without this the
    // path short-circuits at message_imprint_mismatch and never hits the bug.
    const digestChild = spawnSync(process.execPath, ["--input-type=module", "-e", BINDING_DIGEST_DRIVER], {
      encoding: "utf-8",
      timeout: 120_000,
    });
    const digestLine = (digestChild.stdout ?? "").trim().split(/\r?\n/).pop() ?? "";
    const digestParsed = digestLine ? (JSON.parse(digestLine) as Record<string, unknown>) : null;
    expect(
      digestParsed?.["ok"],
      `binding-digest child stdout: ${digestChild.stdout}; stderr: ${digestChild.stderr}`,
    ).toBe(true);
    const bindingDigestHex = String(digestParsed?.["binding_digest_hex"]);
    expect(bindingDigestHex).toMatch(/^[0-9a-f]{64}$/);

    const fx = buildFixture({ bundleDigestHex: bindingDigestHex });
    const child = runInPlainNode(VALIDATE_BUNDLE_DRIVER, fx);
    expect(
      child.stderr.includes("require is not defined"),
      `child stderr: ${child.stderr}`,
    ).toBe(false);
    expect(child.parsed, `child stdout: ${child.stdout}; stderr: ${child.stderr}`).not.toBeNull();
    expect(child.parsed?.["ok"]).toBe(true);
    // outcome=ok proves the crypto path (incl. line ~378) ran to completion
    // without crashing -- a fail-CLOSED structured envelope, not a crash.
    expect(child.parsed?.["tsa_check"]).toBe("ok");
    expect(child.status).toBe(0);
  });
});
