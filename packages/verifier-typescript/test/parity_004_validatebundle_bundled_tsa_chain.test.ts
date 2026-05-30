// VAL-PARITY-004: validateBundle must load the bundled TSA chain (and honor
// the tsa_extra_trusted_roots_pem / tsa_skip_bundled_chain options) so a
// TSA-bearing bundle verifies its CMS SignerInfo signature against a trusted
// root -- exactly as Python `validate_bundle` does.
//
// Bug: Python `validate_bundle` loads the wheel-bundled TSA chain via
// load_bundled_tsa_chain() and passes it (plus any caller-supplied
// tsa_extra_trusted_roots_pem) as chain_certs to validate_tsa_token
// (bundle_validator.py:844-856), so the CMS SignerInfo signature verifies
// against a trusted root and tsa_check='ok'. The TS `validateBundle` called
// validateTsaToken with chainCerts:null and had NO tsa_extra_trusted_roots_pem
// option on ValidateBundleOptions, so EVERY bundle carrying a real
// `tsa_token` (tsr_der_b64u) resolved to tsa_check='invalid' (reason
// 'tsa_cert_chain_unknown_root') and overall='fail'. DIVERGENCE: for a bundle
// with `decided_at` + a valid `tsa_token`, TS failed where Python passed.
//
// This suite mirrors the Python parity test
// `test_validate_bundle_passes_extra_trusted_roots_through`
// (packages/verifier/tests/test_w9_tsa_verifier.py:546): a bundle built with
// the ephemeral test TSA root passes overall when the validator is given that
// root via tsa_extra_trusted_roots_pem; the same bundle fails without it
// (the ephemeral root is not in the wheel-bundled placeholder chain).
//
// The full signed bundle + matching JWKS + ephemeral TSA root PEM are
// constructed entirely on the Python side via the verifier package's own
// build_bundle() fixture (so the JWS, TSA token, and log-inclusion proof all
// verify clean); the identical {bundle, jwks, tsa_root_pem} object is then
// handed to the TS verifier. The Python validate_bundle is also invoked on the
// SAME bundle to prove cross-runtime tsa_check agreement.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import { validateBundle } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity004-pyhelper-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
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
    throw new Error(`python helper failed (status=${r.status}): ${r.stderr}`);
  }
  const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(line) as T;
}

interface BuiltBundleFixture {
  bundle: Record<string, unknown>;
  jwks: { keys: Array<Record<string, unknown>> };
  tsa_root_pem: string;
}

// Build a fully-signed bundle (JWS + valid RFC 3161 TSA token over the binding
// digest + log-inclusion proof) on the Python side via the verifier package's
// own build_bundle() fixture, and emit it as JSON together with the ephemeral
// TSA root PEM the validator must anchor against.
const PY_BUILD = (): string => `
import json, sys
sys.path.insert(0, ${JSON.stringify(resolve(REPO_ROOT, "packages", "verifier", "tests"))})
from conftest_w10_4 import build_bundle

built = build_bundle()
sys.stdout.write(json.dumps({
    "bundle": built.bundle,
    "jwks": built.jwks,
    "tsa_root_pem": built.tsa_extra_roots_pem.decode("ascii"),
}))
`;

// Run Python validate_bundle on the SAME bundle, with/without the extra root,
// and emit the tsa_check + overall so we can assert cross-runtime parity.
const PY_VALIDATE = (
  bundleJson: string,
  jwksJson: string,
  tsaRootPem: string,
): string => `
import json, sys
from relay_verifier.bundle_validator import validate_bundle, ValidateBundleOptions
bundle = json.loads(${JSON.stringify(bundleJson)})
jwks = json.loads(${JSON.stringify(jwksJson)})
root_pem = ${JSON.stringify(tsaRootPem)}.encode("ascii")

out_ok = validate_bundle(
    bundle=bundle,
    jwks=jwks,
    options=ValidateBundleOptions(tsa_extra_trusted_roots_pem=root_pem),
)
out_bad = validate_bundle(bundle=bundle, jwks=jwks)
sys.stdout.write(json.dumps({
    "with_root": {"overall": out_ok["overall"], "tsa_check": out_ok["tsa_check"]},
    "without_root": {"overall": out_bad["overall"], "tsa_check": out_bad["tsa_check"]},
}))
`;

describe("VAL-PARITY-004 validateBundle bundled-TSA-chain parity", () => {
  test("TS validateBundle yields tsa_check='ok' with tsa_extra_trusted_roots_pem (RED before fix)", () => {
    const fx = pyJson<BuiltBundleFixture>(PY_BUILD());

    const out = validateBundle({
      bundle: fx.bundle,
      jwks: fx.jwks as unknown as { keys: Array<{ kid?: unknown }> },
      options: {
        tsa_extra_trusted_roots_pem: Buffer.from(fx.tsa_root_pem, "utf-8"),
      },
    });

    // Sanity: the bundle is structurally valid + signature verifies, so we
    // actually reach the TSA gate (it runs after the structure/signature
    // checks have populated bindingDigestHex).
    expect(out.structure_ok).toBe(true);
    expect(out.signatures_ok).toBe(true);
    expect(out.tsa_check).toBe("ok");
    expect(out.overall).toBe("pass");
  });

  test("TS validateBundle rejects the same bundle WITHOUT the extra root (unknown TSA root)", () => {
    const fx = pyJson<BuiltBundleFixture>(PY_BUILD());

    const out = validateBundle({
      bundle: fx.bundle,
      jwks: fx.jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });

    // The ephemeral test root is not in the wheel-bundled placeholder chain,
    // so without tsa_extra_trusted_roots_pem the SignerInfo chain has no
    // trusted anchor and the TSA token is rejected as invalid -- matching
    // Python's behavior for the same bundle.
    expect(out.tsa_check).toBe("invalid");
    expect(out.overall).toBe("fail");
  });

  test("Python and TypeScript AGREE on tsa_check both WITH and WITHOUT the extra root", () => {
    const fx = pyJson<BuiltBundleFixture>(PY_BUILD());

    const tsWith = validateBundle({
      bundle: fx.bundle,
      jwks: fx.jwks as unknown as { keys: Array<{ kid?: unknown }> },
      options: {
        tsa_extra_trusted_roots_pem: Buffer.from(fx.tsa_root_pem, "utf-8"),
      },
    });
    const tsWithout = validateBundle({
      bundle: fx.bundle,
      jwks: fx.jwks as unknown as { keys: Array<{ kid?: unknown }> },
    });

    const py = pyJson<{
      with_root: { overall: string; tsa_check: string };
      without_root: { overall: string; tsa_check: string };
    }>(
      PY_VALIDATE(
        JSON.stringify(fx.bundle),
        JSON.stringify(fx.jwks),
        fx.tsa_root_pem,
      ),
    );

    // Cross-runtime parity: identical tsa_check + overall in BOTH branches.
    expect(tsWith.tsa_check).toBe(py.with_root.tsa_check);
    expect(tsWith.overall).toBe(py.with_root.overall);
    expect(tsWithout.tsa_check).toBe(py.without_root.tsa_check);
    expect(tsWithout.overall).toBe(py.without_root.overall);

    // And the concrete expected values (guards against a both-broken parity).
    expect(py.with_root.tsa_check).toBe("ok");
    expect(py.without_root.tsa_check).toBe("invalid");
  });

  test("tsa_skip_bundled_chain option is honored (still ok when the extra root carries the chain)", () => {
    const fx = pyJson<BuiltBundleFixture>(PY_BUILD());

    // With the bundled chain skipped but the ephemeral root supplied, the
    // SignerInfo chain still anchors against the extra root -> ok. This
    // exercises the new option plumbing without depending on the placeholder
    // bundled root verifying the ephemeral token.
    const out = validateBundle({
      bundle: fx.bundle,
      jwks: fx.jwks as unknown as { keys: Array<{ kid?: unknown }> },
      options: {
        tsa_skip_bundled_chain: true,
        tsa_extra_trusted_roots_pem: Buffer.from(fx.tsa_root_pem, "utf-8"),
      },
    });

    expect(out.tsa_check).toBe("ok");
    expect(out.overall).toBe("pass");
  });
});
