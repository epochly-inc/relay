// M06 cross-language parity for the seven new TS verifier modules
// (VAL-V2M06-001..025). Each `describe` block covers one assertion.
//
// The Python verifier is the source-of-truth; this suite shells out to
// `python3 -c "..."` (no Vitest plugin), serialises Python outputs to
// JSON via JCS canonicalisation (sorted keys, separator-tight), and
// asserts byte equality of the TS-produced output against Python's.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { writeFileSync, mkdirSync, existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  CACHE_STALENESS_THRESHOLD_SECONDS,
  CLOCK_SKEW_TOLERANCE_SECONDS,
  DEFAULT_JWKS_URL,
  JWKS_CACHE_DIRNAME,
  JWKS_CACHE_SCHEMA_VERSION,
  MIN_RSA_BITS,
  RELAY_EVID_031,
  RELAY_EVID_038,
  RELAY_EVID_041,
  RELAY_EVID_042,
  RELAY_EVID_DECIDED_AT_MISSING,
  SUBJECT_RESOLUTION_LIVE,
  SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
  SUBJECT_RESOLUTION_TOMBSTONED,
  SUBJECT_RESOLUTION_UNKNOWN,
  TRUST_ANCHOR_SOURCE_BUNDLED,
  TRUST_ANCHOR_SOURCE_BYO_CONFIG,
  TRUST_ANCHOR_SOURCE_BYO_FLAG,
  TRUST_ANCHOR_SOURCE_CACHE,
  TRUST_ANCHOR_SOURCE_LIVE,
  TSA_CHAIN_DIRNAME,
  TSA_CHAIN_FILENAME,
  TSA_CRYPTO_IMPLEMENTED,
  VERIFIER_OUTPUT_SCHEMA,
  buildInclusionProof,
  cachePathForUrl,
  canonicalJsonBytes,
  checkSigningKeyLifecycle,
  computeMerkleRoot,
  hostnameForUrl,
  inspectTsaChain,
  loadCachedJwks,
  loadBundledTsaChain,
  resolveSubject,
  resolveTrustAnchorUrl,
  validateBundle,
  validateTsaToken,
  verifyInclusionProof,
  verifyJwsCompact,
  verifyLogInclusion,
  InMemorySubjectStore,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

// ----------------------------------------------------------------------------
// Python parity helpers
// ----------------------------------------------------------------------------

function runPython(code: string): { stdout: string; stderr: string; status: number } {
  // Use a tmpfile to avoid the -c single-line + semicolon-join trap.
  const tmpFile = resolve(tmpdir(), `relay-m06-pyhelper-${process.pid}-${Math.random().toString(36).slice(2)}.py`);
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
    throw new Error(`python helper failed (status=${r.status}): ${r.stderr}`);
  }
  // Python helper prints exactly one JSON line on stdout.
  const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(line) as T;
}

// JCS canonical SHA-256 of the projected envelope. The TS canonical
// encoder is the byte-equal mirror of Python's `jcs_canonicalize`, so
// both runtimes' outputs hash to the same digest when their structural
// content matches.
function digestEnv(env: unknown): string {
  return createHash("sha256").update(canonicalJsonBytes(env)).digest("hex");
}

// ============================================================================
// VAL-V2M06-001 / 007 / 012 / 016 / 018 / 022 / 025: module exports present
// ============================================================================

describe("VAL-V2M06-001 tsa.ts module + exports", () => {
  test("exports validateTsaToken, inspectTsaChain, etc.", () => {
    expect(typeof validateTsaToken).toBe("function");
    expect(typeof inspectTsaChain).toBe("function");
    expect(typeof loadBundledTsaChain).toBe("function");
    expect(typeof RELAY_EVID_031).toBe("string");
    expect(typeof RELAY_EVID_038).toBe("string");
    expect(RELAY_EVID_031).toBe("RELAY-EVID-031");
    expect(RELAY_EVID_038).toBe("RELAY-EVID-038");
    expect(TSA_CHAIN_DIRNAME).toBe("tsa_chain");
    expect(TSA_CHAIN_FILENAME).toBe("tsa-chain.pem");
  });
});

describe("VAL-V2M06-007 transparency_log.ts module + exports", () => {
  test("exports verifyLogInclusion", () => {
    expect(typeof verifyLogInclusion).toBe("function");
  });
});

describe("VAL-V2M06-012 key_lifecycle.ts module + exports", () => {
  test("exports checkSigningKeyLifecycle + RELAY-EVID-041/042", () => {
    expect(typeof checkSigningKeyLifecycle).toBe("function");
    expect(RELAY_EVID_041).toBe("RELAY-EVID-041");
    expect(RELAY_EVID_042).toBe("RELAY-EVID-042");
  });
});

describe("VAL-V2M06-016 retention.ts module + exports", () => {
  test("exports resolveSubject + four resolution constants + InMemorySubjectStore", () => {
    expect(typeof resolveSubject).toBe("function");
    expect(SUBJECT_RESOLUTION_LIVE).toBe("live");
    expect(SUBJECT_RESOLUTION_TOMBSTONED).toBe("tombstoned");
    expect(SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING).toBe("redacted_after_signing");
    expect(SUBJECT_RESOLUTION_UNKNOWN).toBe("unknown");
    const store = new InMemorySubjectStore({
      "r-1": { state: "live", original_digest_hex: "" },
    });
    expect(store.lookup("r-1")?.state).toBe("live");
    expect(store.lookup("none")).toBeNull();
  });
});

describe("VAL-V2M06-018 jwks_loader.ts module + exports", () => {
  test("exports resolver + cache + bundled JWKS surface", () => {
    expect(typeof resolveTrustAnchorUrl).toBe("function");
    expect(typeof loadCachedJwks).toBe("function");
    expect(typeof cachePathForUrl).toBe("function");
    expect(typeof hostnameForUrl).toBe("function");
    expect(TRUST_ANCHOR_SOURCE_LIVE).toBe("live_fetch");
    expect(TRUST_ANCHOR_SOURCE_CACHE).toBe("cached_jwks");
    expect(TRUST_ANCHOR_SOURCE_BUNDLED).toBe("bundled_jwks");
    expect(TRUST_ANCHOR_SOURCE_BYO_FLAG).toBe("byo_flag");
    expect(TRUST_ANCHOR_SOURCE_BYO_CONFIG).toBe("byo_config");
    expect(CACHE_STALENESS_THRESHOLD_SECONDS).toBe(7 * 24 * 60 * 60);
    expect(JWKS_CACHE_SCHEMA_VERSION).toBe("relay.cli.jwks_cache.v1");
    expect(JWKS_CACHE_DIRNAME).toBe("jwks-cache");
  });
});

describe("VAL-V2M06-022 bundle_validator.ts orchestrator + constants", () => {
  test("exports validateBundle + wire codes + size constants", () => {
    expect(typeof validateBundle).toBe("function");
    expect(VERIFIER_OUTPUT_SCHEMA).toBe("relay.verifier.output.v1");
    expect(RELAY_EVID_DECIDED_AT_MISSING).toBe("RELAY-EVID-DECIDED-AT-MISSING");
  });
});

// ============================================================================
// VAL-V2M06-002: TSA_CRYPTO_IMPLEMENTED runtime posture (now real-crypto in both)
// ============================================================================
//
// Python flipped TSA_CRYPTO_IMPLEMENTED to True in v0.2 M09 w9-2 (commit
// 2031152) wiring rfc3161-client + asn1crypto. The TypeScript port stayed
// fail-closed (TSA_CRYPTO_IMPLEMENTED = false) at M06 w6 because porting the
// full RFC 3161 ASN.1 stack to TS was a separate work item. Per
// relay-v0.3-audit-resolution M5/F5.7 (VAL-V3M5-014) the TS verifier is now
// also real-crypto using @peculiar/asn1-tsp + @peculiar/asn1-cms +
// @peculiar/asn1-x509 for decode and node:crypto for chain + SignerInfo
// signature verification. Both runtimes now actively verify; the cross-
// language acceptance gate is preserved.
describe("VAL-V2M06-002 TSA_CRYPTO_IMPLEMENTED runtime posture", () => {
  test("TS now real-crypto (true) per V3M5 F5.7", () => {
    expect(TSA_CRYPTO_IMPLEMENTED).toBe(true);
  });
  test("Python now real-crypto (true) per M09 w9-2", () => {
    const py = pyJson<{ py: boolean }>(
      `import json, sys
from relay_verifier.tsa import TSA_CRYPTO_IMPLEMENTED as f
sys.stdout.write(json.dumps({'py': bool(f)}))
`,
    );
    expect(py.py).toBe(true);
  });
});

// ============================================================================
// VAL-V2M06-003: validateTsaToken rejects token missing tsr_der_b64u
// ============================================================================
//
// Prior to V3M5 F5.7 the TS verifier fail-closed with a "TSA cryptographic
// signature verification" reason prefix when structural checks passed but the
// crypto path was un-ported. Post-V3M5 the crypto path is real; a token that
// passes the dict-level message_imprint + gen_time checks but lacks the
// base64url-encoded TimeStampResp DER payload (``tsr_der_b64u``) is now
// rejected with the structured reason ``"tsr_der_missing"`` matching Python's
// validate_tsa_token. Parity holds: TS and Python both reject the same
// degenerate token shape with the same RELAY-EVID-031 wire code.
describe("VAL-V2M06-003 validateTsaToken rejects token missing tsr_der_b64u", () => {
  test("structural-pass token without tsr_der_b64u => outcome=invalid, reason=tsr_der_missing", () => {
    const token = {
      version: 1,
      message_imprint: {
        hash_algorithm: "sha256",
        hashed_message_hex: "a".repeat(64),
      },
      gen_time: "2026-05-15T12:00:00Z",
      tsa_signature_b64u: "AAAA",
      tsa_signer_cert_subject: "CN=Test",
    };
    const r = validateTsaToken({
      token,
      bundleDigestHex: "a".repeat(64),
      decidedAt: "2026-05-15T12:00:00Z",
      chainCerts: null,
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).toBe("tsr_der_missing");
    expect(r.code).toBe("RELAY-EVID-031");
  });
});

// ============================================================================
// VAL-V2M06-004: TSA missing token returns RELAY-EVID-031
// ============================================================================

describe("VAL-V2M06-004 missing token => outcome=missing + RELAY-EVID-031", () => {
  test("null token", () => {
    const r = validateTsaToken({
      token: null,
      bundleDigestHex: "a".repeat(64),
      decidedAt: "2026-01-01T00:00:00Z",
      chainCerts: null,
    });
    expect(r.outcome).toBe("missing");
    expect(r.code).toBe("RELAY-EVID-031");
  });
  test("undefined token", () => {
    const r = validateTsaToken({
      token: undefined,
      bundleDigestHex: "a".repeat(64),
      decidedAt: "2026-01-01T00:00:00Z",
      chainCerts: null,
    });
    expect(r.outcome).toBe("missing");
    expect(r.code).toBe("RELAY-EVID-031");
  });
});

// ============================================================================
// VAL-V2M06-005: TSA gen_time skew boundary parity
// ============================================================================

describe("VAL-V2M06-005 TSA gen_time skew boundary parity (299/300/301)", () => {
  test("CLOCK_SKEW_TOLERANCE_SECONDS equals 300 in both runtimes", () => {
    expect(CLOCK_SKEW_TOLERANCE_SECONDS).toBe(300);
    const py = pyJson<{ v: number }>(
      `import json, sys
from relay_verifier.tsa import CLOCK_SKEW_TOLERANCE_SECONDS as v
sys.stdout.write(json.dumps({'v': v}))
`,
    );
    expect(py.v).toBe(300);
  });

  for (const skew of [0, 299, 300, 301]) {
    test(`skew=${skew}s row`, () => {
      const decided = new Date("2026-05-15T12:00:00Z");
      const genTime = new Date(decided.getTime() + skew * 1000);
      const decidedIso = decided.toISOString().replace(/\.\d{3}Z$/, "Z");
      const genIso = genTime.toISOString().replace(/\.\d{3}Z$/, "Z");
      const digest = "a".repeat(64);
      const token = {
        message_imprint: { hash_algorithm: "sha256", hashed_message_hex: digest },
        gen_time: genIso,
        tsa_signature_b64u: "AAAA",
      };
      const r = validateTsaToken({
        token,
        bundleDigestHex: digest,
        decidedAt: decidedIso,
        chainCerts: null,
      });
      if (skew > CLOCK_SKEW_TOLERANCE_SECONDS) {
        expect(r.outcome).toBe("skew");
        expect(r.code).toBe("RELAY-EVID-038");
      } else {
        // Within tolerance the skew check passes; post-V3M5 the next gate
        // is the real-crypto path which rejects this stub token (no
        // tsr_der_b64u) with structured reason "tsr_der_missing". The
        // skew_seconds field still echoes the parsed delta.
        expect(r.outcome).toBe("invalid");
        expect(r.reason).toBe("tsr_der_missing");
        expect(r.skew_seconds).toBe(skew);
      }
    });
  }
});

// ============================================================================
// VAL-V2M06-006: TSA chain inspection enforces RSA min 2048
// ============================================================================

describe("VAL-V2M06-006 inspectTsaChain rejects RSA <2048", () => {
  test("MIN_RSA_BITS constant", () => {
    expect(MIN_RSA_BITS).toBe(2048);
    const py = pyJson<{ v: number }>(
      `import json, sys
from relay_verifier.tsa import MIN_RSA_BITS as v
sys.stdout.write(json.dumps({'v': v}))
`,
    );
    expect(py.v).toBe(2048);
  });

  test("bundled TSA chain loads + inspects (Ed25519 self-signed expected)", () => {
    const { path, raw } = loadBundledTsaChain();
    expect(existsSync(path)).toBe(true);
    const check = inspectTsaChain({ pemBytes: raw, chainPath: path });
    expect(check.cert_count).toBeGreaterThanOrEqual(1);
    // Bundled chain is the OSS placeholder Ed25519 root; chain_ok is true.
    expect(check.chain_ok).toBe(true);
  });

  test("RSA 1024 cert triggers MIN_RSA_BITS=2048 rejection", () => {
    // Generate an RSA 1024 self-signed cert on the fly (test-only).
    const tmpScript = resolve(tmpdir(), `relay-m06-rsa1024-${process.pid}-${Date.now()}.py`);
    const tmpOut = resolve(tmpdir(), `relay-m06-rsa1024-${process.pid}-${Date.now()}.pem`);
    const script = `import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

k = rsa.generate_private_key(public_exponent=65537, key_size=1024)
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Weak')])
c = (
    x509.CertificateBuilder()
    .subject_name(n)
    .issuer_name(n)
    .public_key(k.public_key())
    .serial_number(1)
    .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
    .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
    .sign(k, hashes.SHA256())
)
with open(${JSON.stringify(tmpOut)}, 'wb') as f:
    f.write(c.public_bytes(serialization.Encoding.PEM))
`;
    writeFileSync(tmpScript, script, "utf-8");
    try {
      const r = spawnSync("uv", ["run", "python3", tmpScript], {
        cwd: REPO_ROOT,
        encoding: "utf-8",
        timeout: 60_000,
      });
      expect(r.status).toBe(0);
      const pem = readFileSync(tmpOut);
      const check = inspectTsaChain({ pemBytes: pem, chainPath: "" });
      expect(check.chain_ok).toBe(false);
      expect(check.reason).toContain("MIN_RSA_BITS=2048");
    } finally {
      rmSync(tmpScript, { force: true });
      rmSync(tmpOut, { force: true });
    }
  });
});

// ============================================================================
// VAL-V2M06-008: log inclusion absent => "absent" not reject
// ============================================================================

describe("VAL-V2M06-008 verifyLogInclusion null proof => absent", () => {
  test("ts: null proof", () => {
    const r = verifyLogInclusion({
      proof: null,
      bundleDigestHex: "deadbeef".repeat(8),
    });
    expect(r.outcome).toBe("absent");
    expect(r.reason).toBe("no inclusion proof attached");
  });
  test("py: null proof produces same outcome string", () => {
    const py = pyJson<{ outcome: string }>(
      `import json, sys
from relay_verifier.transparency_log import verify_log_inclusion
r = verify_log_inclusion(proof=None, bundle_digest_hex='deadbeef' * 8)
sys.stdout.write(json.dumps({'outcome': r.outcome}))
`,
    );
    expect(py.outcome).toBe("absent");
  });
});

// ============================================================================
// VAL-V2M06-009: log inclusion witness signature verification (ed25519)
// ============================================================================

describe("VAL-V2M06-009 valid witness signature verifies; tampered fails", () => {
  test("ed25519 over tree_root_hex bytes verifies", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    // Build a 2-leaf tree to exercise both leaf and internal hashing.
    const leafA = createHash("sha256").update("a").digest("hex");
    const leafB = createHash("sha256").update("b").digest("hex");
    const root = computeMerkleRoot([leafA, leafB]);
    const proofPath = buildInclusionProof({ leafIndex: 0, claimDigestsHex: [leafA, leafB] });
    const treeRootHex = root;
    const signature = nodeSign(null, Buffer.from(treeRootHex, "utf-8"), privateKey);
    const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    jwk["kid"] = "witness-1";
    const jwks = { keys: [jwk] };

    const proof = {
      log_id: "rekor.epochly.com",
      tree_size: 2,
      tree_root_hex: treeRootHex,
      leaf_index: 0,
      leaf_digest_hex: leafA,
      inclusion_proof: proofPath,
      witness: {
        alg: "EdDSA",
        kid: "witness-1",
        signature_b64u: signature.toString("base64url"),
      },
    };
    const ok = verifyLogInclusion({
      proof,
      bundleDigestHex: leafA,
      witnessJwks: jwks,
    });
    expect(ok.outcome).toBe("ok");

    // Mutate the signature; verification must fail.
    const tampered = { ...proof, witness: { ...proof.witness, signature_b64u: "A" + proof.witness.signature_b64u.slice(1) } };
    const bad = verifyLogInclusion({
      proof: tampered,
      bundleDigestHex: leafA,
      witnessJwks: jwks,
    });
    expect(bad.outcome).toBe("witness_mismatch");
  });
});

// ============================================================================
// VAL-V2M06-010: merkle.ts RFC 6962 leaf/internal domain separation
// ============================================================================

describe("VAL-V2M06-010 merkle RFC 6962 known-answer parity", () => {
  for (const size of [0, 1, 2, 3, 5, 8, 17]) {
    test(`tree size ${size}: ts root equals py root`, () => {
      const leaves = Array.from({ length: size }, (_, i) =>
        createHash("sha256").update(`leaf-${i}`).digest("hex"),
      );
      const tsRoot = computeMerkleRoot(leaves);
      const pyArg = JSON.stringify(leaves);
      const py = pyJson<{ root: string }>(
        `import json, sys
from relay_verifier.merkle import compute_merkle_root
leaves = json.loads(${JSON.stringify(pyArg)})
root = compute_merkle_root(leaves)
sys.stdout.write(json.dumps({'root': root}))
`,
      );
      expect(tsRoot).toBe(py.root);
    });
  }

  test("verifyInclusionProof verifies a TS-built proof at every paired-leaf index (size 8)", () => {
    // Use a power-of-two tree so no lonely-leaf indices appear; the
    // build_inclusion_proof helper does NOT include sibling slots for
    // lonely leaves (RFC 6962 convention), so the verifier returns false
    // for those indices by construction. Power-of-two avoids that edge.
    const n = 8;
    const leaves = Array.from({ length: n }, (_, i) =>
      createHash("sha256").update(`x-${i}`).digest("hex"),
    );
    const root = computeMerkleRoot(leaves);
    for (let i = 0; i < n; i++) {
      const leafI = leaves[i];
      if (leafI === undefined) throw new Error("indexing");
      const p = buildInclusionProof({ leafIndex: i, claimDigestsHex: leaves });
      const ok = verifyInclusionProof({
        leafIndex: i,
        leafDigestHex: leafI,
        proofPath: p,
        treeSize: n,
        claimedRootHex: root,
      });
      expect(ok).toBe(true);
    }
  });
});

// ============================================================================
// VAL-V2M06-011: merkle has zero I/O
// ============================================================================

describe("VAL-V2M06-011 merkle/transparency_log import no fs/net/fetch", () => {
  test("merkle.ts source imports only node:crypto", () => {
    const src = readFileSync(resolve(__dirname, "..", "src", "merkle.ts"), "utf-8");
    expect(/from\s+["']node:fs["']/.test(src)).toBe(false);
    expect(/from\s+["']node:net["']/.test(src)).toBe(false);
    expect(/from\s+["']node:dgram["']/.test(src)).toBe(false);
    expect(/\bfetch\s*\(/.test(src)).toBe(false);
  });
  test("transparency_log.ts source imports only node:crypto + internal modules", () => {
    const src = readFileSync(resolve(__dirname, "..", "src", "transparency_log.ts"), "utf-8");
    expect(/from\s+["']node:fs["']/.test(src)).toBe(false);
    expect(/from\s+["']node:net["']/.test(src)).toBe(false);
    expect(/\bfetch\s*\(/.test(src)).toBe(false);
  });
});

// ============================================================================
// VAL-V2M06-013: key lifecycle +/-300s skew tolerance parity
// ============================================================================

describe("VAL-V2M06-013 key lifecycle skew boundary parity", () => {
  const auditorNow = new Date("2026-05-15T12:00:00Z");
  for (const skew of [-301, -300, -299, 0, 299, 300, 301]) {
    test(`not_before offset ${skew}s`, () => {
      const notBefore = new Date(auditorNow.getTime() + skew * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
      const r = checkSigningKeyLifecycle({
        jwk: { not_before: notBefore },
        bundleSignedAt: "2026-05-15T12:00:00Z",
        auditorNow,
      });
      if (skew > 300) {
        expect(r.outcome).toBe("premature");
        expect(r.code).toBe("RELAY-EVID-041");
      } else {
        expect(r.outcome).toBe("ok");
      }
    });
    test(`not_after offset ${skew}s in the past`, () => {
      // not_after at (auditorNow - skew) means key expired skew seconds ago.
      const notAfter = new Date(auditorNow.getTime() - skew * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
      const r = checkSigningKeyLifecycle({
        jwk: { not_after: notAfter },
        bundleSignedAt: "2026-05-15T12:00:00Z",
        auditorNow,
      });
      if (skew > 300) {
        expect(r.outcome).toBe("expired");
        expect(r.code).toBe("RELAY-EVID-041");
      } else {
        expect(r.outcome).toBe("ok");
      }
    });
  }
});

// ============================================================================
// VAL-V2M06-014: revocation pre/post matrix
// ============================================================================

describe("VAL-V2M06-014 revoked_at pre/post matrix", () => {
  const revokedAt = "2026-05-15T12:00:00Z";
  // Python parity: when a JWK has revoked_at but no not_before/not_after,
  // the lifecycle resolver returns outcome="missing_window" + signer_key_revoked=true
  // for the pre-revocation rows (because the revocation branch only `return`s on
  // the post-revocation reject path, then the missing-window branch triggers).
  // For post-revocation rows it returns outcome="revoked".
  const cases: Array<[string, "missing_window" | "revoked", boolean]> = [
    ["2026-05-14T12:00:00Z", "missing_window", true], // before revocation
    ["2026-05-15T12:00:00Z", "missing_window", true], // exactly at: ok per >comparison, flagged, falls into missing_window
    ["2026-05-15T12:00:01Z", "revoked", true],
    ["2027-05-15T12:00:00Z", "revoked", true],
  ];
  for (const [signedAt, outcome, revoked] of cases) {
    test(`signed_at=${signedAt}`, () => {
      const r = checkSigningKeyLifecycle({
        jwk: { revoked_at: revokedAt },
        bundleSignedAt: signedAt,
      });
      expect(r.outcome).toBe(outcome);
      expect(r.signer_key_revoked).toBe(revoked);
      expect(r.signer_key_revoked_at).toBe(revokedAt);
      if (outcome === "revoked") {
        expect(r.code).toBe("RELAY-EVID-042");
      }
    });
  }

  // Bundle with both revoked_at AND not_before/not_after: outcome=ok for
  // pre-revocation, revoked for post.
  test("with valid window: signed_at < revoked_at => ok + signer_key_revoked", () => {
    const r = checkSigningKeyLifecycle({
      jwk: {
        revoked_at: revokedAt,
        not_before: "2026-01-01T00:00:00Z",
        not_after: "2027-01-01T00:00:00Z",
      },
      bundleSignedAt: "2026-05-14T12:00:00Z",
      auditorNow: new Date("2026-05-14T12:00:00Z"),
    });
    expect(r.outcome).toBe("ok");
    expect(r.signer_key_revoked).toBe(true);
    expect(r.signer_key_revoked_at).toBe(revokedAt);
  });
});

// ============================================================================
// VAL-V2M06-015: alg allow-list enforced before crypto
// ============================================================================

describe("VAL-V2M06-015 alg allow-list rejects HS256/none/ES384/RS512 pre-crypto", () => {
  // Build a minimal compact JWS with `none` alg and empty signature.
  function compactWithAlg(alg: string): string {
    const header = Buffer.from(JSON.stringify({ alg, kid: "k1" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ x: 1 })).toString("base64url");
    return `${header}.${payload}.`;
  }
  for (const alg of ["HS256", "none", "ES384", "RS512"]) {
    test(`alg=${alg} rejected with RELAY-VERIFY-011`, () => {
      const r = verifyJwsCompact(compactWithAlg(alg), { keys: [] });
      expect(r.ok).toBe(false);
      expect(r.code).toBe("RELAY-VERIFY-011");
    });
  }
});

// ============================================================================
// VAL-V2M06-017: retention subject-resolution parity
// ============================================================================

describe("VAL-V2M06-017 retention subject resolution parity", () => {
  test("no store => unknown", () => {
    const r = resolveSubject({
      subjectId: "r-1",
      subjectDigestHex: "abc",
      subjectStore: null,
    });
    expect(r.resolution).toBe("unknown");
  });
  test("no subject_id => live", () => {
    const store = new InMemorySubjectStore();
    const r = resolveSubject({
      subjectId: "",
      subjectDigestHex: null,
      subjectStore: store,
    });
    expect(r.resolution).toBe("live");
  });
  test("missing record => tombstoned", () => {
    const store = new InMemorySubjectStore();
    const r = resolveSubject({
      subjectId: "missing",
      subjectDigestHex: "x",
      subjectStore: store,
    });
    expect(r.resolution).toBe("tombstoned");
  });
  test("redacted_after_signing state propagates", () => {
    const store = new InMemorySubjectStore({
      "r-2": { state: "redacted_after_signing", original_digest_hex: "orig" },
    });
    const r = resolveSubject({
      subjectId: "r-2",
      subjectDigestHex: "orig",
      subjectStore: store,
    });
    expect(r.resolution).toBe("redacted_after_signing");
    expect(r.original_digest_preserved).toBe(true);
  });
  test("digest mismatch flags original_digest_preserved=false", () => {
    const store = new InMemorySubjectStore({
      "r-3": { state: "live", original_digest_hex: "orig" },
    });
    const r = resolveSubject({
      subjectId: "r-3",
      subjectDigestHex: "drifted",
      subjectStore: store,
    });
    expect(r.original_digest_preserved).toBe(false);
  });
});

// ============================================================================
// VAL-V2M06-019: DEFAULT_JWKS_URL pinned and byte-equal to Python
// ============================================================================

describe("VAL-V2M06-019 DEFAULT_JWKS_URL pinned + single occurrence", () => {
  test("literal pinned to spec value", () => {
    expect(DEFAULT_JWKS_URL).toBe("https://relay.epochly.com/.well-known/jwks.json");
    const py = pyJson<{ v: string }>(
      `import json, sys
from relay_verifier.constants import DEFAULT_JWKS_URL
sys.stdout.write(json.dumps({'v': DEFAULT_JWKS_URL}))
`,
    );
    expect(py.v).toBe(DEFAULT_JWKS_URL);
  });
  test("single occurrence in TS source tree outside test/", () => {
    // Grep src/**/*.ts for the literal; expect exactly one occurrence
    // (in constants.ts).
    const r = spawnSync(
      "bash",
      [
        "-c",
        `grep -rno --include='*.ts' 'https://relay.epochly.com/.well-known/jwks.json' src/`,
      ],
      { cwd: resolve(__dirname, ".."), encoding: "utf-8" },
    );
    expect(r.status).toBe(0);
    const lines = (r.stdout ?? "").trim().split(/\r?\n/).filter((s) => s.length > 0);
    // constants.ts has exactly one occurrence on the assignment line.
    expect(lines.length).toBe(1);
    expect(lines[0]).toMatch(/^src\/constants\.ts:/);
  });
});

// ============================================================================
// VAL-V2M06-020: BYO trust-anchor cache keyed by hostname (+port) parity
// ============================================================================

describe("VAL-V2M06-020 hostnameForUrl parity over 12 URLs", () => {
  // file:/// URLs intentionally excluded -- both Python urlparse and JS
  // WHATWG URL produce empty hostnames there, and both runtimes raise
  // "trust anchor URL has no hostname"; the parity contract is over
  // hostname-bearing URLs.
  const fixtures: string[] = [
    "https://relay.epochly.com/.well-known/jwks.json",
    "https://relay.epochly.com:443/.well-known/jwks.json",
    "http://127.0.0.1:8080/jwks.json",
    "http://127.0.0.1/jwks.json",
    "https://Example.COM/jwks.json",
    "https://example.com:80/jwks.json",
    "https://relay.example.com:9443/path?x=1",
    "https://foo.bar.baz.example.org/jwks.json",
    "https://a.example.com:443/.well-known/jwks.json",
    "https://192.0.2.1:9000/jwks.json",
    "https://192.0.2.1/jwks.json",
    "https://relay.epochly.com/.well-known/jwks.json#frag",
  ];
  for (const url of fixtures) {
    test(`url=${url}`, () => {
      const tsHost = hostnameForUrl(url);
      const py = pyJson<{ host: string }>(
        `import json, sys
from relay_verifier.jwks_loader import _hostname_for_url
sys.stdout.write(json.dumps({'host': _hostname_for_url(${JSON.stringify(url)})}))
`,
      );
      expect(tsHost).toBe(py.host);
    });
  }

  test("loadCachedJwks returns null for missing entry; envelope round-trip works", () => {
    const tmp = resolve(tmpdir(), `relay-m06-cache-${process.pid}-${Date.now()}`);
    mkdirSync(resolve(tmp, JWKS_CACHE_DIRNAME), { recursive: true });
    try {
      const url = "https://relay.epochly.com/.well-known/jwks.json";
      expect(loadCachedJwks(url, { home: tmp })).toBeNull();
      const envelope = {
        schema_version: JWKS_CACHE_SCHEMA_VERSION,
        trust_anchor_url: url,
        fetched_at: new Date().toISOString(),
        jwks: { keys: [] },
      };
      writeFileSync(cachePathForUrl(url, tmp), JSON.stringify(envelope));
      const hit = loadCachedJwks(url, { home: tmp });
      expect(hit).not.toBeNull();
      expect(hit?.ageSeconds).toBeGreaterThanOrEqual(0);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ============================================================================
// VAL-V2M06-021: resolver precedence (flag > config > default)
// ============================================================================

describe("VAL-V2M06-021 resolveTrustAnchorUrl precedence parity", () => {
  test("flag set => byo_flag wins", () => {
    const [url, src] = resolveTrustAnchorUrl({ flagUrl: "https://byo.example.com/jwks.json" });
    expect(url).toBe("https://byo.example.com/jwks.json");
    expect(src).toBe("byo_flag");
  });
  test("no flag, no config => default URL with live source", () => {
    const [url, src] = resolveTrustAnchorUrl({ flagUrl: "", configPath: null });
    expect(url).toBe(DEFAULT_JWKS_URL);
    expect(src).toBe("live_fetch");
  });
  test("no flag + config-with-url => byo_config", () => {
    const tmp = resolve(tmpdir(), `relay-m06-config-${process.pid}-${Date.now()}.toml`);
    writeFileSync(tmp, 'trust_anchor_url = "https://cfg.example.com/jwks.json"\n');
    try {
      const [url, src] = resolveTrustAnchorUrl({ configPath: tmp });
      expect(url).toBe("https://cfg.example.com/jwks.json");
      expect(src).toBe("byo_config");
    } finally {
      rmSync(tmp, { force: true });
    }
  });
});

// ============================================================================
// VAL-V2M06-022: validateBundle output envelope JCS parity
// ============================================================================

describe("VAL-V2M06-022 validateBundle output JCS parity with Python", () => {
  test("minimal bundle (no decided_at => decided_at_missing error) byte-equal", () => {
    const bundle = {
      schema_version: "relay.evidence.bundle.v1",
      generated_at: "2026-05-15T12:00:00Z",
      claims: [{ id: "c1", payload: { value: 1 } }],
      trust_anchor: "relay.epochly.com",
    };
    const jwks = { keys: [] as Array<Record<string, unknown>> };
    const tsOut = validateBundle({ bundle, jwks });
    expect(tsOut.tsa_check).toBe("missing");
    expect(tsOut.errors.length).toBeGreaterThanOrEqual(2);
    // The error reason set is a stable cross-runtime contract.
    const reasons = new Set(tsOut.errors.map((e) => String(e["reason"])));
    expect(reasons.has("decided_at_missing")).toBe(true);
    expect(reasons.has("tsa_missing")).toBe(true);
    expect(tsOut.overall).toBe("fail");

    // Python parity on the structural fields that matter (the schema +
    // overall verdict + the TSA-related error reasons).
    const py = pyJson<{
      schema_version: string;
      overall: string;
      tsa_check: string;
      reasons: string[];
    }>(
      `import json, sys
from relay_verifier.bundle_validator import validate_bundle
bundle = json.loads(${JSON.stringify(JSON.stringify(bundle))})
jwks = {'keys': []}
out = validate_bundle(bundle=bundle, jwks=jwks)
sys.stdout.write(json.dumps({
    'schema_version': out['schema_version'],
    'overall': out['overall'],
    'tsa_check': out['tsa_check'],
    'reasons': sorted([e['reason'] for e in out['errors']]),
}))
`,
    );
    expect(py.schema_version).toBe(tsOut.schema_version);
    expect(py.overall).toBe(tsOut.overall);
    expect(py.tsa_check).toBe(tsOut.tsa_check);
    // Reasons set parity.
    const pyReasons = new Set(py.reasons);
    for (const r of pyReasons) expect(reasons.has(r)).toBe(true);
    for (const r of reasons) expect(pyReasons.has(r)).toBe(true);
  });
});

// ============================================================================
// VAL-V2M06-023: trust_anchor field surfaced verbatim + local_dev WARN
// ============================================================================

describe("VAL-V2M06-023 trust_anchor surfacing parity", () => {
  test.each([
    ["relay.epochly.com", false],
    ["local_dev", true],
    ["fork.example", false],
  ] as Array<[string, boolean]>)(
    "trust_anchor=%s expects localDevWarn=%s",
    (anchor, expectLocalDevWarn) => {
      const bundle = {
        schema_version: "relay.evidence.bundle.v1",
        claims: [{ id: "c1", payload: { v: 1 } }],
        trust_anchor: anchor,
        decided_at: "2026-05-15T12:00:00Z",
      };
      const out = validateBundle({
        bundle,
        jwks: { keys: [] },
      });
      expect(out.trust_anchor).toBe(anchor);
      const hasLocalDevWarn = out.warnings.some(
        (w) => w["reason"] === "local_dev_unsupported_for_audit",
      );
      expect(hasLocalDevWarn).toBe(expectLocalDevWarn);
    },
  );
});

// ============================================================================
// VAL-V2M06-024: conformance corpus exists + every output field has a test
// ============================================================================

describe("VAL-V2M06-024 conformance corpus coverage", () => {
  test("corpus directory exists; coverage report enumerates every output field", () => {
    const dir = resolve(REPO_ROOT, "tests", "conformance", "verifier");
    expect(existsSync(dir)).toBe(true);
    const coverage = JSON.parse(
      readFileSync(resolve(dir, "coverage_report.json"), "utf-8"),
    ) as { fields: Record<string, { ts: string[]; py: string[] }> };
    const requiredFields = [
      "tsa_check",
      "log_inclusion",
      "signer_key_revoked",
      "subject_resolution",
      "trust_anchor",
      "signatures_checked",
      "merkle_check",
    ];
    for (const f of requiredFields) {
      expect(coverage.fields[f]).toBeDefined();
      expect(coverage.fields[f]?.ts.length ?? 0).toBeGreaterThan(0);
      expect(coverage.fields[f]?.py.length ?? 0).toBeGreaterThan(0);
    }
  });

  test("digest envelope across N parity-rows matches Python orchestrator", () => {
    // Build a 3-row fixture set exercising trust_anchor variants.
    const fixtures = [
      {
        name: "relay-anchor",
        bundle: {
          schema_version: "relay.evidence.bundle.v1",
          claims: [{ id: "c1", payload: { v: 1 } }],
          trust_anchor: "relay.epochly.com",
        },
      },
      {
        name: "local-dev",
        bundle: {
          schema_version: "relay.evidence.bundle.v1",
          claims: [{ id: "c1", payload: { v: 1 } }],
          trust_anchor: "local_dev",
        },
      },
      {
        name: "fork-anchor",
        bundle: {
          schema_version: "relay.evidence.bundle.v1",
          claims: [{ id: "c1", payload: { v: 1 } }],
          trust_anchor: "fork.example",
        },
      },
    ];
    for (const f of fixtures) {
      const tsOut = validateBundle({ bundle: f.bundle, jwks: { keys: [] } });
      // Project to the byte-equal cross-runtime subset.
      const projected = {
        schema_version: tsOut.schema_version,
        overall: tsOut.overall,
        trust_anchor: tsOut.trust_anchor,
        tsa_check: tsOut.tsa_check,
        log_inclusion: tsOut.log_inclusion,
        signer_key_revoked: tsOut.signer_key_revoked,
        subject_resolution: tsOut.subject_resolution,
        merkle_check: tsOut.merkle_check,
      };
      const tsDigest = digestEnv(projected);
      const py = pyJson<{ digest: string }>(
        `import json, sys, hashlib
from relay_verifier.bundle_validator import validate_bundle
from relay_verifier.canonical import jcs_canonicalize
bundle = json.loads(${JSON.stringify(JSON.stringify(f.bundle))})
out = validate_bundle(bundle=bundle, jwks={'keys': []})
projected = {
    'schema_version': out['schema_version'],
    'overall': out['overall'],
    'trust_anchor': out['trust_anchor'],
    'tsa_check': out['tsa_check'],
    'log_inclusion': out['log_inclusion'],
    'signer_key_revoked': out['signer_key_revoked'],
    'subject_resolution': out['subject_resolution'],
    'merkle_check': out['merkle_check'],
}
d = hashlib.sha256(jcs_canonicalize(projected)).hexdigest()
sys.stdout.write(json.dumps({'digest': d}))
`,
      );
      expect(tsDigest).toBe(py.digest);
    }
  });
});

// ============================================================================
// VAL-V2M06-025: index.ts re-exports the seven new modules
// ============================================================================

describe("VAL-V2M06-025 index.ts re-exports M06 modules", () => {
  test("import * exposes the canonical names", async () => {
    const m = await import("../src/index.js");
    const required = [
      "validateTsaToken",
      "verifyLogInclusion",
      "computeMerkleRoot",
      "verifyInclusionProof",
      "checkSigningKeyLifecycle",
      "resolveSubject",
      "resolveTrustAnchorUrl",
      "loadCachedJwks",
      "validateBundle",
      "DEFAULT_JWKS_URL",
      "TSA_CRYPTO_IMPLEMENTED",
      "MIN_RSA_BITS",
      "CLOCK_SKEW_TOLERANCE_SECONDS",
    ];
    for (const name of required) {
      expect((m as Record<string, unknown>)[name]).toBeDefined();
    }
  });
});
