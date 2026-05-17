// Transparency log inclusion-proof verification (TS parity with
// packages/verifier/src/relay_verifier/transparency_log.py).
//
// Per spec section AB line 5418 ("bundles can be checked for inclusion
// offline using a witness signature") evidence bundles MAY carry an
// inclusion proof against a transparency log that the issuer has
// witnessed. The verifier checks the inclusion offline -- no network
// call to the log server is required (VAL-W10-030 / VAL-V2M06-011).
//
// Witness signature shape (Sigstore Rekor convention; ed25519 detached):
//
//   {
//     "log_id": "rekor.epochly.com",
//     "tree_size": 12345,
//     "tree_root_hex": "<sha256 hex of merkle root after inclusion>",
//     "leaf_index": 1234,
//     "leaf_digest_hex": "<sha256 hex of bundle digest>",
//     "inclusion_proof": ["<hex>", "<hex>", ...],
//     "witness": {
//       "alg": "EdDSA",
//       "kid": "<witness key kid>",
//       "signature_b64u": "<base64url ed25519 sig over tree_root_hex bytes>"
//     }
//   }
//
// Zero I/O. No fs/net/fetch imports. ASCII-only.

import { verify as nodeVerify } from "node:crypto";

import { verifyInclusionProof } from "./merkle.js";
import { _loadPublicKeyFromJwk, _selectJwk, b64uDecode, type JWKS } from "./verifier.js";

export interface LogInclusionResult {
  /**
   * Verdict for a transparency-log inclusion check.
   *   "ok"               -- proof verified AND witness signature verified
   *   "absent"           -- no inclusion proof attached to the bundle
   *   "witness_mismatch" -- proof present but verification failed
   */
  outcome: "ok" | "absent" | "witness_mismatch";
  /** Human-readable detail; "" on ok/absent. */
  reason: string;
  /** Echoed from proof.log_id; "" when absent. */
  log_id: string;
  /** Echoed from proof.tree_size; 0 when absent. */
  tree_size: number;
  /** Echoed from proof.leaf_index; -1 when absent. */
  leaf_index: number;
}

function _newResult(): LogInclusionResult {
  return {
    outcome: "absent",
    reason: "",
    log_id: "",
    tree_size: 0,
    leaf_index: -1,
  };
}

/**
 * Verify a transparency-log inclusion proof offline.
 *
 * Mirrors `relay_verifier.transparency_log.verify_log_inclusion` line-for-line.
 * Performs zero I/O.
 */
export function verifyLogInclusion(args: {
  proof: Record<string, unknown> | null | undefined;
  bundleDigestHex: string;
  witnessJwks?: JWKS | Record<string, unknown> | null;
}): LogInclusionResult {
  const result = _newResult();
  const { proof, bundleDigestHex } = args;
  const witnessJwks = args.witnessJwks ?? null;

  if (proof === null || proof === undefined) {
    result.outcome = "absent";
    result.reason = "no inclusion proof attached";
    return result;
  }

  if (typeof proof !== "object" || Array.isArray(proof)) {
    result.outcome = "witness_mismatch";
    result.reason = `inclusion proof must be a structured object, got ${typeof proof}`;
    return result;
  }

  // Echo identifying fields immediately for telemetry.
  const logId = proof["log_id"];
  if (typeof logId === "string") {
    result.log_id = logId;
  }
  const treeSize = proof["tree_size"];
  if (typeof treeSize === "number" && Number.isInteger(treeSize)) {
    result.tree_size = treeSize;
  }
  const leafIndex = proof["leaf_index"];
  if (typeof leafIndex === "number" && Number.isInteger(leafIndex)) {
    result.leaf_index = leafIndex;
  }

  // 1. Leaf digest must match the bundle digest.
  const leafDigestHex = proof["leaf_digest_hex"];
  if (typeof leafDigestHex !== "string" || leafDigestHex.length === 0) {
    result.outcome = "witness_mismatch";
    result.reason = "inclusion proof missing 'leaf_digest_hex'";
    return result;
  }
  if (leafDigestHex !== bundleDigestHex) {
    result.outcome = "witness_mismatch";
    result.reason =
      `inclusion proof leaf_digest_hex ${JSON.stringify(leafDigestHex)} does not ` +
      `match bundle digest ${JSON.stringify(bundleDigestHex)}`;
    return result;
  }

  // 2. Recompute the merkle path against the claimed tree root.
  const proofPath = proof["inclusion_proof"];
  if (!Array.isArray(proofPath)) {
    result.outcome = "witness_mismatch";
    result.reason = "inclusion proof missing 'inclusion_proof' list";
    return result;
  }
  const treeRootHex = proof["tree_root_hex"];
  if (typeof treeRootHex !== "string" || treeRootHex.length === 0) {
    result.outcome = "witness_mismatch";
    result.reason = "inclusion proof missing 'tree_root_hex'";
    return result;
  }
  if (
    !(typeof leafIndex === "number" && Number.isInteger(leafIndex)) ||
    !(typeof treeSize === "number" && Number.isInteger(treeSize))
  ) {
    result.outcome = "witness_mismatch";
    result.reason = "inclusion proof leaf_index/tree_size must be integers";
    return result;
  }
  let pathOk = false;
  try {
    pathOk = verifyInclusionProof({
      leafIndex,
      leafDigestHex,
      proofPath: proofPath.map((p) => String(p)),
      treeSize,
      claimedRootHex: treeRootHex,
    });
  } catch (exc) {
    result.outcome = "witness_mismatch";
    result.reason = `inclusion proof recomputation failed: ${(exc as Error).message}`;
    return result;
  }
  if (!pathOk) {
    result.outcome = "witness_mismatch";
    result.reason = "inclusion proof recomputation does not match claimed tree_root";
    return result;
  }

  // 3. Witness signature over tree_root_hex (UTF-8 encoded raw hex string).
  const witness = proof["witness"];
  if (witness === null || witness === undefined || typeof witness !== "object" || Array.isArray(witness)) {
    result.outcome = "witness_mismatch";
    result.reason = "inclusion proof missing 'witness' object";
    return result;
  }
  if (witnessJwks === null || witnessJwks === undefined) {
    result.outcome = "witness_mismatch";
    result.reason = "no witness JWKS supplied to verifier";
    return result;
  }
  const w = witness as Record<string, unknown>;
  const witnessAlg = w["alg"];
  if (witnessAlg !== "EdDSA") {
    result.outcome = "witness_mismatch";
    result.reason = `witness alg ${JSON.stringify(witnessAlg)} not supported (v0.1 ships EdDSA only)`;
    return result;
  }
  const witnessKid = w["kid"];
  if (typeof witnessKid !== "string" || witnessKid.length === 0) {
    result.outcome = "witness_mismatch";
    result.reason = "witness signature missing 'kid'";
    return result;
  }
  const witnessSigB64 = w["signature_b64u"];
  if (typeof witnessSigB64 !== "string" || witnessSigB64.length === 0) {
    result.outcome = "witness_mismatch";
    result.reason = "witness signature missing 'signature_b64u'";
    return result;
  }

  const jwk = _selectJwk(witnessJwks as JWKS, witnessKid);
  if (jwk === null) {
    result.outcome = "witness_mismatch";
    result.reason = `no JWK in witness JWKS matches kid ${JSON.stringify(witnessKid)}`;
    return result;
  }
  let publicKey: ReturnType<typeof _loadPublicKeyFromJwk>;
  try {
    publicKey = _loadPublicKeyFromJwk(jwk);
  } catch (exc) {
    result.outcome = "witness_mismatch";
    result.reason = `witness JWK load failed: ${(exc as Error).message}`;
    return result;
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    result.outcome = "witness_mismatch";
    result.reason =
      `witness JWK kty mismatch: expected Ed25519, got ${String(publicKey.asymmetricKeyType)}`;
    return result;
  }

  let sig: Uint8Array;
  try {
    sig = b64uDecode(witnessSigB64);
  } catch (exc) {
    result.outcome = "witness_mismatch";
    result.reason = `witness signature_b64u not valid base64url: ${(exc as Error).message}`;
    return result;
  }
  let verified: boolean;
  try {
    verified = nodeVerify(
      null,
      Buffer.from(new TextEncoder().encode(treeRootHex)),
      publicKey,
      Buffer.from(sig),
    );
  } catch (exc) {
    result.outcome = "witness_mismatch";
    result.reason = `witness signature verification raised: ${(exc as Error).message}`;
    return result;
  }
  if (!verified) {
    result.outcome = "witness_mismatch";
    result.reason = "witness signature did not verify against tree_root_hex bytes";
    return result;
  }

  result.outcome = "ok";
  return result;
}
