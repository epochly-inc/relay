// Merkle tree binding for evidence claims (TS parity with
// packages/verifier/src/relay_verifier/merkle.py).
//
// Per spec section K line 4390 the evidence-bundle protocol "binds claims
// into a Merkle tree" so a verifier can detect any tampering of either a
// single claim digest OR the ordering of claims in the bundle. The same
// primitives also drive transparency-log inclusion-proof verification
// (VAL-W10-030 / VAL-V2M06-010 / VAL-V2M06-011); the inclusion proof is
// a Merkle path against a transparency-log tree root produced by the
// witness service.
//
// Tree shape (RFC 6962 sec 2):
//
//   - Leaves are lowercase-hex SHA-256 digests of each claim's JCS
//     canonical bytes.
//   - Internal nodes hash the concatenation of their two children, with
//     RFC 6962 domain-separation prefixes:
//         leaf hash:     SHA-256(0x00 || data)
//         internal hash: SHA-256(0x01 || left || right)
//     `data` for a leaf is the binary digest of the claim (32 bytes,
//     NOT the hex string).
//   - Odd-cardinality levels promote the last unpaired node verbatim
//     ("lonely-leaf" convention; RFC 6962 sec 2.1).
//
// Pure-functional, deterministic, zero I/O. No fs / net / fetch imports.
// VAL-V2M06-011 enforces the no-I/O posture.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";

// RFC 6962 domain-separation prefixes. Distinct prefixes prevent
// second-preimage attacks where an internal hash could be reinterpreted
// as a leaf or vice versa.
const LEAF_PREFIX: Uint8Array = Uint8Array.from([0x00]);
const INTERNAL_PREFIX: Uint8Array = Uint8Array.from([0x01]);

function _hexToBytes(h: string): Uint8Array {
  if (typeof h !== "string") {
    throw new TypeError(`expected hex string, got ${typeof h}`);
  }
  if (h.length !== 64) {
    throw new Error(`expected 64-char hex digest, got len=${h.length}`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error(`not a valid hex digest: ${h}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function _concat(a: Uint8Array, b: Uint8Array, c?: Uint8Array): Uint8Array {
  const total = a.length + b.length + (c ? c.length : 0);
  const out = new Uint8Array(total);
  out.set(a, 0);
  out.set(b, a.length);
  if (c) {
    out.set(c, a.length + b.length);
  }
  return out;
}

function _sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(Buffer.from(bytes)).digest());
}

function _hashLeaf(claimDigestHex: string): Uint8Array {
  const raw = _hexToBytes(claimDigestHex);
  return _sha256(_concat(LEAF_PREFIX, raw));
}

function _hashInternal(left: Uint8Array, right: Uint8Array): Uint8Array {
  return _sha256(_concat(INTERNAL_PREFIX, left, right));
}

function _bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const v = b[i] ?? 0;
    s += v.toString(16).padStart(2, "0");
  }
  return s;
}

/**
 * Compute the Merkle root over an ordered list of claim digests (lowercase
 * hex). For an empty list returns SHA-256("") (RFC 6962 convention for the
 * empty-tree root) so consumers do not need to special-case empty bundles.
 */
export function computeMerkleRoot(claimDigestsHex: readonly string[]): string {
  if (claimDigestsHex.length === 0) {
    return createHash("sha256").update("").digest("hex");
  }
  let level: Uint8Array[] = claimDigestsHex.map((h) => _hashLeaf(h));
  while (level.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i + 1 < level.length; i += 2) {
      const a = level[i];
      const b = level[i + 1];
      if (a === undefined || b === undefined) {
        throw new Error("internal merkle indexing error");
      }
      nextLevel.push(_hashInternal(a, b));
    }
    if (level.length % 2 === 1) {
      const last = level[level.length - 1];
      if (last !== undefined) {
        nextLevel.push(last);
      }
    }
    level = nextLevel;
  }
  const root = level[0];
  if (root === undefined) {
    throw new Error("internal merkle empty-level error");
  }
  return _bytesToHex(root);
}

/**
 * Verify a Merkle inclusion proof against a claimed tree root.
 *
 * Returns true iff the recomputation equals `claimedRootHex` byte-for-byte.
 * Throws on malformed numeric inputs (negative index, leaf_index >=
 * tree_size). Returns false on a digest-mismatch verdict so consumers can
 * treat the verdict as a structured outcome rather than an exception.
 */
export function verifyInclusionProof(args: {
  leafIndex: number;
  leafDigestHex: string;
  proofPath: readonly string[];
  treeSize: number;
  claimedRootHex: string;
}): boolean {
  const { leafIndex, leafDigestHex, proofPath, treeSize, claimedRootHex } = args;
  if (leafIndex < 0) {
    throw new Error(`leafIndex must be >= 0, got ${leafIndex}`);
  }
  if (treeSize <= 0) {
    throw new Error(`treeSize must be > 0, got ${treeSize}`);
  }
  if (leafIndex >= treeSize) {
    throw new Error(`leafIndex ${leafIndex} >= treeSize ${treeSize}`);
  }
  let node = _hashLeaf(leafDigestHex);
  const claimedRoot = _hexToBytes(claimedRootHex);
  let idx = leafIndex;
  let last = treeSize - 1;
  // Walk up the tree driven by GEOMETRY, not by proof length (RFC 6962
  // sec 2.1.1). At each level, `last` is the index of the rightmost node
  // and `idx` is our position. A node with no sibling at a level -- the
  // rightmost node when the level has an odd count, i.e.
  // `idx === last && idx % 2 === 0` -- is the "lonely leaf": it is promoted
  // verbatim with NO sibling and NO proof entry. We must NOT consume a
  // proof entry or hash in that case; we just rise a level. Only when a
  // real sibling exists do we consume one proof entry and hash. Driving by
  // proof length (the previous implementation) mis-rejected valid proofs
  // for non-power-of-two trees because it consumed a phantom entry at
  // promotion levels.
  let cursor = 0;
  while (last > 0) {
    if (idx === last && idx % 2 === 0) {
      // Lonely promoted node: rise without a sibling or proof entry.
      idx = Math.floor(idx / 2);
      last = Math.floor(last / 2);
      continue;
    }
    // A sibling exists at this level: it must be supplied by the proof.
    if (cursor >= proofPath.length) {
      // Proof is truncated: a required sibling is missing.
      return false;
    }
    const siblingHex = proofPath[cursor];
    cursor += 1;
    if (siblingHex === undefined) {
      return false;
    }
    const sibling = _hexToBytes(siblingHex);
    node =
      idx % 2 === 1
        ? _hashInternal(sibling, node)
        : _hashInternal(node, sibling);
    idx = Math.floor(idx / 2);
    last = Math.floor(last / 2);
  }
  // The proof must be FULLY consumed; leftover entries mean the proof
  // carried more siblings than the tree geometry needs (a forger could
  // otherwise pad a proof with junk the verifier ignores).
  if (cursor !== proofPath.length) {
    return false;
  }
  if (node.length !== claimedRoot.length) {
    return false;
  }
  for (let i = 0; i < node.length; i++) {
    if (node[i] !== claimedRoot[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Build the inclusion proof for `claimDigestsHex[leafIndex]` (test-only
 * helper; production proofs come from the witness service).
 */
export function buildInclusionProof(args: {
  leafIndex: number;
  claimDigestsHex: readonly string[];
}): string[] {
  const { leafIndex, claimDigestsHex } = args;
  const n = claimDigestsHex.length;
  if (leafIndex < 0 || leafIndex >= n) {
    throw new Error(`leafIndex ${leafIndex} out of range for treeSize ${n}`);
  }
  let level: Uint8Array[] = claimDigestsHex.map((h) => _hashLeaf(h));
  const proof: string[] = [];
  let idx = leafIndex;
  let last = n - 1;
  while (last > 0) {
    if (idx % 2 === 1) {
      const sib = level[idx - 1];
      if (sib === undefined) {
        throw new Error("internal merkle proof index error");
      }
      proof.push(_bytesToHex(sib));
    } else if (idx + 1 <= last) {
      const sib = level[idx + 1];
      if (sib === undefined) {
        throw new Error("internal merkle proof index error");
      }
      proof.push(_bytesToHex(sib));
    }
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i + 1 < level.length; i += 2) {
      const a = level[i];
      const b = level[i + 1];
      if (a === undefined || b === undefined) {
        throw new Error("internal merkle indexing error");
      }
      nextLevel.push(_hashInternal(a, b));
    }
    if (level.length % 2 === 1) {
      const tail = level[level.length - 1];
      if (tail !== undefined) {
        nextLevel.push(tail);
      }
    }
    level = nextLevel;
    idx = Math.floor(idx / 2);
    last = Math.floor(last / 2);
  }
  return proof;
}
