// VAL-PARITY-006: Merkle inclusion-proof verification must model RFC 6962
// lonely-leaf promotion (TS parity with packages/verifier/src/relay_verifier/merkle.py).
//
// Bug (HIGH/correctness): verifyInclusionProof was driven by proofPath length
// -- it consumed exactly one proof entry per loop iteration and advanced
// idx/last once per entry. RFC 6962 sec 2.1 promotes a node with no sibling at
// a level verbatim with NO proof entry ("lonely-leaf"). The verify loop never
// modeled that promotion, so VALID inclusion proofs for non-power-of-two trees
// (e.g. treeSize=3 leafIndex=2, treeSize=5 leafIndex=4) were REJECTED.
//
// Fix: drive the walk by tree GEOMETRY, not proof length. At each level, if the
// current node is the lonely promoted node (idx === last && idx % 2 === 0)
// advance without consuming a proof entry or hashing; otherwise consume one
// sibling and hash. Terminate at last === 0 and require the proof to be fully
// consumed (reject leftover entries) and present (reject truncated proofs).
//
// This suite also asserts Python<->TS parity: the same self-built proofs that
// Python accepts must be accepted by TS, and TS-built proofs must be accepted
// by Python.
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
  buildInclusionProof,
  computeMerkleRoot,
  verifyInclusionProof,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function pyJson<T = unknown>(code: string): T {
  const tmpFile = resolve(
    tmpdir(),
    `relay-parity006-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
  );
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 60_000,
    });
    if ((r.status ?? -1) !== 0) {
      throw new Error(`python helper failed (status=${r.status}): ${r.stderr}`);
    }
    const line = (r.stdout ?? "").trim().split(/\r?\n/).pop() ?? "";
    return JSON.parse(line) as T;
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

function leaves(n: number): string[] {
  return Array.from({ length: n }, (_, i) =>
    createHash("sha256").update(`leaf-${i}`).digest("hex"),
  );
}

describe("VAL-PARITY-006 merkle inclusion-proof lonely-leaf promotion", () => {
  // -------------------------------------------------------------------------
  // RED at base: lonely-leaf promotion levels rejected valid proofs.
  // -------------------------------------------------------------------------

  test("treeSize=3 leafIndex=2 (lonely leaf) verifies true", () => {
    const ls = leaves(3);
    const root = computeMerkleRoot(ls);
    const proof = buildInclusionProof({ leafIndex: 2, claimDigestsHex: ls });
    const leaf = ls[2];
    if (leaf === undefined) throw new Error("indexing");
    expect(
      verifyInclusionProof({
        leafIndex: 2,
        leafDigestHex: leaf,
        proofPath: proof,
        treeSize: 3,
        claimedRootHex: root,
      }),
    ).toBe(true);
  });

  test("treeSize=5 leafIndex=4 (lonely leaf) verifies true", () => {
    const ls = leaves(5);
    const root = computeMerkleRoot(ls);
    const proof = buildInclusionProof({ leafIndex: 4, claimDigestsHex: ls });
    const leaf = ls[4];
    if (leaf === undefined) throw new Error("indexing");
    expect(
      verifyInclusionProof({
        leafIndex: 4,
        leafDigestHex: leaf,
        proofPath: proof,
        treeSize: 5,
        claimedRootHex: root,
      }),
    ).toBe(true);
  });

  for (const treeSize of [3, 5, 6, 7]) {
    test(`every leaf index verifies for non-power-of-two treeSize=${treeSize}`, () => {
      const ls = leaves(treeSize);
      const root = computeMerkleRoot(ls);
      for (let i = 0; i < treeSize; i++) {
        const leaf = ls[i];
        if (leaf === undefined) throw new Error("indexing");
        const proof = buildInclusionProof({ leafIndex: i, claimDigestsHex: ls });
        expect(
          verifyInclusionProof({
            leafIndex: i,
            leafDigestHex: leaf,
            proofPath: proof,
            treeSize,
            claimedRootHex: root,
          }),
        ).toBe(true);
      }
    });
  }

  // -------------------------------------------------------------------------
  // Do NOT over-accept: tampered / malformed proofs must reject.
  // -------------------------------------------------------------------------

  test("tampered sibling in lonely-leaf proof rejects", () => {
    const ls = leaves(5);
    const root = computeMerkleRoot(ls);
    const proof = buildInclusionProof({ leafIndex: 4, claimDigestsHex: ls });
    expect(proof.length).toBeGreaterThan(0);
    const bad = proof[0];
    if (bad === undefined) throw new Error("indexing");
    const flipped = (bad[0] !== "0" ? "0" : "1") + bad.slice(1);
    const tampered = [flipped, ...proof.slice(1)];
    const leaf = ls[4];
    if (leaf === undefined) throw new Error("indexing");
    expect(
      verifyInclusionProof({
        leafIndex: 4,
        leafDigestHex: leaf,
        proofPath: tampered,
        treeSize: 5,
        claimedRootHex: root,
      }),
    ).toBe(false);
  });

  test("extra trailing proof entry rejected (iterator must be fully consumed)", () => {
    const ls = leaves(3);
    const root = computeMerkleRoot(ls);
    const proof = buildInclusionProof({ leafIndex: 2, claimDigestsHex: ls });
    const junk = createHash("sha256").update("junk").digest("hex");
    const leaf = ls[2];
    if (leaf === undefined) throw new Error("indexing");
    expect(
      verifyInclusionProof({
        leafIndex: 2,
        leafDigestHex: leaf,
        proofPath: [...proof, junk],
        treeSize: 3,
        claimedRootHex: root,
      }),
    ).toBe(false);
  });

  test("too-few proof entries rejected (truncated proof)", () => {
    const ls = leaves(5);
    const root = computeMerkleRoot(ls);
    const proof = buildInclusionProof({ leafIndex: 0, claimDigestsHex: ls });
    expect(proof.length).toBeGreaterThanOrEqual(2);
    const truncated = proof.slice(0, -1);
    const leaf = ls[0];
    if (leaf === undefined) throw new Error("indexing");
    expect(
      verifyInclusionProof({
        leafIndex: 0,
        leafDigestHex: leaf,
        proofPath: truncated,
        treeSize: 5,
        claimedRootHex: root,
      }),
    ).toBe(false);
  });

  test("power-of-two trees still verify every index", () => {
    for (const treeSize of [1, 2, 4, 8]) {
      const ls = leaves(treeSize);
      const root = computeMerkleRoot(ls);
      for (let i = 0; i < treeSize; i++) {
        const leaf = ls[i];
        if (leaf === undefined) throw new Error("indexing");
        const proof = buildInclusionProof({ leafIndex: i, claimDigestsHex: ls });
        expect(
          verifyInclusionProof({
            leafIndex: i,
            leafDigestHex: leaf,
            proofPath: proof,
            treeSize,
            claimedRootHex: root,
          }),
        ).toBe(true);
      }
    }
  });

  // -------------------------------------------------------------------------
  // Python <-> TypeScript parity for the corpus sizes {3,5,6,7}.
  // -------------------------------------------------------------------------

  for (const treeSize of [3, 5, 6, 7]) {
    test(`Py-built proof accepted by TS for every index (treeSize=${treeSize})`, () => {
      const ls = leaves(treeSize);
      const root = computeMerkleRoot(ls);
      const py = pyJson<{ root: string; proofs: string[][] }>(
        `import json, sys
from relay_verifier.merkle import build_inclusion_proof, compute_merkle_root
leaves = json.loads(${JSON.stringify(JSON.stringify(ls))})
root = compute_merkle_root(leaves)
proofs = [build_inclusion_proof(leaf_index=i, claim_digests_hex=leaves) for i in range(len(leaves))]
sys.stdout.write(json.dumps({'root': root, 'proofs': proofs}))
`,
      );
      // Roots must agree byte-for-byte.
      expect(py.root).toBe(root);
      for (let i = 0; i < treeSize; i++) {
        const leaf = ls[i];
        const pyProof = py.proofs[i];
        if (leaf === undefined || pyProof === undefined) throw new Error("indexing");
        // TS-built proof must equal Py-built proof (geometry parity).
        const tsProof = buildInclusionProof({ leafIndex: i, claimDigestsHex: ls });
        expect(tsProof).toEqual(pyProof);
        // TS verifier accepts the PYTHON-built proof.
        expect(
          verifyInclusionProof({
            leafIndex: i,
            leafDigestHex: leaf,
            proofPath: pyProof,
            treeSize,
            claimedRootHex: root,
          }),
        ).toBe(true);
      }
    });

    test(`TS-built proof accepted by Py for every index (treeSize=${treeSize})`, () => {
      const ls = leaves(treeSize);
      const root = computeMerkleRoot(ls);
      const tsProofs = Array.from({ length: treeSize }, (_, i) =>
        buildInclusionProof({ leafIndex: i, claimDigestsHex: ls }),
      );
      const py = pyJson<{ verdicts: boolean[] }>(
        `import json, sys
from relay_verifier.merkle import verify_inclusion_proof
leaves = json.loads(${JSON.stringify(JSON.stringify(ls))})
proofs = json.loads(${JSON.stringify(JSON.stringify(tsProofs))})
root = ${JSON.stringify(root)}
verdicts = [
    verify_inclusion_proof(
        leaf_index=i,
        leaf_digest_hex=leaves[i],
        proof_path=proofs[i],
        tree_size=len(leaves),
        claimed_root_hex=root,
    )
    for i in range(len(leaves))
]
sys.stdout.write(json.dumps({'verdicts': verdicts}))
`,
      );
      expect(py.verdicts).toEqual(Array.from({ length: treeSize }, () => true));
    });
  }
});
