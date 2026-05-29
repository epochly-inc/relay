/**
 * Unit tests for the @epochly/relay-sidecar-bundle public surface
 * (`src/index.ts`).
 *
 * These exercise the real, load-bearing constants and the pure
 * `cellSlug` derivation that downstream tooling (the `rly
 * verify-install` companion, sub-feature w12.6) and the launcher both
 * consume. They guard:
 *
 *   - VAL-W12-025 ordering invariant via the two distinct error codes
 *     (digest vs Sigstore), so a regression that collapses them into a
 *     single code is caught.
 *   - VAL-W12-020 canonical four-arch matrix shape + immutability.
 *   - CLAUDE.md keystone invariant #11 / banned pattern #13: the
 *     default trust anchor URL must remain
 *     `https://relay.epochly.com/.well-known/jwks.json`. A routine PR
 *     that changes it is a board-level decision; this test fails loudly
 *     if it drifts.
 *   - `cellSlug` parity with the `BuildCell.slug` derivation in
 *     `scripts/build-sidecar-bundle.py` (`${os}-${arch}`).
 *
 * Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
 */

import { describe, expect, it } from "vitest";

import {
  CANONICAL_MATRIX,
  DEFAULT_TRUST_ANCHOR_URL,
  ERR_DIGEST_MISMATCH,
  ERR_SIGSTORE_VERIFY,
  cellSlug,
} from "../src/index.js";

describe("DEFAULT_TRUST_ANCHOR_URL (keystone invariant #11)", () => {
  it("is the canonical Relay OSS verifier JWKS endpoint", () => {
    // Changing this is a board-level decision (banned pattern #13),
    // not a routine PR. The test pins the value so any drift is caught.
    expect(DEFAULT_TRUST_ANCHOR_URL).toBe(
      "https://relay.epochly.com/.well-known/jwks.json",
    );
  });

  it("is an https URL terminating in the well-known JWKS path", () => {
    const parsed = new URL(DEFAULT_TRUST_ANCHOR_URL);
    expect(parsed.protocol).toBe("https:");
    expect(parsed.pathname).toBe("/.well-known/jwks.json");
  });
});

describe("CANONICAL_MATRIX (VAL-W12-020 four-arch matrix)", () => {
  it("contains exactly the four canonical (os, arch) cells", () => {
    expect(CANONICAL_MATRIX).toEqual([
      { os: "macos", arch: "arm64" },
      { os: "linux", arch: "x86_64" },
      { os: "linux", arch: "arm64" },
      { os: "windows", arch: "x86_64" },
    ]);
  });

  it("does NOT include macos-x86_64 (removed by board-level decision)", () => {
    const hasIntelMac = CANONICAL_MATRIX.some(
      (cell) => cell.os === "macos" && cell.arch === "x86_64",
    );
    expect(hasIntelMac).toBe(false);
  });

  it("is frozen so the matrix cannot be mutated at runtime", () => {
    expect(Object.isFrozen(CANONICAL_MATRIX)).toBe(true);
    expect(() => {
      // @ts-expect-error -- intentionally probing runtime immutability.
      CANONICAL_MATRIX.push({ os: "macos", arch: "x86_64" });
    }).toThrow();
    expect(CANONICAL_MATRIX).toHaveLength(4);
  });
});

describe("VAL-W12-025 diagnostic error codes", () => {
  it("digest and Sigstore failures carry distinct codes", () => {
    expect(ERR_DIGEST_MISMATCH).toBe("RELAY-RELEASE-025-DIGEST");
    expect(ERR_SIGSTORE_VERIFY).toBe("RELAY-RELEASE-025-SIGSTORE");
    // Distinctness is the load-bearing property: operators must be able
    // to tell STEP A (digest) from STEP B (Sigstore) failures apart.
    expect(ERR_DIGEST_MISMATCH).not.toBe(ERR_SIGSTORE_VERIFY);
  });
});

describe("cellSlug (BuildCell.slug parity)", () => {
  it("joins os and arch with a single hyphen", () => {
    expect(cellSlug("linux", "x86_64")).toBe("linux-x86_64");
    expect(cellSlug("macos", "arm64")).toBe("macos-arm64");
    expect(cellSlug("windows", "x86_64")).toBe("windows-x86_64");
  });

  it("produces a stable slug for every cell in the canonical matrix", () => {
    const slugs = CANONICAL_MATRIX.map((cell) => cellSlug(cell.os, cell.arch));
    expect(slugs).toEqual([
      "macos-arm64",
      "linux-x86_64",
      "linux-arm64",
      "windows-x86_64",
    ]);
    // No two canonical cells may collapse to the same asset slug,
    // otherwise the launcher could download the wrong binary.
    expect(new Set(slugs).size).toBe(slugs.length);
  });
});
