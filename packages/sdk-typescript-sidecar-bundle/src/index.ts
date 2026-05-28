/**
 * @epochly/relay-sidecar-bundle -- public surface.
 *
 * The launcher entry point is the `bin/launcher.ts` script invoked via
 * `npx @epochly/relay-sidecar-bundle`. This module re-exports the
 * verification primitives so downstream tooling (the `rly verify-install`
 * companion in sub-feature w12.6) can reuse the same digest +
 * Sigstore path.
 *
 * Per contract assertion VAL-W12-025 the verification ordering is
 * load-bearing: STEP A (SHA-256 digest check vs the signed release
 * manifest) MUST run BEFORE STEP B (Sigstore + Rekor inclusion proof).
 * Reversing the order produces a confused-deputy where Sigstore
 * validates a binary whose digest does not match the manifest.
 *
 * Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
 * Per CLAUDE.md keystone invariant #11: the default trust anchor is
 * `https://relay.epochly.com/.well-known/jwks.json`; the constant is
 * defined here and consumed by the launcher.
 */

export const DEFAULT_TRUST_ANCHOR_URL: string =
  // CLAUDE.md keystone #11 -- board-level decision to change.
  "https://relay.epochly.com/.well-known/jwks.json";

/**
 * Canonical four-arch matrix per contract assertion VAL-W12-020
 * (revised 2026-05-28).
 *
 * Adding to this matrix requires a board-level decision (orchestrator
 * sidecar-bundle-arch pin). macos-x86_64 was removed on 2026-05-28 by
 * board-level decision (GitHub Intel-macOS runner pool starvation,
 * Apple 2022 Intel discontinuation, Rosetta fallback). See CHANGELOG
 * v0.1.16. Subsequent removals require an equivalent board-level
 * decision.
 */
export const CANONICAL_MATRIX: ReadonlyArray<{ os: string; arch: string }> =
  Object.freeze([
    { os: "macos", arch: "arm64" },
    { os: "linux", arch: "x86_64" },
    { os: "linux", arch: "arm64" },
    { os: "windows", arch: "x86_64" },
  ]);

/**
 * Canonical error codes the launcher emits. The two error codes for
 * VAL-W12-025 are diagnostically distinct so operators know whether
 * the digest or the Sigstore step diverged.
 */
export const ERR_DIGEST_MISMATCH: string = "RELAY-RELEASE-025-DIGEST";
export const ERR_SIGSTORE_VERIFY: string = "RELAY-RELEASE-025-SIGSTORE";

/**
 * Compute the canonical asset slug for an (os, arch) cell.
 * Mirrors the BuildCell.slug derivation in
 * `scripts/build-sidecar-bundle.py` so cross-language consumers
 * agree on the asset name.
 */
export function cellSlug(os: string, arch: string): string {
  return `${os}-${arch}`;
}
