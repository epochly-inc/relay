// Compiled-in constants for the Relay offline verifier (TS parity with
// packages/verifier/src/relay_verifier/constants.py).
//
// This module is the SINGLE CANONICAL OCCURRENCE of the default trust-
// anchor JWKS URL literal in the TS verifier package source tree
// (VAL-V2M06-019 grep guard). A source-grep over
// packages/verifier-typescript/src/**/*.ts (excluding test paths) MUST
// return exactly one occurrence of the literal URL string, and that
// occurrence MUST live on the DEFAULT_JWKS_URL assignment below.
//
// Per CLAUDE.md keystone invariant #11 the OSS verifier defaults to the
// spec section AO.4 trust anchor. Per banned pattern #13 changing the
// default constant in a routine PR is CI-blocked; this is a board-level
// decision because every offline verifier in the wild (forks, self-hosted
// deployments, OSS users who never registered with the hosted product)
// treats this URL as the root of trust for evidence-bundle signatures.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export const VERIFIER_PACKAGE_NAME = "@epochly/relay-verifier" as const;

/**
 * The OSS verifier's compiled-in default trust-anchor JWKS URL.
 *
 * Spec: section AO.4 line 6165. Mirrors Python
 * `relay_verifier.constants.DEFAULT_JWKS_URL` byte-for-byte.
 *
 * Changing this constant is a CLAUDE.md banned pattern #13 violation
 * unless approved as a board-level decision. Forks/self-hosters should
 * override the trust anchor at runtime via `resolveJwks({ flagUrl })` or
 * a config file entry `trust_anchor_url = "..."`; see VAL-V2M06-021.
 */
export const DEFAULT_JWKS_URL =
  "https://relay.epochly.com/.well-known/jwks.json" as const;

/** Backwards-compatible alias. */
export const DEFAULT_TRUST_ANCHOR_URL = DEFAULT_JWKS_URL;
