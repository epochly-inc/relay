/**
 * Release-manifest and bundle-entry types for the npx wrapper (W4.1).
 *
 * Wire shape of the signed release manifest fetched from
 * ``packages/sdk-typescript/release-manifest.url``. The hosted manifest
 * service emits this JSON with a Sigstore bundle alongside (a separate
 * ``manifest.json.sigstore`` cosign-bundle) so the wrapper can verify the
 * manifest itself before trusting any entry digest.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

/** Supported sidecar bundle OS+arch tuples (5 cells, per VAL-W4-006). */
export type SupportedOs = "darwin" | "linux" | "win32";
export type SupportedArch = "x64" | "arm64";

/** A single bundle entry: one OS+arch combination + its expected digest. */
export interface BundleEntry {
  readonly os: SupportedOs;
  readonly arch: SupportedArch;
  /** Absolute URL of the bundle binary (zip / tarball). */
  readonly url: string;
  /** Lowercase SHA-256 hex of the bundle bytes. */
  readonly sha256: string;
  /** Bytes of the binary; used as a sanity check. */
  readonly size_bytes: number;
  /** Cosign-bundle URL for the Sigstore signature over this entry's digest. */
  readonly sigstore_url: string;
}

export interface ReleaseManifest {
  readonly schema_version: "relay.sidecar_bundle_manifest.v1";
  /** Manifest emission time (RFC 3339). */
  readonly emitted_at: string;
  /** Sidecar version this manifest describes. */
  readonly sidecar_version: string;
  /** Default trust root for Sigstore verification of bundle signatures. */
  readonly trust_root: string;
  readonly bundles: ReadonlyArray<BundleEntry>;
}

/** 5x3 supported matrix (per VAL-W4-006). */
export const SUPPORTED_OS_ARCH: ReadonlyArray<{ os: SupportedOs; arch: SupportedArch }> =
  Object.freeze([
    Object.freeze({ os: "darwin" as const, arch: "x64" as const }),
    Object.freeze({ os: "darwin" as const, arch: "arm64" as const }),
    Object.freeze({ os: "linux" as const, arch: "x64" as const }),
    Object.freeze({ os: "linux" as const, arch: "arm64" as const }),
    Object.freeze({ os: "win32" as const, arch: "x64" as const }),
  ]);

/** Default trust root per CLAUDE.md banned pattern #13 + VAL-W4-008. */
export const DEFAULT_TRUST_ROOT = "relay.epochly.com";

/** Default cache TTL in seconds (24h) for VAL-W4-011b. */
export const DEFAULT_BUNDLE_VERIFY_TTL_SEC = 24 * 60 * 60;
