#!/usr/bin/env node
/**
 * @epochly/relay-sidecar-bundle verifying launcher (`npx
 * @epochly/relay-sidecar-bundle`).
 *
 * This is the `relay-sidecar-bundle` bin entry. It detects the host
 * OS/arch, downloads the matching signed sidecar binary, verifies it, and
 * exec's it. It NEVER runs an unverified binary.
 *
 * REUSE, not reinvention: the download + verify flow is the already-built
 * @epochly/relay `launchSidecar` orchestrator
 * (packages/sdk-typescript/src/bin/wrapper.ts). That function:
 *
 *   1. Fetches the signed aggregated release manifest and verifies its
 *      Sigstore signature over the EXACT manifest bytes, fail-closed,
 *      rooted in the pinned public-good Sigstore trusted root (refusing a
 *      missing/invalid manifest signature). -- manifest.ts + verify.ts
 *   2. Resolves the manifest entry for the host (os, arch).
 *   3. STEP A: computes the downloaded binary's SHA-256 and compares it to
 *      the manifest digest FIRST (RelaySidecarBundleDigestMismatch /
 *      RELAY-SIDECAR-021), before any Sigstore call. -- verify.verifyDigest
 *   4. STEP B: verifies the Sigstore bundle + Rekor inclusion proof
 *      (RelaySidecarBundleUnverified / RELAY-SIDECAR-020). -- verify.ts
 *   5. Persists the verified binary to the digest-keyed bundle cache
 *      (bundle.bin) via the atomic-file primitive. -- cache.ts
 *
 * This launcher delegates ALL of the above to `launchSidecar` (no forked
 * crypto), then:
 *
 *   - Maps the host to a CANONICAL_MATRIX cell (see src/index.ts). The
 *     manifest has no darwin/x64 entry; an Intel mac runs the macos-arm64
 *     binary through Rosetta (per the package README), so the launcher
 *     asks the wrapper to resolve the arm64 entry on darwin/x64.
 *   - Translates the wrapper's wire codes into the package's documented
 *     diagnostic codes so an operator can tell STEP A from STEP B:
 *       RELAY-SIDECAR-021 (digest)   -> RELAY-RELEASE-025-DIGEST
 *       RELAY-SIDECAR-020 (sigstore) -> RELAY-RELEASE-025-SIGSTORE
 *   - On success ONLY, exec's <cache_dir>/bundle.bin as a subprocess,
 *     forwarding argv and propagating the child's exit code.
 *
 * The hosted-mirror / asset-base-url assumption is owned upstream: the
 * release workflow pins every manifest entry's `url` / `sigstore_url` to
 * the versioned hosted mirror prefix, and `launchSidecar` reads the
 * pinned canonical manifest URL. The launcher does not synthesize asset
 * URLs; it trusts the (signature-verified) manifest entries.
 *
 * Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
 * Per CLAUDE.md keystone invariant #11 / banned pattern #13: the default
 * trust anchor is unchanged.
 */

import { spawn } from "node:child_process";
import * as path from "node:path";

import {
  RelaySidecarBundleArchUnsupported,
} from "@epochly/relay";
import {
  launchSidecar as relayLaunchSidecar,
  type LaunchDecision,
  type LaunchSidecarOptions,
} from "@epochly/relay/dist/src/bin/wrapper.js";

import {
  CANONICAL_MATRIX,
  ERR_DIGEST_MISMATCH,
  ERR_SIGSTORE_VERIFY,
  cellSlug,
} from "../index.js";

// Wrapper wire codes the launcher branches on. These are the canonical
// constants from @epochly/relay (packages/sdk-typescript/src/errors.ts);
// duplicated here ONLY as string literals for code-branching (the launcher
// translates them into the package's RELAY-RELEASE-025-* diagnostics). They
// are not a fork of any logic.
const WRAPPER_DIGEST_MISMATCH_CODE = "RELAY-SIDECAR-021";
const WRAPPER_UNVERIFIED_CODE = "RELAY-SIDECAR-020";

/** EX_USAGE: unsupported OS/arch or argv usage error (BSD sysexits.h). */
export const EXIT_USAGE = 64;
/** EX_SOFTWARE: an unexpected internal failure. */
export const EXIT_SOFTWARE = 70;
/** Verification failure (digest or Sigstore) -> exit 1 per the README. */
export const EXIT_VERIFY_FAILED = 1;

/**
 * The launcher's documented digest-mismatch failure (STEP A). Carries the
 * package's RELAY-RELEASE-025-DIGEST code. Wraps the upstream
 * RelaySidecarBundleDigestMismatch (RELAY-SIDECAR-021) so the diagnostic
 * the operator sees distinguishes STEP A from STEP B.
 */
export class LauncherDigestMismatch extends Error {
  readonly code = ERR_DIGEST_MISMATCH;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "LauncherDigestMismatch";
  }
}

/**
 * The launcher's documented Sigstore/Rekor failure (STEP B). Carries the
 * package's RELAY-RELEASE-025-SIGSTORE code. Wraps the upstream
 * RelaySidecarBundleUnverified (RELAY-SIDECAR-020), which the wrapper also
 * raises for a missing/invalid signed release manifest -- both are
 * "the binary's signature chain could not be verified, do not launch".
 */
export class LauncherSigstoreFailure extends Error {
  readonly code = ERR_SIGSTORE_VERIFY;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "LauncherSigstoreFailure";
  }
}

/** A resolved launch target: the canonical cell + the wrapper host override. */
export interface LaunchCell {
  /** The CANONICAL_MATRIX cell (os in {macos,linux,windows}, arch in {arm64,x86_64}). */
  readonly canonical: { readonly os: string; readonly arch: string };
  /** The canonical asset slug (e.g. "macos-arm64") for diagnostics. */
  readonly slug: string;
  /**
   * The (platform, arch) the wrapper must resolve the manifest entry by.
   * Matches Node's process.platform / process.arch vocabulary
   * (darwin/linux/win32 x x64/arm64) because that is what
   * @epochly/relay's manifest parser keys on. For an Intel mac this is the
   * arm64 entry (Rosetta), not the host's x64.
   */
  readonly wrapperHostOs: string;
  readonly wrapperHostArch: string;
  /** True when the host arch differs from the binary arch (Rosetta path). */
  readonly viaRosetta: boolean;
}

/**
 * Map a Node (platform, arch) tuple to the matching CANONICAL_MATRIX cell.
 *
 * Mapping (Node -> canonical):
 *   darwin/arm64 -> macos/arm64
 *   darwin/x64   -> macos/arm64  (Rosetta; the matrix has no macos-x86_64)
 *   linux/x64    -> linux/x86_64
 *   linux/arm64  -> linux/arm64
 *   win32/x64    -> windows/x86_64
 *
 * Any other tuple is unsupported and fails closed with
 * RelaySidecarBundleArchUnsupported (the @epochly/relay typed leaf, so the
 * launcher and the SDK agree on the error shape). There is no silent
 * fallback: an unsupported arch must surface a clear error, never run a
 * wrong-arch binary.
 */
export function resolveLaunchCell(hostOs: string, hostArch: string): LaunchCell {
  // Normalize the canonical (os, arch) and the wrapper host override.
  let canonicalOs: string | null = null;
  let canonicalArch: string | null = null;
  let wrapperHostArch = hostArch;
  let viaRosetta = false;

  if (hostOs === "darwin") {
    canonicalOs = "macos";
    if (hostArch === "arm64") {
      canonicalArch = "arm64";
    } else if (hostArch === "x64") {
      // Intel mac: the matrix has only macos-arm64; run it via Rosetta.
      canonicalArch = "arm64";
      wrapperHostArch = "arm64";
      viaRosetta = true;
    }
  } else if (hostOs === "linux") {
    canonicalOs = "linux";
    if (hostArch === "x64") {
      canonicalArch = "x86_64";
    } else if (hostArch === "arm64") {
      canonicalArch = "arm64";
    }
  } else if (hostOs === "win32") {
    canonicalOs = "windows";
    if (hostArch === "x64") {
      canonicalArch = "x86_64";
    }
  }

  if (canonicalOs === null || canonicalArch === null) {
    throw new RelaySidecarBundleArchUnsupported(
      `host (${hostOs}, ${hostArch}) is not in the canonical sidecar bundle matrix; ` +
        "refusing to launch (no compatible verified binary)",
      {
        details: {
          reason: "host_not_in_matrix",
          host_os: hostOs,
          host_arch: hostArch,
          canonical_matrix: CANONICAL_MATRIX.map((c) => `${c.os}-${c.arch}`),
        },
      },
    );
  }

  // The canonical cell MUST be a frozen matrix member; assert it so a
  // mapping drift (e.g. a typo producing macos-x86_64) fails closed.
  const inMatrix = CANONICAL_MATRIX.some(
    (c) => c.os === canonicalOs && c.arch === canonicalArch,
  );
  if (!inMatrix) {
    throw new RelaySidecarBundleArchUnsupported(
      `resolved cell ${canonicalOs}-${canonicalArch} is not a canonical matrix member`,
      {
        details: {
          reason: "resolved_cell_not_in_matrix",
          host_os: hostOs,
          host_arch: hostArch,
          resolved_os: canonicalOs,
          resolved_arch: canonicalArch,
        },
      },
    );
  }

  return {
    canonical: { os: canonicalOs, arch: canonicalArch },
    slug: cellSlug(canonicalOs, canonicalArch),
    wrapperHostOs: hostOs,
    wrapperHostArch,
    viaRosetta,
  };
}

/** Read a string error code off an unknown thrown value, if present. */
function errorCode(err: unknown): string | undefined {
  if (err !== null && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === "string") return code;
  }
  return undefined;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Translate a thrown wrapper error into the launcher's documented
 * diagnostic. The digest mismatch (STEP A) and the Sigstore / signed-
 * manifest failure (STEP B) get distinct RELAY-RELEASE-025-* codes; any
 * other RelayError (arch unsupported, network unavailable) propagates
 * unchanged so the caller maps it to the correct exit code.
 */
function translateVerificationError(err: unknown): unknown {
  const code = errorCode(err);
  if (code === WRAPPER_DIGEST_MISMATCH_CODE) {
    return new LauncherDigestMismatch(
      `STEP A digest check failed: ${errorMessage(err)}`,
      { cause: err },
    );
  }
  if (code === WRAPPER_UNVERIFIED_CODE) {
    return new LauncherSigstoreFailure(
      `STEP B Sigstore/Rekor verification failed: ${errorMessage(err)}`,
      { cause: err },
    );
  }
  return err;
}

/** Spawn implementation seam. Production exec's the binary; tests inject a fake. */
export type SpawnLaunchedBinaryFn = (
  binaryPath: string,
  args: ReadonlyArray<string>,
) => Promise<number>;

/**
 * Default subprocess launcher: exec the verified binary, inherit stdio, and
 * resolve with the child's exit code. A signal-terminated child resolves to
 * 128 + signal number (POSIX convention) so the parent exit code is still
 * informative. Resources: the child is a detached subprocess whose lifetime
 * is bounded by the resolve/reject of this promise; no file handles are held
 * open by the launcher itself (stdio is inherited).
 */
const SIGNAL_EXIT_OFFSET = 128;
const SIGNAL_NUMBERS: Readonly<Record<string, number>> = {
  SIGINT: 2,
  SIGQUIT: 3,
  SIGKILL: 9,
  SIGTERM: 15,
};

function defaultSpawn(binaryPath: string, args: ReadonlyArray<string>): Promise<number> {
  return new Promise<number>((resolvePromise, reject) => {
    const child = spawn(binaryPath, [...args], { stdio: "inherit" });
    child.on("error", (err) => {
      reject(err);
    });
    child.on("exit", (code, signal) => {
      if (code !== null) {
        resolvePromise(code);
        return;
      }
      if (signal !== null) {
        const num = SIGNAL_NUMBERS[signal] ?? 0;
        resolvePromise(SIGNAL_EXIT_OFFSET + num);
        return;
      }
      // Neither code nor signal (should not happen) -> treat as software error.
      resolvePromise(EXIT_SOFTWARE);
    });
  });
}

/** Options for {@link runLauncher}. All non-test fields default to production. */
export interface RunLauncherOptions {
  /** Host platform; defaults to process.platform. Test seam. */
  hostOs?: string;
  /** Host arch; defaults to process.arch. Test seam. */
  hostArch?: string;
  /** Args forwarded to the launched sidecar subprocess (already sliced). */
  argv?: ReadonlyArray<string>;
  /** Verify+download orchestrator seam. Defaults to @epochly/relay launchSidecar. */
  launchSidecarImpl?: (options: LaunchSidecarOptions) => Promise<LaunchDecision>;
  /** Subprocess launcher seam. Defaults to {@link defaultSpawn}. */
  spawnImpl?: SpawnLaunchedBinaryFn;
  /** Stderr sink (test seam). Defaults to process.stderr.write. */
  stderr?: (line: string) => void;
}

/**
 * Orchestrate one launch: detect arch -> verify+download (reused
 * @epochly/relay flow) -> exec the verified binary. Returns the process
 * exit code; never spawns unless BOTH verification steps passed.
 */
export async function runLauncher(options: RunLauncherOptions = {}): Promise<number> {
  const hostOs = options.hostOs ?? process.platform;
  const hostArch = options.hostArch ?? process.arch;
  const argv = options.argv ?? [];
  const launchImpl = options.launchSidecarImpl ?? relayLaunchSidecar;
  const spawnImpl = options.spawnImpl ?? defaultSpawn;
  const writeErr =
    options.stderr ?? ((line: string) => void process.stderr.write(line));

  // 1. Arch detection -> canonical cell. Fail closed (EX_USAGE) on an
  //    unsupported host. No verification, no spawn.
  let cell: LaunchCell;
  try {
    cell = resolveLaunchCell(hostOs, hostArch);
  } catch (err) {
    const code = errorCode(err) ?? "RELAY-SIDECAR-023";
    writeErr(`[${code}] ${errorMessage(err)}\n`);
    return EXIT_USAGE;
  }

  // 2-5. Reuse the @epochly/relay verify+download orchestrator. It verifies
  //      the signed manifest fail-closed, runs digest-first then Sigstore +
  //      Rekor, and writes the verified binary to the cache. For an Intel mac
  //      we ask it to resolve the arm64 entry (Rosetta).
  let decision: LaunchDecision;
  try {
    const launchOptions: LaunchSidecarOptions = {
      hostOs: cell.wrapperHostOs,
      hostArch: cell.wrapperHostArch,
    };
    decision = await launchImpl(launchOptions);
  } catch (rawErr) {
    const translated = translateVerificationError(rawErr);
    const code = errorCode(translated) ?? "RELAY-SIDECAR-001";
    writeErr(`[${code}] ${errorMessage(translated)}\n`);
    // Arch-unsupported from the wrapper (e.g. manifest missing the entry) is
    // a usage error; network-unavailable maps to a distinct exit; every
    // verification failure (digest / Sigstore / manifest signature) is exit 1.
    if (code === "RELAY-SIDECAR-023") return EXIT_USAGE;
    if (code === "RELAY-SDK-012") return EXIT_USAGE; // trust-root override denied
    if (code === "RELAY-SIDECAR-022") return 3; // network unreachable, no cache
    if (code === ERR_DIGEST_MISMATCH || code === ERR_SIGSTORE_VERIFY) {
      return EXIT_VERIFY_FAILED;
    }
    return EXIT_SOFTWARE;
  }

  // 6. Launch ONLY after verification passed. The verified binary is
  //    bundle.bin under the digest-keyed cache dir.
  const binaryPath = path.join(decision.cache_dir, "bundle.bin");
  if (cell.viaRosetta) {
    writeErr(
      `relay-sidecar-bundle: launching macos-arm64 binary on Intel mac via Rosetta\n`,
    );
  }
  try {
    return await spawnImpl(binaryPath, argv);
  } catch (err) {
    writeErr(
      `[RELAY-SIDECAR-001] failed to exec verified sidecar binary at ${binaryPath}: ${errorMessage(err)}\n`,
    );
    return EXIT_SOFTWARE;
  }
}

/** argv parsing: the launcher forwards everything after the bin name. */
export function launcherArgv(rawArgv: ReadonlyArray<string>): string[] {
  // rawArgv[0] = node, rawArgv[1] = script. Everything else is forwarded to
  // the sidecar subprocess. The launcher itself has no flags of its own at
  // this surface (trust-anchor override is the `rly verify-install`
  // companion's responsibility per the README); unknown flags pass through.
  return rawArgv.slice(2);
}

/** CLI entry: run the launcher and exit with the propagated code. */
export async function main(rawArgv: ReadonlyArray<string>): Promise<number> {
  return runLauncher({ argv: launcherArgv(rawArgv) });
}

// Run if invoked directly (not when imported by tests). Mirrors the
// @epochly/relay sidecar shim's direct-invocation guard.
const isDirect =
  typeof process !== "undefined" &&
  process.argv[1] !== undefined &&
  import.meta.url === `file://${process.argv[1]}`;

if (isDirect) {
  main(process.argv)
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(
        `unhandled: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`,
      );
      process.exit(EXIT_SOFTWARE);
    });
}
