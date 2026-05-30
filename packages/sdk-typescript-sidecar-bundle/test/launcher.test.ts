/**
 * Tests for the @epochly/relay-sidecar-bundle verifying launcher
 * (`src/bin/launcher.ts`).
 *
 * The launcher is the `relay-sidecar-bundle` bin entry invoked via
 * `npx @epochly/relay-sidecar-bundle`. It REUSES the already-built
 * @epochly/relay verification machinery (the working `launchSidecar`
 * orchestrator that fetches + signature-verifies the release manifest,
 * runs the digest check FIRST, then the Sigstore + Rekor inclusion proof,
 * and writes the verified binary to the bundle cache). The launcher's
 * additional responsibilities -- exercised here -- are:
 *
 *   1. Host OS/arch detection -> the matching CANONICAL_MATRIX cell,
 *      including the Intel-mac (darwin/x64) -> macos-arm64-via-Rosetta
 *      mapping documented in the package README, and a fail-closed error
 *      on an unknown/unsupported arch.
 *   2. Translating the wrapper's wire codes into the package's documented
 *      diagnostic codes: STEP A digest mismatch -> RELAY-RELEASE-025-DIGEST
 *      (and Sigstore MUST NOT have been called), STEP B Sigstore/Rekor
 *      failure -> RELAY-RELEASE-025-SIGSTORE. (VAL-W12-025 ordering.)
 *   3. Launching ONLY after both verification steps pass: the verified
 *      binary is exec'd as a subprocess and its exit code is propagated.
 *   4. Refusing when the signed release manifest is missing/invalid (the
 *      wrapper fails closed; the launcher surfaces a non-zero exit and
 *      never spawns).
 *
 * Network and process exec are mocked at the boundary: no real download,
 * no real Sigstore round trip, no real subprocess. The cryptographic
 * correctness of the verifier itself is proven in the @epochly/relay
 * suite (w4_7_sigstore_trust_chain.test.ts) against real recorded
 * bundles; these tests prove the launcher's wiring + ordering + exec.
 *
 * Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
 */

import { describe, expect, it, vi } from "vitest";

import {
  ERR_DIGEST_MISMATCH,
  ERR_SIGSTORE_VERIFY,
} from "../src/index.js";
import {
  EXIT_USAGE,
  LauncherDigestMismatch,
  LauncherSigstoreFailure,
  resolveLaunchCell,
  runLauncher,
  type LaunchCell,
  type RunLauncherOptions,
} from "../src/bin/launcher.js";
import type { LaunchDecision } from "@epochly/relay/dist/src/bin/wrapper.js";

const FAKE_DIGEST = "a".repeat(64);
const FAKE_CACHE_DIR = "/tmp/relay-home/sidecar-bundles/" + FAKE_DIGEST;

// A successful LaunchDecision, mirroring @epochly/relay wrapper's
// LaunchDecision (only the fields the launcher consumes are asserted).
function fakeDecision(overrides: Partial<LaunchDecision> = {}): LaunchDecision {
  return {
    action: "launched_fresh",
    source: "network",
    digest: FAKE_DIGEST,
    verified_at: "2026-05-30T00:00:00.000Z",
    bundle_url:
      "https://relay.epochly.com/.well-known/relay-sidecar-bundle/v0.1.20/relay-sidecar-macos-arm64",
    host_os: "darwin",
    host_arch: "arm64",
    trust_root: "relay.epochly.com",
    cache_dir: FAKE_CACHE_DIR,
    cache_hit: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// (a) Arch detection.
// ---------------------------------------------------------------------------
describe("resolveLaunchCell (host OS/arch detection)", () => {
  it("maps native Apple-Silicon mac to macos-arm64", () => {
    const cell = resolveLaunchCell("darwin", "arm64");
    expect(cell.canonical).toEqual({ os: "macos", arch: "arm64" });
    // The wrapper resolves the manifest entry by Node (platform, arch);
    // a native arm64 mac needs no override.
    expect(cell.wrapperHostOs).toBe("darwin");
    expect(cell.wrapperHostArch).toBe("arm64");
    expect(cell.viaRosetta).toBe(false);
  });

  it("maps Intel mac (darwin/x64) to macos-arm64 via Rosetta", () => {
    const cell = resolveLaunchCell("darwin", "x64");
    expect(cell.canonical).toEqual({ os: "macos", arch: "arm64" });
    // The manifest has no darwin/x64 entry; the launcher must ask the
    // wrapper to resolve the arm64 entry so Rosetta runs it.
    expect(cell.wrapperHostOs).toBe("darwin");
    expect(cell.wrapperHostArch).toBe("arm64");
    expect(cell.viaRosetta).toBe(true);
  });

  it("maps linux x64 / arm64 and windows x64 to their canonical cells", () => {
    expect(resolveLaunchCell("linux", "x64").canonical).toEqual({
      os: "linux",
      arch: "x86_64",
    });
    expect(resolveLaunchCell("linux", "arm64").canonical).toEqual({
      os: "linux",
      arch: "arm64",
    });
    expect(resolveLaunchCell("win32", "x64").canonical).toEqual({
      os: "windows",
      arch: "x86_64",
    });
  });

  it("fails closed on an unsupported arch (no Rosetta path)", () => {
    // 32-bit / exotic arches are not in the matrix and have no fallback.
    expect(() => resolveLaunchCell("linux", "arm")).toThrow();
    expect(() => resolveLaunchCell("linux", "ia32")).toThrow();
    expect(() => resolveLaunchCell("win32", "arm64")).toThrow();
    expect(() => resolveLaunchCell("sunos", "x64")).toThrow();
  });

  it("runLauncher returns the usage exit code on an unsupported arch and never verifies or spawns", async () => {
    const launchSidecarImpl =
      vi.fn<NonNullable<RunLauncherOptions["launchSidecarImpl"]>>();
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>();
    const options: RunLauncherOptions = {
      hostOs: "linux",
      hostArch: "arm",
      argv: [],
      launchSidecarImpl,
      spawnImpl,
      stderr: () => {},
    };
    const code = await runLauncher(options);
    expect(code).toBe(EXIT_USAGE);
    expect(launchSidecarImpl).not.toHaveBeenCalled();
    expect(spawnImpl).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// (b) Digest mismatch -> RELAY-RELEASE-025-DIGEST, Sigstore NOT called, no launch.
// ---------------------------------------------------------------------------
describe("STEP A digest-first ordering (VAL-W12-025)", () => {
  it("surfaces RELAY-RELEASE-025-DIGEST on a digest mismatch and never spawns", async () => {
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>();
    // The wrapper throws its digest-mismatch leaf (RELAY-SIDECAR-021) when the
    // downloaded bytes do not match the manifest digest, BEFORE any Sigstore
    // call. The launcher must translate that into the documented code.
    const launchSidecarImpl: NonNullable<RunLauncherOptions["launchSidecarImpl"]> =
      async () => {
        throw new LauncherDigestMismatchProbe();
      };
    const lines: string[] = [];
    const options: RunLauncherOptions = {
      hostOs: "linux",
      hostArch: "x64",
      argv: [],
      launchSidecarImpl,
      spawnImpl,
      stderr: (s: string) => lines.push(s),
    };
    const code = await runLauncher(options);
    expect(code).not.toBe(0);
    expect(spawnImpl).not.toHaveBeenCalled();
    // The diagnostic code on stderr must be the digest code, not the
    // Sigstore one -- a regression collapsing them is caught here.
    const joined = lines.join("");
    expect(joined).toContain(ERR_DIGEST_MISMATCH);
    expect(joined).not.toContain(ERR_SIGSTORE_VERIFY);
  });
});

// ---------------------------------------------------------------------------
// (c) Sigstore/Rekor failure -> RELAY-RELEASE-025-SIGSTORE, no launch.
// ---------------------------------------------------------------------------
describe("STEP B Sigstore/Rekor verification (VAL-W12-025)", () => {
  it("surfaces RELAY-RELEASE-025-SIGSTORE on a Sigstore/Rekor failure and never spawns", async () => {
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>();
    const launchSidecarImpl: NonNullable<RunLauncherOptions["launchSidecarImpl"]> =
      async () => {
        throw new LauncherSigstoreFailureProbe();
      };
    const lines: string[] = [];
    const options: RunLauncherOptions = {
      hostOs: "linux",
      hostArch: "x64",
      argv: [],
      launchSidecarImpl,
      spawnImpl,
      stderr: (s: string) => lines.push(s),
    };
    const code = await runLauncher(options);
    expect(code).not.toBe(0);
    expect(spawnImpl).not.toHaveBeenCalled();
    const joined = lines.join("");
    expect(joined).toContain(ERR_SIGSTORE_VERIFY);
    expect(joined).not.toContain(ERR_DIGEST_MISMATCH);
  });
});

// ---------------------------------------------------------------------------
// (d) Happy path: verified -> exec'd, exit code propagated.
// ---------------------------------------------------------------------------
describe("happy path: verified binary is exec'd and its exit code propagated", () => {
  it("spawns the cached verified binary and returns its exit code", async () => {
    const decision = fakeDecision();
    const launchSidecarImpl =
      vi.fn<NonNullable<RunLauncherOptions["launchSidecarImpl"]>>(async () => decision);
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>(async () => 7);
    const options: RunLauncherOptions = {
      hostOs: "darwin",
      hostArch: "arm64",
      argv: ["--port", "9000"],
      launchSidecarImpl,
      spawnImpl,
      stderr: () => {},
    };
    const code = await runLauncher(options);
    // Verification ran before the spawn.
    expect(launchSidecarImpl).toHaveBeenCalledTimes(1);
    expect(spawnImpl).toHaveBeenCalledTimes(1);
    const [binPath, forwardedArgs] = spawnImpl.mock.calls[0]!;
    // The spawned binary is the verified bundle.bin under the cache dir.
    expect(binPath).toBe(decision.cache_dir + "/bundle.bin");
    // Extra argv is forwarded to the sidecar subprocess verbatim.
    expect(forwardedArgs).toEqual(["--port", "9000"]);
    // The subprocess exit code is propagated unchanged.
    expect(code).toBe(7);
  });

  it("propagates a zero exit code for a clean sidecar exit", async () => {
    const launchSidecarImpl =
      vi.fn<NonNullable<RunLauncherOptions["launchSidecarImpl"]>>(async () =>
        fakeDecision(),
      );
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>(async () => 0);
    const options: RunLauncherOptions = {
      hostOs: "linux",
      hostArch: "x64",
      argv: [],
      launchSidecarImpl,
      spawnImpl,
      stderr: () => {},
    };
    const code = await runLauncher(options);
    expect(code).toBe(0);
  });

  it("requests the arm64 entry when launching on an Intel mac (Rosetta)", async () => {
    const launchSidecarImpl =
      vi.fn<NonNullable<RunLauncherOptions["launchSidecarImpl"]>>(async () =>
        fakeDecision(),
      );
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>(async () => 0);
    const options: RunLauncherOptions = {
      hostOs: "darwin",
      hostArch: "x64",
      argv: [],
      launchSidecarImpl,
      spawnImpl,
      stderr: () => {},
    };
    await runLauncher(options);
    // The wrapper is asked to resolve the arm64 entry, not the (nonexistent)
    // darwin/x64 entry, so Rosetta runs the arm64 binary.
    const passedOpts = launchSidecarImpl.mock.calls[0]![0];
    expect(passedOpts.hostOs).toBe("darwin");
    expect(passedOpts.hostArch).toBe("arm64");
  });
});

// ---------------------------------------------------------------------------
// (e) Missing / invalid signed manifest -> refuse, never spawn.
// ---------------------------------------------------------------------------
describe("fail-closed on a missing/invalid signed release manifest", () => {
  it("returns non-zero and never spawns when the wrapper refuses the manifest", async () => {
    const spawnImpl = vi.fn<NonNullable<RunLauncherOptions["spawnImpl"]>>();
    // The wrapper's verifyManifestSignature throws an "unverified" leaf
    // (RELAY-SIDECAR-020) when the signed manifest is missing/invalid. A
    // generic refusal must NOT be silently swallowed: no spawn, non-zero exit.
    const launchSidecarImpl: NonNullable<RunLauncherOptions["launchSidecarImpl"]> =
      async () => {
        throw new LauncherManifestRefusalProbe();
      };
    const options: RunLauncherOptions = {
      hostOs: "linux",
      hostArch: "x64",
      argv: [],
      launchSidecarImpl,
      spawnImpl,
      stderr: () => {},
    };
    const code = await runLauncher(options);
    expect(code).not.toBe(0);
    expect(spawnImpl).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Probes that emulate the @epochly/relay wrapper's thrown leaves WITHOUT
// importing the heavy crypto module. The launcher branches on the wire
// `code` field, so these carry the wrapper's actual codes.
// ---------------------------------------------------------------------------
class LauncherDigestMismatchProbe extends Error {
  readonly code = "RELAY-SIDECAR-021";
  constructor() {
    super("bundle SHA-256 digest mismatch");
    this.name = "RelaySidecarBundleDigestMismatch";
  }
}
class LauncherSigstoreFailureProbe extends Error {
  readonly code = "RELAY-SIDECAR-020";
  constructor() {
    super("Sigstore bundle failed fail-closed verification");
    this.name = "RelaySidecarBundleUnverified";
  }
}
class LauncherManifestRefusalProbe extends Error {
  readonly code = "RELAY-SIDECAR-020";
  constructor() {
    super("release manifest has no Sigstore signature");
    this.name = "RelaySidecarBundleUnverified";
  }
}

// Type-only references so an accidental removal of the exported launcher
// error classes is caught at compile time.
const _digestType: typeof LauncherDigestMismatch | undefined = undefined;
const _sigstoreType: typeof LauncherSigstoreFailure | undefined = undefined;
const _cellType: LaunchCell | undefined = undefined;
void _digestType;
void _sigstoreType;
void _cellType;
