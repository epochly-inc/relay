/**
 * W4.1 package surface tests.
 *
 *   VAL-W4-001: @epochly/relay public surface snapshot.
 *   VAL-W4-001b: import @epochly/relay produces zero sidecar spawn.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PKG_ROOT = path.resolve(__dirname, "..");
const SNAPSHOT_PATH = path.join(PKG_ROOT, ".api", "v0.1.snapshot.json");

describe("VAL-W4-001: package exports stable v0.1 public surface", () => {
  it("Object.keys(require('@epochly/relay')) matches committed snapshot byte-for-byte", async () => {
    const mod = await import("../src/index.js");
    const observed = Object.keys(mod).sort();
    const snapshot = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, "utf8")) as {
      exports: string[];
    };
    expect(observed).toEqual([...snapshot.exports].sort());
  });

  it("required v0.1 names are all present", async () => {
    const mod = (await import("../src/index.js")) as Record<string, unknown>;
    const required = [
      "Relay",
      "trace",
      "RelayError",
      "RedactionPolicy",
      "ContractResult",
      "Adapters",
      // Four error-envelope subclasses for the v0.1 wire codes.
      "RelayCanonicalStatusForbidden",
      "RelayHandoffIncomplete",
      "RelayEvidenceIncomplete",
      "RelayReplayPrecondition",
    ];
    for (const name of required) {
      expect(mod[name], `missing public export: ${name}`).toBeDefined();
    }
  });

  it("snapshot file is valid JSON and stable", () => {
    const raw = fs.readFileSync(SNAPSHOT_PATH, "utf8");
    const parsed = JSON.parse(raw) as { schema_version: string; exports: string[] };
    expect(parsed.schema_version).toBe("relay.sdk_ts_surface.v0.1");
    expect(Array.isArray(parsed.exports)).toBe(true);
    expect(parsed.exports.length).toBeGreaterThan(0);
  });
});

describe("VAL-W4-001b: import @epochly/relay produces ZERO sidecar spawn", () => {
  it("a fresh node subprocess that only imports the package does not spawn the sidecar or touch the lockfile", () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w41-import-"));
    const tmpRelayHome = path.join(tmpHome, ".relay");
    fs.mkdirSync(tmpRelayHome, { recursive: true });
    const indexPath = path.join(PKG_ROOT, "src", "index.ts");
    const tsxBin = path.join(PKG_ROOT, "..", "..", "node_modules", ".bin", "tsx");
    const useTsx = fs.existsSync(tsxBin);

    // Compile + run a minimal "import only" subprocess. Use either tsx if
    // available, or fall back to a tiny node loader script with esbuild.
    // Since the workspace ships only tsc + vitest, we rely on the
    // pre-compiled dist when available; if not, we use tsx via
    // node --import. To keep this test hermetic we instead invoke node on
    // a tiny on-the-fly compiled JS file emitted from index.ts via tsc.
    const distDir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w41-dist-"));
    const tscBin = path.join(PKG_ROOT, "..", "..", "node_modules", ".bin", "tsc");
    if (!fs.existsSync(tscBin)) {
      throw new Error(
        `expected hoisted tsc binary at ${tscBin}; ` +
          "the workspace install must place tsc in the relay/ root node_modules",
      );
    }
    execFileSync(
      tscBin,
      [
        "--project",
        path.join(PKG_ROOT, "tsconfig.json"),
        "--outDir",
        distDir,
        "--noEmit",
        "false",
        "--module",
        "ESNext",
        "--moduleResolution",
        "Bundler",
        "--declaration",
        "false",
        "--declarationMap",
        "false",
        "--sourceMap",
        "false",
      ],
      { stdio: "pipe" },
    );
    // tsc with rootDir: . on packages/sdk-typescript/tsconfig.json emits
    // under <outDir>/src/index.js.
    const compiledIndex = path.join(distDir, "src", "index.js");
    expect(fs.existsSync(compiledIndex), "index.js should compile").toBe(true);

    // Add a sentinel script that just imports and exits 0.
    const sentinel = path.join(distDir, "_sentinel.mjs");
    fs.writeFileSync(
      sentinel,
      `import "${compiledIndex.replace(/\\/g, "/")}";\nconsole.log("imported");\n`,
    );

    const env = { ...process.env, RELAY_HOME: tmpRelayHome };
    const result = spawnSync(process.execPath, [sentinel], {
      env,
      encoding: "utf8",
      stdio: "pipe",
    });
    expect(result.status, `stderr: ${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("imported");

    // VAL-W4-001b assertions: no lockfile created.
    const lockfile = path.join(tmpRelayHome, "sidecar.lock");
    expect(
      fs.existsSync(lockfile),
      `sidecar lockfile should NOT exist after pure import; found ${lockfile}`,
    ).toBe(false);
    // No subdirectories spawned under RELAY_HOME by the import.
    const after = fs.readdirSync(tmpRelayHome);
    expect(after, "RELAY_HOME directory should remain empty after import").toEqual([]);

    // Suppress unused-variable hints when the optional tsx path is unused.
    void useTsx;
    void indexPath;
  }, 60_000);
});
