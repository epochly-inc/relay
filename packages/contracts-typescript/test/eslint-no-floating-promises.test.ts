// VAL-CWC-P2TSGATE-007: no-floating-promises lint enabled (missed-await guard).
//
// The contracts-typescript ESLint config enables
// @typescript-eslint/no-floating-promises as an ERROR so a forgotten await on
// the now-async WasmCelBackend.evaluate() is a LINT ERROR rather than a silent
// unhandled rejection (the HIGH risk-register mitigation: 'TS evaluate() async
// breaking change; missed await').
//
// This suite proves the rule both (a) FIRES on a deliberately-floating-promise
// fixture (eslint exits non-zero, error id is no-floating-promises) and (b) is
// CLEAN on the real source tree (`eslint src` exits 0). The rule is TYPE-AWARE:
// without project/type information typescript-eslint silently no-ops it, so a
// fixture that genuinely fires is the only proof the type-aware wiring works.
//
// We invoke the package-local eslint binary via execFileSync rather than the
// programmatic API so the test exercises the SAME config resolution + flat
// config the manifest `lint` command and CI use.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
// packages/contracts-typescript/
const PKG_ROOT = resolve(HERE, "..");
// The deliberately-floating-promise fixture (NOT under src/, NOT a *.test.ts).
const FIXTURE = resolve(HERE, "fixtures", "floating-promise-sample.ts");
const SRC_DIR = resolve(PKG_ROOT, "src");

// Resolve the eslint CLI entrypoint. eslint 10 does NOT export `./bin/eslint.js`
// as a package subpath (its `exports` map omits it), so we resolve the exported
// `eslint/package.json`, read its `bin.eslint` field, and join it to the package
// directory. This runs the EXACT installed eslint independent of PATH and works
// regardless of npm-workspace hoisting.
function resolveEslintBin(): string {
  const require = createRequire(import.meta.url);
  const pkgJsonPath = require.resolve("eslint/package.json");
  const pkgDir = dirname(pkgJsonPath);
  const pkg = require(pkgJsonPath) as { bin?: { eslint?: string } | string };
  const binEntry =
    typeof pkg.bin === "string" ? pkg.bin : pkg.bin?.eslint ?? "bin/eslint.js";
  return resolve(pkgDir, binEntry);
}

interface EslintRun {
  status: number;
  stdout: string;
  stderr: string;
}

// Run eslint on `target` against the package flat config, capturing the exit
// status without throwing. We always pass --no-error-on-unmatched-pattern off
// (default) and rely on the package eslint.config.mjs being auto-discovered
// from cwd = PKG_ROOT.
function runEslint(target: string, extraArgs: string[] = []): EslintRun {
  const bin = resolveEslintBin();
  try {
    const stdout = execFileSync(
      process.execPath,
      [bin, ...extraArgs, target],
      {
        cwd: PKG_ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return { status: 0, stdout, stderr: "" };
  } catch (err) {
    const e = err as {
      status?: number;
      stdout?: Buffer | string;
      stderr?: Buffer | string;
    };
    return {
      status: typeof e.status === "number" ? e.status : 1,
      stdout: e.stdout ? e.stdout.toString() : "",
      stderr: e.stderr ? e.stderr.toString() : "",
    };
  }
}

describe("VAL-CWC-P2TSGATE-007: no-floating-promises lint", () => {
  test("the proof fixture exists and is not under src/", () => {
    expect(existsSync(FIXTURE)).toBe(true);
    expect(FIXTURE.includes(`${SRC_DIR}/`)).toBe(false);
  });

  test("eslint FIRES no-floating-promises on the deliberately-floating fixture (non-zero exit)", () => {
    const run = runEslint(FIXTURE);
    // The rule MUST fire: a non-zero exit AND the specific rule id in output.
    // A silent no-op (type-aware wiring missing) would exit 0 -> this fails.
    const combined = run.stdout + run.stderr;
    expect(
      run.status,
      `eslint should fail on the floating-promise fixture. ` +
        `status=${run.status}\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`,
    ).not.toBe(0);
    expect(combined).toContain("no-floating-promises");
  });

  test("eslint is CLEAN on the real src/ tree (exit 0, no findings)", () => {
    const run = runEslint(SRC_DIR);
    expect(
      run.status,
      `eslint should be clean on src/. status=${run.status}\n` +
        `stdout:\n${run.stdout}\nstderr:\n${run.stderr}`,
    ).toBe(0);
  });
});
