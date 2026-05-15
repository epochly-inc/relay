// VAL-W6-010: cel-js is the only TS CEL evaluator.
//
// The TS contract-evaluation path MUST import from `cel-js` (or its
// pinned fork) and MUST NOT import any second CEL implementation. A
// repo grep under `packages/sdk-typescript/` and
// `packages/contracts-typescript/` returns zero hits for alternate
// CEL libraries.
//
// Evidence: vitest exit code, grep result count = 0,
// `npm ls cel-js` shows a single resolved version.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { RelayCelEvaluator } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");

function* walkSource(root: string): Generator<string> {
  for (const entry of readdirSync(root)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".vitest-cache") {
      continue;
    }
    const full = join(root, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      yield* walkSource(full);
    } else if (full.endsWith(".ts") || full.endsWith(".tsx") || full.endsWith(".mts") || full.endsWith(".cts")) {
      yield full;
    }
  }
}

const FORBIDDEN_CEL_IMPORT_PATTERNS: RegExp[] = [
  // Other JS CEL packages observed in the npm registry. Add here if a
  // second package ever ships under a similar name.
  /^\s*import\s+[^;]*\bfrom\s+['"]@buf\/google_cel\b/m,
  /^\s*import\s+[^;]*\bfrom\s+['"]google-cel\b/m,
  /^\s*import\s+[^;]*\bfrom\s+['"]cel-spec\b/m,
  /^\s*import\s+[^;]*\bfrom\s+['"]@google\/cel\b/m,
  // Defensive: any "cel" package that is NOT exactly cel-js.
  /^\s*import\s+[^;]*\bfrom\s+['"](?:[^'"]*\/)?cel(?:-(?!js)[a-z]+)\b/m,
];

describe("VAL-W6-010: cel-js is the only TS CEL evaluator", () => {
  test("RelayCelEvaluator constructs without error (cel-js path is exercised)", () => {
    // Smoke check that the cel-js import resolves at module load.
    const ev = new RelayCelEvaluator();
    expect(ev.timeoutMs).toBeGreaterThan(0);
  });

  test("no alternate CEL library imports under contracts-typescript or sdk-typescript", () => {
    const roots = [
      join(REPO_ROOT, "packages", "contracts-typescript", "src"),
      join(REPO_ROOT, "packages", "contracts-typescript", "test"),
      join(REPO_ROOT, "packages", "sdk-typescript", "src"),
      join(REPO_ROOT, "packages", "sdk-typescript", "test"),
    ];
    const hits: string[] = [];
    for (const root of roots) {
      for (const file of walkSource(root)) {
        const text = readFileSync(file, "utf-8");
        for (const pattern of FORBIDDEN_CEL_IMPORT_PATTERNS) {
          if (pattern.test(text)) {
            hits.push(`${file}: ${pattern.source}`);
          }
        }
      }
    }
    expect(hits).toEqual([]);
  });

  test("npm ls cel-js shows a single resolved version", () => {
    // Run from the repo root where the workspaces lockfile lives.
    let out: string;
    try {
      out = execFileSync(
        "npm",
        ["ls", "cel-js", "--workspaces", "--include-workspace-root", "--json"],
        { cwd: REPO_ROOT, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] },
      );
    } catch (e) {
      // npm ls exits non-zero when peer deps are unmet but still
      // emits the JSON tree on stdout. Capture stdout from the
      // exception object.
      const err = e as { stdout?: string | Buffer };
      const stdout = err?.stdout;
      if (stdout === undefined) {
        throw e;
      }
      out = typeof stdout === "string" ? stdout : stdout.toString("utf-8");
    }
    // Walk every nested `dependencies` map and collect each unique
    // cel-js version string. The npm ls --json output nests packages
    // arbitrarily deep when --workspaces is given, so we must recurse
    // through every package regardless of name (not only the cel-js
    // sub-tree).
    const tree = JSON.parse(out) as unknown;
    const versions = new Set<string>();
    function walk(node: unknown): void {
      if (node === null || typeof node !== "object") {
        return;
      }
      const obj = node as Record<string, unknown>;
      const dependencies = obj["dependencies"];
      if (
        dependencies !== null &&
        dependencies !== undefined &&
        typeof dependencies === "object"
      ) {
        const deps = dependencies as Record<string, unknown>;
        for (const depName of Object.keys(deps)) {
          const dep = deps[depName];
          if (depName === "cel-js" && dep !== null && typeof dep === "object") {
            const v = (dep as Record<string, unknown>)["version"];
            if (typeof v === "string") {
              versions.add(v);
            }
          }
          // Always recurse so nested workspace packages are also
          // visited.
          walk(dep);
        }
      }
    }
    walk(tree);
    // At least one resolved version (we depend on it); exactly one
    // unique version (no parallel-installed alternates).
    expect(versions.size).toBe(1);
  });
});
