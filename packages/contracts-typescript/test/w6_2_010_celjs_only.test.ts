// VAL-W6-010 (transitioned at M6 WS-I): the wasm engine is the ONLY TS CEL
// evaluator.
//
// At W6 the contract was "cel-js is the only TS CEL evaluator". M6 WS-I removes
// the legacy cel-js engine entirely, so the transitioned contract is the
// inverse single-engine invariant: the TS contract-evaluation path imports NO
// CEL library at all (the wasm engine is a vendored `.wasm` + `.mjs` loader,
// not an npm CEL package), the factory's only constructable engine is the
// wasm backend, and a repo grep under `packages/contracts-typescript/` and
// `packages/sdk-typescript/` returns zero hits for ANY JS CEL library
// (including the removed cel-js).
//
// Evidence: vitest exit code, grep result count = 0, the factory constructs
// WasmCelBackend, and no package.json declares a CEL-library dependency.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");

function* walkSource(root: string): Generator<string> {
  for (const entry of readdirSync(root)) {
    if (
      entry === "node_modules" ||
      entry === "dist" ||
      entry === ".vitest-cache"
    ) {
      continue;
    }
    const full = join(root, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      yield* walkSource(full);
    } else if (
      full.endsWith(".ts") ||
      full.endsWith(".tsx") ||
      full.endsWith(".mts") ||
      full.endsWith(".cts") ||
      full.endsWith(".mjs")
    ) {
      yield full;
    }
  }
}

// JS CEL PACKAGE specifiers observed in the npm registry, INCLUDING the removed
// cel-js. A live import of a BARE specifier (an npm package, not a relative
// path) for any of these is a single-engine-invariant violation post-M6. The
// patterns deliberately anchor the specifier on the OPENING quote (`['"]cel-js`)
// so they match only bare-package imports -- a relative import of the vendored
// wasm loader (e.g. `from "../../cel-wasm/typescript/relay-cel-wasm.mjs"`) is a
// PATH, not a package, and is NOT flagged.
const FORBIDDEN_CEL_IMPORT_PATTERNS: RegExp[] = [
  /\bfrom\s+['"]cel-js['"]/m,
  /\bimport\(\s*['"]cel-js['"]\s*\)/m,
  /\bfrom\s+['"]@buf\/google_cel\b/m,
  /\bfrom\s+['"]google-cel['"]/m,
  /\bfrom\s+['"]cel-spec['"]/m,
  /\bfrom\s+['"]@google\/cel['"]/m,
];

describe("VAL-W6-010 (M6 WS-I): the wasm engine is the only TS CEL evaluator", () => {
  let ev: WasmCelBackend | null = null;

  afterEach(async () => {
    if (ev !== null) {
      await ev.dispose();
      ev = null;
    }
  });

  test("the factory's only constructable engine is the wasm backend", () => {
    ev = makeCelEvaluator();
    expect(ev).toBeInstanceOf(WasmCelBackend);
    expect(ev.constructor.name).toBe("WasmCelBackend");
    expect(ev.timeoutMs).toBeGreaterThan(0);
  });

  test("no JS CEL library is imported under contracts-typescript or sdk-typescript (cel-js removed)", () => {
    const roots = [
      join(REPO_ROOT, "packages", "contracts-typescript", "src"),
      join(REPO_ROOT, "packages", "contracts-typescript", "test"),
      join(REPO_ROOT, "packages", "sdk-typescript", "src"),
      join(REPO_ROOT, "packages", "sdk-typescript", "test"),
    ];
    const hits: string[] = [];
    for (const root of roots) {
      let exists = true;
      try {
        statSync(root);
      } catch {
        exists = false;
      }
      if (!exists) {
        continue;
      }
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

  test("no package.json under contracts-typescript declares a cel-js dependency", () => {
    const pkg = JSON.parse(
      readFileSync(join(PKG_ROOT, "package.json"), "utf-8"),
    ) as {
      dependencies?: Record<string, unknown>;
      devDependencies?: Record<string, unknown>;
    };
    const allDeps = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
    };
    expect(Object.keys(allDeps)).not.toContain("cel-js");
  });
});
