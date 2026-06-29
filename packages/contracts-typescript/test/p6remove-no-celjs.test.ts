// M6 WS-I guards (TS half): cel-js is fully excised from
// packages/contracts-typescript.
//
// VAL-CWC-P6REMOVE-005: the cel-js runtime dependency is removed from
//   packages/contracts-typescript/package.json (the `dependencies` object
//   carries no 'cel-js' key); the package builds with the wasm engine as its
//   only CEL backend.
// VAL-CWC-P6REMOVE-006: no live cel-js import, no
//   createRequire(...).resolve(cel-js), and no cel-js worker-source
//   construction remains in any src/*.ts; the decisive grep
//   `grep -nE 'cel-js|cel_js|CELJS' src/*.ts` returns no live match (a
//   COMMENT mention counts as a match, so every comment was reworded too).
//   The `checkRegexBackref` / `checkFinite` host guards survive in their
//   engine-agnostic / wasm-backed home (locked decision #4).
// VAL-CWC-P6REMOVE-007: the Node lockfile no longer pins / installs cel-js.
//
// These guards are the structural fence against re-introduction: a future PR
// that re-adds a cel-js import, the dependency pin, the legacy evaluator, or
// even a comment naming the engine fails tier-1.
//
// This is the TS mirror of packages/contracts/tests/test_p6remove_no_celpy.py.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import * as contracts from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_DIR = resolve(HERE, "..");
const SRC_DIR = resolve(PKG_DIR, "src");
const REPO_ROOT = resolve(PKG_DIR, "..", "..");

// The evidence-grep token set for VAL-CWC-P6REMOVE-006 (contract.md):
// 'cel-js|cel_js|CELJS'. A comment mention is a match -- the grep does not
// parse, so the removal must reword every comment too.
const REMOVAL_TOKEN = /cel-js|cel_js|CELJS/;

/** Recursively list every .ts source file under `dir`. */
function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listSourceFiles(full));
    } else if (/\.(?:ts|mts|cts)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

describe("VAL-CWC-P6REMOVE-005: cel-js dependency removed from package.json", () => {
  test("the dependencies object carries no 'cel-js' key", () => {
    const pkg = JSON.parse(
      readFileSync(resolve(PKG_DIR, "package.json"), "utf-8"),
    ) as { dependencies?: Record<string, unknown> };
    const deps = pkg.dependencies ?? {};
    expect(Object.keys(deps)).not.toContain("cel-js");
  });

  test("the decisive package.json grep token is absent (the Evidence command)", () => {
    // Mirrors `grep -nE '"cel-js"|cel-js' package.json` exit 1: even a comment
    // or description mention would fail it, so the description was reworded too.
    const raw = readFileSync(resolve(PKG_DIR, "package.json"), "utf-8");
    const hits = raw
      .split("\n")
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /"cel-js"|cel-js/.test(line))
      .map(({ line, n }) => `line ${n}: ${line.trim()}`);
    expect(hits).toEqual([]);
  });
});

describe("VAL-CWC-P6REMOVE-006: no live cel-js reference in any src/*.ts", () => {
  test("the decisive grep `grep -nE 'cel-js|cel_js|CELJS' src/**/*.ts` returns no live match", () => {
    const offenders: string[] = [];
    for (const file of listSourceFiles(SRC_DIR)) {
      const raw = readFileSync(file, "utf-8");
      raw.split("\n").forEach((line, i) => {
        if (REMOVAL_TOKEN.test(line)) {
          offenders.push(`${file}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    expect(offenders, (
      "VAL-CWC-P6REMOVE-006: removal-token match(es) in the decisive grep " +
      "scope (a comment counts):\n  " + offenders.join("\n  ")
    )).toEqual([]);
  });

  test("the legacy cel-js evaluator class is removed from the public surface", () => {
    expect(Object.keys(contracts)).not.toContain("RelayCelEvaluator");
    expect(
      (contracts as Record<string, unknown>)["RelayCelEvaluator"],
    ).toBeUndefined();
  });

  test("the host guards survive: checkRegexBackref / checkFinite are exported (engine-agnostic home)", async () => {
    // Locked decision #4: the regex-backref pre-screen and the finiteness /
    // safe-integer guard survive in the engine-agnostic host-guards module and
    // are applied on the wasm path. Import them from their new home and assert
    // they still behave.
    const guards = await import("../src/host-guards.js");
    expect(typeof guards.checkRegexBackref).toBe("function");
    expect(typeof guards.checkFinite).toBe("function");
    // checkRegexBackref rejects a backreference fail-closed.
    expect(() => guards.checkRegexBackref('"abba".matches("a(b)\\1")')).toThrow();
    // A clean expression passes.
    expect(() => guards.checkRegexBackref("1 + 2")).not.toThrow();
    // checkFinite rejects an out-of-safe-range integer and a non-finite number.
    expect(() => guards.checkFinite(2 ** 53)).toThrow();
    expect(() => guards.checkFinite(Number.POSITIVE_INFINITY)).toThrow();
    // A safe value round-trips.
    expect(guards.checkFinite(42)).toBe(42);
  });
});

describe("VAL-CWC-P6REMOVE-007: lockfile no longer pins / installs cel-js", () => {
  test("the decisive grep `grep -nE 'node_modules/cel-js|\"cel-js\"' package-lock.json` returns no match", () => {
    const lockPath = resolve(REPO_ROOT, "package-lock.json");
    const raw = readFileSync(lockPath, "utf-8");
    const hits = raw
      .split("\n")
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /node_modules\/cel-js|"cel-js"/.test(line))
      .map(({ line, n }) => `line ${n}: ${line.trim()}`);
    expect(hits, (
      "VAL-CWC-P6REMOVE-007: package-lock.json still references cel-js:\n  " +
      hits.join("\n  ")
    )).toEqual([]);
  });
});
