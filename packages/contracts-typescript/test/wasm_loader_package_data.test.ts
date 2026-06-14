// WS-G packaging (LOADER half): the `.mjs` wasm LOADER shipped as
// @epochly/relay-contracts package data, resolvable from an INSTALLED package.
//
// Completes the fresh-install LOAD story (TypeScript mirror of the Python
// test_wasm_loader_package_data.py). The prior WS-G TS feature vendored
// relay_cel_wasm.wasm as @epochly/relay-contracts package data (src/_wasm/,
// shipped via `files`) -- but NOT the `.mjs` LOADER module. The loader lived
// only at the REPO sibling path packages/cel-wasm/typescript/relay-cel-wasm.mjs
// (NOT in the package `files`), so an installed @epochly/relay-contracts
// resolved the `.wasm` yet could NOT construct the wasm backend: the loader was
// absent from every packaged path, and the repo sibling does not exist in an
// install. Result: a fresh `npm install @epochly/relay-contracts` located the
// wasm but could not LOAD it.
//
// This module vendors the canonical loader as a git-tracked package-data copy at
// src/_wasm/relay-cel-wasm.mjs, adds it to package.json `files`, and updates the
// host loader-path resolvers (wasm-evaluator.defaultLoaderPath /
// pipeline.loaderUrl) to PREFER the packaged loader (resolvable from an installed
// package) with the repo sibling as a dev fallback. A BYTE-IDENTITY drift guard
// asserts the vendored copy equals the canonical
// packages/cel-wasm/typescript/relay-cel-wasm.mjs, so CI fails on drift
// (mirroring the Python loader guard).
//
// Covers (all offline, deterministic plumbing -- no network, no build):
//   - the loader package-data relpath constant + resolver exist and return the
//     concrete on-disk loader path (the installed-package resolution);
//   - defaultLoaderPath() (wasm-evaluator) and the pipeline loader URL both
//     point at the PACKAGED loader when present (NOT the repo sibling);
//   - byte-identity drift guard: the vendored copy == the canonical loader;
//   - package.json `files` ships the loader (survives `npm pack`);
//   - the resolver is non-throwing (returns null) for an absent loader.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  WASM_LOADER_PACKAGE_DATA_RELPATH,
  resolvePackagedLoaderPath,
} from "../src/wasm-artifact.js";
import { defaultLoaderPath } from "../src/wasm-evaluator.js";
import { resolveLoaderUrl } from "../src/pipeline.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const PACKAGE_JSON_PATH = resolve(PACKAGE_ROOT, "package.json");

// The canonical loader source -- the single source of truth the vendored copy
// duplicates. Both hosts (Python loose module, this TS sibling) consume the SAME
// loader bytes; the drift guard fails CI the moment the two diverge.
const CANONICAL_LOADER = resolve(
  PACKAGE_ROOT,
  "..",
  "cel-wasm",
  "typescript",
  "relay-cel-wasm.mjs",
);

// The vendored package-data copy (ships in the tarball via `files`).
const VENDORED_LOADER = resolve(
  PACKAGE_ROOT,
  "src",
  "_wasm",
  "relay-cel-wasm.mjs",
);

function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// --- loader package-data relpath + resolver ----------------------------------

describe("WS-G loader package data: relpath constant + resolver", () => {
  test("the loader relpath constant points at src/_wasm/relay-cel-wasm.mjs", () => {
    expect(WASM_LOADER_PACKAGE_DATA_RELPATH).toBe(
      "src/_wasm/relay-cel-wasm.mjs",
    );
  });

  test("resolvePackagedLoaderPath() returns the concrete on-disk vendored loader", () => {
    const resolved = resolvePackagedLoaderPath();
    expect(resolved).not.toBeNull();
    expect(existsSync(resolved as string)).toBe(true);
    // It is the vendored copy under package data, NOT the repo sibling.
    expect(resolved).toBe(VENDORED_LOADER);
  });

  test("resolvePackagedLoaderPath(absent) returns null (non-throwing, no ENOENT)", () => {
    const resolved = resolvePackagedLoaderPath(
      "/nonexistent/relay-cel-wasm__absent__.mjs",
    );
    expect(resolved).toBeNull();
  });
});

// --- host loader-path resolution prefers the packaged loader -----------------

describe("WS-G loader package data: host resolvers prefer the packaged loader", () => {
  test("defaultLoaderPath() (wasm-evaluator) resolves to the PACKAGED loader, not the repo sibling", () => {
    // With the vendored loader present (it ships in package data), the backend
    // host must resolve the PACKAGED loader so an installed package can
    // construct the wasm backend WITHOUT the repo sibling path.
    const path = defaultLoaderPath();
    expect(path).toBe(VENDORED_LOADER);
    expect(existsSync(path)).toBe(true);
  });

  test("the pipeline loader URL resolves to the PACKAGED loader (file:// URL of the vendored copy)", () => {
    // pipeline.evaluateUdfOutputs imports the loader from this URL; it must
    // target the packaged loader so an installed package's wasm path works.
    const url = resolveLoaderUrl();
    // The URL is a file:// URL whose path is the vendored loader.
    expect(url.startsWith("file://")).toBe(true);
    expect(fileURLToPath(url)).toBe(VENDORED_LOADER);
  });
});

// --- byte-identity drift guard (mirrors the Python loader guard) -------------

describe("WS-G loader package data: byte-identity drift guard", () => {
  test("the vendored loader is byte-identical to the canonical packages/cel-wasm/typescript/relay-cel-wasm.mjs", () => {
    // Approach: a git-tracked vendored COPY of the canonical loader. This guard
    // fails CI the moment the two diverge -- no silent drift between the shipped
    // loader and its single canonical source (mirrors the Python
    // test_wasm_loader_vendored_copy_is_byte_identical_to_canonical).
    expect(existsSync(CANONICAL_LOADER)).toBe(true);
    expect(existsSync(VENDORED_LOADER)).toBe(true);
    const vendored = readFileSync(VENDORED_LOADER);
    const canonical = readFileSync(CANONICAL_LOADER);
    expect(sha256Hex(vendored)).toBe(sha256Hex(canonical));
    expect(vendored.equals(canonical)).toBe(true);
  });
});

// --- package.json files ships the loader -------------------------------------

describe("WS-G loader package data: package.json files ships the loader", () => {
  test("package.json files includes the loader so it survives npm pack into the tarball", () => {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON_PATH, "utf8")) as {
      files?: string[];
    };
    const files = pkg.files ?? [];
    const filesJson = JSON.stringify(files);
    // The loader lives under src/_wasm/; `files` must include either the loader
    // path directly or a directory (src or src/_wasm) that contains it.
    const loaderInFiles =
      filesJson.includes("relay-cel-wasm.mjs") ||
      files.includes("src") ||
      files.includes("src/_wasm") ||
      files.includes("src/_wasm/relay-cel-wasm.mjs");
    expect(loaderInFiles).toBe(true);
  });
});

// --- packed-install smoke proof: npm pack ships BOTH the loader AND the wasm --

describe("WS-G loader package data: npm pack ships the loader AND the wasm", () => {
  // `npm pack --dry-run --json` computes the exact tarball file list WITHOUT
  // publishing. We parse it and assert BOTH the package-data wasm AND the
  // package-data `.mjs` loader are present, so an installed @epochly/relay-contracts
  // can BOTH locate the wasm AND construct the wasm backend (the FINDING-1 fix:
  // the loader was missing from every packaged path).
  interface PackedFile {
    path: string;
  }
  interface PackedResult {
    files?: PackedFile[];
  }

  // Compute the tarball file list ONCE for the whole block: `npm pack` spawns a
  // subprocess, so caching it keeps the suite fast and avoids redundant spawns.
  let packedPaths: string[] | null = null;

  // Synchronous backoff without a busy-spin (execFileSync is sync, so we cannot
  // await): block this thread for `ms` via Atomics.wait on a throwaway buffer.
  function sleepSync(ms: number): void {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  }

  function packedFilePaths(): string[] {
    if (packedPaths !== null) {
      return packedPaths;
    }
    // `npm pack --dry-run --json` spawns an npm subprocess that, when several npm
    // processes run concurrently (e.g. a `--workspaces` test run), intermittently
    // fails to parse its own output and exits non-zero with
    // {"error":{"code":"EOF","summary":"did not encounter expected EOF"}} -- a
    // transient npm race, NOT a packaging defect (the test passes in isolation).
    // Retry a few times with a short backoff so the deterministic packaging
    // assertion is not flaky under load.
    let lastErr: unknown = null;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        const stdout = execFileSync("npm", ["pack", "--dry-run", "--json"], {
          cwd: PACKAGE_ROOT,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        });
        const parsed = JSON.parse(stdout) as PackedResult[];
        const entry = parsed[0];
        const files = entry?.files ?? [];
        if (files.length === 0) {
          throw new Error("npm pack --dry-run returned an empty file list");
        }
        packedPaths = files.map((f) => f.path);
        return packedPaths;
      } catch (err) {
        lastErr = err;
        if (attempt < 4) {
          sleepSync(200 * (attempt + 1));
        }
      }
    }
    throw new Error(
      `npm pack --dry-run --json failed after 5 attempts (transient npm race?): ${String(lastErr)}`,
    );
  }

  test("npm pack --dry-run includes both the wasm package data AND the loader package data", () => {
    const paths = packedFilePaths();
    expect(paths.length).toBeGreaterThan(0);
    expect(paths).toContain("src/_wasm/relay_cel_wasm.wasm");
    expect(paths).toContain("src/_wasm/relay-cel-wasm.mjs");
  });

  test("the loader resolution targets the packaged path that npm pack ships (installed-package parity)", () => {
    // The resolver returns the on-disk vendored loader; npm pack ships that same
    // relative path. So an installed package resolves the loader to a file that
    // actually exists in the tarball -- the FINDING-1 load story is closed.
    const resolved = resolvePackagedLoaderPath();
    expect(resolved).toBe(VENDORED_LOADER);
    const paths = packedFilePaths();
    expect(paths).toContain(WASM_LOADER_PACKAGE_DATA_RELPATH);
  });
});
