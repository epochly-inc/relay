// WS-G packaging (TypeScript half): the reproducible wasm shipped as
// @epochly/relay-contracts package data, resolvable via package files + exports.
//
// Covers VAL-CWC-P3CORPUS-009 / -011 (M3 P3CORPUS, WS-G) plus the sha-drift +
// cross-host byte-identity guards:
//
//   - 009: the reproducible relay_cel_wasm.wasm (the build.sh deterministic-
//     recipe artifact, sha 49a6a6a2...) is shipped as PACKAGE DATA of
//     @epochly/relay-contracts and is resolvable via the package `files` +
//     `exports` subpath (require.resolve / import.meta.resolve of the declared
//     subpath) so the `.mjs` loader can locate it from an INSTALLED package
//     WITHOUT crate/target/. package.json `files` array AND `exports` map both
//     reference the wasm artifact; the resolved file exists and its sha256
//     equals the pinned sha.
//   - 011: when the packaged wasm cannot be resolved, the WasmCelBackend /
//     loader rejects with a structured RelayCelError carrying the engine-error
//     code (RELAY-CEL-009), NOT a raw ENOENT / unhandled rejection; a sibling
//     assertion confirms the cel-js default path STILL evaluates 1+2==3 with the
//     wasm absent.
//   - drift guard: the packaged TS wasm's sha256 == the pinned constant == the
//     Python pinned sha == the on-disk bytes (a tampered / stale vendored copy
//     FAILS); the vendored TS wasm is byte-identical to the build.sh artifact.
//
// These are offline, deterministic plumbing tests (no network, no build).
// The `-t` selectors the contract evidence commands use:
//     'wasm package data'                     -> 009
//     'wasm missing artifact structured error'-> 011
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import { RelayCelError } from "../src/errors.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";
import {
  WASM_PACKAGE_DATA_SUBPATH,
  WASM_PINNED_SHA256,
  resolvePackagedWasmPath,
} from "../src/wasm-artifact.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const PACKAGE_JSON_PATH = resolve(PACKAGE_ROOT, "package.json");

// The full sha256 of the reproducible build.sh deterministic-recipe artifact, as
// reported by `bash packages/cel-wasm/conformance/build.sh repro` and pinned on
// the PYTHON side (packages/contracts/src/relay_contracts/wasm_artifact.py
// WASM_PINNED_SHA256). The TS package ships the SAME bytes for the npm ecosystem;
// a divergence between this and the TS pinned constant / on-disk sha is a P0.
const EXPECTED_REPRO_SHA =
  "49a6a6a2d3b3fcd50479dfae68ea6eace70a40cc30aa574e6584045c261b7c08";

// The Python vendored copy of the SAME artifact. The byte-identity guard asserts
// the TS vendored copy equals these bytes (one shared truth across ecosystems).
const PYTHON_VENDORED_WASM = resolve(
  PACKAGE_ROOT,
  "..",
  "contracts",
  "src",
  "relay_contracts",
  "_wasm",
  "relay_cel_wasm.wasm",
);

function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// --- VAL-CWC-P3CORPUS-009: wasm package data via files + exports -------------

describe("VAL-CWC-P3CORPUS-009: wasm package data via files + exports", () => {
  test("wasm package data: the exports subpath resolves to an existing file whose sha matches the pinned sha", () => {
    // Resolve the wasm THROUGH the package `exports` subpath (the installed-
    // package resolution: require.resolve of the declared subpath), proving a
    // consumer can locate the artifact without a crate/target/ relative path.
    const require = createRequire(import.meta.url);
    const resolvedViaExports = require.resolve(
      "@epochly/relay-contracts/wasm",
    );
    expect(existsSync(resolvedViaExports)).toBe(true);

    const bytes = readFileSync(resolvedViaExports);
    expect(bytes.length).toBeGreaterThan(0);
    expect(sha256Hex(bytes)).toBe(WASM_PINNED_SHA256);
    expect(WASM_PINNED_SHA256).toBe(EXPECTED_REPRO_SHA);
  });

  test("wasm package data: the resolver helper returns the same on-disk artifact", () => {
    // The resolver the loader/backend uses resolves the package-data wasm
    // independently of CEL_WASM / crate/target/. It must return a concrete,
    // existing path whose bytes hash to the pinned sha.
    const resolved = resolvePackagedWasmPath();
    expect(resolved).not.toBeNull();
    expect(existsSync(resolved as string)).toBe(true);
    const bytes = readFileSync(resolved as string);
    expect(sha256Hex(bytes)).toBe(WASM_PINNED_SHA256);
  });

  test("wasm package data: package.json files AND exports both reference the wasm artifact", () => {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON_PATH, "utf8")) as {
      files?: string[];
      exports?: Record<string, unknown>;
    };

    // `exports` declares a resolvable subpath for the wasm.
    const exportsMap = pkg.exports ?? {};
    expect(Object.keys(exportsMap)).toContain(WASM_PACKAGE_DATA_SUBPATH);
    const exportTarget = JSON.stringify(exportsMap[WASM_PACKAGE_DATA_SUBPATH]);
    expect(exportTarget).toContain("relay_cel_wasm.wasm");

    // `files` includes the wasm so it survives `npm pack` into the tarball.
    // The wasm lives under src/_wasm/; `files` must include either the wasm
    // path directly or a directory (src or src/_wasm) that contains it.
    const files = pkg.files ?? [];
    const filesJson = JSON.stringify(files);
    const wasmInFiles =
      filesJson.includes("relay_cel_wasm.wasm") ||
      files.includes("src") ||
      files.includes("src/_wasm") ||
      files.includes("src/_wasm/relay_cel_wasm.wasm");
    expect(wasmInFiles).toBe(true);
  });

  test("wasm package data: WasmCelBackend evaluates over the package-data wasm (no CEL_WASM, no crate/target)", async () => {
    // The backend resolves its wasm via the package-data resolver by default
    // (no explicit wasmPath, no CEL_WASM in this assertion's scope). It must
    // evaluate a baseline expression correctly through the package-data engine.
    const packaged = resolvePackagedWasmPath();
    expect(packaged).not.toBeNull();
    const backend = new WasmCelBackend({ timeoutMs: 250, wasmPath: packaged as string });
    try {
      const result = await backend.evaluate("1 + 2");
      expect(result).toBe(3);
    } finally {
      await backend.dispose();
    }
  });
});

// --- VAL-CWC-P3CORPUS-011: missing-artifact structured error -----------------

describe("VAL-CWC-P3CORPUS-011: TS wasm backend gated on artifact presence", () => {
  const ABSENT = "/nonexistent/relay_cel_wasm__absent__.wasm";

  test("wasm missing artifact structured error: an absent resolver path rejects with a RelayCelError carrying a RELAY-CEL- code (not raw ENOENT)", async () => {
    const backend = new WasmCelBackend({ timeoutMs: 250, wasmPath: ABSENT });
    let threw: unknown;
    try {
      await backend.evaluate("1 + 2");
    } catch (e) {
      threw = e;
    } finally {
      await backend.dispose();
    }
    expect(threw).toBeInstanceOf(RelayCelError);
    const err = threw as RelayCelError;
    // Structured engine code, not a raw filesystem error.
    expect((err as unknown as { code?: unknown }).code).toBeTypeOf("string");
    expect(err.code.startsWith("RELAY-CEL-")).toBe(true);
    // It is NOT a bare Node ENOENT system error leaking through.
    expect((err as unknown as { code?: string }).code).not.toBe("ENOENT");
    expect((err as unknown as { errno?: number }).errno).toBeUndefined();
  });

  test("wasm missing artifact structured error: the package-data resolver returns null (not throwing ENOENT) for an absent path", () => {
    // The resolver helper is non-throwing for an absent path: it returns null so
    // the caller maps the absence to a structured engine error rather than
    // letting a bare ENOENT escape.
    const resolved = resolvePackagedWasmPath(ABSENT);
    expect(resolved).toBeNull();
  });

  test("the wasm DEFAULT path resolves the PACKAGED artifact and evaluates 1+2==3 (fresh-install wiring)", async () => {
    // M6 WS-I: the wasm engine is the only backend. The default factory
    // (CEL_WASM unset, no explicit wasmPath) must resolve the PACKAGED wasm +
    // loader (WS-G package data) so a fresh install evaluates with NO
    // configuration. This is the successor of the old "cel-js fallback"
    // assertion: there is no fallback engine -- the packaged wasm IS the
    // default path, and it must work out of the box.
    const savedCelWasm = process.env.CEL_WASM;
    delete process.env.CEL_WASM;
    try {
      expect(resolvePackagedWasmPath()).not.toBeNull();
      const evaluator = makeCelEvaluator({ timeoutMs: 250 });
      try {
        const result = await evaluator.evaluate("1 + 2");
        expect(result).toBe(3);
      } finally {
        await evaluator.dispose();
      }
    } finally {
      if (savedCelWasm !== undefined) {
        process.env.CEL_WASM = savedCelWasm;
      }
    }
  });
});

// --- sha-drift + cross-host byte-identity guards -----------------------------

describe("WS-G TS wasm sha-drift + byte-identity guards", () => {
  test("the TS pinned sha equals the build.sh repro sha and the Python pinned sha", () => {
    expect(WASM_PINNED_SHA256).toBe(EXPECTED_REPRO_SHA);
  });

  test("the packaged TS wasm on-disk sha256 equals the pinned constant (tampered/stale FAILS)", () => {
    const resolved = resolvePackagedWasmPath();
    expect(resolved).not.toBeNull();
    const bytes = readFileSync(resolved as string);
    expect(sha256Hex(bytes)).toBe(WASM_PINNED_SHA256);
  });

  test("the vendored TS wasm is byte-identical to the Python vendored copy (one shared truth)", () => {
    // Both ecosystems ship the SAME bytes; if they differ that is a P0 (the
    // cross-host byte-parity guarantee is void otherwise).
    const tsResolved = resolvePackagedWasmPath();
    expect(tsResolved).not.toBeNull();
    const tsBytes = readFileSync(tsResolved as string);
    const pyBytes = readFileSync(PYTHON_VENDORED_WASM);
    expect(sha256Hex(tsBytes)).toBe(sha256Hex(pyBytes));
    expect(tsBytes.equals(pyBytes)).toBe(true);
  });

  afterAll(() => {
    // No resources to release; the resolver + readFileSync are synchronous.
  });
});
