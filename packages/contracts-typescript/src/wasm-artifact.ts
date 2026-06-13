// Packaged wasm artifact resolution + pinned-sha guard (WS-G, M3 P3CORPUS).
//
// The single CEL engine is a reproducible relay_cel_wasm.wasm produced by the
// packages/cel-wasm/conformance/build.sh deterministic recipe. WS-G ships that
// artifact as PACKAGE DATA of @epochly/relay-contracts (under src/_wasm/) so an
// INSTALLED package can resolve the engine WITHOUT the (gitignored)
// crate/target/ tree. This is the TypeScript mirror of the Python
// packages/contracts/src/relay_contracts/wasm_artifact.py, shipping the SAME
// bytes (the SAME pinned sha) for the npm ecosystem.
//
// This module is the single TS source of truth for:
//
//   - WASM_PACKAGE_DATA_SUBPATH -- the `exports` subpath key
//     ("./wasm") under which @epochly/relay-contracts publishes the wasm, so a
//     consumer resolves it via require.resolve('@epochly/relay-contracts/wasm')
//     or import.meta.resolve of the same subpath -- NOT a crate/target/
//     relative path.
//   - WASM_PACKAGE_DATA_RELPATH -- the wasm's path relative to the package root
//     (src/_wasm/relay_cel_wasm.wasm). Ships in `files` (the `src` dir is in
//     the published `files` list) and is the `exports["./wasm"]` target.
//   - WASM_PINNED_SHA256 -- the full sha256 of the build.sh deterministic-
//     recipe artifact (the [repro] PASS sha). Equal to the Python
//     WASM_PINNED_SHA256 (one shared truth across ecosystems). The shipped
//     package-data wasm MUST hash to this value; a guard test fails on a
//     tampered / stale vendored artifact.
//   - resolvePackagedWasmPath() -- resolve the package-data wasm to a concrete
//     on-disk path. Non-throwing: returns null for an absent artifact so the
//     caller maps a missing artifact to a structured engine error rather than
//     letting a bare ENOENT escape.
//
// This is NOT signing. M3 PINS the sha (a checked-in constant + an on-disk-hash
// guard); the wasm is Apache-2.0-portable CODE, not trust-anchor key material.
// Signing the artifact (KMS / transparency log) lives in relay-platform and is
// explicitly out of scope here (CLAUDE.md banned pattern #14).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The `exports` subpath KEY under which the package publishes the wasm. A
// consumer resolves the artifact via require.resolve / import.meta.resolve of
// `@epochly/relay-contracts/wasm` (package name + this subpath minus the leading
// dot), so the wasm is locatable from an INSTALLED package without a
// crate/target/ relative path. package.json `exports` maps this key to
// WASM_PACKAGE_DATA_RELPATH.
export const WASM_PACKAGE_DATA_SUBPATH = "./wasm" as const;

// The vendored wasm's path RELATIVE TO the package root. Ships in the published
// tarball because the `src` directory is in package.json `files`. This is the
// `exports["./wasm"]` target and the path resolvePackagedWasmPath() returns.
// POSIX-style separator; resolved per-platform via node:path.
export const WASM_PACKAGE_DATA_RELPATH =
  "src/_wasm/relay_cel_wasm.wasm" as const;

// The vendored `.mjs` LOADER's path RELATIVE TO the package root. The canonical
// loader (packages/cel-wasm/typescript/relay-cel-wasm.mjs) is a REPO sibling
// that does NOT ship in this package's `files`, so an installed
// @epochly/relay-contracts could resolve the .wasm (via WASM_PACKAGE_DATA_RELPATH)
// yet NOT construct the wasm backend -- the loader was missing from every
// packaged path. WS-G ships a git-tracked VENDORED COPY of the canonical loader
// here (src/_wasm/relay-cel-wasm.mjs, in package.json `files` via the `src` dir),
// so a fresh-installed package can LOAD the wasm, not only locate it. This is the
// TypeScript mirror of the Python WASM_LOADER_PACKAGE_DATA_RELPATH
// (packages/contracts/src/relay_contracts/wasm_artifact.py). Because the copy is
// a git-tracked DUPLICATE of the canonical source, a BYTE-IDENTITY drift guard
// (wasm_loader_package_data.test.ts) fails CI if the two diverge -- no silent
// drift. POSIX-style separator; resolved per-platform via node:path.
export const WASM_LOADER_PACKAGE_DATA_RELPATH =
  "src/_wasm/relay-cel-wasm.mjs" as const;

// The full sha256 of the reproducible build.sh deterministic-recipe artifact
// (the `[repro] PASS: byte-deterministic (<sha>)` value). EQUAL to the Python
// WASM_PINNED_SHA256 (packages/contracts/src/relay_contracts/wasm_artifact.py):
// both ecosystems ship the SAME bytes. The shipped package-data wasm MUST hash
// to this. PINNED, not signed (see module docstring).
export const WASM_PINNED_SHA256 =
  "431d966b2818ef4539a4f6b78e2903a4d6911c6b6352e256e35531a44f992511" as const;

// The package root, anchored to THIS module's on-disk location. wasm-artifact.ts
// lives at packages/contracts-typescript/src/, so the package root is one level
// up. Resolution is anchored to the imported module, not a cwd-relative path, so
// it works from the dev tree and from an installed package alike (the `src` dir
// ships in `files`, so src/_wasm/relay_cel_wasm.wasm exists in both layouts).
function packageRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "..");
}

// Resolve the package-data wasm to a concrete on-disk path, gated on presence.
//
// When `override` is supplied it is treated as an explicit candidate path
// (used by the presence-gate test to point the resolver at a specific --
// possibly absent -- artifact). Otherwise the package-data path
// (WASM_PACKAGE_DATA_RELPATH under the package root) is used.
//
// Non-throwing: returns the resolved path when it exists as a regular file, else
// null, so the caller can map a missing artifact to a structured engine error
// (RelayCelEngineError / RELAY-CEL-009) rather than letting a bare ENOENT
// escape. Never throws for an absent artifact.
export function resolvePackagedWasmPath(override?: string): string | null {
  const candidate =
    override ?? resolve(packageRoot(), WASM_PACKAGE_DATA_RELPATH);
  try {
    if (!existsSync(candidate)) {
      return null;
    }
    if (!statSync(candidate).isFile()) {
      return null;
    }
  } catch {
    // Any filesystem error (permissions, broken symlink, etc.) is treated as
    // "not resolvable" -- the caller maps that to a structured engine error.
    return null;
  }
  return candidate;
}

// Resolve the package-data `.mjs` LOADER to a concrete on-disk path, gated on
// presence. Mirrors resolvePackagedWasmPath() for the loader source: resolution
// is anchored to THIS module's on-disk location (so it works from the dev tree
// and an installed package alike -- the `src` dir ships in `files`), NOT a cwd-
// or crate/target/-relative path. The TS counterpart of the Python
// resolve_packaged_wasm_loader_path (wasm_artifact.py).
//
// When `override` is supplied it is treated as an explicit candidate path (used
// by the absent-loader test). Otherwise the package-data path
// (WASM_LOADER_PACKAGE_DATA_RELPATH under the package root) is used.
//
// Non-throwing: returns the resolved path when it exists as a regular file, else
// null, so the caller can fall back to the repo sibling (dev tree) or map a
// missing loader to a structured engine error rather than letting a bare ENOENT
// escape. Never throws for an absent loader.
export function resolvePackagedLoaderPath(override?: string): string | null {
  const candidate =
    override ?? resolve(packageRoot(), WASM_LOADER_PACKAGE_DATA_RELPATH);
  try {
    if (!existsSync(candidate)) {
      return null;
    }
    if (!statSync(candidate).isFile()) {
      return null;
    }
  } catch {
    // Any filesystem error (permissions, broken symlink, etc.) is treated as
    // "not resolvable" -- the caller falls back / maps to a structured error.
    return null;
  }
  return candidate;
}

// Resolve the wasm artifact path to pass to the `.mjs` RelayCel loader, with the
// EXPLICIT precedence (ROBOREV round-2 finding G):
//
//   1. an explicit `wasmPath` (the caller-supplied override) -- highest;
//   2. `process.env.CEL_WASM` (the operator's artifact override);
//   3. the WS-G PACKAGE-DATA wasm (resolvePackagedWasmPath()) -- lowest;
//   4. `undefined` -- no host-resolved path, so the loader applies its OWN
//      default (its self-relative package-data probe / crate-target build).
//
// The bug: when no explicit `wasmPath` was given and the packaged wasm resolved,
// the host passed the PACKAGE-DATA path straight to the loader, so the loader's
// own `wasmPath || process.env.CEL_WASM || defaultWasmPath()` chain never saw
// CEL_WASM -- the operator's override was silently ignored while the docs still
// claimed it was honored. This resolver makes CEL_WASM take precedence over the
// packaged wasm: the packaged wasm is returned ONLY when neither an explicit path
// nor CEL_WASM is set.
//
// CEL_WASM is the wasm-ARTIFACT-PATH env var (NOT the RELAY_CEL_ENGINE engine
// SELECTOR), so reading it here does not affect engine-selection determinism (the
// default-engine guard scans only for RELAY_CEL_ENGINE and explicitly exempts
// CEL_WASM). An EMPTY/whitespace CEL_WASM is treated as UNSET so a blank
// assignment does not point the loader at "" (which would fail to load).
//
// Returns a concrete path string, or `undefined` to defer to the loader's own
// default. Never throws.
export function resolveWasmPathForLoader(
  wasmPath?: string,
): string | undefined {
  if (wasmPath !== undefined) {
    return wasmPath;
  }
  const envPath = process.env.CEL_WASM;
  if (envPath !== undefined && envPath.trim() !== "") {
    return envPath;
  }
  const packaged = resolvePackagedWasmPath();
  if (packaged !== null) {
    return packaged;
  }
  return undefined;
}
