// TypeScript pipeline mirror: reconstruct udf_outputs_jcs / udfs_invoked from
// the wasm udf_trace, BYTE-IDENTICAL to the Python host (VAL-CWC-P1HOST-019).
//
// This is the TS mirror of the wasm hot path in
// packages/contracts/src/relay_contracts/pipeline.py (_evaluate_wasm_path +
// the udf_outputs_jcs reconstruction in evaluate_assertion). Both the Python
// host and this TS host load the SAME signed relay_cel_wasm.wasm, so the
// wasm `udf_trace` response field (a per-UDF-name list of typed-canonical
// {"t","v"} values in CALL ORDER) is byte-identical across hosts by
// construction. This module's job is to encode that trace into
// udf_outputs_jcs IDENTICALLY to Python: the typed-canonical
// {name: [{"t","v"}, ...]} per-UDF-name list in call order, run through the
// SAME RFC 8785 JCS encoder (canonical.ts, byte-parity-tested against the
// Python jcs_canonicalize).
//
// Keystone invariant #16 (a P0): the udf_outputs_jcs bytes feed a
// cryptographic digest, so they MUST be byte-identical to the Python host.
// Any single-byte divergence is a release-block.
//
// Scope: this module mirrors the udf_outputs_jcs / udfs_invoked
// reconstruction from the wasm udf_trace (the M1 P1HOST TS feature). The full
// six-key outcome envelope (assertion_id, expression_digest, wall_time_ms,
// outcome) is reconstructed on the Python host's pipeline; the cross-host
// byte-parity contract lives in udf_outputs_jcs, which this module owns on the
// TS side.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

import { jcsCanonicalize } from "./canonical.js";
import {
  resolvePackagedLoaderPath,
  resolvePackagedWasmPath,
} from "./wasm-artifact.js";
// Single source of truth for the native<->typed codec lives in wasm-evaluator.ts
// (VAL-CWC-P2TSGATE-005). This pipeline imports `nativeToTyped` / `TypedValue`
// from there rather than keeping a second copy that could drift -- a P0
// byte-parity risk. The codec's int/double classification + BigInt overflow
// boundary is the keystone-invariant-#16 contract with cel-python.
import {
  decodeWasmEnvelope,
  nativeToTyped,
  type TypedValue,
} from "./wasm-evaluator.js";

// Re-export so the package public surface (index.ts) is unchanged: callers
// importing `nativeToTyped` / `TypedValue` from "./pipeline.js" keep working,
// now backed by the single canonical implementation.
export { nativeToTyped };
export type { TypedValue };

// The wasm response envelope shape (a subset; we only read what this path
// needs). Success carries `value` and optionally `udf_trace`; failure carries
// `error` + `code`.
interface WasmEnvelope {
  ok: boolean;
  value?: TypedValue;
  udf_trace?: Record<string, TypedValue[]>;
  error?: string;
  code?: string;
}

// The `.mjs` loader's optional eval options. `relayProfile:true` turns on the
// Relay CEL profile's call-level fence (dyn/timestamp/duration global calls
// rejected with RELAY-CEL-002); `container` is the optional CEL resolution
// namespace. These field names map to the wasm-request fields the crate reads
// (relay_profile, container; crate/src/lib.rs:239-240, 259) -- the SAME options
// the Python host sets via relay_profile=True. Mirrors the .mjs eval signature
// (packages/cel-wasm/typescript/relay-cel-wasm.mjs).
interface RelayCelEvalOptions {
  relayProfile?: boolean;
  container?: string;
}

// Minimal structural type for the .mjs loader's RelayCel class. We import it
// dynamically (it is a sibling .mjs in packages/cel-wasm/typescript) so this
// module does not hard-depend on a built artifact at import time.
interface RelayCelLoader {
  eval(
    expr: string,
    bindings?: Record<string, TypedValue>,
    options?: RelayCelEvalOptions,
  ): Promise<WasmEnvelope>;
}

interface RelayCelModule {
  RelayCel: {
    load(wasmPath?: string): Promise<RelayCelLoader>;
  };
}

// nativeToTyped (the JS-native -> typed-canonical encoder) is the single
// canonical codec in wasm-evaluator.ts, imported and re-exported above. The
// binding-encode path below uses that SAME function, so the inputs the wasm
// sees on the TS host are byte-identical to the Python host's py_to_typed
// binding.

// ---------------------------------------------------------------------------
// Lazy loader resolution, preferring the PACKAGED loader.
//
// WS-G ships a git-tracked vendored copy of the canonical loader as package data
// (@epochly/relay-contracts/src/_wasm/relay-cel-wasm.mjs, in package.json
// `files`), so an INSTALLED package can import the loader WITHOUT the repo
// sibling path (which does NOT exist in an install). Resolution order:
//   1. the packaged loader (resolvePackagedLoaderPath) -- works from both the
//      dev tree and a fresh install;
//   2. the repo sibling packages/cel-wasm/typescript/relay-cel-wasm.mjs as a DEV
//      fallback when the package-data copy is somehow absent.
// Mirrors wasm-evaluator.defaultLoaderPath() and the Python _load_relay_cel_class
// resolution order; both ecosystems ship the SAME loader bytes (a byte-identity
// drift guard enforces it).
// ---------------------------------------------------------------------------
const requireFromHere = createRequire(import.meta.url);

// Absolute file:// URL of the `.mjs` wasm loader, preferring the packaged copy.
// pathToFileURL turns an absolute filesystem path into the ESM import specifier
// (cross-platform: Windows backslash paths become valid file:// URLs). Exported
// so the WS-G loader package-data guard can assert it targets the packaged
// loader, not the repo sibling.
export function resolveLoaderUrl(): string {
  const packaged = resolvePackagedLoaderPath();
  if (packaged !== null) {
    return pathToFileURL(packaged).href;
  }
  // Dev-tree fallback: the repo sibling at ../../cel-wasm/typescript/ relative
  // to this module (src/ under vitest, dist/ when built).
  const fsPath = requireFromHere.resolve(
    "../../cel-wasm/typescript/relay-cel-wasm.mjs",
  );
  return pathToFileURL(fsPath).href;
}

async function loadRelayCel(wasmPath?: string): Promise<RelayCelLoader> {
  const loaderUrl = resolveLoaderUrl();
  // When the PACKAGED loader is used (an installed package, or the dev tree's
  // vendored copy) and no explicit wasmPath was given, resolve the package-data
  // wasm and pass it EXPLICITLY. The vendored loader's own self-relative
  // defaultWasmPath() probe (../../contracts-typescript/src/_wasm/...) is
  // computed from the CANONICAL loader's location and is WRONG when the loader
  // is the vendored copy under src/_wasm/ -- so the host (not the relocated
  // loader) supplies the wasm path. Mirrors WasmCelBackend / the Python host,
  // which always resolve the package-data wasm and pass it to the loader rather
  // than relying on the relocated loader's self-relative default.
  let resolvedWasmPath = wasmPath;
  if (resolvedWasmPath === undefined && resolvePackagedLoaderPath() !== null) {
    const packagedWasm = resolvePackagedWasmPath();
    if (packagedWasm !== null) {
      resolvedWasmPath = packagedWasm;
    }
  }
  const mod = (await import(loaderUrl)) as unknown as RelayCelModule;
  return mod.RelayCel.load(resolvedWasmPath);
}

export interface EvaluateUdfOutputsOptions {
  /** Explicit wasm artifact path; falls back to CEL_WASM / the release build. */
  wasmPath?: string;
  /**
   * Optional CEL resolution namespace (e.g. "com.example"), threaded into the
   * wasm request as `container` -- the SAME field the Python host passes. Most
   * callers omit it (the default empty container).
   */
  container?: string;
}

export interface UdfOutputsResult {
  /**
   * The JCS-canonical bytes of {name: [typed-canonical, ...]} per invoked UDF
   * name in sorted order. BYTE-IDENTICAL to the Python host's udf_outputs_jcs.
   */
  udfOutputsJcsBytes: Uint8Array;
  /** The udf_outputs_jcs as a UTF-8 string (decoded from the bytes). */
  udfOutputsJcs: string;
  /** UDF names that fired, derived from the udf_trace keys (sorted). */
  udfsInvoked: string[];
}

/**
 * Drive `expression` + `bindings` through the wasm CEL engine and reconstruct
 * udf_outputs_jcs / udfs_invoked from the wasm udf_trace, BYTE-IDENTICAL to the
 * Python host (VAL-CWC-P1HOST-019).
 *
 * `bindings` are native JS values; they are encoded to the wasm typed-canonical
 * form via `nativeToTyped` (the py_to_typed mirror) so the wasm sees the SAME
 * inputs the Python host binds. The wasm's udf_trace OUTPUT is then encoded to
 * udf_outputs_jcs via the SAME RFC 8785 JCS encoder as the Python host.
 */
export async function evaluateUdfOutputs(
  expression: string,
  bindings: Record<string, unknown> = {},
  options: EvaluateUdfOutputsOptions = {},
): Promise<UdfOutputsResult> {
  const cel = await loadRelayCel(options.wasmPath);

  const typedBindings: Record<string, TypedValue> = {};
  for (const k of Object.keys(bindings)) {
    typedBindings[k] = nativeToTyped(bindings[k]);
  }
  const hasBindings = Object.keys(typedBindings).length > 0;

  // Thread the Relay profile fence (relay_profile=True) -- and the optional
  // container -- into the wasm eval, EXACTLY as the Python host does
  // (pipeline.py via WasmCelEvaluator.evaluate_with_trace ->
  // handle.eval(..., relay_profile=True)). WITHOUT this, the TS mirror did NOT
  // enforce the dyn/timestamp/duration fence, so it could emit udf evidence for
  // expressions the Python host rejects -- a cross-host divergence and a
  // keystone-#16 risk. The options object's `container` is omitted when unset so
  // the wasm-request JSON stays byte-identical to the no-container form.
  const evalOptions: RelayCelEvalOptions = { relayProfile: true };
  if (options.container !== undefined) {
    evalOptions.container = options.container;
  }
  const envelope = await cel.eval(
    expression,
    hasBindings ? typedBindings : undefined,
    evalOptions,
  );

  // A non-ok envelope (e.g. a RELAY-CEL-002 profile rejection now that the fence
  // is threaded) must surface as a structured RelayCelError -- NOT silently
  // produce an empty udf_outputs reconstruction. decodeWasmEnvelope maps the
  // {ok:false} cause to the right structured error (profile / engine), exactly
  // as the Python host raises. The crate only attaches udf_trace on {ok:true},
  // so reconstructing from a non-ok envelope would emit evidence the Python host
  // never would.
  if (envelope.ok !== true) {
    // Throws the structured RelayCelError for the failure cause (profile /
    // engine). The trace is only meaningful on a success envelope.
    decodeWasmEnvelope(envelope);
    // decodeWasmEnvelope always throws for a non-ok envelope; this is a
    // defensive fallback so the contract (never proceed past a non-ok envelope)
    // is total even if that ever changes.
    throw new Error(
      `wasm CEL evaluation returned a non-ok envelope: ${JSON.stringify(envelope)}`,
    );
  }

  const udfTrace = extractUdfTrace(envelope);

  // udfs_invoked from the udf_trace keys (SORTED -- matching the wasm BTreeMap
  // key order and the Python pipeline's sorted() semantics,
  // pipeline.py:330-331). udf_outputs is the trace itself (already a per-name
  // list of typed-canonical values in call order), so the JCS bytes match the
  // Python host byte-for-byte.
  const udfsInvoked = Object.keys(udfTrace).slice().sort();
  const udfOutputs: Record<string, TypedValue[]> = {};
  for (const name of udfsInvoked) {
    udfOutputs[name] = udfTrace[name] as TypedValue[];
  }

  // SINGLE typed-canonical contract for udf_outputs_jcs across BOTH hosts
  // (VAL-CWC-P1HOST-015): udfOutputs is a per-UDF-name list of typed-canonical
  // {"t","v"} entries in call order, identical to the Python host's structure,
  // run through the SAME RFC 8785 JCS encoder.
  const udfOutputsJcsBytes = jcsCanonicalize(udfOutputs);
  const udfOutputsJcs = new TextDecoder().decode(udfOutputsJcsBytes);

  return { udfOutputsJcsBytes, udfOutputsJcs, udfsInvoked };
}

/**
 * Normalize the wasm `udf_trace` response field to a per-name list-of-typed
 * map. The crate attaches `udf_trace` only on a success envelope where at least
 * one relay.* UDF ran; it is ABSENT otherwise (udf_trace_drain returns None ->
 * field omitted). Absence normalizes to an empty object. Shape is validated
 * fail-closed so a malformed trace cannot silently corrupt the reconstructed
 * udf_outputs_jcs (which feeds a digest). Mirrors the Python
 * WasmCelEvaluator._extract_udf_trace (wasm_backed_evaluator.py:396-431).
 */
function extractUdfTrace(envelope: WasmEnvelope): Record<string, TypedValue[]> {
  const trace = envelope.udf_trace;
  if (trace === undefined || trace === null) {
    return {};
  }
  if (typeof trace !== "object" || Array.isArray(trace)) {
    throw new TypeError(
      `wasm udf_trace must be an object; got ${typeof trace}`,
    );
  }
  const normalized: Record<string, TypedValue[]> = {};
  for (const name of Object.keys(trace)) {
    const values = trace[name];
    if (!Array.isArray(values)) {
      throw new TypeError(
        `wasm udf_trace[${JSON.stringify(name)}] must be a list; ` +
          `got ${typeof values}`,
      );
    }
    normalized[name] = values.slice();
  }
  return normalized;
}
