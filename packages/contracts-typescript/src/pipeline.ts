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
import { RelayCelNumericOutOfBoundsError } from "./errors.js";

// VAL-PARITY-001 / VAL-CWC-P1HOST-005: integral values whose magnitude exceeds
// Number.MAX_SAFE_INTEGER (2**53 - 1) cannot be represented exactly as a JS
// double, so binding them as a CEL int would diverge the cross-host digest.
// We reject them at the boundary (the host guard stays host-side).
const SAFE_INTEGER_BOUND = 2 ** 53 - 1;

// The wasm typed-canonical value form (the {"t","v"} wire form the crate
// emits and consumes; see crate/src/lib.rs value_to_typed / typed_to_value and
// the Python codec packages/contracts/src/relay_contracts/wasm_codec.py).
// `null` carries no "v" key.
export type TypedValue =
  | { t: "int"; v: string }
  | { t: "uint"; v: string }
  | { t: "double"; v: string }
  | { t: "string"; v: string }
  | { t: "bool"; v: boolean }
  | { t: "bytes"; v: string }
  | { t: "list"; v: TypedValue[] }
  | { t: "map"; v: [TypedValue, TypedValue][] }
  | { t: "null" };

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

// Minimal structural type for the .mjs loader's RelayCel class. We import it
// dynamically (it is a sibling .mjs in packages/cel-wasm/typescript) so this
// module does not hard-depend on a built artifact at import time.
interface RelayCelLoader {
  eval(
    expr: string,
    bindings?: Record<string, TypedValue>,
  ): Promise<WasmEnvelope>;
}

interface RelayCelModule {
  RelayCel: {
    load(wasmPath?: string): Promise<RelayCelLoader>;
  };
}

// ---------------------------------------------------------------------------
// nativeToTyped: JS native value -> wasm typed-canonical {"t","v"}.
//
// Faithful mirror of py_to_typed (wasm_codec.py:208-261). Classification order
// is load-bearing: bool BEFORE number (a JS boolean must serialize as
// {"t":"bool"}, never {"t":"int"}). JS has no separate uint/bytes primitive in
// the binding inputs we accept, so:
//   - boolean        -> {"t":"bool","v":<bool>}      (lib.rs:1141, JSON boolean)
//   - null/undefined -> {"t":"null"}                  (lib.rs:1142, no "v")
//   - bigint         -> {"t":"int","v":<decimal str>} (arbitrary-precision int)
//   - number, integral & |v| <= MAX_SAFE_INTEGER -> {"t":"int","v":str}
//   - number, otherwise                          -> {"t":"double","v":canonical}
//   - string         -> {"t":"string","v":<utf8>}
//   - array          -> {"t":"list","v":[...]}        (order preserved)
//   - object         -> {"t":"map","v":[[k,v],...]}   (sorted by key_sort_string)
//
// Binding values are the INPUTS to the wasm; the udf_trace OUTPUT bytes (the
// byte-parity target) are produced INSIDE the wasm regardless of how we encode
// the inputs, as long as the encoded inputs are semantically the SAME values
// the Python host binds. Python binds via py_to_typed (the same classification),
// so encoding here the same way guarantees the wasm sees identical inputs and
// emits identical udf_trace.
// ---------------------------------------------------------------------------
export function nativeToTyped(value: unknown): TypedValue {
  // bool FIRST -- a JS boolean must not fall through to the number branch.
  if (typeof value === "boolean") {
    return { t: "bool", v: value };
  }
  if (value === null || value === undefined) {
    return { t: "null" };
  }
  if (typeof value === "bigint") {
    // Arbitrary-precision integer -> decimal string (CEL int).
    return { t: "int", v: (value as bigint).toString(10) };
  }
  if (typeof value === "number") {
    const n = value;
    if (!Number.isFinite(n)) {
      throw new RelayCelNumericOutOfBoundsError(
        `binding value is non-finite: ${String(n)}`,
      );
    }
    if (Number.isInteger(n)) {
      if (Math.abs(n) > SAFE_INTEGER_BOUND) {
        throw new RelayCelNumericOutOfBoundsError(
          "binding integer outside the IEEE-754 safe range " +
            `[-(2**53 - 1), 2**53 - 1]: ${String(n)}`,
        );
      }
      // A whole-valued JS number is bound as a CEL int (matches cel-python
      // json_to_cel, which classifies a whole-valued number as int).
      return { t: "int", v: encodeIntString(n) };
    }
    // Non-integral -> double, canonical-g form (matches the Python codec's
    // _canonical_double via String(n) for the finite non-zero case, which is
    // ECMA-262 ToString -- the same shortest-round-trip form).
    return { t: "double", v: canonicalDouble(n) };
  }
  if (typeof value === "string") {
    return { t: "string", v: value };
  }
  if (Array.isArray(value)) {
    return { t: "list", v: value.map(nativeToTyped) };
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    // Map entries are sorted by the wasm key_sort_string total order
    // (lib.rs:1126-1133). Our binding keys are always JS strings (object
    // literals), so the key sort reduces to the "3:string:<s>" bucket; sorting
    // by the string value reproduces that order. The wasm re-sorts internally
    // on typed_to_value anyway, so map-entry order here is not part of the
    // udf_trace byte contract -- but we sort for determinism and to mirror
    // py_to_typed exactly.
    const entries: [TypedValue, TypedValue][] = [];
    const sortKeys: Array<{ key: string; sort: string }> = [];
    for (const k of Object.keys(obj)) {
      sortKeys.push({ key: k, sort: `3:string:${k}` });
    }
    sortKeys.sort((a, b) => (a.sort < b.sort ? -1 : a.sort > b.sort ? 1 : 0));
    for (const { key } of sortKeys) {
      entries.push([
        { t: "string", v: key },
        nativeToTyped(obj[key]),
      ]);
    }
    return { t: "map", v: entries };
  }
  throw new TypeError(
    `nativeToTyped: unsupported binding value type ${typeof value}`,
  );
}

// Decimal string for a safe-range integral JS number. String(n) for an integer
// within the safe range is exact and matches the Python str(int(value)) form
// (no scientific notation for |n| <= 2**53 - 1).
function encodeIntString(n: number): string {
  // For a whole-valued number in the safe range, toFixed(0) avoids any
  // exponent form (e.g. 1e21 would never reach here -- it exceeds the bound).
  return n.toFixed(0);
}

// Canonical-g double string. Mirrors the Python codec's _canonical_double for
// the finite branch: ECMA-262 ToString (String(n)) is the shortest round-trip
// decimal, which the JCS encoder also uses. inf/-inf/nan are rejected upstream
// (non-finite binding values throw), so only finite non-integral numbers reach
// here.
function canonicalDouble(n: number): string {
  if (n === 0) {
    // Both +0 and -0 -- the codec emits "0.0" / "-0.0"; a literal 0 binding is
    // integral and never reaches this branch, so this is defensive only.
    return Object.is(n, -0) ? "-0.0" : "0.0";
  }
  return String(n);
}

// ---------------------------------------------------------------------------
// Lazy, cached loader resolution. The .mjs loader is a sibling package
// (packages/cel-wasm/typescript/relay-cel-wasm.mjs) resolved from this source
// file's location so it works from both src/ (vitest) and dist/ (built).
// ---------------------------------------------------------------------------
const requireFromHere = createRequire(import.meta.url);

// Absolute file:// URL of the sibling .mjs wasm loader, resolved relative to
// THIS module so it works from both src/ (vitest, ts source) and dist/ (built
// js): ../../cel-wasm/typescript/relay-cel-wasm.mjs reaches the loader from
// packages/contracts-typescript/src/ (or dist/). createRequire(...).resolve
// returns an absolute filesystem path; pathToFileURL turns it into the ESM
// import specifier (cross-platform: Windows backslash paths become valid
// file:// URLs).
function loaderUrl(): string {
  const fsPath = requireFromHere.resolve(
    "../../cel-wasm/typescript/relay-cel-wasm.mjs",
  );
  return pathToFileURL(fsPath).href;
}

async function loadRelayCel(wasmPath?: string): Promise<RelayCelLoader> {
  const mod = (await import(loaderUrl())) as unknown as RelayCelModule;
  return mod.RelayCel.load(wasmPath);
}

export interface EvaluateUdfOutputsOptions {
  /** Explicit wasm artifact path; falls back to CEL_WASM / the release build. */
  wasmPath?: string;
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

  const envelope = await cel.eval(
    expression,
    hasBindings ? typedBindings : undefined,
  );

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
