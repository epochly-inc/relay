// Canonical TypeScript half of the wasm CEL typed-canonical value codec.
//
// This module is the SINGLE SOURCE OF TRUTH for the native<->typed marshaling
// (`nativeToTyped` / `typedToNative`) that talks to the wasm CEL reactor's
// typed-canonical {"t","v"} wire form. It is the TS mirror of the Python codec
// packages/contracts/src/relay_contracts/wasm_codec.py (py_to_typed /
// typed_to_py), itself byte-faithful to the Rust source of truth
// packages/cel-wasm/crate/src/lib.rs (value_to_typed / typed_to_value /
// key_sort_string / canonical_double).
//
// CLAUDE.md keystone invariant #16 (a P0): the typed-canonical {"t","v"} form
// and the int/double classification MUST match cel-python EXACTLY -- any
// divergence breaks the cross-host udf_outputs_jcs digest and is a release
// block.
//
// pipeline.ts re-imports `nativeToTyped` / `TypedValue` from HERE (not a second
// copy) so the binding-encode path and this codec never drift.
//
// Scope: this module owns BOTH the codec (VAL-CWC-P2TSGATE-005:
// `nativeToTyped` / `typedToNative`) AND the wasm host orchestration
// (VAL-CWC-P2TSGATE-002/003/006/008: `WasmCelBackend` + `decodeWasmEnvelope`).
// `WasmCelBackend` is the TS counterpart of the Python `WasmCelEvaluator`
// (packages/contracts/src/relay_contracts/wasm_backed_evaluator.py): it routes a
// CEL expression through the SINGLE wasm CEL engine (the `.mjs` `RelayCel`
// loader with `relayProfile: true`) while keeping the engine-agnostic host
// guards HOST-SIDE -- the regex-backref pre-screen (RELAY-CEL-007) before the
// wasm call and the finiteness / safe-integer guard (RELAY-CEL-006) on the
// converted result -- and enforcing the wall-clock timeout via a
// node:worker_threads Worker that is hard-killed (`worker.terminate()`) on
// budget exceed. The host guards are imported from `evaluator.ts` (reused, NOT
// reimplemented). A wasm `{ok:false}` engine envelope maps to the dedicated
// RELAY-CEL-009 `RelayCelEngineError` (never the host 004/006), the wasm's
// RELAY-CEL-002 profile rejection surfaces as `RelayCelProfileError` with the
// wasm's structured subtype, and caller-supplied extra UDFs are rejected
// fail-closed with RELAY-CEL-004 / RELAY-CEL-UDF-UNREGISTERED -- byte-for-byte
// the Python mapping (errors.py:193-225, wasm_backed_evaluator.py:433-475).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { Worker } from "node:worker_threads";

import {
  CODE_RELAY_CEL_002,
  RelayCelEngineError,
  RelayCelNumericOutOfBoundsError,
  RelayCelProfileError,
  RelayCelTimeoutError,
  RelayCelUnsupportedUdfError,
  type RelayCelSubtype,
} from "./errors.js";
import {
  checkFinite,
  checkRegexBackref,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
} from "./evaluator.js";
import type { PureUdf } from "./udf.js";
import { RELAY_COVERAGE_NAME } from "./udfs/coverage.js";
import { RELAY_SCHEMA_MATCH_NAME } from "./udfs/schema_match.js";
import { RELAY_TOOL_ARG_NAME } from "./udfs/tool_arg.js";

// VAL-PARITY-001 / VAL-CWC-P1HOST-005: an INTEGRAL value whose magnitude exceeds
// Number.MAX_SAFE_INTEGER (2**53 - 1) cannot be represented exactly as a JS
// double, so binding/decoding it as a CEL int would diverge the cross-host
// digest. We reject it at the codec boundary (the host guard stays host-side).
// Mirrors the Python SAFE_INTEGER_BOUND (evaluator.py:82, wasm_codec parity).
//
// The bound is a BigInt: the overflow magnitude check operates on the EXACT
// decimal string of the integer (NOT a float64 comparison, which loses
// precision at this scale -- 2**53 is indistinguishable from 2**53 + 1 in
// float64). For any integer V, float64(V) > MAX_SAFE_INTEGER <=> V >= 2**53, so
// rejecting magnitude > (2**53 - 1) is exact and fail-closed in both runtimes.
export const SAFE_INTEGER_BOUND_BIGINT = 9007199254740991n; // 2n**53n - 1n

// The wasm typed-canonical value form (the {"t","v"} wire form the crate emits
// and consumes; see crate/src/lib.rs value_to_typed / typed_to_value and the
// Python codec packages/contracts/src/relay_contracts/wasm_codec.py).
// `null` carries no "v" key (lib.rs:1142).
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

// ---------------------------------------------------------------------------
// nativeToTyped: JS native value -> wasm typed-canonical {"t","v"}.
//
// Faithful mirror of py_to_typed (wasm_codec.py:208-261). Classification order
// is load-bearing: bool BEFORE number (a JS boolean must serialize as
// {"t":"bool"}, never {"t":"int"} -- the cross-host bool-before-int invariant,
// wasm_codec.py:218, lib.rs:1141). JS has no separate uint/bytes primitive in
// the binding inputs we accept, so:
//   - boolean        -> {"t":"bool","v":<bool>}      (lib.rs:1141, JSON boolean)
//   - null/undefined -> {"t":"null"}                  (lib.rs:1142, no "v")
//   - bigint         -> {"t":"int","v":<decimal str>} (arbitrary-precision int)
//   - number, integral & |v| <= 2**53 - 1 -> {"t":"int","v":<decimal str>}
//   - number, otherwise (finite, non-integral) -> {"t":"double","v":canonical}
//   - string         -> {"t":"string","v":<utf8>}
//   - array          -> {"t":"list","v":[...]}        (order preserved)
//   - object         -> {"t":"map","v":[[k,v],...]}   (sorted by key_sort_string)
//
// int/double classification mirrors cel-python json_to_cel (adapter.py:140-155)
// through the JSON wire boundary: a JS whole-valued number serializes to a JSON
// integer (no decimal point) -> Python int -> json_to_cel -> IntType; a JS
// non-integral number serializes to a JSON float -> Python float -> DoubleType.
//
// Binding values are the INPUTS to the wasm; the udf_trace OUTPUT bytes (the
// byte-parity target) are produced INSIDE the wasm regardless of how we encode
// the inputs, as long as the encoded inputs are semantically the SAME values
// the Python host binds. Python binds via py_to_typed (the same classification),
// so encoding here the same way guarantees the wasm sees identical inputs.
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
    // Arbitrary-precision integer -> decimal string (CEL int). A bigint is
    // exact at any magnitude, so no float-precision boundary applies here; the
    // safe-range guard exists to protect the float64 -> int conversion, which a
    // bigint bypasses.
    return { t: "int", v: value.toString(10) };
  }
  if (typeof value === "number") {
    const n = value;
    if (!Number.isFinite(n)) {
      throw new RelayCelNumericOutOfBoundsError(
        `binding value is non-finite: ${String(n)}`,
      );
    }
    if (Number.isInteger(n)) {
      // The EXACT decimal string of the integral float64 (n.toFixed(0) yields
      // the float's exact integer value with no exponent form). The overflow
      // check then operates on that string via BigInt -- NOT a float64
      // comparison, which loses precision at and beyond 2**53.
      const decimal = encodeIntString(n);
      const magnitude = absBigInt(BigInt(decimal));
      if (magnitude > SAFE_INTEGER_BOUND_BIGINT) {
        throw new RelayCelNumericOutOfBoundsError(
          "binding integer outside the IEEE-754 safe range " +
            `[-(2**53 - 1), 2**53 - 1]: ${decimal}`,
        );
      }
      // A whole-valued JS number is bound as a CEL int (matches cel-python
      // json_to_cel, which classifies a JSON integer as IntType).
      return { t: "int", v: decimal };
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
    // py_to_typed exactly (wasm_codec.py:250-257).
    const entries: [TypedValue, TypedValue][] = [];
    const sortKeys: Array<{ key: string; sort: string }> = [];
    for (const k of Object.keys(obj)) {
      sortKeys.push({ key: k, sort: `3:string:${k}` });
    }
    sortKeys.sort((a, b) => (a.sort < b.sort ? -1 : a.sort > b.sort ? 1 : 0));
    for (const { key } of sortKeys) {
      entries.push([{ t: "string", v: key }, nativeToTyped(obj[key])]);
    }
    return { t: "map", v: entries };
  }
  throw new TypeError(
    `nativeToTyped: unsupported binding value type ${typeof value}`,
  );
}

// ---------------------------------------------------------------------------
// typedToNative: wasm typed-canonical {"t","v"} -> JS native value.
//
// Inverse of nativeToTyped (and the TS analogue of typed_to_py,
// wasm_codec.py:267-312). Round-trips every CEL value class:
//   int    -> JS number (rejected if magnitude > 2**53 - 1; a JS number cannot
//             represent it exactly -- the same boundary nativeToTyped enforces)
//   uint   -> JS number (same safe-range rejection)
//   double -> JS number (inf/-inf/nan sentinels + decimal strings, lib.rs:1256)
//   string -> JS string
//   bool   -> JS boolean
//   null   -> JS null (the canonical CEL-null JS value)
//   bytes  -> Uint8Array (decoded from lowercase hex, lib.rs:1143)
//   list   -> JS array (order preserved)
//   map    -> JS plain object (string keys; non-string keys are out of the
//             binding round-trip contract and rejected)
// ---------------------------------------------------------------------------
export function typedToNative(typed: TypedValue): unknown {
  if (typeof typed !== "object" || typed === null || Array.isArray(typed)) {
    throw new TypeError(
      `typedToNative: expected a typed object, got ${typeof typed}`,
    );
  }
  const t = (typed as { t?: unknown }).t;
  if (typeof t !== "string") {
    throw new TypeError("typedToNative: typed object missing 't'");
  }

  switch (t) {
    case "int":
    case "uint": {
      // Decimal string -> JS number, guarded so a value the JS number type
      // cannot hold exactly is rejected rather than silently rounded (a CEL
      // int that overflows the safe range diverges the cross-host digest).
      const decimal = requireStringV(typed, t);
      const big = BigInt(decimal);
      if (absBigInt(big) > SAFE_INTEGER_BOUND_BIGINT) {
        throw new RelayCelNumericOutOfBoundsError(
          `typed ${t} value outside the IEEE-754 safe range ` +
            `[-(2**53 - 1), 2**53 - 1]: ${decimal}`,
        );
      }
      return Number(big);
    }
    case "double":
      return decodeDouble(requireStringV(typed, "double"));
    case "string":
      return requireStringV(typed, "string");
    case "bool": {
      const v = requireV(typed, "bool");
      if (typeof v !== "boolean") {
        throw new TypeError("typedToNative: bool 'v' must be a JSON boolean");
      }
      return v;
    }
    case "null":
      // lib.rs:1286 decodes null to Value::Null; JS null is the canonical
      // CEL-null value (and the inverse of nativeToTyped(null)).
      return null;
    case "bytes":
      return hexToBytes(requireStringV(typed, "bytes"));
    case "list": {
      const v = requireV(typed, "list");
      if (!Array.isArray(v)) {
        throw new TypeError("typedToNative: list 'v' must be an array");
      }
      return (v as TypedValue[]).map(typedToNative);
    }
    case "map": {
      const v = requireV(typed, "map");
      if (!Array.isArray(v)) {
        throw new TypeError(
          "typedToNative: map 'v' must be an array of [k,v] pairs",
        );
      }
      const out: Record<string, unknown> = {};
      for (const pair of v as unknown[]) {
        if (!Array.isArray(pair) || pair.length !== 2) {
          throw new TypeError("typedToNative: map entry must be a [k,v] pair");
        }
        const key = typedToNative(pair[0] as TypedValue);
        if (typeof key !== "string") {
          throw new TypeError(
            "typedToNative: map key must decode to a string for a JS object " +
              `(got ${typeof key})`,
          );
        }
        out[key] = typedToNative(pair[1] as TypedValue);
      }
      return out;
    }
    default:
      throw new TypeError(`typedToNative: unsupported typed tag ${String(t)}`);
  }
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// Decimal string for a whole-valued JS number. toFixed(0) yields the float's
// EXACT integer value with no exponent form (e.g. 1e21 -> a full digit string),
// matching the Python str(int(value)) form. Used by both the int classification
// and its overflow magnitude check.
function encodeIntString(n: number): string {
  return n.toFixed(0);
}

// Absolute value of a BigInt (BigInt has no Math.abs).
function absBigInt(x: bigint): bigint {
  return x < 0n ? -x : x;
}

// Canonical-g double string. Mirrors the Python codec's _canonical_double for
// the finite branch: ECMA-262 ToString (String(n)) is the shortest round-trip
// decimal, which the JCS encoder also uses. inf/-inf/nan are rejected upstream
// on the encode path (non-finite binding values throw), so only finite numbers
// reach here.
function canonicalDouble(n: number): string {
  if (n === 0) {
    // Both +0 and -0 -- the codec emits "0.0" / "-0.0". A literal 0 binding is
    // integral and never reaches this branch, so this is defensive only.
    return Object.is(n, -0) ? "-0.0" : "0.0";
  }
  return String(n);
}

// Decode the double `v` field: the canonical inf/-inf/nan sentinels or a
// decimal string (mirrors wasm_codec.py:321-335 / lib.rs:1256-1270).
function decodeDouble(v: string): number {
  if (v === "inf") {
    return Number.POSITIVE_INFINITY;
  }
  if (v === "-inf") {
    return Number.NEGATIVE_INFINITY;
  }
  if (v === "nan") {
    return Number.NaN;
  }
  const n = Number(v);
  if (Number.isNaN(n)) {
    throw new TypeError(`typedToNative: double 'v' is not a valid number: ${v}`);
  }
  return n;
}

// Decode lowercase-hex bytes to a Uint8Array (inverse of lib.rs:1143-1145).
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new TypeError(
      `typedToNative: bytes hex must have even length, got ${hex.length}`,
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new TypeError(`typedToNative: bytes 'v' is not valid hex: ${hex}`);
    }
    out[i] = byte;
  }
  return out;
}

// Read a required "v" field of any JSON type.
function requireV(typed: TypedValue, tag: string): unknown {
  if (!("v" in typed)) {
    throw new TypeError(`typedToNative: typed ${tag} object missing 'v'`);
  }
  return (typed as { v: unknown }).v;
}

// Read a required "v" field that must be a string.
function requireStringV(typed: TypedValue, tag: string): string {
  const v = requireV(typed, tag);
  if (typeof v !== "string") {
    throw new TypeError(`typedToNative: ${tag} 'v' must be a string`);
  }
  return v;
}

// ===========================================================================
// WasmCelBackend: the wasm-backed CEL host (TS counterpart of the Python
// WasmCelEvaluator). VAL-CWC-P2TSGATE-002/003/006/008.
// ===========================================================================

// The wasm's structured RELAY-CEL-002 profile-rejection code. It carries a
// structured `subtype` (PROFILE-DYN/TS/DUR-DISABLED) which the host maps
// verbatim onto RelayCelProfileError -- NEVER by parsing the message string.
// Mirrors the Python _WASM_PROFILE_CODE (wasm_backed_evaluator.py:95).
const WASM_PROFILE_CODE: string = CODE_RELAY_CEL_002;

// The three relay.* UDFs the wasm hosts natively. A caller may pass these (e.g.
// via RELAY_UDFS) without rejection; any OTHER UDF name has no registration slot
// in the wasm and is rejected fail-closed. Mirrors the Python _NATIVE_UDF_NAMES
// (wasm_backed_evaluator.py:88-90).
const NATIVE_UDF_NAMES: ReadonlySet<string> = new Set([
  RELAY_COVERAGE_NAME,
  RELAY_TOOL_ARG_NAME,
  RELAY_SCHEMA_MATCH_NAME,
]);

// The wasm response envelope (the `.mjs` loader's eval() return shape). Success
// carries a typed-canonical `value`; failure carries `error` + `code` and, for a
// RELAY-CEL-002 profile rejection, a structured `subtype`. Mirrors
// packages/cel-wasm/typescript/relay-cel-wasm.mjs and crate/src/lib.rs.
export interface WasmResponseEnvelope {
  ok: boolean;
  value?: TypedValue;
  error?: string;
  code?: string;
  subtype?: string;
  // Present on a success envelope where >= 1 relay.* UDF ran (call-order trace);
  // not consumed by evaluate() (the pipeline consumes it separately).
  udf_trace?: Record<string, TypedValue[]>;
}

// ---------------------------------------------------------------------------
// decodeWasmEnvelope: translate a wasm response envelope into a JS value or a
// structured RelayCelError. VAL-CWC-P2TSGATE-002 (the engine-error mapping) +
// the host finiteness guard on the success path.
//
//   ok:true                 -> typedToNative(value), then host checkFinite
//                              (RELAY-CEL-006 / NUMERIC-OOB stays host-side)
//   ok:false code 002        -> RelayCelProfileError(message, <wasm subtype>)
//   ok:false (any other)     -> RelayCelEngineError.fromWasmEnvelope(code, msg)
//                              => RELAY-CEL-009 with a per-cause engine subtype;
//                              a wasm EXEC (its 004) / REQUEST (its 006) failure
//                              NEVER surfaces as the host 004 / 006.
//
// Byte-for-byte the Python WasmCelEvaluator._decode_envelope
// (wasm_backed_evaluator.py:433-475).
// ---------------------------------------------------------------------------
export function decodeWasmEnvelope(envelope: unknown): unknown {
  if (envelope === null || typeof envelope !== "object") {
    throw new RelayCelEngineError(
      `wasm engine returned a non-object response: ${typeof envelope}`,
      "RELAY-CEL-ENGINE-REQUEST",
    );
  }
  const env = envelope as WasmResponseEnvelope;

  if (env.ok === true) {
    if (env.value === undefined) {
      throw new RelayCelEngineError(
        "wasm success envelope missing 'value'",
        "RELAY-CEL-ENGINE-REQUEST",
      );
    }
    const value = typedToNative(env.value);
    // Host-side finiteness / safe-integer guard on the converted result. This
    // guard stays HOST-SIDE (it is NOT delegated to the wasm) so a NaN/+-Inf or
    // an out-of-safe-range integer / whole double is rejected with
    // RELAY-CEL-006 / NUMERIC-OOB exactly as the cel-js path does.
    checkFinite(value);
    return value;
  }

  const code = typeof env.code === "string" ? env.code : "";
  const message =
    typeof env.error === "string" ? env.error : "wasm engine error";

  // RELAY-CEL-002 profile rejection: the wasm emits a STRUCTURED subtype; map
  // (code, subtype) -> RelayCelProfileError without message parsing.
  if (code === WASM_PROFILE_CODE) {
    const subtype = env.subtype;
    if (typeof subtype !== "string" || subtype.length === 0) {
      // A profile rejection MUST carry a structured subtype; absent one, treat
      // it as an engine-request anomaly rather than guess.
      throw new RelayCelEngineError(
        `wasm profile rejection missing structured subtype: ${message}`,
        "RELAY-CEL-ENGINE-REQUEST",
      );
    }
    throw new RelayCelProfileError(message, subtype as RelayCelSubtype);
  }

  // Every other wasm failure cause -> the dedicated RELAY-CEL-009 engine error
  // with a per-cause subtype. Reuse the canonical mapping in errors.ts (do NOT
  // reinvent it); a wasm exec (004) / request (006) failure thus surfaces as
  // RELAY-CEL-009 / ENGINE-EXEC|ENGINE-REQUEST, never host 004/006.
  throw RelayCelEngineError.fromWasmEnvelope(code, message);
}

// ---------------------------------------------------------------------------
// Node Worker source.
//
// A persistent node:worker_threads Worker imports the `.mjs` RelayCel loader,
// loads the wasm ONCE at startup, then on each request runs
// `cel.eval(expr, bindings, {relayProfile:true})` and posts the RAW response
// envelope back to the host. Running the eval inside a Worker is what makes the
// wall-clock timeout a HARD kill: the host calls `worker.terminate()` to abort
// an in-flight (or deliberately-hung) evaluation, then respawns a fresh Worker
// on the next evaluate() (the wasm instance lives inside the terminated Worker,
// so it is discarded with the Worker -- no mid-eval instance crosses the
// terminate boundary).
//
// `hangSentinel` is an OPT-IN test affordance: when the host configures it and
// an evaluated expression equals it, the Worker busy-blocks past the budget so
// the host's terminate path can be exercised against a genuinely-stuck Worker.
// It is undefined in production, so no real expression takes the hang branch.
// ---------------------------------------------------------------------------
function buildWorkerSource(loaderPath: string, hangSentinel: string | null): string {
  const loaderLiteral = JSON.stringify(loaderPath);
  const sentinelLiteral = JSON.stringify(hangSentinel);
  return [
    "const { workerData, parentPort } = require('node:worker_threads');",
    "const { pathToFileURL } = require('node:url');",
    "const loaderPath = " + loaderLiteral + ";",
    "const wasmPath = workerData.wasmPath || undefined;",
    "const hangSentinel = " + sentinelLiteral + ";",
    "let cel = null;",
    "const ready = import(pathToFileURL(loaderPath).href).then(async (mod) => {",
    "  cel = await mod.RelayCel.load(wasmPath);",
    "  parentPort.postMessage({ kind: 'ready' });",
    "}).catch((e) => {",
    "  parentPort.postMessage({ kind: 'startup_error', message: (e && e.message) || String(e) });",
    "});",
    "parentPort.on('message', (msg) => {",
    "  if (msg.kind !== 'evaluate') return;",
    "  const reqId = msg.reqId;",
    "  // Deterministic timeout-injection hook (test-only; OFF in production).",
    "  // A synchronous spin keeps the Worker event loop busy so the host's",
    "  // worker.terminate() is the ONLY thing that can stop it -- exercising",
    "  // the real hard-kill path rather than a cooperative timer.",
    "  if (hangSentinel !== null && msg.expression === hangSentinel) {",
    "    // eslint-disable-next-line no-constant-condition",
    "    while (true) { /* spin until terminated by the host */ }",
    "  }",
    "  ready.then(async () => {",
    "    if (cel === null) {",
    "      parentPort.postMessage({ kind: 'result', reqId, envelope: { ok: false, code: 'RELAY-CEL-PANIC', error: 'wasm loader unavailable' } });",
    "      return;",
    "    }",
    "    try {",
    "      const envelope = await cel.eval(msg.expression, msg.bindings || undefined, { relayProfile: true });",
    "      parentPort.postMessage({ kind: 'result', reqId, envelope });",
    "    } catch (e) {",
    "      parentPort.postMessage({ kind: 'result', reqId, envelope: { ok: false, code: 'RELAY-CEL-PANIC', error: (e && e.message) || String(e) } });",
    "    }",
    "  });",
    "});",
  ].join("\n");
}

// Resolve the sibling `.mjs` loader path. wasm-evaluator.ts lives at
// packages/contracts-typescript/src/, so the loader is at
// packages/cel-wasm/typescript/relay-cel-wasm.mjs (three levels up + sibling
// package). Mirrors the Python _load_relay_cel_from_repo path resolution
// (wasm_backed_evaluator.py:116-136).
function defaultLoaderPath(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return resolve(
    here,
    "..",
    "..",
    "cel-wasm",
    "typescript",
    "relay-cel-wasm.mjs",
  );
}

// Per-evaluation request pending on a Worker reply.
interface PendingEval {
  resolve: (envelope: WasmResponseEnvelope) => void;
  reject: (err: unknown) => void;
}

export interface WasmCelBackendOptions {
  /** Per-evaluation wall-clock budget (ms). Defaults to DEFAULT_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Caller-supplied UDFs. Only the 3 native relay.* names are accepted. */
  udfs?: readonly PureUdf[];
  /** Override the wasm artifact path (else the loader's default / CEL_WASM). */
  wasmPath?: string;
  /** Override the `.mjs` loader path (default: the in-repo sibling loader). */
  loaderPath?: string;
  /**
   * Test-only deterministic timeout-injection sentinel. When set and an
   * evaluated expression equals it, the in-Worker runner blocks past the budget
   * so the host's worker.terminate() hard-kill path can be exercised. Undefined
   * in production (no branch is taken for any real expression).
   */
  hangSentinel?: string;
}

export class WasmCelBackend {
  public readonly timeoutMs: number;
  private readonly wasmPath: string | undefined;
  private readonly loaderPath: string;
  private readonly hangSentinel: string | null;

  // Lazy-spawned persistent Worker; null after construction and after every
  // termination (timeout / dispose), respawned on demand.
  private worker: Worker | null = null;
  private workerReady: Promise<void> | null = null;
  private nextReqId = 0;
  private readonly pending = new Map<number, PendingEval>();

  constructor(options: WasmCelBackendOptions = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new Error(
        `timeoutMs MUST be a positive integer; got ${String(timeoutMs)}`,
      );
    }
    if (timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(
        `timeoutMs exceeds Relay cap (${MAX_TIMEOUT_MS} ms); got ${timeoutMs}`,
      );
    }
    this.timeoutMs = timeoutMs;

    // Reject any caller-supplied extra UDF fail-closed BEFORE evaluation: the
    // wasm has no registration slot for a custom callable, so an unsupported UDF
    // is a structured RELAY-CEL-004 / UDF-UNREGISTERED error. The 3 native
    // relay.* UDFs are accepted (baked into the wasm). Mirrors the Python
    // WasmCelEvaluator.__init__ reject loop (wasm_backed_evaluator.py:173-185).
    for (const udf of options.udfs ?? []) {
      if (!NATIVE_UDF_NAMES.has(udf.name)) {
        throw new RelayCelUnsupportedUdfError(
          `WasmCelBackend: the wasm CEL engine exposes only the 3 native ` +
            `relay.* UDFs and has no registration slot for ${JSON.stringify(udf.name)}. ` +
            "Caller-supplied extra UDFs are rejected fail-closed before evaluation.",
        );
      }
    }

    this.wasmPath = options.wasmPath;
    this.loaderPath = options.loaderPath ?? defaultLoaderPath();
    this.hangSentinel = options.hangSentinel ?? null;
  }

  // --- compilation (host-side profile pre-screen) ------------------

  /**
   * Validate `expression` against the host-side pre-screens. Returns the
   * expression unchanged on success (the wasm compiles + checks the AST
   * itself). The regex-backreference pre-screen (RELAY-CEL-007 / REGEX-BACKREF)
   * runs HERE so a backref in any string literal surfaces the structured host
   * error BEFORE the wasm call. Mirrors WasmCelEvaluator.compile
   * (wasm_backed_evaluator.py:277-287).
   */
  compile(expression: string): string {
    checkRegexBackref(expression);
    return expression;
  }

  // --- evaluation (async) ------------------------------------------

  /**
   * Evaluate `expression` through the wasm under the Relay profile. Returns a
   * Promise (VAL-CWC-P2TSGATE-006) resolving to the host-checked result.
   *
   * Host guards run host-side: the regex-backref pre-screen (before the wasm
   * call) and checkFinite on the typedToNative-converted result. The wasm runs
   * inside a node:worker_threads Worker bounded by the wall-clock budget; on
   * budget exceed the Worker is hard-killed (worker.terminate()) and the
   * Promise rejects with RelayCelTimeoutError (VAL-CWC-P2TSGATE-008).
   */
  async evaluate(
    expression: string,
    bindings?: Record<string, unknown>,
  ): Promise<unknown> {
    // Host pre-screen (regex backref) BEFORE the wasm call (fail-closed).
    this.compile(expression);

    const typedBindings = this.encodeBindings(bindings);
    const envelope = await this.runOnWorker(expression, typedBindings);

    // Decode + host finiteness guard + engine-error mapping (a wasm {ok:false}
    // envelope throws the right structured error here, never host 004/006).
    return decodeWasmEnvelope(envelope);
  }

  // --- helpers -----------------------------------------------------

  /** Encode caller bindings into the wasm typed-canonical form (or undefined). */
  private encodeBindings(
    bindings: Record<string, unknown> | undefined,
  ): Record<string, TypedValue> | undefined {
    if (bindings === undefined) {
      return undefined;
    }
    const out: Record<string, TypedValue> = {};
    for (const [name, value] of Object.entries(bindings)) {
      out[name] = nativeToTyped(value);
    }
    return out;
  }

  /**
   * Run one evaluation on the persistent Worker, bounded by the wall-clock
   * budget. On timeout the Worker is hard-killed (terminate) and the resulting
   * Promise rejects with RelayCelTimeoutError; the Worker handle is dropped
   * (quarantined) so the next evaluate() respawns a fresh Worker -- the
   * (possibly mid-eval) wasm instance dies with the terminated Worker and never
   * corrupts the next evaluation. Per-runtime: this is the NODE path. The
   * Cloudflare Workers path is platform-CPU-limit-only until WS-J (see below);
   * we DO NOT silently skip the budget -- an explicit runtime branch selects the
   * Node Worker hard-kill here.
   */
  private async runOnWorker(
    expression: string,
    bindings: Record<string, TypedValue> | undefined,
  ): Promise<WasmResponseEnvelope> {
    if (!isNodeRuntime()) {
      // Cloudflare Workers (and other non-Node runtimes) have no
      // worker_threads + terminate primitive. Per the locked decision, the
      // wall-clock timeout there is the platform CPU limit ONLY, and the full
      // host-enforced hard-kill lands in WS-J (the edge work-stream). We do NOT
      // silently fall through a missing budget: surface a structured engine
      // error so a non-Node caller that reaches here before WS-J fails loud
      // rather than running unbounded.
      throw new RelayCelEngineError(
        "WasmCelBackend wall-clock hard-kill is Node-only until WS-J; the " +
          "Cloudflare path relies on the platform CPU limit and is wired in " +
          "the edge work-stream.",
        "RELAY-CEL-ENGINE-REQUEST",
      );
    }

    const worker = await this.ensureWorker();
    const reqId = this.nextReqId;
    this.nextReqId += 1;

    return await new Promise<WasmResponseEnvelope>((resolvePromise, rejectPromise) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) {
          return;
        }
        settled = true;
        this.pending.delete(reqId);
        // Hard-kill: abort the in-flight (or hung) evaluation. The wasm
        // instance lives inside this Worker, so terminating it discards the
        // instance; the next evaluate() respawns a clean Worker.
        this.disposeWorker();
        rejectPromise(
          new RelayCelTimeoutError(
            `Relay CEL wasm evaluation exceeded ${this.timeoutMs} ms ` +
              `wall-clock budget for expression: ${JSON.stringify(expression)}`,
          ),
        );
      }, this.timeoutMs);
      // Do not let the timer keep the event loop alive on its own.
      if (typeof timer.unref === "function") {
        timer.unref();
      }

      this.pending.set(reqId, {
        resolve: (envelope) => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          this.pending.delete(reqId);
          resolvePromise(envelope);
        },
        reject: (err) => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          this.pending.delete(reqId);
          rejectPromise(err);
        },
      });

      worker.postMessage({ kind: "evaluate", reqId, expression, bindings });
    });
  }

  /** Spawn (or return) the persistent Worker, awaiting its startup `ready`. */
  private ensureWorker(): Promise<Worker> {
    if (this.worker !== null && this.workerReady !== null) {
      const w = this.worker;
      return this.workerReady.then(() => w);
    }
    const source = buildWorkerSource(this.loaderPath, this.hangSentinel);
    const w = new Worker(source, {
      eval: true,
      workerData: { wasmPath: this.wasmPath ?? null },
    });
    this.worker = w;

    this.workerReady = new Promise<void>((resolveReady, rejectReady) => {
      const onMessage = (msg: {
        kind?: string;
        reqId?: number;
        envelope?: WasmResponseEnvelope;
        message?: string;
      }): void => {
        if (msg.kind === "ready") {
          resolveReady();
          return;
        }
        if (msg.kind === "startup_error") {
          rejectReady(
            new RelayCelEngineError(
              `wasm loader failed at Worker startup: ${msg.message ?? "unknown"}`,
              "RELAY-CEL-ENGINE-COMPILE",
            ),
          );
          return;
        }
        if (msg.kind === "result" && typeof msg.reqId === "number") {
          const p = this.pending.get(msg.reqId);
          if (p !== undefined && msg.envelope !== undefined) {
            p.resolve(msg.envelope);
          }
        }
      };
      w.on("message", onMessage);
      w.once("error", (err: Error) => {
        // A Worker-level error (not a wasm {ok:false} envelope) fails the
        // startup promise and any in-flight evaluations, then drops the handle.
        rejectReady(
          new RelayCelEngineError(
            `wasm Worker error: ${err.message}`,
            "RELAY-CEL-ENGINE-PANIC",
          ),
        );
        this.failAllPending(
          new RelayCelEngineError(
            `wasm Worker error: ${err.message}`,
            "RELAY-CEL-ENGINE-PANIC",
          ),
        );
        this.disposeWorker();
      });
    });
    // Keep the Worker from blocking process exit once tests finish.
    w.unref();
    return this.workerReady.then(() => w);
  }

  /** Reject every pending evaluation (used on Worker crash). */
  private failAllPending(err: unknown): void {
    for (const [, p] of this.pending) {
      p.reject(err);
    }
    this.pending.clear();
  }

  /** Terminate the Worker and drop the handle (quarantine). Non-throwing. */
  private disposeWorker(): void {
    const w = this.worker;
    this.worker = null;
    this.workerReady = null;
    if (w !== null) {
      void w.terminate();
    }
  }

  /**
   * Terminate the persistent Worker. Idempotent. Tests should call this in
   * afterEach / afterAll to free resources; production code may rely on
   * `worker.unref()` to avoid blocking process exit.
   */
  async dispose(): Promise<void> {
    const w = this.worker;
    this.worker = null;
    this.workerReady = null;
    this.failAllPending(
      new RelayCelEngineError(
        "WasmCelBackend disposed while an evaluation was in flight",
        "RELAY-CEL-ENGINE-REQUEST",
      ),
    );
    if (w !== null) {
      await w.terminate();
    }
  }
}

// Detect a Node runtime (vs Cloudflare Workers / other). node:worker_threads is
// available under Node; Cloudflare Workers expose neither `process.versions.node`
// nor worker_threads. The runtime branch is explicit (no silent fallthrough on
// the timeout budget) per VAL-CWC-P2TSGATE-008.
function isNodeRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    process.versions !== undefined &&
    typeof process.versions.node === "string"
  );
}
