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

import { existsSync, statSync } from "node:fs";
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
  WASM_PROFILE_SUBTYPES,
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
import {
  resolvePackagedLoaderPath,
  resolvePackagedWasmPath,
} from "./wasm-artifact.js";

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

// ---------------------------------------------------------------------------
// RelayDouble: an explicit CEL-double wrapper for a binding value.
//
// A plain JS `number` cannot carry the int/double distinction for a WHOLE value:
// `1.0 === 1` and `JSON.stringify(1.0) === "1"`, so `nativeToTyped(1.0)` collapses
// to {"t":"int","v":"1"}. The Python host's `py_to_typed(1.0)` (a Python float
// through the JSON wire boundary) keeps it {"t":"double","v":"1.0"}. When such a
// whole double is echoed through `relay.tool_arg`, the wasm udf_trace OUTPUT bytes
// then diverge -- a P0 keystone-#16 byte-parity break.
//
// `RelayDouble` is the JS analogue of Python's float / celtypes.DoubleType: a
// caller that needs a CEL double for a whole value wraps it
// (`new RelayDouble(1)`), and `nativeToTyped` encodes it as
// {"t":"double","v":"1.0"} regardless of whole-valuedness -- byte-identical to
// the Python `py_to_typed(1.0)`. A plain whole `number` still encodes as a CEL
// int, matching the JSON-wire-boundary parity the cross-host harness relies on
// (a JSON integer is an int on BOTH hosts).
//
// The constructor is fail-closed: a non-finite or non-number value is rejected
// (the codec never emits a non-finite double, mirroring the encode-path guard).
// ---------------------------------------------------------------------------
export class RelayDouble {
  /** The finite IEEE-754 double this wrapper forces into the CEL double class. */
  public readonly value: number;

  constructor(value: number) {
    if (typeof value !== "number") {
      throw new TypeError(
        `RelayDouble: value must be a number; got ${typeof value}`,
      );
    }
    if (!Number.isFinite(value)) {
      throw new RelayCelNumericOutOfBoundsError(
        `RelayDouble: value must be finite; got ${String(value)}`,
      );
    }
    this.value = value;
  }
}

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
  // RelayDouble: an explicit CEL double (the int/double distinction a bare JS
  // `number` cannot carry for a whole value). Classified BEFORE the generic
  // object/number branches so a RelayDouble(1) encodes {"t":"double","v":"1.0"}
  // -- byte-identical to the Python py_to_typed(1.0) -- rather than the int the
  // whole-valued number branch would produce. The wrapped value is finite by
  // construction, so canonicalDoubleString always yields a decimal/sign form.
  if (value instanceof RelayDouble) {
    return { t: "double", v: canonicalDoubleString(value.value) };
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
    // Non-integral -> double, canonical-g form (the faithful port of the Python
    // codec's _canonical_double / cel-go strconv.FormatFloat(f,'g',-1,64), NOT a
    // bare String(n), which diverges at the %e/%f boundary and exponent padding).
    return { t: "double", v: canonicalDoubleString(n) };
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
      // Decode keys first to learn whether ALL keys are strings. The wasm CAN
      // emit non-string map keys (key_sort_string supports bool/int/uint;
      // lib.rs:1126-1133), so a string-only assumption was wrong. We also must
      // be prototype-pollution-safe: a "__proto__" / "constructor" string key
      // assigned to a plain object literal could corrupt the prototype chain.
      const decoded: Array<[unknown, unknown]> = [];
      let allStringKeys = true;
      for (const pair of v as unknown[]) {
        if (!Array.isArray(pair) || pair.length !== 2) {
          throw new TypeError("typedToNative: map entry must be a [k,v] pair");
        }
        const key = typedToNative(pair[0] as TypedValue);
        if (typeof key !== "string") {
          allStringKeys = false;
        }
        decoded.push([key, typedToNative(pair[1] as TypedValue)]);
      }
      if (allStringKeys) {
        // String-only keys -> a null-prototype object (prototype-pollution-safe:
        // a "__proto__" / "constructor" key becomes a plain OWN property, never
        // touching the prototype chain). A null-prototype object with the same
        // own string-keyed properties is structurally a plain map (and compares
        // equal under deep-equality), preserving the existing round-trip
        // contract while closing the pollution hole.
        const out: Record<string, unknown> = Object.create(null) as Record<
          string,
          unknown
        >;
        for (const [key, val] of decoded) {
          out[key as string] = val;
        }
        return out;
      }
      // At least one non-string key (bool/int/uint) -> a JS Map, which preserves
      // the key TYPE (a plain object would coerce a number/bool key to a string).
      // A Map has no prototype-pollution surface (set() does not touch a
      // prototype chain). Mixed string/non-string keys also land here so the
      // types survive.
      const map = new Map<unknown, unknown>();
      for (const [key, val] of decoded) {
        map.set(key, val);
      }
      return map;
    }
    default:
      throw new TypeError(`typedToNative: unsupported typed tag ${String(t)}`);
  }
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// Decimal string for a whole-valued JS number, with NO exponent form, so the
// downstream BigInt() parse never sees scientific notation. `toFixed(0)` is NOT
// safe here: for |n| >= ~1e21 it returns exponential notation ("1e+21"), and
// `BigInt("1e+21")` throws a RAW SyntaxError instead of the structured
// RelayCelNumericOutOfBoundsError. `BigInt(n)` accepts an integral JS number
// directly and yields the EXACT integer decimal (no exponent), so the magnitude
// guard then raises the structured RELAY-CEL-006 error for an out-of-range
// value. The caller has already established Number.isInteger(n) is true.
function encodeIntString(n: number): string {
  // BigInt(<integral number>) is exact and never produces exponent form. (A
  // non-integral number would throw here, but the caller only invokes this on
  // an integral value, matching the Python str(int(value)) form.)
  return BigInt(n).toString(10);
}

// Absolute value of a BigInt (BigInt has no Math.abs).
function absBigInt(x: bigint): bigint {
  return x < 0n ? -x : x;
}

// Canonical-g double string. Faithful port of the Python codec's
// _canonical_double / _format_double_g (wasm_codec.py:87-159), itself
// byte-faithful to the Rust format_double_g (crate/src/lib.rs:1131-1203), which
// reproduces cel-go's strconv.FormatFloat(f, 'g', -1, 64). `String(n)` is NOT
// sufficient: it diverges at the %e/%f selection boundary and the exponent
// padding (e.g. 1e-7 -> JS "1e-7" but the canonical form is "1e-07"; 1000000.5
// -> JS "1000000.5" but the canonical form is "1.0000005e+06"; 1e5 -> JS
// "100000" but the canonical form is "100000.0"). Exported as
// `canonicalDoubleString` for the byte-parity test.
export function canonicalDoubleString(n: number): string {
  if (Number.isNaN(n)) {
    return "nan";
  }
  if (!Number.isFinite(n)) {
    return n > 0 ? "inf" : "-inf";
  }
  return formatDoubleG(n);
}

// Shortest round-trip decimal with cel-go's 'g'-verb %e/%f selection. Port of
// _format_double_g (wasm_codec.py:96-159) / format_double_g (lib.rs:1131-1203):
// switch to %e when the decimal exponent of the leading significant digit is
// < -4 or >= 6, else %f; %f always carries a decimal point so a whole double
// (1.0) is textually distinct from the int 1.
function formatDoubleG(f: number): string {
  if (f === 0) {
    // Go prints 0 as "0"; the typed form forces a decimal point downstream.
    return Object.is(f, -0) ? "-0.0" : "0.0";
  }

  // String(f) yields the shortest decimal that round-trips, the same shortest
  // representation Rust's {} for f64 / Python repr(float) produces. It may be in
  // exponent form (e.g. "1e+21", "1e-7"); normalise to significand digits + the
  // base-10 exponent of the leading significant digit.
  const shortest = String(f);
  const neg = shortest.startsWith("-");
  const mag = neg ? shortest.slice(1) : shortest;

  let digits: string;
  let exp10: number;
  if (mag.includes("e") || mag.includes("E")) {
    [digits, exp10] = parseExponentForm(mag);
  } else {
    const dot = mag.indexOf(".");
    const intPart = dot === -1 ? mag : mag.slice(0, dot);
    const fracPart = dot === -1 ? "" : mag.slice(dot + 1);
    if (intPart !== "0" && intPart !== "") {
      // exponent = len(int_part) - 1
      exp10 = intPart.length - 1;
      digits = intPart + fracPart;
    } else {
      // 0.xxxx -- find first nonzero in frac.
      let leadZeros = 0;
      for (const c of fracPart) {
        if (c === "0") {
          leadZeros += 1;
        } else {
          break;
        }
      }
      exp10 = -leadZeros - 1;
      digits = fracPart.slice(leadZeros);
    }
  }

  // Strip trailing zeros of the significand.
  while (digits.length > 1 && digits.endsWith("0")) {
    digits = digits.slice(0, -1);
  }
  if (digits.length === 0) {
    digits = "0";
  }

  const sign = neg ? "-" : "";

  if (exp10 < -4 || exp10 >= 6) {
    // %e: d.dddde(+/-)XX, exponent at least two digits.
    const first = digits.slice(0, 1);
    const rest = digits.slice(1);
    const mantissa = rest.length === 0 ? first : `${first}.${rest}`;
    const esign = exp10 < 0 ? "-" : "+";
    const eabs = Math.abs(exp10);
    const eabsStr = eabs < 10 ? `0${eabs}` : String(eabs);
    return `${sign}${mantissa}e${esign}${eabsStr}`;
  }

  // %f form -- reconstruct then force a decimal point.
  let s = reconstructFixed(digits, exp10);
  if (!s.includes(".")) {
    s = `${s}.0`;
  }
  return `${sign}${s}`;
}

// Significand digits + leading-digit base-10 exponent for an exponent-form
// magnitude string like "1e+21" / "1.5e-7". Mirrors _parse_exponent_form
// (wasm_codec.py:162-174). JS Number.toString exponent form normalises to one
// leading nonzero integer digit, so the leading-digit exponent is exactly the
// printed exponent.
function parseExponentForm(mag: string): [string, number] {
  const eIdx = mag.search(/[eE]/);
  const mantissa = mag.slice(0, eIdx);
  const exp = Number.parseInt(mag.slice(eIdx + 1), 10);
  const dot = mantissa.indexOf(".");
  const intPart = dot === -1 ? mantissa : mantissa.slice(0, dot);
  const fracPart = dot === -1 ? "" : mantissa.slice(dot + 1);
  return [intPart + fracPart, exp];
}

// Fixed-point text from significand digits + leading-digit exponent. Mirrors
// _reconstruct_fixed (wasm_codec.py:177-191) / reconstruct_fixed
// (lib.rs:1207-1227).
function reconstructFixed(digits: string, exp10: number): string {
  if (exp10 >= 0) {
    const intLen = exp10 + 1;
    if (digits.length <= intLen) {
      // pad with trailing zeros.
      return digits + "0".repeat(intLen - digits.length);
    }
    const intS = digits.slice(0, intLen);
    const fracS = digits.slice(intLen);
    return `${intS}.${fracS}`;
  }
  // 0.00..digits with (-exp10 - 1) leading zeros after the point.
  const lead = -exp10 - 1;
  return `0.${"0".repeat(lead)}${digits}`;
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

// The wasm emits bytes as LOWERCASE hex (lib.rs:1143-1145). The strict matcher
// accepts only [0-9a-f] (no uppercase, no non-hex char), so a non-canonical or
// malformed encoding is rejected rather than silently mis-decoded.
const LOWERCASE_HEX_RE = /^[0-9a-f]*$/;

// Decode lowercase-hex bytes to a Uint8Array (inverse of lib.rs:1143-1145).
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new TypeError(
      `typedToNative: bytes hex must have even length, got ${hex.length}`,
    );
  }
  // Validate the WHOLE string up front: Number.parseInt(pair, 16) accepts a
  // PARTIAL hex pair (e.g. parseInt('0g', 16) === 0), silently dropping the
  // invalid nibble. The strict [0-9a-f] matcher rejects any non-(lowercase-hex)
  // character, including uppercase, which the wasm never emits.
  if (!LOWERCASE_HEX_RE.test(hex)) {
    throw new TypeError(
      `typedToNative: bytes 'v' is not valid lowercase hex: ${JSON.stringify(hex)}`,
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    // Each pair is now guaranteed two lowercase-hex chars, so parseInt is exact.
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
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
    // Validate the subtype against the KNOWN wasm profile subtype set
    // (DYN/TS/DUR/STRUCT) BEFORE casting it onto RelayCelProfileError. The wasm
    // should never emit an unknown profile subtype; if it does, that is an
    // engine-request anomaly, not a trustworthy profile rejection -- treating it
    // as one would let a bogus signed per-condition subtype through.
    if (!WASM_PROFILE_SUBTYPES.has(subtype as RelayCelSubtype)) {
      throw new RelayCelEngineError(
        `wasm profile rejection carried an unknown structured subtype ` +
          `${JSON.stringify(subtype)}: ${message}`,
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
//
// `startupHangSentinel` is a second OPT-IN test affordance: when true, the
// Worker busy-blocks DURING startup (before posting `ready`) so the host's
// bounded-startup gate can be exercised against a genuinely-stuck startup
// (loader import / RelayCel.load() never completing). It is false in production,
// so startup proceeds normally for any real backend.
// ---------------------------------------------------------------------------
function buildWorkerSource(
  loaderPath: string,
  hangSentinel: string | null,
  startupHangSentinel: boolean,
): string {
  const loaderLiteral = JSON.stringify(loaderPath);
  const sentinelLiteral = JSON.stringify(hangSentinel);
  const startupHangLiteral = JSON.stringify(startupHangSentinel);
  return [
    "const { workerData, parentPort } = require('node:worker_threads');",
    "const { pathToFileURL } = require('node:url');",
    "const loaderPath = " + loaderLiteral + ";",
    "const wasmPath = workerData.wasmPath || undefined;",
    "const hangSentinel = " + sentinelLiteral + ";",
    "const startupHangSentinel = " + startupHangLiteral + ";",
    "if (startupHangSentinel === true) {",
    "  // Deterministic startup-hang injection (test-only; OFF in production).",
    "  // Block BEFORE posting 'ready' so the host's bounded ensureWorker()+eval",
    "  // timeout is the only thing that can unblock the first evaluate().",
    "  // eslint-disable-next-line no-constant-condition",
    "  while (true) { /* spin until terminated by the host */ }",
    "}",
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

// Resolve the `.mjs` loader path, preferring the PACKAGED loader.
//
// WS-G ships a git-tracked vendored copy of the canonical loader as package data
// (@epochly/relay-contracts/src/_wasm/relay-cel-wasm.mjs, in package.json
// `files`), so an INSTALLED package can construct the wasm backend WITHOUT the
// repo sibling path (which does NOT exist in an install). Resolution order:
//   1. the packaged loader (resolvePackagedLoaderPath) -- works from both the
//      dev tree and a fresh install (the `src` dir ships in `files`);
//   2. the repo sibling packages/cel-wasm/typescript/relay-cel-wasm.mjs (three
//      levels up + sibling package) as a DEV fallback when the package-data copy
//      is somehow absent.
// Mirrors the Python _load_relay_cel_class resolution order (package-data loader
// after the in-repo dev path) -- both ecosystems ship the SAME loader bytes (a
// byte-identity drift guard enforces it), so either path loads an identical
// loader.
export function defaultLoaderPath(): string {
  const packaged = resolvePackagedLoaderPath();
  if (packaged !== null) {
    return packaged;
  }
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
  /**
   * Test-only deterministic STARTUP-hang sentinel. When true, the Worker blocks
   * during startup (before posting `ready`) so the host's bounded
   * ensureWorker()+eval timeout can be exercised against a genuinely-stuck
   * startup. False/undefined in production (startup proceeds normally).
   */
  startupHangSentinel?: boolean;
}

export class WasmCelBackend {
  public readonly timeoutMs: number;
  private readonly wasmPath: string | undefined;
  private readonly loaderPath: string;
  private readonly hangSentinel: string | null;
  private readonly startupHangSentinel: boolean;

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

    // Resolve the wasm artifact path (WS-G, VAL-CWC-P3CORPUS-009/011):
    //   - an explicit options.wasmPath wins (the override / presence-gate path);
    //   - otherwise resolve the WS-G PACKAGE-DATA wasm
    //     (@epochly/relay-contracts/src/_wasm/relay_cel_wasm.wasm) so an
    //     installed package finds the engine WITHOUT crate/target/. If the
    //     package-data copy is absent, leave wasmPath undefined so the `.mjs`
    //     loader applies its OWN default (package-data probe then crate/target)
    //     / CEL_WASM env resolution -- env access stays in the loader, never in
    //     this src tree. Mirrors the Python _resolve_wasm_path_or_none
    //     (wasm_backed_evaluator.py:295-313).
    if (options.wasmPath !== undefined) {
      this.wasmPath = options.wasmPath;
    } else {
      const packaged = resolvePackagedWasmPath();
      this.wasmPath = packaged ?? undefined;
    }
    this.loaderPath = options.loaderPath ?? defaultLoaderPath();
    this.hangSentinel = options.hangSentinel ?? null;
    this.startupHangSentinel = options.startupHangSentinel ?? false;
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

  /**
   * Artifact-presence gate (WS-G, VAL-CWC-P3CORPUS-011). When a concrete wasm
   * path is configured (an explicit options.wasmPath, or the resolved
   * package-data path) but it is NOT an existing regular file, throw a
   * structured RelayCelEngineError (RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST)
   * rather than letting the loader's readFileSync raise a bare ENOENT inside the
   * Worker. An unset wasmPath is a no-op here: the `.mjs` loader applies its own
   * default (package-data probe -> crate/target) / CEL_WASM resolution and fails
   * loud at startup if nothing resolves. Mirrors the Python _resolve_wasm_path
   * override gate (wasm_backed_evaluator.py:268-275).
   */
  private checkConfiguredWasmPresent(): void {
    const configured = this.wasmPath;
    if (configured === undefined) {
      return;
    }
    let present = false;
    try {
      present = existsSync(configured) && statSync(configured).isFile();
    } catch {
      present = false;
    }
    if (!present) {
      throw new RelayCelEngineError(
        `wasm CEL artifact not resolvable at the configured path ` +
          `${JSON.stringify(configured)} (file does not exist). Build it via ` +
          "'bash packages/cel-wasm/conformance/build.sh build', set the " +
          "CEL_WASM env override, or install an @epochly/relay-contracts " +
          "package that ships the wasm package data.",
        "RELAY-CEL-ENGINE-REQUEST",
      );
    }
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
    // Artifact-presence gate (WS-G, VAL-CWC-P3CORPUS-011): when an explicit wasm
    // path is configured but absent, surface a structured RelayCelEngineError
    // (RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST) BEFORE any wasm load -- never a
    // bare ENOENT escaping the loader's readFileSync as an unhandled rejection.
    // A configured-but-absent path is the presence-gate case the test exercises;
    // an unset wasmPath defers to the `.mjs` loader's own default resolution.
    // Mirrors the Python _resolve_wasm_path override gate
    // (wasm_backed_evaluator.py:268-275).
    this.checkConfiguredWasmPresent();

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
   *
   * The wall-clock budget covers the WHOLE sequence -- ensureWorker() (Worker
   * spawn + loader import + RelayCel.load()) AND the eval -- so a stalled
   * STARTUP (loader import / RelayCel.load() that never resolves) cannot hang
   * the first evaluate() forever past the budget (a bug if the timeout were
   * installed only AFTER awaiting ensureWorker()). The single deadline timer is
   * armed BEFORE awaiting ensureWorker().
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

    return await new Promise<WasmResponseEnvelope>((resolvePromise, rejectPromise) => {
      let settled = false;
      let reqId: number | null = null;

      const onTimeout = (): void => {
        if (settled) {
          return;
        }
        settled = true;
        if (reqId !== null) {
          this.pending.delete(reqId);
        }
        // Hard-kill: abort the in-flight (or hung) evaluation / startup. The
        // wasm instance lives inside this Worker, so terminating it discards the
        // instance; the next evaluate() respawns a clean Worker. BEFORE
        // disposing, reject every PEER pending request on this shared Worker --
        // they are being hard-killed under the same terminate() and must NOT be
        // left hanging until their own timers fire (finding 7).
        const timeoutErr = new RelayCelTimeoutError(
          `Relay CEL wasm evaluation exceeded ${this.timeoutMs} ms ` +
            `wall-clock budget for expression: ${JSON.stringify(expression)}`,
        );
        this.failAllPending(
          new RelayCelEngineError(
            "wasm Worker terminated by a concurrent evaluation's wall-clock " +
              "timeout; this evaluation was hard-killed under the shared Worker",
            "RELAY-CEL-ENGINE-REQUEST",
          ),
        );
        this.disposeWorker();
        rejectPromise(timeoutErr);
      };

      const timer = setTimeout(onTimeout, this.timeoutMs);
      // Do not let the timer keep the event loop alive on its own.
      if (typeof timer.unref === "function") {
        timer.unref();
      }

      // The deadline timer is now armed; awaiting ensureWorker() below is thus
      // ALSO bounded by it (finding 6). ensureWorker() may reject (a startup
      // error) -- propagate that, clearing the timer first.
      this.ensureWorker()
        .then((worker) => {
          if (settled) {
            // The deadline already fired (a hung startup): the Worker, if it
            // resolved, is stale -- do not post to it.
            return;
          }
          const id = this.nextReqId;
          this.nextReqId += 1;
          reqId = id;
          this.pending.set(id, {
            resolve: (envelope) => {
              if (settled) {
                return;
              }
              settled = true;
              clearTimeout(timer);
              this.pending.delete(id);
              resolvePromise(envelope);
            },
            reject: (err) => {
              if (settled) {
                return;
              }
              settled = true;
              clearTimeout(timer);
              this.pending.delete(id);
              rejectPromise(err);
            },
          });
          worker.postMessage({ kind: "evaluate", reqId: id, expression, bindings });
        })
        .catch((err: unknown) => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          rejectPromise(err);
        });
    });
  }

  /** Spawn (or return) the persistent Worker, awaiting its startup `ready`. */
  private ensureWorker(): Promise<Worker> {
    if (this.worker !== null && this.workerReady !== null) {
      const w = this.worker;
      return this.workerReady.then(() => w);
    }
    const source = buildWorkerSource(
      this.loaderPath,
      this.hangSentinel,
      this.startupHangSentinel,
    );
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
