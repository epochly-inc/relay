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
// Scope (VAL-CWC-P2TSGATE-005): CODEC ONLY. No wasm loading, no evaluator
// orchestration (that is P2TSGATE-007); this file is the codec's declared home
// and grows the host wiring in a later feature.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { RelayCelNumericOutOfBoundsError } from "./errors.js";

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
