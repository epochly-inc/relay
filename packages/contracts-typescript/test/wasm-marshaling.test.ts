// VAL-CWC-P2TSGATE-005: native<->typed marshaling classification parity with
// cel-python json_to_cel, plus typedToNative round-trip identity.
//
// `wasm-evaluator.ts` exposes nativeToTyped / typedToNative -- the canonical TS
// half of the wasm typed-canonical {"t","v"} codec. The classification of a JS
// `number` MUST match cel-python's json_to_cel through the JSON wire boundary
// (CLAUDE.md keystone invariant #16, a P0 byte-parity contract):
//   - a whole-valued JS number with magnitude <= 2**53 - 1  -> CEL int  (t:'int')
//   - any other finite JS number                            -> CEL double (t:'double')
//   - an INTEGRAL JS number whose magnitude exceeds
//     Number.MAX_SAFE_INTEGER (2**53 - 1) is REJECTED at the boundary, with the
//     overflow checked via BigInt on the EXACT decimal string (NOT a float64
//     comparison, which loses precision at that scale) -> RelayCelNumericOutOfBoundsError
//     (RELAY-CEL-006 / RELAY-CEL-NUMERIC-OOB).
// typedToNative inverts nativeToTyped for every CEL value class (round-trip
// identity): int / uint / double / string / bool / null / bytes / list / map.
//
// Tool: vitest. Evidence: vitest exit code + the asserted {t,v} strings.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  RelayCelNumericOutOfBoundsError,
  SUBTYPE_NUMERIC_OOB,
} from "../src/index.js";
import {
  nativeToTyped,
  typedToNative,
  type TypedValue,
} from "../src/wasm-evaluator.js";

describe("VAL-CWC-P2TSGATE-005: nativeToTyped int/double classification", () => {
  // Acceptance case (a): a whole-valued number is a CEL int with a decimal
  // string `v` (mirrors cel-python json_to_cel: a JSON integer -> IntType,
  // string-encoded in the typed-canonical form per wasm_codec.py:231).
  test("(a) nativeToTyped(5) -> {t:'int', v:'5'}", () => {
    expect(nativeToTyped(5)).toEqual({ t: "int", v: "5" });
  });

  // Acceptance case (b): a non-integral number is a CEL double, canonical-g
  // form (mirrors json_to_cel: a JSON float -> DoubleType).
  test("(b) nativeToTyped(1.5) -> {t:'double', v:'1.5'}", () => {
    expect(nativeToTyped(1.5)).toEqual({ t: "double", v: "1.5" });
  });

  // Acceptance case (c): exactly 2**53 (=== 9007199254740992) is an integral
  // value whose magnitude EXCEEDS Number.MAX_SAFE_INTEGER, so it is rejected at
  // the codec boundary with RELAY-CEL-006. The check uses BigInt on the decimal
  // string, not a float compare.
  test("(c) nativeToTyped(2**53) throws RelayCelNumericOutOfBoundsError (RELAY-CEL-006)", () => {
    expect(2 ** 53).toBe(9007199254740992);
    let caught: unknown = null;
    try {
      nativeToTyped(2 ** 53);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    const err = caught as RelayCelNumericOutOfBoundsError;
    expect(err.code).toBe("RELAY-CEL-006");
    expect(err.subtype).toBe(SUBTYPE_NUMERIC_OOB);
  });

  // The largest whole number accepted: 2**53 - 1 == Number.MAX_SAFE_INTEGER.
  test("the boundary value 2**53 - 1 is accepted as CEL int", () => {
    expect(nativeToTyped(2 ** 53 - 1)).toEqual({
      t: "int",
      v: "9007199254740991",
    });
  });

  // Negative integers classify as int and string-encode the sign.
  test("negative whole-valued numbers are CEL int with a signed decimal string", () => {
    expect(nativeToTyped(-7)).toEqual({ t: "int", v: "-7" });
    expect(nativeToTyped(-(2 ** 53 - 1))).toEqual({
      t: "int",
      v: "-9007199254740991",
    });
  });

  // A negative integral overflow past -(2**53 - 1) is rejected via BigInt on
  // the decimal string (the magnitude check is sign-independent).
  test("a negative integral overflow magnitude > 2**53 - 1 is rejected", () => {
    let caught: unknown = null;
    try {
      nativeToTyped(-(2 ** 53)); // -9007199254740992
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  // BigInt-not-float64 proof: the overflow magnitude check operates on the
  // EXACT decimal string. A larger integral float (1e18) still throws.
  test("a large integral product (1e9 * 1e9 = 1e18) is rejected", () => {
    let caught: unknown = null;
    try {
      nativeToTyped(1000000000 * 1000000000);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).code).toBe(
      "RELAY-CEL-006",
    );
  });

  // Zero classifies as int (whole-valued); negative zero too (it is integral).
  test("0 is CEL int '0'", () => {
    expect(nativeToTyped(0)).toEqual({ t: "int", v: "0" });
  });

  // A small whole-valued double-magnitude number stays int; a fractional one is
  // a double -- this is the int/double boundary, matching json_to_cel.
  test("100 -> int, 100.5 -> double", () => {
    expect(nativeToTyped(100)).toEqual({ t: "int", v: "100" });
    expect(nativeToTyped(100.5)).toEqual({ t: "double", v: "100.5" });
  });

  // A bigint binds as an arbitrary-precision CEL int (no float rounding).
  test("a bigint binds as CEL int (arbitrary precision)", () => {
    expect(nativeToTyped(42n)).toEqual({ t: "int", v: "42" });
  });

  // Non-finite numbers are rejected (NaN / +Inf / -Inf cannot be a CEL int or
  // a representable double on the binding path).
  test("non-finite numbers are rejected", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      let caught: unknown = null;
      try {
        nativeToTyped(bad);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    }
  });

  // bool is classified BEFORE number (a JS boolean must never fall through to
  // the int branch) -- the cross-host bool-before-int invariant (wasm_codec.py
  // py_to_typed classifies bool first; lib.rs:1141 JSON boolean).
  test("bool classifies as {t:'bool'}, never {t:'int'}", () => {
    expect(nativeToTyped(true)).toEqual({ t: "bool", v: true });
    expect(nativeToTyped(false)).toEqual({ t: "bool", v: false });
  });

  // null and undefined both map to the no-"v" null form (lib.rs:1142).
  test("null and undefined -> {t:'null'} (no 'v' key)", () => {
    expect(nativeToTyped(null)).toEqual({ t: "null" });
    expect(nativeToTyped(undefined)).toEqual({ t: "null" });
  });

  test("strings, arrays, and objects classify to string/list/map", () => {
    expect(nativeToTyped("hi")).toEqual({ t: "string", v: "hi" });
    expect(nativeToTyped([1, 2])).toEqual({
      t: "list",
      v: [
        { t: "int", v: "1" },
        { t: "int", v: "2" },
      ],
    });
    // map entries sorted by the wasm key_sort_string (string keys: lexical).
    expect(nativeToTyped({ b: 2, a: 1 })).toEqual({
      t: "map",
      v: [
        [
          { t: "string", v: "a" },
          { t: "int", v: "1" },
        ],
        [
          { t: "string", v: "b" },
          { t: "int", v: "2" },
        ],
      ],
    });
  });
});

describe("VAL-CWC-P2TSGATE-005: typedToNative round-trip identity", () => {
  // Acceptance case (d): typedToNative inverts nativeToTyped for each value
  // class. For int/double/string/bool/null the round-trip is exact identity on
  // the JS value; uint/bytes/list/map decode to their canonical JS forms.

  test("(d) typedToNative inverts nativeToTyped for scalars", () => {
    expect(typedToNative(nativeToTyped(5))).toBe(5);
    expect(typedToNative(nativeToTyped(-7))).toBe(-7);
    expect(typedToNative(nativeToTyped(0))).toBe(0);
    expect(typedToNative(nativeToTyped(1.5))).toBe(1.5);
    expect(typedToNative(nativeToTyped(100.5))).toBe(100.5);
    expect(typedToNative(nativeToTyped("hi"))).toBe("hi");
    expect(typedToNative(nativeToTyped(true))).toBe(true);
    expect(typedToNative(nativeToTyped(false))).toBe(false);
    expect(typedToNative(nativeToTyped(null))).toBe(null);
  });

  test("typedToNative round-trips the largest accepted int (2**53 - 1)", () => {
    const t = nativeToTyped(2 ** 53 - 1);
    expect(typedToNative(t)).toBe(2 ** 53 - 1);
  });

  test("typedToNative round-trips a list (order preserved)", () => {
    const native = [1, 2, "x", true];
    const typed = nativeToTyped(native);
    expect(typedToNative(typed)).toEqual([1, 2, "x", true]);
  });

  test("typedToNative round-trips a map back to a plain object", () => {
    const native = { a: 1, b: "two", c: true };
    const typed = nativeToTyped(native);
    expect(typedToNative(typed)).toEqual({ a: 1, b: "two", c: true });
  });

  test("typedToNative round-trips a nested list/map structure", () => {
    const native = { outer: [{ k: 1 }, { k: 2 }], flag: false };
    const typed = nativeToTyped(native);
    expect(typedToNative(typed)).toEqual(native);
  });

  // uint has no JS native source via nativeToTyped, but typedToNative must
  // decode it (the wasm may emit a uint). It decodes to a JS number when in the
  // safe range; a uint exceeding the safe range is rejected at the boundary
  // (a JS number cannot represent it exactly).
  test("typedToNative decodes a uint within the safe range to a JS number", () => {
    const t: TypedValue = { t: "uint", v: "42" };
    expect(typedToNative(t)).toBe(42);
  });

  test("typedToNative rejects an int/uint string exceeding the safe range", () => {
    const overInt: TypedValue = { t: "int", v: "9007199254740992" };
    const overUint: TypedValue = { t: "uint", v: "9007199254740992" };
    for (const t of [overInt, overUint]) {
      let caught: unknown = null;
      try {
        typedToNative(t);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
      expect((caught as RelayCelNumericOutOfBoundsError).code).toBe(
        "RELAY-CEL-006",
      );
    }
  });

  // bytes decodes from lowercase hex to a Uint8Array; round-trips back to the
  // same hex via nativeToTyped is not symmetric (nativeToTyped has no bytes
  // input), so we assert the decode shape directly.
  test("typedToNative decodes bytes lowercase hex to a Uint8Array", () => {
    const t: TypedValue = { t: "bytes", v: "deadbeef" };
    const out = typedToNative(t);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(Array.from(out as Uint8Array)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  // double sentinel decode: inf / -inf / nan and a plain decimal.
  test("typedToNative decodes double sentinels and decimals", () => {
    expect(typedToNative({ t: "double", v: "inf" })).toBe(
      Number.POSITIVE_INFINITY,
    );
    expect(typedToNative({ t: "double", v: "-inf" })).toBe(
      Number.NEGATIVE_INFINITY,
    );
    expect(Number.isNaN(typedToNative({ t: "double", v: "nan" }))).toBe(true);
    expect(typedToNative({ t: "double", v: "1.5" })).toBe(1.5);
  });

  test("typedToNative rejects a malformed typed object", () => {
    // missing 't'
    expect(() => typedToNative({} as unknown as TypedValue)).toThrow();
    // missing 'v' on a tag that requires it
    expect(() =>
      typedToNative({ t: "int" } as unknown as TypedValue),
    ).toThrow();
    // unknown tag
    expect(() =>
      typedToNative({ t: "weird", v: "x" } as unknown as TypedValue),
    ).toThrow();
  });
});
