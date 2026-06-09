// ROBOREV round-2 findings D + E: the typedToNative non-string-map-key decode
// must be LOSSLESS, and nativeToTyped must round-trip the decoded map.
//
// Finding D (HIGH): typedToNative decoded a non-string map key via typedToNative,
// so CEL {"t":"int","v":"1"} and {"t":"uint","v":"1"} both became JS number 1 and
// collapsed to ONE Map entry -- silent data loss (the key TYPE was lost and a
// genuine two-entry CEL map became one). The Python codec (wasm_codec.py
// typed_to_py) PRESERVES the key type (IntType(1) vs UintType(1)) and FAILS
// CLOSED (celpy MapType raises TypeError) when an int key and a uint key of the
// same numeric value collide -- the two engines must AGREE.
//
// Finding E (HIGH): nativeToTyped had no Map branch, so a decoded non-string-keyed
// Map re-encoded through the object branch -> Object.keys(new Map()) is empty ->
// the map round-tripped to an EMPTY CEL map. The Map branch must re-emit the
// original typed keys, sorted by the wasm key_sort_string order, so decode->encode
// is byte-identical.
//
// The fix: a non-string-keyed CEL map decodes to a JS Map whose KEYS are the
// original TypedValue objects (lossless: int vs uint vs bool are distinct), with
// a key_sort_string collision check that fails closed on a true duplicate key.
// nativeToTyped gains a Map branch that re-emits those typed keys in
// key_sort_string order, so the round-trip is byte-identical -- byte-symmetric
// with the Python codec (keystone invariant #16).
//
// Tool: vitest. Evidence: vitest exit code + the decoded Map contents and the
// re-encoded typed form.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import { RelayCelEngineError } from "../src/errors.js";
import {
  keySortString,
  nativeToTyped,
  typedToNative,
  type TypedValue,
} from "../src/wasm-evaluator.js";

describe("roborev round-2 finding D: int/uint map keys do not collide on decode", () => {
  test("an int-key 1 and a uint-key 1 in the same map are BOTH preserved (no collapse)", () => {
    const typed: TypedValue = {
      t: "map",
      v: [
        [{ t: "int", v: "1" }, { t: "string", v: "as_int" }],
        [{ t: "uint", v: "1" }, { t: "string", v: "as_uint" }],
      ],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    // Both entries survive: the int 1 and the uint 1 are DISTINCT keys (the bug
    // collapsed them to a single number-1 entry).
    expect(m.size).toBe(2);
    // The decoded keys carry the TYPE (TypedValue {t,v}); looking them up by the
    // canonical key_sort_string locates each distinct entry.
    const bySort = new Map<string, unknown>();
    for (const [k, val] of m) {
      bySort.set(keySortString(k as TypedValue), val);
    }
    expect(bySort.get(keySortString({ t: "int", v: "1" }))).toBe("as_int");
    expect(bySort.get(keySortString({ t: "uint", v: "1" }))).toBe("as_uint");
  });

  test("a true duplicate key (two identical int keys) FAILS CLOSED, matching the Python codec", () => {
    // Two identical {"t":"int","v":"5"} keys cannot both exist in one CEL map.
    // The Python celpy MapType raises on a duplicate insert; the TS decode must
    // also reject (fail closed) rather than silently keep the last write.
    const typed: TypedValue = {
      t: "map",
      v: [
        [{ t: "int", v: "5" }, { t: "string", v: "first" }],
        [{ t: "int", v: "5" }, { t: "string", v: "second" }],
      ],
    };
    expect(() => typedToNative(typed)).toThrow(RelayCelEngineError);
  });

  test("a single int key still decodes losslessly (existing contract preserved)", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "int", v: "7" }, { t: "string", v: "seven" }]],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    expect(m.size).toBe(1);
    const [key, val] = [...m.entries()][0]!;
    expect(keySortString(key as TypedValue)).toBe(
      keySortString({ t: "int", v: "7" }),
    );
    expect(val).toBe("seven");
  });
});

describe("roborev round-2 finding E: nativeToTyped round-trips a decoded non-string-keyed Map", () => {
  test("decode -> encode of an int/uint/bool/string mixed-key map is BYTE-IDENTICAL", () => {
    // Mixed key types, deliberately out of key_sort_string order on the wire so
    // the re-encode's sort is exercised: bool < int < uint < string.
    const typed: TypedValue = {
      t: "map",
      v: [
        [{ t: "string", v: "s" }, { t: "int", v: "0" }],
        [{ t: "uint", v: "2" }, { t: "int", v: "1" }],
        [{ t: "int", v: "5" }, { t: "int", v: "2" }],
        [{ t: "bool", v: true }, { t: "int", v: "3" }],
      ],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    // Re-encode and compare to the canonical (key_sort_string-sorted) form.
    const reencoded = nativeToTyped(decoded);
    const expected: TypedValue = {
      t: "map",
      v: [
        [{ t: "bool", v: true }, { t: "int", v: "3" }],
        [{ t: "int", v: "5" }, { t: "int", v: "2" }],
        [{ t: "uint", v: "2" }, { t: "int", v: "1" }],
        [{ t: "string", v: "s" }, { t: "int", v: "0" }],
      ],
    };
    expect(reencoded).toEqual(expected);
    // And the re-encode is NOT the empty-map bug.
    expect((reencoded as { v: unknown[] }).v.length).toBe(4);
  });

  test("a non-string-keyed map does NOT re-encode as an EMPTY map (the finding-E bug)", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "int", v: "9" }, { t: "string", v: "nine" }]],
    };
    const decoded = typedToNative(typed);
    const reencoded = nativeToTyped(decoded) as { t: string; v: unknown[] };
    expect(reencoded.t).toBe("map");
    expect(reencoded.v.length).toBe(1);
    expect(reencoded).toEqual(typed);
  });

  test("a STRING-only-keyed map still decodes to a plain object and round-trips", () => {
    // The string-only path is unchanged (a null-prototype object, not a Map),
    // and still round-trips through the object branch.
    const typed: TypedValue = {
      t: "map",
      v: [
        [{ t: "string", v: "a" }, { t: "int", v: "1" }],
        [{ t: "string", v: "b" }, { t: "int", v: "2" }],
      ],
    };
    const decoded = typedToNative(typed);
    expect(decoded).not.toBeInstanceOf(Map);
    expect(nativeToTyped(decoded)).toEqual(typed);
  });
});

describe("roborev round-2 finding C symmetry: the TS codec has no duration encode/decode path", () => {
  // The negative-sub-second-duration sign corruption (finding C) lives ONLY in
  // the Python codec, which handles celtypes DurationType. The TS codec has NO
  // duration support: nativeToTyped throws on any non-encodable binding type, and
  // typedToNative rejects a {"t":"duration"} tag (it is not in the TypedValue
  // union and hits the default throw). So the TS side CANNOT silently corrupt a
  // duration -- it fails closed by construction, byte-symmetric with the Python
  // fail-closed guard (neither runtime emits a wrong-signed duration).
  test("typedToNative rejects a duration tag (fail closed, no silent decode)", () => {
    // Cast through unknown: a duration tag is intentionally NOT a TypedValue.
    const durationTag = { t: "duration", v: "0.250000000" } as unknown as TypedValue;
    expect(() => typedToNative(durationTag)).toThrow();
  });

  test("typedToNative rejects a timestamp tag (fail closed, same posture)", () => {
    const tsTag = {
      t: "timestamp",
      v: "2024-01-01T00:00:00Z",
    } as unknown as TypedValue;
    expect(() => typedToNative(tsTag)).toThrow();
  });
});

describe("roborev round-2: keySortString mirrors the Python _key_sort_string buckets", () => {
  test("bucket order bool(0) < int(1) < uint(2) < string(3)", () => {
    const sBool = keySortString({ t: "bool", v: false });
    const sInt = keySortString({ t: "int", v: "0" });
    const sUint = keySortString({ t: "uint", v: "0" });
    const sStr = keySortString({ t: "string", v: "" });
    expect(sBool < sInt).toBe(true);
    expect(sInt < sUint).toBe(true);
    expect(sUint < sStr).toBe(true);
  });

  test("int and uint of the same numeric value have DISTINCT sort keys", () => {
    expect(keySortString({ t: "int", v: "1" })).not.toBe(
      keySortString({ t: "uint", v: "1" }),
    );
  });

  test("negative ints sort before positive (i64 + 2**63 offset, zero-padded)", () => {
    expect(keySortString({ t: "int", v: "-3" }) < keySortString({ t: "int", v: "0" })).toBe(true);
    expect(keySortString({ t: "int", v: "0" }) < keySortString({ t: "int", v: "3" })).toBe(true);
  });
});
