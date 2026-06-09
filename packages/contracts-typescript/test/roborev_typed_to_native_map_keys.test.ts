// roborev finding 5 (round 1) + findings D/E (round 2): typedToNative must decode
// non-string map keys LOSSLESSLY and be prototype-pollution-safe.
//
// Round 1 established that the Rust key_sort_string (lib.rs:1126-1133) supports
// bool / int / uint / string map keys, so the wasm CAN emit a {"t":"map"} whose
// keys are bool/int/uint -- typedToNative must not reject those, and string keys
// must not be assigned to a plain object literal (a "__proto__" / "constructor"
// key could corrupt the prototype).
//
// Round 2 (finding D, HIGH) tightened the contract: the round-1 fix decoded each
// non-string key via typedToNative, so {"t":"int","v":"1"} and {"t":"uint","v":"1"}
// both became JS number 1 and COLLAPSED to one Map entry (silent data loss, key
// type lost). The decode now keeps the ORIGINAL TypedValue object as the Map key
// (int 1 and uint 1 stay distinct) and the lookups below use the canonical
// key_sort_string -- the lossless, type-preserving discriminant that mirrors the
// Python codec (celpy keeps IntType(1) and UintType(1) distinct).
//
// Tool: vitest. Evidence: vitest exit code + the decoded Map / object contents.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  keySortString,
  typedToNative,
  type TypedValue,
} from "../src/wasm-evaluator.js";

// Look up a decoded Map entry by the canonical key_sort_string of a typed key.
// The decoded Map's keys are TypedValue objects (lossless), so a value lookup is
// by the canonical ordered key, not by a lossy native key.
function getBySort(m: Map<unknown, unknown>, key: TypedValue): unknown {
  const target = keySortString(key);
  for (const [k, v] of m) {
    if (keySortString(k as TypedValue) === target) {
      return v;
    }
  }
  return undefined;
}

describe("roborev findings 5 + D/E: typedToNative decodes non-string map keys losslessly and is prototype-safe", () => {
  // An int key map: the wasm can emit {"t":"int"} keys (key_sort_string int
  // bucket). The decode must preserve the key (as the typed int) -- not reject,
  // not coerce to a bare number that would collide with a uint of the same value.
  test("a map with an int key decodes to a JS Map keyed by the typed int", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "int", v: "7" }, { t: "string", v: "seven" }]],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    expect(getBySort(m, { t: "int", v: "7" })).toBe("seven");
  });

  // A bool key map (key_sort_string bool bucket).
  test("a map with a bool key decodes to a JS Map keyed by the typed bool", () => {
    const typed: TypedValue = {
      t: "map",
      v: [
        [{ t: "bool", v: true }, { t: "string", v: "yes" }],
        [{ t: "bool", v: false }, { t: "string", v: "no" }],
      ],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    expect(getBySort(m, { t: "bool", v: true })).toBe("yes");
    expect(getBySort(m, { t: "bool", v: false })).toBe("no");
  });

  // A uint key map (key_sort_string uint bucket).
  test("a map with a uint key decodes to a JS Map keyed by the typed uint", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "uint", v: "3" }, { t: "string", v: "u3" }]],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    expect(getBySort(m, { t: "uint", v: "3" })).toBe("u3");
  });

  // Prototype-pollution safety: a "__proto__" string key must NOT corrupt the
  // Object prototype, and the decoded structure must carry the entry safely.
  test("a map with a '__proto__' string key does NOT pollute Object.prototype", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "string", v: "__proto__" }, { t: "string", v: "polluted" }]],
    };
    const decoded = typedToNative(typed);
    // Object.prototype must be untouched.
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(
      (Object.prototype as unknown as Record<string, unknown>).polluted,
    ).toBeUndefined();
    // The entry is preserved as an own property of the null-prototype object.
    const obj = decoded as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(true);
  });

  // A "constructor" string key must also not corrupt anything.
  test("a map with a 'constructor' string key is safe", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "string", v: "constructor" }, { t: "int", v: "1" }]],
    };
    const decoded = typedToNative(typed);
    const obj = decoded as Record<string, unknown>;
    expect(obj.constructor).toBe(1);
  });
});
