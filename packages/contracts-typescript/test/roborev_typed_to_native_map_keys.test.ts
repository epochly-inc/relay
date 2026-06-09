// roborev finding 5: typedToNative rejected non-string map keys and used a plain
// object (prototype-pollution risk).
//
// The Rust key_sort_string (lib.rs:1126-1133) supports bool / int / uint / string
// map keys, so the wasm CAN emit a {"t":"map"} whose keys are bool/int/uint --
// typedToNative rejected those outright. And string keys were assigned to a plain
// object literal `{}`, so a key like "__proto__" / "constructor" could corrupt
// the prototype. The decode must preserve non-string key TYPES (a JS Map) and be
// prototype-pollution-safe.
//
// Tool: vitest. Evidence: vitest exit code + the decoded Map / object contents.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import { typedToNative, type TypedValue } from "../src/wasm-evaluator.js";

describe("roborev finding 5: typedToNative decodes non-string map keys and is prototype-safe", () => {
  // An int key map: the wasm can emit {"t":"int"} keys (key_sort_string int
  // bucket). The decode must preserve the key as a number, not reject it.
  test("a map with an int key decodes to a JS Map with a number key", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "int", v: "7" }, { t: "string", v: "seven" }]],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    expect(m.get(7)).toBe("seven");
  });

  // A bool key map (key_sort_string bool bucket).
  test("a map with a bool key decodes to a JS Map with a boolean key", () => {
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
    expect(m.get(true)).toBe("yes");
    expect(m.get(false)).toBe("no");
  });

  // A uint key map (key_sort_string uint bucket).
  test("a map with a uint key decodes to a JS Map with a number key", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "uint", v: "3" }, { t: "string", v: "u3" }]],
    };
    const decoded = typedToNative(typed);
    expect(decoded).toBeInstanceOf(Map);
    const m = decoded as Map<unknown, unknown>;
    expect(m.get(3)).toBe("u3");
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
    // The entry is preserved (whether as a Map entry or an own property of a
    // null-prototype object).
    if (decoded instanceof Map) {
      expect(decoded.get("__proto__")).toBe("polluted");
    } else {
      const obj = decoded as Record<string, unknown>;
      // own-property access (not via the prototype chain).
      expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(true);
    }
  });

  // A "constructor" string key must also not corrupt anything.
  test("a map with a 'constructor' string key is safe", () => {
    const typed: TypedValue = {
      t: "map",
      v: [[{ t: "string", v: "constructor" }, { t: "int", v: "1" }]],
    };
    const decoded = typedToNative(typed);
    if (decoded instanceof Map) {
      expect(decoded.get("constructor")).toBe(1);
    } else {
      const obj = decoded as Record<string, unknown>;
      expect(obj.constructor).toBe(1);
    }
  });
});
