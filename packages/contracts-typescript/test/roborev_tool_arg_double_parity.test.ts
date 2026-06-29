// roborev finding 2: whole-valued doubles misclassified as int.
//
// `Number.isInteger(1.0) === true`, so a JS binding value `1.0` becomes
// {"t":"int","v":"1"} on the TS host, but the Python `py_to_typed(1.0)` (a
// Python float through the JSON wire boundary) keeps it {"t":"double","v":"1.0"}.
// Routed through `relay.tool_arg` (which echoes the binding value), the
// udf_trace OUTPUT bytes then diverge -- a P0 keystone-#16 byte-parity break.
//
// A plain JS `number` cannot carry the int/double distinction for a whole value
// (1.0 === 1 in JS; JSON.stringify(1.0) === "1"), so the fix gives callers an
// explicit `RelayDouble` wrapper to express a CEL double for a whole value --
// the JS analogue of Python's float/DoubleType. `nativeToTyped(new
// RelayDouble(1))` encodes {"t":"double","v":"1.0"}, byte-identical to the
// Python `py_to_typed(1.0)`. Plain whole `number`s stay int (matching the JSON
// wire boundary the cross-host harness relies on).
//
// Tool: vitest. Evidence: vitest exit code + the asserted {t,v} strings.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import { nativeToTyped, RelayDouble } from "../src/wasm-evaluator.js";

describe("roborev finding 2: RelayDouble preserves the int/double distinction at the JS boundary", () => {
  // relay.tool_arg returning an INT: a plain whole `number` stays a CEL int,
  // matching Python py_to_typed(<JSON int>).
  test("plain whole number 1 encodes as CEL int {t:'int',v:'1'}", () => {
    expect(nativeToTyped(1)).toEqual({ t: "int", v: "1" });
  });

  // relay.tool_arg returning a NON-INTEGRAL double: 1.5 is a CEL double.
  test("non-integral 1.5 encodes as CEL double {t:'double',v:'1.5'}", () => {
    expect(nativeToTyped(1.5)).toEqual({ t: "double", v: "1.5" });
  });

  // relay.tool_arg returning a WHOLE-VALUED double: RelayDouble(1) is a CEL
  // double {t:'double',v:'1.0'}, byte-identical to Python py_to_typed(1.0) (a
  // Python float). This is the case the bare `number` path cannot express.
  test("RelayDouble(1) encodes as CEL double {t:'double',v:'1.0'} (NOT int)", () => {
    expect(nativeToTyped(new RelayDouble(1))).toEqual({
      t: "double",
      v: "1.0",
    });
  });

  test("RelayDouble(0) -> {t:'double',v:'0.0'}", () => {
    expect(nativeToTyped(new RelayDouble(0))).toEqual({
      t: "double",
      v: "0.0",
    });
  });

  test("RelayDouble(-0) -> {t:'double',v:'-0.0'}", () => {
    expect(nativeToTyped(new RelayDouble(-0))).toEqual({
      t: "double",
      v: "-0.0",
    });
  });

  test("RelayDouble(2.5) -> {t:'double',v:'2.5'} (non-integral double via wrapper too)", () => {
    expect(nativeToTyped(new RelayDouble(2.5))).toEqual({
      t: "double",
      v: "2.5",
    });
  });

  test("RelayDouble(1e6) -> {t:'double',v:'1e+06'} (canonical-g format via wrapper)", () => {
    expect(nativeToTyped(new RelayDouble(1e6))).toEqual({
      t: "double",
      v: "1e+06",
    });
  });

  // A whole-valued double nested inside a map binding (the realistic
  // relay.tool_arg case: call.args.x == 1.0) keeps the double tag.
  test("nested RelayDouble in a map binding stays a double", () => {
    const encoded = nativeToTyped({ args: { x: new RelayDouble(1) } });
    expect(encoded).toEqual({
      t: "map",
      v: [
        [
          { t: "string", v: "args" },
          {
            t: "map",
            v: [[{ t: "string", v: "x" }, { t: "double", v: "1.0" }]],
          },
        ],
      ],
    });
  });

  // RelayDouble rejects a non-finite value at construction (the codec never
  // emits a non-finite double; the binding-input guard is fail-closed).
  test("RelayDouble rejects NaN / +-Inf at construction", () => {
    expect(() => new RelayDouble(Number.NaN)).toThrow();
    expect(() => new RelayDouble(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => new RelayDouble(Number.NEGATIVE_INFINITY)).toThrow();
  });

  test("RelayDouble rejects a non-number argument", () => {
    // @ts-expect-error -- deliberately wrong type for the runtime guard test
    expect(() => new RelayDouble("1.0")).toThrow();
  });
});
