// VAL-W6-013: cel-js UDF registration is gated on `pure: true`.
//
// The TS `registerUdf({name, fn, pure, ...})` API MUST throw at
// registration time if `pure: false` is passed. Guard test mirrors
// VAL-W6-004.
//
// Tool: vitest.
// Evidence: vitest exit code, thrown error class `RelayUdfPurityError`.
// Spec: D, eng plan X4 line 216, CLAUDE.md banned pattern #16.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  registerUdf,
  RelayUdfPurityError,
  SUBTYPE_UDF_IMPURE,
} from "../src/index.js";

describe("VAL-W6-013: registerUdf is gated on pure: true", () => {
  test("pure: false throws RelayUdfPurityError with RELAY-CEL-004 / UDF-IMPURE", () => {
    let caught: unknown = null;
    try {
      registerUdf({
        name: "naughty",
        fn: (x) => x,
        pure: false,
        arity: 1,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayUdfPurityError);
    const err = caught as RelayUdfPurityError;
    expect(err.code).toBe("RELAY-CEL-004");
    expect(err.subtype).toBe(SUBTYPE_UDF_IMPURE);
  });

  test("non-bool truthy values for pure are rejected (no silent coercion)", () => {
    expect(() =>
      registerUdf({
        name: "ambiguous-num",
        fn: (x) => x,
        pure: 1 as unknown as boolean,
        arity: 1,
      }),
    ).toThrow(RelayUdfPurityError);
    expect(() =>
      registerUdf({
        name: "ambiguous-str",
        fn: (x) => x,
        pure: "yes" as unknown as boolean,
        arity: 1,
      }),
    ).toThrow(RelayUdfPurityError);
    expect(() =>
      registerUdf({
        name: "ambiguous-arr",
        fn: (x) => x,
        pure: [true] as unknown as boolean,
        arity: 1,
      }),
    ).toThrow(RelayUdfPurityError);
  });

  test("pure: true with valid name/fn/arity returns a frozen PureUdf", () => {
    const udf = registerUdf({
      name: "safe",
      fn: (x: unknown) => (x as number) + 1,
      pure: true,
      arity: 1,
    });
    expect(udf.name).toBe("safe");
    expect(udf.arity).toBe(1);
    // Frozen at runtime: any attempted mutation throws in strict mode
    // (vitest runs ESM strict by default).
    expect(Object.isFrozen(udf)).toBe(true);
  });

  test("empty string name is rejected", () => {
    expect(() =>
      registerUdf({
        name: "",
        fn: (x) => x,
        pure: true,
        arity: 1,
      }),
    ).toThrow(RelayUdfPurityError);
  });

  test("non-function fn is rejected", () => {
    expect(() =>
      registerUdf({
        name: "ok",
        fn: "not a fn" as unknown as (...args: unknown[]) => unknown,
        pure: true,
        arity: 0,
      }),
    ).toThrow(RelayUdfPurityError);
  });

  test("negative arity is rejected", () => {
    expect(() =>
      registerUdf({
        name: "ok",
        fn: () => 0,
        pure: true,
        arity: -1,
      }),
    ).toThrow(RelayUdfPurityError);
  });

  test("non-integer arity is rejected", () => {
    expect(() =>
      registerUdf({
        name: "ok",
        fn: () => 0,
        pure: true,
        arity: 1.5,
      }),
    ).toThrow(RelayUdfPurityError);
  });
});
