// VAL-CWC-P2TSGATE-013 (TS half): the default CEL engine stays cel-js at M2 --
// no premature flip to wasm.
//
// This is the TypeScript mirror of the Python default_engine guard
// (packages/contracts/tests/test_engine_factory.py
// test_default_engine_is_celpy_when_env_unset), which asserts
// make_cel_evaluator() with RELAY_CEL_ENGINE unset returns the cel-python
// RelayCelEvaluator. On the TS side the package exposes NO env-var engine
// factory at M2 (by design / boundaries.md: engine selection is read ONLY in
// the packages/contracts Python factory; the TS wasm backend is an opt-in class,
// not the default). So "the TS default" is the package's primary evaluator
// export -- the cel-js-backed RelayCelEvaluator -- NOT the opt-in wasm
// WasmCelBackend.
//
// The flip to a wasm default is WS-H / M5, NOT M2. This suite is the structural
// fence: it FAILS (bites) if anyone makes the default the wasm engine before
// M5 -- by aliasing the default export to WasmCelBackend, by making
// RelayCelEvaluator a wasm subclass, by re-pointing RelayCelEvaluator at the
// wasm loader, or by introducing a TS engine factory that returns wasm with the
// engine selector unset.
//
// boundaries.md: "Do NOT flip the RELAY_CEL_ENGINE default to wasm before
// milestone M5." and "Do NOT remove cel-js before milestone M6."
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import * as contracts from "../src/index.js";
import { RelayCelEvaluator } from "../src/evaluator.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";
import { RELAY_UDFS } from "../src/udfs/registry.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EVALUATOR_SRC = resolve(HERE, "..", "src", "evaluator.ts");

describe("VAL-CWC-P2TSGATE-013: default TS CEL engine stays cel-js (no premature wasm flip)", () => {
  test("the primary evaluator export is RelayCelEvaluator, not WasmCelBackend", () => {
    // index.ts re-exports RelayCelEvaluator as the package's primary CEL
    // evaluator (mirroring make_cel_evaluator()'s celpy default). WasmCelBackend
    // is an opt-in named export, never the default. If the primary export were
    // re-pointed at the wasm backend, this fails.
    expect(contracts.RelayCelEvaluator).toBe(RelayCelEvaluator);
    expect(contracts.RelayCelEvaluator).not.toBe(WasmCelBackend);
    expect(RelayCelEvaluator).not.toBe(WasmCelBackend);
    expect(RelayCelEvaluator.name).toBe("RelayCelEvaluator");
  });

  test("the default evaluator is NOT the wasm backend (no class identity / subclass flip)", () => {
    // A flip-to-wasm could be smuggled in by aliasing the default to the wasm
    // class or making the default a subclass of WasmCelBackend. Either would
    // route the unset-default through the wasm engine -- both are M5 work, not
    // M2.
    const ev = new RelayCelEvaluator();
    expect(ev).not.toBeInstanceOf(WasmCelBackend);
    // The default class does not derive from the wasm backend.
    expect(
      RelayCelEvaluator.prototype instanceof WasmCelBackend,
    ).toBe(false);
    expect(
      WasmCelBackend.prototype.isPrototypeOf(RelayCelEvaluator.prototype),
    ).toBe(false);
  });

  test("constructing the unset-default evaluator does not load the wasm engine", () => {
    // The default evaluator is the cel-js-backed RelayCelEvaluator. It binds
    // cel-js at module import (evaluator.ts: `import { parse } from "cel-js"`)
    // and spawns a cel-js worker lazily; it never loads the wasm engine. The
    // wasm-loading surface is the `.mjs` RelayCel loader (relay-cel-wasm /
    // RelayCel.load), which lives ONLY in wasm-evaluator.ts (WasmCelBackend).
    // We prove the default's source carries NO wasm-loading surface; an
    // incidental WasmCelBackend mention in a doc comment is not such a surface,
    // so we assert on the load-bearing loader symbols, not the class name.
    const evaluatorSrc = readFileSync(EVALUATOR_SRC, "utf8");
    expect(evaluatorSrc).toContain('from "cel-js"');
    expect(evaluatorSrc).not.toContain("relay-cel-wasm");
    expect(evaluatorSrc).not.toContain("RelayCel.load");

    // Constructing the default with the production UDFs succeeds and yields a
    // cel-js RelayCelEvaluator (not a wasm backend). This is the TS analogue of
    // the Python `type(make_cel_evaluator(udfs=...)).__name__ ==
    // 'RelayCelEvaluator'` assertion.
    const defaultEvaluator = new RelayCelEvaluator({ udfs: RELAY_UDFS });
    expect(defaultEvaluator.constructor).toBe(RelayCelEvaluator);
    expect(defaultEvaluator.constructor.name).toBe("RelayCelEvaluator");
    expect(defaultEvaluator).not.toBeInstanceOf(WasmCelBackend);
  });

  test("there is no TS env-var engine factory that flips the default to wasm at M2", () => {
    // Engine selection (RELAY_CEL_ENGINE) is read ONLY in the Python
    // packages/contracts factory (boundaries.md). The TS package must NOT carry
    // its own RELAY_CEL_ENGINE read that could resolve the unset-env default to
    // the wasm backend. If a future change adds such a factory, it MUST keep the
    // unset default cel-js (M5 is where the default flips). This guard asserts
    // the package does not currently expose a default-engine factory that
    // returns the wasm backend -- the only exported evaluator constructors are
    // RelayCelEvaluator (default, cel-js) and WasmCelBackend (opt-in, wasm), and
    // the primary one is cel-js.
    const exportedNames = Object.keys(contracts);
    expect(exportedNames).toContain("RelayCelEvaluator");
    expect(exportedNames).toContain("WasmCelBackend");
    // No no-arg "default engine" factory function silently resolving to wasm:
    // the package exposes the two evaluator classes explicitly, and the
    // primary/default one is the cel-js RelayCelEvaluator (asserted above). A
    // hypothetical makeCelEvaluator()/defaultCelEvaluator() that returned a
    // WasmCelBackend by default would constitute the premature flip this guard
    // forbids; none such exists at M2.
    const candidateFactoryNames = [
      "makeCelEvaluator",
      "defaultCelEvaluator",
      "createCelEvaluator",
      "selectCelEngine",
    ];
    for (const factoryName of candidateFactoryNames) {
      const maybeFactory = (contracts as Record<string, unknown>)[factoryName];
      if (typeof maybeFactory === "function") {
        // If a factory exists, its zero-arg (unset-default) result MUST be the
        // cel-js evaluator, never the wasm backend.
        const produced = (maybeFactory as () => unknown)();
        expect(produced).not.toBeInstanceOf(WasmCelBackend);
        expect(produced).toBeInstanceOf(RelayCelEvaluator);
      }
    }
  });
});
