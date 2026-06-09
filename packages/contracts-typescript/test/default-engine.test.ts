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
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import * as contracts from "../src/index.js";
import { RelayCelEvaluator } from "../src/evaluator.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";
import { RELAY_UDFS } from "../src/udfs/registry.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = resolve(HERE, "..", "src");
const EVALUATOR_SRC = resolve(SRC_DIR, "evaluator.ts");

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
    try {
      expect(defaultEvaluator.constructor).toBe(RelayCelEvaluator);
      expect(defaultEvaluator.constructor.name).toBe("RelayCelEvaluator");
      expect(defaultEvaluator).not.toBeInstanceOf(WasmCelBackend);

      // Identity/prototype checks alone could be satisfied by a composition
      // wrapper that delegates to wasm at runtime. Prove the default actually
      // ROUTES through cel-js by evaluating an expression: RelayCelEvaluator.
      // evaluate() is the SYNCHRONOUS cel-js worker path (it returns the value
      // directly, not a Promise). The wasm backend's evaluate() returns a
      // Promise (worker_threads async loader). So a synchronous numeric result
      // here is positive evidence the cel-js engine evaluated it -- a wasm-backed
      // default would return a thenable, failing the `not Promise` assertion.
      const sum = defaultEvaluator.evaluate("1 + 1");
      expect(sum).not.toBeInstanceOf(Promise);
      expect(sum).toBe(2);
      // A second expression touching string concat exercises the cel-js parse +
      // eval path, not just integer fast-math.
      expect(defaultEvaluator.evaluate('"a" + "b"')).toBe("ab");
    } finally {
      defaultEvaluator.dispose();
    }
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

    // Dynamic guard (NOT a hardcoded factory-name allowlist): a hardcoded list
    // of candidate factory names (makeCelEvaluator/defaultCelEvaluator/...)
    // would miss a differently-named factory that reads RELAY_CEL_ENGINE. The
    // load-bearing boundary is "RELAY_CEL_ENGINE is read ONLY in the Python
    // factory" -- so we scan the ENTIRE TS src/ tree for ANY read of
    // process.env.RELAY_CEL_ENGINE (or a bracket-form env access). Any such read
    // in the TS package, under ANY function name, trips this guard. This is the
    // grep-based structural check that a renamed/composed factory cannot evade.
    const srcFiles = listSourceFiles(SRC_DIR);
    expect(srcFiles.length).toBeGreaterThan(0);
    const offenders: string[] = [];
    // Match `process.env.RELAY_CEL_ENGINE` and `process.env["RELAY_CEL_ENGINE"]`
    // / `process.env['RELAY_CEL_ENGINE']` (any whitespace), case-sensitive on
    // the env name.
    const envReadPattern =
      /process\s*\.\s*env\s*(?:\.\s*RELAY_CEL_ENGINE|\[\s*["']RELAY_CEL_ENGINE["']\s*\])/;
    for (const file of srcFiles) {
      const text = readFileSync(file, "utf8");
      // Ignore the WS-G vendored wasm loader's CEL_WASM read (a DIFFERENT env
      // var, path resolution only) and doc-comment mentions: the pattern above
      // matches only an actual RELAY_CEL_ENGINE access, so comments naming the
      // var without a process.env access do not match.
      if (envReadPattern.test(text)) {
        offenders.push(file);
      }
    }
    expect(offenders, (
      "engine selection (RELAY_CEL_ENGINE) must be read ONLY in the Python " +
      "packages/contracts factory (boundaries.md); found a process.env." +
      `RELAY_CEL_ENGINE read in TS src/: ${offenders.join(", ")}`
    )).toEqual([]);
  });
});

/**
 * Recursively list every .ts / .mts / .mjs / .js source file under `dir`,
 * skipping nothing (the whole src/ tree is in scope for the env-read scan).
 */
function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listSourceFiles(full));
    } else if (/\.(?:ts|mts|cts|mjs|cjs|js)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}
