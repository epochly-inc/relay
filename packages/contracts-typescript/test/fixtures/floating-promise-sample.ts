// PROOF FIXTURE for VAL-CWC-P2TSGATE-007.
//
// This file deliberately FLOATS a promise: it calls the now-async
// WasmCelBackend.evaluate() WITHOUT awaiting, voiding, or .catch()-ing its
// returned Promise. Under the contracts-typescript ESLint config (which enables
// @typescript-eslint/no-floating-promises as an ERROR) running eslint on THIS
// file MUST exit non-zero with the no-floating-promises rule, proving the
// missed-await guard fires (the HIGH risk-register mitigation: 'TS evaluate()
// async breaking change; missed await').
//
// It is intentionally NOT under src/ (so `npx eslint packages/contracts-typescript/src`
// stays exit 0) and NOT a vitest *.test.ts file (so the suite never imports or
// runs it). The companion test eslint-no-floating-promises.test.ts invokes
// eslint on this fixture explicitly and asserts the rule fires.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { WasmCelBackend } from "../../src/wasm-evaluator.js";

export function floatingEvaluate(backend: WasmCelBackend): void {
  // BUG ON PURPOSE: evaluate() returns a Promise<unknown> and this call drops
  // it on the floor (no await / void / .catch). no-floating-promises must flag
  // this exact line.
  backend.evaluate("1 + 2");
}
