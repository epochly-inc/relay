// ESLint flat config for @epochly/relay-contracts (VAL-CWC-P2TSGATE-007).
//
// Purpose: enable @typescript-eslint/no-floating-promises as an ERROR so a
// forgotten `await` on the now-async WasmCelBackend.evaluate() (wasm-evaluator.ts)
// is a LINT ERROR rather than a silent unhandled rejection. This is the HIGH
// risk-register mitigation for the M2 breaking change "TS evaluate() async;
// missed await".
//
// no-floating-promises is TYPE-AWARE: it needs full type information to know an
// expression evaluates to a Promise. typescript-eslint's `projectService`
// provides that by binding the linted files to the package tsconfig.json (the
// same tsconfig the build / typecheck use). WITHOUT type information the rule
// silently no-ops -- so the companion test
// (test/eslint-no-floating-promises.test.ts) proves the rule actually FIRES on a
// deliberately-floating-promise fixture; a no-op would let that fixture pass.
//
// Scope: this config governs ONLY packages/contracts-typescript (src + test). It
// is package-local (auto-discovered from the package cwd) and does not touch any
// other workspace's linting. We do NOT pull in the broad recommended rule sets:
// the contract is narrowly the missed-await guard, so we enable exactly that
// type-aware rule (plus its required parser/plugin wiring) to keep the existing
// source clean without a large unrelated lint surface.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // Never lint build output or deps.
    ignores: ["dist/**", "node_modules/**"],
  },
  {
    files: ["src/**/*.ts", "test/**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        // Type-aware linting: bind each linted file to the nearest tsconfig via
        // the TypeScript ProjectService (the modern, fast replacement for an
        // explicit `project` array). tsconfig.json `include` already covers
        // src/** and test/**, so every linted file gets full type info and
        // no-floating-promises can see that evaluate() returns a Promise.
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
    },
    rules: {
      // The contract rule (VAL-CWC-P2TSGATE-007). Default options: a Promise
      // used as a statement must be awaited, void-ed, or .catch()-handled.
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
);
