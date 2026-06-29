// CEL engine-selection factory -- the canonical TS evaluator entry point.
//
// `makeCelEvaluator()` is the TypeScript mirror of the Python factory
// packages/contracts/src/relay_contracts/engine.py (make_cel_evaluator). After
// M6 WS-I the wasm engine is the ONLY TS CEL backend: the legacy engine and
// its rollback escape hatch are removed. The factory therefore has a single
// constructable engine behind the host facade (`compile`, `evaluate`,
// `timeoutMs`):
//
//   - "wasm" (the DEFAULT, and the selection when `engine` is unset or blank):
//     :class WasmCelBackend (wasm-evaluator.ts), the single wasm CEL engine
//     behind the host facade. This is the engine EVERY consumer runs on. The
//     default backend resolves the PACKAGED wasm artifact + `.mjs` loader
//     (WS-G package data) with the explicit precedence explicit > CEL_WASM >
//     packaged data (wasm-artifact.ts resolveWasmPathForLoader /
//     wasm-evaluator.ts defaultLoaderPath), so a fresh install loads the
//     engine with no configuration.
//
// Any OTHER engine name -- including the now-removed legacy spellings -- is
// rejected fail-closed with a clear error naming the bad value AND the
// (wasm-only) allowed set; never a silent fallback to a default. The M5
// rollback hatch (explicit legacy selection) is CLOSED at M6: a deployment can
// no longer select the legacy engine because it does not exist.
//
// DETERMINISM BOUNDARY (load-bearing; differs from Python BY DESIGN): the TS
// selection is CONFIG/PARAM-based, NOT environment-based. The engine-selector
// environment variable (RELAY_CEL_ENGINE) is read ONLY in the Python
// packages/contracts factory (boundaries.md); production TS src/ MUST NOT
// name it -- the AST presence scan in test/default-engine.test.ts FAILS the
// build if any src/ file carries that token as an identifier or string
// literal. A TS consumer that wants env-driven selection performs the env
// read itself (outside this package) and passes the resolved token as
// `engine`. (This comment may name the selector: comments are invisible to
// the AST scan, exactly like the wasm-artifact.ts explanatory comments.)
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import type { PureUdf } from "./udf.js";
import { WasmCelBackend } from "./wasm-evaluator.js";

// Canonical engine token. After M6 WS-I "wasm" is the default AND the only
// constructable engine. Matching is exact (case-sensitive) after surrounding-
// whitespace trim -- no locale-dependent case-folding, so selection is
// deterministic. Mirrors engine.py _ENGINE_WASM.
const ENGINE_WASM = "wasm";

// The default engine when `engine` is unset or blank. After M6 WS-I there is
// no alternative to select. Mirrors engine.py _DEFAULT_ENGINE.
const DEFAULT_ENGINE = ENGINE_WASM;

const ALLOWED_ENGINE_TOKENS: readonly string[] = [ENGINE_WASM];

/**
 * The canonical engine token a TypeScript caller may select. After M6 WS-I
 * `"wasm"` is the sole accepted value.
 */
export type CelEngineName = "wasm";

/**
 * The shared host-side CEL evaluator facade the factory returns: the
 * wasm-backed engine. The TS analogue of the Python CelEvaluatorProtocol
 * (engine.py).
 */
export type CelEvaluator = WasmCelBackend;

export interface MakeCelEvaluatorOptions {
  /**
   * Engine selection token. Unset / blank selects the default (wasm). Any
   * other value -- including the now-removed legacy spellings -- is rejected
   * fail-closed. Typed as `string` (not the literal type) deliberately: this
   * mirrors the Python factory's env-string contract -- arbitrary runtime
   * strings are accepted at the type level and validated fail-closed at
   * runtime, so a JS caller threading an externally-resolved token gets the
   * structured rejection, not a type hole.
   */
  engine?: string;
  /**
   * Per-evaluation wall-clock budget (ms). Forwarded to the evaluator's
   * constructor with IDENTICAL semantics (positive integer,
   * <= MAX_TIMEOUT_MS); when omitted the evaluator's own DEFAULT_TIMEOUT_MS
   * governs, exactly as if the class had been constructed directly.
   */
  timeoutMs?: number;
  /**
   * Pure UDFs to register. Forwarded verbatim. The wasm engine accepts ONLY
   * the 3 native relay.* UDFs and rejects any other fail-closed
   * (RelayCelUnsupportedUdfError / RELAY-CEL-004).
   */
  udfs?: readonly PureUdf[];
}

/**
 * Resolve the engine token from the factory options (the TS counterpart of
 * engine.py _select_engine_name, minus the env read -- see the determinism
 * boundary in the module docstring).
 *
 * An absent or blank value resolves to the default (wasm). A non-blank value
 * is trimmed of surrounding whitespace (a common config-plumbing accident) and
 * matched case-sensitively against the (wasm-only) allowed token. A non-string
 * runtime value is a category error (TypeError); any unknown token -- including
 * the removed legacy spellings -- raises a clear Error naming the value and the
 * allowed set.
 */
function selectEngineToken(engine: string | undefined): typeof ENGINE_WASM {
  if (engine === undefined) {
    return DEFAULT_ENGINE;
  }
  if (typeof engine !== "string") {
    // A JS caller bypassing the types. Reject the category error loudly
    // rather than coercing (String(engine) could silently select an engine).
    throw new TypeError(
      `makeCelEvaluator: 'engine' must be a string when provided; ` +
        `got ${typeof engine}`,
    );
  }
  const value = engine.trim();
  if (value === "") {
    // A blank selection (e.g. an empty config field) is the standard "no
    // selection" signal; fall back to the default (wasm).
    return DEFAULT_ENGINE;
  }
  if (value === ENGINE_WASM) {
    return ENGINE_WASM;
  }
  const allowed = ALLOWED_ENGINE_TOKENS.map((token) =>
    JSON.stringify(token),
  ).join(", ");
  throw new Error(
    `makeCelEvaluator: engine ${JSON.stringify(engine)} is not a recognized ` +
      `CEL engine; allowed values are ${allowed} (unset or blank -> ` +
      `${JSON.stringify(DEFAULT_ENGINE)}). Engine names are case-sensitive. ` +
      "The legacy engine was removed at M6; the wasm engine is the only " +
      "CEL backend.",
  );
}

/**
 * Construct the CEL evaluator -- the package's canonical evaluator entry point
 * (VAL-CWC-P5FLIP-011 / VAL-CWC-P6REMOVE-005).
 *
 * `engine` unset / blank / `"wasm"` -> the wasm `WasmCelBackend` (the only
 * engine after M6 WS-I); any other token fails closed. `timeoutMs` and `udfs`
 * are forwarded to the evaluator's constructor with IDENTICAL semantics, so
 * the factory is a transparent substitute for constructing the class directly.
 *
 * The wasm backend's `evaluate()` is async (returns a Promise; the
 * worker_threads hard-kill timeout path).
 *
 * @throws TypeError `engine` is a non-string runtime value.
 * @throws Error `engine` holds an unrecognized token (incl. the removed legacy
 *   spellings), OR the forwarded `timeoutMs` is out of bounds (re-raised from
 *   the evaluator constructor).
 * @throws RelayCelUnsupportedUdfError a non-allowlist UDF was forwarded to the
 *   wasm engine (fail-closed at construction).
 */
export function makeCelEvaluator(
  options?: MakeCelEvaluatorOptions,
): WasmCelBackend {
  // `?? {}` (not a parameter default) so a JS caller passing an explicit
  // `null` gets the default-construction path rather than a bare property
  // read on null.
  const opts = options ?? {};
  // Validate the engine token fail-closed (unknown / legacy tokens throw here).
  selectEngineToken(opts.engine);

  // Forward only the options the caller actually supplied, so the evaluator's
  // own defaults govern the unspecified ones (identical to direct
  // construction). Mirrors engine.py's conditional kwargs build.
  const forwarded: { timeoutMs?: number; udfs?: readonly PureUdf[] } = {};
  if (opts.timeoutMs !== undefined) {
    forwarded.timeoutMs = opts.timeoutMs;
  }
  if (opts.udfs !== undefined) {
    forwarded.udfs = opts.udfs;
  }

  return new WasmCelBackend(forwarded);
}
