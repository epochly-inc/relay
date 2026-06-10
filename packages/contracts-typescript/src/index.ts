// Public surface of @epochly/relay-contracts.
//
// Mirror of packages/contracts/src/relay_contracts/__init__.py. Every
// name here is part of the cross-runtime contract; renaming or
// removing one is a breaking change.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export { jcsCanonicalize } from "./canonical.js";
// VAL-CWC-P5FLIP-011 (M5): the canonical engine-selection factory. Default
// (engine unset/blank) constructs the wasm-backed WasmCelBackend; explicit
// "celjs"/"cel-js" constructs the legacy cel-js RelayCelEvaluator (the
// rollback escape hatch until M6). TS mirror of the Python make_cel_evaluator
// (packages/contracts/src/relay_contracts/engine.py).
export { makeCelEvaluator } from "./engine.js";
export type {
  CelEngineName,
  CelEvaluator,
  MakeCelEvaluatorOptions,
} from "./engine.js";
export {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  RelayCelEvaluator,
} from "./evaluator.js";
// VAL-CWC-P1HOST-019: the wasm-path udf_outputs_jcs reconstruction (TS mirror
// of the Python pipeline's wasm hot path), byte-identical to the Python host.
export { evaluateUdfOutputs } from "./pipeline.js";
export type {
  EvaluateUdfOutputsOptions,
  UdfOutputsResult,
} from "./pipeline.js";
// VAL-CWC-P2TSGATE-005: the canonical native<->typed codec (single source of
// truth). `nativeToTyped` is re-exported from pipeline.js for back-compat but
// is owned here; `typedToNative` is the round-trip inverse.
export {
  canonicalDoubleString,
  decodeWasmEnvelope,
  nativeToTyped,
  RelayDouble,
  typedToNative,
  WasmCelBackend,
} from "./wasm-evaluator.js";
export type {
  TypedValue,
  WasmCelBackendOptions,
  WasmResponseEnvelope,
} from "./wasm-evaluator.js";
export type { PureUdf, RegisterUdfOptions } from "./udf.js";
export { registerUdf } from "./udf.js";

// w6.3 production UDFs.
export {
  RELAY_COVERAGE_ARITY,
  RELAY_COVERAGE_NAME,
  relayCoverage,
} from "./udfs/coverage.js";
export {
  RELAY_TOOL_ARG_ARITY,
  RELAY_TOOL_ARG_NAME,
  relayToolArg,
} from "./udfs/tool_arg.js";
export {
  MAX_DEPTH as RELAY_SCHEMA_MATCH_MAX_DEPTH,
  RELAY_SCHEMA_MATCH_ARITY,
  RELAY_SCHEMA_MATCH_NAME,
  relaySchemaMatch,
} from "./udfs/schema_match.js";
export { RELAY_UDFS } from "./udfs/registry.js";
export {
  CODE_RELAY_CEL_002,
  CODE_RELAY_CEL_003,
  CODE_RELAY_CEL_004,
  CODE_RELAY_CEL_006,
  CODE_RELAY_CEL_007,
  CODE_RELAY_CEL_009,
  RelayCelEngineError,
  RelayCelError,
  RelayCelNumericOutOfBoundsError,
  RelayCelProfileError,
  RelayCelRegexBackreferenceError,
  RelayCelTimeoutError,
  RelayCelUnsupportedUdfError,
  RelayUdfPurityError,
  SUBTYPE_ENGINE_COMPILE,
  SUBTYPE_ENGINE_EXEC,
  SUBTYPE_ENGINE_PANIC,
  SUBTYPE_ENGINE_REQUEST,
  SUBTYPE_NUMERIC_OOB,
  SUBTYPE_PROFILE_DUR_DISABLED,
  SUBTYPE_PROFILE_DYN_DISABLED,
  SUBTYPE_PROFILE_REGEX_BACKREF,
  SUBTYPE_PROFILE_STRUCT_DISABLED,
  SUBTYPE_PROFILE_TS_DISABLED,
  SUBTYPE_TIMEOUT,
  SUBTYPE_UDF_IMPURE,
  SUBTYPE_UDF_UNREGISTERED,
} from "./errors.js";
export type {
  RelayCelCode,
  RelayCelEngineSubtype,
  RelayCelErrorEnvelope,
  RelayCelSubtype,
} from "./errors.js";
