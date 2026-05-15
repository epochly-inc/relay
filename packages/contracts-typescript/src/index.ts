// Public surface of @epochly/relay-contracts.
//
// Mirror of packages/contracts/src/relay_contracts/__init__.py. Every
// name here is part of the cross-runtime contract; renaming or
// removing one is a breaking change.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export { jcsCanonicalize } from "./canonical.js";
export {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  RelayCelEvaluator,
} from "./evaluator.js";
export type { PureUdf, RegisterUdfOptions } from "./udf.js";
export { registerUdf } from "./udf.js";
export {
  CODE_RELAY_CEL_002,
  CODE_RELAY_CEL_003,
  CODE_RELAY_CEL_004,
  CODE_RELAY_CEL_006,
  CODE_RELAY_CEL_007,
  RelayCelError,
  RelayCelNumericOutOfBoundsError,
  RelayCelProfileError,
  RelayCelRegexBackreferenceError,
  RelayCelTimeoutError,
  RelayUdfPurityError,
  SUBTYPE_NUMERIC_OOB,
  SUBTYPE_PROFILE_DUR_DISABLED,
  SUBTYPE_PROFILE_DYN_DISABLED,
  SUBTYPE_PROFILE_REGEX_BACKREF,
  SUBTYPE_PROFILE_TS_DISABLED,
  SUBTYPE_TIMEOUT,
  SUBTYPE_UDF_IMPURE,
} from "./errors.js";
export type {
  RelayCelCode,
  RelayCelErrorEnvelope,
  RelayCelSubtype,
} from "./errors.js";
