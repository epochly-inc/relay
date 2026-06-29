// w6.3 production UDF registry (TypeScript).
//
// Constructed at module-import time via the pure-only `registerUdf`
// entry point so the purity flag (CLAUDE.md banned pattern #16) is
// enforced structurally. Workers passing this readonly array to
// `makeCelEvaluator({ udfs: RELAY_UDFS })` get a fully-wired
// evaluator with no risk of accidentally registering an impure
// callable.
//
// Mirrors packages/contracts/src/relay_contracts/__init__.py's
// RELAY_UDFS tuple. Cross-language byte-equality across the three
// UDFs is enforced by tests/conformance/cel/relay_udfs_parity.json.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { registerUdf, type PureUdf } from "../udf.js";

import {
  RELAY_COVERAGE_ARITY,
  RELAY_COVERAGE_NAME,
  relayCoverage,
} from "./coverage.js";
import {
  RELAY_SCHEMA_MATCH_ARITY,
  RELAY_SCHEMA_MATCH_NAME,
  relaySchemaMatch,
} from "./schema_match.js";
import {
  RELAY_TOOL_ARG_ARITY,
  RELAY_TOOL_ARG_NAME,
  relayToolArg,
} from "./tool_arg.js";

// `as const` + `Object.freeze` belt-and-suspenders: the array is
// readonly at compile time and frozen at runtime. Each element is
// also frozen via the `Object.freeze` inside `registerUdf`.
export const RELAY_UDFS: readonly PureUdf[] = Object.freeze([
  registerUdf({
    name: RELAY_COVERAGE_NAME,
    fn: relayCoverage as (...args: unknown[]) => unknown,
    pure: true,
    arity: RELAY_COVERAGE_ARITY,
  }),
  registerUdf({
    name: RELAY_TOOL_ARG_NAME,
    fn: relayToolArg as (...args: unknown[]) => unknown,
    pure: true,
    arity: RELAY_TOOL_ARG_ARITY,
  }),
  registerUdf({
    name: RELAY_SCHEMA_MATCH_NAME,
    fn: relaySchemaMatch as (...args: unknown[]) => unknown,
    pure: true,
    arity: RELAY_SCHEMA_MATCH_ARITY,
  }),
] as const);
