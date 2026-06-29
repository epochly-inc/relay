// Structured error envelope for the Relay CEL evaluator (TypeScript).
//
// Every Relay-CEL error carries a canonical `RELAY-CEL-NNN` code plus a
// stable `subtype` token. The Python errors module
// (packages/contracts/src/relay_contracts/errors.py) surfaces the SAME
// wasm-emitted engine-error subtypes (the RELAY-CEL-002 profile family
// including PROFILE-STRUCT-DISABLED, the RELAY-CEL-009 engine-* family, etc.) --
// whether via a named constant or by propagating the wasm envelope's subtype
// string. For those wasm-emitted subtypes the pair (`code`, `subtype`) is the
// cross-runtime byte-equality key that VAL-W6-006 / VAL-W6-007 / VAL-W6-014
// enforce. The per-host registries list each host's OWN named-constant set and
// are NOT required to be identical outside the wasm-emitted set (a host may
// name or classify host-internal conditions on its own).
//
// Code-to-subtype map (TypeScript named subtypes; the wasm-emitted set is
// shared with packages/contracts/src/relay_contracts/errors.py):
//
//   RELAY-CEL-002  RELAY-CEL-PROFILE-DYN-DISABLED
//   RELAY-CEL-002  RELAY-CEL-PROFILE-TS-DISABLED
//   RELAY-CEL-002  RELAY-CEL-PROFILE-DUR-DISABLED
//   RELAY-CEL-002  RELAY-CEL-PROFILE-STRUCT-DISABLED
//   RELAY-CEL-003  RELAY-CEL-TIMEOUT-001
//   RELAY-CEL-004  RELAY-CEL-UDF-IMPURE
//   RELAY-CEL-004  RELAY-CEL-UDF-UNREGISTERED
//   RELAY-CEL-006  RELAY-CEL-NUMERIC-OOB
//   RELAY-CEL-007  RELAY-CEL-PROFILE-REGEX-BACKREF
//   RELAY-CEL-009  RELAY-CEL-ENGINE-COMPILE   (wasm engine compile failure)
//   RELAY-CEL-009  RELAY-CEL-ENGINE-EXEC      (wasm engine runtime failure)
//   RELAY-CEL-009  RELAY-CEL-ENGINE-REQUEST   (wasm engine request/marshaling bug)
//   RELAY-CEL-009  RELAY-CEL-ENGINE-PANIC     (wasm reactor trap, re-instantiated)
//
// Spec anchors: D, B.4 (closed error envelope).
// Eng plan anchors: CQ1 lines 145-157, X4 line 216.
// CLAUDE.md anchors: keystone invariant 6, banned pattern #16.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export const SUBTYPE_PROFILE_DYN_DISABLED =
  "RELAY-CEL-PROFILE-DYN-DISABLED" as const;
export const SUBTYPE_PROFILE_TS_DISABLED =
  "RELAY-CEL-PROFILE-TS-DISABLED" as const;
export const SUBTYPE_PROFILE_DUR_DISABLED =
  "RELAY-CEL-PROFILE-DUR-DISABLED" as const;
// The wasm emits RELAY-CEL-PROFILE-STRUCT-DISABLED for the struct/message
// construction fence (`Foo{...}`, struct-field entries; crate/src/lib.rs:106).
// It shares the RELAY-CEL-002 profile code with DYN/TS/DUR and is mapped onto
// RelayCelProfileError by decodeWasmEnvelope. Mirrors the Rust `subtypes::STRUCT`
// constant; Python carries the same token via the wasm envelope.
export const SUBTYPE_PROFILE_STRUCT_DISABLED =
  "RELAY-CEL-PROFILE-STRUCT-DISABLED" as const;
export const SUBTYPE_PROFILE_REGEX_BACKREF =
  "RELAY-CEL-PROFILE-REGEX-BACKREF" as const;
export const SUBTYPE_TIMEOUT = "RELAY-CEL-TIMEOUT-001" as const;
export const SUBTYPE_UDF_IMPURE = "RELAY-CEL-UDF-IMPURE" as const;
export const SUBTYPE_NUMERIC_OOB = "RELAY-CEL-NUMERIC-OOB" as const;
// A caller passed an extra UDF the wasm engine has no registration slot for
// (the engine exposes only the 3 hardcoded relay.* UDFs). Shares the UDF code
// (004) with the purity error -- both are UDF-registration failures. Mirrors
// the Python SUBTYPE_UDF_UNREGISTERED (errors.py:52). The class that raises it
// is RelayCelUnsupportedUdfError (below), thrown by the WasmCelBackend reject
// path (wasm-evaluator.ts, VAL-CWC-P2TSGATE-003).
export const SUBTYPE_UDF_UNREGISTERED = "RELAY-CEL-UDF-UNREGISTERED" as const;
// Engine-error subtypes (RELAY-CEL-009): the wasm engine reported a failure
// that is NOT one of the classified host conditions. Distinct from 004/006 so
// a wasm exec/request failure is never confused with a host UDF-impurity (004)
// / numeric-out-of-bounds (006) classification (which would poison the gate's
// signed per-condition error_code). Mirrors errors.py:58-61.
export const SUBTYPE_ENGINE_COMPILE = "RELAY-CEL-ENGINE-COMPILE" as const;
export const SUBTYPE_ENGINE_EXEC = "RELAY-CEL-ENGINE-EXEC" as const;
export const SUBTYPE_ENGINE_REQUEST = "RELAY-CEL-ENGINE-REQUEST" as const;
export const SUBTYPE_ENGINE_PANIC = "RELAY-CEL-ENGINE-PANIC" as const;

// Canonical RELAY-CEL-NNN codes. The Python side imports these from the
// generated RelayErrorCode registry (packages/schemas/python/relay_schemas/
// error_codes.py). The TS registry lives in
// packages/sdk-typescript/src/_generated/. We import only the literal
// strings to keep this package free of cross-package generated-source
// coupling -- the canonical codes are pinned by VAL-W1-NNN; if they
// change there, the cross-language parity tests catch the divergence.
export const CODE_RELAY_CEL_002 = "RELAY-CEL-002" as const;
export const CODE_RELAY_CEL_003 = "RELAY-CEL-003" as const;
export const CODE_RELAY_CEL_004 = "RELAY-CEL-004" as const;
export const CODE_RELAY_CEL_006 = "RELAY-CEL-006" as const;
export const CODE_RELAY_CEL_007 = "RELAY-CEL-007" as const;
// RELAY-CEL-009: the wasm CEL engine reported a non-classified internal
// failure (compile / exec / request / panic). DISTINCT from the host's
// classified 004 (UDF) / 006 (numeric) codes so a wasm exec/request failure is
// never confused with a host classification. Mirrors errors.py:210.
export const CODE_RELAY_CEL_009 = "RELAY-CEL-009" as const;

export type RelayCelCode =
  | typeof CODE_RELAY_CEL_002
  | typeof CODE_RELAY_CEL_003
  | typeof CODE_RELAY_CEL_004
  | typeof CODE_RELAY_CEL_006
  | typeof CODE_RELAY_CEL_007
  | typeof CODE_RELAY_CEL_009;

export type RelayCelSubtype =
  | typeof SUBTYPE_PROFILE_DYN_DISABLED
  | typeof SUBTYPE_PROFILE_TS_DISABLED
  | typeof SUBTYPE_PROFILE_DUR_DISABLED
  | typeof SUBTYPE_PROFILE_STRUCT_DISABLED
  | typeof SUBTYPE_PROFILE_REGEX_BACKREF
  | typeof SUBTYPE_TIMEOUT
  | typeof SUBTYPE_UDF_IMPURE
  | typeof SUBTYPE_UDF_UNREGISTERED
  | typeof SUBTYPE_NUMERIC_OOB
  | typeof SUBTYPE_ENGINE_COMPILE
  | typeof SUBTYPE_ENGINE_EXEC
  | typeof SUBTYPE_ENGINE_REQUEST
  | typeof SUBTYPE_ENGINE_PANIC;

// The 4 ENGINE subtypes (RELAY-CEL-009). RelayCelEngineError carries ONLY one of
// these -- never a profile (002) / UDF (004) / numeric (006) subtype, which
// would poison the gate's signed per-condition error_code. The constructor and
// WASM_CODE_TO_ENGINE_SUBTYPE are narrowed to this union so a non-engine subtype
// cannot reach an engine error at the type level. Mirrors errors.py's engine
// subtype set (SUBTYPE_ENGINE_*).
export type RelayCelEngineSubtype =
  | typeof SUBTYPE_ENGINE_COMPILE
  | typeof SUBTYPE_ENGINE_EXEC
  | typeof SUBTYPE_ENGINE_REQUEST
  | typeof SUBTYPE_ENGINE_PANIC;

// The known profile (RELAY-CEL-002) subtypes the wasm may emit. decodeWasmEnvelope
// validates the wasm's structured subtype against this set BEFORE casting it onto
// RelayCelProfileError, so an unknown / malformed profile subtype is treated as an
// engine-request anomaly rather than blindly trusted. REGEX-BACKREF is a host
// pre-screen subtype (escalated to RELAY-CEL-007), NOT a wasm-emitted 002 subtype,
// so it is intentionally excluded here.
export const WASM_PROFILE_SUBTYPES: ReadonlySet<RelayCelSubtype> = new Set<
  RelayCelSubtype
>([
  SUBTYPE_PROFILE_DYN_DISABLED,
  SUBTYPE_PROFILE_TS_DISABLED,
  SUBTYPE_PROFILE_DUR_DISABLED,
  SUBTYPE_PROFILE_STRUCT_DISABLED,
]);

// Stable JSON-serialisable envelope. Key set (`code`, `subtype`,
// `message`) matches the Python envelope (errors.py) -- tests compare
// `code` + `subtype` for cross-runtime byte equality.
export interface RelayCelErrorEnvelope {
  code: RelayCelCode;
  subtype: RelayCelSubtype;
  message: string;
}

export class RelayCelError extends Error {
  // Subclasses set `code` and `subtype` as own properties on construction.
  public readonly code: RelayCelCode;
  public readonly subtype: RelayCelSubtype;

  constructor(
    message: string,
    code: RelayCelCode,
    subtype: RelayCelSubtype,
  ) {
    super(message);
    this.name = "RelayCelError";
    this.code = code;
    this.subtype = subtype;
  }

  envelope(): RelayCelErrorEnvelope {
    return { code: this.code, subtype: this.subtype, message: this.message };
  }
}

export class RelayCelProfileError extends RelayCelError {
  constructor(message: string, subtype: RelayCelSubtype) {
    super(message, CODE_RELAY_CEL_002, subtype);
    this.name = "RelayCelProfileError";
  }
}

export class RelayCelTimeoutError extends RelayCelError {
  constructor(message: string) {
    super(message, CODE_RELAY_CEL_003, SUBTYPE_TIMEOUT);
    this.name = "RelayCelTimeoutError";
  }
}

export class RelayUdfPurityError extends RelayCelError {
  constructor(message: string) {
    super(message, CODE_RELAY_CEL_004, SUBTYPE_UDF_IMPURE);
    this.name = "RelayUdfPurityError";
  }
}

// A caller passed an extra UDF the wasm engine cannot host. The single-engine
// (wasm) backend exposes only the 3 hardcoded Relay UDFs (relay.coverage /
// relay.tool_arg / relay.schema_match) and has NO registration mechanism, so any
// caller-supplied extra UDF is rejected fail-closed BEFORE evaluation. Shares
// the UDF code (004) with the purity error; the subtype distinguishes
// "unregistered" from "impure". Mirrors the Python RelayCelUnsupportedUdfError
// (errors.py:171-182) EXACTLY (code 004, subtype RELAY-CEL-UDF-UNREGISTERED).
export class RelayCelUnsupportedUdfError extends RelayCelError {
  constructor(message: string) {
    super(message, CODE_RELAY_CEL_004, SUBTYPE_UDF_UNREGISTERED);
    this.name = "RelayCelUnsupportedUdfError";
  }
}

export class RelayCelNumericOutOfBoundsError extends RelayCelError {
  constructor(message: string) {
    super(message, CODE_RELAY_CEL_006, SUBTYPE_NUMERIC_OOB);
    this.name = "RelayCelNumericOutOfBoundsError";
  }
}

export class RelayCelRegexBackreferenceError extends RelayCelProfileError {
  constructor(message: string) {
    super(message, SUBTYPE_PROFILE_REGEX_BACKREF);
    // Override the inherited code RELAY-CEL-002 with RELAY-CEL-007 to
    // mirror the Python class hierarchy where regex backref escalates
    // the canonical code.
    Object.defineProperty(this, "code", {
      value: CODE_RELAY_CEL_007,
      writable: false,
      enumerable: true,
      configurable: false,
    });
    this.name = "RelayCelRegexBackreferenceError";
  }
}

// Map a wasm engine envelope code -> the RELAY-CEL-009 engine subtype. The wasm
// emits its OWN RELAY-CEL-NNN namespace (packages/cel-wasm crate `codes`):
// 001 = compile, 004 = exec, 006 = request; plus the host loader's
// RELAY-CEL-PANIC trap marker. Their NUMBERS overlap the host's classified
// codes (004 = UDF-impure, 006 = numeric-OOB) but their MEANINGS differ, so the
// wasm-backed adapter translates them into the distinct 009 code with a
// per-cause subtype. (The wasm's 002 profile envelope is handled separately ->
// RelayCelProfileError, carrying the wasm's own subtype.)
// Mirrors packages/contracts/src/relay_contracts/errors.py:193-198 EXACTLY.
const WASM_CODE_TO_ENGINE_SUBTYPE: Readonly<
  Record<string, RelayCelEngineSubtype>
> = {
  "RELAY-CEL-001": SUBTYPE_ENGINE_COMPILE,
  "RELAY-CEL-004": SUBTYPE_ENGINE_EXEC,
  "RELAY-CEL-006": SUBTYPE_ENGINE_REQUEST,
  "RELAY-CEL-PANIC": SUBTYPE_ENGINE_PANIC,
};

export class RelayCelEngineError extends RelayCelError {
  // The CEL engine reported a non-classified internal failure (RELAY-CEL-009).
  //
  // Distinct from the host's classified codes so a wasm compile/exec/request/
  // panic failure is never confused with a host UDF-impurity (004) or
  // numeric-out-of-bounds (006) classification -- a confusion that would poison
  // the gate's signed per-condition error_code (cross-runtime byte equality).
  //
  // A RelayCelError subclass so an `instanceof RelayCelError` catch site
  // catches it (mirrors the Python subclass relationship). Mirrors
  // errors.py:201-225.
  constructor(
    message: string,
    subtype: RelayCelEngineSubtype = SUBTYPE_ENGINE_EXEC,
  ) {
    super(message, CODE_RELAY_CEL_009, subtype);
    this.name = "RelayCelEngineError";
  }

  // Translate a wasm engine `{ok:false}` envelope into a 009 error. `wasmCode`
  // is the engine's OWN RELAY-CEL-NNN code (or RELAY-CEL-PANIC); unknown codes
  // default to ENGINE-EXEC. The original wasm code is preserved in the message
  // for diagnosis. Mirrors Python RelayCelEngineError.from_wasm_envelope
  // (errors.py:216-225).
  static fromWasmEnvelope(wasmCode: string, message: string): RelayCelEngineError {
    const subtype = WASM_CODE_TO_ENGINE_SUBTYPE[wasmCode] ?? SUBTYPE_ENGINE_EXEC;
    return new RelayCelEngineError(`[${wasmCode}] ${message}`, subtype);
  }
}
