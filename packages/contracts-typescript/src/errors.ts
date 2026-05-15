// Structured error envelope for the Relay CEL evaluator (TypeScript).
//
// Every Relay-CEL error carries a canonical `RELAY-CEL-NNN` code plus a
// stable `subtype` token. The cel-python module emits the identical token
// set; the pair (`code`, `subtype`) is the cross-runtime byte-equality
// key that VAL-W6-006 / VAL-W6-007 / VAL-W6-014 enforce.
//
// Code-to-subtype map (must match packages/contracts/src/relay_contracts/errors.py):
//
//   RELAY-CEL-002  RELAY-CEL-PROFILE-DYN-DISABLED
//   RELAY-CEL-002  RELAY-CEL-PROFILE-TS-DISABLED
//   RELAY-CEL-002  RELAY-CEL-PROFILE-DUR-DISABLED
//   RELAY-CEL-003  RELAY-CEL-TIMEOUT-001
//   RELAY-CEL-004  RELAY-CEL-UDF-IMPURE
//   RELAY-CEL-006  RELAY-CEL-NUMERIC-OOB
//   RELAY-CEL-007  RELAY-CEL-PROFILE-REGEX-BACKREF
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
export const SUBTYPE_PROFILE_REGEX_BACKREF =
  "RELAY-CEL-PROFILE-REGEX-BACKREF" as const;
export const SUBTYPE_TIMEOUT = "RELAY-CEL-TIMEOUT-001" as const;
export const SUBTYPE_UDF_IMPURE = "RELAY-CEL-UDF-IMPURE" as const;
export const SUBTYPE_NUMERIC_OOB = "RELAY-CEL-NUMERIC-OOB" as const;

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

export type RelayCelCode =
  | typeof CODE_RELAY_CEL_002
  | typeof CODE_RELAY_CEL_003
  | typeof CODE_RELAY_CEL_004
  | typeof CODE_RELAY_CEL_006
  | typeof CODE_RELAY_CEL_007;

export type RelayCelSubtype =
  | typeof SUBTYPE_PROFILE_DYN_DISABLED
  | typeof SUBTYPE_PROFILE_TS_DISABLED
  | typeof SUBTYPE_PROFILE_DUR_DISABLED
  | typeof SUBTYPE_PROFILE_REGEX_BACKREF
  | typeof SUBTYPE_TIMEOUT
  | typeof SUBTYPE_UDF_IMPURE
  | typeof SUBTYPE_NUMERIC_OOB;

// Stable JSON-serialisable envelope. Key set (`code`, `subtype`,
// `message`) matches the cel-python Python envelope -- tests compare
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
