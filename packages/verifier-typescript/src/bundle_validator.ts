// End-to-end evidence bundle validator (TS parity with
// packages/verifier/src/relay_verifier/bundle_validator.py).
//
// Orchestrates the verifier sub-modules into a single `validateBundle`
// entry point that produces the canonical verifier output envelope
// (schema_version `relay.verifier.output.v1`).
//
// Validation pipeline (each step contributes to the output):
//   1. Archive-bomb gate (VAL-W10-036)
//   2. Structure + per-claim digest (VAL-W10-020 / 022)
//   3. JWS verification (VAL-W10-021 / 023 / 014)
//   4. Merkle root (VAL-W10-024)
//   5. TSA timestamp (VAL-W10-025..027)
//   6. Transparency-log inclusion (VAL-W10-028..030)
//   7. Signer key lifecycle (VAL-W10-031..034)
//   8. trust_anchor surfacing (VAL-W10-035 / 041)
//   9. Subject resolution (VAL-W10-037 / 038)
//
// Output is a plain object whose JCS serialisation matches the Python
// orchestrator's for the same fixture (VAL-V2M06-022).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";

import { checkArtifactPath } from "./bundle_paths.js";
import {
  CANONICAL_NON_BMP_KEY_CODE,
  JCSEncodeError,
  jcsCanonicalize,
  bundleDigest,
} from "./canonical.js";
import { DEFAULT_JWKS_URL } from "./constants.js";
import {
  RELAY_EVID_041,
  RELAY_EVID_042,
  checkSigningKeyLifecycle,
  type KeyLifecycleResult,
} from "./key_lifecycle.js";
import { computeMerkleRoot } from "./merkle.js";
import {
  SUBJECT_RESOLUTION_UNKNOWN,
  type SubjectStore,
  resolveSubject,
} from "./retention.js";
import { verifyLogInclusion } from "./transparency_log.js";
import {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  RELAY_EVID_031,
  RELAY_EVID_038,
  loadBundledTsaChain,
  loadTsaChainPemBytes,
  validateTsaToken,
  type TsaToken,
} from "./tsa.js";
import type { X509Certificate } from "node:crypto";
import {
  _selectJwk,
  canonicalJsonBytes,
  verifyBundleSignature,
  verifyDetachedClaimSignature,
  type BundleSignatureEntry,
  type JWK,
  type JWKS,
  type SignatureCheck,
} from "./verifier.js";

export const VERIFIER_OUTPUT_SCHEMA = "relay.verifier.output.v1" as const;

export const MAX_BUNDLE_ENTRIES = 4096;
export const MAX_BUNDLE_BYTES = 256 * 1024 * 1024;

/**
 * Maximum number of cross-signing signatures the verifier will accept on
 * a single bundle. Per spec section L.5 line 4481 / VAL-V2M08-041 (parity
 * with Python `MAX_BUNDLE_SIGNATURES`).
 *
 * A bundle carrying more than this many signatures is rejected
 * fail-closed BEFORE any per-signature cryptographic work runs. Defends
 * against (1) producers padding bundles with hundreds of dummy
 * signatures to amplify verification cost (DoS); and (2) producers
 * abusing the cross-signing slot for non-signature data.
 */
export const MAX_BUNDLE_SIGNATURES = 4;

export const RELAY_EVID_024 = "RELAY-EVID-024" as const;
/** Archive-bomb limit exceeded (VAL-W10-036). */

export const RELAY_EVID_014 = "RELAY-EVID-014" as const;
/** Evidence-bundle integrity failure (per-claim signature). */

export const RELAY_EVID_040 = "RELAY-EVID-040" as const;
/** Merkle root mismatch (VAL-W10-024). */

export const RELAY_EVID_NAMESPACE_UNKNOWN =
  "RELAY-EVID-NAMESPACE-UNKNOWN" as const;
/**
 * Code surfaced when a claim's `namespaces` dict contains a top-level key
 * outside the closed set {x-relay} (VAL-V3M1-022). Parity with Python
 * `bundle_validator.RELAY_EVID_NAMESPACE_UNKNOWN`. Empty / absent
 * `namespaces` is accepted (the field is optional per spec K line 4421-4423).
 */

/**
 * V3M1-F07: closed set of allowed top-level keys on EvidenceClaim.namespaces.
 * Adding a new key here is a spec amendment, not a routine PR. Mirrors
 * Python `_ALLOWED_NAMESPACE_KEYS` (bundle_validator.py:204).
 */
const ALLOWED_NAMESPACE_KEYS: ReadonlySet<string> = new Set(["x-relay"]);

export const RELAY_EVID_SIGCOUNT_EXCEEDED =
  "RELAY-EVID-SIGCOUNT-EXCEEDED" as const;
/**
 * Bundle carries more than {@link MAX_BUNDLE_SIGNATURES} signatures
 * (VAL-V2M08-041). Surfaced in {@link validateBundle} output as a
 * structured error with `signatures_present` echoing the wire count so
 * operators can identify the over-cap producer.
 */

export const RELAY_EVID_MISSING_TRUST_ANCHOR =
  "RELAY-EVID-MISSING-TRUST-ANCHOR" as const;
/**
 * Bundle is missing the top-level `trust_anchor` field (or the field is
 * not a non-empty string) (VAL-V2M08-043). Per spec section AO.4 line
 * 6166 every signed bundle MUST declare its trust anchor; absence means
 * the verifier cannot classify the bundle against the operator's trust
 * posture and the bundle is rejected fail-closed.
 */

export const RELAY_EVID_DECIDED_AT_MISSING =
  "RELAY-EVID-DECIDED-AT-MISSING" as const;
/**
 * Bundle missing the canonical `decided_at` TSA-binding anchor. The
 * validator MUST NOT silently fall back to `generated_at` or any other
 * sibling timestamp.
 */

export const TRUST_ANCHOR_LOCAL_DEV = "local_dev" as const;
export const WARN_LOCAL_DEV_UNSUPPORTED = "local_dev_unsupported_for_audit" as const;

// w8-trust-anchor: trust_anchor_class output enum (VAL-V2M08-044).
// Per spec section AO.4 lines 6164-6168 the verifier MUST classify the
// bundle's declared trust_anchor into one of three buckets, derived ONLY
// from the bundle's declared value (NEVER from the JWKS URL the verifier
// happens to be running under). A `local_dev` bundle stays
// `untrusted_local` even when the verifier is configured with the
// Relay-Inc default anchor.
export const TRUST_ANCHOR_CLASS_RELAY_INC = "relay_inc" as const;
export const TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL = "untrusted_local" as const;
export const TRUST_ANCHOR_CLASS_BYO = "byo" as const;

export type TrustAnchorClass =
  | ""
  | typeof TRUST_ANCHOR_CLASS_RELAY_INC
  | typeof TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL
  | typeof TRUST_ANCHOR_CLASS_BYO;

/**
 * Raw-authority URL parser that mirrors Python `urllib.parse.urlparse`'s
 * `.hostname` / `.path` semantics, used by {@link classifyTrustAnchor}.
 *
 * CRITICAL (bug verifier-ts-2): we do NOT use WHATWG `new URL()` here.
 * WHATWG URL NORMALIZES a backslash to a slash, so a backslash-crafted
 * authority like `https://relay.epochly.com\evil/.well-known/jwks.json`
 * would parse to host=`relay.epochly.com` (over-classifying relay_inc),
 * whereas Python `urlparse` keeps the backslash inside the reg-name and
 * yields host=`relay.epochly.com\evil` (correctly byo). To stay
 * byte-for-byte parity with Python we parse the raw authority + path
 * substrings ourselves (same rationale as `_canonicalHostOf` in
 * jwks_loader.ts).
 *
 * Mirrors urlparse: lowercases the host, splits userinfo at the FINAL
 * `@`, strips a bracketed IPv6 host's brackets, strips the `:port`
 * suffix, and excludes the query/fragment from the path. A string with
 * no `scheme://` authority (e.g. `fork.example`) yields an empty host,
 * matching Python `urlparse("fork.example").hostname == None`.
 */
// The port suffix accepts ANY characters up to the path delimiter (`[^/?#]*`),
// NOT only digits: Python `urlparse(...).hostname`/`.path` extract host and path
// even when the port is non-numeric (e.g. `host:abc`), because `.port` (which
// validates digits) is never accessed by classify_trust_anchor. Requiring
// `[0-9]*` here made the whole regex FAIL to match
// `https://relay.epochly.com:abc/.well-known/jwks.json`, yielding an empty host
// (-> `byo`) while Python kept the host (-> `relay_inc`): a verifier-output /
// signer_role parity break (roborev 7feb671 MEDIUM). Host is still the run up to
// the FIRST `:` (group 1), matching Python's `partition(':')` hostname split.
const _RAW_URL_RE =
  /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/?#]*@)?(\[[^\]]*\]|[^/:?#@]*)(?::[^/?#]*)?([/?#].*)?$/;

function _urlparseHostPath(url: string): { host: string; path: string } {
  const m = _RAW_URL_RE.exec(url);
  if (m === null) {
    return { host: "", path: "" };
  }
  let host = m[1] ?? "";
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }
  host = host.toLowerCase();
  let path = m[2] ?? "";
  // urlparse .path excludes the query (?) and fragment (#) components.
  const qi = path.search(/[?#]/);
  if (qi >= 0) {
    path = path.slice(0, qi);
  }
  return { host, path };
}

/**
 * Return the `trust_anchor_class` for a bundle-declared `trust_anchor`.
 *
 * Mirrors `relay_verifier.bundle_validator.classify_trust_anchor` so
 * Python and TypeScript verifiers emit the same classification for the
 * same wire value (VAL-V2M08-044). Python's `urlparse` is the parity
 * reference; see {@link _urlparseHostPath}.
 *
 * Returns:
 *   - {@link TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL} when value equals the
 *     `local_dev` sentinel.
 *   - {@link TRUST_ANCHOR_CLASS_RELAY_INC} when value is a URL whose
 *     host is EXACTLY `relay.epochly.com` AND whose path is EXACTLY
 *     `/.well-known/jwks.json` (equality, not a suffix test). The
 *     exact-path check defends against a producer pointing at an
 *     attacker-controlled path on the Relay-Inc host (e.g.
 *     `https://relay.epochly.com/evil` or
 *     `https://relay.epochly.com/attacker/path/.well-known/jwks.json`).
 *   - {@link TRUST_ANCHOR_CLASS_BYO} for any other non-empty string.
 *   - `""` when value is missing, non-string, or empty; caller emits
 *     {@link RELAY_EVID_MISSING_TRUST_ANCHOR} separately.
 */
export function classifyTrustAnchor(trustAnchorValue: unknown): TrustAnchorClass {
  if (typeof trustAnchorValue !== "string" || trustAnchorValue.length === 0) {
    return "";
  }
  if (trustAnchorValue === TRUST_ANCHOR_LOCAL_DEV) {
    return TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL;
  }
  const { host, path } = _urlparseHostPath(trustAnchorValue);
  if (host === "relay.epochly.com" && path === "/.well-known/jwks.json") {
    return TRUST_ANCHOR_CLASS_RELAY_INC;
  }
  return TRUST_ANCHOR_CLASS_BYO;
}

// V3M1-F07: signer_role enum (VAL-V3M1-018; spec K line 4427). Parity with
// Python `bundle_validator.SIGNER_ROLE_*`.
//
// Per spec K rule line 4427 ("The signer can only be the control-plane
// evidence-signer service for hosted bundles. Local OSS bundles can be signed
// with a local key; the verifier reports the trust path.") the verifier MUST
// surface a signer_role classification on every output so auditors can
// attribute the bundle to one of three trust paths. The classification derives
// ONLY from the bundle's declared trust_anchor value (via trust_anchor_class),
// never from the JWKS the verifier is configured with: a local_dev bundle stays
// signer_role='local_dev' even when the verifier runs under the Relay-Inc
// default anchor (no-auto-promotion guarantee).

/**
 * Bundle declares the Relay-Inc default trust_anchor URL; the bundle's signer
 * is attributable to the control-plane evidence-signer service.
 */
export const SIGNER_ROLE_CONTROL_PLANE = "control_plane" as const;

/**
 * Bundle declares `trust_anchor: 'local_dev'`; the bundle's signer is the OSS
 * local-dev signer. Auditors treat these bundles as informational only.
 */
export const SIGNER_ROLE_LOCAL_DEV = "local_dev" as const;

/**
 * Bundle's declared trust_anchor classifies as BYO (third-party anchor) or is
 * missing entirely. The verifier cannot attribute the bundle to either trust
 * path; consumers branching on signer_role see this default rather than an
 * empty string.
 */
export const SIGNER_ROLE_UNKNOWN = "unknown" as const;

export type SignerRole =
  | typeof SIGNER_ROLE_CONTROL_PLANE
  | typeof SIGNER_ROLE_LOCAL_DEV
  | typeof SIGNER_ROLE_UNKNOWN;

/**
 * Return the signer_role classification for a trust_anchor_class. Pure mapping
 * (no I/O, no side effects). Mirrors Python `_classify_signer_role`:
 *   - {@link TRUST_ANCHOR_CLASS_RELAY_INC}       -> {@link SIGNER_ROLE_CONTROL_PLANE}
 *   - {@link TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL} -> {@link SIGNER_ROLE_LOCAL_DEV}
 *   - {@link TRUST_ANCHOR_CLASS_BYO}             -> {@link SIGNER_ROLE_UNKNOWN}
 *   - `""` (missing/non-string anchor)           -> {@link SIGNER_ROLE_UNKNOWN}
 *   - any other string                           -> {@link SIGNER_ROLE_UNKNOWN}
 *     (fail-safe default for unrecognised classifications)
 */
export function classifySignerRole(trustAnchorClass: string): SignerRole {
  if (trustAnchorClass === TRUST_ANCHOR_CLASS_RELAY_INC) {
    return SIGNER_ROLE_CONTROL_PLANE;
  }
  if (trustAnchorClass === TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL) {
    return SIGNER_ROLE_LOCAL_DEV;
  }
  return SIGNER_ROLE_UNKNOWN;
}

export interface ValidateBundleOptions {
  strict_log?: boolean;
  strict_trust_anchor?: boolean;
  auditor_now?: Date;
  artifact_resolver?: ((artifactId: string) => Uint8Array | null) | null;
  subject_store?: SubjectStore | null;
  witness_jwks?: JWKS | Record<string, unknown> | null;
  default_trust_anchor?: string | null;
  /**
   * VAL-PARITY-004. Optional PEM blob of additional TSA trust roots merged
   * with the package-bundled chain at
   * `packages/verifier-typescript/src/tsa_chain/tsa-chain.pem`. Test-injection
   * seam used by fixture builders to anchor an ephemeral TSA root generated at
   * test time so the real RFC 3161 `TimeStampResp` signature verifies without
   * writing private key material to disk (banned pattern #14). Production
   * callers leave this undefined and the verifier uses only the bundled chain.
   * Mirrors the Python `ValidateBundleOptions.tsa_extra_trusted_roots_pem`.
   */
  tsa_extra_trusted_roots_pem?: Uint8Array | Buffer | null;
  /**
   * VAL-PARITY-004. If true, do NOT load the package-bundled TSA cert chain.
   * Used by tests that need to demonstrate the "untrusted root" failure mode
   * without their ephemeral cert accidentally chaining into the bundled
   * placeholder root via a collision. Defaults false. Mirrors the Python
   * `ValidateBundleOptions.tsa_skip_bundled_chain`.
   */
  tsa_skip_bundled_chain?: boolean;
}

export interface VerifierOutputEnvelope {
  schema_version: string;
  overall: "pass" | "fail";
  bundle_path: string;
  bundle_digest_sha256: string;
  digest_ok: boolean;
  structure_ok: boolean;
  signatures_ok: boolean;
  signatures_checked: Array<{
    kid: string;
    alg: string;
    ok: boolean;
    reason: string;
    code: string;
  }>;
  /**
   * VAL-V2M08-041. Wire count of signature entries the producer attached
   * to the bundle, surfaced regardless of per-signature outcomes so
   * consumers can detect the over-cap-rejection case
   * (`signatures_present > MAX_BUNDLE_SIGNATURES`).
   */
  signatures_present: number;
  claims_count: number;
  merkle_check: "ok" | "absent" | "mismatch";
  tsa_check: "ok" | "missing" | "invalid" | "skew";
  log_inclusion: "ok" | "absent" | "witness_mismatch";
  trust_anchor: string;
  /**
   * VAL-V2M08-044. Classification of the bundle's declared `trust_anchor`
   * value. Derived ONLY from the bundle's declared anchor, never from
   * the JWKS URL the verifier is configured with. Empty string when the
   * bundle is missing the `trust_anchor` field; the verifier also emits
   * {@link RELAY_EVID_MISSING_TRUST_ANCHOR} in that case.
   */
  trust_anchor_class: TrustAnchorClass;
  trust_anchor_source: string;
  /**
   * VAL-V3M1-018 (spec K line 4427). Signer attribution path derived from the
   * bundle's declared trust_anchor field (via {@link classifySignerRole}).
   * Defaults to {@link SIGNER_ROLE_UNKNOWN} so consumers branching on this
   * field never see an empty string. Emitted on EVERY return path (matching
   * Python `_new_output` + `validate_bundle` placement) so Python<->TS JCS
   * byte-parity holds -- signer_role sorts between signer_key_revoked_at and
   * structure_ok in the canonical envelope.
   */
  signer_role: string;
  signer_key_revoked: boolean;
  signer_key_revoked_at: string | null;
  subject_resolution: string;
  warnings: Array<Record<string, unknown>>;
  errors: Array<Record<string, unknown>>;
  details?: Record<string, unknown>;
}

function _newOutput(): VerifierOutputEnvelope {
  return {
    schema_version: VERIFIER_OUTPUT_SCHEMA,
    overall: "fail",
    bundle_path: "",
    bundle_digest_sha256: "",
    digest_ok: false,
    structure_ok: false,
    signatures_ok: false,
    signatures_checked: [],
    // w8-trust-anchor: wire count of signatures the producer attached to
    // the bundle, surfaced regardless of per-signature outcomes so
    // consumers can detect the over-cap-rejection case (VAL-V2M08-041).
    signatures_present: 0,
    claims_count: 0,
    merkle_check: "absent",
    tsa_check: "missing",
    log_inclusion: "absent",
    trust_anchor: "",
    // w8-trust-anchor: classification of the bundle's declared
    // trust_anchor field (VAL-V2M08-044). Empty string when the bundle
    // lacks a declarable trust_anchor (which also produces a structural
    // error via RELAY-EVID-MISSING-TRUST-ANCHOR).
    trust_anchor_class: "",
    trust_anchor_source: "",
    // VAL-V3M1-018: signer attribution path derived from the bundle's declared
    // trust_anchor field. Defaults to SIGNER_ROLE_UNKNOWN so consumers
    // branching on this field never see an empty string (parity with Python
    // `_new_output` which seeds SIGNER_ROLE_UNKNOWN).
    signer_role: SIGNER_ROLE_UNKNOWN,
    signer_key_revoked: false,
    signer_key_revoked_at: null,
    subject_resolution: SUBJECT_RESOLUTION_UNKNOWN,
    warnings: [],
    errors: [],
  };
}

function _appendWarning(
  output: VerifierOutputEnvelope,
  args: { reason: string; message: string; code?: string },
): void {
  const entry: Record<string, unknown> = { reason: args.reason, message: args.message };
  if (args.code) {
    entry["code"] = args.code;
  }
  output.warnings.push(entry);
}

/**
 * Format a string the way CPython's ``ascii()`` does, so verifier-output
 * ``message`` bytes match the Python verifier (HIGH #4). The Python side now
 * interpolates attacker-controllable identifiers via ``_py_ascii(...)`` (the
 * builtin ``ascii()``) instead of ``!r``, because plain ``repr()`` keeps
 * PRINTABLE non-ASCII verbatim but ESCAPES non-printable non-ASCII (C1
 * controls, U+00A0, format/separator chars like U+200B/U+2028/U+FEFF). That
 * "printable" distinction depends on the Unicode database and is intractable to
 * mirror byte-for-byte in TS. ``ascii()`` removes the distinction: EVERY
 * non-ASCII code point is escaped by a pure range rule, so both runtimes agree
 * by construction.
 *
 * Rule (identical to CPython ``ascii()``): single quotes, switching to double
 * quotes only when the string contains a single quote and no double quote;
 * backslash-escape the quote char, backslash, and ``\t``/``\n``/``\r``; emit
 * ASCII control bytes (cp < 0x20) and DEL (0x7f) as ``\xNN``; emit every
 * non-ASCII code point as ``\xNN`` (cp <= 0xff), ``\uNNNN`` (cp <= 0xffff), or
 * ``\U`` + 8 hex (astral). Printable ASCII (0x20..0x7e) is emitted verbatim, so
 * the output is unchanged for the ASCII operand domain (artifact ids, hex
 * digests, dotted namespace keys, bundle field names) and existing ASCII parity
 * tests stay byte-identical.
 */
function pyReprStr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (ch === quote || ch === "\\") {
      out += "\\" + ch;
    } else if (ch === "\t") {
      out += "\\t";
    } else if (ch === "\n") {
      out += "\\n";
    } else if (ch === "\r") {
      out += "\\r";
    } else if (cp < 0x20 || cp === 0x7f) {
      out += "\\x" + cp.toString(16).padStart(2, "0");
    } else if (cp >= 0x80) {
      // Non-ASCII: escape by code-point range exactly like CPython ascii().
      if (cp <= 0xff) {
        out += "\\x" + cp.toString(16).padStart(2, "0");
      } else if (cp <= 0xffff) {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      } else {
        out += "\\U" + cp.toString(16).padStart(8, "0");
      }
    } else {
      out += ch;
    }
  }
  return out + quote;
}

/**
 * CPython ``repr()`` for the operand types interpolated with ``!r`` in the
 * Python verifier's error messages: a string, or a list of strings (e.g.
 * ``sorted(allowed_keys)``, ``unknown_keys``, ``present_fields``). A list is
 * rendered ``['a', 'b']`` exactly like Python's ``list.__repr__``.
 */
function pyRepr(value: string | readonly string[]): string {
  if (typeof value === "string") return pyReprStr(value);
  return "[" + value.map((v) => pyReprStr(v)).join(", ") + "]";
}

function _appendError(
  output: VerifierOutputEnvelope,
  args: {
    reason: string;
    message: string;
    code?: string;
    extra?: Record<string, unknown>;
  },
): void {
  const entry: Record<string, unknown> = { reason: args.reason, message: args.message };
  if (args.code) {
    entry["code"] = args.code;
  }
  // Forward additional discriminator keys verbatim (e.g. path_violation +
  // offending_path), matching Python _append_error(**extra) (re-hunt #8).
  if (args.extra) {
    for (const [k, v] of Object.entries(args.extra)) {
      entry[k] = v;
    }
  }
  output.errors.push(entry);
}

// Structured-rejection tokens for a bundle the JCS encoder refuses to
// canonicalise (currently: a supplementary-plane / non-BMP object KEY).
// RFC 8785 sorts object keys by UTF-16 code unit; Python sorts by code
// point. For keys with a codepoint >= U+10000 the orderings diverge, so the
// TypeScript and Python verifiers would canonicalise the same bundle to
// DIFFERENT bytes -> different SHA-256 -> a bundle that verifies on one
// runtime and is rejected as tampered on the other (keystone invariant #11).
// The encoder fails-closed (canonical.ts raises JCSEncodeError); the
// validator pre-screens and emits this structured error so validateBundle
// keeps its never-throws contract. The reason token and message MUST be
// byte-identical to the Python twin in
// packages/verifier/src/relay_verifier/bundle_validator.py so the two
// runtimes return identical structured rejections (keystone invariant #16).
// The message names NO specific key on purpose: JS Object.keys reorders
// integer-like keys relative to Python's insertion order, so a key-naming
// message could diverge across runtimes for adversarial nested inputs -- a
// fixed message is parity-safe by construction.
const NON_CANONICALIZABLE_BUNDLE_REASON = "non_canonicalizable_bundle";
const NON_CANONICALIZABLE_BUNDLE_MESSAGE =
  "bundle contains a non-BMP (supplementary-plane, >= U+10000) object " +
  "key; supplementary-plane object keys produce runtime-divergent " +
  "canonical bytes between the Python and TypeScript verifiers and are " +
  "refused. Re-key any such object with BMP-only strings.";

/**
 * Return true iff `value` contains an object KEY with a codepoint >= U+10000
 * anywhere in its nested structure.
 *
 * Detects -- BEFORE any canonicalisation -- a bundle the JCS encoder would
 * refuse (see `jcsCanonicalize` in canonical.ts, which fails-closed on
 * non-BMP keys to keep Python<->TypeScript canonical bytes identical,
 * keystone invariant #11). Only object KEYS are screened (mirroring the
 * encoder); string VALUES may carry supplementary-plane characters. The
 * boolean result is independent of key-iteration order, so it matches the
 * Python twin `_has_non_bmp_key` regardless of the JS-vs-Python object-key
 * ordering difference.
 */
function _hasNonBmpKey(value: unknown): boolean {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      for (const ch of k) {
        const cp = ch.codePointAt(0);
        if (cp !== undefined && cp >= 0x10000) {
          return true;
        }
      }
      if (_hasNonBmpKey(obj[k])) {
        return true;
      }
    }
    return false;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (_hasNonBmpKey(item)) {
        return true;
      }
    }
    return false;
  }
  return false;
}

function _claimDigestsInOrder(bundle: Record<string, unknown>): string[] {
  const claims = bundle["claims"];
  if (!Array.isArray(claims)) {
    return [];
  }
  const out: string[] = [];
  for (const claim of claims) {
    if (claim !== null && typeof claim === "object" && !Array.isArray(claim)) {
      out.push(bundleDigest(claim, { stripSignatures: true }));
    } else {
      out.push(createHash("sha256").update(jcsCanonicalize(claim)).digest("hex"));
    }
  }
  return out;
}

/**
 * Compute SHA-256(verifier-canonical-JSON(bundle minus signatures/tsa/log)).
 *
 * Mirrors `_compute_binding_digest` in Python: strips `signatures`,
 * `tsa_token`, and `log_inclusion_proof` before canonicalising and
 * hashing. Used by both the TSA token validator AND the transparency-log
 * inclusion-proof verifier so the producer's pre-extensions digest can
 * be recomputed by the verifier.
 */
function _computeBindingDigest(bundle: Record<string, unknown>): string {
  const stripped: Record<string, unknown> = {};
  for (const k of Object.keys(bundle)) {
    if (k === "signatures" || k === "tsa_token" || k === "log_inclusion_proof") {
      continue;
    }
    stripped[k] = bundle[k];
  }
  return createHash("sha256")
    .update(canonicalJsonBytes(stripped))
    .digest("hex");
}

/** VAL-W10-036 archive-bomb pre-flight. */
export function checkArchiveBombLimits(args: {
  entryCount: number;
  uncompressedSizeBytes: number;
}): { ok: boolean; reason: string } {
  if (args.entryCount > MAX_BUNDLE_ENTRIES) {
    return {
      ok: false,
      reason:
        `bundle entry_count ${args.entryCount} exceeds MAX_BUNDLE_ENTRIES ` +
        `${MAX_BUNDLE_ENTRIES} (VAL-W10-036)`,
    };
  }
  if (args.uncompressedSizeBytes > MAX_BUNDLE_BYTES) {
    return {
      ok: false,
      reason:
        `bundle uncompressed_size_bytes ${args.uncompressedSizeBytes} ` +
        `exceeds MAX_BUNDLE_BYTES ${MAX_BUNDLE_BYTES} (VAL-W10-036)`,
    };
  }
  return { ok: true, reason: "" };
}

// ----------------------------------------------------------------------------
// JWS structural verification (mirrors Python `verify_bundle`)
// ----------------------------------------------------------------------------

interface JwsResult {
  digest_ok: boolean;
  structure_ok: boolean;
  signatures_ok: boolean;
  bundle_digest_sha256: string;
  claims_count: number;
  signature_checks: SignatureCheck[];
}

function _verifyBundle(bundle: Record<string, unknown>, jwks: JWKS): JwsResult {
  const result: JwsResult = {
    digest_ok: false,
    structure_ok: false,
    signatures_ok: false,
    bundle_digest_sha256: "",
    claims_count: 0,
    signature_checks: [],
  };
  // Mirror Python `verify_bundle` (verifier.py:362-365) ORDER: the
  // signatures-presence check runs FIRST -- BEFORE the bundle digest and the
  // claims validation. An absent/empty `signatures` array returns the
  // ALL-DEFAULT result (structure_ok=false, digest_ok=false, claims_count=0,
  // bundle_digest_sha256="") because Python returns before computing any of
  // them. Checking signatures first keeps a no-signatures bundle byte-identical
  // to Python on EVERY path -- including one whose `claims` is missing or
  // non-array, which a digest-then-claims order left with a populated
  // bundle_digest while Python returned all-default (re-hunt
  // verifier-structure-parity-1/-2; roborev 8b805fc).
  const signatures = bundle["signatures"];
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return result;
  }

  // Bundle-level digest is over the signature-stripped JCS canonical bytes
  // (mirrors bundleDigest convention and Python's `_payload_for_signing` +
  // `canonical_json_bytes`). Only computed once signatures are present, matching
  // Python (verifier.py:367-370).
  try {
    result.bundle_digest_sha256 = bundleDigest(bundle, { stripSignatures: true });
  } catch (err) {
    if (err instanceof JCSEncodeError) {
      // The JCS encoder fails-closed on a payload it cannot canonicalise to
      // runtime-identical bytes -- specifically a supplementary-plane
      // (non-BMP, >= U+10000) object KEY, which Python sorts by code point
      // while this verifier sorts by UTF-16 code unit (keystone invariant
      // #11). Preserve the never-throws contract: return the all-default
      // result (structure_ok stays false), exactly like the no-signatures
      // early return above. The higher-level validateBundle pre-screens for
      // this and emits a structured 'non_canonicalizable_bundle' error before
      // reaching here; this guard protects DIRECT callers of _verifyBundle.
      return result;
    }
    throw err;
  }

  const claims = bundle["claims"];
  if (!Array.isArray(claims)) {
    return result;
  }
  result.claims_count = claims.length;
  result.structure_ok = true;
  result.digest_ok = true;

  // BUG-C3 wire-shape parity: the canonical signing payload is the
  // bundle with `signatures` stripped. Each signature entry carries
  // `signing_input_b64u` (b64url(jcs_canonicalize(payload))) and
  // `signature_b64u`. This mirrors Python `verifier.py::verify_bundle`
  // lines 366-560 exactly.
  const stripped: Record<string, unknown> = {};
  for (const k of Object.keys(bundle)) {
    if (k === "signatures") continue;
    stripped[k] = bundle[k];
  }
  const expectedCanonicalBytes = jcsCanonicalize(stripped);

  let allValid = true;
  let digestOk = true;
  let anyPresent = false;
  for (let idx = 0; idx < signatures.length; idx++) {
    const sig = signatures[idx];
    if (sig === null || typeof sig !== "object" || Array.isArray(sig)) {
      result.signature_checks.push({
        kid: `<sig[${idx}]>`,
        alg: "<unknown>",
        ok: false,
        reason: "signature entry is not an object",
        code: "",
      });
      allValid = false;
      digestOk = false;
      continue;
    }
    const check = verifyBundleSignature({
      signature: sig as BundleSignatureEntry,
      expectedCanonicalBytes,
      jwks,
      signatureIndex: idx,
    });
    result.signature_checks.push(check);
    if (check.ok) {
      anyPresent = true;
    } else {
      allValid = false;
      // Python flips digest_ok=False on certain failures (missing kid,
      // missing signing_input_b64u, signing_input drift, b64url decode
      // failure). Conservatively flip digest_ok on any structural or
      // signing-input failure -- the surface symptom is "the bundle's
      // recorded canonical bytes don't equal the recomputed ones".
      if (
        check.reason === "signature missing 'kid'" ||
        check.reason === "signature missing 'signing_input_b64u'" ||
        check.reason.startsWith("signing_input drift:") ||
        check.reason.startsWith("signing_input_b64u is not valid base64url:")
      ) {
        digestOk = false;
      }
    }
  }
  result.digest_ok = digestOk;
  // Python's verify_bundle requires `any_signature_present` (line 563);
  // we mirror that here -- a bundle whose signatures all failed
  // pre-crypto checks is NOT `signatures_ok` even if `allValid` is
  // vacuously true (empty checks).
  result.signatures_ok = allValid && anyPresent;
  return result;
}

// ----------------------------------------------------------------------------
// Validator
// ----------------------------------------------------------------------------

/**
 * Validate a parsed evidence bundle end-to-end. Mirrors
 * `relay_verifier.bundle_validator.validate_bundle` line-for-line.
 *
 * Returns a `VerifierOutputEnvelope` whose JCS serialisation matches the
 * Python orchestrator's output for the same fixture (VAL-V2M06-022).
 *
 * Never throws for verification outcomes -- every failure mode is encoded
 * in the structured output.
 */
export function validateBundle(args: {
  bundle: Record<string, unknown>;
  jwks: JWKS | Record<string, unknown>;
  bundle_path?: string;
  trust_anchor_source?: string;
  options?: ValidateBundleOptions;
}): VerifierOutputEnvelope {
  const opts = args.options ?? {};
  const output = _newOutput();
  output.bundle_path = args.bundle_path ?? "";
  output.trust_anchor_source = args.trust_anchor_source ?? "";
  const jwks = args.jwks as JWKS;
  const bundle = args.bundle;

  // --- Trust anchor echo (VAL-W10-035) -------------------------------------
  const trustAnchor = bundle["trust_anchor"];
  if (typeof trustAnchor === "string") {
    output.trust_anchor = trustAnchor;
  }

  // --- Trust anchor classification (VAL-V2M08-044) -------------------------
  // Classification is derived from the BUNDLE's declared trust_anchor
  // field ONLY, never from the JWKS URL the verifier is configured
  // with. local_dev stays untrusted_local even if the verifier is
  // running under the Relay-Inc default anchor.
  output.trust_anchor_class = classifyTrustAnchor(trustAnchor);

  // --- Signer-role classification (VAL-V3M1-018) ---------------------------
  // Per spec K rule line 4427 the verifier surfaces a signer_role on every
  // output. The classification derives ONLY from the bundle's declared
  // trust_anchor (via trust_anchor_class), never from the JWKS the verifier is
  // configured with: a local_dev bundle stays signer_role='local_dev' even
  // when the verifier is running under the Relay-Inc default anchor
  // (no-auto-promotion guarantee). This is computed BEFORE the
  // missing-trust-anchor and signature-count early returns so the field is
  // populated on EVERY return path (parity with Python placement at
  // bundle_validator.py validate_bundle, which sets signer_role before both
  // early returns).
  output.signer_role = classifySignerRole(output.trust_anchor_class);

  // --- Missing-trust_anchor rejection (VAL-V2M08-043) ----------------------
  // Fail-closed when the bundle declares no trust_anchor (or declares a
  // non-string / empty value). This MUST happen before signature work so
  // an unsigned classification cannot leak past the gate.
  if (typeof trustAnchor !== "string" || trustAnchor.length === 0) {
    _appendError(output, {
      reason: "trust_anchor_missing",
      message:
        "bundle is missing the required top-level 'trust_anchor' " +
        "field (spec section AO.4 line 6166); verifier cannot " +
        "classify the bundle against any trust posture",
      code: RELAY_EVID_MISSING_TRUST_ANCHOR,
    });
  }

  // --- Signature-count cap (VAL-V2M08-041) ---------------------------------
  // Per spec L.5 line 4481 bundles can carry up to MAX_BUNDLE_SIGNATURES
  // cross-signing signatures. An over-cap bundle is rejected BEFORE
  // per-signature verification work runs (defends against DoS and
  // against producers abusing the cross-signing slot for non-signature
  // data). The signatures_checked[] array stays empty for the over-cap
  // bundle.
  const rawSigs = bundle["signatures"];
  const signaturesCount = Array.isArray(rawSigs) ? rawSigs.length : 0;
  output.signatures_present = signaturesCount;
  if (signaturesCount > MAX_BUNDLE_SIGNATURES) {
    _appendError(output, {
      reason: "signature_count_exceeded",
      message:
        `bundle carries ${signaturesCount} signatures; the maximum ` +
        `supported is ${MAX_BUNDLE_SIGNATURES} per spec section L.5 ` +
        "line 4481 cross-signing cap",
      code: RELAY_EVID_SIGCOUNT_EXCEEDED,
    });
    // Refuse signature verification on the over-cap bundle. Recover the
    // bundle_digest_sha256 for diagnostic continuity but do NOT populate
    // signatures_checked[] -- per VAL-V2M08-041 the verifier does not
    // attempt verification on an over-cap bundle.
    try {
      output.bundle_digest_sha256 = bundleDigest(bundle, { stripSignatures: true });
    } catch {
      // Defensive: malformed payload that breaks canonicalisation leaves
      // bundle_digest_sha256 at its safe default "".
    }
    const claims = bundle["claims"];
    output.claims_count = Array.isArray(claims) ? claims.length : 0;
    output.overall = _computeOverall(output);
    return output;
  }

  // --- Non-canonicalisable-bundle screen (keystone invariant #11/#16) ------
  // A supplementary-plane (non-BMP, >= U+10000) object KEY cannot be
  // canonicalised to identical bytes across runtimes (RFC 8785 sorts keys by
  // UTF-16 code unit; Python sorts by code point), so the JCS encoder
  // fails-closed by throwing JCSEncodeError. Screen for such a key BEFORE any
  // canonicalisation runs (_verifyBundle, _claimDigestsInOrder, and
  // _computeBindingDigest all canonicalise the bundle MINUS the top-level
  // 'signatures' field, or subsets of it) and return a structured rejection --
  // preserving validateBundle's never-throws contract and emitting a
  // runtime-identical reason/code/message (the Python twin emits the same).
  // The 'signatures' array is stripped from the screened payload because no
  // canonicalisation path includes it, so a non-BMP key confined to a
  // signature entry is not a canonicalisation hazard.
  const payloadToCanon: Record<string, unknown> = {};
  for (const k of Object.keys(bundle)) {
    if (k !== "signatures") {
      payloadToCanon[k] = bundle[k];
    }
  }
  if (_hasNonBmpKey(payloadToCanon)) {
    _appendError(output, {
      reason: NON_CANONICALIZABLE_BUNDLE_REASON,
      message: NON_CANONICALIZABLE_BUNDLE_MESSAGE,
      code: CANONICAL_NON_BMP_KEY_CODE,
    });
    const claims = bundle["claims"];
    output.claims_count = Array.isArray(claims) ? claims.length : 0;
    output.overall = _computeOverall(output);
    return output;
  }

  // --- JWS + bundle-level verification ------------------------------------
  const jwsResult = _verifyBundle(bundle, jwks);
  output.bundle_digest_sha256 = jwsResult.bundle_digest_sha256;
  output.digest_ok = jwsResult.digest_ok;
  output.structure_ok = jwsResult.structure_ok;
  output.signatures_ok = jwsResult.signatures_ok;
  output.claims_count = jwsResult.claims_count;
  output.signatures_checked = jwsResult.signature_checks.map((sc) => ({
    kid: sc.kid,
    alg: sc.alg,
    ok: sc.ok,
    reason: sc.reason,
    code: sc.code,
  }));
  if (!jwsResult.signatures_ok) {
    const firstFail = jwsResult.signature_checks.find((sc) => !sc.ok);
    if (firstFail) {
      _appendError(output, {
        reason: "signature_verification_failed",
        message: firstFail.reason || "signature did not verify under JWK",
        code: firstFail.code || RELAY_EVID_014,
      });
    }
  }

  // --- Per-claim artifact-digest check (VAL-W10-022) ----------------------
  if (jwsResult.structure_ok && opts.artifact_resolver) {
    const claims = bundle["claims"];
    if (Array.isArray(claims)) {
      for (let ci = 0; ci < claims.length; ci++) {
        const claim = claims[ci];
        if (claim === null || typeof claim !== "object" || Array.isArray(claim)) continue;
        const refs = (claim as Record<string, unknown>)["evidence_refs"];
        if (!Array.isArray(refs)) continue;
        for (let ri = 0; ri < refs.length; ri++) {
          const ref = refs[ri];
          if (ref === null || typeof ref !== "object" || Array.isArray(ref)) continue;
          const r = ref as Record<string, unknown>;
          const artifactId = r["artifact_id"];
          const declaredDigest = r["digest"];
          if (typeof artifactId !== "string") continue;
          if (typeof declaredDigest !== "string") continue;
          // VAL-V2M08-015..017: path-traversal hardening MUST run BEFORE
          // the caller-supplied resolver is invoked. A malicious
          // artifact_id ("../../etc/passwd", "/etc/passwd", NFD-encoded
          // name, etc.) reaching the resolver unfiltered would let an
          // evidence bundle drive filesystem reads outside the session
          // sandbox. Parity with Python bundle_validator.py:574-589.
          const pathViolation = checkArtifactPath(artifactId);
          if (pathViolation !== null) {
            _appendError(output, {
              reason: "path_violation",
              message:
                `claim[${ci}].evidence_refs[${ri}] artifact_id ` +
                `${pyRepr(artifactId)} rejected by path screen ` +
                `(${pathViolation.path_violation})`,
              code: pathViolation.code,
              extra: {
                path_violation: pathViolation.path_violation,
                offending_path: pathViolation.offending_path,
              },
            });
            output.digest_ok = false;
            continue;
          }
          let artifactBytes: Uint8Array | null = null;
          try {
            artifactBytes = opts.artifact_resolver(artifactId);
          } catch {
            artifactBytes = null;
          }
          if (artifactBytes === null) {
            _appendError(output, {
              reason: "artifact_unavailable",
              message:
                `claim[${ci}].evidence_refs[${ri}] artifact ` +
                `${pyRepr(artifactId)} could not be resolved`,
              code: RELAY_EVID_014,
            });
            output.digest_ok = false;
            continue;
          }
          const recomputed = createHash("sha256").update(Buffer.from(artifactBytes)).digest("hex");
          if (recomputed !== declaredDigest) {
            _appendError(output, {
              reason: "artifact_digest_mismatch",
              message:
                `claim[${ci}].evidence_refs[${ri}] artifact ` +
                `${pyRepr(artifactId)} digest mismatch: declared=` +
                `${pyRepr(declaredDigest)} recomputed=${pyRepr(recomputed)}`,
              code: RELAY_EVID_014,
            });
            output.digest_ok = false;
          }
        }
      }
    }
  }

  // --- Per-claim namespace + manifest-binding checks ----------------------
  // Two spec K rules share a single per-claim pass, mirroring Python
  // `validate_bundle` (bundle_validator.py:728-798) so cross-runtime error
  // ordering and scope match exactly:
  //
  //   (a) Namespace closed-set check (VAL-V3M1-022). Per spec K lines
  //       4421-4423 each claim's `namespaces` field is restricted to the
  //       closed set {x-relay}. A claim carrying any other top-level key
  //       (e.g. `x-attacker`) is rejected with reason
  //       `claim_namespace_unknown`, code RELAY-EVID-NAMESPACE-UNKNOWN.
  //       Empty / absent `namespaces` is accepted (the field is optional).
  //       This check runs for EVERY claim regardless of whether a manifest
  //       is declared, matching Python (the namespace block at
  //       bundle_validator.py:749-767 runs before the
  //       `if manifest_field is None: continue` skip at line 770).
  //
  //   (b) Evidence-ref manifest binding (VAL-V3M1-019). Per spec K rule line
  //       4428 ("A claim cannot reference an artifact whose digest is not
  //       present in the bundle's manifest.") every `evidence_refs[].digest`
  //       must resolve to an entry in the bundle's top-level `manifest`
  //       list. When the bundle declares no `manifest` the binding check is
  //       SKIPPED (preserves back-compat for legacy bundles that predate
  //       this rule); when the manifest is declared, any claim digest absent
  //       from it triggers structured error
  //       `evidence_ref_artifact_missing_from_manifest` (code RELAY-EVID-014).
  //       The manifest may be a list of dicts each carrying a `digest` key
  //       (preferred per spec K example at line 4393-4399) OR a list of bare
  //       digest strings (defensive accept). Heterogeneous entries are
  //       tolerated -- unparseable entries simply are not contributed to the
  //       allowed set. The set is computed once outside the per-claim loop to
  //       keep the check O(N + M) instead of O(N * M).
  //
  // Runs under jwsResult.structure_ok; placed between the artifact-digest
  // check and the Merkle check to preserve cross-runtime error ordering.
  if (jwsResult.structure_ok) {
    const manifestField = bundle["manifest"];
    let manifestDigests: Set<string> | null = null;
    if (Array.isArray(manifestField)) {
      manifestDigests = new Set<string>();
      for (const entry of manifestField) {
        if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
          const entryDigest = (entry as Record<string, unknown>)["digest"];
          if (typeof entryDigest === "string" && entryDigest.length > 0) {
            manifestDigests.add(entryDigest);
          }
        } else if (typeof entry === "string" && entry.length > 0) {
          manifestDigests.add(entry);
        }
      }
    }

    const claims = bundle["claims"];
    if (Array.isArray(claims)) {
      for (let ci = 0; ci < claims.length; ci++) {
        const claim = claims[ci];
        if (claim === null || typeof claim !== "object" || Array.isArray(claim)) continue;

        // --- (a) namespace closed-set check (runs for every claim) ---
        const ns = (claim as Record<string, unknown>)["namespaces"];
        if (ns !== null && typeof ns === "object" && !Array.isArray(ns)) {
          const unknownKeys = Object.keys(ns as Record<string, unknown>)
            .filter((k) => typeof k !== "string" || !ALLOWED_NAMESPACE_KEYS.has(k))
            .sort();
          if (unknownKeys.length > 0) {
            const allowed = [...ALLOWED_NAMESPACE_KEYS].sort();
            _appendError(output, {
              reason: "claim_namespace_unknown",
              message:
                `claim[${ci}].namespaces contains key(s) outside the closed ` +
                `set ${pyRepr(allowed)}: ${pyRepr(unknownKeys)}`,
              code: RELAY_EVID_NAMESPACE_UNKNOWN,
            });
          }
        }

        // --- (b) manifest binding (only when a manifest is declared) ---
        // manifestDigests === null marks "no manifest declared" -> skip the
        // binding gate for this (and every) claim, mirroring Python's
        // `if manifest_field is None: continue` (bundle_validator.py:770).
        if (manifestDigests === null) continue;
        const refs = (claim as Record<string, unknown>)["evidence_refs"];
        if (!Array.isArray(refs)) continue;
        for (let ri = 0; ri < refs.length; ri++) {
          const ref = refs[ri];
          if (ref === null || typeof ref !== "object" || Array.isArray(ref)) continue;
          const refDigest = (ref as Record<string, unknown>)["digest"];
          // The spec K example shows refs that carry `value` instead of
          // `digest` (e.g. exit_code references). Those refs are not
          // subject to the manifest-binding rule -- only digest-bearing
          // refs are. Mirrors Python bundle_validator.py:779-785.
          if (typeof refDigest !== "string" || refDigest.length === 0) continue;
          if (!manifestDigests.has(refDigest)) {
            _appendError(output, {
              reason: "evidence_ref_artifact_missing_from_manifest",
              message:
                `claim[${ci}].evidence_refs[${ri}] digest ` +
                `${pyRepr(refDigest)} is not present in the ` +
                `bundle's manifest (spec K line 4428); manifest contains ` +
                `${manifestDigests.size} digest(s)`,
              code: RELAY_EVID_014,
            });
          }
        }
      }
    }
  }

  // --- Merkle root check (VAL-W10-024) ------------------------------------
  const declaredMerkle = bundle["merkle_root_hex"];
  if (typeof declaredMerkle === "string" && declaredMerkle.length > 0) {
    const recomputedMerkle = computeMerkleRoot(_claimDigestsInOrder(bundle));
    if (recomputedMerkle === declaredMerkle) {
      output.merkle_check = "ok";
    } else {
      output.merkle_check = "mismatch";
      _appendError(output, {
        reason: "merkle_root_mismatch",
        message:
          `declared merkle_root_hex ${pyRepr(declaredMerkle)} does not ` +
          `match recomputed root ${pyRepr(recomputedMerkle)}`,
        code: RELAY_EVID_040,
      });
    }
  } else {
    output.merkle_check = "absent";
  }

  // --- TSA timestamp + binding digest -------------------------------------
  const tsaTokenRaw = bundle["tsa_token"];
  const rawDecidedAt = bundle["decided_at"];
  const decidedAt = typeof rawDecidedAt === "string" ? rawDecidedAt : "";
  const bindingDigestHex = _computeBindingDigest(bundle);
  if (decidedAt.length > 0) {
    // VAL-PARITY-004: load the package-bundled TSA chain so CMS SignerInfo
    // signatures can be cryptographically verified against the OSS placeholder
    // root, mirroring Python bundle_validator.py:844-856. If the package asset
    // is missing/unparseable we tolerate the error so the rest of the
    // validator still emits a structured outcome -- the empty trust-roots set
    // then yields outcome="invalid" (reason="tsa_cert_chain_unknown_root").
    let bundledChainCerts: X509Certificate[] | null = null;
    if (!opts.tsa_skip_bundled_chain) {
      try {
        const { raw } = loadBundledTsaChain();
        bundledChainCerts = loadTsaChainPemBytes(raw);
      } catch {
        bundledChainCerts = null;
      }
    }
    const tsaResult = validateTsaToken({
      token:
        tsaTokenRaw !== null && typeof tsaTokenRaw === "object" && !Array.isArray(tsaTokenRaw)
          ? (tsaTokenRaw as TsaToken)
          : null,
      bundleDigestHex: bindingDigestHex,
      decidedAt,
      chainCerts: bundledChainCerts,
      extraTrustedRootsPem: opts.tsa_extra_trusted_roots_pem ?? null,
    });
    output.tsa_check = tsaResult.outcome;
    if (tsaResult.outcome === "missing") {
      _appendError(output, {
        reason: "tsa_missing",
        message: tsaResult.reason || "TSA timestamp absent",
        code: RELAY_EVID_031,
      });
    } else if (tsaResult.outcome === "skew") {
      _appendError(output, {
        reason: "tsa_skew",
        message: tsaResult.reason,
        code: RELAY_EVID_038,
      });
    } else if (tsaResult.outcome === "invalid") {
      _appendError(output, {
        reason: "tsa_invalid",
        message: tsaResult.reason,
        code: RELAY_EVID_031,
      });
    }
  } else {
    output.tsa_check = "missing";
    const presentFields = Object.keys(bundle).sort();
    _appendError(output, {
      reason: "decided_at_missing",
      message:
        "bundle is missing the canonical 'decided_at' TSA-binding " +
        "anchor (spec section AB); the validator refuses to fall " +
        "back to 'generated_at' or any sibling timestamp because " +
        "the TSA gen_time skew check binds to decided_at " +
        `specifically. bundle fields present: ${pyRepr(presentFields)}`,
      code: RELAY_EVID_DECIDED_AT_MISSING,
    });
    _appendError(output, {
      reason: "tsa_missing",
      message: "bundle missing decided_at; cannot evaluate TSA window",
      code: RELAY_EVID_031,
    });
  }

  // --- Transparency-log inclusion -----------------------------------------
  const logProof = bundle["log_inclusion_proof"];
  const witnessJwks = opts.witness_jwks ?? jwks;
  const logResult = verifyLogInclusion({
    proof:
      logProof !== null && typeof logProof === "object" && !Array.isArray(logProof)
        ? (logProof as Record<string, unknown>)
        : null,
    bundleDigestHex: bindingDigestHex,
    witnessJwks,
  });
  output.log_inclusion = logResult.outcome;
  if (logResult.outcome === "absent") {
    _appendWarning(output, {
      reason: "log_inclusion_absent",
      message:
        "no transparency-log inclusion proof attached; verification " +
        "proceeds but auditors should treat absence as a red flag",
    });
  } else if (logResult.outcome === "witness_mismatch") {
    if (opts.strict_log) {
      _appendError(output, {
        reason: "log_witness_mismatch",
        message: logResult.reason,
      });
    } else {
      _appendWarning(output, {
        reason: "log_witness_mismatch",
        message: logResult.reason,
      });
    }
  }

  // --- Signer key lifecycle (VAL-W10-031..034) ----------------------------
  if (jwsResult.signature_checks.length > 0) {
    // Primary signer: first OK, else fall back to slot 0 with telemetry.
    let primarySig: SignatureCheck | undefined = jwsResult.signature_checks.find(
      (sc) => sc.ok,
    );
    if (primarySig === undefined) {
      primarySig = jwsResult.signature_checks[0];
      if (primarySig !== undefined) {
        const details = (output.details ??= {});
        details["primary_signer_fallback"] = {
          reason: "no_signature_verified",
          note:
            "no signature in the bundle has ok=true; lifecycle " +
            "resolution falls back to signature_checks[0]",
          selected_kid: primarySig.kid,
        };
      }
    }
    if (primarySig !== undefined) {
      const primaryKid = primarySig.kid;
      const signerJwk = _selectJwk(jwks, primaryKid) as JWK | null;
      const signedAtRaw = bundle["signed_at"];
      const signedAt =
        typeof signedAtRaw === "string" && signedAtRaw.length > 0 ? signedAtRaw : decidedAt;
      if (signerJwk !== null && typeof signedAt === "string" && signedAt.length > 0) {
        const lifeResult: KeyLifecycleResult = checkSigningKeyLifecycle({
          jwk: signerJwk as unknown as Record<string, unknown>,
          bundleSignedAt: signedAt,
          auditorNow: opts.auditor_now,
        });
        output.signer_key_revoked = lifeResult.signer_key_revoked;
        output.signer_key_revoked_at = lifeResult.signer_key_revoked_at
          ? lifeResult.signer_key_revoked_at
          : null;
        if (lifeResult.outcome === "expired") {
          _appendError(output, {
            reason: "signer_key_expired",
            message: lifeResult.reason,
            code: lifeResult.code || RELAY_EVID_041,
          });
        } else if (lifeResult.outcome === "revoked") {
          _appendError(output, {
            reason: "signer_key_revoked_at_or_before_sign_time",
            message: lifeResult.reason,
            code: lifeResult.code || RELAY_EVID_042,
          });
        } else if (lifeResult.outcome === "premature") {
          _appendError(output, {
            reason: "signer_key_premature",
            message: lifeResult.reason,
            code: lifeResult.code || RELAY_EVID_041,
          });
        } else if (lifeResult.signer_key_revoked) {
          _appendWarning(output, {
            reason: "signer_key_revoked_after_sign_time",
            message:
              `key ${pyRepr(primaryKid)} was revoked at ` +
              `${lifeResult.signer_key_revoked_at}; bundle signed before ` +
              `revocation -- auditor decides acceptance`,
          });
        }
      }
    }
  }

  // --- trust_anchor / local_dev surfacing (VAL-W10-035 / 041) -------------
  const defaultAnchor = opts.default_trust_anchor ?? DEFAULT_JWKS_URL;
  if (output.trust_anchor === TRUST_ANCHOR_LOCAL_DEV) {
    const verifierUsingDefault =
      ["live", "cache", "bundled", ""].includes(output.trust_anchor_source) &&
      defaultAnchor.endsWith("relay.epochly.com/.well-known/jwks.json");
    if (verifierUsingDefault) {
      if (opts.strict_trust_anchor) {
        _appendError(output, {
          reason: WARN_LOCAL_DEV_UNSUPPORTED,
          message:
            "bundle trust_anchor='local_dev' is not supported for audit " +
            "under the default trust anchor; --strict-trust-anchor in effect",
        });
      } else {
        _appendWarning(output, {
          reason: WARN_LOCAL_DEV_UNSUPPORTED,
          message:
            "bundle trust_anchor='local_dev' is not supported for audit " +
            "under the default trust anchor; verification proceeds for " +
            "non-audit purposes",
        });
      }
    }
  }

  // --- Subject resolution (VAL-W10-037 / 038) -----------------------------
  const subjectIdRaw = bundle["subject_id"];
  const subjectDigestHexRaw = bundle["subject_digest_hex"];
  const subResult = resolveSubject({
    subjectId: typeof subjectIdRaw === "string" ? subjectIdRaw : null,
    subjectDigestHex: typeof subjectDigestHexRaw === "string" ? subjectDigestHexRaw : null,
    subjectStore: opts.subject_store ?? null,
  });
  output.subject_resolution = subResult.resolution;
  if (!subResult.original_digest_preserved) {
    _appendWarning(output, {
      reason: "subject_digest_drift",
      message: subResult.reason,
    });
  }

  // --- Overall verdict ----------------------------------------------------
  output.overall = _computeOverall(output);
  return output;
}

function _computeOverall(output: VerifierOutputEnvelope): "pass" | "fail" {
  if (output.errors.length > 0) return "fail";
  if (!output.structure_ok) return "fail";
  if (!output.digest_ok) return "fail";
  if (!output.signatures_ok) return "fail";
  if (output.merkle_check === "mismatch") return "fail";
  if (
    output.tsa_check === "missing" ||
    output.tsa_check === "invalid" ||
    output.tsa_check === "skew"
  ) {
    return "fail";
  }
  return "pass";
}

/**
 * Convenience: archive-bomb pre-flight + validate. Mirrors
 * `validate_bundle_with_archive_check` in Python.
 */
export function validateBundleWithArchiveCheck(args: {
  bundle: Record<string, unknown>;
  jwks: JWKS | Record<string, unknown>;
  entryCount: number;
  uncompressedSizeBytes: number;
  bundle_path?: string;
  trust_anchor_source?: string;
  options?: ValidateBundleOptions;
}): VerifierOutputEnvelope {
  const { ok, reason } = checkArchiveBombLimits({
    entryCount: args.entryCount,
    uncompressedSizeBytes: args.uncompressedSizeBytes,
  });
  if (!ok) {
    const output = _newOutput();
    output.bundle_path = args.bundle_path ?? "";
    output.trust_anchor_source = args.trust_anchor_source ?? "";
    _appendError(output, {
      reason: "archive_bomb_limit_exceeded",
      message: reason,
      code: RELAY_EVID_024,
    });
    output.overall = "fail";
    return output;
  }
  return validateBundle({
    bundle: args.bundle,
    jwks: args.jwks,
    bundle_path: args.bundle_path,
    trust_anchor_source: args.trust_anchor_source,
    options: args.options,
  });
}

// Side-effects: keep CLOCK_SKEW_TOLERANCE_SECONDS in the re-export
// surface so consumers do not need to import from tsa.ts directly when
// using the validator alone.
export { CLOCK_SKEW_TOLERANCE_SECONDS };
