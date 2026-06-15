"""Generated Pydantic v2 models for the Relay control-plane envelopes.

Source of truth: ``packages/schemas/raw/envelopes.yaml``.

This module is hand-authored to match the canonical YAML; the W1.5 codegen
pipeline (datamodel-code-generator) will replace the hand-authoring with
generator output, and the W1.5 drift check (VAL-W1-035) will enforce sync.

Per CLAUDE.md keystone invariant #1, the canonical Literal pins on
``written_by`` and ``decided_by`` enforce the control-plane-writes-the-result
rule at the wire-format layer in addition to SQL CHECK constraints.

Per CLAUDE.md keystone invariant #10, every canonical envelope carries a
``schema_version`` field pinned to a string literal. Engines refuse unknown
versions on write.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

Spec anchors:
    A.1  run_results         (RunResult)
    A.2  gate_decisions      (GateDecision)
    A.3  gate_decision_drafts (GateDecisionDraft)
    A.4  gate_rounds         (GateRound)
    A.9  manifest_versions   (ManifestVersion)
    A.11 event_log_entries   (EventLogEntry)
    A.12 idempotency_records (IdempotencyRecord)
    B.2  idempotency ULID grammar
    B.6  ULID alphabet ^[0-9A-HJKMNP-TV-Z]{26}$
    B.7  schema versioning rules
    C.1  per-scope-kind state sets
    C.4  scope_state.epoch aggregate version
    C.5  three-anchor handoff (Actor identity registry)
    W    scope_state aggregate version table
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictBool,
    field_validator,
    model_validator,
)
from pydantic.config import ExtraValues

# -----------------------------------------------------------------------------
# Shared type aliases
# -----------------------------------------------------------------------------
#
# The canonical Relay sha256 wire format is ``sha256-<64 lowercase hex>``
# (hyphen separator, lowercase hex, exactly 64 hex chars). The colon form
# (``sha256:<hex>``) and the bare-hex form are both rejected (VAL-W1-009).

SHA256_HASH_PATTERN = r"^sha256-[0-9a-f]{64}$"

Sha256Hash = Annotated[str, Field(pattern=SHA256_HASH_PATTERN)]
"""Canonical Relay sha256 wire form: ``sha256-`` + 64 lowercase hex chars."""

PositiveRound = Annotated[int, Field(ge=1)]
"""Round counter, >= 1 (spec A.2 ``check (round >= 1)``)."""

NonNegativeEpoch = Annotated[int, Field(ge=0)]
"""Decision epoch, >= 0 (spec A.1 / VAL-W1-059)."""

# Crockford-base32 ULID grammar per spec B.6 line 3517: 26 chars from
# the alphabet 0-9 + A-H + JKMNP-TV-Z (I, L, O, U excluded). Lowercase
# letters are NOT permitted. Used by IdempotencyRecord.idempotency_key
# (VAL-W1-013).
ULID_PATTERN = r"^[0-9A-HJKMNP-TV-Z]{26}$"

Ulid = Annotated[str, Field(pattern=ULID_PATTERN)]
"""Canonical Crockford-base32 ULID, exactly 26 uppercase chars."""

# RFC 3339 offset-marker regex: matches the trailing 'Z'/'z' or '+/-HH:MM' on a
# string. Used by EventLogEntry.occurred_at / capture_clock (VAL-W1-017) to
# reject naive wire-format inputs before Pydantic's datetime coercion silently
# drops the distinction. The 'Z' is case-insensitive ([Zz]) to match the shared
# RFC3339_DATETIME_PATTERN (which accepts [Zz]); an uppercase-only 'Z' here made
# Python reject a lowercase '...z' that the TS checkRfc3339WithOffset accepts ->
# an opposite-verdict Py<->TS divergence on occurred_at/capture_clock.
_RFC3339_OFFSET_RE = re.compile(r"([Zz]|[+-]\d{2}:\d{2})$")

# Minimum length of a canonical RFC 3339 date-time (YYYY-MM-DDTHH:MM:SSZ == 20).
_RFC3339_MIN_LEN = 20

# Strict RFC 3339 date-time grammar (MED #8). The TS ``isRfc3339Datetime`` mirror
# (packages/schemas/typescript/src/envelopes.ts) MUST define the SAME language so
# Python and TypeScript readers agree accept/reject for identical wire bytes (a
# P0 keystone). Earlier the two sides deferred grammar to two DIFFERENT permissive
# parsers (Pydantic-RFC3339 vs ``Date.parse``) whose acceptance sets diverged in
# BOTH directions: ``Date.parse`` accepts RFC-2822-ish forms
# ('Mon May 12 2025 00:00:00', 'Wed, 12 May 2025 00:00:00 GMT') and an
# out-of-range hour ('...T24:00:00Z') that Pydantic rejects, while Pydantic
# accepted a colon-less offset ('+0200') strict RFC 3339 forbids. This regex pins
# ONE grammar on both sides and rejects every such permissive extra.
#
# Grammar (RFC 3339 section 5.6 date-time):
#   full-date  = YYYY '-' (01..12) '-' (01..31)
#   separator  = 'T' | 't' | ' '   (RFC 3339 allows lower-case 'T' and a space)
#   partial-time = (00..23) ':' (00..59) ':' (00..60)  (60 = leap second)
#   time-secfrac = optional '.' DIGIT+
#   time-offset  = 'Z' | 'z' | ('+'|'-') (00..23) ':' (00..59)  (colon REQUIRED)
#
# Anchored with ``\A`` / ``\Z`` (NOT ``^`` / ``$``) because Python's ``$`` matches
# before a trailing newline whereas a non-multiline JS ``$`` does not; ``\A``/``\Z``
# match the JS ``^``/``$`` exactly so a value such as "...Z\n" is rejected on BOTH
# sides byte-for-byte. The two regex source strings define the identical language.
RFC3339_DATETIME_PATTERN = (
    r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"[Tt ]([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d+)?"
    r"([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)"
)
_RFC3339_DATETIME_RE = re.compile(r"\A" + RFC3339_DATETIME_PATTERN + r"\Z")


def _require_rfc3339_string(value: Any) -> Any:
    """Enforce the strict shared RFC 3339 grammar for Py<->TS verdict parity.

    The TS ``isRfc3339Datetime`` (packages/schemas/typescript/src/envelopes.ts)
    requires ``typeof value === "string"`` matching the SAME
    ``RFC3339_DATETIME_PATTERN`` regex; an integer Unix epoch (or float/bool) is
    REJECTED. Pydantic's default datetime coercion instead silently accepts an
    int/float epoch (re-hunt #7), and deferring the remaining grammar to
    Pydantic's RFC3339 parser still diverged from the TS ``Date.parse`` in both
    directions (MED #8). This before-validator enforces the string contract AND
    the strict RFC 3339 grammar on WIRE input so both readers give the same
    accept/reject verdict for the same bytes, while letting an actual
    ``datetime`` object (in-process model construction, which has no wire-string
    equivalent in TS) pass through untouched.
    """
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        if len(value) < _RFC3339_MIN_LEN:
            raise ValueError(
                "must be an RFC 3339 date-time string (length >= 20); "
                f"observed a {len(value)}-char string"
            )
        if _RFC3339_DATETIME_RE.match(value) is None:
            raise ValueError(
                "must be a strict RFC 3339 date-time string "
                "(YYYY-MM-DDThh:mm:ss[.fff](Z|+/-hh:mm)); permissive "
                "Date.parse forms (RFC 2822, hour 24, colon-less offset) are "
                f"rejected for Py<->TS verdict parity per VAL-W1-017 "
                f"(observed={value!r})"
            )
        return value
    # int/float epoch, bool, or any other non-string wire value: reject to
    # match the TS reader (which requires a string).
    raise ValueError(
        "must be an RFC 3339 date-time string, not a "
        f"{type(value).__name__} (an integer/float Unix epoch is rejected for "
        "Py<->TS parse parity per VAL-W1-017)"
    )


# Strict RFC 3339 date-time field type: enforces the TS wire contract (string,
# length >= 20, RFC-3339-parseable) so Python and TypeScript readers agree on
# accept/reject for the same wire bytes. Use in place of a bare ``datetime`` on
# every canonical envelope field. Nullable fields use ``Rfc3339Datetime | None``.
Rfc3339Datetime = Annotated[datetime, BeforeValidator(_require_rfc3339_string)]


# -----------------------------------------------------------------------------
# W1.6 unknown enum value reader policy (VAL-W1-040; RELAY-SCHEMA-001)
# -----------------------------------------------------------------------------
#
# Locked in packages/schemas/raw/enum-forward-compat.md (Option A: strict
# reject). When a canonical envelope carries an enum value outside the closed
# set declared by the canonical YAML, the Py reader raises
# ``RelayUnknownEnumValueError`` carrying the field, observed value, the
# allowed set, the envelope name, and the canonical Relay error code
# ``RELAY-SCHEMA-001``. The TS reader mirrors this behavior at
# packages/schemas/typescript/src/envelopes.ts.


class RelayUnknownEnumValueError(ValueError):
    """Raised when a reader observes an enum value outside the canonical set.

    Locked policy: packages/schemas/raw/enum-forward-compat.md (Option A).
    Spec anchor: CLAUDE.md keystone invariant #10 (schema versioning).
    Contract: VAL-W1-040.
    Relay error code: ``RELAY-SCHEMA-001`` (registered in
    packages/schemas/raw/relay-error-codes.yaml).

    Attributes:
        field: Dotted path to the offending field (e.g. ``"status"``).
        observed_value: The unknown value verbatim.
        allowed_values: Sorted tuple of the canonical closed set.
        envelope_name: The envelope class name (e.g. ``"RunResult"``).
        relay_error_code: Always ``"RELAY-SCHEMA-001"``.
    """

    relay_error_code: str = "RELAY-SCHEMA-001"

    def __init__(
        self,
        envelope_name: str,
        field: str,
        observed_value: str,
        allowed_values: tuple[str, ...],
    ) -> None:
        super().__init__(
            f"unknown enum value for {envelope_name}.{field}: "
            f"observed={observed_value!r} allowed={sorted(allowed_values)!r} "
            f"(VAL-W1-040, {self.relay_error_code})"
        )
        self.envelope_name = envelope_name
        self.field = field
        self.observed_value = observed_value
        self.allowed_values = tuple(sorted(allowed_values))


# -----------------------------------------------------------------------------
# W1.6 generic JCS-compatible canonical bytes (VAL-W1-038..044)
# -----------------------------------------------------------------------------
#
# Cross-language golden corpus canonicalizer. RFC 8785 (JCS) canonicalization
# of the JSON value subset that Relay envelopes use:
#
#   - sort object keys lexicographically (recursively)
#   - compact separators (no whitespace)
#   - arrays preserve order
#   - strings emitted verbatim (incl. RFC 3339 timestamps with offset
#     preserved byte-for-byte per packages/schemas/raw/timestamp-canonicalization.md)
#   - integers emitted as int; decimals encoded as JSON STRINGS (NOT as
#     float) so precision survives Py <-> TS round trips per VAL-W1-041
#   - null preserved as null (used by VAL-W1-038 nullable-field corpus)
#   - missing optional keys stay missing (VAL-W1-039)
#
# The TS mirror is ``canonicalJsonStringify`` at
# packages/schemas/typescript/src/envelopes.ts; both languages MUST produce
# byte-identical UTF-8 output for the same input value.


# Largest IEEE-754 double that is an exact integer (JS Number.MAX_SAFE_INTEGER).
_JS_MAX_SAFE_INTEGER = 2**53 - 1


def _es6_number_to_string_positive(n: float) -> str:
    """ECMA-262 7.1.12.1 Number::toString for a strictly POSITIVE finite double.

    Mirrors JS ``String(n)`` byte-for-byte (ported from
    ``relay_verifier.canonical`` -- the schemas package cannot depend on the
    verifier, so the proven algorithm is duplicated). Python's ``repr(float)``
    and ``json.dumps`` choose different exponent thresholds / zero-padding /
    trailing ``.0`` than ECMA-262, so a bare float serialized via ``json.dumps``
    diverged from the TS ``canonicalJsonStringify`` which uses ``String(value)``
    (re-hunt schemas-03). Caller handles NaN/Inf/zero/negative dispatch.
    """
    s = repr(n)
    if "e" in s:
        mantissa, exp_str = s.split("e")
        exp = int(exp_str)
    else:
        mantissa, exp = s, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    raw_digits = int_part + frac_part
    stripped_lead = raw_digits.lstrip("0")
    leading_zero_count = len(raw_digits) - len(stripped_lead)
    if not stripped_lead:
        return "0"
    stripped = stripped_lead.rstrip("0")
    n_dec = len(int_part) - leading_zero_count + exp
    k = len(stripped)
    if k <= n_dec <= 21:
        return stripped + ("0" * (n_dec - k))
    if 0 < n_dec <= 21:
        return stripped[:n_dec] + "." + stripped[n_dec:]
    if -6 < n_dec <= 0:
        return "0." + ("0" * (-n_dec)) + stripped
    sign = "+" if n_dec - 1 >= 0 else "-"
    abs_exp = str(abs(n_dec - 1))
    if k == 1:
        return stripped + "e" + sign + abs_exp
    return stripped[0] + "." + stripped[1:] + "e" + sign + abs_exp


def _canonical_encode(value: Any) -> str:
    """Recursive RFC-8785 encoder matching the TS ``canonicalJsonStringify``."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # A JSON integer beyond JS's safe-integer range cannot be represented
        # exactly as a double, so TS ``String(parsedNumber)`` would emit a
        # ROUNDED value while Python ``str(int)`` is exact -- irreconcilable.
        # Reject on BOTH sides (the TS guard throws) so the canonical form fails
        # CLOSED rather than diverging (re-hunt schemas-03). Such values must be
        # string-encoded by the caller (see the docstring contract).
        if not (-_JS_MAX_SAFE_INTEGER <= value <= _JS_MAX_SAFE_INTEGER):
            raise ValueError(
                f"integer {value} is outside the JS safe-integer range "
                f"[-(2**53-1), 2**53-1]; canonical payloads MUST string-encode "
                "such values for Py<->TS byte parity"
            )
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError(
                f"canonical JSON cannot encode non-finite number: {value!r}"
            )
        # JS has a single number type, so a JSON exponential like ``1e16`` parses
        # to an INTEGER-valued number that ``Number.isInteger`` accepts but
        # ``Number.isSafeInteger`` rejects -> the TS guard throws. Python parses
        # the same literal to a FLOAT, which would otherwise slip through here and
        # be ECMA-262-formatted (accepted) -> a Py-accepts/TS-rejects divergence.
        # Reject an integer-valued float outside the safe-integer range so BOTH
        # runtimes fail closed on it (re-hunt schemas-03).
        if value.is_integer() and abs(value) > _JS_MAX_SAFE_INTEGER:
            raise ValueError(
                f"float {value!r} has an integer value outside the JS "
                "safe-integer range [-(2**53-1), 2**53-1]; canonical payloads "
                "MUST string-encode such values for Py<->TS byte parity"
            )
        if value == 0.0:
            return "0"  # ECMA-262: both 0.0 and -0.0 -> "0"
        if value < 0:
            return "-" + _es6_number_to_string_positive(-value)
        return _es6_number_to_string_positive(value)
    if isinstance(value, str):
        # Reuse json.dumps' string escaping: byte-identical to the prior
        # implementation AND to TS JSON.stringify for the Relay value subset.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 section 3.2.3: object keys ordered by their UTF-16 code-unit
        # sequence (NOT Unicode code point). For BMP keys the orderings coincide;
        # they diverge only for SMP (>= U+10000) keys, where Python's default
        # str (code-point) sort disagreed with the TS Object.keys().sort()
        # (UTF-16 code-unit) -- a non-BMP-key byte divergence (re-hunt
        # schemas-04). ``encode("utf-16-be")`` orders by code unit.
        items = sorted(
            ((str(k), v) for k, v in value.items()),
            key=lambda kv: kv[0].encode("utf-16-be"),
        )
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + _canonical_encode(v)
                for k, v in items
            )
            + "}"
        )
    raise TypeError(
        f"canonical JSON: unsupported type {type(value).__name__}"
    )


def canonical_bytes(value: Any) -> bytes:
    """Emit RFC-8785 canonical JSON bytes for a Python value.

    Recurses into nested dicts (keys ordered by UTF-16 code unit, RFC 8785
    3.2.3) and lists (preserve order). Numbers are encoded per ECMA-262
    Number::toString so floats match the TS ``canonicalJsonStringify``
    (``String(value)``) byte-for-byte; non-finite floats and integers outside
    the JS safe-integer range are REJECTED fail-closed. Decimals MUST be passed
    in as strings (the caller encodes ``Decimal`` -> string before invoking this
    function so precision is bit-exact across Py and TS).

    Mirrors ``canonicalJsonStringify`` in envelopes.ts byte-for-byte for the
    value subset used by Relay envelopes.
    """
    return _canonical_encode(value).encode("utf-8")


# -----------------------------------------------------------------------------
# Base configuration
# -----------------------------------------------------------------------------


class _RelayEnvelope(BaseModel):
    """Base for every canonical control-plane envelope.

    ``extra="forbid"`` rejects unknown fields at construction time so a
    typo in client code surfaces as a ValidationError rather than silently
    dropping data. ``frozen=False`` is intentional: the SQL layer enforces
    immutability of canonical rows post-insert; the wire-format model is
    used both for outbound serialization and for inbound parsing where
    field-by-field assignment is sometimes needed during deserialization.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=False,
        validate_assignment=False,
    )


# -----------------------------------------------------------------------------
# RunResult (spec A.1)
# -----------------------------------------------------------------------------


class RunResult(_RelayEnvelope):
    """Canonical run outcome. Written exclusively by the control plane.

    VAL-W1-001: schema_version pinned to ``relay.run_result.v1``.
    VAL-W1-002: written_by pinned to ``Literal["control_plane"]``.
    VAL-W1-003: status closed enum {accepted, remediate_required, blocked, invalid};
                accepted requires non-null evidence_bundle_id.
    """

    schema_version: Literal["relay.run_result.v1"]
    run_result_id: UUID
    run_id: UUID
    project_id: UUID
    written_by: Literal["control_plane"]
    status: Literal["accepted", "remediate_required", "blocked", "invalid"]
    primary_failure_class: str | None = None
    error_priority_rule: str = "first_p0_then_highest_severity_then_earliest_span"
    evidence_bundle_id: UUID | None = None
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    decided_at: Rfc3339Datetime
    decision_epoch: NonNegativeEpoch = 0
    signature: str
    signature_key_id: str

    @model_validator(mode="after")
    def _check_accepted_requires_evidence(self) -> RunResult:
        # VAL-W1-003: mirrors SQL constraint accepted_requires_evidence.
        # An accepted RunResult MUST bind to an evidence_bundle_id.
        if self.status == "accepted" and self.evidence_bundle_id is None:
            raise ValueError(
                "accepted_requires_evidence: status='accepted' requires "
                "evidence_bundle_id to be non-null (field=evidence_bundle_id)"
            )
        return self


# -----------------------------------------------------------------------------
# GateDecision (spec A.2)
# -----------------------------------------------------------------------------


class GateDecision(_RelayEnvelope):
    """Canonical gate decision. Written exclusively by the gate engine.

    VAL-W1-046: schema_version pinned to ``relay.gate_decision.v1``.
    VAL-W1-004: action closed enum; decided_by pinned to ``Literal["gate_engine"]``.
    VAL-W1-005: round int >= 1; failed_assertion_ids list[str] default [].
    VAL-W1-059: decision_epoch optional int >= 0 default 0; accepted as
                int | None and coerced to 0 on None per the contract evidence.
    """

    schema_version: Literal["relay.gate_decision.v1"]
    gate_decision_id: UUID
    gate_id: UUID
    scope_type: Literal["run", "replay", "eval_run", "release", "domain_pack"]
    scope_id: UUID
    round: PositiveRound
    action: Literal["accept", "remediate", "block", "invalid"]
    strict_pass: bool = False
    failed_assertion_ids: list[str] = Field(default_factory=list)
    unmet_conditions: list[Any] = Field(default_factory=list)
    evidence_bundle_id: UUID
    cascade_on_block: bool = True
    decided_by: Literal["gate_engine"]
    decided_at: Rfc3339Datetime
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    signature: str
    signature_key_id: str
    decision_epoch: NonNegativeEpoch | None = 0

    @model_validator(mode="before")
    @classmethod
    def _coerce_decision_epoch_none_to_zero(cls, data: Any) -> Any:
        # VAL-W1-059: contract says "field accepted as int | None default 0".
        # Coerce None -> 0 BEFORE field validation so the ge=0 constraint is
        # checked against the coerced integer rather than rejected as a type
        # error.
        if isinstance(data, dict) and data.get("decision_epoch") is None:
            data = {**data, "decision_epoch": 0}
        return data


# -----------------------------------------------------------------------------
# GateDecisionDraft (spec A.3)
# -----------------------------------------------------------------------------


class GateDecisionDraft(_RelayEnvelope):
    """Submitter-facing draft. NOT authoritative.

    VAL-W1-047: schema_version pinned to ``relay.gate_decision_draft.v1``.
    VAL-W1-006: two orthogonal state columns (draft_kind, resolution_state)
                with the cross-field rule ``dry_run_never_resolves``.
    VAL-W1-007: dry_run_unsigned drafts forbid a decision link
                (resolved_gate_decision_id MUST be NULL).
    VAL-W1-058: actor_identity_hash uses the canonical sha256-<hex> pattern
                and is logically a FK to actors(identity_hash). The FK
                constraint itself lives in the SQL migration; the wire-format
                model enforces only the value pattern.
    """

    schema_version: Literal["relay.gate_decision_draft.v1"]
    draft_id: UUID
    gate_id: UUID
    scope_type: str
    scope_id: UUID
    round: PositiveRound
    release_sha: str | None = None
    eval_run_ids: list[UUID] = Field(default_factory=list)
    evidence_refs: list[Any] = Field(default_factory=list)
    worker_id: UUID
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    submitted_at: Rfc3339Datetime
    resolved_gate_decision_id: UUID | None = None
    draft_kind: Literal["submitted", "dry_run_unsigned"] = "submitted"
    resolution_state: Literal[
        "pending",
        "resolved",
        "rejected_handoff",
        "expired",
        "cancelled",
        "duplicate_submission",
    ] = "pending"
    cancelled_at: Rfc3339Datetime | None = None
    cancellation_reason: str | None = None

    @model_validator(mode="after")
    def _check_dry_run_constraints(self) -> GateDecisionDraft:
        # VAL-W1-006: dry_run_never_resolves
        if self.draft_kind == "dry_run_unsigned" and self.resolution_state == "resolved":
            raise ValueError(
                "dry_run_never_resolves: a draft_kind='dry_run_unsigned' draft "
                "cannot have resolution_state='resolved' "
                "(fields: draft_kind, resolution_state)"
            )
        # VAL-W1-007: dry_run_no_decision
        if (
            self.draft_kind == "dry_run_unsigned"
            and self.resolved_gate_decision_id is not None
        ):
            raise ValueError(
                "dry_run_no_decision: a draft_kind='dry_run_unsigned' draft "
                "cannot link a resolved_gate_decision_id "
                "(fields: draft_kind, resolved_gate_decision_id)"
            )
        return self


# -----------------------------------------------------------------------------
# GateRound (spec A.4)
# -----------------------------------------------------------------------------


class GateRound(_RelayEnvelope):
    """Per-round audit trail.

    VAL-W1-048: schema_version pinned to ``relay.gate_round.v1``.
    VAL-W1-008: initiated_by closed enum {control_plane, cron, user, remediation};
                restart_predecessor is a nullable UUID self-reference. NULL on
                the first round; the predecessor gate_round_id on every restart.
    """

    schema_version: Literal["relay.gate_round.v1"]
    gate_round_id: UUID
    gate_id: UUID
    scope_type: str
    scope_id: UUID
    round: PositiveRound
    initiated_at: Rfc3339Datetime
    initiated_by: Literal["control_plane", "cron", "user", "remediation"]
    initiation_reason: str | None = None
    gate_decision_id: UUID | None = None
    restart_predecessor: UUID | None = None


# -----------------------------------------------------------------------------
# Actor registry (spec C.5; VAL-W1-058)
# -----------------------------------------------------------------------------


class Actor(_RelayEnvelope):
    """Actor identity registry row.

    FK target for the three-anchor handoff. A handoff whose actor_identity_hash
    is missing from this table OR whose revoked_at is non-null MUST fail with
    HandoffResult(ok=False, reason="ACTOR_NOT_REGISTERED") (contract preamble
    line 912 narrative). The FK enforcement lives in the SQL migration; the
    wire-format model carries the identity_hash pattern and the kind enum.
    """

    identity_hash: Sha256Hash
    kind: Literal["human", "bot", "worker", "reviewer"]
    created_at: Rfc3339Datetime
    revoked_at: Rfc3339Datetime | None = None


# -----------------------------------------------------------------------------
# ManifestVersion (spec A.9; VAL-W1-009, VAL-W1-010)
# -----------------------------------------------------------------------------


class ManifestVersion(_RelayEnvelope):
    """A committed manifest version.

    VAL-W1-009: ``commit_hash`` MUST match the canonical sha256-<hex> wire
                form. The colon form (sha256:<hex>) and bare-hex form are
                rejected.
    VAL-W1-010: ``schema_version`` pinned to ``Literal["relay.manifest.v1"]``.

    The manifest body is modelled as ``dict[str, Any]`` for forward-compat;
    the W1.5 codegen pipeline will replace this with a typed Manifest model
    once the spec F manifest schema is itself generated from this YAML.
    """

    schema_version: Literal["relay.manifest.v1"]
    manifest_version_id: UUID
    manifest_id: UUID
    commit_hash: Sha256Hash
    body: dict[str, Any]
    signed_by: str | None = None
    signature: str | None = None
    signature_key_id: str | None = None
    effective_at: Rfc3339Datetime
    effective_until: Rfc3339Datetime | None = None


# -----------------------------------------------------------------------------
# ScopeState (spec W; VAL-W1-011, VAL-W1-012, VAL-W1-049)
# -----------------------------------------------------------------------------
#
# Implemented as a discriminated union on ``scope_kind`` so each scope kind's
# allowed state set (spec C.1 lines 3632-3636) is statically enforced at the
# wire-format layer. A document with scope_kind=run carrying state=building
# (an evidence_bundle state) MUST fail validation per VAL-W1-011.


class _ScopeStateBase(_RelayEnvelope):
    """Common fields for every scope_state variant.

    VAL-W1-049: ``schema_version`` literal pin.
    VAL-W1-012: ``epoch`` non-negative bigint; -1 rejected by Field(ge=0).
    """

    schema_version: Literal["relay.scope_state.v1"]
    scope_id: UUID
    project_id: UUID
    epoch: NonNegativeEpoch
    created_at: Rfc3339Datetime
    updated_at: Rfc3339Datetime


class RunScopeState(_ScopeStateBase):
    """scope_kind='run' (spec C.1: pending -> captured -> validating -> gated
    -> result_written -> terminal)."""

    scope_kind: Literal["run"]
    state: Literal[
        "pending",
        "captured",
        "validating",
        "gated",
        "result_written",
        "terminal",
    ]


class ReplayCaseScopeState(_ScopeStateBase):
    """scope_kind='replay_case' (spec C.1: proposed -> fixtures_ready ->
    executing -> analyzed -> terminal)."""

    scope_kind: Literal["replay_case"]
    state: Literal[
        "proposed",
        "fixtures_ready",
        "executing",
        "analyzed",
        "terminal",
    ]


class GateRoundScopeState(_ScopeStateBase):
    """scope_kind='gate_round' (spec C.1: open -> draft_received -> evaluating
    -> decision_written -> restarted | terminal)."""

    scope_kind: Literal["gate_round"]
    state: Literal[
        "open",
        "draft_received",
        "evaluating",
        "decision_written",
        "restarted",
        "terminal",
    ]


class EvidenceBundleScopeState(_ScopeStateBase):
    """scope_kind='evidence_bundle' (spec C.1: building -> signed -> published
    | superseded | revoked)."""

    scope_kind: Literal["evidence_bundle"]
    state: Literal[
        "building",
        "signed",
        "published",
        "superseded",
        "revoked",
    ]


class EvalRunScopeState(_ScopeStateBase):
    """scope_kind='eval_run' (spec AM eval lifecycle: pending -> running ->
    scored | terminal). Per spec W lines 5101-5111 the initial state is
    'pending'; transitions are engine-controlled via compare_and_set_state.

    VAL-V2M01-036: variant landed in milestone M01 feature w1.7.
    VAL-V2M01-037: initial-state policy enforced at storage layer.
    """

    scope_kind: Literal["eval_run"]
    state: Literal[
        "pending",
        "running",
        "scored",
        "terminal",
    ]


class ReleaseScopeState(_ScopeStateBase):
    """scope_kind='release' (spec Q.2 release lifecycle: open -> gated ->
    released | rolled_back | terminal). Per spec W lines 5101-5111 the
    initial state is 'open'; transitions are engine-controlled.

    VAL-V2M01-036: variant landed in milestone M01 feature w1.7.
    VAL-V2M01-037: initial-state policy enforced at storage layer.
    """

    scope_kind: Literal["release"]
    state: Literal[
        "open",
        "gated",
        "released",
        "rolled_back",
        "terminal",
    ]


# Discriminated union (Pydantic v2 ``discriminator='scope_kind'``). The union
# is exposed both as a TypeAlias for callers AND as a ``ScopeState`` class
# wrapper that mirrors the Pydantic ``model_validate`` surface used by the
# tests. Per VAL-V2M01-036 the union spans all six scope_kinds enumerated
# by spec W lines 5072-5085.
_ScopeStateUnion = Annotated[
    RunScopeState
    | ReplayCaseScopeState
    | GateRoundScopeState
    | EvidenceBundleScopeState
    | EvalRunScopeState
    | ReleaseScopeState,
    Field(discriminator="scope_kind"),
]


class _ScopeStateAdapterMeta(type):
    """Metaclass exposing ``ScopeState.model_validate(payload)`` that dispatches
    through the discriminated union and returns the concrete variant instance.

    Direct ``Union[...]`` types do not carry a ``.model_validate`` classmethod,
    so we wrap the union in a small adapter so the tests can call
    ``ScopeState.model_validate(payload)`` exactly like every other envelope.
    """

    def model_validate(cls, payload: Any) -> _ScopeStateUnion:
        from pydantic import TypeAdapter

        adapter: TypeAdapter[_ScopeStateUnion] = TypeAdapter(_ScopeStateUnion)
        return adapter.validate_python(payload)


class ScopeState(metaclass=_ScopeStateAdapterMeta):
    """Discriminated-union facade over the four per-scope-kind state models.

    Calling ``ScopeState.model_validate(payload)`` returns the concrete
    variant (RunScopeState / ReplayCaseScopeState / GateRoundScopeState /
    EvidenceBundleScopeState) selected by the ``scope_kind`` field per
    VAL-W1-011.
    """


# -----------------------------------------------------------------------------
# IdempotencyRecord (spec A.12; VAL-W1-013, VAL-W1-014, VAL-W1-050)
# -----------------------------------------------------------------------------


class IdempotencyRecord(_RelayEnvelope):
    """Request dedupe record.

    VAL-W1-013: ``idempotency_key`` matches the Crockford-base32 ULID grammar
                ``^[0-9A-HJKMNP-TV-Z]{26}$``.
    VAL-W1-014: ``request_digest`` matches the canonical sha256-<hex> form
                (inherited from VAL-W1-009).
    VAL-W1-050: ``schema_version`` literal pin.
    """

    schema_version: Literal["relay.idempotency_record.v1"]
    idempotency_key: Ulid
    project_id: UUID
    request_digest: Sha256Hash
    response_status: NonNegativeEpoch
    response_ref: str | None = None
    first_seen_at: Rfc3339Datetime
    expires_at: Rfc3339Datetime


# -----------------------------------------------------------------------------
# EventLogEntry (spec A.11; VAL-W1-015, VAL-W1-016, VAL-W1-017, VAL-W1-051)
# -----------------------------------------------------------------------------


class EventLogEntry(_RelayEnvelope):
    """Append-only audit-trail row.

    VAL-W1-015: ``scope_type`` closed enum.
    VAL-W1-016: ``actor_kind`` closed enum.
    VAL-W1-017: ``occurred_at`` is RFC 3339 with a required timezone offset.
                Naive timestamps (no Z, no +/-HH:MM) MUST fail validation.
                The original input string is preserved verbatim on a private
                ``_occurred_at_raw`` attribute so the canonical serializer
                (``serialize_event_log_entry_canonical``) can emit it
                byte-for-byte for the cross-language round-trip fixture.
    VAL-W1-051: ``schema_version`` literal pin.
    """

    schema_version: Literal["relay.event_log_entry.v1"]
    event_id: UUID
    project_id: UUID
    scope_type: Literal[
        "run",
        "replay",
        "gate",
        "eval_run",
        "release",
        "manifest",
        "key",
        "other",
    ]
    scope_id: UUID
    event_type: str
    actor_kind: Literal[
        "control_plane",
        "gate_engine",
        "worker",
        "sdk",
        "user",
        "cron",
    ]
    actor_id: UUID | None = None
    manifest_commit_hash: Sha256Hash | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: Rfc3339Datetime
    ingest_sequence: NonNegativeEpoch

    # Private sidecar storing the original wire-format string for occurred_at
    # so the canonical serializer can emit the offset byte-for-byte. Populated
    # by the wrap-mode model_validator below from the raw input. Not a
    # model field (no extra_forbidden interaction); declared via PrivateAttr.
    _occurred_at_raw: str | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def _check_occurred_at_offset_required(cls, data: Any) -> Any:
        # VAL-W1-017: when occurred_at is a string, reject naive forms here
        # BEFORE Pydantic's datetime coercion silently produces a tz-naive
        # datetime. Field-level mode='after' check below catches direct
        # datetime objects that lack tzinfo.
        if isinstance(data, dict):
            raw = data.get("occurred_at")
            if isinstance(raw, str) and _RFC3339_OFFSET_RE.search(raw) is None:
                raise ValueError(
                    "occurred_at: naive RFC 3339 timestamp rejected; wire "
                    "form MUST carry a timezone offset (Z or +/-HH:MM) per "
                    f"VAL-W1-017 (observed={raw!r})"
                )
        return data

    @field_validator("occurred_at", mode="after")
    @classmethod
    def _occurred_at_requires_tzinfo(cls, value: datetime) -> datetime:
        # VAL-W1-017: a naive ``datetime`` object passed in directly bypasses
        # the string regex above; assert tzinfo is non-None here.
        if value.tzinfo is None:
            raise ValueError(
                "occurred_at: timezone-naive datetime rejected; tzinfo MUST "
                "be set per VAL-W1-017"
            )
        return value

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> EventLogEntry:
        # Override to capture the raw occurred_at string on the validated
        # instance. Pydantic's default model_validate does not expose a
        # raw-input hook compatible with PrivateAttr population, so we
        # intercept here, run the parent validator, then stash the raw.
        raw_occurred_at: str | None = None
        if isinstance(obj, dict):
            candidate = obj.get("occurred_at")
            if isinstance(candidate, str):
                raw_occurred_at = candidate
        instance = super().model_validate(
            obj,
            strict=strict,
            extra=extra,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )
        if raw_occurred_at is not None:
            instance._occurred_at_raw = raw_occurred_at
        return instance


def serialize_event_log_entry_canonical(entry: EventLogEntry) -> bytes:
    """Canonical JSON byte serialization for cross-language round-trip.

    Produces the byte stream that both the Python and TypeScript canonical
    serializers MUST agree on (VAL-W1-017 evidence). Rules:

    1. Sort keys lexicographically (``sort_keys=True``).
    2. Use compact separators ``(",", ":")`` (no extra whitespace).
    3. UUID fields rendered as canonical 8-4-4-4-12 lowercase-hex strings.
    4. ``occurred_at`` rendered as the captured original wire-format string
       (``_occurred_at_raw``) preserving the timezone offset byte-for-byte.
    5. Output encoded as UTF-8 bytes.

    The TS canonical serializer in envelopes.ts mirrors these rules so the
    same fixture produces an identical SHA-256 digest in both languages.
    """
    if entry._occurred_at_raw is None:
        # The model was constructed from a datetime object rather than a
        # string. Fall back to isoformat with the offset preserved; the
        # round-trip in this path is best-effort because the original
        # wire-format string was not supplied.
        occurred_at_str = entry.occurred_at.isoformat()
    else:
        occurred_at_str = entry._occurred_at_raw

    canonical: dict[str, Any] = {
        "schema_version": entry.schema_version,
        "event_id": str(entry.event_id),
        "project_id": str(entry.project_id),
        "scope_type": entry.scope_type,
        "scope_id": str(entry.scope_id),
        "event_type": entry.event_type,
        "actor_kind": entry.actor_kind,
        "actor_id": str(entry.actor_id) if entry.actor_id is not None else None,
        "manifest_commit_hash": entry.manifest_commit_hash,
        "payload": entry.payload,
        "occurred_at": occurred_at_str,
        "ingest_sequence": entry.ingest_sequence,
    }
    # Route through canonical_bytes (RFC 8785): ensure_ascii=False raw UTF-8 +
    # allow_nan=False + ECMA-262 numbers + UTF-16 key sort. The prior bare
    # json.dumps here omitted ensure_ascii/allow_nan, so a non-ASCII payload
    # diverged from TS and a non-finite payload float emitted invalid-JSON
    # NaN/Infinity instead of raising (re-hunt schemas-04/-05).
    return canonical_bytes(canonical)


# -----------------------------------------------------------------------------
# W1.3 evidence + replay envelopes (spec J, A.16, A.8, E.2-E.3)
# -----------------------------------------------------------------------------
#
# Spec anchors:
#   J line 2798-2810   evidence_bundles DDL (verification_status column)
#   A.16 lines 3331-3353 evidence_claims DDL (claim_type closed enum,
#                        claim_digest sha256, signature non-empty,
#                        supersedes_claim_id nullable UUID self-ref)
#   A.8 lines 3131-3145 replay_cases DDL (status enum,
#                        expected_assertion_ids list[str] default [],
#                        failure_signature_hash required)
#   A.8 lines 3147-3168 replay_fixtures DDL (kind / mode / side_effect_class
#                        closed enums; allowed_in_replay bool default false;
#                        refresh_policy default invalidate_on_signature_change)
#   E.2 line 3913       capture_clock = wall-clock at fixture capture
#   E.3 lines 3928-3935 side_effect_class enumeration
#   K   lines 4394+     evidence bundle signature semantics
#
# VAL-W1-019 enum-lock-in: spec J does not enumerate verification_status
# values; the eng-plan-locked candidate set is locked in the canonical YAML
# at packages/schemas/raw/envelopes.yaml as
# {unverified, verified, tampered, revoked}.

NonEmptyStr = Annotated[str, Field(min_length=1)]
"""Non-empty string. Used for signatures and failure_signature_hash."""


class EvidenceBundle(_RelayEnvelope):
    """Signed evidence bundle row (spec J line 2792-2810).

    VAL-W1-018: ``bundle_digest`` non-nullable, canonical sha256-<hex> form.
    VAL-W1-019: ``verification_status`` closed enum locked at
                {unverified, verified, tampered, revoked} (see YAML lock-in
                comment + raw/envelopes.yaml).
    VAL-W1-052: ``schema_version`` pinned to ``relay.evidence_bundle.v1``.
    """

    schema_version: Literal["relay.evidence_bundle.v1"]
    evidence_bundle_id: UUID
    org_id: UUID
    project_id: UUID
    scope_type: str
    scope_id: UUID
    bundle_digest: Sha256Hash
    acef_core_version: str
    relay_extension_version: str
    signing_key_id: str | None = None
    signature_algorithm: str | None = None
    verification_status: Literal["unverified", "verified", "tampered", "revoked"]
    redaction_policy_version: str
    manifest_commit_hash: Sha256Hash | None = None
    object_ref: str
    supersedes_bundle_id: UUID | None = None
    created_at: Rfc3339Datetime


# ---------------------------------------------------------------------------
# V3M1-F05 (2026-05-18): full EvidenceClaim shape per spec K lines 4388-4438.
#
# Adds 7 new/restructured fields to the v1 envelope while preserving the
# 'relay.evidence_claim.v1' schema_version literal (the wire shape is
# additive; back-compat is provided via flat-subject property accessors
# and a mode='before' validator that absorbs the flat construction form
# into the nested subject dict).
#
# Spec K lines 4388-4438 authoritative shape:
#   subject              -> ClaimSubject {kind, id, manifest_commit_hash}
#   evidence_refs[]      -> list[EvidenceRef {kind, ref, digest?, value?}]
#   claim_predicate      -> ClaimPredicate {op, args: list[ClaimPredicate]}
#                            (recursion bounded at depth 8)
#   actor_kind           -> closed-enum Literal (control_plane / gate_engine /
#                            worker / sdk / user / cron)
#   actor_identity_hash  -> Sha256Hash
#   occurred_at          -> datetime (distinct from created_at)
#   namespaces           -> optional dict carrying the ACEF x-relay extension
#                            envelope (e.g. {"x-relay": {"schema_version": "v1"}}).
#
# Per VAL-V3M1-015 the flat ``subject_kind`` / ``subject_id`` access path
# remains readable as a property accessor; a SINGLE deprecation warning
# fires per Python process (tracked via the module-level
# ``_FLAT_SUBJECT_DEPRECATION_EMITTED`` set, mirroring VAL-V3M1-023 cross-
# cutting rule on first-occurrence-only emission).
# ---------------------------------------------------------------------------

# Process-level emission tracker for the flat-subject deprecation warning.
# Cleared by tests for hermeticism; checked by ClaimSubject property accessors.
_FLAT_SUBJECT_DEPRECATION_EMITTED: set[str] = set()

# Spec K line 4407: recursion depth bound. ClaimPredicate.args may nest
# ClaimPredicate values up to this many op-layers deep. The bound is
# enforced by a model_validator (after) walk.
_CLAIM_PREDICATE_MAX_DEPTH: int = 8


class ClaimSubject(_RelayEnvelope):
    """Nested subject object for EvidenceClaim per spec K line 4397-4401.

    The kind enum mirrors spec K line 4398:
    ``run | replay | eval_run | release | domain_pack | ai_system``.
    """

    kind: Literal[
        "run",
        "replay",
        "eval_run",
        "release",
        "domain_pack",
        "ai_system",
    ]
    id: UUID
    manifest_commit_hash: Sha256Hash


class EvidenceRef(_RelayEnvelope):
    """Reference to a piece of evidence inside an EvidenceClaim.

    Spec K line 4402-4406 shows three variants of EvidenceRef:
      * ``{kind, ref, digest}``  -- artifact / run_result with sha256 digest.
      * ``{kind, ref, value}``   -- exit_code / scalar evidence with literal
                                    value.
      * digest and value are both optional independently; at least one of
        ref or value must be meaningful but the spec does not impose a
        cross-field rule, so we keep both optional and let the verifier
        bundle-validator enforce the manifest-binding rule (VAL-V3M1-019,
        owned by m1-f07).
    """

    kind: str
    ref: str
    digest: Sha256Hash | None = None
    value: Any = None


class ClaimPredicate(_RelayEnvelope):
    """Recursive op/args structure per spec K line 4407-4413.

    ``op`` is a free-text op identifier (e.g. ``and``, ``or``,
    ``run_result_status_is``, ``gate_decision_action_is``). ``args`` is a
    list of either nested ClaimPredicate values or leaf objects carrying a
    ``value`` field. We model args as ``list[ClaimPredicate]`` because the
    spec example uses nested ops uniformly; leaf rows of the form
    ``{"op": "run_result_status_is", "value": "accepted"}`` parse fine as
    a ClaimPredicate with empty/absent args and a ``value`` extra.

    Recursion depth is bounded at ``_CLAIM_PREDICATE_MAX_DEPTH`` (8) per
    VAL-V3M1-012. Enforcement runs in a model_validator(mode='after') on
    the parent EvidenceClaim; this class itself is lenient on extras so
    leaf ``value`` payloads (which are valid op-args) can ride along.
    """

    model_config = ConfigDict(
        extra="allow",  # leaf args carry ``value`` outside this base shape
        str_strip_whitespace=False,
        validate_assignment=False,
    )
    op: str
    args: list[ClaimPredicate] = Field(default_factory=list)


def _claim_predicate_depth(node: ClaimPredicate, current: int = 1) -> int:
    """Return the maximum nesting depth rooted at ``node``.

    Depth counts op-layers: a single ClaimPredicate with no args is depth 1,
    ``{op:and, args:[{op:leaf}]}`` is depth 2, and so on.
    """
    if not node.args:
        return current
    return max(
        _claim_predicate_depth(arg, current + 1) for arg in node.args
    )


class EvidenceClaim(_RelayEnvelope):
    """Atomic claim inside an evidence bundle (spec K lines 4388-4438).

    VAL-W1-020: ``claim_type`` closed enum of eight kinds.
    VAL-W1-021: ``claim_digest`` canonical sha256-<hex> form; ``signature``
                non-empty string; ``supersedes_claim_id`` nullable UUID.
    VAL-W1-053: ``schema_version`` pinned to ``relay.evidence_claim.v1``.

    V3M1-F05 additions (spec K lines 4388-4438):
        VAL-V3M1-011: ``evidence_refs: list[EvidenceRef]`` (defaults to []).
        VAL-V3M1-012: ``claim_predicate: ClaimPredicate | None`` with
                      recursion depth bounded at 8.
        VAL-V3M1-013: ``actor_kind: Literal[...]`` closed enum
                      mirroring EventLogEntry.actor_kind +
                      ``actor_identity_hash: Sha256Hash`` required.
        VAL-V3M1-014: ``occurred_at: datetime`` distinct from
                      ``created_at`` (spec K line 4417).
        VAL-V3M1-015: ``subject: ClaimSubject`` nested object;
                      ``subject_kind`` / ``subject_id`` retained as
                      deprecated read-only property accessors that fire
                      a single per-process DeprecationWarning.
        VAL-V3M1-020: ``redaction_transform_version`` preserved on the
                      envelope across all 4 layers.
        VAL-V3M1-021: ``namespaces: dict | None`` carrying the optional
                      ACEF x-relay extension envelope.
    """

    schema_version: Literal["relay.evidence_claim.v1"]
    evidence_claim_id: UUID
    evidence_bundle_id: UUID
    claim_type: Literal[
        "run_result",
        "gate_decision",
        "contract_result",
        "replay_result",
        "human_oversight",
        "incident",
        "data_quality_check",
        "provider_compatibility",
    ]
    subject: ClaimSubject
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    claim_predicate: ClaimPredicate | None = None
    claim_digest: Sha256Hash
    redaction_transform_version: str
    actor_kind: Literal[
        "control_plane",
        "gate_engine",
        "worker",
        "sdk",
        "user",
        "cron",
    ]
    actor_identity_hash: Sha256Hash
    occurred_at: Rfc3339Datetime
    manifest_commit_hash: Sha256Hash
    signer_key_id: str
    signature: NonEmptyStr
    supersedes_claim_id: UUID | None = None
    namespaces: dict[str, Any] | None = None
    created_at: Rfc3339Datetime

    # ---------------------------------------------------------------------
    # Back-compat construction shim (VAL-V3M1-015).
    #
    # Existing callers may pass the flat shape:
    #   {"subject_kind": "run", "subject_id": "<uuid>",
    #    "manifest_commit_hash": "sha256-..."}
    # We absorb those keys into a nested ``subject`` dict BEFORE Pydantic's
    # ``extra="forbid"`` rejects them. ``manifest_commit_hash`` remains a
    # top-level required field on the envelope (preserves bundle-anchor
    # semantics) AND is mirrored into ``subject.manifest_commit_hash`` so
    # the spec K nested shape is satisfied even when only the flat form
    # is provided. Callers passing both flat and nested forms must keep
    # them consistent; we treat the nested form as authoritative.
    # ---------------------------------------------------------------------
    @model_validator(mode="before")
    @classmethod
    def _absorb_flat_subject(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        # If nested already supplied, keep it as-is.
        if "subject" in data and isinstance(data["subject"], dict):
            return data
        # Build nested subject from flat keys if any are present.
        flat_kind = data.pop("subject_kind", None) if "subject" not in data else None
        flat_id = data.pop("subject_id", None) if "subject" not in data else None
        if "subject" not in data and (flat_kind is not None or flat_id is not None):
            data["subject"] = {
                "kind": flat_kind,
                "id": flat_id,
                "manifest_commit_hash": data.get("manifest_commit_hash"),
            }
        return data

    @model_validator(mode="after")
    def _enforce_claim_predicate_depth(self) -> EvidenceClaim:
        if self.claim_predicate is None:
            return self
        depth = _claim_predicate_depth(self.claim_predicate)
        if depth > _CLAIM_PREDICATE_MAX_DEPTH:
            raise ValueError(
                f"claim_predicate recursion depth {depth} exceeds "
                f"spec K bound of {_CLAIM_PREDICATE_MAX_DEPTH} "
                f"(VAL-V3M1-012)"
            )
        return self

    # ---------------------------------------------------------------------
    # Back-compat read accessors (VAL-V3M1-015).
    #
    # Reading ``claim.subject_kind`` / ``claim.subject_id`` returns the
    # nested-subject value and emits a single DeprecationWarning per
    # Python process. The per-process tracker honors VAL-V3M1-023's
    # first-occurrence-only rule to prevent CI log spam across the 14+
    # existing call sites enumerated in VAL-V3M1-016.
    # ---------------------------------------------------------------------
    @property
    def subject_kind(self) -> str:
        _emit_flat_subject_deprecation_warning("subject_kind")
        return self.subject.kind

    @property
    def subject_id(self) -> UUID:
        _emit_flat_subject_deprecation_warning("subject_id")
        return self.subject.id


def _emit_flat_subject_deprecation_warning(attr: str) -> None:
    """Emit the flat-subject DeprecationWarning once per Python process.

    Tracker key uses a fixed sentinel (not ``attr``) so reading either
    ``subject_kind`` or ``subject_id`` after the first access on either
    of the two flat properties does NOT re-emit. This matches the
    VAL-V3M1-015 evidence requirement "first-occurrence-per-process
    only" and the VAL-V3M1-023 cross-cutting rule. Tests reset the
    tracker via ``envelopes._FLAT_SUBJECT_DEPRECATION_EMITTED.clear()``.
    """
    sentinel = "evidence_claim.flat_subject"
    if sentinel in _FLAT_SUBJECT_DEPRECATION_EMITTED:
        return
    _FLAT_SUBJECT_DEPRECATION_EMITTED.add(sentinel)
    import warnings as _warnings

    _warnings.warn(
        (
            "EvidenceClaim.subject_kind / subject_id are deprecated; "
            "use claim.subject.kind / claim.subject.id. This message "
            "fires once per process (VAL-V3M1-015 / VAL-V3M1-023)."
        ),
        DeprecationWarning,
        stacklevel=3,
    )


class ReplayCase(_RelayEnvelope):
    """Replay case row (spec A.8 lines 3131-3145).

    VAL-W1-022: ``status`` closed enum {proposed, approved, retired};
                ``expected_assertion_ids`` defaults to []; only non-empty
                strings accepted. ``failure_signature_hash`` required
                non-empty.
    VAL-W1-054: ``schema_version`` pinned to ``relay.replay_case.v1``.
    """

    schema_version: Literal["relay.replay_case.v1"]
    replay_case_id: UUID
    project_id: UUID
    source_run_id: UUID | None = None
    failure_signature_hash: NonEmptyStr
    inputs_ref: str
    inputs_digest: Sha256Hash
    expected_assertion_ids: list[NonEmptyStr] = Field(default_factory=list)
    human_reviewed: bool = False
    reviewer_email: str | None = None
    reviewed_at: Rfc3339Datetime | None = None
    status: Literal["proposed", "approved", "retired"] = "proposed"
    created_at: Rfc3339Datetime


class ReplayFixture(_RelayEnvelope):
    """Replay fixture row (spec A.8 lines 3147-3168, E.2-E.3).

    VAL-W1-023: ``kind`` / ``mode`` / ``side_effect_class`` closed enums;
                ``allowed_in_replay`` STRICT bool (not coercible from
                "true"/"false" strings or int 0/1).
    VAL-W1-024: ``capture_clock`` RFC 3339 timezone-aware; naive timestamps
                rejected. The raw wire-format string is captured on a
                private attribute so the canonical serializer can emit it
                byte-for-byte for the cross-language round-trip fixture.
    VAL-W1-025: ``refresh_policy`` closed four-member enum, default
                ``invalidate_on_signature_change``.
    VAL-W1-055: ``schema_version`` pinned to ``relay.replay_fixture.v1``.
    """

    schema_version: Literal["relay.replay_fixture.v1"]
    fixture_id: UUID
    replay_case_id: UUID
    source_span_id: UUID
    kind: Literal["model_call", "tool_call", "retrieval", "embedding", "custom"]
    mode: Literal["cassette", "live", "degraded_live", "mock"]
    redaction_policy_version: str
    input_digest: Sha256Hash
    output_ref: str | None = None
    output_digest: Sha256Hash | None = None
    provider: str | None = None
    model: str | None = None
    model_signature: str | None = None
    capture_clock: Rfc3339Datetime
    refresh_policy: Literal[
        "invalidate_on_signature_change",
        "hold_forever",
        "refresh_weekly",
        "invalidate_on_model_version_change",
    ] = "invalidate_on_signature_change"
    side_effect_class: Literal[
        "read_only",
        "mutating",
        "external_irreversible",
        "approval_required",
    ]
    allowed_in_replay: bool = False
    created_at: Rfc3339Datetime

    _capture_clock_raw: str | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def _check_capture_clock_offset_and_strict_bool(cls, data: Any) -> Any:
        # VAL-W1-024: reject naive RFC 3339 string forms BEFORE Pydantic's
        # datetime coercion silently produces a tz-naive datetime.
        # VAL-W1-023: reject any allowed_in_replay value that is not a
        # native Python bool. Pydantic v2 default-mode coerces "true"/"false"
        # strings AND int 0/1 to bool; we reject both BEFORE field validation.
        if isinstance(data, dict):
            raw = data.get("capture_clock")
            if isinstance(raw, str) and _RFC3339_OFFSET_RE.search(raw) is None:
                raise ValueError(
                    "capture_clock: naive RFC 3339 timestamp rejected; wire "
                    "form MUST carry a timezone offset (Z or +/-HH:MM) per "
                    f"VAL-W1-024 (observed={raw!r})"
                )
            if "allowed_in_replay" in data:
                value = data["allowed_in_replay"]
                if not isinstance(value, bool):
                    raise ValueError(
                        "allowed_in_replay: strict boolean required; type "
                        f"{type(value).__name__} rejected per VAL-W1-023 "
                        f"(observed={value!r})"
                    )
        return data

    @field_validator("capture_clock", mode="after")
    @classmethod
    def _capture_clock_requires_tzinfo(cls, value: datetime) -> datetime:
        # VAL-W1-024: a naive datetime object passed in directly bypasses
        # the string regex above; assert tzinfo is non-None here.
        if value.tzinfo is None:
            raise ValueError(
                "capture_clock: timezone-naive datetime rejected; tzinfo "
                "MUST be set per VAL-W1-024"
            )
        return value

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> ReplayFixture:
        # Capture the raw capture_clock string on the validated instance so
        # the canonical serializer can emit it byte-for-byte for the
        # cross-language round-trip fixture (mirrors EventLogEntry).
        raw_capture_clock: str | None = None
        if isinstance(obj, dict):
            candidate = obj.get("capture_clock")
            if isinstance(candidate, str):
                raw_capture_clock = candidate
        instance = super().model_validate(
            obj,
            strict=strict,
            extra=extra,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )
        if raw_capture_clock is not None:
            instance._capture_clock_raw = raw_capture_clock
        return instance


def serialize_replay_fixture_canonical(fixture: ReplayFixture) -> bytes:
    """Canonical JSON byte serialization for cross-language round-trip.

    Mirrors ``serialize_event_log_entry_canonical`` (VAL-W1-017) so the same
    fixture produces an identical SHA-256 digest in Py and TS. Rules:

    1. Sort keys lexicographically (``sort_keys=True``).
    2. Use compact separators (",", ":") (no extra whitespace).
    3. UUID fields rendered as canonical 8-4-4-4-12 lowercase-hex strings.
    4. ``capture_clock`` rendered as the captured original wire-format
       string preserving the timezone offset byte-for-byte.
    5. ``created_at`` rendered via ``isoformat()`` (only capture_clock is
       used for the VAL-W1-024 byte-equal evidence; ``created_at`` is not
       on the offset-preservation critical path but is included in the
       canonical envelope for completeness).
    6. UTF-8 encoded bytes.
    """
    if fixture._capture_clock_raw is None:
        capture_clock_str = fixture.capture_clock.isoformat()
    else:
        capture_clock_str = fixture._capture_clock_raw

    canonical: dict[str, Any] = {
        "schema_version": fixture.schema_version,
        "fixture_id": str(fixture.fixture_id),
        "replay_case_id": str(fixture.replay_case_id),
        "source_span_id": str(fixture.source_span_id),
        "kind": fixture.kind,
        "mode": fixture.mode,
        "redaction_policy_version": fixture.redaction_policy_version,
        "input_digest": fixture.input_digest,
        "output_ref": fixture.output_ref,
        "output_digest": fixture.output_digest,
        "provider": fixture.provider,
        "model": fixture.model,
        "model_signature": fixture.model_signature,
        "capture_clock": capture_clock_str,
        "refresh_policy": fixture.refresh_policy,
        "side_effect_class": fixture.side_effect_class,
        "allowed_in_replay": fixture.allowed_in_replay,
        "created_at": fixture.created_at.isoformat(),
    }
    # Route through canonical_bytes for RFC-8785 Py<->TS byte parity (raw UTF-8,
    # allow_nan=False, ECMA-262 numbers, UTF-16 key sort) -- see
    # serialize_event_log_entry_canonical (re-hunt schemas-04/-05).
    return canonical_bytes(canonical)


# -----------------------------------------------------------------------------
# W1.4 RedactionPolicy + ErrorEnvelope (spec A.10, G.1, G.2, B.4)
# -----------------------------------------------------------------------------
#
# Spec anchors:
#   A.10 lines 3219-3225  redaction_policies DDL
#   G.1  lines 4108-4114  raw_capture invariants (hosted; mirrored to wire)
#   G.2  lines 4127-4133  matcher kinds
#   B.4  lines 3392-3408  error envelope closed schema + retry_advice table
#
# VAL-W1-026 RedactionPolicy.schema_version literal "relay.redaction.v1";
#            raw_capture StrictBool; default False.
# VAL-W1-027 cross-field: raw_capture=True REQUIRES dpa_ref AND
#            approver_user_id non-null (CLAUDE.md banned pattern #11).
# VAL-W1-028 matchers[] tagged discriminated union on `kind`:
#              kind="regex"        -> requires `pattern`, forbids `paths`.
#              kind="json_pointer" -> requires `paths`,   forbids `pattern`.
# VAL-W1-029 ErrorEnvelope required fields:
#              schema_version literal "relay.error.v1"
#              code matches ^RELAY-[A-Z]+-[0-9]{3}$
#              http_status int in [400, 599]
#              blocked_surface non-empty string
#              retry_advice closed enum {do_not_retry, after_fix,
#                                        after_retry_after, after_split,
#                                        after_recapture, after_re_auth}
# VAL-W1-031 request_id, trace_id required non-empty strings.
# VAL-W1-056 ErrorEnvelope.schema_version literal "relay.error.v1".

# RELAY-* error code wire-form pattern. Bound to the canonical regex declared
# by VAL-W1-029. Constants generated from packages/schemas/raw/relay-error-codes.yaml
# live in relay_schemas.error_codes.RelayErrorCode (VAL-W1-030).
RELAY_ERROR_CODE_PATTERN = r"^RELAY-[A-Z]+-[0-9]{3}$"

RelayErrorCodeStr = Annotated[str, Field(pattern=RELAY_ERROR_CODE_PATTERN)]
"""Canonical Relay error-code wire form per VAL-W1-029."""

HttpStatus4xx5xx = Annotated[int, Field(ge=400, le=599)]
"""HTTP status in [400, 599] per VAL-W1-029."""


class RedactionPolicyMatcherRegex(_RelayEnvelope):
    """Regex variant of a redaction matcher (VAL-W1-028).

    kind="regex" requires `pattern` (a regex string). `paths` is FORBIDDEN on
    this variant; the `extra="forbid"` config inherited from _RelayEnvelope
    rejects any document carrying `paths` here.
    """

    kind: Literal["regex"]
    pattern: NonEmptyStr


class RedactionPolicyMatcherJsonPointer(_RelayEnvelope):
    """JSON-pointer variant of a redaction matcher (VAL-W1-028).

    kind="json_pointer" requires `paths` (a list of non-empty JSON-pointer
    strings). `pattern` is FORBIDDEN on this variant.
    """

    kind: Literal["json_pointer"]
    paths: list[NonEmptyStr] = Field(min_length=1)


_RedactionPolicyMatcherUnion = Annotated[
    RedactionPolicyMatcherRegex | RedactionPolicyMatcherJsonPointer,
    Field(discriminator="kind"),
]


class RedactionPolicy(_RelayEnvelope):
    """Per-org redaction policy version (spec A.10 lines 3219-3225).

    VAL-W1-026: ``schema_version`` literal pin to ``relay.redaction.v1``;
                ``raw_capture`` is StrictBool (Pydantic v2) so the strings
                ``"true"``/``"false"`` and ints 0/1 are rejected; default
                False.
    VAL-W1-027: cross-field invariant ``raw_capture_requires_dpa_and_approver``
                mirroring spec G.1 hosted invariant + CLAUDE.md banned
                pattern #11. raw_capture=True REQUIRES both dpa_ref AND
                approver_user_id to be non-null.
    VAL-W1-028: ``matchers`` is a tagged union on ``kind`` with regex and
                json_pointer variants. Mixing fields across kinds fails
                validation.
    """

    schema_version: Literal["relay.redaction.v1"]
    redaction_policy_id: UUID
    org_id: UUID
    version: str
    raw_capture: StrictBool = False
    dpa_ref: str | None = None
    approver_user_id: UUID | None = None
    matchers: list[_RedactionPolicyMatcherUnion] = Field(default_factory=list)
    created_at: Rfc3339Datetime

    @model_validator(mode="after")
    def _check_raw_capture_requires_dpa_and_approver(self) -> RedactionPolicy:
        # VAL-W1-027: mirrors spec G.1 hosted invariant at the wire-format
        # layer. raw_capture=True requires BOTH dpa_ref AND approver_user_id
        # to be non-null. A True with either field missing fails.
        if self.raw_capture and (
            self.dpa_ref is None or self.approver_user_id is None
        ):
            raise ValueError(
                "raw_capture_requires_dpa_and_approver: raw_capture=True "
                "requires both dpa_ref and approver_user_id to be "
                "non-null (fields: raw_capture, dpa_ref, "
                "approver_user_id) per VAL-W1-027 and CLAUDE.md banned "
                "pattern #11"
            )
        return self


class ErrorEnvelope(_RelayEnvelope):
    """Canonical Relay error envelope (spec B.4 lines 3392-3408).

    VAL-W1-029: required fields ``schema_version`` (literal
                ``"relay.error.v1"``), ``code`` (non-empty string matching
                ``^RELAY-[A-Z]+-[0-9]{3}$``), ``http_status`` (int in
                ``[400, 599]``), ``blocked_surface`` (non-empty string),
                ``retry_advice`` (closed enum).
    VAL-W1-030: known ``code`` values are enumerated in
                ``packages/schemas/raw/relay-error-codes.yaml`` and
                generated as constants on
                ``relay_schemas.error_codes.RelayErrorCode``.
    VAL-W1-031: ``request_id`` and ``trace_id`` are required non-empty
                strings (``Field(min_length=1)``).
    VAL-W1-056: ``schema_version`` literal pin (mirrors VAL-W1-029 at the
                dedicated schema_version pin uniformly applied per
                CLAUDE.md invariant #10).
    """

    schema_version: Literal["relay.error.v1"]
    code: RelayErrorCodeStr
    http_status: HttpStatus4xx5xx
    blocked_surface: NonEmptyStr
    retry_advice: Literal[
        "do_not_retry",
        "after_fix",
        "after_retry_after",
        "after_split",
        "after_recapture",
        "after_re_auth",
    ]
    request_id: NonEmptyStr
    trace_id: NonEmptyStr
    message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# v0.2 OSS completeness, M01 w1-1: canonical envelopes added 2026-05-16
# =============================================================================
#
# These 12 envelopes back the 13 new SQL tables in
# packages/schemas/sql/0004_v2_canonical_tables.sql (the redaction_policies
# table is mirrored at the wire-format layer by the existing RedactionPolicy
# envelope from W1.4, so it does NOT introduce a new class). Every envelope
# pins schema_version via Literal[...] per CLAUDE.md keystone invariant #10.
#
# Spec anchors:
#   GatePolicy            spec A.5  lines 3063-3076
#   ContractResult        spec A.6  lines 3082-3102
#   AssertionDefinition   spec A.7  lines 3108-3125
#   ReplayResult          spec A.8  lines 3172-3187
#   Manifest              spec A.9  lines 3193-3199 (parent of ManifestVersion)
#   Incident              spec A.13 lines 3274-3290
#   RootCauseHypothesis   spec A.15 lines 3316-3328
#   Span                  spec Z    lines 1825-1836 (parent table)
#   ModelCallSpan         spec Z    lines 5226-5249
#   ToolCallSpan          spec Z    lines 5251-5264
#   RetrievalSpan         spec Z    lines 5266-5279
#   EmbeddingSpan         spec Z    lines 5281-5290
#
# The Manifest envelope's schema_version literal is "relay.manifest_parent.v1"
# to avoid colliding with the existing ManifestVersion literal
# "relay.manifest.v1". ManifestVersion remains the canonical Manifest commit
# envelope; Manifest is the parent identity row.


class GatePolicy(_RelayEnvelope):
    """Per-gate policy version (spec A.5; VAL-V2M01-001).

    Conditions are GatePolicy v1 (spec sectionD.3). blocking_severity is the
    closed three-member enum locked at SQL + wire layers per the v2 audit.
    """

    schema_version: Literal["relay.gate_policy.v1"]
    gate_policy_id: UUID
    gate_id: UUID
    policy_version: str
    conditions: dict[str, Any]
    baseline_selector: dict[str, Any] | None = None
    flaky_quarantine_policy: dict[str, Any] | None = None
    blocking_severity: Literal["p0_only", "p0_p1", "any_failure"] = "p0_only"
    effective_at: Rfc3339Datetime
    effective_until: Rfc3339Datetime | None = None


class ContractResult(_RelayEnvelope):
    """Per-run contract evaluation result (spec A.6; VAL-V2M01-002).

    outcome is the closed five-member set; severity is the standard p0-info
    ladder. metadata is a free-form jsonb bag for the evaluator's
    diagnostic detail.
    """

    schema_version: Literal["relay.contract_result.v1"]
    contract_result_id: UUID
    run_id: UUID
    contract_id: UUID
    contract_version: str
    assertion_id: str | None = None
    span_id: UUID | None = None
    outcome: Literal["pass", "fail", "repaired", "skipped", "error"]
    severity: Literal["p0", "p1", "p2", "info"] | None = None
    raw_signature_hash: str | None = None
    repair_attempt: int = 0
    evaluation_engine_version: str
    evaluated_at: Rfc3339Datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssertionDefinition(_RelayEnvelope):
    """Atomic assertion definition (spec A.7; VAL-V2M01-003).

    Primary identifier is the human-meaningful assertion_id (a text PK on
    the SQL side, e.g. ``"VAL-STRUCTURED-001"``). kind, severity, and
    lifecycle_state are closed enums.
    """

    schema_version: Literal["relay.assertion_definition.v1"]
    assertion_id: str
    project_id: UUID
    kind: Literal[
        "schema_contract",
        "behavioral",
        "tool_arg",
        "eval",
        "coverage",
    ]
    severity: Literal["p0", "p1", "p2", "info"]
    title: str
    description: str | None = None
    owner_email: str
    expression: dict[str, Any]
    applies_to: dict[str, Any] = Field(default_factory=dict)
    lifecycle_state: Literal[
        "draft",
        "active",
        "deprecated",
        "retired",
    ] = "draft"
    current_version: int = 1
    created_at: Rfc3339Datetime
    updated_at: Rfc3339Datetime


class ReplayResult(_RelayEnvelope):
    """Per-replay outcome row (spec A.8; VAL-V2M01-004).

    outcome is the closed four-member set
    {reproduced, diverged, blocked, sandbox_error}. sandbox_driver is a
    text identifier (e.g. ``"local-docker"``, ``"e2b"``,
    ``"local-firecracker"``, ``"modal"``).
    """

    schema_version: Literal["relay.replay_result.v1"]
    replay_result_id: UUID
    replay_case_id: UUID
    replay_run_id: UUID
    outcome: Literal["reproduced", "diverged", "blocked", "sandbox_error"]
    failure_signature_match: bool | None = None
    fixture_hits: int = 0
    fixture_misses: int = 0
    sandbox_driver: str
    sandbox_id: str | None = None
    network_egress_denied: int = 0
    side_effect_attempts: int = 0
    side_effect_approved: int = 0
    evidence_bundle_id: UUID | None = None
    created_at: Rfc3339Datetime


class Manifest(_RelayEnvelope):
    """Manifest parent identity row (spec A.9; VAL-V2M01-005).

    Parent of ManifestVersion. The pair forms the spec A.9 manifest-version
    chain: a Manifest carries the identity (project_id, name); a
    ManifestVersion carries each commit_hash + body. ``schema_version``
    uses the ``relay.manifest_parent.v1`` literal so the parent envelope
    does not collide with the ManifestVersion ``relay.manifest.v1`` literal.
    """

    schema_version: Literal["relay.manifest_parent.v1"]
    manifest_id: UUID
    project_id: UUID
    name: str
    created_at: Rfc3339Datetime


class Incident(_RelayEnvelope):
    """Incident cluster row (spec A.13; VAL-V2M01-007).

    Severity follows the standard sev1-sev4 ladder. State is the closed
    four-member workflow {open, mitigated, closed, suppressed}.
    cluster_signature_hash groups recurring failures into one incident
    record. ``affected_run_ids`` accepts a list of UUIDs (Postgres uuid[];
    SQLite stores as JSON-encoded text).
    """

    schema_version: Literal["relay.incident.v1"]
    incident_id: UUID
    project_id: UUID
    cluster_signature_hash: str
    severity: Literal["sev1", "sev2", "sev3", "sev4"]
    state: Literal["open", "mitigated", "closed", "suppressed"] = "open"
    affected_run_ids: list[UUID] = Field(default_factory=list)
    first_seen_at: Rfc3339Datetime
    last_seen_at: Rfc3339Datetime
    owner_email: str | None = None
    postmortem_ref: str | None = None
    promoted_to_regression: bool = False
    created_at: Rfc3339Datetime | None = None


class RootCauseHypothesis(_RelayEnvelope):
    """Explain root-cause hypothesis (spec A.15, sectionT; VAL-V2M01-008).

    confidence is a float in [0, 1] inclusive (CHECK constraint mirrored
    here). generator follows the spec T taxonomy: ``heuristic.<v>``,
    ``llm.<model>:vN``, or ``user``. reviewer_decision is the closed
    four-member set.
    """

    schema_version: Literal["relay.root_cause_hypothesis.v1"]
    hypothesis_id: UUID
    run_id: UUID
    span_id: UUID | None = None
    hypothesis_class: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    evidence_refs: list[Any] = Field(default_factory=list)
    generator: str
    reviewer_email: str | None = None
    reviewer_decision: (
        Literal["accept", "reject", "modify", "pending"] | None
    ) = None
    promoted_to_replay_case_id: UUID | None = None
    created_at: Rfc3339Datetime


class Span(_RelayEnvelope):
    """Parent span row (spec Z; VAL-V2M01-009).

    span_type is the polymorphic discriminator that drives the typed-detail
    invariant. A Span with span_type in
    ``{model_call, tool_call, retrieval, embedding}`` MUST be accompanied
    by a matching typed-detail row (ModelCallSpan / ToolCallSpan /
    RetrievalSpan / EmbeddingSpan) in the same INSERT transaction. A Span
    with span_type=='custom' requires no typed-detail row. The ingest
    worker enforces this atomically; the canonical missing-detail error
    code is ``RELAY-INGEST-SPAN-DETAIL-MISSING``.
    """

    schema_version: Literal["relay.span.v1"]
    span_id: UUID
    run_id: UUID | None = None
    parent_span_id: UUID | None = None
    span_type: Literal[
        "model_call",
        "tool_call",
        "retrieval",
        "embedding",
        "custom",
    ]
    name: str
    status: str
    started_at: Rfc3339Datetime
    ended_at: Rfc3339Datetime | None = None
    error_class: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelCallSpan(_RelayEnvelope):
    """Typed-detail row for span_type='model_call' (spec Z lines 5226-5249;
    VAL-V2M01-010).
    """

    schema_version: Literal["relay.model_call_span.v1"]
    span_id: UUID
    provider: str
    model: str
    model_signature: str | None = None
    request_message_count: int | None = None
    request_token_count: int | None = None
    response_token_count: int | None = None
    cached_token_count: int | None = None
    reasoning_token_count: int | None = None
    cost_usd: float | None = None
    latency_ms: int | None = None
    finish_reason: str | None = None
    structured_output_mode: str | None = None
    schema_contract_id: str | None = None
    tool_choice_mode: str | None = None
    streaming: bool = False
    input_redaction_policy_version: str
    input_digest: str | None = None
    output_digest: str | None = None
    http_status: int | None = None
    provider_error_code: str | None = None
    provider_error_class: str | None = None


class ToolCallSpan(_RelayEnvelope):
    """Typed-detail row for span_type='tool_call' (spec Z lines 5251-5264;
    VAL-V2M01-011).

    side_effect_class is the canonical four-class label (spec E.3); the
    closed enum lock-in happens in the SideEffectMarker / SideEffectProof
    envelopes that land with M04. args_validation_outcome is the closed
    five-member contract result enum.
    """

    schema_version: Literal["relay.tool_call_span.v1"]
    span_id: UUID
    tool_name: str
    side_effect_class: str
    args_digest: str | None = None
    args_redaction_policy_version: str
    args_schema_contract_id: str | None = None
    args_validation_outcome: (
        Literal["pass", "fail", "repaired", "skipped", "error"] | None
    ) = None
    result_digest: str | None = None
    status: str
    latency_ms: int | None = None
    marker_id: UUID | None = None
    parallel_index: int | None = None


class RetrievalSpan(_RelayEnvelope):
    """Typed-detail row for span_type='retrieval' (spec Z lines 5266-5279;
    VAL-V2M01-012).
    """

    schema_version: Literal["relay.retrieval_span.v1"]
    span_id: UUID
    retriever_name: str
    query_digest: str | None = None
    query_redaction_policy_version: str
    document_count: int | None = None
    duplicate_document_count: int | None = None
    empty_retrieval: bool = False
    relevance_proxy_score: float | None = None
    citation_coverage: float | None = None
    context_token_count: int | None = None
    context_waste_tokens: int | None = None
    latency_ms: int | None = None


class EmbeddingSpan(_RelayEnvelope):
    """Typed-detail row for span_type='embedding' (spec Z lines 5281-5290;
    VAL-V2M01-013).
    """

    schema_version: Literal["relay.embedding_span.v1"]
    span_id: UUID
    provider: str
    model: str
    input_token_count: int | None = None
    embedding_dim: int | None = None
    cached: bool = False
    cost_usd: float | None = None
    latency_ms: int | None = None


class EvidenceLegalHold(_RelayEnvelope):
    """Legal hold row (spec Y lines 5184-5200; VAL-V2M01-026).

    scope_kind is the closed four-member set
    ``{org, project, run, evidence_bundle}``. state is the closed two-member
    workflow ``{active, released}``. The retention sweep references rows
    here via the partial index on (scope_kind, scope_id) WHERE state =
    'active' (see packages/schemas/sql/0005_legal_holds.sql).
    """

    schema_version: Literal["relay.evidence_legal_hold.v1"]
    hold_id: UUID
    org_id: UUID
    scope_kind: Literal["org", "project", "run", "evidence_bundle"]
    scope_id: UUID
    reason: str
    legal_matter_ref: str | None = None
    imposed_by_user_id: UUID
    counsel_signoff_at: Rfc3339Datetime | None = None
    counsel_signoff_by: str | None = None
    state: Literal["active", "released"] = "active"
    imposed_at: Rfc3339Datetime
    released_at: Rfc3339Datetime | None = None
    released_by_user_id: UUID | None = None


class EvidenceBundleRegistry(_RelayEnvelope):
    """Mutable sibling to immutable signed evidence_bundles
    (spec Y lines 5202-5213; VAL-V2M01-027).

    state is the closed four-member machine
    ``{active, superseded, tombstoned, legal_hold}``. The signed bundle
    bytes never change; this row mutates as the bundle is superseded,
    redacted via tombstone, or placed under legal hold.

    State-machine transitions beyond the closed enum (e.g. requiring
    ``superseded_by`` non-null when ``state == 'superseded'``, the
    terminal nature of ``tombstoned``, requiring ``legal_hold_id``
    non-null when ``state == 'legal_hold'``) are enforced by
    :func:`relay_schemas.bundle_registry.validate_registry_transition`.
    """

    schema_version: Literal["relay.evidence_bundle_registry.v1"]
    evidence_bundle_id: UUID
    state: Literal["active", "superseded", "tombstoned", "legal_hold"] = "active"
    superseded_by: UUID | None = None
    subject_redacted_after_signing: bool = False
    redaction_event_ref: str | None = None
    legal_hold_id: UUID | None = None
    last_state_change_at: Rfc3339Datetime


# ---------------------------------------------------------------------------
# v0.2 OSS completeness, M01 w1-6 (added 2026-05-16): two sectionAB
# trusted-timestamping + transparency-log envelopes. Mirror the SQL tables
# in packages/schemas/sql/0007_evidence_timestamps_log.sql.
#
# Per CLAUDE.md keystone invariant #2 ("pass without evidence is not a
# pass"), evidence_timestamps binds the trustworthy time anchor that every
# accepted bundle requires. Per CLAUDE.md keystone invariant #11
# ("trust anchor is the commercial moat"), transparency_log_entries is
# the append-only public log the verifier checks for offline inclusion.
# ---------------------------------------------------------------------------


class EvidenceTimestamp(_RelayEnvelope):
    """RFC 3161 TSA timestamp row for an evidence bundle
    (spec AB lines 5421-5429; VAL-V2M01-033).

    One row per evidence bundle. ``tsa_genTime`` is the parsed genTime
    field from the TimeStampResp CMS SignerInfo (RFC 3161). ``tsa_response_ref``
    points at the canonical ``.tsr`` blob (R2 on hosted; local file on
    OSS sidecar). ``tsa_response_digest`` is the sha256 over the .tsr
    bytes so verifiers can detect mutation. ``tsa_witness_signature``
    is the optional log-witness countersignature per spec AB line 5418.

    Field-name note: ``tsa_genTime`` preserves the RFC 3161 ASN.1 field
    name verbatim (camelCase). The Pydantic model accepts the camelCase
    key on both wire input and Python attribute access.
    """

    schema_version: Literal["relay.evidence_timestamp.v1"]
    evidence_bundle_id: UUID
    tsa_url: str
    tsa_response_digest: str
    tsa_response_ref: str
    tsa_serial_number: str | None = None
    tsa_genTime: datetime  # noqa: N815 - RFC 3161 ASN.1 field name preserved
    tsa_witness_signature: str | None = None


class TransparencyLogEntry(_RelayEnvelope):
    """Append-only public transparency log entry
    (spec AB lines 5431-5439; VAL-V2M01-035).

    Inspired by Sigstore Rekor. ``log_index`` is the canonical 1-based
    serial index (bigserial on Postgres, INTEGER PRIMARY KEY
    AUTOINCREMENT on SQLite). ``tree_root_after`` is the Merkle root
    after this append; ``inclusion_proof_ref`` points at the served proof
    JSON. The verifier checks inclusion offline via the witness signature
    carried separately in the bundle's signature envelope.

    Per spec AB line 5445 the log is append-only; the application role
    grants are INSERT,SELECT only. The OSS sidecar emulates the GRANT
    model via BEFORE DELETE / BEFORE UPDATE triggers that abort with
    ``RELAY-EVID-031``.
    """

    schema_version: Literal["relay.transparency_log_entry.v1"]
    log_index: Annotated[int, Field(ge=1)]
    evidence_bundle_id: UUID
    bundle_digest: str
    signer_key_id: str
    appended_at: Rfc3339Datetime
    tree_root_after: str
    inclusion_proof_ref: str | None = None


# ---------------------------------------------------------------------------
# v0.2 OSS completeness, M01 w1-5 (added 2026-05-16): canonical envelopes for
# the three section-AE evidence-binding tables in
# packages/schemas/sql/0006_human_oversight.sql.
#
# Per CLAUDE.md keystone invariant #2, evidence claims that reference human
# oversight, data-quality checks, or data-provenance rows require first-class
# canonical rows to bind to. Per keystone invariant #10 every envelope pins
# schema_version via Literal[...].
#
# Decoupled-namespace note: the wire-format envelopes here use the
# ``relay.*.v1`` namespace (control-plane canonical wire form). The
# pre-existing ACEF extension dataclasses at
# ``packages/acef/relay_extensions/models/{human_oversight_event,
# data_quality_check,data_provenance_record}.py`` use the
# ``x-relay.*.v1`` namespace (ACEF wire form). Both layers coexist; callers
# choose the surface that matches their consumer.
# ---------------------------------------------------------------------------


class HumanOversightEvent(_RelayEnvelope):
    """Human-in-the-loop oversight event row (spec AE lines 5494-5508;
    VAL-V2M01-030).

    Captures every human oversight event tied to a project, optional run,
    and optional AI-system classification. ``oversight_kind`` is the closed
    six-member enum mirrored from the SQL CHECK constraint. ``evidence_refs``
    is a JSON array of evidence-bundle / evidence-claim references binding
    the oversight event to durable evidence; defaults to ``[]`` so a
    freshly-created event can be progressively enriched before sealing.
    """

    schema_version: Literal["relay.human_oversight_event.v1"]
    oversight_id: UUID
    project_id: UUID
    run_id: UUID | None = None
    ai_system_classification_id: UUID | None = None
    oversight_kind: Literal[
        "pre_action_review",
        "post_action_review",
        "escalation",
        "override",
        "manual_classification",
        "content_review",
    ]
    actor_user_id: UUID | None = None
    decision: str | None = None
    rationale: str | None = None
    evidence_refs: list[Any] = Field(default_factory=list)
    occurred_at: Rfc3339Datetime


class DataQualityCheck(_RelayEnvelope):
    """Per-dataset data-quality check row (spec AE lines 5510-5525;
    VAL-V2M01-031).

    ``check_kind`` is the closed seven-member enum and ``outcome`` is the
    closed five-member enum, both mirrored from the SQL CHECK constraints.
    ``evaluator`` follows the spec narrative: canonical forms are
    ``code:<module>.<fn>:vN`` for a code-based check and
    ``human:<user_id>`` for a human-evaluated check; the wire-format layer
    does not lock the evaluator grammar.
    """

    schema_version: Literal["relay.data_quality_check.v1"]
    data_quality_check_id: UUID
    project_id: UUID
    dataset_id: UUID | None = None
    check_kind: Literal[
        "lineage",
        "representativeness",
        "duplicate_detection",
        "schema_conformance",
        "pii_minimization",
        "licensing",
        "staleness",
    ]
    check_name: str
    inputs_ref: str | None = None
    outcome: Literal["pass", "fail", "warn", "skipped", "error"]
    metric_value: float | None = None
    threshold_value: float | None = None
    evaluator: str
    evidence_refs: list[Any] = Field(default_factory=list)
    performed_at: Rfc3339Datetime


class DataProvenanceRecord(_RelayEnvelope):
    """Per-dataset data-provenance row (spec AE lines 5527-5539;
    VAL-V2M01-032).

    ``source_kind`` is the closed six-member enum mirrored from the SQL
    CHECK constraint. ``license_ref`` is the canonical license identifier
    (SPDX expression preferred, e.g. ``"Apache-2.0"`` / ``"CC-BY-4.0"``) or
    a customer license-registry URI; the wire-format layer does not lock
    the grammar.
    """

    schema_version: Literal["relay.data_provenance_record.v1"]
    provenance_id: UUID
    project_id: UUID
    dataset_id: UUID
    source_kind: Literal[
        "first_party",
        "licensed",
        "public_domain",
        "web_scrape",
        "synthetic",
        "user_generated",
    ]
    license_ref: str | None = None
    acquired_at: Rfc3339Datetime | None = None
    acquired_by_user_id: UUID | None = None
    notes: str | None = None
    evidence_refs: list[Any] = Field(default_factory=list)


__all__ = [
    "Actor",
    "AssertionDefinition",
    "ContractResult",
    "DataProvenanceRecord",
    "DataQualityCheck",
    "EmbeddingSpan",
    "ErrorEnvelope",
    "EvalRunScopeState",
    "EventLogEntry",
    "EvidenceBundle",
    "EvidenceBundleRegistry",
    "EvidenceBundleScopeState",
    "EvidenceClaim",
    "EvidenceLegalHold",
    "EvidenceTimestamp",
    "GateDecision",
    "GateDecisionDraft",
    "GatePolicy",
    "GateRound",
    "GateRoundScopeState",
    "HttpStatus4xx5xx",
    "HumanOversightEvent",
    "IdempotencyRecord",
    "Incident",
    "Manifest",
    "ManifestVersion",
    "ModelCallSpan",
    "NonEmptyStr",
    "RedactionPolicy",
    "RedactionPolicyMatcherJsonPointer",
    "RedactionPolicyMatcherRegex",
    "RELAY_ERROR_CODE_PATTERN",
    "RelayErrorCodeStr",
    "RelayUnknownEnumValueError",
    "ReleaseScopeState",
    "ReplayCase",
    "ReplayCaseScopeState",
    "ReplayFixture",
    "ReplayResult",
    "RetrievalSpan",
    "RootCauseHypothesis",
    "RunResult",
    "RunScopeState",
    "ScopeState",
    "Sha256Hash",
    "SHA256_HASH_PATTERN",
    "Span",
    "ToolCallSpan",
    "TransparencyLogEntry",
    "ULID_PATTERN",
    "Ulid",
    "canonical_bytes",
    "serialize_event_log_entry_canonical",
    "serialize_replay_fixture_canonical",
]
