"""Anti-bypass guard for event_log_entries payloads (W2.5 / VAL-W2-057).

Per CLAUDE.md "REQUIRED GUARD TESTS" + CLAUDE.md banned-pattern #8: the
sidecar MUST refuse to record an event whose payload (post-redaction)
contains any of the canonical bypass-marker tokens::

    --no-verify   --no-gpg-sign   --skip-hooks
    pytest.mark.skip
    # TODO        # FIXME         # HACK

The refusal returns the descriptive error class
``RELAY-SIDECAR-BYPASS-MARKER-DETECTED`` (numeric wire-format code
``RELAY-SIDECAR-009``). The ONLY way to record a payload that legitimately
contains such a token is to set ``event_kind = 'operator_override'`` and
attach an ``operator_override_claim`` whose resolved actor is human +
org_admin.

This module exposes a pure-Python guard ``screen_payload`` that
``transactional_db_write`` and the state engine call BEFORE issuing the
INSERT. The SQLite layer additionally carries a defence-in-depth CHECK on
raw plaintext patterns (VAL-W2-036) but anti-bypass is enforced in Python
because (a) the token list is richer than a SQL LIKE can express
cleanly, (b) the legitimate operator_override path requires reading the
actors table, which is awkward in a trigger.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import aiosqlite

# Canonical bypass-marker token list. Order is presentation-only; matching
# is set-membership against the tokenized payload string. The tokens are
# matched as case-sensitive whole tokens delimited by whitespace, end of
# string, JSON syntax, or punctuation -- a substring like
# "no_verifycation" must NOT match "--no-verify".
#
# Token categories:
#   - git-hook bypass flags  : --no-verify, --no-gpg-sign, --skip-hooks
#   - test-runner skip       : pytest.mark.skip
#   - source-file markers    : # TODO, # FIXME, # HACK (with literal "# " prefix
#                              so a string like "TODO" alone does not match;
#                              the contract pins the comment form)
#
# The list is duplicated in tests/test_anti_bypass.py as a separate copy
# so a token added here without a matching test is impossible.
BYPASS_MARKERS: tuple[str, ...] = (
    "--no-verify",
    "--no-gpg-sign",
    "--skip-hooks",
    "pytest.mark.skip",
    "# TODO",
    "# FIXME",
    "# HACK",
)

# Pre-compiled regexes, one per marker. Each pattern requires a boundary
# (start-of-string, end-of-string, whitespace, or one of the JSON syntax
# characters [],{}":, plus newline) on each side. The CLI-flag and comment
# markers naturally start with -- or # so the left boundary is implicit;
# we still require a right boundary so a longer flag like --no-verifyx
# does NOT trip on --no-verify.
def _compile(token: str) -> re.Pattern[str]:
    # Boundaries: start-of-string, end-of-string, ASCII whitespace, OR
    # any of the JSON syntax punctuation that brackets a string literal.
    # Use re.escape on the token itself so internal hyphens / dots are literal.
    boundary = r"(?:^|[\s,\[\]{}\"\\\\:])"
    right_boundary = r"(?=$|[\s,\[\]{}\"\\\\:])"
    return re.compile(boundary + re.escape(token) + right_boundary)


_MARKER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (m, _compile(m)) for m in BYPASS_MARKERS
)

# Error envelope tokens. Numeric wire-format ``code`` AND descriptive
# ``error_class`` per the existing W2.1 errors.py pattern. The numeric
# code RELAY-SIDECAR-009 is registered in
# packages/schemas/raw/relay-error-codes.yaml; the descriptive class is
# the contract-text token VAL-W2-057 expects.
BYPASS_MARKER_DETECTED_CODE: str = "RELAY-SIDECAR-009"
BYPASS_MARKER_DETECTED_CLASS: str = "RELAY-SIDECAR-BYPASS-MARKER-DETECTED"

# Special event_kind that, paired with a valid operator_override_claim,
# bypasses the anti-bypass guard. Test surface: see test_anti_bypass.py.
OPERATOR_OVERRIDE_EVENT_KIND: str = "operator_override"


@dataclass(frozen=True)
class BypassScanResult:
    """Outcome of a payload anti-bypass scan.

    Attributes:
        ok: True when the payload is permitted.
        detected_tokens: The markers found (empty when ok=True OR when the
            override path permitted an otherwise-flagged payload).
        reason_kind: Structured reason on rejection. None on accept.
    """

    ok: bool
    detected_tokens: tuple[str, ...] = ()
    reason_kind: str | None = None


class AntiBypassRejection(Exception):
    """Raised by ``screen_payload`` when the payload carries bypass markers.

    Carries both the numeric and descriptive forms of the error code so
    the HTTP / CLI surface can populate the canonical error envelope.
    """

    code: str = BYPASS_MARKER_DETECTED_CODE
    error_class: str = BYPASS_MARKER_DETECTED_CLASS

    def __init__(
        self,
        *,
        message: str,
        detected_tokens: tuple[str, ...],
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detected_tokens = detected_tokens

    def to_envelope(self) -> dict[str, object]:
        return {
            "code": self.code,
            "error_class": self.error_class,
            "message": self.message,
            "details": {
                "detected_tokens": list(self.detected_tokens),
            },
        }


def detect_bypass_markers(text: str) -> tuple[str, ...]:
    """Return the bypass markers detected in ``text`` (deterministic order).

    The scan is exact-token: regex with whitespace/punctuation boundaries.
    Substring near-misses (e.g. "no-verifycation") do NOT match.
    """
    found: list[str] = []
    for token, pattern in _MARKER_PATTERNS:
        if pattern.search(text):
            found.append(token)
    return tuple(found)


def _payload_to_scannable_text(payload: dict[str, Any]) -> str:
    """Render a payload dict to the string the scanner inspects.

    Strategy: emit the payload as canonical JSON (sort_keys, compact
    separators), matching the on-row encoding. This guarantees the
    scanner sees exactly the bytes that would have been INSERTed had
    we not blocked.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _scan(text: str) -> BypassScanResult:
    found = detect_bypass_markers(text)
    if not found:
        return BypassScanResult(ok=True)
    return BypassScanResult(
        ok=False,
        detected_tokens=found,
        reason_kind=BYPASS_MARKER_DETECTED_CLASS,
    )


async def _is_override_actor(
    conn: aiosqlite.Connection,
    *,
    actor_identity_hash: str,
) -> bool:
    """Return True iff the actor is a non-revoked human org_admin.

    Reads the actors registry installed by W2.4 migration 0006. Schema:
    actors(identity_hash PK, kind, org_admin INT, registered_at, revoked_at).
    """
    async with conn.execute(
        "SELECT 1 FROM actors "
        "WHERE identity_hash = ? "
        "AND kind = 'human' "
        "AND org_admin = 1 "
        "AND revoked_at IS NULL",
        (actor_identity_hash,),
    ) as cur:
        row = await cur.fetchone()
    return row is not None


async def screen_payload(
    *,
    payload: dict[str, Any] | None,
    event_kind: str | None,
    operator_override_claim: dict[str, Any] | None = None,
    actors_connection: aiosqlite.Connection | None = None,
) -> BypassScanResult:
    """Validate a payload against the bypass-marker token list.

    Args:
        payload: The event_log_entries.payload dict that would be INSERTed.
            None or {} pass trivially.
        event_kind: The event_log_entries.event_kind column. When equal to
            ``operator_override`` AND a valid claim is supplied, the scan
            short-circuits to ``ok=True`` after verifying the override.
        operator_override_claim: When event_kind = 'operator_override',
            this dict MUST carry an ``actor_identity_hash`` field whose
            value resolves via the actors registry to a non-revoked human
            org_admin. Missing field, non-resolving hash, or wrong kind
            yields ``ok=False`` even if the payload would otherwise pass.
        actors_connection: aiosqlite connection used to resolve the
            operator_override_claim. Required when event_kind is
            'operator_override'.

    Returns:
        ``BypassScanResult(ok=True)`` when permitted; on rejection,
        ``ok=False`` with the detected tokens and reason kind.
    """
    if payload is None or not payload:
        return BypassScanResult(ok=True)

    text = _payload_to_scannable_text(payload)
    raw = _scan(text)
    if raw.ok:
        return raw

    # Operator-override path: the payload IS flagged, but a registered
    # human org_admin is explicitly recording it for forensic reasons.
    if event_kind == OPERATOR_OVERRIDE_EVENT_KIND:
        if operator_override_claim is None or actors_connection is None:
            return BypassScanResult(
                ok=False,
                detected_tokens=raw.detected_tokens,
                reason_kind=BYPASS_MARKER_DETECTED_CLASS,
            )
        actor_hash = operator_override_claim.get("actor_identity_hash")
        if not isinstance(actor_hash, str) or not actor_hash:
            return BypassScanResult(
                ok=False,
                detected_tokens=raw.detected_tokens,
                reason_kind=BYPASS_MARKER_DETECTED_CLASS,
            )
        approved = await _is_override_actor(
            actors_connection, actor_identity_hash=actor_hash
        )
        if approved:
            return BypassScanResult(ok=True)
        return BypassScanResult(
            ok=False,
            detected_tokens=raw.detected_tokens,
            reason_kind=BYPASS_MARKER_DETECTED_CLASS,
        )

    return raw


def raise_on_reject(result: BypassScanResult) -> None:
    """Raise ``AntiBypassRejection`` when ``result.ok`` is False.

    Convenience helper for call sites that want to surface the rejection
    as an exception instead of an Either-style return value.
    """
    if result.ok:
        return
    raise AntiBypassRejection(
        message=(
            "anti-bypass: payload contains forbidden marker(s) "
            f"{list(result.detected_tokens)!r}; legitimate recording requires "
            f"event_kind='{OPERATOR_OVERRIDE_EVENT_KIND}' + operator_override_claim "
            "resolving to a human org_admin actor"
        ),
        detected_tokens=result.detected_tokens,
    )


__all__ = [
    "AntiBypassRejection",
    "BYPASS_MARKERS",
    "BYPASS_MARKER_DETECTED_CLASS",
    "BYPASS_MARKER_DETECTED_CODE",
    "BypassScanResult",
    "OPERATOR_OVERRIDE_EVENT_KIND",
    "detect_bypass_markers",
    "raise_on_reject",
    "screen_payload",
]
