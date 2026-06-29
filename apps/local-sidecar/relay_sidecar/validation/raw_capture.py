"""Server-side raw_capture rejection at the ingest boundary (M08-W8).

VAL-V2M08-029 / 030 / 031 (operation contract.md:3675-3706) require the
sidecar ingest endpoints to perform a server-side validation pass that
rejects raw plaintext writes to the canonical raw-eligible span fields
(``model_call.input``, ``model_call.output``, ``tool_call.args``,
``tool_call.result``, ``retrieval.documents``) when the active redaction
policy carries ``raw_capture: false`` -- even if an SDK incorrectly
forwarded raw bytes.

This is **defense in depth** behind the SDK-side redaction at
:mod:`relay.redaction`. The SDK is the first line of defense; this
module is the wire-boundary backstop demanded by CLAUDE.md keystone
invariant #7 ("default-deny raw capture") and spec G.1.

Contract surface:

  - :func:`evaluate_raw_capture` inspects a single span body against a
    parsed redaction policy and returns either ``None`` (accept) or a
    structured :class:`RawCaptureRejection` whose ``code`` is the
    word-form token ``RELAY-INGEST-RAWCAPTURE-DENIED`` (HTTP 422,
    spec G.1 lines 4108-4114). Word-form codes follow the precedent
    set by ``RELAY-EVID-SIGCOUNT-EXCEEDED`` and
    ``RELAY-EVID-MISSING-TRUST-ANCHOR`` (numeric registry refuses
    word-form codes by design; see
    ``packages/schemas/raw/relay-error-codes.yaml:112-121``).

  - A value is treated as a **raw plaintext write** when it appears in
    one of the canonical raw-eligible fields and is NOT already in a
    sanctioned redacted shape (digest-only reference, redact placeholder,
    or a known HMAC-SHA-256 hex digest of declared length).

  - VAL-V2M08-031: raw writes are permitted only when ALL THREE
    preconditions hold on the active policy:
      1. ``raw_capture is True``
      2. ``dpa_ref`` is present + non-empty
      3. ``approver_user_id`` is present + non-empty
    Removing any one yields ``RELAY-INGEST-RAWCAPTURE-DENIED`` with
    ``reason`` naming the missing precondition.

The active policy is supplied per request. The OSS local profile passes
it as ``applied_redaction_policy`` in the ingest request body (the SDK
attaches the policy it used to redact); hosted Relay loads from
``redaction_policies`` for the project. Both paths funnel through
:func:`evaluate_raw_capture`.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

# Word-form error code (see module docstring for why numeric registry
# does NOT carry this code).
RAW_CAPTURE_DENIED_CODE: Final[str] = "RELAY-INGEST-RAWCAPTURE-DENIED"

# HTTP status code per spec G.1 lines 4108-4114.
RAW_CAPTURE_DENIED_HTTP_STATUS: Final[int] = 422

# The canonical raw-eligible span fields (spec G.2
# ``applies_to_fields``). These are the field paths that, when the
# active policy disallows raw capture, MUST NOT carry plaintext.
RAW_ELIGIBLE_SPAN_PATHS: Final[tuple[tuple[str, ...], ...]] = (
    ("model_call", "input"),
    ("model_call", "output"),
    ("tool_call", "args"),
    ("tool_call", "result"),
    ("retrieval", "documents"),
)

# Default redact placeholder per spec G.2 example. Strings exactly
# matching this are presumed already redacted and not flagged as raw.
_DEFAULT_REDACT_PLACEHOLDER: Final[str] = "<redacted>"

# HMAC-SHA-256 hex output: 64 lowercase hex characters. A leaf that
# matches this regex is presumed to be a hash digest (action == "hash"
# in the SDK) and is NOT a raw write.
_HEX64_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RawCaptureRejection:
    """Structured rejection returned by :func:`evaluate_raw_capture`.

    Mirrors the envelope shape consumed by FastAPI ``JSONResponse``
    construction at the sidecar ingest endpoints (runtime.py).
    """

    code: str
    http_status: int
    message: str
    details: dict[str, Any]

    def as_envelope(self) -> dict[str, Any]:
        """Render as the response body the ingest endpoint returns."""
        return {
            "code": self.code,
            "error_class": self.code,
            "message": self.message,
            "details": self.details,
        }


def _is_redacted_shape(value: Any, *, placeholder: str) -> bool:
    """Return True when ``value`` is in a sanctioned redacted shape.

    Sanctioned shapes:

      * Digest-only reference: a dict with the single key
        ``_digest_sha256`` whose value is a 64-char lowercase hex
        string. Emitted by :mod:`relay.redaction` for binary leaves
        (VAL-W4-025) and by callers that pre-compute a content hash.
      * The redact placeholder string (exact match against the active
        policy's ``action_policy.redact.placeholder``, default
        ``"<redacted>"``).
      * A 64-char lowercase hex string: an HMAC-SHA-256 hex digest
        produced by the ``action == "hash"`` matcher path. We cannot
        verify the salt here (server side has no plaintext), but the
        shape is the canonical hash output the SDK emits.
      * None / bool / int / float: not raw plaintext (numeric and
        boolean leaves are non-redactable scalars; the matcher would
        not have been applied to them anyway).

    Anything else (a non-empty string that is not the placeholder and
    not a 64-char hex digest, or an unrecognised dict shape) is treated
    as raw.
    """
    if value is None:
        return True
    if isinstance(value, bool | int | float):
        return True
    if isinstance(value, dict):
        # Digest-only reference is the only sanctioned dict shape.
        if set(value.keys()) == {"_digest_sha256"}:
            inner = value["_digest_sha256"]
            if isinstance(inner, str) and _HEX64_RE.match(inner):
                return True
        return False
    if isinstance(value, str):
        if value == placeholder:
            return True
        if _HEX64_RE.match(value):
            return True
        # Empty string is a degenerate but non-revealing case; treat
        # as redacted (no plaintext to leak).
        return value == ""
    # Lists are descended by the caller; reaching here means the
    # caller deferred and we should treat the list itself as a
    # non-leaf -- but :func:`_iter_string_leaves` only yields leaves,
    # so this branch is defensive.
    return False


def _iter_string_leaves(value: Any, *, path: tuple[str, ...] = ()) -> Any:
    """Yield ``(path, leaf_value)`` for every non-container leaf in ``value``.

    The result is a generator. ``path`` accumulates dict keys + list
    indices (as ``str(idx)``) so the rejection envelope can pinpoint the
    offending field for caller debugging.

    ITERATIVE (explicit stack), NOT recursive: this gate runs at the ingest
    boundary BEFORE the nesting-depth cap (``validate_span_size_and_depth``),
    so a ``yield from`` recursion turned the keystone-#7 raw_capture
    default-deny control into an unhandled-500 DoS -- a ~3000-deep nested body
    (~6 KB, well under the body and 16-level depth caps) exceeds CPython's
    1000-frame recursion limit and raises ``RecursionError``. The explicit
    stack mirrors the iterative ``_measure_depth`` in ingest_limits.py and
    cannot overflow. Children are pushed in REVERSE so the pop order preserves
    the original depth-first, left-to-right leaf-yield order (the path the
    rejection envelope reports).
    """
    stack: list[tuple[tuple[str, ...], Any]] = [(path, value)]
    while stack:
        cur_path, cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in reversed(list(cur.items())):
                stack.append((cur_path + (str(k),), v))
        elif isinstance(cur, list | tuple):
            for idx in range(len(cur) - 1, -1, -1):
                stack.append((cur_path + (str(idx),), cur[idx]))
        else:
            yield (cur_path, cur)


def _walk_dotted_path(span: dict[str, Any], dotted: tuple[str, ...]) -> Any:
    """Return the value at ``dotted`` inside ``span``, or ``None`` if absent.

    The span shape we expect mirrors the spec G.2 ``applies_to_fields``
    listing: top-level groups (``model_call``, ``tool_call``,
    ``retrieval``) with nested ``input``/``output``/``args``/``result``/
    ``documents`` fields.

    Hosted Relay span envelopes may carry the fields directly OR inside
    a top-level ``attributes`` dict (OTel-friendly). Both shapes are
    consulted. Returns ``None`` for either-missing.
    """
    if not isinstance(span, dict):
        return None
    # Direct nested lookup.
    cursor: Any = span
    for token in dotted:
        if not isinstance(cursor, dict) or token not in cursor:
            cursor = None
            break
        cursor = cursor[token]
    if cursor is not None:
        return cursor
    # Fall back to ``attributes.<dotted joined by '.'>`` (flat).
    attrs = span.get("attributes")
    if isinstance(attrs, dict):
        flat = ".".join(dotted)
        if flat in attrs:
            return attrs[flat]
    # Fall back to ``attributes.<group>.<leaf>`` nested.
    if isinstance(attrs, dict):
        cursor = attrs
        for token in dotted:
            if not isinstance(cursor, dict) or token not in cursor:
                return None
            cursor = cursor[token]
        return cursor
    return None


def _resolve_redact_placeholder(policy: dict[str, Any]) -> str:
    """Return the policy's redact placeholder string, defaulting per spec G.2."""
    ap = policy.get("action_policy")
    if isinstance(ap, dict):
        rd = ap.get("redact")
        if isinstance(rd, dict):
            ph = rd.get("placeholder")
            if isinstance(ph, str):
                return ph
    return _DEFAULT_REDACT_PLACEHOLDER


def _check_preconditions_for_raw_capture(
    policy: dict[str, Any],
) -> str | None:
    """Return the missing precondition name, or None when all three are present.

    Precondition order matches VAL-V2M08-031:
      1. raw_capture is True
      2. dpa_ref non-empty
      3. approver_user_id non-empty
    """
    if policy.get("raw_capture") is not True:
        return "raw_capture_false"
    dpa_ref = policy.get("dpa_ref")
    if not (isinstance(dpa_ref, str) and dpa_ref.strip()):
        return "dpa_ref_missing"
    approver = policy.get("approver_user_id")
    if not (isinstance(approver, str) and approver.strip()):
        return "approver_user_id_missing"
    return None


def evaluate_raw_capture(
    *,
    span: dict[str, Any],
    policy: dict[str, Any] | None,
) -> RawCaptureRejection | None:
    """Inspect ``span`` against ``policy`` and return a rejection or None.

    Returns ``None`` (accept) when:
      * The policy permits raw capture AND all three preconditions
        are present (VAL-V2M08-031 accept branch), OR
      * The policy disallows raw capture AND every raw-eligible field
        in the span is either absent or in a sanctioned redacted shape
        (VAL-V2M08-030).

    Returns a :class:`RawCaptureRejection` (HTTP 422) when:
      * The policy disallows raw capture and some raw-eligible field
        carries unredacted text (VAL-V2M08-029), OR
      * The policy claims raw_capture but a precondition is missing
        (VAL-V2M08-031 reject branch).

    When ``policy`` is ``None`` we default-deny raw capture: per
    CLAUDE.md keystone invariant #7, the absence of a policy is
    equivalent to ``raw_capture: false``. This protects the wire path
    from a forged or omitted policy attachment.
    """
    if policy is None:
        # No policy -> default-deny. Synthesise the minimal disallow-state.
        policy = {"raw_capture": False}
    if not isinstance(policy, dict):
        return RawCaptureRejection(
            code=RAW_CAPTURE_DENIED_CODE,
            http_status=RAW_CAPTURE_DENIED_HTTP_STATUS,
            message=(
                "active redaction policy envelope is not a dict; raw "
                "capture denied (default-deny per keystone invariant #7)"
            ),
            details={"reason": "policy_envelope_wrong_type"},
        )

    raw_capture_requested = policy.get("raw_capture") is True

    if raw_capture_requested:
        # VAL-V2M08-031: precondition gate. Missing precondition -> reject.
        missing = _check_preconditions_for_raw_capture(policy)
        if missing is not None:
            return RawCaptureRejection(
                code=RAW_CAPTURE_DENIED_CODE,
                http_status=RAW_CAPTURE_DENIED_HTTP_STATUS,
                message=(
                    "raw_capture=true requires raw_capture=true AND "
                    "non-empty dpa_ref AND non-empty approver_user_id; "
                    f"missing precondition: {missing}"
                ),
                details={
                    "reason": missing,
                    "policy_version": policy.get("policy_version"),
                },
            )
        # All three preconditions met -> accept (raw writes permitted).
        return None

    # raw_capture is false (or absent): every raw-eligible field MUST
    # be redacted-shape or absent. Walk each canonical field; for list
    # / dict fields, descend to leaves and check each one.
    placeholder = _resolve_redact_placeholder(policy)
    for dotted in RAW_ELIGIBLE_SPAN_PATHS:
        field_value = _walk_dotted_path(span, dotted)
        if field_value is None:
            continue
        for leaf_path, leaf_value in _iter_string_leaves(field_value):
            if not _is_redacted_shape(leaf_value, placeholder=placeholder):
                return RawCaptureRejection(
                    code=RAW_CAPTURE_DENIED_CODE,
                    http_status=RAW_CAPTURE_DENIED_HTTP_STATUS,
                    message=(
                        "span carries unredacted text in a raw-eligible "
                        "field while the active policy disallows raw "
                        "capture (raw_capture=false)"
                    ),
                    details={
                        "reason": "unredacted_raw_field",
                        "field_path": ".".join(dotted)
                        + ("." + ".".join(leaf_path) if leaf_path else ""),
                        "policy_version": policy.get("policy_version"),
                    },
                )
    return None


def evaluate_raw_capture_on_request(
    *,
    body: dict[str, Any],
) -> RawCaptureRejection | None:
    """Helper invoked by the sidecar ingest endpoints.

    Reads ``body['applied_redaction_policy']`` as the active policy.
    Per-span: prefers the per-span ``applied_redaction_policy``
    override if present (matches OTel-style per-span attributes), else
    falls back to the request-level policy. Returns the first
    rejection encountered, or None on accept.
    """
    request_policy = body.get("applied_redaction_policy")
    spans = body.get("spans")
    candidates: list[dict[str, Any]] = []
    if isinstance(spans, list):
        for span in spans:
            if isinstance(span, dict):
                candidates.append(span)
    else:
        # /v1/ingest/runs: the body itself may carry the canonical
        # raw-eligible fields at the root (no span wrapper).
        candidates.append(body)
    for span in candidates:
        per_span_policy = span.get("applied_redaction_policy")
        active_policy = (
            per_span_policy if isinstance(per_span_policy, dict) else request_policy
        )
        rejection = evaluate_raw_capture(span=span, policy=active_policy)
        if rejection is not None:
            return rejection
    return None


__all__ = [
    "RAW_CAPTURE_DENIED_CODE",
    "RAW_CAPTURE_DENIED_HTTP_STATUS",
    "RAW_ELIGIBLE_SPAN_PATHS",
    "RawCaptureRejection",
    "evaluate_raw_capture",
    "evaluate_raw_capture_on_request",
]
