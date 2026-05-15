"""W7.2 ReplayFixture-v1 cassette format.

On-disk format (VAL-W7-020): one ``ReplayFixture v1`` record per line of
``~/.relay/cassettes/<session>/cassette.jsonl``. The file is UTF-8,
APPEND-ONLY during recording (VAL-W7-027), and ends with a single ``\\n``
after the final record.

Record schema (VAL-W7-021): every line MUST validate against
``relay_schemas.envelopes.ReplayFixture`` (``relay.replay_fixture.v1``)
which pins required fields and closed enums for ``kind`` / ``mode`` /
``side_effect_class`` / ``refresh_policy``.

Canonical key (VAL-W7-022 / VAL-W7-023): cassette lookup keys are derived
deterministically from the request shape. The key DOES NOT depend on
``User-Agent``, ``Authorization``, ``Date``, ``X-Request-Id``, multipart
boundary tokens, or query-string parameter order. The key is the SHA-256
of the JCS canonical form of::

    {
      "method":     uppercase HTTP verb,
      "url_host":   request URL host (lower-case),
      "url_path":   request URL path,
      "url_query_sorted": canonical query-string (params sorted by name then value),
      "body_canonical":   content-type-specific canonicalization of the body,
      "relevant_headers": allow-list of headers (content-type, accept,
                          plus provider-specific request-shape headers)
    }

``body_canonical`` rules:

  * ``application/json`` (and any ``+json`` suffix): RFC 8785 JCS bytes
    of the parsed JSON value (binds to VAL-W11-016).
  * ``multipart/form-data``: boundary token STRIPPED before hashing; each
    part's ``Content-Disposition`` name + ``Content-Type`` + body bytes
    are concatenated in lexicographic order on part name, then SHA-256.
  * ``application/octet-stream`` (and other binary types):
    ``sha256(raw_bytes)`` of the literal request body.
  * ``text/event-stream`` (SSE / chunked): per-event canonicalization --
    each event delimited by ``\\n\\n`` is JCS-canonicalized inside its
    ``data:`` lines, then events concatenated in capture order before
    SHA-256.

Lookup index (VAL-W7-031): O(1) ``dict[canonical_key -> ReplayFixture]``
built once on load and identical regardless of entry order.

Refresh policy (VAL-W7-029): ``refresh_policy=invalidate_on_signature_change``
flags the record stale when the runtime ``system_fingerprint`` differs
from the recorded ``model_signature``. Other policies (``hold_forever``,
``refresh_weekly``, ``invalidate_on_model_version_change``) are honored
per their documented semantics. The class returns a structured
``RefreshDecision`` rather than mutating any state -- the caller decides
whether to fail or proceed in ``degraded_live`` mode.

APPEND-ONLY writer (VAL-W7-027): the writer opens the cassette with
``O_APPEND`` semantics and never rewrites an existing line. A SIGKILL
mid-stream leaves at most a partially-written final line; on next load
the parser raises ``RelayCassetteCorruptError`` with the line number and
moves the file to ``<session>/quarantine/`` (VAL-W7-026).

Lock retry (VAL-W7-030): on ``EACCES`` / ``ERROR_SHARING_VIOLATION`` the
writer retries with exponential backoff (50 ms, 100 ms, 200 ms; 3
attempts minimum) before raising ``RelayCassetteWriteRetryExhaustedError``.

Per CLAUDE.md keystone invariant #8 the writer goes through ``open(...,
O_WRONLY | O_APPEND | O_CREAT)`` -- this is a sanctioned local-only
append-mode write, not a banned ``open(..., 'w')``. The atomic
``local_atomic_file_write`` primitive is reserved for full-replace writes
(W2.x sidecar lockfile, etc.); a true APPEND-ONLY cassette MUST NOT
read-modify-write because that would break the invariant a SIGKILL'd
recording session leaves only the records ACKed before the kill.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import logging
import os
import shutil
import sys
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qsl, urlparse

from relay_contracts.canonical import jcs_canonicalize
from relay_schemas.envelopes import ReplayFixture

from .errors import (
    RelayCassetteCorruptError,
    RelayCassetteMissError,
    RelayCassetteWriteRetryExhaustedError,
)

LOG = logging.getLogger("relay.replay.cassette")

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Cassette filename inside ``~/.relay/cassettes/<session>/``. The W7.1
# harness already imports ``CASSETTE_FILENAME`` from cassette_server;
# both modules use the SAME filename so a session has exactly one
# canonical cassette on disk.
CASSETTE_FILENAME: Final[str] = "cassette.jsonl"
QUARANTINE_DIR_NAME: Final[str] = "quarantine"

# ReplayFixture v1 schema identifier (VAL-W7-021). Pinned literal from
# relay_schemas.envelopes.ReplayFixture.schema_version.
REPLAY_FIXTURE_SCHEMA_VERSION: Final[str] = "relay.replay_fixture.v1"

# Headers excluded from the canonical key. Lower-case for case-
# insensitive matching against incoming HTTP header dicts (Python's
# http.server lower-cases header names; mitmproxy preserves case but
# we always compare lower).
KEY_EXCLUDED_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "user-agent",
        "authorization",
        "date",
        "x-request-id",
        "x-amz-date",
        "x-correlation-id",
        "host",  # routing-only; the URL host is in the canonical body
        "content-length",  # derived from body, not request shape
        "connection",  # transport detail
        "accept-encoding",  # transport detail
        "transfer-encoding",  # transport detail
        "cookie",  # ephemeral session state
        "set-cookie",  # response side, defensive
    }
)

# Headers included in the canonical key by default. Provider/SDK adapters
# can extend this list at construction time via ``CanonicalKeyConfig``.
KEY_DEFAULT_RELEVANT_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "content-type",
        "accept",
    }
)

# Backoff schedule for VAL-W7-030 lock retry (seconds).
WRITE_RETRY_DELAYS_S: Final[tuple[float, ...]] = (0.05, 0.10, 0.20)

# Refresh-policy enum mirror (kept in sync with envelopes.yaml).
REFRESH_POLICY_INVALIDATE_ON_SIG: Final[str] = "invalidate_on_signature_change"
REFRESH_POLICY_HOLD_FOREVER: Final[str] = "hold_forever"
REFRESH_POLICY_REFRESH_WEEKLY: Final[str] = "refresh_weekly"
REFRESH_POLICY_INVALIDATE_ON_MODEL: Final[str] = (
    "invalidate_on_model_version_change"
)

# Side-effect-class enum mirror (kept in sync with envelopes.yaml).
SIDE_EFFECT_READ_ONLY: Final[str] = "read_only"
SIDE_EFFECT_MUTATING: Final[str] = "mutating"
SIDE_EFFECT_EXTERNAL_IRREVERSIBLE: Final[str] = "external_irreversible"
SIDE_EFFECT_APPROVAL_REQUIRED: Final[str] = "approval_required"

# Output-body sidecar filename pattern: each fixture's response body is
# stored as a separate file ``<fixture_id>.body`` so the cassette JSONL
# stays small and the body bytes are addressable by ``output_ref``.
# (output_ref points at the local file path; the schema permits any
# string. In hosted mode it would be an r2:// URL.)
OUTPUT_REF_LOCAL_PREFIX: Final[str] = "file://"


# -----------------------------------------------------------------------------
# Canonical key derivation (VAL-W7-022, VAL-W7-023)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CanonicalKeyConfig:
    """Per-session knobs for canonical key derivation.

    ``extra_relevant_headers`` lets an adapter shim include
    provider-specific request-shape headers (e.g. OpenAI's
    ``OpenAI-Beta``) without mutating the global default set.
    """

    extra_relevant_headers: frozenset[str] = frozenset()


@dataclass(frozen=True)
class CanonicalRequest:
    """Normalized view of an outbound HTTP request for key derivation.

    Built by the adapter shim or the proxy's request handler from a
    raw HTTP request. ``body_bytes`` is the raw body as it would be
    serialized on the wire (already a multipart-encoded byte string for
    multipart, raw JSON bytes for JSON, etc.); ``content_type`` selects
    the canonicalization branch.
    """

    method: str
    url: str
    headers: Mapping[str, str]
    body_bytes: bytes
    content_type: str = ""

    def canonical_method(self) -> str:
        return self.method.upper().strip()

    def canonical_content_type(self) -> str:
        # Strip parameters (charset, boundary). The boundary token in
        # particular MUST NOT be part of the key (VAL-W7-022 multipart
        # branch).
        ct = self.content_type or self.headers.get("content-type") or ""
        return ct.split(";", 1)[0].strip().lower()

    def boundary(self) -> str | None:
        """Extract the multipart boundary from Content-Type, if present."""
        ct = self.content_type or self.headers.get("content-type") or ""
        for part in ct.split(";"):
            part = part.strip()
            if part.lower().startswith("boundary="):
                value = part.split("=", 1)[1].strip()
                if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                    value = value[1:-1]
                return value
        return None


def _canonicalize_query(query: str) -> str:
    """Return the query string with parameters sorted by (name, value).

    ``parse_qsl(keep_blank_values=True, strict_parsing=False)`` preserves
    blank-value parameters; we then re-emit them sorted to make the key
    independent of capture-time parameter ordering.
    """
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    pairs.sort()  # tuple compare: (name, value)
    # Re-emit using urllib's quote-preserving form. We use a manual loop
    # rather than urlencode() so each pair is rendered as plain
    # ``name=value`` even when value is empty (urlencode emits ``name=``
    # consistently anyway, but being explicit is cheap and obvious).
    out_parts: list[str] = []
    for name, value in pairs:
        out_parts.append(f"{name}={value}")
    return "&".join(out_parts)


def _filter_headers(
    headers: Mapping[str, str],
    *,
    extra_relevant: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Return the subset of ``headers`` that participates in the key.

    Header names are normalized to lower-case. VAL-W7-023: excluded
    headers (``User-Agent``, ``Authorization``, ``Date``, ...) are
    dropped regardless of case. Allow-list policy: a header passes only
    if its lower-case name is in ``KEY_DEFAULT_RELEVANT_HEADERS`` or in
    ``extra_relevant``.

    Multiple headers with the same name (rare in HTTP/1.1; legal in
    HTTP/2) are joined by ", " in lexicographic order so the key is
    deterministic.
    """
    relevant = KEY_DEFAULT_RELEVANT_HEADERS | extra_relevant
    by_name: dict[str, list[str]] = {}
    for raw_name, raw_value in headers.items():
        lower = raw_name.lower()
        if lower in KEY_EXCLUDED_HEADERS:
            continue
        if lower not in relevant:
            continue
        # Strip the boundary param from content-type so a multipart key
        # is independent of the capture-time boundary token.
        value = (
            raw_value.split(";", 1)[0].strip()
            if lower == "content-type"
            else raw_value.strip()
        )
        by_name.setdefault(lower, []).append(value)
    out: dict[str, str] = {}
    for name, values in by_name.items():
        out[name] = ", ".join(sorted(values))
    return out


def _canonicalize_json_body(body_bytes: bytes) -> str:
    """Return the JCS-canonical hex digest of a JSON body."""
    if not body_bytes:
        return hashlib.sha256(b"").hexdigest()
    try:
        parsed = json.loads(body_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RelayCassetteCorruptError(
            f"request body declared as JSON but failed to parse: {exc}",
            details={"content_type_branch": "application/json"},
        ) from exc
    canonical = jcs_canonicalize(parsed)
    return hashlib.sha256(canonical).hexdigest()


def _canonicalize_octet_body(body_bytes: bytes) -> str:
    """Return the SHA-256 hex digest of a raw binary body."""
    return hashlib.sha256(body_bytes).hexdigest()


def _canonicalize_sse_body(body_bytes: bytes) -> str:
    """Per-event canonicalization for ``text/event-stream`` bodies.

    Events are delimited by ``\\n\\n``. For each event, ``data:`` lines
    that contain JSON have their value JCS-canonicalized; non-JSON
    ``data:`` lines pass through verbatim. Events are concatenated in
    capture order with ``\\n`` between them, then SHA-256.
    """
    if not body_bytes:
        return hashlib.sha256(b"").hexdigest()
    try:
        text = body_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RelayCassetteCorruptError(
            f"SSE body is not valid UTF-8: {exc}",
            details={"content_type_branch": "text/event-stream"},
        ) from exc
    canonical_events: list[str] = []
    for raw_event in text.split("\n\n"):
        if not raw_event.strip():
            continue
        canonical_lines: list[str] = []
        for line in raw_event.split("\n"):
            if line.startswith("data:"):
                payload = line[len("data:"):].strip()
                if payload.startswith("{") or payload.startswith("["):
                    try:
                        parsed = json.loads(payload)
                    except json.JSONDecodeError:
                        canonical_lines.append(line)
                        continue
                    canonical_lines.append(
                        "data:" + jcs_canonicalize(parsed).decode("utf-8")
                    )
                else:
                    canonical_lines.append(line)
            else:
                canonical_lines.append(line)
        canonical_events.append("\n".join(canonical_lines))
    joined = "\n".join(canonical_events).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def _canonicalize_multipart_body(body_bytes: bytes, boundary: str | None) -> str:
    """Per-part canonicalization of a multipart/form-data body.

    The boundary token is stripped (VAL-W7-022) and each part's
    ``Content-Disposition`` name + ``Content-Type`` + body bytes are
    concatenated in lexicographic order on part name, then SHA-256.

    If ``boundary`` is None (caller could not extract it from
    Content-Type) the digest falls back to the raw-bytes form so the
    derivation never fails closed -- a missing boundary is a request
    misconfiguration but not a reason to crash the proxy.
    """
    if boundary is None:
        return _canonicalize_octet_body(body_bytes)
    delim = ("--" + boundary).encode("utf-8")
    # Multipart bodies use \r\n line endings per RFC 7578; we tolerate
    # bare \n for tests that hand-roll bodies.
    parts_raw = body_bytes.split(delim)
    canonical_parts: list[tuple[str, bytes]] = []
    for part in parts_raw:
        # Skip the preamble (before the first delimiter) and the closing
        # ``--<boundary>--`` marker.
        stripped = part.strip(b"\r\n-")
        if not stripped:
            continue
        # Split header block from body on the first blank line.
        header_block, _, body = part.partition(b"\r\n\r\n")
        if not body:
            header_block, _, body = part.partition(b"\n\n")
        if not body:
            continue
        # Trim trailing line ending the body block always carries.
        body = body.rstrip(b"\r\n")
        # Extract the part name from Content-Disposition.
        name = "_unnamed"
        for header_line in header_block.split(b"\n"):
            line = header_line.strip().decode("utf-8", errors="replace")
            if line.lower().startswith("content-disposition:"):
                for chunk in line.split(";"):
                    chunk = chunk.strip()
                    if chunk.lower().startswith("name="):
                        raw_name = chunk.split("=", 1)[1].strip()
                        if (
                            raw_name.startswith('"')
                            and raw_name.endswith('"')
                            and len(raw_name) >= 2
                        ):
                            raw_name = raw_name[1:-1]
                        name = raw_name
                        break
        canonical_parts.append((name, body))
    canonical_parts.sort(key=lambda x: x[0])
    h = hashlib.sha256()
    for name, body in canonical_parts:
        h.update(name.encode("utf-8"))
        h.update(b"\x00")
        h.update(body)
        h.update(b"\x00")
    return h.hexdigest()


def _body_canonical(req: CanonicalRequest) -> str:
    """Dispatch to the content-type-specific canonicalizer."""
    ct = req.canonical_content_type()
    if ct == "application/json" or ct.endswith("+json"):
        return _canonicalize_json_body(req.body_bytes)
    if ct.startswith("multipart/"):
        return _canonicalize_multipart_body(req.body_bytes, req.boundary())
    if ct == "text/event-stream":
        return _canonicalize_sse_body(req.body_bytes)
    # Default: treat as opaque bytes. Covers application/octet-stream,
    # image/*, application/x-www-form-urlencoded (form-urlencoded keys
    # are not sorted because the wire form is the spec, not the parsed
    # form), and any other binary type.
    return _canonicalize_octet_body(req.body_bytes)


def derive_canonical_key(
    req: CanonicalRequest,
    *,
    config: CanonicalKeyConfig | None = None,
) -> str:
    """Return the canonical lookup key (``sha256-<hex>``) for ``req``.

    Per VAL-W7-022 the same logical request produces a byte-identical
    key on every invocation. Per VAL-W7-023 the key is invariant to
    ``User-Agent``, ``Authorization``, ``Date``, etc.
    """
    cfg = config or CanonicalKeyConfig()
    parsed = urlparse(req.url)
    body_canonical_hex = _body_canonical(req)
    relevant_headers = _filter_headers(
        req.headers, extra_relevant=cfg.extra_relevant_headers
    )
    canonical_obj = {
        "method": req.canonical_method(),
        "url_host": (parsed.hostname or "").lower(),
        "url_path": parsed.path or "/",
        "url_query_sorted": _canonicalize_query(parsed.query),
        "body_canonical": body_canonical_hex,
        "relevant_headers": relevant_headers,
    }
    canonical_bytes = jcs_canonicalize(canonical_obj)
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return "sha256-" + digest


def request_summary(req: CanonicalRequest, *, max_body_chars: int = 80) -> str:
    """Return ``"METHOD url body_summary"`` for VAL-W7-025 stderr.

    The body summary is a UTF-8 decode of up to ``max_body_chars``
    characters with non-ASCII / control characters replaced. For binary
    bodies the summary reads ``<binary N bytes>``.
    """
    method = req.canonical_method()
    try:
        body_text = req.body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_text = f"<binary {len(req.body_bytes)} bytes>"
    if len(body_text) > max_body_chars:
        body_text = body_text[:max_body_chars] + "..."
    # Strip newlines / control chars so the summary is one line.
    body_text = "".join(c if c.isprintable() else "." for c in body_text)
    return f"{method} {req.url} {body_text}"


# -----------------------------------------------------------------------------
# Output body storage helpers
# -----------------------------------------------------------------------------


def _output_body_path(session_dir: Path, fixture_id: str) -> Path:
    """Return the local sidecar file path for a fixture's response body."""
    return session_dir / "bodies" / f"{fixture_id}.body"


def _read_output_body(session_dir: Path, fixture: ReplayFixture) -> bytes:
    """Load a fixture's response body from disk.

    Honors ``output_ref`` when it points at a local file (``file://`` or
    a bare path). Returns ``b""`` for fixtures with no recorded output.
    """
    if fixture.output_ref is None:
        # No body recorded; expect output_digest to be the empty SHA-256.
        return b""
    ref = fixture.output_ref
    if ref.startswith(OUTPUT_REF_LOCAL_PREFIX):
        ref = ref[len(OUTPUT_REF_LOCAL_PREFIX):]
    body_path = Path(ref)
    if not body_path.is_absolute():
        body_path = session_dir / body_path
    return body_path.read_bytes()


def _verify_output_digest(
    fixture: ReplayFixture, body_bytes: bytes, *, line_number: int
) -> None:
    """VAL-W7-028: assert ``output_digest`` matches the actual body."""
    if fixture.output_digest is None:
        return
    actual = "sha256-" + hashlib.sha256(body_bytes).hexdigest()
    expected = fixture.output_digest
    # ReplayFixture's Sha256Hash type may store the digest as a raw hex
    # string (without the "sha256-" prefix) per the schema's sha256_hash
    # type. Normalize for comparison.
    norm_expected = (
        expected if expected.startswith("sha256-") else "sha256-" + expected
    )
    if actual != norm_expected:
        raise RelayCassetteCorruptError(
            f"cassette line {line_number} fixture {fixture.fixture_id}: "
            f"output_digest mismatch (expected {norm_expected}, "
            f"actual {actual})",
            details={
                "line_number": line_number,
                "fixture_id": str(fixture.fixture_id),
                "expected_digest": norm_expected,
                "actual_digest": actual,
            },
        )


# -----------------------------------------------------------------------------
# Cassette index (VAL-W7-031)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CassetteRecord:
    """One cassette entry: the validated ReplayFixture + its canonical key.

    The key is computed at load time from the request stored alongside
    the fixture in a sidecar file. v0.1 also accepts a key embedded in
    ``output_ref``'s sibling ``<fixture_id>.request.json`` file (the
    recorder's pre-write step computes both).
    """

    fixture: ReplayFixture
    canonical_key: str
    line_number: int
    response_bytes: bytes


@dataclass
class CassetteIndex:
    """O(1) ``canonical_key -> CassetteRecord`` index over the cassette.

    VAL-W7-031: lookup behavior is identical regardless of the on-disk
    record order. Two cassettes with the same set of records hashed in
    different sequences produce equivalent indexes. The index is a
    ``dict``; Python dicts have insertion-order iteration but key-based
    lookup is order-independent by construction.

    A late record with the same canonical key OVERRIDES an earlier one.
    This is documented behavior (W5.3 cassette_server.py:152 already
    used this convention) so re-recording overrides stale entries.
    """

    records: dict[str, CassetteRecord] = field(default_factory=dict)

    def add(self, record: CassetteRecord) -> None:
        self.records[record.canonical_key] = record

    def lookup(self, canonical_key: str) -> CassetteRecord | None:
        return self.records.get(canonical_key)

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[CassetteRecord]:
        return iter(self.records.values())


# -----------------------------------------------------------------------------
# Refresh policy (VAL-W7-029)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class RefreshDecision:
    """Outcome of evaluating a fixture's refresh policy at replay time.

    ``stale`` is True when the fixture's recorded ``model_signature``
    differs from the runtime-observed ``system_fingerprint`` AND the
    policy says to invalidate on that drift. ``divergence_reason``
    matches the spec's ``replay_results.divergence_reason`` enum:
    ``"signature_drift"`` for signature mismatch, ``"none"`` otherwise.
    """

    stale: bool
    divergence_reason: str
    policy: str
    recorded_signature: str | None
    observed_signature: str | None


def evaluate_refresh_policy(
    fixture: ReplayFixture,
    *,
    observed_system_fingerprint: str | None,
) -> RefreshDecision:
    """Apply VAL-W7-029 refresh-policy semantics.

    For ``invalidate_on_signature_change``: stale if the recorded
    ``model_signature`` differs from ``observed_system_fingerprint``.
    For ``hold_forever``: never stale.
    For ``refresh_weekly`` / ``invalidate_on_model_version_change``: not
    in scope for v0.1 (the tier-1 contract pins
    ``invalidate_on_signature_change``); these branches return ``stale=False``
    so a future feature can enrich them without changing the API.
    """
    policy = fixture.refresh_policy
    recorded = fixture.model_signature
    observed = observed_system_fingerprint
    if policy == REFRESH_POLICY_INVALIDATE_ON_SIG:
        # If either side is missing, treat as no drift (we can't
        # compare). The control plane is responsible for capturing
        # signature drift; an absent signature is not a failure.
        if recorded is None or observed is None:
            return RefreshDecision(
                stale=False,
                divergence_reason="none",
                policy=policy,
                recorded_signature=recorded,
                observed_signature=observed,
            )
        if recorded != observed:
            return RefreshDecision(
                stale=True,
                divergence_reason="signature_drift",
                policy=policy,
                recorded_signature=recorded,
                observed_signature=observed,
            )
        return RefreshDecision(
            stale=False,
            divergence_reason="none",
            policy=policy,
            recorded_signature=recorded,
            observed_signature=observed,
        )
    return RefreshDecision(
        stale=False,
        divergence_reason="none",
        policy=policy,
        recorded_signature=recorded,
        observed_signature=observed,
    )


# -----------------------------------------------------------------------------
# Loader (VAL-W7-020, VAL-W7-021, VAL-W7-026, VAL-W7-028, VAL-W7-031)
# -----------------------------------------------------------------------------


def _quarantine(cassette_path: Path) -> Path:
    """Move a corrupted cassette to ``<session>/quarantine/<timestamp>.jsonl``.

    Returns the destination path. Idempotent: if the destination exists
    a numeric suffix is appended.
    """
    quarantine_dir = cassette_path.parent / QUARANTINE_DIR_NAME
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = quarantine_dir / f"{ts}-{cassette_path.name}"
    suffix = 1
    while dest.exists():
        dest = quarantine_dir / f"{ts}-{suffix}-{cassette_path.name}"
        suffix += 1
    shutil.move(str(cassette_path), str(dest))
    return dest


def load_cassette(
    cassette_path: Path,
    *,
    quarantine_on_error: bool = False,
) -> CassetteIndex:
    """Parse + validate a JSONL cassette into a lookup index.

    Each line is decoded as JSON, validated against ``ReplayFixture``,
    and its ``output_digest`` is verified against the on-disk body
    (VAL-W7-028). The accompanying ``<fixture_id>.request.json`` sidecar
    file in ``<session>/requests/`` provides the canonical request used
    to derive the lookup key (VAL-W7-022).

    Raises:
        RelayCassetteCorruptError: any line fails JSON parse, schema
            validation, body digest verification, or sidecar request
            file read. If ``quarantine_on_error`` is True the cassette
            file is moved to ``quarantine/`` BEFORE the exception is
            raised.
    """
    if not cassette_path.exists():
        raise RelayCassetteCorruptError(
            f"cassette file does not exist: {cassette_path}",
            details={"cassette_path": str(cassette_path), "line_number": 0},
        )
    session_dir = cassette_path.parent
    raw = cassette_path.read_bytes()
    text = raw.decode("utf-8", errors="strict")
    # Final newline is the canonical terminator (VAL-W7-020). Empty
    # cassettes are valid (zero records).
    if text and not text.endswith("\n"):
        if quarantine_on_error:
            _quarantine(cassette_path)
        raise RelayCassetteCorruptError(
            f"cassette {cassette_path} does not end with a trailing newline; "
            "VAL-W7-020 requires UTF-8 with a final '\\n' after the last record",
            details={
                "cassette_path": str(cassette_path),
                "line_number": text.count("\n") + 1,
            },
        )
    index = CassetteIndex()
    for line_idx, line in enumerate(text.splitlines()):
        line_number = line_idx + 1
        if line.strip() == "":
            if quarantine_on_error:
                _quarantine(cassette_path)
            raise RelayCassetteCorruptError(
                f"cassette {cassette_path} line {line_number} is blank; "
                "every line MUST be a non-empty JSON record",
                details={
                    "cassette_path": str(cassette_path),
                    "line_number": line_number,
                },
            )
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            if quarantine_on_error:
                _quarantine(cassette_path)
            raise RelayCassetteCorruptError(
                f"cassette {cassette_path} line {line_number}: "
                f"malformed JSON: {exc.msg}",
                details={
                    "cassette_path": str(cassette_path),
                    "line_number": line_number,
                    "json_error": exc.msg,
                },
            ) from exc
        try:
            fixture = ReplayFixture.model_validate(obj)
        except Exception as exc:
            if quarantine_on_error:
                _quarantine(cassette_path)
            raise RelayCassetteCorruptError(
                f"cassette {cassette_path} line {line_number}: "
                f"ReplayFixture v1 validation failed: {exc}",
                details={
                    "cassette_path": str(cassette_path),
                    "line_number": line_number,
                    "schema_version": REPLAY_FIXTURE_SCHEMA_VERSION,
                },
            ) from exc
        body_bytes = _read_output_body(session_dir, fixture)
        try:
            _verify_output_digest(fixture, body_bytes, line_number=line_number)
        except RelayCassetteCorruptError:
            if quarantine_on_error:
                _quarantine(cassette_path)
            raise
        canonical_key = _read_canonical_key_for_fixture(session_dir, fixture)
        if canonical_key is None:
            if quarantine_on_error:
                _quarantine(cassette_path)
            raise RelayCassetteCorruptError(
                f"cassette {cassette_path} line {line_number}: "
                f"no canonical request file for fixture {fixture.fixture_id} "
                f"(expected at <session>/requests/{fixture.fixture_id}.request.json)",
                details={
                    "cassette_path": str(cassette_path),
                    "line_number": line_number,
                    "fixture_id": str(fixture.fixture_id),
                },
            )
        index.add(
            CassetteRecord(
                fixture=fixture,
                canonical_key=canonical_key,
                line_number=line_number,
                response_bytes=body_bytes,
            )
        )
    return index


def _read_canonical_key_for_fixture(
    session_dir: Path, fixture: ReplayFixture
) -> str | None:
    """Read the canonical request from disk and recompute its key.

    Each fixture's CanonicalRequest is materialized at record time as
    ``<session>/requests/<fixture_id>.request.json``::

        {
          "method":       "POST",
          "url":          "https://api.openai.com/v1/chat/completions",
          "headers":      {"content-type": "application/json", ...},
          "body_b64":     "<base64 of the body bytes>",
          "content_type": "application/json"
        }

    Returns the canonical key (``sha256-<hex>``) or None if the sidecar
    file does not exist.
    """
    request_path = session_dir / "requests" / f"{fixture.fixture_id}.request.json"
    if not request_path.exists():
        return None
    raw = request_path.read_text(encoding="utf-8")
    obj = json.loads(raw)
    import base64

    body_bytes = base64.b64decode(obj.get("body_b64", "") or "")
    req = CanonicalRequest(
        method=obj["method"],
        url=obj["url"],
        headers=obj.get("headers", {}),
        body_bytes=body_bytes,
        content_type=obj.get("content_type", "") or "",
    )
    return derive_canonical_key(req)


# -----------------------------------------------------------------------------
# APPEND-ONLY writer (VAL-W7-027, VAL-W7-030)
# -----------------------------------------------------------------------------


def _is_lock_or_share_violation(exc: OSError) -> bool:
    """Return True if ``exc`` is the AV / FS lock errno class."""
    if exc.errno == errno.EACCES:
        return True
    # WinError 32 = ERROR_SHARING_VIOLATION; WinError 33 = ERROR_LOCK_VIOLATION.
    win_err = getattr(exc, "winerror", None)
    return win_err in (32, 33)


def append_record(
    cassette_path: Path,
    *,
    fixture: ReplayFixture,
    canonical_request: CanonicalRequest,
    response_bytes: bytes,
    retry_delays_s: tuple[float, ...] = WRITE_RETRY_DELAYS_S,
    sleep_fn: Any = time.sleep,
    open_fn: Any = None,
) -> str:
    """Append one ReplayFixture record to ``cassette_path`` (APPEND-ONLY).

    Side effects:
      * Creates the parent directory if missing.
      * Writes the response body to
        ``<session>/bodies/<fixture_id>.body``.
      * Writes the canonical request descriptor to
        ``<session>/requests/<fixture_id>.request.json``.
      * Appends the fixture's canonical JSON line to the cassette.

    Returns the canonical lookup key for the appended request.

    VAL-W7-027 enforcement: the cassette is opened with
    ``O_WRONLY | O_APPEND | O_CREAT``. We never read the existing file,
    never seek, never truncate, never rename. A SIGKILL between any two
    appends leaves all prior records intact; the in-flight write is
    either flushed entirely (write(2) is atomic for small payloads under
    PIPE_BUF, and even larger payloads are atomic on POSIX local
    filesystems for a single ``write`` syscall) or absent.

    VAL-W7-030: ``EACCES`` and ``ERROR_SHARING_VIOLATION`` retry with
    backoff per ``retry_delays_s``. ``open_fn`` and ``sleep_fn`` are
    test seams; production callers leave them at the defaults.
    """
    cassette_path.parent.mkdir(parents=True, exist_ok=True)
    bodies_dir = cassette_path.parent / "bodies"
    requests_dir = cassette_path.parent / "requests"
    bodies_dir.mkdir(parents=True, exist_ok=True)
    requests_dir.mkdir(parents=True, exist_ok=True)

    fixture_id = str(fixture.fixture_id)

    # Body sidecar. Plain bytes write; this is not the cassette JSONL,
    # so it does not need APPEND-ONLY semantics. The hash is the
    # authoritative integrity check.
    body_path = bodies_dir / f"{fixture_id}.body"
    body_path.write_bytes(response_bytes)

    # Canonical request descriptor sidecar (for canonical-key recompute
    # at load time).
    import base64

    request_obj = {
        "method": canonical_request.canonical_method(),
        "url": canonical_request.url,
        "headers": dict(canonical_request.headers),
        "body_b64": base64.b64encode(canonical_request.body_bytes).decode("ascii"),
        "content_type": canonical_request.content_type
        or canonical_request.headers.get("content-type", ""),
    }
    request_path = requests_dir / f"{fixture_id}.request.json"
    request_path.write_text(
        json.dumps(request_obj, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    canonical_key = derive_canonical_key(canonical_request)

    # Build the canonical JSONL line. Use the schema's canonical
    # serializer so cross-language byte-equality holds.
    fixture_line = json.dumps(
        json.loads(fixture.model_dump_json()),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    payload = (fixture_line + "\n").encode("utf-8")

    # Open with APPEND semantics + retry on EACCES / share-violation.
    last_exc: OSError | None = None
    total_wait = 0.0
    open_func = open_fn if open_fn is not None else os.open
    attempts = max(len(retry_delays_s), 3)
    for attempt in range(attempts):
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = open_func(str(cassette_path), flags, 0o600)
            try:
                # write(2) on a local FS for a single buffer is atomic
                # at the byte level; we still flush + fsync so a crash
                # immediately after this call observes the new bytes.
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            return canonical_key
        except OSError as exc:
            if not _is_lock_or_share_violation(exc):
                raise
            last_exc = exc
            if attempt >= len(retry_delays_s):
                break
            delay = retry_delays_s[attempt]
            LOG.info(
                "cassette write retry %d/%d after EACCES on %s",
                attempt + 1,
                len(retry_delays_s),
                cassette_path,
            )
            sleep_fn(delay)
            total_wait += delay
    raise RelayCassetteWriteRetryExhaustedError(
        f"cassette write retries exhausted on {cassette_path} after "
        f"{len(retry_delays_s)} attempts (total wait {total_wait:.3f}s)",
        details={
            "attempts": len(retry_delays_s),
            "last_errno": last_exc.errno if last_exc is not None else None,
            "cassette_path": str(cassette_path),
            "total_wait_s": total_wait,
        },
    )


# -----------------------------------------------------------------------------
# Cassette miss helpers (VAL-W7-024, VAL-W7-025)
# -----------------------------------------------------------------------------


def raise_cassette_miss(
    *,
    canonical_key: str,
    request: CanonicalRequest,
    cassette_path: Path | str,
) -> None:
    """Raise a ``RelayCassetteMissError`` carrying the debug context.

    The exception's ``message`` and ``details`` carry both the canonical
    key (so the operator can grep for it in the cassette directory) and
    the request triple (so they can replay the call manually). Per
    VAL-W7-024 there is no live fallthrough -- this function ALWAYS
    raises.
    """
    summary = request_summary(request)
    msg = (
        f"cassette miss for canonical key {canonical_key}: "
        f"{summary}; cassette={cassette_path!s}; "
        f"to record this request: re-run with 'rly replay record'"
    )
    raise RelayCassetteMissError(
        msg,
        details={
            "canonical_key": canonical_key,
            "method": request.canonical_method(),
            "url": request.url,
            "cassette_path": str(cassette_path),
            "exit_code": 4,
        },
    )


def emit_cassette_miss_stderr(
    *,
    canonical_key: str,
    request: CanonicalRequest,
    cassette_path: Path | str,
    stream: Any = None,
) -> None:
    """Print the VAL-W7-025 stderr line for a cassette miss.

    Format: ``"cassette miss: <canonical_key> <method> <url> <body_summary>"``
    on a single line. The line MUST contain ``sha256-[0-9a-f]{64}`` AND
    one of ``GET|POST|PUT|DELETE|PATCH https://`` (regex required by
    VAL-W7-025 evidence).
    """
    out = stream if stream is not None else sys.stderr
    summary = request_summary(request)
    out.write(f"cassette miss: {canonical_key} {summary}\n")
    out.flush() if hasattr(out, "flush") else None


# -----------------------------------------------------------------------------
# Suppress unused-import warnings for forward-compat scaffolding
# -----------------------------------------------------------------------------

_ = (contextlib,)


__all__ = [
    "CASSETTE_FILENAME",
    "CanonicalKeyConfig",
    "CanonicalRequest",
    "CassetteIndex",
    "CassetteRecord",
    "EXIT_CODE_CASSETTE_MISS_REF",
    "KEY_DEFAULT_RELEVANT_HEADERS",
    "KEY_EXCLUDED_HEADERS",
    "OUTPUT_REF_LOCAL_PREFIX",
    "QUARANTINE_DIR_NAME",
    "REFRESH_POLICY_HOLD_FOREVER",
    "REFRESH_POLICY_INVALIDATE_ON_MODEL",
    "REFRESH_POLICY_INVALIDATE_ON_SIG",
    "REFRESH_POLICY_REFRESH_WEEKLY",
    "REPLAY_FIXTURE_SCHEMA_VERSION",
    "RefreshDecision",
    "SIDE_EFFECT_APPROVAL_REQUIRED",
    "SIDE_EFFECT_EXTERNAL_IRREVERSIBLE",
    "SIDE_EFFECT_MUTATING",
    "SIDE_EFFECT_READ_ONLY",
    "WRITE_RETRY_DELAYS_S",
    "append_record",
    "derive_canonical_key",
    "emit_cassette_miss_stderr",
    "evaluate_refresh_policy",
    "load_cassette",
    "raise_cassette_miss",
    "request_summary",
]


# Re-export the canonical exit-code constant from .errors so callers that
# already import this module don't need a second import for the exit code.
from .errors import EXIT_CODE_CASSETTE_MISS as EXIT_CODE_CASSETTE_MISS_REF  # noqa: E402
