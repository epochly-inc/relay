"""Cassette reader/writer (W5.3 Python parity with TS cassette_reader.ts).

The replay cassette format is JSONL: one JSON object per line. The on-disk
format is identical across the Python and TypeScript SDKs so a cassette
recorded by ``rly replay record`` is readable byte-identically by either
runtime.

Cassette schema (relay.cassette.v1):

  { "schema_version": "relay.cassette.v1",
    "case_id": <ULID>,
    "session_id": <ULID>,
    "recorded_at": <RFC3339>,
    "manifest_commit_hash": "sha256-..." }
  { "schema_version": "relay.cassette_entry.v1", ... }   <- one per call
  { "schema_version": "relay.cassette_entry.v1", ... }
  ...

Each entry carries: ``sequence`` (0-based), ``provider``, ``model``,
``request_digest`` (sha256-<hex> of the canonical request body),
``response`` (recorded response object), ``response_digest``,
``timestamp`` (RFC3339).

Per CLAUDE.md keystone invariant #10 the reader validates the header
schema_version and every entry schema_version on load; unknown schema
versions raise synchronously.

Per VAL-W5-020 the writer emits canonical JSON (sort_keys=True,
separators=(",", ":")) for byte-stable digests across runs of the same
input. The Python writer's bytes are byte-identical to the TS writer's
canonical-stringify output for the same input.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from relay_sidecar.primitives import local_atomic_file_write

CASSETTE_HEADER_SCHEMA_VERSION: Final[str] = "relay.cassette.v1"
CASSETTE_ENTRY_SCHEMA_VERSION: Final[str] = "relay.cassette_entry.v1"

# Canonical JSON serializer settings used everywhere a cassette byte sequence
# needs to be deterministic (sequence digest, file digest, response digest).
# Mirrors the TS canonical stringify in packages/sdk-typescript/src/redaction.ts.
_CANONICAL_JSON_KW: Final[dict[str, Any]] = {
    "sort_keys": True,
    "separators": (",", ":"),
    "ensure_ascii": True,
}


class CassetteFormatError(ValueError):
    """Raised when a cassette cannot be parsed or validated.

    Carries the offending line number (1-based) so the CLI can surface the
    failure with file:line context. ``path`` may be None when the cassette
    is parsed from in-memory bytes.
    """

    def __init__(
        self, message: str, line: int, path: str | None = None
    ) -> None:
        super().__init__(message)
        self.line = line
        self.path = path


@dataclass(frozen=True)
class CassetteHeader:
    """Cassette header (line 1 of the JSONL file)."""

    schema_version: str
    case_id: str
    session_id: str
    recorded_at: str
    manifest_commit_hash: str

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "session_id": self.session_id,
            "recorded_at": self.recorded_at,
            "manifest_commit_hash": self.manifest_commit_hash,
        }


@dataclass(frozen=True)
class CassetteEntry:
    """Cassette entry (line >= 2 of the JSONL file)."""

    schema_version: str
    sequence: int
    provider: str
    model: str
    request_digest: str
    response: dict[str, Any]
    response_digest: str
    timestamp: str

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "provider": self.provider,
            "model": self.model,
            "request_digest": self.request_digest,
            "response": self.response,
            "response_digest": self.response_digest,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class Cassette:
    """Parsed cassette: header + ordered entries + file-level SHA-256."""

    header: CassetteHeader
    entries: tuple[CassetteEntry, ...]
    file_digest_sha256: str
    raw_bytes: bytes = field(repr=False)


# -----------------------------------------------------------------------------
# Validation helpers
# -----------------------------------------------------------------------------


def _require_str(value: Any, field_name: str, line: int, path: str | None) -> str:
    if not isinstance(value, str) or value == "":
        raise CassetteFormatError(
            f"cassette field {field_name!r} must be a non-empty string",
            line,
            path,
        )
    return value


def _require_non_neg_int(
    value: Any, field_name: str, line: int, path: str | None
) -> int:
    # bool is a subclass of int; reject explicitly to avoid silent
    # acceptance of True/False as 1/0.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CassetteFormatError(
            f"cassette field {field_name!r} must be a non-negative integer",
            line,
            path,
        )
    return value


def _require_object(
    value: Any, field_name: str, line: int, path: str | None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CassetteFormatError(
            f"cassette field {field_name!r} must be a JSON object",
            line,
            path,
        )
    return value


def _parse_line_json(raw: str, line: int, path: str | None) -> Any:
    if raw.strip() == "":
        raise CassetteFormatError(
            "cassette line is empty; cassettes must not contain blank lines",
            line,
            path,
        )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CassetteFormatError(
            f"cassette line {line} is not valid JSON: {exc.msg}",
            line,
            path,
        ) from exc


def _validate_header(raw: Any, path: str | None) -> CassetteHeader:
    obj = _require_object(raw, "header", 1, path)
    schema_version = _require_str(
        obj.get("schema_version"), "schema_version", 1, path
    )
    if schema_version != CASSETTE_HEADER_SCHEMA_VERSION:
        raise CassetteFormatError(
            "cassette header schema_version must be "
            f"{CASSETTE_HEADER_SCHEMA_VERSION}; got {schema_version!r}",
            1,
            path,
        )
    return CassetteHeader(
        schema_version=schema_version,
        case_id=_require_str(obj.get("case_id"), "case_id", 1, path),
        session_id=_require_str(obj.get("session_id"), "session_id", 1, path),
        recorded_at=_require_str(obj.get("recorded_at"), "recorded_at", 1, path),
        manifest_commit_hash=_require_str(
            obj.get("manifest_commit_hash"), "manifest_commit_hash", 1, path
        ),
    )


def _validate_entry(raw: Any, line: int, path: str | None) -> CassetteEntry:
    obj = _require_object(raw, f"entry@line{line}", line, path)
    schema_version = _require_str(
        obj.get("schema_version"), "schema_version", line, path
    )
    if schema_version != CASSETTE_ENTRY_SCHEMA_VERSION:
        raise CassetteFormatError(
            "cassette entry schema_version must be "
            f"{CASSETTE_ENTRY_SCHEMA_VERSION}; got {schema_version!r}",
            line,
            path,
        )
    return CassetteEntry(
        schema_version=schema_version,
        sequence=_require_non_neg_int(obj.get("sequence"), "sequence", line, path),
        provider=_require_str(obj.get("provider"), "provider", line, path),
        model=_require_str(obj.get("model"), "model", line, path),
        request_digest=_require_str(
            obj.get("request_digest"), "request_digest", line, path
        ),
        response=_require_object(obj.get("response"), "response", line, path),
        response_digest=_require_str(
            obj.get("response_digest"), "response_digest", line, path
        ),
        timestamp=_require_str(obj.get("timestamp"), "timestamp", line, path),
    )


# -----------------------------------------------------------------------------
# Parser / serializer
# -----------------------------------------------------------------------------


def parse_cassette(raw: bytes | str, path: str | None = None) -> Cassette:
    """Parse a cassette from raw JSONL bytes / text.

    Validates the header and every entry. Returns the canonical
    :class:`Cassette`. Per VAL-W4-041 cross-language parity the cassette
    is read byte-identically -- no normalization or re-canonicalization
    on load (the recorded bytes are the wire form by construction).

    Sequence indices MUST be 0..N-1 in order; a gap or out-of-order entry
    raises :class:`CassetteFormatError`.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
        text = raw
    else:
        raw_bytes = bytes(raw)
        text = raw_bytes.decode("utf-8")
    file_digest = hashlib.sha256(raw_bytes).hexdigest()
    lines = text.split("\n")
    # Trim trailing empty newline (the canonical writer always emits one).
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise CassetteFormatError("cassette is empty", 0, path)
    header_obj = _parse_line_json(lines[0], 1, path)
    header = _validate_header(header_obj, path)
    entries: list[CassetteEntry] = []
    for idx in range(1, len(lines)):
        line_no = idx + 1
        obj = _parse_line_json(lines[idx], line_no, path)
        entry = _validate_entry(obj, line_no, path)
        if entry.sequence != idx - 1:
            raise CassetteFormatError(
                f"cassette entry sequence must be {idx - 1}; got {entry.sequence}",
                line_no,
                path,
            )
        entries.append(entry)
    return Cassette(
        header=header,
        entries=tuple(entries),
        file_digest_sha256=file_digest,
        raw_bytes=raw_bytes,
    )


def read_cassette_file(path: Path | str) -> Cassette:
    """Read and parse a cassette from disk."""
    p = Path(path)
    raw = p.read_bytes()
    return parse_cassette(raw, str(p))


def serialize_cassette(
    header: CassetteHeader, entries: list[CassetteEntry] | tuple[CassetteEntry, ...]
) -> bytes:
    """Serialize a cassette to canonical JSONL bytes (deterministic).

    Per VAL-W5-020 the same input MUST produce the same byte sequence on
    every invocation. Achieved by:
      1. Sorting object keys (sort_keys=True).
      2. Compact separators ((",", ":")).
      3. ASCII escaping (ensure_ascii=True) so non-ASCII bytes don't
         depend on the locale.
      4. Sequence indices renumbered to 0..N-1 in declaration order.
      5. A single trailing newline so split("\\n") roundtrips cleanly.
    """
    if header.schema_version != CASSETTE_HEADER_SCHEMA_VERSION:
        raise CassetteFormatError(
            "header schema_version must be "
            f"{CASSETTE_HEADER_SCHEMA_VERSION}; got {header.schema_version!r}",
            1,
            None,
        )
    out = bytearray()
    out.extend(json.dumps(header.to_canonical_dict(), **_CANONICAL_JSON_KW).encode("utf-8"))
    out.extend(b"\n")
    for idx, entry in enumerate(entries):
        if entry.schema_version != CASSETTE_ENTRY_SCHEMA_VERSION:
            raise CassetteFormatError(
                "entry schema_version must be "
                f"{CASSETTE_ENTRY_SCHEMA_VERSION}; got {entry.schema_version!r}",
                idx + 2,
                None,
            )
        # Renumber sequence; the writer is the authority for ordering.
        renumbered = CassetteEntry(
            schema_version=entry.schema_version,
            sequence=idx,
            provider=entry.provider,
            model=entry.model,
            request_digest=entry.request_digest,
            response=entry.response,
            response_digest=entry.response_digest,
            timestamp=entry.timestamp,
        )
        out.extend(
            json.dumps(renumbered.to_canonical_dict(), **_CANONICAL_JSON_KW).encode("utf-8")
        )
        out.extend(b"\n")
    return bytes(out)


def write_cassette_file(
    path: Path | str,
    header: CassetteHeader,
    entries: list[CassetteEntry] | tuple[CassetteEntry, ...],
) -> str:
    """Write a cassette atomically via the four-primitive helper.

    Returns the SHA-256 hex digest of the on-disk bytes (== the value
    that ``parse_cassette(read_cassette_file(path)).file_digest_sha256``
    will yield). Per CLAUDE.md keystone invariant #8 the file write goes
    through ``local_atomic_file_write``; no direct ``open(..., 'wb')``.
    """
    payload = serialize_cassette(header, entries)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    local_atomic_file_write(p, payload, mode=0o600)
    return hashlib.sha256(payload).hexdigest()


def canonical_request_digest(request: dict[str, Any]) -> str:
    """Return ``sha256-<hex>`` of the canonical JSON of ``request``.

    Used by the recorder when capturing provider calls so the playback
    side can match an outbound call to its recorded entry by request
    body equivalence.
    """
    body = json.dumps(request, **_CANONICAL_JSON_KW).encode("utf-8")
    return "sha256-" + hashlib.sha256(body).hexdigest()


def canonical_response_digest(response: dict[str, Any]) -> str:
    """Return ``sha256-<hex>`` of the canonical JSON of ``response``."""
    body = json.dumps(response, **_CANONICAL_JSON_KW).encode("utf-8")
    return "sha256-" + hashlib.sha256(body).hexdigest()


def find_entry_by_sequence(
    cassette: Cassette, sequence: int
) -> CassetteEntry | None:
    """Return the entry at ``sequence`` or None if out of range."""
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        return None
    if sequence < 0 or sequence >= len(cassette.entries):
        return None
    return cassette.entries[sequence]


def find_entry_by_request_digest(
    cassette: Cassette, request_digest: str
) -> CassetteEntry | None:
    """Return the first entry matching ``request_digest`` or None."""
    for entry in cassette.entries:
        if entry.request_digest == request_digest:
            return entry
    return None


__all__ = [
    "CASSETTE_ENTRY_SCHEMA_VERSION",
    "CASSETTE_HEADER_SCHEMA_VERSION",
    "Cassette",
    "CassetteEntry",
    "CassetteFormatError",
    "CassetteHeader",
    "canonical_request_digest",
    "canonical_response_digest",
    "find_entry_by_request_digest",
    "find_entry_by_sequence",
    "parse_cassette",
    "read_cassette_file",
    "serialize_cassette",
    "write_cassette_file",
]
