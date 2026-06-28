"""Security regression tests for the W7.2 cassette subsystem.

These tests pin three verified P0/P1 bugs:

  * Bug 1 (P0): ``_read_output_body`` accepted absolute / dot-dot / non-file
    schemes in ``output_ref`` and could read arbitrary process-accessible
    files. The ``_verify_output_digest`` early-return on ``output_digest is
    None`` made the read silent.
  * Bug 2 (P0): ``CassetteServer._load_if_needed`` did not verify the
    parsed ``file_digest_sha256`` against any anchor value; a tampered
    cassette parsed and served end-to-end. ``lookup()`` likewise did not
    re-verify ``entry.response_digest`` against the served bytes.
  * Bug 3 (P1): ``_filter_headers`` did not lower-case ``extra_relevant``
    headers passed via ``CanonicalKeyConfig``, silently dropping
    provider-specific request-shape headers (e.g. ``OpenAI-Beta``) from
    the canonical lookup key.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from relay_replay_proxy.cassette_format import (
    CanonicalKeyConfig,
    CanonicalRequest,
    _filter_headers,
    _read_output_body,
    _verify_output_digest,
)
from relay_replay_proxy.cassette_server import CassetteServer, IncomingRequest
from relay_replay_proxy.errors import RelayCassetteCorruptError
from relay_sidecar.cassette import (
    CASSETTE_ENTRY_SCHEMA_VERSION,
    CASSETTE_HEADER_SCHEMA_VERSION,
    CassetteEntry,
    CassetteFormatError,
    CassetteHeader,
    canonical_request_digest,
    canonical_response_digest,
    parse_cassette,
    serialize_cassette,
    write_cassette_file,
)

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# Bug 1 (P0): path traversal via fixture output_ref
# -----------------------------------------------------------------------------


def test_read_output_body_rejects_absolute_path(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
) -> None:
    """An absolute ``file://`` URI MUST be rejected (path traversal)."""
    fixture = make_replay_fixture(
        output_ref="file:///etc/passwd",
        output_digest="sha256-" + "0" * 64,
    )
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        _read_output_body(empty_cassette_dir, fixture)
    msg = str(excinfo.value).lower()
    assert "output_ref_absolute_path_rejected" in msg or "absolute" in msg


def test_read_output_body_rejects_bare_absolute_path(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
) -> None:
    """An absolute path WITHOUT the file:// scheme MUST also be rejected."""
    fixture = make_replay_fixture(
        output_ref="/etc/passwd",
        output_digest="sha256-" + "0" * 64,
    )
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        _read_output_body(empty_cassette_dir, fixture)
    msg = str(excinfo.value).lower()
    assert "output_ref_absolute_path_rejected" in msg or "absolute" in msg


def test_read_output_body_rejects_dotdot_traversal(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    tmp_path: Path,
) -> None:
    """A ``..`` traversal MUST be rejected even if the resolved path exists."""
    # Plant a real file outside the session dir so the test would actually
    # succeed at reading if traversal were allowed.
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"top-secret")
    # session_dir is empty_cassette_dir; build a ref that climbs out.
    rel_escape = "../../" + secret.relative_to(tmp_path).as_posix()
    fixture = make_replay_fixture(
        output_ref=rel_escape,
        output_digest="sha256-" + hashlib.sha256(b"top-secret").hexdigest(),
    )
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        _read_output_body(empty_cassette_dir, fixture)
    msg = str(excinfo.value).lower()
    assert "output_ref_escapes_session_dir" in msg or "escape" in msg


def test_read_output_body_rejects_http_scheme(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
) -> None:
    """Non-``file://`` schemes (http, https, data, javascript) MUST be rejected."""
    for ref in (
        "https://example.com/x",
        "http://example.com/x",
        "data:text/plain,hello",
        "javascript:alert(1)",
    ):
        fixture = make_replay_fixture(
            output_ref=ref,
            output_digest="sha256-" + "0" * 64,
        )
        with pytest.raises(RelayCassetteCorruptError):
            _read_output_body(empty_cassette_dir, fixture)


def test_read_output_body_rejects_missing_digest_when_ref_present(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
) -> None:
    """If ``output_ref`` is present, ``output_digest`` MUST also be present.

    The combination ``output_ref != None and output_digest is None`` is what
    used to bypass digest verification entirely via the early return.
    """
    body_dir = empty_cassette_dir / "bodies"
    body_dir.mkdir(parents=True, exist_ok=True)
    (body_dir / "x.body").write_bytes(b"anything")
    fixture = make_replay_fixture(
        output_ref="file://bodies/x.body",
        output_digest=None,
    )
    body = _read_output_body(empty_cassette_dir, fixture)
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        _verify_output_digest(fixture, body, line_number=2)
    msg = str(excinfo.value).lower()
    assert "output_digest" in msg


def test_read_output_body_accepts_relative_file_uri_inside_session(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
) -> None:
    """Happy path: legitimate ``file://bodies/<id>.body`` still works."""
    body_dir = empty_cassette_dir / "bodies"
    body_dir.mkdir(parents=True, exist_ok=True)
    payload = b'{"ok":true}'
    (body_dir / "x.body").write_bytes(payload)
    fixture = make_replay_fixture(
        output_ref="file://bodies/x.body",
        output_digest="sha256-" + hashlib.sha256(payload).hexdigest(),
    )
    body = _read_output_body(empty_cassette_dir, fixture)
    assert body == payload


# -----------------------------------------------------------------------------
# Bug 2 (P0): silent cassette tampering accepted (no integrity check)
# -----------------------------------------------------------------------------


def _seed_session_with_cassette(
    session_dir: Path,
    *,
    request_body: dict[str, Any],
    response_body: dict[str, Any],
) -> Path:
    """Write a one-entry cassette into ``session_dir``; return cassette path."""
    header = CassetteHeader(
        schema_version=CASSETTE_HEADER_SCHEMA_VERSION,
        case_id="case_security",
        session_id=session_dir.name,
        recorded_at="2026-05-14T00:00:00Z",
        manifest_commit_hash="sha256-" + ("0" * 64),
    )
    entry = CassetteEntry(
        schema_version=CASSETTE_ENTRY_SCHEMA_VERSION,
        sequence=0,
        provider="openai",
        model="gpt-4o-mini",
        request_digest=canonical_request_digest(request_body),
        response=response_body,
        response_digest=canonical_response_digest(response_body),
        timestamp="2026-05-14T00:00:01Z",
    )
    cassette_path = session_dir / "cassette.jsonl"
    write_cassette_file(cassette_path, header, [entry])
    return cassette_path


def test_load_if_needed_verifies_expected_file_digest_mismatch(
    cassette_root: Path,
) -> None:
    """Wrong expected digest MUST raise on load."""
    sd = cassette_root / "sesSecurityBug2Mismatch_______"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    response = {"id": "resp1", "object": "chat.completion", "choices": []}
    _seed_session_with_cassette(sd, request_body=request, response_body=response)
    wrong = "0" * 64
    server = CassetteServer(sd, expected_file_digest_sha256=wrong)
    with pytest.raises(CassetteFormatError) as excinfo:
        server.lookup(
            IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
        )
    assert "file_digest_mismatch" in str(excinfo.value)


def test_load_if_needed_passes_when_expected_matches_actual(
    cassette_root: Path,
) -> None:
    """Correct expected digest MUST permit lookup."""
    sd = cassette_root / "sesSecurityBug2Match__________"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    response = {"id": "resp1", "object": "chat.completion", "choices": []}
    cassette_path = _seed_session_with_cassette(
        sd, request_body=request, response_body=response
    )
    parsed = parse_cassette(cassette_path.read_bytes(), str(cassette_path))
    server = CassetteServer(
        sd, expected_file_digest_sha256=parsed.file_digest_sha256
    )
    result = server.lookup(
        IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
    )
    assert result is not None
    assert result.status == 200


def test_load_if_needed_no_expected_digest_still_loads(
    cassette_root: Path,
) -> None:
    """Back-compat: with no expected digest, load still succeeds."""
    sd = cassette_root / "sesSecurityBug2NoExpected_____"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    response = {"id": "resp1", "object": "chat.completion", "choices": []}
    _seed_session_with_cassette(sd, request_body=request, response_body=response)
    server = CassetteServer(sd)
    result = server.lookup(
        IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
    )
    assert result is not None


def test_lookup_rejects_tampered_entry(
    cassette_root: Path,
) -> None:
    """An entry whose response was modified post-parse MUST trip on lookup.

    Simulates an attacker who modifies the in-memory ``entry.response``
    after parsing but before serving (e.g. supply-chain attack on a
    process holding the parsed cassette). The per-lookup digest re-check
    catches the forgery.
    """
    sd = cassette_root / "sesSecurityBug2TamperedEntry__"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    response = {"id": "resp1", "object": "chat.completion", "choices": []}
    _seed_session_with_cassette(sd, request_body=request, response_body=response)
    server = CassetteServer(sd)
    # Force load + index population, then mutate the cached entry.
    server.reload()
    digest = canonical_request_digest(request)
    cached = server._index[digest]
    forged_response = dict(cached.response)
    forged_response["choices"] = [{"injected": True}]
    server._index[digest] = CassetteEntry(
        schema_version=cached.schema_version,
        sequence=cached.sequence,
        provider=cached.provider,
        model=cached.model,
        request_digest=cached.request_digest,
        response=forged_response,
        # Preserve the original (now-stale) response_digest so the
        # mismatch becomes detectable on lookup.
        response_digest=cached.response_digest,
        timestamp=cached.timestamp,
    )
    with pytest.raises(CassetteFormatError) as excinfo:
        server.lookup(
            IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
        )
    assert "response_digest" in str(excinfo.value)


# -----------------------------------------------------------------------------
# Bug 2b (LOW): on-disk re-digested tamper served as authentic without an
# anchor, and no fail-closed mode for trust-requiring serving paths.
#
# The per-entry response_digest re-check (test_lookup_rejects_tampered_entry)
# only catches *in-memory* mutation where the stale recorded digest is left
# behind. An attacker with write access to the cassette FILE rewrites the
# response bytes AND recomputes the per-entry response_digest, so the
# in-memory consistency check passes; the only defense is the file-level
# anchor, which the production caller omits. We add a fail-closed
# ``require_integrity`` mode so a trust-requiring path that lacks an anchor
# refuses to serve rather than serving forged bytes silently.
# -----------------------------------------------------------------------------


def _redigest_forge_on_disk(
    session_dir: Path,
    *,
    request_body: dict[str, Any],
    forged_response: dict[str, Any],
) -> Path:
    """Rewrite the on-disk cassette with a forged response, re-digesting.

    Simulates the real attack: an adversary with write access rewrites the
    entry's response bytes and recomputes the per-entry response_digest so
    the cassette is internally consistent. The only thing that changes that
    an honest verifier could catch is the file-level SHA-256.
    """
    header = CassetteHeader(
        schema_version=CASSETTE_HEADER_SCHEMA_VERSION,
        case_id="case_security",
        session_id=session_dir.name,
        recorded_at="2026-05-14T00:00:00Z",
        manifest_commit_hash="sha256-" + ("0" * 64),
    )
    forged_entry = CassetteEntry(
        schema_version=CASSETTE_ENTRY_SCHEMA_VERSION,
        sequence=0,
        provider="openai",
        model="gpt-4o-mini",
        request_digest=canonical_request_digest(request_body),
        response=forged_response,
        # Attacker recomputes the per-entry digest over the forged bytes,
        # so the in-memory response_digest re-check cannot catch this.
        response_digest=canonical_response_digest(forged_response),
        timestamp="2026-05-14T00:00:01Z",
    )
    cassette_path = session_dir / "cassette.jsonl"
    write_cassette_file(cassette_path, header, [forged_entry])
    return cassette_path


def test_require_integrity_without_anchor_fails_closed(
    cassette_root: Path,
) -> None:
    """A trust-requiring server with no anchor MUST refuse to serve.

    This is the core fix: the production serving path that requires
    integrity but was not handed an ``expected_file_digest_sha256`` anchor
    must fail closed (no cassette served) rather than silently serving
    unanchored, untrusted bytes.
    """
    sd = cassette_root / "sesReqIntegNoAnchor__________"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    response = {"id": "resp1", "object": "chat.completion", "choices": []}
    _seed_session_with_cassette(sd, request_body=request, response_body=response)
    server = CassetteServer(sd, require_integrity=True)
    with pytest.raises(CassetteFormatError) as excinfo:
        server.lookup(
            IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
        )
    assert "integrity_anchor_required" in str(excinfo.value)


def test_require_integrity_with_matching_anchor_serves(
    cassette_root: Path,
) -> None:
    """Trust-requiring server WITH a matching anchor still serves."""
    sd = cassette_root / "sesReqIntegMatch_____________"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    response = {"id": "resp1", "object": "chat.completion", "choices": []}
    cassette_path = _seed_session_with_cassette(
        sd, request_body=request, response_body=response
    )
    parsed = parse_cassette(cassette_path.read_bytes(), str(cassette_path))
    server = CassetteServer(
        sd,
        expected_file_digest_sha256=parsed.file_digest_sha256,
        require_integrity=True,
    )
    result = server.lookup(
        IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
    )
    assert result is not None
    assert result.status == 200


def test_require_integrity_rejects_ondisk_redigested_tamper(
    cassette_root: Path,
) -> None:
    """On-disk re-digested forgery MUST be rejected when anchored.

    The attacker rewrites the cassette file with a forged response and
    recomputes the per-entry response_digest (so the in-memory re-check is
    defeated). With the anchor pinned to the ORIGINAL file digest and
    integrity required, the file-level check catches the forgery on load --
    the forged bytes are never served.
    """
    sd = cassette_root / "sesReqIntegOnDiskForge_______"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    authentic = {"id": "resp1", "object": "chat.completion", "choices": []}
    cassette_path = _seed_session_with_cassette(
        sd, request_body=request, response_body=authentic
    )
    # Capture the trust anchor BEFORE tampering: the file digest of the
    # genuine, recorded cassette (as a signed manifest / evidence bundle
    # would carry).
    anchor = parse_cassette(
        cassette_path.read_bytes(), str(cassette_path)
    ).file_digest_sha256

    # Attacker rewrites the file with a forged-but-internally-consistent
    # response.
    forged = {"id": "resp1", "object": "chat.completion", "choices": [{"injected": True}]}
    _redigest_forge_on_disk(sd, request_body=request, forged_response=forged)

    server = CassetteServer(
        sd, expected_file_digest_sha256=anchor, require_integrity=True
    )
    with pytest.raises(CassetteFormatError) as excinfo:
        server.lookup(
            IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
        )
    assert "file_digest_mismatch" in str(excinfo.value)


def test_redigested_ondisk_forge_unanchored_serves_authentic_today(
    cassette_root: Path,
) -> None:
    """Demonstrates the gap: unanchored serve has NO tamper detection.

    With no anchor (the current production default) an on-disk re-digested
    forgery serves as authentic -- the per-entry digest re-check passes
    because the attacker recomputed it. This is the back-compat behavior
    the fail-closed mode exists to protect against; it MUST remain the
    behavior only when integrity is NOT required (back-compat preserved).
    """
    sd = cassette_root / "sesUnanchoredForgeServes_____"
    sd.mkdir(parents=True, exist_ok=True)
    request = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    forged = {"id": "resp1", "object": "chat.completion", "choices": [{"injected": True}]}
    _redigest_forge_on_disk(sd, request_body=request, forged_response=forged)
    # No anchor, no require_integrity -> back-compat path, serves.
    server = CassetteServer(sd)
    result = server.lookup(
        IncomingRequest(provider="openai", model="gpt-4o-mini", body=request)
    )
    assert result is not None
    assert b"injected" in result.body_bytes


# -----------------------------------------------------------------------------
# Bug 3 (P1): _filter_headers case-mismatch drops extra_relevant_headers
# -----------------------------------------------------------------------------


def test_filter_headers_lowercases_extra_relevant() -> None:
    """``extra_relevant_headers`` MUST be matched case-insensitively.

    An adapter passing ``{"OpenAI-Beta", "X-MyApp"}`` against incoming
    header keys ``openai-beta`` / ``x-myapp`` (HTTP/2 lower-cased) must
    NOT silently drop the headers from the canonical key.
    """
    incoming = {
        "content-type": "application/json",
        "openai-beta": "assistants=v2",
        "x-myapp": "tenant-42",
    }
    extra = frozenset({"OpenAI-Beta", "X-MyApp"})
    filtered = _filter_headers(incoming, extra_relevant=extra)
    assert filtered.get("openai-beta") == "assistants=v2"
    assert filtered.get("x-myapp") == "tenant-42"


def test_filter_headers_case_insensitive_via_config_changes_key(
    make_canonical_request: Any,
) -> None:
    """Same body + different ``OpenAI-Beta`` MUST produce different keys."""
    from relay_replay_proxy.cassette_format import derive_canonical_key

    cfg = CanonicalKeyConfig(extra_relevant_headers=frozenset({"OpenAI-Beta"}))
    req_a = CanonicalRequest(
        method="POST",
        url="https://api.openai.com/v1/chat/completions",
        headers={"content-type": "application/json", "openai-beta": "assistants=v1"},
        body_bytes=b'{"x":1}',
        content_type="application/json",
    )
    req_b = CanonicalRequest(
        method="POST",
        url="https://api.openai.com/v1/chat/completions",
        headers={"content-type": "application/json", "openai-beta": "assistants=v2"},
        body_bytes=b'{"x":1}',
        content_type="application/json",
    )
    assert derive_canonical_key(req_a, config=cfg) != derive_canonical_key(
        req_b, config=cfg
    )


# Suppress unused-import warnings for symbols referenced via fixtures only.
_ = (json, serialize_cassette)
