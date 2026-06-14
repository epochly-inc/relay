"""W7.2 cassette format plumbing tests (VAL-W7-020..031).

Tier-1 plumbing only. Every test here exercises the in-process cassette
format primitives (canonical key derivation, JSONL load/save, refresh
policy, append-only writer, lock retry) without spawning a real proxy
or agent.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from relay_replay_proxy.cassette_format import (
    CASSETTE_FILENAME,
    KEY_EXCLUDED_HEADERS,
    QUARANTINE_DIR_NAME,
    REFRESH_POLICY_HOLD_FOREVER,
    REFRESH_POLICY_INVALIDATE_ON_SIG,
    REPLAY_FIXTURE_SCHEMA_VERSION,
    WRITE_RETRY_DELAYS_S,
    CanonicalKeyConfig,
    CanonicalRequest,
    CassetteIndex,
    append_record,
    derive_canonical_key,
    emit_cassette_miss_stderr,
    evaluate_refresh_policy,
    load_cassette,
    raise_cassette_miss,
)
from relay_replay_proxy.errors import (
    EXIT_CODE_CASSETTE_MISS,
    RELAY_REPLAY_CASSETTE_CORRUPT,
    RELAY_REPLAY_CASSETTE_MISS,
    RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED,
    RelayCassetteCorruptError,
    RelayCassetteMissError,
    RelayCassetteWriteRetryExhaustedError,
)

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _record_one(
    session_dir: Path,
    *,
    fixture: Any,
    request: CanonicalRequest,
    response_bytes: bytes,
) -> str:
    """Append one record and return its canonical key.

    Wraps ``append_record`` so tests don't have to assemble all kwargs.
    """
    cassette_path = session_dir / CASSETTE_FILENAME
    return append_record(
        cassette_path,
        fixture=fixture,
        canonical_request=request,
        response_bytes=response_bytes,
    )


# -----------------------------------------------------------------------------
# VAL-W7-020: cassette is JSONL on disk under ~/.relay/cassettes/<session>/
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-020")
def test_cassette_is_utf8_jsonl_under_session_dir(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """The cassette file MUST be UTF-8 JSONL under <session>/cassette.jsonl."""
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(b'{"id":"r1"}').hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    request = make_canonical_request()
    _record_one(
        empty_cassette_dir,
        fixture=fixture,
        request=request,
        response_bytes=b'{"id":"r1"}',
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    assert cassette_path.is_file(), "cassette must exist on disk"
    raw = cassette_path.read_bytes()
    # Must be valid UTF-8.
    raw.decode("utf-8")
    # Must end with exactly one trailing newline.
    assert raw.endswith(b"\n")
    # Each line must parse as a single JSON object.
    for line in raw.decode("utf-8").splitlines():
        assert line, "no blank lines"
        obj = json.loads(line)
        assert isinstance(obj, dict)


@pytest.mark.fulfills("VAL-W7-020")
def test_cassette_path_lives_under_relay_home(
    empty_cassette_dir: Path,
    relay_home_tmp: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """The session dir MUST be a child of ${RELAY_HOME}/cassettes/."""
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(b"{}").hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    request = make_canonical_request()
    _record_one(
        empty_cassette_dir,
        fixture=fixture,
        request=request,
        response_bytes=b"{}",
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    expected_root = relay_home_tmp / "cassettes"
    assert expected_root in cassette_path.parents


# -----------------------------------------------------------------------------
# VAL-W7-021: cassette record matches ReplayFixture v1 schema
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-021")
def test_cassette_record_validates_against_replay_fixture_v1(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """Every JSONL record MUST validate against ReplayFixture v1."""
    from relay_schemas.envelopes import ReplayFixture

    body = b'{"choices":[]}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    _record_one(
        empty_cassette_dir,
        fixture=fixture,
        request=make_canonical_request(),
        response_bytes=body,
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    for line in cassette_path.read_text(encoding="utf-8").splitlines():
        obj = json.loads(line)
        assert obj["schema_version"] == REPLAY_FIXTURE_SCHEMA_VERSION
        # Re-validating must succeed.
        ReplayFixture.model_validate(obj)


@pytest.mark.fulfills("VAL-W7-021")
def test_cassette_load_rejects_record_with_unknown_fixture_field(
    empty_cassette_dir: Path,
) -> None:
    """A record with an unknown field MUST fail validation on load.

    Pydantic v2 in strict mode rejects extra fields. ReplayFixture
    inherits strict-extras semantics from the _RelayEnvelope base class.
    """
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    bogus = {
        "schema_version": REPLAY_FIXTURE_SCHEMA_VERSION,
        "fixture_id": "00000000-0000-4000-8000-000000000001",
        "replay_case_id": "00000000-0000-4000-8000-000000000002",
        "source_span_id": "00000000-0000-4000-8000-000000000003",
        "kind": "model_call",
        "mode": "cassette",
        "redaction_policy_version": "relay.redaction.v1#default",
        "input_digest": "sha256-" + "1" * 64,
        "side_effect_class": "read_only",
        "capture_clock": "2026-05-14T10:00:00+00:00",
        "created_at": "2026-05-14T10:00:00+00:00",
        "unknown_extra_field": "BOOM",
    }
    cassette_path.write_text(
        json.dumps(bogus, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path)
    assert "ReplayFixture v1 validation failed" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W7-022: canonical key derivation is deterministic
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-022")
def test_canonical_key_is_deterministic_json_branch(
    make_canonical_request: Any,
) -> None:
    """JSON content-type: same logical request -> identical key."""
    a = make_canonical_request(
        body_bytes=b'{"a":1,"b":2,"c":[1,2]}',
        content_type="application/json",
    )
    b = make_canonical_request(
        # Same logical JSON, different formatting + key order.
        body_bytes=b'{"c":[1,2],"b":2,"a":1}',
        content_type="application/json",
    )
    assert derive_canonical_key(a) == derive_canonical_key(b)


@pytest.mark.fulfills("VAL-W7-022")
def test_canonical_key_is_deterministic_octet_branch(
    make_canonical_request: Any,
) -> None:
    """application/octet-stream: identical raw bytes -> identical key."""
    a = make_canonical_request(
        body_bytes=b"\x00\x01binary\xfe\xff",
        content_type="application/octet-stream",
    )
    b = make_canonical_request(
        body_bytes=b"\x00\x01binary\xfe\xff",
        content_type="application/octet-stream",
    )
    assert derive_canonical_key(a) == derive_canonical_key(b)
    # And different bytes -> different key.
    c = make_canonical_request(
        body_bytes=b"\x00\x01different\xfe\xff",
        content_type="application/octet-stream",
    )
    assert derive_canonical_key(a) != derive_canonical_key(c)


@pytest.mark.fulfills("VAL-W7-022")
def test_canonical_key_is_deterministic_multipart_branch(
    make_canonical_request: Any,
) -> None:
    """multipart/form-data: boundary token MUST be stripped from the key.

    Two multipart requests with identical part contents but different
    boundary tokens MUST produce identical canonical keys.
    """
    boundary1 = "----A1B2C3"
    boundary2 = "----X9Y8Z7"
    body1 = (
        f"--{boundary1}\r\n"
        f'Content-Disposition: form-data; name="model"\r\n\r\n'
        f"gpt-4o-mini\r\n"
        f"--{boundary1}\r\n"
        f'Content-Disposition: form-data; name="prompt"\r\n\r\n'
        f"hello\r\n"
        f"--{boundary1}--\r\n"
    ).encode()
    body2 = (
        f"--{boundary2}\r\n"
        f'Content-Disposition: form-data; name="model"\r\n\r\n'
        f"gpt-4o-mini\r\n"
        f"--{boundary2}\r\n"
        f'Content-Disposition: form-data; name="prompt"\r\n\r\n'
        f"hello\r\n"
        f"--{boundary2}--\r\n"
    ).encode()
    a = make_canonical_request(
        body_bytes=body1,
        content_type=f"multipart/form-data; boundary={boundary1}",
        headers={"content-type": f"multipart/form-data; boundary={boundary1}"},
    )
    b = make_canonical_request(
        body_bytes=body2,
        content_type=f"multipart/form-data; boundary={boundary2}",
        headers={"content-type": f"multipart/form-data; boundary={boundary2}"},
    )
    assert derive_canonical_key(a) == derive_canonical_key(b)


@pytest.mark.fulfills("VAL-W7-022")
def test_canonical_key_is_deterministic_sse_branch(
    make_canonical_request: Any,
) -> None:
    """text/event-stream: per-event JCS canonicalization."""
    body = (
        b'data: {"a":1,"b":2}\n\n'
        b'data: {"c":[3,4]}\n\n'
    )
    body_reordered = (
        b'data: {"b":2,"a":1}\n\n'
        b'data: {"c":[3,4]}\n\n'
    )
    a = make_canonical_request(
        body_bytes=body,
        content_type="text/event-stream",
        headers={"content-type": "text/event-stream"},
    )
    b = make_canonical_request(
        body_bytes=body_reordered,
        content_type="text/event-stream",
        headers={"content-type": "text/event-stream"},
    )
    assert derive_canonical_key(a) == derive_canonical_key(b)


@pytest.mark.fulfills("VAL-W7-022")
def test_canonical_key_invariant_to_query_param_order(
    make_canonical_request: Any,
) -> None:
    """Query string parameter order MUST not affect the key."""
    a = make_canonical_request(
        url="https://api.example.com/v1/items?b=2&a=1&c=3",
    )
    b = make_canonical_request(
        url="https://api.example.com/v1/items?c=3&a=1&b=2",
    )
    assert derive_canonical_key(a) == derive_canonical_key(b)


@pytest.mark.fulfills("VAL-W7-022")
def test_canonical_key_format_is_sha256_prefix(
    make_canonical_request: Any,
) -> None:
    """Key MUST be ``sha256-`` + 64 hex chars."""
    key = derive_canonical_key(make_canonical_request())
    assert key.startswith("sha256-")
    assert len(key) == len("sha256-") + 64
    int(key.split("-", 1)[1], 16)  # parses as hex


# -----------------------------------------------------------------------------
# VAL-W7-023: canonical key ignores User-Agent / Authorization / Date
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-023")
@pytest.mark.parametrize(
    "header_name,header_value_a,header_value_b",
    [
        ("User-Agent", "openai-python/1.0", "openai-python/2.0"),
        ("Authorization", "Bearer sk-aaa", "Bearer sk-bbb"),
        ("Date", "Wed, 14 May 2026 10:00:00 GMT", "Thu, 15 May 2026 11:00:00 GMT"),
        ("X-Request-Id", "req-abc-123", "req-xyz-789"),
    ],
)
def test_canonical_key_ignores_excluded_header(
    make_canonical_request: Any,
    header_name: str,
    header_value_a: str,
    header_value_b: str,
) -> None:
    """A mutation in an excluded header MUST not change the key."""
    a = make_canonical_request(
        headers={
            "content-type": "application/json",
            header_name: header_value_a,
        },
    )
    b = make_canonical_request(
        headers={
            "content-type": "application/json",
            header_name: header_value_b,
        },
    )
    assert derive_canonical_key(a) == derive_canonical_key(b)


@pytest.mark.fulfills("VAL-W7-023")
def test_excluded_header_set_includes_canonical_volatiles() -> None:
    """The excluded set MUST contain at least the canonical volatile headers."""
    must_exclude = {
        "user-agent",
        "authorization",
        "date",
        "x-request-id",
    }
    assert must_exclude.issubset(KEY_EXCLUDED_HEADERS)


@pytest.mark.fulfills("VAL-W7-023")
def test_canonical_key_changes_when_relevant_header_changes(
    make_canonical_request: Any,
) -> None:
    """A mutation in a relevant header (Content-Type) MUST change the key."""
    a = make_canonical_request(
        headers={"content-type": "application/json"},
        body_bytes=b'{"x":1}',
        content_type="application/json",
    )
    b = make_canonical_request(
        headers={"content-type": "text/plain"},
        body_bytes=b'{"x":1}',
        content_type="text/plain",
    )
    assert derive_canonical_key(a) != derive_canonical_key(b)


# -----------------------------------------------------------------------------
# VAL-W7-024: cassette miss is FAIL HARD with exit code 4
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-024")
def test_cassette_miss_raises_typed_error(
    empty_cassette_dir: Path,
    make_canonical_request: Any,
) -> None:
    """A miss MUST raise ``RelayCassetteMissError``."""
    request = make_canonical_request()
    key = derive_canonical_key(request)
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteMissError) as excinfo:
        raise_cassette_miss(
            canonical_key=key,
            request=request,
            cassette_path=cassette_path,
        )
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_MISS
    assert excinfo.value.details["canonical_key"] == key
    assert excinfo.value.details["exit_code"] == EXIT_CODE_CASSETTE_MISS


@pytest.mark.fulfills("VAL-W7-024")
def test_exit_code_cassette_miss_is_four() -> None:
    """The pinned exit code for cassette miss MUST be 4."""
    assert EXIT_CODE_CASSETTE_MISS == 4


@pytest.mark.fulfills("VAL-W7-024")
def test_cassette_miss_does_not_attempt_live_fallthrough(
    make_canonical_request: Any,
) -> None:
    """``raise_cassette_miss`` MUST always raise (no return path)."""
    # If the function ever returned (silent miss), this loop would fall
    # through and the assertion would fail.
    raised = False
    try:
        raise_cassette_miss(
            canonical_key="sha256-" + "0" * 64,
            request=make_canonical_request(),
            cassette_path=Path("/nonexistent/cassette.jsonl"),
        )
    except RelayCassetteMissError:
        raised = True
    assert raised, "raise_cassette_miss must never return without raising"


# -----------------------------------------------------------------------------
# VAL-W7-025: cassette miss prints canonical key for debuggability
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-025")
def test_cassette_miss_stderr_contains_canonical_key_and_request_triple(
    make_canonical_request: Any,
) -> None:
    """The stderr line MUST contain ``sha256-<64hex>`` AND the method+URL."""
    import re

    request = make_canonical_request(
        method="POST",
        url="https://api.openai.com/v1/chat/completions",
        body_bytes=b'{"model":"gpt-4o-mini"}',
    )
    key = derive_canonical_key(request)
    buf = io.StringIO()
    emit_cassette_miss_stderr(
        canonical_key=key,
        request=request,
        cassette_path=Path("/tmp/x"),
        stream=buf,
    )
    text = buf.getvalue()
    assert re.search(r"sha256-[0-9a-f]{64}", text), text
    assert re.search(r"(GET|POST|PUT|DELETE|PATCH) https://", text), text


@pytest.mark.fulfills("VAL-W7-025")
def test_cassette_miss_error_message_includes_canonical_key(
    make_canonical_request: Any,
) -> None:
    """The exception's message MUST quote the canonical key verbatim."""
    request = make_canonical_request()
    key = derive_canonical_key(request)
    with pytest.raises(RelayCassetteMissError) as excinfo:
        raise_cassette_miss(
            canonical_key=key,
            request=request,
            cassette_path=Path("/tmp/x"),
        )
    assert key in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W7-026: corrupted cassette raises RelayCassetteCorruptError
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-026")
def test_malformed_json_line_raises_corrupt_error(
    empty_cassette_dir: Path,
) -> None:
    """A non-JSON line MUST raise ``RelayCassetteCorruptError`` with line no."""
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    cassette_path.write_text("this is not json\n", encoding="utf-8")
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["line_number"] == 1
    assert "malformed JSON" in str(excinfo.value)


@pytest.mark.fulfills("VAL-W7-026")
def test_corrupted_cassette_quarantine_moves_file(
    empty_cassette_dir: Path,
) -> None:
    """``quarantine_on_error=True`` MUST move the cassette to <session>/quarantine/."""
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    cassette_path.write_text("garbage{not_json\n", encoding="utf-8")
    with pytest.raises(RelayCassetteCorruptError):
        load_cassette(cassette_path, quarantine_on_error=True)
    assert not cassette_path.exists()
    quarantine_dir = empty_cassette_dir / QUARANTINE_DIR_NAME
    assert quarantine_dir.is_dir()
    quarantined = list(quarantine_dir.iterdir())
    assert len(quarantined) == 1
    # The quarantined file's bytes MUST equal the original.
    assert quarantined[0].read_text(encoding="utf-8") == "garbage{not_json\n"


def _seed_one_recorded_fixture(
    session_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> Any:
    """Record one valid fixture (cassette line + bodies + request.json).

    Returns the ``ReplayFixture`` so callers can locate its sidecar file.
    """
    body = b'{"choices":[]}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    _record_one(
        session_dir,
        fixture=fixture,
        request=make_canonical_request(),
        response_bytes=body,
    )
    return fixture


@pytest.mark.fulfills("VAL-ISO-010")
def test_malformed_canonical_request_json_quarantines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 regression: a request.json that is not valid JSON MUST
    raise ``RelayCassetteCorruptError`` and quarantine -- NOT an uncaught
    ``json.JSONDecodeError`` that bypasses the quarantine path."""
    fixture = _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    request_path = (
        empty_cassette_dir / "requests" / f"{fixture.fixture_id}.request.json"
    )
    assert request_path.is_file(), "sidecar request.json must have been written"
    request_path.write_text("{not valid json", encoding="utf-8")

    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path, quarantine_on_error=True)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["line_number"] == 1
    assert excinfo.value.details["fixture_id"] == str(fixture.fixture_id)
    # The malformed cassette MUST have been moved to quarantine.
    assert not cassette_path.exists()
    quarantine_dir = empty_cassette_dir / QUARANTINE_DIR_NAME
    assert quarantine_dir.is_dir()
    assert len(list(quarantine_dir.iterdir())) == 1


@pytest.mark.fulfills("VAL-ISO-010")
def test_canonical_request_missing_method_key_quarantines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 regression: a request.json that is valid JSON but lacks
    a required ``method`` key MUST raise ``RelayCassetteCorruptError`` and
    quarantine -- NOT an uncaught ``KeyError``."""
    fixture = _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    request_path = (
        empty_cassette_dir / "requests" / f"{fixture.fixture_id}.request.json"
    )
    # Valid JSON, but the obj["method"] access in
    # _read_canonical_key_for_fixture will raise KeyError.
    request_path.write_text(
        json.dumps({"url": "https://api.openai.com/v1/chat/completions"}),
        encoding="utf-8",
    )

    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path, quarantine_on_error=True)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["fixture_id"] == str(fixture.fixture_id)
    assert not cassette_path.exists()


@pytest.mark.fulfills("VAL-ISO-010")
def test_canonical_request_non_string_url_quarantines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 regression: a request.json that is valid JSON with a
    NON-STRING ``url`` (e.g. an int) MUST raise ``RelayCassetteCorruptError``
    and quarantine -- NOT an uncaught ``AttributeError`` escaping from
    ``urlparse(<int>)`` inside ``derive_canonical_key``.

    ``_read_canonical_key_for_fixture`` builds ``CanonicalRequest`` (a frozen
    dataclass with no runtime type validation) from the sidecar fields, then
    ``derive_canonical_key`` calls ``urlparse(url)``. When ``url`` is an int,
    ``urlparse`` raises ``AttributeError`` ('int' has no attribute 'decode'),
    which was NOT in the iso-010 quarantine catch tuple, so the malformed
    fixture escaped quarantine.
    """
    fixture = _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    request_path = (
        empty_cassette_dir / "requests" / f"{fixture.fixture_id}.request.json"
    )
    assert request_path.is_file(), "sidecar request.json must have been written"
    request_path.write_text(
        json.dumps(
            {
                "method": "POST",
                "url": 12345,
                "headers": {},
                "body_b64": "",
                "content_type": "application/json",
            }
        ),
        encoding="utf-8",
    )

    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path, quarantine_on_error=True)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["fixture_id"] == str(fixture.fixture_id)
    # The malformed cassette MUST have been moved to quarantine.
    assert not cassette_path.exists()
    quarantine_dir = empty_cassette_dir / QUARANTINE_DIR_NAME
    assert quarantine_dir.is_dir()
    assert len(list(quarantine_dir.iterdir())) == 1


@pytest.mark.fulfills("VAL-ISO-010")
def test_canonical_request_non_string_method_quarantines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 regression: a request.json that is valid JSON with a
    NON-STRING ``method`` (e.g. an int) MUST raise
    ``RelayCassetteCorruptError`` and quarantine -- NOT an uncaught
    ``AttributeError`` escaping from ``self.method.upper()`` inside
    ``CanonicalRequest.canonical_method`` (called by ``derive_canonical_key``).
    """
    fixture = _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    request_path = (
        empty_cassette_dir / "requests" / f"{fixture.fixture_id}.request.json"
    )
    assert request_path.is_file(), "sidecar request.json must have been written"
    request_path.write_text(
        json.dumps(
            {
                "method": 12345,
                "url": "https://api.openai.com/v1/chat/completions",
                "headers": {},
                "body_b64": "",
                "content_type": "application/json",
            }
        ),
        encoding="utf-8",
    )

    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path, quarantine_on_error=True)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["fixture_id"] == str(fixture.fixture_id)
    # The malformed cassette MUST have been moved to quarantine.
    assert not cassette_path.exists()
    quarantine_dir = empty_cassette_dir / QUARANTINE_DIR_NAME
    assert quarantine_dir.is_dir()
    assert len(list(quarantine_dir.iterdir())) == 1


@pytest.mark.fulfills("VAL-ISO-010")
def test_canonical_request_invalid_base64_body_quarantines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 regression: a request.json with a non-base64 body_b64
    value MUST raise ``RelayCassetteCorruptError`` (binascii.Error caught),
    not an uncaught ``binascii.Error``."""
    fixture = _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    request_path = (
        empty_cassette_dir / "requests" / f"{fixture.fixture_id}.request.json"
    )
    request_path.write_text(
        json.dumps(
            {
                "method": "POST",
                "url": "https://api.openai.com/v1/chat/completions",
                "headers": {},
                "body_b64": "@@@not-base64@@@",
                "content_type": "application/json",
            }
        ),
        encoding="utf-8",
    )

    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path, quarantine_on_error=True)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["fixture_id"] == str(fixture.fixture_id)
    assert not cassette_path.exists()


@pytest.mark.fulfills("VAL-ISO-010")
def test_canonical_request_non_utf8_quarantines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 regression: a request.json whose BYTES are not valid
    UTF-8 MUST raise ``RelayCassetteCorruptError`` and quarantine -- NOT an
    uncaught ``UnicodeDecodeError`` that bypasses the quarantine path.

    ``_read_canonical_key_for_fixture`` decodes the sidecar with
    ``read_text(encoding="utf-8")``; an invalid-encoding sidecar raises
    ``UnicodeDecodeError`` (a ``ValueError`` subclass). The iso-010
    quarantine catch tuple previously caught json.JSONDecodeError, KeyError,
    and binascii.Error but NOT UnicodeDecodeError, so a non-UTF-8 malformed
    fixture escaped quarantine.
    """
    fixture = _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    request_path = (
        empty_cassette_dir / "requests" / f"{fixture.fixture_id}.request.json"
    )
    assert request_path.is_file(), "sidecar request.json must have been written"
    # 0xFF / 0xFE are never valid UTF-8 lead bytes -> read_text(utf-8) raises
    # UnicodeDecodeError. Surround with otherwise JSON-looking ASCII so the
    # failure is the decode step (not a later JSON-parse step) -- i.e. the
    # UnicodeDecodeError path specifically.
    request_path.write_bytes(b'{"method": "POST", "url": "\xff\xfe"}')

    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path, quarantine_on_error=True)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert excinfo.value.details["fixture_id"] == str(fixture.fixture_id)
    # The malformed (non-UTF-8) cassette MUST have been moved to quarantine.
    assert not cassette_path.exists()
    quarantine_dir = empty_cassette_dir / QUARANTINE_DIR_NAME
    assert quarantine_dir.is_dir()
    assert len(list(quarantine_dir.iterdir())) == 1


@pytest.mark.fulfills("VAL-ISO-010")
def test_valid_canonical_request_still_loads(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """VAL-ISO-010 guard: a valid recorded cassette still loads cleanly
    after the try/except hardening (no over-rejection)."""
    _seed_one_recorded_fixture(
        empty_cassette_dir, make_replay_fixture, make_canonical_request
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    index = load_cassette(cassette_path)
    assert len(index) == 1


@pytest.mark.fulfills("VAL-W7-026")
def test_blank_line_raises_corrupt_error(empty_cassette_dir: Path) -> None:
    """An empty line in the JSONL stream MUST raise corrupt error."""
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    cassette_path.write_text("\n", encoding="utf-8")
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path)
    assert "blank" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W7-027: cassette is APPEND-ONLY during a recording session
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-027")
def test_append_record_uses_o_append_flag(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The writer MUST open the cassette with O_APPEND."""
    observed_flags: list[int] = []

    real_open = os.open

    def spy_open(path: str, flags: int, mode: int = 0o777) -> int:
        if path.endswith(CASSETTE_FILENAME):
            observed_flags.append(flags)
        return real_open(path, flags, mode)

    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(b"{}").hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    append_record(
        empty_cassette_dir / CASSETTE_FILENAME,
        fixture=fixture,
        canonical_request=make_canonical_request(),
        response_bytes=b"{}",
        open_fn=spy_open,
    )
    assert observed_flags, "open spy was not invoked on the cassette path"
    flag = observed_flags[0]
    assert flag & os.O_APPEND, f"O_APPEND missing from flags 0x{flag:x}"
    assert flag & os.O_WRONLY, f"O_WRONLY missing from flags 0x{flag:x}"
    assert not (flag & os.O_TRUNC), f"O_TRUNC must NOT be set (0x{flag:x})"


@pytest.mark.fulfills("VAL-W7-027")
def test_two_appends_preserve_first_record(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """A second append MUST NOT rewrite the first record."""
    fixture1 = make_replay_fixture(
        fixture_id="00000000-0000-4000-8000-000000000001",
        output_digest="sha256-" + hashlib.sha256(b'{"r":1}').hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    request1 = make_canonical_request(body_bytes=b'{"r":1}')
    fixture2 = make_replay_fixture(
        fixture_id="00000000-0000-4000-8000-000000000005",
        output_digest="sha256-" + hashlib.sha256(b'{"r":2}').hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000005.body",
    )
    request2 = make_canonical_request(body_bytes=b'{"r":2}')
    _record_one(empty_cassette_dir, fixture=fixture1, request=request1, response_bytes=b'{"r":1}')
    _record_one(empty_cassette_dir, fixture=fixture2, request=request2, response_bytes=b'{"r":2}')
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    lines = cassette_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["fixture_id"] == "00000000-0000-4000-8000-000000000001"
    assert json.loads(lines[1])["fixture_id"] == "00000000-0000-4000-8000-000000000005"
    assert cassette_path.read_bytes().endswith(b"\n")


@pytest.mark.fulfills("VAL-W7-027")
def test_simulated_kill_mid_stream_preserves_acked_records(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """A failure between appends MUST leave previously-ACKed records intact.

    We simulate the SIGKILL by raising mid-call on the THIRD append.
    The first two appends MUST be readable post-failure with no torn
    final line.
    """
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    for idx in range(2):
        fid = f"00000000-0000-4000-8000-{idx + 1:012d}"
        body = f'{{"i":{idx}}}'.encode()
        fixture = make_replay_fixture(
            fixture_id=fid,
            output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
            output_ref=f"file://bodies/{fid}.body",
        )
        _record_one(
            empty_cassette_dir,
            fixture=fixture,
            request=make_canonical_request(body_bytes=body),
            response_bytes=body,
        )

    # Now simulate a kill: open_fn raises before any byte is written.
    def boom_open(path: str, flags: int, mode: int = 0o777) -> int:
        raise OSError(errno.EIO, "simulated kill")

    body3 = b'{"i":99}'
    fixture3 = make_replay_fixture(
        fixture_id="00000000-0000-4000-8000-000000000099",
        output_digest="sha256-" + hashlib.sha256(body3).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000099.body",
    )
    with pytest.raises(OSError):
        append_record(
            cassette_path,
            fixture=fixture3,
            canonical_request=make_canonical_request(body_bytes=body3),
            response_bytes=body3,
            open_fn=boom_open,
        )
    # Cassette MUST still have exactly two clean records, terminated by \n.
    raw = cassette_path.read_bytes()
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 2


# -----------------------------------------------------------------------------
# VAL-W7-028: cassette digest matches recorded output_digest on read
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-028")
def test_load_succeeds_when_output_digest_matches(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """Happy path: digest matches; load returns a populated index."""
    body = b'{"id":"resp1","ok":true}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    _record_one(
        empty_cassette_dir,
        fixture=fixture,
        request=make_canonical_request(),
        response_bytes=body,
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    index = load_cassette(cassette_path)
    assert len(index) == 1


@pytest.mark.fulfills("VAL-W7-028")
def test_load_fails_when_body_byte_mutated(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """A single-byte mutation in the body file MUST trip the digest check."""
    body = b'{"id":"resp1","ok":true}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    _record_one(
        empty_cassette_dir,
        fixture=fixture,
        request=make_canonical_request(),
        response_bytes=body,
    )
    body_path = (
        empty_cassette_dir
        / "bodies"
        / "00000000-0000-4000-8000-000000000001.body"
    )
    # Mutate one byte.
    mutated = bytearray(body_path.read_bytes())
    mutated[0] = mutated[0] ^ 0x01
    body_path.write_bytes(bytes(mutated))
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteCorruptError) as excinfo:
        load_cassette(cassette_path)
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert "output_digest mismatch" in str(excinfo.value)
    assert "expected" in str(excinfo.value)
    assert "actual" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W7-029: cassette refresh policy is honoured on replay
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-029")
def test_refresh_policy_signature_drift_marks_stale(
    make_replay_fixture: Any,
) -> None:
    """invalidate_on_signature_change: signature drift -> stale."""
    fixture = make_replay_fixture(
        refresh_policy=REFRESH_POLICY_INVALIDATE_ON_SIG,
        model_signature="fp_capture_v1",
    )
    decision = evaluate_refresh_policy(
        fixture, observed_system_fingerprint="fp_replay_v2"
    )
    assert decision.stale is True
    assert decision.divergence_reason == "signature_drift"
    assert decision.policy == REFRESH_POLICY_INVALIDATE_ON_SIG


@pytest.mark.fulfills("VAL-W7-029")
def test_refresh_policy_signature_match_is_fresh(
    make_replay_fixture: Any,
) -> None:
    """invalidate_on_signature_change: same signature -> not stale."""
    fixture = make_replay_fixture(
        refresh_policy=REFRESH_POLICY_INVALIDATE_ON_SIG,
        model_signature="fp_steady",
    )
    decision = evaluate_refresh_policy(
        fixture, observed_system_fingerprint="fp_steady"
    )
    assert decision.stale is False
    assert decision.divergence_reason == "none"


@pytest.mark.fulfills("VAL-W7-029")
def test_refresh_policy_hold_forever_never_stale(
    make_replay_fixture: Any,
) -> None:
    """hold_forever: ALWAYS not stale, even on signature drift."""
    fixture = make_replay_fixture(
        refresh_policy=REFRESH_POLICY_HOLD_FOREVER,
        model_signature="fp_capture",
    )
    decision = evaluate_refresh_policy(
        fixture, observed_system_fingerprint="fp_drift"
    )
    assert decision.stale is False
    assert decision.divergence_reason == "none"


# -----------------------------------------------------------------------------
# VAL-W7-030: AV / FS lock on cassette write retries with backoff
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-030")
def test_eacces_then_success_retries_and_succeeds(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """One EACCES followed by a real open MUST succeed via retry."""
    real_open = os.open
    call_count = {"n": 0}

    def flaky_open(path: str, flags: int, mode: int = 0o777) -> int:
        if path.endswith(CASSETTE_FILENAME):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError(errno.EACCES, "simulated AV lock")
        return real_open(path, flags, mode)

    delays: list[float] = []

    def spy_sleep(d: float) -> None:
        delays.append(d)

    body = b'{"ok":1}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    t0 = time.monotonic()
    append_record(
        cassette_path,
        fixture=fixture,
        canonical_request=make_canonical_request(),
        response_bytes=body,
        open_fn=flaky_open,
        sleep_fn=spy_sleep,
    )
    elapsed = time.monotonic() - t0
    assert call_count["n"] >= 2, "writer must have retried at least once"
    assert delays, "sleep must have been called for backoff"
    # First retry uses the first delay in the schedule.
    assert delays[0] == WRITE_RETRY_DELAYS_S[0]
    # Total wall time stays well under the contract bound (<5 s).
    assert elapsed < 5.0
    assert cassette_path.exists()


@pytest.mark.fulfills("VAL-W7-030")
def test_persistent_eacces_exhausts_retries_and_raises(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """All retries exhausted MUST raise ``RelayCassetteWriteRetryExhaustedError``."""

    def always_eacces(path: str, flags: int, mode: int = 0o777) -> int:
        raise OSError(errno.EACCES, "AV holds the file forever")

    body = b'{"ok":1}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(RelayCassetteWriteRetryExhaustedError) as excinfo:
        append_record(
            cassette_path,
            fixture=fixture,
            canonical_request=make_canonical_request(),
            response_bytes=body,
            open_fn=always_eacces,
            sleep_fn=lambda _d: None,
        )
    assert excinfo.value.code == RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED
    assert excinfo.value.details["attempts"] == len(WRITE_RETRY_DELAYS_S)
    assert excinfo.value.details["last_errno"] == errno.EACCES


@pytest.mark.fulfills("VAL-W7-030")
def test_non_lock_oserror_raises_immediately(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """An OSError that is NOT EACCES / share-violation MUST NOT be retried."""

    def enospc_open(path: str, flags: int, mode: int = 0o777) -> int:
        raise OSError(errno.ENOSPC, "disk full")

    body = b'{"ok":1}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    with pytest.raises(OSError) as excinfo:
        append_record(
            cassette_path,
            fixture=fixture,
            canonical_request=make_canonical_request(),
            response_bytes=body,
            open_fn=enospc_open,
            sleep_fn=lambda _d: None,
        )
    assert excinfo.value.errno == errno.ENOSPC
    assert not isinstance(excinfo.value, RelayCassetteWriteRetryExhaustedError)


# -----------------------------------------------------------------------------
# VAL-W7-031: cassette index unaffected by entry order
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-031")
def test_index_lookup_identical_across_orderings(
    empty_cassette_dir: Path,
    cassette_root: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """Two cassettes with the same records in different order MUST produce
    identical lookup behavior for every key.
    """
    bodies = [
        (f"00000000-0000-4000-8000-{i + 1:012d}", f'{{"i":{i}}}'.encode())
        for i in range(5)
    ]
    requests = [
        make_canonical_request(body_bytes=body) for _, body in bodies
    ]
    keys = [derive_canonical_key(r) for r in requests]

    # Build cassette A: insertion in [0..4] order.
    session_a = empty_cassette_dir
    for (fid, body), req in zip(bodies, requests, strict=True):
        fixture = make_replay_fixture(
            fixture_id=fid,
            output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
            output_ref=f"file://bodies/{fid}.body",
        )
        _record_one(session_a, fixture=fixture, request=req, response_bytes=body)
    index_a = load_cassette(session_a / CASSETTE_FILENAME)

    # Build cassette B: insertion in REVERSED order.
    session_b = cassette_root / "ses02_reversed_order"
    session_b.mkdir(parents=True, exist_ok=True)
    for (fid, body), req in zip(reversed(bodies), reversed(requests), strict=True):
        fixture = make_replay_fixture(
            fixture_id=fid,
            output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
            output_ref=f"file://bodies/{fid}.body",
        )
        _record_one(session_b, fixture=fixture, request=req, response_bytes=body)
    index_b = load_cassette(session_b / CASSETTE_FILENAME)

    assert len(index_a) == len(index_b) == len(bodies)
    for key in keys:
        rec_a = index_a.lookup(key)
        rec_b = index_b.lookup(key)
        assert rec_a is not None and rec_b is not None
        assert rec_a.fixture.fixture_id == rec_b.fixture.fixture_id
        assert rec_a.response_bytes == rec_b.response_bytes


@pytest.mark.fulfills("VAL-W7-031")
def test_index_miss_returns_none() -> None:
    """A miss on the index MUST return None (no exception)."""
    index = CassetteIndex()
    assert index.lookup("sha256-" + "0" * 64) is None
    assert len(index) == 0


# -----------------------------------------------------------------------------
# Defensive: source code does not call banned APIs
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-027")
def test_no_pkill_or_killall_in_cassette_format_source() -> None:
    """CLAUDE.md process-safety: no pkill/killall by name."""
    src = Path(__file__).resolve().parents[1] / "relay_replay_proxy" / "cassette_format.py"
    text = src.read_text(encoding="utf-8")
    assert "pkill" not in text
    assert "killall" not in text


# Suppress unused-import warnings for symbols referenced via fixtures only.
_ = (subprocess, sys, CanonicalKeyConfig)
