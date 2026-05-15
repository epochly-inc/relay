"""Shared fixtures for the W7.1 replay-proxy plumbing tests.

Per CLAUDE.md "Working Directory and Environment" every test that touches
``RELAY_HOME`` MUST use a per-test temp directory so we never write to the
developer's real ``~/.relay``. Per VAL-W7-005 the session_dir MUST live
under ``<cassette_root>/<session_id>/`` where cassette_root is
``${RELAY_HOME}/cassettes``.

The ``inproc`` driver is the default test driver because it has zero
external dependencies and works on every CI matrix cell.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from relay_replay_proxy import (
    DRIVER_INPROC,
    ENV_DRIVER,
    HarnessConfig,
    HarnessSession,
)


@pytest.fixture
def relay_home_tmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """Set ``RELAY_HOME`` to a fresh tmpdir; yield it.

    Mirrors the local-sidecar fixture so tests follow one convention.
    """
    home = tmp_path / "relay-home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RELAY_HOME", str(home))
    yield home


@pytest.fixture
def cassette_root(relay_home_tmp: Path) -> Path:
    """Return the per-test cassette root and ensure it exists."""
    root = relay_home_tmp / "cassettes"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def use_inproc_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the in-process driver for plumbing-tier tests."""
    monkeypatch.setenv(ENV_DRIVER, DRIVER_INPROC)


def _write_cassette(
    session_dir: Path,
    *,
    case_id: str = "case01",
    session_id: str | None = None,
    entries: list[dict[str, Any]] | None = None,
) -> Path:
    """Write a minimal valid cassette under ``session_dir``."""
    from relay_cli.cassette import (
        CASSETTE_ENTRY_SCHEMA_VERSION,
        CASSETTE_HEADER_SCHEMA_VERSION,
        CassetteEntry,
        CassetteHeader,
        canonical_request_digest,
        canonical_response_digest,
        write_cassette_file,
    )

    sid = session_id or session_dir.name
    header = CassetteHeader(
        schema_version=CASSETTE_HEADER_SCHEMA_VERSION,
        case_id=case_id,
        session_id=sid,
        recorded_at="2026-05-14T00:00:00Z",
        manifest_commit_hash="sha256-" + ("0" * 64),
    )
    entry_objs: list[CassetteEntry] = []
    for idx, body in enumerate(entries or []):
        request = body["request"]
        response = body["response"]
        entry_objs.append(
            CassetteEntry(
                schema_version=CASSETTE_ENTRY_SCHEMA_VERSION,
                sequence=idx,
                provider=body.get("provider", "openai"),
                model=body.get("model", "gpt-4o-mini"),
                request_digest=canonical_request_digest(request),
                response=response,
                response_digest=canonical_response_digest(response),
                timestamp=body.get("timestamp", "2026-05-14T00:00:01Z"),
            )
        )
    cassette_path = session_dir / "cassette.jsonl"
    write_cassette_file(cassette_path, header, entry_objs)
    return cassette_path


@pytest.fixture
def write_cassette() -> Any:
    """Expose the cassette writer to tests as a fixture."""
    return _write_cassette


@pytest.fixture
def session_dir_with_cassette(cassette_root: Path) -> Path:
    """Create a fresh session dir with a single recorded entry."""
    session_id = "ses01abcdefghijklmnopqr"
    sd = cassette_root / session_id
    sd.mkdir(parents=True, exist_ok=True)
    _write_cassette(
        sd,
        entries=[
            {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "request": {
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                "response": {"id": "resp1", "object": "chat.completion", "choices": []},
            }
        ],
    )
    return sd


@pytest.fixture
def harness(
    cassette_root: Path,
    session_dir_with_cassette: Path,
    use_inproc_driver: None,
) -> Iterator[HarnessSession]:
    """Construct a started ``HarnessSession`` and tear it down afterwards."""
    cfg = HarnessConfig(
        session_id=session_dir_with_cassette.name,
        cassette_root=cassette_root,
    )
    sess = HarnessSession(cfg)
    try:
        sess.start()
        yield sess
    finally:
        sess.stop()


# -----------------------------------------------------------------------------
# W7.2 ReplayFixture v1 cassette format helpers
# -----------------------------------------------------------------------------


def _make_replay_fixture(
    *,
    fixture_id: str = "00000000-0000-4000-8000-000000000001",
    replay_case_id: str = "00000000-0000-4000-8000-000000000002",
    source_span_id: str = "00000000-0000-4000-8000-000000000003",
    kind: str = "model_call",
    mode: str = "cassette",
    side_effect_class: str = "read_only",
    refresh_policy: str = "invalidate_on_signature_change",
    provider: str | None = "openai",
    model: str | None = "gpt-4o-mini",
    model_signature: str | None = "fp_abc123",
    input_digest: str = "sha256-" + "1" * 64,
    output_digest: str | None = None,
    output_ref: str | None = None,
    capture_clock: str = "2026-05-14T10:00:00+00:00",
    created_at: str = "2026-05-14T10:00:00+00:00",
    redaction_policy_version: str = "relay.redaction.v1#default",
    allowed_in_replay: bool = False,
) -> Any:
    """Build a ``ReplayFixture`` with sensible defaults for tests.

    Defaults satisfy the closed-enum constraints (kind / mode /
    side_effect_class / refresh_policy) and produce a valid record with
    minimal caller-side noise.
    """
    from relay_schemas.envelopes import ReplayFixture

    return ReplayFixture.model_validate(
        {
            "schema_version": "relay.replay_fixture.v1",
            "fixture_id": fixture_id,
            "replay_case_id": replay_case_id,
            "source_span_id": source_span_id,
            "kind": kind,
            "mode": mode,
            "redaction_policy_version": redaction_policy_version,
            "input_digest": input_digest,
            "output_ref": output_ref,
            "output_digest": output_digest,
            "provider": provider,
            "model": model,
            "model_signature": model_signature,
            "capture_clock": capture_clock,
            "refresh_policy": refresh_policy,
            "side_effect_class": side_effect_class,
            "allowed_in_replay": allowed_in_replay,
            "created_at": created_at,
        }
    )


@pytest.fixture
def make_replay_fixture() -> Any:
    """Factory fixture: build ``ReplayFixture`` instances with overrides."""
    return _make_replay_fixture


@pytest.fixture
def make_canonical_request() -> Any:
    """Factory fixture: build ``CanonicalRequest`` instances with overrides."""
    from relay_replay_proxy.cassette_format import CanonicalRequest

    def _make(
        *,
        method: str = "POST",
        url: str = "https://api.openai.com/v1/chat/completions",
        headers: dict[str, str] | None = None,
        body_bytes: bytes = b'{"model":"gpt-4o-mini","messages":[]}',
        content_type: str = "application/json",
    ) -> CanonicalRequest:
        return CanonicalRequest(
            method=method,
            url=url,
            headers=headers if headers is not None else {"content-type": content_type},
            body_bytes=body_bytes,
            content_type=content_type,
        )

    return _make


@pytest.fixture
def empty_cassette_dir(cassette_root: Path) -> Path:
    """Return a fresh, empty session directory under cassette_root."""
    session_id = "ses02_w7_2_test_session_id"
    sd = cassette_root / session_id
    sd.mkdir(parents=True, exist_ok=True)
    return sd


# Suppress unused-import warnings for symbols referenced only via fixtures.
_ = (json, os)
