"""In-process driver fail-closed regression (roborev e93594b follow-on).

The mitmproxy driver's malformed-body block was covered by
``test_w7_1_addon_fail_closed.py``; this pins the SAME guarantee for the
in-process driver (``DRIVER_INPROC``): a non-empty malformed / non-object
request body must be BLOCKED (502 RELAY-REPLAY-025), NOT coerced to ``{}`` and
matched against an empty-object cassette entry. ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import http.client
from pathlib import Path
from typing import Any

import pytest
from relay_replay_proxy.harness import HarnessConfig, HarnessSession


def _post(port: int, body: bytes) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        conn.request(
            "POST",
            "/v1/chat/completions",
            body=body,
            headers={
                "Content-Type": "application/json",
                "X-Relay-Provider": "openai",
                "X-Relay-Model": "gpt-4o-mini",
            },
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _start_with_empty_object_cassette(
    cassette_root: Path, write_cassette: Any
) -> HarnessSession:
    # An empty-object {} request entry: under the OLD coerce-to-{} behavior a
    # malformed body would canonicalize to {} and HIT this (leaking 'leak'); the
    # fix must BLOCK before lookup. Same provider/model as the POST so only the
    # body shape decides hit-vs-block.
    session_id = "ses02abcdefghijklmnopqr"
    sd = cassette_root / session_id
    sd.mkdir(parents=True, exist_ok=True)
    write_cassette(
        sd,
        entries=[
            {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "request": {},
                "response": {
                    "id": "leak",
                    "object": "chat.completion",
                    "choices": [],
                },
            }
        ],
    )
    sess = HarnessSession(
        HarnessConfig(session_id=session_id, cassette_root=cassette_root)
    )
    sess.start()
    return sess


@pytest.mark.plumbing
def test_inproc_malformed_body_blocks_not_empty_object_hit(
    cassette_root: Path, write_cassette: Any, use_inproc_driver: None
) -> None:
    """Invalid (unparseable) non-empty body -> 502 block, not a {}-entry hit."""
    sess = _start_with_empty_object_cassette(cassette_root, write_cassette)
    try:
        handle = sess.handle
        assert handle is not None
        status, payload = _post(handle.proxy_port, b"{ this is not valid json")
    finally:
        sess.stop()
    assert status == 502, f"malformed body must be blocked, got {status}: {payload!r}"
    assert b"RELAY-REPLAY-025" in payload
    assert b"leak" not in payload


@pytest.mark.plumbing
def test_inproc_non_object_json_body_blocks_not_empty_object_hit(
    cassette_root: Path, write_cassette: Any, use_inproc_driver: None
) -> None:
    """Valid-JSON-but-non-object body (array) -> 502 block, not a {}-entry hit."""
    sess = _start_with_empty_object_cassette(cassette_root, write_cassette)
    try:
        handle = sess.handle
        assert handle is not None
        status, payload = _post(handle.proxy_port, b"[1, 2, 3]")
    finally:
        sess.stop()
    assert status == 502, f"non-object body must be blocked, got {status}: {payload!r}"
    assert b"RELAY-REPLAY-025" in payload
    assert b"leak" not in payload
