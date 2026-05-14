"""VAL-W3-019 -- SDK flush_policy.on_error='drop_and_log' does not break
the host application.

Given the sidecar is unreachable AND ``on_error='drop_and_log'``:
  * The SDK MUST NOT raise into the host application.
  * The trace ``__exit__`` returns normally.
  * The event is dropped, and a single ``WARN``-level structured log
    line is emitted (NOT a raw stack trace to stderr).

Per VAL-W3-019 the test asserts:
  1. The host continues (no exception escapes).
  2. A WARN log line is captured.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import logging

import pytest
from relay import Relay

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor"
_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-019")
def test_drop_and_log_does_not_raise_on_unreachable_sidecar(
    relay_home_tmp, caplog
) -> None:
    """An unreachable sidecar + drop_and_log -> host continues, WARN log."""
    # 127.0.0.1:1 -- nothing listens; httpx raises ConnectError on connect.
    unreachable = "http://127.0.0.1:1"

    r = Relay(
        project_key=_VALID_KEY,
        relay_home=relay_home_tmp,
        actor_identity_hash=_ACTOR,
        manifest_commit_hash=_MANIFEST,
        redaction_policy_version="v1",
        endpoint_url=unreachable,
        flush_policy={"mode": "sync", "on_error": "drop_and_log"},
    )
    # Set caplog at WARN level on the run logger so we capture the
    # SDK's structured WARN line.
    caplog.set_level(logging.WARNING, logger="relay.run")

    host_app_continued = False
    with r.run(agent={"name": "ops", "version": "0.1"}) as run:
        # capture() submits a lifecycle envelope. The HTTP call fails
        # because nothing is listening. With drop_and_log the SDK MUST
        # swallow the failure and return.
        result = run.capture(client_lifecycle_status="client_succeeded")
        host_app_continued = True
    # The host application kept running -- VAL-W3-019 contract.
    assert host_app_continued is True
    assert result.get("dropped") is True

    # A WARN-level log line was emitted. Match on the documented prefix
    # ``relay.run.drop_and_log`` so a future logger refactor still
    # tells us where the line came from.
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("drop_and_log" in r.getMessage() for r in warns), (
        f"expected a drop_and_log WARN line; got: "
        f"{[r.getMessage() for r in warns]}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-019")
def test_drop_and_log_async_mode_does_not_raise(relay_home_tmp, caplog) -> None:
    """Async mode + drop_and_log: dispatcher swallows error in background."""
    unreachable = "http://127.0.0.1:1"

    r = Relay(
        project_key=_VALID_KEY,
        relay_home=relay_home_tmp,
        actor_identity_hash=_ACTOR,
        manifest_commit_hash=_MANIFEST,
        redaction_policy_version="v1",
        endpoint_url=unreachable,
        flush_policy={"mode": "async", "on_error": "drop_and_log"},
    )
    caplog.set_level(logging.WARNING, logger="relay.flush")

    with r.run(agent={"name": "ops", "version": "0.1"}) as run:
        result = run.capture(client_lifecycle_status="client_succeeded")
        # Async mode returns queued; the worker thread will then fail
        # to connect and log a WARN line via the dispatcher.
        assert result.get("queued") is True
        # Drain so we know the worker has observed the failure.
        run.flush()

    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("drop_and_log" in r.getMessage() for r in warns), (
        f"expected a drop_and_log WARN line; got: "
        f"{[r.getMessage() for r in warns]}"
    )
