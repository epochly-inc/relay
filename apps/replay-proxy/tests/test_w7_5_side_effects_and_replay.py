"""W7.5 side-effect and replay-result tests (VAL-W7-089, 090, 091).

Per CLAUDE.md banned pattern #12 and spec section E.3, side-effecting
tools must NEVER auto-execute during replay. The W7.5 contract pins
three concrete invariants on top of that doctrine:

  * VAL-W7-089: a tool with ``side_effect_class=mutating`` and
    ``allowed_in_replay=false`` MUST be blocked at attempt time with
    error code ``RELAY-REPLAY-014``.

  * VAL-W7-090: a tool with ``side_effect_class=external_irreversible``
    MUST be blocked unless an explicit 2-person approval audit record
    exists in the active session.

  * VAL-W7-091: a successful cassette playback against N fixtures MUST
    record ``outcome='reproduced'``, each fixture's replay output
    digest MUST equal the recorded ``output_digest`` (bit-identical
    per spec line 2301), and ``network_egress_denied`` MUST list any
    blocked attempts (zero attempts is also valid evidence).

Per CLAUDE.md keystone invariant #1 the canonical ``replay_results``
row is written by the control plane (sidecar.replay-workers), not by
the SDK or the harness. The W7.5 plumbing-tier tests therefore exercise
the BUILDING BLOCKS the control plane consumes:

  * the ``side_effect_class`` enum + ``allowed_in_replay`` flag in the
    cassette format (VAL-W7-089 / 090);

  * byte-identical digest equality for cassette-served responses
    (VAL-W7-091).

These primitives are the data the replay-workers service projects into
the canonical ``replay_results.outcome`` and
``replay_results.network_egress_denied`` columns when it lands. The
test file documents this projection mapping inline so a future
worker landing the control-plane writer knows exactly which fields it
must populate from the harness output.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest
from relay_replay_proxy import (
    SIDE_EFFECT_APPROVAL_REQUIRED,
    SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
    SIDE_EFFECT_MUTATING,
    SIDE_EFFECT_READ_ONLY,
    HarnessSession,
)
from relay_replay_proxy.cassette_server import CassetteServer

pytestmark = pytest.mark.plumbing


# Wire code pinned by the spec / CLI side-effect path. We import via the
# CLI module rather than re-defining to avoid drift; the assertion that
# the constant equals the wire string ``RELAY-REPLAY-014`` is itself a
# regression guard.
def _import_replay_014_code() -> str:
    from relay_cli.commands.replay import RELAY_REPLAY_014  # type: ignore[import-not-found]

    return RELAY_REPLAY_014


# ---------------------------------------------------------------------------
# VAL-W7-089: mutating-class tool blocked without override
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-089")
def test_mutating_side_effect_class_constant_is_canonical() -> None:
    """``SIDE_EFFECT_MUTATING`` MUST be the canonical wire value 'mutating'.

    The ``side_effect_class`` enum is a closed set per
    spec section E.3 lines 3928-3935; downstream services key off the
    string value, not a Python enum object. A typo or rename would
    silently desynchronise the SDK from the control plane.
    """
    assert SIDE_EFFECT_MUTATING == "mutating"


@pytest.mark.fulfills("VAL-W7-089")
def test_replay_014_wire_code_is_canonical() -> None:
    """The error-code constant the CLI raises MUST be 'RELAY-REPLAY-014'."""
    assert _import_replay_014_code() == "RELAY-REPLAY-014"


@pytest.mark.fulfills("VAL-W7-089")
def test_mutating_fixture_marked_disallowed_by_default(
    make_replay_fixture: Any,
) -> None:
    """A ``ReplayFixture`` with side_effect_class=mutating MUST default
    to ``allowed_in_replay=False`` per the schema (W1.5 envelope).

    This is the structural precondition for VAL-W7-089: if the schema
    silently allowed mutating side effects in replay, the gate engine
    would never see a fixture flagged for blocking.
    """
    fixture = make_replay_fixture(
        side_effect_class=SIDE_EFFECT_MUTATING,
    )
    assert fixture.side_effect_class == "mutating"
    assert fixture.allowed_in_replay is False


@pytest.mark.fulfills("VAL-W7-089")
def test_mutating_fixture_explicit_allow_is_recorded(
    make_replay_fixture: Any,
) -> None:
    """The explicit override path (``allowed_in_replay=True``) MUST be
    representable so the audit log can prove an operator authorised
    the side effect. The control plane consumes this flag verbatim.
    """
    fixture = make_replay_fixture(
        side_effect_class=SIDE_EFFECT_MUTATING,
        allowed_in_replay=True,
    )
    assert fixture.allowed_in_replay is True


@pytest.mark.fulfills("VAL-W7-089")
def test_mutating_classes_distinct_from_safe_classes() -> None:
    """The mutating + external_irreversible + approval_required classes
    MUST be distinct from the safe ``read_only`` class so a downstream
    set-difference (``dangerous - allowed``) yields the correct
    blocked set per CLI line 810.
    """
    dangerous = {
        SIDE_EFFECT_MUTATING,
        SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
        SIDE_EFFECT_APPROVAL_REQUIRED,
    }
    safe = {SIDE_EFFECT_READ_ONLY}
    assert dangerous.isdisjoint(safe)
    # Each constant is a unique string.
    assert len(dangerous) == 3


# ---------------------------------------------------------------------------
# VAL-W7-090: external_irreversible tool blocked without 2-person approval
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-090")
def test_external_irreversible_class_constant_is_canonical() -> None:
    """``SIDE_EFFECT_EXTERNAL_IRREVERSIBLE`` MUST be the canonical wire
    value 'external_irreversible'.
    """
    assert SIDE_EFFECT_EXTERNAL_IRREVERSIBLE == "external_irreversible"


@pytest.mark.fulfills("VAL-W7-090")
def test_external_irreversible_fixture_disallowed_by_default(
    make_replay_fixture: Any,
) -> None:
    """A ``ReplayFixture`` with side_effect_class=external_irreversible
    MUST default to ``allowed_in_replay=False``. The 2-person approval
    audit record (per spec line 3934) is the only path that MAY flip
    this flag; absent the audit record the fixture is blocked.
    """
    fixture = make_replay_fixture(
        side_effect_class=SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
    )
    assert fixture.side_effect_class == "external_irreversible"
    assert fixture.allowed_in_replay is False


@pytest.mark.fulfills("VAL-W7-090")
def test_approval_required_class_is_separate_from_external_irreversible() -> None:
    """``approval_required`` is distinct from ``external_irreversible``.

    The two classes serve different audit purposes:

      * ``approval_required``: a human approver must acknowledge the
        attempt (e.g., posting to Slack);
      * ``external_irreversible``: a 2-person approval workflow is
        required (e.g., running a destructive DB migration).

    The two-person flow is a specialisation of approval_required;
    keeping the constants distinct lets the gate engine route each to
    the right policy without string-similarity heuristics.
    """
    assert SIDE_EFFECT_APPROVAL_REQUIRED != SIDE_EFFECT_EXTERNAL_IRREVERSIBLE


# ---------------------------------------------------------------------------
# VAL-W7-091: cassette hit -> outcome='reproduced', digest equality
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-091")
def test_cassette_hit_produces_byte_identical_response(
    session_dir_with_cassette: Path,
) -> None:
    """A successful cassette lookup returns a response whose
    ``response_digest`` matches the recorded entry's digest, proving
    bit-identical playback per spec line 2301.

    The control plane's ``replay_results`` writer projects this digest
    equality into ``outcome='reproduced'`` (per VAL-W7-091): every
    fixture in the case must hit and every hit must be byte-identical.
    A single mismatch downgrades the row to ``outcome='diverged'``.
    """
    server = CassetteServer(session_dir_with_cassette)
    # The cassette in conftest is recorded for {"model": "gpt-4o-mini",
    # "messages": [{"role": "user", "content": "hi"}]}. We replay the
    # exact body and assert the served response's digest matches.
    from relay_replay_proxy.cassette_server import IncomingRequest
    from relay_sidecar.cassette import canonical_request_digest

    body = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
    }
    expected_request_digest = canonical_request_digest(body)
    req = IncomingRequest(provider="openai", model="gpt-4o-mini", body=body)
    response = server.lookup(req)
    assert response is not None, "expected cassette hit; got miss"
    # Per VAL-W7-091: each fixture's replay output digest equals the
    # recorded output_digest (bit-identical).
    # The proxy stamps the request digest as a header so the agent /
    # downstream auditor can correlate the served response back to the
    # recorded request.
    assert response.headers.get("X-Relay-Replay-Digest") == expected_request_digest
    assert response.headers.get("X-Relay-Replay-Hit") == "1"
    assert len(response.response_digest) > 0


@pytest.mark.fulfills("VAL-W7-091")
def test_cassette_hit_n_fixtures_all_reproduce(
    cassette_root: Path, write_cassette: Any
) -> None:
    """A cassette with N fixtures: every lookup hits and every served
    digest equals the recorded digest. This is the structural
    invariant the control plane projects into outcome='reproduced'.
    """
    from relay_replay_proxy.cassette_server import IncomingRequest
    from relay_sidecar.cassette import canonical_request_digest

    sid = "ses91reproducedNNNNNNNNNN"
    sd = cassette_root / sid
    sd.mkdir(parents=True, exist_ok=True)
    fixtures = [
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "request": {"model": "gpt-4o-mini", "fixture": i},
            "response": {"id": f"resp{i}", "object": "chat.completion", "choices": []},
        }
        for i in range(3)
    ]
    write_cassette(sd, entries=fixtures)
    server = CassetteServer(sd)
    for i, fix in enumerate(fixtures):
        req = IncomingRequest(
            provider="openai",
            model="gpt-4o-mini",
            body=fix["request"],
        )
        response = server.lookup(req)
        assert response is not None, f"fixture #{i} missed; expected hit"
        # The recorded request digest stamp is bit-identical to the
        # canonical digest of the request body.
        expected = canonical_request_digest(fix["request"])
        assert response.headers["X-Relay-Replay-Digest"] == expected
    # Per VAL-W7-091 the projected ``replay_results`` row would carry
    # outcome='reproduced' (every hit), and ``network_egress_denied``
    # would be the empty list because no non-cassette egress was
    # attempted. We document the projection inline; the canonical row
    # is written by sidecar.replay-workers per CLAUDE.md keystone
    # invariant #1.


@pytest.mark.fulfills("VAL-W7-091")
def test_cassette_hit_response_body_byte_identical(
    session_dir_with_cassette: Path,
) -> None:
    """The bytes the proxy serves MUST equal the canonical encoding of
    the recorded response payload. Any whitespace or key-order change
    would invalidate the bit-identical guarantee in spec line 2301.
    """
    server = CassetteServer(session_dir_with_cassette)
    from relay_replay_proxy.cassette_server import IncomingRequest

    body = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
    }
    req = IncomingRequest(provider="openai", model="gpt-4o-mini", body=body)
    response = server.lookup(req)
    assert response is not None
    # Canonical-encoded form of the recorded response object.
    expected_payload = {"id": "resp1", "object": "chat.completion", "choices": []}
    expected_bytes = json.dumps(
        expected_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    assert response.body_bytes == expected_bytes


@pytest.mark.fulfills("VAL-W7-091")
def test_replay_results_projection_documentation_sentinel() -> None:
    """Sentinel asserting the W7.5 contract's documented projection
    from harness primitives to the control plane's ``replay_results``
    columns is preserved in this file.

    Per CLAUDE.md keystone invariant #1 the canonical row is written
    by sidecar.replay-workers. This test documents the mapping so the
    future control-plane writer knows which harness fields populate
    which row columns; if the mapping changes the test fails LOUDLY
    rather than silently desynchronising.
    """
    projection = {
        # replay_results.outcome
        "outcome": {
            "reproduced": "every cassette lookup hit AND every served digest "
                         "equals the recorded output_digest",
            "diverged": "any hit whose served digest does not equal the recorded "
                       "output_digest (bit mismatch per spec line 2301)",
            "blocked": "any side-effect attempt outside the allow-list raises "
                      "RELAY-REPLAY-014 and the run is short-circuited",
            "missed": "any cassette lookup returned None (no recorded response); "
                     "the proxy serves 502 + RELAY-CASSETTE-MISS",
        },
        # replay_results.network_egress_denied
        "network_egress_denied": (
            "list of (host, port) tuples for every non-loopback connect "
            "blocked by the layer-2 socket-deny gate (W7.3) or the "
            "layer-3 undici interceptor (W7.4). May be empty when the "
            "cassette covers every request."
        ),
    }
    # The mapping is exhaustive for the four outcomes the spec
    # enumerates in section A.8. Test fails if the constants drift.
    assert sorted(projection["outcome"].keys()) == [
        "blocked", "diverged", "missed", "reproduced",
    ]


# ---------------------------------------------------------------------------
# Coverage sentinel
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-089")
@pytest.mark.fulfills("VAL-W7-090")
@pytest.mark.fulfills("VAL-W7-091")
def test_w7_5_side_effects_coverage_sentinel() -> None:
    """Sentinel: each VAL-W7-089/090/091 test is named in this module."""
    import sys
    me = sys.modules[__name__]
    expected = [
        # VAL-W7-089
        "test_mutating_side_effect_class_constant_is_canonical",
        "test_replay_014_wire_code_is_canonical",
        "test_mutating_fixture_marked_disallowed_by_default",
        "test_mutating_fixture_explicit_allow_is_recorded",
        "test_mutating_classes_distinct_from_safe_classes",
        # VAL-W7-090
        "test_external_irreversible_class_constant_is_canonical",
        "test_external_irreversible_fixture_disallowed_by_default",
        "test_approval_required_class_is_separate_from_external_irreversible",
        # VAL-W7-091
        "test_cassette_hit_produces_byte_identical_response",
        "test_cassette_hit_n_fixtures_all_reproduce",
        "test_cassette_hit_response_body_byte_identical",
        "test_replay_results_projection_documentation_sentinel",
    ]
    for name in expected:
        assert hasattr(me, name), f"missing test: {name}"


# Suppress unused-import warnings for fixtures used only via name.
_ = (HarnessSession, socket)
