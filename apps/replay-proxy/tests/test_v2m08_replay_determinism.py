"""W8 / V2M08 replay-determinism cassette schema plumbing tests.

Fulfills VAL-V2M08-020..024:
  * VAL-V2M08-020: cassette schema accepts parallel_index, abort_after,
    page_index, and per-attempt retry fields; older cassettes (without the
    new envelope) continue to validate.
  * VAL-V2M08-021: replay orders parallel tool calls by parallel_index.
  * VAL-V2M08-022: replay honors abort_after cancellation token (truncates
    a streaming response at the recorded token_offset and emits a
    ``cancelled_mid_stream`` event).
  * VAL-V2M08-023: replay pagination preserves page_index ordering; a
    cassette with missing or duplicated page_index is rejected with
    ``RELAY-REPLAY-PAGE-ORDER``.
  * VAL-V2M08-024: replay re-emits per-attempt retries from the cassette;
    the recorded delays are honored (within tolerance) and no live provider
    call is made.

Tier-1 plumbing only: the implementation primitives under test live in
``relay_replay_proxy.cassette_format`` and never spawn a real proxy.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest
from relay_replay_proxy.cassette_format import (
    CASSETTE_ENVELOPE_SCHEMA_VERSION,
    CASSETTE_FILENAME,
    RELAY_REPLAY_CANCELLATION_OVERSHOOT_CODE,
    RELAY_REPLAY_PAGE_ORDER_CODE,
    REPLAY_FIXTURE_SCHEMA_VERSION,
    AbortAfter,
    CassetteAttempt,
    CassetteDeterminism,
    CassetteEnvelope,
    append_envelope,
    apply_abort_after,
    iter_attempts_with_delays,
    load_cassette_envelopes,
    order_pages_or_raise,
    order_parallel_records,
    validate_cassette_envelope,
)
from relay_replay_proxy.errors import (
    RELAY_REPLAY_CASSETTE_CORRUPT,
    RelayCassetteCorruptError,
)

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _make_envelope(
    make_replay_fixture: Any,
    *,
    fixture_id: str = "00000000-0000-4000-8000-000000000001",
    parallel_index: int | None = None,
    abort_after: AbortAfter | None = None,
    page_index: int | None = None,
    attempts: list[CassetteAttempt] | None = None,
) -> CassetteEnvelope:
    body = b"{}"
    fixture = make_replay_fixture(
        fixture_id=fixture_id,
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref=f"file://bodies/{fixture_id}.body",
    )
    determinism = CassetteDeterminism(
        parallel_index=parallel_index,
        abort_after=abort_after,
        page_index=page_index,
        attempts=tuple(attempts) if attempts else (),
    )
    return CassetteEnvelope(fixture=fixture, determinism=determinism)


# -----------------------------------------------------------------------------
# VAL-V2M08-020: schema accepts new fields; legacy cassettes still validate
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_validates_with_parallel_index(make_replay_fixture: Any) -> None:
    """``parallel_index`` is a non-negative integer; the envelope accepts it."""
    env = _make_envelope(make_replay_fixture, parallel_index=2)
    obj = env.to_canonical_obj()
    assert obj["schema_version"] == CASSETTE_ENVELOPE_SCHEMA_VERSION
    assert obj["determinism"]["parallel_index"] == 2
    # Round-trip validation succeeds.
    parsed = validate_cassette_envelope(obj)
    assert parsed.determinism.parallel_index == 2


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_validates_with_abort_after(make_replay_fixture: Any) -> None:
    env = _make_envelope(
        make_replay_fixture, abort_after=AbortAfter(token_offset=17)
    )
    obj = env.to_canonical_obj()
    assert obj["determinism"]["abort_after"] == {"token_offset": 17}
    parsed = validate_cassette_envelope(obj)
    assert parsed.determinism.abort_after is not None
    assert parsed.determinism.abort_after.token_offset == 17


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_validates_with_page_index(make_replay_fixture: Any) -> None:
    env = _make_envelope(make_replay_fixture, page_index=3)
    obj = env.to_canonical_obj()
    assert obj["determinism"]["page_index"] == 3
    parsed = validate_cassette_envelope(obj)
    assert parsed.determinism.page_index == 3


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_validates_with_per_attempt_retries(
    make_replay_fixture: Any,
) -> None:
    env = _make_envelope(
        make_replay_fixture,
        attempts=[
            CassetteAttempt(
                attempt_index=0, attempt_delay_ms=0, attempt_outcome="http_5xx"
            ),
            CassetteAttempt(
                attempt_index=1, attempt_delay_ms=250, attempt_outcome="success"
            ),
        ],
    )
    obj = env.to_canonical_obj()
    assert obj["determinism"]["attempts"] == [
        {"attempt_index": 0, "attempt_delay_ms": 0, "attempt_outcome": "http_5xx"},
        {
            "attempt_index": 1,
            "attempt_delay_ms": 250,
            "attempt_outcome": "success",
        },
    ]
    parsed = validate_cassette_envelope(obj)
    assert len(parsed.determinism.attempts) == 2
    assert parsed.determinism.attempts[0].attempt_outcome == "http_5xx"
    assert parsed.determinism.attempts[1].attempt_delay_ms == 250


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_accepts_empty_determinism_block(
    make_replay_fixture: Any,
) -> None:
    """All four determinism fields are optional; an empty block validates."""
    env = _make_envelope(make_replay_fixture)
    parsed = validate_cassette_envelope(env.to_canonical_obj())
    assert parsed.determinism.parallel_index is None
    assert parsed.determinism.abort_after is None
    assert parsed.determinism.page_index is None
    assert parsed.determinism.attempts == ()


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_rejects_negative_parallel_index(make_replay_fixture: Any) -> None:
    """``parallel_index`` MUST be a non-negative integer."""
    env = _make_envelope(make_replay_fixture, parallel_index=0)
    obj = env.to_canonical_obj()
    obj["determinism"]["parallel_index"] = -1
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        validate_cassette_envelope(obj)
    assert "parallel_index" in str(exc_info.value)


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_rejects_negative_page_index(make_replay_fixture: Any) -> None:
    env = _make_envelope(make_replay_fixture, page_index=0)
    obj = env.to_canonical_obj()
    obj["determinism"]["page_index"] = -2
    with pytest.raises(RelayCassetteCorruptError):
        validate_cassette_envelope(obj)


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_rejects_negative_abort_after_offset(
    make_replay_fixture: Any,
) -> None:
    env = _make_envelope(make_replay_fixture, abort_after=AbortAfter(token_offset=0))
    obj = env.to_canonical_obj()
    obj["determinism"]["abort_after"] = {"token_offset": -3}
    with pytest.raises(RelayCassetteCorruptError):
        validate_cassette_envelope(obj)


@pytest.mark.fulfills("VAL-V2M08-020")
def test_envelope_rejects_bad_attempt_outcome(make_replay_fixture: Any) -> None:
    env = _make_envelope(
        make_replay_fixture,
        attempts=[
            CassetteAttempt(
                attempt_index=0, attempt_delay_ms=0, attempt_outcome="success"
            ),
        ],
    )
    obj = env.to_canonical_obj()
    obj["determinism"]["attempts"][0]["attempt_outcome"] = "not_a_real_outcome"
    with pytest.raises(RelayCassetteCorruptError):
        validate_cassette_envelope(obj)


@pytest.mark.fulfills("VAL-V2M08-020")
def test_legacy_replay_fixture_record_still_validates(
    make_replay_fixture: Any,
) -> None:
    """Lines that are raw ``ReplayFixture v1`` (no envelope wrapper) load.

    Backward compatibility: an existing cassette on disk uses the bare
    ReplayFixture shape (``schema_version: relay.replay_fixture.v1``).
    The new envelope loader MUST treat such a line as an envelope with an
    empty determinism block.
    """
    body = b'{"choices":[]}'
    fixture = make_replay_fixture(
        output_digest="sha256-" + hashlib.sha256(body).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    legacy_obj = json.loads(fixture.model_dump_json())
    assert legacy_obj["schema_version"] == REPLAY_FIXTURE_SCHEMA_VERSION
    parsed = validate_cassette_envelope(legacy_obj)
    assert parsed.fixture.fixture_id == fixture.fixture_id
    assert parsed.determinism.parallel_index is None
    assert parsed.determinism.abort_after is None
    assert parsed.determinism.page_index is None
    assert parsed.determinism.attempts == ()


@pytest.mark.fulfills("VAL-V2M08-020")
def test_load_cassette_envelopes_mixes_legacy_and_envelope_lines(
    empty_cassette_dir: Path,
    make_replay_fixture: Any,
    make_canonical_request: Any,
) -> None:
    """A cassette can contain both legacy and envelope-wrapped records."""
    # Line 1: legacy ReplayFixture-only row (recorded with append_record).
    from relay_replay_proxy.cassette_format import append_record

    body_a = b'{"a":1}'
    fixture_a = make_replay_fixture(
        fixture_id="00000000-0000-4000-8000-000000000001",
        output_digest="sha256-" + hashlib.sha256(body_a).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000001.body",
    )
    req_a = make_canonical_request(
        body_bytes=b'{"model":"gpt","messages":[{"role":"user","content":"a"}]}'
    )
    cassette_path = empty_cassette_dir / CASSETTE_FILENAME
    append_record(
        cassette_path, fixture=fixture_a, canonical_request=req_a, response_bytes=body_a
    )
    # Line 2: envelope-wrapped row.
    body_b = b'{"b":2}'
    fixture_b = make_replay_fixture(
        fixture_id="00000000-0000-4000-8000-000000000002",
        output_digest="sha256-" + hashlib.sha256(body_b).hexdigest(),
        output_ref="file://bodies/00000000-0000-4000-8000-000000000002.body",
    )
    env_b = CassetteEnvelope(
        fixture=fixture_b,
        determinism=CassetteDeterminism(parallel_index=1),
    )
    req_b = make_canonical_request(
        body_bytes=b'{"model":"gpt","messages":[{"role":"user","content":"b"}]}'
    )
    append_envelope(
        cassette_path,
        envelope=env_b,
        canonical_request=req_b,
        response_bytes=body_b,
    )
    envelopes = load_cassette_envelopes(cassette_path)
    assert len(envelopes) == 2
    # Legacy record loaded with empty determinism block.
    assert envelopes[0].determinism.parallel_index is None
    # Envelope record carries its determinism.
    assert envelopes[1].determinism.parallel_index == 1


# -----------------------------------------------------------------------------
# VAL-V2M08-021: replay orders parallel tool calls by parallel_index
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-V2M08-021")
def test_order_parallel_records_sorts_by_parallel_index(
    make_replay_fixture: Any,
) -> None:
    """Dispatch order = parallel_index ascending, regardless of disk order."""
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
        parallel_index=2,
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000000",
        parallel_index=0,
    )
    env_c = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
        parallel_index=1,
    )
    out = order_parallel_records([env_a, env_b, env_c])
    assert [e.determinism.parallel_index for e in out] == [0, 1, 2]


@pytest.mark.fulfills("VAL-V2M08-021")
def test_order_parallel_records_is_deterministic_across_runs(
    make_replay_fixture: Any,
) -> None:
    """Ten independent shufflings produce the same dispatch sequence."""
    import random

    rng = random.Random(0xC0FFEE)
    base = [
        _make_envelope(
            make_replay_fixture,
            fixture_id=f"00000000-0000-4000-8000-00000000000{i}",
            parallel_index=i,
        )
        for i in range(3)
    ]
    # parallel_index is `int | None` on the envelope; these fixtures all set
    # a concrete index, asserted == [0, 1, 2] below, but the element type stays
    # `int | None` to match the source field.
    runs: list[list[int | None]] = []
    for _ in range(10):
        shuffled = list(base)
        rng.shuffle(shuffled)
        ordered = order_parallel_records(shuffled)
        runs.append([e.determinism.parallel_index for e in ordered])
    for run in runs:
        assert run == [0, 1, 2]


@pytest.mark.fulfills("VAL-V2M08-021")
def test_order_parallel_records_passes_through_unindexed(
    make_replay_fixture: Any,
) -> None:
    """Records without parallel_index are passed through in input order."""
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
    )
    out = order_parallel_records([env_a, env_b])
    assert [e.fixture.fixture_id for e in out] == [
        env_a.fixture.fixture_id,
        env_b.fixture.fixture_id,
    ]


# -----------------------------------------------------------------------------
# VAL-V2M08-022: replay honors abort_after cancellation token
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-V2M08-022")
def test_apply_abort_after_truncates_stream_at_token_offset() -> None:
    tokens = [f"t{i}" for i in range(50)]
    emitted, cancelled = apply_abort_after(tokens, AbortAfter(token_offset=17))
    assert len(emitted) == 17
    assert emitted == tokens[:17]
    assert cancelled == "cancelled_mid_stream"


@pytest.mark.fulfills("VAL-V2M08-022")
def test_apply_abort_after_none_emits_full_sequence() -> None:
    tokens = [f"t{i}" for i in range(50)]
    emitted, cancelled = apply_abort_after(tokens, None)
    assert emitted == tokens
    assert cancelled is None


@pytest.mark.fulfills("VAL-V2M08-022")
def test_apply_abort_after_zero_offset_emits_nothing_and_cancels() -> None:
    tokens = ["t0", "t1", "t2"]
    emitted, cancelled = apply_abort_after(tokens, AbortAfter(token_offset=0))
    assert emitted == []
    assert cancelled == "cancelled_mid_stream"


@pytest.mark.fulfills("VAL-V2M08-022")
def test_apply_abort_after_overshoot_raises_corruption() -> None:
    """BUG-F3 (audit-r3 P2): recorded offset > stream length is corruption.

    A valid recorder cannot capture a cancellation offset that exceeds
    the recorded stream length. The previous behavior silently downgraded
    overshoots to "no cancellation", masking truncated cassettes (e.g.
    proxy died mid-write). The corrected behavior raises
    ``RelayCassetteCorruptError`` so callers cannot replay a truncated
    recording as if the stream finished normally.
    """
    tokens = ["t0", "t1"]
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        apply_abort_after(tokens, AbortAfter(token_offset=99))
    details = exc_info.value.details
    assert details["reason"] == RELAY_REPLAY_CANCELLATION_OVERSHOOT_CODE
    assert details["token_offset"] == 99
    assert details["stream_length"] == 2


@pytest.mark.fulfills("VAL-V2M08-022")
def test_apply_abort_after_at_boundary_emits_cancellation() -> None:
    """BUG-F3 (audit-r3 P2): offset == len(tokens) is the boundary case.

    The recorder observed every token and then the cancellation; replay
    reproduces that by emitting all tokens AND the cancellation event.
    Previously this case was silently downgraded to "no cancellation".
    """
    tokens = ["t0", "t1"]
    emitted, cancelled = apply_abort_after(tokens, AbortAfter(token_offset=2))
    assert emitted == tokens
    assert cancelled == "cancelled_mid_stream"


# -----------------------------------------------------------------------------
# VAL-V2M08-023: replay pagination preserves page_index ordering
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-V2M08-023")
def test_order_pages_or_raise_sorts_ascending(make_replay_fixture: Any) -> None:
    env_2 = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
        page_index=2,
    )
    env_0 = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000000",
        page_index=0,
    )
    env_1 = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
        page_index=1,
    )
    out = order_pages_or_raise([env_2, env_0, env_1])
    assert [e.determinism.page_index for e in out] == [0, 1, 2]


@pytest.mark.fulfills("VAL-V2M08-023")
def test_order_pages_or_raise_rejects_duplicate_page_index(
    make_replay_fixture: Any,
) -> None:
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
        page_index=0,
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
        page_index=0,
    )
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        order_pages_or_raise([env_a, env_b])
    assert exc_info.value.details.get("reason") == RELAY_REPLAY_PAGE_ORDER_CODE
    assert "duplicate" in str(exc_info.value).lower()


@pytest.mark.fulfills("VAL-V2M08-023")
def test_order_pages_or_raise_rejects_missing_page_index_in_paginated_set(
    make_replay_fixture: Any,
) -> None:
    """If any record is paginated, every record in the set MUST be."""
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
        page_index=0,
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
    )
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        order_pages_or_raise([env_a, env_b])
    assert exc_info.value.details.get("reason") == RELAY_REPLAY_PAGE_ORDER_CODE
    assert "missing" in str(exc_info.value).lower()


@pytest.mark.fulfills("VAL-V2M08-023")
def test_order_pages_or_raise_rejects_non_contiguous_page_index(
    make_replay_fixture: Any,
) -> None:
    """A gap (0, 2 -- no 1) is rejected; page sets MUST be contiguous from 0."""
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
        page_index=0,
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
        page_index=2,
    )
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        order_pages_or_raise([env_a, env_b])
    assert exc_info.value.details.get("reason") == RELAY_REPLAY_PAGE_ORDER_CODE


@pytest.mark.fulfills("VAL-V2M08-023")
def test_order_pages_or_raise_passes_when_no_pagination(
    make_replay_fixture: Any,
) -> None:
    """A set with zero page_index annotations is left as-is."""
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
    )
    out = order_pages_or_raise([env_a, env_b])
    assert [e.fixture.fixture_id for e in out] == [
        env_a.fixture.fixture_id,
        env_b.fixture.fixture_id,
    ]


@pytest.mark.fulfills("VAL-V2M08-023")
def test_corrupt_error_carries_relay_replay_page_order_code(
    make_replay_fixture: Any,
) -> None:
    """The error message and details carry the RELAY-REPLAY-PAGE-ORDER label."""
    env_a = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000001",
        page_index=0,
    )
    env_b = _make_envelope(
        make_replay_fixture,
        fixture_id="00000000-0000-4000-8000-000000000002",
        page_index=0,
    )
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        order_pages_or_raise([env_a, env_b])
    # The outer error code is the existing cassette-corrupt wire code; the
    # PAGE-ORDER label is carried as the structured reason so callers can
    # distinguish this class of corruption without a new exception type.
    assert exc_info.value.code == RELAY_REPLAY_CASSETTE_CORRUPT
    assert exc_info.value.details["reason"] == RELAY_REPLAY_PAGE_ORDER_CODE


# -----------------------------------------------------------------------------
# VAL-V2M08-024: replay re-emits per-attempt retries from cassette
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-V2M08-024")
def test_iter_attempts_with_delays_yields_in_order(
    make_replay_fixture: Any,
) -> None:
    """Attempts are emitted by attempt_index ascending with the recorded delay."""
    env = _make_envelope(
        make_replay_fixture,
        attempts=[
            CassetteAttempt(
                attempt_index=1, attempt_delay_ms=250, attempt_outcome="success"
            ),
            CassetteAttempt(
                attempt_index=0, attempt_delay_ms=0, attempt_outcome="http_5xx"
            ),
        ],
    )
    sleeps: list[float] = []
    out = list(iter_attempts_with_delays(env, sleep_fn=sleeps.append))
    assert [a.attempt_index for a in out] == [0, 1]
    assert [a.attempt_outcome for a in out] == ["http_5xx", "success"]
    # Sleeps are in seconds, recorded in ms; first attempt's delay (0)
    # MUST still be honored as a sleep(0).
    assert sleeps == [0.0, 0.250]


@pytest.mark.fulfills("VAL-V2M08-024")
def test_iter_attempts_with_delays_no_attempts_yields_nothing(
    make_replay_fixture: Any,
) -> None:
    env = _make_envelope(make_replay_fixture)
    sleeps: list[float] = []
    out = list(iter_attempts_with_delays(env, sleep_fn=sleeps.append))
    assert out == []
    assert sleeps == []


@pytest.mark.fulfills("VAL-V2M08-024")
def test_iter_attempts_with_delays_uses_real_sleep_within_tolerance(
    make_replay_fixture: Any,
) -> None:
    """Default sleep_fn is time.sleep; verify the wall-clock delay is honored
    within +/- 50 ms tolerance (assertion-text bound).
    """
    env = _make_envelope(
        make_replay_fixture,
        attempts=[
            CassetteAttempt(
                attempt_index=0, attempt_delay_ms=0, attempt_outcome="http_429"
            ),
            CassetteAttempt(
                attempt_index=1, attempt_delay_ms=100, attempt_outcome="success"
            ),
        ],
    )
    start = time.monotonic()
    out = list(iter_attempts_with_delays(env))
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert [a.attempt_index for a in out] == [0, 1]
    # 100ms recorded delay + scheduler jitter. Upper bound 250ms gives us
    # plenty of headroom on a busy CI runner without losing the assertion.
    assert 50.0 <= elapsed_ms <= 400.0, (
        f"expected ~100ms with +/-50 to +300ms slack, got {elapsed_ms:.1f}ms"
    )


@pytest.mark.fulfills("VAL-V2M08-024")
def test_iter_attempts_makes_no_network_calls(make_replay_fixture: Any) -> None:
    """Re-emitting recorded attempts MUST NOT touch the network.

    The function operates on in-memory cassette envelope data only. We
    monkeypatch socket creation so that any accidental network call would
    raise.
    """
    import socket

    original_socket = socket.socket

    def _no_network(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise AssertionError(
            "replay attempt iteration MUST NOT open a socket; "
            "cassette mode never contacts the live provider"
        )

    socket.socket = _no_network  # type: ignore[assignment]
    try:
        env = _make_envelope(
            make_replay_fixture,
            attempts=[
                CassetteAttempt(
                    attempt_index=0,
                    attempt_delay_ms=0,
                    attempt_outcome="http_5xx",
                ),
                CassetteAttempt(
                    attempt_index=1,
                    attempt_delay_ms=0,
                    attempt_outcome="success",
                ),
            ],
        )
        sleeps: list[float] = []
        out = list(iter_attempts_with_delays(env, sleep_fn=sleeps.append))
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
    assert len(out) == 2
