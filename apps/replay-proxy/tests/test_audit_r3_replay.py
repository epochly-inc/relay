"""Audit-R3 replay P2 regression tests (BUG-F1, BUG-F2, BUG-F3).

These plumbing-tier tests pin the three audit-r3 P2 fixes in the
replay-proxy:

* BUG-F1: ``_canonicalize_query`` must percent-encode names and values
  before re-emission so distinct inputs cannot collide on the canonical
  form (``?a=b%26c=d`` vs ``?a=b&c=d``).
* BUG-F2: ``_validate_session_dir`` must enforce strict containment
  inside ``cassette_root`` so attacker-controlled paths whose parts
  happen to contain the literal ``"cassettes"`` are rejected.
* BUG-F3: ``apply_abort_after`` must raise ``RelayCassetteCorruptError``
  when the recorded ``token_offset`` overshoots the captured stream
  length, instead of silently downgrading to "no cancellation".

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from relay_replay_proxy.cassette_format import (
    RELAY_REPLAY_CANCELLATION_OVERSHOOT_CODE,
    AbortAfter,
    _canonicalize_query,
    apply_abort_after,
)
from relay_replay_proxy.cert_authority import _validate_session_dir
from relay_replay_proxy.errors import RelayCassetteCorruptError

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# BUG-F1: query canonicalization injectivity
# -----------------------------------------------------------------------------


def test_canonicalize_query_distinguishes_encoded_ampersand_from_pair_separator() -> None:
    """A literal ``&`` inside a value must not collide with a pair separator.

    Pre-fix: ``parse_qsl`` decoded ``%26`` to ``&`` and the re-emit loop
    wrote it verbatim, producing ``a=b&c=d`` for BOTH ``?a=b%26c=d`` (one
    pair, value ``b&c=d``) and ``?a=b&c=d`` (two pairs ``a=b`` and
    ``c=d``). Post-fix: ``quote(..., safe='')`` re-encodes the ``&`` in
    the value so the two inputs canonicalize to different strings.
    """
    single_pair = _canonicalize_query("a=b%26c=d")
    two_pairs = _canonicalize_query("a=b&c=d")
    assert single_pair != two_pairs, (
        f"BUG-F1 regression: single-pair canonical {single_pair!r} "
        f"collides with two-pair canonical {two_pairs!r}"
    )
    # Spot-check the specific encoded forms so a refactor that breaks the
    # encoding contract (e.g. quote with too-permissive ``safe=``) is
    # caught by name, not just by inequality.
    assert "%26" in single_pair, single_pair
    assert "%3D" in single_pair, single_pair  # the literal '=' inside the value
    assert two_pairs == "a=b&c=d"


def test_canonicalize_query_encodes_equals_inside_value() -> None:
    """A literal ``=`` inside a value must be percent-encoded."""
    out = _canonicalize_query("k=a%3Db")
    # value was 'a=b' after decode; re-encoding must produce 'a%3Db'
    assert out == "k=a%3Db", out


def test_canonicalize_query_sorting_still_applies() -> None:
    """Parameter sort order is preserved across the encoding fix."""
    out = _canonicalize_query("b=2&a=1")
    assert out == "a=1&b=2", out


def test_canonicalize_query_empty_string_unchanged() -> None:
    assert _canonicalize_query("") == ""


def test_canonicalize_query_blank_value_preserved() -> None:
    assert _canonicalize_query("a=") == "a="


# -----------------------------------------------------------------------------
# BUG-F2: strict session_dir containment
# -----------------------------------------------------------------------------


def test_validate_session_dir_rejects_substring_lookalike(tmp_path: Path) -> None:
    """A path under ``cassettes-evil/.../cassettes/<id>`` must be rejected.

    Pre-fix: the validator only checked ``"cassettes" in parts``, so
    ``/tmp/cassettes-evil/foo/cassettes/x`` -- whose ``parts`` does
    contain the literal ``"cassettes"`` -- passed the check even though
    its real prefix has nothing to do with the legitimate cassette
    root. Post-fix: strict ``is_relative_to`` containment makes the
    substring trick ineffective.
    """
    legit_root = tmp_path / "cassettes"
    legit_root.mkdir(parents=True, exist_ok=True)

    evil_root = tmp_path / "cassettes-evil"
    evil_session = evil_root / "foo" / "cassettes" / "x"
    evil_session.mkdir(parents=True, exist_ok=True)

    # Sanity: the attacker path contains the literal "cassettes" in its
    # parts, which is exactly what the pre-fix substring check accepted.
    assert "cassettes" in evil_session.parts

    with pytest.raises(ValueError, match="descendant"):
        _validate_session_dir(evil_session, cassette_root=legit_root)


def test_validate_session_dir_accepts_legitimate_child(tmp_path: Path) -> None:
    """A real child of cassette_root must still pass."""
    legit_root = tmp_path / "cassettes"
    legit_root.mkdir(parents=True, exist_ok=True)
    sd = legit_root / "ses-bug-f2-aaaaaaaaaaaaaaaaaaa"
    sd.mkdir(parents=True, exist_ok=True)
    # Should not raise.
    _validate_session_dir(sd, cassette_root=legit_root)


def test_validate_session_dir_rejects_sibling_of_cassette_root(tmp_path: Path) -> None:
    """A session_dir that lives next to (not inside) cassette_root is rejected."""
    legit_root = tmp_path / "cassettes"
    legit_root.mkdir(parents=True, exist_ok=True)
    sibling = tmp_path / "elsewhere" / "x"
    sibling.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="descendant"):
        _validate_session_dir(sibling, cassette_root=legit_root)


def test_validate_session_dir_rejects_relative_cassette_root(tmp_path: Path) -> None:
    legit_session = tmp_path / "cassettes" / "x"
    legit_session.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="cassette_root must be absolute"):
        _validate_session_dir(legit_session, cassette_root=Path("relative/cassettes"))


# -----------------------------------------------------------------------------
# BUG-F3: abort_after overshoot detection
# -----------------------------------------------------------------------------


def test_apply_abort_after_raises_when_offset_overshoots_stream() -> None:
    """A recorded offset past ``len(tokens)`` is structural corruption."""
    tokens = ["t0", "t1"]
    overshoot = AbortAfter(token_offset=5)
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        apply_abort_after(tokens, overshoot)
    details = exc_info.value.details
    assert details["reason"] == RELAY_REPLAY_CANCELLATION_OVERSHOOT_CODE
    assert details["token_offset"] == 5
    assert details["stream_length"] == 2
    assert details["violation"] == "offset_overshoots_stream"


def test_apply_abort_after_at_stream_boundary_emits_cancellation() -> None:
    """``offset == len(tokens)`` emits all tokens AND the cancellation event.

    Pre-fix: this case was silently downgraded to "no cancellation"
    (event = None), losing the distinction between a stream that ran
    to completion and one that was cancelled exactly at its final
    token boundary.
    """
    tokens = ["t0", "t1", "t2"]
    boundary = AbortAfter(token_offset=3)
    emitted, event = apply_abort_after(tokens, boundary)
    assert emitted == ["t0", "t1", "t2"]
    assert event == "cancelled_mid_stream"


def test_apply_abort_after_mid_stream_unchanged() -> None:
    """``offset < len(tokens)`` keeps the existing mid-stream behavior."""
    tokens = ["t0", "t1", "t2"]
    mid = AbortAfter(token_offset=1)
    emitted, event = apply_abort_after(tokens, mid)
    assert emitted == ["t0"]
    assert event == "cancelled_mid_stream"


def test_apply_abort_after_none_returns_full_stream() -> None:
    """``abort_after = None`` (no cancellation recorded) is unchanged."""
    tokens = ["t0", "t1"]
    emitted, event = apply_abort_after(tokens, None)
    assert emitted == ["t0", "t1"]
    assert event is None


def test_apply_abort_after_negative_offset_raises() -> None:
    """Defensive: a negative offset is structural corruption."""
    tokens = ["t0"]
    bad = AbortAfter(token_offset=-1)
    with pytest.raises(RelayCassetteCorruptError) as exc_info:
        apply_abort_after(tokens, bad)
    assert exc_info.value.details["violation"] == "negative_offset"
