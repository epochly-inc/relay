"""VAL-ISO-007: anti-bypass guard must catch pytest.mark.skip(...) and flag=value.

Defect (bug-hunt finding ISO-007): the bypass-marker boundary regex
(anti_bypass.py:69-75) required a right-hand boundary from the class
``[\\s,\\[\\]{}\\"\\\\:]`` -- whitespace, comma, brackets, braces,
double-quote, backslash, colon. That class omitted ``(`` and ``=``, so the
canonical Python skip-decorator form ``pytest.mark.skip(reason=...)`` and
the canonical git flag form ``--skip-hooks=true`` / ``--no-verify=...`` were
NOT detected -- a real quality-bypass slipped through.

Empirically at base: ``detect_bypass_markers('{"x":"pytest.mark.skip(reason=foo)"}') == ()``
and ``detect_bypass_markers('{"x":"--skip-hooks=true"}') == ()``.

Fix: add ``(``, ``)``, ``=``, ``;``, ``.``, ``@`` (and adjacent shell/JSON
punctuation) to BOTH boundary character classes so the marker is treated as
terminated by any such punctuation. Legitimate prose containing only a
substring near-miss MUST still not be over-flagged.

These tests are RED at base commit and GREEN after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio

import pytest
from relay_sidecar.anti_bypass import (
    BYPASS_MARKER_DETECTED_CLASS,
    detect_bypass_markers,
    screen_payload,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_pytest_mark_skip_call_form_detected() -> None:
    """``pytest.mark.skip(reason=...)`` -- token followed by '(' -- MUST be
    detected (was missed: '(' absent from the boundary class)."""
    found = detect_bypass_markers('{"x":"pytest.mark.skip(reason=foo)"}')
    assert "pytest.mark.skip" in found, found


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_pytest_mark_skip_decorator_form_detected() -> None:
    """``@pytest.mark.skip`` -- token preceded by '@' -- MUST be detected."""
    found = detect_bypass_markers('{"x":"@pytest.mark.skip"}')
    assert "pytest.mark.skip" in found, found


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_skip_hooks_flag_value_form_detected() -> None:
    """``--skip-hooks=true`` -- token followed by '=' -- MUST be detected
    (was missed: '=' absent from the boundary class)."""
    found = detect_bypass_markers('{"x":"--skip-hooks=true"}')
    assert "--skip-hooks" in found, found


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_no_verify_flag_value_form_detected() -> None:
    """``--no-verify=1`` -- token followed by '=' -- MUST be detected."""
    found = detect_bypass_markers('{"x":"--no-verify=1"}')
    assert "--no-verify" in found, found


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_screen_payload_rejects_skip_call_form() -> None:
    """The end-to-end screen MUST reject a payload with the call form."""
    result = asyncio.run(
        screen_payload(
            payload={"note": "pytest.mark.skip(reason=flaky)"},
            event_kind="telemetry",
        )
    )
    assert result.ok is False, result
    assert "pytest.mark.skip" in result.detected_tokens
    assert result.reason_kind == BYPASS_MARKER_DETECTED_CLASS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_substring_near_miss_not_over_flagged() -> None:
    """A longer token whose prefix is a marker MUST NOT match: the new
    boundary punctuation must not over-flag legitimate identifiers."""
    # 'pytest.mark.skipper' extends past the marker with an identifier char.
    assert detect_bypass_markers('{"x":"pytest.mark.skipper"}') == ()
    # '--skip-hooksXYZ' extends with identifier chars (no boundary).
    assert detect_bypass_markers('{"x":"--skip-hooksXYZ"}') == ()
    # '--no-verifyish' (the pre-existing near-miss case) still does not match.
    assert detect_bypass_markers('{"x":"--no-verifyish"}') == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-007")
def test_legitimate_prose_not_over_flagged() -> None:
    """Prose that merely embeds a marker substring inside a word MUST NOT
    match (e.g. 'autoskip-hooksession')."""
    assert detect_bypass_markers('{"x":"the autoskip-hooksession ran"}') == ()
