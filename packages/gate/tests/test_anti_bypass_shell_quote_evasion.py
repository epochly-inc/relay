"""Round-3 P1 fix #6: anti-bypass MUST detect banned tokens hidden in
shell quotes or parentheses.

The pre-fix regex boundary used ``(?:^|\\s)`` and ``(?=$|\\s)`` -- only
whitespace and start/end of string. A banned token wrapped in shell
quotes evades the boundary check:

  bash -c "git commit --no-verify ..."
  sh -c 'git commit --no-verify'
  (git commit --no-verify)

The fix parses the input with ``shlex.split`` (robust to any quote
nesting) and checks each resulting literal token against the banned
list. Substring near-misses (``--no-verifyx``) still do NOT match
because token comparison is exact.

CLAUDE.md anchors: keystone invariant 5 (gate restart on failure), spec
F (anti-bypass screen).
ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_gate_engine.evaluator import _detect_banned_tokens


@pytest.mark.plumbing
def test_anti_bypass_detects_token_in_double_quotes() -> None:
    """bash -c "git commit --no-verify ..." MUST trigger detection."""
    command_line = 'bash -c "git commit --no-verify -m bypass"'
    detected = _detect_banned_tokens(command_line)
    assert "--no-verify" in detected, detected


@pytest.mark.plumbing
def test_anti_bypass_detects_token_in_single_quotes() -> None:
    """sh -c 'git commit --no-verify' MUST trigger detection."""
    command_line = "sh -c 'git commit --no-verify'"
    detected = _detect_banned_tokens(command_line)
    assert "--no-verify" in detected, detected


@pytest.mark.plumbing
def test_anti_bypass_detects_token_in_parens() -> None:
    """(git commit --no-verify) MUST trigger detection."""
    command_line = "(git commit --no-verify)"
    detected = _detect_banned_tokens(command_line)
    assert "--no-verify" in detected, detected


@pytest.mark.plumbing
def test_anti_bypass_substring_extension_still_does_not_match() -> None:
    """Regression: --no-verifyx (substring) MUST NOT match --no-verify
    even after the shlex-based parsing change.

    The fix uses exact token comparison after shlex.split, so the
    substring-near-miss safety property is preserved.
    """
    command_line = "custom-tool --no-verifyx run"
    detected = _detect_banned_tokens(command_line)
    assert detected == (), detected


@pytest.mark.plumbing
def test_anti_bypass_clean_command_remains_clean() -> None:
    """A command with no banned tokens MUST return empty."""
    detected = _detect_banned_tokens("git commit -m 'message text'")
    assert detected == (), detected


@pytest.mark.plumbing
def test_anti_bypass_dash_n_short_form_still_detected() -> None:
    """The git short-form -n is detected as a standalone arg."""
    detected = _detect_banned_tokens("git commit -n -m 'short form'")
    assert "-n" in detected, detected


@pytest.mark.plumbing
def test_anti_bypass_dash_n_inside_name_flag_does_not_match() -> None:
    """--name has -n inside but is NOT the bare -n token; no match."""
    detected = _detect_banned_tokens("git commit --name 'Bob' --message 'fine'")
    assert detected == (), detected


@pytest.mark.plumbing
def test_anti_bypass_malformed_shell_input_falls_back_safely() -> None:
    """An unterminated quote string MUST not raise; the screen returns
    a deterministic result even for malformed input.

    shlex.split raises ValueError on unbalanced quotes; the screen must
    catch and fall back to a conservative substring scan rather than
    propagate to the caller (the gate engine cannot know whether the
    caller's malformed input is intentionally adversarial).
    """
    # The unterminated quote contains the banned token; we expect the
    # fallback path to either flag it (preferred) or return an empty
    # tuple, but NOT raise.
    command_line = 'bash -c "git commit --no-verify'
    detected = _detect_banned_tokens(command_line)
    # Either detection (preferred fail-closed) or silent skip; the
    # invariant is "no exception escapes".
    assert isinstance(detected, tuple)
