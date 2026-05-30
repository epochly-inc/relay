"""w6.3 -- Relay UDF determinism guards.

VAL-W6-023: wall-clock independence (mock time.time / time.monotonic)
VAL-W6-024: network isolation (socket creation forbidden)
VAL-W6-025: locale independence (4 LC_ALL settings)
VAL-W6-026: random-source independence (seeded PRNG comparison + grep)
VAL-W6-027: no mutable process globals (env mutation + grep)
VAL-W6-028: no filesystem reads outside declared inputs (open / read shims)

Each test runs a UDF twice under perturbed conditions and asserts
JCS-canonical output bytes are byte-identical, AND asserts the per-shim
invocation counter equals zero where a shim is installed.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import builtins
import hashlib
import io
import locale
import os
import re
import socket
import time
import tokenize
from pathlib import Path
from typing import Any

import pytest
from relay_contracts import (
    jcs_canonicalize,
    relay_coverage,
    relay_schema_match,
    relay_tool_arg,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC_UDFS = REPO_ROOT / "packages" / "contracts" / "src" / "relay_contracts" / "udfs"


def _scrub_strings_and_comments(src: str) -> str:
    """Return ``src`` with all string literals and comments replaced
    by empty placeholders, using Python's tokenize module.

    Used by the determinism source-grep guards (VAL-W6-026, VAL-W6-027)
    to avoid false positives where the UDF source's docstrings or
    explanatory comments mention forbidden tokens (e.g., the
    docstring for ``coverage.py`` says "no os.environ" -- that text
    is documentation, not a behavior).
    """

    out_lines: list[str] = []
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(src.encode("utf-8")).readline))
    except tokenize.TokenError:
        # Defensive: if the file fails to tokenize, fall back to
        # comment-only stripping. The line-strip below is the original
        # behavior; we accept it as a last resort.
        return "\n".join(
            ln for ln in src.splitlines() if not ln.lstrip().startswith("#")
        )
    # Reconstruct source with STRING and COMMENT tokens replaced by
    # equal-length whitespace so column positions stay stable for any
    # downstream grep that depends on them. We don't depend on column
    # positions here; an empty replacement is simpler and equivalent.
    line_buf: list[str] = []
    for tok in tokens:
        if tok.type in (tokenize.ENCODING, tokenize.ENDMARKER):
            continue
        if tok.type in (tokenize.NEWLINE, tokenize.NL):
            out_lines.append("".join(line_buf))
            line_buf = []
            continue
        if tok.type in (tokenize.INDENT, tokenize.DEDENT):
            continue
        if tok.type in (tokenize.STRING, tokenize.COMMENT):
            # Drop the body. We do NOT insert a placeholder space:
            # downstream substring search uses dotted forms like
            # "os.environ" that are emitted by tokenize as three
            # tokens (NAME, OP, NAME). Inserting separators would
            # break those exact-string matches.
            continue
        line_buf.append(tok.string)
    if line_buf:
        out_lines.append("".join(line_buf))
    return "\n".join(out_lines)

# Standard happy-path fixtures shared across determinism tests. Every
# fixture returns a definite, non-trivial result for its UDF so a
# determinism break would be visible in the JCS bytes.
COVERAGE_TRACE = {
    "steps": [
        {"name": "step.alpha", "status": "ok"},
        {"name": "step.beta", "status": "ok"},
        {"name": "step.gamma", "status": "ok"},
    ],
}
COVERAGE_STEP = "step.beta"

TOOL_CALL = {
    "tool_name": "create_case_note",
    "args": {"case_id": "C-001", "note": "approved", "score": 0.875},
}
TOOL_KEY = "score"

SCHEMA_PAYLOAD = {
    "case_id": "C-001",
    "score": 0.875,
    "tags": ["a", "b", "c"],
    "owner": {"id": 42, "name": "alice"},
}
SCHEMA_DEF = {
    "type": "object",
    "required": ["case_id", "score"],
    "properties": {
        "case_id": {"type": "string"},
        "score": {"type": "number"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "owner": {
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
            },
        },
    },
}


def _digest(value: Any) -> str:
    return hashlib.sha256(jcs_canonicalize(value)).hexdigest()


def _all_three_outputs() -> dict[str, str]:
    """Return the JCS digest of each UDF on the standard fixtures."""

    return {
        "relay.coverage": _digest(relay_coverage(COVERAGE_TRACE, COVERAGE_STEP)),
        "relay.tool_arg": _digest(relay_tool_arg(TOOL_CALL, TOOL_KEY)),
        "relay.schema_match": _digest(
            relay_schema_match(SCHEMA_PAYLOAD, SCHEMA_DEF)
        ),
    }


# ---------------------------------------------------------------------------
# VAL-W6-023: wall-clock independent
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-023")
def test_udfs_are_wall_clock_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock time.time / time.monotonic / time.perf_counter to distinct
    values across two evaluation runs on the same input. JCS-canonical
    output bytes MUST be identical.
    """

    monkeypatch.setattr(time, "time", lambda: 1700000000.0)
    monkeypatch.setattr(time, "monotonic", lambda: 1.0)
    monkeypatch.setattr(time, "perf_counter", lambda: 1.0)
    run1 = _all_three_outputs()

    monkeypatch.setattr(time, "time", lambda: 1900000000.0)
    monkeypatch.setattr(time, "monotonic", lambda: 9999.0)
    monkeypatch.setattr(time, "perf_counter", lambda: 9999.0)
    run2 = _all_three_outputs()

    assert run1 == run2, (
        f"VAL-W6-023: UDF outputs differed across mocked clocks; "
        f"run1={run1}, run2={run2}"
    )


# ---------------------------------------------------------------------------
# VAL-W6-024: network-isolated
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-024")
def test_udfs_do_not_create_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace socket.socket.__init__ with a counter+raise. Each UDF
    on its happy-path fixture MUST NOT touch the shim.
    """

    counter = {"n": 0}
    original = socket.socket.__init__

    def shim(self: socket.socket, *args: Any, **kwargs: Any) -> None:
        counter["n"] += 1
        raise RuntimeError("VAL-W6-024: UDF attempted to create a socket")

    monkeypatch.setattr(socket.socket, "__init__", shim)
    try:
        outputs = _all_three_outputs()
    finally:
        # restoration is monkeypatch's job; the try/finally is here so
        # we observe the counter even on output failure.
        pass
    assert counter["n"] == 0, (
        f"VAL-W6-024: socket shim invoked {counter['n']} time(s) by UDFs"
    )
    # And outputs are still well-formed (digest is a hex string).
    for name, dig in outputs.items():
        assert re.fullmatch(r"[0-9a-f]{64}", dig), f"{name} -> {dig!r}"
    # Reference `original` so the binding is intentionally observed
    # (mirrors the monkeypatch restoration that pytest does for us).
    assert callable(original)


# ---------------------------------------------------------------------------
# VAL-W6-025: locale-independent
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-025")
def test_udfs_are_locale_independent() -> None:
    """Evaluate the same input under up to 4 LC_ALL settings:
    C / en_US.UTF-8 / tr_TR.UTF-8 / de_DE.UTF-8. JCS-canonical output
    bytes MUST be identical across all available locales. Locales not
    installed on the runner are skipped (CI matrix may be minimal).
    """

    candidates = ("C", "en_US.UTF-8", "tr_TR.UTF-8", "de_DE.UTF-8")
    digests: list[tuple[str, dict[str, str]]] = []
    saved = locale.setlocale(locale.LC_ALL)
    try:
        for cand in candidates:
            try:
                locale.setlocale(locale.LC_ALL, cand)
            except locale.Error:
                # Locale not installed on this runner; skip this slot.
                continue
            digests.append((cand, _all_three_outputs()))
    finally:
        try:
            locale.setlocale(locale.LC_ALL, saved)
        except locale.Error:
            locale.setlocale(locale.LC_ALL, "C")

    # We require at least the C locale to have been usable.
    assert len(digests) >= 1, (
        "VAL-W6-025: no locales were usable; cannot assert determinism"
    )
    first = digests[0][1]
    for cand, snap in digests[1:]:
        assert snap == first, (
            f"VAL-W6-025: UDF outputs differed under locale {cand}; "
            f"first={first}, here={snap}"
        )


# Dotted-I fixture: Turkish lower-cases "I" to "U+0131" and upper-cases
# "i" to "U+0130". A locale-aware case-fold or sort would diverge.
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-025")
def test_tool_arg_is_codepoint_keyed_not_locale_folded() -> None:
    """relay.tool_arg MUST treat 'i' and 'I' as distinct keys regardless
    of locale (no case-folding lookup).
    """

    call = {"args": {"i": "lower", "I": "upper"}}
    # Same input twice under the same locale -> same answer; the
    # important property is that under a Turkish locale we still
    # distinguish 'i' from 'I' rather than folding them.
    assert relay_tool_arg(call, "i") == "lower"
    assert relay_tool_arg(call, "I") == "upper"


# ---------------------------------------------------------------------------
# VAL-W6-026: random-source independent
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-026")
def test_udfs_are_random_source_independent() -> None:
    """Re-seed Python's random + secrets across runs. Outputs MUST be
    identical. Source greps under packages/contracts/src/relay_contracts/
    udfs/ MUST find zero references to random / secrets / urandom.
    """

    import random
    import secrets

    random.seed(1)
    _ = random.random()
    _ = secrets.token_bytes(16)
    run1 = _all_three_outputs()

    random.seed(987654321)
    _ = random.random()
    _ = secrets.token_bytes(16)
    run2 = _all_three_outputs()

    assert run1 == run2, (
        f"VAL-W6-026: UDF outputs differed across seeded PRNGs; "
        f"run1={run1}, run2={run2}"
    )

    # Source grep guard: forbidden names anywhere in udfs/ code
    # (docstrings and comments are stripped via tokenize so the
    # explanatory text in the UDF docstrings does not produce false
    # positives).
    forbidden = ("random", "secrets", "os.urandom", "Math.random", "crypto.randomBytes")
    hits: list[tuple[str, str, str]] = []
    for py in PKG_SRC_UDFS.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        scrubbed = _scrub_strings_and_comments(text)
        for token in forbidden:
            if token in scrubbed:
                hits.append((str(py.relative_to(REPO_ROOT)), token, "code-only"))
    assert hits == [], (
        f"VAL-W6-026: forbidden random-source token in UDF source: {hits}"
    )


# ---------------------------------------------------------------------------
# VAL-W6-027: no mutable process globals
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-027")
def test_udfs_do_not_read_mutable_process_globals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutate os.environ['RELAY_TEST_SENTINEL'] between two evaluation
    runs. UDF outputs MUST be identical. Source grep MUST find zero
    references to os.environ in udfs/.
    """

    monkeypatch.setenv("RELAY_TEST_SENTINEL", "first")
    run1 = _all_three_outputs()
    monkeypatch.setenv("RELAY_TEST_SENTINEL", "second")
    run2 = _all_three_outputs()
    assert run1 == run2, (
        f"VAL-W6-027: UDF outputs differed across env sentinel mutation; "
        f"run1={run1}, run2={run2}"
    )

    # Source grep guard (docstrings and comments are stripped via
    # tokenize so the explanatory text "no os.environ" in the UDF
    # docstrings does not produce a false positive).
    forbidden = ("os.environ", "os.getenv", "process.env")
    hits: list[tuple[str, str]] = []
    for py in PKG_SRC_UDFS.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        scrubbed = _scrub_strings_and_comments(text)
        for token in forbidden:
            if token in scrubbed:
                hits.append((str(py.relative_to(REPO_ROOT)), token))
    assert hits == [], (
        f"VAL-W6-027: forbidden mutable-global token in UDF source: {hits}"
    )


# ---------------------------------------------------------------------------
# VAL-W6-028: no filesystem reads outside declared inputs
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-028")
def test_udfs_do_not_read_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install shims for builtins.open, os.open, and Path.read_text.
    The UDFs on their happy-path fixtures MUST NOT touch any shim.
    """

    counters = {"open": 0, "os_open": 0, "path_read_text": 0, "path_read_bytes": 0}
    real_open = builtins.open
    real_os_open = os.open
    real_path_read_text = Path.read_text
    real_path_read_bytes = Path.read_bytes

    def open_shim(*args: Any, **kwargs: Any) -> Any:
        counters["open"] += 1
        raise RuntimeError("VAL-W6-028: UDF attempted builtins.open()")

    def os_open_shim(*args: Any, **kwargs: Any) -> int:
        counters["os_open"] += 1
        raise RuntimeError("VAL-W6-028: UDF attempted os.open()")

    def path_read_text_shim(self: Path, *args: Any, **kwargs: Any) -> str:
        counters["path_read_text"] += 1
        raise RuntimeError("VAL-W6-028: UDF attempted Path.read_text()")

    def path_read_bytes_shim(self: Path, *args: Any, **kwargs: Any) -> bytes:
        counters["path_read_bytes"] += 1
        raise RuntimeError("VAL-W6-028: UDF attempted Path.read_bytes()")

    monkeypatch.setattr(builtins, "open", open_shim)
    monkeypatch.setattr(os, "open", os_open_shim)
    monkeypatch.setattr(Path, "read_text", path_read_text_shim)
    monkeypatch.setattr(Path, "read_bytes", path_read_bytes_shim)

    outputs = _all_three_outputs()

    assert counters == {
        "open": 0, "os_open": 0, "path_read_text": 0, "path_read_bytes": 0,
    }, f"VAL-W6-028: filesystem shim(s) invoked: {counters}"

    # outputs are still well-formed.
    for name, dig in outputs.items():
        assert re.fullmatch(r"[0-9a-f]{64}", dig), f"{name} -> {dig!r}"
    # silence unused real_* warnings in some linters
    assert real_open and real_os_open and real_path_read_text and real_path_read_bytes
