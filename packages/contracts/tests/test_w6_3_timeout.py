"""w6.3 -- Relay UDF execution is bounded by per-call CPU timeout.

VAL-W6-029: relay.schema_match (the most recursive of the three UDFs)
on a pathological deeply-nested fixture MUST be aborted by the
evaluator's wall-clock budget, not by an internal off-loading bypass.

Asserts:
  - the UDF aborts via the depth cap (returns False) without exceeding
    the evaluator's 50 ms default budget
  - source grep over packages/contracts/src/relay_contracts/udfs/ finds
    zero references to threading.Thread / asyncio.to_thread /
    concurrent.futures / subprocess.Popen / os.fork / multiprocessing /
    asyncio.create_task -- any of those would let a UDF dodge the
    evaluator's timeout

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import io
import time
import tokenize
from pathlib import Path

import pytest
from relay_contracts import (
    RELAY_UDFS,
    RelayCelTimeoutError,
    WasmCelEvaluator,
    relay_schema_match,
)
from relay_contracts.udfs.schema_match import MAX_DEPTH

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC_UDFS = REPO_ROOT / "packages" / "contracts" / "src" / "relay_contracts" / "udfs"


def _scrub_strings_and_comments(src: str) -> str:
    """Tokenize-based scrubber matching the determinism module's
    helper. Duplicated here to avoid a cross-test import; both
    helpers are pure and remain in lockstep.
    """

    out_lines: list[str] = []
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(src.encode("utf-8")).readline))
    except tokenize.TokenError:
        return "\n".join(
            ln for ln in src.splitlines() if not ln.lstrip().startswith("#")
        )
    line_buf: list[str] = []
    for tok in tokens:
        if tok.type in (tokenize.ENCODING, tokenize.ENDMARKER):
            continue
        if tok.type == tokenize.NEWLINE or tok.type == tokenize.NL:
            out_lines.append("".join(line_buf))
            line_buf = []
            continue
        if tok.type in (tokenize.INDENT, tokenize.DEDENT):
            continue
        if tok.type in (tokenize.STRING, tokenize.COMMENT):
            continue
        line_buf.append(tok.string)
    if line_buf:
        out_lines.append("".join(line_buf))
    return "\n".join(out_lines)


def _make_deeply_nested(depth: int) -> dict[str, object]:
    """Build a payload that is one bigger than schema_match's own
    depth cap so it triggers the depth guard without recursing
    indefinitely.
    """

    payload: object = "leaf"
    for _ in range(depth):
        payload = {"x": payload}
    return {"x": payload}


def _make_deeply_nested_schema(depth: int) -> dict[str, object]:
    schema: object = {"type": "string"}
    for _ in range(depth):
        schema = {"type": "object", "properties": {"x": schema}}
    return {"type": "object", "properties": {"x": schema}}


# ---------------------------------------------------------------------------
# VAL-W6-029: depth cap + grep guard list
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-029")
def test_relay_schema_match_depth_cap_returns_false_quickly() -> None:
    """A payload + schema nested deeper than MAX_DEPTH MUST return
    False (rejected by the depth cap) and complete well under the
    evaluator's 50 ms wall-clock budget.
    """

    pathological_payload = _make_deeply_nested(MAX_DEPTH + 8)
    pathological_schema = _make_deeply_nested_schema(MAX_DEPTH + 8)

    start = time.perf_counter()
    result = relay_schema_match(pathological_payload, pathological_schema)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert result is False, (
        "VAL-W6-029: depth-exceeding schema_match must return False"
    )
    assert elapsed_ms < 50.0, (
        f"VAL-W6-029: depth-bounded relay.schema_match took {elapsed_ms:.1f} ms; "
        f"must complete inside the evaluator's 50 ms wall-clock budget"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-029")
def test_evaluator_wall_clock_timeout_still_fires_for_a_slow_engine_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: the evaluator's wall-clock budget is the primary guard.
    An engine call that outlives the budget MUST trigger RELAY-CEL-003 /
    TIMEOUT. The Relay UDFs themselves do not sleep (verified by
    VAL-W6-023 / VAL-W6-029 grep) -- this test only proves the upstream
    bound is wired through ``evaluate()``.

    M6 WS-I port: the wasm engine hosts no caller-registered UDFs, so the
    slow engine call is simulated by stubbing the per-thread handle's
    ``eval`` to sleep past the budget -- the evaluate path (compile screens,
    run_with_timeout, quarantine) is the genuine code under test; the sleep
    is a test instrument, not a production behavior.
    """

    evaluator = WasmCelEvaluator(udfs=RELAY_UDFS)

    def slow_eval(expr, bindings=None, container=None, relay_profile=False):
        # 250 ms exceeds the default 50 ms budget by 5x.
        time.sleep(0.250)
        return {"ok": True, "value": {"t": "int", "v": "1"}}

    monkeypatch.setattr(evaluator._thread_handle(), "eval", slow_eval)
    with pytest.raises(RelayCelTimeoutError):
        evaluator.evaluate("1 + 1")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-029")
def test_udfs_do_not_use_off_loading_primitives() -> None:
    """Source grep over packages/contracts/src/relay_contracts/udfs/.
    The forbidden tokens are off-loading primitives that would let a
    UDF execute outside the evaluator's wall-clock budget. The grep
    scrubs strings and comments to avoid docstring false positives.
    """

    forbidden = (
        # Python side
        "threading.Thread",
        "asyncio.to_thread",
        "asyncio.create_task",
        "concurrent.futures",
        "subprocess.Popen",
        "subprocess.run",
        "os.fork",
        "multiprocessing.",
        # TS side (these tokens are in TS sources, but grepping the
        # Python tree for them is a defense-in-depth: a future PR
        # that pasted TS source verbatim would be caught).
        "worker_threads",
        "child_process.spawn",
        "child_process.exec",
        "child_process.fork",
        "cluster.fork",
    )
    hits: list[tuple[str, str]] = []
    for py in PKG_SRC_UDFS.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        scrubbed = _scrub_strings_and_comments(text)
        for token in forbidden:
            if token in scrubbed:
                hits.append((str(py.relative_to(REPO_ROOT)), token))
    assert hits == [], (
        f"VAL-W6-029: forbidden off-loading primitive in UDF source: {hits}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-029")
def test_relay_udfs_evaluator_construct_does_not_panic() -> None:
    """The fully-wired evaluator (RELAY_UDFS) constructs without
    error and refuses an over-budget timeout request.
    """

    evaluator = WasmCelEvaluator(udfs=RELAY_UDFS, timeout_ms=50)
    assert evaluator.timeout_ms == 50

    with pytest.raises(ValueError):
        # MAX_TIMEOUT_MS is 250; 9999 must be rejected.
        WasmCelEvaluator(udfs=RELAY_UDFS, timeout_ms=9999)
