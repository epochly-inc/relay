"""W8.1 plumbing tests: VAL-W8-005 evaluator is deterministic.

Two evaluations on identical inputs produce byte-identical
unmet_conditions / failed_assertion_ids. Also greps the package source
for non-determinism sources (time, random, env, network); zero non-
comment hits permitted per the contract assertion text.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    InMemoryEvidenceProvider,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_contracts import jcs_canonicalize
from relay_gate_engine import GateAssertion

# Source paths to scan for non-determinism patterns. The contract
# assertion text scopes the grep to packages/gate/ excluding test
# directories. VAL-W8-005 governs the W8.1 EVALUATOR (a pure function);
# the W8.2 writer (decision_writer.py + signed_decision.py + db_grants.py)
# legitimately mints UUIDs and reads wall-clock time and is therefore
# scoped out of this grep. The W8.2 modules carry their own determinism
# discipline through their canonical-JSON output (RFC 8785 byte stable
# given equal inputs) which is enforced separately in
# test_w8_2_*.py via byte-equality of canonical_json_bytes(...) for
# fixed payloads.
_PACKAGE_SRC = Path(__file__).resolve().parent.parent / "src" / "relay_gate_engine"

# W8.1-only file allowlist for the determinism grep. New W8.2 modules
# (decision_writer, signed_decision, db_grants) are deliberately excluded:
# they implement the canonical-row writer which by spec produces fresh
# UUIDs (gate_decision_id, evidence_bundle_id, event_id) and uses the
# wall clock for decided_at timestamps.
_W8_1_DETERMINISM_FILES: tuple[str, ...] = (
    "evaluator.py",
    "pipeline.py",
    "draft_lock.py",
    "errors.py",
)


# Per VAL-W8-005, ALL of these patterns must have zero non-comment hits
# in the package source. Splitting into Py and TS lists; this package is
# Python-only so only the Py list applies here.
_PY_NON_DETERMINISM_PATTERNS: tuple[str, ...] = (
    "time.time",
    "time.monotonic",
    "random.",
    "os.urandom",
    "uuid.uuid4",
    "secrets.",
    "datetime.now",
    "os.environ",
    "socket.",
    "requests.",
    "urllib.request",
    "httpx.",
)


def _strip_python_comments(src_text: str) -> str:
    """Drop full-line and trailing # comments from Python source.

    Heuristic: not a full Python parser; sufficient to suppress doc
    references like "no time.time" inside docstring lines that begin
    with #. Triple-quoted docstrings are also stripped because the
    contract scoping is "non-comment hits" and docstrings are
    documentation, not executable code.
    """
    out_lines: list[str] = []
    in_triple = False
    triple_marker = ""
    for line in src_text.splitlines():
        stripped = line.lstrip()
        if in_triple:
            if triple_marker in stripped:
                in_triple = False
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            triple_marker = stripped[:3]
            # Single-line triple docstring case.
            rest = stripped[3:]
            if triple_marker in rest:
                continue
            in_triple = True
            continue
        if stripped.startswith("#"):
            continue
        # Strip trailing # comments cautiously: split at the first '#'
        # that is not inside a string literal. Approximate by ignoring
        # # that follow an odd number of unescaped quotes.
        cleaned = re.sub(r"(?<!['\"])\s*#.*$", "", line)
        out_lines.append(cleaned)
    return "\n".join(out_lines)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-005")
def test_evaluator_output_is_byte_identical_across_runs(
    evaluator, evidence_provider: InMemoryEvidenceProvider,
) -> None:
    """Two runs on identical inputs produce byte-identical canonical bytes."""
    evidence_provider.add("bundle-x", {"artifact_sha256": "sha256-deadbeef"})
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)

    def _run() -> tuple[bytes, bytes]:
        pipeline = make_pipeline(evaluator)
        gate = make_gate(
            gate_id=GATE_ID_SCRUTINY,
            gate_name="scrutiny",
            assertions=(
                GateAssertion(
                    assertion_id="VAL-X-001", priority="p0", expression="1 == 1",
                ),
                GateAssertion(
                    assertion_id="VAL-X-002", priority="p1", expression="1 == 2",
                ),
                GateAssertion(
                    assertion_id="VAL-X-003", priority="p2", expression="1 == 1",
                ),
            ),
            conditions=("1 == 1", "2 == 2"),
        )
        # Pin the same draft_id across both runs so the JCS bytes are
        # bound to the same draft envelope. Determinism is about
        # SAME-INPUT producing SAME-OUTPUT; differing draft_ids would
        # not be the "same input" the contract refers to.
        draft = make_draft(
            gate_id=GATE_ID_SCRUTINY,
            draft_id="draft-fixed-001",
            evidence_refs=("bundle-x",),
        )
        outcome = pipeline.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft, now=now,
        )
        # JCS-canonical bytes of the two output fields the contract pins.
        unmet_bytes = jcs_canonicalize(
            [dict(c) for c in outcome.unmet_conditions]
        )
        failed_bytes = jcs_canonicalize(list(outcome.failed_assertion_ids))
        return unmet_bytes, failed_bytes

    a_unmet, a_failed = _run()
    b_unmet, b_failed = _run()
    assert a_unmet == b_unmet
    assert a_failed == b_failed


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-005")
def test_no_non_determinism_in_package_source() -> None:
    """Greps packages/gate/src/relay_gate_engine/ for banned patterns.

    Excludes test directories and __pycache__. Strips comments and
    docstrings before matching so a doc that mentions "time.time" in a
    sentence does not falsely flag.
    """
    hits: dict[str, list[str]] = {p: [] for p in _PY_NON_DETERMINISM_PATTERNS}
    # Scope to the W8.1 evaluator files only; W8.2 writer modules
    # legitimately mint UUIDs + use wall-clock time and are excluded.
    py_files = sorted(
        _PACKAGE_SRC / name for name in _W8_1_DETERMINISM_FILES
    )
    assert py_files, f"no python source found under {_PACKAGE_SRC}"
    for py_file in py_files:
        if "__pycache__" in py_file.parts:
            continue
        if not py_file.exists():
            raise AssertionError(
                f"W8.1 determinism allowlist file missing: {py_file}"
            )
        text = py_file.read_text(encoding="utf-8")
        cleaned = _strip_python_comments(text)
        for pattern in _PY_NON_DETERMINISM_PATTERNS:
            if pattern in cleaned:
                hits[pattern].append(str(py_file))
    # Build a single readable failure message naming pattern + files.
    bad = {p: files for p, files in hits.items() if files}
    assert not bad, (
        "VAL-W8-005: non-determinism source(s) found in "
        "packages/gate/src/relay_gate_engine/ (after stripping comments "
        f"+ docstrings): {bad}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-005")
def test_sort_is_deterministic_with_priority_ties(evaluator) -> None:
    """Equal-priority assertions sort by assertion_id lexicographically.

    This pins the secondary tiebreaker so the iteration order is
    stable across runs even when input order varies.
    """
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        cascade_on_block=False,
        # Three P1 assertions in REVERSE alphabetical input order; the
        # evaluator MUST return them in alpha order in evaluated_assertion_ids.
        assertions=(
            GateAssertion(assertion_id="VAL-X-Z", priority="p1", expression="1 == 1"),
            GateAssertion(assertion_id="VAL-X-Y", priority="p1", expression="1 == 1"),
            GateAssertion(assertion_id="VAL-X-A", priority="p1", expression="1 == 1"),
        ),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    assert outcome.evaluated_assertion_ids == ("VAL-X-A", "VAL-X-Y", "VAL-X-Z")
