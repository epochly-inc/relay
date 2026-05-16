"""W17.4 VAL-W17-016: aggregate Relay-CEL corpus size floor.

The aggregate Relay-CEL conformance corpus (W6.5 corpus +
per-UDF case files + idiom/adversarial cases) MUST contain >= 150
cases. Target per CQ1 brief is ~200; the 150 floor is the
release-blocking minimum.

Cases are categorised by their source directory / source file:

  - udf       : per-UDF cases under tests/conformance/cel/relay-udfs/
  - idiom     : eval_value / udf_value cases from the W6.5 corpus
                (relay_cel_corpus.json); these exercise CEL idioms
                and UDF semantics.
  - adversarial: eval_error cases from the W6.5 corpus (profile
                 rejection, regex backreference, type-coercion edges).

Tool: conformance-corpus-test (pytest plumbing tier).
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CEL_DIR = REPO_ROOT / "tests" / "conformance" / "cel"
RELAY_UDFS_DIR = CEL_DIR / "relay-udfs"
W6_5_CORPUS_PATH = CEL_DIR / "relay_cel_corpus.json"
MIN_TOTAL_CASES: int = 150


def _count_udf_cases() -> int:
    if not RELAY_UDFS_DIR.exists():
        return 0
    return sum(1 for _ in RELAY_UDFS_DIR.rglob("case_*.json"))


def _categorise_w6_5() -> dict[str, int]:
    if not W6_5_CORPUS_PATH.exists():
        return {"idiom": 0, "adversarial": 0}
    doc = json.loads(W6_5_CORPUS_PATH.read_text(encoding="utf-8"))
    cases = doc.get("cases", []) or []
    idiom = 0
    adversarial = 0
    for c in cases:
        kind = c.get("kind")
        if kind in ("eval_value", "udf_value"):
            idiom += 1
        elif kind == "eval_error":
            adversarial += 1
    return {"idiom": idiom, "adversarial": adversarial}


def _category_breakdown() -> dict[str, int]:
    bd = _categorise_w6_5()
    bd["udf"] = _count_udf_cases()
    return bd


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-016")
def test_corpus_total_meets_release_floor() -> None:
    breakdown = _category_breakdown()
    total = sum(breakdown.values())
    assert total >= MIN_TOTAL_CASES, (
        f"VAL-W17-016: aggregate Relay-CEL corpus has {total} cases; "
        f"release-blocking floor is {MIN_TOTAL_CASES}.\n"
        f"  Breakdown: {breakdown}\n"
        f"  Target per CQ1 brief is ~200."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-016")
def test_corpus_breakdown_includes_all_categories() -> None:
    """Every category MUST contribute at least one case so the corpus
    exercises all three buckets (udf / idiom / adversarial)."""

    breakdown = _category_breakdown()
    empty = [cat for cat, n in breakdown.items() if n == 0]
    assert empty == [], (
        f"VAL-W17-016: corpus categories with zero cases: {empty}; "
        f"breakdown: {breakdown}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-016")
def test_corpus_breakdown_is_reported_for_evidence() -> None:
    """Evidence requirement: the CI assertion MUST report the breakdown
    by category so a regression in any single bucket is debuggable."""

    breakdown = _category_breakdown()
    # Stable, deterministic ordering for evidence capture.
    rendered = ", ".join(f"{k}={breakdown[k]}" for k in sorted(breakdown.keys()))
    print(f"[w17.4-corpus-size] total={sum(breakdown.values())} {rendered}")
    # Sanity: udf bucket must be non-trivial (>= 3 UDFs * >= 5 cases = 15).
    assert breakdown.get("udf", 0) >= 15, (
        f"VAL-W17-016: udf bucket has {breakdown.get('udf', 0)} cases; "
        "expected >= 15 (3 UDFs * 5 cases minimum per VAL-W17-015)"
    )
