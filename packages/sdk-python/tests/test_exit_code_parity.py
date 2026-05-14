"""W4.4 parity test for the canonical Relay exit-code table.

Binds to VAL-W4-031 (TS canonical exit-code mapping) and the Python
parity in :mod:`relay.exit_codes`. Ensures the cross-language fixture at
``tests/conformance/cli-exit-codes/parity_fixtures.json`` agrees with the
Py-side resolver row-by-row. The TS sibling test consumes the same
corpus and asserts the same equality from the JS surface.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from relay.exit_codes import (
    CANONICAL_EXIT_CODE_TABLE,
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_4XX_BLOCK,
    EXIT_4XX_REMEDIATE,
    EXIT_5XX_TRANSIENT,
    EXIT_CASSETTE_MISS,
    EXIT_CLI_USAGE,
    EXIT_EVAL_DEFERRED,
    EXIT_GATE_TTL_EXPIRED,
    EXIT_SUCCESS,
    EXIT_UNCAUGHT_INTERNAL,
    EXIT_WAL_STORAGE,
    exit_code_for_code_and_status,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = (
    REPO_ROOT / "tests" / "conformance" / "cli-exit-codes" / "parity_fixtures.json"
)


def _load_corpus() -> dict[str, object]:
    raw = CORPUS_PATH.read_text(encoding="utf-8")
    return json.loads(raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_canonical_exit_code_table_constants_match_contract() -> None:
    """Exit code constants byte-equal the contract VAL-W4-031 table."""
    assert EXIT_SUCCESS == 0
    assert EXIT_4XX_BLOCK == 1
    assert EXIT_4XX_REMEDIATE == 2
    assert EXIT_4XX_AUTH_HANDOFF == 3
    assert EXIT_CASSETTE_MISS == 4
    assert EXIT_5XX_TRANSIENT == 5
    assert EXIT_WAL_STORAGE == 6
    assert EXIT_GATE_TTL_EXPIRED == 7
    assert EXIT_EVAL_DEFERRED == 8
    assert EXIT_CLI_USAGE == 64
    assert EXIT_UNCAUGHT_INTERNAL == 70


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_canonical_exit_code_table_dict_completeness() -> None:
    """CANONICAL_EXIT_CODE_TABLE has exactly 11 entries (one per row)."""
    assert len(CANONICAL_EXIT_CODE_TABLE) == 11
    assert CANONICAL_EXIT_CODE_TABLE["EXIT_SUCCESS"] == 0
    assert CANONICAL_EXIT_CODE_TABLE["EXIT_UNCAUGHT_INTERNAL"] == 70


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_corpus_loads_with_expected_schema_version() -> None:
    """Cross-language corpus JSON loads cleanly and pins the schema."""
    corpus = _load_corpus()
    assert corpus["schema_version"] == "relay.cli_exit_code_parity.v1"
    assert isinstance(corpus["fixtures"], list)
    assert len(corpus["fixtures"]) >= 12  # >= one row per canonical exit code


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_python_resolver_matches_every_corpus_row() -> None:
    """Py-side exit_code_for_code_and_status agrees with each corpus row."""
    corpus = _load_corpus()
    for fixture in corpus["fixtures"]:
        actual = exit_code_for_code_and_status(
            fixture["wire_code"],
            fixture["http_status"],
            fixture["retry_advice_mode"],
        )
        assert actual == fixture["expected_exit"], (
            f"row '{fixture['name']}' Py mismatch: got {actual}, "
            f"expected {fixture['expected_exit']}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_corpus_canonical_table_matches_python_constants() -> None:
    """The corpus's embedded canonical_exit_code_table matches Py constants."""
    corpus = _load_corpus()
    assert corpus["canonical_exit_code_table"] == CANONICAL_EXIT_CODE_TABLE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_unknown_code_with_no_status_routes_to_uncaught_internal() -> None:
    """Forward-compat: unknown code + no http_status -> exit 70."""
    assert (
        exit_code_for_code_and_status("RELAY-FUTURE-999", None, None)
        == EXIT_UNCAUGHT_INTERNAL
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_relay_auth_namespace_routes_to_auth_handoff_bucket() -> None:
    """Every RELAY-AUTH-* code routes to exit 3 regardless of http_status."""
    for code in ("RELAY-AUTH-001", "RELAY-AUTH-014", "RELAY-AUTH-999"):
        assert (
            exit_code_for_code_and_status(code, 401, "no_retry")
            == EXIT_4XX_AUTH_HANDOFF
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_4xx_remediate_modes_route_to_remediate_bucket() -> None:
    """4xx + (after_state_change | retryable | after_retry_after) -> exit 2."""
    for mode in ("after_state_change", "retryable", "after_retry_after"):
        assert (
            exit_code_for_code_and_status("RELAY-ING-001", 422, mode)
            == EXIT_4XX_REMEDIATE
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_4xx_no_retry_routes_to_block_bucket() -> None:
    """4xx + no_retry -> exit 1 (block)."""
    assert (
        exit_code_for_code_and_status("RELAY-ING-001", 422, "no_retry")
        == EXIT_4XX_BLOCK
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-031")
def test_5xx_routes_to_transient_bucket_unless_storage() -> None:
    """5xx without storage prefix -> exit 5; with storage prefix -> exit 6."""
    assert (
        exit_code_for_code_and_status("RELAY-SIDECAR-013", 503, None)
        == EXIT_5XX_TRANSIENT
    )
    assert (
        exit_code_for_code_and_status("RELAY-SIDECAR-STORAGE-001", 500, None)
        == EXIT_WAL_STORAGE
    )
    assert (
        exit_code_for_code_and_status("RELAY-SQLITE-001", 500, None)
        == EXIT_WAL_STORAGE
    )
