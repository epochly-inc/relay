"""Generate the cross-language CLI exit-code parity corpus (VAL-W4-031).

Emits ``parity_fixtures.json`` next to this file. Each fixture row pins
a single ``(wire_code, http_status, retry_advice_mode)`` triple to its
canonical exit code per the contract VAL-W4-031 table. The TS test
``packages/sdk-typescript/test/w4_4_exit_codes.test.ts`` and the Python
test ``packages/sdk-python/tests/test_exit_code_parity.py`` consume this
file and assert their respective resolvers produce the same exit code
for every row.

Run:
    uv run python tests/conformance/cli-exit-codes/generate_parity_fixtures.py

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_PYTHON_SRC = REPO_ROOT / "packages" / "sdk-python"
sys.path.insert(0, str(SDK_PYTHON_SRC))

from relay.exit_codes import (  # noqa: E402
    CANONICAL_EXIT_CODE_TABLE,
    exit_code_for_code_and_status,
)

# Each row: (wire_code, http_status, retry_advice_mode, expected_exit,
# scenario_label).
_ROWS: list[tuple[str, int | None, str | None, int, str]] = [
    # success path -- the SDK never raises for 2xx but the table covers it.
    ("RELAY-ING-001", 200, "no_retry", 0, "row_exit_0_success_2xx"),
    # 4xx with action=block (SDK raises a typed leaf with no_retry advice).
    ("RELAY-SDK-005", 422, "no_retry", 1, "row_exit_1_4xx_block"),
    ("RELAY-SDK-001", 400, "no_retry", 1, "row_exit_1_config_block"),
    # 4xx with action=remediate (after_state_change OR retryable advice).
    ("RELAY-ING-022", 422, "after_state_change", 2, "row_exit_2_4xx_remediate"),
    ("RELAY-RATE-001", 429, "after_retry_after", 2, "row_exit_2_rate_limited"),
    # 4xx auth/handoff (RELAY-GATE-021 + RELAY-AUTH-*).
    ("RELAY-GATE-021", 422, "after_state_change", 3, "row_exit_3_handoff_stale"),
    ("RELAY-AUTH-001", 401, "no_retry", 3, "row_exit_3_auth_missing"),
    ("RELAY-AUTH-014", 401, "no_retry", 3, "row_exit_3_auth_expired"),
    # cassette miss.
    ("RELAY-CASSETTE-MISS", 422, "no_retry", 4, "row_exit_4_cassette_miss"),
    # 5xx + network transient.
    ("RELAY-SIDECAR-013", 503, "after_state_change", 5, "row_exit_5_5xx_transient"),
    # WAL/storage.
    ("RELAY-SIDECAR-STORAGE-001", 500, "no_retry", 6, "row_exit_6_storage_wal"),
    ("RELAY-SQLITE-001", 500, "no_retry", 6, "row_exit_6_sqlite"),
    # gate TTL expired.
    ("RELAY-GATE-024", 422, "no_retry", 7, "row_exit_7_gate_ttl"),
    # LLM-judge deferred.
    ("RELAY-EVAL-EVALUATOR-DEFERRED", 422, "no_retry", 8, "row_exit_8_eval_deferred"),
    # CLI usage error (the CLI binary owns this; the SDK never raises it).
    # Code constant RELAY-CLI-070 maps to exit 70 (uncaught internal). The
    # symbolic 'wrong-flag' bucket is exit 64; the CLI emits that directly
    # without going through the error envelope, so the conformance row
    # below pins the documented exit-64 sentinel via http_status only.
    ("RELAY-FUTURE-999", None, None, 70, "row_exit_70_uncaught_unknown"),
    ("RELAY-FUTURE-999", 999, None, 70, "row_exit_70_unknown_status"),
]


def main() -> None:
    fixtures: list[dict[str, Any]] = []
    for wire_code, http_status, mode, expected_exit, label in _ROWS:
        actual = exit_code_for_code_and_status(wire_code, http_status, mode)
        assert actual == expected_exit, (
            f"row '{label}' Py mismatch: got {actual}, expected {expected_exit}"
        )
        fixtures.append(
            {
                "name": label,
                "wire_code": wire_code,
                "http_status": http_status,
                "retry_advice_mode": mode,
                "expected_exit": expected_exit,
            }
        )

    corpus = {
        "schema_version": "relay.cli_exit_code_parity.v1",
        "description": (
            "Cross-language CLI exit-code parity corpus (VAL-W4-031 + "
            "VAL-W5-006). Each row pins (wire_code, http_status, "
            "retry_advice_mode) -> expected_exit per the canonical Relay "
            "exit-code table. Both Py (relay.exit_codes) and TS "
            "(@epochly/relay/exit_codes) resolvers MUST produce the "
            "same exit code for every row."
        ),
        "canonical_exit_code_table": CANONICAL_EXIT_CODE_TABLE,
        "fixtures": fixtures,
    }
    out_path = Path(__file__).parent / "parity_fixtures.json"
    out_path.write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(fixtures)} CLI exit-code fixtures to {out_path}")


if __name__ == "__main__":
    main()
