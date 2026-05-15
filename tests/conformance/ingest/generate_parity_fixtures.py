"""Generate the cross-language ingest-run-envelope parity corpus (VAL-W4-037).

For a fixed set of run inputs (agent, version, input, redaction policy,
manifest commit hash, etc.), the Python SDK builds the
``POST /v1/ingest/runs`` envelope via :func:`relay.lifecycle.build_ingest_run_envelope`,
JCS-canonicalizes the result, and writes the canonical bytes hex form
plus their SHA-256.

The TS conformance test (``packages/sdk-typescript/test/w4_5_cross_language_parity.test.ts``)
calls the corresponding TS builder
(``buildIngestRunEnvelope`` from ``packages/sdk-typescript/src/lifecycle.ts``)
with the SAME inputs, JCS-canonicalizes via the same canonicalizer, and
asserts byte-equality with the Python-emitted hex.

Run:
    uv run python tests/conformance/ingest/generate_parity_fixtures.py

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_PYTHON_SRC = REPO_ROOT / "packages" / "sdk-python"
SCHEMAS_PYTHON_SRC = REPO_ROOT / "packages" / "schemas" / "python"
sys.path.insert(0, str(SDK_PYTHON_SRC))
sys.path.insert(0, str(SCHEMAS_PYTHON_SRC))

from relay.lifecycle import build_ingest_run_envelope  # noqa: E402
from relay_schemas.envelopes import canonical_bytes  # noqa: E402

# Each fixture: deterministic inputs with explicit idempotency_key so the
# resulting envelope is byte-stable (no ULID generation in the path).
_FIXTURE_MATRIX: list[dict[str, Any]] = [
    {
        "name": "minimal_started",
        "inputs": {
            "run_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "trace_id": "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "project_id": "00000000-0000-0000-0000-000000000001",
            "agent": {"name": "ops-agent", "version": "0.1.0"},
            "client_lifecycle_status": "started",
            "started_at": "2026-05-14T12:34:56.789Z",
            "sdk_version": "relay-typescript@0.0.0",
            "sdk_clock": "2026-05-14T12:34:56.789Z",
            "manifest_commit_hash": (
                "sha256-"
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            "actor_identity_hash": (
                "sha256-"
                "0000000000000000000000000000000000000000000000000000000000000002"
            ),
            "redaction_policy_version": "v1",
            "sequence_number": 1,
            "idempotency_key": "01ARZ3NDEKTSV4RRFFQ69G5FAX",
        },
    },
    {
        "name": "succeeded_with_metadata",
        "inputs": {
            "run_id": "01HXYZ0000000000000000000A",
            "trace_id": "01HXYZ0000000000000000000B",
            "project_id": "11111111-1111-1111-1111-111111111111",
            "agent": {
                "name": "code-review-agent",
                "version": "2.4.1",
                "framework": "openai-tools",
            },
            "client_lifecycle_status": "client_succeeded",
            "started_at": "2026-05-14T01:00:00.000Z",
            "sdk_version": "relay-typescript@0.0.0",
            "sdk_clock": "2026-05-14T01:00:01.500Z",
            "manifest_commit_hash": (
                "sha256-"
                "abcdef0000000000000000000000000000000000000000000000000000000000"
            ),
            "actor_identity_hash": (
                "sha256-"
                "fedcba0000000000000000000000000000000000000000000000000000000000"
            ),
            "redaction_policy_version": "v2",
            "sequence_number": 2,
            "metadata": {"flow": "review", "round": 1},
            "idempotency_key": "01HXYZ0000000000000000000C",
        },
    },
    {
        "name": "failed_with_extras",
        "inputs": {
            "run_id": "01HXYZ0000000000000000010A",
            "trace_id": "01HXYZ0000000000000000010B",
            "project_id": "22222222-2222-2222-2222-222222222222",
            "agent": {"name": "fraud-screen", "version": "0.9.0"},
            "client_lifecycle_status": "client_failed",
            "started_at": "2026-05-14T02:00:00.000Z",
            "sdk_version": "relay-typescript@0.0.0",
            "sdk_clock": "2026-05-14T02:00:05.000Z",
            "manifest_commit_hash": (
                "sha256-"
                "1111111111111111111111111111111111111111111111111111111111111111"
            ),
            "actor_identity_hash": (
                "sha256-"
                "2222222222222222222222222222222222222222222222222222222222222222"
            ),
            "redaction_policy_version": "v3",
            "sequence_number": 3,
            "extras": {
                "test_marker": "parity-fixture",
                "evidence_count": 7,
            },
            "idempotency_key": "01HXYZ0000000000000000010C",
        },
    },
]


def _render_fixture(name: str, inputs: dict[str, Any]) -> dict[str, Any]:
    envelope = build_ingest_run_envelope(**inputs)
    canonical = canonical_bytes(envelope)
    return {
        "name": name,
        "inputs": inputs,
        "envelope": envelope,
        "canonical_hex": canonical.hex(),
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main() -> None:
    fixtures = [_render_fixture(entry["name"], entry["inputs"]) for entry in _FIXTURE_MATRIX]
    corpus = {
        "schema_version": "relay.ingest_run_parity.v1",
        "description": (
            "Cross-language ingest-run envelope parity corpus (VAL-W4-037). "
            "Each fixture is the JCS-canonical hex of the Py-emitted "
            "buildIngestRunEnvelope output. The TS SDK MUST produce the "
            "same canonical bytes for the same inputs."
        ),
        "fixtures": fixtures,
    }
    out_path = Path(__file__).parent / "parity_fixtures.json"
    out_path.write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(fixtures)} fixtures to {out_path}")


if __name__ == "__main__":
    main()
