"""Generate cassette parity corpus (VAL-W4-041).

Produces canonical JSONL cassette payloads bound to fixed inputs so the
TS replay client (``readCassetteFile``) can read the cassette
byte-identically and validate header + entry shape.

The generator emits two artefacts:

  * ``parity_fixtures.json`` -- a JSON document carrying the cassette
    inputs, the canonical JSONL bytes (utf-8 text), and the SHA-256 of
    the bytes.
  * ``cassette_minimal.jsonl`` -- a side-by-side raw JSONL file the TS
    test reads via :func:`readCassetteFile` to exercise the file-IO
    path.

Run:
    uv run python tests/conformance/cassettes/generate_parity_fixtures.py

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_PYTHON_SRC = REPO_ROOT / "packages" / "schemas" / "python"
sys.path.insert(0, str(SCHEMAS_PYTHON_SRC))

from relay_schemas.envelopes import canonical_bytes  # noqa: E402

CASSETTE_HEADER_SCHEMA_VERSION = "relay.cassette.v1"
CASSETTE_ENTRY_SCHEMA_VERSION = "relay.cassette_entry.v1"


def _canonical_line(value: dict[str, Any]) -> bytes:
    """Return the canonical-JSON bytes for one cassette line.

    Uses the same canonicalizer the TS reader trusts on load
    (RFC-8785 JCS via :func:`canonical_bytes`). The line is the
    canonical bytes followed by a single ``\n``.
    """
    return canonical_bytes(value) + b"\n"


def _build_cassette(
    *,
    case_id: str,
    session_id: str,
    recorded_at: str,
    manifest_commit_hash: str,
    entries: list[dict[str, Any]],
) -> bytes:
    header = {
        "schema_version": CASSETTE_HEADER_SCHEMA_VERSION,
        "case_id": case_id,
        "session_id": session_id,
        "recorded_at": recorded_at,
        "manifest_commit_hash": manifest_commit_hash,
    }
    parts: list[bytes] = [_canonical_line(header)]
    for i, entry in enumerate(entries):
        record = {
            "schema_version": CASSETTE_ENTRY_SCHEMA_VERSION,
            "sequence": i,
            **entry,
        }
        parts.append(_canonical_line(record))
    return b"".join(parts)


_FIXTURES: list[dict[str, Any]] = [
    {
        "name": "minimal_two_entries",
        "inputs": {
            "case_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "session_id": "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "recorded_at": "2026-05-14T12:00:00.000Z",
            "manifest_commit_hash": (
                "sha256-"
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            "entries": [
                {
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "request_digest": (
                        "sha256-"
                        "1111111111111111111111111111111111111111111111111111111111111111"
                    ),
                    "response": {
                        "id": "chatcmpl-fixture-1",
                        "model": "gpt-4o-mini",
                        "system_fingerprint": "fp_fixture_1",
                        "usage": {
                            "prompt_tokens": 12,
                            "completion_tokens": 4,
                            "total_tokens": 16,
                        },
                    },
                    "response_digest": (
                        "sha256-"
                        "2222222222222222222222222222222222222222222222222222222222222222"
                    ),
                    "timestamp": "2026-05-14T12:00:00.100Z",
                },
                {
                    "provider": "anthropic",
                    "model": "claude-3-5-haiku",
                    "request_digest": (
                        "sha256-"
                        "3333333333333333333333333333333333333333333333333333333333333333"
                    ),
                    "response": {
                        "id": "msg_fixture_2",
                        "model": "claude-3-5-haiku",
                        "stop_reason": "end_turn",
                        "usage": {
                            "input_tokens": 18,
                            "output_tokens": 6,
                        },
                    },
                    "response_digest": (
                        "sha256-"
                        "4444444444444444444444444444444444444444444444444444444444444444"
                    ),
                    "timestamp": "2026-05-14T12:00:00.250Z",
                },
            ],
        },
    },
    {
        "name": "single_vercel_ai_entry",
        "inputs": {
            "case_id": "01HXYZ0000000000000000000A",
            "session_id": "01HXYZ0000000000000000000B",
            "recorded_at": "2026-05-14T13:00:00.000Z",
            "manifest_commit_hash": (
                "sha256-"
                "abcdef0000000000000000000000000000000000000000000000000000000000"
            ),
            "entries": [
                {
                    "provider": "vercel-ai",
                    "model": "gpt-4o",
                    "request_digest": (
                        "sha256-"
                        "5555555555555555555555555555555555555555555555555555555555555555"
                    ),
                    "response": {
                        "text": "ok",
                        "finishReason": "stop",
                        "usage": {
                            "promptTokens": 7,
                            "completionTokens": 2,
                            "totalTokens": 9,
                        },
                    },
                    "response_digest": (
                        "sha256-"
                        "6666666666666666666666666666666666666666666666666666666666666666"
                    ),
                    "timestamp": "2026-05-14T13:00:00.500Z",
                },
            ],
        },
    },
]


def main() -> None:
    rendered: list[dict[str, Any]] = []
    for fixture in _FIXTURES:
        cassette_bytes = _build_cassette(**fixture["inputs"])
        rendered.append(
            {
                "name": fixture["name"],
                "inputs": fixture["inputs"],
                "cassette_text": cassette_bytes.decode("utf-8"),
                "cassette_sha256": hashlib.sha256(cassette_bytes).hexdigest(),
                "entry_count": len(fixture["inputs"]["entries"]),
            }
        )

    out_path = Path(__file__).parent / "parity_fixtures.json"
    out_path.write_text(
        json.dumps(
            {
                "schema_version": "relay.cassette_parity.v1",
                "description": (
                    "Cross-language cassette parity corpus (VAL-W4-041). "
                    "Each fixture carries a Python-emitted JSONL cassette; "
                    "the TS reader (parseCassette / readCassetteFile) MUST "
                    "load it byte-identically and produce a matching "
                    "fileDigestSha256."
                ),
                "fixtures": rendered,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Side-by-side raw cassette file for the file-IO path test.
    minimal_bytes = _build_cassette(**_FIXTURES[0]["inputs"])
    minimal_path = Path(__file__).parent / "cassette_minimal.jsonl"
    minimal_path.write_bytes(minimal_bytes)

    print(f"wrote {len(rendered)} fixtures to {out_path}")
    print(f"wrote raw cassette file to {minimal_path}")


if __name__ == "__main__":
    main()
