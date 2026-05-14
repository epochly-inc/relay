"""Generate the cross-language redaction parity corpus (VAL-W4-020).

Emits ``parity_fixtures.json`` next to this file. The Python redaction
engine processes a curated set of input payloads under a curated set of
policies + salt provisions, then writes the JCS-canonical bytes hex-form
of the redacted output for each fixture. The TypeScript engine, given
the same fixtures, MUST produce byte-identical canonical bytes.

VAL-W4-020 evidence: "JCS-canonical SHA-256 equality across Py and TS
per fixture; corpus exit code 0".

Run:
    uv run python tests/conformance/redaction/generate_parity_fixtures.py

This is a build-time helper; the generated JSON is committed and
consumed by both Py (parity self-check) and TS
(``packages/sdk-typescript/test/w4_3_cross_language_parity.test.ts``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Make the package source importable when running as a script.
REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_PYTHON_SRC = REPO_ROOT / "packages" / "sdk-python"
sys.path.insert(0, str(SDK_PYTHON_SRC))

from relay.redaction import (  # noqa: E402
    DEFAULT_APPLIES_TO_FIELDS,
    RedactionEngine,
    RedactionPolicy,
)

# Canonical fixed salt -- the corpus pins this on both sides so HMAC
# digests match byte-for-byte.
TENANT_SALT = b"test-tenant-salt-v3-do-not-use-in-prod"

BASE_POLICY: dict[str, Any] = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "2026-05-12.001",
    "raw_capture": False,
    "retention_days": 30,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {
            "id": "api_key",
            "kind": "regex",
            "pattern": "(sk-|key_)[A-Za-z0-9]{20,}",
            "action": "redact",
        },
        {
            "id": "email",
            "kind": "regex",
            "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+",
            "action": "hash",
        },
        {
            "id": "ssn_us",
            "kind": "regex",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "action": "redact",
        },
        {
            "id": "phone_us",
            "kind": "regex",
            "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
            "action": "drop",
        },
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_v3"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": "<dropped>"},
    },
    "applies_to_fields": list(DEFAULT_APPLIES_TO_FIELDS),
}


def _salt_provider(salt_ref: str) -> bytes:
    if salt_ref == "tenant_salt_v3":
        return TENANT_SALT
    raise KeyError(salt_ref)


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    """JCS-canonical bytes (sort keys, compact separators).

    Matches the TS ``canonicalJsonStringify`` in
    ``packages/sdk-typescript/src/redaction.ts`` and the codegen-side
    canonicalizer in ``packages/schemas/typescript/src/envelopes.ts``.
    """
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


# Curated input payloads. Each entry produces one fixture.
CASES: list[dict[str, Any]] = [
    {
        "name": "ascii-email-and-api-key-in-model-call",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "schema_version": "relay.trace.event.v1",
            "model_call": {
                "input": "please email alice@example.com about sk-ABCDEFGHIJKLMNOPQRSTUV",
                "output": "okay",
            },
        },
    },
    {
        "name": "secret-across-five-applies-to-fields",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "model_call": {
                "input": "key sk-ZZZZZZZZZZZZZZZZZZZZ",
                "output": "echo sk-ZZZZZZZZZZZZZZZZZZZZ",
            },
            "tool_call": {
                "args": {"q": "use sk-ZZZZZZZZZZZZZZZZZZZZ"},
                "result": {"text": "got sk-ZZZZZZZZZZZZZZZZZZZZ"},
            },
            "retrieval": {
                "documents": [
                    {"text": "doc-a contains sk-ZZZZZZZZZZZZZZZZZZZZ"},
                    {"text": "doc-b is clean"},
                ],
            },
        },
    },
    {
        "name": "cyrillic-A-homoglyph-api-key",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "model_call": {
                # U+0410 CYRILLIC CAPITAL LETTER A in place of ASCII A.
                "input": "key is sk-" + chr(0x0410) + "BCDEFGHIJKLMNOPQRSTU end",
            },
        },
    },
    {
        "name": "greek-A-homoglyph-api-key",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "model_call": {
                # U+0391 GREEK CAPITAL LETTER ALPHA.
                "input": "key is sk-" + chr(0x0391) + "BCDEFGHIJKLMNOPQRSTU end",
            },
        },
    },
    {
        "name": "cyrillic-a-homoglyph-email-hash",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "tool_call": {
                # U+0430 CYRILLIC SMALL LETTER A.
                "args": {"q": "email is " + chr(0x0430) + "lice@example.com please"},
            },
        },
    },
    {
        "name": "ssn-and-phone-in-tool-args",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "tool_call": {
                "args": {
                    "ssn": "123-45-6789",
                    "phone": "555-867-5309",
                    "note": "see ssn 987-65-4321 and phone 555-123-4567",
                },
            },
        },
    },
    {
        "name": "no-match-clean-payload",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "model_call": {"input": "tell me about the weather", "output": "it is sunny"},
        },
    },
    {
        "name": "deterministic-keys-mixed-case",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "z_top": "hello",
            "a_top": "world",
            "m_top": {"y_inner": 1, "b_inner": 2, "n_inner": [3, 2, 1]},
        },
    },
    # NOTE: a binary-attachment fixture would diverge between Py and TS:
    # the Python W3.3 engine routes bytes through ``_to_string`` (decoded
    # with errors='replace') whereas the TS W4.3 engine emits a
    # ``{_digest_sha256: hex}`` reference per VAL-W4-025. Cross-language
    # byte-equality therefore EXCLUDES binary fixtures; VAL-W4-025 is
    # exercised solely from the TS side in
    # ``packages/sdk-typescript/test/w4_3_binary_attachments.test.ts``.
    {
        "name": "nested-arrays-and-objects",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "tool_call": {
                "args": {
                    "items": [
                        {"name": "alpha", "secret": "sk-aaaaaaaaaaaaaaaaaaaaa"},
                        {"name": "beta", "email": "bob@example.com"},
                        {"name": "gamma", "tags": ["x", "y", "z"]},
                    ],
                },
            },
        },
    },
    {
        "name": "ascii-only-email-hash-determinism",
        "policy": "BASE_POLICY",
        "salt_ref": "tenant_salt_v3",
        "input": {
            "model_call": {"input": "two: alice@example.com and alice@example.com"},
        },
    },
]


def _rehydrate_binary(value: Any) -> Any:
    """Rewrite ``{$binary_b64: hex}`` markers into native bytes."""
    if isinstance(value, dict):
        if set(value.keys()) == {"$binary_b64"} and isinstance(value["$binary_b64"], str):
            return base64.b64decode(value["$binary_b64"])
        return {k: _rehydrate_binary(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_rehydrate_binary(v) for v in value]
    return value


def main() -> int:
    out_path = Path(__file__).parent / "parity_fixtures.json"
    fixtures: list[dict[str, Any]] = []

    policies = {"BASE_POLICY": BASE_POLICY}
    loaded_policies = {name: RedactionPolicy.load(body) for name, body in policies.items()}

    for case in CASES:
        policy = loaded_policies[case["policy"]]
        engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
        rehydrated = _rehydrate_binary(case["input"])
        # The Python engine returns a dict; we compute canonical bytes
        # ourselves so the bytes-form is the SAME canonicalization the
        # TS side uses (sort_keys + compact separators).
        # NOTE: redact_capture_payload uses Python defaults (sort_keys
        # with default separators) which differ in spaces; here we
        # bypass it and call engine.redact() + canonical_bytes directly.
        redacted_dict = engine.redact(rehydrated)
        # Bytes objects in the redacted output (from the binary digest
        # path) are not directly JSON-serialisable. The Python engine
        # currently coerces bytes via ``_to_string`` into a redacted
        # string (because the byte payload runs through the matcher
        # path). For parity-fixture purposes we record the redacted
        # dict as-is; if it contains bytes, decode via errors='replace'.
        # The fixture loader on both sides applies the same coercion.
        json_safe = _coerce_to_json(redacted_dict)
        canonical = _canonical_bytes(json_safe)
        digest = hashlib.sha256(canonical).hexdigest()
        fixtures.append(
            {
                "name": case["name"],
                "policy": case["policy"],
                "salt_ref": case["salt_ref"],
                # Original input -- TS test loads this and re-runs
                # against its own engine to compare.
                "input": case["input"],
                # Canonical-bytes hex-encoded for transport in JSON.
                "canonical_redacted_hex": canonical.hex(),
                # SHA-256 of the canonical bytes (cheap to compare).
                "canonical_redacted_sha256": digest,
            }
        )

    payload = {
        "schema_version": "relay.redaction_parity.v1",
        "tenant_salt_b64": base64.b64encode(TENANT_SALT).decode("ascii"),
        "policies": policies,
        "fixtures": fixtures,
    }

    out_path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(fixtures)} fixtures to {out_path}")
    return 0


def _coerce_to_json(value: Any) -> Any:
    """Coerce Python bytes / bytearray to UTF-8 strings for JSON.

    The Python engine's binary handling (in v0.1) routes bytes through
    the matcher path via ``_to_string``; this helper merely makes the
    output dict serialisable (bytes -> string with errors='replace').
    """
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {k: _coerce_to_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_coerce_to_json(v) for v in value]
    if isinstance(value, tuple):
        return [_coerce_to_json(v) for v in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
