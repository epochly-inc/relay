"""Cross-language parity for json_pointer matcher at null / bool leaves
(P1 audit fix).

Pre-fix Python coerced ``None`` via ``str(None) == "None"`` and bools
via ``str(True/False) == "True"/"False"``. The TS mirror at
``packages/sdk-typescript/src/redaction.ts:797-876`` uses
``String(null) === "null"`` and ``String(true) === "true"``. For a
json_pointer matcher with action ``hash``, the HMAC inputs diverged
across runtimes -> divergent digests for the same logical wire input.

This test pins the canonical coercion: ``null`` -> ``"null"``,
``true`` -> ``"true"``, ``false`` -> ``"false"``. The same fixtures
are exercised by the TS suite in
``packages/sdk-typescript/test/w4_3_cross_language_parity.test.ts``
(or a sibling parity test) -- the contract is identical.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import hmac

import pytest
from relay.redaction import RedactionEngine, RedactionPolicy

_DETERMINISTIC_SALT = b"json-pointer-null-leaf-parity-salt"


def _salt_provider(_ref: str) -> bytes:
    return _DETERMINISTIC_SALT


def _hmac_hex(plaintext: str) -> str:
    return hmac.new(
        _DETERMINISTIC_SALT, plaintext.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _hash_pointer_policy(paths: list[str]) -> dict:
    return {
        "schema_version": "relay.redaction.v1",
        "policy_version": "2026-05-17.002",
        "raw_capture": False,
        "retention_days": 30,
        "dpa_ref": None,
        "approver_user_id": None,
        "matchers": [
            {
                "id": "leaf_hash",
                "kind": "json_pointer",
                "paths": paths,
                "action": "hash",
            },
        ],
        "action_policy": {
            "hash": {"algorithm": "hmac-sha256", "salt_ref": "salt-a"},
            "redact": {"placeholder": "<redacted>"},
            "drop": {"placeholder": None},
        },
    }


@pytest.mark.plumbing
def test_json_pointer_null_leaf_hashes_literal_null_not_python_None() -> None:
    """A JSON ``null`` leaf under a hash-action json_pointer matcher MUST
    be HMAC'd over the literal string ``"null"``, matching JS
    ``String(null)``. Pre-fix Python emitted HMAC over ``"None"``.
    """
    policy = RedactionPolicy.load(_hash_pointer_policy(["/x"]))
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {"x": None}
    out = engine.redact(payload)
    expected = _hmac_hex("null")
    assert out == {"x": expected}, out
    # Defensive: the pre-fix value must NOT appear.
    forbidden = _hmac_hex("None")
    assert out["x"] != forbidden, (
        "regression: HMAC computed over Python-coerced 'None' instead of "
        "the canonical literal 'null'"
    )


@pytest.mark.plumbing
def test_json_pointer_true_leaf_hashes_literal_true_not_python_True() -> None:
    """A JSON ``true`` leaf under hash MUST HMAC over ``"true"``."""
    policy = RedactionPolicy.load(_hash_pointer_policy(["/flag"]))
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"flag": True})
    assert out == {"flag": _hmac_hex("true")}
    assert out["flag"] != _hmac_hex("True"), (
        "regression: HMAC computed over Python-coerced 'True' instead of "
        "the canonical literal 'true'"
    )


@pytest.mark.plumbing
def test_json_pointer_false_leaf_hashes_literal_false_not_python_False() -> None:
    """A JSON ``false`` leaf under hash MUST HMAC over ``"false"``."""
    policy = RedactionPolicy.load(_hash_pointer_policy(["/flag"]))
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"flag": False})
    assert out == {"flag": _hmac_hex("false")}
    assert out["flag"] != _hmac_hex("False")


@pytest.mark.plumbing
def test_json_pointer_int_leaf_hashes_str_int() -> None:
    """Sanity: a JSON integer leaf coerces via ``str`` on both sides and
    Py ``str(1) == "1"`` already matches JS ``String(1)``. No change
    here; this test pins the contract so a future change cannot break
    it without surfacing.
    """
    policy = RedactionPolicy.load(_hash_pointer_policy(["/n"]))
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"n": 42})
    assert out == {"n": _hmac_hex("42")}
