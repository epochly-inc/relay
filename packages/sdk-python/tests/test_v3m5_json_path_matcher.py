"""VAL-V3M5-018: KNOWN_MATCHER_KINDS includes 'json_path'.

The SDK accepts a third matcher kind, ``json_path``, alongside the existing
``regex`` and ``json_pointer`` kinds (spec G.3). The matcher's ``paths`` list
contains JSONPath selectors (RFC 9535 subset) of the form ``$.foo.bar`` and
``$.foo[N]``. A leaf whose path is selected by ANY of the matcher's selectors
fires the matcher's action (mirrors the json_pointer leaf-evaluation rule at
VAL-V2M08-025).

The minimal selector subset the SDK supports natively is:

  * ``$``                  -- the root (not useful at leaf-eval time)
  * ``$.<key>``            -- dotted child access
  * ``$.<key>.<key>``...   -- chained child access
  * ``$.<key>[N]``         -- array index access (decimal integer)
  * ``$.<key>[N].<key>``...-- chained mix

That subset is sufficient for VAL-V3M5-018 and the cross-runtime parity case.
Wildcards / filters / recursive descent (``..``) are NOT required by the
assertion and remain out of scope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay.redaction import RedactionEngine, RedactionPolicy

_TENANT_SALT = b"test-tenant-salt-v3m5-f08-do-not-use-in-prod"


def _salt_provider(salt_ref: str) -> bytes:
    if salt_ref == "tenant_salt_v3m5_f08":
        return _TENANT_SALT
    raise KeyError(salt_ref)


def _build_policy(paths: list[str]) -> RedactionPolicy:
    return RedactionPolicy.load(
        {
            "schema_version": "relay.redaction.v1",
            "policy_version": "v3m5-f08.001",
            "raw_capture": False,
            "matchers": [
                {
                    "id": "json_path_redactor",
                    "kind": "json_path",
                    "paths": paths,
                    "action": "redact",
                },
            ],
            "action_policy": {
                "hash": {
                    "algorithm": "hmac-sha256",
                    "salt_ref": "tenant_salt_v3m5_f08",
                },
                "redact": {"placeholder": "<redacted-v3m5-f08>"},
                "drop": {"placeholder": None},
            },
        }
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-018")
def test_known_matcher_kinds_includes_json_path() -> None:
    """``json_path`` is a recognised matcher kind at policy load."""
    from relay.redaction import _KNOWN_MATCHER_KINDS

    assert "json_path" in _KNOWN_MATCHER_KINDS
    assert {"regex", "json_pointer", "json_path"} <= _KNOWN_MATCHER_KINDS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-018")
def test_json_path_selector_matches_nested_dict_path() -> None:
    """A ``$.foo.bar`` selector redacts the value at that nested path."""
    policy = _build_policy(["$.foo.bar"])
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"foo": {"bar": "SECRET", "baz": "keep"}})
    assert out == {"foo": {"bar": "<redacted-v3m5-f08>", "baz": "keep"}}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-018")
def test_json_path_selector_matches_array_index() -> None:
    """A ``$.foo[0]`` selector redacts the array-indexed leaf."""
    policy = _build_policy(["$.foo[0]"])
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"foo": ["SECRET", "keep1", "keep2"]})
    assert out == {"foo": ["<redacted-v3m5-f08>", "keep1", "keep2"]}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-018")
def test_json_path_selector_does_not_match_when_path_absent() -> None:
    """A selector whose path is not present passes through unchanged."""
    policy = _build_policy(["$.missing.path"])
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"foo": {"bar": "keep"}})
    assert out == {"foo": {"bar": "keep"}}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-018")
def test_json_path_selector_requires_non_empty_paths() -> None:
    """A ``json_path`` matcher without paths is rejected at load."""
    from relay.errors import RelayPolicyError

    with pytest.raises(RelayPolicyError) as exc:
        RedactionPolicy.load(
            {
                "schema_version": "relay.redaction.v1",
                "policy_version": "v3m5-f08.002",
                "raw_capture": False,
                "matchers": [
                    {
                        "id": "bad",
                        "kind": "json_path",
                        "paths": [],
                        "action": "redact",
                    },
                ],
                "action_policy": {
                    "hash": {
                        "algorithm": "hmac-sha256",
                        "salt_ref": "tenant_salt_v3m5_f08",
                    },
                    "redact": {"placeholder": "<redacted>"},
                    "drop": {"placeholder": None},
                },
            }
        )
    assert exc.value.details["reason"] == "json_paths_missing"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-018")
def test_json_path_cross_runtime_parity_corpus() -> None:
    """The Python engine produces the redaction output the TS parity corpus
    will assert byte-for-byte. Pinning the expected dict here lets the TS
    counterpart load the same fixture and compare.

    NOTE: The cross-runtime parity assertion is the redaction OUTPUT, not the
    selector parser implementation. The two runtimes may parse the selector
    string differently but MUST agree on the leaf the selector designates.
    """
    policy = _build_policy(["$.user.email", "$.tokens[0]"])
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {
        "user": {"email": "alice@example.com", "name": "Alice"},
        "tokens": ["sk-AAA", "sk-BBB"],
        "other": "untouched",
    }
    expected = {
        "user": {"email": "<redacted-v3m5-f08>", "name": "Alice"},
        "tokens": ["<redacted-v3m5-f08>", "sk-BBB"],
        "other": "untouched",
    }
    assert engine.redact(payload) == expected
