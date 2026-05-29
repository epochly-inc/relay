"""W3.3 SDK-side redaction at the trace boundary.

This test module covers VAL-W3-020 through VAL-W3-028. Per CLAUDE.md
keystone invariant #7 (default-deny raw capture) and spec G, the SDK
redacts every trace-bound field BEFORE any HTTP body is written. The
redacted body is what crosses localhost; plaintext never does on the
default policy.

The tests use the W3.2 test loopback server fixture to assert wire-
format bytes; the redaction module itself is exercised in isolation
where the assertion does not require the HTTP boundary.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import hmac

import pytest
from relay.errors import RelayPolicyError
from relay.redaction import (
    DEFAULT_APPLIES_TO_FIELDS,
    RedactionEngine,
    RedactionPolicy,
    redact_capture_payload,
)

# A canonical valid v1 redaction policy used as the test baseline. The
# matcher set mirrors the spec G.2 example but is pared back to the
# regex matchers the SDK enforces directly.
_BASE_POLICY: dict = {
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
            "pattern": "[\\w.+-]+@[\\w-]+\\.[\\w.-]+",
            "action": "hash",
        },
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_v3"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
    "applies_to_fields": list(DEFAULT_APPLIES_TO_FIELDS),
}

# A deterministic test salt the engine resolves for ``tenant_salt_v3``.
# Tests use this to assert HMAC golden values (VAL-W3-028).
_TENANT_SALT = b"test-tenant-salt-v3-do-not-use-in-prod"

_SECRET_API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUV"  # noqa: S105 - test fixture


def _salt_provider(salt_ref: str) -> bytes:
    """Resolve a salt_ref to bytes for the test suite only."""
    if salt_ref == "tenant_salt_v3":
        return _TENANT_SALT
    raise KeyError(salt_ref)


# ---------------------------------------------------------------------------
# VAL-W3-020 / VAL-W3-021 -- secret never crosses the localhost boundary
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-020")
def test_secret_in_model_call_prompt_is_redacted_before_http_body() -> None:
    """A known secret in ``model_call.input`` is redacted before the
    payload is serialised for HTTP transmission.

    The SDK never produces an HTTP body containing the literal seeded
    secret; the captured payload bytes contain only the placeholder.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    raw_payload = {
        "schema_version": "relay.trace.event.v1",
        "kind": "model_call",
        "model_call": {
            "input": f"my key is {_SECRET_API_KEY}",
            "output": "ok",
        },
    }
    body_bytes = redact_capture_payload(engine, raw_payload)
    assert _SECRET_API_KEY.encode("utf-8") not in body_bytes
    assert b"<redacted>" in body_bytes


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-021")
def test_same_matcher_catches_secret_across_all_applies_to_fields() -> None:
    """The same matcher set is applied across model_call.input/output,
    tool_call.args/result, and retrieval.documents. Zero occurrences of
    the seeded secret in the final body across all five surfaces.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    raw_payload = {
        "schema_version": "relay.trace.event.v1",
        "model_call": {
            "input": f"prompt {_SECRET_API_KEY}",
            "output": f"echo {_SECRET_API_KEY}",
        },
        "tool_call": {
            "args": {"q": f"see {_SECRET_API_KEY}"},
            "result": {"text": f"got {_SECRET_API_KEY}"},
        },
        "retrieval": {
            "documents": [
                {"text": f"doc-a contains {_SECRET_API_KEY}"},
                {"text": "doc-b is clean"},
            ],
        },
    }
    body_bytes = redact_capture_payload(engine, raw_payload)
    assert _SECRET_API_KEY.encode("utf-8") not in body_bytes
    # All five surfaces were redacted -- count placeholders.
    assert body_bytes.count(b"<redacted>") >= 5


# ---------------------------------------------------------------------------
# VAL-W3-022 -- Unicode homoglyph normalisation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-022")
def test_unicode_homoglyph_variant_is_redacted() -> None:
    """A Cyrillic-A homoglyph variant of the API key is still redacted
    after NFKC + confusables-map normalisation.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # Cyrillic Capital Letter A (U+0410) replaces the ASCII 'A' in the
    # seeded API key. The pattern is sk-[A-Za-z0-9]{20,}; the engine
    # must normalise the Cyrillic A back to ASCII before matching.
    homoglyph = "sk-АBCDEFGHIJKLMNOPQRSTU"
    raw_payload = {
        "model_call": {"input": f"my key is {homoglyph}"},
    }
    body_bytes = redact_capture_payload(engine, raw_payload)
    # Neither the original homoglyph form NOR the ASCII-normalised form
    # of the literal string appears in the body.
    assert homoglyph.encode("utf-8") not in body_bytes
    assert b"sk-ABCDEFGHIJKLMNOPQRSTU" not in body_bytes
    assert b"<redacted>" in body_bytes


# ---------------------------------------------------------------------------
# VAL-W3-023 -- mixed-encoding retrieval document
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-023")
def test_mixed_encoding_retrieval_document_is_digested_not_decoded() -> None:
    """A retrieval document arrives as raw bytes. Per CLAUDE.md keystone
    invariant #7 (default-deny raw capture) and parity with TS
    ``walk`` (``packages/sdk-typescript/src/redaction.ts:789-794``),
    raw bytes leaves are replaced by a ``{"_digest_sha256": "<hex>"}``
    reference; the engine MUST NOT decode bytes through a UTF-8
    ``errors='replace'`` path and then run string matchers, because
    plaintext survives whenever no matcher fires on the decoded form
    (Bug 2 P0).

    Test pins the digest expectation so the bytes-handling path is
    proven byte-stable, and asserts that no fragment of the original
    bytes (including the seeded secret) survives in the wire body.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # Construct mixed-encoding bytes containing a seeded API key.
    bad_bytes = (
        b"first paragraph "
        + b"\xe9"
        + f" second paragraph contains {_SECRET_API_KEY} end.".encode()
    )
    expected_digest = hashlib.sha256(bad_bytes).hexdigest()
    raw_payload = {
        "retrieval": {
            "documents": [{"bytes": bad_bytes}],
        },
    }
    redacted = engine.redact(raw_payload)
    assert redacted["retrieval"]["documents"][0]["bytes"] == {
        "_digest_sha256": expected_digest
    }
    body_bytes = redact_capture_payload(engine, raw_payload)
    # Neither the plaintext secret nor the surrounding decoded form
    # appears in the wire body.
    assert _SECRET_API_KEY.encode("utf-8") not in body_bytes
    assert b"first paragraph" not in body_bytes
    assert b"second paragraph" not in body_bytes
    # The digest hex is the only representation that survives.
    assert expected_digest.encode("ascii") in body_bytes


# ---------------------------------------------------------------------------
# VAL-W3-024 -- determinism across calls
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-024")
def test_redaction_deterministic_for_same_policy_version_and_salt_ref() -> None:
    """Two calls capturing the same plaintext under the same policy
    version produce byte-identical redacted output. Identical SHA-256
    of the redacted ingest body across runs.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine_a = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    engine_b = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    raw_payload = {
        "model_call": {"input": f"email me at alice@example.com and use {_SECRET_API_KEY}"},
    }
    body_a = redact_capture_payload(engine_a, raw_payload)
    body_b = redact_capture_payload(engine_b, raw_payload)
    assert hashlib.sha256(body_a).hexdigest() == hashlib.sha256(body_b).hexdigest()
    # Plaintext absent in both.
    assert _SECRET_API_KEY.encode("utf-8") not in body_a
    assert b"alice@example.com" not in body_a


# ---------------------------------------------------------------------------
# VAL-W3-025 -- policy parse error fails closed
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-025")
def test_malformed_regex_raises_relay_policy_error_at_load() -> None:
    """A malformed regex matcher raises RelayPolicyError on policy load.
    The SDK MUST NOT proceed; the caller never gets a partially-redacted
    payload.
    """
    bad_policy = {**_BASE_POLICY}
    bad_policy["matchers"] = [
        {
            "id": "bad",
            "kind": "regex",
            "pattern": "(unterminated[",
            "action": "redact",
        }
    ]
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(bad_policy)
    assert excinfo.value.error_class == "RELAY-SDK-POLICY-INVALID"
    assert excinfo.value.code == "RELAY-SDK-010"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-025")
def test_unknown_matcher_kind_raises_relay_policy_error() -> None:
    """Unknown matcher ``kind`` fails closed at load."""
    bad_policy = {**_BASE_POLICY}
    bad_policy["matchers"] = [
        {"id": "x", "kind": "telepathy", "pattern": "x", "action": "redact"}
    ]
    with pytest.raises(RelayPolicyError):
        RedactionPolicy.load(bad_policy)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-025")
def test_unknown_action_raises_relay_policy_error() -> None:
    """Unknown matcher ``action`` fails closed at load."""
    bad_policy = {**_BASE_POLICY}
    bad_policy["matchers"] = [
        {"id": "x", "kind": "regex", "pattern": "x", "action": "obliterate"}
    ]
    with pytest.raises(RelayPolicyError):
        RedactionPolicy.load(bad_policy)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-025")
def test_missing_required_field_raises_relay_policy_error() -> None:
    """A policy missing ``schema_version`` fails closed at load."""
    bad_policy = {**_BASE_POLICY}
    del bad_policy["schema_version"]
    with pytest.raises(RelayPolicyError):
        RedactionPolicy.load(bad_policy)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-025")
def test_wrong_schema_version_raises_relay_policy_error() -> None:
    """A policy with the wrong ``schema_version`` literal fails closed."""
    bad_policy = {**_BASE_POLICY, "schema_version": "relay.redaction.v0"}
    with pytest.raises(RelayPolicyError):
        RedactionPolicy.load(bad_policy)


# ---------------------------------------------------------------------------
# VAL-W3-026 -- raw_capture without DPA + approver is refused
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-026")
def test_raw_capture_true_without_dpa_ref_is_refused() -> None:
    """raw_capture=true with dpa_ref=None is refused by the SDK at policy
    load. The SDK does not rely solely on the sidecar to reject; it
    refuses to even attempt.
    """
    bad_policy = {
        **_BASE_POLICY,
        "raw_capture": True,
        "dpa_ref": None,
        "approver_user_id": "8c7c2ec6-3a2b-4dba-9d36-5d8c2c1f64ed",
    }
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(bad_policy)
    assert "RAW-CAPTURE" in excinfo.value.details.get("reason", "").upper()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-026")
def test_raw_capture_true_without_approver_is_refused() -> None:
    """raw_capture=true with approver_user_id=None is refused."""
    bad_policy = {
        **_BASE_POLICY,
        "raw_capture": True,
        "dpa_ref": "dpa-12345",
        "approver_user_id": None,
    }
    with pytest.raises(RelayPolicyError):
        RedactionPolicy.load(bad_policy)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-026")
def test_raw_capture_true_with_both_dpa_and_approver_loads_cleanly() -> None:
    """A correctly-attested raw_capture policy DOES load. The SDK still
    redacts matched fields; raw_capture only changes what hosted Relay
    is permitted to persist, not whether the SDK applies matchers.
    """
    ok_policy = {
        **_BASE_POLICY,
        "raw_capture": True,
        "dpa_ref": "dpa-2026-05-12",
        "approver_user_id": "8c7c2ec6-3a2b-4dba-9d36-5d8c2c1f64ed",
    }
    policy = RedactionPolicy.load(ok_policy)
    assert policy.raw_capture is True
    assert policy.dpa_ref == "dpa-2026-05-12"


# ---------------------------------------------------------------------------
# VAL-W3-027 -- defense-in-depth sidecar rejection of raw payload
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-027")
def test_sidecar_rejects_raw_payload_via_mock_endpoint() -> None:
    """If a forged SDK bypass path emits a raw payload, the sidecar
    rejects with HTTP 422 + RELAY-ING-RAW-PAYLOAD. The SDK surfaces the
    error as a typed RelayPolicyError (the redaction-policy class).

    Test uses the W3.2 LoopbackServer as a mock sidecar that implements
    the validating ingest route. This is the SDK-side defense-in-depth
    check; the in-process sidecar's full ingest validator lands later.
    """
    from relay.errors import RELAY_ING_RAW_PAYLOAD_CODE
    from relay.run import _LifecycleHTTPClient
    from test_loopback_server import LoopbackServer

    server = LoopbackServer()
    server.add_route(
        "POST",
        "/v1/ingest/runs",
        lambda req: (
            422,
            {
                "schema_version": "relay.error.v1",
                "code": RELAY_ING_RAW_PAYLOAD_CODE,
                "error_class": "RELAY-ING-RAW-PAYLOAD",
                "message": "raw plaintext field detected; redaction policy violated",
                "retry_advice": {"mode": "no_retry"},
                "details": {},
            },
            {},
        ),
    )
    server.start()
    try:
        from relay.errors import RelayPolicyError as PolicyErr

        client = _LifecycleHTTPClient(base_url=server.base_url)
        forged_envelope = {
            "schema_version": "relay.ingest.run.v1",
            # A forged payload containing a literal plaintext API key
            # that SHOULD have been redacted.
            "raw_field": _SECRET_API_KEY,
        }
        try:
            with pytest.raises(PolicyErr) as excinfo:
                client.post_ingest_run(forged_envelope)
            assert excinfo.value.code == "RELAY-SDK-010"
            assert (
                excinfo.value.details.get("code")
                == RELAY_ING_RAW_PAYLOAD_CODE
            )
        finally:
            client.close()
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# VAL-W3-028 -- HMAC-SHA-256 for hash matchers with per-tenant salt
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-028")
def test_hash_matcher_emits_hmac_sha256_with_salt() -> None:
    """For matchers with action=hash, the SDK MUST emit
    HMAC-SHA-256(salt_value_for(salt_ref), plaintext). Test pins a
    known plaintext and salt and asserts the golden HMAC output.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    plaintext_email = "alice@example.com"
    raw_payload = {
        "model_call": {"input": f"please email me at {plaintext_email}"},
    }
    body_bytes = redact_capture_payload(engine, raw_payload)
    # The matcher acts on the NFKC-normalised form; the email is ASCII
    # so the normalised form equals the original.
    expected_hmac = hmac.new(
        _TENANT_SALT, plaintext_email.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert expected_hmac.encode("utf-8") in body_bytes
    # NOT a plain SHA-256.
    plain_sha = hashlib.sha256(plaintext_email.encode("utf-8")).hexdigest()
    assert plain_sha.encode("utf-8") not in body_bytes
    # Plaintext absent.
    assert plaintext_email.encode("utf-8") not in body_bytes


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-028")
def test_hash_matcher_uses_distinct_salt_for_distinct_salt_ref() -> None:
    """Two policies with different salt_ref produce distinct HMACs for
    the same plaintext. This proves the salt is actually flowing into
    the HMAC computation (not statically baked in).
    """
    policy_a = RedactionPolicy.load(_BASE_POLICY)
    policy_b_body = {
        **_BASE_POLICY,
        "action_policy": {
            **_BASE_POLICY["action_policy"],
            "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_alt"},
        },
    }
    policy_b = RedactionPolicy.load(policy_b_body)

    def _salt_two(salt_ref: str) -> bytes:
        if salt_ref == "tenant_salt_v3":
            return _TENANT_SALT
        if salt_ref == "tenant_salt_alt":
            return b"alt-salt-value-bytes-for-test"
        raise KeyError(salt_ref)

    engine_a = RedactionEngine(policy=policy_a, salt_provider=_salt_two)
    engine_b = RedactionEngine(policy=policy_b, salt_provider=_salt_two)
    raw = {"model_call": {"input": "alice@example.com"}}
    body_a = redact_capture_payload(engine_a, raw)
    body_b = redact_capture_payload(engine_b, raw)
    assert body_a != body_b


# ---------------------------------------------------------------------------
# VAL-REDACT-002 -- overlapping spans must be merged into their interval
# union; the unredacted tail of a longer overlapping match MUST NOT leak.
# ---------------------------------------------------------------------------

# Two regex matchers whose spans overlap such that the LATER-sorted span
# starts inside the earlier (kept) span but extends BEYOND its end. On the
# input "alphabravosecret":
#   * matcher "left"  matches "alphabra"    -> span [0, 8)
#   * matcher "right" matches "bravosecret" -> span [5, 16)
# Sort key (start, -end) keeps "left" (start 0); the pre-fix skip-on-overlap
# branch drops "right" entirely because 5 < 8, splicing normalised[8:]
# ("secret") back in as plaintext -- leaking the tail of a matched secret.
_OVERLAP_POLICY: dict = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "2026-05-29.overlap",
    "raw_capture": False,
    "retention_days": 30,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {"id": "left", "kind": "regex", "pattern": "alphabra", "action": "redact"},
        {"id": "right", "kind": "regex", "pattern": "bravosecret", "action": "redact"},
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_v3"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
    "applies_to_fields": list(DEFAULT_APPLIES_TO_FIELDS),
}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-002")
def test_overlapping_spans_merge_to_union_no_tail_leak() -> None:
    """When a later overlapping span extends past the kept span's end,
    the engine MUST redact the full interval union, never emit the tail.

    Pre-fix the skip-on-overlap branch dropped the longer span and the
    bytes between the two ends ("secret") survived in plaintext.
    """
    policy = RedactionPolicy.load(_OVERLAP_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # Direct string-level assertion against the merge logic.
    out = engine._apply_matchers_to_string("alphabravosecret")
    # The full union [0, 16) is one redaction; no residual plaintext.
    assert out == "<redacted>"
    assert "secret" not in out
    assert "bravo" not in out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-002")
def test_overlapping_spans_tail_never_crosses_http_boundary() -> None:
    """The unredacted tail of an overlapping match MUST NOT appear in the
    serialised wire body (keystone invariant #7: plaintext never crosses).
    """
    policy = RedactionPolicy.load(_OVERLAP_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    raw_payload = {"model_call": {"input": "alphabravosecret"}}
    body_bytes = redact_capture_payload(engine, raw_payload)
    # Neither the leaked tail nor any matched fragment survives.
    assert b"secret" not in body_bytes
    assert b"bravo" not in body_bytes
    assert b"alpha" not in body_bytes
    assert b"<redacted>" in body_bytes
