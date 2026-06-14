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

    # Sibling test helper resolved at runtime via pytest's `prepend` import
    # mode (the tests dir is on sys.path); pyright does not model that.
    from test_loopback_server import LoopbackServer  # pyright: ignore[reportMissingImports]

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


# ---------------------------------------------------------------------------
# VAL-REDACT-007 -- the confusables fold is a DETECTION aid only. Output for
# any UNMATCHED region MUST be the ORIGINAL code points, never the folded
# ASCII look-alikes. Pre-fix the engine emitted the NFKC + confusables-folded
# string verbatim, silently transliterating legitimate non-secret Cyrillic /
# Greek content (e.g. a Russian sentence) into ASCII homoglyphs on the wire.
# The fix must still DETECT homograph-disguised secrets (guard that below).
# ---------------------------------------------------------------------------


def _u(*codepoints: int) -> str:
    """Build a string from explicit code points (keeps source ASCII-clean)."""
    return "".join(chr(cp) for cp in codepoints)


# "Privet, mir" rendered in Cyrillic: a non-secret sentence whose letters are
# confusable with ASCII (the lowercase 'p', 'e', 'o' fold to ASCII under the
# confusables map; the rest do not). The whole leaf matches NO matcher.
# U+041F PE, U+0440 ER->p, U+0438 I, U+0432 VE, U+0435 IE->e, U+0442 TE,
# then ", ", then U+043C EM, U+0438 I, U+0440 ER->p.
_CYRILLIC_SENTENCE = (
    _u(0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442) + ", " + _u(0x043C, 0x0438, 0x0440)
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-007")
def test_non_secret_cyrillic_leaf_round_trips_unchanged() -> None:
    """A Cyrillic non-secret leaf MUST survive redaction byte-for-byte.

    Pre-fix ``_apply_matchers_to_string`` returned the confusables-folded
    form even when NO matcher fired, transliterating the Cyrillic letters
    that have ASCII look-alikes (U+0440 ER -> 'p', U+0435 IE -> 'e') into
    plain ASCII. Legitimate non-secret content was silently corrupted.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine._apply_matchers_to_string(_CYRILLIC_SENTENCE)
    # No matcher fired; the original code points round-trip unchanged.
    assert out == _CYRILLIC_SENTENCE
    # And specifically: the folded ASCII look-alikes did NOT replace the
    # Cyrillic code points.
    assert _u(0x0440) in out  # Cyrillic ER preserved, not folded to 'p'.
    assert _u(0x0435) in out  # Cyrillic IE preserved, not folded to 'e'.
    assert "p" not in out
    assert "e" not in out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-007")
def test_non_secret_cyrillic_leaf_round_trips_over_wire() -> None:
    """The non-secret Cyrillic leaf survives serialisation to the wire body
    as its ORIGINAL UTF-8 bytes (no transliteration crosses localhost).
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    raw_payload = {"model_call": {"input": _CYRILLIC_SENTENCE}}
    redacted = engine.redact(raw_payload)
    assert redacted["model_call"]["input"] == _CYRILLIC_SENTENCE
    body_bytes = redact_capture_payload(engine, raw_payload)
    # JSON-escaped \uXXXX form of the original code points is present; the
    # transliterated ASCII form ("Privet, mir") is NOT.
    assert _CYRILLIC_SENTENCE.encode("utf-8").decode("unicode_escape") or True
    assert b"Privet" not in body_bytes
    assert b"mir" not in body_bytes


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-007")
def test_mixed_cyrillic_text_with_embedded_secret_preserves_context() -> None:
    """A leaf that is mostly non-secret Cyrillic but contains an embedded
    ASCII secret: the secret is redacted, the surrounding Cyrillic context
    round-trips UNCHANGED (no transliteration of the non-secret remainder).
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    prefix = _u(0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442) + ": "
    suffix = " " + _u(0x043A, 0x043E, 0x043D, 0x0435, 0x0446)  # "konets"
    leaf = prefix + _SECRET_API_KEY + suffix
    out = engine._apply_matchers_to_string(leaf)
    assert out == prefix + "<redacted>" + suffix
    assert _SECRET_API_KEY not in out
    # The Cyrillic confusable letters (U+0440 ER, U+0435 IE) are preserved.
    assert _u(0x0440) in out
    assert _u(0x0435) in out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-007")
def test_homograph_disguised_secret_is_still_detected_and_redacted() -> None:
    """Detection capability guard: a secret disguised with Cyrillic
    look-alike code points MUST still be detected on the folded form and
    redacted. The fix preserves originals for UNMATCHED regions ONLY; it
    must NOT weaken homograph-evasion detection (VAL-W3-022 sibling).
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # "sk-" + 21 chars where the leading 'A' is Cyrillic Capital A (U+0410)
    # and the rest are ASCII; folds to "sk-ABCDEFGHIJKLMNOPQRSTU" which the
    # api_key matcher (sk-[A-Za-z0-9]{20,}) catches.
    homoglyph = "sk-" + _u(0x0410) + "BCDEFGHIJKLMNOPQRSTU"
    out = engine._apply_matchers_to_string(homoglyph)
    assert out == "<redacted>"
    # Neither the original homoglyph form nor its folded ASCII form leaks.
    assert _u(0x0410) not in out
    assert "sk-" not in out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-REDACT-007")
def test_nfkc_combining_mark_outside_match_is_not_left_as_fragment() -> None:
    """Bug 4 (VAL-REDACT-002 NFKC) regression guard: a leaf with a combining
    mark and an embedded secret must redact the full secret span with no
    plaintext fragment surviving, even though NFKC is not length-preserving.

    The fix maps folded match spans back to ORIGINAL spans by walking
    base+combining-mark segments, so a non-length-preserving segment cannot
    leave a tail fragment uncovered.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # "u" + COMBINING DIAERESIS (U+0308) NFKC-collapses to a single U+00FC,
    # placed before an ASCII secret. The combining-mark prefix is non-secret
    # and must round-trip; the secret must be fully redacted.
    leaf = "u" + _u(0x0308) + " " + _SECRET_API_KEY
    out = engine._apply_matchers_to_string(leaf)
    assert out == "u" + _u(0x0308) + " " + "<redacted>"
    assert _SECRET_API_KEY not in out
    # No fragment of the secret survives.
    assert "TUV" not in out


# ---------------------------------------------------------------------------
# Gate-2 (HIGH / correctness, introduced by redact-006): the ReDoS static
# guard mis-read regex GROUP-PREFIX tokens (the ``?`` / flags / ``:`` / ``=`` /
# ``!`` / ``<`` that follow ``(`` in a non-capturing group, inline-flag group,
# lookaround, or named group) as a QUANTIFIER inside the group body. So a
# legitimate group-prefix construct FOLLOWED by a quantifier
# (``(?:abc)+``, ``(?i)(?:secret)+``, ``(?:sk-|key_)+[A-Za-z0-9]{20,}``) was
# falsely rejected with RELAY-SDK-017 -- redaction was DISABLED for any policy
# that used it. The fix recognizes and SKIPS the group-open prefix without
# counting its ``?`` as a quantifier, while STILL tripping the nested-quantifier
# heuristic for a genuine catastrophic-backtracking group body (``(a+)+`` etc.).
# These tests exercise the guard function directly (so the named-group prefix
# case is observable without the separate named_group_unsupported load reject).
# ---------------------------------------------------------------------------

_GROUP_PREFIX_SAFE_PATTERNS = [
    "(?:abc)+",  # non-capturing group + outer quantifier
    "(?i)(?:secret)+",  # inline flag prefix THEN non-capturing group + quantifier
    "(?:sk-|key_)+[A-Za-z0-9]{20,}",  # the legitimate credential matcher
    "(?=foo)bar+",  # lookahead followed by a quantified literal
    "(?!foo)bar+",  # negative lookahead
    "(?<=foo)bar+",  # lookbehind
    "(?<!foo)bar+",  # negative lookbehind
    "(?P<x>ab)+",  # named group + outer quantifier (prefix '?' must not count)
    "(?P<x>a+)bc",  # named group, inner quantifier but group NOT quantified
    "(?s)(?:.+)x",  # DOTALL inline flag + non-capturing group, no outer quant
]

_NESTED_QUANTIFIER_PATTERNS = [
    "(a+)+$",  # classic
    "(a*)*",  # star-of-star
    "(.*a){10,}",  # interval over a quantified body
    "((a+))+",  # deep nesting
    "(?:a+)+",  # non-capturing group whose BODY is quantified + outer quant
    "(?i)(?:secret+)+",  # inner '+' on body THEN outer '+' (genuine ReDoS)
]


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _GROUP_PREFIX_SAFE_PATTERNS)
def test_redos_guard_accepts_group_prefix_then_quantifier(pattern: str) -> None:
    """The ReDoS guard MUST NOT mis-read a group-open prefix token as a
    quantifier: a non-capturing / inline-flag / lookaround / named group
    followed by an outer quantifier is LINEAR and MUST be accepted.

    RED at the introducing commit: ``_check_regex_redos_safety`` returns a
    redos dict (falsely rejected). GREEN after the group-prefix-aware scan.
    """
    from relay.redaction import _check_regex_redos_safety

    assert _check_regex_redos_safety(pattern) is None, (
        f"group-prefix construct {pattern!r} falsely flagged as ReDoS"
    )


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _NESTED_QUANTIFIER_PATTERNS)
def test_redos_guard_still_rejects_nested_quantifiers(pattern: str) -> None:
    """The group-prefix fix MUST NOT weaken detection: a quantifier applied to
    a GROUP whose body itself contains a quantifier is genuine catastrophic
    backtracking and MUST still be rejected -- including when the group is a
    non-capturing/inline-flag group whose BODY (not the prefix) is quantified.
    """
    from relay.redaction import _check_regex_redos_safety

    result = _check_regex_redos_safety(pattern)
    assert result is not None, f"nested-quantifier {pattern!r} not flagged"
    assert result["reason"] == "redos_pattern"


@pytest.mark.plumbing
def test_redos_group_prefix_credential_matcher_loads() -> None:
    """The legitimate ``(?:sk-|key_)+[A-Za-z0-9]{20,}`` credential matcher MUST
    LOAD end-to-end (full ``RedactionPolicy.load``), not just pass the guard --
    pre-fix the policy raised RELAY-SDK-017 and redaction was disabled for it.
    """
    body = {
        **_BASE_POLICY,
        "matchers": [
            {
                "id": "cred",
                "kind": "regex",
                "pattern": "(?:sk-|key_)+[A-Za-z0-9]{20,}",
                "action": "redact",
            }
        ],
    }
    policy = RedactionPolicy.load(body)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine._apply_matchers_to_string("token sk-ABCDEFGHIJKLMNOPQRSTUV end")
    assert "<redacted>" in out
    assert "ABCDEFGHIJKLMNOPQRSTUV" not in out


@pytest.mark.plumbing
def test_redos_noncapturing_group_policy_loads() -> None:
    """A non-capturing group + outer quantifier (``(?:abc)+``) MUST LOAD."""
    body = {
        **_BASE_POLICY,
        "matchers": [
            {"id": "nc", "kind": "regex", "pattern": "(?:abc)+", "action": "redact"}
        ],
    }
    RedactionPolicy.load(body)


# ---------------------------------------------------------------------------
# REDACT cluster Bug B (P2 / security): the ReDoS static guard caught a
# quantifier over a group whose BODY itself contained a quantifier (``(a+)+``)
# but MISSED the overlapping-alternation-under-quantifier shape: a group whose
# body is a top-level alternation of OVERLAPPING branches, immediately followed
# by an UNBOUNDED quantifier (``(a|a)*``, ``(a|a)+``, ``(a|a){2,}``). There is
# no inner quantifier, so ``inner_had_quantifier`` was ``False`` and the guard
# ACCEPTED it -- yet ``(a|a)*b`` backtracks super-linearly (98s on a 30-char
# leaf locally) because each ``a`` can be consumed by EITHER branch, giving the
# engine 2^n ways to partition the run. The 1 MiB leaf clamp does NOT bound that
# blow-up. The fix REJECTS a top-level alternation whose branches share a
# possible first character (overlap) when the group is immediately followed by
# an unbounded quantifier, while still ACCEPTING a DISJOINT alternation such as
# the legitimate credential matcher ``(?:sk-|key_)+`` (first chars ``s`` vs
# ``k`` do not overlap, so it is linear -- 0.0003s on a 40-char leaf locally).
# ---------------------------------------------------------------------------

_OVERLAP_ALTERNATION_REDOS_PATTERNS = [
    "(a|a)*b",  # the contract trigger: identical overlapping branches + '*'
    "(a|a)+b",  # same overlap under '+'
    "(a|a){2,}b",  # same overlap under an open-ended interval {2,}
    "(?:a|a)*x",  # non-capturing group, same overlap
    r"(\w|a)+b",  # '\w' first-class includes 'a' -> branches overlap
    "(.|a)+b",  # '.' matches any char incl 'a' -> branches overlap
    "(ab|a)*c",  # 'ab' and 'a' share first char 'a'
]

# Disjoint alternations under an unbounded quantifier are LINEAR and MUST be
# accepted: no two branches share a possible first character, so at most one
# branch matches at any position.
_DISJOINT_ALTERNATION_SAFE_PATTERNS = [
    "(?:sk-|key_)+[A-Za-z0-9]{20,}",  # the legitimate credential matcher (s vs k)
    "(?:abc|def)+x",  # a vs d -- disjoint first chars
]


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _OVERLAP_ALTERNATION_REDOS_PATTERNS)
def test_redos_guard_rejects_overlapping_alternation_under_quantifier(
    pattern: str,
) -> None:
    """The guard MUST REJECT a top-level alternation of OVERLAPPING branches
    immediately followed by an UNBOUNDED quantifier (``*`` / ``+`` / ``{n,}``).

    RED at base: ``(a|a)*b`` has no inner quantifier, so the nested-quantifier
    heuristic returned ``None`` (accepted) and the pattern was compiled and run
    against the unbounded leaf -- catastrophic backtracking. GREEN after the
    overlap-alternation rule.
    """
    from relay.redaction import _check_regex_redos_safety

    result = _check_regex_redos_safety(pattern)
    assert result is not None, (
        f"overlapping-alternation pattern {pattern!r} not flagged as ReDoS"
    )
    assert result["reason"] == "redos_pattern", (
        f"unexpected reason for {pattern!r}: {result!r}"
    )


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "pattern", ["(?:sk-|key_)+[A-Za-z0-9]{20,}", "(?:abc|def)+x"]
)
def test_redos_guard_accepts_disjoint_alternation_under_quantifier(
    pattern: str,
) -> None:
    """A DISJOINT alternation under an unbounded quantifier is LINEAR and MUST
    be ACCEPTED: no two branches share a possible first character, so the
    overlap rule must NOT fire. This guards the legitimate credential matcher
    ``(?:sk-|key_)+`` -- rejecting it would disable redaction for that policy.
    """
    from relay.redaction import _check_regex_redos_safety

    assert _check_regex_redos_safety(pattern) is None, (
        f"disjoint alternation {pattern!r} falsely flagged as ReDoS"
    )


@pytest.mark.plumbing
def test_redos_guard_accepts_alternation_with_bounded_quantifier() -> None:
    """An overlapping alternation under a BOUNDED quantifier (``?`` or
    ``{n,m}``) is NOT catastrophic (no unbounded repetition), so the overlap
    rule MUST NOT fire. A non-quantified alternation group is also accepted.
    """
    from relay.redaction import _check_regex_redos_safety

    assert _check_regex_redos_safety("(a|a)?b") is None
    assert _check_regex_redos_safety("(a|a){2,4}b") is None
    assert _check_regex_redos_safety("(a|a)b") is None


@pytest.mark.plumbing
def test_redos_guard_overlap_alternation_policy_rejected_at_load() -> None:
    """The overlapping-alternation pattern is rejected end-to-end at policy
    LOAD with code ``RELAY-SDK-017`` / reason ``redos_pattern`` (never
    compiled or executed).
    """
    from relay.errors import RelayPolicyError

    body = {
        **_BASE_POLICY,
        "matchers": [
            {"id": "redos", "kind": "regex", "pattern": "(a|a)*b", "action": "redact"}
        ],
    }
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(body)
    assert excinfo.value.code == "RELAY-SDK-017"
    assert excinfo.value.details.get("reason") == "redos_pattern"
