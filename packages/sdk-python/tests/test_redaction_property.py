"""Property-based tests for SDK-side redaction (ACCEPTANCE GATE #1,
formal-methods). Keystone invariant #7: redaction NEVER leaks a matched
secret + is idempotent + deterministic, and the interval-union/overlap-merge
(VAL-REDACT-002) never reintroduces a matched byte in the gap between two
overlapping spans.

These are the universally-quantified counterpart to the example-based suites
(``test_redaction.py`` / ``test_redaction_parity.py``): the examples prove
specific inputs redact; these properties prove the structural invariants over a
Hypothesis-generated domain of secret-bearing payloads.

Properties encoded (over generated text + a redaction policy that WILL match):

  1. NO-LEAK (redact action): a generated ``sk-``/``key_`` secret token embedded
     in generated benign text NEVER survives verbatim in the wire bytes.
  2. NO-LEAK (hash action): a generated email token NEVER survives verbatim
     (it is replaced by an HMAC-SHA-256 digest).
  3. NO-LEAK (json_pointer): the hosted-default policy redacts every
     ``messages[*].content.text`` leaf so the prompt content never leaks.
  4. IDEMPOTENCE: ``redact(redact(x)) == redact(x)`` -- the redacted form is a
     fixed point (placeholder + HMAC digest + bytes-digest are never re-matched).
  5/6. INTERVAL-UNION / OVERLAP (VAL-REDACT-002): when two matched spans overlap
     (tail-beyond AND full-containment shapes), the output contains a SINGLE
     merged replacement and NO matched byte survives in the gap.
  7. DETERMINISM: ``redact(x) == redact(x)`` (dict form, stable).
  8. DETERMINISM (wire): ``redact_capture_payload(x)`` is stable across calls.
  9. DETERMINISM (independent engines): two engines built from the same policy +
     salt provider emit byte-identical wire output for the same input (spec G.3).

The public entrypoints exercised are :func:`relay.redaction.redact_capture_payload`
(payload dict -> canonical JSON wire bytes) and
:meth:`relay.redaction.RedactionEngine.redact` (payload dict -> redacted dict).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from relay.redaction import (
    HOSTED_DEFAULT_POLICY,
    RedactionEngine,
    RedactionPolicy,
    redact_capture_payload,
)

# ---------------------------------------------------------------------------
# Policies + salt provider. All deterministic; no IO.
# ---------------------------------------------------------------------------

# A redact-action secret matcher (mirrors the canonical base policy's api_key
# matcher) plus a hash-action email matcher. A generated token built to satisfy
# either pattern is GUARANTEED to be matched, so a verbatim survival is a leak.
_REDACT_HASH_POLICY_BODY: dict[str, Any] = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "prop-test.redact-hash.v1",
    "raw_capture": False,
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
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
}

# Two overlapping redact matchers. On input "SK<core>TK" (core = digits):
#   left  "SK[0-9]+"  matches "SK<core>"   spanning [p, p+2+len(core))
#   right "[0-9]+TK"  matches "<core>TK"   spanning [p+2, p+2+len(core)+2)
# The spans OVERLAP by len(core) and the right span's TAIL ("TK") extends
# beyond the left span's end -- the exact VAL-REDACT-002 leak shape. A correct
# interval-union merges them into one placeholder; the pre-fix bug spliced the
# "TK" tail back in as plaintext.
_OVERLAP_TAIL_POLICY_BODY: dict[str, Any] = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "prop-test.overlap-tail.v1",
    "raw_capture": False,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {"id": "left", "kind": "regex", "pattern": "SK[0-9]+", "action": "redact"},
        {"id": "right", "kind": "regex", "pattern": "[0-9]+TK", "action": "redact"},
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
}

# Containment shape: outer "SK[0-9A-Z]+" matches the WHOLE "SK<core>TK"; inner
# "[0-9]+" matches just <core>, fully contained in outer. Exercises the merge's
# max(end) branch (a contained later span must NOT shrink the redacted range).
_OVERLAP_CONTAIN_POLICY_BODY: dict[str, Any] = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "prop-test.overlap-contain.v1",
    "raw_capture": False,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {"id": "outer", "kind": "regex", "pattern": "SK[0-9A-Z]+", "action": "redact"},
        {"id": "inner", "kind": "regex", "pattern": "[0-9]+", "action": "redact"},
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
}

_TENANT_SALT = b"prop-test-tenant-salt-do-not-use-in-prod"


def _salt_provider(salt_ref: str) -> bytes:
    if salt_ref == "tenant_salt":
        return _TENANT_SALT
    raise KeyError(salt_ref)


def _redact_hash_engine() -> RedactionEngine:
    return RedactionEngine(
        policy=RedactionPolicy.load(_REDACT_HASH_POLICY_BODY),
        salt_provider=_salt_provider,
    )


def _overlap_tail_engine() -> RedactionEngine:
    return RedactionEngine(
        policy=RedactionPolicy.load(_OVERLAP_TAIL_POLICY_BODY),
        salt_provider=_salt_provider,
    )


def _overlap_contain_engine() -> RedactionEngine:
    return RedactionEngine(
        policy=RedactionPolicy.load(_OVERLAP_CONTAIN_POLICY_BODY),
        salt_provider=_salt_provider,
    )


def _hosted_default_engine() -> RedactionEngine:
    return RedactionEngine(
        policy=RedactionPolicy.load(HOSTED_DEFAULT_POLICY),
        salt_provider=lambda _ref: b"hosted-default-salt-prop",
    )


# ---------------------------------------------------------------------------
# Generation strategies.
# ---------------------------------------------------------------------------

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_DIGITS = "0123456789"

# A secret the api_key matcher ALWAYS matches: a fixed prefix + >= 20 alnum
# (the {20,} quantifier is satisfied by construction).
_secret_token = st.builds(
    lambda pfx, body: pfx + body,
    st.sampled_from(("sk-", "key_")),
    st.text(alphabet=_ALNUM, min_size=20, max_size=40),
)

# An email the email matcher ALWAYS matches: alnum local + alnum domain + a
# lowercase tld (>= 2 chars). No char here needs JSON escaping, so the raw
# bytes of the token can be searched for directly in the wire body.
_email_token = st.builds(
    lambda local, domain, tld: local + "@" + domain + "." + tld,
    st.text(alphabet=_ALNUM, min_size=1, max_size=10),
    st.text(alphabet=_ALNUM, min_size=1, max_size=10),
    st.text(alphabet=_LOWER, min_size=2, max_size=5),
)

# Benign surrounding text for the NO-LEAK tests: rich Unicode but with "<" / ">"
# excluded so the placeholder "<redacted>" can never appear in the benign text
# itself -- asserting the placeholder is present then proves the matcher fired
# (the test is not vacuous) without weakening the leak assertion. Lone
# surrogates (category Cs) are excluded (invalid in UTF-8 / JSON).
_benign_fill = st.text(
    st.characters(blacklist_categories=("Cs",), blacklist_characters="<>"),
    max_size=24,
)

# General-purpose benign text for the idempotence / determinism payloads.
_benign_text = st.text(st.characters(blacklist_categories=("Cs",)), max_size=20)

# Simple ASCII keys (kept plain so JSON-pointer escaping is never a factor).
_key = st.text(alphabet=_LOWER + "_", min_size=1, max_size=6)

# Recursive secret-bearing payload: scalars (incl. secret/email tokens + raw
# bytes that must become digest-only references) at the leaves; lists / dicts as
# nodes. The top level is always a dict (the engine entrypoint requires it).
_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**9), max_value=10**9),
    _benign_text,
    _secret_token,
    _email_token,
    st.binary(max_size=16),
)
_node = st.recursive(
    _leaf,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(_key, children, max_size=4)
    ),
    max_leaves=12,
)
_payload = st.dictionaries(_key, _node, min_size=1, max_size=4)


# ---------------------------------------------------------------------------
# Property 1: NO-LEAK -- a matched redact-action secret never survives.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(prefix=_benign_fill, secret=_secret_token, suffix=_benign_fill)
@settings(max_examples=300, deadline=None)
def test_no_leak_redact_secret_absent_from_wire_bytes(
    prefix: str, secret: str, suffix: str
) -> None:
    """A generated ``sk-``/``key_`` secret embedded in benign text MUST NOT
    appear verbatim in the redacted wire bytes; the redact placeholder MUST
    be present (proving the matcher fired)."""
    engine = _redact_hash_engine()
    payload = {"model_call": {"input": prefix + secret + suffix}}
    body = redact_capture_payload(engine, payload)
    assert secret.encode("utf-8") not in body, (
        f"redact-action secret leaked verbatim into wire bytes: {body!r}"
    )
    assert b"<redacted>" in body, (
        f"redact placeholder absent -- matcher did not fire: {body!r}"
    )


# ---------------------------------------------------------------------------
# Property 2: NO-LEAK -- a matched hash-action email never survives.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(prefix=_benign_fill, email=_email_token, suffix=_benign_fill)
@settings(max_examples=300, deadline=None)
def test_no_leak_hash_email_absent_from_wire_bytes(
    prefix: str, email: str, suffix: str
) -> None:
    """A generated email embedded in benign text MUST NOT survive verbatim --
    the hash matcher replaces it with an HMAC-SHA-256 digest."""
    engine = _redact_hash_engine()
    payload = {"tool_call": {"args": {"to": prefix + email + suffix}}}
    body = redact_capture_payload(engine, payload)
    assert email.encode("utf-8") not in body, (
        f"hash-action email leaked verbatim into wire bytes: {body!r}"
    )


# ---------------------------------------------------------------------------
# Property 3: NO-LEAK -- hosted-default json_pointer redacts every message leaf.
# ---------------------------------------------------------------------------

# A distinctive, JSON-clean sensitive marker the matchers cannot accidentally
# partial-match; placed at a json_pointer-covered leaf it must be fully replaced.
_sensitive_content = st.builds(
    lambda body: "SENSITIVE-" + body,
    st.text(alphabet=_ALNUM + " ", min_size=1, max_size=24),
)


@pytest.mark.plumbing
@given(contents=st.lists(_sensitive_content, min_size=1, max_size=5))
@settings(max_examples=200, deadline=None)
def test_no_leak_hosted_default_message_content(contents: list[str]) -> None:
    """Under the hosted-default policy every ``messages[i].content.text`` leaf
    is matched by the ``/messages/*/content/text`` json_pointer wildcard, so
    NONE of the sensitive contents survive verbatim and each leaf becomes the
    redact placeholder."""
    engine = _hosted_default_engine()
    payload = {"messages": [{"content": {"text": c}} for c in contents]}
    redacted = engine.redact(payload)
    for idx, _content in enumerate(contents):
        assert redacted["messages"][idx]["content"]["text"] == "<redacted>", (
            f"json_pointer leaf {idx} not fully redacted: {redacted!r}"
        )
    body = redact_capture_payload(engine, payload)
    for content in contents:
        assert content.encode("utf-8") not in body, (
            f"hosted-default policy leaked message content: {body!r}"
        )


# ---------------------------------------------------------------------------
# Property 4: IDEMPOTENCE -- redact(redact(x)) == redact(x).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(payload=_payload)
@settings(max_examples=300, deadline=None)
def test_redact_is_idempotent(payload: dict[str, Any]) -> None:
    """The redacted form is a fixed point: re-redacting it yields the same
    structure (placeholders, HMAC digests, and bytes-digest references are never
    re-matched)."""
    engine = _redact_hash_engine()
    once = engine.redact(payload)
    twice = engine.redact(once)
    assert once == twice


@pytest.mark.plumbing
@given(payload=_payload)
@settings(max_examples=200, deadline=None)
def test_redact_capture_payload_is_idempotent_at_wire(
    payload: dict[str, Any],
) -> None:
    """Re-redacting the wire-decoded redacted dict yields byte-identical wire
    output -- the canonical redacted bytes are a fixed point."""
    import json

    engine = _redact_hash_engine()
    once = redact_capture_payload(engine, payload)
    reparsed = json.loads(once.decode("utf-8"))
    twice = redact_capture_payload(engine, reparsed)
    assert once == twice


# ---------------------------------------------------------------------------
# Properties 5/6: INTERVAL-UNION / OVERLAP (VAL-REDACT-002).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(
    prefix=st.text(alphabet=_LOWER, max_size=8),
    core=st.text(alphabet=_DIGITS, min_size=1, max_size=12),
    suffix=st.text(alphabet=_LOWER, max_size=8),
)
@settings(max_examples=300, deadline=None)
def test_overlap_tail_merges_to_single_replacement_no_gap_leak(
    prefix: str, core: str, suffix: str
) -> None:
    """Two overlapping spans whose RIGHT span extends past the LEFT span's end
    (the VAL-REDACT-002 tail-leak shape) merge into ONE placeholder, and the
    tail ("TK") that only the right span covered does NOT survive."""
    engine = _overlap_tail_engine()
    secret = "SK" + core + "TK"
    leaf = prefix + secret + suffix
    redacted = engine.redact({"data": leaf})["data"]
    # Single merged replacement: prefix + one placeholder + suffix (benign
    # lowercase prefix/suffix are matched by neither matcher).
    assert redacted == prefix + "<redacted>" + suffix, (
        f"overlap did not merge to a single replacement: {redacted!r}"
    )
    # The gap tail "TK" (covered only by the overlapping right span) must be gone.
    assert "TK" not in redacted, f"overlap gap tail leaked: {redacted!r}"
    # No matched secret byte (any digit of the overlapping core) survives.
    assert not any(ch in _DIGITS for ch in redacted), (
        f"a core digit leaked through the overlap merge: {redacted!r}"
    )


@pytest.mark.plumbing
@given(
    prefix=st.text(alphabet=_LOWER, max_size=8),
    core=st.text(alphabet=_DIGITS, min_size=1, max_size=12),
    suffix=st.text(alphabet=_LOWER, max_size=8),
)
@settings(max_examples=300, deadline=None)
def test_overlap_containment_merges_to_single_replacement_no_leak(
    prefix: str, core: str, suffix: str
) -> None:
    """A span fully CONTAINED in another (the merge's max(end) branch) merges to
    a single placeholder; the contained span must not shrink the redacted range
    and no matched byte survives."""
    engine = _overlap_contain_engine()
    secret = "SK" + core + "TK"
    leaf = prefix + secret + suffix
    redacted = engine.redact({"data": leaf})["data"]
    assert redacted == prefix + "<redacted>" + suffix, (
        f"containment did not merge to a single replacement: {redacted!r}"
    )
    assert "TK" not in redacted, f"contained span tail leaked: {redacted!r}"
    assert not any(ch in _DIGITS for ch in redacted), (
        f"a core digit leaked through the containment merge: {redacted!r}"
    )


# ---------------------------------------------------------------------------
# Properties 7/8/9: DETERMINISM.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(payload=_payload)
@settings(max_examples=300, deadline=None)
def test_redact_dict_is_deterministic(payload: dict[str, Any]) -> None:
    """Two redactions of the same payload (same engine) produce equal output --
    HMAC digests and bytes digests are stable under the cached salt."""
    engine = _redact_hash_engine()
    assert engine.redact(payload) == engine.redact(payload)


@pytest.mark.plumbing
@given(payload=_payload)
@settings(max_examples=300, deadline=None)
def test_redact_capture_payload_is_deterministic(payload: dict[str, Any]) -> None:
    """The canonical wire bytes are stable across calls (sorted keys + compact
    separators + deterministic digests)."""
    engine = _redact_hash_engine()
    assert redact_capture_payload(engine, payload) == redact_capture_payload(
        engine, payload
    )


@pytest.mark.plumbing
@given(payload=_payload)
@settings(max_examples=200, deadline=None)
def test_independent_engines_emit_byte_identical_wire_output(
    payload: dict[str, Any],
) -> None:
    """Spec G.3: two engines built from the same policy version + salt provider
    emit byte-identical wire output for the same input."""
    engine_a = _redact_hash_engine()
    engine_b = _redact_hash_engine()
    assert redact_capture_payload(engine_a, payload) == redact_capture_payload(
        engine_b, payload
    )
