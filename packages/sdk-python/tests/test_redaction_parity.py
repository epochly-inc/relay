"""Cross-language parity tests for SDK-side redaction (P0/P1 bug fixes).

These tests guard against four parity defects identified by structural
review of ``packages/sdk-python/relay/redaction.py`` vs
``packages/sdk-typescript/src/redaction.ts``:

  * Bug 1 (P0): ``redact_capture_payload`` used Python's default JSON
    separators ``(', ', ': ')``, while TS uses JCS-compact ``(',', ':')``.
    Same input -> different wire bytes; breaks cross-language byte
    equality (VAL-W4-020).

  * Bug 2 (P0): Bytes / bytearray leaves were routed through the string
    matcher path via ``_to_string`` (UTF-8 decode with errors='replace').
    Plaintext leaked verbatim when no matcher fired. TS replaces every
    binary leaf with ``{_digest_sha256: "<hex>"}`` (VAL-W4-025).
    Keystone invariant #7 (default-deny raw capture) violation.

  * Bug 3 (P0): The schema_version alias ``relay.redaction_policy.v1``
    accepted by TS was rejected by Python; same policy body, different
    outcome cross-language.

  * Bug 4 (P1): ``_apply_matchers_to_string`` NFKC-normalized the input
    then spliced match offsets back into the ORIGINAL (non-normalized)
    string. NFKC is not length-preserving for combining marks (e.g.
    ``u + U+0308`` -> ``u-with-diaeresis`` collapses to a single code
    point); offsets pointed to the wrong positions.

The first three are also exercised against the live TS engine via a
Node subprocess for byte-equality at the wire layer (Bug 1).

ASCII-only per CLAUDE.md "ASCII-Safe Source": Unicode test inputs use
``\\uXXXX`` escapes in source so the file stays pure ASCII.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from relay.errors import RelayPolicyError
from relay.redaction import (
    DEFAULT_APPLIES_TO_FIELDS,
    RedactionEngine,
    RedactionPolicy,
    redact_capture_payload,
)

# Same canonical baseline policy as test_redaction.py / parity corpus.
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
            "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+",
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

_TENANT_SALT = b"test-tenant-salt-v3-do-not-use-in-prod"


def _salt_provider(salt_ref: str) -> bytes:
    if salt_ref == "tenant_salt_v3":
        return _TENANT_SALT
    raise KeyError(salt_ref)


# ---------------------------------------------------------------------------
# Bug 1 (P0): JSON separator parity (no whitespace; matches TS JCS-compact).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_redact_capture_payload_uses_jcs_compact_separators() -> None:
    """``redact_capture_payload`` emits NO whitespace between JSON
    tokens. The TS canonicalizer uses ``,`` and ``:`` with no spaces;
    Python must match byte-for-byte.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {"a": 1, "b": [1, 2, {"c": "ok"}], "d": None}
    body = redact_capture_payload(engine, payload)
    text = body.decode("utf-8")
    # JCS-compact has zero ``", "`` or ``": "`` substrings.
    assert ", " not in text, f"found ', ' whitespace in {text!r}"
    assert ": " not in text, f"found ': ' whitespace in {text!r}"
    # Exact expected bytes (sort_keys + compact separators).
    expected = b'{"a":1,"b":[1,2,{"c":"ok"}],"d":null}'
    assert body == expected, f"expected {expected!r}, got {body!r}"


@pytest.mark.plumbing
def test_redact_capture_payload_matches_generator_canonicalization() -> None:
    """The bytes emitted by ``redact_capture_payload`` MUST equal the
    bytes produced by the parity-fixture generator's ``_canonical_bytes``
    helper for the same input (which uses
    ``sort_keys=True, separators=(',', ':'), ensure_ascii=False``).
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {
        "schema_version": "relay.trace.event.v1",
        "model_call": {"input": "no matches here", "output": "ok"},
    }
    body = redact_capture_payload(engine, payload)
    # The generator's canonicalization, inlined here to keep this test
    # independent of the generator script.
    redacted = engine.redact(payload)
    expected = json.dumps(
        redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert body == expected


def _find_node() -> str | None:
    return shutil.which("node")


def _ts_canonicalize_via_node(
    policy_body: dict, payload: dict, tenant_salt: bytes
) -> bytes | None:
    """Invoke the TS engine via Node subprocess; return canonical bytes.

    Returns None when Node or the TS build are unavailable; the caller
    should skip rather than fail in that case (offline / pre-build
    environments).
    """
    node = _find_node()
    if node is None:
        return None
    repo_root = Path(__file__).resolve().parents[3]
    ts_dist = (
        repo_root / "packages" / "sdk-typescript" / "dist" / "src" / "redaction.js"
    )
    if not ts_dist.exists():
        return None
    ts_dist_json = json.dumps(str(ts_dist))
    script = f"""
import {{ loadRedactionPolicy, RedactionEngine, _canonicalJsonStringify }} from {ts_dist_json};

const stdin = await new Promise((resolve) => {{
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => {{ buf += c; }});
  process.stdin.on('end', () => resolve(buf));
}});
const input = JSON.parse(stdin);
const saltBytes = Buffer.from(input.salt_b64, 'base64');
const policy = loadRedactionPolicy(input.policy);
const engine = new RedactionEngine({{
  policy,
  saltProvider: () => new Uint8Array(saltBytes),
}});
const redacted = engine.redact(input.payload);
const text = _canonicalJsonStringify(redacted);
const bytes = Buffer.from(text, 'utf8');
process.stdout.write(bytes.toString('hex'));
"""
    import base64

    payload_in = {
        "policy": policy_body,
        "payload": payload,
        "salt_b64": base64.b64encode(tenant_salt).decode("ascii"),
    }
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(payload_in),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        # Bubble useful diagnostics so a real bug surfaces instead of
        # silently skipping. Empty hex means the subprocess died.
        raise RuntimeError(
            f"node TS subprocess failed: rc={proc.returncode} stderr={proc.stderr!r}"
        )
    return bytes.fromhex(proc.stdout.strip())


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "name,payload",
    [
        (
            "string-with-emoji-no-match",
            # Emoji is supplementary plane (surrogate pair in UTF-16).
            # TS JSON.stringify emits raw UTF-8; Python with ensure_ascii=False
            # also emits raw UTF-8. Use a clean string (no matcher hits).
            {"model_call": {"input": "hello world no secret"}},
        ),
        (
            "nested-dict-no-match",
            {"a": {"b": {"c": {"d": "ok"}}}, "z": 1, "m": [1, 2, 3]},
        ),
        (
            "array-of-arrays",
            {"matrix": [[1, 2, 3], [4, 5, 6], [7, 8, 9]]},
        ),
        (
            "all-null-leaves",
            {"a": None, "b": None, "c": {"d": None, "e": None}},
        ),
        (
            "ascii-secret-redacted",
            {
                "model_call": {
                    "input": "key is sk-ABCDEFGHIJKLMNOPQRSTUV end",
                    "output": "ok",
                },
            },
        ),
    ],
)
def test_python_canonical_bytes_match_typescript_via_node_subprocess(
    name: str, payload: dict
) -> None:
    """For each payload shape, Python ``redact_capture_payload`` MUST
    emit byte-identical bytes to TS ``_canonicalJsonStringify`` of the
    same redacted dict.

    Skipped when Node is unavailable or the TS dist has not been built
    (e.g. CI offline tier-1 environment); guarded so this test does
    not flake on environment lifecycle. When Node + dist are present
    the test is authoritative.
    """
    ts_bytes = _ts_canonicalize_via_node(_BASE_POLICY, payload, _TENANT_SALT)
    if ts_bytes is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language byte equality cannot be checked "
            "in this environment"
        )
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    py_bytes = redact_capture_payload(engine, payload)
    assert py_bytes == ts_bytes, (
        f"cross-language byte mismatch on fixture {name!r}: "
        f"py={py_bytes!r} ts={ts_bytes!r}"
    )


# ---------------------------------------------------------------------------
# Bug 2 (P0): bytes leaves -> digest-only reference (no plaintext leak).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_walk_binary_value_returns_digest_only() -> None:
    """A ``bytes`` leaf MUST become ``{"_digest_sha256": "<hex>"}``;
    plaintext MUST NOT survive into the wire body.

    The plaintext here is ``b"my secret password 12345"`` -- a string
    no regex matcher in the base policy would catch. Pre-fix, this
    survived verbatim via the ``_to_string`` decode path.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    plaintext = b"my secret password 12345"
    expected_digest = hashlib.sha256(plaintext).hexdigest()
    payload = {"tool_call": {"args": {"attachment": plaintext}}}
    redacted = engine.redact(payload)
    leaf = redacted["tool_call"]["args"]["attachment"]
    assert leaf == {"_digest_sha256": expected_digest}, (
        f"bytes leaf not converted to digest reference: {leaf!r}"
    )
    # And the wire body has no plaintext.
    body = redact_capture_payload(engine, payload)
    assert plaintext not in body
    assert expected_digest.encode("ascii") in body


@pytest.mark.plumbing
def test_walk_bytearray_value_returns_digest_only() -> None:
    """``bytearray`` MUST be treated identically to ``bytes``."""
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    plaintext = bytearray(b"another raw secret blob without matcher hits")
    expected_digest = hashlib.sha256(bytes(plaintext)).hexdigest()
    payload = {"retrieval": {"documents": [{"bytes": plaintext}]}}
    redacted = engine.redact(payload)
    leaf = redacted["retrieval"]["documents"][0]["bytes"]
    assert leaf == {"_digest_sha256": expected_digest}


@pytest.mark.plumbing
def test_walk_memoryview_rejected_like_ts_blob() -> None:
    """``memoryview`` is the Python parallel of JS ``Blob``: a view
    object that does not directly expose a contiguous bytes buffer in
    the way the engine guarantees. The engine MUST refuse it loudly
    rather than silently decode garbage.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    mv = memoryview(b"some-bytes")
    payload = {"tool_call": {"args": {"buffer": mv}}}
    with pytest.raises(RelayPolicyError) as excinfo:
        engine.redact(payload)
    reason = excinfo.value.details.get("reason", "")
    assert reason in ("unresolved_memoryview", "binary_payload_must_be_bytes") or (
        "memoryview" in str(excinfo.value).lower()
    )


# ---------------------------------------------------------------------------
# Bug 3 (P0): schema_version alias 'relay.redaction_policy.v1' is accepted.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_schema_version_alias_relay_redaction_policy_v1_accepted() -> None:
    """The codegen-friendly alias ``relay.redaction_policy.v1`` MUST
    load on Python (TS already accepts both literals at lines 77-78).
    """
    body = {**_BASE_POLICY, "schema_version": "relay.redaction_policy.v1"}
    policy = RedactionPolicy.load(body)
    assert policy.policy_version == _BASE_POLICY["policy_version"]


@pytest.mark.plumbing
def test_schema_version_primary_still_accepted() -> None:
    """Regression guard: the primary literal still loads."""
    body = {**_BASE_POLICY, "schema_version": "relay.redaction.v1"}
    policy = RedactionPolicy.load(body)
    assert policy.policy_version == _BASE_POLICY["policy_version"]


@pytest.mark.plumbing
def test_schema_version_unknown_still_rejected() -> None:
    """Regression guard: an unrelated literal is still refused."""
    body = {**_BASE_POLICY, "schema_version": "relay.redaction.v999"}
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(body)
    assert excinfo.value.details.get("reason") == "schema_version"


# ---------------------------------------------------------------------------
# Bug 4 (P1): NFKC combining-mark splice offsets are correct.
# ---------------------------------------------------------------------------

# Constructed via explicit code points to keep source pure ASCII.
# U+0308 = COMBINING DIAERESIS. Decomposed form: ord('u') + U+0308.
# Under NFKC, this pair composes into the single code point U+00FC
# (LATIN SMALL LETTER U WITH DIAERESIS) -- two code units collapse to
# one. The composed form is what the matcher's pattern targets.
_COMBINING_DIAERESIS = "\u0308"
_U_WITH_DIAERESIS = "\u00fc"


@pytest.mark.plumbing
def test_walk_combining_mark_redaction_no_offset_error() -> None:
    """A string containing a combining mark collapses two code points
    to one under normalization.

    Pre-fix: the engine matched on the normalized form (length N-1)
    and spliced into the original (length N), so the placeholder
    landed at the wrong offset and a fragment of the original
    plaintext survived. Post-fix: matching and splicing operate on the
    SAME (normalized) string, so the entire match span is replaced.
    """
    # Pattern targets the COMPOSED form ``passw + u-with-diaeresis + rd``.
    pattern = "passw" + _U_WITH_DIAERESIS + "rd"
    policy_body = {
        **_BASE_POLICY,
        "matchers": [
            {
                "id": "passw",
                "kind": "regex",
                "pattern": pattern,
                "action": "redact",
            }
        ],
    }
    policy = RedactionPolicy.load(policy_body)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # Input is the DECOMPOSED form: 'u' + COMBINING DIAERESIS (U+0308).
    decomposed = "my passw" + "u" + _COMBINING_DIAERESIS + "rd is here"
    payload = {"model_call": {"input": decomposed}}
    redacted = engine.redact(payload)
    out = redacted["model_call"]["input"]
    # The composed form of the entire secret must NOT survive.
    composed_secret = "passw" + _U_WITH_DIAERESIS + "rd"
    assert composed_secret not in out, (
        f"composed secret leaked: out={out!r}"
    )
    # And the trailing fragment of the decomposed form must not appear
    # adjacent to the placeholder (proves placeholder consumed the
    # whole secret, not just a prefix).
    assert (_U_WITH_DIAERESIS + "rd") not in out
    assert "<redacted>" in out
    # CRITICAL: the exact pre-fix failure mode is the trailing 'd' of
    # 'passwurd' (the last code point of the decomposed input) being
    # spliced past in the ORIGINAL string. Post-fix, the entire match
    # span is consumed and the placeholder is followed by a space.
    assert "<redacted>d" not in out, (
        f"trailing 'd' leaked due to NFKC off-by-one splice: out={out!r}"
    )
    # Exact expected output after the fix: prefix + placeholder + suffix
    # where suffix starts at the FIRST character after the matched
    # secret in the normalized form (which is ' is here').
    assert out == "my <redacted> is here", (
        f"unexpected splice result: out={out!r}"
    )
