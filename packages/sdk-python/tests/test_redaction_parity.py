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
    HOSTED_DEFAULT_POLICY,
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


def _ts_redact_outcome_via_node(
    policy_body: dict, payload: dict, tenant_salt: bytes
) -> dict | None:
    """Invoke the TS engine via Node and report its OUTCOME (not bytes).

    Returns a dict ``{"ok": True, "hex": "<canonical-bytes-hex>"}`` when the
    TS ``redactCapturePayload`` succeeds, or ``{"ok": False, "code": "...",
    "reason": "...", "message": "..."}`` when it raises. This lets a parity
    test assert that BOTH runtimes fail closed on the same input (e.g. a
    non-finite numeric leaf), capturing the typed rejection shape rather than
    only the success bytes.

    Returns ``None`` when Node or the TS build are unavailable; the caller
    should skip rather than fail in that case (offline / pre-build).
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
import {{ loadRedactionPolicy, RedactionEngine, redactCapturePayload }} from {ts_dist_json};

const stdin = await new Promise((resolve) => {{
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => {{ buf += c; }});
  process.stdin.on('end', () => resolve(buf));
}});
const input = JSON.parse(stdin, (key, value) => {{
  // Rehydrate the non-finite sentinels the Python side encodes as strings
  // (JSON has no Infinity/NaN literal): "__RELAY_INFINITY__" etc. become
  // the real JS numeric values so the TS engine sees a non-finite leaf.
  if (value === '__RELAY_INFINITY__') return Infinity;
  if (value === '__RELAY_NEG_INFINITY__') return -Infinity;
  if (value === '__RELAY_NAN__') return NaN;
  return value;
}});
const saltBytes = Buffer.from(input.salt_b64, 'base64');
const policy = loadRedactionPolicy(input.policy);
const engine = new RedactionEngine({{
  policy,
  saltProvider: () => new Uint8Array(saltBytes),
}});
try {{
  const bytes = redactCapturePayload(engine, input.payload);
  process.stdout.write(JSON.stringify({{
    ok: true,
    hex: Buffer.from(bytes).toString('hex'),
  }}));
}} catch (err) {{
  process.stdout.write(JSON.stringify({{
    ok: false,
    code: err && err.code ? err.code : null,
    reason: err && err.details ? (err.details.reason ?? null) : null,
    message: err && err.message ? err.message : String(err),
    name: err && err.name ? err.name : null,
  }}));
}}
"""
    import base64

    payload_in = {
        "policy": policy_body,
        "payload": payload,
        "salt_b64": base64.b64encode(tenant_salt).decode("ascii"),
    }

    def _default(o: object) -> object:
        raise TypeError(f"unexpected type in payload: {type(o)!r}")

    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        # ``allow_nan=True`` would emit bare Infinity/NaN tokens that JS
        # JSON.parse rejects, so encode them as sentinel strings the Node
        # reviver above rehydrates into real non-finite numbers.
        input=json.dumps(payload_in, allow_nan=False, default=_default),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"node TS subprocess failed: rc={proc.returncode} stderr={proc.stderr!r}"
        )
    return json.loads(proc.stdout.strip())


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
# Number canonicalization parity (fix-r3-number-canonicalization).
# ---------------------------------------------------------------------------
# EMPIRICALLY CONFIRMED Gate-2 REAL_DEFECT (pre-existing): for a captured
# payload ``{"x": <num>}``, Python ``redact_capture_payload`` (via
# ``json.dumps`` float repr) emitted ``{"x":1.0}`` / ``{"x":1e+16}`` /
# ``{"x":1e+20}`` while TS ``canonicalJsonStringify`` (via ``String(value)``)
# emitted ``1`` / ``10000000000000000`` / ``100000000000000000000``. This
# broke Py<->TS byte-equality (keystone invariant #10) for any captured
# payload containing an integral float or |x| >= 1e16. TS ``String()`` is the
# ECMA-262 / RFC-8785 JCS-correct form; Python ``json.dumps`` was WRONG. The
# fix routes the Python serializer through the ECMA-262/JCS number encoder.

#: Value table covering the divergent cases AND the previously-coinciding
#: ones. The diverging-at-base entries are 1.0, 1e16, 1e20 (integral float /
#: large magnitude). 1.5, 100, 0, -17, 1e-7 already coincided.
_NUMBER_CANON_FLOAT_TABLE: list[tuple[str, float]] = [
    ("one-point-zero", 1.0),
    ("one-e16", 1e16),
    ("one-e20", 1e20),
    ("one-e21-exponent-boundary", 1e21),
    ("negative-zero", -0.0),
    ("one-point-five", 1.5),
    ("hundred-float", 100.0),
    ("zero", 0.0),
    ("negative-seventeen", -17.0),
    ("one-e-minus-7", 1e-7),
]


def _expected_jcs_number(value: float | int) -> str:
    """The ECMA-262/JCS Number-to-String form, sourced from the existing
    contracts canonical encoder (the authoritative implementation). The
    redaction encoder MUST be byte-identical to this across the table.
    """
    from relay_contracts.canonical import _encode_number

    return _encode_number(value)


@pytest.mark.plumbing
@pytest.mark.parametrize("name,value", _NUMBER_CANON_FLOAT_TABLE)
def test_redact_number_leaf_uses_ecma262_jcs_form(name: str, value: float) -> None:
    """``redact_capture_payload`` MUST emit a numeric leaf using the
    ECMA-262/JCS Number-to-String algorithm, not Python's ``json.dumps``
    float repr. RED at base for 1.0 / 1e16 / 1e20 (json.dumps emits
    ``1.0`` / ``1e+16`` / ``1e+20``; JCS demands ``1`` /
    ``10000000000000000`` / ``100000000000000000000``).
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    body = redact_capture_payload(engine, {"x": value})
    expected = ('{"x":' + _expected_jcs_number(value) + "}").encode("utf-8")
    assert body == expected, (
        f"number-leaf {name!r} ({value!r}) emitted {body!r}, "
        f"expected JCS form {expected!r}"
    )


@pytest.mark.plumbing
def test_redact_large_int_leaf_emits_exact_decimal() -> None:
    """A Python ``int`` leaf is emitted as its EXACT decimal -- no float
    coercion (which would lose precision past 2**53). JCS integer form.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    big = 9007199254740993  # 2**53 + 1: inexact as an IEEE-754 double.
    body = redact_capture_payload(engine, {"x": big})
    assert body == b'{"x":9007199254740993}', f"got {body!r}"


@pytest.mark.plumbing
@pytest.mark.parametrize("name,value", _NUMBER_CANON_FLOAT_TABLE)
def test_redact_number_leaf_byte_identical_to_contracts_encoder(
    name: str, value: float
) -> None:
    """The redaction module's number formatter MUST be byte-identical to
    ``relay_contracts.canonical._encode_number`` across the value table.

    The redaction module replicates the JCS formatter rather than taking a
    hard dependency on ``relay_contracts`` (not a declared dep of the
    sdk-python package). This test pins the two implementations together so
    they cannot drift.
    """
    from relay.redaction import _encode_jcs_number

    assert _encode_jcs_number(value) == _expected_jcs_number(value), (
        f"redaction _encode_jcs_number diverged from "
        f"relay_contracts.canonical._encode_number on {name!r} ({value!r})"
    )


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "name,payload",
    [
        ("integral-float-1.0", {"x": 1.0}),
        ("large-float-1e16", {"x": 1e16}),
        ("large-float-1e20", {"x": 1e20}),
        ("exponent-boundary-1e21", {"x": 1e21}),
        ("fraction-1.5", {"x": 1.5}),
        ("small-exponent-1e-7", {"x": 1e-7}),
        ("zero", {"x": 0}),
        ("mixed-numeric-leaves", {"a": 1.0, "b": 1e20, "c": [1e16, 2.5, 0], "d": 1e-7}),
    ],
)
def test_number_canonicalization_byte_equal_typescript_via_node_subprocess(
    name: str, payload: dict
) -> None:
    """Python ``redact_capture_payload`` MUST emit byte-identical bytes to
    TS ``_canonicalJsonStringify`` for numeric-leaf payloads. RED at base:
    1.0 / 1e16 / 1e20 diverge (Python ``1.0``/``1e+16``/``1e+20`` vs TS
    ``1``/``10000000000000000``/``100000000000000000000``).

    Skipped when Node or the TS dist are unavailable.
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
        f"cross-language numeric byte mismatch on {name!r}: "
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


# ---------------------------------------------------------------------------
# VAL-REDACT-001 (HIGH / security): the hosted default policy declares a
# json_pointer matcher path ``/messages/*/content/text``. Real chat payloads
# produce array-indexed leaf pointers like ``/messages/0/content/text``.
# Pre-fix, ``_find_json_pointer_match`` tested ``pointer in matcher.json_paths``
# with an exact-membership comparison, so the literal-``*`` path never matched
# an indexed pointer and the default policy redacted NOTHING -- prompt content
# (SSNs, etc.) was emitted verbatim. The fix interprets a ``*`` token in a
# ``json_pointer`` matcher path as a single-segment wildcard matching any one
# array index or object key.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_hosted_default_policy_redacts_indexed_message_content() -> None:
    """The contract trigger: the default policy MUST redact the SSN at
    ``/messages/0/content/text`` even though the matcher path uses ``*``.

    RED at base commit b4fd821: the literal ``*`` segment never equals the
    concrete array index ``0``, so the SSN leaks verbatim. GREEN after the
    wildcard fix.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    payload = {"messages": [{"content": {"text": "my SSN is 123-45-6789"}}]}
    body = redact_capture_payload(engine, payload)
    assert b"123-45-6789" not in body, (
        "default policy leaked prompt content verbatim: "
        f"{body!r}"
    )
    assert b"<redacted>" in body, (
        f"expected the redact placeholder in {body!r}"
    )


@pytest.mark.plumbing
def test_hosted_default_policy_redacts_every_message_index() -> None:
    """The ``*`` wildcard matches ANY single array index, not just 0.

    A multi-message payload must have every ``messages[*].content.text``
    leaf redacted.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    # Inputs deliberately avoid the default policy's regex matchers
    # (password/api_key/secret/token) so the assertion isolates the
    # json_pointer wildcard behavior: a pointer match replaces the WHOLE
    # leaf with the placeholder (pointer match wins over regex per _walk).
    redacted = engine.redact(
        {
            "messages": [
                {"content": {"text": "first ssn 111-11-1111"}},
                {"content": {"text": "second ssn 222-22-2222"}},
                {"content": {"text": "third ssn 333-33-3333"}},
            ]
        }
    )
    for idx in range(3):
        assert (
            redacted["messages"][idx]["content"]["text"] == "<redacted>"
        ), f"message index {idx} not redacted: {redacted!r}"


@pytest.mark.plumbing
def test_hosted_default_policy_redacts_output_text_exact_pointer() -> None:
    """Regression guard: a json_pointer matcher with NO ``*`` segment
    (``/output/text``) still matches by exact pointer, unchanged by the
    wildcard fix.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    redacted = engine.redact({"output": {"text": "agent said 444-44-4444"}})
    assert redacted["output"]["text"] == "<redacted>"


# ---------------------------------------------------------------------------
# REDACT cluster Bug A (P2 / security): the default policy matcher path
# ``/messages/*/content/text`` only covers the OBJECT content shape
# (``content: {text: ...}``). The standard chat shape used by OpenAI Chat
# Completions and Anthropic Messages is a LIST of content PARTS:
# ``content: [{type: "text", text: ...}]`` whose leaf pointer is
# ``/messages/0/content/0/text`` (6 segments) -- the 5-segment matcher path
# never matched it, so prompt text LEAKED verbatim. The fix adds the sibling
# matcher path ``/messages/*/content/*/text`` (and ``/output/*/text`` alongside
# ``/output/text``) using the existing single-segment ``*`` wildcard machinery.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_hosted_default_policy_redacts_array_of_content_parts() -> None:
    """The default policy MUST redact the text leaf in the list-of-content-parts
    chat shape ``messages[*].content[j].text`` (OpenAI Chat Completions /
    Anthropic Messages), not only the object ``content.text`` shape.

    RED at base: the matcher path ``/messages/*/content/text`` has 5 segments
    but the array-of-parts pointer ``/messages/0/content/0/text`` has 6, so the
    private medical text leaked. GREEN after adding ``/messages/*/content/*/text``.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "my private medical diagnosis is X"}
                ],
            }
        ]
    }
    body = redact_capture_payload(engine, payload)
    assert b"my private medical diagnosis is X" not in body, (
        "default policy leaked array-of-parts prompt content verbatim: "
        f"{body!r}"
    )
    assert b"<redacted>" in body, f"expected the redact placeholder in {body!r}"


@pytest.mark.plumbing
def test_hosted_default_policy_redacts_both_content_shapes() -> None:
    """BOTH content shapes (object ``content.text`` AND array-of-parts
    ``content[j].text``) MUST be redacted under the default policy in a single
    payload, proving the fix did not REPLACE the object-shape matcher but
    ADDED the array-of-parts matcher alongside it.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    redacted = engine.redact(
        {
            "messages": [
                # Object shape: /messages/0/content/text
                {"role": "user", "content": {"text": "object shape ssn 111-11-1111"}},
                # Array-of-parts shape: /messages/1/content/0/text
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "array shape ssn 222-22-2222"}
                    ],
                },
            ]
        }
    )
    assert redacted["messages"][0]["content"]["text"] == "<redacted>"
    assert redacted["messages"][1]["content"][0]["text"] == "<redacted>"
    # The ``type`` sibling (``/messages/1/content/0/type``) value is "text" and
    # MUST NOT be matched by ``/messages/*/content/*/text`` (last segment differs).
    assert redacted["messages"][1]["content"][0]["type"] == "text"


@pytest.mark.plumbing
def test_hosted_default_policy_redacts_array_output_text() -> None:
    """The default policy MUST redact the array-of-parts OUTPUT shape
    ``output[j].text`` (``/output/*/text``) alongside the object
    ``/output/text`` shape.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    redacted = engine.redact(
        {"output": [{"type": "text", "text": "agent leaked 333-33-3333"}]}
    )
    assert redacted["output"][0]["text"] == "<redacted>"


@pytest.mark.plumbing
def test_json_pointer_wildcard_does_not_overmatch_segment_count() -> None:
    """A ``*`` matches exactly ONE segment, never spans multiple.

    ``/messages/*/content/text`` must NOT fire on a deeper or shallower
    pointer such as ``/messages/0/extra/content/text`` (an extra segment)
    or ``/messages/0/content`` (a missing trailing segment): the wildcard
    is single-segment, not a recursive-descent glob.
    """
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=lambda _ref: b"hosted-default-salt"
    )
    # Extra intervening segment: pointer is /messages/0/extra/content/text.
    # Input avoids the regex matchers so only the pointer logic is exercised.
    redacted = engine.redact(
        {"messages": [{"extra": {"content": {"text": "plain value here"}}}]}
    )
    leaf = redacted["messages"][0]["extra"]["content"]["text"]
    assert leaf == "plain value here", (
        f"wildcard over-matched a deeper pointer: {leaf!r}"
    )


@pytest.mark.plumbing
def test_base_policy_parity_unchanged_by_wildcard_fix() -> None:
    """Parity regression guard for VAL-REDACT-001: the regex-only base
    policy (which contains no ``json_pointer`` ``*`` matcher) MUST still
    produce byte-identical output on Python and TypeScript after the
    wildcard fix. Skipped when Node / TS dist are unavailable.
    """
    payload = {
        "messages": [{"content": {"text": "key is sk-ABCDEFGHIJKLMNOPQRSTUV"}}],
        "model_call": {"input": "ok", "output": "fine"},
    }
    ts_bytes = _ts_canonicalize_via_node(_BASE_POLICY, payload, _TENANT_SALT)
    if ts_bytes is None:
        pytest.skip(
            "node binary or TS dist not available; cross-language byte "
            "equality cannot be checked in this environment"
        )
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    py_bytes = redact_capture_payload(engine, payload)
    assert py_bytes == ts_bytes, (
        f"wildcard fix broke base-policy parity: py={py_bytes!r} ts={ts_bytes!r}"
    )


# The TS half of the VAL-REDACT-001 fix landed in
# packages/sdk-typescript/src/redaction.ts (``jsonPointerMatches`` +
# ``findJsonPointerMatch``). Before that fix the TS SDK used exact membership
# (``matcher.jsonPaths.includes(pointer)``) so the hosted default matcher path
# ``/messages/*/content/text`` never matched the concrete array-indexed pointer
# ``/messages/0/content/text`` -- the TS SDK UNDER-REDACTED and LEAKED prompt
# content. The Python single-segment ``*`` wildcard landed first
# (``_json_pointer_matches``). This parity surface proves both runtimes now
# redact ``/messages/<n>/content/text`` BYTE-IDENTICALLY for the hosted default
# policy (keystone invariant #7: Python<->TS must agree byte-for-byte).
#
# The hosted-default matchers are all ``redact`` (no ``hash``), so the salt is
# never resolved; the salt provider exists only to satisfy the engine contract
# and is keyed by the hosted default ``salt_ref``.
_HOSTED_DEFAULT_SALT = b"hosted-default-salt-do-not-use-in-prod"


def _hosted_default_salt_provider(salt_ref: str) -> bytes:
    if salt_ref == "hosted_default_salt":
        return _HOSTED_DEFAULT_SALT
    raise KeyError(salt_ref)


@pytest.mark.plumbing
def test_hosted_default_wildcard_pointer_byte_equal_typescript_via_node_subprocess() -> (
    None
):
    """Python and TS MUST emit byte-identical canonical bytes for the hosted
    default policy redacting an array-indexed message-content pointer
    (``/messages/0/content/text`` and ``/messages/2/content/text``) via the
    json_pointer ``*`` single-segment wildcard.

    This is the VAL-REDACT-001 TS-parity surface (the TS half of the fix): the
    SSN in the message content MUST be redacted byte-identically on BOTH
    runtimes, and the wildcard MUST NOT over-match a different-segment-count
    pointer (``/messages/0/meta`` stays verbatim). Pre-fix the TS SDK leaked the
    SSN verbatim while Python redacted it -- the SDKs diverged. Post-fix they
    agree byte-for-byte.

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present (the gate environment rebuilds the dist first) the test is
    authoritative.
    """
    payload = {
        "messages": [
            {"content": {"text": "first ssn 111-11-1111"}},
            {"role": "assistant"},
            {"content": {"text": "third ssn 333-33-3333"}},
        ],
        # Different segment count than /messages/*/content/text: the wildcard
        # is single-segment, so this leaf MUST stay verbatim on both runtimes.
        # The value deliberately avoids the hosted-default regex matchers
        # (password / api[_-]?key / secret / token) so the assertion isolates
        # the json_pointer wildcard behavior.
        "model_call": {"input": "plain value here"},
    }
    ts_bytes = _ts_canonicalize_via_node(
        HOSTED_DEFAULT_POLICY, payload, _HOSTED_DEFAULT_SALT
    )
    if ts_bytes is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language byte equality cannot be checked "
            "in this environment"
        )
    policy = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    engine = RedactionEngine(
        policy=policy, salt_provider=_hosted_default_salt_provider
    )
    py_bytes = redact_capture_payload(engine, payload)
    assert py_bytes == ts_bytes, (
        "cross-language byte mismatch on hosted-default wildcard pointer: "
        f"py={py_bytes!r} ts={ts_bytes!r}"
    )
    # The indexed message content MUST be redacted (no SSN leak) on the Python
    # side; byte-equality above guarantees the same on TS.
    assert b"111-11-1111" not in py_bytes, (
        f"message[0] content leaked: {py_bytes!r}"
    )
    assert b"333-33-3333" not in py_bytes, (
        f"message[2] content leaked: {py_bytes!r}"
    )
    assert b"<redacted>" in py_bytes
    # The wildcard did NOT over-match: the different-segment leaf is verbatim.
    assert b"plain value here" in py_bytes, (
        f"wildcard over-matched a different-segment pointer: {py_bytes!r}"
    )


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


# ---------------------------------------------------------------------------
# VAL-REDACT-003 (HIGH / correctness): Python inline-flag regex matchers
# (e.g. the default policy's ``(?i)password``) load and match in Python; the
# TS SDK threw on them with ``new RegExp(rawPattern, "g")`` because JS RegExp
# does not understand Python's leading inline scoped flags. The fix
# translates the supported ``(?i)``/``(?s)``/``(?m)`` subset to JS flags and
# rejects Python named groups ``(?P<...>)`` consistently on BOTH SDKs.
# ---------------------------------------------------------------------------

# A policy whose ONLY regex matcher uses a leading Python inline flag, mirror
# of the hosted default policy's ``(?i)password`` matcher. The TS SDK threw at
# load on this exact pattern pre-fix.
_INLINE_FLAG_POLICY: dict = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "2026-05-29.inline-flags",
    "raw_capture": False,
    "retention_days": 30,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {
            "id": "password-field",
            "kind": "regex",
            "pattern": "(?i)password",
            "action": "redact",
        },
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_v3"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
    "applies_to_fields": list(DEFAULT_APPLIES_TO_FIELDS),
}


@pytest.mark.plumbing
def test_inline_flag_policy_loads_and_matches_case_insensitively() -> None:
    """The ``(?i)password`` matcher must load and redact case-insensitively.

    Python ``re.compile('(?i)password')`` sets IGNORECASE natively. This is
    the parity baseline TS must reach (TS threw on this pattern pre-fix).
    """
    policy = RedactionPolicy.load(_INLINE_FLAG_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    out = engine.redact({"model_call": {"input": "my PASSWORD is here"}})
    rendered = out["model_call"]["input"]
    assert "PASSWORD" not in rendered
    assert "<redacted>" in rendered


@pytest.mark.plumbing
def test_inline_flag_policy_byte_equal_typescript_via_node_subprocess() -> None:
    """Python and TS MUST emit byte-identical canonical bytes for a policy
    whose matcher uses a Python inline flag (``(?i)password``).

    This is the VAL-REDACT-003 parity surface: pre-fix the TS subprocess
    threw 'Invalid regular expression: /(?i)password/g: Invalid group' while
    Python loaded and matched -- the SDKs diverged. Post-fix they agree.

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    payload = {"model_call": {"input": "my PASSWORD is the secret pAsSwOrD"}}
    ts_bytes = _ts_canonicalize_via_node(
        _INLINE_FLAG_POLICY, payload, _TENANT_SALT
    )
    if ts_bytes is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language byte equality cannot be checked "
            "in this environment"
        )
    policy = RedactionPolicy.load(_INLINE_FLAG_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    py_bytes = redact_capture_payload(engine, payload)
    assert py_bytes == ts_bytes, (
        "cross-language byte mismatch on (?i) inline-flag policy: "
        f"py={py_bytes!r} ts={ts_bytes!r}"
    )


@pytest.mark.plumbing
def test_python_named_group_rejected_like_typescript() -> None:
    """Python named groups ``(?P<...>)`` MUST be rejected on the Python side
    so the supported regex dialect matches the TS SDK exactly.

    Pre-fix Python ``re.compile`` accepted ``(?P<word>password)`` (the
    matcher would silently match) while the TS SDK threw -- a parity defect.
    Post-fix both reject it with a ``named_group_unsupported`` reason.
    """
    body = {
        **_INLINE_FLAG_POLICY,
        "matchers": [
            {
                "id": "named",
                "kind": "regex",
                "pattern": "(?P<word>password)",
                "action": "redact",
            }
        ],
    }
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(body)
    assert excinfo.value.details.get("reason") == "named_group_unsupported"


@pytest.mark.plumbing
def test_python_named_backreference_rejected() -> None:
    """``(?P=name)`` named backreference is rejected as named-group syntax."""
    body = {
        **_INLINE_FLAG_POLICY,
        "matchers": [
            {
                "id": "backref",
                "kind": "regex",
                "pattern": "(?P<a>x)(?P=a)",
                "action": "redact",
            }
        ],
    }
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(body)
    assert excinfo.value.details.get("reason") == "named_group_unsupported"


# ---------------------------------------------------------------------------
# VAL-REDACT-003 (codex P2 follow-up): Python-only scoped / global inline
# flags must be rejected so the supported dialect agrees with TS on
# accept/reject. Python's ``re`` accepts the scoped ASCII / Unicode flag
# groups ``(?a:...)`` / ``(?u:...)`` and the global ``(?a)`` / ``(?u)`` forms
# (and tolerates verbose ``(?x:...)`` / ``(?x)``), but JavaScript ``RegExp``
# rejects all of them (``Invalid group``). Pre-fix a matcher using
# ``(?a:password)`` LOADED on Python but THREW on TS -- a Py<->TS divergence
# where one SDK silently has no rule while the other errors. Post-fix Python
# rejects them too via the existing ``bad_regex`` path so both SDKs agree.
# ``(?L:...)`` / ``(?L)`` were already rejected by Python's ``re`` (str
# patterns cannot use the LOCALE flag) and by TS; kept here for coverage.
# ---------------------------------------------------------------------------

# Patterns Python USED to accept but TS rejects (and a couple Python already
# rejected). After the fix every one of these must be rejected by BOTH SDKs.
_PYTHON_ONLY_INLINE_FLAG_PATTERNS: tuple[str, ...] = (
    "(?a:password)",
    "(?u:password)",
    "(?x:password)",
    "(?a)password",
    "(?u)password",
    "(?x)password",
    "(?L:password)",
    "(?L)password",
)


def _inline_flag_policy(pattern: str) -> dict:
    return {
        **_INLINE_FLAG_POLICY,
        "matchers": [
            {"id": "m", "kind": "regex", "pattern": pattern, "action": "redact"}
        ],
    }


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _PYTHON_ONLY_INLINE_FLAG_PATTERNS)
def test_python_only_inline_flag_rejected(pattern: str) -> None:
    """A Python-only scoped/global inline-flag group MUST be rejected by the
    Python SDK so a pattern TS cannot compile is also rejected on Python.

    Pre-fix Python ``re.compile`` accepted ``(?a:password)`` / ``(?u:...)`` /
    ``(?x:...)`` (and the global forms) while TS threw 'Invalid group' --
    one SDK silently had no redaction rule. Post-fix Python rejects them via
    the existing ``RelayPolicyError`` policy-load path (code RELAY-SDK-010).
    """
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(_inline_flag_policy(pattern))
    # Reuses an existing rejection reason -- no new code is invented. The
    # rejection lands on the same policy-load failure path as other
    # unsupported regex constructs (bad_regex / unsupported_inline_flag).
    reason = excinfo.value.details.get("reason")
    assert reason in ("bad_regex", "unsupported_inline_flag"), (
        f"unexpected rejection reason for {pattern!r}: {reason!r}"
    )


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _PYTHON_ONLY_INLINE_FLAG_PATTERNS)
def test_python_only_inline_flag_rejected_like_typescript(pattern: str) -> None:
    """Py<->TS parity: a Python-only inline-flag pattern that Python now
    rejects MUST also be rejected by the TS ``loadRedactionPolicy``.

    Authoritative when Node + the TS dist are present; skipped otherwise
    (offline tier-1). Asserts the two SDKs AGREE on reject for the same
    policy body.
    """
    outcome = _ts_load_outcome_via_node(_inline_flag_policy(pattern))
    if outcome is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language accept/reject parity cannot be checked"
        )
    assert outcome["ok"] is False, (
        f"TS unexpectedly ACCEPTED {pattern!r}: {outcome!r}; "
        "Py<->TS accept/reject parity broken"
    )


@pytest.mark.plumbing
def test_supported_inline_flag_not_over_rejected() -> None:
    """The supported ``(?i)foo`` matcher MUST still load on Python (the fix
    must not over-reject patterns BOTH runtimes accept)."""
    policy = RedactionPolicy.load(_inline_flag_policy("(?i)foo"))
    assert len(policy.matchers) == 1


@pytest.mark.plumbing
def test_supported_inline_flag_not_over_rejected_like_typescript() -> None:
    """Py<->TS parity: the supported ``(?i)foo`` matcher loads on BOTH SDKs.

    Guards against the fix over-rejecting a pattern both runtimes accept.
    Authoritative when Node + the TS dist are present; skipped otherwise.
    """
    outcome = _ts_load_outcome_via_node(_inline_flag_policy("(?i)foo"))
    if outcome is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language accept/reject parity cannot be checked"
        )
    assert outcome["ok"] is True, (
        f"TS unexpectedly REJECTED supported '(?i)foo': {outcome!r}"
    )


# ---------------------------------------------------------------------------
# VAL-REDACT-004 (HIGH / security): overlapping matcher spans merge to their
# INTERVAL UNION on BOTH runtimes. The Python interval-union merge landed as
# VAL-REDACT-002 (relay/packages/sdk-python/relay/redaction.py
# `_apply_matchers_to_string`); the TypeScript half landed as VAL-REDACT-004
# (packages/sdk-typescript/src/redaction.ts `applyMatchersToString`). This case
# was deliberately deferred from VAL-REDACT-002 until the TS fix existed: it is
# the live Node-subprocess byte-equality surface proving the two runtimes now
# emit byte-identical output for an overlapping-span payload.
#
# Two regex matchers whose spans overlap such that the LATER-sorted span starts
# inside the earlier (kept) span but extends BEYOND its end. On the input
# "alphabravosecret":
#   * matcher "left"  matches "alphabra"    -> span [0, 8)
#   * matcher "right" matches "bravosecret" -> span [5, 16)
# Sort key (start, -end) keeps "left" (start 0); pre-fix BOTH runtimes dropped
# "right" (skip-on-overlap) and spliced the tail back in as plaintext. Post-fix
# both extend the open interval to max(end) = 16 and redact the full union with
# one placeholder.
# ---------------------------------------------------------------------------

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
def test_overlapping_spans_union_byte_equal_typescript_via_node_subprocess() -> None:
    """Python and TS MUST emit byte-identical canonical bytes for a payload
    whose matcher spans overlap such that a later span extends past the kept
    span's end ("alphabravosecret").

    This is the VAL-REDACT-004 parity surface (folded obligation from
    VAL-REDACT-002): pre-fix both runtimes leaked the tail ("vosecret" on TS,
    a "secret" splice on Python); post-fix both redact the full interval union
    [0, 16) with one placeholder. The expected wire body is the leaf collapsed
    to a single ``<redacted>``.

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    payload = {"model_call": {"input": "alphabravosecret"}}
    ts_bytes = _ts_canonicalize_via_node(_OVERLAP_POLICY, payload, _TENANT_SALT)
    if ts_bytes is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language byte equality cannot be checked "
            "in this environment"
        )
    policy = RedactionPolicy.load(_OVERLAP_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    py_bytes = redact_capture_payload(engine, payload)
    assert py_bytes == ts_bytes, (
        "cross-language byte mismatch on overlapping-span union policy: "
        f"py={py_bytes!r} ts={ts_bytes!r}"
    )
    # And the union is fully redacted on the Python side: no leaked tail.
    assert b"secret" not in py_bytes
    assert b"bravo" not in py_bytes
    assert b"alpha" not in py_bytes
    assert b"<redacted>" in py_bytes


# ---------------------------------------------------------------------------
# VAL-REDACT-005 (MEDIUM / determinism): a non-finite numeric leaf
# (Infinity/-Infinity/NaN) at a non-pointer-matched path must FAIL CLOSED
# IDENTICALLY on both runtimes.
#
# Pre-fix divergence: ``_walk`` returns the number leaf unchanged (no pointer
# match), then the canonicalizers diverged:
#   * Python ``redact_capture_payload`` used ``json.dumps(...)`` with the
#     default ``allow_nan=True``, emitting literal ``Infinity``/``-Infinity``/
#     ``NaN`` tokens -- NON-canonical JSON, forbidden by RFC 8785 JCS.
#   * TS ``canonicalJsonStringify`` THREW a bare ``Error``
#     ("non-finite number not allowed").
# So the same payload produced invalid-but-accepted output on Python and an
# untyped throw on TS -- the two SDKs disagreed on outcome AND error shape.
#
# Post-fix (preferred per contract): BOTH reject non-finite numbers with a
# typed error carrying ``code == RELAY-SDK-010`` and
# ``details.reason == "non_finite_number"``.
# ---------------------------------------------------------------------------

# The marker the canonicalizers must surface in their structured details so
# both runtimes report the rejection identically.
_NON_FINITE_REASON = "non_finite_number"
_POLICY_INVALID_CODE = "RELAY-SDK-010"


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "name,value",
    [
        ("positive-infinity", float("inf")),
        ("negative-infinity", float("-inf")),
        ("nan", float("nan")),
    ],
)
def test_non_finite_number_leaf_rejected_python(name: str, value: float) -> None:
    """``redact_capture_payload`` MUST reject a non-finite numeric leaf with a
    typed ``RelayPolicyError`` instead of emitting ``Infinity``/``NaN`` tokens.

    RED at base commit c911607: ``json.dumps`` with the default
    ``allow_nan=True`` emitted the literal token (invalid JSON). GREEN after
    the fail-closed fix.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # The leaf is at a non-pointer-matched path (the base policy declares no
    # json_pointer matchers), so ``_walk`` passes the number through unchanged.
    payload = {"metrics": {"score": value}}
    with pytest.raises(RelayPolicyError) as excinfo:
        redact_capture_payload(engine, payload)
    assert excinfo.value.code == _POLICY_INVALID_CODE, (
        f"unexpected code: {excinfo.value.code!r}"
    )
    assert excinfo.value.details.get("reason") == _NON_FINITE_REASON, (
        f"unexpected reason: {excinfo.value.details!r}"
    )
    # And it MUST NOT have emitted a non-canonical token into wire bytes (the
    # pre-fix defect): the call raised before returning, so no body exists.
    # ``pytest.raises`` already guarantees no return value escaped; assert the
    # encoded reason marker drives the fail-closed path, not a serialized token.
    assert excinfo.value.code == _POLICY_INVALID_CODE


@pytest.mark.plumbing
def test_non_finite_number_in_array_rejected_python() -> None:
    """A non-finite number nested inside an array leaf is also rejected."""
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {"series": [1.0, 2.0, float("inf"), 4.0]}
    with pytest.raises(RelayPolicyError) as excinfo:
        redact_capture_payload(engine, payload)
    assert excinfo.value.details.get("reason") == _NON_FINITE_REASON


@pytest.mark.plumbing
def test_finite_number_leaf_still_serialized_python() -> None:
    """Regression guard: finite numbers (incl. large/negative/zero) still
    serialize unchanged -- the fail-closed check rejects ONLY non-finite.
    """
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {"a": 0, "b": -17, "c": 1.5, "d": 1e308}
    body = redact_capture_payload(engine, payload)
    assert body == b'{"a":0,"b":-17,"c":1.5,"d":1e+308}'


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "name,sentinel,py_value",
    [
        ("positive-infinity", "__RELAY_INFINITY__", float("inf")),
        ("negative-infinity", "__RELAY_NEG_INFINITY__", float("-inf")),
        ("nan", "__RELAY_NAN__", float("nan")),
    ],
)
def test_non_finite_number_rejected_both_runtimes_via_node_subprocess(
    name: str, sentinel: str, py_value: float
) -> None:
    """Python and TS MUST BOTH fail closed on a non-finite numeric leaf, with
    the SAME typed code (RELAY-SDK-010) and reason ("non_finite_number").

    This is the VAL-REDACT-005 parity surface: pre-fix the TS engine threw a
    bare Error while Python emitted invalid ``Infinity``/``NaN`` tokens -- the
    SDKs diverged. Post-fix both reject identically.

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    # The TS payload uses a sentinel string the Node reviver rehydrates into a
    # real non-finite number (JSON cannot carry Infinity/NaN literals).
    ts_payload = {"metrics": {"score": sentinel}}
    outcome = _ts_redact_outcome_via_node(_BASE_POLICY, ts_payload, _TENANT_SALT)
    if outcome is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language fail-closed parity cannot be checked "
            "in this environment"
        )
    # TS must REJECT (not emit bytes) with the shared typed shape.
    assert outcome["ok"] is False, (
        f"TS did not reject a non-finite leaf for {name!r}: {outcome!r}"
    )
    assert outcome["code"] == _POLICY_INVALID_CODE, (
        f"TS rejection code mismatch for {name!r}: {outcome!r}"
    )
    assert outcome["reason"] == _NON_FINITE_REASON, (
        f"TS rejection reason mismatch for {name!r}: {outcome!r}"
    )
    # Python must REJECT the equivalent payload with the SAME typed shape.
    policy = RedactionPolicy.load(_BASE_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    with pytest.raises(RelayPolicyError) as excinfo:
        redact_capture_payload(engine, {"metrics": {"score": py_value}})
    assert excinfo.value.code == outcome["code"], (
        f"Py/TS code divergence for {name!r}: "
        f"py={excinfo.value.code!r} ts={outcome['code']!r}"
    )
    assert excinfo.value.details.get("reason") == outcome["reason"], (
        f"Py/TS reason divergence for {name!r}: "
        f"py={excinfo.value.details!r} ts={outcome['reason']!r}"
    )


# ---------------------------------------------------------------------------
# VAL-REDACT-006 (MEDIUM / resource-leak): a policy-supplied regex was compiled
# directly from the policy ``pattern`` string and executed against an unbounded
# leaf with NO ReDoS / complexity guard. A catastrophic-backtracking pattern
# (e.g. ``(a+)+$``) plus a long near-matching input drives the backtracking
# engine to exponential work, blocking the caller synchronously on BOTH runtimes
# (Python ``re`` and V8 ``RegExp`` are both backtracking engines).
#
# The deterministic fix (no wall-clock assertions) has two layers, byte-for-byte
# identical across SDKs:
#   (a) a static ReDoS heuristic that REJECTS nested-quantifier patterns at
#       policy LOAD time with code ``RELAY-SDK-017`` and reason
#       ``redos_pattern``;
#   (b) a documented ``MAX_REDACTION_LEAF_LENGTH`` clamp applied to the leaf
#       string before matching, with a shared ``[relay:truncated]`` marker.
#
# These cases assert Python<->TypeScript parity: the same pattern is rejected
# at load on BOTH runtimes with the same code + reason (via the live Node
# subprocess), and the same cap constant clamps an over-cap leaf identically.
# ---------------------------------------------------------------------------

_REDOS_CODE = "RELAY-SDK-017"
_REDOS_REASON = "redos_pattern"

# The classic catastrophic-backtracking shape: a quantifier applied to a group
# that itself ends in a quantifier. The contract trigger ``(a+)+$`` is first.
# The last two are GROUP-PREFIX groups whose BODY (not the prefix) is quantified
# AND that carry an outer quantifier -- genuine ReDoS that the group-prefix-aware
# scan must STILL reject on BOTH runtimes (Gate-2 fix must not weaken detection).
_REDOS_PATTERNS = [
    "(a+)+$",
    "(a*)*$",
    "(a+)*",
    "(a*)+",
    "(.*a){10,}",
    r"(\w+\s?)*$",
    "(?:a+)+",
    "(?i)(?:secret+)+",
    # REDACT cluster Bug B: overlapping-alternation-under-quantifier. No inner
    # quantifier, so the original nested-quantifier heuristic MISSED these, yet
    # they backtrack super-linearly. Both runtimes MUST now reject them with the
    # same RELAY-SDK-017 / redos_pattern outcome.
    "(a|a)*b",
    "(a|a)+b",
    "(a|a){2,}b",
    "(?:a|a)*x",
    "(ab|a)*c",
    # Nested-wrapper bypass (roborev 7feb671 HIGH): the overlap is hidden one
    # level down -- the OUTER group has no top-level `|` and the INNER overlap
    # group is not itself quantified -- yet ((a|a))* is just as exponential as
    # (a|a)*. Both runtimes MUST reject these identically after propagating the
    # overlap signal up the group stack.
    "((a|a))*b",
    "(?:(?:a|a))*b",
    "((a|a))+y",
    "((a|a)){2,}z",
    "(((a|a)))+x",
    "((a|a)?)*w",
]

# Gate-2: legitimate GROUP-PREFIX constructs (non-capturing / inline-flag /
# lookaround) FOLLOWED by an outer quantifier. The introducing commit mis-read
# the prefix ``?`` as a quantifier and falsely rejected these with RELAY-SDK-017,
# disabling redaction for any policy that used them. They are LINEAR and MUST
# load on BOTH runtimes after the fix. (Python named-group forms ``(?P<...>)``
# are excluded here because both SDKs reject them for the separate
# ``named_group_unsupported`` dialect reason, not redos.)
_GROUP_PREFIX_SAFE_PATTERNS = [
    "(?:abc)+",
    "(?i)(?:secret)+",
    "(?:sk-|key_)+[A-Za-z0-9]{20,}",
    "(?=foo)bar+",
    "(?!foo)bar+",
    "(?<=foo)bar+",
    "(?<!foo)bar+",
    "(?s)(?:.+)x",
]


def _redos_policy(pattern: str) -> dict:
    return {
        "schema_version": "relay.redaction.v1",
        "policy_version": "2026-05-29.redos",
        "raw_capture": False,
        "retention_days": 30,
        "dpa_ref": None,
        "approver_user_id": None,
        "matchers": [
            {"id": "redos", "kind": "regex", "pattern": pattern, "action": "redact"}
        ],
        "action_policy": {
            "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_v3"},
            "redact": {"placeholder": "<redacted>"},
            "drop": {"placeholder": None},
        },
        "applies_to_fields": list(DEFAULT_APPLIES_TO_FIELDS),
    }


def _ts_load_outcome_via_node(policy_body: dict) -> dict | None:
    """Invoke the TS ``loadRedactionPolicy`` via Node and report its OUTCOME.

    Returns ``{"ok": True}`` when the policy loads, or ``{"ok": False,
    "code": ..., "reason": ..., "message": ...}`` when ``loadRedactionPolicy``
    raises. Returns ``None`` when Node or the TS build are unavailable; the
    caller should skip rather than fail (offline / pre-build).
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
import {{ loadRedactionPolicy }} from {ts_dist_json};

const stdin = await new Promise((resolve) => {{
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => {{ buf += c; }});
  process.stdin.on('end', () => resolve(buf));
}});
const input = JSON.parse(stdin);
try {{
  loadRedactionPolicy(input.policy);
  process.stdout.write(JSON.stringify({{ ok: true }}));
}} catch (err) {{
  process.stdout.write(JSON.stringify({{
    ok: false,
    code: err && err.code ? err.code : null,
    reason: err && err.details ? (err.details.reason ?? null) : null,
    message: err && err.message ? err.message : String(err),
    name: err && err.name ? err.name : null,
  }}));
}}
"""
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps({"policy": policy_body}),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"node TS subprocess failed: rc={proc.returncode} stderr={proc.stderr!r}"
        )
    return json.loads(proc.stdout.strip())


def _ts_max_leaf_length_via_node() -> int | None:
    """Return the TS ``MAX_REDACTION_LEAF_LENGTH`` constant via Node.

    Returns ``None`` when Node / the TS dist are unavailable.
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
import {{ MAX_REDACTION_LEAF_LENGTH }} from {ts_dist_json};
process.stdout.write(String(MAX_REDACTION_LEAF_LENGTH));
"""
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"node TS subprocess failed: rc={proc.returncode} stderr={proc.stderr!r}"
        )
    return int(proc.stdout.strip())


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _REDOS_PATTERNS)
def test_redos_pattern_rejected_at_load_python(pattern: str) -> None:
    """A nested-quantifier (catastrophic-backtracking) pattern MUST be rejected
    by ``RedactionPolicy.load`` with code ``RELAY-SDK-017`` / reason
    ``redos_pattern`` -- the pattern is never compiled or executed.
    """
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(_redos_policy(pattern))
    assert excinfo.value.code == _REDOS_CODE, (
        f"unexpected code for {pattern!r}: {excinfo.value.code!r}"
    )
    assert excinfo.value.details.get("reason") == _REDOS_REASON, (
        f"unexpected reason for {pattern!r}: {excinfo.value.details!r}"
    )


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "pattern",
    [
        "(sk-|key_)[A-Za-z0-9]{20,}",
        r"[\w.+-]+@[\w-]+\.[\w.-]+",
        "(?i)password",
        "(?i)api[_-]?key",
        "(sk-|sk-ant-)[A-Za-z0-9]+",
        # Gate-2: quantified group-prefix constructs MUST load (the prefix ``?``
        # is not a quantifier).
        *_GROUP_PREFIX_SAFE_PATTERNS,
    ],
)
def test_safe_patterns_not_rejected_python(pattern: str) -> None:
    """The ReDoS heuristic MUST NOT reject the default-policy patterns (single,
    non-nested quantifiers) NOR a legitimate group-prefix construct followed by
    an outer quantifier; rejecting them would break every real policy.
    """
    RedactionPolicy.load(_redos_policy(pattern))


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _GROUP_PREFIX_SAFE_PATTERNS)
def test_group_prefix_pattern_loads_both_runtimes_via_node_subprocess(
    pattern: str,
) -> None:
    """Python and TS MUST BOTH ACCEPT a legitimate group-prefix construct
    followed by an outer quantifier at LOAD time (Gate-2 parity surface).

    Pre-fix both runtimes mis-read the prefix ``?`` as a quantifier and rejected
    these with RELAY-SDK-017 -- redaction was disabled for the policy. Post-fix
    both load them identically.

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    outcome = _ts_load_outcome_via_node(_redos_policy(pattern))
    if outcome is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language group-prefix acceptance parity cannot "
            "be checked in this environment"
        )
    assert outcome["ok"] is True, (
        f"TS falsely rejected group-prefix pattern {pattern!r}: {outcome!r}"
    )
    # Python must ACCEPT the same pattern (no exception).
    RedactionPolicy.load(_redos_policy(pattern))


@pytest.mark.plumbing
@pytest.mark.parametrize("pattern", _REDOS_PATTERNS)
def test_redos_pattern_rejected_both_runtimes_via_node_subprocess(
    pattern: str,
) -> None:
    """Python and TS MUST BOTH reject a catastrophic-backtracking pattern at
    LOAD time, with the SAME typed code (RELAY-SDK-017) and reason
    ("redos_pattern").

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    outcome = _ts_load_outcome_via_node(_redos_policy(pattern))
    if outcome is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language ReDoS-rejection parity cannot be "
            "checked in this environment"
        )
    assert outcome["ok"] is False, (
        f"TS did not reject ReDoS pattern {pattern!r}: {outcome!r}"
    )
    assert outcome["code"] == _REDOS_CODE, (
        f"TS rejection code mismatch for {pattern!r}: {outcome!r}"
    )
    assert outcome["reason"] == _REDOS_REASON, (
        f"TS rejection reason mismatch for {pattern!r}: {outcome!r}"
    )
    with pytest.raises(RelayPolicyError) as excinfo:
        RedactionPolicy.load(_redos_policy(pattern))
    assert excinfo.value.code == outcome["code"], (
        f"Py/TS code divergence for {pattern!r}: "
        f"py={excinfo.value.code!r} ts={outcome['code']!r}"
    )
    assert excinfo.value.details.get("reason") == outcome["reason"], (
        f"Py/TS reason divergence for {pattern!r}: "
        f"py={excinfo.value.details!r} ts={outcome['reason']!r}"
    )


@pytest.mark.plumbing
def test_max_leaf_length_clamps_over_cap_leaf_python() -> None:
    """An over-cap leaf is clamped to ``MAX_REDACTION_LEAF_LENGTH`` before
    matching; the output carries the deterministic ``[relay:truncated]`` marker
    and is shorter than the original (the full leaf is never matched).
    """
    from relay.redaction import MAX_REDACTION_LEAF_LENGTH

    assert isinstance(MAX_REDACTION_LEAF_LENGTH, int)
    assert MAX_REDACTION_LEAF_LENGTH > 0
    policy = RedactionPolicy.load(_redos_policy("zzz"))
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    over_cap = "x" * (MAX_REDACTION_LEAF_LENGTH + 1000)
    redacted = engine.redact({"model_call": {"input": over_cap}})
    out = redacted["model_call"]["input"]
    assert isinstance(out, str)
    assert len(out) < len(over_cap)
    assert "[relay:truncated]" in out


@pytest.mark.plumbing
def test_max_leaf_length_constant_matches_typescript_via_node_subprocess() -> None:
    """The Python and TS ``MAX_REDACTION_LEAF_LENGTH`` constants MUST be equal
    (Pattern B/C parity: same clamp on both SDKs).

    Skipped when Node / the TS dist are unavailable.
    """
    from relay.redaction import MAX_REDACTION_LEAF_LENGTH

    ts_cap = _ts_max_leaf_length_via_node()
    if ts_cap is None:
        pytest.skip(
            "node binary or TS dist not available; cross-language clamp "
            "constant parity cannot be checked in this environment"
        )
    assert ts_cap == MAX_REDACTION_LEAF_LENGTH, (
        f"cap constant divergence: py={MAX_REDACTION_LEAF_LENGTH} ts={ts_cap}"
    )


# ---------------------------------------------------------------------------
# VAL-REDACT-007 parity (Gate-1 scrutiny finding): the two SDKs grouped
# combining marks into the preceding base segment by DIFFERENT predicates in
# ``_fold_with_origin`` (Python) / ``foldWithOrigin`` (TS):
#
#   * Python: ``unicodedata.combining(ch) != 0`` -- TRUE only for a NON-ZERO
#     canonical combining class.
#   * TS:     ``\p{Mn}|\p{Mc}|\p{Me}`` -- TRUE for ALL Mark categories.
#
# A class-0 SPACING combining mark such as U+0903 (DEVANAGARI SIGN VISARGA,
# category Mc, canonical combining class 0) is matched by the TS predicate but
# NOT by the Python one. So for an input that contains such a mark, TS absorbs
# it into the preceding base segment while Python starts a NEW segment -- the
# fold-with-origin offset maps diverge, and a matched span maps to a DIFFERENT
# original slice on each runtime. Worst case is fail-closed over-redaction
# (never a leak), but it breaks the keystone Python<->TypeScript byte-equality
# contract.
#
# The fix unifies the grouping rule to Unicode MARK CATEGORY (Mn/Mc/Me) on BOTH
# sides (Option a): Python switches to
# ``unicodedata.category(ch) in {"Mn","Mc","Me"}`` and TS keeps its existing
# ``\p{Mn}|\p{Mc}|\p{Me}`` test. After the fix the two engines group the
# IDENTICAL set of code points and emit byte-identical redaction output.
#
# Source stays ASCII per CLAUDE.md "ASCII-Safe Source": the combining marks are
# written as ``\uXXXX`` escapes, never raw glyphs.
# ---------------------------------------------------------------------------

# U+0903 DEVANAGARI SIGN VISARGA: category Mc, canonical combining class 0.
# This is the precise code point on which the two predicates disagreed.
# Written as a ``\uXXXX`` escape so the source stays pure ASCII (CLAUDE.md).
_VISARGA = "\u0903"
# U+0BBE TAMIL VOWEL SIGN AA: a second category-Mc, combining-class-0 mark, so
# the parity surface is not pinned to a single code point.
_TAMIL_VOWEL_SIGN_AA = "\u0bbe"
# U+0308 COMBINING DIAERESIS: a class-230 (non-zero) mark -- matched by BOTH
# predicates already, included so the round-trip fixture mixes a class-0 and a
# non-zero-class mark.
_COMBINING_DIAERESIS_MARK = "\u0308"

# A policy whose only matcher redacts the literal ``SECRET`` so we can place a
# class-0 spacing mark immediately AFTER a matched span and observe whether the
# splice consumes it.
_VISARGA_SECRET_POLICY: dict = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "2026-05-29.visarga",
    "raw_capture": False,
    "retention_days": 30,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {"id": "secret", "kind": "regex", "pattern": "SECRET", "action": "redact"},
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "tenant_salt_v3"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
    "applies_to_fields": list(DEFAULT_APPLIES_TO_FIELDS),
}


@pytest.mark.plumbing
def test_class0_spacing_mark_segments_identically_python_local() -> None:
    """Python ``_fold_with_origin`` MUST group a class-0 spacing combining mark
    (U+0903) into the preceding base segment, identically to the TS predicate.

    Pre-fix Python used ``unicodedata.combining(ch) != 0``; U+0903 has combining
    class 0, so Python started a NEW segment for it while TS (``\\p{Mc}``)
    absorbed it. Post-fix Python groups by category (Mn/Mc/Me), so the mark is
    absorbed into the preceding base's segment -- every folded code point of the
    base+mark sequence maps to the FULL base+mark original span.
    """
    from relay.redaction import _fold_with_origin

    # 'a' (base) + VISARGA + 'b' (base). After the fix the VISARGA shares the
    # 'a' segment, so folded[0] ('a') and folded[1] (VISARGA) BOTH map to the
    # half-open original span [0, 2).
    value = "a" + _VISARGA + "b"
    folded, origin_starts, origin_ends = _fold_with_origin(value)
    # Detection surface is unchanged (NFKC keeps the three code points here).
    assert folded == value
    # The base 'a' (index 0) and the VISARGA (index 1) MUST share one segment
    # spanning [0, 2). Pre-fix the VISARGA was its own segment: starts/ends
    # would have been [0, 1, 2] / [1, 2, 3].
    assert origin_starts == [0, 0, 2], (
        f"class-0 mark not grouped with base: starts={origin_starts}"
    )
    assert origin_ends == [2, 2, 3], (
        f"class-0 mark not grouped with base: ends={origin_ends}"
    )


@pytest.mark.plumbing
def test_class0_spacing_mark_redaction_byte_equal_typescript_via_node_subprocess() -> (  # noqa: E501
    None
):
    """Python and TS MUST emit byte-identical canonical bytes for a leaf
    containing a class-0 SPACING combining mark (U+0903) immediately after a
    matched secret.

    This is the VAL-REDACT-007 parity surface (Gate-1 scrutiny finding).
    Pre-fix the two engines DIVERGED on ``"pre SECRET<VISARGA> tail"``:

      * Python (``combining != 0``): the VISARGA was its own segment, so the
        ``SECRET`` match mapped to the original span NOT including the VISARGA
        -- output ``"pre <redacted><VISARGA> tail"`` (VISARGA survives next to
        the placeholder).
      * TS (``\\p{Mc}``): the VISARGA was absorbed into the preceding base
        segment, so the match consumed it -- output ``"pre <redacted> tail"``.

    Post-fix both group by Mark category, so both consume the VISARGA and emit
    byte-identical bytes. This proves the class-0 spacing mark segments
    identically and never leaks (fail-closed over-redaction at worst).

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    payload = {"model_call": {"input": "pre SECRET" + _VISARGA + " tail"}}
    ts_bytes = _ts_canonicalize_via_node(
        _VISARGA_SECRET_POLICY, payload, _TENANT_SALT
    )
    if ts_bytes is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language byte equality cannot be checked "
            "in this environment"
        )
    policy = RedactionPolicy.load(_VISARGA_SECRET_POLICY)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    py_bytes = redact_capture_payload(engine, payload)
    assert py_bytes == ts_bytes, (
        "cross-language byte mismatch on class-0 spacing-mark (U+0903) "
        f"redaction: py={py_bytes!r} ts={ts_bytes!r}"
    )
    # Behavioural anchor: the VISARGA MUST NOT survive adjacent to the
    # placeholder on EITHER side (the match span consumed it).
    out = engine.redact(payload)["model_call"]["input"]
    assert out == "pre <redacted> tail", f"unexpected splice result: out={out!r}"
    assert _VISARGA not in out, f"class-0 mark leaked next to placeholder: {out!r}"


@pytest.mark.plumbing
def test_class0_spacing_mark_non_secret_round_trips_byte_equal_typescript() -> None:
    """A NON-secret string containing class-0 spacing combining marks (U+0903,
    U+0BBE) and a non-zero-class mark (U+0308) MUST round-trip UNCHANGED and
    byte-identically on Python and TS (the missing-coverage fixture the
    reviewer flagged).

    No matcher fires, so the engine emits the ORIGINAL code points verbatim on
    both runtimes (VAL-REDACT-007: the fold is a detection aid only). This
    guards against over-redaction / silent transliteration of legitimate
    combining-mark content, and confirms the unified segmentation rule does not
    perturb the unmatched-leaf path.

    Skipped when Node or the TS dist are unavailable (offline tier-1); when
    present the test is authoritative.
    """
    # A benign sentence-shaped leaf mixing a base+class-0-mark sequence, a
    # base+class-0-mark sequence (Tamil), and a base+non-zero-class mark
    # (combining diaeresis) -- none of which any matcher in the base policy
    # touches.
    benign = (
        "namaste a" + _VISARGA + " ka" + _TAMIL_VOWEL_SIGN_AA + " u"
        + _COMBINING_DIAERESIS_MARK + " ok"
    )
    payload = {"model_call": {"input": benign}}
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
        "cross-language byte mismatch on non-secret combining-mark round-trip: "
        f"py={py_bytes!r} ts={ts_bytes!r}"
    )
    # The leaf MUST be reproduced verbatim (no redaction, no transliteration).
    out = engine.redact(payload)["model_call"]["input"]
    assert out == benign, f"non-secret combining-mark leaf was altered: {out!r}"
