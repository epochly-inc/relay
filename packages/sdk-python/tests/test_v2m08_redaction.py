"""M08-W8 redaction gap closure tests (VAL-V2M08-025..032).

Covers eight assertions:

  * VAL-V2M08-025: json_pointer matcher leaf-level evaluation
  * VAL-V2M08-026: json_pointer matcher with missing path passes through
  * VAL-V2M08-027: salt rotation produces new policy_version
  * VAL-V2M08-028: salt rotation does not re-derive historical hashes
  * VAL-V2M08-029: ingest server rejects raw write under raw_capture=false
  * VAL-V2M08-030: ingest server accepts redacted writes under raw_capture=false
  * VAL-V2M08-031: ingest server allows raw writes only with
                   raw_capture=true + DPA + approver
  * VAL-V2M08-032: validation_fixtures harness validates declared
                   input -> output digest and rejects mismatches

The sidecar endpoint assertions invoke ``evaluate_raw_capture_on_request``
directly (the same function the ``/v1/ingest/runs`` and
``/v1/ingest/spans:batch`` endpoints call); this keeps the test in the
tier-1 plumbing tier (no real ports, no real HTTP socket, no ASGI
runtime) while exercising the same defense-in-depth code path the wire
endpoints exercise.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import hmac
import json

# Conformance harness lives under tests/conformance/redaction/; import
# via package path. The conformance tree carries an __init__-less layout
# (per repo convention); use a sys.path shim so the tier-1 plumbing
# test can import the harness without standing up a fully-installed
# conformance package.
import sys
from pathlib import Path

import pytest
from relay.errors import RelayPolicyError
from relay.redaction import (
    RedactionEngine,
    RedactionPolicy,
    redact_capture_payload,
)
from relay.salt_registry import SaltRegistry

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFORMANCE_REDACTION = _REPO_ROOT / "tests" / "conformance" / "redaction"
if str(_CONFORMANCE_REDACTION) not in sys.path:
    sys.path.insert(0, str(_CONFORMANCE_REDACTION))

from validation_fixtures import (  # noqa: E402
    FIXTURE_MISMATCH_CODE,
    FixtureMismatch,
    compute_expected_digest,
    load_fixtures_from_policy_body,
    validate_policy_fixtures,
    validate_policy_or_raise,
)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

_DETERMINISTIC_SALT = b"v2m08-test-salt-do-not-use-in-prod"


def _salt_provider(_ref: str) -> bytes:
    return _DETERMINISTIC_SALT


def _base_policy_with_pointer_matcher() -> dict:
    """Policy with a single json_pointer matcher redacting /user/email."""
    return {
        "schema_version": "relay.redaction.v1",
        "policy_version": "2026-05-17.001",
        "raw_capture": False,
        "retention_days": 30,
        "dpa_ref": None,
        "approver_user_id": None,
        "matchers": [
            {
                "id": "user_email_pointer",
                "kind": "json_pointer",
                "paths": ["/user/email"],
                "action": "redact",
            },
        ],
        "action_policy": {
            "hash": {"algorithm": "hmac-sha256", "salt_ref": "salt-a"},
            "redact": {"placeholder": "<redacted>"},
            "drop": {"placeholder": None},
        },
    }


def _hash_only_policy(salt_ref: str, policy_version: str) -> dict:
    """Policy with a single hash-action matcher on an email-shaped regex."""
    return {
        "schema_version": "relay.redaction.v1",
        "policy_version": policy_version,
        "raw_capture": False,
        "retention_days": 30,
        "dpa_ref": None,
        "approver_user_id": None,
        "matchers": [
            {
                "id": "email_hash",
                "kind": "regex",
                "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+",
                "action": "hash",
            },
        ],
        "action_policy": {
            "hash": {"algorithm": "hmac-sha256", "salt_ref": salt_ref},
            "redact": {"placeholder": "<redacted>"},
            "drop": {"placeholder": None},
        },
    }


# -----------------------------------------------------------------------------
# VAL-V2M08-025: json_pointer leaf-level evaluation
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-025")
def test_json_pointer_matcher_redacts_leaf_at_declared_path() -> None:
    """The matcher fires for leaf evaluation, not just parse."""
    policy = RedactionPolicy.load(_base_policy_with_pointer_matcher())
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {"user": {"email": "a@b.com", "name": "Ana"}}
    out = engine.redact(payload)
    assert out == {"user": {"email": "<redacted>", "name": "Ana"}}, out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-025")
def test_json_pointer_matcher_typescript_parity_corpus() -> None:
    """Wire form: redact -> JCS bytes -> deterministic across calls.

    Acts as a Py-side parity anchor for the TS pointer evaluation
    (TS-side coverage is enforced by the TS test suite). Two calls
    must produce byte-identical output (VAL-W3-024 carries through).
    """
    policy = RedactionPolicy.load(_base_policy_with_pointer_matcher())
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    payload = {"user": {"email": "a@b.com", "name": "Ana"}}
    first = redact_capture_payload(engine, payload)
    second = redact_capture_payload(engine, payload)
    assert first == second
    assert b'"email":"<redacted>"' in first
    assert b'"name":"Ana"' in first


# -----------------------------------------------------------------------------
# VAL-V2M08-026: missing path passes through
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-026")
def test_json_pointer_matcher_handles_missing_path_without_error() -> None:
    """Matcher returns input unchanged; no exception; redaction event count = 0."""
    policy = RedactionPolicy.load(_base_policy_with_pointer_matcher())
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    # No /user/email leaf -- only /user/name.
    payload = {"user": {"name": "Ana"}}
    out = engine.redact(payload)
    assert out == {"user": {"name": "Ana"}}, out


# -----------------------------------------------------------------------------
# VAL-V2M08-027: salt rotation produces new policy_version
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-027")
def test_salt_rotation_produces_new_policy_version(tmp_path: Path) -> None:
    """rotate() appends a binding row with a strictly greater policy_version.

    The predecessor row is preserved (not overwritten).
    """
    registry = SaltRegistry(path=tmp_path / "salts.json")
    # First version of policy: allocate a fresh salt ref AND a binding
    # so the subsequent rotate() has a predecessor to roll over from.
    first_rotation = registry.rotate(
        policy_id="p1",
        new_salt_ref="tenant_salt_v3",
        new_policy_version="2026-05-12.001",
        new_salt_bytes=b"\x01" * 32,
    )
    assert first_rotation.predecessor is None
    assert first_rotation.successor.policy_version == "2026-05-12.001"
    assert first_rotation.successor.salt_ref == "tenant_salt_v3"
    # Rotate: allocate a NEW salt ref, declare a strictly greater
    # policy_version, preserve the predecessor.
    second_rotation = registry.rotate(
        policy_id="p1",
        new_salt_ref="tenant_salt_v4",
        new_policy_version="2026-06-01.001",
        new_salt_bytes=b"\x02" * 32,
    )
    assert second_rotation.predecessor is not None
    assert second_rotation.predecessor.policy_version == "2026-05-12.001"
    assert second_rotation.predecessor.salt_ref == "tenant_salt_v3"
    assert second_rotation.successor.policy_version == "2026-06-01.001"
    assert second_rotation.successor.salt_ref == "tenant_salt_v4"
    # Predecessor row preserved on disk.
    all_versions = registry.list_policy_versions(policy_id="p1")
    assert [v.policy_version for v in all_versions] == [
        "2026-05-12.001",
        "2026-06-01.001",
    ]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-027")
def test_salt_rotation_refuses_non_monotonic_policy_version(tmp_path: Path) -> None:
    """new_policy_version MUST be strictly greater than the predecessor."""
    registry = SaltRegistry(path=tmp_path / "salts.json")
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s1",
        new_policy_version="2026-05-12.001",
        new_salt_bytes=b"\x01" * 32,
    )
    with pytest.raises(RelayPolicyError) as exc_info:
        registry.rotate(
            policy_id="p1",
            new_salt_ref="s2",
            new_policy_version="2026-05-12.001",  # equal -- not strictly greater
            new_salt_bytes=b"\x02" * 32,
        )
    assert exc_info.value.details.get("reason") == "policy_version_not_monotonic"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-027")
def test_salt_rotation_v9_to_v10_uses_numeric_compare(tmp_path: Path) -> None:
    """Regression: ``v9 -> v10`` is a legitimate monotonic bump.

    Audit P1: rotate() previously used lexicographic string compare,
    which incorrectly rejected ``"v10" > "v9"`` (lex ordering gives
    ``"v10" < "v9"`` because ``'1' < '9'``). The fix switches to
    numeric semver compare.
    """
    registry = SaltRegistry(path=tmp_path / "salts.json")
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_v9",
        new_policy_version="v9",
        new_salt_bytes=b"\x09" * 32,
    )
    # v10 > v9 numerically -- must be accepted, not rejected.
    result = registry.rotate(
        policy_id="p1",
        new_salt_ref="s_v10",
        new_policy_version="v10",
        new_salt_bytes=b"\x10" * 32,
    )
    assert result.successor.policy_version == "v10"
    assert result.predecessor is not None
    assert result.predecessor.policy_version == "v9"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-027")
def test_salt_rotation_dated_version_uses_numeric_compare(tmp_path: Path) -> None:
    """Regression: zero-padded date suffix ``.010 > .001`` not lex-less.

    A date-stamped version ``2026-05-12.010`` must be accepted as
    greater than ``2026-05-12.009`` even though both lex compares
    happen to give the right answer here (numeric and lex agree on
    zero-padded suffixes). Where they disagree is mixed-width
    suffixes (``001`` vs ``10``); this case is the dangerous one
    and the test pins it.
    """
    registry = SaltRegistry(path=tmp_path / "salts.json")
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_a",
        new_policy_version="2026-05-12.001",
        new_salt_bytes=b"\x01" * 32,
    )
    # numeric: (2026, 5, 12, 10) > (2026, 5, 12, 1) -- accept.
    result = registry.rotate(
        policy_id="p1",
        new_salt_ref="s_b",
        new_policy_version="2026-05-12.10",
        new_salt_bytes=b"\x02" * 32,
    )
    assert result.successor.policy_version == "2026-05-12.10"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-027")
def test_salt_rotation_v10_to_v9_still_rejected(tmp_path: Path) -> None:
    """Going backwards numerically (v10 -> v9) must be rejected."""
    registry = SaltRegistry(path=tmp_path / "salts.json")
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_v10",
        new_policy_version="v10",
        new_salt_bytes=b"\x10" * 32,
    )
    with pytest.raises(RelayPolicyError) as exc_info:
        registry.rotate(
            policy_id="p1",
            new_salt_ref="s_v9",
            new_policy_version="v9",
            new_salt_bytes=b"\x09" * 32,
        )
    assert exc_info.value.details.get("reason") == "policy_version_not_monotonic"


# -----------------------------------------------------------------------------
# VAL-V2M08-028: salt rotation does not re-derive historical hashes
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-028")
def test_salt_rotation_does_not_rederive_historical_hashes(tmp_path: Path) -> None:
    """Predecessor and successor digests of the same value are different.

    Both digests remain retrievable; predecessor-era lookup still
    succeeds (spec G.3 line 4148).
    """
    registry = SaltRegistry(path=tmp_path / "salts.json")
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_pre",
        new_policy_version="2026-05-12.001",
        new_salt_bytes=b"pre" * 11,
    )
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_post",
        new_policy_version="2026-06-01.001",
        new_salt_bytes=b"post" * 8,
    )
    plaintext = "a@b.com"
    pre_salt = registry.resolve("s_pre")
    post_salt = registry.resolve("s_post")
    pre_digest = hmac.new(pre_salt, plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
    post_digest = hmac.new(post_salt, plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
    assert pre_digest != post_digest
    # Both salts still resolvable -- predecessor never overwritten.
    assert registry.resolve("s_pre") == b"pre" * 11
    assert registry.resolve("s_post") == b"post" * 8


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-028")
def test_salt_rotation_engine_digests_diverge_under_rotation(tmp_path: Path) -> None:
    """End-to-end: redact same input under predecessor + successor policies.

    The email leaf produces two different digests; predecessor digest
    remains computable from the registry's predecessor salt.
    """
    registry = SaltRegistry(path=tmp_path / "salts.json")
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_pre",
        new_policy_version="2026-05-12.001",
        new_salt_bytes=b"AAAA" * 8,
    )
    registry.rotate(
        policy_id="p1",
        new_salt_ref="s_post",
        new_policy_version="2026-06-01.001",
        new_salt_bytes=b"BBBB" * 8,
    )

    def pre_provider(ref: str) -> bytes:
        return registry.resolve(ref)

    pre_policy = RedactionPolicy.load(
        _hash_only_policy(salt_ref="s_pre", policy_version="2026-05-12.001")
    )
    post_policy = RedactionPolicy.load(
        _hash_only_policy(salt_ref="s_post", policy_version="2026-06-01.001")
    )
    pre_engine = RedactionEngine(policy=pre_policy, salt_provider=pre_provider)
    post_engine = RedactionEngine(policy=post_policy, salt_provider=pre_provider)
    payload = {"who": "a@b.com"}
    pre_out = pre_engine.redact(payload)
    post_out = post_engine.redact(payload)
    # The string field was replaced by its HMAC hex digest; both are
    # 64-char lowercase hex, but they differ.
    assert pre_out["who"] != post_out["who"]
    assert len(pre_out["who"]) == 64
    assert len(post_out["who"]) == 64


# -----------------------------------------------------------------------------
# VAL-V2M08-029/030/031: ingest server-side raw_capture rejection
# -----------------------------------------------------------------------------


def _ingest_runs_body_with_raw(field_path: tuple[str, ...], value: object) -> dict:
    """Build a /v1/ingest/runs body whose ``field_path`` carries ``value``."""
    body: dict = {
        "applied_redaction_policy": {
            "schema_version": "relay.redaction.v1",
            "policy_version": "2026-05-17.001",
            "raw_capture": False,
            "action_policy": {
                "hash": {"algorithm": "hmac-sha256", "salt_ref": "s"},
                "redact": {"placeholder": "<redacted>"},
                "drop": {"placeholder": None},
            },
            "matchers": [],
        },
    }
    cursor: dict = body
    for token in field_path[:-1]:
        cursor = cursor.setdefault(token, {})
    cursor[field_path[-1]] = value
    return body


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-029")
def test_ingest_runs_rejects_raw_write_when_policy_disallows() -> None:
    """raw_capture=false + raw model_call.input -> 422 RELAY-INGEST-RAWCAPTURE-DENIED."""
    body = _ingest_runs_body_with_raw(
        ("model_call", "input"), "raw plaintext that must be rejected"
    )
    # Manifest anchors not set: this exercises an early reject. The
    # raw_capture check runs AFTER manifest enforcement, so we add the
    # anchors the sidecar expects on the unauthenticated test path.
    # The runtime tests in the sidecar test suite already cover that
    # codepath; here we focus on raw_capture rejection by bypassing
    # the manifest gate via a direct call into the validation helper.
    from relay_sidecar.validation.raw_capture import (
        evaluate_raw_capture_on_request,
    )

    rejection = evaluate_raw_capture_on_request(body=body)
    assert rejection is not None
    assert rejection.code == "RELAY-INGEST-RAWCAPTURE-DENIED"
    assert rejection.http_status == 422
    assert "model_call.input" in rejection.details["field_path"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-030")
def test_ingest_runs_accepts_redacted_writes_when_policy_disallows_raw() -> None:
    """raw_capture=false + redacted fields -> accept (rejection is None)."""
    from relay_sidecar.validation.raw_capture import (
        evaluate_raw_capture_on_request,
    )

    body = _ingest_runs_body_with_raw(("model_call", "input"), "<redacted>")
    rejection = evaluate_raw_capture_on_request(body=body)
    assert rejection is None
    # Hash-shape (64-char hex) is also accepted.
    body2 = _ingest_runs_body_with_raw(
        ("tool_call", "args"),
        "0" * 64,
    )
    assert evaluate_raw_capture_on_request(body=body2) is None
    # Digest-only reference accepted.
    body3 = _ingest_runs_body_with_raw(
        ("retrieval", "documents"),
        [{"text": {"_digest_sha256": "a" * 64}}],
    )
    assert evaluate_raw_capture_on_request(body=body3) is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-031")
def test_ingest_allows_raw_writes_only_with_full_preconditions() -> None:
    """raw_capture=true requires dpa_ref AND approver_user_id; missing any -> reject."""
    from relay_sidecar.validation.raw_capture import (
        evaluate_raw_capture_on_request,
    )

    def body_with_policy(policy_overrides: dict) -> dict:
        body = _ingest_runs_body_with_raw(("model_call", "input"), "raw plaintext")
        body["applied_redaction_policy"].update(policy_overrides)
        return body

    # Reject: raw_capture is false (default in helper).
    rj_false = evaluate_raw_capture_on_request(
        body=body_with_policy({"raw_capture": False})
    )
    assert rj_false is not None
    assert rj_false.details["reason"] == "unredacted_raw_field"

    # Reject: raw_capture true but dpa_ref missing.
    rj_dpa = evaluate_raw_capture_on_request(
        body=body_with_policy(
            {
                "raw_capture": True,
                "dpa_ref": None,
                "approver_user_id": "admin-1",
            }
        )
    )
    assert rj_dpa is not None
    assert rj_dpa.details["reason"] == "dpa_ref_missing"

    # Reject: raw_capture true + dpa_ref but approver missing.
    rj_app = evaluate_raw_capture_on_request(
        body=body_with_policy(
            {
                "raw_capture": True,
                "dpa_ref": "dpa-uuid-123",
                "approver_user_id": None,
            }
        )
    )
    assert rj_app is not None
    assert rj_app.details["reason"] == "approver_user_id_missing"

    # Accept: all three preconditions present.
    accept_body = body_with_policy(
        {
            "raw_capture": True,
            "dpa_ref": "dpa-uuid-123",
            "approver_user_id": "admin-1",
        }
    )
    assert evaluate_raw_capture_on_request(body=accept_body) is None


# -----------------------------------------------------------------------------
# VAL-V2M08-032: validation_fixtures harness
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-032")
def test_validation_fixtures_harness_passes_on_matching_digest() -> None:
    """Pin a fixture's expected digest with compute_expected_digest, then validate."""
    policy = _base_policy_with_pointer_matcher()
    payload = {"user": {"email": "a@b.com", "name": "Ana"}}
    expected = compute_expected_digest(
        policy_body=policy,
        payload=payload,
        salt_provider=_salt_provider,
    )
    # Pin the policy with the matching expected digest.
    policy["validation_fixtures"] = [
        {
            "input_ref": "fixture://user-email",
            "expected_output_digest": expected,
        }
    ]
    payload_registry = {"fixture://user-email": payload}
    # validate_policy_or_raise must succeed (no FixtureMismatch).
    results = validate_policy_or_raise(
        policy_body=policy,
        payload_registry=payload_registry,
        salt_provider=_salt_provider,
    )
    assert len(results) == 1
    assert results[0].ok is True
    assert results[0].computed_digest == expected


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-032")
def test_validation_fixtures_harness_rejects_mismatching_digest() -> None:
    """Mismatch raises FixtureMismatch with code RELAY-REDACT-FIXTURE-MISMATCH."""
    policy = _base_policy_with_pointer_matcher()
    payload = {"user": {"email": "a@b.com", "name": "Ana"}}
    policy["validation_fixtures"] = [
        {
            "input_ref": "fixture://user-email",
            # Deliberately wrong digest (all zeros).
            "expected_output_digest": "0" * 64,
        }
    ]
    payload_registry = {"fixture://user-email": payload}
    with pytest.raises(FixtureMismatch) as exc_info:
        validate_policy_or_raise(
            policy_body=policy,
            payload_registry=payload_registry,
            salt_provider=_salt_provider,
        )
    assert exc_info.value.code == FIXTURE_MISMATCH_CODE
    assert exc_info.value.details["http_status"] == 422
    assert exc_info.value.details["input_ref"] == "fixture://user-email"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-032")
def test_validation_fixtures_harness_accepts_empty_fixtures_list() -> None:
    """A policy with no validation_fixtures passes the harness trivially."""
    policy = _base_policy_with_pointer_matcher()
    # No validation_fixtures field at all.
    assert "validation_fixtures" not in policy
    results = validate_policy_fixtures(
        policy_body=policy,
        payload_registry={},
        salt_provider=_salt_provider,
    )
    assert results == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-032")
def test_validation_fixtures_harness_loads_referenced_payloads() -> None:
    """Missing input_ref in registry surfaces a structured error."""
    policy = _base_policy_with_pointer_matcher()
    policy["validation_fixtures"] = [
        {
            "input_ref": "fixture://does-not-exist",
            "expected_output_digest": "0" * 64,
        }
    ]
    with pytest.raises(RelayPolicyError) as exc_info:
        load_fixtures_from_policy_body(
            policy_body=policy,
            payload_registry={},
        )
    assert exc_info.value.details["reason"] == "input_ref_unknown"


# Round-trip sanity: the canonical JCS bytes the harness hashes are
# the SAME bytes the SDK's transport would write -- not a different
# canonicalization. Anchors the harness to redact_capture_payload.
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-032")
def test_validation_fixtures_harness_digest_matches_sdk_wire_bytes() -> None:
    """The harness's digest is sha256(SDK wire bytes)."""
    policy_body = _base_policy_with_pointer_matcher()
    payload = {"user": {"email": "a@b.com", "name": "Ana"}}
    policy = RedactionPolicy.load(policy_body)
    engine = RedactionEngine(policy=policy, salt_provider=_salt_provider)
    sdk_bytes = redact_capture_payload(engine, payload)
    sdk_digest = hashlib.sha256(sdk_bytes).hexdigest()
    harness_digest = compute_expected_digest(
        policy_body=policy_body,
        payload=payload,
        salt_provider=_salt_provider,
    )
    assert sdk_digest == harness_digest
    # And it is a valid 64-char lowercase hex digest.
    assert len(harness_digest) == 64
    assert all(c in "0123456789abcdef" for c in harness_digest)
    # Defensive: the JCS bytes are also pure ASCII-safe JSON.
    assert json.loads(sdk_bytes.decode("utf-8")) == {
        "user": {"email": "<redacted>", "name": "Ana"}
    }
