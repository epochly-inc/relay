"""V2 M02 W2.6 sidecar evidence-bundle HTTP endpoint tests.

Covers VAL-V2M02-049..056 (8 assertions):
  - 049 POST /v1/evidence-bundles creates a bundle (201).
  - 050 POST enforces evidence:read scope.
  - 051 GET /v1/evidence-bundles/{id} returns metadata (200) or 410 tombstoned.
  - 052 GET enforces evidence:read scope.
  - 053 GET /v1/evidence-bundles/{id}/download returns signed tar.gz.
  - 054 download enforces evidence:read scope.
  - 055 POST /v1/evidence-bundles/{id}/verify is publicly accessible.
  - 056 POST verify returns signatures_ok=false on bad signature.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from _v2m02_w25_helpers import (
    V2M02Client,
    no_scope_header,
    scope_header,
)


async def _create_bundle(c: httpx.AsyncClient) -> str:
    # Audit fix (2026-05-17 P0): POST requires ``evidence:write``.
    r = await c.post(
        "/v1/evidence-bundles",
        json={
            "scope_kind": "run",
            "scope_id": "run-1",
            "claims": [
                {"assertion_id": "VAL-EXAMPLE-001", "result": "pass"}
            ],
        },
        headers=scope_header("evidence:write"),
    )
    assert r.status_code == 201, r.text
    return json.loads(r.text)["bundle_id"]


# ---- VAL-V2M02-049: create bundle ----------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-049")
@pytest.mark.asyncio
async def test_create_evidence_bundle(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    # Audit fix (2026-05-17 P0): POST requires ``evidence:write``.
    r = await c.post(
        "/v1/evidence-bundles",
        json={"scope_kind": "run", "scope_id": "r1", "claims": []},
        headers=scope_header("evidence:write"),
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["bundle_id"].startswith("eb-")
    # Audit fix (2026-05-17 P0): hyphen wire form per VAL-W1-009.
    assert payload["digest"].startswith("sha256-")
    assert "await_url" in payload


# ---- VAL-V2M02-050: create scope -----------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-050")
@pytest.mark.asyncio
async def test_create_evidence_bundle_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.post(
        "/v1/evidence-bundles", json={}, headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-051: GET bundle / tombstoned 410 --------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-051")
@pytest.mark.asyncio
async def test_get_evidence_bundle_canonical(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, app = v2m02_client
    bid = await _create_bundle(c)
    r = await c.get(
        f"/v1/evidence-bundles/{bid}", headers=scope_header("evidence:read")
    )
    assert r.status_code == 200, r.text
    payload = json.loads(r.text)
    # Audit fix (2026-05-17 P0): hyphen wire form per VAL-W1-009.
    assert payload["digest"].startswith("sha256-")
    assert payload["signer_key_id"]
    assert payload["trust_anchor"].startswith("https://")
    assert isinstance(payload["claims_count"], int)
    # Tombstone path -> 410.
    runtime = app.state.runtime
    runtime.evidence_bundles[bid]["state"] = "tombstoned"
    r410 = await c.get(
        f"/v1/evidence-bundles/{bid}", headers=scope_header("evidence:read")
    )
    assert r410.status_code == 410
    assert json.loads(r410.text)["code"] == "RELAY-EVID-001"


# ---- VAL-V2M02-052: GET bundle scope -------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-052")
@pytest.mark.asyncio
async def test_get_evidence_bundle_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get(
        "/v1/evidence-bundles/x", headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-053: download returns gzip with sha256-matching body ------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-053")
@pytest.mark.asyncio
async def test_download_evidence_bundle(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, app = v2m02_client
    bid = await _create_bundle(c)
    r = await c.get(
        f"/v1/evidence-bundles/{bid}/download",
        headers=scope_header("evidence:read"),
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/gzip")
    assert f'filename="{bid}.tar.gz"' in r.headers["content-disposition"]
    # Audit fix (2026-05-17 P0): hyphen wire form per VAL-W1-009.
    body_digest = "sha256-" + hashlib.sha256(r.content).hexdigest()
    stored_digest = app.state.runtime.evidence_bundles[bid]["digest"]
    assert body_digest == stored_digest


# ---- VAL-V2M02-054: download scope ---------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-054")
@pytest.mark.asyncio
async def test_download_evidence_bundle_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get(
        "/v1/evidence-bundles/x/download", headers=no_scope_header()
    )
    assert r.status_code == 403


# ---- VAL-V2M02-055: verify is publicly accessible ------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-055")
@pytest.mark.asyncio
async def test_verify_evidence_bundle_public(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    bid = await _create_bundle(c)
    # No auth headers whatsoever.
    r = await c.post(f"/v1/evidence-bundles/{bid}/verify")
    assert r.status_code == 200, r.text
    payload = json.loads(r.text)
    for k in (
        "bundle_id",
        "verifier_engine_version",
        "structure_ok",
        "digest_ok",
        "signatures_ok",
        "signatures_checked",
        "claims_count",
    ):
        assert k in payload, f"missing {k}"


# ---- VAL-V2M02-056: bad signature returns signatures_ok=false ------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-056")
@pytest.mark.asyncio
async def test_verify_evidence_bundle_bad_signature(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    bid = await _create_bundle(c)
    r = await c.post(
        f"/v1/evidence-bundles/{bid}/verify", json={"tampered": True}
    )
    assert r.status_code == 200, r.text
    payload = json.loads(r.text)
    assert payload["signatures_ok"] is False
    assert any(
        sig["valid"] is False for sig in payload["signatures_checked"]
    )


# ---- VAL-CRYPTO-006: verify never reports signatures_ok=true without
#      real cryptographic signature verification --------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CRYPTO-006")
@pytest.mark.asyncio
async def test_verify_no_green_signatures_without_real_crypto(
    v2m02_client: V2M02Client,
) -> None:
    """Regression for VAL-CRYPTO-006.

    POST /verify with no body against a freshly created OSS-stub bundle
    MUST NOT report ``signatures_ok: true``. The OSS sidecar fabricates a
    ``sig-<sha256...>`` value with no ed25519 key material and never
    performs cryptographic verification, so a green ``signatures_ok``
    derived from a self-asserted ``valid`` flag is dishonest. The response
    must fail closed: ``signatures_ok`` is not true, the bundle is surfaced
    as ``verification_status: unverified``, and a reason is given.
    """
    c, _db, _app = v2m02_client
    bid = await _create_bundle(c)
    # No body whatsoever -- the original tautology returned signatures_ok=true.
    r = await c.post(f"/v1/evidence-bundles/{bid}/verify")
    payload = json.loads(r.text)
    # The core invariant: a consumer can NEVER receive a green
    # signatures_ok for a bundle that was not cryptographically verified.
    assert payload["signatures_ok"] is not True, payload
    # Honest surfacing of the unverified state.
    assert payload.get("verification_status") == "unverified", payload
    # Every per-signature entry must be honest too: none claims valid=true.
    assert all(
        sig.get("valid") is not True
        for sig in payload.get("signatures_checked", [])
    ), payload
    # A human-readable reason must explain why it is not verified.
    assert payload.get("signatures_reason"), payload


# ---- VAL-CRYPTO-007: digest check compares against an independent
#      expected digest, not a tautological re-hash of stored bytes -------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CRYPTO-007")
@pytest.mark.asyncio
async def test_verify_digest_detects_record_tampering(
    v2m02_client: V2M02Client,
) -> None:
    """Regression for VAL-CRYPTO-007.

    The original digest check recomputed sha256 over the SAME immutable
    stored blob whose hash IS the recorded digest -- a tautology that is
    always true and can never detect record tampering. The honest check
    re-serializes the CURRENT live record (excluding mutable
    digest/claims_count/state/alias fields) and compares it to the recorded
    bundle_digest, so mutating the live record flips digest_ok to false.
    """
    c, _db, app = v2m02_client
    bid = await _create_bundle(c)
    runtime = app.state.runtime
    # Tamper with the live record AFTER its digest was recorded.
    runtime.evidence_bundles[bid]["claims"] = [
        {"assertion_id": "VAL-INJECTED-999", "result": "pass"}
    ]
    r = await c.post(f"/v1/evidence-bundles/{bid}/verify")
    payload = json.loads(r.text)
    # The divergence between the live record and its claimed digest MUST
    # be detected -- the tautology could never do this.
    assert payload["digest_ok"] is False, payload


# ---- VAL-CRYPTO-006 (fail-closed boolean): unverified OSS stub bundle
#      MUST report signatures_ok=false (a real JSON boolean), not null ----


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CRYPTO-006")
@pytest.mark.asyncio
async def test_verify_unverified_bundle_signatures_ok_is_false_not_null(
    v2m02_client: V2M02Client,
) -> None:
    """Fail-closed boolean regression (codex-review verify-signatures-ok-false).

    For an UNVERIFIED (non-tampered) OSS stub bundle the handler previously
    set ``signatures_ok = None`` and per-signature ``valid = None``,
    serialising to JSON ``null``. The verifier-output schema
    (packages/schemas/raw/verifier-output.yaml) declares ``signatures_ok``
    as ``type: boolean`` (non-nullable) and per-signature ``ok`` as a
    required boolean. ``null`` violates that contract and is NOT fail-closed:
    a consumer doing a boolean check (``if signatures_ok``) treats null as
    falsy by luck, not by contract, and a strict equality check sees an
    ambiguous third state. Per keystone fail-closed (#2, #11) an unverified
    bundle MUST report a concrete boolean ``false``.

    Distinct from ``test_verify_no_green_signatures_without_real_crypto``,
    which only asserts ``is not True`` (passes under the buggy null state).
    This test asserts the strict boolean ``is False``.
    """
    c, _db, _app = v2m02_client
    bid = await _create_bundle(c)
    # No body -> the UNVERIFIED (non-tampered) OSS stub path.
    r = await c.post(f"/v1/evidence-bundles/{bid}/verify")
    assert r.status_code == 200, r.text
    payload = json.loads(r.text)
    # Strict: a real JSON boolean false, never null.
    assert payload["signatures_ok"] is False, payload
    # Honest verification_status is preserved.
    assert payload.get("verification_status") == "unverified", payload
    # Every per-signature verdict is a concrete boolean false, not null.
    sigs = payload.get("signatures_checked", [])
    assert sigs, "fixture invariant: created bundle ships >= 1 signature"
    for sig in sigs:
        assert sig.get("valid") is False, sig
    # A human-readable reason still explains the unverified state.
    assert payload.get("signatures_reason"), payload
