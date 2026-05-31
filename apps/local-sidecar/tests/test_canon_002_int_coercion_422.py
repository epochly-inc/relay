"""VAL-CANON-002: int() coercion of JSON body fields must fail closed as 422.

Bug (relay-bughunt-2026-05-28, base c911607): several gate write handlers
coerce client-controlled JSON body fields with a bare ``int()``:

  - ``v1_put_gate``       int(body.get("draft_ttl_seconds", 900))
                          int(body.get("remediation_round_cap", 5))
  - ``v1_post_gate_draft`` round_n = int(body.get("round", 1))
                          draft_ttl = int(gate_cfg.get("draft_ttl_seconds", 900))

A non-numeric string (e.g. ``{"remediation_round_cap": "abc"}``) makes
``int()`` raise ``ValueError`` which is unhandled, yielding a bare HTTP 500
instead of a canonical RELAY-ING-001 422 ingest-validation envelope (the same
malformed-field rejection sibling code paths already emit).

These tests are RED at base commit c911607 (500) and GREEN after the fix
(422 + canonical RELAY-ING-001 envelope). They also guard against
over-rejection: valid integer-typed fields still succeed.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import httpx
import pytest
from _v2m02_w25_helpers import V2M02Client, scope_header, seed_three_anchor_handoff

# Anchors for the gate-draft POSTs. VAL-ISO-003 made the three-anchor
# handoff validator run unconditionally (fail closed on unseeded
# registries). The handoff validation runs BEFORE the round int-coercion,
# so tests that need to reach the coercion (or expect a 202) must seed a
# valid actor + active manifest matching these hashes.
_DRAFT_MANIFEST_HASH = "sha256-" + ("0" * 64)
_DRAFT_ACTOR_HASH = "sha256-" + ("1" * 64)


def _assert_canonical_422(r: httpx.Response) -> dict:
    """A non-int body field must produce a canonical RELAY-ING-001 422,
    never a bare 500."""
    assert r.status_code == 422, (
        f"expected 422 (canonical ingest-validation), got "
        f"{r.status_code}: {r.text}"
    )
    payload = json.loads(r.text)
    assert payload["code"] == "RELAY-ING-001", payload
    assert payload["http_status"] == 422, payload
    assert payload["schema_version"] == "relay.error.v1", payload
    # Canonical envelope completeness (spec B.4).
    assert payload["message"], payload
    assert payload["blocked_surface"], payload
    return payload


# ---- v1_put_gate: int(body.get("remediation_round_cap", 5)) --------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_put_gate_non_int_remediation_round_cap_returns_422(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/gate-canon2-cap",
        json={"name": "g", "remediation_round_cap": "abc"},
        headers=scope_header("gates:configure"),
    )
    _assert_canonical_422(r)


# ---- v1_put_gate: int(body.get("draft_ttl_seconds", 900)) ----------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_put_gate_non_int_draft_ttl_returns_422(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/gate-canon2-ttl",
        json={"name": "g", "draft_ttl_seconds": "not-a-number"},
        headers=scope_header("gates:configure"),
    )
    _assert_canonical_422(r)


# ---- v1_post_gate_draft: round_n = int(body.get("round", 1)) -------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_post_gate_draft_non_int_round_returns_422(
    v2m02_client: V2M02Client,
) -> None:
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    body = {
        "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
        "actor_identity_hash": _DRAFT_ACTOR_HASH,
        "worker_id": "worker-canon2",
        "round": "abc",
    }
    r = await c.post(
        "/v1/gates/gate-canon2-round/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    _assert_canonical_422(r)


# ---- v1_post_gate_draft: int(gate_cfg.get("draft_ttl_seconds", 900)) -----
# Site 3 reads the stored gate config; once a gate is configured with a
# non-int draft_ttl_seconds the configure path itself fails closed (site 2
# above), so site 3 can never observe a non-int. This test pins that a gate
# whose configure was rejected does not leave a poisoned record that a
# subsequent draft submission would 500 on.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_draft_against_gate_with_rejected_ttl_does_not_500(
    v2m02_client: V2M02Client,
) -> None:
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    # Configure attempt with a bad ttl is rejected (no poisoned record).
    bad = await c.put(
        "/v1/gates/gate-canon2-site3",
        json={"name": "g", "draft_ttl_seconds": "xyz"},
        headers=scope_header("gates:configure"),
    )
    _assert_canonical_422(bad)
    # A subsequent valid draft submission must NOT hit a bare 500 from a
    # poisoned gate_cfg["draft_ttl_seconds"]; it succeeds (202) using the
    # default ttl because no record was stored.
    draft = await c.post(
        "/v1/gates/gate-canon2-site3/drafts",
        json={
            "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
            "actor_identity_hash": _DRAFT_ACTOR_HASH,
            "worker_id": "worker-canon2",
            "round": 1,
        },
        headers=scope_header("gates:execute"),
    )
    assert draft.status_code == 202, draft.text
    assert json.loads(draft.text)["draft_ttl_seconds"] == 900


# ---- Over-rejection guard: valid int fields still succeed -----------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_valid_int_fields_still_accepted(
    v2m02_client: V2M02Client,
) -> None:
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    # Valid ints (and JSON-numeric strings the spec permits) accepted.
    r = await c.put(
        "/v1/gates/gate-canon2-ok",
        json={
            "name": "g",
            "draft_ttl_seconds": 1200,
            "remediation_round_cap": 3,
        },
        headers=scope_header("gates:configure"),
    )
    assert r.status_code == 201, r.text
    d = await c.post(
        "/v1/gates/gate-canon2-ok/drafts",
        json={
            "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
            "actor_identity_hash": _DRAFT_ACTOR_HASH,
            "worker_id": "worker-canon2",
            "round": 2,
        },
        headers=scope_header("gates:execute"),
    )
    assert d.status_code == 202, d.text
    assert json.loads(d.text)["draft_ttl_seconds"] == 1200


# ---- Non-integral JSON number rejection (codex-review P2) -----------------
# _coerce_int_field used a bare ``int(raw)``, which TRUNCATES a non-integral
# JSON float (1.9 -> 1, 0.5 -> 0) while REJECTING a non-integral numeric
# STRING ("1.9" -> ValueError). That asymmetry silently accepted malformed
# input. The fix rejects a non-integral float symmetrically (same canonical
# RELAY-ING-001 422 the string-float reject path emits), while still
# accepting integer-valued numbers (1.0 -> 1) and integer numeric strings.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_post_gate_draft_non_integral_float_round_returns_422(
    v2m02_client: V2M02Client,
) -> None:
    """``round: 1.9`` MUST be rejected (was: truncated to round 1)."""
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    r = await c.post(
        "/v1/gates/gate-canon2-frac-round/drafts",
        json={
            "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
            "actor_identity_hash": _DRAFT_ACTOR_HASH,
            "worker_id": "worker-canon2",
            "round": 1.9,
        },
        headers=scope_header("gates:execute"),
    )
    _assert_canonical_422(r)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_put_gate_non_integral_float_ttl_returns_422(
    v2m02_client: V2M02Client,
) -> None:
    """``draft_ttl_seconds: 0.5`` MUST be rejected (was: truncated to 0)."""
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/gate-canon2-frac-ttl",
        json={"name": "g", "draft_ttl_seconds": 0.5},
        headers=scope_header("gates:configure"),
    )
    _assert_canonical_422(r)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_post_gate_draft_integer_valued_float_round_accepted(
    v2m02_client: V2M02Client,
) -> None:
    """``round: 1.0`` (integer-valued JSON number) MUST still be accepted."""
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    r = await c.post(
        "/v1/gates/gate-canon2-int-float-round/drafts",
        json={
            "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
            "actor_identity_hash": _DRAFT_ACTOR_HASH,
            "worker_id": "worker-canon2",
            "round": 1.0,
        },
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 202, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-002")
@pytest.mark.asyncio
async def test_post_gate_draft_plain_int_round_accepted(
    v2m02_client: V2M02Client,
) -> None:
    """``round: 2`` (plain JSON integer) MUST still be accepted."""
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    r = await c.post(
        "/v1/gates/gate-canon2-plain-int-round/drafts",
        json={
            "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
            "actor_identity_hash": _DRAFT_ACTOR_HASH,
            "worker_id": "worker-canon2",
            "round": 2,
        },
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 202, r.text
