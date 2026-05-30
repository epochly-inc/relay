"""VAL-IDEMP-001: idempotency key must not collide across distinct gates.

Bug (base commit c911607): the gate-bearing idempotency surfaces are stored
as un-interpolated path templates -- ``_GATE_DRAFT_SURFACE`` is the literal
``"POST /v1/gates/{gate_id}/drafts"`` (runtime.py line 2933/3007) and the
concrete ``gate_id`` path parameter is NEVER substituted before the surface
reaches ``_canonical_idempotency_key`` (the only gate-distinguishing material
in the key derivation, runtime.py 3450-3482). So two DISTINCT gates
(``POST /v1/gates/A/drafts`` and ``POST /v1/gates/B/drafts``) with the same
valid ULID Idempotency-Key and identical body compute the SAME canonical
idempotency key: gate B's write is wrongly treated as a replay of gate A's,
and the second gate gets no draft of its own.

PASS when: the resolved path parameter (the concrete ``gate_id`` /
``policy_id``) is folded into the idempotency surface so two distinct
resources never alias the same idempotency record, while a genuine retry of
the SAME gate still collides (idempotent replay preserved).

RED at base commit c911607 (distinct gates collide -> the second call replays
the first's body); GREEN after the fix (distinct gates -> distinct responses;
same gate retry -> identical body + Idempotent-Replay: true).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from _v2m02_w25_helpers import V2M02Client, scope_header, seed_three_anchor_handoff

# Same valid Crockford-base32 ULID Idempotency-Key for every request so the
# ONLY differentiator across requests is the resolved path parameter.
_SHARED_KEY = "01HZX9F8K7M3N4P5Q6R7S8T9V0"

# Anchors for the gate-draft POSTs. VAL-ISO-003 made the three-anchor
# handoff validator run unconditionally (fail closed on unseeded
# registries), so the draft-posting tests must seed a valid actor +
# active manifest matching these hashes.
_DRAFT_MANIFEST_HASH = "sha256-" + ("0" * 64)
_DRAFT_ACTOR_HASH = "sha256-" + ("1" * 64)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-001")
@pytest.mark.asyncio
async def test_gate_draft_distinct_gates_do_not_alias_idempotency(
    v2m02_client: V2M02Client,
) -> None:
    """POST /v1/gates/A/drafts and POST /v1/gates/B/drafts with an identical
    body + the same Idempotency-Key MUST NOT alias: gate B gets its own draft,
    not a replay of gate A's.
    """
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    headers = {
        **scope_header("gates:execute"),
        "Idempotency-Key": _SHARED_KEY,
    }
    body = {
        "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
        "actor_identity_hash": _DRAFT_ACTOR_HASH,
        "round": 1,
    }

    r_a = await c.post("/v1/gates/gate-A/drafts", json=body, headers=headers)
    assert r_a.status_code == 202, r_a.text
    draft_a = r_a.json()["draft_id"]
    # Gate A's first write is not a replay.
    assert r_a.headers.get("idempotent-replay") != "true"

    r_b = await c.post("/v1/gates/gate-B/drafts", json=body, headers=headers)
    # Gate B is a DISTINCT resource: it must NOT be served gate A's cached
    # response as an idempotent replay.
    assert r_b.headers.get("idempotent-replay") != "true", (
        "distinct gate B was served gate A's response as an idempotent "
        "replay -- the un-interpolated {gate_id} surface aliased the key"
    )
    assert r_b.status_code == 202, r_b.text
    draft_b = r_b.json()["draft_id"]
    assert draft_b != draft_a, (
        "distinct gates produced the same draft_id -> idempotency key "
        "collided across distinct gates (VAL-IDEMP-001)"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-001")
@pytest.mark.asyncio
async def test_gate_draft_same_gate_retry_still_replays(
    v2m02_client: V2M02Client,
) -> None:
    """A genuine retry of the SAME gate (same gate_id, same key, same body)
    MUST still collide -> identical response body + Idempotent-Replay: true.
    The fix must not break the legitimate idempotent-replay path.
    """
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    headers = {
        **scope_header("gates:execute"),
        "Idempotency-Key": _SHARED_KEY,
    }
    body = {
        "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
        "actor_identity_hash": _DRAFT_ACTOR_HASH,
        "round": 1,
    }

    r1 = await c.post("/v1/gates/gate-X/drafts", json=body, headers=headers)
    assert r1.status_code == 202, r1.text
    first = r1.json()

    r2 = await c.post("/v1/gates/gate-X/drafts", json=body, headers=headers)
    assert r2.status_code == 202, r2.text
    assert r2.headers.get("idempotent-replay") == "true", (
        "same-gate retry was NOT served as an idempotent replay -- the fix "
        "broke the legitimate replay path"
    )
    assert r2.json() == first


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-001")
@pytest.mark.asyncio
async def test_put_gate_distinct_gate_ids_do_not_alias(
    v2m02_client: V2M02Client,
) -> None:
    """PUT /v1/gates/{gate_id} shares the same un-interpolated surface bug.
    Two distinct gate_ids with the same key + body must not alias: gate B's
    response must reference gate B, not replay gate A's body.
    """
    c, _db, _app = v2m02_client
    headers = {
        **scope_header("gates:configure"),
        "Idempotency-Key": _SHARED_KEY,
    }
    body = {"scope_type": "run"}

    r_a = await c.put("/v1/gates/cfg-A", json=body, headers=headers)
    assert r_a.status_code in (200, 201), r_a.text
    assert r_a.json()["gate_id"] == "cfg-A"

    r_b = await c.put("/v1/gates/cfg-B", json=body, headers=headers)
    assert r_b.headers.get("idempotent-replay") != "true", (
        "distinct gate cfg-B was served cfg-A's response as a replay"
    )
    assert r_b.status_code in (200, 201), r_b.text
    assert r_b.json()["gate_id"] == "cfg-B", (
        "PUT /v1/gates/cfg-B replayed cfg-A's response body -> the "
        "un-interpolated {gate_id} surface aliased the idempotency key"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-001")
@pytest.mark.asyncio
async def test_put_gate_policy_distinct_policy_ids_do_not_alias(
    v2m02_client: V2M02Client,
) -> None:
    """PUT /v1/gate-policies/{policy_id} carries the same defect on
    ``_GATE_POLICY_SURFACE``. Distinct policy_ids must not alias.
    """
    c, _db, _app = v2m02_client
    headers = {
        **scope_header("gates:configure"),
        "Idempotency-Key": _SHARED_KEY,
    }
    body = {"policy_version": "v1", "conditions": []}

    r_a = await c.put("/v1/gate-policies/pol-A", json=body, headers=headers)
    assert r_a.status_code in (200, 201), r_a.text
    assert r_a.json()["policy_id"] == "pol-A"

    r_b = await c.put("/v1/gate-policies/pol-B", json=body, headers=headers)
    assert r_b.headers.get("idempotent-replay") != "true", (
        "distinct policy pol-B was served pol-A's response as a replay"
    )
    assert r_b.status_code in (200, 201), r_b.text
    assert r_b.json()["policy_id"] == "pol-B", (
        "PUT /v1/gate-policies/pol-B replayed pol-A's response body -> the "
        "un-interpolated {policy_id} surface aliased the idempotency key"
    )
