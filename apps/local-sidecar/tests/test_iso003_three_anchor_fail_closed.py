"""VAL-ISO-003 regression: three-anchor handoff validation must FAIL
CLOSED when the anchor registries are unseeded.

Bug (base commit c911607): ``v1_post_gate_draft`` only calls
``validate_three_anchor_handoff`` when BOTH the ``actors`` AND
``manifest_versions`` tables are non-empty (``if actors_seeded and
manifests_seeded:``). On an unseeded DB the actor/manifest anchor
verification is bypassed entirely and the draft is ACCEPTED with whatever
attacker-supplied ``actor_identity_hash`` / ``manifest_commit_hash`` the
body carries -- violating CLAUDE.md keystone invariant #4 (three-anchor
handoff, no fallback skip path).

Fix: run ``validate_three_anchor_handoff`` UNCONDITIONALLY. The validator
already fails closed for empty tables (an empty ``actors`` table yields
``ACTOR_NOT_REGISTERED``; an empty ``manifest_versions`` table yields
``MANIFEST_NOT_ACTIVE``), surfaced as 422 RELAY-GATE-021.

RED at base (unseeded draft accepted with 202); GREEN after (unseeded
draft rejected 422 RELAY-GATE-021), while a properly-seeded valid handoff
still succeeds.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from _v2m02_w25_helpers import V2M02Client, scope_header, seed_three_anchor_handoff

# Anchors used across the tests. The actor/manifest hashes are the
# sha256-<hex> wire form the validator requires.
_ACTOR_HASH = "sha256-" + ("1" * 64)
_MANIFEST_HASH = "sha256-" + ("0" * 64)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-003")
@pytest.mark.asyncio
async def test_gate_draft_on_unseeded_anchors_is_rejected(
    v2m02_client: V2M02Client,
) -> None:
    """Unseeded actors/manifest_versions -> handoff REJECTED (fail closed).

    Before the fix the skip path accepted the draft with 202; after the
    fix the validator runs unconditionally and rejects with 422
    RELAY-GATE-021 (ACTOR_NOT_REGISTERED on the empty actors table).
    """
    c, _db, _app = v2m02_client
    body = {
        "manifest_commit_hash": _MANIFEST_HASH,
        "actor_identity_hash": _ACTOR_HASH,
        "worker_id": "worker-attacker",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-unseeded/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 422, r.text
    env = json.loads(r.text)
    assert env["code"] == "RELAY-GATE-021", env
    # The structured reason proves it was the validator (not the legacy
    # presence-only check) that rejected.
    assert env["details"]["reason"] == "ACTOR_NOT_REGISTERED", env


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-003")
@pytest.mark.asyncio
async def test_gate_draft_with_seeded_anchors_succeeds(
    v2m02_client: V2M02Client,
) -> None:
    """A genuine, properly-seeded valid handoff still succeeds (202).

    Guards against an over-broad fix that would reject ALL drafts.
    """
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_ACTOR_HASH,
        manifest_commit_hash=_MANIFEST_HASH,
    )
    body = {
        "manifest_commit_hash": _MANIFEST_HASH,
        "actor_identity_hash": _ACTOR_HASH,
        "worker_id": "worker-legit",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-seeded/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 202, r.text
    payload = json.loads(r.text)
    assert "draft_id" in payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-003")
@pytest.mark.asyncio
async def test_gate_draft_seeded_manifest_only_still_rejects_unknown_actor(
    v2m02_client: V2M02Client,
) -> None:
    """Manifest seeded but actor unknown -> ACTOR_NOT_REGISTERED.

    Proves the fix does not merely key off "both tables non-empty": a
    half-seeded DB with an unregistered actor must still fail closed.
    """
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=None,  # seed manifest only
        manifest_commit_hash=_MANIFEST_HASH,
    )
    body = {
        "manifest_commit_hash": _MANIFEST_HASH,
        "actor_identity_hash": "sha256-" + ("9" * 64),  # not registered
        "worker_id": "worker-x",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-half/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 422, r.text
    env = json.loads(r.text)
    assert env["code"] == "RELAY-GATE-021", env
    assert env["details"]["reason"] == "ACTOR_NOT_REGISTERED", env
