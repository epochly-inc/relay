"""W8.1 plumbing tests: VAL-W8-041 anti-bypass guard.

Verifies the gate engine refuses drafts whose declared command (resolved
via the manifest's command_hash -> command_line map) contains any of:
--no-verify, --no-gpg-sign, --skip-hooks, or git short-form -n. The
only legitimate path is an org-admin operator override claim.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    SCOPE_ID,
    SCOPE_TYPE,
    InMemoryEvidenceProvider,
    InMemoryManifestResolver,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_gate_engine import (
    BANNED_BYPASS_TOKENS,
    AntiBypassGuard,
    AntiBypassRejectedError,
    GateEvaluator,
    StaleHandoffError,
)
from relay_gate_engine.evaluator import AntiBypassOverrideClaim
from relay_schemas.error_codes import RelayErrorCode


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_banned_token_list_pinned() -> None:
    """The banned token list MUST contain --no-verify, --no-gpg-sign,
    --skip-hooks, and -n (git short-form per the contract assertion)."""
    assert "--no-verify" in BANNED_BYPASS_TOKENS
    assert "--no-gpg-sign" in BANNED_BYPASS_TOKENS
    assert "--skip-hooks" in BANNED_BYPASS_TOKENS
    assert "-n" in BANNED_BYPASS_TOKENS


@pytest.mark.parametrize(
    "command_line",
    [
        "git commit --no-verify -m 'bypass'",
        "git push --no-gpg-sign origin main",
        "make ci --skip-hooks",
        "git commit -n -m 'short form'",
    ],
)
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_each_banned_flag_triggers_rejection_in_pipeline(
    command_line: str,
    evidence_provider: InMemoryEvidenceProvider,
    manifest_resolver: InMemoryManifestResolver,
) -> None:
    """Each banned flag in the resolved command line is rejected with
    RELAY-GATE-061 and zero gate decisions are written.

    Maps to the contract assertion's "for each bypass flag" evidence.
    """
    manifest_resolver.add("sha256-bypass", command_line)
    evaluator = GateEvaluator(
        evidence_provider=evidence_provider,
        manifest_resolver=manifest_resolver,
    )
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(gate_id=GATE_ID_SCRUTINY, command_hash="sha256-bypass")

    with pytest.raises(AntiBypassRejectedError) as ei:
        pipeline.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft, now=now,
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_061
    # Zero decisions in the pipeline (the outcome was never recorded).
    assert pipeline.result().outcomes == ()
    # The manifest command_hash lookup was recorded in the payload.
    assert ei.value.payload["command_hash"] == "sha256-bypass"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_clean_command_with_dash_n_substring_does_not_match() -> None:
    """Substring near-misses MUST NOT trip (e.g., --name has -n inside)."""
    guard = AntiBypassGuard()
    detected = guard.screen(
        command_hash="sha256-test",
        command_line="git commit --name 'Bob' --message 'fine'",
        scope_type="run",
        scope_id="x",
    )
    assert detected == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_no_verify_substring_extension_does_not_match() -> None:
    """--no-verifyx must NOT match --no-verify (whole-arg boundary)."""
    guard = AntiBypassGuard()
    detected = guard.screen(
        command_hash="sha256-test",
        command_line="custom-tool --no-verifyx run",
        scope_type="run",
        scope_id="x",
    )
    assert detected == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_override_with_org_admin_actor_permits_bypass(
    evidence_provider: InMemoryEvidenceProvider,
    manifest_resolver: InMemoryManifestResolver,
) -> None:
    """An org_admin override claim binds a banned-flag command to a decision.

    Mirrors the contract assertion's "override-allowed case": event_log
    row with event_kind='operator_override' present, actor role
    org_admin, gate decision written successfully (i.e., the engine
    proceeds to evaluation, action='accept').
    """
    manifest_resolver.add("sha256-bypass", "git commit --no-verify -m 'audited'")
    actor_hash_admin = "sha256-" + ("c" * 64)

    def _resolver(scope_type: str, scope_id: str, command_hash: str):
        if (
            scope_type == SCOPE_TYPE
            and scope_id == str(SCOPE_ID)
            and command_hash == "sha256-bypass"
        ):
            return AntiBypassOverrideClaim(
                actor_identity_hash=actor_hash_admin,
                actor_kind="human",
                actor_role="org_admin",
                scope_type=scope_type,
                scope_id=scope_id,
                command_hash=command_hash,
                revoked=False,
            )
        return None

    guard = AntiBypassGuard(override_resolver=_resolver)
    evaluator = GateEvaluator(
        evidence_provider=evidence_provider,
        manifest_resolver=manifest_resolver,
        anti_bypass=guard,
    )
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(gate_id=GATE_ID_SCRUTINY, command_hash="sha256-bypass")

    outcome = pipeline.run_gate(
        gate_name="scrutiny", gate=gate, draft=draft, now=now,
    )
    assert outcome.action == "accept"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_revoked_override_claim_rejected() -> None:
    guard = AntiBypassGuard(
        override_resolver=lambda st, si, ch: AntiBypassOverrideClaim(
            actor_identity_hash="sha256-x",
            actor_kind="human",
            actor_role="org_admin",
            scope_type=st,
            scope_id=si,
            command_hash=ch,
            revoked=True,
        ),
    )
    with pytest.raises(AntiBypassRejectedError):
        guard.screen(
            command_hash="sha256-x",
            command_line="git commit --no-verify",
            scope_type="run",
            scope_id="x",
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_non_human_override_actor_rejected() -> None:
    """An override claim whose actor_kind != 'human' is a stale-handoff signal."""
    guard = AntiBypassGuard(
        override_resolver=lambda st, si, ch: AntiBypassOverrideClaim(
            actor_identity_hash="sha256-x",
            actor_kind="bot",
            actor_role="org_admin",
            scope_type=st,
            scope_id=si,
            command_hash=ch,
        ),
    )
    with pytest.raises(StaleHandoffError):
        guard.screen(
            command_hash="sha256-x",
            command_line="git commit --no-verify",
            scope_type="run",
            scope_id="x",
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_non_admin_role_rejected() -> None:
    guard = AntiBypassGuard(
        override_resolver=lambda st, si, ch: AntiBypassOverrideClaim(
            actor_identity_hash="sha256-x",
            actor_kind="human",
            actor_role="org_member",
            scope_type=st,
            scope_id=si,
            command_hash=ch,
        ),
    )
    with pytest.raises(AntiBypassRejectedError):
        guard.screen(
            command_hash="sha256-x",
            command_line="git commit --no-verify",
            scope_type="run",
            scope_id="x",
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_override_claim_for_different_scope_rejected() -> None:
    """A claim whose scope_id doesn't match is rejected (defence in depth)."""
    guard = AntiBypassGuard(
        override_resolver=lambda st, si, ch: AntiBypassOverrideClaim(
            actor_identity_hash="sha256-x",
            actor_kind="human",
            actor_role="org_admin",
            scope_type=st,
            scope_id="DIFFERENT_SCOPE",
            command_hash=ch,
        ),
    )
    with pytest.raises(AntiBypassRejectedError):
        guard.screen(
            command_hash="sha256-x",
            command_line="git commit --no-verify",
            scope_type="run",
            scope_id="actual",
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-041")
def test_undeclared_command_hash_is_stale_handoff(
    evidence_provider: InMemoryEvidenceProvider,
) -> None:
    """A command_hash not in the manifest -> StaleHandoffError per
    CLAUDE.md keystone invariant 3 (manifest is the source of truth)."""
    # Empty manifest resolver.
    resolver = InMemoryManifestResolver()
    evaluator = GateEvaluator(
        evidence_provider=evidence_provider,
        manifest_resolver=resolver,
    )
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(
        gate_id=GATE_ID_SCRUTINY, command_hash="sha256-undeclared",
    )
    with pytest.raises(StaleHandoffError) as ei:
        pipeline.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft, now=now,
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_021
