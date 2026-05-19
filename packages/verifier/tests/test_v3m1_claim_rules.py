"""V3M1-F07 (2026-05-18): spec section K claim-level rules.

Per spec section K (lines 4427-4432) the verifier MUST enforce four
claim-level rules in addition to the cryptographic signature checks
already wired into :func:`relay_verifier.bundle_validator.validate_bundle`:

  VAL-V3M1-017  supersedes_claim_id is allowed ONLY for claim_type IN
                {human_oversight, incident}. The schema layer enforces a
                CHECK constraint at the persistence boundary (both
                Postgres + sidecar SQLite); the verifier mirrors the
                rule for bundle-time defense.

  VAL-V3M1-018  Signer-restriction reporting. The verifier surfaces
                ``signer_role`` in its output as one of
                ``{control_plane, local_dev, unknown}``. Classification
                derives ONLY from the bundle's declared ``trust_anchor``
                field (mirroring the ``trust_anchor_class`` derivation
                rule in VAL-V2M08-044) so that a local_dev bundle can
                never auto-promote to ``control_plane`` even when the
                verifier is configured under the Relay-Inc anchor.

  VAL-V3M1-019  evidence_refs[].digest binding. Every ``digest`` field
                referenced by any claim's ``evidence_refs[]`` MUST be
                present in the bundle's top-level ``manifest`` (a list of
                artifact descriptors, each carrying a ``digest`` field).
                When the bundle declares no ``manifest``, the check is
                skipped (preserves back-compat for legacy bundles); when
                the manifest is declared, every claim digest MUST resolve
                or the verifier rejects with structured reason
                ``evidence_ref_artifact_missing_from_manifest``.

  VAL-V3M1-022  Unknown namespace rejection. The ``namespaces`` field on
                each claim is restricted to the closed set ``{x-relay}``
                (extensible only via spec amendment). Any other top-level
                key (e.g. ``x-attacker``) triggers structured rejection
                with code ``RELAY-EVID-NAMESPACE-UNKNOWN``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make conftest_w10_4 importable.
sys.path.insert(0, str(Path(__file__).parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    ValidateBundleOptions,
    validate_bundle,
)
from relay_verifier.bundle_validator import (  # noqa: E402
    RELAY_EVID_NAMESPACE_UNKNOWN,
    SIGNER_ROLE_CONTROL_PLANE,
    SIGNER_ROLE_LOCAL_DEV,
    SIGNER_ROLE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Repository paths used by the schema-layer assertions (VAL-V3M1-017).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PG_MIGRATION_F07 = (
    _REPO_ROOT / "packages" / "schemas" / "sql" / "0015_v3_claim_rule_checks.sql"
)
_SIDECAR_MIGRATION_F07 = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0028_v3_claim_rule_checks.sql"
)


# ===========================================================================
# VAL-V3M1-017: supersedes_claim_id CHECK constraint (both tiers)
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-017")
def test_val_v3m1_017_pg_migration_has_supersedes_check() -> None:
    """Postgres migration 0015 declares the CHECK constraint restricting
    ``supersedes_claim_id`` to non-null ONLY for human_oversight / incident
    claim types. Per spec K line 4430-4432."""
    text = _PG_MIGRATION_F07.read_text(encoding="utf-8").lower()
    assert "alter table evidence_claims" in text, (
        "VAL-V3M1-017: PG migration must ALTER evidence_claims to add the "
        "supersedes_claim_id CHECK constraint (spec K line 4430-4432)"
    )
    assert "supersedes_only_oversight_incident" in text, (
        "VAL-V3M1-017: PG migration must name the CHECK constraint "
        "'supersedes_only_oversight_incident' so callers can detect the "
        "violation by constraint name"
    )
    # Constraint clause must include both allowed claim_type values.
    assert "supersedes_claim_id is null" in text, (
        "VAL-V3M1-017: CHECK constraint missing 'supersedes_claim_id IS NULL' clause"
    )
    assert "'human_oversight'" in text, (
        "VAL-V3M1-017: CHECK constraint missing 'human_oversight' allowed value"
    )
    assert "'incident'" in text, (
        "VAL-V3M1-017: CHECK constraint missing 'incident' allowed value"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-017")
def test_val_v3m1_017_sidecar_migration_has_supersedes_check() -> None:
    """Sidecar SQLite migration 0028 mirrors the same CHECK constraint.

    SQLite does not support ALTER TABLE ADD CONSTRAINT CHECK after the
    fact, so the sidecar migration uses a CREATE TRIGGER (BEFORE INSERT
    / BEFORE UPDATE) that raises an integrity error when the rule is
    violated. The trigger name encodes the rule for greppability."""
    text = _SIDECAR_MIGRATION_F07.read_text(encoding="utf-8").lower()
    assert "supersedes_only_oversight_incident" in text, (
        "VAL-V3M1-017: sidecar migration must reference "
        "'supersedes_only_oversight_incident' trigger name"
    )
    assert "human_oversight" in text, (
        "VAL-V3M1-017: sidecar migration missing 'human_oversight' allowed value"
    )
    assert "incident" in text, (
        "VAL-V3M1-017: sidecar migration missing 'incident' allowed value"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-017")
def test_val_v3m1_017_sidecar_check_enforced_at_runtime() -> None:
    """End-to-end sidecar SQLite enforcement: a run_result claim with a
    non-null supersedes_claim_id must be rejected with an IntegrityError."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        # Minimal evidence_claims table mirroring the sidecar schema
        # surface needed for this CHECK. The real sidecar schema includes
        # additional columns; this test isolates the CHECK rule itself.
        conn.executescript(
            """
            CREATE TABLE evidence_claims (
                evidence_claim_id   TEXT PRIMARY KEY,
                claim_type          TEXT NOT NULL,
                supersedes_claim_id TEXT
            );
            """
        )
        # Apply the trigger-based CHECK from the migration.
        migration_sql = _SIDECAR_MIGRATION_F07.read_text(encoding="utf-8")
        conn.executescript(migration_sql)

        # A human_oversight claim with supersedes_claim_id MUST succeed.
        conn.execute(
            "INSERT INTO evidence_claims VALUES (?, ?, ?)",
            ("claim-A", "human_oversight", "claim-prior"),
        )
        # An incident claim with supersedes_claim_id MUST succeed.
        conn.execute(
            "INSERT INTO evidence_claims VALUES (?, ?, ?)",
            ("claim-B", "incident", "claim-prior"),
        )
        # A run_result claim with supersedes_claim_id MUST be rejected.
        with pytest.raises(sqlite3.IntegrityError) as exc_info:
            conn.execute(
                "INSERT INTO evidence_claims VALUES (?, ?, ?)",
                ("claim-C", "run_result", "claim-prior"),
            )
        assert "supersedes_only_oversight_incident" in str(exc_info.value).lower(), (
            f"VAL-V3M1-017: sidecar trigger must surface rule name; "
            f"got {exc_info.value!r}"
        )
        # A run_result claim with NULL supersedes_claim_id MUST succeed.
        conn.execute(
            "INSERT INTO evidence_claims VALUES (?, ?, ?)",
            ("claim-D", "run_result", None),
        )
    finally:
        conn.close()


# ===========================================================================
# VAL-V3M1-018: signer_role reported by verifier
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-018")
def test_val_v3m1_018_signer_role_relay_inc_anchor_reports_control_plane() -> None:
    """Bundle declaring the Relay-Inc default trust_anchor URL surfaces
    ``signer_role='control_plane'``."""
    built = build_bundle(
        trust_anchor="https://relay.epochly.com/.well-known/jwks.json",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["signer_role"] == SIGNER_ROLE_CONTROL_PLANE, (
        f"VAL-V3M1-018: Relay-Inc anchor must report signer_role="
        f"{SIGNER_ROLE_CONTROL_PLANE!r}; got {output.get('signer_role')!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-018")
def test_val_v3m1_018_signer_role_local_dev_anchor_reports_local_dev() -> None:
    """Bundle declaring trust_anchor='local_dev' surfaces
    ``signer_role='local_dev'`` regardless of which JWKS the verifier
    happens to be configured with (parallels the trust_anchor_class
    no-auto-promotion guarantee of VAL-V2M08-044)."""
    built = build_bundle(trust_anchor="local_dev")
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["signer_role"] == SIGNER_ROLE_LOCAL_DEV, (
        f"VAL-V3M1-018: local_dev anchor must report signer_role="
        f"{SIGNER_ROLE_LOCAL_DEV!r}; got {output.get('signer_role')!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-018")
def test_val_v3m1_018_signer_role_byo_anchor_reports_unknown() -> None:
    """Bundle declaring a BYO trust_anchor (third-party URL) surfaces
    ``signer_role='unknown'`` -- the verifier cannot attribute the bundle
    to either the Relay-Inc control plane or the OSS local signer."""
    built = build_bundle(
        trust_anchor="https://example.byo-anchor.test/.well-known/jwks.json",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="byo_flag",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["signer_role"] == SIGNER_ROLE_UNKNOWN, (
        f"VAL-V3M1-018: BYO anchor must report signer_role="
        f"{SIGNER_ROLE_UNKNOWN!r}; got {output.get('signer_role')!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-018")
def test_val_v3m1_018_signer_role_missing_anchor_reports_unknown() -> None:
    """Bundle missing trust_anchor entirely surfaces
    ``signer_role='unknown'`` (the verifier already emits
    RELAY-EVID-MISSING-TRUST-ANCHOR; the signer_role field defaults
    to ``unknown`` so consumers branching on it never see an empty
    string)."""
    built = build_bundle()
    # Strip the trust_anchor field on the bundle dict.
    built.bundle.pop("trust_anchor", None)
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["signer_role"] == SIGNER_ROLE_UNKNOWN, (
        f"VAL-V3M1-018: missing trust_anchor must report signer_role="
        f"{SIGNER_ROLE_UNKNOWN!r}; got {output.get('signer_role')!r}"
    )


# ===========================================================================
# VAL-V3M1-019: evidence_refs_manifest_binding
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-019")
def test_val_v3m1_019_evidence_refs_manifest_binding_rejects_missing_digest() -> None:
    """A claim referencing an artifact digest absent from the bundle-level
    ``manifest`` list MUST be rejected with structured reason
    ``evidence_ref_artifact_missing_from_manifest``."""
    import hashlib

    good_digest = hashlib.sha256(b"in-manifest").hexdigest()
    bad_digest = hashlib.sha256(b"not-in-manifest").hexdigest()
    built = build_bundle(
        claims=[
            {
                "claim_id": "claim-1",
                "kind": "command_evidence",
                "command_id": "test-cmd",
                "exit_code": 0,
                "artifact_id": "art-bad",
                "evidence_refs": [
                    {"artifact_id": "art-bad", "digest": bad_digest},
                ],
            },
        ],
    )
    # Attach a manifest listing only the GOOD digest. The bad digest in
    # the claim is what triggers the rejection.
    built.bundle["manifest"] = [{"artifact_id": "art-good", "digest": good_digest}]
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        e
        for e in output["errors"]
        if e.get("reason") == "evidence_ref_artifact_missing_from_manifest"
    ]
    assert matching, (
        f"VAL-V3M1-019: expected reason="
        f"'evidence_ref_artifact_missing_from_manifest'; got errors="
        f"{output['errors']!r}"
    )
    err = matching[0]
    assert bad_digest in err["message"], (
        f"VAL-V3M1-019: error message must cite the offending digest "
        f"{bad_digest!r}; got {err['message']!r}"
    )
    assert output["overall"] == "fail", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-019")
def test_val_v3m1_019_evidence_refs_manifest_binding_accepts_matching_digest() -> None:
    """When the manifest contains every claim's digest, the check passes
    (no manifest-binding error emitted)."""
    import hashlib

    matching_digest = hashlib.sha256(b"matching-bytes").hexdigest()
    built = build_bundle(
        claims=[
            {
                "claim_id": "claim-1",
                "kind": "command_evidence",
                "command_id": "test-cmd",
                "exit_code": 0,
                "artifact_id": "art-1",
                "evidence_refs": [
                    {"artifact_id": "art-1", "digest": matching_digest},
                ],
            },
        ],
    )
    built.bundle["manifest"] = [
        {"artifact_id": "art-1", "digest": matching_digest},
    ]
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        e
        for e in output["errors"]
        if e.get("reason") == "evidence_ref_artifact_missing_from_manifest"
    ]
    assert not matching, (
        f"VAL-V3M1-019: matching digest must not be flagged; got "
        f"{matching!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-019")
def test_val_v3m1_019_evidence_refs_manifest_binding_skipped_when_no_manifest() -> None:
    """When the bundle declares NO ``manifest`` field, the check is
    skipped (back-compat for legacy bundles that predate the manifest
    binding rule). The verifier still runs every other check."""
    built = build_bundle()  # default bundle has no top-level "manifest"
    assert "manifest" not in built.bundle
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        e
        for e in output["errors"]
        if e.get("reason") == "evidence_ref_artifact_missing_from_manifest"
    ]
    assert not matching, (
        f"VAL-V3M1-019: missing manifest must skip the check; got "
        f"{matching!r}"
    )


# ===========================================================================
# VAL-V3M1-022: unknown namespace rejection
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-022")
def test_val_v3m1_022_unknown_namespace_key_rejected() -> None:
    """A claim whose ``namespaces`` dict carries any key outside the
    closed set ``{x-relay}`` MUST be rejected with structured code
    ``RELAY-EVID-NAMESPACE-UNKNOWN``."""
    built = build_bundle(
        claims=[
            {
                "claim_id": "claim-1",
                "kind": "command_evidence",
                "command_id": "test-cmd",
                "exit_code": 0,
                "namespaces": {
                    "x-relay": {"schema_version": "v1"},
                    "x-attacker": {"injected": True},
                },
            },
        ],
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_NAMESPACE_UNKNOWN
    ]
    assert matching, (
        f"VAL-V3M1-022: expected code={RELAY_EVID_NAMESPACE_UNKNOWN!r}; "
        f"got errors={output['errors']!r}"
    )
    err = matching[0]
    assert "x-attacker" in err["message"], (
        f"VAL-V3M1-022: error must cite the unknown key 'x-attacker'; "
        f"got {err['message']!r}"
    )
    assert output["overall"] == "fail", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-022")
def test_val_v3m1_022_x_relay_only_namespace_accepted() -> None:
    """A claim whose ``namespaces`` dict carries ONLY the ``x-relay`` key
    is accepted (no namespace-unknown error emitted)."""
    built = build_bundle(
        claims=[
            {
                "claim_id": "claim-1",
                "kind": "command_evidence",
                "command_id": "test-cmd",
                "exit_code": 0,
                "namespaces": {"x-relay": {"schema_version": "v1"}},
            },
        ],
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_NAMESPACE_UNKNOWN
    ]
    assert not matching, (
        f"VAL-V3M1-022: x-relay-only namespace must not be flagged; "
        f"got {matching!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-022")
def test_val_v3m1_022_missing_namespaces_field_accepted() -> None:
    """A claim with NO ``namespaces`` field (or an empty dict) is
    accepted -- the field is optional per spec K line 4421-4423."""
    built = build_bundle()  # default claims have no namespaces field
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_NAMESPACE_UNKNOWN
    ]
    assert not matching, (
        f"VAL-V3M1-022: missing namespaces field must not be flagged; "
        f"got {matching!r}"
    )
