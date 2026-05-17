"""W10.4 subject-retention + local_dev trust-anchor surface tests.

Covers:
  * VAL-W10-037 (tombstone resolution)
  * VAL-W10-038 (redacted_after_signing resolution)
  * VAL-W10-041 (local_dev under default anchor -> WARN; strict -> ERROR;
                  BYO local-dev anchor -> no WARN)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    SUBJECT_RESOLUTION_LIVE,
    SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
    SUBJECT_RESOLUTION_TOMBSTONED,
    SUBJECT_RESOLUTION_UNKNOWN,
    WARN_LOCAL_DEV_UNSUPPORTED,
    InMemorySubjectStore,
    SubjectRecord,
    ValidateBundleOptions,
    validate_bundle,
)

# w9-2 unblocked these tests: the cryptographic RFC 3161 verifier is now
# wired. Tests pass the ephemeral fixture root via
# ValidateBundleOptions(tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem).


# ---------------------------------------------------------------------------
# VAL-W10-037: subject deleted under retention -> tombstoned resolution
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-037")
def test_subject_deleted_under_retention_resolves_tombstoned() -> None:
    """When the referenced subject is absent from the store the verifier
    MUST resolve to 'tombstoned' and still pass."""
    built = build_bundle(subject_id="run_01j0test")
    empty_store = InMemorySubjectStore()  # subject NOT in store
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            subject_store=empty_store,
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["subject_resolution"] == SUBJECT_RESOLUTION_TOMBSTONED
    assert output["overall"] == "pass", output


# ---------------------------------------------------------------------------
# VAL-W10-038: subject redacted after signing -> redacted_after_signing
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-038")
def test_subject_redacted_after_signing_resolves_redacted() -> None:
    """Subject present in store with state='redacted_after_signing' AND
    the original digest preserved -> verifier resolves accordingly."""
    built = build_bundle(subject_id="run_01j0test")
    # The default subject_digest_hex is SHA-256 of the subject_id.
    import hashlib
    expected_digest = hashlib.sha256(b"run_01j0test").hexdigest()
    store = InMemorySubjectStore({
        "run_01j0test": SubjectRecord(
            state=SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
            original_digest_hex=expected_digest,
        ),
    })
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(subject_store=store),
    )
    assert output["subject_resolution"] == SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING
    # Original digest binding preserved (no subject_digest_drift warning).
    drift_warnings = [
        w for w in output["warnings"]
        if w["reason"] == "subject_digest_drift"
    ]
    assert drift_warnings == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-038")
def test_subject_live_in_store_resolves_live() -> None:
    """Subject present and live -> resolution='live'."""
    built = build_bundle(subject_id="run_01j0test")
    import hashlib
    expected_digest = hashlib.sha256(b"run_01j0test").hexdigest()
    store = InMemorySubjectStore({
        "run_01j0test": SubjectRecord(
            state=SUBJECT_RESOLUTION_LIVE,
            original_digest_hex=expected_digest,
        ),
    })
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(subject_store=store),
    )
    assert output["subject_resolution"] == SUBJECT_RESOLUTION_LIVE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-037")
def test_subject_resolution_unknown_without_store() -> None:
    """When no subject_store is supplied, resolution stays 'unknown'."""
    built = build_bundle(subject_id="run_01j0test")
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["subject_resolution"] == SUBJECT_RESOLUTION_UNKNOWN


# ---------------------------------------------------------------------------
# VAL-W10-041: local_dev bundles WARN by default, ERROR under strict
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-041")
def test_local_dev_under_default_anchor_emits_warn_exit_0() -> None:
    """trust_anchor='local_dev' under the default trust anchor MUST
    emit WARN with reason 'local_dev_unsupported_for_audit', exit 0."""
    built = build_bundle(trust_anchor="local_dev")
    # No default-anchor override -> default trust anchor in effect.
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    # WARN present with the canonical reason.
    matching_warns = [
        w for w in output["warnings"]
        if w["reason"] == WARN_LOCAL_DEV_UNSUPPORTED
    ]
    assert matching_warns, output["warnings"]
    # trust_anchor surfaced verbatim.
    assert output["trust_anchor"] == "local_dev"
    # Exit code stays 0 (overall pass).
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-041")
def test_local_dev_under_strict_trust_anchor_is_error_exit_nonzero() -> None:
    """`--strict-trust-anchor` -> local_dev becomes ERROR (exit non-zero)."""
    built = build_bundle(trust_anchor="local_dev")
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
        options=ValidateBundleOptions(strict_trust_anchor=True),
    )
    matching_errors = [
        e for e in output["errors"]
        if e["reason"] == WARN_LOCAL_DEV_UNSUPPORTED
    ]
    assert matching_errors, output["errors"]
    assert output["overall"] == "fail"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-041")
def test_local_dev_under_byo_local_anchor_no_warn() -> None:
    """When the verifier is configured via BYO trust anchor (a local dev
    JWKS), local_dev bundles MUST validate normally with no WARN."""
    built = build_bundle(trust_anchor="local_dev")
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="byo_flag",  # not the default
        options=ValidateBundleOptions(
            default_trust_anchor="http://localhost:8080/jwks.json",
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    matching = [
        w for w in output["warnings"]
        if w["reason"] == WARN_LOCAL_DEV_UNSUPPORTED
    ]
    assert matching == [], (
        "BYO anchor should suppress local_dev WARN; got: " + repr(output["warnings"])
    )
    assert output["overall"] == "pass", output
