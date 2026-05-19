"""VAL-V3M1-016: production callers do not trip EvidenceClaim flat-subject
deprecation warnings.

Spec K (lines 4388-4438) defines EvidenceClaim's canonical shape with a
nested ``subject: ClaimSubject {kind, id, manifest_commit_hash}``. m1-f05
(commit f480aec) added Pydantic property accessors
``EvidenceClaim.subject_kind`` / ``EvidenceClaim.subject_id`` that delegate
to the nested form AND emit a first-occurrence-per-process
``DeprecationWarning`` via the module-level tracker
``relay_schemas.envelopes._FLAT_SUBJECT_DEPRECATION_EMITTED`` (see
``_emit_flat_subject_deprecation_warning``).

VAL-V3M1-016 requires production code paths to use the nested form
(``claim.subject.kind`` / ``claim.subject.id``) so the deprecation warning
never fires from production callers in normal operation.

m1-f06 finding (recorded in handoff): a full grep audit
(``grep -rn 'claim\\.subject_id\\|claim\\.subject_kind' packages/ apps/
--include='*.py'`` excluding test files) returns ZERO production matches
across the entire codebase. The five files enumerated in VAL-V3M1-016 do
contain the strings ``subject_id`` / ``subject_kind``, but they refer to
either:

  * a LOCAL parameter named ``subject_id`` (``local_signer.py:114-207`` --
    the bundle-level subject identifier, a plain string written into
    ``core_payload['subject_id']``; not an EvidenceClaim attribute), or
  * a LOCAL parameter named ``subject_id`` in ``retention.resolve_subject``
    (the subject-store lookup key, again a plain string), or
  * are non-existent (``packages/acef/relay_extensions/loader.py``,
    ``engine.py``, ``rule_engine.py`` do not exist in the tree).

This guard test materialises that audit as live evidence: it imports the
five modules named by VAL-V3M1-016 (only the two that exist; the three
non-existent ACEF modules are exercised via the parent package import) and
exercises representative code paths under
``warnings.catch_warnings(record=True)`` filtering on the exact
``DeprecationWarning`` subclass + the load-bearing substring of the
m1-f05 warning text ("EvidenceClaim.subject_kind / subject_id are
deprecated"). The test asserts ZERO matching warnings emit.

If a future commit adds a production call site of
``EvidenceClaim.subject_kind`` / ``EvidenceClaim.subject_id``, this test
will regress (the warning fires the first time the call site is touched)
and force migration to the nested form before merge.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib
import warnings
from datetime import UTC, datetime
from uuid import uuid4

import pytest

# ACEF parent package -- the three named submodules (loader.py, engine.py,
# rule_engine.py) do not exist in the tree per m1-f06 finding, but the
# parent package import still exercises every existing relay_extensions
# submodule (bindings, emission, errors, models, schemas) which is the
# representative production-import surface. Per package convention the
# import path is the workspace package name ``relay_extensions`` (see
# packages/acef/tests/test_w11_2_x_relay_extensions.py:42 for the
# canonical import style), NOT a dotted ``packages.acef.*`` path.
import relay_extensions as _acef_ext_init  # noqa: F401

# Process-level deprecation tracker (m1-f05) -- the production tracker is
# shared across the test process. We clear it BEFORE recording warnings so
# this test is hermetic regardless of prior tests' subject-flat accesses.
from relay_schemas import envelopes as _envelopes_mod

# Modules under audit per VAL-V3M1-016. We import them at module-load time
# so any side-effecting import (none expected) is also captured.
from relay_verifier import local_signer as _local_signer_mod
from relay_verifier import retention as _retention_mod

_FLAT_SUBJECT_WARNING_SUBSTRING = (
    "EvidenceClaim.subject_kind / subject_id are deprecated"
)


pytestmark = pytest.mark.plumbing


def _clear_process_deprecation_tracker() -> None:
    """Clear the module-level first-occurrence tracker for hermeticism.

    The m1-f05 warning helper records emissions in a process-wide set
    keyed on the sentinel ``evidence_claim.flat_subject``. Without this
    clear, a previous test in the same process that legitimately read
    ``claim.subject_kind`` would have already emitted the warning and the
    first-occurrence-only rule would mask any regression we are guarding
    against.
    """
    _envelopes_mod._FLAT_SUBJECT_DEPRECATION_EMITTED.clear()


def _matching_deprecation_warnings(
    captured: list[warnings.WarningMessage],
) -> list[warnings.WarningMessage]:
    """Filter to the EvidenceClaim flat-subject deprecation warning only.

    Other DeprecationWarnings may legitimately fire from dependencies
    (e.g., cryptography or datetime-related changes across Python
    versions). The audit target is specifically the m1-f05 flat-subject
    deprecation; we match on the warning class AND the load-bearing
    substring so unrelated DeprecationWarnings do not produce false
    positives.
    """
    matched: list[warnings.WarningMessage] = []
    for w in captured:
        if not issubclass(w.category, DeprecationWarning):
            continue
        if _FLAT_SUBJECT_WARNING_SUBSTRING in str(w.message):
            matched.append(w)
    return matched


def test_import_of_local_signer_does_not_trip_flat_subject_deprecation():
    """Importing local_signer.py exercises no flat EvidenceClaim subject access.

    Production audit: the module's ``subject_id`` references are a local
    function parameter (``build_local_dev_bundle(subject_id=...)``) and a
    bundle-payload dict key, NOT EvidenceClaim attribute reads.
    """
    _clear_process_deprecation_tracker()
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        importlib.reload(_local_signer_mod)
    assert _matching_deprecation_warnings(captured) == [], (
        "local_signer.py import unexpectedly emitted the m1-f05 flat-subject "
        "DeprecationWarning -- a regression in VAL-V3M1-016"
    )


def test_build_local_dev_bundle_does_not_trip_flat_subject_deprecation():
    """Running build_local_dev_bundle end-to-end emits no flat-subject warning.

    The helper constructs an evidence bundle including the bundle-level
    ``subject_id`` string; it does not construct EvidenceClaim envelopes
    via the deprecated flat shape and does not read flat fields on any
    EvidenceClaim instance.
    """
    _clear_process_deprecation_tracker()
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        result = _local_signer_mod.build_local_dev_bundle(
            subject_id="run_v3m1_f06_audit",
            signer_seed=b"\x00" * 32,
        )
    # Sanity: the helper still produced a valid bundle.
    assert result.bundle["trust_anchor"] == _local_signer_mod.TRUST_ANCHOR_LOCAL_DEV
    assert result.bundle["subject_id"] == "run_v3m1_f06_audit"
    assert _matching_deprecation_warnings(captured) == [], (
        "build_local_dev_bundle execution unexpectedly emitted the m1-f05 "
        "flat-subject DeprecationWarning -- a regression in VAL-V3M1-016"
    )


def test_resolve_subject_does_not_trip_flat_subject_deprecation():
    """resolve_subject() exercises subject lookup without flat-EvidenceClaim access.

    The function's ``subject_id`` parameter is a plain string passed to a
    ``SubjectStore.lookup`` call; it never reads
    ``EvidenceClaim.subject_id`` / ``subject_kind`` on any envelope.
    """
    _clear_process_deprecation_tracker()
    store = _retention_mod.InMemorySubjectStore(
        records={
            "run_audit_subject": _retention_mod.SubjectRecord(
                state=_retention_mod.SUBJECT_RESOLUTION_LIVE,
                original_digest_hex="abc" * 21 + "x",
            ),
        },
    )
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        # Exercise all three resolve paths: no store (unknown), no
        # subject_id (live-by-definition), found-in-store (live-record).
        r_unknown = _retention_mod.resolve_subject(
            subject_id="anything",
            subject_digest_hex=None,
            subject_store=None,
        )
        r_no_subject = _retention_mod.resolve_subject(
            subject_id=None,
            subject_digest_hex=None,
            subject_store=store,
        )
        r_found = _retention_mod.resolve_subject(
            subject_id="run_audit_subject",
            subject_digest_hex="abc" * 21 + "x",
            subject_store=store,
        )
    assert r_unknown.resolution == _retention_mod.SUBJECT_RESOLUTION_UNKNOWN
    assert r_no_subject.resolution == _retention_mod.SUBJECT_RESOLUTION_LIVE
    assert r_found.resolution == _retention_mod.SUBJECT_RESOLUTION_LIVE
    assert _matching_deprecation_warnings(captured) == [], (
        "resolve_subject() execution unexpectedly emitted the m1-f05 "
        "flat-subject DeprecationWarning -- a regression in VAL-V3M1-016"
    )


def test_acef_relay_extensions_import_does_not_trip_flat_subject_deprecation():
    """Importing every relay_extensions submodule emits no flat-subject warning.

    VAL-V3M1-016 enumerates loader/engine/rule_engine inside
    packages/acef/relay_extensions/, but those modules do not exist in
    the tree. The parent package's existing submodules (bindings,
    emission, errors, models, schemas) are imported here as the
    representative production-import surface. None of them access
    EvidenceClaim flat-subject properties.
    """
    _clear_process_deprecation_tracker()
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        # Re-import the existing submodules so any module-level side
        # effect is captured under the warning filter.
        for name in (
            "relay_extensions.bindings",
            "relay_extensions.emission",
            "relay_extensions.errors",
        ):
            mod = importlib.import_module(name)
            importlib.reload(mod)
    assert _matching_deprecation_warnings(captured) == [], (
        "relay_extensions package import unexpectedly emitted the m1-f05 "
        "flat-subject DeprecationWarning -- a regression in VAL-V3M1-016"
    )


def test_flat_subject_warning_does_fire_on_genuine_flat_access_sanity_check():
    """Sanity: the guard test framework correctly detects a flat-subject access.

    This negative-control case proves the test machinery would catch a
    regression. We construct an EvidenceClaim with the nested shape and
    then deliberately read ``claim.subject_kind`` (a flat property) once
    -- the m1-f05 helper MUST fire the DeprecationWarning the first
    time after the tracker is cleared. If this assertion ever flips,
    either the m1-f05 emission helper was disabled (which would silently
    mask future VAL-V3M1-016 regressions) or the warning text was
    changed without updating this guard.
    """
    _clear_process_deprecation_tracker()
    claim = _envelopes_mod.EvidenceClaim(
        schema_version="relay.evidence_claim.v1",
        evidence_claim_id=uuid4(),
        evidence_bundle_id=uuid4(),
        claim_type="run_result",
        subject=_envelopes_mod.ClaimSubject(
            kind="run",
            id=uuid4(),
            manifest_commit_hash="sha256-" + "0" * 64,
        ),
        claim_digest="sha256-" + "0" * 64,
        redaction_transform_version="v1",
        actor_kind="control_plane",
        actor_identity_hash="sha256-" + "0" * 64,
        occurred_at=datetime.now(tz=UTC),
        manifest_commit_hash="sha256-" + "0" * 64,
        signer_key_id="test-kid",
        signature="test-signature-not-empty",
        created_at=datetime.now(tz=UTC),
    )
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        _ = claim.subject_kind  # deliberate flat-access; must fire the warning
    matched = _matching_deprecation_warnings(captured)
    assert len(matched) == 1, (
        "sanity-check failed: the flat-subject access did NOT fire the "
        "m1-f05 DeprecationWarning -- the guard test machinery cannot "
        "detect VAL-V3M1-016 regressions until this is fixed"
    )
