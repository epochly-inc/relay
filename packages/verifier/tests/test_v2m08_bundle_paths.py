"""VAL-V2M08-015..017: validate_bundle wires check_artifact_path.

The 2026-05-17 whole-codebase audit surfaced that ``check_artifact_path``
(packages/verifier/src/relay_verifier/bundle_paths.py) defines NFC +
UTF-8 + absolute-path + ``..`` segment defenses but had ZERO callers.
``validate_bundle`` was forwarding ``evidence_refs[].artifact_id``
directly to ``opts.artifact_resolver(...)`` with no path-traversal
screening. A bundle declaring ``artifact_id: "../../etc/passwd"`` would
reach the caller-supplied resolver unfiltered.

This module asserts the wiring: every ``evidence_refs[].artifact_id``
is screened by :func:`check_artifact_path` BEFORE the resolver is
invoked. A bundle declaring an absolute, ``..``-bearing, non-NFC, or
invalid-UTF-8 ``artifact_id`` is rejected with the matching
``path_violation`` discriminator and the resolver is never called.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# Sibling helper import (mirror test_w10_4_bundle_validator.py).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    RELAY_EVID_024,
    ValidateBundleOptions,
    validate_bundle,
)


def _bundle_with_artifact_id(bad_id: str):
    """Construct a signed bundle whose sole evidence_ref.artifact_id is
    ``bad_id``. The claim is rebuilt and re-signed so the bundle's JWS
    signature is valid -- forcing the path-screen to be the gate that
    catches the malicious id."""
    artifact_bytes = b"artifact-bytes"
    claims = [
        {
            "claim_id": "claim-1",
            "kind": "command_evidence",
            "command_id": "test-cmd",
            "exit_code": 0,
            "artifact_id": bad_id,
            "evidence_refs": [
                {
                    "artifact_id": bad_id,
                    "digest": hashlib.sha256(artifact_bytes).hexdigest(),
                },
            ],
        },
    ]
    return build_bundle(claims=claims)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-015")
def test_validate_bundle_rejects_relative_traversal_artifact_id() -> None:
    """An ``artifact_id`` carrying a ``..`` segment is rejected by
    :func:`validate_bundle` with the ``relative_traversal``
    path_violation discriminator. The caller-supplied resolver is NEVER
    invoked on the malicious id."""
    bad_id = "../../etc/passwd"
    built = _bundle_with_artifact_id(bad_id)
    resolver_calls: list[str] = []

    def resolver(artifact_id: str) -> bytes:
        resolver_calls.append(artifact_id)
        return b"artifact-bytes"

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            artifact_resolver=resolver,
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["overall"] == "fail", output
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_024
        and e.get("path_violation") == "relative_traversal"
    ]
    assert matching, output["errors"]
    assert matching[0]["offending_path"] == bad_id
    # Resolver MUST NOT have been invoked on the bad id.
    assert bad_id not in resolver_calls, resolver_calls


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-016")
def test_validate_bundle_rejects_absolute_artifact_id() -> None:
    """An absolute ``artifact_id`` is rejected with ``absolute_path``
    and the resolver is never called."""
    bad_id = "/etc/passwd"
    built = _bundle_with_artifact_id(bad_id)
    resolver_calls: list[str] = []

    def resolver(artifact_id: str) -> bytes:
        resolver_calls.append(artifact_id)
        return b"artifact-bytes"

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            artifact_resolver=resolver,
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["overall"] == "fail", output
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_024
        and e.get("path_violation") == "absolute_path"
    ]
    assert matching, output["errors"]
    assert matching[0]["offending_path"] == bad_id
    assert bad_id not in resolver_calls, resolver_calls


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-016")
def test_validate_bundle_rejects_windows_unc_artifact_id() -> None:
    """A Windows UNC ``artifact_id`` is rejected with ``absolute_path``."""
    bad_id = "\\\\host\\share\\file"
    built = _bundle_with_artifact_id(bad_id)

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            artifact_resolver=lambda _aid: b"artifact-bytes",
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["overall"] == "fail", output
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_024
        and e.get("path_violation") == "absolute_path"
    ]
    assert matching, output["errors"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-017")
def test_validate_bundle_rejects_non_nfc_artifact_id() -> None:
    """A non-NFC ``artifact_id`` (e.g. NFD ``cafe`` + combining acute)
    is rejected with ``non_nfc_name``."""
    import unicodedata

    bad_id = "artifacts/" + unicodedata.normalize("NFD", "café.txt")
    built = _bundle_with_artifact_id(bad_id)

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            artifact_resolver=lambda _aid: b"artifact-bytes",
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["overall"] == "fail", output
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_024
        and e.get("path_violation") == "non_nfc_name"
    ]
    assert matching, output["errors"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-015")
def test_validate_bundle_accepts_clean_relative_artifact_id() -> None:
    """A clean relative ``artifact_id`` under ``artifacts/`` is NOT
    rejected by the path-screen; the bundle verifies normally and the
    resolver is invoked."""
    good_id = "artifacts/run-001/output.json"
    artifact_bytes = b"clean-artifact-bytes"
    claims = [
        {
            "claim_id": "claim-1",
            "kind": "command_evidence",
            "command_id": "test-cmd",
            "exit_code": 0,
            "artifact_id": good_id,
            "evidence_refs": [
                {
                    "artifact_id": good_id,
                    "digest": hashlib.sha256(artifact_bytes).hexdigest(),
                },
            ],
        },
    ]
    built = build_bundle(claims=claims)
    resolver_calls: list[str] = []

    def resolver(artifact_id: str) -> bytes:
        resolver_calls.append(artifact_id)
        return artifact_bytes

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            artifact_resolver=resolver,
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    # No path-violation errors.
    path_errors = [
        e for e in output["errors"]
        if e.get("path_violation") is not None
    ]
    assert not path_errors, path_errors
    # Resolver WAS called on the clean id.
    assert good_id in resolver_calls, resolver_calls
    # End-to-end happy path.
    assert output["overall"] == "pass", output


__all__ = []
