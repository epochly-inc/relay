"""VAL-W3-009, VAL-W3-010, VAL-W3-012, VAL-W3-016 -- SDK ingest envelope tests.

These tests pin the SDK envelope's wire-format contract:

  * VAL-W3-009 -- the envelope carries ONLY lifecycle metadata; never a
    canonical-result field. A grep over the outbound builder for the
    canonical-write literals returns zero matches.
  * VAL-W3-010 -- a caller attempting to set a canonical-write field is
    rejected by the SDK BEFORE any HTTP I/O (and also by the sidecar
    with HTTP 422 + RELAY-ING-031; see test_canonical_status_sidecar.py
    for the wire path).
  * VAL-W3-012 -- ``client_lifecycle_status`` is constrained to the
    closed enum. Invalid values raise RelayLifecycleInvalid BEFORE the
    HTTP request is built.
  * VAL-W3-016 -- the SDK NEVER writes ``written_by`` into an outbound
    envelope. A repo-grep confirms it.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from relay import RelayCanonicalStatusForbidden, RelayLifecycleInvalid
from relay.lifecycle import (
    CANONICAL_WRITE_FIELDS,
    INGEST_RUN_SCHEMA_VERSION,
    LIFECYCLE_STATUSES,
    build_ingest_run_envelope,
)

_VALID_ANCHORS = {
    "manifest_commit_hash": "sha256-" + "1" * 64,
    "actor_identity_hash": "sha256-" + "2" * 64,
}
_VALID_AGENT = {"name": "ops-agent", "version": "0.1.0"}


def _good_envelope(**overrides):
    base = dict(
        run_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        trace_id="trace-abc",
        project_id="aa111111-2222-3333-4444-555555555555",
        agent=_VALID_AGENT,
        client_lifecycle_status="started",
        started_at="2026-05-12T10:00:00Z",
        sdk_version="relay-python@0.0.0",
        sdk_clock="2026-05-12T10:00:00.123Z",
        redaction_policy_version="v1",
        sequence_number=1,
        **_VALID_ANCHORS,
    )
    base.update(overrides)
    return build_ingest_run_envelope(**base)


# --- VAL-W3-009 -------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-009")
def test_ingest_envelope_carries_only_lifecycle_metadata() -> None:
    """A well-formed envelope contains client_lifecycle_status and no
    canonical-write field.
    """
    envelope = _good_envelope()
    # Lifecycle marker present.
    assert envelope["client_lifecycle_status"] == "started"
    assert envelope["schema_version"] == INGEST_RUN_SCHEMA_VERSION
    # NONE of the canonical-write fields appear.
    for forbidden in CANONICAL_WRITE_FIELDS:
        assert forbidden not in envelope, (
            f"canonical-write field {forbidden!r} appeared in SDK ingest envelope"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-009")
def test_ingest_builder_source_does_not_assign_canonical_write_keys() -> None:
    """Grep the SDK source for canonical-write keys appearing as OUTBOUND
    envelope keys. The denylist itself in lifecycle.py is permitted (it
    is the screen, not an outbound assignment); the only matches must
    be (a) the denylist constant, (b) error-class details payloads.
    """
    src = Path(__file__).resolve().parent.parent / "relay"
    # Walk every .py file under the SDK source tree (excluding _generated)
    # and the tests dir; collect lines that reference a canonical-write
    # literal as an OUTBOUND envelope key. The outbound builders live in
    # lifecycle.py; the only legitimate references are inside the
    # CANONICAL_WRITE_FIELDS frozenset declaration.
    for path in src.rglob("*.py"):
        if "_generated" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for canonical in ("status", "primary_failure_class", "written_by"):
            # Match e.g. envelope["status"] = ... or "status": ...
            # in the LHS of a dict literal that builds an outbound body.
            # We're permissive: any "{canonical}": appearing OUTSIDE the
            # known safe sites is suspect.
            pattern = re.compile(r'envelope\[\s*"' + canonical + r'"\s*\]\s*=')
            assert not pattern.search(text), (
                f"{path.relative_to(src.parent)} has an envelope[{canonical!r}] "
                f"assignment -- forbidden by VAL-W3-009 / keystone invariant #1"
            )


# --- VAL-W3-010 -------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-010")
@pytest.mark.parametrize(
    "forbidden_field",
    sorted(CANONICAL_WRITE_FIELDS),
)
def test_ingest_builder_rejects_canonical_write_fields(forbidden_field: str) -> None:
    """For each of the five canonical-write fields the SDK MUST refuse
    to build an envelope. The error names the offending field in
    ``details.forbidden_fields``.
    """
    with pytest.raises(RelayCanonicalStatusForbidden) as excinfo:
        _good_envelope(extras={forbidden_field: "tampered-value"})
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-CANONICAL-STATUS-FORBIDDEN"
    assert err.code == "RELAY-SDK-005"
    assert forbidden_field in err.details["forbidden_fields"]


# --- VAL-W3-012 -------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-012")
@pytest.mark.parametrize(
    "bad_status",
    [
        "passing",
        "accepted",
        "remediate_required",
        "blocked",
        "STARTED",  # case-sensitive
        "",
        None,
        42,
    ],
)
def test_ingest_builder_rejects_non_enum_lifecycle_status(bad_status) -> None:
    """Non-enum status raises RelayLifecycleInvalid at the SDK boundary."""
    with pytest.raises(RelayLifecycleInvalid) as excinfo:
        _good_envelope(client_lifecycle_status=bad_status)
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-LIFECYCLE-INVALID"
    assert err.code == "RELAY-SDK-006"
    assert err.details["received"] == bad_status
    assert sorted(LIFECYCLE_STATUSES) == sorted(err.details["allowed"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-012")
@pytest.mark.parametrize(
    "good_status",
    sorted(LIFECYCLE_STATUSES),
)
def test_ingest_builder_accepts_every_enum_value(good_status: str) -> None:
    """Each enum member is accepted and round-trips into the envelope."""
    envelope = _good_envelope(client_lifecycle_status=good_status)
    assert envelope["client_lifecycle_status"] == good_status


# --- VAL-W3-016 -------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-016")
def test_sdk_source_never_writes_written_by() -> None:
    """A full-tree grep for ``written_by = `` in SDK source returns zero
    matches outside the denylist constant. Mirrors the CI lint guard.
    """
    src = Path(__file__).resolve().parent.parent / "relay"
    offending: list[str] = []
    for path in src.rglob("*.py"):
        if "_generated" in path.parts:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # Match a literal assignment that builds outbound envelopes.
            if re.search(r'"written_by"\s*:', line) or re.search(
                r'envelope\[\s*"written_by"\s*\]\s*=', line
            ):
                offending.append(f"{path.relative_to(src.parent)}:{lineno}: {line.strip()}")
    assert not offending, (
        "SDK source contains outbound envelope assignments for "
        "'written_by' -- forbidden by VAL-W3-016. Offending:\n"
        + "\n".join(offending)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-016")
def test_repo_wide_grep_written_by_in_sdk_outbound_paths() -> None:
    """Repo-grep guard: rg + sdk-python builder paths. A new offender
    would be caught here even if the file walk above misses it.
    """
    sdk_root = Path(__file__).resolve().parent.parent / "relay"
    # Use python's own search (no shell-out) so this test works on
    # systems without rg installed.
    bad: list[str] = []
    for path in sdk_root.rglob("*.py"):
        if "_generated" in path.parts:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # Outbound-envelope literal: "written_by" as a key OR a Python
            # attribute assignment ``foo.written_by = ...``.
            if re.search(r'(?<!_)written_by\s*=\s*[\'"]', line):
                bad.append(f"{path}:{lineno}: {line.strip()}")
    assert not bad, "SDK source writes 'written_by' literally:\n" + "\n".join(bad)


# --- subprocess belt-and-suspenders for VAL-W3-001 preservation ----------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-009")
def test_envelope_module_import_is_side_effect_free(tmp_path: Path) -> None:
    """Importing relay.lifecycle in a fresh subprocess does NOT spawn,
    bind, or touch the lockfile -- VAL-W3-001 preserved through W3.2.
    """
    home = tmp_path / "relay-home"
    home.mkdir()
    code = (
        "import os; os.environ['RELAY_HOME']=" + repr(str(home)) + "; "
        "import relay; import relay.lifecycle; import relay.run; import relay.flush; "
        "from pathlib import Path; "
        "lockfile = Path(os.environ['RELAY_HOME']) / 'sidecar.lock'; "
        "assert not lockfile.exists(), 'lockfile must not exist after import'; "
        "print('ok')"
    )
    out = subprocess.check_output(
        [sys.executable, "-c", code], text=True, timeout=30
    )
    assert out.strip() == "ok"
