"""W1.5 codegen pipeline contract tests.

Covers:
  VAL-W1-032 single OpenAPI 3.1 source of truth + 14-envelope coverage
  VAL-W1-033 generated Python imports cleanly, BaseModel + extra='forbid'
  VAL-W1-035 drift-check happy path AND simulated-drift exit-non-zero path
  VAL-W1-036 forward-compat unknown schema_version hard error
  VAL-W1-037 snake_case <-> camelCase alias map (Python side)

Tier-1 plumbing tests (offline, every commit, <= 60s).

Tool: pytest
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    # packages/schemas/python/tests/test_codegen_pipeline.py -> repo root
    return Path(__file__).resolve().parents[4]


def _openapi_doc() -> dict:
    return yaml.safe_load(
        (_repo_root() / "packages" / "schemas" / "raw" / "openapi.yaml").read_text(
            encoding="utf-8"
        )
    )


CANONICAL_ENVELOPES: tuple[str, ...] = (
    "RunResult",
    "GateDecision",
    "GateDecisionDraft",
    "GateRound",
    "ManifestVersion",
    "ScopeState",
    "IdempotencyRecord",
    "EventLogEntry",
    "EvidenceBundle",
    "EvidenceClaim",
    "ReplayCase",
    "ReplayFixture",
    "RedactionPolicy",
    "ErrorEnvelope",
)


def _valid_run_result_payload() -> dict:
    return {
        "schema_version": "relay.run_result.v1",
        "run_result_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "written_by": "control_plane",
        "status": "blocked",
        "manifest_commit_hash": "sha256-" + "a" * 64,
        "actor_identity_hash": "sha256-" + "b" * 64,
        "decided_at": "2026-05-13T12:00:00+00:00",
        "signature": "signature-bytes",
        "signature_key_id": "key-1",
    }


# ---------------------------------------------------------------------------
# VAL-W1-032: single OpenAPI 3.1 source of truth + coverage invariant
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-032")
def test_openapi_doc_exists() -> None:
    """packages/schemas/raw/openapi.yaml MUST exist."""
    p = _repo_root() / "packages" / "schemas" / "raw" / "openapi.yaml"
    assert p.is_file(), f"missing canonical OpenAPI doc: {p}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-032")
def test_openapi_is_3_1() -> None:
    """The document MUST declare openapi: 3.1.x."""
    doc = _openapi_doc()
    assert str(doc.get("openapi", "")).startswith("3.1"), (
        f"expected openapi: 3.1.x; got {doc.get('openapi')!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-032")
@pytest.mark.parametrize("envelope", CANONICAL_ENVELOPES)
def test_envelope_appears_exactly_once_in_components_schemas(envelope: str) -> None:
    """Each canonical envelope MUST appear in exactly ONE components.schemas entry."""
    doc = _openapi_doc()
    schemas = doc.get("components", {}).get("schemas", {})
    matches = [k for k in schemas if k == envelope]
    assert len(matches) == 1, (
        f"VAL-W1-032: envelope {envelope!r} appears {len(matches)} times "
        f"in components.schemas; expected exactly 1"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-032")
def test_no_hand_authored_json_schema_files_in_raw() -> None:
    """No .schema.json hand-authored files in raw/.

    VAL-W1-032 forbids hand-authored JSON Schema files outside the derived
    output. The canonical custom-format envelopes.yaml is documentation only,
    not a JSON Schema, and is permitted.
    """
    raw_dir = _repo_root() / "packages" / "schemas" / "raw"
    schema_jsons = list(raw_dir.glob("**/*.schema.json"))
    assert schema_jsons == [], (
        f"VAL-W1-032: hand-authored JSON Schema files forbidden in raw/: "
        f"{schema_jsons}"
    )


# ---------------------------------------------------------------------------
# VAL-W1-033: generated Python imports cleanly with extra='forbid'
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-033")
def test_generated_python_imports_cleanly() -> None:
    """The full 14-name import surface MUST succeed."""
    mod = importlib.import_module("relay._generated.schemas")
    for name in CANONICAL_ENVELOPES:
        assert hasattr(mod, name), f"missing symbol: {name}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-033")
@pytest.mark.parametrize("envelope", CANONICAL_ENVELOPES)
def test_generated_class_is_basemodel_with_extra_forbid(envelope: str) -> None:
    """Every generated envelope MUST be a BaseModel with extra='forbid'.

    Discriminated unions (ScopeState, RedactionPolicy matchers) wrap a
    RootModel; check that property structurally.
    """
    mod = importlib.import_module("relay._generated.schemas")
    klass = getattr(mod, envelope)
    if envelope == "ScopeState":
        # RootModel-wrapped discriminated union; the underlying variants are
        # BaseModel subclasses with extra='forbid'. Validate one variant.
        from relay._generated.schemas import RunScopeState

        assert issubclass(RunScopeState, BaseModel)
        assert RunScopeState.model_config.get("extra") == "forbid"
        return
    assert issubclass(klass, BaseModel), (
        f"VAL-W1-033: {envelope} is not a BaseModel subclass; got {klass!r}"
    )
    assert klass.model_config.get("extra") == "forbid", (
        f"VAL-W1-033: {envelope}.model_config['extra'] expected 'forbid'; "
        f"got {klass.model_config.get('extra')!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-033")
def test_generated_run_result_accepts_valid_payload() -> None:
    """Smoke test: a valid RunResult payload validates cleanly."""
    from relay._generated.schemas import RunResult

    r = RunResult.model_validate(_valid_run_result_payload())
    assert r.status == "blocked"
    assert r.written_by == "control_plane"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-033")
def test_generated_models_module_carries_extra_forbid_text() -> None:
    """The generated _models.py source MUST contain extra='forbid' markers.

    Inspect via reading the file rather than introspecting the class because
    the contract requires the model_config DECLARATION (not just runtime
    behavior).
    """
    models = _repo_root() / "packages" / "sdk-python" / "relay" / "_generated" / "_models.py"
    text = models.read_text(encoding="utf-8")
    # The trial run confirmed: every BaseModel emits `extra="forbid"`.
    # Count occurrences; one per BaseModel class.
    assert text.count('extra="forbid"') >= len(CANONICAL_ENVELOPES) - 1, (
        f"VAL-W1-033: expected >= {len(CANONICAL_ENVELOPES) - 1} extra='forbid' "
        f"declarations; found {text.count('extra=\"forbid\"')}"
    )


# ---------------------------------------------------------------------------
# VAL-W1-035: drift check happy + simulated-drift paths
# ---------------------------------------------------------------------------


def _run_drift_check() -> subprocess.CompletedProcess:
    """Invoke scripts/check-codegen-drift.py and capture exit code + stderr."""
    return subprocess.run(
        [sys.executable, str(_repo_root() / "scripts" / "check-codegen-drift.py")],
        check=False,
        capture_output=True,
        text=True,
        cwd=_repo_root(),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-035")
def test_drift_check_exits_zero_on_clean_tree() -> None:
    """With committed generated trees matching fresh codegen, drift check exits 0."""
    result = _run_drift_check()
    assert result.returncode == 0, (
        f"drift check returned {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "0 files differ" in result.stdout, (
        f"expected happy-path log; got stdout={result.stdout!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-035")
def test_drift_check_exits_nonzero_on_simulated_drift(tmp_path: Path) -> None:
    """Edit a generated file in-place; drift check MUST exit non-zero and emit [drift] line."""
    target = (
        _repo_root() / "packages" / "sdk-python" / "relay" / "_generated" / "_models.py"
    )
    original = target.read_text(encoding="utf-8")
    backup = tmp_path / "_models.py.backup"
    backup.write_text(original, encoding="utf-8")
    try:
        target.write_text(original + "\n# DRIFT TEST MARKER\n", encoding="utf-8")
        result = _run_drift_check()
        assert result.returncode != 0, (
            f"drift check should exit non-zero on simulated drift; "
            f"got {result.returncode}"
        )
        # Captured log line MUST identify the drifted file.
        assert "[drift]" in result.stderr, (
            f"expected '[drift]' marker in stderr; got {result.stderr!r}"
        )
        assert "_models.py" in result.stderr, (
            f"drift log should name _models.py; got {result.stderr!r}"
        )
    finally:
        target.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")


# ---------------------------------------------------------------------------
# VAL-W1-036: forward-compat unknown schema_version
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-036")
def test_parse_envelope_raises_relay_unknown_schema_version_error_on_v99() -> None:
    """A payload with relay.run_result.v99 MUST raise RelayUnknownSchemaVersionError."""
    from relay._generated.schemas import (
        RelayUnknownSchemaVersionError,
        RunResult,
        parse_envelope,
    )

    payload = _valid_run_result_payload()
    payload["schema_version"] = "relay.run_result.v99"
    with pytest.raises(RelayUnknownSchemaVersionError) as exc_info:
        parse_envelope(RunResult, payload)
    err = exc_info.value
    assert err.envelope_kind == "RunResult"
    assert err.observed_version == "relay.run_result.v99"
    assert "v1" in err.expected_version
    # Message must clearly say "unknown" + schema_version-related text.
    message = str(err)
    assert "unknown" in message.lower()
    assert "v99" in message


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-036")
def test_parse_envelope_accepts_known_schema_version() -> None:
    """A payload with the correct schema_version MUST succeed."""
    from relay._generated.schemas import RunResult, parse_envelope

    parsed = parse_envelope(RunResult, _valid_run_result_payload())
    assert isinstance(parsed, RunResult)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-036")
def test_relay_unknown_schema_version_error_is_value_error_subclass() -> None:
    """The error class MUST be a ValueError subclass so callers can catch broadly."""
    from relay._generated.schemas import RelayUnknownSchemaVersionError

    assert issubclass(RelayUnknownSchemaVersionError, ValueError)


# ---------------------------------------------------------------------------
# VAL-W1-037: snake_case <-> camelCase alias map (Python side)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-037")
def test_alias_module_exposes_field_aliases_by_envelope() -> None:
    """The aliases module MUST export FIELD_ALIASES_BY_ENVELOPE."""
    from relay._generated import aliases

    assert hasattr(aliases, "FIELD_ALIASES_BY_ENVELOPE")
    table = aliases.FIELD_ALIASES_BY_ENVELOPE
    assert isinstance(table, dict)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-037")
def test_alias_map_uses_camel_case_for_snake_case_run_result_id() -> None:
    """Field run_result_id MUST map to camelCase runResultId on RunResult."""
    from relay._generated.aliases import FIELD_ALIASES_BY_ENVELOPE

    table = FIELD_ALIASES_BY_ENVELOPE["RunResult"]
    assert table["run_result_id"] == "runResultId"
    assert table["evidence_bundle_id"] == "evidenceBundleId"
    assert table["manifest_commit_hash"] == "manifestCommitHash"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-037")
def test_alias_helpers_round_trip() -> None:
    """snake_to_camel and camel_to_snake MUST be inverse for known envelopes."""
    from relay._generated.aliases import camel_to_snake, snake_to_camel

    fwd = snake_to_camel("RunResult")
    inv = camel_to_snake("RunResult")
    assert fwd, "RunResult should have alias entries"
    for snake, camel in fwd.items():
        assert inv[camel] == snake, f"round-trip broken for {snake} <-> {camel}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-037")
def test_python_side_serializes_snake_case_by_default() -> None:
    """The Python BaseModel MUST emit snake_case field names by default.

    A RunResult constructed with snake_case payload re-serializes back to
    snake_case JSON without any alias transformation. This is the Python
    half of the cross-language round-trip evidence.
    """
    from relay._generated.schemas import RunResult

    r = RunResult.model_validate(_valid_run_result_payload())
    dumped = r.model_dump(mode="json")
    # Every key in the dump MUST be snake_case (no camelCase keys).
    for key in dumped:
        assert "_" in key or key.islower() or key in {"signature", "round", "status"}, (
            f"VAL-W1-037: Python side emitted a key {key!r} that looks "
            f"camelCase; canonical wire form is snake_case"
        )
    # Specifically: run_result_id present, runResultId absent.
    assert "run_result_id" in dumped
    assert "runResultId" not in dumped


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-037")
def test_alias_map_has_entries_for_every_canonical_envelope_with_snake_case_fields() -> None:
    """Every envelope whose schema has snake_case fields MUST appear in the alias map.

    Discriminated unions and shared scalar root models (Sha256Hash, Ulid, etc.)
    have no field aliases (no `properties:` block) and are correctly absent.
    """
    from relay._generated.aliases import FIELD_ALIASES_BY_ENVELOPE

    # The 14 primary envelopes minus the union types (which dispatch to variants).
    object_envelopes = [
        e for e in CANONICAL_ENVELOPES
        if e not in ("ScopeState",)  # ScopeState is a union dispatcher
    ]
    for env in object_envelopes:
        assert env in FIELD_ALIASES_BY_ENVELOPE, (
            f"VAL-W1-037: alias map missing entry for envelope {env}"
        )


# ---------------------------------------------------------------------------
# Bound the file just below so future workers can extend without re-parsing.
# ---------------------------------------------------------------------------
_ = datetime
_ = timezone
