"""V3M1-F02 (2026-05-18): RunResult no-array guard.

Per spec §A.1 the RunResult envelope binds to its contract results and
gate decisions via the dedicated join tables ``run_result_contract_results``
and ``run_result_gate_decisions`` (locked in by V3M1-F01). The historical
array-column form (``contract_result_ids`` / ``gate_decision_ids`` as
``uuid[]`` / ``list[UUID]`` columns directly on RunResult) MUST NOT be
reintroduced on the wire-format envelope, because:

  1. Array FKs cannot be enforced at the database layer in Postgres,
     defeating the CLAUDE.md keystone invariant #8 (atomic primitives +
     allowlisted tables route every write through ``transactional_db_write_raw``).
  2. The join tables provide the canonical normalization point and the
     control-plane write path; restoring array columns would create two
     sources of truth and let the SDK bypass the join-table write rule.
  3. CLAUDE.md keystone invariant #1 (control plane writes the result):
     the SDK must never set canonical relationship state on RunResult.
     Array fields on the envelope make that bypass trivial.

This is a PURE GUARD test. The current tree already lacks these fields
(reviewer B confirmed at pass-2). This test locks in the absence so a
future PR cannot silently reintroduce them.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

Assertion: VAL-V3M1-004.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from relay_schemas.envelopes import RunResult

# -----------------------------------------------------------------------------
# Banned field names (the historical array-column form).
# -----------------------------------------------------------------------------

_BANNED_RUN_RESULT_FIELDS: tuple[str, ...] = (
    "contract_result_ids",
    "gate_decision_ids",
)

# Tests in this package live four levels deep:
#   relay/packages/schemas/python/tests/test_v3m1_runresult_no_array.py
#   parents[4] -> relay/
_REPO_ROOT = Path(__file__).resolve().parents[4]
_ENVELOPES_YAML = (
    _REPO_ROOT / "packages" / "schemas" / "raw" / "envelopes.yaml"
)


# -----------------------------------------------------------------------------
# VAL-V3M1-004: Pydantic RunResult does not carry array forms.
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_004_runresult_pydantic_has_no_contract_result_ids_field() -> None:
    """RunResult.model_fields MUST NOT contain ``contract_result_ids``.

    Reintroducing this field would bypass the join table
    ``run_result_contract_results`` and break atomic-write enforcement.
    """
    assert "contract_result_ids" not in RunResult.model_fields, (
        "RunResult must NOT declare 'contract_result_ids'. The canonical "
        "binding lives in the run_result_contract_results join table per "
        "spec A.1 + CLAUDE.md keystone invariants #1 and #8. "
        f"Observed model_fields: {sorted(RunResult.model_fields.keys())!r}"
    )


@pytest.mark.plumbing
def test_val_v3m1_004_runresult_pydantic_has_no_gate_decision_ids_field() -> None:
    """RunResult.model_fields MUST NOT contain ``gate_decision_ids``.

    Reintroducing this field would bypass the join table
    ``run_result_gate_decisions`` and break atomic-write enforcement.
    """
    assert "gate_decision_ids" not in RunResult.model_fields, (
        "RunResult must NOT declare 'gate_decision_ids'. The canonical "
        "binding lives in the run_result_gate_decisions join table per "
        "spec A.1 + CLAUDE.md keystone invariants #1 and #8. "
        f"Observed model_fields: {sorted(RunResult.model_fields.keys())!r}"
    )


@pytest.mark.plumbing
def test_val_v3m1_004_runresult_pydantic_no_banned_array_fields_combined() -> None:
    """Combined assertion: neither banned array field appears on RunResult.

    Defensive double-check (in addition to the per-field tests above) to
    make a single grep-able failure if either reintroduction lands.
    """
    observed = set(RunResult.model_fields.keys())
    leaked = observed & set(_BANNED_RUN_RESULT_FIELDS)
    assert leaked == set(), (
        "RunResult reintroduced banned array field(s): "
        f"{sorted(leaked)!r}. Canonical relationships live in the join "
        "tables run_result_contract_results and run_result_gate_decisions."
    )


# -----------------------------------------------------------------------------
# VAL-V3M1-004: envelopes.yaml RunResult section does not declare array fields.
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_004_envelopes_yaml_runresult_no_array_fields() -> None:
    """envelopes.yaml RunResult.fields MUST NOT declare the banned array fields.

    The Pydantic model is generated from / aligned with the YAML source of
    truth; if YAML stays clean and the codegen drift check is green, the
    model stays clean too. This test asserts the YAML side directly.
    """
    assert _ENVELOPES_YAML.exists(), (
        f"envelopes.yaml not found at {_ENVELOPES_YAML} -- repo layout "
        "changed? Update _ENVELOPES_YAML path."
    )

    with _ENVELOPES_YAML.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    assert isinstance(doc, dict), "envelopes.yaml top level must be a mapping"
    schemas = doc.get("schemas")
    assert isinstance(schemas, dict), (
        "envelopes.yaml must declare a top-level 'schemas' mapping; "
        f"observed top-level keys: {sorted(doc.keys())!r}"
    )
    run_result = schemas.get("RunResult")
    assert isinstance(run_result, dict), (
        "envelopes.yaml must declare schemas.RunResult; observed schema "
        f"keys: {sorted(schemas.keys())!r}"
    )
    fields = run_result.get("fields")
    assert isinstance(fields, dict), (
        "envelopes.RunResult must declare a 'fields' mapping; observed keys: "
        f"{sorted(run_result.keys())!r}"
    )

    leaked = set(fields.keys()) & set(_BANNED_RUN_RESULT_FIELDS)
    assert leaked == set(), (
        "envelopes.yaml RunResult.fields reintroduced banned array field(s): "
        f"{sorted(leaked)!r}. Canonical relationships live in the join "
        "tables run_result_contract_results and run_result_gate_decisions "
        "per spec A.1."
    )
