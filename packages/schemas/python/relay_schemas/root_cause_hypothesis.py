"""relay.root_cause_hypothesis.v1 schema loader and validator (M05 w5-explain).

Loads the canonical JSON Schema from
``packages/schemas/raw/root-cause-hypothesis.v1.yaml`` and exposes a
``Draft202012Validator`` plus convenience ``validate`` / ``iter_errors`` helpers.

Used by:

  - VAL-V2M05-001..006 plumbing tests in
    ``packages/sdk-python/tests/test_v2m05_explain.py``.
  - The explain engine ingestion path (which maps LLM-returned out-of-enum
    hypothesis_class values to ``unknown`` and emits a ``taxonomy_review_required``
    event per VAL-V2M05-014).

The schema text is the single source of truth; this module is a thin loader
plus per-field accessor helpers so callers do not have to re-parse the YAML.

Spec anchors: T 4856-4896 (Explain object), AJ 5733-5746 (generator taxonomy).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

_REPO_ROOT = Path(__file__).resolve().parents[4]
SCHEMA_YAML_PATH = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "raw"
    / "root-cause-hypothesis.v1.yaml"
)
EXAMPLE_JSON_PATH = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "examples"
    / "root_cause_hypothesis.v1.json"
)

SCHEMA_VERSION = "relay.root_cause_hypothesis.v1"

# The 12 canonical hypothesis_class values (VAL-V2M05-003). Mirrored at the
# DB layer via CHECK constraint and at the SQL DDL layer for introspection.
HYPOTHESIS_CLASSES: frozenset[str] = frozenset(
    {
        "schema_contract_drift",
        "retrieval_miss",
        "tool_arg_invalid",
        "prompt_regression",
        "provider_drift",
        "rate_limit",
        "cost_overrun",
        "context_overflow",
        "hallucinated_citation",
        "stale_tool_doc",
        "user_misuse",
        "unknown",
    }
)

# Generator taxonomy regex (VAL-V2M05-006, VAL-V2M05-009). Pure string, no
# wall clock or external state. Used both for wire-format validation and for
# the DB-layer CHECK constraint (Postgres ~ operator; SQLite REGEXP).
GENERATOR_REGEX: str = r"^heuristic\.v\d+$|^llm\.[a-z0-9-]+:v\d+$"

# Closed set of reviewer_decision values at the wire layer. The DB layer
# stores NULL or one of these four strings (VAL-V2M05-011).
#
# Audit-R3 (2026-05-18): aligned to spec line 3325 + envelopes.yaml:
# {accept, reject, modify, pending}. The prior three-value set omitted
# 'pending' (a hypothesis awaiting review but not yet decided).
REVIEWER_DECISIONS: frozenset[str] = frozenset(
    {"accept", "reject", "modify", "pending"}
)


def _load_yaml() -> dict[str, Any]:
    text = SCHEMA_YAML_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuntimeError(
            "root-cause-hypothesis.v1.yaml malformed: top-level must be a "
            f"mapping, got {type(data).__name__}"
        )
    if data.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"root-cause-hypothesis.v1.yaml top-level schema_version "
            f"must be {SCHEMA_VERSION!r}, got {data.get('schema_version')!r}"
        )
    schema = data.get("json_schema")
    if not isinstance(schema, dict):
        raise RuntimeError(
            "root-cause-hypothesis.v1.yaml missing required 'json_schema' mapping"
        )
    return data


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Return the JSON Schema dict for relay.root_cause_hypothesis.v1.

    Cached at module level; safe to call repeatedly. The cache key is empty,
    so reloading after a file edit requires ``load_schema.cache_clear()``.
    """
    data = _load_yaml()
    return data["json_schema"]


@lru_cache(maxsize=1)
def get_validator() -> Draft202012Validator:
    """Return a Draft 2020-12 validator pinned to the canonical schema."""
    schema = load_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate(payload: dict[str, Any]) -> None:
    """Validate ``payload`` against the canonical schema.

    Raises :class:`jsonschema.exceptions.ValidationError` on failure with the
    first violating field cited in the error's ``absolute_path``.
    """
    get_validator().validate(payload)


def iter_errors(payload: dict[str, Any]) -> list[ValidationError]:
    """Return all validation errors (empty list = valid)."""
    return list(get_validator().iter_errors(payload))


def load_example() -> dict[str, Any]:
    """Return the canonical example record at ``examples/root_cause_hypothesis.v1.json``."""
    text = EXAMPLE_JSON_PATH.read_text(encoding="utf-8")
    return json.loads(text)


__all__ = [
    "EXAMPLE_JSON_PATH",
    "GENERATOR_REGEX",
    "HYPOTHESIS_CLASSES",
    "REVIEWER_DECISIONS",
    "SCHEMA_VERSION",
    "SCHEMA_YAML_PATH",
    "get_validator",
    "iter_errors",
    "load_example",
    "load_schema",
    "validate",
]
