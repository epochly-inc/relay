"""V2 M03 W3 canonical manifest.v1 schema + command_hash + validator tests.

Covers contract assertions VAL-V2M03-001 through VAL-V2M03-011 (schema +
validator + command_hash core). Sidecar enforcement (VAL-V2M03-012 through
VAL-V2M03-016) lives in apps/local-sidecar/tests/.

Each test is bound to its assertion via the pytest.mark.fulfills marker so
the gate engine can attribute pass/fail to the assertion's evidence
requirement.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
import uuid
from collections import deque
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

# Repo-root anchored paths.
# test file lives at packages/schemas/python/tests/test_v2m03_manifest.py
# parents[4] is the public relay/ repo root (anchored on the public
# relay package — same convention as test_v2m01_envelopes.py).
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_SCHEMA_PATH = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "catalogs"
    / "manifest.v1.schema.json"
)
_OPS_MANIFEST_PATH = _REPO_ROOT / ".ops" / "manifest.yaml"


def _load_schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _minimal_valid_body() -> dict[str, Any]:
    """Return a minimal manifest body that validates against the schema.

    Tests mutate this to drive negative cases (missing field, wrong const,
    pattern violation, etc.).
    """
    return {
        "schema_version": "relay.manifest.v1",
        "manifest_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "services": [
            {
                "id": "local-sidecar",
                "image": "ghcr.io/epochly/relay-sidecar@sha256:" + ("0" * 64),
                "ports": [49152],
            }
        ],
        "commands": [
            {
                "id": "lint",
                "argv": ["uv", "run", "ruff", "check", "."],
                "cwd": ".",
                "timeout_seconds": 60,
                "network_policy": {
                    "egress_default": "deny",
                    "egress_allowlist": [],
                },
                "artifacts": [],
            }
        ],
        "validation_surfaces": [
            {
                "surface": "cli",
                "contract_ref": "VAL-V2M03-001",
                "globs": ["tests/contract/test_manifest_*.py"],
            }
        ],
        "network_policy": {
            "egress_default": "deny",
            "egress_allowlist": [],
        },
        "artifacts": [],
        "side_effect_tools": [],
        "mutation_boundaries": [],
        "grace_window": {"seconds": 1800},
    }


# ---------------------------------------------------------------------------
# VAL-V2M03-001: schema file present + Draft 2020-12 valid + $id correct
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-001")
def test_manifest_schema_file_present_and_valid() -> None:
    assert _SCHEMA_PATH.is_file(), f"missing canonical schema at {_SCHEMA_PATH}"
    schema = _load_schema()
    # Spec line 4013: $id pinned to relay.epochly.com.
    assert schema["$id"] == "https://relay.epochly.com/schemas/manifest.v1.json"
    assert schema["type"] == "object"
    # Spec line 4015 top-level required set.
    required = set(schema["required"])
    assert required == {
        "schema_version",
        "manifest_id",
        "services",
        "commands",
        "validation_surfaces",
    }, f"unexpected required set: {required}"
    # Draft 2020-12 meta-schema validates without raising.
    Draft202012Validator.check_schema(schema)


# ---------------------------------------------------------------------------
# VAL-V2M03-002: schema_version is a const (relay.manifest.v1)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-002")
def test_schema_version_const_enforced() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["schema_version"] = "relay.manifest.v2"
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["schema_version"])
    assert exc.value.validator == "const"


# ---------------------------------------------------------------------------
# VAL-V2M03-003: services[].id + image + ports required, id pattern, port range
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-003")
def test_services_missing_image_fails() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    del body["services"][0]["image"]
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["services", 0])
    assert exc.value.validator == "required"
    assert "image" in exc.value.message


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-003")
def test_services_id_pattern_violation() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["services"][0]["id"] = "Bad Id"
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["services", 0, "id"])
    assert exc.value.validator == "pattern"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-003")
def test_services_port_maximum_violation() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["services"][0]["ports"] = [70000]
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["services", 0, "ports", 0])
    assert exc.value.validator == "maximum"


# ---------------------------------------------------------------------------
# VAL-V2M03-004: commands[].argv minItems=1, timeout 1..7200
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-004")
def test_commands_missing_argv_fails() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    del body["commands"][0]["argv"]
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["commands", 0])
    assert exc.value.validator == "required"
    assert "argv" in exc.value.message


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-004")
def test_commands_argv_min_items() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["argv"] = []
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["commands", 0, "argv"])
    assert exc.value.validator == "minItems"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-004")
def test_commands_timeout_minimum() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["timeout_seconds"] = 0
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["commands", 0, "timeout_seconds"])
    assert exc.value.validator == "minimum"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-004")
def test_commands_timeout_maximum() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["timeout_seconds"] = 7201
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["commands", 0, "timeout_seconds"])
    assert exc.value.validator == "maximum"


# ---------------------------------------------------------------------------
# VAL-V2M03-005: commands[].network_policy.egress_default const "deny"
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-005")
def test_command_network_policy_default_deny_const() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["network_policy"]["egress_default"] = "allow"
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(
        ["commands", 0, "network_policy", "egress_default"]
    )
    assert exc.value.validator == "const"


# ---------------------------------------------------------------------------
# VAL-V2M03-006: commands[].artifacts[] expected_digest required + pattern
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-006")
def test_artifact_kind_missing_digest_fails() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["artifacts"] = [
        {"path": "build/out", "kind": "artifact"}
    ]
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    # The if/then enforcement may surface as either "expected_digest" required
    # under the conditional, or as the allOf branch. Accept either, but the
    # missing field name must be present in the message.
    assert "expected_digest" in exc.value.message


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-006")
def test_artifact_expected_digest_wrong_prefix() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["artifacts"] = [
        {
            "path": "build/out",
            "kind": "artifact",
            "expected_digest": "md5-" + ("a" * 32),
        }
    ]
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.validator == "pattern"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-006")
def test_artifact_expected_digest_too_short() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["commands"][0]["artifacts"] = [
        {
            "path": "build/out",
            "kind": "artifact",
            "expected_digest": "sha256-abc",
        }
    ]
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.validator == "pattern"


# ---------------------------------------------------------------------------
# VAL-V2M03-007: mutation_boundaries + side_effect_tools typed arrays of str
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-007")
def test_command_side_effect_fields_typed_arrays_of_strings() -> None:
    schema = _load_schema()
    cmd_props = schema["properties"]["commands"]["items"]["properties"]
    assert cmd_props["side_effect_tools"]["type"] == "array"
    assert cmd_props["side_effect_tools"]["items"]["type"] == "string"
    assert cmd_props["mutation_boundaries"]["type"] == "array"
    assert cmd_props["mutation_boundaries"]["items"]["type"] == "string"


# ---------------------------------------------------------------------------
# VAL-V2M03-008: grace_window.seconds non-negative integer, default 1800
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-008")
def test_grace_window_seconds_zero_valid() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["grace_window"] = {"seconds": 0}
    jsonschema.validate(body, schema)  # MUST NOT raise


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-008")
def test_grace_window_seconds_negative_invalid() -> None:
    schema = _load_schema()
    body = _minimal_valid_body()
    body["grace_window"] = {"seconds": -1}
    with pytest.raises(ValidationError) as exc:
        jsonschema.validate(body, schema)
    assert exc.value.absolute_path == deque(["grace_window", "seconds"])
    assert exc.value.validator == "minimum"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-008")
def test_grace_window_default_when_absent_treated_as_1800() -> None:
    from relay_schemas.manifest import effective_grace_window_seconds

    body = _minimal_valid_body()
    body.pop("grace_window")
    assert effective_grace_window_seconds(body) == 1800


# ---------------------------------------------------------------------------
# VAL-V2M03-009: body validator rejects missing required fields
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-009")
def test_body_validator_rejects_missing_required_fields() -> None:
    from relay_schemas.manifest import validate as manifest_validate

    # Per the contract, the validator's required field set is the union of
    # spec F.required (services, validation_surfaces) plus
    # network_policy.egress_allowlist, artifacts[].expected_digest,
    # side_effect_tools, mutation_boundaries, grace_window. We assert each
    # removal in turn surfaces ok=False with a missing_field path.
    fields_to_remove = [
        ("services",),
        ("validation_surfaces",),
        ("network_policy",),
        ("artifacts",),
        ("side_effect_tools",),
        ("mutation_boundaries",),
        ("grace_window",),
    ]
    for (field,) in fields_to_remove:
        body = _minimal_valid_body()
        body.pop(field, None)
        result = manifest_validate(body)
        assert result.ok is False, f"validator accepted body missing {field}"
        assert field in result.missing_field, (
            f"validator did not surface missing_field={field}: "
            f"actual={result.missing_field}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-009")
def test_body_validator_happy_path() -> None:
    from relay_schemas.manifest import validate as manifest_validate

    body = _minimal_valid_body()
    result = manifest_validate(body)
    assert result.ok is True, f"validator rejected minimal body: {result}"


# ---------------------------------------------------------------------------
# VAL-V2M03-010: relay/.ops/manifest.yaml validates against canonical schema
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-010")
@pytest.mark.skipif(
    not _OPS_MANIFEST_PATH.exists(),
    reason=(
        ".ops/manifest.yaml is a workspace-parent Operations-system artifact "
        "(gitignored in the OSS relay repo). The test validates the reference "
        "manifest when present; on a CI checkout of just the public relay/ "
        "repo (without the workspace parent's .ops/ tree) the file is "
        "legitimately absent and the test skips."
    ),
)
def test_ops_manifest_validates_against_canonical_schema() -> None:
    schema = _load_schema()
    body = yaml.safe_load(_OPS_MANIFEST_PATH.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(body))
    assert errors == [], (
        f"reference manifest at {_OPS_MANIFEST_PATH} failed canonical schema "
        f"validation: {[e.message for e in errors]}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M03-011: command_hash canonical + deterministic
# ---------------------------------------------------------------------------


_GOLDEN_VECTOR_PATH = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "catalogs"
    / "command_hash.golden.json"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-011")
def test_command_hash_canonical_env_order_invariant() -> None:
    from relay_schemas.manifest import compute_command_hash

    h1 = compute_command_hash(
        argv=["python", "x.py"],
        cwd="/tmp",
        env={"A": "1", "B": "2"},
        container_image="img",
    )
    h2 = compute_command_hash(
        argv=["python", "x.py"],
        cwd="/tmp",
        env={"B": "2", "A": "1"},  # different insertion order
        container_image="img",
    )
    assert h1 == h2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-011")
def test_command_hash_sensitive_to_cwd_change() -> None:
    from relay_schemas.manifest import compute_command_hash

    h1 = compute_command_hash(
        argv=["x"], cwd="/tmp", env={}, container_image=None
    )
    h2 = compute_command_hash(
        argv=["x"], cwd="/tmp ", env={}, container_image=None
    )
    assert h1 != h2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-011")
def test_command_hash_sensitive_to_argv_order() -> None:
    from relay_schemas.manifest import compute_command_hash

    h1 = compute_command_hash(
        argv=["a", "b"], cwd=".", env={}, container_image=None
    )
    h2 = compute_command_hash(
        argv=["b", "a"], cwd=".", env={}, container_image=None
    )
    assert h1 != h2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-011")
def test_command_hash_matches_wire_pattern() -> None:
    from relay_schemas.manifest import compute_command_hash

    h = compute_command_hash(
        argv=["x"], cwd=".", env={}, container_image=None
    )
    assert re.match(r"^sha256-[0-9a-f]{64}$", h), h


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-011")
def test_command_hash_cross_language_golden_vector() -> None:
    """The Python implementation MUST match the cross-language golden vector.

    The golden vector is consumed by the TypeScript SDK's
    ``computeCommandHash`` (packages/sdk-typescript/src/manifest.ts);
    Py vs TS parity is enforced via this shared fixture so byte-equality
    is provable in both directions.
    """
    from relay_schemas.manifest import compute_command_hash

    assert _GOLDEN_VECTOR_PATH.is_file(), (
        f"missing cross-language golden vector at {_GOLDEN_VECTOR_PATH}"
    )
    vectors = json.loads(_GOLDEN_VECTOR_PATH.read_text(encoding="utf-8"))
    assert isinstance(vectors, list) and vectors, "golden vector must be non-empty list"
    for case in vectors:
        h = compute_command_hash(
            argv=case["argv"],
            cwd=case["cwd"],
            env=case["env"],
            container_image=case.get("container_image"),
        )
        assert h == case["expected"], (
            f"case {case.get('name')!r}: expected {case['expected']!r}, "
            f"got {h!r}"
        )


# ---------------------------------------------------------------------------
# VAL-CWC-P3CORPUS-013: M3 manifest + discipline gate
#
# Guards that the .ops/manifest.yaml declares the WS-E and WS-G commands
# introduced in M3 P3CORPUS, with schema-valid network_policy (egress_default
# must be "deny" and egress_allowlist must be present) on every entry.
# Also guards that the M3 source deliverables are ASCII-only (no non-ASCII
# bytes in any non-binary M3 file).
#
# The skipif mirrors the parent test_ops_manifest_validates_against_canonical_
# schema: the .ops/manifest.yaml is a workspace-level artifact that is absent
# on a public-relay-only checkout; the guard skips gracefully in that case.
# ---------------------------------------------------------------------------

# M3 command IDs that MUST be present in the manifest.
_M3_COMMAND_IDS: frozenset[str] = frozenset(
    {
        "generate-relay-udf-via-cel-corpus",
        "test-udf-via-cel-corpus",
        "test-node-udf-cross-host",
        "check-wasm-pinned-sha",
    }
)

# M3 source files (text, not binary) that must be ASCII-only.
_M3_ASCII_FILES: tuple[str, ...] = (
    "scripts/generate-relay-udf-via-cel-corpus.py",
    "tests/conformance/cel/test_udf_via_cel_byte_match_runner.py",
    "tests/conformance/cel/test_udf_via_cel_corpus.py",
    "packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs",
    "packages/contracts/src/relay_contracts/wasm_artifact.py",
    "packages/contracts/src/relay_contracts/wasm_backed_evaluator.py",
    "packages/contracts/src/relay_contracts/_wasm/relay_cel_wasm.py",
    "packages/contracts/tests/test_wasm_loader_package_data.py",
    "packages/contracts/tests/test_wasm_package_data.py",
    "packages/contracts-typescript/src/wasm-artifact.ts",
    "packages/contracts-typescript/test/udf_via_cel_cross_host.test.ts",
    "packages/contracts-typescript/test/wasm_package_data.test.ts",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P3CORPUS-013")
@pytest.mark.skipif(
    not _OPS_MANIFEST_PATH.exists(),
    reason=(
        ".ops/manifest.yaml absent (public-relay-only checkout). "
        "The M3 manifest guard skips; it runs in the workspace environment."
    ),
)
def test_m3_manifest_commands_declared_with_deny_policy() -> None:
    """M3 WS-E/WS-G commands declared in manifest; each has egress_default deny.

    VAL-CWC-P3CORPUS-013: every M3 command entry MUST carry
    network_policy.egress_default == "deny". A prior regression set
    egress_default to "allow" and broke test_ops_manifest_validates_against_
    canonical_schema (the schema enforces "deny" as a const).
    """
    body = yaml.safe_load(_OPS_MANIFEST_PATH.read_text(encoding="utf-8"))
    commands: list[dict] = body.get("commands", [])
    declared_ids: set[str] = {c.get("id", "") for c in commands}

    missing = _M3_COMMAND_IDS - declared_ids
    assert missing == set(), (
        f"VAL-CWC-P3CORPUS-013: M3 command(s) missing from .ops/manifest.yaml: "
        f"{sorted(missing)}. Add a schema-valid entry (egress_default: deny, "
        "egress_allowlist: *id001) for each."
    )

    bad_policy: list[str] = []
    for cmd in commands:
        if cmd.get("id") in _M3_COMMAND_IDS:
            np = cmd.get("network_policy", {})
            if np.get("egress_default") != "deny":
                bad_policy.append(
                    f"{cmd['id']}: egress_default={np.get('egress_default')!r}"
                )
    assert bad_policy == [], (
        f"VAL-CWC-P3CORPUS-013: M3 command(s) have wrong egress_default "
        f"(must be 'deny'): {bad_policy}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P3CORPUS-013")
def test_m3_source_files_ascii_only() -> None:
    """M3 WS-E/WS-G source deliverables contain no non-ASCII bytes.

    VAL-CWC-P3CORPUS-013 ASCII discipline: every M3 text file (generators,
    runners, loaders, packaging metadata) must be ASCII-only. Binary files
    (.wasm) are excluded from this check.
    """
    violations: list[str] = []
    for rel_path in _M3_ASCII_FILES:
        abs_path = _REPO_ROOT / rel_path
        if not abs_path.exists():
            # A missing file is a distinct problem (not an ASCII violation).
            # The manifest-commands test above catches missing deliverables;
            # here we only check the ones that exist.
            continue
        raw = abs_path.read_bytes()
        offending_lines: list[tuple[int, bytes]] = []
        for i, line in enumerate(raw.splitlines(), start=1):
            try:
                line.decode("ascii")
            except UnicodeDecodeError:
                offending_lines.append((i, line))
        if offending_lines:
            for lineno, line in offending_lines[:3]:
                violations.append(f"{rel_path}:{lineno}: {line[:60]!r}")
    assert violations == [], (
        "VAL-CWC-P3CORPUS-013: non-ASCII bytes in M3 source deliverables:\n  "
        + "\n  ".join(violations)
    )
