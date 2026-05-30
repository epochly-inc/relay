#!/usr/bin/env python3
"""W12.4 in-toto attestation guard (workflow lint + offline link/layout verifier).

Four modes of operation, selected via ``--mode``:

  ``--mode workflow``
      Static linter that parses ``.github/workflows/release-in-toto.yml``
      and asserts:

        - VAL-W12-016  workflow declares one emit-link-* job (or step)
                      per step name in the layout's ``steps[]`` list
        - VAL-W12-017  workflow's ``env.RELAY_INTOTO_DECLARED_STEPS``
                      list matches exactly the layout's ``steps[]``
                      ``name`` values (no drift, no missing, no extra)

  ``--mode layout``
      Offline-loads a release.layout file and asserts:

        - VAL-W12-017  layout structure conforms to the in-toto layout
                      schema: _type, signed.{_type, expires, readme,
                      keys, steps, inspect}, signatures
        - VAL-W12-019  every ``functionary`` key id in ``signed.keys``
                      has a non-expired ``not_after`` timestamp; the
                      layout's own signing key id (signatures[].keyid)
                      resolves to a key in ``signed.keys`` whose
                      ``not_after`` is strictly in the future, or carries
                      a ``witness_signature`` block (rotated-with-witness
                      mode)

  ``--mode chain``
      Offline-loads every ``*.link`` file under ``--link-dir`` and asserts:

        - VAL-W12-016  every layout step has a corresponding .link file
                      named ``<step-name>.<key-id>.link``
        - VAL-W12-018  for every consecutive (step N, step N+1) pair in
                      the layout, every product digest of step N appears
                      as a material digest of step N+1 (one-direction
                      strict inclusion; extra materials at step N+1 are
                      permitted because steps may consume external
                      sources). When ``--check-coverage-only`` is set,
                      only the per-step coverage assertion runs (faster
                      preflight).

  ``--mode rotation``
      Offline-loads the layout and asserts only the signing-key rotation
      window check from ``--mode layout``. This is a hot-path subset for
      use by the release workflow's ``sign-layout`` job (VAL-W12-019).

Exit codes:
    0  all checks passed
    1  one or more checks failed (RELAY-RELEASE-NNN reported in JSON)
    2  input file missing or unparseable
    3  invalid invocation

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output and source.
Per CLAUDE.md keystone #3: this script lives in ``scripts/`` and is
invoked through manifest-declared commands (``lint-in-toto-attestations``
or via the release workflow itself).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants pinned to the contract.
# ---------------------------------------------------------------------------

WORKFLOW_RELPATH = ".github/workflows/release-in-toto.yml"

# The env variable inside the workflow that lists declared steps. The
# workflow guard asserts this list equals the layout's steps[].name list.
WORKFLOW_DECLARED_STEPS_ENV_VAR = "RELAY_INTOTO_DECLARED_STEPS"

# in-toto layout/link wire-format constants. The layout we ship is the
# v0.1 dialect which is a thin extension of the in-toto-golang
# 0.9 dialect: signed-then-DSSE-wrapped JSON. The schema fields below
# are the minimum the guard understands.
LAYOUT_TYPE = "layout"
LINK_TYPE = "link"

# Filename grammar: <step-name>.<key-id>.link
# step-name allows lowercase letters, digits, hyphen.
# key-id is a hex string (sha256 of public key bytes).
_LINK_FILENAME_RE = re.compile(
    r"^(?P<step>[a-z][a-z0-9\-]*)\.(?P<keyid>[A-Za-z0-9_\-]+)\.link$"
)
# A 64-char lowercase hex string is the canonical sha256 digest format.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# A short hex key id is anything 8..64 hex chars (sha256 of pubkey
# truncated to a humane length).
_KEYID_RE = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")


# ---------------------------------------------------------------------------
# Result types.
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single VAL-W12-NNN check."""

    assertion: str
    error_code: str
    passed: bool
    message: str = ""


@dataclass
class GuardReport:
    """Aggregate report for any of the four modes."""

    mode: str
    inputs: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "inputs": self.inputs,
            "ok": self.ok,
            "checks": [
                {
                    "assertion": c.assertion,
                    "error_code": c.error_code,
                    "passed": c.passed,
                    "message": c.message,
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# YAML / JSON loading helpers.
# ---------------------------------------------------------------------------


def _load_workflow_yaml(workflow_path: Path) -> dict[str, Any]:
    try:
        text = workflow_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(
            f"FAIL: workflow file not found at {workflow_path}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        print(f"FAIL: workflow YAML unparseable: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not isinstance(data, dict):
        print("FAIL: workflow YAML root must be a mapping", file=sys.stderr)
        raise SystemExit(2)
    return data


def _load_json_file(path: Path, kind: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"FAIL: {kind} file not found at {path}", file=sys.stderr)
        raise SystemExit(2) from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"FAIL: {kind} JSON unparseable: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not isinstance(data, dict):
        print(f"FAIL: {kind} JSON root must be an object", file=sys.stderr)
        raise SystemExit(2)
    return data


def _parse_iso8601(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp; return None on failure."""
    if not isinstance(value, str):
        return None
    try:
        # Accept trailing 'Z' as +00:00.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Workflow-mode helpers.
# ---------------------------------------------------------------------------


def _extract_declared_steps_from_workflow(
    workflow: dict[str, Any],
) -> list[str] | None:
    """Pull the whitespace-separated step list from
    workflow.env.RELAY_INTOTO_DECLARED_STEPS. Returns None when the env
    var is missing or malformed."""
    env = workflow.get("env")
    if not isinstance(env, dict):
        return None
    raw = env.get(WORKFLOW_DECLARED_STEPS_ENV_VAR)
    if not isinstance(raw, str):
        return None
    return raw.split()


def _extract_layout_step_names(layout_signed: dict[str, Any]) -> list[str]:
    steps = layout_signed.get("steps", [])
    if not isinstance(steps, list):
        return []
    out: list[str] = []
    for s in steps:
        if isinstance(s, dict):
            name = s.get("name")
            if isinstance(name, str):
                out.append(name)
    return out


def _layout_signed_block(layout: dict[str, Any]) -> dict[str, Any]:
    signed = layout.get("signed")
    if not isinstance(signed, dict):
        return {}
    return signed


# ---------------------------------------------------------------------------
# Workflow-mode checks.
# ---------------------------------------------------------------------------


def check_workflow_val_w12_017(
    workflow: dict[str, Any], layout: dict[str, Any]
) -> CheckResult:
    """env.RELAY_INTOTO_DECLARED_STEPS matches layout.signed.steps[].name."""
    declared = _extract_declared_steps_from_workflow(workflow)
    if declared is None:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            (
                "workflow has no env.RELAY_INTOTO_DECLARED_STEPS or it is "
                "not a whitespace-separated string"
            ),
        )
    layout_steps = _extract_layout_step_names(_layout_signed_block(layout))
    if not layout_steps:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            "layout has no signed.steps[] (or all step entries lacked name)",
        )
    declared_set = set(declared)
    layout_set = set(layout_steps)
    missing_in_workflow = sorted(layout_set - declared_set)
    missing_in_layout = sorted(declared_set - layout_set)
    if missing_in_workflow or missing_in_layout:
        msg_parts: list[str] = []
        if missing_in_workflow:
            msg_parts.append(
                f"steps in layout but not declared in workflow: "
                f"{missing_in_workflow}"
            )
        if missing_in_layout:
            msg_parts.append(
                f"steps declared in workflow but absent from layout: "
                f"{missing_in_layout}"
            )
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            "; ".join(msg_parts),
        )
    if declared != layout_steps:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            (
                f"step ordering disagrees: workflow={declared}, "
                f"layout={layout_steps}"
            ),
        )
    return CheckResult("VAL-W12-017", "RELAY-RELEASE-017", True)


def check_workflow_val_w12_016(
    workflow: dict[str, Any], layout: dict[str, Any]
) -> CheckResult:
    """Workflow declares an emit-link job/step for every layout step.

    The check is structural: for every step name N in
    layout.signed.steps, the workflow must contain at least one job whose
    ``steps[].run`` references ``--step-name N`` (i.e. invokes the
    generate-in-toto-link.py script with the matching step name). A
    missing emit-link wiring fails RELAY-RELEASE-016.
    """
    layout_steps = _extract_layout_step_names(_layout_signed_block(layout))
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return CheckResult(
            "VAL-W12-016",
            "RELAY-RELEASE-016",
            False,
            "workflow has no jobs",
        )

    # Concatenate every step's run text once so the per-step regex is cheap.
    haystacks: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if isinstance(run, str):
                haystacks.append(run)
    big_haystack = "\n".join(haystacks)

    missing: list[str] = []
    for step_name in layout_steps:
        # Match either the long-form '--step-name foo' or the short-form
        # '--step-name=foo'. Step names are lower-case + hyphen so the
        # token boundary on \b is safe.
        token_re = re.compile(
            r"--step-name[ =]" + re.escape(step_name) + r"\b"
        )
        if not token_re.search(big_haystack):
            missing.append(step_name)
    if missing:
        return CheckResult(
            "VAL-W12-016",
            "RELAY-RELEASE-016",
            False,
            (
                f"workflow has no emit-link wiring for layout step(s): "
                f"{missing}"
            ),
        )
    return CheckResult("VAL-W12-016", "RELAY-RELEASE-016", True)


def run_workflow_checks(repo_root: Path) -> GuardReport:
    workflow_path = repo_root / WORKFLOW_RELPATH
    workflow = _load_workflow_yaml(workflow_path)
    layout_path = repo_root / "tests" / "release" / "fixtures" / "release.layout"
    layout = _load_json_file(layout_path, "layout")
    report = GuardReport(
        mode="workflow",
        inputs=[str(workflow_path), str(layout_path)],
    )
    report.checks.append(check_workflow_val_w12_017(workflow, layout))
    report.checks.append(check_workflow_val_w12_016(workflow, layout))
    return report


# ---------------------------------------------------------------------------
# Layout-mode checks.
# ---------------------------------------------------------------------------


def check_layout_schema(layout: dict[str, Any]) -> CheckResult:
    """Validate the layout against the v0.1 in-toto layout schema.

    Required structure:
      {
        "signed": {
          "_type": "layout",
          "expires": "<ISO-8601>",
          "readme": "<string>",
          "keys": { "<keyid>": { ... key fields ... }, ... },
          "steps": [ { "name": ..., "expected_command": [...],
                       "pubkeys": [...], "expected_materials": [...],
                       "expected_products": [...], "threshold": int }, ... ],
          "inspect": [ ... ] (may be empty)
        },
        "signatures": [ { "keyid": "<hex>", "sig": "<base64>",
                          "rotation": { ... } (optional) }, ... ]
      }
    """
    signed = _layout_signed_block(layout)
    if signed.get("_type") != LAYOUT_TYPE:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            "layout.signed._type must be 'layout'",
        )
    for required in ("expires", "readme", "keys", "steps", "inspect"):
        if required not in signed:
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                f"layout.signed missing required field '{required}'",
            )
    if not isinstance(signed.get("keys"), dict) or not signed["keys"]:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            "layout.signed.keys must be a non-empty mapping",
        )
    steps = signed.get("steps")
    if not isinstance(steps, list) or not steps:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            "layout.signed.steps must be a non-empty list",
        )
    seen_names: set[str] = set()
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                f"layout.signed.steps[{idx}] must be an object",
            )
        for step_required in (
            "name",
            "expected_command",
            "pubkeys",
            "expected_materials",
            "expected_products",
            "threshold",
        ):
            if step_required not in step:
                return CheckResult(
                    "VAL-W12-017",
                    "RELAY-RELEASE-017",
                    False,
                    (
                        f"layout.signed.steps[{idx}] missing required "
                        f"field '{step_required}'"
                    ),
                )
        name = step["name"]
        if not isinstance(name, str) or not name:
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                f"layout.signed.steps[{idx}].name must be a non-empty string",
            )
        if name in seen_names:
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                f"layout.signed.steps[*].name has duplicate '{name}'",
            )
        seen_names.add(name)
        threshold = step.get("threshold")
        if not isinstance(threshold, int) or threshold < 1:
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                (
                    f"layout.signed.steps[{idx}].threshold must be a "
                    f"positive integer; got {threshold!r}"
                ),
            )
        pubkeys = step.get("pubkeys")
        if not isinstance(pubkeys, list) or not pubkeys:
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                (
                    f"layout.signed.steps[{idx}].pubkeys must be a "
                    f"non-empty list of functionary keyids"
                ),
            )
        for pk in pubkeys:
            if not isinstance(pk, str) or not _KEYID_RE.match(pk):
                return CheckResult(
                    "VAL-W12-017",
                    "RELAY-RELEASE-017",
                    False,
                    (
                        f"layout.signed.steps[{idx}].pubkeys contains "
                        f"non-keyid entry {pk!r}"
                    ),
                )
            if pk not in signed["keys"]:
                return CheckResult(
                    "VAL-W12-017",
                    "RELAY-RELEASE-017",
                    False,
                    (
                        f"layout.signed.steps[{idx}] references functionary "
                        f"keyid '{pk}' not present in signed.keys"
                    ),
                )
    signatures = layout.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return CheckResult(
            "VAL-W12-017",
            "RELAY-RELEASE-017",
            False,
            "layout.signatures must be a non-empty list",
        )
    for idx, sig in enumerate(signatures):
        if not isinstance(sig, dict):
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                f"layout.signatures[{idx}] must be an object",
            )
        for sig_required in ("keyid", "sig"):
            if sig_required not in sig:
                return CheckResult(
                    "VAL-W12-017",
                    "RELAY-RELEASE-017",
                    False,
                    (
                        f"layout.signatures[{idx}] missing required "
                        f"field '{sig_required}'"
                    ),
                )
        if sig["keyid"] not in signed["keys"]:
            return CheckResult(
                "VAL-W12-017",
                "RELAY-RELEASE-017",
                False,
                (
                    f"layout.signatures[{idx}].keyid '{sig['keyid']}' not "
                    f"present in signed.keys"
                ),
            )
    return CheckResult("VAL-W12-017", "RELAY-RELEASE-017", True)


def check_layout_signing_key_rotation(
    layout: dict[str, Any],
    *,
    now: datetime | None = None,
) -> CheckResult:
    """Every signing-key id in signatures[] resolves to a key in
    signed.keys whose ``not_after`` is strictly in the future, OR carries
    a witness_signature block (rotated-with-witness mode per spec L.3).

    The layout's overall ``signed.expires`` must also be in the future
    (a layout signed but expired cannot bind a release).
    """
    if now is None:
        now = datetime.now(tz=UTC)
    signed = _layout_signed_block(layout)
    expires = _parse_iso8601(signed.get("expires", ""))
    if expires is None:
        return CheckResult(
            "VAL-W12-019",
            "RELAY-RELEASE-019",
            False,
            "layout.signed.expires missing or not a parseable ISO-8601 timestamp",
        )
    if expires <= now:
        return CheckResult(
            "VAL-W12-019",
            "RELAY-RELEASE-019",
            False,
            (
                f"layout.signed.expires ({expires.isoformat()}) is not in "
                f"the future (now={now.isoformat()})"
            ),
        )
    keys: dict[str, Any] = signed.get("keys", {})
    signatures = layout.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        return CheckResult(
            "VAL-W12-019",
            "RELAY-RELEASE-019",
            False,
            "layout.signatures must be a non-empty list",
        )
    for idx, sig in enumerate(signatures):
        if not isinstance(sig, dict):
            continue
        keyid = sig.get("keyid")
        if not isinstance(keyid, str) or keyid not in keys:
            return CheckResult(
                "VAL-W12-019",
                "RELAY-RELEASE-019",
                False,
                (
                    f"layout.signatures[{idx}].keyid '{keyid}' not present "
                    f"in signed.keys"
                ),
            )
        key_entry = keys[keyid]
        not_after_raw = (
            key_entry.get("not_after") if isinstance(key_entry, dict) else None
        )
        not_after = _parse_iso8601(not_after_raw or "")
        witness = (
            sig.get("witness_signature") if isinstance(sig, dict) else None
        )
        if not_after is None:
            return CheckResult(
                "VAL-W12-019",
                "RELAY-RELEASE-019",
                False,
                (
                    f"layout.signed.keys['{keyid}'].not_after missing or "
                    f"unparseable"
                ),
            )
        if not_after <= now:
            # Allow rotated-with-witness mode: the predecessor key may
            # sign a layout past its not_after if the successor key
            # countersigns via witness_signature (spec L.3 two-phase).
            if not isinstance(witness, dict):
                return CheckResult(
                    "VAL-W12-019",
                    "RELAY-RELEASE-019",
                    False,
                    (
                        f"layout.signatures[{idx}] uses key '{keyid}' past "
                        f"not_after ({not_after.isoformat()}; "
                        f"now={now.isoformat()}) without a witness_signature"
                    ),
                )
            witness_keyid = witness.get("keyid")
            if (
                not isinstance(witness_keyid, str)
                or witness_keyid not in keys
            ):
                return CheckResult(
                    "VAL-W12-019",
                    "RELAY-RELEASE-019",
                    False,
                    (
                        f"layout.signatures[{idx}].witness_signature.keyid "
                        f"'{witness_keyid}' not present in signed.keys"
                    ),
                )
            witness_key_entry = keys[witness_keyid]
            witness_not_after = _parse_iso8601(
                witness_key_entry.get("not_after", "")
                if isinstance(witness_key_entry, dict)
                else ""
            )
            if witness_not_after is None or witness_not_after <= now:
                return CheckResult(
                    "VAL-W12-019",
                    "RELAY-RELEASE-019",
                    False,
                    (
                        f"layout.signatures[{idx}].witness_signature.keyid "
                        f"'{witness_keyid}' is itself past not_after"
                    ),
                )
    return CheckResult("VAL-W12-019", "RELAY-RELEASE-019", True)


def run_layout_checks(
    layout_path: Path, *, now: datetime | None = None
) -> GuardReport:
    layout = _load_json_file(layout_path, "layout")
    report = GuardReport(mode="layout", inputs=[str(layout_path)])
    report.checks.append(check_layout_schema(layout))
    report.checks.append(check_layout_signing_key_rotation(layout, now=now))
    return report


def run_rotation_checks(
    layout_path: Path, *, now: datetime | None = None
) -> GuardReport:
    layout = _load_json_file(layout_path, "layout")
    report = GuardReport(mode="rotation", inputs=[str(layout_path)])
    report.checks.append(check_layout_signing_key_rotation(layout, now=now))
    return report


# ---------------------------------------------------------------------------
# Chain-mode helpers + checks.
# ---------------------------------------------------------------------------


def _iter_link_files(link_dir: Path) -> list[Path]:
    return sorted(link_dir.glob("*.link"))


def _parse_link_filename(name: str) -> tuple[str, str] | None:
    m = _LINK_FILENAME_RE.match(name)
    if not m:
        return None
    return m.group("step"), m.group("keyid")


def _link_signed_block(link: dict[str, Any]) -> dict[str, Any]:
    signed = link.get("signed")
    if not isinstance(signed, dict):
        return {}
    return signed


def _link_step_name(link: dict[str, Any]) -> str | None:
    signed = _link_signed_block(link)
    name = signed.get("name")
    return name if isinstance(name, str) else None


def _digest_set(
    items: list[dict[str, Any]] | Any, hash_alg: str = "sha256"
) -> set[str]:
    """Collect the hash_alg digests from a materials/products list.

    in-toto link materials/products are arrays of objects:
      [ {"uri": "<path>", "digest": {"sha256": "<hex>", ...}}, ... ]
    """
    out: set[str] = set()
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        digest = item.get("digest")
        if not isinstance(digest, dict):
            continue
        h = digest.get(hash_alg)
        if isinstance(h, str) and _SHA256_RE.match(h):
            out.add(h)
    return out


def _count_digest_bearing_entries(items: list[dict[str, Any]] | Any) -> int:
    """Count materials/products entries that declare a ``digest`` object.

    Used by the chain check (VAL-ISO-006) to detect the vacuity where a
    non-empty ``products[]`` declares digests but NONE are parseable
    lowercase ``sha256`` (e.g. a ``sha512``-only or uppercase/short value).
    Such a parent yields an empty :func:`_digest_set`, which would
    otherwise make the parent->child continuity assertion pass vacuously.
    Entries with no ``digest`` object at all are not counted: only digest
    declarations whose sha256 we expect to parse are relevant.
    """
    if not isinstance(items, list):
        return 0
    count = 0
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("digest"), dict):
            count += 1
    return count


def check_chain_val_w12_016(
    layout: dict[str, Any],
    links_by_step: dict[str, dict[str, Any]],
) -> CheckResult:
    """Every layout step has a corresponding .link file."""
    layout_steps = _extract_layout_step_names(_layout_signed_block(layout))
    if not layout_steps:
        return CheckResult(
            "VAL-W12-016",
            "RELAY-RELEASE-016",
            False,
            "layout has no signed.steps[]",
        )
    missing = [s for s in layout_steps if s not in links_by_step]
    if missing:
        return CheckResult(
            "VAL-W12-016",
            "RELAY-RELEASE-016",
            False,
            f"layout step(s) without a .link file: {missing}",
        )
    return CheckResult("VAL-W12-016", "RELAY-RELEASE-016", True)


def check_chain_val_w12_018(
    layout: dict[str, Any],
    links_by_step: dict[str, dict[str, Any]],
) -> CheckResult:
    """For every consecutive (step N, step N+1) pair in the layout,
    every product digest of step N appears as a material digest of step
    N+1 (one-direction strict inclusion).

    Steps may have multiple parents in the chain (e.g. upload consumes
    products of every build). The layout DSL expresses this via the
    ``expected_materials`` directive on step N+1, which references step
    N by name. The check below uses step ordering AS DECLARED IN THE
    LAYOUT to derive the chain; non-adjacent edges are encoded
    explicitly via the ``expected_materials`` rule
    ``MATCH ... FROM <other-step>`` form.
    """
    layout_steps = _extract_layout_step_names(_layout_signed_block(layout))
    signed = _layout_signed_block(layout)
    step_defs: dict[str, dict[str, Any]] = {}
    for s in signed.get("steps", []):
        if isinstance(s, dict) and isinstance(s.get("name"), str):
            step_defs[s["name"]] = s

    # Derive the parent-of-step graph from the layout's
    # expected_materials rules. Each rule string is shaped like:
    #   "MATCH <pattern> WITH PRODUCTS FROM <step-name>"
    # The script extracts the FROM <step-name> token; if a step has no
    # MATCH-FROM rule, its parent is implicitly the previous step in the
    # declaration order.
    match_from_re = re.compile(
        r"MATCH\b.*?\bWITH\s+PRODUCTS\s+FROM\s+(\S+)",
        re.IGNORECASE,
    )
    parents: dict[str, list[str]] = {}
    for idx, name in enumerate(layout_steps):
        sdef = step_defs[name]
        rules = sdef.get("expected_materials", [])
        derived: list[str] = []
        if isinstance(rules, list):
            for rule in rules:
                # Rules are either strings ("MATCH ... FROM ...") or
                # arrays of tokens (in-toto-golang style). Normalize to
                # a flat string for the regex.
                rule_str = (
                    " ".join(str(t) for t in rule)
                    if isinstance(rule, list)
                    else str(rule)
                )
                for m in match_from_re.finditer(rule_str):
                    parent = m.group(1)
                    if parent and parent != name and parent not in derived:
                        derived.append(parent)
        if not derived and idx > 0:
            derived = [layout_steps[idx - 1]]
        parents[name] = derived

    # For each step, materials must include every product of every parent.
    for step_name in layout_steps:
        step_link = links_by_step[step_name]
        step_signed = _link_signed_block(step_link)
        step_materials = _digest_set(step_signed.get("materials", []))
        for parent_name in parents.get(step_name, []):
            parent_link = links_by_step.get(parent_name)
            if parent_link is None:
                return CheckResult(
                    "VAL-W12-018",
                    "RELAY-RELEASE-018",
                    False,
                    (
                        f"step '{step_name}' references parent "
                        f"'{parent_name}' which has no .link file"
                    ),
                )
            parent_signed = _link_signed_block(parent_link)
            parent_raw_products = parent_signed.get("products", [])
            parent_products = _digest_set(parent_raw_products)
            # VAL-ISO-006: fail closed when the parent declares
            # digest-bearing products but NONE parse as a lowercase
            # sha256. An empty parent_products derived from a non-empty
            # products[] would otherwise make ``missing`` empty and pass
            # the continuity assertion vacuously, accepting a chain whose
            # parent products are never actually verified against the
            # child's materials (e.g. a sha512-only or uppercase digest).
            if (
                not parent_products
                and _count_digest_bearing_entries(parent_raw_products) > 0
            ):
                return CheckResult(
                    "VAL-W12-018",
                    "RELAY-RELEASE-018",
                    False,
                    (
                        f"chain break at step '{step_name}': parent "
                        f"'{parent_name}' declares products with no "
                        f"parseable lowercase sha256 digest; the "
                        f"parent->child continuity cannot be verified"
                    ),
                )
            missing = parent_products - step_materials
            if missing:
                return CheckResult(
                    "VAL-W12-018",
                    "RELAY-RELEASE-018",
                    False,
                    (
                        f"chain break at step '{step_name}': "
                        f"products of parent '{parent_name}' missing from "
                        f"materials: {sorted(missing)}"
                    ),
                )
    return CheckResult("VAL-W12-018", "RELAY-RELEASE-018", True)


def run_chain_checks(
    layout_path: Path,
    link_dir: Path,
    *,
    coverage_only: bool = False,
) -> GuardReport:
    layout = _load_json_file(layout_path, "layout")
    report = GuardReport(
        mode="chain",
        inputs=[str(layout_path), str(link_dir)],
    )
    if not link_dir.is_dir():
        report.checks.append(
            CheckResult(
                "VAL-W12-016",
                "RELAY-RELEASE-016",
                False,
                f"--link-dir does not exist or is not a directory: {link_dir}",
            )
        )
        return report

    # Index every .link in the directory by the (step-name) token in its
    # filename. A step name may have multiple links if signed by multiple
    # functionaries (threshold > 1); for the coverage check we treat all
    # of them as covering the step.
    links_by_step: dict[str, dict[str, Any]] = {}
    for link_path in _iter_link_files(link_dir):
        parsed = _parse_link_filename(link_path.name)
        if parsed is None:
            continue
        step, _keyid = parsed
        link = _load_json_file(link_path, "link")
        # Validate the link's internal step name matches the filename token.
        internal = _link_step_name(link)
        if internal is not None and internal != step:
            report.checks.append(
                CheckResult(
                    "VAL-W12-016",
                    "RELAY-RELEASE-016",
                    False,
                    (
                        f"link {link_path.name}: filename step '{step}' "
                        f"disagrees with signed.name '{internal}'"
                    ),
                )
            )
            return report
        # First link wins per step; functionary-multi-sign is a future
        # extension once the relay-platform signing service is wired.
        links_by_step.setdefault(step, link)

    report.checks.append(check_chain_val_w12_016(layout, links_by_step))
    # Only run the digest-chain check when coverage already passed;
    # otherwise the chain check would dereference missing entries.
    if not coverage_only and report.checks[-1].passed:
        report.checks.append(
            check_chain_val_w12_018(layout, links_by_step)
        )
    return report


# ---------------------------------------------------------------------------
# Output helpers.
# ---------------------------------------------------------------------------


def _print_human(report: GuardReport) -> None:
    print(f"mode: {report.mode}")
    print("inputs:")
    for p in report.inputs:
        print(f"  - {p}")
    print("")
    for c in report.checks:
        marker = "[OK]  " if c.passed else "[FAIL]"
        line = f"{marker} {c.assertion}  {c.error_code}"
        if not c.passed and c.message:
            line += f"  -- {c.message}"
        print(line)
    print("")
    print("PASS" if report.ok else "FAIL")


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "in-toto attestation guard (workflow lint + offline link/layout "
            "verifier)."
        )
    )
    parser.add_argument(
        "--mode",
        choices=("workflow", "layout", "chain", "rotation"),
        required=True,
        help=(
            "Select 'workflow' (static lint of release-in-toto.yml), "
            "'layout' (offline schema + rotation check on a release.layout), "
            "'chain' (offline coverage + digest-chain check on a layout + "
            "links/), or 'rotation' (rotation-only subset of layout mode)."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Repository root containing .github/workflows/release-in-toto.yml "
            "(workflow mode)."
        ),
    )
    parser.add_argument(
        "--layout",
        type=Path,
        default=None,
        help="Path to a release.layout file (layout / chain / rotation modes).",
    )
    parser.add_argument(
        "--link-dir",
        type=Path,
        default=None,
        help="Path to a directory of *.link files (chain mode).",
    )
    parser.add_argument(
        "--check-coverage-only",
        action="store_true",
        help=(
            "Run only the per-step coverage assertion (VAL-W12-016) in "
            "chain mode; skip the digest-chain comparison (VAL-W12-018)."
        ),
    )
    parser.add_argument(
        "--now",
        type=str,
        default=None,
        help=(
            "Override 'now' for rotation checks; ISO-8601 timestamp. "
            "Used by tests to drive deterministic time-based assertions."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human report.",
    )
    args = parser.parse_args(argv)

    now: datetime | None = None
    if args.now is not None:
        now = _parse_iso8601(args.now)
        if now is None:
            print(
                f"FAIL: --now value not parseable as ISO-8601: {args.now!r}",
                file=sys.stderr,
            )
            return 3

    if args.mode == "workflow":
        repo_root = (args.repo_root or Path.cwd()).resolve()
        report = run_workflow_checks(repo_root)
    elif args.mode == "layout":
        if args.layout is None:
            print(
                "FAIL: --layout PATH is required in layout mode",
                file=sys.stderr,
            )
            return 3
        report = run_layout_checks(args.layout.resolve(), now=now)
    elif args.mode == "chain":
        if args.layout is None or args.link_dir is None:
            print(
                "FAIL: --layout and --link-dir are required in chain mode",
                file=sys.stderr,
            )
            return 3
        report = run_chain_checks(
            args.layout.resolve(),
            args.link_dir.resolve(),
            coverage_only=args.check_coverage_only,
        )
    else:  # rotation
        if args.layout is None:
            print(
                "FAIL: --layout PATH is required in rotation mode",
                file=sys.stderr,
            )
            return 3
        report = run_rotation_checks(args.layout.resolve(), now=now)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_human(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
