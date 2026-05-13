"""Tier-1 plumbing tests for VAL-W1-057 + VAL-W1-060.

Covers two canonical-YAML coverage assertions:

VAL-W1-057: ``packages/schemas/raw/relay-error-codes.yaml`` enumerates every
            ``RELAY-{AREA}-NNN`` code referenced anywhere in the contract
            (``contract.md`` and ``contract-drafts/``). Codes referenced in
            contract text but missing from the YAML MUST fail the test.
            Codes in the YAML never referenced emit a warning but do NOT
            fail.

VAL-W1-060: ``packages/schemas/raw/owner-email-deny.yaml`` exists, parses,
            and contains the four canonical default-deny prefixes
            (``team-``, ``group-``, ``dl-``, ``all-``) under
            ``default_deny_prefixes``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path

import pytest
import yaml

# -----------------------------------------------------------------------------
# Configuration constants (cite absolute paths per orchestrator instructions)
# -----------------------------------------------------------------------------

# parents[0]=tests, [1]=python, [2]=schemas, [3]=packages, [4]=relay (repo root)
REPO_ROOT = Path(__file__).resolve().parents[4]
RAW_ROOT = REPO_ROOT / "packages" / "schemas" / "raw"

ERROR_CODES_YAML = RAW_ROOT / "relay-error-codes.yaml"
OWNER_DENY_YAML = RAW_ROOT / "owner-email-deny.yaml"

# Operation contract paths. Tests read these via absolute paths declared as
# config constants per orchestrator directive; we DO NOT copy contract text
# into the repo.
OPS_DIR = Path("/Users/chandlervaughn/.ops-runtime/relay-v0.1-oss-wedge")
CONTRACT_MD = OPS_DIR / "contract.md"
CONTRACT_DRAFTS_DIR = OPS_DIR / "contract-drafts"

# Canonical RELAY-* error-code pattern per VAL-W1-029.
RELAY_CODE_RE = re.compile(r"RELAY-[A-Z]+-[0-9]{3}")


def _collect_codes_from_contract_text() -> set[str]:
    """Grep equivalent: scan contract.md + contract-drafts/ for RELAY-* codes."""
    codes: set[str] = set()
    if CONTRACT_MD.exists():
        codes.update(RELAY_CODE_RE.findall(CONTRACT_MD.read_text(encoding="utf-8")))
    if CONTRACT_DRAFTS_DIR.exists():
        for path in sorted(CONTRACT_DRAFTS_DIR.glob("*.md")):
            codes.update(RELAY_CODE_RE.findall(path.read_text(encoding="utf-8")))
    return codes


def _load_yaml_codes() -> set[str]:
    text = ERROR_CODES_YAML.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "codes" not in data:
        raise AssertionError(
            f"{ERROR_CODES_YAML} missing top-level 'codes' key"
        )
    codes = data["codes"]
    if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
        raise AssertionError(
            f"{ERROR_CODES_YAML}: 'codes' MUST be a list of strings"
        )
    return set(codes)


# -----------------------------------------------------------------------------
# VAL-W1-057: relay-error-codes.yaml coverage
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-057")
def test_relay_error_codes_yaml_exists() -> None:
    assert ERROR_CODES_YAML.is_file(), (
        f"VAL-W1-057: {ERROR_CODES_YAML} MUST exist"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-057")
def test_relay_error_codes_yaml_parses_with_codes_key() -> None:
    yaml_codes = _load_yaml_codes()
    # Must enumerate at least the 15 documented spec B.4 codes per VAL-W1-030.
    assert len(yaml_codes) >= 15, (
        f"VAL-W1-057: relay-error-codes.yaml has only {len(yaml_codes)} codes; "
        f"VAL-W1-030 requires the 15 spec B.4 codes at minimum"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-057")
def test_relay_error_codes_yaml_covers_every_contract_code() -> None:
    if not CONTRACT_MD.exists():
        pytest.skip(
            "RELAY-EVAL-TIER1-SKIPPED-CONTRACT-PATH-ABSENT: "
            f"{CONTRACT_MD} not present on this host (forks / fresh checkouts "
            "may not have ops state). Test runs full coverage only in the "
            "ops-runtime environment."
        )
    yaml_codes = _load_yaml_codes()
    contract_codes = _collect_codes_from_contract_text()
    missing = contract_codes - yaml_codes
    assert not missing, (
        f"VAL-W1-057: codes referenced in contract text but missing from "
        f"{ERROR_CODES_YAML.name}: {sorted(missing)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-057")
def test_relay_error_codes_yaml_unreferenced_codes_emit_warning_only() -> None:
    if not CONTRACT_MD.exists():
        pytest.skip(
            "RELAY-EVAL-TIER1-SKIPPED-CONTRACT-PATH-ABSENT: contract.md absent"
        )
    yaml_codes = _load_yaml_codes()
    contract_codes = _collect_codes_from_contract_text()
    unreferenced = yaml_codes - contract_codes
    if unreferenced:
        warnings.warn(
            f"VAL-W1-057: codes in {ERROR_CODES_YAML.name} never referenced "
            f"by contract text (warning only, not a failure): "
            f"{sorted(unreferenced)}",
            stacklevel=2,
        )
    # Assertion: this code path NEVER fails. Unreferenced codes are allowed
    # for spec-locked codes not yet bound in contract assertions.
    assert True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-057")
def test_relay_error_codes_yaml_every_token_matches_pattern() -> None:
    yaml_codes = _load_yaml_codes()
    pattern = re.compile(r"^RELAY-[A-Z]+-[0-9]{3}$")
    bad = [c for c in yaml_codes if not pattern.match(c)]
    assert not bad, (
        f"VAL-W1-057: tokens in {ERROR_CODES_YAML.name} not matching "
        f"^RELAY-[A-Z]+-[0-9]{{3}}$: {bad}"
    )


# -----------------------------------------------------------------------------
# VAL-W1-060: owner-email-deny.yaml default deny prefixes
# -----------------------------------------------------------------------------


REQUIRED_DENY_PREFIXES = ["team-", "group-", "dl-", "all-"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-060")
def test_owner_email_deny_yaml_exists() -> None:
    assert OWNER_DENY_YAML.is_file(), (
        f"VAL-W1-060: {OWNER_DENY_YAML} MUST exist"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-060")
def test_owner_email_deny_yaml_parses_with_default_deny_prefixes_key() -> None:
    text = OWNER_DENY_YAML.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert isinstance(data, dict), (
        f"VAL-W1-060: {OWNER_DENY_YAML} root MUST be a mapping"
    )
    assert "default_deny_prefixes" in data, (
        f"VAL-W1-060: {OWNER_DENY_YAML} missing 'default_deny_prefixes' key"
    )
    prefixes = data["default_deny_prefixes"]
    assert isinstance(prefixes, list), (
        "VAL-W1-060: 'default_deny_prefixes' MUST be a list"
    )
    assert all(isinstance(p, str) for p in prefixes), (
        "VAL-W1-060: every entry in 'default_deny_prefixes' MUST be a string"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-060")
@pytest.mark.parametrize("required_prefix", REQUIRED_DENY_PREFIXES)
def test_owner_email_deny_yaml_contains_required_prefix(required_prefix: str) -> None:
    text = OWNER_DENY_YAML.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    prefixes = data.get("default_deny_prefixes", [])
    assert required_prefix in prefixes, (
        f"VAL-W1-060: canonical deny prefix {required_prefix!r} MUST appear "
        f"in {OWNER_DENY_YAML.name}'s default_deny_prefixes; observed: {prefixes}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-060")
def test_owner_email_deny_yaml_all_required_prefixes_in_one_pass() -> None:
    text = OWNER_DENY_YAML.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    prefixes = set(data.get("default_deny_prefixes", []))
    missing = set(REQUIRED_DENY_PREFIXES) - prefixes
    assert not missing, (
        f"VAL-W1-060: missing canonical deny prefixes from "
        f"{OWNER_DENY_YAML.name}: {sorted(missing)}"
    )
