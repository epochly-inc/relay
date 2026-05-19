"""VAL-V3M5-019: Hosted default redaction policy exported.

The SDK ships a canonical default redaction policy (spec G.8) that
applies common-sense defaults: prompt + output content is redacted,
field-value patterns matching ``password``/``api_key``/``secret``/
``token`` are redacted, and ``raw_capture`` is ``False`` (default-deny
per CLAUDE.md keystone #7).

The constant ``HOSTED_DEFAULT_POLICY`` lives in
``packages/sdk-python/relay/redaction.py``. The fixture mirror is at
``packages/schemas/raw/redaction-policy.default.v1.yaml``. The two
forms MUST be byte-equal when the constant is serialised via
``yaml.safe_dump(..., sort_keys=False)`` so a downstream consumer that
reads either form sees the same bytes.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from relay.redaction import HOSTED_DEFAULT_POLICY, RedactionPolicy

_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "schemas"
    / "raw"
    / "redaction-policy.default.v1.yaml"
)


@pytest.mark.plumbing
def test_hosted_default_policy_constant_imports() -> None:
    """The HOSTED_DEFAULT_POLICY constant is importable from relay.redaction."""
    assert isinstance(HOSTED_DEFAULT_POLICY, dict)
    assert HOSTED_DEFAULT_POLICY  # non-empty


@pytest.mark.plumbing
def test_hosted_default_policy_raw_capture_false() -> None:
    """Default policy is default-deny on raw capture (keystone #7)."""
    assert HOSTED_DEFAULT_POLICY.get("raw_capture") is False


@pytest.mark.plumbing
def test_hosted_default_policy_has_at_least_four_matchers() -> None:
    """Spec G.8 requires at least the four common-sense field patterns."""
    matchers = HOSTED_DEFAULT_POLICY.get("matchers")
    assert isinstance(matchers, list)
    assert len(matchers) >= 4


@pytest.mark.plumbing
def test_hosted_default_policy_fixture_exists() -> None:
    """The YAML mirror fixture exists at the spec-pinned path."""
    assert _FIXTURE_PATH.is_file(), f"missing fixture: {_FIXTURE_PATH}"


@pytest.mark.plumbing
def test_hosted_default_policy_byte_equal_with_fixture() -> None:
    """Constant serialised via yaml.safe_dump matches fixture bytes verbatim."""
    serialised = yaml.safe_dump(HOSTED_DEFAULT_POLICY, sort_keys=False)
    fixture_text = _FIXTURE_PATH.read_text(encoding="utf-8")
    assert serialised == fixture_text


@pytest.mark.plumbing
def test_hosted_default_policy_loads_as_redaction_policy() -> None:
    """Constant is a valid v1 redaction policy body (RedactionPolicy.load)."""
    parsed = RedactionPolicy.load(HOSTED_DEFAULT_POLICY)
    assert parsed.raw_capture is False
    assert parsed.dpa_ref is None
    assert parsed.approver_user_id is None
    assert len(parsed.matchers) >= 4


@pytest.mark.plumbing
def test_hosted_default_policy_fixture_loads_as_redaction_policy() -> None:
    """Fixture YAML body also loads as a valid v1 redaction policy."""
    body = yaml.safe_load(_FIXTURE_PATH.read_text(encoding="utf-8"))
    parsed = RedactionPolicy.load(body)
    assert parsed.raw_capture is False
    assert len(parsed.matchers) >= 4
