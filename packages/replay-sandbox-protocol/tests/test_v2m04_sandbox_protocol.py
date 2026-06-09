"""V2 M04 w4-side-effects: ReplaySandboxDriver Protocol tests.

Covers contract assertions VAL-V2M04-030, VAL-V2M04-031, VAL-V2M04-032.
Spec anchors: section E.4 lines 3939-3987.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import inspect
import re
import subprocess
from dataclasses import fields
from pathlib import Path

import pytest
from relay_replay_sandbox_protocol import (
    P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS,
    EphemeralCredential,
    NetworkPolicy,
    ReplaySandboxDriver,
    SandboxHandle,
    SideEffectDecision,
    ToolPolicy,
)

_THIS = Path(__file__).resolve()
# packages/replay-sandbox-protocol/tests/test_v2m04_sandbox_protocol.py
# parents[3] is the public relay/ repo root.
_REPO_ROOT = _THIS.parents[3]


# ---------------------------------------------------------------------------
# VAL-V2M04-030: ReplaySandboxDriver Protocol with exactly five methods.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_protocol_has_required_five_methods() -> None:
    """Protocol exposes provision, exec_run, attempt_side_effect, snapshot,
    teardown (spec E.4 lines 3947-3964).
    """
    required = {
        "provision",
        "exec_run",
        "attempt_side_effect",
        "snapshot",
        "teardown",
    }
    members = {
        name
        for name in dir(ReplaySandboxDriver)
        if not name.startswith("_")
    }
    missing = required - members
    assert not missing, f"Protocol missing methods: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_protocol_has_name_class_attribute() -> None:
    """Protocol declares ``name: str`` class attribute (spec line 3945)."""
    annotations = getattr(ReplaySandboxDriver, "__annotations__", {})
    assert "name" in annotations, (
        f"Protocol must declare `name: str` annotation; got {annotations!r}"
    )
    # `from __future__ import annotations` stringifies; accept either form.
    raw = annotations["name"]
    assert raw is str or (isinstance(raw, str) and raw == "str"), raw


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_provision_signature_matches_spec() -> None:
    """``provision`` signature per spec lines 3947-3952."""
    sig = inspect.signature(ReplaySandboxDriver.provision)
    params = list(sig.parameters.values())
    # self + 6 keyword-only params
    assert params[0].name == "self"
    keyword_only = {p.name for p in params if p.kind == p.KEYWORD_ONLY}
    expected = {
        "fixture_refs",
        "network_policy",
        "tool_policy",
        "ephemeral_credentials",
        "fs_snapshot_ref",
        "timeout_seconds",
    }
    assert keyword_only == expected, (
        f"provision keyword-only params mismatch: got {keyword_only}, "
        f"expected {expected}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_exec_run_signature_matches_spec() -> None:
    """``exec_run(handle, *, command, env, stdin_ref)`` per spec 3954-3957."""
    sig = inspect.signature(ReplaySandboxDriver.exec_run)
    params = list(sig.parameters.values())
    assert params[0].name == "self"
    assert params[1].name == "handle"
    assert params[1].kind == params[1].POSITIONAL_OR_KEYWORD
    keyword_only = {p.name for p in params if p.kind == p.KEYWORD_ONLY}
    assert keyword_only == {"command", "env", "stdin_ref"}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_attempt_side_effect_signature_matches_spec() -> None:
    """``attempt_side_effect(handle, request)`` per spec 3959-3960."""
    sig = inspect.signature(ReplaySandboxDriver.attempt_side_effect)
    params = list(sig.parameters.values())
    assert params[0].name == "self"
    assert params[1].name == "handle"
    assert params[2].name == "request"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_snapshot_signature_matches_spec() -> None:
    """``snapshot(handle, *, label) -> str`` per spec line 3962."""
    sig = inspect.signature(ReplaySandboxDriver.snapshot)
    params = list(sig.parameters.values())
    assert params[0].name == "self"
    assert params[1].name == "handle"
    keyword_only = [p for p in params if p.kind == p.KEYWORD_ONLY]
    assert len(keyword_only) == 1 and keyword_only[0].name == "label"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_teardown_signature_matches_spec() -> None:
    """``teardown(handle) -> None`` per spec line 3964."""
    sig = inspect.signature(ReplaySandboxDriver.teardown)
    params = list(sig.parameters.values())
    assert [p.name for p in params] == ["self", "handle"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_protocol_is_runtime_checkable_isinstance_passes() -> None:
    """A class that implements all five methods + `name` is an instance."""

    class FullDriver:
        name = "test-driver"

        def provision(
            self,
            *,
            fixture_refs,
            network_policy,
            tool_policy,
            ephemeral_credentials,
            fs_snapshot_ref,
            timeout_seconds,
        ):
            return SandboxHandle(sandbox_id="sb-1", driver_name=self.name)

        def exec_run(self, handle, *, command, env, stdin_ref):
            return None

        def attempt_side_effect(self, handle, request):
            return SideEffectDecision(allowed=True, reason="test")

        def snapshot(self, handle, *, label):
            return "snap-ref"

        def teardown(self, handle):
            return None

    assert isinstance(FullDriver(), ReplaySandboxDriver)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-030")
def test_protocol_is_runtime_checkable_isinstance_fails_on_missing_method() -> None:
    """A stub class missing one method fails isinstance."""

    class PartialDriver:
        name = "partial"

        def provision(self, **kwargs):
            return None

        # Missing exec_run, attempt_side_effect, snapshot, teardown.

    assert not isinstance(PartialDriver(), ReplaySandboxDriver)


# ---------------------------------------------------------------------------
# VAL-V2M04-031: supporting dataclasses + TTL validator.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_network_policy_fields() -> None:
    """NetworkPolicy has egress_default, egress_allowlist, egress_proxy."""
    field_names = {f.name for f in fields(NetworkPolicy)}
    assert field_names == {"egress_default", "egress_allowlist", "egress_proxy"}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_network_policy_egress_default_is_deny_literal() -> None:
    """The annotation pins ``egress_default`` to ``Literal['deny']``."""
    annotations = NetworkPolicy.__annotations__
    type_str = str(annotations["egress_default"])
    assert "deny" in type_str, (
        f"egress_default must be Literal['deny']; got {type_str!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-038")
def test_network_policy_accepts_deny_default() -> None:
    """The only permitted ``egress_default`` value, ``"deny"``, constructs."""
    policy = NetworkPolicy(egress_default="deny")
    assert policy.egress_default == "deny"
    assert policy.egress_allowlist == []
    assert policy.egress_proxy is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-038")
@pytest.mark.parametrize("bad_value", ["allow", "ALLOW", "", "Deny", "deny ", "permit"])
def test_network_policy_rejects_non_deny_egress_default(bad_value: str) -> None:
    """Constructing NetworkPolicy with egress_default != "deny" MUST raise
    ValueError at construction time (VAL-ISO-038).

    The ``Literal["deny"]`` annotation is NOT enforced at runtime; without a
    ``__post_init__`` guard a third-party caller can build
    ``NetworkPolicy(egress_default="allow")`` and silently defeat the P0
    default-deny invariant. This mirrors EphemeralCredential.__post_init__.
    """
    with pytest.raises(ValueError, match="deny"):
        NetworkPolicy(egress_default=bad_value)  # type: ignore[arg-type]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_tool_policy_fields() -> None:
    """ToolPolicy has mocked_tools, live_tools, blocked_tools,
    approval_required_tools (all list[str])."""
    field_names = {f.name for f in fields(ToolPolicy)}
    assert field_names == {
        "mocked_tools",
        "live_tools",
        "blocked_tools",
        "approval_required_tools",
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_ephemeral_credential_fields() -> None:
    """EphemeralCredential has label, secret_ref, ttl_seconds."""
    field_names = {f.name for f in fields(EphemeralCredential)}
    assert field_names == {"label", "secret_ref", "ttl_seconds"}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_ephemeral_credential_accepts_ttl_at_p0_max() -> None:
    """ttl_seconds == 900 (the P0 max) is accepted."""
    cred = EphemeralCredential(
        label="lab",
        secret_ref="vault://x",
        ttl_seconds=P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS,
    )
    assert cred.ttl_seconds == 900


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_ephemeral_credential_rejects_ttl_over_p0_max() -> None:
    """ttl_seconds == 901 raises ValueError per spec line 3986."""
    with pytest.raises(ValueError, match="900"):
        EphemeralCredential(
            label="lab",
            secret_ref="vault://x",
            ttl_seconds=901,
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_ephemeral_credential_rejects_zero_ttl() -> None:
    """ttl_seconds == 0 raises ValueError (defensive: a 0-TTL credential
    would be unusable)."""
    with pytest.raises(ValueError):
        EphemeralCredential(label="x", secret_ref="r", ttl_seconds=0)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-031")
def test_ephemeral_credential_rejects_negative_ttl() -> None:
    """ttl_seconds == -1 raises ValueError (defensive)."""
    with pytest.raises(ValueError):
        EphemeralCredential(label="x", secret_ref="r", ttl_seconds=-1)


# ---------------------------------------------------------------------------
# VAL-V2M04-032: no concrete drivers in OSS.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-032")
def test_no_concrete_replay_sandbox_drivers_in_oss() -> None:
    """grep guard: only the Protocol definition file may declare
    ReplaySandboxDriver. No concrete classes (E2BDriver, ModalDriver,
    LocalFirecrackerDriver, LocalDockerDriver) anywhere in OSS.
    """
    # Scan only OSS source paths (packages/, apps/, services/) and exclude
    # tests/ + __pycache__ + .venv + node_modules.
    candidates = []
    for top in ("packages", "apps", "services"):
        top_path = _REPO_ROOT / top
        if not top_path.is_dir():
            continue
        for py in top_path.rglob("*.py"):
            parts = set(py.parts)
            if "__pycache__" in parts or ".venv" in parts:
                continue
            if "tests" in parts or "_generated" in parts:
                continue
            candidates.append(py)

    # The Protocol's class definition lives in the protocol package; that
    # is the ONLY non-test file allowed to declare the name.
    protocol_file = (
        _REPO_ROOT
        / "packages"
        / "replay-sandbox-protocol"
        / "src"
        / "relay_replay_sandbox_protocol"
        / "__init__.py"
    )
    allowed = {protocol_file.resolve()}

    pattern = re.compile(r"^\s*class\s+\w*ReplaySandboxDriver\w*\b")
    forbidden_concrete = re.compile(
        r"^\s*class\s+(E2B|Modal|LocalFirecracker|LocalDocker)Driver\b"
    )
    offenders: list[tuple[Path, int, str]] = []
    for py in candidates:
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if forbidden_concrete.search(line):
                offenders.append((py, lineno, line.strip()))
            if pattern.search(line) and py.resolve() not in allowed:
                offenders.append((py, lineno, line.strip()))
    assert offenders == [], (
        "No concrete ReplaySandboxDriver classes are permitted in OSS; "
        "violations:\n"
        + "\n".join(f"  {p}:{ln}: {src}" for p, ln, src in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-032")
def test_grep_finds_only_protocol_definition() -> None:
    """Independent grep-based guard mirroring the VAL-V2M04-032 evidence
    requirement (``grep -rn "class.*ReplaySandboxDriver" relay/packages
    relay/apps relay/services``).
    """
    try:
        result = subprocess.run(
            [
                "grep",
                "-rn",
                "-E",
                # Skip Rust BUILD-ARTIFACT trees only (mirrors the Python-sibling
                # guard at test_no_concrete_replay_sandbox_drivers_in_oss, which
                # excludes .venv/__pycache__). cel-wasm's crate/target AND
                # vendor/cel/target are ~1.1GB of Rust build output; without
                # pruning them grep exceeds the 15s timeout. ``--exclude-dir=
                # target`` prunes BOTH (it matches a dir named ``target`` at ANY
                # depth, including ``vendor/cel/target``), so the heavy trees are
                # excluded while committed source under ``vendor/`` is STILL
                # scanned -- we deliberately do NOT ``--exclude-dir=vendor``,
                # which would hide a future legit (or illicit) concrete
                # ReplaySandboxDriver added in committed vendor SOURCE. The one
                # true ReplaySandboxDriver Protocol definition lives in
                # packages/replay-sandbox-protocol/src, not under any target/ dir.
                "--exclude-dir=target",
                r"class[[:space:]]+\w*ReplaySandboxDriver",
                "packages",
                "apps",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(_REPO_ROOT),
            check=False,
        )
    except FileNotFoundError:
        pytest.skip("grep not available on this platform")
    matches = [
        line
        for line in result.stdout.splitlines()
        if "__pycache__" not in line and "/tests/" not in line
    ]
    # Every match must come from the Protocol definition file.
    for line in matches:
        assert "packages/replay-sandbox-protocol" in line, (
            f"unexpected ReplaySandboxDriver definition outside the "
            f"Protocol package: {line!r}"
        )
