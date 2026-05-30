"""Public ReplaySandboxDriver Protocol + supporting dataclasses (M04 w4).

Per spec section E.4 (lines 3939-3987) replay execution runs inside an
isolated sandbox managed by a pluggable driver. This package is the ONLY
OSS surface third-party drivers may target: the Protocol is pure-Python
(stdlib-only) and grants the right to implement against it under the
package's Apache-2.0 license. Concrete drivers (e2b, modal,
local-firecracker, local-docker) live in ``relay-platform`` and are NOT
open-sourced (CLAUDE.md repo-boundary rule, spec line 3941).

Why a separate package: the contract VAL-V2M04-030 mandates the path
``packages/replay-sandbox-protocol/`` so third-party driver authors can
add a single dependency without pulling in the local-sidecar, the
replay-proxy, or any other Relay internals. The package has ZERO runtime
dependencies.

VAL-V2M04-030: ``ReplaySandboxDriver`` is a ``typing.Protocol`` decorated
with ``@runtime_checkable`` so ``isinstance(stub, ReplaySandboxDriver)``
returns True only when every required method is present.

VAL-V2M04-031: ``NetworkPolicy``, ``ToolPolicy``, ``EphemeralCredential``
are exported alongside the Protocol. ``EphemeralCredential.ttl_seconds``
is bounded to <= 900 per spec line 3986 (P0 max); the dataclass validates
in ``__post_init__`` and raises ``ValueError`` on violation.

VAL-V2M04-032: this package contains the Protocol definition only. No
concrete driver classes (``E2BDriver``, ``ModalDriver``,
``LocalFirecrackerDriver``, ``LocalDockerDriver``) are defined in any OSS
package; a grep guard at VAL-V2M04-032 enforces.

Spec anchors:
  E.4 3939-3987   ReplaySandboxDriver Protocol + dataclasses
  E.3 3931-3936   canonical four side_effect_class values
  Repository topology (CLAUDE.md): drivers stay private

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

# Per spec line 3986 the P0 maximum TTL on an ephemeral sandbox credential
# is 900 seconds (15 minutes). A driver implementation that accepts a
# longer-lived credential violates the spec; we enforce at construction
# time with a structured ValueError so misuse fails closed at the call
# site rather than silently expanding the blast radius of a leaked
# credential.
P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS = 900


# -----------------------------------------------------------------------------
# Opaque types passed across the Protocol boundary.
# -----------------------------------------------------------------------------
#
# These types are intentionally minimal stubs. The Protocol commits to
# their names and shapes; the precise wire format of each is owned by the
# driver implementation. A third-party driver may treat the dataclass as
# a plain bag-of-fields and serialize it however it wants.

@dataclass(frozen=True)
class FixtureRef:
    """Reference to a recorded replay fixture (spec E.2)."""

    fixture_id: str
    output_ref: str | None = None


@dataclass(frozen=True)
class SandboxHandle:
    """Opaque handle returned by ``provision``; passed to subsequent calls."""

    sandbox_id: str
    driver_name: str


@dataclass(frozen=True)
class SandboxExecResult:
    """Result of ``exec_run``: exit code + stdout/stderr refs.

    The refs are opaque strings; concrete drivers may write them to
    blob storage, the local filesystem, or any other location.
    """

    exit_code: int
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class SideEffectRequest:
    """One side-effect attempt as observed by the sandbox driver.

    ``side_effect_class`` MUST be one of the spec's canonical four values
    (``read_only``, ``mutating``, ``external_irreversible``,
    ``approval_required``). The Protocol does NOT validate the value
    itself; ``attempt_side_effect`` returns a ``SideEffectDecision`` with
    ``allowed=False`` and ``reason`` set on out-of-enum input.
    """

    tool_name: str
    side_effect_class: str
    args_digest: str
    idempotency_key: str
    approval_token: str | None = None


@dataclass(frozen=True)
class SideEffectDecision:
    """Driver's verdict on a side-effect attempt."""

    allowed: bool
    reason: str
    marker_id: str | None = None


# -----------------------------------------------------------------------------
# NetworkPolicy (spec E.4 lines 3967-3972; VAL-V2M04-031)
# -----------------------------------------------------------------------------
#
# Network egress defaults to deny per spec line 3969. The driver enforces
# the allowlist; this dataclass is the wire shape passed across the
# Protocol boundary.

@dataclass(frozen=True)
class NetworkPolicy:
    """Sandbox network egress policy.

    Fields:
        egress_default: ALWAYS the literal ``"deny"`` in P0. The Literal
            type pin documents the intent, and ``__post_init__`` enforces
            it at runtime (VAL-ISO-038): a Python ``Literal`` annotation is
            NOT checked at runtime, so the guard is what actually prevents a
            caller from passing ``"allow"``.
        egress_allowlist: Exact-match hostnames or CIDR blocks. Empty
            list means full deny.
        egress_proxy: When set, all egress is routed via Relay's recording
            proxy at this URL. ``None`` means direct egress against the
            allowlist.
    """

    egress_default: Literal["deny"]
    egress_allowlist: list[str] = field(default_factory=list)
    egress_proxy: str | None = None

    def __post_init__(self) -> None:
        # VAL-ISO-038: runtime-enforce the P0 default-deny invariant. The
        # ``Literal["deny"]`` annotation is not checked at runtime, so a
        # caller could otherwise construct ``egress_default="allow"`` and
        # silently defeat the sandbox's default-deny egress (spec E.4 line
        # 3969). Fail closed at construction time, mirroring
        # ``EphemeralCredential.__post_init__``.
        if self.egress_default != "deny":
            raise ValueError(
                f"NetworkPolicy.egress_default must be the literal 'deny' "
                f"(P0 default-deny egress per spec E.4 line 3969); got "
                f"{self.egress_default!r}. The allowlist is the only way to "
                f"permit egress; the default may never be relaxed."
            )


# -----------------------------------------------------------------------------
# ToolPolicy (spec E.4 lines 3974-3979; VAL-V2M04-031)
# -----------------------------------------------------------------------------
#
# Per-replay tool routing: which tools come from cassette, which are
# allowed live, which are blocked, which need approval. A tool name MAY
# appear in only one list; the driver enforces no-overlap at provisioning
# time.

@dataclass(frozen=True)
class ToolPolicy:
    """Per-replay tool routing policy.

    Fields:
        mocked_tools: tool_name -> serve from cassette.
        live_tools: tool_name -> allowed live calls. MUST be read_only or
            carry an approved policy override.
        blocked_tools: tool_name -> deny outright; any attempt produces
            RELAY-REPLAY-014.
        approval_required_tools: tool_name -> blocked until human approval
            via UI single-use token (VAL-V2M04-026/027).
    """

    mocked_tools: list[str] = field(default_factory=list)
    live_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    approval_required_tools: list[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# EphemeralCredential (spec E.4 lines 3982-3987; VAL-V2M04-031)
# -----------------------------------------------------------------------------
#
# A scoped, short-lived credential handed to the sandbox. The secret
# itself is NEVER inlined (spec line 3985); only a reference to a vault
# entry is passed. The driver fetches the actual secret out-of-band right
# before use.
#
# ttl_seconds is bounded to P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS (900
# seconds = 15 min) per spec line 3986; a longer-lived credential
# violates the P0 contract and raises ValueError at construction time.

@dataclass(frozen=True)
class EphemeralCredential:
    """Scoped JWT/STS credential handed to the sandbox for one session.

    The secret itself is NEVER inlined; ``secret_ref`` is an opaque
    reference (e.g., a vault path) that the driver resolves at call time.

    VAL-V2M04-031: ``__post_init__`` raises ValueError when
    ``ttl_seconds > 900``.
    """

    label: str
    secret_ref: str
    ttl_seconds: int

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError(
                f"EphemeralCredential.ttl_seconds must be > 0; "
                f"got {self.ttl_seconds!r}"
            )
        if self.ttl_seconds > P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS:
            raise ValueError(
                f"EphemeralCredential.ttl_seconds must be <= "
                f"{P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS} (P0 max per "
                f"spec E.4 line 3986); got {self.ttl_seconds!r}. "
                f"A longer-lived credential violates the P0 sandbox "
                f"contract and expands the blast radius of a leak."
            )


# -----------------------------------------------------------------------------
# ReplaySandboxDriver Protocol (spec E.4 lines 3944-3964; VAL-V2M04-030)
# -----------------------------------------------------------------------------
#
# Five required methods + one required class attribute (``name``). The
# Protocol is decorated ``@runtime_checkable`` so callers can use
# ``isinstance(obj, ReplaySandboxDriver)`` to dispatch on driver shape.
#
# Signatures match spec lines 3944-3964 verbatim (parameter names, types,
# return types). A stub class missing any one method fails the isinstance
# check.

@runtime_checkable
class ReplaySandboxDriver(Protocol):
    """Public Protocol every replay sandbox driver MUST implement.

    Concrete drivers (E2B, Modal, local-firecracker, local-docker) live
    in ``relay-platform/services/replay-workers/`` and are NOT open-
    sourced. Third-party driver authors target this Protocol and depend
    on this package alone.

    Spec section E.4 lines 3944-3964.
    """

    # Driver name as it appears in evidence bundles; matches one of
    # 'e2b' | 'modal' | 'local-firecracker' | 'local-docker' for the
    # canonical drivers. Third-party drivers SHOULD use a reverse-DNS
    # name (e.g. 'com.acme.relay-driver') to avoid collision.
    name: str

    def provision(
        self,
        *,
        fixture_refs: list[FixtureRef],
        network_policy: NetworkPolicy,
        tool_policy: ToolPolicy,
        ephemeral_credentials: list[EphemeralCredential],
        fs_snapshot_ref: str | None,
        timeout_seconds: int,
    ) -> SandboxHandle:
        """Create a new sandbox session with the given policies + fixtures.

        Returns a SandboxHandle that subsequent calls accept.
        """
        ...

    def exec_run(
        self,
        handle: SandboxHandle,
        *,
        command: list[str],
        env: dict[str, str],
        stdin_ref: str | None,
    ) -> SandboxExecResult:
        """Run a command inside the sandbox; return its exit code + refs."""
        ...

    def attempt_side_effect(
        self,
        handle: SandboxHandle,
        request: SideEffectRequest,
    ) -> SideEffectDecision:
        """Decide whether a side-effecting tool call is permitted.

        For ``read_only`` tools the driver MAY return ``allowed=True``
        when the destination is on the egress allowlist. For ``mutating``
        and ``external_irreversible`` tools the driver MUST return
        ``allowed=False`` unless an audited override is in effect. For
        ``approval_required`` tools the driver MUST return
        ``allowed=False`` unless ``request.approval_token`` is an
        unexpired single-use token.
        """
        ...

    def snapshot(self, handle: SandboxHandle, *, label: str) -> str:
        """Take a filesystem snapshot of the sandbox; return its ref."""
        ...

    def teardown(self, handle: SandboxHandle) -> None:
        """Destroy the sandbox session and release its resources."""
        ...


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

__all__ = [
    "P0_MAX_EPHEMERAL_CREDENTIAL_TTL_SECONDS",
    "EphemeralCredential",
    "FixtureRef",
    "NetworkPolicy",
    "ReplaySandboxDriver",
    "SandboxExecResult",
    "SandboxHandle",
    "SideEffectDecision",
    "SideEffectRequest",
    "ToolPolicy",
]


# Acknowledge unused import (Any imported for forward extensibility).
_ = (Any,)
