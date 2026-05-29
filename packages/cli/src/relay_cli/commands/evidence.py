"""``rly evidence`` subcommands (W5.4 VAL-W5-025..030).

Subcommand surface:

  * ``rly evidence list``    -- VAL-W5-025: paginated JSON listing of
                                evidence bundles in the local OSS
                                profile, with required binding fields.
  * ``rly evidence show``    -- VAL-W5-026: emits the full evidence
                                bundle JSON for a given bundle id.
  * ``rly evidence verify``  -- VAL-W5-027/028/029/030: offline JWS
                                verification against a cached JWKS;
                                tamper detection; BYO trust-anchor
                                override with a structured warning;
                                spec-pinned default trust anchor.

Per CLAUDE.md keystone invariants:

  * #1 control plane writes the result. The CLI never writes
    ``run_results``; bundle ``verification_status`` is reported as a
    derived view of the on-disk bundle, never written back to the
    canonical control plane from this surface.
  * #8 atomic persistence. Cache writes flow through the JWKS cache
    helper (which uses ``local_atomic_file_write``).
  * #11 trust anchor. The default JWKS URL is pinned to the spec
    section AO.4 value; this module is the single canonical occurrence
    of that literal in ``packages/cli/`` (VAL-W5-030 grep guard).
  * Banned pattern #13: changing :data:`DEFAULT_TRUST_ANCHOR_URL` in a
    routine PR is a CI-blocked board-level decision. The ``--trust-
    anchor`` flag exists for forks/self-hosters; it emits a structured
    stderr WARN line per VAL-W5-029 so the override is auditable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Final

import typer
from relay_acef.bundle_verifier import (
    is_acef_bundle,
    verify_acef_bundle,
)
from relay_sidecar.lockfile import relay_home

from ..errors import build_envelope, emit_envelope
from ..evidence_verifier import (
    VERIFIER_RESULT_SCHEMA,
    parse_bundle_bytes,
    verify_bundle,
)
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_4XX_REMEDIATE,
    EXIT_CLI_USAGE,
    EXIT_SUCCESS,
)
from ..jwks_cache import load_jwks_from_cache
from ..output import emit_json

# -----------------------------------------------------------------------------
# Schema-version constants (one per stdout JSON envelope shape)
# -----------------------------------------------------------------------------

EVIDENCE_LIST_SCHEMA: Final[str] = "relay.cli.evidence_list.v1"
EVIDENCE_SHOW_SCHEMA: Final[str] = "relay.cli.evidence_show.v1"
EVIDENCE_VERIFY_SCHEMA: Final[str] = "relay.cli.evidence_verify.v1"

# -----------------------------------------------------------------------------
# Default trust anchor (CANONICAL OCCURRENCE -- DO NOT DUPLICATE)
# -----------------------------------------------------------------------------
#
# Per CLAUDE.md keystone invariant #11 and banned pattern #13 the OSS
# verifier defaults to the spec section AO.4 JWKS URL. This module is the
# SINGLE canonical occurrence of that literal under ``packages/cli/``;
# VAL-W5-030 enforces the count via a grep guard test. Forks may pass a
# different URL via ``--trust-anchor``, but the default is a board-level
# decision and changing it in a routine PR is CI-blocked.

DEFAULT_TRUST_ANCHOR_URL: Final[str] = (
    "https://relay.epochly.com/.well-known/jwks.json"
)

# Wire codes (spec section B.6 + CLAUDE.md error pattern matching table).
RELAY_EVID_014: Final[str] = "RELAY-EVID-014"
RELAY_CLI_TRUST_ANCHOR_OVERRIDE: Final[str] = "RELAY-CLI-TRUST-ANCHOR-OVERRIDE"
RELAY_CLI_EVIDENCE_BUNDLE_NOT_FOUND: Final[str] = (
    "RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND"
)
RELAY_CLI_EVIDENCE_BUNDLE_INVALID: Final[str] = (
    "RELAY-CLI-EVIDENCE-BUNDLE-INVALID"
)
RELAY_CLI_EVIDENCE_NO_JWKS_CACHE: Final[str] = (
    "RELAY-CLI-EVIDENCE-NO-JWKS-CACHE"
)

# Default page size for ``rly evidence list``.
DEFAULT_LIST_LIMIT: Final[int] = 50
MAX_LIST_LIMIT: Final[int] = 500

# Per-bundle required binding fields (VAL-W5-025). Items missing any
# field are filtered out and counted in the ``malformed_count`` field.
REQUIRED_LIST_BINDING_FIELDS: Final[tuple[str, ...]] = (
    "evidence_bundle_id",
    "schema_version",
    "profile",
    "signing_key_id",
    "generated_at",
    "manifest_commit_hash",
    "redaction_policy_version",
    "trust_anchor",
)

# Per-bundle required full-shape fields (VAL-W5-026). The show command
# echoes the full bundle but asserts each named field is present before
# emitting; missing any field is RELAY-CLI-EVIDENCE-BUNDLE-INVALID.
REQUIRED_SHOW_FIELDS: Final[tuple[str, ...]] = (
    "evidence_bundle_id",
    "assertion_ids",
    "artifacts",
    "commands",
    "trace_span_ids",
    "agent_id",
    "manifest_commit_hash",
    "created_at",
    "signature",
    "trust_anchor",
)


# -----------------------------------------------------------------------------
# Evidence directory helpers
# -----------------------------------------------------------------------------


def _resolve_home(home: str) -> Path:
    """Resolve ``--home`` like the sidecar/replay groups."""
    return Path(home).expanduser() if home else relay_home()


def _evidence_dir(home: Path) -> Path:
    """Return ``${RELAY_HOME}/evidence``."""
    return home / "evidence"


def _bundle_path_by_id(home: Path, bundle_id: str) -> Path:
    """Return the canonical on-disk path for a bundle id."""
    return _evidence_dir(home) / f"{bundle_id}.json"


# -----------------------------------------------------------------------------
# Trust-anchor override warning (VAL-W5-029)
# -----------------------------------------------------------------------------


def _emit_trust_anchor_override_warning(url: str) -> None:
    """Emit a structured stderr WARN line for a BYO trust anchor.

    Per VAL-W5-029 the CLI MUST surface the override in JSON form so
    auditors can attribute the deviation from the spec-pinned default
    to an explicit operator action. Written on stderr (not stdout) so
    machine consumers parsing stdout JSON are not confused.
    """
    warn = {
        "schema_version": "relay.cli.warning.v1",
        "code": RELAY_CLI_TRUST_ANCHOR_OVERRIDE,
        "level": "warn",
        "url": url,
        "message": (
            "trust anchor overridden via --trust-anchor; the spec-pinned "
            "default is " + DEFAULT_TRUST_ANCHOR_URL
        ),
    }
    sys.stderr.write(
        json.dumps(
            warn,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )
    sys.stderr.flush()


# -----------------------------------------------------------------------------
# rly evidence list (VAL-W5-025)
# -----------------------------------------------------------------------------


def _scan_evidence_dir(evidence_dir: Path) -> tuple[list[dict[str, Any]], int]:
    """Scan ``evidence_dir`` for bundle JSON files.

    Returns ``(items, malformed_count)`` where:
      * ``items`` is the list of bundle dicts that have every required
        binding field (VAL-W5-025).
      * ``malformed_count`` is the count of files that parsed as JSON
        but were missing a required field, or failed to parse at all.
        A missing directory yields ``([], 0)``; the operator simply has
        no bundles yet.
    """
    if not evidence_dir.exists() or not evidence_dir.is_dir():
        return [], 0
    items: list[dict[str, Any]] = []
    malformed = 0
    for path in sorted(evidence_dir.glob("*.json")):
        try:
            raw = path.read_bytes()
            bundle = json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            malformed += 1
            continue
        if not isinstance(bundle, dict):
            malformed += 1
            continue
        if any(field not in bundle for field in REQUIRED_LIST_BINDING_FIELDS):
            malformed += 1
            continue
        items.append(bundle)
    # Sort by evidence_bundle_id for deterministic pagination.
    items.sort(key=lambda b: str(b.get("evidence_bundle_id", "")))
    return items, malformed


def _project_list_item(bundle: dict[str, Any]) -> dict[str, Any]:
    """Project a bundle dict into the VAL-W5-025 list-item shape."""
    return {field: bundle[field] for field in REQUIRED_LIST_BINDING_FIELDS}


def _cmd_evidence_list(
    project: str = typer.Option(
        "",
        "--project",
        help=(
            "Optional project UUID filter. v0.1 OSS profile lists all "
            "local bundles regardless of project; the flag is accepted "
            "for forward compatibility with the hosted profile."
        ),
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    limit: int = typer.Option(
        DEFAULT_LIST_LIMIT,
        "--limit",
        help=f"Maximum items per page (1..{MAX_LIST_LIMIT}; default {DEFAULT_LIST_LIMIT}).",
    ),
) -> None:
    """``rly evidence list`` -- list bundles with required binding fields."""
    if limit < 1 or limit > MAX_LIST_LIMIT:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-LIMIT",
            http_status=400,
            message=f"--limit must be in 1..{MAX_LIST_LIMIT}; got {limit}",
            blocked_surface="rly evidence list",
            retry_advice="after_fix",
            details={"limit": limit, "max": MAX_LIST_LIMIT},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    base_home = _resolve_home(home)
    items, malformed = _scan_evidence_dir(_evidence_dir(base_home))

    # Optional project filter (forward-compat hook). When specified the
    # list shrinks to bundles whose ``project_id`` field equals the
    # provided UUID; bundles without ``project_id`` are excluded.
    if project:
        items = [
            it for it in items if str(it.get("project_id", "")) == project
        ]

    page = items[:limit]
    has_more = len(items) > limit

    payload: dict[str, Any] = {
        "schema_version": EVIDENCE_LIST_SCHEMA,
        "items": [_project_list_item(b) for b in page],
        "next_cursor": None,
        "has_more": has_more,
        "malformed_count": malformed,
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly evidence show (VAL-W5-026)
# -----------------------------------------------------------------------------


def _cmd_evidence_show(
    bundle_id: str = typer.Argument(
        ...,
        metavar="BUNDLE_ID",
        help="evidence_bundle_id to display (UUID).",
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    json_flag: bool = typer.Option(
        True,
        "--json/--no-json",
        help=(
            "Emit the full bundle JSON to stdout. Default true; the "
            "OSS profile has no human-readable rendering for v0.1."
        ),
    ),
) -> None:
    """``rly evidence show <id>`` -- emit the full bundle JSON."""
    if not bundle_id:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-BUNDLE-ID",
            http_status=400,
            message="BUNDLE_ID is required and must be non-empty",
            blocked_surface="rly evidence show",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    if not json_flag:
        # OSS v0.1 ships JSON-only for show; --no-json is reserved for a
        # future human-readable rendering. Surfacing a structured signal
        # is preferable to silently emitting nothing.
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-NO-JSON-UNSUPPORTED",
            http_status=400,
            message=(
                "rly evidence show only supports --json output in v0.1; "
                "human-readable rendering lands in a future sub-feature."
            ),
            blocked_surface="rly evidence show",
            retry_advice="after_fix",
            details={"bundle_id": bundle_id},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    base_home = _resolve_home(home)
    path = _bundle_path_by_id(base_home, bundle_id)
    if not path.exists():
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_NOT_FOUND,
            http_status=404,
            message=f"evidence bundle {bundle_id!r} not found at {path!s}",
            blocked_surface="rly evidence show",
            retry_advice="after_fix",
            details={"bundle_id": bundle_id, "path": str(path)},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    try:
        raw = path.read_bytes()
        bundle = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_INVALID,
            http_status=422,
            message=f"evidence bundle {bundle_id!r} is malformed: {exc}",
            blocked_surface="rly evidence show",
            retry_advice="do_not_retry",
            details={"bundle_id": bundle_id, "path": str(path)},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_REMEDIATE) from exc

    if not isinstance(bundle, dict):
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_INVALID,
            http_status=422,
            message=(
                f"evidence bundle {bundle_id!r} root is not a JSON object"
            ),
            blocked_surface="rly evidence show",
            retry_advice="do_not_retry",
            details={"bundle_id": bundle_id, "path": str(path)},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_REMEDIATE)

    missing = [field for field in REQUIRED_SHOW_FIELDS if field not in bundle]
    if missing:
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_INVALID,
            http_status=422,
            message=(
                f"evidence bundle {bundle_id!r} missing required fields: "
                f"{missing}"
            ),
            blocked_surface="rly evidence show",
            retry_advice="do_not_retry",
            details={
                "bundle_id": bundle_id,
                "path": str(path),
                "missing_fields": missing,
            },
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_REMEDIATE)

    payload: dict[str, Any] = {
        "schema_version": EVIDENCE_SHOW_SCHEMA,
        "bundle": bundle,
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly evidence verify (VAL-W5-027/028/029/030)
# -----------------------------------------------------------------------------


def _resolve_bundle_path(arg: str, home: Path) -> Path:
    """Resolve the verify argument to an absolute bundle path.

    Accepts either:
      * an absolute or relative path to a JSON file (preferred -- the
        verify surface is path-based so a CI runner can hand it any
        bundle location, not just ones under RELAY_HOME), or
      * a bare bundle id, in which case the path is resolved under
        ``${RELAY_HOME}/evidence/<id>.json`` for parity with `show`.
    """
    candidate = Path(arg).expanduser()
    if candidate.suffix == ".json" or "/" in arg or "\\" in arg:
        return candidate
    return _bundle_path_by_id(home, arg)


def _cmd_evidence_verify(
    bundle_arg: str = typer.Argument(
        ...,
        metavar="BUNDLE",
        help=(
            "Path to an evidence bundle JSON file, or an "
            "evidence_bundle_id resolved under ${RELAY_HOME}/evidence/."
        ),
    ),
    trust_anchor: str = typer.Option(
        "",
        "--trust-anchor",
        help=(
            "Override the spec-pinned default JWKS URL with a BYO "
            "trust anchor (forks / self-hosters per spec section AO.4). "
            "Emits a structured stderr WARN line when used."
        ),
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
) -> None:
    """``rly evidence verify`` -- offline JWS verification.

    Per VAL-W5-027 verification MUST work fully offline given a populated
    JWKS cache. No outbound network call is attempted at any point in
    this command; if the JWKS is not cached the CLI exits with
    ``RELAY-CLI-EVIDENCE-NO-JWKS-CACHE`` and instructs the operator to
    pre-fetch the JWKS.

    Per VAL-W5-028 a single-byte mutation of the bundle MUST cause a
    non-zero exit with stderr envelope ``RELAY-EVID-014`` and stdout
    JSON ``digest_ok=false, signatures_ok=false``.

    Per VAL-W5-029 the ``--trust-anchor`` flag accepts a BYO JWKS URL
    and emits a structured stderr WARN line; the stdout JSON includes
    ``trust_anchor_overridden=true`` and the provided URL.

    Per VAL-W5-030 the default trust anchor (no flag) is the canonical
    spec-pinned URL declared in :data:`DEFAULT_TRUST_ANCHOR_URL`; that
    constant is the SINGLE source of truth for the URL string in this
    package (CI grep guard enforces uniqueness).
    """
    base_home = _resolve_home(home)
    bundle_path = _resolve_bundle_path(bundle_arg, base_home)

    if not bundle_path.exists():
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_NOT_FOUND,
            http_status=404,
            message=f"evidence bundle not found at {bundle_path!s}",
            blocked_surface="rly evidence verify",
            retry_advice="after_fix",
            details={"path": str(bundle_path)},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    try:
        bundle = parse_bundle_bytes(bundle_path.read_bytes())
    except ValueError as exc:
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_INVALID,
            http_status=422,
            message=str(exc),
            blocked_surface="rly evidence verify",
            retry_advice="do_not_retry",
            details={"path": str(bundle_path)},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_REMEDIATE) from exc

    # Trust-anchor selection: explicit override > default. The default
    # literal lives in :data:`DEFAULT_TRUST_ANCHOR_URL` (canonical
    # occurrence; VAL-W5-030 grep guard).
    overridden = bool(trust_anchor)
    anchor_url = trust_anchor.strip() if overridden else DEFAULT_TRUST_ANCHOR_URL

    if overridden:
        _emit_trust_anchor_override_warning(anchor_url)

    jwks = load_jwks_from_cache(anchor_url, home=base_home)
    if jwks is None:
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_NO_JWKS_CACHE,
            http_status=409,
            message=(
                "no JWKS in local cache for trust anchor "
                f"{anchor_url!r}; offline verification requires a "
                "pre-populated cache. Run a one-time online fetch and "
                "store the JWKS at "
                "${RELAY_HOME}/jwks-cache/<host>.json before retrying."
            ),
            blocked_surface="rly evidence verify",
            retry_advice="after_fix",
            details={
                "trust_anchor": anchor_url,
                "trust_anchor_overridden": overridden,
            },
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    # W11.4 / VAL-CRYPTO-001/004/005: ACEF bundles (ACEF Core schema_version
    # "v0.3" / x-relay namespace shape) are verified by the Relay-OWNED
    # fail-closed ACEF verifier, which resolves keys ONLY from the trusted
    # JWKS by kid (never a header-embedded jwk/x5c) and counts only
    # cryptographically-verified signatures. Relay-native evidence bundles
    # keep using the existing ``verify_bundle``.
    is_acef = is_acef_bundle(bundle)
    if is_acef:
        acef_result = verify_acef_bundle(
            bundle,
            jwks,
            trust_anchor_url=anchor_url,
            offline=True,
        )
        result_digest_ok = acef_result.digest_ok
        result_signatures_ok = acef_result.signatures_ok
        result_structure_ok = acef_result.structure_ok
        result_checks = acef_result.signature_checks
        result_claims_count = acef_result.claims_count
        result_digest = acef_result.bundle_digest_sha256
        result_errors = list(acef_result.errors)
        extra_fields: dict[str, Any] = {
            "bundle_kind": "acef",
            "verified_signature_count": acef_result.verified_signature_count,
            "verified_algorithms": list(acef_result.verified_algorithms),
        }
    else:
        result = verify_bundle(bundle, jwks)
        result_digest_ok = result.digest_ok
        result_signatures_ok = result.signatures_ok
        result_structure_ok = result.structure_ok
        result_checks = result.signature_checks
        result_claims_count = result.claims_count
        result_digest = result.bundle_digest_sha256
        result_errors = list(result.errors)
        extra_fields = {"bundle_kind": "relay-native"}

    payload: dict[str, Any] = {
        "schema_version": EVIDENCE_VERIFY_SCHEMA,
        "digest_ok": result_digest_ok,
        "signatures_ok": result_signatures_ok,
        "structure_ok": result_structure_ok,
        "signatures_checked": [
            {"kid": s.kid, "alg": s.alg, "ok": s.ok, "reason": s.reason}
            for s in result_checks
        ],
        "claims_count": result_claims_count,
        "trust_anchor": anchor_url,
        "trust_anchor_overridden": overridden,
        "bundle_path": str(bundle_path),
        "bundle_digest_sha256": result_digest,
        "errors": result_errors,
        **extra_fields,
    }

    emit_json(payload)

    if result_digest_ok and result_signatures_ok and result_structure_ok:
        raise typer.Exit(code=EXIT_SUCCESS)

    # Tamper detected (or signature crypto failure, or missing/untrusted
    # JWK). Emit RELAY-EVID-014 stderr envelope and exit non-zero. The same
    # fail-closed envelope is emitted for ACEF and Relay-native bundles.
    failed_reasons = [
        f"{s.kid}/{s.alg}: {s.reason}"
        for s in result_checks
        if not s.ok
    ]
    if not failed_reasons:
        failed_reasons = list(result_errors) or ["verification failed"]
    envelope = build_envelope(
        code=RELAY_EVID_014,
        http_status=422,
        message=(
            "evidence bundle failed verification: "
            + "; ".join(failed_reasons[:5])
        ),
        blocked_surface="rly evidence verify",
        retry_advice="do_not_retry",
        details={
            "path": str(bundle_path),
            "bundle_kind": "acef" if is_acef else "relay-native",
            "digest_ok": result_digest_ok,
            "signatures_ok": result_signatures_ok,
            "structure_ok": result_structure_ok,
            "trust_anchor": anchor_url,
            "trust_anchor_overridden": overridden,
            "failed_signature_count": sum(
                1 for s in result_checks if not s.ok
            ),
        },
    )
    emit_envelope(envelope)
    raise typer.Exit(code=EXIT_4XX_BLOCK)


# -----------------------------------------------------------------------------
# rly evidence assess (M07 w7-cli-evidence-assess; VAL-V2M07-020/021)
# -----------------------------------------------------------------------------


EVIDENCE_ASSESS_SCHEMA: Final[str] = "relay.cli.evidence_assess.v1"

# Per CLAUDE.md keystone #2 ("pass without evidence is not a pass") and
# banned pattern "NEVER fabricate IDs that have no backing artifact":
# the readiness-assessment worker lives in private relay-platform and is
# NOT implemented in the OSS sidecar. The OSS CLI therefore MUST NOT
# fabricate an assessment_id locally and emit ``status: "queued"`` with
# exit 0 -- doing so misrepresents a never-enqueued request as a queued
# one. Instead the OSS surface verifies the bundle exists on disk and
# emits a structured ``RELAY-CLI-HOSTED-ONLY`` envelope with
# ``assessment_id: null`` and exit 1 (block / not actionable here). The
# stdout envelope is preserved so machine consumers see a stable record
# with the discriminating ``status: "hosted_only_pending"``.
RELAY_CLI_HOSTED_ONLY: Final[str] = "RELAY-CLI-HOSTED-ONLY"
RELAY_CLI_EVIDENCE_ASSESS_STATUS_HOSTED_ONLY: Final[str] = "hosted_only_pending"


def _cmd_evidence_assess(
    bundle: str = typer.Option(
        ..., "--bundle", help="Evidence bundle id (UUID) to assess."
    ),
    readiness_profile: str = typer.Option(
        "default",
        "--readiness-profile",
        help=(
            "Readiness profile to assess against (e.g., 'eu-ai-act', "
            "'nist-ai-rmf'). Hosted-only in OSS v0.2: the OSS sidecar "
            "does not implement the assessment worker (lives in private "
            "relay-platform). The OSS CLI verifies the bundle exists "
            "locally and emits a hosted-only envelope."
        ),
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly evidence assess --bundle <id>`` -- bundle-existence preflight.

    Per VAL-V2M07-021 the stdout envelope carries ``schema_version:
    "relay.cli.evidence_assess.v1"``, ``assessment_id``, ``bundle_id``,
    ``readiness_profile``, ``enqueued_at``, and ``status``.

    Behavior (OSS v0.2):

      * If the bundle is not found under ``${RELAY_HOME}/evidence/<id>.json``
        the CLI emits ``RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND`` on stderr
        and exits with EXIT_4XX_BLOCK (1). No assess envelope is emitted
        because there is no backing artifact to assess.
      * If the bundle exists the CLI emits the assess envelope with
        ``assessment_id: null`` and ``status: "hosted_only_pending"``,
        accompanied by a ``RELAY-CLI-HOSTED-ONLY`` stderr envelope, and
        exits EXIT_4XX_BLOCK (1). This signals: the request reached a
        well-formed bundle but the OSS sidecar has no assessment worker
        to enqueue against; operators must point at hosted Relay to
        complete the assessment.

    This shape preserves the canonical CLI envelope contract (so a CI
    runner sees a parseable stdout record) while making the absence of
    a backing hosted assessment explicit (``assessment_id`` null,
    non-zero exit). The previous OSS behavior fabricated a UUID and
    exited 0; that violated CLAUDE.md keystone #2 ("pass without
    evidence is not a pass") and was a P0 bug surfaced by the 2026-05-17
    audit.
    """
    del json_output

    if not bundle:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-BUNDLE",
            http_status=400,
            message="--bundle is required",
            blocked_surface="rly evidence assess",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    base_home = _resolve_home(home)
    bundle_path = _bundle_path_by_id(base_home, bundle)
    if not bundle_path.exists():
        envelope = build_envelope(
            code=RELAY_CLI_EVIDENCE_BUNDLE_NOT_FOUND,
            http_status=404,
            message=(
                f"evidence bundle {bundle!r} not found at {bundle_path!s}; "
                "cannot assess a bundle with no backing artifact"
            ),
            blocked_surface="rly evidence assess",
            retry_advice="after_fix",
            details={"bundle_id": bundle, "path": str(bundle_path)},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    from datetime import UTC
    from datetime import datetime as _dt

    enqueued_at = (
        _dt.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    # Emit the canonical assess envelope with assessment_id explicitly
    # null. The discriminating ``status: "hosted_only_pending"`` plus the
    # null assessment_id make the OSS reality machine-detectable without
    # parsing stderr.
    emit_json({
        "schema_version": EVIDENCE_ASSESS_SCHEMA,
        "assessment_id": None,
        "bundle_id": bundle,
        "readiness_profile": readiness_profile,
        "enqueued_at": enqueued_at,
        "status": RELAY_CLI_EVIDENCE_ASSESS_STATUS_HOSTED_ONLY,
    })
    envelope = build_envelope(
        code=RELAY_CLI_HOSTED_ONLY,
        http_status=501,
        message=(
            "evidence assessment worker is hosted-only; OSS sidecar does "
            "not enqueue or write assessments. Bundle was verified to "
            "exist locally but no assessment_id was issued. Point at "
            "hosted Relay (relay.epochly.com) to complete the assessment."
        ),
        blocked_surface="rly evidence assess",
        retry_advice="do_not_retry",
        details={
            "bundle_id": bundle,
            "readiness_profile": readiness_profile,
            "bundle_path": str(bundle_path),
        },
    )
    emit_envelope(envelope)
    raise typer.Exit(code=EXIT_4XX_BLOCK)


__all__ = [
    "DEFAULT_LIST_LIMIT",
    "DEFAULT_TRUST_ANCHOR_URL",
    "EVIDENCE_ASSESS_SCHEMA",
    "EVIDENCE_LIST_SCHEMA",
    "EVIDENCE_SHOW_SCHEMA",
    "EVIDENCE_VERIFY_SCHEMA",
    "MAX_LIST_LIMIT",
    "RELAY_CLI_EVIDENCE_ASSESS_STATUS_HOSTED_ONLY",
    "RELAY_CLI_EVIDENCE_BUNDLE_INVALID",
    "RELAY_CLI_EVIDENCE_BUNDLE_NOT_FOUND",
    "RELAY_CLI_EVIDENCE_NO_JWKS_CACHE",
    "RELAY_CLI_HOSTED_ONLY",
    "RELAY_CLI_TRUST_ANCHOR_OVERRIDE",
    "RELAY_EVID_014",
    "REQUIRED_LIST_BINDING_FIELDS",
    "REQUIRED_SHOW_FIELDS",
    "VERIFIER_RESULT_SCHEMA",
    "_cmd_evidence_assess",
    "_cmd_evidence_list",
    "_cmd_evidence_show",
    "_cmd_evidence_verify",
]
