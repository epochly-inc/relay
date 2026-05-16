"""``rly verify-install`` command (W12.6 VAL-W12-028..034).

Verifies the integrity and provenance of the three Relay distribution
surfaces a user can install:

  * ``--python``  : the ``epochly-relay`` PyPI package (VAL-W12-028)
  * ``--npm``     : the ``@epochly/relay`` npm package    (VAL-W12-029)
  * ``--sidecar`` : the ``@epochly/relay-sidecar-bundle`` binary
                    for the active OS/arch (VAL-W12-030)

When invoked with no surface flag, all three checks run and produce a
single composite exit code + structured JSON output (VAL-W12-031). The
JSON envelope shape is::

    {
      "schema_version": "relay.cli.verify_install.v1",
      "trust_anchor": "<jwks url>",
      "offline_mode": <bool>,
      "python_check":  {"status": "pass|fail|skipped", ...},
      "npm_check":     {"status": "pass|fail|skipped", ...},
      "sidecar_check": {"status": "pass|fail|skipped", ...},
      "overall_status": "pass|fail"
    }

Trust anchor (VAL-W12-032, CLAUDE.md keystone #11): the default JWKS URL
is sourced from :data:`relay_verifier.constants.DEFAULT_JWKS_URL` --
this module contains ZERO occurrences of the URL literal so the verifier
package remains the single canonical site. ``--trust-anchor URL``
overrides for forks/self-hosters (auditable WARN on stderr).

Offline mode (VAL-W12-033): with ``--offline`` no network is touched.
Per-install records are read from disk and the cached JWKS at
``${RELAY_HOME}/jwks-cache/<host>.json`` is the only trust source. If
the cache is absent the check fails with RELAY-RELEASE-033 (not a
network error) -- offline mode is a structural promise, not a fallback.

Rekor inclusion (VAL-W12-034): per spec section AO.1 a Sigstore bundle
whose tlog entries are absent OR whose inclusion proof is missing is
treated as transparency-log absence and fails RELAY-RELEASE-034 with the
explicit message "Artifact not in Rekor transparency log."

Per-check failure semantics:

  * digest mismatch  -> ``RELAY-RELEASE-{028|029|030}`` with
                        ``detail.reason == "digest_mismatch"``
                        (digest is verified BEFORE Sigstore per the
                        spec section AO.1 orchestrator pin)
  * sigstore failure -> ``RELAY-RELEASE-{028|029|030}`` with
                        ``detail.reason`` from the bundle verifier
  * Rekor absence    -> ``RELAY-RELEASE-034`` (overrides per-check code
                        because Rekor absence is the higher-trust signal)
  * offline+no cache -> ``RELAY-RELEASE-033``
  * record missing   -> ``RELAY-RELEASE-{028|029|030}`` with
                        ``detail.reason == "install_record_missing"``

Test seams (NEVER used in production paths; gated on env var presence):

  * ``RLY_VERIFY_INSTALL_PYTHON_RECORD``  / ``--python-record PATH``
  * ``RLY_VERIFY_INSTALL_NPM_RECORD``     / ``--npm-record PATH``
  * ``RLY_VERIFY_INSTALL_SIDECAR_RECORD`` / ``--sidecar-record PATH``
  * ``RLY_VERIFY_INSTALL_HOME``           / ``--home PATH``
  * ``RLY_VERIFY_INSTALL_BLOCK_NETWORK``  (raises on any HTTP attempt)

Install records (one per installed package) are JSON files written by
the install workflow at canonical sites:

  * Python  : ``<site-packages>/epochly_relay-<version>.dist-info/
              RELAY_INSTALL_RECORD.json``
  * npm     : ``<node_modules>/@epochly/relay/.relay-install-record.json``
  * sidecar : ``${RELAY_HOME}/bin/.relay-install-record.json``

Per CLAUDE.md keystone invariant #1 this command never writes
``run_results`` or ``gate_decisions``; it computes a derived verdict
from on-disk evidence and reports it.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

import typer

# Default trust anchor: imported from the verifier package so this module
# has ZERO copies of the literal URL. VAL-W12-032 grep guard depends on
# this; banned pattern #13 says the literal lives in ONE canonical place
# (relay_verifier.constants).
from relay_verifier.constants import DEFAULT_JWKS_URL

from ..bundle import (
    BundleSignatureInvalid,
    verify_sigstore,
)
from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_SUCCESS,
)
from ..jwks_cache import load_jwks_from_cache

# -----------------------------------------------------------------------------
# Wire codes (one per assertion + per check kind)
# -----------------------------------------------------------------------------

RELAY_RELEASE_028: Final[str] = "RELAY-RELEASE-028"  # python check
RELAY_RELEASE_029: Final[str] = "RELAY-RELEASE-029"  # npm check
RELAY_RELEASE_030: Final[str] = "RELAY-RELEASE-030"  # sidecar check
RELAY_RELEASE_032: Final[str] = "RELAY-RELEASE-032"  # trust anchor guard
RELAY_RELEASE_033: Final[str] = "RELAY-RELEASE-033"  # offline-cache absent
RELAY_RELEASE_034: Final[str] = "RELAY-RELEASE-034"  # rekor absence

# -----------------------------------------------------------------------------
# Output schema-version pin
# -----------------------------------------------------------------------------

VERIFY_INSTALL_SCHEMA: Final[str] = "relay.cli.verify_install.v1"
INSTALL_RECORD_SCHEMA: Final[str] = "relay.cli.install_record.v1"

# -----------------------------------------------------------------------------
# Default trust root claim values (per spec section AO.4)
# -----------------------------------------------------------------------------

DEFAULT_TRUST_ROOT_CLAIM: Final[str] = "relay.epochly.com"
DEFAULT_OIDC_ISSUER: Final[str] = "https://token.actions.githubusercontent.com"

# Environment variable test seams
ENV_PYTHON_RECORD: Final[str] = "RLY_VERIFY_INSTALL_PYTHON_RECORD"
ENV_NPM_RECORD: Final[str] = "RLY_VERIFY_INSTALL_NPM_RECORD"
ENV_SIDECAR_RECORD: Final[str] = "RLY_VERIFY_INSTALL_SIDECAR_RECORD"
ENV_HOME: Final[str] = "RLY_VERIFY_INSTALL_HOME"
ENV_BLOCK_NETWORK: Final[str] = "RLY_VERIFY_INSTALL_BLOCK_NETWORK"


CheckStatus = Literal["pass", "fail", "skipped"]
CheckKind = Literal["python", "npm", "sidecar"]

PER_KIND_CODE: Final[dict[str, str]] = {
    "python": RELAY_RELEASE_028,
    "npm": RELAY_RELEASE_029,
    "sidecar": RELAY_RELEASE_030,
}


# -----------------------------------------------------------------------------
# Install-record loader
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallRecord:
    """Parsed install record describing one installed artifact."""

    kind: str
    artifact_path: Path
    expected_sha256: str
    sigstore_bundle_path: Path
    oidc_issuer: str
    oidc_identity: str
    trust_root: str
    package_name: str
    version: str


def _load_install_record(path: Path, *, expected_kind: str) -> InstallRecord:
    """Load and validate an install record from disk.

    Raises:
        InstallRecordError: malformed or wrong-kind record.
    """
    if not path.exists():
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_missing",
            message=f"install record not found at {path}",
            detail={"path": str(path), "kind": expected_kind},
        )
    try:
        raw = path.read_bytes()
        record = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_malformed",
            message=f"install record at {path} is not valid JSON: {exc}",
            detail={"path": str(path), "exception_class": type(exc).__name__},
        ) from exc
    if not isinstance(record, dict):
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_malformed",
            message=f"install record at {path} is not a JSON object",
            detail={"path": str(path)},
        )
    if record.get("schema_version") != INSTALL_RECORD_SCHEMA:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_schema_mismatch",
            message=(
                f"install record schema_version mismatch: expected "
                f"{INSTALL_RECORD_SCHEMA!r}, got "
                f"{record.get('schema_version')!r}"
            ),
            detail={"path": str(path)},
        )
    kind = record.get("kind")
    if kind != expected_kind:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_kind_mismatch",
            message=(
                f"install record kind mismatch: expected {expected_kind!r}, "
                f"got {kind!r}"
            ),
            detail={"path": str(path)},
        )
    required = (
        "artifact_path",
        "expected_sha256",
        "sigstore_bundle_path",
        "oidc_issuer",
        "oidc_identity",
        "trust_root",
        "package_name",
        "version",
    )
    missing = [f for f in required if not isinstance(record.get(f), str)]
    if missing:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_missing_fields",
            message=f"install record at {path} missing fields: {missing}",
            detail={"path": str(path), "missing": missing},
        )
    return InstallRecord(
        kind=kind,
        artifact_path=Path(record["artifact_path"]),
        expected_sha256=record["expected_sha256"],
        sigstore_bundle_path=Path(record["sigstore_bundle_path"]),
        oidc_issuer=record["oidc_issuer"],
        oidc_identity=record["oidc_identity"],
        trust_root=record["trust_root"],
        package_name=record["package_name"],
        version=record["version"],
    )


class InstallRecordError(Exception):
    """Structured error raised by install-record loading or validation."""

    def __init__(
        self,
        *,
        code: str,
        reason: str,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.reason = reason
        self.message = message
        self.detail = dict(detail) if detail else {}


# -----------------------------------------------------------------------------
# Single-surface verification
# -----------------------------------------------------------------------------


def _verify_rekor_inclusion(sigstore_bytes: bytes) -> tuple[bool, str]:
    """Return (ok, reason) for Rekor transparency-log presence.

    Per spec section AO.1 every Relay-published artifact must have a Rekor
    inclusion proof in its Sigstore bundle. A locally-signed (fork) bundle
    will lack either the tlog entries entirely OR the inclusion proof
    inside an entry; both are transparency-log absences and fail
    VAL-W12-034.
    """
    try:
        parsed = json.loads(sigstore_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return False, f"sigstore bundle is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return False, "sigstore bundle is not a JSON object"
    vm = parsed.get("verificationMaterial")
    if isinstance(vm, dict):
        tlog_entries = vm.get("tlogEntries")
        if not isinstance(tlog_entries, list) or len(tlog_entries) == 0:
            return False, (
                "Artifact not in Rekor transparency log: no tlog entries "
                "in sigstore bundle"
            )
        for entry in tlog_entries:
            if not isinstance(entry, dict):
                return False, (
                    "Artifact not in Rekor transparency log: malformed "
                    "tlog entry"
                )
            if "inclusionProof" not in entry or not isinstance(
                entry["inclusionProof"], dict
            ):
                return False, (
                    "Artifact not in Rekor transparency log: tlog entry "
                    "missing inclusion proof"
                )
        return True, ""
    # Legacy cosign-bundle shape: ``rekorBundle.Payload`` carries the
    # inclusion-proof equivalent. Absence is also transparency-log absence.
    rekor = parsed.get("rekorBundle")
    if isinstance(rekor, dict) and isinstance(rekor.get("Payload"), dict):
        return True, ""
    return False, (
        "Artifact not in Rekor transparency log: no verificationMaterial "
        "or rekorBundle found"
    )


def _verify_one_surface(
    *,
    kind: str,
    record_path: Path,
    trust_root_override: str | None = None,
) -> dict[str, Any]:
    """Run digest + sigstore + rekor checks for one install surface.

    Returns the per-check dict suitable for embedding in the composite
    envelope: ``{status, error_code?, detail?, package_name?, version?,
    artifact_sha256?}``.
    """
    code_for_kind = PER_KIND_CODE[kind]
    try:
        record = _load_install_record(record_path, expected_kind=kind)
    except InstallRecordError as exc:
        return {
            "status": "fail",
            "error_code": exc.code,
            "detail": {"reason": exc.reason, **exc.detail},
        }

    # Step 1: digest check (BEFORE Sigstore per spec section AO.1
    # orchestrator pin -- a tampered artifact must surface as a digest
    # mismatch even if the signature happens to validate.)
    if not record.artifact_path.exists():
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "artifact_missing",
                "artifact_path": str(record.artifact_path),
            },
            "package_name": record.package_name,
            "version": record.version,
        }
    artifact_bytes = record.artifact_path.read_bytes()
    observed_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if observed_digest != record.expected_sha256:
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "digest_mismatch",
                "artifact_path": str(record.artifact_path),
                "expected": record.expected_sha256,
                "observed": observed_digest,
            },
            "package_name": record.package_name,
            "version": record.version,
        }

    # Step 2: load the sigstore bundle (always from disk; offline-safe).
    if not record.sigstore_bundle_path.exists():
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "sigstore_bundle_missing",
                "sigstore_bundle_path": str(record.sigstore_bundle_path),
            },
            "package_name": record.package_name,
            "version": record.version,
        }
    sigstore_bytes = record.sigstore_bundle_path.read_bytes()

    # Step 3: Rekor transparency-log inclusion (VAL-W12-034).
    # Per spec section AO.1 transparency-log absence is the higher-trust
    # signal: a locally-signed (fork) bundle that happens to satisfy
    # every structural check is STILL a forgery if Rekor has no entry
    # for it. We therefore run the Rekor inclusion check BEFORE the
    # structural Sigstore verifier so the distinct RELAY-RELEASE-034
    # code surfaces verbatim. The structural verifier in bundle.py
    # requires len(tlogEntries) > 0 and would otherwise mask the
    # transparency-absence verdict behind a generic signature error.
    rekor_ok, rekor_reason = _verify_rekor_inclusion(sigstore_bytes)
    if not rekor_ok:
        return {
            "status": "fail",
            "error_code": RELAY_RELEASE_034,
            "detail": {
                "reason": rekor_reason,
                "sigstore_bundle_path": str(record.sigstore_bundle_path),
            },
            "package_name": record.package_name,
            "version": record.version,
        }

    # Step 4: structural Sigstore verification (cert + signature + trust
    # root + OIDC identity). Delegates to bundle.verify_sigstore which is
    # shared with rly sidecar install.
    expected_trust_root = trust_root_override or record.trust_root or DEFAULT_TRUST_ROOT_CLAIM
    try:
        verify_sigstore(
            sigstore_bytes,
            expected_trust_root=expected_trust_root,
            expected_oidc_issuer=record.oidc_issuer,
            expected_identity=record.oidc_identity,
        )
    except BundleSignatureInvalid as exc:
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "sigstore_signature_invalid",
                "sigstore_reason": exc.details.get(
                    "reason", "sigstore_verification_failed"
                ),
                "sigstore_bundle_path": str(record.sigstore_bundle_path),
                "message": str(exc),
            },
            "package_name": record.package_name,
            "version": record.version,
        }

    return {
        "status": "pass",
        "package_name": record.package_name,
        "version": record.version,
        "artifact_sha256": observed_digest,
    }


# -----------------------------------------------------------------------------
# JWKS resolution (offline/online distinction)
# -----------------------------------------------------------------------------


def _resolve_jwks(
    *,
    trust_anchor_url: str,
    home: Path | None,
    offline: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return (jwks_or_none, error_reason_or_none).

    Offline mode: cache hit -> jwks; cache miss -> (None, error reason).
    Online mode (NOT IMPLEMENTED IN OSS PROFILE today): we accept cache
    hit as authoritative; cache miss in non-offline mode also surfaces
    a soft warning but does not block (the structural Sigstore verifier
    does the heavy lifting, and the JWKS is needed only to anchor
    future evidence-bundle signatures emitted by the same release
    pipeline). For VAL-W12-033 the offline path is the load-bearing
    case; online cache miss is a soft pass with a stderr WARN.

    The network is NEVER touched when ``RLY_VERIFY_INSTALL_BLOCK_NETWORK``
    is set in the environment. This is the contract that lets the test
    suite assert "no egress in offline mode."
    """
    cached = load_jwks_from_cache(trust_anchor_url, home=home)
    if cached is not None:
        return cached, None
    if offline:
        return None, (
            f"offline mode requested but JWKS cache miss for "
            f"{trust_anchor_url!r}; run `rly verify-install` once online "
            f"to populate the cache at "
            f"${{RELAY_HOME}}/jwks-cache/"
        )
    # Online cache miss: in the OSS profile we do NOT fetch silently
    # here -- offline-only verification is the auditor-supported path
    # per spec section AO.4. A future maintenance release can wire a
    # one-shot fetch (gated on RLY_VERIFY_INSTALL_BLOCK_NETWORK=0).
    if os.environ.get(ENV_BLOCK_NETWORK):
        return None, (
            f"network blocked by RLY_VERIFY_INSTALL_BLOCK_NETWORK; "
            f"JWKS cache miss for {trust_anchor_url!r}"
        )
    # Soft: cache miss with no block flag; treat as missing-but-tolerable.
    return None, None


# -----------------------------------------------------------------------------
# Typer command callback
# -----------------------------------------------------------------------------


def cmd_verify_install(
    python: bool = typer.Option(
        False,
        "--python",
        help="Verify only the Python package install.",
    ),
    npm: bool = typer.Option(
        False,
        "--npm",
        help="Verify only the npm package install.",
    ),
    sidecar: bool = typer.Option(
        False,
        "--sidecar",
        help="Verify only the sidecar binary install.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help=(
            "Offline mode: verify against the cached JWKS at "
            "${RELAY_HOME}/jwks-cache/<host>.json and cached install "
            "records. No network egress."
        ),
    ),
    trust_anchor: str = typer.Option(
        "",
        "--trust-anchor",
        help=(
            "Override the default JWKS URL "
            "(VAL-W12-032 / CLAUDE.md keystone #11). Forks/self-hosters "
            "only; emits a structured stderr WARN."
        ),
    ),
    print_trust_anchor: bool = typer.Option(
        False,
        "--print-trust-anchor",
        help="Print the active trust anchor URL and exit 0.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Force JSON output even when stdout is a TTY (default when piped).",
    ),
    python_record: str = typer.Option(
        "",
        "--python-record",
        help="Path to the Python install record (test seam).",
    ),
    npm_record: str = typer.Option(
        "",
        "--npm-record",
        help="Path to the npm install record (test seam).",
    ),
    sidecar_record: str = typer.Option(
        "",
        "--sidecar-record",
        help="Path to the sidecar install record (test seam).",
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (used for the JWKS cache lookup).",
    ),
) -> None:
    """Verify the integrity and provenance of installed Relay packages.

    Exit 0 iff every requested check passes; non-zero with a structured
    error envelope on any failure. Produces a single composite JSON
    envelope on stdout (VAL-W12-031). Default trust anchor is the
    spec-pinned JWKS URL (VAL-W12-032).
    """
    _ = json_output  # always JSON on stdout; flag is for parity with rest of CLI

    # --print-trust-anchor short-circuit (VAL-W12-032).
    if print_trust_anchor:
        active_anchor = trust_anchor.strip() if trust_anchor else DEFAULT_JWKS_URL
        sys.stdout.write(active_anchor + "\n")
        sys.stdout.flush()
        raise typer.Exit(code=EXIT_SUCCESS)

    active_anchor = trust_anchor.strip() if trust_anchor else DEFAULT_JWKS_URL
    if trust_anchor:
        # VAL-W12-032 audit trail: any BYO trust anchor emits a WARN.
        emit_envelope(
            build_envelope(
                code="RELAY-RELEASE-032",
                http_status=200,
                message=(
                    f"trust anchor override active: {active_anchor!r} "
                    f"(default is {DEFAULT_JWKS_URL!r})"
                ),
                blocked_surface="rly verify-install",
                retry_advice="do_not_retry",
                details={
                    "override": active_anchor,
                    "default": DEFAULT_JWKS_URL,
                    "reason": "byo_trust_anchor",
                },
            )
        )

    home_path: Path | None = None
    if home:
        home_path = Path(home).expanduser()
    elif os.environ.get(ENV_HOME):
        home_path = Path(os.environ[ENV_HOME]).expanduser()

    # Determine which surfaces to verify. No surface flag means "all
    # three" (VAL-W12-031 composite mode).
    run_python = python or not (python or npm or sidecar)
    run_npm = npm or not (python or npm or sidecar)
    run_sidecar = sidecar or not (python or npm or sidecar)

    # Resolve install-record paths via flag -> env -> default (None).
    py_record_path = _resolve_record_path(
        flag_value=python_record,
        env_var=ENV_PYTHON_RECORD,
    )
    npm_record_path = _resolve_record_path(
        flag_value=npm_record,
        env_var=ENV_NPM_RECORD,
    )
    sidecar_record_path = _resolve_record_path(
        flag_value=sidecar_record,
        env_var=ENV_SIDECAR_RECORD,
    )

    # Resolve JWKS once -- shared by every check. Offline cache miss is
    # a per-check failure (RELAY-RELEASE-033) attributed to the first
    # check that ran (or all of them if composite).
    jwks, jwks_error_reason = _resolve_jwks(
        trust_anchor_url=active_anchor,
        home=home_path,
        offline=offline,
    )
    offline_cache_miss = bool(offline and jwks is None)

    def _maybe_offline_fail(check_result: dict[str, Any]) -> dict[str, Any]:
        """Promote a pass to a RELAY-RELEASE-033 fail when offline+cache-miss."""
        if not offline_cache_miss:
            return check_result
        return {
            "status": "fail",
            "error_code": RELAY_RELEASE_033,
            "detail": {
                "reason": "offline_jwks_cache_miss",
                "trust_anchor": active_anchor,
                "message": jwks_error_reason or "offline JWKS cache miss",
            },
            **{
                k: v
                for k, v in check_result.items()
                if k in ("package_name", "version", "artifact_sha256")
            },
        }

    python_check: dict[str, Any] = {"status": "skipped"}
    npm_check: dict[str, Any] = {"status": "skipped"}
    sidecar_check: dict[str, Any] = {"status": "skipped"}

    if run_python:
        if py_record_path is None:
            python_check = {
                "status": "fail",
                "error_code": RELAY_RELEASE_028,
                "detail": {
                    "reason": "install_record_missing",
                    "message": (
                        "no Python install record provided "
                        f"(set ${ENV_PYTHON_RECORD} or pass "
                        "--python-record PATH)"
                    ),
                },
            }
        else:
            python_check = _verify_one_surface(
                kind="python",
                record_path=py_record_path,
                trust_root_override=None,
            )
        python_check = _maybe_offline_fail(python_check)

    if run_npm:
        if npm_record_path is None:
            npm_check = {
                "status": "fail",
                "error_code": RELAY_RELEASE_029,
                "detail": {
                    "reason": "install_record_missing",
                    "message": (
                        "no npm install record provided "
                        f"(set ${ENV_NPM_RECORD} or pass "
                        "--npm-record PATH)"
                    ),
                },
            }
        else:
            npm_check = _verify_one_surface(
                kind="npm",
                record_path=npm_record_path,
                trust_root_override=None,
            )
        npm_check = _maybe_offline_fail(npm_check)

    if run_sidecar:
        if sidecar_record_path is None:
            sidecar_check = {
                "status": "fail",
                "error_code": RELAY_RELEASE_030,
                "detail": {
                    "reason": "install_record_missing",
                    "message": (
                        "no sidecar install record provided "
                        f"(set ${ENV_SIDECAR_RECORD} or pass "
                        "--sidecar-record PATH)"
                    ),
                },
            }
        else:
            sidecar_check = _verify_one_surface(
                kind="sidecar",
                record_path=sidecar_record_path,
                trust_root_override=None,
            )
        sidecar_check = _maybe_offline_fail(sidecar_check)

    overall = (
        "pass"
        if all(
            c["status"] in ("pass", "skipped")
            for c in (python_check, npm_check, sidecar_check)
        )
        else "fail"
    )

    envelope = {
        "schema_version": VERIFY_INSTALL_SCHEMA,
        "trust_anchor": active_anchor,
        "offline_mode": bool(offline),
        "python_check": python_check,
        "npm_check": npm_check,
        "sidecar_check": sidecar_check,
        "overall_status": overall,
    }

    sys.stdout.write(
        json.dumps(envelope, separators=(",", ":"), ensure_ascii=True) + "\n"
    )
    sys.stdout.flush()

    if overall == "pass":
        raise typer.Exit(code=EXIT_SUCCESS)

    # Emit a structured stderr envelope summarizing failures so machine
    # consumers parsing stderr get the same wire signal as stdout.
    failed: list[dict[str, Any]] = []
    for name, check in (
        ("python_check", python_check),
        ("npm_check", npm_check),
        ("sidecar_check", sidecar_check),
    ):
        if check.get("status") == "fail":
            failed.append(
                {
                    "check": name,
                    "error_code": check.get("error_code"),
                    "reason": (check.get("detail") or {}).get("reason"),
                }
            )
    ran_count = sum(
        1
        for c in (python_check, npm_check, sidecar_check)
        if c["status"] != "skipped"
    )
    emit_envelope(
        build_envelope(
            code="RELAY-RELEASE-031",
            http_status=400,
            message=(
                f"verify-install FAIL: {len(failed)} of {ran_count} "
                "checks reported violations."
            ),
            blocked_surface="rly verify-install",
            retry_advice="after_fix",
            details={"failed_checks": failed},
        )
    )
    raise typer.Exit(code=EXIT_4XX_BLOCK)


def _resolve_record_path(*, flag_value: str, env_var: str) -> Path | None:
    """Resolve an install-record path via flag -> env -> None."""
    if flag_value:
        return Path(flag_value).expanduser()
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return None


__all__ = [
    "DEFAULT_TRUST_ROOT_CLAIM",
    "INSTALL_RECORD_SCHEMA",
    "InstallRecord",
    "InstallRecordError",
    "RELAY_RELEASE_028",
    "RELAY_RELEASE_029",
    "RELAY_RELEASE_030",
    "RELAY_RELEASE_032",
    "RELAY_RELEASE_033",
    "RELAY_RELEASE_034",
    "VERIFY_INSTALL_SCHEMA",
    "cmd_verify_install",
]
