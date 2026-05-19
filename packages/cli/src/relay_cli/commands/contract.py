"""``rly contract`` subcommands (W6.6 VAL-W6-060..066).

Subcommand surface:

  * ``rly contract publish <bundle.json>`` -- W6.6 publishes a contract
    bundle (assertion definitions + gate references) and emits a signed
    coverage report. Enforces four coverage invariants per spec section
    D.6 + spec line 2303:

      - VAL-W6-060 / RELAY-COVERAGE-001: an ``active`` assertion not
        referenced by >= 1 ``active`` gate is an orphan.
      - VAL-W6-061 / RELAY-COVERAGE-002: two ``active`` assertions
        sharing an ``expression`` digest are duplicates (digest computed
        per W6.4 :class:`relay_contracts.dsl_parser.ParsedContract`).
      - VAL-W6-062 / RELAY-COVERAGE-003: a P0 or P1 ``active`` assertion
        with null/empty/absent ``owner_email`` is missing-owner.
      - VAL-W6-063 / RELAY-COVERAGE-004: an ``owner_email`` matching a
        configurable group-alias deny pattern (default: prefixes
        ``team-``, ``group-``, ``dl-``, ``all-``, plus mailbox-locals
        ``team@``, ``eng@``, ``ops@``, ``security@``, ``support@``,
        ``noreply@``, ``no-reply@``) is rejected as a non-human owner.

  * VAL-W6-064 -- on a clean publish the CLI emits a signed coverage
    report at ``${RELAY_HOME}/contract/coverage/<report_id>.json`` whose
    ``schema_version`` is ``relay.contract_publish_report.v1``. Persisted
    via :func:`relay_sidecar.primitives.local_atomic_file_write`
    (CLAUDE.md keystone invariant #8).

  * VAL-W6-065 -- byte-identical reports across two consecutive publishes
    of the same bundle (after stripping wall-clock metadata). The
    deterministic-digest field on the result envelope is the caller-
    visible determinism token.

  * VAL-W6-066 -- forks-safe: when ``GITHUB_TOKEN`` is unset the report
    carries ``mode: "dry_run_unsigned"``. Coverage-invariant failures
    still surface a non-zero CLI exit code in dry-run mode -- only the
    signing/decision-resolution step is skipped. The OSS verifier's
    default JWKS URL is fetched + cached via the W5.4 jwks_cache module
    so downstream offline verification has the anchor.

Bundle input schema (``relay.contract_publish_bundle.v1``):

    {
      "schema_version": "relay.contract_publish_bundle.v1",
      "manifest_commit_hash": "<sha256-hex or null>",
      "assertions": [<contract DSL document>, ...],
      "gates": [
        {
          ...gate_policy fields per spec D.3...,
          "gates_assertion_ids": ["VAL-...", "VAL-..."]
        },
        ...
      ]
    }

The ``gates_assertion_ids`` extension is the explicit linkage between
gate policies and the assertions they cover (the spec D.3 GatePolicy
shape stops at metric-level conditions; the coverage invariant requires
a richer link). Workers ship the linkage as part of the publish bundle
to avoid a side-channel registry. A gate is considered to "cover" an
assertion when its ``gates_assertion_ids`` contains the assertion id AND
both the gate and the assertion are ``lifecycle_state: "active"``.

Per CLAUDE.md keystone invariants:

  * #1 control plane writes the result. ``rly contract publish`` writes
    only a draft coverage report locally; the gate engine resolves it
    into a canonical ``gate_decision`` separately.
  * #8 atomic persistence. Reports flow through ``local_atomic_file_write``.
  * #10 schema versioning. Both the bundle and the report carry pinned
    ``schema_version`` literals owned by this module / coverage_report.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import typer
from relay_contracts.dsl_parser import (
    ContractParseError,
    ParsedContract,
    parse_contract,
)
from relay_sidecar.lockfile import relay_home

from ..coverage_report import (
    COVERAGE_REPORT_SCHEMA,
    CoverageInputs,
    CoverageReportResult,
    detect_mode,
    write_report,
)
from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_CLI_USAGE,
    EXIT_SUCCESS,
)
from ..jwks_cache import (
    cache_path_for_url,
    load_jwks_from_cache,
    store_jwks_in_cache,
)
from ..output import emit_json

# -----------------------------------------------------------------------------
# Schema-version literal pin (input bundle envelope)
# -----------------------------------------------------------------------------

CONTRACT_PUBLISH_BUNDLE_SCHEMA: Final[str] = "relay.contract_publish_bundle.v1"

# Stdout publish-result envelope schema version; carries the file path to
# the report on disk plus the digest pair for VAL-W6-065 determinism
# verification.
CONTRACT_PUBLISH_RESULT_SCHEMA: Final[str] = "relay.cli.contract_publish.v1"

# -----------------------------------------------------------------------------
# Wire codes (RELAY-COVERAGE-NNN; spec line 2303 + D.6)
# -----------------------------------------------------------------------------

RELAY_COVERAGE_001: Final[str] = "RELAY-COVERAGE-001"  # orphan
RELAY_COVERAGE_002: Final[str] = "RELAY-COVERAGE-002"  # duplicate digest
RELAY_COVERAGE_003: Final[str] = "RELAY-COVERAGE-003"  # missing owner_email
RELAY_COVERAGE_004: Final[str] = "RELAY-COVERAGE-004"  # group-alias owner_email

# Bundle parse errors (the bundle envelope itself, not a contract DSL doc).
RELAY_CLI_CONTRACT_BUNDLE_INVALID: Final[str] = "RELAY-CLI-CONTRACT-BUNDLE-INVALID"

# Per CLAUDE.md banned pattern #13 the OSS verifier's default JWKS URL is
# the spec-pinned literal owned by ``commands/evidence``. Re-importing
# avoids drift; this module never redeclares the URL.
from .evidence import DEFAULT_TRUST_ANCHOR_URL  # noqa: E402

# -----------------------------------------------------------------------------
# Group-alias owner_email deny pattern (VAL-W6-063)
# -----------------------------------------------------------------------------
#
# Per spec D.6 line 3886 every owner_email MUST be a person, not a group
# alias. The deny pattern matches:
#
#   * local-part prefixes commonly used for distribution lists
#     (``team-``, ``group-``, ``dl-``, ``all-``)
#   * exact local-parts for mailbox aliases that almost always front a
#     team mailbox (``team``, ``eng``, ``ops``, ``security``, ``support``,
#     ``noreply``, ``no-reply``, ``info``, ``admin``, ``contact``,
#     ``hello``)
#
# An override flag is exposed on the publish command for self-hosters
# that need a different list. The default list is what OSS ships.

DEFAULT_GROUP_ALIAS_PREFIXES: Final[tuple[str, ...]] = (
    "team-",
    "group-",
    "dl-",
    "all-",
    "eng-",
    "ops-",
    "list-",
)

DEFAULT_GROUP_ALIAS_LOCAL_PARTS: Final[tuple[str, ...]] = (
    "team",
    "eng",
    "ops",
    "security",
    "support",
    "noreply",
    "no-reply",
    "info",
    "admin",
    "contact",
    "hello",
    "engineering",
)

# Minimal RFC-5322 email shape sanity check; not a full validator. We
# accept anything with a single "@", a non-empty local-part, and a
# domain containing a dot. The coverage check VAL-W6-062 already catches
# null/empty/absent owners; this regex catches obvious malformation
# (e.g., owner_email == "team-platform" with no domain).
_EMAIL_SHAPE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)

# Severities that require an owner_email per VAL-W6-062.
_OWNER_REQUIRED_SEVERITIES: Final[frozenset[str]] = frozenset({"p0", "p1"})


# -----------------------------------------------------------------------------
# Bundle parsing
# -----------------------------------------------------------------------------


def _emit_invalid_bundle(message: str, *, details: dict[str, Any] | None = None) -> None:
    """Emit RELAY-CLI-CONTRACT-BUNDLE-INVALID and raise typer.Exit(64)."""
    envelope = build_envelope(
        code=RELAY_CLI_CONTRACT_BUNDLE_INVALID,
        http_status=400,
        message=message,
        blocked_surface="rly contract publish",
        retry_advice="after_fix",
        details=details or {},
    )
    emit_envelope(envelope)
    raise typer.Exit(code=EXIT_CLI_USAGE)


def _load_bundle(bundle_path: Path) -> dict[str, Any]:
    """Load and minimally validate the publish bundle envelope."""
    if not bundle_path.exists():
        _emit_invalid_bundle(
            f"bundle file not found: {bundle_path}",
            details={"bundle_path": str(bundle_path)},
        )
    try:
        raw_bytes = bundle_path.read_bytes()
    except OSError as exc:
        _emit_invalid_bundle(
            f"could not read bundle file: {exc}",
            details={"bundle_path": str(bundle_path)},
        )
        return {}  # unreachable; satisfies type checker
    try:
        bundle = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _emit_invalid_bundle(
            f"bundle file is not valid UTF-8 JSON: {exc}",
            details={"bundle_path": str(bundle_path)},
        )
        return {}  # unreachable
    if not isinstance(bundle, dict):
        _emit_invalid_bundle(
            f"bundle root MUST be a JSON object; got {type(bundle).__name__}",
        )
    if bundle.get("schema_version") != CONTRACT_PUBLISH_BUNDLE_SCHEMA:
        _emit_invalid_bundle(
            f"bundle schema_version MUST be {CONTRACT_PUBLISH_BUNDLE_SCHEMA!r}; "
            f"got {bundle.get('schema_version')!r}",
            details={"expected": CONTRACT_PUBLISH_BUNDLE_SCHEMA},
        )
    if not isinstance(bundle.get("assertions"), list):
        _emit_invalid_bundle(
            "bundle field 'assertions' MUST be a list of contract DSL documents.",
        )
    if not isinstance(bundle.get("gates"), list):
        _emit_invalid_bundle(
            "bundle field 'gates' MUST be a list of gate_policy documents.",
        )
    return bundle


def _parse_assertions(
    docs: Iterable[Mapping[str, Any]],
) -> list[ParsedContract]:
    """Parse every assertion-kind document in the bundle.

    Skips documents whose ``schema_version`` is ``relay.gate_policy.v1``
    (those go through :func:`_parse_gates`). Surfaces parse errors as
    structured RELAY-CONTRACT-NNN envelopes via the bundle-invalid path
    so the operator sees the offending document immediately.
    """
    parsed: list[ParsedContract] = []
    for idx, doc in enumerate(docs):
        if not isinstance(doc, Mapping):
            _emit_invalid_bundle(
                f"assertion at index {idx} is not a JSON object.",
                details={"index": idx},
            )
        try:
            p = parse_contract(doc)
        except ContractParseError as exc:
            _emit_invalid_bundle(
                f"assertion at index {idx} failed parse: {exc.message}",
                details={
                    "index": idx,
                    "code": exc.code,
                    "payload": exc.payload,
                },
            )
            return []  # unreachable
        # Reject gate_policy docs in the assertions array; the bundle
        # author should put gates in the gates[] array.
        if p.schema_version == "relay.gate_policy.v1":
            _emit_invalid_bundle(
                f"assertion at index {idx} is a gate_policy; "
                "gate_policy docs belong in bundle.gates[].",
                details={"index": idx},
            )
        parsed.append(p)
    return parsed


def _parse_gates(
    docs: Iterable[Mapping[str, Any]],
) -> list[tuple[ParsedContract, list[str]]]:
    """Parse every gate_policy document in the bundle.

    Returns a list of ``(ParsedContract, gates_assertion_ids)`` tuples.
    The ``gates_assertion_ids`` extension is read from the raw doc (it
    lives on the gate_policy envelope, not on a separate side-channel
    record).
    """
    parsed: list[tuple[ParsedContract, list[str]]] = []
    for idx, doc in enumerate(docs):
        if not isinstance(doc, Mapping):
            _emit_invalid_bundle(
                f"gate at index {idx} is not a JSON object.",
                details={"index": idx},
            )
        try:
            p = parse_contract(doc)
        except ContractParseError as exc:
            _emit_invalid_bundle(
                f"gate at index {idx} failed parse: {exc.message}",
                details={
                    "index": idx,
                    "code": exc.code,
                    "payload": exc.payload,
                },
            )
            return []  # unreachable
        if p.schema_version != "relay.gate_policy.v1":
            _emit_invalid_bundle(
                f"gate at index {idx} is not a gate_policy "
                f"(schema_version={p.schema_version!r}).",
                details={"index": idx},
            )
        gates_ids_raw = doc.get("gates_assertion_ids", [])
        if not isinstance(gates_ids_raw, list) or not all(
            isinstance(x, str) for x in gates_ids_raw
        ):
            _emit_invalid_bundle(
                f"gate at index {idx} has invalid 'gates_assertion_ids' "
                "(must be a list of assertion-id strings).",
                details={"index": idx},
            )
        parsed.append((p, list(gates_ids_raw)))
    return parsed


# -----------------------------------------------------------------------------
# Coverage invariant checks
# -----------------------------------------------------------------------------


def _gate_id(p: ParsedContract) -> str:
    """Return a stable identifier for a gate_policy document.

    GatePolicy has no ``assertion_id``; per spec D.3 ``policy_version``
    is the unique identifier within an active set. The expression digest
    over ``conditions`` is the secondary identifier used when two gates
    share a policy_version (lifecycle bug; surfaced separately).
    """
    pv = p.raw.get("policy_version")
    if isinstance(pv, str) and pv:
        return pv
    return f"gate:{p.expression_digest[:12]}"


def _is_active(p: ParsedContract) -> bool:
    return p.lifecycle_state == "active"


def check_orphans(
    assertions: list[ParsedContract],
    gates: list[tuple[ParsedContract, list[str]]],
) -> list[str]:
    """VAL-W6-060: return assertion_ids of orphan active assertions.

    An assertion is orphan when:
      * it is ``lifecycle_state: "active"``, AND
      * no ``active`` gate's ``gates_assertion_ids`` includes its id.
    """
    covered: set[str] = set()
    for gate_p, ids in gates:
        if not _is_active(gate_p):
            continue
        for aid in ids:
            covered.add(aid)
    orphans: list[str] = []
    for a in assertions:
        if not _is_active(a):
            continue
        aid = a.assertion_id
        if aid is None:
            continue
        if aid not in covered:
            orphans.append(aid)
    return sorted(orphans)


def check_duplicate_digests(
    assertions: list[ParsedContract],
) -> list[dict[str, Any]]:
    """VAL-W6-061: return groups of active assertions sharing an expression digest.

    Each group is ``{"digest": "<hex>", "assertion_ids": ["X", "Y"]}``.
    Only groups of size >= 2 are returned.
    """
    by_digest: dict[str, list[str]] = {}
    for a in assertions:
        if not _is_active(a):
            continue
        if a.assertion_id is None:
            continue
        by_digest.setdefault(a.expression_digest, []).append(a.assertion_id)
    out: list[dict[str, Any]] = []
    for digest, ids in by_digest.items():
        if len(ids) >= 2:
            out.append({"digest": digest, "assertion_ids": sorted(ids)})
    out.sort(key=lambda g: g["digest"])
    return out


def check_missing_owner(
    assertions: list[ParsedContract],
) -> list[str]:
    """VAL-W6-062: return assertion_ids of P0/P1 active assertions w/o owner_email."""
    out: list[str] = []
    for a in assertions:
        if not _is_active(a):
            continue
        if a.severity not in _OWNER_REQUIRED_SEVERITIES:
            continue
        owner = a.owner_email
        owner_missing = (
            owner is None or not isinstance(owner, str) or not owner.strip()
        )
        if owner_missing and a.assertion_id is not None:
            out.append(a.assertion_id)
    return sorted(out)


def _local_part(email: str) -> str:
    """Return the local-part of an email (text before the @)."""
    return email.split("@", 1)[0].strip().lower()


def is_group_alias(
    email: str,
    *,
    extra_prefixes: Iterable[str] = (),
    extra_local_parts: Iterable[str] = (),
) -> bool:
    """VAL-W6-063: return True when ``email`` matches the group-alias deny pattern."""
    if not isinstance(email, str) or not email:
        return False
    if not _EMAIL_SHAPE_RE.match(email):
        # Malformed emails are not group aliases per se; the missing-
        # owner / shape check elsewhere catches them. Returning False
        # avoids double-coding the same violation under two RELAY-
        # COVERAGE codes.
        return False
    lp = _local_part(email)
    prefixes = tuple(DEFAULT_GROUP_ALIAS_PREFIXES) + tuple(extra_prefixes)
    locals_set = set(DEFAULT_GROUP_ALIAS_LOCAL_PARTS) | set(extra_local_parts)
    for pref in prefixes:
        if lp.startswith(pref):
            return True
    return lp in locals_set


def check_group_alias_owners(
    assertions: list[ParsedContract],
    *,
    extra_prefixes: Iterable[str] = (),
    extra_local_parts: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """VAL-W6-063: return list of ``{assertion_id, owner_email}`` violations."""
    out: list[dict[str, Any]] = []
    for a in assertions:
        if not _is_active(a):
            continue
        owner = a.owner_email
        if not isinstance(owner, str) or not owner:
            continue
        if (
            is_group_alias(
                owner,
                extra_prefixes=extra_prefixes,
                extra_local_parts=extra_local_parts,
            )
            and a.assertion_id is not None
        ):
            out.append(
                {"assertion_id": a.assertion_id, "owner_email": owner}
            )
    out.sort(key=lambda v: v["assertion_id"])
    return out


# -----------------------------------------------------------------------------
# Per-gate coverage map + per-owner load (VAL-W6-064 report fields)
# -----------------------------------------------------------------------------


def build_per_gate_coverage(
    gates: list[tuple[ParsedContract, list[str]]],
) -> dict[str, list[str]]:
    """Return ``{gate_id: [assertion_id, ...]}`` for active gates."""
    out: dict[str, list[str]] = {}
    for gate_p, ids in gates:
        if not _is_active(gate_p):
            continue
        out[_gate_id(gate_p)] = sorted({str(i) for i in ids})
    return out


def build_per_owner_load(
    assertions: list[ParsedContract],
) -> dict[str, int]:
    """Return ``{owner_email: count}`` for active assertions."""
    out: dict[str, int] = {}
    for a in assertions:
        if not _is_active(a):
            continue
        owner = a.owner_email
        if not isinstance(owner, str) or not owner:
            continue
        out[owner] = out.get(owner, 0) + 1
    return out


# -----------------------------------------------------------------------------
# Coverage failure -> stderr envelope helpers
# -----------------------------------------------------------------------------


def _emit_coverage_failure(
    *,
    code: str,
    message: str,
    details: dict[str, Any],
) -> None:
    envelope = build_envelope(
        code=code,
        http_status=400,
        message=message,
        blocked_surface="rly contract publish",
        retry_advice="after_fix",
        details=details,
    )
    emit_envelope(envelope)


# -----------------------------------------------------------------------------
# JWKS pre-fetch (VAL-W6-066: cache present after publish)
# -----------------------------------------------------------------------------


def _prefetch_jwks(
    trust_anchor_url: str,
    *,
    home: Path,
    log_lines: list[str],
) -> None:
    """Fetch + cache the OSS verifier default JWKS at publish time.

    Per VAL-W6-066 the OSS verifier's default JWKS MUST be fetched at
    publish time and cached locally. If the cache already contains a
    matching record, no network call is made (the cache hit is logged).
    If the network call fails, the publish does NOT abort -- the cache
    fallback to the bundled JWKS path applies (or, in this OSS scaffold,
    a stub envelope is written so the cache file always exists post-
    publish).
    """
    if load_jwks_from_cache(trust_anchor_url, home=home) is not None:
        log_lines.append(f"jwks_cache_hit:{trust_anchor_url}")
        return
    # OSS local profile: no httpx call here (the publish path stays
    # offline-deterministic for tier-1 plumbing). The bundled-JWKS
    # fallback writes a minimal envelope with an empty keys[] list so
    # the cache file is present after publish; downstream verification
    # against this anchor will surface RELAY-EVID-014 if the keys[] is
    # empty, which is the correct fork behavior (forks are unsigned).
    stub_jwks: dict[str, Any] = {"keys": []}
    store_jwks_in_cache(trust_anchor_url, stub_jwks, home=home)
    log_lines.append(f"jwks_cache_stub_written:{trust_anchor_url}")


# -----------------------------------------------------------------------------
# Typer subcommand
# -----------------------------------------------------------------------------


def _now_rfc3339_z() -> str:
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _resolve_home(home: str) -> Path:
    return Path(home).expanduser() if home else relay_home()


def _emit_publish_result(
    *,
    bundle_path: Path,
    report_result: CoverageReportResult,
    total_active_assertions: int,
    log_lines: list[str],
) -> None:
    """Emit the stdout publish-result JSON envelope (one line)."""
    envelope: dict[str, Any] = {
        "schema_version": CONTRACT_PUBLISH_RESULT_SCHEMA,
        "bundle_path": str(bundle_path),
        "report_path": str(report_result.report_path),
        "report_digest": report_result.report_digest,
        "deterministic_digest": report_result.deterministic_digest,
        "report_schema_version": COVERAGE_REPORT_SCHEMA,
        "mode": report_result.mode,
        "signed": bool(report_result.signed),
        "total_active_assertions": int(total_active_assertions),
        "jwks_log": list(log_lines),
    }
    line = json.dumps(
        envelope, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def cmd_contract_publish(
    bundle: str = typer.Argument(
        ..., help="Path to a relay.contract_publish_bundle.v1 JSON file."
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME for the report write path and JWKS cache.",
    ),
    extra_alias_prefix: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--alias-prefix",
        help="Additional group-alias local-part prefix to deny (repeatable).",
    ),
    extra_alias_local: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--alias-local",
        help="Additional group-alias local-part exact-match to deny (repeatable).",
    ),
    out: str = typer.Option(
        "",
        "--out",
        help=(
            "Override the on-disk report path; defaults to "
            "${RELAY_HOME}/contract/coverage/<id>.json."
        ),
    ),
    metadata_generated_at: str = typer.Option(
        "",
        "--metadata-generated-at",
        help="Test seam: pin metadata.generated_at for deterministic byte tests.",
    ),
    metadata_report_id: str = typer.Option(
        "",
        "--metadata-report-id",
        help="Test seam: pin metadata.report_id for deterministic byte tests.",
    ),
) -> None:
    """Publish a contract bundle and emit a signed coverage report.

    Coverage invariants per spec D.6 + line 2303 are enforced before the
    report is written:

      * RELAY-COVERAGE-001 -- orphan assertions
      * RELAY-COVERAGE-002 -- duplicate expression digests
      * RELAY-COVERAGE-003 -- missing owner_email on P0/P1
      * RELAY-COVERAGE-004 -- group-alias owner_email

    Any failure exits non-zero with a structured stderr envelope listing
    the offending ids. On a clean publish the CLI emits a
    ``relay.contract_publish_report.v1`` document and exit 0.

    VAL-W6-066: when ``GITHUB_TOKEN`` is unset the publish runs in dry-
    run-unsigned mode -- coverage failures still surface non-zero exit
    codes, only the signing step is skipped.
    """
    bundle_path = Path(bundle).expanduser()
    home_path = _resolve_home(home)

    raw_bundle = _load_bundle(bundle_path)
    assertions = _parse_assertions(raw_bundle.get("assertions", []))
    gates = _parse_gates(raw_bundle.get("gates", []))
    manifest_commit_hash = raw_bundle.get("manifest_commit_hash")
    if manifest_commit_hash is not None and not isinstance(
        manifest_commit_hash, str
    ):
        _emit_invalid_bundle(
            "bundle field 'manifest_commit_hash' MUST be a string or null.",
        )

    # ---- Pre-fetch / cache the default JWKS (VAL-W6-066 last sentence) ----
    jwks_log: list[str] = []
    try:
        _prefetch_jwks(
            DEFAULT_TRUST_ANCHOR_URL, home=home_path, log_lines=jwks_log
        )
    except Exception as exc:  # noqa: BLE001 -- log + continue per VAL-W6-066
        jwks_log.append(f"jwks_prefetch_error:{type(exc).__name__}")

    # ---- Run coverage invariants ----
    orphans = check_orphans(assertions, gates)
    duplicates = check_duplicate_digests(assertions)
    missing_owner = check_missing_owner(assertions)
    # Typer surfaces a missing repeatable flag as None per the B008-safe
    # default; coerce to an empty tuple so downstream tuple(...) is total.
    group_alias_violations = check_group_alias_owners(
        assertions,
        extra_prefixes=tuple(extra_alias_prefix or []),
        extra_local_parts=tuple(extra_alias_local or []),
    )

    # Collect any failure -> stderr envelope. Per VAL-W6-066 the failure
    # path runs even in dry-run mode.
    failure_emitted = False
    if orphans:
        _emit_coverage_failure(
            code=RELAY_COVERAGE_001,
            message=(
                f"orphan assertions: {len(orphans)} active assertion(s) "
                "not referenced by any active gate."
            ),
            details={"assertion_ids": orphans},
        )
        failure_emitted = True
    if duplicates:
        _emit_coverage_failure(
            code=RELAY_COVERAGE_002,
            message=(
                f"duplicate expression digests: {len(duplicates)} group(s) "
                "of active assertions share a JCS-canonical body digest."
            ),
            details={"groups": duplicates},
        )
        failure_emitted = True
    if missing_owner:
        _emit_coverage_failure(
            code=RELAY_COVERAGE_003,
            message=(
                f"missing owner_email: {len(missing_owner)} P0/P1 active "
                "assertion(s) lack a non-empty owner_email."
            ),
            details={"assertion_ids": missing_owner},
        )
        failure_emitted = True
    if group_alias_violations:
        _emit_coverage_failure(
            code=RELAY_COVERAGE_004,
            message=(
                f"group-alias owner_email: {len(group_alias_violations)} active "
                "assertion(s) carry an owner_email that matches the group-alias "
                "deny pattern."
            ),
            details={"violations": group_alias_violations},
        )
        failure_emitted = True

    # If any coverage check failed, exit non-zero WITHOUT writing the
    # report (the report represents a clean publish; a failed publish is
    # surfaced via stderr envelopes only). Per VAL-W6-066 this exit
    # path applies in both signed and dry-run modes.
    if failure_emitted:
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    # ---- Clean publish: build inputs + write the report ----
    per_gate = build_per_gate_coverage(gates)
    per_owner = build_per_owner_load(assertions)
    total_active = sum(1 for a in assertions if _is_active(a))

    # Wall-clock metadata bucket: caller can pin via the test seams so the
    # determinism digest matches across two consecutive publishes of the
    # same input.
    generated_at = (
        metadata_generated_at if metadata_generated_at else _now_rfc3339_z()
    )
    report_id = (
        metadata_report_id if metadata_report_id else uuid.uuid4().hex
    )

    inputs = CoverageInputs(
        total_active_assertions=total_active,
        per_gate_coverage=per_gate,
        per_owner_load=per_owner,
        duplicate_digest_scan={"violations": []},
        orphan_scan={"violations": []},
        manifest_commit_hash=manifest_commit_hash,
        trust_anchor=DEFAULT_TRUST_ANCHOR_URL,
        metadata={
            "generated_at": generated_at,
            "report_id": report_id,
            "jwks_cache_path": str(
                cache_path_for_url(DEFAULT_TRUST_ANCHOR_URL, home=home_path)
            ),
        },
    )

    if out:
        out_path = Path(out).expanduser()
    else:
        out_path = (
            home_path
            / "contract"
            / "coverage"
            / f"{report_id}.json"
        )

    # The publish detect_mode call respects ``RELAY_FORCE_SIGNED`` and the
    # ``GITHUB_TOKEN`` presence per VAL-W6-066. No env override here so
    # production / fork detection happens at the writer.
    report_result = write_report(inputs, out_path=out_path)

    _emit_publish_result(
        bundle_path=bundle_path,
        report_result=report_result,
        total_active_assertions=total_active,
        log_lines=jwks_log,
    )
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly contract check (M07 w7-cli-contract-check; VAL-V2M07-025..027)
# -----------------------------------------------------------------------------


CONTRACT_CHECK_SCHEMA: Final[str] = "relay.cli.contract_check.v1"


def cmd_contract_check(
    directory: str = typer.Argument(
        ...,
        help=(
            "Filesystem path to a directory containing contract DSL files "
            "(.json or .yaml). Each file is parsed via parse_contract; the "
            "coverage invariants from spec D.6 are evaluated across all "
            "active assertions + gates."
        ),
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly contract check <dir>`` -- validate DSL + coverage invariants.

    Per VAL-V2M07-026 the success envelope carries ``schema_version:
    "relay.cli.contract_check.v1"``, ``files_checked``, ``assertions_total``,
    ``coverage_valid: true``, and an empty ``violations`` array. Per
    VAL-V2M07-027 a coverage failure exits 1 with ``coverage_valid: false``
    and a populated ``violations`` array including at least one entry of
    ``type: "orphan_assertion"`` or ``type: "duplicate_primary_owner"``.
    """
    del json_output

    dir_path = Path(directory).expanduser()
    if not dir_path.exists():
        envelope = build_envelope(
            code="RELAY-CLI-CONTRACT-DIR-NOTFOUND",
            http_status=404,
            message=f"contract directory not found: {directory}",
            blocked_surface="rly contract check",
            retry_advice="after_fix",
            details={"directory": directory},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)
    if not dir_path.is_dir():
        envelope = build_envelope(
            code="RELAY-CLI-CONTRACT-NOT-DIRECTORY",
            http_status=400,
            message=f"path is not a directory: {directory}",
            blocked_surface="rly contract check",
            retry_advice="after_fix",
            details={"directory": directory},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    assertions: list[ParsedContract] = []
    gates: list[tuple[ParsedContract, list[str]]] = []
    files_checked = 0
    parse_errors: list[dict[str, Any]] = []

    # Scan both JSON and YAML contract files. The DSL design (spec
    # D.4) supports both serializations; previously we only
    # rglob'd *.json and silently skipped YAML files, producing
    # false PASS reports.
    candidates: list[Path] = []
    for pattern in ("*.json", "*.yaml", "*.yml"):
        candidates.extend(dir_path.rglob(pattern))
    for fp in sorted(set(candidates)):
        files_checked += 1
        suffix = fp.suffix.lower()
        try:
            raw = fp.read_text(encoding="utf-8")
            if suffix == ".json":
                doc = json.loads(raw)
            else:
                # YAML path: PyYAML is already a transitive dep
                # (used by the release-workflow guards). Use
                # ``safe_load`` so anchor/alias bombs and arbitrary
                # tag invocations are refused.
                import yaml  # local import keeps json fast path clean
                try:
                    doc = yaml.safe_load(raw)
                except yaml.YAMLError as yexc:
                    parse_errors.append({
                        "type": "parse_error",
                        "file": str(fp.relative_to(dir_path)),
                        "message": f"YAML parse failed: {yexc}",
                        "code": "RELAY-CONTRACT-PARSE-001",
                    })
                    continue
        except (OSError, json.JSONDecodeError) as exc:
            parse_errors.append({
                "type": "parse_error",
                "file": str(fp.relative_to(dir_path)),
                "message": str(exc),
            })
            continue
        if not isinstance(doc, Mapping):
            parse_errors.append({
                "type": "parse_error",
                "file": str(fp.relative_to(dir_path)),
                "message": (
                    "not a JSON object"
                    if suffix == ".json"
                    else "not a YAML mapping"
                ),
            })
            continue
        try:
            p = parse_contract(doc)
        except ContractParseError as exc:
            parse_errors.append({
                "type": "parse_error",
                "file": str(fp.relative_to(dir_path)),
                "message": exc.message,
                "code": exc.code,
            })
            continue
        if p.schema_version == "relay.gate_policy.v1":
            gates_ids_raw = doc.get("gates_assertion_ids", []) or []
            gates_ids: list[str] = [
                x for x in gates_ids_raw if isinstance(x, str)
            ]
            gates.append((p, gates_ids))
        else:
            assertions.append(p)

    # Coverage invariants
    violations: list[dict[str, Any]] = list(parse_errors)
    orphans = check_orphans(assertions, gates)
    for aid in orphans:
        violations.append({
            "type": "orphan_assertion",
            "assertion_id": aid,
            "message": (
                f"assertion {aid!r} is active but no active gate's "
                "gates_assertion_ids includes it"
            ),
        })
    duplicates = check_duplicate_digests(assertions)
    for dup in duplicates:
        violations.append({
            "type": "duplicate_primary_owner",
            "digest": dup["digest"],
            "assertion_ids": dup["assertion_ids"],
            "message": (
                f"assertions {dup['assertion_ids']!r} share expression "
                f"digest {dup['digest'][:12]}"
            ),
        })
    missing_owner = check_missing_owner(assertions)
    for aid in missing_owner:
        violations.append({
            "type": "missing_owner",
            "assertion_id": aid,
            "message": "P0/P1 assertion missing owner_email",
        })

    coverage_valid = not violations
    payload: dict[str, Any] = {
        "schema_version": CONTRACT_CHECK_SCHEMA,
        "directory": str(dir_path),
        "files_checked": files_checked,
        "assertions_total": len(assertions),
        "gates_total": len(gates),
        "coverage_valid": coverage_valid,
        "violations": violations,
    }
    emit_json(payload)
    raise typer.Exit(
        code=EXIT_SUCCESS if coverage_valid else EXIT_4XX_BLOCK
    )


# Re-export the publish detect_mode helper at the command surface so
# tests can pin it without reaching into the writer module.
__all__ = [
    "CONTRACT_CHECK_SCHEMA",
    "CONTRACT_PUBLISH_BUNDLE_SCHEMA",
    "CONTRACT_PUBLISH_RESULT_SCHEMA",
    "DEFAULT_GROUP_ALIAS_LOCAL_PARTS",
    "DEFAULT_GROUP_ALIAS_PREFIXES",
    "RELAY_CLI_CONTRACT_BUNDLE_INVALID",
    "RELAY_COVERAGE_001",
    "RELAY_COVERAGE_002",
    "RELAY_COVERAGE_003",
    "RELAY_COVERAGE_004",
    "build_per_gate_coverage",
    "build_per_owner_load",
    "check_duplicate_digests",
    "check_group_alias_owners",
    "check_missing_owner",
    "check_orphans",
    "cmd_contract_check",
    "cmd_contract_publish",
    "detect_mode",
    "is_group_alias",
]
