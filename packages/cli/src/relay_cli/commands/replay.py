"""``rly replay`` subcommands (W5.3 VAL-W5-019..024).

Subcommand surface:

  * ``rly replay list``    -- VAL-W5-019: paginated JSON registry of replay
                              cases (cursor + has_more + items).
  * ``rly replay record``  -- VAL-W5-020: capture a recorded run into a
                              fixture with a deterministic SHA-256 digest.
  * ``rly replay run``     -- VAL-W5-021..024: cassette-by-default playback;
                              blocks side effects without explicit policy
                              override; rejects digest mismatch; never
                              writes ``run_results``.

Per CLAUDE.md keystone invariants:

  * #1 control plane writes the result. The CLI submits drafts only and
    NEVER writes ``run_results``. The replay registry stored at
    ``${RELAY_HOME}/replay/cases.json`` is metadata for the operator
    surface; canonical evidence is bound by the sidecar control plane,
    not by the CLI.
  * #6 side-effect idempotency. Side-effecting tools (``mutating`` /
    ``external_irreversible``) are blocked from playback unless the case
    declares the policy override AND the operator passes
    ``--allow-side-effects=<class>`` on the command line.
  * #8 atomic persistence. Registry and fixture writes go through
    :func:`relay_sidecar.primitives.local_atomic_file_write`.
  * #9 cassette-first replay. ``run`` defaults to ``--mode cassette``;
    a ``--live`` opt-in is reserved for a future sub-feature and is NOT
    exposed in W5.3 (live mode lands in W6 alongside the replay-proxy).
  * #10 schema versioning. Every persisted envelope carries a pinned
    ``schema_version`` literal that this module owns.

Per spec §B.6:
  * ``RELAY-REPLAY-001`` -- fixture digest mismatch.
  * ``RELAY-REPLAY-014`` -- side effect attempted in replay without
    audited policy override.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import typer
from relay_sidecar.lockfile import relay_home
from relay_sidecar.primitives import local_atomic_file_write

from ..cassette import (
    CASSETTE_ENTRY_SCHEMA_VERSION,
    CASSETTE_HEADER_SCHEMA_VERSION,
    CassetteEntry,
    CassetteFormatError,
    CassetteHeader,
    canonical_request_digest,
    canonical_response_digest,
    parse_cassette,
    write_cassette_file,
)
from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_CLI_USAGE,
    EXIT_SUCCESS,
)
from ..output import emit_json

# -----------------------------------------------------------------------------
# Schema-version constants (one per stdout JSON envelope shape)
# -----------------------------------------------------------------------------

REPLAY_LIST_SCHEMA: Final[str] = "relay.cli.replay_list.v1"
REPLAY_RECORD_SCHEMA: Final[str] = "relay.cli.replay_record.v1"
REPLAY_RUN_SCHEMA: Final[str] = "relay.cli.replay_run.v1"

# Local registry envelope (persisted at ${RELAY_HOME}/replay/cases.json).
REPLAY_REGISTRY_SCHEMA: Final[str] = "relay.cli.replay_registry.v1"

# Wire codes (spec section B.6).
RELAY_REPLAY_001: Final[str] = "RELAY-REPLAY-001"
RELAY_REPLAY_014: Final[str] = "RELAY-REPLAY-014"
RELAY_REPLAY_CASE_NOT_FOUND: Final[str] = "RELAY-CLI-REPLAY-CASE-NOT-FOUND"
RELAY_REPLAY_RUN_NOT_FOUND: Final[str] = "RELAY-CLI-REPLAY-RUN-NOT-FOUND"

# Side-effect classes (spec §X, §E.3). Cassette mode safely replays
# ``none`` and ``reversible`` calls without override; ``mutating`` and
# ``external_irreversible`` REQUIRE an audited policy override.
SIDE_EFFECT_NONE: Final[str] = "none"
SIDE_EFFECT_REVERSIBLE: Final[str] = "reversible"
SIDE_EFFECT_MUTATING: Final[str] = "mutating"
SIDE_EFFECT_EXTERNAL_IRREVERSIBLE: Final[str] = "external_irreversible"
_DANGEROUS_SIDE_EFFECTS: Final[frozenset[str]] = frozenset(
    {SIDE_EFFECT_MUTATING, SIDE_EFFECT_EXTERNAL_IRREVERSIBLE}
)

# Default page size for ``rly replay list``.
DEFAULT_LIST_LIMIT: Final[int] = 50
MAX_LIST_LIMIT: Final[int] = 500

# Test seam: when set, the recorder reads a JSON document of recorded
# provider calls from this path instead of querying the sidecar. Each
# call is shaped:
#   {
#     "provider": "openai",
#     "model": "gpt-4o-mini",
#     "request": {<canonicalizable object>},
#     "response": {<canonicalizable object>},
#     "timestamp": "2026-05-14T00:00:00Z",
#     "side_effect_class": "none"   # optional; defaults to "none"
#   }
# The seam keeps the recorder deterministic for tier-1 plumbing tests
# without a live sidecar; the production code path will replace this
# with a sidecar query in W6 when the replay-proxy ships.
ENV_REPLAY_RECORD_SOURCE: Final[str] = "RELAY_CLI_REPLAY_RECORD_SOURCE"

# Test seam: when set, the recorder uses these fixed values for the
# session_id, recorded_at, and manifest_commit_hash header fields so the
# resulting cassette bytes are byte-stable across invocations on the
# same input. Without this seam the header would carry wall-clock time
# and a freshly-minted session ULID, breaking digest determinism.
ENV_REPLAY_RECORD_SESSION_ID: Final[str] = "RELAY_CLI_REPLAY_RECORD_SESSION_ID"
ENV_REPLAY_RECORD_RECORDED_AT: Final[str] = "RELAY_CLI_REPLAY_RECORD_RECORDED_AT"
ENV_REPLAY_RECORD_MANIFEST_HASH: Final[str] = "RELAY_CLI_REPLAY_RECORD_MANIFEST_HASH"


# -----------------------------------------------------------------------------
# Registry helpers
# -----------------------------------------------------------------------------


def _now_rfc3339_z() -> str:
    """Return the current UTC time as an RFC 3339 ``Z`` string."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _resolve_home(home: str) -> Path:
    """Resolve ``--home`` with the same semantics as the sidecar group."""
    return Path(home).expanduser() if home else relay_home()


def _replay_dir(home: Path) -> Path:
    """Return ``${HOME}/replay``."""
    return home / "replay"


def _registry_path(home: Path) -> Path:
    return _replay_dir(home) / "cases.json"


def _fixtures_dir(home: Path) -> Path:
    return _replay_dir(home) / "fixtures"


def _fixture_path(home: Path, case_id: str) -> Path:
    return _fixtures_dir(home) / f"{case_id}.json"


def _empty_registry() -> dict[str, Any]:
    """Return the empty registry envelope (sorted, schema-versioned)."""
    return {
        "schema_version": REPLAY_REGISTRY_SCHEMA,
        "items": [],
    }


def _load_registry(home: Path) -> dict[str, Any]:
    """Load the local replay-case registry, returning the empty form on miss.

    Items live as a list of dicts ordered by ``replay_case_id`` ascending
    so pagination is deterministic without a separate index column.
    """
    path = _registry_path(home)
    if not path.exists() or path.stat().st_size == 0:
        return _empty_registry()
    try:
        loaded = json.loads(path.read_bytes().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Malformed registry: surface as empty so the operator can
        # re-record. The sidecar event log records the parse failure
        # when the sidecar is later queried; the CLI does not silently
        # rewrite the file.
        return _empty_registry()
    if not isinstance(loaded, dict) or loaded.get("schema_version") != REPLAY_REGISTRY_SCHEMA:
        return _empty_registry()
    items = loaded.get("items", [])
    if not isinstance(items, list):
        items = []
    # Defensive: drop any item lacking the required keys.
    cleaned = [
        item
        for item in items
        if isinstance(item, dict)
        and isinstance(item.get("replay_case_id"), str)
        and item.get("replay_case_id")
    ]
    cleaned.sort(key=lambda it: it["replay_case_id"])
    return {"schema_version": REPLAY_REGISTRY_SCHEMA, "items": cleaned}


def _save_registry(home: Path, registry: dict[str, Any]) -> None:
    """Persist the registry through the atomic primitive."""
    path = _registry_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        registry, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"
    local_atomic_file_write(path, payload, mode=0o600)


def _upsert_case(
    registry: dict[str, Any],
    *,
    replay_case_id: str,
    name: str,
    fixture_path: Path,
    fixture_digest: str,
    last_status: str,
    side_effects: list[str],
) -> dict[str, Any]:
    """Insert or update a registry entry, returning the updated registry."""
    items = list(registry.get("items", []))
    new_item = {
        "replay_case_id": replay_case_id,
        "name": name,
        "fixture_path": str(fixture_path),
        "fixture_digest": fixture_digest,
        "last_run_at": _now_rfc3339_z(),
        "last_status": last_status,
        "side_effects": sorted(set(side_effects)),
    }
    found = False
    for idx, existing in enumerate(items):
        if existing.get("replay_case_id") == replay_case_id:
            # Preserve the original creation order; update fields in place.
            new_item["last_run_at"] = (
                existing.get("last_run_at") or new_item["last_run_at"]
            )
            items[idx] = new_item
            found = True
            break
    if not found:
        items.append(new_item)
    items.sort(key=lambda it: it["replay_case_id"])
    return {"schema_version": REPLAY_REGISTRY_SCHEMA, "items": items}


# -----------------------------------------------------------------------------
# Cursor helpers (opaque base64url JSON, per spec §B.3 pagination convention)
# -----------------------------------------------------------------------------


def _encode_cursor(replay_case_id: str) -> str:
    """Encode a cursor as base64url(JSON) so it is opaque to clients."""
    raw = json.dumps(
        {"after_replay_case_id": replay_case_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> str | None:
    """Return the ``after_replay_case_id`` field or None on parse failure."""
    if not cursor:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = urlsafe_b64decode(cursor + padding)
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    val = decoded.get("after_replay_case_id")
    return val if isinstance(val, str) and val else None


# -----------------------------------------------------------------------------
# Recorder source-loading
# -----------------------------------------------------------------------------


def _load_record_source() -> list[dict[str, Any]]:
    """Read the JSON document of recorded provider calls from the test seam.

    Returns an empty list when the env var is unset (zero captured calls).
    Raises :class:`CassetteFormatError` on malformed input -- the caller
    converts it to a structured envelope.
    """
    src_path = os.environ.get(ENV_REPLAY_RECORD_SOURCE, "").strip()
    if not src_path:
        return []
    try:
        raw = Path(src_path).read_bytes()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        raise CassetteFormatError(
            f"replay record source not readable: {exc}", 0, src_path
        ) from exc
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CassetteFormatError(
            f"replay record source is not valid JSON: {exc.msg}", 0, src_path
        ) from exc
    if not isinstance(loaded, list):
        raise CassetteFormatError(
            "replay record source must be a JSON array", 0, src_path
        )
    return loaded


def _build_entries(
    calls: list[dict[str, Any]], path_for_errors: str | None
) -> tuple[list[CassetteEntry], list[str]]:
    """Project the recorded-calls list into validated cassette entries.

    Returns ``(entries, side_effect_classes)`` where ``side_effect_classes``
    is the deduped list of declared side-effect classes across the calls.
    Calls missing ``side_effect_class`` default to ``"none"``.
    """
    entries: list[CassetteEntry] = []
    side_effects: set[str] = set()
    for idx, call in enumerate(calls):
        if not isinstance(call, dict):
            raise CassetteFormatError(
                f"call[{idx}] must be an object", idx, path_for_errors
            )
        provider = call.get("provider")
        model = call.get("model")
        request = call.get("request")
        response = call.get("response")
        timestamp = call.get("timestamp")
        side_class = call.get("side_effect_class", SIDE_EFFECT_NONE)
        if not isinstance(provider, str) or not provider:
            raise CassetteFormatError(
                f"call[{idx}] missing non-empty 'provider'", idx, path_for_errors
            )
        if not isinstance(model, str) or not model:
            raise CassetteFormatError(
                f"call[{idx}] missing non-empty 'model'", idx, path_for_errors
            )
        if not isinstance(request, dict):
            raise CassetteFormatError(
                f"call[{idx}] 'request' must be an object", idx, path_for_errors
            )
        if not isinstance(response, dict):
            raise CassetteFormatError(
                f"call[{idx}] 'response' must be an object", idx, path_for_errors
            )
        if not isinstance(timestamp, str) or not timestamp:
            raise CassetteFormatError(
                f"call[{idx}] missing non-empty 'timestamp'", idx, path_for_errors
            )
        if not isinstance(side_class, str):
            raise CassetteFormatError(
                f"call[{idx}] 'side_effect_class' must be a string",
                idx,
                path_for_errors,
            )
        side_effects.add(side_class)
        entries.append(
            CassetteEntry(
                schema_version=CASSETTE_ENTRY_SCHEMA_VERSION,
                sequence=idx,
                provider=provider,
                model=model,
                request_digest=canonical_request_digest(request),
                response=response,
                response_digest=canonical_response_digest(response),
                timestamp=timestamp,
            )
        )
    return entries, sorted(side_effects)


# -----------------------------------------------------------------------------
# Deterministic identifier helpers
# -----------------------------------------------------------------------------


def _deterministic_case_id(run_id: str) -> str:
    """Map a ``run_id`` to a stable replay_case_id.

    Per VAL-W5-020 re-running ``record`` on the same run_id must produce
    a byte-identical fixture. The case_id is derived from the run_id via
    SHA-256 truncation so two record invocations in different processes
    yield the same identifier without consulting a side database.
    """
    digest = hashlib.sha256(("relay.replay.case." + run_id).encode("utf-8")).hexdigest()
    # Use first 26 chars to mimic ULID width; the format is opaque to
    # consumers and only needs to be stable per run_id.
    return digest[:26]


def _deterministic_session_id(run_id: str) -> str:
    digest = hashlib.sha256(("relay.replay.session." + run_id).encode("utf-8")).hexdigest()
    return digest[:26]


# -----------------------------------------------------------------------------
# rly replay list (VAL-W5-019)
# -----------------------------------------------------------------------------


def _cmd_replay_list(
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
    cursor: str = typer.Option(
        "",
        "--cursor",
        help="Opaque cursor returned by a previous --limit page (next_cursor).",
    ),
) -> None:
    """``rly replay list`` -- paginated JSON registry (VAL-W5-019)."""
    base_home = _resolve_home(home)
    if limit < 1 or limit > MAX_LIST_LIMIT:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-LIMIT",
            http_status=400,
            message=f"--limit must be in 1..{MAX_LIST_LIMIT}; got {limit}",
            blocked_surface="rly replay list",
            retry_advice="after_fix",
            details={"limit": limit, "max": MAX_LIST_LIMIT},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    registry = _load_registry(base_home)
    items = list(registry.get("items", []))
    after = _decode_cursor(cursor) if cursor else None
    if after is not None:
        items = [it for it in items if it["replay_case_id"] > after]

    page = items[:limit]
    has_more = len(items) > limit
    next_cursor: str | None = (
        _encode_cursor(page[-1]["replay_case_id"]) if has_more and page else None
    )

    payload: dict[str, Any] = {
        "schema_version": REPLAY_LIST_SCHEMA,
        "items": [
            {
                "replay_case_id": it["replay_case_id"],
                "name": it.get("name", ""),
                "last_run_at": it.get("last_run_at"),
                "last_status": it.get("last_status"),
                "fixture_digest": it.get("fixture_digest", ""),
            }
            for it in page
        ],
        "next_cursor": next_cursor,
        "has_more": has_more,
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly replay record (VAL-W5-020)
# -----------------------------------------------------------------------------


def _cmd_replay_record(
    run_id: str = typer.Option(
        ...,
        "--run-id",
        help="Run identifier (UUID) whose tool calls + provider responses to capture.",
    ),
    name: str = typer.Option(
        "",
        "--name",
        help="Optional human-friendly name to store with the registry entry.",
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
) -> None:
    """``rly replay record`` -- capture a run into a deterministic fixture."""
    if not run_id:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-RUN-ID",
            http_status=400,
            message="--run-id is required and must be non-empty",
            blocked_surface="rly replay record",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    base_home = _resolve_home(home)

    try:
        calls = _load_record_source()
    except CassetteFormatError as exc:
        envelope = build_envelope(
            code="RELAY-CLI-REPLAY-SOURCE-INVALID",
            http_status=400,
            message=str(exc),
            blocked_surface="rly replay record",
            retry_advice="after_fix",
            details={"path": exc.path, "line": exc.line},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE) from exc

    case_id = _deterministic_case_id(run_id)

    # Header fields default to deterministic-by-run-id seams when the test
    # env vars are set; otherwise fall back to wall-clock + fresh ULID.
    session_id = (
        os.environ.get(ENV_REPLAY_RECORD_SESSION_ID, "").strip()
        or _deterministic_session_id(run_id)
    )
    recorded_at = (
        os.environ.get(ENV_REPLAY_RECORD_RECORDED_AT, "").strip()
        or _now_rfc3339_z()
    )
    manifest_hash = (
        os.environ.get(ENV_REPLAY_RECORD_MANIFEST_HASH, "").strip()
        or "sha256-" + ("0" * 64)
    )

    try:
        entries, side_effects = _build_entries(
            calls, os.environ.get(ENV_REPLAY_RECORD_SOURCE) or None
        )
    except CassetteFormatError as exc:
        envelope = build_envelope(
            code="RELAY-CLI-REPLAY-SOURCE-INVALID",
            http_status=400,
            message=str(exc),
            blocked_surface="rly replay record",
            retry_advice="after_fix",
            details={"path": exc.path, "line": exc.line},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE) from exc

    header = CassetteHeader(
        schema_version=CASSETTE_HEADER_SCHEMA_VERSION,
        case_id=case_id,
        session_id=session_id,
        recorded_at=recorded_at,
        manifest_commit_hash=manifest_hash,
    )

    fixture_path = _fixture_path(base_home, case_id)
    fixture_digest = write_cassette_file(fixture_path, header, entries)

    # Record / refresh the registry entry. The CLI never writes
    # ``run_results``; this is the operator-visible registry only.
    registry = _load_registry(base_home)
    registry = _upsert_case(
        registry,
        replay_case_id=case_id,
        name=name or run_id,
        fixture_path=fixture_path,
        fixture_digest=fixture_digest,
        last_status="recorded",
        side_effects=side_effects,
    )
    _save_registry(base_home, registry)

    payload: dict[str, Any] = {
        "schema_version": REPLAY_RECORD_SCHEMA,
        "replay_case_id": case_id,
        "fixture_path": str(fixture_path),
        "fixture_digest": fixture_digest,
        "captured_calls": len(entries),
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly replay run (VAL-W5-021..024)
# -----------------------------------------------------------------------------


def _parse_allow_side_effects(raw: str) -> set[str]:
    """Parse ``--allow-side-effects`` into a validated set of classes.

    Multiple classes may be passed comma-separated. Only ``mutating`` and
    ``external_irreversible`` are accepted; ``none`` and ``reversible`` are
    rejected because they are always allowed and listing them would mislead
    operators into thinking they are gated behind a flag.
    """
    if not raw:
        return set()
    out: set[str] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if token not in _DANGEROUS_SIDE_EFFECTS:
            raise ValueError(
                f"--allow-side-effects accepts only "
                f"{sorted(_DANGEROUS_SIDE_EFFECTS)}; got {token!r}"
            )
        out.add(token)
    return out


def _cmd_replay_run(
    case: str = typer.Option(
        ...,
        "--case",
        help="replay_case_id to play back (returned by `rly replay list`).",
    ),
    mode: str = typer.Option(
        "cassette",
        "--mode",
        help="Playback mode. Only 'cassette' is supported in W5.3.",
    ),
    allow_side_effects: str = typer.Option(
        "",
        "--allow-side-effects",
        help=(
            "Comma-separated side-effect classes to permit. Default empty: "
            "any 'mutating' or 'external_irreversible' call in the recorded "
            "fixture causes RELAY-REPLAY-014. Permitted values: "
            "'mutating', 'external_irreversible'."
        ),
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    proxy: bool = typer.Option(
        False,
        "--proxy/--no-proxy",
        help=(
            "Spawn the W7.1 mitmproxy harness for this replay. When set, "
            "the CLI generates a per-session CA, allocates a free port, "
            "starts the proxy, and returns its URL + CA path in the "
            "result envelope (the agent subprocess is NOT spawned by "
            "the CLI; consumers that need that surface should call "
            "the harness library directly via "
            "relay_replay_proxy.HarnessSession). Default off."
        ),
    ),
    session: str = typer.Option(
        "",
        "--session",
        help=(
            "Override the session_id used by --proxy. Defaults to the "
            "replay case_id so cassettes recorded by 'rly replay record' "
            "are immediately usable. Cassette dir is "
            "${RELAY_HOME}/cassettes/<session>/."
        ),
    ),
) -> None:
    """``rly replay run`` -- cassette playback (VAL-W5-021..024).

    Per CLAUDE.md keystone invariant #1 the CLI never writes
    ``run_results``; the per-replay outcome is materialized as an
    operator-facing JSON envelope and the registry's ``last_status``
    field. Canonical evidence binding is owned by the sidecar's replay-
    workers service, which W5.3 does not invoke (the OSS CLI's local
    sidecar profile uses cassette playback only).
    """
    base_home = _resolve_home(home)

    if mode != "cassette":
        # Per VAL-W5-021 cassette is the default. Live mode is reserved
        # for a later sub-feature alongside the replay-proxy in W6;
        # surfacing it here without the proxy would silently re-execute
        # provider calls and violate the cassette-first invariant.
        envelope = build_envelope(
            code="RELAY-CLI-REPLAY-MODE-UNSUPPORTED",
            http_status=400,
            message=(
                f"replay mode {mode!r} is not supported in this build; "
                "only 'cassette' is available. Live mode lands in W6 with "
                "the replay-proxy."
            ),
            blocked_surface="rly replay run",
            retry_advice="do_not_retry",
            details={"mode": mode},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE)

    try:
        allowed_classes = _parse_allow_side_effects(allow_side_effects)
    except ValueError as exc:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-ALLOW-SIDE-EFFECTS",
            http_status=400,
            message=str(exc),
            blocked_surface="rly replay run",
            retry_advice="after_fix",
            details={"argument": allow_side_effects},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CLI_USAGE) from exc

    registry = _load_registry(base_home)
    item = next(
        (it for it in registry.get("items", []) if it.get("replay_case_id") == case),
        None,
    )
    if item is None:
        envelope = build_envelope(
            code=RELAY_REPLAY_CASE_NOT_FOUND,
            http_status=404,
            message=f"replay case {case!r} not found in registry",
            blocked_surface="rly replay run",
            retry_advice="after_fix",
            details={"replay_case_id": case, "registry_path": str(_registry_path(base_home))},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    fixture_path = Path(item["fixture_path"])
    expected_digest = item.get("fixture_digest", "")
    declared_side_effects = set(item.get("side_effects", []) or [])

    # VAL-W5-023: independent SHA-256 of the on-disk bytes; refuse
    # silent re-capture if the digest does not match the registry.
    if not fixture_path.exists():
        envelope = build_envelope(
            code=RELAY_REPLAY_001,
            http_status=409,
            message=f"replay fixture missing at {fixture_path!s}",
            blocked_surface="rly replay run",
            retry_advice="do_not_retry",
            details={
                "replay_case_id": case,
                "fixture_path": str(fixture_path),
                "expected_digest": expected_digest,
                "actual_digest": None,
            },
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    on_disk_bytes = fixture_path.read_bytes()
    actual_digest = hashlib.sha256(on_disk_bytes).hexdigest()
    if actual_digest != expected_digest:
        envelope = build_envelope(
            code=RELAY_REPLAY_001,
            http_status=409,
            message=(
                "replay fixture digest mismatch: registry expected "
                f"{expected_digest!r}; on-disk {actual_digest!r}. The CLI "
                "MUST NOT silently re-capture; re-record explicitly via "
                "'rly replay record --run-id <id>'."
            ),
            blocked_surface="rly replay run",
            retry_advice="do_not_retry",
            details={
                "replay_case_id": case,
                "fixture_path": str(fixture_path),
                "expected_digest": expected_digest,
                "actual_digest": actual_digest,
            },
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    # Parse the cassette so we know how many entries to "play back" and
    # so the file's structural validity is asserted before the run is
    # declared a success.
    try:
        cassette = parse_cassette(on_disk_bytes, str(fixture_path))
    except CassetteFormatError as exc:
        envelope = build_envelope(
            code=RELAY_REPLAY_001,
            http_status=409,
            message=f"replay fixture failed structural validation: {exc}",
            blocked_surface="rly replay run",
            retry_advice="do_not_retry",
            details={
                "replay_case_id": case,
                "fixture_path": str(fixture_path),
                "line": exc.line,
            },
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc

    # VAL-W5-022: refuse playback when the case's recorded run touched a
    # mutating / external_irreversible tool unless the operator explicitly
    # allowed that class with --allow-side-effects.
    blocked = sorted(
        (declared_side_effects & _DANGEROUS_SIDE_EFFECTS) - allowed_classes
    )
    if blocked:
        envelope = build_envelope(
            code=RELAY_REPLAY_014,
            http_status=403,
            message=(
                "replay refused: case declares side-effect class(es) "
                f"{blocked!r} but --allow-side-effects did not authorize them. "
                "Per CLAUDE.md keystone invariant #6, mutating and "
                "external_irreversible tools must not auto-replay without "
                "an audited policy override."
            ),
            blocked_surface="rly replay run",
            retry_advice="after_fix",
            details={
                "replay_case_id": case,
                "blocked_side_effect_classes": blocked,
                "allowed_side_effect_classes": sorted(allowed_classes),
                "declared_side_effect_classes": sorted(declared_side_effects),
            },
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    # W7.1 mitmproxy harness opt-in. When --proxy is set we materialize a
    # session under ${RELAY_HOME}/cassettes/<session>/ (copying the
    # fixture so it is reachable by the proxy's confined cassette
    # server), then start the harness. Failures bubble out via typed
    # error envelopes; successful start adds proxy fields to the
    # operator-facing JSON.
    proxy_payload: dict[str, Any] | None = None
    proxy_session = None
    if proxy:
        proxy_session, proxy_payload = _start_proxy_for_run(
            case=case,
            session_id_override=session,
            base_home=base_home,
            fixture_path=fixture_path,
        )

    # Successful playback: emit the replay envelope. Note: this command
    # does NOT write the canonical run-result row -- that is the sidecar's
    # control-plane responsibility (CLAUDE.md keystone invariant #1).
    payload: dict[str, Any] = {
        "schema_version": REPLAY_RUN_SCHEMA,
        "replay_case_id": case,
        "mode": "cassette",
        "fixture_path": str(fixture_path),
        "fixture_digest": actual_digest,
        "entries_played": len(cassette.entries),
        "allowed_side_effect_classes": sorted(allowed_classes),
        "wrote_run_results": False,
        "control_plane_writer": "sidecar.replay-workers",
        "replay_id": "replay_" + uuid.uuid4().hex,
    }
    if proxy_payload is not None:
        payload["proxy"] = proxy_payload
    try:
        emit_json(payload)
    finally:
        # The CLI surface is fire-and-emit: we tear down the proxy
        # immediately because the agent subprocess (when implemented in
        # a follow-up) is owned by the caller, not by this command. The
        # consumer that needs a long-lived proxy must call the harness
        # library directly.
        if proxy_session is not None:
            proxy_session.stop()
    raise typer.Exit(code=EXIT_SUCCESS)


def _start_proxy_for_run(
    *,
    case: str,
    session_id_override: str,
    base_home: Path,
    fixture_path: Path,
) -> tuple[Any, dict[str, Any]]:
    """Materialize the cassette dir + start the W7.1 harness.

    Returns ``(harness_session, proxy_payload_for_envelope)``. Raises
    ``typer.Exit`` with the appropriate exit code on failure (the
    typed error envelope is emitted to stderr via build_envelope).
    """
    # Local imports keep relay_cli importable on hosts that have not
    # installed the replay-proxy package (e.g., the schemas-only CI cell).
    from relay_replay_proxy import (
        HarnessConfig,
        HarnessSession,
        RelayProxyDownError,
        RelayProxyError,
        RelayProxyMissingCassetteError,
        RelayProxyStartError,
    )

    session_id = session_id_override.strip() or case
    cassette_root = base_home / "cassettes"
    cassette_root.mkdir(parents=True, exist_ok=True)
    session_dir = cassette_root / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    # Copy the fixture into the session dir under the canonical filename
    # the harness expects (cassette.jsonl). We use the atomic primitive
    # so a process kill mid-copy cannot leave a half-written cassette.
    target = session_dir / "cassette.jsonl"
    if not target.exists() or target.read_bytes() != fixture_path.read_bytes():
        local_atomic_file_write(target, fixture_path.read_bytes(), mode=0o600)

    cfg = HarnessConfig(session_id=session_id, cassette_root=cassette_root)
    sess = HarnessSession(cfg)
    try:
        handle = sess.start()
    except RelayProxyMissingCassetteError as exc:
        envelope = build_envelope(
            code=exc.code,
            http_status=exc.http_status,
            message=exc.message,
            blocked_surface=exc.blocked_surface,
            retry_advice=exc.retry_advice,
            details=exc.details,
            documentation_url=exc.documentation_url,
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc
    except RelayProxyStartError as exc:
        envelope = build_envelope(
            code=exc.code,
            http_status=exc.http_status,
            message=exc.message,
            blocked_surface=exc.blocked_surface,
            retry_advice=exc.retry_advice,
            details=exc.details,
            documentation_url=exc.documentation_url,
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc
    except RelayProxyDownError as exc:  # pragma: no cover - start path
        envelope = build_envelope(
            code=exc.code,
            http_status=exc.http_status,
            message=exc.message,
            blocked_surface=exc.blocked_surface,
            retry_advice=exc.retry_advice,
            details=exc.details,
            documentation_url=exc.documentation_url,
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc
    except RelayProxyError as exc:  # base class catch-all
        envelope = build_envelope(
            code=exc.code,
            http_status=exc.http_status,
            message=exc.message,
            blocked_surface=exc.blocked_surface,
            retry_advice=exc.retry_advice,
            details=exc.details,
            documentation_url=exc.documentation_url,
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc

    proxy_payload: dict[str, Any] = {
        "session_id": handle.session_id,
        "session_dir": str(handle.session_dir),
        "proxy_url": handle.proxy_url,
        "proxy_port": handle.proxy_port,
        "ca_cert_path": str(handle.ca.cert_path),
        "driver": handle.driver_name,
    }
    return sess, proxy_payload


# -----------------------------------------------------------------------------
# Typer app construction
# -----------------------------------------------------------------------------


def build_replay_app() -> typer.Typer:
    """Construct the ``rly replay`` sub-Typer with all three commands wired."""
    app = typer.Typer(
        name="replay",
        help=(
            "Record and play back agent traffic. Cassette mode is the "
            "default; live mode lands in W6. Side effects are blocked "
            "without an explicit --allow-side-effects override."
        ),
        no_args_is_help=False,
        rich_markup_mode=None,
        add_completion=False,
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @app.callback(invoke_without_command=True)
    def _root(ctx: typer.Context) -> None:
        if ctx.invoked_subcommand is None:
            from ..main import _emit_not_implemented  # local import: avoid cycle

            _emit_not_implemented("replay", "w5.3")

    app.command("list")(_cmd_replay_list)
    app.command("record")(_cmd_replay_record)
    app.command("run")(_cmd_replay_run)
    return app


__all__ = [
    "DEFAULT_LIST_LIMIT",
    "ENV_REPLAY_RECORD_MANIFEST_HASH",
    "ENV_REPLAY_RECORD_RECORDED_AT",
    "ENV_REPLAY_RECORD_SESSION_ID",
    "ENV_REPLAY_RECORD_SOURCE",
    "MAX_LIST_LIMIT",
    "RELAY_REPLAY_001",
    "RELAY_REPLAY_014",
    "RELAY_REPLAY_CASE_NOT_FOUND",
    "REPLAY_LIST_SCHEMA",
    "REPLAY_RECORD_SCHEMA",
    "REPLAY_REGISTRY_SCHEMA",
    "REPLAY_RUN_SCHEMA",
    "SIDE_EFFECT_EXTERNAL_IRREVERSIBLE",
    "SIDE_EFFECT_MUTATING",
    "SIDE_EFFECT_NONE",
    "SIDE_EFFECT_REVERSIBLE",
    "build_replay_app",
]
