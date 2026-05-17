"""``rly manifest check`` command (M07 w7-cli-manifest-check).

Implements VAL-V2M07-022..024: validates a manifest against the canonical
``manifest.v1.json`` schema (M03 w3-manifest) and emits a structured
report including computed command_hash digests.

Exit codes:
  * 0  -- valid manifest
  * 1  -- schema-invalid manifest
  * 64 -- usage (path missing / unreadable)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import typer
from relay_schemas.manifest import compute_command_hash, validate

from ..errors import build_envelope, emit_envelope
from ..exit_codes import EXIT_4XX_BLOCK, EXIT_SUCCESS
from ..output import emit_json

MANIFEST_CHECK_SCHEMA: Final[str] = "relay.cli.manifest_check.v1"
MANIFEST_SCHEMA_ID: Final[str] = "manifest.v1.json"


def cmd_manifest_check(
    path: str = typer.Argument(
        ..., help="Filesystem path to a JSON manifest document."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly manifest check <path>`` -- validate + emit command_hash map.

    Per VAL-V2M07-023 the success envelope carries ``schema_version:
    "relay.cli.manifest_check.v1"``, ``manifest_path``, ``schema_id:
    "manifest.v1.json"``, ``valid: true``, an empty ``errors`` array,
    and a ``command_hash`` map (command name -> sha256 hex digest of the
    canonical command string).
    """
    del json_output

    manifest_path = Path(path).expanduser()
    if not manifest_path.exists():
        envelope = build_envelope(
            code="RELAY-CLI-MANIFEST-NOTFOUND",
            http_status=404,
            message=f"manifest path not found: {path}",
            blocked_surface="rly manifest check",
            retry_advice="after_fix",
            details={"path": path},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=64)

    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        envelope = build_envelope(
            code="RELAY-CLI-MANIFEST-UNREADABLE",
            http_status=400,
            message=f"manifest not readable: {exc}",
            blocked_surface="rly manifest check",
            retry_advice="after_fix",
            details={"path": path},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=64) from exc

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        emit_json({
            "schema_version": MANIFEST_CHECK_SCHEMA,
            "manifest_path": str(manifest_path),
            "schema_id": MANIFEST_SCHEMA_ID,
            "valid": False,
            "errors": [{
                "path": "",
                "message": f"manifest body is not valid JSON: {exc.msg}",
            }],
            "command_hash": {},
        })
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc

    if not isinstance(body, dict):
        emit_json({
            "schema_version": MANIFEST_CHECK_SCHEMA,
            "manifest_path": str(manifest_path),
            "schema_id": MANIFEST_SCHEMA_ID,
            "valid": False,
            "errors": [{
                "path": "",
                "message": "manifest body must be a JSON object",
            }],
            "command_hash": {},
        })
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    result = validate(body)
    if not result.ok:
        errors = [{
            "path": result.missing_field or "",
            "message": (
                result.schema_errors[0]
                if result.schema_errors
                else f"missing required field: {result.missing_field}"
            ),
        }]
        for err in result.schema_errors[1:]:
            errors.append({"path": "", "message": err})
        emit_json({
            "schema_version": MANIFEST_CHECK_SCHEMA,
            "manifest_path": str(manifest_path),
            "schema_id": MANIFEST_SCHEMA_ID,
            "valid": False,
            "errors": errors,
            "command_hash": {},
        })
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    # Compute command_hash per declared command
    command_hash_map: dict[str, str] = {}
    services = body.get("services", []) or []
    services_by_id: dict[str, dict[str, Any]] = {}
    if isinstance(services, list):
        for svc in services:
            if isinstance(svc, dict) and isinstance(svc.get("id"), str):
                services_by_id[svc["id"]] = svc
    for cmd in body.get("commands", []) or []:
        if not isinstance(cmd, dict):
            continue
        cmd_id = cmd.get("id")
        argv = cmd.get("argv")
        cwd = cmd.get("cwd")
        if not isinstance(cmd_id, str) or not isinstance(argv, list):
            continue
        if not isinstance(cwd, str):
            cwd = "."
        # Optional env + container_image; per spec §F line 4100 they
        # participate in the digest.
        env_raw = cmd.get("env") or {}
        env: dict[str, str] = {}
        if isinstance(env_raw, dict):
            for k, v in env_raw.items():
                if isinstance(k, str) and isinstance(v, str):
                    env[k] = v
        container_image = None
        svc_id = cmd.get("service")
        if isinstance(svc_id, str) and svc_id in services_by_id:
            img = services_by_id[svc_id].get("image")
            if isinstance(img, str) and img:
                container_image = img
        argv_strs = [a for a in argv if isinstance(a, str)]
        try:
            command_hash_map[cmd_id] = compute_command_hash(
                argv=argv_strs,
                cwd=cwd,
                env=env,
                container_image=container_image,
            )
        except (TypeError, ValueError):
            continue

    emit_json({
        "schema_version": MANIFEST_CHECK_SCHEMA,
        "manifest_path": str(manifest_path),
        "schema_id": MANIFEST_SCHEMA_ID,
        "valid": True,
        "errors": [],
        "command_hash": command_hash_map,
    })
    raise typer.Exit(code=EXIT_SUCCESS)


__all__ = ["MANIFEST_CHECK_SCHEMA", "MANIFEST_SCHEMA_ID", "cmd_manifest_check"]
