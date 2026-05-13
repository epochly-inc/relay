"""Sidecar lockfile body model (W2.1).

The lockfile at ``${RELAY_HOME:-~/.relay}/sidecar.lock`` MUST contain JSON
with exactly the keys:

    {pid, port, launched_at, launched_by, sidecar_version, bearer_token_digest}

No extras, no omissions (VAL-W2-002). Missing any key fails the spawn
with ``RELAY-SIDECAR-LOCKFILE-MALFORMED``.

This module owns:

  - ``LockfileBody`` Pydantic model (strict, extra='forbid').
  - ``parse_lockfile_body(raw)`` -> LockfileBody (raises SidecarError on
    malformed input).
  - ``serialize_lockfile_body(body)`` -> bytes (canonical JSON, sorted
    keys, compact separators).
  - ``resolve_lockfile_path(home)`` -> ``${RELAY_HOME or home}/sidecar.lock``.

Per VAL-W1-029 + W1.1-W1.4 conventions, every model carries
``model_config = ConfigDict(extra='forbid', strict=True)`` so any extra
field on the wire is rejected at parse time.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    StrictInt,
    StrictStr,
    ValidationError,
)

from .errors import RELAY_SIDECAR_LOCKFILE_MALFORMED, make_error

# Fixed lockfile filename. The path policy is RELAY_HOME if set,
# otherwise ~/.relay (VAL-W2-001). The filename itself is invariant.
LOCKFILE_FILENAME: Final[str] = "sidecar.lock"


def relay_home() -> Path:
    """Return the resolved Relay home directory.

    Per VAL-W2-001:
      - If ``RELAY_HOME`` env var is set and non-empty, use it verbatim.
      - Otherwise, ``~/.relay``.

    The returned path is NOT created here; callers MUST mkdir before
    writing. Resolution uses ``Path.expanduser`` so ``~`` is interpreted
    in the caller's environment, not in the process default.
    """
    override = os.environ.get("RELAY_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".relay"


def resolve_lockfile_path(home: Path | None = None) -> Path:
    """Return the absolute lockfile path under the resolved home."""
    base = home if home is not None else relay_home()
    return base / LOCKFILE_FILENAME


class LockfileBody(BaseModel):
    """Canonical lockfile JSON body (VAL-W2-002)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    pid: PositiveInt
    port: StrictInt = Field(ge=1, le=65535)
    launched_at: StrictStr = Field(min_length=1)
    launched_by: StrictStr = Field(min_length=1)
    sidecar_version: StrictStr = Field(min_length=1)
    bearer_token_digest: StrictStr = Field(
        min_length=1,
        # Form: 'sha256-<64 lowercase hex chars>' per VAL-W1-009 canonical.
        pattern=r"^sha256-[0-9a-f]{64}$",
    )


def parse_lockfile_body(raw: bytes | str) -> LockfileBody:
    """Parse and validate lockfile bytes; raise SidecarError on malformed input.

    Empty input ``b""`` is treated as malformed (STALE_PID-cleared state).
    """
    if isinstance(raw, bytes):
        if not raw.strip():
            raise make_error(
                RELAY_SIDECAR_LOCKFILE_MALFORMED,
                "lockfile body is empty (cleared or never-written state)",
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise make_error(
                RELAY_SIDECAR_LOCKFILE_MALFORMED,
                f"lockfile body is not valid UTF-8: {e}",
            ) from e
    else:
        text = raw
        if not text.strip():
            raise make_error(
                RELAY_SIDECAR_LOCKFILE_MALFORMED,
                "lockfile body is empty (cleared or never-written state)",
            )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_MALFORMED,
            f"lockfile body is not valid JSON: {e}",
            details={"raw_preview": text[:200]},
        ) from e

    if not isinstance(data, dict):
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_MALFORMED,
            f"lockfile body must be a JSON object; observed {type(data).__name__}",
        )

    try:
        return LockfileBody.model_validate(data)
    except ValidationError as e:
        # Surface the missing/extra keys as part of the structured error so
        # ``rly sidecar status`` can present a useful diagnostic.
        missing = sorted(
            err["loc"][0]
            for err in e.errors()
            if err.get("type") == "missing" and err.get("loc")
        )
        extra = sorted(
            err["loc"][0]
            for err in e.errors()
            if err.get("type") == "extra_forbidden" and err.get("loc")
        )
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_MALFORMED,
            "lockfile body failed schema validation",
            details={
                "missing_keys": list(missing),
                "extra_keys": list(extra),
                "validation_errors": [
                    {"loc": list(err.get("loc", ())), "type": err.get("type")}
                    for err in e.errors()
                ],
            },
        ) from e


def serialize_lockfile_body(body: LockfileBody) -> bytes:
    """Serialize the lockfile body to canonical JSON bytes.

    Canonical form: sorted keys, compact separators, UTF-8 bytes. Matches
    the W1 cross-language canonical-JCS convention.
    """
    payload = body.model_dump(mode="json")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


__all__ = [
    "LOCKFILE_FILENAME",
    "LockfileBody",
    "parse_lockfile_body",
    "relay_home",
    "resolve_lockfile_path",
    "serialize_lockfile_body",
]
