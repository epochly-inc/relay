"""Structured error-code registry loader (M05 w5-explain; VAL-V2M05-016/017).

The flat ``codes:`` list in ``packages/schemas/raw/relay-error-codes.yaml`` is
the source-of-truth for the wire-format token set (consumed by
``gen_error_codes.py`` to emit ``RelayErrorCode`` constants).

This module exposes the *structured* metadata block ``code_details:`` from
the same YAML, returning per-code ``description`` + ``http_status`` + spec
anchor for callers that need to construct error envelopes with the correct
HTTP status (e.g. the explain ingestion path returning 422 on a missing
span_id reference).

The loader is intentionally additive: codes that lack a ``code_details``
entry simply return ``None`` from :func:`get_code_details`. Existing
callers that only need the flat token set continue to use
``RelayErrorCode`` constants.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[4]
YAML_PATH = _REPO_ROOT / "packages" / "schemas" / "raw" / "relay-error-codes.yaml"


@dataclass(frozen=True)
class CodeDetail:
    """Structured metadata for a single error code."""

    code: str
    description: str
    http_status: int
    spec_anchor: str | None = None


def _load_yaml() -> dict[str, Any]:
    text = YAML_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"{YAML_PATH} malformed: top-level must be a mapping"
        )
    return data


@lru_cache(maxsize=1)
def load_codes() -> frozenset[str]:
    """Return the set of every wire-format token in ``codes:``."""
    data = _load_yaml()
    codes = data.get("codes", [])
    if not isinstance(codes, list):
        raise RuntimeError(f"{YAML_PATH} 'codes:' must be a list")
    return frozenset(str(c) for c in codes)


@lru_cache(maxsize=1)
def load_code_details() -> dict[str, CodeDetail]:
    """Return a mapping of code -> :class:`CodeDetail` for the metadata block.

    Codes present in ``codes:`` but absent from ``code_details:`` are
    omitted from the returned mapping; callers should use
    :func:`get_code_details` and handle ``None`` gracefully.
    """
    data = _load_yaml()
    details_raw = data.get("code_details", {}) or {}
    if not isinstance(details_raw, dict):
        raise RuntimeError(f"{YAML_PATH} 'code_details:' must be a mapping")
    codes = load_codes()
    out: dict[str, CodeDetail] = {}
    for code, fields in details_raw.items():
        if not isinstance(code, str):
            raise RuntimeError(
                f"{YAML_PATH} code_details key {code!r} must be a string"
            )
        if code not in codes:
            raise RuntimeError(
                f"{YAML_PATH} code_details entry {code!r} is not present "
                f"in the flat codes: list; add it there first"
            )
        if not isinstance(fields, dict):
            raise RuntimeError(
                f"{YAML_PATH} code_details[{code!r}] must be a mapping"
            )
        description = fields.get("description")
        http_status = fields.get("http_status")
        spec_anchor = fields.get("spec_anchor")
        if not isinstance(description, str) or not description.strip():
            raise RuntimeError(
                f"{YAML_PATH} code_details[{code!r}].description must be a non-empty string"
            )
        if not isinstance(http_status, int) or http_status < 100 or http_status >= 600:
            raise RuntimeError(
                f"{YAML_PATH} code_details[{code!r}].http_status must be an int in [100, 599]"
            )
        if spec_anchor is not None and not isinstance(spec_anchor, str):
            raise RuntimeError(
                f"{YAML_PATH} code_details[{code!r}].spec_anchor must be a string if present"
            )
        out[code] = CodeDetail(
            code=code,
            description=description.strip(),
            http_status=http_status,
            spec_anchor=spec_anchor,
        )
    return out


def get_code_details(code: str) -> CodeDetail | None:
    """Return :class:`CodeDetail` for ``code`` or ``None`` if no entry."""
    return load_code_details().get(code)


def http_status_for(code: str, default: int = 500) -> int:
    """Return the HTTP status mapped to ``code`` or ``default`` if absent."""
    detail = get_code_details(code)
    return detail.http_status if detail is not None else default


__all__ = [
    "CodeDetail",
    "YAML_PATH",
    "get_code_details",
    "http_status_for",
    "load_code_details",
    "load_codes",
]
