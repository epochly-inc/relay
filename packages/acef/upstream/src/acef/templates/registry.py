"""ACEF template registry — discovery, loading, and digest computation."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from acef.errors import ACEFProfileError
from acef.integrity import canonicalize, sha256_hex
from acef.templates.models import Template

# Template directory — bundled with the SDK
_TEMPLATE_DIR = Path(__file__).parent


def _get_template_dir() -> Path:
    """Get the template directory."""
    return _TEMPLATE_DIR


@lru_cache(maxsize=16)
def load_template(template_id: str) -> Template:
    """Load a regulation mapping template by ID.

    Templates are JSON files in the templates/ directory named {template_id}.json.

    Args:
        template_id: The template identifier, e.g., 'eu-ai-act-2024'.

    Returns:
        Parsed Template object.

    Raises:
        ACEFProfileError: If the template file is not found.
    """
    template_dir = _get_template_dir()
    template_file = template_dir / f"{template_id}.json"

    if not template_file.exists():
        raise ACEFProfileError(
            f"Template not found: {template_id}",
            code="ACEF-030",
        )

    try:
        with open(template_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ACEFProfileError(
            f"Invalid JSON in template {template_id}: {e}",
            code="ACEF-030",
        ) from e

    return Template.model_validate(data)


def compute_template_digest(template_id: str) -> str:
    """Compute the SHA-256 digest of a template's canonical form.

    Used for the Assessment Bundle's template_digests field.

    Args:
        template_id: The template identifier.

    Returns:
        Hex-encoded SHA-256 digest prefixed with 'sha256:'.
    """
    template = load_template(template_id)
    canonical = canonicalize(template.model_dump(mode="json"))
    digest = sha256_hex(canonical)
    return f"sha256:{digest}"


def list_templates() -> list[str]:
    """List all available template IDs.

    Returns:
        List of template IDs found in the templates directory.
    """
    template_dir = _get_template_dir()
    result: list[str] = []
    for f in sorted(template_dir.glob("*.json")):
        result.append(f.stem)
    return result


def get_template_provisions(template_id: str) -> list[str]:
    """Get all provision IDs from a template.

    Args:
        template_id: The template identifier.

    Returns:
        List of provision IDs.
    """
    template = load_template(template_id)
    return [p.provision_id for p in template.provisions]
