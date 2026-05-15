"""ACEF URN generation, validation, and parsing.

URN format: urn:acef:{type}:{uuid}
Types: pkg, sub, cmp, dat, act, rec, asx
"""

from __future__ import annotations

import re
import uuid
from enum import Enum
from typing import NamedTuple

from acef.errors import ACEFError

_URN_PATTERN = re.compile(r"^urn:acef:(pkg|sub|cmp|dat|act|rec|asx):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")


class URNType(str, Enum):
    """ACEF URN type prefixes."""

    PACKAGE = "pkg"
    SUBJECT = "sub"
    COMPONENT = "cmp"
    DATASET = "dat"
    ACTOR = "act"
    RECORD = "rec"
    ASSESSMENT = "asx"


class ParsedURN(NamedTuple):
    """Parsed ACEF URN components."""

    urn_type: URNType
    uuid_str: str
    full_urn: str


def generate_urn(urn_type: URNType) -> str:
    """Generate a new ACEF URN with a random UUID v4.

    Args:
        urn_type: The URN type prefix (pkg, sub, cmp, dat, act, rec, asx).

    Returns:
        A URN string like 'urn:acef:sub:550e8400-e29b-41d4-a716-446655440000'.
    """
    return f"urn:acef:{urn_type.value}:{uuid.uuid4()}"


def validate_urn(urn: str) -> bool:
    """Validate an ACEF URN string.

    Args:
        urn: The URN string to validate.

    Returns:
        True if the URN is valid, False otherwise.
    """
    return _URN_PATTERN.match(urn) is not None


def parse_urn(urn: str) -> ParsedURN:
    """Parse an ACEF URN into its components.

    Args:
        urn: The URN string to parse.

    Returns:
        A ParsedURN with type, uuid, and full URN.

    Raises:
        ACEFError: If the URN is invalid.
    """
    match = _URN_PATTERN.match(urn)
    if not match:
        raise ACEFError(f"Invalid ACEF URN: {urn!r}", code="ACEF-020")
    return ParsedURN(
        urn_type=URNType(match.group(1)),
        uuid_str=match.group(2),
        full_urn=urn,
    )
