"""x-relay/data-provenance-record dataclass (W1-5 / VAL-V2M01-032).

Mirrors the canonical Postgres ``data_provenance_records`` table declared at
``packages/schemas/sql/0006_human_oversight.sql`` and its sidecar SQLite
mirror at ``apps/local-sidecar/migrations/0014_human_oversight.sql``.

This dataclass is intentionally NOT registered in
``relay_extensions.RELAY_EXTENSION_NAMESPACES`` (that 10-tuple is locked by
VAL-W11-009 and only enumerates the ten ACEF Core extension namespaces). It
is the canonical Postgres-table mirror dataclass that callers in the
evidence-claim path use to construct typed payloads from rows in
``data_provenance_records`` for inclusion in evidence bundles under
``bundle.namespaces["x-relay"]``.

The wire-format Pydantic envelope at
``packages/schemas/python/relay_schemas/envelopes.py``
(``DataProvenanceRecord``) uses the ``relay.data_provenance_record.v1``
schema_version literal for canonical control-plane writes. This ACEF
dataclass uses ``x-relay.data-provenance-record.v1`` so the
namespace-prefixed ACEF wire form does not collide with the
control-plane wire form. Same decoupling pattern as
``HumanOversightEvent`` and ``DataQualityCheck``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.data-provenance-record.v1"

# Closed enum members locked at the SQL + wire-format layers (spec sectionAE
# lines 5531-5533). Mirrored here so callers can validate before submission.
SOURCE_KIND_MEMBERS: Final[frozenset[str]] = frozenset(
    {
        "first_party",
        "licensed",
        "public_domain",
        "web_scrape",
        "synthetic",
        "user_generated",
    }
)


@dataclass(frozen=True)
class DataProvenanceRecord:
    """DataProvenanceRecord extension; spec sectionAE lines 5527-5539.

    Required fields mirror the SQL NOT NULL columns:
    ``provenance_id``, ``project_id``, ``dataset_id``, ``source_kind``.
    ``evidence_refs`` defaults to the empty list so a freshly-constructed
    record can be progressively enriched before sealing.
    """

    provenance_id: str
    project_id: str
    dataset_id: str
    source_kind: str
    license_ref: str | None = None
    acquired_at: str | None = None
    acquired_by_user_id: str | None = None
    notes: str | None = None
    evidence_refs: tuple[Any, ...] = field(default_factory=tuple)
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict form.

        ``evidence_refs`` is exported as a list (JSON has no tuple
        primitive). The remaining fields pass through dataclass-asdict
        directly.
        """
        d = asdict(self)
        d["evidence_refs"] = list(self.evidence_refs)
        return d


__all__ = [
    "SCHEMA_VERSION",
    "SOURCE_KIND_MEMBERS",
    "DataProvenanceRecord",
]
