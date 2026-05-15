"""ACEF records utility — sorting, sharding, and shared record operations.

Provides deterministic record ordering and shard boundary computation
per spec Section 3.1.1. These functions are shared between the package
builder (Layer 3) and the export module (Layer 4) to avoid a
dependency direction violation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from acef.integrity import canonicalize

if TYPE_CHECKING:
    from acef.models.records import RecordEnvelope

# Maximum shard size in bytes (256 MB)
_SHARD_SIZE_LIMIT = 256 * 1024 * 1024
# Maximum records per shard
_SHARD_RECORD_LIMIT = 100_000


def canonicalize_record(record_dict: dict[str, Any]) -> bytes:
    """Canonicalize a single record via RFC 8785.

    Public function shared between records_util (shard boundary computation)
    and export.py (JSONL writing).
    """
    return canonicalize(record_dict)


def sort_records(records: list[RecordEnvelope]) -> list[RecordEnvelope]:
    """Sort records by timestamp ascending, then record_id ascending.

    Per spec: deterministic ordering for conformance.
    """
    return sorted(records, key=lambda r: (r.timestamp, r.record_id))


def compute_shard_boundaries(records: list[RecordEnvelope]) -> list[list[RecordEnvelope]]:
    """Split records into shards per spec deterministic algorithm.

    Split at the earlier of 100,000 records or the last complete record
    before 256 MB.
    """
    if len(records) <= _SHARD_RECORD_LIMIT:
        # Check if total size exceeds limit
        total_size = 0
        for rec in records:
            data = rec.to_jsonl_dict()
            total_size += len(canonicalize_record(data)) + 1  # +1 for \n
        if total_size <= _SHARD_SIZE_LIMIT:
            return [records]

    shards: list[list[Any]] = []
    current_shard: list[Any] = []
    current_size = 0

    for rec in records:
        data = rec.to_jsonl_dict()
        rec_size = len(canonicalize_record(data)) + 1

        should_split = (
            len(current_shard) >= _SHARD_RECORD_LIMIT
            or (current_size + rec_size > _SHARD_SIZE_LIMIT and current_shard)
        )

        if should_split:
            shards.append(current_shard)
            current_shard = []
            current_size = 0

        current_shard.append(rec)
        current_size += rec_size

    if current_shard:
        shards.append(current_shard)

    return shards
