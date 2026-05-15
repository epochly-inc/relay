"""ACEF DSL operators — all 10 built-in operators per spec Section 3.5.

Each operator takes params and a list of records, returns (passed, evidence_refs).
Empty-set semantics:
  - Existential operators -> FAIL on zero records
  - Universal operators -> PASS (vacuous truth)
"""

from __future__ import annotations

import re
import signal
import sys
import threading
from datetime import datetime, timedelta
from typing import Any, Callable

import jsonpointer

from acef.errors import ACEFEvaluationError
from acef.models.records import RecordEnvelope

# Maximum allowed regex pattern length to mitigate ReDoS.
# Per ECMA-262 dialect requirement, patterns should be short rule-level matchers.
_MAX_REGEX_PATTERN_LENGTH = 1024

# Maximum allowed input string length for regex matching.
_MAX_REGEX_INPUT_LENGTH = 1_000_000

# Regex match timeout in seconds (only effective on Unix systems with SIGALRM).
_REGEX_TIMEOUT_SECONDS = 5


class _RegexTimeoutError(Exception):
    """Raised when a regex match exceeds the allowed timeout."""


def _regex_timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for regex timeout."""
    raise _RegexTimeoutError("Regex evaluation timed out")


def _safe_regex_search(pattern: str, text: str) -> bool:
    """Execute a regex search with length limits and optional timeout.

    Mitigates ReDoS attacks by:
    1. Limiting pattern length to _MAX_REGEX_PATTERN_LENGTH characters
    2. Limiting input text length to _MAX_REGEX_INPUT_LENGTH characters
    3. Applying a SIGALRM-based timeout on Unix systems (main thread only)

    Args:
        pattern: ECMA-262 regex pattern from DSL rule.
        text: The string value to match against.

    Returns:
        True if the pattern matches anywhere in the text.

    Raises:
        ACEFEvaluationError: If the pattern is too long, invalid, or times out.
    """
    if len(pattern) > _MAX_REGEX_PATTERN_LENGTH:
        raise ACEFEvaluationError(
            f"Regex pattern exceeds maximum length ({len(pattern)} > {_MAX_REGEX_PATTERN_LENGTH})",
            code="ACEF-045",
        )

    if len(text) > _MAX_REGEX_INPUT_LENGTH:
        raise ACEFEvaluationError(
            f"Input string exceeds maximum length for regex matching "
            f"({len(text)} > {_MAX_REGEX_INPUT_LENGTH})",
            code="ACEF-045",
        )

    # On Unix, use SIGALRM for timeout protection against catastrophic backtracking.
    # M-SCOUT-1: SIGALRM only works in the main thread of the main interpreter.
    use_alarm = (
        hasattr(signal, "SIGALRM")
        and sys.platform != "win32"
        and threading.current_thread() is threading.main_thread()
    )

    if use_alarm:
        old_handler = signal.signal(signal.SIGALRM, _regex_timeout_handler)
        signal.alarm(_REGEX_TIMEOUT_SECONDS)
        try:
            result = re.search(pattern, text) is not None
        except _RegexTimeoutError:
            raise ACEFEvaluationError(
                f"Regex evaluation timed out after {_REGEX_TIMEOUT_SECONDS}s "
                f"(possible catastrophic backtracking): {pattern!r}",
                code="ACEF-045",
            )
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        return result
    else:
        # On non-Unix systems or non-main threads, rely on pattern and input length limits only.
        return re.search(pattern, text) is not None


def _resolve_pointer(record_data: dict[str, Any], pointer: str) -> Any:
    """Resolve a JSON Pointer (RFC 6901) against a record dict.

    Returns None if the path doesn't exist (missing-path behavior per spec).
    """
    try:
        return jsonpointer.resolve_pointer(record_data, pointer)
    except jsonpointer.JsonPointerException:
        return None


def _compare(actual: Any, op: str, expected: Any) -> bool:
    """Apply a comparison operator.

    For ordering operators (gt, gte, lt, lte), incompatible types
    (e.g., dict vs int) return False instead of raising TypeError (m6 Scout R2).
    """
    if actual is None:
        # Missing path: all comparisons false except ne
        return op == "ne"

    if op == "eq":
        return actual == expected
    elif op == "ne":
        return actual != expected
    elif op == "gt":
        try:
            return actual > expected
        except TypeError:
            return False
    elif op == "gte":
        try:
            return actual >= expected
        except TypeError:
            return False
    elif op == "lt":
        try:
            return actual < expected
        except TypeError:
            return False
    elif op == "lte":
        try:
            return actual <= expected
        except TypeError:
            return False
    elif op == "in":
        if isinstance(expected, list):
            return actual in expected
        return False
    elif op == "regex":
        if not isinstance(expected, str) or not isinstance(actual, str):
            return False
        try:
            return _safe_regex_search(expected, actual)
        except ACEFEvaluationError:
            raise
        except re.error as e:
            raise ACEFEvaluationError(
                f"Invalid regex pattern: {expected!r}: {e}",
                code="ACEF-045",
            ) from e
    return False


def _filter_by_type(records: list[RecordEnvelope], record_type: str) -> list[RecordEnvelope]:
    """Filter records by record_type."""
    return [r for r in records if r.record_type == record_type]




# --- Operator implementations ---


def op_has_record_type(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """has_record_type: At least min_count records of given type exist.

    Existential operator -> FAIL on zero matching records if min_count > 0.
    """
    record_type = params["type"]
    min_count = params.get("min_count", 1)
    matching = _filter_by_type(records, record_type)
    evidence_refs = [r.record_id for r in matching]
    return len(matching) >= min_count, evidence_refs


def op_field_present(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """field_present: Every record of given type has non-null value at path.

    Universal operator -> PASS vacuously on zero records.
    """
    record_type = params["record_type"]
    field = params["field"]
    matching = _filter_by_type(records, record_type)

    if not matching:
        return True, []  # Vacuous truth

    evidence_refs: list[str] = []
    all_present = True
    for rec in matching:
        data = rec.to_jsonl_dict()
        value = _resolve_pointer(data, field)
        if value is not None:
            evidence_refs.append(rec.record_id)
        else:
            all_present = False

    return all_present, evidence_refs


def op_field_value(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """field_value: Field value satisfies comparison for every record of given type.

    Universal operator -> PASS vacuously on zero records.
    """
    record_type = params["record_type"]
    field = params["field"]
    op = params["op"]
    value = params["value"]
    matching = _filter_by_type(records, record_type)

    if not matching:
        return True, []  # Vacuous truth

    evidence_refs: list[str] = []
    all_match = True
    for rec in matching:
        data = rec.to_jsonl_dict()
        actual = _resolve_pointer(data, field)
        if _compare(actual, op, value):
            evidence_refs.append(rec.record_id)
        else:
            all_match = False

    return all_match, evidence_refs


def op_evidence_freshness(
    params: dict[str, Any],
    records: list[RecordEnvelope],
    *,
    evaluation_instant: str = "",
    package_timestamp: str = "",
    provision_effective_date: str = "",
) -> tuple[bool, list[str]]:
    """evidence_freshness: All records within scope have timestamp within max_days.

    Universal operator -> PASS vacuously on zero records.

    Per spec Section 3.7: all date-sensitive rule logic MUST use
    evaluation_instant as the single reference time. MUST NOT use
    wall-clock time during evaluation.

    Args:
        params: Operator parameters (max_days, reference_date).
        records: Records to evaluate.
        evaluation_instant: ISO 8601 evaluation timestamp.
        package_timestamp: ISO 8601 package creation timestamp.
        provision_effective_date: ISO 8601 provision effective date (M6 Implementer R2).
    """
    if not records:
        return True, []  # Vacuous truth

    max_days = params["max_days"]
    reference_date_type = params.get("reference_date", "validation_time")

    # Determine reference date per spec Section 3.7:
    # - validation_time -> evaluation_instant
    # - package_time -> metadata.timestamp
    # - obligation_effective_date -> provision effective_date (M6 Implementer R2)
    if reference_date_type == "validation_time":
        ref_str = evaluation_instant
    elif reference_date_type == "package_time":
        ref_str = package_timestamp
    elif reference_date_type == "obligation_effective_date":
        # M6 (Implementer R2): Resolve to provision's effective_date
        ref_str = provision_effective_date if provision_effective_date else evaluation_instant
    else:
        # Unknown type, fall back to evaluation_instant per spec
        ref_str = evaluation_instant

    if not ref_str:
        # Per spec Section 3.7: MUST NOT use wall-clock time during evaluation.
        # If no reference date is available, the rule cannot be evaluated.
        return True, []

    try:
        ref_dt = datetime.fromisoformat(ref_str.replace("Z", "+00:00"))
    except ValueError:
        return True, []

    cutoff = ref_dt - timedelta(days=max_days)

    evidence_refs: list[str] = []
    all_fresh = True
    for rec in records:
        try:
            rec_dt = datetime.fromisoformat(rec.timestamp.replace("Z", "+00:00"))
            if rec_dt >= cutoff:
                evidence_refs.append(rec.record_id)
            else:
                all_fresh = False
        except ValueError:
            all_fresh = False

    return all_fresh, evidence_refs


def op_attachment_exists(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """attachment_exists: At least one record of given type has an attachment.

    Existential operator -> FAIL on zero matching records.
    """
    record_type = params["record_type"]
    media_type = params.get("media_type")
    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        for att in rec.attachments:
            if media_type is None or att.media_type == media_type:
                evidence_refs.append(rec.record_id)
                break

    return len(evidence_refs) > 0, evidence_refs


def op_entity_linked(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """entity_linked: Every record of given type has at least one entity ref of given type.

    Universal operator -> PASS vacuously on zero records.
    """
    record_type = params["record_type"]
    entity_type = params["entity_type"]
    matching = _filter_by_type(records, record_type)

    if not matching:
        return True, []

    ref_field_map = {
        "subject": "subject_refs",
        "component": "component_refs",
        "dataset": "dataset_refs",
        "actor": "actor_refs",
    }
    ref_field = ref_field_map.get(entity_type)
    if ref_field is None:
        raise ACEFEvaluationError(
            f"Unknown entity_type: {entity_type!r}",
            code="ACEF-045",
        )

    evidence_refs: list[str] = []
    all_linked = True
    for rec in matching:
        refs = getattr(rec.entity_refs, ref_field, [])
        if refs:
            evidence_refs.append(rec.record_id)
        else:
            all_linked = False

    return all_linked, evidence_refs


def op_exists_where(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """exists_where: At least min_count records exist where field satisfies comparison.

    Existential operator -> FAIL on zero matching records if min_count > 0.
    """
    record_type = params["record_type"]
    field = params["field"]
    op = params["op"]
    value = params["value"]
    min_count = params.get("min_count", 1)

    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        data = rec.to_jsonl_dict()
        actual = _resolve_pointer(data, field)
        if _compare(actual, op, value):
            evidence_refs.append(rec.record_id)

    return len(evidence_refs) >= min_count, evidence_refs


def op_attachment_kind_exists(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """attachment_kind_exists: Records of given type have attachments with matching attachment_type.

    Existential operator -> FAIL on zero matching.
    """
    record_type = params["record_type"]
    attachment_type = params["attachment_type"]
    min_count = params.get("min_count", 1)

    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        for att in rec.attachments:
            if att.attachment_type == attachment_type:
                evidence_refs.append(rec.record_id)
                break

    return len(evidence_refs) >= min_count, evidence_refs


def op_bundle_signed(
    params: dict[str, Any],
    records: list[RecordEnvelope],
    *,
    signature_count: int = 0,
    signature_algorithms: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """bundle_signed: Bundle has at least min_signatures valid signatures.

    Existential operator on signatures (not records).
    """
    min_signatures = params.get("min_signatures", 1)
    required_alg = params.get("required_alg")

    effective_count = signature_count
    if required_alg and signature_algorithms:
        effective_count = sum(1 for a in signature_algorithms if a in required_alg)

    return effective_count >= min_signatures, []


def op_record_attested(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """record_attested: At least min_count records have valid attestation blocks.

    Existential operator -> FAIL on zero matching.
    """
    record_type = params["record_type"]
    min_count = params.get("min_count", 1)

    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        if rec.attestation and rec.attestation.signature:
            evidence_refs.append(rec.record_id)

    return len(evidence_refs) >= min_count, evidence_refs


# --- Operator registry ---

OperatorFunc = Callable[..., tuple[bool, list[str]]]

OPERATOR_REGISTRY: dict[str, OperatorFunc] = {
    "has_record_type": op_has_record_type,
    "field_present": op_field_present,
    "field_value": op_field_value,
    "evidence_freshness": op_evidence_freshness,
    "attachment_exists": op_attachment_exists,
    "entity_linked": op_entity_linked,
    "exists_where": op_exists_where,
    "attachment_kind_exists": op_attachment_kind_exists,
    "bundle_signed": op_bundle_signed,
    "record_attested": op_record_attested,
}
