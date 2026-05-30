"""Redaction validation fixtures harness (M08-W8 / VAL-V2M08-032).

Spec G.2 lines 4140-4142 define a ``validation_fixtures`` array inside
``redaction_policies`` that pins every policy to a reproducible test
corpus:

  ``validation_fixtures``: [
    { "input_ref": "fixture://prompt-with-email",
      "expected_output_digest": "sha256-..." }
  ]

This module loads each fixture, runs the declared policy against the
fixture's ``input_ref`` payload, computes the SHA-256 digest of the
canonical JCS bytes of the redacted output, and asserts byte-equality
against ``expected_output_digest``. A mismatch raises a structured
:class:`FixtureMismatch` that the ``relay contract publish`` /
``relay redaction publish`` paths surface as the word-form code
``RELAY-REDACT-FIXTURE-MISMATCH`` (HTTP 422).

The harness is intentionally library-shaped: tests call into it
directly. A small ``relay`` CLI wrapper can later invoke
:func:`validate_policy_fixtures` to make the harness reachable from
the publish flow.

Surface:

  - :class:`Fixture` -- a single ``(input_ref, expected_output_digest,
    input_payload)`` triple.
  - :class:`FixtureResult` -- per-fixture outcome from
    :func:`validate_policy_fixtures`.
  - :class:`FixtureMismatch` -- raised by :func:`validate_policy_or_raise`
    on the first mismatch (publish-path semantic).
  - :func:`load_fixtures_from_policy_body` -- resolve a policy dict's
    ``validation_fixtures[]`` array into concrete :class:`Fixture`
    instances by looking up each ``input_ref`` in the caller-supplied
    payload registry.
  - :func:`validate_policy_fixtures` -- run every fixture, return a
    list of :class:`FixtureResult` (each carries ``ok``,
    ``computed_digest``, optional ``error``).

Input resolution: ``input_ref`` strings follow the spec G.2 example
form ``fixture://<name>``. The harness consults a caller-supplied
:type:`FixturePayloadRegistry` (a dict mapping ``input_ref`` to
payload dict) -- the OSS profile loads it from disk; tests build it
in-memory.

Determinism: the harness uses the SDK's
:func:`relay.redaction.redact_capture_payload` directly, which emits
JCS-canonical bytes. The digest is the SHA-256 hex of those bytes.
Two harness runs against the same fixture + policy + salt produce
identical digests (VAL-V2M08-027 determinism guarantee, spec G.3).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from relay.errors import RelayPolicyError
from relay.redaction import (
    RedactionEngine,
    RedactionPolicy,
    SaltProvider,
    redact_capture_payload,
)

# Word-form code per spec G + contract VAL-V2M08-032. Word-form codes
# follow the precedent in packages/schemas/raw/relay-error-codes.yaml
# lines 112-121 (the numeric registry refuses word-form codes by
# design; both forms coexist).
FIXTURE_MISMATCH_CODE: Final[str] = "RELAY-REDACT-FIXTURE-MISMATCH"

# HTTP status for publish-time rejection of a policy whose fixture
# digest does not match its expectation. 422 matches the existing
# RELAY-REDACT-014 ReDoS rejection code (spec AI line 5665) -- the
# publish path consistently surfaces redaction-policy violations as
# unprocessable-entity.
FIXTURE_MISMATCH_HTTP_STATUS: Final[int] = 422


# Mapping from ``input_ref`` (e.g. ``"fixture://prompt-with-email"``)
# to the payload dict the policy should redact.
FixturePayloadRegistry = Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class Fixture:
    """A single resolved validation fixture."""

    input_ref: str
    expected_output_digest: str
    input_payload: Mapping[str, Any]


@dataclass(frozen=True)
class FixtureResult:
    """Per-fixture outcome of :func:`validate_policy_fixtures`."""

    input_ref: str
    expected_output_digest: str
    computed_digest: str
    ok: bool
    error: str | None = None


class FixtureMismatch(Exception):
    """Raised by :func:`validate_policy_or_raise` on the first mismatch.

    Carries the offending fixture's ``input_ref`` + ``expected_digest`` +
    ``computed_digest`` in ``details`` so the caller (e.g.
    ``relay contract publish``) can render a precise envelope.

    Deliberately NOT a subclass of :class:`relay.errors.RelayPolicyError`.
    The W3-029 envelope-discovery test walks every concrete
    :class:`relay.errors.RelayError` subclass and instantiates each via
    ``cls("message")``. The harness exception's structured keyword-only
    constructor is incompatible with that calling convention; keeping
    the class outside the :class:`RelayError` hierarchy preserves the
    structured constructor contract for harness callers while staying
    out of the envelope-discovery tree. The publish path consumes the
    ``code`` and ``http_status`` attributes directly when rendering the
    wire envelope; subclass relationship to :class:`RelayError` is not
    load-bearing.
    """

    def __init__(
        self,
        *,
        input_ref: str,
        expected_output_digest: str,
        computed_digest: str,
    ) -> None:
        message = (
            f"redaction validation fixture {input_ref!r} expected digest "
            f"{expected_output_digest!r} but computed {computed_digest!r}"
        )
        super().__init__(message)
        self.message: str = message
        self.code: str = FIXTURE_MISMATCH_CODE
        self.http_status: int = FIXTURE_MISMATCH_HTTP_STATUS
        self.details: dict[str, Any] = {
            "reason": "fixture_digest_mismatch",
            "input_ref": input_ref,
            "expected_output_digest": expected_output_digest,
            "computed_digest": computed_digest,
            "code": FIXTURE_MISMATCH_CODE,
            "http_status": FIXTURE_MISMATCH_HTTP_STATUS,
        }


def _normalize_digest(value: object) -> str:
    """Return ``value`` without its ``sha256-`` prefix, lowercased.

    Spec G.2 example uses ``"sha256-..."`` form for clarity; the
    harness compares the raw hex tail. We accept either ``"sha256-<hex>"``
    or ``"<hex>"`` directly and normalise both to the bare hex form.

    ``value`` is typed ``object`` because callers pass raw policy-body
    values (``Mapping.get(...)`` results) whose type is unknown; the
    non-string case is validated and rejected below.
    """
    if not isinstance(value, str):
        raise RelayPolicyError(
            "expected_output_digest must be a string",
            details={"reason": "expected_digest_wrong_type"},
        )
    raw = value.strip().lower()
    if raw.startswith("sha256-"):
        raw = raw[len("sha256-") :]
    if not raw:
        raise RelayPolicyError(
            "expected_output_digest must be non-empty after stripping "
            "the optional 'sha256-' prefix",
            details={"reason": "expected_digest_empty"},
        )
    return raw


def load_fixtures_from_policy_body(
    *,
    policy_body: Mapping[str, Any],
    payload_registry: FixturePayloadRegistry,
) -> list[Fixture]:
    """Resolve every ``validation_fixtures[]`` entry to a :class:`Fixture`.

    Raises:
        RelayPolicyError: when the policy body is malformed, when a
            fixture entry lacks ``input_ref`` or
            ``expected_output_digest``, or when an ``input_ref`` is not
            present in ``payload_registry`` (the caller MUST register
            every referenced fixture before invoking the harness;
            silent-skip would mask a mis-pinned corpus).
    """
    if not isinstance(policy_body, Mapping):
        raise RelayPolicyError(
            "policy_body must be a Mapping",
            details={"reason": "policy_body_wrong_type"},
        )
    raw_fixtures = policy_body.get("validation_fixtures")
    if raw_fixtures is None:
        return []
    if not isinstance(raw_fixtures, list):
        raise RelayPolicyError(
            "validation_fixtures must be a list",
            details={"reason": "validation_fixtures_wrong_type"},
        )
    resolved: list[Fixture] = []
    for idx, entry in enumerate(raw_fixtures):
        if not isinstance(entry, Mapping):
            raise RelayPolicyError(
                f"validation_fixtures[{idx}] must be a dict",
                details={"reason": "fixture_entry_wrong_type", "index": idx},
            )
        input_ref = entry.get("input_ref")
        if not isinstance(input_ref, str) or not input_ref.strip():
            raise RelayPolicyError(
                f"validation_fixtures[{idx}].input_ref must be a non-empty string",
                details={"reason": "input_ref_missing", "index": idx},
            )
        expected_digest = entry.get("expected_output_digest")
        normalized = _normalize_digest(expected_digest)
        if input_ref not in payload_registry:
            raise RelayPolicyError(
                f"validation_fixtures[{idx}].input_ref {input_ref!r} is "
                "not present in the payload registry; cannot validate a "
                "fixture without its declared input payload",
                details={
                    "reason": "input_ref_unknown",
                    "index": idx,
                    "input_ref": input_ref,
                },
            )
        payload = payload_registry[input_ref]
        if not isinstance(payload, Mapping):
            raise RelayPolicyError(
                f"payload_registry[{input_ref!r}] must be a Mapping",
                details={"reason": "payload_wrong_type", "input_ref": input_ref},
            )
        resolved.append(
            Fixture(
                input_ref=input_ref,
                expected_output_digest=normalized,
                input_payload=payload,
            )
        )
    return resolved


def _compute_digest_for_payload(
    *,
    engine: RedactionEngine,
    payload: Mapping[str, Any],
) -> str:
    """Redact ``payload`` and return the SHA-256 hex of the JCS bytes."""
    redacted_bytes = redact_capture_payload(engine, dict(payload))
    return hashlib.sha256(redacted_bytes).hexdigest()


def validate_policy_fixtures(
    *,
    policy_body: Mapping[str, Any],
    payload_registry: FixturePayloadRegistry,
    salt_provider: SaltProvider,
) -> list[FixtureResult]:
    """Run every fixture in ``policy_body`` and return per-fixture results.

    Does NOT raise on a digest mismatch; the caller inspects each
    :class:`FixtureResult` and decides whether to surface a publish
    rejection. For the publish-path "first mismatch raises" semantic
    use :func:`validate_policy_or_raise`.

    Args:
        policy_body: The full ``redaction_policies.body`` dict (spec G.2
            schema). Parsed via :meth:`RedactionPolicy.load`.
        payload_registry: ``{input_ref: payload}`` lookup. Every
            ``validation_fixtures[].input_ref`` MUST be present.
        salt_provider: The same salt_provider the SDK would use at
            runtime (the harness MUST run under the SAME salt the
            production policy will use, otherwise hash matchers would
            produce different digests and every fixture would
            mismatch).
    """
    policy = RedactionPolicy.load(dict(policy_body))
    engine = RedactionEngine(policy=policy, salt_provider=salt_provider)
    fixtures = load_fixtures_from_policy_body(
        policy_body=policy_body,
        payload_registry=payload_registry,
    )
    results: list[FixtureResult] = []
    for fixture in fixtures:
        try:
            computed = _compute_digest_for_payload(
                engine=engine,
                payload=fixture.input_payload,
            )
        except RelayPolicyError as exc:
            results.append(
                FixtureResult(
                    input_ref=fixture.input_ref,
                    expected_output_digest=fixture.expected_output_digest,
                    computed_digest="",
                    ok=False,
                    error=str(exc),
                )
            )
            continue
        ok = computed == fixture.expected_output_digest
        results.append(
            FixtureResult(
                input_ref=fixture.input_ref,
                expected_output_digest=fixture.expected_output_digest,
                computed_digest=computed,
                ok=ok,
                error=None if ok else "digest_mismatch",
            )
        )
    return results


def validate_policy_or_raise(
    *,
    policy_body: Mapping[str, Any],
    payload_registry: FixturePayloadRegistry,
    salt_provider: SaltProvider,
) -> list[FixtureResult]:
    """Run :func:`validate_policy_fixtures` and raise on first mismatch.

    Returns the result list on full pass (so the caller can log
    per-fixture digests for evidence). Raises :class:`FixtureMismatch`
    on the first failed fixture; the exception carries the offending
    ``input_ref`` + expected/computed digests.
    """
    results = validate_policy_fixtures(
        policy_body=policy_body,
        payload_registry=payload_registry,
        salt_provider=salt_provider,
    )
    for result in results:
        if not result.ok:
            raise FixtureMismatch(
                input_ref=result.input_ref,
                expected_output_digest=result.expected_output_digest,
                computed_digest=result.computed_digest,
            )
    return results


def compute_expected_digest(
    *,
    policy_body: Mapping[str, Any],
    payload: Mapping[str, Any],
    salt_provider: SaltProvider,
) -> str:
    """Return the SHA-256 hex digest of the redacted JCS bytes.

    Helper for fixture authors: feed the policy + a candidate payload,
    capture the digest, and pin it into the policy's
    ``validation_fixtures[].expected_output_digest`` field. Deterministic
    when the policy + salt are deterministic.
    """
    policy = RedactionPolicy.load(dict(policy_body))
    engine = RedactionEngine(policy=policy, salt_provider=salt_provider)
    return _compute_digest_for_payload(engine=engine, payload=payload)


__all__ = [
    "FIXTURE_MISMATCH_CODE",
    "FIXTURE_MISMATCH_HTTP_STATUS",
    "Fixture",
    "FixtureMismatch",
    "FixturePayloadRegistry",
    "FixtureResult",
    "compute_expected_digest",
    "load_fixtures_from_policy_body",
    "validate_policy_fixtures",
    "validate_policy_or_raise",
]
