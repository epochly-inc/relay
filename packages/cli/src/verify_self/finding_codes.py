"""Closed enum of ``rly verify-self`` finding codes (VAL-W5-036).

Each invariant checker reports findings whose ``code`` field is drawn
from this enum. A check that emits a code outside this enum is itself a
contract violation and the runner refuses the result.

Per CLAUDE.md "Evidence binds. Narrative doesn't." every finding carries
``{file, line, code, suggested_fix}``; the ``code`` value is the stable
machine identifier and the enum below is the single source of truth.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Final

# -----------------------------------------------------------------------------
# Banned-pattern findings (no-todo-fixme check; VAL-W5-032)
# -----------------------------------------------------------------------------

#: Source contains a TODO/FIXME/XXX/HACK marker outside test paths.
RELAY_VERIFY_SELF_TODO_FIXME: Final[str] = "RELAY-VERIFY-SELF-TODO-FIXME"

#: Source contains a banned process-control primitive
#: (``pkill``/``killall``).
RELAY_VERIFY_SELF_KILL_BY_NAME: Final[str] = "RELAY-VERIFY-SELF-KILL-BY-NAME"

#: Source contains ``pytest.mark.skip`` (banned per CLAUDE.md
#: banned pattern #7).
RELAY_VERIFY_SELF_PYTEST_SKIP: Final[str] = "RELAY-VERIFY-SELF-PYTEST-SKIP"

#: Source contains banned product copy
#: (``compliant`` / ``certified`` / ``AI Act-approved`` /
#: ``guaranteed AI Act compliance``).
RELAY_VERIFY_SELF_BANNED_COPY: Final[str] = "RELAY-VERIFY-SELF-BANNED-COPY"

# -----------------------------------------------------------------------------
# Mocks-in-non-test findings (no-mocks-in-prod check; VAL-W5-033)
# -----------------------------------------------------------------------------

#: Production source under ``packages/`` / ``services/`` / ``apps/``
#: imports a mock primitive (``unittest.mock``, ``MagicMock``, ``@patch``,
#: ``@mock.``) outside test paths.
RELAY_VERIFY_SELF_MOCK_IN_SOURCE: Final[str] = "RELAY-VERIFY-SELF-MOCK-IN-SOURCE"

# -----------------------------------------------------------------------------
# Atomic-primitives findings (atomic-primitives-only check; VAL-W5-034)
# -----------------------------------------------------------------------------

#: Production source bypasses the four atomic persistence primitives
#: (``db.execute(``, ``s3.put_object(``, ``queue.send(``, or
#: ``open(..., 'w')`` outside ``primitives/``).
RELAY_VERIFY_SELF_PRIMITIVE_BYPASS: Final[str] = (
    "RELAY-VERIFY-SELF-PRIMITIVE-BYPASS"
)

# -----------------------------------------------------------------------------
# Control-plane-write findings (control-plane-write-only check; VAL-W5-035)
# -----------------------------------------------------------------------------

#: Source outside ``services/result-writer/`` and ``services/gate-engine/``
#: contains a direct ``INSERT/UPDATE`` against ``run_results`` or
#: ``gate_decisions``.
RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP: Final[str] = (
    "RELAY-VERIFY-SELF-CANONICAL-WRITE-OUTSIDE-CP"
)

# -----------------------------------------------------------------------------
# Gate-engine invariants (W8.2 VAL-W8-040)
# -----------------------------------------------------------------------------

#: The W8.2 migration is missing one of the required gate-engine
#: invariants: role-gate trigger, immutability trigger, evidence-bundle
#: FK trigger, signature-required trigger, or bundle-manifest-match
#: trigger. Each absent trigger is one finding so remediation is
#: targeted.
RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING: Final[str] = (
    "RELAY-VERIFY-SELF-GATE-INVARIANT-MISSING"
)

# -----------------------------------------------------------------------------
# M09 crypto-verifier-implemented findings
# -----------------------------------------------------------------------------
#
# After M09 (real Sigstore + Rekor + TSA crypto wired) the three
# ``*_CRYPTO_IMPLEMENTED`` flags MUST be True. A False value indicates
# the verifier has reverted to fail-closed mode and the public trust
# anchor cannot be exercised. Each flag has its own finding code so
# remediation is targeted.

#: The Sigstore verifier (``VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED`` in
#: ``packages/cli/src/relay_cli/bundle.py``) is False; real cosign-bundle
#: cryptographic verification is disabled.
RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED: Final[str] = (
    "RELAY-VERIFY-SELF-SIGSTORE-NOT-IMPLEMENTED"
)

#: The Rekor verifier (``REKOR_CRYPTO_IMPLEMENTED`` in
#: ``packages/cli/src/relay_cli/commands/verify_install.py``) is False;
#: transparency-log inclusion-proof verification is disabled.
RELAY_VERIFY_SELF_REKOR_NOT_IMPLEMENTED: Final[str] = (
    "RELAY-VERIFY-SELF-REKOR-NOT-IMPLEMENTED"
)

#: The TSA verifier (``TSA_CRYPTO_IMPLEMENTED`` in
#: ``packages/verifier/src/relay_verifier/tsa.py``) is False; RFC 3161
#: TimeStampResp ASN.1 verification is disabled.
RELAY_VERIFY_SELF_TSA_NOT_IMPLEMENTED: Final[str] = (
    "RELAY-VERIFY-SELF-TSA-NOT-IMPLEMENTED"
)

# -----------------------------------------------------------------------------
# Closed enum
# -----------------------------------------------------------------------------

#: The closed enum of finding codes. Any code emitted by a checker that is
#: NOT a member of this set is a contract violation; the runner refuses
#: such results so the JSON envelope cannot leak ad-hoc strings.
FINDING_CODES: Final[frozenset[str]] = frozenset(
    {
        RELAY_VERIFY_SELF_TODO_FIXME,
        RELAY_VERIFY_SELF_KILL_BY_NAME,
        RELAY_VERIFY_SELF_PYTEST_SKIP,
        RELAY_VERIFY_SELF_BANNED_COPY,
        RELAY_VERIFY_SELF_MOCK_IN_SOURCE,
        RELAY_VERIFY_SELF_PRIMITIVE_BYPASS,
        RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP,
        RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
        RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED,
        RELAY_VERIFY_SELF_REKOR_NOT_IMPLEMENTED,
        RELAY_VERIFY_SELF_TSA_NOT_IMPLEMENTED,
    }
)


__all__ = [
    "FINDING_CODES",
    "RELAY_VERIFY_SELF_BANNED_COPY",
    "RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP",
    "RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING",
    "RELAY_VERIFY_SELF_KILL_BY_NAME",
    "RELAY_VERIFY_SELF_MOCK_IN_SOURCE",
    "RELAY_VERIFY_SELF_PRIMITIVE_BYPASS",
    "RELAY_VERIFY_SELF_PYTEST_SKIP",
    "RELAY_VERIFY_SELF_REKOR_NOT_IMPLEMENTED",
    "RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED",
    "RELAY_VERIFY_SELF_TODO_FIXME",
    "RELAY_VERIFY_SELF_TSA_NOT_IMPLEMENTED",
]
