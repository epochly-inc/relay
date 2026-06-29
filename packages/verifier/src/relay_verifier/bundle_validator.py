"""End-to-end evidence bundle validator (W10.4 VAL-W10-021..042).

Orchestrates the verifier sub-modules into a single
:func:`validate_bundle` entry point that produces the canonical verifier
output JSON envelope (see ``packages/schemas/raw/verifier-output.yaml``;
schema_version ``relay.verifier.output.v1``).

Validation pipeline (each step contributes to the output):

  1. **Archive-bomb gate** (VAL-W10-036) -- the bundle producer is
     expected to inflate any zipped archive before calling
     :func:`validate_bundle`; the validator accepts a parsed bundle
     dict + a `claims_count_observed` and `uncompressed_size_bytes`
     pair so the caller can enforce limits up-front. Hard limits are
     `MAX_BUNDLE_ENTRIES = 4096` and `MAX_BUNDLE_BYTES = 256 MiB`
     (eng plan + spec section K line 5662).
  2. **Structure + per-claim digest** (VAL-W10-020 / 022) -- each
     `evidence_refs[].digest` is compared against
     :func:`relay_verifier.canonical.bundle_digest` of the referenced
     artifact.
  3. **JWS verification** (VAL-W10-021 / 023 / 014) -- via
     :func:`relay_verifier.verifier.verify_bundle`.
  4. **Merkle root** (VAL-W10-024) -- via
     :func:`relay_verifier.merkle.compute_merkle_root`.
  5. **TSA timestamp** (VAL-W10-025..027) -- via
     :func:`relay_verifier.tsa.validate_tsa_token`.
  6. **Transparency log inclusion** (VAL-W10-028..030) -- via
     :func:`relay_verifier.transparency_log.verify_log_inclusion`.
  7. **Signer key lifecycle** (VAL-W10-031..034) -- via
     :func:`relay_verifier.key_lifecycle.check_signing_key_lifecycle`.
  8. **trust_anchor surfacing** (VAL-W10-035 / 041) -- verbatim echo
     plus the local_dev WARN.
  9. **Subject resolution** (VAL-W10-037 / 038) -- via
     :func:`relay_verifier.retention.resolve_subject`.

Output is a Python dict whose JSON serialisation matches the
``relay.verifier.output.v1`` envelope.

The validator does not call sys.exit; the CLI wrapper consumes
``output["overall"]`` and translates to an exit code (0 for "pass",
non-zero otherwise; "warn" mode treated as pass per VAL-W10-028).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from typing import Any, Final

from .bundle_paths import check_artifact_path
from .canonical import (
    bundle_digest,
    jcs_canonicalize,
    screen_noncanonicalizable,
)
from .key_lifecycle import (
    RELAY_EVID_041,
    RELAY_EVID_042,
    check_signing_key_lifecycle,
)
from .merkle import compute_merkle_root
from .retention import (
    SUBJECT_RESOLUTION_UNKNOWN,
    SubjectStore,
    resolve_subject,
)
from .transparency_log import verify_log_inclusion
from .tsa import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    RELAY_EVID_031,
    RELAY_EVID_038,
    load_bundled_tsa_chain,
    load_tsa_chain_pem_bytes,
    validate_tsa_token,
)
from .verifier import _select_jwk, verify_bundle

# Output schema version (single source of truth; cross-checked by the
# verifier-output schema guard test against the YAML at
# packages/schemas/raw/verifier-output.yaml).
VERIFIER_OUTPUT_SCHEMA: Final[str] = "relay.verifier.output.v1"

# Archive-bomb limits (VAL-W10-036; spec K line 5662).
MAX_BUNDLE_ENTRIES: Final[int] = 4096
MAX_BUNDLE_BYTES: Final[int] = 256 * 1024 * 1024  # 256 MiB

RELAY_EVID_024: Final[str] = "RELAY-EVID-024"
"""Archive-bomb limit exceeded (VAL-W10-036)."""

RELAY_EVID_014: Final[str] = "RELAY-EVID-014"
"""Evidence-bundle integrity failure (per-claim signature)."""

RELAY_EVID_040: Final[str] = "RELAY-EVID-040"
"""Merkle root mismatch (VAL-W10-024)."""

RELAY_EVID_DECIDED_AT_MISSING: Final[str] = "RELAY-EVID-DECIDED-AT-MISSING"
"""Bundle is missing the canonical ``decided_at`` TSA-binding anchor.

Per spec section AB the TSA token's binding skew check compares
``tsa_token.gen_time`` against ``decided_at``. The validator MUST NOT
silently fall back to ``generated_at`` or any other timestamp field --
doing so silently moves the trust boundary. A bundle missing
``decided_at`` is rejected fail-closed and surfaces this code so
operators can fix the producer."""

# w8-trust-anchor: cross-signing cap (VAL-V2M08-041; spec L.5 line 4481).
MAX_BUNDLE_SIGNATURES: Final[int] = 4
"""Maximum number of cross-signing signatures the verifier will accept
on a single bundle. Per spec section L.5 line 4481:

    "Bundles can carry up to 4 signatures; verifier reports
    signatures_checked[] with valid/invalid per signature."

A bundle carrying more than this many signatures is rejected fail-closed
BEFORE any per-signature verification work runs. The cap defends against
two abuse patterns: (1) a malicious producer padding a bundle with
hundreds of dummy signatures to amplify verification cost (DoS); and
(2) a producer abusing the cross-signing slot for non-signature data.
Both are blocked by surfacing :data:`RELAY_EVID_SIGCOUNT_EXCEEDED`
without invoking any cryptographic primitive on the over-cap input."""

RELAY_EVID_SIGCOUNT_EXCEEDED: Final[str] = "RELAY-EVID-SIGCOUNT-EXCEEDED"
"""Bundle carries more than :data:`MAX_BUNDLE_SIGNATURES` signatures
(VAL-V2M08-041). Surfaced in :attr:`validate_bundle` output as a
structured error with ``signatures_present`` echoing the wire count so
operators can identify which producer emitted the over-cap bundle."""

RELAY_EVID_MISSING_TRUST_ANCHOR: Final[str] = "RELAY-EVID-MISSING-TRUST-ANCHOR"
"""Bundle is missing the top-level ``trust_anchor`` field (or the field
is not a non-empty string) (VAL-V2M08-043). Per spec section AO.4 line
6166 every signed bundle MUST declare its trust anchor; absence means
the verifier cannot classify the bundle against the operator's trust
posture and the bundle is rejected fail-closed."""

# Trust-anchor "local_dev" sentinel (per spec section AO.4 line 6166).
TRUST_ANCHOR_LOCAL_DEV: Final[str] = "local_dev"
WARN_LOCAL_DEV_UNSUPPORTED: Final[str] = "local_dev_unsupported_for_audit"

# w8-trust-anchor: trust_anchor_class output enum (VAL-V2M08-044).
# Per spec section AO.4 lines 6164-6168 the verifier MUST classify the
# bundle's declared trust_anchor into one of three buckets:
#
#   * relay_inc       -- the Relay-Inc default JWKS URL (or any URL
#                        whose host is ``relay.epochly.com`` with the
#                        canonical ``/.well-known/jwks.json`` path).
#   * untrusted_local -- the ``local_dev`` sentinel emitted by the OSS
#                        local signer. NEVER auto-promotes to
#                        ``relay_inc`` regardless of which JWKS the
#                        bundle's signature happens to verify under.
#   * byo             -- everything else (a third-party operator's BYO
#                        anchor URL or any non-Relay-Inc string).
#
# The classification is computed from the BUNDLE's declared
# ``trust_anchor`` field alone -- NOT from the JWKS URL the verifier
# happens to be configured with. This is the load-bearing guarantee of
# VAL-V2M08-044: a local_dev bundle stays untrusted_local even if the
# operator runs the verifier under a Relay-Inc anchor.
TRUST_ANCHOR_CLASS_RELAY_INC: Final[str] = "relay_inc"
TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL: Final[str] = "untrusted_local"
TRUST_ANCHOR_CLASS_BYO: Final[str] = "byo"

# V3M1-F07: signer_role enum (VAL-V3M1-018; spec K line 4427).
#
# Per spec K rule line 4427 ("The signer can only be the control-plane
# evidence-signer service for hosted bundles. Local OSS bundles can be
# signed with a local key; the verifier reports the trust path.") the
# verifier MUST surface a signer_role classification on every output so
# auditors can attribute the bundle to one of three trust paths.
#
# The classification derives ONLY from the bundle's declared trust_anchor
# value (mirroring the trust_anchor_class derivation rule for VAL-V2M08-044),
# never from the JWKS the verifier is configured with: a local_dev bundle
# stays signer_role='local_dev' even when the verifier is running under the
# Relay-Inc default anchor. This is the load-bearing no-auto-promotion
# guarantee.
SIGNER_ROLE_CONTROL_PLANE: Final[str] = "control_plane"
"""Bundle declares the Relay-Inc default trust_anchor URL; the bundle's
signer is attributable to the control-plane evidence-signer service."""

SIGNER_ROLE_LOCAL_DEV: Final[str] = "local_dev"
"""Bundle declares ``trust_anchor: 'local_dev'``; the bundle's signer is
the OSS local-dev signer. Auditors treat these bundles as informational
only -- they are NOT acceptable evidence for audit."""

SIGNER_ROLE_UNKNOWN: Final[str] = "unknown"
"""Bundle's declared trust_anchor classifies as BYO (third-party anchor)
or is missing entirely. The verifier cannot attribute the bundle to
either trust path; consumers branching on signer_role see this default
rather than an empty string."""

# V3M1-F07: namespace-key closed-set rejection (VAL-V3M1-022; spec K
# lines 4421-4423).
#
# Each claim's ``namespaces`` dict is restricted to the closed set
# {x-relay} (extensible only via spec amendment). Any other top-level
# key (e.g. ``x-attacker``) triggers a structured rejection with the
# code below. Empty or absent ``namespaces`` is accepted (the field is
# optional per spec K line 4421-4423).
RELAY_EVID_NAMESPACE_UNKNOWN: Final[str] = "RELAY-EVID-NAMESPACE-UNKNOWN"
"""Code surfaced when a claim's ``namespaces`` dict contains a key
outside the closed set ``{x-relay}`` (VAL-V3M1-022)."""

# V3M1-F07: closed set of allowed top-level keys on EvidenceClaim.namespaces.
# Adding a new key here is a spec amendment, not a routine PR.
_ALLOWED_NAMESPACE_KEYS: Final[frozenset[str]] = frozenset({"x-relay"})

# Default trust-anchor URL is owned by constants.py; the validator does
# not paste the literal here (CLAUDE.md banned pattern #13 + VAL-W10-001
# source-grep guard).


def _py_ascii(value: Any) -> str:
    """ASCII-safe repr for attacker-controllable message operands (HIGH #4).

    Equivalent to the builtin ``ascii()``: like ``repr()`` but every non-ASCII
    code point is escaped (``\\xNN`` for cp<=0xff, ``\\uNNNN`` for cp<=0xffff,
    ``\\U`` + 8 hex for astral). Plain ``repr()`` keeps PRINTABLE non-ASCII
    verbatim while escaping non-printable non-ASCII (C1 controls, U+00A0,
    format/separator chars like U+200B/U+2028/U+FEFF) -- a "printable"
    distinction that depends on the Unicode database and cannot be mirrored
    byte-for-byte by the TypeScript verifier (packages/verifier-typescript
    bundle_validator.ts ``pyReprStr``). Message operands here -- namespace
    keys, artifact ids, digests, field names -- are attacker-controllable, so
    a divergence on an interior non-printable non-ASCII code point would make
    the two verifiers emit non-identical ``message`` bytes for the same wire
    input (a P0 Py<->TS parity break). Routing every operand through
    ``ascii()`` removes the distinction: both runtimes escape ALL non-ASCII by
    the same pure code-point-range rule. For ASCII operands the output is
    byte-identical to ``repr()``/``!r``, so existing ASCII parity tests are
    unaffected. Lists (e.g. ``unknown_keys``) render element-wise identically
    to ``ascii([...])`` because ``ascii()`` recurses into the container.
    """
    return ascii(value)


# The validate_bundle structured-error reason token shared by BOTH
# canonicalisability hazards (non-BMP object key, out-of-safe-range integer).
# The discriminating wire CODE and the byte-identical MESSAGE come from the
# shared screen relay_verifier.canonical.screen_noncanonicalizable, which every
# public verifier entrypoint uses so all fail closed identically across Python
# and TypeScript (keystone invariant #11/#16). Detection helpers, the
# safe-integer bound, the RELAY-CANON-* subcodes, and the rejection messages
# now live in relay_verifier.canonical (single source of truth for both this
# validator and the verifier.py signature entrypoints).
_NON_CANONICALIZABLE_BUNDLE_REASON: Final[str] = "non_canonicalizable_bundle"


@dataclass
class ValidateBundleOptions:
    """Caller-supplied options that gate per-policy behaviors.

    `strict_log`: if True, a `log_inclusion: "witness_mismatch"` outcome
      promotes from WARN to ERROR (exit non-zero).
    `strict_trust_anchor`: if True, a `local_dev` bundle under the
      default trust anchor produces an ERROR (exit non-zero) instead of
      a WARN.
    `auditor_now`: clock override for tests; defaults to wall-clock UTC.
    `artifact_resolver`: optional callable that maps
      ``evidence_refs[].artifact_id -> bytes`` so VAL-W10-022 can run.
      None disables the artifact-digest cross-check.
    `subject_store`: optional store for VAL-W10-037/038.
    `witness_jwks`: optional separate JWKS for the transparency-log
      witness key; defaults to the same JWKS used for the bundle.
    `default_trust_anchor`: the URL the verifier is configured to use
      as its default; controls whether `local_dev` bundles emit the
      WARN. Defaults to the spec-pinned default
      (`relay_verifier.constants.DEFAULT_JWKS_URL`) when None.
    `tsa_extra_trusted_roots_pem`: optional PEM blob of additional TSA
      trust roots merged with the wheel-bundled chain at
      ``packages/verifier/src/relay_verifier/tsa_chain/tsa-chain.pem``.
      Test-injection seam used by fixture builders to anchor an
      ephemeral TSA root generated at test time so the real RFC 3161
      ``TimeStampResp`` signature verifies (VAL-V2M09-016) without
      writing private key material to disk (banned pattern #14).
      Production callers leave this None and the verifier uses only the
      wheel-bundled chain.
    `tsa_skip_bundled_chain`: if True, do NOT load the wheel-bundled
      TSA cert chain. Used by tests that need to demonstrate the
      "untrusted root" failure mode without their ephemeral cert
      accidentally chaining into the bundled placeholder root via a
      collision. Defaults False.
    """

    strict_log: bool = False
    strict_trust_anchor: bool = False
    auditor_now: _dt.datetime | None = None
    artifact_resolver: Any | None = None  # Callable[[str], bytes] | None
    subject_store: SubjectStore | None = None
    witness_jwks: dict[str, Any] | None = None
    default_trust_anchor: str | None = None
    tsa_extra_trusted_roots_pem: bytes | None = None
    tsa_skip_bundled_chain: bool = False


# -----------------------------------------------------------------------------
# Archive-bomb gate
# -----------------------------------------------------------------------------


def check_archive_bomb_limits(
    *,
    entry_count: int,
    uncompressed_size_bytes: int,
) -> tuple[bool, str]:
    """Return (ok, reason). Caller MUST call this before validating.

    The function is exposed separately from :func:`validate_bundle` so a
    streaming inflater can fail fast without buffering an entire 2 GB
    archive into memory just to validate its claims.
    """
    if entry_count > MAX_BUNDLE_ENTRIES:
        return (
            False,
            f"bundle entry_count {entry_count} exceeds MAX_BUNDLE_ENTRIES "
            f"{MAX_BUNDLE_ENTRIES} (VAL-W10-036)",
        )
    if uncompressed_size_bytes > MAX_BUNDLE_BYTES:
        return (
            False,
            f"bundle uncompressed_size_bytes {uncompressed_size_bytes} "
            f"exceeds MAX_BUNDLE_BYTES {MAX_BUNDLE_BYTES} (VAL-W10-036)",
        )
    return True, ""


# -----------------------------------------------------------------------------
# Validator
# -----------------------------------------------------------------------------


def _new_output() -> dict[str, Any]:
    """Return a fresh output dict pre-populated with safe defaults."""
    return {
        "schema_version": VERIFIER_OUTPUT_SCHEMA,
        "overall": "fail",
        "bundle_path": "",
        "bundle_digest_sha256": "",
        "digest_ok": False,
        "structure_ok": False,
        "signatures_ok": False,
        "signatures_checked": [],
        # w8-trust-anchor: wire count of signatures the producer attached
        # to the bundle, surfaced regardless of per-signature outcomes so
        # consumers can detect the over-cap-rejection case (VAL-V2M08-041).
        "signatures_present": 0,
        "claims_count": 0,
        "merkle_check": "absent",
        "tsa_check": "missing",
        "log_inclusion": "absent",
        "trust_anchor": "",
        # w8-trust-anchor: classification of the bundle's declared
        # trust_anchor field (VAL-V2M08-044). Empty string when the
        # bundle lacks a declarable trust_anchor (which also produces a
        # structural error via RELAY-EVID-MISSING-TRUST-ANCHOR).
        "trust_anchor_class": "",
        "trust_anchor_source": "",
        # V3M1-F07 (VAL-V3M1-018): signer attribution path derived from the
        # bundle's declared trust_anchor field. Defaults to 'unknown' so
        # consumers branching on this field never see an empty string.
        "signer_role": SIGNER_ROLE_UNKNOWN,
        "signer_key_revoked": False,
        "signer_key_revoked_at": None,
        "subject_resolution": SUBJECT_RESOLUTION_UNKNOWN,
        "warnings": [],
        "errors": [],
    }


def classify_trust_anchor(trust_anchor_value: Any) -> str:
    """Return the trust_anchor_class for a bundle-declared trust_anchor.

    The classification depends ONLY on the bundle's declared value, never
    on the JWKS URL the verifier is configured with. This is the
    load-bearing guarantee of VAL-V2M08-044: a ``local_dev`` bundle stays
    ``untrusted_local`` even if the operator happens to be running the
    verifier under the Relay-Inc default anchor.

    Returns one of:
      * :data:`TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL` -- value equals the
        ``local_dev`` sentinel.
      * :data:`TRUST_ANCHOR_CLASS_RELAY_INC` -- value is a URL whose
        host is ``relay.epochly.com`` AND whose path is EXACTLY
        ``/.well-known/jwks.json``. The exact-path check (equality, not
        a suffix test) defends against a producer that points at an
        attacker-controlled path on the Relay-Inc host (e.g.
        ``https://relay.epochly.com/evil`` or
        ``https://relay.epochly.com/attacker/path/.well-known/jwks.json``).
      * :data:`TRUST_ANCHOR_CLASS_BYO` -- any other non-empty string.
      * ``""`` -- value is missing, non-string, or empty. The caller
        emits :data:`RELAY_EVID_MISSING_TRUST_ANCHOR` separately.
    """
    if not isinstance(trust_anchor_value, str) or not trust_anchor_value:
        return ""
    if trust_anchor_value == TRUST_ANCHOR_LOCAL_DEV:
        return TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL
    # Parse as URL (lazy import to keep top-of-module diff narrow).
    from urllib.parse import urlparse

    try:
        parsed = urlparse(trust_anchor_value)
    except ValueError:
        return TRUST_ANCHOR_CLASS_BYO
    host = (parsed.hostname or "").strip().lower()
    if host == "relay.epochly.com" and parsed.path == "/.well-known/jwks.json":
        return TRUST_ANCHOR_CLASS_RELAY_INC
    return TRUST_ANCHOR_CLASS_BYO


def _classify_signer_role(trust_anchor_class: str) -> str:
    """Return the signer_role classification for a trust_anchor_class.

    Pure mapping (no I/O, no side effects). The mapping derives ONLY from
    the bundle-declared trust_anchor_class, never from the JWKS URL the
    verifier is configured with -- this preserves the no-auto-promotion
    guarantee of VAL-V2M08-044: a local_dev bundle stays
    ``signer_role='local_dev'`` even when the verifier is running under
    the Relay-Inc default anchor.

    Inputs and outputs:
      * :data:`TRUST_ANCHOR_CLASS_RELAY_INC`       -> :data:`SIGNER_ROLE_CONTROL_PLANE`
      * :data:`TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL` -> :data:`SIGNER_ROLE_LOCAL_DEV`
      * :data:`TRUST_ANCHOR_CLASS_BYO`             -> :data:`SIGNER_ROLE_UNKNOWN`
      * ``""`` (missing/non-string anchor)         -> :data:`SIGNER_ROLE_UNKNOWN`
      * any other string                           -> :data:`SIGNER_ROLE_UNKNOWN`
        (fail-safe default for unrecognised classifications)
    """
    if trust_anchor_class == TRUST_ANCHOR_CLASS_RELAY_INC:
        return SIGNER_ROLE_CONTROL_PLANE
    if trust_anchor_class == TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL:
        return SIGNER_ROLE_LOCAL_DEV
    return SIGNER_ROLE_UNKNOWN


def _append_warning(
    output: dict[str, Any],
    *,
    reason: str,
    message: str,
    code: str = "",
) -> None:
    entry: dict[str, Any] = {"reason": reason, "message": message}
    if code:
        entry["code"] = code
    output["warnings"].append(entry)


def _append_error(
    output: dict[str, Any],
    *,
    reason: str,
    message: str,
    code: str = "",
    **extra: Any,
) -> None:
    """Append a structured error entry to ``output["errors"]``.

    ``**extra`` forwards arbitrary additional discriminator keys onto
    the error envelope (e.g., ``path_violation`` and ``offending_path``
    emitted by the path-screen wired into :func:`validate_bundle` per
    VAL-V2M08-015..017). Keys are written verbatim onto the dict; the
    helper does NOT collide-check against canonical keys because the
    canonical keys (``reason``, ``message``, ``code``) are already
    written by name above.
    """
    entry: dict[str, Any] = {"reason": reason, "message": message}
    if code:
        entry["code"] = code
    for k, v in extra.items():
        entry[k] = v
    output["errors"].append(entry)


def _compute_binding_digest(bundle: dict[str, Any]) -> str:
    """Return SHA-256(verifier-canonical-JSON(bundle minus signatures/tsa/log)).

    The TSA token's `message_imprint.hashed_message_hex` and the
    transparency-log proof's `leaf_digest_hex` both reference the
    PRE-extensions digest of the payload -- the digest the issuer
    computed BEFORE adding either extension to the bundle. A field
    inside the payload cannot self-reference its containing object's
    digest (no fix-point), so the binding is to the digest taken with
    the TSA token and log proof stripped.

    The verifier reverses this by stripping `signatures`, `tsa_token`,
    and `log_inclusion_proof` before canonicalising and hashing. The
    canonical encoder is :func:`relay_verifier.verifier.canonical_json_bytes`
    (the same encoder the JWS verifier uses for the full
    bundle-digest), preserving byte-for-byte parity with how the
    issuer computed the pre-extensions digest.
    """
    # Use the verifier-package's own canonical encoder so the digest
    # matches the one the JWS signer used at sign time.
    from .verifier import canonical_json_bytes as _verifier_canonical_json_bytes

    stripped = {
        k: v
        for k, v in bundle.items()
        if k not in {"signatures", "tsa_token", "log_inclusion_proof"}
    }
    canonical = _verifier_canonical_json_bytes(stripped)
    return hashlib.sha256(canonical).hexdigest()


def _claim_digests_in_order(bundle: dict[str, Any]) -> list[str]:
    """Compute each claim's digest in declaration order.

    Strips a per-claim ``signatures`` field if present (mirrors the
    bundle-level convention) before canonicalising.
    """
    claims = bundle.get("claims")
    if not isinstance(claims, list):
        return []
    out: list[str] = []
    for claim in claims:
        if isinstance(claim, dict):
            out.append(bundle_digest(claim, strip_signatures=True))
        else:
            # Non-dict claim is invalid but defensively hashable.
            out.append(hashlib.sha256(jcs_canonicalize(claim)).hexdigest())
    return out


def validate_bundle(
    *,
    bundle: dict[str, Any],
    jwks: dict[str, Any],
    bundle_path: str = "",
    trust_anchor_source: str = "",
    options: ValidateBundleOptions | None = None,
) -> dict[str, Any]:
    """Validate a parsed evidence bundle end-to-end.

    Returns a dict matching ``relay.verifier.output.v1``. Never raises
    for verification outcomes -- every failure mode is encoded in the
    structured output.

    Caller responsibilities:
      * Run :func:`check_archive_bomb_limits` against the inflated
        archive metrics before invoking this function.
      * Supply a parsed JWKS via :func:`relay_verifier.resolve_jwks`.
      * Optionally supply an artifact resolver, subject store, and
        witness JWKS via :class:`ValidateBundleOptions`.

    Exit code translation (caller does this):
      * output["overall"] == "pass" -> exit 0
      * otherwise                   -> exit non-zero
    """
    opts = options or ValidateBundleOptions()
    output = _new_output()
    output["bundle_path"] = bundle_path
    output["trust_anchor_source"] = trust_anchor_source

    # --- Trust anchor echo (VAL-W10-035) -------------------------------------
    trust_anchor = bundle.get("trust_anchor")
    if isinstance(trust_anchor, str):
        output["trust_anchor"] = trust_anchor

    # --- Trust anchor classification (VAL-V2M08-044) -------------------------
    # Classification is derived from the BUNDLE's declared trust_anchor
    # field ONLY, never from the JWKS URL the verifier is configured
    # with. local_dev stays untrusted_local even if the verifier is
    # running under the Relay-Inc default anchor.
    output["trust_anchor_class"] = classify_trust_anchor(trust_anchor)

    # --- Signer-role classification (VAL-V3M1-018) ---------------------------
    # Per spec K rule line 4427 the verifier surfaces a signer_role on
    # every output. The classification derives ONLY from the bundle's
    # declared trust_anchor (via trust_anchor_class), never from the
    # JWKS the verifier is configured with: a local_dev bundle stays
    # signer_role='local_dev' even when the verifier is running under
    # the Relay-Inc default anchor (no-auto-promotion guarantee). This
    # is computed BEFORE the signature-count cap so the field is
    # populated even on the over-cap early-return path.
    output["signer_role"] = _classify_signer_role(output["trust_anchor_class"])

    # --- Missing-trust_anchor rejection (VAL-V2M08-043) ----------------------
    # Fail-closed when the bundle declares no trust_anchor (or declares
    # a non-string / empty value). This MUST happen before signature
    # work so an unsigned classification cannot leak past the gate.
    if not isinstance(trust_anchor, str) or not trust_anchor:
        _append_error(
            output,
            reason="trust_anchor_missing",
            message=(
                "bundle is missing the required top-level 'trust_anchor' "
                "field (spec section AO.4 line 6166); verifier cannot "
                "classify the bundle against any trust posture"
            ),
            code=RELAY_EVID_MISSING_TRUST_ANCHOR,
        )

    # Record the wire signature count early so EVERY return path -- including
    # the non-canonicalisable-bundle early return below -- carries it.
    raw_sigs = bundle.get("signatures")
    signatures_count = (
        len(raw_sigs) if isinstance(raw_sigs, list) else 0
    )
    output["signatures_present"] = signatures_count

    # --- Non-canonicalisable-bundle screen (keystone invariant #11/#16) ------
    # A bundle carrying a value the JCS encoder cannot canonicalise to
    # byte-identical bytes across runtimes -- a supplementary-plane (non-BMP,
    # >= U+10000) object KEY, or an out-of-safe-range integer (abs > 2**53 - 1)
    # -- would verify on one runtime and be rejected as tampered on the other.
    # This screen runs BEFORE the over-cap signature check because a bundle
    # whose canonical bytes are not even well-defined is the most fundamental
    # failure (every downstream check is meaningless), and running first keeps
    # the over-cap branch's diagnostic bundle_digest canonicalisation on
    # canonicalisable payloads only (so its contextlib.suppress never silently
    # swallows the screen's JCSEncodeError). It runs on the bundle MINUS the
    # top-level 'signatures' field because every canonicalisation site
    # (verify_bundle, _claim_digests_in_order, _compute_binding_digest)
    # operates on that payload or a subset; a hazard confined to a signature
    # entry is not a canonicalisation hazard. The detection + byte-identical
    # (code, message) come from the shared
    # relay_verifier.canonical.screen_noncanonicalizable so this validator and
    # the verifier.py signature entrypoints fail closed IDENTICALLY across
    # Python and TypeScript.
    _payload_to_canon = {k: v for k, v in bundle.items() if k != "signatures"}
    _hazard = screen_noncanonicalizable(_payload_to_canon)
    if _hazard is not None:
        _hazard_code, _hazard_message = _hazard
        _append_error(
            output,
            reason=_NON_CANONICALIZABLE_BUNDLE_REASON,
            message=_hazard_message,
            code=_hazard_code,
        )
        claims = bundle.get("claims")
        output["claims_count"] = len(claims) if isinstance(claims, list) else 0
        output["overall"] = _compute_overall(output)
        return output

    # --- Signature-count cap (VAL-V2M08-041) ---------------------------------
    # Per spec L.5 line 4481 bundles can carry up to 4 cross-signing
    # signatures. An over-cap bundle is rejected BEFORE per-signature
    # verification work runs (defends against DoS and against producers
    # abusing the cross-signing slot for non-signature data). The
    # signatures_checked[] array stays empty for the over-cap bundle.
    if signatures_count > MAX_BUNDLE_SIGNATURES:
        _append_error(
            output,
            reason="signature_count_exceeded",
            message=(
                f"bundle carries {signatures_count} signatures; the "
                f"maximum supported is {MAX_BUNDLE_SIGNATURES} per spec "
                f"section L.5 line 4481 cross-signing cap"
            ),
            code=RELAY_EVID_SIGCOUNT_EXCEEDED,
        )
        # Refuse signature verification on the over-cap bundle. Recover
        # the bundle_digest_sha256 for diagnostic continuity but do NOT
        # populate signatures_checked[] -- per VAL-V2M08-041 the verifier
        # does not attempt verification on an over-cap bundle.
        import contextlib

        from .verifier import _payload_for_signing as _pfs
        from .verifier import canonical_json_bytes as _vcjb

        # Defensive: a malformed payload that breaks canonicalization
        # leaves bundle_digest_sha256 as its safe default "".
        with contextlib.suppress(TypeError, ValueError):
            output["bundle_digest_sha256"] = hashlib.sha256(
                _vcjb(_pfs(bundle))
            ).hexdigest()
        claims = bundle.get("claims")
        output["claims_count"] = len(claims) if isinstance(claims, list) else 0
        output["overall"] = _compute_overall(output)
        return output

    # --- JWS + bundle-level verification (VAL-W10-021, 023, 014) -------------
    jws_result = verify_bundle(bundle, jwks)
    output["bundle_digest_sha256"] = jws_result.bundle_digest_sha256
    output["digest_ok"] = jws_result.digest_ok
    output["structure_ok"] = jws_result.structure_ok
    output["signatures_ok"] = jws_result.signatures_ok
    output["claims_count"] = jws_result.claims_count
    output["signatures_checked"] = [
        {
            "kid": sc.kid,
            "alg": sc.alg,
            "ok": sc.ok,
            "reason": sc.reason,
            "code": sc.code,
        }
        for sc in jws_result.signature_checks
    ]
    if not jws_result.signatures_ok:
        # Attribute the first failing signature with a structured error.
        first_fail = next(
            (sc for sc in jws_result.signature_checks if not sc.ok),
            None,
        )
        if first_fail is not None:
            _append_error(
                output,
                reason="signature_verification_failed",
                message=first_fail.reason
                or "signature did not verify under JWK",
                code=first_fail.code or RELAY_EVID_014,
            )

    # --- Per-claim artifact-digest check (VAL-W10-022) -----------------------
    if jws_result.structure_ok and opts.artifact_resolver is not None:
        claims = bundle.get("claims") or []
        for ci, claim in enumerate(claims):
            if not isinstance(claim, dict):
                continue
            refs = claim.get("evidence_refs")
            if not isinstance(refs, list):
                continue
            for ri, ref in enumerate(refs):
                if not isinstance(ref, dict):
                    continue
                artifact_id = ref.get("artifact_id")
                declared_digest = ref.get("digest")
                if not isinstance(artifact_id, str):
                    continue
                if not isinstance(declared_digest, str):
                    continue
                # VAL-V2M08-015..017: path-traversal hardening MUST run
                # BEFORE the caller-supplied resolver is invoked. A
                # malicious artifact_id ("../../etc/passwd",
                # "/etc/passwd", NFD-encoded name, etc.) reaching the
                # resolver unfiltered would let an evidence bundle drive
                # filesystem reads outside the session sandbox. The
                # screen is pure (no I/O) so it is safe to run on every
                # ref. A path violation appends a structured error,
                # flips digest_ok to False, and skips the resolver
                # invocation entirely for the offending id (the loop
                # continues to subsequent refs so all violations surface
                # in a single pass).
                path_violation = check_artifact_path(artifact_id)
                if path_violation is not None:
                    _append_error(
                        output,
                        reason="path_violation",
                        message=(
                            f"claim[{ci}].evidence_refs[{ri}] artifact_id "
                            f"{_py_ascii(artifact_id)} rejected by path screen "
                            f"({path_violation['path_violation']})"
                        ),
                        code=path_violation["code"],
                        path_violation=path_violation["path_violation"],
                        offending_path=path_violation["offending_path"],
                    )
                    output["digest_ok"] = False
                    continue
                try:
                    artifact_bytes = opts.artifact_resolver(artifact_id)
                except (KeyError, FileNotFoundError, OSError, ValueError):
                    artifact_bytes = None
                if artifact_bytes is None:
                    _append_error(
                        output,
                        reason="artifact_unavailable",
                        message=(
                            f"claim[{ci}].evidence_refs[{ri}] artifact "
                            f"{_py_ascii(artifact_id)} could not be resolved"
                        ),
                        code=RELAY_EVID_014,
                    )
                    output["digest_ok"] = False
                    continue
                recomputed = hashlib.sha256(artifact_bytes).hexdigest()
                if recomputed != declared_digest:
                    _append_error(
                        output,
                        reason="artifact_digest_mismatch",
                        message=(
                            f"claim[{ci}].evidence_refs[{ri}] artifact "
                            f"{_py_ascii(artifact_id)} digest mismatch: declared="
                            f"{_py_ascii(declared_digest)} recomputed={_py_ascii(recomputed)}"
                        ),
                        code=RELAY_EVID_014,
                    )
                    output["digest_ok"] = False

    # --- Namespace closed-set check (VAL-V3M1-022) ---------------------------
    # Per spec K lines 4421-4423 the ``namespaces`` field on each claim is
    # restricted to the closed set {x-relay}. A claim carrying any other
    # top-level key (e.g. ``x-attacker``) is rejected with structured
    # code RELAY-EVID-NAMESPACE-UNKNOWN. Empty / absent ``namespaces`` is
    # accepted (the field is optional per the spec).
    #
    # --- Evidence-ref manifest binding (VAL-V3M1-019) ------------------------
    # Per spec K rule line 4428 ("A claim cannot reference an artifact
    # whose digest is not present in the bundle's manifest.") the
    # verifier checks that every ``evidence_refs[].digest`` resolves to
    # an entry in the bundle's top-level ``manifest`` list. When the
    # bundle declares no ``manifest`` the check is SKIPPED (preserves
    # back-compat for legacy bundles that predate this rule); when the
    # manifest is declared, any claim digest absent from it triggers
    # structured error ``evidence_ref_artifact_missing_from_manifest``.
    #
    # The manifest may be a list of dicts each carrying a ``digest`` key
    # (preferred per spec K example at line 4393-4399) OR a list of
    # bare digest strings (defensive accept). Heterogeneous entries are
    # tolerated -- unparseable entries are simply not contributed to the
    # allowed set. Computing the set once outside the per-claim loop
    # keeps the check O(N + M) instead of O(N * M).
    if jws_result.structure_ok:
        manifest_field = bundle.get("manifest")
        if isinstance(manifest_field, list):
            manifest_digests: set[str] = set()
            for entry in manifest_field:
                if isinstance(entry, dict):
                    entry_digest = entry.get("digest")
                    if isinstance(entry_digest, str) and entry_digest:
                        manifest_digests.add(entry_digest)
                elif isinstance(entry, str) and entry:
                    manifest_digests.add(entry)
        else:
            manifest_digests = set()
            manifest_field = None  # mark "no manifest" for skip semantics

        claims = bundle.get("claims") or []
        if isinstance(claims, list):
            for ci, claim in enumerate(claims):
                if not isinstance(claim, dict):
                    continue

                # --- (a) namespace closed-set check ---
                ns = claim.get("namespaces")
                if isinstance(ns, dict) and ns:
                    unknown_keys = sorted(
                        k for k in ns
                        if not isinstance(k, str) or k not in _ALLOWED_NAMESPACE_KEYS
                    )
                    if unknown_keys:
                        _append_error(
                            output,
                            reason="claim_namespace_unknown",
                            message=(
                                f"claim[{ci}].namespaces contains key(s) "
                                f"outside the closed set "
                                f"{_py_ascii(sorted(_ALLOWED_NAMESPACE_KEYS))}: "
                                f"{_py_ascii(unknown_keys)}"
                            ),
                            code=RELAY_EVID_NAMESPACE_UNKNOWN,
                        )

                # --- (b) manifest binding (only when manifest declared) ---
                if manifest_field is None:
                    continue
                refs = claim.get("evidence_refs")
                if not isinstance(refs, list):
                    continue
                for ri, ref in enumerate(refs):
                    if not isinstance(ref, dict):
                        continue
                    ref_digest = ref.get("digest")
                    if not isinstance(ref_digest, str) or not ref_digest:
                        # The spec K example shows refs that carry
                        # ``value`` instead of ``digest`` (e.g. exit_code
                        # references). Those refs are not subject to the
                        # manifest-binding rule -- only digest-bearing
                        # refs are.
                        continue
                    if ref_digest not in manifest_digests:
                        _append_error(
                            output,
                            reason="evidence_ref_artifact_missing_from_manifest",
                            message=(
                                f"claim[{ci}].evidence_refs[{ri}] digest "
                                f"{_py_ascii(ref_digest)} is not present in the "
                                f"bundle's manifest (spec K line 4428); "
                                f"manifest contains "
                                f"{len(manifest_digests)} digest(s)"
                            ),
                            code=RELAY_EVID_014,
                        )

    # --- Merkle root check (VAL-W10-024) -------------------------------------
    declared_merkle = bundle.get("merkle_root_hex")
    if isinstance(declared_merkle, str) and declared_merkle:
        recomputed_merkle = compute_merkle_root(_claim_digests_in_order(bundle))
        if recomputed_merkle == declared_merkle:
            output["merkle_check"] = "ok"
        else:
            output["merkle_check"] = "mismatch"
            _append_error(
                output,
                reason="merkle_root_mismatch",
                message=(
                    f"declared merkle_root_hex {_py_ascii(declared_merkle)} does not "
                    f"match recomputed root {_py_ascii(recomputed_merkle)}"
                ),
                code=RELAY_EVID_040,
            )
    else:
        output["merkle_check"] = "absent"

    # --- TSA timestamp (VAL-W10-025..027) ------------------------------------
    # The TSA token's message_imprint binds the bundle digest computed
    # BEFORE the TSA token (and log inclusion proof) were inserted into
    # the payload, because a field inside the payload cannot self-
    # reference its containing object's digest (no fix-point). The
    # verifier recomputes the binding digest by stripping the TSA token
    # AND the log_inclusion_proof from the payload before hashing.
    tsa_token = bundle.get("tsa_token")
    # decided_at is the canonical TSA-binding anchor (spec section AB).
    # Bundles missing this field are rejected fail-closed; do NOT silently
    # fall back to ``generated_at`` (or any sibling timestamp) -- the TSA
    # gen_time skew check compares against ``decided_at`` specifically,
    # and a fallback would silently move the trust boundary (round-4 P1
    # structural fix).
    raw_decided_at = bundle.get("decided_at")
    decided_at = raw_decided_at if isinstance(raw_decided_at, str) else ""
    binding_digest_hex = _compute_binding_digest(bundle)
    if decided_at:
        # Load the wheel-bundled TSA chain so SignerInfo signatures can
        # be cryptographically verified against the OSS placeholder root
        # (VAL-V2M09-016). If the wheel is damaged (chain file absent)
        # we tolerate the FileNotFoundError so the rest of the validator
        # still emits a structured outcome -- the empty trust-roots list
        # yields outcome="invalid" with reason="tsa_no_trust_roots_available".
        bundled_chain_certs: list | None = None
        if not opts.tsa_skip_bundled_chain:
            try:
                _, chain_bytes = load_bundled_tsa_chain()
                bundled_chain_certs = load_tsa_chain_pem_bytes(chain_bytes)
            except (FileNotFoundError, ValueError):
                bundled_chain_certs = None
        tsa_result = validate_tsa_token(
            token=tsa_token if isinstance(tsa_token, dict) else None,
            bundle_digest_hex=binding_digest_hex,
            decided_at=decided_at,
            chain_certs=bundled_chain_certs,
            extra_trusted_roots_pem=opts.tsa_extra_trusted_roots_pem,
        )
        output["tsa_check"] = tsa_result.outcome
        if tsa_result.outcome == "missing":
            _append_error(
                output,
                reason="tsa_missing",
                message=tsa_result.reason or "TSA timestamp absent",
                code=RELAY_EVID_031,
            )
        elif tsa_result.outcome == "skew":
            _append_error(
                output,
                reason="tsa_skew",
                message=tsa_result.reason,
                code=RELAY_EVID_038,
            )
        elif tsa_result.outcome == "invalid":
            _append_error(
                output,
                reason="tsa_invalid",
                message=tsa_result.reason,
                code=RELAY_EVID_031,
            )
    else:
        # Fail-closed: surface BOTH the structural anchor-missing code
        # and the canonical tsa_missing reason so consumers branching on
        # either path catch the rejection.
        output["tsa_check"] = "missing"
        present_fields = sorted(bundle.keys()) if isinstance(bundle, dict) else []
        _append_error(
            output,
            reason="decided_at_missing",
            message=(
                "bundle is missing the canonical 'decided_at' TSA-binding "
                "anchor (spec section AB); the validator refuses to fall "
                "back to 'generated_at' or any sibling timestamp because "
                "the TSA gen_time skew check binds to decided_at "
                f"specifically. bundle fields present: {_py_ascii(present_fields)}"
            ),
            code=RELAY_EVID_DECIDED_AT_MISSING,
        )
        _append_error(
            output,
            reason="tsa_missing",
            message="bundle missing decided_at; cannot evaluate TSA window",
            code=RELAY_EVID_031,
        )

    # --- Transparency-log inclusion (VAL-W10-028..030) -----------------------
    # As with TSA, the log proof's leaf_digest_hex binds the pre-log
    # digest of the payload (the proof itself cannot self-reference).
    log_proof = bundle.get("log_inclusion_proof")
    witness_jwks = opts.witness_jwks if opts.witness_jwks is not None else jwks
    log_result = verify_log_inclusion(
        proof=log_proof if isinstance(log_proof, dict) else None,
        bundle_digest_hex=binding_digest_hex,
        witness_jwks=witness_jwks,
    )
    output["log_inclusion"] = log_result.outcome
    if log_result.outcome == "absent":
        _append_warning(
            output,
            reason="log_inclusion_absent",
            message=(
                "no transparency-log inclusion proof attached; verification "
                "proceeds but auditors should treat absence as a red flag"
            ),
        )
    elif log_result.outcome == "witness_mismatch":
        if opts.strict_log:
            _append_error(
                output,
                reason="log_witness_mismatch",
                message=log_result.reason,
            )
        else:
            _append_warning(
                output,
                reason="log_witness_mismatch",
                message=log_result.reason,
            )

    # --- Signer key lifecycle (VAL-W10-031..034) -----------------------------
    if jws_result.signature_checks:
        # "Primary signer" selection rule: pick the FIRST entry whose
        # signature verified (ok=True). Blindly using index 0 would
        # silently skip lifecycle checks when slot 0 is a malformed
        # entry (kid not in JWKS, bad base64, etc.) AND a later slot
        # carries the actually-valid signer -- a revoked second-signer
        # key would not be detected (round-4 P1 structural fix).
        primary_sig = next(
            (sc for sc in jws_result.signature_checks if sc.ok),
            None,
        )
        if primary_sig is None:
            # All-failed case: fall back to slot 0 to preserve the
            # prior diagnostic surface (e.g. "revoked key on a failed
            # signature" still reaches the lifecycle path) and emit a
            # structured note so the fallback is auditable.
            primary_sig = jws_result.signature_checks[0]
            output.setdefault("details", {})["primary_signer_fallback"] = {
                "reason": "no_signature_verified",
                "note": (
                    "no signature in the bundle has ok=True; lifecycle "
                    "resolution falls back to signature_checks[0]"
                ),
                "selected_kid": primary_sig.kid,
            }
        primary_kid = primary_sig.kid
        signer_jwk = _select_jwk(jwks, primary_kid)
        signed_at = bundle.get("signed_at") or decided_at or ""
        if isinstance(signer_jwk, dict) and isinstance(signed_at, str):
            life_result = check_signing_key_lifecycle(
                jwk=signer_jwk,
                bundle_signed_at=signed_at,
                auditor_now=opts.auditor_now,
            )
            output["signer_key_revoked"] = life_result.signer_key_revoked
            output["signer_key_revoked_at"] = (
                life_result.signer_key_revoked_at
                if life_result.signer_key_revoked_at
                else None
            )
            if life_result.outcome == "expired":
                _append_error(
                    output,
                    reason="signer_key_expired",
                    message=life_result.reason,
                    code=life_result.code or RELAY_EVID_041,
                )
            elif life_result.outcome == "revoked":
                _append_error(
                    output,
                    reason="signer_key_revoked_at_or_before_sign_time",
                    message=life_result.reason,
                    code=life_result.code or RELAY_EVID_042,
                )
            elif life_result.outcome == "premature":
                _append_error(
                    output,
                    reason="signer_key_premature",
                    message=life_result.reason,
                    code=life_result.code or RELAY_EVID_041,
                )
            elif life_result.signer_key_revoked:
                _append_warning(
                    output,
                    reason="signer_key_revoked_after_sign_time",
                    message=(
                        f"key {_py_ascii(primary_kid)} was revoked at "
                        f"{life_result.signer_key_revoked_at}; bundle signed "
                        f"before revocation -- auditor decides acceptance"
                    ),
                )

    # --- trust_anchor / local_dev surfacing (VAL-W10-035 / 041) --------------
    default_anchor = opts.default_trust_anchor
    if default_anchor is None:
        # Lazy import to keep the verifier output schema decoupled
        # from the canonical URL literal.
        from .constants import DEFAULT_JWKS_URL

        default_anchor = DEFAULT_JWKS_URL
    if output["trust_anchor"] == TRUST_ANCHOR_LOCAL_DEV:
        # Only WARN when the verifier is using its default anchor; a
        # BYO local dev anchor matched to local_dev verifies normally.
        verifier_using_default_anchor = (
            trust_anchor_source in ("live", "cache", "bundled", "")
            and default_anchor.endswith("relay.epochly.com/.well-known/jwks.json")
        )
        if verifier_using_default_anchor:
            if opts.strict_trust_anchor:
                _append_error(
                    output,
                    reason=WARN_LOCAL_DEV_UNSUPPORTED,
                    message=(
                        "bundle trust_anchor='local_dev' is not supported "
                        "for audit under the default trust anchor; "
                        "--strict-trust-anchor in effect"
                    ),
                )
            else:
                _append_warning(
                    output,
                    reason=WARN_LOCAL_DEV_UNSUPPORTED,
                    message=(
                        "bundle trust_anchor='local_dev' is not supported "
                        "for audit under the default trust anchor; "
                        "verification proceeds for non-audit purposes"
                    ),
                )

    # --- Subject resolution (VAL-W10-037 / 038) ------------------------------
    subject_id = bundle.get("subject_id")
    subject_digest_hex = bundle.get("subject_digest_hex")
    sub_result = resolve_subject(
        subject_id=subject_id if isinstance(subject_id, str) else None,
        subject_digest_hex=(
            subject_digest_hex if isinstance(subject_digest_hex, str) else None
        ),
        subject_store=opts.subject_store,
    )
    output["subject_resolution"] = sub_result.resolution
    if not sub_result.original_digest_preserved:
        _append_warning(
            output,
            reason="subject_digest_drift",
            message=sub_result.reason,
        )

    # --- Aggregate overall verdict -------------------------------------------
    output["overall"] = _compute_overall(output)
    return output


def _compute_overall(output: dict[str, Any]) -> str:
    """Compute overall verdict from per-check fields and warning/error lists."""
    if output["errors"]:
        return "fail"
    if not output["structure_ok"]:
        return "fail"
    if not output["digest_ok"]:
        return "fail"
    if not output["signatures_ok"]:
        return "fail"
    if output["merkle_check"] == "mismatch":
        return "fail"
    if output["tsa_check"] in ("missing", "invalid", "skew"):
        return "fail"
    return "pass"


# -----------------------------------------------------------------------------
# Convenience: archive-bomb pre-flight + validate
# -----------------------------------------------------------------------------


def validate_bundle_with_archive_check(
    *,
    bundle: dict[str, Any],
    jwks: dict[str, Any],
    entry_count: int,
    uncompressed_size_bytes: int,
    bundle_path: str = "",
    trust_anchor_source: str = "",
    options: ValidateBundleOptions | None = None,
) -> dict[str, Any]:
    """Run :func:`check_archive_bomb_limits` then :func:`validate_bundle`.

    If the archive-bomb gate trips, returns a minimal output envelope
    with `overall: "fail"` and the structured error pre-populated -- no
    signature work is performed. This preserves the VAL-W10-036
    guarantee that archive-bomb rejection happens before signature work.
    """
    ok, reason = check_archive_bomb_limits(
        entry_count=entry_count,
        uncompressed_size_bytes=uncompressed_size_bytes,
    )
    if not ok:
        output = _new_output()
        output["bundle_path"] = bundle_path
        output["trust_anchor_source"] = trust_anchor_source
        _append_error(
            output,
            reason="archive_bomb_limit_exceeded",
            message=reason,
            code=RELAY_EVID_024,
        )
        output["overall"] = "fail"
        return output
    return validate_bundle(
        bundle=bundle,
        jwks=jwks,
        bundle_path=bundle_path,
        trust_anchor_source=trust_anchor_source,
        options=options,
    )


__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "MAX_BUNDLE_BYTES",
    "MAX_BUNDLE_ENTRIES",
    "MAX_BUNDLE_SIGNATURES",
    "RELAY_EVID_014",
    "RELAY_EVID_024",
    "RELAY_EVID_031",
    "RELAY_EVID_038",
    "RELAY_EVID_040",
    "RELAY_EVID_041",
    "RELAY_EVID_042",
    "RELAY_EVID_MISSING_TRUST_ANCHOR",
    "RELAY_EVID_NAMESPACE_UNKNOWN",
    "RELAY_EVID_SIGCOUNT_EXCEEDED",
    "SIGNER_ROLE_CONTROL_PLANE",
    "SIGNER_ROLE_LOCAL_DEV",
    "SIGNER_ROLE_UNKNOWN",
    "TRUST_ANCHOR_CLASS_BYO",
    "TRUST_ANCHOR_CLASS_RELAY_INC",
    "TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL",
    "TRUST_ANCHOR_LOCAL_DEV",
    "VERIFIER_OUTPUT_SCHEMA",
    "WARN_LOCAL_DEV_UNSUPPORTED",
    "ValidateBundleOptions",
    "check_archive_bomb_limits",
    "classify_trust_anchor",
    "validate_bundle",
    "validate_bundle_with_archive_check",
]
