#!/usr/bin/env python3
"""W12.5 sidecar bundle release workflow guard.

Static linter that parses ``.github/workflows/release-sidecar-bundle.yml``
plus the supporting documents to enforce the 14 contract assertions
assigned to feature ``w12.5-release-sidecar-bundle``:

  - VAL-W12-020  Release publishes signed sidecar binaries for every
                 supported OS/arch (the canonical five-arch matrix).
  - VAL-W12-021  Each sidecar binary is keyless-signed via Sigstore
                 with a Rekor inclusion proof.
  - VAL-W12-022  Sigstore TSA timestamp is attached to each binary
                 signature.
  - VAL-W12-023  Sidecar binary is functionally equivalent to the
                 Python-installed sidecar (tier-1 plumbing parity).
  - VAL-W12-024  Sidecar binary signing happens on the SLSA L3
                 hermetic builder, not on a developer laptop.
  - VAL-W12-025  npm wrapper does digest check FIRST, Sigstore Rekor
                 verification SECOND, before launching the binary.
  - VAL-W12-026  macOS notarized + stapled; Windows Authenticode-signed
                 (or Sigstore-compatible attestation).
  - VAL-W12-027  Bundle binaries are signed and verifiable
                 (digest-matches-manifest + Rekor entry validates).
  - VAL-W12-035  No trust-anchor key material in repo (greppable).
  - VAL-W12-036  Secret-scan workflow catches future attempts.
  - VAL-W12-037  Every signed artifact has a Rekor entry verifiable
                 offline via Merkle proof.
  - VAL-W12-041  Compromised-OIDC drill is documented and rehearsed.
  - VAL-W12-042  Trust-anchor governance document references the
                 release pipeline.
  - VAL-W12-043  Sectigo TSA fallback path is wired but inactive by
                 default.

Exit codes:
    0  all checks passed
    1  one or more checks failed (RELAY-RELEASE-NNN reported)
    2  workflow file missing or unparseable
    3  invalid invocation

Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
Per CLAUDE.md keystone #3: invoked via the manifest-declared
``lint-sidecar-bundle-workflow`` command, not ad-hoc.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants pinned to the contract.
# ---------------------------------------------------------------------------

WORKFLOW_RELPATH = ".github/workflows/release-sidecar-bundle.yml"
SECRET_SCAN_WORKFLOW_RELPATH = ".github/workflows/secret-scan.yml"
RUNBOOK_RELPATH = "docs/release/runbook.md"
DRILLS_RELDIR = "docs/release/drills"
SECTIGO_DOC_RELPATH = "docs/release/sectigo-tsa-fallback.md"
COMPROMISED_OIDC_DOC_RELPATH = "docs/release/compromised-oidc-drill.md"
TRUST_ANCHOR_GOV_RELPATHS = (
    # The public-facing doc lives in relay-platform; the OSS repo carries
    # a stub that cross-references it. We accept either being present.
    "docs/release/trust-anchor-governance.md",
    "docs/legal/trust-anchor-governance.md",
)
BUILD_DRIVER_RELPATH = "scripts/build-sidecar-bundle.py"
ASSEMBLE_MANIFEST_RELPATH = "scripts/assemble-release-manifest.py"
SIDECAR_BUNDLE_PKG_RELDIR = "packages/sdk-typescript-sidecar-bundle"

# ---------------------------------------------------------------------------
# SHA-pin enforcement (VAL-W12-012 strengthening per spec keystone #11).
# See scripts/check-pypi-publish-workflow.py for the rationale narrative.
# ---------------------------------------------------------------------------

SHA40_RE: re.Pattern[str] = re.compile(r"^[a-f0-9]{40}$")

# The sidecar-bundle workflow consumes the SLSA reusable workflow for
# provenance. Future additions of supply-chain critical third-party
# actions (e.g., a non-Apple-tool macOS notarizer wrapper) should be
# appended here so they too are SHA-pin enforced.
SHA_PIN_REQUIRED_ACTIONS: tuple[str, ...] = (
    "slsa-framework/slsa-github-generator",
)

# Canonical four-arch matrix per VAL-W12-020 (revised 2026-05-28).
# Adding to this requires a board-level decision. macos-x86_64 was
# removed on 2026-05-28 by board-level decision: GitHub's free
# Intel-macOS runner pool is perpetually queue-starved, Apple stopped
# shipping Intel Macs in 2022, and the remaining install base runs
# the arm64 binary through Rosetta. Subsequent removals require an
# equivalent board-level decision documented in CHANGELOG.
CANONICAL_MATRIX: tuple[str, ...] = (
    "macos-arm64",
    "linux-x86_64",
    "linux-arm64",
    "windows-x86_64",
)

# Tokens the workflow MUST reference somewhere in its job graph.
REQUIRED_TOKENS_IN_WORKFLOW: tuple[tuple[str, str], ...] = (
    # (substring, what it covers)
    ("sigstore", "VAL-W12-021 keyless signing"),
    ("rekor", "VAL-W12-021/037 transparency log"),
    ("slsa-framework/slsa-github-generator", "VAL-W12-024 SLSA L3 builder"),
    ("in-toto", "VAL-W12-024 hermetic build attestation cross-link"),
    ("notariz", "VAL-W12-026 macOS notarization step"),
)

# Banned long-lived publish secret names; the sidecar bundle uses npm
# trusted publishing for the npm package and Sigstore keyless for the
# binaries. Any reference to a long-lived publish token fails.
LONG_LIVED_SECRET_NAMES: tuple[str, ...] = (
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "TWINE_PASSWORD",
)

# Required runbook sections for VAL-W12-041 / 042 / 043.
REQUIRED_RUNBOOK_SECTIONS: tuple[str, ...] = (
    "## Compromised OIDC response",
    "## Sectigo TSA fallback",
    "## Trust-anchor governance cross-reference",
)


# ---------------------------------------------------------------------------
# Result types.
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single VAL-W12-NNN check."""

    assertion: str
    error_code: str
    passed: bool
    message: str = ""


@dataclass
class GuardReport:
    """Aggregate report across every assertion this guard enforces."""

    workflow_path: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_path": self.workflow_path,
            "ok": self.ok,
            "checks": [
                {
                    "assertion": c.assertion,
                    "error_code": c.error_code,
                    "passed": c.passed,
                    "message": c.message,
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Loading helpers.
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> tuple[dict[str, Any], str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"FAIL: file not found at {path}", file=sys.stderr)
        raise SystemExit(2) from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        print(f"FAIL: YAML unparseable at {path}: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not isinstance(data, dict):
        print(f"FAIL: YAML root at {path} must be a mapping", file=sys.stderr)
        raise SystemExit(2)
    return data, text


def _iter_jobs(workflow: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []
    return [(name, job) for name, job in jobs.items() if isinstance(job, dict)]


def _iter_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [s for s in steps if isinstance(s, dict)]


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Individual assertion checks.
# ---------------------------------------------------------------------------


def _iter_uses_refs(
    workflow: dict[str, Any],
) -> list[tuple[str, int, str]]:
    """Yield every ``(job_name, step_index_or_-1, uses_value)`` triple."""
    out: list[tuple[str, int, str]] = []
    for name, job in _iter_jobs(workflow):
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            out.append((name, -1, job_uses))
        for idx, step in enumerate(_iter_steps(job)):
            uses = step.get("uses")
            if isinstance(uses, str):
                out.append((name, idx, uses))
    return out


def _split_uses_ref(uses: str) -> tuple[str, str]:
    if "@" not in uses:
        return ("", uses)
    action_path, _, ref = uses.partition("@")
    return (action_path, ref)


def _locate_uses_line(raw_text: str, uses_value: str) -> int:
    needle = uses_value.strip()
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("uses:"):
            value = stripped[len("uses:") :].strip().strip("'\"")
            if value == needle:
                return idx
    return 0


def check_sha_pinning(
    workflow: dict[str, Any], raw_text: str, workflow_relpath: str
) -> CheckResult:
    """Every reference to a supply-chain critical action MUST pin to a
    40-character lowercase-hex commit SHA. See pypi guard for narrative.
    """
    violations: list[str] = []
    for job_name, _step_idx, uses in _iter_uses_refs(workflow):
        action_path, ref = _split_uses_ref(uses)
        if not action_path:
            continue
        for required in SHA_PIN_REQUIRED_ACTIONS:
            if not action_path.startswith(required):
                continue
            if SHA40_RE.match(ref) is None:
                lineno = _locate_uses_line(raw_text, uses)
                msg = (
                    f"FAIL: {workflow_relpath}:{lineno}: action {uses!r} "
                    f"must be pinned to 40-char SHA, got {ref!r} "
                    f"(job={job_name!r})"
                )
                violations.append(msg)
                print(msg, file=sys.stderr)
            break
    if violations:
        return CheckResult(
            "VAL-W12-012",
            "RELAY-RELEASE-012",
            False,
            "; ".join(violations),
        )
    return CheckResult("VAL-W12-012", "RELAY-RELEASE-012", True)


def check_val_w12_020(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """All five canonical OS/arch cells declared in build matrix."""
    for slug in CANONICAL_MATRIX:
        if slug not in raw_text:
            return CheckResult(
                "VAL-W12-020",
                "RELAY-RELEASE-020",
                False,
                f"workflow missing canonical matrix entry '{slug}'",
            )
    # Verify the build job actually uses a matrix.
    build_jobs = [
        (name, job)
        for name, job in _iter_jobs(workflow)
        if "build" in name.lower() and "strategy" in job
    ]
    if not build_jobs:
        return CheckResult(
            "VAL-W12-020",
            "RELAY-RELEASE-020",
            False,
            "no build job with a matrix strategy found",
        )
    return CheckResult("VAL-W12-020", "RELAY-RELEASE-020", True)


def check_val_w12_021(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """Sigstore keyless signing + Rekor inclusion proof referenced."""
    if "sigstore" not in raw_text.lower():
        return CheckResult(
            "VAL-W12-021",
            "RELAY-RELEASE-021",
            False,
            "workflow does not reference sigstore",
        )
    if "rekor" not in raw_text.lower():
        return CheckResult(
            "VAL-W12-021",
            "RELAY-RELEASE-021",
            False,
            "workflow does not reference Rekor (transparency log)",
        )
    # The signing job MUST grant id-token: write for OIDC.
    workflow_perms = workflow.get("permissions")
    workflow_has_id_token = (
        isinstance(workflow_perms, dict) and workflow_perms.get("id-token") == "write"
    )
    has_id_token = workflow_has_id_token
    for _, job in _iter_jobs(workflow):
        job_perms = job.get("permissions")
        if isinstance(job_perms, dict) and job_perms.get("id-token") == "write":
            has_id_token = True
            break
    if not has_id_token:
        return CheckResult(
            "VAL-W12-021",
            "RELAY-RELEASE-021",
            False,
            "no job grants 'permissions.id-token: write' for keyless OIDC signing",
        )
    return CheckResult("VAL-W12-021", "RELAY-RELEASE-021", True)


def check_val_w12_022(raw_text: str) -> CheckResult:
    """TSA timestamp configured (default Sigstore TSA)."""
    # The workflow or a referenced action MUST set TSA on. sigstore-python
    # uses --tsa or env SIGSTORE_TIMESTAMP_AUTHORITY; cosign embeds it
    # implicitly. We look for either token.
    indicators = ("tsa", "timestamp", "timestampVerificationData")
    if not any(tok.lower() in raw_text.lower() for tok in indicators):
        return CheckResult(
            "VAL-W12-022",
            "RELAY-RELEASE-022",
            False,
            "workflow does not reference TSA or timestamp configuration",
        )
    return CheckResult("VAL-W12-022", "RELAY-RELEASE-022", True)


def check_val_w12_023(workflow: dict[str, Any]) -> CheckResult:
    """Tier-1 plumbing parity job present."""
    jobs = _iter_jobs(workflow)
    for name, job in jobs:
        lower = name.lower()
        if "parity" in lower or "plumb" in lower or "equiv" in lower:
            return CheckResult("VAL-W12-023", "RELAY-RELEASE-023", True)
        # also accept a step name match within a build/test job
        for step in _iter_steps(job):
            stepname = (step.get("name") or "").lower()
            if "tier-1" in stepname or "plumbing" in stepname or "equivalence" in stepname:
                return CheckResult("VAL-W12-023", "RELAY-RELEASE-023", True)
    return CheckResult(
        "VAL-W12-023",
        "RELAY-RELEASE-023",
        False,
        "no functional-equivalence (tier-1 plumbing parity) job/step found",
    )


def check_val_w12_024(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """SLSA L3 hermetic builder used for signing."""
    if "slsa-framework/slsa-github-generator" not in raw_text:
        return CheckResult(
            "VAL-W12-024",
            "RELAY-RELEASE-024",
            False,
            "workflow does not reference slsa-framework/slsa-github-generator",
        )
    return CheckResult("VAL-W12-024", "RELAY-RELEASE-024", True)


def check_val_w12_025(repo_root: Path) -> CheckResult:
    """npm wrapper enforces digest-first, Sigstore-second.

    The wrapper lives in packages/sdk-typescript-sidecar-bundle/src/. We
    look for the digest-before-Sigstore comments and the canonical error
    codes RELAY-RELEASE-025-DIGEST and RELAY-RELEASE-025-SIGSTORE.
    """
    pkg = repo_root / SIDECAR_BUNDLE_PKG_RELDIR
    if not pkg.is_dir():
        return CheckResult(
            "VAL-W12-025",
            "RELAY-RELEASE-025-DIGEST",
            False,
            f"sidecar bundle package missing at {pkg}",
        )
    sources = list(pkg.rglob("*.ts")) + list(pkg.rglob("*.mts"))
    if not sources:
        return CheckResult(
            "VAL-W12-025",
            "RELAY-RELEASE-025-DIGEST",
            False,
            "sidecar bundle package has no TS sources",
        )
    needed = ("RELAY-RELEASE-025-DIGEST", "RELAY-RELEASE-025-SIGSTORE")
    found: set[str] = set()
    for src in sources:
        text = src.read_text(encoding="utf-8")
        for token in needed:
            if token in text:
                found.add(token)
    missing = [t for t in needed if t not in found]
    if missing:
        return CheckResult(
            "VAL-W12-025",
            "RELAY-RELEASE-025-DIGEST",
            False,
            f"wrapper missing error tokens: {', '.join(missing)}",
        )
    return CheckResult("VAL-W12-025", "RELAY-RELEASE-025-DIGEST", True)


def check_val_w12_026(raw_text: str) -> CheckResult:
    """macOS notarized + stapled; Windows signing path."""
    lower = raw_text.lower()
    if "notariz" not in lower:
        return CheckResult(
            "VAL-W12-026",
            "RELAY-RELEASE-026",
            False,
            "workflow does not reference notarization (macOS)",
        )
    # Windows: signtool, Authenticode, or a documented sigstore-compatible
    # path. We accept any of these tokens.
    win_tokens = ("signtool", "authenticode", "windows-codesign", "osslsigncode")
    if not any(tok in lower for tok in win_tokens):
        return CheckResult(
            "VAL-W12-026",
            "RELAY-RELEASE-026",
            False,
            "workflow does not reference a Windows code-signing path",
        )
    return CheckResult("VAL-W12-026", "RELAY-RELEASE-026", True)


def check_val_w12_027(repo_root: Path, raw_text: str) -> CheckResult:
    """Digest-matches-manifest + signing wired."""
    driver = repo_root / BUILD_DRIVER_RELPATH
    if not driver.is_file():
        return CheckResult(
            "VAL-W12-027",
            "RELAY-RELEASE-027",
            False,
            f"build driver missing at {driver}",
        )
    driver_text = driver.read_text(encoding="utf-8")
    if "sha256" not in driver_text:
        return CheckResult(
            "VAL-W12-027",
            "RELAY-RELEASE-027",
            False,
            "build driver does not compute SHA-256 digests",
        )
    if "manifest" not in raw_text.lower():
        return CheckResult(
            "VAL-W12-027",
            "RELAY-RELEASE-027",
            False,
            "workflow does not reference the build manifest output",
        )
    return CheckResult("VAL-W12-027", "RELAY-RELEASE-027", True)


def check_val_w12_035(raw_text: str) -> CheckResult:
    """No trust-anchor key material referenced in workflow.

    The workflow must not inline a private key, KMS URN, or TSA
    credential. Reference to a secret with these patterns is also
    flagged.
    """
    banned_patterns = (
        "-----BEGIN",  # PEM block
        "arn:aws:kms",
        "vault.azure.net/keys",
        "/keyRings/",
        "X-API-Key.*sectigo",
        "X-API-Key.*digicert",
    )
    for pat in banned_patterns:
        if re.search(pat, raw_text):
            return CheckResult(
                "VAL-W12-035",
                "RELAY-RELEASE-035",
                False,
                f"workflow references banned trust-anchor pattern '{pat}'",
            )
    return CheckResult("VAL-W12-035", "RELAY-RELEASE-035", True)


def check_val_w12_036(repo_root: Path) -> CheckResult:
    """Secret-scan workflow exists and references trust-anchor patterns."""
    path = repo_root / SECRET_SCAN_WORKFLOW_RELPATH
    if not path.is_file():
        return CheckResult(
            "VAL-W12-036",
            "RELAY-RELEASE-036",
            False,
            f"secret-scan workflow missing at {path}",
        )
    text = path.read_text(encoding="utf-8")
    # The workflow MUST scan for at least one of the canonical extensions
    # AND reference gitleaks (or an equivalent named scanner).
    needed_tokens = (".pem", ".p12", "kms", "sectigo")
    missing = [t for t in needed_tokens if t not in text]
    if missing:
        return CheckResult(
            "VAL-W12-036",
            "RELAY-RELEASE-036",
            False,
            f"secret-scan workflow missing pattern tokens: {', '.join(missing)}",
        )
    if "gitleaks" not in text.lower() and "scan" not in text.lower():
        return CheckResult(
            "VAL-W12-036",
            "RELAY-RELEASE-036",
            False,
            "secret-scan workflow does not invoke a named scanner",
        )
    return CheckResult("VAL-W12-036", "RELAY-RELEASE-036", True)


def check_val_w12_037(raw_text: str) -> CheckResult:
    """Rekor offline-verifiability declared.

    The workflow must mention either ``--offline`` cosign verification or
    Rekor inclusion proof export so downstream verifiers can validate
    against a pinned checkpoint.
    """
    lower = raw_text.lower()
    if "rekor" not in lower:
        return CheckResult(
            "VAL-W12-037",
            "RELAY-RELEASE-037",
            False,
            "workflow does not reference Rekor",
        )
    if "offline" not in lower and "inclusion" not in lower and "merkle" not in lower:
        return CheckResult(
            "VAL-W12-037",
            "RELAY-RELEASE-037",
            False,
            "workflow does not reference offline/Merkle/inclusion-proof verification",
        )
    return CheckResult("VAL-W12-037", "RELAY-RELEASE-037", True)


def check_val_w12_041(repo_root: Path) -> CheckResult:
    """Compromised-OIDC drill documented."""
    doc = repo_root / COMPROMISED_OIDC_DOC_RELPATH
    if not doc.is_file():
        return CheckResult(
            "VAL-W12-041",
            "RELAY-RELEASE-041",
            False,
            f"compromised-OIDC drill doc missing at {doc}",
        )
    text = doc.read_text(encoding="utf-8")
    required = (
        "revoke",
        "rotate",
        "advisory",
        "publish a new release",
    )
    missing = [r for r in required if r.lower() not in text.lower()]
    if missing:
        return CheckResult(
            "VAL-W12-041",
            "RELAY-RELEASE-041",
            False,
            f"compromised-OIDC doc missing steps: {', '.join(missing)}",
        )
    # Runbook must also reference the drill.
    runbook = _read_text(repo_root / RUNBOOK_RELPATH)
    if runbook is None or "Compromised OIDC" not in runbook:
        return CheckResult(
            "VAL-W12-041",
            "RELAY-RELEASE-041",
            False,
            "runbook missing 'Compromised OIDC' section reference",
        )
    return CheckResult("VAL-W12-041", "RELAY-RELEASE-041", True)


def check_val_w12_042(repo_root: Path) -> CheckResult:
    """Trust-anchor governance document references the release pipeline."""
    found: Path | None = None
    for relpath in TRUST_ANCHOR_GOV_RELPATHS:
        candidate = repo_root / relpath
        if candidate.is_file():
            found = candidate
            break
    if found is None:
        return CheckResult(
            "VAL-W12-042",
            "RELAY-RELEASE-042",
            False,
            "trust-anchor governance document not found in either path",
        )
    text = found.read_text(encoding="utf-8")
    required_references = (
        "release pipeline",
        "Sigstore",
        "in-toto",
        "SLSA",
    )
    missing = [r for r in required_references if r.lower() not in text.lower()]
    if missing:
        return CheckResult(
            "VAL-W12-042",
            "RELAY-RELEASE-042",
            False,
            f"governance doc missing references: {', '.join(missing)}",
        )
    return CheckResult("VAL-W12-042", "RELAY-RELEASE-042", True)


def check_val_w12_043(repo_root: Path, raw_text: str) -> CheckResult:
    """Sectigo TSA fallback wired but inactive by default."""
    doc = repo_root / SECTIGO_DOC_RELPATH
    if not doc.is_file():
        return CheckResult(
            "VAL-W12-043",
            "RELAY-RELEASE-043",
            False,
            f"Sectigo TSA fallback doc missing at {doc}",
        )
    text = doc.read_text(encoding="utf-8")
    if 'TSA_PRIMARY = "sigstore"' not in text and 'TSA_PRIMARY="sigstore"' not in text:
        return CheckResult(
            "VAL-W12-043",
            "RELAY-RELEASE-043",
            False,
            "fallback doc does not pin TSA_PRIMARY='sigstore' as default",
        )
    if "sectigo" not in text.lower():
        return CheckResult(
            "VAL-W12-043",
            "RELAY-RELEASE-043",
            False,
            "fallback doc does not reference Sectigo",
        )
    # Workflow must default TSA_PRIMARY to sigstore (string match on the
    # env value or a comment that names the default).
    if "TSA_PRIMARY" not in raw_text:
        return CheckResult(
            "VAL-W12-043",
            "RELAY-RELEASE-043",
            False,
            "workflow does not declare TSA_PRIMARY",
        )
    return CheckResult("VAL-W12-043", "RELAY-RELEASE-043", True)


def check_val_crypto_003(repo_root: Path, raw_text: str) -> CheckResult:
    """Release pipeline assembles AND keyless-signs the aggregated manifest.

    VAL-CRYPTO-003 (producer side): the npx wrapper trusts the aggregated
    ``manifest.json`` (per-entry sha256 + trust_root) to decide which bundle
    to run, so the manifest itself MUST be signed and the wrapper verifies
    the signature over the exact manifest bytes before trusting any field.
    This guard asserts the workflow:
      1. assembles the aggregated ``manifest.json`` (via the assemble script);
      2. keyless-signs it producing ``manifest.json.sigstore`` (mirroring the
         per-binary sigstore signing step);
      3. and that the assemble script exists in the repo.
    """
    code = "RELAY-RELEASE-MANIFEST-SIG"
    assertion = "VAL-CRYPTO-003"
    assemble = repo_root / ASSEMBLE_MANIFEST_RELPATH
    if not assemble.is_file():
        return CheckResult(
            assertion,
            code,
            False,
            f"aggregated-manifest assembler missing at {assemble}",
        )
    # The workflow must invoke the assembler and produce the wrapper-facing
    # manifest.json (the assemble step references the script).
    if "assemble-release-manifest.py" not in raw_text:
        return CheckResult(
            assertion,
            code,
            False,
            "workflow does not invoke scripts/assemble-release-manifest.py "
            "to build the aggregated manifest.json",
        )
    # The workflow must keyless-sign manifest.json itself, producing
    # manifest.json.sigstore. We require both the signing invocation over
    # manifest.json AND the manifest.json.sigstore bundle name.
    if "manifest.json.sigstore" not in raw_text:
        return CheckResult(
            assertion,
            code,
            False,
            "workflow does not produce a 'manifest.json.sigstore' signature "
            "over the aggregated manifest",
        )
    # The signing step must run sigstore sign over dist/manifest.json with a
    # bundle output (mirror of the per-binary keyless-sign step). Match the
    # sign invocation + the bundle flag near manifest.json.sigstore.
    if "python -m sigstore sign" not in raw_text:
        return CheckResult(
            assertion,
            code,
            False,
            "workflow does not invoke 'python -m sigstore sign' for keyless "
            "manifest signing",
        )
    # The aggregated manifest must be published as a release asset (the
    # wrapper fetches it from the pinned URL; the GitHub release is the
    # canonical signed source the hosted manifest service mirrors).
    if "-name 'manifest.json'" not in raw_text and '-name "manifest.json"' not in raw_text:
        return CheckResult(
            assertion,
            code,
            False,
            "publish step does not upload the aggregated manifest.json asset",
        )
    return CheckResult(assertion, code, True)


def check_no_long_lived_secrets(raw_text: str) -> CheckResult:
    """Defensive check (covers VAL-W12-035 secret-name surface)."""
    for name in LONG_LIVED_SECRET_NAMES:
        if f"secrets.{name}" in raw_text:
            return CheckResult(
                "VAL-W12-035",
                "RELAY-RELEASE-035",
                False,
                f"workflow references long-lived secret 'secrets.{name}'",
            )
    return CheckResult("VAL-W12-035", "RELAY-RELEASE-035", True)


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def build_report(repo_root: Path) -> GuardReport:
    workflow_path = repo_root / WORKFLOW_RELPATH
    workflow, raw_text = _load_yaml(workflow_path)
    report = GuardReport(workflow_path=str(workflow_path))

    # VAL-W12-012 strengthening: SHA-pin enforcement for supply-chain
    # critical actions. See pypi guard for narrative.
    report.checks.append(check_sha_pinning(workflow, raw_text, WORKFLOW_RELPATH))
    report.checks.append(check_val_w12_020(workflow, raw_text))
    report.checks.append(check_val_w12_021(workflow, raw_text))
    report.checks.append(check_val_w12_022(raw_text))
    report.checks.append(check_val_w12_023(workflow))
    report.checks.append(check_val_w12_024(workflow, raw_text))
    report.checks.append(check_val_w12_025(repo_root))
    report.checks.append(check_val_w12_026(raw_text))
    report.checks.append(check_val_w12_027(repo_root, raw_text))
    # VAL-W12-035 has two angles (no key material in workflow + no long-
    # lived secrets); we run both and surface the first failure.
    long_lived = check_no_long_lived_secrets(raw_text)
    key_material = check_val_w12_035(raw_text)
    report.checks.append(long_lived if not long_lived.passed else key_material)
    report.checks.append(check_val_w12_036(repo_root))
    report.checks.append(check_val_w12_037(raw_text))
    report.checks.append(check_val_w12_041(repo_root))
    report.checks.append(check_val_w12_042(repo_root))
    report.checks.append(check_val_w12_043(repo_root, raw_text))
    # VAL-CRYPTO-003 producer side: the aggregated manifest is assembled
    # AND keyless-signed (manifest.json.sigstore) so the wrapper can verify
    # the manifest signature over the exact bytes before trusting any entry.
    report.checks.append(check_val_crypto_003(repo_root, raw_text))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="W12.5 sidecar bundle release workflow guard.",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root (default: parent of scripts/).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON report on stdout instead of human-readable.",
    )
    args = parser.parse_args(argv)

    repo_root = (
        Path(args.repo_root).resolve()
        if args.repo_root
        else Path(__file__).resolve().parent.parent
    )

    report = build_report(repo_root)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        for c in report.checks:
            status = "PASS" if c.passed else "FAIL"
            extra = f" {c.message}" if c.message else ""
            print(f"{status} {c.assertion} ({c.error_code}){extra}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
