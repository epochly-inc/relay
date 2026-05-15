"""ACEF — AI Compliance Evidence Format Reference SDK.

Usage:
    import acef

    pkg = acef.Package(producer={"name": "my-tool", "version": "1.0"})
    system = pkg.add_subject("ai_system", name="My AI System")
    pkg.record("risk_register", provisions=["article-9"], payload={...})
    pkg.export("output.acef/")

    # Validate
    assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"])
    print(assessment.summary())

    # Load
    pkg2 = acef.load("output.acef/")
"""

from acef._version import __version__
from acef.assessment_builder import export_assessment, validate
from acef.loader import load
from acef.merge import merge_packages
from acef.package import Package
from acef.redaction import redact_package, redact_record
from acef.render import render_console, render_markdown
from acef.signing import (
    create_detached_jws,
    sign_assessment,
    sign_bundle,
    verify_detached_jws,
)


def chain(prior_bundle_path: str, **kwargs) -> Package:
    """Create a new package chained to a prior Evidence Bundle.

    Computes the bundle digest of the prior bundle and sets it as
    prior_package_ref on the new package.

    Args:
        prior_bundle_path: Path to the prior bundle directory or archive.
        **kwargs: Additional arguments passed to Package constructor.

    Returns:
        A new Package with prior_package_ref set.
    """
    import tempfile
    from pathlib import Path

    from acef.integrity import compute_bundle_digest, compute_content_hashes

    prior = Path(prior_bundle_path)
    if prior.suffix == ".gz" or str(prior).endswith(".tar.gz"):
        loaded = load(prior_bundle_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_bundle = Path(tmpdir) / "prior.acef"
            loaded.export(str(tmp_bundle))
            hashes = compute_content_hashes(tmp_bundle)
    else:
        hashes = compute_content_hashes(prior)

    digest = compute_bundle_digest(hashes)
    return Package(prior_package_ref=digest, **kwargs)


# Top-level sign/verify per spec 5.2
sign = sign_bundle
verify = verify_detached_jws

# Top-level convenience aliases per spec 5.2
redact = redact_package
render = render_markdown
merge = merge_packages

__all__ = [
    "Package",
    "__version__",
    "chain",
    "create_detached_jws",
    "export_assessment",
    "load",
    "merge",
    "merge_packages",
    "redact",
    "redact_package",
    "redact_record",
    "render",
    "render_console",
    "render_markdown",
    "sign",
    "sign_assessment",
    "sign_bundle",
    "validate",
    "verify",
    "verify_detached_jws",
]
