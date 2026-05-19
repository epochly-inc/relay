"""V3 M2 F02 hosted-only 501 route stubs.

Covers VAL-V3M2-004 and VAL-V3M2-005 (2 assertions):

  - VAL-V3M2-004: 5 hosted-only routes are declared in
    packages/schemas/raw/openapi.yaml with a 501 response and a
    description containing the marker string ``[OUT-OF-SCOPE-PRIVATE]``.

  - VAL-V3M2-005: the sidecar FastAPI app registers a handler for each
    of the 5 routes; each returns HTTP 501 with a structured Relay
    error envelope whose ``code`` is ``RELAY-HOSTED-ONLY`` and whose
    ``blocked_surface`` is ``hosted_control_plane``.

The 5 hosted-only routes (per .ops boundaries.md DEFERRED item #3 and
contract.md VAL-V3M2-004):

  POST /v1/evidence-bundles/{bundle_id}/assess
  GET  /v1/assessment-bundles/{bundle_id}
  GET  /v1/assessment-bundles/{bundle_id}/gaps
  GET  /v1/projects/{project_id}/compliance/readiness
  GET  /v1/orgs/{org_id}/usage

These endpoints belong to the private ``relay-platform`` hosted control
plane. The OSS sidecar must surface a clean ``RELAY-HOSTED-ONLY``
rejection so SDK callers see a deterministic non-200 response (rather
than a 404 that would falsely suggest a missing or renamed route).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"

# Canonical (method, path-template, param-name) tuples for the 5
# hosted-only stub routes. The OpenAPI ``paths:`` key uses the original
# path-parameter names (``bundle_id`` etc.) verbatim; FastAPI's
# path-parameter names are matched by position, not name. The HTTP-level
# test substitutes a concrete string id into the path template.
HOSTED_ONLY_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("POST", "/v1/evidence-bundles/{bundle_id}/assess", "bundle_id"),
    ("GET", "/v1/assessment-bundles/{bundle_id}", "bundle_id"),
    ("GET", "/v1/assessment-bundles/{bundle_id}/gaps", "bundle_id"),
    ("GET", "/v1/projects/{project_id}/compliance/readiness", "project_id"),
    ("GET", "/v1/orgs/{org_id}/usage", "org_id"),
)


def _concretize(path_template: str, param_name: str) -> str:
    """Substitute a deterministic test id into the path template."""
    placeholder = "{" + param_name + "}"
    return path_template.replace(placeholder, "test-id-001")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-005")
@pytest.mark.asyncio
async def test_hosted_only_routes_return_501_envelope(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    """Each of the 5 hosted-only routes returns 501 + structured envelope.

    The envelope must carry ``code == 'RELAY-HOSTED-ONLY'`` AND
    ``blocked_surface == 'hosted_control_plane'`` (contract VAL-V3M2-005).
    """
    c, _db, _app = v2m02_client
    for method, path_template, param_name in HOSTED_ONLY_ROUTES:
        url = _concretize(path_template, param_name)
        if method == "POST":
            response = await c.post(url, json={})
        elif method == "GET":
            response = await c.get(url)
        else:  # pragma: no cover (defensive; closed enum above)
            raise AssertionError(f"unexpected method {method}")
        assert response.status_code == 501, (
            f"{method} {url} expected 501, got "
            f"{response.status_code}: {response.text}"
        )
        envelope = json.loads(response.text)
        assert envelope.get("code") == "RELAY-HOSTED-ONLY", (
            f"{method} {url} envelope.code != 'RELAY-HOSTED-ONLY': "
            f"{envelope!r}"
        )
        assert envelope.get("blocked_surface") == "hosted_control_plane", (
            f"{method} {url} envelope.blocked_surface != "
            f"'hosted_control_plane': {envelope!r}"
        )
        assert envelope.get("http_status") == 501, (
            f"{method} {url} envelope.http_status != 501: {envelope!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-004")
def test_openapi_declares_5_hosted_only_routes_with_marker() -> None:
    """openapi.yaml carries 5 hosted-only route entries with the marker.

    Each entry must:
      * exist under ``paths:`` for the documented method+path,
      * declare a ``501`` response, and
      * declare a description (operation- OR response-level) containing
        the marker string ``[OUT-OF-SCOPE-PRIVATE]``.
    """
    doc = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    paths = doc.get("paths") or {}
    assert isinstance(paths, dict), "openapi.yaml paths: must be a mapping"

    marker = "[OUT-OF-SCOPE-PRIVATE]"
    for method, path_template, _param_name in HOSTED_ONLY_ROUTES:
        methods = paths.get(path_template)
        assert isinstance(methods, dict), (
            f"openapi.yaml missing entry for path {path_template!r}"
        )
        op = methods.get(method.lower())
        assert isinstance(op, dict), (
            f"openapi.yaml missing {method} operation under {path_template!r}"
        )
        responses = op.get("responses") or {}
        response_keys = {str(k) for k in responses}
        assert "501" in response_keys, (
            f"{method} {path_template}: 501 response not declared "
            f"(got responses={sorted(response_keys)})"
        )
        # The marker may appear on the operation summary/description OR
        # the 501-response description; either satisfies the contract.
        op_summary = str(op.get("summary") or "")
        op_description = str(op.get("description") or "")
        resp_501 = responses.get("501") or responses.get(501) or {}
        resp_description = str(resp_501.get("description") or "")
        haystacks = (op_summary, op_description, resp_description)
        assert any(marker in h for h in haystacks), (
            f"{method} {path_template}: marker {marker!r} not found in "
            f"summary/description or 501-response description "
            f"(summary={op_summary!r}, description={op_description!r}, "
            f"501 description={resp_description!r})"
        )
