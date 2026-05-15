"""Relay replay-proxy harness (W7.1).

Public surface:

  * :class:`HarnessSession` -- own one mitmproxy session lifecycle.
  * :class:`HarnessConfig` -- caller-supplied configuration.
  * :class:`HarnessHandle` -- materialized session metadata.
  * :class:`RelayProxyDownError` / :class:`RelayProxyMissingCassetteError` /
    :class:`RelayProxyStartError` -- typed errors mapped to wire codes
    ``RELAY-REPLAY-021/022/023``.
  * :class:`CassetteServer` / :class:`IncomingRequest` -- cassette lookup
    surface (used by both the in-process driver and the mitmproxy addon).
  * :func:`generate_ca` / :func:`remove_ca` / :class:`GeneratedCA` --
    per-session CA cert authority (VAL-W7-003 / VAL-W7-004).

Per CLAUDE.md "ASCII-Safe Source" every name and docstring is ASCII.
"""

from __future__ import annotations

from .cassette_format import (
    KEY_DEFAULT_RELEVANT_HEADERS,
    KEY_EXCLUDED_HEADERS,
    QUARANTINE_DIR_NAME,
    REFRESH_POLICY_HOLD_FOREVER,
    REFRESH_POLICY_INVALIDATE_ON_MODEL,
    REFRESH_POLICY_INVALIDATE_ON_SIG,
    REFRESH_POLICY_REFRESH_WEEKLY,
    REPLAY_FIXTURE_SCHEMA_VERSION,
    SIDE_EFFECT_APPROVAL_REQUIRED,
    SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
    SIDE_EFFECT_MUTATING,
    SIDE_EFFECT_READ_ONLY,
    WRITE_RETRY_DELAYS_S,
    CanonicalKeyConfig,
    CanonicalRequest,
    CassetteIndex,
    CassetteRecord,
    RefreshDecision,
    append_record,
    derive_canonical_key,
    emit_cassette_miss_stderr,
    evaluate_refresh_policy,
    load_cassette,
    raise_cassette_miss,
    request_summary,
)
from .cassette_server import (
    CASSETTE_FILENAME,
    HEADER_REPLAY_DIGEST,
    HEADER_REPLAY_HIT,
    HEADER_REPLAY_SESSION,
    CassetteResponse,
    CassetteServer,
    IncomingRequest,
)
from .cert_authority import (
    CA_CERT_FILENAME,
    CA_KEY_FILENAME,
    GeneratedCA,
    generate_ca,
    remove_ca,
)
from .errors import (
    EXIT_CODE_CASSETTE_MISS,
    RELAY_REPLAY_CASSETTE_CORRUPT,
    RELAY_REPLAY_CASSETTE_MISS,
    RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED,
    RELAY_REPLAY_PROXY_DOWN,
    RELAY_REPLAY_PROXY_MISSING_CASSETTE,
    RELAY_REPLAY_PROXY_START_FAILED,
    RelayCassetteCorruptError,
    RelayCassetteMissError,
    RelayCassetteWriteRetryExhaustedError,
    RelayProxyDownError,
    RelayProxyError,
    RelayProxyMissingCassetteError,
    RelayProxyStartError,
)
from .harness import (
    DEFAULT_READY_TIMEOUT_S,
    DRIVER_FAKE_FAILURE,
    DRIVER_INPROC,
    DRIVER_MITMPROXY,
    ENV_DRIVER,
    ENV_HTTP_PROXY,
    ENV_HTTPS_PROXY,
    ENV_REPLAY_PROXY_URL,
    ENV_REPLAY_SESSION,
    ENV_SSL_CERT_FILE,
    EPHEMERAL_PORT_HIGH,
    EPHEMERAL_PORT_LOW,
    MAX_PORT_RETRIES,
    HarnessConfig,
    HarnessHandle,
    HarnessSession,
    pick_free_port,
)

__all__ = [
    "CASSETTE_FILENAME",
    "CA_CERT_FILENAME",
    "CA_KEY_FILENAME",
    "CanonicalKeyConfig",
    "CanonicalRequest",
    "CassetteIndex",
    "CassetteRecord",
    "CassetteResponse",
    "CassetteServer",
    "DEFAULT_READY_TIMEOUT_S",
    "DRIVER_FAKE_FAILURE",
    "DRIVER_INPROC",
    "DRIVER_MITMPROXY",
    "ENV_DRIVER",
    "ENV_HTTP_PROXY",
    "ENV_HTTPS_PROXY",
    "ENV_REPLAY_PROXY_URL",
    "ENV_REPLAY_SESSION",
    "ENV_SSL_CERT_FILE",
    "EPHEMERAL_PORT_HIGH",
    "EPHEMERAL_PORT_LOW",
    "EXIT_CODE_CASSETTE_MISS",
    "GeneratedCA",
    "HEADER_REPLAY_DIGEST",
    "HEADER_REPLAY_HIT",
    "HEADER_REPLAY_SESSION",
    "HarnessConfig",
    "HarnessHandle",
    "HarnessSession",
    "IncomingRequest",
    "KEY_DEFAULT_RELEVANT_HEADERS",
    "KEY_EXCLUDED_HEADERS",
    "MAX_PORT_RETRIES",
    "QUARANTINE_DIR_NAME",
    "REFRESH_POLICY_HOLD_FOREVER",
    "REFRESH_POLICY_INVALIDATE_ON_MODEL",
    "REFRESH_POLICY_INVALIDATE_ON_SIG",
    "REFRESH_POLICY_REFRESH_WEEKLY",
    "RELAY_REPLAY_CASSETTE_CORRUPT",
    "RELAY_REPLAY_CASSETTE_MISS",
    "RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED",
    "RELAY_REPLAY_PROXY_DOWN",
    "RELAY_REPLAY_PROXY_MISSING_CASSETTE",
    "RELAY_REPLAY_PROXY_START_FAILED",
    "REPLAY_FIXTURE_SCHEMA_VERSION",
    "RefreshDecision",
    "RelayCassetteCorruptError",
    "RelayCassetteMissError",
    "RelayCassetteWriteRetryExhaustedError",
    "RelayProxyDownError",
    "RelayProxyError",
    "RelayProxyMissingCassetteError",
    "RelayProxyStartError",
    "SIDE_EFFECT_APPROVAL_REQUIRED",
    "SIDE_EFFECT_EXTERNAL_IRREVERSIBLE",
    "SIDE_EFFECT_MUTATING",
    "SIDE_EFFECT_READ_ONLY",
    "WRITE_RETRY_DELAYS_S",
    "append_record",
    "derive_canonical_key",
    "emit_cassette_miss_stderr",
    "evaluate_refresh_policy",
    "generate_ca",
    "load_cassette",
    "pick_free_port",
    "raise_cassette_miss",
    "remove_ca",
    "request_summary",
]
