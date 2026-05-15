"""Typed errors for the W7.1 mitmproxy replay harness.

Surface ``RelayProxyDownError`` (VAL-W7-010), ``RelayProxyMissingCassetteError``
(VAL-W7-011), and ``RelayProxyStartError`` (generic spawn / port / cert
failure) as named exception classes. Each carries the canonical wire code
defined in ``packages/schemas/raw/relay-error-codes.yaml`` and a structured
``details`` dict so the CLI's :mod:`relay_cli.errors.build_envelope` can map
the failure into a single line of stderr JSON without paraphrasing.

Per CLAUDE.md keystone invariant #2 (pass without evidence is not a pass),
proxy errors carry the binding fields a downstream gate engine needs to
correlate the failure with the active replay session: ``session_id``,
``cassette_dir``, ``proxy_pid`` (when known), and ``proxy_port`` (when known).

Per CLAUDE.md "ASCII-Safe Source", every message in this module is ASCII.
"""

from __future__ import annotations

from typing import Any, Final

# Wire codes (mirrors packages/schemas/raw/relay-error-codes.yaml).
RELAY_REPLAY_PROXY_DOWN: Final[str] = "RELAY-REPLAY-021"
RELAY_REPLAY_PROXY_MISSING_CASSETTE: Final[str] = "RELAY-REPLAY-022"
RELAY_REPLAY_PROXY_START_FAILED: Final[str] = "RELAY-REPLAY-023"
# W7.2 cassette-format error codes. Suffix vocabulary follows the W7.1
# block (021..023) sequentially. Per Gaps disposition #1 the spec is
# silent on these suffixes; this module pins them as the local source of
# truth and a future spec amendment to packages/schemas/raw/relay-error-codes.yaml
# (RELAY-REPLAY-024..026) will register them globally without changing
# the wire codes here.
RELAY_REPLAY_CASSETTE_MISS: Final[str] = "RELAY-REPLAY-024"
RELAY_REPLAY_CASSETTE_CORRUPT: Final[str] = "RELAY-REPLAY-025"
RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED: Final[str] = "RELAY-REPLAY-026"

# Exit code emitted by ``rly replay run`` on cassette miss (VAL-W7-024).
# Pinned by eng plan A4 layer 4 line 95: "Cassette miss = exit code 4".
EXIT_CODE_CASSETTE_MISS: Final[int] = 4

# Doc URL prefix is duplicated here intentionally so this package has no
# import-time dependency on relay_cli or relay (the harness is consumed
# from both directions: the CLI imports the harness; the harness must NOT
# import the CLI). The prefix matches the canonical docs base used by
# relay_cli.errors._DEFAULT_DOC_URL_PREFIX.
_DOC_URL_PREFIX: Final[str] = "https://relay.epochly.com/docs/errors/"


class RelayProxyError(Exception):
    """Base class for all replay-proxy harness errors.

    Carries the wire ``code`` and a JSON-serializable ``details`` dict so
    the CLI shim can build a wire envelope without re-deriving fields.
    """

    code: str
    http_status: int
    blocked_surface: str
    retry_advice: str

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = dict(details) if details else {}

    @property
    def documentation_url(self) -> str:
        return f"{_DOC_URL_PREFIX}{self.code}"


class RelayProxyDownError(RelayProxyError):
    """VAL-W7-010: the proxy exited or became unreachable mid-replay.

    Surfaced when the SDK or the harness observes ``ECONNREFUSED`` on the
    proxy port, or when the harness's own poll detects the proxy
    subprocess exited without being asked to. Per the contract, raising
    this MUST cause the agent subprocess to be terminated and ``rly
    replay run`` to exit non-zero with restart instructions on stderr.
    """

    code = RELAY_REPLAY_PROXY_DOWN
    http_status = 503
    blocked_surface = "rly replay run --proxy"
    retry_advice = "after_fix"


class RelayProxyMissingCassetteError(RelayProxyError):
    """VAL-W7-011: cassette directory missing and no --record flag passed.

    The harness MUST refuse to start in this case rather than silently
    creating an empty directory (which would mask the operator error and
    yield cassette-miss errors deep inside the agent run).
    """

    code = RELAY_REPLAY_PROXY_MISSING_CASSETTE
    http_status = 404
    blocked_surface = "rly replay run --proxy"
    retry_advice = "after_fix"


class RelayProxyStartError(RelayProxyError):
    """Generic harness start failure (port bind, cert generation, exec).

    Distinct from ``RelayProxyDownError`` because the failure happens
    BEFORE the agent subprocess is spawned -- the harness owns the
    cleanup path and no agent process is ever created.
    """

    code = RELAY_REPLAY_PROXY_START_FAILED
    http_status = 500
    blocked_surface = "rly replay run --proxy"
    retry_advice = "after_fix"


class RelayCassetteMissError(RelayProxyError):
    """VAL-W7-024 / VAL-W7-025: incoming request has no matching cassette entry.

    Carries the canonical request key (``sha256-<hex>``) and a
    human-readable request triple (``method url body_summary``) so the
    operator can reproduce the request and re-record the cassette.

    The CLI maps this exception to **exit code 4** (eng plan A4 layer 4
    line 95). There is NO live network fallthrough: a miss MUST fail.
    """

    code = RELAY_REPLAY_CASSETTE_MISS
    http_status = 502
    blocked_surface = "rly replay run --proxy"
    retry_advice = "after_fix"


class RelayCassetteCorruptError(RelayProxyError):
    """VAL-W7-026 / VAL-W7-028: cassette is malformed or fails an integrity check.

    Raised at session start, BEFORE the agent subprocess is spawned, when
    any of the following holds:

      * a JSONL line is not valid JSON;
      * a record fails ``ReplayFixture v1`` schema validation;
      * a record's ``output_digest`` does not match the SHA-256 of the
        stored output body bytes.

    ``details`` carries ``line_number``, ``fixture_id`` (when available),
    ``expected_digest``, ``actual_digest``, and ``quarantine_path`` so the
    operator can move the offending file out of the active cassette dir.
    """

    code = RELAY_REPLAY_CASSETTE_CORRUPT
    http_status = 422
    blocked_surface = "rly replay run --proxy"
    retry_advice = "after_fix"


class RelayCassetteWriteRetryExhaustedError(RelayProxyError):
    """VAL-W7-030: AV / FS lock retry budget exhausted on cassette append.

    Raised after the writer exhausts its exponential-backoff retry budget
    on ``EACCES`` / ``ERROR_SHARING_VIOLATION`` (Windows AV scan window).
    ``details`` carries ``attempts``, ``last_errno``, ``cassette_path``,
    and ``total_wait_s``.
    """

    code = RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED
    http_status = 503
    blocked_surface = "rly replay record"
    retry_advice = "after_fix"


__all__ = [
    "EXIT_CODE_CASSETTE_MISS",
    "RELAY_REPLAY_CASSETTE_CORRUPT",
    "RELAY_REPLAY_CASSETTE_MISS",
    "RELAY_REPLAY_CASSETTE_WRITE_RETRY_EXHAUSTED",
    "RELAY_REPLAY_PROXY_DOWN",
    "RELAY_REPLAY_PROXY_MISSING_CASSETTE",
    "RELAY_REPLAY_PROXY_START_FAILED",
    "RelayCassetteCorruptError",
    "RelayCassetteMissError",
    "RelayCassetteWriteRetryExhaustedError",
    "RelayProxyDownError",
    "RelayProxyError",
    "RelayProxyMissingCassetteError",
    "RelayProxyStartError",
]
