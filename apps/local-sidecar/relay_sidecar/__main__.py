"""PyInstaller / `python -m relay_sidecar` entrypoint.

The standalone PyInstaller binary built by `release-sidecar-bundle.yml`
imports this module as its script argument. Running the bundled binary
(`./relay-sidecar-<cell>`) or `python -m relay_sidecar` must behave
identically to the Python-installed sidecar started via
``run_uvicorn`` (VAL-W12-023 functional equivalence).

Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
Per CLAUDE.md keystone #3: this entrypoint runs only the
manifest-declared command surface; no extra flags beyond what
``relay_sidecar.spawn`` and the CLI already use.

Exit codes:
    0    clean shutdown (SIGTERM / SIGINT honored by uvicorn)
    1    unrecoverable startup failure (uncaught exception)
    3    sqlite corruption detected at pre-launch recover_or_refuse
    5    sqlite schema-version mismatch
    6    WAL replay failure
    64   invalid argv (per VAL-CLI-001 argparse exit convention)
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

from relay_sidecar.health import HealthState
from relay_sidecar.runtime import run_uvicorn
from relay_sidecar.spawn import BEARER_TOKEN_BYTES, _digest_of_token


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="relay-sidecar",
        description=(
            "Run the Relay local sidecar process. The sidecar binds a "
            "loopback HTTP listener on 127.0.0.1 and serializes its "
            "per-host singleton invariant via a four-state lockfile."
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host (default: 127.0.0.1 loopback-only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Bind port (default: 0 = ephemeral, written to lockfile).",
    )
    parser.add_argument(
        "--bearer-token",
        default=None,
        help=(
            "Pre-generated bearer token. When omitted, the sidecar "
            "generates a fresh 256-bit token at startup and prints its "
            "sha256 digest to stderr."
        ),
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=None,
        help=(
            "SQLite DB path (default: ${RELAY_HOME}/sidecar.db). "
            "Overriding is intended for tests, not normal operation."
        ),
    )
    parser.add_argument(
        "--relay-home",
        type=Path,
        default=None,
        help=(
            "Override ${RELAY_HOME} discovery. Used by integration tests "
            "to point a real sidecar subprocess at a tmpdir."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    bearer_token = args.bearer_token or secrets.token_urlsafe(BEARER_TOKEN_BYTES)
    bearer_token_digest = _digest_of_token(bearer_token)

    if args.bearer_token is None:
        # Print the digest (NOT the token) so the spawner can correlate
        # without a token round-trip. The plaintext token stays in
        # process memory only.
        sys.stderr.write(
            f"relay-sidecar: generated bearer_token_digest={bearer_token_digest}\n"
        )
        sys.stderr.flush()

    health = HealthState(
        port=args.port,
        bearer_token=bearer_token,
        bearer_token_digest=bearer_token_digest,
    )

    try:
        run_uvicorn(
            health=health,
            host=args.host,
            port=args.port,
            sqlite_path=args.sqlite_path,
            relay_home_override=args.relay_home,
        )
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover (entrypoint)
    raise SystemExit(main())
