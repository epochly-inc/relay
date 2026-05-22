# Local Compose Deployment

## What this provides

A Docker Compose profile that builds a containerized dev shell for Relay.
The container runs `python:3.12-slim`, installs `uv`, syncs the workspace
from a bind-mounted copy of the repo, and stays alive so you can exec
`rly` commands without polluting your host Python. State (lockfile,
SQLite WAL, event log) persists in a named volume so `docker compose
down` / `up` cycles do not wipe it.

## Prerequisites

One of the following Compose-compatible runtimes:

- Docker Desktop 4.30+ (macOS or Windows; bundles Compose v2)
- `colima` + `docker` CLI (macOS alternative; install Compose v2 separately)
- `podman-compose` 1.0+ (Linux; verify it accepts the v3 schema this file
  uses)

Verify with:

```bash run
docker compose version
```

Exit 0 with a `Docker Compose version v2.x` line confirms the runtime.

## Quickstart

```bash run
cd deploy/local-compose
cp .env.example .env
docker compose up -d
docker compose ps
```

The first `up` pulls `python:3.12-slim`, installs `uv` via `pip`, then
runs `uv sync --all-packages` against the bind-mounted repo. Expect 2-5
minutes on first run, seconds on subsequent restarts.

## Verify

The container does NOT expose an HTTP port by default (see "Known
limitations" below). Verify the stack via the CLI smoke command instead:

```bash
docker compose exec relay-sidecar uv run rly --version
```

A successful run emits a single JSON line of the form
`{"schema_version":"relay.cli.version.v1","version":"...","python":"...","platform":"..."}`
and exits 0. Anything else means `uv sync` or the workspace install
failed; `docker compose logs relay-sidecar` shows the cause.

To explore the CLI surface from inside the container:

```bash
docker compose exec relay-sidecar uv run rly --help
```

## Stop

```bash run
docker compose down
```

The named volume `local-compose_relay-home` survives `down`. To wipe
state (lockfile, SQLite database, event log) as well:

```bash run
docker compose down -v
```

## Known limitations (v0.1)

The Relay sidecar's standalone long-lived daemon is wired up in
milestone W5+ of the OSS wedge plan; v0.1 ships the library surface
and the `rly` CLI but does not yet fork a uvicorn daemon under
`rly sidecar start --daemon`. As a consequence:

- The container keeps itself alive via `sleep infinity` after the
  initial `uv sync` succeeds. Real long-lived HTTP serving lands once
  the W5 entrypoint is published.
- The sidecar binds `127.0.0.1` (loopback-only; never `0.0.0.0`) as a
  privacy default. Cross-container HTTP attach requires a host-bind
  override flag that v0.1 does not expose; the `ports:` block in
  `docker-compose.yml` is intentionally commented out.
- Use the CLI inside the container via `docker compose exec` rather
  than HTTP attach from the host.

## Troubleshooting

### `pip install uv` fails on first `up`

The container needs outbound network to PyPI on first launch. Confirm
your Docker network policy allows egress to `pypi.org` and
`files.pythonhosted.org`. After the initial install succeeds, the `uv`
binary is cached inside the image layer for the lifetime of that
container; only `docker compose down --rmi` forces a re-install.

### Port conflict on `docker compose up`

Compose binds ports on the host. The default Compose file in this
directory exposes no host ports, so a conflict here means another
service is using a port you uncommented in the `ports:` block. Report
the conflict (`lsof -i :<port>`); do not `pkill` the existing process.
Free the port at its source (stop the conflicting service via its own
manifest stop command), or choose a different host port in the
`ports:` block.

### Build cache stale after a `pyproject.toml` edit

`uv sync` is invoked at container start, not at image build, so a
`pyproject.toml` edit on the host is picked up automatically on the
next `docker compose restart relay-sidecar`. If you want a fully
clean restart, `docker compose down -v && docker compose up -d`.

### Healthcheck stays "starting" past 60 seconds

The healthcheck `start_period` is 60 s. On slow networks or older
hardware, `uv sync --all-packages` may take longer. Inspect
`docker compose logs -f relay-sidecar` to confirm sync progress; once
the `[relay-sidecar] container ready` line prints, the next
healthcheck probe should flip the state to healthy.

Spec: planning/epochly-replay-spec.md "Public relay repository layout"
(deploy/local-compose/); plan.md Wave 1 deliverable 8.
