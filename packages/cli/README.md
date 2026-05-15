# epochly-relay-cli

The `rly` command-line interface for the Relay agent reliability OS.

This package ships the public Apache 2.0 control surface declared in spec
section P (CLI inventory + contract). The W5 milestone (sub-features w5.1
through w5.5) wires the CLI onto the Python SDK (`epochly-relay`), the
canonical schemas (`epochly-relay-schemas`), and the local sidecar
(`epochly-relay-sidecar`).

## Installation (development)

```
uv sync --all-packages
uv pip install -e packages/cli
```

After install, `rly --version` prints version JSON to a piped stdout and a
human-readable form to a TTY. Exit code is always 0 on success.

## Why JSON-by-default

Relay is a control-plane CLI consumed by CI runners, gate engines,
auditors, and other automation. Spec section P pins the rule that piped
stdout is machine-parsable JSON; TTY stdout is permitted to render
human-readable text. This package implements the rule via
`sys.stdout.isatty()` detection at output emit time.

## Why Typer + Click pinned to exact versions

Per VAL-W5-002 (eng plan CQ3), Typer and Click are pinned with the exact
operator (`==`) rather than a range. The CLI's stdout-JSON contract and
cross-shell snapshot fixtures depend on Typer's command dispatch and
`--help` rendering; an upstream version bump would invalidate the
snapshots. Bumping Typer or Click is a deliberate W5 maintenance feature,
not an unattended dependency upgrade.

## Process safety

Per CLAUDE.md keystone invariant #3 and `.ops/manifest.yaml`, sidecar
lifecycle commands (`rly sidecar start|stop|restart|status`) read PID and
port from `~/.relay/sidecar.lock` and never invoke kill-by-name primitives
(`pkill`, `killall`). The full lifecycle implementation lands in W5.2.

## Banned product copy

This package and every customer-facing surface produced by its
distribution pipeline (PyPI long_description, npm description, release
notes, embedded sidecar binary string resources) is scrubbed of the
banned tokens enumerated in CLAUDE.md (banned pattern #9, spec J.5).
The `scripts/lint-banned-product-copy.py` lint runs in tier-1 plumbing
and fails CI on any match.
