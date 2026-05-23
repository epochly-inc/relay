# Devcontainer Setup

This directory ships a `devcontainer.json` that boots a reproducible
Relay OSS development environment in VS Code or GitHub Codespaces with
Python 3.12, Node 22, `uv`, `git`, and `gh` preinstalled.

## What this provides

A one-click dev environment that matches the versions Relay's CI runs
against, so a contributor can clone the repo and have a working
`uv sync`-ed workspace in a few minutes without installing toolchains
on the host.

## Open in VS Code

Prerequisites: Docker Desktop running and the
[Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
extension installed.

1. Open the `relay/` repository in VS Code.
2. Press `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Linux/Windows) and run
   `Dev Containers: Reopen in Container`.
3. VS Code builds the image, runs the `postCreateCommand`
   (`uv sync --all-packages` + `npm install`), and reopens the workspace
   inside the container.

## Open in GitHub Codespaces

1. From the [`epochly-inc/relay`](https://github.com/epochly-inc/relay)
   GitHub page, click the green `Code` button.
2. Select the `Codespaces` tab and click `Create codespace on main`
   (or pick a branch).
3. Codespaces reads `.devcontainer/devcontainer.json` (Codespaces
   autodiscovery requires the config at this exact root-level path),
   builds the image, runs the `postCreateCommand`, and opens the
   codespace in the browser (or your local VS Code, if configured).
   The canonical copy of the config lives at
   `deploy/devcontainer/devcontainer.json` for organizational visibility;
   both files MUST match -- the root-level copy is what Codespaces
   resolves.

## What gets installed

- Python 3.12 (from `mcr.microsoft.com/devcontainers/python:1-3.12-bullseye`)
- Node 22 (via the `ghcr.io/devcontainers/features/node:1` feature)
- `git` (via the `ghcr.io/devcontainers/features/git:1` feature)
- `gh` GitHub CLI (via the `ghcr.io/devcontainers/features/github-cli:1`
  feature)
- `uv` (installed by the official `astral.sh/uv` installer in
  `postCreateCommand`)
- The Python workspace (`uv sync --all-packages`)
- The Node workspaces (`npm install --workspaces --include-workspace-root`)
- VS Code extensions: Python, Pylance, Ruff, Even Better TOML, YAML,
  Prettier, ESLint, GitHub Pull Requests

## First-run timing

Expect roughly five to ten minutes on the first open: container image
pull, three `devcontainers/features/*` installs, `uv sync` across every
workspace member, and `npm install` across every npm workspace. Subsequent
reopens reuse the cached image and the `relay-uv-cache` volume, so they
complete in well under a minute.

## Verify

After the container finishes building, open a new terminal inside the
container and run:

```bash
uv run rly --version
```

The command should print the `rly` CLI's version string and exit `0`.
If you see a non-zero exit or a `ModuleNotFoundError`, the `uv sync`
step did not complete - rerun it manually:

```bash
uv sync --all-packages
uv run rly --version
```

## Troubleshooting

- **Container fails to build.** Check that Docker Desktop is running
  on the host and that it has enough disk space (the Microsoft Python
  base image plus the three features needs ~2 GB). On macOS / Windows,
  Docker Desktop must be open before VS Code attempts the build.
- **VS Code does not detect the devcontainer.** Reload the window
  (`Cmd+Shift+P` -> `Developer: Reload Window`), then rerun
  `Dev Containers: Reopen in Container`. If VS Code still does not see
  the config, confirm the Dev Containers extension is installed and
  enabled.
- **`postCreateCommand` fails on `uv sync`.** The container has `uv`
  installed at `$HOME/.local/bin/uv` by the astral.sh installer; if a
  proxy or network policy blocks `astral.sh`, set
  `"postCreateCommand"` locally to install `uv` via `pipx install uv`
  instead, and rebuild.
- **`npm install` fails.** Confirm Node 22 is on PATH (`node --version`).
  If the `node:1` feature install failed earlier, rebuild the container
  (`Dev Containers: Rebuild Container`).
- **Codespaces does not start.** Verify the repo has Codespaces enabled
  in its organization settings. Codespaces also requires a billable
  GitHub plan above the free tier for private forks.

---

Spec: see [planning/epochly-replay-spec.md](https://github.com/epochly-inc/relay)
local-deploy section (plan.md Wave 1 deliverable 9).
