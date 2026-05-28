# Relay v0.1 OSS -- PyInstaller spec for the standalone sidecar binary
# (sub-feature w12.5).
#
# This spec drives the PyInstaller build for the canonical five-arch
# matrix declared by VAL-W12-020:
#
#   1. macOS-x86_64    (darwin-amd64)
#   2. macOS-arm64     (darwin-arm64)
#   3. linux-x86_64    (linux-amd64)
#   4. linux-arm64     (linux-aarch64)
#   5. windows-x86_64  (windows-amd64)
#
# PyInstaller is invoked once per (OS, arch) cell in the
# release-sidecar-bundle.yml workflow's build matrix; this spec is the
# single source of truth for what gets bundled. The OS/arch suffix in
# the final binary name is set by the workflow's PYINSTALLER_OUTPUT_NAME
# env var so we keep one spec file rather than five near-duplicates.
#
# Why a .spec file (not pyinstaller CLI args):
#   - The spec is checkable into git; CLI invocations drift.
#   - PyInstaller's hidden-imports + datas + binaries lists are non-trivial
#     for FastAPI + aiosqlite + portalocker + uvicorn -- a spec keeps the
#     transitive surface explicit and reviewable.
#   - VAL-W12-023 requires functional equivalence with the Python-installed
#     sidecar; the spec is the contract that proves the bundled binary
#     ships every module the Python install ships.
#
# Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
# Per CLAUDE.md banned pattern #14: no trust-anchor key material in this
# file or any referenced asset. Signing keys live only in relay-platform
# KMS; this spec is signing-agnostic and the workflow does the keyless
# Sigstore signing post-build.
#
# Spec citations:
#   - Eng plan L3 line 226 (two-tier TS distribution + signed standalone
#     binaries)
#   - Spec section H.5 (lockfile semantics; the binary MUST behave
#     identically to the Python-installed sidecar)
#   - VAL-W12-020 (canonical five-arch matrix)
#   - VAL-W12-023 (functional equivalence)
#   - VAL-W12-027 (digest-matches-manifest + Rekor entry validates;
#     reproducibility is NOT required, signing IS)

# pylint: disable=undefined-variable
# PyInstaller imports `Analysis`, `PYZ`, `EXE`, `BUNDLE` into the spec's
# exec namespace; they are not visible to static analyzers reading this
# file in isolation.

import os
import sys
from pathlib import Path

# ----------------------------------------------------------------------------
# Resolve the local-sidecar source root.
#
# This spec lives at apps/local-sidecar/pyinstaller/relay-sidecar.spec; the
# sidecar source is at apps/local-sidecar/relay_sidecar/. Two parents up
# resolves to the relay/ repo root which we anchor against.
# ----------------------------------------------------------------------------

SPEC_DIR = Path(os.path.dirname(os.path.abspath(SPEC)))  # type: ignore[name-defined]
SIDECAR_PKG_DIR = SPEC_DIR.parent / "relay_sidecar"
REPO_ROOT = SPEC_DIR.parent.parent.parent

# ----------------------------------------------------------------------------
# Output name. The workflow sets PYINSTALLER_OUTPUT_NAME per (OS, arch)
# matrix cell so a single spec produces correctly-named binaries.
# Canonical 4-arch matrix (revised 2026-05-28, see CHANGELOG v0.1.16):
#
#   relay-sidecar-macos-arm64
#   relay-sidecar-linux-x86_64
#   relay-sidecar-linux-arm64
#   relay-sidecar-windows-x86_64.exe   (Windows; .exe suffix added by PyInstaller)
#
# macos-x86_64 was removed by board-level decision (GitHub Intel-macOS
# runner pool starvation, Apple 2022 Intel discontinuation, Rosetta
# fallback).
#
# Default (for local dev builds) is platform-agnostic "relay-sidecar".
# ----------------------------------------------------------------------------

OUTPUT_NAME = os.environ.get("PYINSTALLER_OUTPUT_NAME", "relay-sidecar")

# ----------------------------------------------------------------------------
# Entry point.
#
# The sidecar's __main__ module is relay_sidecar/__main__.py; PyInstaller
# treats this as the script argument to Analysis().
# ----------------------------------------------------------------------------

ENTRYPOINT = str(SIDECAR_PKG_DIR / "__main__.py")

# ----------------------------------------------------------------------------
# Hidden imports.
#
# FastAPI + uvicorn use runtime imports that PyInstaller's static analyzer
# does not always discover. aiosqlite and portalocker also have
# platform-conditional modules that need explicit declaration.
# ----------------------------------------------------------------------------

HIDDEN_IMPORTS = [
    # FastAPI dependency injection + Pydantic runtime model build
    "fastapi",
    "fastapi.routing",
    "fastapi.applications",
    "fastapi.dependencies.utils",
    "pydantic",
    "pydantic.fields",
    "pydantic.main",
    "pydantic_core",
    # uvicorn loop variants (we pin to plain asyncio per sidecar pyproject;
    # uvloop is intentionally excluded to avoid macOS ctypes statfs segfault
    # documented in apps/local-sidecar/pyproject.toml)
    "uvicorn",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.lifespan.on",
    # aiosqlite + sqlite3 platform driver
    "aiosqlite",
    "sqlite3",
    # portalocker cross-platform lock backends
    "portalocker",
    "portalocker.portalocker",
    # httpx shared client (sidecar's outbound HTTP)
    "httpx",
    "httpx._transports.default",
    # zstandard for rolling event-log archive (VAL-W2-040)
    "zstandard",
    # schemas package (workspace dep)
    "epochly_relay_schemas",
]

# ----------------------------------------------------------------------------
# Data + binaries.
#
# - SQL migration files: the sidecar runs migrations from a packaged
#   directory; PyInstaller's --add-data flag is mirrored here.
# - No vendored TLS roots: the binary uses the OS trust store by default
#   (avoids embedding cert material which conflicts with banned #14).
# - No trust-anchor public keys: the Sigstore verifier in the npx wrapper
#   fetches JWKS from relay.epochly.com per CLAUDE.md keystone #11.
# ----------------------------------------------------------------------------

MIGRATIONS_DIR = REPO_ROOT / "apps" / "local-sidecar" / "migrations"
DATAS = []
if MIGRATIONS_DIR.is_dir():
    # PyInstaller expects (src, dest) tuples; dest is relative to the bundle.
    DATAS.append((str(MIGRATIONS_DIR), "migrations"))

# ----------------------------------------------------------------------------
# Excludes.
#
# Trim the bundle by excluding modules we explicitly do not ship:
#   - tkinter: no GUI surface
#   - tests / pytest: test-only deps
#   - uvloop: excluded for the reason documented in sidecar pyproject.toml
# ----------------------------------------------------------------------------

EXCLUDES = [
    "tkinter",
    "pytest",
    "pytest_asyncio",
    "pytest_timeout",
    "uvloop",
]

# ----------------------------------------------------------------------------
# PyInstaller Analysis + EXE pipeline.
#
# console=True: the sidecar is a daemon-style HTTP server with stderr logs;
# a console binary is correct on every platform (incl. Windows where
# console=False would produce a windowed app with no logging surface).
#
# upx=False: UPX compression breaks notarization on macOS and triggers
# false-positive AV scans on Windows. The Sigstore signature applies to
# the unpacked binary, so signature verification works whether or not UPX
# was applied; we disable it to maximize first-run reliability per
# VAL-W12-026.
# ----------------------------------------------------------------------------

a = Analysis(
    [ENTRYPOINT],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=OUTPUT_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # see comment above
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,  # workflow sets ARCHFLAGS for cross-arch on macOS
    codesign_identity=None,  # signing is done post-build by the workflow
    entitlements_file=None,
)
