"""Validation primitives for the sidecar's ingest and auth surfaces.

Each module here implements a single adversarial-input hardening check
declared in M08-W8 (spec AI lines 5651-5732). Modules are pure (no
network, no filesystem mutation, no global state) so they can be
exercised by tier-1 plumbing tests without spawning the full sidecar.
"""
