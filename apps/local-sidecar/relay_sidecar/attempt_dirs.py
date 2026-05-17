"""Per-attempt artifact directory scheme (spec section AM.5, lines 5927-5931).

Adopts the SRP-SP P6 append-only artifact tree verbatim: every gate
round writes its artifacts under
``<artifacts_root>/attempts/<round>-<worker_id>/`` so retries cannot
overwrite the evidence of the original failure. The
``evidence_bundle_registry`` row's ``artifact_prefix`` field points at
exactly one of those directories (the canonical accepted attempt);
other attempt directories remain on disk untouched.

Per CLAUDE.md keystone invariant #8 the four atomic-persistence
primitives are the only sanctioned write path for sidecar-owned files.
This module owns DIRECTORY structure, not file writes. It exposes
``resolve_attempt_dir`` (mkdir helper) and ``list_attempt_dirs``
(directory enumeration), and the small ``bind_canonical_attempt``
helper that constructs an in-memory ``evidence_bundle_registry`` row
dict bound to a single canonical attempt directory.

Public API:

  * :class:`AttemptDir` - immutable triple (round, worker_id, path).
  * :func:`resolve_attempt_dir` - resolve + optionally mkdir the
    attempt directory for ``(round, worker_id)`` under an artifacts root.
  * :func:`list_attempt_dirs` - enumerate every attempt directory under
    an artifacts root in deterministic (round, worker_id) order.
  * :func:`bind_canonical_attempt` - build the registry-row dict
    pointing at the canonical accepted attempt.

Determinism guarantees (load-bearing for VAL-V2M08-036/037):

  * The path layout is byte-stable: ``attempts/<round>-<worker_id>/``.
  * ``list_attempt_dirs`` sorts by (round asc, worker_id asc).
  * ``resolve_attempt_dir`` with ``create=True, exist_ok=False`` raises
    ``FileExistsError`` so a careless retry cannot silently overwrite
    the original failure's evidence.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# Subdirectory name under artifacts_root that holds every attempt.
# Spec AM.5 line 5929 fixes this layout for hosted R2 storage; line 5931
# requires the local OSS profile use the SRP-SP layout verbatim.
ATTEMPTS_DIRNAME: Final[str] = "attempts"

# Attempt directory name regex: <round>-<worker_id>. round is a 1+ digit
# positive integer; worker_id is non-empty and contains only the
# characters [A-Za-z0-9_-] (matches relay worker_id allowable set
# defined alongside spec C.5 three-anchor handoff identity).
_ATTEMPT_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<round>[1-9][0-9]*)-(?P<worker_id>[A-Za-z0-9_\-]+)$"
)


@dataclass(frozen=True)
class AttemptDir:
    """Immutable triple describing one attempt directory.

    Fields:

      * ``round_`` - the 1-indexed gate round number.
      * ``worker_id`` - the worker identifier (e.g., ``w-abc``).
      * ``path`` - the resolved on-disk path
        (``<artifacts_root>/attempts/<round>-<worker_id>/``).
    """

    round_: int
    worker_id: str
    path: Path


def _attempt_name(round_: int, worker_id: str) -> str:
    """Compute the canonical directory name for an attempt.

    Validates the inputs eagerly so a malformed (round, worker_id) pair
    surfaces here instead of silently writing artifacts under a path
    that ``list_attempt_dirs`` will later refuse to enumerate.
    """
    if not isinstance(round_, int) or isinstance(round_, bool) or round_ < 1:
        raise ValueError(
            f"attempt round must be a positive integer; got {round_!r}"
        )
    if not isinstance(worker_id, str) or not worker_id:
        raise ValueError(f"worker_id must be a non-empty string; got {worker_id!r}")
    name = f"{round_}-{worker_id}"
    if not _ATTEMPT_NAME_RE.match(name):
        raise ValueError(
            f"worker_id contains characters outside [A-Za-z0-9_-]: {worker_id!r}"
        )
    return name


def resolve_attempt_dir(
    *,
    artifacts_root: Path | str,
    round_: int,
    worker_id: str,
    create: bool = False,
    exist_ok: bool = True,
) -> AttemptDir:
    """Resolve (and optionally create) the attempt directory.

    Args:
        artifacts_root: the parent directory under which the
            ``attempts/`` subtree lives. Parent of this root is the
            caller's responsibility (typically the sidecar's
            per-run artifacts root).
        round_: the gate round number (1-indexed).
        worker_id: the worker identifier (e.g., ``w-abc``).
        create: when True, ensure the directory exists. The
            ``attempts/`` parent is created with ``parents=True``.
        exist_ok: when False and ``create`` is True, raise
            ``FileExistsError`` if the directory already exists.
            Default True preserves idempotent resolution for callers
            that re-derive paths during recovery.

    Returns:
        :class:`AttemptDir` describing the resolved attempt.

    Raises:
        ValueError: when ``round_`` or ``worker_id`` is malformed.
        FileExistsError: when ``create=True`` and ``exist_ok=False``
            and the directory already exists. Load-bearing for spec
            AM.5: a retry must NEVER overwrite the prior attempt's
            artifacts.
    """
    name = _attempt_name(round_, worker_id)
    root = Path(artifacts_root)
    path = root / ATTEMPTS_DIRNAME / name
    if create:
        # Create the attempts/ parent with parents=True regardless of
        # exist_ok; only the leaf directory honors exist_ok.
        (root / ATTEMPTS_DIRNAME).mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not exist_ok:
                raise FileExistsError(
                    f"attempt directory already exists; refusing to overwrite: {path}"
                )
            # exist_ok=True: idempotent no-op.
        else:
            path.mkdir(parents=False, exist_ok=False)
    return AttemptDir(round_=round_, worker_id=worker_id, path=path)


def list_attempt_dirs(*, artifacts_root: Path | str) -> list[AttemptDir]:
    """Enumerate every attempt directory under ``artifacts_root``.

    Returns the list sorted by (round ascending, worker_id ascending).
    Skips entries that do not match the canonical attempt naming pattern
    so unrelated subdirectories (or stray dotfiles) are not surfaced as
    attempts. Returns an empty list when no ``attempts/`` subdirectory
    exists yet.
    """
    root = Path(artifacts_root)
    base = root / ATTEMPTS_DIRNAME
    if not base.is_dir():
        return []
    results: list[AttemptDir] = []
    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        match = _ATTEMPT_NAME_RE.match(entry.name)
        if match is None:
            # Skip non-conforming directories; surfacing them as
            # attempts would produce misleading round counts.
            continue
        results.append(
            AttemptDir(
                round_=int(match.group("round")),
                worker_id=match.group("worker_id"),
                path=entry,
            )
        )
    # Deterministic order: round asc, worker_id asc. Required so
    # VAL-V2M08-036 can assert exact (round, worker_id) sequences.
    results.sort(key=lambda d: (d.round_, d.worker_id))
    return results


def bind_canonical_attempt(
    *,
    evidence_bundle_id: str,
    canonical: AttemptDir,
    artifacts_root: Path | str,
    state: str = "active",
) -> dict[str, str]:
    """Construct an evidence_bundle_registry row dict for the canonical
    accepted attempt.

    The row's ``artifact_prefix`` is a POSIX-style relative path under
    ``artifacts_root`` referencing exactly one
    ``attempts/<round>-<worker_id>/`` directory. Other attempt
    directories under the same root remain untouched (this function
    performs NO filesystem mutation; it only computes the registry-row
    payload).

    Spec AM.5 line 5929: "the ``evidence_bundle_registry`` row points
    to the canonical attempt." This helper is the construction site for
    that pointer.

    Args:
        evidence_bundle_id: the bundle identifier the row keys on.
        canonical: the :class:`AttemptDir` for the accepted attempt.
            MUST be a descendant of ``artifacts_root/attempts/`` or
            ``ValueError`` is raised.
        artifacts_root: the per-run artifacts root the prefix is
            relative to.
        state: registry state. Defaults to ``"active"`` (the canonical
            accepted state); callers in still-building flows may pass
            ``"building"``.

    Returns:
        Dict shaped like an ``evidence_bundle_registry`` row with at
        least ``evidence_bundle_id``, ``state``, and ``artifact_prefix``.

    Raises:
        ValueError: when ``canonical.path`` is not under
            ``artifacts_root/attempts/``.
    """
    if not evidence_bundle_id:
        raise ValueError("evidence_bundle_id must be a non-empty string")
    root = Path(artifacts_root).resolve()
    attempts_base = (root / ATTEMPTS_DIRNAME).resolve()
    canonical_resolved = canonical.path.resolve()
    try:
        relative = canonical_resolved.relative_to(attempts_base)
    except ValueError as exc:
        raise ValueError(
            f"canonical attempt {canonical.path} is not under "
            f"{attempts_base}; cannot bind"
        ) from exc
    # POSIX-style path under artifacts_root (no leading slash).
    artifact_prefix = f"{ATTEMPTS_DIRNAME}/{relative.as_posix()}"
    return {
        "evidence_bundle_id": evidence_bundle_id,
        "state": state,
        "artifact_prefix": artifact_prefix,
    }


__all__ = [
    "ATTEMPTS_DIRNAME",
    "AttemptDir",
    "bind_canonical_attempt",
    "list_attempt_dirs",
    "resolve_attempt_dir",
]
