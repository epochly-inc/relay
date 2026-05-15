"""W5.3 plumbing tests: ``rly replay`` subcommands.

Encodes every VAL-W5-019 .. VAL-W5-024 assertion as a plumbing-tier test
bound to its assertion via the ``@pytest.mark.fulfills(...)`` marker.

Per CLAUDE.md test discipline + boundaries.md:

  * The CLI MUST NOT write ``run_results`` (keystone invariant #1). The
    grep test `test_replay_source_does_not_write_run_results` enforces
    that there is zero canonical-row write path under packages/cli/.
  * Cassette mode is the default playback mode (keystone invariant #9);
    no test is allowed to invoke a live mode in the CI matrix.
  * All persistent writes flow through ``local_atomic_file_write``.
  * Tests use ``tmp_path`` and ``RELAY_HOME`` overrides; the real
    ``~/.relay`` is NEVER touched.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Match triple-quoted strings (both """...""" and '''...''') across multiple
# lines. Used by the static guard tests to drop docstring prose before
# regex-grepping for banned code patterns. Triple-quoted strings are the
# canonical docstring form in this codebase; ordinary string literals
# (e.g., ``'wb'``, ``'INSERT INTO ...'``) remain in the projected text so
# the guard still catches real code violations.
_TRIPLE_QUOTED_RE = re.compile(
    r'(?ms)("""(?:\\.|(?!""").)*"""' + r"|'''(?:\\.|(?!''').)*''')"
)


def _strip_docstrings(source: str) -> str:
    """Return ``source`` with prose-bearing surfaces removed.

    Drops both:
      * Triple-quoted string blocks (``\"\"\"...\"\"\"`` and ``'''...'''``):
        the canonical docstring form in this codebase.
      * Single-line ``#`` comments (everything from a ``#`` outside a
        string literal to end-of-line): the canonical inline-comment form.

    Static guard tests grep against this projection so prose explaining
    *why* a token is banned (e.g., an inline comment that names a
    canonical-row write verb in narrative form) does not trip the regex.
    Real code that uses single-/double-quoted SQL strings or open()
    modes survives both strips because it lives outside docstrings and
    outside ``#`` comments.

    Line counts are preserved (newline-padded placeholders for triple-
    quoted blocks; single ``#`` comments are simply dropped to end-of-line)
    so any line-anchored downstream regex still reports the right line.
    """
    # Step 1: strip triple-quoted blocks first, padding with newlines.
    def _doc_replacer(match: re.Match[str]) -> str:
        block = match.group(0)
        line_count = block.count("\n")
        if line_count == 0:
            return "''"
        return "''" + ("\n" * line_count)
    intermediate = _TRIPLE_QUOTED_RE.sub(_doc_replacer, source)

    # Step 2: per-line, strip ``#`` to end-of-line UNLESS the ``#`` is
    # inside a single-line string literal (rare; canonical Python forbids
    # multi-line ordinary strings without triple quoting which we already
    # stripped). The naive split is sufficient for the CLI source files
    # we guard.
    out_lines: list[str] = []
    for line in intermediate.split("\n"):
        in_single = False
        in_double = False
        cut_at: int | None = None
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == "\\" and i + 1 < len(line):
                # Skip escaped character; relevant inside strings to avoid
                # treating an escaped quote as a string boundary.
                i += 2
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                cut_at = i
                break
            i += 1
        if cut_at is not None:
            out_lines.append(line[:cut_at])
        else:
            out_lines.append(line)
    return "\n".join(out_lines)

# Repository root (relay/), four parents up from this test file.
REPO_ROOT = Path(__file__).resolve().parents[3]


# -----------------------------------------------------------------------------
# Subprocess invocation helpers
# -----------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``uv run rly <args>`` non-TTY (capture_output=True)."""
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["uv", "run", "rly", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def _record_source_doc(calls: list[dict[str, Any]]) -> str:
    """Serialize a recorded-calls list to canonical JSON for the seam env."""
    return json.dumps(calls, sort_keys=True, separators=(",", ":"))


def _basic_record_env(
    home: Path,
    src_path: Path,
    *,
    session_id: str = "00000000000000000000000001",
    recorded_at: str = "2026-05-14T00:00:00.000000Z",
    manifest_hash: str = "sha256-" + ("a" * 64),
) -> dict[str, str]:
    """Return env vars that pin the recorder header for digest determinism."""
    return {
        "RELAY_HOME": str(home),
        "RELAY_CLI_REPLAY_RECORD_SOURCE": str(src_path),
        "RELAY_CLI_REPLAY_RECORD_SESSION_ID": session_id,
        "RELAY_CLI_REPLAY_RECORD_RECORDED_AT": recorded_at,
        "RELAY_CLI_REPLAY_RECORD_MANIFEST_HASH": manifest_hash,
    }


def _write_record_source(path: Path, calls: list[dict[str, Any]]) -> None:
    """Write the recorded-calls JSON document where the recorder will read it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_record_source_doc(calls), encoding="utf-8")


def _sample_call_none(
    *, idx: int = 0, side_effect_class: str = "none"
) -> dict[str, Any]:
    """Return a deterministic recorded call shape for tests."""
    return {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "request": {"messages": [{"role": "user", "content": f"hello {idx}"}]},
        "response": {"id": f"chatcmpl-{idx}", "choices": [{"index": 0}]},
        "timestamp": f"2026-05-14T00:00:0{idx}Z",
        "side_effect_class": side_effect_class,
    }


# =============================================================================
# Cassette serializer determinism (foundational for VAL-W5-020)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-020")
def test_cassette_serialize_is_deterministic_in_process() -> None:
    """``serialize_cassette`` MUST produce byte-identical output for same input."""
    from relay_cli.cassette import (
        CASSETTE_ENTRY_SCHEMA_VERSION,
        CASSETTE_HEADER_SCHEMA_VERSION,
        CassetteEntry,
        CassetteHeader,
        canonical_request_digest,
        canonical_response_digest,
        serialize_cassette,
    )

    header = CassetteHeader(
        schema_version=CASSETTE_HEADER_SCHEMA_VERSION,
        case_id="case-abc",
        session_id="sess-xyz",
        recorded_at="2026-05-14T00:00:00Z",
        manifest_commit_hash="sha256-" + ("0" * 64),
    )
    req = {"k": "v", "nested": {"b": 2, "a": 1}}
    rsp = {"id": "x"}
    entry = CassetteEntry(
        schema_version=CASSETTE_ENTRY_SCHEMA_VERSION,
        sequence=0,
        provider="openai",
        model="gpt-4o-mini",
        request_digest=canonical_request_digest(req),
        response=rsp,
        response_digest=canonical_response_digest(rsp),
        timestamp="2026-05-14T00:00:00Z",
    )
    a = serialize_cassette(header, [entry])
    b = serialize_cassette(header, [entry])
    assert a == b, "serialize_cassette must be deterministic in-process"
    # Trailing newline contract.
    assert a.endswith(b"\n")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-020")
def test_cassette_parse_roundtrips_serialized_bytes() -> None:
    """``parse_cassette(serialize_cassette(...))`` MUST roundtrip the entries."""
    from relay_cli.cassette import (
        CASSETTE_ENTRY_SCHEMA_VERSION,
        CASSETTE_HEADER_SCHEMA_VERSION,
        CassetteEntry,
        CassetteHeader,
        canonical_request_digest,
        canonical_response_digest,
        parse_cassette,
        serialize_cassette,
    )

    header = CassetteHeader(
        schema_version=CASSETTE_HEADER_SCHEMA_VERSION,
        case_id="case-rt",
        session_id="sess-rt",
        recorded_at="2026-05-14T00:00:00Z",
        manifest_commit_hash="sha256-" + ("0" * 64),
    )
    entries = []
    for i in range(3):
        req = {"i": i}
        rsp = {"r": i}
        entries.append(
            CassetteEntry(
                schema_version=CASSETTE_ENTRY_SCHEMA_VERSION,
                sequence=i,
                provider="openai",
                model="gpt-4o-mini",
                request_digest=canonical_request_digest(req),
                response=rsp,
                response_digest=canonical_response_digest(rsp),
                timestamp=f"2026-05-14T00:00:0{i}Z",
            )
        )
    raw = serialize_cassette(header, entries)
    parsed = parse_cassette(raw)
    assert parsed.header.case_id == "case-rt"
    assert len(parsed.entries) == 3
    assert [e.sequence for e in parsed.entries] == [0, 1, 2]
    # File-level digest matches what hashlib computes over the bytes.
    assert parsed.file_digest_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-020")
def test_cassette_rejects_out_of_order_sequence() -> None:
    """A cassette whose entries skip a sequence index MUST fail to parse."""
    from relay_cli.cassette import CassetteFormatError, parse_cassette

    raw = (
        b'{"case_id":"c","manifest_commit_hash":"sha256-0000000000000000000000000000000000000000000000000000000000000000","recorded_at":"2026-05-14T00:00:00Z","schema_version":"relay.cassette.v1","session_id":"s"}\n'
        b'{"model":"m","provider":"openai","request_digest":"sha256-x","response":{},"response_digest":"sha256-y","schema_version":"relay.cassette_entry.v1","sequence":5,"timestamp":"t"}\n'
    )
    with pytest.raises(CassetteFormatError):
        parse_cassette(raw)


# =============================================================================
# VAL-W5-019: ``rly replay list`` returns paginated JSON with cursor
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-019")
def test_replay_list_empty_registry_emits_zero_items(tmp_path: Path) -> None:
    """No registry -> items=[], next_cursor=null, has_more=false, exit 0."""
    home = tmp_path / "relay_home_list_empty"
    home.mkdir()
    result = _run_rly(["replay", "list"], extra_env={"RELAY_HOME": str(home)})
    assert result.returncode == 0, "stderr=" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.replay_list.v1"
    assert payload["items"] == []
    assert payload["next_cursor"] is None
    assert payload["has_more"] is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-019")
def test_replay_list_returns_recorded_case(tmp_path: Path) -> None:
    """After `record`, `list` MUST surface the case with required fields."""
    home = tmp_path / "relay_home_list_one"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)

    record = _run_rly(["replay", "record", "--run-id", "run-1"], extra_env=env)
    assert record.returncode == 0, "record stderr=" + record.stderr

    listed = _run_rly(["replay", "list"], extra_env={"RELAY_HOME": str(home)})
    assert listed.returncode == 0, "list stderr=" + listed.stderr
    payload = json.loads(listed.stdout)
    assert payload["schema_version"] == "relay.cli.replay_list.v1"
    assert payload["has_more"] is False
    assert payload["next_cursor"] is None
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert isinstance(item["replay_case_id"], str) and item["replay_case_id"]
    assert "name" in item
    assert "last_run_at" in item
    assert "last_status" in item
    assert isinstance(item["fixture_digest"], str) and len(item["fixture_digest"]) == 64


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-019")
def test_replay_list_pagination_cursor_advances(tmp_path: Path) -> None:
    """``--limit 1`` MUST surface has_more=true and a non-null cursor."""
    home = tmp_path / "relay_home_list_paged"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env_base = _basic_record_env(home, src)

    # Record three distinct cases by varying run_id (-> distinct case_ids).
    for run_id in ("run-a", "run-b", "run-c"):
        rec = _run_rly(
            ["replay", "record", "--run-id", run_id],
            extra_env=env_base,
        )
        assert rec.returncode == 0, "record " + run_id + " stderr=" + rec.stderr

    page1 = _run_rly(
        ["replay", "list", "--limit", "1"],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert page1.returncode == 0, "page1 stderr=" + page1.stderr
    p1 = json.loads(page1.stdout)
    assert len(p1["items"]) == 1
    assert p1["has_more"] is True
    assert isinstance(p1["next_cursor"], str) and p1["next_cursor"]

    page2 = _run_rly(
        ["replay", "list", "--limit", "1", "--cursor", p1["next_cursor"]],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert page2.returncode == 0
    p2 = json.loads(page2.stdout)
    assert len(p2["items"]) == 1
    # Cursor advances to a different case_id (registry sorted).
    assert p2["items"][0]["replay_case_id"] != p1["items"][0]["replay_case_id"]


# =============================================================================
# VAL-W5-020: ``rly replay record`` produces a deterministic fixture digest
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-020")
def test_replay_record_emits_record_envelope(tmp_path: Path) -> None:
    """Stdout JSON MUST carry the spec-pinned schema and required fields."""
    home = tmp_path / "relay_home_record"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)

    result = _run_rly(["replay", "record", "--run-id", "run-1"], extra_env=env)
    assert result.returncode == 0, "stderr=" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.replay_record.v1"
    assert isinstance(payload["replay_case_id"], str) and payload["replay_case_id"]
    assert payload["fixture_path"].endswith(".json")
    assert isinstance(payload["fixture_digest"], str) and len(payload["fixture_digest"]) == 64
    assert payload["captured_calls"] == 1
    # Fixture is on disk and its sha256 matches the reported digest.
    on_disk = Path(payload["fixture_path"]).read_bytes()
    assert hashlib.sha256(on_disk).hexdigest() == payload["fixture_digest"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-020")
def test_replay_record_digest_is_stable_across_invocations(tmp_path: Path) -> None:
    """Re-running record with the same input MUST yield the same digest."""
    home = tmp_path / "relay_home_det"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(
        src,
        [_sample_call_none(idx=0), _sample_call_none(idx=1)],
    )
    env = _basic_record_env(home, src)

    first = _run_rly(["replay", "record", "--run-id", "run-det"], extra_env=env)
    assert first.returncode == 0, "first stderr=" + first.stderr
    second = _run_rly(["replay", "record", "--run-id", "run-det"], extra_env=env)
    assert second.returncode == 0, "second stderr=" + second.stderr
    p1 = json.loads(first.stdout)
    p2 = json.loads(second.stdout)
    assert p1["replay_case_id"] == p2["replay_case_id"]
    assert p1["fixture_digest"] == p2["fixture_digest"], (
        "fixture_digest must be stable across record invocations on same input"
    )


# =============================================================================
# VAL-W5-021: ``rly replay run`` defaults to cassette mode (no live calls)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-021")
def test_replay_run_default_mode_is_cassette(tmp_path: Path) -> None:
    """Without --mode, run MUST report mode='cassette' and exit 0."""
    home = tmp_path / "relay_home_run_default"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-cm"], extra_env=env)
    assert rec.returncode == 0, "record stderr=" + rec.stderr
    case_id = json.loads(rec.stdout)["replay_case_id"]

    run = _run_rly(
        ["replay", "run", "--case", case_id],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert run.returncode == 0, "run stderr=" + run.stderr
    payload = json.loads(run.stdout)
    assert payload["schema_version"] == "relay.cli.replay_run.v1"
    assert payload["mode"] == "cassette"
    assert payload["entries_played"] == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-021")
def test_replay_run_rejects_unsupported_live_mode(tmp_path: Path) -> None:
    """``--mode live`` MUST be rejected (live mode lands in W6)."""
    home = tmp_path / "relay_home_run_live"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-live"], extra_env=env)
    assert rec.returncode == 0
    case_id = json.loads(rec.stdout)["replay_case_id"]

    result = _run_rly(
        ["replay", "run", "--case", case_id, "--mode", "live"],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 64, (
        "expected exit 64 for unsupported mode; got " + str(result.returncode)
    )
    # Envelope on stderr.
    err = json.loads(result.stderr.strip().splitlines()[-1])
    assert err["code"] == "RELAY-CLI-REPLAY-MODE-UNSUPPORTED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-021")
def test_replay_source_does_not_import_live_provider_clients() -> None:
    """The replay command source MUST NOT import openai/anthropic/httpx clients.

    This is a static guard for keystone invariant #9: cassette-first replay
    must not silently fall through to live execution. The implementation
    file should be free of provider-client imports; cassette playback uses
    only file I/O on registered fixtures.
    """
    src = (
        REPO_ROOT / "packages" / "cli" / "src" / "relay_cli" / "commands" / "replay.py"
    ).read_text(encoding="utf-8")
    banned_imports = [
        r"^import\s+openai\b",
        r"^from\s+openai\b",
        r"^import\s+anthropic\b",
        r"^from\s+anthropic\b",
        r"^import\s+httpx\b",
        r"^from\s+httpx\b",
        r"^import\s+requests\b",
        r"^from\s+requests\b",
    ]
    for pat in banned_imports:
        matches = re.findall(pat, src, flags=re.MULTILINE)
        assert not matches, "replay.py imports a live provider client: " + pat


# =============================================================================
# VAL-W5-022: side effects blocked without explicit policy override
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-022")
def test_replay_run_blocks_mutating_side_effects_by_default(tmp_path: Path) -> None:
    """Mutating-class case MUST exit 1 with RELAY-REPLAY-014 on stderr."""
    home = tmp_path / "relay_home_se_block"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(
        src,
        [_sample_call_none(idx=0, side_effect_class="mutating")],
    )
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-mut"], extra_env=env)
    assert rec.returncode == 0, "record stderr=" + rec.stderr
    case_id = json.loads(rec.stdout)["replay_case_id"]

    result = _run_rly(
        ["replay", "run", "--case", case_id],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 1, (
        "expected exit 1 (block) for mutating side effects; got "
        + str(result.returncode) + " stderr=" + result.stderr
    )
    err = json.loads(result.stderr.strip().splitlines()[-1])
    assert err["code"] == "RELAY-REPLAY-014"
    assert "mutating" in err["details"]["blocked_side_effect_classes"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-022")
def test_replay_run_allows_mutating_with_explicit_override(tmp_path: Path) -> None:
    """`--allow-side-effects=mutating` MUST permit playback (exit 0)."""
    home = tmp_path / "relay_home_se_allow"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(
        src,
        [_sample_call_none(idx=0, side_effect_class="mutating")],
    )
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-mut2"], extra_env=env)
    assert rec.returncode == 0
    case_id = json.loads(rec.stdout)["replay_case_id"]

    result = _run_rly(
        [
            "replay",
            "run",
            "--case",
            case_id,
            "--allow-side-effects",
            "mutating",
        ],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 0, "run stderr=" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["allowed_side_effect_classes"] == ["mutating"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-022")
def test_replay_run_blocks_external_irreversible_by_default(tmp_path: Path) -> None:
    """external_irreversible class MUST also be blocked by default."""
    home = tmp_path / "relay_home_se_ext"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(
        src,
        [_sample_call_none(idx=0, side_effect_class="external_irreversible")],
    )
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-ext"], extra_env=env)
    assert rec.returncode == 0, "record stderr=" + rec.stderr
    case_id = json.loads(rec.stdout)["replay_case_id"]

    result = _run_rly(
        ["replay", "run", "--case", case_id],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 1
    err = json.loads(result.stderr.strip().splitlines()[-1])
    assert err["code"] == "RELAY-REPLAY-014"
    assert "external_irreversible" in err["details"]["blocked_side_effect_classes"]


# =============================================================================
# VAL-W5-023: fixture-digest mismatch is rejected
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-023")
def test_replay_run_rejects_digest_mismatch(tmp_path: Path) -> None:
    """Tampering with the on-disk fixture MUST cause RELAY-REPLAY-001."""
    home = tmp_path / "relay_home_dig_mm"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-mm"], extra_env=env)
    assert rec.returncode == 0
    rec_payload = json.loads(rec.stdout)
    fixture_path = Path(rec_payload["fixture_path"])

    # Tamper: append a benign byte; the on-disk SHA-256 changes but
    # parse_cassette would also reject -- the digest check fires first
    # so the surface error is RELAY-REPLAY-001.
    tampered = fixture_path.read_bytes() + b" "
    fixture_path.write_bytes(tampered)

    result = _run_rly(
        ["replay", "run", "--case", rec_payload["replay_case_id"]],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 1, (
        "expected exit 1 for digest mismatch; got " + str(result.returncode)
        + " stderr=" + result.stderr
    )
    err = json.loads(result.stderr.strip().splitlines()[-1])
    assert err["code"] == "RELAY-REPLAY-001"
    assert err["details"]["expected_digest"] == rec_payload["fixture_digest"]
    assert err["details"]["actual_digest"] != rec_payload["fixture_digest"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-023")
def test_replay_run_does_not_silently_recapture(tmp_path: Path) -> None:
    """After a digest mismatch the on-disk fixture MUST NOT be overwritten."""
    home = tmp_path / "relay_home_no_recap"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-nr"], extra_env=env)
    assert rec.returncode == 0
    rec_payload = json.loads(rec.stdout)
    fixture_path = Path(rec_payload["fixture_path"])

    tampered = fixture_path.read_bytes() + b"x"
    fixture_path.write_bytes(tampered)
    pre_run_bytes = fixture_path.read_bytes()

    _ = _run_rly(
        ["replay", "run", "--case", rec_payload["replay_case_id"]],
        extra_env={"RELAY_HOME": str(home)},
    )
    post_run_bytes = fixture_path.read_bytes()
    assert pre_run_bytes == post_run_bytes, (
        "rly replay run MUST NOT silently rewrite the tampered fixture"
    )


# =============================================================================
# VAL-W5-024: rly replay run does NOT write canonical run_results
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-024")
def test_replay_source_does_not_write_run_results() -> None:
    """Static guard: zero canonical-row write paths in packages/cli/.

    Per CLAUDE.md keystone invariant #1 the CLI MUST NEVER
    INSERT/UPDATE ``run_results`` or ``gate_decisions``. The replay
    command in particular is the highest-risk surface because cassette
    playback could be tempted to "materialize" the replayed outcome.
    The contract requires the sidecar's replay-workers service to be
    the sole writer.
    """
    cli_src_dir = REPO_ROOT / "packages" / "cli" / "src"
    banned_patterns = [
        r"INSERT\s+INTO\s+run_results\b",
        r"UPDATE\s+run_results\b",
        r"INSERT\s+INTO\s+gate_decisions\b",
        r"UPDATE\s+gate_decisions\b",
    ]
    offending: list[str] = []
    for py_path in cli_src_dir.rglob("*.py"):
        # Strip module/function docstrings and inline comments so prose
        # that names a canonical-row write verb in narrative form does
        # not trip the guard. Only triple-quoted strings and ``#``
        # comments are stripped; real code that uses single/double-quoted
        # SQL strings is still detected.
        text = _strip_docstrings(py_path.read_text(encoding="utf-8"))
        for pat in banned_patterns:
            if re.search(pat, text, flags=re.IGNORECASE):
                offending.append(f"{py_path}: {pat}")
    assert not offending, "banned canonical write found in CLI source: " + str(offending)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-024")
def test_replay_run_envelope_declares_no_run_results_write(tmp_path: Path) -> None:
    """Run envelope MUST report wrote_run_results=false and CP attribution."""
    home = tmp_path / "relay_home_no_rr"
    home.mkdir()
    src = tmp_path / "src.json"
    _write_record_source(src, [_sample_call_none(idx=0)])
    env = _basic_record_env(home, src)
    rec = _run_rly(["replay", "record", "--run-id", "run-nrr"], extra_env=env)
    assert rec.returncode == 0
    case_id = json.loads(rec.stdout)["replay_case_id"]

    result = _run_rly(
        ["replay", "run", "--case", case_id],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 0, "stderr=" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["wrote_run_results"] is False
    # Attribution names the control-plane writer so log forwarders can
    # cross-check that the canonical row, when it eventually exists,
    # was written by the named service and NOT by the CLI.
    assert payload["control_plane_writer"] == "sidecar.replay-workers"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-024")
def test_replay_source_does_not_open_sidecar_db_for_writes() -> None:
    """Replay source MUST NOT open the sidecar SQLite database for writing.

    The CLI's replay surface is a pure file-I/O operator tool; it must
    not connect to ``${RELAY_HOME}/sidecar.db`` for any write path. The
    sidecar service is the sole owner of that database file.
    """
    src = (
        REPO_ROOT / "packages" / "cli" / "src" / "relay_cli" / "commands" / "replay.py"
    ).read_text(encoding="utf-8")
    banned = [
        r"sqlite3\.connect\b",
        r"aiosqlite\b",
        r"sidecar\.db",
    ]
    for pat in banned:
        matches = re.findall(pat, src)
        assert not matches, "replay.py touches sidecar.db: " + pat


# =============================================================================
# Boundary checks: replay command must not bypass atomic primitives
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-020")
def test_replay_module_does_not_call_open_for_writes() -> None:
    """Atomic-primitives-only guard for replay.py and cassette.py.

    Per boundaries.md §3 / CLAUDE.md keystone #8, persistent writes go
    through ``local_atomic_file_write``. Allow-list of test seam paths:
    the recorder reads its source via ``Path.read_bytes`` (read-only;
    not a banned write).
    """
    targets = [
        REPO_ROOT
        / "packages"
        / "cli"
        / "src"
        / "relay_cli"
        / "commands"
        / "replay.py",
        REPO_ROOT / "packages" / "cli" / "src" / "relay_cli" / "cassette.py",
    ]
    banned_write_patterns = [
        r"open\([^)]+['\"]w['\"]",
        r"open\([^)]+['\"]wb['\"]",
        r"\.write_bytes\(",
        r"\.write_text\(",
        r"shutil\.move\(",
        r"shutil\.copy\(",
        r"os\.rename\(",
    ]
    for target in targets:
        # Strip docstrings so prose like ``open(..., 'wb')`` in a comment
        # explaining the banned pattern does not trip the guard. Real
        # banned calls use the literal ``'wb'`` string which survives
        # docstring stripping (only triple-quoted blocks are removed).
        text = _strip_docstrings(target.read_text(encoding="utf-8"))
        for pat in banned_write_patterns:
            matches = re.findall(pat, text)
            assert not matches, (
                f"{target.name} bypasses atomic primitives: pattern {pat} "
                f"matched {matches}"
            )


# Suppress unused-import warning for sys (kept for future skip conditions).
_ = sys
