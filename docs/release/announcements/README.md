# Breaking-change announcements

This directory holds breaking-change announcements for `epochly-relay`
releases. Per spec section Q.2 (and contract assertion VAL-W12-046),
the release workflow refuses to publish a tag annotated with the
`RELAY-BREAKING-CHANGE` marker unless a qualifying announcement file
exists here AND was published at least 7 days earlier than the
release.

## File format

```
docs/release/announcements/YYYY-MM-DD-<slug>.md
```

Frontmatter (required):

```markdown
---
target_version: 1.0.0
breaking: true
published_at: 2026-04-15T12:00:00Z
---

# v1.0.0: Drops Python 3.11 support

<body explaining the breaking change, migration guidance, etc.>
```

The frontmatter parser in `scripts/check-pre-announcement.py` is
intentionally minimal (no nested YAML). The three required keys
(`target_version`, `breaking`, `published_at`) must be present and
non-empty; `published_at` must be RFC 3339 with explicit timezone
offset (we accept the trailing `Z` shortcut for UTC).

## What "breaking" means

A release is breaking when removing or changing the behavior of a
publicly-supported API in `epochly-relay` would force downstream
users to modify their code. Dropping a Python version, renaming a
public function, or changing the wire format of an evidence bundle
all qualify. Adding a new optional parameter, bumping an internal
dependency, or fixing a documented bug do not.

When in doubt, treat the change as breaking and write the announcement
7+ days ahead. The cost of an unnecessary announcement is one markdown
file; the cost of a surprise breaking release is downstream trust.

## Marking a tag breaking

The tag is the gate input. Annotate the tag with the literal token
`RELAY-BREAKING-CHANGE` on its own line:

```
git tag -a v1.0.0 -m "v1.0.0

RELAY-BREAKING-CHANGE

Drops Python 3.11 support. See announcement
docs/release/announcements/2026-04-15-drop-py311.md."
git push origin v1.0.0
```

The pre-announcement gate (`scripts/check-pre-announcement.py`)
detects the token, looks up the matching announcement, and verifies
the 7-day lead time. Non-breaking tags skip the check entirely.

## Cross-references

- Runbook: `docs/release/runbook.md`
- Pre-announcement gate: `scripts/check-pre-announcement.py`
- Contract assertion: VAL-W12-046 (`relay-v0.1-oss-wedge` operation)
- Spec section: Q.2 ("major changes pre-announced 7 days in advance")
