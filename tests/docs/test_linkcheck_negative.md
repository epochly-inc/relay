<!--
  NEGATIVE TEST FIXTURE -- do not link from real docs.

  Purpose: a manual / opt-in trigger to confirm CI linkcheck actually fails on
  broken links. To exercise:

    lychee --no-progress tests/docs/test_linkcheck_negative.md

  Expected: non-zero exit (broken link detected). The positive CI workflow at
  .github/workflows/linkcheck.yml excludes this path via .lychee.toml
  `exclude_path` so it does not break normal builds.

  Spec citations:
    - plan.md Wave 4 deliverable 41 (linkcheck)
    - contract VAL-DOCS-M4-007
-->

# Linkcheck Negative Fixture

This page intentionally links to
[a definitively-broken URL](https://thisdoesnotexist-relay-test-fixture.invalid)
so that we can verify CI linkcheck catches broken links when invoked directly
against this file.

Do NOT link to this page from any real doc.
