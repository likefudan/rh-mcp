# Security review artifacts for `v0.1.0`

This directory holds the deliverables of the independent security review of
release `v0.1.0` (commit `a81464f699fc3c9dc314e674a1198c7fe2b9ab8f`).

| File | Purpose |
|---|---|
| `REPORT.md` | Full report per `INDEPENDENT_SECURITY_REVIEW.md` §13 |
| `test_adversarial_review.py` | Reviewer-authored adversarial tests |

## Re-run the adversarial tests against the pinned source

```bash
git fetch --tags
git worktree add /tmp/rh-mcp-v0.1.0-review a81464f699fc3c9dc314e674a1198c7fe2b9ab8f
cd /tmp/rh-mcp-v0.1.0-review
uv sync --frozen
PYTHONPATH=/tmp/rh-mcp-v0.1.0-review \
  uv run --frozen pytest /path/to/repo/security-review/v0.1.0/test_adversarial_review.py -v
```

Against `v0.1.0`, expect **27 passed / 4 failed**. The four failures are the
secure-property assertions for findings P0 and P1 in `REPORT.md`. They must
turn green on a fixed release before approval.

## Status against the fixed source (added by the implementer)

Against `v0.2.0` this file passes **31 / 31**, on both supported interpreters,
and CI runs it on every commit. Reverting either fix makes exactly the
corresponding assertions fail again — verified in both directions, and pinned
by `scripts/mutate.py`.

Two lines were removed from `test_adversarial_review.py`; no assertion was
changed. The file's module-level import of `open_provider_session` cannot
coexist with its own
`test_open_provider_session_is_importable_from_installed_package`, and it
backed no assertion. The full reasoning is in a note at the foot of that file.

`REPORT.md` is unmodified. Its findings describe `v0.1.0` and remain the
record of what was found there. Its approval gate is bound to the `v0.1.0`
commit and artifacts: **`v0.2.0` is a new artifact and is not covered by it.**
