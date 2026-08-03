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
