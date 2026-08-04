# Security review artifacts for `v0.2.0`

Deliverables of the independent security review of release `v0.2.0`
(commit `46128a623c87f954c18d037870e4ac36b9e61e13`).

| File | Purpose |
|---|---|
| `REPORT.md` | Full report per `INDEPENDENT_SECURITY_REVIEW.md` §13 |
| `test_adversarial_review_v020.py` | Additional reviewer-authored adversarial tests |

**Disposition: `APPROVED_FOR_AINVEST_INTEGRATION`** for this exact artifact only.

## Re-run

```bash
git fetch --tags
git worktree add /tmp/rh-mcp-v0.2.0-review 46128a623c87f954c18d037870e4ac36b9e61e13
cd /tmp/rh-mcp-v0.2.0-review
uv sync --frozen
PYTHONPATH=/tmp/rh-mcp-v0.2.0-review uv run --frozen pytest \
  security-review/v0.1.0/test_adversarial_review.py \
  security-review/v0.2.0/test_adversarial_review_v020.py -v
```

Also verify artifacts:

```bash
gh release download v0.2.0 --repo likefudan/rh-mcp --dir /tmp/rh-mcp-artifacts-v020
gh attestation verify /tmp/rh-mcp-artifacts-v020/rh_mcp-0.2.0-py3-none-any.whl --repo likefudan/rh-mcp
```
