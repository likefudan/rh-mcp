# Adversarial review artifacts for `0.3.3` (source)

Deliverables of an **in-project adversarial review** of source commit
`ce8f839660040a2fed543525f01fb2f54e732aa4`, declared package version `0.3.3`.

| File | Purpose |
|---|---|
| `REPORT.md` | Full report, in the shape `v0.2.0`'s used |
| `test_adversarial_review_v033.py` | Reviewer-authored adversarial tests |
| `test_v010_pin_isolated.py` | Isolates the one `v0.1.0` suite failure as a version pin, not a regression |

## This is not what `v0.1.0` and `v0.2.0` are

`security-review/v0.1.0/` and `security-review/v0.2.0/` hold reviews by parties
**external to this project**, performed on **immutable published artifacts**,
and `v0.2.0`'s carries `APPROVED_FOR_AINVEST_INTEGRATION`.

This one does not, and says so in its own header and independence statement.
It was performed by a fresh agent with no prior context — independent in that
narrow sense — running inside the owner's working checkout, against source with
no tag, no release, and no build attestation. Its disposition is
**`INTERNAL_ADVERSARIAL_REVIEW_PASS_WITH_CONDITIONS`**.

Directory named `0.3.3` rather than `v0.3.3` for that reason: there is no
`v0.3.3` tag for it to be named after.

DESIGN §12.4 requires a fresh **external** review when a tool appears, and
`get_limited_margin_upgrade_info` appeared after `v0.2.0`. That requirement is
**not** discharged by this document.

## The digest this report names is not the current one

The report binds to full-manifest digest
`sha256:2ea0954b4a52d9469837bc2b167904ab871de893475e68b43dc2a8fb02e7f886`.

Finding **P2-2** was that `update_scan_config`'s shipped rationale claimed it
"overwrites those two fields only" after the tool had gained `columns` and
stopped requiring the two fields it named. Correcting that rationale — in the
same change that commits this report — moves the digest to
`sha256:79ae864355be48818030eaf534b6db6cd9a5993b48f3a0e2cebc736ecde85cda`.

So this report describes the artifact **as reviewed**, which is one rationale
and one digest behind the artifact that ships. That ordering is deliberate: a
report edited to match what its own findings changed would no longer be a
record of what was examined. Every other finding and every verification in it
applies unchanged — no `disposition`, `mutates` value or capability moved.

## Re-run

```bash
git worktree add /tmp/rh-mcp-0.3.3-review ce8f839660040a2fed543525f01fb2f54e732aa4
cd /tmp/rh-mcp-0.3.3-review
uv sync --frozen
PYTHONPATH=/tmp/rh-mcp-0.3.3-review uv run --frozen pytest \
  security-review/v0.1.0/test_adversarial_review.py \
  security-review/v0.2.0/test_adversarial_review_v020.py -v
```

The `v0.1.0` suite fails one test at that commit. `test_v010_pin_isolated.py`
demonstrates that the failure is its pinned manifest version and digest, and
that the assertion's substance passes with only the pin removed.
