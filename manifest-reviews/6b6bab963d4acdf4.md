# Provider tool-set review required

This Draft PR records a stable provider observation without publishing the
unreviewed tool names or schemas.

- Previous tool count: 76
- Observed tool count: 87
- Appeared: 11
- Disappeared: 0
- Candidate SHA-256: `02620afa5430de89847d03d6bc6fc6407683f57dcf33f208f1e75efad93765fb`
- Provider surface digest: `sha256:6b6bab963d4acdf449db478f6b03d1b0c77ac2492ce1c9a1ba2dc8ebf07e4487`
- Encrypted Actions run: https://github.com/likefudan/rh-mcp/actions/runs/38203223528

Re-run `rh-mcp admin discover` locally, confirm its candidate hash against the
run, review every new or removed capability, and author `capability`,
`disposition`, `mutates` and `rationale` decisions. This PR intentionally
cannot auto-merge or auto-release.
