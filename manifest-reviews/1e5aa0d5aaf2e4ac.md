# Provider tool-set review required

This Draft PR records a stable provider observation without publishing the
unreviewed tool names or schemas.

- Previous tool count: 76
- Observed tool count: 96
- Appeared: 20
- Disappeared: 0
- Candidate SHA-256: `75bd5d9ff19bd7ea9ac8300664eefbff2e3549b424e9ed7fda72513412fef7e1`
- Provider surface digest: `sha256:1e5aa0d5aaf2e4acc8bb8e7beb1583dce98e5cd3f7789b4ae979e4ea6cb08ec9`
- Encrypted Actions run: https://github.com/likefudan/rh-mcp/actions/runs/45399816801

Re-run `rh-mcp admin discover` locally, confirm its candidate hash against the
run, review every new or removed capability, and author `capability`,
`disposition`, `mutates` and `rationale` decisions. This PR intentionally
cannot auto-merge or auto-release.
