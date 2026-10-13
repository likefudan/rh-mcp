# Provider tool-set review required

This Draft PR records a stable provider observation without publishing the
unreviewed tool names or schemas.

- Previous tool count: 76
- Observed tool count: 91
- Appeared: 15
- Disappeared: 0
- Candidate SHA-256: `c8ffb1c441db914d1efd815f23d693d4aa3b15b95fbee02b980ebcfca50935b2`
- Provider surface digest: `sha256:fc7d5e17b7ad7ebdf67742d8487c20b287ebc0247ff699eca45cda0775ba3b0d`
- Encrypted Actions run: https://github.com/likefudan/rh-mcp/actions/runs/38329940919

Re-run `rh-mcp admin discover` locally, confirm its candidate hash against the
run, review every new or removed capability, and author `capability`,
`disposition`, `mutates` and `rationale` decisions. This PR intentionally
cannot auto-merge or auto-release.
