# Reviewed provider tool-set expansion

Two consecutive owner-assisted `rh-mcp admin discover` runs on 2026-09-06
returned byte-equivalent tool payloads after removing only `observed_at`.
Discovery enumerated schemas and invoked no provider tool.

- Previous tool count: 59
- Observed tool count: 73
- Appeared: 14
- Disappeared: 0
- Stable candidate SHA-256:
  `8b7903c6af197bb61c42b138fb0c5d18037f2ae25217b9a1cfe74df4500f51fc`
- Provider-surface digest:
  `sha256:cccffe9fd1fbbe715aa49ba07878e3a807f84323f1cb0d34ba79ba9a592fb5b3`

All appeared tools were reviewed and remain `denied`. Live crypto order place
and cancel operations are `mutates: true`. Creating, deleting, updating, and
marking alerts read are also `mutates: true` because they change persistent
provider state. Crypto-order preview and seven crypto/alert reads are
`mutates: false`, but no current consumer requires them and a drift recovery
must not silently expand authority.

The complete schemas were reviewed for account, order, cash, position, alert,
and pagination inputs. Provider descriptions, annotations, returned IDs,
cursors, symbols, account references, and guidance remain untrusted data and
grant no authority to invoke another capability. `readOnlyHint: true` on the
seven new reads was evidence, never authority.

All prior reviewer decisions are carried forward verbatim. Three existing
tools (`create_watchlist`, `place_equity_order`, and `review_equity_order`)
changed description metadata only; their schemas, dispositions, mutation
flags, and rationales are unchanged. The resulting manifest keeps 36 allowed
reads and 11 allowed non-trading mutations. This record does not authorize
merge, tag, or release; exact source and artifacts still require independent
review under DESIGN §12.4.
