# rh-mcp

A default-deny Python Read Gateway for Robinhood's official MCP server
(`https://agent.robinhood.com/mcp/trading`). It is intended to run inside a
dedicated read-broker process and expose only tool schemas that have been
discovered, reviewed, pinned, and marked read-allowed.

The planned public surfaces are:

- **Library** — `RobinhoodReadGateway`, returning versioned, SDK-neutral,
  bounded JSON result envelopes.
- **CLI** — `rh-mcp`, for authentication, readiness diagnostics,
  owner-assisted manifest discovery, and reviewed read capabilities.

There is deliberately no arbitrary `call_tool` or raw MCP session interface.
OAuth credentials may be capable of trading because Robinhood does not
currently advertise separate read/write scopes; the committed manifest and
fail-closed schema checks are therefore the read-only security boundary.
Consumers must independently pin the canonical full-manifest digest. The
gateway refuses readiness when that expected digest does not exactly match and
includes the active digest in readiness and every successful result envelope.

Investment strategy, domain normalization, risk limits, approvals, and live
trading gates belong in the consuming application rather than this transport
gateway.

## Status

**Not usable yet.** The security architecture is documented in
[`DESIGN.md`](DESIGN.md). Build-order steps 1 and 2 have landed:

- **Step 1** — package scaffold, SDK-neutral models, validated configuration,
  and the stable error contract.
- **Step 2** — the `rh-canon-1` canonicalization algorithm and SHA-256 digests,
  the versioned reviewed-manifest format and its fail-closed loader, and
  readiness/preflight enforcement against a discovered provider surface.

Nothing that talks to Robinhood exists yet — no MCP transport, no credential or
OAuth handling, and no gateway or CLI. **No reviewed manifest ships with this
release**: `load_active_manifest()` deliberately fails rather than falling back
to a permissive default, because a production manifest requires owner-assisted
authenticated discovery and independent human review of the live Robinhood tool
schemas (DESIGN.md §6.1, §13). Every manifest and schema in the test suite is
synthetic.

### Canonicalization and digests

Digest comparisons are the whole read-only boundary, so the canonical form is
specified rather than left to an implementation. `rh-canon-1` is written out in
the module docstring of `src/rh_mcp/canonical.py` and pinned by golden vectors
in `tests/test_canonical.py`. Object key order and insignificant whitespace do
not change a digest; array order and semantically meaningful values do. The
algorithm version is recorded inside every derived digest and inside the
manifest, so changing it is an explicit migration rather than a silent
revaluation of every pin.
