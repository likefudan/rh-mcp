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

**Pre-implementation.** The corrected security architecture is documented in
[`DESIGN.md`](DESIGN.md). A production release also requires owner-assisted
authenticated discovery and independent review of the live Robinhood tool
schemas; no client code or production manifest exists yet.
