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
[`DESIGN.md`](DESIGN.md), and build-order step 1 has landed: the package
scaffold, SDK-neutral models, validated configuration, and the stable error
contract. Nothing that talks to Robinhood exists yet — no manifest enforcement,
no MCP transport, no credential or OAuth handling, and no gateway or CLI. A
production release additionally requires owner-assisted authenticated discovery
and independent review of the live Robinhood tool schemas, and no production
manifest exists.
