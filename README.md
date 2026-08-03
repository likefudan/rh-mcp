# rh-mcp

A default-deny Python Read Gateway for Robinhood's official MCP server
(`https://agent.robinhood.com/mcp/trading`). It is intended to run inside a
dedicated read-broker process and expose only tool schemas that have been
discovered, reviewed, pinned, and marked read-allowed.

The public surfaces are:

- **Library** — `RobinhoodGateway`, returning versioned, SDK-neutral,
  bounded JSON result envelopes.
- **CLI** — `rh-mcp`, for authentication, readiness diagnostics,
  owner-assisted manifest discovery, and reviewed read capabilities.

There is deliberately no arbitrary `call_tool` or raw MCP session interface.
OAuth credentials are capable of trading because Robinhood does not advertise
separate read/write scopes; the committed manifest and fail-closed schema
checks are therefore the security boundary. That boundary is **"no trading",
not "no writes"** — the reviewed manifest denies all six order tools and both
order simulators, and allows 11 non-trading mutations (watchlist and
saved-scan management) alongside its reads. Each entry carries a reviewed
`mutates` flag, so a consumer that gates writes never has to infer which
capabilities are which.
Consumers must independently pin the canonical full-manifest digest. The
gateway refuses readiness when that expected digest does not exactly match and
includes the active digest in readiness and every successful result envelope.

Investment strategy, domain normalization, risk limits, approvals, and live
trading gates belong in the consuming application rather than this transport
gateway.

## Status

**Usable, not yet released.** All six build-order steps have landed and the
first reviewed manifest is committed. `DESIGN.md` is the authoritative spec.

Owner-assisted discovery ran against the live Robinhood server on 2026-08-03.
A human reviewed all 53 discovered tools: **45 allowed, 8 denied**. The denied
set is exactly the trading surface — the six order tools plus both order
simulators. The allowed set is 34 reads plus 11 non-trading mutations
(watchlist and saved-scan management), each carrying a reviewed `mutates` flag
so a consumer gating writes never has to infer which is which.

The full-manifest digest a consumer pins:

```
sha256:f7ad490475d0842815173ee416d7fae18f1346f7393a9af658f0702bfcccb5e9
```

Not released yet: the DESIGN.md §12 acceptance list remains — changelog,
tagged artifact with checksums, and a published compatibility policy.

**This software has had no independent security review.** Its own design
document requires one for release; the requirement has been deliberately
waived, not met. Every review to date was performed by agents operating under
the same orchestration as the implementation, so no party outside its
development has examined it. See DESIGN.md §12.1 and `NOTICE`.

### Canonicalization and digests

Digest comparisons are the whole boundary, so the canonical form is
specified rather than left to an implementation. `rh-canon-1` is written out in
the module docstring of `src/rh_mcp/canonical.py` and pinned by golden vectors
in `tests/test_canonical.py`. Object key order and insignificant whitespace do
not change a digest; array order and semantically meaningful values do. The
algorithm version is recorded inside every derived digest and inside the
manifest, so changing it is an explicit migration rather than a silent
revaluation of every pin.
