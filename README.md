# rh-mcp

A default-deny Python Read Gateway for Robinhood's official MCP server
(`https://agent.robinhood.com/mcp/trading`). It is intended to run inside a
dedicated read-broker process and expose only tool schemas that have been
discovered, reviewed, pinned, and marked read-allowed.

The public surfaces are:

- **Library** — `open_gateway(config)`, an async context manager yielding a
  `RobinhoodGateway` whose `invoke(capability, arguments)` returns versioned,
  SDK-neutral, bounded JSON result envelopes. Import it as
  `from rh_mcp.gateway import open_gateway`; the top-level `rh_mcp` package
  re-exports nothing.
- **CLI** — `rh-mcp`, for authentication, readiness diagnostics,
  owner-assisted manifest discovery, and reviewed read capabilities.

There is deliberately no arbitrary `call_tool` or raw MCP session interface.
(In `v0.1.0` there was one, via `rh_mcp.transport`; see Status below.)
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

**Released.** `v0.1.0` shipped on 2026-08-03; `v0.2.0` is the response to the
independent security review below. All seven DESIGN.md §14 build-order steps
have landed except the remainder of step 7, and the first reviewed manifest is
committed. `DESIGN.md` is the authoritative spec.

Owner-assisted discovery ran against the live Robinhood server on 2026-08-03.
A human reviewed all 53 discovered tools: **45 allowed, 8 denied**. The denied
set is exactly the trading surface — the six order tools plus both order
simulators. The allowed set is 34 reads plus 11 non-trading mutations
(watchlist and saved-scan management), each carrying a reviewed `mutates` flag
so a consumer gating writes never has to infer which is which.

The full-manifest digest a consumer pins:

```
sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b
```

Of the DESIGN.md §12 acceptance list, the changelog, the tagged artifact with
checksums, and the independent security review have landed. A published
compatibility policy has not.

**This software has now had an independent security review, and it found
blocking defects.** An AI-assisted reviewer outside this project examined the
exact `v0.1.0` artifacts and returned **CHANGES_REQUIRED**: a public transport
export that accepted an arbitrary provider tool name with no manifest check
(reaching `place_equity_order`), and a validated-argument snapshot that
`invoke` discarded in favour of the caller's live mapping. Both are fixed in
`v0.2.0`. Four prior review rounds, all run under the same orchestration as the
implementation, found neither.

The review is committed in full at `security-review/v0.1.0/`, including the
reviewer's own adversarial tests, which CI runs on every commit. It is an
AI-assisted review with a disclosed independence limitation, not a human
penetration test or a certification, and its approval gate is bound to the
`v0.1.0` artifacts — **`v0.2.0` has not been re-reviewed**. See DESIGN.md
§12.1 and `NOTICE`.

### Canonicalization and digests

Digest comparisons are the whole boundary, so the canonical form is
specified rather than left to an implementation. `rh-canon-1` is written out in
the module docstring of `src/rh_mcp/canonical.py` and pinned by golden vectors
in `tests/test_canonical.py`. Object key order and insignificant whitespace do
not change a digest; array order and semantically meaningful values do. The
algorithm version is recorded inside every derived digest and inside the
manifest, so changing it is an explicit migration rather than a silent
revaluation of every pin.
