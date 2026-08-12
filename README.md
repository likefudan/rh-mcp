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

The current source builds `0.3.0`, the new package identity reserved for the
permission-expanded manifest lineage introduced on `2026.08.09`. It now
carries the owner-reviewed `2026.08.12` scanner refresh described below. It is
not the already released `v0.2.0` artifact.

Owner-assisted discovery ran against the live Robinhood server on 2026-08-03
and has been re-run on each observed drift since. A human has reviewed all 54
discovered tools: **46 allowed, 8 denied**. The denied set is exactly the
trading surface — the six order tools plus both order simulators — and every
denied tool genuinely writes. The allowed set is 35 reads plus 11 non-trading
mutations (watchlist and saved-scan management), each carrying a reviewed
`mutates` flag so a consumer gating writes never has to infer which is which.

The 35th read arrived on `2026.08.09`: `get_limited_margin_upgrade_info`,
which returns limited-margin eligibility and the links that start the upgrade
flow. It is a permission expansion, and the first time the allowed set has
grown since the manifest was first committed.

On `2026.08.12`, Robinhood expanded `create_scan` within the already allowed
saved-scanner write domain: it can append a new active configuration version
to an existing scan and persist expression filters. It remains
`allowed` / `mutates: true`; the expansion cannot place orders, move funds, or
change account permissions. Four other scanner tools changed only their
schemas' explanatory text so those expression filters can round-trip. The new
provider prose also names `get_scanner_datapoints`, which is not on the offered
tool surface; like the five existing dangling tool references, it is inert in
this gateway but must not be forwarded into a model or user-facing context.

The full-manifest digest a consumer pins, for manifest `2026.08.12` in the
reviewed `0.3.0` source:

```
sha256:403ddc4c8a71bf470da906f572134c7d00684ae23af023e91df1872fc6d71b3f
```

The manifest version is named alongside it deliberately. A digest belongs to
one manifest, the two move together, and a released tag ships whichever
manifest it was cut from — so take the digest you pin from the artifact you are
pinning, not from a document describing a different revision (DESIGN.md §12.5).

The DESIGN.md §12 acceptance list is now complete: the changelog, the tagged
artifact with checksums, the independent security review, and the published
**compatibility policy** (DESIGN.md §12.5) have all landed. §12.5 is what a
consumer reads before pinning — it states what the result envelope, the nine
error wire strings, the CLI exit codes, the manifest format fields, and the
`CredentialStore` protocol promise across a version change, and what they
deliberately do not.

**Two released-artifact review reports, plus two pre-merge manifest-change
reviews.** The first found blocking defects in `v0.1.0`; the second approved
`v0.2.0`. PR #34 independently reviewed the `2026.08.09` permission expansion,
and PR #35 independently reviewed this `2026.08.12` scanner refresh before
merge.

An AI-assisted reviewer outside this project examined the exact `v0.1.0`
artifacts and returned **CHANGES_REQUIRED**: a public transport export that
accepted an arbitrary provider tool name with no manifest check (reaching
`place_equity_order`), and a validated-argument snapshot that `invoke`
discarded in favour of the caller's live mapping. Four prior review rounds,
all run under the same orchestration as the implementation, found neither.

Both are fixed in `v0.2.0`, which was then re-reviewed as a fresh artifact and
returned **APPROVED_FOR_AINVEST_INTEGRATION**.

The first two reviews are committed in full at `security-review/`, including
the reviewers' own adversarial tests — 38 of them, which CI runs on every
commit. The PR #34 and #35 reviews are recorded on their pull requests and bind
only the exact pre-merge source and locally rebuilt artifacts they name. All
four are AI-assisted reviews with a disclosed independence limitation, not
human penetration tests or certifications. See DESIGN.md §12.1–12.3 and
`NOTICE`.

### Production runs on macOS

The only credential adapter accepted in production mode is `keychain`, backed
by the macOS `security` tool. `file_dev` stores a trading-capable credential as
plaintext JSON, so `GatewayConfig` refuses it in production rather than letting
a deployment degrade into it.

A broker started on another platform fails closed at start-up:

```
configuration_error: the macOS `security` tool was not found;
                     the keychain adapter needs macOS
```

That is the intended behaviour, not a gap to route around. DESIGN.md §5.2
anticipates an injected secret-manager adapter — Vault, AWS or GCP secret
managers — for other platforms; none ships, because the first deployment target
is macOS. `CredentialStore` is a narrow protocol, so adding one is a small
piece of work when a deployment needs it, and it also solves moving a
credential between machines, which matters because the first login must open a
browser.

### One residual risk, and it is a requirement on you

A caller that imports underscore-prefixed internals by name can still assemble
a session that bypasses the manifest and places an order. This is accepted
rather than fixed: DESIGN.md §3 already says importing this package into a
privileged process is not a security boundary, so a caller able to do that
already holds the credential.

The consequence is exact, and the reviewer recorded it as a consumer
requirement:

> Use only `open_gateway` / `RobinhoodGateway.invoke` and the `rh-mcp` CLI. A
> consumer that does cannot bypass the manifest. A consumer that imports
> underscore-prefixed names can.

### Canonicalization and digests

Digest comparisons are the whole boundary, so the canonical form is
specified rather than left to an implementation. `rh-canon-1` is written out in
the module docstring of `src/rh_mcp/canonical.py` and pinned by golden vectors
in `tests/test_canonical.py`. Object key order and insignificant whitespace do
not change a digest; array order and semantically meaningful values do. The
algorithm version is recorded inside every derived digest and inside the
manifest, so changing it is an explicit migration rather than a silent
revaluation of every pin.
