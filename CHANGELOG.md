# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Two things a consumer pins, and they move independently

**The package version** covers the code: the public API, the error contract,
the envelope shape, the manifest *format*, and the `CredentialStore` protocol.

**The full-manifest digest** covers what the gateway is permitted to do. It is
published with every release below and in the release notes, and a consumer
supplies it through `GatewayConfig(expected_manifest_digest=...)`.

They move independently on purpose (DESIGN.md §6.2, §9). A manifest refresh
changes the digest without touching a line of code, and a code release can
leave the digest untouched. **A new digest is never inferred from a version
bump** — accepting one is a deliberate decision, which is the whole point of
the mechanism. Expect the digest to move more often than the version: the
provider's tool schemas change, and the first observed drift arrived within a
day of the first manifest being committed.

Manifest-only changes are recorded under `### Manifest` within the release
that carries them.

---

## [Unreleased]

## [0.1.0] — 2026-08-03

First release. Nothing before this was published, so this entry describes the
whole surface rather than a diff.

### The boundary

`rh-mcp` is a default-deny gateway to Robinhood's official MCP server.
Robinhood advertises a single OAuth scope, `internal`, so **the credential this
software holds can trade** — there is no read-only scope to request. What
restrains it is a human-reviewed manifest committed to the package plus exact
digest comparisons made before every call.

**That boundary is "no trading", not "no writes."** The reviewed manifest
denies all six order tools and both order simulators, and allows 11
non-trading mutations (watchlist and saved-scan management) alongside 34 reads.
Every capability carries a reviewed `mutates` flag so a consumer gating writes
never has to infer which is which.

### Added

- `RobinhoodGateway` — async context manager with `readiness()` and
  `invoke(capability, arguments)`, returning versioned, SDK-neutral result
  envelopes. No public surface exposes an MCP session, a raw provider result,
  a provider tool name, or a generic tool call.
- `rh-mcp` CLI — `login`, `logout`, `auth-status`, `status`, `capabilities`,
  `read`, `admin discover`. No `call` command and no flag that relaxes
  manifest enforcement. Structured JSON to stdout alone; a failure emits
  nothing to stdout.
- Reviewed manifest with canonical digests: `rh-canon-1` canonicalization,
  per-tool schema and metadata digests, and a full-manifest digest covering
  every capability mapping, disposition, and rationale.
- Fail-closed readiness and per-call preflight (DESIGN.md §6.2), including
  argument validation against the pinned input schema with default-deny on
  argument *names* at every depth.
- Private MCP SDK v2 transport with bounded pagination, §8 resource bounds
  enforced while reading, and §7.1 content mapping. No `mcp.*` or `httpx2.*`
  type appears in any public signature, exception, serialized result, or
  annotation.
- `CredentialStore` protocol with macOS Keychain, file (development-only), and
  in-memory adapters. OAuth with dynamic client registration and PKCE-S256,
  a loopback callback bound to an explicit address, and single-flight refresh.
- Production egress pinned to `(host, port)` origins; TLS verification cannot
  be disabled; redirects rejected.
- `scripts/refresh_manifest.py` for the recurring case of provider drift. It
  carries every reviewer decision forward verbatim and has no flag to change
  one.

### Manifest

`2026.08.03.1` — 53 tools, 45 allowed, 8 denied.

```
sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b
```

Produced by owner-assisted discovery on 2026-08-03 and reviewed by hand. The
denied set is exactly the trading surface: `place_equity_order`,
`place_option_order`, `exercise_option`, `cancel_equity_order`,
`cancel_option_order`, `cancel_option_exercise`, `review_equity_order`,
`review_option_order`.

The two `review_*` simulators are denied despite claiming not to place
anything. `review_equity_order`'s input schema is `place_equity_order`'s minus
only the idempotency key, with the same required set; allowing it would mean
forwarding a complete order payload with nothing but the tool name between it
and a fill.

Superseding `2026.08.03` after observed provider drift the same day:
`get_accounts` gained an output field and `get_portfolio`'s output schema
description changed. No disposition moved.

### Known limitations

- **No independent security review.** DESIGN.md §12 requires one for release;
  the requirement is deliberately waived, not met. Every review to date was
  performed by agents operating under the same orchestration as the
  implementation. See §12.1 and `NOTICE`.
- Manifest format 1.2 cannot distinguish a provider that omitted `description`
  or `annotations` from one that sent `""` or `{}`, so a provider switching
  between those spellings produces no drift finding.
- Tool descriptions from this provider contain agent-directed imperatives,
  including instructions to call a tool absent from the surface and to embed
  an unmasked account number in a URL. They are provider-controlled text; a
  consumer feeding them into a model context is accepting instructions
  Robinhood can change at will.
- No injected secret-manager adapter ships for non-macOS production.
- The `stdio` development transport bounds payload size after decoding rather
  than during, unlike the HTTP path.

[Unreleased]: https://github.com/likefudan/rh-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/likefudan/rh-mcp/releases/tag/v0.1.0
