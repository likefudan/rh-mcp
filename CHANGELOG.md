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

### Added

- Automated dependency review (`.github/dependabot.yml`), the last §12
  acceptance item outstanding besides the compatibility policy. Runtime
  dependencies are ungrouped so `mcp` and `httpx2` each get their own PR and CI
  run; dev tooling is grouped into one. Major bumps are refused rather than
  proposed — widening either cap is a §12 security-boundary change, and a PR
  that cannot merge still asks a reviewer to think in a dependency-update
  frame, which is the wrong frame for it.
- `tests/test_dependency_bounds.py` asserts the caps, that the runtime
  dependency set is exactly the two reviewed packages, and that dependabot's
  ignore rules agree with `pyproject.toml`. Both a comment and a robot config
  are edited by the same PR that would widen them, so neither is a check.

### Changed

- `v0.2.0` was re-reviewed as a fresh artifact by the independent reviewer and
  returned **APPROVED_FOR_AINVEST_INTEGRATION**, bound to commit `46128a62`
  and to the released wheel and sdist re-hashed from GitHub. Both prior
  blocking findings are recorded as resolved on the published surface. The
  report and the reviewer's tests are committed at `security-review/v0.2.0/`.
- DESIGN §12.1–12.3, README and `NOTICE` record the approval, what these
  reviews are and are not, and the two non-blocking items below.
- CI and the release workflow now discover reviewer suites with
  `find security-review -name 'test_*.py'` rather than naming files. Listing
  them was the same mistake as `TestNoEscapeHatch` asserting against one class:
  the next review's tests would land in the repo and silently not run. 38
  adversarial tests now run on every commit.

### Residual risks recorded, not fixed

- **Private names remain importable (reviewer P2).** A caller that deliberately
  imports `_open_provider_session` with `StoredTokenProvider` and
  `open_credential_store` can assemble a manifest-free session and place an
  order. Accepted under DESIGN §3, which already states that importing this
  package into a privileged process is not a security boundary. Recorded as a
  **consumer requirement**: use only `open_gateway` / `RobinhoodGateway.invoke`
  and the `rh-mcp` CLI.
- **One `v0.1.0` adversarial assertion is defeatable by renaming (reviewer
  P3).** Their `test_call_tool_protocol_accepts_arbitrary_provider_name_without_manifest`
  checks the first parameter is no longer named `provider_tool_name`, which a
  rename greens without adding a manifest check. The load-bearing check is
  `tests/test_public_surface.py`, which asks the question of every published
  name rather than of a list.

## [0.2.0] — unreleased

The response to the independent security review of `v0.1.0`, which returned
**CHANGES_REQUIRED**. The reviewer's report and their own adversarial tests are
committed at `security-review/v0.1.0/`; CI runs those tests on every commit.

**This is a breaking release.** Four names leave the public export surface.

### Security

- **Withdrew a manifest-free provider call path from the public API**
  (reviewer finding P0). `rh_mcp.transport.__all__` exported
  `open_provider_session` and `ProviderTransport`, whose
  `call_tool(provider_tool_name, ...)` accepted any string with no manifest
  lookup; `auth` exported `StoredTokenProvider` and `credentials` exported
  `open_credential_store`, which together attach a write-capable bearer token.
  The reviewer reached `place_equity_order` through the published API while
  DESIGN.md §1, the README and this changelog all said no public surface could.

  Calibrate this as what it is. DESIGN.md §3 already states that in-process
  separation is not a security boundary — code that can call
  `open_provider_session` is inside the broker process and can read the
  credential store directly — so this is **not** a privilege escalation and
  removing the exports stops no attacker who is already there. The defect is
  that a documented public contract was false, and the realistic failure is a
  consumer adapter importing a transport helper because it was exported and
  believing it was still inside the gateway.

  `AccessTokenProvider` was also withdrawn. Neither the reviewer nor four
  internal rounds named it; the new package-wide test found it.

  `GuardedJsonClient` and `open_json_client` were withdrawn on review of this
  fix. They are **not** a `call_tool` equivalent and do not reopen P0:
  `open_json_client(config)` accepts no token provider and the client's three
  verbs accept no headers, so no credential can be attached to a request made
  through them — pointing one at the pinned MCP endpoint yields an
  unauthenticated request. They leave because a single exported HTTP helper
  standing beside four withdrawn ones reads as deliberately retained, and this
  release's argument is that exported names get used. Nothing outside the
  package implements or calls either.

- **`invoke` now sends the validated argument snapshot** (reviewer finding
  P1). `preflight_read` validated a private copy of the arguments and returned
  only the `ManifestEntry`, so `invoke` forwarded the caller's original
  mapping. A `MutableMapping` that changed after validation put `side` and
  `quantity` on the wire. `preflight_read` now returns
  `PreflightResult(entry, arguments)` with the arguments deep-frozen, and
  `invoke` sends only that.

  This never let a caller change which *tool* was called, so it was not by
  itself a route to a trading tool. It defeated pinned input-schema
  enforcement on all 45 allowed capabilities, 11 of which write.

- **Package-wide escape-hatch tests** (`tests/test_public_surface.py`). The
  test that should have caught P0 existed and passed: `TestNoEscapeHatch`
  asked whether `RobinhoodGateway` had an escape hatch, while the claim it
  defended was about the package. The new sweep asks, of every module, what
  `from rh_mcp.<module> import *` actually binds and whether any of it — or
  anything it returns, unwrapped through `AsyncIterator` — offers a public
  `call_tool`, `access_token`, or one of the three `GuardedJsonClient` HTTP
  verbs. Deriving the rule is what makes it answer for the helper nobody has
  written yet; a list of the names already found would not have caught
  `AccessTokenProvider` or `open_json_client`.

### Changed

- **BREAKING.** `open_provider_session` is now `_open_provider_session`.
  `ProviderTransport`, `AccessTokenProvider`, `GuardedJsonClient`,
  `open_json_client`, `StoredTokenProvider` and `open_credential_store` are no
  longer in their modules' `__all__`. Those six remain importable under their
  existing names; only `open_provider_session` is renamed. After this,
  `from rh_mcp.transport import *` binds exactly `PRODUCTION_EGRESS_HOSTS`,
  `HttpJsonResponse`, `PayloadSource` and `ToolPayload` — four value types and
  a constant, and nothing that talks to the network. A consumer using only
  `GatewayConfig`, `open_gateway` and `RobinhoodGateway.invoke`, as DESIGN.md
  §7.1 and §10 direct, is unaffected.
- **BREAKING.** `manifest.preflight_read` returns `PreflightResult` rather
  than `ManifestEntry`. Callers read `.entry`, and must send `.arguments`.
- `ProviderTransport.call_tool`'s first parameter is `reviewed_tool_name`, not
  `provider_tool_name`. It is passed positionally throughout, so an
  implementation of the protocol is unaffected.

### Packaging

- **The sdist is now an allowlist** (reviewer finding P2). The released
  `rh_mcp-0.1.0.tar.gz` contains `.claude/settings.local.json`, which is in no
  commit at the tagged revision — the release was cut from a dirty working
  tree, and the published checksum matches that dirty artifact. The wheel was
  clean and byte-identical to a rebuild. No credential was in the file; the
  failure is reproducibility, since an sdist that is not derivable from the
  commit cannot be verified against it. `pyproject.toml` now enumerates what
  ships and `scripts/check_sdist.py` independently refuses anything else,
  including non-regular files, in CI.
- **Build provenance** (reviewer finding P2). `gh attestation verify` returned
  404 for the `v0.1.0` wheel because there was no release workflow at all.
  `.github/workflows/release.yml` now builds from the tag in a clean checkout,
  re-runs the full gate, and signs an OIDC provenance attestation over every
  artifact. It does not publish — §12 keeps a release a reviewed human event.

### Documentation

- **DESIGN.md §12.1 and `NOTICE` no longer say the independent security review
  was waived.** It was performed, it found P0 and P1, and both are fixed.
  `NOTICE` travels with any redistribution under Apache-2.0 §4(d), so the
  correction travels too. Both now also state plainly that the review's
  approval gate is bound to the `v0.1.0` artifacts and that **`v0.2.0` has not
  been re-reviewed**.
- Swept DESIGN.md, README.md, AGENTS.md and source docstrings for the whole
  class of stale-claim defect the reviewer found two instances of, rather than
  the two lines (reviewer finding P2). Corrected: `RobinhoodGateway(config,
  credential_store)` and `gateway.read(...)` in the §7.1 example, which should
  be `open_gateway(config)` and `gateway.invoke(...)`; `RobinhoodGateway`
  described as an async context manager, which it is not; manifest format
  "1.1", which is 1.2 and for which 1.1 is also refused; the disposition
  spelled `read_allowed`, which is `allowed` in the manifest and a Python
  attribute only; the CLI subcommand `auth status`, which is `auth-status`;
  "not yet released" and the §12/§14 status lists; and an architecture table
  that omitted four shipped modules and attributed the error contract to the
  wrong one.

### Manifest

Unchanged. `2026.08.03.1`,
`sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`.
Nothing in this release touches a disposition, a rationale, or a digest, so a
consumer's pinned manifest digest does not move.

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

- **No independent security review** *at the time of this release.* The
  requirement was deliberately waived, not met. It has since been performed
  against these exact artifacts and returned **CHANGES_REQUIRED**: see
  `security-review/v0.1.0/REPORT.md` and the `0.2.0` entry above. Two blocking
  findings apply to `0.1.0` as published — a public transport export accepting
  an arbitrary provider tool name, and argument validation whose result was
  discarded. **Do not use `0.1.0` with a real trading-capable credential.**
- **The released sdist is not reproducible from the tagged commit.** It
  contains `.claude/settings.local.json`, absent from the commit, and its
  published checksum matches that dirty artifact. The wheel is clean and
  rebuilds byte-identically; prefer the wheel.
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

[Unreleased]: https://github.com/likefudan/rh-mcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/likefudan/rh-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/likefudan/rh-mcp/releases/tag/v0.1.0
