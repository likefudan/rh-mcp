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

- **DESIGN §12.5 is the published compatibility policy** — the last §12
  acceptance item, written now because `ainvest` is about to pin `v0.2.0` and a
  promise should be written down before it is relied on rather than after. It
  covers the four surfaces §12 names: the result envelope and its
  `envelope_version`, the nine `ErrorCode` **wire strings** with the
  `GatewayError` field set and the five CLI exit-code buckets, the manifest
  format's three version fields, and the `CredentialStore` protocol. It states
  the versioning rule — for a 0.x package the minor is the breaking position —
  and how that interacts with §12.4: compatibility is not a security verdict,
  and since §12.3 binds each review to the exact artifact it examined, a later
  compatible release inherits nothing.

  What it declines to promise is the load-bearing half. Error `message` text is
  human-facing and may change in a patch with no entry here — branch on `code`
  and `retryable`, never on prose. `retryable` is per-error and not a function
  of `code`: five raise sites can set it, two of them conditional on a 5xx
  status class, so a provider 5xx is retryable while a provider *request
  timeout* is not — `timeout` and `provider_error` each appear on both sides.
  `correlation_id` is public and **never populated** by anything in this
  package. The manifest's *content* is deliberately not a compatibility surface
  — it is expected to move, which is exactly what the pinned
  `expected_manifest_digest` is for. And `rh-mcp status` / `rh-mcp capabilities`
  JSON carries no version field of its own, unlike the envelope; that asymmetry
  is recorded rather than closed, because closing it means editing
  enforcement-path code, which §12.4 puts behind a review.

- **Fixtures for every surface §12.5 promises**, because a policy CI does not
  hold is worse than none:

  - `tests/test_errors.py` pins the nine literal error wire strings and the five
    literal exit integers. The existing golden table is keyed by enum *member*,
    so it asserted which bucket a member lands in without asserting the string
    that member carries. Measured on `b6d6a35` rather than assumed: renaming
    `capability_denied` to `capability_refused`, or moving
    `EXIT_CODE_PROVIDER_FAILURE` from 1 to 8, each left all 1176 tests green.
  - `tests/test_cli.py` pins the CLI's stderr error line, `rh-mcp: <code>:
    <message>`, for all nine codes. §12.5 names that line as one of the two
    places a consumer meets a wire string, and nothing asserted it: rewriting it
    to `rh-mcp error [CAPABILITY_DENIED]: …` left the suite green. The
    `test_errors.py` fixture asserts `str(ErrorCode.X) == "x"`, which is a
    property of `StrEnum`, not of `cli.py` — asserting the adjacent thing is the
    defect this whole change exists to retire.
  - `tests/test_credentials.py` pins the eight `CredentialStore` member names as
    a set. Seven are methods with in-package call sites, so `mypy` catches their
    removal; `namespace` has no reader anywhere in `src/` or `tests/`, and both
    deleting and renaming it left `mypy src` clean and the suite green. The
    member with no consumer is the one a refactor drops unnoticed.
  - `tests/test_manifest.py` and `tests/test_gateway.py` pin the whole key sets
    of `ReadinessAssessment`, `DriftFinding` and `CapabilityDescription` JSON.
    Renames were already caught, because every key is read by name; *additions*
    were not, and an added key is how an unversioned payload changes shape under
    a consumer.
  - `tests/test_cli.py` parses what `rh-mcp status` and `rh-mcp capabilities`
    actually write to stdout and pins those key sets, top level and per entry,
    in both directions. **This** is the mitigation §12.5 leans on when it
    accepts that the two payloads carry no version field. Pinning the objects
    above is not the same claim: `_cmd_capabilities` assembles its four
    top-level keys inline in `cli.py` and serializes the pinned type only for
    the list inside, so renaming `manifest_version` to `mv` left the suite
    green while the CLI demonstrably emitted the renamed key.

  Nothing was added for the envelope or `Readiness`: `test_to_json_dict_shape`
  already compares whole rendered dictionaries against literals, in both
  directions, and a redundant fixture is not free — it reads like coverage.

  The bullets above other than the first exist because an independent review
  disproved by mutation five "already defended, no fixture needed" claims in
  this change, across two rounds — three in the first draft, then two more
  after the first round's own fixes reproduced the same defect one layer up.
  The standing rule is now that no such claim enters DESIGN §12.5 without the
  mutation that demonstrates it.

- DESIGN §12.4 states when a manifest change needs a new external review and
  when it does not. The reviewers bind each verdict to the exact artifact they
  examined, and the provider drifted twice in three days — taken literally that
  puts every refresh behind an external review, which is not a policy anyone
  would follow. A refresh carrying dispositions forward does not need one; a
  disposition change, a tool-set change, a format change, or any change to
  enforcement code does. What is given up is stated rather than glossed: a
  refresh can carry an `allowed` disposition onto a tool whose schema changed
  underneath it, and the human reading of the refresh report is the control.

### Fixed

- **DESIGN §13 and §14 said the `v0.2.0` re-review was still outstanding.** It
  is not: §12.2 records **APPROVED_FOR_AINVEST_INTEGRATION** on 2026-08-04 bound
  to commit `46128a62`, and `security-review/v0.2.0/` is committed. Both "what
  remains" enumerations were written before the approval landed and edited
  afterwards without being re-read, so the document contradicted itself in three
  places. §12 has nothing outstanding; §14 step 7 has consumer contract
  integration and nothing else.

- **`## [0.2.0] — unreleased`** was never true. The tag, the GitHub release and
  its `SHA256SUMS` all exist, published 2026-08-04. Unlike the digest lines
  below it, this is not a published record being corrected — it is a heading
  that never matched reality, seven lines above the first wrong digest in the
  entry §12.5 now points consumers at.

- `scripts/refresh_manifest.py` restamped `reviewer.reviewed_at` with `now()`
  on every run, so two consecutive `--dry-run`s reported two different digests
  and neither matched what the real run wrote. A dry run exists to show the
  value you are about to accept and pin; one that cannot be trusted is worse
  than none. The fix is not a frozen clock — the reviewer block is carried
  forward like every other decision, because a refresh reviews nothing and
  stamping a new date claimed a review that did not happen.

- `actions/attest-build-provenance` majors are now refused by Dependabot, and
  `tests/test_dependency_bounds.py` asserts both the refusal and the premise
  behind it — that the action appears only in `release.yml`, which no
  pull-request CI run executes. If it ever moves into `ci.yml` the test fails,
  so the pin gets revisited rather than cargo-culted.

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

### Manifest

`2026.08.05`, refreshed for the observed `direction` field on
`place_option_order` and `review_option_order`. 53 tools in and out, no
disposition moved, both affected tools denied either way.

```
sha256:49b7218278fc2aebb1a040c89b8c94f60750afe142d6b728e88771944a88093a
```

Recorded here because the preamble above requires it: manifest changes go under
`### Manifest` within the release that carries them, and this one had no entry —
the refresh landed with entries under **Fixed** and **Added** but not this one.

**And a correction that goes with it.** The `[0.1.0]` and `[0.2.0]` entries
below both print `sha256:49b7218…` beside manifest version `2026.08.03.1`.
Those two values do not go together. Both tags ship `2026.08.03.1` with
`sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b` —
check with `git show v0.2.0:src/rh_mcp/manifests/read-manifest.json`.
`49b7218…` is `2026.08.05`, which is what `main` ships, what the README
publishes, and what this entry records. The refresh commit `b6d6a35` rewrote the
digest inside those two historical entries, so `[0.2.0]`'s "Unchanged … so a
consumer's pinned manifest digest does not move" now names a digest that did
move. The `v0.2.0` GitHub release notes publish the correct value; this file is
the only place carrying the wrong one, and it carries it under the two headings
a consumer pinning a tag jumps straight to.

Both wrong values are **left in place and marked in line**, which is the whole
of the fix. Silently substituting the right digest would rewrite a published
release record, and that is not a side effect a compatibility-policy change gets
to have. Leaving the line unmarked is a different act with a different cost — a
reader who jumps to their version's heading, which is how a changelog is read,
meets a wrong digest and no warning. A note 125 lines above it is not a warning.
So the record is preserved and the hazard is removed, and whoever owns the
release record can still decide to substitute.

By this file's own standard, borrowed from the tests: a line stating a wrong
digest under the right heading is worse than no line, for the same reason a
passing test that asserts something adjacent is worse than no test — it reads
like the thing it is not.

## [0.2.0] — 2026-08-04

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
  been re-reviewed**. *(Superseded: `v0.2.0` was re-reviewed as a fresh artifact
  and APPROVED on 2026-08-04, bound to commit `46128a62` — see DESIGN §12.2 and
  `security-review/v0.2.0/`. The sentence is true of what `v0.2.0` shipped and
  is left standing as that record, not rewritten. It is marked because §12.5 now
  sends a consumer to their own version's heading, where an unmarked line reads
  as current.)*
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
`sha256:49b7218278fc2aebb1a040c89b8c94f60750afe142d6b728e88771944a88093a`.
Nothing in this release touches a disposition, a rationale, or a digest, so a
consumer's pinned manifest digest does not move.

> **[Corrected — do not pin the digest on the line above.]** The `v0.2.0` tag
> ships `2026.08.03.1` with
> `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`,
> which is also what the `v0.2.0` GitHub release notes publish. Verify with
> `git show v0.2.0:src/rh_mcp/manifests/read-manifest.json`. `49b7218…` is
> manifest `2026.08.05`, which `main` ships; commit `b6d6a35` substituted it
> into this entry while refreshing the manifest. The original line is preserved
> rather than rewritten — see `[Unreleased]` → **Manifest**, and DESIGN §12.5.

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
sha256:49b7218278fc2aebb1a040c89b8c94f60750afe142d6b728e88771944a88093a
```

> **[Corrected — do not pin the digest in the block above.]** The `v0.1.0` tag
> ships `2026.08.03.1` with
> `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`.
> Verify with `git show v0.1.0:src/rh_mcp/manifests/read-manifest.json`.
> `49b7218…` is manifest `2026.08.05`, which `main` ships; commit `b6d6a35`
> substituted it into this entry while refreshing the manifest. The original
> block is preserved rather than rewritten — see `[Unreleased]` → **Manifest**,
> and DESIGN §12.5. (`v0.1.0` should not be used with a real credential in any
> case; see **Known limitations** below.)

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
- **Production runs on macOS.** The only adapter accepted in production mode is
  `keychain`, which shells out to the macOS `security` tool; `file_dev` and
  `in_memory` are refused there by `GatewayConfig`. Deploying the broker on
  another platform fails closed at start-up with `configuration_error: the
  macOS security tool was not found; the keychain adapter needs macOS`, which
  is the intended behaviour rather than a gap to route around. §5.2 anticipates
  an injected secret-manager adapter (Vault, AWS/GCP secret managers) for other
  platforms; none ships, because the first deployment target is macOS.
- The `stdio` development transport bounds payload size after decoding rather
  than during, unlike the HTTP path.

[Unreleased]: https://github.com/likefudan/rh-mcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/likefudan/rh-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/likefudan/rh-mcp/releases/tag/v0.1.0
