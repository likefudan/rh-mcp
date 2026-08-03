# rh-mcp — Design

Status: **implemented, and the first manifest is reviewed and committed.**
Owner-assisted discovery ran against the live server on 2026-08-03; a human
reviewed all 53 tools and committed 45 allowed / 8 denied (§2.1). What remains
before a release is the §12 acceptance list — license, changelog, tagged
artifact, published digest, compatibility policy, and independent security
review.

## 1. Purpose

`rh-mcp` is a default-deny Python gateway to Robinhood's official MCP server.
It gives a consuming application a narrow, reviewable capability surface while
keeping OAuth credentials, the MCP SDK, transport objects, and unreviewed MCP
tools behind the gateway boundary.

**The boundary this gateway enforces is "no trading", not "no writes".** The
first reviewed manifest allows a set of non-trading mutations — watchlist and
saved-scan management — alongside its reads. That was a deliberate reviewer
decision, and §2 states the resulting rule precisely. Say it plainly here
because the type is still named `RobinhoodReadGateway` and its method is still
`read()`: those names are narrower than what the manifest now permits, and a
name that overstates a guarantee is how a reader ends up trusting one that
does not exist.

It has two supported public surfaces:

- **Library** — `RobinhoodReadGateway`, an async context manager for a trusted
  read-broker process.
- **CLI** — `rh-mcp`, for login, readiness diagnostics, and invoking only
  capabilities present in the reviewed read manifest.

The CLI is a thin shell over the same gateway. Neither surface exposes an MCP
`ClientSession`, raw MCP result types, arbitrary tool names, or a generic
`call_tool` operation.

## 2. Security model and non-goals

Robinhood currently advertises one OAuth scope, `internal`, rather than
separate read and write scopes. A token must therefore be treated as capable
of trading whatever this gateway chooses to do with it. The boundary is
enforced locally with a committed allowlist and exact schema validation; it is
not inferred from the token, a tool name, or an MCP annotation.

Authenticated discovery (§13) settled two facts that this section previously
had to speculate about, and both matter more than they look:

- The provider surface is 53 tools, and **six of them place, cancel, or
  exercise real orders**. They arrive over the same session, under the same
  token, as every quote and position read. This manifest is the only thing
  between a consumer and a trade.
- **Not one of the 53 tools carries `readOnlyHint`, or any annotation at
  all.** Rule 4 below said annotations are evidence and never authority; the
  live surface supplies no evidence whatsoever. Every disposition in the
  manifest is a human judgement from a name, a description, and a schema.

The governing rules are:

1. Every discovered tool is denied unless a reviewed manifest entry marks its
   exact schema digest as allowed.
2. An unknown, missing, duplicate, malformed, or changed tool makes the
   gateway not ready. Discovery never grants permission automatically.
3. A denied request is rejected before any MCP tool call is sent.
4. MCP annotations such as `readOnlyHint` are review evidence only and never
   authority.
5. **Trading support** — order submission, cancellation, replacement, and
   option exercise — must use a separate client surface, credential namespace,
   runtime identity, and deployment role. It must not be added by widening
   this gateway. The six trading tools and both order-simulation tools are
   denied in the committed manifest, and a reviewer moving any of them to
   allowed is making that change, not a configuration tweak.

The gateway owns transport security and the capability boundary. It does
**not** own investment risk limits, order approval, strategy policy, portfolio
semantics, or application audit workflows. Those remain responsibilities of
the consumer (§10).

### 2.1 What the first manifest actually allows

45 of 53 tools are allowed; 8 are denied. The denied set is exactly the
trading surface:

| denied | why |
|---|---|
| `place_equity_order`, `place_option_order` | Robinhood's own description: "Place a real equity order with **real money**" |
| `cancel_equity_order`, `cancel_option_order`, `cancel_option_exercise` | change the state of a live order |
| `exercise_option` | exercises a position |
| `review_equity_order`, `review_option_order` | "simulate an order without placing it" — denied anyway. Simulation is not a read of account state, it takes a complete order as its argument, and the meaning of "simulate" is defined entirely on Robinhood's side. If that meaning ever shifts, what we handed over was an order. |

The allowed set is 34 reads plus **11 non-trading mutations**: watchlist
create/update/add/remove/follow/unfollow, and saved-scan create/update. These
write to Robinhood, and calling them through a method named `read()` is a wart
the reviewer accepted knowingly. They move no money and touch no order.

Two consequences a consumer must not discover by surprise:

- `RobinhoodReadGateway.read()` can mutate. Renaming the type and method to
  match is deferred, not rejected — nothing has shipped, so the cost is low
  and the reason to wait is that a rename should follow the §12 release gate
  rather than ride along with a manifest change.
- §10 tells `ainvest` this surface is safe to call unattended. That remains
  true for the trading boundary, which is what its approval and paper/live
  gates exist for — but an unattended call can now create a watchlist. If
  `ainvest` gates mutations separately, it must gate these too.

  It does not have to infer which ones. Every manifest entry carries a
  reviewed `mutates` boolean, reported alongside `read_allowed` in
  `capabilities` output. That field is why the manifest format is **1.1** and
  not 1.0: a 1.0 manifest cannot say whether a capability writes, and a loader
  that guessed would be guessing about precisely the thing the field exists to
  state, so 1.0 is refused rather than migrated in place. Adding it after a
  consumer had pinned a digest would have cost a coordinated migration; adding
  it now costs one regenerated file.

Also out of scope for v0:

- order submission, cancellation, replacement, and option exercise;
- Robinhood domain models such as `Quote`, `Position`, or `Order`;
- response caching, a general community-server client, or a public raw MCP
  debugging interface;
- background retries of tool calls.

## 3. Production target and deployment boundary

- Resource and issuer: `https://agent.robinhood.com/mcp/trading`
- Transport: Streamable HTTP
- Authorization host: `https://robinhood.com`
- Token host: `https://api.robinhood.com`
- Registration host: `https://agent.robinhood.com`

Production mode pins HTTPS, the resource URL, discovery metadata, expected
issuer/resource values, and the three hostnames above. Programmatic redirects
and gateway egress outside that set are rejected. TLS verification cannot be
disabled; the user's browser remains outside the gateway egress boundary.

The intended deployment is a dedicated read-broker process. It alone can read
the Robinhood credential and establish an MCP session. Importing this package
inside a broadly privileged process is supported for development but is not a
security boundary: package separation does not isolate memory, credentials,
or network authority.

Custom URLs and stdio exist only behind an explicit development/test mode.
That mode:

- uses a separate credential namespace and refuses a production credential
  store;
- emits a prominent diagnostic identifying the non-production target;
- cannot be enabled by an untrusted per-request value; and
- is exercised with fake credentials and local servers only.

## 4. Architecture

```text
config.py       Validated production or development configuration. No I/O.
credentials.py  CredentialStore protocol and explicit adapters.
auth.py         OAuth provider, DCR, browser redirect, loopback callback.
manifest.py     Manifest loading, canonicalization, digests, drift checks.
transport.py    Private MCP SDK v2 session and bounded pagination.
gateway.py      RobinhoodReadGateway; preflight deny and result sanitization.
models.py       SDK-neutral result envelope, readiness report, stable errors.
cli.py          Thin CLI over gateway/auth/admin workflows.
```

The MCP Python SDK v2 and `httpx2` are private implementation dependencies.
No public signature, exception, serialized result, or type annotation may
contain an `mcp.*` or `httpx2.*` type. This prevents consumers using another
MCP major version from inheriting a dependency or wire-contract conflict.

Transport selection happens once when the private session is opened. The MCP
session and transport are never available through a public property.

## 5. OAuth and credential handling

### 5.0 Verified discovery metadata

The public protected-resource document currently advertises:

```json
{
  "authorization_servers": ["https://agent.robinhood.com/mcp/trading"],
  "bearer_methods_supported": ["header"],
  "resource": "https://agent.robinhood.com/mcp/trading",
  "scopes_supported": ["internal"]
}
```

The authorization-server document currently advertises:

```json
{
  "issuer": "https://agent.robinhood.com/mcp/trading",
  "authorization_endpoint": "https://robinhood.com/oauth",
  "token_endpoint": "https://api.robinhood.com/oauth2/token/",
  "registration_endpoint": "https://agent.robinhood.com/oauth/trading/register",
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["internal"],
  "token_endpoint_auth_methods_supported": ["none"]
}
```

Production startup validates these security-relevant values instead of
silently accepting changed issuer, endpoint, PKCE, or token-auth semantics.
An intentional provider change requires a reviewed release.

### 5.1 Registration and authorization

The gateway uses dynamic client registration and Authorization Code with
PKCE-S256. Client registration metadata is credential-shaped even though this
is a public client and is stored with the same controls as tokens.

`rh-mcp login` is the only workflow allowed to open a browser. Its callback:

- binds only an explicit loopback address, never a wildcard interface;
- uses a configured, registered port and an exact callback path;
- validates `state`, issuer, redirect URI, and the expected authorization
  transaction before exchanging the code;
- accepts one code, has a short timeout, and then closes the listener; and
- never prints the code, tokens, registration response, or callback query.

All read operations are non-interactive. They may perform one coordinated
token refresh, but never open a browser. If login is required they fail with
the stable `auth_required` error and direct a human to `rh-mcp login`.

The only currently advertised scope is `internal`; the implementation must
record whether no explicit scope or `internal` is required during the first
owner-assisted login. Either way, the resulting credential is treated as
write-capable.

### 5.2 Credential stores

The auth layer depends on a narrow asynchronous `CredentialStore` protocol
for tokens and DCR client information. It supports read, atomic update, and
delete without exposing serialized secrets to callers.

Required adapters and policy:

- a platform secret store (macOS Keychain for the first local deployment) or
  an injected production secret-manager adapter is the normal choice;
- an in-memory adapter supports tests;
- `FileCredentialStore` is an explicit local-development option only. It uses
  a distinct dev namespace, directory mode `0700`, file mode `0600`, atomic
  replacement, restrictive creation permissions, and inter-process locking;
- production mode refuses the file adapter and refuses a credential namespace
  shared with a development target or future write client.

Refresh is single-flight within a process and serialized across processes by
the adapter where multiple processes can share a credential. Tokens and DCR
metadata are never logged, included in exceptions, or written to CLI output.
Logout removes both after explicit confirmation.

## 6. Reviewed read manifest and drift control

The repository contains a versioned manifest generated from authenticated
discovery and then reviewed and committed by a human. It records, for every
tool in the observed provider surface:

- provider tool name and description;
- complete input schema, output schema when supplied, and relevant
  annotations;
- deterministic canonical schema and metadata digests;
- review disposition (`read_allowed` or `denied`) and review rationale;
- a required `mutates` boolean stating whether invoking the capability changes
  provider state. It is a reviewer's assertion, not a derived value — the live
  surface carries no annotations to derive it from — and it has no default: a
  manifest that omits it has not answered the question, which is not the same
  as answering "no". Format 1.0 predates it and is refused rather than
  migrated, because every value a migration could supply would be a guess
  about precisely the field that exists to record a human judgement.
- manifest format version, provider-surface digest, observation timestamp,
  reviewer metadata, and a canonical full-manifest digest.

The schema digest covers the provider name and complete input/output schemas;
the metadata digest covers description and annotations. Canonicalization is a
documented, test-vector-backed algorithm over UTF-8 JSON, followed by SHA-256.
Object key order and insignificant whitespace do not change a digest; array
order and semantically meaningful values do. The manifest format and digest
algorithm are versioned so an algorithm change is an explicit migration.

The **full-manifest digest** is SHA-256 over the canonical form of the complete
manifest except the self-referential `full_manifest_digest` field. It therefore
covers the manifest/digest format versions, provider-surface digest,
observation and reviewer metadata, every public capability-to-provider-tool
mapping, exact descriptions/schemas/annotations, every `read_allowed` or
`denied` disposition and rationale, and every other manifest field. Entries
have a defined canonical order. A capability remap, permission change,
same-version replacement, or metadata/schema edit necessarily produces a new
full-manifest digest; changing only the stored digest to match altered content
does not satisfy a separately configured expected digest.

The loader requires the manifest's declared `full_manifest_digest`, the
locally recomputed value, and the configured expected value to be identical.
The shorter public field name `manifest_digest` always means this same
full-manifest digest; it is not a per-tool or provider-surface digest.

### 6.1 Owner-assisted discovery

`rh-mcp admin discover` is an authenticated, owner-run administrative command.
It pages through the complete tool surface with strict bounds and writes a
sanitized candidate manifest. It does not invoke a tool, print account data,
change the active manifest, or grant permissions. The candidate becomes
active only after code review and a package release.

No real tool names or schemas are guessed before that run. Documentation and
tests use synthetic fixtures; any provisional names observed elsewhere must
not enter the production manifest without authenticated discovery and review.

### 6.2 Startup and call preflight

Before becoming ready, the gateway discovers the complete provider surface
and compares it with the committed manifest. It also recomputes the active
full-manifest digest and compares it with the consumer-supplied
`expected_manifest_digest`. Readiness fails closed, before a tool call, on:

- an unknown, missing, duplicate, or malformed tool;
- any input schema, output schema, annotation, or security-relevant metadata
  digest mismatch;
- pagination that exceeds limits, repeats a cursor, or does not terminate;
- a manifest with an unsupported version, invalid digest, duplicate entry, or
  no reviewed read capabilities; or
- a missing, malformed, or mismatched expected full-manifest digest.

The expected value is never inferred from the installed manifest and cannot be
overridden by a request. Thus package pinning and manifest pinning are separate
checks: a consumer must deliberately accept a new full-manifest digest even if
the package version or human-readable manifest version did not change.

For each request, the gateway resolves a public capability identifier through
the active manifest, verifies its `read_allowed` disposition and exact digest,
validates the input against the pinned schema, and only then calls the private
transport. Callers cannot supply an arbitrary provider tool name.

## 7. Public interfaces

### 7.1 Library

The conceptual interface is:

```python
config = GatewayConfig(expected_manifest_digest="sha256:...")
async with RobinhoodReadGateway(config, credential_store) as gateway:
    readiness = await gateway.readiness()
    result = await gateway.read(capability, arguments)
```

Every gateway instance that can invoke reads requires the expected digest as a
trusted constructor/configuration input. A separate discovery-only
administrative context may create a candidate manifest but cannot invoke a
read capability or become ready.

Readiness is an immutable, SDK-neutral object whose JSON form includes at
least:

```json
{
  "ready": true,
  "manifest_version": "...",
  "manifest_digest": "sha256:...",
  "expected_manifest_digest": "sha256:..."
}
```

On success the two digest values are equal. On mismatch, readiness is false,
reports only safe digest/configuration diagnostics, and no read can be sent.
The active `manifest_digest` is always the locally recomputed full-manifest
digest, never a value trusted directly from the manifest file.

`capability` is resolved only from the reviewed manifest. The exact Python
type may be generated from that manifest or represented by a validated enum;
it is never a free provider tool-name passthrough.

The result is an immutable, SDK-neutral envelope with a versioned JSON form:

```json
{
  "envelope_version": "1.0",
  "manifest_version": "...",
  "manifest_digest": "sha256:...",
  "capability": "...",
  "schema_digest": "sha256:...",
  "result_digest": "sha256:...",
  "observed_at": "...",
  "data": {},
  "warnings": []
}
```

`data` preserves the bounded provider JSON rather than inventing Robinhood
domain models. Structured content is checked against the pinned output schema
when one exists. A text block is accepted only through an explicit,
test-covered JSON decoding rule. Images, audio, resource links, embedded
resources, unexpected content types, ambiguous multiple payloads, and invalid
JSON fail with `protocol_error`; provider error content becomes a sanitized
`provider_error`. The canonical result digest is computed before returning the
envelope. Every successful envelope carries the same locally recomputed
full-manifest digest that made the gateway ready, allowing the consumer to
verify and audit the exact capability and permission contract used for that
call.

### 7.2 CLI

Supported command groups are:

- `login`, `logout`, and `auth status`;
- `status` and `capabilities` for safe readiness/manifest diagnostics;
- `read <capability> --input <json>` for reviewed capabilities only —
  34 reads and 11 non-trading mutations, never a trading tool (§2.1);
- `admin discover` for the owner-assisted candidate-manifest workflow.

There is no `call` command and no flag that disables manifest enforcement.
Structured JSON goes to stdout alone; diagnostics go to stderr. A failure
emits no partial result to stdout.

### 7.3 Stable errors and exit codes

Public errors contain a stable code, safe message, retryability flag, and
optional correlation identifier. They never include raw provider responses,
URLs with queries, headers, tokens, account identifiers, or stack traces.

Initial error codes are:

- `auth_required`
- `not_ready`
- `capability_denied`
- `input_invalid`
- `provider_error`
- `timeout`
- `response_too_large`
- `protocol_error`
- `configuration_error`

CLI exit codes remain small and documented: success, safe runtime/provider
failure, usage error, configuration/not-ready error, and authentication
required. Code-to-exit mapping is covered by compatibility tests.

## 8. Resource bounds, retries, and observability

Configuration supplies conservative defaults and hard maximums for connect,
read, total operation, OAuth callback, discovery, and pagination timeouts.
The gateway also bounds:

- number of pages and tools discovered;
- repeated cursors and total discovery bytes;
- request JSON depth and serialized size;
- response bytes, JSON depth, node count, and string length; and
- concurrent calls and refresh attempts.

All limits are enforced while reading/decoding, not only after an unbounded
payload is resident in memory. MCP tool calls are not automatically retried,
regardless of `idempotentHint`. A coordinated OAuth refresh may be attempted
once; transport failures otherwise return a stable error for the consumer to
handle deliberately.

Logs may contain operation class, reviewed capability, duration, readiness,
manifest/schema/result digests, safe error code, and correlation identifier.
They must not contain request arguments, response data, account identifiers,
credentials, or raw MCP traffic.

## 9. Configuration

Production configuration is intentionally narrow:

- credential-store adapter and namespace;
- callback port and exact loopback host/path;
- bounded timeout/concurrency settings; and
- active committed manifest selected by the installed package version; and
- required `expected_manifest_digest`, supplied independently by the consumer
  (`RH_MCP_EXPECTED_MANIFEST_DIGEST` for the CLI).

The expected digest must use the supported algorithm prefix and exact digest
length. Missing or malformed values are configuration errors. The expected
value is not read from the manifest itself, a provider response, or a mutable
per-request argument. `ainvest` passes its deployment-pinned digest into
`GatewayConfig`; CLI users pin the reviewed release digest through trusted
deployment configuration.

The official endpoint, issuer, OAuth hosts, TLS policy, and production
transport are not ordinary runtime overrides. Development-only endpoint,
stdio command, environment, and working-directory settings require the
explicit development mode described in §3 and cannot use production
credentials.

## 10. Boundary with ainvest and other consumers

`rh-mcp` owns:

- OAuth/DCR/PKCE, token refresh, and credential-store integration;
- official MCP endpoint validation and private MCP SDK v2 transport;
- bounded discovery, reviewed manifest, schema digests, and default-deny
  read enforcement;
- SDK-neutral bounded payloads, stable sanitized errors, and safe transport
  telemetry.

`ainvest` owns:

- pinning a reviewed `rh-mcp` release and expected full-manifest digest,
  supplying that digest to `GatewayConfig`, and verifying it on readiness and
  every result envelope;
- mapping gateway payloads into its versioned Quote, Position, Portfolio,
  Order, and other domain contracts;
- account/symbol consistency, freshness, data-quality, and tradability checks;
- strategy, sizing, risk limits, approval, paper/live gates, application audit,
  and user-facing CLI or Telegram workflows;
- system-level tests proving Research and Strategy components cannot obtain a
  credential, raw MCP session, unreviewed tool, or **trading** capability —
  and, separately, gating the 11 reviewed non-trading mutations §2.1 allows.
  "No write capability" was the original wording and is no longer true: a
  test asserting it would either fail or, worse, pass while asserting
  something false.

The consuming application must not parse MCP content blocks or receive a
Robinhood token. If deployed out of process, the broker protocol is separately
versioned, authenticated, authorized, bounded, and limited to the same
reviewed capabilities.

## 11. Testing requirements

The default test suite is offline. It uses synthetic schemas, fake OAuth
services, fake transports, temporary or in-memory credential stores, and a
controllable clock — with one deliberate exception: `TestTheShippedManifest`
asserts directly on the committed manifest, pinning its digest and naming
every trading tool that must stay denied. The manifest is a data file, so
without it nothing in the suite would notice a disposition changing. Required coverage includes:

- canonicalization and digest golden vectors;
- full-manifest golden vectors proving that capability mapping, provider tool,
  schema, metadata, allow/deny disposition, rationale, and same-version
  replacement changes alter the digest;
- manifest validation and every fail-closed drift case in §6.2;
- missing/malformed/mismatched expected-digest tests proving readiness is false
  and no read reaches the transport, with locally detectable mismatches
  rejected before provider discovery;
- readiness/envelope contract tests proving the locally recomputed active
  full-manifest digest is present and equals the configured expected digest;
- proof that denied/unknown/invalid requests never reach the transport;
- input/output schema validation and every supported MCP content mapping;
- pagination, repeated-cursor, timeout, cancellation, concurrency, and all
  request/response size/depth limits;
- stable envelope/error/exit-code compatibility fixtures;
- OAuth state/issuer/redirect validation, PKCE, callback timeout and replay;
- refresh single-flight, token rotation, atomic credential writes, locking,
  permissions, logout, and log/exception redaction;
- production endpoint/egress pinning and rejection of dev mode with a
  production credential store;
- dependency-boundary tests proving no MCP SDK types are public.

Live tests are manual or explicitly scheduled, opt-in, never run on pull
requests, use a dedicated non-production credential namespace, invoke only
manifest-approved reads, and redact all account data from artifacts. They do
not update the committed manifest automatically.

## 12. Packaging, CI, and release acceptance

Before another repository depends on `rh-mcp`, it must have:

- a `pyproject.toml`, supported Python range, reproducible lock file, package
  metadata, command entry point, and an explicit license;
- pinned compatible MCP SDK v2 constraints and automated dependency review;
- formatting, linting, type checking, unit/contract/security tests, build and
  package-install smoke tests in CI;
- semantic versioning, changelog, tagged release, immutable artifact, and
  checksums or provenance suitable for consumer pinning;
- publication of the reviewed full-manifest digest in the release artifact and
  release notes so consumers can pin it independently of package version;
- documented public API and compatibility policy for envelope, errors,
  manifest format, and credential-store protocol;
- a release gate requiring independent review of manifest changes and all
  security-boundary changes.

A release is not production-ready until authenticated discovery has produced
a reviewed manifest, all drift/deny tests pass, the credential adapter for the
target environment is validated, and an offline consumer contract test passes
against the built artifact.

## 13. Open items

All six owner-assisted observations are **closed**, on 2026-08-03:

1. ~~Confirm DCR acceptance and redirect-URI constraints.~~ Registration was
   accepted and reused across logins; the loopback redirect URI was not
   constrained beyond the registration.
2. ~~Determine whether an explicit scope is required.~~ `internal` was granted.
   The credential is write-capable and the token lifetime is ~4.7 days.
3. ~~Capture the authenticated tool surface.~~ 53 tools.
4. ~~Review each tool and commit dispositions.~~ 45 allowed, 8 denied (§2.1).
5. ~~Compute and publish the full-manifest digest.~~ Pinned in
   `tests/test_manifest.py::TestTheShippedManifest` and published in §12's
   release artifact.
6. ~~Confirm real response shapes and pagination.~~ Discovery paged and
   terminated within bounds. One bound was wrong and is fixed: a `tools/list`
   page is schemas *about* data and outgrew a depth limit sized for data, so
   discovery now has its own (§8).

Two provider behaviours observed and deliberately not worked around:

- **No tool carries any annotation.** Rule 4's "annotations are evidence, never
  authority" turned out to be moot — there is no evidence at all.
- **Session termination returns 400.** The MCP SDK sends a DELETE on close and
  Robinhood rejects it. Non-fatal; discovery completes. Left unsilenced,
  because suppressing another library's warning hides a signal that is not
  ours to hide.

What remains is the §12 release-acceptance list, not further observation.

## 14. Build order

1. Package/CI scaffold, SDK-neutral models, configuration, and error contract.
2. Canonicalization, full-manifest digest and expected-digest configuration,
   manifest format, offline fixtures, and fail-closed readiness/preflight
   enforcement.
3. Private MCP SDK v2 transport with bounded pagination, payload handling, and
   synthetic-server tests.
4. CredentialStore protocol/adapters and hardened OAuth/DCR/callback flow.
5. Public gateway and safe CLI composed over the tested lower layers.
6. Owner-assisted authenticated discovery, human review of the candidate
   manifest, and publication of its full-manifest digest.
7. Independent security/compatibility review, tagged release, and consumer
   contract integration.
