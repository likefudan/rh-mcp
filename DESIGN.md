# rh-mcp — Design

Status: **released.** `v0.1.0` shipped on 2026-08-03, `v0.2.0` on 2026-08-04,
and `v0.3.0` on 2026-08-12. Owner-assisted discovery has since observed 54
tools; a human reviewed 46 allowed / 8 denied (§2.1).

The §12 acceptance list is now satisfied: license, changelog, tagged artifact
with published digests, the independent security review, and — as of §12.5 —
the published **compatibility policy** have all landed. `v0.2.0` responded to
the independent review that returned CHANGES_REQUIRED against `v0.1.0`;
`v0.3.0` ships the independently reviewed permission expansion and scanner
refresh — see §12.1–§12.4 and PRs #34–#35.

## 1. Purpose

`rh-mcp` is a default-deny Python gateway to Robinhood's official MCP server.
It gives a consuming application a narrow, reviewable capability surface while
keeping OAuth credentials, the MCP SDK, transport objects, and unreviewed MCP
tools behind the gateway boundary.

**The boundary this gateway enforces is "no trading", not "no writes".** The
first reviewed manifest allows a set of non-trading mutations — watchlist and
saved-scan management — alongside its reads. That was a deliberate reviewer
decision, and §2 states the resulting rule precisely. Say it plainly here
because the type is still named `RobinhoodGateway`: that name is narrower than
what the manifest now permits, and a name that overstates a guarantee is how a
reader ends up trusting one that does not exist. The method was renamed from
`read()` to `invoke()` in `v0.1.0` for exactly that reason; the type name is
the remaining half of the wart.

It has two supported public surfaces:

- **Library** — `open_gateway(config)`, an async context manager yielding a
  `RobinhoodGateway` for a trusted read-broker process. `RobinhoodGateway` is
  not itself a context manager and is not constructed directly by a consumer:
  it requires a loaded `ReviewedManifest` and an open transport, both of which
  `open_gateway` supplies. Import it as
  `from rh_mcp.gateway import open_gateway` — the top-level `rh_mcp` package
  re-exports nothing.
- **CLI** — `rh-mcp`, for login, readiness diagnostics, and invoking only
  capabilities present in the reviewed read manifest.

The CLI is a thin shell over the same gateway. Neither surface exposes an MCP
`ClientSession`, raw MCP result types, arbitrary tool names, or a generic
`call_tool` operation.

That last sentence was **false in `v0.1.0`** and is stated here as a corrected
claim rather than an unbroken one. `rh_mcp.transport.__all__` exported
`open_provider_session` and `ProviderTransport`, whose `call_tool` took any
provider tool name with no manifest lookup; the independent reviewer reached
`place_equity_order` through it. `v0.2.0` withdraws those names, and
`tests/test_public_surface.py` now checks the claim across every module rather
than only against `RobinhoodGateway` — which is how it stayed false through
four internal review rounds. See §12.1.

## 2. Security model and non-goals

Robinhood currently advertises one OAuth scope, `internal`, rather than
separate read and write scopes. A token must therefore be treated as capable
of trading whatever this gateway chooses to do with it. The boundary is
enforced locally with a committed allowlist and exact schema validation; it is
not inferred from the token, a tool name, or an MCP annotation.

Authenticated discovery (§13) settled two facts that this section previously
had to speculate about, and both matter more than they look:

- The provider surface is 54 tools, and **six of them place, cancel, or
  exercise real orders**. They arrive over the same session, under the same
  token, as every quote and position read. This manifest is the only thing
  between a consumer and a trade.
- **Not one of the 54 tools carries `readOnlyHint`, or any annotation at
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

### 2.1 What the active manifest actually allows

46 of 54 tools are allowed; 8 are denied. The denied set is exactly the
trading surface:

| denied | why |
|---|---|
| `place_equity_order`, `place_option_order` | Robinhood's own description: "Place a real equity order with **real money**" |
| `cancel_equity_order`, `cancel_option_order`, `cancel_option_exercise` | change the state of a live order |
| `exercise_option` | exercises a position |
| `review_equity_order`, `review_option_order` | "simulate an order without placing it" — denied anyway. Simulation is not a read of account state, it takes a complete order as its argument, and the meaning of "simulate" is defined entirely on Robinhood's side. If that meaning ever shifts, what we handed over was an order. |

The allowed set is 35 reads plus **11 non-trading mutations**: watchlist
create/update/add/remove/follow/unfollow, and saved-scan create/update. They
write to Robinhood; they move no money and touch no order.

The 35th read is `get_limited_margin_upgrade_info`, added on `2026.08.09` when
it appeared on the provider surface — the first time this table's *allowed* side
has grown since the manifest was first committed, and a permission expansion in
the sense §12.4 means. It returns limited-margin eligibility and the links that
start the upgrade flow. A draft of that change denied it on the reasoning that
its output is a route to a state change; review found the manifest had already
answered the question, because `get_option_level_upgrade_info` has the same
shape, gates the higher privilege of options trading, and has shipped `allowed`
/ `mutates: false` since the first commit. The denial would have made this
section's opening claim false — the denied set would no longer have been exactly
the trading surface — which is the clearest statement of why the two had to
agree.

The `2026.08.12` observation expanded one of the already allowed non-trading
mutations. `create_scan` can now take `scan_id` to append a new active
configuration version to an existing saved scan, and it can persist expression
filters. The owner accepted that as an expansion within the existing
saved-scanner configuration domain: the entry remains `allowed` / `mutates:
true`, its rationale now names the REPLACE-semantics blast radius, and no order,
funds, position, or account-permission state is reachable through it. The other
four moved scanner entries only changed provider prose nested in their schemas
to describe how custom expressions round-trip.

Two consequences a consumer must not discover by surprise:

- `RobinhoodGateway.invoke()` can mutate. The method was named `read()` when
  this manifest was reviewed, which was a wart the reviewer accepted knowingly;
  it was renamed to `invoke()` before `v0.1.0` shipped. The *type* is still
  `RobinhoodGateway`, and renaming it is deferred rather than rejected — that
  is now a breaking change to a released API, so it belongs to a deliberate
  major-version decision rather than riding along with a manifest change.
- §10 tells `ainvest` this surface is safe to call unattended. That remains
  true for the trading boundary, which is what its approval and paper/live
  gates exist for — but an unattended call can now create a watchlist. If
  `ainvest` gates mutations separately, it must gate these too.

  It does not have to infer which ones. Every manifest entry carries a
  reviewed `mutates` boolean, reported alongside `allowed` in `capabilities`
  output. That field is why the manifest format left 1.0 behind: a 1.0
  manifest cannot say whether a capability writes, and a loader that guessed
  would be guessing about precisely the thing the field exists to state, so
  1.0 is refused rather than migrated in place.

  The current format is **1.2**, and 1.1 is refused too. 1.1 introduced
  `mutates` but spelled the allowed disposition `read_allowed`, which read as
  a promise the manifest had stopped making — 11 of its allowed entries write.
  1.2 spells it `allowed`. `read_allowed` survives only as a Python attribute
  on `ManifestEntry` and `CapabilityDescription`; it is not a manifest value
  and not a JSON key.

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
canonical.py    The rh-canon-1 canonicalization algorithm and digests.
schema.py       The strict JSON Schema subset the pinned schemas validate under.
validation.py   Shared field validators and deep JSON freezing.
errors.py       The nine stable ErrorCodes and their exit-code buckets.
manifest.py     Manifest loading, digests, drift checks, per-call preflight.
transport.py    Private MCP SDK v2 session and bounded pagination.
gateway.py      open_gateway/RobinhoodGateway; preflight deny and sanitization.
models.py       SDK-neutral result envelope and readiness report.
cli.py          Thin CLI over gateway/auth/admin workflows.
```

The table lists every module in `src/rh_mcp/`; `__init__.py` is deliberately
empty, so there is no top-level re-export surface to keep in step with it.

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

- a platform secret store or an injected production secret-manager adapter is
  the normal choice. **The first deployment target is macOS, and the macOS
  Keychain adapter is the only one this package accepts in production mode.**
  That is a decision, not an omission: `file_dev` stores a trading-capable
  credential as plaintext JSON, so refusing to start beats degrading to it. A
  broker on another platform fails closed at start-up naming the reason, and
  adding a `CredentialStore` implementation over Vault or a cloud secret
  manager is the supported way to move — the protocol is narrow enough that it
  is a small piece of work, and doing it also solves moving a credential
  between machines, which matters because the first login must open a browser;
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
- review disposition (`allowed` or `denied`) and review rationale;
- a required `mutates` boolean stating whether invoking the capability changes
  provider state. It is a reviewer's assertion, not a derived value — the live
  surface carries no annotations to derive it from — and it has no default: a
  manifest that omits it has not answered the question, which is not the same
  as answering "no". Formats 1.0 and 1.1 are both refused rather than
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
mapping, exact descriptions/schemas/annotations, every `allowed` or
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

No real tool names or schemas are guessed before that run. Until it happened
the documentation and tests used synthetic fixtures only; that run has now
occurred (§13), so the committed manifest and `TestTheShippedManifest` hold
real names and schemas while every other fixture stays synthetic. The rule
this paragraph exists for is unchanged and still live: a provisional name
observed anywhere else must not enter the manifest without authenticated
discovery and review.

### 6.1.1 Refreshing a stale manifest

The committed manifest went stale within a day of first being committed: two
output schemas changed, readiness refused, and all 53 dispositions were still
correct. That is the ordinary case and it recurs, so it has one procedure:

```
rh-mcp admin discover > candidate.json
python scripts/refresh_manifest.py candidate.json --dry-run   # read the report
python scripts/refresh_manifest.py candidate.json
```

The script carries every reviewer decision forward verbatim and refreshes only
provider-derived fields and the digests over them. It cannot grant a
permission, because it never writes a disposition it did not read from the
previous manifest. It **refuses** when a tool appears or disappears (a changed
tool *set* is a review, not a refresh — no prior decision exists to carry
forward), when the observed surface is identical to the committed one (a
digest that moves when nothing moved destroys the signal the value carries),
and when either document fails to load.

It has no flag to change a disposition, and a test asserts none is ever added.
A permission change goes through §6.1's review, with a human writing the
rationale.

It does not update the pinned digest anywhere else. Every consumer of that
value has to be changed deliberately, because accepting a new manifest is the
decision §9's expected-digest mechanism exists to make explicit.

**A refresh is not a review.** Digests moving is the signal to go and read what
changed in those tools — a tool that gained a write capability would still
carry its previous `allowed` disposition through a refresh.

**What reading it caught on 2026-08-09.** `get_equity_orders`'s description
changed only to tell a caller to invoke `get_equity_orders`, `get_option_orders`
and `get_advanced_orders` "in parallel". The provider does not offer a
`get_advanced_orders`.

The first draft of that observation called this the first instance of provider
prose directing a call to a tool that does not exist. That was wrong, and the
correction is more useful than the claim. Sweeping every description and
schema-description string in the observed surface finds **five** such
references, and four of them —
`get_quotes` from `get_watchlist_items`, `get_crypto_positions` from
`get_accounts`, `get_currency_pairs` from `add_to_watchlist`, and
`preview_scan` from the `create_scan` and `update_scan_filters` schemas — have
been there since the first manifest was committed in `b2d4e2b`, several in
directive form ("call `get_quotes` with the symbol(s)", "Only preview_scan
accepts expressions"). So this is a standing property of the surface, not an
event.

`get_limited_margin_upgrade_info` is the instructive case. It was itself a
dangling reference on `2026.08.05`: the `get_accounts` and `get_portfolio`
guides both said "if the `get_limited_margin_upgrade_info` tool is available —
call it". On `2026.08.09` it appeared. These references are not provider errors;
they are forward pointers to tools being rolled out, which is also why the tool
that appeared arrived already wired into two read guides.

Nothing in this package acts on a description, so no enforcement is affected and
readiness noticed the change only as a metadata digest moving. The exposure is
entirely downstream: a consumer that forwards provider prose into a model's
context is handing the provider a channel for instructions addressed to that
model, which is what the `v0.2.0` review's consumer requirement 5 — discard
provider `guide`, tool descriptions and schema descriptions from model,
Telegram, CLI and log context — already requires be closed. Five live dangling
references make that requirement continuously load-bearing rather than
precautionary. Recorded here because the control §6.1.1 relies on is a human
reading what moved, and this is what that reading is for.

The `2026.08.12` scanner refresh added a **sixth** dangling name:
`get_scanner_datapoints`, repeated in `create_scan`'s description, filter
schema, and result guide. The offered tool set still has no such name. It is
the same downstream prompt-channel risk and changes no enforcement result:
provider prose is data, the gateway never resolves a name from it, and a
consumer must discard it rather than follow it.

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
the active manifest, verifies its `allowed` disposition and exact digest,
validates the input against the pinned schema, and only then calls the private
transport with **the frozen arguments that validation ran against** — not with
the mapping the caller passed in, which the caller may still mutate. Callers
cannot supply an arbitrary provider tool name.

## 7. Public interfaces

### 7.1 Library

The conceptual interface is:

```python
from rh_mcp.config import GatewayConfig
from rh_mcp.gateway import open_gateway

config = GatewayConfig(expected_manifest_digest="sha256:...")
async with open_gateway(config) as gateway:
    readiness = await gateway.readiness()
    result = await gateway.invoke(capability, arguments)
```

`open_gateway` is the entry point; `RobinhoodGateway` is what it yields, and a
consumer does not construct it. Its `store=`, `manifest=` and `transport=`
keywords exist for tests and for `admin discover` — a production caller passes
none of them, and none of them can disable manifest enforcement. There is no
`credential_store` positional parameter; the keyword is `store`.

Every gateway that can invoke reads requires the expected digest as a trusted
configuration input, carried on `GatewayConfig` rather than passed per call. A
separate discovery-only administrative context may create a candidate manifest
but cannot invoke a capability or become ready.

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

- `login`, `logout`, and `auth-status`;
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
- pinned compatible MCP SDK v2 constraints and automated dependency review
  (`.github/dependabot.yml`; the caps and the robot's agreement with them are
  asserted by `tests/test_dependency_bounds.py`, because a comment and a
  config are both edited by the PR that would widen them);
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

### 12.1 Independent security review — PERFORMED against v0.1.0

This item was **waived** through `v0.1.0`. It has since been **performed**, and
this section records the outcome rather than the exemption.

An independent AI-assisted reviewer outside this project examined the exact
`v0.1.0` artifacts — tag `a81464f6`, the released wheel and sdist, re-hashed
from the GitHub release — between 2026-08-03 and 2026-08-04. Their report and
their own adversarial tests are committed verbatim at
`security-review/v0.1.0/`. Disposition: **CHANGES_REQUIRED**.

They found two blocking defects:

- **P0.** `rh_mcp.transport.__all__` exported `open_provider_session` and
  `ProviderTransport`, whose `call_tool` accepted an arbitrary provider tool
  name with no manifest lookup, alongside the credential and token helpers
  needed to attach a write-capable bearer token. §1 of this document, the
  README and the CHANGELOG all claimed no public surface did that. They
  reached `place_equity_order` through the published API.
- **P1.** `preflight_read` validated a private copy of the arguments and
  returned only the entry; `invoke` then forwarded the caller's original
  mapping to the transport. A `MutableMapping` that changed after validation
  put `side` and `quantity` on the wire.

Both are fixed in `v0.2.0`, together with three P2 items: a released sdist
built from a dirty working tree, stale API and release-status claims in this
document and the README, and absent build provenance.

**The argument for the requirement is what happened, not what was found.**
Every earlier review this project had was performed by agents operating under
the same orchestration as the implementation. Four such rounds ran over the
code that shipped as `v0.1.0`. They were adversarial and productive — they
found a fail-open argument-validation bypass, a non-ASCII `state` that
defeated the OAuth callback's abort, a credential record printed by a
`__repr__`, an account identifier reaching consumer-visible JSON, and several
documentation claims the code did not support. None of the four found P0 or
P1.

P0 is the sharper lesson of the two. The repository *had* a test for exactly
that claim — `tests/test_gateway.py::TestNoEscapeHatch` — and it passed, every
run, for the whole life of `v0.1.0`. It asked whether `RobinhoodGateway` had
an escape hatch while the claim it defended was about the package. An outside
reviewer, reading the claim rather than the test, went straight to the module
the test never mentioned. A reviewer who shares an orchestrator with the
implementer inherits the implementer's idea of where to look, and that is not
a failure of diligence that more diligence would have fixed.

`tests/test_public_surface.py` now asks the question of every module, derived
from the claim rather than from the list of names already found.

Scope and honesty about the review itself. It is an **AI-assisted independent
review, with a disclosed limitation** — it ran in the same cloud-agent
environment that had previously done development-environment setup for this
repository, though not production code for `v0.1.0`, and it used a detached
worktree at the pinned commit. It is not a human penetration test, not a
third-party certification, and it performed no live authenticated calls
against Robinhood. Its approval gate is bound to the exact commit and
artifacts it names.

### 12.2 Independent security review — APPROVED for v0.2.0

`v0.2.0` was re-reviewed as a fresh artifact and returned
**APPROVED_FOR_AINVEST_INTEGRATION** on 2026-08-04, bound to commit
`46128a62`, the released wheel and sdist re-hashed from GitHub, manifest
`2026.08.03.1`, and envelope version `1.0`. The report and the reviewer's own
tests are committed at `security-review/v0.2.0/`.

Both prior blocking findings are recorded as resolved *on the published
surface*. Two non-blocking items remain, and both are consumer-facing rather
than defects to fix here:

**P2 — private names remain importable, and that is the accepted model.**
`_open_provider_session`, `StoredTokenProvider` and `open_credential_store`
can still be assembled into a manifest-free session by a caller who imports
them deliberately by name. §3 already states the threat model this sits
inside: importing this package into a broadly privileged process is not a
security boundary, because package separation isolates neither memory nor
credentials. The reviewer accepted it on that basis and recorded it as **a
requirement on the consumer**, which is the useful form: *a consumer that uses
only `open_gateway` / `RobinhoodGateway.invoke` cannot bypass the manifest; a
consumer that imports underscore-prefixed names can.* That sentence belongs in
`ainvest`'s integration checklist, not in a future patch here.

**P3 — one of their own `v0.1.0` assertions is defeatable by renaming.**
`test_call_tool_protocol_accepts_arbitrary_provider_name_without_manifest`
checks that the first parameter is no longer called `provider_tool_name`, so a
rename greens it without adding any manifest check. They flagged it against
their own test, which is the right instinct and worth recording: the
load-bearing check is `tests/test_public_surface.py`, which asks whether any
published name — or anything one returns — can reach the network, derived from
the claim rather than from a list of names. Both suites now run in CI on every
commit so neither can regress quietly.

### 12.3 What the reviews are and are not

Both were **AI-assisted independent reviews with a disclosed limitation**: they
ran in the same cloud-agent environment that had previously done
development-environment setup for this repository, though not the production
fixes they examined, and each used a detached worktree at its pinned commit.
Neither is a human penetration test, neither is a third-party certification,
and neither performed a live authenticated call against Robinhood.

Each verdict is bound to the exact commit and artifacts it names. A future
release is a new artifact and inherits neither.

Anyone evaluating this software for use against a real brokerage account
should weigh that directly. The same statement appears in `NOTICE`, so it
travels with any redistribution under Apache-2.0 §4(d).

### 12.4 When a manifest change needs a new external review

The reviewers bind each verdict to the exact artifact they examined, and by
their own wording a changed artifact is not covered. Taken literally that would
put every manifest refresh behind an external review — and the provider drifted
twice in three days, so "literally" is not a policy anyone would follow. This
section says what actually triggers one, so the answer is decided once rather
than argued each time.

**A refresh does not need a new review.** `scripts/refresh_manifest.py` carries
every `capability`, `disposition`, `mutates` and `rationale` forward verbatim
and refreshes only provider-derived fields and the digests over them. It
*cannot* grant a permission: it never writes a disposition it did not read from
the previous manifest, a post-write assertion proves none moved, and the script
has no flag to change one — with a test asserting none is ever added. What
moves is a description or a schema the provider changed.

**These do need one**, and the refresh tool already refuses all but the last,
so refusing is the normal way they surface:

- a tool appearing or disappearing — no prior decision exists to carry forward,
  and §6.1 requires a human to make it;
- any disposition, `mutates` value or capability mapping changing;
- a change to the manifest format, the canonicalization, or the digest
  derivation;
- any change to code on the enforcement path.

**What is given up by saying this.** A refresh can carry a reviewed `allowed`
disposition onto a tool whose schema has changed underneath it — the tool is
the same name doing something new. The refresh report names every entry whose
digests moved precisely so a human reads what changed there, and the two
refreshes so far were read that way: an additive `unsettled_funds` field on two
reads, and a `direction` field on two order tools that are denied anyway. That
reading is the control, and it is a human one. It is weaker than an external
review and stronger than nothing, and calling it what it is beats pretending
the digest check covers it.

**One consequence in the reviewers' own tests.** Their
`test_exact_8_trading_denied_and_11_mutations_allowed` opens by pinning the
manifest version and digest, so after a refresh it fails on the first line and
never reaches the assertions its name is about. Their file is not edited for
this — editing an auditor's evidence to make it pass is only defensible when
the file contradicts itself, which this does not. CI deselects that one test by
name and records why, and the property it was guarding is held independently by
`TestTheShippedManifest`, which asserts the same 8 denials, the same 11 flagged
mutations, and the same 46/8 split against whatever manifest ships. It also
asserts the denied set *as a set*, which the 2026.08.09 review added after a
draft of that change put a ninth entry in it and every existing count assertion
stayed green.

### 12.5 Published compatibility policy

This is the §12 acceptance item that was outstanding: "documented public API and
compatibility policy for envelope, errors, manifest format, and
credential-store protocol". `ainvest` is about to pin `v0.2.0`, so the promise
has to be written down before it is relied on rather than after.

Everything below is checked against the code, not against the prose that
preceded it. Where a surface is under-specified, or where the tests did not
actually defend a claim this document makes, it says so — a compatibility
policy that overstates its own guarantees is the same defect as §1's original
"no public surface exposes a generic `call_tool`", which was false for the whole
life of `v0.1.0`.

That is not a claim of having got it right first time. Three rounds of
independent review disproved, by mutation, six of this section's statements —
an enumeration of `retryable` sites that missed the most common one, and five
claims that an existing test already defended a surface when it did not. Each is
corrected below with the mutation that found it named beside the fixture that
now fails it. **Read that as the calibration for everything here that CI does
not hold:** a section whose confident claims needed an outside reader with a
mutation harness to falsify is a section whose remaining unfalsified claims
deserve the same suspicion.

The shape of those five matters more than the count. Three were in the first
draft. The fourth was in round 1's own *fix* for the third: it pinned the type
the CLI serializes and left what the CLI emits unpinned. The fifth was in round
2's fix for the fourth: it pinned what the CLI emits in the not-ready branch and
left the ready branch unpinned. One rule — assert the surface the promise names,
not the type behind it — failed three times in three disguises, each time inside
the work written to satisfy it. That is the argument for the outside reader
rather than against the rule.

**Two things a consumer pins, and they move independently.** The package
version covers the code — the surfaces below. The full-manifest digest covers
what the gateway is permitted to do. `CHANGELOG.md` opens with this and §6.2 and
§9 enforce it; it is not restated here beyond the one consequence that matters
for versioning: a new digest is never inferred from a version bump, and a
version bump is never inferred from a new digest.

#### The result envelope

`rh_mcp.models.ResultEnvelope` is what `RobinhoodGateway.invoke()` returns and
what `rh-mcp read` prints. Its `to_json_dict()` emits exactly nine keys:

`envelope_version`, `manifest_version`, `manifest_digest`, `capability`,
`schema_digest`, `result_digest`, `observed_at`, `data`, `warnings`.

`envelope_version` is `"1.0"`. It is a `field(init=False)` class default, so a
caller cannot pass one in and an envelope cannot claim a version it was not
built under. `manifest_digest` is always the locally recomputed full-manifest
digest that made the gateway ready (§7.1), never a value read from the manifest
file. `data` is the bounded provider JSON, deep-frozen at construction so
`result_digest` keeps binding exactly the payload it was computed over.
`warnings` is a JSON array of strings and may be empty.

**Stable, within `envelope_version` `1.x`:** those nine key names, their JSON
types, and their meanings. A consumer reading an envelope whose
`envelope_version` starts with `1.` is entitled to assume all nine are present.

**What may be added:** a new top-level key, in a minor release, with
`envelope_version` moving to `1.1`. A consumer must therefore ignore keys it
does not recognise rather than reject the envelope. **What may never change
meaning:** an existing key. Removing one, renaming one, or changing what one
means moves `envelope_version` to `2.0` and is a breaking release.

**Not promised:** the contents of `data`. That is provider JSON shaped by
Robinhood's output schema, and §6.1.1 records the provider changing schemas
twice in three days. Mapping it into domain contracts is `ainvest`'s job (§10).
`observed_at` is this gateway's clock at the moment the envelope was built, not
a provider timestamp.

**Honest about the enforcement.** Nothing in the code makes adding a key
*require* bumping `envelope_version`; the rule above is a rule for humans. What
CI holds is `tests/test_models.py::TestResultEnvelope::test_to_json_dict_shape`
and `::test_envelope_version_is_fixed`, which compare the whole rendered
dictionary against a literal, so any added, removed or renamed key fails the
suite and a reviewer then has to decide the version. That was verified by
mutation rather than assumed: renaming `envelope_version`, renaming
`expected_manifest_digest` on `Readiness`, renaming `warnings`, and changing the
version constant to `"1.1"` each fail `pytest`. No new fixture was added for
this surface, because a second one would assert what those already do.

#### Errors

**The nine wire strings are the contract, not the Python member names.**
`ErrorCode` is a `StrEnum`, so a member formats and JSON-serializes as its
value. The nine values are:

`auth_required`, `not_ready`, `capability_denied`, `input_invalid`,
`provider_error`, `timeout`, `response_too_large`, `protocol_error`,
`configuration_error`.

They are observable in two places a consumer actually reads, and both are
stable:

- the CLI's stderr line, exactly `rh-mcp: <code>: <message>`, pinned by
  `tests/test_cli.py::…::test_the_stderr_error_line_carries_the_wire_string_verbatim`
  for all nine codes;
- the `error_code` field of each finding in `rh-mcp status` JSON, which
  `DriftFinding.to_json_dict()` emits as `str(self.error_code)`.

Renaming `ErrorCode.CAPABILITY_DENIED` in Python while keeping the value
`"capability_denied"` is not a breaking change; keeping the member name and
changing the value is.

The stderr line needed its own fixture and did not have one when this section
was first written. `tests/test_errors.py` asserts `str(ErrorCode.X) == "x"`,
which is a property of `StrEnum` and says nothing about what `cli.py` writes: an
independent review rewrote the line to `rh-mcp error [CAPABILITY_DENIED]: …`,
changing both the format and the form of the code, and the whole suite stayed
green. That is the §12.1 `TestNoEscapeHatch` defect — a passing test asserting
something adjacent to the claim — reappearing inside the change written to
retire it. The lesson generalises and is worth stating once: **a fixture must
assert the surface the promise names, not a property of the type behind it.**

The set is closed at nine for now. A tenth code may be added in a minor
release, so a consumer switching on the code must have a default branch.

**`GatewayError` carries four public fields:** `code` (`ErrorCode`), `message`
(`str`), `retryable` (`bool`), `correlation_id` (`str | None`). That set is
stable. There is deliberately **no** `to_json_dict()` on `GatewayError` and none
is planned here: §7.2 rule 3 says a failure writes nothing to stdout, so nothing
in this package needs to serialize an error, and adding a method to an
enforcement-path module is a §12.4 trigger for a convenience nobody has asked
for.

**`message` is explicitly not stable.** It is human-facing text and may change
in any release, including a patch, with no changelog entry. A consumer must
branch on `code` and `retryable`, never on message text, and must never parse a
message for a value. §7.3 already constrains what a message may *contain* —
never a raw provider response, a URL with a query, a header, a token, an account
identifier, or a stack trace — and that constraint is stable even though the
wording is not.

**`retryable` is per-error and is not a function of `code`.** Five raise sites
can produce `True` today, and the two a consumer meets most often are
*conditional* rather than literal:

- **any provider HTTP 5xx.** `transport.py` peels 401 and 403 off first as
  `auth_required`, and records `retryable=500 <= response.status_code < 600` on
  every *remaining* response at or above 400 — so a 502 or 503 from Robinhood
  arrives as a **retryable** `provider_error` while a 400 or 429 arrives as a
  non-retryable one, and a 401 never reaches the expression at all.
  `tests/test_transport.py::test_a_server_failure_becomes_a_retryable_provider_error`
  asserts this for a 503.
- **any authorization-server 5xx** — the same expression, behind the same
  401/403 peel, in `auth.py`'s `_require_payload`, covering the token and
  registration endpoints.
- a failed connection to the provider — `provider_error`.
- contention on the credential `flock` — `timeout`.
- a non-answering macOS `security` tool — `timeout`.

Everything else carries the default `False`, and the sharp case is that a
provider *request* timeout is among them: it is `timeout` and it is **not**
retryable, while `flock` contention is `timeout` and is. `provider_error`
likewise appears on both sides, split by status class. So both of the codes a
consumer meets most often appear both ways, and deriving retryability from the
code is wrong in both directions.

Read `retryable=True` as "the gateway asserts a retry is safe" and `False` as
the absence of that assertion, not as "a retry will fail". The 400-versus-5xx
split is the shape of that distinction: a 400 is not asserted retryable because
resending the same request produces the same 400. Which sites set it, and the
condition each uses, may change in a minor release.

An earlier draft of this section said "exactly three raise sites". It was
counted by grepping for the literal `retryable=True`, which finds neither
conditional site — so it told a consumer that the most common retryable case
does not occur, with a committed test in this repository asserting that it does.
Recorded rather than quietly corrected, because it is the exact failure this
section is about: a confident enumeration that was never checked against the
code it enumerates.

**`correlation_id` exists and is never populated.** §7.3 calls it optional and
§8 lists a correlation identifier among what logs may contain, but no code in
`src/rh_mcp/` passes the argument: every `GatewayError` this package raises has
`correlation_id is None`. The field is public and a consumer constructing its
own `GatewayError` may set it; a consumer *reading* one must not depend on it
being there. This is recorded rather than fixed — populating it means touching
enforcement-path modules, which §12.4 says triggers a new external review, and
that is not a trade worth making for a field nothing currently reads.

**The five CLI exit-code buckets, and the integers are part of the contract:**

| exit | bucket | codes |
|---|---|---|
| 0 | success | — |
| 1 | safe runtime/provider failure | `provider_error`, `protocol_error`, `timeout`, `response_too_large` |
| 2 | usage error | `input_invalid`, `capability_denied` |
| 3 | configuration / not ready | `configuration_error`, `not_ready` |
| 4 | authentication required | `auth_required` |

`EXIT_CODE_MAP` is the single mapping and `cli.py` has no second one. Two
honest footnotes. `main()` returns **130** on `KeyboardInterrupt`, which is a
sixth value outside the five buckets and is the conventional SIGINT code rather
than an oversight. And an argparse usage failure returns `2` directly, landing
in the usage bucket by construction rather than through the map.

**This surface was the one the tests did not defend, and now they do.** Before
this section was written, the golden table in `tests/test_errors.py` was keyed
by enum *member*, so it asserted that `ErrorCode.CAPABILITY_DENIED` maps to exit
2 without ever asserting what string that member carries. Verified by mutation
on the tree at `b6d6a35`: changing the value to `"capability_refused"` left all
1176 tests passing. The exit integers had the same shape of gap — changing
`EXIT_CODE_PROVIDER_FAILURE` from `1` to `8`, or `EXIT_CODE_AUTH_REQUIRED` from
`4` to `9`, also left the suite green. `tests/test_errors.py` now pins the nine
literal strings and the five literal integers, and asserts the string set is
exactly those nine, so the promise made above fails CI when it stops being true.
It is the same lesson as §12.1's `TestNoEscapeHatch`: a test that passes while
asserting something adjacent to the claim is worse than no test, because it
reads like coverage.

#### Manifest format

Three version fields in every manifest document are checked exactly by the
loader, and a mismatch on any of them refuses the manifest rather than
migrating it:

- `manifest_format_version` — `"1.2"`. `SUPPORTED_MANIFEST_FORMAT_VERSIONS` is
  exactly `{"1.2"}`. 1.0 and 1.1 are refused, not migrated, for the reasons in
  §2.1 and §6: 1.0 cannot state `mutates`, and 1.1 spelled the allowed
  disposition `read_allowed` while 11 allowed entries write.
- `canonicalization_version` — `"rh-canon-1"`. The algorithm is specified in
  `src/rh_mcp/canonical.py`'s module docstring and pinned by golden vectors in
  `tests/test_canonical.py`. It is deliberately **not** RFC 8785/JCS — it sorts
  object keys by Unicode code point, not UTF-16 code unit — and no
  interoperability with JCS is claimed.
- `digest_algorithm` — `"sha256"`.

Every digest this package publishes or accepts is the string `"sha256:"`
followed by exactly 64 lowercase hex characters. `DIGEST_PATTERN` is anchored
with `\Z` rather than `$`, so a trailing newline picked up from a file or a CI
variable is rejected instead of silently never comparing equal. That shape is
stable and is what a consumer writes into `expected_manifest_digest` and
`RH_MCP_EXPECTED_MANIFEST_DIGEST`.

**Stable:** those three literal version strings and the digest string shape.
Changing any of them is, by §12.4's own list, "a change to the manifest format,
the canonicalization, or the digest derivation" — it triggers a new independent
external review, ships with a stated migration, and moves the package version in
its breaking position.

**Deliberately not a compatibility surface: the manifest's content.** Which
capabilities exist, which are `allowed` or `denied`, which set `mutates`, the
rationales, the human-readable `manifest_version` string, the
`provider_surface_digest`, and the `full_manifest_digest` itself are all
expected to move, and §6.1.1 shows how routinely. That movement is not a
compatibility break — it is the mechanism working. The pinned
`expected_manifest_digest` is exactly what turns a moved digest into a
deliberate human decision instead of a silent one (§6.2, §9), and **§12.4** says
which of those movements additionally need an external review: a refresh does
not, a disposition or tool-set change does.

So the two pins answer different questions, and a consumer needs both: *"is this
the code I reviewed?"* is the package version, and *"is this the permission set
I reviewed?"* is the digest.

**Under-specified, and stated rather than fixed.** The manifest is read only by
this package's loader; there is no published JSON Schema for it, so an outside
tool reading a manifest is reading a format defined by §6's prose and
`manifest.py`'s field sets. And format 1.2 still cannot distinguish a provider
that omitted `description`/`annotations` from one that sent `""`/`{}` — the
known limitation recorded in `manifest.py` and in the `0.1.0` changelog entry,
carried forward here rather than quietly dropped.

**One discrepancy this policy surfaces rather than hides.** `CHANGELOG.md`'s
`[0.1.0]` and `[0.2.0]` entries both print
`sha256:49b7218278fc2aebb1a040c89b8c94f60750afe142d6b728e88771944a88093a`
beside manifest version `2026.08.03.1`. Those two values do not go together.
`git show v0.1.0:src/rh_mcp/manifests/read-manifest.json` and the same at
`v0.2.0` both carry `2026.08.03.1` with
`sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`;
`49b7218…` is the digest of `2026.08.05`, which was what `main` shipped when
this section was written. Commit `b6d6a35` rewrote the digest inside the two
historical entries while refreshing the manifest. A consumer pinning the
`v0.2.0` *artifact* and taking its digest from that changelog entry would pin a
digest the artifact refuses readiness against.

<!-- manifest-automation:current-start -->
The current source declares package `0.3.3` and carries manifest `2026.08.22` / `79ae8643…`. This statement is about source identity; publication is established only by a completed tag workflow and GitHub release.
<!-- manifest-automation:current-end -->
That does not fix anything above and is
not meant to read as though it did: both changelog entries still print
`49b7218…` beside `2026.08.03.1`, both tags still ship `70f88615…`, and the
bracketed corrections beside them are still the whole of the remedy. A newer
source digest has now made those entries wrong twice over, which is the
argument for the rule below rather than against it — a changelog line
describing one release cannot be kept true by a later one.

Both wrong values are **left in place with a bracketed correction beside each**,
naming the tag, the correct digest, and the `git show` that produces it.
Substituting the right string silently would rewrite a published release record,
which is the release owner's decision and not a side effect of writing a policy;
leaving the line unmarked is a different act with a different cost, because a
changelog is read by jumping to your version's heading, and that reader is
exactly the one who would take the wrong digest. So the record is preserved and
the hazard is removed. The `v0.2.0` GitHub release notes carry the correct
value, and this file is the only place that does not.

Beyond the specific error, this is the general rule the policy asserts: **the
digest a consumer pins comes from the artifact it is pinning**, verified against
the release notes and the manifest inside it, never from a changelog line
describing a different release.

#### The credential-store protocol

`rh_mcp.credentials.CredentialStore` is a `typing.Protocol` with eight members,
and the set is the contract:

- `namespace: str` — a read-only property naming the credential namespace.
- `exclusive() -> AbstractAsyncContextManager[None]` — the cross-process mutex.
- `load_token() -> TokenCredential | None`
- `store_token(token: TokenCredential) -> None`
- `delete_token() -> bool` — `True` if something was removed.
- `load_registration() -> ClientRegistration | None`
- `store_registration(registration: ClientRegistration) -> None`
- `delete_registration() -> bool`

The six record operations are async. Each is individually atomic: a reader
never sees a half-written credential. What that does *not* give an implementer
is a safe read-modify-write across processes, which is what `exclusive()` is
for. The individual methods deliberately do not take the lock, so a sequence
inside `exclusive()` cannot deadlock against itself — an implementer must
therefore make `exclusive()` work for the sharing model its backend actually
has, and callers must hold it around any read-modify-write. `auth.py`'s
coordinated refresh is the one such sequence today.

`TokenCredential` and `ClientRegistration` are part of this surface: an
implementer accepts and returns them and does not reach for a serialized form,
because §5.2 requires read/update/delete "without exposing serialized secrets to
callers" and the encoders are module-private for that reason. Both refuse
`pickle` and redact `__repr__`/`__str__`; `dataclasses.asdict` remains an open
channel, which the module docstring states and a test pins.

**What is deliberately absent is also the contract.** There is no `list`, no
read-raw, no export, and no way to obtain the serialized form. A future member
may be added in a minor release — that breaks existing implementers, which is
why it is a minor and not a patch.

Two properties an implementer should know. The protocol is **not**
`@runtime_checkable`, so `isinstance(store, CredentialStore)` raises
`TypeError`; conformance is checked statically by `mypy` at the call sites that
accept one. And §5.2's production policy is separate from this protocol: in
production mode this package accepts only the macOS Keychain adapter, and
supplying another store means injecting an implementation of this protocol.

**What defends this, and the member that nothing defended.** Deleting any one of
the seven *method* declarations from the protocol fails `mypy src` — each has an
in-package call site through a `CredentialStore`-typed reference — and renaming
one consistently across the protocol and the adapters fails `pytest`, because
the adapter tests call them by name. That covers seven of the eight.

It did not cover `namespace`, which is the member listed first above. Nothing in
`src/` or `tests/` reads `.namespace` off a store, so an independent review
deleted it from the protocol and got a clean `mypy src`, then renamed it to
`scope_name` on both the protocol and `_BytesBackedStore` and got a clean
`mypy src` with the full suite passing. The member with no in-package consumer
is exactly the one a refactor drops without noticing, and it was undefended
precisely *because* nothing here uses it — which is the general shape of this
gap, not an accident of one name.

`tests/test_credentials.py` now pins the eight member names as a set, and
asserts every shipped adapter satisfies it. Both of the review's mutations fail
against it. The set assertion also catches an addition, which is the direction
that breaks an outside implementer rather than this package.

The wider point is worth keeping: an argument of the form "the existing gate
already catches this" has to be checked member by member, because the gate
catches things through call sites and a published contract may have members
that nothing in the package calls.

#### The versioning rule

The package is `0.3.0` and follows SemVer with the 0.x convention `pyproject.toml`
already states: **for a 0.x package the minor is the breaking position.**

- **Patch** (`0.3.0` → `0.3.1`): no change to any surface above. Error `message`
  text, log lines, stderr wording, and internal behaviour may change.
- **Minor** (`0.3.0` → `0.4.0`): may break. Adding an envelope key (and moving
  `envelope_version` to `1.1`), adding a tenth `ErrorCode`, adding a
  `CredentialStore` member, or withdrawing a public name all live here. `v0.2.0`
  itself was such a release: it withdrew four names from the export surface.
- **Major** (`1.0.0`): reserved. Renaming `RobinhoodGateway` — §1 and §2.1 both
  call that out as deferred rather than rejected — belongs to that decision.
  Once it happens the breaking position moves to major.

A consumer pins an exact package version **and** an exact
`expected_manifest_digest`, and neither is derivable from the other.

**How this interacts with §12.4's external-review trigger.** They are different
axes and both apply. §12.4 asks "does this change need a new independent
review?"; this section asks "what may a consumer's code assume across this
version change?". A manifest refresh moves the digest, needs no review, and
needs no version bump at all. A format, canonicalization, digest-derivation or
enforcement-path change needs a review *and* a minor bump.

The consequence for a consumer is sharper than it looks, because §12.3 binds
each verdict to the exact artifact it examined and says a future release
inherits nothing. `v0.2.0` carries **APPROVED_FOR_AINVEST_INTEGRATION** bound to
commit `46128a62` and to the wheel and sdist re-hashed from GitHub. A later
release that is compatible under this section is still an unreviewed artifact.
**Compatibility is not a security verdict**, and a consumer upgrading for
security reasons should pin the reviewed version rather than the newest
compatible one, or arrange for its own review.

#### What this policy does not promise

- **Anything about the provider.** Robinhood's tool set, schemas, descriptions,
  and payload shapes are theirs, and §6.1.1 shows them moving within a day.
- **`data` contents**, per the envelope section.
- **Anything private.** No underscore-prefixed name, and nothing outside a
  module's `__all__`, is covered — including `_open_provider_session`,
  `StoredTokenProvider` and `open_credential_store`, whose importability §12.2
  records as an accepted residual risk. A consumer relying on one has left this
  policy and, per that section, the security boundary too.
- **`DriftReason`'s strings.** Its nine values appear in `rh-mcp status` JSON,
  and its own docstring calls them "diagnostic detail, not part of §7.3's nine
  codes". New members may appear in a minor release; do not switch on them
  exhaustively.
- **`rh-mcp status` and `rh-mcp capabilities` JSON, beyond a floor.**
  `ReadinessAssessment.to_json_dict()` and `CapabilityDescription.to_json_dict()`
  carry **no version field of their own** — only the envelope does. §7.1 pins
  `Readiness`'s four keys as a floor with "includes at least"; the assessment
  adds `findings`, each finding rendering `reason`, `detail` and `error_code`.
  `capabilities` output is four top-level keys — `manifest_version`,
  `manifest_digest`, `expected_manifest_digest`, `digest_matches` — around a
  `capabilities` list whose entries carry `capability`, `allowed`, `mutates`,
  `description`, `schema_digest`, `rationale` and `input_schema`.

  Both payloads are pinned **as the CLI emits them**: `tests/test_cli.py` parses
  each command's stdout and asserts the whole key set, top level and per entry,
  in both directions, and `tests/test_manifest.py` and `tests/test_gateway.py`
  pin the objects underneath. So neither shape can move silently. What remains
  open is that neither payload announces its own version the way the envelope
  does, so a consumer has no way to *detect* a shape change short of comparing
  keys itself. That asymmetry is under-specified and is stated rather than
  closed: adding a version field to either means editing enforcement-path code,
  so it waits for a release already going through §12.4's review.

  That first sentence took three rounds of external review to become true, and
  how it kept failing is the transferable part. The first gap was additions:
  every key was read by name somewhere, so renames failed, but nothing compared
  a rendered dictionary against a literal — and an added key is precisely how an
  unversioned payload changes shape under a consumer that has no version field
  to notice it. Closing that by pinning `ReadinessAssessment.to_json_dict` and
  `CapabilityDescription.to_json_dict` then reproduced the same defect one layer
  up: `rh-mcp capabilities` assembles its four top-level keys inline in `cli.py`
  and serializes the pinned type only inside the list, so renaming
  `manifest_version` and `manifest_digest` in the emitted JSON still left the
  suite green. **Pinning the type a caller serializes is not pinning the payload
  that caller emits**, and the two claims come apart the moment anything is
  assembled around the type.

  Closing *that* by parsing stdout then left one branch: the fixture drove only
  the not-ready path, because the helper it reused could not build a ready
  assessment, so a key added under `if assessment.ready` reached stdout with the
  suite green. **A payload pinned in one branch is not a payload pinned**, and a
  command that renders two shapes needs both. Three rounds, three disguises of
  one rule — assert the surface the promise names, not the type behind it, and
  not one path through it.
- **Python beyond `requires-python = ">=3.12"`**, or any behaviour of the
  private `mcp` and `httpx2` dependencies, whose major bounds §12 treats as a
  security-boundary change to widen.
- **That the policy is self-enforcing.** The fixtures named above are what CI
  actually holds: the envelope and `Readiness` key sets, the `status` and
  `capabilities` payloads as the CLI emits them, the nine error wire strings,
  the CLI's stderr error line, the five exit integers, the code-to-bucket map,
  the `CredentialStore` member set, the canonicalization vectors, and the
  shipped manifest's dispositions. Everything else here is a commitment a human
  can break in a single commit, and saying which is which is the point of
  writing it down.

  The standing rule that follows from how this section was written: **no claim
  of the form "the existing gate already catches this" enters it without the
  mutation that demonstrates it**, named beside the fixture that fails.

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

Nothing in §12 now remains, and nothing that remains is further observation of
the provider. The compatibility policy is §12.5, the last item; the `v0.2.0`
re-review is §12.2, which records **APPROVED_FOR_AINVEST_INTEGRATION** on
2026-08-04 bound to commit `46128a62`, with the report at
`security-review/v0.2.0/`.

This sentence had said the re-review was outstanding, which §12.2 had already
contradicted — the text was written before the approval landed and was edited
rather than re-read afterwards. It is corrected here rather than left, because
§12.5 now tells a consumer to decide what to pin from these enumerations, and a
stale "what remains" list is exactly the kind of claim §12.1 says four review
rounds walked past.

What remains outside §12 is §14's consumer contract integration.

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

Steps 1–6 are complete. Step 7 is nearly complete: `v0.1.0` was tagged and
released, the independent security review was performed and returned
CHANGES_REQUIRED (§12.1), `v0.2.0` was re-reviewed as a fresh artifact and
returned APPROVED_FOR_AINVEST_INTEGRATION (§12.2), and the compatibility policy
§12 asked for is published as §12.5. Outstanding within step 7: **consumer
contract integration**, and nothing else.
