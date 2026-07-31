# rh-mcp — Design

Status: **design agreed, not implemented.** No code yet. The two open items
that previously blocked the auth layer are resolved — see §5.0 for the
discovery documents and §9 for what remains.

## 1. What this is

`rh-mcp` is a small, read-only Python client for Robinhood's official MCP
server, exposed two ways:

- **A library** — `RobinhoodMCPClient`, an async context manager. The primary
  consumer is the executor of an agentic trading system.
- **A CLI** — `rh-mcp`, for humans inspecting the server and debugging the
  executor.

Both are public surfaces and both are supported. The CLI is a thin shell over
the library and holds no logic of its own.

## 2. Non-goals

**No safety, policy, or risk logic lives in this client.** Order gating,
position limits, confirmation flows, audit trails, and retry policy are the
responsibility of the agentic trading system that consumes this client. A
component that quietly enforces its own trading policy is harder to reason
about than one that does exactly what it is told, and duplicated safety logic
in two layers is worse than in one.

Also out of scope:

- Writes of any kind for v0. The client is read-only (§5.2).
- Domain models. No `Position`/`Order`/`Quote` types, no normalization of
  server responses. Callers get what the server returned.
- A config file, output-shape compatibility guarantees, response caching, or
  a daemon/connection-reuse layer.

## 3. Target server

- Endpoint: `https://agent.robinhood.com/mcp/trading`
- Transport: streamable HTTP, remote and multi-tenant
- Auth: OAuth (§5)

The stdio transport is retained because it costs one branch, lets the test
suite run without a network, and supports local community servers. It is not
the design target.

**We do not hardcode tool names.** The client is a generic passthrough:
`list_tools` and `call_tool` work without knowing anything about Robinhood's
tool surface. This is why the MVP is not blocked on observing the real schemas
— it never needs them.

## 4. Architecture

```
config.py   ServerConfig — connection details and credential paths. No I/O.
auth.py     FileTokenStorage + OAuth provider construction.
client.py   RobinhoodMCPClient — AsyncExitStack over the transport, then
            ClientSession.initialize(). Passthrough methods.
cli.py      Typer app. Argument parsing, output rendering, exit codes.
```

Two invariants carried over from the existing scaffold:

- Transport is chosen once, in `ServerConfig`, and branched on once, in
  `__aenter__`. Both transports yield the same `(read_stream, write_stream)`,
  so everything below that branch is transport-agnostic.
- `RobinhoodMCPClient.session` raises `RuntimeError` if accessed before
  `__aenter__`, rather than returning `None`.

## 5. Authentication

The only substantial component that does not yet exist, and the only reason
the MVP is more than an afternoon.

The SDK supplies the machinery: `mcp.client.auth` provides
`OAuthClientProvider` — which is itself an `httpx2.Auth` — plus `TokenStorage`
and `PKCEParameters`. Wiring is therefore:

```
httpx2.AsyncClient(auth=OAuthClientProvider(...))
  -> streamable_http_client(url, http_client=...)
```

Note the dependency is **`httpx2`**, not `httpx`.

We supply three pieces:

| Piece | Responsibility |
|---|---|
| `FileTokenStorage` | `TokenStorage`: `get`/`set_tokens`, `get`/`set_client_info` |
| `redirect_handler` | Opens the browser at the authorization URL |
| `callback_handler` | One-shot `localhost` listener returning `AuthorizationCodeResult(code, state, iss)` |

### 5.0 Discovery — resolved

Both discovery documents are public and were read directly. Verbatim:

`GET /.well-known/oauth-protected-resource/mcp/trading`

```json
{
  "authorization_servers": ["https://agent.robinhood.com/mcp/trading"],
  "bearer_methods_supported": ["header"],
  "resource": "https://agent.robinhood.com/mcp/trading",
  "scopes_supported": ["internal"]
}
```

`GET /.well-known/oauth-authorization-server`

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

Four consequences worth stating before §5.1 and §5.2 read them off:

- **The client is public.** `token_endpoint_auth_methods_supported: ["none"]`
  plus `code_challenge_methods_supported: ["S256"]` means PKCE-only, no client
  secret. Nothing secret-shaped is ever stored except the tokens themselves.
- **Three hosts are in play.** Issuer and registration live on
  `agent.robinhood.com`, authorization on `robinhood.com`, token exchange on
  `api.robinhood.com`. Any egress allowlist in front of the executor must
  cover all three, and the browser leaves the issuer's origin during `login`.
- **Issuer equals resource.** The authorization server identifier is the MCP
  endpoint URL itself, so RFC 8707 resource-indicator handling and issuer
  validation both compare against the same string.
- **Discovery is served at both paths.** The issuer carries a path component
  (`/mcp/trading`), so RFC 8414 wants
  `/.well-known/oauth-authorization-server/mcp/trading`; the OIDC-style
  root path also works and returns a byte-identical document. Whichever URL
  the SDK probes first will succeed, so we do not pin one.
  `/.well-known/openid-configuration` is 404 — this is OAuth, not OIDC, and
  no ID token is issued.

### 5.1 Client registration — resolved: DCR supported

`registration_endpoint` is present. `rh-mcp login` self-registers on first
run; there is no `client_id` for the user to obtain or manage, and no
`RH_MCP_CLIENT_ID` in §7. `redirect_uris` still has to be supplied in the
client metadata we register with, which means the callback listener's port is
part of the registration and cannot drift between runs.

The registration response is a credential-shaped object and is persisted
through `FileTokenStorage.set_client_info` under the same `0600` rules as
tokens (§5.3). Re-registering on every `login` would be wasteful and may be
rate-limited; `get_client_info` returning a stored registration short-circuits
it.

**Untested from here:** whether the endpoint accepts an unauthenticated
registration in practice, and whether it pins or rejects particular
`redirect_uris` values. Both surface on the first real `login` and neither
changes the design — only the error message we should write for them.

### 5.2 Scope — resolved: one scope, `internal`

`scopes_supported` is `["internal"]` in both documents. There is no granular
scope, no read/write split, and the one value on offer is named in a way that
suggests it was not written with third-party clients in mind.

The §5.2 fallback therefore applies as written: **we request no scope** and
accept whatever the server's default grant is, rather than sending a string we
would be guessing at. Sending `internal` explicitly is the obvious
alternative and we specifically do not, because a scope value that reads as
server-internal is exactly the kind of thing that gets renamed without notice.

This has one consequence the original text did not anticipate and which should
be stated plainly: **read-only cannot be enforced at the scope layer.** The
grant we receive is whatever `internal` confers, which presumably includes
trading. v0 is read-only only in the sense that the client issues no writes
and the CLI exposes no write command — a convention, not a boundary. Per §2
that is consistent (gating belongs to the executor, and now it has to, because
the authorization server will not do it for us), but "the token can trade" is
a materially different security posture from "the token is scoped to reads,"
and the executor's threat model has to account for a stored credential that is
strictly more powerful than the client using it.

When the executor later needs to trade, there is accordingly nothing to widen.

### 5.3 Token storage

- JSON at `~/.config/rh-mcp/tokens.json`, honouring `XDG_CONFIG_HOME`.
- Mode `0600`, directory `0700`, enforced on every write.
- Atomic writes: temp file in the same directory, then `os.replace()`, so a
  crash cannot truncate a working credential.
- Never logged or included in error output.

**Known limitation, accepted for v0:** no locking around refresh. Two
concurrent processes may both refresh, and if the server rotates refresh
tokens one will be invalidated and require re-login. Deferred until the
executor's concurrency model is known; a file lock is the fix when it matters.

### 5.4 Interactive vs unattended

`login`, `logout`, and `auth status` are interactive and human-run. Every other
command and every library call is non-interactive: load tokens, refresh
silently, and never open a browser. If re-authentication is genuinely required,
fail immediately with exit `4` naming `rh-mcp login`, rather than blocking on a
prompt no automated caller will ever see.

## 6. Interfaces

### 6.1 Library

```python
async with RobinhoodMCPClient(ServerConfig.from_env()) as client:
    tools = await client.list_tools()
    result = await client.call_tool("some_tool", {...})
```

`call_tool` returns the raw `CallToolResult`. The executor unwraps content
blocks itself. Returning something pre-digested would mean inventing a shape
we would then owe compatibility on — and §2 rules out domain models. Raw is
honest and stable.

`list_tools` and `list_resources` follow `next_cursor` to completion; the
current scaffold drops it and silently truncates against a paginated server.

### 6.2 CLI

`login`, `logout`, `auth status`, `tools`, `call`, `resources`, `read`.

- `--output json|table`, defaulting to `table` on a TTY and `json` when piped.
- Structured output goes to stdout alone; all human messaging to stderr.
- **On failure stdout emits nothing**, so a consumer never parses a partial or
  error payload. The exit code carries the signal.

### 6.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error — tool returned `is_error`, or the call failed |
| 2 | Usage error |
| 3 | Configuration error |
| 4 | Authentication required; run `rh-mcp login` |

Deliberately small. Richer taxonomies belong upstream, where the retry and risk
decisions are actually made.

## 7. Configuration

Environment variables, overridable per-invocation by flags. No config file.

| Variable | Meaning |
|---|---|
| `RH_MCP_TRANSPORT` | `http` (default) or `stdio` |
| `RH_MCP_URL` | Endpoint; defaults to the official server |
| `RH_MCP_COMMAND` / `RH_MCP_ARGS` / `RH_MCP_ENV` / `RH_MCP_CWD` | stdio transport only |
| `RH_MCP_CALLBACK_PORT` | Fixed port for the `login` callback listener; must match the registered `redirect_uris` (§5.1) |

`RH_MCP_CLIENT_ID` is **dropped** — §5.1 resolved to "DCR supported", so there
is no client ID for a user to supply.

## 8. Testing

No test spawns a server or touches the network. The existing pattern holds:
fake the collaborator where it is imported into the module under test, not the
`mcp` classes globally.

Auth needs one addition — `FileTokenStorage` is tested directly against a
`tmp_path` (round-trip, permissions, atomic replace), and the OAuth flow is
tested with a fake authorization server rather than a live one.

## 9. Open items

Both of the original blockers are **closed**; the discovery documents are
transcribed in §5.0.

1. ~~**`registration_endpoint` present?**~~ Yes — DCR is supported, `login`
   self-registers, no `client_id` to manage (§5.1).
2. ~~**`scopes_supported` values?**~~ One value, `internal`. We request no
   scope and take the default (§5.2).

Nothing now blocks the auth layer. What remains are questions that can only be
answered by running against the live server, none of which change the
architecture:

- Does `/oauth/trading/register` accept an unauthenticated registration, and
  does it constrain `redirect_uris`? (§5.1)
- Does the default grant actually permit reads without an explicit scope?
- What does Robinhood's tool surface look like — needed for the CLI's
  ergonomics, not for the client, which never hardcodes tool names (§3).

## 10. Build order

1. **This document.**
2. Non-auth cleanups: HTTP-first defaults, pagination fix, `--output`/exit
   codes, stream discipline. Fully testable offline.
3. Auth. Unblocked as of §9; §5.0 supplies every value it needs.
