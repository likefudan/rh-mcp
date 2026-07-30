# rh-mcp — Design

Status: **design agreed, not implemented.** No code in this PR.

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

### 5.1 Client registration — open

`OAuthClientProvider` supports dynamic client registration, and
`redirect_uris` is required in the client metadata. Whether Robinhood permits
DCR is **unverified** (this environment's egress policy blocks the host), and
it decides the first-run experience:

- **DCR supported** — `rh-mcp login` self-registers. No `client_id` to manage.
- **DCR not supported** — the user registers an app and supplies `client_id`
  (and possibly a fixed redirect URI/port) via environment.

Resolved by reading `registration_endpoint` from the authorization server's
`/.well-known/oauth-authorization-server` document. Both paths are cheap; we
build whichever the metadata dictates.

### 5.2 Scope

`login` requests the narrowest scope that permits reads. The exact scope
strings are **unverified**, to be read from `scopes_supported` in the same
metadata document. If Robinhood offers no granular scopes, we request none and
accept the server's default rather than guessing a string that could fail
authorization outright.

Read-only is v0's scope request, not a client-enforced rule. When the executor
later needs to trade, it widens the scope request here; the gating decision
still belongs to the executor.

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
| `RH_MCP_CLIENT_ID` | Only if §5.1 resolves to "no DCR" |

## 8. Testing

No test spawns a server or touches the network. The existing pattern holds:
fake the collaborator where it is imported into the module under test, not the
`mcp` classes globally.

Auth needs one addition — `FileTokenStorage` is tested directly against a
`tmp_path` (round-trip, permissions, atomic replace), and the OAuth flow is
tested with a fake authorization server rather than a live one.

## 9. Open items

1. **`registration_endpoint` present?** (§5.1) — decides the login UX.
2. **`scopes_supported` values** (§5.2) — decides what `login` requests.

Both come from two unauthenticated `curl`s against the server's discovery
documents, and both must be answered before the auth layer is written.

## 10. Build order

1. **This document.**
2. Non-auth cleanups: HTTP-first defaults, pagination fix, `--output`/exit
   codes, stream discipline. Fully testable offline.
3. Auth, once §9 is resolved.
