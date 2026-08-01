"""The private MCP SDK v2 session (DESIGN.md §3, §4, §7.1, §8).

This is the **only** module in the package permitted to import the MCP SDK or
`httpx2`. Everything it hands back is an ordinary Python value or one of the
SDK-neutral types in `models.py`/`manifest.py`, so a consumer on a different
MCP major version inherits no dependency or wire-contract conflict (§4). The
session object and its transport are never reachable from a public property.

Four decisions in here are load-bearing enough to state up front.

**Discovery and tool results are read as raw JSON, not as SDK models.** The
obvious implementation calls `ClientSession.list_tools()` and maps
`types.Tool` into `ObservedTool`. It is wrong, and quietly so. `mcp_types`
models default to Pydantic's `extra="ignore"`, so a `tools/list` response
carrying `{"annotations": {"readOnlyHint": true, "vendorFoo": 1}}` validates
into a model that has dropped `vendorFoo` — measured, not assumed. Every
digest in §6 is computed over the annotations we observed, so a provider could
add, change, or remove any field the installed SDK does not model and the
metadata digest would never move. §2 requires an annotation change to surface
as review evidence; reading the raw payload is what makes that true. Both
methods therefore go through `send_request(..., RootModel[dict[str, Any]])`,
which still runs the SDK's protocol-conformance check on the response and then
returns the untouched decoded JSON.

**The server-initiated GET stream is refused inside the guarded transport.**
Streamable HTTP lets a server open a long-lived SSE channel for notifications.
This gateway is a request/response read client that never consumes one, and an
unbounded stream is precisely what §8 forbids: a byte cap on it would either be
useless or would kill a healthy session after enough notifications. The guard
answers the SDK's GET with a local 405 and performs no egress, which is the
same thing a server that does not support the channel would return, so the SDK
handles it on a documented path.

**Nothing is retried.** §8 is explicit that a tool call is never automatically
retried regardless of `idempotentHint`, so the session uses `ClientSession`
rather than `Client`: `Client.call_tool` drives an input-required retry loop
and `Client.list_tools` serves cached listings, and a cached tool surface would
make the §6.2 drift comparison compare the manifest against a memory of the
provider rather than the provider.

**Bounds are enforced where the bytes are.** For every HTTP target the response
byte cap is applied while the body streams, so an oversized payload is aborted
mid-read and never becomes resident. Depth, node count, and string length are
then enforced by a walk that stops at the first breach. The one honest gap is
the development-only stdio target, which has no byte layer to meter; there the
size bound is applied after the SDK has decoded a message. That is a
development target reached only through §3's explicit development mode against
a local server, and it is called out here rather than papered over.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal, NoReturn, Protocol, cast
from urllib.parse import urlsplit

import anyio
import httpx2
import mcp_types
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from pydantic import RootModel, ValidationError

from rh_mcp.canonical import canonicalize
from rh_mcp.config import PRODUCTION_RESOURCE_URL, GatewayConfig, ResourceLimits
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.manifest import ObservedSurface, ObservedTool
from rh_mcp.schema import validate_instance
from rh_mcp.validation import is_encodable

logger = logging.getLogger(__name__)

# §3: the complete set of hosts this gateway may ever contact in production.
# Authorization and token hosts are here because step 4's OAuth exchanges run
# through the same guarded client; the browser stays outside the boundary.
PRODUCTION_EGRESS_HOSTS: Final[frozenset[str]] = frozenset(
    {"agent.robinhood.com", "robinhood.com", "api.robinhood.com"}
)

# The result type both MCP calls are decoded into. A `RootModel` over a plain
# dict is what keeps the raw JSON raw: `send_request` still runs the SDK's
# protocol-conformance check on the response, and then this hands back exactly
# the decoded object, with every field the installed SDK's typed models would
# have silently dropped still present. See the module docstring.
_RawResult = RootModel[dict[str, Any]]

# JSON-RPC error codes worth distinguishing. Everything else from a provider
# collapses into `provider_error`; the provider's own message is never used.
_JSONRPC_CODE_MAP: Final[dict[int, ErrorCode]] = {
    mcp_types.PARSE_ERROR: ErrorCode.PROTOCOL_ERROR,
    mcp_types.INVALID_REQUEST: ErrorCode.PROTOCOL_ERROR,
    mcp_types.METHOD_NOT_FOUND: ErrorCode.PROTOCOL_ERROR,
    mcp_types.INVALID_PARAMS: ErrorCode.INPUT_INVALID,
    mcp_types.REQUEST_TIMEOUT: ErrorCode.TIMEOUT,
}


# --------------------------------------------------------------------------
# SDK-neutral surface
# --------------------------------------------------------------------------


PayloadSource = Literal["structured_content", "text_content"]


@dataclass(frozen=True)
class ToolPayload:
    """One bounded, SDK-neutral tool result, ready for step 5 to wrap (§7.1).

    Deliberately *not* a `ResultEnvelope`: the envelope carries the manifest
    version, manifest digest, capability name, and schema digest, none of which
    this layer knows or should know. A transport that could name a capability
    would be a transport that could be asked for one.

    `source` records which §7.1 mapping produced `data`. It exists so step 5
    and the audit log can tell a schema-checked structured payload from one
    recovered by decoding a text block, which are different evidentiary
    situations even when the bytes agree.
    """

    data: Mapping[str, Any]
    source: PayloadSource
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.data, Mapping):
            _fail(ErrorCode.PROTOCOL_ERROR, "tool payload data must be a JSON object")
        object.__setattr__(self, "warnings", tuple(self.warnings))


class AccessTokenProvider(Protocol):
    """How the transport obtains a bearer token, without owning credentials.

    Step 4 implements this over the credential store and single-flight refresh.
    It is a one-method protocol returning a plain string so no credential type,
    store handle, or SDK auth object crosses into this module. The token is
    written into an `Authorization` header and is never logged, never placed in
    an exception message, and never returned to a caller (§5.2, §7.3).
    """

    async def access_token(self) -> str: ...


class ProviderTransport(Protocol):
    """What step 5 needs from an open session. `SurfaceDiscovery` plus a call.

    Structural rather than concrete so the gateway can be tested against a
    fake without either side importing the other's implementation.
    """

    async def discover(self) -> ObservedSurface: ...

    async def call_tool(
        self,
        provider_tool_name: str,
        arguments: Mapping[str, Any],
        *,
        output_schema: Mapping[str, Any] | None,
    ) -> ToolPayload: ...


def _fail(code: ErrorCode, message: str, *, retryable: bool = False) -> NoReturn:
    raise GatewayError(code, message, retryable=retryable)


# --------------------------------------------------------------------------
# Bounded JSON handling (§8)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Budget:
    """The §8 payload bounds, resolved once from `ResourceLimits`."""

    max_bytes: int
    max_depth: int
    max_nodes: int
    max_string_length: int


def _budget_for_response(limits: ResourceLimits) -> _Budget:
    return _Budget(
        max_bytes=limits.max_response_bytes,
        max_depth=limits.max_json_depth,
        max_nodes=limits.max_response_nodes,
        max_string_length=limits.max_response_string_length,
    )


def _budget_for_request(limits: ResourceLimits) -> _Budget:
    # §8 bounds request depth and serialized size. Node count and string length
    # have no separate request knob, so the response bounds stand in: they are
    # the reviewed ceilings for "a JSON value this gateway will handle", and a
    # request is always the smaller of the two in practice.
    return _Budget(
        max_bytes=limits.max_request_bytes,
        max_depth=limits.max_json_depth,
        max_nodes=limits.max_response_nodes,
        max_string_length=limits.max_response_string_length,
    )


def bound_json(value: Any, budget: _Budget, code: ErrorCode, *, label: str = "payload") -> Any:
    """Walk decoded JSON under the §8 bounds and return an immutable copy.

    The walk stops at the *first* breach rather than measuring the whole value
    and then complaining, so a decode bomb costs only the traversal up to the
    limit. It also re-validates that the value really is decoded JSON, using
    the same rules as `validation.freeze_json` — non-finite floats, unpaired
    surrogates and non-string keys are rejected here too, because a payload
    that reached this module through a fake transport never passed the HTTP
    decoder.

    Byte size is checked separately by `_ensure_within_bytes`, because the
    exact canonical length is only meaningful once the structure is known to be
    bounded.
    """
    nodes = 0

    def walk(item: Any, depth: int) -> Any:
        nonlocal nodes
        if depth > budget.max_depth:
            _fail(code, f"{label} nests deeper than the {budget.max_depth}-level limit")
        nodes += 1
        if nodes > budget.max_nodes:
            _fail(code, f"{label} contains more than {budget.max_nodes} JSON nodes")
        if isinstance(item, Mapping):
            frozen: dict[str, Any] = {}
            for key, sub in item.items():
                if not isinstance(key, str):
                    _fail(code, f"{label} object keys must be strings")
                if not is_encodable(key):
                    _fail(code, f"{label} object keys may not contain unpaired surrogates")
                if len(key) > budget.max_string_length:
                    _fail(
                        code,
                        f"{label} contains an object key longer than "
                        f"{budget.max_string_length} characters",
                    )
                frozen[key] = walk(sub, depth + 1)
            return MappingProxyType(frozen)
        if isinstance(item, (list, tuple)):
            return tuple(walk(sub, depth + 1) for sub in item)
        if isinstance(item, str):
            if len(item) > budget.max_string_length:
                _fail(
                    code,
                    f"{label} contains a string longer than "
                    f"{budget.max_string_length} characters",
                )
            if not is_encodable(item):
                _fail(code, f"{label} may not contain unpaired surrogates")
            return item
        if isinstance(item, bool) or item is None or isinstance(item, int):
            return item
        if isinstance(item, float):
            # RFC 8259 has no NaN/Infinity literal, and a NaN passes every
            # numeric threshold a consumer applies (§7.1, §10).
            if item != item or item in (float("inf"), float("-inf")):
                _fail(code, f"{label} may not contain NaN or Infinity")
            return item
        _fail(code, f"{label} may contain only JSON types, got {type(item).__name__}")

    return walk(value, 0)


def _ensure_within_bytes(
    value: Any, budget: _Budget, code: ErrorCode, *, over_code: ErrorCode, label: str
) -> int:
    """Measure a bounded value's canonical byte length and enforce the cap.

    Two codes, because "this is not encodable JSON" and "this is too big" are
    different faults: the first is a `protocol_error` or an `input_invalid`
    depending on who produced the value, the second is `response_too_large` for
    a response and `input_invalid` for a request.

    The measurement runs *after* the structural walk, so by the time an exact
    length is computed the value is already known to be bounded in depth, node
    count and string length — and for an HTTP target the streaming cap has
    already refused anything larger than `max_response_bytes` on the wire.
    """
    size = len(canonicalize(value, code=code))
    if size > budget.max_bytes:
        _fail(over_code, f"{label} serializes to more than {budget.max_bytes} bytes")
    return size


def _exceeds_text_depth(text: str, limit: int) -> bool:
    """Whether JSON *text* nests deeper than `limit`, without decoding it.

    The same guard `manifest.py` uses, for the same reason: `json.loads`
    recurses, and a few hundred thousand opening brackets raise `RecursionError`
    — which is not a `ValueError` and escapes the §7.3 error contract entirely.
    Characters inside strings are skipped so a bracket in a value cannot
    inflate the count.
    """
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > limit:
                return True
        elif character in "]}":
            depth -= 1
    return False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a JSON object that names one key twice.

    `json.loads` keeps the last occurrence silently. In a payload that a
    consumer will act on financially, two different readings of the same bytes
    is not a difference anyone should absorb quietly.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            _fail(ErrorCode.PROTOCOL_ERROR, "a provider text payload names the same key twice")
        seen[key] = value
    return seen


def _reject_json_constant(name: str) -> Any:
    _fail(ErrorCode.PROTOCOL_ERROR, f"a provider text payload contains the literal {name}")


# --------------------------------------------------------------------------
# Egress policy and the guarded HTTP transport (§3, §8)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _EgressPolicy:
    """What the guarded HTTP transport will let out (§3).

    Built once when a session opens. `require_https` and `allowed_hosts` are
    not runtime overrides: production values come from module constants, and
    the development values can only describe a loopback target because
    `GatewayConfig` already refused anything else.
    """

    allowed_hosts: frozenset[str]
    require_https: bool
    max_response_bytes: int
    max_request_bytes: int

    @classmethod
    def for_config(cls, config: GatewayConfig) -> _EgressPolicy:
        limits = config.limits
        if config.mode == "production":
            return cls(
                allowed_hosts=PRODUCTION_EGRESS_HOSTS,
                require_https=True,
                max_response_bytes=limits.max_response_bytes,
                max_request_bytes=limits.max_request_bytes,
            )
        url = config.dev_url
        if url is None:
            _fail(ErrorCode.CONFIGURATION_ERROR, "an HTTP egress policy needs a development URL")
        host = urlsplit(url).hostname
        if host is None:
            _fail(ErrorCode.CONFIGURATION_ERROR, "the development URL names no host")
        return cls(
            allowed_hosts=frozenset({host.lower()}),
            require_https=False,
            max_response_bytes=limits.max_response_bytes,
            max_request_bytes=limits.max_request_bytes,
        )


class _Fault:
    """The one place an HTTP-layer refusal is recorded.

    A `GatewayError` raised inside an `httpx2` transport does not arrive at the
    caller intact: the SDK's writer task catches it, pushes it into the read
    stream, and the pending request surfaces as a generic connection failure.
    Recording the real fault here and consulting it in `_translate` is what
    keeps `response_too_large`, `auth_required` and a rejected redirect from
    being flattened into `protocol_error` — the difference between an operator
    running `rh-mcp login` and an operator filing a provider bug.
    """

    def __init__(self) -> None:
        self.error: GatewayError | None = None

    def record(self, error: GatewayError) -> GatewayError:
        # First fault wins: it is the one that caused everything after it.
        if self.error is None:
            self.error = error
        return error

    def take(self) -> GatewayError | None:
        error, self.error = self.error, None
        return error


class _CappedStream(httpx2.AsyncByteStream):
    """Aborts a response body as soon as it exceeds the §8 byte cap.

    The cap is applied *while* the body streams, which is the difference §8
    insists on: an oversized payload is never fully resident, so a provider
    cannot exhaust memory before a limit gets a chance to fire.
    """

    def __init__(self, inner: httpx2.AsyncByteStream, cap: int, fault: _Fault) -> None:
        self._inner = inner
        self._cap = cap
        self._fault = fault

    async def __aiter__(self) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in self._inner:
            total += len(chunk)
            if total > self._cap:
                raise self._fault.record(
                    GatewayError(
                        ErrorCode.RESPONSE_TOO_LARGE,
                        f"the provider response exceeded {self._cap} bytes and was aborted "
                        "while still being read",
                    )
                )
            yield chunk

    async def aclose(self) -> None:
        aclose = getattr(self._inner, "aclose", None)
        if aclose is not None:
            await aclose()


class _GuardedAsyncTransport(httpx2.AsyncBaseTransport):
    """Enforces §3 pinning and §8 request/response bounds on every request.

    Placed under the `httpx2.AsyncClient` the SDK writes through, so there is
    no code path from the MCP session to the network that skips it — including
    the SDK's own transport-internal GET and DELETE.
    """

    def __init__(
        self,
        inner: httpx2.AsyncBaseTransport,
        policy: _EgressPolicy,
        fault: _Fault,
        token_provider: AccessTokenProvider | None,
    ) -> None:
        self._inner = inner
        self._policy = policy
        self._fault = fault
        self._token_provider = token_provider

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET":
            # See the module docstring: this gateway never consumes a
            # server-initiated notification stream, and refusing it locally
            # both removes an unbounded read and performs no egress at all.
            return httpx2.Response(405, request=request, content=b"")

        self._check_egress(request)
        self._check_request_size(request)
        await self._apply_authorization(request)

        response = await self._inner.handle_async_request(request)

        if 300 <= response.status_code < 400:
            await response.aclose()
            raise self._fault.record(
                GatewayError(
                    ErrorCode.PROTOCOL_ERROR,
                    "the provider attempted a redirect; programmatic redirects are rejected "
                    "so a pinned endpoint cannot be moved by a response",
                )
            )
        if response.status_code in (401, 403):
            self._fault.record(
                GatewayError(
                    ErrorCode.AUTH_REQUIRED,
                    "the provider rejected the credential; run `rh-mcp login`",
                )
            )
        elif response.status_code >= 400:
            # The status class is safe telemetry; the body is not (§7.3, §8).
            self._fault.record(
                GatewayError(
                    ErrorCode.PROVIDER_ERROR,
                    f"the provider returned HTTP {response.status_code}",
                    retryable=500 <= response.status_code < 600,
                )
            )

        return httpx2.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_CappedStream(
                cast(httpx2.AsyncByteStream, response.stream),
                self._policy.max_response_bytes,
                self._fault,
            ),
            extensions=response.extensions,
            request=request,
        )

    def _check_egress(self, request: httpx2.Request) -> None:
        scheme = (request.url.scheme or "").lower()
        host = (request.url.host or "").lower()
        if self._policy.require_https and scheme != "https":
            raise self._fault.record(
                GatewayError(
                    ErrorCode.CONFIGURATION_ERROR,
                    f"production egress must use https, got {scheme!r}",
                )
            )
        if scheme not in ("http", "https"):
            raise self._fault.record(
                GatewayError(ErrorCode.CONFIGURATION_ERROR, f"unsupported scheme {scheme!r}")
            )
        if host not in self._policy.allowed_hosts:
            # The host is configuration, not provider data, so naming it is
            # safe and is the only useful thing this error can say.
            raise self._fault.record(
                GatewayError(
                    ErrorCode.CONFIGURATION_ERROR,
                    f"egress to {host!r} is outside this deployment's allowed hosts",
                )
            )

    def _check_request_size(self, request: httpx2.Request) -> None:
        body = request.content
        if len(body) > self._policy.max_request_bytes:
            raise self._fault.record(
                GatewayError(
                    ErrorCode.INPUT_INVALID,
                    f"the outbound request body exceeds {self._policy.max_request_bytes} bytes",
                )
            )

    async def _apply_authorization(self, request: httpx2.Request) -> None:
        if self._token_provider is None:
            return
        token = await self._token_provider.access_token()
        if not isinstance(token, str) or not token:
            raise self._fault.record(
                GatewayError(ErrorCode.AUTH_REQUIRED, "no access token is available")
            )
        # A token is attacker-influenced in the sense that matters here: it is
        # a string from a credential store that ends up in a header. A newline
        # would split the header block. Never echo the value (§7.3).
        if any(character < "\x20" or character > "\x7e" for character in token):
            raise self._fault.record(
                GatewayError(
                    ErrorCode.AUTH_REQUIRED,
                    "the stored access token contains characters that cannot appear in an "
                    "HTTP header",
                )
            )
        request.headers["authorization"] = f"Bearer {token}"

    async def aclose(self) -> None:
        await self._inner.aclose()


def _build_http_client(
    config: GatewayConfig,
    fault: _Fault,
    token_provider: AccessTokenProvider | None,
    *,
    inner: httpx2.AsyncBaseTransport | None = None,
) -> httpx2.AsyncClient:
    """The only `httpx2.AsyncClient` this package ever creates (§3).

    Two properties are structural rather than configurable. `follow_redirects`
    is False, so a 3xx can never move the pinned endpoint — and the guarded
    transport refuses one outright rather than handing it to the SDK. TLS
    verification is left at `httpx2`'s default, which is on. There is
    deliberately no parameter, environment variable, or development-mode
    branch anywhere in this module that can turn it off, and a source-level
    test asserts no TLS-verification argument is ever passed.

    `inner` exists for the offline suite, which mounts a synthetic MCP server
    under the guard so the guard itself is exercised on every test request.
    """
    limits = config.limits
    timeout = httpx2.Timeout(
        connect=limits.connect_timeout_s,
        read=limits.read_timeout_s,
        write=limits.connect_timeout_s,
        pool=limits.connect_timeout_s,
    )
    policy = _EgressPolicy.for_config(config)
    base = _new_base_transport() if inner is None else inner
    return httpx2.AsyncClient(
        transport=_GuardedAsyncTransport(base, policy, fault, token_provider),
        follow_redirects=False,
        timeout=timeout,
    )


def _new_base_transport() -> httpx2.AsyncBaseTransport:
    """The real network transport, isolated so the suite can replace it.

    A separate function purely so `open_provider_session` needs no injection
    parameter: an `httpx2` type in that signature would breach §4, and a
    public "give me your own transport" hook is a hole in the pinning this
    module exists to enforce. The offline suite patches this name, which means
    it exercises the production code path — guard, policy, redirect rejection
    and all — rather than a parallel one written for tests.
    """
    return httpx2.AsyncHTTPTransport()


# --------------------------------------------------------------------------
# Error translation (§7.3)
# --------------------------------------------------------------------------


def _stable_error(exc: BaseException, fault: _Fault) -> GatewayError:
    """Decide what a failed operation reports, in the one order that is right.

    The order matters more than it looks, and getting it wrong was a real bug
    found by the offline suite. When the guarded transport refuses a request —
    a bad host, a rejected redirect, an unusable token — it raises inside an
    `httpx2` transport, which is inside the SDK's writer task, which is inside
    an `anyio` task group. The SDK catches it, closes the connection, and the
    task group cancels its siblings. What arrives at the awaiting caller is
    therefore a *cancellation*, not the refusal.

    So a recorded fault is consulted **before** the cancellation check.
    Otherwise every §3 pinning refusal would surface as a bare
    `CancelledError`: the operator sees a cancelled task where the truth was
    "this deployment refused to talk to that host".

    The tradeoff is stated plainly. If a caller cancels at the same instant the
    guard records a fault, this reports the fault and the cancellation is not
    re-raised from here. That is a narrow race, the recorded fault is real
    either way, and the alternative — losing every pinning diagnostic to a
    cancellation the SDK generated itself — is worse. With no fault recorded, a
    cancellation always propagates untouched, which is the case that keeps a
    caller's `CancelScope` working and is covered by its own test.
    """
    recorded = fault.take()
    if recorded is not None:
        return recorded
    _reraise_if_cancelled(exc)
    return _translate(exc, fault)


def _translate(exc: BaseException, fault: _Fault) -> GatewayError:
    """Turn any failure into one of the nine public codes, safely.

    Nothing provider-derived is copied into the message — not a JSON-RPC
    `message`, not a response body, not a URL.
    """
    if isinstance(exc, GatewayError):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            translated = _translate(inner, fault)
            if translated.code is not ErrorCode.PROTOCOL_ERROR:
                return translated
        return GatewayError(ErrorCode.PROTOCOL_ERROR, "the provider session failed")
    if isinstance(exc, TimeoutError):
        return GatewayError(ErrorCode.TIMEOUT, "the provider did not answer in time")
    if isinstance(exc, httpx2.TimeoutException):
        return GatewayError(ErrorCode.TIMEOUT, "the provider did not answer in time")
    if isinstance(exc, httpx2.TransportError):
        return GatewayError(
            ErrorCode.PROVIDER_ERROR, "the connection to the provider failed", retryable=True
        )
    if isinstance(exc, ValidationError):
        return GatewayError(
            ErrorCode.PROTOCOL_ERROR, "the provider sent a response that is not valid MCP"
        )
    mcp_error = _as_mcp_error(exc)
    if mcp_error is not None:
        code = _JSONRPC_CODE_MAP.get(mcp_error, ErrorCode.PROVIDER_ERROR)
        return GatewayError(code, f"the provider returned MCP error {mcp_error}")
    return GatewayError(ErrorCode.PROTOCOL_ERROR, "the provider session failed")


def _as_mcp_error(exc: BaseException) -> int | None:
    """The JSON-RPC code of an SDK error, or None.

    Read structurally rather than with `isinstance(exc, MCPError)` so the
    *only* thing crossing out of the SDK is an integer. The provider's
    `message` and `data` are deliberately left behind: §7.3 keeps a raw
    provider response out of a public error, and a JSON-RPC message is one.
    """
    error = getattr(exc, "error", None)
    code = getattr(error, "code", None)
    return code if isinstance(code, int) else None


# --------------------------------------------------------------------------
# The private session
# --------------------------------------------------------------------------


class _PrivateSession:
    """Wraps an MCP `ClientSession`. Never handed to a caller.

    The SDK session is a private attribute with no accessor, so §4's "the MCP
    session and transport are never available through a public property" is a
    property of the class rather than a convention.
    """

    def __init__(
        self, session: ClientSession, limits: ResourceLimits, fault: _Fault
    ) -> None:
        self.__session = session
        self._limits = limits
        self._fault = fault
        self._semaphore = anyio.Semaphore(limits.max_concurrent_calls)
        self._response_budget = _budget_for_response(limits)
        self._request_budget = _budget_for_request(limits)

    # -- discovery ---------------------------------------------------------

    async def discover(self) -> ObservedSurface:
        """Page through `tools/list` under every §6.2 and §8 bound.

        Budgets and protocol violations are reported differently on purpose. A
        page or tool budget being spent means the surface may be larger than
        what was seen, which is exactly what `ObservedSurface.complete=False`
        says, and readiness turns it into `incomplete_discovery`. A repeated
        cursor is not a budget — §6.2 lists it beside "does not terminate" as a
        fail-closed condition with no allowance — so it raises instead, and no
        configuration can permit even one repeat.
        """
        limits = self._limits
        tools: list[ObservedTool] = []
        seen_cursors: set[str] = set()
        cursor: str | None = None
        pages = 0
        total_bytes = 0
        complete = True

        try:
            with anyio.fail_after(limits.pagination_timeout_s):
                while True:
                    if pages >= limits.max_discovery_pages:
                        complete = False
                        break
                    pages += 1
                    page = await self._list_tools_page(cursor)

                    total_bytes += _ensure_within_bytes(
                        page,
                        self._response_budget,
                        ErrorCode.PROTOCOL_ERROR,
                        over_code=ErrorCode.RESPONSE_TOO_LARGE,
                        label="a tools/list page",
                    )
                    if total_bytes > limits.max_discovery_bytes:
                        _fail(
                            ErrorCode.RESPONSE_TOO_LARGE,
                            f"discovery read more than {limits.max_discovery_bytes} bytes",
                        )

                    entries = _page_tools(page)
                    room = limits.max_discovery_tools - len(tools)
                    if len(entries) > room:
                        # More tools exist than the reviewed budget allows this
                        # run to enumerate. The ones already read are kept so an
                        # operator can see what was there, but the surface is
                        # explicitly not complete.
                        complete = False
                        entries = entries[:room]
                    tools.extend(_observed_tool(entry) for entry in entries)
                    if not complete:
                        break

                    cursor = _next_cursor(page)
                    if cursor is None:
                        break
                    if cursor in seen_cursors:
                        # §6.2 lists a repeated cursor beside "does not
                        # terminate" as a fail-closed condition with no budget,
                        # so this raises rather than spending an allowance:
                        # once a cursor repeats, no bound on pages can make the
                        # enumeration exactly-once again.
                        _fail(
                            ErrorCode.PROTOCOL_ERROR,
                            "the provider repeated a pagination cursor, so the tool "
                            "surface cannot be enumerated exactly once",
                        )
                    seen_cursors.add(cursor)
        except GatewayError:
            raise
        except BaseException as exc:  # noqa: BLE001 - re-raised as a stable code
            raise _stable_error(exc, self._fault) from None

        return ObservedSurface(tuple(tools), complete=complete)

    async def _list_tools_page(self, cursor: str | None) -> Mapping[str, Any]:
        request = mcp_types.ListToolsRequest(
            params=mcp_types.PaginatedRequestParams(cursor=cursor)
        )
        raw = await self.__session.send_request(
            request,
            _RawResult,
            request_read_timeout_seconds=self._limits.discovery_timeout_s,
        )
        bounded = bound_json(
            raw.root, self._response_budget, ErrorCode.PROTOCOL_ERROR, label="a tools/list page"
        )
        return cast(Mapping[str, Any], bounded)

    # -- invocation --------------------------------------------------------

    async def call_tool(
        self,
        provider_tool_name: str,
        arguments: Mapping[str, Any],
        *,
        output_schema: Mapping[str, Any] | None,
    ) -> ToolPayload:
        """Send exactly one `tools/call` and map its result per §7.1.

        Exactly one: there is no retry here for any reason, including a
        provider `idempotentHint` (§8). A failed read returns a stable error
        and the consumer decides deliberately whether to ask again.
        """
        if not isinstance(provider_tool_name, str) or not provider_tool_name:
            _fail(ErrorCode.INPUT_INVALID, "a provider tool name is required")
        if not isinstance(arguments, Mapping):
            _fail(ErrorCode.INPUT_INVALID, "tool arguments must be a JSON object")

        bounded_arguments = bound_json(
            arguments, self._request_budget, ErrorCode.INPUT_INVALID, label="tool arguments"
        )
        _ensure_within_bytes(
            bounded_arguments,
            self._request_budget,
            ErrorCode.INPUT_INVALID,
            over_code=ErrorCode.INPUT_INVALID,
            label="tool arguments",
        )
        payload = cast(dict[str, Any], _plain(bounded_arguments))

        # The semaphore bounds *concurrent* calls (§8) rather than rejecting a
        # burst: a read that waits its turn is what a caller expects, and the
        # total-operation timeout inside covers a queue that never drains.
        async with self._semaphore:
            try:
                with anyio.fail_after(self._limits.total_timeout_s):
                    raw = await self.__session.send_request(
                        mcp_types.CallToolRequest(
                            params=mcp_types.CallToolRequestParams(
                                name=provider_tool_name, arguments=payload
                            )
                        ),
                        _RawResult,
                        request_read_timeout_seconds=self._limits.read_timeout_s,
                    )
            except GatewayError:
                raise
            except BaseException as exc:  # noqa: BLE001 - re-raised as a stable code
                raise _stable_error(exc, self._fault) from None

        bounded = bound_json(
            raw.root, self._response_budget, ErrorCode.PROTOCOL_ERROR, label="a tools/call result"
        )
        _ensure_within_bytes(
            bounded,
            self._response_budget,
            ErrorCode.PROTOCOL_ERROR,
            over_code=ErrorCode.RESPONSE_TOO_LARGE,
            label="a tools/call result",
        )
        return self._map_result(cast(Mapping[str, Any], bounded), output_schema)

    # -- §7.1 content mapping ---------------------------------------------

    def _map_result(
        self, result: Mapping[str, Any], output_schema: Mapping[str, Any] | None
    ) -> ToolPayload:
        """The complete §7.1 mapping table, in one place.

        1. `isError` is a provider-reported tool failure and becomes a
           sanitized `provider_error`. The provider's own content is dropped
           entirely: it is free text from the far side, §7.3 forbids it in a
           public error, and an error string is exactly where an account
           identifier has been seen before.
        2. `structuredContent` is authoritative when present and is checked
           against the pinned output schema when the manifest supplies one. An
           accompanying text block is discarded with a warning rather than
           reconciled — MCP servers are told to duplicate the JSON there for
           backward compatibility, so treating the duplicate as a second,
           conflicting payload would reject conforming servers.
        3. With no structured content, exactly one text block is accepted and
           decoded by the explicit rule in `_decode_text_payload`. Zero blocks
           and two-or-more blocks are both `protocol_error`: the first has no
           payload and the second is the ambiguity §7.1 names.
        4. Every other content type — image, audio, resource link, embedded
           resource, or anything unrecognised — is `protocol_error`, whether it
           appears alone or beside a payload.
        """
        if result.get("isError") is True:
            _fail(
                ErrorCode.PROVIDER_ERROR,
                "the provider reported that the tool call failed",
                retryable=False,
            )

        blocks = result.get("content")
        if blocks is None:
            blocks = ()
        if not isinstance(blocks, (list, tuple)):
            _fail(ErrorCode.PROTOCOL_ERROR, "the provider's result content is not an array")

        kinds = [_block_kind(block) for block in blocks]
        unexpected = sorted({kind for kind in kinds if kind != "text"})
        if unexpected:
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                f"the provider returned unsupported result content of type(s) {unexpected}; "
                "this gateway accepts structured content or a single JSON text block",
            )

        structured = result.get("structuredContent")
        warnings: list[str] = []

        if structured is not None:
            if not isinstance(structured, Mapping):
                _fail(
                    ErrorCode.PROTOCOL_ERROR,
                    "the provider's structured content is not a JSON object",
                )
            if output_schema is not None:
                validate_instance(structured, output_schema, label="structured content")
            if blocks:
                warnings.append(
                    f"the provider also returned {len(blocks)} text block(s); they were "
                    "discarded in favour of the structured content"
                )
            return ToolPayload(
                data=structured, source="structured_content", warnings=tuple(warnings)
            )

        if not blocks:
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                "the provider returned neither structured content nor a text block",
            )
        if len(blocks) > 1:
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                f"the provider returned {len(blocks)} text blocks, so which one is the "
                "result is ambiguous",
            )

        decoded = self._decode_text_payload(blocks[0])
        if output_schema is not None:
            validate_instance(decoded, output_schema, label="decoded text content")
        warnings.append(
            "the payload was recovered by decoding a text block; the provider sent no "
            "structured content"
        )
        return ToolPayload(data=decoded, source="text_content", warnings=tuple(warnings))

    def _decode_text_payload(self, block: Any) -> Mapping[str, Any]:
        """The explicit, test-covered rule for accepting a text block (§7.1).

        Stated as rules rather than left to `json.loads`, because every default
        in that function is more permissive than this gateway wants:

        * the block's `text` must be a string;
        * its UTF-8 length is checked *before* decoding, so an oversized string
          is refused rather than expanded into objects first;
        * its bracket depth is checked before decoding too, because deep JSON
          raises `RecursionError`, which is not a `ValueError`;
        * `NaN`, `Infinity` and `-Infinity` are rejected — they are Python
          extensions, not JSON, and a NaN satisfies every numeric threshold a
          consumer might apply;
        * a duplicate object key is rejected rather than silently last-wins;
        * the decoded value must be a JSON **object**, because that is what a
          `ResultEnvelope.data` is; an array or a bare scalar is not a result;
        * the decoded value is then walked under the same §8 bounds as
          structured content.
        """
        if not isinstance(block, Mapping):
            _fail(ErrorCode.PROTOCOL_ERROR, "the provider's content block is not an object")
        text = block.get("text")
        if not isinstance(text, str):
            _fail(ErrorCode.PROTOCOL_ERROR, "the provider's text block carries no string text")
        if not is_encodable(text):
            _fail(ErrorCode.PROTOCOL_ERROR, "the provider's text block is not encodable as UTF-8")
        if len(text.encode("utf-8")) > self._response_budget.max_bytes:
            _fail(
                ErrorCode.RESPONSE_TOO_LARGE,
                f"the provider's text block exceeds {self._response_budget.max_bytes} bytes",
            )
        if _exceeds_text_depth(text, self._response_budget.max_depth):
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                f"the provider's text block nests deeper than "
                f"{self._response_budget.max_depth} levels",
            )
        try:
            decoded = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except GatewayError:
            raise
        except ValueError:
            # The decoder's message quotes the offending text (§7.3).
            _fail(ErrorCode.PROTOCOL_ERROR, "the provider's text block is not valid JSON")
        if not isinstance(decoded, Mapping):
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                "the provider's text block decoded to something other than a JSON object",
            )
        bounded = bound_json(
            decoded, self._response_budget, ErrorCode.PROTOCOL_ERROR, label="a decoded text block"
        )
        return cast(Mapping[str, Any], bounded)


def _reraise_if_cancelled(exc: BaseException) -> None:
    """Let a cancellation through untouched.

    Converting a cancellation into a `GatewayError` would swallow the caller's
    own `CancelScope` and leave a task that refuses to stop. `anyio` decides
    what cancellation looks like on the running backend, so the class is asked
    for rather than assumed to be `asyncio.CancelledError`.
    """
    if isinstance(exc, anyio.get_cancelled_exc_class()):
        raise exc


def _plain(value: Any) -> Any:
    """A mutable, JSON-serializable copy of a frozen bounded value."""
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _block_kind(block: Any) -> str:
    if not isinstance(block, Mapping):
        return "<malformed>"
    kind = block.get("type")
    return kind if isinstance(kind, str) and kind else "<untyped>"


def _page_tools(page: Mapping[str, Any]) -> tuple[Any, ...]:
    tools = page.get("tools")
    if tools is None:
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list page carries no tools array")
    if not isinstance(tools, (list, tuple)):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list page's tools field is not an array")
    return tuple(tools)


def _next_cursor(page: Mapping[str, Any]) -> str | None:
    cursor = page.get("nextCursor")
    if cursor is None:
        return None
    if not isinstance(cursor, str) or not cursor:
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list page returned a malformed pagination cursor")
    return cursor


def _observed_tool(entry: Any) -> ObservedTool:
    """Map one raw `tools/list` entry into the SDK-neutral observed shape.

    Two lossy mappings are unavoidable and are stated here rather than
    discovered later. MCP makes `description` and `annotations` optional, while
    a reviewed manifest entry stores a string and an object; `null` and `""`
    therefore produce the same metadata digest, as do `null` and `{}`. A
    provider flipping between those spellings would not register as drift.
    Widening the manifest format to distinguish them is a §6 format change, not
    a transport change, and the tests pin the current behaviour so the gap
    stays visible.
    """
    if not isinstance(entry, Mapping):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list entry is not a JSON object")
    name = entry.get("name")
    if not isinstance(name, str):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list entry has no string name")

    description = entry.get("description")
    if description is None:
        description = ""
    if not isinstance(description, str):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list entry has a non-string description")

    input_schema = entry.get("inputSchema")
    if not isinstance(input_schema, Mapping):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list entry has no inputSchema object")

    output_schema = entry.get("outputSchema")
    if output_schema is not None and not isinstance(output_schema, Mapping):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list entry has a non-object outputSchema")

    annotations = entry.get("annotations")
    if annotations is None:
        annotations = {}
    if not isinstance(annotations, Mapping):
        _fail(ErrorCode.PROTOCOL_ERROR, "a tools/list entry has non-object annotations")

    return ObservedTool(
        name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
    )


# --------------------------------------------------------------------------
# Opening a session — transport selection happens exactly here (§4)
# --------------------------------------------------------------------------


_StreamConnector = Callable[[], Any]
"""A zero-argument callable returning the SDK's own transport context manager.

Typed `Any` deliberately: naming the SDK's stream types here would put an
`mcp.*` type in a signature, which §4 forbids. Nothing outside this module
constructs one — `_open_over_connector` is private for exactly that reason.
"""


@asynccontextmanager
async def open_provider_session(
    config: GatewayConfig,
    *,
    token_provider: AccessTokenProvider | None = None,
) -> AsyncIterator[ProviderTransport]:
    """Open the one private MCP session, choosing its transport once (§4).

    Production is Streamable HTTP against the pinned resource URL and nothing
    else: the URL comes from `config.effective_resource_url`, which returns the
    module constant in production mode regardless of any other field, and the
    guarded client refuses egress anywhere outside §3's three hosts. A
    development target is either a loopback URL or a stdio command, and
    `GatewayConfig` has already proved a development URL cannot name a remote
    host.

    The selection happens here, once, before the session exists. There is no
    later branch, no reconnection to a different target, and no property that
    hands the session or the transport back out.
    """
    if config.mode == "production" and config.effective_resource_url != PRODUCTION_RESOURCE_URL:
        # Unreachable through `GatewayConfig`, and checked anyway: this is the
        # single assertion that a production session talks to the pinned
        # endpoint, and it costs one comparison.
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "a production session may only target the pinned Robinhood resource URL",
        )

    fault = _Fault()
    url = config.effective_resource_url

    if url is not None:
        client = _build_http_client(config, fault, token_provider)

        def connect() -> Any:
            return streamable_http_client(url, http_client=client)

        async with client:
            async with _open_over_connector(connect, config, fault) as session:
                yield session
        return

    command = config.dev_stdio_command
    if command is None:  # pragma: no cover - GatewayConfig guarantees one target
        _fail(ErrorCode.CONFIGURATION_ERROR, "no transport target is configured")
    if token_provider is not None:
        # A stdio server is a local subprocess; handing it a production-shaped
        # bearer token would put a credential on a pipe for no benefit.
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "a development stdio target must not be given an access token",
        )

    parameters = StdioServerParameters(
        command=command,
        args=list(config.dev_stdio_args),
        env=dict(config.dev_stdio_env) or None,
        cwd=config.dev_stdio_cwd,
    )

    def connect_stdio() -> Any:
        return stdio_client(parameters)

    async with _open_over_connector(connect_stdio, config, fault) as session:
        yield session


@asynccontextmanager
async def _open_over_connector(
    connector: _StreamConnector, config: GatewayConfig, fault: _Fault
) -> AsyncIterator[ProviderTransport]:
    """Drive the MCP handshake over an already-selected transport.

    Private because its argument yields SDK stream objects. The offline suite
    calls it directly to run a synthetic server in-process; nothing on the
    public surface can.
    Connect and teardown are handled through an explicit `AsyncExitStack`
    rather than nested `async with` blocks, for two reasons that are easy to
    get wrong.

    First, only *connect* failures are translated into a stable error code. A
    single `try` wrapped around a nested `yield` would also catch whatever the
    consumer's own body raised and relabel it as a provider fault, which turns
    a bug in step 5 into a report that Robinhood misbehaved.

    Second, the handshake carries no `anyio.fail_after` scope. It is tempting
    to add one, and it does not work: `streamable_http_client` enters a task
    group that outlives the handshake, so a cancel scope opened around connect
    would have to be exited before a scope opened inside it, and anyio refuses
    the non-LIFO exit at runtime. The bound is applied where it actually
    belongs instead — `httpx2.Timeout(connect=...)` on the client, and
    `ClientSession(read_timeout_seconds=...)` on `initialize`.
    """
    limits = config.limits
    stack = AsyncExitStack()
    try:
        streams = await stack.enter_async_context(connector())
        read_stream, write_stream = streams
        session = await stack.enter_async_context(
            ClientSession(read_stream, write_stream, read_timeout_seconds=limits.read_timeout_s)
        )
        await session.initialize()
    except BaseException as exc:  # noqa: BLE001 - re-raised as a stable code
        await _close_quietly(stack)
        if isinstance(exc, GatewayError):
            raise
        raise _stable_error(exc, fault) from None

    try:
        yield _PrivateSession(session, limits, fault)
    finally:
        await _close_quietly(stack)


async def _close_quietly(stack: AsyncExitStack) -> None:
    """Tear the session down without letting teardown replace the outcome.

    A failure while closing is logged by *type name only* — never the message,
    which may quote a provider response (§8) — and then dropped. Two reasons:
    the read the caller made has already succeeded or failed on its own merits
    and must not be overwritten by a socket that closed badly, and an SDK
    exception escaping here would put an `mcp.*` type on the public surface
    that §4 forbids.
    """
    try:
        await stack.aclose()
    except GatewayError:
        raise
    except BaseException as exc:  # noqa: BLE001 - teardown must not mask the result
        _reraise_if_cancelled(exc)
        logger.debug("provider session teardown raised %s", type(exc).__name__)


# Every name here is SDK-neutral. The guarded transport, the egress policy and
# the client factory are private precisely because their signatures mention
# `httpx2` types, and §4 forbids that on a public one.
__all__ = [
    "PRODUCTION_EGRESS_HOSTS",
    "AccessTokenProvider",
    "PayloadSource",
    "ProviderTransport",
    "ToolPayload",
    "open_provider_session",
]
