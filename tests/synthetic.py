"""A synthetic MCP server that never leaves the process (DESIGN.md §11).

Every transport test drives the *real* MCP SDK client, the *real* Streamable
HTTP transport, and the *real* guarded `httpx2` transport from `transport.py`.
Only the bottom-most layer is replaced: instead of an `AsyncHTTPTransport` that
opens a socket, the client is given an `httpx2.MockTransport` whose handler is
the fake server below. No test opens a port, spawns a process, or resolves a
name.

The point of doing it this way rather than with in-memory streams is that the
guard *is* an `httpx2` transport. A harness that bypassed HTTP would exercise
the pagination and content-mapping logic while quietly skipping egress pinning,
redirect rejection, the streaming byte cap, and the `Authorization` header —
which is most of §3.

`SyntheticServer` is deliberately scriptable down to raw bytes. Half of these
tests need a provider that is not merely unusual but malformed, oversized, or
hostile, and a well-behaved server framework cannot produce those.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any

import httpx2

from rh_mcp.config import GatewayConfig, ResourceLimits
from rh_mcp.transport import _build_http_client, _Fault, _open_over_connector

PROTOCOL_VERSION = "2025-06-18"
SESSION_ID = "synthetic-session"

# Any digest of the right shape; the transport suite never loads a manifest.
DIGEST = "sha256:" + "a" * 64


def production_config(**limit_overrides: Any) -> GatewayConfig:
    return GatewayConfig(
        expected_manifest_digest=DIGEST, limits=ResourceLimits(**limit_overrides)
    )


def development_config(url: str = "http://127.0.0.1:9999/mcp", **limits: Any) -> GatewayConfig:
    return GatewayConfig(
        expected_manifest_digest=DIGEST,
        mode="development",
        credential_adapter="in_memory",
        credential_namespace="dev-rh-mcp",
        dev_url=url,
        limits=ResourceLimits(**limits),
    )


def tool(
    name: str = "synthetic_alpha_read",
    *,
    description: str | None = "Synthetic alpha read used only by the offline suite.",
    input_schema: Mapping[str, Any] | None = None,
    output_schema: Mapping[str, Any] | None = None,
    annotations: Mapping[str, Any] | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One raw `tools/list` entry, in wire form.

    Wire form matters: `inputSchema` is camelCase on the wire and snake_case in
    the SDK's models, and this suite is checking what arrives, not what a model
    would have made of it.
    """
    entry: dict[str, Any] = {
        "name": name,
        "inputSchema": (
            {"type": "object", "properties": {}} if input_schema is None else dict(input_schema)
        ),
    }
    if description is not None:
        entry["description"] = description
    if output_schema is not None:
        entry["outputSchema"] = dict(output_schema)
    if annotations is not None:
        entry["annotations"] = dict(annotations)
    if extra is not None:
        entry.update(extra)
    return entry


Handler = Callable[[str, Any, Any], Any]
"""`(method, params, request_id) -> result | httpx2.Response`."""


class SyntheticServer:
    """A scriptable MCP provider reachable only through `httpx2.MockTransport`."""

    def __init__(
        self,
        *,
        pages: Sequence[Mapping[str, Any]] | None = None,
        call_result: Mapping[str, Any] | None = None,
        handler: Handler | None = None,
        protocol_version: str = PROTOCOL_VERSION,
    ) -> None:
        self.pages = [dict(page) for page in (pages or [{"tools": [tool()]}])]
        # `content` is required by `CallToolResult`, and the SDK's own
        # protocol-conformance check runs before this package's §7.1 mapping.
        # A fixture that omits it tests the SDK, not the gateway, so every
        # result gets an empty list unless a test supplies one.
        resolved = (
            {"structuredContent": {"synthetic_value": 1}} if call_result is None else call_result
        )
        self.call_result: Mapping[str, Any] = {"content": [], **dict(resolved)}
        self.handler = handler
        self.protocol_version = protocol_version
        self.requests: list[httpx2.Request] = []
        self.methods: list[str] = []
        self.cursors: list[Any] = []
        self.call_count = 0
        self.in_flight = 0
        self.max_in_flight = 0
        self.delay_s = 0.0

    # -- the httpx2 handler ------------------------------------------------

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if request.method != "POST":
            return httpx2.Response(405, request=request)

        body = json.loads(request.content)
        method = body.get("method")
        params = body.get("params") or {}
        request_id = body.get("id")
        self.methods.append(method)

        if method == "initialize":
            return self._respond(
                request,
                request_id,
                {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "synthetic", "version": "0"},
                },
            )
        if request_id is None:
            return httpx2.Response(202, request=request)

        if self.handler is not None:
            outcome = self.handler(method, params, request_id)
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
            if isinstance(outcome, httpx2.Response):
                outcome.request = request
                return outcome
            return self._respond(request, request_id, outcome)

        if method == "tools/list":
            return self._respond(request, request_id, self._page(params.get("cursor")))
        if method == "tools/call":
            return await self._call(request, request_id)
        return httpx2.Response(
            200,
            request=request,
            headers={"content-type": "application/json"},
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "unsupported"},
                }
            ).encode(),
        )

    async def _call(self, request: httpx2.Request, request_id: Any) -> httpx2.Response:
        self.call_count += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay_s:
                await asyncio.sleep(self.delay_s)
            return self._respond(request, request_id, self.call_result)
        finally:
            self.in_flight -= 1

    def _page(self, cursor: Any) -> Mapping[str, Any]:
        """Serve the page a cursor names.

        A cursor that is not an index — the `"same"` a stuck server keeps
        handing back — serves page zero again, which is exactly the
        non-terminating behaviour §6.2 has to catch.
        """
        self.cursors.append(cursor)
        index = int(cursor) if isinstance(cursor, str) and cursor.isdigit() else 0
        return self.pages[min(index, len(self.pages) - 1)]

    def _respond(self, request: httpx2.Request, request_id: Any, result: Any) -> httpx2.Response:
        return httpx2.Response(
            200,
            request=request,
            headers={"content-type": "application/json", "mcp-session-id": SESSION_ID},
            content=json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}).encode(),
        )


def paged(*pages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build `tools/list` pages whose cursors are their own indices."""
    built: list[dict[str, Any]] = []
    for index, tools in enumerate(pages):
        page: dict[str, Any] = {"tools": [dict(entry) for entry in tools]}
        if index + 1 < len(pages):
            page["nextCursor"] = str(index + 1)
        built.append(page)
    return built


@asynccontextmanager
async def open_session(
    server: SyntheticServer | Callable[[httpx2.Request], Awaitable[httpx2.Response]],
    config: GatewayConfig | None = None,
) -> Any:
    """Open a real transport session whose only fake part is the socket.

    `_build_http_client` and `_open_over_connector` are the same functions
    `open_provider_session` uses, so the guard, the egress policy, the
    redirect rejection and the streaming cap are all live here.
    """
    from mcp.client.streamable_http import streamable_http_client

    resolved = production_config() if config is None else config
    fault = _Fault()
    client = _build_http_client(
        resolved, fault, None, inner=httpx2.MockTransport(server)
    )
    url = resolved.effective_resource_url
    assert url is not None

    async with client:
        async with _open_over_connector(
            lambda: streamable_http_client(url, http_client=client), resolved, fault
        ) as session:
            yield session


def mapper(**limits: Any) -> Any:
    """A `_PrivateSession` with no session behind it, for mapping-only tests.

    Some §7.1 rejections cannot be reached end-to-end: the SDK's own
    protocol-conformance check refuses a `structuredContent` that is not an
    object, or a content block with no `type`, before this package's mapping
    ever sees them. Those guards still have to exist and still have to be
    proved, because the SDK is a dependency rather than a security boundary and
    a version bump can loosen what it validates. `_map_result` is exercised
    directly for exactly those cases.
    """
    from typing import cast

    from rh_mcp.transport import _Fault, _PrivateSession

    return _PrivateSession(cast(Any, None), ResourceLimits(**limits), _Fault())


def deep_object(depth: int) -> dict[str, Any]:
    """A JSON object nested `depth` levels deep."""
    node: dict[str, Any] = {"leaf": 1}
    for _ in range(depth - 1):
        node = {"n": node}
    return node


def wide_object(nodes: int) -> dict[str, Any]:
    return {"items": [index for index in range(nodes)]}


def json_response(payload: Any, *, status: int = 200, **headers: str) -> httpx2.Response:
    merged = {"content-type": "application/json", "mcp-session-id": SESSION_ID}
    merged.update(headers)
    return httpx2.Response(status, headers=merged, content=json.dumps(payload).encode())


def iter_sizes(start: int, step: int, count: int) -> Iterator[int]:  # pragma: no cover - helper
    for index in range(count):
        yield start + index * step
