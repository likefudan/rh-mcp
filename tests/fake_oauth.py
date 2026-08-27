"""A fake authorization server that never leaves the process (DESIGN.md §11).

Same shape as `tests/synthetic.py`, and for the same reason: the only thing
replaced is the socket. Every OAuth request in this suite goes through the real
`_GuardedAsyncTransport` — origin pinning, redirect rejection, the streaming
byte cap, the request-size bound — with an `httpx2.MockTransport` underneath.
A harness that called `auth.py`'s functions with hand-built dictionaries would
exercise the validation and quietly skip §3 entirely, which is most of what
makes this step safe.

The server is scriptable down to the raw response, because half of these tests
need an authorization server that is not merely unusual but hostile.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx2

from rh_mcp.config import GatewayConfig, ResourceLimits
from rh_mcp.transport import GuardedJsonClient, _new_json_client

DIGEST = "sha256:" + "a" * 64

DEV_ORIGIN = "http://127.0.0.1:9999"
DEV_RESOURCE = f"{DEV_ORIGIN}/mcp"

# A token value with a distinctive shape, so a redaction test can grep for it
# in logs, reprs, and exception text and be sure a hit is really this secret.
PLANTED_ACCESS_TOKEN = "planted-access-token-3f9c1d7e"
PLANTED_REFRESH_TOKEN = "planted-refresh-token-a1b2c3d4"
PLANTED_CODE = "planted-authorization-code-5e6f"
PLANTED_CLIENT_ID = "planted-client-id-77aa"


def development_config(**overrides: Any) -> GatewayConfig:
    limits = overrides.pop("limits", None)
    settings: dict[str, Any] = {
        "expected_manifest_digest": DIGEST,
        "mode": "development",
        "credential_adapter": "in_memory",
        "credential_namespace": "dev-rh-mcp",
        "dev_url": DEV_RESOURCE,
        "limits": ResourceLimits() if limits is None else limits,
    }
    settings.update(overrides)
    return GatewayConfig(**settings)


def production_config(**overrides: Any) -> GatewayConfig:
    settings: dict[str, Any] = {"expected_manifest_digest": DIGEST}
    settings.update(overrides)
    return GatewayConfig(**settings)


# --------------------------------------------------------------------------
# The documents
# --------------------------------------------------------------------------


def dev_resource_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "authorization_servers": [DEV_RESOURCE],
        "bearer_methods_supported": ["header"],
        "resource": DEV_RESOURCE,
        "scopes_supported": ["internal"],
    }
    document.update(overrides)
    return document


def dev_server_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "issuer": DEV_RESOURCE,
        "authorization_endpoint": f"{DEV_ORIGIN}/oauth",
        "token_endpoint": f"{DEV_ORIGIN}/oauth2/token/",
        "registration_endpoint": f"{DEV_ORIGIN}/oauth/register",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["internal"],
        "token_endpoint_auth_methods_supported": ["none"],
    }
    document.update(overrides)
    return document


def production_resource_document(**overrides: Any) -> dict[str, Any]:
    """Exactly the §5.0 transcription, so a test mutates one field at a time."""
    document: dict[str, Any] = {
        "authorization_servers": ["https://agent.robinhood.com/mcp/trading"],
        "bearer_methods_supported": ["header"],
        "resource": "https://agent.robinhood.com/mcp/trading",
        "scopes_supported": ["internal"],
    }
    document.update(overrides)
    return document


def production_server_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "issuer": "https://agent.robinhood.com/mcp/trading",
        "authorization_endpoint": "https://robinhood.com/oauth",
        "token_endpoint": "https://api.robinhood.com/oauth2/token/",
        "registration_endpoint": "https://agent.robinhood.com/oauth/trading/register",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["internal"],
        "token_endpoint_auth_methods_supported": ["none"],
    }
    document.update(overrides)
    return document


# --------------------------------------------------------------------------
# The server
# --------------------------------------------------------------------------

Route = Callable[[httpx2.Request], httpx2.Response]


class FakeAuthorizationServer:
    """Serves the two §5.0 documents, registration, and the token endpoint."""

    def __init__(
        self,
        *,
        resource_document: Mapping[str, Any] | None = None,
        server_document: Mapping[str, Any] | None = None,
        registration_response: Mapping[str, Any] | None = None,
        token_response: Mapping[str, Any] | None = None,
        production: bool = False,
        routes: Mapping[str, Route] | None = None,
    ) -> None:
        self.production = production
        self.resource_document = (
            (production_resource_document() if production else dev_resource_document())
            if resource_document is None
            else dict(resource_document)
        )
        self.server_document = (
            (production_server_document() if production else dev_server_document())
            if server_document is None
            else dict(server_document)
        )
        self.registration_response = (
            {"client_id": PLANTED_CLIENT_ID}
            if registration_response is None
            else dict(registration_response)
        )
        self.token_response = (
            {
                "access_token": PLANTED_ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": PLANTED_REFRESH_TOKEN,
                "scope": "internal",
            }
            if token_response is None
            else dict(token_response)
        )
        self.routes: dict[str, Route] = {} if routes is None else dict(routes)
        self.requests: list[httpx2.Request] = []
        self.paths: list[str] = []
        self.token_calls: list[dict[str, str]] = []
        self.registration_bodies: list[Any] = []
        self.token_status = 200
        self.registration_status = 200
        self.delay_s = 0.0

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = urlsplit(str(request.url)).path
        self.paths.append(path)
        if self.delay_s:
            await asyncio.sleep(self.delay_s)

        route = self.routes.get(path)
        if route is not None:
            response = route(request)
            response.request = request
            return response

        if path.endswith("/.well-known/oauth-protected-resource") or (
            "/.well-known/oauth-protected-resource" in path
        ):
            return _json(self.resource_document, request=request)
        if "/.well-known/oauth-authorization-server" in path:
            return _json(self.server_document, request=request)
        if path.endswith("/register"):
            self.registration_bodies.append(json.loads(request.content or b"{}"))
            return _json(
                self.registration_response, status=self.registration_status, request=request
            )
        if "token" in path:
            self.token_calls.append(dict(parse_qsl(request.content.decode("utf-8"))))
            return _json(self.token_response, status=self.token_status, request=request)
        return httpx2.Response(404, request=request, content=b"{}")


def _json(
    payload: Any, *, status: int = 200, request: httpx2.Request | None = None
) -> httpx2.Response:
    return httpx2.Response(
        status,
        request=request,
        headers={"content-type": "application/json"},
        content=json.dumps(payload).encode("utf-8"),
    )


def raw(body: bytes, *, status: int = 200, content_type: str = "application/json") -> Route:
    """A route that returns exactly these bytes."""

    def route(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, headers={"content-type": content_type}, content=body)

    return route


def status_only(status: int) -> Route:
    def route(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, content=b"{}")

    return route


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


@asynccontextmanager
async def open_client(
    server: FakeAuthorizationServer, config: GatewayConfig
) -> AsyncIterator[GuardedJsonClient]:
    """A real guarded JSON client whose only fake part is the socket."""
    client, json_client = _new_json_client(config, inner=httpx2.MockTransport(server))
    async with client:
        yield json_client


def client_factory(server: FakeAuthorizationServer, config: GatewayConfig) -> Callable[[], Any]:
    def factory() -> Any:
        return open_client(server, config)

    return factory


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def free_port() -> int:
    """An unused loopback port, for the two socket-level callback tests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


LOCK_HOLDER = """
import fcntl, sys, time
handle = open(sys.argv[1], "a+b")
fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(float(sys.argv[2]))
"""


@contextmanager
def another_process_holding(lock_path: Any) -> Any:
    """Hold an `flock` on `lock_path` from a real second process."""
    import subprocess
    import sys as _sys

    holder = subprocess.Popen(
        [_sys.executable, "-c", LOCK_HOLDER, str(lock_path), "10"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"
        yield holder
    finally:
        holder.kill()
        holder.wait()


def state_of(url: str) -> str:
    return parse_qs(urlsplit(url).query)["state"][0]


async def deliver_callback(
    authority: str, path: str, query: str, *, host_header: str | None = None
) -> bytes:
    """Send one raw HTTP GET to the callback listener and return the response."""
    host, _, port = authority.rpartition(":")
    reader, writer = await asyncio.open_connection(host.strip("[]"), int(port))
    target = f"{path}?{query}" if query else path
    request = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {authority if host_header is None else host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    writer.write(request)
    await writer.drain()
    body = await reader.read()
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:  # pragma: no cover - platform dependent
        pass
    return body
