"""OAuth, dynamic client registration, and the loopback callback (§5, §3, §8).

The credential this module obtains is write-capable. Robinhood advertises one
scope, `internal`, so a token that reaches an attacker can trade (§2). Every
decision below is made from that starting point rather than from "it is only a
read gateway".

Five things are worth reading before the code.

**Production endpoints are pinned constants, and the live metadata document is
checked against them.** §5.0 transcribes what Robinhood currently advertises;
those values are reproduced here as expectations, not re-derived. A document
that names a different issuer, a different endpoint, a PKCE method other than
`S256`, or a token-endpoint auth method other than `none` is refused, because
each of those is a change in the security semantics of the flow and §13 says
an unexpected OAuth behaviour triggers design review rather than a permissive
fallback.

**The authorization endpoint is the one URL that does not go through the egress
guard.** It goes to the user's browser, which §3 puts outside the gateway
boundary. So the origin check on it happens *here*, before `webbrowser.open`,
and it is the only thing standing between a tampered metadata document and a
user typing Robinhood credentials into an attacker's page. `_check_endpoint`
is therefore applied to all four endpoints uniformly, including the two the
guard would have caught anyway.

**Refresh never fetches metadata in production.** It uses the pinned token
endpoint directly. Re-fetching a provider-controlled document on the path that
exchanges a long-lived refresh token would add an input to the most sensitive
request in the system for no benefit — the pinned value is the reviewed one,
and a legitimate change to it requires a release either way.

**Every read path is non-interactive.** `StoredTokenProvider` performs at most
one coordinated refresh, single-flight in-process and serialized across
processes by the store's `exclusive()`. It cannot open a browser: no function
it calls imports one. `login()` is the only caller of `webbrowser.open` in the
package, and a test asserts a read path never reaches it.

**Nothing here is printed.** Codes, verifiers, states, tokens, registration
responses, and the raw callback query never enter a log record, an exception
message, or a return value. The callback listener is hand-written rather than
built on `http.server` for exactly this reason: `BaseHTTPRequestHandler`
logs the request line — including `?code=...` — to stderr by default, which is
the leak §5.1 names.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import secrets
import time
import webbrowser
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Final, NoReturn
from urllib.parse import parse_qsl, urlencode, urlsplit

from rh_mcp.config import PRODUCTION_RESOURCE_URL, GatewayConfig
from rh_mcp.credentials import ClientRegistration, CredentialStore, TokenCredential
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.transport import (
    PRODUCTION_EGRESS_HOSTS,
    GuardedJsonClient,
    HttpJsonResponse,
    open_json_client,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# The reviewed §5.0 expectations
# --------------------------------------------------------------------------

PRODUCTION_ISSUER: Final[str] = PRODUCTION_RESOURCE_URL
PRODUCTION_AUTHORIZATION_ENDPOINT: Final[str] = "https://robinhood.com/oauth"
PRODUCTION_TOKEN_ENDPOINT: Final[str] = "https://api.robinhood.com/oauth2/token/"
PRODUCTION_REGISTRATION_ENDPOINT: Final[str] = (
    "https://agent.robinhood.com/oauth/trading/register"
)

PRODUCTION_AUTHORIZATION_SERVERS: Final[frozenset[str]] = frozenset({PRODUCTION_ISSUER})
PRODUCTION_BEARER_METHODS: Final[frozenset[str]] = frozenset({"header"})
PRODUCTION_GRANT_TYPES: Final[frozenset[str]] = frozenset({"authorization_code", "refresh_token"})
PRODUCTION_RESPONSE_TYPES: Final[frozenset[str]] = frozenset({"code"})
PRODUCTION_CODE_CHALLENGE_METHODS: Final[frozenset[str]] = frozenset({"S256"})
PRODUCTION_SCOPES: Final[frozenset[str]] = frozenset({"internal"})
PRODUCTION_TOKEN_ENDPOINT_AUTH_METHODS: Final[frozenset[str]] = frozenset({"none"})

# §5.1 leaves open whether Robinhood requires no explicit scope or `internal`,
# and §13 makes settling it an owner-assisted observation. `internal` is the
# only advertised value, so it is what the first login asks for; the *granted*
# scope is recorded from the token response either way.
DEFAULT_SCOPE: Final[str] = "internal"

# The only PKCE method this gateway will use. `plain` is not a fallback: a
# downgrade to it is exactly the attack PKCE exists to stop.
PKCE_METHOD: Final[str] = "S256"

CLIENT_NAME: Final[str] = "rh-mcp read gateway"

# §8 bounds on values the authorization server controls.
MAX_CODE_CHARS: Final[int] = 2_048
MAX_ENDPOINT_CHARS: Final[int] = 2_048
MAX_SCOPE_CHARS: Final[int] = 512
MAX_EXPIRES_IN_S: Final[int] = 315_360_000  # ten years; anything larger is nonsense

# Callback listener bounds. A login waits up to `oauth_callback_timeout_s` for
# a browser; without these, that window is also an unbounded invitation.
_MAX_REQUEST_LINE_BYTES: Final[int] = 8_192
_MAX_HEADER_LINES: Final[int] = 64
_MAX_STRAY_REQUESTS: Final[int] = 16
_REQUEST_READ_TIMEOUT_S: Final[float] = 10.0

_CALLBACK_PAGE: Final[bytes] = (
    b"<!doctype html><html><head><title>rh-mcp</title></head><body>"
    b"<h1>Authorization received</h1>"
    b"<p>You can close this window and return to the terminal.</p>"
    b"</body></html>"
)

# The one loopback host set a callback may bind. `GatewayConfig` already
# refuses anything else; this is the assertion that the listener itself never
# binds a wildcard interface (§5.1).
_LOOPBACK_BIND_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1"})

Clock = Callable[[], float]
BrowserOpener = Callable[[str], bool]
ClientFactory = Callable[[], AbstractAsyncContextManager[GuardedJsonClient]]


def _fail(code: ErrorCode, message: str, *, retryable: bool = False) -> NoReturn:
    raise GatewayError(code, message, retryable=retryable)


def _auth_required(reason: str) -> NoReturn:
    """The one place `auth_required` is raised, so the advice is consistent."""
    _fail(ErrorCode.AUTH_REQUIRED, f"{reason}; run `rh-mcp login`")


# --------------------------------------------------------------------------
# Metadata (§5.0)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationServerMetadata:
    """The validated authorization-server document (§5.0).

    SDK-neutral and immutable. Only the fields §5.0 transcribes are modelled:
    an unmodelled field cannot influence the flow, so carrying it would only
    create somewhere for provider data to hide.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str
    grant_types_supported: frozenset[str]
    response_types_supported: frozenset[str]
    code_challenge_methods_supported: frozenset[str]
    scopes_supported: frozenset[str]
    token_endpoint_auth_methods_supported: frozenset[str]


def _string_field(document: Mapping[str, Any], name: str, *, limit: int) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"the OAuth metadata field {name!r} is missing")
    if len(value) > limit:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"the OAuth metadata field {name!r} is too long")
    if any(character.isspace() or ord(character) < 0x20 for character in value):
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"the OAuth metadata field {name!r} contains whitespace or control characters",
        )
    return value


def _string_set_field(document: Mapping[str, Any], name: str) -> frozenset[str]:
    value = document.get(name)
    if not isinstance(value, (list, tuple)) or not value:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"the OAuth metadata field {name!r} must be a non-empty array",
        )
    if len(value) > 64:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"the OAuth metadata field {name!r} is too long")
    entries: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item or len(item) > MAX_SCOPE_CHARS:
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                f"the OAuth metadata field {name!r} must contain non-empty strings",
            )
        entries.add(item)
    return frozenset(entries)


def _origin_of(url: str) -> tuple[str, str, int] | None:
    """`(scheme, host, port)` for a URL, or None if it is not usable as one."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    host = parsed.hostname
    if host is None:
        return None
    if parsed.username is not None or parsed.password is not None:
        # Userinfo in an endpoint is refused for the same reason `transport.py`
        # refuses it on egress: it becomes a competing credential.
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return scheme, host.lower(), port or (443 if scheme == "https" else 80)


def allowed_endpoint_origins(config: GatewayConfig) -> frozenset[tuple[str, str, int]]:
    """Origins an OAuth endpoint may name, for this deployment (§3).

    In production this is §3's three hosts on HTTPS/443 and nothing else. In
    development it is the single loopback origin `dev_url` names — the same
    pinning `transport.py` applies to egress, restated here because the
    *authorization* endpoint never reaches that guard: it is handed to a
    browser, and a browser is outside the boundary.
    """
    if config.mode == "production":
        # Taken from `transport.py`'s constant rather than restated. Two copies
        # of "the hosts this gateway may contact" is exactly the divergence
        # that turns a fail-closed check into a fail-open one when only one of
        # them is updated.
        return frozenset(("https", host, 443) for host in PRODUCTION_EGRESS_HOSTS)
    url = config.dev_url
    if url is None:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "an OAuth flow needs an HTTP development target, not a stdio one",
        )
    origin = _origin_of(url)
    if origin is None:  # pragma: no cover - GatewayConfig already validated it
        _fail(ErrorCode.CONFIGURATION_ERROR, "the development URL is not a usable origin")
    return frozenset({origin})


def _check_endpoint(name: str, url: str, config: GatewayConfig) -> None:
    origin = _origin_of(url)
    if origin is None:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"the OAuth {name} is not a usable http(s) URL")
    if config.mode == "production" and origin[0] != "https":
        _fail(ErrorCode.CONFIGURATION_ERROR, f"the OAuth {name} must use https in production")
    if origin not in allowed_endpoint_origins(config):
        # The host and port are named because they are the actionable part and
        # neither is a secret; the full URL is not, because §7.3 keeps a URL
        # with a query out of a public error and a metadata document is
        # provider-controlled text.
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"the OAuth {name} points at {origin[1]}:{origin[2]}, which is outside this "
            "deployment's allowed origins",
        )


def _expect(name: str, observed: object, expected: object) -> None:
    if observed != expected:
        # The observed value is deliberately not echoed: it is provider text,
        # and the reviewed expectation is the useful half of the comparison.
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"the authorization server's {name} does not match the reviewed value "
            f"in DESIGN.md §5.0; an intentional provider change requires a reviewed release",
        )


def parse_authorization_server_metadata(
    document: Mapping[str, Any], config: GatewayConfig
) -> AuthorizationServerMetadata:
    """Validate an authorization-server document (§5.0).

    Two layers, and both matter. *Structural* rules hold in every mode: PKCE
    must offer `S256`, the response type must include `code`, the grant types
    must include `authorization_code`, the token endpoint must accept `none`,
    and every endpoint must sit on an origin this deployment allows. *Pinned*
    rules hold in production only, where each §5.0 value is compared exactly.

    Set comparison is exact — no extra members. A document that adds `plain` to
    `code_challenge_methods_supported` or `client_secret_post` to
    `token_endpoint_auth_methods_supported` has changed the security semantics
    of the flow even though it still contains the reviewed value, so equality
    rather than membership is the right test.

    Fields §5.0 does not transcribe are ignored. They cannot reach the flow,
    because nothing below reads them.
    """
    metadata = AuthorizationServerMetadata(
        issuer=_string_field(document, "issuer", limit=MAX_ENDPOINT_CHARS),
        authorization_endpoint=_string_field(
            document, "authorization_endpoint", limit=MAX_ENDPOINT_CHARS
        ),
        token_endpoint=_string_field(document, "token_endpoint", limit=MAX_ENDPOINT_CHARS),
        registration_endpoint=_string_field(
            document, "registration_endpoint", limit=MAX_ENDPOINT_CHARS
        ),
        grant_types_supported=_string_set_field(document, "grant_types_supported"),
        response_types_supported=_string_set_field(document, "response_types_supported"),
        code_challenge_methods_supported=_string_set_field(
            document, "code_challenge_methods_supported"
        ),
        scopes_supported=_string_set_field(document, "scopes_supported"),
        token_endpoint_auth_methods_supported=_string_set_field(
            document, "token_endpoint_auth_methods_supported"
        ),
    )

    for name, endpoint in (
        ("authorization_endpoint", metadata.authorization_endpoint),
        ("token_endpoint", metadata.token_endpoint),
        ("registration_endpoint", metadata.registration_endpoint),
    ):
        _check_endpoint(name, endpoint, config)

    if PKCE_METHOD not in metadata.code_challenge_methods_supported:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the authorization server does not advertise PKCE S256; this gateway will not "
            "fall back to a weaker code challenge",
        )
    if "code" not in metadata.response_types_supported:
        _fail(ErrorCode.CONFIGURATION_ERROR, "the authorization server does not support 'code'")
    if "authorization_code" not in metadata.grant_types_supported:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the authorization server does not support the authorization_code grant",
        )
    if "none" not in metadata.token_endpoint_auth_methods_supported:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the authorization server does not accept a public client at its token endpoint",
        )

    if config.mode == "production":
        _expect("issuer", metadata.issuer, PRODUCTION_ISSUER)
        _expect(
            "authorization_endpoint",
            metadata.authorization_endpoint,
            PRODUCTION_AUTHORIZATION_ENDPOINT,
        )
        _expect("token_endpoint", metadata.token_endpoint, PRODUCTION_TOKEN_ENDPOINT)
        _expect(
            "registration_endpoint",
            metadata.registration_endpoint,
            PRODUCTION_REGISTRATION_ENDPOINT,
        )
        _expect("grant_types_supported", metadata.grant_types_supported, PRODUCTION_GRANT_TYPES)
        _expect(
            "response_types_supported",
            metadata.response_types_supported,
            PRODUCTION_RESPONSE_TYPES,
        )
        _expect(
            "code_challenge_methods_supported",
            metadata.code_challenge_methods_supported,
            PRODUCTION_CODE_CHALLENGE_METHODS,
        )
        _expect("scopes_supported", metadata.scopes_supported, PRODUCTION_SCOPES)
        _expect(
            "token_endpoint_auth_methods_supported",
            metadata.token_endpoint_auth_methods_supported,
            PRODUCTION_TOKEN_ENDPOINT_AUTH_METHODS,
        )
    return metadata


def parse_protected_resource_metadata(
    document: Mapping[str, Any], config: GatewayConfig
) -> str:
    """Validate the protected-resource document and return its issuer (§5.0).

    RFC 9728 allows several authorization servers; this gateway accepts exactly
    one, because "which of these did we just send a user to" is not a question
    a default-deny design should have to answer at runtime.
    """
    resource = _string_field(document, "resource", limit=MAX_ENDPOINT_CHARS)
    servers = _string_set_field(document, "authorization_servers")
    bearer_methods = _string_set_field(document, "bearer_methods_supported")
    scopes = _string_set_field(document, "scopes_supported")

    if len(servers) != 1:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the protected-resource document names more than one authorization server",
        )
    issuer = next(iter(servers))
    _check_endpoint("authorization server", issuer, config)

    if "header" not in bearer_methods:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the resource does not accept a bearer token in the Authorization header",
        )

    if config.mode == "production":
        _expect("resource", resource, PRODUCTION_RESOURCE_URL)
        _expect("authorization_servers", servers, PRODUCTION_AUTHORIZATION_SERVERS)
        _expect("bearer_methods_supported", bearer_methods, PRODUCTION_BEARER_METHODS)
        _expect("scopes_supported", scopes, PRODUCTION_SCOPES)
    else:
        expected_resource = config.effective_resource_url
        if expected_resource is not None:
            _expect("resource", resource, expected_resource)
    return issuer


def protected_resource_metadata_urls(resource: str) -> tuple[str, ...]:
    """RFC 9728 §3.1: insert the well-known segment before the resource path."""
    return (_well_known(resource, "oauth-protected-resource"),)


def authorization_server_metadata_urls(issuer: str) -> tuple[str, ...]:
    """The two well-known forms an issuer with a path may use.

    RFC 8414 §3.1 inserts the well-known segment before the issuer path; the
    MCP authorization specification also permits appending it to the path.
    Both are tried, in that order, because a single wrong guess makes login
    impossible and neither candidate weakens anything: both are checked against
    the same pinned origins, and whichever document comes back is validated by
    the same `parse_authorization_server_metadata`.

    A candidate that returns a document which then *fails* validation is fatal;
    the next candidate is not tried. Otherwise a provider could serve a
    tampered document at the first URL and a valid one at the second, and the
    flow would quietly prefer whichever one it could make work.
    """
    split = urlsplit(issuer)
    appended = f"{split.scheme}://{split.netloc}{split.path.rstrip('/')}" + (
        "/.well-known/oauth-authorization-server"
    )
    return (_well_known(issuer, "oauth-authorization-server"), appended)


def _well_known(url: str, segment: str) -> str:
    split = urlsplit(url)
    path = split.path.rstrip("/")
    return f"{split.scheme}://{split.netloc}/.well-known/{segment}{path}"


async def _fetch_document(
    client: GuardedJsonClient, urls: Sequence[str], *, label: str
) -> Mapping[str, Any]:
    last_status: int | None = None
    for url in urls:
        response = await client.get_json(url)
        if 200 <= response.status_code < 300 and response.payload is not None:
            return response.payload
        last_status = response.status_code
    _fail(
        ErrorCode.CONFIGURATION_ERROR,
        f"the {label} document could not be read (last status {last_status})",
    )


async def discover_metadata(
    client: GuardedJsonClient, config: GatewayConfig
) -> AuthorizationServerMetadata:
    """Fetch and validate both §5.0 documents.

    The protected-resource document is read first and its single authorization
    server becomes the issuer; the authorization-server document must then
    declare that exact issuer. Chaining them this way is what makes a swapped
    document detectable rather than merely different.
    """
    resource = config.effective_resource_url
    if resource is None:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "an OAuth flow needs an HTTP resource URL, not a stdio development target",
        )
    resource_document = await _fetch_document(
        client, protected_resource_metadata_urls(resource), label="protected-resource"
    )
    issuer = parse_protected_resource_metadata(resource_document, config)

    server_document = await _fetch_document(
        client, authorization_server_metadata_urls(issuer), label="authorization-server"
    )
    metadata = parse_authorization_server_metadata(server_document, config)
    if metadata.issuer != issuer:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the authorization-server document declares a different issuer than the "
            "protected-resource document named",
        )
    return metadata


async def verify_discovery_metadata(
    config: GatewayConfig, *, client_factory: ClientFactory | None = None
) -> AuthorizationServerMetadata:
    """§5.0's production startup check, as a standalone call for step 5."""
    factory = _default_client_factory(config) if client_factory is None else client_factory
    async with factory() as client:
        return await discover_metadata(client, config)


def _default_client_factory(config: GatewayConfig) -> ClientFactory:
    def factory() -> AbstractAsyncContextManager[GuardedJsonClient]:
        return open_json_client(config)

    return factory


# --------------------------------------------------------------------------
# PKCE and the authorization transaction (§5.1)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationTransaction:
    """The expected transaction a callback is validated against (§5.1).

    Held only in memory, for the lifetime of one `login()`. `state` and
    `code_verifier` are secrets — a leaked verifier turns an intercepted code
    into a token — so `__repr__` redacts both, the same way `TokenCredential`
    does.
    """

    state: str
    code_verifier: str
    code_challenge: str
    redirect_uri: str
    issuer: str
    client_id: str
    created_at: float

    def __repr__(self) -> str:
        return (
            "AuthorizationTransaction(state=<redacted>, code_verifier=<redacted>, "
            f"redirect_uri={self.redirect_uri!r}, issuer={self.issuer!r}, "
            "client_id=<redacted>)"
        )

    __str__ = __repr__


def new_code_verifier() -> str:
    """A PKCE verifier from the CSPRNG.

    `token_urlsafe(64)` yields 86 unreserved characters, inside RFC 7636's
    43-128 range with a wide margin. `secrets`, not `random`: this value is the
    only thing binding an authorization code to this process.
    """
    return secrets.token_urlsafe(64)


def code_challenge_for(verifier: str) -> str:
    """base64url(SHA-256(verifier)), unpadded — RFC 7636 S256."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def new_state() -> str:
    return secrets.token_urlsafe(32)


def callback_redirect_uri(config: GatewayConfig) -> str:
    """The exact redirect URI this deployment registers and listens on (§5.1)."""
    return f"http://{callback_authority(config)}{config.callback_path}"


def callback_authority(config: GatewayConfig) -> str:
    host = config.callback_host
    literal = f"[{host}]" if ":" in host else host
    return f"{literal}:{config.callback_port}"


def build_authorization_url(
    metadata: AuthorizationServerMetadata,
    transaction: AuthorizationTransaction,
    *,
    scope: str | None,
) -> str:
    """Assemble the URL the browser opens. Never logged (§5.1)."""
    parameters: dict[str, str] = {
        "response_type": "code",
        "client_id": transaction.client_id,
        "redirect_uri": transaction.redirect_uri,
        "state": transaction.state,
        "code_challenge": transaction.code_challenge,
        "code_challenge_method": PKCE_METHOD,
    }
    if scope is not None:
        parameters["scope"] = scope
    separator = "&" if urlsplit(metadata.authorization_endpoint).query else "?"
    return f"{metadata.authorization_endpoint}{separator}{urlencode(parameters)}"


# --------------------------------------------------------------------------
# The loopback callback listener (§5.1)
# --------------------------------------------------------------------------


class _CallbackListener:
    """Accepts exactly one valid authorization code, then stops.

    The validation order is the security order: path, then `Host`, then the
    query's shape, then `state`, then `iss`, then the code itself. A request
    that fails any of the *authorization-transaction* checks — a wrong `state`,
    a wrong issuer, a duplicated parameter, a `Host` that is not the registered
    redirect authority — aborts the whole login rather than being ignored.
    That is the deliberate choice: those failures mean something is delivering
    to this callback that is not the browser we sent, and continuing to wait
    would hand the next attempt to whoever is already interfering.

    A request to a *different* path is merely stray — a favicon fetch, a probe
    — and is answered 404 without ending the login, up to a bounded count.
    """

    def __init__(
        self, transaction: AuthorizationTransaction, *, path: str, authority: str
    ) -> None:
        self._transaction = transaction
        self._path = path
        self._authority = authority.lower()
        self._future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self._strays = 0

    @property
    def future(self) -> asyncio.Future[str]:
        return self._future

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._handle(reader, writer)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            # A malformed or abandoned connection is not evidence of an attack
            # and must not end a login. Nothing about it is logged: the only
            # interesting content is the request line, which may carry a code.
            await _close(writer)
        except GatewayError as error:
            self._abort(error)
            await _close(writer)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request_line = await asyncio.wait_for(
            reader.readuntil(b"\r\n"), timeout=_REQUEST_READ_TIMEOUT_S
        )
        if len(request_line) > _MAX_REQUEST_LINE_BYTES:
            await self._respond(writer, 431, b"")
            return
        headers = await self._read_headers(reader)

        parts = request_line.decode("latin-1").strip().split(" ")
        if len(parts) != 3:
            await self._respond(writer, 400, b"")
            return
        method, target, _version = parts

        path, _, query = target.partition("?")
        if path != self._path:
            # Stray traffic. Bounded, because the listener is open for as long
            # as a human takes to log in.
            self._strays += 1
            if self._strays > _MAX_STRAY_REQUESTS:
                await self._respond(writer, 404, b"")
                _fail(
                    ErrorCode.TIMEOUT,
                    "the login callback received too many unrelated requests and stopped",
                )
            await self._respond(writer, 404, b"")
            return
        if method != "GET":
            # The exact callback path, but not a browser redirect.
            await self._respond(writer, 405, b"")
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                "the login callback received a non-GET request on the callback path",
            )

        self._check_host(headers)
        code = self._validate_query(query)

        if self._future.done():  # pragma: no cover - the server closes first
            await self._respond(writer, 409, b"")
            return
        await self._respond(writer, 200, _CALLBACK_PAGE)
        self._future.set_result(code)

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict[str, str]:
        headers: dict[str, str] = {}
        for _ in range(_MAX_HEADER_LINES):
            line = await asyncio.wait_for(
                reader.readuntil(b"\r\n"), timeout=_REQUEST_READ_TIMEOUT_S
            )
            if line in (b"\r\n", b"\n"):
                return headers
            name, separator, value = line.decode("latin-1").partition(":")
            if separator:
                headers.setdefault(name.strip().lower(), value.strip())
        _fail(ErrorCode.PROTOCOL_ERROR, "the login callback received too many request headers")

    def _check_host(self, headers: Mapping[str, str]) -> None:
        """The `Host` must be the registered redirect authority (§5.1).

        A request that reaches this listener under some other name resolved to
        loopback — the classic DNS-rebinding shape — is refused. The value is
        not echoed; a `Host` header is attacker-chosen text.
        """
        host = headers.get("host", "").lower()
        if host != self._authority:
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                "the login callback was delivered under a host that is not the registered "
                "redirect URI's authority",
            )

    def _validate_query(self, query: str) -> str:
        """Validate the callback query and return the code. Never echoes it."""
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
        seen: dict[str, str] = {}
        for key, value in pairs:
            if key in seen:
                # Two spellings of the same parameter is not a browser doing
                # its job; it is someone hoping this reads the other one.
                _fail(
                    ErrorCode.PROTOCOL_ERROR,
                    "the login callback query names the same parameter twice",
                )
            seen[key] = value

        if "error" in seen:
            # `error` and `error_description` are provider-controlled text and
            # are not repeated (§7.3).
            _auth_required("the authorization server refused the login request")

        state = seen.get("state")
        if not isinstance(state, str) or not secrets.compare_digest(
            state, self._transaction.state
        ):
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                "the login callback carried a state that does not match this authorization "
                "request",
            )

        issuer = seen.get("iss")
        if issuer is not None and issuer != self._transaction.issuer:
            # RFC 9207. Present only if the server sends it; wrong is fatal.
            _fail(
                ErrorCode.PROTOCOL_ERROR,
                "the login callback named a different issuer than the one authorized",
            )

        code = seen.get("code")
        if not isinstance(code, str) or not code:
            _fail(ErrorCode.PROTOCOL_ERROR, "the login callback carried no authorization code")
        if len(code) > MAX_CODE_CHARS:
            _fail(ErrorCode.PROTOCOL_ERROR, "the login callback's authorization code is too long")
        for character in code:
            if character < "\x21" or character > "\x7e":
                _fail(
                    ErrorCode.PROTOCOL_ERROR,
                    "the login callback's authorization code contains unusable characters",
                )
        return code

    def _abort(self, error: GatewayError) -> None:
        if not self._future.done():
            self._future.set_exception(error)

    async def _respond(self, writer: asyncio.StreamWriter, status: int, body: bytes) -> None:
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
                  409: "Conflict", 431: "Request Header Fields Too Large"}.get(status, "Error")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Referrer-Policy: no-referrer\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(head + body)
        try:
            await writer.drain()
        except OSError:  # pragma: no cover - the browser may have gone away
            pass
        await _close(writer)


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, RuntimeError):  # pragma: no cover - already gone
        pass


@asynccontextmanager
async def _callback_listener(
    config: GatewayConfig, transaction: AuthorizationTransaction
) -> AsyncIterator[asyncio.Future[str]]:
    """Bind the loopback callback, yield its result, and always close it (§5.1).

    Bound *before* the browser opens, so there is no window in which the
    authorization server can redirect to a port nothing is listening on — and
    no temptation to retry the bind afterwards.
    """
    if config.callback_host not in _LOOPBACK_BIND_HOSTS:
        # `GatewayConfig` refuses anything else, and this is the assertion that
        # the socket itself never binds `0.0.0.0` or `::`. Passing `None` as a
        # host to `start_server` binds every interface, which would put an
        # authorization code on the network.
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the OAuth callback may bind only an explicit loopback address",
        )
    listener = _CallbackListener(
        transaction, path=config.callback_path, authority=callback_authority(config)
    )
    server = await asyncio.start_server(
        listener.handle,
        host=config.callback_host,
        port=config.callback_port,
        limit=_MAX_REQUEST_LINE_BYTES,
    )
    try:
        yield listener.future
    finally:
        server.close()
        try:
            await server.wait_closed()
        except (OSError, RuntimeError):  # pragma: no cover - platform dependent
            pass


async def await_authorization_code(
    config: GatewayConfig, future: asyncio.Future[str]
) -> str:
    """Wait out the §8 callback budget for exactly one code."""
    try:
        return await asyncio.wait_for(future, timeout=config.limits.oauth_callback_timeout_s)
    except TimeoutError:
        _fail(
            ErrorCode.TIMEOUT,
            "the login callback was not completed within "
            f"{config.limits.oauth_callback_timeout_s} seconds",
        )


# --------------------------------------------------------------------------
# Registration and token exchange (§5.1)
# --------------------------------------------------------------------------


async def register_client(
    client: GuardedJsonClient,
    metadata: AuthorizationServerMetadata,
    *,
    redirect_uri: str,
    scope: str | None,
    now: float,
) -> ClientRegistration:
    """Dynamic client registration for a public, loopback-redirect client.

    A returned `client_secret` is refused rather than stored. §5.0 pins
    `token_endpoint_auth_methods_supported` to `["none"]`, so a secret means
    the authorization server has decided this is a confidential client — a
    different flow with different storage obligations. §13 says unexpected
    OAuth behaviour triggers design review, not a fallback, and accepting a
    secret silently is precisely the fallback it warns about.
    """
    body: dict[str, Any] = {
        "client_name": CLIENT_NAME,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    }
    if scope is not None:
        body["scope"] = scope

    response = await client.post_json(metadata.registration_endpoint, body)
    payload = _require_payload(response, "client registration")

    if payload.get("client_secret") is not None:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the authorization server issued a client secret, which contradicts the reviewed "
            "public-client registration in DESIGN.md §5.0; this needs design review",
        )

    echoed = payload.get("redirect_uris")
    if echoed is not None:
        if not isinstance(echoed, (list, tuple)) or list(echoed) != [redirect_uri]:
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "the authorization server registered a different redirect URI than the one "
                "requested",
            )

    client_id = payload.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        _fail(ErrorCode.CONFIGURATION_ERROR, "the registration response carried no client_id")

    expires_at = payload.get("client_id_expires_at")
    if expires_at is not None and (
        isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))
    ):
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the registration response carried a malformed client_id_expires_at",
        )

    return ClientRegistration(
        client_id=client_id,
        issuer=metadata.issuer,
        redirect_uri=redirect_uri,
        registered_at=now,
        client_id_expires_at=None if expires_at is None else float(expires_at),
    )


def _require_payload(response: HttpJsonResponse, label: str) -> Mapping[str, Any]:
    if response.status_code in (401, 403):
        _auth_required(f"the authorization server rejected the {label} request")
    if not (200 <= response.status_code < 300) or response.payload is None:
        # The status is safe telemetry; the body is not — a token endpoint's
        # error body has been seen to echo request parameters (§7.3, §8).
        _fail(
            ErrorCode.PROVIDER_ERROR,
            f"the {label} request failed with HTTP {response.status_code}",
            retryable=500 <= response.status_code < 600,
        )
    return response.payload


async def exchange_code(
    client: GuardedJsonClient,
    metadata: AuthorizationServerMetadata,
    transaction: AuthorizationTransaction,
    code: str,
    *,
    now: float,
) -> TokenCredential:
    """Exchange one authorization code for a token, with the PKCE verifier."""
    response = await client.post_form(
        metadata.token_endpoint,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": transaction.redirect_uri,
            "client_id": transaction.client_id,
            "code_verifier": transaction.code_verifier,
        },
    )
    if response.status_code == 400:
        # The canonical `invalid_grant`: a replayed, expired, or mismatched
        # code. The body says which, and the body is not repeated.
        _auth_required("the authorization server rejected the authorization code")
    payload = _require_payload(response, "token")
    return _token_from_payload(payload, issuer=metadata.issuer, now=now)


async def refresh_access_token(
    client: GuardedJsonClient,
    token_endpoint: str,
    token: TokenCredential,
    *,
    client_id: str,
    issuer: str,
    now: float,
) -> TokenCredential:
    """Spend a refresh token for a new access token.

    Rotation is handled by `_token_from_payload`: when the response carries no
    new `refresh_token`, the existing one is carried forward, and when it does,
    the old one is dropped. Getting that backwards either discards a still-valid
    refresh token or keeps using a rotated-out one, and both end in a login
    prompt at the worst moment.
    """
    if token.refresh_token is None:
        _auth_required("the stored credential has expired and carries no refresh token")
    response = await client.post_form(
        token_endpoint,
        {
            "grant_type": "refresh_token",
            "refresh_token": token.refresh_token,
            "client_id": client_id,
        },
    )
    if response.status_code in (400, 401, 403):
        _auth_required("the authorization server rejected the refresh token")
    payload = _require_payload(response, "token refresh")
    return _token_from_payload(payload, issuer=issuer, now=now, previous=token)


def _token_from_payload(
    payload: Mapping[str, Any],
    *,
    issuer: str,
    now: float,
    previous: TokenCredential | None = None,
) -> TokenCredential:
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        _fail(ErrorCode.PROTOCOL_ERROR, "the token response carried no access_token")

    token_type = payload.get("token_type")
    if token_type is None:
        # RFC 6749 requires it; some servers omit it. Assuming Bearer is safe
        # because that is the only thing this gateway can present anyway, and
        # `TokenCredential` refuses to store anything else.
        token_type = "Bearer"
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        _fail(
            ErrorCode.PROTOCOL_ERROR,
            "the token response is not a Bearer token, which this gateway cannot present",
        )

    expires_at: float | None = None
    expires_in = payload.get("expires_in")
    if expires_in is not None:
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
            _fail(ErrorCode.PROTOCOL_ERROR, "the token response carried a malformed expires_in")
        if not (0 < float(expires_in) <= MAX_EXPIRES_IN_S):
            _fail(ErrorCode.PROTOCOL_ERROR, "the token response carried an implausible expires_in")
        expires_at = now + float(expires_in)

    refresh_token = payload.get("refresh_token")
    if refresh_token is not None and (not isinstance(refresh_token, str) or not refresh_token):
        _fail(ErrorCode.PROTOCOL_ERROR, "the token response carried a malformed refresh_token")
    if refresh_token is None and previous is not None:
        refresh_token = previous.refresh_token

    scope = payload.get("scope")
    if scope is not None:
        if not isinstance(scope, str) or len(scope) > MAX_SCOPE_CHARS:
            _fail(ErrorCode.PROTOCOL_ERROR, "the token response carried a malformed scope")
    elif previous is not None:
        scope = previous.granted_scope

    return TokenCredential(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        granted_scope=scope,
        token_type="Bearer",
        issuer=issuer,
        obtained_at=now,
    )


# --------------------------------------------------------------------------
# The non-interactive access token provider (§5.1, §5.2, §8)
# --------------------------------------------------------------------------


class StoredTokenProvider:
    """`AccessTokenProvider` over a credential store. Never opens a browser.

    Refresh discipline, in the order it happens:

    1. A fast path reads the store and returns a token that is not near expiry.
    2. Otherwise an in-process `asyncio.Lock` makes the refresh single-flight:
       ten concurrent reads produce one refresh, not ten.
    3. Inside that, the store's `exclusive()` serializes against other
       processes sharing the same credential.
    4. The token is re-read *after* both locks are held, because the process
       that held them before this one may already have refreshed — in which
       case a second refresh would spend a refresh token that has just been
       rotated out, and lose the new one.
    5. At most `limits.max_refresh_attempts` HTTP attempts happen (§8 caps that
       at 1). A failure raises `auth_required`; it never loops and never
       prompts.
    """

    def __init__(
        self,
        config: GatewayConfig,
        store: CredentialStore,
        *,
        client_factory: ClientFactory | None = None,
        clock: Clock = time.time,
        expiry_skew_s: float = 60.0,
    ) -> None:
        self._config = config
        self._store = store
        self._client_factory = (
            _default_client_factory(config) if client_factory is None else client_factory
        )
        self._clock = clock
        self._skew_s = expiry_skew_s
        self._lock = asyncio.Lock()

    async def access_token(self) -> str:
        token = await self._store.load_token()
        if token is None:
            _auth_required("no Robinhood credential is stored")
        if not token.is_expired(self._clock(), skew_s=self._skew_s):
            return token.access_token
        return await self._refresh()

    async def _refresh(self) -> str:
        async with self._lock:
            async with self._store.exclusive():
                current = await self._store.load_token()
                if current is None:
                    _auth_required("the stored Robinhood credential was removed")
                if not current.is_expired(self._clock(), skew_s=self._skew_s):
                    # Another task or process already refreshed while this one
                    # waited for the locks.
                    return current.access_token

                registration = await self._store.load_registration()
                if registration is None:
                    _auth_required("no client registration is stored")

                attempts = max(1, self._config.limits.max_refresh_attempts)
                last: GatewayError | None = None
                for _ in range(attempts):
                    try:
                        refreshed = await self._attempt_refresh(current, registration)
                    except GatewayError as error:
                        if error.code is ErrorCode.AUTH_REQUIRED:
                            raise
                        last = error
                        continue
                    await self._store.store_token(refreshed)
                    return refreshed.access_token
                if last is not None:
                    raise last
                _auth_required(  # pragma: no cover - unreachable while attempts >= 1
                    "the stored Robinhood credential could not be refreshed"
                )

    async def _attempt_refresh(
        self, token: TokenCredential, registration: ClientRegistration
    ) -> TokenCredential:
        endpoint = await self._token_endpoint()
        async with self._client_factory() as client:
            return await refresh_access_token(
                client,
                endpoint,
                token,
                client_id=registration.client_id,
                issuer=registration.issuer,
                now=self._clock(),
            )

    async def _token_endpoint(self) -> str:
        """Where a refresh is sent.

        Production uses the pinned §5.0 constant and performs no discovery. The
        alternative — re-reading a provider-controlled metadata document on the
        path that spends a refresh token — would add a provider-steerable input
        to the most sensitive request this gateway makes, in exchange for
        nothing: a legitimate endpoint change needs a reviewed release anyway.

        Development has no pinned value, so it discovers and validates one.
        """
        if self._config.mode == "production":
            return PRODUCTION_TOKEN_ENDPOINT
        async with self._client_factory() as client:
            metadata = await discover_metadata(client, self._config)
        return metadata.token_endpoint


# --------------------------------------------------------------------------
# The workflows (§5.1, §5.2, §7.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LoginOutcome:
    """What `login()` may safely tell a human (§5.2, §7.2).

    Every field here is printable. There is deliberately no token, no client
    id, and no expiry *instant* beyond a duration, so a CLI can render this
    without a redaction step of its own.
    """

    issuer: str
    granted_scope: str | None
    expires_in_s: float | None
    has_refresh_token: bool
    registered_new_client: bool

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "granted_scope": self.granted_scope,
            "expires_in_s": self.expires_in_s,
            "has_refresh_token": self.has_refresh_token,
            "registered_new_client": self.registered_new_client,
            "write_capable": True,
        }


@dataclass(frozen=True)
class AuthStatus:
    """Safe answer to `rh-mcp auth status` (§7.2)."""

    has_credential: bool
    has_registration: bool
    issuer: str | None
    granted_scope: str | None
    expires_in_s: float | None
    has_refresh_token: bool

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "has_credential": self.has_credential,
            "has_registration": self.has_registration,
            "issuer": self.issuer,
            "granted_scope": self.granted_scope,
            "expires_in_s": self.expires_in_s,
            "has_refresh_token": self.has_refresh_token,
        }


async def login(
    config: GatewayConfig,
    store: CredentialStore,
    *,
    client_factory: ClientFactory | None = None,
    open_browser: BrowserOpener | None = None,
    clock: Clock = time.time,
    scope: str | None = DEFAULT_SCOPE,
) -> LoginOutcome:
    """The only workflow allowed to open a browser (§5.1).

    Order matters. The callback binds before the browser opens, so the
    authorization server can never redirect to a closed port. Metadata is
    validated before a registration is made, so a tampered document cannot
    cause a registration against the wrong issuer. And the token is written
    inside `exclusive()`, so a concurrent refresh in another process cannot
    interleave with the write.
    """
    opener = webbrowser.open if open_browser is None else open_browser
    factory = _default_client_factory(config) if client_factory is None else client_factory
    redirect_uri = callback_redirect_uri(config)
    now = clock()

    async with factory() as client:
        metadata = await discover_metadata(client, config)

        registration = await store.load_registration()
        registered_new_client = False
        if not _registration_is_usable(registration, metadata, redirect_uri, now):
            registration = await register_client(
                client, metadata, redirect_uri=redirect_uri, scope=scope, now=now
            )
            await store.store_registration(registration)
            registered_new_client = True
        if registration is None:  # pragma: no cover - narrowed by the branch above
            # Not an `assert`: `python -O` strips those, and this one is what
            # keeps a `client_id` of `None` out of an authorization request.
            _fail(ErrorCode.CONFIGURATION_ERROR, "no client registration is available")

        verifier = new_code_verifier()
        transaction = AuthorizationTransaction(
            state=new_state(),
            code_verifier=verifier,
            code_challenge=code_challenge_for(verifier),
            redirect_uri=redirect_uri,
            issuer=metadata.issuer,
            client_id=registration.client_id,
            created_at=now,
        )
        authorization_url = build_authorization_url(metadata, transaction, scope=scope)

        async with _callback_listener(config, transaction) as future:
            # The URL carries `state` and the PKCE challenge, so it is handed
            # to the browser and to nothing else — not a log, not stdout.
            if opener(authorization_url) is False:
                # Otherwise the login sits for the full callback timeout with
                # nothing on the other end, and the URL cannot simply be
                # printed instead: it carries `state`.
                _fail(
                    ErrorCode.CONFIGURATION_ERROR,
                    "no browser could be opened for the login redirect",
                )
            code = await await_authorization_code(config, future)

        token = await exchange_code(client, metadata, transaction, code, now=clock())

    async with store.exclusive():
        await store.store_token(token)

    logger.debug("login completed; a write-capable credential was stored")
    return LoginOutcome(
        issuer=token.issuer,
        granted_scope=token.granted_scope,
        expires_in_s=None if token.expires_at is None else token.expires_at - clock(),
        has_refresh_token=token.has_refresh_token,
        registered_new_client=registered_new_client,
    )


def _registration_is_usable(
    registration: ClientRegistration | None,
    metadata: AuthorizationServerMetadata,
    redirect_uri: str,
    now: float,
) -> bool:
    """Whether a stored registration still describes *this* login.

    A registration made against another issuer, or for a callback port that has
    since changed, is not reused. Reusing one would authorize against a
    different authorization server or register a redirect the listener is not
    on — both silent, both wrong.
    """
    if registration is None:
        return False
    if registration.issuer != metadata.issuer:
        return False
    if registration.redirect_uri != redirect_uri:
        return False
    return not registration.is_expired(now)


async def logout(store: CredentialStore, *, confirm: bool) -> dict[str, bool]:
    """Remove both records after explicit confirmation (§5.2).

    `confirm` is a required keyword with no default: §5.2 says logout removes
    the credential "after explicit confirmation", and a default would make the
    destructive path the easy one to reach by accident.
    """
    if confirm is not True:
        _fail(
            ErrorCode.INPUT_INVALID,
            "logout removes the stored Robinhood credential and requires explicit confirmation",
        )
    async with store.exclusive():
        removed_token = await store.delete_token()
        removed_registration = await store.delete_registration()
    return {"token": removed_token, "client_registration": removed_registration}


async def auth_status(store: CredentialStore, *, clock: Clock = time.time) -> AuthStatus:
    """Safe diagnostics. Reads the store; never contacts the provider."""
    token = await store.load_token()
    registration = await store.load_registration()
    now = clock()
    return AuthStatus(
        has_credential=token is not None,
        has_registration=registration is not None,
        issuer=None if token is None else (token.issuer or None),
        granted_scope=None if token is None else token.granted_scope,
        expires_in_s=(
            None if token is None or token.expires_at is None else token.expires_at - now
        ),
        has_refresh_token=token is not None and token.has_refresh_token,
    )


__all__ = [
    "DEFAULT_SCOPE",
    "PKCE_METHOD",
    "PRODUCTION_AUTHORIZATION_ENDPOINT",
    "PRODUCTION_ISSUER",
    "PRODUCTION_REGISTRATION_ENDPOINT",
    "PRODUCTION_TOKEN_ENDPOINT",
    "AuthStatus",
    "AuthorizationServerMetadata",
    "AuthorizationTransaction",
    "LoginOutcome",
    "StoredTokenProvider",
    "allowed_endpoint_origins",
    "auth_status",
    "authorization_server_metadata_urls",
    "await_authorization_code",
    "build_authorization_url",
    "callback_authority",
    "callback_redirect_uri",
    "code_challenge_for",
    "discover_metadata",
    "exchange_code",
    "login",
    "logout",
    "new_code_verifier",
    "new_state",
    "parse_authorization_server_metadata",
    "parse_protected_resource_metadata",
    "protected_resource_metadata_urls",
    "refresh_access_token",
    "register_client",
    "verify_discovery_metadata",
]
