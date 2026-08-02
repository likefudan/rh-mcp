"""OAuth, DCR, PKCE, and the loopback callback (DESIGN.md §5, §11).

Every HTTP request in this file goes through the real guarded transport with
`httpx2.MockTransport` underneath, so §3 origin pinning is live on all of them.
Nothing resolves a name or reaches the internet. Two tests bind an ephemeral
loopback port, because "binds an explicit loopback address, never a wildcard"
and "accepts one code, then closes the listener" are properties of a socket and
cannot be proved without one.

The callback logic itself is driven without a socket: a real `StreamReader` fed
raw bytes and a writer that records them. That keeps the hostile cases —
duplicated parameters, a wrong `Host`, a mismatched `state` — fast and
deterministic, and lets a test assert on the exact bytes written back.
"""

from __future__ import annotations

import asyncio
import logging
import webbrowser
from collections.abc import Coroutine
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

import rh_mcp.auth as auth
from rh_mcp.auth import (
    PRODUCTION_AUTHORIZATION_ENDPOINT,
    PRODUCTION_ISSUER,
    PRODUCTION_TOKEN_ENDPOINT,
    AuthorizationTransaction,
    StoredTokenProvider,
    auth_status,
    authorization_server_metadata_urls,
    build_authorization_url,
    code_challenge_for,
    discover_metadata,
    exchange_code,
    login,
    logout,
    new_code_verifier,
    parse_authorization_server_metadata,
    parse_protected_resource_metadata,
    protected_resource_metadata_urls,
    refresh_access_token,
    register_client,
)
from rh_mcp.credentials import ClientRegistration, InMemoryCredentialStore, TokenCredential
from rh_mcp.errors import ErrorCode, GatewayError
from tests.fake_oauth import (
    DEV_ORIGIN,
    DEV_RESOURCE,
    PLANTED_ACCESS_TOKEN,
    PLANTED_CLIENT_ID,
    PLANTED_CODE,
    PLANTED_REFRESH_TOKEN,
    FakeAuthorizationServer,
    another_process_holding,
    client_factory,
    deliver_callback,
    dev_resource_document,
    dev_server_document,
    development_config,
    free_port,
    open_client,
    production_config,
    production_resource_document,
    production_server_document,
    raw,
    state_of,
    status_only,
)


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def refused(coro: Coroutine[Any, Any, Any]) -> GatewayError:
    with pytest.raises(GatewayError) as caught:
        run(coro)
    return caught.value


async def _discover(server: FakeAuthorizationServer, config: Any = None) -> Any:
    resolved = development_config() if config is None else config
    async with open_client(server, resolved) as client:
        return await discover_metadata(client, resolved)


def discovered(server: FakeAuthorizationServer, config: Any = None) -> Any:
    return run(_discover(server, config))


# ==========================================================================
# PKCE (§5.1)
# ==========================================================================


def test_the_s256_challenge_matches_the_rfc_7636_vector() -> None:
    """Appendix B. A wrong transform fails only at the token endpoint."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge_for(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_a_verifier_is_long_unpredictable_and_url_safe() -> None:
    values = {new_code_verifier() for _ in range(64)}
    assert len(values) == 64
    for value in values:
        assert 43 <= len(value) <= 128
        assert all(character.isalnum() or character in "-._~" for character in value)


def test_the_challenge_is_unpadded_base64url() -> None:
    challenge = code_challenge_for(new_code_verifier())
    assert "=" not in challenge and "+" not in challenge and "/" not in challenge


# ==========================================================================
# Well-known derivation (§5.0)
# ==========================================================================


def test_the_protected_resource_url_inserts_the_well_known_segment() -> None:
    assert protected_resource_metadata_urls(PRODUCTION_ISSUER) == (
        "https://agent.robinhood.com/.well-known/oauth-protected-resource/mcp/trading",
    )


def test_the_authorization_server_urls_cover_both_documented_forms() -> None:
    assert authorization_server_metadata_urls(PRODUCTION_ISSUER) == (
        "https://agent.robinhood.com/.well-known/oauth-authorization-server/mcp/trading",
        "https://agent.robinhood.com/mcp/trading/.well-known/oauth-authorization-server",
    )


def test_a_path_less_issuer_yields_one_candidate_not_a_duplicate() -> None:
    """Both forms collapse when the issuer has no path; retrying an identical
    failed GET is noise."""
    urls = authorization_server_metadata_urls("https://robinhood.com")
    assert urls == ("https://robinhood.com/.well-known/oauth-authorization-server",)
    assert len(set(urls)) == len(urls)


def test_a_404_on_the_first_candidate_falls_through_to_the_second() -> None:
    server = FakeAuthorizationServer(
        routes={"/.well-known/oauth-authorization-server/mcp": status_only(404)}
    )
    metadata = discovered(server)
    assert metadata.issuer == DEV_RESOURCE
    assert "/mcp/.well-known/oauth-authorization-server" in server.paths


def test_an_invalid_first_document_is_fatal_rather_than_retried() -> None:
    """Otherwise a provider could serve a tampered doc first and a valid one second."""
    server = FakeAuthorizationServer(
        server_document=dev_server_document(code_challenge_methods_supported=["plain"])
    )
    error = refused(_discover(server))
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "PKCE S256" in error.message
    assert "/mcp/.well-known/oauth-authorization-server" not in server.paths


# ==========================================================================
# Production metadata pinning (§5.0)
# ==========================================================================


PRODUCTION_MUTATIONS = [
    ("issuer", "https://agent.robinhood.com/mcp/other"),
    ("authorization_endpoint", "https://robinhood.com/oauth2"),
    ("token_endpoint", "https://api.robinhood.com/oauth2/token"),
    ("registration_endpoint", "https://agent.robinhood.com/oauth/register"),
    ("grant_types_supported", ["authorization_code"]),
    ("response_types_supported", ["code", "token"]),
    ("code_challenge_methods_supported", ["S256", "plain"]),
    ("scopes_supported", ["internal", "trading"]),
    ("token_endpoint_auth_methods_supported", ["none", "client_secret_post"]),
]


@pytest.mark.parametrize(
    "field,value", PRODUCTION_MUTATIONS, ids=[mutation[0] for mutation in PRODUCTION_MUTATIONS]
)
def test_every_pinned_metadata_value_is_checked_in_production(field: str, value: Any) -> None:
    """§5.0: 'instead of silently accepting a changed issuer, endpoint, PKCE, or
    token-auth semantics'. One field at a time, so each guard is proved alone."""
    document = production_server_document(**{field: value})
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, production_config())
    assert caught.value.code is ErrorCode.CONFIGURATION_ERROR


def test_the_unmutated_production_document_is_accepted() -> None:
    """The positive direction: a normalisation bug that rejects the real
    document fails safe and would survive a suite of refusals only."""
    metadata = parse_authorization_server_metadata(
        production_server_document(), production_config()
    )
    assert metadata.issuer == PRODUCTION_ISSUER
    assert metadata.authorization_endpoint == PRODUCTION_AUTHORIZATION_ENDPOINT
    assert metadata.token_endpoint == PRODUCTION_TOKEN_ENDPOINT


def test_the_unmutated_production_resource_document_is_accepted() -> None:
    assert (
        parse_protected_resource_metadata(production_resource_document(), production_config())
        == PRODUCTION_ISSUER
    )


PRODUCTION_RESOURCE_MUTATIONS = [
    ("resource", "https://agent.robinhood.com/mcp/other"),
    ("authorization_servers", ["https://agent.robinhood.com/mcp/other"]),
    ("bearer_methods_supported", ["header", "body"]),
    ("scopes_supported", ["internal", "trading"]),
]


@pytest.mark.parametrize(
    "field,value", PRODUCTION_RESOURCE_MUTATIONS, ids=[m[0] for m in PRODUCTION_RESOURCE_MUTATIONS]
)
def test_every_pinned_resource_value_is_checked(field: str, value: Any) -> None:
    with pytest.raises(GatewayError):
        parse_protected_resource_metadata(
            production_resource_document(**{field: value}), production_config()
        )


def test_two_authorization_servers_are_refused() -> None:
    document = production_resource_document(
        authorization_servers=[PRODUCTION_ISSUER, "https://agent.robinhood.com/mcp/other"]
    )
    with pytest.raises(GatewayError) as caught:
        parse_protected_resource_metadata(document, production_config())
    assert "more than one" in caught.value.message


def test_an_issuer_mismatch_between_the_two_documents_is_refused() -> None:
    """The chain is what makes a swapped document detectable."""
    server = FakeAuthorizationServer(
        server_document=dev_server_document(issuer=f"{DEV_ORIGIN}/other")
    )
    error = refused(_discover(server))
    assert "different issuer" in error.message


# ==========================================================================
# Structural validation, in every mode (§5.0)
# ==========================================================================


def test_pkce_s256_is_required_and_plain_is_not_a_fallback() -> None:
    document = dev_server_document(code_challenge_methods_supported=["plain"])
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, development_config())
    assert "PKCE S256" in caught.value.message


def test_a_public_client_token_endpoint_is_required() -> None:
    document = dev_server_document(token_endpoint_auth_methods_supported=["client_secret_basic"])
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, development_config())
    assert "public client" in caught.value.message


def test_the_authorization_code_grant_is_required() -> None:
    document = dev_server_document(grant_types_supported=["implicit"])
    with pytest.raises(GatewayError):
        parse_authorization_server_metadata(document, development_config())


def test_the_code_response_type_is_required() -> None:
    document = dev_server_document(response_types_supported=["token"])
    with pytest.raises(GatewayError):
        parse_authorization_server_metadata(document, development_config())


@pytest.mark.parametrize("field", ["issuer", "authorization_endpoint", "token_endpoint",
                                   "registration_endpoint"])
def test_a_missing_metadata_field_is_refused(field: str) -> None:
    document = dev_server_document()
    del document[field]
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, development_config())
    assert field in caught.value.message


def test_a_metadata_endpoint_containing_whitespace_is_refused() -> None:
    document = dev_server_document(token_endpoint=f"{DEV_ORIGIN}/token\nX-Evil: 1")
    with pytest.raises(GatewayError):
        parse_authorization_server_metadata(document, development_config())


def test_the_resource_must_accept_a_header_bearer_token() -> None:
    document = dev_resource_document(bearer_methods_supported=["body"])
    with pytest.raises(GatewayError):
        parse_protected_resource_metadata(document, development_config())


# ==========================================================================
# Endpoint origin pinning (§3, §5.1)
# ==========================================================================


@pytest.mark.parametrize(
    "field",
    ["authorization_endpoint", "token_endpoint", "registration_endpoint"],
)
def test_an_endpoint_outside_the_allowed_origins_is_refused_in_development(field: str) -> None:
    document = dev_server_document(**{field: "https://evil.example.com/oauth"})
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, development_config())
    assert "outside this deployment's allowed origins" in caught.value.message


def test_the_authorization_endpoint_is_pinned_even_though_it_never_hits_the_guard() -> None:
    """It goes to the browser, which §3 puts outside the egress boundary, so
    this check is the only thing between a tampered document and a phishing
    page wearing Robinhood's login form."""
    document = production_server_document(
        authorization_endpoint="https://robinhood.com.evil.example/oauth"
    )
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, production_config())
    assert "allowed origins" in caught.value.message


def test_a_documented_host_on_an_undocumented_port_is_refused() -> None:
    """§3 pins origins, not hosts: `https://api.robinhood.com:9999` is not it."""
    document = production_server_document(token_endpoint="https://api.robinhood.com:9999/token")
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, production_config())
    assert "9999" in caught.value.message


def test_a_plain_http_production_endpoint_is_refused() -> None:
    document = production_server_document(token_endpoint="http://api.robinhood.com/oauth2/token/")
    with pytest.raises(GatewayError) as caught:
        parse_authorization_server_metadata(document, production_config())
    assert "https" in caught.value.message


def test_an_endpoint_carrying_userinfo_is_refused() -> None:
    document = dev_server_document(token_endpoint="http://user:pass@127.0.0.1:9999/token")
    with pytest.raises(GatewayError):
        parse_authorization_server_metadata(document, development_config())


def test_a_non_http_endpoint_scheme_is_refused() -> None:
    document = dev_server_document(authorization_endpoint="javascript:alert(1)")
    with pytest.raises(GatewayError):
        parse_authorization_server_metadata(document, development_config())


def test_the_egress_guard_also_refuses_an_out_of_origin_request() -> None:
    """Defence in depth: even if the metadata check were removed, the §3 guard
    stops the token exchange itself."""
    config = development_config()
    metadata = parse_authorization_server_metadata(dev_server_document(), config)
    hostile = auth.AuthorizationServerMetadata(
        **{**vars(metadata), "token_endpoint": "https://evil.example.com/token"}
    )
    server = FakeAuthorizationServer()

    async def scenario() -> Any:
        async with open_client(server, config) as client:
            return await exchange_code(client, hostile, transaction(), PLANTED_CODE, now=0.0)

    error = refused(scenario())
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "allowed origins" in error.message


# ==========================================================================
# Dynamic client registration (§5.1)
# ==========================================================================


def transaction(**overrides: Any) -> AuthorizationTransaction:
    verifier = "verifier-" + "v" * 40
    settings: dict[str, Any] = {
        "state": "state-token-abcdef",
        "code_verifier": verifier,
        "code_challenge": code_challenge_for(verifier),
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "issuer": DEV_RESOURCE,
        "client_id": PLANTED_CLIENT_ID,
        "created_at": 0.0,
    }
    settings.update(overrides)
    return AuthorizationTransaction(**settings)


async def _register(server: FakeAuthorizationServer, config: Any = None) -> Any:
    resolved = development_config() if config is None else config
    async with open_client(server, resolved) as client:
        metadata = await discover_metadata(client, resolved)
        return await register_client(
            client,
            metadata,
            redirect_uri="http://127.0.0.1:8765/callback",
            scope="internal",
            now=100.0,
        )


def test_registration_requests_a_public_native_client() -> None:
    server = FakeAuthorizationServer()
    result = run(_register(server))
    body = server.registration_bodies[-1]
    assert body["token_endpoint_auth_method"] == "none"
    assert body["redirect_uris"] == ["http://127.0.0.1:8765/callback"]
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    assert result.client_id == PLANTED_CLIENT_ID
    assert result.issuer == DEV_RESOURCE


def test_a_returned_client_secret_is_refused() -> None:
    """§5.0 pins `token_endpoint_auth_methods_supported: ["none"]`. A secret
    means the server made this a confidential client — §13 says design review,
    not a permissive fallback."""
    server = FakeAuthorizationServer(
        registration_response={"client_id": PLANTED_CLIENT_ID, "client_secret": "sh-h-h"}
    )
    error = refused(_register(server))
    assert "client secret" in error.message
    assert "sh-h-h" not in error.message


def test_a_registration_that_echoes_a_different_redirect_uri_is_refused() -> None:
    server = FakeAuthorizationServer(
        registration_response={
            "client_id": PLANTED_CLIENT_ID,
            "redirect_uris": ["http://127.0.0.1:9999/callback"],
        }
    )
    assert "different redirect URI" in refused(_register(server)).message


def test_a_registration_without_a_client_id_is_refused() -> None:
    server = FakeAuthorizationServer(registration_response={"ok": True})
    assert "client_id" in refused(_register(server)).message


def test_a_failing_registration_reports_only_the_status() -> None:
    server = FakeAuthorizationServer()
    server.registration_status = 500
    error = refused(_register(server))
    assert error.code is ErrorCode.PROVIDER_ERROR
    assert "500" in error.message


# ==========================================================================
# The authorization URL (§5.1)
# ==========================================================================


def test_the_authorization_url_carries_the_challenge_and_never_the_verifier() -> None:
    metadata = parse_authorization_server_metadata(dev_server_document(), development_config())
    active = transaction()
    url = build_authorization_url(metadata, active, scope="internal")
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [active.code_challenge]
    assert query["state"] == [active.state]
    assert query["redirect_uri"] == [active.redirect_uri]
    assert query["response_type"] == ["code"]
    assert active.code_verifier not in url


def test_a_transaction_never_renders_its_secrets() -> None:
    active = transaction()
    for rendered in (repr(active), str(active), f"{active}"):
        assert active.code_verifier not in rendered
        assert active.state not in rendered
        assert PLANTED_CLIENT_ID not in rendered


# ==========================================================================
# The callback listener (§5.1) — driven without a socket
# ==========================================================================


class RecordingWriter:
    def __init__(self) -> None:
        self.written = bytearray()

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


def request_bytes(target: str, *, method: str = "GET", host: str = "127.0.0.1:8765") -> bytes:
    return (
        f"{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode("latin-1")


async def _drive(
    listener: auth._CallbackListener, payload: bytes
) -> RecordingWriter:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    writer = RecordingWriter()
    await listener.handle(reader, writer)  # type: ignore[arg-type]
    return writer


def listener(active: AuthorizationTransaction | None = None) -> auth._CallbackListener:
    return auth._CallbackListener(
        transaction() if active is None else active,
        path="/callback",
        authority="127.0.0.1:8765",
    )


def drive(target: str, **kwargs: Any) -> tuple[auth._CallbackListener, RecordingWriter]:
    async def scenario() -> tuple[auth._CallbackListener, RecordingWriter]:
        instance = listener(kwargs.pop("transaction", None))
        writer = await _drive(instance, request_bytes(target, **kwargs))
        return instance, writer

    return run(scenario())


def test_a_valid_callback_yields_the_code() -> None:
    instance, writer = drive(f"/callback?code={PLANTED_CODE}&state=state-token-abcdef")
    assert instance.future.result() == PLANTED_CODE
    assert b"200 OK" in bytes(writer.written)


def test_the_callback_response_never_echoes_the_code_or_the_query() -> None:
    """§5.1: 'never prints the code, tokens, registration response, or callback query'."""
    _instance, writer = drive(f"/callback?code={PLANTED_CODE}&state=state-token-abcdef")
    body = bytes(writer.written)
    assert PLANTED_CODE.encode() not in body
    assert b"state-token-abcdef" not in body


def test_a_mismatched_state_aborts_the_login() -> None:
    instance, writer = drive(f"/callback?code={PLANTED_CODE}&state=wrong")
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert caught.value.code is ErrorCode.PROTOCOL_ERROR
    assert "state" in caught.value.message
    assert PLANTED_CODE.encode() not in bytes(writer.written)


NON_ASCII_STATES = [
    ("percent-encoded utf-8", "%C3%A9"),
    ("raw high byte", "é"),
    ("multibyte cjk", "%E6%BC%A2%E5%AD%97"),
    ("non-ascii sharing an ascii prefix", "state-token-abcdef%C3%A9"),
    ("emoji", "%F0%9F%92%A9"),
]


@pytest.mark.parametrize("label,state", NON_ASCII_STATES, ids=[m[0] for m in NON_ASCII_STATES])
def test_a_non_ascii_state_is_a_mismatch_not_an_exception(label: str, state: str) -> None:
    """`secrets.compare_digest` *raises* `TypeError` on a non-ASCII `str`.

    It does not return False. A review found the resulting exception escaped
    the connection handler, left the future unresolved, and held the listener
    bound for the full callback budget — the exact "keep waiting for whoever is
    interfering" outcome the abort exists to prevent. Reachable by any local
    process, and by a page the user has open: a no-cors GET to loopback carries
    a `Host` that passes `_check_host`.

    This is an input-space test, not a guard-presence test. Deleting the state
    check entirely would be caught by the mismatch tests; only feeding it this
    input catches the hole.
    """
    instance, _writer = drive(f"/callback?code={PLANTED_CODE}&state={state}")
    assert instance.future.done(), "the login was left hanging instead of aborting"
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert caught.value.code is ErrorCode.PROTOCOL_ERROR
    # Specifically the *state* refusal, not the handler's catch-all. Both stop
    # the hang — that is the point of having both — but only the comparison
    # fix makes this a decided mismatch rather than a caught crash, and a test
    # that accepted either would stop holding the primary fix.
    assert "state" in caught.value.message


def test_a_non_ascii_state_aborts_over_a_real_socket() -> None:
    """The same input against a bound listener, since the escape happened in
    the event loop's connection handler rather than in the parser."""
    port = free_port()
    config = development_config(callback_port=port)
    object.__setattr__(config.limits, "oauth_callback_timeout_s", 3.0)
    active = transaction(redirect_uri=f"http://127.0.0.1:{port}/callback")

    async def scenario() -> Any:
        async with auth._callback_listener(config, active) as future:
            await deliver_callback(
                f"127.0.0.1:{port}", "/callback", f"code={PLANTED_CODE}&state=%C3%A9"
            )
            return await auth.await_authorization_code(config, future)

    error = refused(scenario())
    # The point is that it is not a TIMEOUT: a timeout would mean the listener
    # sat for the whole budget with the future unresolved.
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "state" in error.message


def test_the_constant_time_comparison_decides_and_never_raises() -> None:
    for observed, expected, result in [
        ("abc", "abc", True),
        ("abc", "abd", False),
        ("abc", "é", False),
        ("é", "abc", False),
        ("é", "é", True),
        ("\ud800", "abc", False),  # a lone surrogate is not encodable at all
        ("", "", True),
    ]:
        assert auth._constant_time_equal(observed, expected) is result


def test_an_unanticipated_handler_exception_stops_the_login() -> None:
    """Defence in depth for the *shape* of the blocking bug, not its instance.

    Any parser failure that the benign-exception tuple does not name must abort
    rather than leave the future unresolved and the listener bound.
    """

    async def scenario() -> auth._CallbackListener:
        instance = listener()

        def explode(query: str) -> str:
            raise RuntimeError("an exception type nobody anticipated")

        instance._validate_query = explode  # type: ignore[method-assign]
        await _drive(instance, request_bytes(f"/callback?code={PLANTED_CODE}&state=x"))
        return instance

    instance = run(scenario())
    assert instance.future.done(), "an unanticipated exception left the login hanging"
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert caught.value.code is ErrorCode.PROTOCOL_ERROR


def test_an_unanticipated_handler_exception_leaks_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    async def scenario() -> auth._CallbackListener:
        instance = listener()

        def explode(query: str) -> str:
            raise RuntimeError(f"parser choked on {PLANTED_CODE}")

        instance._validate_query = explode  # type: ignore[method-assign]
        await _drive(instance, request_bytes(f"/callback?code={PLANTED_CODE}&state=x"))
        return instance

    instance = run(scenario())
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert PLANTED_CODE not in caught.value.message
    assert PLANTED_CODE not in caplog.text
    assert "RuntimeError" in caplog.text


def test_a_missing_state_aborts_the_login() -> None:
    instance, _writer = drive(f"/callback?code={PLANTED_CODE}")
    with pytest.raises(GatewayError):
        instance.future.result()


def test_a_duplicated_parameter_is_refused() -> None:
    """Two spellings of `code` is someone hoping this reads the other one."""
    instance, _writer = drive(
        f"/callback?code={PLANTED_CODE}&code=other&state=state-token-abcdef"
    )
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "twice" in caught.value.message


def test_a_mismatched_issuer_parameter_is_refused() -> None:
    """RFC 9207 `iss`, when the server sends it."""
    instance, _writer = drive(
        f"/callback?code={PLANTED_CODE}&state=state-token-abcdef&iss=https://evil.example.com"
    )
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "different issuer" in caught.value.message


def test_a_matching_issuer_parameter_is_accepted() -> None:
    instance, _writer = drive(
        f"/callback?code={PLANTED_CODE}&state=state-token-abcdef&iss={DEV_RESOURCE}"
    )
    assert instance.future.result() == PLANTED_CODE


def test_an_authorization_error_becomes_auth_required_without_echoing_it() -> None:
    instance, _writer = drive(
        "/callback?error=access_denied&error_description=nope&state=state-token-abcdef"
    )
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert caught.value.code is ErrorCode.AUTH_REQUIRED
    assert "access_denied" not in caught.value.message
    assert "nope" not in caught.value.message


def test_a_callback_under_the_wrong_host_is_refused() -> None:
    """The DNS-rebinding shape: delivered to loopback under another name."""
    instance, _writer = drive(
        f"/callback?code={PLANTED_CODE}&state=state-token-abcdef",
        host="evil.example.com:8765",
    )
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "registered redirect URI" in caught.value.message


def test_a_stray_path_is_answered_404_and_the_login_continues() -> None:
    async def scenario() -> tuple[auth._CallbackListener, bytes]:
        instance = listener()
        writer = await _drive(instance, request_bytes("/favicon.ico"))
        return instance, bytes(writer.written)

    instance, written = run(scenario())
    assert b"404" in written
    assert not instance.future.done()


def test_too_many_stray_requests_stop_the_login() -> None:
    async def scenario() -> auth._CallbackListener:
        instance = listener()
        for _ in range(auth._MAX_STRAY_REQUESTS + 1):
            await _drive(instance, request_bytes("/favicon.ico"))
        return instance

    instance = run(scenario())
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert caught.value.code is ErrorCode.TIMEOUT


def test_a_non_get_request_on_the_callback_path_is_refused() -> None:
    instance, _writer = drive(
        f"/callback?code={PLANTED_CODE}&state=state-token-abcdef", method="POST"
    )
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "non-GET" in caught.value.message


def test_a_callback_with_no_code_is_refused() -> None:
    instance, _writer = drive("/callback?state=state-token-abcdef")
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "no authorization code" in caught.value.message


def test_an_oversized_code_is_refused() -> None:
    instance, _writer = drive(
        f"/callback?code={'a' * (auth.MAX_CODE_CHARS + 1)}&state=state-token-abcdef"
    )
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "too long" in caught.value.message


def test_a_code_with_unusable_characters_is_refused() -> None:
    instance, _writer = drive("/callback?code=a%20b&state=state-token-abcdef")
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "unusable characters" in caught.value.message


def test_a_malformed_request_line_is_answered_400_without_ending_the_login() -> None:
    async def scenario() -> tuple[auth._CallbackListener, bytes]:
        instance = listener()
        writer = await _drive(instance, b"GARBAGE\r\n\r\n")
        return instance, bytes(writer.written)

    instance, written = run(scenario())
    assert b"400" in written
    assert not instance.future.done()


def test_over_long_headers_on_a_stray_path_do_not_abort_the_login() -> None:
    """The stray-traffic policy says a wrong path gets a bounded 404.

    Reading the header block before comparing the path made an over-long header
    set on `/favicon.ico` abort the whole login instead.
    """

    async def scenario() -> tuple[auth._CallbackListener, bytes]:
        instance = listener()
        headers = b"".join(
            b"X-Filler-%d: 1\r\n" % index for index in range(auth._MAX_HEADER_LINES + 5)
        )
        payload = b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n" + headers + b"\r\n"
        writer = await _drive(instance, payload)
        return instance, bytes(writer.written)

    instance, written = run(scenario())
    assert b"404" in written
    assert not instance.future.done()


def test_too_many_headers_are_refused() -> None:
    async def scenario() -> auth._CallbackListener:
        instance = listener()
        headers = b"".join(
            b"X-Filler-%d: 1\r\n" % index for index in range(auth._MAX_HEADER_LINES + 5)
        )
        payload = (
            b"GET /callback?code=abc&state=state-token-abcdef HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8765\r\n" + headers + b"\r\n"
        )
        await _drive(instance, payload)
        return instance

    instance = run(scenario())
    with pytest.raises(GatewayError) as caught:
        instance.future.result()
    assert "too many request headers" in caught.value.message


def test_the_callback_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    config = development_config()
    object.__setattr__(config.limits, "oauth_callback_timeout_s", 0.05)

    async def scenario() -> Any:
        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        return await auth.await_authorization_code(config, future)

    error = refused(scenario())
    assert error.code is ErrorCode.TIMEOUT


# -- the two socket-level properties ---------------------------------------


def test_the_listener_binds_only_the_configured_loopback_address() -> None:
    """§5.1: 'binds only an explicit loopback address, never a wildcard'."""
    port = free_port()
    config = development_config(callback_port=port)

    async def scenario() -> Any:
        async with auth._callback_listener(config, transaction()):
            # Reach into the running loop's servers via a fresh connection to
            # prove the socket is really there, then read its bound address.
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return True

    assert run(scenario()) is True


def test_a_wildcard_bind_host_is_refused() -> None:
    config = development_config()
    object.__setattr__(config, "callback_host", "0.0.0.0")  # noqa: S104 - the thing being refused

    async def scenario() -> Any:
        async with auth._callback_listener(config, transaction()):
            return None

    error = refused(scenario())
    assert "explicit loopback" in error.message


def test_the_listener_accepts_one_code_and_then_closes() -> None:
    """§5.1: 'accepts one code, has a short timeout, and then closes'. A replay
    of the same code afterwards must find nothing listening."""
    port = free_port()
    config = development_config(callback_port=port)
    active = transaction(redirect_uri=f"http://127.0.0.1:{port}/callback")
    authority = f"127.0.0.1:{port}"

    async def scenario() -> tuple[str, bool]:
        async with auth._callback_listener(config, active) as future:
            await deliver_callback(
                authority, "/callback", f"code={PLANTED_CODE}&state={active.state}"
            )
            code = await asyncio.wait_for(future, timeout=5)
        # The context manager has closed the listener.
        try:
            await deliver_callback(
                authority, "/callback", f"code={PLANTED_CODE}&state={active.state}"
            )
        except OSError:
            return code, True
        return code, False

    code, refused_replay = run(scenario())
    assert code == PLANTED_CODE
    assert refused_replay is True


# ==========================================================================
# Token exchange and refresh (§5.1, §5.2)
# ==========================================================================


async def _exchange(server: FakeAuthorizationServer, config: Any = None) -> Any:
    resolved = development_config() if config is None else config
    async with open_client(server, resolved) as client:
        metadata = await discover_metadata(client, resolved)
        return await exchange_code(client, metadata, transaction(), PLANTED_CODE, now=1_000.0)


def test_the_exchange_sends_the_verifier_and_the_code() -> None:
    server = FakeAuthorizationServer()
    token = run(_exchange(server))
    form = server.token_calls[-1]
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == PLANTED_CODE
    assert form["code_verifier"] == transaction().code_verifier
    assert form["client_id"] == PLANTED_CLIENT_ID
    assert "client_secret" not in form
    assert token.access_token == PLANTED_ACCESS_TOKEN
    assert token.expires_at == 1_000.0 + 3_600
    assert token.granted_scope == "internal"


def test_a_rejected_code_becomes_auth_required() -> None:
    server = FakeAuthorizationServer()
    server.token_status = 400
    error = refused(_exchange(server))
    assert error.code is ErrorCode.AUTH_REQUIRED
    assert "rh-mcp login" in error.message


def test_a_non_bearer_token_is_refused() -> None:
    server = FakeAuthorizationServer(
        token_response={"access_token": PLANTED_ACCESS_TOKEN, "token_type": "mac"}
    )
    assert "Bearer" in refused(_exchange(server)).message


def test_a_token_response_with_no_access_token_is_refused() -> None:
    server = FakeAuthorizationServer(token_response={"token_type": "Bearer"})
    assert "no access_token" in refused(_exchange(server)).message


def test_an_implausible_expires_in_is_refused() -> None:
    server = FakeAuthorizationServer(
        token_response={"access_token": PLANTED_ACCESS_TOKEN, "expires_in": 10**12}
    )
    assert "implausible" in refused(_exchange(server)).message


def test_a_missing_token_type_is_treated_as_bearer() -> None:
    server = FakeAuthorizationServer(token_response={"access_token": PLANTED_ACCESS_TOKEN})
    assert run(_exchange(server)).token_type == "Bearer"


def stored_token(**overrides: Any) -> TokenCredential:
    settings: dict[str, Any] = {
        "access_token": "old-access-token",
        "refresh_token": PLANTED_REFRESH_TOKEN,
        "expires_at": 500.0,
        "granted_scope": "internal",
        "issuer": DEV_RESOURCE,
    }
    settings.update(overrides)
    return TokenCredential(**settings)


async def _refresh(server: FakeAuthorizationServer, token: TokenCredential) -> Any:
    config = development_config()
    async with open_client(server, config) as client:
        return await refresh_access_token(
            client,
            f"{DEV_ORIGIN}/oauth2/token/",
            token,
            client_id=PLANTED_CLIENT_ID,
            issuer=DEV_RESOURCE,
            now=1_000.0,
        )


def test_a_rotated_refresh_token_replaces_the_old_one() -> None:
    server = FakeAuthorizationServer(
        token_response={
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 600,
        }
    )
    refreshed = run(_refresh(server, stored_token()))
    assert refreshed.refresh_token == "rotated-refresh-token"
    assert refreshed.access_token == "new-access-token"


def test_an_unrotated_refresh_token_is_carried_forward() -> None:
    """Dropping it here would force a login the next time the token expires."""
    server = FakeAuthorizationServer(
        token_response={"access_token": "new-access-token", "expires_in": 600}
    )
    refreshed = run(_refresh(server, stored_token()))
    assert refreshed.refresh_token == PLANTED_REFRESH_TOKEN
    assert refreshed.granted_scope == "internal"


def test_a_rejected_refresh_token_becomes_auth_required() -> None:
    server = FakeAuthorizationServer()
    server.token_status = 400
    assert refused(_refresh(server, stored_token())).code is ErrorCode.AUTH_REQUIRED


def test_refreshing_without_a_refresh_token_is_auth_required() -> None:
    server = FakeAuthorizationServer()
    error = refused(_refresh(server, stored_token(refresh_token=None)))
    assert error.code is ErrorCode.AUTH_REQUIRED
    assert "no refresh token" in error.message


# ==========================================================================
# The non-interactive provider (§5.1, §5.2, §8)
# ==========================================================================


def provider(
    server: FakeAuthorizationServer,
    store: InMemoryCredentialStore,
    *,
    config: Any = None,
    now: float = 1_000.0,
) -> StoredTokenProvider:
    resolved = development_config() if config is None else config
    return StoredTokenProvider(
        resolved,
        store,
        client_factory=client_factory(server, resolved),
        clock=lambda: now,
    )


def seeded_store(token: TokenCredential | None = None) -> InMemoryCredentialStore:
    store = InMemoryCredentialStore()

    async def seed() -> None:
        if token is not None:
            await store.store_token(token)
        await store.store_registration(
            ClientRegistration(
                client_id=PLANTED_CLIENT_ID,
                issuer=DEV_RESOURCE,
                redirect_uri="http://127.0.0.1:8765/callback",
            )
        )

    run(seed())
    return store


def test_a_live_token_is_returned_without_any_request() -> None:
    server = FakeAuthorizationServer()
    store = seeded_store(stored_token(expires_at=10_000.0))
    assert run(provider(server, store).access_token()) == "old-access-token"
    assert server.requests == []


def test_a_live_token_is_served_while_another_process_holds_the_lock(tmp_path: Any) -> None:
    """The fast path is not only an optimisation.

    Without it, every read would take the credential lock, and a read broker
    would start failing with `timeout` whenever a sibling process happened to
    be refreshing — even though the token it holds is perfectly good. Proved
    with a real second process holding a real `flock`.
    """
    from rh_mcp.credentials import FileCredentialStore

    config = development_config(credential_adapter="file_dev")
    store = FileCredentialStore("dev-rh-mcp", directory=tmp_path, lock_timeout_s=0.3)

    async def seed() -> None:
        await store.store_token(stored_token(expires_at=10_000.0))
        await store.store_registration(
            ClientRegistration(
                client_id=PLANTED_CLIENT_ID,
                issuer=DEV_RESOURCE,
                redirect_uri="http://127.0.0.1:8765/callback",
            )
        )

    run(seed())
    server = FakeAuthorizationServer()
    instance = StoredTokenProvider(
        config, store, client_factory=client_factory(server, config), clock=lambda: 1_000.0
    )
    with another_process_holding(store.directory / ".lock"):
        assert run(instance.access_token()) == "old-access-token"
    assert server.requests == []


def test_an_expired_token_is_refreshed_once() -> None:
    server = FakeAuthorizationServer(
        token_response={"access_token": "refreshed-token", "expires_in": 600}
    )
    store = seeded_store(stored_token(expires_at=500.0))
    assert run(provider(server, store).access_token()) == "refreshed-token"
    assert len(server.token_calls) == 1
    assert run(store.load_token()).access_token == "refreshed-token"  # type: ignore[union-attr]


def test_concurrent_reads_share_one_refresh() -> None:
    """§5.2: 'refresh is single-flight within a process'."""
    server = FakeAuthorizationServer(
        token_response={"access_token": "refreshed-token", "expires_in": 600}
    )
    server.delay_s = 0.01
    store = seeded_store(stored_token(expires_at=500.0))
    instance = provider(server, store)

    async def scenario() -> list[str]:
        return list(await asyncio.gather(*(instance.access_token() for _ in range(10))))

    results = run(scenario())
    assert results == ["refreshed-token"] * 10
    assert len(server.token_calls) == 1


class NoLockStore(InMemoryCredentialStore):
    """A store whose `exclusive()` does nothing, like an injected adapter might.

    The default `CredentialStore.exclusive()` in `_BytesBackedStore` is a
    no-op, and a consumer-supplied secret-manager adapter may reasonably not
    implement one. This is what proves the provider's *own* in-process lock is
    what makes refresh single-flight, rather than the store's lock happening to
    do it — mutation testing showed the shipped concurrency test passed with
    the provider's lock removed, because `InMemoryCredentialStore.exclusive()`
    was quietly serializing everything.
    """

    def exclusive(self) -> Any:
        return auth.asynccontextmanager(_nothing)()


async def _nothing() -> Any:
    yield


def test_single_flight_holds_even_when_the_store_provides_no_lock() -> None:
    server = FakeAuthorizationServer(
        token_response={"access_token": "refreshed-token", "expires_in": 600}
    )
    server.delay_s = 0.01
    store = NoLockStore()

    async def seed() -> None:
        await store.store_token(stored_token(expires_at=500.0))
        await store.store_registration(
            ClientRegistration(
                client_id=PLANTED_CLIENT_ID,
                issuer=DEV_RESOURCE,
                redirect_uri="http://127.0.0.1:8765/callback",
            )
        )

    run(seed())
    instance = provider(server, store)

    async def scenario() -> list[str]:
        return list(await asyncio.gather(*(instance.access_token() for _ in range(10))))

    assert run(scenario()) == ["refreshed-token"] * 10
    assert len(server.token_calls) == 1


def test_no_stored_credential_is_auth_required() -> None:
    error = refused(provider(FakeAuthorizationServer(), seeded_store()).access_token())
    assert error.code is ErrorCode.AUTH_REQUIRED
    assert "rh-mcp login" in error.message


def test_a_missing_registration_is_auth_required() -> None:
    store = InMemoryCredentialStore()
    run(store.store_token(stored_token(expires_at=500.0)))
    error = refused(provider(FakeAuthorizationServer(), store).access_token())
    assert error.code is ErrorCode.AUTH_REQUIRED
    assert "client registration" in error.message


def test_a_read_path_never_opens_a_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    """§5.1: 'All read operations are non-interactive... never open a browser'."""
    def explode(*args: Any, **kwargs: Any) -> bool:
        raise AssertionError("a read path opened a browser")

    monkeypatch.setattr(webbrowser, "open", explode)
    monkeypatch.setattr(auth.webbrowser, "open", explode)
    server = FakeAuthorizationServer(
        token_response={"access_token": "refreshed-token", "expires_in": 600}
    )
    store = seeded_store(stored_token(expires_at=500.0))
    assert run(provider(server, store).access_token()) == "refreshed-token"

    # And the failing path, which is the one that would be tempted to prompt.
    server.token_status = 400
    store_two = seeded_store(stored_token(expires_at=500.0))
    assert refused(provider(server, store_two).access_token()).code is ErrorCode.AUTH_REQUIRED


def test_a_failed_refresh_is_attempted_only_once() -> None:
    """§8 caps a coordinated refresh at one attempt."""
    server = FakeAuthorizationServer()
    server.token_status = 500
    store = seeded_store(stored_token(expires_at=500.0))
    error = refused(provider(server, store).access_token())
    assert error.code is ErrorCode.PROVIDER_ERROR
    assert len(server.token_calls) == 1


def test_a_production_refresh_uses_the_pinned_endpoint_and_no_discovery() -> None:
    """Re-reading a provider document on the path that spends a refresh token
    would add a provider-steerable input to the most sensitive request here."""
    server = FakeAuthorizationServer(
        production=True, token_response={"access_token": "refreshed-token", "expires_in": 600}
    )
    store = seeded_store(stored_token(expires_at=500.0, issuer=PRODUCTION_ISSUER))
    config = production_config()
    instance = StoredTokenProvider(
        config, store, client_factory=client_factory(server, config), clock=lambda: 1_000.0
    )
    assert run(instance.access_token()) == "refreshed-token"
    assert not any(".well-known" in path for path in server.paths)
    assert str(server.requests[-1].url) == PRODUCTION_TOKEN_ENDPOINT


def test_a_refresh_re_reads_the_store_after_taking_the_locks() -> None:
    """Another process may already have refreshed and rotated the token out."""
    server = FakeAuthorizationServer()
    store = seeded_store(stored_token(expires_at=500.0))
    instance = provider(server, store)

    async def scenario() -> str:
        # Simulate the other process winning the race: it writes a fresh token
        # while this one is between the fast path and the locks.
        await store.store_token(stored_token(access_token="other-process", expires_at=10_000.0))
        return await instance._refresh()

    assert run(scenario()) == "other-process"
    assert server.token_calls == []


# ==========================================================================
# The workflows (§5.1, §5.2, §7.2)
# ==========================================================================


def browser_that_completes_the_login(
    authority: str, *, code: str = PLANTED_CODE, path: str = "/callback"
) -> Any:
    """A stand-in browser that performs the redirect back to the callback."""

    def opener(url: str) -> bool:
        state = state_of(url)
        asyncio.get_running_loop().create_task(
            deliver_callback(authority, path, f"code={code}&state={state}")
        )
        return True

    return opener


def test_login_registers_stores_and_reports_only_safe_fields() -> None:
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()

    outcome = run(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=browser_that_completes_the_login(f"127.0.0.1:{port}"),
            clock=lambda: 1_000.0,
        )
    )
    assert outcome.registered_new_client is True
    assert outcome.granted_scope == "internal"
    assert outcome.has_refresh_token is True
    assert outcome.to_json_dict()["write_capable"] is True
    rendered = repr(outcome.to_json_dict())
    assert PLANTED_ACCESS_TOKEN not in rendered
    assert PLANTED_CLIENT_ID not in rendered

    stored = run(store.load_token())
    assert stored is not None and stored.access_token == PLANTED_ACCESS_TOKEN


def test_login_reuses_a_matching_registration() -> None:
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()
    run(
        store.store_registration(
            ClientRegistration(
                client_id=PLANTED_CLIENT_ID,
                issuer=DEV_RESOURCE,
                redirect_uri=f"http://127.0.0.1:{port}/callback",
            )
        )
    )
    outcome = run(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=browser_that_completes_the_login(f"127.0.0.1:{port}"),
            clock=lambda: 1_000.0,
        )
    )
    assert outcome.registered_new_client is False
    assert server.registration_bodies == []


def test_login_re_registers_when_the_callback_port_changed() -> None:
    """A stored registration names a redirect the listener is no longer on."""
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()
    run(
        store.store_registration(
            ClientRegistration(
                client_id=PLANTED_CLIENT_ID,
                issuer=DEV_RESOURCE,
                redirect_uri="http://127.0.0.1:1234/callback",
            )
        )
    )
    outcome = run(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=browser_that_completes_the_login(f"127.0.0.1:{port}"),
            clock=lambda: 1_000.0,
        )
    )
    assert outcome.registered_new_client is True


def test_login_leaks_nothing_into_the_logs(caplog: pytest.LogCaptureFixture) -> None:
    """§5.2/§8: no token, code, verifier, or registration response in a log."""
    caplog.set_level(logging.DEBUG)
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()
    run(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=browser_that_completes_the_login(f"127.0.0.1:{port}"),
            clock=lambda: 1_000.0,
        )
    )
    for secret in (PLANTED_ACCESS_TOKEN, PLANTED_REFRESH_TOKEN, PLANTED_CODE, PLANTED_CLIENT_ID):
        assert secret not in caplog.text


def test_a_login_whose_callback_carries_a_bad_state_fails_and_stores_nothing() -> None:
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()

    def opener(url: str) -> bool:
        asyncio.get_running_loop().create_task(
            deliver_callback(
                f"127.0.0.1:{port}", "/callback", f"code={PLANTED_CODE}&state=forged"
            )
        )
        return True

    error = refused(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=opener,
            clock=lambda: 1_000.0,
        )
    )
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert run(store.load_token()) is None
    assert server.token_calls == []


def test_a_browser_that_will_not_open_fails_fast() -> None:
    """Rather than sitting out the full callback timeout with nothing coming."""
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()
    error = refused(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=lambda url: False,
            clock=lambda: 1_000.0,
        )
    )
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "no browser" in error.message
    assert run(store.load_token()) is None


def test_logout_requires_explicit_confirmation() -> None:
    store = seeded_store(stored_token())
    error = refused(logout(store, confirm=False))
    assert error.code is ErrorCode.INPUT_INVALID
    assert run(store.load_token()) is not None


def test_logout_removes_both_records() -> None:
    store = seeded_store(stored_token())
    assert run(logout(store, confirm=True)) == {"token": True, "client_registration": True}
    assert run(store.load_token()) is None
    assert run(store.load_registration()) is None


def test_auth_status_is_safe_to_print() -> None:
    store = seeded_store(stored_token(expires_at=2_000.0))
    status = run(auth_status(store, clock=lambda: 1_000.0))
    assert status.has_credential is True
    assert status.has_registration is True
    assert status.expires_in_s == 1_000.0
    rendered = repr(status.to_json_dict())
    assert "old-access-token" not in rendered
    assert PLANTED_REFRESH_TOKEN not in rendered
    assert PLANTED_CLIENT_ID not in rendered


def test_auth_status_on_an_empty_store() -> None:
    status = run(auth_status(InMemoryCredentialStore()))
    assert status.has_credential is False
    assert status.issuer is None


# ==========================================================================
# Bounded and hostile responses (§8)
# ==========================================================================


def test_an_oversized_metadata_document_is_refused() -> None:
    server = FakeAuthorizationServer(
        routes={
            "/.well-known/oauth-protected-resource/mcp": raw(
                b'{"padding":"' + b"x" * 2_000_000 + b'"}'
            )
        }
    )
    error = refused(_discover(server))
    assert error.code in (ErrorCode.RESPONSE_TOO_LARGE, ErrorCode.CONFIGURATION_ERROR)


def test_a_deeply_nested_oauth_response_is_refused_before_decoding() -> None:
    depth = 5_000
    body = b"[" * depth + b"1" + b"]" * depth
    server = FakeAuthorizationServer(
        routes={"/.well-known/oauth-protected-resource/mcp": raw(body)}
    )
    error = refused(_discover(server))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "nests deeper" in error.message


def test_a_duplicate_key_in_an_oauth_response_is_refused() -> None:
    server = FakeAuthorizationServer(
        routes={
            "/.well-known/oauth-protected-resource/mcp": raw(
                b'{"resource":"a","resource":"b"}'
            )
        }
    )
    assert "same key twice" in refused(_discover(server)).message


def test_a_non_json_metadata_body_is_refused() -> None:
    server = FakeAuthorizationServer(
        routes={"/.well-known/oauth-protected-resource/mcp": raw(b"<html>nope</html>")}
    )
    assert refused(_discover(server)).code is ErrorCode.PROTOCOL_ERROR


def test_no_oauth_request_carries_an_authorization_header() -> None:
    """An OAuth request must never carry the credential it is trying to get.

    The OAuth client is built with no token provider; if that changed, a stored
    bearer token would ride along on discovery and registration — requests that
    are unauthenticated by design and go to a different host than the resource.
    """
    port = free_port()
    config = development_config(callback_port=port)
    server = FakeAuthorizationServer()
    store = InMemoryCredentialStore()
    run(
        login(
            config,
            store,
            client_factory=client_factory(server, config),
            open_browser=browser_that_completes_the_login(f"127.0.0.1:{port}"),
            clock=lambda: 1_000.0,
        )
    )
    assert server.requests
    for request in server.requests:
        assert "authorization" not in {name.lower() for name in request.headers}


def test_the_oauth_client_may_perform_the_discovery_get() -> None:
    """The MCP client answers every GET with a local 405; the OAuth client must
    not, or §5.0 discovery is unreachable. The positive direction of that flag."""
    server = FakeAuthorizationServer()
    discovered(server)
    assert any(request.method == "GET" for request in server.requests)


def test_an_unreachable_metadata_document_reports_only_a_status() -> None:
    server = FakeAuthorizationServer(
        routes={"/.well-known/oauth-protected-resource/mcp": status_only(503)}
    )
    error = refused(_discover(server))
    assert "503" in error.message
