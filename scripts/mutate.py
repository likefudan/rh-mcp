"""Mutation-test the step-4 guards: revert one, confirm a named test fails.

A guard whose mutation survives is a guard no test holds. Step 2 shipped a fix
that reintroducing the bug left entirely green, which is why this exists as a
committed script rather than a one-off shell loop.

Two operational details matter and have both cost time before:

* **Bytecode caching is disabled** (`PYTHONDONTWRITEBYTECODE=1`,
  `-p no:cacheprovider`). CPython's pyc header keys on (mtime-seconds, size),
  so a same-size mutation applied within a second of the original reuses stale
  bytecode and reports a false "not caught".
* Each mutation names the test it must break. Running the whole suite would
  also pass if some *other* test happened to fail, which is not the claim.

**This takes about five and a half minutes and prints nothing for the first
several seconds of each mutation.** It is not hung. Every mutation edits a
source file, shells out to a fresh `pytest` subprocess, and restores the file,
so the cost is one interpreter start-up plus one test collection per mutation
— currently 88 of them, ~3.7s each. It is deliberately not parallel: two
mutations in flight would be editing the same working tree.

Because it edits files in place and restores them in a `finally`, do not run
it concurrently with anything else that reads `src/rh_mcp`, and do not
interrupt it with SIGKILL — a `git status` afterwards is a cheap way to
confirm the tree came back clean.

Usage: `uv run python scripts/mutate.py [--verbose]`
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "rh_mcp"


@dataclass(frozen=True)
class Mutation:
    """One guard, reverted. `test` must fail while `old` is replaced by `new`."""

    label: str
    module: str
    old: str
    new: str
    test: str


MUTATIONS: list[Mutation] = [
    # -- v0.2.0: the independent review's findings -------------------------
    #
    # Every one of these reverts the shipped v0.1.0 defect exactly. If any
    # survives, the fix for that finding is held by no test and would ship
    # again the next time someone tidied the line.
    Mutation(
        "P1: invoke sends the validated snapshot, not the caller's mapping",
        "gateway.py",
        "        payload = await self.__transport.call_tool(\n            entry.provider_tool_name,\n            preflight.arguments,",
        "        payload = await self.__transport.call_tool(\n            entry.provider_tool_name,\n            arguments or {},",
        "tests/test_gateway.py::TestValidatedSnapshotReachesTheTransport"
        "::test_a_mapping_that_flips_after_preflight_cannot_smuggle_keys",
    ),
    Mutation(
        "P1: the returned snapshot is deep-frozen, not a mutable copy",
        "manifest.py",
        "        arguments=freeze_json(safe_arguments, ErrorCode.INPUT_INVALID, label=\"arguments\"),",
        "        arguments=safe_arguments,",
        "tests/test_gateway.py::TestValidatedSnapshotReachesTheTransport"
        "::test_the_snapshot_the_transport_receives_cannot_be_edited",
    ),
    Mutation(
        "P0: ProviderTransport stays out of the published surface",
        "transport.py",
        "__all__ = [\n    \"PRODUCTION_EGRESS_HOSTS\",\n    \"HttpJsonResponse\",",
        "__all__ = [\n    \"PRODUCTION_EGRESS_HOSTS\",\n    \"ProviderTransport\",\n    \"HttpJsonResponse\",",
        "tests/test_public_surface.py::test_no_star_imported_name_is_a_raw_call_surface"
        "[rh_mcp.transport]",
    ),
    Mutation(
        "P0: no published name hands back a raw session",
        "transport.py",
        "    \"ToolPayload\",\n]",
        "    \"ToolPayload\",\n    \"open_provider_session\",\n]\n\nopen_provider_session = _open_provider_session",
        "tests/test_public_surface.py::test_no_star_imported_callable_returns_a_raw_call_surface"
        "[rh_mcp.transport]",
    ),
    Mutation(
        "P0: the HTTP seam's shape stays out of the published surface",
        "transport.py",
        "    \"PayloadSource\",\n    \"ToolPayload\",",
        "    \"PayloadSource\",\n    \"GuardedJsonClient\",\n    \"ToolPayload\",",
        "tests/test_public_surface.py::test_no_star_imported_name_is_a_raw_call_surface"
        "[rh_mcp.transport]",
    ),
    Mutation(
        "P0: no published name hands back an HTTP client either",
        "transport.py",
        "    \"HttpJsonResponse\",\n    \"PayloadSource\",",
        "    \"HttpJsonResponse\",\n    \"open_json_client\",\n    \"PayloadSource\",",
        "tests/test_public_surface.py::test_no_star_imported_callable_returns_a_raw_call_surface"
        "[rh_mcp.transport]",
    ),
    Mutation(
        "P0: StoredTokenProvider stays out of the published surface",
        "auth.py",
        "    \"LoginOutcome\",\n    \"allowed_endpoint_origins\",",
        "    \"LoginOutcome\",\n    \"StoredTokenProvider\",\n    \"allowed_endpoint_origins\",",
        "tests/test_public_surface.py::test_no_star_imported_name_is_a_raw_call_surface"
        "[rh_mcp.auth]",
    ),
    Mutation(
        "P0: the credential store factory stays out of the published surface",
        "credentials.py",
        "    \"default_credential_directory\",\n]",
        "    \"default_credential_directory\",\n    \"open_credential_store\",\n]",
        "tests/test_public_surface.py::test_the_credential_store_factory_is_not_advertised",
    ),
    Mutation(
        "P0: the transport's call takes a reviewed name, not a free-form one",
        "transport.py",
        "    async def call_tool(\n        self,\n        reviewed_tool_name: str,\n        arguments: Mapping[str, Any],\n        *,\n        output_schema: Mapping[str, Any] | None,\n    ) -> ToolPayload:\n        \"\"\"Send one call for an already-reviewed tool.",
        "    async def call_tool(\n        self,\n        provider_tool_name: str,\n        arguments: Mapping[str, Any],\n        *,\n        output_schema: Mapping[str, Any] | None,\n    ) -> ToolPayload:\n        \"\"\"Send one call for an already-reviewed tool.",
        "tests/test_public_surface.py::test_the_capability_argument_is_not_a_provider_tool_name",
    ),
    # A mutation of the *detector*, not of a guard. `_has_raw_call_surface`
    # is what every sweep above depends on, and a sweep that silently stopped
    # detecting anything would report a clean package on a broken one. This is
    # the failure mode `TestNoEscapeHatch` had for the whole of v0.1.0, in a
    # different form, so it gets its own mutation.
    Mutation(
        "the escape-hatch detector itself still detects",
        "transport.py",
        "    async def discover(self) -> ObservedSurface: ...\n\n    async def call_tool(",
        "    async def discover(self) -> ObservedSurface: ...\n\n    async def call_tool_renamed(",
        "tests/test_public_surface.py::test_the_package_still_contains_raw_call_surfaces_to_find",
    ),
    # The same canary, for the HTTP half of the detector. The MCP half above
    # would still pass with the three HTTP verbs missing from the frozenset,
    # so one mutation cannot hold both — and a frozenset that had silently
    # lost the verbs would report a clean package while `open_json_client` sat
    # back in `__all__`.
    Mutation(
        "the detector still detects the HTTP seam, not only the MCP one",
        "transport.py",
        "    async def get_json(self, url: str) -> HttpJsonResponse: ...",
        "    async def get_json_renamed(self, url: str) -> HttpJsonResponse: ...",
        "tests/test_public_surface.py::test_the_package_still_contains_raw_call_surfaces_to_find",
    ),
    # -- credentials.py: file adapter --------------------------------------
    Mutation(
        "file mode 0600 is enforced on read",
        "credentials.py",
        "if stat.S_IMODE(info.st_mode) & 0o077:\n        _fail(\n            ErrorCode.CONFIGURATION_ERROR,\n            f\"{label} is readable or writable by group or other; it must be mode 0600\",",
        "if stat.S_IMODE(info.st_mode) & 0o000:\n        _fail(\n            ErrorCode.CONFIGURATION_ERROR,\n            f\"{label} is readable or writable by group or other; it must be mode 0600\",",
        "tests/test_credentials.py::test_a_credential_file_readable_by_others_is_refused_on_read",
    ),
    Mutation(
        "file ownership is enforced",
        "credentials.py",
        "    if not stat.S_ISREG(info.st_mode):\n        _fail(ErrorCode.CONFIGURATION_ERROR, f\"{label} is not a regular file\")\n    if info.st_uid != os.getuid():",
        "    if not stat.S_ISREG(info.st_mode):\n        _fail(ErrorCode.CONFIGURATION_ERROR, f\"{label} is not a regular file\")\n    if False:",
        "tests/test_credentials.py::test_a_credential_file_owned_by_another_user_is_refused",
    ),
    Mutation(
        "O_NOFOLLOW stops a symlinked credential file",
        "credentials.py",
        "descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)",
        "descriptor = os.open(path, os.O_RDONLY)",
        "tests/test_credentials.py::test_a_symlinked_credential_file_is_not_followed",
    ),
    Mutation(
        "the credential file is created at mode 0600",
        "credentials.py",
        "            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600",
        "            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666",
        "tests/test_credentials.py::test_the_credential_directory_is_0700_and_the_file_is_0600",
    ),
    Mutation(
        "the credential directory is created at mode 0700",
        "credentials.py",
        "        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)",
        "        self._directory.mkdir(parents=True, exist_ok=True, mode=0o755)",
        "tests/test_credentials.py::test_the_credential_directory_is_0700_and_the_file_is_0600",
    ),
    Mutation(
        "a pre-existing insecure credential directory is refused, not repaired",
        "credentials.py",
        '        _check_directory_security(os.stat(self._directory), "the development credential directory")',
        "        pass",
        "tests/test_credentials.py::test_a_pre_existing_group_readable_directory_is_refused_not_repaired",
    ),
    Mutation(
        "the inter-process flock really is taken",
        "credentials.py",
        "                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n                return handle",
        "                return handle",
        "tests/test_credentials.py::test_exclusive_serializes_against_another_process",
    ),
    Mutation(
        "an oversized credential file is refused before it is read",
        "credentials.py",
        "            if info.st_size > MAX_SECRET_BYTES:",
        "            if False:",
        "tests/test_credentials.py::test_an_oversized_credential_file_is_refused",
    ),
    Mutation(
        "an oversized stored record is refused (the keychain has no size check)",
        "credentials.py",
        "    if len(raw) > MAX_SECRET_BYTES:",
        "    if False:",
        "tests/test_credentials.py::test_an_oversized_keychain_record_is_refused",
    ),
    # -- credentials.py: records -------------------------------------------
    Mutation(
        "a token is redacted in repr",
        "credentials.py",
        '            "TokenCredential(access_token=<redacted>, "',
        '            f"TokenCredential(access_token={self.access_token!r}, "',
        "tests/test_credentials.py::test_no_rendering_of_a_token_reveals_it",
    ),
    Mutation(
        "a client id is redacted in repr",
        "credentials.py",
        '            "ClientRegistration(client_id=<redacted>, "',
        '            f"ClientRegistration(client_id={self.client_id!r}, "',
        "tests/test_credentials.py::test_no_rendering_of_a_registration_reveals_the_client_id",
    ),
    Mutation(
        "a header-splitting token is refused",
        "credentials.py",
        '        if character < "\\x21" or character > "\\x7e":',
        "        if False:",
        "tests/test_credentials.py::test_a_token_with_a_newline_is_refused",
    ),
    Mutation(
        "only a Bearer token is stored",
        "credentials.py",
        '        if self.token_type.lower() != "bearer":',
        "        if False:",
        "tests/test_credentials.py::test_only_a_bearer_token_can_be_stored",
    ),
    Mutation(
        "the expiry skew refreshes early",
        "credentials.py",
        "        return now >= self.expires_at - skew_s",
        "        return now >= self.expires_at",
        "tests/test_credentials.py::test_expiry_uses_the_skew_so_a_token_never_expires_in_flight",
    ),
    Mutation(
        "a registration expiry of zero means never",
        "credentials.py",
        "        if self.client_id_expires_at is None or self.client_id_expires_at == 0:",
        "        if self.client_id_expires_at is None:",
        "tests/test_credentials.py::test_a_registration_expiry_of_zero_means_never",
    ),
    Mutation(
        "a record of the wrong kind is refused",
        "credentials.py",
        '    if document.get("kind") != kind:',
        "    if False:",
        "tests/test_credentials.py::test_a_record_of_the_wrong_kind_is_refused",
    ),
    Mutation(
        "an unsupported record format version is refused",
        "credentials.py",
        '    if document.get("version") != CREDENTIAL_RECORD_VERSION:',
        "    if False:",
        "tests/test_credentials.py::test_a_record_from_an_unsupported_format_version_is_refused",
    ),
    # -- credentials.py: namespaces and keychain ---------------------------
    Mutation(
        "the write-client namespace is refused",
        "credentials.py",
        "    if namespace.startswith(WRITE_NAMESPACE_PREFIX):",
        "    if False:",
        "tests/test_credentials.py::test_a_write_client_namespace_is_refused_in_every_mode",
    ),
    Mutation(
        "a dev namespace is refused in production",
        "credentials.py",
        '    if mode == "production" and namespace.startswith(DEV_NAMESPACE_PREFIX):',
        "    if False:",
        "tests/test_credentials.py::test_a_development_namespace_is_refused_in_production",
    ),
    Mutation(
        "the keychain secret is passed on stdin, not argv",
        "credentials.py",
        '        result = await asyncio.to_thread(self._runner, ["security", "-i"], command)',
        '        result = await asyncio.to_thread(\n            self._runner,\n            ["security", "add-generic-password", "-U", "-a", account, "-s", self._service,\n             "-w", encoded],\n            None,\n        )',
        "tests/test_credentials.py::test_the_secret_never_appears_in_argv",
    ),
    Mutation(
        "a non-base64 keychain value is refused",
        "credentials.py",
        "        if not _BASE64_PATTERN.fullmatch(encoded):\n            _fail(ErrorCode.CONFIGURATION_ERROR, \"the keychain credential is not valid base64\")",
        "        if False:\n            _fail(ErrorCode.CONFIGURATION_ERROR, \"the keychain credential is not valid base64\")",
        "tests/test_credentials.py::test_a_non_base64_keychain_value_is_refused",
    ),
    Mutation(
        "production refuses the file adapter",
        "credentials.py",
        '        if config.mode == "production":\n            _fail(\n                ErrorCode.CONFIGURATION_ERROR,\n                "the file credential adapter stores a write-capable token in plaintext and "',
        '        if False:\n            _fail(\n                ErrorCode.CONFIGURATION_ERROR,\n                "the file credential adapter stores a write-capable token in plaintext and "',
        "tests/test_credentials.py::test_production_refuses_the_file_adapter",
    ),
    # -- auth.py: §5.0 pinning ---------------------------------------------
    Mutation(
        "the pinned §5.0 values are compared",
        "auth.py",
        "def _expect(name: str, observed: object, expected: object) -> None:\n    if observed != expected:",
        "def _expect(name: str, observed: object, expected: object) -> None:\n    if False:",
        "tests/test_auth.py::test_every_pinned_metadata_value_is_checked_in_production",
    ),
    Mutation(
        "an endpoint origin outside the pin is refused",
        "auth.py",
        "    if origin not in allowed_endpoint_origins(config):",
        "    if False:",
        "tests/test_auth.py::test_the_authorization_endpoint_is_pinned_even_though_it_never_hits_the_guard",
    ),
    Mutation(
        "the endpoint pin is an origin, not a host",
        "auth.py",
        "    return scheme, host.lower(), port or (443 if scheme == \"https\" else 80)",
        "    return scheme, host.lower(), 443",
        "tests/test_auth.py::test_a_documented_host_on_an_undocumented_port_is_refused",
    ),
    Mutation(
        "production endpoints must be https",
        "auth.py",
        '    if config.mode == "production" and origin[0] != "https":',
        "    if False:",
        "tests/test_auth.py::test_a_plain_http_production_endpoint_is_refused",
    ),
    Mutation(
        "PKCE S256 is required",
        "auth.py",
        "    if PKCE_METHOD not in metadata.code_challenge_methods_supported:",
        "    if False:",
        "tests/test_auth.py::test_pkce_s256_is_required_and_plain_is_not_a_fallback",
    ),
    Mutation(
        "a public-client token endpoint is required",
        "auth.py",
        '    if "none" not in metadata.token_endpoint_auth_methods_supported:',
        "    if False:",
        "tests/test_auth.py::test_a_public_client_token_endpoint_is_required",
    ),
    Mutation(
        "the two documents must agree on the issuer",
        "auth.py",
        "    if metadata.issuer != issuer:",
        "    if False:",
        "tests/test_auth.py::test_an_issuer_mismatch_between_the_two_documents_is_refused",
    ),
    Mutation(
        "only one authorization server is accepted",
        "auth.py",
        "    if len(servers) != 1:",
        "    if False:",
        "tests/test_auth.py::test_two_authorization_servers_are_refused",
    ),
    # -- auth.py: registration ---------------------------------------------
    Mutation(
        "a returned client secret is refused",
        "auth.py",
        '    if payload.get("client_secret") is not None:',
        "    if False:",
        "tests/test_auth.py::test_a_returned_client_secret_is_refused",
    ),
    Mutation(
        "a mismatched registered redirect URI is refused",
        "auth.py",
        "        if not isinstance(echoed, (list, tuple)) or list(echoed) != [redirect_uri]:",
        "        if False:",
        "tests/test_auth.py::test_a_registration_that_echoes_a_different_redirect_uri_is_refused",
    ),
    # -- auth.py: the callback ---------------------------------------------
    Mutation(
        "the callback state is compared",
        "auth.py",
        "        if not isinstance(state, str) or not _constant_time_equal(\n            state, self._transaction.state\n        ):",
        "        if False:",
        "tests/test_auth.py::test_a_mismatched_state_aborts_the_login",
    ),
    Mutation(
        "the callback Host must be the registered authority",
        "auth.py",
        "        if host != self._authority:",
        "        if False:",
        "tests/test_auth.py::test_a_callback_under_the_wrong_host_is_refused",
    ),
    Mutation(
        "a duplicated callback parameter is refused",
        "auth.py",
        "            if key in seen:",
        "            if False:",
        "tests/test_auth.py::test_a_duplicated_parameter_is_refused",
    ),
    Mutation(
        "a mismatched iss parameter is refused",
        "auth.py",
        "        if issuer is not None and issuer != self._transaction.issuer:",
        "        if False:",
        "tests/test_auth.py::test_a_mismatched_issuer_parameter_is_refused",
    ),
    Mutation(
        "an authorization error is not exchanged for a token",
        "auth.py",
        '        if "error" in seen:',
        "        if False:",
        "tests/test_auth.py::test_an_authorization_error_becomes_auth_required_without_echoing_it",
    ),
    Mutation(
        "the callback path must match exactly",
        "auth.py",
        "        if path != self._path:",
        "        if False:",
        "tests/test_auth.py::test_a_stray_path_is_answered_404_and_the_login_continues",
    ),
    Mutation(
        "an oversized authorization code is refused",
        "auth.py",
        "        if len(code) > MAX_CODE_CHARS:",
        "        if False:",
        "tests/test_auth.py::test_an_oversized_code_is_refused",
    ),
    Mutation(
        "an authorization code with unusable characters is refused",
        "auth.py",
        '            if character < "\\x21" or character > "\\x7e":',
        "            if False:",
        "tests/test_auth.py::test_a_code_with_unusable_characters_is_refused",
    ),
    Mutation(
        "stray callback requests are bounded",
        "auth.py",
        "            if self._strays > _MAX_STRAY_REQUESTS:",
        "            if False:",
        "tests/test_auth.py::test_too_many_stray_requests_stop_the_login",
    ),
    Mutation(
        "the callback binds only an explicit loopback address",
        "auth.py",
        "    if config.callback_host not in _LOOPBACK_BIND_HOSTS:",
        "    if False:",
        "tests/test_auth.py::test_a_wildcard_bind_host_is_refused",
    ),
    Mutation(
        "the callback response never echoes the code",
        "auth.py",
        "        await self._respond(writer, 200, _CALLBACK_PAGE)",
        "        await self._respond(writer, 200, _CALLBACK_PAGE + code.encode())",
        "tests/test_auth.py::test_the_callback_response_never_echoes_the_code_or_the_query",
    ),
    # -- auth.py: tokens and refresh ---------------------------------------
    Mutation(
        "a rejected authorization code becomes auth_required",
        "auth.py",
        "    if response.status_code == 400:\n        # The canonical `invalid_grant`",
        "    if False:\n        # The canonical `invalid_grant`",
        "tests/test_auth.py::test_a_rejected_code_becomes_auth_required",
    ),
    Mutation(
        "a non-Bearer token response is refused",
        "auth.py",
        '    if not isinstance(token_type, str) or token_type.lower() != "bearer":',
        "    if False:",
        "tests/test_auth.py::test_a_non_bearer_token_is_refused",
    ),
    Mutation(
        "an unrotated refresh token is carried forward",
        "auth.py",
        "    if refresh_token is None and previous is not None:\n        refresh_token = previous.refresh_token",
        "    pass",
        "tests/test_auth.py::test_an_unrotated_refresh_token_is_carried_forward",
    ),
    Mutation(
        "refresh is single-flight on the provider's own lock",
        "auth.py",
        "        async with self._lock:\n            async with self._store.exclusive():",
        "        if True:\n            async with self._store.exclusive():",
        "tests/test_auth.py::test_single_flight_holds_even_when_the_store_provides_no_lock",
    ),
    Mutation(
        "the re-read after the locks short-circuits a completed refresh",
        "auth.py",
        "                if not current.is_expired(self._clock(), skew_s=self._skew_s):",
        "                if False:",
        "tests/test_auth.py::test_a_refresh_re_reads_the_store_after_taking_the_locks",
    ),
    Mutation(
        "production refresh uses the pinned token endpoint",
        "auth.py",
        '        if self._config.mode == "production":\n            return PRODUCTION_TOKEN_ENDPOINT',
        "        if False:\n            return PRODUCTION_TOKEN_ENDPOINT",
        "tests/test_auth.py::test_a_production_refresh_uses_the_pinned_endpoint_and_no_discovery",
    ),
    Mutation(
        "a missing credential is auth_required, not a browser prompt",
        "auth.py",
        '        if token is None:\n            _auth_required("no Robinhood credential is stored")',
        "        if token is None:\n            token = TokenCredential(access_token='x')",
        "tests/test_auth.py::test_no_stored_credential_is_auth_required",
    ),
    Mutation(
        "a browser that will not open fails fast",
        "auth.py",
        "            if opener(authorization_url) is False:",
        "            if False:",
        "tests/test_auth.py::test_a_browser_that_will_not_open_fails_fast",
    ),
    Mutation(
        "logout requires explicit confirmation",
        "auth.py",
        "    if confirm is not True:",
        "    if False:",
        "tests/test_auth.py::test_logout_requires_explicit_confirmation",
    ),
    # -- transport.py: the OAuth seam --------------------------------------
    Mutation(
        "the MCP client still refuses the server-initiated GET",
        "transport.py",
        "    refuse_get: bool = True,\n) -> _httpx2.AsyncClient:",
        "    refuse_get: bool = False,\n) -> _httpx2.AsyncClient:",
        "tests/test_transport.py::test_the_notification_get_stream_is_refused_without_egress",
    ),
    Mutation(
        "the OAuth client carries no bearer token",
        "transport.py",
        "    client = _build_http_client(config, fault, None, inner=inner, refuse_get=False)",
        "    client = _build_http_client(\n        config, fault, _StubProvider(), inner=inner, refuse_get=False\n    )",
        "tests/test_auth.py::test_no_oauth_request_carries_an_authorization_header",
    ),
    Mutation(
        "an OAuth response is depth-bounded before decoding",
        "transport.py",
        "        if _exceeds_text_depth(text, self._response_budget.max_depth):\n            # Refused whatever the status",
        "        if False:\n            # Refused whatever the status",
        "tests/test_auth.py::test_a_deeply_nested_oauth_response_is_refused_before_decoding",
    ),
    # -- review round 1 fixes ----------------------------------------------
    #
    # Both blocking findings lived where this harness structurally cannot look:
    # one was an exception type escaping a handler, the other the behaviour of
    # a real external binary. Mutation testing answers "does deleting this
    # guard break a test"; it cannot answer "does this guard have a hole for an
    # input nobody wrote a test for". The mutations below are still worth
    # having — they keep the *fixes* held — but the tests they point at are
    # input-space tests, which is the part that actually found the bugs.
    Mutation(
        "a non-ASCII state is a mismatch, not a TypeError that escapes",
        "auth.py",
        "        if not isinstance(state, str) or not _constant_time_equal(\n            state, self._transaction.state\n        ):",
        "        if not isinstance(state, str) or not secrets.compare_digest(\n            state, self._transaction.state\n        ):",
        "tests/test_auth.py::test_a_non_ascii_state_is_a_mismatch_not_an_exception",
    ),
    Mutation(
        "a non-ASCII state aborts over a real socket",
        "auth.py",
        "    try:\n        return secrets.compare_digest(observed.encode(\"utf-8\"), expected.encode(\"utf-8\"))\n    except (UnicodeEncodeError, TypeError, AttributeError):\n        return False",
        "    return secrets.compare_digest(observed, expected)",
        "tests/test_auth.py::test_a_non_ascii_state_aborts_over_a_real_socket",
    ),
    Mutation(
        "an unanticipated handler exception still stops the login",
        "auth.py",
        "        except Exception as exc:  # noqa: BLE001 - see below; this must not escape",
        "        except ZeroDivisionError as exc:  # noqa: BLE001",
        "tests/test_auth.py::test_an_unanticipated_handler_exception_stops_the_login",
    ),
    Mutation(
        "over-long headers on a stray path do not abort the login",
        "auth.py",
        # Reproduces the *shape* of the bug — headers read before the stray
        # path is answered — rather than merely inlining the call, which an
        # earlier version of this mutation did and which changed nothing.
        "            self._strays += 1",
        "            await self._read_headers(reader)\n            self._strays += 1",
        "tests/test_auth.py::test_over_long_headers_on_a_stray_path_do_not_abort_the_login",
    ),
    Mutation(
        "the well-known candidates are de-duplicated",
        "auth.py",
        '    return tuple(dict.fromkeys((_well_known(issuer, "oauth-authorization-server"), appended)))',
        '    return (_well_known(issuer, "oauth-authorization-server"), appended)',
        "tests/test_auth.py::test_a_path_less_issuer_yields_one_candidate_not_a_duplicate",
    ),
    Mutation(
        "the keychain write refuses a record past the measured line budget",
        "credentials.py",
        "        if len(command.encode(\"ascii\")) > SECURITY_MAX_COMMAND_LINE_BYTES:",
        "        if False:",
        "tests/test_credentials.py::test_an_oversized_record_is_refused_before_security_is_invoked",
    ),
    Mutation(
        "the reported keychain ceiling reflects the real line budget",
        "credentials.py",
        "        return available // 4 * 3",
        "        return available",
        "tests/test_credentials.py::test_a_record_at_the_reported_ceiling_really_fits_the_measured_limit",
    ),
    Mutation(
        "CommandResult redacts stdout, which is the credential on a read",
        "credentials.py",
        '        return f"CommandResult(returncode={self.returncode!r}, stdout=<redacted>)"',
        '        return f"CommandResult(returncode={self.returncode!r}, stdout={self.stdout!r})"',
        "tests/test_credentials.py::test_a_command_result_never_reveals_stdout",
    ),
    Mutation(
        "the directory check runs on the read path too",
        "credentials.py",
        '        _check_directory_security(info, "the development credential directory")\n        try:',
        "        try:",
        "tests/test_credentials.py::test_a_widened_directory_is_refused_on_read_not_only_on_write",
    ),
    Mutation(
        "a missing directory still reads as absent",
        "credentials.py",
        "        try:\n            info = os.stat(self._directory)\n        except FileNotFoundError:\n            return None",
        "        info = os.stat(self._directory)",
        "tests/test_credentials.py::test_a_missing_directory_reads_as_absent_rather_than_failing",
    ),
    Mutation(
        "the records have no instance __dict__",
        "credentials.py",
        "@dataclass(frozen=True, slots=True, weakref_slot=True)\nclass TokenCredential(CredentialMaterial):",
        "@dataclass(frozen=True, weakref_slot=False)\nclass TokenCredential(CredentialMaterial):",
        "tests/test_credentials.py::test_a_record_has_no_instance_dict",
    ),
    Mutation(
        "the records refuse to be pickled at every protocol",
        "credentials.py",
        "    def __reduce__(self) -> tuple[Any, ...]:\n        raise GatewayError(",
        "    def __reduce_unused__(self) -> tuple[Any, ...]:\n        raise GatewayError(",
        "tests/test_credentials.py::test_a_record_refuses_to_be_pickled_at_every_protocol",
    ),
    # -- review round 2 nits -----------------------------------------------
    Mutation(
        "slots=True does not silently remove weak-reference support",
        "credentials.py",
        "@dataclass(frozen=True, slots=True, weakref_slot=True)\nclass TokenCredential(CredentialMaterial):",
        "@dataclass(frozen=True, slots=True)\nclass TokenCredential(CredentialMaterial):",
        "tests/test_credentials.py::test_a_record_can_still_be_weak_referenced",
    ),
    Mutation(
        "the whole credential-material family keeps weak references",
        "auth.py",
        "@dataclass(frozen=True, slots=True, weakref_slot=True)\nclass AuthorizationTransaction(CredentialMaterial):",
        "@dataclass(frozen=True, slots=True)\nclass AuthorizationTransaction(CredentialMaterial):",
        "tests/test_credentials.py::test_every_credential_material_type_supports_weak_references",
    ),
    Mutation(
        "the credential-material base is public, not reached across privately",
        "credentials.py",
        '    "CredentialMaterial",\n',
        "",
        "tests/test_credentials.py::test_the_credential_material_base_is_public",
    ),
    Mutation(
        "refusing pickle does not break copying",
        "credentials.py",
        "    def __deepcopy__(self, memo: dict[int, Any]) -> CredentialMaterial:\n        return self",
        "    pass",
        "tests/test_credentials.py::test_a_record_can_still_be_copied",
    ),
    # -- the positive direction --------------------------------------------
    #
    # A guard that makes the *legitimate* path unreachable fails safe, so a
    # suite of refusals stays green while login is impossible. These mutations
    # break the accepting path and must also be caught. Step 2's review found
    # exactly this shape of hole.
    Mutation(
        "the production origins really admit the documented endpoints",
        "auth.py",
        '        return frozenset(("https", host, 443) for host in PRODUCTION_EGRESS_HOSTS)',
        '        return frozenset(("https", host, 443) for host in {"agent.robinhood.com"})',
        "tests/test_auth.py::test_the_unmutated_production_document_is_accepted",
    ),
    Mutation(
        "the well-known path derivation is right, not merely strict",
        "auth.py",
        'return f"{split.scheme}://{split.netloc}/.well-known/{segment}{path}"',
        'return f"{split.scheme}://{split.netloc}{path}/.well-known/{segment}"',
        "tests/test_auth.py::test_the_protected_resource_url_inserts_the_well_known_segment",
    ),
    Mutation(
        "a valid callback is actually accepted",
        "auth.py",
        "        if path != self._path:",
        "        if True:",
        "tests/test_auth.py::test_a_valid_callback_yields_the_code",
    ),
    Mutation(
        "a live token is served without taking the credential lock",
        "auth.py",
        "        if not token.is_expired(self._clock(), skew_s=self._skew_s):",
        "        if False:",
        # Deliberately *not* `test_a_live_token_is_returned_without_any_request`:
        # that one still passes, because `_refresh` re-reads and short-circuits
        # without any HTTP. The fast path's real property is availability — a
        # read must not start failing with `timeout` because a sibling process
        # is mid-refresh — and that needs a held `flock` to observe.
        "tests/test_auth.py::test_a_live_token_is_served_while_another_process_holds_the_lock",
    ),
    Mutation(
        "a stored credential really round-trips through the serialized form",
        "credentials.py",
        '            "access_token": token.access_token,',
        '            "access_token": token.access_token[:-1],',
        "tests/test_credentials.py::test_an_in_memory_store_round_trips_both_records",
    ),
    Mutation(
        "an OAuth response with duplicate keys is refused",
        "transport.py",
        "                text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_json_constant",
        "                text, parse_constant=_reject_json_constant",
        "tests/test_auth.py::test_a_duplicate_key_in_an_oauth_response_is_refused",
    ),
]

# The stub the "OAuth client carries no bearer token" mutation needs.
_STUB_PROVIDER = '''

class _StubProvider:
    async def access_token(self) -> str:
        return "mutation-token"

'''


def apply(mutation: Mutation) -> str:
    path = SOURCE / mutation.module
    original = path.read_text(encoding="utf-8")
    if mutation.old not in original:
        raise SystemExit(f"mutation target not found: {mutation.label}")
    if original.count(mutation.old) != 1:
        raise SystemExit(f"mutation target is not unique: {mutation.label}")
    mutated = original.replace(mutation.old, mutation.new)
    if "_StubProvider()" in mutation.new:
        mutated = mutated.replace("\ndef _new_json_client(", _STUB_PROVIDER + "\ndef _new_json_client(")
    path.write_text(mutated, encoding="utf-8")
    return original


def restore(mutation: Mutation, original: str) -> None:
    (SOURCE / mutation.module).write_text(original, encoding="utf-8")


def run_test(test: str, verbose: bool) -> tuple[bool, str]:
    environment = dict(os.environ)
    # CPython's pyc header keys on (mtime-seconds, size). A same-size mutation
    # applied inside one second would otherwise reuse stale bytecode and report
    # a false "not caught".
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", test, "-q", "-x", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
    )
    output = completed.stdout + completed.stderr
    if verbose:
        print(output)
    return completed.returncode != 0, output


def main() -> int:
    verbose = "--verbose" in sys.argv
    survivors: list[str] = []
    # Announced up front rather than left to the module docstring: the first
    # sign of trouble is a reviewer watching a silent terminal and deciding the
    # script has hung. Each line below appears only after its subprocess exits.
    print(
        f"{len(MUTATIONS)} mutations, one pytest subprocess each — expect roughly "
        f"{len(MUTATIONS) * 3.7 / 60:.0f} minutes.",
        flush=True,
    )
    for mutation in MUTATIONS:
        original = apply(mutation)
        try:
            caught, output = run_test(mutation.test, verbose)
        finally:
            restore(mutation, original)
        status = "caught" if caught else "SURVIVED"
        print(f"{status:>9}  {mutation.label}")
        if not caught:
            survivors.append(mutation.label)
            print("           " + output.strip().splitlines()[-1] if output.strip() else "")
    print()
    print(f"{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} mutations caught")
    for survivor in survivors:
        print(f"  SURVIVED: {survivor}")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
