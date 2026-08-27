import dataclasses

import pytest

from rh_mcp.config import PRODUCTION_RESOURCE_URL, GatewayConfig, ResourceLimits
from rh_mcp.errors import ErrorCode, GatewayError

DIGEST = "sha256:" + "a" * 64


def _dev(**overrides: object) -> GatewayConfig:
    """A development config that is valid apart from the overridden fields."""
    fields: dict[str, object] = {
        "expected_manifest_digest": DIGEST,
        "mode": "development",
        "credential_adapter": "in_memory",
        "credential_namespace": "dev-test",
        "dev_url": "http://127.0.0.1:9999/mcp",
    }
    fields.update(overrides)
    return GatewayConfig(**fields)  # type: ignore[arg-type]


def test_valid_production_config() -> None:
    config = GatewayConfig(expected_manifest_digest=DIGEST)
    assert config.mode == "production"
    assert config.credential_adapter == "keychain"
    assert config.effective_resource_url == "https://agent.robinhood.com/mcp/trading"


@pytest.mark.parametrize(
    "bad_digest", ["", "sha256:short", "md5:" + "a" * 64, "no-prefix-" + "a" * 64]
)
def test_rejects_malformed_expected_digest(bad_digest: str) -> None:
    with pytest.raises(GatewayError) as excinfo:
        GatewayConfig(expected_manifest_digest=bad_digest)
    assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


def test_production_rejects_dev_url() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(expected_manifest_digest=DIGEST, dev_url="http://localhost:9999")


def test_production_rejects_file_dev_adapter() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(expected_manifest_digest=DIGEST, credential_adapter="file_dev")


def test_production_rejects_dev_namespace_prefix() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(expected_manifest_digest=DIGEST, credential_namespace="dev-anything")


def test_development_requires_a_dev_target() -> None:
    with pytest.raises(GatewayError, match="requires dev_url or dev_stdio_command"):
        GatewayConfig(
            expected_manifest_digest=DIGEST,
            mode="development",
            credential_adapter="in_memory",
            credential_namespace="dev-test",
        )


def test_development_rejects_keychain_adapter() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(
            expected_manifest_digest=DIGEST,
            mode="development",
            credential_adapter="keychain",
            credential_namespace="dev-test",
            dev_url="http://localhost:9999",
        )


def test_development_requires_dev_namespace_prefix() -> None:
    with pytest.raises(GatewayError, match="must use the 'dev-' prefix"):
        GatewayConfig(
            expected_manifest_digest=DIGEST,
            mode="development",
            credential_adapter="in_memory",
            credential_namespace="rh-mcp",
            dev_url="http://localhost:9999",
        )


def test_valid_development_config() -> None:
    config = GatewayConfig(
        expected_manifest_digest=DIGEST,
        mode="development",
        credential_adapter="in_memory",
        credential_namespace="dev-test",
        dev_stdio_command="python",
        dev_stdio_args=("-m", "fake_server"),
    )
    assert config.effective_resource_url is None


def test_callback_host_must_be_loopback_literal() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(expected_manifest_digest=DIGEST, callback_host="0.0.0.0")


def test_callback_port_range() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(expected_manifest_digest=DIGEST, callback_port=80)


@pytest.mark.parametrize(
    "bad_path",
    [
        "callback",
        "/callback?evil=1",
        "/cb\r\nX-Injected: 1",
        "/cb#frag",
        "/a//b",
        "/../etc/passwd",
        "/cb/..",
        "/cb space",
        "/cb%2e%2e",
        "//evil.example.com/cb",
    ],
)
def test_rejects_unsafe_callback_path(bad_path: str) -> None:
    with pytest.raises(GatewayError) as excinfo:
        GatewayConfig(expected_manifest_digest=DIGEST, callback_path=bad_path)
    assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


@pytest.mark.parametrize("good_path", ["/", "/callback", "/oauth/callback", "/cb-1_2.3~x"])
def test_accepts_conservative_callback_path(good_path: str) -> None:
    assert GatewayConfig(expected_manifest_digest=DIGEST, callback_path=good_path).callback_path


def test_rejects_expected_digest_with_trailing_newline() -> None:
    """A digest sourced from a file or CI variable often carries '\\n' (§9)."""
    with pytest.raises(GatewayError) as excinfo:
        GatewayConfig(expected_manifest_digest=DIGEST + "\n")
    assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


class TestDevUrl:
    """§3/§9: a development target can never be the production endpoint."""

    PRODUCTION_SPELLINGS = [
        PRODUCTION_RESOURCE_URL,
        "https://AGENT.ROBINHOOD.COM/mcp/trading",
        "https://Agent.Robinhood.Com/mcp/trading",
        "https://agent.robinhood.com./mcp/trading",
        "https://agent.robinhood.com../mcp/trading",
        "https://agent.robinhood.com:443/mcp/trading",
        "http://agent.robinhood.com/mcp/trading",
        "https://localhost@agent.robinhood.com/mcp/trading",
        "https://127.0.0.1@agent.robinhood.com/mcp/trading",
        "https://user:pass@agent.robinhood.com/mcp/trading",
        "https://agent.robinhood.com\t/mcp/trading",
        "https://agent.robinhood.com\n/mcp/trading",
        "https://agent.robinhood.com /mcp/trading",
        "https://localhost。agent.robinhood.com/mcp/trading",
    ]

    @pytest.mark.parametrize("url", PRODUCTION_SPELLINGS)
    def test_rejects_every_production_spelling(self, url: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url=url)
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize(
        "url",
        [
            "http://attacker.example.com/mcp",
            "https://example.com/mcp",
            "not even a url ://",
            "",
            "localhost:9999",
            "ftp://127.0.0.1/mcp",
            "file:///etc/passwd",
            "http://0.0.0.0:9999/mcp",
            "http://[::]:9999/mcp",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/mcp",
            "http://127.0.0.1.attacker.example.com/mcp",
            "http://localhost.attacker.example.com/mcp",
            "http://127.1/mcp",
            "http://2130706433/mcp",
            "http://[::1]x/mcp",
            "http://[::1]extra:80/mcp",
            "http://[::1]agent.robinhood.com/mcp",
            "http://[127.0.0.1]/mcp",
            "http://[not-an-ipv6]/mcp",
            "http://localhost:/mcp",
            "http://user@127.0.0.1/mcp",
            "http://[::ffff:8.8.8.8]/mcp",
        ],
    )
    def test_rejects_non_loopback_or_unparseable(self, url: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url=url)
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:9999",
            "http://localhost:9999/mcp",
            "https://localhost/mcp",
            "http://LOCALHOST:9999/mcp",
            "http://localhost./mcp",
            "http://127.0.0.1:9999/mcp",
            "http://127.0.0.53/mcp",
            "https://[::1]:8080/mcp",
            "HTTP://127.0.0.1:9999/mcp",
            "http://[::ffff:127.0.0.1]:9999/mcp",
        ],
    )
    def test_accepts_loopback_targets(self, url: str) -> None:
        assert _dev(dev_url=url).effective_resource_url == url

    @pytest.mark.parametrize(
        "url",
        [
            "https://localhost#@agent.robinhood.com/",
            "https://localhost?@agent.robinhood.com/",
            "http://127.0.0.1:9999/mcp?token=abc",
            "http://127.0.0.1:9999/mcp#fragment",
            "http://localhost/mcp?",
            "http://localhost/mcp#",
        ],
    )
    def test_rejects_query_or_fragment(self, url: str) -> None:
        """A dev endpoint needs neither, and §7.3 bars a URL with a query
        from the §3 dev-mode diagnostic that prints this value in step 5."""
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url=url)
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    def test_rejects_whitespace_inside_the_authority(self) -> None:
        """The only case the whitespace guard alone catches.

        `urlsplit` strips the tab and reports the host as `localhost`, so
        without the guard this URL is accepted and stored with an embedded
        tab that a transport would later see.
        """
        with pytest.raises(GatewayError, match="whitespace or control characters"):
            _dev(dev_url="https://local\thost/")

    @pytest.mark.parametrize(
        "url", ["https://local\nhost/", "https://local\rhost/", "https://local host/"]
    )
    def test_rejects_other_whitespace_in_the_authority(self, url: str) -> None:
        with pytest.raises(GatewayError, match="whitespace or control characters"):
            _dev(dev_url=url)

    def test_effective_resource_url_is_never_production_in_development(self) -> None:
        for url in self.PRODUCTION_SPELLINGS:
            with pytest.raises(GatewayError):
                assert _dev(dev_url=url).effective_resource_url is None

    def test_error_does_not_echo_url_query(self) -> None:
        """§7.3: public errors never contain URLs with queries."""
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url="http://evil.example.com/mcp?token=SUPERSECRETVALUE")
        assert "SUPERSECRETVALUE" not in str(excinfo.value)
        assert "SUPERSECRETVALUE" not in repr(excinfo.value)

    def test_ipv4_mapped_loopback_is_accepted_on_every_supported_python(self) -> None:
        """`IPv6Address.is_loopback` for a mapped address is patch-dependent.

        True on 3.11.15/3.12.13/3.13.14 but False on 3.12.3, so this must go
        through `ipv4_mapped` delegation. Removing that branch as a "no-op"
        broke CI, which runs 3.12.3.
        """
        assert _dev(dev_url="http://[::ffff:127.0.0.1]:9999/mcp").dev_url is not None

    def test_ipv4_mapped_public_address_is_still_rejected(self) -> None:
        """The dangerous direction, pinned under both semantics."""
        with pytest.raises(GatewayError):
            _dev(dev_url="http://[::ffff:8.8.8.8]/mcp")

    @pytest.mark.parametrize(
        "url",
        [
            "http://[::1]agent.robinhood.com/mcp",
            "http://[::1]extra:80/mcp",
            "http://[::1]x/mcp",
        ],
    )
    def test_rejects_trailing_garbage_after_a_bracketed_literal(self, url: str) -> None:
        """On 3.12.3 `urlsplit` drops it and reports the host as '::1'.

        The authority must be validated as a whole, or we validate one reading
        of the URL and store a string another client may read differently.
        Which guard rejects first differs by version — the port parse raises
        on 3.11/3.12.13/3.13, the authority pattern catches it on 3.12.3 — so
        this pins the rejection, not the message.
        """
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url=url)
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    def test_parse_failure_does_not_chain_a_url_bearing_exception(self) -> None:
        """`urlsplit` reports a bad port by quoting it; §7.3 forbids a traceback."""
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url="http://127.0.0.1:PORTSECRET/mcp")
        assert "PORTSECRET" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__

    def test_rejects_naming_two_dev_targets(self) -> None:
        with pytest.raises(GatewayError) as excinfo:
            _dev(dev_url="http://127.0.0.1:9999/mcp", dev_stdio_command="python")
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    def test_rejects_stdio_settings_alongside_dev_url(self) -> None:
        with pytest.raises(GatewayError):
            _dev(dev_url="http://127.0.0.1:9999/mcp", dev_stdio_env={"FOO": "bar"})


class TestCredentialNamespace:
    """§5.2: the namespace is the separation control between stores."""

    @pytest.mark.parametrize("namespace", ["", "   ", "\t", "rh mcp", "rh/mcp", "-rh", "rh\nmcp"])
    def test_production_rejects_empty_or_unsafe(self, namespace: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig(expected_manifest_digest=DIGEST, credential_namespace=namespace)
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize("namespace", ["dev-", "dev- x", "dev-\t"])
    def test_development_rejects_unsafe(self, namespace: str) -> None:
        with pytest.raises(GatewayError):
            _dev(credential_namespace=namespace)

    def test_accepts_the_defaults(self) -> None:
        assert GatewayConfig(expected_manifest_digest=DIGEST).credential_namespace == "rh-mcp"
        assert _dev(credential_namespace="dev-test").credential_namespace == "dev-test"


@pytest.mark.parametrize("field_name", ["dev_url", "dev_stdio_command"])
def test_production_rejects_empty_string_dev_fields(field_name: str) -> None:
    """The production guard must test presence, not truthiness."""
    with pytest.raises(GatewayError) as excinfo:
        GatewayConfig(expected_manifest_digest=DIGEST, **{field_name: ""})  # type: ignore[arg-type]
    assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


class TestDevStdioEnv:
    def test_is_copied_at_construction(self) -> None:
        source = {"FOO": "bar"}
        config = _dev(dev_url=None, dev_stdio_command="python", dev_stdio_env=source)
        source["LD_PRELOAD"] = "/tmp/evil.so"
        assert dict(config.dev_stdio_env) == {"FOO": "bar"}

    def test_is_not_mutable_through_the_config(self) -> None:
        config = _dev(dev_url=None, dev_stdio_command="python", dev_stdio_env={"FOO": "bar"})
        with pytest.raises(TypeError):
            config.dev_stdio_env["LD_PRELOAD"] = "/tmp/evil.so"  # type: ignore[index]

    def test_stdio_args_coerced_to_tuple(self) -> None:
        args = ["-m", "fake_server"]
        config = _dev(dev_url=None, dev_stdio_command="python", dev_stdio_args=args)
        args.append("--evil")
        assert config.dev_stdio_args == ("-m", "fake_server")


# field name -> hard maximum. Hard-coded on purpose: if a ceiling in config.py
# is loosened, this table must be edited too. Every field is a budget where a
# larger number is more permissive, so a single uniform bounds contract holds.
LIMIT_BOUNDS: dict[str, float] = {
    "connect_timeout_s": 30.0,
    "read_timeout_s": 60.0,
    "total_timeout_s": 120.0,
    "oauth_callback_timeout_s": 600.0,
    "discovery_timeout_s": 120.0,
    "pagination_timeout_s": 120.0,
    "max_discovery_pages": 200,
    "max_discovery_tools": 5_000,
    "max_discovery_bytes": 16_777_216,
    "max_concurrent_calls": 32,
    "max_refresh_attempts": 1,
    "max_request_bytes": 1_048_576,
    "max_response_bytes": 16_777_216,
    "max_json_depth": 64,
    "max_discovery_depth": 64,
    "max_response_nodes": 1_000_000,
    "max_response_string_length": 1_048_576,
}


class TestResourceLimits:
    def test_defaults_are_valid(self) -> None:
        ResourceLimits()

    def test_bounds_table_covers_every_field(self) -> None:
        assert set(LIMIT_BOUNDS) == {f.name for f in dataclasses.fields(ResourceLimits)}

    @pytest.mark.parametrize("name", sorted(LIMIT_BOUNDS))
    def test_defaults_are_within_the_documented_ceiling(self, name: str) -> None:
        default = getattr(ResourceLimits(), name)
        assert 1 <= default <= LIMIT_BOUNDS[name]

    @pytest.mark.parametrize("name", sorted(LIMIT_BOUNDS))
    def test_rejects_zero(self, name: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            ResourceLimits(**{name: 0})
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize("name", sorted(LIMIT_BOUNDS))
    def test_rejects_negative(self, name: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            ResourceLimits(**{name: -1})
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize("name", sorted(LIMIT_BOUNDS))
    def test_rejects_above_ceiling(self, name: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            ResourceLimits(**{name: LIMIT_BOUNDS[name] + 1})
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize("name", sorted(LIMIT_BOUNDS))
    def test_accepts_exactly_the_ceiling(self, name: str) -> None:
        ceiling = LIMIT_BOUNDS[name]
        assert getattr(ResourceLimits(**{name: ceiling}), name) == ceiling

    def test_refresh_attempts_ceiling_matches_the_single_refresh_rule(self) -> None:
        """§5.1/§8: a coordinated refresh may be attempted once."""
        with pytest.raises(GatewayError):
            ResourceLimits(max_refresh_attempts=2)


class TestFromEnv:
    def test_requires_expected_digest(self) -> None:
        with pytest.raises(GatewayError, match="RH_MCP_EXPECTED_MANIFEST_DIGEST"):
            GatewayConfig.from_env(environ={})

    def test_round_trip_production(self) -> None:
        config = GatewayConfig.from_env(
            environ={
                "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                "RH_MCP_CALLBACK_PORT": "9000",
                "RH_MCP_CALLBACK_HOST": "::1",
            }
        )
        assert config.expected_manifest_digest == DIGEST
        assert config.callback_port == 9000
        assert config.callback_host == "::1"

    def test_round_trip_development(self) -> None:
        config = GatewayConfig.from_env(
            environ={
                "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                "RH_MCP_MODE": "development",
                "RH_MCP_CREDENTIAL_ADAPTER": "in_memory",
                "RH_MCP_CREDENTIAL_NAMESPACE": "dev-test",
                "RH_MCP_DEV_STDIO_COMMAND": "python",
                "RH_MCP_DEV_STDIO_ARGS": "-m fake_server --flag value",
                "RH_MCP_DEV_STDIO_ENV": "FOO=bar, BAZ=qux",
            }
        )
        assert config.mode == "development"
        assert config.dev_stdio_command == "python"
        assert config.dev_stdio_args == ("-m", "fake_server", "--flag", "value")
        assert config.dev_stdio_env == {"FOO": "bar", "BAZ": "qux"}

    def test_invalid_callback_port_is_configuration_error(self) -> None:
        with pytest.raises(GatewayError, match="RH_MCP_CALLBACK_PORT"):
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_CALLBACK_PORT": "not-a-number",
                }
            )

    def test_malformed_dev_env_pair_is_configuration_error(self) -> None:
        with pytest.raises(GatewayError, match="KEY=VALUE"):
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_DEV_STDIO_ENV": "not-a-pair",
                }
            )

    def test_malformed_dev_env_pair_does_not_echo_its_value(self) -> None:
        """§7.3: RH_MCP_DEV_STDIO_ENV carries secrets; never reflect one back."""
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_DEV_STDIO_ENV": "TOKEN=abc,supersecret-bearer-value",
                }
            )
        assert "supersecret-bearer-value" not in str(excinfo.value)
        assert "supersecret-bearer-value" not in repr(excinfo.value)
        assert "abc" not in str(excinfo.value)

    def test_dev_env_pair_with_bad_key_does_not_echo_its_value(self) -> None:
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_DEV_STDIO_ENV": "BAD KEY=supersecret-bearer-value",
                }
            )
        assert "supersecret-bearer-value" not in str(excinfo.value)

    def test_dev_url_from_env_is_validated(self) -> None:
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_MODE": "development",
                    "RH_MCP_CREDENTIAL_ADAPTER": "file_dev",
                    "RH_MCP_CREDENTIAL_NAMESPACE": "dev-x",
                    "RH_MCP_DEV_URL": PRODUCTION_RESOURCE_URL,
                }
            )
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


class TestCallbackTimeoutIsReachable:
    """The one tunable a human-in-the-loop login depends on (§5.1, §9).

    The original 120s default was not survivable — a real sign-in is a
    password, a 2FA code, and sometimes an approval in a phone app — and it
    was not settable from the environment, so a user whose login took longer
    could not complete `rh-mcp login` at all.
    """

    def test_the_default_allows_a_realistic_sign_in(self) -> None:
        assert GatewayConfig(expected_manifest_digest=DIGEST).limits.oauth_callback_timeout_s >= 300

    def test_it_can_be_raised_from_the_environment(self) -> None:
        config = GatewayConfig.from_env(
            environ={
                "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                "RH_MCP_CALLBACK_TIMEOUT_S": "480",
            }
        )
        assert config.limits.oauth_callback_timeout_s == 480.0

    def test_it_is_still_bounded_by_the_reviewed_ceiling(self) -> None:
        """§5.1 wants a short window; configurable is not unbounded."""
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_CALLBACK_TIMEOUT_S": "99999",
                }
            )
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    @pytest.mark.parametrize("raw", ["not-a-number", "", "0", "-5"])
    def test_a_malformed_value_is_a_configuration_error(self, raw: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig.from_env(
                environ={
                    "RH_MCP_EXPECTED_MANIFEST_DIGEST": DIGEST,
                    "RH_MCP_CALLBACK_TIMEOUT_S": raw,
                }
            )
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


class TestDiscoveryDepthIsSeparate:
    """A `tools/list` page is schemas *about* data, not data (§8).

    The real Robinhood surface exceeded the 16-level result bound on the first
    authenticated discovery run: every level of the described data costs two or
    three in the schema, on top of the JSON-RPC envelope. §8 already gave
    discovery its own page, tool and byte bounds — depth was the one dimension
    it did not get.
    """

    def test_discovery_is_deeper_than_the_result_bound(self) -> None:
        limits = ResourceLimits()
        assert limits.max_discovery_depth > limits.max_json_depth

    def test_it_is_still_bounded(self) -> None:
        with pytest.raises(GatewayError):
            ResourceLimits(max_discovery_depth=1000)

    def test_it_still_rejects_zero(self) -> None:
        with pytest.raises(GatewayError):
            ResourceLimits(max_discovery_depth=0)


class TestTheMutationSwitchCannotFailOpen:
    """Two ways the kill switch opened by accident, both found by review.

    Neither was visible to the suite. Every `GatewayConfig` in this repository
    is built with keywords and with a real bool, so 1219 tests agreed the
    switch worked while both holes were present — the same blindness this
    change was written to fix in `mutates` itself.
    """

    def test_it_cannot_be_bound_positionally(self) -> None:
        """It was inserted ahead of `mode`, so an existing positional call
        turned it on.

        `GatewayConfig(digest, "development")` is a call a 0.3.3 consumer could
        already have written. With the field ordinary and second, it bound
        "development" here — truthy, gate open — and left `mode` at
        "production", so the caller lost dev mode and gained writes at once,
        silently.
        """
        positional = GatewayConfig(
            DIGEST,
            "development",
            "in_memory",
            "dev-positional",
            dev_url="http://127.0.0.1:9/mcp",
        )

        # The second positional now reaches `mode`, where the caller meant it
        # to go, and the switch is not in the positional order at all.
        assert positional.mode == "development"
        assert positional.allow_mutations is False

        # And it cannot be reached by counting further along either. Moving
        # the field to the end would also have fixed the call above while
        # leaving some argument count that lands on it; `kw_only` removes it
        # from the positional order entirely, which is the property asserted.
        switch = next(f for f in dataclasses.fields(GatewayConfig) if f.name == "allow_mutations")
        assert switch.kw_only is True
        assert "allow_mutations" not in [
            f.name for f in dataclasses.fields(GatewayConfig) if not f.kw_only
        ]

    @pytest.mark.parametrize("value", ["false", "no", "0", "", 1, 0, [1], None])
    def test_only_a_real_bool_is_accepted(self, value: object) -> None:
        """The check downstream is `and not allow_mutations`, a truthiness
        test.

        So `"false"` — what a YAML, JSON, env or argparse layer produces —
        opened the gate, as did `"no"` and `"0"`. Falsy non-bools are refused
        too: they happen to close the gate, but a config that silently accepts
        `None` for a security switch is one that accepted a mistake.
        """
        with pytest.raises(GatewayError):
            GatewayConfig(expected_manifest_digest=DIGEST, allow_mutations=value)  # type: ignore[arg-type]

    def test_a_real_bool_is_still_accepted(self) -> None:
        """Otherwise the parametrised test above passes on a config that
        refuses everything."""
        assert (
            GatewayConfig(expected_manifest_digest=DIGEST, allow_mutations=True)
        ).allow_mutations is True
        assert (
            GatewayConfig(expected_manifest_digest=DIGEST, allow_mutations=False)
        ).allow_mutations is False
