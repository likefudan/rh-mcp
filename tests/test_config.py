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
