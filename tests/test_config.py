import pytest

from rh_mcp.config import GatewayConfig, ResourceLimits
from rh_mcp.errors import ErrorCode, GatewayError

DIGEST = "sha256:" + "a" * 64


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


def test_callback_path_must_start_with_slash() -> None:
    with pytest.raises(GatewayError):
        GatewayConfig(expected_manifest_digest=DIGEST, callback_path="callback")


class TestResourceLimits:
    def test_defaults_are_valid(self) -> None:
        ResourceLimits()

    def test_rejects_zero(self) -> None:
        with pytest.raises(GatewayError):
            ResourceLimits(connect_timeout_s=0)

    def test_rejects_above_ceiling(self) -> None:
        with pytest.raises(GatewayError):
            ResourceLimits(max_concurrent_calls=1000)


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
