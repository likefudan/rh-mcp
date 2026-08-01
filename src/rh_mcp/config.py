"""Validated gateway configuration. No I/O (DESIGN.md §3, §9)."""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, NoReturn

from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.models import DIGEST_PATTERN

PRODUCTION_RESOURCE_URL = "https://agent.robinhood.com/mcp/trading"

Mode = Literal["production", "development"]
CredentialAdapter = Literal["keychain", "file_dev", "in_memory"]

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_PRODUCTION_ADAPTERS: frozenset[CredentialAdapter] = frozenset({"keychain"})
_DEVELOPMENT_ADAPTERS: frozenset[CredentialAdapter] = frozenset({"file_dev", "in_memory"})
_DEV_NAMESPACE_PREFIX = "dev-"


def _fail(message: str) -> NoReturn:
    raise GatewayError(ErrorCode.CONFIGURATION_ERROR, message)


def _bounded(name: str, value: float, *, ceiling: float) -> None:
    if not (0 < value <= ceiling):
        _fail(f"{name} must be > 0 and <= {ceiling}, got {value!r}")


def _bounded_int(name: str, value: int, *, ceiling: int) -> None:
    if not (0 < value <= ceiling):
        _fail(f"{name} must be > 0 and <= {ceiling}, got {value!r}")


@dataclass(frozen=True)
class ResourceLimits:
    """Bounded timeouts/concurrency/payload limits (DESIGN.md §8)."""

    connect_timeout_s: float = 5.0
    read_timeout_s: float = 10.0
    total_timeout_s: float = 30.0
    oauth_callback_timeout_s: float = 120.0
    discovery_timeout_s: float = 30.0
    max_discovery_pages: int = 20
    max_discovery_tools: int = 500
    max_concurrent_calls: int = 4
    max_refresh_attempts: int = 1
    max_request_bytes: int = 65_536
    max_response_bytes: int = 1_048_576
    max_json_depth: int = 16

    def __post_init__(self) -> None:
        _bounded("connect_timeout_s", self.connect_timeout_s, ceiling=30.0)
        _bounded("read_timeout_s", self.read_timeout_s, ceiling=60.0)
        _bounded("total_timeout_s", self.total_timeout_s, ceiling=120.0)
        _bounded("oauth_callback_timeout_s", self.oauth_callback_timeout_s, ceiling=600.0)
        _bounded("discovery_timeout_s", self.discovery_timeout_s, ceiling=120.0)
        _bounded_int("max_discovery_pages", self.max_discovery_pages, ceiling=200)
        _bounded_int("max_discovery_tools", self.max_discovery_tools, ceiling=5_000)
        _bounded_int("max_concurrent_calls", self.max_concurrent_calls, ceiling=32)
        _bounded_int("max_refresh_attempts", self.max_refresh_attempts, ceiling=3)
        _bounded_int("max_request_bytes", self.max_request_bytes, ceiling=1_048_576)
        _bounded_int("max_response_bytes", self.max_response_bytes, ceiling=16_777_216)
        _bounded_int("max_json_depth", self.max_json_depth, ceiling=64)


@dataclass(frozen=True)
class GatewayConfig:
    """Validated production or development configuration (DESIGN.md §3, §9).

    Selecting or loading the *active* manifest is not this module's job —
    that belongs to `manifest.py`. This only validates and stores the
    `expected_manifest_digest` a consumer independently pins.
    """

    expected_manifest_digest: str
    mode: Mode = "production"
    credential_adapter: CredentialAdapter = "keychain"
    credential_namespace: str = "rh-mcp"
    callback_host: str = "127.0.0.1"
    callback_port: int = 8765
    callback_path: str = "/callback"
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    dev_url: str | None = None
    dev_stdio_command: str | None = None
    dev_stdio_args: tuple[str, ...] = ()
    dev_stdio_env: Mapping[str, str] = field(default_factory=dict)
    dev_stdio_cwd: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("production", "development"):
            _fail(f"mode must be 'production' or 'development', got {self.mode!r}")
        if not DIGEST_PATTERN.match(self.expected_manifest_digest):
            _fail(
                "expected_manifest_digest must match 'sha256:<64 hex chars>', "
                f"got {self.expected_manifest_digest!r}"
            )
        if self.callback_host not in _LOOPBACK_HOSTS:
            _fail(
                f"callback_host must be an explicit loopback literal {sorted(_LOOPBACK_HOSTS)}, "
                f"got {self.callback_host!r}"
            )
        if not (1024 <= self.callback_port <= 65535):
            _fail(f"callback_port must be in [1024, 65535], got {self.callback_port!r}")
        if not self.callback_path.startswith("/"):
            _fail(f"callback_path must start with '/', got {self.callback_path!r}")
        if not isinstance(self.limits, ResourceLimits):
            _fail("limits must be a ResourceLimits instance")

        has_dev_target = bool(self.dev_url) or bool(self.dev_stdio_command)
        if self.mode == "production":
            if has_dev_target:
                _fail("dev_url/dev_stdio_* are not allowed when mode='production'")
            if self.dev_stdio_args or self.dev_stdio_env or self.dev_stdio_cwd:
                _fail("dev_stdio_args/env/cwd are not allowed when mode='production'")
            if self.credential_adapter not in _PRODUCTION_ADAPTERS:
                _fail(
                    f"credential_adapter must be one of {sorted(_PRODUCTION_ADAPTERS)} "
                    f"when mode='production', got {self.credential_adapter!r}"
                )
            if self.credential_namespace.startswith(_DEV_NAMESPACE_PREFIX):
                _fail(
                    "credential_namespace must not use the "
                    f"{_DEV_NAMESPACE_PREFIX!r} prefix when mode='production'"
                )
        else:
            if not has_dev_target:
                _fail(
                    "development mode requires dev_url or dev_stdio_command "
                    "to name a non-production target"
                )
            if self.credential_adapter not in _DEVELOPMENT_ADAPTERS:
                _fail(
                    f"credential_adapter must be one of {sorted(_DEVELOPMENT_ADAPTERS)} "
                    f"when mode='development', got {self.credential_adapter!r}"
                )
            if not self.credential_namespace.startswith(_DEV_NAMESPACE_PREFIX):
                _fail(
                    f"credential_namespace must use the {_DEV_NAMESPACE_PREFIX!r} prefix "
                    "when mode='development', to keep it separate from a production store"
                )

    @property
    def effective_resource_url(self) -> str | None:
        """The endpoint the transport should connect to.

        `None` in development mode when a stdio target was chosen instead of
        an HTTP URL.
        """
        if self.mode == "production":
            return PRODUCTION_RESOURCE_URL
        return self.dev_url

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> GatewayConfig:
        env = os.environ if environ is None else environ

        digest = env.get("RH_MCP_EXPECTED_MANIFEST_DIGEST")
        if digest is None:
            _fail("RH_MCP_EXPECTED_MANIFEST_DIGEST is required")

        kwargs: dict[str, object] = {"expected_manifest_digest": digest}

        if "RH_MCP_MODE" in env:
            kwargs["mode"] = env["RH_MCP_MODE"]
        if "RH_MCP_CREDENTIAL_ADAPTER" in env:
            kwargs["credential_adapter"] = env["RH_MCP_CREDENTIAL_ADAPTER"]
        if "RH_MCP_CREDENTIAL_NAMESPACE" in env:
            kwargs["credential_namespace"] = env["RH_MCP_CREDENTIAL_NAMESPACE"]
        if "RH_MCP_CALLBACK_HOST" in env:
            kwargs["callback_host"] = env["RH_MCP_CALLBACK_HOST"]
        if "RH_MCP_CALLBACK_PORT" in env:
            raw_port = env["RH_MCP_CALLBACK_PORT"]
            try:
                kwargs["callback_port"] = int(raw_port)
            except ValueError:
                _fail(f"RH_MCP_CALLBACK_PORT must be an integer, got {raw_port!r}")
        if "RH_MCP_CALLBACK_PATH" in env:
            kwargs["callback_path"] = env["RH_MCP_CALLBACK_PATH"]
        if "RH_MCP_DEV_URL" in env:
            kwargs["dev_url"] = env["RH_MCP_DEV_URL"]
        if "RH_MCP_DEV_STDIO_COMMAND" in env:
            kwargs["dev_stdio_command"] = env["RH_MCP_DEV_STDIO_COMMAND"]
        if "RH_MCP_DEV_STDIO_ARGS" in env:
            kwargs["dev_stdio_args"] = tuple(shlex.split(env["RH_MCP_DEV_STDIO_ARGS"]))
        if "RH_MCP_DEV_STDIO_ENV" in env:
            kwargs["dev_stdio_env"] = _parse_env_pairs(env["RH_MCP_DEV_STDIO_ENV"])
        if "RH_MCP_DEV_STDIO_CWD" in env:
            kwargs["dev_stdio_cwd"] = env["RH_MCP_DEV_STDIO_CWD"]

        return cls(**kwargs)  # type: ignore[arg-type]


def _parse_env_pairs(raw: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            _fail(f"env pair {item!r} must be in KEY=VALUE form")
        key, _, value = item.partition("=")
        pairs[key] = value
    return pairs
