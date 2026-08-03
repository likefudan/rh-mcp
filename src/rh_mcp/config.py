"""Validated gateway configuration. No I/O (DESIGN.md §3, §9)."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, NoReturn
from urllib.parse import urlsplit

from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.models import is_digest

PRODUCTION_RESOURCE_URL = "https://agent.robinhood.com/mcp/trading"

Mode = Literal["production", "development"]
CredentialAdapter = Literal["keychain", "file_dev", "in_memory"]

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_PRODUCTION_ADAPTERS: frozenset[CredentialAdapter] = frozenset({"keychain"})
_DEVELOPMENT_ADAPTERS: frozenset[CredentialAdapter] = frozenset({"file_dev", "in_memory"})
_DEV_NAMESPACE_PREFIX = "dev-"

# The only registrable hostname a development target may use. Everything else
# must be a loopback IP literal, which is what makes a production spelling of
# `dev_url` unrepresentable rather than merely blocklisted (DESIGN.md §3, §9).
_LOOPBACK_HOSTNAMES = frozenset({"localhost"})
_DEV_URL_SCHEMES = frozenset({"http", "https"})

# `host[:port]` or `[ipv6-literal][:port]`, and nothing else — no userinfo, no
# trailing characters after a bracketed literal. Matched against the whole
# authority so validation does not depend on `urlsplit`'s patch-dependent
# strictness (see `_validate_dev_url`).
_AUTHORITY_PATTERN = re.compile(
    r"\A(?:\[(?P<v6>[0-9A-Fa-f:.]+)\]|(?P<host>[A-Za-z0-9._-]+))(?::(?P<port>[0-9]{1,5}))?\Z"
)

# A registered redirect URI is compared against a request path that carries no
# query or fragment, so an "exact callback path" (§5.1) is one path with
# unreserved characters only: no query, fragment, whitespace, CR/LF, percent
# escape, empty segment, or dot segment.
_CALLBACK_PATH_PATTERN = re.compile(r"\A/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?\Z")

# Conventional environment-variable name shape; a value is never echoed.
_ENV_KEY_PATTERN = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

# §5.2 makes the namespace the separation control between the production
# store, the development store, and any future write client. An empty or
# whitespace-only value is the most likely thing to collide with a store's
# default or an unset variable, so require a conservative, non-empty name.
_CREDENTIAL_NAMESPACE_PATTERN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?\Z")


def _fail(message: str, *, suppress_context: bool = False) -> NoReturn:
    """Raise the stable configuration error (DESIGN.md §7.3).

    `suppress_context` drops the chained exception when the underlying error
    quotes the input it choked on — `urlsplit` reports a bad port by echoing
    it, which would put a fragment of a URL into a displayed traceback.
    """
    error = GatewayError(ErrorCode.CONFIGURATION_ERROR, message)
    if suppress_context:
        raise error from None
    raise error


def _bounded(name: str, value: float, *, ceiling: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{name} must be a number, got {type(value).__name__}")
    if not (0 < value <= ceiling):
        _fail(f"{name} must be > 0 and <= {ceiling}, got {value!r}")


def _bounded_int(name: str, value: int, *, ceiling: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be an int, got {type(value).__name__}")
    if not (0 < value <= ceiling):
        _fail(f"{name} must be > 0 and <= {ceiling}, got {value!r}")


def _is_loopback_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an IP literal is loopback, consistently across supported Pythons.

    DO NOT simplify this to `address.is_loopback`. For an IPv4-mapped IPv6
    address, `IPv6Address.is_loopback` is **patch-version dependent** —
    CPython changed it to delegate to the embedded IPv4 address, and that
    landed in a later 3.12.x than 3.12.3. Measured directly:

        3.11.15  IPv6Address('::ffff:127.0.0.1').is_loopback -> True
        3.12.3   IPv6Address('::ffff:127.0.0.1').is_loopback -> False
        3.12.13  IPv6Address('::ffff:127.0.0.1').is_loopback -> True
        3.13.14  IPv6Address('::ffff:127.0.0.1').is_loopback -> True

    `ipv4_mapped` delegation is True on every one of those, so it is the
    version-independent spelling. This branch was once removed as a "no-op"
    because every interpreter to hand happened to be a newer patch release;
    CI on 3.12.3 then rejected a legitimate loopback dev URL. The
    `::ffff:127.0.0.1` / `::ffff:8.8.8.8` accept-reject tests pin both
    directions — keep them.
    """
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped.is_loopback
    return address.is_loopback


def _is_loopback_host(host: str) -> bool:
    """Whether `host` can only ever resolve to this machine.

    Names are an allowlist of exactly `localhost`; everything else must be an
    IP literal that `ipaddress` agrees is loopback. A name such as
    `localhost.attacker.example.com`, a decimal or shorthand IPv4 form, or any
    routable literal therefore fails closed.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in _LOOPBACK_HOSTNAMES
    return _is_loopback_address(address)


def _validate_dev_url(url: str) -> None:
    """Constrain a development endpoint to a local server (DESIGN.md §3, §9).

    The production endpoint, its OAuth hosts, and any other remote host are
    unrepresentable here by construction: a development login must not be able
    to run an unpinned OAuth flow against production and drop a write-capable
    `internal`-scope token into a development credential store.

    Errors report the scheme or host at most, never the URL: §7.3 forbids
    putting a URL with a query into a public error.
    """
    # `urlsplit` silently strips ASCII tab/newline, so a value containing them
    # would be validated in a different form than the one stored.
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        _fail("dev_url must not contain whitespace or control characters")

    try:
        parsed = urlsplit(url)
        _port = parsed.port  # raises ValueError on a malformed port
    except ValueError:
        _fail("dev_url must be a parseable http(s) URL", suppress_context=True)

    scheme = parsed.scheme.lower()
    if scheme not in _DEV_URL_SCHEMES:
        _fail(f"dev_url scheme must be 'http' or 'https', got {scheme!r}")
    # A dev endpoint needs neither, and both are components nothing here
    # validates that would ride along into the §3 dev-mode diagnostic — which
    # §7.3 forbids from carrying a URL with a query. Checked against the raw
    # string, not the parsed components: the delimiter is what matters,
    # wherever it appears.
    if "?" in url:
        _fail("dev_url must not contain a query")
    if "#" in url:
        _fail("dev_url must not contain a fragment")
    if "@" in parsed.netloc:
        _fail("dev_url must not contain userinfo")

    # The authority is matched here rather than read off `parsed.hostname`,
    # because how strictly `urlsplit` validates a bracketed IPv6 authority is
    # *also* patch-version dependent. Measured directly on
    # `http://[::1]extra:80/mcp`:
    #
    #     3.11.15  hostname -> ValueError
    #     3.12.3   hostname -> '::1'        (trailing garbage silently dropped)
    #     3.12.13  hostname -> ValueError
    #     3.13.14  hostname -> ValueError
    #
    # Trusting `hostname` on 3.12.3 means validating one reading of the
    # authority while storing a string another client may read differently —
    # the same parser-differential the whitespace guard above exists to stop,
    # and this one fails *open*. Matching the whole authority ourselves is
    # version-independent.
    authority = _AUTHORITY_PATTERN.fullmatch(parsed.netloc)
    if authority is None:
        _fail("dev_url authority must be a plain host or [ipv6 literal] with an optional port")

    literal = authority.group("v6")
    if literal is not None:
        try:
            address = ipaddress.IPv6Address(literal)
        except ValueError:
            _fail("dev_url bracketed authority must be an IPv6 literal", suppress_context=True)
        if not _is_loopback_address(address):
            _fail(
                "dev_url host must be a loopback literal or 'localhost' so a development "
                f"target can never be a remote endpoint, got {literal!r}"
            )
        return

    # A trailing root label ('localhost.') is the same name; strip it before
    # the comparison so the allowlist cannot be side-stepped by spelling.
    host = authority.group("host").lower().rstrip(".")
    if not _is_loopback_host(host):
        _fail(
            "dev_url host must be a loopback literal or 'localhost' so a development "
            f"target can never be a remote endpoint, got {host!r}"
        )


@dataclass(frozen=True)
class ResourceLimits:
    """Bounded timeouts/concurrency/payload limits (DESIGN.md §8).

    Every bound §8 enumerates that is a *budget* has a field here, including
    the response node count and string length that stop a depth- and
    byte-bounded payload from still being a decode bomb. Ceilings are hard
    maximums: a deployment may tighten a limit but never loosen one past the
    reviewed value, and a larger number is always more permissive.

    A repeated pagination cursor is deliberately not a field. §6.2 makes it a
    fail-closed readiness condition alongside "does not terminate", not a
    budget, so step 3 enforces it directly in `transport.py` rather than
    offering a knob that could only ever hold one value.
    """

    connect_timeout_s: float = 5.0
    read_timeout_s: float = 10.0
    total_timeout_s: float = 30.0
    # 120s was the original value and it is not survivable in practice: a real
    # login is a password, a 2FA code, and sometimes an approval in a phone
    # app. When the budget expires the listener closes, so the browser's
    # redirect arrives at a dead port and the user sees ERR_CONNECTION_REFUSED
    # with no clue that a timeout caused it. §5.1 wants a *short* window, not
    # an unusable one — the window is only reachable over loopback and only
    # accepts a code carrying the expected `state`, so minutes are defensible
    # where hours would not be. Settable via RH_MCP_CALLBACK_TIMEOUT_S up to
    # the ceiling below.
    oauth_callback_timeout_s: float = 300.0
    discovery_timeout_s: float = 30.0
    pagination_timeout_s: float = 60.0
    max_discovery_pages: int = 20
    max_discovery_tools: int = 500
    max_discovery_bytes: int = 4_194_304
    max_concurrent_calls: int = 4
    # §5.1/§8: a coordinated refresh may be attempted once. The ceiling equals
    # the default so no configuration can exceed the design's own bound.
    max_refresh_attempts: int = 1
    max_request_bytes: int = 65_536
    max_response_bytes: int = 1_048_576
    max_json_depth: int = 16
    max_response_nodes: int = 100_000
    max_response_string_length: int = 262_144

    def __post_init__(self) -> None:
        _bounded("connect_timeout_s", self.connect_timeout_s, ceiling=30.0)
        _bounded("read_timeout_s", self.read_timeout_s, ceiling=60.0)
        _bounded("total_timeout_s", self.total_timeout_s, ceiling=120.0)
        _bounded("oauth_callback_timeout_s", self.oauth_callback_timeout_s, ceiling=600.0)
        _bounded("discovery_timeout_s", self.discovery_timeout_s, ceiling=120.0)
        _bounded("pagination_timeout_s", self.pagination_timeout_s, ceiling=120.0)
        _bounded_int("max_discovery_pages", self.max_discovery_pages, ceiling=200)
        _bounded_int("max_discovery_tools", self.max_discovery_tools, ceiling=5_000)
        _bounded_int("max_discovery_bytes", self.max_discovery_bytes, ceiling=16_777_216)
        _bounded_int("max_concurrent_calls", self.max_concurrent_calls, ceiling=32)
        _bounded_int("max_refresh_attempts", self.max_refresh_attempts, ceiling=1)
        _bounded_int("max_request_bytes", self.max_request_bytes, ceiling=1_048_576)
        _bounded_int("max_response_bytes", self.max_response_bytes, ceiling=16_777_216)
        _bounded_int("max_json_depth", self.max_json_depth, ceiling=64)
        _bounded_int("max_response_nodes", self.max_response_nodes, ceiling=1_000_000)
        _bounded_int(
            "max_response_string_length", self.max_response_string_length, ceiling=1_048_576
        )


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
        if not is_digest(self.expected_manifest_digest):
            _fail(
                "expected_manifest_digest must match 'sha256:<64 lowercase hex chars>' "
                "exactly, with no surrounding whitespace or newline, got "
                f"{self.expected_manifest_digest!r}"
            )
        if not _CREDENTIAL_NAMESPACE_PATTERN.fullmatch(self.credential_namespace):
            _fail(
                "credential_namespace must be 1-64 characters of letters, digits, '.', "
                "'_' or '-', starting and ending alphanumeric, got "
                f"{self.credential_namespace!r}"
            )
        if self.callback_host not in _LOOPBACK_HOSTS:
            _fail(
                f"callback_host must be an explicit loopback literal {sorted(_LOOPBACK_HOSTS)}, "
                f"got {self.callback_host!r}"
            )
        if not (1024 <= self.callback_port <= 65535):
            _fail(f"callback_port must be in [1024, 65535], got {self.callback_port!r}")
        if not _CALLBACK_PATH_PATTERN.fullmatch(self.callback_path) or ".." in self.callback_path:
            _fail(
                "callback_path must be an exact path of unreserved characters with no "
                "query, fragment, empty segment, dot segment, or whitespace, got "
                f"{self.callback_path!r}"
            )
        if not isinstance(self.limits, ResourceLimits):
            _fail("limits must be a ResourceLimits instance")

        # Detach the mutable containers from the caller so a validated frozen
        # config cannot be edited afterwards — `dev_stdio_env` reaches a child
        # process in step 4.
        object.__setattr__(self, "dev_stdio_args", tuple(self.dev_stdio_args))
        object.__setattr__(self, "dev_stdio_env", MappingProxyType(dict(self.dev_stdio_env)))
        for key, value in self.dev_stdio_env.items():
            if not isinstance(key, str) or not _ENV_KEY_PATTERN.fullmatch(key):
                _fail(f"dev_stdio_env key {key!r} is not a valid environment variable name")
            if not isinstance(value, str):
                _fail(f"dev_stdio_env value for {key!r} must be a string")
        for argument in self.dev_stdio_args:
            if not isinstance(argument, str):
                _fail("dev_stdio_args must be a sequence of strings")

        has_stdio_settings = bool(self.dev_stdio_args or self.dev_stdio_env or self.dev_stdio_cwd)
        if self.mode == "production":
            # Presence, not truthiness: `dev_url=""` is still a dev field set
            # on a production config, and must be rejected like any other.
            if self.dev_url is not None or self.dev_stdio_command is not None:
                _fail("dev_url/dev_stdio_* are not allowed when mode='production'")
            if has_stdio_settings:
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
            if self.dev_url is not None and self.dev_stdio_command is not None:
                _fail(
                    "dev_url and dev_stdio_command name two different targets; "
                    "set exactly one, because transport selection happens once"
                )
            if self.dev_url is None and self.dev_stdio_command is None:
                _fail(
                    "development mode requires dev_url or dev_stdio_command "
                    "to name a non-production target"
                )
            if self.dev_url is not None:
                if has_stdio_settings:
                    _fail("dev_stdio_args/env/cwd are not allowed alongside dev_url")
                _validate_dev_url(self.dev_url)
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
        an HTTP URL. In development mode the value is always a validated
        loopback URL, never the production endpoint.
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
        if "RH_MCP_CALLBACK_TIMEOUT_S" in env:
            raw_timeout = env["RH_MCP_CALLBACK_TIMEOUT_S"]
            try:
                seconds = float(raw_timeout)
            except ValueError:
                _fail(f"RH_MCP_CALLBACK_TIMEOUT_S must be a number, got {raw_timeout!r}")
            kwargs["limits"] = ResourceLimits(oauth_callback_timeout_s=seconds)
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
    """Parse `KEY=VALUE,KEY=VALUE`.

    This variable carries values destined for a child process — a test token
    or API key lives here. §7.3 therefore allows an error to name the failing
    entry's position, and a key only once it is known to be a well-formed key,
    but never any part of a value.
    """
    pairs: dict[str, str] = {}
    for index, item in enumerate(raw.split(",")):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            _fail(
                f"RH_MCP_DEV_STDIO_ENV entry {index} must be in KEY=VALUE form "
                "(its content is omitted because it may be a secret)"
            )
        key, _, value = item.partition("=")
        if not _ENV_KEY_PATTERN.fullmatch(key):
            _fail(
                f"RH_MCP_DEV_STDIO_ENV entry {index} does not start with a valid "
                "environment variable name"
            )
        if key in pairs:
            _fail(f"RH_MCP_DEV_STDIO_ENV sets {key!r} more than once")
        pairs[key] = value
    return pairs
