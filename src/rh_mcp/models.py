"""SDK-neutral, immutable result types (DESIGN.md §7.1).

Nothing in this module may import `mcp` or `httpx2` (DESIGN.md §4) — these
types are the only shapes a consumer ever sees, independent of whatever MCP
SDK major version the gateway happens to use internally.

Validation failures raise `GatewayError`, not a bare `ValueError`: these are
public types, and §7.3 requires every failure that can reach a caller or the
CLI to carry a stable code and a safe message rather than a traceback.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, NoReturn

from rh_mcp.errors import ErrorCode, GatewayError

# Anchored at both ends with `\Z` rather than `$`: `$` also matches just
# before a trailing newline, which would let a digest read from a file or a
# CI variable keep its newline and never compare equal (DESIGN.md §9).
DIGEST_PATTERN = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


def is_digest(value: object) -> bool:
    """Whether `value` is exactly 'sha256:' + 64 lowercase hex characters."""
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def _invalid(message: str) -> NoReturn:
    raise GatewayError(ErrorCode.PROTOCOL_ERROR, message)


def _require_digest(name: str, value: str) -> None:
    if not is_digest(value):
        _invalid(f"{name} must match 'sha256:<64 lowercase hex chars>', got {value!r}")


def _require_nonempty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        _invalid(f"{name} must be a non-empty string")


def _require_bool(name: str, value: object) -> None:
    if not isinstance(value, bool):
        _invalid(f"{name} must be a bool, got {type(value).__name__}")


def _require_utc_timestamp(name: str, value: str) -> None:
    if not isinstance(value, str):
        _invalid(f"{name} must be an ISO-8601 timestamp string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _invalid(f"{name} must be an ISO-8601 timestamp, got {value!r}")
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        _invalid(f"{name} must be timezone-aware UTC, got {value!r}")


def _freeze_json(value: Any) -> Any:
    """Deep-copy decoded JSON into a structure nothing else can mutate.

    §7.1 computes `result_digest` over the payload *before* the envelope is
    returned, so the envelope must stop sharing structure with whatever buffer
    the payload was decoded into; otherwise a later mutation silently breaks
    the consumer's digest verification.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _json_safe(value: Any) -> Any:
    """Render a frozen payload back into plain JSON-serializable containers."""
    if isinstance(value, Mapping):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


@dataclass(frozen=True)
class Readiness:
    """Whether the gateway may currently serve reads (DESIGN.md §7.1)."""

    ready: bool
    manifest_version: str
    manifest_digest: str
    expected_manifest_digest: str

    def __post_init__(self) -> None:
        _require_bool("ready", self.ready)
        _require_nonempty("manifest_version", self.manifest_version)
        _require_digest("manifest_digest", self.manifest_digest)
        _require_digest("expected_manifest_digest", self.expected_manifest_digest)
        if self.ready and self.manifest_digest != self.expected_manifest_digest:
            _invalid("ready cannot be True when manifest_digest != expected_manifest_digest")

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "manifest_version": self.manifest_version,
            "manifest_digest": self.manifest_digest,
            "expected_manifest_digest": self.expected_manifest_digest,
        }


_ENVELOPE_VERSION = "1.0"


@dataclass(frozen=True)
class ResultEnvelope:
    """A single successful read result (DESIGN.md §7.1)."""

    manifest_version: str
    manifest_digest: str
    capability: str
    schema_digest: str
    result_digest: str
    observed_at: str
    data: Mapping[str, Any]
    warnings: tuple[str, ...] = ()
    envelope_version: str = field(default=_ENVELOPE_VERSION, init=False)

    def __post_init__(self) -> None:
        _require_nonempty("manifest_version", self.manifest_version)
        _require_digest("manifest_digest", self.manifest_digest)
        _require_nonempty("capability", self.capability)
        _require_digest("schema_digest", self.schema_digest)
        _require_digest("result_digest", self.result_digest)
        _require_utc_timestamp("observed_at", self.observed_at)

        if not isinstance(self.data, Mapping):
            _invalid(f"data must be a JSON object, got {type(self.data).__name__}")
        if isinstance(self.warnings, (str, bytes)) or not isinstance(self.warnings, Iterable):
            _invalid("warnings must be a sequence of strings")
        warnings = tuple(self.warnings)
        for warning in warnings:
            if not isinstance(warning, str):
                _invalid("warnings must be a sequence of strings")

        # Detach from the caller's objects so the envelope stays immutable and
        # `result_digest` keeps binding exactly the payload it was computed over.
        object.__setattr__(self, "data", _freeze_json(self.data))
        object.__setattr__(self, "warnings", warnings)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "manifest_version": self.manifest_version,
            "manifest_digest": self.manifest_digest,
            "capability": self.capability,
            "schema_digest": self.schema_digest,
            "result_digest": self.result_digest,
            "observed_at": self.observed_at,
            "data": _json_safe(self.data),
            "warnings": list(self.warnings),
        }


__all__ = [
    "DIGEST_PATTERN",
    "Readiness",
    "ResultEnvelope",
    "is_digest",
]
