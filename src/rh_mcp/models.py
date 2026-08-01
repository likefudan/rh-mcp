"""SDK-neutral, immutable result types (DESIGN.md §7.1).

Nothing in this module may import `mcp` or `httpx2` (DESIGN.md §4) — these
types are the only shapes a consumer ever sees, independent of whatever MCP
SDK major version the gateway happens to use internally.

Validation failures raise `GatewayError`, not a bare `ValueError`: these are
public types, and §7.3 requires every failure that can reach a caller or the
CLI to carry a stable code and a safe message rather than a traceback.

The two classes use different codes because their failures have different
causes and belong in different §7.3 exit buckets. A `Readiness` that cannot be
constructed is a local fault — a mis-pinned or mismatched digest — so it
raises `not_ready` (configuration bucket, exit 3) and points an operator at
the §6.2 drift they actually need to look at. A `ResultEnvelope` is assembled
from provider-derived data, so it raises `protocol_error` (exit 1).
"""

from __future__ import annotations

import math
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


def _invalid(message: str, code: ErrorCode) -> NoReturn:
    raise GatewayError(code, message)


def _require_digest(name: str, value: str, code: ErrorCode) -> None:
    if not is_digest(value):
        _invalid(f"{name} must match 'sha256:<64 lowercase hex chars>', got {value!r}", code)


def _require_nonempty(name: str, value: str, code: ErrorCode) -> None:
    if not isinstance(value, str) or not value:
        _invalid(f"{name} must be a non-empty string", code)


def _require_bool(name: str, value: object, code: ErrorCode) -> None:
    if not isinstance(value, bool):
        _invalid(f"{name} must be a bool, got {type(value).__name__}", code)


def _require_utc_timestamp(name: str, value: str, code: ErrorCode) -> None:
    if not isinstance(value, str):
        _invalid(f"{name} must be an ISO-8601 timestamp string", code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _invalid(f"{name} must be an ISO-8601 timestamp, got {value!r}", code)
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        _invalid(f"{name} must be timezone-aware UTC, got {value!r}", code)


# A structural rail so a cyclic or pathologically nested payload raises the
# public error contract instead of `RecursionError`. This is deliberately well
# above the configurable §8 `max_json_depth` ceiling (64) — enforcing that
# bound while decoding is step 3's job, not this copy's.
_MAX_STRUCTURAL_DEPTH = 128


def _is_encodable(value: str) -> bool:
    """Whether `value` can be encoded as UTF-8 (no unpaired surrogates)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _freeze_json(value: Any, *, depth: int = 0) -> Any:
    """Deep-copy decoded JSON into a structure nothing else can mutate.

    §7.1 computes `result_digest` over the payload *before* the envelope is
    returned, so the envelope must stop sharing structure with whatever buffer
    the payload was decoded into; otherwise a later mutation silently breaks
    the consumer's digest verification.

    The walk also enforces that the payload really is decoded JSON. A set, a
    `bytearray`, or a custom object would otherwise fall through by reference
    and stay mutable through the envelope; a non-string key would make
    `to_json_dict()` return something `json.dumps` cannot serialize; and a
    non-finite float is not a JSON value at all.
    """
    if depth > _MAX_STRUCTURAL_DEPTH:
        _invalid(
            f"data nests deeper than {_MAX_STRUCTURAL_DEPTH} levels or contains a cycle",
            ErrorCode.PROTOCOL_ERROR,
        )
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _invalid(
                    f"data object keys must be strings, got {type(key).__name__}",
                    ErrorCode.PROTOCOL_ERROR,
                )
            if not _is_encodable(key):
                _invalid(
                    "data object keys may not contain unpaired surrogates",
                    ErrorCode.PROTOCOL_ERROR,
                )
            frozen[key] = _freeze_json(item, depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, depth=depth + 1) for item in value)
    # RFC 8259 has no NaN/Infinity literal, so a non-finite float is not
    # decoded JSON any more than a `Decimal` is. `json.loads` produces them
    # from the non-standard literals by default, and `json.dumps` re-emits
    # them by default as unparseable output — a documented Python extension,
    # not evidence of validity. It also fails *open*: `nan > x` and `nan < x`
    # are both False, so a NaN price would pass every downstream threshold,
    # risk gate and sanity bound a consumer applies (§7.1, §10).
    if isinstance(value, float) and not math.isfinite(value):
        _invalid("data may not contain NaN or Infinity", ErrorCode.PROTOCOL_ERROR)
    # A lone UTF-16 surrogate survives `json.loads` (from a `\udXXX` escape)
    # but cannot be encoded to UTF-8, so it is not representable JSON text.
    # Rejecting it here keeps the failure inside the §7.3 error contract:
    # otherwise the first component to encode the payload — the canonical
    # `result_digest` — raises an uncaught `UnicodeEncodeError`.
    if isinstance(value, str) and not _is_encodable(value):
        _invalid("data may not contain unpaired surrogates", ErrorCode.PROTOCOL_ERROR)
    # `bool` is a subclass of `int`, so it is covered here.
    if value is None or isinstance(value, (str, int, float)):
        return value
    _invalid(
        f"data may contain only JSON types, got {type(value).__name__}",
        ErrorCode.PROTOCOL_ERROR,
    )


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
        # A readiness object that cannot be constructed describes a gateway
        # that is not ready; §7.3 puts that in the configuration bucket, not
        # the provider-failure one.
        code = ErrorCode.NOT_READY
        _require_bool("ready", self.ready, code)
        _require_nonempty("manifest_version", self.manifest_version, code)
        _require_digest("manifest_digest", self.manifest_digest, code)
        _require_digest("expected_manifest_digest", self.expected_manifest_digest, code)
        if self.ready and self.manifest_digest != self.expected_manifest_digest:
            _invalid("ready cannot be True when manifest_digest != expected_manifest_digest", code)

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
        # An envelope is assembled from provider-derived data, so a malformed
        # one is a protocol-level fault (§7.1, §7.3).
        code = ErrorCode.PROTOCOL_ERROR
        _require_nonempty("manifest_version", self.manifest_version, code)
        _require_digest("manifest_digest", self.manifest_digest, code)
        _require_nonempty("capability", self.capability, code)
        _require_digest("schema_digest", self.schema_digest, code)
        _require_digest("result_digest", self.result_digest, code)
        _require_utc_timestamp("observed_at", self.observed_at, code)

        if not isinstance(self.data, Mapping):
            _invalid(f"data must be a JSON object, got {type(self.data).__name__}", code)
        if isinstance(self.warnings, (str, bytes)) or not isinstance(self.warnings, Iterable):
            _invalid("warnings must be a sequence of strings", code)
        warnings = tuple(self.warnings)
        for warning in warnings:
            if not isinstance(warning, str):
                _invalid("warnings must be a sequence of strings", code)

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
