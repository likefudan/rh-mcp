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

The field validators and the JSON freezing walk live in `validation.py` so
`manifest.py` enforces the identical rules; `DIGEST_PATTERN` and `is_digest`
stay importable from here because they are part of the published surface.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from rh_mcp.errors import ErrorCode
from rh_mcp.validation import (
    DIGEST_PATTERN,
    freeze_json,
    invalid,
    is_digest,
    json_safe,
    require_bool,
    require_digest,
    require_nonempty,
    require_utc_timestamp,
)


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
        require_bool("ready", self.ready, code)
        require_nonempty("manifest_version", self.manifest_version, code)
        require_digest("manifest_digest", self.manifest_digest, code)
        require_digest("expected_manifest_digest", self.expected_manifest_digest, code)
        if self.ready and self.manifest_digest != self.expected_manifest_digest:
            invalid("ready cannot be True when manifest_digest != expected_manifest_digest", code)

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
        require_nonempty("manifest_version", self.manifest_version, code)
        require_digest("manifest_digest", self.manifest_digest, code)
        require_nonempty("capability", self.capability, code)
        require_digest("schema_digest", self.schema_digest, code)
        require_digest("result_digest", self.result_digest, code)
        require_utc_timestamp("observed_at", self.observed_at, code)

        if not isinstance(self.data, Mapping):
            invalid(f"data must be a JSON object, got {type(self.data).__name__}", code)
        if isinstance(self.warnings, (str, bytes)) or not isinstance(self.warnings, Iterable):
            invalid("warnings must be a sequence of strings", code)
        warnings = tuple(self.warnings)
        for warning in warnings:
            if not isinstance(warning, str):
                invalid("warnings must be a sequence of strings", code)

        # Detach from the caller's objects so the envelope stays immutable and
        # `result_digest` keeps binding exactly the payload it was computed over.
        object.__setattr__(self, "data", freeze_json(self.data, code, label="data"))
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
            "data": json_safe(self.data),
            "warnings": list(self.warnings),
        }


__all__ = [
    "DIGEST_PATTERN",
    "Readiness",
    "ResultEnvelope",
    "is_digest",
]
