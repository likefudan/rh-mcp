"""SDK-neutral, immutable result types (DESIGN.md §7.1).

Nothing in this module may import `mcp` or `httpx2` (DESIGN.md §4) — these
types are the only shapes a consumer ever sees, independent of whatever MCP
SDK major version the gateway happens to use internally.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_digest(name: str, value: str) -> None:
    if not DIGEST_PATTERN.match(value):
        raise ValueError(f"{name} must match 'sha256:<64 hex chars>', got {value!r}")


def _require_nonempty(name: str, value: str) -> None:
    if not value:
        raise ValueError(f"{name} must be a non-empty string")


def _require_utc_timestamp(name: str, value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp, got {value!r}") from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{name} must be timezone-aware UTC, got {value!r}")


@dataclass(frozen=True)
class Readiness:
    """Whether the gateway may currently serve reads (DESIGN.md §7.1)."""

    ready: bool
    manifest_version: str
    manifest_digest: str
    expected_manifest_digest: str

    def __post_init__(self) -> None:
        _require_nonempty("manifest_version", self.manifest_version)
        _require_digest("manifest_digest", self.manifest_digest)
        _require_digest("expected_manifest_digest", self.expected_manifest_digest)
        if self.ready and self.manifest_digest != self.expected_manifest_digest:
            raise ValueError(
                "ready cannot be True when manifest_digest != expected_manifest_digest"
            )

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

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "manifest_version": self.manifest_version,
            "manifest_digest": self.manifest_digest,
            "capability": self.capability,
            "schema_digest": self.schema_digest,
            "result_digest": self.result_digest,
            "observed_at": self.observed_at,
            "data": dict(self.data),
            "warnings": list(self.warnings),
        }
