"""Shared field validators, digest-shape checks, and JSON freezing.

Extracted from `models.py` unchanged so `canonical.py` and `manifest.py` can
reuse exactly the same rules rather than growing a second, subtly different
copy. A divergence between two "identical" validators is precisely the kind of
gap that turns a fail-closed check into a fail-open one, so there is
deliberately one implementation of each rule in the package.

Every helper takes the `ErrorCode` to raise. The callers legitimately disagree
about the code — a malformed provider payload is a `protocol_error` while a
malformed committed manifest is a local `not_ready` fault (DESIGN.md §7.3) —
and hard-coding either one here would mislabel the other.

This module imports nothing from the rest of the package except `errors`, so
it can sit underneath both `models` and `manifest` without a cycle.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any, NoReturn

from rh_mcp.errors import ErrorCode, GatewayError

# Anchored at both ends with `\Z` rather than `$`: `$` also matches just
# before a trailing newline, which would let a digest read from a file or a
# CI variable keep its newline and never compare equal (DESIGN.md §9).
DIGEST_PATTERN = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

# A structural rail so a cyclic or pathologically nested payload raises the
# public error contract instead of `RecursionError`. This is deliberately well
# above the configurable §8 `max_json_depth` ceiling (64) — enforcing that
# bound while decoding is step 3's job, not this copy's.
MAX_STRUCTURAL_DEPTH = 128


def is_digest(value: object) -> bool:
    """Whether `value` is exactly 'sha256:' + 64 lowercase hex characters."""
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def invalid(message: str, code: ErrorCode) -> NoReturn:
    raise GatewayError(code, message)


def require_digest(name: str, value: str, code: ErrorCode) -> None:
    if not is_digest(value):
        invalid(f"{name} must match 'sha256:<64 lowercase hex chars>', got {value!r}", code)


def require_nonempty(name: str, value: str, code: ErrorCode) -> None:
    if not isinstance(value, str) or not value:
        invalid(f"{name} must be a non-empty string", code)


def require_bool(name: str, value: object, code: ErrorCode) -> None:
    if not isinstance(value, bool):
        invalid(f"{name} must be a bool, got {type(value).__name__}", code)


def require_utc_timestamp(name: str, value: str, code: ErrorCode) -> None:
    if not isinstance(value, str):
        invalid(f"{name} must be an ISO-8601 timestamp string", code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        invalid(f"{name} must be an ISO-8601 timestamp, got {value!r}", code)
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        invalid(f"{name} must be timezone-aware UTC, got {value!r}", code)


def is_encodable(value: str) -> bool:
    """Whether `value` can be encoded as UTF-8 (no unpaired surrogates)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def freeze_json(value: Any, code: ErrorCode, *, label: str = "value", depth: int = 0) -> Any:
    """Deep-copy decoded JSON into a structure nothing else can mutate.

    §7.1 computes `result_digest` over the payload *before* the envelope is
    returned, so the envelope must stop sharing structure with whatever buffer
    the payload was decoded into; otherwise a later mutation silently breaks
    the consumer's digest verification. The manifest loader depends on the same
    property for a different reason: a pinned input schema whose contents can
    still be edited after its digest was verified is not pinned at all.

    The walk also enforces that the payload really is decoded JSON. A set, a
    `bytearray`, or a custom object would otherwise fall through by reference
    and stay mutable; a non-string key would make `to_json_dict()` return
    something `json.dumps` cannot serialize; and a non-finite float is not a
    JSON value at all.
    """
    if depth > MAX_STRUCTURAL_DEPTH:
        invalid(
            f"{label} nests deeper than {MAX_STRUCTURAL_DEPTH} levels or contains a cycle",
            code,
        )
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                invalid(f"{label} object keys must be strings, got {type(key).__name__}", code)
            if not is_encodable(key):
                invalid(f"{label} object keys may not contain unpaired surrogates", code)
            frozen[key] = freeze_json(item, code, label=label, depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item, code, label=label, depth=depth + 1) for item in value)
    # RFC 8259 has no NaN/Infinity literal, so a non-finite float is not
    # decoded JSON any more than a `Decimal` is. `json.loads` produces them
    # from the non-standard literals by default, and `json.dumps` re-emits
    # them by default as unparseable output — a documented Python extension,
    # not evidence of validity. It also fails *open*: `nan > x` and `nan < x`
    # are both False, so a NaN price would pass every downstream threshold,
    # risk gate and sanity bound a consumer applies (§7.1, §10).
    if isinstance(value, float) and not math.isfinite(value):
        invalid(f"{label} may not contain NaN or Infinity", code)
    # A lone UTF-16 surrogate survives `json.loads` (from a `\udXXX` escape)
    # but cannot be encoded to UTF-8, so it is not representable JSON text.
    # Rejecting it here keeps the failure inside the §7.3 error contract:
    # otherwise the first component to encode the payload — canonicalization —
    # raises an uncaught `UnicodeEncodeError`.
    if isinstance(value, str) and not is_encodable(value):
        invalid(f"{label} may not contain unpaired surrogates", code)
    # `bool` is a subclass of `int`, so it is covered here.
    if value is None or isinstance(value, (str, int, float)):
        return value
    invalid(f"{label} may contain only JSON types, got {type(value).__name__}", code)


def json_safe(value: Any) -> Any:
    """Render a frozen payload back into plain JSON-serializable containers."""
    if isinstance(value, Mapping):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    return value


__all__ = [
    "DIGEST_PATTERN",
    "MAX_STRUCTURAL_DEPTH",
    "freeze_json",
    "invalid",
    "is_digest",
    "is_encodable",
    "json_safe",
    "require_bool",
    "require_digest",
    "require_nonempty",
    "require_utc_timestamp",
]
