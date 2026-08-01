"""Synthetic manifest fixtures (DESIGN.md §6.1, §11).

Every tool name, description, and schema in this file is invented. DESIGN.md
§6.1 forbids guessing real Robinhood tool names or schemas before owner-assisted
authenticated discovery has happened, so the whole offline suite runs against
`synthetic_*` names that could not be mistaken for a production surface.

The builders below construct a *correct* manifest document — one whose stored
per-tool digests, provider-surface digest, and full-manifest digest all agree
with its contents. Tests then mutate one thing at a time. That is the only way
to prove a specific guard fires: a fixture that was invalid for three reasons
would pass a test for any one of them.
"""

from __future__ import annotations

import json
from typing import Any

from rh_mcp.canonical import (
    CANONICALIZATION_VERSION,
    tool_metadata_digest,
    tool_schema_digest,
)
from rh_mcp.manifest import (
    MANIFEST_FORMAT_VERSION,
    ManifestEntry,
    compute_full_manifest_digest,
    surface_digest_for_entries,
)

OBSERVED_AT = "2026-01-15T00:00:00+00:00"
REVIEWED_AT = "2026-01-16T00:00:00+00:00"
MANIFEST_VERSION = "2026.01.16"

ALPHA_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"synthetic_symbol": {"type": "string", "maxLength": 8}},
    "required": ["synthetic_symbol"],
    "additionalProperties": False,
}
ALPHA_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"synthetic_value": {"type": "number"}},
    "additionalProperties": False,
}
BETA_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"synthetic_page": {"type": "integer", "minimum": 1}},
    "additionalProperties": False,
}
GAMMA_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"synthetic_quantity": {"type": "number"}},
    "required": ["synthetic_quantity"],
    "additionalProperties": False,
}


def build_entry(
    *,
    provider_tool_name: str,
    capability: str | None,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
    disposition: str = "read_allowed",
    rationale: str = "synthetic fixture rationale",
) -> dict[str, Any]:
    """One manifest entry with digests that match its own contents."""
    resolved_annotations = {} if annotations is None else annotations
    return {
        "capability": capability,
        "provider_tool_name": provider_tool_name,
        "description": description,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "annotations": resolved_annotations,
        "schema_digest": tool_schema_digest(provider_tool_name, input_schema, output_schema),
        "metadata_digest": tool_metadata_digest(description, resolved_annotations),
        "disposition": disposition,
        "rationale": rationale,
    }


def default_entries() -> list[dict[str, Any]]:
    """Two allowed synthetic reads and one explicitly denied synthetic tool."""
    return [
        build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description="Synthetic alpha read used only by the offline suite.",
            input_schema=ALPHA_INPUT_SCHEMA,
            output_schema=ALPHA_OUTPUT_SCHEMA,
            annotations={"readOnlyHint": True, "title": "Synthetic Alpha"},
            rationale="Reviewed: returns synthetic reference data with no side effects.",
        ),
        build_entry(
            provider_tool_name="synthetic_beta_read",
            capability="beta_reading",
            description="Synthetic beta read used only by the offline suite.",
            input_schema=BETA_INPUT_SCHEMA,
            annotations={"readOnlyHint": True},
            rationale="Reviewed: paginated synthetic listing with no side effects.",
        ),
        build_entry(
            provider_tool_name="synthetic_gamma_mutate",
            capability="gamma_reading",
            description="Synthetic mutating tool used only by the offline suite.",
            input_schema=GAMMA_INPUT_SCHEMA,
            annotations={"readOnlyHint": True},
            disposition="denied",
            rationale=(
                "Denied: the annotation claims read-only but the reviewed behaviour "
                "mutates state, and an annotation is evidence, never authority."
            ),
        ),
    ]


def build_manifest(
    entries: list[dict[str, Any]] | None = None,
    *,
    manifest_version: str = MANIFEST_VERSION,
    manifest_format_version: str = MANIFEST_FORMAT_VERSION,
    canonicalization_version: str = CANONICALIZATION_VERSION,
    digest_algorithm: str = "sha256",
    observed_at: str = OBSERVED_AT,
    reviewer: dict[str, Any] | None = None,
    sort_entries: bool = True,
) -> dict[str, Any]:
    """A self-consistent manifest document.

    `sort_entries` exists so a test can build one that is correct in every
    respect *except* canonical entry order.
    """
    resolved_entries = default_entries() if entries is None else entries
    if sort_entries:
        resolved_entries = sorted(resolved_entries, key=lambda item: item["provider_tool_name"])
    document: dict[str, Any] = {
        "manifest_format_version": manifest_format_version,
        "canonicalization_version": canonicalization_version,
        "digest_algorithm": digest_algorithm,
        "manifest_version": manifest_version,
        "provider_surface_digest": surface_digest_for_entries(
            _as_manifest_entries(resolved_entries)
        ),
        "observed_at": observed_at,
        "reviewer": (
            {"name": "synthetic-reviewer", "reviewed_at": REVIEWED_AT}
            if reviewer is None
            else reviewer
        ),
        "entries": resolved_entries,
    }
    document["full_manifest_digest"] = compute_full_manifest_digest(document)
    return document


def reseal(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute both derived digests after a test mutated the contents.

    This models the strongest realistic attack on the design: someone edits a
    manifest and then updates its own stored digests so the file is internally
    consistent again. DESIGN.md §6 says that must still fail against a
    separately configured expected digest, and `test_manifest.py` proves it.
    """
    document = dict(document)
    document["provider_surface_digest"] = surface_digest_for_entries(
        _as_manifest_entries(document["entries"])
    )
    document.pop("full_manifest_digest", None)
    document["full_manifest_digest"] = compute_full_manifest_digest(document)
    return document


def dumps(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2)


def _as_manifest_entries(entries: list[dict[str, Any]]) -> list[ManifestEntry]:
    return [
        ManifestEntry(
            capability=entry["capability"],
            provider_tool_name=entry["provider_tool_name"],
            description=entry["description"],
            input_schema=entry["input_schema"],
            output_schema=entry["output_schema"],
            annotations=entry["annotations"],
            schema_digest=entry["schema_digest"],
            metadata_digest=entry["metadata_digest"],
            disposition=entry["disposition"],
            rationale=entry["rationale"],
        )
        for entry in entries
    ]
