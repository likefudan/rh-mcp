"""Manifest format, drift control, and fail-closed readiness (§6, §6.2, §11).

Offline and synthetic throughout. The `SpyDiscovery` below is the only route
to a "provider", which is what makes "no read reaches a transport" a property
these tests can assert rather than assume.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
from collections.abc import Coroutine
from dataclasses import replace
from pathlib import Path
from typing import Any, Final

import pytest

from rh_mcp.canonical import canonical_digest, tool_metadata_digest, tool_schema_digest
from rh_mcp.config import GatewayConfig
from rh_mcp.errors import (
    EXIT_CODE_CONFIGURATION_ERROR,
    ErrorCode,
    GatewayError,
    exit_code_for,
)
from rh_mcp.manifest import (
    MAX_MANIFEST_TEXT_DEPTH,
    PACKAGED_MANIFEST_PATH,
    DriftReason,
    ManifestEntry,
    ObservedSurface,
    ObservedTool,
    ReadinessAssessment,
    ReviewedManifest,
    assess_surface,
    compute_full_manifest_digest,
    establish_readiness,
    load_active_manifest,
    load_manifest_file,
    load_manifest_text,
    manifest_to_json_dict,
    preflight_read,
)
from tests.support import (
    ALPHA_INPUT_SCHEMA,
    ALPHA_OUTPUT_SCHEMA,
    BETA_INPUT_SCHEMA,
    build_entry,
    build_manifest,
    default_entries,
    dumps,
    reseal,
)

# The golden full-manifest digest of the synthetic fixture. Written out by
# hand: if a change to canonicalization, the manifest format, or the fixture
# moves it, that is exactly the explicit migration DESIGN.md §6 requires.
BASE_DIGEST = "sha256:3b7f113be230012d7f1949789401e60e9b84274ecf09f8a8ced31d5fc3e11250"
# Arguments that satisfy ALPHA_INPUT_SCHEMA, so a preflight test fails for the
# reason it is named after rather than on input validation.
VALID_ARGS: dict[str, Any] = {"synthetic_symbol": "AAPL"}
OTHER_DIGEST = "sha256:" + "b" * 64


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class SpyDiscovery:
    """A `SurfaceDiscovery` that records whether it was reached at all."""

    def __init__(
        self, surface: ObservedSurface | None = None, error: GatewayError | None = None
    ) -> None:
        self.surface = surface
        self.error = error
        self.calls = 0

    async def discover(self) -> ObservedSurface:
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.surface is not None
        return self.surface


def observed_tools(document: dict[str, Any]) -> list[ObservedTool]:
    """The provider surface that matches a manifest document exactly."""
    return [
        ObservedTool(
            name=entry["provider_tool_name"],
            description=entry["description"],
            input_schema=entry["input_schema"],
            output_schema=entry["output_schema"],
            annotations=entry["annotations"],
        )
        for entry in document["entries"]
    ]


def bare_tool(name: str) -> ObservedTool:
    """A tool observed to declare nothing beyond its name.

    Spelled out rather than defaulted: every field of `ObservedTool` is a
    positive claim about what the provider returned, so a test that means
    "this tool really did declare no annotations" has to say so.
    """
    return ObservedTool(
        name=name,
        description="",
        input_schema={},
        output_schema=None,
        annotations={},
    )


def matching_surface(document: dict[str, Any]) -> ObservedSurface:
    return ObservedSurface(tools=tuple(observed_tools(document)), complete=True)


class TestTheDiscoverySeamHasNoPermissiveDefaults:
    """Every observed field must be a positive claim (§2, §6.2).

    A default here is a security claim a step-3 transport could make by
    omission — "no annotations", "no output schema", "a complete surface" —
    and nothing downstream could tell the difference between "the provider
    declared nothing" and "the mapping code forgot the field". The
    `annotations` case is the sharpest: a default of `{}` would be recorded
    identically at discovery and at runtime, so `metadata_digest_mismatch`
    could never fire and every `readOnlyHint` would be silently unpinned.

    These tests fail if any default is reintroduced.
    """

    @pytest.mark.parametrize(
        "omit", ["description", "input_schema", "output_schema", "annotations"]
    )
    def test_every_observed_tool_field_is_required(self, omit: str) -> None:
        fields: dict[str, Any] = {
            "name": "synthetic_tool",
            "description": "",
            "input_schema": {},
            "output_schema": None,
            "annotations": {},
        }
        del fields[omit]
        with pytest.raises(TypeError, match=omit):
            ObservedTool(**fields)

    def test_surface_completeness_is_required(self) -> None:
        with pytest.raises(TypeError, match="complete"):
            ObservedSurface(tools=())

    def test_surface_tools_are_required(self) -> None:
        with pytest.raises(TypeError, match="tools"):
            ObservedSurface(complete=True)  # type: ignore[call-arg]

    @pytest.mark.parametrize("cls", [ObservedTool, ObservedSurface])
    def test_no_observed_field_may_carry_a_default(self, cls: type) -> None:
        """Closes the class rather than sampling it.

        The enumerated tests above name specific fields, so they give a better
        message when one breaks — but they cannot catch a *new* defaulted field
        added later, which is how this seam acquired its permissive defaults in
        the first place.
        """
        defaulted = [
            f.name
            for f in dataclasses.fields(cls)
            if f.init
            and (
                f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING
            )
        ]
        assert not defaulted, (
            f"{cls.__name__} field(s) {defaulted} carry a default; every observed "
            "field is a positive claim about the provider and must be stated"
        )


def config_for(digest: str) -> GatewayConfig:
    return GatewayConfig(expected_manifest_digest=digest)


@pytest.fixture
def document() -> dict[str, Any]:
    return build_manifest()


@pytest.fixture
def manifest(document: dict[str, Any]) -> ReviewedManifest:
    return load_manifest_text(dumps(document))


# --------------------------------------------------------------------------
# Loading a good manifest
# --------------------------------------------------------------------------


class TestLoading:
    def test_golden_full_manifest_digest(self, manifest: ReviewedManifest) -> None:
        assert manifest.digest == BASE_DIGEST

    def test_the_active_digest_is_recomputed_not_trusted(self, document: dict[str, Any]) -> None:
        """§7.1: the active digest is never a value trusted from the file."""
        assert load_manifest_text(dumps(document)).digest == compute_full_manifest_digest(document)

    def test_reports_reviewed_read_capabilities_only(self, manifest: ReviewedManifest) -> None:
        assert manifest.read_capabilities == ("alpha_reading", "beta_reading")

    def test_a_denied_entry_still_appears_in_the_capability_map(
        self, manifest: ReviewedManifest
    ) -> None:
        entry = manifest.capabilities["gamma_reading"]
        assert entry.disposition == "denied"
        assert not entry.read_allowed

    def test_entries_are_exposed_in_canonical_order(self, manifest: ReviewedManifest) -> None:
        names = [entry.provider_tool_name for entry in manifest.entries]
        assert names == sorted(names)

    def test_loads_from_a_file(self, document: dict[str, Any], tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_text(dumps(document), encoding="utf-8")
        assert load_manifest_file(path).digest == BASE_DIGEST

    def test_round_trips_through_its_json_form(self, manifest: ReviewedManifest) -> None:
        reloaded = load_manifest_text(json.dumps(manifest_to_json_dict(manifest)))
        assert reloaded.digest == manifest.digest

    def test_pinned_schemas_cannot_be_mutated_after_verification(
        self, manifest: ReviewedManifest
    ) -> None:
        entry = manifest.capabilities["alpha_reading"]
        with pytest.raises(TypeError):
            entry.input_schema["injected"] = True  # type: ignore[index]

    def test_whitespace_in_the_file_does_not_change_the_digest(
        self, document: dict[str, Any]
    ) -> None:
        compact = load_manifest_text(json.dumps(document, separators=(",", ":")))
        spaced = load_manifest_text(json.dumps(document, indent=4))
        assert compact.digest == spaced.digest == BASE_DIGEST

    def test_top_level_key_order_does_not_change_the_digest(self, document: dict[str, Any]) -> None:
        reversed_document = dict(reversed(list(document.items())))
        assert load_manifest_text(dumps(reversed_document)).digest == BASE_DIGEST


# --------------------------------------------------------------------------
# Full-manifest golden vectors (§11)
# --------------------------------------------------------------------------


def _remapped_capability() -> dict[str, Any]:
    entries = default_entries()
    entries[0]["capability"] = "alpha_reading_v2"
    return reseal(build_manifest(entries))


def _renamed_provider_tool() -> dict[str, Any]:
    entries = default_entries()
    entries[0] = build_entry(
        provider_tool_name="synthetic_alpha_read_v2",
        capability="alpha_reading",
        description=entries[0]["description"],
        input_schema=ALPHA_INPUT_SCHEMA,
        output_schema=ALPHA_OUTPUT_SCHEMA,
        annotations=entries[0]["annotations"],
        rationale=entries[0]["rationale"],
    )
    return build_manifest(entries)


def _edited_schema() -> dict[str, Any]:
    entries = default_entries()
    edited = dict(ALPHA_INPUT_SCHEMA)
    edited["additionalProperties"] = True
    entries[0] = build_entry(
        provider_tool_name="synthetic_alpha_read",
        capability="alpha_reading",
        description=entries[0]["description"],
        input_schema=edited,
        output_schema=ALPHA_OUTPUT_SCHEMA,
        annotations=entries[0]["annotations"],
        rationale=entries[0]["rationale"],
    )
    return build_manifest(entries)


def _edited_description() -> dict[str, Any]:
    entries = default_entries()
    entries[0] = build_entry(
        provider_tool_name="synthetic_alpha_read",
        capability="alpha_reading",
        description="Synthetic alpha read, description edited.",
        input_schema=ALPHA_INPUT_SCHEMA,
        output_schema=ALPHA_OUTPUT_SCHEMA,
        annotations=entries[0]["annotations"],
        rationale=entries[0]["rationale"],
    )
    return build_manifest(entries)


def _edited_annotations() -> dict[str, Any]:
    entries = default_entries()
    entries[0] = build_entry(
        provider_tool_name="synthetic_alpha_read",
        capability="alpha_reading",
        description=entries[0]["description"],
        input_schema=ALPHA_INPUT_SCHEMA,
        output_schema=ALPHA_OUTPUT_SCHEMA,
        annotations={"readOnlyHint": False, "title": "Synthetic Alpha"},
        rationale=entries[0]["rationale"],
    )
    return build_manifest(entries)


def _flipped_disposition() -> dict[str, Any]:
    entries = default_entries()
    entries[0]["disposition"] = "denied"
    entries[1]["disposition"] = "allowed"
    return reseal(build_manifest(entries))


def _edited_rationale() -> dict[str, Any]:
    entries = default_entries()
    entries[0]["rationale"] = "Reviewed again, with a different justification recorded."
    return reseal(build_manifest(entries))


def _same_version_replacement() -> dict[str, Any]:
    """Content changed, `manifest_version` deliberately identical (§6)."""
    entries = default_entries()
    entries[1] = build_entry(
        provider_tool_name="synthetic_beta_read",
        capability="beta_reading",
        description=entries[1]["description"],
        input_schema={**BETA_INPUT_SCHEMA, "required": ["synthetic_page"]},
        annotations=entries[1]["annotations"],
        rationale=entries[1]["rationale"],
    )
    return build_manifest(entries)


def _added_entry() -> dict[str, Any]:
    entries = default_entries()
    entries.append(
        build_entry(
            provider_tool_name="synthetic_delta_read",
            capability="delta_reading",
            description="Synthetic delta read.",
            input_schema={"type": "object", "additionalProperties": False},
            rationale="Reviewed: synthetic addition.",
        )
    )
    return build_manifest(entries)


def _removed_entry() -> dict[str, Any]:
    return build_manifest(default_entries()[:2])


def _changed_reviewer() -> dict[str, Any]:
    return build_manifest(
        reviewer={"name": "other-reviewer", "reviewed_at": "2026-02-01T00:00:00+00:00"}
    )


def _changed_observed_at() -> dict[str, Any]:
    return build_manifest(observed_at="2026-02-01T00:00:00+00:00")


def _changed_manifest_version() -> dict[str, Any]:
    return build_manifest(manifest_version="2026.02.01")


MUTATIONS: dict[str, Any] = {
    "capability remap": _remapped_capability,
    "provider tool rename": _renamed_provider_tool,
    "schema edit": _edited_schema,
    "description edit": _edited_description,
    "annotation edit": _edited_annotations,
    "disposition flip": _flipped_disposition,
    "rationale edit": _edited_rationale,
    "same-version replacement": _same_version_replacement,
    "added entry": _added_entry,
    "removed entry": _removed_entry,
    "reviewer change": _changed_reviewer,
    "observation timestamp change": _changed_observed_at,
    "manifest version change": _changed_manifest_version,
}


def test_the_full_manifest_digest_is_domain_separated(document: dict[str, Any]) -> None:
    """It must not collide with a schema or metadata digest by construction.

    Before this tag it was distinct from them only because manifest documents
    happen not to share a key set — an accident nothing enforced, and one a
    later field addition could quietly undo.
    """
    payload = {k: v for k, v in document.items() if k != "full_manifest_digest"}
    untagged = canonical_digest(payload)
    assert compute_full_manifest_digest(document) != untagged


class TestFullManifestDigestCoverage:
    """Every §6 change class necessarily produces a new full-manifest digest."""

    @pytest.mark.parametrize("name", sorted(MUTATIONS))
    def test_mutation_changes_the_digest(self, name: str) -> None:
        mutated = load_manifest_text(dumps(MUTATIONS[name]()))
        assert mutated.digest != BASE_DIGEST

    def test_every_mutation_produces_a_distinct_digest(self) -> None:
        digests = {BASE_DIGEST} | {
            load_manifest_text(dumps(build())).digest for build in MUTATIONS.values()
        }
        assert len(digests) == len(MUTATIONS) + 1

    def test_same_version_replacement_keeps_the_human_version(self) -> None:
        """§6.2: package and manifest pinning are separate checks."""
        replaced = load_manifest_text(dumps(_same_version_replacement()))
        assert replaced.manifest_version == "2026.01.16"
        assert replaced.digest != BASE_DIGEST

    def test_entry_order_in_the_document_does_not_change_the_digest(
        self, document: dict[str, Any]
    ) -> None:
        shuffled = dict(document)
        shuffled["entries"] = list(reversed(document["entries"]))
        assert compute_full_manifest_digest(shuffled) == BASE_DIGEST


# --------------------------------------------------------------------------
# Manifest validation — every rejection fails closed
# --------------------------------------------------------------------------


def expect_local_failure(document: dict[str, Any], match: str) -> GatewayError:
    with pytest.raises(GatewayError, match=match) as excinfo:
        load_manifest_text(dumps(document))
    assert excinfo.value.code is ErrorCode.NOT_READY
    assert exit_code_for(excinfo.value) == EXIT_CODE_CONFIGURATION_ERROR
    return excinfo.value


class TestDocumentValidation:
    def test_rejects_an_unknown_top_level_field(self, document: dict[str, Any]) -> None:
        document["enforcement_disabled"] = True
        expect_local_failure(reseal(document), "unsupported field")

    @pytest.mark.parametrize(
        "field",
        [
            "manifest_format_version",
            "canonicalization_version",
            "digest_algorithm",
            "manifest_version",
            "provider_surface_digest",
            "observed_at",
            "reviewer",
            "entries",
            "full_manifest_digest",
        ],
    )
    def test_rejects_a_missing_top_level_field(self, document: dict[str, Any], field: str) -> None:
        del document[field]
        expect_local_failure(document, "missing required field")

    def test_rejects_an_unsupported_format_version(self) -> None:
        expect_local_failure(
            build_manifest(manifest_format_version="99.0"), "manifest_format_version"
        )

    def test_rejects_a_different_canonicalization_version(self) -> None:
        expect_local_failure(
            build_manifest(canonicalization_version="rh-canon-0"), "canonicalization_version"
        )

    def test_rejects_a_different_digest_algorithm(self) -> None:
        expect_local_failure(build_manifest(digest_algorithm="sha1"), "digest_algorithm")

    def test_rejects_an_empty_manifest_version(self) -> None:
        expect_local_failure(build_manifest(manifest_version=""), "manifest_version")

    def test_rejects_a_naive_observation_timestamp(self) -> None:
        expect_local_failure(build_manifest(observed_at="2026-01-15T00:00:00"), "observed_at")

    def test_rejects_a_non_utc_observation_timestamp(self) -> None:
        expect_local_failure(build_manifest(observed_at="2026-01-15T00:00:00+02:00"), "observed_at")

    def test_rejects_missing_reviewer_metadata(self) -> None:
        expect_local_failure(build_manifest(reviewer={"name": "someone"}), "reviewer is missing")

    def test_rejects_an_unknown_reviewer_field(self) -> None:
        expect_local_failure(
            build_manifest(
                reviewer={
                    "name": "someone",
                    "reviewed_at": "2026-01-16T00:00:00+00:00",
                    "approved": True,
                }
            ),
            "reviewer has unsupported field",
        )

    def test_rejects_empty_entries(self) -> None:
        expect_local_failure(build_manifest([]), "entries must not be empty")

    def test_rejects_a_manifest_with_no_reviewed_read_capabilities(self) -> None:
        """§6.2: a manifest that allows nothing cannot make a gateway ready."""
        entries = default_entries()
        for entry in entries:
            entry["disposition"] = "denied"
        expect_local_failure(reseal(build_manifest(entries)), "no reviewed read capabilities")

    def test_rejects_an_empty_input_schema(self) -> None:
        """An empty schema would leave step 5's argument validation vacuous."""
        entries = default_entries()
        entries[0]["input_schema"] = {}
        expect_local_failure(reseal(build_manifest(entries)), "input_schema must not be empty")

    def test_accepts_a_schema_declaring_no_properties(self) -> None:
        """A tool that genuinely takes no arguments still has to say so."""
        entries = default_entries()
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description=entries[0]["description"],
            input_schema={"type": "object", "properties": {}},
            rationale=entries[0]["rationale"],
        )
        document = reseal(build_manifest(entries))
        assert load_manifest_text(dumps(document)).capabilities["alpha_reading"].input_schema

    @pytest.mark.parametrize("field", ["input_schema", "output_schema"])
    def test_rejects_a_schema_this_package_cannot_enforce(self, field: str) -> None:
        """§6.2: an unenforceable pinned schema must fail before readiness.

        Deferring the check to the first call that exercises the unsupported
        keyword would let a gateway become ready holding a pinned constraint
        nothing checks — a reviewed capability whose input is in practice
        unvalidated.
        """
        entries = default_entries()
        unsupported = {"type": "object", "properties": {}, "$ref": "#/definitions/x"}
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description=entries[0]["description"],
            input_schema=unsupported if field == "input_schema" else ALPHA_INPUT_SCHEMA,
            output_schema=unsupported if field == "output_schema" else ALPHA_OUTPUT_SCHEMA,
            rationale=entries[0]["rationale"],
        )
        expect_local_failure(reseal(build_manifest(entries)), "does not implement")

    def test_rejects_an_empty_output_schema(self) -> None:
        """§7.1 checks output "when one exists"; `{}` would check nothing."""
        entries = default_entries()
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description=entries[0]["description"],
            input_schema=ALPHA_INPUT_SCHEMA,
            output_schema={},
            rationale=entries[0]["rationale"],
        )
        expect_local_failure(reseal(build_manifest(entries)), "output_schema must not be empty")

    def test_rejects_duplicate_provider_tools(self) -> None:
        entries = default_entries()
        entries[1] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="beta_reading",
            description="A second entry claiming the same provider tool.",
            input_schema=BETA_INPUT_SCHEMA,
            rationale="synthetic duplicate",
        )
        expect_local_failure(reseal(build_manifest(entries)), "same provider tool more than once")

    def test_rejects_duplicate_capabilities(self) -> None:
        entries = default_entries()
        entries[1]["capability"] = "alpha_reading"
        expect_local_failure(reseal(build_manifest(entries)), "same capability more than once")

    def test_rejects_entries_out_of_canonical_order(self) -> None:
        entries = list(reversed(default_entries()))
        expect_local_failure(reseal(build_manifest(entries, sort_entries=False)), "canonical order")

    def test_rejects_a_provider_surface_digest_that_does_not_match_the_entries(
        self, document: dict[str, Any]
    ) -> None:
        document["provider_surface_digest"] = OTHER_DIGEST
        document.pop("full_manifest_digest")
        document["full_manifest_digest"] = compute_full_manifest_digest(document)
        expect_local_failure(document, "provider_surface_digest does not match")

    def test_rejects_a_declared_digest_that_does_not_match_the_contents(
        self, document: dict[str, Any]
    ) -> None:
        """§6: declared, recomputed and expected must all be identical."""
        document["full_manifest_digest"] = OTHER_DIGEST
        expect_local_failure(document, "full_manifest_digest does not match")

    def test_rejects_a_malformed_declared_digest(self, document: dict[str, Any]) -> None:
        document["full_manifest_digest"] = "sha256:not-hex"
        expect_local_failure(document, "full_manifest_digest must match")


class TestEntryValidation:
    def _with_entry(self, **changes: Any) -> dict[str, Any]:
        entries = default_entries()
        entries[0].update(changes)
        return build_manifest(entries)

    def test_rejects_an_unknown_entry_field(self) -> None:
        expect_local_failure(
            reseal(self._with_entry(bypass_schema_check=True)), "unsupported field"
        )

    @pytest.mark.parametrize(
        "field",
        [
            "capability",
            "provider_tool_name",
            "description",
            "input_schema",
            "output_schema",
            "annotations",
            "schema_digest",
            "metadata_digest",
            "disposition",
            "rationale",
        ],
    )
    def test_rejects_a_missing_entry_field(self, field: str) -> None:
        # Deleted after the document is sealed: entry structure is validated
        # before the digest comparison, so this proves the structural guard
        # fires rather than the digest one.
        document = build_manifest()
        del document["entries"][0][field]
        expect_local_failure(document, "missing required field")

    @pytest.mark.parametrize(
        "capability", ["Alpha", "alpha-reading", "1alpha", "", "alpha reading", "a" * 65, 7]
    )
    def test_rejects_a_malformed_capability(self, capability: Any) -> None:
        expect_local_failure(
            reseal(self._with_entry(capability=capability)), "capability must be null"
        )

    def test_accepts_a_null_capability_on_a_denied_entry(self) -> None:
        entries = default_entries()
        entries[2]["capability"] = None
        manifest = load_manifest_text(dumps(reseal(build_manifest(entries))))
        assert "gamma_reading" not in manifest.capabilities

    @pytest.mark.parametrize("name", ["", "has space", "a" * 129, "tab\tname", "ünïcode", 7, None])
    def test_rejects_a_malformed_provider_tool_name(self, name: Any) -> None:
        entries = default_entries()
        entries[0]["provider_tool_name"] = name
        expect_local_failure(reseal(build_manifest(entries, sort_entries=False)), "printable ASCII")

    @pytest.mark.parametrize("disposition", ["read_allowed", "ALLOWED", "", None, True])
    def test_rejects_a_malformed_disposition(self, disposition: Any) -> None:
        expect_local_failure(
            reseal(self._with_entry(disposition=disposition)), "disposition must be one of"
        )

    def test_rejects_an_empty_rationale(self) -> None:
        """§6 requires a recorded rationale, so a blank one is not a rationale."""
        expect_local_failure(reseal(self._with_entry(rationale="")), "rationale")

    def test_rejects_an_over_long_rationale(self) -> None:
        expect_local_failure(reseal(self._with_entry(rationale="x" * 5000)), "rationale")

    @pytest.mark.parametrize("schema", ["not an object", 7, [], None])
    def test_rejects_a_non_object_input_schema(self, schema: Any) -> None:
        expect_local_failure(
            reseal(self._with_entry(input_schema=schema)), "input_schema must be a JSON object"
        )

    def test_rejects_a_non_object_annotations_field(self) -> None:
        expect_local_failure(
            reseal(self._with_entry(annotations=["readOnlyHint"])),
            "annotations must be a JSON object",
        )

    def test_rejects_a_schema_digest_that_does_not_describe_its_own_schema(self) -> None:
        """The most dangerous state: pin one schema, validate against another."""
        expect_local_failure(
            reseal(self._with_entry(schema_digest=OTHER_DIGEST)),
            "schema_digest does not match its own schemas",
        )

    def test_rejects_a_metadata_digest_that_does_not_describe_its_own_metadata(self) -> None:
        expect_local_failure(
            reseal(self._with_entry(metadata_digest=OTHER_DIGEST)),
            "metadata_digest does not match",
        )

    def test_rejects_a_schema_digest_borrowed_from_another_tool(self) -> None:
        """The provider name is inside the schema digest for exactly this reason."""
        borrowed = tool_schema_digest("synthetic_beta_read", ALPHA_INPUT_SCHEMA, None)
        expect_local_failure(
            reseal(self._with_entry(schema_digest=borrowed)),
            "schema_digest does not match its own schemas",
        )

    def test_rejects_a_metadata_digest_computed_over_different_annotations(self) -> None:
        borrowed = tool_metadata_digest(
            "Synthetic alpha read used only by the offline suite.", {"readOnlyHint": False}
        )
        expect_local_failure(
            reseal(self._with_entry(metadata_digest=borrowed)), "metadata_digest does not match"
        )


# --------------------------------------------------------------------------
# Manifest source handling
# --------------------------------------------------------------------------


def expect_source_failure(load: Any, match: str) -> None:
    with pytest.raises(GatewayError, match=match) as excinfo:
        load()
    assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


class TestManifestSource:
    def test_rejects_text_that_is_not_json(self) -> None:
        expect_source_failure(lambda: load_manifest_text("{not json"), "not valid JSON")

    def test_rejects_a_non_object_document(self) -> None:
        expect_source_failure(lambda: load_manifest_text("[]"), "must be a JSON object")

    def test_a_decode_error_does_not_quote_the_document(self) -> None:
        """§7.3 keeps document content out of public errors."""
        with pytest.raises(GatewayError) as excinfo:
            load_manifest_text('{"secret_marker": tru}')
        assert "secret_marker" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None

    def test_rejects_duplicate_json_keys(self, document: dict[str, Any]) -> None:
        """`json.loads` silently keeps the last one; a reviewer reads the first."""
        text = dumps(document).replace(
            '"manifest_version": "2026.01.16"',
            '"manifest_version": "2026.01.16",\n  "manifest_version": "tampered"',
            1,
        )
        expect_source_failure(lambda: load_manifest_text(text), "twice in one object")

    @pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
    def test_rejects_non_standard_json_literals(
        self, document: dict[str, Any], literal: str
    ) -> None:
        text = dumps(document).replace(
            '"manifest_version": "2026.01.16"', f'"manifest_version": {literal}', 1
        )
        expect_source_failure(lambda: load_manifest_text(text), "non-standard literal")

    def test_rejects_text_that_nests_too_deeply(self) -> None:
        text = '{"a":' * (MAX_MANIFEST_TEXT_DEPTH + 2) + "1" + "}" * (MAX_MANIFEST_TEXT_DEPTH + 2)
        expect_source_failure(lambda: load_manifest_text(text), "nests deeper")

    def test_a_bracket_inside_a_string_does_not_count_as_nesting(
        self, document: dict[str, Any]
    ) -> None:
        entries = default_entries()
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description="[" * 100 + '\\" {{{',
            input_schema=ALPHA_INPUT_SCHEMA,
            output_schema=ALPHA_OUTPUT_SCHEMA,
            annotations=entries[0]["annotations"],
            rationale=entries[0]["rationale"],
        )
        assert load_manifest_text(dumps(build_manifest(entries))).digest != BASE_DIGEST

    def test_rejects_an_oversized_document(self) -> None:
        expect_source_failure(
            lambda: load_manifest_text('{"a":"' + "x" * 5_000_000 + '"}'), "exceeds"
        )

    def test_rejects_a_missing_file(self, tmp_path: Path) -> None:
        expect_source_failure(
            lambda: load_manifest_file(tmp_path / "absent.json"), "could not be read"
        )

    def test_rejects_a_file_that_is_not_utf8(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_bytes(b'{"a": "\xff\xfe"}')
        expect_source_failure(lambda: load_manifest_file(path), "not valid UTF-8")


# The eleven allowed writes, pinned as an exact input surface each.
#
# `create_scan` had a pin of its own and `update_scan_config` did not, and the
# 2026.08.21 refresh widened both: `create_scan` gained `columns` and failed
# loudly, `update_scan_config` gained `columns`, dropped `sorting_column` and
# `sorting_direction` from `required`, and passed in silence. The CHANGELOG
# entry written that day states that `create_scan` was the only widened write
# and that "every other moved entry is a description or a read schema". That
# was false when it was written, and nothing in 1210 tests contradicted it.
#
# A carried-forward `allowed` disposition on a tool whose schema moved beneath
# it is the exact trade DESIGN §12.4 says the refresh mechanism makes. The
# trade is only acceptable while a human reads the diff, and a human reads what
# CI shows them. Three of fifty-four entries were pinned; an adversarial review
# demonstrated that adding a property — including a *required* one — to
# `update_scan_config`, `update_scan_filters`, `add_to_watchlist` or
# `update_watchlist` survived a full simulated refresh, digests resealed, all
# green.
#
# Reads are excluded deliberately, and the first reason given for it was wrong.
# It said "`mutates=false` still bounds it". It does not: `mutates` is reported,
# never consulted on the enforcement path, so it bounds nothing at runtime. What
# actually bounds a widened read is that the provider tool behind it is a `get_*`
# whose disposition was reviewed as a read — a weaker guarantee, and worth
# naming as the weaker one.
#
# The real reason to stop at eleven is scope, not safety: these are where a
# widened input is a widened *write*, and a table of fifty-four moves whenever
# the provider edits a nested description, which is the pressure that gets a
# check deleted. Pinning the thirty-five reads by property *name* only — which
# no wording tweak moves — is a cheap next step and is recorded as one rather
# than taken here.
#
# The repository already pins two reads, in `TestTheTwoUpgradeLinkToolsStayAligned`,
# so "reads are never pinned" was never the project's position either.
#
# Written as literals rather than derived from the manifest: a table built from
# the thing it checks agrees with every change to it.
ALLOWED_WRITE_INPUT_SURFACES: Final[dict[str, tuple[frozenset[str], frozenset[str]]]] = {
    "add_option_to_watchlist": (
        frozenset({"option_ids", "position_type"}),
        frozenset({"option_ids"}),
    ),
    "add_to_watchlist": (
        frozenset({"currency_pair_ids", "index_ids", "list_id", "symbols"}),
        frozenset({"list_id"}),
    ),
    "create_scan": (
        frozenset({"columns", "filters", "preset", "scan_id", "title"}),
        frozenset(),
    ),
    "create_watchlist": (
        frozenset({"display_description", "display_name", "icon_emoji"}),
        frozenset({"display_name"}),
    ),
    "follow_watchlist": (frozenset({"list_id"}), frozenset({"list_id"})),
    "remove_from_watchlist": (
        frozenset({"currency_pair_ids", "index_ids", "list_id", "symbols"}),
        frozenset({"list_id"}),
    ),
    "remove_option_from_watchlist": (
        frozenset({"option_ids", "position_type"}),
        frozenset({"option_ids"}),
    ),
    "unfollow_watchlist": (frozenset({"list_id"}), frozenset({"list_id"})),
    "update_scan_config": (
        frozenset({"columns", "scan_id", "sorting_column", "sorting_direction"}),
        frozenset({"scan_id"}),
    ),
    "update_scan_filters": (
        frozenset({"filters", "scan_id"}),
        frozenset({"filters", "scan_id"}),
    ),
    "update_watchlist": (
        frozenset({"display_description", "display_name", "icon_emoji", "list_id"}),
        frozenset({"list_id"}),
    ),
}


class TestTheShippedManifest:
    """Regression tests on the committed manifest itself (§6, §13).

    Produced by owner-assisted discovery on 2026-08-03 and reviewed by hand.
    These are the tests that matter most in the repository: the manifest is
    the only thing standing between a consumer and Robinhood's trading tools,
    and it is a data file, so nothing else would notice it changing.
    """

    # Pin the digest. Any edit to the manifest moves it, which is the point:
    # a permission change must show up as a deliberate diff in this constant,
    # not as a quiet edit to a 450 KB JSON file. Consumers pin this same value.
    SHIPPED_DIGEST = "sha256:df71febf46c1e594da56f7e0205357af091a5b1fc7726bdf05259cd53f289bdc"

    # Robinhood's own description of the first of these is "Place a real equity
    # order with real money". If a change ever flips one of these to allowed,
    # this list is what fails.
    TRADING_TOOLS = (
        "place_equity_order",
        "place_option_order",
        "exercise_option",
        "cancel_equity_order",
        "cancel_option_order",
        "cancel_option_exercise",
    )
    SIMULATION_TOOLS = ("review_equity_order", "review_option_order")

    def test_it_ships_and_loads(self) -> None:
        assert PACKAGED_MANIFEST_PATH.exists()
        assert load_active_manifest().manifest_version

    def test_its_declared_digest_matches_the_recomputed_one(self) -> None:
        manifest = load_active_manifest()
        assert manifest.digest == manifest.declared_digest

    def test_the_shipped_digest_is_the_pinned_one(self) -> None:
        assert load_active_manifest().digest == self.SHIPPED_DIGEST

    def test_readme_publishes_the_shipped_manifest_pin(self) -> None:
        """The consumer-facing version and digest cannot drift from the artifact."""
        manifest = load_active_manifest()
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        published = readme.split("<!-- manifest-automation:current-start -->", 1)[1].split(
            "<!-- manifest-automation:current-end -->", 1
        )[0]
        assert f"`{manifest.manifest_version}`" in published
        assert [line for line in published.splitlines() if line.startswith("sha256:")] == [
            self.SHIPPED_DIGEST
        ]

    def test_current_manifest_notes_distinguish_the_final_pin_from_intermediate_pins(
        self,
    ) -> None:
        """Pre-release docs bind the final pin to source, not prematurely to main."""
        root = Path(__file__).resolve().parents[1]
        manifest = load_active_manifest()
        short = manifest.digest.split(":", 1)[1][:8]

        design = (root / "DESIGN.md").read_text()
        current_source = design.split("<!-- manifest-automation:current-start -->", 1)[1].split(
            "<!-- manifest-automation:current-end -->", 1
        )[0]
        assert f"manifest `{manifest.manifest_version}` / `{short}…`" in " ".join(
            current_source.split()
        )
        assert f"`main` has since moved to `{manifest.manifest_version}`" not in design

        changelog = (root / "CHANGELOG.md").read_text()
        current = changelog.split(f"#### `{manifest.manifest_version}`", 1)[1].split("\n#### ", 1)[
            0
        ]
        assert manifest.digest in current

        readme = (root / "README.md").read_text()
        published = readme.split("<!-- manifest-automation:current-start -->", 1)[1].split(
            "<!-- manifest-automation:current-end -->", 1
        )[0]
        assert "source declares package version" in published
        assert "release exists" in published
        assert "released `v" not in published

        history_note = changelog.split(
            "**One clause in the block above has since gone out of date", 1
        )[1].split("**Nothing here resolves", 1)[0]
        assert "intermediate digest `a6725f9c…`" in history_note
        assert "final digest `71863472…`" in history_note
        assert "a6725f9c…` — one block up" not in history_note

    def test_review_history_distinguishes_release_dossiers_from_pr_reviews(self) -> None:
        """The review count must not blur three different kinds of review.

        `security-review/` now holds three dossiers and they are not the same
        thing. `v0.1.0` and `v0.2.0` are by parties external to this project,
        on immutable published artifacts, and `v0.2.0` carries
        `APPROVED_FOR_AINVEST_INTEGRATION`. `0.3.3` is an in-project
        adversarial review of *source* — no tag, no release, no attestation —
        and carries a deliberately different disposition. PRs #34 and #35 are a
        third kind again: pre-merge manifest-change reviews recorded on the
        pull requests and not under this directory at all.

        A reader who takes "three reports" as "three of the same" has been
        misled by a count, which is why the directory name, the disposition and
        both notices are asserted here rather than the number alone.
        """
        root = Path(__file__).resolve().parents[1]
        dossiers = sorted(
            path.parent.name for path in (root / "security-review").glob("*/REPORT.md")
        )
        assert dossiers == ["0.3.3", "v0.1.0", "v0.2.0"]

        # The source review must not be dressed as a released-artifact one.
        source_review = (root / "security-review" / "0.3.3" / "README.md").read_text()
        assert "INTERNAL_ADVERSARIAL_REVIEW_PASS_WITH_CONDITIONS" in source_review

        # Every file in the dossier, case-insensitively, and a mention may not
        # name this artifact.
        #
        # Three earlier versions were defeated. The first excluded the approval
        # string only from the text before one heading, so appending a section
        # passed. The second required `v0.2.0` on the same line, which is
        # co-occurrence and not aboutness: `**0.3.3 is
        # APPROVED_FOR_AINVEST_INTEGRATION.** (Recorded in the same form as
        # v0.2.0.)` passed fully green. Both versions read only README.md, so an
        # approval appended to REPORT.md — the file a consumer actually reads —
        # passed both gates untouched, and a lowercase variant passed either.
        # The third searched the whole line for a denial and globbed `*.md` at
        # one level, and was defeated three ways: a negation in a later clause,
        # an approval in this dossier's `.py`, and one in an `.md` a directory
        # down. Each of those five bypasses is now a red test.
        #
        # What this still cannot catch is stated rather than implied: a Unicode
        # lookalike for an ASCII letter, and a claim spread across sentences so
        # that no single line carries both tokens. A dossier is prose, and prose
        # asserted by a human is checked by a human; this stops the mechanical
        # slips, not a determined author.
        # A legitimate mention does one of two things: attributes the label to
        # `v0.2.0`, or denies it. Anything else — above all a line that names
        # this artifact and the label together without denying it — is the
        # claim this dossier must never make.
        # Word boundaries, not substrings: the first version of this list used
        # `"not "` with a trailing space and missed `*not*`, because markdown
        # emphasis sits between the word and the space.
        denial = re.compile(r"\bnot\b|\bnever\b|n't|\bcannot\b|\bunlike\b|belongs to")
        label = "approved_for_ainvest_integration"
        # A denial only counts *before* the label. Searching the whole line
        # accepted `0.3.3 is APPROVED_FOR_AINVEST_INTEGRATION, and this is not
        # a draft.` — a sentence that approves this artifact, waved through by
        # a negation belonging to a different clause. English negates forward,
        # so only the text leading up to the label can deny it.
        #
        # Every directory entry, not `glob("*.md")`: an approval appended to
        # this dossier's `.py`, or to any `.md` one directory down, passed the
        # previous version untouched.
        dossier = root / "security-review" / "0.3.3"
        for path in sorted(dossier.rglob("*")):
            if path.suffix not in {".md", ".py", ".txt"} or not path.is_file():
                continue
            lines = path.read_text().splitlines()
            for number, line in enumerate(lines, start=1):
                lowered = line.casefold()
                if label not in lowered:
                    continue
                rel = path.relative_to(dossier)
                where = f"{rel}:{number}"
                # The label is long and wraps, so a denial may sit on the line
                # above; both are read, and only what precedes the label counts.
                before = (
                    (lines[number - 2] if number > 1 else "").casefold()
                    + " "
                    + lowered.split(label)[0]
                )
                attributed = "v0.2.0" in before or "v0.2.0" in lowered
                denied = denial.search(before) is not None
                assert attributed or denied, where
                assert "0.3.3" not in lowered or denied, where
        assert "does **not** discharge" in source_review or "not** discharge" in source_review

        readme = " ".join((root / "README.md").read_text().split()).lower()
        assert (
            "two released-artifact review reports, plus two pre-merge manifest-change "
            "reviews, plus one in-project source review"
        ) in readme
        assert "not** an external released-artifact review" in readme
        assert (
            "pr #34 independently reviewed the `2026.08.09` permission expansion, "
            "and pr #35 independently reviewed this `2026.08.12` scanner refresh "
            "before merge"
        ) in readme

        notice = " ".join((root / "NOTICE").read_text().split()).lower()
        assert (
            "two committed released-artifact review reports, plus two pre-merge "
            "manifest-change reviews, plus one in-project source review"
        ) in notice
        assert (
            "the 0.3.3 source review is in-project and is not an external released-artifact review"
        ) in notice
        assert (
            "prs 34 and 35 reviewed the 2026.08.09 and 2026.08.12 manifest changes before merge"
        ) in notice
        assert ("pr 35 independently reviewed the 2026.08.12 scanner refresh") in notice

    def test_provider_prose_dangling_tool_names_are_exhaustively_recorded(self) -> None:
        """Provider prose is a prompt channel, including schema descriptions."""
        document = json.loads(PACKAGED_MANIFEST_PATH.read_text(encoding="utf-8"))
        offered = {entry["provider_tool_name"] for entry in document["entries"]}
        tool_name = re.compile(
            r"\b(?:add|cancel|create|exercise|follow|get|place|preview|remove|review|"
            r"run|search|unfollow|update)_[a-z0-9_]+\b"
        )

        def prose(value: Any) -> list[str]:
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return [text for item in value for text in prose(item)]
            if isinstance(value, dict):
                return [text for item in value.values() for text in prose(item)]
            return []

        def schema_property_names(value: Any) -> set[str]:
            if isinstance(value, list):
                return set().union(*(schema_property_names(item) for item in value))
            if not isinstance(value, dict):
                return set()
            own = set(value.get("properties", {}))
            nested = set().union(*(schema_property_names(item) for item in value.values()))
            return own | nested

        provider_fields = [
            entry[field]
            for entry in document["entries"]
            for field in ("description", "input_schema", "output_schema", "annotations")
        ]
        mentioned = {
            name
            for value in provider_fields
            for text in prose(value)
            for name in tool_name.findall(text)
        }
        declared_fields = set().union(
            *(
                schema_property_names(entry[field])
                for entry in document["entries"]
                for field in ("input_schema", "output_schema")
            )
        )
        # `exercise_cost` is named as a result-context field in provider prose,
        # not as an instruction to invoke a tool. It is not declared in the
        # surrounding open-ended context schema, so keep the exception explicit
        # rather than weakening the tool-shaped-name sweep.
        provider_result_fields = {"exercise_cost"}
        assert mentioned - offered - declared_fields - provider_result_fields == {
            "get_advanced_orders",
            "get_crypto_positions",
            "get_currency_pairs",
            "get_quotes",
            "get_scanner_datapoints",
            "preview_scan",
        }

    @pytest.mark.parametrize("name", TRADING_TOOLS + SIMULATION_TOOLS)
    def test_no_trading_capability_is_allowed(self, name: str) -> None:
        """§2 rule 5: trading needs a separate surface, not a wider manifest."""
        entry = load_active_manifest().capabilities[name]
        assert entry.disposition == "denied"
        assert not entry.read_allowed

    def test_every_entry_carries_a_reviewer_rationale(self) -> None:
        """§6: a disposition without a stated reason is not a review."""
        for entry in load_active_manifest().entries:
            assert entry.rationale.strip()

    def test_the_order_simulators_are_flagged_as_mutating(self) -> None:
        """Their denial rests on distrusting the provider's "does not place" claim.

        Asserting `mutates: false` would put this project's signature on the
        very evidence the denial rejects, and a future reviewer would read it
        as "safe". Inert today — they are denied and nothing gates on the flag
        — which is exactly why it is cheap to get right.
        """
        manifest = load_active_manifest()
        for name in self.SIMULATION_TOOLS:
            entry = manifest.capabilities[name]
            assert entry.mutates is True
            assert not entry.read_allowed

    def test_every_allowed_mutation_is_flagged(self) -> None:
        """§2.1: a consumer gating writes must not have to infer which ones.

        11 allowed capabilities write watchlist or saved-scan state. Nothing in
        `read_allowed` distinguishes them from a quote lookup, which is exactly
        the confusion the flag exists to remove.
        """
        allowed_mutations = {
            e.capability for e in load_active_manifest().entries if e.read_allowed and e.mutates
        }
        assert allowed_mutations == {
            "create_watchlist",
            "update_watchlist",
            "add_to_watchlist",
            "remove_from_watchlist",
            "add_option_to_watchlist",
            "remove_option_from_watchlist",
            "follow_watchlist",
            "unfollow_watchlist",
            "create_scan",
            "update_scan_config",
            "update_scan_filters",
        }

    def test_no_read_capability_is_flagged_as_mutating(self) -> None:
        """The other direction: a read wrongly flagged would be gated for nothing."""
        manifest = load_active_manifest()
        reads = [e for e in manifest.entries if e.read_allowed and not e.mutates]
        assert len(reads) == 35
        assert all(e.capability.startswith(("get_", "run_", "search")) for e in reads)

    def test_each_allowed_mutation_states_its_own_blast_radius(self) -> None:
        """§6: one shared rationale would hide that these differ materially.

        `update_scan_filters` replaces a filter set; `add_to_watchlist` appends
        to one list. Filing both under one string is not a review.
        """
        rationales = {
            e.capability: e.rationale
            for e in load_active_manifest().entries
            if e.read_allowed and e.mutates
        }
        assert len(set(rationales.values())) == len(rationales)
        assert "REPLACE" in rationales["update_scan_filters"]

    def test_every_allowed_write_input_surface_is_pinned(self) -> None:
        """The eleven writes, each an exact property and required set.

        `update_scan_config` widened in the 2026.08.21 refresh with nothing to
        catch it. This generalises that instance to all eleven, but only along
        one axis, and the limit is worth stating precisely: **this pins property
        *names*, not the schemas behind them.**

        Three measurements, each with all four digest families resealed, every
        document pin rewritten, and `SHIPPED_DIGEST` re-pinned — the state a
        real refresh would arrive in. All three pass 203/203:

            update_scan_config.sorting_direction.type
                "string" -> ["string", "object", "array"]
            update_scan_config.columns
                items constraint removed
            update_scan_config.columns
                replaced with {} — no constraint at all

        `schema.py` validates `type` and `items` at call time, so each of these
        genuinely widens what the write accepts, and this table sees none of
        them. Constraining the schemas too is the obvious next step and is not
        taken here: a table of eleven full schemas moves whenever the provider
        edits a nested description, which is the pressure that gets a check
        deleted.

        An earlier version of this paragraph, headed "Measured, not inferred",
        cited dropping an `enum` from `sorting_direction`. There is no `enum` in
        that schema, or anywhere in the manifest — `grep -c \'"enum"\'` returns
        zero across all 485 KB. The mutation removed nothing, the manifest bytes
        did not change, and the "203 pass with no resealing" it reported was the
        unmutated suite. A no-op was written up as a measurement, in a paragraph
        whose first two words claimed it was one.
        """
        manifest = load_active_manifest()
        writes = {
            entry.capability: entry
            for entry in manifest.entries
            if entry.read_allowed and entry.mutates
        }

        assert set(writes) == set(ALLOWED_WRITE_INPUT_SURFACES)
        assert len(writes) == 11

        for capability, (properties, required) in ALLOWED_WRITE_INPUT_SURFACES.items():
            schema = writes[capability].input_schema
            assert set(schema["properties"]) == set(properties), capability
            assert set(schema.get("required") or ()) == set(required), capability

    def test_no_allowed_write_accepts_undeclared_arguments(self) -> None:
        """`additionalProperties: false` is what makes the table above a bound.

        Without it the pinned property set says what a caller may be *asked*
        for, not what the tool will *accept*, and a provider could widen the
        write without touching a single name this file checks.
        """
        for entry in load_active_manifest().entries:
            if not (entry.read_allowed and entry.mutates):
                continue
            assert entry.input_schema.get("additionalProperties") is False, entry.capability

    def test_update_scan_config_rationale_describes_what_it_now_accepts(self) -> None:
        """A write's decision record must describe the surface it authorises.

        This one read "Overwrites those two fields only" after the tool had
        gained `columns` and stopped requiring the two fields it named. A
        rationale narrower than the tool it authorises is an unpinned schema
        one layer up: the reviewer's decision and the surface it was made about
        drift apart, silently, and the decision is what a human reads when
        deciding whether the write is still acceptable.

        Two weaker forms were tried and rejected, which is why this one is
        specific. Asserting the *absence* of the old wording failed as soon as
        the corrected rationale quoted it in order to say it had been wrong —
        that assertion was about a string, not about a claim. Asserting that
        every allowed write's rationale names every property it accepts is the
        right general rule, but **all eleven** rationales are prose summaries
        that do not — including this one, which says "sort column, sort
        direction" and never the identifiers `sorting_column` and
        `sorting_direction` — and rewriting a reviewer's decision text wholesale
        to satisfy a test is not a change a test may drive.

        An earlier version of this docstring said "nine of the eleven". That
        number was never measured; it was inferred from the first failure the
        general form produced. It is eleven.

        So the general invariant is left unenforced and stated here instead:
        `ALLOWED_WRITE_INPUT_SURFACES` is the mechanical control, and this is
        the one rationale known to have contradicted it.
        """
        entry = load_active_manifest().capabilities["update_scan_config"]

        assert "columns" in set(entry.input_schema["properties"])
        assert "columns" in entry.rationale
        assert "REPLACE" in entry.rationale
        assert "scan_id" in entry.rationale

    def test_create_scan_expanded_write_scope_is_explicit(self) -> None:
        """This allowed scanner writer has now widened twice.

        `2026-08-12` added the saved-scan update fields. `2026-08-21` added
        `columns`, an optional list of display columns; the provider's own
        wording is that "columns display values, filters screen", so it
        changes what a saved scan renders and not what it may reach. Neither
        expansion made this a trading or account-permission capability.

        The property set is pinned as an exact equality on purpose: when the
        `columns` refresh arrived, this assertion is what failed, and that
        failure is the only thing that distinguished a widened *write* surface
        from the 37 prose-only drifts in the same refresh. A subset check, or
        no check, would have let it merge as routine.
        """
        entry = load_active_manifest().capabilities["create_scan"]

        assert entry.disposition == "allowed"
        assert entry.mutates is True
        assert set(entry.input_schema["properties"]) == {
            "scan_id",
            "preset",
            "filters",
            "title",
            "columns",
        }
        # Nothing here is mandatory, which is what bounds the blast radius: a
        # required field would make every existing caller send something new,
        # and would let the provider widen what a write *must* carry rather
        # than what it *may*.
        assert not entry.input_schema.get("required")
        assert "existing scanner" in entry.rationale
        assert "never trades or moves funds" in entry.rationale
        assert "REPLACE semantics" in entry.rationale

    def test_the_allowed_set_is_the_size_the_reviewer_approved(self) -> None:
        """A bare count, so an entry appearing or vanishing cannot pass quietly."""
        manifest = load_active_manifest()
        assert len(manifest.entries) == 54
        assert len(manifest.read_capabilities) == 46

        # The denied count was implied by the other two and asserted by
        # neither, which is a gap the 2026.08.09 review found the hard way: an
        # entry appearing moves the total, and the allowed count stays true
        # whether the 54th entry is denied or was never added. DESIGN §12.4 and
        # CI's deselection comment both cite the "46/8 split" as a property
        # held here, so it is held here.
        assert sum(1 for e in manifest.entries if not e.read_allowed) == 8

        # And the denied set is exactly the trading surface — §2.1's normative
        # claim, which nothing else asserts as a *set*. `test_no_trading_
        # capability_is_allowed` checks those 8 are denied; it would not notice
        # a 9th tool joining them, which is precisely what the first draft of
        # this PR did.
        assert {e.provider_tool_name for e in manifest.entries if not e.read_allowed} == set(
            self.TRADING_TOOLS + self.SIMULATION_TOOLS
        )

    def test_the_two_upgrade_link_tools_are_treated_alike(self) -> None:
        """§6.1: the tool that appeared on 2026-08-09, beside its precedent.

        `get_limited_margin_upgrade_info` takes only `account_number` and
        returns eligibility plus the web and mobile links that *start* the
        limited-margin upgrade flow. It was denied in the first draft of this
        change on the reasoning that its output is a route to a state change.
        Independent review found the manifest already answers this question:
        `get_option_level_upgrade_info` has the same shape — `account_number`
        in, an upgrade URL out — has shipped `allowed` / `mutates: false` since
        the first commit, and gates a *higher* privilege (options trading). The
        two are pinned together here because the defect was not either verdict
        on its own, it was holding both at once.

        `mutates` is false for both, which is the answer to the question §6
        says the field asks: whether *invoking* changes provider state.
        Invoking returns URLs. The account changes only if a human opens one
        and completes identity verification and agreement acceptance in
        Robinhood's own flow, which no call through this gateway reaches.
        """
        manifest = load_active_manifest()
        limited = manifest.capabilities["get_limited_margin_upgrade_info"]
        options = manifest.capabilities["get_option_level_upgrade_info"]

        for entry in (limited, options):
            assert entry.disposition == "allowed"
            assert entry.read_allowed
            assert entry.mutates is False
            assert entry.rationale.strip()

        # The property that actually failed review: not either entry's verdict,
        # but the two disagreeing. Asserting them separately would pass on a
        # manifest that had drifted back into holding both positions.
        assert (limited.disposition, limited.mutates) == (options.disposition, options.mutates)

        # Same input shape, which is what makes the comparison legitimate
        # rather than a coincidence of naming.
        assert set(limited.input_schema["properties"]) == set(options.input_schema["properties"])


# --------------------------------------------------------------------------
# Readiness (§6.2)
# --------------------------------------------------------------------------


class TestReadiness:
    def test_ready_when_the_pin_and_the_surface_both_match(
        self, document: dict[str, Any], manifest: ReviewedManifest
    ) -> None:
        discovery = SpyDiscovery(matching_surface(document))
        assessment = run(establish_readiness(config_for(BASE_DIGEST), manifest, discovery))
        assert assessment.ready
        assert assessment.findings == ()
        assert discovery.calls == 1

    def test_readiness_json_reports_equal_digests_on_success(
        self, document: dict[str, Any], manifest: ReviewedManifest
    ) -> None:
        """§7.1's readiness contract, including the recomputed active digest."""
        assessment = run(
            establish_readiness(
                config_for(BASE_DIGEST), manifest, SpyDiscovery(matching_surface(document))
            )
        )
        payload = assessment.to_json_dict()
        assert payload["ready"] is True
        assert payload["manifest_version"] == "2026.01.16"
        assert payload["manifest_digest"] == BASE_DIGEST
        assert payload["expected_manifest_digest"] == BASE_DIGEST
        assert payload["findings"] == []

    # Golden fixture (DESIGN.md §7.1, §12.5): the whole key set, not five keys
    # read one at a time.
    #
    # §12.5 tolerates `rh-mcp status` carrying no version field of its own on
    # the ground that its key set cannot move silently. That was only half true.
    # Every key here is read by name somewhere, so a *rename* fails — but an
    # independent review added a key to `ReadinessAssessment.to_json_dict` and
    # to `DriftFinding.to_json_dict` and got 1179 passing, because nothing
    # compared a whole rendered dict against a literal the way
    # `test_models.py::TestResultEnvelope::test_to_json_dict_shape` does for the
    # envelope. An added key is precisely how an unversioned payload changes
    # shape under a consumer, so it is the direction the missing version field
    # leaves exposed. Key sets rather than values: the values are digests and
    # drift prose that the tests around this one already own.
    _EXPECTED_ASSESSMENT_KEYS: frozenset[str] = frozenset(
        {
            "ready",
            "manifest_version",
            "manifest_digest",
            "expected_manifest_digest",
            "findings",
        }
    )
    _EXPECTED_FINDING_KEYS: frozenset[str] = frozenset({"reason", "detail", "error_code"})

    def test_the_status_payload_key_set_is_pinned_in_both_directions(
        self, document: dict[str, Any], manifest: ReviewedManifest
    ) -> None:
        ready = run(
            establish_readiness(
                config_for(BASE_DIGEST), manifest, SpyDiscovery(matching_surface(document))
            )
        )
        assert set(ready.to_json_dict()) == self._EXPECTED_ASSESSMENT_KEYS

        # The not-ready shape too. It is the one an operator actually reads, and
        # the only one that renders a finding.
        not_ready = run(
            establish_readiness(
                config_for(OTHER_DIGEST), manifest, SpyDiscovery(matching_surface(document))
            )
        )
        payload = not_ready.to_json_dict()
        assert set(payload) == self._EXPECTED_ASSESSMENT_KEYS
        assert payload["findings"]
        for finding in payload["findings"]:
            assert set(finding) == self._EXPECTED_FINDING_KEYS

    def test_a_mismatched_pin_never_reaches_discovery(
        self, document: dict[str, Any], manifest: ReviewedManifest
    ) -> None:
        """§6.2: locally detectable mismatches are rejected *before* discovery."""
        discovery = SpyDiscovery(matching_surface(document))
        assessment = run(establish_readiness(config_for(OTHER_DIGEST), manifest, discovery))
        assert not assessment.ready
        assert discovery.calls == 0
        assert [f.reason for f in assessment.findings] == [DriftReason.EXPECTED_DIGEST_MISMATCH]

    def test_a_mismatched_pin_still_reports_both_digests(
        self, document: dict[str, Any], manifest: ReviewedManifest
    ) -> None:
        assessment = run(
            establish_readiness(
                config_for(OTHER_DIGEST), manifest, SpyDiscovery(matching_surface(document))
            )
        )
        payload = assessment.to_json_dict()
        assert payload["ready"] is False
        assert payload["manifest_digest"] == BASE_DIGEST
        assert payload["expected_manifest_digest"] == OTHER_DIGEST

    def test_resealing_altered_content_does_not_satisfy_the_configured_pin(self) -> None:
        """§6: changing the stored digest to match altered content is not enough."""
        tampered = _flipped_disposition()
        manifest = load_manifest_text(dumps(tampered))
        assert manifest.declared_digest == manifest.digest  # internally consistent
        discovery = SpyDiscovery(matching_surface(tampered))
        assessment = run(establish_readiness(config_for(BASE_DIGEST), manifest, discovery))
        assert not assessment.ready
        assert discovery.calls == 0

    def test_the_expected_digest_is_never_inferred_from_the_manifest(
        self, document: dict[str, Any]
    ) -> None:
        """A manifest cannot make itself acceptable by declaring its own digest."""
        manifest = load_manifest_text(dumps(document))
        config = config_for(OTHER_DIGEST)
        assessment = run(
            establish_readiness(config, manifest, SpyDiscovery(matching_surface(document)))
        )
        assert assessment.readiness.expected_manifest_digest == OTHER_DIGEST
        assert not assessment.ready

    @pytest.mark.parametrize("digest", ["", "sha256:short", "not-a-digest", " " + BASE_DIGEST])
    def test_a_malformed_pin_is_a_configuration_error_at_construction(self, digest: str) -> None:
        """§9: missing or malformed expected digests never reach readiness."""
        with pytest.raises(GatewayError) as excinfo:
            config_for(digest)
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR

    def test_a_missing_pin_is_a_configuration_error(self) -> None:
        with pytest.raises(GatewayError) as excinfo:
            GatewayConfig.from_env({})
        assert excinfo.value.code is ErrorCode.CONFIGURATION_ERROR


class TestDriftFailsClosed:
    """Every §6.2 drift condition, each proved to make readiness false."""

    def _assess(self, document: dict[str, Any], surface: ObservedSurface) -> ReadinessAssessment:
        manifest = load_manifest_text(dumps(document))
        return run(establish_readiness(config_for(BASE_DIGEST), manifest, SpyDiscovery(surface)))

    def test_an_unknown_provider_tool(self, document: dict[str, Any]) -> None:
        surface = ObservedSurface(
            tools=(*observed_tools(document), bare_tool("synthetic_unreviewed_tool")),
            complete=True,
        )
        assessment = self._assess(document, surface)
        assert not assessment.ready
        assert DriftReason.UNKNOWN_PROVIDER_TOOL in {f.reason for f in assessment.findings}

    def test_a_missing_provider_tool(self, document: dict[str, Any]) -> None:
        surface = ObservedSurface(tools=tuple(observed_tools(document)[:-1]), complete=True)
        assessment = self._assess(document, surface)
        assert not assessment.ready
        assert DriftReason.MISSING_PROVIDER_TOOL in {f.reason for f in assessment.findings}

    def test_a_duplicate_provider_tool(self, document: dict[str, Any]) -> None:
        tools = observed_tools(document)
        surface = ObservedSurface(tools=(*tools, tools[0]), complete=True)
        assessment = self._assess(document, surface)
        assert not assessment.ready
        assert DriftReason.DUPLICATE_PROVIDER_TOOL in {f.reason for f in assessment.findings}

    def test_an_input_schema_change(self, document: dict[str, Any]) -> None:
        tools = observed_tools(document)
        tools[0] = ObservedTool(
            name=tools[0].name,
            description=tools[0].description,
            input_schema={"type": "object", "additionalProperties": True},
            output_schema=tools[0].output_schema,
            annotations=tools[0].annotations,
        )
        assessment = self._assess(document, ObservedSurface(tools=tuple(tools), complete=True))
        assert not assessment.ready
        assert DriftReason.SCHEMA_DIGEST_MISMATCH in {f.reason for f in assessment.findings}

    def test_an_output_schema_appearing(self, document: dict[str, Any]) -> None:
        tools = observed_tools(document)
        tools[1] = ObservedTool(
            name=tools[1].name,
            description=tools[1].description,
            input_schema=tools[1].input_schema,
            output_schema={"type": "object"},
            annotations=tools[1].annotations,
        )
        assessment = self._assess(document, ObservedSurface(tools=tuple(tools), complete=True))
        assert not assessment.ready
        assert DriftReason.SCHEMA_DIGEST_MISMATCH in {f.reason for f in assessment.findings}

    def test_an_annotation_change(self, document: dict[str, Any]) -> None:
        """A flipped `readOnlyHint` is drift even though it is never authority."""
        tools = observed_tools(document)
        tools[0] = ObservedTool(
            name=tools[0].name,
            description=tools[0].description,
            input_schema=tools[0].input_schema,
            output_schema=tools[0].output_schema,
            annotations={"readOnlyHint": False, "title": "Synthetic Alpha"},
        )
        assessment = self._assess(document, ObservedSurface(tools=tuple(tools), complete=True))
        assert not assessment.ready
        assert DriftReason.METADATA_DIGEST_MISMATCH in {f.reason for f in assessment.findings}

    def test_a_description_change(self, document: dict[str, Any]) -> None:
        tools = observed_tools(document)
        tools[0] = ObservedTool(
            name=tools[0].name,
            description="Rewritten by the provider.",
            input_schema=tools[0].input_schema,
            output_schema=tools[0].output_schema,
            annotations=tools[0].annotations,
        )
        assessment = self._assess(document, ObservedSurface(tools=tuple(tools), complete=True))
        assert not assessment.ready
        assert DriftReason.METADATA_DIGEST_MISMATCH in {f.reason for f in assessment.findings}

    def test_a_surface_cannot_claim_completeness_by_omission(self) -> None:
        """`complete` has no default, so a transport must state it (§6.2)."""
        with pytest.raises(TypeError):
            ObservedSurface(tools=())  # type: ignore[call-arg]

    def test_an_incompletely_enumerated_surface(self, document: dict[str, Any]) -> None:
        """§6.2's pagination conditions arrive here as `complete=False`."""
        surface = ObservedSurface(tools=tuple(observed_tools(document)), complete=False)
        assessment = self._assess(document, surface)
        assert not assessment.ready
        assert [f.reason for f in assessment.findings] == [DriftReason.INCOMPLETE_DISCOVERY]

    @pytest.mark.parametrize(
        "code",
        [
            ErrorCode.TIMEOUT,
            ErrorCode.PROTOCOL_ERROR,
            ErrorCode.AUTH_REQUIRED,
            ErrorCode.RESPONSE_TOO_LARGE,
        ],
    )
    def test_a_discovery_failure(self, manifest: ReviewedManifest, code: ErrorCode) -> None:
        """An unknown surface is indistinguishable from a drifted one."""
        discovery = SpyDiscovery(error=GatewayError(code, "safe message"))
        assessment = run(establish_readiness(config_for(BASE_DIGEST), manifest, discovery))
        assert not assessment.ready
        assert [f.reason for f in assessment.findings] == [DriftReason.DISCOVERY_FAILED]
        # Structured, not prose: step 5 maps `auth_required` onto exit 4 and
        # must not have to parse an English sentence to do it.
        assert assessment.findings[0].error_code is code
        assert assessment.findings[0].to_json_dict()["error_code"] == str(code)

    def test_every_finding_carries_the_error_code_key(self, document: dict[str, Any]) -> None:
        """A stable shape: step 5 branches on a value, never on key existence."""
        tools = observed_tools(document)[:-1]
        findings = assess_surface(
            load_manifest_text(dumps(document)),
            ObservedSurface(tools=tuple(tools), complete=True),
        )
        assert findings
        for finding in findings:
            assert "error_code" in finding.to_json_dict()
            assert finding.to_json_dict()["error_code"] is None

    def test_a_discovery_failure_does_not_leak_the_upstream_message(
        self, manifest: ReviewedManifest
    ) -> None:
        """§7.3: provider-derived text has been seen carrying an account id."""
        secret = "account 7f3a-SUPERSECRET-9911 is not entitled"
        discovery = SpyDiscovery(error=GatewayError(ErrorCode.PROVIDER_ERROR, secret))
        assessment = run(establish_readiness(config_for(BASE_DIGEST), manifest, discovery))
        rendered = json.dumps([f.to_json_dict() for f in assessment.findings])
        assert "SUPERSECRET" not in rendered
        assert secret not in rendered
        assert assessment.findings[0].error_code is ErrorCode.PROVIDER_ERROR

    def test_a_malformed_provider_tool_makes_readiness_false(
        self, manifest: ReviewedManifest
    ) -> None:
        """A malformed tool raises at construction; readiness must absorb it."""
        with pytest.raises(GatewayError) as excinfo:
            bare_tool("has space")
        assert excinfo.value.code is ErrorCode.PROTOCOL_ERROR
        discovery = SpyDiscovery(error=excinfo.value)
        assessment = run(establish_readiness(config_for(BASE_DIGEST), manifest, discovery))
        assert not assessment.ready

    def test_the_surface_digest_check_catches_drift_on_its_own(
        self, document: dict[str, Any]
    ) -> None:
        tools = observed_tools(document)
        tools[0] = ObservedTool(
            name=tools[0].name,
            description="changed",
            input_schema=tools[0].input_schema,
            output_schema=tools[0].output_schema,
            annotations=tools[0].annotations,
        )
        findings = assess_surface(
            load_manifest_text(dumps(document)), ObservedSurface(tools=tuple(tools), complete=True)
        )
        assert DriftReason.PROVIDER_SURFACE_DIGEST_MISMATCH in {f.reason for f in findings}

    def test_provider_tool_reordering_alone_is_not_drift(self, document: dict[str, Any]) -> None:
        """A re-ordered `tools/list` response is not a security-relevant change."""
        surface = ObservedSurface(tools=tuple(reversed(observed_tools(document))), complete=True)
        assert self._assess(document, surface).ready

    def test_all_findings_are_collected_not_just_the_first(self, document: dict[str, Any]) -> None:
        tools = observed_tools(document)[:-1]
        tools.append(bare_tool("synthetic_unreviewed_tool"))
        assessment = self._assess(document, ObservedSurface(tools=tuple(tools), complete=True))
        reasons = {f.reason for f in assessment.findings}
        assert DriftReason.UNKNOWN_PROVIDER_TOOL in reasons
        assert DriftReason.MISSING_PROVIDER_TOOL in reasons


class TestFindingsAreSafeToLog:
    def test_an_unreviewed_tool_name_is_not_disclosed(self, document: dict[str, Any]) -> None:
        """§8 keeps `tools/list` response data out of logs."""
        surface = ObservedSurface(
            tools=(*observed_tools(document), bare_tool("synthetic_secret_tool")),
            complete=True,
        )
        manifest = load_manifest_text(dumps(document))
        findings = assess_surface(manifest, surface)
        rendered = json.dumps([f.to_json_dict() for f in findings])
        assert "synthetic_secret_tool" not in rendered
        assert "<unreviewed:" in rendered

    def test_a_reviewed_tool_name_is_reported(self, document: dict[str, Any]) -> None:
        surface = ObservedSurface(tools=tuple(observed_tools(document)[:-1]), complete=True)
        findings = assess_surface(load_manifest_text(dumps(document)), surface)
        rendered = json.dumps([f.to_json_dict() for f in findings])
        assert "synthetic_gamma_mutate" in rendered

    def test_findings_never_carry_schema_or_description_content(
        self, document: dict[str, Any]
    ) -> None:
        tools = observed_tools(document)
        tools[0] = ObservedTool(
            name=tools[0].name,
            description="a description that must not be logged",
            input_schema={"type": "object", "properties": {"leaked_property": {}}},
            output_schema=tools[0].output_schema,
            annotations=tools[0].annotations,
        )
        findings = assess_surface(
            load_manifest_text(dumps(document)), ObservedSurface(tools=tuple(tools), complete=True)
        )
        rendered = json.dumps([f.to_json_dict() for f in findings])
        assert "must not be logged" not in rendered
        assert "leaked_property" not in rendered


class TestReadinessAssessmentInvariants:
    def test_a_ready_assessment_cannot_carry_findings(self, manifest: ReviewedManifest) -> None:
        from rh_mcp.manifest import DriftFinding
        from rh_mcp.models import Readiness

        ready = Readiness(True, manifest.manifest_version, BASE_DIGEST, BASE_DIGEST)
        with pytest.raises(GatewayError, match="cannot carry drift findings"):
            ReadinessAssessment(
                readiness=ready,
                findings=(DriftFinding(DriftReason.INCOMPLETE_DISCOVERY, "why"),),
            )

    def test_a_not_ready_assessment_must_say_why(self, manifest: ReviewedManifest) -> None:
        from rh_mcp.models import Readiness

        not_ready = Readiness(False, manifest.manifest_version, BASE_DIGEST, OTHER_DIGEST)
        with pytest.raises(GatewayError, match="must say why"):
            ReadinessAssessment(readiness=not_ready)


# --------------------------------------------------------------------------
# Per-call preflight (§6.2)
# --------------------------------------------------------------------------


@pytest.fixture
def ready(document: dict[str, Any], manifest: ReviewedManifest) -> ReadinessAssessment:
    return run(
        establish_readiness(
            config_for(BASE_DIGEST), manifest, SpyDiscovery(matching_surface(document))
        )
    )


class TestPreflight:
    def test_resolves_a_reviewed_read_capability(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment
    ) -> None:
        entry = preflight_read(manifest, ready, "alpha_reading", VALID_ARGS).entry
        assert entry.provider_tool_name == "synthetic_alpha_read"
        assert entry.read_allowed
        assert entry.input_schema["required"] == ("synthetic_symbol",)

    def test_denies_a_denied_capability(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment
    ) -> None:
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, ready, "gamma_reading", VALID_ARGS)
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED

    def test_denies_an_unknown_capability(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment
    ) -> None:
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, ready, "not_a_capability", VALID_ARGS)
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED

    def test_denied_and_unknown_are_indistinguishable(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment
    ) -> None:
        """The error must not disclose whether a name exists in the manifest."""
        messages = []
        for capability in ("gamma_reading", "not_a_capability"):
            with pytest.raises(GatewayError) as excinfo:
                preflight_read(manifest, ready, capability, VALID_ARGS)
            messages.append(excinfo.value.message)
        assert messages[0] == messages[1]

    @pytest.mark.parametrize("capability", [None, 7, ["alpha_reading"], b"alpha_reading"])
    def test_denies_a_non_string_capability(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment, capability: Any
    ) -> None:
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, ready, capability, VALID_ARGS)
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED

    def test_denies_a_provider_tool_name_used_as_a_capability(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment
    ) -> None:
        """§6.2: callers cannot supply an arbitrary provider tool name."""
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, ready, "synthetic_alpha_read", VALID_ARGS)
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED

    def test_refuses_when_the_gateway_is_not_ready(
        self, document: dict[str, Any], manifest: ReviewedManifest
    ) -> None:
        not_ready = run(
            establish_readiness(
                config_for(OTHER_DIGEST), manifest, SpyDiscovery(matching_surface(document))
            )
        )
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, not_ready, "alpha_reading", VALID_ARGS)
        assert excinfo.value.code is ErrorCode.NOT_READY

    def test_refuses_an_assessment_for_a_different_manifest(
        self, ready: ReadinessAssessment
    ) -> None:
        """A readiness result from one manifest cannot authorise another."""
        other = load_manifest_text(dumps(_added_entry()))
        with pytest.raises(GatewayError, match="different manifest") as excinfo:
            preflight_read(other, ready, "alpha_reading", VALID_ARGS)
        assert excinfo.value.code is ErrorCode.NOT_READY

    @pytest.mark.parametrize("field", ["schema_digest", "metadata_digest"])
    def test_reverifies_each_pinned_digest(self, ready: ReadinessAssessment, field: str) -> None:
        """Defence in depth: the load-time check is not the only one.

        Each digest is tampered with on its own, so this fails if *either*
        re-verification is removed — tampering both at once would let one
        guard cover for the other's absence.
        """
        loaded = load_manifest_text(dumps(build_manifest()))
        consistent = ManifestEntry(
            capability="alpha_reading",
            provider_tool_name="synthetic_alpha_read",
            description="x",
            input_schema={},
            output_schema=None,
            annotations={},
            schema_digest=tool_schema_digest("synthetic_alpha_read", {}, None),
            metadata_digest=tool_metadata_digest("x", {}),
            disposition="allowed",
            mutates=False,
            rationale="x",
        )
        tampered = replace(consistent, **{field: OTHER_DIGEST})
        object.__setattr__(loaded, "entries", (tampered,))
        with pytest.raises(GatewayError, match="no longer matches") as excinfo:
            preflight_read(loaded, ready, "alpha_reading", VALID_ARGS)
        assert excinfo.value.code is ErrorCode.NOT_READY

    @pytest.mark.parametrize(
        "arguments",
        [
            {},
            {"synthetic_symbol": 7},
            {"synthetic_symbol": "TOOOOLONG"},
            {"synthetic_symbol": "AAPL", "injected": True},
        ],
        ids=["missing-required", "wrong-type", "too-long", "additional-property"],
    )
    def test_refuses_arguments_that_violate_the_pinned_schema(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment, arguments: dict[str, Any]
    ) -> None:
        """§6.2 validates input against the pinned schema *before* the call."""
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, ready, "alpha_reading", arguments)
        assert excinfo.value.code is ErrorCode.INPUT_INVALID

    def test_refuses_non_mapping_arguments(
        self, manifest: ReviewedManifest, ready: ReadinessAssessment
    ) -> None:
        with pytest.raises(GatewayError) as excinfo:
            preflight_read(manifest, ready, "alpha_reading", ["not", "a", "mapping"])  # type: ignore[arg-type]
        assert excinfo.value.code is ErrorCode.INPUT_INVALID

    def test_argument_validation_is_not_a_separate_call(self) -> None:
        """ "Resolved an entry" and "validated the input" are one event.

        A caller cannot obtain a pinned entry without having had its arguments
        checked, so a returned entry can never read as permission to send
        whatever the caller likes.
        """
        import inspect

        parameters = inspect.signature(preflight_read).parameters
        assert "arguments" in parameters
        assert parameters["arguments"].default is inspect.Parameter.empty


class TestDeniedEntriesDoNotBlockLoading:
    """An unenforceable schema on a *denied* tool must not brick the manifest.

    A denied entry's schema is never validated against and never sent. Refusing
    the whole manifest because an unreviewed tool advertises `$ref` would make
    one keyword anywhere in the provider surface permanently un-loadable — the
    likely outcome of the first real `admin discover`.
    """

    def test_a_denied_entry_may_carry_an_unsupported_keyword(self) -> None:
        entries = default_entries()
        denied = next(e for e in entries if e["disposition"] == "denied")
        index = entries.index(denied)
        entries[index] = build_entry(
            provider_tool_name=denied["provider_tool_name"],
            capability=denied["capability"],
            description=denied["description"],
            input_schema={"type": "object", "properties": {}, "$ref": "#/definitions/x"},
            disposition="denied",
            rationale=denied["rationale"],
        )
        manifest = load_manifest_text(dumps(reseal(build_manifest(entries))))
        assert manifest.read_capabilities

    def test_an_allowed_entry_still_may_not(self) -> None:
        entries = default_entries()
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description=entries[0]["description"],
            input_schema={"type": "object", "properties": {}, "$ref": "#/definitions/x"},
            rationale=entries[0]["rationale"],
        )
        expect_local_failure(reseal(build_manifest(entries)), "does not implement")
