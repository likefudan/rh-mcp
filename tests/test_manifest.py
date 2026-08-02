"""Manifest format, drift control, and fail-closed readiness (§6, §6.2, §11).

Offline and synthetic throughout. The `SpyDiscovery` below is the only route
to a "provider", which is what makes "no read reaches a transport" a property
these tests can assert rather than assume.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from collections.abc import Coroutine
from dataclasses import replace
from pathlib import Path
from typing import Any

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
BASE_DIGEST = "sha256:463295e635f21ed81c3792da15f3474c6096d8821cd815d9cbddc6867dc8b705"
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
                f.default is not dataclasses.MISSING
                or f.default_factory is not dataclasses.MISSING
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

    def test_the_active_digest_is_recomputed_not_trusted(
        self, document: dict[str, Any]
    ) -> None:
        """§7.1: the active digest is never a value trusted from the file."""
        assert load_manifest_text(dumps(document)).digest == compute_full_manifest_digest(
            document
        )

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

    def test_top_level_key_order_does_not_change_the_digest(
        self, document: dict[str, Any]
    ) -> None:
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
    entries[1]["disposition"] = "read_allowed"
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
    def test_rejects_a_missing_top_level_field(
        self, document: dict[str, Any], field: str
    ) -> None:
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
        expect_local_failure(
            build_manifest(observed_at="2026-01-15T00:00:00+02:00"), "observed_at"
        )

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
        expect_local_failure(
            reseal(build_manifest(entries, sort_entries=False)), "canonical order"
        )

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

    @pytest.mark.parametrize(
        "name", ["", "has space", "a" * 129, "tab\tname", "ünïcode", 7, None]
    )
    def test_rejects_a_malformed_provider_tool_name(self, name: Any) -> None:
        entries = default_entries()
        entries[0]["provider_tool_name"] = name
        expect_local_failure(
            reseal(build_manifest(entries, sort_entries=False)), "printable ASCII"
        )

    @pytest.mark.parametrize("disposition", ["allowed", "READ_ALLOWED", "", None, True])
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
        text = dumps(document).replace('"manifest_version": "2026.01.16"',
                                       f'"manifest_version": {literal}', 1)
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
            description="[" * 100 + '\\" {{{' ,
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

    def test_no_reviewed_manifest_ships_with_this_release(self) -> None:
        """§13: a production manifest requires owner-assisted discovery first."""
        assert not PACKAGED_MANIFEST_PATH.exists()
        expect_source_failure(load_active_manifest, "ships no reviewed read manifest")


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
    def test_a_malformed_pin_is_a_configuration_error_at_construction(
        self, digest: str
    ) -> None:
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

    def _assess(
        self, document: dict[str, Any], surface: ObservedSurface
    ) -> ReadinessAssessment:
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

    def test_every_finding_carries_the_error_code_key(
        self, document: dict[str, Any]
    ) -> None:
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

    def test_provider_tool_reordering_alone_is_not_drift(
        self, document: dict[str, Any]
    ) -> None:
        """A re-ordered `tools/list` response is not a security-relevant change."""
        surface = ObservedSurface(
            tools=tuple(reversed(observed_tools(document))), complete=True
        )
        assert self._assess(document, surface).ready

    def test_all_findings_are_collected_not_just_the_first(
        self, document: dict[str, Any]
    ) -> None:
        tools = observed_tools(document)[:-1]
        tools.append(bare_tool("synthetic_unreviewed_tool"))
        assessment = self._assess(document, ObservedSurface(tools=tuple(tools), complete=True))
        reasons = {f.reason for f in assessment.findings}
        assert DriftReason.UNKNOWN_PROVIDER_TOOL in reasons
        assert DriftReason.MISSING_PROVIDER_TOOL in reasons


class TestFindingsAreSafeToLog:
    def test_an_unreviewed_tool_name_is_not_disclosed(
        self, document: dict[str, Any]
    ) -> None:
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
        entry = preflight_read(manifest, ready, "alpha_reading", VALID_ARGS)
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
    def test_reverifies_each_pinned_digest(
        self, ready: ReadinessAssessment, field: str
    ) -> None:
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
            disposition="read_allowed",
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
        """"Resolved an entry" and "validated the input" are one event.

        A caller cannot obtain a pinned entry without having had its arguments
        checked, so a returned entry can never read as permission to send
        whatever the caller likes.
        """
        import inspect

        parameters = inspect.signature(preflight_read).parameters
        assert "arguments" in parameters
        assert parameters["arguments"].default is inspect.Parameter.empty
