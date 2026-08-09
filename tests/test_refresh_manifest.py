"""The refresh tool's refusals (DESIGN.md §6, §6.1, §9).

This script is the only thing permitted to rewrite the committed manifest, so
what it *declines* to do is the whole of its security value. Most of these
tests assert a refusal; the two that assert success exist to prove the
refusals are not vacuous.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from refresh_manifest import (  # noqa: E402
    RefusedError,
    _next_version,
    refresh,
)

from rh_mcp.manifest import FULL_MANIFEST_DIGEST_FIELD, load_manifest_text  # noqa: E402
from tests.support import build_manifest, dumps  # noqa: E402


def candidate_from(document: dict[str, Any]) -> dict[str, Any]:
    """The `admin discover` document a provider matching `document` would give."""
    return {
        "candidate": True,
        "observed_at": "2026-08-04T00:00:00+00:00",
        "tools": [
            {
                "provider_tool_name": e["provider_tool_name"],
                "description": e["description"],
                "input_schema": e["input_schema"],
                "output_schema": e["output_schema"],
                "annotations": e["annotations"],
                "capability": None,
                "disposition": "denied",
                "mutates": None,
                "rationale": "UNREVIEWED",
            }
            for e in document["entries"]
        ],
    }


@pytest.fixture
def manifest_path(tmp_path: Path) -> Path:
    path = tmp_path / "read-manifest.json"
    path.write_text(dumps(build_manifest()), encoding="utf-8")
    return path


@pytest.fixture
def candidate_path(tmp_path: Path) -> Path:
    return tmp_path / "candidate.json"


def write(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def drifted(document: dict[str, Any], tool: str = "synthetic_alpha_read") -> dict[str, Any]:
    """A candidate whose schema for one tool has changed, as a provider's would."""
    candidate = candidate_from(document)
    for entry in candidate["tools"]:
        if entry["provider_tool_name"] == tool:
            entry["output_schema"] = {
                "type": "object",
                "properties": {"synthetic_value": {"type": "number"}, "added": {"type": "string"}},
                "additionalProperties": False,
            }
    return candidate


class TestItRefuses:
    def test_a_tool_that_appeared(self, manifest_path: Path, candidate_path: Path) -> None:
        """A new tool has no prior disposition, and nothing here may invent one."""
        document = build_manifest()
        candidate = drifted(document)
        candidate["tools"].append(
            {
                "provider_tool_name": "synthetic_new_tool",
                "description": "",
                "input_schema": {"type": "object", "properties": {}},
                "output_schema": None,
                "annotations": {},
                "capability": None,
                "disposition": "denied",
                "mutates": None,
                "rationale": "UNREVIEWED",
            }
        )
        with pytest.raises(RefusedError, match="review and not a refresh"):
            refresh(write(candidate_path, candidate), manifest_path)

    def test_a_tool_that_disappeared(self, manifest_path: Path, candidate_path: Path) -> None:
        candidate = drifted(build_manifest())
        candidate["tools"].pop()
        with pytest.raises(RefusedError, match="disappeared"):
            refresh(write(candidate_path, candidate), manifest_path)

    def test_a_surface_identical_to_the_manifest(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        """A no-op refresh must not mint a digest.

        `reviewed_at` moves every run, so writing unconditionally would produce
        a new digest when nothing changed — destroying the one signal the value
        carries, and training whoever runs this to update pins reflexively.
        """
        candidate = candidate_from(build_manifest())
        with pytest.raises(RefusedError, match="identical to the committed manifest"):
            refresh(write(candidate_path, candidate), manifest_path)

    def test_a_document_that_is_not_a_candidate(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        """A manifest passed by mistake must not be treated as an observation."""
        with pytest.raises(RefusedError, match="not an `admin discover` candidate"):
            refresh(write(candidate_path, build_manifest()), manifest_path)

    def test_a_candidate_with_no_tools(self, manifest_path: Path, candidate_path: Path) -> None:
        with pytest.raises(RefusedError, match="no observed tools"):
            refresh(
                write(candidate_path, {"candidate": True, "observed_at": "x", "tools": []}),
                manifest_path,
            )

    def test_a_manifest_that_does_not_load(self, tmp_path: Path, candidate_path: Path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text('{"manifest_format_version": "9.9"}', encoding="utf-8")
        with pytest.raises(RefusedError, match="does not load"):
            refresh(
                write(candidate_path, candidate_from(build_manifest())), broken
            )

    def test_it_offers_no_flag_to_change_a_disposition(self) -> None:
        """The absent escape hatch, asserted so it stays absent.

        A permission change is a review. A flag here would be the one place in
        this project where one could happen without a human writing a rationale.
        """
        source = (Path(__file__).resolve().parent.parent / "scripts" / "refresh_manifest.py")
        text = source.read_text(encoding="utf-8")
        body = text.split('"""', 2)[2]  # skip the module docstring, which discusses it
        for forbidden in ("--allow-disposition", "--force", "--grant", "--allow-new-tool"):
            assert forbidden not in body


class TestItCarriesDecisionsForward:
    def test_every_reviewer_decision_survives_verbatim(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        document = build_manifest()
        before = {e["provider_tool_name"]: e for e in document["entries"]}
        refreshed = refresh(
            write(candidate_path, drifted(document)), manifest_path
        )
        assert refreshed["entries"]
        for entry in refreshed["entries"]:
            kept = before[entry["provider_tool_name"]]
            for field in ("capability", "disposition", "mutates", "rationale"):
                assert entry[field] == kept[field]

    def test_only_the_drifted_tool_moves(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        document = build_manifest()
        before = {e["provider_tool_name"]: e for e in document["entries"]}
        refreshed = refresh(
            write(candidate_path, drifted(document)), manifest_path
        )
        moved = [
            e["provider_tool_name"]
            for e in refreshed["entries"]
            if e["schema_digest"] != before[e["provider_tool_name"]]["schema_digest"]
        ]
        assert moved == ["synthetic_alpha_read"]

    def test_the_result_loads_and_is_self_consistent(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        refreshed = refresh(
            write(candidate_path, drifted(build_manifest())), manifest_path
        )
        loaded = load_manifest_text(json.dumps(refreshed))
        assert loaded.digest == refreshed[FULL_MANIFEST_DIGEST_FIELD]

    def test_the_digest_moves(self, manifest_path: Path, candidate_path: Path) -> None:
        """Drift the consumer must accept has to be visible as a new pin."""
        document = build_manifest()
        refreshed = refresh(
            write(candidate_path, drifted(document)), manifest_path
        )
        assert refreshed[FULL_MANIFEST_DIGEST_FIELD] != document[FULL_MANIFEST_DIGEST_FIELD]

    def test_a_denied_tool_stays_denied_even_when_its_schema_changes(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        """The case that matters: drift must never launder a denial into an allowance."""
        document = build_manifest()
        denied = next(e for e in document["entries"] if e["disposition"] == "denied")
        refreshed = refresh(
            write(candidate_path, drifted(document, denied["provider_tool_name"])),
            manifest_path,
        )
        entry = next(
            e
            for e in refreshed["entries"]
            if e["provider_tool_name"] == denied["provider_tool_name"]
        )
        assert entry["disposition"] == "denied"
        assert entry["capability"] == denied["capability"]


class TestTheReportIsTrue:
    """A dry run must print the digest the real run writes.

    It did not. `reviewed_at` was stamped with `now()` on every invocation, so
    two consecutive dry runs reported two different digests and neither matched
    the file that was then written. The whole point of the dry run is to show
    the value you are about to accept and pin, so a report that cannot be
    trusted is worse than no report.

    The fix was not to freeze a clock: it was to stop restamping. A refresh
    carries the reviewer's decisions forward verbatim, so nobody reviewed
    anything, and writing a fresh `reviewed_at` claimed a review that did not
    happen. Carrying the reviewer block forward makes the tool honest and
    deterministic at once.
    """

    def test_two_refreshes_of_the_same_input_agree(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        candidate = write(candidate_path, drifted(build_manifest()))
        first = refresh(candidate, manifest_path)
        second = refresh(candidate, manifest_path)
        assert first[FULL_MANIFEST_DIGEST_FIELD] == second[FULL_MANIFEST_DIGEST_FIELD]
        assert first == second

    def test_the_reviewer_block_is_carried_forward_not_restamped(
        self, manifest_path: Path, candidate_path: Path
    ) -> None:
        before = load_manifest_text(manifest_path.read_text(encoding="utf-8"))
        refreshed = refresh(
            write(candidate_path, drifted(build_manifest())), manifest_path
        )
        assert refreshed["reviewer"] == dict(before.reviewer), (
            "a refresh reviews nothing, so it must not claim a new review date"
        )


class TestVersioning:
    @pytest.mark.parametrize(
        ("previous", "observed_at", "expected"),
        [
            ("2026.08.03", "2026-08-04T00:00:00+00:00", "2026.08.04"),
            ("2026.08.03", "2026-08-03T12:00:00+00:00", "2026.08.03.1"),
            ("2026.08.03.1", "2026-08-03T12:00:00+00:00", "2026.08.03.2"),
            ("2026.08.03.9", "2026-08-03T12:00:00+00:00", "2026.08.03.10"),
        ],
    )
    def test_next_version(self, previous: str, observed_at: str, expected: str) -> None:
        assert _next_version(previous, observed_at) == expected


def test_the_shipped_manifest_is_refreshable(tmp_path: Path) -> None:
    """The tool runs against the real manifest, not only fixtures.

    A refusal here would mean the committed manifest and the tool that
    maintains it have diverged — which is exactly the state that would be
    discovered at the worst moment otherwise.
    """
    from rh_mcp.manifest import PACKAGED_MANIFEST_PATH, load_active_manifest
    from rh_mcp.validation import json_safe

    real = load_active_manifest()
    candidate = {
        "candidate": True,
        "observed_at": "2026-08-04T00:00:00+00:00",
        "tools": [
            {
                "provider_tool_name": e.provider_tool_name,
                "description": e.description + (" x" if e.capability == "get_accounts" else ""),
                "input_schema": json_safe(e.input_schema),
                "output_schema": None if e.output_schema is None else json_safe(e.output_schema),
                "annotations": json_safe(e.annotations),
            }
            for e in real.entries
        ],
    }
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(candidate), encoding="utf-8")
    refreshed = refresh(path, PACKAGED_MANIFEST_PATH)
    assert len(refreshed["entries"]) == len(real.entries)

    # Against the real manifest's own dispositions, not a literal. The literal
    # was `== 8`, which passed for the reason this test is named after and also
    # for a reason it is not: it would have gone green on a manifest whose
    # denials had been swapped for eight different tools. Comparing the whole
    # mapping says what the refresh actually promises — every disposition
    # carried forward verbatim — and does not need editing when a review adds
    # an entry, which is when a stale literal would fail for the wrong reason.
    assert {e["provider_tool_name"]: e["disposition"] for e in refreshed["entries"]} == {
        e.provider_tool_name: e.disposition for e in real.entries
    }
