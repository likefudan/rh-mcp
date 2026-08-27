"""The runtime dependency caps, asserted rather than commented (§4, §12).

`pyproject.toml` pins `mcp` and `httpx2` below their next major version, and
`.github/dependabot.yml` refuses to propose a major bump. Neither of those is
a check: one is a declaration and the other is a robot's instructions, and both
are edited by the same PR that would widen them.

§4's boundary is why the cap matters. A consumer holding its own MCP SDK must
not inherit a conflict from this package, and a v3 SDK could change the wire
contract the fail-closed checks in `transport.py` are written against. Widening
either bound is a security-boundary change under §12 — this test is what makes
that a deliberate act rather than a diff nobody read.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# Both are private implementation dependencies (§4). Neither appears in any
# public signature, exception, serialized result, or annotation.
CAPPED = {"httpx2": "3.0.0", "mcp": "3.0.0"}


def runtime_requirements() -> dict[str, str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for spec in data["project"]["dependencies"]:
        name = spec.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()
        out[name] = spec
    return out


def project_version() -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_the_current_source_identity_is_published_without_claiming_a_release() -> None:
    """Source pins are current even in the interval before a tag workflow finishes."""
    version = project_version()
    assert tuple(int(part) for part in version.split(".")) >= (0, 3, 0)

    root = PYPROJECT.parent
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{version}]" in changelog
    assert f"[{version}]: https://github.com/likefudan/rh-mcp/compare/" in changelog
    # `[Unreleased]` compares from the newest tag that exists, which is not
    # `v{version}` unless this version has been released. Pinning the latter
    # is what let `v0.3.1...HEAD` and `v0.3.2...HEAD` ship, both 404s against
    # tags that were never cut.
    unreleased = re.search(
        r"(?m)^\[Unreleased\]: https://github\.com/likefudan/rh-mcp/compare/(\S+)\.\.\.HEAD$",
        changelog,
    )
    assert unreleased is not None, "no [Unreleased] comparison link"
    base = unreleased.group(1)
    tags = subprocess.run(
        ["git", "-C", str(root), "tag", "--list"],
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    ).stdout.split()
    # Not skipped quietly. `ci.yml` gives the test job `fetch-depth: 0` for
    # exactly this assertion; without tags it would pass vacuously in the one
    # place it is meant to run, which is how `v0.3.1...HEAD` and
    # `v0.3.2...HEAD` shipped against tags that were never cut. A checkout
    # with no tags is a misconfigured run, not a reason to assert nothing.
    if not tags:
        pytest.skip("no tags in this checkout; CI sets fetch-depth: 0 so this runs there")
    assert base in tags, f"[Unreleased] compares from {base}, which is not a tag"

    readme = (root / "README.md").read_text(encoding="utf-8")
    current = readme.split("<!-- manifest-automation:current-start -->", 1)[1].split(
        "<!-- manifest-automation:current-end -->", 1
    )[0]
    assert f"source declares package version `v{version}`" in " ".join(current.split())
    assert "released `v" not in current


def test_the_runtime_dependency_set_is_exactly_the_two_reviewed_ones() -> None:
    """A third runtime dependency is a decision, not a dependency update.

    Every line of a runtime dependency runs inside the broker process holding a
    write-capable credential, so adding one is reviewed on that basis.
    """
    assert set(runtime_requirements()) == set(CAPPED)


@pytest.mark.parametrize("name", sorted(CAPPED))
def test_each_runtime_dependency_is_capped_below_the_next_major(name: str) -> None:
    spec = runtime_requirements()[name]
    assert f"<{CAPPED[name]}" in spec, (
        f"{name} must stay capped below {CAPPED[name]}. Widening it is a §12 "
        "security-boundary change and needs the release gate, not a dependency PR."
    )


# The provenance action is the one GitHub Action whose major belongs with the
# runtime dependencies rather than with the other actions: it produces the
# signed attestation that is a consumer's only independent evidence of an
# artifact's origin, and it appears only in `release.yml`, which no
# pull-request CI run executes.
ATTESTATION_ACTION = "actions/attest-build-provenance"


def test_the_provenance_action_is_used_only_where_ci_cannot_exercise_it() -> None:
    """The premise behind pinning its major, asserted rather than assumed.

    If it ever appears in `ci.yml`, a bump to it would be genuinely exercised
    by pull-request CI and the reason for the pin weakens. This fails if that
    changes, so the pin is revisited rather than cargo-culted.
    """
    workflows = PYPROJECT.parent / ".github" / "workflows"
    ci = (workflows / "ci.yml").read_text(encoding="utf-8")
    release = (workflows / "release.yml").read_text(encoding="utf-8")
    assert ATTESTATION_ACTION in release, "release.yml must attest the artifacts it builds"
    assert ATTESTATION_ACTION not in ci, (
        "the provenance action now runs in pull-request CI; revisit the major-version "
        "pin in dependabot.yml, whose stated reason is that CI cannot exercise it"
    )


def test_dependabot_refuses_a_major_bump_of_the_provenance_action() -> None:
    config = (PYPROJECT.parent / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    block = config.split(f"dependency-name: {ATTESTATION_ACTION}")
    assert len(block) == 2, f"dependabot.yml does not ignore major bumps for {ATTESTATION_ACTION}"
    assert "semver-major" in block[1].split("- dependency-name")[0].split("- package-ecosystem")[0]


def test_dependabot_refuses_to_propose_a_major_bump() -> None:
    """The robot's instructions and the cap have to agree.

    If they drift, the failure is quiet in the worst way: a major-bump PR that
    cannot merge, arriving in a frame that invites a reviewer to treat it as
    routine.
    """
    config = (PYPROJECT.parent / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    for name in CAPPED:
        block = config.split(f"dependency-name: {name}")
        assert len(block) == 2, f"dependabot.yml does not ignore major bumps for {name}"
        assert "semver-major" in block[1].split("- dependency-name")[0]


# ---------------------------------------------------------------------------
# The reviewer-suite deselection (DESIGN §12.4)
# ---------------------------------------------------------------------------

DESELECTED = "test_exact_8_trading_denied_and_11_mutations_allowed"
WORKFLOWS = PYPROJECT.parent / ".github" / "workflows"


@pytest.mark.parametrize("workflow", ["ci.yml", "release.yml"])
def test_exactly_one_reviewer_test_is_deselected(workflow: str) -> None:
    """A deselection is a hole in an auditor's suite, so it is counted.

    The one that exists is justified in §12.4: the test pins the manifest
    version and digest on its first line, so any refresh stops it before the
    assertions its name is about. Widening this is how a suite quietly stops
    guarding what it was written to guard, which is the failure mode that let
    the v0.1.0 findings survive four internal rounds.
    """
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    assert text.count("--deselect") == 1, (
        f"{workflow} deselects more than one reviewer test; each hole in an "
        "auditor's suite needs its own entry in DESIGN §12.4"
    )
    assert DESELECTED in text
    assert "-k " not in text.split("suites=")[1].split("uv run pytest")[1][:400], (
        "the reviewer suites must not be filtered with -k; deselect by full "
        "node id so what is skipped is named rather than matched"
    )


def test_the_deselected_property_is_guarded_elsewhere() -> None:
    """Deselecting is only acceptable because our own suite holds the property."""
    ours = (PYPROJECT.parent / "tests" / "test_manifest.py").read_text(encoding="utf-8")
    assert "class TestTheShippedManifest" in ours
    for guard in (
        "test_no_trading_capability_is_allowed",
        "test_every_allowed_mutation_is_flagged",
        "test_the_allowed_set_is_the_size_the_reviewer_approved",
    ):
        assert guard in ours, (
            f"{guard} is what makes deselecting the reviewer's test defensible; "
            "removing it means the property is guarded nowhere"
        )
