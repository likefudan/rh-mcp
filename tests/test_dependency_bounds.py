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
