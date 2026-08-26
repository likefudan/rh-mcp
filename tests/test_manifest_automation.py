"""Automation stays narrower than the credential and manifest boundaries."""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import manifest_automation as automation  # noqa: E402
from manifest_automation import (  # noqa: E402
    AutomationError,
    _run_discovery,
    classify_candidate,
    prepare_refresh,
    require_stable_candidates,
    seal_candidate,
    stable_candidate_bytes,
)
from release_notes import render  # noqa: E402

from rh_mcp.manifest import load_active_manifest, load_manifest_file  # noqa: E402
from rh_mcp.validation import json_safe  # noqa: E402


def candidate_from_active() -> dict[str, Any]:
    manifest = load_active_manifest()
    return {
        "candidate": True,
        "observed_at": "2026-08-13T08:00:00+00:00",
        "tools": [
            {
                "provider_tool_name": entry.provider_tool_name,
                "description": entry.description,
                "input_schema": json_safe(entry.input_schema),
                "output_schema": json_safe(entry.output_schema),
                "annotations": json_safe(entry.annotations),
                "capability": None,
                "disposition": "denied",
                "mutates": None,
                "rationale": "UNREVIEWED",
            }
            for entry in manifest.entries
        ],
    }


def write_json(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _completed(returncode: int, *, stdout: bytes = b"", stderr: bytes = b"") -> Any:
    return subprocess.CompletedProcess(
        args=("rh-mcp", "admin", "discover"),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_provider_failure_retries_privately_then_clears_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diagnostic = tmp_path / "private/state/last-error.log"
    destination = tmp_path / "candidate.json"
    candidate = json.dumps(candidate_from_active()).encode()
    responses = iter(
        (
            _completed(1, stdout=b"unsanitized-candidate", stderr=b"safe provider detail"),
            _completed(0, stdout=candidate),
        )
    )
    calls: list[tuple[Any, ...]] = []
    sleeps: list[float] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["capture_output"] is True
        return next(responses)

    def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        assert diagnostic.stat().st_mode & 0o777 == 0o600
        text = diagnostic.read_text()
        assert "safe provider detail" in text
        assert "unsanitized-candidate" not in text

    monkeypatch.setattr(automation.subprocess, "run", fake_run)
    monkeypatch.setattr(automation.time, "sleep", fake_sleep)
    _run_discovery(
        ("rh-mcp", "admin", "discover"),
        destination,
        "sha256:" + "a" * 64,
        diagnostic_log=diagnostic,
        retry_delays=(0.25,),
    )

    assert len(calls) == 2
    assert sleeps == [0.25]
    assert json.loads(destination.read_text()) == candidate_from_active()
    assert not diagnostic.exists()


@pytest.mark.parametrize("returncode", [2, 3, 4])
def test_operator_failures_do_not_retry_or_publish_private_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    diagnostic = tmp_path / "private/last-error.log"
    calls = 0

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return _completed(
            returncode,
            stdout=b"provider candidate must never be diagnosed",
            stderr=b"local-only-detail",
        )

    monkeypatch.setattr(automation.subprocess, "run", fake_run)
    with pytest.raises(AutomationError, match=f"failed with exit {returncode}") as caught:
        _run_discovery(
            ("rh-mcp", "admin", "discover"),
            tmp_path / "candidate.json",
            "sha256:" + "a" * 64,
            diagnostic_log=diagnostic,
            retry_delays=(0.0, 0.0),
        )

    assert calls == 1
    assert "local-only-detail" not in str(caught.value)
    assert diagnostic.stat().st_mode & 0o777 == 0o600
    assert "local-only-detail" in diagnostic.read_text()
    assert "provider candidate" not in diagnostic.read_text()


def test_stability_ignores_only_the_observation_clock(tmp_path: Path) -> None:
    first = candidate_from_active()
    second = copy.deepcopy(first)
    second["observed_at"] = "2026-08-13T08:01:00+00:00"
    assert stable_candidate_bytes(first) == stable_candidate_bytes(second)
    assert (
        require_stable_candidates(
            write_json(tmp_path / "one.json", first), write_json(tmp_path / "two.json", second)
        )
        == second
    )

    second["tools"][0]["description"] += " changed"
    with pytest.raises(AutomationError, match="disagreed"):
        require_stable_candidates(
            write_json(tmp_path / "one.json", first),
            write_json(tmp_path / "two.json", second),
        )


def test_classification_separates_refresh_from_permission_review() -> None:
    manifest_path = ROOT / "src/rh_mcp/manifests/read-manifest.json"
    unchanged = candidate_from_active()
    assert classify_candidate(unchanged, manifest_path).state == "no_drift"

    drifted = copy.deepcopy(unchanged)
    moved = drifted["tools"][0]["provider_tool_name"]
    drifted["tools"][0]["description"] += " changed"
    refresh = classify_candidate(drifted, manifest_path)
    assert refresh.state == "refresh"
    assert refresh.moved == (moved,)

    appeared = copy.deepcopy(unchanged)
    appeared["tools"].append(
        {
            "provider_tool_name": "provider_unreviewed_name",
            "description": "unreviewed",
            "input_schema": {"type": "object", "properties": {}},
            "output_schema": None,
            "annotations": {},
        }
    )
    review = classify_candidate(appeared, manifest_path)
    assert review.state == "review_required"
    assert review.added_count == 1
    assert "provider_unreviewed_name" not in json.dumps(review.to_json_dict())


def _minimal_refresh_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src/rh_mcp/manifests").mkdir(parents=True)
    (root / "tests").mkdir()
    source_manifest = ROOT / "src/rh_mcp/manifests/read-manifest.json"
    (root / "src/rh_mcp/manifests/read-manifest.json").write_text(
        source_manifest.read_text(encoding="utf-8"), encoding="utf-8"
    )
    digest = load_active_manifest().digest
    (root / "pyproject.toml").write_text(
        '[project]\nname = "rh-mcp"\nversion = "0.3.0"\n', encoding="utf-8"
    )
    (root / "uv.lock").write_text(
        '[[package]]\nname = "rh-mcp"\nversion = "0.3.0"\n', encoding="utf-8"
    )
    (root / "tests/test_manifest.py").write_text(
        f'    SHIPPED_DIGEST = "{digest}"\n', encoding="utf-8"
    )
    (root / "README.md").write_text(
        "before\n<!-- manifest-automation:current-start -->\nold\n"
        "<!-- manifest-automation:current-end -->\nafter\n",
        encoding="utf-8",
    )
    (root / "DESIGN.md").write_text(
        "before\n<!-- manifest-automation:current-start -->\nold\n"
        "<!-- manifest-automation:current-end -->\nafter\n",
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.3.0] — 2026-08-12\nold\n\n"
        "<!-- manifest-automation:release-links-start -->\n"
        "[Unreleased]: https://github.com/likefudan/rh-mcp/compare/v0.3.0...HEAD\n"
        "[0.3.0]: https://github.com/likefudan/rh-mcp/compare/v0.2.0...v0.3.0\n"
        "<!-- manifest-automation:release-links-end -->\n"
        "[0.2.0]: old\n",
        encoding="utf-8",
    )
    return root


def test_prepare_refresh_bumps_patch_and_carries_every_decision(tmp_path: Path) -> None:
    root = _minimal_refresh_repo(tmp_path)
    before = load_manifest_file(root / "src/rh_mcp/manifests/read-manifest.json")
    candidate = candidate_from_active()
    candidate["tools"][0]["description"] += " changed"
    candidate_path = write_json(tmp_path / "candidate.json", candidate)
    report = tmp_path / "report.md"

    assert prepare_refresh(candidate_path, root, report) == "0.3.1"
    after = load_manifest_file(root / "src/rh_mcp/manifests/read-manifest.json")
    old = {entry.provider_tool_name: entry for entry in before.entries}
    for entry in after.entries:
        prior = old[entry.provider_tool_name]
        assert (entry.capability, entry.disposition, entry.mutates, entry.rationale) == (
            prior.capability,
            prior.disposition,
            prior.mutates,
            prior.rationale,
        )
    assert 'version = "0.3.1"' in (root / "pyproject.toml").read_text()
    assert 'version = "0.3.1"' in (root / "uv.lock").read_text()
    assert after.digest in (root / "README.md").read_text()
    assert after.digest in (root / "CHANGELOG.md").read_text()
    assert "Reviewer decisions: unchanged" in report.read_text()


def test_release_notes_bind_the_manifest_and_checksums() -> None:
    manifest = {
        "manifest_version": "2026.08.13",
        "full_manifest_digest": "sha256:" + "a" * 64,
    }
    notes = render(manifest, "abc  wheel.whl\n")
    assert "`2026.08.13`" in notes
    assert manifest["full_manifest_digest"] in notes
    assert "abc  wheel.whl" in notes


def test_candidate_is_authenticated_ciphertext_before_artifact_upload(tmp_path: Path) -> None:
    candidate = write_json(tmp_path / "candidate.json", candidate_from_active())
    key = tmp_path / "key.pem"
    certificate = tmp_path / "certificate.pem"
    encrypted = tmp_path / "candidate.cms"
    decrypted = tmp_path / "decrypted.json"
    subprocess.run(
        (
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=test-observation",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ),
        check=True,
        capture_output=True,
    )
    seal_candidate(candidate, encrypted, certificate)
    assert not candidate.exists()
    assert encrypted.is_file()
    subprocess.run(
        (
            "openssl",
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            str(encrypted),
            "-recip",
            str(certificate),
            "-inkey",
            str(key),
            "-out",
            str(decrypted),
        ),
        check=True,
        capture_output=True,
    )
    assert json.loads(decrypted.read_text()) == candidate_from_active()


def test_credential_job_cannot_be_triggered_by_a_pull_request_or_read_app_secrets() -> None:
    workflow = (ROOT / ".github/workflows/manifest-refresh.yml").read_text()
    trigger, jobs = workflow.split("jobs:", 1)
    discover, hosted = jobs.split("  prepare_refresh_pr:", 1)
    assert "pull_request" not in trigger
    assert "pull_request_target" not in trigger
    assert "runs-on: [self-hosted, macOS, ARM64, rh-mcp-probe]" in discover
    assert "RH_MCP_BOT_APP_PRIVATE_KEY" not in discover
    assert "RH_MCP_OBSERVATION_DECRYPT_KEY" not in discover
    assert "contents: write" not in discover
    assert "actions/create-github-app-token" in hosted
    assert "candidate.cms" in hosted
    assert "RH_MCP_OBSERVATION_DECRYPT_KEY" in hosted


def test_release_requires_bot_identity_current_approval_and_narrow_diff() -> None:
    coordinator = (ROOT / ".github/workflows/auto-release.yml").read_text()
    release = (ROOT / ".github/workflows/release.yml").read_text()
    assert "EXPECTED_BOT_LOGIN" in coordinator
    assert 'test "$decision" = "APPROVED"' in coordinator
    assert "scripts/verify_release_pr.py" in coordinator
    assert "git rev-parse" in coordinator
    assert "refusing to move or replace existing tag" in coordinator
    assert "gh release create" in release
    assert "gh attestation verify" in release
    assert "release ref must be an annotated tag" in release
    assert "refusing to overwrite existing release" in release


# ---------------------------------------------------------------------------
# The credential preflight (`preflight-credential`)
#
# It exists because the probe path *cannot* report an unreadable credential.
# Measured on the probe runner: a locked keychain surfaced as a cancelled MCP
# handshake with exit 1 — the CLI's retryable-provider bucket — and three
# retries, while `auth-status` on the same machine returned exit 3 with the
# real reason. These tests pin that distinction, because the distinction is the
# entire value of the step.
# ---------------------------------------------------------------------------


def _fake_completed(returncode: int, stderr: bytes = b"") -> Any:
    return subprocess.CompletedProcess(args=["rh-mcp"], returncode=returncode, stderr=stderr)


def test_preflight_passes_and_clears_a_stale_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "private/preflight.log"
    log.parent.mkdir(parents=True)
    log.write_text("a failure from a previous run\n", encoding="utf-8")

    monkeypatch.setattr(automation.subprocess, "run", lambda *a, **k: _fake_completed(0))
    automation.preflight_credential(
        ("rh-mcp", "auth-status"), "sha256:" + "0" * 64, diagnostic_log=log
    )

    # A left-behind log would make the next operator debug the wrong failure.
    assert not log.exists()


def test_preflight_names_an_unreadable_credential_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 3 must be reported as a credential problem, not a provider one."""
    log = tmp_path / "private/preflight.log"
    monkeypatch.setattr(
        automation.subprocess,
        "run",
        lambda *a, **k: _fake_completed(
            3, b"reading the keychain credential failed with status 36"
        ),
    )

    with pytest.raises(AutomationError) as caught:
        automation.preflight_credential(
            ("rh-mcp", "auth-status"), "sha256:" + "0" * 64, diagnostic_log=log
        )

    message = str(caught.value)
    assert "credential store" in message
    assert "no provider call" in message
    # The public message must not carry the private detail it points at.
    assert "status 36" not in message
    assert "keychain" not in message


def test_preflight_does_not_call_an_unreadable_store_a_provider_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mutation this file exists to catch.

    Dropping the exit-3 branch leaves a message that reads as a generic
    failure, which is exactly the wording that sent an operator to the network
    for an afternoon. Assert the two classes produce *different* text.
    """
    log = tmp_path / "private/preflight.log"

    def message_for(returncode: int) -> str:
        monkeypatch.setattr(
            automation.subprocess, "run", lambda *a, **k: _fake_completed(returncode, b"detail")
        )
        with pytest.raises(AutomationError) as caught:
            automation.preflight_credential(
                ("rh-mcp", "auth-status"), "sha256:" + "0" * 64, diagnostic_log=log
            )
        return str(caught.value)

    unreadable = message_for(automation._CLI_CONFIGURATION_ERROR)
    other = message_for(1)

    assert unreadable != other
    assert "credential store" in unreadable
    assert "credential store" not in other


def test_preflight_writes_the_detail_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "private/preflight.log"
    monkeypatch.setattr(
        automation.subprocess, "run", lambda *a, **k: _fake_completed(3, b"the private reason")
    )

    with pytest.raises(AutomationError):
        automation.preflight_credential(
            ("rh-mcp", "auth-status"), "sha256:" + "0" * 64, diagnostic_log=log
        )

    assert "the private reason" in log.read_text(encoding="utf-8")
    assert log.stat().st_mode & 0o777 == 0o600


def test_the_configuration_exit_code_matches_the_gateway_contract() -> None:
    """A literal, checked against the source of truth rather than restated.

    If the CLI's exit contract moves, this fails here instead of silently
    reclassifying an unreadable credential as a retryable provider blip.
    """
    from rh_mcp.errors import EXIT_CODE_CONFIGURATION_ERROR

    assert automation._CLI_CONFIGURATION_ERROR == EXIT_CODE_CONFIGURATION_ERROR == 3


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )


def _tagged_repo(root: Path, *tags: str) -> None:
    """A real git repository carrying exactly `tags`."""
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    for tag in tags:
        _git(root, "tag", tag)


def test_the_comparison_link_names_a_tag_that_exists(tmp_path: Path) -> None:
    """The link used to assume every version bump becomes a tag.

    It does not. `0.3.1` and `0.3.2` were written into the changelog by this
    function and never released, so it emitted
    `compare/v0.3.2...v0.3.3` and `compare/v0.3.1...v0.3.2` — neither base
    exists, and GitHub answers both with a 404. A release record whose own
    diff link is dead is exactly the class of small false statement this
    repository spends its effort removing, so it is now a test rather than a
    convention.

    Here the source says `0.3.0` while the newest real tag is `v0.2.0`,
    reproducing that situation directly.
    """
    root = _minimal_refresh_repo(tmp_path)
    _tagged_repo(root, "v0.1.0", "v0.2.0")
    candidate = candidate_from_active()
    candidate["tools"][0]["description"] += " changed"
    candidate_path = write_json(tmp_path / "candidate.json", candidate)

    assert prepare_refresh(candidate_path, root, tmp_path / "report.md") == "0.3.1"

    changelog = (root / "CHANGELOG.md").read_text()
    assert "[0.3.1]: https://github.com/likefudan/rh-mcp/compare/v0.2.0...v0.3.1" in changelog
    assert "compare/v0.3.0...v0.3.1" not in changelog

    # Every base a *released* line compares from must be a tag that exists.
    #
    # `[Unreleased]` is deliberately excluded rather than overlooked: it reads
    # `compare/v{new}...HEAD`, and `v{new}` is the tag this refresh is
    # proposing, which correctly does not exist until the release workflow
    # creates it. Asserting over every line would have failed on that, which
    # is a check about the wrong thing.
    existing = subprocess.run(
        ["git", "-C", str(root), "tag", "--list"],
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    ).stdout.split()
    released = re.findall(
        r"(?m)^\[\d[^\]]*\]: https://github\.com/likefudan/rh-mcp/compare/(\S+?)\.\.\.",
        changelog,
    )
    assert released, "no released comparison links were emitted at all"
    for base in released:
        assert base in existing, base


def test_it_falls_back_when_the_repository_has_no_tags(tmp_path: Path) -> None:
    """A tagless checkout must still produce the shape the next run parses.

    `prepare_refresh` finds the previous link with a regex anchored on
    `...v{old_version}`, so emitting nothing, or something differently shaped,
    would break the following refresh rather than this one.
    """
    root = _minimal_refresh_repo(tmp_path)
    _tagged_repo(root)
    candidate = candidate_from_active()
    candidate["tools"][0]["description"] += " changed"
    candidate_path = write_json(tmp_path / "candidate.json", candidate)

    assert prepare_refresh(candidate_path, root, tmp_path / "report.md") == "0.3.1"
    assert (
        "[0.3.1]: https://github.com/likefudan/rh-mcp/compare/v0.3.0...v0.3.1"
        in (root / "CHANGELOG.md").read_text()
    )


def test_a_shallow_checkout_refuses_to_guess_the_comparison_base(tmp_path: Path) -> None:
    """The environment this script actually runs in fetches no tags.

    `actions/checkout` defaults to a depth-1 clone. A depth-1 clone of this
    repository reports `--is-shallow-repository true` and `git tag --list`
    returns nothing, so a resolver that fell back on "no tags found" would
    emit `compare/v{old_version}...` — the dangling link this whole change
    exists to prevent — in CI, silently, with every local test still green.

    "No tags" and "no tags visible from here" are different facts. The second
    one is not a licence to guess, so it raises.
    """
    root = _minimal_refresh_repo(tmp_path)
    _tagged_repo(root, "v0.1.0", "v0.2.0")
    # A later commit, so the tags sit behind HEAD. This matters: `git clone
    # --depth 1` *does* carry a tag that points at the commit it fetched, so a
    # repository whose only commit is also its tag would not reproduce the
    # situation at all — which is how the first version of this test passed
    # for the wrong reason.
    (root / "later.txt").write_text("later\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "later")

    # A depth-1 clone of that repository: shallow, and carrying no tags.
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{root}", str(shallow)],
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )
    assert (
        subprocess.run(
            ["git", "-C", str(shallow), "rev-parse", "--is-shallow-repository"],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == "true"
    )
    assert automation._latest_existing_tag(shallow) is None

    candidate = candidate_from_active()
    candidate["tools"][0]["description"] += " changed"
    candidate_path = write_json(tmp_path / "candidate.json", candidate)

    with pytest.raises(AutomationError, match="shallow"):
        prepare_refresh(candidate_path, shallow, tmp_path / "report.md")


def test_a_tag_on_another_branch_is_not_the_comparison_base(tmp_path: Path) -> None:
    """Reachability, not recency across the whole repository.

    A tag on a branch this commit is not on describes a lineage that never
    led here, and a comparison link against it renders a diff that never
    happened. `v9.0.0` below is newer by every version ordering and sits on a
    sidetrack; the base must still be `v0.2.0`.
    """
    root = _minimal_refresh_repo(tmp_path)
    _tagged_repo(root, "v0.1.0", "v0.2.0")
    _git(root, "checkout", "-q", "-b", "sidetrack")
    (root / "sidetrack.txt").write_text("elsewhere\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "sidetrack")
    _git(root, "tag", "v9.0.0")
    _git(root, "checkout", "-q", "-")

    assert automation._latest_existing_tag(root) == "v0.2.0"

    candidate = candidate_from_active()
    candidate["tools"][0]["description"] += " changed"
    candidate_path = write_json(tmp_path / "candidate.json", candidate)

    assert prepare_refresh(candidate_path, root, tmp_path / "report.md") == "0.3.1"
    changelog = (root / "CHANGELOG.md").read_text()
    assert "[0.3.1]: https://github.com/likefudan/rh-mcp/compare/v0.2.0...v0.3.1" in changelog
    assert "v9.0.0" not in changelog
