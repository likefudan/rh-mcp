"""Safe automation around owner-assisted Robinhood tool discovery.

This file deliberately has two halves that run on different machines/jobs:

* ``probe`` runs on the credential-bearing Mac.  It can enumerate the provider
  surface, but it has no GitHub write credential and never invokes a tool.
* ``prepare-refresh`` runs on a GitHub-hosted runner.  It consumes an uploaded
  candidate and can edit a checkout, but it never has the Robinhood credential.

The boundary is structural rather than conventional: the probe only writes a
short-lived bundle and a non-sensitive summary.  It contains no GitHub client.
The prepare half reuses ``refresh_manifest.py``, so it cannot invent or change
``capability``, ``disposition``, ``mutates`` or ``rationale`` decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from refresh_manifest import RefusedError, refresh  # noqa: E402

from rh_mcp.canonical import tool_metadata_digest, tool_schema_digest  # noqa: E402
from rh_mcp.manifest import (  # noqa: E402
    FULL_MANIFEST_DIGEST_FIELD,
    PACKAGED_MANIFEST_PATH,
    ObservedSurface,
    ObservedTool,
    load_manifest_file,
    provider_surface_digest,
)

README_START = "<!-- manifest-automation:current-start -->"
README_END = "<!-- manifest-automation:current-end -->"
DESIGN_START = "<!-- manifest-automation:current-start -->"
DESIGN_END = "<!-- manifest-automation:current-end -->"
LINKS_START = "<!-- manifest-automation:release-links-start -->"
LINKS_END = "<!-- manifest-automation:release-links-end -->"


class AutomationError(RuntimeError):
    """A safe refusal that must stop automation."""


@dataclass(frozen=True)
class DriftSummary:
    state: str
    stable_candidate_sha256: str
    provider_surface_digest: str
    prior_tool_count: int
    observed_tool_count: int
    moved: tuple[str, ...] = ()
    added_count: int = 0
    removed_count: int = 0

    def to_json_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "state": self.state,
            "stable_candidate_sha256": self.stable_candidate_sha256,
            "provider_surface_digest": self.provider_surface_digest,
            "prior_tool_count": self.prior_tool_count,
            "observed_tool_count": self.observed_tool_count,
            "moved_count": len(self.moved),
            "added_count": self.added_count,
            "removed_count": self.removed_count,
        }
        # A changed-set observation is unreviewed provider data.  Do not put new
        # names in Actions output, logs, or the public draft marker.
        if self.state != "review_required":
            document["moved"] = list(self.moved)
        return document


def _load_candidate(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AutomationError(f"candidate is not readable JSON: {exc}") from None
    if not isinstance(document, dict) or document.get("candidate") is not True:
        raise AutomationError("document is not an `rh-mcp admin discover` candidate")
    if not isinstance(document.get("observed_at"), str):
        raise AutomationError("candidate has no observation timestamp")
    tools = document.get("tools")
    if not isinstance(tools, list) or not tools:
        raise AutomationError("candidate contains no tools")
    names: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("provider_tool_name"), str):
            raise AutomationError("candidate contains a malformed tool")
        name = tool["provider_tool_name"]
        if not name:
            raise AutomationError("candidate contains an empty provider tool name")
        if not isinstance(tool.get("input_schema"), dict):
            raise AutomationError("candidate contains a tool without an input schema")
        if tool.get("description") is not None and not isinstance(tool["description"], str):
            raise AutomationError("candidate contains a non-string tool description")
        if tool.get("output_schema") is not None and not isinstance(
            tool["output_schema"], dict
        ):
            raise AutomationError("candidate contains a malformed output schema")
        if tool.get("annotations") is not None and not isinstance(tool["annotations"], dict):
            raise AutomationError("candidate contains malformed annotations")
        names.append(name)
    if len(names) != len(set(names)):
        raise AutomationError("candidate contains duplicate provider tool names")
    return document


def stable_candidate_bytes(document: dict[str, Any]) -> bytes:
    """Canonical comparison payload, excluding only the observation clock."""
    payload = {key: value for key, value in document.items() if key != "observed_at"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def require_stable_candidates(first: Path, second: Path) -> dict[str, Any]:
    one = _load_candidate(first)
    two = _load_candidate(second)
    if stable_candidate_bytes(one) != stable_candidate_bytes(two):
        raise AutomationError(
            "two consecutive discoveries disagreed; refusing to open or update a PR"
        )
    return two


def _observed_surface(document: dict[str, Any]) -> ObservedSurface:
    return ObservedSurface(
        tools=tuple(
            ObservedTool(
                name=tool["provider_tool_name"],
                description=tool.get("description") or "",
                input_schema=tool["input_schema"],
                output_schema=tool.get("output_schema"),
                annotations=tool.get("annotations") or {},
            )
            for tool in document["tools"]
        ),
        complete=True,
    )


def classify_candidate(candidate: dict[str, Any], manifest_path: Path) -> DriftSummary:
    previous = load_manifest_file(manifest_path)
    prior = {entry.provider_tool_name: entry for entry in previous.entries}
    observed = {tool["provider_tool_name"]: tool for tool in candidate["tools"]}
    added = sorted(set(observed) - set(prior))
    removed = sorted(set(prior) - set(observed))
    surface_digest = provider_surface_digest(_observed_surface(candidate))
    fingerprint = hashlib.sha256(stable_candidate_bytes(candidate)).hexdigest()
    if added or removed:
        return DriftSummary(
            state="review_required",
            stable_candidate_sha256=fingerprint,
            provider_surface_digest=surface_digest,
            prior_tool_count=len(prior),
            observed_tool_count=len(observed),
            added_count=len(added),
            removed_count=len(removed),
        )

    moved = tuple(
        name
        for name in sorted(observed)
        if tool_schema_digest(
            name, observed[name]["input_schema"], observed[name].get("output_schema")
        )
        != prior[name].schema_digest
        or tool_metadata_digest(
            observed[name].get("description") or "", observed[name].get("annotations") or {}
        )
        != prior[name].metadata_digest
    )
    return DriftSummary(
        state="refresh" if moved else "no_drift",
        stable_candidate_sha256=fingerprint,
        provider_surface_digest=surface_digest,
        prior_tool_count=len(prior),
        observed_tool_count=len(observed),
        moved=moved,
    )


def _private_write(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise AutomationError(f"refusing to write through symlink: {path}")
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def write_summary(path: Path, summary: DriftSummary) -> None:
    _private_write(path, json.dumps(summary.to_json_dict(), indent=2) + "\n")


def _run_discovery(command: Sequence[str], destination: Path, expected_digest: str) -> None:
    env = os.environ.copy()
    env["RH_MCP_EXPECTED_MANIFEST_DIGEST"] = expected_digest
    completed = subprocess.run(
        command,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        # Provider and OAuth diagnostics are intentionally not copied to stdout.
        raise AutomationError(
            f"authenticated discovery failed with exit {completed.returncode}; "
            "inspect the credential-bearing runner locally"
        )
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise AutomationError("discovery output was not UTF-8 JSON") from None
    _private_write(destination, text)
    _load_candidate(destination)


def seal_candidate(candidate: Path, destination: Path, certificate: Path) -> None:
    """Encrypt a candidate before it leaves the public repository's Mac runner."""
    if not certificate.is_file():
        raise AutomationError("manifest observation encryption certificate is missing")
    completed = subprocess.run(
        (
            "openssl",
            "cms",
            "-encrypt",
            "-binary",
            "-aes-256-gcm",
            "-in",
            str(candidate),
            "-out",
            str(destination),
            "-outform",
            "DER",
            str(certificate),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AutomationError("candidate encryption failed; plaintext was not uploaded")
    destination.chmod(0o600)
    candidate.unlink()


def probe(
    *,
    manifest_path: Path,
    output_dir: Path,
    settle_seconds: float,
    command: Sequence[str],
    certificate: Path,
) -> DriftSummary:
    previous = load_manifest_file(manifest_path)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    first = output_dir / "candidate-first.json"
    stable = output_dir / "candidate.json"
    _run_discovery(command, first, previous.digest)
    if settle_seconds:
        time.sleep(settle_seconds)
    _run_discovery(command, stable, previous.digest)
    candidate = require_stable_candidates(first, stable)
    summary = classify_candidate(candidate, manifest_path)
    write_summary(output_dir / "summary.json", summary)
    first.unlink()
    seal_candidate(stable, output_dir / "candidate.cms", certificate)
    return summary


def _read_version(pyproject: Path) -> str:
    match = re.search(
        r"(?m)^version = \"(\d+\.\d+\.\d+)\"$", pyproject.read_text(encoding="utf-8")
    )
    if match is None:
        raise AutomationError("pyproject has no single literal project version")
    return match.group(1)


def _next_patch(version: str) -> str:
    major, minor, patch = (int(part) for part in version.split("."))
    return f"{major}.{minor}.{patch + 1}"


def _replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AutomationError(f"expected exactly one update target in {path}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def _replace_marked(path: Path, start: str, end: str, body: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(start) != 1 or text.count(end) != 1:
        raise AutomationError(f"missing or duplicate automation markers in {path}")
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    path.write_text(f"{before}{start}\n{body.rstrip()}\n{end}{after}", encoding="utf-8")


def _bump_uv_lock(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    target = f'[[package]]\nname = "rh-mcp"\nversion = "{old}"'
    replacement = f'[[package]]\nname = "rh-mcp"\nversion = "{new}"'
    if text.count(target) != 1:
        raise AutomationError("uv.lock does not contain the expected root package version")
    path.write_text(text.replace(target, replacement), encoding="utf-8")


def _changelog_entry(
    *, old_version: str, new_version: str, document: dict[str, Any], moved: tuple[str, ...]
) -> str:
    manifest_version = str(document["manifest_version"])
    digest = str(document[FULL_MANIFEST_DIGEST_FIELD])
    observed_day = str(document["observed_at"])[:10]
    names = ", ".join(f"`{name}`" for name in moved)
    return f"""## [{new_version}] — {observed_day}

### Manifest

#### `{manifest_version}` — automated provider refresh candidate

```
{digest}
```

The provider tool set and every reviewed `capability`, `disposition`, `mutates`
and `rationale` decision are unchanged from `{old_version}`. Two consecutive
authenticated discoveries returned byte-equivalent tool payloads after the
observation timestamp was removed. Provider-derived schema or metadata moved
for {names}.

The bot made no permission decision. Approval of the PR carrying this block is
the owner's review of the provider diff and authorizes the release coordinator
to merge, tag and publish this exact source.
"""


def prepare_refresh(candidate_path: Path, repo_root: Path, report_path: Path) -> str:
    manifest_path = repo_root / "src/rh_mcp/manifests/read-manifest.json"
    previous = load_manifest_file(manifest_path)
    candidate = _load_candidate(candidate_path)
    summary = classify_candidate(candidate, manifest_path)
    if summary.state != "refresh":
        raise AutomationError(f"candidate is {summary.state}, not a same-set refresh")

    try:
        document = refresh(candidate_path, manifest_path)
    except RefusedError as exc:
        raise AutomationError(str(exc)) from None
    manifest_path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    pyproject = repo_root / "pyproject.toml"
    old_version = _read_version(pyproject)
    new_version = _next_patch(old_version)
    _replace_once(pyproject, f'version = "{old_version}"', f'version = "{new_version}"')
    _bump_uv_lock(repo_root / "uv.lock", old_version, new_version)

    digest = str(document[FULL_MANIFEST_DIGEST_FIELD])
    manifest_version = str(document["manifest_version"])
    _replace_once(
        repo_root / "tests/test_manifest.py",
        f'    SHIPPED_DIGEST = "{previous.digest}"',
        f'    SHIPPED_DIGEST = "{digest}"',
    )

    readme_body = f"""The current source declares package version `v{new_version}` and carries
manifest `{manifest_version}`. Its full-manifest digest is:

```
{digest}
```

The version and digest belong to this source tree. A GitHub release exists only
after the tag workflow has completed; consumers should pin both values from the
same tagged artifact."""
    _replace_marked(repo_root / "README.md", README_START, README_END, readme_body)

    short = digest.split(":", 1)[1][:8]
    design_body = (
        f"The current source declares package `{new_version}` and carries manifest "
        f"`{manifest_version}` / `{short}…`. This statement is about source identity; "
        "publication is established only by a completed tag workflow and GitHub release."
    )
    _replace_marked(repo_root / "DESIGN.md", DESIGN_START, DESIGN_END, design_body)

    changelog = repo_root / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    old_link_match = re.search(
        rf"(?m)^\[{re.escape(old_version)}\]: https://github\.com/likefudan/"
        rf"rh-mcp/compare/v[^\s]+\.\.\.v{re.escape(old_version)}$",
        text,
    )
    if old_link_match is None:
        raise AutomationError("CHANGELOG has no exact comparison link for the current version")
    old_link = old_link_match.group(0)
    insertion_point = "## [Unreleased]\n"
    if text.count(insertion_point) != 1:
        raise AutomationError("CHANGELOG has no unique Unreleased insertion point")
    entry = _changelog_entry(
        old_version=old_version, new_version=new_version, document=document, moved=summary.moved
    )
    text = text.replace(insertion_point, f"{insertion_point}\n{entry}\n", 1)
    changelog.write_text(text, encoding="utf-8")
    links = (
        f"[Unreleased]: https://github.com/likefudan/rh-mcp/compare/v{new_version}...HEAD\n"
        f"[{new_version}]: https://github.com/likefudan/rh-mcp/compare/"
        f"v{old_version}...v{new_version}\n"
        f"{old_link}"
    )
    _replace_marked(changelog, LINKS_START, LINKS_END, links)

    report = f"""# Automated manifest refresh

- Package: `{old_version}` → `{new_version}`
- Manifest: `{manifest_version}`
- Full digest: `{digest}`
- Provider surface: `{summary.provider_surface_digest}`
- Tool set: unchanged ({summary.observed_tool_count})
- Reviewer decisions: unchanged
- Changed entries: {', '.join(f'`{name}`' for name in summary.moved)}

Review the committed provider-schema diff. In particular, confirm that no
already-allowed tool gained a write or trading-shaped operation. The bot cannot
merge this PR; owner approval and all required checks remain mandatory.
"""
    report_path.write_text(report, encoding="utf-8")
    return new_version


def write_review_marker(summary_path: Path, destination: Path, run_url: str) -> None:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("state") != "review_required":
        raise AutomationError("a review marker is only valid for a changed tool set")
    body = f"""# Provider tool-set review required

This Draft PR records a stable provider observation without publishing the
unreviewed tool names or schemas.

- Previous tool count: {summary['prior_tool_count']}
- Observed tool count: {summary['observed_tool_count']}
- Appeared: {summary['added_count']}
- Disappeared: {summary['removed_count']}
- Candidate SHA-256: `{summary['stable_candidate_sha256']}`
- Provider surface digest: `{summary['provider_surface_digest']}`
- Encrypted Actions run: {run_url}

Re-run `rh-mcp admin discover` locally, confirm its candidate hash against the
run, review every new or removed capability, and author `capability`,
`disposition`, `mutates` and `rationale` decisions. This PR intentionally
cannot auto-merge or auto-release.
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body, encoding="utf-8")


def _write_github_output(path: Path, summary: DriftSummary) -> None:
    safe = summary.to_json_dict()
    fields = {
        "state": safe["state"],
        "surface_short": str(safe["provider_surface_digest"]).split(":", 1)[1][:16],
        "added_count": safe["added_count"],
        "removed_count": safe["removed_count"],
        "moved_count": safe["moved_count"],
    }
    with path.open("a", encoding="utf-8") as stream:
        for key, value in fields.items():
            stream.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="manifest_automation")
    sub = parser.add_subparsers(dest="command", required=True)

    probe_parser = sub.add_parser("probe")
    probe_parser.add_argument("--manifest", type=Path, default=PACKAGED_MANIFEST_PATH)
    probe_parser.add_argument("--output-dir", type=Path, required=True)
    probe_parser.add_argument("--settle-seconds", type=float, default=60.0)
    probe_parser.add_argument("--github-output", type=Path)
    probe_parser.add_argument(
        "--certificate",
        type=Path,
        default=REPO_ROOT / ".github/manifest-observation-cert.pem",
    )

    prepare = sub.add_parser("prepare-refresh")
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    prepare.add_argument("--report", type=Path, required=True)

    marker = sub.add_parser("write-review-marker")
    marker.add_argument("--summary", type=Path, required=True)
    marker.add_argument("--destination", type=Path, required=True)
    marker.add_argument("--run-url", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            executable = Path(sys.executable).with_name("rh-mcp")
            summary = probe(
                manifest_path=args.manifest,
                output_dir=args.output_dir,
                settle_seconds=args.settle_seconds,
                command=(str(executable), "admin", "discover"),
                certificate=args.certificate,
            )
            print(
                f"stable discovery: {summary.state}; prior={summary.prior_tool_count}; "
                f"observed={summary.observed_tool_count}; moved={len(summary.moved)}; "
                f"added={summary.added_count}; removed={summary.removed_count}"
            )
            if args.github_output is not None:
                _write_github_output(args.github_output, summary)
        elif args.command == "prepare-refresh":
            version = prepare_refresh(args.candidate, args.repo_root, args.report)
            print(f"prepared same-set refresh for v{version}")
        else:
            write_review_marker(args.summary, args.destination, args.run_url)
    except (AutomationError, RefusedError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
