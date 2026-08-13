"""Verify that an automatically releasable PR has exactly the narrow shape expected."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ALLOWED_PATHS = {
    "CHANGELOG.md",
    "DESIGN.md",
    "README.md",
    "pyproject.toml",
    "src/rh_mcp/manifests/read-manifest.json",
    "tests/test_manifest.py",
    "uv.lock",
}
REQUIRED_PATHS = ALLOWED_PATHS


def _git(*args: str) -> str:
    return subprocess.check_output(("git", *args), text=True).strip()


def _version_at(ref: str) -> str:
    text = _git("show", f"{ref}:pyproject.toml")
    match = re.search(r'(?m)^version = "(\d+)\.(\d+)\.(\d+)"$', text)
    if match is None:
        raise RuntimeError(f"{ref} has no literal project version")
    return ".".join(match.groups())


def verify(base: str, head: str) -> str:
    changed = set(filter(None, _git("diff", "--name-only", base, head).splitlines()))
    unexpected = changed - ALLOWED_PATHS
    missing = REQUIRED_PATHS - changed
    if unexpected:
        raise RuntimeError(f"automatic release PR changed unexpected paths: {sorted(unexpected)}")
    if missing:
        raise RuntimeError(f"automatic release PR omitted required paths: {sorted(missing)}")

    old = _version_at(base)
    new = _version_at(head)
    old_tuple = tuple(int(part) for part in old.split("."))
    new_tuple = tuple(int(part) for part in new.split("."))
    if new_tuple != (old_tuple[0], old_tuple[1], old_tuple[2] + 1):
        raise RuntimeError(f"automatic refresh must be one patch bump, got {old} -> {new}")

    manifest = Path("src/rh_mcp/manifests/read-manifest.json").read_text(encoding="utf-8")
    digest_match = re.search(r'"full_manifest_digest": "(sha256:[0-9a-f]{64})"', manifest)
    if digest_match is None:
        raise RuntimeError("head manifest has no valid declared digest")
    digest = digest_match.group(1)
    for path in ("README.md", "CHANGELOG.md", "tests/test_manifest.py"):
        if digest not in Path(path).read_text(encoding="utf-8"):
            raise RuntimeError(f"{path} does not pin the head manifest digest")
    return new


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: verify_release_pr BASE_SHA HEAD_SHA", file=sys.stderr)
        return 2
    try:
        version = verify(args[0], args[1])
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"verified approved manifest refresh for v{version}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
