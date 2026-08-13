"""Generate minimal release notes that publish the two consumer pins together."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def render(manifest: dict[str, Any], checksums: str) -> str:
    version = manifest.get("manifest_version")
    digest = manifest.get("full_manifest_digest")
    if not isinstance(version, str) or not version:
        raise ValueError("manifest_version is missing")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("full_manifest_digest is missing")
    return f"""This release was built from the tagged commit after the manifest-refresh
PR passed all required checks and received owner approval.

Manifest version: `{version}`

Full-manifest digest:

```
{digest}
```

Consumers must pin the package tag and this digest together. Build provenance
attestations are attached by GitHub Actions.

Artifact checksums:

```
{checksums.rstrip()}
```
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    notes = render(manifest, args.checksums.read_text(encoding="utf-8"))
    args.output.write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
