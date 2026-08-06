"""Refresh the committed manifest against a new discovery run.

The manifest went stale within a day of first being committed (DESIGN.md §13):
Robinhood changed two output schemas, readiness refused, and every one of the
53 dispositions was still correct. That is the ordinary case, and it will
recur. This script exists so the ordinary case has one procedure instead of an
ad-hoc script written slightly differently each time.

**What it does is narrow, and what it refuses is the point.**

It carries every reviewer decision forward *verbatim* — `disposition`,
`mutates`, `rationale`, and the capability name — and refreshes only the
provider-derived fields and the digests computed from them. It cannot grant a
permission, because it never writes a disposition it did not read from the
previous manifest.

It refuses outright when:

* a tool appears or disappears, or a capability is renamed. A changed tool
  *set* is a review, not a refresh — §6.1 requires a human to decide each
  disposition, and there is no prior decision to carry forward for a tool
  nobody has seen.
* the previous manifest is missing, unreadable, or fails its own loader.
* the candidate document is not a discovery output, or is incomplete.
* the resulting manifest would not load.

Two design notes worth stating because they look like omissions:

* It does **not** take an `--allow-disposition-change` flag or anything like
  it. A permission change is a review, and a review produces a fresh manifest
  through the `admin discover` path with a human writing rationales. An escape
  hatch here would be the one place in this project where a permission could
  change without that.
* It writes the refreshed file and prints the new digest, but does **not**
  update the pinned digest anywhere else. Every consumer of that value —
  `tests/test_manifest.py`, README, a deployment config — has to be changed
  deliberately, because accepting a new manifest is exactly the decision the
  expected-digest mechanism exists to make explicit (§9).

Usage:

    uv run rh-mcp admin discover > candidate.json
    uv run python scripts/refresh_manifest.py candidate.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from rh_mcp.canonical import tool_metadata_digest, tool_schema_digest  # noqa: E402
from rh_mcp.errors import GatewayError  # noqa: E402
from rh_mcp.manifest import (  # noqa: E402
    FULL_MANIFEST_DIGEST_FIELD,
    PACKAGED_MANIFEST_PATH,
    ObservedSurface,
    ObservedTool,
    compute_full_manifest_digest,
    load_manifest_file,
    load_manifest_text,
    provider_surface_digest,
)
from rh_mcp.validation import json_safe  # noqa: E402


class RefusedError(RuntimeError):
    """A refusal. Every one of these means a human has to look."""


def _load_candidate(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RefusedError(f"{path} could not be read as JSON: {exc}") from None
    if not isinstance(document, dict) or document.get("candidate") is not True:
        raise RefusedError(
            f"{path} is not an `admin discover` candidate document. Regenerate it with "
            "`rh-mcp admin discover` rather than editing a manifest by hand."
        )
    tools = document.get("tools")
    if not isinstance(tools, list) or not tools:
        raise RefusedError(f"{path} contains no observed tools")
    return document


def _refuse_on_set_change(prior: dict[str, Any], observed: dict[str, Any]) -> None:
    added = sorted(set(observed) - set(prior))
    removed = sorted(set(prior) - set(observed))
    if not (added or removed):
        return
    lines = ["the provider tool set changed, so this is a review and not a refresh."]
    if added:
        lines.append(f"  appeared ({len(added)}): {added}")
        lines.append("    No prior disposition exists for these. §6.1 requires a human to")
        lines.append("    decide each one; nothing here may decide for them.")
    if removed:
        lines.append(f"  disappeared ({len(removed)}): {removed}")
        lines.append("    Dropping a reviewed entry silently would shrink the manifest")
        lines.append("    without anyone deciding to.")
    raise RefusedError("\n".join(lines))


def refresh(candidate_path: Path, manifest_path: Path) -> dict[str, Any]:
    """Return the refreshed manifest document. Raises `RefusedError` if it must not."""
    try:
        previous = load_manifest_file(manifest_path)
    except GatewayError as exc:
        raise RefusedError(
            f"the current manifest at {manifest_path} does not load ({exc.code}: "
            f"{exc.message}). Fix that before refreshing it."
        ) from None

    candidate = _load_candidate(candidate_path)
    prior = {entry.provider_tool_name: entry for entry in previous.entries}
    observed = {t["provider_tool_name"]: t for t in candidate["tools"]}
    _refuse_on_set_change(prior, observed)

    _refuse_when_nothing_moved(prior, observed)

    entries: list[dict[str, Any]] = []
    for name in sorted(observed):
        tool, kept = observed[name], prior[name]
        description = tool.get("description") or ""
        annotations = tool.get("annotations") or {}
        entries.append(
            {
                # Carried forward verbatim. This script decides none of these.
                "capability": kept.capability,
                "disposition": kept.disposition,
                "mutates": kept.mutates,
                "rationale": kept.rationale,
                # Refreshed from the observation.
                "provider_tool_name": name,
                "description": description,
                "input_schema": tool["input_schema"],
                "output_schema": tool.get("output_schema"),
                "annotations": annotations,
                "schema_digest": tool_schema_digest(
                    name, tool["input_schema"], tool.get("output_schema")
                ),
                "metadata_digest": tool_metadata_digest(description, annotations),
            }
        )

    surface = ObservedSurface(
        tools=tuple(
            ObservedTool(
                name=e["provider_tool_name"],
                description=e["description"],
                input_schema=e["input_schema"],
                output_schema=e["output_schema"],
                annotations=e["annotations"],
            )
            for e in entries
        ),
        complete=True,
    )

    document = {
        "manifest_format_version": previous.manifest_format_version,
        "canonicalization_version": previous.canonicalization_version,
        "digest_algorithm": previous.digest_algorithm,
        "manifest_version": _next_version(previous.manifest_version, candidate["observed_at"]),
        "provider_surface_digest": provider_surface_digest(surface),
        "observed_at": candidate["observed_at"],
        # Carried forward, not restamped. Nobody reviewed anything here — the
        # dispositions came from the previous manifest — so writing a fresh
        # `reviewed_at` would claim a review that did not happen.
        #
        # It also made the tool lie. `reviewed_at` was `now()` per invocation,
        # so two consecutive `--dry-run`s reported two different digests and
        # neither matched what the real run wrote. A dry run whose whole
        # purpose is to tell you the digest you are about to accept must be
        # deterministic, and the digest it prints must be the one written.
        "reviewer": json_safe(previous.reviewer),
        "entries": entries,
    }
    document[FULL_MANIFEST_DIGEST_FIELD] = compute_full_manifest_digest(document)

    # A refresh that produces a manifest the loader rejects is a refresh that
    # has broken something; better to find out here than at the next readiness.
    reloaded = load_manifest_text(json.dumps(document))
    if reloaded.digest != document[FULL_MANIFEST_DIGEST_FIELD]:  # pragma: no cover
        raise RefusedError("the refreshed manifest does not reload to its own digest")

    _assert_no_decision_changed(prior, entries)
    return document


def _refuse_when_nothing_moved(prior: dict[str, Any], observed: dict[str, Any]) -> None:
    """A refresh with no provider change must be a no-op, not a new digest.

    `reviewed_at` moves on every run, so writing unconditionally would mint a
    fresh digest each time — and a digest that changes when nothing changed is
    worse than useless: it destroys the one signal the value carries. It would
    also train whoever runs this to update pinned digests reflexively, which is
    precisely the reflex §6's bump rule exists to prevent.
    """
    moved = [
        name
        for name, tool in observed.items()
        if tool_schema_digest(name, tool["input_schema"], tool.get("output_schema"))
        != prior[name].schema_digest
        or tool_metadata_digest(tool.get("description") or "", tool.get("annotations") or {})
        != prior[name].metadata_digest
    ]
    if not moved:
        raise RefusedError(
            "the observed surface is identical to the committed manifest — nothing to "
            "refresh. If readiness is failing, the cause is elsewhere: check the pinned "
            "expected digest, not the manifest."
        )


def _next_version(previous: str, observed_at: str) -> str:
    """`YYYY.MM.DD` of the observation, with a counter when same-day."""
    day = observed_at[:10].replace("-", ".")
    if not previous.startswith(day):
        return day
    tail = previous[len(day) :].lstrip(".")
    return f"{day}.{int(tail) + 1 if tail.isdigit() else 1}"


def _assert_no_decision_changed(prior: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    """Belt to the braces above: prove no reviewer decision moved.

    The carry-forward is a few lines and obviously correct by inspection, which
    is exactly the kind of thing that stops being true after an edit. This
    fails loudly rather than writing a manifest whose permissions drifted.
    """
    for entry in entries:
        kept = prior[entry["provider_tool_name"]]
        for field in ("capability", "disposition", "mutates", "rationale"):
            if entry[field] != getattr(kept, field):  # pragma: no cover
                raise RefusedError(
                    f"refusing to write: {entry['provider_tool_name']}.{field} changed "
                    "during a refresh, which must never happen"
                )


def report(previous_path: Path, document: dict[str, Any]) -> list[str]:
    """What moved, in the terms a reviewer needs to decide whether to accept."""
    previous = load_manifest_file(previous_path)
    prior = {e.provider_tool_name: e for e in previous.entries}
    moved = [
        e["provider_tool_name"]
        for e in document["entries"]
        if e["schema_digest"] != prior[e["provider_tool_name"]].schema_digest
        or e["metadata_digest"] != prior[e["provider_tool_name"]].metadata_digest
    ]
    allowed = sum(1 for e in document["entries"] if e["disposition"] == "allowed")
    denied = sum(1 for e in document["entries"] if e["disposition"] == "denied")
    lines = [
        f"tools:              {len(document['entries'])} (unchanged set)",
        f"dispositions:       unchanged — {allowed} allowed, {denied} denied",
        f"entries that moved: {moved or 'none'}",
        "",
        f"manifest_version: {previous.manifest_version} -> {document['manifest_version']}",
        f"digest:           {previous.digest}",
        f"              ->  {document[FULL_MANIFEST_DIGEST_FIELD]}",
    ]
    if moved:
        lines += [
            "",
            "Review what changed in those tools before accepting. A refresh keeps every",
            "disposition, so a tool that gained a write capability would still be marked",
            "allowed — the digests moving is the signal to go and look.",
        ]
    lines += [
        "",
        "Nothing else was updated. Update the pinned digest in tests, README and any",
        "deployment config deliberately: accepting a new manifest is the decision the",
        "expected-digest mechanism exists to make explicit (DESIGN.md §9).",
    ]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="refresh_manifest",
        description="Refresh the committed manifest against a new discovery run.",
    )
    parser.add_argument("candidate", type=Path, help="output of `rh-mcp admin discover`")
    parser.add_argument("--manifest", type=Path, default=PACKAGED_MANIFEST_PATH)
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would change; write nothing"
    )
    args = parser.parse_args(argv)

    try:
        document = refresh(args.candidate, args.manifest)
    except RefusedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1

    for line in report(args.manifest, document):
        print(line)

    if args.dry_run:
        print("\n(dry run — nothing written)")
        return 0

    args.manifest.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print(f"\nwrote {args.manifest}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
