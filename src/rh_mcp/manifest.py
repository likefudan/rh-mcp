"""Reviewed read manifest, digests, and fail-closed drift control (§6, §6.2).

This module is the security boundary. Robinhood advertises a single `internal`
OAuth scope, so the token is write-capable and read-only behaviour cannot be
inferred from it, from a tool name, or from an MCP annotation (§2). What makes
this gateway read-only is a human-reviewed, committed manifest plus the exact
digest comparisons implemented here. Every check below therefore fails closed:
the outcome of "I do not understand this" is always denial, never a default.

Two error codes are used, and the split is deliberate (§7.3, both exit 3):

* `configuration_error` — the manifest *source* is unusable as a source: the
  file is missing or unreadable, is not UTF-8, is too large or too deeply
  nested to decode safely, or is not a JSON object. Nothing can be said about
  a digest, so there is no readiness report to make. §9 also puts a missing or
  malformed `expected_manifest_digest` here, which `GatewayConfig` already
  enforces at construction.
* `not_ready` — the manifest decoded but fails the security contract:
  unsupported version, structural violation, self-inconsistent digest,
  duplicate entry, no reviewed read capabilities, or observed provider drift.

`GatewayError` is raised for local manifest faults because a manifest that
cannot be validated has no trustworthy digest to report. Once a manifest *is*
valid and self-consistent, a mismatch against the configured expected digest —
or drift in the observed provider surface — is reported as
`Readiness(ready=False)` with safe findings instead, which is what §7.1
requires the consumer to see.

Nothing here imports an MCP SDK. Discovery is reached only through the
`SurfaceDiscovery` protocol over the SDK-neutral `ObservedSurface`, so step 3
can supply a real transport without reopening this file.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, cast

from rh_mcp.canonical import (
    CANONICALIZATION_VERSION,
    DIGEST_ALGORITHM,
    DIGEST_PREFIX,
    canonical_digest,
    tool_metadata_digest,
    tool_schema_digest,
)
from rh_mcp.config import GatewayConfig
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.models import Readiness
from rh_mcp.schema import ensure_schema_supported, validate_instance
from rh_mcp.validation import (
    freeze_json,
    invalid,
    is_encodable,
    json_safe,
    require_digest,
    require_nonempty,
    require_utc_timestamp,
)

MANIFEST_FORMAT_VERSION: Final = "1.0"
SUPPORTED_MANIFEST_FORMAT_VERSIONS: Final[frozenset[str]] = frozenset({MANIFEST_FORMAT_VERSION})

# When to bump MANIFEST_FORMAT_VERSION — the rule, before there is a shipped
# manifest to get it wrong on.
#
# Bump it for any change that alters what `compute_full_manifest_digest` hashes
# or how: a new or removed document field, a change to entry ordering, a change
# to the digest's input construction. Do *not* bump it for a change confined to
# loader behaviour that leaves the hashed bytes identical.
#
# The reason is a diagnostic one, and it matters more than it looks. A manifest
# sealed under an older derivation does not announce itself as stale — it fails
# with "full_manifest_digest does not match the manifest contents", which is
# also exactly what a *tampered* manifest reports. An operator reading that
# message has one obvious remediation available: reseal the file. That is
# precisely the action §6 exists to defeat, and the fail-closed check would
# have handed them the motive to defeat it. A version mismatch reports itself
# as a version mismatch and points at a migration instead.
#
# CANONICALIZATION_VERSION is a different knob and moves for a different
# reason: it names the canonical form itself — how bytes are produced from a
# JSON value — and is published for non-Python implementers. Changing what gets
# fed into that form is a format change, not a canonicalization change.
#
# Known limitation of format 1.0, to revisit on the next bump. An entry stores
# `description` as a string and `annotations` as an object, so the format
# cannot represent the difference between a provider that *omitted* either
# field and one that sent `""` or `{}`. MCP makes both optional, so step 3's
# transport maps the absent form onto the empty one and a provider switching
# between those two spellings produces no digest change and no drift finding.
# The exposure is narrow — it is the fail-open direction, but only for a
# change that carries no meaning — and closing it means adding a
# null-vs-empty distinction to the entry schema, which is exactly the kind of
# change this bump rule exists to govern. **Step 6's manifest review must not
# assume a fidelity the format does not have**: if a reviewed tool's
# description or annotations matter, record them explicitly rather than
# relying on the digest to notice their disappearance.

# The self-referential field that is excluded from its own digest (§6).
FULL_MANIFEST_DIGEST_FIELD: Final = "full_manifest_digest"

# A committed manifest is a small reviewed document, not a payload. These
# bounds exist so a corrupted or hostile file cannot exhaust memory or blow
# the C stack inside `json.loads` before any validation runs. They are not §8
# network budgets and deliberately do not live in `ResourceLimits`.
MAX_MANIFEST_BYTES: Final = 4_194_304
MAX_MANIFEST_TEXT_DEPTH: Final = 32

_TOP_LEVEL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "manifest_format_version",
        "canonicalization_version",
        "digest_algorithm",
        "manifest_version",
        "provider_surface_digest",
        "observed_at",
        "reviewer",
        "entries",
        FULL_MANIFEST_DIGEST_FIELD,
    }
)
_ENTRY_FIELDS: Final[frozenset[str]] = frozenset(
    {
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
    }
)
_REVIEWER_REQUIRED_FIELDS: Final[frozenset[str]] = frozenset({"name", "reviewed_at"})
_REVIEWER_FIELDS: Final[frozenset[str]] = _REVIEWER_REQUIRED_FIELDS | {"reference"}

# A capability is a public identifier a consumer writes in its own source and
# that §7.1 may turn into a generated enum member. Keeping it to lowercase
# snake_case means every reviewed manifest can produce a valid Python
# identifier, and that no capability can be visually confused with another.
CAPABILITY_PATTERN: Final = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")

# Provider tool names are chosen by Robinhood, not by us, so this is a
# conservative shape rather than a naming policy: printable ASCII, no spaces.
# Anything outside it fails closed at discovery and goes to a human (§6.1)
# rather than being silently normalised into a name we then pin.
PROVIDER_TOOL_NAME_PATTERN: Final = re.compile(r"\A[\x21-\x7e]{1,128}\Z")

_MAX_MANIFEST_VERSION_LENGTH: Final = 64
_MAX_RATIONALE_LENGTH: Final = 4096

Disposition = Literal["read_allowed", "denied"]
_DISPOSITIONS: Final[frozenset[str]] = frozenset({"read_allowed", "denied"})

_LOCAL = ErrorCode.NOT_READY
_SOURCE = ErrorCode.CONFIGURATION_ERROR


# --------------------------------------------------------------------------
# Provider surface — the SDK-neutral seam step 3 fills in
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservedTool:
    """One tool as observed on the live provider surface.

    Deliberately SDK-neutral (§4): a transport converts whatever its MCP
    client returned into this shape, and nothing downstream ever sees an
    `mcp.*` type. Malformed values raise `protocol_error` because they are
    provider-derived (§7.3); `establish_readiness` turns that into a
    fail-closed `Readiness(ready=False)` rather than letting it escape.

    **Every observed field is a required keyword argument with no default**,
    for the same reason as `ObservedSurface.complete`. Each omission would be
    a positive security claim about the provider — "it declared no
    annotations", "no output schema", "an unconstrained input schema" — and
    the defaults would let a transport make all four by accident. The
    `annotations` case is the dangerous one: MCP's `annotations` is optional,
    so it is the most natural field to drop while writing the SDK mapping, and
    dropping it would record `{}` for every tool at discovery *and* at
    runtime. Both sides would agree forever, `metadata_digest_mismatch` could
    never fire, and every `readOnlyHint` in the surface would be silently
    unpinned — defeating §2's requirement that an annotation change surface as
    review evidence. A field that cannot be omitted cannot be omitted by
    accident.
    """

    name: str
    description: str = field(kw_only=True)
    input_schema: Mapping[str, Any] = field(kw_only=True)
    output_schema: Mapping[str, Any] | None = field(kw_only=True)
    annotations: Mapping[str, Any] = field(kw_only=True)
    schema_digest: str = field(init=False, default="")
    metadata_digest: str = field(init=False, default="")

    def __post_init__(self) -> None:
        code = ErrorCode.PROTOCOL_ERROR
        _require_tool_name("tool name", self.name, code)
        if not isinstance(self.description, str):
            invalid("tool description must be a string", code)
        input_schema = _require_json_object("tool input_schema", self.input_schema, code)
        output_schema = (
            None
            if self.output_schema is None
            else _require_json_object("tool output_schema", self.output_schema, code)
        )
        annotations = _require_json_object("tool annotations", self.annotations, code)

        object.__setattr__(self, "input_schema", input_schema)
        object.__setattr__(self, "output_schema", output_schema)
        object.__setattr__(self, "annotations", annotations)
        object.__setattr__(
            self,
            "schema_digest",
            tool_schema_digest(self.name, input_schema, output_schema, code=code),
        )
        object.__setattr__(
            self,
            "metadata_digest",
            tool_metadata_digest(self.description, annotations, code=code),
        )


@dataclass(frozen=True)
class ObservedSurface:
    """The complete tool surface a discovery run observed.

    `complete` is the seam for §6.2's pagination conditions. A transport that
    hit a page limit, saw a repeated cursor, or failed to terminate must
    either raise or pass `complete=False`; both make readiness false.

    It is a **required keyword argument with no default** on purpose. The
    obvious default is `True`, and that is exactly the wrong one: a step-3
    transport that forgot the field would silently assert it had enumerated
    the whole provider surface, which is the one claim this type exists to
    carry. Making it unrepresentable-by-omission costs one keyword at every
    construction site and removes a permissive fallback from the seam.

    `tools` has no default either, for the same reason: an omitted `tools` is
    the positive claim "the provider returned zero tools". An empty surface
    does fail closed today — every reviewed entry reports
    `missing_provider_tool` — but only because `entries` must be non-empty and
    contain at least one `read_allowed`. That is safety by accident, resting on
    a property of a different type, and it is the same reasoning eliminated for
    the digest tag below.

    Duplicate tool names are *not* rejected here. §6.2 requires a duplicate to
    be a fail-closed readiness condition, so it has to survive into the drift
    comparison where it is reported, rather than being deduplicated or raised
    away at construction.
    """

    tools: tuple[ObservedTool, ...]
    complete: bool = field(kw_only=True)

    def __post_init__(self) -> None:
        code = ErrorCode.PROTOCOL_ERROR
        if isinstance(self.tools, (str, bytes)) or not isinstance(self.tools, Iterable):
            invalid("tools must be a sequence of ObservedTool", code)
        tools = tuple(self.tools)
        for tool in tools:
            if not isinstance(tool, ObservedTool):
                invalid("tools must be a sequence of ObservedTool", code)
        if not isinstance(self.complete, bool):
            invalid("complete must be a bool", code)
        object.__setattr__(self, "tools", tools)


class SurfaceDiscovery(Protocol):
    """How readiness reaches the provider surface (§6.2).

    The only thing this module knows about a transport. Step 3 implements it
    over the private MCP SDK v2 session with bounded pagination; the offline
    suite implements it with synthetic fixtures. Because it is the *sole*
    route to the provider, "no read reaches a transport" is a property that
    can be proved by a test spy rather than argued.
    """

    async def discover(self) -> ObservedSurface: ...


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestEntry:
    """One reviewed tool, allowed or denied (§6).

    A `denied` entry may still declare the `capability` it would have been
    exposed as. That keeps the refusal explicit in the reviewed document and,
    more importantly, makes an allow/deny flip a pure `disposition` change
    that the full-manifest digest must catch on its own — rather than one that
    also happens to add or remove a capability field.
    """

    capability: str | None
    provider_tool_name: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    annotations: Mapping[str, Any]
    schema_digest: str
    metadata_digest: str
    disposition: Disposition
    rationale: str

    @property
    def read_allowed(self) -> bool:
        return self.disposition == "read_allowed"

    def recomputed_schema_digest(self) -> str:
        return tool_schema_digest(
            self.provider_tool_name, self.input_schema, self.output_schema, code=_LOCAL
        )

    def recomputed_metadata_digest(self) -> str:
        return tool_metadata_digest(self.description, self.annotations, code=_LOCAL)


@dataclass(frozen=True)
class ReviewedManifest:
    """A loaded, structurally validated, self-consistent manifest.

    `digest` is always the *locally recomputed* full-manifest digest, never
    the value read from the file (§7.1). `declared_digest` is kept only so a
    diagnostic can show both; the loader has already proved they are equal, so
    no decision is ever made from `declared_digest`.
    """

    manifest_format_version: str
    canonicalization_version: str
    digest_algorithm: str
    manifest_version: str
    provider_surface_digest: str
    observed_at: str
    reviewer: Mapping[str, Any]
    entries: tuple[ManifestEntry, ...]
    declared_digest: str
    digest: str

    @property
    def capabilities(self) -> Mapping[str, ManifestEntry]:
        """Every declared capability, including ones a review denied."""
        return MappingProxyType(
            {entry.capability: entry for entry in self.entries if entry.capability is not None}
        )

    @property
    def read_capabilities(self) -> tuple[str, ...]:
        """Capability identifiers a review marked `read_allowed`."""
        return tuple(
            sorted(
                entry.capability
                for entry in self.entries
                if entry.capability is not None and entry.read_allowed
            )
        )

    @property
    def provider_tool_names(self) -> frozenset[str]:
        return frozenset(entry.provider_tool_name for entry in self.entries)


# --------------------------------------------------------------------------
# Digest definitions
# --------------------------------------------------------------------------


def _surface_digest(
    records: Sequence[tuple[str, Any, Any, Any, Any]], code: ErrorCode
) -> str:
    """The one definition of the provider-surface digest (§6).

    Sorted by provider tool name so the digest describes the observed *set*
    and does not change when a provider re-orders its `tools/list` response —
    a re-order is not a security-relevant change, whereas every value inside
    each record is.

    The sort key is total on purpose. Duplicate names must not raise, because
    §6.2 needs a duplicate to survive into the drift comparison; and a
    non-string name must not raise either, because this can be reached with a
    name that has not been shape-checked yet. `sorted` comparing a `str` to a
    `None` would throw `TypeError` straight past the §7.3 error contract.
    """
    return canonical_digest(
        {
            "digest_kind": "provider_surface",
            "canonicalization": CANONICALIZATION_VERSION,
            "tools": [
                {
                    "provider_tool_name": name,
                    "description": description,
                    "input_schema": input_schema,
                    "output_schema": output_schema,
                    "annotations": annotations,
                }
                for name, description, input_schema, output_schema, annotations in sorted(
                    records, key=lambda record: _name_sort_key(record[0])
                )
            ],
        },
        code=code,
    )


def surface_digest_for_entries(entries: Iterable[ManifestEntry]) -> str:
    """The provider-surface digest implied by a manifest's reviewed entries."""
    return _surface_digest(
        [
            (
                entry.provider_tool_name,
                entry.description,
                entry.input_schema,
                entry.output_schema,
                entry.annotations,
            )
            for entry in entries
        ],
        _LOCAL,
    )


def provider_surface_digest(surface: ObservedSurface) -> str:
    """The provider-surface digest of a live observed surface."""
    return _surface_digest(
        [
            (
                tool.name,
                tool.description,
                tool.input_schema,
                tool.output_schema,
                tool.annotations,
            )
            for tool in surface.tools
        ],
        ErrorCode.PROTOCOL_ERROR,
    )


def compute_full_manifest_digest(document: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical form of everything but the digest field (§6).

    `entries` is sorted into canonical order (by provider tool name) before
    hashing so the digest is a function of the reviewed content and not of the
    order a file happens to list it in. The loader separately *requires* the
    committed file to already be in that order, so what a human reviews and
    what gets hashed are the same sequence.

    Like the schema and metadata digests, the hashed input is tagged with its
    `digest_kind` and the canonicalization version. Without the tag this digest
    was distinct from the others only because manifest documents happen not to
    share a key set with them — an accident nothing enforced, and one a later
    field addition could quietly undo. The manifest is nested under its own key
    so the tag can never collide with a document field.
    """
    payload = {key: value for key, value in document.items() if key != FULL_MANIFEST_DIGEST_FIELD}
    entries = payload.get("entries")
    if isinstance(entries, (list, tuple)):
        payload["entries"] = tuple(
            sorted(entries, key=lambda entry: _entry_sort_key(entry))
        )
    return canonical_digest(
        {
            "digest_kind": "full_manifest",
            "canonicalization": CANONICALIZATION_VERSION,
            "manifest": payload,
        },
        code=_LOCAL,
    )


def _name_sort_key(name: Any) -> str:
    """A total ordering key. A non-string name is rejected by validation; this
    only has to keep the digest computation itself from raising."""
    return name if isinstance(name, str) else ""


def _entry_sort_key(entry: Any) -> str:
    if isinstance(entry, Mapping):
        return _name_sort_key(entry.get("provider_tool_name"))
    return ""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def _require_json_object(name: str, value: Any, code: ErrorCode) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        invalid(f"{name} must be a JSON object, got {type(value).__name__}", code)
    # `freeze_json` returns a `MappingProxyType` for any `Mapping` input, so
    # this cast restates what the branch above already established.
    return cast(Mapping[str, Any], freeze_json(value, code, label=name))


def _require_tool_name(name: str, value: Any, code: ErrorCode) -> None:
    if not isinstance(value, str) or not PROVIDER_TOOL_NAME_PATTERN.fullmatch(value):
        invalid(
            f"{name} must be 1-128 printable ASCII characters with no spaces",
            code,
        )


def _exceeds_text_depth(text: str, limit: int) -> bool:
    """Whether the JSON *text* nests deeper than `limit`.

    Checked before `json.loads`, because the decoder recurses and a few
    hundred thousand opening brackets crash the interpreter with a
    `RecursionError` that no `except ValueError` catches. String contents are
    skipped so a bracket inside a description cannot inflate the count.
    """
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > limit:
                return True
        elif character in "]}":
            depth -= 1
    return False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a JSON object that names the same key twice.

    `json.loads` silently keeps the last occurrence. In a document whose whole
    purpose is human review that is a fail-open: a reviewer reads
    `"disposition": "denied"` on line 20 while the loader uses
    `"disposition": "read_allowed"` from line 40. The full-manifest digest
    would cover only the surviving value, so pinning would not catch it either.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            invalid(f"manifest JSON names the key {key!r} twice in one object", _SOURCE)
        seen[key] = value
    return seen


def _reject_json_constant(name: str) -> Any:
    invalid(f"manifest JSON may not contain the non-standard literal {name}", _SOURCE)


def load_manifest_text(text: str) -> ReviewedManifest:
    """Decode and fully validate a manifest document.

    Raises `GatewayError` and never returns a partially trusted object: there
    is no "manifest with warnings" state, because a caller holding one would
    have to decide whether to proceed, and that decision is exactly what this
    package exists to take away.
    """
    if not isinstance(text, str):
        invalid("manifest text must be a string", _SOURCE)
    if not is_encodable(text):
        invalid("manifest text must be encodable as UTF-8", _SOURCE)
    if len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        invalid(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes", _SOURCE)
    if _exceeds_text_depth(text, MAX_MANIFEST_TEXT_DEPTH):
        invalid(f"manifest JSON nests deeper than {MAX_MANIFEST_TEXT_DEPTH} levels", _SOURCE)
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError:
        # The decoder's message quotes the offending text; §7.3 keeps document
        # content out of public errors, so the context is dropped.
        raise GatewayError(_SOURCE, "manifest is not valid JSON") from None
    if not isinstance(decoded, Mapping):
        invalid("manifest must be a JSON object", _SOURCE)
    return _validate_document(decoded)


def load_manifest_file(path: Path | str) -> ReviewedManifest:
    """Read and validate a manifest file."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError:
        raise GatewayError(_SOURCE, "manifest file could not be read") from None
    if len(raw) > MAX_MANIFEST_BYTES:
        invalid(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes", _SOURCE)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise GatewayError(_SOURCE, "manifest file is not valid UTF-8") from None
    return load_manifest_text(text)


PACKAGED_MANIFEST_PATH: Final = Path(__file__).parent / "manifests" / "read-manifest.json"


def load_active_manifest() -> ReviewedManifest:
    """Load the manifest committed to the installed package (§9).

    No production manifest exists yet: DESIGN.md §13 requires owner-assisted
    authenticated discovery and human review before one can be committed. This
    raises rather than falling back to an empty or permissive default, so a
    gateway built on an unfinished install cannot become ready.
    """
    if not PACKAGED_MANIFEST_PATH.is_file():
        invalid(
            "this release ships no reviewed read manifest; authenticated discovery and "
            "human review (DESIGN.md §6.1, §13) must produce one before the gateway can "
            "become ready",
            _SOURCE,
        )
    return load_manifest_file(PACKAGED_MANIFEST_PATH)


def _validate_document(decoded: Mapping[str, Any]) -> ReviewedManifest:
    document = _require_json_object("manifest", decoded, _LOCAL)

    unknown = sorted(set(document) - _TOP_LEVEL_FIELDS)
    if unknown:
        invalid(f"manifest has unsupported field(s) {unknown}", _LOCAL)
    missing = sorted(_TOP_LEVEL_FIELDS - set(document))
    if missing:
        invalid(f"manifest is missing required field(s) {missing}", _LOCAL)

    format_version = document["manifest_format_version"]
    if format_version not in SUPPORTED_MANIFEST_FORMAT_VERSIONS:
        invalid(
            "manifest_format_version "
            f"{format_version!r} is not one of {sorted(SUPPORTED_MANIFEST_FORMAT_VERSIONS)}",
            _LOCAL,
        )
    canonicalization = document["canonicalization_version"]
    if canonicalization != CANONICALIZATION_VERSION:
        invalid(
            f"canonicalization_version must be {CANONICALIZATION_VERSION!r}, "
            f"got {canonicalization!r}",
            _LOCAL,
        )
    algorithm = document["digest_algorithm"]
    if algorithm != DIGEST_ALGORITHM:
        invalid(f"digest_algorithm must be {DIGEST_ALGORITHM!r}, got {algorithm!r}", _LOCAL)

    manifest_version = document["manifest_version"]
    require_nonempty("manifest_version", manifest_version, _LOCAL)
    if len(manifest_version) > _MAX_MANIFEST_VERSION_LENGTH or not manifest_version.isprintable():
        invalid(
            f"manifest_version must be at most {_MAX_MANIFEST_VERSION_LENGTH} printable "
            "characters",
            _LOCAL,
        )

    require_digest("provider_surface_digest", document["provider_surface_digest"], _LOCAL)
    require_utc_timestamp("observed_at", document["observed_at"], _LOCAL)
    require_digest(FULL_MANIFEST_DIGEST_FIELD, document[FULL_MANIFEST_DIGEST_FIELD], _LOCAL)

    reviewer = _validate_reviewer(document["reviewer"])
    entries = _validate_entries(document["entries"])

    declared_surface_digest = document["provider_surface_digest"]
    recomputed_surface_digest = surface_digest_for_entries(entries)
    if declared_surface_digest != recomputed_surface_digest:
        invalid(
            "provider_surface_digest does not match the reviewed entries "
            f"(declared {declared_surface_digest}, recomputed {recomputed_surface_digest})",
            _LOCAL,
        )

    declared_digest = document[FULL_MANIFEST_DIGEST_FIELD]
    recomputed_digest = compute_full_manifest_digest(document)
    if declared_digest != recomputed_digest:
        invalid(
            "full_manifest_digest does not match the manifest contents "
            f"(declared {declared_digest}, recomputed {recomputed_digest})",
            _LOCAL,
        )

    if not any(entry.read_allowed for entry in entries):
        invalid("manifest contains no reviewed read capabilities", _LOCAL)

    return ReviewedManifest(
        manifest_format_version=format_version,
        canonicalization_version=canonicalization,
        digest_algorithm=algorithm,
        manifest_version=manifest_version,
        provider_surface_digest=declared_surface_digest,
        observed_at=document["observed_at"],
        reviewer=reviewer,
        entries=entries,
        declared_digest=declared_digest,
        digest=recomputed_digest,
    )


def _validate_reviewer(value: Any) -> Mapping[str, Any]:
    reviewer = _require_json_object("reviewer", value, _LOCAL)
    unknown = sorted(set(reviewer) - _REVIEWER_FIELDS)
    if unknown:
        invalid(f"reviewer has unsupported field(s) {unknown}", _LOCAL)
    missing = sorted(_REVIEWER_REQUIRED_FIELDS - set(reviewer))
    if missing:
        invalid(f"reviewer is missing required field(s) {missing}", _LOCAL)
    require_nonempty("reviewer.name", reviewer["name"], _LOCAL)
    require_utc_timestamp("reviewer.reviewed_at", reviewer["reviewed_at"], _LOCAL)
    if "reference" in reviewer:
        require_nonempty("reviewer.reference", reviewer["reference"], _LOCAL)
    return reviewer


def _validate_entries(value: Any) -> tuple[ManifestEntry, ...]:
    if not isinstance(value, (list, tuple)):
        invalid("entries must be a JSON array", _LOCAL)
    if not value:
        invalid("entries must not be empty", _LOCAL)

    entries = tuple(_validate_entry(index, item) for index, item in enumerate(value))

    names = [entry.provider_tool_name for entry in entries]
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    if duplicate_names:
        invalid(f"entries name the same provider tool more than once: {duplicate_names}", _LOCAL)

    capabilities = [entry.capability for entry in entries if entry.capability is not None]
    duplicate_capabilities = sorted(
        {name for name in capabilities if capabilities.count(name) > 1}
    )
    if duplicate_capabilities:
        invalid(f"entries declare the same capability more than once: {duplicate_capabilities}",
                _LOCAL)

    if names != sorted(names):
        invalid(
            "entries must be in canonical order, sorted by provider_tool_name, so the "
            "reviewed sequence and the hashed sequence are the same",
            _LOCAL,
        )
    return entries


def _validate_entry(index: int, value: Any) -> ManifestEntry:
    entry = _require_json_object(f"entries[{index}]", value, _LOCAL)
    unknown = sorted(set(entry) - _ENTRY_FIELDS)
    if unknown:
        invalid(f"entries[{index}] has unsupported field(s) {unknown}", _LOCAL)
    missing = sorted(_ENTRY_FIELDS - set(entry))
    if missing:
        invalid(f"entries[{index}] is missing required field(s) {missing}", _LOCAL)

    capability = entry["capability"]
    if capability is not None:
        if not isinstance(capability, str) or not CAPABILITY_PATTERN.fullmatch(capability):
            invalid(
                f"entries[{index}].capability must be null or lowercase snake_case "
                "starting with a letter",
                _LOCAL,
            )

    _require_tool_name(f"entries[{index}].provider_tool_name", entry["provider_tool_name"], _LOCAL)

    description = entry["description"]
    if not isinstance(description, str):
        invalid(f"entries[{index}].description must be a string", _LOCAL)

    input_schema = _require_json_object(f"entries[{index}].input_schema", entry["input_schema"],
                                        _LOCAL)
    # An empty schema constrains nothing, so it would make step 5's argument
    # validation vacuous for this entry — a reviewed capability whose input is
    # in practice unvalidated. A tool that genuinely takes no arguments still
    # says so, as `{"type": "object", "properties": {}}`.
    if not input_schema:
        invalid(
            f"entries[{index}].input_schema must not be empty: an empty schema "
            "constrains nothing and would leave arguments unvalidated",
            _LOCAL,
        )
    raw_output_schema = entry["output_schema"]
    output_schema = (
        None
        if raw_output_schema is None
        else _require_json_object(f"entries[{index}].output_schema", raw_output_schema, _LOCAL)
    )
    # Same rule as input_schema, for symmetry: a declared-but-empty output
    # schema constrains nothing, so §7.1's "checked against the pinned output
    # schema when one exists" would silently check nothing. A tool with no
    # output schema says so with null, not with {}.
    if output_schema is not None and not output_schema:
        invalid(
            f"entries[{index}].output_schema must not be empty: use null to declare "
            "that the tool supplies no output schema",
            _LOCAL,
        )

    annotations = _require_json_object(f"entries[{index}].annotations", entry["annotations"],
                                       _LOCAL)

    disposition = entry["disposition"]
    if disposition not in _DISPOSITIONS:
        invalid(
            f"entries[{index}].disposition must be one of {sorted(_DISPOSITIONS)}, "
            f"got {disposition!r}",
            _LOCAL,
        )

    # Refuse a schema this package cannot enforce, at *load* time. Deferring it
    # to the first call that happens to exercise the unsupported keyword would
    # mean a gateway that became ready while holding a pinned constraint nothing
    # checks — a reviewed capability whose input is in practice unvalidated,
    # which is the failure §6.2 exists to prevent. `not_ready` is the right
    # code: the manifest decoded fine, it just fails the contract.
    #
    # Only for an entry a read may actually use. A *denied* entry's schema is
    # never validated against and never sent, so refusing the whole manifest
    # because an unreviewed tool advertises `$ref` would make one unenforceable
    # keyword anywhere in the provider surface permanently un-loadable — the
    # likely outcome of the first real `admin discover`, and a fail-closed
    # check with no remediation short of the provider changing its schema.
    if disposition == "read_allowed":
        ensure_schema_supported(input_schema, _LOCAL, path=f"entries[{index}].input_schema")
        if output_schema is not None:
            ensure_schema_supported(
                output_schema, _LOCAL, path=f"entries[{index}].output_schema"
            )

    rationale = entry["rationale"]
    require_nonempty(f"entries[{index}].rationale", rationale, _LOCAL)
    if len(rationale) > _MAX_RATIONALE_LENGTH:
        invalid(
            f"entries[{index}].rationale must be at most {_MAX_RATIONALE_LENGTH} characters",
            _LOCAL,
        )

    require_digest(f"entries[{index}].schema_digest", entry["schema_digest"], _LOCAL)
    require_digest(f"entries[{index}].metadata_digest", entry["metadata_digest"], _LOCAL)

    built = ManifestEntry(
        capability=capability,
        provider_tool_name=entry["provider_tool_name"],
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        schema_digest=entry["schema_digest"],
        metadata_digest=entry["metadata_digest"],
        disposition=disposition,
        rationale=rationale,
    )

    # The per-tool digests are recomputed from the entry's own content rather
    # than trusted. A stored digest that does not describe the schema stored
    # beside it is the single most dangerous state this file can be in: the
    # gateway would pin one thing and validate against another.
    recomputed_schema = built.recomputed_schema_digest()
    if built.schema_digest != recomputed_schema:
        invalid(
            f"entries[{index}].schema_digest does not match its own schemas "
            f"(declared {built.schema_digest}, recomputed {recomputed_schema})",
            _LOCAL,
        )
    recomputed_metadata = built.recomputed_metadata_digest()
    if built.metadata_digest != recomputed_metadata:
        invalid(
            f"entries[{index}].metadata_digest does not match its own description and "
            f"annotations (declared {built.metadata_digest}, recomputed {recomputed_metadata})",
            _LOCAL,
        )
    return built


# --------------------------------------------------------------------------
# Drift findings and readiness
# --------------------------------------------------------------------------


class DriftReason(StrEnum):
    """Why readiness failed. Diagnostic detail, not part of §7.3's nine codes."""

    EXPECTED_DIGEST_MISMATCH = "expected_digest_mismatch"
    DISCOVERY_FAILED = "discovery_failed"
    INCOMPLETE_DISCOVERY = "incomplete_discovery"
    DUPLICATE_PROVIDER_TOOL = "duplicate_provider_tool"
    UNKNOWN_PROVIDER_TOOL = "unknown_provider_tool"
    MISSING_PROVIDER_TOOL = "missing_provider_tool"
    SCHEMA_DIGEST_MISMATCH = "schema_digest_mismatch"
    METADATA_DIGEST_MISMATCH = "metadata_digest_mismatch"
    PROVIDER_SURFACE_DIGEST_MISMATCH = "provider_surface_digest_mismatch"


@dataclass(frozen=True)
class DriftFinding:
    """One safe, structured reason readiness failed.

    `detail` carries digests, counts, and the names of tools that are already
    in the committed manifest — all of which are in the repository and in the
    §8 list of things logs may contain. It never carries a description, a
    schema, a payload, or the name of an *unreviewed* provider tool: that name
    is `tools/list` response data, and §8 keeps response data out of logs. An
    unreviewed tool is identified by a short digest of its name instead, which
    is enough to correlate with `rh-mcp admin discover` output — the reviewed
    place to see the real thing (§6.1).

    `error_code` carries the originating `ErrorCode` when this finding stands
    in for a raised `GatewayError`. It is a **structured field, not prose**:
    step 5 has to map `auth_required` onto exit 4, and recovering that by
    parsing an English sentence would be neither reliable nor stable. The
    message that accompanied the error is deliberately *not* carried — it is
    provider-derived text, §7.3 forbids it in public output, and it has been
    observed to contain an account identifier.
    """

    reason: DriftReason
    detail: str
    error_code: ErrorCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, DriftReason):
            invalid("reason must be a DriftReason", _LOCAL)
        require_nonempty("detail", self.detail, _LOCAL)
        if self.error_code is not None and not isinstance(self.error_code, ErrorCode):
            invalid("error_code must be an ErrorCode", _LOCAL)

    def to_json_dict(self) -> dict[str, Any]:
        # `error_code` is always present, `null` when there was no originating
        # error: a conditional key would make step 5 branch on key existence
        # rather than on a value, and a stable shape is cheaper to consume.
        return {
            "reason": str(self.reason),
            "detail": self.detail,
            "error_code": None if self.error_code is None else str(self.error_code),
        }


@dataclass(frozen=True)
class ReadinessAssessment:
    """A `Readiness` plus the safe findings explaining it (§7.1)."""

    readiness: Readiness
    findings: tuple[DriftFinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.readiness, Readiness):
            invalid("readiness must be a Readiness", _LOCAL)
        findings = tuple(self.findings)
        for finding in findings:
            if not isinstance(finding, DriftFinding):
                invalid("findings must be DriftFinding instances", _LOCAL)
        if self.readiness.ready and findings:
            invalid("a ready assessment cannot carry drift findings", _LOCAL)
        if not self.readiness.ready and not findings:
            invalid("a not-ready assessment must say why", _LOCAL)
        object.__setattr__(self, "findings", findings)

    @property
    def ready(self) -> bool:
        return self.readiness.ready

    @property
    def manifest_digest(self) -> str:
        """The locally recomputed full-manifest digest this describes (§7.1)."""
        return self.readiness.manifest_digest

    def to_json_dict(self) -> dict[str, Any]:
        payload = self.readiness.to_json_dict()
        payload["findings"] = [finding.to_json_dict() for finding in self.findings]
        return payload


_UNREVIEWED_LABEL_LENGTH: Final = 16


def _safe_tool_label(name: str, reviewed: Collection[str]) -> str:
    """A loggable identifier for a tool name (see `DriftFinding`)."""
    if name in reviewed:
        return name
    digest = canonical_digest(name, code=ErrorCode.PROTOCOL_ERROR)
    return f"<unreviewed:{digest[len(DIGEST_PREFIX):][:_UNREVIEWED_LABEL_LENGTH]}>"


def assess_surface(
    manifest: ReviewedManifest, surface: ObservedSurface
) -> tuple[DriftFinding, ...]:
    """Every §6.2 difference between the reviewed manifest and what was observed.

    All checks run and every finding is collected rather than returning on the
    first one: an operator fixing drift needs the whole picture, and a partial
    list invites the "fix one, rerun, fix one" loop that ends in someone
    disabling the check. Any non-empty result means not ready.
    """
    findings: list[DriftFinding] = []
    reviewed = manifest.provider_tool_names

    if not surface.complete:
        findings.append(
            DriftFinding(
                DriftReason.INCOMPLETE_DISCOVERY,
                "the provider surface was not fully enumerated, so an unreviewed tool "
                "may exist outside it",
            )
        )

    observed_names = [tool.name for tool in surface.tools]
    duplicates = sorted({name for name in observed_names if observed_names.count(name) > 1})
    for name in duplicates:
        findings.append(
            DriftFinding(
                DriftReason.DUPLICATE_PROVIDER_TOOL,
                f"the provider offered {_safe_tool_label(name, reviewed)} more than once, "
                "so which schema a call would reach is undefined",
            )
        )

    by_name: dict[str, ObservedTool] = {}
    for tool in surface.tools:
        by_name.setdefault(tool.name, tool)

    unknown = sorted(set(by_name) - reviewed)
    for name in unknown:
        findings.append(
            DriftFinding(
                DriftReason.UNKNOWN_PROVIDER_TOOL,
                f"the provider offers {_safe_tool_label(name, reviewed)}, which no reviewed "
                "manifest entry covers",
            )
        )

    for name in sorted(reviewed - set(by_name)):
        findings.append(
            DriftFinding(
                DriftReason.MISSING_PROVIDER_TOOL,
                f"reviewed tool {name} is absent from the provider surface",
            )
        )

    for entry in manifest.entries:
        observed = by_name.get(entry.provider_tool_name)
        if observed is None:
            continue
        if observed.schema_digest != entry.schema_digest:
            findings.append(
                DriftFinding(
                    DriftReason.SCHEMA_DIGEST_MISMATCH,
                    f"{entry.provider_tool_name} schema digest is {observed.schema_digest}, "
                    f"reviewed as {entry.schema_digest}",
                )
            )
        if observed.metadata_digest != entry.metadata_digest:
            findings.append(
                DriftFinding(
                    DriftReason.METADATA_DIGEST_MISMATCH,
                    f"{entry.provider_tool_name} metadata digest is {observed.metadata_digest}, "
                    f"reviewed as {entry.metadata_digest}",
                )
            )

    observed_surface_digest = provider_surface_digest(surface)
    if observed_surface_digest != manifest.provider_surface_digest:
        findings.append(
            DriftFinding(
                DriftReason.PROVIDER_SURFACE_DIGEST_MISMATCH,
                f"observed provider surface digest is {observed_surface_digest}, "
                f"reviewed as {manifest.provider_surface_digest}",
            )
        )

    return tuple(findings)


async def establish_readiness(
    config: GatewayConfig,
    manifest: ReviewedManifest,
    discovery: SurfaceDiscovery,
) -> ReadinessAssessment:
    """Decide whether the gateway may serve reads (§6.2).

    The order is the security property, not an optimisation: the locally
    recomputed full-manifest digest is compared with the configured expected
    digest **before** `discovery.discover()` is awaited. A consumer whose pin
    does not match the installed manifest therefore never opens a session
    against Robinhood at all. The expected value is read only from
    `GatewayConfig`, which validated its shape at construction (§9); it is
    never taken from the manifest, from a provider response, or from an
    argument to this function.
    """
    expected = config.expected_manifest_digest

    def readiness_for(ready: bool) -> Readiness:
        return Readiness(
            ready=ready,
            manifest_version=manifest.manifest_version,
            manifest_digest=manifest.digest,
            expected_manifest_digest=expected,
        )

    if manifest.digest != expected:
        return ReadinessAssessment(
            readiness=readiness_for(False),
            findings=(
                DriftFinding(
                    DriftReason.EXPECTED_DIGEST_MISMATCH,
                    f"the active manifest digest is {manifest.digest}, but this deployment "
                    f"pinned {expected}; a new manifest must be accepted deliberately",
                ),
            ),
        )

    try:
        surface = await discovery.discover()
    except GatewayError as error:
        # Any provider-side failure leaves the surface unknown, and an unknown
        # surface is indistinguishable from a drifted one. The originating
        # code is preserved in the detail so step 5 can still map, say, an
        # `auth_required` to exit 4 without this layer special-casing it.
        return ReadinessAssessment(
            readiness=readiness_for(False),
            findings=(
                # The error's message is dropped, not reformatted: it is
                # provider-derived and has been observed carrying an account
                # identifier into this consumer-visible JSON (§7.3). The code
                # survives as a structured field so step 5 can map
                # `auth_required` onto exit 4 without parsing prose.
                DriftFinding(
                    DriftReason.DISCOVERY_FAILED,
                    "provider discovery failed",
                    error_code=error.code,
                ),
            ),
        )

    findings = assess_surface(manifest, surface)
    return ReadinessAssessment(readiness=readiness_for(not findings), findings=findings)


# --------------------------------------------------------------------------
# Per-call preflight
# --------------------------------------------------------------------------


def preflight_read(
    manifest: ReviewedManifest,
    assessment: ReadinessAssessment,
    capability: object,
    arguments: Mapping[str, Any],
) -> ManifestEntry:
    """Resolve a capability and validate its arguments, as one event (§6.2).

    Returns the pinned entry only when the gateway is ready, the assessment
    describes *this* manifest, the capability is declared, its review
    disposition is `read_allowed`, its stored digests still match its own
    stored schemas and metadata, **and `arguments` validates against the
    pinned input schema**.

    An unknown capability and a denied one produce the identical error, so the
    failure never discloses whether a name exists in the manifest.

    `arguments` is required rather than optional, and validation happens here
    rather than in a separate function, because "resolved an entry" and
    "validated the input" have to be the same event: a second call is one a
    caller can forget, and a returned entry would then read as permission to
    send whatever they liked. §6.2 orders it this way — validate against the
    pinned schema, *and only then* call the transport.

    The validator is this package's strict subset, not `jsonschema`, which
    ignores keywords it does not recognise — default-allow on precisely the
    axis this package is default-deny. Unsupported keywords are refused at
    manifest *load* time (see `_validate_entry_schemas`), so an unenforceable
    schema fails closed before readiness rather than at the first call that
    happens to exercise the keyword.
    """
    if not assessment.ready:
        invalid("the gateway is not ready, so no read may be sent", _LOCAL)
    if assessment.manifest_digest != manifest.digest:
        invalid(
            "the readiness assessment describes a different manifest than the one being "
            "used to resolve this capability",
            _LOCAL,
        )

    entry = manifest.capabilities.get(capability) if isinstance(capability, str) else None
    if entry is None or not entry.read_allowed:
        invalid(
            "capability is not a reviewed read capability of the active manifest",
            ErrorCode.CAPABILITY_DENIED,
        )

    if entry.schema_digest != entry.recomputed_schema_digest():
        invalid("the pinned schema digest no longer matches the pinned schema", _LOCAL)
    if entry.metadata_digest != entry.recomputed_metadata_digest():
        invalid("the pinned metadata digest no longer matches the pinned metadata", _LOCAL)

    if not isinstance(arguments, Mapping):
        invalid("arguments must be a JSON object", ErrorCode.INPUT_INVALID)
    safe_arguments = json_safe(arguments)
    validate_instance(
        safe_arguments,
        entry.input_schema,
        code=ErrorCode.INPUT_INVALID,
        schema_code=_LOCAL,
        label="arguments",
    )
    _refuse_undeclared_arguments(entry, safe_arguments)
    return entry


def _refuse_undeclared_arguments(entry: ManifestEntry, arguments: Mapping[str, Any]) -> None:
    """Allow only argument names the pinned schema actually declares.

    Schema validation alone is not enough here, and the gap is not theoretical.
    JSON Schema is permissive by default: unless a schema says
    `additionalProperties: false`, any extra property validates. So a reviewed
    capability whose provider schema omits that keyword would forward
    caller-chosen keys verbatim to a **write-capable** tool — `side`,
    `quantity`, `account_id` — and every check above would pass.

    The manifest reviewer cannot close this. Adding `additionalProperties:
    false` to the entry changes its `schema_digest`, which then disagrees with
    the schema the provider actually advertises, and the gateway never becomes
    ready. Whatever Robinhood ships is the ceiling on what the pinned schema
    can say, so the tightening has to happen here.

    Hence default-deny on argument *names*, independent of what the schema says
    about additional properties: a name that is not a declared property is
    refused. A schema declaring no properties therefore accepts no arguments,
    which is the fail-closed reading of "this tool takes nothing".
    """
    _refuse_undeclared(arguments, entry.input_schema, path="arguments")


def _declared_names(schema: Any) -> frozenset[str]:
    """Property names a schema declares, including through combinators.

    `allOf`/`anyOf`/`oneOf` are how a schema most naturally says "an object
    shaped like one of these", and their branches declare properties just as
    the root can. Ignoring them would load, become ready, and then refuse every
    argument set including the legal one — the same defect class as refusing a
    denied entry's schema, surfaced at first call instead of at load.
    """
    if not isinstance(schema, Mapping):
        return frozenset()
    names: set[str] = set()
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        names.update(k for k in properties if isinstance(k, str))
    for combinator in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, Sequence) and not isinstance(branches, (str, bytes)):
            for branch in branches:
                names |= _declared_names(branch)
    return frozenset(names)


def _subschema_for(schema: Any, name: str) -> Any:
    """The schema governing property `name`, searched through combinators."""
    if not isinstance(schema, Mapping):
        return None
    properties = schema.get("properties")
    if isinstance(properties, Mapping) and name in properties:
        return properties[name]
    for combinator in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, Sequence) and not isinstance(branches, (str, bytes)):
            for branch in branches:
                found = _subschema_for(branch, name)
                if found is not None:
                    return found
    return None


def _refuse_undeclared(value: Any, schema: Any, *, path: str) -> None:
    """Walk the payload, refusing any object key the schema does not declare.

    Enforced at **every** depth, not just the root. The first version of this
    check looked only at the top level, and a hostile payload simply moved one
    level down: a declared object with no properties of its own accepted
    `{"side": "sell", "quantity": 100}` wholesale. Objects inside an array are
    the same hole and the more likely one, since a batch or filter argument is
    exactly where they appear.

    `items` and `additionalProperties`-as-schema are followed too, so a
    declared container cannot become an unchecked bag.
    """
    if isinstance(value, Mapping):
        allowed = _declared_names(schema)
        # Keys are compared and reported as text: a non-string key cannot be
        # a declared property, and sorting a mixed-type set raises TypeError.
        present = {key if isinstance(key, str) else repr(key) for key in value}
        undeclared = sorted(present - allowed)
        if undeclared:
            # The names came from the caller, not the provider, so echoing them
            # is safe and is the only useful thing this error can say (§7.3).
            invalid(
                f"{path} contains name(s) {undeclared} that the pinned input schema does "
                "not declare; only reviewed argument names may be sent",
                ErrorCode.INPUT_INVALID,
            )
        for key, item in value.items():
            _refuse_undeclared(item, _subschema_for(schema, key), path=f"{path}.{key}")
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        items = schema.get("items") if isinstance(schema, Mapping) else None
        for index, item in enumerate(value):
            _refuse_undeclared(item, items, path=f"{path}[{index}]")


def manifest_to_json_dict(manifest: ReviewedManifest) -> dict[str, Any]:
    """Render a loaded manifest back into its JSON document form.

    Used by the fixtures and by `admin discover` in step 6 to prove a
    round-trip is digest-stable.
    """
    return {
        "manifest_format_version": manifest.manifest_format_version,
        "canonicalization_version": manifest.canonicalization_version,
        "digest_algorithm": manifest.digest_algorithm,
        "manifest_version": manifest.manifest_version,
        "provider_surface_digest": manifest.provider_surface_digest,
        "observed_at": manifest.observed_at,
        "reviewer": json_safe(manifest.reviewer),
        "entries": [
            {
                "capability": entry.capability,
                "provider_tool_name": entry.provider_tool_name,
                "description": entry.description,
                "input_schema": json_safe(entry.input_schema),
                "output_schema": (
                    None if entry.output_schema is None else json_safe(entry.output_schema)
                ),
                "annotations": json_safe(entry.annotations),
                "schema_digest": entry.schema_digest,
                "metadata_digest": entry.metadata_digest,
                "disposition": entry.disposition,
                "rationale": entry.rationale,
            }
            for entry in manifest.entries
        ],
        FULL_MANIFEST_DIGEST_FIELD: manifest.digest,
    }


__all__ = [
    "CAPABILITY_PATTERN",
    "FULL_MANIFEST_DIGEST_FIELD",
    "MANIFEST_FORMAT_VERSION",
    "MAX_MANIFEST_BYTES",
    "MAX_MANIFEST_TEXT_DEPTH",
    "PACKAGED_MANIFEST_PATH",
    "PROVIDER_TOOL_NAME_PATTERN",
    "SUPPORTED_MANIFEST_FORMAT_VERSIONS",
    "Disposition",
    "DriftFinding",
    "DriftReason",
    "ManifestEntry",
    "ObservedSurface",
    "ObservedTool",
    "ReadinessAssessment",
    "ReviewedManifest",
    "SurfaceDiscovery",
    "assess_surface",
    "compute_full_manifest_digest",
    "establish_readiness",

    "load_active_manifest",
    "load_manifest_file",
    "load_manifest_text",
    "manifest_to_json_dict",
    "preflight_read",
    "provider_surface_digest",
    "surface_digest_for_entries",
]
