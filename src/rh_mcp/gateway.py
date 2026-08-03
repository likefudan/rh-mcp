"""The public read gateway (§7.1).

This module is mostly composition, and the composition *is* the security
property. Four steps of enforcement live below it — a reviewed manifest with
canonical digests, a bounded transport, pinned egress, a credential store —
and each is only load-bearing if it sits in the right order relative to the
others. The orders that matter here:

* Readiness is established **before** any read is possible, and a read is
  refused unless the assessment it is checked against describes the same
  manifest the entry came from.
* `preflight_read` resolves the capability *and* validates the arguments in
  one call, so a caller cannot hold a pinned entry it has not earned — and it
  hands back the frozen arguments it validated, so the value that reaches the
  transport is the value that was checked rather than one that merely tested
  clean a moment earlier.
* Only after both does anything reach the transport's `call_tool`.

What this module must never do is give a caller a way around that order. No
public surface exposes an MCP session, a raw provider result, a provider tool
name, or a generic `call_tool` (§1, §2) — a gateway that could be asked for an
arbitrary tool would be a gateway whose manifest is advisory.

`AdminDiscoveryContext` is the deliberate exception, and it is exceptional in
the safe direction: it can observe the provider surface but has no manifest,
cannot become ready, and has no `read` at all.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from rh_mcp.canonical import canonical_digest
from rh_mcp.config import GatewayConfig
from rh_mcp.credentials import CredentialStore, open_credential_store
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.manifest import (
    ManifestEntry,
    ObservedSurface,
    PreflightResult,
    ReadinessAssessment,
    ReviewedManifest,
    establish_readiness,
    load_active_manifest,
    preflight_read,
)
from rh_mcp.models import ResultEnvelope
from rh_mcp.transport import ProviderTransport, _open_provider_session
from rh_mcp.validation import invalid, json_safe

_LOCAL: Final = ErrorCode.NOT_READY


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _result_digest(data: Mapping[str, Any]) -> str:
    """The canonical digest §7.1 requires, computed before the envelope exists.

    Taken over the frozen payload the envelope will carry, so what a consumer
    verifies is what a consumer received.
    """
    return canonical_digest(json_safe(data), code=ErrorCode.PROTOCOL_ERROR)


def _raise_originating_error(assessment: ReadinessAssessment) -> None:
    """Surface the code that actually caused a not-ready assessment.

    §5.1 is about *all* read operations: "if login is required they fail with
    the stable `auth_required` error and direct a human to `rh-mcp login`."
    Reporting an expired credential as a generic `not_ready` sends a caller —
    and `ainvest`, which sees this surface rather than the CLI's — hunting
    manifest drift when the answer is a login. `DriftFinding.error_code` exists
    to carry that code as structured data rather than prose; honouring it here
    is what makes the library half of §5.1 true, not just the CLI half.
    """
    if assessment.ready:
        return
    originating = next((f.error_code for f in assessment.findings if f.error_code), None)
    if originating is not None:
        raise GatewayError(originating, "provider discovery failed")


@dataclass(frozen=True)
class CapabilityDescription:
    """One reviewed capability, as `rh-mcp capabilities` reports it.

    Denied entries are included with `read_allowed=False` rather than hidden:
    the reviewed decision to deny is part of what a consumer is pinning, and a
    listing that showed only allowances would make a permission change look
    like a capability appearing from nowhere.
    """

    capability: str
    read_allowed: bool
    mutates: bool
    description: str
    schema_digest: str
    rationale: str
    input_schema: Mapping[str, Any]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "allowed": self.read_allowed,
            # Reported next to `read_allowed`, because `read_allowed: true` on
            # a capability that writes is exactly the confusion §2.1 warns
            # about. A consumer gating mutations reads this field; asking it to
            # infer the answer from a tool name would be asking it to re-do
            # the human review.
            "mutates": self.mutates,
            "description": self.description,
            "schema_digest": self.schema_digest,
            "rationale": self.rationale,
            "input_schema": json_safe(self.input_schema),
        }


def capability_listing(manifest: ReviewedManifest) -> tuple[CapabilityDescription, ...]:
    """The reviewed capabilities of a manifest, allowed and denied alike.

    A module-level function, not only a gateway method, because listing the
    manifest needs no credential, no session, and no provider: it reports a
    file that ships inside the package. Routing it through the gateway meant
    opening a credential store first, so on a host without one — CI, a
    container, anything not macOS — `rh-mcp capabilities` failed with a
    configuration error while the manifest sat right there readable.
    """
    return tuple(
        CapabilityDescription(
            capability=capability,
            read_allowed=entry.read_allowed,
            mutates=entry.mutates,
            description=entry.description,
            schema_digest=entry.schema_digest,
            rationale=entry.rationale,
            input_schema=entry.input_schema,
        )
        for capability, entry in sorted(manifest.capabilities.items())
    )


class RobinhoodGateway:
    """A default-deny read gateway over a reviewed manifest (§7.1).

    Open it with `open_gateway`, as an async context manager. `readiness()`
    reports whether reads are permitted and why not; `invoke()` performs one,
    or refuses.

    The gateway holds the transport privately. There is no property, no
    attribute, and no method that yields it, the MCP session beneath it, or a
    raw provider result.
    """

    def __init__(
        self,
        config: GatewayConfig,
        manifest: ReviewedManifest,
        transport: ProviderTransport,
    ) -> None:
        self.__config = config
        self.__manifest = manifest
        self.__transport = transport
        self.__assessment: ReadinessAssessment | None = None
        self.__readiness_lock = asyncio.Lock()

    # -- readiness ---------------------------------------------------------

    async def readiness(self) -> ReadinessAssessment:
        """Establish readiness, discovering the provider surface once.

        Cached for the life of the gateway: re-running discovery per call
        would make every read depend on a fresh network round trip, and a
        surface that changed mid-session is drift to be surfaced on the next
        open rather than silently absorbed.
        """
        if self.__assessment is None:
            async with self.__readiness_lock:
                # Re-check inside the lock: several concurrent reads await the
                # same first `readiness()`, and without this each would run its
                # own discovery. §8 bounds discovery per session, not per
                # caller, so N concurrent reads must not mean N surface fetches.
                if self.__assessment is None:
                    self.__assessment = await establish_readiness(
                        self.__config, self.__manifest, self.__transport
                    )
        return self.__assessment

    @property
    def manifest_version(self) -> str:
        return self.__manifest.manifest_version

    @property
    def manifest_digest(self) -> str:
        """The locally recomputed full-manifest digest, never a trusted value."""
        return self.__manifest.digest

    def capabilities(self) -> tuple[CapabilityDescription, ...]:
        """The reviewed capabilities, allowed and denied alike.

        Safe without readiness: it reports the committed manifest, which is in
        the repository, and says nothing about the provider.
        """
        return capability_listing(self.__manifest)

    # -- reads -------------------------------------------------------------

    async def invoke(
        self, capability: object, arguments: Mapping[str, Any] | None = None
    ) -> ResultEnvelope:
        """Perform one reviewed read (§7.1).

        Refuses before touching the transport if the gateway is not ready, the
        capability is not a reviewed read capability, its pinned digests no
        longer match, or the arguments do not validate against the pinned
        input schema.
        """
        assessment = await self.readiness()
        _raise_originating_error(assessment)
        preflight: PreflightResult = preflight_read(
            self.__manifest, assessment, capability, arguments or {}
        )
        entry: ManifestEntry = preflight.entry

        # `preflight.arguments`, never `arguments`. The caller's mapping is not
        # this package's value: an independent security review demonstrated a
        # `MutableMapping` that read as `{"synthetic_symbol": "AAPL"}` while
        # preflight walked it and as `{..., "side": "buy", "quantity": "100"}`
        # by the time the transport iterated it, and both keys reached the
        # wire. Sending the frozen snapshot is what makes §6.2's ordering —
        # validate against the pinned schema, and only then call the transport
        # — a property of the data rather than of the sequence of statements.
        payload = await self.__transport.call_tool(
            entry.provider_tool_name,
            preflight.arguments,
            output_schema=entry.output_schema,
        )

        return ResultEnvelope(
            manifest_version=self.__manifest.manifest_version,
            # The same locally recomputed digest that made the gateway ready,
            # so a consumer can verify the exact permission contract this call
            # was made under (§7.1, §10).
            manifest_digest=self.__manifest.digest,
            capability=entry.capability or "",
            schema_digest=entry.schema_digest,
            result_digest=_result_digest(payload.data),
            observed_at=_now(),
            data=payload.data,
            warnings=payload.warnings,
        )


@asynccontextmanager
async def open_gateway(
    config: GatewayConfig,
    *,
    store: CredentialStore | None = None,
    manifest: ReviewedManifest | None = None,
    transport: ProviderTransport | None = None,
) -> AsyncIterator[RobinhoodGateway]:
    """Open a gateway over the active reviewed manifest.

    `manifest` and `transport` exist for tests and for `admin discover`; a
    production caller passes neither and gets the committed manifest plus a
    real session. There is deliberately no argument that disables manifest
    enforcement — the injection points replace the manifest, they cannot
    remove it.
    """
    active = load_active_manifest() if manifest is None else manifest

    if transport is not None:
        yield RobinhoodGateway(config, active, transport)
        return

    credential_store = open_credential_store(config) if store is None else store
    token_provider = _token_provider_for(config, credential_store)
    async with _open_provider_session(config, token_provider=token_provider) as session:
        yield RobinhoodGateway(config, active, session)


def _token_provider_for(config: GatewayConfig, store: CredentialStore) -> Any:
    """Build the non-interactive token provider (§5.4).

    Imported lazily so a caller that injects a transport — every test, and
    `admin discover` against a synthetic server — never constructs a
    credential path it does not use.
    """
    from rh_mcp.auth import StoredTokenProvider

    return StoredTokenProvider(config, store)


class AdminDiscoveryContext:
    """Owner-run discovery that cannot read (§6.1, §7.1).

    Deliberately not a `RobinhoodGateway` subclass and deliberately not
    holding a manifest. There is no `read`, no capability resolution, and no
    readiness — so "discovery-only" is a property of the type rather than a
    rule someone has to remember. It observes the surface and writes a
    candidate manifest for human review; it grants nothing.
    """

    def __init__(self, transport: ProviderTransport) -> None:
        self.__transport = transport

    async def observe(self) -> ObservedSurface:
        surface = await self.__transport.discover()
        if not surface.complete:
            invalid(
                "the provider surface was not fully enumerated, so a candidate manifest "
                "would describe an unknown fraction of it",
                _LOCAL,
            )
        return surface

    async def candidate_document(self) -> dict[str, Any]:
        """A sanitized candidate for human review — never an active manifest.

        `disposition` is `denied` and `capability` is null for every entry;
        `mutates` is null because only a human can answer it; and the digest
        fields a real manifest carries are absent. §6.1 is explicit that
        discovery grants no permission: a reviewer has to write each allowance
        by hand, so the safe default is the one that costs them work.

        Every field a real manifest requires and this document withholds is a
        field the loader will refuse the document for — which is what stops a
        candidate being renamed into place.
        """
        surface = await self.observe()
        return {
            "candidate": True,
            "observed_at": _now(),
            "tools": [
                {
                    "provider_tool_name": tool.name,
                    "description": tool.description,
                    "input_schema": json_safe(tool.input_schema),
                    "output_schema": (
                        None if tool.output_schema is None else json_safe(tool.output_schema)
                    ),
                    "annotations": json_safe(tool.annotations),
                    "capability": None,
                    "disposition": "denied",
                    # Null, not false. The provider ships no annotation to
                    # derive this from, so a candidate that guessed would be
                    # putting a reviewer's signature on a machine's guess.
                    "mutates": None,
                    "rationale": "UNREVIEWED — a human must review this tool, decide whether "
                    "it mutates provider state, and write a rationale before it can be "
                    "allowed",
                }
                for tool in sorted(surface.tools, key=lambda t: t.name)
            ],
        }


@asynccontextmanager
async def open_admin_discovery(
    config: GatewayConfig,
    *,
    store: CredentialStore | None = None,
    transport: ProviderTransport | None = None,
) -> AsyncIterator[AdminDiscoveryContext]:
    """Open a discovery-only context. Requires no manifest, grants no read."""
    if transport is not None:
        yield AdminDiscoveryContext(transport)
        return

    credential_store = open_credential_store(config) if store is None else store
    token_provider = _token_provider_for(config, credential_store)
    async with _open_provider_session(config, token_provider=token_provider) as session:
        yield AdminDiscoveryContext(session)


def render_json(value: Any) -> str:
    """The one JSON rendering used for every structured stdout payload."""
    return json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False)


__all__ = [
    "AdminDiscoveryContext",
    "CapabilityDescription",
    "capability_listing",
    "RobinhoodGateway",
    "open_admin_discovery",
    "open_gateway",
    "render_json",
]
