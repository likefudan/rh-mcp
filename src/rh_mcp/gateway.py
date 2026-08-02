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
  one call, so a caller cannot hold a pinned entry it has not earned.
* Only after both does anything reach `ProviderTransport.call_tool`.

What this module must never do is give a caller a way around that order. No
public surface exposes an MCP session, a raw provider result, a provider tool
name, or a generic `call_tool` (§1, §2) — a gateway that could be asked for an
arbitrary tool would be a gateway whose manifest is advisory.

`AdminDiscoveryContext` is the deliberate exception, and it is exceptional in
the safe direction: it can observe the provider surface but has no manifest,
cannot become ready, and has no `read` at all.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from rh_mcp.canonical import canonical_digest
from rh_mcp.config import GatewayConfig
from rh_mcp.credentials import CredentialStore, open_credential_store
from rh_mcp.errors import ErrorCode
from rh_mcp.manifest import (
    ManifestEntry,
    ObservedSurface,
    ReadinessAssessment,
    ReviewedManifest,
    establish_readiness,
    load_active_manifest,
    preflight_read,
)
from rh_mcp.models import ResultEnvelope
from rh_mcp.transport import ProviderTransport, open_provider_session
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
    description: str
    schema_digest: str
    input_schema: Mapping[str, Any]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "read_allowed": self.read_allowed,
            "description": self.description,
            "schema_digest": self.schema_digest,
            "input_schema": json_safe(self.input_schema),
        }


class RobinhoodReadGateway:
    """A default-deny read gateway over a reviewed manifest (§7.1).

    Open it as an async context manager. `readiness()` reports whether reads
    are permitted and why not; `read()` performs one, or refuses.

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

    # -- readiness ---------------------------------------------------------

    async def readiness(self) -> ReadinessAssessment:
        """Establish readiness, discovering the provider surface once.

        Cached for the life of the gateway: re-running discovery per call
        would make every read depend on a fresh network round trip, and a
        surface that changed mid-session is drift to be surfaced on the next
        open rather than silently absorbed.
        """
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
        return tuple(
            CapabilityDescription(
                capability=capability,
                read_allowed=entry.read_allowed,
                description=entry.description,
                schema_digest=entry.schema_digest,
                input_schema=entry.input_schema,
            )
            for capability, entry in sorted(self.__manifest.capabilities.items())
        )

    # -- reads -------------------------------------------------------------

    async def read(
        self, capability: object, arguments: Mapping[str, Any] | None = None
    ) -> ResultEnvelope:
        """Perform one reviewed read (§7.1).

        Refuses before touching the transport if the gateway is not ready, the
        capability is not a reviewed read capability, its pinned digests no
        longer match, or the arguments do not validate against the pinned
        input schema.
        """
        assessment = await self.readiness()
        entry: ManifestEntry = preflight_read(
            self.__manifest, assessment, capability, arguments or {}
        )

        payload = await self.__transport.call_tool(
            entry.provider_tool_name,
            arguments or {},
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
) -> AsyncIterator[RobinhoodReadGateway]:
    """Open a gateway over the active reviewed manifest.

    `manifest` and `transport` exist for tests and for `admin discover`; a
    production caller passes neither and gets the committed manifest plus a
    real session. There is deliberately no argument that disables manifest
    enforcement — the injection points replace the manifest, they cannot
    remove it.
    """
    active = load_active_manifest() if manifest is None else manifest

    if transport is not None:
        yield RobinhoodReadGateway(config, active, transport)
        return

    credential_store = open_credential_store(config) if store is None else store
    token_provider = _token_provider_for(config, credential_store)
    async with open_provider_session(config, token_provider=token_provider) as session:
        yield RobinhoodReadGateway(config, active, session)


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

    Deliberately not a `RobinhoodReadGateway` subclass and deliberately not
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

        `disposition` is `denied` and `capability` is null for every entry, and
        the digest fields a real manifest carries are absent. §6.1 is explicit
        that discovery grants no permission: a reviewer has to write each
        allowance by hand, so the safe default is the one that costs them work.
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
                    "rationale": "UNREVIEWED — a human must review this tool and write a "
                    "rationale before it can be allowed",
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
    async with open_provider_session(config, token_provider=token_provider) as session:
        yield AdminDiscoveryContext(session)


def render_json(value: Any) -> str:
    """The one JSON rendering used for every structured stdout payload."""
    return json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False)


__all__ = [
    "AdminDiscoveryContext",
    "CapabilityDescription",
    "RobinhoodReadGateway",
    "open_admin_discovery",
    "open_gateway",
    "render_json",
]
