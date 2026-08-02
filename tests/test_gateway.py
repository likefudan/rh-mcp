"""Gateway composition contract (§7.1, §10, §11).

The point of these tests is not that the gateway calls the right functions —
it is that a caller cannot reach the transport without having passed every
check first. `SpyTransport` counts calls, so "no read reaches the transport"
is asserted rather than assumed.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Coroutine, Mapping
from typing import Any

import pytest

from rh_mcp.config import GatewayConfig
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.gateway import (
    AdminDiscoveryContext,
    RobinhoodReadGateway,
    open_admin_discovery,
    open_gateway,
)
from rh_mcp.manifest import ObservedSurface, ObservedTool, load_manifest_text
from rh_mcp.models import ResultEnvelope
from rh_mcp.transport import ToolPayload
from tests.support import build_manifest, dumps

BASE_DIGEST = "sha256:463295e635f21ed81c3792da15f3474c6096d8821cd815d9cbddc6867dc8b705"
OTHER_DIGEST = "sha256:" + "c" * 64
VALID_ARGS: dict[str, Any] = {"synthetic_symbol": "AAPL"}


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class SpyTransport:
    """A `ProviderTransport` that records every call it receives."""

    def __init__(self, document: dict[str, Any], *, complete: bool = True) -> None:
        self.tools = tuple(
            ObservedTool(
                name=entry["provider_tool_name"],
                description=entry["description"],
                input_schema=entry["input_schema"],
                output_schema=entry["output_schema"],
                annotations=entry["annotations"],
            )
            for entry in document["entries"]
        )
        self.complete = complete
        self.discover_calls = 0
        self.call_tool_calls: list[tuple[str, Mapping[str, Any]]] = []

    async def discover(self) -> ObservedSurface:
        self.discover_calls += 1
        return ObservedSurface(tools=self.tools, complete=self.complete)

    async def call_tool(
        self,
        provider_tool_name: str,
        arguments: Mapping[str, Any],
        *,
        output_schema: Mapping[str, Any] | None,
    ) -> ToolPayload:
        self.call_tool_calls.append((provider_tool_name, dict(arguments)))
        return ToolPayload(
            data={"synthetic_value": 1}, source="structured_content"
        )


@pytest.fixture
def document() -> dict[str, Any]:
    return build_manifest()


@pytest.fixture
def transport(document: dict[str, Any]) -> SpyTransport:
    return SpyTransport(document)


def gateway_for(
    document: dict[str, Any], transport: SpyTransport, digest: str = BASE_DIGEST
) -> RobinhoodReadGateway:
    return RobinhoodReadGateway(
        GatewayConfig(expected_manifest_digest=digest),
        load_manifest_text(dumps(document)),
        transport,
    )


class TestReadiness:
    def test_ready_against_a_matching_surface(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        assessment = run(gateway_for(document, transport).readiness())
        assert assessment.ready
        assert assessment.manifest_digest == BASE_DIGEST

    def test_a_mismatched_expected_digest_is_not_ready(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        assessment = run(gateway_for(document, transport, OTHER_DIGEST).readiness())
        assert not assessment.ready

    def test_discovery_runs_once_across_repeated_readiness(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        gateway = gateway_for(document, transport)

        async def twice() -> None:
            await gateway.readiness()
            await gateway.readiness()

        run(twice())
        assert transport.discover_calls == 1


class TestReadsThatMustNotReachTheTransport:
    """§6.2/§11: a refused read must never produce a provider call."""

    def _expect_refusal(
        self,
        document: dict[str, Any],
        transport: SpyTransport,
        capability: object,
        arguments: Mapping[str, Any],
        code: ErrorCode,
        digest: str = BASE_DIGEST,
    ) -> None:
        gateway = gateway_for(document, transport, digest)
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.read(capability, arguments))
        assert excinfo.value.code is code
        assert transport.call_tool_calls == []

    def test_a_denied_capability(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        self._expect_refusal(
            document, transport, "gamma_reading", VALID_ARGS, ErrorCode.CAPABILITY_DENIED
        )

    def test_an_unknown_capability(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        self._expect_refusal(
            document, transport, "not_a_capability", VALID_ARGS, ErrorCode.CAPABILITY_DENIED
        )

    def test_a_provider_tool_name_used_as_a_capability(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        """A caller must not be able to reach a tool by naming it directly."""
        self._expect_refusal(
            document,
            transport,
            "synthetic_alpha_read",
            VALID_ARGS,
            ErrorCode.CAPABILITY_DENIED,
        )

    @pytest.mark.parametrize(
        "arguments",
        [{}, {"synthetic_symbol": 7}, {"synthetic_symbol": "AAPL", "injected": True}],
        ids=["missing-required", "wrong-type", "additional-property"],
    )
    def test_arguments_that_violate_the_pinned_schema(
        self, document: dict[str, Any], transport: SpyTransport, arguments: dict[str, Any]
    ) -> None:
        self._expect_refusal(
            document, transport, "alpha_reading", arguments, ErrorCode.INPUT_INVALID
        )

    def test_a_gateway_that_is_not_ready(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        self._expect_refusal(
            document,
            transport,
            "alpha_reading",
            VALID_ARGS,
            ErrorCode.NOT_READY,
            digest=OTHER_DIGEST,
        )

    def test_an_incompletely_enumerated_surface(self, document: dict[str, Any]) -> None:
        """A partial surface is drift, not a smaller provider."""
        self._expect_refusal(
            document,
            SpyTransport(document, complete=False),
            "alpha_reading",
            VALID_ARGS,
            ErrorCode.NOT_READY,
        )


class TestSuccessfulRead:
    def test_returns_an_envelope_carrying_the_active_digest(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        envelope = run(gateway_for(document, transport).read("alpha_reading", VALID_ARGS))
        assert isinstance(envelope, ResultEnvelope)
        assert envelope.manifest_digest == BASE_DIGEST
        assert envelope.capability == "alpha_reading"
        assert envelope.data == {"synthetic_value": 1}

    def test_the_envelope_digest_equals_the_configured_expected_digest(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        """§7.1/§10: the consumer verifies the contract the call was made under."""
        config_digest = BASE_DIGEST
        envelope = run(gateway_for(document, transport, config_digest).read(
            "alpha_reading", VALID_ARGS
        ))
        assert envelope.manifest_digest == config_digest

    def test_calls_the_provider_tool_the_manifest_pins(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        run(gateway_for(document, transport).read("alpha_reading", VALID_ARGS))
        assert transport.call_tool_calls == [("synthetic_alpha_read", VALID_ARGS)]

    def test_the_result_digest_binds_the_payload(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        envelope = run(gateway_for(document, transport).read("alpha_reading", VALID_ARGS))
        assert envelope.result_digest.startswith("sha256:")
        assert envelope.to_json_dict()["result_digest"] == envelope.result_digest


class TestNoEscapeHatch:
    """§1/§2: no public surface may yield a session, a raw result, or a tool name."""

    def test_the_gateway_exposes_no_transport_or_session(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        gateway = gateway_for(document, transport)
        public = [n for n in dir(gateway) if not n.startswith("_")]
        assert "session" not in public
        assert "transport" not in public
        assert "call_tool" not in public
        for name in public:
            assert not isinstance(getattr(gateway, name, None), SpyTransport)

    def test_the_gateway_has_no_generic_call_method(self) -> None:
        methods = {
            n for n, _ in inspect.getmembers(RobinhoodReadGateway) if not n.startswith("_")
        }
        assert methods == {
            "capabilities",
            "manifest_digest",
            "manifest_version",
            "read",
            "readiness",
        }

    def test_open_gateway_has_no_flag_that_disables_enforcement(self) -> None:
        parameters = set(inspect.signature(open_gateway).parameters)
        assert parameters == {"config", "store", "manifest", "transport"}


class TestAdminDiscovery:
    """§6.1: discovery observes; it never grants."""

    def test_has_no_read_method(self) -> None:
        methods = {n for n, _ in inspect.getmembers(AdminDiscoveryContext) if not n.startswith("_")}
        assert "read" not in methods
        assert "readiness" not in methods

    def test_candidate_marks_every_tool_denied_and_uncapable(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        candidate = run(AdminDiscoveryContext(transport).candidate_document())
        assert candidate["candidate"] is True
        assert candidate["tools"]
        for tool in candidate["tools"]:
            assert tool["disposition"] == "denied"
            assert tool["capability"] is None
            assert "UNREVIEWED" in tool["rationale"]

    def test_candidate_carries_no_digest_that_could_be_mistaken_for_a_manifest(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        rendered = json.dumps(run(AdminDiscoveryContext(transport).candidate_document()))
        assert "full_manifest_digest" not in rendered
        assert "schema_digest" not in rendered

    def test_refuses_an_incomplete_surface(self, document: dict[str, Any]) -> None:
        with pytest.raises(GatewayError) as excinfo:
            run(AdminDiscoveryContext(SpyTransport(document, complete=False)).observe())
        assert excinfo.value.code is ErrorCode.NOT_READY

    def test_open_admin_discovery_takes_no_manifest(self) -> None:
        assert "manifest" not in inspect.signature(open_admin_discovery).parameters


class TestUndeclaredArgumentsAreRefused:
    """The blocking finding from review: JSON Schema is permissive by default.

    A reviewed schema that omits `additionalProperties: false` would otherwise
    forward caller-chosen keys verbatim to a write-capable tool. The manifest
    reviewer cannot close it — adding the keyword changes `schema_digest` and
    the gateway never becomes ready — so the gateway refuses argument names the
    pinned schema does not declare.
    """

    @staticmethod
    def _loose_gateway() -> tuple[RobinhoodReadGateway, SpyTransport]:
        from tests.support import build_entry, default_entries, reseal

        entries = default_entries()
        loose = {
            "type": "object",
            "properties": {"synthetic_symbol": {"type": "string"}},
            "required": ["synthetic_symbol"],
        }
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description=entries[0]["description"],
            input_schema=loose,
            rationale=entries[0]["rationale"],
        )
        document = reseal(build_manifest(entries))
        manifest = load_manifest_text(dumps(document))
        transport = SpyTransport(document)
        gateway = RobinhoodReadGateway(
            GatewayConfig(expected_manifest_digest=manifest.digest), manifest, transport
        )
        return gateway, transport

    def test_a_trade_shaped_argument_never_reaches_the_provider(self) -> None:
        gateway, transport = self._loose_gateway()
        hostile = {
            "synthetic_symbol": "AAPL",
            "side": "sell",
            "quantity": 100,
            "account_id": "RH-9999",
        }
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.read("alpha_reading", hostile))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []

    def test_declared_arguments_still_pass(self) -> None:
        gateway, transport = self._loose_gateway()
        run(gateway.read("alpha_reading", {"synthetic_symbol": "AAPL"}))
        assert transport.call_tool_calls == [("synthetic_alpha_read", {"synthetic_symbol": "AAPL"})]

    def test_the_refusal_names_only_caller_supplied_keys(self) -> None:
        """§7.3: the names came from the caller, so echoing them is safe."""
        gateway, _ = self._loose_gateway()
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.read("alpha_reading", {"synthetic_symbol": "A", "side": "sell"}))
        assert "side" in excinfo.value.message


class SlowSpyTransport(SpyTransport):
    """A spy whose `discover` actually yields control.

    Without a real await point the event loop runs each coroutine straight
    through, so eight concurrent `readiness()` calls serialise on their own and
    a missing lock is invisible. This is why the first version of the test
    below passed against the unlocked code.
    """

    async def discover(self) -> ObservedSurface:
        self.discover_calls += 1
        await asyncio.sleep(0)
        return ObservedSurface(tools=self.tools, complete=self.complete)


class TestReadinessIsSingleFlight:
    def test_concurrent_reads_trigger_one_discovery(self, document: dict[str, Any]) -> None:
        """§8 bounds discovery per session, not per caller."""
        transport = SlowSpyTransport(document)
        gateway = gateway_for(document, transport)

        async def eight() -> None:
            await asyncio.gather(*(gateway.readiness() for _ in range(8)))

        run(eight())
        assert transport.discover_calls == 1
