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
from collections.abc import Coroutine, Mapping, MutableMapping
from typing import Any

import pytest

from rh_mcp.config import GatewayConfig
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.gateway import (
    AdminDiscoveryContext,
    RobinhoodGateway,
    open_admin_discovery,
    open_gateway,
)
from rh_mcp.manifest import (
    ObservedSurface,
    ObservedTool,
    load_manifest_text,
    preflight_read,
)
from rh_mcp.models import ResultEnvelope
from rh_mcp.transport import ToolPayload
from tests.support import (
    ALPHA_INPUT_SCHEMA,
    build_entry,
    build_manifest,
    default_entries,
    dumps,
)

BASE_DIGEST = "sha256:3b7f113be230012d7f1949789401e60e9b84274ecf09f8a8ced31d5fc3e11250"
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
        return ToolPayload(data={"synthetic_value": 1}, source="structured_content")


@pytest.fixture
def document() -> dict[str, Any]:
    return build_manifest()


@pytest.fixture
def transport(document: dict[str, Any]) -> SpyTransport:
    return SpyTransport(document)


def gateway_for(
    document: dict[str, Any], transport: SpyTransport, digest: str = BASE_DIGEST
) -> RobinhoodGateway:
    return RobinhoodGateway(
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
            run(gateway.invoke(capability, arguments))
        assert excinfo.value.code is code
        assert transport.call_tool_calls == []

    def test_a_denied_capability(self, document: dict[str, Any], transport: SpyTransport) -> None:
        self._expect_refusal(
            document, transport, "gamma_reading", VALID_ARGS, ErrorCode.CAPABILITY_DENIED
        )

    def test_an_unknown_capability(self, document: dict[str, Any], transport: SpyTransport) -> None:
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
        envelope = run(gateway_for(document, transport).invoke("alpha_reading", VALID_ARGS))
        assert isinstance(envelope, ResultEnvelope)
        assert envelope.manifest_digest == BASE_DIGEST
        assert envelope.capability == "alpha_reading"
        assert envelope.data == {"synthetic_value": 1}

    def test_the_envelope_digest_equals_the_configured_expected_digest(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        """§7.1/§10: the consumer verifies the contract the call was made under."""
        config_digest = BASE_DIGEST
        envelope = run(
            gateway_for(document, transport, config_digest).invoke("alpha_reading", VALID_ARGS)
        )
        assert envelope.manifest_digest == config_digest

    def test_calls_the_provider_tool_the_manifest_pins(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        run(gateway_for(document, transport).invoke("alpha_reading", VALID_ARGS))
        assert transport.call_tool_calls == [("synthetic_alpha_read", VALID_ARGS)]

    def test_the_result_digest_binds_the_payload(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        envelope = run(gateway_for(document, transport).invoke("alpha_reading", VALID_ARGS))
        assert envelope.result_digest.startswith("sha256:")
        assert envelope.to_json_dict()["result_digest"] == envelope.result_digest


class TestValidatedSnapshotReachesTheTransport:
    """Finding P1: `invoke` must send what preflight validated, not its input.

    The reviewer's demonstration, kept in this repository's own suite so it
    runs on every commit rather than only when someone remembers the review
    directory. The bug was not in any check — the argument walk in
    `manifest._refuse_undeclared` is exhaustive to every depth and every
    declared name. It was in the wiring: `preflight_read` validated
    `json_safe(arguments)`, a private copy, and `invoke` then forwarded the
    caller's original mapping to the transport. A thorough guard whose result
    is discarded is not a guard.
    """

    def test_a_mapping_that_flips_after_preflight_cannot_smuggle_keys(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        class FlipAfterValidate(MutableMapping[str, Any]):
            """Valid while preflight reads it, hostile immediately after.

            Not a contrived object: any `Mapping` a caller passes is arbitrary
            code, and a plain `dict` shared with a concurrent task has the same
            property with less effort.
            """

            def __init__(self) -> None:
                self._current: dict[str, Any] = dict(VALID_ARGS)

            def flip(self) -> None:
                self._current = {**VALID_ARGS, "side": "buy", "quantity": "100"}

            def __getitem__(self, key: str) -> Any:
                return self._current[key]

            def __setitem__(self, key: str, value: Any) -> None:
                self._current[key] = value

            def __delitem__(self, key: str) -> None:
                del self._current[key]

            def __iter__(self) -> Any:
                return iter(self._current)

            def __len__(self) -> int:
                return len(self._current)

        arguments = FlipAfterValidate()

        import rh_mcp.gateway as gateway_module

        original = gateway_module.preflight_read

        def flipping(*args: Any, **kwargs: Any) -> Any:
            result = original(*args, **kwargs)
            arguments.flip()
            return result

        gateway = gateway_for(document, transport)
        gateway_module.preflight_read = flipping  # type: ignore[assignment]
        try:
            run(gateway.invoke("alpha_reading", arguments))
        finally:
            gateway_module.preflight_read = original  # type: ignore[assignment]

        assert transport.call_tool_calls, "the read should have succeeded"
        sent_name, sent_arguments = transport.call_tool_calls[0]
        assert sent_name == "synthetic_alpha_read"
        assert dict(sent_arguments) == VALID_ARGS
        assert "side" not in sent_arguments
        assert "quantity" not in sent_arguments

    def test_the_snapshot_the_transport_receives_cannot_be_edited(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        """A snapshot that is still mutable is a snapshot with a later window.

        `SpyTransport` copies what it is handed, so this test keeps the object
        itself: the property being asserted is that the *real* transport, which
        iterates the mapping some time after `invoke` passed it along, cannot
        be handed something that is still editable in the meantime. A plain
        `dict` copy would close the reviewer's exact demonstration and leave
        the shape of it open.
        """

        class RawRecordingTransport(SpyTransport):
            def __init__(self, document: dict[str, Any]) -> None:
                super().__init__(document)
                self.raw: list[Mapping[str, Any]] = []

            async def call_tool(
                self,
                provider_tool_name: str,
                arguments: Mapping[str, Any],
                *,
                output_schema: Mapping[str, Any] | None,
            ) -> ToolPayload:
                self.raw.append(arguments)
                return await super().call_tool(
                    provider_tool_name, arguments, output_schema=output_schema
                )

        recorder = RawRecordingTransport(document)
        run(gateway_for(document, recorder).invoke("alpha_reading", VALID_ARGS))
        sent_arguments = recorder.raw[0]
        assert dict(sent_arguments) == VALID_ARGS
        with pytest.raises(TypeError):
            sent_arguments["side"] = "buy"  # type: ignore[index]
        assert sent_arguments is not VALID_ARGS

    def test_preflight_no_longer_returns_something_sendable_on_its_own(self) -> None:
        """The type change is the durable half of the fix.

        Returning a bare `ManifestEntry` let `invoke` reach for the only
        arguments in scope — the caller's. Returning entry *and* snapshot
        together means the wiring bug would now be a mypy error.
        """
        from rh_mcp.manifest import ManifestEntry, PreflightResult, preflight_read

        returned = inspect.signature(preflight_read).return_annotation
        assert returned in (PreflightResult, "PreflightResult")
        assert returned is not ManifestEntry


class TestNoEscapeHatch:
    """§1/§2: no public surface may yield a session, a raw result, or a tool name.

    Scoped to `RobinhoodGateway`, and that scope is why finding P0 shipped:
    the claim these tests were written to defend is about the whole package,
    and `rh_mcp.transport` exported a generic `call_tool` for the whole of
    v0.1.0 with this class green. The package-wide sweep now lives in
    `tests/test_public_surface.py`; what stays here is the behavioural half —
    that a *constructed* gateway holds no reachable transport — which a static
    sweep over `__all__` cannot see.
    """

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
        methods = {n for n, _ in inspect.getmembers(RobinhoodGateway) if not n.startswith("_")}
        assert methods == {
            "capabilities",
            "invoke",
            "manifest_digest",
            "manifest_version",
            "readiness",
        }

    def test_open_gateway_has_no_flag_that_disables_enforcement(self) -> None:
        parameters = set(inspect.signature(open_gateway).parameters)
        assert parameters == {"config", "store", "manifest", "transport"}


class TestCapabilityListingShowsMutation:
    """§2.1: `read_allowed: true` on a writing capability is the confusion."""

    def test_the_listing_carries_a_mutation_flag_and_a_rationale(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        rendered = [c.to_json_dict() for c in gateway_for(document, transport).capabilities()]
        assert rendered
        for entry in rendered:
            assert "mutates" in entry
            assert isinstance(entry["mutates"], bool)
            assert entry["rationale"].strip()

    # Golden fixture (DESIGN.md §7.2, §12.5): the whole per-entry key set.
    #
    # Same gap as the `status` payload, and for the same reason. Every key here
    # is read by name somewhere, so a rename fails; an independent review
    # *added* a key to `CapabilityDescription.to_json_dict` and got 1179
    # passing. §12.5 accepts `rh-mcp capabilities` having no version field of
    # its own only because its shape cannot move unnoticed, and that has to be
    # true in the addition direction too.
    #
    # `read_allowed` is deliberately not in this set: §2.1 renamed the JSON key
    # to `allowed` in manifest format 1.2 and kept `read_allowed` as a Python
    # attribute only. A key of that name reappearing here would be the 1.1
    # spelling coming back, on a listing where 11 allowed entries write.
    _EXPECTED_CAPABILITY_KEYS: frozenset[str] = frozenset(
        {
            "capability",
            "allowed",
            "mutates",
            "description",
            "schema_digest",
            "rationale",
            "input_schema",
        }
    )

    def test_the_capability_listing_key_set_is_pinned_in_both_directions(
        self, document: dict[str, Any], transport: SpyTransport
    ) -> None:
        rendered = [c.to_json_dict() for c in gateway_for(document, transport).capabilities()]
        assert rendered
        for entry in rendered:
            assert set(entry) == self._EXPECTED_CAPABILITY_KEYS
            assert "read_allowed" not in entry


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
    def _loose_gateway() -> tuple[RobinhoodGateway, SpyTransport]:
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
        gateway = RobinhoodGateway(
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
            run(gateway.invoke("alpha_reading", hostile))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []

    def test_declared_arguments_still_pass(self) -> None:
        gateway, transport = self._loose_gateway()
        run(gateway.invoke("alpha_reading", {"synthetic_symbol": "AAPL"}))
        assert transport.call_tool_calls == [("synthetic_alpha_read", {"synthetic_symbol": "AAPL"})]

    def test_the_refusal_names_only_caller_supplied_keys(self) -> None:
        """§7.3: the names came from the caller, so echoing them is safe."""
        gateway, _ = self._loose_gateway()
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", {"synthetic_symbol": "A", "side": "sell"}))
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


class TestUndeclaredArgumentsAtEveryDepth:
    """The round-2 blocking finding: the first fix was depth-0 only.

    A hostile payload simply moved one level down — a declared object with no
    properties of its own accepted anything. Objects inside an array are the
    same hole and the likelier one, since a batch or filter argument is exactly
    where they appear.
    """

    @staticmethod
    def _gateway(schema: dict[str, Any]) -> tuple[RobinhoodGateway, SpyTransport]:
        from tests.support import build_entry, default_entries, reseal

        entries = default_entries()
        entries[0] = build_entry(
            provider_tool_name="synthetic_alpha_read",
            capability="alpha_reading",
            description=entries[0]["description"],
            input_schema=schema,
            rationale=entries[0]["rationale"],
        )
        document = reseal(build_manifest(entries))
        manifest = load_manifest_text(dumps(document))
        transport = SpyTransport(document)
        return (
            RobinhoodGateway(
                GatewayConfig(expected_manifest_digest=manifest.digest), manifest, transport
            ),
            transport,
        )

    HOSTILE = {"side": "sell", "quantity": 100, "account_id": "RH-9999"}

    @pytest.mark.parametrize(
        ("schema", "arguments"),
        [
            (
                {
                    "type": "object",
                    "properties": {"s": {"type": "string"}, "f": {"type": "object"}},
                },
                {"s": "A", "f": HOSTILE},
            ),
            (
                {
                    "type": "object",
                    "properties": {
                        "s": {"type": "string"},
                        "f": {"type": "object", "properties": {"ok": {"type": "string"}}},
                    },
                },
                {"s": "A", "f": {"ok": "x", **HOSTILE}},
            ),
            (
                {
                    "type": "object",
                    "properties": {
                        "rows": {
                            "type": "array",
                            "items": {"type": "object", "properties": {"ok": {"type": "string"}}},
                        }
                    },
                },
                {"rows": [{"ok": "x"}, {"ok": "y", **HOSTILE}]},
            ),
        ],
        ids=["declared-object-no-properties", "declared-object-with-properties", "array-item"],
    )
    def test_nested_undeclared_names_never_reach_the_provider(
        self, schema: dict[str, Any], arguments: dict[str, Any]
    ) -> None:
        gateway, transport = self._gateway(schema)
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", arguments))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []

    def test_a_combinator_schema_still_accepts_its_declared_names(self) -> None:
        """allOf/anyOf/oneOf declare properties too.

        Ignoring them would load, become ready, then refuse every argument set
        including the legal one — a defect surfaced at first call rather than
        at load.
        """
        gateway, transport = self._gateway(
            {"type": "object", "allOf": [{"properties": {"synthetic_symbol": {"type": "string"}}}]}
        )
        run(gateway.invoke("alpha_reading", {"synthetic_symbol": "AAPL"}))
        assert transport.call_tool_calls

    @pytest.mark.parametrize(
        "inner",
        [{1: "x"}, {"ok": "x", 1: "y"}, {"ok": "x", None: "y"}, {2: "a", "b": "c"}],
        ids=["int-only", "str-then-int", "str-then-none", "int-then-str"],
    )
    def test_a_non_string_key_is_refused_not_a_crash(self, inner: dict[Any, Any]) -> None:
        """A mixed-type key set is the hazard: sorting one raises TypeError.

        `{"ok": ..., 1: ...}` is the case that matters — a set holding both a
        str and an int cannot be sorted, so the refusal would escape as an
        uncaught TypeError instead of the stable INPUT_INVALID contract.
        """
        gateway, transport = self._gateway(
            {
                "type": "object",
                "properties": {"s": {"type": "object", "properties": {"ok": {"type": "string"}}}},
            }
        )
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", {"s": inner}))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []


class TestReadSurfacesTheOriginatingError:
    """§5.1 covers *all* read operations, not just the CLI's `status`."""

    def test_an_auth_failure_during_discovery_reaches_the_library_caller(
        self, document: dict[str, Any]
    ) -> None:
        class AuthFailingTransport(SpyTransport):
            async def discover(self) -> ObservedSurface:
                self.discover_calls += 1
                raise GatewayError(ErrorCode.AUTH_REQUIRED, "credential expired")

        transport = AuthFailingTransport(document)
        gateway = gateway_for(document, transport)
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", VALID_ARGS))
        assert excinfo.value.code is ErrorCode.AUTH_REQUIRED
        assert transport.call_tool_calls == []

    def test_plain_drift_still_reports_not_ready(self, document: dict[str, Any]) -> None:
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport, OTHER_DIGEST)
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", VALID_ARGS))
        assert excinfo.value.code is ErrorCode.NOT_READY


class TestTheArgumentWalkIsBounded:
    """A RecursionError would escape the §7.3 error contract.

    `max_json_depth` is a §8 payload bound enforced downstream of this check,
    which is too late: the crash happens while validating caller input, before
    anything reaches the transport.
    """

    def test_a_deeply_nested_payload_is_refused_not_a_crash(self) -> None:
        gateway, transport = TestUndeclaredArgumentsAtEveryDepth._gateway(
            {"type": "object", "properties": {"rows": {"type": "array"}}}
        )
        payload: dict[str, Any] = {"rows": []}
        cursor: list[Any] = payload["rows"]
        for _ in range(5000):
            nxt: list[Any] = []
            cursor.append(nxt)
            cursor = nxt
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", payload))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert "nests deeper" in excinfo.value.message
        assert transport.call_tool_calls == []

    def test_a_realistically_nested_payload_still_passes(self) -> None:
        """The rail must not refuse a schema a reviewer would plausibly write."""
        gateway, transport = TestUndeclaredArgumentsAtEveryDepth._gateway(
            {
                "type": "object",
                "properties": {
                    "a": {
                        "type": "object",
                        "properties": {
                            "b": {
                                "type": "object",
                                "properties": {"c": {"type": "string"}},
                            }
                        },
                    }
                },
            }
        )
        run(gateway.invoke("alpha_reading", {"a": {"b": {"c": "x"}}}))
        assert transport.call_tool_calls


class TestCombinatorDescent:
    """`_subschema_for` searches combinator branches, and that is load-bearing.

    Without it a legal argument nested under an `allOf` branch is refused —
    the branch survived mutation against the whole suite until this test.
    """

    def test_a_legal_argument_nested_under_a_combinator_is_accepted(self) -> None:
        gateway, transport = TestUndeclaredArgumentsAtEveryDepth._gateway(
            {
                "type": "object",
                "allOf": [
                    {
                        "properties": {
                            "filter": {
                                "type": "object",
                                "properties": {"ok": {"type": "string"}},
                            }
                        }
                    }
                ],
            }
        )
        run(gateway.invoke("alpha_reading", {"filter": {"ok": "x"}}))
        assert transport.call_tool_calls == [("synthetic_alpha_read", {"filter": {"ok": "x"}})]

    def test_an_undeclared_name_under_a_combinator_is_still_refused(self) -> None:
        gateway, transport = TestUndeclaredArgumentsAtEveryDepth._gateway(
            {
                "type": "object",
                "allOf": [
                    {
                        "properties": {
                            "filter": {
                                "type": "object",
                                "properties": {"ok": {"type": "string"}},
                            }
                        }
                    }
                ],
            }
        )
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", {"filter": {"ok": "x", "side": "sell"}}))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []


class TestAdditionalPropertiesIsDeliberatelyNotFollowed:
    """Not descending is what makes it safe — a regression guard on the docstring.

    A key governed only by `additionalProperties` never enters
    `_declared_names`, so it is refused at its parent. Adding the descent would
    turn that refusal into a permit and reopen the blocking finding.
    """

    def test_a_key_under_additional_properties_is_refused(self) -> None:
        gateway, transport = TestUndeclaredArgumentsAtEveryDepth._gateway(
            {
                "type": "object",
                "properties": {"s": {"type": "string"}},
                "additionalProperties": {"type": "object"},
            }
        )
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("alpha_reading", {"s": "A", "anything": {"side": "sell"}}))
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []


class TestMutationsAreRefusedUnlessEnabled:
    """`mutates` decides something now (§6.2, config `allow_mutations`).

    Until 0.4.0 it decided nothing. It was declared in the manifest, checked
    for type at load, and reported to callers, and no branch anywhere read it
    to permit or refuse a call. An external review of v0.3.3 stated it
    exactly: writes were gated as reads were, and "confirm with the user
    first" was advice to the calling model rather than a control.

    The suite passing is not evidence for any of this. When the branch was
    first added, all 1215 tests passed unchanged — because no test invoked a
    mutating capability through the gateway at all. These do.
    """

    @staticmethod
    def _document_with_a_write() -> dict[str, Any]:
        entries = default_entries()
        entries.append(
            build_entry(
                provider_tool_name="synthetic_write",
                capability="synthetic_writing",
                description="Synthetic write used only by the offline suite.",
                input_schema=ALPHA_INPUT_SCHEMA,
                mutates=True,
            )
        )
        return build_manifest(entries=entries)

    def test_a_write_is_refused_by_default_and_never_reaches_the_transport(self) -> None:
        """The refusal has to be observable at the wire, not just at the call.

        An exception proves the caller saw an error. It does not prove the
        provider was left alone — that is what the recorded calls are for, and
        it is the property that matters for a credential that can trade.
        """
        document = self._document_with_a_write()
        recorder = SpyTransport(document)
        gateway = RobinhoodGateway(
            GatewayConfig(expected_manifest_digest=load_manifest_text(dumps(document)).digest),
            load_manifest_text(dumps(document)),
            recorder,
        )

        with pytest.raises(GatewayError) as raised:
            run(gateway.invoke("synthetic_writing", VALID_ARGS))

        assert raised.value.code is ErrorCode.CAPABILITY_DENIED
        assert recorder.call_tool_calls == []

    def test_the_refusal_is_indistinguishable_from_an_unknown_capability(self) -> None:
        """A distinct code would answer "is this a write?" for free.

        The manifest is not secret and `capabilities()` reports `mutates`
        openly, so this is not hiding the fact. It is refusing to answer the
        question through an error channel, where a caller probing names could
        map the write surface without ever being allowed to call one.
        """
        document = self._document_with_a_write()
        gateway = RobinhoodGateway(
            GatewayConfig(expected_manifest_digest=load_manifest_text(dumps(document)).digest),
            load_manifest_text(dumps(document)),
            SpyTransport(document),
        )

        with pytest.raises(GatewayError) as denied_write:
            run(gateway.invoke("synthetic_writing", VALID_ARGS))
        with pytest.raises(GatewayError) as unknown:
            run(gateway.invoke("no_such_capability_at_all", VALID_ARGS))

        assert denied_write.value.code is unknown.value.code
        assert str(denied_write.value) == str(unknown.value)

    def test_enabling_mutations_lets_the_write_through(self) -> None:
        """Otherwise the previous two tests pass on a gateway that refuses
        everything, which would make them a check on nothing."""
        document = self._document_with_a_write()
        recorder = SpyTransport(document)
        gateway = RobinhoodGateway(
            GatewayConfig(
                expected_manifest_digest=load_manifest_text(dumps(document)).digest,
                allow_mutations=True,
            ),
            load_manifest_text(dumps(document)),
            recorder,
        )

        run(gateway.invoke("synthetic_writing", VALID_ARGS))

        assert [name for name, _ in recorder.call_tool_calls] == ["synthetic_write"]

    def test_the_exported_gate_refuses_a_non_bool_directly(self) -> None:
        """The check has to be at the gate, not only at the config boundary.

        `GatewayConfig` validating the flag protects callers who go through
        `RobinhoodGateway`. `preflight_read` is in `manifest.__all__`, and this
        package's history records a reviewer who ignored the gateway and
        imported the exported function; reached that way with the string
        `"false"` — truthy — the gate opened and returned a `PreflightResult`
        authorising the write. A control that holds only when approached
        through one caller is a convention.
        """
        document = self._document_with_a_write()
        manifest = load_manifest_text(dumps(document))
        gateway = RobinhoodGateway(
            GatewayConfig(expected_manifest_digest=manifest.digest),
            manifest,
            SpyTransport(document),
        )
        assessment = run(gateway.readiness())

        for value in ("false", "no", "0", 1, [1]):
            with pytest.raises(GatewayError) as raised:
                preflight_read(
                    manifest,
                    assessment,
                    "synthetic_writing",
                    VALID_ARGS,
                    allow_mutations=value,  # type: ignore[arg-type]
                )
            assert raised.value.code is not ErrorCode.CAPABILITY_DENIED, value

        # The control: a real bool still authorises, so the loop above is not
        # passing on a function that refuses everything.
        allowed = preflight_read(
            manifest, assessment, "synthetic_writing", VALID_ARGS, allow_mutations=True
        )
        assert allowed.entry.capability == "synthetic_writing"

    def test_enabling_mutations_does_not_unlock_a_denied_capability(self) -> None:
        """`allow_mutations` is a second lock, never a key to the first.

        The reviewed disposition still decides membership; this flag only
        decides whether the mutating subset of what was already allowed may be
        called.
        """
        document = self._document_with_a_write()
        recorder = SpyTransport(document)
        gateway = RobinhoodGateway(
            GatewayConfig(
                expected_manifest_digest=load_manifest_text(dumps(document)).digest,
                allow_mutations=True,
            ),
            load_manifest_text(dumps(document)),
            recorder,
        )

        with pytest.raises(GatewayError) as raised:
            run(gateway.invoke("gamma_reading", VALID_ARGS))

        assert raised.value.code is ErrorCode.CAPABILITY_DENIED
        assert recorder.call_tool_calls == []
