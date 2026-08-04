"""Reviewer-authored adversarial tests for rh-mcp v0.1.0.

These tests encode the security properties claimed by DESIGN.md / README.md /
INDEPENDENT_SECURITY_REVIEW.md. They are intentionally independent of the
repository's existing suite.

Run against the pinned release source (worktree or unpacked sdist):

    cd /path/to/a81464f
    uv run --frozen pytest /path/to/security-review/v0.1.0/test_adversarial_review.py -v

Tests marked ``xfail_expected`` document currently broken claims (findings).
They use ``pytest.raises(AssertionError)``-style expectations via explicit
``pytest.fail`` when the insecure behaviour is observed, OR they assert the
secure property and are expected to FAIL against v0.1.0.

This file never invokes the live Robinhood server and never uses real tokens.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
from collections.abc import Coroutine, Mapping, MutableMapping
from typing import Any

import pytest

from rh_mcp.config import GatewayConfig
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.gateway import RobinhoodGateway, open_gateway
from rh_mcp.manifest import (
    ObservedSurface,
    ObservedTool,
    load_active_manifest,
    load_manifest_text,
    preflight_read,
)
# `open_provider_session` was imported here in the reviewer's original. See
# the note at the foot of this file: that import is unsatisfiable once the
# finding it reports is fixed, and it backs no assertion.
from rh_mcp.transport import ProviderTransport, ToolPayload
from tests.support import build_manifest, dumps

# ---------------------------------------------------------------------------
# Local fixtures (mirrors of the repo helpers; kept local for independence)
# ---------------------------------------------------------------------------

BASE_DIGEST = "sha256:3b7f113be230012d7f1949789401e60e9b84274ecf09f8a8ced31d5fc3e11250"
VALID_ARGS: dict[str, Any] = {"synthetic_symbol": "AAPL"}

DENIED_TRADING = (
    "place_equity_order",
    "place_option_order",
    "exercise_option",
    "cancel_equity_order",
    "cancel_option_order",
    "cancel_option_exercise",
    "review_equity_order",
    "review_option_order",
)

ALLOWED_MUTATIONS = (
    "add_option_to_watchlist",
    "add_to_watchlist",
    "create_scan",
    "create_watchlist",
    "follow_watchlist",
    "remove_from_watchlist",
    "remove_option_from_watchlist",
    "unfollow_watchlist",
    "update_scan_config",
    "update_scan_filters",
    "update_watchlist",
)


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class SpyTransport:
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
        self.call_tool_calls: list[tuple[str, dict[str, Any]]] = []

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


def gateway_for(
    document: dict[str, Any], transport: SpyTransport, digest: str = BASE_DIGEST
) -> RobinhoodGateway:
    return RobinhoodGateway(
        GatewayConfig(expected_manifest_digest=digest),
        load_manifest_text(dumps(document)),
        transport,
    )


# ===========================================================================
# §6 — Capability / manifest boundary (packaged artifact)
# ===========================================================================


class TestPackagedManifestBoundary:
    def test_exact_8_trading_denied_and_11_mutations_allowed(self) -> None:
        manifest = load_active_manifest()
        assert manifest.manifest_version == "2026.08.03.1"
        assert (
            manifest.digest
            == "sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b"
        )

        denied = {
            name
            for name, entry in manifest.capabilities.items()
            if entry.disposition == "denied"
        }
        allowed_mut = {
            name
            for name, entry in manifest.capabilities.items()
            if entry.disposition == "allowed" and entry.mutates
        }
        allowed_read = {
            name
            for name, entry in manifest.capabilities.items()
            if entry.disposition == "allowed" and not entry.mutates
        }
        assert denied == set(DENIED_TRADING)
        assert allowed_mut == set(ALLOWED_MUTATIONS)
        assert len(allowed_read) == 34
        for name in DENIED_TRADING:
            assert manifest.capabilities[name].mutates is True

    def test_capability_listing_exposes_mutates_flag(self) -> None:
        from rh_mcp.gateway import capability_listing

        listing = {c.capability: c for c in capability_listing(load_active_manifest())}
        for name in ALLOWED_MUTATIONS:
            assert listing[name].mutates is True
            assert listing[name].read_allowed is True
            assert listing[name].to_json_dict()["allowed"] is True
            assert listing[name].to_json_dict()["mutates"] is True
        for name in DENIED_TRADING:
            assert listing[name].read_allowed is False
            assert listing[name].to_json_dict()["allowed"] is False

    @pytest.mark.parametrize("capability", DENIED_TRADING)
    def test_each_packaged_denied_trading_tool_never_reaches_transport(
        self, capability: str
    ) -> None:
        """Independent of the synthetic-only denial tests in the repo suite."""
        manifest = load_active_manifest()
        # Build a SpyTransport whose discover surface matches the packaged
        # manifest so readiness can succeed; then invoke each denied name.
        tools = tuple(
            ObservedTool(
                name=entry.provider_tool_name,
                description=entry.description,
                input_schema=entry.input_schema,
                output_schema=entry.output_schema,
                annotations=entry.annotations,
            )
            for entry in manifest.capabilities.values()
        )

        class PackagedSpy:
            def __init__(self) -> None:
                self.call_tool_calls: list[tuple[str, dict[str, Any]]] = []

            async def discover(self) -> ObservedSurface:
                return ObservedSurface(tools=tools, complete=True)

            async def call_tool(
                self,
                provider_tool_name: str,
                arguments: Mapping[str, Any],
                *,
                output_schema: Mapping[str, Any] | None,
            ) -> ToolPayload:
                self.call_tool_calls.append((provider_tool_name, dict(arguments)))
                return ToolPayload(data={}, source="structured_content")

        transport = PackagedSpy()
        digest = manifest.digest
        gateway = RobinhoodGateway(
            GatewayConfig(expected_manifest_digest=digest),
            manifest,
            transport,  # type: ignore[arg-type]
        )
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke(capability, {}))
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED
        assert transport.call_tool_calls == []
        # Identical wording for unknown vs denied — no provider name leak.
        assert "place_" not in excinfo.value.message
        assert capability not in excinfo.value.message or True  # capability may equal message? 
        # The stable message must not disclose the provider tool name distinctly;
        # the reviewed message is generic:
        assert (
            excinfo.value.message
            == "capability is not a reviewed read capability of the active manifest"
        )


class TestCapabilityNameConfusion:
    @pytest.mark.parametrize(
        "name",
        [
            "Place_Equity_Order",
            "PLACE_EQUITY_ORDER",
            " place_equity_order",
            "place_equity_order ",
            "place_equity_order\n",
            "place_equity_order\x00",
            "plаce_equity_order",  # Cyrillic 'а'
            "place_equity_order\u200b",
            "synthetic_alpha_read",  # provider tool name, not capability
            123,
            None,
            ["place_equity_order"],
        ],
    )
    def test_confused_names_are_denied_before_transport(self, name: object) -> None:
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport)
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke(name, VALID_ARGS))  # type: ignore[arg-type]
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED
        assert transport.call_tool_calls == []


# ===========================================================================
# Finding P0 — public transport bypasses the manifest
# ===========================================================================


class TestFindingP0PublicTransportBypass:
    """DESIGN.md §1 / README claim: no public generic call_tool.

    v0.1.0 exports ``open_provider_session`` and ``ProviderTransport.call_tool``
    which accept an arbitrary provider tool name with no manifest check.
    """

    def test_transport_module_exports_generic_call_tool_surface(self) -> None:
        mod = importlib.import_module("rh_mcp.transport")
        public = set(getattr(mod, "__all__", []))
        # Secure expectation: these must NOT be public.
        leaked = public & {"open_provider_session", "ProviderTransport"}
        assert leaked == set(), (
            f"public transport escape hatch still exported: {sorted(leaked)}"
        )

    def test_call_tool_protocol_accepts_arbitrary_provider_name_without_manifest(
        self,
    ) -> None:
        """Secure expectation: ProviderTransport.call_tool must not be reachable
        as a public API that takes an arbitrary tool name.

        Against v0.1.0 this documents the bypass: the Protocol's call_tool
        signature takes ``provider_tool_name: str`` with no manifest type.
        """
        sig = inspect.signature(ProviderTransport.call_tool)
        params = list(sig.parameters)
        assert params[1] != "provider_tool_name", (
            "ProviderTransport.call_tool still takes an arbitrary provider_tool_name"
        )

    def test_open_provider_session_is_importable_from_installed_package(self) -> None:
        # Secure expectation: this import should fail or the name should be private.
        assert not hasattr(
            importlib.import_module("rh_mcp.transport"), "open_provider_session"
        ), "open_provider_session remains importable from rh_mcp.transport"


# ===========================================================================
# Finding P1 — validated arguments discarded; original mapping sent
# ===========================================================================


class _FlipAfterValidate(MutableMapping[str, Any]):
    """A mapping that looks valid during preflight, then flips before transport."""

    def __init__(self, good: dict[str, Any], bad: dict[str, Any]) -> None:
        self._good = dict(good)
        self._bad = dict(bad)
        self._flipped = False
        self.reads = 0

    def flip(self) -> None:
        self._flipped = True

    def _current(self) -> dict[str, Any]:
        return self._bad if self._flipped else self._good

    def __getitem__(self, key: str) -> Any:
        self.reads += 1
        return self._current()[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._current()[key] = value

    def __delitem__(self, key: str) -> None:
        del self._current()[key]

    def __iter__(self):
        return iter(self._current())

    def __len__(self) -> int:
        return len(self._current())

    def keys(self):  # noqa: D401 - Mapping protocol
        return self._current().keys()

    def items(self):
        return self._current().items()

    def values(self):
        return self._current().values()


class TestFindingP1ArgumentToctou:
    def test_invoke_must_send_the_validated_argument_snapshot(self) -> None:
        """Secure expectation: transport receives the validated snapshot, not a
        live mutable mapping that can change after preflight.
        """
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport)

        args = _FlipAfterValidate(
            good={"synthetic_symbol": "AAPL"},
            bad={"synthetic_symbol": "AAPL", "side": "buy", "quantity": "100"},
        )

        # Patch: flip between preflight returning and call_tool iterating.
        original_preflight = preflight_read

        def flipping_preflight(*a: Any, **k: Any) -> Any:
            entry = original_preflight(*a, **k)
            args.flip()
            return entry

        import rh_mcp.gateway as gateway_mod

        previous = gateway_mod.preflight_read
        gateway_mod.preflight_read = flipping_preflight  # type: ignore[assignment]
        try:
            run(gateway.invoke("alpha_reading", args))
        finally:
            gateway_mod.preflight_read = previous  # type: ignore[assignment]

        assert transport.call_tool_calls, "expected a transport call after valid preflight"
        sent_name, sent_args = transport.call_tool_calls[0]
        assert sent_name == "synthetic_alpha_read"
        # Secure property: undeclared keys must not reach the transport.
        assert "side" not in sent_args
        assert "quantity" not in sent_args
        assert sent_args == {"synthetic_symbol": "AAPL"}


# ===========================================================================
# Additional fail-closed properties that should hold on v0.1.0
# ===========================================================================


class TestFailClosedPropertiesThatShouldPass:
    def test_unknown_capability_matches_denied_message(self) -> None:
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport)
        with pytest.raises(GatewayError) as denied:
            run(gateway.invoke("gamma_reading", {"synthetic_quantity": 1}))
        with pytest.raises(GatewayError) as unknown:
            run(gateway.invoke("totally_unknown_capability", VALID_ARGS))
        assert denied.value.message == unknown.value.message
        assert transport.call_tool_calls == []

    def test_undeclared_root_key_never_reaches_transport(self) -> None:
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport)
        with pytest.raises(GatewayError) as excinfo:
            run(
                gateway.invoke(
                    "alpha_reading",
                    {"synthetic_symbol": "AAPL", "extra": "nope"},
                )
            )
        assert excinfo.value.code is ErrorCode.INPUT_INVALID
        assert transport.call_tool_calls == []

    def test_mismatched_expected_digest_blocks_invoke(self) -> None:
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(
            document, transport, "sha256:" + "a" * 64
        )
        with pytest.raises(GatewayError):
            run(gateway.invoke("alpha_reading", VALID_ARGS))
        assert transport.call_tool_calls == []

    def test_robinhood_gateway_itself_has_no_call_tool(self) -> None:
        methods = {
            n for n, _ in inspect.getmembers(RobinhoodGateway) if not n.startswith("_")
        }
        assert "call_tool" not in methods
        assert methods == {
            "capabilities",
            "invoke",
            "manifest_digest",
            "manifest_version",
            "readiness",
        }

    def test_open_gateway_has_no_disable_enforcement_flag(self) -> None:
        assert set(inspect.signature(open_gateway).parameters) == {
            "config",
            "store",
            "manifest",
            "transport",
        }


# ---------------------------------------------------------------------------
# Implementer's note on the only edit made to this file
# ---------------------------------------------------------------------------
#
# This file is the reviewer's, and it is kept as they wrote it apart from two
# lines, both concerning `open_provider_session`:
#
#   * the module-level `from rh_mcp.transport import ... open_provider_session`
#   * a trailing `_ = open_provider_session`
#
# They are removed because they are self-contradictory with the file's own
# assertion, not because that assertion is inconvenient.
# `test_open_provider_session_is_importable_from_installed_package` requires
# `hasattr(rh_mcp.transport, "open_provider_session")` to be False. In CPython
# `from M import n` and `hasattr(M, n)` resolve through the same lookup, so no
# implementation can satisfy the import and the assertion at once: while the
# finding stands the import works and the test fails, and the moment the
# finding is fixed the import raises `ImportError` and all 31 tests error out
# during collection.
#
# The trailing `_ = open_provider_session` and its comment ("imported for
# isinstance/name checks above") describe a use that does not exist — grep the
# file: the name appears nowhere else. So the two removed lines back no
# assertion, and removing them weakens nothing. Every assertion in this file,
# including all four that encode findings P0 and P1, is untouched.
#
# `ProviderTransport` and `ToolPayload` are still imported, because
# `test_call_tool_protocol_accepts_arbitrary_provider_name_without_manifest`
# genuinely inspects the former.
