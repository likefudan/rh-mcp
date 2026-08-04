"""Reviewer-authored adversarial tests for rh-mcp v0.2.0.

These extend the v0.1.0 adversarial suite with checks that the published
contract remains closed and that the P1 frozen-argument property holds on
the gateway path. They deliberately do **not** treat underscore-prefixed
internals as a published API: DESIGN.md §3 states in-process separation is
not a security boundary, and `tests/test_public_surface.py` documents the
same limit.

Run against the pinned release source:

    cd /path/to/46128a6
    uv sync --frozen
    uv run --frozen pytest security-review/v0.1.0/test_adversarial_review.py \
        security-review/v0.2.0/test_adversarial_review.py -v
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
from collections.abc import Coroutine, Mapping, MutableMapping
from types import MappingProxyType
from typing import Any

import pytest

from rh_mcp.config import GatewayConfig
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.gateway import RobinhoodGateway
from rh_mcp.manifest import ObservedSurface, ObservedTool, load_manifest_text
from rh_mcp.transport import ToolPayload
from tests.support import build_manifest, dumps

BASE_DIGEST = "sha256:3b7f113be230012d7f1949789401e60e9b84274ecf09f8a8ced31d5fc3e11250"
VALID_ARGS: dict[str, Any] = {"synthetic_symbol": "AAPL"}


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class SpyTransport:
    def __init__(self, document: dict[str, Any]) -> None:
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
        self.call_tool_calls: list[tuple[str, Mapping[str, Any], type]] = []

    async def discover(self) -> ObservedSurface:
        return ObservedSurface(tools=self.tools, complete=True)

    async def call_tool(
        self,
        reviewed_tool_name: str,
        arguments: Mapping[str, Any],
        *,
        output_schema: Mapping[str, Any] | None,
    ) -> ToolPayload:
        self.call_tool_calls.append(
            (reviewed_tool_name, arguments, type(arguments))
        )
        return ToolPayload(data={"synthetic_value": 1}, source="structured_content")


def gateway_for(document: dict[str, Any], transport: SpyTransport) -> RobinhoodGateway:
    return RobinhoodGateway(
        GatewayConfig(expected_manifest_digest=BASE_DIGEST),
        load_manifest_text(dumps(document)),
        transport,
    )


class TestPublishedContractClosed:
    def test_transport_star_import_is_only_value_types_and_egress_constant(self) -> None:
        ns: dict[str, Any] = {}
        exec("from rh_mcp.transport import *", ns)  # noqa: S102 - intentional surface probe
        names = sorted(k for k in ns if not k.startswith("_"))
        assert names == [
            "HttpJsonResponse",
            "PRODUCTION_EGRESS_HOSTS",
            "PayloadSource",
            "ToolPayload",
        ]

    def test_no_module_star_import_offers_call_tool_or_access_token(self) -> None:
        import pkgutil

        import rh_mcp

        forbidden = {"call_tool", "access_token"}
        for info in pkgutil.iter_modules(rh_mcp.__path__):
            module = importlib.import_module(f"rh_mcp.{info.name}")
            declared = getattr(module, "__all__", None)
            names = (
                list(declared)
                if declared is not None
                else [n for n in vars(module) if not n.startswith("_")]
            )
            for name in names:
                obj = getattr(module, name)
                for method in forbidden:
                    assert not callable(getattr(obj, method, None)), (
                        f"{module.__name__}.{name} publishes {method}"
                    )

    def test_legacy_open_provider_session_name_is_gone(self) -> None:
        mod = importlib.import_module("rh_mcp.transport")
        assert not hasattr(mod, "open_provider_session")
        assert "open_provider_session" not in getattr(mod, "__all__", [])

    def test_stored_token_provider_is_not_star_imported(self) -> None:
        auth = importlib.import_module("rh_mcp.auth")
        assert "StoredTokenProvider" not in auth.__all__


class TestP1FrozenSnapshotHolds:
    def test_invoke_sends_immutable_validated_snapshot(self) -> None:
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport)

        class Flip(MutableMapping[str, Any]):
            def __init__(self) -> None:
                self._good = dict(VALID_ARGS)
                self._bad = {
                    "synthetic_symbol": "AAPL",
                    "side": "buy",
                    "quantity": "100",
                }
                self._flipped = False

            def flip(self) -> None:
                self._flipped = True

            def _cur(self) -> dict[str, Any]:
                return self._bad if self._flipped else self._good

            def __getitem__(self, key: str) -> Any:
                return self._cur()[key]

            def __setitem__(self, key: str, value: Any) -> None:
                self._cur()[key] = value

            def __delitem__(self, key: str) -> None:
                del self._cur()[key]

            def __iter__(self):
                return iter(self._cur())

            def __len__(self) -> int:
                return len(self._cur())

        args = Flip()
        import rh_mcp.gateway as gateway_mod
        from rh_mcp.manifest import preflight_read as original

        def flipping_preflight(*a: Any, **k: Any) -> Any:
            result = original(*a, **k)
            args.flip()
            return result

        previous = gateway_mod.preflight_read
        gateway_mod.preflight_read = flipping_preflight  # type: ignore[assignment]
        try:
            run(gateway.invoke("alpha_reading", args))
        finally:
            gateway_mod.preflight_read = previous  # type: ignore[assignment]

        assert len(transport.call_tool_calls) == 1
        name, sent, sent_type = transport.call_tool_calls[0]
        assert name == "synthetic_alpha_read"
        assert dict(sent) == VALID_ARGS
        assert "side" not in sent and "quantity" not in sent
        assert sent_type is MappingProxyType
        with pytest.raises(TypeError):
            sent["x"] = 1  # type: ignore[index]


class TestGatewayPathStillDeniesTrading:
    def test_denied_synthetic_never_reaches_transport(self) -> None:
        document = build_manifest()
        transport = SpyTransport(document)
        gateway = gateway_for(document, transport)
        with pytest.raises(GatewayError) as excinfo:
            run(gateway.invoke("gamma_reading", {"synthetic_quantity": 1}))
        assert excinfo.value.code is ErrorCode.CAPABILITY_DENIED
        assert transport.call_tool_calls == []


class TestResidualPrivateImportDocumented:
    """Not a failure: records the DESIGN §3 residual for the report."""

    def test_underscore_session_opener_still_exists_for_in_process_callers(self) -> None:
        mod = importlib.import_module("rh_mcp.transport")
        opener = getattr(mod, "_open_provider_session", None)
        assert opener is not None
        assert callable(opener)
        # Private session still trusts the tool-name argument completely.
        session_cls = getattr(mod, "_PrivateSession")
        params = list(inspect.signature(session_cls.call_tool).parameters)
        assert "reviewed_tool_name" in params
