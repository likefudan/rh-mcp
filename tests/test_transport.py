"""The private MCP transport (DESIGN.md §3, §4, §7.1, §8, §11).

Every test here drives the real MCP SDK client, the real Streamable HTTP
transport and the real guarded `httpx2` transport. The only substitution is
`httpx2.MockTransport` in place of a socket, so nothing in this file opens a
port, spawns a process, or resolves a name — and the §3 pinning, the streaming
byte cap, and the `Authorization` header are all live on every request.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import httpx2
import pytest

import rh_mcp.transport as transport
from rh_mcp.config import PRODUCTION_RESOURCE_URL, GatewayConfig, ResourceLimits
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.transport import (
    PRODUCTION_EGRESS_HOSTS,
    ToolPayload,
    open_provider_session,
)
from tests.synthetic import (
    DIGEST,
    SyntheticServer,
    deep_object,
    development_config,
    json_response,
    mapper,
    open_session,
    paged,
    production_config,
    tool,
)


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def refused(coro: Coroutine[Any, Any, Any]) -> GatewayError:
    with pytest.raises(GatewayError) as caught:
        run(coro)
    return caught.value


async def _discover(server: SyntheticServer, config: GatewayConfig | None = None) -> Any:
    async with open_session(server, config) as session:
        return await session.discover()


async def _call(
    server: SyntheticServer,
    arguments: Any = None,
    *,
    config: GatewayConfig | None = None,
    output_schema: Any = None,
    name: str = "synthetic_alpha_read",
) -> ToolPayload:
    async with open_session(server, config) as session:
        return await session.call_tool(
            name, {} if arguments is None else arguments, output_schema=output_schema
        )


# ==========================================================================
# Discovery and bounded pagination (§6.2, §8)
# ==========================================================================


def test_a_single_page_surface_is_complete() -> None:
    surface = run(_discover(SyntheticServer(pages=paged([tool("synthetic_alpha_read")]))))
    assert surface.complete is True
    assert [item.name for item in surface.tools] == ["synthetic_alpha_read"]


def test_pagination_follows_every_cursor_to_the_end() -> None:
    server = SyntheticServer(
        pages=paged([tool("synthetic_a")], [tool("synthetic_b")], [tool("synthetic_c")])
    )
    surface = run(_discover(server))
    assert surface.complete is True
    assert [item.name for item in surface.tools] == ["synthetic_a", "synthetic_b", "synthetic_c"]
    assert server.cursors == [None, "1", "2"]


def test_a_repeated_cursor_fails_closed_with_no_budget() -> None:
    """§6.2 lists a repeated cursor beside 'does not terminate'. Zero allowed."""
    stuck = [{"tools": [tool("synthetic_a")], "nextCursor": "same"}]
    error = refused(_discover(SyntheticServer(pages=stuck)))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "repeated a pagination cursor" in error.message


def test_a_cursor_repeat_is_caught_even_when_pages_would_still_be_allowed() -> None:
    """A generous page budget must not turn the cursor check into a delay."""
    stuck = [{"tools": [tool("synthetic_a")], "nextCursor": "same"}]
    config = production_config(max_discovery_pages=200)
    error = refused(_discover(SyntheticServer(pages=stuck), config))
    assert "repeated a pagination cursor" in error.message


def test_a_page_budget_reports_an_incomplete_surface_rather_than_a_partial_truth() -> None:
    pages = [
        {"tools": [tool(f"synthetic_{index}")], "nextCursor": str(index + 1)} for index in range(9)
    ]
    server = SyntheticServer(pages=pages)
    surface = run(_discover(server, production_config(max_discovery_pages=3)))
    assert surface.complete is False
    assert len(surface.tools) == 3


def test_a_tool_budget_reports_an_incomplete_surface() -> None:
    page = {"tools": [tool(f"synthetic_{index}") for index in range(10)]}
    surface = run(
        _discover(SyntheticServer(pages=[page]), production_config(max_discovery_tools=4))
    )
    assert surface.complete is False
    assert len(surface.tools) == 4


def test_a_non_terminating_provider_is_bounded_by_the_page_budget() -> None:
    """New cursor every page, forever: bounded, and never reported complete."""
    pages = [
        {"tools": [tool(f"synthetic_{index}")], "nextCursor": str(index + 1)} for index in range(50)
    ]
    server = SyntheticServer(pages=pages)
    surface = run(_discover(server, production_config(max_discovery_pages=5)))
    assert surface.complete is False
    assert server.methods.count("tools/list") == 5


def test_total_discovery_bytes_are_bounded_across_pages() -> None:
    filler = "x" * 400
    pages = [
        {"tools": [tool(f"synthetic_{index}", description=filler)], "nextCursor": str(index + 1)}
        for index in range(20)
    ]
    error = refused(
        _discover(SyntheticServer(pages=pages), production_config(max_discovery_bytes=1200))
    )
    assert error.code is ErrorCode.RESPONSE_TOO_LARGE
    assert "discovery read more than" in error.message


@pytest.mark.parametrize(
    "page",
    [
        {},
        {"tools": "not-an-array"},
        {"tools": ["not-an-object"]},
        {"tools": [{"inputSchema": {"type": "object"}}]},
        {"tools": [{"name": 5, "inputSchema": {"type": "object"}}]},
        {"tools": [{"name": "a"}]},
        {"tools": [{"name": "a", "inputSchema": "no"}]},
        {"tools": [{"name": "a", "inputSchema": {}, "description": 5}]},
        {"tools": [{"name": "a", "inputSchema": {}, "annotations": "no"}]},
        {"tools": [{"name": "a", "inputSchema": {}, "outputSchema": "no"}]},
    ],
)
def test_a_malformed_tools_list_page_is_a_protocol_error(page: dict[str, Any]) -> None:
    error = refused(_discover(SyntheticServer(pages=[page])))
    assert error.code is ErrorCode.PROTOCOL_ERROR


def test_an_empty_pagination_cursor_is_refused_by_name() -> None:
    """Pinned to this guard's own message.

    An empty cursor is valid MCP, so it reaches the gateway. Without this check
    it would be sent back as a cursor, fetch page one again, and be caught by
    the repeated-cursor rule — fail-closed, but reported as the wrong fault.
    """
    page = {"tools": [tool()], "nextCursor": ""}
    error = refused(_discover(SyntheticServer(pages=[page])))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "malformed pagination cursor" in error.message


@pytest.mark.parametrize("cursor", [7, [], {}, True])
def test_a_non_string_pagination_cursor_is_refused_by_shape(cursor: Any) -> None:
    """Reached directly, because the SDK's response model refuses it first.

    Defence in depth for the same reason as the content-mapping guards: the SDK
    is a dependency, not a security boundary, and a cursor is the one
    provider-controlled value that decides whether enumeration terminates.
    """
    with pytest.raises(GatewayError) as caught:
        transport._next_cursor({"tools": [], "nextCursor": cursor})
    assert caught.value.code is ErrorCode.PROTOCOL_ERROR
    assert "malformed pagination cursor" in caught.value.message


def test_discovery_preserves_annotation_fields_the_sdk_models_would_drop() -> None:
    """The reason discovery reads raw JSON instead of `types.Tool` (§2, §6).

    `mcp_types.ToolAnnotations` is a Pydantic model with `extra="ignore"`, so a
    vendor annotation validates away to nothing. If that happened here, the
    metadata digest would be identical before and after the provider added,
    changed, or removed it — and §2's "an annotation change is review evidence"
    would be silently false.
    """
    import mcp_types

    raw = {"readOnlyHint": True, "vendorRiskTier": "high"}
    assert mcp_types.ToolAnnotations.model_validate(raw).model_dump(
        by_alias=True, exclude_none=True
    ) == {"readOnlyHint": True}, "the SDK still drops unknown annotations; this test's premise"

    surface = run(_discover(SyntheticServer(pages=paged([tool(annotations=raw)]))))
    assert dict(surface.tools[0].annotations) == raw

    without = run(
        _discover(SyntheticServer(pages=paged([tool(annotations={"readOnlyHint": True})])))
    )
    assert surface.tools[0].metadata_digest != without.tools[0].metadata_digest


def test_discovery_preserves_unknown_top_level_tool_fields_in_the_input_schema() -> None:
    """The same fidelity property, on the schema that gets pinned."""
    schema = {"type": "object", "properties": {}, "x-vendor-constraint": {"max": 1}}
    surface = run(_discover(SyntheticServer(pages=paged([tool(input_schema=schema)]))))
    assert dict(surface.tools[0].input_schema) == schema


def test_a_null_description_and_an_empty_one_are_indistinguishable() -> None:
    """A documented fidelity gap, pinned so it cannot become a surprise.

    A reviewed manifest entry stores `description` as a string, so a provider
    that switches between `null` and `""` produces no digest change. Closing it
    is a §6 manifest-format change, not a transport change.
    """
    absent = run(_discover(SyntheticServer(pages=paged([tool(description=None)]))))
    empty = run(_discover(SyntheticServer(pages=paged([tool(description="")]))))
    assert absent.tools[0].metadata_digest == empty.tools[0].metadata_digest


def test_a_null_annotations_object_and_an_empty_one_are_indistinguishable() -> None:
    absent = run(_discover(SyntheticServer(pages=paged([tool(annotations=None)]))))
    empty = run(_discover(SyntheticServer(pages=paged([tool(annotations={})]))))
    assert absent.tools[0].metadata_digest == empty.tools[0].metadata_digest


def test_a_duplicate_tool_name_survives_into_the_surface_for_drift_to_report() -> None:
    """§6.2 needs the duplicate; deduplicating here would hide it."""
    page = {"tools": [tool("synthetic_a"), tool("synthetic_a", description="different")]}
    surface = run(_discover(SyntheticServer(pages=[page])))
    assert [item.name for item in surface.tools] == ["synthetic_a", "synthetic_a"]


def test_pagination_that_never_answers_times_out() -> None:
    def stall(method: str, params: Any, request_id: Any) -> Any:
        raise AssertionError  # pragma: no cover - replaced below

    async def slow(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "tools/list":
            await asyncio.sleep(5)
        return await SyntheticServer()(request)

    del stall
    error = refused(
        _discover(
            slow,  # type: ignore[arg-type]
            production_config(pagination_timeout_s=0.2, read_timeout_s=5, total_timeout_s=5),
        )
    )
    assert error.code is ErrorCode.TIMEOUT


# ==========================================================================
# Response bounds (§8)
# ==========================================================================


def test_response_depth_is_bounded() -> None:
    page = {"tools": [tool(input_schema={"type": "object", "deep": deep_object(30)})]}
    error = refused(_discover(SyntheticServer(pages=[page]), production_config(max_json_depth=8)))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "nests deeper" in error.message


def test_response_node_count_is_bounded() -> None:
    server = SyntheticServer(
        call_result={"structuredContent": {"items": list(range(500))}}
    )
    error = refused(_call(server, config=production_config(max_response_nodes=50)))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "JSON nodes" in error.message


def test_response_string_length_is_bounded() -> None:
    server = SyntheticServer(call_result={"structuredContent": {"blob": "y" * 5000}})
    error = refused(_call(server, config=production_config(max_response_string_length=100)))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "longer than" in error.message


def test_an_object_key_longer_than_the_string_bound_is_refused() -> None:
    server = SyntheticServer(call_result={"structuredContent": {"k" * 5000: 1}})
    error = refused(_call(server, config=production_config(max_response_string_length=100)))
    assert "object key longer than" in error.message


def test_an_oversized_response_is_aborted_while_it_is_still_being_read() -> None:
    """§8: the cap fires during the read, not after the payload is resident."""
    server = SyntheticServer(call_result={"structuredContent": {"blob": "z" * 20_000}})
    error = refused(
        _call(server, config=production_config(max_response_bytes=2048, max_json_depth=8))
    )
    assert error.code is ErrorCode.RESPONSE_TOO_LARGE
    assert "while still being read" in error.message


def test_the_streaming_cap_stops_consuming_the_body_at_the_limit() -> None:
    """The cap directly: a long stream is abandoned, not drained."""
    delivered = 0

    class Endless:
        async def __aiter__(self) -> Any:
            nonlocal delivered
            for _ in range(1000):
                delivered += 1
                yield b"x" * 1024

        async def aclose(self) -> None:
            return None

    capped = transport._CappedStream(Endless(), 4096, transport._Fault())  # type: ignore[arg-type]

    async def drain() -> None:
        async for _ in capped:
            pass

    with pytest.raises(GatewayError) as caught:
        run(drain())
    assert caught.value.code is ErrorCode.RESPONSE_TOO_LARGE
    assert delivered <= 6, "the body kept streaming past the cap"


# ==========================================================================
# Request bounds (§8)
# ==========================================================================


def test_request_size_is_bounded_before_anything_is_sent() -> None:
    """The bound that fires in `call_tool`, not the one in the HTTP guard.

    Both exist, and the outer one would keep the request off the wire on its
    own — which is why the message is asserted. Without it this test passes
    with the inner bound deleted, and the §8 requirement that a request be
    measured before it is handed to the SDK would be unproved.
    """
    server = SyntheticServer()
    error = refused(
        _call(server, {"blob": "q" * 5000}, config=production_config(max_request_bytes=1024))
    )
    assert error.code is ErrorCode.INPUT_INVALID
    assert error.message == "tool arguments serializes to more than 1024 bytes"
    assert "tools/call" not in server.methods


def test_request_depth_is_bounded_before_anything_is_sent() -> None:
    server = SyntheticServer()
    error = refused(
        _call(server, deep_object(30), config=production_config(max_json_depth=8))
    )
    assert error.code is ErrorCode.INPUT_INVALID
    assert "tools/call" not in server.methods


def test_non_json_arguments_are_refused_as_caller_input() -> None:
    server = SyntheticServer()
    error = refused(_call(server, {"when": object()}))
    assert error.code is ErrorCode.INPUT_INVALID
    assert "tools/call" not in server.methods


def test_non_finite_arguments_are_refused() -> None:
    """Pinned to the bounded walk's own message.

    Canonicalization also refuses NaN, so a looser assertion would pass with
    this guard removed. A NaN satisfies every numeric threshold a consumer
    applies, so the walk that produces the payload must refuse it itself.
    """
    server = SyntheticServer()
    error = refused(_call(server, {"price": float("nan")}))
    assert error.code is ErrorCode.INPUT_INVALID
    assert error.message == "tool arguments may not contain NaN or Infinity"


def test_arguments_must_be_an_object() -> None:
    error = refused(_call(SyntheticServer(), ["not", "an", "object"]))
    assert error.code is ErrorCode.INPUT_INVALID


# ==========================================================================
# §7.1 content mapping
# ==========================================================================


ALPHA_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"synthetic_value": {"type": "number"}},
    "required": ["synthetic_value"],
    "additionalProperties": False,
}


def test_structured_content_is_accepted_and_is_authoritative() -> None:
    payload = run(_call(SyntheticServer(call_result={"structuredContent": {"a": 1}})))
    assert payload.source == "structured_content"
    assert dict(payload.data) == {"a": 1}
    assert payload.warnings == ()


def test_structured_content_is_checked_against_the_pinned_output_schema() -> None:
    server = SyntheticServer(call_result={"structuredContent": {"synthetic_value": 1.5}})
    payload = run(_call(server, output_schema=ALPHA_OUTPUT_SCHEMA))
    assert dict(payload.data) == {"synthetic_value": 1.5}


def test_structured_content_that_violates_the_pinned_schema_is_refused() -> None:
    server = SyntheticServer(call_result={"structuredContent": {"synthetic_value": "no"}})
    error = refused(_call(server, output_schema=ALPHA_OUTPUT_SCHEMA))
    assert error.code is ErrorCode.PROTOCOL_ERROR


def test_structured_content_with_an_unexpected_property_is_refused() -> None:
    server = SyntheticServer(
        call_result={"structuredContent": {"synthetic_value": 1, "account_number": "9876"}}
    )
    error = refused(_call(server, output_schema=ALPHA_OUTPUT_SCHEMA))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "9876" not in error.message
    assert "account_number" not in error.message


def test_structured_content_that_is_not_an_object_is_refused() -> None:
    """Reached through `_map_result`, because the SDK refuses it first.

    That is defence in depth working, not a redundant check: the SDK is a
    dependency, not a security boundary, and a later MCP revision that widens
    `structuredContent` to any JSON value would hand this an array. `data` in a
    `ResultEnvelope` is an object, so the gateway keeps its own guard.
    """
    with pytest.raises(GatewayError) as caught:
        mapper()._map_result({"structuredContent": [1, 2, 3]}, None)
    assert caught.value.code is ErrorCode.PROTOCOL_ERROR
    assert "not a JSON object" in caught.value.message


def test_content_blocks_the_sdk_would_reject_are_refused_by_the_gateway_too() -> None:
    """The same defence-in-depth argument, for content the SDK screens out."""
    with pytest.raises(GatewayError) as no_type:
        mapper()._map_result({"content": [{"text": "{}"}]}, None)
    assert "unsupported result content" in no_type.value.message

    with pytest.raises(GatewayError) as unknown_type:
        mapper()._map_result({"content": [{"type": "video", "data": "AAA="}]}, None)
    assert "unsupported result content" in unknown_type.value.message

    with pytest.raises(GatewayError) as malformed:
        mapper()._map_result({"content": ["not-a-block"]}, None)
    assert "unsupported result content" in malformed.value.message

    with pytest.raises(GatewayError) as no_text:
        mapper()._map_result({"content": [{"type": "text", "text": 5}]}, None)
    assert "carries no string text" in no_text.value.message


def test_a_text_block_larger_than_the_response_bound_is_refused_before_decoding() -> None:
    """The pre-decode size check, reached through `_map_result`.

    End-to-end it is unreachable by construction: a text block lives inside the
    response envelope, so a block over `max_response_bytes` means an envelope
    over `max_response_bytes`, and the streaming cap aborts the body first.
    Both orderings refuse; this exercises the inner one so a change to the
    outer one cannot silently remove it.
    """
    oversized = json.dumps({"blob": "w" * 5000})
    with pytest.raises(GatewayError) as caught:
        mapper(max_response_bytes=1024)._map_result(
            {"content": [{"type": "text", "text": oversized}]}, None
        )
    assert caught.value.code is ErrorCode.RESPONSE_TOO_LARGE
    assert "exceeds 1024 bytes" in caught.value.message


def test_a_duplicated_text_block_beside_structured_content_is_a_warning_not_a_conflict() -> None:
    """MCP tells servers to duplicate the JSON as text for older clients."""
    server = SyntheticServer(
        call_result={
            "structuredContent": {"a": 1},
            "content": [{"type": "text", "text": '{"a": 1}'}],
        }
    )
    payload = run(_call(server))
    assert payload.source == "structured_content"
    assert dict(payload.data) == {"a": 1}
    assert len(payload.warnings) == 1
    assert "discarded" in payload.warnings[0]


def test_a_single_text_block_is_decoded_by_the_explicit_rule() -> None:
    server = SyntheticServer(
        call_result={"content": [{"type": "text", "text": '{"synthetic_value": 2}'}]}
    )
    payload = run(_call(server, output_schema=ALPHA_OUTPUT_SCHEMA))
    assert payload.source == "text_content"
    assert dict(payload.data) == {"synthetic_value": 2}
    assert any("decoding a text block" in warning for warning in payload.warnings)


def test_a_decoded_text_block_is_also_checked_against_the_pinned_schema() -> None:
    server = SyntheticServer(
        call_result={"content": [{"type": "text", "text": '{"synthetic_value": "no"}'}]}
    )
    error = refused(_call(server, output_schema=ALPHA_OUTPUT_SCHEMA))
    assert error.code is ErrorCode.PROTOCOL_ERROR


@pytest.mark.parametrize(
    "text, expected, fragment",
    [
        ("not json at all", ErrorCode.PROTOCOL_ERROR, "not valid JSON"),
        ("[1, 2, 3]", ErrorCode.PROTOCOL_ERROR, "other than a JSON object"),
        ('"a string"', ErrorCode.PROTOCOL_ERROR, "other than a JSON object"),
        ("42", ErrorCode.PROTOCOL_ERROR, "other than a JSON object"),
        # Pinned to `parse_constant`'s own wording: the bounded walk would
        # also refuse a NaN afterwards, so a looser match would pass with the
        # decoder-level guard deleted. Refusing at decode is the stronger
        # position — the value never exists.
        ('{"a": NaN}', ErrorCode.PROTOCOL_ERROR, "text payload contains the literal NaN"),
        (
            '{"a": Infinity}',
            ErrorCode.PROTOCOL_ERROR,
            "text payload contains the literal Infinity",
        ),
        ('{"a": 1, "a": 2}', ErrorCode.PROTOCOL_ERROR, "same key twice"),
    ],
)
def test_the_text_decoding_rule_refuses_everything_outside_it(
    text: str, expected: ErrorCode, fragment: str
) -> None:
    server = SyntheticServer(call_result={"content": [{"type": "text", "text": text}]})
    error = refused(_call(server))
    assert error.code is expected
    assert fragment in error.message


def test_a_text_block_deeper_than_the_json_depth_bound_is_refused_before_decoding() -> None:
    text = "[" * 500 + "]" * 500
    error = refused(
        _call(
            SyntheticServer(call_result={"content": [{"type": "text", "text": text}]}),
            config=production_config(max_json_depth=16),
        )
    )
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "nests deeper" in error.message


@pytest.mark.parametrize(
    "block",
    [
        {"type": "image", "data": "AAA=", "mimeType": "image/png"},
        {"type": "audio", "data": "AAA=", "mimeType": "audio/wav"},
        {"type": "resource_link", "name": "r", "uri": "https://example.invalid/r"},
        {
            "type": "resource",
            "resource": {"uri": "https://example.invalid/r", "text": "{}"},
        },
    ],
)
def test_every_unsupported_content_type_is_a_protocol_error(block: dict[str, Any]) -> None:
    error = refused(_call(SyntheticServer(call_result={"content": [block]})))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "unsupported result content" in error.message


def test_an_unsupported_block_beside_structured_content_is_still_refused() -> None:
    server = SyntheticServer(
        call_result={
            "structuredContent": {"a": 1},
            "content": [{"type": "image", "data": "AAA=", "mimeType": "image/png"}],
        }
    )
    error = refused(_call(server))
    assert error.code is ErrorCode.PROTOCOL_ERROR


def test_two_text_blocks_are_ambiguous() -> None:
    server = SyntheticServer(
        call_result={
            "content": [
                {"type": "text", "text": '{"a": 1}'},
                {"type": "text", "text": '{"a": 2}'},
            ]
        }
    )
    error = refused(_call(server))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "ambiguous" in error.message


def test_no_payload_at_all_is_a_protocol_error() -> None:
    error = refused(_call(SyntheticServer(call_result={"content": []})))
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "neither structured content nor a text block" in error.message


def test_content_that_is_not_an_array_is_a_protocol_error() -> None:
    error = refused(_call(SyntheticServer(call_result={"content": "text"})))
    assert error.code is ErrorCode.PROTOCOL_ERROR


def test_provider_error_content_is_sanitized() -> None:
    """§7.3: the provider's own text never reaches a consumer."""
    server = SyntheticServer(
        call_result={
            "isError": True,
            "content": [
                {"type": "text", "text": "account 8675309 is restricted; token abc123"}
            ],
        }
    )
    error = refused(_call(server))
    assert error.code is ErrorCode.PROVIDER_ERROR
    assert "8675309" not in error.message
    assert "abc123" not in error.message


def test_an_is_error_result_is_refused_even_when_it_carries_structured_content() -> None:
    server = SyntheticServer(
        call_result={"isError": True, "structuredContent": {"a": 1}}
    )
    assert refused(_call(server)).code is ErrorCode.PROVIDER_ERROR


# ==========================================================================
# Production pinning and egress (§3)
# ==========================================================================


def test_the_egress_allowlist_is_exactly_the_three_documented_hosts() -> None:
    assert PRODUCTION_EGRESS_HOSTS == {
        "agent.robinhood.com",
        "robinhood.com",
        "api.robinhood.com",
    }


def _guard(config: GatewayConfig | None = None) -> Any:
    return transport._GuardedAsyncTransport(
        httpx2.MockTransport(lambda request: httpx2.Response(200)),
        transport._EgressPolicy.for_config(production_config() if config is None else config),
        transport._Fault(),
        None,
    )


def _egress(url: str, config: GatewayConfig | None = None) -> GatewayError:
    guard = _guard(config)
    request = httpx2.Request("POST", url, content=b"{}")
    with pytest.raises(GatewayError) as caught:
        run(guard.handle_async_request(request))
    return caught.value


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/mcp",
        "https://agent.robinhood.com.evil.example/mcp",
        "https://127.0.0.1/mcp",
    ],
)
def test_production_egress_outside_the_allowlist_is_refused(url: str) -> None:
    error = _egress(url)
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "outside this deployment's allowed origins" in error.message


@pytest.mark.parametrize(
    "url",
    [
        "https://agent.robinhood.com:8443/mcp/trading",
        "https://api.robinhood.com:9999/oauth2/token/",
        "https://robinhood.com:1/oauth",
        "https://agent.robinhood.com:80/mcp/trading",
    ],
)
def test_a_pinned_host_on_an_unpinned_port_is_refused(url: str) -> None:
    """§3 pins an origin, not a hostname.

    Nothing in this step can reach a URL like these — the resource URL is
    pinned configuration and redirects are rejected. Step 4 can: §5.0 takes
    `authorization_endpoint`, `token_endpoint` and `registration_endpoint`
    from the provider's own metadata document, so a document naming
    `https://api.robinhood.com:9999/oauth2/token/` would arrive here, and what
    gets sent to a token endpoint is a PKCE code exchange. A host-only
    allowlist passes every one of these.
    """
    error = _egress(url)
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "outside this deployment's allowed origins" in error.message


@pytest.mark.parametrize(
    "url",
    [
        "https://agent.robinhood.com/mcp/trading",
        "https://agent.robinhood.com:443/mcp/trading",
    ],
)
def test_the_https_default_port_is_allowed_however_it_is_spelled(url: str) -> None:
    """`https://h/x` and `https://h:443/x` are the same origin.

    `httpx2` reports `URL.port` as None for a scheme default, so without the
    normalisation one spelling would miss the allowlist and the pinned
    endpoint would be unreachable when written the other way.
    """
    guard = _guard()
    request = httpx2.Request("POST", url, content=b"{}")
    response = run(guard.handle_async_request(request))
    assert response.status_code == 200


def test_a_development_target_is_pinned_to_its_own_port() -> None:
    """A dev server on 9100 must not be reachable on 9101."""
    config = development_config("http://127.0.0.1:9100/mcp")
    assert transport._EgressPolicy.for_config(config).allowed_origins == {("127.0.0.1", 9100)}
    error = _egress("http://127.0.0.1:9101/mcp", config)
    assert "outside this deployment's allowed origins" in error.message


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com@agent.robinhood.com/mcp/trading",
        "https://user:s3cret@agent.robinhood.com/mcp/trading",
    ],
)
def test_an_egress_url_carrying_userinfo_is_refused_and_never_echoed(url: str) -> None:
    """Not a bypass — the destination really is `agent.robinhood.com`.

    It is refused because `httpx2` turns userinfo into an `Authorization:
    Basic` header, which would then race the bearer token the guard sets, and
    because a URL carrying a credential is a URL that can leak one.
    """
    error = _egress(url)
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "may not carry userinfo" in error.message
    assert "s3cret" not in error.message
    assert "evil.example.com" not in error.message


def test_production_egress_must_use_https() -> None:
    policy = transport._EgressPolicy.for_config(production_config())
    guard = transport._GuardedAsyncTransport(
        httpx2.MockTransport(lambda request: httpx2.Response(200)),
        policy,
        transport._Fault(),
        None,
    )
    request = httpx2.Request("POST", "http://agent.robinhood.com/mcp/trading", content=b"{}")
    with pytest.raises(GatewayError) as caught:
        run(guard.handle_async_request(request))
    assert "must use https" in caught.value.message


def test_a_development_policy_allows_only_its_own_loopback_host() -> None:
    policy = transport._EgressPolicy.for_config(development_config("http://127.0.0.1:9100/mcp"))
    assert policy.allowed_hosts == {"127.0.0.1"}
    assert policy.require_https is False
    assert "agent.robinhood.com" not in policy.allowed_hosts


def test_the_production_policy_pins_every_documented_host_to_the_https_port() -> None:
    policy = transport._EgressPolicy.for_config(production_config())
    assert policy.allowed_origins == {(host, 443) for host in PRODUCTION_EGRESS_HOSTS}


def test_a_programmatic_redirect_is_rejected() -> None:
    async def redirector(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "tools/list":
            return httpx2.Response(
                302, headers={"location": "https://robinhood.com/elsewhere"}
            )
        return await SyntheticServer()(request)

    error = refused(_discover(redirector))  # type: ignore[arg-type]
    assert error.code is ErrorCode.PROTOCOL_ERROR
    assert "redirect" in error.message


def test_the_http_client_never_follows_redirects() -> None:
    client = transport._build_http_client(
        production_config(), transport._Fault(), None,
        inner=httpx2.MockTransport(lambda request: httpx2.Response(200)),
    )
    assert client.follow_redirects is False


def test_tls_verification_cannot_be_switched_off_anywhere_in_this_module() -> None:
    """§3: 'TLS verification cannot be disabled.'

    A source-level assertion because the property is the *absence* of a knob.
    `httpx2` verifies by default; the only way to lose that is for someone to
    add a `verify=` argument, and this is what notices.
    """
    source = Path(transport.__file__).read_text(encoding="utf-8")
    assert "verify=" not in source
    assert "follow_redirects=True" not in source


def test_the_server_initiated_get_stream_is_answered_locally_with_no_egress() -> None:
    """The SDK does open the notification GET; the guard answers it itself.

    The synthetic server records every request that reached it. A GET must not
    be among them: it was answered with a local 405 and no egress. The DELETE
    the SDK sends to terminate the session does reach the server, which is
    correct and is why this asserts on GET rather than on POST-only.
    """
    server = SyntheticServer()
    run(_discover(server))
    assert server.requests
    assert not any(request.method == "GET" for request in server.requests)


def test_a_production_session_may_only_target_the_pinned_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = production_config()
    monkeypatch.setattr(
        GatewayConfig,
        "effective_resource_url",
        property(lambda self: "https://agent.robinhood.com/mcp/other"),
    )

    async def attempt() -> None:
        async with open_provider_session(config):
            pass  # pragma: no cover - the guard fires first

    error = refused(attempt())
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "pinned Robinhood resource URL" in error.message


def test_the_public_entry_point_reaches_the_pinned_url_over_the_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`open_provider_session` itself, with only the socket replaced."""
    server = SyntheticServer()
    monkeypatch.setattr(transport, "_new_base_transport", lambda: httpx2.MockTransport(server))

    async def go() -> Any:
        async with open_provider_session(production_config()) as session:
            return await session.discover()

    surface = run(go())
    assert surface.complete is True
    assert {str(request.url) for request in server.requests} == {PRODUCTION_RESOURCE_URL}


# ==========================================================================
# HTTP status handling (§7.3)
# ==========================================================================


@pytest.mark.parametrize("status", [401, 403])
def test_a_rejected_credential_becomes_auth_required(status: int) -> None:
    async def unauthorized(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "tools/list":
            return httpx2.Response(status, content=b"token xyz for account 42 is invalid")
        return await SyntheticServer()(request)

    error = refused(_discover(unauthorized))  # type: ignore[arg-type]
    assert error.code is ErrorCode.AUTH_REQUIRED
    assert "xyz" not in error.message
    assert "42" not in error.message


def test_a_server_failure_becomes_a_retryable_provider_error() -> None:
    async def broken(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "tools/list":
            return httpx2.Response(503, content=b"upstream down for account 42")
        return await SyntheticServer()(request)

    error = refused(_discover(broken))  # type: ignore[arg-type]
    assert error.code is ErrorCode.PROVIDER_ERROR
    assert error.retryable is True
    assert "42" not in error.message


def test_a_jsonrpc_error_never_carries_the_providers_message() -> None:
    async def rpc_error(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "tools/call":
            return json_response(
                {
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {
                        "code": -32603,
                        "message": "account 8675309 has no positions",
                    },
                }
            )
        return await SyntheticServer()(request)

    error = refused(_call(rpc_error))  # type: ignore[arg-type]
    assert error.code is ErrorCode.PROVIDER_ERROR
    assert "8675309" not in error.message


def test_a_malformed_mcp_result_is_a_protocol_error() -> None:
    async def malformed(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "tools/list":
            return json_response({"jsonrpc": "2.0", "id": body["id"], "result": "not-an-object"})
        return await SyntheticServer()(request)

    error = refused(_discover(malformed))  # type: ignore[arg-type]
    assert error.code is ErrorCode.PROTOCOL_ERROR


# ==========================================================================
# Authorization header handling (§5.2, §7.3)
# ==========================================================================


class _Token:
    def __init__(self, value: str) -> None:
        self.value = value

    async def access_token(self) -> str:
        return self.value


def _session_with_token(server: SyntheticServer, token: str) -> Any:
    from mcp.client.streamable_http import streamable_http_client

    config = production_config()
    fault = transport._Fault()
    client = transport._build_http_client(
        config, fault, _Token(token), inner=httpx2.MockTransport(server)
    )
    url = config.effective_resource_url
    assert url is not None

    async def go() -> Any:
        async with client:
            async with transport._open_over_connector(
                lambda: streamable_http_client(url, http_client=client), config, fault
            ) as session:
                return await session.discover()

    return go()


def test_a_bearer_token_is_attached_to_every_outbound_request() -> None:
    server = SyntheticServer()
    run(_session_with_token(server, "synthetic-token"))
    assert server.requests
    for request in server.requests:
        assert request.headers["authorization"] == "Bearer synthetic-token"


@pytest.mark.parametrize("token", ["bad\r\nX-Injected: 1", "with space\n", "tab\there", ""])
def test_a_token_that_cannot_appear_in_a_header_is_refused_and_never_echoed(
    token: str,
) -> None:
    server = SyntheticServer()
    error = refused(_session_with_token(server, token))
    assert error.code is ErrorCode.AUTH_REQUIRED
    assert token.strip() == "" or token not in error.message
    assert not server.requests


# ==========================================================================
# Timeouts, cancellation, concurrency, and the no-retry rule (§8)
# ==========================================================================


def test_a_slow_tool_call_times_out() -> None:
    server = SyntheticServer()
    server.delay_s = 2.0
    error = refused(
        _call(server, config=production_config(total_timeout_s=0.3, read_timeout_s=5))
    )
    assert error.code is ErrorCode.TIMEOUT


def test_cancellation_propagates_instead_of_becoming_a_gateway_error() -> None:
    """A cancelled read must stay cancelled, or a caller's scope never exits."""
    server = SyntheticServer()
    server.delay_s = 5.0

    async def go() -> None:
        async with open_session(server) as session:
            task = asyncio.ensure_future(
                session.call_tool("synthetic_alpha_read", {}, output_schema=None)
            )
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    run(go())


def test_concurrent_calls_never_exceed_the_configured_limit() -> None:
    server = SyntheticServer()
    server.delay_s = 0.05

    async def go() -> None:
        async with open_session(server, production_config(max_concurrent_calls=2)) as session:
            await asyncio.gather(
                *(
                    session.call_tool("synthetic_alpha_read", {}, output_schema=None)
                    for _ in range(8)
                )
            )

    run(go())
    assert server.call_count == 8
    assert server.max_in_flight <= 2


def test_a_failing_tool_call_is_never_retried() -> None:
    """§8: no automatic retry, whatever `idempotentHint` says."""
    attempts = 0

    async def failing(request: httpx2.Request) -> httpx2.Response:
        nonlocal attempts
        body = json.loads(request.content)
        if body.get("method") == "tools/call":
            attempts += 1
            return json_response(
                {
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32603, "message": "transient"},
                }
            )
        return await SyntheticServer()(request)

    refused(_call(failing))  # type: ignore[arg-type]
    assert attempts == 1


def test_an_idempotent_hint_does_not_earn_a_retry() -> None:
    attempts = 0
    annotated = tool(annotations={"readOnlyHint": True, "idempotentHint": True})

    async def failing(request: httpx2.Request) -> httpx2.Response:
        nonlocal attempts
        body = json.loads(request.content)
        if body.get("method") == "tools/call":
            attempts += 1
            return httpx2.Response(500, content=b"nope")
        return await SyntheticServer(pages=paged([annotated]))(request)

    async def go() -> None:
        async with open_session(failing) as session:  # type: ignore[arg-type]
            await session.discover()
            await session.call_tool("synthetic_alpha_read", {}, output_schema=None)

    with pytest.raises(GatewayError):
        run(go())
    assert attempts == 1


# ==========================================================================
# Development stdio target (§3)
# ==========================================================================


def test_a_stdio_development_target_refuses_an_access_token() -> None:
    config = GatewayConfig(
        expected_manifest_digest=DIGEST,
        mode="development",
        credential_adapter="in_memory",
        credential_namespace="dev-rh-mcp",
        dev_stdio_command="/bin/false",
        limits=ResourceLimits(),
    )

    async def go() -> None:
        async with open_provider_session(config, token_provider=_Token("x")):
            pass  # pragma: no cover - the guard fires first

    error = refused(go())
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "must not be given an access token" in error.message


# ==========================================================================
# The SDK-neutral payload type
# ==========================================================================


def test_a_tool_payload_refuses_a_non_object_data() -> None:
    with pytest.raises(GatewayError):
        ToolPayload(data=[1, 2], source="structured_content")  # type: ignore[arg-type]


def test_a_bounded_payload_is_immutable() -> None:
    payload = run(_call(SyntheticServer(call_result={"structuredContent": {"a": {"b": 1}}})))
    with pytest.raises(TypeError):
        payload.data["a"] = 2  # type: ignore[index]
