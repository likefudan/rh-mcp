"""Canonicalization and digest golden vectors (DESIGN.md §6, §11).

The literal expectations in this file *are* the specification of `rh-canon-1`.
They are written out by hand rather than computed, so a change to
`canonical.py` cannot quietly redefine what the digests mean: if the algorithm
moves, these tests break, and breaking them is the migration signal §6 asks for.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from rh_mcp.canonical import (
    CANONICALIZATION_VERSION,
    DIGEST_PREFIX,
    MAX_CANONICAL_DEPTH,
    MAX_INT_DIGITS,
    canonical_digest,
    canonicalize,
    tool_metadata_digest,
    tool_schema_digest,
)
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.models import is_digest

# --------------------------------------------------------------------------
# Golden canonical forms
# --------------------------------------------------------------------------

CANONICAL_FORM_VECTORS: list[tuple[str, Any, str]] = [
    ("empty object", {}, "{}"),
    ("empty array", [], "[]"),
    ("keys are sorted", {"b": 1, "a": 2}, '{"a":2,"b":1}'),
    (
        "nested structures keep array order and sort object keys",
        {"z": [1, 2, {"y": None, "x": True}], "a": "é"},
        '{"a":"é","z":[1,2,{"x":true,"y":null}]}',
    ),
    (
        "minimal escapes only",
        'a"b\\c\nd\tef\x00\x1f\x7f',
        '"a\\"b\\\\c\\nd\\tef\\u0000\\u001f\x7f"',
    ),
    (
        "numbers keep their decoded int/float identity",
        [1, 1.0, -0.0, 0.0, 1e30, 0.1, -3, 10**20],
        "[1,1.0,-0.0,0.0,1e+30,0.1,-3,100000000000000000000]",
    ),
    (
        "keys sort by Unicode code point, not UTF-16 code unit",
        {"￿": 1, "\U00010000": 2},
        '{"￿":1,"\U00010000":2}',
    ),
    ("non-ASCII is emitted literally", {"k": "é中\U0001f600"},
     '{"k":"é中\U0001f600"}'),
    ("literals", [True, False, None], "[true,false,null]"),
]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(value, expected) for _, value, expected in CANONICAL_FORM_VECTORS],
    ids=[name for name, _, _ in CANONICAL_FORM_VECTORS],
)
def test_canonical_form_golden_vector(value: Any, expected: str) -> None:
    assert canonicalize(value) == expected.encode("utf-8")


GOLDEN_DIGESTS: list[tuple[Any, str]] = [
    ({}, "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    ("hello", "sha256:5aa762ae383fbb727af3c7a36d4940a5b8c40a989452d2304fc958ff3f354e7a"),
    (
        {"z": [1, 2, {"y": None, "x": True}], "a": "é"},
        "sha256:b04f85ee723327dc6691ebde7d29f922cf12c52401a6280db865ba874beedbef",
    ),
]


@pytest.mark.parametrize(("value", "expected"), GOLDEN_DIGESTS)
def test_canonical_digest_golden_vector(value: Any, expected: str) -> None:
    assert canonical_digest(value) == expected


def test_digest_shape_matches_the_public_digest_contract() -> None:
    assert is_digest(canonical_digest({"any": "value"}))


def test_utf16_ordering_would_disagree() -> None:
    """Pin the deliberate divergence from RFC 8785/JCS (§6).

    JCS sorts object keys by UTF-16 code unit, which puts an astral character
    *before* U+FFFF because its high surrogate is 0xD800. `rh-canon-1` sorts by
    code point and puts it after. Anyone "aligning us with JCS" has to delete
    this test on purpose.
    """
    keys = ["￿", "\U00010000"]
    code_point_order = sorted(keys)
    utf16_order = sorted(keys, key=lambda key: key.encode("utf-16-be"))
    assert code_point_order != utf16_order
    assert canonicalize(dict.fromkeys(keys, 0)).decode() == '{"￿":0,"\U00010000":0}'


# --------------------------------------------------------------------------
# Properties DESIGN.md §6 states explicitly
# --------------------------------------------------------------------------


class TestInsignificantDifferencesDoNotChangeADigest:
    def test_object_key_order(self) -> None:
        assert canonical_digest({"a": 1, "b": 2}) == canonical_digest({"b": 2, "a": 1})

    def test_nested_object_key_order(self) -> None:
        left = {"outer": {"a": 1, "b": {"c": 1, "d": 2}}}
        right = {"outer": {"b": {"d": 2, "c": 1}, "a": 1}}
        assert canonical_digest(left) == canonical_digest(right)

    def test_insignificant_whitespace_in_the_source_text(self) -> None:
        compact = json.loads('{"a":[1,2],"b":{"c":3}}')
        spaced = json.loads('{\n  "a" : [ 1 , 2 ]\t,\n  "b" : { "c" : 3 }\n}')
        assert canonical_digest(compact) == canonical_digest(spaced)

    def test_a_list_and_a_tuple_are_the_same_json_array(self) -> None:
        assert canonical_digest({"a": [1, 2]}) == canonical_digest({"a": (1, 2)})


class TestMeaningfulDifferencesChangeADigest:
    def test_array_order(self) -> None:
        assert canonical_digest([1, 2]) != canonical_digest([2, 1])

    def test_nested_array_order(self) -> None:
        assert canonical_digest({"a": [{"x": 1}, {"y": 2}]}) != canonical_digest(
            {"a": [{"y": 2}, {"x": 1}]}
        )

    def test_a_value_change(self) -> None:
        assert canonical_digest({"a": 1}) != canonical_digest({"a": 2})

    def test_a_key_rename(self) -> None:
        assert canonical_digest({"a": 1}) != canonical_digest({"b": 1})

    def test_true_is_not_one(self) -> None:
        """`bool` is an `int` subclass; JSON's `true` is not the number 1."""
        assert canonical_digest([True]) != canonical_digest([1])
        assert canonicalize([True]) == b"[true]"
        assert canonicalize([1]) == b"[1]"

    def test_integer_and_float_spellings_stay_distinct(self) -> None:
        """The fail-closed direction: more drift alerts, never fewer (§6)."""
        assert canonical_digest([1]) != canonical_digest([1.0])
        assert canonical_digest([0.0]) != canonical_digest([-0.0])

    def test_an_absent_value_is_not_a_null_value(self) -> None:
        assert canonical_digest({"a": 1}) != canonical_digest({"a": 1, "b": None})

    def test_an_empty_object_is_not_an_empty_array(self) -> None:
        assert canonical_digest({}) != canonical_digest([])

    def test_a_string_is_not_the_number_it_spells(self) -> None:
        assert canonical_digest("1") != canonical_digest(1)


def test_canonicalization_is_stable_across_repeated_calls() -> None:
    value = {"b": [1, {"z": None, "a": "x"}], "a": 2.5}
    first = canonicalize(value)
    assert all(canonicalize(value) == first for _ in range(5))


def test_a_json_round_trip_preserves_the_digest() -> None:
    value = {"b": [1, {"z": None, "a": "x"}], "a": 2.5, "c": "é\U0001f600"}
    assert canonical_digest(json.loads(json.dumps(value))) == canonical_digest(value)


# --------------------------------------------------------------------------
# Rejections — everything here fails closed rather than being coerced
# --------------------------------------------------------------------------


class TestRejectsNonJsonValues:
    @pytest.mark.parametrize(
        "value",
        [
            {1, 2},
            b"bytes",
            bytearray(b"bytes"),
            object(),
            2 + 3j,
            range(3),
        ],
    )
    def test_non_json_types(self, value: Any) -> None:
        with pytest.raises(GatewayError) as excinfo:
            canonicalize(value)
        assert excinfo.value.code is ErrorCode.PROTOCOL_ERROR

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_floats(self, value: float) -> None:
        """A NaN fails open through every downstream comparison (§7.1)."""
        with pytest.raises(GatewayError, match="NaN or Infinity"):
            canonicalize([value])

    def test_non_string_object_keys(self) -> None:
        with pytest.raises(GatewayError, match="object keys must be strings"):
            canonicalize({1: "a"})

    def test_unpaired_surrogate_in_a_value(self) -> None:
        with pytest.raises(GatewayError, match="unpaired surrogates"):
            canonicalize(["\ud800"])

    def test_unpaired_surrogate_in_a_key(self) -> None:
        with pytest.raises(GatewayError, match="unpaired surrogates"):
            canonicalize({"\ud800": 1})

    def test_the_caller_chooses_the_error_code(self) -> None:
        with pytest.raises(GatewayError) as excinfo:
            canonicalize(object(), code=ErrorCode.NOT_READY)
        assert excinfo.value.code is ErrorCode.NOT_READY


def test_rejects_a_structure_deeper_than_the_rail() -> None:
    value: Any = "leaf"
    for _ in range(MAX_CANONICAL_DEPTH + 2):
        value = [value]
    with pytest.raises(GatewayError, match="nests deeper"):
        canonicalize(value)


def test_accepts_a_structure_at_the_rail() -> None:
    value: Any = "leaf"
    for _ in range(MAX_CANONICAL_DEPTH - 1):
        value = [value]
    assert canonicalize(value).endswith(b'"leaf"' + b"]" * (MAX_CANONICAL_DEPTH - 1))


def test_rejects_a_cyclic_structure_without_a_recursion_error() -> None:
    cycle: list[Any] = []
    cycle.append(cycle)
    with pytest.raises(GatewayError, match="nests deeper"):
        canonicalize(cycle)


def test_rejects_an_integer_wider_than_the_digit_limit() -> None:
    """Without the bound, CPython's int-to-str limit raises a bare ValueError."""
    with pytest.raises(GatewayError, match="limited to"):
        canonicalize(10 ** (MAX_INT_DIGITS + 10))


def test_accepts_a_large_integer_inside_the_digit_limit() -> None:
    assert canonicalize(10 ** (MAX_INT_DIGITS - 10)).startswith(b"1")


def test_the_digit_limit_does_not_widen_when_cpython_is_reconfigured() -> None:
    """`sys.set_int_max_str_digits` is process-global and any dependency can
    call it. The canonical form is a security contract and must not widen
    because something else raised an unrelated interpreter limit."""
    original = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(MAX_INT_DIGITS * 3)
    try:
        with pytest.raises(GatewayError, match="limited to"):
            canonicalize(10 ** (MAX_INT_DIGITS + 10))
    finally:
        sys.set_int_max_str_digits(original)


# --------------------------------------------------------------------------
# Per-tool digests (§6)
# --------------------------------------------------------------------------


SYNTHETIC_SCHEMA: dict[str, Any] = {"type": "object"}


class TestToolSchemaDigest:
    def test_golden_vector(self) -> None:
        assert tool_schema_digest("synthetic_alpha_read", SYNTHETIC_SCHEMA, None) == (
            "sha256:877c4cec9346f82077ebadeef34bafcb50e090507a54365727d9d16d59ce99c0"
        )

    def test_covers_the_provider_name(self) -> None:
        """Same schema, different tool: the digests must not be reusable."""
        assert tool_schema_digest("synthetic_a", SYNTHETIC_SCHEMA, None) != tool_schema_digest(
            "synthetic_b", SYNTHETIC_SCHEMA, None
        )

    def test_covers_the_input_schema(self) -> None:
        assert tool_schema_digest("t", {"type": "object"}, None) != tool_schema_digest(
            "t", {"type": "string"}, None
        )

    def test_covers_the_output_schema(self) -> None:
        assert tool_schema_digest("t", SYNTHETIC_SCHEMA, None) != tool_schema_digest(
            "t", SYNTHETIC_SCHEMA, {"type": "object"}
        )

    def test_no_output_schema_is_not_an_unconstrained_one(self) -> None:
        assert tool_schema_digest("t", SYNTHETIC_SCHEMA, None) != tool_schema_digest(
            "t", SYNTHETIC_SCHEMA, {}
        )

    def test_ignores_schema_key_order(self) -> None:
        assert tool_schema_digest("t", {"a": 1, "b": 2}, None) == tool_schema_digest(
            "t", {"b": 2, "a": 1}, None
        )


class TestToolMetadataDigest:
    def test_golden_vector(self) -> None:
        assert tool_metadata_digest("Synthetic alpha read.", {"readOnlyHint": True}) == (
            "sha256:be10464d495c1842dbb5a5290f527fb99732a453f5229004a0686115672d44c2"
        )

    def test_covers_the_description(self) -> None:
        assert tool_metadata_digest("a", {}) != tool_metadata_digest("b", {})

    def test_covers_the_annotations(self) -> None:
        """A flipped `readOnlyHint` changed the evidence a human reviewed (§2)."""
        assert tool_metadata_digest("a", {"readOnlyHint": True}) != tool_metadata_digest(
            "a", {"readOnlyHint": False}
        )

    def test_a_removed_annotation_is_visible(self) -> None:
        assert tool_metadata_digest("a", {"readOnlyHint": True}) != tool_metadata_digest("a", {})


def test_schema_and_metadata_digests_are_domain_separated() -> None:
    """Identical hashed content must not collide across digest kinds."""
    assert tool_schema_digest("t", {}, None) != tool_metadata_digest("t", {})


def test_every_derived_digest_covers_the_algorithm_version() -> None:
    """An algorithm revision must change every stored digest (§6)."""
    assert CANONICALIZATION_VERSION.encode() in canonicalize(
        {
            "digest_kind": "schema",
            "canonicalization": CANONICALIZATION_VERSION,
            "provider_tool_name": "t",
            "input_schema": {},
            "output_schema": None,
        }
    )
    assert tool_schema_digest("t", {}, None).startswith(DIGEST_PREFIX)
