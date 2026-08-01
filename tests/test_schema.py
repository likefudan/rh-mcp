"""The strict-subset schema validator (DESIGN.md §7.1).

The test that matters most in this file is the negative one: an unknown
keyword must be *rejected*, not ignored. That is the single behaviour that
distinguishes this validator from the `jsonschema` library the design forbids,
and it is the one a well-meaning refactor would remove.
"""

from __future__ import annotations

from typing import Any

import pytest

from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.schema import (
    SUPPORTED_KEYWORDS,
    ensure_schema_supported,
    validate_instance,
)


def check(instance: Any, schema: Any) -> None:
    validate_instance(instance, schema)


def refused(instance: Any, schema: Any) -> GatewayError:
    with pytest.raises(GatewayError) as caught:
        validate_instance(instance, schema)
    return caught.value


# --------------------------------------------------------------------------
# The default-deny property
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "keyword, value",
    [
        ("$ref", "#/definitions/x"),
        ("if", {"type": "string"}),
        ("then", {"type": "string"}),
        ("patternProperties", {"^a": {"type": "string"}}),
        ("propertyNames", {"type": "string"}),
        ("dependentSchemas", {"a": {"type": "string"}}),
        ("not", {"type": "string"}),
        ("format", "date-time"),
        ("contains", {"type": "string"}),
        ("unevaluatedProperties", False),
        ("misspelledRequired", ["a"]),
    ],
)
def test_an_unimplemented_keyword_is_rejected_not_ignored(keyword: str, value: Any) -> None:
    """This is the whole reason the module exists."""
    error = refused({"a": "x"}, {"type": "object", keyword: value})
    assert error.code is ErrorCode.NOT_READY
    assert keyword in error.message


def test_an_unimplemented_keyword_is_rejected_inside_a_subschema() -> None:
    error = refused(
        {"a": {"b": 1}},
        {"type": "object", "properties": {"a": {"type": "object", "$ref": "#/x"}}},
    )
    assert "$ref" in error.message


def test_format_is_rejected_even_though_it_is_only_an_annotation() -> None:
    """Documented decision: a reviewer writing `format` means a constraint."""
    assert "format" not in SUPPORTED_KEYWORDS
    refused("2026-01-01", {"type": "string", "format": "date"})


def test_annotation_keywords_are_accepted_and_ignored() -> None:
    check(
        {"a": 1},
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "t",
            "description": "d",
            "default": {},
            "examples": [{}],
            "$comment": "c",
            "type": "object",
        },
    )


# --------------------------------------------------------------------------
# Types
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, ok, bad",
    [
        ("object", {}, []),
        ("array", [], {}),
        ("string", "x", 1),
        ("number", 1.5, "x"),
        ("integer", 3, 3.5),
        ("boolean", True, 1),
        ("null", None, 0),
    ],
)
def test_each_json_type(name: str, ok: Any, bad: Any) -> None:
    check(ok, {"type": name})
    refused(bad, {"type": name})


def test_a_boolean_is_never_a_number_or_an_integer() -> None:
    """`bool` subclasses `int` in Python; JSON has no such relationship."""
    refused(True, {"type": "number"})
    refused(True, {"type": "integer"})
    refused(False, {"type": "integer"})


def test_a_float_with_no_fraction_counts_as_an_integer() -> None:
    """Otherwise validity would depend on the provider's serializer."""
    check(3.0, {"type": "integer"})
    refused(3.25, {"type": "integer"})


def test_a_union_of_types() -> None:
    check(None, {"type": ["string", "null"]})
    check("x", {"type": ["string", "null"]})
    refused(1, {"type": ["string", "null"]})


def test_an_unknown_type_name_is_rejected() -> None:
    refused("x", {"type": "text"})


# --------------------------------------------------------------------------
# Objects
# --------------------------------------------------------------------------


def test_required_properties() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
    check({"a": "x"}, schema)
    error = refused({}, schema)
    assert "a" in error.message


def test_additional_properties_false_reports_a_count_and_never_a_name() -> None:
    """§7.3: a property name in a provider payload is provider data."""
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "additionalProperties": False,
    }
    check({"a": "x"}, schema)
    error = refused({"a": "x", "account_number": "1234567890"}, schema)
    assert "account_number" not in error.message
    assert "1234567890" not in error.message
    assert "1 propertie" in error.message


def test_additional_properties_as_a_schema() -> None:
    schema = {"type": "object", "properties": {}, "additionalProperties": {"type": "number"}}
    check({"x": 1, "y": 2.5}, schema)
    refused({"x": "no"}, schema)


def test_nested_property_failure_names_the_schema_path_only() -> None:
    schema = {
        "type": "object",
        "properties": {"outer": {"type": "object", "properties": {"inner": {"type": "string"}}}},
    }
    error = refused({"outer": {"inner": 5}}, schema)
    assert "data.outer.inner" in error.message
    assert "5" not in error.message.replace("JSON type", "")


# --------------------------------------------------------------------------
# Arrays, strings, numbers
# --------------------------------------------------------------------------


def test_array_bounds_and_items() -> None:
    schema = {"type": "array", "items": {"type": "integer"}, "minItems": 1, "maxItems": 2}
    check([1, 2], schema)
    refused([], schema)
    refused([1, 2, 3], schema)
    refused(["x"], schema)


def test_unique_items_uses_the_canonical_form() -> None:
    schema = {"type": "array", "uniqueItems": True}
    check([{"a": 1, "b": 2}, {"a": 1, "b": 3}], schema)
    # Key order does not make two objects different values.
    refused([{"a": 1, "b": 2}, {"b": 2, "a": 1}], schema)


def test_string_bounds_and_pattern_never_echo_the_value() -> None:
    schema = {"type": "string", "minLength": 2, "maxLength": 4, "pattern": "^[A-Z]+$"}
    check("ABC", schema)
    refused("A", schema)
    refused("ABCDE", schema)
    error = refused("abcd", schema)
    assert "abcd" not in error.message


def test_number_bounds() -> None:
    check(5, {"type": "number", "minimum": 5, "maximum": 5})
    refused(4.9, {"type": "number", "minimum": 5})
    refused(5.1, {"type": "number", "maximum": 5})
    refused(5, {"type": "number", "exclusiveMinimum": 5})
    refused(5, {"type": "number", "exclusiveMaximum": 5})
    check(6, {"type": "number", "multipleOf": 3})
    refused(7, {"type": "number", "multipleOf": 3})


# --------------------------------------------------------------------------
# enum / const / combinators
# --------------------------------------------------------------------------


def test_enum_and_const_do_not_conflate_true_with_one() -> None:
    refused(True, {"enum": [1, 2]})
    refused(True, {"const": 1})
    check(1, {"enum": [1, 2]})
    check(1, {"const": 1})


def test_combinators() -> None:
    check("x", {"anyOf": [{"type": "string"}, {"type": "integer"}]})
    refused(1.5, {"anyOf": [{"type": "string"}, {"type": "integer"}]})
    check("x", {"oneOf": [{"type": "string"}, {"type": "integer"}]})
    refused(1, {"oneOf": [{"type": "integer"}, {"type": "number"}]})
    check(1, {"allOf": [{"type": "integer"}, {"minimum": 0}]})
    refused(-1, {"allOf": [{"type": "integer"}, {"minimum": 0}]})


# --------------------------------------------------------------------------
# Structural limits and malformed schemas
# --------------------------------------------------------------------------


def test_a_deeply_nested_schema_is_refused_rather_than_recursing() -> None:
    schema: dict[str, Any] = {"type": "object"}
    for _ in range(64):
        schema = {"type": "object", "properties": {"n": schema}}
    with pytest.raises(GatewayError) as caught:
        ensure_schema_supported(schema)
    assert "nests deeper" in caught.value.message


@pytest.mark.parametrize(
    "schema",
    [
        {"type": 5},
        {"type": []},
        {"required": "a"},
        {"required": [1]},
        {"enum": []},
        {"minLength": -1},
        {"maxItems": True},
        {"minimum": "5"},
        {"multipleOf": 0},
        {"uniqueItems": "yes"},
        {"pattern": 5},
        {"pattern": "("},
        {"pattern": "a" * 4096},
        {"properties": []},
        {"anyOf": []},
        {"anyOf": {}},
        "not-a-schema",
    ],
)
def test_a_malformed_schema_is_a_local_fault(schema: Any) -> None:
    with pytest.raises(GatewayError) as caught:
        ensure_schema_supported(schema)
    assert caught.value.code is ErrorCode.NOT_READY


def test_boolean_schemas() -> None:
    check({"anything": 1}, True)
    refused({"anything": 1}, False)


def test_the_two_error_codes_are_distinct() -> None:
    """A payload fault and an unenforceable schema are different parties."""
    with pytest.raises(GatewayError) as unenforceable:
        validate_instance({}, {"$ref": "#/x"})
    assert unenforceable.value.code is ErrorCode.NOT_READY

    with pytest.raises(GatewayError) as payload:
        validate_instance({}, {"type": "string"})
    assert payload.value.code is ErrorCode.PROTOCOL_ERROR
