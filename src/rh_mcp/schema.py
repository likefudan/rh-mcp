"""A strict-subset JSON Schema validator (DESIGN.md §7.1, §6.2).

`manifest.py` settled the rule this module implements, and it is worth
restating because it inverts the usual advice:

> Write a **strict-subset validator**; do not reach for `jsonschema`. That
> library *ignores* keywords it does not recognize, which is default-allow on
> precisely the axis this package is default-deny.

`jsonschema` is already installed as a transitive dependency of the MCP SDK, so
using it would have been one import. The reason not to is that a reviewed
manifest pins a schema *as the constraint a payload must satisfy*. If the
validator silently skips a keyword — because it is from a draft the library
does not implement, because it is misspelled, or because it is a vendor
extension — the reviewed constraint is not enforced and nothing says so. The
gateway would report a schema-checked result that was never checked.

So: every keyword is either implemented or rejected. `ensure_schema_supported`
walks a schema and refuses anything outside `SUPPORTED_KEYWORDS`, and
`validate_instance` refuses to run against a schema that has not passed. A
provider surface that needs `$ref`, `if`/`then`, `patternProperties` or
`format` therefore makes the gateway fail closed and sends a human to extend
this file deliberately — which is the §6 review workflow working, not a bug.

Error messages name **schema paths only, never instance values**. A schema
comes from the committed manifest and is safe to quote; an instance is a
provider payload and §7.3 keeps it out of public errors. The count of
unexpected properties is reported rather than their names, because a property
name in a provider response is provider data too.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, NoReturn

from rh_mcp.canonical import canonicalize
from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.validation import invalid

# Keywords that constrain an instance. Every one is implemented below.
_APPLICATOR_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "enum",
        "const",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "allOf",
        "anyOf",
        "oneOf",
    }
)

# Keywords that carry no constraint at all in JSON Schema and are therefore
# safe to accept and ignore. This list is short and closed on purpose: it is
# the one place where "ignored" is a correct outcome, so anything added to it
# is a claim that the keyword cannot constrain an instance.
#
# `format` is deliberately absent. It is *specified* as an annotation, so
# ignoring it would be defensible by the letter of the spec — but a reviewer
# writing `"format": "date-time"` in a manifest plainly intends a constraint,
# and silently accepting the keyword while enforcing nothing is exactly the
# fail-open this module exists to prevent. Rejecting it makes the reviewer
# choose: implement it here, or express the constraint with `pattern`.
_ANNOTATION_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"title", "description", "default", "examples", "$comment", "$schema", "$id"}
)

SUPPORTED_KEYWORDS: Final[frozenset[str]] = _APPLICATOR_KEYWORDS | _ANNOTATION_KEYWORDS

_TYPE_NAMES: Final[frozenset[str]] = frozenset(
    {"object", "array", "string", "number", "integer", "boolean", "null"}
)

# A schema is reviewed content, but a pathological `pattern` is still a denial
# of service against provider data, and Python's `re` has no step limit. A
# short bound keeps a reviewed regex reviewable.
MAX_PATTERN_LENGTH: Final = 512

# A schema nests no deeper than this. Well above anything a reviewed tool
# schema should need, and low enough that the recursive walk cannot approach
# CPython's stack limit.
MAX_SCHEMA_DEPTH: Final = 32


def _fail(path: str, message: str, code: ErrorCode) -> NoReturn:
    invalid(f"{path or 'value'} {message}", code)


# --------------------------------------------------------------------------
# Schema support check
# --------------------------------------------------------------------------


def ensure_schema_supported(
    schema: Any, code: ErrorCode = ErrorCode.NOT_READY, *, path: str = "schema", depth: int = 0
) -> None:
    """Refuse a schema this module cannot fully enforce.

    Call this once, as early as possible — ideally when the manifest is loaded
    (§6.2), so an unenforceable pinned schema stops a gateway from becoming
    ready rather than surfacing at whichever call first exercises the keyword.
    `validate_instance` calls it too, because a validator that trusts its
    caller to have checked is a validator that eventually runs unchecked.
    """
    if depth > MAX_SCHEMA_DEPTH:
        _fail(path, f"nests deeper than {MAX_SCHEMA_DEPTH} levels", code)
    if isinstance(schema, bool):
        # `true`/`false` schemas are valid JSON Schema and unambiguous.
        return
    if not isinstance(schema, Mapping):
        _fail(path, "must be a JSON object or boolean schema", code)

    unsupported = sorted(key for key in schema if key not in SUPPORTED_KEYWORDS)
    if unsupported:
        _fail(
            path,
            f"uses keyword(s) {unsupported} that this validator does not implement; "
            "an unenforced keyword would be a pinned constraint that is never checked",
            code,
        )

    if "type" in schema:
        declared_type = schema["type"]
        if isinstance(declared_type, str):
            names: tuple[Any, ...] = (declared_type,)
        elif isinstance(declared_type, (list, tuple)) and declared_type:
            names = tuple(declared_type)
        else:
            _fail(f"{path}.type", "must be a string or non-empty array of strings", code)
        for name in names:
            if name not in _TYPE_NAMES:
                _fail(f"{path}.type", f"must name JSON types {sorted(_TYPE_NAMES)}", code)

    for keyword in ("enum",):
        if keyword in schema:
            values = schema[keyword]
            if not isinstance(values, (list, tuple)) or not values:
                _fail(f"{path}.{keyword}", "must be a non-empty array", code)

    if "required" in schema:
        required = schema["required"]
        if not isinstance(required, (list, tuple)) or any(
            not isinstance(name, str) for name in required
        ):
            _fail(f"{path}.required", "must be an array of strings", code)

    for keyword in ("minItems", "maxItems", "minLength", "maxLength"):
        if keyword in schema:
            value = schema[keyword]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                _fail(f"{path}.{keyword}", "must be a non-negative integer", code)

    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"):
        if keyword in schema:
            value = schema[keyword]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                _fail(f"{path}.{keyword}", "must be a number", code)
    if "multipleOf" in schema and schema["multipleOf"] <= 0:
        _fail(f"{path}.multipleOf", "must be greater than zero", code)

    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        _fail(f"{path}.uniqueItems", "must be a boolean", code)

    if "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str):
            _fail(f"{path}.pattern", "must be a string", code)
        if len(pattern) > MAX_PATTERN_LENGTH:
            _fail(f"{path}.pattern", f"must be at most {MAX_PATTERN_LENGTH} characters", code)
        try:
            re.compile(pattern)
        except re.error:
            # The exception text quotes the pattern; the pattern is reviewed
            # content, but reproducing it adds nothing a path does not.
            _fail(f"{path}.pattern", "is not a valid regular expression", code)

    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, Mapping):
            _fail(f"{path}.properties", "must be a JSON object", code)
        for name, subschema in properties.items():
            if not isinstance(name, str):
                _fail(f"{path}.properties", "keys must be strings", code)
            ensure_schema_supported(
                subschema, code, path=f"{path}.properties.{name}", depth=depth + 1
            )

    if "additionalProperties" in schema:
        ensure_schema_supported(
            schema["additionalProperties"],
            code,
            path=f"{path}.additionalProperties",
            depth=depth + 1,
        )

    if "items" in schema:
        ensure_schema_supported(schema["items"], code, path=f"{path}.items", depth=depth + 1)

    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in schema:
            branches = schema[keyword]
            if not isinstance(branches, (list, tuple)) or not branches:
                _fail(f"{path}.{keyword}", "must be a non-empty array of schemas", code)
            for index, branch in enumerate(branches):
                ensure_schema_supported(
                    branch, code, path=f"{path}.{keyword}[{index}]", depth=depth + 1
                )


# --------------------------------------------------------------------------
# Instance validation
# --------------------------------------------------------------------------


def validate_instance(
    instance: Any,
    schema: Any,
    *,
    code: ErrorCode = ErrorCode.PROTOCOL_ERROR,
    schema_code: ErrorCode = ErrorCode.NOT_READY,
    label: str = "data",
) -> None:
    """Check `instance` against a pinned `schema`, or raise.

    `code` labels a payload that does not satisfy the schema; `schema_code`
    labels a schema this validator cannot enforce. They differ because the two
    faults belong to different parties and to different §7.3 exit buckets: an
    unenforceable pinned schema is a local configuration fault, while a payload
    that violates an enforceable one is a provider fault.
    """
    ensure_schema_supported(schema, schema_code)
    _check(instance, schema, code=code, path=label, depth=0)


def _check(instance: Any, schema: Any, *, code: ErrorCode, path: str, depth: int) -> None:
    if depth > MAX_SCHEMA_DEPTH:
        _fail(path, f"nests deeper than the {MAX_SCHEMA_DEPTH}-level schema limit", code)
    if schema is True:
        return
    if schema is False:
        _fail(path, "is not permitted by the pinned schema", code)
    if not isinstance(schema, Mapping):
        # `ensure_schema_supported` already proved this, but an `assert` would
        # vanish under `python -O` and turn a fail-closed check into a silent
        # `Mapping` method call on whatever was passed.
        _fail(path, "was checked against a schema that is not a JSON object", code)

    declared_type = schema.get("type")
    if declared_type is not None:
        names = (declared_type,) if isinstance(declared_type, str) else tuple(declared_type)
        if not any(_matches_type(instance, name) for name in names):
            _fail(path, f"must be of JSON type {list(names)}", code)

    if "const" in schema and not _json_equal(instance, schema["const"]):
        _fail(path, "does not equal the pinned const value", code)

    if "enum" in schema and not any(_json_equal(instance, choice) for choice in schema["enum"]):
        _fail(path, "is not one of the pinned enum values", code)

    if isinstance(instance, str):
        _check_string(instance, schema, code=code, path=path)
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        _check_number(instance, schema, code=code, path=path)
    if isinstance(instance, Mapping):
        _check_object(instance, schema, code=code, path=path, depth=depth)
    if isinstance(instance, (list, tuple)):
        _check_array(instance, schema, code=code, path=path, depth=depth)

    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if branches is None:
            continue
        satisfied = 0
        for index, branch in enumerate(branches):
            try:
                _check(
                    instance, branch, code=code, path=f"{path}<{keyword}[{index}]>", depth=depth + 1
                )
            except GatewayError:
                # A failing branch is an ordinary outcome of a combinator, not
                # an error. Only `GatewayError` is swallowed, so a genuine bug
                # in this module still propagates instead of silently counting
                # as "branch not satisfied".
                continue
            satisfied += 1
        if keyword == "allOf" and satisfied != len(branches):
            _fail(path, "does not satisfy every allOf branch of the pinned schema", code)
        if keyword == "anyOf" and satisfied == 0:
            _fail(path, "satisfies no anyOf branch of the pinned schema", code)
        if keyword == "oneOf" and satisfied != 1:
            _fail(path, "must satisfy exactly one oneOf branch of the pinned schema", code)


def _matches_type(instance: Any, name: str) -> bool:
    if name == "object":
        return isinstance(instance, Mapping)
    if name == "array":
        return isinstance(instance, (list, tuple))
    if name == "string":
        return isinstance(instance, str)
    if name == "boolean":
        return isinstance(instance, bool)
    if name == "null":
        return instance is None
    if name == "integer":
        # JSON Schema treats 1.0 as an integer; Python's decoder does not. Both
        # spellings decode from the same JSON text, so refusing the float form
        # would make validity depend on the provider's serializer.
        if isinstance(instance, bool):
            return False
        if isinstance(instance, int):
            return True
        return isinstance(instance, float) and instance.is_integer()
    if name == "number":
        return not isinstance(instance, bool) and isinstance(instance, (int, float))
    return False  # pragma: no cover - ensure_schema_supported rejects other names


def _check_string(instance: str, schema: Mapping[str, Any], *, code: ErrorCode, path: str) -> None:
    minimum = schema.get("minLength")
    if minimum is not None and len(instance) < minimum:
        _fail(path, f"must be at least {minimum} characters", code)
    maximum = schema.get("maxLength")
    if maximum is not None and len(instance) > maximum:
        _fail(path, f"must be at most {maximum} characters", code)
    pattern = schema.get("pattern")
    if pattern is not None and re.search(pattern, instance) is None:
        # The instance is provider data (§7.3), so only the pattern's presence
        # is reported, never the value that failed it.
        _fail(path, "does not match the pinned pattern", code)


def _check_number(
    instance: float, schema: Mapping[str, Any], *, code: ErrorCode, path: str
) -> None:
    minimum = schema.get("minimum")
    if minimum is not None and instance < minimum:
        _fail(path, "is below the pinned minimum", code)
    maximum = schema.get("maximum")
    if maximum is not None and instance > maximum:
        _fail(path, "is above the pinned maximum", code)
    exclusive_minimum = schema.get("exclusiveMinimum")
    if exclusive_minimum is not None and instance <= exclusive_minimum:
        _fail(path, "is not above the pinned exclusiveMinimum", code)
    exclusive_maximum = schema.get("exclusiveMaximum")
    if exclusive_maximum is not None and instance >= exclusive_maximum:
        _fail(path, "is not below the pinned exclusiveMaximum", code)
    multiple_of = schema.get("multipleOf")
    if multiple_of is not None:
        quotient = instance / multiple_of
        if abs(quotient - round(quotient)) > 1e-9:
            _fail(path, "is not a multiple of the pinned multipleOf", code)


def _check_object(
    instance: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    code: ErrorCode,
    path: str,
    depth: int,
) -> None:
    required = schema.get("required")
    if required is not None:
        missing = sorted(name for name in required if name not in instance)
        if missing:
            # These names come from the reviewed schema, not the payload.
            _fail(path, f"is missing required propertie(s) {missing}", code)

    properties = schema.get("properties") or {}
    for name, subschema in properties.items():
        if name in instance:
            _check(instance[name], subschema, code=code, path=f"{path}.{name}", depth=depth + 1)

    if "additionalProperties" in schema:
        additional = schema["additionalProperties"]
        extra = [name for name in instance if name not in properties]
        if additional is False:
            if extra:
                # Only the count. A property name in a provider response is
                # provider data, and one of those has already been observed to
                # be an account identifier (§7.3, §8).
                _fail(
                    path,
                    f"has {len(extra)} propertie(s) the pinned schema does not permit",
                    code,
                )
        else:
            for name in extra:
                _check(instance[name], additional, code=code, path=f"{path}.*", depth=depth + 1)


def _check_array(
    instance: Sequence[Any], schema: Mapping[str, Any], *, code: ErrorCode, path: str, depth: int
) -> None:
    minimum = schema.get("minItems")
    if minimum is not None and len(instance) < minimum:
        _fail(path, f"must have at least {minimum} item(s)", code)
    maximum = schema.get("maxItems")
    if maximum is not None and len(instance) > maximum:
        _fail(path, f"must have at most {maximum} item(s)", code)
    if schema.get("uniqueItems") is True:
        seen: set[bytes] = set()
        for item in instance:
            encoded = canonicalize(item, code=code)
            if encoded in seen:
                _fail(path, "must not contain duplicate items", code)
            seen.add(encoded)
    items = schema.get("items")
    if items is not None:
        for index, item in enumerate(instance):
            _check(item, items, code=code, path=f"{path}[{index}]", depth=depth + 1)


def _json_equal(left: Any, right: Any) -> bool:
    """Equality over decoded JSON, without Python's `1 == 1.0 == True` conflation.

    `enum`/`const` are pinned values in a reviewed manifest. If `True` matched
    a pinned `1`, a reviewed enumeration of numeric codes would silently accept
    a boolean, so the comparison goes through the canonical form — the same
    definition of "the same JSON value" every digest in this package uses.
    """
    try:
        return canonicalize(left, code=ErrorCode.PROTOCOL_ERROR) == canonicalize(
            right, code=ErrorCode.PROTOCOL_ERROR
        )
    except GatewayError:
        # A value that has no canonical form is not equal to anything; the
        # caller's own type checks report the real fault.
        return False


__all__ = [
    "MAX_PATTERN_LENGTH",
    "MAX_SCHEMA_DEPTH",
    "SUPPORTED_KEYWORDS",
    "ensure_schema_supported",
    "validate_instance",
]
