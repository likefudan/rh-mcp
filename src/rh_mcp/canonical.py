"""Deterministic canonical JSON and SHA-256 digests (DESIGN.md §6).

Every permission decision this package makes reduces to a digest comparison,
so the canonical form has to be a *specification*, not an implementation
detail. It is written out in full below and pinned by golden vectors in
`tests/test_canonical.py`. If a change to this module does not break those
vectors, the change did not do what its author thought it did.

## The `rh-canon-1` canonical form

The input must already be decoded JSON: object (string keys), array, string,
number, `true`, `false`, `null`. Anything else — a set, `bytes`, a `Decimal`,
a non-string key, NaN, Infinity, an unpaired surrogate — is rejected rather
than coerced, because a coercion is a place where two different inputs can
acquire the same digest.

1. **Objects** are emitted as `{` `"key":value` pairs joined by `,` `}`, with
   the pairs sorted by key. The sort is over the key's sequence of **Unicode
   code points** (Python's native string ordering). This is deliberately *not*
   RFC 8785/JCS, which sorts by UTF-16 code units and therefore orders an
   astral character before U+FFFF; `rh-canon-1` orders it after. No
   interoperability with JCS is claimed, and a golden vector pins the
   difference so nobody "fixes" it by accident.
2. **Arrays** are emitted as `[` elements joined by `,` `]` in their given
   order. Array order is semantically meaningful and is never sorted.
3. **Strings** are emitted between `"` with the minimal RFC 8259 escape set:
   `\\"` and `\\\\`, the two-character forms for backspace, form feed,
   newline, carriage return and tab, and `\\u00xx` (lowercase hex) for every
   other code point below U+0020. Every other character — including U+007F
   and all non-ASCII — is emitted literally and encoded as UTF-8. There is no
   `\\uXXXX` escaping of non-ASCII, so the canonical form is genuinely UTF-8
   bytes rather than ASCII.
4. **Integers** (Python `int`, excluding `bool`) are emitted by `repr`: an
   optional `-` and decimal digits, no exponent, no leading zeros.
5. **Floats** are emitted by `repr`, which is CPython's shortest
   round-tripping representation and has been stable since 3.1. Consequences
   worth stating because they are digest-visible: `1` and `1.0` are
   *different* canonical values, and so are `0.0` and `-0.0`. JSON does not
   distinguish them but Python's decoder does, deterministically, so treating
   them as distinct only ever produces *more* digest changes — never fewer.
   That is the fail-closed direction: a spurious drift alert costs a human
   review, a missed one costs the security boundary.
6. `true`, `false`, `null` are emitted as those literals.
7. No whitespace is emitted anywhere between tokens.

The result is UTF-8 bytes; the digest is `"sha256:"` followed by their SHA-256
hex digest.

## Versioning

`CANONICALIZATION_VERSION` is recorded inside every derived digest input and
inside the manifest itself, so changing this algorithm changes every digest in
the system and forces the explicit migration DESIGN.md §6 requires. It is not
a knob: only one version is implemented at a time.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from typing import Any, Final

from rh_mcp.errors import ErrorCode, GatewayError
from rh_mcp.validation import invalid, is_encodable

CANONICALIZATION_VERSION: Final = "rh-canon-1"
DIGEST_ALGORITHM: Final = "sha256"
DIGEST_PREFIX: Final = "sha256:"

# Structural depth rail. Canonicalization recurses, so an adversarial or
# accidentally cyclic structure must hit the public error contract rather than
# `RecursionError`. Matches `validation.MAX_STRUCTURAL_DEPTH` in spirit but is
# checked independently: this function is the hashing primitive and must never
# depend on a caller having already walked the value.
MAX_CANONICAL_DEPTH: Final = 128

# CPython refuses to render an integer wider than this many digits by default
# (`sys.set_int_max_str_digits`). `repr` therefore *raises* on such a value,
# which would escape the §7.3 error contract, so the limit is enforced here
# explicitly instead of being discovered by an exception.
MAX_INT_DIGITS: Final = 4300

_SHORT_ESCAPES: Final[dict[str, str]] = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _canonical_string(value: str, code: ErrorCode) -> str:
    if not is_encodable(value):
        invalid("canonical strings may not contain unpaired surrogates", code)
    out = ['"']
    for character in value:
        escape = _SHORT_ESCAPES.get(character)
        if escape is not None:
            out.append(escape)
        elif character < " ":
            out.append(f"\\u{ord(character):04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _canonical_number(value: int | float, code: ErrorCode) -> str:
    if isinstance(value, int):
        try:
            rendered = repr(value)
        except ValueError:
            # CPython's own int-to-str limit. Re-raised as the stable error
            # with the context dropped, so an oversized literal never reaches
            # a caller as a traceback (§7.3).
            raise GatewayError(
                code, f"canonical integers are limited to {MAX_INT_DIGITS} digits"
            ) from None
        # Independent of CPython's limit, which a process can raise at runtime
        # with `sys.set_int_max_str_digits`. The canonical form must not widen
        # just because an interpreter was reconfigured.
        if len(rendered.lstrip("-")) > MAX_INT_DIGITS:
            invalid(f"canonical integers are limited to {MAX_INT_DIGITS} digits", code)
        return rendered
    if not math.isfinite(value):
        invalid("canonical numbers may not be NaN or Infinity", code)
    return repr(value)


def _write(value: Any, out: list[str], code: ErrorCode, depth: int) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        invalid(
            f"value nests deeper than {MAX_CANONICAL_DEPTH} levels or contains a cycle",
            code,
        )
    # `bool` is checked before `int` because it is a subclass of it; JSON's
    # `true` must never be canonicalized as the number `1`.
    if value is None:
        out.append("null")
        return
    if value is True:
        out.append("true")
        return
    if value is False:
        out.append("false")
        return
    if isinstance(value, str):
        out.append(_canonical_string(value, code))
        return
    if isinstance(value, (int, float)):
        out.append(_canonical_number(value, code))
        return
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                invalid(f"canonical object keys must be strings, got {type(key).__name__}", code)
            items.append((key, item))
        # Sorted by Unicode code point; see the module docstring. A `Mapping`
        # cannot carry duplicate keys, so no de-duplication rule is needed
        # here — duplicate keys in JSON *text* are rejected by the manifest
        # loader before decoding reaches this point.
        items.sort(key=lambda pair: pair[0])
        out.append("{")
        for index, (key, item) in enumerate(items):
            if index:
                out.append(",")
            out.append(_canonical_string(key, code))
            out.append(":")
            _write(item, out, code, depth + 1)
        out.append("}")
        return
    if isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out, code, depth + 1)
        out.append("]")
        return
    # A `str`/`bytes` is not a generic Sequence we accept; anything else that
    # merely looks list-like is rejected rather than guessed at.
    if isinstance(value, Sequence):
        invalid(f"canonical arrays must be a list or tuple, got {type(value).__name__}", code)
    invalid(f"value may contain only JSON types, got {type(value).__name__}", code)


def canonicalize(value: Any, *, code: ErrorCode = ErrorCode.PROTOCOL_ERROR) -> bytes:
    """Render decoded JSON into the `rh-canon-1` canonical UTF-8 byte string."""
    out: list[str] = []
    _write(value, out, code, 0)
    return "".join(out).encode("utf-8")


def canonical_digest(value: Any, *, code: ErrorCode = ErrorCode.PROTOCOL_ERROR) -> str:
    """SHA-256 over the canonical form, as `'sha256:<64 lowercase hex>'`."""
    return DIGEST_PREFIX + hashlib.sha256(canonicalize(value, code=code)).hexdigest()


def tool_schema_digest(
    provider_tool_name: str,
    input_schema: Any,
    output_schema: Any,
    *,
    code: ErrorCode = ErrorCode.PROTOCOL_ERROR,
) -> str:
    """Digest over the provider name and complete input/output schemas (§6).

    The name is inside the digest on purpose: two tools that happen to share a
    schema must not share a schema digest, or a manifest entry's pinned digest
    would still verify after the provider moved that schema to a different
    tool.

    A tool with no output schema hashes `null`, which is distinct from an
    empty object `{}` — "the provider declared no output schema" and "the
    provider declared an unconstrained one" are different security facts.

    `digest_kind` and `canonicalization` are part of the hashed input so a
    schema digest can never collide with a metadata or provider-surface digest,
    and so an algorithm revision necessarily changes every stored value.
    """
    return canonical_digest(
        {
            "digest_kind": "schema",
            "canonicalization": CANONICALIZATION_VERSION,
            "provider_tool_name": provider_tool_name,
            "input_schema": input_schema,
            "output_schema": output_schema,
        },
        code=code,
    )


def tool_metadata_digest(
    description: Any,
    annotations: Any,
    *,
    code: ErrorCode = ErrorCode.PROTOCOL_ERROR,
) -> str:
    """Digest over the description and annotations (§6).

    Annotations such as `readOnlyHint` are review evidence and never authority
    (§2), but they still have to be pinned: a provider that flips one has
    changed the evidence a human reviewed, and that must surface as drift
    rather than pass silently.
    """
    return canonical_digest(
        {
            "digest_kind": "metadata",
            "canonicalization": CANONICALIZATION_VERSION,
            "description": description,
            "annotations": annotations,
        },
        code=code,
    )


__all__ = [
    "CANONICALIZATION_VERSION",
    "DIGEST_ALGORITHM",
    "DIGEST_PREFIX",
    "MAX_CANONICAL_DEPTH",
    "MAX_INT_DIGITS",
    "canonical_digest",
    "canonicalize",
    "tool_metadata_digest",
    "tool_schema_digest",
]
