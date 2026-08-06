import json

from rh_mcp import errors
from rh_mcp.errors import (
    EXIT_CODE_AUTH_REQUIRED,
    EXIT_CODE_CONFIGURATION_ERROR,
    EXIT_CODE_MAP,
    EXIT_CODE_PROVIDER_FAILURE,
    EXIT_CODE_SUCCESS,
    EXIT_CODE_USAGE_ERROR,
    ErrorCode,
    GatewayError,
    exit_code_for,
)

# Golden fixture (DESIGN.md §7.3, §11, §12.5): pins the nine literal wire
# strings.
#
# The bucket table below is keyed by enum *member*, so it says nothing about
# the string a member carries. That gap was real and was measured before this
# fixture existed: on `b6d6a35`, changing
# `CAPABILITY_DENIED = "capability_denied"` to `"capability_refused"` left all
# 1176 tests passing. The value is the contract — `ErrorCode` is a `StrEnum`,
# so it is what `cli.py` writes to stderr and what `DriftFinding.to_json_dict()`
# puts in `rh-mcp status` output — and §12.5 now promises these nine strings to
# a consumer. A promise CI does not defend is the shape of defect §12.1's
# `TestNoEscapeHatch` was: a passing test asserting something adjacent to the
# claim.
#
# Keyed by member *name* written out as a literal, and valued by the wire
# string written out as a literal. A fixture built from `ErrorCode` itself
# would agree with any rename in either position.
_EXPECTED_WIRE_STRINGS: dict[str, str] = {
    "AUTH_REQUIRED": "auth_required",
    "NOT_READY": "not_ready",
    "CAPABILITY_DENIED": "capability_denied",
    "INPUT_INVALID": "input_invalid",
    "PROVIDER_ERROR": "provider_error",
    "TIMEOUT": "timeout",
    "RESPONSE_TOO_LARGE": "response_too_large",
    "PROTOCOL_ERROR": "protocol_error",
    "CONFIGURATION_ERROR": "configuration_error",
}

# Golden fixture (DESIGN.md §7.3, §12.5): the five exit integers themselves.
# `_EXPECTED_BUCKETS` maps codes onto the named constants, so it pins the
# grouping but not the numbers. Measured the same way: on `b6d6a35`, changing
# `EXIT_CODE_PROVIDER_FAILURE` from 1 to 8, or `EXIT_CODE_AUTH_REQUIRED` from 4
# to 9, also left the suite green. An operator's runbook and a consumer's
# process supervisor both branch on the integer, not on the constant's name.
_EXPECTED_EXIT_INTEGERS: dict[str, int] = {
    "EXIT_CODE_SUCCESS": 0,
    "EXIT_CODE_PROVIDER_FAILURE": 1,
    "EXIT_CODE_USAGE_ERROR": 2,
    "EXIT_CODE_CONFIGURATION_ERROR": 3,
    "EXIT_CODE_AUTH_REQUIRED": 4,
}

# Golden fixture (DESIGN.md §7.3, §11): pins the code->exit-code bucket so an
# accidental remap breaks CI instead of shipping silently.
_EXPECTED_BUCKETS: dict[ErrorCode, int] = {
    ErrorCode.PROVIDER_ERROR: EXIT_CODE_PROVIDER_FAILURE,
    ErrorCode.PROTOCOL_ERROR: EXIT_CODE_PROVIDER_FAILURE,
    ErrorCode.TIMEOUT: EXIT_CODE_PROVIDER_FAILURE,
    ErrorCode.RESPONSE_TOO_LARGE: EXIT_CODE_PROVIDER_FAILURE,
    ErrorCode.INPUT_INVALID: EXIT_CODE_USAGE_ERROR,
    ErrorCode.CAPABILITY_DENIED: EXIT_CODE_USAGE_ERROR,
    ErrorCode.CONFIGURATION_ERROR: EXIT_CODE_CONFIGURATION_ERROR,
    ErrorCode.NOT_READY: EXIT_CODE_CONFIGURATION_ERROR,
    ErrorCode.AUTH_REQUIRED: EXIT_CODE_AUTH_REQUIRED,
}


def test_error_code_wire_strings_are_pinned() -> None:
    """§12.5: the nine values, not the nine member names, are the contract."""
    for member_name, wire_string in _EXPECTED_WIRE_STRINGS.items():
        code = getattr(ErrorCode, member_name)
        assert code.value == wire_string
        # `StrEnum`, so these are the forms a consumer actually meets: the
        # stderr line `cli.py` formats and the `error_code` field
        # `DriftFinding.to_json_dict()` emits with `str()`.
        assert str(code) == wire_string
        assert f"{code}" == wire_string
        assert json.dumps(code) == json.dumps(wire_string)


def test_the_error_code_set_is_exactly_the_nine_pinned_strings() -> None:
    """A tenth code is a minor release (§12.5), never an unnoticed addition."""
    assert {code.value for code in ErrorCode} == set(_EXPECTED_WIRE_STRINGS.values())
    assert {code.name for code in ErrorCode} == set(_EXPECTED_WIRE_STRINGS)
    assert len(_EXPECTED_WIRE_STRINGS) == 9


def test_exit_code_integers_are_pinned() -> None:
    """§12.5: the integers are the contract, not just the grouping."""
    for constant_name, expected in _EXPECTED_EXIT_INTEGERS.items():
        assert getattr(errors, constant_name) == expected
    # Five distinct buckets, so no two failures collapse onto one exit status.
    assert len(set(_EXPECTED_EXIT_INTEGERS.values())) == 5
    assert set(EXIT_CODE_MAP.values()) == set(_EXPECTED_EXIT_INTEGERS.values()) - {
        EXIT_CODE_SUCCESS
    }


def test_every_error_code_has_a_pinned_exit_bucket() -> None:
    assert set(EXIT_CODE_MAP) == set(ErrorCode)
    assert EXIT_CODE_MAP == _EXPECTED_BUCKETS


def test_exit_code_for_success_is_zero() -> None:
    assert exit_code_for(None) == EXIT_CODE_SUCCESS


def test_exit_code_for_each_code_matches_golden_table() -> None:
    for code, expected_exit in _EXPECTED_BUCKETS.items():
        error = GatewayError(code, "safe message", retryable=False)
        assert exit_code_for(error) == expected_exit


def test_gateway_error_carries_fields() -> None:
    error = GatewayError(
        ErrorCode.TIMEOUT, "the call timed out", retryable=True, correlation_id="abc-123"
    )
    assert error.code is ErrorCode.TIMEOUT
    assert error.message == "the call timed out"
    assert error.retryable is True
    assert error.correlation_id == "abc-123"
    assert str(error) == "the call timed out"
