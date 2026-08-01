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
