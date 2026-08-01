"""Stable public error contract for the gateway (DESIGN.md §7.3)."""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    """The nine public error codes a `GatewayError` may carry."""

    AUTH_REQUIRED = "auth_required"
    NOT_READY = "not_ready"
    CAPABILITY_DENIED = "capability_denied"
    INPUT_INVALID = "input_invalid"
    PROVIDER_ERROR = "provider_error"
    TIMEOUT = "timeout"
    RESPONSE_TOO_LARGE = "response_too_large"
    PROTOCOL_ERROR = "protocol_error"
    CONFIGURATION_ERROR = "configuration_error"


class GatewayError(Exception):
    """The base public exception.

    `message` must already be safe to show a caller or put in a log: never a
    raw provider response body, a URL with a query string, a header, a
    token, or an account identifier. Callers constructing a `GatewayError`
    are responsible for that redaction before this point — this class does
    not scrub its input.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        retryable: bool = False,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.correlation_id = correlation_id

    def __repr__(self) -> str:
        return (
            f"GatewayError(code={self.code!r}, message={self.message!r}, "
            f"retryable={self.retryable!r}, correlation_id={self.correlation_id!r})"
        )


# Collapses the nine error codes into the five documented CLI exit-code
# buckets (DESIGN.md §7.3): success, safe runtime/provider failure, usage
# error, configuration/not-ready error, authentication required.
EXIT_CODE_SUCCESS = 0
EXIT_CODE_PROVIDER_FAILURE = 1
EXIT_CODE_USAGE_ERROR = 2
EXIT_CODE_CONFIGURATION_ERROR = 3
EXIT_CODE_AUTH_REQUIRED = 4

EXIT_CODE_MAP: dict[ErrorCode, int] = {
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


def exit_code_for(error: GatewayError | None) -> int:
    """CLI exit code for a completed call. `None` means success."""
    if error is None:
        return EXIT_CODE_SUCCESS
    return EXIT_CODE_MAP[error.code]
