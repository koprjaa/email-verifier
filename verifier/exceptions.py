# src/verifier/exceptions.py


class EmailVerifierException(Exception):
    """Base exception class for all EmailVerifier-specific errors."""

    def __init__(
        self, message: str, status_code: str = None, verification_steps: list = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.verification_steps = (
            verification_steps if verification_steps is not None else []
        )


class VerificationError(EmailVerifierException):
    """Generic error during email verification process."""

    pass


class TimeoutException(EmailVerifierException):
    """Timeout occurred during operation (e.g., waiting for DNS or SMTP response)."""

    pass


class NoConnectionException(EmailVerifierException):
    """Unable to establish connection to target server."""

    pass


class UnexpectedResponseException(EmailVerifierException):
    """Server response was unexpected or could not be interpreted."""

    pass


class RateLimitException(EmailVerifierException):
    """Rate limit exceeded on target server or service."""

    pass


class DNSError(EmailVerifierException):
    """DNS-related error (e.g., MX records not found)."""

    pass


class SyntaxError(EmailVerifierException):
    """Email address format is invalid (does not meet syntax rules)."""

    pass


class DisposableDomainError(EmailVerifierException):
    """Email domain is recognized as disposable."""

    pass


class ConfigurationError(EmailVerifierException):
    """Configuration error in EmailVerifier or its dependencies."""

    pass
