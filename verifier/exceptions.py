#
# Project: email-verifier
# File:    exceptions.py
#
# Description:
# The exception types the verifier raises.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

class EmailVerifierException(Exception):
    """Base for every error this package raises.

    Carries the status the address should be reported with and the steps that
    ran before the failure, so a caller can report a partial result instead of
    only an error.
    """

    def __init__(
        self,
        message: str,
        status_code: str | None = None,
        verification_steps: list | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.verification_steps = (
            verification_steps if verification_steps is not None else []
        )


class TimeoutException(EmailVerifierException):
    """An operation ran out of time, usually a DNS or SMTP response."""


class NoConnectionException(EmailVerifierException):
    """The mail server could not be reached."""


class UnexpectedResponseException(EmailVerifierException):
    """The server answered with something the client cannot interpret."""


class RateLimitException(EmailVerifierException):
    """The server is refusing further probes for now.

    Caught on its own, because the address is then neither valid nor invalid.
    The caller has to try again rather than record a verdict.
    """


class DNSError(EmailVerifierException):
    """The domain has no usable MX record."""
