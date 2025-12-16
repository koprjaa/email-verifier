"""Email verification module."""
from .email_verifier import EmailVerifier
from .exceptions import (
    EmailVerifierException,
    TimeoutException,
    NoConnectionException,
    UnexpectedResponseException,
    RateLimitException,
)

__all__ = [
    "EmailVerifier",
    "EmailVerifierException",
    "TimeoutException",
    "NoConnectionException",
    "UnexpectedResponseException",
    "RateLimitException",
]
