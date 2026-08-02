"""
Project: email-verifier
File: verifier/__init__.py
Description: Package initialization for email verification module exports.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
from .email_verifier import EmailVerifier
from .exceptions import (
    EmailVerifierException,
    NoConnectionException,
    RateLimitException,
    TimeoutException,
    UnexpectedResponseException,
)

__all__ = [
    "EmailVerifier",
    "EmailVerifierException",
    "NoConnectionException",
    "RateLimitException",
    "TimeoutException",
    "UnexpectedResponseException",
]
