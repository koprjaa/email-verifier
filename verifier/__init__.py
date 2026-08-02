#
# Project: email-verifier
# File:    __init__.py
#
# Description:
# Package entry point. Exposes EmailVerifier and the exceptions it raises.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

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
