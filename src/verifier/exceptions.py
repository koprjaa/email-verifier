# src/verifier/exceptions.py

class EmailVerifierException(Exception):
    def __init__(self, message: str, status_code: str = None, verification_steps: list = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.verification_steps = verification_steps if verification_steps is not None else []

class TimeoutException(EmailVerifierException):
    pass

class NoConnectionException(EmailVerifierException):
    pass

class UnexpectedResponseException(EmailVerifierException):
    pass

class RateLimitException(EmailVerifierException):
    pass

class DNSError(EmailVerifierException):
    pass

class SyntaxError(EmailVerifierException):
    pass

class DisposableDomainError(EmailVerifierException):
    pass

class ConfigurationError(EmailVerifierException):
    pass