class EmailValidatorException(Exception):
    """Základní výjimka pro chyby validace emailu"""
    pass

class TimeoutException(EmailValidatorException):
    """Výjimka pro timeout při připojení k SMTP serveru"""
    pass

class NoConnectionException(EmailValidatorException):
    """Výjimka pro chyby připojení k SMTP serveru"""
    pass

class UnexpectedResponseException(EmailValidatorException):
    """Výjimka pro neočekávané odpovědi od SMTP serveru"""
    pass

class RateLimitException(EmailValidatorException):
    """Výjimka pro překročení rate limitu"""
    pass

class DomainValidationException(EmailValidatorException):
    """Výjimka pro chyby validace domény"""
    pass

class ConfigurationError(EmailValidatorException):
    """Výjimka pro chyby v konfiguraci"""
    pass

class DNSValidationError(EmailValidatorException):
    """Výjimka pro chyby validace DNS záznamů"""
    pass

class SMTPConnectionError(EmailValidatorException):
    """Výjimka pro chyby SMTP připojení"""
    pass 