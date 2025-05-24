# src/verifier/exceptions.py


class EmailVerifierException(Exception):
    """
    Základní třída výjimky pro všechny specifické chyby v EmailVerifieru.

    Attributes:
        message (str): Popisná zpráva o chybě.
        status_code (str, optional): Interní stavový kód chyby pro snadnější identifikaci.
                                     Výchozí je None.
        verification_steps (list, optional): Seznam kroků verifikace, které vedly k této chybě.
                                            Výchozí je prázdný seznam.
    """

    def __init__(
        self, message: str, status_code: str = None, verification_steps: list = None
    ):
        """
        Inicializuje EmailVerifierException.

        Args:
            message (str): Zpráva o chybě.
            status_code (str, optional): Interní stavový kód chyby.
            verification_steps (list, optional): Seznam kroků verifikace.
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.verification_steps = (
            verification_steps if verification_steps is not None else []
        )


class VerificationError(EmailVerifierException):
    """
    Obecná chyba, která nastala během procesu verifikace emailu.
    Indikuje, že email nemohl být úspěšně ověřen z nějakého důvodu,
    který není specifikován detailnějšími typy výjimek.
    """

    pass


class TimeoutException(EmailVerifierException):
    """
    Výjimka signalizující vypršení časového limitu (timeout) během operace.
    Například při čekání na odpověď od DNS nebo SMTP serveru.
    """

    pass


class NoConnectionException(EmailVerifierException):
    """
    Výjimka signalizující nemožnost navázat spojení s cílovým serverem.
    Může nastat, pokud server není dostupný nebo odmítá spojení.
    """

    pass


class UnexpectedResponseException(EmailVerifierException):
    """
    Výjimka signalizující, že odpověď od serveru byla neočekávaná
    nebo nemohla být správně interpretována.
    """

    pass


class RateLimitException(EmailVerifierException):
    """
    Výjimka signalizující, že byl překročen povolený počet požadavků
    (rate limit) na cílový server nebo službu.
    """

    pass


class DNSError(EmailVerifierException):
    """
    Výjimka signalizující problém související s DNS dotazy.
    Například nenalezení MX záznamů nebo jiné chyby při DNS překladu.
    """

    pass


class SyntaxError(EmailVerifierException):
    """
    Výjimka signalizující, že formát emailové adresy je neplatný
    (nevyhovuje syntaktickým pravidlům).
    """

    pass


class DisposableDomainError(EmailVerifierException):
    """
    Výjimka signalizující, že doména emailové adresy je rozpoznána
    jako jednorázová (disposable) doména.
    """

    pass


class ConfigurationError(EmailVerifierException):
    """
    Výjimka signalizující problém v konfiguraci EmailVerifieru
    nebo jeho závislostí.
    """

    pass
