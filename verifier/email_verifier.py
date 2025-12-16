"""
Project: email-verifier
File: verifier/email_verifier.py
Description: Core email verification engine implementing SMTP, DNS, and catch-all domain checks.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import asyncio
import logging
import random
import socket
import re
import json
import time
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiodns
import aiosmtplib
from email_validator import (
    EmailNotValidError,
    validate_email,
)
from dns.resolver import Resolver

from .exceptions import (
    EmailVerifierException,
    TimeoutException,
    NoConnectionException,
    UnexpectedResponseException,
    RateLimitException,
    DNSError,
    SyntaxError as VerifierSyntaxError,
    DisposableDomainError,
    ConfigurationError,
)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "default_verifier_config.json"
SMTP_CODES_SUCCESS = (250, 251, 252)
SMTP_CODES_TEMP_FAIL = (421, 450, 451, 452)
SMTP_CODES_PERM_FAIL = (500, 501, 502, 503, 504, 550, 551, 552, 553, 554)

# SMTP error codes that indicate temporary failures (retryable)
TEMPORARY_ERROR_CODES = {
    421,
    450,
    451,
    452,
    454,
    458,
    459,
    471,
    472,
    552,
    553,
    554,
}

KNOWN_FREEMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoodns.net",
    "aol.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "seznam.cz",
    "email.cz",
    "post.cz",
    "centrum.cz",
    "gmx.com",
    "gmx.net",
    "mail.com",
    "mail.ru",
    "yandex.ru",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "mac.com",
}
CATCHALL_TEST_PORTS = [25, 587]

MICROSOFT_DOMAINS = {
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "office365.com",
    "microsoft.com",
}

MICROSOFT_MX_PATTERNS = [
    "*.mail.protection.outlook.com",
    "*.outlook.com",
    "*.hotmail.com",
]

# Czech email providers that are sensitive to sender reputation
REPUTATION_SENSITIVE_DOMAINS = {"centrum.cz", "post.cz", "seznam.cz", "email.cz"}

REPUTATION_ERROR_PATTERNS = [
    "poor reputation",
    "reputation",
    "spam",
    "blocked",
    "blacklisted",
    "rejected",
]


class EmailVerifier:
    """Verifies email addresses using SMTP and DNS queries."""

    def __init__(
        self,
        timeout: int = 15,
        smtp_timeout: int = 10,
        dns_timeout: int = 5,
        catchall_test_enabled: bool = True,
        check_disposable_enabled: bool = True,
        connect_port: int = 25,
        rate_limit_delay_base: float = 2.0,
        max_concurrent_domains: int = 5,
        helo_hostname: Optional[str] = None,
        retry_attempts: int = 2,
        retry_delay_base: float = 5.0,
        disposable_domains_file: str = "data/disposable_domains.txt",
        logger: Optional[logging.Logger] = None,
        dns_servers: Optional[List[str]] = None,
        sender_email_override: Optional[str] = None,
        default_sender_email_config: Optional[str] = None,
        sender_emails_by_domain_config: Optional[Dict[str, str]] = None,
    ):
        self.logger = logger or self._setup_default_logger()
        self.internal_config = self._load_default_config_from_file()

        self.timeout = timeout
        self.smtp_timeout = smtp_timeout
        self.dns_timeout = dns_timeout
        self.catchall_test_enabled = catchall_test_enabled
        self.check_disposable_enabled = check_disposable_enabled
        self.default_connect_port = connect_port
        self.rate_limit_delay_base = rate_limit_delay_base
        # Semaphore limits concurrent connections to different domains to avoid overwhelming servers
        self.max_concurrent_domains_semaphore = asyncio.Semaphore(
            max_concurrent_domains
        )
        # HELO hostname defaults to machine FQDN if not specified
        self.helo_hostname = (
            helo_hostname
            or self.internal_config.get("helo_hostname")
            or socket.getfqdn()
        )
        self.retry_attempts = retry_attempts
        self.retry_delay_base = retry_delay_base
        self.sender_email_override = sender_email_override
        self.default_sender_email = (
            default_sender_email_config
            or self.internal_config.get(
                "default_sender_email", f"verifier@{self.helo_hostname}"
            )
        )
        self.sender_emails_by_domain = (
            sender_emails_by_domain_config
            or self.internal_config.get("sender_emails_by_domain", {})
        )

        _dns_servers_to_use = dns_servers or self.internal_config.get("dns_servers")
        # Sync resolver used only for configuring async resolver
        self.dns_resolver = Resolver()
        if _dns_servers_to_use:
            self.dns_resolver.nameservers = _dns_servers_to_use

        self.async_dns_resolver = aiodns.DNSResolver(
            timeout=self.dns_timeout,
            tries=self.internal_config.get("dns_resolver_tries", 2),
            servers=_dns_servers_to_use,
        )

        self.disposable_domains_file_path = Path(disposable_domains_file)
        self._ensure_data_dirs_exist()
        self.disposable_domains: Set[str] = self._load_disposable_domains()

        self.verification_steps: List[Dict[str, Any]] = []
        self.is_catchall_domain_cache: Dict[str, Optional[bool]] = {}
        self.mx_records_cache: Dict[str, List[Tuple[int, str]]] = {}
        # Lock protects MX cache from concurrent access
        self.mx_cache_lock = asyncio.Lock()

        self.logger.info(
            f"EmailVerifier init. HELO: {self.helo_hostname}, Catch-all: {self.catchall_test_enabled}, Disposable check: {self.check_disposable_enabled}"
        )

    def _setup_default_logger(self) -> logging.Logger:
        """Creates and returns default logger instance if none provided."""
        logger = logging.getLogger("EmailVerifierDefault")
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        return logger

    def _load_default_config_from_file(self) -> Dict[str, Any]:
        """Loads default configuration from JSON file."""
        if DEFAULT_CONFIG_PATH.exists():
            try:
                with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error parsing/loading {DEFAULT_CONFIG_PATH}: {e}")
        return {}

    def _ensure_data_dirs_exist(self):
        """Ensures data directory exists for files like disposable_domains.txt."""
        try:
            self.disposable_domains_file_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.logger.error(
                f"Error creating data directory {self.disposable_domains_file_path.parent}: {e}"
            )

    def _load_disposable_domains(self) -> Set[str]:
        """Loads disposable domains from file. Returns lowercase set of domains."""
        if not self.check_disposable_enabled:
            return set()
        if self.disposable_domains_file_path.exists():
            try:
                with open(
                    self.disposable_domains_file_path, "r", encoding="utf-8"
                ) as f:
                    # Skip empty lines and comments (lines starting with #)
                    return {
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    }
            except Exception as e:
                self.logger.error(
                    f"Error loading disposable domains from '{self.disposable_domains_file_path}': {e}"
                )
        else:
            self.logger.warning(
                f"Disposable domains file '{self.disposable_domains_file_path}' not found."
            )
        return set()

    def reset_internal_state_for_run(self):
        """Resets internal caches for new batch run. Used when instance processes multiple batches."""
        self.is_catchall_domain_cache = {}
        self.mx_records_cache = {}

    def _reset_steps_for_single_email(self):
        """Resets verification steps list for new email."""
        self.verification_steps = []

    def _add_verification_step(
        self, status: str, action: str, details: str = "", code: Optional[Any] = None
    ):
        """Adds a step to verification trace for debugging and user feedback."""
        step = {
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "action": action,
            "details": details,
            "code": str(code) if code is not None else None,
        }
        self.verification_steps.append(step)
        self.logger.debug(
            f"Step: {action} - {details} (Status: {status}, Code: {code})"
        )

    async def _resolve_mx_records(self, domain: str) -> List[Tuple[int, str]]:
        """Resolves and sorts MX records for domain. Uses async DNS resolver with caching."""
        self._add_verification_step("info", "DNS MX query", f"Getting MX for {domain}")

        async with self.mx_cache_lock:
            if domain in self.mx_records_cache:
                cached_records = self.mx_records_cache[domain]
                self._add_verification_step(
                    "info", "DNS MX query", f"Using cached MX records for {domain}"
                )
                return cached_records

        try:
            # Create new resolver instance per query (aiodns recommendation for asyncio stability)
            resolver = aiodns.DNSResolver(
                timeout=self.dns_timeout,
                tries=self.internal_config.get("dns_resolver_tries", 2),
            )
            if (
                hasattr(self.async_dns_resolver, "nameservers")
                and self.async_dns_resolver.nameservers
            ):
                resolver.nameservers = self.async_dns_resolver.nameservers

            mx_records = await resolver.query(domain, "MX")
            # Sort by priority and remove trailing dot from hostname
            sorted_mxs = sorted(
                [(int(r.priority), str(r.host).rstrip(".")) for r in mx_records]
            )
            if not sorted_mxs:
                msg = f"No MX records found for {domain}."
                self._add_verification_step("error", "DNS MX query", msg)
                raise DNSError(
                    msg,
                    status_code="no_mx_records",
                    verification_steps=self.verification_steps,
                )

            async with self.mx_cache_lock:
                self.mx_records_cache[domain] = sorted_mxs

            self._add_verification_step(
                "success", "DNS MX query", f"Found MX: {sorted_mxs}"
            )
            return sorted_mxs
        except aiodns.error.DNSError as e:
            msg = f"DNS error (MX) for {domain}: {e.args[0]} (code: {e.args[1]})"
            self._add_verification_step("error", "DNS MX query", msg)
            raise DNSError(
                msg,
                status_code=f"dns_error_code_{e.args[1]}",
                verification_steps=self.verification_steps,
            ) from e
        except Exception as e:
            msg = f"Unexpected error during DNS MX query for {domain}: {str(e)}"
            self._add_verification_step("error", "DNS MX query", msg)
            raise DNSError(
                msg,
                status_code="dns_resolver_failure",
                verification_steps=self.verification_steps,
            ) from e

    async def _resolve_host_ip_for_log(self, hostname: str) -> Optional[str]:
        """Resolves hostname to IP (A or AAAA record) for logging purposes. Returns first found IP or None."""
        try:
            resolver = aiodns.DNSResolver(
                timeout=self.dns_timeout,
                tries=self.internal_config.get("dns_resolver_tries", 2),
            )
            if (
                hasattr(self.async_dns_resolver, "nameservers")
                and self.async_dns_resolver.nameservers
            ):
                resolver.nameservers = self.async_dns_resolver.nameservers
            records_a = await resolver.query(hostname, "A")
            if records_a:
                return str(records_a[0].host)
        except aiodns.error.DNSError:
            pass
        try:
            resolver = aiodns.DNSResolver(
                timeout=self.dns_timeout,
                tries=self.internal_config.get("dns_resolver_tries", 2),
            )
            if (
                hasattr(self.async_dns_resolver, "nameservers")
                and self.async_dns_resolver.nameservers
            ):
                resolver.nameservers = self.async_dns_resolver.nameservers
            records_aaaa = await resolver.query(hostname, "AAAA")
            if records_aaaa:
                return str(records_aaaa[0].host)
        except aiodns.error.DNSError:
            pass
        return None

    def _is_disposable_domain(self, domain: str) -> bool:
        """Checks if domain or its parent domain is in disposable domains list."""
        if not self.check_disposable_enabled:
            return False
        normalized_domain = domain.lower()
        if normalized_domain in self.disposable_domains:
            self._add_verification_step(
                "warning", "Domain check", f"Domain '{domain}' is disposable."
            )
            return True
        parts = normalized_domain.split(".")
        # Check if parent domain (e.g., sub.example.com -> example.com) is disposable
        if len(parts) > 2 and ".".join(parts[-2:]) in self.disposable_domains:
            self._add_verification_step(
                "warning", "Domain check", f"Parent domain of '{domain}' is disposable."
            )
            return True
        return False

    def _is_reputation_error(self, code: int, message: str) -> bool:
        """Checks if SMTP error is related to sender IP reputation."""
        if code == 554:
            return True
        message_lower = message.lower()
        return any(pattern in message_lower for pattern in REPUTATION_ERROR_PATTERNS)

    def _get_sender_email(self, recipient_domain: str) -> str:
        """Selects best sender email for recipient domain. Prioritizes domain-specific senders for reputation-sensitive domains."""
        if self.sender_email_override:
            return self.sender_email_override

        # For reputation-sensitive domains, try same-domain or trusted-domain senders first
        if recipient_domain in REPUTATION_SENSITIVE_DOMAINS:
            for domain_key, sender in self.sender_emails_by_domain.items():
                if domain_key == recipient_domain:
                    return sender

            # Fallback to trusted domains if same-domain sender not found
            trusted_domains = ["gmail.com", "outlook.com", "yahoo.com"]
            for domain_key in trusted_domains:
                if domain_key in self.sender_emails_by_domain:
                    return self.sender_emails_by_domain[domain_key]

        if recipient_domain in self.sender_emails_by_domain:
            return self.sender_emails_by_domain[recipient_domain]

        return self.default_sender_email

    async def _perform_smtp_check(
        self, email: str, domain: str, mx_host: str, port: int
    ) -> Tuple[bool, str, str, Optional[int]]:
        """
        Provede SMTP komunikaci s MX serverem pro ověření emailové adresy.
        :param email: Emailová adresa k ověření.
        :param domain: Doména emailové adresy.
        :param mx_host: Hostitel MX serveru.
        :param port: Port pro SMTP připojení.
        :return: Tuple (platnost, stavový kód, zpráva, interní SMTP kód).
        :raises TimeoutException, NoConnectionException, RateLimitException, UnexpectedResponseException
        """
        server_ip_for_log = await self._resolve_host_ip_for_log(
            mx_host
        )  # Získá IP adresu serveru pro log
        self._add_verification_step(
            "info",
            f"SMTP Connect (Port {port})",
            f"Attempting connect to {mx_host} (IP: {server_ip_for_log or 'N/A'})",
        )

        smtp_client = None
        current_smtp_code = None  # Poslední obdržený SMTP kód
        try:
            async with self.max_concurrent_domains_semaphore:  # Omezení souběžných připojení
                smtp_client = aiosmtplib.SMTP(  # Vytvoření SMTP klienta
                    hostname=mx_host, port=port, timeout=self.smtp_timeout
                )
                await smtp_client.connect(
                    timeout=self.smtp_timeout
                )  # Připojení k serveru
            self._add_verification_step(
                "success",
                f"SMTP Connect (Port {port})",
                f"Connected to {mx_host}:{port}",
            )

            try:
                code, msg_bytes = await smtp_client.ehlo()  # Pokus o EHLO
            except aiosmtplib.SMTPException:
                (
                    code,
                    msg_bytes,
                ) = await smtp_client.helo()  # Pokud EHLO selže, zkusí HELO

            current_smtp_code = code
            msg_str = (
                msg_bytes
                if isinstance(msg_bytes, str)
                else msg_bytes.decode(errors="ignore")
            )  # Dekóduje zprávu
            self._add_verification_step(
                "info", "EHLO/HELO", f"Resp: {code} {msg_str}", code
            )
            # Kód 220 (připraveno) je také úspěšný pro EHLO/HELO
            if code not in SMTP_CODES_SUCCESS and code != 220:
                raise UnexpectedResponseException(  # Pokud EHLO/HELO selže
                    f"EHLO/HELO failed: {code} {msg_str}",
                    status_code="ehlo_failed",
                    verification_steps=self.verification_steps,
                )

            sender = self._get_sender_email(domain)  # Získá vhodného odesílatele
            self._add_verification_step("info", "MAIL FROM", f"Sender: {sender}")
            code, msg_bytes = await smtp_client.mail(sender)  # Odešle MAIL FROM
            current_smtp_code = code
            msg_str = (
                msg_bytes
                if isinstance(msg_bytes, str)
                else msg_bytes.decode(errors="ignore")
            )
            self._add_verification_step(
                "info", "MAIL FROM", f"Resp: {code} {msg_str}", code
            )

            # Pokud je detekována chyba reputace
            if self._is_reputation_error(code, msg_str):
                self._add_verification_step(
                    "warning",
                    "MAIL FROM",
                    f"Reputation-based rejection detected. Will retry with different sender if available.",
                )
                # Pokusí se najít alternativního odesílatele
                alternative_sender = None
                for test_domain, test_sender in self.sender_emails_by_domain.items():
                    if test_domain != domain and test_sender != sender:
                        alternative_sender = test_sender
                        break

                if alternative_sender:  # Pokud je nalezen alternativní odesílatel
                    self._add_verification_step(
                        "info",
                        "MAIL FROM",
                        f"Retrying with alternative sender: {alternative_sender}",
                    )
                    code, msg_bytes = await smtp_client.mail(
                        alternative_sender
                    )  # Opakuje MAIL FROM
                    current_smtp_code = code
                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )
                    self._add_verification_step(
                        "info", "MAIL FROM", f"Resp: {code} {msg_str}", code
                    )

            if code not in SMTP_CODES_SUCCESS:  # Pokud MAIL FROM selže
                if code in SMTP_CODES_TEMP_FAIL:  # Dočasná chyba
                    raise RateLimitException(
                        f"MAIL FROM temp error: {code} {msg_str}",
                        status_code="mail_from_temp_fail",
                        verification_steps=self.verification_steps,
                    )
                raise UnexpectedResponseException(  # Trvalá chyba
                    f"MAIL FROM perm error: {code} {msg_str}",
                    status_code="mail_from_perm_fail",
                    verification_steps=self.verification_steps,
                )

            self._add_verification_step("info", "RCPT TO", f"Recipient: {email}")
            code, msg_bytes = await smtp_client.rcpt(email)  # Odešle RCPT TO
            current_smtp_code = code
            msg_str = (
                msg_bytes
                if isinstance(msg_bytes, str)
                else msg_bytes.decode(errors="ignore")
            )
            self._add_verification_step(
                "info", "RCPT TO", f"Resp: {code} {msg_str}", code
            )

            try:
                await smtp_client.rset()  # Resetuje SMTP transakci
            except (aiosmtplib.SMTPException, OSError):
                pass  # Ignoruje chyby při RSET

            if code in SMTP_CODES_SUCCESS:  # Pokud RCPT TO uspěje, email je platný
                return True, "valid", msg_str, code
            if code in SMTP_CODES_TEMP_FAIL:  # Dočasná chyba u RCPT TO
                raise RateLimitException(
                    f"RCPT TO temp error: {code} {msg_str}",
                    status_code="rcpt_to_temp_fail",
                    verification_steps=self.verification_steps,
                )
            # Jinak je schránka neplatná (trvalá chyba)
            return False, "invalid_mailbox", msg_str, code

        except (
            asyncio.TimeoutError,
            aiosmtplib.SMTPTimeoutError,
        ) as e:  # Chyba časového limitu
            self._add_verification_step(
                "error",
                f"SMTP Timeout (Port {port})",
                f"Timeout with {mx_host}: {str(e)}",
            )
            raise TimeoutException(
                f"Timeout on {mx_host}:{port} - {str(e)}",
                status_code="smtp_timeout",
                verification_steps=self.verification_steps,
            ) from e
        except (  # Chyby připojení
            aiosmtplib.SMTPConnectError,
            ConnectionRefusedError,
            socket.gaierror,  # Chyba překladu adresy
            OSError,  # Obecná chyba OS (např. síť nedostupná)
        ) as e:
            self._add_verification_step(
                "error",
                f"SMTP Connect Error (Port {port})",
                f"Connect error to {mx_host}: {str(e)}",
            )
            raise NoConnectionException(
                f"Connect error to {mx_host}:{port} - {str(e)}",
                status_code="smtp_connect_error",
                verification_steps=self.verification_steps,
            ) from e
        except (
            RateLimitException,
            UnexpectedResponseException,
        ):  # Propaguje specifické výjimky
            raise
        except aiosmtplib.SMTPException as e:  # Obecná SMTP chyba
            self._add_verification_step(
                "error",
                f"SMTP Error (Port {port})",
                f"General SMTP error with {mx_host}: {e.code} {e.message}",
            )
            return False, "unknown_smtp_error", f"{e.code} {e.message}", e.code
        finally:
            if smtp_client and smtp_client.is_connected:  # Pokud je klient připojen
                try:
                    await smtp_client.quit()  # Ukončí SMTP spojení
                except (aiosmtplib.SMTPException, OSError):
                    pass  # Ignoruje chyby při QUIT

        # Pokud se kód dostane sem, došlo k neočekávanému průběhu
        return (
            False,
            "unknown_flow_error",
            "Unexpected flow in SMTP check",
            current_smtp_code,
        )

    def _is_microsoft_domain(self, domain: str, mx_host: str) -> bool:
        """
        Zkontroluje, zda doména nebo MX hostitel souvisí se servery Microsoftu.
        """
        if domain in MICROSOFT_DOMAINS:  # Přímá shoda domény
            return True
        # Zkontroluje, zda MX hostitel odpovídá vzorům Microsoftu
        return any(
            mx_host.endswith(pattern.replace("*", ""))
            for pattern in MICROSOFT_MX_PATTERNS
        )

    async def _is_catch_all_domain(
        self, domain: str, mx_hosts_priority: List[Tuple[int, str]]
    ) -> bool:
        """
        Testuje, zda je doména "catch-all" (přijímá emaily na neexistující adresy).
        :param domain: Doména k testování.
        :param mx_hosts_priority: Seznam MX hostitelů a jejich priorit.
        :return: True, pokud je doména pravděpodobně catch-all, jinak False.
        """
        if not self.catchall_test_enabled:  # Pokud je testování vypnuto
            self._add_verification_step("info", "Catch-all Test", "Skipped (config).")
            return False
        if (
            domain in KNOWN_FREEMAIL_DOMAINS
        ):  # Freemailové domény se netestují jako catch-all
            self._add_verification_step(
                "info", "Catch-all Test", f"Skipped ('{domain}' is known freemail)."
            )
            return False
        if domain in self.is_catchall_domain_cache:  # Zkontroluje cache
            cached = self.is_catchall_domain_cache[domain]
            self._add_verification_step(
                "info",
                "Catch-all Test (Cache)",
                f"Result for '{domain}' from cache: {cached}",
            )
            return cached if cached is not None else False  # Vrátí výsledek z cache

        self._add_verification_step(
            "info", "Catch-all Test", f"Starting test for '{domain}'."
        )
        ts = int(time.time())  # Aktuální časové razítko
        # Vygeneruje unikátní testovací emailové adresy
        test_emails = [
            f"catchall-probe-{ts}-{random.getrandbits(16)}-{i}@{domain}"
            for i in range(2)  # Použije 2 testovací emaily pro větší spolehlivost
        ]
        successful_tests = (
            0  # Počet úspěšných testů (kdy server přijal neexistující email)
        )
        inconclusive_tests = (
            0  # Počet nejednoznačných testů (např. u Microsoft serverů)
        )
        mx_hosts = [host for _, host in mx_hosts_priority]  # Seznam MX hostitelů

        for test_email in test_emails:
            accepted = False  # Zda byl testovací email přijat
            for mx_host in mx_hosts:
                if (
                    accepted
                ):  # Pokud byl email již přijat jiným MX, není třeba pokračovat
                    break
                smtp_client = None  # Explicitní inicializace
                try:
                    smtp_client = aiosmtplib.SMTP(  # Vytvoření SMTP klienta
                        hostname=mx_host,
                        port=25,
                        timeout=self.smtp_timeout,  # Testuje na portu 25
                    )
                    await smtp_client.connect(timeout=self.smtp_timeout)

                    try:
                        code, msg_bytes = await smtp_client.ehlo()
                    except aiosmtplib.SMTPException:
                        code, msg_bytes = await smtp_client.helo()

                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )
                    if code not in SMTP_CODES_SUCCESS and code != 220:
                        continue  # Přeskočí na další MX, pokud EHLO/HELO selže

                    sender = self._get_sender_email(domain)  # Získá odesílatele
                    code, msg_bytes = await smtp_client.mail(sender)
                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )
                    if code not in SMTP_CODES_SUCCESS:
                        continue  # Přeskočí na další MX, pokud MAIL FROM selže

                    code, msg_bytes = await smtp_client.rcpt(
                        test_email
                    )  # Odešle RCPT TO s testovacím emailem
                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )

                    # Speciální zacházení pro Microsoft domény
                    if self._is_microsoft_domain(domain, mx_host):
                        # Odpověď "Access denied" od Microsoftu je často nejednoznačná
                        if code == 550 and "Access denied" in msg_str:
                            self._add_verification_step(
                                "warning",
                                "Catch-all Test (Microsoft)",
                                f"Microsoft domain detected - Access denied response treated as inconclusive.",
                            )
                            inconclusive_tests += 1
                            accepted = True  # Považuje za přijaté pro účely ukončení testu na tomto MX
                            break  # Ukončí test pro tento email na tomto MX

                    if (
                        code in SMTP_CODES_SUCCESS
                    ):  # Pokud server přijal testovací email
                        self._add_verification_step(
                            "warning",
                            "Catch-all Test (Attempt)",
                            f"Test email '{test_email}' accepted on {mx_host}:25.",
                        )
                        successful_tests += 1
                        accepted = True
                        break  # Ukončí test pro tento email na tomto MX
                except Exception as e:  # Ignoruje chyby při testování catch-all, aby neovlivnily hlavní ověření
                    self.logger.debug(f"Unexpected error in catch-all sub-test: {e}")
                finally:
                    if smtp_client and smtp_client.is_connected:
                        try:
                            await smtp_client.quit()
                        except (aiosmtplib.SMTPException, OSError):
                            pass
            if not accepted:  # Pokud email nebyl přijat žádným MX serverem
                self._add_verification_step(
                    "info",
                    "Catch-all Test (Attempt)",
                    f"Test email '{test_email}' not accepted.",
                )

        # Vyhodnocení výsledků testu catch-all
        is_catchall = False
        if successful_tests > 0:  # Pokud alespoň jeden testovací email byl přijat
            is_catchall = True
        elif (
            inconclusive_tests > 0
        ):  # Pokud byly testy nejednoznačné (typicky Microsoft)
            # Pro Microsoft domény s nejednoznačnými výsledky označí jako pravděpodobný catch-all
            is_catchall = True
            self._add_verification_step(
                "warning",
                "Catch-all Test (Result)",
                f"Domain '{domain}' is likely catch-all (Microsoft domain with inconclusive results).",
            )
        else:  # Pokud žádný testovací email nebyl přijat
            self._add_verification_step(
                "info",
                "Catch-all Test (Result)",
                f"Domain '{domain}' is not catch-all. Successful: {successful_tests}/{len(test_emails)}.",
            )

        self.is_catchall_domain_cache[domain] = is_catchall  # Uloží výsledek do cache
        return is_catchall

    def _is_temporary_error(self, code: int, message: str) -> bool:
        """
        Zkontroluje, zda SMTP chyba (kód a zpráva) indikuje dočasný problém,
        který by mohl být vyřešen opakováním pokusu.
        """
        if code in TEMPORARY_ERROR_CODES:  # Kontrola podle SMTP kódu
            return True
        message_lower = message.lower()  # Převede zprávu na malá písmena
        # Hledá klíčová slova indikující dočasnou chybu
        return any(
            pattern in message_lower
            for pattern in [
                "temporary",
                "try again",
                "later",
                "busy",
                "overloaded",
                "rate limit",
                "throttled",
                "quota",
                "limit exceeded",
            ]
        )

    async def verify_single_email(self, email: str, attempt: int = 1) -> Dict[str, Any]:
        """
        Ověří platnost jedné emailové adresy.
        :param email: Emailová adresa k ověření.
        :param attempt: Číslo aktuálního pokusu (pro opakování při chybách).
        :return: Slovník s výsledky ověření.
        """
        self._reset_steps_for_single_email()  # Resetuje kroky pro tento email
        self._add_verification_step(
            "info", "Verification start", f"Email: {email}, Attempt: {attempt}"
        )
        # Výchozí struktura výsledku
        res = {
            "email": email,
            "is_valid": False,  # Zda je email platný
            "status_code": "unknown_error",  # Stavový kód výsledku (např. "valid", "invalid_mailbox")
            "message": "Unknown error",  # Popisná zpráva výsledku
            "is_catchall": False,  # Zda je doména catch-all
            "mx_record": None,  # Použitý MX záznam
            "smtp_code_internal": None,  # Interní SMTP kód z odpovědi serveru
            "verification_steps": self.verification_steps,  # Seznam kroků ověření
        }
        try:
            # Kontrola syntaxe emailu pomocí externí knihovny
            val_res = validate_email(
                email, check_deliverability=False
            )  # check_deliverability=False, protože to děláme sami
            domain = val_res.domain.lower()  # Získá doménu z emailu
            self._add_verification_step(
                "success", "Syntax check", f"Email '{email}' syntax valid."
            )
        except EmailNotValidError as e:  # Chyba syntaxe
            self._add_verification_step(
                "error", "Syntax check", f"Invalid email format '{email}': {e}"
            )
            res.update(
                {"is_valid": False, "status_code": "syntax_error", "message": str(e)}
            )
            return res  # Ukončí ověření

        # Kontrola jednorázové domény
        if self._is_disposable_domain(domain):
            res.update(
                {
                    "is_valid": False,
                    "status_code": "disposable_domain",
                    "message": "Domain is disposable.",
                }
            )
            return res  # Ukončí ověření

        mx_records: List[Tuple[int, str]] = []
        try:
            mx_records = await self._resolve_mx_records(domain)  # Získá MX záznamy
            if mx_records:
                res["mx_record"] = mx_records[0][
                    1
                ]  # Uloží první (nejvyšší prioritu) MX záznam
        except DNSError as e:  # Chyba při získávání MX záznamů
            res.update(
                {
                    "is_valid": False,
                    "status_code": e.status_code or "dns_error_mx",
                    "message": str(e),
                }
            )
            return res
        except Exception as e:  # Neočekávaná chyba při DNS dotazu
            self._add_verification_step(
                "error", "DNS MX query", f"Unexpected error: {str(e)}"
            )
            res.update(
                {
                    "is_valid": False,
                    "status_code": "dns_unhandled_error",
                    "message": str(e),
                }
            )
            return res

        # Test na catch-all doménu
        is_catchall = await self._is_catch_all_domain(domain, mx_records)
        res["is_catchall"] = is_catchall

        # Iteruje přes MX záznamy (seřazené podle priority) a pokusí se o SMTP ověření
        for _, mx_host in mx_records:
            res["mx_record"] = mx_host  # Aktualizuje MX záznam na aktuálně testovaný
            try:
                # Provede SMTP kontrolu
                smtp_valid, status, msg, code = await self._perform_smtp_check(
                    email, domain, mx_host, self.default_connect_port
                )
                if smtp_valid:  # Pokud je email platný podle SMTP
                    res.update(
                        {
                            "is_valid": True,
                            "status_code": status,
                            "message": msg,
                            "smtp_code_internal": code,
                        }
                    )
                    return res  # Ukončí ověření, email je platný
                # Pokud je schránka neplatná nebo došlo k trvalé chybě
                if status == "invalid_mailbox" or "fail" in status or "error" in status:
                    res.update(
                        {
                            "is_valid": False,
                            "status_code": status,
                            "message": msg,
                            "smtp_code_internal": code,
                        }
                    )
                    return res  # Ukončí ověření, email je neplatný
            except RateLimitException as e:  # Zachytí RateLimitException (dočasná chyba)
                self.logger.warning(
                    f"Rate limit for {email} on {mx_host}:{self.default_connect_port} - {e.message}"
                )
                if attempt < self.retry_attempts:  # Pokud je možné opakování
                    delay = self.retry_delay_base * (
                        2**attempt
                    )  # Exponenciální prodleva
                    self._add_verification_step(
                        "warning",
                        "Rate Limit Retry",
                        f"Attempt {attempt}/{self.retry_attempts}. Waiting {delay:.1f}s for {email}.",
                    )
                    await asyncio.sleep(delay)  # Počká před opakováním
                    return await self.verify_single_email(
                        email, attempt + 1
                    )  # Rekurzivní volání pro opakování
                # Pokud byly vyčerpány pokusy o opakování
                res.update(
                    {
                        "is_valid": None,  # Stav je neznámý (ani platný, ani neplatný)
                        "status_code": e.status_code or "rate_limited",
                        "message": e.message,
                    }
                )
                return res  # Ukončí ověření
            except (
                TimeoutException,
                NoConnectionException,
            ) as e:  # Zachytí Timeout nebo NoConnection (může být dočasné)
                self.logger.warning(f"Temp error for {email} on {mx_host}: {e.message}")
                # Zkontroluje, zda je chyba skutečně dočasná
                if self._is_temporary_error(
                    e.code if hasattr(e, "code") else 0, e.message
                ):
                    if attempt < self.retry_attempts:  # Pokud je možné opakování
                        delay = self.retry_delay_base * (2**attempt)
                        self._add_verification_step(
                            "warning",
                            "Temporary Error Retry",
                            f"Attempt {attempt}/{self.retry_attempts}. Waiting {delay:.1f}s for {email}.",
                        )
                        await asyncio.sleep(delay)
                        return await self.verify_single_email(email, attempt + 1)
                # Pokud chyba není dočasná nebo byly vyčerpány pokusy, pokračuje na další MX
                continue
            except EmailVerifierException as e:  # Zachytí ostatní vlastní výjimky
                self.logger.error(
                    f"Verifier error for {email} on {mx_host}: {e.message}"
                )
                # Zkontroluje, zda je chyba dočasná (např. UnexpectedResponse, která může být dočasná)
                if self._is_temporary_error(
                    e.code if hasattr(e, "code") else 0, e.message
                ):
                    if attempt < self.retry_attempts:
                        delay = self.retry_delay_base * (2**attempt)
                        self._add_verification_step(
                            "warning",
                            "Temporary Error Retry",
                            f"Attempt {attempt}/{self.retry_attempts}. Waiting {delay:.1f}s for {email}.",
                        )
                        await asyncio.sleep(delay)
                        return await self.verify_single_email(email, attempt + 1)
                # Pokud chyba není dočasná nebo byly vyčerpány pokusy, pokračuje na další MX
                continue
            except Exception as e:  # Zachytí neočekávané chyby během SMTP komunikace
                self.logger.error(
                    f"Unexpected SMTP error for {email} on {mx_host}: {e}",
                    exc_info=True,  # Zapíše traceback do logu
                )
                continue  # Pokračuje na další MX server

        # Pokud se nepodařilo ověřit na žádném MX serveru (všechny selhaly nebo vrátily dočasnou chybu)
        self._add_verification_step(
            "error", "SMTP Verification", "Failed to verify on any MX."
        )
        res.update(
            {
                "is_valid": None,  # Stav je neznámý
                "status_code": "unreachable_all_mx"  # Stavový kód, pokud existovaly MX záznamy
                if mx_records
                else (
                    res["status_code"] or "dns_error_mx"
                ),  # Jinak použije předchozí stav (např. z DNS chyby)
                "message": "Cannot connect to any MX or all returned temp error."
                if mx_records
                else (res["message"] or "MX records error"),
            }
        )
        return res

    async def verify_emails_in_batch(
        self, email_list: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Ověří seznam emailových adres souběžně.
        :param email_list: Seznam emailových adres k ověření.
        :return: Seznam slovníků s výsledky ověření pro každý email.
        """
        # Vytvoří úlohy (tasks) pro souběžné ověření každého emailu
        tasks = [self.verify_single_email(email) for email in email_list]
        # Spustí úlohy souběžně a počká na jejich dokončení
        # return_exceptions=True zajistí, že výjimky budou vráceny jako výsledky, neukončí gather
        results_or_exceptions = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for i, item in enumerate(results_or_exceptions):
            email = email_list[i]  # Původní email pro tento výsledek
            if isinstance(item, Exception):  # Pokud úloha skončila výjimkou
                self.logger.error(
                    f"Unexpected exception during batch for '{email}': {item}",
                    exc_info=True,  # Zapíše traceback do logu
                )
                # Získá kroky ověření z výjimky, pokud je to možné
                steps = (
                    item.verification_steps
                    if isinstance(item, EmailVerifierException)
                    and item.verification_steps
                    else []
                )
                # Vytvoří chybový výsledek
                final_results.append(
                    {
                        "email": email,
                        "is_valid": None,
                        "status_code": "internal_verifier_error",
                        "message": f"Verifier error: {type(item).__name__} - {str(item)}",
                        "is_catchall": False,
                        "mx_record": None,
                        "smtp_code_internal": None,
                        "verification_steps": steps,
                    }
                )
            else:  # Pokud úloha vrátila normální výsledek (slovník)
                final_results.append(item)
        return final_results
