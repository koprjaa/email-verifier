"""
Project: email-verifier
File: verifier/email_verifier.py
Description: Core email verification engine implementing SMTP, DNS, and catch-all domain checks.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import asyncio
import ipaddress
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

    @staticmethod
    def _is_blocked_ip(ip_str: str) -> bool:
        """
        Returns True if the IP address belongs to a private, loopback, link-local,
        CGNAT, reserved or otherwise non-globally-routable range. Used as an SSRF
        guard to prevent unauthenticated internal-network probing via attacker-
        influenced MX records.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            # Unparseable address -> treat as unsafe.
            return True
        # CGNAT (RFC 6598) is not flagged by is_private; check explicitly.
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip.version == 4 and ip in cgnat:
            return True
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    async def _resolve_all_host_ips(self, hostname: str) -> List[str]:
        """Resolves a hostname to all of its A and AAAA records (for SSRF validation)."""
        ips: List[str] = []
        for record_type in ("A", "AAAA"):
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
                records = await resolver.query(hostname, record_type)
                ips.extend(str(r.host) for r in records)
            except aiodns.error.DNSError:
                continue
        return ips

    async def _assert_mx_host_is_public(self, mx_host: str, port: int) -> None:
        """
        SSRF guard: resolves the MX host and refuses to connect if any of its
        resolved IP addresses fall into a private/loopback/link-local/CGNAT/
        reserved range. Raises NoConnectionException when blocked.
        """
        resolved_ips = await self._resolve_all_host_ips(mx_host)
        if not resolved_ips:
            msg = f"Could not resolve MX host {mx_host} to a public IP address."
            self._add_verification_step(
                "error", f"SSRF check (Port {port})", msg
            )
            raise NoConnectionException(
                msg,
                status_code="mx_host_unresolvable",
                verification_steps=self.verification_steps,
            )
        for ip_str in resolved_ips:
            if self._is_blocked_ip(ip_str):
                msg = (
                    f"Refusing to connect to MX host {mx_host}: resolved IP "
                    f"{ip_str} is in a private/reserved range (SSRF protection)."
                )
                self._add_verification_step(
                    "error", f"SSRF check (Port {port})", msg
                )
                raise NoConnectionException(
                    msg,
                    status_code="mx_host_blocked",
                    verification_steps=self.verification_steps,
                )

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
        # SSRF guard: ensure the MX host resolves only to public IPs before any
        # outbound connection is attempted. Raises NoConnectionException if blocked.
        await self._assert_mx_host_is_public(mx_host, port)

        server_ip_for_log = await self._resolve_host_ip_for_log(
            mx_host
        )  # Get server IP address for logging
        self._add_verification_step(
            "info",
            f"SMTP Connect (Port {port})",
            f"Attempting connect to {mx_host} (IP: {server_ip_for_log or 'N/A'})",
        )

        smtp_client = None
        current_smtp_code = None  # Last received SMTP code
        try:
            async with self.max_concurrent_domains_semaphore:  # Limit concurrent connections
                smtp_client = aiosmtplib.SMTP(  # Create SMTP client
                    hostname=mx_host, port=port, timeout=self.smtp_timeout
                )
                await smtp_client.connect(
                    timeout=self.smtp_timeout
                )  # Connect to server
            self._add_verification_step(
                "success",
                f"SMTP Connect (Port {port})",
                f"Connected to {mx_host}:{port}",
            )

            try:
                code, msg_bytes = await smtp_client.ehlo()  # Attempt EHLO
            except aiosmtplib.SMTPException:
                (
                    code,
                    msg_bytes,
                ) = await smtp_client.helo()  # If EHLO fails, try HELO

            current_smtp_code = code
            msg_str = (
                msg_bytes
                if isinstance(msg_bytes, str)
                else msg_bytes.decode(errors="ignore")
            )  # Decode message
            self._add_verification_step(
                "info", "EHLO/HELO", f"Resp: {code} {msg_str}", code
            )
            # Code 220 (ready) is also successful for EHLO/HELO
            if code not in SMTP_CODES_SUCCESS and code != 220:
                raise UnexpectedResponseException(  # If EHLO/HELO fails
                    f"EHLO/HELO failed: {code} {msg_str}",
                    status_code="ehlo_failed",
                    verification_steps=self.verification_steps,
                )

            sender = self._get_sender_email(domain)  # Get appropriate sender
            self._add_verification_step("info", "MAIL FROM", f"Sender: {sender}")
            code, msg_bytes = await smtp_client.mail(sender)  # Send MAIL FROM
            current_smtp_code = code
            msg_str = (
                msg_bytes
                if isinstance(msg_bytes, str)
                else msg_bytes.decode(errors="ignore")
            )
            self._add_verification_step(
                "info", "MAIL FROM", f"Resp: {code} {msg_str}", code
            )

            # If reputation error is detected
            if self._is_reputation_error(code, msg_str):
                self._add_verification_step(
                    "warning",
                    "MAIL FROM",
                    f"Reputation-based rejection detected. Will retry with different sender if available.",
                )
                # Try to find alternative sender
                alternative_sender = None
                for test_domain, test_sender in self.sender_emails_by_domain.items():
                    if test_domain != domain and test_sender != sender:
                        alternative_sender = test_sender
                        break

                if alternative_sender:  # If alternative sender is found
                    self._add_verification_step(
                        "info",
                        "MAIL FROM",
                        f"Retrying with alternative sender: {alternative_sender}",
                    )
                    code, msg_bytes = await smtp_client.mail(
                        alternative_sender
                    )  # Retry MAIL FROM
                    current_smtp_code = code
                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )
                    self._add_verification_step(
                        "info", "MAIL FROM", f"Resp: {code} {msg_str}", code
                    )

            if code not in SMTP_CODES_SUCCESS:  # If MAIL FROM fails
                if code in SMTP_CODES_TEMP_FAIL:  # Temporary error
                    raise RateLimitException(
                        f"MAIL FROM temp error: {code} {msg_str}",
                        status_code="mail_from_temp_fail",
                        verification_steps=self.verification_steps,
                    )
                raise UnexpectedResponseException(  # Permanent error
                    f"MAIL FROM perm error: {code} {msg_str}",
                    status_code="mail_from_perm_fail",
                    verification_steps=self.verification_steps,
                )

            self._add_verification_step("info", "RCPT TO", f"Recipient: {email}")
            code, msg_bytes = await smtp_client.rcpt(email)  # Send RCPT TO
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
                await smtp_client.rset()  # Reset SMTP transaction
            except (aiosmtplib.SMTPException, OSError):
                pass  # Ignore errors during RSET

            if code in SMTP_CODES_SUCCESS:  # If RCPT TO succeeds, email is valid
                return True, "valid", msg_str, code
            if code in SMTP_CODES_TEMP_FAIL:  # Temporary error on RCPT TO
                raise RateLimitException(
                    f"RCPT TO temp error: {code} {msg_str}",
                    status_code="rcpt_to_temp_fail",
                    verification_steps=self.verification_steps,
                )
            # Otherwise mailbox is invalid (permanent error)
            return False, "invalid_mailbox", msg_str, code

        except (
            asyncio.TimeoutError,
            aiosmtplib.SMTPTimeoutError,
        ) as e:  # Timeout error
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
        except (  # Connection errors
            aiosmtplib.SMTPConnectError,
            ConnectionRefusedError,
            socket.gaierror,  # Address translation error
            OSError,  # General OS error (e.g., network unavailable)
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
        ):  # Propagate specific exceptions
            raise
        except aiosmtplib.SMTPException as e:  # General SMTP error
            self._add_verification_step(
                "error",
                f"SMTP Error (Port {port})",
                f"General SMTP error with {mx_host}: {e.code} {e.message}",
            )
            return False, "unknown_smtp_error", f"{e.code} {e.message}", e.code
        finally:
            if smtp_client and smtp_client.is_connected:  # If client is connected
                try:
                    await smtp_client.quit()  # Close SMTP connection
                except (aiosmtplib.SMTPException, OSError):
                    pass  # Ignore errors during QUIT

        # If code reaches here, unexpected flow occurred
        return (
            False,
            "unknown_flow_error",
            "Unexpected flow in SMTP check",
            current_smtp_code,
        )

    def _is_microsoft_domain(self, domain: str, mx_host: str) -> bool:
        """
        Checks whether the domain or MX host is related to Microsoft servers.
        """
        if domain in MICROSOFT_DOMAINS:  # Direct domain match
            return True
        # Check if MX host matches Microsoft patterns
        return any(
            mx_host.endswith(pattern.replace("*", ""))
            for pattern in MICROSOFT_MX_PATTERNS
        )

    async def _is_catch_all_domain(
        self, domain: str, mx_hosts_priority: List[Tuple[int, str]]
    ) -> bool:
        """
        Tests whether the domain is "catch-all" (accepts emails to non-existent addresses).
        :param domain: Domain to test.
        :param mx_hosts_priority: List of MX hosts and their priorities.
        :return: True if the domain is likely catch-all, otherwise False.
        """
        if not self.catchall_test_enabled:  # Skip if catch-all test is disabled
            self._add_verification_step("info", "Catch-all Test", "Skipped (config).")
            return False
        if (
            domain in KNOWN_FREEMAIL_DOMAINS
        ):  # Freemail domains are not tested as catch-all
            self._add_verification_step(
                "info", "Catch-all Test", f"Skipped ('{domain}' is known freemail)."
            )
            return False
        if domain in self.is_catchall_domain_cache:  # Check cache
            cached = self.is_catchall_domain_cache[domain]
            self._add_verification_step(
                "info",
                "Catch-all Test (Cache)",
                f"Result for '{domain}' from cache: {cached}",
            )
            return cached if cached is not None else False  # Return cached result

        self._add_verification_step(
            "info", "Catch-all Test", f"Starting test for '{domain}'."
        )
        ts = int(time.time())  # Current timestamp
        # Generate unique test email addresses
        test_emails = [
            f"catchall-probe-{ts}-{random.getrandbits(16)}-{i}@{domain}"
            for i in range(2)  # Use 2 test emails for greater reliability
        ]
        successful_tests = (
            0  # Number of successful tests (when server accepted non-existent email)
        )
        inconclusive_tests = (
            0  # Number of inconclusive tests (e.g., on Microsoft servers)
        )
        mx_hosts = [host for _, host in mx_hosts_priority]  # List of MX hosts

        for test_email in test_emails:
            accepted = False  # Whether test email was accepted
            for mx_host in mx_hosts:
                if (
                    accepted
                ):  # If email was already accepted by another MX, no need to continue
                    break
                smtp_client = None  # Explicit initialization
                try:
                    # SSRF guard: ensure the MX host resolves only to public IPs
                    # before any outbound connection. Mirrors _perform_smtp_check.
                    # Raises NoConnectionException if blocked.
                    await self._assert_mx_host_is_public(mx_host, 25)

                    smtp_client = aiosmtplib.SMTP(  # Create SMTP client
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
                        continue  # Skip to next MX if EHLO/HELO fails

                    sender = self._get_sender_email(domain)  # Get sender
                    code, msg_bytes = await smtp_client.mail(sender)
                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )
                    if code not in SMTP_CODES_SUCCESS:
                        continue  # Skip to next MX if MAIL FROM fails

                    code, msg_bytes = await smtp_client.rcpt(
                        test_email
                    )  # Send RCPT TO with test email
                    msg_str = (
                        msg_bytes
                        if isinstance(msg_bytes, str)
                        else msg_bytes.decode(errors="ignore")
                    )

                    # Special handling for Microsoft domains
                    if self._is_microsoft_domain(domain, mx_host):
                        # "Access denied" response from Microsoft is often ambiguous
                        if code == 550 and "Access denied" in msg_str:
                            self._add_verification_step(
                                "warning",
                                "Catch-all Test (Microsoft)",
                                f"Microsoft domain detected - Access denied response treated as inconclusive.",
                            )
                            inconclusive_tests += 1
                            accepted = True  # Consider accepted for purposes of ending test on this MX
                            break  # End test for this email on this MX

                    if (
                        code in SMTP_CODES_SUCCESS
                    ):  # If server accepted test email
                        self._add_verification_step(
                            "warning",
                            "Catch-all Test (Attempt)",
                            f"Test email '{test_email}' accepted on {mx_host}:25.",
                        )
                        successful_tests += 1
                        accepted = True
                        break  # End test for this email on this MX
                except Exception as e:  # Ignore errors during catch-all testing to avoid affecting main verification
                    self.logger.debug(f"Unexpected error in catch-all sub-test: {e}")
                finally:
                    if smtp_client and smtp_client.is_connected:
                        try:
                            await smtp_client.quit()
                        except (aiosmtplib.SMTPException, OSError):
                            pass
            if not accepted:  # If email was not accepted by any MX server
                self._add_verification_step(
                    "info",
                    "Catch-all Test (Attempt)",
                    f"Test email '{test_email}' not accepted.",
                )

        # Evaluate catch-all test results
        is_catchall = False
        if successful_tests > 0:  # If at least one test email was accepted
            is_catchall = True
        elif (
            inconclusive_tests > 0
        ):  # If tests were inconclusive (typically Microsoft)
            # For Microsoft domains with inconclusive results, mark as likely catch-all
            is_catchall = True
            self._add_verification_step(
                "warning",
                "Catch-all Test (Result)",
                f"Domain '{domain}' is likely catch-all (Microsoft domain with inconclusive results).",
            )
        else:  # If no test email was accepted
            self._add_verification_step(
                "info",
                "Catch-all Test (Result)",
                f"Domain '{domain}' is not catch-all. Successful: {successful_tests}/{len(test_emails)}.",
            )

        self.is_catchall_domain_cache[domain] = is_catchall  # Store result in cache
        return is_catchall

    def _is_temporary_error(self, code: int, message: str) -> bool:
        """
        Checks whether SMTP error (code and message) indicates a temporary problem
        that could be resolved by retrying.
        """
        if code in TEMPORARY_ERROR_CODES:  # Check by SMTP code
            return True
        message_lower = message.lower()  # Convert message to lowercase
        # Search for keywords indicating temporary error
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
        Verifies the validity of a single email address.
        :param email: Email address to verify.
        :param attempt: Current attempt number (for retries on errors).
        :return: Dictionary with verification results.
        """
        self._reset_steps_for_single_email()  # Reset steps for this email
        self._add_verification_step(
            "info", "Verification start", f"Email: {email}, Attempt: {attempt}"
        )
        # Default result structure
        res = {
            "email": email,
            "is_valid": False,  # Whether email is valid
            "status_code": "unknown_error",  # Result status code (e.g., "valid", "invalid_mailbox")
            "message": "Unknown error",  # Descriptive result message
            "is_catchall": False,  # Whether domain is catch-all
            "mx_record": None,  # MX record used
            "smtp_code_internal": None,  # Internal SMTP code from server response
            "verification_steps": self.verification_steps,  # List of verification steps
        }
        try:
            # Email syntax check using external library
            val_res = validate_email(
                email, check_deliverability=False
            )  # check_deliverability=False because we do it ourselves
            domain = val_res.domain.lower()  # Get domain from email
            self._add_verification_step(
                "success", "Syntax check", f"Email '{email}' syntax valid."
            )
        except EmailNotValidError as e:  # Syntax error
            self._add_verification_step(
                "error", "Syntax check", f"Invalid email format '{email}': {e}"
            )
            res.update(
                {"is_valid": False, "status_code": "syntax_error", "message": str(e)}
            )
            return res  # End verification

        # Disposable domain check
        if self._is_disposable_domain(domain):
            res.update(
                {
                    "is_valid": False,
                    "status_code": "disposable_domain",
                    "message": "Domain is disposable.",
                }
            )
            return res  # End verification

        mx_records: List[Tuple[int, str]] = []
        try:
            mx_records = await self._resolve_mx_records(domain)  # Get MX records
            if mx_records:
                res["mx_record"] = mx_records[0][
                    1
                ]  # Store first (highest priority) MX record
        except DNSError as e:  # Error getting MX records
            res.update(
                {
                    "is_valid": False,
                    "status_code": e.status_code or "dns_error_mx",
                    "message": str(e),
                }
            )
            return res
        except Exception as e:  # Unexpected error during DNS query
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

        # Catch-all domain test
        is_catchall = await self._is_catch_all_domain(domain, mx_records)
        res["is_catchall"] = is_catchall

        # Iterate over MX records (sorted by priority) and attempt SMTP verification
        for _, mx_host in mx_records:
            res["mx_record"] = mx_host  # Update MX record to currently tested one
            try:
                # Perform SMTP check
                smtp_valid, status, msg, code = await self._perform_smtp_check(
                    email, domain, mx_host, self.default_connect_port
                )
                if smtp_valid:  # If email is valid according to SMTP
                    res.update(
                        {
                            "is_valid": True,
                            "status_code": status,
                            "message": msg,
                            "smtp_code_internal": code,
                        }
                    )
                    return res  # End verification, email is valid
                # If mailbox is invalid or permanent error occurred
                if status == "invalid_mailbox" or "fail" in status or "error" in status:
                    res.update(
                        {
                            "is_valid": False,
                            "status_code": status,
                            "message": msg,
                            "smtp_code_internal": code,
                        }
                    )
                    return res  # End verification, email is invalid
            except RateLimitException as e:  # Catch RateLimitException (temporary error)
                self.logger.warning(
                    f"Rate limit for {email} on {mx_host}:{self.default_connect_port} - {e.message}"
                )
                if attempt < self.retry_attempts:  # If retry is possible
                    delay = self.retry_delay_base * (
                        2**attempt
                    )  # Exponential delay
                    self._add_verification_step(
                        "warning",
                        "Rate Limit Retry",
                        f"Attempt {attempt}/{self.retry_attempts}. Waiting {delay:.1f}s for {email}.",
                    )
                    await asyncio.sleep(delay)  # Wait before retry
                    return await self.verify_single_email(
                        email, attempt + 1
                    )  # Recursive call for retry
                # If retry attempts are exhausted
                res.update(
                    {
                        "is_valid": None,  # Status is unknown (neither valid nor invalid)
                        "status_code": e.status_code or "rate_limited",
                        "message": e.message,
                    }
                )
                return res  # End verification
            except (
                TimeoutException,
                NoConnectionException,
            ) as e:  # Catch Timeout or NoConnection (may be temporary)
                self.logger.warning(f"Temp error for {email} on {mx_host}: {e.message}")
                # Check if error is actually temporary
                if self._is_temporary_error(
                    e.code if hasattr(e, "code") else 0, e.message
                ):
                    if attempt < self.retry_attempts:  # If retry is possible
                        delay = self.retry_delay_base * (2**attempt)
                        self._add_verification_step(
                            "warning",
                            "Temporary Error Retry",
                            f"Attempt {attempt}/{self.retry_attempts}. Waiting {delay:.1f}s for {email}.",
                        )
                        await asyncio.sleep(delay)
                        return await self.verify_single_email(email, attempt + 1)
                # If error is not temporary or attempts exhausted, continue to next MX
                continue
            except EmailVerifierException as e:  # Catch other custom exceptions
                self.logger.error(
                    f"Verifier error for {email} on {mx_host}: {e.message}"
                )
                # Check if error is temporary (e.g., UnexpectedResponse, which may be temporary)
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
                # If error is not temporary or attempts exhausted, continue to next MX
                continue
            except Exception as e:  # Catch unexpected errors during SMTP communication
                self.logger.error(
                    f"Unexpected SMTP error for {email} on {mx_host}: {e}",
                    exc_info=True,  # Write traceback to log
                )
                continue  # Continue to next MX server

        # If verification failed on all MX servers (all failed or returned temporary error)
        self._add_verification_step(
            "error", "SMTP Verification", "Failed to verify on any MX."
        )
        res.update(
            {
                "is_valid": None,  # Status is unknown
                "status_code": "unreachable_all_mx"  # Status code if MX records existed
                if mx_records
                else (
                    res["status_code"] or "dns_error_mx"
                ),  # Otherwise use previous status (e.g., from DNS error)
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
        Verifies a list of email addresses concurrently.
        :param email_list: List of email addresses to verify.
        :return: List of dictionaries with verification results for each email.
        """
        # Create tasks for concurrent verification of each email
        tasks = [self.verify_single_email(email) for email in email_list]
        # Run tasks concurrently and wait for completion
        # return_exceptions=True ensures exceptions are returned as results, does not stop gather
        results_or_exceptions = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for i, item in enumerate(results_or_exceptions):
            email = email_list[i]  # Original email for this result
            if isinstance(item, Exception):  # If task ended with exception
                self.logger.error(
                    f"Unexpected exception during batch for '{email}': {item}",
                    exc_info=True,  # Write traceback to log
                )
                # Get verification steps from exception if possible
                steps = (
                    item.verification_steps
                    if isinstance(item, EmailVerifierException)
                    and item.verification_steps
                    else []
                )
                # Create error result
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
            else:  # If task returned normal result (dictionary)
                final_results.append(item)
        return final_results
