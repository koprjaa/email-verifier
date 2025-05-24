# src/verifier/email_verifier.py

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
from email_validator import EmailNotValidError, validate_email
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


class EmailVerifier:
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
        self.max_concurrent_domains_semaphore = asyncio.Semaphore(
            max_concurrent_domains
        )
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
        # Create DNS resolver for email_validator
        self.dns_resolver = Resolver()
        if _dns_servers_to_use:
            self.dns_resolver.nameservers = _dns_servers_to_use
        
        # Create async DNS resolver for other operations
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
        self.mx_cache_lock = asyncio.Lock()

        self.logger.info(
            f"EmailVerifier init. HELO: {self.helo_hostname}, Catch-all: {self.catchall_test_enabled}, Disposable check: {self.check_disposable_enabled}"
        )

    def _setup_default_logger(self) -> logging.Logger:
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
        if DEFAULT_CONFIG_PATH.exists():
            try:
                with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error parsing/loading {DEFAULT_CONFIG_PATH}: {e}")
        return {}

    def _ensure_data_dirs_exist(self):
        try:
            self.disposable_domains_file_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.logger.error(
                f"Error creating data directory {self.disposable_domains_file_path.parent}: {e}"
            )

    def _load_disposable_domains(self) -> Set[str]:
        if not self.check_disposable_enabled:
            return set()
        if self.disposable_domains_file_path.exists():
            try:
                with open(
                    self.disposable_domains_file_path, "r", encoding="utf-8"
                ) as f:
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
        self.is_catchall_domain_cache = {}
        self.mx_records_cache = {}

    def _reset_steps_for_single_email(self):
        self.verification_steps = []

    def _add_verification_step(
        self, status: str, action: str, details: str = "", code: Optional[Any] = None
    ):
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
        self._add_verification_step("info", "DNS MX query", f"Getting MX for {domain}")
        
        # Check cache first
        async with self.mx_cache_lock:
            if domain in self.mx_records_cache:
                cached_records = self.mx_records_cache[domain]
                self._add_verification_step(
                    "info", "DNS MX query", f"Using cached MX records for {domain}"
                )
                return cached_records

        try:
            # Create a new DNS resolver instance for each query
            resolver = aiodns.DNSResolver(
                timeout=self.dns_timeout,
                tries=self.internal_config.get("dns_resolver_tries", 2),
            )
            if hasattr(self.async_dns_resolver, 'nameservers'):
                resolver.nameservers = self.async_dns_resolver.nameservers
            mx_records = await resolver.query(domain, "MX")
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
            
            # Cache the results
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
        try:
            # Create a new DNS resolver instance for each query
            resolver = aiodns.DNSResolver(
                timeout=self.dns_timeout,
                tries=self.internal_config.get("dns_resolver_tries", 2),
            )
            if hasattr(self.async_dns_resolver, 'nameservers'):
                resolver.nameservers = self.async_dns_resolver.nameservers
            records_a = await resolver.query(hostname, "A")
            if records_a:
                return str(records_a[0].host)
        except aiodns.error.DNSError:
            pass
        try:
            # Create a new DNS resolver instance for each query
            resolver = aiodns.DNSResolver(
                timeout=self.dns_timeout,
                tries=self.internal_config.get("dns_resolver_tries", 2),
            )
            if hasattr(self.async_dns_resolver, 'nameservers'):
                resolver.nameservers = self.async_dns_resolver.nameservers
            records_aaaa = await resolver.query(hostname, "AAAA")
            if records_aaaa:
                return str(records_aaaa[0].host)
        except aiodns.error.DNSError:
            pass
        return None

    def _is_disposable_domain(self, domain: str) -> bool:
        if not self.check_disposable_enabled:
            return False
        normalized_domain = domain.lower()
        if normalized_domain in self.disposable_domains:
            self._add_verification_step(
                "warning", "Domain check", f"Domain '{domain}' is disposable."
            )
            return True
        parts = normalized_domain.split(".")
        if len(parts) > 2 and ".".join(parts[-2:]) in self.disposable_domains:
            self._add_verification_step(
                "warning", "Domain check", f"Parent domain of '{domain}' is disposable."
            )
            return True
        return False

    def _get_sender_email(self, recipient_domain: str) -> str:
        if self.sender_email_override:
            return self.sender_email_override
        if recipient_domain in self.sender_emails_by_domain:
            return self.sender_emails_by_domain[recipient_domain]
        return self.default_sender_email

    async def _perform_smtp_check(
        self, email: str, domain: str, mx_host: str, port: int
    ) -> Tuple[bool, str, str, Optional[int]]:
        server_ip_for_log = await self._resolve_host_ip_for_log(mx_host)
        self._add_verification_step(
            "info",
            f"SMTP Connect (Port {port})",
            f"Attempting connect to {mx_host} (IP: {server_ip_for_log or 'N/A'})",
        )

        smtp_client = None
        current_smtp_code = None
        try:
            async with self.max_concurrent_domains_semaphore:
                smtp_client = aiosmtplib.SMTP(
                    hostname=mx_host, port=port, timeout=self.smtp_timeout
                )
                await smtp_client.connect(timeout=self.smtp_timeout)
            self._add_verification_step(
                "success",
                f"SMTP Connect (Port {port})",
                f"Connected to {mx_host}:{port}",
            )

            # Send EHLO/HELO command
            try:
                code, msg_bytes = await smtp_client.ehlo()
            except aiosmtplib.SMTPException:
                code, msg_bytes = await smtp_client.helo()
            
            current_smtp_code = code
            msg_str = msg_bytes if isinstance(msg_bytes, str) else msg_bytes.decode(errors="ignore")
            self._add_verification_step(
                "info", "EHLO/HELO", f"Resp: {code} {msg_str}", code
            )
            if code not in SMTP_CODES_SUCCESS and code != 220:
                raise UnexpectedResponseException(
                    f"EHLO/HELO failed: {code} {msg_str}",
                    status_code="ehlo_failed",
                    verification_steps=self.verification_steps,
                )

            sender = self._get_sender_email(domain)
            self._add_verification_step("info", "MAIL FROM", f"Sender: {sender}")
            code, msg_bytes = await smtp_client.mail(sender)
            current_smtp_code = code
            msg_str = msg_bytes if isinstance(msg_bytes, str) else msg_bytes.decode(errors="ignore")
            self._add_verification_step(
                "info", "MAIL FROM", f"Resp: {code} {msg_str}", code
            )
            if code not in SMTP_CODES_SUCCESS:
                if code in SMTP_CODES_TEMP_FAIL:
                    raise RateLimitException(
                        f"MAIL FROM temp error: {code} {msg_str}",
                        status_code="mail_from_temp_fail",
                        verification_steps=self.verification_steps,
                    )
                raise UnexpectedResponseException(
                    f"MAIL FROM perm error: {code} {msg_str}",
                    status_code="mail_from_perm_fail",
                    verification_steps=self.verification_steps,
                )

            self._add_verification_step("info", "RCPT TO", f"Recipient: {email}")
            code, msg_bytes = await smtp_client.rcpt(email)
            current_smtp_code = code
            msg_str = msg_bytes if isinstance(msg_bytes, str) else msg_bytes.decode(errors="ignore")
            self._add_verification_step(
                "info", "RCPT TO", f"Resp: {code} {msg_str}", code
            )

            try:
                await smtp_client.rset()
            except (aiosmtplib.SMTPException, OSError):
                pass

            if code in SMTP_CODES_SUCCESS:
                return True, "valid", msg_str, code
            if code in SMTP_CODES_TEMP_FAIL:
                raise RateLimitException(
                    f"RCPT TO temp error: {code} {msg_str}",
                    status_code="rcpt_to_temp_fail",
                    verification_steps=self.verification_steps,
                )
            return False, "invalid_mailbox", msg_str, code

        except (asyncio.TimeoutError, aiosmtplib.SMTPTimeoutError) as e:
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
        except (
            aiosmtplib.SMTPConnectError,
            ConnectionRefusedError,
            socket.gaierror,
            OSError,
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
        except (RateLimitException, UnexpectedResponseException):
            raise
        except aiosmtplib.SMTPException as e:
            self._add_verification_step(
                "error",
                f"SMTP Error (Port {port})",
                f"General SMTP error with {mx_host}: {e.code} {e.message}",
            )
            return False, "unknown_smtp_error", f"{e.code} {e.message}", e.code
        finally:
            if smtp_client and smtp_client.is_connected:
                try:
                    await smtp_client.quit()
                except (aiosmtplib.SMTPException, OSError):
                    pass

        return (
            False,
            "unknown_flow_error",
            "Unexpected flow in SMTP check",
            current_smtp_code,
        )

    async def _is_catch_all_domain(
        self, domain: str, mx_hosts_priority: List[Tuple[int, str]]
    ) -> bool:
        if not self.catchall_test_enabled:
            self._add_verification_step("info", "Catch-all Test", "Skipped (config).")
            return False
        if domain in KNOWN_FREEMAIL_DOMAINS:
            self._add_verification_step(
                "info", "Catch-all Test", f"Skipped ('{domain}' is known freemail)."
            )
            return False
        if domain in self.is_catchall_domain_cache:
            cached = self.is_catchall_domain_cache[domain]
            self._add_verification_step(
                "info",
                "Catch-all Test (Cache)",
                f"Result for '{domain}' from cache: {cached}",
            )
            return cached if cached is not None else False

        self._add_verification_step(
            "info", "Catch-all Test", f"Starting test for '{domain}'."
        )
        ts = int(time.time())
        test_emails = [
            f"catchall-probe-{ts}-{random.getrandbits(16)}-{i}@{domain}"
            for i in range(2)
        ]
        successful_tests = 0
        mx_hosts = [host for _, host in mx_hosts_priority]

        for test_email in test_emails:
            accepted = False
            for mx_host in mx_hosts:
                if accepted:
                    break
                for port in CATCHALL_TEST_PORTS:
                    try:
                        smtp_client = aiosmtplib.SMTP(
                            hostname=mx_host, port=port, timeout=self.smtp_timeout
                        )
                        await smtp_client.connect(timeout=self.smtp_timeout)
                        
                        try:
                            code, msg_bytes = await smtp_client.ehlo()
                        except aiosmtplib.SMTPException:
                            code, msg_bytes = await smtp_client.helo()
                        
                        msg_str = msg_bytes if isinstance(msg_bytes, str) else msg_bytes.decode(errors="ignore")
                        if code not in SMTP_CODES_SUCCESS and code != 220:
                            continue

                        sender = self._get_sender_email(domain)
                        code, msg_bytes = await smtp_client.mail(sender)
                        msg_str = msg_bytes if isinstance(msg_bytes, str) else msg_bytes.decode(errors="ignore")
                        if code not in SMTP_CODES_SUCCESS:
                            continue

                        code, msg_bytes = await smtp_client.rcpt(test_email)
                        msg_str = msg_bytes if isinstance(msg_bytes, str) else msg_bytes.decode(errors="ignore")
                        
                        if code in SMTP_CODES_SUCCESS:
                            self._add_verification_step(
                                "warning",
                                "Catch-all Test (Attempt)",
                                f"Test email '{test_email}' accepted on {mx_host}:{port}.",
                            )
                            successful_tests += 1
                            accepted = True
                            break
                    except Exception as e:
                        self.logger.debug(
                            f"Unexpected error in catch-all sub-test: {e}"
                        )
                    finally:
                        if smtp_client and smtp_client.is_connected:
                            try:
                                await smtp_client.quit()
                            except (aiosmtplib.SMTPException, OSError):
                                pass
            if not accepted:
                self._add_verification_step(
                    "info",
                    "Catch-all Test (Attempt)",
                    f"Test email '{test_email}' not accepted.",
                )

        is_catchall = successful_tests > 0
        self._add_verification_step(
            "warning" if is_catchall else "info",
            "Catch-all Test (Result)",
            f"Domain '{domain}' {'is' if is_catchall else 'is not'} likely catch-all. Successful: {successful_tests}/{len(test_emails)}.",
        )
        self.is_catchall_domain_cache[domain] = is_catchall
        return is_catchall

    async def verify_single_email(self, email: str, attempt: int = 1) -> Dict[str, Any]:
        self._reset_steps_for_single_email()
        self._add_verification_step(
            "info", "Verification start", f"Email: {email}, Attempt: {attempt}"
        )
        res = {
            "email": email,
            "is_valid": False,
            "status_code": "unknown_error",
            "message": "Unknown error",
            "is_catchall": False,
            "mx_record": None,
            "smtp_code_internal": None,
            "verification_steps": self.verification_steps,
        }
        try:
            val_res = validate_email(email, check_deliverability=False)
            domain = val_res.domain.lower()
            self._add_verification_step(
                "success", "Syntax check", f"Email '{email}' syntax valid."
            )
        except EmailNotValidError as e:
            self._add_verification_step(
                "error", "Syntax check", f"Invalid email format '{email}': {e}"
            )
            res.update(
                {"is_valid": False, "status_code": "syntax_error", "message": str(e)}
            )
            return res

        if self._is_disposable_domain(domain):
            res.update(
                {
                    "is_valid": False,
                    "status_code": "disposable_domain",
                    "message": "Domain is disposable.",
                }
            )
            return res

        mx_records: List[Tuple[int, str]] = []
        try:
            mx_records = await self._resolve_mx_records(domain)
            if mx_records:
                res["mx_record"] = mx_records[0][1]
        except DNSError as e:
            res.update(
                {
                    "is_valid": False,
                    "status_code": e.status_code or "dns_error_mx",
                    "message": str(e),
                }
            )
            return res
        except Exception as e:
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

        is_catchall = await self._is_catch_all_domain(domain, mx_records)
        res["is_catchall"] = is_catchall

        for _, mx_host in mx_records:
            res["mx_record"] = mx_host
            try:
                smtp_valid, status, msg, code = await self._perform_smtp_check(
                    email, domain, mx_host, self.default_connect_port
                )
                if smtp_valid:
                    res.update(
                        {
                            "is_valid": True,
                            "status_code": status,
                            "message": msg,
                            "smtp_code_internal": code,
                        }
                    )
                    return res
                if status == "invalid_mailbox" or "fail" in status or "error" in status:
                    res.update(
                        {
                            "is_valid": False,
                            "status_code": status,
                            "message": msg,
                            "smtp_code_internal": code,
                        }
                    )
                    return res
            except RateLimitException as e:
                self.logger.warning(
                    f"Rate limit for {email} on {mx_host}:{self.default_connect_port} - {e.message}"
                )
                if attempt < self.retry_attempts:
                    delay = self.retry_delay_base * (2**attempt)
                    self._add_verification_step(
                        "warning",
                        "Rate Limit Retry",
                        f"Attempt {attempt}/{self.retry_attempts}. Waiting {delay:.1f}s for {email}.",
                    )
                    await asyncio.sleep(delay)
                    return await self.verify_single_email(email, attempt + 1)
                res.update(
                    {
                        "is_valid": None,
                        "status_code": e.status_code or "rate_limited",
                        "message": e.message,
                    }
                )
                return res
            except (TimeoutException, NoConnectionException) as e:
                self.logger.warning(f"Temp error for {email} on {mx_host}: {e.message}")
                continue
            except EmailVerifierException as e:
                self.logger.error(
                    f"Verifier error for {email} on {mx_host}: {e.message}"
                )
                continue
            except Exception as e:
                self.logger.error(
                    f"Unexpected SMTP error for {email} on {mx_host}: {e}",
                    exc_info=True,
                )
                continue

        self._add_verification_step(
            "error", "SMTP Verification", "Failed to verify on any MX."
        )
        res.update(
            {
                "is_valid": None,
                "status_code": "unreachable_all_mx"
                if mx_records
                else (res["status_code"] or "dns_error_mx"),
                "message": "Cannot connect to any MX or all returned temp error."
                if mx_records
                else (res["message"] or "MX records error"),
            }
        )
        return res

    async def verify_emails_in_batch(
        self, email_list: List[str]
    ) -> List[Dict[str, Any]]:
        tasks = [self.verify_single_email(email) for email in email_list]
        results_or_exceptions = await asyncio.gather(*tasks, return_exceptions=True)
        final_results = []
        for i, item in enumerate(results_or_exceptions):
            email = email_list[i]
            if isinstance(item, Exception):
                self.logger.error(
                    f"Unexpected exception during batch for '{email}': {item}",
                    exc_info=True,
                )
                steps = (
                    item.verification_steps
                    if isinstance(item, EmailVerifierException)
                    and item.verification_steps
                    else []
                )
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
            else:
                final_results.append(item)
        return final_results
