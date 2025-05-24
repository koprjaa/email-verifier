import asyncio
import logging
import random
import socket
import re
import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiodns
import aiosmtplib
from email_validator import EmailNotValidError, validate_email

# --- Výjimky (mohou být v samostatném souboru) ---
class EmailVerifierException(Exception): pass
class TimeoutException(EmailVerifierException): pass
class NoConnectionException(EmailVerifierException): pass
class UnexpectedResponseException(EmailVerifierException): pass
class RateLimitException(EmailVerifierException): pass
class DNSError(EmailVerifierException): pass


# --- Konfigurace a konstanty ---
DEFAULT_CONFIG_PATH = Path(__file__).parent / "default_verifier_config.json"

# SMTP kódy pro různé situace
SMTP_CODES_SUCCESS = (250, 251, 252) # RFC 5321: 250 (Okay), 251 (User not local), 252 (Cannot VRFY)
SMTP_CODES_TEMP_FAIL = (421, 450, 451, 452) # Service not available, Mailbox unavailable (busy), Local error, Insufficient storage
SMTP_CODES_PERM_FAIL = (500, 501, 502, 503, 504, 550, 551, 552, 553, 554) # Syntax error, param error, cmd not impl, bad sequence, param not impl, Mailbox unavailable, User not local, Storage exceeded, Mailbox name not allowed, Transaction failed

# Domény, u kterých je catch-all test často zbytečný nebo problematický
KNOWN_FREEMAIL_DOMAINS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoodns.net', 'aol.com', 'hotmail.com',
    'outlook.com', 'live.com', 'msn.com', 'seznam.cz', 'email.cz', 'post.cz',
    'centrum.cz', 'gmx.com', 'gmx.net', 'mail.com', 'mail.ru', 'yandex.ru',
    'protonmail.com', 'icloud.com', 'me.com', 'mac.com'
}
# Seznam portů pro testování catch-all
CATCHALL_TEST_PORTS = [25, 587, 465]


class EmailVerifier:
    def __init__(
        self,
        timeout: int = 15,
        smtp_timeout: int = 10,
        dns_timeout: int = 5,
        catchall_test_enabled: bool = True,
        connect_port: int = 25, # Výchozí port pro SMTP, ale catch-all test zkouší i jiné
        rate_limit_delay_base: float = 2.0,
        batch_size: int = 50, # Interní velikost dávky pro `verify_emails_in_batch`, kolik emailů se řeší "paralelně"
        max_concurrent_domains: int = 5, # Kolik různých domén se může ověřovat současně
        helo_hostname: Optional[str] = None,
        retry_attempts: int = 2, # Kolikrát zkusit znovu, pokud dojde k dočasné chybě (např. rate limit)
        retry_delay_base: float = 5.0,
        progress_file_path: str = "data/verification_progress.json", # Ukládá stav mezi běhy
        adaptive_params_file_path: str = "data/adaptive_params.json", # Pro ukládání naučených parametrů
        disposable_domains_file: str = "data/disposable_domains.txt",
        skip_signal_handlers: bool = False, # Pro použití v rámci jiné aplikace (Flask)
        logger: Optional[logging.Logger] = None,
        dns_servers: Optional[List[str]] = None,
        sender_email_override: Optional[str] = None, # Možnost přepsat odesílatele
    ):
        self.logger = logger or self._setup_default_logger()
        self.config = self._load_config_from_file() # Načte default_verifier_config.json

        self.timeout = timeout
        self.smtp_timeout = smtp_timeout
        self.dns_timeout = dns_timeout
        self.catchall_test_enabled = catchall_test_enabled
        self.default_connect_port = connect_port # Port použitý, pokud není specifikován jinak
        self.rate_limit_delay_base = rate_limit_delay_base
        self.internal_batch_size = batch_size
        self.max_concurrent_domains_semaphore = asyncio.Semaphore(max_concurrent_domains)
        self.helo_hostname = helo_hostname or self.config.get("helo_hostname", socket.getfqdn())
        self.retry_attempts = retry_attempts
        self.retry_delay_base = retry_delay_base
        self.sender_email_override = sender_email_override

        self.progress_file = Path(progress_file_path)
        self.adaptive_params_file = Path(adaptive_params_file_path)
        self.disposable_domains_file_path = Path(disposable_domains_file)
        self._ensure_data_dirs_exist()

        self.disposable_domains: Set[str] = self._load_disposable_domains()
        self.dns_resolver = aiodns.DNSResolver(timeout=self.dns_timeout, tries=2, servers=dns_servers or self.config.get("dns_servers"))

        # Interní stav pro jeden běh (resetuje se)
        self.verification_steps: List[Dict[str, Any]] = [] # Log kroků pro jednotlivý email
        self.is_catchall_domain_cache: Dict[str, Optional[bool]] = {} # Cache pro výsledky catch-all testů v rámci jednoho běhu
        self.current_results_batch: Dict[str, Dict[str, Any]] = {} # Výsledky pro aktuální dávku v `verify_emails_in_batch`

        self.logger.info(f"EmailVerifier inicializován. HELO: {self.helo_hostname}, Catch-all test: {'Povoleno' if self.catchall_test_enabled else 'Zakázáno'}.")

    def _setup_default_logger(self) -> logging.Logger:
        logger = logging.getLogger("EmailVerifierDefault")
        if not logger.handlers: # Přidat handler pouze pokud ještě žádný není
            logger.setLevel(logging.INFO)
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        return logger

    def _load_config_from_file(self) -> Dict[str, Any]:
        if DEFAULT_CONFIG_PATH.exists():
            try:
                with open(DEFAULT_CONFIG_PATH, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                self.logger.error(f"Chyba při parsování konfiguračního souboru: {DEFAULT_CONFIG_PATH}")
        return {} # Výchozí prázdná konfigurace

    def _ensure_data_dirs_exist(self):
        self.progress_file.parent.mkdir(parents=True, exist_ok=True)
        self.adaptive_params_file.parent.mkdir(parents=True, exist_ok=True)
        self.disposable_domains_file_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_disposable_domains(self) -> Set[str]:
        if self.disposable_domains_file_path.exists():
            try:
                with open(self.disposable_domains_file_path, "r") as f:
                    return {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
            except Exception as e:
                self.logger.error(f"Chyba při načítání disposable domén z '{self.disposable_domains_file_path}': {e}")
        else:
            self.logger.warning(f"Soubor s disposable doménami '{self.disposable_domains_file_path}' nenalezen.")
        return set()

    def reset_internal_state(self, single_email_mode: bool = False):
        """Resetuje stav pro nový běh verifikace nebo pro jednotlivý email."""
        self.verification_steps = []
        if not single_email_mode: # Pro hromadný běh resetovat i cache
            self.is_catchall_domain_cache = {}
            self.current_results_batch = {}
        # self.logger.debug("Interní stav EmailVerifier resetován.")


    def _add_verification_step(self, status: str, action: str, details: str = "", code: Optional[Any] = None):
        step = {
            "timestamp": datetime.now().isoformat(),
            "status": status,  # 'success', 'error', 'warning', 'info'
            "action": action,
            "details": details,
            "code": str(code) if code is not None else None,
        }
        self.verification_steps.append(step)
        self.logger.debug(f"Krok verifikace: {action} - {details} (Status: {status}, Kód: {code})")


    @lru_cache(maxsize=1024) # Cache pro MX záznamy (globální pro instanci)
    async def _resolve_mx_records(self, domain: str) -> List[Tuple[int, str]]:
        self._add_verification_step("info", "DNS MX dotaz", f"Získávání MX záznamů pro {domain}")
        try:
            mx_records = await self.dns_resolver.query(domain, 'MX')
            # Formát [(priority, host), ...]
            sorted_mxs = sorted([(int(r.priority), str(r.host).rstrip('.')) for r in mx_records])
            if not sorted_mxs:
                self._add_verification_step("error", "DNS MX dotaz", f"Nenalezeny žádné MX záznamy pro {domain}.")
                raise DNSError(f"Nenalezeny MX záznamy pro {domain}")
            self._add_verification_step("success", "DNS MX dotaz", f"Nalezeny MX záznamy: {sorted_mxs}")
            return sorted_mxs
        except aiodns.error.DNSError as e:
            self._add_verification_step("error", "DNS MX dotaz", f"Chyba DNS (MX) pro {domain}: {e.args[0]} ({e.args[1]})")
            raise DNSError(f"Chyba DNS (MX) pro {domain}: {e.args[0]}") from e

    @lru_cache(maxsize=1024) # Cache pro A/AAAA záznamy (globální pro instanci)
    async def _resolve_host_ip(self, hostname: str) -> Optional[str]:
        self._add_verification_step("info", "DNS A/AAAA dotaz", f"Získávání IP adresy pro {hostname}")
        try:
            # Zkusit A záznam (IPv4)
            records_a = await self.dns_resolver.query(hostname, 'A')
            if records_a:
                ip = str(records_a[0].host)
                self._add_verification_step("success", "DNS A dotaz", f"Nalezena IPv4 pro {hostname}: {ip}")
                return ip
        except aiodns.error.DNSError:
            self._add_verification_step("warning", "DNS A dotaz", f"Nenalezena IPv4 pro {hostname}, zkouším IPv6.")
        
        try:
            # Zkusit AAAA záznam (IPv6)
            records_aaaa = await self.dns_resolver.query(hostname, 'AAAA')
            if records_aaaa:
                ip = str(records_aaaa[0].host) # aiosmtplib by měl zvládat IPv6 adresy v hostname
                self._add_verification_step("success", "DNS AAAA dotaz", f"Nalezena IPv6 pro {hostname}: {ip}")
                return ip
        except aiodns.error.DNSError as e:
            self._add_verification_step("error", "DNS AAAA dotaz", f"Chyba DNS (AAAA) pro {hostname}: {e.args[0]}")
            # Nepovažovat za fatální chybu, pokud A selhalo a AAAA také, _perform_smtp_check to zachytí
        
        self._add_verification_step("error", "DNS A/AAAA dotaz", f"Nepodařilo se přeložit IP adresu pro {hostname}")
        return None # Nepodařilo se přeložit


    def _is_disposable_domain(self, domain: str) -> bool:
        normalized_domain = domain.lower()
        if normalized_domain in self.disposable_domains:
            self._add_verification_step("warning", "Kontrola domény", f"Doména '{domain}' je na seznamu jednorázových (disposable).")
            return True
        
        # Zkusit i subdomény pro běžné disposable vzory
        parts = normalized_domain.split('.')
        if len(parts) > 2:
            # např. sub.mailinator.com -> kontroluj mailinator.com
            parent_domain = '.'.join(parts[-2:])
            if parent_domain in self.disposable_domains:
                self._add_verification_step("warning", "Kontrola domény", f"Nadřazená doména '{parent_domain}' pro '{domain}' je disposable.")
                return True
        return False

    def _get_sender_email(self, recipient_domain: str) -> str:
        """Vrátí odesílací email. Buď přepsaný, nebo z konfigurace, nebo default."""
        if self.sender_email_override:
            return self.sender_email_override
        
        domain_senders = self.config.get("sender_emails_by_domain", {})
        if recipient_domain in domain_senders:
            return domain_senders[recipient_domain]
        
        return self.config.get("default_sender_email", f"verifier@{self.helo_hostname}")


    async def _perform_smtp_check(
        self, email: str, domain: str, mx_host: str, port: int
    ) -> Tuple[bool, str, str, Optional[int]]:
        """
        Provede SMTP komunikaci.
        Vrací: (is_valid, status_code_str, message, smtp_response_code_int)
        """
        server_ip = await self._resolve_host_ip(mx_host) # Znovu přeložit, mohlo se změnit, nebo pro logování
        self._add_verification_step("info", f"SMTP Připojení (Port {port})", f"Pokus o připojení k {mx_host} (IP: {server_ip or 'N/A'})")

        smtp_client = None
        try:
            smtp_client = aiosmtplib.SMTP(
                hostname=mx_host, # Použít hostname pro SNI
                port=port,
                timeout=self.smtp_timeout,
                # source_address=None # Zde by byla rotace IP, pokud je implementována
            )
            await smtp_client.connect()
            self._add_verification_step("success", f"SMTP Připojení (Port {port})", f"Připojeno k {mx_host}:{port}")

            # EHLO/HELO
            code, msg_bytes = await smtp_client.ehlo_or_helo_if_needed(self.helo_hostname)
            msg_str = msg_bytes.decode(errors='ignore')
            self._add_verification_step("info", "EHLO/HELO", f"Odpověď: {code} {msg_str}", code)
            if code not in SMTP_CODES_SUCCESS and code != 220: # 220 je také OK pro EHLO
                raise UnexpectedResponseException(f"EHLO/HELO selhalo: {code} {msg_str}")

            # MAIL FROM
            sender_email = self._get_sender_email(domain)
            self._add_verification_step("info", "MAIL FROM", f"Odesílatel: {sender_email}")
            code, msg_bytes = await smtp_client.mail(sender_email)
            msg_str = msg_bytes.decode(errors='ignore')
            self._add_verification_step("info", "MAIL FROM", f"Odpověď: {code} {msg_str}", code)
            if code not in SMTP_CODES_SUCCESS:
                if code in SMTP_CODES_TEMP_FAIL:
                    raise RateLimitException(f"MAIL FROM dočasná chyba: {code} {msg_str}") # Může být rate limit
                raise UnexpectedResponseException(f"MAIL FROM selhalo: {code} {msg_str}")

            # RCPT TO
            self._add_verification_step("info", "RCPT TO", f"Příjemce: {email}")
            code, msg_bytes = await smtp_client.rcpt(email)
            msg_str = msg_bytes.decode(errors='ignore')
            self._add_verification_step("info", "RCPT TO", f"Odpověď: {code} {msg_str}", code)

            # RSET pro čisté ukončení, pokud je to možné (ignorovat chyby)
            try: await smtp_client.rset()
            except: pass

            if code in SMTP_CODES_SUCCESS:
                return True, "valid", msg_str, code
            elif code in SMTP_CODES_TEMP_FAIL: # Např. 450, 451 (greylisting, mailbox busy)
                # Toto bereme jako dočasnou chybu, která by mohla být úspěšná při retry
                # Pro účely _is_catch_all_domain to ale může znamenat, že schránka (i neexistující) je dočasně odmítnuta
                raise RateLimitException(f"RCPT TO dočasná chyba/greylisting: {code} {msg_str}")
            else: # Permanentní chyba (5xx)
                return False, "invalid_mailbox", msg_str, code

        except (asyncio.TimeoutError, aiosmtplib.SMTPTimeoutError) as e:
            self._add_verification_step("error", f"SMTP Timeout (Port {port})", f"Timeout při operaci s {mx_host}: {e}")
            raise TimeoutException(f"Timeout na {mx_host}:{port}") from e
        except (aiosmtplib.SMTPConnectError, ConnectionRefusedError, socket.gaierror, OSError) as e:
            # socket.gaierror může nastat, pokud se IP nepodařilo přeložit
            self._add_verification_step("error", f"SMTP Chyba připojení (Port {port})", f"Chyba připojení k {mx_host}: {e}")
            raise NoConnectionException(f"Chyba připojení k {mx_host}:{port}: {e}") from e
        except RateLimitException: # Propuštění výjimky nahoru
            raise
        except UnexpectedResponseException as e:
            self._add_verification_step("error", f"SMTP Neočekávaná odpověď (Port {port})", f"Neočekávaná odpověď od {mx_host}: {e}")
            return False, "smtp_protocol_error", str(e), None # Kód chyby je v e
        except aiosmtplib.SMTPException as e: # Obecná SMTP chyba
            self._add_verification_step("error", f"SMTP Chyba (Port {port})", f"Obecná SMTP chyba u {mx_host}: {e.code} {e.message}")
            return False, "unknown_smtp_error", f"{e.code} {e.message}", e.code
        finally:
            if smtp_client and smtp_client.is_connected:
                try: await smtp_client.quit()
                except: pass
        
        # Pokud se sem kód dostane (neměl by, všechny cesty by měly vrátit nebo vyvolat výjimku)
        return False, "unknown_flow_error", "Neočekávaný průběh v SMTP kontrole", None


    async def _is_catch_all_domain(self, domain: str, mx_hosts_priority: List[Tuple[int, str]]) -> bool:
        if not self.catchall_test_enabled:
            self._add_verification_step("info", "Catch-all Test", "Přeskočeno (zakázáno v konfiguraci).")
            return False
        
        if domain in KNOWN_FREEMAIL_DOMAINS:
            self._add_verification_step("info", "Catch-all Test", f"Přeskočeno (doména '{domain}' je známý freemail).")
            return False # Známé freemaily obvykle nejsou catch-all v tom smyslu, že by akceptovaly cokoliv

        if domain in self.is_catchall_domain_cache:
            cached_result = self.is_catchall_domain_cache[domain]
            self._add_verification_step("info", "Catch-all Test (Cache)", f"Výsledek pro '{domain}' z cache: {cached_result}")
            return cached_result if cached_result is not None else False # Pokud bylo None (nelze určit), zkusit znovu? Nebo vrátit False?

        self._add_verification_step("info", "Catch-all Test", f"Zahájení testu pro doménu '{domain}'.")

        # Vytvořit několik nepravděpodobných emailů
        # Použití timestampu a náhodných znaků pro unikátnost
        ts = int(time.time())
        test_emails = [
            f"verify-catchall-{ts}-{random.randint(10000,99999)}@{domain}",
            f"random-nonexistent-{random.getrandbits(32)}@{domain}",
            f"test-email-probe-{ts}@{domain}",
        ]

        successful_tests = 0
        attempted_tests = 0
        
        # Projít MX servery podle priority
        mx_hosts = [host for _, host in mx_hosts_priority]

        for test_email in test_emails:
            # Pro každý testovací email zkusit dostupné MX a porty
            test_email_accepted_on_any_mx = False
            for mx_host in mx_hosts:
                if test_email_accepted_on_any_mx: break # Pokud už byl tento testovací email přijat, zkusit další testovací email

                for port in CATCHALL_TEST_PORTS:
                    try:
                        # Použít _perform_smtp_check pro konzistenci
                        # Zde je důležité, že `_perform_smtp_check` vrací True pro úspěšný RCPT TO
                        is_accepted, _, _, smtp_code = await self._perform_smtp_check(test_email, domain, mx_host, port)
                        
                        if is_accepted and smtp_code in SMTP_CODES_SUCCESS:
                            self._add_verification_step("warning", "Catch-all Test (Pokus)", f"Testovací email '{test_email}' byl přijat na {mx_host}:{port}. SMTP: {smtp_code}.")
                            successful_tests += 1
                            test_email_accepted_on_any_mx = True
                            break # Tento testovací email byl přijat, není třeba zkoušet další porty/MX pro něj
                        # Pokud RateLimitException nebo jiná dočasná chyba, _perform_smtp_check ji vyvolá.
                        # Pokud permanentní chyba (nevalidní), tak to není catch-all pro tento email.
                    except (NoConnectionException, TimeoutException):
                        self._add_verification_step("warning", "Catch-all Test (Pokus)", f"Nelze se připojit k {mx_host}:{port} pro test '{test_email}'.")
                        continue # Zkusit další port nebo MX
                    except RateLimitException: # Dočasná chyba, tento MX může být dočasně nedostupný
                        self._add_verification_step("warning", "Catch-all Test (Pokus)", f"Dočasná chyba/rate limit na {mx_host}:{port} pro '{test_email}'.")
                        continue # Zkusit další, ale tento testovací email se nepočítá jako úspěšný ani neúspěšný
                    except Exception as e: # Jiné neočekávané chyby
                        self.logger.debug(f"Chyba při catch-all testu pro '{test_email}' na {mx_host}:{port}: {e}")
                        continue
                # Konec smyčky portů
            # Konec smyčky MX serverů
            if test_email_accepted_on_any_mx:
                attempted_tests +=1 # Počítáme pouze testy, kde byl email explicitně přijat
        # Konec smyčky testovacích emailů

        if attempted_tests == 0: # Pokud žádný testovací email nebyl úspěšně doručen (všechny selhaly nebo timeout)
            self._add_verification_step("warning", "Catch-all Test", f"Nelze spolehlivě určit catch-all pro '{domain}', žádný testovací email nebyl přijat.")
            self.is_catchall_domain_cache[domain] = None # Indikace, že nelze určit
            return False # Bezpečnější je předpokládat, že není catch-all, pokud nemůžeme potvrdit opak

        # Pokud alespoň polovina explicitně přijatých testovacích emailů prošla
        is_catchall = successful_tests >= (len(test_emails) / 2.0) # Upravte threshold dle potřeby (např. > 0)

        if is_catchall:
            self._add_verification_step("warning", "Catch-all Test (Výsledek)", f"Doména '{domain}' je pravděpodobně catch-all. Úspěšných testů: {successful_tests}/{len(test_emails)}.")
        else:
            self._add_verification_step("info", "Catch-all Test (Výsledek)", f"Doména '{domain}' se nezdá být catch-all. Úspěšných testů: {successful_tests}/{len(test_emails)}.")

        self.is_catchall_domain_cache[domain] = is_catchall
        return is_catchall


    async def verify_single_email(self, email: str, attempt: int = 1) -> Dict[str, Any]:
        """Hlavní metoda pro verifikaci jednoho emailu."""
        self.reset_internal_state(single_email_mode=True) # Vyčistit kroky z předchozího volání této metody
        self._add_verification_step("info", "Zahájení verifikace", f"Email: {email}, Pokus: {attempt}")

        # 1. Syntaktická validace a disposable check
        try:
            validation_result = validate_email(email, check_deliverability=False, dns_resolver=self.dns_resolver)
            domain = validation_result.domain.lower()
            local_part = validation_result.local_part
            self._add_verification_step("success", "Syntax check", f"Email '{email}' má validní syntax.")
        except EmailNotValidError as e:
            self._add_verification_step("error", "Syntax check", f"Nevalidní formát emailu '{email}': {e}")
            return {
                "email": email, "is_valid": False, "status_code": "syntax_error", "message": str(e),
                "is_catchall": False, "mx_record": None, "server_ip": None,
                "verification_steps": self.verification_steps, "smtp_code_internal": None
            }

        if self._is_disposable_domain(domain):
            return {
                "email": email, "is_valid": False, "status_code": "disposable_domain", "message": "Doména je na seznamu jednorázových.",
                "is_catchall": False, "mx_record": None, "server_ip": None,
                "verification_steps": self.verification_steps, "smtp_code_internal": None
            }

        # 2. DNS MX Záznamy
        mx_records_priority: List[Tuple[int, str]] = []
        try:
            mx_records_priority = await self._resolve_mx_records(domain)
        except DNSError as e:
            return {
                "email": email, "is_valid": False, "status_code": "dns_error_mx", "message": str(e),
                "is_catchall": False, "mx_record": None, "server_ip": None,
                "verification_steps": self.verification_steps, "smtp_code_internal": None
            }

        # 3. Catch-all test (pokud je povolen a doména není známý freemail)
        # Výsledek catch-all testu se ukládá do `self.is_catchall_domain_cache`
        is_domain_catch_all = await self._is_catch_all_domain(domain, mx_records_priority)
        # Pokud _is_catch_all_domain vrátila None (nelze určit), zacházíme s tím jako s "není catch-all" pro účely rozhodování,
        # ale frontend může chtít zobrazit informaci o nejistotě.

        # 4. SMTP Ověření
        last_mx_tried: Optional[str] = None
        last_ip_tried: Optional[str] = None
        
        for _, mx_host in mx_records_priority: # Procházet MX podle priority
            last_mx_tried = mx_host
            last_ip_tried = await self._resolve_host_ip(mx_host) # Pro logování a výsledek

            try:
                # Pro SMTP check použijeme výchozí port nebo porty z CATCHALL_TEST_PORTS, pokud to dává smysl
                # Zde použijeme `self.default_connect_port` pro hlavní SMTP ověření.
                # Catch-all test si řeší porty interně.
                smtp_valid, status_str, smtp_msg, smtp_code_int = await self._perform_smtp_check(
                    email, domain, mx_host, self.default_connect_port
                )

                if smtp_valid:
                    return {
                        "email": email, "is_valid": True, "status_code": status_str, "message": smtp_msg,
                        "is_catchall": is_domain_catch_all, "mx_record": mx_host, "server_ip": last_ip_tried,
                        "verification_steps": self.verification_steps, "smtp_code_internal": smtp_code_int
                    }
                
                # Pokud je to permanentní chyba (např. invalid_mailbox), není třeba zkoušet další MX
                if status_str == "invalid_mailbox" or status_str in ["smtp_protocol_error", "unknown_smtp_error"]:
                    return {
                        "email": email, "is_valid": False, "status_code": status_str, "message": smtp_msg,
                        "is_catchall": is_domain_catch_all, "mx_record": mx_host, "server_ip": last_ip_tried,
                        "verification_steps": self.verification_steps, "smtp_code_internal": smtp_code_int
                    }
                # Pokud byla jiná chyba (např. flow error), zkusit další MX.
                # RateLimitException (dočasná chyba) je řešena níže.

            except TimeoutException as e:
                self.logger.warning(f"Timeout pro {email} na {mx_host}:{self.default_connect_port} - {e}")
                # Pokračovat na další MX, pokud existuje
            except NoConnectionException as e:
                self.logger.warning(f"Chyba připojení pro {email} na {mx_host}:{self.default_connect_port} - {e}")
                # Pokračovat na další MX
            except RateLimitException as e: # Zachyceno z _perform_smtp_check
                self.logger.warning(f"Rate limit/dočasná chyba pro {email} na {mx_host}:{self.default_connect_port} - {e}")
                if attempt < self.retry_attempts:
                    delay = self.retry_delay_base * (2 ** (attempt - 1)) # Exponenciální backoff
                    self._add_verification_step("warning", "Rate Limit Retry", f"Pokus {attempt}/{self.retry_attempts}. Čekání {delay:.1f}s před dalším pokusem pro {email}.")
                    await asyncio.sleep(delay)
                    return await self.verify_single_email(email, attempt + 1) # Rekurzivní volání pro retry
                else:
                    # Max retries dosaženo, vrátit jako dočasnou chybu
                    return {
                        "email": email, "is_valid": None, "status_code": "rate_limited", "message": str(e),
                        "is_catchall": is_domain_catch_all, "mx_record": mx_host, "server_ip": last_ip_tried,
                        "verification_steps": self.verification_steps, "smtp_code_internal": None # SMTP kód může být v `e`
                    }
            except Exception as e: # Obecná neočekávaná chyba pro tento MX
                self.logger.error(f"Neočekávaná chyba při SMTP ověřování {email} na {mx_host}: {e}", exc_info=True)
                # Pokračovat na další MX
        
        # Pokud žádný MX server nedal definitivní odpověď (valid/invalid) nebo všechny selhaly
        self._add_verification_step("error", "SMTP Ověření", "Nepodařilo se ověřit email na žádném MX serveru.")
        return {
            "email": email, "is_valid": None, # None znamená, že nevíme (ne nutně nevalidní)
            "status_code": "unreachable_all_mx" if mx_records_priority else "dns_error_mx",
            "message": "Nelze se spojit s žádným MX serverem" if mx_records_priority else "Chyba MX záznamů",
            "is_catchall": is_domain_catch_all,
            "mx_record": last_mx_tried, "server_ip": last_ip_tried, # Poslední zkoušený
            "verification_steps": self.verification_steps, "smtp_code_internal": None
        }

    async def verify_emails_in_batch(self, email_list: List[str]) -> List[Dict[str, Any]]:
        """
        Ověří dávku emailů asynchronně. Používá self.internal_batch_size pro řízení paralelizace.
        """
        # Resetovat cache pro catch-all na začátku celého hromadného běhu (mělo by se dít v app.py)
        # self.reset_internal_state(single_email_mode=False)
        # Zde předpokládáme, že reset byl proveden před voláním této metody pro první dávku velkého jobu.
        # Tato metoda se volá pro menší "aplikační" dávky.

        tasks = []
        # Omezení počtu souběžných úloh na různé domény
        # Pro emaily na stejné doméně se semafor pro doménu postará o serializaci
        # Tento vnější semafor (self.max_concurrent_domains_semaphore) zde není přímo použit,
        # protože `asyncio.gather` spouští vše "najednou" a semafory se uplatní uvnitř `_perform_smtp_check`.
        # Pokud by bylo potřeba omezit počet *současně běžících* `verify_single_email` tasků,
        # musela by se použít smyčka s `asyncio.Semaphore` a `asyncio.create_task`.
        
        # Pro jednoduchost zde spouštíme všechny tasky v dávce a spoléháme na semafory uvnitř.
        for email in email_list:
            # Každý email v dávce dostane vlastní sadu `verification_steps` díky resetu v `verify_single_email`
            tasks.append(self.verify_single_email(email))
            
        results_with_exceptions = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for i, res_or_exc in enumerate(results_with_exceptions):
            email = email_list[i]
            if isinstance(res_or_exc, Exception):
                self.logger.error(f"Neočekávaná výjimka při dávkovém ověřování '{email}': {res_or_exc}", exc_info=True)
                # Zde by mohly být kroky `verification_steps` z neúspěšného pokusu, pokud je `EmailVerifierException`
                steps_from_exc = []
                if hasattr(res_or_exc, 'verification_steps') and isinstance(res_or_exc.verification_steps, list):
                    steps_from_exc = res_or_exc.verification_steps
                elif self.verification_steps: # Pokud se výjimka stala po nějakých krocích
                    steps_from_exc = list(self.verification_steps) # Kopie

                final_results.append({
                    "email": email, "is_valid": None, "status_code": "internal_verifier_error",
                    "message": f"Interní chyba verifikátoru: {type(res_or_exc).__name__}",
                    "is_catchall": False, "mx_record": None, "server_ip": None,
                    "verification_steps": steps_from_exc, "smtp_code_internal": None
                })
            else:
                final_results.append(res_or_exc)
            
            # Ukládání výsledků pro aktuální dávku (pokud by se to používalo)
            # self.current_results_batch[email] = final_results[-1]
            # `app.py` bude sbírat výsledky z `final_results`

        return final_results

# --- Příklad použití (pro testování třídy samostatně) ---
async def main_test():
    # logger = logging.getLogger("EmailVerifierTest")
    # logger.setLevel(logging.DEBUG) # Detailní logování pro test
    # handler = logging.StreamHandler()
    # handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'))
    # logger.addHandler(handler)

    verifier = EmailVerifier(catchall_test_enabled=True, logger=None, smtp_timeout=7, dns_timeout=3)
    
    test_emails = [
        "valid.email.exists@gmail.com", # Nahraďte skutečným existujícím emailem
        "nonexistent.email.xyz123@gmail.com",
        "test@nonexistent-domain-xyz123abc.com",
        "test@example-catchall-domain.com", # Doména, která je catch-all (pokud máte)
        "another.test@outlook.com", # Nahraďte existujícím
        "disposable.email@mailinator.com",
        "invalid-syntax",
        "blocked.ip.test@volny.cz" # Pro test blokace, pokud máte IP s reputací
    ]

    # Test jednotlivých emailů
    for email_to_test in test_emails:
        print(f"\n--- Ověřování: {email_to_test} ---")
        result = await verifier.verify_single_email(email_to_test)
        print(f"Výsledek pro {email_to_test}:")
        print(f"  Validní: {result.get('is_valid')}")
        print(f"  Status: {result.get('status_code')}")
        print(f"  Zpráva: {result.get('message')}")
        print(f"  Catch-all: {result.get('is_catchall')}")
        print(f"  MX: {result.get('mx_record')} (IP: {result.get('server_ip')})")
        print(f"  SMTP kód: {result.get('smtp_code_internal')}")
        print(f"  Kroky verifikace:")
        for step in result.get('verification_steps', []):
            print(f"    [{step['timestamp']}] [{step['status'].upper()}] {step['action']}: {step['details']} { '(Kód: ' + str(step['code']) + ')' if step['code'] else ''}")
        print("-" * 30)
        await asyncio.sleep(1) # Malá pauza mezi jednotlivými testy

    # Test dávkového ověření
    print("\n--- Test Dávkového Ověření ---")
    batch_test_emails = [
        "user1@gmail.com", # Existující
        "fakeuser123asdf@gmail.com", # Neexistující
        "info@seznam.cz", # Existující
        "noexist@seznam.cz", # Neexistující
        "test@thisdomainshouldnotexist12345.org", # Neexistující doména
    ]
    # Před dávkovým během je dobré resetovat stav (pokud chceme čistou cache pro catch-all atd.)
    # verifier.reset_internal_state(single_email_mode=False)
    
    results_batch = await verifier.verify_emails_in_batch(batch_test_emails)
    for res_b in results_batch:
        print(f"Dávka - {res_b['email']}: Valid: {res_b.get('is_valid')}, Status: {res_b.get('status_code')}, Catchall: {res_b.get('is_catchall')}, Msg: {res_b.get('message')}")


if __name__ == '__main__':
    # Pro spuštění testu:
    # Musí být spuštěno v prostředí, kde běží event loop,
    # nebo `asyncio.run(main_test())`
    # Např. python -m asyncio email_verifier.py (pokud je __main__ na konci)
    # nebo upravit konec souboru pro přímé spuštění.
    try:
        asyncio.run(main_test())
    except KeyboardInterrupt:
        print("\nTest přerušen.")