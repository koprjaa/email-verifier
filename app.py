import asyncio  # Pro asynchronní operace
import csv  # Pro práci s CSV soubory
import json  # Pro práci s JSON daty
import logging  # Pro logování
import os  # Pro interakci s operačním systémem (cesty, proměnné prostředí)
import threading  # Pro práci s vlákny (hromadná verifikace na pozadí)
import time  # Pro práci s časem (měření doby, časová razítka)
from datetime import datetime  # Pro práci s datem a časem
from pathlib import Path  # Pro objektově orientovanou práci s cestami k souborům
from typing import Dict, Any, List  # Pro typové hinty

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
)  # Základní komponenty Flasku
from flask_cors import CORS  # Pro povolení Cross-Origin Resource Sharing (CORS)
from werkzeug.utils import secure_filename  # Pro bezpečné názvy souborů
import pandas as pd  # Knihovna pro práci s daty (zde nepoužitá, ale importovaná)

from verifier.email_verifier import EmailVerifier  # Vlastní třída pro verifikaci emailů
from verifier.exceptions import (
    VerificationError,
)  # Vlastní výjimka pro chyby verifikace

app = Flask(__name__)  # Inicializace Flask aplikace
CORS(app)  # Povolení CORS pro všechny route
app.config["MAX_CONTENT_LENGTH"] = (
    10 * 1024 * 1024
)  # Maximální velikost nahrávaného souboru (10 MB)
app.config["UPLOAD_FOLDER"] = "uploads"  # Složka pro nahrávané soubory
app.config["RESULTS_FOLDER"] = "results"  # Složka pro výsledky verifikace
os.makedirs(
    app.config["UPLOAD_FOLDER"], exist_ok=True
)  # Vytvoření složky uploads, pokud neexistuje
os.makedirs(
    app.config["RESULTS_FOLDER"], exist_ok=True
)  # Vytvoření složky results, pokud neexistuje

# Nastavení loggeru pro aplikaci
app_logger = logging.getLogger("flask.app")
app_logger.setLevel(logging.DEBUG)  # Nastavení úrovně logování na DEBUG
flask_handler = logging.StreamHandler()  # Handler pro výstup logů do konzole
flask_handler.setLevel(logging.DEBUG)
flask_formatter = logging.Formatter(  # Formát logovacích zpráv
    "%(asctime)s - %(threadName)s - %(levelname)s - %(message)s"
)
flask_handler.setFormatter(flask_formatter)
if not app_logger.handlers:  # Přidání handleru, pokud ještě žádný není
    app_logger.addHandler(flask_handler)

# Načtení hlavní konfigurace aplikace ze souboru config.json
try:
    with open("config.json", "r", encoding="utf-8") as f:
        app_level_config = json.load(f)
    app_logger.info("Main config.json loaded successfully.")
except FileNotFoundError:
    app_logger.warning(
        "Main config.json not found in root. Using default parameters for EmailVerifier setup."
    )
    app_level_config = {}  # Použití prázdné konfigurace, pokud soubor neexistuje
except json.JSONDecodeError as e:
    app_logger.error(f"Error parsing main config.json: {e}. Using default parameters.")
    app_level_config = {}  # Použití prázdné konfigurace při chybě parsování

# Odstranění 'batch_size' z konfigurace, pokud existuje (spravováno jinak)
if "batch_size" in app_level_config:
    del app_level_config["batch_size"]

# Inicializace instance EmailVerifier s konfigurací z config.json nebo výchozími hodnotami
email_verifier_instance = EmailVerifier(
    timeout=app_level_config.get("timeout", 15),
    smtp_timeout=app_level_config.get("smtp_timeout", 10),
    dns_timeout=app_level_config.get("dns_timeout", 5),
    catchall_test_enabled=app_level_config.get(  # Povolení testu catch-all, zpětně kompatibilní s 'check_catchall'
        "catchall_test", app_level_config.get("check_catchall", True)
    ),
    check_disposable_enabled=app_level_config.get("check_disposable", True),
    connect_port=app_level_config.get("connect_port", 25),
    rate_limit_delay_base=app_level_config.get(
        "rate_limit_delay", 2.0
    ),  # Nyní se používá pro retry_delay_base
    max_concurrent_domains=app_level_config.get("max_concurrent_domains", 5),
    helo_hostname=app_level_config.get("helo_hostname", None),
    retry_attempts=app_level_config.get("retry_attempts", 2),
    retry_delay_base=app_level_config.get("retry_delay", 5.0),
    disposable_domains_file=app_level_config.get(
        "disposable_domains_file_path", "data/disposable_domains.txt"
    ),
    logger=app_logger,  # Předání loggeru aplikace do verifikátoru
    dns_servers=app_level_config.get("dns_servers", None),
    sender_email_override=app_level_config.get("sender_email_override", None),
    default_sender_email_config=app_level_config.get(
        "sender_emails", {}
    ).get(  # Výchozí email odesílatele
        "default"
    ),
    sender_emails_by_domain_config={  # Emaily odesílatele specifické pro domény
        k: v
        for k, v in app_level_config.get("sender_emails", {}).items()
        if k != "default"  # Vyloučení 'default' klíče
    },
)
app_logger.info("Global EmailVerifier instance created and configured.")

# Globální stav verifikace a zámek pro synchronizaci
current_verification_state: Dict[str, Any] = {}
verification_lock = threading.RLock()  # Použití RLock pro lepší prevenci deadlocků
bulk_verification_thread = None  # Vlákno pro hromadnou verifikaci


def reset_verification_state():
    """
    Resetuje globální stav verifikace na výchozí hodnoty.

    Tato funkce inicializuje všechny proměnné stavu na jejich výchozí hodnoty.
    Používá se při startu aplikace a při resetování stavu mezi verifikacemi.

    Stav obsahuje následující hodnoty:
        - status: "idle" - výchozí stav
        - error_message: None - žádná chyba
        - uploaded_filepath: None - žádný nahraný soubor
        - selected_column: None - žádný vybraný sloupec
        - emails_to_verify: [] - prázdný seznam emailů
        - total_emails: 0 - žádné emaily k verifikaci
        - processed_emails: 0 - žádné zpracované emaily
        - valid_emails: 0 - žádné validní emaily
        - invalid_emails: 0 - žádné nevalidní emaily
        - probable_emails: 0 - žádné pravděpodobně validní emaily
        - unknown_emails: 0 - žádné emaily s neznámým stavem
        - current_batch_num: 0 - žádná aktuální dávka
        - total_batches: 0 - žádné dávky
        - results: {} - prázdný slovník výsledků
        - verification_log: [] - prázdný log
        - start_time: None - žádný čas začátku
        - last_activity_time: None - žádná poslední aktivita
        - result_filepath: None - žádný soubor s výsledky
        - accept_all_domains_summary: {} - prázdný souhrn catch-all domén
        - stop_requested: False - žádný požadavek na zastavení
        - verification_run_id: None - žádné ID běhu
        - is_thread_active: False - žádné aktivní vlákno
        - detected_encoding: None - žádné detekované kódování
        - detected_delimiter: None - žádný detekovaný oddělovač
        - app_batch_size_for_ui: 20 - výchozí velikost dávky pro UI
    """
    global current_verification_state
    with verification_lock:  # Zámek pro bezpečný přístup ke globálnímu stavu
        current_verification_state = {
            "status": "idle",  # Aktuální stav (idle, loading_csv, verifying, atd.)
            "error_message": None,  # Chybová zpráva, pokud nastala chyba
            "uploaded_filepath": None,  # Cesta k nahranému CSV souboru
            "selected_column": None,  # Název sloupce s emaily
            "emails_to_verify": [],  # Seznam emailů k verifikaci
            "total_emails": 0,  # Celkový počet emailů
            "processed_emails": 0,  # Počet zpracovaných emailů
            "valid_emails": 0,  # Počet validních emailů
            "invalid_emails": 0,  # Počet nevalidních emailů
            "probable_emails": 0,  # Počet pravděpodobně validních (catch-all)
            "unknown_emails": 0,  # Počet emailů s neznámým stavem
            "current_batch_num": 0,  # Číslo aktuální zpracovávané dávky
            "total_batches": 0,  # Celkový počet dávek
            "results": {},  # Slovník s výsledky verifikace {email: výsledek}
            "verification_log": [],  # Seznam logovacích zpráv pro UI
            "start_time": None,  # Čas zahájení verifikace
            "last_activity_time": None,  # Čas poslední aktivity
            "result_filepath": None,  # Cesta k souboru s výsledky
            "accept_all_domains_summary": {},  # Souhrn catch-all domén
            "stop_requested": False,  # Příznak požadavku na zastavení
            "verification_run_id": None,  # Unikátní ID běhu verifikace
            "is_thread_active": False,  # Příznak, zda běží vlákno verifikace
            "detected_encoding": None,  # Detekované kódování CSV
            "detected_delimiter": None,  # Detekovaný oddělovač CSV
            "app_batch_size_for_ui": app_level_config.get(
                "ui_batch_size", 20
            ),  # Velikost dávky pro UI (z konfigurace)
        }
        app_logger.info("Global verification state has been reset to 'idle'.")


reset_verification_state()  # Reset stavu při startu aplikace


@app.route("/")
def index():
    """
    Hlavní route aplikace.

    Zobrazuje hlavní stránku aplikace s rozhraním pro:
    - Verifikaci jednotlivých emailových adres
    - Nahrávání CSV souborů pro hromadnou verifikaci
    - Zobrazení průběhu a výsledků verifikace

    Returns:
        str: HTML šablonu hlavní stránky (index.html)
    """
    return render_template("index.html")  # Vrátí renderovanou HTML šablonu


@app.route("/verify_single", methods=["POST"])
def verify_single_email_route():
    """
    Route pro verifikaci jednotlivé emailové adresy.

    Očekává JSON s klíčem 'email' obsahujícím adresu k ověření.
    Provede následující kroky:
    1. Kontrola syntaxe emailové adresy
    2. Kontrola disposable domény
    3. Resolvování MX záznamů
    4. Test catch-all domény
    5. SMTP verifikace

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: výsledek verifikace obsahující:
                - is_valid: True/False/None (validní/nevalidní/neznámý)
                - status_code: kód výsledku verifikace
                - message: popis výsledku
                - is_catchall: True/False (catch-all doména)
                - mx_record: primární MX záznam
                - smtp_code_internal: SMTP kód odpovědi
                - verification_steps: seznam kroků verifikace
            - Při chybě: chybovou zprávu a status 400/500
    """
    data = request.json  # Získání JSON dat z požadavku
    email_to_verify = data.get("email")
    if not email_to_verify:
        app_logger.warning("API /verify_single: Missing 'email' in request payload.")
        return (
            jsonify({"error": "Chybí email v požadavku"}),
            400,
        )  # Chyba 400, pokud email chybí

    app_logger.info(
        f"API /verify_single: Received request to verify email: {email_to_verify}"
    )

    # Vytvoření nové smyčky událostí pro tento požadavek (důležité pro asyncio v Flasku)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        app_logger.info(
            f"API /verify_single: Starting verification process for {email_to_verify}"
        )
        # Spuštění asynchronní verifikace v synchronním kontextu Flasku
        result = loop.run_until_complete(
            email_verifier_instance.verify_single_email(email_to_verify)
        )
        app_logger.info(
            f"API /verify_single: Verification completed for {email_to_verify}. Result: {result.get('status_code')}"
        )
        app_logger.debug(
            f"API /verify_single: Full verification result: {json.dumps(result, indent=2)}"
        )
        return jsonify(result)  # Vrácení výsledku jako JSON
    except Exception as e:
        app_logger.error(
            f"API /verify_single: Error during verification of {email_to_verify}: {e}",
            exc_info=True,  # Logování s tracebackem
        )
        return (
            jsonify({"error": f"Interní chyba serveru: {str(e)}"}),
            500,
        )  # Chyba 500 při interní chybě
    finally:
        loop.close()  # Uzavření smyčky událostí


@app.route("/load_csv", methods=["POST"])
def load_csv_route():
    """
    Route pro nahrání a zpracování CSV souboru s emaily.

    Očekává multipart/form-data s klíčem 'file' obsahujícím CSV soubor.
    Provede následující kroky:
    1. Kontrola existence a typu souboru
    2. Uložení souboru do uploads složky
    3. Detekce kódování souboru (utf-8-sig, utf-8, cp1250, iso-8859-2, windows-1250)
    4. Detekce oddělovače sloupců (,, ;, tab, |)
    5. Načtení hlaviček CSV
    6. Detekce sloupce s emaily

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: "select_column"
                - columns: seznam sloupců z CSV
                - suggested_email_column: doporučený sloupec s emaily
            - Při chybě: chybovou zprávu a status 400/500

    Možné chyby:
        - Chybí soubor v požadavku
        - Neplatný typ souboru (není CSV)
        - Prázdný soubor
        - Nepodařilo se detekovat kódování
        - Nepodařilo se načíst hlavičky
    """
    app_logger.info("=" * 50)  # Oddělovač v logu pro lepší čitelnost
    app_logger.info("API /load_csv: Starting CSV upload process")
    # Detailní logování informací o požadavku pro debugging
    app_logger.info(f"API /load_csv: Request content type: {request.content_type}")
    app_logger.info(f"API /load_csv: Request headers: {dict(request.headers)}")
    app_logger.info(f"API /load_csv: Request method: {request.method}")
    app_logger.info(f"API /load_csv: Request form data: {request.form}")
    app_logger.info(f"API /load_csv: Request files: {request.files}")

    try:
        with verification_lock:
            app_logger.info(
                f"API /load_csv: Current verification state: {current_verification_state['status']}"
            )
            # Kontrola, zda již neprobíhá jiná operace
            if current_verification_state["status"] not in [
                "idle",  # Připraveno
                "error",  # Nastala chyba
                "completed",  # Dokončeno
                "stopped",  # Zastaveno
            ]:
                app_logger.warning(
                    f"API /load_csv: Attempt to load CSV while in state '{current_verification_state['status']}'."
                )
                return jsonify({"error": "Jiná operace již probíhá."}), 400
            reset_verification_state()  # Reset stavu pro nový CSV soubor
            current_verification_state[
                "status"
            ] = "loading_csv"  # Nastavení stavu na načítání CSV
            current_verification_state["last_activity_time"] = time.time()
            app_logger.info(
                "API /load_csv: Reset verification state and set status to 'loading_csv'"
            )

        if "file" not in request.files:  # Kontrola, zda byl soubor přiložen
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning("API /load_csv: No file part in the request.")
            app_logger.warning(
                f"API /load_csv: Available files in request: {list(request.files.keys())}"
            )
            return jsonify({"error": "Soubor nebyl poskytnut"}), 400

        file = request.files["file"]  # Získání souboru z požadavku
        app_logger.info(f"API /load_csv: Received file: {file.filename}")
        app_logger.info(f"API /load_csv: File content type: {file.content_type}")
        app_logger.info(
            f"API /load_csv: File size: {request.content_length if request.content_length else 'unknown'}"
        )

        if file.filename == "":  # Kontrola, zda byl soubor vybrán
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning("API /load_csv: No file selected (empty filename).")
            return jsonify({"error": "Nebyl vybrán žádný soubor"}), 400

        if not file.filename.lower().endswith(".csv"):  # Kontrola přípony souboru
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning(
                f"API /load_csv: Invalid file type '{file.filename}'. Only CSV allowed."
            )
            return jsonify({"error": "Povoleny jsou pouze CSV soubory"}), 400

        filename = secure_filename(file.filename)  # Zabezpečení názvu souboru
        # Vytvoření unikátní cesty pro uložení souboru
        uploaded_filepath = (
            Path(app.config["UPLOAD_FOLDER"])
            / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        )
        app_logger.info(f"API /load_csv: Saving file to: {uploaded_filepath}")

        try:
            app_logger.info("API /load_csv: Starting file save operation...")
            # Čtení a zápis souboru po částech pro velké soubory
            chunk_size = 8192  # 8KB
            total_size = 0
            chunk_count = 0
            start_time = time.time()

            app_logger.info(
                f"API /load_csv: Opening file for writing: {uploaded_filepath}"
            )
            with open(
                uploaded_filepath, "wb"
            ) as f:  # Otevření souboru pro binární zápis
                while True:
                    app_logger.debug(
                        f"API /load_csv: Reading chunk {chunk_count + 1}..."
                    )
                    chunk = file.read(chunk_size)  # Přečtení části souboru
                    if not chunk:  # Konec souboru
                        app_logger.debug("API /load_csv: No more chunks to read")
                        break
                    f.write(chunk)  # Zápis části do nového souboru
                    total_size += len(chunk)
                    chunk_count += 1
                    if chunk_count % 100 == 0:  # Logování průběhu každých 100 částí
                        elapsed = time.time() - start_time
                        speed = (
                            total_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
                        )
                        app_logger.info(
                            f"API /load_csv: Progress - {total_size/1024:.1f}KB written, {speed:.1f}MB/s"
                        )

            elapsed = time.time() - start_time
            speed = total_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
            app_logger.info(
                f"API /load_csv: File '{filename}' saved to '{uploaded_filepath}' ({total_size/1024:.1f}KB total, {chunk_count} chunks, {speed:.1f}MB/s average speed)."
            )

            # Ověření, zda byl soubor správně uložen
            if not uploaded_filepath.exists():
                raise Exception(f"File was not saved correctly at {uploaded_filepath}")
            app_logger.info(
                f"API /load_csv: Verified file exists at {uploaded_filepath}"
            )

            # Kontrola velikosti uloženého souboru
            file_size = uploaded_filepath.stat().st_size
            app_logger.info(f"API /load_csv: Saved file size: {file_size} bytes")

            if file_size == 0:  # Pokud je soubor prázdný
                raise Exception("Uploaded file is empty")

            # Detekce kódování a oddělovače
            detected_encoding = None
            headers = []
            encodings_to_try = [  # Seznam kódování k vyzkoušení
                "utf-8-sig",  # UTF-8 s BOM (často z Excelu)
                "utf-8",
                "cp1250",  # Windows-1250 (Střední Evropa)
                "iso-8859-2",  # Latin-2 (Střední Evropa)
                "windows-1250",  # Duplicitní, ale neškodí
            ]
            app_logger.info("API /load_csv: Starting encoding detection...")

            # Pokus o přečtení prvních bajtů pro kontrolu čitelnosti souboru
            try:
                app_logger.info("API /load_csv: Reading first 1024 bytes of file...")
                with open(uploaded_filepath, "rb") as f:
                    first_bytes = f.read(1024)
                    # Logování prvních bajtů může pomoci při diagnostice problémů s kódováním
                    app_logger.info(
                        f"API /load_csv: First 1024 bytes of file: {first_bytes[:100]}..."
                    )  # Jen prvních 100 bajtů
            except Exception as e:
                app_logger.error(
                    f"API /load_csv: Error reading first bytes of file: {str(e)}"
                )
                raise

            # Seznam oddělovačů k vyzkoušení
            delimiters = [",", ";", "\t", "|"]
            detected_delimiter = None

            for enc in encodings_to_try:
                try:
                    app_logger.debug(f"API /load_csv: Trying encoding '{enc}'...")
                    with open(uploaded_filepath, "r", encoding=enc) as f_csv:
                        # Přečtení prvního řádku pro detekci oddělovače
                        first_line = f_csv.readline().strip()
                        app_logger.debug(
                            f"API /load_csv: First line with encoding '{enc}': {first_line}"
                        )

                        # Pokus o detekci oddělovače
                        for delimiter in delimiters:
                            if delimiter in first_line:
                                parts = first_line.split(delimiter)
                                if len(parts) > 1:  # Pokud máme více než jeden sloupec
                                    detected_delimiter = delimiter
                                    app_logger.info(
                                        f"API /load_csv: Detected delimiter '{delimiter}' with encoding '{enc}'"
                                    )
                                    break  # Oddělovač nalezen

                        if detected_delimiter:
                            # Resetování ukazatele souboru a přečtení hlaviček s detekovaným oddělovačem
                            f_csv.seek(0)
                            reader = csv.reader(f_csv, delimiter=detected_delimiter)
                            headers = next(reader)  # Načtení hlaviček
                            detected_encoding = enc  # Uložení úspěšného kódování
                            app_logger.info(
                                f"API /load_csv: Successfully read CSV with encoding '{enc}' and delimiter '{detected_delimiter}'. Headers: {headers}"
                            )
                            break  # Kódování a oddělovač nalezeny, ukončení smyčky
                except (
                    UnicodeDecodeError,
                    StopIteration,
                ) as e:  # Chyby při čtení nebo prázdný soubor
                    app_logger.debug(
                        f"API /load_csv: Failed to read with encoding '{enc}': {str(e)}"
                    )
                    continue  # Pokračování na další kódování
                except Exception as e:  # Neočekávané chyby
                    app_logger.error(
                        f"API /load_csv: Unexpected error while trying encoding '{enc}': {str(e)}"
                    )
                    continue

            if not headers:  # Pokud se nepodařilo načíst hlavičky
                if uploaded_filepath.exists():
                    os.remove(uploaded_filepath)  # Smazání neúspěšně nahraného souboru
                with verification_lock:
                    current_verification_state["status"] = "error"
                app_logger.error(
                    "API /load_csv: Failed to read CSV headers. File might be empty or unsupported encoding/delimiter."
                )
                return (
                    jsonify(
                        {
                            "error": "Nepodařilo se přečíst CSV soubor. Zkontrolujte kódování a oddělovač sloupců."
                        }
                    ),
                    400,
                )

            app_logger.info("API /load_csv: Looking for email column in headers...")
            suggested_column = None
            common_email_headers = [
                "email",
                "e-mail",
                "mail",
                "emailaddress",
            ]  # Běžné názvy sloupců s emaily
            for header_item in headers:
                # Normalizace názvu sloupce pro porovnání (malá písmena, bez mezer a podtržítek)
                normalized_header = (
                    header_item.lower().replace(" ", "").replace("_", "")
                )
                if normalized_header in common_email_headers:
                    suggested_column = header_item  # Nalezen doporučený sloupec
                    app_logger.info(
                        f"API /load_csv: Found suggested email column: {suggested_column}"
                    )
                    break
            if (
                not suggested_column and headers
            ):  # Pokud nebyl nalezen, použije se první sloupec
                suggested_column = headers[0]
                app_logger.info(
                    f"API /load_csv: No email column found, using first column: {suggested_column}"
                )

            app_logger.info("API /load_csv: Updating verification state...")
            with verification_lock:
                current_verification_state["uploaded_filepath"] = str(uploaded_filepath)
                current_verification_state[
                    "status"
                ] = "selecting_column"  # Stav pro výběr sloupce
                current_verification_state["detected_encoding"] = detected_encoding
                current_verification_state["detected_delimiter"] = detected_delimiter
                current_verification_state["last_activity_time"] = time.time()
                app_logger.info(
                    "API /load_csv: Successfully processed CSV file, ready for column selection"
                )

            response_data = {
                "status": "select_column",  # Informace pro frontend
                "columns": headers,  # Seznam sloupců
                "suggested_email_column": suggested_column,  # Doporučený sloupec
            }
            app_logger.info(f"API /load_csv: Sending response: {response_data}")
            app_logger.info("=" * 50)  # Konec logu pro tento požadavek
            return jsonify(response_data)

        except Exception as e:  # Zachycení chyb při zpracování souboru
            app_logger.error(
                f"API /load_csv: Error processing CSV file '{filename}': {str(e)}",
                exc_info=True,
            )
            if (
                "uploaded_filepath" in locals() and uploaded_filepath.exists()
            ):  # Kontrola, zda uploaded_filepath bylo definováno
                os.remove(uploaded_filepath)  # Smazání souboru při chybě
                app_logger.info(
                    f"API /load_csv: Removed failed upload file: {uploaded_filepath}"
                )
            with verification_lock:
                current_verification_state["status"] = "error"
                current_verification_state["error_message"] = str(e)
            app_logger.info("=" * 50)
            return jsonify({"error": f"Chyba při zpracování CSV: {str(e)}"}), 500

    except Exception as e:  # Zachycení neočekávaných chyb v handleru
        app_logger.error(
            f"API /load_csv: Unexpected error in route handler: {str(e)}", exc_info=True
        )
        with verification_lock:
            current_verification_state["status"] = "error"
            current_verification_state["error_message"] = str(e)
        app_logger.info("=" * 50)
        return jsonify({"error": f"Neočekávaná chyba serveru: {str(e)}"}), 500


@app.route("/load_txt", methods=["POST"])
def load_txt_route():
    """
    Route pro nahrání a zpracování TXT souboru s emaily.
    
    TXT soubor může obsahovat emaily v různých formátech:
    - Jeden email na řádek
    - Emaily oddělené čárkami, středníky nebo jinými oddělovači
    - Emaily v různých kódováních
    
    Očekává multipart/form-data s klíčem 'file' obsahujícím TXT soubor.
    Provede následující kroky:
    1. Kontrola existence a typu souboru
    2. Uložení souboru do uploads složky
    3. Detekce kódování souboru (utf-8-sig, utf-8, cp1250, iso-8859-2, windows-1250)
    4. Načtení obsahu souboru
    5. Parsování emailů z obsahu
    
    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: "ready"
                - total_emails: počet nalezených emailů
                - sample_emails: ukázka prvních 5 emailů
            - Při chybě: chybovou zprávu a status 400/500
    """
    app_logger.info("=" * 50)
    app_logger.info("API /load_txt: Starting TXT upload process")
    app_logger.info(f"API /load_txt: Request content type: {request.content_type}")
    app_logger.info(f"API /load_txt: Request files: {request.files}")

    try:
        with verification_lock:
            app_logger.info(f"API /load_txt: Current verification state: {current_verification_state['status']}")
            if current_verification_state["status"] not in ["idle", "error", "completed", "stopped"]:
                app_logger.warning(f"API /load_txt: Attempt to load TXT while in state '{current_verification_state['status']}'.")
                return jsonify({"error": "Jiná operace již probíhá."}), 400
            reset_verification_state()
            current_verification_state["status"] = "loading_txt"
            current_verification_state["last_activity_time"] = time.time()
            app_logger.info("API /load_txt: Reset verification state and set status to 'loading_txt'")

        if "file" not in request.files:
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning("API /load_txt: No file part in the request.")
            return jsonify({"error": "Soubor nebyl poskytnut"}), 400

        file = request.files["file"]
        app_logger.info(f"API /load_txt: Received file: {file.filename}")
        app_logger.info(f"API /load_txt: File content type: {file.content_type}")

        if file.filename == "":
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning("API /load_txt: No file selected.")
            return jsonify({"error": "Nebyl vybrán žádný soubor"}), 400

        # Kontrola přípony souboru
        if not file.filename.lower().endswith('.txt'):
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning(f"API /load_txt: Invalid file type: {file.filename}")
            return jsonify({"error": "Povoleny jsou pouze TXT soubory"}), 400

        # Uložení souboru
        filename = secure_filename(file.filename)
        uploaded_filepath = Path("uploads") / filename
        uploaded_filepath.parent.mkdir(exist_ok=True)
        
        file.save(str(uploaded_filepath))
        app_logger.info(f"API /load_txt: File saved to: {uploaded_filepath}")

        # Kontrola velikosti souboru
        file_size = uploaded_filepath.stat().st_size
        if file_size == 0:
            with verification_lock:
                current_verification_state["status"] = "error"
            os.remove(uploaded_filepath)
            app_logger.warning("API /load_txt: Empty file uploaded.")
            return jsonify({"error": "Soubor je prázdný"}), 400

        app_logger.info(f"API /load_txt: File size: {file_size} bytes")

        # Seznam kódování k vyzkoušení
        encodings_to_try = ["utf-8-sig", "utf-8", "cp1250", "iso-8859-2", "windows-1250"]
        detected_encoding = None
        file_content = None

        for enc in encodings_to_try:
            try:
                app_logger.debug(f"API /load_txt: Trying encoding '{enc}'...")
                with open(uploaded_filepath, "r", encoding=enc) as f:
                    file_content = f.read()
                    detected_encoding = enc
                    app_logger.info(f"API /load_txt: Successfully read TXT with encoding '{enc}'")
                    break
            except UnicodeDecodeError:
                app_logger.debug(f"API /load_txt: Failed to read with encoding '{enc}'")
                continue

        if not file_content:
            with verification_lock:
                current_verification_state["status"] = "error"
            os.remove(uploaded_filepath)
            app_logger.error("API /load_txt: Could not read file with any supported encoding.")
            return jsonify({"error": "Nepodařilo se načíst soubor s podporovaným kódováním"}), 400

        # Parsování emailů z obsahu
        import re
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Rozdělení obsahu na řádky a hledání emailů
        lines = file_content.splitlines()
        emails_found = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:  # Přeskočit prázdné řádky
                continue
                
            # Pokud řádek obsahuje více emailů oddělených čárkami, středníky atd.
            if any(sep in line for sep in [',', ';', '|', '\t']):
                # Rozdělit podle různých oddělovačů
                for sep in [',', ';', '|', '\t']:
                    if sep in line:
                        parts = line.split(sep)
                        for part in parts:
                            part = part.strip()
                            if re.match(email_pattern, part):
                                emails_found.append(part)
                        break
            else:
                # Jeden email na řádek nebo email v textu
                matches = re.findall(email_pattern, line)
                emails_found.extend(matches)

        # Odstranění duplicit a prázdných hodnot
        unique_emails = list(dict.fromkeys([email.strip() for email in emails_found if email.strip()]))
        
        if not unique_emails:
            with verification_lock:
                current_verification_state["status"] = "error"
            os.remove(uploaded_filepath)
            app_logger.warning("API /load_txt: No valid emails found in file.")
            return jsonify({"error": "V souboru nebyly nalezeny žádné platné emailové adresy"}), 400

        app_logger.info(f"API /load_txt: Found {len(unique_emails)} unique emails")

        # Uložení informací o souboru do stavu
        with verification_lock:
            current_verification_state["uploaded_filepath"] = str(uploaded_filepath)
            current_verification_state["detected_encoding"] = detected_encoding
            current_verification_state["file_type"] = "txt"
            current_verification_state["emails_list"] = unique_emails
            current_verification_state["status"] = "ready"
            current_verification_state["last_activity_time"] = time.time()

        # Příprava odpovědi
        sample_emails = unique_emails[:5]  # Prvních 5 emailů jako ukázka
        
        response_data = {
            "status": "ready",
            "total_emails": len(unique_emails),
            "sample_emails": sample_emails,
            "file_info": {
                "filename": filename,
                "encoding": detected_encoding,
                "size_bytes": file_size
            }
        }
        
        app_logger.info(f"API /load_txt: Sending response: {response_data}")
        app_logger.info("=" * 50)
        return jsonify(response_data)

    except Exception as e:
        app_logger.error(f"API /load_txt: Error processing TXT file: {str(e)}", exc_info=True)
        if "uploaded_filepath" in locals() and uploaded_filepath.exists():
            os.remove(uploaded_filepath)
            app_logger.info(f"API /load_txt: Removed failed upload file: {uploaded_filepath}")
        with verification_lock:
            current_verification_state["status"] = "error"
            current_verification_state["error_message"] = str(e)
        app_logger.info("=" * 50)
        return jsonify({"error": f"Chyba při zpracování TXT: {str(e)}"}), 500


@app.route("/select_column", methods=["POST"])
def select_column_route():
    """
    Route pro výběr sloupce s emaily z nahraného CSV.

    Očekává JSON s klíčem 'column' obsahujícím název vybraného sloupce.
    Provede následující kroky:
    1. Kontrola stavu verifikace
    2. Načtení CSV souboru s detekovaným kódováním a oddělovačem
    3. Extrakce emailů z vybraného sloupce
    4. Filtrace duplicitních emailů
    5. Aktualizace stavu verifikace

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: "ready"
                - total_emails: počet nalezených unikátních emailů
            - Při chybě: chybovou zprávu a status 400/500

    Možné chyby:
        - Neplatný stav pro výběr sloupce
        - Chybí název sloupce v požadavku
        - Sloupec nebyl nalezen v CSV
        - V sloupci nebyly nalezeny žádné emaily
    """
    with verification_lock:
        # Kontrola, zda je aplikace ve správném stavu pro výběr sloupce nebo je připravena TXT
        if current_verification_state["status"] not in ["selecting_column", "ready"]:
            app_logger.warning(
                f"API /select_column: Invalid state '{current_verification_state['status']}' for column selection."
            )
            return jsonify({"error": "Neplatný stav pro výběr sloupce."}), 400
        current_verification_state["last_activity_time"] = time.time()

    # Získání cesty k souboru a typu souboru ze stavu
    uploaded_filepath_str = current_verification_state.get("uploaded_filepath")
    file_type = current_verification_state.get("file_type", "csv")
    
    if not uploaded_filepath_str or not Path(uploaded_filepath_str).exists():
        app_logger.error("API /select_column: Uploaded file path not found or file does not exist.")
        return jsonify({"error": "Nejprve nahrajte soubor"}), 400

    # Pro TXT soubory jsou emaily již zpracovány
    if file_type == "txt":
        emails_list = current_verification_state.get("emails_list", [])
        if not emails_list:
            app_logger.error("API /select_column: No emails found in TXT file.")
            return jsonify({"error": "V TXT souboru nebyly nalezeny žádné emaily"}), 400
        
        unique_emails_list = emails_list
        app_logger.info(f"API /select_column: Using {len(unique_emails_list)} emails from TXT file")
    
    else:  # CSV soubor
        data = request.json
        selected_column = data.get("column")
        if not selected_column:
            app_logger.warning("API /select_column: No column selected in request.")
            return jsonify({"error": "Nebyl vybrán žádný sloupec"}), 400

        detected_encoding = current_verification_state.get("detected_encoding", "utf-8")
        detected_delimiter = current_verification_state.get("detected_delimiter", ";")

        try:
            emails_to_verify_list = []
            # Otevření CSV souboru s detekovaným kódováním a oddělovačem
            with open(uploaded_filepath_str, "r", encoding=detected_encoding) as f_csv:
                reader = csv.DictReader(
                    f_csv, delimiter=detected_delimiter
                )  # Použití DictReader pro snadný přístup ke sloupcům
                if (
                    selected_column not in reader.fieldnames
                ):  # Kontrola, zda vybraný sloupec existuje
                    with verification_lock:
                        current_verification_state["status"] = "error"
                    app_logger.error(
                        f"API /select_column: Selected column '{selected_column}' not found. Available: {reader.fieldnames}"
                    )
                    return (
                        jsonify(
                            {"error": f"Sloupec '{selected_column}' nebyl v CSV nalezen."}
                        ),
                        400,
                    )
                for row in reader:  # Iterace přes řádky CSV
                    email_value = row.get(
                        selected_column, ""
                    ).strip()  # Získání hodnoty z vybraného sloupce
                    if email_value:  # Pokud hodnota není prázdná
                        emails_to_verify_list.append(email_value)

            # Odstranění duplicitních emailů (zachování pořadí)
            unique_emails_list = list(dict.fromkeys(emails_to_verify_list))
            app_logger.info(
                f"API /select_column: Column '{selected_column}' selected. Found {len(emails_to_verify_list)} emails, {len(unique_emails_list)} unique."
            )

            if not unique_emails_list:  # Pokud nebyly nalezeny žádné emaily
                with verification_lock:
                    current_verification_state["status"] = "error"
                app_logger.warning(
                    f"API /select_column: No email addresses found in column '{selected_column}'."
                )
                return (
                    jsonify(
                        {
                            "error": f"Ve sloupci '{selected_column}' nebyly nalezeny žádné platné emailové adresy."
                        }
                    ),
                    400,
                )

        except Exception as e:  # Zachycení chyb při extrakci emailů z CSV
            with verification_lock:
                current_verification_state["status"] = "error"
                current_verification_state["error_message"] = str(e)
            app_logger.error(
                f"API /select_column: Error extracting emails from column '{selected_column}': {e}",
                exc_info=True,
            )
            return jsonify({"error": f"Chyba při extrakci emailů z CSV: {str(e)}"}), 500

    # Kontrola, zda byly nalezeny nějaké emaily (pro oba typy souborů)
    if not unique_emails_list:
        with verification_lock:
            current_verification_state["status"] = "error"
        app_logger.warning("API /select_column: No email addresses found.")
        return jsonify({"error": "Nebyly nalezeny žádné platné emailové adresy."}), 400

    # Aktualizace stavu verifikace s načtenými emaily
    with verification_lock:
        if file_type == "csv":
            current_verification_state["selected_column"] = selected_column
        current_verification_state["emails_to_verify"] = unique_emails_list
        current_verification_state["total_emails"] = len(unique_emails_list)
        current_verification_state["status"] = "ready_to_verify"
        current_verification_state["last_activity_time"] = time.time()
    
    app_logger.info(f"API /select_column: Prepared {len(unique_emails_list)} emails for verification")
    return jsonify({"status": "ready", "total_emails": len(unique_emails_list)})


def run_bulk_verification_in_thread():
    """
    Spouští hromadnou verifikaci emailů v samostatném vlákně.

    Tato funkce zpracovává emaily po dávkách a ukládá výsledky verifikace.
    Používá asynchronní verifikaci pro efektivní zpracování velkého množství emailů.
    Podporuje zastavení verifikace a zachování výsledků.
    """
    global current_verification_state
    run_id_for_thread = None  # ID běhu specifické pro toto vlákno
    with verification_lock:
        run_id_for_thread = current_verification_state.get("verification_run_id")
        current_verification_state[
            "is_thread_active"
        ] = True  # Označení, že vlákno je aktivní

    # Vytvoření nové smyčky událostí pro toto vlákno (každé vlákno s asyncio potřebuje vlastní smyčku)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    app_logger.info(
        f"Thread (ID: {run_id_for_thread}): Starting bulk verification process."
    )
    email_verifier_instance.reset_internal_state_for_run()  # Reset interní cache verifikátoru pro nový běh

    try:
        # Získání seznamu emailů a velikosti dávky ze stavu (kopie pro bezpečnost vláken)
        emails_for_this_run = list(
            current_verification_state.get("emails_to_verify", [])
        )
        total_emails_for_this_run = len(emails_for_this_run)
        ui_app_batch_size = current_verification_state.get("app_batch_size_for_ui", 20)

        # Iterace přes emaily po dávkách
        for i in range(0, total_emails_for_this_run, ui_app_batch_size):
            # Kritická sekce: kontrola požadavku na zastavení a ID běhu na začátku každé dávky
            with verification_lock:
                stop_requested = current_verification_state.get("stop_requested", False)
                current_run_id = current_verification_state.get("verification_run_id")

                # Pokud bylo požádáno o zastavení nebo se ID běhu změnilo (nový běh byl spuštěn)
                if stop_requested or current_run_id != run_id_for_thread:
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Stopping verification. "
                        f"stop_requested={stop_requested}, "
                        f"current_run_id={current_run_id}, "
                        f"thread_run_id={run_id_for_thread}"
                    )

                    if (
                        current_run_id == run_id_for_thread
                    ):  # Pokud se jedná o aktuální běh tohoto vlákna
                        current_verification_state[
                            "status"
                        ] = "stopped"  # Nastavení stavu na zastaveno
                        save_verification_results(
                            run_id_for_thread, is_final_save=True
                        )  # Uložení finálních výsledků

                    break  # Ukončení smyčky zpracování dávek

                current_verification_state["last_activity_time"] = time.time()
                current_verification_state["current_batch_num"] = (
                    i // ui_app_batch_size
                ) + 1  # Aktualizace čísla dávky

            batch_to_process_list = emails_for_this_run[
                i : i + ui_app_batch_size
            ]  # Aktuální dávka emailů
            app_logger.info(
                f"Thread (ID: {run_id_for_thread}): Processing batch {current_verification_state['current_batch_num']}/{current_verification_state['total_batches']} ({len(batch_to_process_list)} emails)."
            )

            batch_results_list = []
            try:
                # Asynchronní verifikace dávky emailů
                batch_results_list = loop.run_until_complete(
                    email_verifier_instance.verify_emails_in_batch(
                        batch_to_process_list
                    )
                )
            except Exception as e_gen:  # Zachycení obecné chyby při verifikaci dávky
                app_logger.error(
                    f"Thread (ID: {run_id_for_thread}): General error during batch verification: {e_gen}",
                    exc_info=True,
                )

            # Pokud se nepodařilo získat výsledky, vytvoří se chybové záznamy
            if not batch_results_list and batch_to_process_list:
                batch_results_list = [
                    {
                        "email": eml,
                        "is_valid": None,
                        "status_code": "batch_processing_error",
                        "message": "Error processing batch in verification thread.",
                        "is_catchall": False,
                        "verification_steps": [],
                        "smtp_code_internal": None,
                    }
                    for eml in batch_to_process_list
                ]

            # Opětovná kontrola před uložením výsledků dávky (pro případ, že mezitím přišel požadavek na stop)
            with verification_lock:
                if current_verification_state.get(
                    "verification_run_id"
                ) != run_id_for_thread or current_verification_state.get(
                    "stop_requested", False
                ):
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Skipping batch results save - run superseded or stop requested"
                    )
                    break  # Ukončení smyčky

                # Zpracování výsledků dávky a aktualizace statistik
                for result_item in batch_results_list:
                    email_addr = result_item["email"]
                    current_verification_state["results"][email_addr] = result_item
                    current_verification_state["processed_emails"] += 1
                    if result_item.get("is_valid") is True:
                        domain_part = email_addr.split("@")[-1]
                        if result_item.get("is_catchall"):  # Pokud je doména catch-all
                            current_verification_state["probable_emails"] += 1
                            # Aktualizace souhrnu catch-all domén
                            current_verification_state["accept_all_domains_summary"][
                                domain_part
                            ] = (
                                current_verification_state[
                                    "accept_all_domains_summary"
                                ].get(domain_part, 0)
                                + 1
                            )
                        else:  # Normálně validní
                            current_verification_state["valid_emails"] += 1
                    elif result_item.get("is_valid") is False:  # Nevalidní
                        current_verification_state["invalid_emails"] += 1
                    else:  # Neznámý stav
                        current_verification_state["unknown_emails"] += 1

                    # Přidání záznamu do logu pro UI
                    log_status_str = (
                        "success"  # Zelená barva pro validní
                        if result_item.get("is_valid")
                        else (
                            "warning" if result_item.get("is_catchall") else "error"
                        )  # Oranžová pro catch-all, červená pro ostatní
                    )
                    current_verification_state["verification_log"].append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "status": log_status_str,
                            "action": f"Ověřen email: {email_addr}",
                            "details": f"Výsledek: {result_item.get('status_code', 'N/A')}",
                        }
                    )
                    # Omezení délky logu pro UI
                    if len(current_verification_state["verification_log"]) > 100:
                        current_verification_state[
                            "verification_log"
                        ] = current_verification_state["verification_log"][
                            -50:
                        ]  # Ponechání posledních 50 záznamů

                # Uložení výsledků po každé dávce (pro případ pádu nebo zastavení)
                save_verification_results(run_id_for_thread, is_final_save=False)

        # Finální aktualizace stavu po dokončení všech dávek nebo zastavení
        with verification_lock:
            if (
                current_verification_state.get("verification_run_id")
                == run_id_for_thread
            ):  # Pokud stále platí ID tohoto běhu
                if (
                    current_verification_state["status"] == "verifying"
                ):  # Pokud nebyl mezitím stav změněn (např. na 'stopping')
                    if (
                        current_verification_state["processed_emails"]
                        >= total_emails_for_this_run
                    ):
                        current_verification_state[
                            "status"
                        ] = "completed"  # Všechny emaily zpracovány
                        app_logger.info(
                            f"Thread (ID: {run_id_for_thread}): Bulk verification process completed successfully."
                        )
                    else:  # Pokud nebyly všechny emaily zpracovány (např. kvůli předčasnému zastavení)
                        current_verification_state["status"] = "stopped"
                        app_logger.info(
                            f"Thread (ID: {run_id_for_thread}): Bulk verification process was stopped during execution."
                        )
                save_verification_results(
                    run_id_for_thread, is_final_save=True
                )  # Finální uložení výsledků
            else:  # Pokud byl tento běh nahrazen novým
                app_logger.info(
                    f"Thread (ID: {run_id_for_thread}): Run was superseded by a new one. Results for this old run will not be saved centrally by this thread."
                )

    finally:
        # Finální úklid vlákna
        with verification_lock:
            # Změna is_thread_active na False pouze pokud je to stále aktuální vlákno nebo pokud žádné jiné vlákno není aktivní
            if current_verification_state.get(
                "verification_run_id"
            ) == run_id_for_thread or not current_verification_state.get(
                "is_thread_active"
            ):
                current_verification_state["is_thread_active"] = False
                app_logger.info(
                    f"Thread (ID: {run_id_for_thread}): Thread cleanup completed."
                )
        loop.close()  # Uzavření smyčky událostí vlákna


def save_verification_results(run_id_to_save: int, is_final_save: bool = False):
    """
    Ukládá výsledky verifikace do CSV souboru.

    Args:
        run_id_to_save (int): ID běhu verifikace pro uložení
        is_final_save (bool): Pokud True, jedná se o finální uložení běhu
    """
    try:
        with verification_lock:
            # Kontrola, zda se ID běhu shoduje (pro případ, že by se mezitím spustil nový běh)
            if current_verification_state["verification_run_id"] != run_id_to_save:
                app_logger.warning(
                    f"Run ID mismatch during save: {run_id_to_save} vs {current_verification_state['verification_run_id']}"
                )
                return

            if not current_verification_state[
                "results"
            ]:  # Pokud nejsou žádné výsledky k uložení
                app_logger.warning("No results to save")
                return

            # Určení cesty k souboru s výsledky
            if not current_verification_state[
                "result_filepath"
            ]:  # Pokud ještě nebyla cesta vytvořena
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                result_filepath = (
                    Path(app.config["RESULTS_FOLDER"])
                    / f"verification_results_{timestamp}.csv"
                )
                current_verification_state["result_filepath"] = str(result_filepath)
            else:  # Použití existující cesty
                result_filepath = Path(current_verification_state["result_filepath"])

            # Příprava dat pro zápis do CSV
            csv_data = []
            for email, result in current_verification_state["results"].items():
                # Určení stavu na základě is_valid a is_catchall
                status = "unknown"
                if result.get("is_valid") is True:
                    status = "valid" if not result.get("is_catchall") else "catchall"
                elif result.get("is_valid") is False:
                    status = "invalid"

                # Získání typu domény
                domain_type = "unknown"
                if result.get("domain_type"):  # Pokud je explicitně uveden
                    domain_type = result.get("domain_type")
                elif result.get("is_disposable"):  # Pokud je doména jednorázová
                    domain_type = "disposable"

                # Získání SMTP odpovědi s kódem
                smtp_response = ""
                if result.get("smtp_response"):  # Starší název klíče
                    smtp_response = result.get("smtp_response")
                if result.get("smtp_code"):  # Starší název klíče
                    code = result.get("smtp_code")
                    if smtp_response:
                        smtp_response = f"{code}: {smtp_response}"
                    else:
                        smtp_response = f"Code: {code}"
                elif result.get("smtp_code_internal"):  # Novější název klíče
                    code = result.get("smtp_code_internal")
                    if smtp_response:  # Pokud již byla zpráva z 'smtp_response'
                        smtp_response = f"{code}: {smtp_response}"
                    elif result.get("message"):  # Použití 'message' jako textu odpovědi
                        smtp_response = f"{code}: {result.get('message')}"
                    else:
                        smtp_response = f"Code: {code}"

                # Získání DNS záznamů
                dns_records = ""
                if result.get("mx_records"):  # Seznam MX záznamů
                    # Zformátování jako string oddělený čárkou
                    dns_records = ", ".join(
                        [host for prio, host in result.get("mx_records", [])]
                    )
                elif result.get("mx_record"):  # Jeden MX záznam
                    dns_records = result.get("mx_record")

                # Získání chybové zprávy
                error_msg = ""
                if result.get("error"):  # Starší název klíče
                    error_msg = result.get("error")
                elif result.get(
                    "message"
                ):  # Novější název klíče (obsahuje detailnější popis)
                    error_msg = result.get("message")
                elif result.get(
                    "status_code"
                ):  # Pokud není zpráva, použije se status_code
                    error_msg = f"Status: {result.get('status_code')}"

                # Získání času verifikace (pokud je k dispozici)
                verification_time = ""
                if result.get("verification_time"):
                    verification_time = str(result.get("verification_time"))

                # Pole pro CSV řádek
                # Poznámka: Názvy sloupců by měly být konzistentní s tím, co očekává frontend nebo další zpracování.
                # Zde jsou použity obecné názvy.
                row = {
                    "email": email,
                    "status": status,  # valid, invalid, catchall, unknown
                    "error_details": error_msg,  # Detailní chybová zpráva nebo stavový kód
                    "domain_type": domain_type,  # disposable, unknown
                    "smtp_response_full": smtp_response,  # SMTP kód a zpráva
                    "mx_servers": dns_records,  # Seznam MX serverů
                    "verification_duration_ms": verification_time,  # Doba verifikace v ms (pokud je)
                    # Další potenciálně užitečné informace z 'result':
                    "raw_status_code": result.get("status_code"),
                    "is_catchall_domain": result.get("is_catchall", False),
                    "smtp_internal_code": result.get("smtp_code_internal"),
                }
                csv_data.append(row)

            if (
                not csv_data
            ):  # Pokud nejsou žádná data k zápisu (např. všechny emaily byly chybné před SMTP)
                app_logger.warning(
                    "No data to write to CSV, although results dictionary was not empty."
                )
                return

            # Určení, zda je potřeba zapsat hlavičky (nový soubor nebo finální uložení)
            write_headers = not result_filepath.exists() or is_final_save

            # Uložení do CSV s kódováním UTF-8-SIG pro kompatibilitu s Excelem
            mode = (
                "w" if write_headers else "a"
            )  # 'w' pro přepsání (s hlavičkami), 'a' pro připojení
            with open(result_filepath, mode, newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                if write_headers:
                    writer.writeheader()  # Zápis hlaviček
                writer.writerows(csv_data)  # Zápis dat

            app_logger.info(
                f"Results saved to {result_filepath} ({'final save' if is_final_save else 'incremental save'})"
            )
            # Přidání logu o uložení (pouze pokud je to relevantní pro aktuální běh)
            if current_verification_state["verification_run_id"] == run_id_to_save:
                add_verification_log(
                    "success",
                    "Uložení výsledků",
                    f"Výsledky uloženy do {result_filepath.name}",
                )

    except Exception as e:
        app_logger.error(f"Error saving verification results: {e}", exc_info=True)
        if current_verification_state["verification_run_id"] == run_id_to_save:
            add_verification_log("error", "Chyba při uložení výsledků", str(e))


@app.route(
    "/start_verification", methods=["GET"]
)  # Metoda GET je zde použita pro jednoduchost volání z UI tlačítka
def start_verification_route():
    """
    Route pro spuštění hromadné verifikace emailů.

    Spustí verifikaci v samostatném vlákně a vrací ID běhu.
    Provede následující kroky:
    1. Kontrola stavu verifikace
    2. Generování nového ID běhu
    3. Reset stavu verifikace
    4. Spuštění verifikačního vlákna
    5. Vrácení ID běhu

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: "verifying"
                - message: "Verifikace byla spuštěna."
                - run_id: ID běhu verifikace
            - Při chybě: chybovou zprávu a status 400

    Možné chyby:
        - Neplatný stav pro spuštění verifikace
        - Chybí emaily k verifikaci
        - Staré vlákno stále běží
    """
    global bulk_verification_thread
    with verification_lock:
        # Kontrola, zda je možné spustit novou verifikaci
        if current_verification_state["status"] not in [
            "ready_to_verify",  # Připraveno po výběru sloupce
            "stopped",  # Předchozí běh byl zastaven
            "completed",  # Předchozí běh byl dokončen
            "error",  # Předchozí operace skončila chybou
            "idle",  # Úplně nový start (pokud by se emaily načetly jinak)
        ]:
            app_logger.warning(
                f"API /start_verification: Attempt to start verification in invalid state '{current_verification_state['status']}'."
            )
            return jsonify({"error": "Verifikace již běží nebo není připravena."}), 400
        if not current_verification_state.get(
            "emails_to_verify"
        ):  # Kontrola, zda jsou nějaké emaily k verifikaci
            app_logger.warning("API /start_verification: No emails found to verify.")
            return (
                jsonify({"error": "Nejprve nahrajte CSV a vyberte sloupec s emaily."}),
                400,
            )

        # Signalizace starému vláknu, aby se ukončilo, pokud ještě běží
        if bulk_verification_thread and bulk_verification_thread.is_alive():
            app_logger.warning(
                "API /start_verification: Old verification thread is still active. Signaling it to stop."
            )
            current_verification_state[
                "stop_requested"
            ] = True  # Nastavení příznaku pro zastavení
            # Krátká pauza, aby staré vlákno mohlo zareagovat
            time.sleep(0.5)
            # Poznámka: Ideálně by se mělo počkat na ukončení vlákna (join), ale to by mohlo blokovat UI.
            # Alternativou je, že vlákno samo kontroluje run_id a ukončí se, pokud je ID jiné.

        # Generování nového ID běhu a resetování relevantních částí stavu
        new_run_id_val = int(
            time.time() * 1000
        )  # ID na základě timestampu v milisekundách
        current_verification_state.update(
            {
                "status": "verifying",  # Nový stav: verifikace probíhá
                "error_message": None,  # Reset chybové zprávy
                "processed_emails": 0,  # Reset počítadel
                "valid_emails": 0,
                "invalid_emails": 0,
                "probable_emails": 0,
                "unknown_emails": 0,
                "results": {},  # Reset výsledků
                "verification_log": [  # Inicializace logu pro nový běh
                    {
                        "timestamp": datetime.now().isoformat(),
                        "status": "info",
                        "action": "Spuštění verifikace",
                        "details": f"Běh ID: {new_run_id_val}",
                    }
                ],
                "start_time": datetime.now().isoformat(),  # Čas spuštění
                "last_activity_time": time.time(),
                "result_filepath": None,  # Reset cesty k výsledkům (nový soubor pro nový běh)
                "accept_all_domains_summary": {},  # Reset souhrnu catch-all
                "stop_requested": False,  # Reset příznaku zastavení pro nový běh
                "verification_run_id": new_run_id_val,  # Nastavení nového ID běhu
                "is_thread_active": False,  # Vlákno ještě není aktivní (bude nastaveno ve vlákně)
            }
        )

        # Výpočet celkového počtu dávek
        app_batch_size_for_ui_calc = current_verification_state.get(
            "app_batch_size_for_ui", 20
        )  # Použití hodnoty ze stavu
        total_emails_count = current_verification_state["total_emails"]
        current_verification_state["total_batches"] = (
            (total_emails_count + app_batch_size_for_ui_calc - 1)  # Zaokrouhlení nahoru
            // app_batch_size_for_ui_calc
            if total_emails_count > 0  # Ošetření dělení nulou
            else 0
        )

        app_logger.info(
            f"API /start_verification: Starting new verification run with ID: {new_run_id_val}."
        )
        # Vytvoření a spuštění nového vlákna pro hromadnou verifikaci
        bulk_verification_thread = threading.Thread(
            target=run_bulk_verification_in_thread,  # Cílová funkce vlákna
            name=f"BulkVerifyThread-{new_run_id_val}",  # Název vlákna pro snazší identifikaci v logu
        )
        bulk_verification_thread.daemon = (
            True  # Nastavení vlákna jako daemon (ukončí se s hlavním programem)
        )
        bulk_verification_thread.start()  # Spuštění vlákna
    return jsonify(
        {
            "status": "verifying",
            "message": "Verifikace byla spuštěna.",
            "run_id": new_run_id_val,  # Vrácení ID běhu klientovi
        }
    )


def add_verification_log(status: str, action: str, details: str = None):
    """
    Přidává záznam do logu verifikace (pro UI).

    Args:
        status (str): Status záznamu (success, error, warning, info)
        action (str): Popis akce
        details (str, optional): Detailní informace o akci
    """
    with verification_lock:
        log_entry = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),  # Formátované časové razítko
            "status": status,
            "action": action,
            "details": details,
        }
        current_verification_state["verification_log"].append(log_entry)
        # Omezení délky logu (např. posledních 1000 záznamů)
        if len(current_verification_state["verification_log"]) > 1000:
            current_verification_state["verification_log"] = current_verification_state[
                "verification_log"
            ][-1000:]


def cleanup_old_files(clear_current_state_files_only: bool = False):
    """
    Čistí staré soubory z upload a results složek.

    Args:
        clear_current_state_files_only (bool): Pokud True, smaže pouze soubory,
            které nejsou součástí aktuálního stavu verifikace.
            Pokud False, smaže všechny soubory ve složkách.
    """
    try:
        with verification_lock:
            current_files = set()  # Sada souborů, které jsou aktuálně používány
            if current_verification_state.get(
                "uploaded_filepath"
            ):  # Získání s .get pro bezpečnost
                current_files.add(Path(current_verification_state["uploaded_filepath"]))
            if current_verification_state.get("result_filepath"):
                current_files.add(Path(current_verification_state["result_filepath"]))

            # Čištění složky uploads
            uploads_dir = Path(app.config["UPLOAD_FOLDER"])
            for file_path in uploads_dir.glob(
                "*"
            ):  # Iterace přes všechny soubory ve složce
                if (
                    clear_current_state_files_only
                ):  # Pokud se mají mazat jen nepoužívané
                    if file_path not in current_files:
                        try:
                            file_path.unlink()  # Smazání souboru
                            app_logger.info(f"Deleted old upload file: {file_path}")
                        except Exception as e:
                            app_logger.error(f"Error deleting file {file_path}: {e}")
                else:  # Pokud se mají mazat všechny soubory
                    try:
                        file_path.unlink()
                        app_logger.info(f"Deleted upload file: {file_path}")
                    except Exception as e:
                        app_logger.error(f"Error deleting file {file_path}: {e}")

            # Čištění složky results (stejná logika)
            results_dir = Path(app.config["RESULTS_FOLDER"])
            for file_path in results_dir.glob("*"):
                if clear_current_state_files_only:
                    if file_path not in current_files:
                        try:
                            file_path.unlink()
                            app_logger.info(f"Deleted old result file: {file_path}")
                        except Exception as e:
                            app_logger.error(f"Error deleting file {file_path}: {e}")
                else:
                    try:
                        file_path.unlink()
                        app_logger.info(f"Deleted result file: {file_path}")
                    except Exception as e:
                        app_logger.error(f"Error deleting file {file_path}: {e}")

    except Exception as e:
        app_logger.error(f"Error during cleanup: {e}", exc_info=True)


@app.route("/cleanup", methods=["POST"])
def cleanup_route():
    """
    Route pro vyčištění starých souborů a reset stavu.

    Provede následující kroky:
    1. Smazání všech souborů z uploads složky
    2. Smazání všech souborů z results složky
    3. Reset stavu verifikace

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: "success"
                - message: "Cleanup completed"
            - Při chybě: chybovou zprávu a status 500

    Možné chyby:
        - Chyba při mazání souborů
        - Chyba při resetu stavu
    """
    try:
        cleanup_old_files(clear_current_state_files_only=False)  # Smazání všech souborů
        reset_verification_state()  # Resetování globálního stavu
        return jsonify({"status": "success", "message": "Cleanup completed"})
    except Exception as e:
        app_logger.error(f"Error during cleanup: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/status", methods=["GET"])
def status_route():
    """
    Route pro získání aktuálního stavu verifikace.

    Vrací detailní informace o průběhu verifikace včetně:
    - Aktuálního stavu
    - Statistik zpracování
    - Posledních záznamů z logu
    - Časových údajů
    - Informací o výsledcích

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: aktuální stav verifikace
                - error_message: popis chyby (pokud nastala)
                - total_emails: celkový počet emailů
                - processed_emails: počet zpracovaných emailů
                - valid_emails: počet validních emailů
                - invalid_emails: počet nevalidních emailů
                - probable_emails: počet pravděpodobně validních emailů
                - unknown_emails: počet emailů s neznámým stavem
                - current_batch: číslo aktuální dávky
                - total_batches: celkový počet dávek
                - start_time: čas začátku verifikace
                - last_activity_time: čas poslední aktivity
                - result_filepath: cesta k souboru s výsledky
                - has_results: příznak existence výsledků
                - verification_log_batch: poslední záznamy z logu
            - Při chybě: chybovou zprávu a status 500
    """
    try:
        with verification_lock:  # Zámek pro bezpečné čtení stavu
            # Získání dávky logů pro UI (např. poslední N záznamů dle velikosti dávky pro UI)
            log_batch = current_verification_state["verification_log"][
                -current_verification_state.get("app_batch_size_for_ui", 20) :
            ]

            # Sestavení JSON odpovědi s relevantními informacemi ze stavu
            return jsonify(
                {
                    "status": current_verification_state["status"],
                    "error_message": current_verification_state["error_message"],
                    "total_emails": current_verification_state["total_emails"],
                    "processed_emails": current_verification_state["processed_emails"],
                    "valid_emails": current_verification_state["valid_emails"],
                    "invalid_emails": current_verification_state["invalid_emails"],
                    "probable_emails": current_verification_state["probable_emails"],
                    "unknown_emails": current_verification_state["unknown_emails"],
                    "current_batch": current_verification_state["current_batch_num"],
                    "total_batches": current_verification_state["total_batches"],
                    "start_time": current_verification_state["start_time"],
                    "last_activity_time": current_verification_state[
                        "last_activity_time"
                    ],
                    "result_filepath": current_verification_state["result_filepath"],
                    "has_results": bool(
                        current_verification_state["result_filepath"]
                    ),  # True, pokud existuje cesta k výsledkům
                    "verification_log_batch": log_batch,  # Dávka logů pro UI
                }
            )
    except Exception as e:
        app_logger.error(f"Error getting status: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/stop_verification", methods=["POST"])
def stop_verification_route():
    """
    Route pro zastavení probíhající verifikace.

    Provede následující kroky:
    1. Kontrola aktuálního stavu verifikace
    2. Nastavení příznaku pro zastavení
    3. Počkání na dokončení aktuální dávky (vlákno samo kontroluje příznak)
    4. Uložení dosavadních výsledků
    5. Aktualizace stavu verifikace

    Returns:
        tuple: (JSON response, HTTP status code)
            - Při úspěchu: JSON obsahující:
                - status: "stopped"
                - message: "Verification process stopped"
                - filepath: cesta k souboru s výsledky
                - has_results: příznak existence výsledků
            - Při chybě: chybovou zprávu a status 500

    Možné chyby:
        - Verifikace neběží
        - Chyba při ukládání výsledků
    """
    try:
        with verification_lock:
            final_status = current_verification_state.get("status", "idle")
            run_id_at_stop = current_verification_state.get(
                "verification_run_id"
            )  # ID běhu v momentě požadavku na stop

            # Pokud verifikace neběží nebo není ve stavu, kdy ji lze zastavit
            if final_status not in [
                "verifying",
                "running",
            ]:  # 'running' je alias pro 'verifying'
                return jsonify(
                    {
                        "status": final_status,
                        "message": "No verification process is currently running",
                        "has_results": bool(
                            current_verification_state["result_filepath"]
                        ),
                    }
                )

            # Nastavení příznaků pro zastavení
            current_verification_state["stop_requested"] = True
            current_verification_state[
                "status"
            ] = "stopping"  # Přechodný stav "zastavování"
            add_verification_log(
                "info",
                "Požadavek na zastavení",
                "Verifikace bude zastavena po dokončení aktuální dávky.",
            )

        # Počkání na vlákno, aby se ukončilo (s timeoutem)
        # Vlákno by mělo samo detekovat 'stop_requested' nebo změnu 'run_id'
        if bulk_verification_thread and bulk_verification_thread.is_alive():
            bulk_verification_thread.join(timeout=5.0)  # Počká maximálně 5 sekund

        # Finální aktualizace stavu a uložení výsledků
        with verification_lock:
            # Ujistíme se, že operujeme na stejném běhu, který byl zastavován
            if current_verification_state.get("verification_run_id") == run_id_at_stop:
                save_verification_results(
                    run_id_at_stop, is_final_save=True
                )  # Uložení finálních (nebo částečných) výsledků
                current_verification_state[
                    "status"
                ] = "stopped"  # Konečný stav "zastaveno"
                add_verification_log(
                    "info",
                    "Verifikace zastavena",
                    "Proces verifikace byl úspěšně zastaven.",
                )
            else:
                # Pokud se mezitím spustil nový běh, tento starý je již irelevantní
                app_logger.info(
                    f"Stop request for run {run_id_at_stop} processed, but a new run is active."
                )

            return jsonify(
                {
                    "status": current_verification_state.get(
                        "status", "stopped"
                    ),  # Vrácení aktuálního stavu
                    "message": "Verification process stopped",
                    "filepath": current_verification_state.get("result_filepath"),
                    "has_results": bool(
                        current_verification_state.get("result_filepath")
                    ),
                }
            )

    except Exception as e:
        app_logger.error(f"Error stopping verification: {e}", exc_info=True)
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"Error stopping verification: {str(e)}",
                    "has_results": bool(
                        current_verification_state.get("result_filepath")
                    ),  # .get pro bezpečnost
                }
            ),
            500,
        )


@app.route("/download_results", methods=["GET"])
def download_results_route():
    """
    Route pro stažení výsledků verifikace.

    Provede následující kroky:
    1. Kontrola existence souboru s výsledky
    2. Kontrola bezpečnosti cesty k souboru
    3. Odeslání souboru pro stažení

    Returns:
        tuple: (File response, HTTP status code)
            - Při úspěchu: CSV soubor pro stažení
            - Při chybě: chybovou zprávu a status 404/403/500

    Možné chyby:
        - Soubor s výsledky neexistuje
        - Neplatná cesta k souboru
        - Soubor není v povolené složce
    """
    try:
        with verification_lock:
            # Kontrola, zda existuje cesta k souboru s výsledky
            if not current_verification_state.get(
                "result_filepath"
            ):  # .get pro bezpečnost
                return jsonify({"error": "No results file available"}), 404

            result_path = Path(current_verification_state["result_filepath"])
            if not result_path.exists():  # Kontrola, zda soubor fyzicky existuje
                return jsonify({"error": "Results file not found"}), 404

            # Bezpečnostní kontrola: zajistí, že soubor je ve složce RESULTS_FOLDER
            results_folder = Path(
                app.config["RESULTS_FOLDER"]
            ).resolve()  # Absolutní cesta k povolené složce
            result_path_resolved = (
                result_path.resolve()
            )  # Absolutní cesta k požadovanému souboru

            # Zkontroluje, zda cesta k souboru začíná cestou k povolené složce
            if not str(result_path_resolved).startswith(str(results_folder)):
                app_logger.error(
                    f"Security check failed: {result_path_resolved} is not in {results_folder}"
                )
                return (
                    jsonify({"error": "Invalid file path"}),
                    403,
                )  # Chyba 403 Forbidden

            # Získání názvu souboru z cesty
            filename = result_path.name

            app_logger.info(f"Sending file for download: {result_path}")
            # Odeslání souboru klientovi
            return send_file(
                result_path,
                mimetype="text/csv",  # MIME typ pro CSV
                as_attachment=True,  # Soubor se má stáhnout, ne zobrazit v prohlížeči
                download_name=filename,  # Název souboru pro stažení
            )

    except Exception as e:
        app_logger.error(f"Error downloading results: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Načtení konfigurace hosta a portu z proměnných prostředí nebo výchozích hodnot
    host_val = os.environ.get(
        "FLASK_RUN_HOST", "0.0.0.0"
    )  # Výchozí host 0.0.0.0 (poslouchá na všech rozhraních)
    port_val = int(os.environ.get("FLASK_RUN_PORT", 5001))  # Výchozí port 5001
    is_debug_mode = (
        os.environ.get("FLASK_DEBUG", "1") == "1"
    )  # Povolení debug módu (výchozí je zapnuto)
    app_logger.info(
        f"Starting Flask app on {host_val}:{port_val} with debug_mode={is_debug_mode}"
    )

    # Registrace funkce pro úklid při ukončení aplikace
    import atexit

    # Lambda funkce, která zavolá cleanup_old_files s parametrem, aby se mazaly jen nepoužívané soubory
    # Pokud by se měly mazat všechny, parametr by byl False.
    atexit.register(lambda: cleanup_old_files(clear_current_state_files_only=True))

    # Spuštění Flask aplikace
    app.run(
        debug=is_debug_mode,  # Povolení debug módu
        host=host_val,
        port=port_val,
        threaded=True,  # Povolení více vláken pro zpracování požadavků (důležité pro asyncio a vlákna na pozadí)
        use_reloader=is_debug_mode,  # Povolení automatického restartu při změnách kódu (pouze v debug módu)
    )
