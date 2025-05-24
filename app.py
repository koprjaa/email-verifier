"""
Flask aplikace pro verifikaci emailových adres.

Tato aplikace poskytuje REST API pro verifikaci jednotlivých emailových adres
a pro hromadnou verifikaci emailů z CSV souborů. Aplikace využívá asynchronní
verifikaci emailů a poskytuje detailní logování a sledování průběhu verifikace.

Hlavní funkce:
    - Verifikace jednotlivých emailových adres
    - Hromadná verifikace emailů z CSV souborů
    - Detekce kódování a oddělovačů v CSV souborech
    - Asynchronní zpracování velkého množství emailů
    - Detailní logování a sledování průběhu verifikace
    - Export výsledků do CSV souboru

Konfigurace:
    Aplikace načítá konfiguraci z následujících zdrojů:
    - Soubor config.json v kořenovém adresáři
    - Proměnné prostředí (FLASK_RUN_HOST, FLASK_RUN_PORT, FLASK_DEBUG)
    - Výchozí hodnoty pro případ chybějící konfigurace

Složky:
    - uploads/: Pro dočasné ukládání nahraných CSV souborů
    - results/: Pro ukládání výsledků verifikace
    - data/: Pro ukládání konfiguračních souborů (např. seznam disposable domén)

Attributes:
    app (Flask): Instance Flask aplikace
    app_logger (logging.Logger): Logger pro aplikaci s nastaveným formátováním a úrovní logování
    email_verifier_instance (EmailVerifier): Instance verifikátoru emailů s načtenou konfigurací
    current_verification_state (dict): Aktuální stav verifikace obsahující:
        - status: Aktuální stav verifikace (idle, loading_csv, verifying, completed, error)
        - error_message: Popis chyby, pokud nastala
        - uploaded_filepath: Cesta k nahranému CSV souboru
        - selected_column: Název vybraného sloupce s emaily
        - emails_to_verify: Seznam emailů k verifikaci
        - total_emails: Celkový počet emailů k verifikaci
        - processed_emails: Počet zpracovaných emailů
        - valid_emails: Počet validních emailů
        - invalid_emails: Počet nevalidních emailů
        - probable_emails: Počet pravděpodobně validních emailů (catch-all domény)
        - unknown_emails: Počet emailů s neznámým stavem
        - current_batch_num: Číslo aktuální dávky
        - total_batches: Celkový počet dávek
        - results: Slovník s výsledky verifikace
        - verification_log: Seznam záznamů o průběhu verifikace
        - start_time: Čas začátku verifikace
        - last_activity_time: Čas poslední aktivity
        - result_filepath: Cesta k souboru s výsledky
        - accept_all_domains_summary: Souhrn catch-all domén
        - stop_requested: Příznak požadavku na zastavení
        - verification_run_id: ID běhu verifikace
        - is_thread_active: Příznak aktivního vlákna
        - detected_encoding: Detekované kódování CSV
        - detected_delimiter: Detekovaný oddělovač sloupců
        - app_batch_size_for_ui: Velikost dávky pro UI
    verification_lock (threading.RLock): Zámek pro synchronizaci přístupu ke stavu verifikace
    bulk_verification_thread (threading.Thread): Vlákno pro hromadnou verifikaci emailů
"""

import asyncio
import csv
import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import pandas as pd

from verifier.email_verifier import EmailVerifier
from verifier.exceptions import VerificationError

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["RESULTS_FOLDER"] = "results"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["RESULTS_FOLDER"], exist_ok=True)

app_logger = logging.getLogger("flask.app")
app_logger.setLevel(logging.DEBUG)
flask_handler = logging.StreamHandler()
flask_handler.setLevel(logging.DEBUG)
flask_formatter = logging.Formatter(
    "%(asctime)s - %(threadName)s - %(levelname)s - %(message)s"
)
flask_handler.setFormatter(flask_formatter)
if not app_logger.handlers:
    app_logger.addHandler(flask_handler)

try:
    with open("config.json", "r", encoding="utf-8") as f:
        app_level_config = json.load(f)
    app_logger.info("Main config.json loaded successfully.")
except FileNotFoundError:
    app_logger.warning(
        "Main config.json not found in root. Using default parameters for EmailVerifier setup."
    )
    app_level_config = {}
except json.JSONDecodeError as e:
    app_logger.error(f"Error parsing main config.json: {e}. Using default parameters.")
    app_level_config = {}

# Remove batch_size from config if it exists
if "batch_size" in app_level_config:
    del app_level_config["batch_size"]

email_verifier_instance = EmailVerifier(
    timeout=app_level_config.get("timeout", 15),
    smtp_timeout=app_level_config.get("smtp_timeout", 10),
    dns_timeout=app_level_config.get("dns_timeout", 5),
    catchall_test_enabled=app_level_config.get(
        "catchall_test", app_level_config.get("check_catchall", True)
    ),
    check_disposable_enabled=app_level_config.get("check_disposable", True),
    connect_port=app_level_config.get("connect_port", 25),
    rate_limit_delay_base=app_level_config.get("rate_limit_delay", 2.0),
    max_concurrent_domains=app_level_config.get("max_concurrent_domains", 5),
    helo_hostname=app_level_config.get("helo_hostname", None),
    retry_attempts=app_level_config.get("retry_attempts", 2),
    retry_delay_base=app_level_config.get("retry_delay", 5.0),
    disposable_domains_file=app_level_config.get(
        "disposable_domains_file_path", "data/disposable_domains.txt"
    ),
    logger=app_logger,
    dns_servers=app_level_config.get("dns_servers", None),
    sender_email_override=app_level_config.get("sender_email_override", None),
    default_sender_email_config=app_level_config.get("sender_emails", {}).get(
        "default"
    ),
    sender_emails_by_domain_config={
        k: v
        for k, v in app_level_config.get("sender_emails", {}).items()
        if k != "default"
    },
)
app_logger.info("Global EmailVerifier instance created and configured.")

current_verification_state: Dict[str, Any] = {}
verification_lock = threading.RLock()  # Changed to RLock for better deadlock prevention
bulk_verification_thread = None


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
    with verification_lock:
        current_verification_state = {
            "status": "idle",
            "error_message": None,
            "uploaded_filepath": None,
            "selected_column": None,
            "emails_to_verify": [],
            "total_emails": 0,
            "processed_emails": 0,
            "valid_emails": 0,
            "invalid_emails": 0,
            "probable_emails": 0,
            "unknown_emails": 0,
            "current_batch_num": 0,
            "total_batches": 0,
            "results": {},
            "verification_log": [],
            "start_time": None,
            "last_activity_time": None,
            "result_filepath": None,
            "accept_all_domains_summary": {},
            "stop_requested": False,
            "verification_run_id": None,
            "is_thread_active": False,
            "detected_encoding": None,
            "detected_delimiter": None,
            "app_batch_size_for_ui": app_level_config.get("ui_batch_size", 20),
        }
        app_logger.info("Global verification state has been reset to 'idle'.")


reset_verification_state()


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
    return render_template("index.html")


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
    data = request.json
    email_to_verify = data.get("email")
    if not email_to_verify:
        app_logger.warning("API /verify_single: Missing 'email' in request payload.")
        return jsonify({"error": "Chybí email v požadavku"}), 400
    
    app_logger.info(f"API /verify_single: Received request to verify email: {email_to_verify}")
    
    # Create new event loop for this request
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        app_logger.info(f"API /verify_single: Starting verification process for {email_to_verify}")
        result = loop.run_until_complete(
            email_verifier_instance.verify_single_email(email_to_verify)
        )
        app_logger.info(
            f"API /verify_single: Verification completed for {email_to_verify}. Result: {result.get('status_code')}"
        )
        app_logger.debug(f"API /verify_single: Full verification result: {json.dumps(result, indent=2)}")
        return jsonify(result)
    except Exception as e:
        app_logger.error(
            f"API /verify_single: Error during verification of {email_to_verify}: {e}",
            exc_info=True,
        )
        return jsonify({"error": f"Interní chyba serveru: {str(e)}"}), 500
    finally:
        loop.close()


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
    app_logger.info("="*50)
    app_logger.info("API /load_csv: Starting CSV upload process")
    app_logger.info(f"API /load_csv: Request content type: {request.content_type}")
    app_logger.info(f"API /load_csv: Request headers: {dict(request.headers)}")
    app_logger.info(f"API /load_csv: Request method: {request.method}")
    app_logger.info(f"API /load_csv: Request form data: {request.form}")
    app_logger.info(f"API /load_csv: Request files: {request.files}")
    
    try:
        with verification_lock:
            app_logger.info(f"API /load_csv: Current verification state: {current_verification_state['status']}")
            if current_verification_state["status"] not in [
                "idle",
                "error",
                "completed",
                "stopped",
            ]:
                app_logger.warning(
                    f"API /load_csv: Attempt to load CSV while in state '{current_verification_state['status']}'."
                )
                return jsonify({"error": "Jiná operace již probíhá."}), 400
            reset_verification_state()
            current_verification_state["status"] = "loading_csv"
            current_verification_state["last_activity_time"] = time.time()
            app_logger.info("API /load_csv: Reset verification state and set status to 'loading_csv'")

        if "file" not in request.files:
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning("API /load_csv: No file part in the request.")
            app_logger.warning(f"API /load_csv: Available files in request: {list(request.files.keys())}")
            return jsonify({"error": "Soubor nebyl poskytnut"}), 400

        file = request.files["file"]
        app_logger.info(f"API /load_csv: Received file: {file.filename}")
        app_logger.info(f"API /load_csv: File content type: {file.content_type}")
        app_logger.info(f"API /load_csv: File size: {request.content_length if request.content_length else 'unknown'}")
        
        if file.filename == "":
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning("API /load_csv: No file selected (empty filename).")
            return jsonify({"error": "Nebyl vybrán žádný soubor"}), 400

        if not file.filename.lower().endswith(".csv"):
            with verification_lock:
                current_verification_state["status"] = "error"
            app_logger.warning(
                f"API /load_csv: Invalid file type '{file.filename}'. Only CSV allowed."
            )
            return jsonify({"error": "Povoleny jsou pouze CSV soubory"}), 400

        filename = secure_filename(file.filename)
        uploaded_filepath = (
            Path(app.config["UPLOAD_FOLDER"])
            / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        )
        app_logger.info(f"API /load_csv: Saving file to: {uploaded_filepath}")

        try:
            app_logger.info("API /load_csv: Starting file save operation...")
            # Read file in chunks to handle large files
            chunk_size = 8192  # 8KB chunks for better progress tracking
            total_size = 0
            chunk_count = 0
            start_time = time.time()
            
            app_logger.info(f"API /load_csv: Opening file for writing: {uploaded_filepath}")
            with open(uploaded_filepath, 'wb') as f:
                while True:
                    app_logger.debug(f"API /load_csv: Reading chunk {chunk_count + 1}...")
                    chunk = file.read(chunk_size)
                    if not chunk:
                        app_logger.debug("API /load_csv: No more chunks to read")
                        break
                    f.write(chunk)
                    total_size += len(chunk)
                    chunk_count += 1
                    if chunk_count % 100 == 0:  # Log every 100 chunks
                        elapsed = time.time() - start_time
                        speed = total_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
                        app_logger.info(f"API /load_csv: Progress - {total_size/1024:.1f}KB written, {speed:.1f}MB/s")
            
            elapsed = time.time() - start_time
            speed = total_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
            app_logger.info(
                f"API /load_csv: File '{filename}' saved to '{uploaded_filepath}' ({total_size/1024:.1f}KB total, {chunk_count} chunks, {speed:.1f}MB/s average speed)."
            )
            
            # Verify file was saved correctly
            if not uploaded_filepath.exists():
                raise Exception(f"File was not saved correctly at {uploaded_filepath}")
            app_logger.info(f"API /load_csv: Verified file exists at {uploaded_filepath}")
            
            # Check file size after save
            file_size = uploaded_filepath.stat().st_size
            app_logger.info(f"API /load_csv: Saved file size: {file_size} bytes")
            
            if file_size == 0:
                raise Exception("Uploaded file is empty")
            
            detected_encoding = None
            headers = []
            encodings_to_try = [
                "utf-8-sig",
                "utf-8",
                "cp1250",
                "iso-8859-2",
                "windows-1250",
            ]
            app_logger.info("API /load_csv: Starting encoding detection...")
            
            # Try to read first few bytes to check if file is readable
            try:
                app_logger.info("API /load_csv: Reading first 1024 bytes of file...")
                with open(uploaded_filepath, 'rb') as f:
                    first_bytes = f.read(1024)
                    app_logger.info(f"API /load_csv: First 1024 bytes of file: {first_bytes}")
            except Exception as e:
                app_logger.error(f"API /load_csv: Error reading first bytes of file: {str(e)}")
                raise

            # Try different delimiters
            delimiters = [',', ';', '\t', '|']
            detected_delimiter = None
            
            for enc in encodings_to_try:
                try:
                    app_logger.debug(f"API /load_csv: Trying encoding '{enc}'...")
                    with open(uploaded_filepath, "r", encoding=enc) as f_csv:
                        # Read first line to detect delimiter
                        first_line = f_csv.readline().strip()
                        app_logger.debug(f"API /load_csv: First line with encoding '{enc}': {first_line}")
                        
                        # Try to detect delimiter
                        for delimiter in delimiters:
                            if delimiter in first_line:
                                parts = first_line.split(delimiter)
                                if len(parts) > 1:  # If we have multiple columns
                                    detected_delimiter = delimiter
                                    app_logger.info(f"API /load_csv: Detected delimiter '{delimiter}' with encoding '{enc}'")
                                    break
                        
                        if detected_delimiter:
                            # Reset file pointer and read with detected delimiter
                            f_csv.seek(0)
                            reader = csv.reader(f_csv, delimiter=detected_delimiter)
                            headers = next(reader)
                            detected_encoding = enc
                            app_logger.info(
                                f"API /load_csv: Successfully read CSV with encoding '{enc}' and delimiter '{detected_delimiter}'. Headers: {headers}"
                            )
                            break
                except (UnicodeDecodeError, StopIteration) as e:
                    app_logger.debug(f"API /load_csv: Failed to read with encoding '{enc}': {str(e)}")
                    continue
                except Exception as e:
                    app_logger.error(f"API /load_csv: Unexpected error while trying encoding '{enc}': {str(e)}")
                    continue

            if not headers:
                if uploaded_filepath.exists():
                    os.remove(uploaded_filepath)
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
            common_email_headers = ["email", "e-mail", "mail", "emailaddress"]
            for header_item in headers:
                normalized_header = header_item.lower().replace(" ", "").replace("_", "")
                if normalized_header in common_email_headers:
                    suggested_column = header_item
                    app_logger.info(f"API /load_csv: Found suggested email column: {suggested_column}")
                    break
            if not suggested_column and headers:
                suggested_column = headers[0]
                app_logger.info(f"API /load_csv: No email column found, using first column: {suggested_column}")

            app_logger.info("API /load_csv: Updating verification state...")
            with verification_lock:
                current_verification_state["uploaded_filepath"] = str(uploaded_filepath)
                current_verification_state["status"] = "selecting_column"
                current_verification_state["detected_encoding"] = detected_encoding
                current_verification_state["detected_delimiter"] = detected_delimiter
                current_verification_state["last_activity_time"] = time.time()
                app_logger.info("API /load_csv: Successfully processed CSV file, ready for column selection")
            
            response_data = {
                "status": "select_column",
                "columns": headers,
                "suggested_email_column": suggested_column,
            }
            app_logger.info(f"API /load_csv: Sending response: {response_data}")
            app_logger.info("="*50)
            return jsonify(response_data)

        except Exception as e:
            app_logger.error(f"API /load_csv: Error processing CSV file '{filename}': {str(e)}", exc_info=True)
            if uploaded_filepath.exists():
                os.remove(uploaded_filepath)
                app_logger.info(f"API /load_csv: Removed failed upload file: {uploaded_filepath}")
            with verification_lock:
                current_verification_state["status"] = "error"
                current_verification_state["error_message"] = str(e)
            app_logger.info("="*50)
            return jsonify({"error": f"Chyba při zpracování CSV: {str(e)}"}), 500
            
    except Exception as e:
        app_logger.error(f"API /load_csv: Unexpected error in route handler: {str(e)}", exc_info=True)
        with verification_lock:
            current_verification_state["status"] = "error"
            current_verification_state["error_message"] = str(e)
        app_logger.info("="*50)
        return jsonify({"error": f"Neočekávaná chyba serveru: {str(e)}"}), 500


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
        if current_verification_state["status"] != "selecting_column":
            app_logger.warning(
                f"API /select_column: Invalid state '{current_verification_state['status']}' for column selection."
            )
            return jsonify({"error": "Neplatný stav pro výběr sloupce."}), 400
        current_verification_state["last_activity_time"] = time.time()

    data = request.json
    selected_column = data.get("column")
    if not selected_column:
        app_logger.warning("API /select_column: No column selected in request.")
        return jsonify({"error": "Nebyl vybrán žádný sloupec"}), 400

    uploaded_filepath_str = current_verification_state.get("uploaded_filepath")
    detected_encoding = current_verification_state.get("detected_encoding", "utf-8")
    detected_delimiter = current_verification_state.get("detected_delimiter", ";")

    if not uploaded_filepath_str or not Path(uploaded_filepath_str).exists():
        with verification_lock:
            current_verification_state["status"] = "error"
        app_logger.error(
            "API /select_column: Uploaded CSV file path not found or file does not exist."
        )
        return jsonify({"error": "Nejprve nahrajte CSV soubor"}), 400

    try:
        emails_to_verify_list = []
        with open(uploaded_filepath_str, "r", encoding=detected_encoding) as f_csv:
            reader = csv.DictReader(f_csv, delimiter=detected_delimiter)
            if selected_column not in reader.fieldnames:
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
            for row in reader:
                email_value = row.get(selected_column, "").strip()
                if email_value:
                    emails_to_verify_list.append(email_value)

        unique_emails_list = list(dict.fromkeys(emails_to_verify_list))
        app_logger.info(
            f"API /select_column: Column '{selected_column}' selected. Found {len(emails_to_verify_list)} emails, {len(unique_emails_list)} unique."
        )

        if not unique_emails_list:
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

        with verification_lock:
            current_verification_state["selected_column"] = selected_column
            current_verification_state["emails_to_verify"] = unique_emails_list
            current_verification_state["total_emails"] = len(unique_emails_list)
            current_verification_state["status"] = "ready_to_verify"
            current_verification_state["last_activity_time"] = time.time()
        return jsonify({"status": "ready", "total_emails": len(unique_emails_list)})

    except Exception as e:
        with verification_lock:
            current_verification_state["status"] = "error"
            current_verification_state["error_message"] = str(e)
        app_logger.error(
            f"API /select_column: Error extracting emails from column '{selected_column}': {e}",
            exc_info=True,
        )
        return jsonify({"error": f"Chyba při extrakci emailů z CSV: {str(e)}"}), 500


def run_bulk_verification_in_thread():
    """
    Spouští hromadnou verifikaci emailů v samostatném vlákně.
    
    Tato funkce zpracovává emaily po dávkách a ukládá výsledky verifikace.
    Používá asynchronní verifikaci pro efektivní zpracování velkého množství emailů.
    Podporuje zastavení verifikace a zachování výsledků.
    """
    global current_verification_state
    run_id_for_thread = None
    with verification_lock:
        run_id_for_thread = current_verification_state.get("verification_run_id")
        current_verification_state["is_thread_active"] = True

    # Create new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    app_logger.info(f"Thread (ID: {run_id_for_thread}): Starting bulk verification process.")
    email_verifier_instance.reset_internal_state_for_run()

    try:
        emails_for_this_run = list(current_verification_state.get("emails_to_verify", []))
        total_emails_for_this_run = len(emails_for_this_run)
        ui_app_batch_size = current_verification_state.get("app_batch_size_for_ui", 20)

        for i in range(0, total_emails_for_this_run, ui_app_batch_size):
            # Critical check at the start of each batch
            with verification_lock:
                stop_requested = current_verification_state.get("stop_requested", False)
                current_run_id = current_verification_state.get("verification_run_id")
                
                if stop_requested or current_run_id != run_id_for_thread:
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Stopping verification. "
                        f"stop_requested={stop_requested}, "
                        f"current_run_id={current_run_id}, "
                        f"thread_run_id={run_id_for_thread}"
                    )
                    
                    if current_run_id == run_id_for_thread:
                        current_verification_state["status"] = "stopped"
                        save_verification_results(run_id_for_thread, is_final_save=True)
                    
                    break
                
                current_verification_state["last_activity_time"] = time.time()
                current_verification_state["current_batch_num"] = (i // ui_app_batch_size) + 1

            batch_to_process_list = emails_for_this_run[i : i + ui_app_batch_size]
            app_logger.info(
                f"Thread (ID: {run_id_for_thread}): Processing batch {current_verification_state['current_batch_num']}/{current_verification_state['total_batches']} ({len(batch_to_process_list)} emails)."
            )
            
            batch_results_list = []
            try:
                batch_results_list = loop.run_until_complete(
                    email_verifier_instance.verify_emails_in_batch(batch_to_process_list)
                )
            except Exception as e_gen:
                app_logger.error(
                    f"Thread (ID: {run_id_for_thread}): General error during batch verification: {e_gen}",
                    exc_info=True,
                )

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

            # Check again before saving batch results
            with verification_lock:
                if current_verification_state.get("verification_run_id") != run_id_for_thread or current_verification_state.get("stop_requested", False):
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Skipping batch results save - run superseded or stop requested"
                    )
                    break

                for result_item in batch_results_list:
                    email_addr = result_item["email"]
                    current_verification_state["results"][email_addr] = result_item
                    current_verification_state["processed_emails"] += 1
                    if result_item.get("is_valid") is True:
                        domain_part = email_addr.split("@")[-1]
                        if result_item.get("is_catchall"):
                            current_verification_state["probable_emails"] += 1
                            current_verification_state["accept_all_domains_summary"][
                                domain_part
                            ] = (
                                current_verification_state[
                                    "accept_all_domains_summary"
                                ].get(domain_part, 0)
                                + 1
                            )
                        else:
                            current_verification_state["valid_emails"] += 1
                    elif result_item.get("is_valid") is False:
                        current_verification_state["invalid_emails"] += 1
                    else:
                        current_verification_state["unknown_emails"] += 1

                    log_status_str = (
                        "success"
                        if result_item.get("is_valid")
                        else ("warning" if result_item.get("is_catchall") else "error")
                    )
                    current_verification_state["verification_log"].append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "status": log_status_str,
                            "action": f"Ověřen email: {email_addr}",
                            "details": f"Výsledek: {result_item.get('status_code', 'N/A')}",
                        }
                    )
                    if len(current_verification_state["verification_log"]) > 100:
                        current_verification_state[
                            "verification_log"
                        ] = current_verification_state["verification_log"][-50:]

                # Save results after each batch
                save_verification_results(run_id_for_thread, is_final_save=False)

        # Final state update after loop completion
        with verification_lock:
            if current_verification_state.get("verification_run_id") == run_id_for_thread:
                if current_verification_state["status"] == "verifying":
                    if current_verification_state["processed_emails"] >= total_emails_for_this_run:
                        current_verification_state["status"] = "completed"
                        app_logger.info(
                            f"Thread (ID: {run_id_for_thread}): Bulk verification process completed successfully."
                        )
                    else:
                        current_verification_state["status"] = "stopped"
                        app_logger.info(
                            f"Thread (ID: {run_id_for_thread}): Bulk verification process was stopped during execution."
                        )
                save_verification_results(run_id_for_thread, is_final_save=True)
            else:
                app_logger.info(
                    f"Thread (ID: {run_id_for_thread}): Run was superseded by a new one. Results for this old run will not be saved centrally by this thread."
                )

    finally:
        # Final thread cleanup
        with verification_lock:
            if (current_verification_state.get("verification_run_id") == run_id_for_thread or 
                not current_verification_state.get("is_thread_active")):
                current_verification_state["is_thread_active"] = False
                app_logger.info(f"Thread (ID: {run_id_for_thread}): Thread cleanup completed.")
        loop.close()


def save_verification_results(run_id_to_save: int, is_final_save: bool = False):
    """
    Ukládá výsledky verifikace do CSV souboru.
    
    Args:
        run_id_to_save (int): ID běhu verifikace pro uložení
        is_final_save (bool): Pokud True, jedná se o finální uložení běhu
    """
    try:
        with verification_lock:
            if current_verification_state["verification_run_id"] != run_id_to_save:
                app_logger.warning(f"Run ID mismatch during save: {run_id_to_save} vs {current_verification_state['verification_run_id']}")
                return

            if not current_verification_state["results"]:
                app_logger.warning("No results to save")
                return

            # Use existing filepath if available, otherwise create new one
            if not current_verification_state["result_filepath"]:
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                result_filepath = Path(app.config["RESULTS_FOLDER"]) / f"verification_results_{timestamp}.csv"
                current_verification_state["result_filepath"] = str(result_filepath)
            else:
                result_filepath = Path(current_verification_state["result_filepath"])

            # Prepare data for CSV
            csv_data = []
            for email, result in current_verification_state["results"].items():
                # Determine status based on is_valid and is_catchall
                status = "unknown"
                if result.get("is_valid") is True:
                    status = "valid" if not result.get("is_catchall") else "catchall"
                elif result.get("is_valid") is False:
                    status = "invalid"

                # Get domain type
                domain_type = "unknown"
                if result.get("domain_type"):
                    domain_type = result.get("domain_type")
                elif result.get("is_disposable"):
                    domain_type = "disposable"

                # Get SMTP response with code
                smtp_response = ""
                if result.get("smtp_response"):
                    smtp_response = result.get("smtp_response")
                if result.get("smtp_code"):
                    code = result.get("smtp_code")
                    if smtp_response:
                        smtp_response = f"{code}: {smtp_response}"
                    else:
                        smtp_response = f"Code: {code}"
                elif result.get("smtp_code_internal"):
                    code = result.get("smtp_code_internal")
                    if smtp_response:
                        smtp_response = f"{code}: {smtp_response}"
                    else:
                        smtp_response = f"Code: {code}"

                # Get DNS records
                dns_records = ""
                if result.get("mx_records"):
                    dns_records = ", ".join(result.get("mx_records"))
                elif result.get("mx_record"):
                    dns_records = result.get("mx_record")

                # Get error message
                error_msg = ""
                if result.get("error"):
                    error_msg = result.get("error")
                elif result.get("message"):
                    error_msg = result.get("message")
                elif result.get("status_code"):
                    error_msg = f"Status: {result.get('status_code')}"

                # Get verification time
                verification_time = ""
                if result.get("verification_time"):
                    verification_time = str(result.get("verification_time"))

                row = {
                    "email": email,
                    "status": status,
                    "error": error_msg,
                    "domain_type": domain_type,
                    "smtp_response": smtp_response,
                    "dns_records": dns_records,
                    "verification_time": verification_time
                }
                csv_data.append(row)

            # Determine if we need to write headers
            write_headers = not result_filepath.exists() or is_final_save

            # Save to CSV with UTF-8-SIG encoding for Excel compatibility
            mode = 'w' if write_headers else 'a'
            with open(result_filepath, mode, newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                if write_headers:
                    writer.writeheader()
                writer.writerows(csv_data)

            app_logger.info(f"Results saved to {result_filepath} ({'final save' if is_final_save else 'incremental save'})")
            add_verification_log("success", "save_results", f"Results saved to {result_filepath}")

    except Exception as e:
        app_logger.error(f"Error saving verification results: {e}", exc_info=True)
        add_verification_log("error", "save_results", str(e))


@app.route("/start_verification", methods=["GET"])
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
        if current_verification_state["status"] not in [
            "ready_to_verify",
            "stopped",
            "completed",
            "error",
            "idle",
        ]:
            app_logger.warning(
                f"API /start_verification: Attempt to start verification in invalid state '{current_verification_state['status']}'."
            )
            return jsonify({"error": "Verifikace již běží nebo není připravena."}), 400
        if not current_verification_state.get("emails_to_verify"):
            app_logger.warning("API /start_verification: No emails found to verify.")
            return (
                jsonify({"error": "Nejprve nahrajte CSV a vyberte sloupec s emaily."}),
                400,
            )

        # Signal old thread to stop if it's still running
        if bulk_verification_thread and bulk_verification_thread.is_alive():
            app_logger.warning(
                "API /start_verification: Old verification thread is still active. Signaling it to stop."
            )
            current_verification_state["stop_requested"] = True
            # Wait briefly for the old thread to notice the stop signal
            time.sleep(0.5)

        # Generate new run ID and reset state
        new_run_id_val = int(time.time() * 1000)
        current_verification_state.update(
            {
                "status": "verifying",
                "error_message": None,
                "processed_emails": 0,
                "valid_emails": 0,
                "invalid_emails": 0,
                "probable_emails": 0,
                "unknown_emails": 0,
                "results": {},
                "verification_log": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "status": "info",
                        "action": "Spuštění verifikace",
                        "details": f"Běh ID: {new_run_id_val}",
                    }
                ],
                "start_time": datetime.now().isoformat(),
                "last_activity_time": time.time(),
                "result_filepath": None,
                "accept_all_domains_summary": {},
                "stop_requested": False,  # Reset stop flag for new run
                "verification_run_id": new_run_id_val,
                "is_thread_active": False,
            }
        )

        app_batch_size_for_ui_calc = app_level_config.get("batch_size", 20)
        current_verification_state["app_batch_size_for_ui"] = app_batch_size_for_ui_calc
        total_emails_count = current_verification_state["total_emails"]
        current_verification_state["total_batches"] = (
            (total_emails_count + app_batch_size_for_ui_calc - 1)
            // app_batch_size_for_ui_calc
            if total_emails_count > 0
            else 0
        )

        app_logger.info(
            f"API /start_verification: Starting new verification run with ID: {new_run_id_val}."
        )
        bulk_verification_thread = threading.Thread(
            target=run_bulk_verification_in_thread,
            name=f"BulkVerifyThread-{new_run_id_val}",
        )
        bulk_verification_thread.daemon = True
        bulk_verification_thread.start()
    return jsonify(
        {
            "status": "verifying",
            "message": "Verifikace byla spuštěna.",
            "run_id": new_run_id_val,
        }
    )


def add_verification_log(status: str, action: str, details: str = None):
    """
    Přidává záznam do logu verifikace.
    
    Args:
        status (str): Status záznamu (success, error, warning, info)
        action (str): Popis akce
        details (str, optional): Detailní informace o akci
    """
    with verification_lock:
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "action": action,
            "details": details
        }
        current_verification_state["verification_log"].append(log_entry)
        if len(current_verification_state["verification_log"]) > 1000:
            current_verification_state["verification_log"] = current_verification_state["verification_log"][-1000:]


def cleanup_old_files(clear_current_state_files_only: bool = False):
    """
    Čistí staré soubory z upload a results složek.
    
    Args:
        clear_current_state_files_only (bool): Pokud True, smaže pouze soubory,
            které nejsou součástí aktuálního stavu verifikace
    """
    try:
        with verification_lock:
            current_files = set()
            if current_verification_state["uploaded_filepath"]:
                current_files.add(Path(current_verification_state["uploaded_filepath"]))
            if current_verification_state["result_filepath"]:
                current_files.add(Path(current_verification_state["result_filepath"]))

            # Clean up uploads folder
            uploads_dir = Path(app.config["UPLOAD_FOLDER"])
            for file_path in uploads_dir.glob("*"):
                if clear_current_state_files_only:
                    if file_path not in current_files:
                        try:
                            file_path.unlink()
                            app_logger.info(f"Deleted old upload file: {file_path}")
                        except Exception as e:
                            app_logger.error(f"Error deleting file {file_path}: {e}")
                else:
                    try:
                        file_path.unlink()
                        app_logger.info(f"Deleted upload file: {file_path}")
                    except Exception as e:
                        app_logger.error(f"Error deleting file {file_path}: {e}")

            # Clean up results folder
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
        cleanup_old_files(clear_current_state_files_only=False)
        reset_verification_state()
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
        with verification_lock:
            log_batch = current_verification_state["verification_log"][-current_verification_state["app_batch_size_for_ui"]:]
            
            return jsonify({
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
                "last_activity_time": current_verification_state["last_activity_time"],
                "result_filepath": current_verification_state["result_filepath"],
                "has_results": bool(current_verification_state["result_filepath"]),
                "verification_log_batch": log_batch
            })
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
    3. Počkání na dokončení aktuální dávky
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
            run_id_at_stop = current_verification_state.get("verification_run_id")
            
            if final_status not in ["verifying", "running"]:
                return jsonify({
                    "status": final_status,
                    "message": "No verification process is currently running",
                    "has_results": bool(current_verification_state["result_filepath"])
                })

            # Set stop flags
            current_verification_state["stop_requested"] = True
            current_verification_state["status"] = "stopping"
            add_verification_log("info", "stop_requested", "Verification stop requested")

        # Wait for the thread to finish (with timeout)
        if bulk_verification_thread and bulk_verification_thread.is_alive():
            bulk_verification_thread.join(timeout=5.0)

        with verification_lock:
            if current_verification_state["verification_run_id"] == run_id_at_stop:
                save_verification_results(run_id_at_stop, is_final_save=True)
                current_verification_state["status"] = "stopped"
                add_verification_log("info", "verification_stopped", "Verification process stopped")

            return jsonify({
                "status": current_verification_state["status"],
                "message": "Verification process stopped",
                "filepath": current_verification_state["result_filepath"],
                "has_results": bool(current_verification_state["result_filepath"])
            })

    except Exception as e:
        app_logger.error(f"Error stopping verification: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Error stopping verification: {str(e)}",
            "has_results": bool(current_verification_state["result_filepath"])
        }), 500


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
            if not current_verification_state["result_filepath"]:
                return jsonify({"error": "No results file available"}), 404

            result_path = Path(current_verification_state["result_filepath"])
            if not result_path.exists():
                return jsonify({"error": "Results file not found"}), 404

            # Security check - ensure file is in RESULTS_FOLDER
            results_folder = Path(app.config["RESULTS_FOLDER"]).resolve()
            result_path = result_path.resolve()
            
            if not str(result_path).startswith(str(results_folder)):
                app_logger.error(f"Security check failed: {result_path} is not in {results_folder}")
                return jsonify({"error": "Invalid file path"}), 403

            # Get the filename from the path
            filename = result_path.name
            
            app_logger.info(f"Sending file for download: {result_path}")
            return send_file(
                result_path,
                mimetype="text/csv",
                as_attachment=True,
                download_name=filename
            )

    except Exception as e:
        app_logger.error(f"Error downloading results: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    host_val = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port_val = int(os.environ.get("FLASK_RUN_PORT", 5001))
    is_debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    app_logger.info(
        f"Starting Flask app on {host_val}:{port_val} with debug_mode={is_debug_mode}"
    )
    
    # Register cleanup on application exit
    import atexit
    atexit.register(lambda: cleanup_old_files(clear_current_state_files_only=True))
    
    app.run(
        debug=is_debug_mode,
        host=host_val,
        port=port_val,
        threaded=True,
        use_reloader=is_debug_mode
    )
