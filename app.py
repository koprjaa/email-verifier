# app.py
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

from src.verifier.email_verifier import EmailVerifier

# Create global event loop
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

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
verification_lock = threading.Lock()
bulk_verification_thread = None


def reset_verification_state():
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
        }
        app_logger.info("Global verification state has been reset to 'idle'.")


reset_verification_state()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/verify_single", methods=["POST"])
def verify_single_email_route():
    data = request.json
    email_to_verify = data.get("email")
    if not email_to_verify:
        app_logger.warning("API /verify_single: Missing 'email' in request payload.")
        return jsonify({"error": "Chybí email v požadavku"}), 400
    app_logger.info(
        f"API /verify_single: Received request to verify email: {email_to_verify}"
    )
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


@app.route("/load_csv", methods=["POST"])
def load_csv_route():
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
            
            for enc in encodings_to_try:
                try:
                    app_logger.debug(f"API /load_csv: Trying encoding '{enc}'...")
                    with open(uploaded_filepath, "r", encoding=enc) as f_csv:
                        reader = csv.reader(f_csv)
                        headers = next(reader)
                        detected_encoding = enc
                        app_logger.info(
                            f"API /load_csv: Successfully read CSV with encoding '{enc}'. Headers: {headers}"
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
                    "API /load_csv: Failed to read CSV headers. File might be empty or unsupported encoding."
                )
                return (
                    jsonify(
                        {
                            "error": "Nepodařilo se přečíst CSV soubor. Zkontrolujte kódování a formát."
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
            reader = csv.DictReader(f_csv)
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
    global current_verification_state
    run_id_for_thread = None
    with verification_lock:
        run_id_for_thread = current_verification_state.get("verification_run_id")
        current_verification_state["is_thread_active"] = True

    app_logger.info(
        f"Thread (ID: {run_id_for_thread}): Starting bulk verification process."
    )
    email_verifier_instance.reset_internal_state_for_run()

    emails_for_this_run = list(current_verification_state.get("emails_to_verify", []))
    total_emails_for_this_run = len(emails_for_this_run)
    ui_app_batch_size = current_verification_state.get("app_batch_size_for_ui", 20)

    try:
        for i in range(0, total_emails_for_this_run, ui_app_batch_size):
            batch_to_process_list = emails_for_this_run[i : i + ui_app_batch_size]
            with verification_lock:
                if (
                    current_verification_state.get("stop_requested")
                    or current_verification_state.get("verification_run_id")
                    != run_id_for_thread
                ):
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Stop requested or new run started. Terminating current processing."
                    )
                    current_verification_state["status"] = "stopped"
                    break
                current_verification_state["last_activity_time"] = time.time()
                current_verification_state["current_batch_num"] = (
                    i // ui_app_batch_size
                ) + 1

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

            with verification_lock:
                if (
                    current_verification_state.get("verification_run_id")
                    != run_id_for_thread
                ):
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): New run started while processing batch. Discarding results for this old run's batch."
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

        with verification_lock:
            if current_verification_state.get("verification_run_id") == run_id_for_thread:
                if current_verification_state["status"] == "verifying":
                    current_verification_state["status"] = "completed"
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Bulk verification process completed."
                    )
                elif current_verification_state["status"] == "stopping":
                    current_verification_state["status"] = "stopped"
                    app_logger.info(
                        f"Thread (ID: {run_id_for_thread}): Bulk verification process was stopped during execution."
                    )
                save_verification_results(run_id_for_thread)
            else:
                app_logger.info(
                    f"Thread (ID: {run_id_for_thread}): Run was superseded by a new one. Results for this old run will not be saved centrally by this thread."
                )

            if current_verification_state.get(
                "verification_run_id"
            ) == run_id_for_thread or not current_verification_state.get(
                "is_thread_active"
            ):
                current_verification_state["is_thread_active"] = False
            app_logger.info(f"Thread (ID: {run_id_for_thread}): Terminating execution.")
    finally:
        loop.close()


def save_verification_results(run_id_to_save: int):
    if current_verification_state.get("verification_run_id") != run_id_to_save:
        app_logger.warning(
            f"Attempting to save results for a non-current run (Save ID: {run_id_to_save}, Current ID: {current_verification_state.get('verification_run_id')}). Save operation skipped."
        )
        return
    if not current_verification_state.get("results"):
        app_logger.info(f"No results available to save for run ID: {run_id_to_save}.")
        return

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id_filename_part = str(run_id_to_save) if run_id_to_save else timestamp_str
    result_filename_str = f"verification_results_{run_id_filename_part}.csv"
    result_filepath_obj = Path(app.config["RESULTS_FOLDER"]) / result_filename_str
    try:
        with open(
            result_filepath_obj, "w", newline="", encoding="utf-8-sig"
        ) as f_csv_out:
            fieldnames_list = [
                "Email",
                "Status",
                "Status Kod Verifikatoru",
                "SMTP Odpoved Kod",
                "Zprava",
                "Je Catchall",
                "MX Zaznam",
            ]
            writer_obj = csv.DictWriter(f_csv_out, fieldnames=fieldnames_list)
            writer_obj.writeheader()
            for email_key, result_data_val in current_verification_state.get(
                "results", {}
            ).items():
                status_display_str = "Neznámý"
                is_catchall_display_str = "Ne"
                if result_data_val.get("is_valid") is True:
                    if result_data_val.get("is_catchall"):
                        status_display_str = "Pravděpodobně validní (Catch-all)"
                        is_catchall_display_str = "Ano"
                    else:
                        status_display_str = "Validní"
                elif result_data_val.get("is_valid") is False:
                    status_display_str = "Nevalidní"
                elif result_data_val.get("is_valid") is None:
                    status_display_str = "Neznámý (chyba/timeout)"

                writer_obj.writerow(
                    {
                        "Email": email_key,
                        "Status": status_display_str,
                        "Status Kod Verifikatoru": result_data_val.get(
                            "status_code", "N/A"
                        ),
                        "SMTP Odpoved Kod": result_data_val.get(
                            "smtp_code_internal", "N/A"
                        ),
                        "Zprava": result_data_val.get("message", "N/A"),
                        "Je Catchall": is_catchall_display_str,
                        "MX Zaznam": result_data_val.get("mx_record", "N/A"),
                    }
                )
        current_verification_state["result_filepath"] = str(result_filepath_obj)
        app_logger.info(
            f"Verification results for run ID {run_id_to_save} saved to '{result_filepath_obj}'."
        )
    except Exception as e_save:
        app_logger.error(
            f"Error saving verification results for run ID {run_id_to_save} to CSV: {e_save}",
            exc_info=True,
        )
        current_verification_state[
            "error_message"
        ] = f"Chyba při ukládání výsledků: {str(e_save)}"
        if current_verification_state["status"] not in ["error", "stopped"]:
            current_verification_state["status"] = "error"


@app.route("/start_verification", methods=["GET"])
def start_verification_route():
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

        if bulk_verification_thread and bulk_verification_thread.is_alive():
            app_logger.warning(
                "API /start_verification: Old verification thread is still active. Signaling it to stop."
            )
            current_verification_state["stop_requested"] = True

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
                "stop_requested": False,
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


@app.route("/status", methods=["GET"])
def status_route():
    with verification_lock:
        if (
            current_verification_state.get("is_thread_active")
            and bulk_verification_thread
            and not bulk_verification_thread.is_alive()
            and current_verification_state["status"] == "verifying"
        ):

            current_run_id_status = current_verification_state.get(
                "verification_run_id"
            )
            app_logger.warning(
                f"API /status: Verification thread (ID: {current_run_id_status}, Name: {bulk_verification_thread.name if bulk_verification_thread else 'N/A'}) is no longer alive, but status is 'verifying'. Updating status."
            )

            if (
                current_verification_state["processed_emails"]
                >= current_verification_state["total_emails"]
                and current_verification_state["total_emails"] > 0
            ):
                current_verification_state["status"] = "completed"
                app_logger.info(
                    f"API /status: Status updated to 'completed' for run ID: {current_run_id_status} as all emails processed."
                )
                if not current_verification_state.get("result_filepath"):
                    save_verification_results(current_run_id_status)
            else:
                current_verification_state["status"] = "error"
                current_verification_state[
                    "error_message"
                ] = "Proces verifikace byl neočekávaně ukončen."
                app_logger.error(
                    f"API /status: Status updated to 'error' for run ID: {current_run_id_status}."
                )
            current_verification_state["is_thread_active"] = False

        status_payload_dict = {
            k: v
            for k, v in current_verification_state.items()
            if k not in ["emails_to_verify", "results"]
        }
        accept_all_summary_dict = current_verification_state.get(
            "accept_all_domains_summary", {}
        )
        status_payload_dict["accept_all_details"] = {
            "count": sum(accept_all_summary_dict.values()),
            "domains": [
                {"domain": d, "count": c}
                for d, c in sorted(
                    accept_all_summary_dict.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:10]
            ],
        }
        status_payload_dict["verification_log_batch"] = current_verification_state.get(
            "verification_log", []
        )[-20:]
    return jsonify(status_payload_dict)


@app.route("/stop_verification", methods=["POST"])
def stop_verification_route():
    message_response = "Žádná aktivní verifikace k zastavení."
    final_status_response = current_verification_state.get("status", "idle")

    with verification_lock:
        run_id_to_be_stopped = current_verification_state.get("verification_run_id")
        if (
            current_verification_state["status"] == "verifying"
            and current_verification_state.get("is_thread_active", False)
            and bulk_verification_thread
            and bulk_verification_thread.is_alive()
        ):

            app_logger.info(
                f"API /stop_verification: Received request to stop verification (ID: {run_id_to_be_stopped})."
            )
            current_verification_state["stop_requested"] = True
            current_verification_state["status"] = "stopping"
            message_response = "Požadavek na zastavení odeslán. Čekání na dokončení aktuální dávky a uložení výsledků."
            final_status_response = "stopping"
        elif current_verification_state["status"] == "verifying":
            app_logger.warning(
                f"API /stop_verification: Status is 'verifying' for ID {run_id_to_be_stopped}, but thread is not running or not marked active. Setting status to 'stopped'."
            )
            current_verification_state["status"] = "stopped"
            current_verification_state["stop_requested"] = True
            save_verification_results(run_id_to_be_stopped)
            message_response = "Verifikace byla označena jako zastavená (vlákno pravděpodobně již neběželo)."
            final_status_response = "stopped"
            current_verification_state["is_thread_active"] = False
        else:
            app_logger.info(
                f"API /stop_verification: No running verification found to stop (current status: {current_verification_state['status']})."
            )
            if final_status_response not in ["idle", "error", "completed", "stopped"]:
                message_response = f"Verifikace je ve stavu '{final_status_response}', nelze přímo zastavit."

        filepath_to_return_val = current_verification_state.get("result_filepath")
    return jsonify(
        {
            "status": final_status_response,
            "message": message_response,
            "filepath": filepath_to_return_val,
        }
    )


@app.route("/download", methods=["GET"])
def download_results_route():
    filepath_param_val = request.args.get("filepath")
    if not filepath_param_val:
        app_logger.warning("API /download: Missing 'filepath' query parameter.")
        return jsonify({"error": "Chybí parametr filepath"}), 400

    results_folder_abs_path = Path(app.config["RESULTS_FOLDER"]).resolve()
    requested_file_basename_str = Path(filepath_param_val).name
    requested_file_abs_path = (
        results_folder_abs_path / requested_file_basename_str
    ).resolve()

    if (
        not requested_file_abs_path.is_file()
        or requested_file_abs_path.parent != results_folder_abs_path
    ):
        app_logger.warning(
            f"API /download: Attempt to download invalid or non-existent file: '{filepath_param_val}' (Resolved: '{requested_file_abs_path}')"
        )
        return jsonify({"error": "Soubor nenalezen nebo neplatná cesta"}), 404

    app_logger.info(
        f"API /download: Providing file '{requested_file_abs_path}' for download as '{requested_file_basename_str}'."
    )
    return send_file(
        requested_file_abs_path,
        as_attachment=True,
        download_name=requested_file_basename_str,
    )


if __name__ == "__main__":
    host_val = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port_val = int(os.environ.get("FLASK_RUN_PORT", 5001))
    debug_mode_val = os.environ.get("FLASK_DEBUG", "1") == "1"
    app_logger.info(
        f"Starting Flask app on {host_val}:{port_val} with debug_mode={debug_mode_val}"
    )
    try:
        app.run(debug=debug_mode_val, host=host_val, port=port_val, threaded=True)
    finally:
        loop.close()
