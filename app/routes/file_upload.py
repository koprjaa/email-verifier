"""
Project: email-verifier
File: app/routes/file_upload.py
Description: Flask routes for CSV/TXT file upload, processing, and result download.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import logging
import os
import time
from pathlib import Path
from flask import Blueprint, jsonify, request, current_app, send_file

from app.services.file_service import FileService

logger = logging.getLogger(__name__)
file_upload_bp = Blueprint("file_upload", __name__)


@file_upload_bp.route("/load_csv", methods=["POST"])
def load_csv():
    """Load and process CSV file."""
    logger.info("=" * 50)
    logger.info("API /load_csv: Starting CSV upload process")
    
    state = current_app.verification_state
    file_service = current_app.file_service
    
    try:
        with state.lock:
            if state.get("status") not in ["idle", "error", "completed", "stopped"]:
                logger.warning(
                    f"API /load_csv: Attempt to load CSV while in state '{state.get('status')}'."
                )
                return jsonify({"error": "Jiná operace již probíhá."}), 400
            
            state.reset()
            state.set("status", "loading_csv")
            state.set("last_activity_time", time.time())
        
        if "file" not in request.files:
            with state.lock:
                state.set("status", "error")
            logger.warning("API /load_csv: No file part in the request.")
            return jsonify({"error": "Soubor nebyl poskytnut"}), 400
        
        file = request.files["file"]
        if file.filename == "":
            with state.lock:
                state.set("status", "error")
            logger.warning("API /load_csv: No file selected.")
            return jsonify({"error": "Nebyl vybrán žádný soubor"}), 400
        
        if not file.filename.lower().endswith(".csv"):
            with state.lock:
                state.set("status", "error")
            logger.warning(f"API /load_csv: Invalid file type '{file.filename}'. Only CSV allowed.")
            return jsonify({"error": "Povoleny jsou pouze CSV soubory"}), 400
        
        try:
            uploaded_filepath = file_service.save_uploaded_file(file)
            
            encoding, delimiter, headers = file_service.detect_csv_encoding_and_delimiter(
                uploaded_filepath
            )
            
            if not headers:
                if uploaded_filepath.exists():
                    os.remove(uploaded_filepath)
                with state.lock:
                    state.set("status", "error")
                logger.error("API /load_csv: Failed to read CSV headers.")
                return jsonify({
                    "error": "Nepodařilo se přečíst CSV soubor. Zkontrolujte kódování a oddělovač sloupců."
                }), 400
            
            suggested_column = file_service.suggest_email_column(headers)
            
            with state.lock:
                state.set("uploaded_filepath", str(uploaded_filepath))
                state.set("status", "selecting_column")
                state.set("detected_encoding", encoding)
                state.set("detected_delimiter", delimiter)
                state.set("last_activity_time", time.time())
            
            return jsonify({
                "status": "select_column",
                "columns": headers,
                "suggested_email_column": suggested_column,
            })
        
        except Exception as e:
            logger.error(f"API /load_csv: Error processing CSV: {str(e)}", exc_info=True)
            if "uploaded_filepath" in locals() and uploaded_filepath.exists():
                os.remove(uploaded_filepath)
            with state.lock:
                state.set("status", "error")
                state.set("error_message", str(e))
            return jsonify({"error": f"Chyba při zpracování CSV: {str(e)}"}), 500
    
    except Exception as e:
        logger.error(f"API /load_csv: Unexpected error: {str(e)}", exc_info=True)
        with state.lock:
            state.set("status", "error")
            state.set("error_message", str(e))
        return jsonify({"error": f"Neočekávaná chyba serveru: {str(e)}"}), 500


@file_upload_bp.route("/load_txt", methods=["POST"])
def load_txt():
    """Load and process TXT file."""
    logger.info("=" * 50)
    logger.info("API /load_txt: Starting TXT upload process")
    
    state = current_app.verification_state
    file_service = current_app.file_service
    
    try:
        with state.lock:
            if state.get("status") not in ["idle", "error", "completed", "stopped"]:
                logger.warning(f"API /load_txt: Attempt to load TXT while in state '{state.get('status')}'.")
                return jsonify({"error": "Jiná operace již probíhá."}), 400
            
            state.reset()
            state.set("status", "loading_txt")
            state.set("last_activity_time", time.time())
        
        if "file" not in request.files:
            with state.lock:
                state.set("status", "error")
            return jsonify({"error": "Soubor nebyl poskytnut"}), 400
        
        file = request.files["file"]
        if file.filename == "":
            with state.lock:
                state.set("status", "error")
            return jsonify({"error": "Nebyl vybrán žádný soubor"}), 400
        
        if not file.filename.lower().endswith('.txt'):
            with state.lock:
                state.set("status", "error")
            return jsonify({"error": "Povoleny jsou pouze TXT soubory"}), 400
        
        try:
            uploaded_filepath = file_service.save_uploaded_file(file, "txt")
            encoding = file_service.detect_txt_encoding(uploaded_filepath)
            
            if not encoding:
                with state.lock:
                    state.set("status", "error")
                os.remove(uploaded_filepath)
                return jsonify({"error": "Nepodařilo se načíst soubor s podporovaným kódováním"}), 400
            
            emails = file_service.extract_emails_from_txt(uploaded_filepath, encoding)
            
            if not emails:
                with state.lock:
                    state.set("status", "error")
                os.remove(uploaded_filepath)
                return jsonify({"error": "V souboru nebyly nalezeny žádné platné emailové adresy"}), 400
            
            with state.lock:
                state.set("uploaded_filepath", str(uploaded_filepath))
                state.set("detected_encoding", encoding)
                state.set("file_type", "txt")
                state.set("emails_list", emails)
                state.set("status", "ready")
                state.set("last_activity_time", time.time())
            
            return jsonify({
                "status": "ready",
                "total_emails": len(emails),
                "sample_emails": emails[:5],
                "file_info": {
                    "filename": file.filename,
                    "encoding": encoding,
                    "size_bytes": uploaded_filepath.stat().st_size
                }
            })
        
        except Exception as e:
            logger.error(f"API /load_txt: Error processing TXT: {str(e)}", exc_info=True)
            if "uploaded_filepath" in locals() and uploaded_filepath.exists():
                os.remove(uploaded_filepath)
            with state.lock:
                state.set("status", "error")
                state.set("error_message", str(e))
            return jsonify({"error": f"Chyba při zpracování TXT: {str(e)}"}), 500
    
    except Exception as e:
        logger.error(f"API /load_txt: Unexpected error: {str(e)}", exc_info=True)
        with state.lock:
            state.set("status", "error")
            state.set("error_message", str(e))
        return jsonify({"error": f"Chyba při zpracování TXT: {str(e)}"}), 500


@file_upload_bp.route("/select_column", methods=["POST"])
def select_column():
    """Select column from CSV or use TXT emails."""
    
    state = current_app.verification_state
    file_service = current_app.file_service
    
    with state.lock:
        if state.get("status") not in ["selecting_column", "ready"]:
            logger.warning(f"API /select_column: Invalid state '{state.get('status')}'.")
            return jsonify({"error": "Neplatný stav pro výběr sloupce."}), 400
        state.set("last_activity_time", time.time())
    
    uploaded_filepath_str = state.get("uploaded_filepath")
    file_type = state.get("file_type", "csv")
    
    if not uploaded_filepath_str or not Path(uploaded_filepath_str).exists():
        return jsonify({"error": "Nejprve nahrajte soubor"}), 400
    
    if file_type == "txt":
        emails_list = state.get("emails_list", [])
        if not emails_list:
            return jsonify({"error": "V TXT souboru nebyly nalezeny žádné emaily"}), 400
        
        unique_emails = emails_list
        logger.info(f"API /select_column: Using {len(unique_emails)} emails from TXT file")
    else:
        data = request.json
        selected_column = data.get("column")
        if not selected_column:
            return jsonify({"error": "Nebyl vybrán žádný sloupec"}), 400
        
        try:
            unique_emails = file_service.extract_emails_from_csv(
                Path(uploaded_filepath_str),
                selected_column,
                state.get("detected_encoding", "utf-8"),
                state.get("detected_delimiter", ";")
            )
            
            if not unique_emails:
                with state.lock:
                    state.set("status", "error")
                return jsonify({
                    "error": f"Ve sloupci '{selected_column}' nebyly nalezeny žádné platné emailové adresy."
                }), 400
            
            with state.lock:
                state.set("selected_column", selected_column)
        
        except Exception as e:
            with state.lock:
                state.set("status", "error")
                state.set("error_message", str(e))
            logger.error(f"API /select_column: Error extracting emails: {e}", exc_info=True)
            return jsonify({"error": f"Chyba při extrakci emailů z CSV: {str(e)}"}), 500
    
    if not unique_emails:
        with state.lock:
            state.set("status", "error")
        return jsonify({"error": "Nebyly nalezeny žádné platné emailové adresy."}), 400
    
    with state.lock:
        state.set("emails_to_verify", unique_emails)
        state.set("total_emails", len(unique_emails))
        state.set("status", "ready_to_verify")
        state.set("last_activity_time", time.time())
    
    logger.info(f"API /select_column: Prepared {len(unique_emails)} emails for verification")
    return jsonify({"status": "ready", "total_emails": len(unique_emails)})


@file_upload_bp.route("/download_results", methods=["GET"])
def download_results():
    """Download verification results CSV file."""
    state = current_app.verification_state
    
    try:
        with state.lock:
            if not state.get("result_filepath"):
                return jsonify({"error": "No results file available"}), 404
            
            result_path = Path(state.get("result_filepath"))
            if not result_path.exists():
                return jsonify({"error": "Results file not found"}), 404
            
            # Security check: ensure file is in RESULTS_FOLDER
            results_folder = Path(current_app.config["RESULTS_FOLDER"]).resolve()
            result_path_resolved = result_path.resolve()
            
            if not str(result_path_resolved).startswith(str(results_folder)):
                logger.error(
                    f"Security check failed: {result_path_resolved} is not in {results_folder}"
                )
                return jsonify({"error": "Invalid file path"}), 403
            
            filename = result_path.name
            logger.info(f"Sending file for download: {result_path}")
            return send_file(
                result_path,
                mimetype="text/csv",
                as_attachment=True,
                download_name=filename,
            )
    
    except Exception as e:
        logger.error(f"Error downloading results: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

