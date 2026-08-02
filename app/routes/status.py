"""
Project: email-verifier
File: app/routes/status.py
Description: Flask routes for checking verification status and performing cleanup operations.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import logging

from flask import Blueprint, current_app, jsonify

logger = logging.getLogger(__name__)
status_bp = Blueprint("status", __name__)


@status_bp.route("/status", methods=["GET"])
def get_status():
    """Returns current verification status and statistics."""
    state = current_app.verification_state

    try:
        with state.lock:
            log_batch = state.get("verification_log", [])[
                -state.get("app_batch_size_for_ui", 20) :
            ]

            return jsonify({
                "status": state.get("status"),
                "error_message": state.get("error_message"),
                "total_emails": state.get("total_emails"),
                "processed_emails": state.get("processed_emails"),
                "valid_emails": state.get("valid_emails"),
                "invalid_emails": state.get("invalid_emails"),
                "probable_emails": state.get("probable_emails"),
                "unknown_emails": state.get("unknown_emails"),
                "current_batch": state.get("current_batch_num"),
                "total_batches": state.get("total_batches"),
                "start_time": state.get("start_time"),
                "last_activity_time": state.get("last_activity_time"),
                "result_filepath": state.get("result_filepath"),
                "has_results": bool(state.get("result_filepath")),
                "verification_log_batch": log_batch,
            })
    except Exception:
        logger.exception("Error getting status")
        return jsonify({"error": "Chyba při získávání stavu."}), 500


@status_bp.route("/cleanup", methods=["POST"])
def cleanup():
    """Cleans old files and resets verification state."""
    state = current_app.verification_state
    file_service = current_app.file_service

    try:
        file_service.cleanup_files(clear_current_state_only=False)
        state.reset()
        return jsonify({"status": "success", "message": "Cleanup completed"})
    except Exception:
        logger.exception("Error during cleanup")
        return jsonify({"error": "Chyba při čištění."}), 500

