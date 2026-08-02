"""
Project: email-verifier
File: app/routes/verification.py
Description: Flask routes for single and bulk email verification operations.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import asyncio
import json
import logging

from flask import Blueprint, current_app, jsonify, request

logger = logging.getLogger(__name__)
verification_bp = Blueprint("verification", __name__)


@verification_bp.route("/")
def index():
    """Main page route."""
    from flask import render_template
    return render_template("index.html")


@verification_bp.route("/verify_single", methods=["POST"])
def verify_single_email():
    """Verify a single email address."""
    data = request.json
    email_to_verify = data.get("email")

    if not email_to_verify:
        logger.warning("API /verify_single: Missing 'email' in request payload.")
        return jsonify({"error": "Chybí email v požadavku"}), 400

    logger.info(f"API /verify_single: Received request to verify email: {email_to_verify}")

    # Get services from app context
    verification_service = current_app.verification_service

    # Flask is synchronous; create new event loop for async email verification
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        logger.info(f"API /verify_single: Starting verification process for {email_to_verify}")
        result = verification_service.verify_single_email(email_to_verify)
        logger.info(
            f"API /verify_single: Verification completed for {email_to_verify}. "
            f"Result: {result.get('status_code')}"
        )
        logger.debug(
            f"API /verify_single: Full verification result: {json.dumps(result, indent=2)}"
        )
        return jsonify(result)
    except Exception:
        logger.exception("API /verify_single: Error during verification of {email_to_verify}")
        return jsonify({"error": "Interní chyba serveru."}), 500
    finally:
        loop.close()


@verification_bp.route("/start_verification", methods=["GET"])
def start_verification():
    """Start bulk email verification."""
    verification_service = current_app.verification_service

    try:
        run_id = verification_service.start_bulk_verification()
        return jsonify({
            "status": "verifying",
            "message": "Verifikace byla spuštěna.",
            "run_id": run_id,
        })
    except ValueError as e:
        logger.warning(f"API /start_verification: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("API /start_verification: Error")
        return jsonify({"error": "Chyba při spuštění verifikace."}), 500


@verification_bp.route("/stop_verification", methods=["POST"])
def stop_verification():
    """Stop running verification."""
    verification_service = current_app.verification_service
    state = current_app.verification_state

    try:
        run_id = verification_service.stop_verification()

        if not run_id:
            return jsonify({
                "status": state.get("status", "idle"),
                "message": "No verification process is currently running",
                "has_results": bool(state.get("result_filepath")),
            })

        # Wait for thread to finish (with timeout)
        if verification_service.verification_thread and verification_service.verification_thread.is_alive():
            verification_service.verification_thread.join(timeout=5.0)

        with state.lock:
            if state.get("verification_run_id") == run_id:
                from app.services.state_service import StateService
                state_service = StateService(state, current_app.config_obj)
                state_service.save_results(run_id, is_final_save=True)
                state.set("status", "stopped")
                state_service._add_log(
                    "info",
                    "Verifikace zastavena",
                    "Proces verifikace byl úspěšně zastaven.",
                )

        return jsonify({
            "status": state.get("status", "stopped"),
            "message": "Verification process stopped",
            "filepath": state.get("result_filepath"),
            "has_results": bool(state.get("result_filepath")),
        })

    except Exception:
        logger.exception("Error stopping verification")
        return jsonify({
            "status": "error",
            "message": "Error stopping verification.",
            "has_results": bool(state.get("result_filepath")),
        }), 500

