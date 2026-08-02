#
# Project: email-verifier
# File:    __init__.py
#
# Description:
# Builds the Flask application: configuration, logging, and route registration.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

import hmac
import logging
import os

from flask import Flask

from app.config import Config
from app.models.verification_state import VerificationState
from app.routes import register_routes
from app.services.file_service import FileService
from app.services.verification_service import VerificationService
from app.utils.logging import setup_logging
from verifier.email_verifier import EmailVerifier

logger = logging.getLogger(__name__)


def create_app(config=None):
    """Create and configure Flask application."""
    app = Flask(__name__, template_folder="templates")

    # Load configuration
    app_config = Config()
    app.config_obj = app_config  # Store config object for services
    if config:
        app.config.update(config)
    else:
        app.config.update(app_config.to_dict())

    # CORS intentionally not enabled: this is a same-origin local app.
    # (Previously `CORS(app)` opened all origins — removed for security.)


    # Setup logging
    setup_logging(app)

    # Initialize verification state
    default_batch_size = app_config.app_level_config.get("ui_batch_size", 20)
    app.verification_state = VerificationState(default_batch_size=default_batch_size)

    # Initialize EmailVerifier
    verifier_config = app_config.get_verifier_config()
    app_logger = logging.getLogger("flask.app")
    app.email_verifier = EmailVerifier(
        timeout=verifier_config.get("timeout", 15),
        smtp_timeout=verifier_config.get("smtp_timeout", 10),
        dns_timeout=verifier_config.get("dns_timeout", 5),
        catchall_test_enabled=verifier_config.get(
            "catchall_test", verifier_config.get("check_catchall", True)
        ),
        check_disposable_enabled=verifier_config.get("check_disposable", True),
        connect_port=verifier_config.get("connect_port", 25),
        rate_limit_delay_base=verifier_config.get("rate_limit_delay", 2.0),
        max_concurrent_domains=verifier_config.get("max_concurrent_domains", 5),
        helo_hostname=verifier_config.get("helo_hostname", None),
        retry_attempts=verifier_config.get("retry_attempts", 2),
        retry_delay_base=verifier_config.get("retry_delay", 5.0),
        disposable_domains_file=verifier_config.get(
            "disposable_domains_file_path", "data/disposable_domains.txt"
        ),
        logger=app_logger,
        dns_servers=verifier_config.get("dns_servers", None),
        sender_email_override=verifier_config.get("sender_email_override", None),
        default_sender_email_config=verifier_config.get("sender_emails", {}).get("default"),
        sender_emails_by_domain_config={
            k: v
            for k, v in verifier_config.get("sender_emails", {}).items()
            if k != "default"
        },
    )
    app_logger.info("Global EmailVerifier instance created and configured.")

    # Initialize services
    app.verification_service = VerificationService(
        app.email_verifier, app.verification_state, app_config
    )
    app.file_service = FileService(app_config, app.verification_state)

    # Register routes
    register_routes(app)

    # Optional shared-token auth. Fail-open by design: enforced ONLY when the
    # EMAIL_VERIFIER_TOKEN env var is set, so the default local UX is unchanged.
    # When set, every request must present the token via the
    # 'X-Auth-Token' header or '?token=' query param. The index page and static
    # assets are exempt so the UI can load and prompt the user.
    auth_token = os.environ.get("EMAIL_VERIFIER_TOKEN")
    if auth_token:
        app_logger.info("EMAIL_VERIFIER_TOKEN set: shared-token auth enabled.")

        @app.before_request
        def _require_token():
            from flask import jsonify, request

            if request.endpoint in ("static", "verification.index"):
                return None
            if request.path == "/":
                return None
            provided = request.headers.get("X-Auth-Token") or request.args.get("token")
            if not provided or not hmac.compare_digest(provided, auth_token):
                return jsonify({"error": "Unauthorized"}), 401
            return None

    return app

