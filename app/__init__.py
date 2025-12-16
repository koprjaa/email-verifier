"""
Project: email-verifier
File: app/__init__.py
Description: Flask application factory that creates and configures the Flask app instance.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import logging
from flask import Flask
from flask_cors import CORS

from app.config import Config
from app.utils.logging import setup_logging
from app.routes import register_routes
from app.models.verification_state import VerificationState
from app.services.verification_service import VerificationService
from app.services.file_service import FileService
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
    
    # Setup CORS
    CORS(app)
    
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
    
    return app

