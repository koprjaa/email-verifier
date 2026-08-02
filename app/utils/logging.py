"""
Project: email-verifier
File: app/utils/logging.py
Description: Configures application-wide logging with formatters and handlers.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import logging


def setup_logging(app):
    """Setup application logging."""
    app_logger = logging.getLogger("flask.app")
    app_logger.setLevel(logging.DEBUG)

    if not app_logger.handlers:
        flask_handler = logging.StreamHandler()
        flask_handler.setLevel(logging.DEBUG)
        flask_formatter = logging.Formatter(
            "%(asctime)s - %(threadName)s - %(levelname)s - %(message)s"
        )
        flask_handler.setFormatter(flask_formatter)
        app_logger.addHandler(flask_handler)

    return app_logger

