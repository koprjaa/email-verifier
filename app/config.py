#
# Project: email-verifier
# File:    config.py
#
# Description:
# Flask configuration: upload limits, paths, and the verifier defaults.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Config:
    """Application configuration."""

    def __init__(self):
        self.max_content_length = 10 * 1024 * 1024  # 10 MB
        self.upload_folder = "uploads"
        self.results_folder = "results"
        self.flask_run_host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
        self.flask_run_port = int(os.environ.get("FLASK_RUN_PORT", 5001))
        self.flask_debug = os.environ.get("FLASK_DEBUG", "0") == "1"

        # Load from config.json if exists
        self.app_level_config = self._load_config_file()

        # Ensure directories exist
        Path(self.upload_folder).mkdir(exist_ok=True)
        Path(self.results_folder).mkdir(exist_ok=True)

    def _load_config_file(self) -> dict[str, Any]:
        """Load configuration from config.json file."""
        try:
            with Path("config.json").open(encoding="utf-8") as f:
                config = json.load(f)
            logger.info("Main config.json loaded successfully.")
            return config
        except FileNotFoundError:
            logger.warning(
                "Main config.json not found in root. Using default parameters."
            )
            return {}
        except json.JSONDecodeError:
            logger.exception("Error parsing main config.json, using default parameters")
            return {}

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary for Flask app.config."""
        return {
            "MAX_CONTENT_LENGTH": self.max_content_length,
            "UPLOAD_FOLDER": self.upload_folder,
            "RESULTS_FOLDER": self.results_folder,
        }

    def get_verifier_config(self) -> dict[str, Any]:
        """Get configuration for EmailVerifier."""
        config = self.app_level_config.copy()
        # batch_size is managed separately via app_batch_size_for_ui
        if "batch_size" in config:
            del config["batch_size"]
        return config

