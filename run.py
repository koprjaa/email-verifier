"""
Project: email-verifier
File: run.py
Description: Application entry point that initializes Flask app and handles cleanup on exit.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import atexit
import logging

from app import create_app

logger = logging.getLogger(__name__)

app = create_app()

# Clean up unused files on exit
atexit.register(
    lambda: app.file_service.cleanup_files(clear_current_state_only=True)
)

if __name__ == "__main__":
    app.run(
        debug=app.config_obj.flask_debug,
        host=app.config_obj.flask_run_host,
        port=app.config_obj.flask_run_port,
        threaded=True,
        use_reloader=app.config_obj.flask_debug,
    )

