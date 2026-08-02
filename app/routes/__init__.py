#
# Project: email-verifier
# File:    __init__.py
#
# Description:
# Registers every blueprint on the application.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

from flask import Flask

from app.routes.file_upload import file_upload_bp
from app.routes.status import status_bp
from app.routes.verification import verification_bp


def register_routes(app: Flask):
    """Register all route blueprints."""
    app.register_blueprint(verification_bp)
    app.register_blueprint(file_upload_bp)
    app.register_blueprint(status_bp)

