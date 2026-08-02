#
# Project: email-verifier
# File:    file_service.py
#
# Description:
# Reads an uploaded address list: encoding detection, CSV parsing, and cleanup of old uploads.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

import csv
import logging
import re
import time
from datetime import datetime
from pathlib import Path

from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)


class FileService:
    """Service for processing uploaded files."""

    def __init__(self, config, state):
        self.config = config
        self.state = state

    def save_uploaded_file(self, file, file_type: str = "csv") -> Path:
        """Save uploaded file with timestamp prefix."""
        filename = secure_filename(file.filename)
        uploaded_filepath = (
            Path(self.config.upload_folder)
            / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        )

        logger.info(f"Saving file to: {uploaded_filepath}")

        # Chunked read/write for large files
        chunk_size = 8192
        total_size = 0
        chunk_count = 0
        start_time = time.time()

        with Path(uploaded_filepath).open("wb") as f:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                total_size += len(chunk)
                chunk_count += 1
                if chunk_count % 100 == 0:
                    elapsed = time.time() - start_time
                    speed = total_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
                    logger.info(
                        f"Progress - {total_size/1024:.1f}KB written, {speed:.1f}MB/s"
                    )

        if not uploaded_filepath.exists():
            raise OSError(f"File was not saved correctly at {uploaded_filepath}")

        file_size = uploaded_filepath.stat().st_size
        if file_size == 0:
            raise ValueError("Uploaded file is empty")

        return uploaded_filepath

    def detect_csv_encoding_and_delimiter(
        self, filepath: Path
    ) -> tuple[str | None, str | None, list[str]]:
        """Detect CSV encoding, delimiter, and read headers."""
        encodings_to_try = [
            "utf-8-sig",
            "utf-8",
            "cp1250",
            "iso-8859-2",
            "windows-1250",
        ]
        delimiters = [",", ";", "\t", "|"]

        detected_encoding = None
        detected_delimiter = None
        headers = []

        for enc in encodings_to_try:
            try:
                with Path(filepath).open(encoding=enc) as f_csv:
                    first_line = f_csv.readline().strip()

                    for delimiter in delimiters:
                        if delimiter in first_line:
                            parts = first_line.split(delimiter)
                            if len(parts) > 1:
                                detected_delimiter = delimiter
                                break

                    if detected_delimiter:
                        f_csv.seek(0)
                        reader = csv.reader(f_csv, delimiter=detected_delimiter)
                        headers = next(reader)
                        detected_encoding = enc
                        logger.info(
                            f"Detected encoding '{enc}' and delimiter '{detected_delimiter}'. "
                            f"Headers: {headers}"
                        )
                        break
            except (UnicodeDecodeError, StopIteration):
                continue
            except Exception:
                logger.exception("Error trying encoding '{enc}'")
                continue

        return detected_encoding, detected_delimiter, headers

    def suggest_email_column(self, headers: list[str]) -> str | None:
        """Suggest email column from headers."""
        common_email_headers = [
            "email",
            "e-mail",
            "mail",
            "emailaddress",
        ]

        for header_item in headers:
            normalized_header = (
                header_item.lower().replace(" ", "").replace("_", "")
            )
            if normalized_header in common_email_headers:
                logger.info(f"Found suggested email column: {header_item}")
                return header_item

        if headers:
            logger.info(f"No email column found, using first column: {headers[0]}")
            return headers[0]

        return None

    def extract_emails_from_csv(
        self, filepath: Path, column: str, encoding: str, delimiter: str
    ) -> list[str]:
        """Extract emails from CSV column."""
        emails = []
        with Path(filepath).open(encoding=encoding) as f_csv:
            reader = csv.DictReader(f_csv, delimiter=delimiter)
            if column not in reader.fieldnames:
                raise ValueError(f"Column '{column}' not found in CSV")

            for row in reader:
                email_value = row.get(column, "").strip()
                if email_value:
                    emails.append(email_value)

        # Remove duplicates while preserving order
        return list(dict.fromkeys(emails))

    def extract_emails_from_txt(self, filepath: Path, encoding: str) -> list[str]:
        """Extract emails from TXT file."""
        with Path(filepath).open(encoding=encoding) as f:
            file_content = f.read()

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        lines = file_content.splitlines()
        emails_found = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Handle lines with multiple emails separated by delimiters
            if any(sep in line for sep in [',', ';', '|', '\t']):
                for sep in [',', ';', '|', '\t']:
                    if sep in line:
                        parts = line.split(sep)
                        for part in parts:
                            part = part.strip()
                            if re.match(email_pattern, part):
                                emails_found.append(part)
                        break
            else:
                matches = re.findall(email_pattern, line)
                emails_found.extend(matches)

        # Remove duplicates while preserving order
        return list(dict.fromkeys([email.strip() for email in emails_found if email.strip()]))

    def detect_txt_encoding(self, filepath: Path) -> str | None:
        """Detect TXT file encoding."""
        encodings_to_try = [
            "utf-8-sig",
            "utf-8",
            "cp1250",
            "iso-8859-2",
            "windows-1250",
        ]

        for enc in encodings_to_try:
            try:
                with Path(filepath).open(encoding=enc) as f:
                    f.read()
                return enc
            except UnicodeDecodeError:
                continue

        return None

    def cleanup_files(self, clear_current_state_only: bool = False):
        """Clean up old files from uploads and results folders."""
        with self.state.lock:
            current_files = set()
            if self.state.get("uploaded_filepath"):
                current_files.add(Path(self.state.get("uploaded_filepath")))
            if self.state.get("result_filepath"):
                current_files.add(Path(self.state.get("result_filepath")))

            # Clean uploads folder
            uploads_dir = Path(self.config.upload_folder)
            for file_path in uploads_dir.glob("*"):
                if clear_current_state_only:
                    if file_path not in current_files:
                        try:
                            file_path.unlink()
                            logger.info(f"Deleted old upload file: {file_path}")
                        except Exception:
                            logger.exception("Error deleting file {file_path}")
                else:
                    try:
                        file_path.unlink()
                        logger.info(f"Deleted upload file: {file_path}")
                    except Exception:
                        logger.exception("Error deleting file {file_path}")

            # Clean results folder
            results_dir = Path(self.config.results_folder)
            for file_path in results_dir.glob("*"):
                if clear_current_state_only:
                    if file_path not in current_files:
                        try:
                            file_path.unlink()
                            logger.info(f"Deleted old result file: {file_path}")
                        except Exception:
                            logger.exception("Error deleting file {file_path}")
                else:
                    try:
                        file_path.unlink()
                        logger.info(f"Deleted result file: {file_path}")
                    except Exception:
                        logger.exception("Error deleting file {file_path}")

