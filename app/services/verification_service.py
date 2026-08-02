#
# Project: email-verifier
# File:    verification_service.py
#
# Description:
# Runs a verification in the background and reports its progress to the state service.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

import asyncio
import logging
import threading
import time
from datetime import datetime

from verifier.email_verifier import EmailVerifier

logger = logging.getLogger(__name__)


class VerificationService:
    """Service for managing email verification operations."""

    def __init__(self, verifier: EmailVerifier, state, config):
        self.verifier = verifier
        self.state = state
        self.config = config
        self.verification_thread: threading.Thread | None = None

    def verify_single_email(self, email: str):
        """Verify a single email address."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(self.verifier.verify_single_email(email))
        finally:
            loop.close()

    def start_bulk_verification(self):
        """Start bulk verification in a separate thread."""
        with self.state.lock:
            if self.state.get("status") not in [
                "ready_to_verify",
                "stopped",
                "completed",
                "error",
                "idle",
            ]:
                raise ValueError("Verification already running or not ready")

            if not self.state.get("emails_to_verify"):
                raise ValueError("No emails to verify")

            # Signal old thread to stop if still running
            if self.verification_thread and self.verification_thread.is_alive():
                logger.warning("Old verification thread is still active. Signaling it to stop.")
                self.state.set("stop_requested", True)
                time.sleep(0.5)

            # Generate new run ID and reset state
            new_run_id = int(time.time() * 1000)
            self.state.update({
                "status": "verifying",
                "error_message": None,
                "processed_emails": 0,
                "valid_emails": 0,
                "invalid_emails": 0,
                "probable_emails": 0,
                "unknown_emails": 0,
                "results": {},
                "verification_log": [{
                    "timestamp": datetime.now().isoformat(),
                    "status": "info",
                    "action": "Spuštění verifikace",
                    "details": f"Běh ID: {new_run_id}",
                }],
                "start_time": datetime.now().isoformat(),
                "last_activity_time": time.time(),
                "result_filepath": None,
                "accept_all_domains_summary": {},
                "stop_requested": False,
                "verification_run_id": new_run_id,
                "is_thread_active": False,
            })

            # Calculate total batches
            batch_size = self.state.get("app_batch_size_for_ui", 20)
            total_emails = self.state.get("total_emails", 0)
            self.state.set("total_batches", (
                (total_emails + batch_size - 1) // batch_size
                if total_emails > 0 else 0
            ))

            # Start verification thread
            self.verification_thread = threading.Thread(
                target=self._run_bulk_verification,
                name=f"BulkVerifyThread-{new_run_id}",
                daemon=True
            )
            self.verification_thread.start()

            return new_run_id

    def stop_verification(self):
        """Stop running verification."""
        with self.state.lock:
            if self.state.get("status") not in ["verifying", "running"]:
                return False

            run_id = self.state.get("verification_run_id")
            self.state.set("stop_requested", True)
            self.state.set("status", "stopping")
            self._add_log("info", "Požadavek na zastavení",
                         "Verifikace bude zastavena po dokončení aktuální dávky.")

            return run_id

    def _run_bulk_verification(self):
        """Run bulk verification in thread."""
        from app.services.state_service import StateService

        run_id = None
        state_service = StateService(self.state, self.config)
        with self.state.lock:
            run_id = self.state.get("verification_run_id")
            self.state.set("is_thread_active", True)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        logger.info(f"Thread (ID: {run_id}): Starting bulk verification process.")
        self.verifier.reset_internal_state_for_run()

        try:
            emails = list(self.state.get("emails_to_verify", []))
            total_emails = len(emails)
            batch_size = self.state.get("app_batch_size_for_ui", 20)

            for i in range(0, total_emails, batch_size):
                with self.state.lock:
                    if (self.state.get("stop_requested") or
                        self.state.get("verification_run_id") != run_id):
                        if self.state.get("verification_run_id") == run_id:
                            self.state.set("status", "stopped")
                            state_service.save_results(run_id, is_final_save=True)
                        break

                    self.state.set("last_activity_time", time.time())
                    self.state.set("current_batch_num", (i // batch_size) + 1)

                batch = emails[i:i + batch_size]
                logger.info(
                    f"Thread (ID: {run_id}): Processing batch "
                    f"{self.state.get('current_batch_num')}/{self.state.get('total_batches')} "
                    f"({len(batch)} emails)."
                )

                batch_results = []
                try:
                    batch_results = loop.run_until_complete(
                        self.verifier.verify_emails_in_batch(batch)
                    )
                except Exception:
                    logger.exception("Thread (ID: {run_id}): Error during batch verification")

                if not batch_results and batch:
                    batch_results = [{
                        "email": email,
                        "is_valid": None,
                        "status_code": "batch_processing_error",
                        "message": "Error processing batch in verification thread.",
                        "is_catchall": False,
                        "verification_steps": [],
                        "smtp_code_internal": None,
                    } for email in batch]

                with self.state.lock:
                    if (self.state.get("verification_run_id") != run_id or
                        self.state.get("stop_requested")):
                        break

                    state_service.process_batch_results(batch_results)
                    state_service.save_results(run_id, is_final_save=False)

            with self.state.lock:
                if self.state.get("verification_run_id") == run_id:
                    if self.state.get("status") == "verifying":
                        if self.state.get("processed_emails") >= total_emails:
                            self.state.set("status", "completed")
                            logger.info(
                                f"Thread (ID: {run_id}): Bulk verification completed successfully."
                            )
                        else:
                            self.state.set("status", "stopped")
                            logger.info(
                                f"Thread (ID: {run_id}): Bulk verification was stopped."
                            )
                    state_service.save_results(run_id, is_final_save=True)

        finally:
            with self.state.lock:
                if (self.state.get("verification_run_id") == run_id or
                    not self.state.get("is_thread_active")):
                    self.state.set("is_thread_active", False)
                    logger.info(f"Thread (ID: {run_id}): Thread cleanup completed.")
            loop.close()

    def _add_log(self, status: str, action: str, details: str | None = None):
        """Add log entry."""
        with self.state.lock:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "status": status,
                "action": action,
                "details": details,
            }
            self.state["verification_log"].append(log_entry)
            if len(self.state["verification_log"]) > 1000:
                self.state["verification_log"] = self.state["verification_log"][-1000:]

