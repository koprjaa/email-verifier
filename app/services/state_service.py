"""
Project: email-verifier
File: app/services/state_service.py
Description: Service for managing verification state updates and CSV result file generation.
Author: Jan Alexandr Kopřiva jan.alexandr.kopriva@gmail.com
License: MIT
"""
import csv
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class StateService:
    """Service for managing verification state and results."""

    def __init__(self, state, config):
        self.state = state
        self.config = config

    def process_batch_results(self, batch_results: list):
        """Process batch verification results and update statistics."""
        for result_item in batch_results:
            email_addr = result_item["email"]
            self.state["results"][email_addr] = result_item
            self.state["processed_emails"] = self.state.get("processed_emails", 0) + 1

            if result_item.get("is_valid") is True:
                domain_part = email_addr.split("@")[-1]
                if result_item.get("is_catchall"):
                    self.state["probable_emails"] = self.state.get("probable_emails", 0) + 1
                    summary = self.state.get("accept_all_domains_summary", {})
                    summary[domain_part] = summary.get(domain_part, 0) + 1
                    self.state["accept_all_domains_summary"] = summary
                else:
                    self.state["valid_emails"] = self.state.get("valid_emails", 0) + 1
            elif result_item.get("is_valid") is False:
                self.state["invalid_emails"] = self.state.get("invalid_emails", 0) + 1
            else:
                self.state["unknown_emails"] = self.state.get("unknown_emails", 0) + 1

            log_status = (
                "success" if result_item.get("is_valid")
                else ("warning" if result_item.get("is_catchall") else "error")
            )
            self.state["verification_log"].append({
                "timestamp": datetime.now().isoformat(),
                "status": log_status,
                "action": f"Ověřen email: {email_addr}",
                "details": f"Výsledek: {result_item.get('status_code', 'N/A')}",
            })

            # Keep log size manageable
            if len(self.state["verification_log"]) > 100:
                self.state["verification_log"] = self.state["verification_log"][-50:]

    def save_results(self, run_id: int, is_final_save: bool = False):
        """Save verification results to CSV file."""
        try:
            with self.state.lock:
                if self.state.get("verification_run_id") != run_id:
                    logger.warning(
                        f"Run ID mismatch during save: {run_id} vs {self.state.get('verification_run_id')}"
                    )
                    return

                if not self.state.get("results"):
                    logger.warning("No results to save")
                    return

                if not self.state.get("result_filepath"):
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    result_filepath = (
                        Path(self.config.results_folder)
                        / f"verification_results_{timestamp}.csv"
                    )
                    self.state.set("result_filepath", str(result_filepath))
                else:
                    result_filepath = Path(self.state.get("result_filepath"))

                csv_data = []
                for email, result in self.state.get("results", {}).items():
                    status = "unknown"
                    if result.get("is_valid") is True:
                        status = "valid" if not result.get("is_catchall") else "catchall"
                    elif result.get("is_valid") is False:
                        status = "invalid"

                    domain_type = "unknown"
                    if result.get("domain_type"):
                        domain_type = result.get("domain_type")
                    elif result.get("is_disposable"):
                        domain_type = "disposable"

                    # Handle both old and new result key names
                    smtp_response = ""
                    if result.get("smtp_response"):
                        smtp_response = result.get("smtp_response")
                    if result.get("smtp_code"):
                        code = result.get("smtp_code")
                        smtp_response = f"{code}: {smtp_response}" if smtp_response else f"Code: {code}"
                    elif result.get("smtp_code_internal"):
                        code = result.get("smtp_code_internal")
                        if smtp_response:
                            smtp_response = f"{code}: {smtp_response}"
                        elif result.get("message"):
                            smtp_response = f"{code}: {result.get('message')}"
                        else:
                            smtp_response = f"Code: {code}"

                    dns_records = ""
                    if result.get("mx_records"):
                        dns_records = ", ".join(
                            [host for prio, host in result.get("mx_records", [])]
                        )
                    elif result.get("mx_record"):
                        dns_records = result.get("mx_record")

                    error_msg = ""
                    if result.get("error"):
                        error_msg = result.get("error")
                    elif result.get("message"):
                        error_msg = result.get("message")
                    elif result.get("status_code"):
                        error_msg = f"Status: {result.get('status_code')}"

                    verification_time = ""
                    if result.get("verification_time"):
                        verification_time = str(result.get("verification_time"))

                    row = {
                        "email": email,
                        "status": status,
                        "error_details": error_msg,
                        "domain_type": domain_type,
                        "smtp_response_full": smtp_response,
                        "mx_servers": dns_records,
                        "verification_duration_ms": verification_time,
                        "raw_status_code": result.get("status_code"),
                        "is_catchall_domain": result.get("is_catchall", False),
                        "smtp_internal_code": result.get("smtp_code_internal"),
                    }
                    csv_data.append(row)

                if not csv_data:
                    logger.warning("No data to write to CSV")
                    return

                write_headers = not result_filepath.exists() or is_final_save
                mode = "w" if write_headers else "a"

                with Path(result_filepath).open(mode, newline="", encoding="utf-8-sig") as f:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    if write_headers:
                        writer.writeheader()
                    writer.writerows(csv_data)

                logger.info(
                    f"Results saved to {result_filepath} "
                    f"({'final save' if is_final_save else 'incremental save'})"
                )

                if self.state.get("verification_run_id") == run_id:
                    self._add_log(
                        "success",
                        "Uložení výsledků",
                        f"Výsledky uloženy do {result_filepath.name}",
                    )

        except Exception as e:
            logger.exception("Error saving verification results")
            if self.state.get("verification_run_id") == run_id:
                self._add_log("error", "Chyba při uložení výsledků", str(e))

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

