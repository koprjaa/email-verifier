#
# Project: email-verifier
# File:    verification_state.py
#
# Description:
# The state of one running verification: progress, results, and the stop flag.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class VerificationState:
    """Manages global verification state with thread-safe access."""

    def __init__(self, default_batch_size: int = 20):
        self._state: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._default_batch_size = default_batch_size
        self.reset()

    def reset(self):
        """Reset state to defaults."""
        with self._lock:
            self._state = {
                "status": "idle",
                "error_message": None,
                "uploaded_filepath": None,
                "selected_column": None,
                "emails_to_verify": [],
                "total_emails": 0,
                "processed_emails": 0,
                "valid_emails": 0,
                "invalid_emails": 0,
                "probable_emails": 0,
                "unknown_emails": 0,
                "current_batch_num": 0,
                "total_batches": 0,
                "results": {},
                "verification_log": [],
                "start_time": None,
                "last_activity_time": None,
                "result_filepath": None,
                "accept_all_domains_summary": {},
                "stop_requested": False,
                "verification_run_id": None,
                "is_thread_active": False,
                "detected_encoding": None,
                "detected_delimiter": None,
                "app_batch_size_for_ui": self._default_batch_size,
            }

    def get(self, key: str, default=None):
        """Get state value."""
        with self._lock:
            return self._state.get(key, default)

    def set(self, key: str, value: Any):
        """Set state value."""
        with self._lock:
            self._state[key] = value

    def update(self, updates: dict[str, Any]):
        """Update multiple state values."""
        with self._lock:
            self._state.update(updates)

    def __getitem__(self, key: str):
        """Get state value using bracket notation."""
        with self._lock:
            return self._state[key]

    def __setitem__(self, key: str, value: Any):
        """Set state value using bracket notation."""
        with self._lock:
            self._state[key] = value

    def __contains__(self, key: str) -> bool:
        """Check if key exists in state."""
        with self._lock:
            return key in self._state

    @property
    def lock(self):
        """Get the lock for manual synchronization."""
        return self._lock

    def to_dict(self) -> dict[str, Any]:
        """Get state as dictionary (for JSON serialization)."""
        with self._lock:
            return self._state.copy()

