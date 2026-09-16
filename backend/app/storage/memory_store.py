"""
VAJRA Forensic Platform - Thread-Safe In-Memory FIFO Case Store
Zero disk writes. Maintains the most recent 25 forensic cases in RAM.
"""

import threading
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any


class MemoryCaseStore:
    """Thread-safe bounded FIFO store for recent forensic email cases."""

    def __init__(self, max_capacity: int = 25) -> None:
        self._max_capacity = max_capacity
        self._lock = threading.Lock()
        self._cases: List[Dict[str, Any]] = []

    def save_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save a new forensic case. Prepends to list; drops oldest when capacity > 25."""
        with self._lock:
            # Ensure unique case_id exists
            if not case_data.get("case_id"):
                date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
                short_id = uuid.uuid4().hex[:6].upper()
                case_data["case_id"] = f"CAS-{date_str}-{short_id}"

            # Ensure UTC timestamp exists
            if not case_data.get("created_at"):
                case_data["created_at"] = datetime.now(timezone.utc).isoformat()

            # Prepend to list (index 0 is most recent)
            self._cases.insert(0, case_data)

            # Enforce FIFO bound (maximum 25 cases)
            while len(self._cases) > self._max_capacity:
                self._cases.pop()

            return case_data

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific forensic case by its unique case_id."""
        clean_id = case_id.strip("\"' ") if case_id else case_id
        with self._lock:
            for case in self._cases:
                if case.get("case_id") == clean_id:
                    # Return a copy to prevent mutation outside the lock
                    return dict(case)
            return None

    def list_recent_cases(self) -> List[Dict[str, Any]]:
        """Return a snapshot of all currently stored cases (most recent first)."""
        with self._lock:
            return [dict(c) for c in self._cases]

    def purge(self) -> int:
        """Purge all stored cases in memory (ephemeral zero-trace wipe). Returns count of purged cases."""
        with self._lock:
            purged_count = len(self._cases)
            self._cases.clear()
            return purged_count

    def clear(self) -> None:
        """Clear all stored cases in memory (useful for test isolation)."""
        with self._lock:
            self._cases.clear()

    @property
    def count(self) -> int:
        """Current number of cases in memory."""
        with self._lock:
            return len(self._cases)


# Global singleton store instance
case_store = MemoryCaseStore(max_capacity=25)


# Module-level convenience functions
def save_case(case_data: Dict[str, Any]) -> Dict[str, Any]:
    return case_store.save_case(case_data)


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    return case_store.get_case(case_id)


def list_recent_cases() -> List[Dict[str, Any]]:
    return case_store.list_recent_cases()


def purge_cases() -> int:
    return case_store.purge()


def clear_store() -> None:
    case_store.clear()
