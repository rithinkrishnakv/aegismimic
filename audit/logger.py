"""
audit/logger.py — Thread-safe NDJSON audit log writer.

One JSON object per line. Compatible with:
  · jq   : jq '.' audit/aegismimic.log
  · grep  : grep UNAUTHORIZED audit/aegismimic.log
  · SIEM  : direct ingest as log stream
"""

import logging
import threading
from pathlib import Path

from audit.event import SecurityEvent

log = logging.getLogger("audit")


class AuditLogger:
    """Appends SecurityEvents as NDJSON to a log file."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._lock    = threading.Lock()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log.info(f"Audit log: {log_path}")

    def record(self, event: SecurityEvent) -> None:
        line = event.to_json()
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError as exc:
                log.error(f"Failed to write audit event: {exc}")
