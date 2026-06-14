"""
core/snapshot.py — Forensic process snapshot captured BEFORE kill.

Once a process is SIGKILLed, all its /proc entries vanish instantly.
By capturing everything first, we preserve evidence for post-incident analysis:

  · Full environment variables (may reveal C2 URLs, staging paths)
  · Memory maps (shared libraries loaded, injected regions)
  · Network connections (active TCP/UDP sockets at time of kill)
  · Open file descriptors (which files it had open beyond our trap)
  · Process status and resource usage

Snapshots are saved as pretty-printed JSON:
  <snapshot_dir>/aegismimic_snap_<pid>_<timestamp>.json
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("snapshot")


class SnapshotManager:
    """Captures /proc state of a process and saves it to disk."""

    def __init__(self, snapshot_dir: Optional[Path]):
        self.snapshot_dir = snapshot_dir

    def capture(self, pid: int, proc_info) -> Path:
        """
        Read everything we can from /proc/<pid>/ and save to a JSON file.
        Returns the path of the saved snapshot.
        Raises OSError if the snapshot directory is not writable.
        """
        ts       = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        filename = f"aegismimic_snap_{pid}_{ts}.json"
        out_path = self.snapshot_dir / filename

        snapshot = {
            "aegismimic_version": "1.0.0",
            "captured_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note":         "Captured immediately before SIGTERM — process still alive at capture time.",
            "process": {
                "pid":          pid,
                "exe":          proc_info.exe,
                "ppid":         proc_info.ppid,
                "parent_exe":   proc_info.parent_exe,
                "cmdline":      proc_info.cmdline,
                "username":     proc_info.username,
                "open_fd_count": proc_info.open_fd_count,
                "open_paths":   proc_info.open_paths,
                "start_time":   proc_info.start_time,
            },
            "environ":   self._read_environ(pid),
            "status":    self._read_status(pid),
            "maps":      self._read_maps(pid),
            "net_tcp":   self._read_net(pid, "tcp"),
            "net_tcp6":  self._read_net(pid, "tcp6"),
            "net_udp":   self._read_net(pid, "udp"),
            "io":        self._read_io(pid),
        }

        out_path.write_text(json.dumps(snapshot, indent=2, default=str))
        log.info(f"Forensic snapshot saved: {out_path}")
        return out_path

    # ──────────────────────────────────────────────────────────────────
    #  /proc readers
    # ──────────────────────────────────────────────────────────────────

    def _read_environ(self, pid: int) -> Dict[str, str]:
        """
        Parse /proc/<pid>/environ — null-byte-separated KEY=VALUE pairs.
        May reveal: C2 URLs in env vars, staging paths, injected credentials.
        """
        try:
            raw   = Path(f"/proc/{pid}/environ").read_bytes()
            pairs = raw.decode("utf-8", errors="replace").split("\x00")
            result: Dict[str, str] = {}
            for pair in pairs:
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    result[k] = v
            return result
        except OSError:
            return {}

    def _read_status(self, pid: int) -> Dict[str, str]:
        """
        Parse /proc/<pid>/status — key-value process metadata including
        UID/GID, memory usage (VmRSS, VmPeak), thread count, and capabilities.
        """
        try:
            text   = Path(f"/proc/{pid}/status").read_text()
            result: Dict[str, str] = {}
            for line in text.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    result[k.strip()] = v.strip()
            return result
        except OSError:
            return {}

    def _read_maps(self, pid: int) -> List[str]:
        """
        Read /proc/<pid>/maps — memory map of all mapped regions.
        Reveals loaded shared libraries, injected code regions, and
        anonymous mappings that may represent shellcode.
        Capped at 200 lines.
        """
        try:
            lines = Path(f"/proc/{pid}/maps").read_text(errors="replace").splitlines()
            return lines[:200]
        except OSError:
            return []

    def _read_net(self, pid: int, proto: str) -> List[str]:
        """
        Read network socket table for the given protocol (tcp/tcp6/udp).
        Shows active connections at the time of capture — reveals C2 channels.
        Falls back to global /proc/net/<proto> if per-process path unavailable.
        """
        try:
            # Try per-process network namespace first
            path = Path(f"/proc/{pid}/net/{proto}")
            if not path.exists():
                path = Path(f"/proc/net/{proto}")
            return path.read_text().splitlines()[:100]
        except OSError:
            return []

    def _read_io(self, pid: int) -> Dict[str, str]:
        """
        Read /proc/<pid>/io — I/O byte counters.
        Shows how much data the process read/wrote — useful for estimating
        exfiltration volume.
        """
        try:
            text   = Path(f"/proc/{pid}/io").read_text()
            result: Dict[str, str] = {}
            for line in text.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    result[k.strip()] = v.strip()
            return result
        except OSError:
            return {}
