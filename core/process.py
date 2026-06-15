"""
core/process.py — Linux /proc-based process inspection.

The central challenge: inotify gives you the file and the event type,
but NOT the PID of the accessor. To resolve it, we exploit the fact
that Linux exposes every process's open file descriptors under
/proc/<pid>/fd/, each as a symlink to the actual file path.

We iterate all living PIDs, resolve each FD symlink, and look for
any that point into our watched directory.

Complexity: O(n_pids × n_fds) — fast in practice because:
  · Most processes have < 20 open FDs
  · We abort per-PID on first matching FD
  · We only run on inotify events, not in a continuous loop
"""

import os
import pwd
import time
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Tuple

log = logging.getLogger("process")


@dataclass
class ProcessInfo:
    pid: int
    exe: str                    # Resolved binary path (/proc/<pid>/exe)
    ppid: int                   # Parent PID
    parent_exe: str             # Parent's binary path
    cmdline: List[str]          # Full argv (/proc/<pid>/cmdline)
    username: str               # Owning user (resolved from UID)
    open_fd_count: int          # Total open file descriptors
    open_paths: List[str]       # Resolved non-socket FD paths (capped at 50)
    start_time: float           # Process start time in clock ticks / HZ


class ProcessInspector:

    # ──────────────────────────────────────────────────────────────────
    #  Primary: find PIDs with open FDs into watch_path
    # ──────────────────────────────────────────────────────────────────

    def find_pids_with_open_path(self, watch_path: str) -> List[int]:
        """
        Scan /proc to find all processes that currently hold an open
        file descriptor pointing into watch_path.

        Returns a list of matching PIDs. Empty list = no match found.
        """
        watch_path = os.path.realpath(watch_path)
        matches: List[int] = []

        for pid in self._enumerate_pids():
            try:
                fd_dir = Path(f"/proc/{pid}/fd")
                if not fd_dir.exists():
                    continue

                for fd_entry in fd_dir.iterdir():
                    try:
                        resolved = os.readlink(str(fd_entry))
                        if resolved.startswith(watch_path):
                            matches.append(pid)
                            break  # One match per PID is enough
                    except (OSError, PermissionError):
                        continue

            except (PermissionError, ProcessLookupError, FileNotFoundError):
                continue

        return matches

    # ──────────────────────────────────────────────────────────────────
    #  Fallback: find recent accessors via /proc/*/maps + birth time
    # ──────────────────────────────────────────────────────────────────

    def find_recent_accessors(self, watch_path: str, window_seconds: float = 5.0) -> List[int]:
        """
        For transient accessors that already closed their FD by the time
        we finish scanning, look for processes that:
          (a) memory-mapped a file from our directory (/proc/<pid>/maps)
          (b) were born very recently (within window_seconds of uptime)

        This is best-effort — truly instantaneous reads (< 1ms) may still
        be missed without kernel-level hooks like fanotify or eBPF.
        """
        watch_path = os.path.realpath(watch_path)
        matches: List[int] = []
        uptime = self._get_system_uptime()
        hz = self._get_clock_hz()

        for pid in self._enumerate_pids():
            try:
                # Check memory maps for files from our directory
                maps_path = Path(f"/proc/{pid}/maps")
                if maps_path.exists():
                    content = maps_path.read_text(errors="replace")
                    if watch_path in content:
                        matches.append(pid)
                        continue

                # Check process age — newborns are suspicious in context
                stat_path = Path(f"/proc/{pid}/stat")
                if stat_path.exists():
                    stat_raw = stat_path.read_text()
                    rparen = stat_raw.rfind(")")
                    fields = stat_raw[rparen + 2:].split()
                    if len(fields) > 19:
                        start_ticks = int(fields[19])
                        process_age = uptime - (start_ticks / hz)
                        if 0 <= process_age < window_seconds:
                            exe = self._read_exe(pid)
                            log.debug(
                                f"Young process (age {process_age:.2f}s): "
                                f"PID {pid} → {exe}"
                            )

            except (PermissionError, FileNotFoundError, ValueError, OSError):
                continue

        return matches

    # ──────────────────────────────────────────────────────────────────
    #  Full process context
    # ──────────────────────────────────────────────────────────────────

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Read everything available from /proc/<pid>/ about a process.
        Returns None if the process has exited before we could inspect it.
        """
        try:
            exe          = self._read_exe(pid)
            ppid, stime  = self._read_stat(pid)
            cmdline      = self._read_cmdline(pid)
            username     = self._read_username(pid)
            parent_exe   = self._read_exe(ppid) if ppid else "unknown"
            open_paths, fd_count = self._read_open_paths(pid)

            return ProcessInfo(
                pid=pid,
                exe=exe,
                ppid=ppid,
                parent_exe=parent_exe,
                cmdline=cmdline,
                username=username,
                open_fd_count=fd_count,
                open_paths=open_paths,
                start_time=stime,
            )

        except (FileNotFoundError, ProcessLookupError):
            return None
        except Exception as exc:
            log.debug(f"Error inspecting PID {pid}: {exc}")
            return None

    # ──────────────────────────────────────────────────────────────────
    #  /proc parsing helpers
    # ──────────────────────────────────────────────────────────────────

    def _enumerate_pids(self) -> List[int]:
        return [int(e) for e in os.listdir("/proc") if e.isdigit()]

    def _read_exe(self, pid: int) -> str:
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            try:
                return Path(f"/proc/{pid}/comm").read_text().strip()
            except OSError:
                return "unknown"

    def _read_stat(self, pid: int) -> Tuple[int, float]:
        """
        Parse /proc/<pid>/stat for PPID and process start time.
        Field layout: pid (comm) state ppid ...
        The comm field can contain spaces and parens — we parse from
        the rightmost closing paren to handle this safely.
        """
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            rparen = raw.rfind(")")
            fields = raw[rparen + 2:].split()
            ppid        = int(fields[1])    # 4th field overall
            start_ticks = int(fields[19])   # 22nd field overall
            hz = self._get_clock_hz()
            return ppid, start_ticks / hz
        except (OSError, IndexError, ValueError):
            return 0, 0.0

    def _read_cmdline(self, pid: int) -> List[str]:
        """Read null-byte-separated argv from /proc/<pid>/cmdline."""
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            return [a for a in raw.decode("utf-8", errors="replace").split("\x00") if a]
        except OSError:
            return []

    def _read_username(self, pid: int) -> str:
        """Resolve real UID → username via /proc/<pid>/status."""
        try:
            status = Path(f"/proc/{pid}/status").read_text()
            for line in status.splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    try:
                        return pwd.getpwuid(uid).pw_name
                    except KeyError:
                        return str(uid)
        except OSError:
            pass
        return "unknown"

    def _read_open_paths(self, pid: int) -> Tuple[List[str], int]:
        """
        Enumerate open FDs and resolve their symlinks.
        Returns (list_of_readable_paths, total_fd_count).
        Caps at 50 resolved paths to avoid huge memory use on fd-heavy processes.
        """
        paths: List[str] = []
        count = 0
        fd_dir = Path(f"/proc/{pid}/fd")
        try:
            entries = list(fd_dir.iterdir())
            count = len(entries)
            for fd_path in entries[:50]:
                try:
                    resolved = os.readlink(str(fd_path))
                    if not (
                        resolved.startswith("socket:")
                        or resolved.startswith("pipe:")
                        or resolved.startswith("/proc")
                        or resolved.startswith("anon_inode")
                    ):
                        paths.append(resolved)
                except OSError:
                    continue
        except (PermissionError, FileNotFoundError):
            pass
        return paths, count

    def _get_clock_hz(self) -> int:
        try:
            return os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        except (AttributeError, ValueError):
            return 100

    def _get_system_uptime(self) -> float:
        try:
            return float(Path("/proc/uptime").read_text().split()[0])
        except (OSError, ValueError):
            return 0.0
