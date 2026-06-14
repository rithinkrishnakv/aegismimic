"""
core/daemon.py — AegisMimic main event loop and response orchestrator.

Pipeline:
    inotify event
        → async event queue
        → PID resolver  (retry loop: 5 × 200ms, handles Hyper-V/Docker latency)
        → policy check  (YAML whitelist, AND/OR logic)
        → [forensic snapshot → chameleon swap → process-group kill → alert → audit]

The PID resolution problem:
    inotify events carry no PID. We resolve by scanning /proc/*/fd/* immediately
    after each event. The retry loop handles Docker Desktop and Hyper-V VM
    latency (Windows/Mac) where the process may not appear on the first scan.
"""

import os
import time
import signal
import logging
import threading
from pathlib import Path
from typing import Optional
from queue import Queue, Empty

try:
    import inotify.adapters
    import inotify.constants
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

from core.policy import PolicyEngine
from core.process import ProcessInspector
from core.honeypot import HoneypotManager
from core.alert import AlertManager
from core.snapshot import SnapshotManager
from audit.logger import AuditLogger
from audit.event import SecurityEvent, EventType

log = logging.getLogger("daemon")

# inotify flags: every meaningful file-access event
_WATCH_FLAGS: int = 0
if INOTIFY_AVAILABLE:
    _WATCH_FLAGS = (
        inotify.constants.IN_OPEN
        | inotify.constants.IN_ACCESS
        | inotify.constants.IN_CLOSE_WRITE
        | inotify.constants.IN_CLOSE_NOWRITE
        | inotify.constants.IN_CREATE
        | inotify.constants.IN_DELETE
        | inotify.constants.IN_MOVED_FROM
        | inotify.constants.IN_MODIFY
    )

_DIV = "─" * 62


class AegisDaemon:
    """
    Orchestrates the full AegisMimic response pipeline.

    Thread model:
      · Main thread  — inotify event generator (blocking loop)
      · Consumer thread — dequeues events, resolves PIDs, dispatches response
      · Alert threads — fire-and-forget webhook POSTs (daemon threads)
    """

    def __init__(
        self,
        watch_dir: Path,
        policy: PolicyEngine,
        audit: AuditLogger,
        alerts: AlertManager,
        dry_run: bool = False,
        snapshot_dir: Optional[Path] = None,
        reset_after_seconds: float = 300.0,
    ):
        self.watch_dir  = watch_dir
        self.policy     = policy
        self.audit      = audit
        self.alerts     = alerts
        self.dry_run    = dry_run
        self._running   = False

        self.inspector   = ProcessInspector()
        self.honeypot    = HoneypotManager(watch_dir, reset_after_seconds=reset_after_seconds)
        self.snapshotter = SnapshotManager(snapshot_dir) if snapshot_dir else None

        self._event_queue: Queue = Queue()
        self._killed_pids: set   = set()
        self._killed_lock        = threading.Lock()

        # Session statistics
        self._stat_violations = 0
        self._stat_authorized = 0
        self._stat_kills       = 0

    # ──────────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._running = True
        log.info(f"AegisMimic online. Shield raised over: {self.watch_dir}")

        if not INOTIFY_AVAILABLE:
            log.warning("inotify package not found — using polling fallback (500ms).")
            log.warning("Install with: pip install inotify==0.2.10")
            self._run_polling()
            return

        consumer = threading.Thread(
            target=self._process_event_queue,
            name="aegis-consumer",
            daemon=True,
        )
        consumer.start()
        self._run_inotify()

    def stop(self) -> None:
        self._running = False
        log.info(
            f"Session summary — "
            f"violations: {self._stat_violations}  "
            f"kills: {self._stat_kills}  "
            f"authorized: {self._stat_authorized}"
        )

    # ──────────────────────────────────────────────────────────────────
    #  inotify watcher  (primary, Linux only)
    # ──────────────────────────────────────────────────────────────────

    def _run_inotify(self) -> None:
        i = inotify.adapters.Inotify()
        i.add_watch(str(self.watch_dir), mask=_WATCH_FLAGS)
        log.info("[*] inotify watch armed. Watching for unauthorized access.")

        for event in i.event_gen(yield_nones=False):
            if not self._running:
                break
            (_, type_names, path, filename) = event
            log.debug(f"inotify │ {type_names} → {filename or '<dir>'}")
            self._event_queue.put((time.monotonic(), path, filename, type_names))

    # ──────────────────────────────────────────────────────────────────
    #  Polling fallback  (macOS / non-Linux)
    # ──────────────────────────────────────────────────────────────────

    def _run_polling(self) -> None:
        log.info("[*] Polling mode active.")
        while self._running:
            pids = self.inspector.find_pids_with_open_path(str(self.watch_dir))
            for pid in pids:
                self._handle_accessor(pid, trigger_file="<poll-detected>")
            time.sleep(0.5)

    # ──────────────────────────────────────────────────────────────────
    #  Event consumer
    # ──────────────────────────────────────────────────────────────────

    def _process_event_queue(self) -> None:
        while self._running:
            try:
                _, path, filename, _ = self._event_queue.get(timeout=1.0)
            except Empty:
                continue

            # ── PID resolution with retry ─────────────────────────────
            # inotify doesn't give us the PID. We scan /proc/*/fd/* looking
            # for an open file descriptor pointing into our watch directory.
            #
            # Retry loop: 5 attempts × 200ms = 1 second total window.
            # Needed for Docker Desktop on Windows (Hyper-V VM adds latency)
            # and for processes that take time to open their first FD.
            pids = []
            for attempt in range(5):
                pids = self.inspector.find_pids_with_open_path(path)
                if pids:
                    if attempt > 0:
                        log.debug(f"PID resolved on retry {attempt + 1}/5")
                    break
                time.sleep(0.2)

            # Fallback for transient accessors (open→read→close < 1s)
            if not pids:
                pids = self.inspector.find_recent_accessors(path, window_seconds=5.0)

            if not pids:
                log.debug(
                    f"Event on '{filename or '<dir>'}' — "
                    f"accessor exited before /proc scan (transient < 1s access)"
                )
                continue

            for pid in pids:
                self._handle_accessor(pid, trigger_file=filename or "<dir>")

    # ──────────────────────────────────────────────────────────────────
    #  Core response logic
    # ──────────────────────────────────────────────────────────────────

    def _handle_accessor(self, pid: int, trigger_file: str) -> None:
        with self._killed_lock:
            if pid in self._killed_pids:
                return  # Already handled

        # ── Gather process context ────────────────────────────────────
        proc = self.inspector.get_process_info(pid)
        if not proc:
            log.debug(f"PID {pid} vanished before inspection.")
            return

        # ── Policy evaluation ─────────────────────────────────────────
        verdict = self.policy.evaluate(proc)

        if verdict.authorized:
            self._stat_authorized += 1
            log.debug(
                f"[ALLOW] {proc.exe} (PID {pid}, user={proc.username}) "
                f"— matched rule: '{verdict.matched_rule}'"
            )
            return

        # ══ VIOLATION ══════════════════════════════════════════════════
        self._stat_violations += 1

        log.warning(f"\n  {_DIV}")
        log.warning(f"  [!] AegisMimic │ UNAUTHORIZED ACCESS — violation #{self._stat_violations}")
        log.warning(f"  {_DIV}")
        log.warning(f"  Process   │ {proc.exe}")
        log.warning(f"  PID       │ {pid}  (parent: {proc.parent_exe or 'unknown'}, PPID {proc.ppid})")
        log.warning(f"  User      │ {proc.username}")
        log.warning(f"  Command   │ {' '.join(proc.cmdline[:8])}")
        log.warning(f"  Trigger   │ {trigger_file}")
        log.warning(f"  Open FDs  │ {proc.open_fd_count}")
        log.warning(f"  Reason    │ {verdict.reason}")
        log.warning(f"  {_DIV}\n")

        # ── Audit event ───────────────────────────────────────────────
        event = SecurityEvent(
            event_type=EventType.UNAUTHORIZED_ACCESS,
            pid=pid,
            exe=proc.exe,
            ppid=proc.ppid,
            parent_exe=proc.parent_exe,
            cmdline=proc.cmdline,
            username=proc.username,
            trigger_file=trigger_file,
            violation_reason=verdict.reason,
            dry_run=self.dry_run,
        )
        self.audit.record(event)

        # ── Webhook alert (non-blocking) ──────────────────────────────
        threading.Thread(
            target=self.alerts.send_violation,
            args=(event,),
            name=f"aegis-alert-{pid}",
            daemon=True,
        ).start()

        if self.dry_run:
            log.info(
                f"  [DRY RUN] Detected PID {pid} ({proc.exe}). "
                f"Would have: snapshot → honeypot → kill."
            )
            return

        # ── 1. Forensic snapshot (before kill — /proc data is lost after) ──
        if self.snapshotter:
            try:
                snap_path = self.snapshotter.capture(pid, proc)
                log.info(f"  [*] Snapshot saved: {snap_path}")
            except Exception as exc:
                log.warning(f"  [!] Snapshot failed: {exc}")

        # ── 2. Chameleon — shift directory state BEFORE kill ──────────
        #    Process may re-read files in the 2s SIGTERM grace window.
        #    In ENGAGED state it sees more tempting decoys + canary token.
        try:
            self.honeypot.activate_honeypot_state(accessed_file=trigger_file)
            log.info("  [*] Chameleon active — directory shifted to ENGAGED state.")
        except Exception as exc:
            log.error(f"  [!] Honeypot swap failed: {exc}")

        # ── 3. Ryuk — terminate process group ─────────────────────────
        with self._killed_lock:
            self._killed_pids.add(pid)

        killed = self._terminate_process_group(pid)

        if killed:
            self._stat_kills += 1
            log.warning(
                f"  [!] AegisMimic │ Target eliminated. "
                f"{proc.exe} PID {pid} — terminated. "
                f"(Total kills: {self._stat_kills})"
            )
        else:
            log.error(f"  [!] Kill failed for PID {pid}. Process may have escaped.")

    # ──────────────────────────────────────────────────────────────────
    #  Process group termination
    # ──────────────────────────────────────────────────────────────────

    def _terminate_process_group(self, pid: int) -> bool:
        """
        Two-stage termination targeting the ENTIRE process group.

        Why process groups:
            A single os.kill(pid, SIGKILL) leaves any forked children alive.
            os.killpg(pgid, signal) sends to the entire group atomically.

        Safety check:
            We only call killpg if pgid != our own process group — prevents
            accidentally nuking the AegisMimic daemon itself if the target
            shares our group (rare, but possible in some container setups).

        Stage 1 — SIGTERM: allows graceful cleanup.
                           Some malware flushes exfil buffers on shutdown —
                           this gives us 2 seconds of observable behavior.
        Stage 2 — SIGKILL: unconditional. No escape.
        """
        try:
            pgid = os.getpgid(pid)
        except (ProcessLookupError, OSError):
            pgid = None

        try:
            if pgid and pgid != os.getpgrp():
                # Kill the whole process group
                log.debug(f"  Targeting PGID={pgid} (from PID {pid})")
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(2.0)
                try:
                    os.killpg(pgid, signal.SIGKILL)
                    log.debug(f"  SIGKILL delivered to PGID={pgid}")
                except ProcessLookupError:
                    log.debug(f"  PGID {pgid} already dead after SIGTERM")

            else:
                # Fallback: single-PID kill
                # (process shares our group, or getpgid failed)
                log.debug(f"  Single-PID fallback for PID={pid}")
                os.kill(pid, signal.SIGTERM)
                time.sleep(2.0)
                try:
                    os.kill(pid, 0)  # existence check
                    os.kill(pid, signal.SIGKILL)
                    log.debug(f"  SIGKILL delivered to PID={pid}")
                except ProcessLookupError:
                    log.debug(f"  PID {pid} already dead after SIGTERM")

            return True

        except ProcessLookupError:
            return False  # Already gone

        except PermissionError:
            log.error(
                f"  Permission denied — cannot kill PID {pid}. "
                f"Run AegisMimic as root for full kill capability."
            )
            return False
