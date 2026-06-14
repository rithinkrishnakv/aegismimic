"""
core/honeypot.py — The Chameleon layer.

State machine:
  NORMAL   → Realistic-looking decoy files (SSH keys, AWS creds, DB passwords).
             All fake. Nothing here is real.
  ENGAGED  → Unauthorized access detected. Additional tempting files added.
             A unique canary token written — fingerprints this engagement event.
             If that canary appears in attacker infrastructure later, it traces
             back to exactly this incident.
  RESET    → Transitioning back to NORMAL after quiet period.

The ENGAGED transition happens BEFORE the process kill fires, so the process
sees poisoned data during the 2-second SIGTERM grace window.

Auto-reset: after reset_after_seconds of no new access, the directory
quietly reverts to NORMAL. Each new access restarts the countdown.
"""

import hashlib
import json
import logging
import os
import threading
import time
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("honeypot")


class HoneypotState(Enum):
    NORMAL   = auto()
    ENGAGED  = auto()
    RESET    = auto()


# ── NORMAL decoys — look legitimate, zero real value ──────────────────────────

NORMAL_DECOYS: Dict[str, str] = {
    "id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAA[DECOY — AEGISMIMIC PROTECTED]\n"
        "AAAA[THIS IS NOT A REAL KEY]\n"
        "-----END OPENSSH PRIVATE KEY-----"
    ),
    "id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQ[DECOY]== aegis@mimic-protected",
    "aws_credentials": (
        "[default]\n"
        "aws_access_key_id = AKIADECOY00000000000\n"
        "aws_secret_access_key = DECOY+NOT+A+REAL+KEY+VALUE+DO+NOT+USE\n"
        "region = us-east-1"
    ),
    "database.env": (
        "# Production — do not commit\n"
        "DB_HOST=prod-primary.internal.corp\n"
        "DB_PORT=5432\n"
        "DB_NAME=production\n"
        "DB_USER=db_admin\n"
        "DB_PASS=DECOY_NOT_REAL_0xDEADBEEF\n"
        "DB_SSL_MODE=require"
    ),
    "backup_manifest.json": json.dumps({
        "schema_version": "2.1",
        "created": "2024-01-15T03:00:00Z",
        "volumes": ["prod-db-primary", "user-data", "secrets-vault"],
        "encryption": "AES-256-GCM",
        "backup_key_ref": "./backup.key",
        "total_size_gb": 847.3,
    }, indent=2),
    ".vault_token": "s.DECOY0000000000000000000000",
    "README.txt": "Backup directory. Do not modify manually. — Ops",
}

# ── ENGAGED additions — even more tempting, includes the canary ───────────────

ENGAGED_ADDITIONS: Dict[str, str] = {
    "master.key": (
        "# Rails credentials master key — DO NOT SHARE\n"
        "DECOY1234567890abcdef1234567890ab"
    ),
    "ssh_config": (
        "Host prod-jump\n"
        "  HostName jump.internal.corp\n"
        "  User deploy\n"
        "  IdentityFile ~/.ssh/id_rsa\n\n"
        "Host prod-db\n"
        "  HostName db.internal.corp\n"
        "  ProxyJump prod-jump"
    ),
    "stripe_keys.json": json.dumps({
        "live_secret_key": "sk_live_YOUR_DECOY_STRIPE_KEY_REPLACEME_MIMIC",
        "live_publishable_key": "pk_live_YOUR_DECOY_PUBLISHABLE_KEY_MIMIC",
        "webhook_secret": "whsec_YOUR_DECOY_WEBHOOK_SECRET_MIMIC",
    }, indent=2),
    "gcp_service_account.json": json.dumps({
        "type": "service_account",
        "project_id": "prod-corp-internal",
        "private_key_id": "DECOY000000000000000000000000000000000000",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\n[DECOY]\n-----END RSA PRIVATE KEY-----",
        "client_email": "deploy@prod-corp-internal.iam.gserviceaccount.com",
    }, indent=2),
}


class HoneypotManager:
    """
    Manages the honey directory's file state and access fingerprinting.
    """

    def __init__(self, watch_dir: Path, reset_after_seconds: float = 300.0):
        self.watch_dir           = watch_dir
        self.state               = HoneypotState.NORMAL
        self._lock               = threading.Lock()
        self._access_log: List[dict] = []
        self._reset_after        = reset_after_seconds
        self._reset_timer: Optional[threading.Timer] = None
        self._current_canary: Optional[str] = None

        self._ensure_normal_state()

    # ──────────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────────

    def activate_honeypot_state(self, accessed_file: Optional[str] = None) -> None:
        """
        Transition to ENGAGED state or refresh if already engaged.

        On each call:
          · Logs which file was accessed
          · Adds ENGAGED_ADDITIONS if not already present
          · Deploys / refreshes the canary token
          · (Re)schedules the auto-reset countdown
        """
        with self._lock:
            if accessed_file:
                self._log_access(accessed_file)

            if self.state == HoneypotState.ENGAGED:
                # Already engaged — restart the reset timer
                self._reschedule_reset()
                return

            log.info("[*] Honeypot: transitioning NORMAL → ENGAGED")
            self.state = HoneypotState.ENGAGED

            # Add engaged-only files
            for filename, content in ENGAGED_ADDITIONS.items():
                path = self.watch_dir / filename
                if not path.exists():
                    try:
                        path.write_text(content)
                    except OSError as exc:
                        log.warning(f"Could not write engaged file '{filename}': {exc}")

            # Deploy canary token — unique fingerprint for this engagement
            canary_id = hashlib.sha256(
                f"{time.time()}-{os.urandom(8).hex()}".encode()
            ).hexdigest()[:20]
            self._current_canary = canary_id

            canary_path = self.watch_dir / ".session_token"
            try:
                canary_path.write_text(
                    f"session_id={canary_id}\n"
                    f"issued={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
                    f"user=deploy-svc\n"
                    f"scope=backup:read,vault:read,secrets:list\n"
                    f"expires={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 86400))}"
                )
                log.info(f"[*] Canary deployed: session_id={canary_id}")
                log.info(f"    If this token appears in attacker infra, trace to this event.")
            except OSError as exc:
                log.warning(f"Canary write failed: {exc}")

            self._reschedule_reset()

    def reset_to_normal(self) -> None:
        """Revert to NORMAL state. Called by timer or manually."""
        with self._lock:
            if self.state == HoneypotState.NORMAL:
                return

            log.info("[*] Honeypot: auto-resetting ENGAGED → NORMAL")

            if self._reset_timer and self._reset_timer.is_alive():
                self._reset_timer.cancel()
                self._reset_timer = None

            # Remove engaged-only files and canary
            to_remove = list(ENGAGED_ADDITIONS.keys()) + [".session_token"]
            for filename in to_remove:
                path = self.watch_dir / filename
                if path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        pass

            self._current_canary = None
            self.state = HoneypotState.NORMAL
            log.info("[*] Honeypot back to NORMAL state.")

    def get_canary(self) -> Optional[str]:
        with self._lock:
            return self._current_canary

    def get_access_log(self) -> List[dict]:
        with self._lock:
            return list(self._access_log)

    # ──────────────────────────────────────────────────────────────────
    #  Internal
    # ──────────────────────────────────────────────────────────────────

    def _ensure_normal_state(self) -> None:
        """Write NORMAL decoy files on startup if they don't exist."""
        try:
            for filename, content in NORMAL_DECOYS.items():
                path = self.watch_dir / filename
                if not path.exists():
                    path.write_text(content)
        except OSError as exc:
            log.warning(f"Could not initialize decoys: {exc}")

    def _reschedule_reset(self) -> None:
        """
        Cancel any existing reset timer and schedule a fresh one.
        Each new access in ENGAGED state restarts the countdown —
        we stay ENGAGED as long as the directory is being actively probed.

        NOTE: Must be called while self._lock is already held.
        """
        if self._reset_timer and self._reset_timer.is_alive():
            self._reset_timer.cancel()

        self._reset_timer = threading.Timer(
            self._reset_after,
            self.reset_to_normal,
        )
        self._reset_timer.daemon = True
        self._reset_timer.start()
        log.debug(
            f"[*] Honeypot auto-reset in {self._reset_after:.0f}s "
            f"(resets on each new access)"
        )

    def _log_access(self, filename: str) -> None:
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "file": filename,
            "state": self.state.name,
            "canary": self._current_canary,
        }
        self._access_log.append(entry)
