"""
core/alert.py — Real-time violation alerting via webhook.

Supports:
  · Slack incoming webhooks  (auto-detected by slack.com in URL)
  · Discord webhooks         (auto-detected by discord.com in URL)
  · Generic HTTP POST        (any other URL — sends structured JSON)

Alerts fire in a daemon thread so they never delay the kill chain.
Network failures are logged as warnings, never raised.
"""

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("alert")


@dataclass
class AlertConfig:
    webhook_url: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    @property
    def is_slack(self) -> bool:
        return bool(self.webhook_url and "hooks.slack.com" in self.webhook_url)

    @property
    def is_discord(self) -> bool:
        return bool(self.webhook_url and "discord.com/api/webhooks" in self.webhook_url)


class AlertManager:
    """Sends structured violation alerts to configured webhook endpoint."""

    def __init__(self, config: AlertConfig):
        self.config = config
        if config.enabled:
            log.info(
                f"Webhook alerting enabled: "
                f"{'Slack' if config.is_slack else 'Discord' if config.is_discord else 'Generic'}"
            )

    def send_violation(self, event) -> bool:
        """
        POST a formatted alert. Returns True on success.
        Designed to be called from a daemon thread — never raises.
        """
        if not self.config.enabled:
            return False

        try:
            payload = self._build_payload(event)
            data    = json.dumps(payload).encode("utf-8")
            req     = urllib.request.Request(
                self.config.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.debug(f"Alert delivered: HTTP {resp.status}")
            return True

        except urllib.error.URLError as exc:
            log.warning(f"Alert failed (network): {exc.reason}")
        except Exception as exc:
            log.warning(f"Alert failed: {exc}")
        return False

    # ──────────────────────────────────────────────────────────────────
    #  Payload builders
    # ──────────────────────────────────────────────────────────────────

    def _build_payload(self, event) -> dict:
        tag = " ⚠ DRY RUN" if event.dry_run else ""

        if self.config.is_discord:
            return self._discord_payload(event, tag)
        if self.config.is_slack:
            return self._slack_payload(event, tag)
        return self._generic_payload(event)

    def _discord_payload(self, event, tag: str) -> dict:
        return {
            "embeds": [{
                "title": f"🛡️ AegisMimic Alert{tag}",
                "description": "Unauthorized access to honey directory detected and terminated.",
                "color": 15158332,  # red
                "fields": [
                    {"name": "Process",      "value": f"`{event.exe}`",      "inline": True},
                    {"name": "PID",          "value": str(event.pid),        "inline": True},
                    {"name": "User",         "value": event.username,        "inline": True},
                    {"name": "Parent",       "value": f"`{event.parent_exe}`", "inline": True},
                    {"name": "Trigger File", "value": event.trigger_file,    "inline": True},
                    {"name": "Dry Run",      "value": str(event.dry_run),    "inline": True},
                    {"name": "Violation",    "value": event.violation_reason or "Policy violation", "inline": False},
                ],
                "footer": {
                    "text": "AegisMimic · \"I Don't Want To Get Hacked, So I'll Max Out My Camouflage!\""
                },
                "timestamp": event.timestamp,
            }]
        }

    def _slack_payload(self, event, tag: str) -> dict:
        return {
            "text": f"🛡️ *AegisMimic Alert*{tag}",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {"title": "Process",      "value": event.exe,            "short": True},
                    {"title": "PID",          "value": str(event.pid),       "short": True},
                    {"title": "User",         "value": event.username,       "short": True},
                    {"title": "Trigger File", "value": event.trigger_file,   "short": True},
                    {"title": "Command",      "value": " ".join(event.cmdline[:5]), "short": False},
                    {"title": "Violation",    "value": event.violation_reason or "Policy violation", "short": False},
                ],
                "footer": "AegisMimic",
                "ts": event.timestamp,
            }]
        }

    def _generic_payload(self, event) -> dict:
        return {
            "source":           "AegisMimic",
            "event_type":       event.event_type,
            "timestamp":        event.timestamp,
            "dry_run":          event.dry_run,
            "pid":              event.pid,
            "exe":              event.exe,
            "ppid":             event.ppid,
            "parent_exe":       event.parent_exe,
            "cmdline":          event.cmdline,
            "username":         event.username,
            "trigger_file":     event.trigger_file,
            "violation_reason": event.violation_reason,
        }
