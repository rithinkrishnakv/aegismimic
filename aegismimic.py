#!/usr/bin/env python3
"""
AegisMimic
==========
Author: Rimu
"I Don't Want To Get Hacked, So I'll Max Out My Camouflage!"

A professional-grade honey directory engine combining:
  · inotify-driven file access detection (kernel-level, zero polling)
  · /proc-based PID resolution with retry logic
  · Dynamic directory deception (Chameleon layer)
  · Process group termination (Ryuk layer)
  · Forensic /proc snapshots captured before kill
  · Slack / Discord / webhook alerting
  · NDJSON structured audit logs

Deployment:
  Production  → sudo python3 aegismimic.py --watch /secure/keys
  As service  → sudo ./install.sh && systemctl start aegismimic
  Testing     → docker compose up  (see docker-compose.yml)

Usage:
    sudo python3 aegismimic.py --demo --dry-run
    sudo python3 aegismimic.py --watch /secure/keys --config config/policy.yaml
    sudo python3 aegismimic.py --watch /srv/secrets --webhook https://hooks.slack.com/...
    sudo python3 aegismimic.py --watch /secure/backup --snapshot-dir /var/log/aegismimic/snaps
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

from core.daemon import AegisDaemon
from core.policy import PolicyEngine
from core.alert import AlertManager, AlertConfig
from audit.logger import AuditLogger


BANNER = r"""
    _   ___ ___ ___ ___ __  __ ___ __  __ ___ ___
   /_\ | __/ __|_ _/ __|  \/  |_ _|  \/  |_ _/ __|
  / _ \| _| (_ || |\__ \ |\/| || || |\/| || | (__
 /_/ \_\___\___|___|___/_|  |_|___|_|  |_|___\___|

  "I Don't Want To Get Hacked, So I'll Max Out My Camouflage!"
  ─────────────────────────────────────────────────────────────
  Honey Directory Engine  ·  Active Deception  ·  Process Termination
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegismimic",
        description='AegisMimic — Honey Directory Engine with Active Deception',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python3 aegismimic.py --demo --dry-run
  sudo python3 aegismimic.py --watch /home/user/keys --config config/policy.yaml
  sudo python3 aegismimic.py --watch /secure/backup --webhook https://hooks.slack.com/T.../B.../...
  sudo python3 aegismimic.py --watch /srv/secrets --snapshot-dir /var/log/aegismimic/snaps -v
        """,
    )

    watch = parser.add_argument_group("watch target")
    watch.add_argument("--watch", type=Path, metavar="DIR",
                       help="Directory to monitor (the honey trap)")
    watch.add_argument("--demo", action="store_true",
                       help="Auto-create demo trap at /tmp/aegis_demo and watch it")

    pol = parser.add_argument_group("policy")
    pol.add_argument("--config", type=Path, default=Path("config/policy.yaml"),
                     metavar="FILE", help="Policy YAML (default: config/policy.yaml)")

    resp = parser.add_argument_group("response")
    resp.add_argument("--dry-run", action="store_true",
                      help="Detect and log violations — do NOT kill or swap files")
    resp.add_argument("--reset-after", type=float, default=300.0, metavar="SECS",
                      help="Auto-reset honeypot to NORMAL after N quiet seconds (default: 300)")
    resp.add_argument("--snapshot-dir", type=Path, default=None, metavar="DIR",
                      help="Save forensic /proc snapshots here before each kill")

    alert = parser.add_argument_group("alerting")
    alert.add_argument("--webhook", type=str, default=None, metavar="URL",
                       help="Slack / Discord / generic HTTP webhook for real-time alerts")

    out = parser.add_argument_group("output")
    out.add_argument("--log-file", type=Path, default=Path("audit/aegismimic.log"),
                     metavar="FILE", help="NDJSON audit log (default: audit/aegismimic.log)")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Enable debug-level output")

    return parser.parse_args()


def setup_demo(watch_dir: Path) -> None:
    """Populate a convincing honey directory for testing."""
    watch_dir.mkdir(parents=True, exist_ok=True)
    decoys = {
        "id_rsa": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA[DECOY — AEGISMIMIC PROTECTED]\n"
            "-----END OPENSSH PRIVATE KEY-----"
        ),
        "id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQ[DECOY]== aegis@mimic",
        "aws_credentials": (
            "[default]\n"
            "aws_access_key_id = AKIADECOY00000000000\n"
            "aws_secret_access_key = DECOY+NOT+A+REAL+SECRET+KEY+DO+NOT+USE\n"
            "region = us-east-1"
        ),
        "database.env": (
            "# Production credentials\n"
            "DB_HOST=prod-primary.internal.corp\n"
            "DB_PORT=5432\n"
            "DB_NAME=production\n"
            "DB_USER=db_admin\n"
            "DB_PASS=DECOY_PASSWORD_NOT_REAL_0xDEADBEEF\n"
            "DB_SSL_MODE=require"
        ),
        "backup_manifest.json": (
            '{"schema":"2.1","volumes":["prod-db","user-data","secrets-vault"],'
            '"encryption":"AES-256-GCM","last_run":"2024-01-15T03:00:00Z"}'
        ),
        ".vault_token": "s.DECOY0000000000000000000000",
        "README.txt": "Backup directory. Do not modify manually.",
    }
    for name, content in decoys.items():
        (watch_dir / name).write_text(content)
    print(f"  [*] Demo trap armed at: {watch_dir}")
    print(f"  [*] Access any file inside to trigger AegisMimic.\n")


def main() -> None:
    args = parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-8s] %(name)-12s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    watch_dir = Path("/tmp/aegis_demo") if args.demo else args.watch
    if not watch_dir:
        print("[!] --watch <directory> is required unless --demo is used.\n")
        sys.exit(1)

    if args.demo:
        setup_demo(watch_dir)

    if not watch_dir.exists():
        print(f"[!] Watch directory does not exist: {watch_dir}\n")
        sys.exit(1)

    if args.snapshot_dir:
        args.snapshot_dir.mkdir(parents=True, exist_ok=True)

    args.log_file.parent.mkdir(parents=True, exist_ok=True)

    policy = PolicyEngine(args.config)
    audit  = AuditLogger(args.log_file)
    alerts = AlertManager(AlertConfig(webhook_url=args.webhook))

    print(BANNER)
    pad = 14
    div = "─" * 64
    print(f"  {div}")
    print(f"  {'Watching':<{pad}}: {watch_dir}")
    print(f"  {'Policy':<{pad}}: {args.config}")
    print(f"  {'Audit log':<{pad}}: {args.log_file}")
    mode = "DRY RUN — detection only, no kills" if args.dry_run else "LIVE — will terminate violators"
    print(f"  {'Mode':<{pad}}: {mode}")
    if args.webhook:
        short = args.webhook[:52] + "..." if len(args.webhook) > 52 else args.webhook
        print(f"  {'Webhook':<{pad}}: {short}")
    if args.snapshot_dir:
        print(f"  {'Snapshots':<{pad}}: {args.snapshot_dir}")
    print(f"  {'Honeypot reset':<{pad}}: {args.reset_after:.0f}s after last access")
    print(f"  {div}\n")

    daemon = AegisDaemon(
        watch_dir=watch_dir,
        policy=policy,
        audit=audit,
        alerts=alerts,
        dry_run=args.dry_run,
        snapshot_dir=args.snapshot_dir,
        reset_after_seconds=args.reset_after,
    )

    def _shutdown(signum, frame):
        print("\n[*] AegisMimic shutting down.")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    daemon.run()


if __name__ == "__main__":
    main()
