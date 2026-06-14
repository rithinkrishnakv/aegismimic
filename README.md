# AegisMimic

**"I Don't Want To Get Hacked, So I'll Max Out My Camouflage!"**

> Built by **Rimu**

[![CI](https://github.com/rithinkrishnakv/aegismimic/actions/workflows/ci.yml/badge.svg)](https://github.com/rithinkrishnakv/aegismimic/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://kernel.org/)

AegisMimic is a **honey directory engine** for Linux servers. It places a folder full of convincing fake credentials where an attacker looks first. The moment any unauthorized process touches it — the directory shifts its appearance, the process is fingerprinted with a canary token, and it is terminated. The entire sequence takes under one second.

---

## How It Works

```
Unauthorized process touches honey directory
         │
         ▼
  inotify event  (kernel-level, instant — no polling)
         │
         ▼
  /proc scan → PID resolved  (retry loop handles VM/container latency)
         │
         ▼
  Policy check  (config/policy.yaml whitelist)
         │
         ├── AUTHORIZED ──► log OK, continue
         │
         └── UNAUTHORIZED
                  │
                  ├─ 1. Forensic snapshot saved  (/proc: env, maps, net, I/O)
                  ├─ 2. Directory → ENGAGED state  (more decoys + canary token)
                  ├─ 3. SIGTERM → 2s grace → SIGKILL  (entire process group)
                  ├─ 4. Webhook alert fired  (Slack / Discord / HTTP)
                  └─ 5. NDJSON audit event written
```

---

## Features

| Layer | Description |
|---|---|
| **inotify watcher** | Kernel file access events — zero polling overhead |
| **PID resolver** | Scans `/proc/*/fd/*`; retry loop handles Docker/Hyper-V latency |
| **Policy engine** | YAML whitelist with AND/OR logic, glob patterns, case-insensitive users |
| **Chameleon** | `NORMAL → ENGAGED` state machine; adds decoys + deploys canary token |
| **Process kill** | `SIGTERM → SIGKILL` targeting the full process group (catches forked children) |
| **Snapshot engine** | Captures env vars, memory maps, network connections before kill |
| **Webhook alerts** | Auto-detects Slack, Discord, or generic HTTP POST |
| **NDJSON audit log** | SIEM-compatible structured events, jq/grep friendly |
| **Auto-reset** | Honeypot reverts to `NORMAL` after configurable quiet period |
| **Dry-run mode** | Full detection and logging without terminating anything |

---

## Deployment

### Does Docker protect the host?

This is the most important question to answer before deploying:

| Mode | What is protected | How |
|---|---|---|
| `docker compose up` | Container only | Internal volume, container /proc |
| `docker compose -f docker-compose.host.yml up` | **Host machine** | `pid: host` + host volume mount |
| `sudo ./install.sh` (systemd) | **Host machine** | Runs natively, recommended |

### Option 1 — Native systemd (Recommended for Production)

```bash
git clone https://github.com/rithinkrishnakv/aegismimic
cd aegismimic

sudo ./install.sh --watch /home/user/keys

# Edit policy to whitelist your processes
sudo nano /etc/aegismimic/policy.yaml

sudo systemctl start aegismimic
sudo systemctl status aegismimic
sudo journalctl -u aegismimic -f
```

### Option 2 — Docker with Host Protection

```bash
# Edit docker-compose.host.yml first:
# Change /path/on/host/to/protect to your real directory.
nano docker-compose.host.yml

docker compose -f docker-compose.host.yml up -d
docker logs -f aegismimic_host_guard
```

The `pid: "host"` flag shares the host PID namespace. `/proc` inside the container shows all host processes. Kill signals terminate actual host processes.

### Option 3 — Docker Dev/Test

Watches a directory inside the container only. The host is NOT protected. Use for development and testing.

```bash
docker compose up     # Ubuntu daemon + Kali attacker, shared volume
```

---

## Quick Start

```bash
pip install -r requirements.txt

# Safe demo — creates /tmp/aegis_demo, no kills
sudo python3 aegismimic.py --demo --dry-run

# Live — watches a real directory
sudo python3 aegismimic.py --watch /home/user/keys --config config/policy.yaml

# With Slack alerts + forensic snapshots
sudo python3 aegismimic.py \
    --watch /secure/backup \
    --webhook https://hooks.slack.com/services/T.../B.../... \
    --snapshot-dir /var/log/aegismimic/snapshots
```

> Requires root for `/proc` enumeration and kill capability.

---

## Testing (Docker Lab)

```bash
# Terminal 1 — start lab
docker compose up

# Terminal 2 — shell into Kali attacker
docker exec -it aegis_attacker bash

# Hold a file open long enough for /proc scan to catch you
python3 -c "
f = open('/secure/backup/aws_credentials', 'r')
print(f.read())
import time; time.sleep(15)
f.close()
"

# Terminal 3 — watch audit log on host
tail -f audit/aegismimic.log | python3 -m json.tool

docker compose down -v
```

---

## Policy Configuration

Edit `config/policy.yaml`. Any process not matching a rule is unauthorized.

```yaml
authorized_rules:

  - name: "interactive-shells"
    exe_patterns: ["/bin/bash", "/bin/zsh"]
    users: ["youruser", "root"]       # change youruser

  - name: "backup-agent"
    exe_patterns: ["/usr/bin/restic"]
    users: ["backup"]

  # AND logic: Python only if launched from your shell, not cron
  - name: "python-from-shell"
    exe_patterns: ["/usr/bin/python3"]
    parent_exe_patterns: ["/bin/bash"]
    require_all: true
```

**Secure by default:** missing policy file → DENY-ALL mode, every accessor flagged.

---

## Audit Log

NDJSON format, one event per line, SIEM-compatible:

```json
{
  "event_type": "UNAUTHORIZED_ACCESS",
  "timestamp": "2026-05-23T17:42:01Z",
  "pid": 31337,
  "exe": "/tmp/malware",
  "ppid": 1204,
  "parent_exe": "/usr/bin/cron",
  "cmdline": ["/tmp/malware", "--exfil", "s3://attacker.com"],
  "username": "www-data",
  "trigger_file": "aws_credentials",
  "violation_reason": "No rule authorizes exe='/tmp/malware' | user='www-data'",
  "dry_run": false
}
```

```bash
jq 'select(.event_type == "UNAUTHORIZED_ACCESS")' audit/aegismimic.log
jq -r '.trigger_file' audit/aegismimic.log | sort | uniq -c | sort -rn
```

---

## Project Structure

```
aegismimic/
├── aegismimic.py              Entry point, CLI
├── install.sh                 Production installer (systemd)
├── aegismimic.service         systemd unit file
├── Dockerfile
├── docker-compose.yml         Dev/test (container only)
├── docker-compose.host.yml    Host protection via Docker
├── test_intruder.sh           Attacker simulation for testing
├── config/
│   └── policy.yaml            Authorization whitelist
├── core/
│   ├── daemon.py              Event loop, PID resolver, orchestrator
│   ├── process.py             /proc-based process inspection
│   ├── policy.py              YAML rule engine
│   ├── honeypot.py            Directory state machine, canary tokens
│   ├── alert.py               Slack / Discord / webhook alerting
│   └── snapshot.py            Forensic /proc capture before kill
└── audit/
    ├── event.py               SecurityEvent dataclass
    └── logger.py              Thread-safe NDJSON writer
```

---

## Limitations

| Gap | Notes |
|---|---|
| Transient accessors (< 200ms) | fanotify/eBPF gives 100% coverage; planned enhancement |
| Linux only (inotify) | Polling fallback on macOS; WSL2 on Windows |
| Root required | Expected for a system-level security daemon |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
