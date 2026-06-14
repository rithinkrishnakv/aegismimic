# Contributing to AegisMimic

Thank you for your interest in contributing. This document covers how to set up a development environment, the project's coding standards, and how to submit changes.

---

## Development Setup

```bash
git clone https://github.com/rithinkrishnakv/aegismimic
cd aegismimic

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pyflakes   # for linting
```

Run in demo mode to verify everything works:

```bash
sudo python3 aegismimic.py --demo --dry-run -v
```

---

## Project Layout

```
core/daemon.py     Main event loop — edit with care, it's the hot path
core/process.py    /proc parsing — Linux-specific, performance-sensitive
core/policy.py     Rule engine — straightforward, good place to start
core/honeypot.py   State machine — any new decoy files go here
core/alert.py      Webhook payloads — add new platforms here
core/snapshot.py   /proc capture — add new data sources here
audit/             Event model and log writer — keep stable
```

---

## Coding Standards

**Python version:** 3.9+ compatible. No walrus operators or 3.10+ match statements in shared code.

**Type hints:** All public methods and function signatures should have type hints.

**Docstrings:** Every module and every public class/method needs a docstring explaining *why*, not just *what*.

**Error handling:** Never let a plugin/subcomponent exception crash the main daemon. Wrap in try/except and log at `WARNING` or `ERROR` level.

**Thread safety:** The daemon is multi-threaded. Any shared mutable state must be protected by a `threading.Lock()`. See `HoneypotManager._lock` and `AegisDaemon._killed_lock` as examples.

**No external dependencies beyond requirements.txt.** The tool should install cleanly with two packages (`inotify`, `pyyaml`) on a fresh Linux system.

---

## Adding a New Alert Platform

Edit `core/alert.py`:

1. Add a detection property to `AlertConfig`:
```python
@property
def is_pagerduty(self) -> bool:
    return bool(self.webhook_url and "events.pagerduty.com" in self.webhook_url)
```

2. Add a payload builder method:
```python
def _pagerduty_payload(self, event, tag: str) -> dict:
    return {
        "routing_key": "...",
        "event_action": "trigger",
        "payload": {
            "summary": f"AegisMimic: Unauthorized access{tag}",
            "severity": "critical",
            "custom_details": { ... },
        }
    }
```

3. Add it to `_build_payload()`:
```python
if self.config.is_pagerduty:
    return self._pagerduty_payload(event, tag)
```

---

## Adding New Honeypot Decoys

Edit `core/honeypot.py`. Add to `NORMAL_DECOYS` for files present from the start, or `ENGAGED_ADDITIONS` for files that only appear after unauthorized access:

```python
NORMAL_DECOYS: Dict[str, str] = {
    # ... existing entries ...
    "github_token.txt": "ghp_DECOY000000000000000000000000000000",
}
```

Keep decoys realistic. The goal is that a real attacker looking at the file would believe it's genuine at a glance.

---

## Submitting a Pull Request

1. Fork the repository and create a branch: `git checkout -b feature/your-feature`
2. Make your changes with tests if applicable
3. Verify CI passes locally:
   ```bash
   python3 -c "import ast; [ast.parse(open(f).read()) for f in __import__('pathlib').Path('.').rglob('*.py')]"
   python3 -c "from core.daemon import AegisDaemon; print('imports OK')"
   ```
4. Open a pull request against `main` with a clear description of what the change does and why

---

## Reporting Security Issues

Do not open a public GitHub issue for security vulnerabilities. Email **Rimu** directly. We will respond within 72 hours and coordinate a fix before public disclosure.

---

## Roadmap / Good First Issues

- [ ] `fanotify` backend — delivers PID directly, eliminates the /proc race window
- [ ] eBPF tracepoint fallback — `tracepoint:syscalls:sys_enter_openat` for kernel-level access
- [ ] Email alerting — SMTP alongside webhook
- [ ] Web dashboard — React frontend over a local API for live violation monitoring
- [ ] RPM/DEB packaging — proper system package for enterprise deployment
- [ ] macOS support — FSEvents backend replacing inotify
- [ ] Unit tests — pytest suite for policy engine and honeypot state machine
