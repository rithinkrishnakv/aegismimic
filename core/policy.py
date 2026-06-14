"""
core/policy.py — Authorization rule engine.

Policies are defined in config/policy.yaml as a whitelist.
Any process NOT matching at least one rule is treated as unauthorized.

Rule matching supports:
  exe_paths     — exact binary path match
  exe_patterns  — glob patterns (fnmatch)
  users         — allowed usernames (case-insensitive, empty = any)
  parent_exe_patterns — required parent process patterns
  require_all   — AND logic (all conditions must match) vs OR logic (any)

Secure by default: missing policy file → DENY-ALL mode.
"""

import logging
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import List, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from core.process import ProcessInfo

log = logging.getLogger("policy")


@dataclass
class PolicyVerdict:
    authorized: bool
    matched_rule: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class AuthRule:
    name: str
    exe_paths: List[str]
    exe_patterns: List[str]
    users: List[str]                 # Stored lowercase
    parent_exe_patterns: List[str]
    require_all: bool                # True = AND, False = OR


class PolicyEngine:
    """
    Evaluates whether a process is authorized to access the honey directory.
    Implements whitelist semantics: explicit allow, implicit deny.
    """

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.rules: List[AuthRule] = []
        self._load()

    def _load(self) -> None:
        if not self.config_path.exists():
            log.warning(
                f"Policy file not found: {self.config_path} — "
                f"running in DENY-ALL mode (every accessor flagged)."
            )
            return

        if not YAML_AVAILABLE:
            log.error("PyYAML not installed. Run: pip install pyyaml")
            return

        try:
            with open(self.config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            for rule_data in data.get("authorized_rules", []):
                rule = AuthRule(
                    name=rule_data.get("name", "unnamed"),
                    exe_paths=rule_data.get("exe_paths", []),
                    exe_patterns=rule_data.get("exe_patterns", []),
                    # Normalize users to lowercase — prevents silent mismatch
                    users=[u.lower() for u in rule_data.get("users", [])],
                    parent_exe_patterns=rule_data.get("parent_exe_patterns", []),
                    require_all=rule_data.get("require_all", False),
                )
                self.rules.append(rule)

            log.info(f"Policy loaded: {len(self.rules)} authorized rules from {self.config_path}")

        except Exception as exc:
            log.error(f"Failed to load policy ({self.config_path}): {exc}")

    def evaluate(self, proc: ProcessInfo) -> PolicyVerdict:
        """
        Check the process against all rules.
        Returns authorized=True if ANY rule matches (whitelist OR logic at rule level).
        Within a rule, require_all controls AND/OR between conditions.
        """
        for rule in self.rules:
            if self._matches_rule(proc, rule):
                return PolicyVerdict(authorized=True, matched_rule=rule.name)

        return PolicyVerdict(
            authorized=False,
            reason=self._violation_summary(proc),
        )

    def _matches_rule(self, proc: ProcessInfo, rule: AuthRule) -> bool:
        checks: List[bool] = []

        # Executable check
        if rule.exe_paths or rule.exe_patterns:
            exe_ok = (
                proc.exe in rule.exe_paths
                or any(fnmatch(proc.exe, p) for p in rule.exe_patterns)
            )
            checks.append(exe_ok)

        # User check (case-insensitive)
        if rule.users:
            checks.append(proc.username.lower() in rule.users)

        # Parent executable check
        if rule.parent_exe_patterns:
            parent_ok = any(
                fnmatch(proc.parent_exe or "", p) for p in rule.parent_exe_patterns
            )
            checks.append(parent_ok)

        if not checks:
            return False  # Empty rule matches nothing

        return all(checks) if rule.require_all else any(checks)

    def _violation_summary(self, proc: ProcessInfo) -> str:
        if not self.rules:
            return "DENY-ALL mode (no policy file loaded)"

        parts = [f"No rule authorizes exe='{proc.exe}'"]
        if proc.username and proc.username != "unknown":
            parts.append(f"user='{proc.username}'")
        if proc.parent_exe and proc.parent_exe not in ("unknown", ""):
            parts.append(f"parent='{proc.parent_exe}'")
        return " | ".join(parts)
