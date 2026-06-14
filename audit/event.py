"""
audit/event.py — Structured security event model.

Events are serialized as NDJSON (newline-delimited JSON) — one event per line.
This format is directly ingestible by SIEM tools, Elasticsearch, Splunk,
or simple grep/jq queries.
"""

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional
import json


class EventType(str, Enum):
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    PROCESS_KILLED      = "PROCESS_KILLED"
    HONEYPOT_ENGAGED    = "HONEYPOT_ENGAGED"
    HONEYPOT_RESET      = "HONEYPOT_RESET"
    AUTHORIZED_ACCESS   = "AUTHORIZED_ACCESS"
    DAEMON_START        = "DAEMON_START"
    DAEMON_STOP         = "DAEMON_STOP"


@dataclass
class SecurityEvent:
    event_type:       EventType
    pid:              int
    exe:              str
    ppid:             int
    parent_exe:       str
    cmdline:          List[str]
    username:         str
    trigger_file:     str
    violation_reason: Optional[str] = None
    dry_run:          bool = False
    timestamp:        str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
