"""Core data models for sentinai.

All records are plain dataclasses that serialize to/from JSON-friendly dicts
so every stage (ingest -> detect -> triage -> correlate -> respond -> report)
is inspectable and reproducible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional

#: Telemetry channels understood by the correlation engine.
CHANNELS: tuple = ("auth", "web", "process", "flow", "alert")

#: RFC 5737 documentation ranges — the *only* routable-in-fiction addresses
#: treated as simulation targets. Everything outside of loopback + RFC 5737 is
#: hard-refused by the response engine.
RFC5737_PREFIXES: tuple = ("192.0.2.", "198.51.100.", "203.0.113.")

#: Ordered MITRE ATT&CK tactics (enterprise, abbreviated) used for kill-chain
#: reconstruction. Position in this sequence *is* the stage weight order.
MITRE_TACTICS: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_INDEX: Dict[str, int] = {t: i for i, t in enumerate(MITRE_TACTICS)}


def rfc5737(ip: str) -> bool:
    """True when *ip* falls in a documentation range (safe simulation space)."""
    return any(ip.startswith(p) for p in RFC5737_PREFIXES)


def next_id(prefix: str, used: Iterable[str]) -> str:
    """Deterministic id generator: prefix-N where N = max used + 1."""
    nums = [int(m) for m in (re.search(r"(\d+)$", i).group(1) if re.search(r"(\d+)$", i) else "0")
            for i in used]
    return f"{prefix}-{max(nums) + 1 if nums else 1}"


def dedupe_dicts(records: List[Dict[str, Any]], keys: Iterable[str]) -> List[Dict[str, Any]]:
    """Return *records* with duplicates (same key tuple) removed, first wins."""
    seen, out = set(), []
    for rec in records:
        k = tuple(rec.get(key) for key in keys)
        if k in seen:
            continue
        seen.add(k)
        out.append(rec)
    return out


@dataclass
class Event:
    """A single normalized telemetry record."""

    ts: float
    src: str
    channel: str
    signal: str
    severity: int
    raw: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Event":
        return Event(ts=d["ts"], src=d["src"], channel=d["channel"],
                     signal=d["signal"], severity=d["severity"],
                     raw=d.get("raw", ""), extra=d.get("extra", {}))


@dataclass
class Finding:
    """A detection produced by a detector plus IOL/MITRE enrichment."""

    rule: str
    signal: str
    src: str
    channel: str
    ts: float
    ts_end: float
    severity: int
    confidence: float
    evidence_ids: List[str]
    description: str = ""
    tactic: str = ""
    techniques: List[str] = field(default_factory=list)
    priority: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)  # asset, host, user, count, ...

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Finding":
        known = {k: d[k] for k in ("rule", "signal", "src", "channel", "ts", "ts_end",
                                   "severity", "confidence", "evidence_ids")}
        rest = {k: v for k, v in d.items() if k not in known}
        return Finding(**known, description=rest.pop("description", ""),
                       tactic=rest.pop("tactic", ""), techniques=rest.pop("techniques", []),
                       priority=rest.pop("priority", 0.0), extra=rest.pop("extra", {}))


@dataclass
class Incident:
    """A correlated multi-channel incident with kill-chain reconstruction."""

    id: str
    src: str
    findings: List[Dict[str, Any]]
    channels: List[str]
    ts_start: float
    ts_end: float
    stages: List[Dict[str, str]] = field(default_factory=list)  # [{stage,tactic,ts,signal}]
    victims: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    priority: float = 0.0
    status: str = "open"          # open | contained | eradicated | closed
    action_ids: List[str] = field(default_factory=list)
    evidence_paths: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Incident":
        known = {k: d[k] for k in ("id", "src", "channels", "ts_start", "ts_end")}
        rest = {k: v for k, v in d.items() if k not in known}
        return Incident(**known, findings=rest.pop("findings", []),
                        stages=rest.pop("stages", []), victims=rest.pop("victims", []),
                        users=rest.pop("users", []), priority=rest.pop("priority", 0.0),
                        status=rest.pop("status", "open"),
                        action_ids=rest.pop("action_ids", []),
                        evidence_paths=rest.pop("evidence_paths", []),
                        extra=rest.pop("extra", {}))


@dataclass
class RespondAction:
    """Result record of an executed/refused defensive response action."""

    id: str
    action: str
    target: str
    mode: str              # simulated | executed | refused
    status: str            # approved | denied | hard_refused | executed | simulated
    ts: float
    approval: str          # auto | ask | never
    detail: str = ""
    incident_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "RespondAction":
        known = {k: d[k] for k in ("id", "action", "target", "mode", "status", "ts", "approval")}
        rest = {k: v for k, v in d.items() if k not in known}
        return RespondAction(**known, detail=rest.pop("detail", ""),
                             incident_id=rest.pop("incident_id", ""))


@dataclass
class PlannerStep:
    """One step of an agent plan."""

    phase: str          # triage | contain | eradicate | recover | lessons
    action: Optional[str]
    target: Optional[str]
    rationale: str
    reflection: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)