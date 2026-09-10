"""Detection + enrichment: indicators-of-attack -> MITRE ATT&CK mapping.

Detectors are pure functions over :class:`Event` lists. They produce
:class:`Finding` records; the IOL table (fixtures/iol.json with embedded
fallback) decorates each finding with MITRE tactic + technique ids used by the
kill-chain reconstruction and the incident MITRE mapping.
"""

from __future__ import annotations

import json
import os
import re
import statistics
from typing import Any, Dict, List, Optional

from .models import Event, Finding, rfc5737, TACTIC_INDEX
from .timeutil import after_hours

# ---------------------------------------------------------------------------
# IOL fixture mapping table (signal -> MITRE)
# ---------------------------------------------------------------------------

IOL_FALLBACK: Dict[str, Dict[str, Any]] = {
    "brute_force": {"tactic": "Initial Access", "techniques": ["T1110", "T1078"]},
    "root_login": {"tactic": "Initial Access", "techniques": ["T1078"]},
    "web_sqli": {"tactic": "Initial Access", "techniques": ["T1190"]},
    "web_xss": {"tactic": "Execution", "techniques": ["T1059"]},
    "proc_suspicious": {"tactic": "Execution", "techniques": ["T1059"]},
    "proc_unusual_path": {"tactic": "Persistence", "techniques": ["T1036"]},
    "flow_beacon": {"tactic": "Command and Control", "techniques": ["T1071.001"]},
    "flow_scan": {"tactic": "Discovery", "techniques": ["T1046"]},
    "alert_C2_BEACON": {"tactic": "Command and Control", "techniques": ["T1071.001"]},
    "alert_IDS_SQLI": {"tactic": "Initial Access", "techniques": ["T1190"]},
    "alert_IDS_SCAN": {"tactic": "Discovery", "techniques": ["T1046"]},
}


def load_iol(fixtures_dir: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    if fixtures_dir:
        path = os.path.join(fixtures_dir, "iol.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
    return dict(IOL_FALLBACK)


def enrich_iol(finding: Finding, iol: Dict[str, Dict[str, Any]]) -> Finding:
    hit = iol.get(finding.signal) or iol.get(f"alert_{finding.signal}")
    if hit:
        finding.tactic = hit.get("tactic", "")
        finding.techniques = list(hit.get("techniques", []))
    return finding


def tactic_from_alert(rule: str, iol: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for key, val in iol.items():
        if key.startswith("alert_") and rule in key:
            return val
    return None


# ---------------------------------------------------------------------------
# Detector helpers
# ---------------------------------------------------------------------------

def _eids(events: List[Event]) -> List[str]:
    return [e.extra.get("eid", "") for e in events]


def _extract_rfc5737(text: str) -> Optional[str]:
    for m in re.finditer(r"\b(192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3})\b",
                         text or ""):
        return m.group(1)
    # tolerate private-lab host labels used by own sinkholes
    return None


_BAD_EXE_NAMES = ("xmrig", "kdevtmpfsi", "kinsing", "c3pool", "miner", "pwns",
                  "masscan", "cryptominer", "b", "jse", "sslh")


def is_unusual_path(exe: str) -> bool:
    return bool(re.search(r"(?:^|/)(?:tmp|dev/shm|var/tmp|\.cache|\.ssh)(?:/|$)", exe or ""))


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_ssh_brute(events: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    window = cfg["window"]["ssh"]
    min_fail = cfg["thresholds"]["ssh_failed_min"]
    by_src: Dict[str, List[Event]] = {}
    for ev in events:
        if ev.channel == "auth" and ev.signal == "ssh_failed":
            by_src.setdefault(ev.src, []).append(ev)
    for src, evs in sorted(by_src.items()):
        evs.sort(key=lambda e: e.ts)
        start = evs[0].ts
        burst = [e for e in evs if e.ts <= start + window]
        if len(burst) >= min_fail:
            sev = max(e.severity for e in burst)
            if cfg["thresholds"]["after_hours"] and any(after_hours(e.ts) for e in burst):
                sev = min(5, sev + 1)
            hosts = sorted({e.extra.get("host", "") for e in burst})
            users = sorted({e.extra.get("user", "") for e in burst})
            out.append(Finding(
                rule="ssh-brute", signal="brute_force", src=src, channel="auth",
                ts=start, ts_end=burst[-1].ts, severity=sev, confidence=0.9,
                evidence_ids=_eids(burst),
                description=f"SSH brute force: {len(burst)} failed logins from {src}",
                extra={"count": len(burst), "hosts": hosts, "users": users}))
    return out


def detect_root_login(events: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for ev in events:
        if ev.channel == "auth" and ev.signal == "ssh_success" and ev.extra.get("user") == "root":
            out.append(Finding(
                rule="ssh-root-login", signal="root_login", src=ev.src, channel="auth",
                ts=ev.ts, ts_end=ev.ts, severity=5, confidence=0.95,
                evidence_ids=[ev.extra.get("eid", "")],
                description=f"Successful root SSH login from {ev.src}", extra={}))
    return out


_SQLI = re.compile(
    r"(union[^a-z]*select|\bselect[^a-z]*(?:from|where)|%27|\b(?:or|and)\b[^a-z1-9]*['\"]?"
    r"\d|--\s|/\*.*?\*/|\bsleep\s*\(|\bbenchmark\s*\(|information_schema|0x[0-9a-f]{6,})",
    re.IGNORECASE)
_XSS = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|<img\b[^>]*on)",
                  re.IGNORECASE)


def detect_web_attack(events: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for ev in events:
        if ev.channel != "web":
            continue
        url = ev.extra.get("url", "")
        sev = ev.severity
        if cfg["thresholds"]["web_sqli"] and _SQLI.search(url):
            if int(ev.extra.get("status", 0)) >= 500:
                sev = max(sev, 4)
            out.append(Finding(
                rule="web-attack", signal="web_sqli", src=ev.src, channel="web",
                ts=ev.ts, ts_end=ev.ts, severity=sev, confidence=0.85,
                evidence_ids=[ev.extra.get("eid", "")],
                description=f"SQLi probe in web request from {ev.src}",
                extra={"status": ev.extra.get("status"), "url": url,
                       "host": ev.extra.get("host")}))
        if cfg["thresholds"]["web_xss"] and _XSS.search(url):
            out.append(Finding(
                rule="web-attack", signal="web_xss", src=ev.src, channel="web",
                ts=ev.ts, ts_end=ev.ts, severity=max(sev, 3), confidence=0.8,
                evidence_ids=[ev.extra.get("eid", "")],
                description=f"XSS payload in web request from {ev.src}",
                extra={"status": ev.extra.get("status"), "url": url,
                       "host": ev.extra.get("host")}))
    return out


def detect_process(events: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for ev in events:
        if ev.channel != "process":
            continue
        command = ev.extra.get("command", "")
        exe = (command.split() or [""])[0]
        tokens = command.split()
        bad_name = any(n in tok for tok in tokens for n in _BAD_EXE_NAMES)
        unusual = any(is_unusual_path(tok) for tok in tokens if tok.startswith("/"))
        actor = _extract_rfc5737(command) or ev.src
        if bad_name or unusual:
            out.append(Finding(
                rule="process-suspicious", signal="proc_suspicious", src=actor,
                channel="process", ts=ev.ts, ts_end=ev.ts, severity=4,
                confidence=0.88 if bad_name else 0.7,
                evidence_ids=[ev.extra.get("eid", "")],
                description=f"Suspicious process {os.path.basename(exe)!r} on {ev.extra.get('host')}",
                extra={"exe": exe, "command": command, "user": ev.extra.get("user"),
                       "host": ev.extra.get("host"), "pid": ev.extra.get("pid"),
                       "bad_name": bad_name, "unusual_path": unusual}))
    return out


def detect_flow(events: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    flows = [ev for ev in events if ev.channel == "flow"]
    beacon_win = cfg["window"]["beacon"]
    scan_win = cfg["window"]["scan"]

    # Beaconing: actor -> internal, regular high-egress rhythm.
    by_pair: Dict[tuple, List[Event]] = {}
    for ev in flows:
        by_pair.setdefault((ev.src, ev.extra.get("internal", ""), ev.extra.get("dport", "")),
                           []).append(ev)
    for (src, internal, dport), evs in by_pair.items():
        evs.sort(key=lambda e: e.ts)
        if len(evs) < max(2, cfg["thresholds"]["beacons_min"]):
            continue
        if evs[-1].ts - evs[0].ts > beacon_win:
            continue
        gaps = [b.ts - a.ts for a, b in zip(evs, evs[1:]) if b.ts - a.ts > 0]
        if not gaps:
            continue
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        regularity = statistics.pstdev(gaps) / mean
        avg_bytes = statistics.mean(e.extra.get("bytes", 0) for e in evs)
        if regularity <= cfg["thresholds"]["beacon_regularity"] and \
                avg_bytes >= cfg["thresholds"]["beacon_bytes_min"]:
            out.append(Finding(
                rule="flow-beacon", signal="flow_beacon", src=src, channel="flow",
                ts=evs[0].ts, ts_end=evs[-1].ts, severity=4, confidence=0.85,
                evidence_ids=_eids(evs),
                description=f"Regular high-egress beaconing {internal} -> {src}:{dport}",
                extra={"internal": internal, "dport": dport, "count": len(evs),
                       "regularity": round(regularity, 3),
                       "avg_bytes": int(avg_bytes)}))

    # Port spanning: actor sprays many distinct dst ports at one internal host.
    by_scanner: Dict[str, List[Event]] = {}
    for ev in flows:
        by_scanner.setdefault(ev.src, []).append(ev)
    for src, evs in by_scanner.items():
        by_internal: Dict[str, List[Event]] = {}
        for ev in evs:
            by_internal.setdefault(ev.extra.get("internal", ""), []).append(ev)
        for internal, grp in by_internal.items():
            grp.sort(key=lambda e: e.ts)
            if grp[-1].ts - grp[0].ts > scan_win:
                continue
            ports = {e.extra.get("dport") for e in grp}
            if len(ports) >= cfg["thresholds"]["scan_min_ports"]:
                out.append(Finding(
                    rule="flow-port-scan", signal="flow_scan", src=src, channel="flow",
                    ts=grp[0].ts, ts_end=grp[-1].ts, severity=3, confidence=0.8,
                    evidence_ids=_eids(grp),
                    description=f"Port scan: {src} hit {len(ports)} ports on {internal}",
                    extra={"internal": internal, "ports": len(ports)}))

    # De-duplicate by (rule,src) preferring strongest finding.
    seen: set = set()
    dedup: List[Finding] = []
    for f in sorted(out, key=lambda x: (x.rule, x.src, -x.severity)):
        if (f.rule, f.src) in seen:
            continue
        seen.add((f.rule, f.src))
        dedup.append(f)
    return dedup


def run_all(events: List[Event], cfg: Dict[str, Any],
            iol: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Finding]:
    """Run every detector, then decorate with IOL/MITRE mapping."""
    iol = iol or load_iol()
    findings: List[Finding] = []
    for fn in (detect_ssh_brute, detect_root_login, detect_web_attack,
               detect_process, detect_flow):
        for f in fn(events, cfg):
            enrich_iol(f, iol)
            findings.append(f)

    # Alert feed signals are second-hand detection events -> promote to findings.
    for ev in events:
        if ev.channel == "alert":
            hit = tactic_from_alert(ev.signal, iol)
            if hit:
                findings.append(Finding(
                    rule="alert-feed", signal=ev.signal, src=ev.src, channel="alert",
                    ts=ev.ts, ts_end=ev.ts, severity=ev.severity, confidence=0.7,
                    evidence_ids=[ev.extra.get("eid", "")],
                    description=ev.extra.get("msg", f"alert {ev.signal} from {ev.src}"),
                    tactic=hit.get("tactic", ""), techniques=hit.get("techniques", []),
                    extra={"host": ev.extra.get("host"), "rule": ev.extra.get("rule")}))
    return findings