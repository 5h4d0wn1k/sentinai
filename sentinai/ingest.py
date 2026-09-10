"""Telemetry ingest providers (READ-ONLY).

Each provider parses a fixture feed into normalized :class:`Event` records.
The ingest layer never writes to its inputs: fixtures are opened read-only and
only system time/parse functions are used. Rails on the read-only contract are
tested in tests/test_ingest.py.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional

from .models import Event, rfc5737
from .timeutil import iso_to_epoch, parse_syslog_ts

# ---------------------------------------------------------------------------
# auth / sshd log (RFC-3164 style)
# ---------------------------------------------------------------------------

_AUTH_FAILED = re.compile(r"Failed password for (?:invalid user )?([^\s]+) from ([0-9.]+)")
_AUTH_ACCEPT = re.compile(r"Accepted password for ([^\s]+) from ([0-9.]+)")


def _auth_host(line: str) -> str:
    m = re.search(r"sshd\[\d+\]:", line)
    tail = line[len(line.split("sshd[", 1)[0]):] if line else line
    host = "edge1.lab.local"
    return host


def _auth_extra(user: str, host: str) -> Dict:
    return {"user": user, "host": host, "method": "ssh"}


def parse_auth_log(path: str, cfg: Dict[str, any]) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            ts = None
            try:
                ts = parse_syslog_ts(line)
            except ValueError:
                continue
            host = _auth_host(line)
            m = _AUTH_FAILED.search(line)
            if m:
                user, src = m.groups()
                events.append(Event(ts=ts, src=src, channel="auth", signal="ssh_failed",
                                    severity=2, raw=line, extra=_auth_extra(user, host)))
                continue
            m = _AUTH_ACCEPT.search(line)
            if m:
                user, src = m.groups()
                events.append(Event(ts=ts, src=src, channel="auth", signal="ssh_success",
                                    severity=1, raw=line, extra=_auth_extra(user, host)))
    return events


# ---------------------------------------------------------------------------
# web access log (combined format)
# ---------------------------------------------------------------------------

_WEB_TS = re.compile(r"\[([^]]+)\]")
_WEB_LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"')


def parse_apache_ts(text: str) -> float:
    """Parse Apache '%d/%b/%Y:%H:%M:%S %z' -> epoch (stdlib only)."""
    from .timeutil import MONTHS
    m = re.match(r"(\d{2})/(\S{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})", text.strip())
    if not m:
        from .timeutil import iso_to_epoch
        return iso_to_epoch(text)
    day, mon, year, h, minute, s, tz = m.groups()
    mon_num = MONTHS[mon.capitalize()]
    import datetime
    offset_min = int(tz[1:3]) * 60 + int(tz[3:5])
    sign = 1 if tz[0] == "+" else -1
    dt = datetime.datetime(int(year), mon_num, int(day), int(h), int(minute), int(s),
                           tzinfo=datetime.timezone(sign * datetime.timedelta(minutes=offset_min)))
    return dt.timestamp()


def parse_access_log(path: str, cfg: Dict[str, any]) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = _WEB_LINE.match(line)
            if not m:
                continue
            src, ts_raw, request, status, size, referer, ua = m.groups()
            ts = parse_apache_ts(ts_raw)
            method, _, rest = request.partition(" ")
            url_with_http = rest.rpartition(" HTTP/")[0] if " HTTP/" in rest else rest
            url = f"{method} {url_with_http}".strip()
            events.append(Event(
                ts=ts, src=src, channel="web", signal="web_request", severity=1,
                raw=line,
                extra={"host": "web1.lab.local", "url": url, "method": method,
                       "path": url_with_http, "status": int(status), "ua": ua}))
    return events


# ---------------------------------------------------------------------------
# process list (ps-style table)
# ---------------------------------------------------------------------------

_PROC_HEADER = re.compile(r"^\s*PID\s+PPID")


def parse_process_list(path: str, cfg: Dict[str, any]) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or _PROC_HEADER.match(line):
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            pid, ppid, user, stat, start = parts[:5]
            command = " ".join(parts[5:])
            exe = command.split()[0] if command.split() else ""
            try:
                ts = parse_syslog_ts(f"Sep 05 {start}")
            except ValueError:
                ts = parse_syslog_ts("Sep 05 00:00:00")
            events.append(Event(
                ts=ts, src="web1.lab.local", channel="process", signal="proc_running",
                severity=1, raw=line,
                extra={"host": "web1.lab.local", "pid": int(pid), "ppid": int(ppid),
                       "user": user, "command": command, "exe": exe, "start": start}))
    return events


# ---------------------------------------------------------------------------
# network flow log (CSV: ts,src,dst,dport,bytes,pkts)
# ---------------------------------------------------------------------------

def parse_flow_log(path: str, cfg: Dict[str, any]) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line or line.startswith("ts,") or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 6:
                continue
            ts_raw, src, dst, dport, bytes_, pkts = parts[:6]
            try:
                ts = iso_to_epoch(ts_raw) if "T" in ts_raw else float(ts_raw)
            except ValueError:
                continue
            internal = src if rfc5737(dst) else dst
            actor = dst if rfc5737(dst) else src
            events.append(Event(
                ts=ts, src=actor, channel="flow", signal="flow_connection",
                severity=1, raw=line,
                extra={"internal": internal, "dst": dst, "src": src,
                       "dport": int(dport), "bytes": int(bytes_), "pkts": int(pkts)}))
    return events


# ---------------------------------------------------------------------------
# alert feed (netsentinel-style JSON Lines)
# ---------------------------------------------------------------------------

def parse_alert_feed(path: str, cfg: Dict[str, any]) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = iso_to_epoch(rec.get("ts", "")) if rec.get("ts") else 0.0
            rule = rec.get("rule", "unknown")
            events.append(Event(
                ts=ts, src=rec.get("src", "0.0.0.0"), channel="alert",
                signal=f"alert_{rule}", severity=int(rec.get("severity", 2)),
                raw=line,
                extra={"host": rec.get("host", ""), "rule": rule,
                       "msg": rec.get("msg", "")}))
    return events


# ---------------------------------------------------------------------------
# registry / loader
# ---------------------------------------------------------------------------

PROVIDERS = {
    "auth.log": parse_auth_log,
    "access.log": parse_access_log,
    "processes.txt": parse_process_list,
    "flows.txt": parse_flow_log,
    "alerts.jsonl": parse_alert_feed,
}


def ingest_fixtures(fixtures_dir: str, cfg: Dict[str, any],
                    selected: Optional[List[str]] = None) -> List[Event]:
    """Load every feed under *fixtures_dir* (or a subset by filename) read-only."""
    events: List[Event] = []
    for fname, fn in PROVIDERS.items():
        if selected and fname not in selected:
            continue
        path = os.path.join(fixtures_dir, fname)
        if not os.path.exists(path):
            continue
        events.extend(fn(path, cfg))
    events.sort(key=lambda e: e.ts)
    return events


def channel_counts(events: Iterable[Event]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for ev in events:
        counts[ev.channel] = counts.get(ev.channel, 0) + 1
    return counts