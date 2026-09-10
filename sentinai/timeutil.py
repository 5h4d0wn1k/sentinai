"""Time parsing/formatting helpers (stdlib only)."""

from __future__ import annotations

import calendar
import datetime
import re

MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}
YEAR = 2026  # fixture epoch referenced from fixed year for determinism


def iso_to_epoch(iso: str) -> float:
    """ISO-8601 ('YYYY-MM-DDTHH:MM:SS[.f](Z|+HH:MM)') -> epoch seconds."""
    iso = iso.strip()
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def epoch_to_iso(ts: float) -> str:
    """Epoch seconds -> UTC ISO-8601 (second precision)."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_syslog_ts(text: str, year: int = YEAR) -> float:
    """Parse RFC-3164-style 'Sep 05 03:12:41' -> epoch seconds."""
    m = re.match(r"\s*([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", text)
    if not m:
        raise ValueError(f"unparseable syslog timestamp: {text!r}")
    mon, day, h, minute, s = m.groups()
    mon_num = MONTHS[mon.capitalize()]
    dt = datetime.datetime(year, mon_num, int(day), int(h), int(minute), int(s),
                           tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def maybe_epoch(value) -> Optional[float]:
    """Tolerate int/float/iso/syslog/none inputs to epoch."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and "T" in value:
        return iso_to_epoch(value)
    if isinstance(value, str):
        return parse_syslog_ts(value)
    raise ValueError(f"cannot parse timestamp: {value!r}")


def after_hours(ts: float) -> bool:
    """True when UTC hour is outside the 06:00-19:59 window."""
    hour = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).hour
    return hour < 6 or hour >= 20