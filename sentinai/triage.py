"""Autonomous prioritizer (triage).

Priority = severity x asset value x kill-chain stage weight. Findings are
de-duplicated and grouped by actor (src) so the correlator and planner work on
the highest-signal subset.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import Finding


def asset_value(finding: Finding, cfg: Dict[str, Any]) -> int:
    assets = cfg.get("assets", {})
    default = cfg.get("asset_default", 2)
    hosts = finding.extra.get("hosts") or finding.extra.get("host")
    if isinstance(hosts, str):
        hosts = [hosts]
    if not hosts:
        hosts = finding.extra.get("internal")
        if isinstance(hosts, str):
            hosts = [hosts]
    values = [assets.get(h, default) for h in (hosts or [default])]
    # Prefer the most critical asset involved.
    return max(values) if values else default


def stage_factor(finding: Finding, cfg: Dict[str, Any]) -> float:
    weights = cfg.get("stage_weights", {})
    return float(weights.get(finding.tactic or "", 1.0))


def score(finding: Finding, cfg: Dict[str, Any]) -> float:
    """Deterministic priority score for a finding."""
    sev = float(clsamp(finding.severity, 1, 5))
    asset = float(asset_value(finding, cfg))
    stage = stage_factor(finding, cfg)
    return round(sev * asset * stage, 3)


def clsamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def dedupe(findings: List[Finding], cfg: Dict[str, Any]) -> List[Finding]:
    """Drop findings that duplicate (rule, src, channel) keeping the strongest."""
    seen: Dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule, f.src, f.channel)
        prev = seen.get(key)
        if prev is None or score(f, cfg) > score(prev, cfg):
            seen[key] = f
    return list(seen.values())


def triage(findings: List[Finding], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Assign priorities, dedupe, group by actor; return ordered result set."""
    for f in findings:
        f.priority = score(f, cfg)
    findings = dedupe(findings, cfg)
    ordered = sorted(findings, key=lambda f: (f.priority, f.ts, f.signal), reverse=True)
    grouped: Dict[str, List[Finding]] = {}
    for f in ordered:
        grouped.setdefault(f.src, []).append(f)
    return {"ordered": ordered, "grouped": grouped}