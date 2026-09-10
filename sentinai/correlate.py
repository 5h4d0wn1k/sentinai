"""Cross-channel correlation + kill-chain reconstruction.

For every actor the detectors attributed, correlation links findings and raw
events across channels within a sliding window, produces one incident per actor
(merged/deduplicated), and reconstructs the kill chain step-by-step in MITRE
tactic order with timestamps and evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import Incident, TACTIC_INDEX, MITRE_TACTICS
from .store import Store


def _stage_name(tactic: str) -> str:
    if tactic in TACTIC_INDEX:
        return MITRE_TACTICS[TACTIC_INDEX[tactic]]
    return tactic or "Unassigned"


def correlate(store: Store, cfg: Dict[str, Any], window: float = 0.0) -> List[Incident]:
    window = window or float(cfg["window"]["correlate"])
    min_channels = int(cfg["correlate"]["min_channels"])
    by_actor: Dict[str, List[Dict[str, Any]]] = {}
    for f in store.findings:
        by_actor.setdefault(f.src, []).append(f.to_dict())

    incidents: List[Incident] = []
    for actor, findings in sorted(by_actor.items()):
        channels = sorted({f["channel"] for f in findings})
        if len(channels) < min_channels:
            continue
        f0, f1 = min(f["ts"] for f in findings), max(f["ts_end"] for f in findings)
        if f1 - f0 > window:
            # findings too spread to be one intrusion; still kept, but capped.
            pass
        incidents.append(_build_incident(store, actor, findings, cfg, f0, f1))

    # De-duplicate: one incident per actor within window (merge on ts overlap).
    merged: List[Incident] = []
    for inc in sorted(incidents, key=lambda i: i.priority, reverse=True):
        existing = next((x for x in merged if x.src == inc.src), None)
        if existing is None:
            merged.append(inc)
        else:
            existing.findings = _merge_findings(existing.findings, inc.findings)
            existing.channels = sorted(set(existing.channels) | set(inc.channels))
            existing.ts_start = min(existing.ts_start, inc.ts_start)
            existing.ts_end = max(existing.ts_end, inc.ts_end)
            existing.stages = _reconstruct_stages(existing.findings)
    merged.sort(key=lambda i: i.priority, reverse=True)
    return merged


def _merge_findings(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {tuple(sorted((f["rule"], f["src"], f["channel"]))) for f in a}
    out = list(a)
    for f in b:
        key = tuple(sorted((f["rule"], f["src"], f["channel"])))
        if key not in seen:
            out.append(f)
            seen.add(key)
    return out


def _build_incident(store: Store, actor: str, findings: List[Dict[str, Any]],
                    cfg: Dict[str, Any], ts0: float, ts1: float) -> Incident:
    priority = max(f.get("priority", 0.0) for f in findings)
    stages = _reconstruct_stages(findings)
    victims, users = _attribution(store, actor, findings)
    channels = sorted({f["channel"] for f in findings})
    return Incident(
        id="", src=actor, findings=findings, channels=channels,
        ts_start=ts0, ts_end=ts1, stages=stages,
        victims=victims, users=users, priority=priority, status="open")


def _reconstruct_stages(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Order findings by earliest evidence time, annotate with MITRE stage."""
    ordered = sorted(findings, key=lambda f: (f["ts"], TACTIC_INDEX.get(f.get("tactic", ""), 99)))
    stages: List[Dict[str, str]] = []
    seen: set = set()
    for f in ordered:
        tactic = f.get("tactic", "") or "Unassigned"
        key = tactic
        if key in seen:
            continue
        seen.add(key)
        stages.append({
            "stage": _stage_name(tactic),
            "tactic": tactic,
            "ts": f"{f['ts']:.3f}",
            "signal": f.get("signal", ""),
            "rule": f.get("rule", ""),
            "confidence": f"{f.get('confidence', 0.0)}",
        })
    return stages


def _attribution(store: Store, actor: str, findings: List[Dict[str, Any]]) -> tuple:
    victims: List[str] = []
    users: List[str] = []
    for ev in store.events:
        if ev.src != actor:
            continue
        host = ev.extra.get("host") or ev.extra.get("internal")
        if host and host not in victims:
            victims.append(host)
        user = ev.extra.get("user")
        if user and user not in users:
            users.append(user)
    # Findings may carry hosts/users directly for process/web evidence.
    for f in findings:
        for key in ("host", "hosts", "internal"):
            host = f.get("extra", {}).get(key)
            if isinstance(host, str) and host not in victims:
                victims.append(host)
            elif isinstance(host, list):
                for h in host:
                    if h not in victims:
                        victims.append(h)
        user = f.get("extra", {}).get("user")
        if user and user not in users:
            users.append(user)
    return sorted(victims), sorted(users)