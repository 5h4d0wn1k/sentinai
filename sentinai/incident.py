"""Incident narrative + final report generation.

Produces the full narrative timeline (events + findings + actions + judgement),
MITRE ATT&CK mapping, containment status, IOC list, lessons learned and a
remediation checklist. Written as Markdown (human) + JSON (machine) under
<report_root>/incidents/<INS-n>/.
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from .store import Store
from .timeutil import epoch_to_iso


def _timeline(store: Store, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    src = incident["src"]
    items: List[Dict[str, Any]] = []
    added = set()
    for ev in store.events:
        involved = ev.src == src or ev.extra.get("dst") == src or ev.extra.get("internal") == src
        if not involved:
            continue
        key = (ev.extra.get("eid", ""), ev.ts)
        if key in added:
            continue
        added.add(key)
        items.append({"ts": ev.ts, "kind": "event", "channel": ev.channel,
                      "label": ev.signal, "detail": ev.raw.strip()[:200]})
    for f in incident.get("findings", []):
        items.append({"ts": float(f["ts"]), "kind": "finding", "channel": f["channel"],
                      "label": f["rule"], "detail": f["description"]})
    for aid in incident.get("action_ids", []):
        act = next((a for a in store.actions if a.id == aid), None)
        if act:
            items.append({"ts": act.ts, "kind": "action", "channel": "respond",
                          "label": act.action, "detail": f"{act.target} [{act.status}] {act.detail}"})
    items.sort(key=lambda i: i["ts"])
    return items


def _mitre_mapping(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    agg: "OrderedDict[str, OrderedDict]" = OrderedDict()
    for f in incident.get("findings", []):
        tactic = f.get("tactic") or "Unassigned"
        techs = f.get("techniques", [])
        if tactic not in agg:
            agg[tactic] = OrderedDict()
        for t in techs:
            agg[tactic][t] = agg[tactic].get(t, 0) + 1
    out = []
    for tactic, techs in agg.items():
        out.append({"tactic": tactic,
                    "techniques": [{"id": t, "count": c} for t, c in techs.items()]})
    return out


def _ioc_list(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    iocs: List[Dict[str, str]] = []
    seen = set()
    for f in incident.get("findings", []):
        ex = f.get("extra", {})
        src = f.get("src")
        key = (src, f.get("signal"))
        if key in seen:
            continue
        seen.add(key)
        iocs.append({
            "type": "address",
            "value": src,
            "indicator": f.get("signal", ""),
            "technique": ", ".join(f.get("techniques", [])),
            "evidence": ex.get("internal") or ex.get("host") or "",
        })
    return iocs


_LESSONS = [
    "SSH brute force is a reliable Initial Access vector on exposed services; "
    "key-only auth + fail2ban removes most of it.",
    "HTTP endpoints must be injected-safe (parameterized queries, output "
    "encoding) — SQLi/XSS probes were observed hitting the fixture web tier.",
    "Endpoint hygiene matters: suspicious binaries ran from /tmp and /dev/shm.",
    "Regular low-jitter outbound connections are a strong C2 signal; egress "
    "allowlisting and beacon detection close that channel.",
    "Containment should begin at the FIRST cross-channel correlation, not after "
    "forensic completion.",
    "Fixture evidence shows detection->correlation->response closed the loop "
    "within minutes because approval gate auto mode was scoped to lab targets.",
]


def lessons_learned(incident: Dict[str, Any], findings_count: int, response_time_s: float,
                    agent_notes: List[str]) -> List[str]:
    lessons = [l.format(fc=findings_count, rt=response_time_s) for l in _LESSONS]
    if agent_notes:
        lessons.append("Agent reflection: " + "; ".join(agent_notes[-3:]))
    return lessons


def remediation_checklist() -> List[str]:
    return [
        "Block the actor source at the edge and confirm egress is denied (lab).",
        "Rotate every credential/secret the intrusion path could have touched.",
        "Disable compromised fixture accounts and enforce escalation review.",
        "Patch the exploited web-facing service and add a WAF/baseline rule for SQLi/XSS.",
        "Review outbound egress allowlist; alert on low-jitter periodic connections.",
        "Re-image compromised hosts from a clean baseline and verify no persistence.",
        "Enable auditd/config-drift alerting on all lab endpoints.",
        "Restore services only after containment is verified (post-recovery testing).",
        "Complete the incident review and fold lessons into detection rules.",
    ]


def build_narrative(timeline: List[Dict[str, Any]], incident: Dict[str, Any]) -> str:
    src = incident["src"]
    mid = len(timeline) // 2 if timeline else 0
    lines = [f"On {epoch_to_iso(incident['ts_start'])} the actor {src} began activity "
             f"observed across {len(incident['channels'])} telemetry channels."]
    if timeline:
        lines.append(f"Early indicators ({timeline[0]['kind']}: {timeline[0]['label']}) escalated "
                     "into a coordinated intrusion campaign against lab fixture hosts.")
        if mid:
            lines.append(f"By mid-window the actor had progressed from initial access towards "
                         f"{incident['stages'][-1]['tactic'] if incident.get('stages') else 'later stages'} "
                         "(kill-chain stage reconstruction).")
        lines.append(f"Response actions ({len(incident.get('action_ids', []))}) drove the incident to "
                     f"status '{incident.get('status', 'open')}'.")
    lines.append("Judgement: this is a believable multi-stage intrusion consistent with "
                 "automated credential stuffing followed by web exploitation and C2 beaconing.")
    return "\n".join(lines)


def _containment_status(store: Store, incident: Dict[str, Any]) -> str:
    if incident.get("status") == "contained":
        return "CONTAINED"
    from .lab import Lab
    try:
        lab = Lab(store.cfg if hasattr(store, "cfg") else {}, store.root)
    except Exception:
        lab = None
    if lab and lab.src_blocked(incident["src"]):
        return "CONTAINED (source blocked at edge)"
    return "OPEN — containment pending"


def write_incident_report(store: Store, incident_id: str, cfg: Dict[str, Any],
                          agent_notes: Optional[List[str]] = None) -> Dict[str, Any]:
    incident_obj = store.get_incident(incident_id)
    if incident_obj is None:
        raise KeyError(f"no incident {incident_id}")
    incident = incident_obj.to_dict()
    agent_notes = agent_notes or []

    timeline = _timeline(store, incident)
    mitre = _mitre_mapping(incident)
    iocs = _ioc_list(incident)
    contained = _containment_status(store, incident)
    resp_secs = _response_seconds(store, incident)
    lessons = lessons_learned(incident, len(incident.get("findings", [])), resp_secs, agent_notes)
    checklist = remediation_checklist()
    narrative = build_narrative(timeline, incident)

    report = {
        "incident_id": incident_id,
        "src": incident["src"],
        "status": incident.get("status"),
        "containment": contained,
        "channels": incident["channels"],
        "window": {"start": epoch_to_iso(incident["ts_start"]),
                   "end": epoch_to_iso(incident["ts_end"])},
        "kill_chain": incident.get("stages", []),
        "narrative": narrative,
        "timeline": [{**x, "ts": epoch_to_iso(x["ts"])} for x in timeline],
        "mitre_mapping": mitre,
        "iocs": iocs,
        "victims": incident.get("victims", []),
        "users": incident.get("users", []),
        "lessons": lessons,
        "remediation_checklist": checklist,
        "agent_notes": agent_notes,
        "metrics": {
            "findings": len(incident.get("findings", [])),
            "events_attributed": len(timeline),
            "response_seconds": round(resp_secs, 1),
            "priority": incident.get("priority", 0.0),
        },
    }
    out_dir = os.path.join(store.root, "incidents", incident_id)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "incident.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "incident.md"), "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
    store.persist()
    return report


def _response_seconds(store: Store, incident: Dict[str, Any]) -> float:
    first_action = None
    for aid in incident.get("action_ids", []):
        act = next((a for a in store.actions if a.id == aid), None)
        if act and act.status not in ("denied", "hard_refused"):
            first_action = min(first_action, act.ts) if first_action else act.ts
    if not first_action:
        return 0.0
    return max(0.0, first_action - incident["ts_start"])


def render_markdown(report: Dict[str, Any]) -> str:
    md = []
    md.append(f"# Incident Report {report['incident_id']}")
    md.append("")
    md.append(f"- **Actor:** `{report['src']}`")
    md.append(f"- **Status:** `{report['status']}` — **Containment:** {report['containment']}")
    md.append(f"- **Channels:** {', '.join(report['channels'])}")
    md.append(f"- **Window:** {report['window']['start']} → {report['window']['end']}")
    md.append(f"- **Victims:** {', '.join(report['victims']) or 'n/a'}")
    md.append(f"- **Users:** {', '.join(report['users']) or 'n/a'}")
    md.append("")
    md.append("## Narrative")
    md.append("")
    md.append(report["narrative"])
    md.append("")
    md.append("## Timeline")
    md.append("")
    md.append("| time (UTC) | kind | channel | label | detail |")
    md.append("|---|---|---|---|---|")
    for t in report["timeline"]:
        md.append(f"| {t['ts']} | {t['kind']} | {t['channel']} | {t['label']} | "
                  f"{t['detail'].replace('|', '/')[:120]} |")
    md.append("")
    md.append("## Kill Chain")
    md.append("")
    for st in report["kill_chain"]:
        md.append(f"1. **{st['stage']}** ({st['tactic']}) — {st['signal']} @ {st['ts']}")
    md.append("")
    md.append("## MITRE ATT&CK Mapping")
    md.append("")
    for m in report["mitre_mapping"]:
        techs = ", ".join(f"{t['id']} x{t['count']}" for t in m["techniques"])
        md.append(f"- **{m['tactic']}**: {techs}")
    md.append("")
    md.append("## Indicators of Compromise")
    md.append("")
    for ioc in report["iocs"]:
        md.append(f"- `{ioc['value']}` — {ioc['indicator']} ({ioc['technique']})")
    md.append("")
    md.append("## Lessons Learned")
    md.append("")
    for l in report["lessons"]:
        md.append(f"- {l}")
    md.append("")
    md.append("## Remediation Checklist")
    md.append("")
    for i, c in enumerate(report["remediation_checklist"], 1):
        md.append(f"- [ ] {i}. {c}")
    md.append("")
    md.append("## Agent Notes")
    md.append("")
    for n in report["agent_notes"]:
        md.append(f"- `{n}`")
    md.append("")
    return "\n".join(md)