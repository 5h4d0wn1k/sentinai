"""JSON-backed state store for the SOC pipeline.

The store owns two responsibilities:
1. bookkeeping (ids, counters, incident membership),
2. durable artifacts under `report_root` so every stage is reproducible:
   events.json, findings.json, incidents.json, actions.json, plans.json.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .models import Event, Finding, Incident, RespondAction, PlannerStep


class Store:
    def __init__(self, report_root: str, auto_persist: bool = True):
        self.root = os.path.abspath(report_root)
        self.auto = auto_persist
        self.events: List[Event] = []
        self.findings: List[Finding] = []
        self.incidents: List[Incident] = []
        self.actions: List[RespondAction] = []
        self.plans: List[PlannerStep] = []
        self.state: Dict[str, Any] = {
            "event_seq": 0, "finding_seq": 0, "incident_seq": 0, "action_seq": 0,
        }
        self.load()

    # ---- paths ---------------------------------------------------------
    @property
    def state_file(self) -> str:
        return os.path.join(self.root, "state.json")

    def _paths(self):
        return {
            "events": os.path.join(self.root, "events.json"),
            "findings": os.path.join(self.root, "findings.json"),
            "incidents": os.path.join(self.root, "incidents.json"),
            "actions": os.path.join(self.root, "actions.json"),
            "plans": os.path.join(self.root, "plans.json"),
        }

    # ---- persistence -----------------------------------------------------
    def load(self) -> None:
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                self.state = json.load(fh)
            # Reload collections lazily from json sidecars.
            ev = self._read_list("events.json")
            self.events = [Event.from_dict(x) for x in ev]
            fd = self._read_list("findings.json")
            self.findings = [Finding.from_dict(x) for x in fd]
            inc = self._read_list("incidents.json")
            self.incidents = [Incident.from_dict(x) for x in inc]
            act = self._read_list("actions.json")
            self.actions = [RespondAction.from_dict(x) for x in act]
            pl = self._read_list("plans.json")
            self.plans = [PlannerStep(**x) for x in pl]
        except Exception:
            # A corrupt sidecar should not brick the tool; start clean.
            self.state = {
                "event_seq": 0, "finding_seq": 0, "incident_seq": 0, "action_seq": 0,
            }

    def _read_list(self, name: str) -> List[Dict[str, Any]]:
        p = os.path.join(self.root, name)
        if not os.path.exists(p):
            return []
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def persist(self) -> None:
        os.makedirs(self.root, exist_ok=True)
        payload = {
            "events": [e.to_dict() for e in self.events],
            "findings": [f.to_dict() for f in self.findings],
            "incidents": [i.to_dict() for i in self.incidents],
            "actions": [a.to_dict() for a in self.actions],
            "plans": [p.to_dict() for p in self.plans],
        }
        for name, recs in payload.items():
            with open(os.path.join(self.root, f"{name}.json"), "w", encoding="utf-8") as fh:
                json.dump(recs, fh, indent=2, sort_keys=True)
        with open(self.state_file, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, indent=2, sort_keys=True)

    def _maybe_persist(self) -> None:
        if self.auto:
            self.persist()

    # ---- id + append helpers --------------------------------------------
    def add_event(self, event: Event) -> Event:
        self.state["event_seq"] += 1
        event.extra["eid"] = f"EVT-{self.state['event_seq']}"
        self.events.append(event)
        self._maybe_persist()
        return event

    def add_events(self, events: List[Event]) -> List[Event]:
        for e in events:
            self.add_event(e)
        return events

    def add_finding(self, finding: Finding) -> Finding:
        self.state["finding_seq"] += 1
        finding.extra["fid"] = f"DET-{self.state['finding_seq']}"
        self.findings.append(finding)
        self._maybe_persist()
        return finding

    def add_incident(self, incident: Incident) -> Incident:
        self.state["incident_seq"] += 1
        if not incident.id:
            incident.id = f"INS-{self.state['incident_seq']}"
        self.incidents.append(incident)
        self._maybe_persist()
        return incident

    def add_action(self, action: RespondAction) -> RespondAction:
        self.state["action_seq"] += 1
        if not action.id:
            action.id = f"ACT-{self.state['action_seq']}"
        self.actions.append(action)
        if action.incident_id:
            inc = self.get_incident(action.incident_id)
            if inc and action.id not in inc.action_ids:
                inc.action_ids.append(action.id)
        self._maybe_persist()
        return action

    def add_plan_steps(self, steps: List[PlannerStep]) -> None:
        self.plans.extend(steps)
        self._maybe_persist()

    # ---- lookups ---------------------------------------------------------
    def event_by_id(self, eid: str) -> Optional[Event]:
        for e in self.events:
            if e.extra.get("eid") == eid:
                return e
        return None

    def get_incident(self, iid: str) -> Optional[Incident]:
        for i in self.incidents:
            if i.id == iid:
                return i
        return None

    def incidents_for_src(self, src: str) -> List[Incident]:
        return [i for i in self.incidents if i.src == src]

    def evidence_ids_for(self, src: str) -> List[str]:
        return [e.extra["eid"] for e in self.events if e.src == src]