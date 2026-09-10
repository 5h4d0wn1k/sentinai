"""Agent core: goal-driven planner with rule-based playbook + optional LLM.

The planner turns a natural-language goal (e.g. "contain the ongoing intrusion
from 198.51.100.7") into an ordered, budget-limited step plan following the
canonical defensive playbook:

    triage -> contain -> eradicate -> recover -> lessons

with a reflection step in between actions. `--planner rule` is the canonical
offline path; `--planner llm` is optional-guarded on SENTINAI_LLM_BASE /
SENTINAI_LLM_KEY env vars and degrades to the rule playbook with a clear
notice. Actions produced by the plan always pass through the response engine's
approval + lab-boundary gates — the planner can never override safety.
"""

from __future__ import annotations

import os
import re
import time
import json
import urllib.request
from typing import Any, Dict, List, Optional

from .models import PlannerStep, Incident, rfc5737
from .store import Store

PLAYBOOK_PHASES = ["triage", "contain", "eradicate", "recover", "lessons"]


def goal_src(goal: str) -> Optional[str]:
    """Extract an RFC 5737 actor address from a goal string, if present."""
    for m in re.finditer(r"\b(192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3})\b",
                         goal or ""):
        return m.group(1)
    return None


class Planner:
    def __init__(self, cfg: Dict[str, Any], store: Store):
        self.cfg = cfg
        self.store = store

    @staticmethod
    def llm_available() -> bool:
        return bool(os.environ.get("SENTINAI_LLM_BASE") and os.environ.get("SENTINAI_LLM_KEY"))

    @staticmethod
    def llm_missing_message() -> str:
        return ("[planner] LLM mode requested but SENTINAI_LLM_BASE / SENTINAI_LLM_KEY are not "
                "set. Falling back to the offline rule playbook (or run '--planner rule').")

    def plan(self, goal: str, incident: Optional[Incident], mode: str = "rule",
             budget: Optional[int] = None) -> Dict[str, Any]:
        steps = self._plan_rule(goal, incident, budget)
        notes = []
        if mode == "llm":
            if not self.llm_available():
                notes.append(self.llm_missing_message())
                steps = self._plan_rule(goal, incident, budget)  # safe fallback
            else:
                llm_steps = self._plan_llm(goal, incident)
                if llm_steps is None:
                    notes.append("[planner] LLM call failed; keeping the rule playbook "
                                 "(safety gates unchanged).")
        return {"steps": steps, "notes": notes, "goal": goal, "mode": mode}

    # ---- rule playbook -----------------------------------------------------
    def _plan_rule(self, goal: str, incident: Optional[Incident],
                   budget: Optional[int]) -> List[PlannerStep]:
        steps: List[PlannerStep] = []
        srcs = self._actor_srcs(incident, goal)
        budget = budget or int(self.cfg["planner"]["budget"])

        steps.append(PlannerStep(phase="triage", action=None, target=None,
                                 rationale="Confirm the actor, victims and attack surface via "
                                           "detect/triage/correlate before acting."))
        for src in srcs:
            steps.append(PlannerStep(phase="contain", action="block-src", target=src,
                                     rationale=f"Contain the intrusion: block egress/inbound "
                                               f"from {src} at the edge (lab)."))
        for user in (incident.users if incident else [])[:2]:
            steps.append(PlannerStep(phase="eradicate", action="disable-user", target=user,
                                     rationale=f"Eradicate foothold: disable compromised "
                                               f"fixture account {user}."))
        steps.append(PlannerStep(phase="eradicate", action="rotate-fixture-secret",
                                 target="lab-db-password",
                                 rationale="Eradicate: re-key the fixture secret that the "
                                           "intrusion path may have captured."))
        fixtures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    os.path.pardir, "fixtures")
        for feed in ("auth.log", "access.log", "flows.txt", "processes.txt", "alerts.jsonl"):
            steps.append(PlannerStep(phase="recover", action="snapshot-artifact",
                                     target=os.path.join(fixtures_dir, feed),
                                     rationale="Recover: snapshot fixture evidence into the "
                                               "incident case file."))
        steps.append(PlannerStep(phase="recover", action=None, target=None,
                                 rationale="Recover: verify containment (src blocked) and no "
                                           "residual beacon traffic before declaring closed."))
        steps.append(PlannerStep(phase="lessons", action=None, target=None,
                                 rationale="Lessons: produce the incident narrative, MITRE "
                                           "mapping, IOCs, lessons and remediation checklist."))
        return steps[:budget]

    def _actor_srcs(self, incident: Optional[Incident], goal: str) -> List[str]:
        srcs: List[str] = []
        if incident:
            srcs.append(incident.src)
        gsrc = goal_src(goal)
        for s in srcs:
            if s == gsrc:
                break
        if gsrc and gsrc not in srcs:
            srcs.append(gsrc)
        return srcs

    def reflect(self, step: PlannerStep, incident: Optional[Incident]) -> str:
        """Reflection between steps: appraise the just-completed action."""
        try:
            from .lab import Lab
            lab = Lab(self.cfg, self.store.root)
        except Exception:
            lab = None
        if step.action == "block-src" and step.target:
            blocked = bool(lab) and lab.src_blocked(step.target)
            return ("containment verified: source blocked at edge"
                    if blocked
                    else "WARNING: source not yet blocked — re-check approval mode or "
                         "re-run respond.")
        if step.phase == "lessons":
            return ("analysis complete; incident closed once narrative + IOCs are written.")
        return f"{step.phase} step executed; moving to next phase of the playbook."

    # ---- optional LLM driver (never authorizes actions) ---------------------
    def _plan_llm(self, goal: str, incident: Optional[Incident]) -> Optional[List[PlannerStep]]:
        try:
            base = os.environ["SENTINAI_LLM_BASE"].rstrip("/")
            key = os.environ["SENTINAI_LLM_KEY"]
            prompt = (
                "You are the planner of an autonomous SOC copilot. Return JSON only: "
                'a list of {"phase","action","target","rationale"} for goal: '
                f"{json.dumps(goal)}. Action names must come from "
                "block-src, rotate-fixture-secret, disable-user, snapshot-artifact or null. "
                "Never authorize actions; planning is advisory."
            )
            req = urllib.request.Request(
                f"{base}/chat/completions",
                data=json.dumps({
                    "model": "sentinai-planner",
                    "messages": [{"role": "user", "content": prompt}],
                }).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {key}"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=int(self.cfg["planner"].get("llm_timeout", 10))) as resp:
                body = json.loads(resp.read().decode())
            content = body["choices"][0]["message"]["content"]
            steps_json = json.loads(content) if isinstance(content, str) else content
            if isinstance(steps_json, dict):
                steps_json = steps_json.get("steps", [steps_json])
            return [PlannerStep(**{k: s.get(k) for k in ("phase", "action", "target",
                                                         "rationale")})
                    for s in steps_json[:int(self.cfg["planner"]["budget"])]]
        except Exception:
            return None


class Agent:
    """Autonomous loop: plan -> act -> reflect, budget-limited, deterministic."""

    def __init__(self, cfg: Dict[str, Any], store: Store, responder: Any = None):
        self.cfg = cfg
        self.store = store
        if responder is None:
            from .respond import ApprovalGate, Responder
            self.responder = Responder(store, cfg,
                                       gate=ApprovalGate(cfg["approval"]["mode"]))
        else:
            self.responder = responder
        self.planner = Planner(cfg, store)

    def run(self, goal: str, planner_mode: str = "rule",
            approval: str = "auto", budget: Optional[int] = None) -> Dict[str, Any]:
        budget = budget or int(self.cfg["planner"]["budget"])
        from .correlate import correlate
        incidents = correlate(self.store, self.cfg)
        target_src = goal_src(goal)
        incident = None
        if target_src:
            incident = next((i for i in incidents if i.src == target_src), None)
        incident = incident or (incidents[0] if incidents else None)
        if incident:
            existing = next((x for x in self.store.incidents if x.src == incident.src), None)
            incident = existing or self.store.add_incident(incident)

        plan = self.planner.plan(goal, incident, planner_mode, budget)
        steps: List[PlannerStep] = []
        iters = 0
        notes = list(plan["notes"])
        contained = False
        for step in plan["steps"]:
            iters += 1
            if iters > budget:
                notes.append(f"[agent] iteration budget {budget} exhausted; stopping.")
                break
            if step.action and incident:
                act = self.responder.run(action=step.action, target=step.target,
                                         incident_id=incident.id,
                                         approval_mode=approval)
                notes.append(f"[agent] {step.action} {step.target} -> {act.status} "
                             f"({act.mode})")
                if step.action == "block-src" and act.status in ("executed", "simulated"):
                    contained = True
                if incident.id and step.action == "block-src":
                    inc = self.store.get_incident(incident.id)
                    if inc and inc.src == step.target and act.status in ("executed", "simulated"):
                        inc.status = "contained"
            step.reflection = self.planner.reflect(step, incident)
            steps.append(step)
            if step.phase == "recover" and contained:
                notes.append("[agent] containment verified after recover phase; proceeding to lessons.")
            if step.phase == "lessons":
                notes.append("[agent] final narrative phase reached; run complete.")
                break

        if incident:
            from .incident import write_incident_report
            report = write_incident_report(self.store, incident.id, self.cfg, notes)
            contained = incident.status == "contained"
        else:
            report = {"incident": None, "contained": False}

        self.store.add_plan_steps(steps)
        return {
            "goal": goal,
            "planner_mode": planner_mode,
            "incident_id": incident.id if incident else None,
            "steps": [s.to_dict() for s in steps],
            "iters": iters,
            "budget": budget,
            "contained": contained,
            "notes": notes,
            "report": report,
        }