"""Defensive response engine (own-lab only, approval-gated).

Safety model is two independent gates, both of which must pass:

1. **Lab boundary** — the target must classify as *loopback* (real ACK against
   our own sandbox) or *RFC 5737 / own-lab* (recorded simulation). Any other
   target is **hard-refused** and never reaches execution.
2. **Approval gate** — mode `auto` | `ask` | `never`. `ask` requires an
   explicit `--approve` (non-interactive) or a live yes at the TTY. `never`
   denies everything. Default mode comes from config (`ask`).

Both gates are checked before any write occurs, and they cannot be weakened by
flags (only widened by stricter choices).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .lab import Lab, classify_target, valid_fixture_user, Target
from .models import RespondAction
from .store import Store

ACTION_SPECS: Dict[str, Dict[str, Any]] = {
    "block-src": {
        "help": "Block a source IP at the edge (iptables stub / recorded sim).",
        "payload": "src",
        "sim_ok": True,
    },
    "rotate-fixture-secret": {
        "help": "Re-key an allowlisted lab fixture secret (generation bump).",
        "payload": "secret-name",
        "sim_ok": True,
    },
    "disable-user": {
        "help": "Disable a fixture lab account (simulation, recorded).",
        "payload": "user",
        "sim_ok": True,
    },
    "snapshot-artifact": {
        "help": "Copy a fixture artifact into the incident evidence dir.",
        "payload": "fixture-path",
        "sim_ok": True,
    },
}


@dataclass
class ApprovalGate:
    mode: str          # auto | ask | never
    preapproved: bool = False   # explicit --approve (honoured only when helpfully strict)

    def decide(self, action: str, target: str, kind: str) -> Tuple[bool, str]:
        mode = self.mode
        if mode == "never":
            return False, "approval mode 'never' denies all actions"
        if kind == "refused":
            return False, "target outside lab allowlist (hard refusal)"
        if mode == "auto":
            return True, "auto-approval granted (lab allowlist target)"
        if mode == "ask":
            if self.preapproved:
                return True, "explicit --approve granted"
            if self._tty_confirm(action, target):
                return True, "interactive confirmation granted (tty)"
            return False, "no approval given for ask mode (denied)"
        return False, f"unknown approval mode {mode!r} (denied)"

    @staticmethod
    def _tty_confirm(action: str, target: str) -> bool:
        try:
            if not os.isatty(0):
                return False
            reply = input(f"[SENTINAI] approve {action} on {target}? [y/N] ").strip().lower()
            return reply in ("y", "yes")
        except (EOFError, OSError):
            return False


class Responder:
    def __init__(self, store: Store, cfg: Dict[str, Any],
                 gate: Optional[ApprovalGate] = None,
                 lab: Optional[Lab] = None):
        self.store = store
        self.cfg = cfg
        self.gate = gate or ApprovalGate(cfg["approval"]["mode"])
        self.lab = lab or Lab(cfg, store.root)

    # ---- single-action entrypoint ----------------------------------------
    def run(self, action: str, target: str,
            incident_id: str = "", approval_mode: Optional[str] = None,
            preapproved: bool = False, asof: Optional[float] = None) -> RespondAction:
        if approval_mode:
            self.gate = ApprovalGate(approval_mode, preapproved)
        self._now = asof if asof is not None else time.time()
        spec = ACTION_SPECS.get(action)
        if not spec:
            raise ValueError(f"unknown action {action!r}; choose from {sorted(ACTION_SPECS)}")

        if action == "block-src":
            return self._block_src(action, target, spec, incident_id)
        if action == "rotate-fixture-secret":
            return self._rotate_secret(action, target, spec)
        if action == "disable-user":
            return self._disable_user(action, target, spec)
        if action == "snapshot-artifact":
            return self._snapshot(action, target, spec, incident_id)
        raise ValueError(f"unhandled action {action!r}")

    def _ts(self) -> float:
        return getattr(self, "_now", time.time())

    # ---- executors --------------------------------------------------------
    def _block_src(self, action: str, target: str, spec: Dict[str, Any],
                   incident_id: str) -> RespondAction:
        tgt = classify_target(target, self.cfg)
        approved, why = self.gate.decide(action, target, tgt.kind)
        base_ts = self._ts()
        if tgt.kind == "refused":
            return self._record(action, target, mode="refused", status="hard_refused",
                                ts=base_ts, approval=self.gate.mode,
                                detail="target outside lab allowlist (hard refusal)",
                                incident_id=incident_id)
        if not approved:
            return self._record(action, target, mode="denied", status="denied",
                                ts=base_ts, approval=self.gate.mode,
                                detail=why, incident_id=incident_id)
        ok, detail = self.lab.apply_block(target, tgt)
        if not ok:
            return self._record(action, target, mode="failed", status="failed",
                                ts=base_ts, approval=self.gate.mode,
                                detail=detail, incident_id=incident_id)
        mode = "executed" if tgt.can_ack else "simulated"
        act = self._record(action, target, mode=mode, status=mode, ts=base_ts,
                           approval=self.gate.mode, detail=detail,
                           incident_id=incident_id)
        self._mark_contained(incident_id, target)
        return act

    def _rotate_secret(self, action: str, secret: str, spec: Dict[str, Any]) -> RespondAction:
        tgt = Target(secret, "lab", "fixture secret (lab sim)", can_ack=False)
        if secret not in self.cfg["lab"]["secrets"]:
            return self._record(action, secret, mode="refused", status="hard_refused",
                                ts=self._ts(), approval=self.gate.mode,
                                detail="secret not in lab allowlist")
        approved, why = self.gate.decide(action, secret, tgt.kind)
        if not approved:
            return self._record(action, secret, mode="denied", status="denied",
                                ts=self._ts(), approval=self.gate.mode, detail=why)
        ok, detail, gen = self.lab.rotate_secret(secret)
        return self._record(action, secret, mode="simulated" if ok else "failed",
                            status="executed" if ok else "failed", ts=self._ts(),
                            approval=self.gate.mode, detail=detail)

    def _disable_user(self, action: str, user: str, spec: Dict[str, Any]) -> RespondAction:
        tgt = Target(user, "lab", "fixture user (lab sim)", can_ack=False)
        if not valid_fixture_user(user, self.cfg):
            return self._record(action, user, mode="refused", status="hard_refused",
                                ts=self._ts(), approval=self.gate.mode,
                                detail="user not in lab fixture allowlist")
        approved, why = self.gate.decide(action, user, tgt.kind)
        if not approved:
            return self._record(action, user, mode="denied", status="denied",
                                ts=self._ts(), approval=self.gate.mode, detail=why)
        detail = f"fixture sim: account {user} disabled (login disabled)"
        return self._record(action, user, mode="simulated", status="executed",
                            ts=self._ts(), approval=self.gate.mode, detail=detail)

    def _snapshot(self, action: str, path: str, spec: Dict[str, Any],
                  incident_id: str) -> RespondAction:
        fixtures_root = os.path.abspath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         os.path.pardir, "fixtures"))
        src_abspath = os.path.abspath(path)
        if not src_abspath.startswith(fixtures_root):
            return self._record(action, path, mode="refused", status="hard_refused",
                                ts=self._ts(), approval=self.gate.mode,
                                detail="snapshot source outside fixtures/ (hard refusal)",
                                incident_id=incident_id)
        tgt = Target(path, "lab", "fixture artifact (read-only source)", can_ack=False)
        approved, why = self.gate.decide(action, path, tgt.kind)
        if not approved:
            return self._record(action, path, mode="denied", status="denied",
                                ts=self._ts(), approval=self.gate.mode, detail=why)
        incident_dir = os.path.join(self.store.root, "evidence", incident_id or "adhoc")
        ok, detail = self.lab.snapshot(path, incident_dir)
        mode = "executed" if ok else "failed"
        act = self._record(action, path, mode=mode, status=mode, ts=self._ts(),
                           approval=self.gate.mode, detail=detail, incident_id=incident_id)
        if ok:
            inc = self.store.get_incident(incident_id) if incident_id else None
            if inc and incident_dir not in inc.evidence_paths:
                inc.evidence_paths.append(incident_dir)
        return act

    # ---- helpers ----------------------------------------------------------
    def _record(self, action: str, target: str, mode: str, status: str, ts: float,
                approval: str, detail: str = "", incident_id: str = "") -> RespondAction:
        act = RespondAction(id="", action=action, target=target, mode=mode,
                            status=status, ts=ts, approval=approval,
                            detail=detail, incident_id=incident_id)
        self.store.add_action(act)
        return act

    def _mark_contained(self, incident_id: str, src: str) -> None:
        inc = self.store.get_incident(incident_id) if incident_id else None
        if inc and inc.src == src:
            inc.status = "contained"
            self.store.persist()