"""Continuous watch mode.

Feeds fixture telemetry into the store in time-ordered batches (simulated
arrival), re-runs the detect/triage/correlate pipeline incrementally and
emits incremental updates whenever a batch produces new correlation. Strictly
budget-limited: the loop terminates after `budget` rounds no matter what.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .detect import run_all
from .ingest import ingest_fixtures
from .models import Incident
from .store import Store
from .triage import triage


def _finding_sig(f: Dict[str, Any]) -> tuple:
    return (f.get("rule"), f.get("src"), f.get("channel"),
            round(float(f.get("ts", 0.0)), 3))


def _merge_findings_into_store(store: Store, findings, existing_sigs) -> int:
    added = 0
    for f in findings:
        if _finding_sig(f.to_dict()) in existing_sigs:
            continue
        store.add_finding(f)
        added += 1
    return added


def run_round(store: Store, cfg: Dict[str, Any], fixtures_dir: str,
              horizon: float, batch: int) -> Dict[str, Any]:
    """Ingest the next `batch` events up to `horizon`, then re-analyze."""
    from .ingest import PROVIDERS
    from .correlate import correlate

    existing_sigs = {_finding_sig(f.to_dict()) for f in store.findings}
    stream = ingest_fixtures(fixtures_dir, cfg)
    pending = [e for e in stream if e.ts <= horizon]
    if store.events:
        have = {e.raw for e in store.events}
    else:
        have = set()
    fresh = [e for e in pending if e.raw not in have][:batch]
    store.add_events(fresh)

    findings = run_all(store.events, cfg)
    added = _merge_findings_into_store(store, findings, existing_sigs)
    t = triage(store.findings, cfg)
    for f in t["ordered"]:
        pass

    incidents = correlate(store, cfg)
    new_incidents = []
    grown = []
    for inc in incidents:
        existing = next((x for x in store.incidents if x.src == inc.src), None)
        if existing is None:
            store.add_incident(inc)
            new_incidents.append(inc)
        elif set(existing.channels) != set(inc.channels) or existing.status != inc.status:
            existing.channels = sorted(set(existing.channels) | set(inc.channels))
            existing.stages = inc.stages
            existing.priority = max(existing.priority, inc.priority)
            existing.ts_end = max(existing.ts_end, inc.ts_end)
            store.persist()
            grown.append(existing)
    return {"consumed": len(fresh), "findings_added": added,
            "new_incidents": new_incidents, "grown": grown,
            "incidents": len(store.incidents)}


def watch(store: Store, cfg: Dict[str, Any], fixtures_dir: str,
          interval: Optional[float] = None, budget: Optional[int] = None,
          batch: Optional[int] = None, quiet: bool = False) -> Dict[str, Any]:
    wcfg = cfg["watch"]
    interval = float(interval if interval is not None else wcfg["interval"])
    budget = int(budget if budget is not None else wcfg["budget"])
    batch = int(batch if batch is not None else wcfg["batch"])

    stream = ingest_fixtures(fixtures_dir, cfg)
    if not stream:
        return {"rounds": 0, "consumed": 0, "updates": [], "budget": budget}
    base = stream[0].ts
    horizon = base
    updates: List[Dict[str, Any]] = []
    rounds = 0
    consumed_total = 0
    while consumed_total < len(stream) and rounds < budget:
        rounds += 1
        if rounds > 1:
            horizon = base + (rounds - 1) * interval
        result = run_round(store, cfg, fixtures_dir, horizon, batch)
        consumed_total += result["consumed"]
        for inc in result["new_incidents"]:
            update = {
                "round": rounds,
                "incident_id": inc.id,
                "src": inc.src,
                "channels": inc.channels,
                "stages": len(inc.stages),
            }
            updates.append(update)
            if not quiet:
                print(f"[watch] round={rounds} incident {inc.id}: {inc.src} "
                      f"channels={inc.channels}")
        for inc in result["grown"]:
            update = {
                "round": rounds,
                "incident_id": inc.id,
                "src": inc.src,
                "channels": inc.channels,
                "stages": len(inc.stages),
                "update": "growth",
            }
            updates.append(update)
            if not quiet:
                print(f"[watch] round={rounds} incident {inc.id} growth: "
                      f"channels={inc.channels} stages={len(inc.stages)}")
        if not quiet:
            print(f"[watch] round={rounds}: consumed={result['consumed']} "
                  f"findings={result['findings_added']} "
                  f"live incidents={result['incidents']}")
        if result["consumed"] == 0:
            if not quiet:
                print("[watch] no new events to consume — advancing horizon.")
            continue
    store.persist()
    return {"rounds": rounds, "consumed": consumed_total, "updates": updates,
            "budget": budget}