"""Shared helpers for sentinai tests (not collected as a test module)."""

from __future__ import annotations

import os
import shutil
import tempfile

from sentinai.config import load_config
from sentinai.store import Store
from sentinai.ingest import ingest_fixtures
from sentinai.detect import run_all
from sentinai.triage import triage
from sentinai.correlate import correlate

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
FIXTURES = os.path.join(REPO, "fixtures")
STUB = os.path.join(REPO, "lab", "scripts", "iptables")


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def make_env(tmpdir: str) -> dict:
    """Config with absolute paths pointing inside a per-test temp dir."""
    cfg = load_config(None)
    cfg["paths"]["report_root"] = os.path.join(tmpdir, "reports")
    cfg["paths"]["lab_root"] = os.path.join(tmpdir, "lab")
    cfg["paths"]["lab_state"] = os.path.join(tmpdir, "lab", "state")
    cfg["paths"]["lab_iptables"] = STUB
    return cfg


def fresh_store(cfg: dict, tmpdir: str):
    store = Store(cfg["paths"]["report_root"], auto_persist=True)
    store.cfg = cfg
    return store


def seeded_store(tmpdir: str, approval_mode: str = "ask", extra_cfg=None):
    """Fresh store with the full ingest->detect->triage->correlate pipeline run."""
    cfg = make_env(tmpdir)
    if extra_cfg:
        for k, v in extra_cfg.items():
            cfg.setdefault(k, {}).update(v) if isinstance(v, dict) else cfg.__setitem__(k, v)
    cfg["approval"]["mode"] = approval_mode
    store = fresh_store(cfg, tmpdir)
    events = ingest_fixtures(FIXTURES, cfg)
    store.add_events(events)
    findings = run_all(store.events, cfg)
    for f in findings:
        store.add_finding(f)
    triage(store.findings, cfg)
    incidents = correlate(store, cfg)
    for inc in incidents:
        store.add_incident(inc)
    return store, cfg


def has_plans_field(result: dict, key: str) -> bool:
    return bool(result.get(key))