"""Command-line interface for sentinai.

Subcommands: ingest, detect, triage, correlate, respond, planner, incident,
watch. `--demo` runs the full offline pipeline and exits 0 with real proof.
Global flags let you point at an alternative config, report root or fixture
directory. All paths default to the repository layout; safe defaults keep every
write inside `reports/` and `lab/state/`.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .config import load_config

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))


def _fixtures_dir() -> str:
    return os.path.join(REPO_ROOT, "fixtures")


def _make_store(cfg: Dict[str, Any], report_root: Optional[str] = None):
    from .store import Store
    root = report_root or cfg["paths"]["report_root"]
    store = Store(root)
    store.cfg = cfg  # wire cfg onto store for the lab boundary helpers
    return store


def _pipeline(cfg: Dict[str, Any], report_root: Optional[str] = None) -> Dict[str, Any]:
    """ingest -> detect -> triage -> correlate; returns store."""
    from .store import Store
    from .ingest import ingest_fixtures, channel_counts
    from .detect import run_all, load_iol
    from .triage import triage
    from .correlate import correlate

    store = _make_store(cfg, report_root)
    events = ingest_fixtures(_fixtures_dir(), cfg)
    for ev in events:
        if not any(e.src == ev.src and e.ts == ev.ts and e.channel == ev.channel
                   and e.signal == ev.signal for e in store.events):
            store.add_event(ev)
    iol = load_iol(_fixtures_dir())
    findings = run_all(store.events, cfg, iol)
    for f in findings:
        if not any(x.rule == f.rule and x.src == f.src and x.ts == f.ts
                   for x in store.findings):
            store.add_finding(f)
    t = triage(store.findings, cfg)
    incidents = correlate(store, cfg)
    for inc in incidents:
        if not any(x.src == inc.src for x in store.incidents):
            store.add_incident(inc)
    return {"store": store, "counts": channel_counts(store.events),
            "findings": t, "incidents": incidents}


def cmd_ingest(args, cfg):
    from .ingest import ingest_fixtures, channel_counts
    store = _make_store(cfg, args.report_root)
    events = ingest_fixtures(_fixtures_dir(), cfg)
    store.add_events(events)
    counts = channel_counts(store.events)
    for ch, n in sorted(counts.items()):
        print(f"{ch}: {n}")
    print(f"total events: {len(store.events)}")
    return 0


def cmd_detect(args, cfg):
    result = _pipeline(cfg, args.report_root)
    findings = result["findings"]["ordered"]
    print(f"findings: {len(findings)}")
    for f in findings:
        extra = f.extra.get("count") or f.extra.get("internal") or ""
        print(f"  {f.rule:18s} {f.src:16s} sev={f.severity} {f.tactic:20s} {extra}")
    return 0


def cmd_triage(args, cfg):
    result = _pipeline(cfg, args.report_root)
    for f in result["findings"]["ordered"]:
        print(f"  prio={f.priority:5.2f} {f.rule:18s} {f.src:16s} "
              f"sev={f.severity} asset-scored={f.extra.get('host') or '-'}")
    return 0


def cmd_correlate(args, cfg):
    result = _pipeline(cfg, args.report_root)
    incidents = result["incidents"]
    print(f"incidents: {len(incidents)}")
    for inc in incidents:
        stages = " -> ".join(s["stage"] for s in inc.stages)
        print(f"  {inc.id} src={inc.src} channels={inc.channels}")
        print(f"      priority={inc.priority} status={inc.status}")
        print(f"      kill chain: {stages}")
        print(f"      victims={inc.victims} users={inc.users}")
    return 0


def cmd_respond(args, cfg):
    from .respond import Responder
    from .store import Store
    store = _make_store(cfg, args.report_root)
    responder = Responder(store, cfg)
    target = args.target
    if args.action == "snapshot-artifact":
        target = os.path.join(_fixtures_dir(), args.target)
    act = responder.run(action=args.action, target=target,
                        incident_id=args.incident,
                        approval_mode=args.approval, preapproved=args.approve)
    print(f"{act.id} {act.action} {act.target} -> {act.status} ({act.mode})")
    if args.verbose:
        print(f"  detail: {act.detail}")
    return 0 if act.status not in ("denied", "hard_refused", "failed") else 1


def _agent_goal(cfg: Dict[str, Any], store) -> str:
    for inc in store.incidents:
        return f"contain intrusion from {inc.src} and eradicate the foothold"
    return "respond to reported intrusion in the lab"


def cmd_planner(args, cfg):
    from .planner import Agent
    from .store import Store
    store = _make_store(cfg, args.report_root)
    result = _pipeline(cfg, args.report_root)
    store = result["store"]
    goal = args.goal or _agent_goal(cfg, store)
    agent = Agent(cfg, store)
    out = agent.run(goal, planner_mode=args.planner, approval=args.approval,
                    budget=args.budget)
    print(f"goal: {out['goal']}")
    print(f"incident: {out['incident_id']} contained={out['contained']} "
          f"iters={out['iters']}/{out['budget']}")
    for step in out["steps"]:
        mark = step["action"] or step["phase"]
        print(f"  [{step['phase']:10s}] {mark:28s} {step['rationale'][:60]}")
    for n in out["notes"]:
        print(f"  NOTE: {n}")
    report = out.get("report") or {}
    if report.get("incident"):
        print(f"report written to: {os.path.join(store.root, 'incidents', out['incident_id'], 'incident.md')}")
    return 0


def cmd_incident(args, cfg):
    from .incident import write_incident_report
    store = _make_store(cfg, args.report_root)
    missing = _pipeline(cfg, args.report_root)
    report = write_incident_report(store, args.id, cfg, [])
    print(f"narrative: {report['narrative'][:200]}...")
    print(f"containment: {report['containment']}")
    return 0


def cmd_watch(args, cfg):
    from .watch import watch
    store = _make_store(cfg, args.report_root)
    summary = watch(store, cfg, _fixtures_dir(), interval=args.interval,
                    budget=args.budget, batch=args.batch, quiet=args.quiet)
    print(f"watch complete: rounds={summary['rounds']} consumed={summary['consumed']} "
          f"updates={len(summary['updates'])} budget={summary['budget']}")
    return 0


def demo(cfg: Dict[str, Any], args) -> int:
    """Full offline pipeline; exits 0 only when real proof artifacts exist."""
    from .planner import Agent
    result = _pipeline(cfg, args.report_root)
    store = result["store"]
    findings = result["findings"]["ordered"]
    incidents = result["incidents"]

    brute = [f for f in findings if f.signal == "brute_force" and f.src == "198.51.100.7"]
    main = next((i for i in incidents if i.src == "198.51.100.7"), None)

    agent = Agent(cfg, store)
    goal = f"contain intrusion from 198.51.100.7 and eradicate the foothold"
    out = agent.run(goal, planner_mode="rule", approval="auto")
    report = out["report"]

    checks = {
        "brute force detected for 198.51.100.7": bool(brute),
        "incident built from >=3 channels with kill chain": bool(main) and len(main.channels) >= 3
        and len(main.stages) >= 2,
        "contain executed (auto-approve, lab targets)": out["contained"],
        "narrative timeline written": bool(report.get("timeline")),
        "IOC list present": bool(report.get("iocs")),
        "remediation checklist present": bool(report.get("remediation_checklist")),
    }

    print("=" * 70)
    print("sentinai demo (offline, fixture lab only) — PROOF")
    print("=" * 70)
    if brute:
        b = brute[0]
        print(f"[detect] {b.rule}: {b.description} (sev={b.severity}, "
              f"count={b.extra.get('count')})")
    if main:
        stages = " -> ".join(s["stage"] for s in main.stages)
        print(f"[correlate] {main.id}: src={main.src} channels={main.channels}")
        print(f"[kill-chain]   {stages}")
        print(f"[triage]       priority={main.priority} victims={main.victims} users={main.users}")
    print(f"[agent] goal: {goal}")
    print(f"[agent] iters={out['iters']}/{out['budget']} contained={out['contained']}")
    for n in out["notes"]:
        if n.startswith("[agent]"):
            print(f"  {n}")
    print(f"[incident] narrative: {report.get('narrative', '')[:220]}...")
    for ioc in report.get("iocs", [])[:5]:
        print(f"[ioc] {ioc['value']} — {ioc['indicator']} ({ioc['technique']})")
    print(f"[incident] containment: {report.get('containment')}")
    print(f"[incident] report: {os.path.join(store.root, 'incidents', out['incident_id'], 'incident.md')}")
    print("[remediation]")
    for i, item in enumerate(report.get("remediation_checklist", []), 1):
        print(f"  {i}. {item}")

    failed = [k for k, v in checks.items() if not v]
    if failed:
        print("DEMO FAILED: " + ", ".join(failed))
        return 1
    print("=" * 70)
    print("DEMO OK — all proof checks passed (offline, no network touched).")
    return 0


def _common() -> argparse.ArgumentParser:
    """Options available on every subcommand (works before or after it)."""
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("--report-root", default=None,
                   help="override report output dir (default from config)")
    c.add_argument("--verbose", "-v", action="store_true")
    return c


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinai",
        description="Agentic AI blue-team detection & response (SOC copilot). "
                    "Own-lab / fixture targets only; safety gates are non-negotiable.")
    p.add_argument("--version", action="version", version=f"sentinai {__version__}")
    p.add_argument("--config", default=None, help="path to YAML/JSON config")
    p.add_argument("--report-root", default=None,
                   help="override report output dir (default from config)")
    p.add_argument("--verbose", "-v", action="store_true")

    sub = p.add_subparsers(dest="command", required=False)

    sub.add_parser("ingest", parents=[_common()],
                   help="load fixture telemetry (read-only)")
    sub.add_parser("detect", parents=[_common()],
                   help="run detectors + IOL/MITRE enrichment")
    sub.add_parser("triage", parents=[_common()],
                   help="priority score, dedupe, grouping")
    sub.add_parser("correlate", parents=[_common()],
                   help="cross-channel correlation -> incidents")

    re = sub.add_parser("respond", parents=[_common()],
                        help="defensive actions, approval-gated (lab only)")
    re.add_argument("--action", required=True,
                    choices=["block-src", "rotate-fixture-secret", "disable-user",
                             "snapshot-artifact"])
    re.add_argument("--target", required=True, help="src IP / secret / user / fixture file")
    re.add_argument("--incident", default="", help="incident id to link (INS-n)")
    re.add_argument("--approval", default=None, choices=["auto", "ask", "never"])
    re.add_argument("--approve", action="store_true",
                    help="explicitly approve (honours --approval ask)")

    pl = sub.add_parser("planner", parents=[_common()],
                        help="agent core: plan, act, reflect")
    pl.add_argument("--goal", default=None, help="natural-language goal")
    pl.add_argument("--planner", default=None, choices=["rule", "llm"])
    pl.add_argument("--approval", default="auto", choices=["auto", "ask"])
    pl.add_argument("--budget", type=int, default=None)

    ic = sub.add_parser("incident", parents=[_common()],
                        help="final incident report")
    ic.add_argument("--id", required=True, help="incident id (INS-n)")

    wa = sub.add_parser("watch", parents=[_common()],
                        help="continuous watch mode")
    wa.add_argument("--interval", type=float, default=None)
    wa.add_argument("--budget", type=int, default=None)
    wa.add_argument("--batch", type=int, default=None)
    wa.add_argument("--quiet", action="store_true")

    p.add_argument("--demo", action="store_true",
                   help="full offline demo pipeline (exits 0 with proof)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    if args.report_root:
        cfg["paths"]["report_root"] = args.report_root

    if args.demo:
        return demo(cfg, args)

    cmd = args.command or "help"
    table = {
        "ingest": cmd_ingest,
        "detect": cmd_detect,
        "triage": cmd_triage,
        "correlate": cmd_correlate,
        "respond": cmd_respond,
        "planner": cmd_planner,
        "incident": cmd_incident,
        "watch": cmd_watch,
    }
    handler = table.get(cmd)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())