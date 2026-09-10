# sentinai

Agentic AI blue-team detection & response orchestration (SOC copilot).

sentinai is an autonomous SOC analyst that **ingests** telemetry fixtures,
**detects** intrusions, **triages** priorities, **correlates** cross-channel
kill chains, **responds** against *own-lab services only* with approval-gated
actions, and writes a full **incident narrative**. The agent loop mirrors the
portfolio's red-team design, but defensively: the planner turns a goal like
`contain the intrusion from 198.51.100.7` into a budget-limited
*triage → contain → eradicate → recover → lessons* plan with reflection between
steps. An LLM planner is optional and env-guarded; the rule playbook is fully
offline and is the canonical path.

> Requires Python ≥ 3.9, **stdlib only** (no third-party runtime deps).
> Feed fixtures are read-only; actions touch RFC 5737 simulation space and your
> own loopback via an iptables **stub**. Nothing real is ever blocked.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

## Install

```bash
python3 -m pip install -e .        # console script: sentinai
python3 -m sentinai --version      # or: sentinai --version
```

See also `sentinai.yaml` (YAML/JSON config reference; defaults are built-in).

## Quickstart

```bash
sentinai --demo                     # offline, exits 0 with real proof
sentinai ingest
sentinai detect
sentinai triage
sentinai correlate
sentinai respond --action block-src --target 198.51.100.7 --approval ask --approve \
                 --incident INS-1    # approval-gated, lab allowlist only
sentinai planner --goal "contain the intrusion from 198.51.100.7" --planner rule --approval auto
sentinai incident --id INS-1
sentinai watch --budget 50          # continuous watch, budget-limited
python3 -m unittest discover -s tests
```

## Architecture / command summary

| subcommand | purpose |
|---|---|
| `ingest` | load 5 fixture feeds (auth/ssh log, web access log, process list, network flows, netsentinel-style alert feed) into normalized `Event` records. **Read-only providers.** |
| `detect` | ssh-brute threshold, web SQLi/XSS regex, process bad-name/odd-path, flow beacon + port-span detectors — all pure stdlib — plus IOL → MITRE ATT&CK tactic mapping. |
| `triage` | priority = severity × asset value × kill-chain stage weight; dedupe; group by actor. |
| `correlate` | same actor across ≥2 channels within a window → incident; kill-chain reconstruction; victim/user attribution. |
| `respond` | `block-src`, `rotate-fixture-secret`, `disable-user`, `snapshot-artifact`. Lab boundary (loopback = real ACK via stub; RFC 5737 = recorded simulation; anything else = **hard refusal**) AND approval gate (auto/ask/never). |
| `planner` | agent core: goal → playbook steps → act → reflect. `--planner llm` needs `SENTINAI_LLM_BASE`/`SENTINAI_LLM_KEY` (clear message + offline fallback otherwise). |
| `incident` | final narrative report: timeline, MITRE mapping, containment status, IOC list, lessons, remediation checklist (JSON + Markdown). |
| `watch` | continuous mode: feeds batches over time, emits incremental correlation updates, budget-limited. |

### Safety model (two independent gates, never weakenable)

1. **Lab boundary** (`sentinai/lab.py`): targets must be loopback (`127.x`, `::1`,
   `localhost` — may actually ACK against your own stub) or **RFC 5737**
   documentation space / `*.lab.local` (recorded simulation). Any real address
   (`8.8.8.8`, `10.x`, …) is **hard-refused** before execution, regardless of approvals.
2. **Approval gate** (`sentinai/respond.py`): `auto | ask | never`. Default config
   mode is `ask`; non-interactive `ask` requires an explicit `--approve`. `never`
   denies everything. The planner defaults to `auto` **only within the lab
   allowlist** (RFC 5737 simulations / loopback) as in the demo; it can never
   widen the lab boundary.

Default behavior is dry-run: fixtures, reports and state are all written under
`reports/` and `lab/state/`; real-world-affecting actions require explicit
approval and remain simulation-recorded for RFC 5737 targets.

## Live Lab Test Plan

Run against **your own lab only**. The plan proves every engine stage with exit
standards and expected evidence, then should be re-run with counters.

```bash
# 1. Ingest (read-only). Expect 5 channels, no fixture mutation.
sentinai ingest && git diff --stat fixtures/      # must be empty

# 2. Detect/plant verification: brute flagged exactly, clean baseline silent.
sentinai detect | grep -c "ssh-brute"             # expect >= 1

# 3. Triage ordering + correlation with kill chain.
sentinai triage
sentinai correlate | grep -A4 "INS-"              # >=3 channels + stages

# 4. Response: approved blocks, unapproved refuses, non-lab hard-refused.
sentinai respond --action block-src --target 198.51.100.7 --approval never   # rc=1 denied
sentinai respond --action block-src --target 8.8.8.8 --approval auto         # rc=1 hard-refused
sentinai respond --action block-src --target 198.51.100.7 --approval auto    # rc=0 simulated
ls lab/state/iptables.rules                        # contain proof recorded

# 5. Autonomous agent: goal-driven loop, containment, narrative.
sentinai planner --goal "contain the intrusion from 198.51.100.7" \
                 --planner rule --approval auto
cat reports/incidents/INS-1/incident.md            # narrative + IOC + lessons

# 6. Continuous watch, budget-limited.
sentinai watch --budget 50 --interval 1800
```

**Expected proof output**: demo (below) exits `0` with all checks green; the
incident report shows 4 channels, a multi-stage kill chain, `CONTAINED`
status, IOC list, and remediation checklist. Counters after the run feed
`METRICS.md`.

## Metrics

Updated in `METRICS.md` after each feature and after the demo run — detector
TP/FP against planted fixtures, incident count, agent iterations vs budget,
and time-to-contain. See the file for the as-measured numbers.

## Development

- Stdlib-first, `tests/` per engine, offline demo exits 0.
- House rules: placeholders only (RFC 5737, `*.lab.local`, `alice@example.com`).
- Run `python3 -m py_compile` on changed files and keep
  `python3 -m unittest discover -s tests` green (currently 81 tests).
- Legal + safety gates (SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md,
  AUTHORS, LICENSE) apply to all contributions.