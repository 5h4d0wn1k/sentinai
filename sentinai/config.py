"""Configuration loader.

Supports JSON and a conservative YAML subset (comments, key: value, nested
indent, dash lists, inline lists, scalars). Pure stdlib so the whole tool
runs fully offline.
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from typing import Any, Dict, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "window": {
        "correlate": 1800.0,   # seconds across which srcs are linked into incidents
        "ssh": 600.0,          # brute-force counting window
        "beacon": 600.0,       # beaconing observation window
        "scan": 120.0,         # port-span observation window
    },
    "thresholds": {
        "ssh_failed_min": 5,   # min failed attempts per src to flag brute force
        "web_sqli": True,
        "web_xss": True,
        "beacons_min": 4,      # min beacon connections to flag
        "beacon_regularity": 0.5,  # max allowed std/mean for "regular" beaconing
        "beacon_bytes_min": 2000,  # min avg bytes per beacon connection
        "scan_min_ports": 5,   # distinct dest ports to flag port scan
        "after_hours": True,
    },
    "assets": {  # hostname -> asset value (1..5)
        "db1.lab.local": 5,
        "web1.lab.local": 4,
        "edge1.lab.local": 3,
        "workstation-alice.lab.local": 2,
        "mail1.lab.local": 3,
    },
    "asset_default": 2,
    "stage_weights": {  # kill-chain stage -> priority multiplier
        "Initial Access": 1.0,
        "Execution": 1.2,
        "Persistence": 1.4,
        "Privilege Escalation": 1.6,
        "Defense Evasion": 1.5,
        "Credential Access": 1.8,
        "Discovery": 1.4,
        "Lateral Movement": 1.7,
        "Collection": 1.6,
        "Command and Control": 2.0,
        "Exfiltration": 2.0,
        "Impact": 2.0,
        "Reconnaissance": 0.8,
        "Resource Development": 0.8,
    },
    "correlate": {
        "min_channels": 2,     # distinct channels required to form an incident
    },
    "approval": {
        "mode": "ask",         # auto | ask | never  (respond default)
    },
    "planner": {
        "default": "rule",     # rule | llm
        "budget": 20,          # max agent iterations
        "llm_base": os.environ.get("SENTINAI_LLM_BASE"),
        "llm_key": os.environ.get("SENTINAI_LLM_KEY"),
    },
    "watch": {
        "interval": 1.0,       # simulated seconds per round
        "budget": 200,         # max rounds
        "batch": 8,            # events fed per round
    },
    "paths": {
        "report_root": "reports",
        "lab_root": "lab",
        "lab_iptables": "lab/scripts/iptables",
        "lab_state": "lab/state",
    },
    "lab": {
        "allow_loopback": True,
        "allow_rfc5737": True,
        "secrets": {"lab-db-password": "secret-gen-1", "lab-api-token": "secret-gen-1"},
        "users": ["root", "alice", "bob", "admin", "operator"],
    },
}


def _parse_scalar(tok: str):
    tok = tok.strip().strip('"').strip("'")
    if tok in ("", "null", "None", "~"):
        return None
    if tok in ("true", "True", "yes"):
        return True
    if tok in ("false", "False", "no"):
        return False
    if re.fullmatch(r"-?\d+", tok):
        return int(tok)
    if re.fullmatch(r"-?\d+\.\d+", tok):
        return float(tok)
    if tok.startswith("[") and tok.endswith("]"):
        inner = tok[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x) for x in re.split(r",\s*", inner)]
    if tok.startswith("{") and tok.endswith("}"):
        inner = tok[1:-1].strip()
        out = {}
        if inner:
            for part in re.split(r",\s*(?=[^:]+:)", inner):
                k, _, v = part.partition(":")
                out[k.strip().strip('"\'')] = _parse_scalar(v)
        return out
    return tok


def parse_yaml(text: str) -> Dict[str, Any]:
    """Minimal YAML subset parser for sentinai config files."""
    lines = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if raw.strip().startswith("#") else raw
        if not line.strip():
            continue
        lines.append(line.rstrip())

    def _strip_comment(s: str) -> str:
        # Naive comment strip: honour quotes.
        in_s = in_d = False
        for i, ch in enumerate(s):
            if ch == '"' and not in_s:
                in_d = not in_d
            elif ch == "'" and not in_d:
                in_s = not in_s
            elif ch == "#" and not in_s and not in_d:
                return s[:i].rstrip()
        return s

    indent_char = "  "
    root: Dict[str, Any] = {}
    stack = [(-1, root)]  # (indent, container). container is dict or list-tail dict

    def container_for(indent: int):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        return stack[-1][1]

    for raw_line in lines:
        raw_line = raw_line.rstrip()
        if not raw_line.strip():
            continue
        line = _strip_comment(raw_line)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        is_list_item = line.lstrip().startswith("- ")
        if is_list_item:
            content = line.lstrip()[2:].strip()
            parent = container_for(indent)
            # Ensure a list exists under the parent key that owns this indent block.
            key_for_list = None
            for k, v in reversed(list(parent.items())):
                if isinstance(v, list):
                    key_for_list = k
                    break
            lst = parent[key_for_list] if key_for_list else None
            if key_for_list is None:
                # start implicit list under last scalar-less key: derive from spacials
                # Fall back: build list at parent level keyed "items".
                lst = parent.setdefault("_items", [])
            if ":" in content:
                k, _, v = content.partition(":")
                node: Any = _parse_scalar(v) if v.strip() else {}
                if isinstance(node, dict):
                    node = dict(node)
                lst.append({k.strip(): node} if not (isinstance(node, dict) and v.strip() == "") else {k.strip(): {}})
                if isinstance(lst[-1].get(k.strip()), dict) and v.strip() == "":
                    stack.append((indent, lst[-1][k.strip()]))
            else:
                lst.append(_parse_scalar(content))
            continue

        m = re.match(r"^([^:]+):\s*(.*)$", line)
        if not m:
            continue
        key = m.group(1).strip().strip('"').strip("'")
        val = m.group(2).strip()
        parent = container_for(indent)
        if val == "":
            node: Dict[str, Any] = {}
            if key in parent and isinstance(parent[key], list):
                # re-open list context under same key
                continue
            parent[key] = node
            stack.append((indent, node))
        else:
            parsed = _parse_scalar(val)
            parent[key] = parsed
            if isinstance(parsed, dict):
                stack.append((indent, parsed))

    root.pop("_items", None)
    return root


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load config, deep-merged over defaults. JSON or YAML accepted."""
    cfg = deepcopy(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            if path.endswith(".json"):
                loaded = json.load(fh)
            else:
                loaded = parse_yaml(fh.read())
        cfg = _deep_merge(cfg, loaded)
    cfg["env"] = {
        "llm_base": os.environ.get("SENTINAI_LLM_BASE", DEFAULT_CONFIG["planner"]["llm_base"]),
        "llm_key": os.environ.get("SENTINAI_LLM_KEY", DEFAULT_CONFIG["planner"]["llm_key"]),
    }
    return cfg


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out