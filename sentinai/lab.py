"""Lab identity + safety boundary.

The response engine only ever touches the *own-lab* allowlist:
  * loopback   (127.0.0.0/8, ::1, localhost)        -> actions may actually ACK
  * RFC 5737   (192.0.2/24, 198.51.100/24, 203.0.113/24) -> simulations, recorded
Everything else (real routables, private cloud ranges, .com hosts) is
**hard-refused**, regardless of approval mode.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .models import rfc5737

LOOPBACK_HOSTS = {"127.0.0.1", "127.0.0.2", "::1", "localhost", "lab-loopback"}
LAB_HOST_SUFFIXES = (".lab.local",)
LAB_HOST_PREFIXES = ("lab-",)

KIND_LOOPBACK = "loopback"
KIND_LAB = "lab"
KIND_REFUSED = "refused"


@dataclass
class Target:
    value: str
    kind: str
    reason: str       # why this kind was chosen
    can_ack: bool     # loopback targets can yield a real ACK


def classify_target(target: Optional[str], cfg: Dict[str, Any]) -> Target:
    """Classify a response target against the lab allowlist."""
    t = (target or "").strip().lower()
    if not t:
        return Target(t, KIND_REFUSED, "empty target")
    addr = None
    if "/" in t or ":" in t or t.replace(".", "").isdigit():
        try:
            addr = ipaddress.ip_address(t)
        except ValueError:
            addr = None

    if cfg.get("lab", {}).get("allow_loopback", True):
        if t in LOOPBACK_HOSTS or (addr is not None and addr.is_loopback):
            return Target(t, KIND_LOOPBACK, "own loopback lab service", can_ack=True)
    if cfg.get("lab", {}).get("allow_rfc5737", True):
        if rfc5737(t) or t.endswith(LAB_HOST_SUFFIXES) or t.startswith(LAB_HOST_PREFIXES):
            return Target(t, KIND_LAB, "RFC5737/own-lab simulation space", can_ack=False)
    return Target(t, KIND_REFUSED, "not in lab allowlist (refused by policy)", can_ack=False)


class Lab:
    """Interface to the own-lab sandbox: iptables stub, secrets, evidence."""

    def __init__(self, cfg: Dict[str, Any], report_root: str):
        self.cfg = cfg
        self.root = cfg["paths"]["lab_root"]
        self.state_dir = os.path.abspath(os.path.join(report_root, os.path.pardir, cfg["paths"]["lab_state"])) \
            if not os.path.isabs(cfg["paths"]["lab_state"]) \
            else cfg["paths"]["lab_state"]
        self.rules_file = os.path.join(self.state_dir, "iptables.rules")
        self.secrets_file = os.path.join(self.state_dir, "secrets.json")
        os.makedirs(self.state_dir, exist_ok=True)
        self._ensure_secrets()

    # ---- iptables stub ---------------------------------------------------
    def apply_block(self, src: str, target: Target) -> Tuple[bool, str]:
        """Block *src* at the edge. Loopback -> real ACK via stub; lab -> sim."""
        if target.kind == KIND_LOOPBACK:
            stub = self.cfg["paths"]["lab_iptables"]
            if not os.path.exists(stub):
                return False, f"iptables stub missing: {stub}"
            import subprocess
            env = dict(os.environ, LAB_STATE_DIR=self.state_dir)
            # Invoke via `sh` so the stub works on noexec mounts (e.g. USB).
            proc = subprocess.run(
                ["sh", stub, "-I", "INPUT", "-s", src, "-j", "DROP"],
                capture_output=True, text=True, env=env, timeout=10)
            if proc.returncode != 0:
                return False, f"iptables stub failed: {proc.stderr.strip()} rc={proc.returncode}"
            return True, proc.stdout.strip()
        # Simulation recorded to the state dir only (own fiction space).
        with open(self.rules_file, "a", encoding="utf-8") as fh:
            fh.write(f"# simulation (RFC5737) {src}\n")
        return True, "simulation recorded (no real network touched)"

    def current_rules(self) -> str:
        if os.path.exists(self.rules_file):
            with open(self.rules_file, "r", encoding="utf-8") as fh:
                return fh.read()
        return ""

    def src_blocked(self, src: str) -> bool:
        return src in self.current_rules()

    # ---- secret re-key ----------------------------------------------------
    def rotate_secret(self, secret_name: str) -> Tuple[bool, str, int]:
        """Re-key demo: bump generation of an allowlisted fixture secret."""
        secrets = self.cfg["lab"]["secrets"]
        if secret_name not in secrets:
            return False, "secret not in lab allowlist", 0
        state = self._secret_state()
        gen = state.get(secret_name, {}).get("generation", 0) + 1
        state[secret_name] = {"generation": gen, "rotated_at": "re-key-demo"}
        self._write_secrets_state(state)
        return True, f"re-keyed {secret_name} to generation {gen} (fixture sim)", gen

    def _secret_state(self) -> Dict[str, Any]:
        if os.path.exists(self.secrets_file):
            with open(self.secrets_file, "r", encoding="utf-8") as fh:
                data = fh.read()
            try:
                return json.loads(data) if data.strip() else {}
            except json.JSONDecodeError:
                return {}
        return {}

    def _ensure_secrets(self) -> None:
        if not os.path.exists(self.secrets_file):
            self._write_secrets_state({})

    def _write_secrets_state(self, state: Optional[Dict[str, Any]] = None) -> None:
        with open(self.secrets_file, "w", encoding="utf-8") as fh:
            json.dump(state if state is not None else self._secret_state(),
                      fh, indent=2, sort_keys=True)

    def secret_generation(self, secret_name: str) -> int:
        return self._secret_state().get(secret_name, {}).get("generation", 0)

    # ---- evidence ---------------------------------------------------------
    def snapshot(self, source: str, incident_dir: str) -> Tuple[bool, str]:
        """Copy a fixture artifact into the incident evidence dir (own data)."""
        src = os.path.abspath(source)
        fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, "fixtures"))
        if not src.startswith(fixtures_dir):
            return False, "snapshot source must live under fixtures/ (read-only feed)"
        if not os.path.exists(src):
            return False, f"artifact not found: {source}"
        os.makedirs(incident_dir, exist_ok=True)
        # Write an evidence manifest rather than mutating the live feed copy
        # semantics: we copy fixture lines, the originals are never modified.
        with open(src, "r", encoding="utf-8") as fh:
            content = fh.read()
        dest_path = os.path.join(incident_dir, os.path.basename(src))
        with open(dest_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return True, f"snapshot -> {dest_path}"


def valid_fixture_user(user: str, cfg: Dict[str, Any]) -> bool:
    return user in cfg.get("lab", {}).get("users", [])