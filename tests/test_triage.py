import unittest

from sentinai.config import load_config
from sentinai.models import Finding
from sentinai.triage import triage, score, dedupe, asset_value
from tests.testutil import seeded_store


def _finding(signal="brute_force", src="198.51.100.7", sev=3, tactic="Initial Access",
             host="web1.lab.local"):
    return Finding(rule="r", signal=signal, src=src, channel="auth", ts=1000.0,
                   ts_end=1001.0, severity=sev, confidence=0.9,
                   evidence_ids=["e1"], tactic=tactic, techniques=["T1110"],
                   extra={"host": host})


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(None)

    def test_priority_ordering_is_descending(self):
        fs = [_finding(sev=2), _finding(sev=5, tactic="Command and Control"),
              _finding(sev=4)]
        out = triage(fs, self.cfg)
        prios = [f.priority for f in out["ordered"]]
        self.assertEqual(prios, sorted(prios, reverse=True))

    def test_priority_deterministic_formula(self):
        f = _finding(sev=4, tactic="Command and Control", host="db1.lab.local")
        # severity 4 * asset 5 (db1) * stage 2.0 = 40.0
        self.assertEqual(score(f, self.cfg), 40.0)

    def test_asset_default_applies(self):
        f = _finding(host="unknown.lab.local")
        self.assertEqual(asset_value(f, self.cfg), self.cfg["asset_default"])

    def test_dedupe_keeps_strongest_per_key(self):
        base = _finding(sev=2)
        strong = _finding(sev=5)
        out = dedupe([base, strong], self.cfg)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, 5)

    def test_grouped_by_actor(self):
        fs = [_finding(src="198.51.100.7"), _finding(src="203.0.113.5", sev=4),
              _finding(src="198.51.100.7", signal="web_sqli", sev=4)]
        out = triage(fs, self.cfg)
        self.assertEqual(set(out["grouped"]), {"198.51.100.7", "203.0.113.5"})

    def test_seeded_pipeline_orders_actor_first(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            store, cfg = seeded_store(td)
            ordered = [f for f in store.findings if f.priority > 0]
            self.assertTrue(ordered)
            self.assertEqual(ordered[0].src, "198.51.100.7")


if __name__ == "__main__":
    unittest.main()