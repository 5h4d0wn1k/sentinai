import os
import tempfile
import unittest

from tests.testutil import seeded_store


class CorrelateTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store, self.cfg = seeded_store(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def main_incident(self):
        return next((i for i in self.store.incidents if i.src == "198.51.100.7"), None)

    def test_incident_built_from_three_channels(self):
        inc = self.main_incident()
        self.assertIsNotNone(inc)
        for ch in ("auth", "web", "flow"):
            self.assertIn(ch, inc.channels)
        self.assertGreaterEqual(len(inc.channels), 3)

    def test_kill_chain_stages_reconstructed(self):
        inc = self.main_incident()
        tactics = [s["tactic"] for s in inc.stages]
        self.assertIn("Initial Access", tactics)          # earliest (brute/sqli)
        self.assertIn("Command and Control", tactics)     # beaconing
        self.assertIn("Execution", tactics)               # xmrig (c2 in cmdline)
        self.assertEqual(tactics[0], "Initial Access")
        self.assertGreaterEqual(len(inc.stages), 3)

    def test_victim_user_attribution(self):
        inc = self.main_incident()
        self.assertIn("edge1.lab.local", inc.victims)
        self.assertIn("web1.lab.local", inc.victims)
        self.assertIn("root", inc.users)

    def test_single_incident_per_actor(self):
        matches = [i for i in self.store.incidents if i.src == "198.51.100.7"]
        self.assertEqual(len(matches), 1)

    def test_lone_scanner_not_correlated(self):
        # 203.0.113.5 is flow-only (port scan) -> below min_channels, no incident.
        self.assertFalse(any(i.src == "203.0.113.5" for i in self.store.incidents))

    def test_incident_priority_is_actor_max(self):
        inc = self.main_incident()
        expected = max(f["priority"] for f in inc.findings)
        self.assertEqual(inc.priority, expected)


if __name__ == "__main__":
    unittest.main()