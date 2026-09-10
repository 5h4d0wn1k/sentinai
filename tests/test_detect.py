import tempfile
import unittest

from sentinai.config import load_config
from sentinai.ingest import ingest_fixtures
from sentinai.detect import (run_all, load_iol, detect_flow, _BAD_EXE_NAMES,
                            is_unusual_path)
from tests.testutil import FIXTURES


class DetectTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(None)
        self.events = ingest_fixtures(FIXTURES, self.cfg)
        self.iol = load_iol(FIXTURES)
        self.findings = run_all(self.events, self.cfg, self.iol)

    def findings_by(self, signal):
        return [f for f in self.findings if f.signal == signal]

    def test_brute_flags_attacker_exactly(self):
        brute = self.findings_by("brute_force")
        self.assertEqual(len(brute), 1)            # exactly the planted brute
        self.assertEqual(brute[0].src, "198.51.100.7")
        # 6 burst attempts in the 600s window (+1 late after-hours, excluded)
        self.assertEqual(brute[0].extra["count"], 6)

    def test_clean_baseline_not_flagged(self):
        flaged_srcs = {f.src for f in self.findings}
        self.assertNotIn("192.0.2.11", flaged_srcs)
        self.assertNotIn("203.0.113.60", flaged_srcs)  # benign success + 404

    def test_web_sqli_detected(self):
        sqli = self.findings_by("web_sqli")
        self.assertEqual(len(sqli), 2)
        self.assertTrue(all(f.src == "198.51.100.7" for f in sqli))

    def test_web_500_raises_severity(self):
        sqli = self.findings_by("web_sqli")
        boosted = [f for f in sqli if f.extra.get("status") == 500]
        self.assertEqual(boosted[0].severity, 4)

    def test_web_xss_detected(self):
        xss = self.findings_by("web_xss")
        self.assertEqual(len(xss), 1)
        self.assertEqual(xss[0].src, "198.51.100.7")

    def test_process_suspicious_both_found(self):
        procs = self.findings_by("proc_suspicious")
        commands = [f.extra["command"] for f in procs]
        self.assertTrue(any("/tmp/xmrig" in c for c in commands))
        self.assertTrue(any("kdevtmpfsi" in c for c in commands))
        self.assertTrue(all(f.extra["bad_name"] for f in procs))

    def test_process_attributes_actor_from_command(self):
        xmrig = [f for f in self.findings_by("proc_suspicious")
                 if "xmrig" in f.extra.get("command", "")][0]
        self.assertEqual(xmrig.src, "198.51.100.7")

    def test_flow_beacon_detected(self):
        beacons = self.findings_by("flow_beacon")
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0].src, "198.51.100.7")
        self.assertEqual(beacons[0].extra["internal"], "web1.lab.local")

    def test_flow_scan_detected(self):
        scans = self.findings_by("flow_scan")
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].src, "203.0.113.5")

    def test_alert_feed_promoted(self):
        alerts = [f for f in self.findings if f.channel == "alert"]
        self.assertGreaterEqual(len(alerts), 2)
        self.assertTrue(any(f.src == "198.51.100.7" for f in alerts))

    def test_iol_enrichment_sets_tactic(self):
        brute = self.findings_by("brute_force")[0]
        self.assertEqual(brute.tactic, "Initial Access")
        self.assertIn("T1110", brute.techniques)
        beacon = self.findings_by("flow_beacon")[0]
        self.assertEqual(beacon.tactic, "Command and Control")
        self.assertIn("T1071.001", beacon.techniques)

    def test_after_hours_raises_brute_severity(self):
        brute = self.findings_by("brute_force")[0]
        self.assertGreaterEqual(brute.severity, 3)

    def test_helper_lists(self):
        self.assertIn("xmrig", _BAD_EXE_NAMES)
        self.assertTrue(is_unusual_path("/tmp/xmrig"))
        self.assertTrue(is_unusual_path("/dev/shm/.x"))
        self.assertFalse(is_unusual_path("/usr/bin/sshd"))

    def test_all_findings_have_confidence(self):
        self.assertTrue(all(0.0 <= f.confidence <= 1.0 for f in self.findings))


if __name__ == "__main__":
    unittest.main()