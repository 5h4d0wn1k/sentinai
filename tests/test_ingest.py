import os
import tempfile
import unittest

from sentinai.config import load_config
from sentinai.ingest import (parse_auth_log, parse_access_log, parse_process_list,
                             parse_flow_log, parse_alert_feed, ingest_fixtures,
                             channel_counts)
from tests.testutil import fixture, FIXTURES


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(None)

    def test_auth_parses_attack_and_baseline(self):
        events = parse_auth_log(fixture("auth.log"), self.cfg)
        failed = [e for e in events if e.signal == "ssh_failed"]
        attacker = [e for e in failed if e.src == "198.51.100.7"]
        self.assertEqual(len(attacker), 7)  # 6 in burst + 1 after-hours
        self.assertTrue(all(e.extra["user"] in ("root", "admin", "operator")
                            for e in attacker))
        baseline = [e for e in failed if e.src == "192.0.2.11"]
        self.assertEqual(len(baseline), 1)
        self.assertEqual(len([e for e in events if e.signal == "ssh_success"]), 2)

    def test_web_parses_request_and_src(self):
        events = parse_access_log(fixture("access.log"), self.cfg)
        self.assertEqual(len(events), 5)
        sqli = [e for e in events if "0' or '1'='1" in e.raw]
        self.assertEqual(sqli[0].src, "198.51.100.7")
        self.assertEqual(sqli[0].extra["status"], 200)
        five00 = [e for e in events if e.extra["status"] == 500][0]
        self.assertEqual(five00.src, "198.51.100.7")

    def test_process_parses_columns(self):
        events = parse_process_list(fixture("processes.txt"), self.cfg)
        self.assertEqual(len(events), 5)
        xmrig = [e for e in events if e.extra.get("exe", "").endswith("xmrig")][0]
        self.assertEqual(xmrig.extra["exe"], "/tmp/xmrig")
        self.assertEqual(xmrig.extra["user"], "root")
        self.assertEqual(xmrig.extra["pid"], 3127)

    def test_flow_attribution_picks_rfc5737_side(self):
        events = parse_flow_log(fixture("flows.txt"), self.cfg)
        beacon = [e for e in events if e.extra["dport"] == 8444]
        self.assertEqual(beacon[0].src, "198.51.100.7")  # actor = external C2
        self.assertEqual(beacon[0].extra["internal"], "web1.lab.local")
        self.assertTrue(all(e.channel == "flow" for e in events))

    def test_alert_feed_parse(self):
        events = parse_alert_feed(fixture("alerts.jsonl"), self.cfg)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].src, "198.51.100.7")
        self.assertEqual(events[0].signal, "alert_NETSENTINEL_C2_BEACON")
        self.assertTrue(all(e.channel == "alert" for e in events))

    def test_all_channels_present_after_ingest(self):
        events = ingest_fixtures(FIXTURES, self.cfg)
        counts = channel_counts(events)
        for ch in ("auth", "web", "process", "flow", "alert"):
            self.assertIn(ch, counts)
            self.assertGreater(counts[ch], 0)

    def test_providers_are_read_only(self):
        before = {os.path.basename(p): open(p, "rb").read()
                  for p in filter(os.path.isfile, glob_ff())}
        ingest_fixtures(FIXTURES, self.cfg)
        after = {os.path.basename(p): open(p, "rb").read()
                 for p in filter(os.path.isfile, glob_ff())}
        self.assertEqual(before, after)

    def test_events_carry_integer_sorted_chronology(self):
        events = ingest_fixtures(FIXTURES, self.cfg)
        ts = [e.ts for e in events]
        self.assertEqual(ts, sorted(ts))
        self.assertTrue(all(isinstance(e.severity, int) for e in events))


def glob_ff():
    import glob
    return [os.path.join(FIXTURES, f) for f in
            ("auth.log", "access.log", "processes.txt", "flows.txt", "alerts.jsonl")]


if __name__ == "__main__":
    unittest.main()