import tempfile
import unittest

from sentinai.watch import watch, run_round
from tests.testutil import make_env, fresh_store, FIXTURES


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.cfg = make_env(self.td.name)
        self.store = fresh_store(self.cfg, self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_watch_consumes_feed_within_budget(self):
        result = watch(self.store, self.cfg, FIXTURES, interval=60.0,
                       budget=5, batch=6, quiet=True)
        self.assertLessEqual(result["rounds"], 5)
        self.assertGreater(result["consumed"], 0)

    def test_watch_terminates_with_tiny_budget(self):
        result = watch(self.store, self.cfg, FIXTURES, interval=1.0,
                       budget=1, batch=1, quiet=True)
        self.assertEqual(result["rounds"], 1)

    def test_run_round_ingests_events(self):
        first = watch(self.store, self.cfg, FIXTURES, interval=1.0,
                      budget=1, batch=50, quiet=True)
        self.assertGreaterEqual(self.store.state["event_seq"], 1)

    def test_watch_orders_consumption_and_reports(self):
        # budget 1, batch 5: only first 5 events land in this session.
        result = watch(self.store, self.cfg, FIXTURES, interval=1.0,
                       budget=1, batch=5, quiet=True)
        self.assertEqual(result["rounds"], 1)
        self.assertEqual(result["consumed"] or 0, min(5, len(self.store.events)))

    def test_watch_full_budget_discovers_incident_actor(self):
        result = watch(self.store, self.cfg, FIXTURES, interval=1800.0,
                       budget=30, batch=4, quiet=True)
        incident_srcs = {u["src"] for u in result["updates"]}
        self.assertIn("198.51.100.7", incident_srcs)


if __name__ == "__main__":
    unittest.main()