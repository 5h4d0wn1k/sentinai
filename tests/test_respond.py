import os
import shutil
import tempfile
import unittest

from sentinai.config import load_config
from sentinai.lab import classify_target, Lab, KIND_LOOPBACK, KIND_LAB, KIND_REFUSED
from sentinai.respond import ApprovalGate, Responder
from tests.testutil import make_env, seeded_store, STUB, fixture


class RespondTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store, self.cfg = seeded_store(self.td.name, approval_mode="ask")
        self.cfg["paths"]["lab_iptables"] = STUB

    def tearDown(self):
        self.td.cleanup()

    def _responder(self, mode="ask", preapproved=False):
        return Responder(self.store, self.cfg,
                         gate=ApprovalGate(mode, preapproved=preapproved))

    def test_block_with_approval_records_block(self):
        lab = Lab(self.cfg, self.store.root)
        act = self._responder("auto").run("block-src", "198.51.100.7",
                                          incident_id=self.main_incident().id)
        self.assertEqual(act.status, "simulated")
        self.assertIn(act.id, self.main_incident().action_ids)
        self.assertTrue(lab.src_blocked("198.51.100.7"))
        self.assertIn("simulation", act.detail)

    def test_block_refused_without_approval(self):
        act = self._responder("never").run("block-src", "198.51.100.7")
        self.assertEqual(act.status, "denied")
        self.assertFalse(self._lab_rules_contain("198.51.100.7"))

    def test_block_ask_denied_non_tty(self):
        act = self._responder("ask", preapproved=False).run("block-src", "198.51.100.7")
        self.assertEqual(act.status, "denied")

    def test_block_hard_refused_non_loopback_real_ip(self):
        act = self._responder("auto").run("block-src", "8.8.8.8")
        self.assertEqual(act.status, "hard_refused")
        self.assertEqual(act.mode, "refused")

    def test_block_hard_refused_private(self):
        act = self._responder("auto").run("block-src", "10.0.0.5")
        self.assertEqual(act.status, "hard_refused")

    def test_block_loopback_real_ack(self):
        act = self._responder("auto", preapproved=True).run("block-src", "127.0.0.1")
        self.assertEqual(act.status, "executed")
        self.assertEqual(act.mode, "executed")
        self.assertIn("ACK", act.detail)
        rules = self._lab_rules()
        self.assertIn("127.0.0.1", rules)

    def test_classify_targets(self):
        self.assertEqual(classify_target("127.0.0.1", self.cfg).kind, KIND_LOOPBACK)
        self.assertEqual(classify_target("localhost", self.cfg).kind, KIND_LOOPBACK)
        self.assertEqual(classify_target("198.51.100.7", self.cfg).kind, KIND_LAB)
        self.assertEqual(classify_target("edge1.lab.local", self.cfg).kind, KIND_LAB)
        self.assertEqual(classify_target("8.8.8.8", self.cfg).kind, KIND_REFUSED)
        self.assertEqual(classify_target("10.1.2.3", self.cfg).kind, KIND_REFUSED)

    def test_rotate_secret_generation_bump(self):
        lab = Lab(self.cfg, self.store.root)
        before = lab.secret_generation("lab-db-password")
        act = self._responder("auto").run("rotate-fixture-secret", "lab-db-password")
        after = lab.secret_generation("lab-db-password")
        self.assertEqual(act.status, "executed")
        self.assertEqual(after, before + 1)
        self.assertIn("generation", act.detail)

    def test_rotate_unknown_secret_refused(self):
        act = self._responder("auto").run("rotate-fixture-secret", "prod-db-password")
        self.assertEqual(act.status, "hard_refused")

    def test_disable_user_simulated(self):
        act = self._responder("auto").run("disable-user", "root")
        self.assertEqual(act.status, "executed")
        self.assertEqual(act.mode, "simulated")

    def test_disable_unknown_user_refused(self):
        act = self._responder("auto").run("disable-user", "ceo")
        self.assertEqual(act.status, "hard_refused")

    def test_snapshot_copies_evidence(self):
        evidence = os.path.join(self.store.root, "evidence")
        act = self._responder("auto").run(
            "snapshot-artifact", fixture("auth.log"), incident_id=self.main_incident().id)
        self.assertEqual(act.status, "executed")
        dest = os.path.join(evidence, self.main_incident().id, "auth.log")
        self.assertTrue(os.path.exists(dest))
        self.assertEqual(open(dest).read(), open(fixture("auth.log")).read())

    def test_snapshot_outside_fixtures_refused(self):
        tmp = os.path.join(self.td.name, "not-a-fixture.txt")
        open(tmp, "w").write("untrusted")
        act = self._responder("auto").run("snapshot-artifact", tmp)
        self.assertEqual(act.status, "hard_refused")

    def main_incident(self):
        return next((i for i in self.store.incidents if i.src == "198.51.100.7"), None)

    def _lab_rules(self):
        st = os.path.join(self.td.name, "lab", "state")
        rules = os.path.join(st, "iptables.rules")
        return open(rules).read() if os.path.exists(rules) else ""

    def _lab_rules_contain(self, needle):
        return needle in self._lab_rules()


if __name__ == "__main__":
    unittest.main()