import os
import unittest

from sentinai.cli import main


class CliTests(unittest.TestCase):
    def tmp(self):
        import tempfile
        return tempfile.mkdtemp()

    def test_version_flag(self):
        import contextlib
        with contextlib.redirect_stderr(None):
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_no_args_prints_help(self):
        self.assertEqual(main([]), 0)

    def test_ingest_command(self):
        with self.subTest():
            td = self.tmp()
            rc = main(["ingest", "--report-root", td])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(os.path.join(td, "events.json")))

    def test_detect_command(self):
        td = self.tmp()
        rc = main(["detect", "--report-root", td])
        self.assertEqual(rc, 0)

    def test_correlate_command(self):
        td = self.tmp()
        rc = main(["correlate", "--report-root", td])
        self.assertEqual(rc, 0)

    def test_triage_command(self):
        td = self.tmp()
        rc = main(["triage", "--report-root", td])
        self.assertEqual(rc, 0)

    def test_respond_denied_returns_nonzero(self):
        td = self.tmp()
        rc = main(["respond", "--action", "block-src", "--target", "198.51.100.7",
                   "--approval", "never", "--report-root", td])
        self.assertEqual(rc, 1)

    def test_respond_approved_returns_zero(self):
        td = self.tmp()
        rc = main(["respond", "--action", "block-src", "--target", "198.51.100.7",
                   "--approval", "auto", "--report-root", td])
        self.assertEqual(rc, 0)

    def test_respond_hard_refused_real_ip(self):
        td = self.tmp()
        rc = main(["respond", "--action", "block-src", "--target", "8.8.8.8",
                   "--approval", "auto", "--report-root", td])
        self.assertEqual(rc, 1)

    def test_planner_command_end_to_end(self):
        td = self.tmp()
        rc = main(["planner", "--goal", "contain intrusion from 198.51.100.7",
                   "--planner", "rule", "--approval", "auto", "--report-root", td])
        self.assertEqual(rc, 0)
        inc = os.path.join(td, "incidents")
        self.assertTrue(os.path.isdir(inc))
        self.assertGreaterEqual(len(os.listdir(inc)), 1)

    def test_incident_report_command(self):
        td = self.tmp()
        self.assertEqual(main(["planner", "--goal",
                               "contain intrusion from 198.51.100.7",
                               "--approval", "auto", "--report-root", td]), 0)
        rc = main(["incident", "--id", "INS-1", "--report-root", td])
        self.assertEqual(rc, 0)

    def test_watch_command(self):
        td = self.tmp()
        rc = main(["watch", "--budget", "4", "--quiet", "--report-root", td])
        self.assertEqual(rc, 0)

    def test_demo_exit_zero_with_proof(self):
        td = self.tmp()
        rc = main(["--demo", "--report-root", td])
        self.assertEqual(rc, 0)
        probe = os.path.join(td, "incidents")
        self.assertTrue(os.path.isdir(probe))
        # Containment proof: at least one block-src action recorded.
        import json
        actions = json.load(open(os.path.join(td, "actions.json")))
        self.assertTrue(any(a["action"] == "block-src" and a["status"] == "simulated"
                            for a in actions))


if __name__ == "__main__":
    unittest.main()