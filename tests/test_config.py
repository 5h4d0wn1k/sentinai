import json
import os
import tempfile
import unittest

from sentinai import config as cfgmod


class ConfigTests(unittest.TestCase):
    def test_yaml_subset_parsing(self):
        text = """
# comment
window:
  correlate: 1800.0
  ssh: 600
thresholds:
  flags: [true, false, 5, 1.5, ok]
name: sentinai
"""
        parsed = cfgmod.parse_yaml(text)
        self.assertAlmostEqual(parsed["window"]["correlate"], 1800.0)
        self.assertEqual(parsed["window"]["ssh"], 600)
        self.assertEqual(parsed["thresholds"]["flags"], [True, False, 5, 1.5, "ok"])
        self.assertEqual(parsed["name"], "sentinai")

    def test_defaults_are_sane(self):
        cfg = cfgmod.load_config(None)
        self.assertEqual(cfg["approval"]["mode"], "ask")
        self.assertGreater(cfg["planner"]["budget"], 5)
        self.assertEqual(cfg["correlate"]["min_channels"], 2)
        self.assertIn("198.51.100.7", _dummy())

    def test_json_config_replaces_mode(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "cfg.json")
            with open(p, "w") as fh:
                json.dump({"approval": {"mode": "never"},
                           "thresholds": {"ssh_failed_min": 3}}, fh)
            cfg = cfgmod.load_config(p)
            self.assertEqual(cfg["approval"]["mode"], "never")
            self.assertEqual(cfg["thresholds"]["ssh_failed_min"], 3)

    def test_charity_gates_survive_override(self):
        # Deep merge: stage weights can be overridden but keys not present stay.
        cfg = cfgmod.load_config(None)
        merged = cfgmod._deep_merge(cfg, {"stage_weights": {"Impact": 2.5}})
        self.assertEqual(merged["stage_weights"]["Impact"], 2.5)
        self.assertEqual(merged["stage_weights"]["Initial Access"], 1.0)
        self.assertEqual(merged["lab"]["allow_loopback"], True)


def _dummy():
    return "fixture src placeholder: 198.51.100.7"


if __name__ == "__main__":
    unittest.main()