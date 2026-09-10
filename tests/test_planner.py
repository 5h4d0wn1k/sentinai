import os
import tempfile
import unittest

from sentinai.incident import write_incident_report, lessons_learned
from sentinai.planner import Agent, Planner, goal_src
from tests.testutil import seeded_store


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store, self.cfg = seeded_store(self.td.name)
        self.incident = next((i for i in self.store.incidents
                              if i.src == "198.51.100.7"), None)

    def tearDown(self):
        self.td.cleanup()

    def _agent(self):
        return Agent(self.cfg, self.store)

    def test_goal_src_extraction(self):
        self.assertEqual(goal_src("contain intrusion from 198.51.100.7"), "198.51.100.7")
        self.assertIsNone(goal_src("no address here"))

    def test_rule_playbook_contains_phases(self):
        plan = Planner(self.cfg, self.store).plan(
            "contain the intrusion from 198.51.100.7", self.incident, "rule")
        phases = [s.phase for s in plan["steps"]]
        for phase in ("triage", "contain", "eradicate", "recover", "lessons"):
            self.assertIn(phase, phases)
        self.assertEqual(phases[0], "triage")
        self.assertEqual(phases[-1], "lessons")

    def test_llm_unavailable_without_env(self):
        for k in ("SENTINAI_LLM_BASE", "SENTINAI_LLM_KEY"):
            os.environ.pop(k, None)
        self.assertFalse(Planner.llm_available())
        plan = Planner(self.cfg, self.store).plan(
            "contain the intrusion from 198.51.100.7", self.incident, "llm")
        self.assertTrue(any("SENTINAI_LLM_BASE" in n for n in plan["notes"]))
        self.assertTrue(plan["steps"])  # safe rule fallback still produced

    def test_agent_end_to_end_autonomous(self):
        out = self._agent().run(
            "contain intrusion from 198.51.100.7 and eradicate the foothold",
            planner_mode="rule", approval="auto")
        self.assertTrue(out["contained"])
        self.assertLessEqual(out["iters"], out["budget"])
        self.assertIsNotNone(out["incident_id"])
        report = out["report"]
        self.assertTrue(report.get("timeline"), "narrative timeline expected")
        self.assertEqual(report.get("containment"), "CONTAINED")
        self.assertNotEqual(report.get("iocs"), [])
        self.assertGreaterEqual(len(report.get("lessons", [])), 1)
        self.assertGreaterEqual(len(report.get("remediation_checklist", [])), 5)
        actions = [a for a in self.store.actions if a.action == "block-src"]
        self.assertTrue(actions)
        self.assertIn("simulation", actions[0].detail)
        self.assertIn("lessons", [s.phase for s in self.store.plans])
        self.assertTrue(self.store.get_incident(out["incident_id"]).status == "contained")

    def test_agent_budget_respected(self):
        out = self._agent().run("contain the intrusion from 198.51.100.7", budget=2)
        self.assertLessEqual(out["iters"], 2)

    def test_agent_loop_terminates(self):
        out = self._agent().run("contain the intrusion from 198.51.100.7")
        self.assertLessEqual(out["iters"], out["budget"])
        self.assertGreater(out["iters"], 0)


class IncidentReportTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store, self.cfg = seeded_store(self.td.name)
        self.incid = next((i for i in self.store.incidents
                           if i.src == "198.51.100.7"), None)
        self.report = write_incident_report(self.store, self.incid.id, self.cfg,
                                            ["agent note one"])

    def tearDown(self):
        self.td.cleanup()

    def test_incident_has_narrative_with_actor(self):
        self.assertIn("198.51.100.7", self.report["narrative"])
        self.assertIn("Judgement", self.report["narrative"])
        self.assertTrue(self.report["timeline"])

    def test_mitre_mapping_present(self):
        tactics = {m["tactic"] for m in self.report["mitre_mapping"]}
        self.assertIn("Initial Access", tactics)
        self.assertIn("Command and Control", tactics)
        self.assertTrue(all(m["techniques"] for m in self.report["mitre_mapping"]))

    def test_ioc_list_contains_actor(self):
        values = [i["value"] for i in self.report["iocs"]]
        self.assertIn("198.51.100.7", values)

    def test_remediation_checklist_nonempty(self):
        self.assertGreaterEqual(len(self.report["remediation_checklist"]), 5)
        self.assertIn("Block the actor source at the edge",
                      self.report["remediation_checklist"][0])

    def test_lessons_learned_produced(self):
        lessons = lessons_learned(self.incid.to_dict(), 3, 12.0, ["x"])
        self.assertGreaterEqual(len(lessons), 4)

    def test_markdown_and_json_written(self):
        d = os.path.join(self.store.root, "incidents", self.incid.id)
        self.assertTrue(os.path.exists(os.path.join(d, "incident.md")))
        self.assertTrue(os.path.exists(os.path.join(d, "incident.json")))


if __name__ == "__main__":
    unittest.main()