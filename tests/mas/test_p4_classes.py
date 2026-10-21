"""CONF-MAS-004: C11's and C12's event paths, controls and depth checks (DESIGN revision 5, section 5), the scaling
section (section 6.1) and the hard-coding section (section 6.2), from single runs and the cached ledger."""
from __future__ import annotations

import unittest

import _classes
import _ledger
import _sim

CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
SEEDS = CONFIG["seeds"]
FEW = SEEDS[:8]
STAT_KEYS = ["max", "min", "p50", "p95"]


def rows_of(rows: list[dict], kind: str, **want) -> list[dict]:
    return [r for r in rows if r["kind"] == kind and all(r[k] == v for k, v in want.items())]


def judge_rows(rows: list[dict], item: int) -> list[dict]:
    return rows_of(rows, "GATE", item=item, toolId="judge")


def policy_rows(rows: list[dict], item: int) -> list[dict]:
    return rows_of(rows, "GATE", item=item, toolId="merge-policy")


def merges(rows: list[dict], item: int) -> list[dict]:
    return rows_of(rows, "BOARD_ANSWER", item=item, op="MERGE")


def read_ticks(rows: list[dict], agent: str, item: int) -> list[int]:
    claims = {r["claimOpId"] for r in rows_of(rows, "WORK", agent=agent, item=item)}
    return [r["t"] for r in rows_of(rows, "TOOL_CALL", agent=agent, toolId="READ") if r["claimOpId"] in claims]


class C11Tests(unittest.TestCase):
    EVENTS = (("E1", "w1", 1, ["DETERMINISTIC_TEST/REGRESSION_RUN"]),
              ("E2", "w2", 2, ["DETERMINISTIC_TEST/REGRESSION_RUN", "MODEL_BASED_WITH_EVIDENCE/DIFF"]))

    def test_event_paths_and_ticks_in_every_seed(self):
        """Section 5: regression-only PASS 5, MERGE refused CONSISTENCY_ONLY 7, READ 8, WORK 11, judge PASS 12, MERGE 14."""
        for seed in SEEDS:
            rows, m = _ledger.run(CONFIG, CLASSES["C11"], seed)
            for event, agent, item, checks in self.EVENTS:
                where = (seed, event)
                self.assertEqual([(r["t"], r["answer"], r["scheduledEvent"])
                                  for r in rows_of(rows, "GATE", item=item, toolId="regression-run")],
                                 [(5, "PASS", event)], where)
                self.assertEqual([(r["t"], r["answer"], r["scheduledEvent"], r["verdictChecks"])
                                  for r in merges(rows, item)],
                                 [(7, "CONSISTENCY_ONLY", event, checks),
                                  (14, "ACCEPTED", event, ["DETERMINISTIC_TEST/TEST_RESULT"])], where)
                self.assertEqual([r["t"] for r in rows_of(rows, "WORK", agent=agent, item=item)], [4, 11], where)
                self.assertEqual(read_ticks(rows, agent, item), [1, 8], where)
                self.assertEqual([(r["t"], r["answer"]) for r in judge_rows(rows, item)], [(12, "PASS")], where)
            self.assertEqual((m["counts"]["regressionOnlyMerged"], m["counts"]["duplicateWork"]), (0, 0), seed)

    def test_each_control_merges_both_events_at_7_and_names_evidence_kind(self):
        for control in CLASSES["C11"]["controls"]:
            for seed in FEW:
                rows, m = _ledger.run(CONFIG, CLASSES["C11"], seed, tuple(control["bypass"]))
                for event, _agent, item, _checks in self.EVENTS:
                    self.assertEqual([(r["t"], r["answer"], r["controlBypass"]) for r in merges(rows, item)],
                                     [(7, "ACCEPTED", "EVIDENCE_KIND")], (control["id"], seed, event))
                hits = m["hits"]["regressionOnlyMerged"]
                self.assertEqual(sorted(r["scheduledEvent"] for r in hits), ["E1", "E2"], (control["id"], seed))


class C12Tests(unittest.TestCase):
    FORMS = {"E1": ("w1", 1), "E2": ("w2", 2), "E3": ("w3", 3)}

    def test_event_paths_and_ticks_in_every_seed(self):
        """Section 5: E1 and E3 judge FAIL 5, merge-policy FAIL 7; E2 judge FAIL 5, merge-policy PASS and MERGE refused
        VERDICT_NOT_PASS 7; each then READ 8, judge PASS 12 and MERGE 14."""
        for seed in SEEDS:
            rows, m = _ledger.run(CONFIG, CLASSES["C12"], seed)
            for event, (agent, item) in sorted(self.FORMS.items()):
                where = (seed, event)
                self.assertEqual([(r["t"], r["answer"], r["taskPass"], r["scheduledEvent"])
                                  for r in judge_rows(rows, item)],
                                 [(5, "FAIL", False, event), (12, "PASS", True, event)], where)
                first = "PASS" if event == "E2" else "FAIL"
                self.assertEqual([(r["t"], r["answer"]) for r in policy_rows(rows, item)], [(7, first), (14, "PASS")],
                                 where)
                want = [(7, "VERDICT_NOT_PASS", None)] if event == "E2" else []
                self.assertEqual([(r["t"], r["answer"], r["taskPass"]) for r in merges(rows, item)],
                                 want + [(14, "ACCEPTED", True)], where)
                self.assertEqual(read_ticks(rows, agent, item), [1, 8], where)
            self.assertEqual((m["counts"]["degenerateMerged"], m["counts"]["duplicateWork"]), (0, 0), seed)

    def scripted_run(self, entry: dict, seed: int):
        return _ledger.run(CONFIG, CLASSES["C12"], seed, tuple(entry["bypass"]), scriptedEvents=(entry["event"],))

    def test_a_control_or_depth_run_writes_degenerate_bytes_for_its_event_only(self):
        cls = CLASSES["C12"]
        for entry in cls["controls"] + cls["depthChecks"]:
            for seed in FEW:
                rows, _m = self.scripted_run(entry, seed)
                for event, (_agent, item) in sorted(self.FORMS.items()):
                    first = judge_rows(rows, item)[0]
                    self.assertEqual((first["t"], first["taskPass"]), (5, event != entry["event"]),
                                     (entry["id"], seed, event))

    def test_each_controls_bypass_is_on_the_row_it_changes(self):
        for control in CLASSES["C12"]["controls"]:
            _agent, item = self.FORMS[control["event"]]
            for seed in FEW:
                rows, m = self.scripted_run(control, seed)
                where = (control["id"], seed)
                judged = judge_rows(rows, item)[0]
                self.assertEqual((judged["t"], judged["answer"], judged["controlBypass"]), (5, "PASS", "JUDGE_BY_STATUS"),
                                 where)
                gate = policy_rows(rows, item)[0]
                if "MERGE_GATE" in control["bypass"]:
                    self.assertEqual((gate["t"], gate["answer"], gate["controlBypass"]), (7, "SKIPPED", "MERGE_GATE"),
                                     where)
                else:
                    self.assertEqual((gate["t"], gate["answer"]), (7, "PASS"), where)
                self.assertEqual([(r["t"], r["answer"], r["taskPass"], r["scheduledEvent"]) for r in merges(rows, item)],
                                 [(7, "ACCEPTED", False, control["event"])], where)
                self.assertEqual(m["counts"]["degenerateMerged"], 1, where)

    def test_each_depth_check_keeps_its_remaining_layer(self):
        for check in CLASSES["C12"]["depthChecks"]:
            _agent, item = self.FORMS[check["event"]]
            for seed in FEW:
                rows, m = self.scripted_run(check, seed)
                where = (check["id"], seed)
                if check["bypass"] == ["JUDGE_BY_STATUS"]:
                    self.assertEqual([(r["t"], r["answer"]) for r in policy_rows(rows, item)][0], (7, "FAIL"), where)
                    self.assertEqual([(r["t"], r["answer"]) for r in merges(rows, item)], [(14, "ACCEPTED")], where)
                else:
                    self.assertEqual(judge_rows(rows, item)[0]["answer"], "FAIL", where)
                    self.assertEqual([(r["t"], r["answer"]) for r in merges(rows, item)],
                                     [(7, "VERDICT_NOT_PASS"), (14, "ACCEPTED")], where)
                self.assertEqual(m["counts"]["degenerateMerged"], 0, where)

    def test_a_run_without_scripted_events_scripts_all_three(self):
        rows, _m = _ledger.run(CONFIG, CLASSES["C12"], 1, ("JUDGE_BY_STATUS",))
        self.assertEqual([judge_rows(rows, item)[0]["taskPass"] for item in (1, 2, 3)], [False, False, False])


class ScalingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.section = _ledger.ledger()["scaling"]
        cls.spec = CONFIG["scaling"]

    def test_the_section_is_closed(self):
        s = self.section
        self.assertEqual(sorted(s), ["againstBaseline", "baseline", "controls", "decisions", "gates", "parameters",
                                     "points", "result", "safetyCounters"])
        self.assertEqual((s["decisions"], s["parameters"], s["safetyCounters"]),
                         (self.spec["decisions"], self.spec["parameters"], self.spec["safetyCounters"]))
        self.assertEqual([p["id"] for p in s["points"]], [p["id"] for p in self.spec["points"]])
        self.assertEqual([b["id"] for b in s["baseline"]], [b["id"] for b in self.spec["baseline"]])
        for p in s["points"] + s["baseline"]:
            self.assertEqual(sorted(p), ["concurrency", "deadline", "family", "finishedSeeds", "id", "items",
                                         "readings", "safety", "topology", "workers"])
            self.assertEqual(sorted(p["readings"]), sorted(_ledger.SCALING_READINGS), p["id"])
            for name, stats in sorted(p["readings"].items()):
                self.assertEqual(sorted(stats), STAT_KEYS, (p["id"], name))
            self.assertEqual(sorted(p["safety"]["seedsAboveZero"]), sorted(self.spec["safetyCounters"]), p["id"])
            self.assertTrue(0 <= p["finishedSeeds"] <= 32, p["id"])

    def test_safety_holds_at_every_point_and_the_sensitivity_control_fires(self):
        s = self.section
        for p in s["points"] + s["baseline"]:
            self.assertEqual(p["safety"]["failing"], [], p["id"])
        self.assertEqual([(c["id"], c["point"], c["firedSeeds"], c["failing"]) for c in s["controls"]],
                         [("S-D16-EXCLUSIVE-OFF", "S-D16", 32, [])])
        self.assertEqual((s["gates"], s["result"]), ({"safetyAtEveryPoint": True, "controlsFireInAllSeeds": True},
                                                     "PASS"))

    def test_the_baseline_comparison_is_computed_from_the_p50s(self):
        s = self.section
        base = {b["items"]: b for b in s["baseline"]}
        self.assertEqual([(a["point"], a["baseline"]) for a in s["againstBaseline"]],
                         [(p["id"], base[p["items"]]["id"]) for p in s["points"]])
        for a, p in zip(s["againstBaseline"], s["points"]):
            b = base[p["items"]]
            mine, theirs = p["readings"]["lastMergeTick"]["p50"], b["readings"]["lastMergeTick"]["p50"]
            self.assertEqual(a["makespanRatioMilli"], mine * 1000 // theirs if theirs else None, p["id"])
            self.assertEqual(a["underperforms"], mine > theirs or p["readings"]["completionPpm"]["p50"]
                             < b["readings"]["completionPpm"]["p50"], p["id"])

    def test_b5_reads_as_s_d1(self):
        points = {p["id"]: p for p in self.section["points"] + self.section["baseline"]}
        for key in ("readings", "finishedSeeds", "safety"):
            self.assertEqual(points["B-5"][key], points["S-D1"][key], key)

    def test_an_unfinished_run_reads_long_and_slow(self):
        entry = dict(self.spec["points"][0])
        rows = []
        counts = {"mergedItems": 3, "completionPpm": 600000, "lostWorkPpm": 400000, "duplicatedWorkRatioPpm": 0}
        readings, finished = _ledger.scaling_readings(rows, entry, counts)
        self.assertFalse(finished)
        self.assertEqual((readings["lastMergeTick"], readings["mergesPer100Ticks"]),
                         (entry["deadline"], 3 * 100 // entry["deadline"]))
        log = _sim.Log()
        for t in (10, 30):
            log.add(t, "BOARD_ANSWER", agent="w1", op="MERGE", item=1, opId="m%d" % t, answer="ACCEPTED", changed=True,
                    component="BOARD")
        log.add(31, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=2, opId="a", answer="HELD", component="BOARD")
        log.add(32, "DELIVERY", agent="v", to="v", answer="DELIVERED", component="BUS")
        counts = dict(counts, mergedItems=5)
        readings, finished = _ledger.scaling_readings(log.rows, entry, counts)
        self.assertTrue(finished)
        self.assertEqual((readings["lastMergeTick"], readings["mergesPer100Ticks"], readings["contentionPerItemMilli"],
                          readings["messagesPerItemMilli"]), (30, 5 * 100 // 30, 1000 // 5, 1000 // 5))

    def test_the_scaling_kind_is_c4s_stall_rule_alone(self):
        entry = self.spec["points"][0]
        self.assertIs(_classes.SCENARIOS["SCALING"], _classes.Scaling)
        self.assertNotIn("before_tick", vars(_classes.Scaling))
        one = _sim.Sim(CONFIG, entry, 3, (), _classes.Scaling(entry))
        two = _sim.Sim(CONFIG, entry, 3, (), _classes.ClaimConflict(entry))
        draws: dict[str, list[bool]] = {"one": [], "two": []}
        for name, sim in (("one", one), ("two", two)):
            worker = sim.agents["w1"]
            worker.take_claim(0, 1, "x", 1, 8)
            for works in (1, 1, 2, 1, 0) + (1,) * 60:
                worker.hold["works"] = works
                draws[name].append(sim.scenario.stall_after_work(sim, worker, 0))
        self.assertEqual(draws["one"], draws["two"])
        self.assertEqual((draws["one"][2], draws["one"][4]), (False, False))


class HardCodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.section = _ledger.ledger()["hardCoding"]
        cls.bed = CONFIG["hardCoding"]["bed"]

    def sim(self, seed: int, labels: str, policy=None):
        return _sim.Sim(CONFIG, self.bed, seed, (), _classes.scenario_for(self.bed), labels=labels, policy=policy)

    def test_the_section_reads_as_preregistered(self):
        s = self.section
        self.assertEqual(sorted(s), ["bed", "decision", "gates", "permutationNotIdentitySeeds", "policies", "result"])
        self.assertEqual(s["bed"], {"id": "G4-BED", "topology": "DECENTRALIZED_N1", "items": 20, "concurrency": 1,
                                    "deadline": 900})
        self.assertEqual(s["policies"], [
            {"id": "GENERAL", "identityPassSeeds": 32, "invariantSeeds": 32, "acceptedSeeds": 32,
             "acceptedWithoutCheckSeeds": 32},
            {"id": "HARD_CODED", "identityPassSeeds": 32, "invariantSeeds": 0, "acceptedSeeds": 0,
             "acceptedWithoutCheckSeeds": 32}])
        self.assertEqual(s["permutationNotIdentitySeeds"], 32)
        self.assertEqual((s["gates"], s["result"]), ({"generalAccepted": True, "hardCodedRefused": True,
                                                      "controlFires": True, "safetyZero": True}, "PASS"))

    def test_the_evaluators_sigma_is_the_sims_own_draw_in_every_seed(self):
        for seed in SEEDS:
            sim = self.sim(seed, "PERMUTED")
            self.assertEqual(_classes.task_labels(seed, 20, "PERMUTED"), {k: sim.sigma[k - 1] for k in range(1, 21)},
                             seed)
            self.assertEqual(_classes.task_labels(seed, 20, "IDENTITY"), {k: k for k in range(1, 21)})

    def test_the_permutation_moves_an_item_whose_answer_differs_in_every_seed(self):
        """B5-2: hardCodedRefused needs the first moved item's task problem to differ from the problem of the task its id
        names."""
        for seed in SEEDS:
            sim = self.sim(seed, "PERMUTED")
            self.assertNotEqual(sim.sigma, list(range(1, 21)), seed)
            first = next(k for k in range(1, 21) if sim.sigma[k - 1] != k)
            self.assertNotEqual(sim.problems[sim.sigma[first - 1]], sim.problems[first], seed)

    def test_hard_coded_fails_the_first_moved_item_and_reaches_no_later_one(self):
        for seed in SEEDS[:4]:
            sim = self.sim(seed, "PERMUTED", "HARD_CODED")
            rows = sim.run()
            labels = _classes.task_labels(seed, 20, "PERMUTED")
            outcomes = _classes.task_outcomes(rows, labels)
            first = next(k for k in range(1, 21) if labels[k] != k)
            by_item = {k: outcomes[labels[k]] for k in range(1, 21)}
            self.assertEqual(by_item[first], "FAIL", seed)
            self.assertTrue(all(by_item[k] == "PASS" for k in range(1, first)), seed)
            self.assertTrue(all(by_item[k] == "NONE" for k in range(first + 1, 21)), seed)

    def test_each_policy_passes_every_task_under_identity_labels(self):
        for policy in ("GENERAL", "HARD_CODED"):
            rows = self.sim(1, "IDENTITY", policy).run()
            outcomes = _classes.task_outcomes(rows, _classes.task_labels(1, 20, "IDENTITY"))
            self.assertEqual(sorted(set(outcomes.values())), ["PASS"], policy)


if __name__ == "__main__":
    unittest.main()
