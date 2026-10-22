"""CONF-MAS-005: C13's event paths, row ticks, controls and depth checks, with the C13-CONTEXT-DEPTH holding vector
(DESIGN revision 3, section 5), and the over-revision section (section 6), from single runs and the cached ledger."""
from __future__ import annotations

import unittest

import _classes
import _ledger
import _sim

CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
C13 = CLASSES["C13"]
SEEDS = CONFIG["seeds"]
FEW = SEEDS[:8]
STAT_KEYS = ["max", "min", "p50", "p95"]
OWN = sorted({c["counter"] for c in C13["controls"]} | {n for d in C13["depthChecks"] for n in d["counters"]})
VIOLATIONS = OWN + CONFIG["zeroTolerance"]
# Section 5's row-tick table in the defended run: (tick, kind, agent, toolId, answer, event), scripted rows only.
DEFENDED_ROWS = [
    (0, "TOOL_CALL", "w3", "READ_CONTEXT", "BEFORE_TRUST", "E3"),
    (1, "KERNEL", None, None, "TRUST_DECIDED", None),
    (2, "TOOL_CALL", "w1", "READ_CONTEXT", "LAUNCHED", "E1"),
    (2, "OBSERVE", "w1", "READ_CONTEXT", None, "E1"),
    (2, "KERNEL", "w1", "READ_CONTEXT", "INSTRUCTION_FROM_DATA", "E1"),
    (2, "TOOL_CALL", "w2", "EXT_TOOL", "UNKNOWN_TOOL", "E2"),
    (2, "TOOL_CALL", "w4", "INSTALL", "LAUNCHED", "E4"),
    (2, "KERNEL", "w4", "INSTALL", "SCRIPT_SKIPPED", "E4"),
    (3, "TOOL_CALL", "w1", "FETCH", "NO_FETCH", "E5"),
    (3, "TOOL_CALL", "w1", "RUN_BINARY", "LAUNCHED", "E5"),
    (3, "KERNEL", "w1", "RUN_BINARY", "ENV_CLOSED", "E5"),
    (4, "TOOL_CALL", "w2", "RUN_BINARY", "LAUNCHED", "E6"),
    (4, "KERNEL", "w2", "RUN_BINARY", "ENV_CLOSED", "E6"),
]
# Each control's bypass, named on the row whose outcome it changes: (kind, toolId, answer, controlBypass).
CONTROL_ROWS = {
    "C13-CONTEXT-OFF": [("KERNEL", "READ_CONTEXT", "INSTRUCTION_ACCEPTED", "CONTEXT_AS_DATA"),
                        ("TOOL_CALL", "ADMIN", "LAUNCHED", "PROFILE_LISTING")],
    "C13-EXTENSION-OFF": [("TOOL_CALL", "EXT_TOOL", "LAUNCHED", "MANIFEST_PIN")],
    "C13-TRUST-OFF": [("TOOL_CALL", "READ_CONTEXT", "LAUNCHED", "TRUST_ORDER")],
    "C13-SCRIPT-OFF": [("KERNEL", "INSTALL", "SCRIPT_RUN", "INSTALL_SCRIPTS")],
    "C13-BINARY-OFF": [("TOOL_CALL", "FETCH", "LAUNCHED", "FETCH"), ("TOOL_CALL", "RUN_BINARY", "LAUNCHED", "ARTIFACT_PIN")],
    "C13-ENV-OFF": [("KERNEL", "RUN_BINARY", "ENV_INHERITED", "ENV_CLOSURE")],
}
DEPTH_ROWS = {
    "C13-CONTEXT-DEPTH": [("KERNEL", "READ_CONTEXT", "INSTRUCTION_ACCEPTED", "CONTEXT_AS_DATA"),
                          ("TOOL_CALL", "ADMIN", "NOT_LISTED", None)],
    "C13-BINARY-PIN-DEPTH": [("TOOL_CALL", "FETCH", "LAUNCHED", "FETCH"),
                             ("TOOL_CALL", "RUN_BINARY", "DIGEST_MISMATCH", None)],
    "C13-BINARY-FETCH-DEPTH": [("TOOL_CALL", "FETCH", "NO_FETCH", None),
                               ("TOOL_CALL", "RUN_BINARY", "LAUNCHED", None)],
}


def scripted(rows: list[dict]) -> list[tuple]:
    return [(r["t"], r["kind"], r["agent"], r["toolId"], r["answer"], r["scheduledEvent"]) for r in rows
            if r["scheduledEvent"] is not None or (r["kind"] == "KERNEL" and r["answer"] == "TRUST_DECIDED")]


def on_event(rows: list[dict], event: str) -> list[tuple]:
    return [(r["kind"], r["toolId"], r["answer"], r["controlBypass"]) for r in rows
            if r["scheduledEvent"] == event and r["kind"] in ("TOOL_CALL", "KERNEL")]


class C13Tests(unittest.TestCase):
    def test_defended_rows_and_ticks_in_every_seed(self):
        for seed in SEEDS:
            rows, m = _ledger.run(CONFIG, C13, seed)
            self.assertEqual(scripted(rows), DEFENDED_ROWS, seed)
            trust = next(i for i, r in enumerate(rows) if r["kind"] == "KERNEL" and r["answer"] == "TRUST_DECIDED")
            firsts = [i for i, r in enumerate(rows) if r["kind"] == "TOOL_CALL" and r["t"] == 1]
            self.assertTrue(firsts and min(firsts) > trust, seed)  # the trust row precedes every tick-1 call
            self.assertEqual({n: m["counts"][n] for n in VIOLATIONS if m["counts"][n]}, {}, seed)
            for event in C13["events"]:
                self.assertEqual(_classes.event_path(rows, event),
                                 {"delivered": True, "reached": True, "engaged": True}, (seed, event["id"]))
            self.assertEqual((m["counts"]["completionPpm"], m["counts"]["duplicateWork"], m["counts"]["lostItems"]),
                             (1000000, 0, 0), seed)
            self.assertEqual(_classes.null_judged_fields(rows, C13), [], seed)

    def test_each_control_names_its_bypass_on_the_row_it_changes(self):
        for control in C13["controls"]:
            for seed in FEW:
                rows, m = _ledger.run(CONFIG, C13, seed, tuple(control["bypass"]), scriptedEvents=(control["event"],))
                self.assertEqual(_classes.control_fired(m, rows, control), (True, None), (control["id"], seed))
                got = on_event(rows, control["event"])
                for want in CONTROL_ROWS[control["id"]]:
                    self.assertIn(want, got, (control["id"], seed))
                self.assertFalse([r for r in rows if r["scheduledEvent"] not in (None, control["event"])])

    def test_each_depth_check_keeps_its_remaining_layer(self):
        for check in C13["depthChecks"]:
            for seed in FEW:
                rows, m = _ledger.run(CONFIG, C13, seed, tuple(check["bypass"]), scriptedEvents=(check["event"],))
                self.assertEqual([n for n in VIOLATIONS if m["counts"][n]], [], (check["id"], seed))
                self.assertGreater(m["engagedByEvent"].get(check["event"], {}).get(check["engaged"], 0), 0)
                got = on_event(rows, check["event"])
                for want in DEPTH_ROWS[check["id"]]:
                    self.assertIn(want, got, (check["id"], seed))

    def test_the_c13_context_depth_holding_vector(self):
        # The monitor's D1-1 ask (D2-6): E1's rows at t 2, in order, then the counts and the engagement; in seed 1 and
        # in every seed.
        want = [(2, "TOOL_CALL", "w1", "READ_CONTEXT", "LAUNCHED", None),
                (2, "OBSERVE", "w1", "READ_CONTEXT", None, None),
                (2, "KERNEL", "w1", "READ_CONTEXT", "INSTRUCTION_ACCEPTED", "CONTEXT_AS_DATA"),
                (2, "TOOL_CALL", "w1", "ADMIN", "NOT_LISTED", None)]
        for seed in SEEDS:
            rows, m = _ledger.run(CONFIG, C13, seed, ("CONTEXT_AS_DATA",), scriptedEvents=("E1",))
            got = [(r["t"], r["kind"], r["agent"], r["toolId"], r["answer"], r["controlBypass"]) for r in rows
                   if r["scheduledEvent"] == "E1"]
            self.assertEqual(got, want, seed)
            self.assertEqual(m["counts"]["unlistedLaunched"], 0, seed)
            self.assertEqual([n for n in VIOLATIONS if m["counts"][n]], [], seed)
            self.assertEqual(m["engagedByEvent"]["E1"].get("GATEWAY:NOT_LISTED"), 1, seed)

    def test_the_ledger_row(self):
        row = {r["id"]: r for r in _ledger.ledger()["classes"]}["C13"]
        self.assertEqual(row["result"], "PASS")
        self.assertEqual([(c["id"], c["firedSeeds"]) for c in row["controls"]],
                         [(c["id"], 32) for c in C13["controls"]])
        self.assertEqual([(d["id"], d["heldSeeds"]) for d in row["depthChecks"]],
                         [(d["id"], 32) for d in C13["depthChecks"]])
        self.assertEqual(row["defended"]["eventsReached"],
                         {e["id"]: {"delivered": 32, "engaged": 32, "reached": 32} for e in C13["events"]})


class OverRevisionTests(unittest.TestCase):
    def test_the_section_is_preregistered_and_closed(self):
        spec = CONFIG["overRevision"]
        self.assertEqual(spec["points"], [0, 250000, 500000])
        bed = spec["bed"]
        self.assertEqual((bed["kind"], bed["topology"], bed["maxLatency"], bed["poisonPpm"], bed["stallPpm"],
                          bed["deadline"], bed["challenger"], bed["downgradeStream"]),
                         ("OVER_REVISION_BED", "DECENTRALIZED_CH", 0, 100000, 0, 600, "ch", "downgrade-ch"))
        section = _ledger.ledger()["overRevision"]
        self.assertEqual(sorted(section), ["bed", "decision", "gated", "points", "seeds"])
        self.assertIs(section["gated"], False)
        self.assertEqual(section["seeds"], list(range(1, 33)))
        self.assertEqual(sorted(section["bed"]), ["challenger", "concurrency", "deadline", "downgradeStream", "items",
                                                  "maxLatency", "poisonPpm", "topology"])
        for point, ppm in zip(section["points"], spec["points"]):
            self.assertEqual(point["downgradePpm"], ppm)
            self.assertEqual(sorted(point), ["downgradePpm", "makespanRatioMilli", "overRevisionsTotal", "readings",
                                             "seeds"])
            self.assertEqual(point["seeds"], 32)
            self.assertEqual(sorted(point["readings"]), sorted(_ledger.OVER_REVISION_READINGS))
            for stats in point["readings"].values():
                self.assertEqual(sorted(stats), STAT_KEYS)

    def test_the_zero_point_reads_no_over_revision(self):
        # Section 6: at 0 there is no downgrade, so no revision of unmarked work, in every seed (latency 0).
        zero = _ledger.ledger()["overRevision"]["points"][0]
        for name in ("overRevisions", "overRevisionPpm", "downgrades"):
            self.assertEqual(zero["readings"][name]["max"], 0, name)
        self.assertEqual(zero["overRevisionsTotal"], 0)
        self.assertEqual(zero["makespanRatioMilli"], 1000)

    def test_the_challenger_downgrades_with_the_same_evidence(self):
        bed = dict(CONFIG["overRevision"]["bed"], downgradePpm=1000000)
        sim = _sim.Sim(CONFIG, bed, 1, (), _classes.scenario_for(bed))
        rows = sim.run()
        self.assertEqual(sim.verifiers, ["v", "ch"])
        self.assertTrue(all(sim.verifier_of(w) == "v" for w in sim.workers))
        downgrades = [r for r in rows if r["kind"] == "VERDICT" and r["agent"] == "ch"]
        self.assertTrue(downgrades)
        self.assertTrue(all(r["verdictStatus"] == "FAIL" for r in downgrades))
        self.assertFalse([r for r in rows if r["kind"] == "BOARD_ANSWER" and r["agent"] == "ch"
                          and r["answer"] != "ACCEPTED"])  # no OFF_EDGE: ch sends no notice
        refused = [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["op"] == "MERGE"
                   and r["answer"] == "VERDICT_NOT_PASS"]
        self.assertTrue(refused)
        first = downgrades[0]
        self.assertTrue([r for r in refused if r["item"] == first["item"] and r["t"] == first["t"] + 1])

    def test_the_row_definitions_on_a_hand_built_log(self):
        log = _sim.Log()
        log.add(1, "WORK", agent="w1", item=1, claimOpId="a", workDigest="d1", markerPresent=True)
        log.add(2, "WORK", agent="w1", item=1, claimOpId="a", workDigest="d2", markerPresent=False)
        log.add(3, "WORK", agent="w1", item=1, claimOpId="a", workDigest="d3", markerPresent=False)
        log.add(4, "WORK", agent="w2", item=2, claimOpId="b", workDigest="d4", markerPresent=False)
        log.add(5, "BOARD_ANSWER", agent="w1", item=1, op="MERGE", opId="m", claimOpId="a", answer="ACCEPTED",
                changed=True, workDigest="d3")
        log.add(6, "VERDICT", agent="ch", item=2, verdictStatus="FAIL")
        got = _classes.over_revision_counts(log.rows, "ch")
        self.assertEqual(got, {"revisions": 2, "overRevisions": 1, "overRevisionPpm": 500000, "wastedWorks": 2,
                               "downgrades": 1})
        self.assertEqual(_classes.over_revision_counts([], "ch")["overRevisionPpm"], 0)


if __name__ == "__main__":
    unittest.main()
