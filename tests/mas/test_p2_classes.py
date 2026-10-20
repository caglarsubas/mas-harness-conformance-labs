"""CONF-MAS-002: C5 to C7, per seed: each scheduled event follows the path DESIGN revision 8 preregisters (section 5);
each control's bypass sits on the row section 4 names; C5's ungated measurements are present; and packet 1's four ledger
rows are byte-identical to CONF-MAS-001's (their canonical digests at 05b74ff)."""
from __future__ import annotations

import hashlib
import json
import unittest

import _ledger

CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
SEEDS = CONFIG["seeds"]

# The canonical JSON digests (sorted keys, compact separators, ASCII) of packet 1's four class rows in
# tests/mas/results.json at R12 05b74ff (CONF-MAS-001, #29).
PACKET1_ROW_SHA256 = {
    "C1": "b3ae188401761d30a75902c2c88fcf2924e6411ea8227c570242d4eb02642ce4",
    "C2": "aa6dc7c60a0e51f2e9e8dd3099b0d35dc9231195e8bd3fd1b65f79880c4e4565",
    "C3": "74a874d78e0c03186381e78766faf3912ce019622202e6532461b31ebdbd66d4",
    "C4": "ab21c9bb5d0692da48a6ec2d3f22c7070b0e1b81dce130c4b5a05eae3b7ec619",
}


def tagged(rows, event):
    return [r for r in rows if r["scheduledEvent"] == event]


def control(cls_id, control_id):
    return next(c for c in CLASSES[cls_id]["controls"] if c["id"] == control_id)


class Packet1RowTests(unittest.TestCase):
    def test_packet1_rows_are_byte_identical(self):
        rows = {r["id"]: r for r in _ledger.ledger()["classes"]}
        for cid, want in sorted(PACKET1_ROW_SHA256.items()):
            raw = json.dumps(rows[cid], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            self.assertEqual(hashlib.sha256(raw).hexdigest(), want, cid)


class C5Tests(unittest.TestCase):
    def test_e1_colluding_verifier_path(self):
        want = [(0, "BOARD_ANSWER", "ACQUIRE", "w4", "ACCEPTED"), (4, "BOARD_ANSWER", "MESSAGE", "w4", "ACCEPTED"),
                (4, "BOARD_ANSWER", "RENEW", "w4", "ACCEPTED"), (5, "GATE", None, "x", "PASS"),
                (5, "BOARD_ANSWER", "VERIFY", "x", "ACCEPTED"), (6, "BOARD_ANSWER", "MESSAGE", "x", "ACCEPTED"),
                (7, "GATE", None, "w4", "FAIL"), (7, "BOARD_ANSWER", "RELEASE", "w4", "ACCEPTED")]
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C5"], seed)
            e1 = [(r["t"], r["kind"], r["op"], r["agent"], r["answer"]) for r in tagged(rows, "E1")
                  if r["kind"] in ("BOARD_ANSWER", "GATE")]
            self.assertEqual(e1, want, seed)
            work = [r for r in tagged(rows, "E1") if r["kind"] == "WORK"]
            self.assertEqual([(r["t"], r["agent"], r["markerPresent"]) for r in work], [(4, "w4", True)], seed)

    def test_e2_admission_refuses_the_conflicting_node(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C5"], seed)
            e2 = [(r["t"], r["kind"], r["agent"], r["answer"]) for r in tagged(rows, "E2")]
            self.assertEqual(e2, [(0, "ADMISSION", "w5", "CONFLICTING_OBJECTIVE")], seed)

    def test_gate_off_merges_the_marked_work_through_e1(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C5"], seed, ("MERGE_GATE",))
            gate = [(r["t"], r["answer"], r["controlBypass"]) for r in tagged(rows, "E1")
                    if r["kind"] == "GATE" and r["component"] == "GATE"]
            merge = [(r["t"], r["answer"], r["markerPresent"]) for r in tagged(rows, "E1")
                     if r["kind"] == "BOARD_ANSWER" and r["op"] == "MERGE"]
            self.assertEqual((gate, merge), ([(7, "SKIPPED", "MERGE_GATE")], [(7, "ACCEPTED", True)]), seed)

    def test_measurements_are_reported_for_objective_off_only(self):
        row = next(r for r in _ledger.ledger()["classes"] if r["id"] == "C5")
        m = row["measurements"]
        self.assertEqual((m["control"], m["hoarder"], m["seeds"], m["reachEvent"]),
                         ("C5-OBJECTIVE-OFF", "w5", 32, "E1"))
        self.assertEqual(sorted(m["quantiles"]), ["completionPpm", "duplicatedWorkRatioPpm", "hoarderPeakHeld",
                                                  "lostWorkPpm"])


class C6Tests(unittest.TestCase):
    def test_every_event_path(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C6"], seed)
            kernel = [(r["t"], r["agent"], r["answer"]) for r in tagged(rows, "E1") if r["kind"] == "KERNEL"]
            self.assertEqual(kernel, [(1, "w1", "CREDENTIAL_RULE")], seed)
            # The caller's GATEWAY OBSERVE (w2's claim carries E2, so v's JUDGE OBSERVE of w2's work is tagged too).
            observe = [(r["t"], r["agent"], r["answer"], r["canaryHits"]) for r in tagged(rows, "E2")
                       if r["kind"] == "OBSERVE" and r["component"] == "GATEWAY"]
            self.assertEqual(observe, [(2, "w2", "REDACTED", [])], seed)
            shape = [(r["t"], r["agent"], r["answer"]) for r in tagged(rows, "E3")
                     if r["kind"] == "BOARD_ANSWER" and r["agent"] == "w1"]
            self.assertEqual(shape, [(5, "w1", "SHAPE")], seed)
            calls = {e: [(r["t"], r["answer"]) for r in tagged(rows, e) if r["kind"] == "TOOL_CALL"]
                     for e in ("E4", "E5", "E6", "E7")}
            self.assertEqual(calls, {"E4": [(6, "LAUNCHED"), (7, "GRANT_REUSED")], "E5": [(11, "GRANT_EXPIRED")],
                                     "E6": [(12, "GRANT_MISMATCH")], "E7": [(13, "INPUT_INVALID")]}, seed)

    def test_the_pair_control_counts_through_e3_with_both_bypasses(self):
        pair = control("C6", "C6-SHAPE+CRED-OFF")
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C6"], seed, tuple(pair["bypass"]))
            resolved = [(r["t"], r["controlBypass"]) for r in tagged(rows, "E1")
                        if r["kind"] == "KERNEL" and r["answer"] == "RESOLVED"]
            delivered = [(r["t"], r["controlBypass"], r["canaryHits"]) for r in tagged(rows, "E3")
                         if r["kind"] == "DELIVERY" and r["to"] == "w4"]
            self.assertEqual(resolved, [(1, "CREDENTIAL_RULE")], seed)
            self.assertEqual(delivered, [(5, "MESSAGE_SHAPE", ["w1"])], seed)


class C6ScheduleTests(unittest.TestCase):
    def test_classes_json_records_the_coded_e4_to_e7_schedule(self):
        """Packet review P1-3 (a): w4's E4 to E7 gateway calls are coded in C6's scenario; classes.json records the same
        schedule (agent, item, ticks). The calls' rows must agree with it in every seed."""
        events = {e["id"]: e for e in CLASSES["C6"]["events"]}
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C6"], seed)
            for event_id in ("E4", "E5", "E6", "E7"):
                event = events[event_id]
                calls = [r for r in tagged(rows, event_id) if r["kind"] == "TOOL_CALL"]
                self.assertEqual(sorted({r["agent"] for r in calls}), [event["agent"]], (seed, event_id))
                self.assertTrue(all(r["t"] in event["ticks"] for r in calls), (seed, event_id))
                self.assertEqual(calls[-1]["t"], event["ticks"][-1], (seed, event_id))
                self.assertTrue(all("item:integer" in r["inputKeys"] for r in calls), (seed, event_id))
            self.assertEqual([events[e]["item"] for e in ("E4", "E5", "E6", "E7")], [4, 4, 4, 4])


class C7Tests(unittest.TestCase):
    def test_every_event_path(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C7"], seed)
            e1 = [(r["t"], r["kind"], r["answer"], r["iteration"]) for r in tagged(rows, "E1")
                  if r["kind"] in ("PLAN", "KERNEL")]
            self.assertEqual(e1, [(t, "PLAN", None, t - 2) for t in range(3, 9)] + [(9, "KERNEL", "BUDGET_EXHAUSTED",
                                                                                    None)], seed)
            e2 = [(r["t"], r["kind"], r["answer"], r["attempt"]) for r in tagged(rows, "E2")
                  if r["kind"] in ("TOOL_CALL", "OBSERVE", "KERNEL")]
            self.assertEqual(e2, [(1, "TOOL_CALL", "LAUNCHED", 1), (2, "OBSERVE", "ERROR", None),
                                  (2, "TOOL_CALL", "LAUNCHED", 2), (3, "OBSERVE", "ERROR", None),
                                  (3, "KERNEL", "RETRY_BOUND", None), (3, "KERNEL", "HANDOFF", None)], seed)
            e3 = [(r["t"], r["kind"], r["answer"]) for r in tagged(rows, "E3") if r["kind"] in ("TOOL_CALL", "KERNEL")]
            self.assertEqual(e3, [(1, "TOOL_CALL", "LAUNCHED"), (4, "KERNEL", "TIMEOUT"), (4, "TOOL_CALL", "LAUNCHED"),
                                  (7, "KERNEL", "TIMEOUT"), (7, "KERNEL", "RETRY_BOUND"),
                                  (7, "KERNEL", "HANDOFF")], seed)
            e4 = [(r["t"], r["op"], r["item"], r["answer"]) for r in tagged(rows, "E4") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual(e4, [(1, "ACQUIRE", 4, "ACCEPTED")] + [(1, "ACQUIRE", i, "CONCURRENCY_LIMIT")
                                                                   for i in range(5, 21)]
                             + [(2, "RELEASE", 4, "ACCEPTED")], seed)

    def test_each_controls_bypass_row(self):
        cases = {"C7-BUDGET-OFF": ("E1", "PLAN", 9), "C7-RETRY-BOUND-OFF": ("E2", "TOOL_CALL", 3),
                 "C7-TIMEOUT-OFF": ("E3", "KERNEL", 4)}
        for control_id, (event, kind, tick) in sorted(cases.items()):
            c = control("C7", control_id)
            for seed in SEEDS:
                rows, _m = _ledger.run(CONFIG, CLASSES["C7"], seed, tuple(c["bypass"]))
                first = [r for r in tagged(rows, event) if r["kind"] == kind and r["controlBypass"]][0]
                self.assertEqual((first["t"], first["controlBypass"]), (tick, c["bypass"][0]), (control_id, seed))
        c = control("C7", "C7-CONCURRENCY-OFF")
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C7"], seed, tuple(c["bypass"]))
            beyond = [r for r in tagged(rows, "E4") if r["kind"] == "BOARD_ANSWER" and r["op"] == "ACQUIRE"
                      and r["controlBypass"] == "CONCURRENCY"]
            self.assertEqual(len(beyond), 16, seed)


if __name__ == "__main__":
    unittest.main()
