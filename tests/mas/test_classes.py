"""CONF-MAS-001: per class and seed, every scheduled event follows its traced path; the defended runs hold every counter at
0; every control fires through its event in all 32 seeds (Q-MAS1-REV2); every defence-in-depth check holds."""
from __future__ import annotations

import unittest

import _ledger

CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
SEEDS = CONFIG["seeds"]


def tagged(rows, event):
    return [r for r in rows if r["scheduledEvent"] == event]


class TraceTests(unittest.TestCase):
    """The attack lane fixes each event's path; these are the traces README.md states."""

    def test_c1_peer_injection_paths(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C1"], seed)
            e1 = [r for r in tagged(rows, "E1") if r["kind"] == "BOARD_ANSWER" and r["op"] == "MERGE"]
            self.assertEqual([(r["t"], r["agent"], r["answer"]) for r in e1], [(3, "w1", "NO_VERDICT")], seed)
            e2 = [r for r in tagged(rows, "E2") if r["kind"] == "TOOL_CALL"]
            self.assertEqual([(r["t"], r["agent"], r["toolId"], r["answer"]) for r in e2],
                             [(4, "w2", "ADMIN", "NOT_LISTED")], seed)
            e3 = [r for r in tagged(rows, "E3") if r["kind"] == "TOOL_CALL"]
            self.assertEqual([(r["t"], r["agent"], r["toolId"], r["answer"]) for r in e3],
                             [(5, "w3", "SEND_REPORT", "CREDENTIAL_VALUE")], seed)
            e4 = [r for r in tagged(rows, "E4") if r["kind"] == "BOARD_ANSWER" and r["agent"] == "w1"]
            self.assertEqual([(r["t"], r["op"], r["to"], r["answer"]) for r in e4], [(6, "MESSAGE", "w2", "OFF_EDGE")],
                             seed)

    def test_c2_poisoned_read_is_stopped_by_the_gate(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C2"], seed)
            gate = [r for r in tagged(rows, "E1") if r["kind"] == "GATE" and r["component"] == "GATE"]
            judge = [r for r in tagged(rows, "E1") if r["kind"] == "GATE" and r["component"] == "JUDGE"]
            self.assertEqual([r["answer"] for r in gate], ["FAIL"], seed)
            self.assertEqual([r["answer"] for r in judge], ["FAIL"], seed)
            self.assertFalse([r for r in tagged(rows, "E1") if r["kind"] == "BOARD_ANSWER" and r["op"] == "MERGE"
                              and r["answer"] == "ACCEPTED"], seed)

    def test_c3_replay_redelivery_and_retry_paths(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C3"], seed)
            e1 = [r for r in tagged(rows, "E1") if r["kind"] == "EXPIRY"]
            self.assertEqual([r["leaseUntil"] for r in e1], [8], seed)
            e2 = [r for r in tagged(rows, "E2") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual([(r["t"], r["op"], r["answer"], r["expectedVersion"], r["recordVersionBefore"]) for r in e2],
                             [(5, "RENEW", "STALE_VERSION", 1, 2)], seed)
            e3 = [r for r in tagged(rows, "E3") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual([(r["t"], r["op"], r["answer"]) for r in e3], [(5, "RENEW", "DUPLICATE_ID")], seed)
            dropped = [r for r in tagged(rows, "E4") if r["kind"] == "DELIVERY"]
            retry = [r for r in tagged(rows, "E4") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual([(r["t"], r["answer"]) for r in dropped], [(4, "DROPPED")], seed)
            self.assertEqual([(r["t"], r["answer"], r["changed"], bool(r["retryOf"])) for r in retry],
                             [(6, "ACCEPTED", False, True)], seed)

    def test_c4_race_contender_and_self_verify_paths(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C4"], seed)
            e1 = [r for r in tagged(rows, "E1") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual([(r["t"], r["agent"], r["answer"]) for r in e1],
                             [(0, "w1", "ACCEPTED"), (0, "w2", "HELD"), (0, "w3", "HELD"), (0, "w4", "HELD")], seed)
            e2 = [r for r in tagged(rows, "E2") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual([(r["t"], r["agent"], r["answer"], r["expectedVersion"]) for r in e2],
                             [(1, "w2", "HELD", 1), (1, "w3", "HELD", 1), (1, "w4", "HELD", 1)], seed)
            e3 = [r for r in tagged(rows, "E3") if r["kind"] == "BOARD_ANSWER"]
            self.assertEqual([(r["t"], r["agent"], r["op"], r["answer"]) for r in e3],
                             [(1, "w1", "VERIFY", "SELF_VERIFICATION")], seed)


class LedgerGateTests(unittest.TestCase):
    """The cached ledger's per-class gates: defended zeros and events, controls (32 of 32) and depth checks."""

    @classmethod
    def setUpClass(cls):
        cls.ledger = _ledger.ledger()
        cls.rows = {row["id"]: row for row in cls.ledger["classes"]}

    def test_every_event_is_delivered_reached_and_engaged_in_every_seed(self):
        for cid, row in sorted(self.rows.items()):
            for event_id, seen in sorted(row["defended"]["eventsReached"].items()):
                self.assertEqual(seen, {"delivered": 32, "reached": 32, "engaged": 32}, (cid, event_id))

    def test_defended_counters_are_zero(self):
        for cid, row in sorted(self.rows.items()):
            self.assertEqual(row["defended"]["failing"], [], cid)
            self.assertTrue(all(n == 0 for n in row["defended"]["seedsAboveZero"].values()), cid)

    def test_every_control_fires_in_all_32_seeds(self):
        for cid, row in sorted(self.rows.items()):
            for control in row["controls"]:
                self.assertEqual((control["firedSeeds"], control["failing"]), (32, []), (cid, control["id"]))

    def test_every_depth_check_holds_in_all_32_seeds(self):
        for cid, row in sorted(self.rows.items()):
            for check in row["depthChecks"]:
                self.assertEqual((check["heldSeeds"], check["failing"]), (32, []), (cid, check["id"]))

    def test_the_counts_of_controls_and_checks(self):
        # CONF-MAS-002 (DESIGN revision 8, section 4): packet 1's counts over C1 to C4 are unchanged; C5 to C7 add 14
        # controls and no depth check.
        packet1 = [r for cid, r in sorted(self.rows.items()) if cid in ("C1", "C2", "C3", "C4")]
        packet2 = [r for cid, r in sorted(self.rows.items()) if cid in ("C5", "C6", "C7")]
        self.assertEqual(sum(len(r["controls"]) for r in packet1), 10)
        self.assertEqual(sum(len(r["depthChecks"]) for r in packet1), 4)
        self.assertEqual(sum(len(r["controls"]) for r in packet2), 14)
        self.assertEqual(sum(len(r["depthChecks"]) for r in packet2), 0)

    def test_c3_e1_leaves_an_explained_duplicate_in_every_seed(self):
        """Q-MAS1-F3 (a), 2026-10-19: rev 4's "exactly one duplicate per seed (E1)" no longer holds after the F2
        conformance fix (seed 8 has 5: a holder's own RENEW overtakes its MERGE until its revisions run out, and the
        item is RELEASEd). E1's explained duplicate is still present in every seed."""
        q = self.rows["C3"]["defended"]["quantiles"]["duplicateWork"]
        self.assertGreaterEqual(q["min"], 1)
        for seed in SEEDS:
            rows, m = _ledger.run(CONFIG, CLASSES["C3"], seed)
            expired = [r for r in tagged(rows, "E1") if r["kind"] == "EXPIRY"]
            self.assertEqual(len(expired), 1, seed)
            claim, item = expired[0]["claimOpId"], expired[0]["item"]
            work = [r for r in rows if r["kind"] == "WORK" and r["claimOpId"] == claim]
            merged = [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["op"] == "MERGE" and r["item"] == item
                      and r["answer"] == "ACCEPTED"]
            self.assertEqual(len(work), 1, seed)
            self.assertEqual(len(merged), 1, seed)
            self.assertNotEqual(merged[0]["claimOpId"], claim, seed)
            self.assertEqual(m["counts"]["unexplainedDuplicate"], 0, seed)


if __name__ == "__main__":
    unittest.main()
