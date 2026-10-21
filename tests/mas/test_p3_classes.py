"""CONF-MAS-003: C8 to C10, per seed: each scheduled event follows the path DESIGN revision 6 preregisters (section 5);
each control's and depth check's bypass sits on the row it changes; C8's and C9's measurements have their preregistered
shapes and expectations."""
from __future__ import annotations

import unittest

import _ledger

CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
SEEDS = CONFIG["seeds"]


def tagged(rows, event):
    return [r for r in rows if r["scheduledEvent"] == event]


def bypass_of(cls_id, check_id):
    cls = CLASSES[cls_id]
    return tuple(next(c for c in cls["controls"] + cls["depthChecks"] if c["id"] == check_id)["bypass"])


def board(rows, event, op=None, agent=None):
    return [r for r in tagged(rows, event) if r["kind"] == "BOARD_ANSWER" and (op is None or r["op"] == op)
            and (agent is None or r["agent"] == agent)]


def ledger_row(cls_id):
    return next(r for r in _ledger.ledger()["classes"] if r["id"] == cls_id)


class C8Tests(unittest.TestCase):
    @staticmethod
    def crashed(rows):
        fault = [r for r in rows if r["kind"] == "FAULT"]
        return fault[0]["agent"], fault[0]["item"], fault

    def test_every_event_path(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C8"], seed)
            w_a, item_a, fault = self.crashed(rows)
            self.assertEqual([(r["t"], r["answer"], r["scheduledEvent"]) for r in fault], [(1, "CRASH", "E1")], seed)
            self.assertEqual(item_a, CONFIG["topologies"]["CENTRAL"]["workers"].index(w_a) + 1, seed)
            launched = [r for r in rows if r["kind"] == "TOOL_CALL" and r["agent"] == w_a]
            self.assertEqual([(r["t"], r["answer"]) for r in launched], [(1, "LAUNCHED")], seed)
            expiry = [(r["t"], r["agent"], r["item"], r["leaseUntil"], r["answer"]) for r in tagged(rows, "E1")
                      if r["kind"] == "EXPIRY"]
            self.assertEqual(expiry, [(8, w_a, item_a, 8, None)], seed)
            dropped = [(r["t"], r["agent"], r["answer"], r["component"]) for r in tagged(rows, "E2")
                       if r["kind"] == "DELIVERY"]
            self.assertEqual(dropped, [(0, "c", "DROPPED", "CHANNEL")], seed)
            retry = [(r["t"], r["op"], r["answer"], r["changed"], r["retryOf"] is not None) for r in board(rows, "E2")]
            self.assertEqual(retry, [(2, "ASSIGN", "ACCEPTED", False, True)], seed)
            resumed = sorted((r["item"], r["answer"]) for r in board(rows, "E3", "ASSIGN"))
            want = sorted((i, "STALE_VERSION" if i == item_a else "MERGED") for i in range(1, 5))
            self.assertEqual(resumed, want, seed)
            self.assertTrue(all(r["t"] == 8 for r in board(rows, "E3")), seed)

    def test_controls_and_depth_checks(self):
        for seed in SEEDS:
            rows, m = _ledger.run(CONFIG, CLASSES["C8"], seed, bypass_of("C8", "C8-EXPIRY-OFF"))
            skipped = [(r["t"], r["answer"], r["controlBypass"]) for r in tagged(rows, "E1") if r["kind"] == "EXPIRY"]
            self.assertEqual(skipped, [(8, "SKIPPED", "EXPIRY")], seed)
            self.assertGreaterEqual(m["counts"]["crashedHoldsAtDeadline"], 1, seed)
            cases = {"C8-RETRY-OFF": ("ACCEPTED", True, "RETRY+HELD+VERSION+CONCURRENCY"),
                     "C8-RETRY-DEPTH": ("HELD", False, "RETRY"),
                     "C8-RETRY-HELD-DEPTH": ("STALE_VERSION", False, "RETRY+HELD")}
            for check_id, want in sorted(cases.items()):
                rows, _m = _ledger.run(CONFIG, CLASSES["C8"], seed, bypass_of("C8", check_id))
                retry = [(r["answer"], r["changed"], r["controlBypass"]) for r in board(rows, "E2") if r["retryOf"]]
                self.assertEqual(retry, [want], (seed, check_id))
            rows, _m = _ledger.run(CONFIG, CLASSES["C8"], seed, bypass_of("C8", "C8-VERSION-OFF"))
            _w_a, item_a, _fault = self.crashed(rows)
            stale = [(r["answer"], r["controlBypass"]) for r in board(rows, "E3", "ASSIGN") if r["item"] == item_a]
            self.assertEqual(stale, [("ACCEPTED", "VERSION")], seed)

    def test_readings(self):
        row = ledger_row("C8")
        m = row["measurements"]
        self.assertEqual((m["kind"], m["seeds"]), ("DEFENDED_READINGS", 32))
        self.assertEqual(sorted(m["quantiles"]), sorted(CLASSES["C8"]["measurements"]["readings"]))
        self.assertEqual(m["quantiles"]["recoveryTicks"]["min"], 8)


class C9Tests(unittest.TestCase):
    def test_every_event_path(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C9"], seed)
            aborts = sorted((r["t"], r["agent"]) for r in tagged(rows, "E1")
                            if r["kind"] == "KERNEL" and r["answer"] == "BUDGET_EXHAUSTED")
            self.assertEqual(aborts, [(101, "w1"), (101, "w2")], seed)
            first = next(r["claimOpId"] for r in rows if r["kind"] == "WORK" and r["agent"] == "w3"
                         and r["scheduledEvent"] == "E2")
            works = [r for r in rows if r["kind"] == "WORK" and r["claimOpId"] == first]
            self.assertEqual([r["markerPresent"] for r in works], [True] * 4, seed)
            bound = [(r["agent"], r["claimOpId"]) for r in tagged(rows, "E2")
                     if r["kind"] == "KERNEL" and r["answer"] == "REVISION_BOUND"]
            self.assertEqual(bound, [("w3", first)], seed)
            released = [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["op"] == "RELEASE"
                        and r["claimOpId"] == first and r["answer"] == "ACCEPTED"]
            self.assertEqual(len(released), 1, seed)

    def test_controls(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C9"], seed, bypass_of("C9", "C9-WALL-OFF"))
            overrun = sorted((r["t"], r["agent"], r["controlBypass"]) for r in tagged(rows, "E1")
                             if r["kind"] == "KERNEL" and r["answer"] == "WALL_OVERRUN")
            self.assertEqual(overrun, [(101, "w1", "WALL_CLOCK"), (101, "w2", "WALL_CLOCK")], seed)
            rows, _m = _ledger.run(CONFIG, CLASSES["C9"], seed, bypass_of("C9", "C9-REVISION-OFF"))
            kernel = [(r["answer"], r["controlBypass"]) for r in tagged(rows, "E2") if r["kind"] == "KERNEL"]
            self.assertEqual(kernel, [("REVISION_OVERRUN", "REVISION_BOUND"), ("BUDGET_EXHAUSTED", None)], seed)
            first = next(r["claimOpId"] for r in rows if r["kind"] == "WORK" and r["scheduledEvent"] == "E2")
            self.assertEqual(sum(1 for r in rows if r["kind"] == "WORK" and r["claimOpId"] == first), 6, seed)
            rows, _m = _ledger.run(CONFIG, CLASSES["C9"], seed, bypass_of("C9", "C9-REVISION+BUDGET-OFF"))
            first = next(r["claimOpId"] for r in rows if r["kind"] == "WORK" and r["scheduledEvent"] == "E2")
            works = [r for r in rows if r["kind"] == "WORK" and r["claimOpId"] == first]
            self.assertGreaterEqual(len(works), 7, seed)
            self.assertEqual(works[6]["controlBypass"], "BUDGET", seed)

    def test_relay_measurement(self):
        m = ledger_row("C9")["measurements"]
        self.assertEqual((m["kind"], m["seeds"], m["event"]), ("RELAY_RUNS", 32, "E3"))
        relay, defended = m["relay"]["quantiles"], m["defended"]["quantiles"]
        self.assertEqual(sorted(relay), sorted(CLASSES["C9"]["measurements"]["readings"]))
        for name in ("relayDeliveries", "deliveriesPer100Ticks", "relayLastTick"):
            self.assertNotIn(name, defended)
        # Expected, stated before any run (section 5): one delivery per tick to the deadline; work readings unchanged.
        self.assertEqual(relay["relayLastTick"], {"p50": 600, "p95": 600, "max": 600, "min": 600})
        self.assertEqual(relay["deliveriesPer100Ticks"]["min"], 100)
        for name in ("mergesPer100Ticks", "maxClaimTicks", "lastMergeTick", "completionPpm", "lostWorkPpm"):
            self.assertEqual(relay[name], defended[name], name)


class C10Tests(unittest.TestCase):
    def test_every_event_path(self):
        for seed in SEEDS:
            rows, _m = _ledger.run(CONFIG, CLASSES["C10"], seed)
            verdicts = [(r["t"], r["verdictStatus"]) for r in tagged(rows, "E1") if r["kind"] == "VERDICT"]
            self.assertEqual(verdicts[:2], [(5, "PASS"), (6, "FAIL")], seed)
            e1 = [(r["t"], r["answer"]) for r in board(rows, "E1", "MERGE", "w1")]
            self.assertEqual(e1[0], (7, "VERDICT_NOT_PASS"), seed)
            gate = [r for r in tagged(rows, "E2") if r["kind"] == "GATE" and r["component"] == "GATE"
                    and r["answer"] == "FAIL"]
            self.assertGreaterEqual(len(gate), 2, seed)
            self.assertEqual(gate[0]["workDigest"], gate[1]["workDigest"], seed)
            self.assertEqual(gate[0]["t"], 7, seed)
            e3 = [(r["t"], r["answer"]) for r in board(rows, "E3", "MERGE", "w3")]
            self.assertEqual(e3, [(7, "ACCEPTED"), (7, "NOT_HOLDER")], seed)
            expiry = [(r["leaseUntil"], r["agent"]) for r in tagged(rows, "E4") if r["kind"] == "EXPIRY"]
            self.assertEqual(expiry, [(12, "w4")], seed)
            reclaim = [r["t"] for r in rows if r["kind"] == "BOARD_ANSWER" and r["op"] == "ACQUIRE" and r["item"] == 4
                       and r["agent"] != "w4" and r["answer"] == "ACCEPTED" and r["changed"]]
            e4 = [(r["t"], r["answer"]) for r in board(rows, "E4", "MERGE", "w4")]
            self.assertEqual(e4, [(reclaim[0] + 1, "NOT_HOLDER")], seed)

    def test_controls_and_depth_checks(self):
        merges = {
            "C10-SUPERSEDE-OFF": ("E1", "w1", 0, ("ACCEPTED", "SUPERSESSION")),
            "C10-RACE-OFF": ("E3", "w3", 1, ("ACCEPTED", "SINGLE_MERGE+VERSION")),
            "C10-RACE-DEPTH": ("E3", "w3", 1, ("STALE_VERSION", "SINGLE_MERGE")),
            "C10-HOLDER-OFF": ("E4", "w4", 0, ("ACCEPTED", "HOLDER+VERSION+MERGE_VERDICT")),
            "C10-HOLDER-DEPTH": ("E4", "w4", 0, ("STALE_VERSION", "HOLDER")),
            "C10-HOLDER-VERSION-DEPTH": ("E4", "w4", 0, ("NO_VERDICT", "HOLDER+VERSION")),
        }
        for seed in SEEDS:
            for check_id, (event, agent, index, want) in sorted(merges.items()):
                rows, _m = _ledger.run(CONFIG, CLASSES["C10"], seed, bypass_of("C10", check_id))
                got = [(r["answer"], r["controlBypass"]) for r in board(rows, event, "MERGE", agent)]
                self.assertEqual(got[index], want, (seed, check_id))
            rows, _m = _ledger.run(CONFIG, CLASSES["C10"], seed, bypass_of("C10", "C10-WORK-OFF"))
            accepted = [r for r in board(rows, "E2", "MERGE", "w2") if r["answer"] == "ACCEPTED"]
            self.assertEqual([(r["markerPresent"], r["controlBypass"]) for r in accepted][:1], [(True, "WORK_VERDICT")],
                             seed)
            rows, _m = _ledger.run(CONFIG, CLASSES["C10"], seed, bypass_of("C10", "C10-WORK-DEPTH"))
            refused = [r["answer"] for r in board(rows, "E2", "MERGE", "w2")]
            self.assertEqual(refused[:2], ["VERDICT_NOT_PASS", "VERDICT_NOT_PASS"], seed)

    def test_rows_list_no_unexercised_invariant_and_scope_depth_by_event(self):
        row = ledger_row("C10")
        self.assertEqual(row["unexercisedInvariants"], [])
        self.assertEqual([d["event"] for d in row["depthChecks"]], ["E2", "E3", "E4", "E4"])
        for cid in ("C8", "C9"):
            self.assertEqual(ledger_row(cid)["unexercisedInvariants"], ["doubleMerge", "nonHolderAccepted"])


if __name__ == "__main__":
    unittest.main()
