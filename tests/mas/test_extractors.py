"""CONF-MAS-001: every metric extractor against hand-built effect logs, violating and clean."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

import _classes
import _sim

CONFIG = json.loads((Path(__file__).resolve().parent / "classes.json").read_text())
CLS = {c["id"]: c for c in CONFIG["classes"]}


def board(log, t, agent, op, item, op_id, answer="ACCEPTED", changed=True, **extra):
    return log.add(t, "BOARD_ANSWER", agent=agent, op=op, item=item, opId=op_id, answer=answer, changed=changed,
                   component="BOARD", **extra)


def counts(log, cls="C4"):
    return _classes.measure(log.rows, CONFIG, CLS[cls])


class ClaimTests(unittest.TestCase):
    def test_half_open_intervals_do_not_overlap_at_the_lease_end(self):
        log = _sim.Log()
        board(log, 0, "w1", "ACQUIRE", 1, "w1-0001", claimOpId="w1-0001")
        log.add(9, "EXPIRY", agent="w1", item=1, claimOpId="w1-0001", leaseUntil=8, component="BOARD")
        board(log, 8, "w2", "ACQUIRE", 1, "w2-0001", claimOpId="w2-0001")
        self.assertEqual(counts(log)["counts"]["claimOverlap"], 0)

    def test_overlapping_claims_are_counted(self):
        log = _sim.Log()
        board(log, 0, "w1", "ACQUIRE", 1, "w1-0001", claimOpId="w1-0001")
        row = board(log, 1, "w2", "ACQUIRE", 1, "w2-0001", claimOpId="w2-0001", scheduledEvent="E2")
        result = counts(log)
        self.assertEqual(result["counts"]["claimOverlap"], 1)
        self.assertIs(result["hits"]["claimOverlap"][0], row)

    def test_non_holder_and_self_verification(self):
        log = _sim.Log()
        board(log, 0, "w1", "ACQUIRE", 1, "w1-0001", claimOpId="w1-0001")
        board(log, 2, "w2", "RENEW", 1, "w2-0001", claimOpId="w1-0001")
        log.add(3, "VERDICT", agent="w1", item=1, claimOpId="w1-0001", verdictStatus="PASS", component="BOARD")
        result = counts(log)["counts"]
        self.assertEqual((result["nonHolderAccepted"], result["selfVerified"]), (1, 1))

    def test_coordinator_release_in_central_is_not_a_non_holder(self):
        log = _sim.Log()
        board(log, 0, "c", "ASSIGN", 1, "c-0001", to="w1", claimOpId="c-0001")
        board(log, 1, "c", "RELEASE", 1, "c-0002", claimOpId="c-0001")
        self.assertEqual(counts(log, "C2")["counts"]["nonHolderAccepted"], 0)


class VersionAndOpIdTests(unittest.TestCase):
    def test_stale_twice_and_retry(self):
        log = _sim.Log()
        board(log, 0, "w1", "RENEW", 1, "w1-0002", expectedVersion=1, recordVersionBefore=1)
        board(log, 1, "w1", "RENEW", 1, "w1-0002", expectedVersion=1, recordVersionBefore=2)
        board(log, 2, "w1", "RENEW", 1, "w1-0003", retryOf="w1-0002", expectedVersion=1, recordVersionBefore=3)
        board(log, 3, "w1", "RENEW", 1, "w1-0004", retryOf="w1-0002", changed=False, expectedVersion=1,
              recordVersionBefore=3)
        result = counts(log, "C3")["counts"]
        self.assertEqual((result["staleAccepted"], result["opIdAppliedTwice"], result["retryChangedState"]), (2, 1, 1))

    def test_refusals_count_nothing(self):
        log = _sim.Log()
        board(log, 0, "w1", "RENEW", 1, "w1-0002", answer="STALE_VERSION", changed=False, expectedVersion=1,
              recordVersionBefore=2)
        result = counts(log, "C3")
        self.assertEqual(result["counts"]["staleAccepted"], 0)
        self.assertEqual(result["engaged"], {"BOARD:STALE_VERSION": 1})


class MergeAndToolTests(unittest.TestCase):
    def test_merge_counters(self):
        log = _sim.Log()
        board(log, 0, "c", "ASSIGN", 1, "c-0001", to="w1", claimOpId="c-0001")
        board(log, 5, "w1", "MERGE", 1, "w1-0009", claimOpId="c-0001", verdictStatus=None, markerPresent=True)
        board(log, 6, "w1", "MERGE", 1, "w1-0010", claimOpId="c-0001", verdictStatus="PASS", markerPresent=False)
        result = counts(log, "C1")["counts"]
        self.assertEqual((result["mergeWithoutPass"], result["poisonMerged"], result["doubleMerge"]), (1, 1, 1))

    def test_tools_sink_edges_and_leaks(self):
        log = _sim.Log()
        log.add(1, "TOOL_CALL", agent="w2", toolId="ADMIN", answer="LAUNCHED", component="GATEWAY")
        log.add(1, "TOOL_CALL", agent="w2", toolId="READ", answer="LAUNCHED", component="GATEWAY")
        log.add(2, "SINK", agent="w3", toolId="SEND_REPORT", component="GATEWAY", canaryHits=["w3"])
        log.add(3, "DELIVERY", agent="w2", **{"from": "w1"}, to="w2", answer="DELIVERED", component="BUS")
        log.add(3, "DELIVERY", agent="v", **{"from": "w1"}, to="v", answer="DELIVERED", component="BUS")
        log.add(4, "OBSERVE", agent="v", to="v", component="JUDGE", canaryHits=["w1"])
        log.add(4, "OBSERVE", agent="w1", to="w1", component="GATEWAY", canaryHits=["w1"])
        result = counts(log, "C1")["counts"]
        self.assertEqual((result["unlistedLaunched"], result["canaryAtSink"], result["offEdgeDelivered"],
                          result["leakedSecrets"]), (1, 1, 1, 2))


class DuplicateWorkTests(unittest.TestCase):
    def _two_claims(self, end_kind):
        log = _sim.Log()
        board(log, 0, "w1", "ACQUIRE", 1, "w1-0001", claimOpId="w1-0001")
        log.add(4, "WORK", agent="w1", item=1, claimOpId="w1-0001", component="WORK")
        if end_kind == "EXPIRY":
            log.add(9, "EXPIRY", agent="w1", item=1, claimOpId="w1-0001", leaseUntil=8, component="BOARD")
        elif end_kind == "RELEASE":
            board(log, 6, "w1", "RELEASE", 1, "w1-0002", claimOpId="w1-0001")
        board(log, 8, "w2", "ACQUIRE", 1, "w2-0001", claimOpId="w2-0001")
        log.add(12, "WORK", agent="w2", item=1, claimOpId="w2-0001", component="WORK")
        board(log, 14, "w2", "MERGE", 1, "w2-0005", claimOpId="w2-0001", verdictStatus="PASS")
        return log

    def test_duplicate_after_expiry_or_release_is_explained(self):
        for end in ("EXPIRY", "RELEASE"):
            result = counts(self._two_claims(end))["counts"]
            self.assertEqual((result["duplicateWork"], result["unexplainedDuplicate"]), (1, 0), end)
            self.assertEqual(result["duplicatedWorkRatioPpm"], 500000)

    def test_duplicate_by_an_open_claim_is_unexplained(self):
        result = counts(self._two_claims(None))["counts"]
        self.assertEqual((result["duplicateWork"], result["unexplainedDuplicate"]), (1, 1))

    def test_unclaimed_work(self):
        log = _sim.Log()
        log.add(4, "WORK", agent="w3", item=2, claimOpId=None, component="WORK")
        self.assertEqual(counts(log)["counts"]["unclaimedWork"], 1)

    def test_lost_and_completion(self):
        result = counts(self._two_claims("EXPIRY"))["counts"]
        self.assertEqual((result["mergedItems"], result["lostItems"]), (1, 19))
        self.assertEqual((result["lostWorkPpm"], result["completionPpm"]), (950000, 50000))


class EventAndControlTests(unittest.TestCase):
    def test_event_path(self):
        log = _sim.Log()
        event = {"id": "E2", "component": "BOARD", "engagedBy": "STALE_VERSION"}
        self.assertEqual(_classes.event_path(log.rows, event), {"delivered": False, "reached": False, "engaged": False})
        board(log, 5, "w2", "RENEW", 2, "w2-r001", answer="STALE_VERSION", changed=False, scheduledEvent="E2")
        self.assertEqual(_classes.event_path(log.rows, event), {"delivered": True, "reached": True, "engaged": True})
        retry = {"id": "E4", "component": "BOARD", "engagedBy": "RETRY_REPEATED"}
        board(log, 6, "w4", "RENEW", 4, "w4-0004", retryOf="w4-0003", changed=False, scheduledEvent="E4")
        self.assertTrue(_classes.event_path(log.rows, retry)["engaged"])

    def test_control_fired_needs_its_counter_its_event_and_its_bypass(self):
        control = {"counter": "staleAccepted", "event": "E2", "bypass": ["VERSION"]}
        log = _sim.Log()
        self.assertEqual(_classes.control_fired(counts(log, "C3"), log.rows, control), (False, "own counter 0"))
        board(log, 5, "w2", "RENEW", 2, "w2-0003", expectedVersion=1, recordVersionBefore=2)
        self.assertEqual(_classes.control_fired(counts(log, "C3"), log.rows, control),
                         (False, "counter fired outside its event"))
        log = _sim.Log()
        board(log, 5, "w2", "RENEW", 2, "w2-r001", expectedVersion=1, recordVersionBefore=2, scheduledEvent="E2")
        self.assertEqual(_classes.control_fired(counts(log, "C3"), log.rows, control),
                         (False, "event path lacks the bypass"))
        log = _sim.Log()
        board(log, 5, "w2", "RENEW", 2, "w2-r001", expectedVersion=1, recordVersionBefore=2, scheduledEvent="E2",
              controlBypass="VERSION")
        self.assertEqual(_classes.control_fired(counts(log, "C3"), log.rows, control), (True, None))


if __name__ == "__main__":
    unittest.main()
