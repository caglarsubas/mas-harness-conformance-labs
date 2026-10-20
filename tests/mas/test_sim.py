"""CONF-MAS-001: the restated rules (board, gateway, PRNG, renewal guarantee) against hand-built cases."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

import _classes
import _sim

CONFIG = json.loads((Path(__file__).resolve().parent / "classes.json").read_text())


def make_sim(topology: str = "DECENTRALIZED", bypass: tuple[str, ...] = (), max_latency: int = 0, deadline: int = 100):
    cls = {"id": "T", "kind": "TEST", "topology": topology, "deadline": deadline, "maxLatency": max_latency,
           "poisonPpm": 0, "stallPpm": 0, "compromised": None, "events": [], "controls": [], "depthChecks": []}
    return _sim.Sim(CONFIG, cls, 1, bypass, _classes.Scenario(cls))


class Ops:
    """Hand-built operations with unique opIds."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self, agent: str, op: str, item=None, **fields) -> dict:
        self.n += 1
        return {"opId": "%s-t%04d" % (agent, self.n), "agent": agent, "op": op, "item": item, **fields}


def answer(sim, t: int, op: dict) -> str:
    return sim.board.apply(t, op)["result"]["answer"]


class StreamTests(unittest.TestCase):
    def test_draws_are_deterministic_per_seed_and_stream(self):
        a, b = _sim.Streams(7), _sim.Streams(7)
        self.assertEqual([a.draw("lat-w1") for _ in range(5)], [b.draw("lat-w1") for _ in range(5)])
        c = _sim.Streams(7)
        c.draw("stall-w2")
        self.assertEqual(c.draw("lat-w1"), _sim.Streams(7).draw("lat-w1"))
        self.assertNotEqual(_sim.Streams(7).draw("lat-w1"), _sim.Streams(8).draw("lat-w1"))

    def test_stream_names_exclude_colons(self):
        with self.assertRaises(ValueError):
            _sim.Streams(1).draw("lat:w1")

    def test_permutation_is_fisher_yates(self):
        s = _sim.Streams(3)
        out = s.permutation("sched-c3", ["w1", "w2", "w3", "w4"])
        self.assertEqual(sorted(out), ["w1", "w2", "w3", "w4"])
        ref = _sim.Streams(3)
        items = ["w1", "w2", "w3", "w4"]
        for i in (3, 2, 1):
            j = ref.draw("sched-c3") % (i + 1)
            items[i], items[j] = items[j], items[i]
        self.assertEqual(out, items)

    def test_chance_and_range_mappings(self):
        s = _sim.Streams(5)
        d = _sim.Streams(5).draw("x")
        self.assertEqual(s.below("x", 4), d % 4)
        t = _sim.Streams(5)
        self.assertEqual(t.chance("x", 250000), d % 1000000 < 250000)


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.ops = Ops()

    def test_acquire_rules_and_precedence(self):
        sim = make_sim()
        op = self.ops
        self.assertEqual(answer(sim, 0, op("w1", "ACQUIRE", 1, expectedVersion=0)), "ACCEPTED")
        rec = sim.board.records[1]
        self.assertEqual((rec["state"], rec["version"], rec["claims"][0]["leaseUntil"]), ("HELD", 1, 8))
        # MERGED or HELD comes before STALE_VERSION.
        self.assertEqual(answer(sim, 1, op("w2", "ACQUIRE", 1, expectedVersion=0)), "HELD")
        self.assertEqual(answer(sim, 1, op("w2", "ACQUIRE", 2, expectedVersion=5)), "STALE_VERSION")
        self.assertEqual(answer(sim, 1, op("c", "ACQUIRE", 2, expectedVersion=0)), "NOT_PERMITTED")
        for item, worker in ((2, "w2"), (3, "w3"), (4, "w4")):
            self.assertEqual(answer(sim, 1, op(worker, "ACQUIRE", item, expectedVersion=0)), "ACCEPTED")
        self.assertEqual(answer(sim, 1, op("w1", "ACQUIRE", 5, expectedVersion=0)), "CONCURRENCY_LIMIT")

    def test_acquire_is_decentralized_only_and_assign_central_only(self):
        central = make_sim("CENTRAL")
        op = self.ops
        self.assertEqual(answer(central, 0, op("w1", "ACQUIRE", 1, expectedVersion=0)), "NOT_PERMITTED")
        self.assertEqual(answer(central, 0, op("w1", "ASSIGN", 1, to="w2", expectedVersion=0)), "NOT_PERMITTED")
        self.assertEqual(answer(central, 0, op("c", "ASSIGN", 1, to="v", expectedVersion=0)), "NOT_PERMITTED")
        self.assertEqual(answer(central, 0, op("c", "ASSIGN", 1, to="w2", expectedVersion=0)), "ACCEPTED")
        self.assertEqual(central.board.records[1]["claims"][0]["holder"], "w2")
        notices = [x for x in central.inflight_in if x[3]["type"] == "NOTICE"]
        self.assertEqual(len(notices), 1)
        self.assertEqual(answer(make_sim(), 0, op("c", "ASSIGN", 1, to="w2", expectedVersion=0)), "NOT_PERMITTED")

    def test_expiry_reopens_bumps_version_and_clears_verdicts(self):
        sim = make_sim()
        op = self.ops
        acq = op("w1", "ACQUIRE", 1, expectedVersion=0)
        answer(sim, 0, acq)
        verdict = {"verdictId": "v-1", "verifier": "v", "holder": "w1", "claimOpId": acq["opId"], "workDigest": "d",
                   "status": "PASS", "supersedes": None, "evidence": 1}
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=verdict)), "ACCEPTED")
        snap = sim.board.read(8)
        self.assertEqual(snap[1], ("OPEN", 2, ()))
        expiry = [r for r in sim.log.rows if r["kind"] == "EXPIRY"]
        self.assertEqual((len(expiry), expiry[0]["leaseUntil"], expiry[0]["claimOpId"]), (1, 8, acq["opId"]))
        self.assertEqual(sim.board.records[1]["claims"], [])

    def test_renew_release_rules(self):
        sim = make_sim()
        op = self.ops
        acq = op("w1", "ACQUIRE", 1, expectedVersion=0)
        answer(sim, 0, acq)
        self.assertEqual(answer(sim, 2, op("w2", "RENEW", 1, expectedVersion=1)), "NOT_HOLDER")
        self.assertEqual(answer(sim, 2, op("w1", "RENEW", 1, expectedVersion=0)), "STALE_VERSION")
        self.assertEqual(answer(sim, 3, op("w1", "RENEW", 1, expectedVersion=1)), "ACCEPTED")
        self.assertEqual(sim.board.records[1]["claims"][0]["leaseUntil"], 3 + 8)
        self.assertEqual(answer(sim, 4, op("w2", "RELEASE", 1, expectedVersion=2)), "NOT_HOLDER")
        self.assertEqual(answer(sim, 4, op("w1", "RELEASE", 1, expectedVersion=2)), "ACCEPTED")
        self.assertEqual(sim.board.records[1]["state"], "OPEN")

    def test_coordinator_may_release_in_central(self):
        sim = make_sim("CENTRAL")
        op = self.ops
        answer(sim, 0, op("c", "ASSIGN", 1, to="w1", expectedVersion=0))
        self.assertEqual(answer(sim, 1, op("c", "RELEASE", 1, expectedVersion=1)), "ACCEPTED")

    def _held_with_claim(self):
        sim = make_sim()
        acq = self.ops("w1", "ACQUIRE", 1, expectedVersion=0)
        answer(sim, 0, acq)
        return sim, acq["opId"]

    def _verdict(self, claim, **over):
        base = {"verdictId": "v-%s-1" % claim, "verifier": "v", "holder": "w1", "claimOpId": claim, "workDigest": "d1",
                "status": "PASS", "supersedes": None, "evidence": 1}
        base.update(over)
        return base

    def test_verify_codes_and_precedence(self):
        op = self.ops
        sim = make_sim()
        self.assertEqual(answer(sim, 0, op("v", "VERIFY", 1, verdict=self._verdict("x"))), "NOT_HELD")
        sim, claim = self._held_with_claim()
        # SELF_VERIFICATION is checked on the operation's agent, before LEDGER_MISMATCH.
        self.assertEqual(answer(sim, 1, op("w1", "VERIFY", 1, verdict=self._verdict(claim, verifier="v"))),
                         "SELF_VERIFICATION")
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=self._verdict(claim, verifier="w2"))),
                         "LEDGER_MISMATCH")
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=self._verdict("other"))), "LEDGER_MISMATCH")
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=self._verdict(claim, holder="w2"))),
                         "LEDGER_MISMATCH")

    def test_verdict_history(self):
        op = self.ops
        sim, claim = self._held_with_claim()
        fail = self._verdict(claim, verdictId="a", status="FAIL")
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=fail)), "ACCEPTED")
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=dict(fail))), "VERDICT_HISTORY")  # reused id
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=self._verdict(claim, verdictId="b"))),
                         "VERDICT_HISTORY")  # does not supersede the latest
        better_same = self._verdict(claim, verdictId="c", supersedes="a", status="PASS", evidence=1)
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=better_same)), "VERDICT_HISTORY")
        better_new = self._verdict(claim, verdictId="d", supersedes="a", status="PASS", evidence=2)
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=better_new)), "ACCEPTED")
        worse = self._verdict(claim, verdictId="e", supersedes="d", status="FAIL", evidence=2)
        self.assertEqual(answer(sim, 1, op("v", "VERIFY", 1, verdict=worse)), "ACCEPTED")  # worse is always allowed

    def test_merge_codes_and_precedence(self):
        op = self.ops
        sim, claim = self._held_with_claim()
        self.assertEqual(answer(sim, 1, op("w2", "MERGE", 1, expectedVersion=1, workDigest="d1")), "NOT_HOLDER")
        self.assertEqual(answer(sim, 1, op("w1", "MERGE", 1, expectedVersion=0, workDigest="d1")), "STALE_VERSION")
        self.assertEqual(answer(sim, 1, op("w1", "MERGE", 1, expectedVersion=1, workDigest="d1")), "NO_VERDICT")
        answer(sim, 1, op("v", "VERIFY", 1, verdict=self._verdict(claim, verdictId="a", status="FAIL")))
        self.assertEqual(answer(sim, 2, op("w1", "MERGE", 1, expectedVersion=1, workDigest="d2")), "WORK_MISMATCH")
        self.assertEqual(answer(sim, 2, op("w1", "MERGE", 1, expectedVersion=1, workDigest="d1")), "VERDICT_NOT_PASS")
        answer(sim, 2, op("v", "VERIFY", 1, verdict=self._verdict(claim, verdictId="b", supersedes=None,
                                                                   workDigest="d2")))
        self.assertEqual(answer(sim, 3, op("w1", "MERGE", 1, expectedVersion=1, workDigest="d2")), "ACCEPTED")
        self.assertEqual(sim.board.records[1]["state"], "MERGED")
        self.assertEqual(answer(sim, 4, op("w2", "ACQUIRE", 1, expectedVersion=2)), "MERGED")

    def test_message_edges(self):
        sim = make_sim()
        op = self.ops
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, to="w3", messageType="TEST",
                                           requiredAction="NONE")), "OFF_EDGE")
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, to="w2", messageType="TEST",
                                           requiredAction="NONE")), "ACCEPTED")
        self.assertEqual(sum(1 for r in sim.log.rows if r["kind"] == "DELIVERY" and r["component"] == "BUS"), 1)

    def test_deadline_duplicate_and_retry(self):
        sim = make_sim(deadline=10)
        op = self.ops
        acq = op("w1", "ACQUIRE", 1, expectedVersion=0)
        self.assertEqual(answer(sim, 0, acq), "ACCEPTED")
        self.assertEqual(answer(sim, 1, dict(acq)), "DUPLICATE_ID")  # before any operation check
        retry = dict(acq, opId="w1-retry", retryOf=acq["opId"])
        result = sim.board.apply(2, retry)
        self.assertEqual((result["result"]["answer"], result["row"]["changed"]), ("ACCEPTED", False))
        self.assertEqual(sim.board.records[1]["version"], 1)
        mismatch = dict(acq, opId="w1-bad", retryOf=acq["opId"], expectedVersion=9)
        self.assertEqual(answer(sim, 2, mismatch), "RETRY_MISMATCH")
        self.assertEqual(answer(sim, 11, op("w2", "ACQUIRE", 2, expectedVersion=0)), "DEADLINE")
        late_retry = dict(acq, opId="w1-late", retryOf=acq["opId"])
        self.assertEqual(answer(sim, 11, late_retry), "ACCEPTED")

    def test_each_bypass_flips_exactly_its_check(self):
        op = self.ops
        sim = make_sim(bypass=("HELD",))
        answer(sim, 0, op("w1", "ACQUIRE", 1, expectedVersion=0))
        row = sim.board.apply(1, op("w2", "ACQUIRE", 1, expectedVersion=1))["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "HELD"))
        self.assertEqual(answer(sim, 1, op("w3", "ACQUIRE", 1, expectedVersion=1)), "STALE_VERSION")
        sim = make_sim(bypass=("VERSION",))
        answer(sim, 0, op("w1", "ACQUIRE", 1, expectedVersion=0))
        row = sim.board.apply(1, op("w1", "RENEW", 1, expectedVersion=0))["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "VERSION"))
        sim = make_sim(bypass=("DEDUPE",))
        acq = op("w1", "ACQUIRE", 1, expectedVersion=0)
        answer(sim, 0, acq)
        self.assertEqual(answer(sim, 1, dict(acq)), "HELD")
        sim = make_sim(bypass=("SELF_VERIFICATION",))
        held = op("w1", "ACQUIRE", 1, expectedVersion=0)
        answer(sim, 0, held)
        mine = self._verdict(held["opId"], verifier="w1")
        row = sim.board.apply(1, op("w1", "VERIFY", 1, verdict=mine))["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "SELF_VERIFICATION"))
        sim = make_sim(bypass=("MERGE_VERDICT",))
        answer(sim, 0, op("w1", "ACQUIRE", 1, expectedVersion=0))
        row = sim.board.apply(1, op("w1", "MERGE", 1, expectedVersion=1, workDigest="d"))["row"]
        self.assertEqual((row["answer"], row["controlBypass"], row["verdictStatus"]), ("ACCEPTED", "MERGE_VERDICT", None))
        sim = make_sim(bypass=("EDGE",))
        row = sim.board.apply(0, op("w1", "MESSAGE", None, to="w3", messageType="TEST", requiredAction="NONE"))["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "EDGE"))


class GatewayTests(unittest.TestCase):
    def test_listing_grant_and_credentials(self):
        sim = make_sim()
        self.assertFalse(sim.gateway.call(0, "w1", "ADMIN", {}, None)["launched"])
        self.assertEqual(sim.log.rows[-1]["answer"], "NOT_LISTED")
        self.assertFalse(sim.gateway.call(0, "v", "READ", {"item": 1}, None)["launched"])
        self.assertTrue(sim.gateway.call(0, "w1", "READ", {"item": 1}, None)["launched"])
        value = sim.canaries["w1"]
        self.assertFalse(sim.gateway.call(0, "w1", "SEND_REPORT", {"report": "s", "token": value}, None)["launched"])
        self.assertEqual(sim.log.rows[-1]["answer"], "CREDENTIAL_VALUE")
        ref = {"param": "token", "brokerRef": "broker://example"}
        self.assertTrue(sim.gateway.call(0, "w1", "SEND_REPORT", {"report": "s", "token": ref}, None)["launched"])
        self.assertEqual([r["kind"] for r in sim.log.rows[-2:]], ["TOOL_CALL", "SINK"])
        self.assertEqual(sim.log.rows[-1]["canaryHits"], [])

    def test_bypasses(self):
        sim = make_sim(bypass=("PROFILE_LISTING",))
        # CONF-MAS-002 (DESIGN revision 8, section 4): ADMIN's valid input, as Worker.run_todo's CALL_ADMIN sends it; an
        # empty input is now INPUT_INVALID (test_p2_rules asserts that separately).
        self.assertTrue(sim.gateway.call(0, "w1", "ADMIN", {"action": "reconfigure"}, None)["launched"])
        self.assertEqual(sim.log.rows[-1]["controlBypass"], "PROFILE_LISTING")
        sim = make_sim(bypass=("CREDENTIAL_REF",))
        self.assertTrue(sim.gateway.call(0, "w1", "SEND_REPORT", {"report": "s", "token": sim.canaries["w1"]}, None)
                        ["launched"])
        self.assertEqual(sim.log.rows[-1]["kind"], "SINK")
        self.assertEqual(sim.log.rows[-1]["canaryHits"], ["w1"])


class RenewalGuaranteeTests(unittest.TestCase):
    def test_worst_case_latency_never_loses_a_lease(self):
        """Off the attack lane, with latency 3 in both directions and no drop, no holder loses its lease."""
        sim = make_sim("DECENTRALIZED", max_latency=3, deadline=600)
        sim.latency = lambda agent, lane: 0 if lane else 3
        rows = sim.run()
        self.assertEqual([r for r in rows if r["kind"] == "EXPIRY"], [])
        self.assertTrue(all(rec["state"] == "MERGED" for rec in sim.board.records.values()))

    def test_central_run_completes_without_expiry(self):
        sim = make_sim("CENTRAL", deadline=400)
        rows = sim.run()
        self.assertEqual([r for r in rows if r["kind"] == "EXPIRY"], [])
        self.assertTrue(all(rec["state"] == "MERGED" for rec in sim.board.records.values()))


if __name__ == "__main__":
    unittest.main()
