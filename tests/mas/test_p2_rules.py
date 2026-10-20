"""CONF-MAS-002: packet 2's restated rules against hand-built cases (DESIGN revision 8, sections 2 and 4; BUILD_NOTES
B8-1 to B8-4): issued grants with reuse, match and expiry checks, input validity, the closed message body and its canary
hits, the kernel's budgets, retries and timeouts, admission, the judged-field run check, and the attestation."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

import _classes
import _ledger
import _sim

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "classes.json").read_text())
CLASSES = {c["id"]: c for c in CONFIG["classes"]}


def make_sim(topology: str = "DECENTRALIZED", bypass: tuple[str, ...] = (), deadline: int = 100, **keys):
    cls = {"id": "T", "kind": "TEST", "topology": topology, "deadline": deadline, "maxLatency": 0, "poisonPpm": 0,
           "stallPpm": 0, "compromised": None, "events": [], "controls": [], "depthChecks": [], **keys}
    return _sim.Sim(CONFIG, cls, 1, bypass, _classes.Scenario(cls))


class Ops:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, agent: str, op: str, item=None, **fields) -> dict:
        self.n += 1
        return {"opId": "%s-p%04d" % (agent, self.n), "agent": agent, "op": op, "item": item, **fields}


def answer(sim, t: int, op: dict) -> str:
    return sim.board.apply(t, op)["result"]["answer"]


class GatewayTests(unittest.TestCase):
    def test_input_validity(self):
        sim = make_sim()
        self.assertEqual(sim.gateway.call(0, "w1", "READ", {"item": "1"}, None)["row"]["answer"], "INPUT_INVALID")
        self.assertEqual(sim.gateway.call(0, "w1", "READ", {"item": 1, "x": 1}, None)["row"]["answer"],
                         "INPUT_INVALID")
        self.assertEqual(sim.gateway.call(0, "w1", "READ", {"item": True}, None)["row"]["answer"], "INPUT_INVALID")
        row = sim.gateway.call(0, "w1", "READ", {"item": 1}, None)["row"]
        self.assertEqual((row["answer"], row["inputKeys"]), ("LAUNCHED", ["item:integer"]))
        # The credential parameter is the credential rule's, not the schema's: a value passes the schema and is refused
        # CREDENTIAL_VALUE (packet 1's C1 E3 input).
        token = sim.canaries["w1"]
        row = sim.gateway.call(0, "w1", "SEND_REPORT", {"report": "s", "token": token}, None)["row"]
        self.assertEqual((row["answer"], row["inputKeys"]), ("CREDENTIAL_VALUE", ["report:string"]))
        # An empty ADMIN input is INPUT_INVALID once NOT_LISTED is bypassed (packet 1's test now sends {action}).
        sim = make_sim(bypass=("PROFILE_LISTING",))
        self.assertEqual(sim.gateway.call(0, "w1", "ADMIN", {}, None)["row"]["answer"], "INPUT_INVALID")

    def test_grants_are_issued_presented_and_checked_in_order(self):
        sim = make_sim()
        rows_before = len(sim.log.rows)
        h = sim.gateway.issue(0, "w1", "READ")
        self.assertEqual(len(sim.log.rows), rows_before)  # issuing writes no row
        self.assertEqual((h["toolId"], h["scope"], h["expiresAt"]), ("READ", "read", 0 + CONFIG["grantTicks"]))
        first = sim.gateway.call(1, "w1", "READ", {"item": 1}, None)
        self.assertTrue(first["launched"])
        g = first["grant"]
        self.assertEqual(first["row"]["grantId"], g["grantId"])
        self.assertEqual(sim.gateway.call(2, "w1", "READ", {"item": 1}, None, grant=g)["row"]["answer"],
                         "GRANT_REUSED")
        self.assertEqual(sim.gateway.call(2, "w1", "READ", {"item": 1}, None, grant=h)["row"]["answer"],
                         "GRANT_EXPIRED")
        k = sim.gateway.issue(3, "w1", "SEND_REPORT")
        self.assertEqual(sim.gateway.call(3, "w1", "READ", {"item": 1}, None, grant=k)["row"]["answer"],
                         "GRANT_MISMATCH")
        # Precedence: an invalid input is refused before any grant condition; reuse before mismatch before expiry.
        self.assertEqual(sim.gateway.call(9, "w1", "READ", {"item": 1, "p": "x"}, None, grant=g)["row"]["answer"],
                         "INPUT_INVALID")
        old_k = sim.gateway.issue(4, "w1", "SEND_REPORT")
        self.assertEqual(sim.gateway.call(9, "w1", "READ", {"item": 1}, None, grant=old_k)["row"]["answer"],
                         "GRANT_MISMATCH")

    def test_each_bypass_flips_exactly_its_check(self):
        cases = (("GRANT_REUSE", "reuse"), ("GRANT_EXPIRY", "expired"), ("GRANT_MATCH", "mismatch"),
                 ("INPUT_SCHEMA", "input"))
        for bypass, case in cases:
            sim = make_sim(bypass=(bypass,))
            g = sim.gateway.call(0, "w1", "READ", {"item": 1}, None)["grant"]
            inp, grant, t = {"item": 1}, None, 1
            if case == "reuse":
                grant = g
            elif case == "expired":
                grant, t = sim.gateway.issue(0, "w1", "READ"), 5
            elif case == "mismatch":
                grant = sim.gateway.issue(1, "w1", "SEND_REPORT")
            else:
                inp = {"item": 1, "payload": "x"}
            row = sim.gateway.call(t, "w1", "READ", inp, None, grant=grant)["row"]
            self.assertEqual((row["answer"], row["controlBypass"]), ("LAUNCHED", bypass), bypass)


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.ops = Ops()

    def test_the_closed_body(self):
        sim = make_sim()
        op = self.ops
        ok = {"to": "w2", "messageType": "TEST", "requiredAction": "NONE"}
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, **ok)), "ACCEPTED")  # ref is optional
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, ref={"relayTo": "w3"}, **ok)), "ACCEPTED")
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, ref={"content": "x"}, **ok)), "SHAPE")
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, content="x", **ok)), "SHAPE")
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", 3, **ok)), "SHAPE")  # a non-null envelope item
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, ref={"item": "3"}, **ok)), "SHAPE")
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, ref={"to": "w4"}, **ok)), "SHAPE")
        missing = {"to": "w2", "messageType": "TEST"}
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, **missing)), "SHAPE")
        # SHAPE comes before OFF_EDGE (w1 to w3 is off the ring).
        off = {"to": "w3", "messageType": "TEST", "requiredAction": "NONE"}
        self.assertEqual(answer(sim, 0, op("w1", "MESSAGE", None, ref={"content": "x"}, **off)), "SHAPE")
        sim = make_sim(bypass=("MESSAGE_SHAPE",))
        row = sim.board.apply(0, self.ops("w1", "MESSAGE", None, ref={"content": "x"}, **ok))["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "MESSAGE_SHAPE"))
        delivery = [r for r in sim.log.rows if r["kind"] == "DELIVERY" and r["component"] == "BUS"][-1]
        self.assertEqual(delivery["bodyKeys"], ["messageType", "ref", "ref.content", "requiredAction", "to"])

    def test_a_canary_in_a_string_ref_field_is_counted_in_a_defended_run(self):
        """B8-1: deliver_message computes the hits on every delivery, not only under a bypass."""
        cls = dict(CLASSES["C3"])
        sim = _sim.Sim(CONFIG, cls, 1, (), _classes.Scenario(cls))
        status = "leak " + sim.canaries["w3"]
        sim.board.apply(0, self.ops("w1", "MESSAGE", None, to="w2", messageType="TEST", requiredAction="NONE",
                                    ref={"status": status}))
        row = [r for r in sim.log.rows if r["kind"] == "DELIVERY" and r["component"] == "BUS"][-1]
        self.assertEqual(row["canaryHits"], ["w3"])
        measured = _classes.measure(sim.log.rows, CONFIG, cls)
        self.assertEqual(measured["counts"]["canaryDelivered"], 1)
        self.assertEqual(measured["counts"]["leakedSecrets"], 1)
        self.assertEqual(measured["counts"]["messageContentDelivered"], 0)


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.ops = Ops()

    def test_held_before_is_counted_after_the_ticks_expiries(self):
        sim = make_sim()
        op = self.ops
        for item in (1, 2, 3, 4):
            answer(sim, 0, op("w%d" % item, "ACQUIRE", item, expectedVersion=0))
        self.assertEqual(answer(sim, 1, op("w1", "ACQUIRE", 5, expectedVersion=0)), "CONCURRENCY_LIMIT")
        lease = CONFIG["shared"]["leaseTicks"]
        row = sim.board.apply(lease, op("w1", "ACQUIRE", 5, expectedVersion=0))["row"]
        self.assertEqual((row["answer"], row["heldBefore"]), ("ACCEPTED", 0))

    def test_the_concurrency_bypass(self):
        sim = make_sim(bypass=("CONCURRENCY",))
        op = self.ops
        for item in (1, 2, 3, 4):
            answer(sim, 0, op("w%d" % item, "ACQUIRE", item, expectedVersion=0))
        row = sim.board.apply(0, op("w1", "ACQUIRE", 5, expectedVersion=0))["row"]
        self.assertEqual((row["answer"], row["heldBefore"], row["controlBypass"]), ("ACCEPTED", 4, "CONCURRENCY"))


class AdmissionAndRolesTests(unittest.TestCase):
    def test_admission_refuses_a_declared_conflict(self):
        cls = CLASSES["C5"]
        for bypass, answer_w5, steps in ((), "CONFLICTING_OBJECTIVE", False), (("OBJECTIVE",), "ADMITTED", True):
            sim = _sim.Sim(CONFIG, cls, 1, bypass, _classes.scenario_for(cls))
            sim.cfg = dict(cls, deadline=0)
            sim.run()
            rows = {r["agent"]: r for r in sim.log.rows if r["kind"] == "ADMISSION"}
            self.assertEqual(sorted(rows), sorted(sim.order))
            self.assertEqual((rows["w5"]["answer"], rows["w5"]["objectiveId"], rows["w5"]["scheduledEvent"]),
                             (answer_w5, "obj-B", "E2"))
            self.assertEqual("w5" in sim.admitted, steps)
            self.assertTrue(all(r["answer"] == "ADMITTED" for a, r in rows.items() if a != "w5"))

    def test_roles_resolve_before_canaries_and_own_verifiers(self):
        cls = CLASSES["C7"]
        for seed in (1, 2, 3):
            sim = _sim.Sim(CONFIG, cls, seed, (), _classes.scenario_for(cls))
            w_d = sim.roles["w_d"]
            self.assertEqual(sim.compromised_set, {w_d})
            self.assertNotIn(w_d, sim.canaries)
            self.assertTrue(sim.agents[w_d].compromised)
        sim = _sim.Sim(CONFIG, CLASSES["C5"], 1, (), _classes.scenario_for(CLASSES["C5"]))
        self.assertEqual([sim.verifier_of(w) for w in ("w1", "w2", "w3", "w4", "w5")], ["v", "v", "v", "x", "v"])
        self.assertEqual(sim.compromised_set, {"w4", "x"})


class CounterTests(unittest.TestCase):
    def test_new_counters_judge_only_rows_that_carry_their_fields(self):
        """A hand-built row with null judged fields counts nothing (packet 1's test_extractors relies on it)."""
        log = _sim.Log()
        log.add(0, "TOOL_CALL", agent="w1", toolId="READ", answer="LAUNCHED", component="GATEWAY")
        log.add(0, "DELIVERY", agent="w2", **{"from": "w1"}, to="w2", answer="DELIVERED", component="BUS")
        log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="a", claimOpId="a", answer="ACCEPTED",
                changed=True, component="BOARD")
        counts = _classes.measure(log.rows, CONFIG, CLASSES["C7"])["counts"]
        for name in _classes.NEW_COUNTERS:
            self.assertEqual(counts[name], 0, name)


class RunCheckTests(unittest.TestCase):
    def test_no_judged_row_of_any_sim_run_has_a_null_judged_field(self):
        """B8-2: every defended and control run of every class (packet 1's included); claimOpId excepted."""
        for cls in CONFIG["classes"]:
            for bypass in [()] + [tuple(c["bypass"]) for c in cls["controls"]]:
                for seed in CONFIG["seeds"]:
                    rows, _m = _ledger.run(CONFIG, cls, seed, bypass)
                    self.assertEqual(_classes.null_judged_fields(rows, cls), [], (cls["id"], bypass, seed))


class AttestationTests(unittest.TestCase):
    def test_the_fourth_flag_and_its_scope(self):
        att = json.loads((HERE / "attestation.json").read_text())
        self.assertIs(att["implementationReadOrRunForExpectedResults"], False)
        self.assertEqual(att["packet"], "CONF-MAS-002")
        self.assertIn("packet 1's merged R12 code at 05b74ff", att["note"])
        self.assertIn("ran approximations of C5 and C7 on a copy of packet 1's merged engine at 05b74ff", att["note"])


if __name__ == "__main__":
    unittest.main()
