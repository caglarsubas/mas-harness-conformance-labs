"""CONF-MAS-003: the rules packet 3 adds (DESIGN revision 6, sections 2 and 4) against hand-built cases and single runs,
packets 1 and 2's seven ledger rows byte-identical, the data files closed, the campaign record and the attestation."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

import _classes
import _ledger
import _sim

HERE = Path(__file__).resolve().parent
CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}

# Canonical JSON digests (sorted keys, compact separators, ASCII) of packets 1 and 2's seven class rows in
# tests/mas/results.json at R12 c672aad (CONF-MAS-002, #30), and of the entries of classes.json at c672aad that stay
# byte-identical (section 3).
ROW_SHA256 = {
    "C1": "b3ae188401761d30a75902c2c88fcf2924e6411ea8227c570242d4eb02642ce4",
    "C2": "aa6dc7c60a0e51f2e9e8dd3099b0d35dc9231195e8bd3fd1b65f79880c4e4565",
    "C3": "74a874d78e0c03186381e78766faf3912ce019622202e6532461b31ebdbd66d4",
    "C4": "ab21c9bb5d0692da48a6ec2d3f22c7070b0e1b81dce130c4b5a05eae3b7ec619",
    "C5": "2ee5ad5d482b77fee15925dda13763815bf4c57d91fcae530794e66d28189e10",
    "C6": "5a1988368aa2d212153ad7fc44f4427c8f70a447dfc715fd3e24126a84ea2ef3",
    "C7": "4439b7cd2675ee00a00ae406c559540029e93d894f455cae4b00b8aa2a491713",
}
CLASSES_1_TO_7_SHA256 = "6c963f33bc4b62ebb85f5c70c3ca96cc20967f5e33f08f8ca20740f0b8e67d7d"
TOPOLOGIES_SHA256 = "dd3ef276776db8e2d4a025616cece55e292596ce12109e34f58d83d4636a1263"
REST_SHA256 = "97e7deb229aa6e90cd5582fb096539ff558bb83567878ec615dd0a7affab7d2e"
STREAMS_SHA256 = "5e28d1ac0d22fec7bc96daeca23643bad350c95b45966b73c4341527fec8e91f"
PIN = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"


def canonical(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def make_sim(topology: str = "DECENTRALIZED", bypass: tuple[str, ...] = (), **extra):
    cls = {"id": "T", "kind": "TEST", "topology": topology, "deadline": 100, "maxLatency": 0, "poisonPpm": 0,
           "stallPpm": 0, "compromised": None, "events": [], "controls": [], "depthChecks": [], **extra}
    return _sim.Sim(CONFIG, cls, 1, bypass, _classes.Scenario(cls))


class Ops:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, agent: str, op: str, item=None, **fields) -> dict:
        self.n += 1
        return {"opId": "%s-p%04d" % (agent, self.n), "agent": agent, "op": op, "item": item, **fields}


def apply(sim, t: int, op: dict) -> dict:
    return sim.board.apply(t, op)["row"]


def verdict(claim: str, work: str, status: str, n: int, supersedes=None, evidence: int = 1) -> dict:
    return {"verdictId": "v-%s-%d" % (claim, n), "verifier": "v", "holder": "w1", "claimOpId": claim,
            "workDigest": work, "status": status, "supersedes": supersedes, "evidence": evidence}


class ByteIdentityTests(unittest.TestCase):
    def test_packets_1_and_2_rows_are_byte_identical(self):
        rows = {r["id"]: r for r in _ledger.ledger()["classes"]}
        for cid, want in sorted(ROW_SHA256.items()):
            self.assertEqual(canonical(rows[cid]), want, cid)

    def test_existing_classes_json_entries_are_unchanged(self):
        self.assertEqual(canonical(CONFIG["classes"][:7]), CLASSES_1_TO_7_SHA256)
        # CONF-MAS-004 (DESIGN revision 5, section 10): its eight topologies, two streams and two sections are excluded.
        new = ["%s_N%d" % (family, n) for family in ("CENTRAL", "DECENTRALIZED") for n in (1, 2, 8, 16)]
        old_topologies = {k: v for k, v in CONFIG["topologies"].items() if k != "DECENTRALIZED_C9" and k not in new}
        self.assertEqual(canonical(old_topologies), TOPOLOGIES_SHA256)
        self.assertEqual(canonical(CONFIG["streams"][:6]), STREAMS_SHA256)
        self.assertEqual(CONFIG["streams"][6], "sched-c8")
        rest = {k: v for k, v in CONFIG.items() if k not in ("classes", "topologies", "streams", "schemaVersion",
                                                              "packet", "arms", "scaling", "hardCoding")}
        self.assertEqual(canonical(rest), REST_SHA256)
        self.assertEqual((CONFIG["schemaVersion"], CONFIG["packet"]), ("r12.mas-simulation-classes/v4", "CONF-MAS-004"))

    def test_the_new_switches_are_absent_from_packets_1_and_2(self):
        for cls in CONFIG["classes"][:7]:
            for key in ("crashes", "drops", "restarts", "scripts", "exercises", "relayRing"):
                self.assertNotIn(key, cls, (cls["id"], key))
            self.assertNotIn("rounds", cls.get("budgets") or {}, cls["id"])
            self.assertNotIn("wallTicks", cls.get("budgets") or {}, cls["id"])
            self.assertNotIn("kind", cls.get("measurements") or {}, cls["id"])

    def test_run_parameters_default_to_packet_1(self):
        sim = make_sim()
        self.assertEqual((sim.arm, sim.arm_policy, sim.until_deadline, sorted(sim.crashed)), (None, None, False, []))

    def test_the_coordinator_never_retries_without_drops(self):
        """Section 4: the coordinator's overdue retry runs only in a class with `drops` (C8)."""
        for cid in ("C1", "C2", "C6"):
            rows, _m = _ledger.run(CONFIG, CLASSES[cid], 1)
            retries = [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["agent"] == "c" and r["retryOf"]]
            self.assertEqual(retries, [], cid)


class BoardRuleTests(unittest.TestCase):
    def setUp(self):
        self.op = Ops()

    def test_supersession_reads_the_latest_and_its_bypass_the_first(self):
        sim = make_sim()
        acq = self.op("w1", "ACQUIRE", 1, expectedVersion=0)
        apply(sim, 0, acq)
        claim = acq["opId"]
        apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(claim, "a", "PASS", 1)))
        apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(claim, "a", "FAIL", 2, supersedes="v-%s-1" % claim,
                                                                evidence=2)))
        row = apply(sim, 2, self.op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))
        self.assertEqual((row["answer"], row["verdictStatus"]), ("VERDICT_NOT_PASS", "FAIL"))
        sim = make_sim(bypass=("SUPERSESSION",))
        acq = self.op("w1", "ACQUIRE", 1, expectedVersion=0)
        apply(sim, 0, acq)
        claim = acq["opId"]
        apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(claim, "a", "PASS", 1)))
        apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(claim, "a", "FAIL", 2, supersedes="v-%s-1" % claim,
                                                                evidence=2)))
        row = apply(sim, 2, self.op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))
        self.assertEqual((row["answer"], row["controlBypass"], row["verdictStatus"]),
                         ("ACCEPTED", "SUPERSESSION", "FAIL"))

    def test_per_work_history_and_the_work_verdict_bypass(self):
        for bypass, want in (((), ("VERDICT_NOT_PASS", None)), (("WORK_VERDICT",), ("ACCEPTED", "WORK_VERDICT"))):
            sim = make_sim(bypass=bypass)
            acq = self.op("w1", "ACQUIRE", 1, expectedVersion=0)
            apply(sim, 0, acq)
            claim = acq["opId"]
            apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(claim, "a", "FAIL", 1)))
            apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(claim, "b", "PASS", 2)))
            row = apply(sim, 2, self.op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))
            self.assertEqual((row["answer"], row["controlBypass"]), want, bypass)
            self.assertEqual(row["verdictStatus"], "FAIL")

    def test_a_merged_record_has_no_holder_unless_single_merge(self):
        for bypass, want in (((), ("NOT_HOLDER", None)), (("HOLDER",), ("NOT_HOLDER", None)),
                             (("HOLDER", "VERSION"), ("NOT_HOLDER", None)),
                             (("SINGLE_MERGE",), ("STALE_VERSION", "SINGLE_MERGE")),
                             (("SINGLE_MERGE", "VERSION"), ("ACCEPTED", "SINGLE_MERGE+VERSION"))):
            sim = make_sim(bypass=bypass)
            acq = self.op("w1", "ACQUIRE", 1, expectedVersion=0)
            apply(sim, 0, acq)
            apply(sim, 1, self.op("v", "VERIFY", 1, verdict=verdict(acq["opId"], "a", "PASS", 1)))
            first = apply(sim, 2, self.op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))
            self.assertEqual(first["answer"], "ACCEPTED")
            second = apply(sim, 2, self.op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))
            self.assertEqual((second["answer"], second["controlBypass"]), want, bypass)

    def test_holder_applies_a_non_holder_merge_to_the_live_claim(self):
        for bypass, want in ((("HOLDER",), "STALE_VERSION"), (("HOLDER", "VERSION"), "NO_VERDICT"),
                             (("HOLDER", "VERSION", "MERGE_VERDICT"), "ACCEPTED")):
            sim = make_sim(bypass=bypass)
            apply(sim, 0, self.op("w2", "ACQUIRE", 1, expectedVersion=0))
            row = apply(sim, 1, self.op("w4", "MERGE", 1, expectedVersion=0, workDigest="old"))
            self.assertEqual(row["answer"], want, bypass)
            self.assertIn("HOLDER", row["controlBypass"], bypass)
        sim = make_sim()
        apply(sim, 0, self.op("w2", "ACQUIRE", 1, expectedVersion=0))
        self.assertEqual(apply(sim, 1, self.op("w4", "MERGE", 1, expectedVersion=1, workDigest="old"))["answer"],
                         "NOT_HOLDER")

    def test_expiry_bypass_logs_one_skipped_row_and_keeps_the_claim(self):
        sim = make_sim(bypass=("EXPIRY",))
        acq = self.op("w1", "ACQUIRE", 1, expectedVersion=0)
        apply(sim, 0, acq)
        sim.board.read(8)
        sim.board.read(9)
        rows = [r for r in sim.log.rows if r["kind"] == "EXPIRY"]
        self.assertEqual([(r["t"], r["answer"], r["controlBypass"]) for r in rows], [(8, "SKIPPED", "EXPIRY")])
        self.assertEqual(sim.board.records[1]["state"], "HELD")


class ReaderTests(unittest.TestCase):
    def test_skipped_expiry_rows_end_no_claim_and_engage_nothing(self):
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="w1-0001", answer="ACCEPTED", changed=True,
                claimOpId="w1-0001", component="BOARD", expectedVersion=0, recordVersionBefore=0)
        log.add(8, "EXPIRY", agent="w1", item=1, claimOpId="w1-0001", leaseUntil=8, component="BOARD",
                answer="SKIPPED", controlBypass="EXPIRY", scheduledEvent="E1")
        self.assertIsNone(_classes.claim_intervals(log.rows)["w1-0001"]["end"])
        m = _classes.measure(log.rows, CONFIG, CLASSES["C8"])
        self.assertEqual(m["counts"]["expiries"], 0)
        event = {"id": "E1", "component": "BOARD", "engagedBy": "EXPIRY"}
        self.assertFalse(_classes.event_path(log.rows, event)["engaged"])

    def test_event_scoped_engagement_is_outside_engaged(self):
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="w1", op="RENEW", item=1, opId="w1-0002", answer="STALE_VERSION",
                changed=False, component="BOARD", scheduledEvent="E4")
        m = _classes.measure(log.rows, CONFIG, CLASSES["C3"])
        self.assertEqual(m["engaged"], {"BOARD:STALE_VERSION": 1})
        self.assertEqual(m["engagedByEvent"], {"E4": {"BOARD:STALE_VERSION": 1}})


class P18Tests(unittest.TestCase):
    """P1-8 (section 4): the FAULT clause on C8's rows; the claim-ended clause and a control case on hand-built rows."""

    @staticmethod
    def launched(log, t, claim, grant):
        log.add(t, "TOOL_CALL", agent="w1", toolId="READ", answer="LAUNCHED", component="GATEWAY", claimOpId=claim,
                grantId=grant, attempt=1, inputKeys=["item:integer"], grantToolId="READ", grantScope="read",
                grantManifestDigest=CONFIG["manifest"]["READ"]["manifestDigest"], grantExpiresAt=t + 2)

    def test_the_fault_clause_on_c8(self):
        for seed in CONFIG["seeds"]:
            rows, m = _ledger.run(CONFIG, CLASSES["C8"], seed)
            self.assertEqual(m["counts"]["timeoutExceeded"], 0, seed)
            without_fault = [r for r in rows if r["kind"] != "FAULT"]
            counts = _classes.measure(without_fault, CONFIG, CLASSES["C8"])["counts"]
            self.assertEqual(counts["timeoutExceeded"], 1, seed)

    def test_the_claim_ended_clause_and_its_control(self):
        cls = CLASSES["C7"]
        for end_kind in ("RELEASE", "EXPIRY"):
            log = _sim.Log()
            log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="w1-0001", answer="ACCEPTED",
                    changed=True, claimOpId="w1-0001", component="BOARD", heldBefore=0)
            self.launched(log, 1, "w1-0001", "g-1")
            if end_kind == "RELEASE":
                log.add(2, "BOARD_ANSWER", agent="w1", op="RELEASE", item=1, opId="w1-0002", answer="ACCEPTED",
                        changed=True, claimOpId="w1-0001", component="BOARD")
            else:
                log.add(3, "EXPIRY", agent="w1", item=1, claimOpId="w1-0001", leaseUntil=3, component="BOARD")
            self.assertEqual(_classes.measure(log.rows, CONFIG, cls)["counts"]["timeoutExceeded"], 0, end_kind)
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="w1-0001", answer="ACCEPTED", changed=True,
                claimOpId="w1-0001", component="BOARD", heldBefore=0)
        self.launched(log, 1, "w1-0001", "g-1")
        self.assertEqual(_classes.measure(log.rows, CONFIG, cls)["counts"]["timeoutExceeded"], 1)


class CounterTests(unittest.TestCase):
    def test_revisions_beyond_bound_counts_from_the_fifth_work(self):
        log = _sim.Log()
        for n in range(6):
            log.add(n, "WORK", agent="w3", item=3, claimOpId="w3-0001", workDigest="d%d" % n, component="WORK")
        self.assertEqual(_classes.measure(log.rows, CONFIG, CLASSES["C9"])["counts"]["revisionsBeyondBound"], 2)

    def test_claims_beyond_wall_budget_by_overrun_or_late_renew(self):
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="w1-0001", answer="ACCEPTED", changed=True,
                claimOpId="w1-0001", component="BOARD", heldBefore=0)
        log.add(109, "BOARD_ANSWER", agent="w1", op="RENEW", item=1, opId="w1-0009", answer="ACCEPTED", changed=True,
                claimOpId="w1-0001", component="BOARD")
        self.assertEqual(_classes.measure(log.rows, CONFIG, CLASSES["C9"])["counts"]["claimsBeyondWallBudget"], 0)
        log.add(110, "BOARD_ANSWER", agent="w1", op="RENEW", item=1, opId="w1-0010", answer="ACCEPTED", changed=True,
                claimOpId="w1-0001", component="BOARD")
        self.assertEqual(_classes.measure(log.rows, CONFIG, CLASSES["C9"])["counts"]["claimsBeyondWallBudget"], 1)

    def test_crashed_holds_count_unended_claims_of_a_crashed_agent(self):
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="c", to="w2", op="ASSIGN", item=2, opId="c-0002", answer="ACCEPTED",
                changed=True, claimOpId="c-0002", component="BOARD", heldBefore=1)
        log.add(1, "FAULT", agent="w2", item=2, claimOpId="c-0002", answer="CRASH", component="SCHEDULE",
                scheduledEvent="E1")
        self.assertEqual(_classes.measure(log.rows, CONFIG, CLASSES["C8"])["counts"]["crashedHoldsAtDeadline"], 1)
        log.add(8, "EXPIRY", agent="w2", item=2, claimOpId="c-0002", leaseUntil=8, component="BOARD")
        self.assertEqual(_classes.measure(log.rows, CONFIG, CLASSES["C8"])["counts"]["crashedHoldsAtDeadline"], 0)


class RecordTests(unittest.TestCase):
    def test_the_campaign_record_is_regenerated_byte_for_byte(self):
        self.assertEqual(_ledger.serialize(_ledger.campaign_record()), (HERE / "campaign-record.json").read_bytes())

    def test_the_campaign_record_is_closed(self):
        rec = _ledger.campaign_record()
        # CONF-MAS-004 (DESIGN revision 5, section 10): v2's keys; packet 3's entry keeps v1's digest, packet 4's
        # entry carries results.json's.
        self.assertEqual(sorted(rec), ["arms", "campaign", "classes", "consumer", "eventScopedReadings", "findings",
                                       "hardCoding", "notClaimed", "packets", "recordedFails", "scaling",
                                       "schemaVersion"])
        self.assertEqual([p["packetId"] for p in rec["packets"]],
                         ["CONF-MAS-001", "CONF-MAS-002", "CONF-MAS-003", "CONF-MAS-004"])
        self.assertEqual(rec["packets"][2]["resultsSha256"],
                         "1893118540358ccd0db0d3ad4009af97041560c2f210773cbc0805231cc40f87")
        self.assertEqual(rec["packets"][3]["resultsSha256"],
                         hashlib.sha256((HERE / "results.json").read_bytes()).hexdigest())
        self.assertEqual([c["id"] for c in rec["classes"]], [c["id"] for c in CONFIG["classes"]])
        self.assertEqual(sorted(r["check"] for r in rec["eventScopedReadings"]),
                         ["C2-GATE-OFF", "C2-VERIFIER-OFF", "C3-DEDUPE-OFF", "C3-RETRY-OFF"])
        self.assertEqual(len(rec["arms"]), 15)
        raw = (HERE / "campaign-record.json").read_bytes()
        self.assertNotIn(b"CANARY-", raw)
        self.assertNotIn(b"/" + b"Users/", raw)  # no home path (built from parts, so this file holds none either)

    def test_the_arms_section_is_preregistered(self):
        arms = _ledger.ledger()["arms"]
        self.assertEqual((arms["classes"], arms["policies"]), (CONFIG["arms"]["classes"], CONFIG["arms"]["policies"]))
        self.assertEqual([(r["arm"], r["class"]) for r in arms["results"]],
                         [(p["id"], c) for p in CONFIG["arms"]["policies"] for c in CONFIG["arms"]["classes"]])
        for r in arms["results"]:
            self.assertEqual(sorted(r), ["arm", "class", "quantiles", "totals", "wouldHoldBounds"])
            self.assertEqual(sorted(r["totals"]), ["a1ResentMerges", "a3ReReads", "duplicateWork",
                                                   "revisionExhaustionReleases", "workEffects"])


class AttestationTests(unittest.TestCase):
    def test_packet_3_attestation_is_closed_and_pinned(self):
        att = json.loads((HERE / "attestation-p3.json").read_text())
        old = json.loads((HERE / "attestation.json").read_text())
        pins = json.loads((HERE / "contracts.json").read_text())
        self.assertEqual(sorted(att), sorted(old))
        self.assertEqual((att["schemaVersion"], att["packet"]), ("r12.mas-attestation/v1", "CONF-MAS-003"))
        self.assertEqual(pins["commit"], PIN)
        self.assertTrue(all(n.startswith("<harness-onion>/") and n.endswith("@585364b") for n in att["inputs"]))
        # CONF-MAS-004 (section 10): packet 3's attestation has the first ten pins; the eleventh is packet 4's.
        want = {"<harness-onion>/%s@585364b" % f["path"]: f["sha256"] for f in pins["files"][:10]}
        self.assertEqual(att["inputDigests"], want)
        for flag in ("warmSourceRead", "r10SourceRead", "w03WorkInProgressRead",
                     "implementationReadOrRunForExpectedResults"):
            self.assertIs(att[flag], False, flag)
        # B5-1 and B5-4: each round's reads and probes from its own record; packet review rounds added before the squash.
        for phrase in ("round 5 read only tests/mas/README.md and tests/mas/contracts.json",
                       "round 3 ran 40 single simulations", "before the packet's final squash"):
            self.assertIn(phrase, att["note"])


if __name__ == "__main__":
    unittest.main()
