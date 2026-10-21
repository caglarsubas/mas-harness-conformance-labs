"""CONF-MAS-004: the rules packet 4 adds (DESIGN revision 5, section 4) against hand-built cases and single runs, the
claimAwareWorker checks (section 4.9), packet 3's rows and classes.json entries byte-identical, the data files, the
attestation and the campaign record v2."""
from __future__ import annotations

import hashlib
import inspect
import json
import unittest
from pathlib import Path

import _classes
import _ledger
import _sim

HERE = Path(__file__).resolve().parent
CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
PIN = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"

# Canonical JSON digests (sorted keys, compact separators, ASCII) of packet 3's three class rows and of the ledger's arms
# in tests/mas/results.json at 0a479a55 (tree c80b4d67, R12 dbc45c7's tree), and of packet 3's classes.json entries at
# the same tree (section 10).
ROW_SHA256 = {
    "C8": "92b999f15ddfdce224fd9f19a08e9eed9be3fa6dceb9ef83d3ced265d02e7ac3",
    "C9": "45fc3528881275d75974aad8adbcf2428d8197405163578bb180413c603a3832",
    "C10": "317d58dd0196053e36c2ffce47e5863f68c4b8b957ccd895db4950d808604df6",
}
LEDGER_ARMS_SHA256 = "fa1e7481fd20fb73fccc68950a822895c83192d295a7f6caa35e4095bbdd54f6"
CLASSES_8_TO_10_SHA256 = "7d74d5c14971e276280c7fca093c90af6121ece6a656e8a8c00f1ef1511a29ac"
DECENTRALIZED_C9_SHA256 = "5d20332d5b3de035560fca5f409011695b027d30193417f4ccc40ed29df2f9be"
CLASSES_ARMS_SHA256 = "f22cf5291c98f446aa4effc79b552c0c0544d12351c8f6753c590b2f08c76e8d"
P3_RESULTS_SHA256 = "1893118540358ccd0db0d3ad4009af97041560c2f210773cbc0805231cc40f87"
NEW_KEYS = ("load", "tasks", "selfReport", "degenerateCheck", "isolateEvents", "evidenceRule", "claimAwareWorker")
# Section 4.5: the restated registry subset, as this design states it (R12's CI cannot reach harness-onion; the reviews
# verify it against the pinned check-kinds.json).
EVIDENCE_RULE = {"deterministicChecks": ["DETERMINISTIC_POLICY", "DETERMINISTIC_SCHEMA", "DETERMINISTIC_TEST"],
                 "consistencyOnly": ["REGRESSION_RUN"], "source": "architecture/verdict-ledger/check-kinds.json"}
TASKS = {"problemStream": "task-problem"}
SAFETY = ["leakedSecrets", "doubleMerge", "nonHolderAccepted", "unexplainedDuplicate", "unclaimedWork",
          "mergeWithoutPass", "poisonMerged", "staleAccepted", "opIdAppliedTwice", "retryChangedState", "claimOverlap",
          "selfVerified", "offEdgeDelivered", "unlistedLaunched", "heldBeyondConcurrency"]


def canonical(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def make_cls(topology: str = "DECENTRALIZED", **extra) -> dict:
    return {"id": "T", "kind": "TEST", "topology": topology, "deadline": 100, "maxLatency": 0, "poisonPpm": 0,
            "stallPpm": 0, "compromised": None, "events": [], "controls": [], "depthChecks": [], **extra}


def make_sim(topology: str = "DECENTRALIZED", bypass: tuple[str, ...] = (), labels: str = "IDENTITY", **extra):
    cls = make_cls(topology, **extra)
    return _sim.Sim(CONFIG, cls, 1, bypass, _classes.Scenario(cls), labels=labels)


class Ops:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, agent: str, op: str, item=None, **fields) -> dict:
        self.n += 1
        return {"opId": "%s-p%04d" % (agent, self.n), "agent": agent, "op": op, "item": item, **fields}


def apply(sim, t: int, op: dict) -> dict:
    return sim.board.apply(t, op)["row"]


def verdict(claim: str, work: str, status: str, n: int, checks=None, supersedes=None, evidence: int = 1) -> dict:
    out = {"verdictId": "v-%s-%d" % (claim, n), "verifier": "v", "holder": "w1", "claimOpId": claim,
           "workDigest": work, "status": status, "supersedes": supersedes, "evidence": evidence}
    if checks is not None:
        out["checks"] = checks
    return out


def gate_rows(sim, tool: str) -> list[dict]:
    return [r for r in sim.log.rows if r["kind"] == "GATE" and r["toolId"] == tool]


class LoadTests(unittest.TestCase):
    def test_load_replaces_items_and_concurrency_only(self):
        self.assertIs(_sim.shared_for(CONFIG, make_cls()), CONFIG["shared"])
        sim = make_sim(load={"items": 7, "concurrency": 2})
        self.assertEqual(sim.shared, dict(CONFIG["shared"], items=7, concurrency=2))
        self.assertEqual(sorted(sim.board.records), list(range(1, 8)))
        op = Ops()
        answers = [apply(sim, 0, op("w%d" % k, "ACQUIRE", k, expectedVersion=0))["answer"] for k in (1, 2, 3)]
        self.assertEqual(answers, ["ACCEPTED", "ACCEPTED", "CONCURRENCY_LIMIT"])

    def test_measure_reads_the_merged_load(self):
        cls = make_cls(load={"items": 7, "concurrency": 2})
        counts = _classes.measure([], CONFIG, cls)["counts"]
        self.assertEqual((counts["lostItems"], counts["completionPpm"], counts["lostWorkPpm"]), (7, 0, 1000000))
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="a", claimOpId="a", answer="ACCEPTED",
                changed=True, component="BOARD", heldBefore=2)
        self.assertEqual(_classes.measure(log.rows, CONFIG, cls)["counts"]["heldBeyondConcurrency"], 1)
        self.assertEqual(_classes.measure(log.rows, CONFIG, make_cls())["counts"]["heldBeyondConcurrency"], 0)

    def test_degenerate_check_requires_tasks_and_the_parameters_are_closed(self):
        with self.assertRaises(ValueError):
            make_sim(degenerateCheck=True)
        make_sim(degenerateCheck=True, tasks=TASKS)
        with self.assertRaises(ValueError):
            make_sim(labels="PERMUTED")
        with self.assertRaises(ValueError):
            make_sim(labels="SHUFFLED", tasks=TASKS)
        cls = make_cls()
        with self.assertRaises(ValueError):
            _sim.Sim(CONFIG, cls, 1, (), _classes.Scenario(cls), policy="CLEVER")


class RunInterfaceTests(unittest.TestCase):
    def test_the_three_new_parameters_are_keyword_only_with_packet_1_defaults(self):
        params = list(inspect.signature(_ledger.run).parameters.values())
        self.assertEqual([p.name for p in params], ["config", "cls", "seed", "bypass", "arm", "until_deadline", "labels",
                                                     "scriptedEvents", "policy"])
        self.assertEqual([p.kind for p in params[6:]], [inspect.Parameter.KEYWORD_ONLY] * 3)
        self.assertEqual([p.default for p in params[3:]], [(), None, False, "IDENTITY", None, None])
        sim = make_sim()
        self.assertEqual((sim.labels, sim.scripted_events, sim.policy, sim.tasks, sim.sigma), ("IDENTITY", None,
                                                                                               "GENERAL", None, None))

    def test_explicit_defaults_give_the_same_run(self):
        rows, _m = _ledger.run(CONFIG, CLASSES["C3"], 1)
        again, _m = _ledger.run(CONFIG, CLASSES["C3"], 1, (), None, False, labels="IDENTITY", scriptedEvents=None,
                                policy=None)
        self.assertEqual(rows, again)
        bed = CONFIG["hardCoding"]["bed"]
        self.assertEqual(_ledger.run(CONFIG, bed, 1)[0], _ledger.run(CONFIG, bed, 1, policy="GENERAL")[0])


def rule_topology(family: str, n: int) -> dict:
    """Section 6.1's rule, written here on its own."""
    workers = ["w%d" % i for i in range(1, n + 1)]
    edges = []
    for w in workers:
        edges += [["v", w], [w, "v"]]
    if family == "CENTRAL":
        edges += [["c", "v"], ["v", "c"]]
        for w in workers:
            edges += [["c", w], [w, "c"]]
        return {"coordinator": "c", "edges": sorted(edges), "mode": "CENTRAL", "verifier": "v", "workers": workers}
    if n >= 2:
        edges += [[workers[i - 1], workers[i % n]] for i in range(1, n + 1)]
    return {"coordinator": None, "edges": sorted(edges), "mode": "DECENTRALIZED", "verifier": "v",
            "workers": workers}


class TopologyAndPointTests(unittest.TestCase):
    def test_the_rule_regenerates_the_eight_new_topologies_and_packet_1s_two(self):
        topologies = CONFIG["topologies"]
        for family in ("CENTRAL", "DECENTRALIZED"):
            self.assertEqual(rule_topology(family, 4), topologies[family], family)
            for n in (1, 2, 8, 16):
                self.assertEqual(rule_topology(family, n), topologies["%s_N%d" % (family, n)], (family, n))
        self.assertEqual(topologies["CENTRAL_N16"]["workers"][9:11], ["w10", "w11"])  # numeric order

    def test_the_points_follow_the_preregistered_rule(self):
        spec = CONFIG["scaling"]
        ids = [p["id"] for p in spec["points"]]
        self.assertEqual(ids, ["S-C1", "S-C2", "S-C4", "S-C8", "S-C16", "S-D1", "S-D2", "S-D4", "S-D8", "S-D16"])
        self.assertEqual([b["id"] for b in spec["baseline"]], ["B-5", "B-10", "B-20", "B-40", "B-80"])
        for entry in spec["points"] + spec["baseline"]:
            n, items = entry["workers"], entry["load"]["items"]
            name = entry["family"] if n == 4 else "%s_N%d" % (entry["family"], n)
            self.assertEqual(entry["topology"], name, entry["id"])
            self.assertEqual((entry["kind"], entry["maxLatency"], entry["stallPpm"], entry["poisonPpm"]),
                             ("SCALING", 3, 20000, 50000), entry["id"])
            self.assertEqual((entry["deadline"], entry["events"], entry["compromised"]), (400 + 50 * items, [], None))
            self.assertIs(entry["claimAwareWorker"], True, entry["id"])
            if entry["id"].startswith("S-"):
                self.assertEqual((items, entry["load"]["concurrency"]), (5 * n, n), entry["id"])
            else:
                self.assertEqual((entry["topology"], entry["load"]["concurrency"], items),
                                 ("DECENTRALIZED_N1", 1, int(entry["id"][2:])), entry["id"])
        self.assertEqual(spec["safetyCounters"], SAFETY)
        self.assertEqual(spec["safetyCounters"][:5], CONFIG["zeroTolerance"])
        self.assertEqual(tuple(spec["readings"]), _ledger.SCALING_READINGS)
        self.assertEqual(spec["controls"], [{"bypass": ["HELD", "VERSION"], "counter": "claimOverlap",
                                             "id": "S-D16-EXCLUSIVE-OFF", "point": "S-D16"}])

    def test_the_bed_is_preregistered(self):
        spec = CONFIG["hardCoding"]
        bed = spec["bed"]
        self.assertEqual((bed["kind"], bed["topology"], bed["load"], bed["deadline"]),
                         ("HARD_CODING_BED", "DECENTRALIZED_N1", {"concurrency": 1, "items": 20}, 900))
        self.assertEqual((bed["maxLatency"], bed["poisonPpm"], bed["stallPpm"], bed["tasks"]), (0, 0, 0, TASKS))
        self.assertEqual((spec["policies"], spec["labels"], spec["permutationStream"]),
                         (["GENERAL", "HARD_CODED"], ["IDENTITY", "PERMUTED"], _sim.PERMUTATION_STREAM))
        self.assertEqual(CONFIG["streams"][7:], ["task-problem", "perm-items"])


class TaskTests(unittest.TestCase):
    def test_solve_and_the_last_problem(self):
        self.assertEqual(_sim.solve("000123"), hashlib.sha256(b"solve:000123").hexdigest()[:16])
        self.assertEqual(_sim.last_problem(["read:w1:1:000001 problem:111111", "read:w1:1:000002 problem:222222"]),
                         "222222")
        self.assertEqual(_sim.last_problem(["read:w1:1:000001"]), "")

    def test_problems_are_drawn_in_task_order_and_labels_default_to_identity(self):
        sim = make_sim(tasks=TASKS, load={"items": 5, "concurrency": 1})
        streams = _sim.Streams(1)
        want = {}
        for task in range(1, 6):
            want[task] = "%06d" % (streams.draw("task-problem") % 1000000)
        self.assertEqual(sim.problems, want)
        self.assertEqual(sim.task_of, {k: k for k in range(1, 6)})
        self.assertIsNone(sim.sigma)

    def test_permuted_labels_draw_sigma_from_its_own_stream(self):
        for seed in (1, 2, 3):
            cls = make_cls(tasks=TASKS, load={"items": 20, "concurrency": 1})
            sim = _sim.Sim(CONFIG, cls, seed, (), _classes.Scenario(cls), labels="PERMUTED")
            sigma = _sim.Streams(seed).permutation("perm-items", list(range(1, 21)))
            self.assertEqual(sim.sigma, sigma)
            self.assertEqual(sim.task_of, {k: sigma[k - 1] for k in range(1, 21)})
            self.assertEqual(sim.problem_of_item(3), sim.problems[sigma[2]])

    def test_a_read_carries_its_task_problem_and_honest_work_its_answer(self):
        sim = make_sim(tasks=TASKS, load={"items": 3, "concurrency": 1})
        op = Ops()
        acq = op("w1", "ACQUIRE", 2, expectedVersion=0)
        apply(sim, 0, acq)
        worker = sim.agents["w1"]
        worker.take_claim(0, 2, acq["opId"], 1, 8)
        worker.start_read(1, 1)
        worker.read_progress(2)
        problem = sim.problems[2]
        self.assertTrue(worker.hold["reads"][-1].endswith(" problem:" + problem))
        raw = ("item-2|" + "|".join(worker.hold["reads"])).encode("utf-8")
        honest = sim.scenario.work_bytes(sim, worker, raw)
        self.assertEqual(honest, raw + b"|answer:" + _sim.solve(problem).encode("ascii"))
        self.assertTrue(sim.task_pass(honest, 2))
        self.assertFalse(sim.task_pass(raw, 2))
        plain = make_sim()
        self.assertEqual(plain.scenario.work_bytes(plain, plain.agents["w1"], raw), raw)


class JudgeTests(unittest.TestCase):
    @staticmethod
    def judge(sim, raw: bytes, status=None) -> dict:
        work = _sim.digest(raw)
        sim.artefacts[work] = raw
        ref = {"item": 1, "claimOpId": "w1-c", "workDigest": work}
        if status is not None:
            ref["status"] = status
        sim.agents["v"].judge(5, {"type": "MESSAGE", "from": "w1", "messageType": "TEST", "ref": ref, "event": None})
        return gate_rows(sim, "judge")[-1]

    def test_the_task_test_reads_the_bytes(self):
        sim = make_sim(tasks=TASKS, load={"items": 3, "concurrency": 1})
        answer = b"|answer:" + _sim.solve(sim.problems[1]).encode("ascii")
        cases = ((b"item-1|x" + answer, "PASS", True), (b"item-1|x", "FAIL", False),
                 (b"item-1|x|answer:0000000000000000", "FAIL", False),
                 (b"item-1|x POISON-MARKER" + answer, "FAIL", True))
        for raw, want, task in cases:
            row = self.judge(sim, raw)
            self.assertEqual((row["answer"], row["taskPass"], row["controlBypass"]), (want, task, None), raw)
        plain = make_sim()
        row = self.judge(plain, b"item-1|x")
        self.assertEqual((row["answer"], row["taskPass"]), ("PASS", None))

    def test_judge_by_status_takes_the_reported_status_and_is_named_only_when_it_turns_a_fail(self):
        sim = make_sim(bypass=("JUDGE_BY_STATUS",), tasks=TASKS, load={"items": 3, "concurrency": 1})
        good = b"item-1|x|answer:" + _sim.solve(sim.problems[1]).encode("ascii")
        for raw, status, want in ((b"item-1|", "PASS", ("PASS", False, "JUDGE_BY_STATUS")),
                                  (good, "PASS", ("PASS", True, None)),
                                  (b"item-1|", None, ("FAIL", False, None))):
            row = self.judge(sim, raw, status)
            self.assertEqual((row["answer"], row["taskPass"], row["controlBypass"]), want, (raw, status))
        defended = make_sim(tasks=TASKS, load={"items": 3, "concurrency": 1})
        self.assertEqual(self.judge(defended, b"item-1|", "PASS")["answer"], "FAIL")

    def test_an_evidence_rule_class_verdict_cites_a_task_test(self):
        sim = make_sim(evidenceRule=EVIDENCE_RULE)
        self.judge(sim, b"item-1|x")
        sent = [e["op"]["verdict"] for e in sim.agents["v"].pending.values() if e["op"]["op"] == "VERIFY"]
        self.assertEqual([v["checks"] for v in sent], [["DETERMINISTIC_TEST/TEST_RESULT"]])
        plain = make_sim()
        self.judge(plain, b"item-1|x")
        self.assertTrue(all("checks" not in e["op"]["verdict"] for e in plain.agents["v"].pending.values()))

    def test_a_self_report_rides_only_c12s_test_messages(self):
        for cid, want in (("C12", True), ("C10", False), ("C11", False)):
            rows, _m = _ledger.run(CONFIG, CLASSES[cid], 1)
            tests = [r for r in rows if r["kind"] == "DELIVERY" and r["component"] == "BUS" and r["to"] == "v"]
            self.assertTrue(tests, cid)
            self.assertTrue(all(("ref.status" in r["bodyKeys"]) is want for r in tests), cid)


class DegenerateCheckTests(unittest.TestCase):
    READS = ["read:w1:1:000001 problem:123456"]

    def gate(self, raw: bytes, bypass: tuple[str, ...] = (), **extra) -> dict:
        sim = make_sim(bypass=bypass, **extra)
        worker = sim.agents["w1"]
        worker.take_claim(0, 1, "w1-c", 1, 8)
        worker.hold["reads"] = list(self.READS)
        worker.merge_gate(7, raw, _sim.digest(raw), "E1")
        return gate_rows(sim, "merge-policy")[-1]

    def test_an_empty_body_or_a_copy_of_the_reads_fails_and_markerpresent_keeps_packet_1s_value(self):
        keys = {"degenerateCheck": True, "tasks": TASKS, "load": {"items": 3, "concurrency": 1}}
        empty, copy = b"item-1|", ("item-1|" + "|".join(self.READS)).encode("utf-8")
        constant = b"item-1|answer:0000000000000000"
        honest = copy + b"|answer:" + _sim.solve("123456").encode("ascii")
        for raw, want in ((empty, "FAIL"), (copy, "FAIL"), (constant, "PASS"), (honest, "PASS")):
            row = self.gate(raw, **keys)
            self.assertEqual((row["answer"], row["markerPresent"]), (want, False), raw)
        self.assertEqual(self.gate(honest + b" POISON-MARKER", **keys)["markerPresent"], True)
        for raw, named in ((empty, "MERGE_GATE"), (copy, "MERGE_GATE"), (honest, None)):
            row = self.gate(raw, ("MERGE_GATE",), **keys)
            self.assertEqual((row["answer"], row["controlBypass"], row["markerPresent"]), ("SKIPPED", named, False))

    def test_without_the_key_packet_1s_gate_is_unchanged(self):
        for raw in (b"item-1|", ("item-1|" + "|".join(self.READS)).encode("utf-8")):
            self.assertEqual(self.gate(raw, tasks=TASKS, load={"items": 3, "concurrency": 1})["answer"], "PASS")
            self.assertEqual(self.gate(raw)["answer"], "PASS")


class EvidenceRuleTests(unittest.TestCase):
    def merge(self, checks, bypass: tuple[str, ...] = (), rule=EVIDENCE_RULE) -> dict:
        extra = {"evidenceRule": rule} if rule else {}
        sim = make_sim(bypass=bypass, **extra)
        op = Ops()
        acq = op("w1", "ACQUIRE", 1, expectedVersion=0)
        apply(sim, 0, acq)
        apply(sim, 1, op("v", "VERIFY", 1, verdict=verdict(acq["opId"], "a", "PASS", 1, checks=checks)))
        return apply(sim, 2, op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))

    def test_deterministic_support_outside_the_consistency_only_list_is_needed(self):
        cases = ((["DETERMINISTIC_TEST/REGRESSION_RUN"], "CONSISTENCY_ONLY"),
                 (["DETERMINISTIC_TEST/REGRESSION_RUN", "MODEL_BASED_WITH_EVIDENCE/DIFF"], "CONSISTENCY_ONLY"),
                 (["DETERMINISTIC_TEST/REGRESSION_RUN", "DETERMINISTIC_TEST/REPRODUCER"], "ACCEPTED"),
                 (["DETERMINISTIC_TEST/TEST_RESULT"], "ACCEPTED"),
                 (["MODEL_BASED_WITH_EVIDENCE/DIFF"], "CONSISTENCY_ONLY"), ([], "CONSISTENCY_ONLY"))
        for checks, want in cases:
            row = self.merge(checks)
            self.assertEqual((row["answer"], row["verdictChecks"], row["controlBypass"]), (want, checks, None), checks)

    def test_evidence_kind_and_merge_verdict_accept_and_are_named(self):
        row = self.merge(["DETERMINISTIC_TEST/REGRESSION_RUN"], ("EVIDENCE_KIND",))
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "EVIDENCE_KIND"))
        row = self.merge(["DETERMINISTIC_TEST/TEST_RESULT"], ("EVIDENCE_KIND",))
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", None))
        row = self.merge(["DETERMINISTIC_TEST/REGRESSION_RUN"], ("MERGE_VERDICT",))
        self.assertEqual((row["answer"], row["controlBypass"]), ("ACCEPTED", "MERGE_VERDICT"))

    def test_without_the_key_the_rule_is_inert(self):
        row = self.merge(["DETERMINISTIC_TEST/REGRESSION_RUN"], rule=None)
        self.assertEqual(row["answer"], "ACCEPTED")
        row = self.merge(None, rule=None)
        self.assertEqual((row["answer"], row["verdictChecks"]), ("ACCEPTED", None))

    def test_the_rule_reads_the_verdict_the_acceptance_rests_on(self):
        for later, want in ((["DETERMINISTIC_TEST/REGRESSION_RUN"], ("CONSISTENCY_ONLY", "WORK_VERDICT")),
                            (["DETERMINISTIC_TEST/TEST_RESULT"], ("ACCEPTED", "WORK_VERDICT"))):
            sim = make_sim(bypass=("WORK_VERDICT",), evidenceRule=EVIDENCE_RULE)
            op = Ops()
            acq = op("w1", "ACQUIRE", 1, expectedVersion=0)
            apply(sim, 0, acq)
            claim = acq["opId"]
            apply(sim, 1, op("v", "VERIFY", 1, verdict=verdict(claim, "a", "FAIL", 1,
                                                              checks=["DETERMINISTIC_TEST/TEST_RESULT"])))
            apply(sim, 1, op("v", "VERIFY", 1, verdict=verdict(claim, "b", "PASS", 2, checks=later)))
            row = apply(sim, 2, op("w1", "MERGE", 1, expectedVersion=1, workDigest="a"))
            self.assertEqual((row["answer"], row["controlBypass"]), want, later)

    def test_c11_carries_the_stated_rule_and_consistency_only_is_engagement(self):
        self.assertEqual(CLASSES["C11"]["evidenceRule"], EVIDENCE_RULE)
        self.assertIn("CONSISTENCY_ONLY", _classes.REFUSALS)
        log = _sim.Log()
        log.add(7, "BOARD_ANSWER", agent="w1", op="MERGE", item=1, opId="m", answer="CONSISTENCY_ONLY", changed=False,
                component="BOARD", scheduledEvent="E1")
        m = _classes.measure(log.rows, CONFIG, CLASSES["C11"])
        self.assertEqual((m["engaged"], m["engagedByEvent"]),
                         ({"BOARD:CONSISTENCY_ONLY": 1}, {"E1": {"BOARD:CONSISTENCY_ONLY": 1}}))


class CounterTests(unittest.TestCase):
    @staticmethod
    def merged(**fields) -> list[dict]:
        log = _sim.Log()
        log.add(0, "BOARD_ANSWER", agent="w1", op="ACQUIRE", item=1, opId="w1-0001", claimOpId="w1-0001",
                answer="ACCEPTED", changed=True, component="BOARD", heldBefore=0)
        log.add(9, "BOARD_ANSWER", agent="w1", op="MERGE", item=1, opId="w1-0009", claimOpId="w1-0001",
                answer="ACCEPTED", changed=True, component="BOARD", verdictStatus="PASS", **fields)
        return log.rows

    def count(self, cid: str, name: str, **fields) -> int:
        return _classes.measure(self.merged(**fields), CONFIG, CLASSES[cid])["counts"][name]

    def test_regression_only_merged(self):
        self.assertEqual(self.count("C11", "regressionOnlyMerged", verdictChecks=["DETERMINISTIC_TEST/REGRESSION_RUN"]),
                         1)
        self.assertEqual(self.count("C11", "regressionOnlyMerged", verdictChecks=[]), 1)
        self.assertEqual(self.count("C11", "regressionOnlyMerged", verdictChecks=["DETERMINISTIC_TEST/TEST_RESULT"]), 0)
        self.assertEqual(self.count("C11", "regressionOnlyMerged"), 0)
        self.assertEqual(self.count("C10", "regressionOnlyMerged", verdictChecks=["DETERMINISTIC_TEST/REGRESSION_RUN"]),
                         0)

    def test_degenerate_merged(self):
        self.assertEqual(self.count("C12", "degenerateMerged", taskPass=False), 1)
        self.assertEqual(self.count("C12", "degenerateMerged", taskPass=True), 0)
        self.assertEqual(self.count("C12", "degenerateMerged"), 0)
        self.assertEqual(self.count("C11", "degenerateMerged", taskPass=False), 0)

    def test_both_default_to_zero_in_every_class(self):
        for cls in CONFIG["classes"] + [CONFIG["hardCoding"]["bed"]] + CONFIG["scaling"]["points"]:
            counts = _classes.measure([], CONFIG, cls)["counts"]
            self.assertEqual((counts["regressionOnlyMerged"], counts["degenerateMerged"]), (0, 0), cls["id"])

    def test_the_null_judged_field_rule(self):
        rows = self.merged(verdictChecks=None, taskPass=None)
        log = _sim.Log()
        log.add(5, "GATE", agent="v", item=1, workDigest="d", answer="FAIL", component="JUDGE", toolId="judge")
        self.assertEqual(_classes.null_judged_fields(rows, CLASSES["C11"]), [(9, "BOARD_ANSWER", "w1", "verdictChecks")])
        self.assertEqual(_classes.null_judged_fields(rows + log.rows, CLASSES["C12"]),
                         [(9, "BOARD_ANSWER", "w1", "taskPass"), (5, "GATE", "v", "taskPass")])
        self.assertEqual(_classes.null_judged_fields(rows + log.rows, CLASSES["C10"]), [])


class ClaimAwareWorkerTests(unittest.TestCase):
    """Section 4.9's four moments on hand-built CENTRAL cases, each against packet 1's worker without the key."""

    @staticmethod
    def setup(aware: bool):
        extra = {"claimAwareWorker": True} if aware else {}
        sim = make_sim(topology="CENTRAL", **extra)
        return sim, Ops(), sim.agents["w1"]

    @staticmethod
    def assign(sim, ops, t: int, item: int) -> str:
        op = ops("c", "ASSIGN", item, to="w1", expectedVersion=sim.board.records[item]["version"])
        assert apply(sim, t, op)["answer"] == "ACCEPTED"
        return op["opId"]

    def replaced(self, aware: bool):
        """w1 took claim x of item 1 at 0; x expired at 8; item 1 was ASSIGNed to w1 again at 9 (claim y)."""
        sim, ops, worker = self.setup(aware)
        x = self.assign(sim, ops, 0, 1)
        worker.take_claim(0, 1, x, 1, 8)
        sim.board.expire(8)
        y = self.assign(sim, ops, 9, 1)
        return sim, worker, x, y

    @staticmethod
    def notice(sim, item: int, claim: str) -> dict:
        rec = sim.board.records[item]
        lease = next(c["leaseUntil"] for c in rec["claims"] if c["claimOpId"] == claim)
        return {"type": "NOTICE", "item": item, "claimOpId": claim, "version": rec["version"], "leaseUntil": lease}

    def test_a_resumed_worker_whose_claim_was_replaced_abandons_it(self):
        for aware in (True, False):
            sim, worker, x, _y = self.replaced(aware)
            worker.stalled_until = 12
            worker.step(12)
            if aware:
                self.assertIsNone(worker.hold)
            else:
                self.assertEqual(worker.hold["claimOpId"], x)  # packet 1: holder membership only

    def test_a_resync_that_finds_a_reassigned_claim_abandons_the_old_hold(self):
        for aware in (True, False):
            sim, worker, x, _y = self.replaced(aware)
            worker.resync(12)
            if aware:
                self.assertIsNone(worker.hold)
            else:
                self.assertEqual((worker.hold["claimOpId"], worker.hold["version"]),
                                 (x, sim.board.records[1]["version"]))

    def test_a_renew_answer_that_finds_a_reassigned_claim_abandons_the_old_hold(self):
        for aware in (True, False):
            sim, worker, x, y = self.replaced(aware)
            renew = worker.new_op(10, "RENEW", 1, expectedVersion=3)
            worker.pending[renew["opId"]] = {"op": renew, "expected": 10, "retried": False}
            worker.handle(10, {"type": "ANSWER", "opId": renew["opId"], "op": "RENEW", "item": 1, "answer": "ACCEPTED",
                               "version": 4, "leaseUntil": 18, "claimOpId": y, "event": None})
            if aware:
                self.assertIsNone(worker.hold)
            else:
                self.assertEqual((worker.hold["claimOpId"], worker.hold["leaseUntil"]), (x, 18))

    def test_a_notice_during_a_hold_is_kept_and_taken_when_the_hold_ends(self):
        for aware in (True, False):
            sim, ops, worker = self.setup(aware)
            a = self.assign(sim, ops, 0, 2)
            worker.take_claim(0, 2, a, 1, 8)
            z = self.assign(sim, ops, 1, 1)
            notice = self.notice(sim, 1, z)
            worker.handle(1, notice)
            self.assertEqual(worker.hold["claimOpId"], a)
            self.assertEqual(worker.kept, [notice] if aware else [])
            worker.abandon()
            if aware:
                worker.take_kept(5)
                self.assertEqual((worker.hold["claimOpId"], worker.kept), (z, []))

    def test_a_kept_notice_whose_claim_expired_is_dropped(self):
        sim, ops, worker = self.setup(True)
        a = self.assign(sim, ops, 0, 2)
        worker.take_claim(0, 2, a, 1, 8)
        z = self.assign(sim, ops, 1, 1)
        worker.handle(1, self.notice(sim, 1, z))
        worker.abandon()
        worker.take_kept(9)  # z's lease ended at 9
        self.assertEqual((worker.hold, worker.kept), (None, []))

    def test_a_notice_that_waited_through_a_stall_is_taken_only_if_its_claim_is_live(self):
        for aware, assigned, want in ((True, 0, None), (True, 6, "live"), (False, 0, "taken")):
            sim, ops, worker = self.setup(aware)
            z = self.assign(sim, ops, assigned, 1)
            worker.inbox.append(self.notice(sim, 1, z))
            worker.stalled_until = 12
            worker.step(12)
            if want is None:
                self.assertIsNone(worker.hold)
            else:
                self.assertEqual(worker.hold["claimOpId"], z, (aware, assigned))

    def test_the_switch_is_set_only_on_the_scaling_and_baseline_points(self):
        spec = CONFIG["scaling"]
        for entry in spec["points"] + spec["baseline"]:
            self.assertIs(entry["claimAwareWorker"], True, entry["id"])
        for cls in CONFIG["classes"] + [CONFIG["hardCoding"]["bed"]]:
            self.assertNotIn("claimAwareWorker", cls, cls["id"])
            sim = _sim.Sim(CONFIG, cls, 1, (), _classes.scenario_for(cls))
            self.assertTrue(all(not getattr(a, "claim_aware", False) for _n, a in sorted(sim.agents.items())), cls["id"])
        point = spec["points"][0]
        sim = _sim.Sim(CONFIG, point, 1, (), _classes.scenario_for(point))
        self.assertTrue(sim.agents["w1"].claim_aware)


class InertnessTests(unittest.TestCase):
    def test_packets_1_to_3_lack_every_new_key(self):
        for cls in CONFIG["classes"][:10]:
            for key in NEW_KEYS:
                self.assertNotIn(key, cls, (cls["id"], key))

    def test_the_new_fields_are_null_in_every_row_of_c1_to_c10(self):
        for cls in CONFIG["classes"][:10]:
            rows, _m = _ledger.run(CONFIG, cls, 1)
            bad = [r for r in rows if r["verdictChecks"] is not None or r["taskPass"] is not None]
            self.assertEqual(bad, [], cls["id"])
        self.assertEqual(_sim.FIELDS[-2:], ("verdictChecks", "taskPass"))
        self.assertEqual(len(_sim.FIELDS), 36)


class ByteIdentityTests(unittest.TestCase):
    def test_packet_3s_rows_and_the_arms_are_byte_identical(self):
        value = _ledger.ledger()
        rows = {r["id"]: r for r in value["classes"]}
        for cid, want in sorted(ROW_SHA256.items()):
            self.assertEqual(canonical(rows[cid]), want, cid)
        self.assertEqual(canonical(value["arms"]), LEDGER_ARMS_SHA256)

    def test_packet_3s_classes_json_entries_are_unchanged(self):
        self.assertEqual(canonical(CONFIG["classes"][7:10]), CLASSES_8_TO_10_SHA256)
        self.assertEqual(canonical(CONFIG["topologies"]["DECENTRALIZED_C9"]), DECENTRALIZED_C9_SHA256)
        self.assertEqual(canonical(CONFIG["arms"]), CLASSES_ARMS_SHA256)
        self.assertEqual(CONFIG["streams"][6], "sched-c8")


class DataFileTests(unittest.TestCase):
    def test_contracts_json_adds_the_eleventh_row(self):
        pins = json.loads((HERE / "contracts.json").read_text())
        self.assertEqual(pins["commit"], PIN)
        self.assertEqual(len(pins["files"]), 11)
        self.assertEqual(pins["files"][10], {
            "packet": "MET-MAS-001", "path": "architecture/verdict-ledger/check-kinds.json",
            "sha256": "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac", "size": 3173})
        self.assertIn("eleventh row, architecture/verdict-ledger/check-kinds.json", pins["note"])

    def test_packet_4_attestation_is_closed_and_pinned(self):
        att = json.loads((HERE / "attestation-p4.json").read_text())
        old = json.loads((HERE / "attestation-p3.json").read_text())
        pins = json.loads((HERE / "contracts.json").read_text())
        self.assertEqual(sorted(att), sorted(old))
        self.assertEqual((att["schemaVersion"], att["packet"]), ("r12.mas-attestation/v1", "CONF-MAS-004"))
        self.assertEqual(att["inputs"], ["<harness-onion>/%s@585364b" % f["path"] for f in pins["files"]])
        self.assertEqual(att["inputDigests"], {"<harness-onion>/%s@585364b" % f["path"]: f["sha256"]
                                               for f in pins["files"]})
        for flag in ("warmSourceRead", "r10SourceRead", "w03WorkInProgressRead",
                     "implementationReadOrRunForExpectedResults"):
            self.assertIs(att[flag], False, flag)
        # B5-4 and B5-5: the monitor rulings in full, and the owner's independence answer beside the W03 flag.
        for phrase in ("MON-P4-DR1-NOTED, MON-P4-D16, MON-P4-DR1-KEEP to MON-P4-DR5-KEEP, Q-P4-D3-1 (a) and Q-P4-CAP (a)",
                       "'Accept as metadata-only (Recommended)'", "round 4 ran 40",
                       "before the packet's final squash"):
            self.assertIn(phrase, att["note"])
        self.assertNotIn("/" + "Users/", att["note"])


class RecordTests(unittest.TestCase):
    def test_the_campaign_record_v2(self):
        rec = _ledger.campaign_record()
        value = _ledger.ledger()
        self.assertEqual((rec["schemaVersion"], rec["campaign"], rec["consumer"]),
                         ("r12.mas-campaign-record/v2", "MAS-RA-010 and MAS-RA-010-F", "CONF-A3-001 (input, HO-D2)"))
        self.assertEqual(rec["packets"][2], {"packetId": "CONF-MAS-003", "commit": None,
                                             "resultsSha256": P3_RESULTS_SHA256})
        self.assertEqual(rec["packets"][3]["commit"], None)
        self.assertEqual([(c["id"], c["packet"]) for c in rec["classes"][10:]],
                         [("C11", "CONF-MAS-004"), ("C12", "CONF-MAS-004")])
        self.assertEqual([f["id"] for f in rec["findings"][-4:]], ["F-C11-1", "F-C12-1", "F-G4-1", "F-G1-1"])
        self.assertEqual(len(rec["findings"]), 14)
        self.assertEqual(len(rec["notClaimed"]), 6)
        self.assertEqual(sorted(rec["scaling"]), ["baseline", "points"])
        self.assertEqual([p["id"] for p in rec["scaling"]["points"]], [p["id"] for p in value["scaling"]["points"]])
        self.assertEqual([b["id"] for b in rec["scaling"]["baseline"]], ["B-5", "B-10", "B-20", "B-40", "B-80"])
        against = {a["point"]: a for a in value["scaling"]["againstBaseline"]}
        for p in rec["scaling"]["points"]:
            self.assertEqual(sorted(p), ["family", "finishedSeeds", "id", "items", "makespanRatioMilli", "p50",
                                         "safety", "underperforms", "workers"])
            # B5-3: the per-point value from the two p50s, recorded as is.
            self.assertEqual(p["makespanRatioMilli"], against[p["id"]]["makespanRatioMilli"])
            self.assertEqual(sorted(p["p50"]), sorted(_ledger.SCALING_READINGS))
        self.assertEqual(rec["hardCoding"], {"gates": value["hardCoding"]["gates"],
                                             "result": value["hardCoding"]["result"]})
        # B5-1: the CENTRAL transient's statement names the three ungated readings it can nudge.
        g1 = next(f["summary"] for f in rec["findings"] if f["id"] == "F-G1-1")
        self.assertIn("three ungated readings (contention, messages, makespan)", g1)


if __name__ == "__main__":
    unittest.main()
