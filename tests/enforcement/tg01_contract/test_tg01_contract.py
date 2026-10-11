"""TG-01 contract tests (W04-2, CONF-ENF-002): every adopted contract's vectors through its snapshotted reference model.

The run must reproduce tg01_contract/results.json exactly: each vector PASS, or NOT_RUN_ENV_UNAVAILABLE when its replay
needs jsonschema (owner decision Q-T4, 2026-10-11), never PASS for a vector that was not run. A model or vector that
disagrees fails here; an environment that gains jsonschema also fails here, so the ledger is redone, never stale.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import _models
from tg01_contract import _replays

HERE = Path(__file__).resolve().parent
RESULTS = {"PASS", "FAIL", "WARN", "NOT_APPLICABLE", "NOT_RUN_ENV_UNAVAILABLE"}
ROW_FIELDS = {"contract", "vectorSet", "cases", "vectors", "results", "notRunIds", "reason"}
PLAN = "architecture/enforcement-test-plan/traceability.json"


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def tg01():
    return next(group for group in _models.data(PLAN)["testGroups"] if group["id"] == "TG-01")


def rows_for(contract):
    return [row for row in ledger()["rows"] if row["contract"] == contract]


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_closed_and_names_every_replay(self):
        value = ledger()
        self.assertEqual(set(value), {"schemaVersion", "packet", "testGroup", "profile", "rule", "rows", "deferred"})
        self.assertEqual((value["schemaVersion"], value["packet"], value["testGroup"]),
                         ("r12.enforcement-tg01-results/v1", "CONF-ENF-002", "TG-01"))
        keys = [(row["contract"], row["vectorSet"]) for row in value["rows"]]
        self.assertEqual(keys, list(_replays.REPLAYS))
        for row in value["rows"]:
            with self.subTest(row=(row["contract"], row["vectorSet"])):
                self.assertEqual(set(row), ROW_FIELDS)
                self.assertLessEqual(set(row["results"]), RESULTS)
                self.assertEqual(sum(row["results"].values()), row["vectors"])
                self.assertEqual(len(row["notRunIds"]), row["results"]["NOT_RUN_ENV_UNAVAILABLE"])
                self.assertEqual(row["reason"] is None, not row["notRunIds"])

    def test_every_offline_tg01_case_and_contract_is_covered_and_codec_is_deferred(self):
        group, value = tg01(), ledger()
        offline = {case["tag"] for case in group["cases"] if case["phase"] == "W04_OFFLINE"}
        covered = {case for row in value["rows"] for case in row["cases"]}
        self.assertEqual(covered, offline)
        self.assertLessEqual({row["contract"] for row in value["rows"]}, set(group["contracts"]))
        later = [case["tag"] for case in group["cases"] if case["phase"] != "W04_OFFLINE"]
        self.assertEqual([row["case"] for row in value["deferred"]], later)
        self.assertTrue(all(row["result"] == "NOT_RUN_ENV_UNAVAILABLE" for row in value["deferred"]))

    def test_the_jsonschema_gap_is_real_in_this_environment(self):
        # Q-T4: a NOT_RUN_ENV_UNAVAILABLE row is only true while the profile lacks jsonschema.
        self.assertIsNone(importlib.util.find_spec("jsonschema"))


class ReplayTests(unittest.TestCase):
    """One method per contract; each vector set must reproduce its ledger row exactly."""

    def replay(self, contract):
        rows = rows_for(contract)
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(vectorSet=row["vectorSet"]):
                tally = _replays.REPLAYS[contract, row["vectorSet"]]()
                passed, not_run = tally.ids["PASS"], tally.ids["NOT_RUN_ENV_UNAVAILABLE"]
                self.assertEqual(len(passed) + len(not_run), row["vectors"])
                self.assertEqual(len(set(passed) | set(not_run)), row["vectors"])
                self.assertEqual(not_run, row["notRunIds"])
                self.assertEqual({"PASS": len(passed), "NOT_RUN_ENV_UNAVAILABLE": len(not_run)}, row["results"])

    def test_selinux_matrix_v4(self):
        self.replay("SELinux matrix v4")

    def test_seccomp_allowlists_v2(self):
        self.replay("Seccomp allowlists v2")

    def test_admission_semantics_v3(self):
        self.replay("Admission semantics v3")

    def test_i05_gate_channel_v3(self):
        self.replay("I05 gate channel v3")

    def test_i07_policy_write_v3_and_ce23(self):
        self.replay("I07 policy write v3")
        kinds = _models.data(_replays.I07 + "policy-kinds.json")
        model = _models.model("i07_policy_write_v3")
        vectors = _models.data(_replays.I07 + "vectors.json")
        # CE23: a WRITE_OBJECT carrying a Pod, or a kind outside the table, is refused.
        pods = [row for row in vectors["kindChecks"] if row["payload"].get("object", {}).get("kind") == "Pod"]
        unknown = [row for row in vectors["kindChecks"] if row["expect"] == "KIND_OUTSIDE_TABLE"]
        self.assertTrue(pods and unknown)
        self.assertEqual({row["expect"] for row in pods}, {"EFFECT_KIND"})
        for row in pods + unknown:
            with self.subTest(ce23=row["id"]):
                self.assertEqual(model.check_write(kinds, _replays.I07_NAMESPACE, row["payload"]), row["expect"])

    def test_i06_backend_profile_v2(self):
        self.replay("I06 backend profile v2")

    def test_native_qualification_profile_v3(self):
        self.replay("Native qualification profile v3")


class FidelityTests(unittest.TestCase):
    """A replay that cannot tell a wrong expectation from a right one proves nothing."""

    def test_a_flipped_expectation_is_caught(self):
        original = _models.data
        cases = (("SELinux matrix v4", "accessChecks", _replays.SEL, lambda v: v["accessChecks"][0].update(expect=not v["accessChecks"][0]["expect"])),
                 ("Seccomp allowlists v2", "policyMutations", _replays.SEC, lambda v: v["policyMutations"][0].update(expect="accepted")),
                 ("Admission semantics v3", "claims", _replays.ADM, lambda v: v["claims"][0].update(expect="X")),
                 ("I05 gate channel v3", "agreement", _replays.I05, lambda v: v["agreement"][0].update(expect="X")),
                 ("I07 policy write v3", "kindChecks", _replays.I07, lambda v: v["kindChecks"][0].update(expect="OBJECT_RULE")))
        for contract, vector_set, prefix, change in cases:
            def forged(path, prefix=prefix, change=change):
                value = original(path)
                if path == prefix + "vectors.json":
                    change(value)
                return value
            with self.subTest(contract=contract):
                _replays._SECCOMP.clear()
                _models.data = forged
                try:
                    with self.assertRaises(_replays.Mismatch):
                        _replays.REPLAYS[contract, vector_set]()
                finally:
                    _models.data = original
                    _replays._SECCOMP.clear()


if __name__ == "__main__":
    unittest.main()
