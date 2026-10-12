"""TG-01 contract tests (W04-2, CONF-ENF-002): every adopted contract's vectors through its snapshotted reference model.

The run must reproduce tg01_contract/results.json exactly: each vector PASS, or NOT_RUN_ENV_UNAVAILABLE when its replay
needs jsonschema (owner decision Q-T4, 2026-10-11), never PASS for a vector that was not run. A model or vector that
disagrees fails here; an environment that gains jsonschema also fails here, so the ledger is redone, never stale.
"""
from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path

import _models
from tg01_contract import _replays

HERE = Path(__file__).resolve().parent
RESULTS = {"PASS", "FAIL", "WARN", "NOT_APPLICABLE", "NOT_RUN_ENV_UNAVAILABLE"}
ROW_FIELDS = {"contract", "vectorSet", "cases", "vectors", "results", "notRunIds", "reason"}
PLAN = "architecture/enforcement-test-plan/traceability.json"
# The W01 base W02D amends: the plan's own sources pin, restated here so a changed snapshot cannot move it (Q-T7).
W01_BASE_SHA256 = "8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4"


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
        self.assertEqual({row["contract"] for row in value["rows"]}, set(group["contracts"]))
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

    def test_w01_amendment_w02d(self):
        self.replay("W01 amendment W02D")

    def test_the_w02d_base_is_the_plans_sources_pin(self):
        # Q-T7: the snapshotted W01 base is the plan's sources pin, the model's BASE_SHA256 and the amendment's own pin.
        model = _models.model("host_interface_amendment")
        pins = [row["sha256"] for row in _models.data(PLAN)["sources"] if row["path"] == model.BASE_PATH]
        self.assertEqual(pins, [W01_BASE_SHA256])
        self.assertEqual(hashlib.sha256(_models.snapshot_bytes(model.BASE_PATH)).hexdigest(), W01_BASE_SHA256)
        self.assertEqual(model.BASE_SHA256, W01_BASE_SHA256)
        self.assertEqual(_models.data(model.RECORD_PATH)["base"], {"path": model.BASE_PATH, "sha256": W01_BASE_SHA256})
        self.assertEqual(model.CARRIED_PATH, "architecture/seccomp-allowlists/status.json")

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

    def test_a_changed_w02d_input_is_caught(self):
        model, original = _models.model("host_interface_amendment"), _models.snapshot_bytes
        changes = {model.BASE_PATH: (b"seccomp", b"seccomP"), model.EFFECTIVE_PATH: (b"seccomp", b"seccomP"),
                   model.CARRIED_PATH: (b"W4 does not name setgroups", b"W4 does not name setgroupz"),
                   model.RECORD_PATH: (b"2ac2751cbddd", b"2ac2751cbdde")}
        for path, (old, new) in changes.items():
            def forged(relative, path=path, old=old, new=new):
                raw = original(relative)
                if relative != path:
                    return raw
                assert old in raw, old
                return raw.replace(old, new, 1)
            with self.subTest(path=path):
                _models.snapshot_bytes = forged
                try:
                    with self.assertRaises(_replays.Mismatch):
                        _replays.w02d_amendment()
                finally:
                    _models.snapshot_bytes = original


if __name__ == "__main__":
    unittest.main()
