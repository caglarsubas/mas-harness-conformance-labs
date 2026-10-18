"""TG-01 contract tests (W04-2, CONF-ENF-002; jsonschema replays CONF-ENF-009): every adopted contract's vectors
through its snapshotted reference model.

The run must reproduce tg01_contract/results.json exactly: each vector PASS when it was replayed and passed in this run,
never PASS for a vector that was not run (AGENTS rule 14). The nine sets whose models need jsonschema run in a child
process on the pinned met-001 venv python (owner decisions Q-LC-1..4, 2026-10-18; _child.py); R12's own interpreter stays
standard library only, and a missing or changed child interpreter or jsonschema fails here instead of recording
NOT_RUN_ENV_UNAVAILABLE. A model or vector that disagrees fails here.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

import _models
from tg01_contract import _child, _replays

HERE = Path(__file__).resolve().parent
RESULTS = {"PASS", "FAIL", "WARN", "NOT_APPLICABLE", "NOT_RUN_ENV_UNAVAILABLE"}
ROW_FIELDS = {"contract", "vectorSet", "cases", "vectors", "results", "notRunIds", "reason", "runner"}
RUNNERS = {"IN_PROCESS", "CHILD_MET_001"}
SELECTION_FIELDS = {"case", "contract", "vectorSet", "basis", "ids"}
CASE_FIELDS = {"case", "contract", "vectors", "results", "result"}
PLAN = "architecture/enforcement-test-plan/traceability.json"
# The W01 base W02D amends: the plan's own sources pin, restated here so a changed snapshot cannot move it (Q-T7).
W01_BASE_SHA256 = "8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4"


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def tg01():
    return next(group for group in _models.data(PLAN)["testGroups"] if group["id"] == "TG-01")


def rows_for(contract):
    return [row for row in ledger()["rows"] if row["contract"] == contract]


def offline_cases():
    return [case["tag"] for case in tg01()["cases"] if case["phase"] == "W04_OFFLINE"]


# Review R1-7: each vector set's size from the pinned vector data itself, not from the replays that wrote the ledger.
VECTOR_DATA = {"SELinux matrix v4": _replays.SEL, "Seccomp allowlists v2": _replays.SEC, "Admission semantics v3": _replays.ADM,
               "I05 gate channel v3": _replays.I05, "I07 policy write v3": _replays.I07, "I06 backend profile v2": _replays.I06,
               "Native qualification profile v3": _replays.NAT}
SET_SIZES = {
    # One check per role and architecture program.
    ("Seccomp allowlists v2", "programs"): lambda v: sum(len(arches) for arches in v["filterDigests"].values()),
    # The rendering, the sealed objects and the pinned directory hash, then each positive manifest.
    ("Admission semantics v3", "sealed"): lambda v: 3 + len(v["positives"]),
    ("I06 backend profile v2", "vectors"): lambda v: sum(len(v[key]) for key in ("evidenceAccepted", "snapshotAccepted", "evidenceNegative",
                                                                                   "snapshotNegative", "crossVersion")),
    ("Native qualification profile v3", "vectors"): lambda v: len(v["positive"]) + sum(len(v[key]) for key in ("negative", "accepted",
                                                                                                                "crossVersion", "migration")),
}


# Reviews R2-3/R3-1: vectors each mixed-set case must keep, whatever its rule becomes (from the vectors' intents and
# reviews R1-R3).
ANCHORS = {
    ("MATRIX:wrong peer", "I05 gate channel v3", "transcripts"): {"T14", "T26", "T41", "T60", "T89", "T93"},
    ("MATRIX:wrong peer", "I07 policy write v3", "transcripts"): {"T19", "T20", "T42", "T46", "T50", "T57"},
    ("MATRIX:role/version mismatch", "I05 gate channel v3", "configRefusals"): {"K04"},
    ("MATRIX:role/version mismatch", "I05 gate channel v3", "frames"): {"G10", "G32", "G34"},
    ("MATRIX:role/version mismatch", "I05 gate channel v3", "transcripts"): {"T19", "T63"},
    ("MATRIX:role/version mismatch", "I07 policy write v3", "frames"): {"G38", "G48"},
    ("MATRIX:role/version mismatch", "I07 policy write v3", "transcripts"): {"T23", "T45"},
    ("MATRIX:role/version mismatch", "I06 backend profile v2", "vectors"): {"G03", "G17", "X01", "X02", "X03", "X04"},
    ("MATRIX:role/version mismatch", "Native qualification profile v3", "vectors"): {"R01", "R02", "R03", "R07", "R75", "C13", "C31",
                                                                                     "V29", "X01", "X14"},
    ("CE23", "I07 policy write v3", "transcripts"): {"T08"},
}


# Review R3-4: the vectors mapped to each case and contract, so a narrower CASE_TAGS or rule fails here too, not only
# through the ledger the same code wrote. A change to the mapping changes this table, in the same reviewed diff.
CASE_VECTORS = {
    ("MATRIX:exact fields", "SELinux matrix v4"): 55,
    ("MATRIX:exact fields", "Seccomp allowlists v2"): 15,
    ("MATRIX:exact fields", "Admission semantics v3"): 123,
    ("MATRIX:exact fields", "I05 gate channel v3"): 95,
    ("MATRIX:exact fields", "I07 policy write v3"): 165,
    ("MATRIX:exact fields", "Native qualification profile v3"): 248,
    ("MATRIX:duplicate/unknown keys", "I05 gate channel v3"): 48,
    ("MATRIX:duplicate/unknown keys", "I07 policy write v3"): 57,
    ("MATRIX:role/version mismatch", "I05 gate channel v3"): 6,
    ("MATRIX:role/version mismatch", "I07 policy write v3"): 4,
    ("MATRIX:role/version mismatch", "I06 backend profile v2"): 8,
    ("MATRIX:role/version mismatch", "Native qualification profile v3"): 36,
    ("MATRIX:transcript replay", "I05 gate channel v3"): 126,
    ("MATRIX:transcript replay", "I07 policy write v3"): 62,
    ("MATRIX:wrong peer", "I05 gate channel v3"): 7,
    ("MATRIX:wrong peer", "I07 policy write v3"): 6,
    ("CE23", "I07 policy write v3"): 80,
    ("CONTRACT-DATA", "SELinux matrix v4"): 1928,
    ("CONTRACT-DATA", "Seccomp allowlists v2"): 3195,
    ("CONTRACT-DATA", "W01 amendment W02D"): 1,
    ("CONTRACT-DATA", "I06 backend profile v2"): 147,
}


def derived_case_results(value):
    """Review R1-1: a case is PASS for a contract only when every vector mapped to it ran and passed."""
    by_key = {(row["contract"], row["vectorSet"]): row for row in value["rows"]}
    results = []
    for case in offline_cases():
        for contract in dict.fromkeys(row["contract"] for row in value["rows"]):
            vectors = passed = 0
            for row in value["rows"]:
                if row["contract"] == contract and case in row["cases"]:
                    vectors, passed = vectors + row["vectors"], passed + row["results"]["PASS"]
            for selection in value["selections"]:
                if (selection["case"], selection["contract"]) == (case, contract):
                    not_run = set(by_key[contract, selection["vectorSet"]]["notRunIds"])
                    vectors += len(selection["ids"])
                    passed += sum(1 for ident in selection["ids"] if ident not in not_run)
            if vectors:
                results.append({"case": case, "contract": contract, "vectors": vectors,
                                "results": {"PASS": passed, "NOT_RUN_ENV_UNAVAILABLE": vectors - passed},
                                "result": "PASS" if passed == vectors else "NOT_RUN_ENV_UNAVAILABLE"})
    return results


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_closed_and_names_every_replay(self):
        value = ledger()
        self.assertEqual(set(value), {"schemaVersion", "packet", "testGroup", "profile", "rule", "rows", "selections", "caseResults",
                                      "deferred"})
        self.assertEqual((value["schemaVersion"], value["packet"], value["testGroup"]),
                         ("r12.enforcement-tg01-results/v1", "CONF-ENF-009", "TG-01"))
        keys = [(row["contract"], row["vectorSet"]) for row in value["rows"]]
        self.assertEqual(keys, list(_replays.REPLAYS))
        for row in value["rows"]:
            with self.subTest(row=(row["contract"], row["vectorSet"])):
                self.assertEqual(set(row), ROW_FIELDS)
                self.assertLessEqual(set(row["results"]), RESULTS)
                self.assertEqual(sum(row["results"].values()), row["vectors"])
                self.assertEqual(len(row["notRunIds"]), row["results"]["NOT_RUN_ENV_UNAVAILABLE"])
                self.assertEqual(row["reason"] is None, not row["notRunIds"])
                self.assertIn(row["runner"], RUNNERS)
        # CONF-ENF-009: exactly the nine jsonschema sets run in the child, and none of them may record a vector not run.
        child = [(row["contract"], row["vectorSet"]) for row in value["rows"] if row["runner"] == "CHILD_MET_001"]
        self.assertEqual(child, list(_replays.CHILD_SETS))
        for row in value["rows"]:
            if row["runner"] == "CHILD_MET_001":
                self.assertEqual((row["results"]["PASS"], row["notRunIds"], row["reason"]), (row["vectors"], [], None))

    def test_every_offline_tg01_case_and_contract_is_covered_and_codec_is_deferred(self):
        group, value = tg01(), ledger()
        offline = set(offline_cases())
        covered = {case for row in value["rows"] for case in row["cases"]} | {row["case"] for row in value["selections"]}
        self.assertEqual(covered, offline)
        self.assertEqual({row["case"] for row in value["caseResults"]}, offline)
        self.assertEqual({row["contract"] for row in value["rows"]}, set(group["contracts"]))
        later = [case["tag"] for case in group["cases"] if case["phase"] != "W04_OFFLINE"]
        self.assertEqual([row["case"] for row in value["deferred"]], later)
        self.assertTrue(all(row["result"] == "NOT_RUN_ENV_UNAVAILABLE" for row in value["deferred"]))

    def test_case_results_follow_from_the_rows_and_selections_and_never_overstate(self):
        value = ledger()
        self.assertEqual(value["caseResults"], derived_case_results(value))
        self.assertEqual({(row["case"], row["contract"]): row["vectors"] for row in value["caseResults"]}, CASE_VECTORS)
        for row in value["caseResults"]:
            with self.subTest(case=row["case"], contract=row["contract"]):
                self.assertEqual(set(row), CASE_FIELDS)
                self.assertEqual(row["result"] == "PASS", row["results"]["NOT_RUN_ENV_UNAVAILABLE"] == 0)

    def test_the_ledger_records_the_area_codes_case_mapping(self):
        # Review R2-3: whole-set tags and selections come from _replays (CASE_TAGS, SELECTORS) over the pinned vectors,
        # so a regenerated ledger cannot narrow a case by data alone.
        value = ledger()
        self.assertEqual({(row["contract"], row["vectorSet"]): row["cases"] for row in value["rows"]}, _replays.CASE_TAGS)
        self.assertEqual(value["selections"], _replays.selections())
        selected = {(row["case"], row["contract"], row["vectorSet"]): set(row["ids"]) for row in value["selections"]}
        self.assertEqual(set(selected), set(ANCHORS))
        for key, anchors in ANCHORS.items():
            with self.subTest(selection=key):
                self.assertLessEqual(anchors, selected[key])

    def test_every_selection_names_real_vectors_of_its_set(self):
        value = ledger()
        by_key = {(row["contract"], row["vectorSet"]): row for row in value["rows"]}
        for selection in value["selections"]:
            key = (selection["contract"], selection["vectorSet"])
            with self.subTest(case=selection["case"], set=key):
                self.assertEqual(set(selection), SELECTION_FIELDS)
                self.assertIn(selection["case"], offline_cases())
                self.assertNotIn(selection["case"], by_key[key]["cases"])
                self.assertTrue(type(selection["basis"]) is str and selection["basis"])
                self.assertTrue(selection["ids"] and len(set(selection["ids"])) == len(selection["ids"]))
                tally = _replays.REPLAYS[key]()
                self.assertLessEqual(set(selection["ids"]), set(tally.ids["PASS"]) | set(tally.ids["NOT_RUN_ENV_UNAVAILABLE"]))

    def test_each_vector_count_is_the_pinned_vector_sets_size(self):
        for row in ledger()["rows"]:
            key = (row["contract"], row["vectorSet"])
            with self.subTest(set=key):
                if row["contract"] == "W01 amendment W02D":
                    self.assertEqual(row["vectors"], 1)
                    continue
                if key == ("I05 gate channel v3", "supplement"):
                    self.assertEqual(row["vectors"], len(_models.data(_replays.I05_SUPPLEMENT + "vectors.json")["transcripts"]))
                    continue
                vectors = _models.data(VECTOR_DATA[row["contract"]] + "vectors.json")
                self.assertEqual(row["vectors"], SET_SIZES[key](vectors) if key in SET_SIZES else len(vectors[row["vectorSet"]]))

    def test_jsonschema_stays_out_of_r12s_interpreter(self):
        # Q-T1, Q-T4 and Q-LC-2: R12's own interpreter stays standard library only; jsonschema runs only in the child.
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
        # Some kind checks carry "object": null; only an object that is a mapping can name a kind.
        pods = [row for row in vectors["kindChecks"]
                if type(row["payload"].get("object")) is dict and row["payload"]["object"].get("kind") == "Pod"]
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

    def test_only_a_missing_jsonschema_is_not_run(self):
        # Review R1-6: Q-T4's guard. Any other import failure or any mismatch propagates and is never counted.
        def failing(exc):
            def check():
                raise exc
            return check
        for exc in (ModuleNotFoundError("other", name="other"), ModuleNotFoundError("sub", name="jsonschema.validators"),
                    ImportError("unnamed"), _replays.Mismatch("wrong")):
            with self.subTest(exc=repr(exc)):
                tally = _replays.Tally()
                with self.assertRaises(type(exc)):
                    tally.run("x", failing(exc))
                with self.assertRaises(type(exc)):
                    tally.whole(["y", "z"], failing(exc))
                self.assertEqual(tally.ids, {"PASS": [], "NOT_RUN_ENV_UNAVAILABLE": []})
        tally = _replays.Tally()
        tally.run("x", failing(ModuleNotFoundError("jsonschema", name="jsonschema")))
        tally.whole(["y", "z"], failing(ModuleNotFoundError("jsonschema", name="jsonschema")))
        tally.run("p", lambda: None)
        self.assertEqual(tally.ids, {"PASS": ["p"], "NOT_RUN_ENV_UNAVAILABLE": ["x", "y", "z"]})

    def test_a_sibling_name_held_by_an_outside_module_is_refused(self):
        # Review R1-2: I07 v3 imports I05 v3 by name; a replaced sys.modules entry must not reach it.
        pinned = _models.model("i05_gate_channel_v3")
        loaded = _models._LOADED.pop("i07_policy_write_v3", None)
        held = sys.modules.pop("i07_policy_write_v3", None)
        sys.modules["i05_gate_channel_v3"] = types.ModuleType("i05_gate_channel_v3")
        try:
            with self.assertRaisesRegex(ValueError, "outside module holds the sibling name i05_gate_channel_v3"):
                _models.model("i07_policy_write_v3")
            self.assertNotIn("i07_policy_write_v3", _models._LOADED)
        finally:
            sys.modules["i05_gate_channel_v3"] = pinned
            if loaded is not None:
                _models._LOADED["i07_policy_write_v3"] = loaded
            if held is not None:
                sys.modules["i07_policy_write_v3"] = held

    def test_a_flipped_expectation_is_caught(self):
        original = _models.data
        cases = (("SELinux matrix v4", "accessChecks", _replays.SEL, lambda v: v["accessChecks"][0].update(expect=not v["accessChecks"][0]["expect"])),
                 ("Seccomp allowlists v2", "policyMutations", _replays.SEC, lambda v: v["policyMutations"][0].update(expect="accepted")),
                 ("Admission semantics v3", "claims", _replays.ADM, lambda v: v["claims"][0].update(expect="X")),
                 ("I05 gate channel v3", "agreement", _replays.I05, lambda v: v["agreement"][0].update(expect="X")),
                 ("I07 policy write v3", "kindChecks", _replays.I07, lambda v: v["kindChecks"][0].update(expect="OBJECT_RULE")),
                 # Q-T10: S01 must equal S02 outside the injections; the check runs before the model needs jsonschema.
                 ("I05 gate channel v3", "supplement", _replays.I05_SUPPLEMENT, lambda v: v["transcripts"][0]["final"].update(state="X")),
                 # Review R1-10: the supplement must name the pinned v3 vectors and model, and reference the v3 configuration.
                 ("I05 gate channel v3", "supplement", _replays.I05_SUPPLEMENT, lambda v: v["contract"]["model"].update(sha256="0" * 64)),
                 ("I05 gate channel v3", "supplement", _replays.I05_SUPPLEMENT, lambda v: v["configs"]["ACTIVE"].update(key=["configs", "LATER"])))
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


class ChildTests(unittest.TestCase):
    """CONF-ENF-009 (owner decisions Q-LC-1..4): the child process, its pins and the parent's closed checks."""

    def good_report(self):
        pin = _child.pins()
        names = ["|".join(key) for key in _replays.CHILD_SETS]
        return {"interpreter": {"versionInfo": pin["versionInfo"], "prefix": pin["prefix"], "basePrefix": pin["basePrefix"],
                                "isolated": 1, "dontWriteBytecode": True},
                "jsonschema": pin["jsonschema"],
                "tallies": {name: {"PASS": _replays.expected_ids(key), "NOT_RUN_ENV_UNAVAILABLE": []}
                            for name, key in zip(names, _replays.CHILD_SETS)},
                "flips": {name: {"id": _replays.FLIPS[key][2], "field": _replays.FLIPS[key][3], "caught": True}
                          for name, key in zip(names, _replays.CHILD_SETS)}}

    def test_the_child_ran_every_child_set_with_its_pinned_results(self):
        tallies = _child.run()
        self.assertEqual(list(tallies), ["|".join(key) for key in _replays.CHILD_SETS])
        for key in _replays.CHILD_SETS:
            with self.subTest(set=key):
                self.assertEqual(tallies["|".join(key)], {"PASS": _replays.expected_ids(key), "NOT_RUN_ENV_UNAVAILABLE": []})

    def test_the_pin_row_is_the_installed_met_001_venv(self):
        pin = _child.pins()
        self.assertEqual((pin["state"], pin["decidedBy"], pin["path"], pin["arguments"]),
                         ("IN_USE", "Q-LC-2", "/opt/planeon/toolchains/met-001/.venv/bin/python3", ["-I", "-B"]))
        self.assertEqual((pin["prefix"], pin["basePrefix"], pin["realpathRoot"], pin["jsonschema"], pin["versionInfo"]),
                         ("/opt/planeon/toolchains/met-001/.venv", "/opt/planeon/python/3.12.14", "/opt/planeon/python/3.12.14",
                          "4.24.0", [3, 12, 14, "final", 0]))
        self.assertEqual(_child.tree_digest(pin["prefix"]), pin["venvTreeSha256"])

    def test_a_report_that_differs_from_the_pins_is_refused(self):
        good = self.good_report()
        pin = _child.pins()
        self.assertEqual(list(_child.check_report(copy.deepcopy(good), pin)), list(good["tallies"]))
        first, last = "|".join(_replays.CHILD_SETS[0]), "|".join(_replays.CHILD_SETS[-1])

        def changed(change):
            value = copy.deepcopy(good)
            change(value)
            return value
        forged = {
            "extra key": lambda v: v.update(extra=1),
            "key order": lambda v: v.update({"jsonschema": v.pop("jsonschema")}),
            "version": lambda v: v["interpreter"].update(versionInfo=[3, 12, 13, "final", 0]),
            "prefix": lambda v: v["interpreter"].update(prefix="/opt/planeon/toolchains/other/.venv"),
            "not isolated": lambda v: v["interpreter"].update(isolated=0),
            "bytecode": lambda v: v["interpreter"].update(dontWriteBytecode=False),
            "jsonschema": lambda v: v.update(jsonschema="4.23.0"),
            "missing set": lambda v: v["tallies"].pop(last),
            "set order": lambda v: v.update(tallies=dict(reversed(list(v["tallies"].items())))),
            "not run": lambda v: v["tallies"][first].update(NOT_RUN_ENV_UNAVAILABLE=[v["tallies"][first]["PASS"].pop()]),
            "dropped id": lambda v: v["tallies"][last]["PASS"].pop(),
            "reordered ids": lambda v: v["tallies"][last]["PASS"].reverse(),
            "flip not caught": lambda v: v["flips"][first].update(caught=False),
            "flip on another vector": lambda v: v["flips"][last].update(id="R03"),
            "flip on another field": lambda v: v["flips"][first].update(field="frame"),
        }
        for name, change in forged.items():
            with self.subTest(forged=name):
                with self.assertRaises(_child.ChildError):
                    _child.check_report(changed(change), pin)

    def test_a_changed_venv_tree_or_a_missing_interpreter_fails_closed(self):
        pin = _child.pins()
        cases = {"tree": dict(pin, venvTreeSha256="0" * 64), "path": dict(pin, path="/opt/planeon/toolchains/met-001/.venv/bin/none"),
                 "root": dict(pin, realpathRoot="/opt/planeon/python/3.12.13")}
        original = _child.pins
        for name, value in cases.items():
            with self.subTest(case=name):
                _child.pins = lambda value=value: value
                try:
                    with self.assertRaises(_child.ChildError):
                        _child._launch()
                finally:
                    _child.pins = original

    def test_a_failed_launch_is_cached_and_raised_again(self):
        saved, launch, calls = dict(_child._OUTCOME), _child._launch, []

        def failing():
            calls.append(1)
            raise _child.ChildError("forged launch failure")
        _child._OUTCOME.clear()
        _child._launch = failing
        try:
            for _ in range(3):
                with self.assertRaises(_child.ChildError):
                    _child.run()
            self.assertEqual(len(calls), 1)
        finally:
            _child._launch = launch
            _child._OUTCOME.clear()
            _child._OUTCOME.update(saved)

    def test_the_tree_digest_sees_files_links_modes_and_pth_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "lib").mkdir()
            (root / "lib/module.py").write_bytes(b"x = 1\n")
            before = _child.tree_digest(folder)
            self.assertEqual(_child.tree_digest(folder), before)
            for change in (lambda: (root / "lib/module.py").write_bytes(b"x = 2\n"),
                           lambda: (root / "lib/module.py").chmod(0o755),
                           lambda: (root / "lib/_virtualenv.pth").write_bytes(b"import os\n"),
                           lambda: os.symlink("lib/module.py", root / "link")):
                change()
                after = _child.tree_digest(folder)
                self.assertNotEqual(after, before)
                before = after

    def test_the_flips_are_the_pinned_targets_past_the_jsonschema_call(self):
        self.assertEqual({key: (target[1], target[2], target[3]) for key, target in _replays.FLIPS.items()}, {
            ("I05 gate channel v3", "frames"): ("frames", "G01", "expect"),
            ("I05 gate channel v3", "byteFrames"): ("byteFrames", "B01", "expect"),
            ("I05 gate channel v3", "transcripts"): ("transcripts", "T01", "final"),
            ("I05 gate channel v3", "supplement"): ("transcripts", "S05", "final"),
            ("I07 policy write v3", "frames"): ("frames", "G01", "expect"),
            ("I07 policy write v3", "byteFrames"): ("byteFrames", "B01", "expect"),
            ("I07 policy write v3", "transcripts"): ("transcripts", "T01", "final"),
            ("I06 backend profile v2", "vectors"): ("evidenceNegative", "E01", "refusal"),
            ("Native qualification profile v3", "vectors"): ("negative", "R02", "refusal")})
        for key, (path, list_key, ident, field) in _replays.FLIPS.items():
            with self.subTest(set=key):
                rows = [row for row in _models.data(path)[list_key] if row["id"] == ident]
                self.assertEqual(len(rows), 1)
                self.assertIn(field, rows[0])
                self.assertIn(ident, _replays.expected_ids(key))
        # The supplement's target is linked by `equals` in neither direction, so only the model replay can catch it.
        transcripts = _models.data(_replays.I05_SUPPLEMENT + "vectors.json")["transcripts"]
        self.assertFalse([row["id"] for row in transcripts if row["id"] == "S05" and "equals" in row or row.get("equals") == "S05"])

    def test_the_child_sets_keep_their_standard_library_pre_checks_in_this_interpreter(self):
        original = _models.data

        def forged(path):
            value = original(path)
            if path == _replays.I05 + "vectors.json":
                value["byteFrames"].reverse()
            return value
        _models.data = forged
        try:
            with self.assertRaises(_replays.Mismatch):
                _replays.REPLAYS["I05 gate channel v3", "byteFrames"]()
        finally:
            _models.data = original


if __name__ == "__main__":
    unittest.main()
