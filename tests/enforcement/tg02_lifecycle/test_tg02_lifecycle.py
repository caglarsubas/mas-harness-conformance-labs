"""TG-02 lifecycle (W04-3, CONF-ENF-003): the case ledger, the catalog of the gated cases and LEDGER-E09's properties.

tg02_lifecycle/results.json must equal what _catalog.ledger gives: the plan's TG-02 cases in order; LEDGER-E09 with the
property table of its reader guard tests (owner decision Q-T9), PASS when every property within its own scope ran, the
Linux-only properties being carried by named W06 native cases (owner decision Q-T11); every other case
NOT_RUN_ENV_UNAVAILABLE with the contract vectors that specify it (owner decision Q-T8, 2026-10-13). The anchors and the
exact selection pins (size and digest of the id list) are a second pin, so neither a regenerated ledger nor a changed
rule can narrow, widen or swap a case's vectors unseen; a deliberate change updates them in the same reviewed diff.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

import _catalog
import _models
from tg02_lifecycle import test_reader_guards

HERE = Path(__file__).resolve().parent
GROUP = "TG-02"
# Vectors each selection must keep (from the vectors' own intents, refusals and reviews R1).
ANCHORS = {
    ("MATRIX:unarmed/duplicate/cross-case action", "I05 gate channel v3", "transcripts"): {"T07", "T12", "T48", "T76"},
    ("MATRIX:unarmed/duplicate/cross-case action", "I07 policy write v3", "transcripts"): {"T20", "T26", "T32"},
    ("MATRIX:unarmed/duplicate/cross-case action", "Admission semantics v3", "claims"): {"Q21"},
    ("MATRIX:old socket", "I05 gate channel v3", "transcripts"): {"T02", "T38", "T64"},
    ("MATRIX:old socket", "I07 policy write v3", "transcripts"): {"T16", "T44"},
    ("MATRIX:queued action", "I05 gate channel v3", "transcripts"): {"T02", "T03", "T39", "T42"},
    ("MATRIX:queued action", "I07 policy write v3", "transcripts"): {"T29"},
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "agreement"): {"A02", "A20", "A37"},
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "transcripts"): {"T31", "T68", "T83", "T100", "T114"},
    ("MATRIX:conflicting gate/server result", "I07 policy write v3", "transcripts"): {"T03", "T30", "T50", "T51", "T53", "T59"},
    ("MATRIX:same-generation delayed-identical-request across two armed actions", "I05 gate channel v3", "transcripts"): {"T02", "T03"},
    ("S63-SOURCE", "I05 gate channel v3", "agreement"): {"A20"},
    ("S63-SOURCE", "I05 gate channel v3", "transcripts"): {"T83", "T100"},
    ("S63-SOURCE", "I07 policy write v3", "transcripts"): {"T30", "T51"},
    ("S63-NATIVE", "I05 gate channel v3", "agreement"): {"A20"},
    ("S63-NATIVE", "I05 gate channel v3", "transcripts"): {"T83", "T100"},
    ("S63-NATIVE", "I07 policy write v3", "transcripts"): {"T30", "T51"},
    ("CE18", "I05 gate channel v3", "transcripts"): {"T27", "T30", "T87", "T88", "T89", "T90"},
    ("CE18", "I07 policy write v3", "transcripts"): {"T02", "T05"},
    ("CE18", "Admission semantics v3", "claims"): {"Q12", "Q13", "Q14", "Q15"},
    ("CE22", "I05 gate channel v3", "transcripts"): {"T64"},
    ("S8-C2C3", "I05 gate channel v3", "transcripts"): {"T02", "T03"},
    ("S8-C2C3", "I07 policy write v3", "transcripts"): {"T20"},
}
# Each selection exactly: (size, the first 16 hex of sha256 over its ids joined by newlines).
SELECTION_PINS = {
    ("MATRIX:unarmed/duplicate/cross-case action", "I05 gate channel v3", "transcripts"): (28, "bee753c45fcfb0ac"),
    ("MATRIX:unarmed/duplicate/cross-case action", "I07 policy write v3", "transcripts"): (16, "d5c86168a40a8e70"),
    ("MATRIX:unarmed/duplicate/cross-case action", "Admission semantics v3", "claims"): (1, "f3344439866ac3a1"),
    ("MATRIX:old socket", "I05 gate channel v3", "transcripts"): (16, "9b94e663e52c660a"),
    ("MATRIX:old socket", "I07 policy write v3", "transcripts"): (7, "9d012a50265e6612"),
    ("MATRIX:queued action", "I05 gate channel v3", "transcripts"): (6, "f4a655e956d7114d"),
    ("MATRIX:queued action", "I07 policy write v3", "transcripts"): (1, "1fa54d688b787409"),
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "agreement"): (27, "52e2499b8be18870"),
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "transcripts"): (21, "b128ced9610dfbda"),
    ("MATRIX:conflicting gate/server result", "I07 policy write v3", "transcripts"): (16, "b87764f1b453b0f2"),
    ("MATRIX:same-generation delayed-identical-request across two armed actions", "I05 gate channel v3", "transcripts"): (2, "3d59080c84d17170"),
    ("S63-SOURCE", "I05 gate channel v3", "agreement"): (1, "084835c6a489af31"),
    ("S63-SOURCE", "I05 gate channel v3", "transcripts"): (7, "0525e43ac6eba28e"),
    ("S63-SOURCE", "I07 policy write v3", "transcripts"): (2, "4097937de58623cf"),
    ("S63-NATIVE", "I05 gate channel v3", "agreement"): (1, "084835c6a489af31"),
    ("S63-NATIVE", "I05 gate channel v3", "transcripts"): (7, "0525e43ac6eba28e"),
    ("S63-NATIVE", "I07 policy write v3", "transcripts"): (2, "4097937de58623cf"),
    ("CE18", "I05 gate channel v3", "transcripts"): (13, "3e88eec61cbcbadf"),
    ("CE18", "I07 policy write v3", "transcripts"): (4, "a2359be804e8c9c4"),
    ("CE18", "Admission semantics v3", "claims"): (4, "f612245f134e75b0"),
    ("CE22", "I05 gate channel v3", "transcripts"): (1, "cb29d4d1bbbdb53e"),
    ("S8-C2C3", "I05 gate channel v3", "transcripts"): (9, "4b9e10fd83ffe638"),
    ("S8-C2C3", "I07 policy write v3", "transcripts"): (1, "aa6fa6f11e1c0f05"),
}
PREFIXES = {"I05 gate channel v3": _catalog.I05, "I07 policy write v3": _catalog.I07, "Admission semantics v3": _catalog.ADMISSION}


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def pin(ids):
    return len(ids), hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]


def set_ids(contract, vector_set):
    prefix = _catalog.SUPPLEMENT if vector_set == "supplement" else PREFIXES[contract]
    return [row["id"] for row in _models.data(prefix + "vectors.json")["transcripts" if vector_set == "supplement" else vector_set]]


def native_cases(group):
    plan_group = next(row for row in _models.data(_catalog.PLAN)["testGroups"] if row["id"] == group)
    return {(case["tag"], case["phase"]) for case in plan_group["cases"]}


def guard_tests():
    names = []
    def walk(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                walk(test)
            else:
                names.append("%s.%s" % (type(test).__name__, test._testMethodName))
    walk(unittest.defaultTestLoader.loadTestsFromModule(test_reader_guards))
    return names


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_the_plans_cases_with_their_catalog_and_properties(self):
        self.assertEqual(ledger(), _catalog.ledger(GROUP, {"LEDGER-E09": test_reader_guards.PROPERTIES}))

    def test_no_case_is_pass_while_any_part_of_its_own_scope_was_not_run(self):
        # Owner decision Q-T11: a property carried by named native cases is outside the case's own scope; every other
        # property must be PASS for the case to be PASS, and a gated case is never PASS.
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual(row["result"] == "PASS", bool(row["properties"]) and all(
                    item["result"] == "PASS" or item["carriedBy"] for item in row["properties"]))
                self.assertEqual(row["reason"] is None, row["result"] == "PASS")
                self.assertEqual(bool(row["catalog"]), row["phase"] != "W04_OFFLINE")
        e09 = next(row for row in ledger()["cases"] if row["tag"] == "LEDGER-E09")
        self.assertEqual(e09["result"], "PASS")
        self.assertEqual([item["result"] for item in e09["properties"] if item["carriedBy"]], ["NOT_RUN_ENV_UNAVAILABLE"] * 2)

    def test_every_e09_property_maps_to_tests_that_exist_and_every_test_to_a_property(self):
        names = set(guard_tests())
        mapped = set()
        for row in test_reader_guards.PROPERTIES:
            with self.subTest(property=row["property"]):
                self.assertEqual(set(row), set(_catalog.PROPERTY_FIELDS))
                self.assertIn(row["result"], ("PASS", "NOT_RUN_ENV_UNAVAILABLE"))
                self.assertEqual(bool(row["tests"]), row["result"] == "PASS")
                self.assertEqual(row["reason"] is None, row["result"] == "PASS")
                self.assertLessEqual(set(row["tests"]), names)
                # Review R2-3: a property not run here names the plan's native cases that carry it.
                self.assertEqual(bool(row["carriedBy"]), row["result"] != "PASS")
                for carrier in row["carriedBy"]:
                    group, tag = carrier.split(" ", 1)
                    self.assertIn((tag, "W06_NATIVE_ONLY"), native_cases(group))
                mapped |= set(row["tests"])
        self.assertEqual(mapped, names)

    def test_the_e09_evidence_ran_and_passed_with_nothing_skipped(self):
        # Review R1-2: evidence is what ran in this command, not the names of tests that might be skipped.
        evidence = next(row for row in ledger()["cases"] if row["tag"] == "LEDGER-E09")["evidence"]
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name, test_reader_guards) for name in evidence)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual((result.testsRun, result.failures, result.errors, result.skipped, result.expectedFailures),
                         (len(evidence), [], [], [], []))

    def test_every_selection_is_pinned_and_names_real_vectors(self):
        selections = {(row["case"], row["contract"], row["vectorSet"]): row["ids"] for row in _catalog.catalog(GROUP)}
        self.assertEqual(set(selections), set(ANCHORS))
        self.assertEqual({key: pin(ids) for key, ids in selections.items()}, SELECTION_PINS)
        for key, ids in selections.items():
            with self.subTest(selection=key):
                self.assertLessEqual(ANCHORS[key], set(ids))
                self.assertEqual(len(set(ids)), len(ids))
                self.assertLessEqual(set(ids), set(set_ids(key[1], key[2])))


if __name__ == "__main__":
    unittest.main()
