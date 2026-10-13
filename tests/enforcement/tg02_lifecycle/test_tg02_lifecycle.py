"""TG-02 lifecycle (W04-3, CONF-ENF-003): the case ledger, the catalog of the gated cases and LEDGER-E09's evidence.

tg02_lifecycle/results.json must equal what _catalog.ledger gives: the plan's TG-02 cases in order; LEDGER-E09 PASS only
through the reader guard tests of this run (owner decision Q-T9); every other case NOT_RUN_ENV_UNAVAILABLE with the
contract vectors that specify it (owner decision Q-T8, 2026-10-13). The anchors and per-selection counts below are a
second pin, so neither a regenerated ledger nor a narrower rule can drop a case's vectors unseen.
"""
from __future__ import annotations

from pathlib import Path
import unittest

import _catalog
import _models
from tg02_lifecycle import test_reader_guards

HERE = Path(__file__).resolve().parent
GROUP = "TG-02"
# Vectors each selection must keep (from the vectors' own intents and refusals).
ANCHORS = {
    ("MATRIX:unarmed/duplicate/cross-case action", "I05 gate channel v3", "transcripts"): {"T12", "T48", "T76"},
    ("MATRIX:unarmed/duplicate/cross-case action", "I07 policy write v3", "transcripts"): {"T20", "T32"},
    ("MATRIX:old socket", "I05 gate channel v3", "transcripts"): {"T02", "T38", "T64"},
    ("MATRIX:old socket", "I07 policy write v3", "transcripts"): {"T16", "T44"},
    ("MATRIX:queued action", "I05 gate channel v3", "transcripts"): {"T02", "T03", "T39"},
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "agreement"): {"A02", "A20", "A37"},
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "transcripts"): {"T31", "T68", "T114"},
    ("MATRIX:conflicting gate/server result", "I07 policy write v3", "transcripts"): {"T03", "T59"},
    ("MATRIX:same-generation delayed-identical-request across two armed actions", "I05 gate channel v3", "transcripts"): {"T02", "T03"},
    ("S63-SOURCE", "I05 gate channel v3", "agreement"): {"A02", "A20"},
    ("S63-NATIVE", "I05 gate channel v3", "agreement"): {"A02", "A20"},
    ("CE18", "I05 gate channel v3", "transcripts"): {"T30", "T27"},
    ("CE18", "I07 policy write v3", "transcripts"): {"T02"},
    ("CE22", "I05 gate channel v3", "transcripts"): {"T64"},
    ("S8-C2C3", "I05 gate channel v3", "transcripts"): {"T02", "T03"},
    ("S8-C2C3", "I07 policy write v3", "transcripts"): {"T20"},
}
# The number of vectors each selection holds on the pinned vectors.
SELECTION_SIZES = {
    ("MATRIX:unarmed/duplicate/cross-case action", "I05 gate channel v3", "transcripts"): 26,
    ("MATRIX:unarmed/duplicate/cross-case action", "I07 policy write v3", "transcripts"): 8,
    ("MATRIX:old socket", "I05 gate channel v3", "transcripts"): 16,
    ("MATRIX:old socket", "I07 policy write v3", "transcripts"): 7,
    ("MATRIX:queued action", "I05 gate channel v3", "transcripts"): 4,
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "agreement"): 27,
    ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "transcripts"): 11,
    ("MATRIX:conflicting gate/server result", "I07 policy write v3", "transcripts"): 9,
    ("MATRIX:same-generation delayed-identical-request across two armed actions", "I05 gate channel v3", "transcripts"): 2,
    ("S63-SOURCE", "I05 gate channel v3", "agreement"): 8,
    ("S63-NATIVE", "I05 gate channel v3", "agreement"): 8,
    ("CE18", "I05 gate channel v3", "transcripts"): 5,
    ("CE18", "I07 policy write v3", "transcripts"): 2,
    ("CE22", "I05 gate channel v3", "transcripts"): 1,
    ("S8-C2C3", "I05 gate channel v3", "transcripts"): 9,
    ("S8-C2C3", "I07 policy write v3", "transcripts"): 1,
}
# LEDGER-E09's properties (E09, A02), one test class each.
GUARD_CLASSES = {"CustodyTickTests", "StickyPhaseTests", "PartialConstructionTests", "OwnerTests", "CleanupTests"}


def guard_tests():
    names = []
    def walk(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                walk(test)
            else:
                names.append("%s.%s" % (type(test).__name__, test._testMethodName))
    walk(unittest.defaultTestLoader.loadTestsFromModule(test_reader_guards))
    return sorted(names)


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def set_ids(contract, vector_set):
    prefix = {"I05 gate channel v3": _catalog.I05, "I07 policy write v3": _catalog.I07}[contract]
    if vector_set == "supplement":
        prefix = _catalog.SUPPLEMENT
    return [row["id"] for row in _models.data(prefix + "vectors.json")["agreement" if vector_set == "agreement" else "transcripts"]]


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_the_plans_cases_with_their_catalog_and_evidence(self):
        self.assertEqual(ledger(), _catalog.ledger(GROUP, {"LEDGER-E09": guard_tests()}))

    def test_only_the_offline_case_passes_and_only_through_its_tests(self):
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                offline = row["phase"] == "W04_OFFLINE"
                self.assertEqual(row["result"], "PASS" if offline else "NOT_RUN_ENV_UNAVAILABLE")
                self.assertEqual(bool(row["evidence"]), offline)
                self.assertEqual(bool(row["catalog"]), not offline)
        e09 = next(row for row in ledger()["cases"] if row["tag"] == "LEDGER-E09")
        self.assertEqual({name.split(".")[0] for name in e09["evidence"]}, GUARD_CLASSES)

    def test_every_selection_is_pinned_and_names_real_vectors(self):
        selections = {(row["case"], row["contract"], row["vectorSet"]): row["ids"] for row in _catalog.catalog(GROUP)}
        self.assertEqual(set(selections), set(ANCHORS))
        self.assertEqual({key: len(ids) for key, ids in selections.items()}, SELECTION_SIZES)
        for key, ids in selections.items():
            with self.subTest(selection=key):
                self.assertLessEqual(ANCHORS[key], set(ids))
                self.assertEqual(len(set(ids)), len(ids))
                self.assertLessEqual(set(ids), set(set_ids(key[1], key[2])))


if __name__ == "__main__":
    unittest.main()
