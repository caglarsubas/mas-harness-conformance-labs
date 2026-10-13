"""TG-03 persistence (W04-3, CONF-ENF-003): the case ledger and the catalog of its gated cases.

tg03_persistence/results.json must equal what _catalog.ledger gives: the plan's TG-03 cases in order, every one
NOT_RUN_ENV_UNAVAILABLE until W05's release set or W06's native hosts, each with the contract vectors that specify it
(owner decision Q-T8, 2026-10-13), the I05 v3 supplement's storage-failure transcripts included (owner decision Q-T10).
The anchors and per-selection counts below are a second pin on the catalog.
"""
from __future__ import annotations

from pathlib import Path
import unittest

import _catalog
import _models

HERE = Path(__file__).resolve().parent
GROUP = "TG-03"
SUPPLEMENT = {"S01", "S02", "S03", "S04", "S05", "S06"}
# Vectors each selection must keep (from the vectors' own intents and injected faults).
ANCHORS = {
    ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "transcripts"): {"T25", "T102", "T120"},
    ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "supplement"): SUPPLEMENT,
    ("MATRIX:kill at each fsync/send/result boundary", "I07 policy write v3", "transcripts"): {"T09", "T47"},
    ("MATRIX:ENOSPC", "I05 gate channel v3", "transcripts"): {"T35", "T57", "T84"},
    ("MATRIX:ENOSPC", "I05 gate channel v3", "supplement"): SUPPLEMENT,
    ("MATRIX:ENOSPC", "I07 policy write v3", "transcripts"): {"T06", "T60"},
    ("MATRIX:partial records", "I05 gate channel v3", "transcripts"): {"T102"},
    ("MATRIX:partial records", "I05 gate channel v3", "supplement"): {"S06"},
    ("MATRIX:lost acknowledgements", "I05 gate channel v3", "transcripts"): {"T31", "T114"},
    ("MATRIX:lost acknowledgements", "I07 policy write v3", "transcripts"): {"T49", "T57"},
    ("MATRIX:restart/rollback", "I05 gate channel v3", "transcripts"): {"T13", "T25", "T95", "T118"},
    ("MATRIX:restart/rollback", "I05 gate channel v3", "supplement"): SUPPLEMENT,
    ("MATRIX:restart/rollback", "I07 policy write v3", "transcripts"): {"T14", "T61"},
    ("CE21", "I05 gate channel v3", "transcripts"): {"T25"},
    ("S8-C2C3", "I05 gate channel v3", "transcripts"): {"T02", "T03"},
    ("S8-C2C3", "I07 policy write v3", "transcripts"): {"T20"},
}
# The number of vectors each selection holds on the pinned vectors.
SELECTION_SIZES = {
    ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "transcripts"): 18,
    ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "supplement"): 6,
    ("MATRIX:kill at each fsync/send/result boundary", "I07 policy write v3", "transcripts"): 8,
    ("MATRIX:ENOSPC", "I05 gate channel v3", "transcripts"): 24,
    ("MATRIX:ENOSPC", "I05 gate channel v3", "supplement"): 6,
    ("MATRIX:ENOSPC", "I07 policy write v3", "transcripts"): 8,
    ("MATRIX:partial records", "I05 gate channel v3", "transcripts"): 1,
    ("MATRIX:partial records", "I05 gate channel v3", "supplement"): 1,
    ("MATRIX:lost acknowledgements", "I05 gate channel v3", "transcripts"): 10,
    ("MATRIX:lost acknowledgements", "I07 policy write v3", "transcripts"): 4,
    ("MATRIX:restart/rollback", "I05 gate channel v3", "transcripts"): 21,
    ("MATRIX:restart/rollback", "I05 gate channel v3", "supplement"): 6,
    ("MATRIX:restart/rollback", "I07 policy write v3", "transcripts"): 8,
    ("CE21", "I05 gate channel v3", "transcripts"): 1,
    ("S8-C2C3", "I05 gate channel v3", "transcripts"): 9,
    ("S8-C2C3", "I07 policy write v3", "transcripts"): 1,
}


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def set_ids(contract, vector_set):
    prefix = {"I05 gate channel v3": _catalog.I05, "I07 policy write v3": _catalog.I07}[contract]
    if vector_set == "supplement":
        prefix = _catalog.SUPPLEMENT
    return [row["id"] for row in _models.data(prefix + "vectors.json")["transcripts"]]


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_the_plans_cases_with_their_catalog(self):
        self.assertEqual(ledger(), _catalog.ledger(GROUP, {}))

    def test_no_case_passes_before_its_subject_exists(self):
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertNotEqual(row["phase"], "W04_OFFLINE")
                self.assertEqual(row["result"], "NOT_RUN_ENV_UNAVAILABLE")
                self.assertTrue(row["catalog"] and not row["evidence"])

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
