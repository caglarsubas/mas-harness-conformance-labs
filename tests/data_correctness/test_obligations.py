"""CONF-DATA-001: the obligation matrix restates the pinned record's 103 cells (deployable x family), each naming the
cases that test its rule on the simulation; every adapter is PENDING."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
OBLIGATIONS = json.loads((HERE / "obligations.json").read_text(encoding="ascii"))
CASES = json.loads((HERE / "cases.json").read_text(encoding="ascii"))
CONTRACTS = json.loads((HERE / "contracts.json").read_text(encoding="ascii"))
BY_FAMILY = {"RF-1": 24, "RF-2": 6, "RF-3": 24, "RF-4": 10, "RF-5": 24, "RF-6": 5, "RF-7": 10}


class ObligationTests(unittest.TestCase):
    def test_the_matrix_holds_103_unique_cells_with_the_records_counts(self):
        cells = OBLIGATIONS["cells"]
        self.assertEqual(len(cells), 103)
        self.assertEqual(len({(c["deployable"], c["family"]) for c in cells}), 103)
        self.assertEqual(len({c["deployable"] for c in cells}), 24)
        counts = {f: sum(c["family"] == f for c in cells) for f in BY_FAMILY}
        self.assertEqual(counts, BY_FAMILY)
        self.assertEqual(OBLIGATIONS["byFamily"], BY_FAMILY)

    def test_the_matrix_pins_the_record_the_contracts_pin(self):
        rec = [f for f in CONTRACTS["files"] if f["path"] == OBLIGATIONS["record"]["path"]]
        self.assertEqual(len(rec), 1)
        self.assertEqual(OBLIGATIONS["record"]["sha256"], rec[0]["sha256"])
        self.assertEqual(OBLIGATIONS["record"]["commit"], CONTRACTS["commit"])

    def test_every_cell_names_existing_cases_of_its_family_and_keeps_extensions_apart(self):
        family = {c["id"]: c["family"] for c in CASES["cases"]}
        parity = {c["id"]: c["parity"] for c in CASES["cases"]}
        for cell in OBLIGATIONS["cells"]:
            with self.subTest(cell=(cell["deployable"], cell["family"])):
                self.assertEqual(cell["adapterState"], "PENDING")
                self.assertTrue(cell["cases"])
                for cid in cell["cases"]:
                    self.assertEqual((family[cid], parity[cid]), (cell["family"], "MODEL_OPS"))
                for cid in cell["r12Extensions"]:
                    self.assertEqual((family[cid], parity[cid]), (cell["family"], "R12_EXTENSION"))


if __name__ == "__main__":
    unittest.main()
