"""CONF-DATA-001: the case catalogue matches the simulation; arms vary one switch over a shared schedule; the three R12
extensions are labelled, provisional and R12's (VIS-C15-SPLIT conditions 1 and 4)."""
from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

import _judge
import _sim

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "cases.json").read_text(encoding="ascii"))
PREFIX = {"WS": "RF-1", "FN": "RF-2", "CK": "RF-3", "OP": "RF-4", "CV": "RF-5", "DD": "RF-6", "RS": "RF-7"}
EXTENSIONS = ["CK-04", "CV-04", "DD-04"]
CRASH_POINTS = {"CP-1": ["WS-01", "OP-01"], "CP-2": ["OP-02"], "CP-3": ["OP-01", "OP-04"], "CP-4": ["OP-03", "OP-04", "OP-07"],
                "CP-5": ["FN-01", "FN-02", "CK-02"]}


class CaseCatalogueTests(unittest.TestCase):
    def test_the_catalogue_holds_29_cases_in_the_simulations_order(self):
        ids = [c["id"] for c in CASES["cases"]]
        self.assertEqual(ids, list(_sim.RUNNERS))
        self.assertEqual(len(ids), 29)
        counts = {p: sum(i.startswith(p + "-") for i in ids) for p in PREFIX}
        self.assertEqual(counts, {"WS": 3, "FN": 3, "CK": 4, "OP": 7, "CV": 6, "DD": 4, "RS": 2})
        self.assertEqual(CASES["seeds"], {"first": 1, "last": 32})
        self.assertEqual(_sim.SEEDS, tuple(range(1, 33)))

    def test_every_case_names_its_family_its_arms_and_its_codes(self):
        for case in CASES["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["family"], PREFIX[case["id"][:2]])
                self.assertTrue(case["arms"])
                names = [a["name"] for a in case["arms"]]
                self.assertEqual(len(names), len(set(names)))
                for arm in case["arms"]:
                    if arm["kind"] == "DEFENDED":
                        self.assertEqual((arm["code"], arm["floor"]), (None, 0))
                    else:
                        self.assertIn(arm["kind"], ("CONTROL", "NEGATIVE"))
                        self.assertEqual(arm["code"], _judge.CODE_OF[case["family"]])
                        self.assertTrue(1 <= arm["floor"] <= 32)

    def test_the_r12_extensions_are_labelled_provisional_and_r12s(self):
        for case in CASES["cases"]:
            ext = case["id"] in EXTENSIONS
            self.assertEqual(case["parity"], "R12_EXTENSION" if ext else "MODEL_OPS", case["id"])
            self.assertEqual(case["provisional"], ext, case["id"])
            self.assertEqual(case["expectedArmsBy"], "R12" if ext else "RECORD", case["id"])

    def test_the_crash_points_sit_where_the_design_puts_them(self):
        got = {}
        for case in CASES["cases"]:
            for cp in case["crashPoints"]:
                got.setdefault(cp, []).append(case["id"])
        self.assertEqual(got, CRASH_POINTS)

    def test_the_random_source_is_seeded_by_case_and_seed_only(self):
        tree = ast.parse((HERE / "_sim.py").read_text(encoding="ascii"))
        rng = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_rng"][0]
        self.assertEqual([a.arg for a in rng.args.args], ["case", "seed"])
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_rng"]
        self.assertTrue(calls)
        for call in calls:
            self.assertEqual([getattr(a, "id", None) for a in call.args], ["case", "seed"])
        modules = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and getattr(n.value, "id", "") == "random"]
        self.assertEqual({n.attr for n in modules}, {"Random"})

    def test_every_run_is_a_well_formed_trace_whose_parity_is_the_cases(self):
        for case in CASES["cases"]:
            for arm in case["arms"]:
                for seed in (1, 17, 32):
                    run = _sim.run(case["id"], arm["name"], seed)
                    _judge.check_shape(run["trace"])
                    self.assertEqual(run["trace"]["id"], case["id"])
                    self.assertEqual(run["trace"]["family"], case["family"])
                    self.assertEqual(_judge.parity(run["trace"]), case["parity"], (case["id"], arm["name"]))

    def test_arms_of_a_case_see_one_schedule(self):
        """A defended arm and a control arm of one seed differ only where the arm's switch acts: here, the number of
        steps of WS-01 under NONE and SERIALIZABLE share the same begins in the same order."""
        for seed in (2, 9):
            a = [s for s in _sim.run("WS-01", "SERIALIZABLE", seed)["trace"]["steps"] if s["op"] == "begin"]
            b = [s for s in _sim.run("WS-01", "NONE", seed)["trace"]["steps"] if s["op"] == "begin"]
            self.assertEqual(a[:2], b[:2])
            self.assertEqual(_sim.run("CK-01", "MONOTONIC", seed)["trace"]["steps"][0],
                             _sim.run("CK-01", "WALL", seed)["trace"]["steps"][0])


if __name__ == "__main__":
    unittest.main()
