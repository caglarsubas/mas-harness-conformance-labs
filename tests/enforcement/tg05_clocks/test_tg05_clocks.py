"""TG-05 clocks (W04-4a, CONF-ENF-004): the case ledger, the catalog of each case and the LEDGER-E09 carry.

tg05_clocks/results.json must equal what _catalog.ledger gives: the plan's six TG-05 cases, all W06_NATIVE_ONLY and
NOT_RUN_ENV_UNAVAILABLE, each with the contract rows whose expected results W06 checks while the case's probe runs, the
probe that injects its fault (probes/enforcement/tg05_clocks), the verdict checks that judge the probe's timeline with
W06's answer log (_verdicts.py), and the LEDGER-E09 properties it carries (owner decision Q-T11) with the checks that
observe each. Anchors and exact pins (size and digest of each id list) guard every selection.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

import _catalog
import _models
from tg02_lifecycle import test_reader_guards
from tg05_clocks import _verdicts

HERE = Path(__file__).resolve().parent
GROUP = "TG-05"
EXPIRE = {"T36", "T62", "T119"}
# The obligation rows (owner decision Q-T13) each case serves, as the plan lists them.
OBLIGATIONS = {
    'MATRIX:expiry with stalled Python': {'E08'},
    'MATRIX:suspend': {'E08'},
    'MATRIX:wall-clock rollback': {'E08'},
    'MATRIX:peer death/restart': {'E07'},
    'MATRIX:original deadlines': {'E11', 'E08'},
    'S8-FREEZE': {'E07', 'E08'},
}
# Rows each selection must keep (from the vectors' own intents and the reference model's own messages).
ANCHORS = {
    ("MATRIX:expiry with stalled Python", "I05 gate channel v3", "transcripts"): EXPIRE,
    ("MATRIX:expiry with stalled Python", "W01 amendment W02D", "specSections"): {"5.4 W6"},
    ("MATRIX:suspend", "I05 gate channel v3", "transcripts"): EXPIRE,
    ("MATRIX:suspend", "Native qualification profile v3", "negative"): {"L10"},
    ("MATRIX:suspend", "Native qualification profile v3", "modelRules"): {"expired capture", "expired backend capture"},
    ("MATRIX:wall-clock rollback", "I05 gate channel v3", "transcripts"): EXPIRE,
    ("MATRIX:wall-clock rollback", "Native qualification profile v3", "modelRules"): {"rollback or renewed lifetime"},
    ("MATRIX:peer death/restart", "I05 gate channel v3", "transcripts"): {"T26", "T41"},
    ("MATRIX:peer death/restart", "Native qualification profile v3", "negative"): {"Q06"},
    ("MATRIX:peer death/restart", "W01 amendment W02D", "specSections"): {"5.4 W2", "5.4 W6"},
    ("MATRIX:original deadlines", "I05 gate channel v3", "transcripts"): EXPIRE,
    ("MATRIX:original deadlines", "Native qualification profile v3", "modelRules"): {"rollback or renewed lifetime", "inspection deadline"},
    ("S8-FREEZE", "W01 amendment W02D", "specSections"): {"5.4 W1", "5.4 W2", "5.4 W3"},
    ("S8-FREEZE", "Native qualification profile v3", "negative"): {"Q06"},
    ('MATRIX:expiry with stalled Python', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:expiry with stalled Python'],
    ('MATRIX:suspend', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:suspend'],
    ('MATRIX:wall-clock rollback', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:wall-clock rollback'],
    ('MATRIX:peer death/restart', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:peer death/restart'],
    ('MATRIX:original deadlines', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:original deadlines'],
    ('S8-FREEZE', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['S8-FREEZE'],
}
# Each selection exactly: (size, the first 16 hex of sha256 over its ids joined by newlines).
SELECTION_PINS = {
    ('MATRIX:expiry with stalled Python', 'I05 gate channel v3', 'transcripts'): (6, '4dc2ee146d775925'),
    ('MATRIX:expiry with stalled Python', 'W01 amendment W02D', 'specSections'): (1, 'f3f11618b88000a7'),
    ('MATRIX:suspend', 'I05 gate channel v3', 'transcripts'): (6, '4dc2ee146d775925'),
    ('MATRIX:suspend', 'Native qualification profile v3', 'negative'): (1, '079c79cfaa5a36db'),
    ('MATRIX:suspend', 'Native qualification profile v3', 'modelRules'): (2, 'ddc91089da63d458'),
    ('MATRIX:wall-clock rollback', 'I05 gate channel v3', 'transcripts'): (6, '4dc2ee146d775925'),
    ('MATRIX:wall-clock rollback', 'Native qualification profile v3', 'modelRules'): (1, '40b23e79ff19e5ee'),
    ('MATRIX:peer death/restart', 'I05 gate channel v3', 'transcripts'): (5, '6a9633d3f4fc7b32'),
    ('MATRIX:peer death/restart', 'Native qualification profile v3', 'negative'): (1, '0f7a974dc7d0621f'),
    ('MATRIX:peer death/restart', 'W01 amendment W02D', 'specSections'): (2, '774b47132c9671e5'),
    ('MATRIX:original deadlines', 'I05 gate channel v3', 'transcripts'): (6, '4dc2ee146d775925'),
    ('MATRIX:original deadlines', 'Native qualification profile v3', 'modelRules'): (2, '018fa36b05009d2f'),
    ('S8-FREEZE', 'W01 amendment W02D', 'specSections'): (3, 'ba9a877a1c0e44d2'),
    ('S8-FREEZE', 'Native qualification profile v3', 'negative'): (1, '0f7a974dc7d0621f'),
    ('MATRIX:expiry with stalled Python', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'd6f62ec0a4c3dd6e'),
    ('MATRIX:suspend', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'd6f62ec0a4c3dd6e'),
    ('MATRIX:wall-clock rollback', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'd6f62ec0a4c3dd6e'),
    ('MATRIX:peer death/restart', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, '99e3940e063f5ff2'),
    ('MATRIX:original deadlines', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, 'b62f43c16c384ded'),
    ('S8-FREEZE', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, 'b9b209bde9337ccd'),
}


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def plan_cases():
    return next(row for row in _models.data(_catalog.PLAN)["testGroups"] if row["id"] == GROUP)["cases"]


def pin(ids):
    return len(ids), hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_the_plans_cases_with_their_catalog(self):
        self.assertEqual(ledger(), _catalog.ledger(GROUP, {}))

    def test_no_case_passes_before_w06_runs_it(self):
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual((row["phase"], row["result"]), ("W06_NATIVE_ONLY", "NOT_RUN_ENV_UNAVAILABLE"))
                self.assertTrue(row["catalog"] and not row["evidence"] and not row["properties"])

    def test_each_probe_case_has_exactly_its_verdict_checks(self):
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                if row["probe"] is None:
                    self.assertEqual((row["tag"], row["probeIn"], row["verdicts"]), ("S8-FREEZE", None, []))
                else:
                    self.assertEqual((row["probe"]["crate"], row["probeIn"]), ("tg05_clocks", None))
                    self.assertEqual(row["verdicts"], _verdicts.CHECKS[row["tag"]])


class SelectionTests(unittest.TestCase):
    def test_every_selection_is_pinned_and_anchored(self):
        selections = {(row["case"], row["contract"], row["vectorSet"]): row["ids"] for row in _catalog.native_catalog(GROUP)}
        self.assertEqual(set(selections), set(ANCHORS))
        self.assertEqual({key: pin(ids) for key, ids in selections.items()}, SELECTION_PINS)
        for key, ids in selections.items():
            with self.subTest(selection=key):
                self.assertLessEqual(ANCHORS[key], set(ids))
                self.assertEqual(len(set(ids)), len(ids))

    def test_every_row_names_a_real_vector_rule_or_step_of_its_source(self):
        messages = _catalog.model_rule_messages(_catalog.NATIVE_MODEL)
        refusals = {row["refusal"] for row in _models.data(_catalog.NATIVE)["negative"]}
        for row in _catalog.native_catalog(GROUP):
            with self.subTest(selection=(row["case"], row["vectorSet"])):
                if row["vectorSet"] == "modelRules":
                    # Review D1-10: a model rule is cited only when no vector exercises it.
                    self.assertLessEqual(set(row["ids"]), messages)
                    self.assertFalse(set(row["ids"]) & refusals)
                elif row["vectorSet"] == "specSections":
                    text = _models.snapshot_bytes(row["source"]).decode("utf-8")
                    self.assertTrue(all(_catalog.spec_step(text, ident) for ident in row["ids"]))
                elif row["vectorSet"] == "obligationRows":
                    # Owner decision Q-T13: the case's own plan obligations, each a row of the pinned table.
                    text = _models.snapshot_bytes(row["source"]).decode("utf-8")
                    plan_case = next(case for case in plan_cases() if case["tag"] == row["case"])
                    self.assertEqual(row["ids"], plan_case["obligations"])
                    self.assertTrue(all(_catalog.obligation_row(text, ident) for ident in row["ids"]))
                else:
                    data = _models.data(row["source"])
                    self.assertLessEqual(set(row["ids"]), {item["id"] for item in data[row["vectorSet"]]})

    def test_the_plans_contracts_are_the_only_sources(self):
        # Review D1-12: TG-05's rows come from its own contract set (I05 v3, native v3, W02D).
        plan_group = next(row for row in _models.data(_catalog.PLAN)["testGroups"] if row["id"] == GROUP)
        self.assertLessEqual({row["contract"] for row in _catalog.native_catalog(GROUP)},
                             set(plan_group["contracts"]) | {_catalog.FEASIBILITY_NAME})


class RouteTests(unittest.TestCase):
    def test_every_case_waits_for_the_probe_route(self):
        # Owner decision Q-T14 (2026-10-13): the route is decided in W06; it gates the run, not the source.
        value = ledger()
        self.assertEqual(value["blockers"], [_catalog.PROBE_ROUTE])
        for row in value["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual(row["blockedBy"], ["D-W02A-F2", "D-PROBE-ROUTE"])

    def test_each_probes_permissions_are_named_in_matrix_terms(self):
        matrix = _models.data(_catalog.MATRIX)
        assertions = {row["id"]: row for row in matrix["assertions"]}
        names = {row["name"] for row in matrix["types"]} | {row["name"] for row in matrix["domains"]}
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual(bool(row["permissions"]), row["probe"] is not None)
                # Review D2-6: what the harness restores after every run, whether or not the probe ended.
                self.assertEqual(bool(row["harnessRestore"]), row["probe"] is not None)
                self.assertIsNone(row["permissionsIn"])
            for item in row["permissions"]:
                with self.subTest(case=row["tag"], permission=(item["class"], item["perms"], item["targets"])):
                    host = [target for target in item["targets"] if target.startswith("HOST_POLICY:")]
                    if host:
                        self.assertEqual((host, item["assertions"], item["grantedTo"]), (item["targets"], [], None))
                        continue
                    self.assertLessEqual(set(item["targets"]), names)
                    for ident in item["assertions"]:
                        self.assertEqual(assertions[ident]["class"], item["class"])
                        self.assertLessEqual(set(item["perms"]), set(assertions[ident]["perms"]))
                        self.assertLessEqual(set(item["targets"]), set(assertions[ident]["targets"]))
                    # W06 sees which domains the enrolled policy grants it to (none of them the probe's).
                    self.assertTrue(item["grantedTo"])
                    self.assertEqual(item["grantedTo"], _catalog.granted_to(item["class"], item["perms"], item["targets"], item["assertions"]))


class CarryTests(unittest.TestCase):
    def test_the_e09_carry_is_closed_from_both_sides(self):
        # Owner decision Q-T11: each carried E09 property names its native cases; each such TG-05 case lists it with the
        # checks that observe it, and lists nothing E09 does not carry. The two tables are written separately.
        carried_here = {(row["tag"], item["property"]) for row in ledger()["cases"] for item in row["carries"]}
        expected = {(carrier.split(" ", 1)[1], name) for name, carriers in test_reader_guards.CARRIED.items()
                    for carrier in carriers if carrier.startswith(GROUP + " ")}
        self.assertEqual(carried_here, expected)

    def test_each_carried_property_is_observed_by_its_cases_reader_checks(self):
        # Review D2-9: an E09 property is the reader's, so only checks that judge the reader's answers observe it.
        for row in ledger()["cases"]:
            for item in row["carries"]:
                with self.subTest(case=row["tag"], property=item["property"][:40]):
                    self.assertEqual(item["case"], "LEDGER-E09")
                    self.assertTrue(item["checks"])
                    self.assertLessEqual(set(item["checks"]), set(row["verdicts"]) & _verdicts.READER_CHECKS)


if __name__ == "__main__":
    unittest.main()
