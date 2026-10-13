"""TG-04 host (W04-4a, CONF-ENF-004): the case ledger and the catalog of each case; the probes come with CONF-ENF-005.

tg04_host/results.json must equal what _catalog.ledger gives: the plan's TG-04 cases, all W06_NATIVE_ONLY and
NOT_RUN_ENV_UNAVAILABLE, each with the contract rows (SELinux matrix v4 checks, seccomp v2 decisions, native v3 vectors
and model rules, W02D items and spec steps) whose expected results W06 checks while the case's probe runs. Every probe
comes with CONF-ENF-005 (W04-4b, owner decision 2026-10-13), which also adds the checks for the LEDGER-E09 properties these
cases carry (owner decision Q-T11). Anchors (for check and decision sets, the first denial of each named assertion or
syscall) and exact pins guard every selection.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

import _catalog
import _models
from tg02_lifecycle import test_reader_guards

HERE = Path(__file__).resolve().parent
GROUP = "TG-04"
# The obligation rows (owner decision Q-T13) each case serves, as the plan lists them.
OBLIGATIONS = {
    'MATRIX:policy/load/boolean/relabel': {'E04'},
    'MATRIX:namespaces/mount aliases': {'E01', 'E03'},
    'MATRIX:effective BPF ancestors': {'E05'},
    'MATRIX:mappings/injection': {'E06'},
    'MATRIX:parent/FD spoof': {'E02', 'E07'},
    'LEDGER-E01': {'E01'},
    'LEDGER-E02': {'E02'},
    'S8-KERNEL-FACTS': {'E05', 'E06'},
    'S8-POLICYLOAD': {'E04'},
    'S8-FREEZE': {'E12', 'E07'},
    'S8-CLOSURE': {'E04', 'E05', 'E03'},
    'O-T04-AMEND': {'E12', 'E07', 'E06'},
    'CE19': {'E04', 'E05'},
    'CE25': {'E11', 'E04'},
    'CE27': {'E05'},
    'CE28': {'E05'},
}
# Rows each selection must keep.
ANCHORS = {
    ('MATRIX:policy/load/boolean/relabel', 'SELinux matrix v4', 'accessChecks'): {'C316', 'C307', 'C1776'},
    ('MATRIX:policy/load/boolean/relabel', 'SELinux matrix v4', 'mutationChecks'): {'M08', 'M07', 'M15'},
    ('MATRIX:policy/load/boolean/relabel', 'Native qualification profile v3', 'negative'): {'R13', 'R12', 'R14'},
    ('MATRIX:policy/load/boolean/relabel', 'Native qualification profile v3', 'modelRules'): {'active policy changed'},
    ('MATRIX:policy/load/boolean/relabel', 'W01 amendment W02D', 'specSections'): {'5.2 S4', '5.5 M1'},
    ('MATRIX:namespaces/mount aliases', 'Seccomp allowlists v2', 'decisionChecks'): {'D0024', 'D0054', 'D0055'},
    ('MATRIX:namespaces/mount aliases', 'Seccomp allowlists v2', 'policyMutations'): {'M07'},
    ('MATRIX:namespaces/mount aliases', 'Native qualification profile v3', 'negative'): {'C27', 'C09', 'C28'},
    ('MATRIX:effective BPF ancestors', 'SELinux matrix v4', 'accessChecks'): {'C327', 'C336', 'C322'},
    ('MATRIX:effective BPF ancestors', 'SELinux matrix v4', 'mutationChecks'): {'M11', 'M10', 'M09'},
    ('MATRIX:effective BPF ancestors', 'Seccomp allowlists v2', 'decisionChecks'): {'D0009'},
    ('MATRIX:effective BPF ancestors', 'Seccomp allowlists v2', 'policyMutations'): {'M08', 'M03'},
    ('MATRIX:effective BPF ancestors', 'Native qualification profile v3', 'negative'): {'R11', 'R26', 'R10'},
    ('MATRIX:mappings/injection', 'SELinux matrix v4', 'accessChecks'): {'C1323', 'C1263', 'C1203'},
    ('MATRIX:mappings/injection', 'SELinux matrix v4', 'mutationChecks'): {'M20', 'M19', 'M21'},
    ('MATRIX:mappings/injection', 'Seccomp allowlists v2', 'decisionChecks'): {'D0045', 'D0130', 'D0044'},
    ('MATRIX:mappings/injection', 'Seccomp allowlists v2', 'policyMutations'): {'M01', 'M06', 'M09'},
    ('MATRIX:mappings/injection', 'Native qualification profile v3', 'negative'): {'V07', 'V09', 'V08'},
    ('MATRIX:mappings/injection', 'Native qualification profile v3', 'modelRules'): {'file measurement differs', 'incomplete loaded-code closure', 'missing or injected executable map'},
    ('MATRIX:parent/FD spoof', 'SELinux matrix v4', 'accessChecks'): {'C1625', 'C1662', 'C1643'},
    ('MATRIX:parent/FD spoof', 'SELinux matrix v4', 'mutationChecks'): {'M45', 'M33', 'M34'},
    ('MATRIX:parent/FD spoof', 'Seccomp allowlists v2', 'decisionChecks'): {'D0028', 'D0035', 'D0033'},
    ('MATRIX:parent/FD spoof', 'Seccomp allowlists v2', 'policyMutations'): {'M05', 'M04', 'M13'},
    ('MATRIX:parent/FD spoof', 'Native qualification profile v3', 'negative'): {'C13', 'C14', 'C15'},
    ('MATRIX:parent/FD spoof', 'W01 amendment W02D', 'items'): {'A12', 'A11', 'A10'},
    ('MATRIX:parent/FD spoof', 'W01 amendment W02D', 'specSections'): {'5.4 W2', '5.4 W3', '5.4 W6'},
    ('LEDGER-E01', 'SELinux matrix v4', 'accessChecks'): {'C316', 'C307', 'C594'},
    ('LEDGER-E01', 'SELinux matrix v4', 'mutationChecks'): {'M08', 'M07', 'M25'},
    ('LEDGER-E01', 'Native qualification profile v3', 'negative'): {'V43', 'V15', 'V16'},
    ('LEDGER-E02', 'Seccomp allowlists v2', 'decisionChecks'): {'D0233', 'D0035', 'D0525'},
    ('LEDGER-E02', 'W01 amendment W02D', 'specSections'): {'5.4 W3'},
    ('S8-KERNEL-FACTS', 'W01 amendment W02D', 'specSections'): {'5.1'},
    ('S8-KERNEL-FACTS', 'SELinux matrix v4', 'accessChecks'): {'C359', 'C336', 'C352'},
    ('S8-KERNEL-FACTS', 'Seccomp allowlists v2', 'decisionChecks'): {'D0009'},
    ('S8-KERNEL-FACTS', 'Native qualification profile v3', 'negative'): {'R09', 'R11', 'R10'},
    ('S8-POLICYLOAD', 'SELinux matrix v4', 'accessChecks'): {'C387', 'C391', 'C1776'},
    ('S8-POLICYLOAD', 'Native qualification profile v3', 'negative'): {'R13', 'R12', 'R14'},
    ('S8-POLICYLOAD', 'W01 amendment W02D', 'specSections'): {'5.2 S4'},
    ('S8-FREEZE', 'W01 amendment W02D', 'specSections'): {'5.4 W2', '5.4 W1', '5.4 W3'},
    ('S8-FREEZE', 'Native qualification profile v3', 'negative'): {'Q06'},
    ('S8-FREEZE', 'Seccomp allowlists v2', 'decisionChecks'): set(),
    ('S8-FREEZE', 'SELinux matrix v4', 'accessChecks'): {'C448'},
    ('S8-CLOSURE', 'Native qualification profile v3', 'negative'): {'C19', 'C21', 'C20'},
    ('S8-CLOSURE', 'SELinux matrix v4', 'accessChecks'): {'C1038', 'C1008', 'C1023'},
    ('S8-CLOSURE', 'W01 amendment W02D', 'specSections'): {'2.3', '2.2'},
    ('O-T04-AMEND', 'Seccomp allowlists v2', 'decisionChecks'): {'D0003', 'D0023', 'D0009'},
    ('O-T04-AMEND', 'Seccomp allowlists v2', 'workerStackChecks'): {'S1845', 'S1843', 'S1844'},
    ('O-T04-AMEND', 'Seccomp allowlists v2', 'policyMutations'): {'M15', 'M14', 'M09'},
    ('O-T04-AMEND', 'W01 amendment W02D', 'items'): {'A1', 'A2', 'A3'},
    ('O-T04-AMEND', 'W01 amendment W02D', 'obligations'): {'O-T04-AMEND'},
    ('CE19', 'SELinux matrix v4', 'accessChecks'): {'C387', 'C391', 'C413'},
    ('CE19', 'W01 amendment W02D', 'specSections'): {'5.2 S4', '9 19', '5.2 S2'},
    ('CE25', 'SELinux matrix v4', 'accessChecks'): {'C761', 'C080'},
    ('CE25', 'W01 amendment W02D', 'specSections'): {'9 25'},
    ('CE27', 'SELinux matrix v4', 'accessChecks'): {'C663'},
    ('CE27', 'Seccomp allowlists v2', 'decisionChecks'): {'D0009'},
    ('CE27', 'Native qualification profile v3', 'negative'): {'R09'},
    ('CE27', 'W01 amendment W02D', 'specSections'): {'9 27', '5.1'},
    # Review D2-12: one admin denial per kind CE28 relies on (program descriptor, cgroup search and open, cgroup file write,
    # CAP_DAC_READ_SEARCH).
    ('CE28', 'SELinux matrix v4', 'accessChecks'): {'C352', 'C543', 'F02', 'C594', 'C640'},
    ('CE28', 'Native qualification profile v3', 'negative'): {'R11'},
    ('CE28', 'W01 amendment W02D', 'specSections'): {'9 28', '5.1'},
    ('MATRIX:policy/load/boolean/relabel', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:policy/load/boolean/relabel'],
    ('MATRIX:namespaces/mount aliases', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:namespaces/mount aliases'],
    ('MATRIX:effective BPF ancestors', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:effective BPF ancestors'],
    ('MATRIX:mappings/injection', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:mappings/injection'],
    ('MATRIX:parent/FD spoof', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['MATRIX:parent/FD spoof'],
    ('LEDGER-E01', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['LEDGER-E01'],
    ('LEDGER-E02', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['LEDGER-E02'],
    ('S8-KERNEL-FACTS', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['S8-KERNEL-FACTS'],
    ('S8-POLICYLOAD', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['S8-POLICYLOAD'],
    ('S8-FREEZE', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['S8-FREEZE'],
    ('S8-CLOSURE', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['S8-CLOSURE'],
    ('O-T04-AMEND', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['O-T04-AMEND'],
    ('CE19', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['CE19'],
    ('CE25', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['CE25'],
    ('CE27', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['CE27'],
    ('CE28', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): OBLIGATIONS['CE28'],
}
# Each selection exactly: (size, the first 16 hex of sha256 over its ids joined by newlines).
SELECTION_PINS = {
    ('MATRIX:policy/load/boolean/relabel', 'SELinux matrix v4', 'accessChecks'): (80, '6457ff0567ead0c9'),
    ('MATRIX:policy/load/boolean/relabel', 'SELinux matrix v4', 'mutationChecks'): (7, 'e7562931531ef4fe'),
    ('MATRIX:policy/load/boolean/relabel', 'Native qualification profile v3', 'negative'): (14, '5f2f22aef9353bdb'),
    ('MATRIX:policy/load/boolean/relabel', 'Native qualification profile v3', 'modelRules'): (1, '43fec36b1f42f49f'),
    ('MATRIX:policy/load/boolean/relabel', 'W01 amendment W02D', 'specSections'): (2, '5da7c209d14fe3ef'),
    ('MATRIX:namespaces/mount aliases', 'Seccomp allowlists v2', 'decisionChecks'): (182, 'd51f8a4fcde725ba'),
    ('MATRIX:namespaces/mount aliases', 'Seccomp allowlists v2', 'policyMutations'): (1, '36bcdccc44445c07'),
    ('MATRIX:namespaces/mount aliases', 'Native qualification profile v3', 'negative'): (5, '9c00e16119b7063a'),
    ('MATRIX:effective BPF ancestors', 'SELinux matrix v4', 'accessChecks'): (156, '45c0b4f7e6f053df'),
    ('MATRIX:effective BPF ancestors', 'SELinux matrix v4', 'mutationChecks'): (7, '79ff33b694eee599'),
    ('MATRIX:effective BPF ancestors', 'Seccomp allowlists v2', 'decisionChecks'): (134, '7ecaa3b8d7c1779b'),
    ('MATRIX:effective BPF ancestors', 'Seccomp allowlists v2', 'policyMutations'): (2, '7eb83c20e298d005'),
    ('MATRIX:effective BPF ancestors', 'Native qualification profile v3', 'negative'): (11, '4a55941f3f397187'),
    ('MATRIX:mappings/injection', 'SELinux matrix v4', 'accessChecks'): (486, 'b4df5008b7e72761'),
    ('MATRIX:mappings/injection', 'SELinux matrix v4', 'mutationChecks'): (6, '6cbb01064a71fee9'),
    ('MATRIX:mappings/injection', 'Seccomp allowlists v2', 'decisionChecks'): (212, '7ffb6c3a455f4286'),
    ('MATRIX:mappings/injection', 'Seccomp allowlists v2', 'policyMutations'): (3, '9559d743d5f6f3b9'),
    ('MATRIX:mappings/injection', 'Native qualification profile v3', 'negative'): (4, '52fad5197a8d84ac'),
    ('MATRIX:mappings/injection', 'Native qualification profile v3', 'modelRules'): (3, '2ef879f78e747236'),
    ('MATRIX:parent/FD spoof', 'SELinux matrix v4', 'accessChecks'): (217, 'ac6b78cd02e72b7b'),
    ('MATRIX:parent/FD spoof', 'SELinux matrix v4', 'mutationChecks'): (6, '486cd1d7d8e9377f'),
    ('MATRIX:parent/FD spoof', 'Seccomp allowlists v2', 'decisionChecks'): (218, '793c52f4e8158823'),
    ('MATRIX:parent/FD spoof', 'Seccomp allowlists v2', 'policyMutations'): (5, '6bb56ec7381eb746'),
    ('MATRIX:parent/FD spoof', 'Native qualification profile v3', 'negative'): (8, '1e95e07455819673'),
    ('MATRIX:parent/FD spoof', 'W01 amendment W02D', 'items'): (3, 'd25f3a8d81364be2'),
    ('MATRIX:parent/FD spoof', 'W01 amendment W02D', 'specSections'): (3, '61c54cf202c77511'),
    ('LEDGER-E01', 'SELinux matrix v4', 'accessChecks'): (107, 'b1a5294533a1b92e'),
    ('LEDGER-E01', 'SELinux matrix v4', 'mutationChecks'): (5, '6aeeb287286a4bd1'),
    ('LEDGER-E01', 'Native qualification profile v3', 'negative'): (5, 'c43eeaf378c5a7c2'),
    ('LEDGER-E02', 'Seccomp allowlists v2', 'decisionChecks'): (158, '6b02d139766c0e1a'),
    ('LEDGER-E02', 'W01 amendment W02D', 'specSections'): (1, '0043f5b6f5f20dc5'),
    ('S8-KERNEL-FACTS', 'W01 amendment W02D', 'specSections'): (1, '77065cda8fe15518'),
    ('S8-KERNEL-FACTS', 'SELinux matrix v4', 'accessChecks'): (49, 'a1675cc1c19d3ed3'),
    ('S8-KERNEL-FACTS', 'Seccomp allowlists v2', 'decisionChecks'): (134, '7ecaa3b8d7c1779b'),
    ('S8-KERNEL-FACTS', 'Native qualification profile v3', 'negative'): (7, '57db7b09e6f30525'),
    ('S8-POLICYLOAD', 'SELinux matrix v4', 'accessChecks'): (55, '6351e095e0690870'),
    ('S8-POLICYLOAD', 'Native qualification profile v3', 'negative'): (6, '4b3a85bfd6a1fb2e'),
    ('S8-POLICYLOAD', 'W01 amendment W02D', 'specSections'): (1, '8a69e0650bb17793'),
    ('S8-FREEZE', 'W01 amendment W02D', 'specSections'): (3, 'ba9a877a1c0e44d2'),
    ('S8-FREEZE', 'Native qualification profile v3', 'negative'): (1, '0f7a974dc7d0621f'),
    ('S8-FREEZE', 'Seccomp allowlists v2', 'decisionChecks'): (2, 'e7f22b9ada52ce39'),
    ('S8-FREEZE', 'SELinux matrix v4', 'accessChecks'): (10, 'ebd9e7245111a6fe'),
    ('S8-CLOSURE', 'Native qualification profile v3', 'negative'): (25, 'be269994e987c7d4'),
    ('S8-CLOSURE', 'SELinux matrix v4', 'accessChecks'): (804, 'f53fd618cb949600'),
    ('S8-CLOSURE', 'W01 amendment W02D', 'specSections'): (2, '6e6ee65291360b65'),
    ('O-T04-AMEND', 'Seccomp allowlists v2', 'decisionChecks'): (2813, 'dad5815041a84dd6'),
    ('O-T04-AMEND', 'Seccomp allowlists v2', 'workerStackChecks'): (353, '97409c99e5596abb'),
    ('O-T04-AMEND', 'Seccomp allowlists v2', 'policyMutations'): (3, 'be9ca5bfdf4ea022'),
    ('O-T04-AMEND', 'W01 amendment W02D', 'items'): (12, '5834bc1b50bd3840'),
    ('O-T04-AMEND', 'W01 amendment W02D', 'obligations'): (1, '25a1eabd66bd3770'),
    ('CE19', 'SELinux matrix v4', 'accessChecks'): (33, 'cb0e7f4e0bb4a5a7'),
    ('CE19', 'W01 amendment W02D', 'specSections'): (3, 'e3e04b9d474d2065'),
    ('CE25', 'SELinux matrix v4', 'accessChecks'): (25, 'bcef88c752723f9c'),
    ('CE25', 'W01 amendment W02D', 'specSections'): (1, 'f2d3331861f17b20'),
    ('CE27', 'SELinux matrix v4', 'accessChecks'): (18, '9354c741eea6fd6e'),
    ('CE27', 'Seccomp allowlists v2', 'decisionChecks'): (78, '40d0abcaae815c6c'),
    ('CE27', 'Native qualification profile v3', 'negative'): (1, '022ba278a0b38716'),
    ('CE27', 'W01 amendment W02D', 'specSections'): (2, '9f11cf553ac51150'),
    ('CE28', 'SELinux matrix v4', 'accessChecks'): (23, '4e50ca737e486b39'),
    ('CE28', 'Native qualification profile v3', 'negative'): (1, '46165daa97b98f17'),
    ('CE28', 'W01 amendment W02D', 'specSections'): (2, '5b2d25a198f6b851'),
    ('MATRIX:policy/load/boolean/relabel', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'bf3d2191e215de96'),
    ('MATRIX:namespaces/mount aliases', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, 'c28cd396a5e13537'),
    ('MATRIX:effective BPF ancestors', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, '26e2b663c8399b7c'),
    ('MATRIX:mappings/injection', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, '51afa6f61e345ec3'),
    ('MATRIX:parent/FD spoof', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, '836cadeb97df5ea0'),
    ('LEDGER-E01', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'e7e7dd241b31082d'),
    ('LEDGER-E02', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'd134709e21f92151'),
    ('S8-KERNEL-FACTS', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, '0a05c4987129a9a9'),
    ('S8-POLICYLOAD', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, 'bf3d2191e215de96'),
    ('S8-FREEZE', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, 'cbb06acd92327e99'),
    ('S8-CLOSURE', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (3, '7681beb8f9a8f860'),
    ('O-T04-AMEND', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (3, 'b23902e0af5fe3e6'),
    ('CE19', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, 'edc0191173de00ee'),
    ('CE25', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (2, 'e4b00c401cae02c6'),
    ('CE27', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, '26e2b663c8399b7c'),
    ('CE28', 'Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)', 'obligationRows'): (1, '26e2b663c8399b7c'),
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
                self.assertEqual((row["probe"], row["probeIn"], row["verdicts"]), (None, "CONF-ENF-005", []))


class SelectionTests(unittest.TestCase):
    def test_every_selection_is_pinned_and_anchored(self):
        selections = {(row["case"], row["contract"], row["vectorSet"]): row["ids"] for row in _catalog.native_catalog(GROUP)}
        self.assertEqual(set(selections), set(ANCHORS))
        self.assertEqual({key: pin(ids) for key, ids in selections.items()}, SELECTION_PINS)
        for key, ids in selections.items():
            with self.subTest(selection=key):
                self.assertLessEqual(ANCHORS[key], set(ids))
                self.assertEqual(len(set(ids)), len(ids))

    def test_every_case_has_rows_and_every_row_names_its_source(self):
        plan_group = next(row for row in _models.data(_catalog.PLAN)["testGroups"] if row["id"] == GROUP)
        cases = {row["tag"] for row in plan_group["cases"]}
        self.assertEqual({row["case"] for row in _catalog.native_catalog(GROUP)}, cases)
        messages = _catalog.model_rule_messages(_catalog.NATIVE_MODEL)
        refusals = {row["refusal"] for row in _models.data(_catalog.NATIVE)["negative"]}
        for row in _catalog.native_catalog(GROUP):
            with self.subTest(selection=(row["case"], row["contract"], row["vectorSet"])):
                self.assertTrue(row["ids"])
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
        plan_group = next(row for row in _models.data(_catalog.PLAN)["testGroups"] if row["id"] == GROUP)
        self.assertLessEqual({row["contract"] for row in _catalog.native_catalog(GROUP)},
                             set(plan_group["contracts"]) | {_catalog.FEASIBILITY_NAME})

    def test_o_t04_amend_covers_every_seccomp_decision_of_both_architectures(self):
        rows = {row["vectorSet"]: row["ids"] for row in _catalog.native_catalog(GROUP) if row["case"] == "O-T04-AMEND"}
        vectors = _models.data(_catalog.SECCOMP)
        self.assertEqual(rows["decisionChecks"], [row["id"] for row in vectors["decisionChecks"]])
        self.assertEqual({row["arch"] for row in vectors["decisionChecks"]}, {"x86_64", "aarch64"})
        self.assertEqual(rows["workerStackChecks"], [row["id"] for row in vectors["workerStackChecks"]])


class RouteTests(unittest.TestCase):
    def test_every_case_waits_for_the_probe_route_and_lists_its_permissions_with_its_probe(self):
        # Owner decision Q-T14 (2026-10-13): the route is decided in W06; each probe's permissions come with it (CONF-ENF-005).
        value = ledger()
        self.assertEqual(value["blockers"], [_catalog.PROBE_ROUTE])
        for row in value["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual(row["blockedBy"], ["D-W02A-F2", "D-PROBE-ROUTE"])
                # Review D2-11: not listed yet (null), rather than an empty list that would read as "needs nothing".
                self.assertEqual((row["permissions"], row["permissionsIn"], row["harnessRestore"]), (None, "CONF-ENF-005", None))


class CarryTests(unittest.TestCase):
    def test_the_e09_carry_is_closed_from_both_sides_and_its_checks_come_with_conf_enf_005(self):
        carried_here = {(row["tag"], item["property"]) for row in ledger()["cases"] for item in row["carries"]}
        expected = {(carrier.split(" ", 1)[1], name) for name, carriers in test_reader_guards.CARRIED.items()
                    for carrier in carriers if carrier.startswith(GROUP + " ")}
        self.assertEqual(carried_here, expected)
        for row in ledger()["cases"]:
            for item in row["carries"]:
                self.assertEqual((item["case"], item["checks"], row["probeIn"]), ("LEDGER-E09", [], "CONF-ENF-005"))


if __name__ == "__main__":
    unittest.main()
