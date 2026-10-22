"""CONF-MAS-001: the committed ledger is reproduced byte for byte; the gates hold; the data files are closed; the code uses
only the standard library and no order that depends on hashing."""
from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path

import _ledger

HERE = Path(__file__).resolve().parent
CONFIG, CLASSES_SHA = _ledger.load_config()
CODE = ("_sim.py", "_classes.py", "_ledger.py")
ALLOWED_IMPORTS = {"__future__", "hashlib", "json", "pathlib", "_sim", "_classes"}
RATIOS = ("duplicatedWorkRatioPpm", "lostWorkPpm", "completionPpm")
# Q-MAS1-F1 (a), owner, 2026-10-19: the bounds are kept and the ledger is asserted as recorded. C2 FAILs its
# duplicated-work bound only (revision exhaustion under 25% poisoning); every other gate of every class holds.
# Q3-2 (a), owner, 2026-10-20: C5's and C7's duplicated-work bound is preregistered as an expected FAIL (packet 1's carried
# revision exhaustion, MAS1-CARRY-1). Any other or missing FAIL is recorded as it reads and reported to the lane monitor;
# this dict changes only with a recorded disposition.
# Q-D3-1 (a), owner, 2026-10-20: C9's duplicated-work bound is preregistered as an expected FAIL, by construction (its
# events' explained duplicates: E2's four and E1's two; CONF-MAS-003 DESIGN revision 6, section 5).
RECORDED_FAILS = {"C2": {"duplicatedWorkRatioPpm"}, "C5": {"duplicatedWorkRatioPpm"}, "C7": {"duplicatedWorkRatioPpm"},
                  "C9": {"duplicatedWorkRatioPpm"}}


class LedgerTests(unittest.TestCase):
    def test_the_committed_ledger_is_regenerated_byte_for_byte(self):
        """CI's python3 uses its own hash seed, so this comparison also catches any dependence on hash order."""
        self.assertEqual(_ledger.serialize(_ledger.ledger()), (HERE / "results.json").read_bytes())

    def test_a_second_in_process_build_is_identical(self):
        self.assertEqual(_ledger.serialize(_ledger.build()), _ledger.serialize(_ledger.ledger()))

    def test_every_gate_holds_except_the_recorded_c2_finding(self):
        for row in _ledger.ledger()["classes"]:
            gates, failing = row["gates"], RECORDED_FAILS.get(row["id"], set())
            self.assertTrue(gates["defendedZeroAndEvents"], row["id"])
            self.assertEqual(gates["ratioBounds"], {name: name not in failing for name in RATIOS}, row["id"])
            self.assertTrue(gates["controlsFireInAllSeeds"], row["id"])
            self.assertTrue(gates["depthChecksHoldInAllSeeds"], row["id"])
            self.assertEqual(row["result"], "FAIL" if failing else "PASS", row["id"])

    def test_the_ledger_is_closed_and_bound_to_its_parameters(self):
        value = _ledger.ledger()
        # CONF-MAS-004 (DESIGN revision 5, section 10): the ledger v4 adds `scaling`, `hardCoding`, C11 and C12.
        # CONF-MAS-005 (DESIGN revision 3, section 10): the ledger v5 adds `overRevision` and C13.
        self.assertEqual(sorted(value), ["arms", "classes", "classesSha256", "contractsCommit", "hardCoding",
                                         "overRevision", "packet", "profile", "rule", "scaling", "schemaVersion",
                                         "seeds"])
        self.assertEqual((value["schemaVersion"], value["packet"], value["classesSha256"], value["seeds"]),
                         ("r12.mas-simulation-results/v5", "CONF-MAS-005", CLASSES_SHA, list(range(1, 33))))
        self.assertEqual([row["id"] for row in value["classes"]],
                         ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13"])
        for row in value["classes"]:
            extra = ["measurements"] if row["id"] in ("C5", "C8", "C9") else []
            self.assertEqual(sorted(row), sorted(["controls", "defended", "depthChecks", "gates", "id", "kind",
                                                  "parameters", "result", "unexercisedInvariants"] + extra))
            self.assertIn(row["result"], ("PASS", "FAIL"))

    def test_no_canary_value_reaches_the_ledger(self):
        self.assertNotIn(b"CANARY-", (HERE / "results.json").read_bytes())


class DataFileTests(unittest.TestCase):
    def test_classes_json_is_preregistered_data(self):
        raw = (HERE / "classes.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), CLASSES_SHA)
        # CONF-MAS-005 (section 10): the top-level key `overRevision`.
        self.assertEqual(sorted(CONFIG), ["arms", "bounds", "classes", "controlGate", "grantTicks", "hardCoding",
                                          "inputSchemas", "instructions", "manifest", "overRevision", "packet",
                                          "profiles", "scaling", "schemaVersion", "seeds", "shared", "streams",
                                          "topologies", "unexercisedInvariants", "zeroTolerance"])
        self.assertEqual(CONFIG["seeds"], list(range(1, 33)))
        self.assertEqual(CONFIG["controlGate"]["mustFireSeeds"], 32)
        self.assertTrue(all(":" not in name for name in CONFIG["streams"]))
        self.assertEqual(CONFIG["shared"]["leaseTicks"], 8)
        self.assertEqual(CONFIG["shared"]["items"], 20)
        kinds = {c["kind"] for c in CONFIG["classes"]}
        self.assertEqual(kinds, {"PEER_INJECTION", "POISONED_TOOL_RESULT", "REPLAY_STALE", "CLAIM_CONFLICT",
                                 "COLLUSION_CONFLICTING_OBJECTIVES", "CROSS_AGENT_EXFILTRATION", "RESOURCE_EXHAUSTION",
                                 "AGENT_LOSS_PARTIAL_OBSERVABILITY", "DEADLOCK_LIVELOCK", "MERGE_CORRECTNESS",
                                 "REGRESSION_ONLY_PASS", "DEGENERATE_SUBMISSION", "TRUST_BOUNDARY"})
        text = raw.decode("ascii")
        for forbidden in ("import", "lambda", "exec(", "http", "module", "handler"):
            self.assertNotIn(forbidden, text)  # declarative data: no code, module or handler names

    def test_contracts_json_pins_the_ten_files(self):
        # The name is packet 1's; CONF-MAS-004 (section 2) adds an eleventh row, check-kinds.json, at the same commit;
        # CONF-MAS-005 (section 2) adds the twelfth and thirteenth, the harness documents H11 and H13.
        pins = json.loads((HERE / "contracts.json").read_text())
        self.assertEqual(sorted(pins), ["commit", "files", "note", "schemaVersion"])
        self.assertEqual(pins["commit"], _ledger.CONTRACTS_COMMIT)
        self.assertEqual(len(pins["files"]), 13)
        for i, row in enumerate(pins["files"]):
            self.assertEqual(sorted(row), ["packet", "path", "sha256", "size"])
            self.assertTrue(row["path"].startswith("architecture/" if i < 11 else "docs/harnesses/"))
            self.assertEqual(len(row["sha256"]), 64)

    def test_attestation_is_closed(self):
        att = json.loads((HERE / "attestation.json").read_text())
        self.assertFalse(att["warmSourceRead"])
        self.assertFalse(att["r10SourceRead"])
        self.assertFalse(att["w03WorkInProgressRead"])
        self.assertTrue(all(name.startswith("<harness-onion>/") and name.endswith("@27c54605")
                            for name in att["inputs"]))


class CodeTests(unittest.TestCase):
    def _trees(self):
        return {name: ast.parse((HERE / name).read_text()) for name in CODE}

    def test_standard_library_only(self):
        for name, tree in sorted(self._trees().items()):
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    modules = {(node.module or "").split(".")[0]}
                else:
                    continue
                self.assertTrue(modules <= ALLOWED_IMPORTS, (name, modules))

    def test_no_order_that_depends_on_hashing(self):
        """No hash() or id(), and no loop or comprehension over a set expression unless it is wrapped in sorted()."""
        for name, tree in sorted(self._trees().items()):
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("hash", "id"), name)
                iters = []
                if isinstance(node, ast.For):
                    iters.append(node.iter)
                elif isinstance(node, ast.comprehension):
                    iters.append(node.iter)
                for it in iters:
                    is_set = isinstance(it, (ast.Set, ast.SetComp)) or (
                        isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id in ("set", "frozenset"))
                    self.assertFalse(is_set, (name, ast.dump(it)[:80]))


if __name__ == "__main__":
    unittest.main()
