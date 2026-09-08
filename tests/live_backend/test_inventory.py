import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from _fixtures import ROOT
from _inventory import (BASELINE, CURRENT, SUCCESSOR, isolated_inventory, load_baseline,
                        source_inventory, validate_checkpoint, verify_repository)
from harness_conformance.live_backend_authority import COMMANDS, PACKET_DIGEST, SUITE_ROOTS


class BackendInventoryTests(unittest.TestCase):
    def test_all_six_roots_ast_equal_actual_and_all_170_predecessors_preserved(self):
        count = 0
        for root in SUITE_ROOTS:
            observed = isolated_inventory(ROOT / root)
            expected = {path[len(root) + 1:]: methods for path, methods in CURRENT["tests"].items()
                        if path.startswith(root + "/")}
            if root != "tests/live_backend":
                self.assertEqual(observed, expected)
                count += sum(map(len, observed.values()))
            cases = sum(map(len, observed.values()))
            print(f"backend-inventory root={root} modules={len(observed)} cases={cases} status=PASS", flush=True)
        self.assertEqual(count, 170)
        self.assertEqual(tuple(BASELINE["suiteRoots"]), SUITE_ROOTS[:5])

    def test_all_110_accepted_files_are_fixed_with_only_closed_final_hook_proof(self):
        self.assertEqual(CURRENT["commit"], "01ef8b1ca9e86ae36331c82d6d552fcc9f236221")
        self.assertEqual(CURRENT["tree"], "9860515758052c17174c33321a8eb017106cf29b")
        self.assertEqual(len(CURRENT["files"]), 110)
        result = verify_repository(ROOT)
        self.assertEqual(result["evidenceClass"], "SOURCE_INVENTORY_ONLY")
        self.assertIs(result["nativeAcceptance"], False)
        self.assertEqual(result["trackedFiles"], (110, 120, 127, 135, 141, 146, 151)[result["stage"]])

    def test_original_103_120_and_scalar_106_150_histories_remain_separate(self):
        scalar = json.loads(CURRENT["scalarBaselineRaw"])
        historical = json.loads(scalar["historical103Raw"])
        self.assertEqual(len(BASELINE["files"]), 103)
        self.assertEqual(sum(map(len, BASELINE["tests"].values())), 120)
        self.assertEqual(BASELINE["commit"], "88de1d9b7272a25678b01129e51d5756dbe608ed")
        self.assertEqual(BASELINE["tree"], "71270ce85626c71680a42435423b7537870964cb")
        self.assertEqual(len(scalar["files"]), 106)
        self.assertEqual(sum(map(len, scalar["tests"].values())), 150)
        self.assertEqual(len(historical["files"]), 103)
        self.assertEqual(sum(map(len, historical["tests"].values())), 120)
        for path, ids in BASELINE["tests"].items():
            self.assertEqual(CURRENT["tests"][path], ids)
        for path, ids in scalar["tests"].items():
            self.assertEqual(CURRENT["tests"][path], ids)
        self.assertEqual(CURRENT["draft"]["status"], "CANCELLED_NOT_PASS")
        self.assertEqual(CURRENT["closure"]["main"], CURRENT["commit"])
        self.assertEqual(CURRENT["closure"]["mainReplay"]["tests"], 170)
        self.assertFalse(CURRENT["closure"]["nativeAcceptance"])

    def test_tracked_inventory_has_only_complete_ordered_packet_stages(self):
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        result = validate_checkpoint(rows, sources)
        expected = set(CURRENT["files"])
        for stage in range(1, result["stage"] + 1):
            expected.update(BASELINE["packetPaths"][f"CONF-LIVE-{stage:03d}"])
        self.assertEqual({row["path"] for row in rows}, expected)
        for row in rows:
            if row["path"] in BASELINE["packetPaths"]["CONF-LIVE-001"]:
                with self.subTest(missing=row["path"]), self.assertRaises(ValueError):
                    validate_checkpoint([r for r in rows if r is not row], sources)

    def test_presence_of_integration_file_never_exempts_launcher(self):
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        changed = dict(sources)
        changed["src/harness_conformance/live_backend_campaign.py"] = b"# inert adversarial presence\n"
        changed["src/harness_conformance/live_launcher.py"] += b"# unapproved delta\n"
        with self.assertRaises(ValueError):
            validate_checkpoint(rows, changed)

    def test_all_four_accepted_correction_additions_are_hash_bound(self):
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        for path in SUCCESSOR.RECORD["repairPaths"]:
            altered_rows, altered_sources = deepcopy(rows), dict(sources)
            altered_sources[path] += b"\n"
            row = next(r for r in altered_rows if r["path"] == path)
            row.update(size=len(altered_sources[path]), sha256=hashlib.sha256(altered_sources[path]).hexdigest())
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_checkpoint(altered_rows, altered_sources)

    def test_baseline_tampering_and_duplicate_members_refuse(self):
        raw = (ROOT / "fixtures/live-backend/baseline.json").read_bytes()
        for altered in (raw + b"\n", b'{"a":1,"a":2}', b"{}", raw.replace(b"CANCELLED_NOT_PASS", b"PASS")):
            with self.subTest(size=len(altered)), self.assertRaises(ValueError):
                load_baseline(altered)

    def test_linked_root_ancestor_and_hardlinked_test_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            real = Path(folder).resolve()
            root = real / "suite"
            root.mkdir()
            source = root / "test_link.py"
            source.write_text("import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n")
            link = real / "alias"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                source_inventory(link)
            nested = root / "nested"
            nested.mkdir()
            with self.assertRaises(ValueError):
                source_inventory(link / "nested")
            os.link(source, real / "hardlink")
            with self.assertRaises(ValueError):
                source_inventory(root)

    def test_authority_source_and_model_release_are_exact_nonexecuting_pins(self):
        self.assertEqual(BASELINE["metaCommit"], "50cfd3f13c6942bc7a6995d463482a390db0a98e")
        self.assertEqual(BASELINE["modelContractsCommit"], "e9de8e53cf036a90a03b1e114eba08fc0ba89ae3")
        self.assertEqual(BASELINE["modelContractFiles"]["contracts/release-manifest.json"],
                         "sha256:5c4ee8e23676083f97bdc8f63be127314ca27c85fb8b724760e1f3ed1c9a14ad")
        self.assertEqual(BASELINE["authorityFiles"]["task-packets/CONF-LIVE-006.yaml"], PACKET_DIGEST)
        self.assertEqual(BASELINE["commands"], [list(argv) for argv in COMMANDS])
        self.assertEqual(len(COMMANDS), 8)
        self.assertEqual(BASELINE["originalTestCount"], 120)
        self.assertEqual(BASELINE["evidenceClass"], "SOURCE_INVENTORY_ONLY")
        self.assertIs(BASELINE["nativeAcceptance"], False)

    def test_new_runtime_modules_have_no_io_signing_or_legacy_verifier_substitution(self):
        forbidden = {"os", "pathlib", "subprocess", "socket", "http", "urllib", "ctypes", "pickle", "marshal", "importlib"}
        for name in ("live_session.py", "live_backend_authority.py"):
            tree = ast.parse((ROOT / "src/harness_conformance" / name).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                    self.assertFalse({m.split(".")[0] for m in modules} & forbidden)
                    self.assertFalse({a.name for a in node.names} & {"sign", "verify_linux_authority", "preflight", "secure_read", "load_json"})
                if isinstance(node, ast.Call):
                    func = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                    self.assertNotIn(func, {"open", "exec", "eval", "__import__", "compile", "sign", "verify_linux_authority", "getenv", "setattr"})

    def test_inventory_rejects_empty_duplicate_hidden_and_non_test_method(self):
        cases = ["", "import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n def test_ok(self): pass\n",
                 "class T:\n def test_not_collected(self): pass\n",
                 "import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\ndef load_tests(loader, tests, pattern): return unittest.TestSuite()\n"]
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "test_discovery_negative.py"
                path.write_text(source)
                with self.assertRaises(ValueError):
                    isolated_inventory(path.parent)

    def test_inventory_rejects_skip_and_expected_failure_and_namespace_omission(self):
        for decorator in ('unittest.skip("fixture-only negative")', "unittest.expectedFailure"):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "test_discovery_negative.py"
                path.write_text("import unittest\nclass T(unittest.TestCase):\n @" + decorator + "\n def test_ok(self): pass\n")
                with self.assertRaises(ValueError):
                    isolated_inventory(path.parent)
        with tempfile.TemporaryDirectory() as folder:
            nested = Path(folder) / "uncollected"
            nested.mkdir()
            (nested / "test_nested.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_hidden(self): pass\n")
            with self.assertRaises(ValueError):
                source_inventory(Path(folder))

    def test_inventory_roots_with_colliding_module_names_remain_independent(self):
        # No preloading of a foreign _fixtures/test_inventory module can replace
        # either suite in the fresh-child collection used by the real gate.
        for root in ("tests/fixes/runner_boundary", "tests/live_backend"):
            self.assertEqual(isolated_inventory(ROOT / root), source_inventory(ROOT / root))
