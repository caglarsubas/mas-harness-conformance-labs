import ast
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from _fixtures import ROOT
from _inventory import isolated_inventory, source_inventory
from harness_conformance.live_backend_authority import COMMANDS, PACKET_DIGEST, SUITE_ROOTS

BASELINE = json.loads((ROOT / "fixtures/live-backend/baseline.json").read_bytes())


class BackendInventoryTests(unittest.TestCase):
    def test_all_six_roots_ast_equal_actual_and_all_120_predecessors_preserved(self):
        count = 0
        for root in SUITE_ROOTS:
            observed = isolated_inventory(ROOT / root)
            for path, methods in BASELINE["tests"].items():
                if path.startswith(root + "/"):
                    self.assertEqual(observed[path[len(root) + 1:]], methods)
                    count += len(methods)
            cases = sum(map(len, observed.values()))
            if root in BASELINE["suites"]:
                self.assertEqual(BASELINE["suites"][root], {"modules": len(observed), "testCount": cases})
            print(f"backend-inventory root={root} modules={len(observed)} cases={cases} status=PASS", flush=True)
        self.assertEqual(count, 120)
        self.assertEqual(tuple(BASELINE["suiteRoots"]), SUITE_ROOTS[:5])

    def test_clean_103_file_baseline_immutable_except_final_owned_launcher_hook(self):
        self.assertEqual(BASELINE["commit"], "88de1d9b7272a25678b01129e51d5756dbe608ed")
        self.assertEqual(BASELINE["tree"], "71270ce85626c71680a42435423b7537870964cb")
        self.assertEqual(len(BASELINE["files"]), 103)
        # Only CONF-LIVE-006 owns the one existing production file. Until its
        # independently owned integration module exists, its bytes remain fixed.
        integration = ROOT / "src/harness_conformance/live_backend_campaign.py"
        for name, expected in BASELINE["files"].items():
            with self.subTest(path=name):
                path = ROOT / name
                self.assertFalse(path.is_symlink())
                self.assertTrue(path.is_file())
                self.assertEqual(bool(path.stat().st_mode & 0o111), expected["mode"] == "100755")
                if name == "src/harness_conformance/live_launcher.py" and integration.is_file():
                    continue
                raw = path.read_bytes()
                self.assertEqual(len(raw), expected["size"])
                self.assertEqual("sha256:" + hashlib.sha256(raw).hexdigest(), expected["sha256"])
                self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), expected["blob"])

    def test_tracked_inventory_has_only_closed_additive_packet_paths(self):
        result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
        tracked = set(result.stdout.decode().strip("\0").split("\0"))
        allowed = set(BASELINE["files"])
        for paths in BASELINE["packetPaths"].values():
            self.assertTrue(all(not p.endswith("/") and ".." not in p.split("/") for p in paths))
            allowed.update(paths)
        self.assertTrue(set(BASELINE["files"]) <= tracked)
        self.assertFalse(tracked - allowed, tracked - allowed)
        self.assertTrue(set(BASELINE["packetPaths"]["CONF-LIVE-001"]) <= tracked)
        # The immutable historical file hash guards above still execute; there
        # is no extension to either predecessor guard's old mutable exceptions.
        for packet, paths in BASELINE["packetPaths"].items():
            overlap = set(paths) & set(BASELINE["files"])
            self.assertEqual(overlap, {"src/harness_conformance/live_launcher.py"}
                             if packet == "CONF-LIVE-006" else set())

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
