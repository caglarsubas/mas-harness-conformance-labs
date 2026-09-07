import ast
import hashlib
import importlib.util
import unittest

from _fixtures import ROOT
from harness_conformance.canonical import load_json


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class LinuxInventoryTests(unittest.TestCase):
    def test_all_five_suites_collect_every_module_and_preserve_all_83_predecessors(self):
        source = ROOT / "tests/fixes/runner_boundary/_inventory.py"
        spec = importlib.util.spec_from_file_location("linux_predecessor_inventory", source)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        legacy = load_json(ROOT / "fixtures/platform/linux-baseline/predecessor-inventory.json")["tests"]
        self.assertEqual(sum(map(len, legacy.values())), 83)
        for root in ("tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary", "tests/platform/linux_baseline"):
            inventory = helper.discover_inventory(ROOT / root)
            self.assertGreater(sum(map(len, inventory.values())), 0)
            for file, methods in legacy.items():
                if file.startswith(root + "/"):
                    self.assertTrue(set(methods) <= set(inventory[file[len(root) + 1:]]))
            print(f"linux-test-inventory root={root} modules={len(inventory)} cases={sum(map(len, inventory.values()))} status=PASS", flush=True)

    def test_original_files_are_unchanged_except_ten_authorized_integrations(self):
        baseline = load_json(ROOT / "fixtures/platform/linux-baseline/predecessor-inventory.json")
        mutable = {"src/harness_conformance/" + name for name in ("campaign.py", "cli.py", "live.py", "live_launcher.py", "models.py", "schema.py")}
        mutable |= {"schemas/v1alpha1/" + name + ".schema.json" for name in ("conformance-campaign", "control-result")}
        mutable |= {"tests/meta/test_canonical_schema.py", "tests/meta/test_registry_dispatch.py"}
        self.assertEqual(len(baseline["files"]), 91)
        for file, expected in baseline["files"].items():
            path = ROOT / file
            with self.subTest(file=file):
                self.assertFalse(path.is_symlink())
                self.assertEqual(bool(path.stat().st_mode & 0o111), expected["mode"] == "100755")
                if file not in mutable:
                    self.assertEqual(blob(path.read_bytes()), expected["blob"])

    def test_legacy_three_file_edits_and_registry_addition_are_exact(self):
        cases = (
            ("src/harness_conformance/models.py", b'    "LINUX_READINESS",\n', b"", "f94ba09d491ce716875f259d81d17f38c1b7786d45db1ad700eaf9a0c7cf14a4"),
            ("schemas/v1alpha1/control-result.schema.json", b', "LINUX_READINESS"', b"", "8dd30591c96d6d023d706336ceae630a838182dd0efa3e08e11e314f4594427b"),
            ("tests/meta/test_canonical_schema.py", b'self.assertEqual(HANDLERS, ("STATIC_ASSERTION", "SCHEMA_ASSERTION", "LIFECYCLE_ASSERTION", "EVENT_ASSERTION", "ENVIRONMENT_CAPABILITY", "LINUX_READINESS"))',
             b"self.assertEqual(len(HANDLERS), 5)", "4ff004974fc75c6ea15010eedb9d1596c002330b33596c64a888622f0bd02c8f"),
        )
        for file, addition, original, digest in cases:
            data = (ROOT / file).read_bytes()
            self.assertEqual(data.count(addition), 1)
            self.assertEqual(hashlib.sha256(data.replace(addition, original, 1)).hexdigest(), digest)
        baseline = load_json(ROOT / "fixtures/platform/linux-baseline/predecessor-inventory.json")
        file = "tests/meta/test_registry_dispatch.py"
        data = (ROOT / file).read_bytes()
        self.assertEqual(data.count(b', "linux-baseline"'), 1)
        self.assertEqual(blob(data.replace(b', "linux-baseline"', b"", 1)), baseline["files"][file]["blob"])

    def test_legacy_comparison_sources_are_pinned_owned_baseline_bytes(self):
        baseline = load_json(ROOT / "fixtures/platform/linux-baseline/predecessor-inventory.json")
        snapshot = load_json(ROOT / "fixtures/platform/linux-baseline/predecessor-sources.json")
        self.assertEqual(snapshot["commit"], baseline["commit"])
        self.assertEqual(set(snapshot["sources"]), {"campaign.py", "cli.py", "schema.py", "models.py"})
        for name, content in snapshot["sources"].items():
            self.assertEqual(blob(content.encode()), baseline["files"]["src/harness_conformance/" + name]["blob"])

    def test_pure_verifier_has_no_execution_network_or_signing_primitive(self):
        tree = ast.parse((ROOT / "src/harness_conformance/linux_readiness.py").read_bytes())
        forbidden = {"subprocess", "socket", "os", "pathlib", "requests", "urllib", "http", "ctypes", "multiprocessing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse({name.name.split(".")[0] for name in node.names} & forbidden)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".")[0], forbidden)
                self.assertNotIn("sign", {name.name for name in node.names})
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "exec", "eval", "__import__", "compile"})
