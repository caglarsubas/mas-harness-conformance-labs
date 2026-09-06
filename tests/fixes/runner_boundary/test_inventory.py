from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from _inventory import discover_inventory

ROOT = Path(__file__).resolve().parents[3]
SUITES = ("tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary")


class InventoryTests(unittest.TestCase):
    def test_all_four_suites_collect_every_module_and_keep_legacy_cases(self):
        legacy = json.loads((Path(__file__).parent / "legacy-tests.json").read_text())
        for suite in SUITES:
            with self.subTest(suite=suite):
                inventory = discover_inventory(ROOT / suite)
                count = sum(len(methods) for methods in inventory.values())
                self.assertGreater(count, 0)
                for file, methods in legacy.items():
                    if file.startswith(suite + "/"):
                        self.assertTrue(set(methods) <= set(inventory[file[len(suite) + 1:]]))
                print(f"test-inventory root={suite} modules={len(inventory)} cases={count} status=PASS", flush=True)

    def temporary_inventory(self, content, *, nested=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "unpackaged" if nested else root
            target.mkdir(exist_ok=True)
            (target / "test_inventory_fixture.py").write_text(content)
            try:
                return discover_inventory(root)
            finally:
                sys.modules.pop("test_inventory_fixture", None)

    def test_added_file_is_collected_without_manual_registration(self):
        value = self.temporary_inventory("import unittest\nclass Added(unittest.TestCase):\n def test_new(self): pass\n")
        self.assertEqual(value, {"test_inventory_fixture.py": ["Added.test_new"]})

    def test_nested_unimportable_new_file_cannot_be_silently_omitted(self):
        with self.assertRaises(ValueError):
            self.temporary_inventory("import unittest\nclass Added(unittest.TestCase):\n def test_new(self): pass\n", nested=True)

    def test_empty_or_import_broken_module_fails(self):
        for content in ("", "import missing_inventory_fixture_module\nclass X:\n def test_x(self): pass\n"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.temporary_inventory(content)

    def test_load_tests_cannot_hide_or_duplicate_a_case(self):
        base = "import unittest\nclass Added(unittest.TestCase):\n def test_new(self): pass\n"
        for content in (base + "def load_tests(loader, tests, pattern): return unittest.TestSuite()\n",
                        base + "def load_tests(loader, tests, pattern): return unittest.TestSuite([tests, tests])\n"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.temporary_inventory(content)

    def test_skipped_or_expected_failure_cannot_hide_a_case(self):
        for decorator in ('unittest.skip("hidden")', 'unittest.expectedFailure'):
            with self.subTest(decorator=decorator), self.assertRaises(ValueError):
                self.temporary_inventory("import unittest\nclass Added(unittest.TestCase):\n @" + decorator + "\n def test_new(self): pass\n")

    def test_missing_or_empty_root_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                discover_inventory(Path(folder) / "absent")
            with self.assertRaises(ValueError):
                discover_inventory(Path(folder))
