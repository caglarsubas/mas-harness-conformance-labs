from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from harness_conformance.errors import ConformanceError

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("validate_registry", ROOT / "parity/adapters/validate_registry.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RegistryTests(unittest.TestCase):
    def test_registry_and_vectors_pass_without_source_access(self) -> None:
        results = MODULE.validate_registry(ROOT)
        self.assertEqual(len(results), 7)
        self.assertEqual(sum(item["status"] == "PASS" for item in results), 6)
        self.assertEqual(sum(item["status"] == "WARN" for item in results), 1)

    def test_registry_contains_no_content_or_copy_authority(self) -> None:
        registry = json.loads((ROOT / "parity/registry.yaml").read_text())
        serialized = json.dumps(registry)
        for token in ('"content"', '"bytes"', '"copyAuthorization"', '"sourceOutput"'):
            self.assertNotIn(token, serialized)
        self.assertTrue(all(item["reuseDisposition"] == "REFERENCE_ONLY_PENDING_PATH_REVIEW" for item in registry["records"]))

    def test_unknown_object_relation_and_binding_fail(self) -> None:
        registry = json.loads((ROOT / "parity/registry.yaml").read_text())
        cases = []
        wrong_object = copy.deepcopy(registry)
        wrong_object["records"][0]["gitObject"] = "0" * 40
        cases.append(wrong_object)
        wrong_relation = copy.deepcopy(registry)
        wrong_relation["vectors"][0]["expectedRelation"] = "ASSUMED"
        cases.append(wrong_relation)
        wrong_binding = copy.deepcopy(registry)
        wrong_binding["vectors"][0]["records"] = ["unknown"]
        cases.append(wrong_binding)
        for registry_case in cases:
            with self.subTest(), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "parity").mkdir()
                (root / "parity/registry.yaml").write_text(json.dumps(registry_case), encoding="utf-8")
                for vector in registry_case["vectors"]:
                    target = root / vector["fixture"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = ROOT / vector["fixture"]
                    target.write_bytes(source.read_bytes())
                with self.assertRaises(ConformanceError):
                    MODULE.validate_registry(root)


if __name__ == "__main__":
    unittest.main()
