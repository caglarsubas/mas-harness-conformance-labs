from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

from harness_conformance.canonical import canonical_bytes
from harness_conformance.errors import ConformanceError

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("run_parity", ROOT / "parity/adapters/run_parity.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REGISTRY = json.loads((ROOT / "parity/registry.yaml").read_text())


class AdapterTests(unittest.TestCase):
    def test_every_vector_is_deterministic(self) -> None:
        for entry in REGISTRY["vectors"]:
            vector = json.loads((ROOT / entry["fixture"]).read_text())
            with self.subTest(vector=entry["vectorId"]):
                self.assertEqual(canonical_bytes(MODULE.execute(vector, entry)), canonical_bytes(MODULE.execute(vector, entry)))

    def test_altered_expectation_fails_exact(self) -> None:
        entry = REGISTRY["vectors"][0]
        vector = json.loads((ROOT / entry["fixture"]).read_text())
        vector["expected"] = {"tenantNeutral": False}
        self.assertEqual(MODULE.execute(vector, entry)["status"], "FAIL")

    def test_unknown_family_and_unbound_vector_fail(self) -> None:
        entry = copy.deepcopy(REGISTRY["vectors"][0])
        vector = json.loads((ROOT / entry["fixture"]).read_text())
        entry["adapter"] = "DYNAMIC_MODULE"
        vector["family"] = "DYNAMIC_MODULE"
        with self.assertRaises(ConformanceError) as raised:
            MODULE.execute(vector, entry)
        self.assertEqual(raised.exception.reason, "UNKNOWN_PARITY_FAMILY")
        vector["vectorId"] = "different"
        with self.assertRaises(ConformanceError):
            MODULE.execute(vector, entry)

    def test_vector_shape_rejects_command_url_and_credentials(self) -> None:
        entry = REGISTRY["vectors"][1]
        vector = json.loads((ROOT / entry["fixture"]).read_text())
        for field in ("command", "url", "credential"):
            changed = copy.deepcopy(vector)
            changed[field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                MODULE.execute(changed, entry)


if __name__ == "__main__":
    unittest.main()
