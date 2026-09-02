from __future__ import annotations

import json
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

from harness_conformance.errors import ConformanceError
from harness_conformance.schema import validate_porting

ROOT = Path(__file__).resolve().parents[2]


class PortingZeroBillTests(unittest.TestCase):
    def test_porting_ledger_is_exact_inert_sentinel(self) -> None:
        expected = (
            "schemaVersion: harness.planeon.ai/porting-ledger/v1alpha1\n"
            "destinationRepository: mas-harness-conformance-labs\n"
            "records:\n"
            "  - disposition: NO_AUTHORIZATION\n"
            "    reason: No source path is authorized for copying, adaptation, translation, or derivative reuse.\n"
        )
        self.assertEqual((ROOT / "PORTING.yaml").read_text(encoding="utf-8"), expected)
        validate_porting({"schemaVersion": "harness.planeon.ai/porting-ledger/v1alpha1", "destinationRepository": "mas-harness-conformance-labs", "records": [{"disposition": "NO_AUTHORIZATION", "reason": "closed"}]})

    def test_every_copy_claim_is_rejected(self) -> None:
        base = {"schemaVersion": "harness.planeon.ai/porting-ledger/v1alpha1", "destinationRepository": "mas-harness-conformance-labs", "records": [{"disposition": "NO_AUTHORIZATION", "reason": "closed"}]}
        for field in ("sourceRepository", "sourceCommit", "sourcePath", "destinationPath", "authorizationId", "mapping", "copiedContent"):
            value = json.loads(json.dumps(base))
            value["records"][0][field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                validate_porting(value)

    def test_workflow_and_toolchain_are_zero_bill(self) -> None:
        workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        self.assertIn("self-hosted", workflow)
        self.assertIn("credential-free", workflow)
        self.assertIn("persist-credentials: false", workflow)
        for token in ("ubuntu-latest", "actions/cache", "upload-artifact", "schedule:"):
            self.assertNotIn(token, workflow)
        lock = json.loads((ROOT / "toolchain.lock").read_text())
        self.assertEqual(lock["dependencies"], [])
        self.assertFalse(lock["workflow"]["hostedRunner"])

    def test_zero_bill_scanner_rejects_each_declared_vector(self) -> None:
        spec = importlib.util.spec_from_file_location("zero_bill", ROOT / "ci/zero_bill.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for token in module.WORKFLOW_FORBIDDEN:
            with self.subTest(vector=token), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary)
                (target / ".github/workflows").mkdir(parents=True)
                workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8") + f"\n# {token}\n"
                (target / ".github/workflows/verify.yml").write_text(workflow, encoding="utf-8")
                (target / "src").mkdir()
                shutil.copyfile(ROOT / "pyproject.toml", target / "pyproject.toml")
                shutil.copyfile(ROOT / "toolchain.lock", target / "toolchain.lock")
                with self.assertRaises(RuntimeError):
                    module.validate(target)
        for token in module.SOURCE_FORBIDDEN:
            with self.subTest(vector=token), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary)
                (target / ".github/workflows").mkdir(parents=True)
                shutil.copyfile(ROOT / ".github/workflows/verify.yml", target / ".github/workflows/verify.yml")
                (target / "src").mkdir()
                (target / "src/bad.py").write_text(token, encoding="utf-8")
                shutil.copyfile(ROOT / "pyproject.toml", target / "pyproject.toml")
                shutil.copyfile(ROOT / "toolchain.lock", target / "toolchain.lock")
                with self.assertRaises(RuntimeError):
                    module.validate(target)


if __name__ == "__main__":
    unittest.main()
