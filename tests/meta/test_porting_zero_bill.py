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
        # CONF-CI-002: the owner-operated verifier replaced the pinned workflow, so the repository carries none.
        self.assertEqual(sorted((ROOT / ".github").rglob("*")) if (ROOT / ".github").exists() else [], [])
        lock = json.loads((ROOT / "toolchain.lock").read_text())
        self.assertEqual(lock["dependencies"], [])
        self.assertFalse(lock["workflow"]["hostedRunner"])
        module = _zero_bill()
        module.validate(ROOT)

    def test_zero_bill_scanner_rejects_each_declared_vector(self) -> None:
        module = _zero_bill()
        for token in module.WORKFLOW_FORBIDDEN:
            with self.subTest(vector=token), tempfile.TemporaryDirectory() as temporary:
                target = _scratch(Path(temporary))
                (target / ".github/workflows").mkdir(parents=True)
                (target / ".github/workflows/verify.yml").write_text(_SELF_HOSTED + f"\n# {token}\n", encoding="utf-8")
                with self.assertRaises(RuntimeError):
                    module.validate(target)
        for token in module.SOURCE_FORBIDDEN:
            with self.subTest(vector=token), tempfile.TemporaryDirectory() as temporary:
                target = _scratch(Path(temporary))
                (target / "src/bad.py").write_text(token, encoding="utf-8")
                with self.assertRaises(RuntimeError):
                    module.validate(target)
        with self.subTest(case="no workflow passes"), tempfile.TemporaryDirectory() as temporary:
            module.validate(_scratch(Path(temporary)))
        with self.subTest(case="one self-hosted workflow passes"), tempfile.TemporaryDirectory() as temporary:
            target = _scratch(Path(temporary))
            (target / ".github/workflows").mkdir(parents=True)
            (target / ".github/workflows/verify.yml").write_text(_SELF_HOSTED, encoding="utf-8")
            module.validate(target)
        for case, files in (("two workflows", {"a.yml": _SELF_HOSTED, "b.yaml": _SELF_HOSTED}),
                            ("hosted workflow", {"verify.yml": "jobs:\n  verify:\n    runs-on: [self-hosted]\n"})):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                target = _scratch(Path(temporary))
                (target / ".github/workflows").mkdir(parents=True)
                for name, text in files.items():
                    (target / ".github/workflows" / name).write_text(text, encoding="utf-8")
                with self.assertRaises(RuntimeError):
                    module.validate(target)


_SELF_HOSTED = ("jobs:\n  verify:\n    runs-on: [self-hosted, credential-free]\n    steps:\n"
                "      - uses: actions/checkout@pinned\n        with:\n          persist-credentials: false\n")


def _zero_bill():
    spec = importlib.util.spec_from_file_location("zero_bill", ROOT / "ci/zero_bill.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scratch(target: Path) -> Path:
    (target / "src").mkdir()
    shutil.copyfile(ROOT / "pyproject.toml", target / "pyproject.toml")
    shutil.copyfile(ROOT / "toolchain.lock", target / "toolchain.lock")
    return target

if __name__ == "__main__":
    unittest.main()
