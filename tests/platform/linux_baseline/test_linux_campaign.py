from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from _fixtures import LinuxFixture, ROOT
from harness_conformance import campaign as engine, models, schema
from harness_conformance.canonical import canonical_bytes, load_json
from harness_conformance.errors import ConformanceError
from harness_conformance.linux_readiness import ARCHITECTURES, CASES, CASE_AXES
from harness_conformance.registry import campaign_registry


class LinuxCampaignTests(unittest.TestCase):
    def assert_handler_view(self, view):
        self.assertEqual(tuple(view), ("STATIC_ASSERTION", "SCHEMA_ASSERTION", "LIFECYCLE_ASSERTION", "EVENT_ASSERTION", "ENVIRONMENT_CAPABILITY", "LINUX_READINESS"))

    def setUp(self):
        self.path = ROOT / "campaigns/platform/linux-baseline/campaign.json"
        self.campaign = load_json(self.path)
        self.environment = load_json(ROOT / self.campaign["environmentFixture"])

    def cli(self, command, campaign, repository=ROOT):
        environment = dict(os.environ, PYTHONPATH=str(repository / "src"), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-B", "-m", "harness_conformance", command,
                                 "--campaign", str(campaign), "--repository", str(repository)],
                                cwd=repository, env=environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result.stdout

    def test_all_handler_views_keep_exact_order_and_no_aliases(self):
        expected = ("STATIC_ASSERTION", "SCHEMA_ASSERTION", "LIFECYCLE_ASSERTION", "EVENT_ASSERTION", "ENVIRONMENT_CAPABILITY", "LINUX_READINESS")
        for view in (models.HANDLERS, engine.HANDLERS, schema.HANDLERS):
            self.assert_handler_view(view)
        for name, path in (("conformance-campaign", ("properties", "controls", "items", "properties", "handler", "enum")),
                           ("control-result", ("properties", "handler", "enum"))):
            value = load_json(ROOT / f"schemas/v1alpha1/{name}.schema.json")
            for part in path:
                value = value[part]
            self.assert_handler_view(value)
            for mutant in (value[:-1], value + ["EXEC"], value + [value[0]], value[::-1]):
                with self.subTest(schema=name, mutant=mutant), self.assertRaises(AssertionError):
                    self.assert_handler_view(mutant)
        for mutant in (expected[:-1], expected + ("EXEC",), expected + (expected[0],), expected[::-1]):
            with self.subTest(registry=mutant), self.assertRaises(AssertionError):
                self.assert_handler_view(mutant)
        for handler in ("LINUX", "linux_readiness", "EXEC", "NATIVE_PASS", None, []):
            changed = deepcopy(self.campaign)
            changed["controls"][0]["handler"] = handler
            with self.subTest(handler=handler), self.assertRaises(ConformanceError):
                schema.validate_campaign(changed)

    def test_twenty_required_cases_are_closed_in_runtime_and_published_schema(self):
        controls = self.campaign["controls"]
        self.assertEqual(len(controls), 20)
        self.assertEqual([(c["input"]["architecture"], c["input"]["caseId"], c["axis"]) for c in controls],
                         [(arch, case, axis) for arch in ARCHITECTURES for case, axis in zip(CASES, CASE_AXES)])
        published = load_json(ROOT / "schemas/v1alpha1/conformance-campaign.schema.json")
        self.assertEqual(published["allOf"][0]["then"]["properties"]["controls"]["const"], controls)
        for index in range(20):
            for field, value in (("required", False), ("axis", "UNIT"), ("handler", "ENVIRONMENT_CAPABILITY")):
                changed = deepcopy(self.campaign)
                changed["controls"][index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(ConformanceError):
                    schema.validate_campaign(changed)
            changed = deepcopy(self.campaign)
            changed["controls"].pop(index)
            with self.assertRaises(ConformanceError):
                schema.validate_campaign(changed)
        for controls in (controls[::-1], controls + [controls[0]], []):
            changed = dict(self.campaign, controls=controls)
            with self.assertRaises(ConformanceError):
                schema.validate_campaign(changed)

    def test_environment_flags_and_session_variables_never_create_native_authority(self):
        self.environment["capabilities"] = {"linux": True, "native": True, "verified": True, "cluster": True}
        with patch.dict(os.environ, {"HARNESS_LIVE_EXECUTION_ENVELOPE": "/unit-only/fake-envelope", "HARNESS_LIVE_VERIFIED": "1"}), \
                patch("builtins.open", side_effect=AssertionError("must not open environment-selected files")):
            report = engine.run_campaign(self.campaign, self.environment, run_id="unit-only", observed_at=self.environment["capturedAt"])
        self.assertEqual(report["status"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(len(report["results"]), 20)
        for result in report["results"]:
            self.assertEqual(result["status"], "NOT_RUN_ENV_UNAVAILABLE")
            self.assertEqual(result["reasonCode"], "LINUX_LIVE_BACKEND_UNAVAILABLE")
        for field in ("verified", "session", "nativeAcceptance", "command", "evidenceFile", "authority"):
            changed = deepcopy(self.campaign)
            changed["controls"][0]["input"][field] = True
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                schema.validate_campaign(changed)

    def test_cli_keeps_unavailable_results_and_unsigned_acceptance(self):
        report = json.loads(self.cli("run", self.path))
        evidence = json.loads(self.cli("evidence-verify", self.path))
        candidate = json.loads(self.cli("acceptance-candidate", self.path))
        self.assertEqual(report["status"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(evidence["resultStatus"], report["status"])
        self.assertEqual(evidence["verificationClass"], "STRUCTURAL_ONLY")
        self.assertIs(evidence["nativeAcceptance"], False)
        self.assertEqual(candidate["status"], "PENDING")
        self.assertIs(candidate["unsigned"], True)
        self.assertEqual(len(candidate["findings"]), 20)
        self.assertNotIn("signature", str(candidate))

    def test_validate_cli_is_explicitly_structural_not_signature_acceptance(self):
        fixture = LinuxFixture()
        # An invalid signature with a valid encoding still has valid shape.
        fixture.record["platformSignature"] = "A" * 86
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unit-only.json"
            path.write_bytes(canonical_bytes(fixture.record))
            result = subprocess.run([sys.executable, "-B", "-m", "harness_conformance", "validate", "--kind", "linux-readiness-evidence", str(path)],
                                    cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout), {"kind": "linux-readiness-evidence", "status": "PASS", "verificationClass": "STRUCTURAL_ONLY", "nativeAcceptance": False})

    def test_legacy_reports_evidence_and_candidates_are_byte_identical_to_predecessor(self):
        snapshot = load_json(ROOT / "fixtures/platform/linux-baseline/predecessor-sources.json")
        with tempfile.TemporaryDirectory() as folder:
            old = Path(folder)
            for directory in ("src", "campaigns", "fixtures", "parity"):
                if (ROOT / directory).is_dir():
                    shutil.copytree(ROOT / directory, old / directory, ignore=shutil.ignore_patterns("__pycache__"))
            for name, content in snapshot["sources"].items():
                (old / "src/harness_conformance" / name).write_text(content, encoding="utf-8")
            registry = campaign_registry(ROOT)
            for name in ("meta-core", "parity-metadata", "alpha1-white-goods"):
                relative = registry[name].relative_to(ROOT)
                for command in ("run", "evidence-verify", "acceptance-candidate"):
                    with self.subTest(campaign=name, command=command):
                        self.assertEqual(self.cli(command, ROOT / relative), self.cli(command, old / relative, old))
