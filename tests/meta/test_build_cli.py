from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class BuildCliTests(unittest.TestCase):
    def environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        return environment

    def test_reproducible_live_candidate(self) -> None:
        completed = subprocess.run([sys.executable, "ci/build_live_launcher.py", "--verify-reproducible"], cwd=ROOT, env=self.environment(), check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("authority=UNINSTALLED_CANDIDATE", completed.stdout)

    def test_cli_report_and_evidence_are_deterministic(self) -> None:
        command = [sys.executable, "-m", "harness_conformance", "run", "--campaign", "campaigns/meta/campaign.json", "--repository", str(ROOT)]
        first = subprocess.run(command, cwd=ROOT, env=self.environment(), check=False, capture_output=True)
        second = subprocess.run(command, cwd=ROOT, env=self.environment(), check=False, capture_output=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        verify_command = [sys.executable, "-m", "harness_conformance", "evidence-verify", "--campaign", "campaigns/meta/campaign.json", "--repository", str(ROOT)]
        verified = subprocess.run(verify_command, cwd=ROOT, env=self.environment(), check=False, capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn(b'"status":"PASS"', verified.stdout)

    def test_live_inner_adapter_refuses_direct_and_ci(self) -> None:
        direct = subprocess.run([sys.executable, "ci/verify-live-campaign.py", "--", sys.executable, "-c", "pass"], cwd=ROOT, env=self.environment(), check=False, capture_output=True, text=True)
        self.assertEqual(direct.returncode, 2)
        environment = self.environment()
        environment["CI"] = "true"
        ci = subprocess.run([sys.executable, "ci/verify-live-campaign.py", "--", sys.executable, "-c", "pass"], cwd=ROOT, env=environment, check=False, capture_output=True, text=True)
        self.assertEqual(ci.returncode, 2)

    def test_build_backend_wheel_is_reproducible(self) -> None:
        from harness_conformance.build_backend import build_wheel

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = Path(first) / build_wheel(first)
            two = Path(second) / build_wheel(second)
            self.assertEqual(one.read_bytes(), two.read_bytes())


if __name__ == "__main__":
    unittest.main()
