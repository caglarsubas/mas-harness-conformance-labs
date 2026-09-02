from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from harness_conformance.errors import ConformanceError
from harness_conformance.registry import campaign_registry, resolve_campaign

ROOT = Path(__file__).resolve().parents[2]


class RegistryDispatchTests(unittest.TestCase):
    def test_meta_campaign_resolves_exactly(self) -> None:
        registry = campaign_registry(ROOT)
        self.assertEqual(set(registry), {"meta-core"})
        self.assertEqual(resolve_campaign(ROOT, "meta-core"), ROOT / "campaigns/meta/campaign.json")
        for invalid in ("", "../meta", "META", "meta core", "https://invalid"):
            with self.subTest(invalid=invalid), self.assertRaises(ConformanceError):
                resolve_campaign(ROOT, invalid)

    def test_duplicate_campaign_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            for name in ("a", "b"):
                target = repository / "campaigns" / name
                target.mkdir(parents=True)
                target.joinpath("campaign.json").write_bytes((ROOT / "campaigns/meta/campaign.json").read_bytes())
            with self.assertRaises(ConformanceError) as raised:
                campaign_registry(repository)
            self.assertEqual(raised.exception.reason, "DUPLICATE_CAMPAIGN")

    def test_makefile_never_interpolates_campaign(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("$(CAMPAIGN)", makefile)
        self.assertNotIn("${CAMPAIGN}", makefile)
        self.assertEqual(makefile.count("ci/run_make_target.py"), 8)

    def test_descriptor_is_closed_direct_argv(self) -> None:
        descriptor = json.loads((ROOT / "ci/targets/conf-001.json").read_text())
        self.assertEqual(set(descriptor), {"schemaVersion", "packetId", "handlers"})
        self.assertEqual(descriptor["packetId"], "CONF-001")
        for handler in descriptor["handlers"]:
            self.assertEqual(set(handler), {"target", "variables", "argv"})
            self.assertIsInstance(handler["argv"], list)
            self.assertNotIn(handler["argv"][0], {"sh", "bash", "zsh"})

    def test_unknown_and_undeclared_dispatch_fail(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        unknown = subprocess.run([sys.executable, "ci/run_make_target.py", "unknown"], cwd=ROOT, env=environment, capture_output=True, text=True)
        self.assertEqual(unknown.returncode, 2)
        environment["CAMPAIGN"] = "meta-core"
        undeclared = subprocess.run([sys.executable, "ci/run_make_target.py", "zero-bill"], cwd=ROOT, env=environment, capture_output=True, text=True)
        self.assertEqual(undeclared.returncode, 2)

    def test_generic_campaign_has_no_shell_injection(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        environment["CAMPAIGN"] = "meta-core;touch-pwned"
        completed = subprocess.run([sys.executable, "ci/run_make_target.py", "campaign"], cwd=ROOT, env=environment, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse((ROOT / "touch-pwned").exists())


if __name__ == "__main__":
    unittest.main()
