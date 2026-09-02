from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from harness_conformance.campaign import run_campaign, run_campaign_files
from harness_conformance.canonical import canonical_bytes
from harness_conformance.models import RESULT_STATES

ROOT = Path(__file__).resolve().parents[2]


class CampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.campaign = json.loads((ROOT / "campaigns/meta/campaign.json").read_text())
        self.environment = json.loads((ROOT / "fixtures/environments/meta-complete.json").read_text())

    def execute(self, campaign=None, environment=None):
        return run_campaign(campaign or self.campaign, environment or self.environment, run_id="fixed-run", observed_at="2026-01-01T00:00:00Z")

    def test_all_handlers_and_non_failing_states_are_exercised(self) -> None:
        report = self.execute(self.campaign, self.environment)
        self.assertEqual({item["handler"] for item in report["results"]}, {item["handler"] for item in self.campaign["controls"]})
        statuses = {item["status"] for item in report["results"]}
        self.assertTrue({"PASS", "WARN", "NOT_APPLICABLE", "NOT_RUN_ENV_UNAVAILABLE"} <= statuses)
        self.assertEqual(report["status"], "WARN")

    def test_required_failure_blocks(self) -> None:
        campaign = copy.deepcopy(self.campaign)
        campaign["controls"][0]["input"]["actual"] = "open"
        report = self.execute(campaign, self.environment)
        self.assertEqual(report["status"], "FAIL")

    def test_required_unavailable_is_honest(self) -> None:
        campaign = copy.deepcopy(self.campaign)
        campaign["controls"] = [{"axis": "UNIT", "controlId": "missing", "handler": "ENVIRONMENT_CAPABILITY", "input": {"capability": "cluster", "expected": True}, "required": True}]
        report = self.execute(campaign, self.environment)
        self.assertEqual(report["status"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_illegal_lifecycle_and_event_fail(self) -> None:
        campaign = copy.deepcopy(self.campaign)
        campaign["controls"] = [copy.deepcopy(campaign["controls"][2]), copy.deepcopy(campaign["controls"][3])]
        campaign["controls"][0]["input"]["fromState"] = "SUCCEEDED"
        del campaign["controls"][1]["input"]["event"]["data"]["evidenceDigest"]
        report = self.execute(campaign, self.environment)
        self.assertEqual([item["status"] for item in report["results"]], ["FAIL", "FAIL"])

    def test_two_runs_are_byte_identical(self) -> None:
        first, _ = run_campaign_files(ROOT / "campaigns/meta/campaign.json", ROOT)
        second, _ = run_campaign_files(ROOT / "campaigns/meta/campaign.json", ROOT)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_unknown_result_aliases_do_not_exist(self) -> None:
        self.assertNotIn("LIVE_PASS", RESULT_STATES)
        self.assertNotIn("NOT_RUN", RESULT_STATES)


if __name__ == "__main__":
    unittest.main()
