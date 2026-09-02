from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from harness_conformance.campaign import run_campaign_files
from harness_conformance.canonical import canonical_bytes
from harness_conformance.evidence import build_evidence, validate_evidence

from contract import AXES, ContractError, load_canonical, validate_all, validate_journey, validate_overview


class Alpha1ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.journey, cls.journey_raw = load_canonical("fixtures/alpha1/journey.json")
        cls.overview, cls.overview_raw = load_canonical("fixtures/alpha1/overview.json")

    def test_complete_journey_and_overview_are_closed(self) -> None:
        validate_all(self.journey, self.overview, self.overview_raw)

    def test_fixture_reads_and_canonical_outputs_are_deterministic(self) -> None:
        second_journey, second_journey_raw = load_canonical("fixtures/alpha1/journey.json")
        second_overview, second_overview_raw = load_canonical("fixtures/alpha1/overview.json")
        self.assertEqual((self.journey_raw, self.overview_raw), (second_journey_raw, second_overview_raw))
        self.assertEqual(canonical_bytes(self.journey), canonical_bytes(second_journey))
        self.assertEqual(canonical_bytes(self.overview), canonical_bytes(second_overview))

    def test_journey_mutations_fail_closed(self) -> None:
        cases = []
        cases.append(lambda value: value["authority"]["records"][0].update(commit="0" * 40))
        cases.append(lambda value: value["dataReadiness"]["gates"].pop())
        cases.append(lambda value: value["dataReadiness"]["gates"][0].update(evidenceRefs=[]))
        cases.append(lambda value: value["profile"]["selectedModules"].pop())
        cases.append(lambda value: value["profile"]["selectedModules"].append(copy.deepcopy(value["profile"]["selectedModules"][0])))
        cases.append(lambda value: value["bundle"]["images"].append("public.example/image:latest"))
        cases.append(lambda value: value["organization"]["externalEndpoints"].append("https://outside.invalid"))
        cases.append(lambda value: value["organization"].update(credential="forbidden"))
        cases.append(lambda value: value["stages"].reverse())
        cases.append(lambda value: value["stages"][5].update(state="PASS"))
        cases.append(lambda value: value["stages"][6].update(state="PASS"))
        cases.append(lambda value: value["stages"][7].update(state="PASS"))
        cases.append(lambda value: value["stages"][8].update(state="PASS"))
        cases.append(lambda value: value["stages"][9].update(state="PASS"))
        cases.append(lambda value: value["stages"][10].update(state="PASS"))
        cases.append(lambda value: value["overviewRef"].update(sha256="sha256:" + "0" * 64))
        for mutate in cases:
            changed = copy.deepcopy(self.journey)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises(ContractError):
                validate_journey(changed, self.overview, self.overview_raw)

    def test_overview_mutations_fail_closed(self) -> None:
        cases = []
        cases.append(lambda value: value["harnesses"].append(copy.deepcopy(value["harnesses"][0])))
        cases.append(lambda value: value["harnesses"][0]["axisStates"].pop())
        cases.append(lambda value: value["harnesses"][0]["axisStates"].__setitem__(-1, "PASS"))
        cases.append(lambda value: value["harnesses"][1].update(selectionState="SELECTED"))
        cases.append(lambda value: value["harnesses"][0].update(installationState="READY", aggregateState="READY"))
        cases.append(lambda value: value["harnesses"][0]["evidenceRefs"].pop("SOURCE"))
        cases.append(lambda value: value.update(stateCounts={"BLOCKED": 4, "EMPTY": 12}))
        cases.append(lambda value: value["planes"][0].update(aggregateState="READY"))
        cases.append(lambda value: value["binding"].update(state="CURRENT"))
        cases.append(lambda value: value["navigation"]["harnessRoutes"].pop())
        cases.append(lambda value: value["navigation"].update(minimumTargetCssPixels=43))
        cases.append(lambda value: value["notFound"].update(crossTenant="FORBIDDEN", status=403))
        for mutate in cases:
            changed = copy.deepcopy(self.overview)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises(ContractError):
                validate_overview(changed)

    def test_navigation_and_evidence_axes_are_complete(self) -> None:
        navigation = self.overview["navigation"]
        self.assertEqual(tuple(self.overview["evidenceAxisOrder"]), AXES)
        self.assertEqual(len(navigation["planeRoutes"]), 4)
        self.assertEqual(len(navigation["harnessRoutes"]), 16)
        self.assertTrue(navigation["compactSemanticList"])
        self.assertGreaterEqual(navigation["minimumTargetCssPixels"], 44)
        self.assertGreaterEqual(navigation["zoomPercent"], 200)

    def test_fixture_has_no_public_request_or_secret_material(self) -> None:
        combined = (self.journey_raw + self.overview_raw).decode("utf-8").casefold()
        for token in ("http://", "https://", '"password"', '"apikey"', '"credential"', '"token"'):
            self.assertNotIn(token, combined)
        self.assertEqual(self.journey["organization"]["externalEndpoints"], [])
        self.assertEqual(self.journey["organization"]["secretReferences"], [])


class Alpha1CampaignTests(unittest.TestCase):
    def test_offline_campaign_is_honestly_unavailable(self) -> None:
        campaign = ROOT / "campaigns/alpha1/campaign.json"
        report, _environment = run_campaign_files(campaign, ROOT)
        self.assertEqual(report["executionClass"], "LIVE_CAMPAIGN")
        self.assertEqual(report["status"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual([item["axis"] for item in report["results"]], ["RUNTIME", "ASSURANCE"])
        self.assertEqual([item["status"] for item in report["results"]], ["NOT_RUN_ENV_UNAVAILABLE", "NOT_RUN_ENV_UNAVAILABLE"])
        evidence = build_evidence(report)
        validate_evidence(evidence, signed=False)
        self.assertEqual(evidence["resultStatus"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(evidence["originatedAxes"], ["RUNTIME", "ASSURANCE"])
        self.assertNotIn("TENANT_ACCEPTANCE", evidence["originatedAxes"])

    def test_campaign_and_evidence_are_reproducible(self) -> None:
        campaign = ROOT / "campaigns/alpha1/campaign.json"
        first, _ = run_campaign_files(campaign, ROOT)
        second, _ = run_campaign_files(campaign, ROOT)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(canonical_bytes(build_evidence(first)), canonical_bytes(build_evidence(second)))

    def test_report_template_preserves_authority_boundaries(self) -> None:
        report = (ROOT / "docs/reports/alpha1-template.md").read_text(encoding="utf-8")
        for phrase in ("NOT_RUN_ENV_UNAVAILABLE", "zero-incremental-cost", "dual-signed envelope", "cannot sign or assert TENANT_ACCEPTANCE"):
            self.assertIn(phrase, report)
        self.assertNotIn("health score", report.casefold())


if __name__ == "__main__":
    unittest.main()
