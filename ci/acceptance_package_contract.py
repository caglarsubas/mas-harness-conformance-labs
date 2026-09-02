from __future__ import annotations

from pathlib import Path

from harness_conformance.acceptance import build_candidate, validate_candidate
from harness_conformance.campaign import run_campaign_files
from harness_conformance.canonical import canonical_bytes
from harness_conformance.evidence import build_evidence, validate_evidence

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    campaign = ROOT / "campaigns/meta/campaign.json"
    first_report, _ = run_campaign_files(campaign, ROOT)
    second_report, _ = run_campaign_files(campaign, ROOT)
    if canonical_bytes(first_report) != canonical_bytes(second_report):
        raise RuntimeError("campaign report is not deterministic")
    first_evidence = build_evidence(first_report)
    second_evidence = build_evidence(second_report)
    if canonical_bytes(first_evidence) != canonical_bytes(second_evidence):
        raise RuntimeError("technical evidence is not deterministic")
    validate_evidence(first_evidence, signed=False)
    candidate = build_candidate(first_report, first_evidence)
    validate_candidate(candidate)
    if any("signature" in key.lower() for key in candidate) or candidate["unsigned"] is not True or candidate["status"] != "PENDING":
        raise RuntimeError("acceptance candidate gained signing or acceptance authority")
    tampered = dict(candidate)
    tampered["tenantAcceptance"] = "PASS"
    try:
        validate_candidate(tampered)
    except ValueError:
        pass
    else:
        raise RuntimeError("tenant acceptance escalation was not rejected")
    print(f"acceptance_package_status=PASS candidate={candidate['candidateDigest']} authority=UNSIGNED_CANDIDATE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
