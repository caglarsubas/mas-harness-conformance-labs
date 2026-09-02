from __future__ import annotations

from typing import Any

from .canonical import canonical_digest
from .errors import ConformanceError
from .evidence import validate_evidence


def build_candidate(report: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    evidence = validate_evidence(evidence)
    if evidence["tenantId"] != report["tenantId"] or evidence["reportDigest"] != report["reportDigest"]:
        raise ConformanceError("CANDIDATE_BINDING_MISMATCH", "candidate evidence does not bind the report")
    if "TENANT_ACCEPTANCE" in evidence["originatedAxes"]:
        raise ConformanceError("TENANT_ACCEPTANCE_FORBIDDEN", "campaign evidence cannot contain tenant acceptance")
    candidate = {
        "schemaVersion": "harness.planeon.ai/tenant-acceptance-candidate/v1alpha1",
        "candidateId": f"{report['runId']}.candidate",
        "campaignId": report["campaignId"],
        "createdAt": report["observedAt"],
        "evidenceDigests": [evidence["bundleDigest"]],
        "findings": [result["reasonCode"] for result in report["results"] if result["status"] != "PASS"],
        "status": "PENDING",
        "tenantId": report["tenantId"],
        "unsigned": True,
    }
    candidate["candidateDigest"] = canonical_digest(candidate, "planeon.harness-acceptance-candidate/v1alpha1")
    return candidate


def validate_candidate(candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ConformanceError("TYPE_MISMATCH", "candidate must be an object")
    expected = {
        "schemaVersion",
        "candidateId",
        "campaignId",
        "createdAt",
        "evidenceDigests",
        "findings",
        "status",
        "tenantId",
        "unsigned",
        "candidateDigest",
    }
    if set(candidate) != expected:
        raise ConformanceError("CANDIDATE_NOT_UNSIGNED", "candidate fields are not the closed unsigned shape")
    if candidate["status"] != "PENDING" or candidate["unsigned"] is not True:
        raise ConformanceError("CANDIDATE_STATE_INVALID", "candidate must remain unsigned and pending")
    if any("signature" in key.lower() or key == "tenantAcceptance" for key in candidate):
        raise ConformanceError("TENANT_ACCEPTANCE_FORBIDDEN", "candidate cannot carry acceptance authority")
    unsigned = {key: value for key, value in candidate.items() if key != "candidateDigest"}
    if candidate["candidateDigest"] != canonical_digest(unsigned, "planeon.harness-acceptance-candidate/v1alpha1"):
        raise ConformanceError("CANDIDATE_DIGEST_MISMATCH", "candidate digest does not match")
    return candidate
