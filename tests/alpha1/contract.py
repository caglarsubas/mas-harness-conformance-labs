from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

AXES = (
    "SOURCE", "CONTRACT_UNIT", "PR_CHECK", "MERGE", "ARTIFACT_SBOM",
    "SIGNATURE_RELEASE", "DEPLOYMENT", "RUNTIME", "SECURITY", "ASSURANCE",
    "TENANT_ACCEPTANCE",
)
SELECTED_STATES = (
    "PASS", "PASS", "MISSING", "MISSING", "MISSING", "MISSING",
    "NOT_RUN_ENV_UNAVAILABLE", "NOT_RUN_ENV_UNAVAILABLE", "MISSING",
    "NOT_RUN_ENV_UNAVAILABLE", "NOT_APPLICABLE",
)
NOT_SELECTED_STATES = ("NOT_APPLICABLE",) * len(AXES)
SELECTED = {
    "knowledge.data-integration": "DEMAND_SELECTED",
    "knowledge.domain-semantic": "DEMAND_SELECTED",
    "runtime.infrastructure": "REQUIRED_FOUNDATION_DEPENDENCY",
    "trust.observability-finops": "REQUIRED_FOUNDATION_DEPENDENCY",
    "trust.security-safety": "REQUIRED_FOUNDATION_DEPENDENCY",
}
DEMANDED = ("knowledge.data-integration", "knowledge.domain-semantic")
GATES = (
    "business.owner", "business.outcome", "data.owner", "data.quality",
    "data.completeness", "data.freshness", "data.provenance",
    "data.classification", "integration.readiness", "autonomy.boundary",
)
STAGES = (
    "QUESTIONNAIRE", "BUSINESS_CONTEXT", "DOMAIN_CONTEXT", "DATA_READINESS",
    "PROFILE_LOCK", "BUNDLE_BUILD", "SIGNATURE_RELEASE", "PREFLIGHT", "APPLY",
    "RUNTIME_HEALTH", "EVIDENCE_FRESHNESS",
)
HARNESS_DEFINITIONS = (
    (1, "runtime.infrastructure", "runtime", "Infrastructure & Runtime"),
    (2, "runtime.model-inference", "runtime", "Model & Inference"),
    (3, "runtime.ai-gateway", "runtime", "AI Gateway"),
    (4, "runtime.experience", "runtime", "Experience & Interaction"),
    (5, "knowledge.domain-semantic", "knowledge", "Domain & Semantic"),
    (6, "knowledge.data-integration", "knowledge", "Data Integration & Provenance"),
    (7, "knowledge.retrieval-context", "knowledge", "Retrieval & Context Engineering"),
    (8, "knowledge.memory-state", "knowledge", "Memory & State"),
    (9, "execution.protocol-interoperability", "execution", "Protocol & Interoperability"),
    (10, "execution.orchestration", "execution", "Orchestration & Durable Execution"),
    (11, "execution.tool-skill-sandbox", "execution", "Tool, Skill & Sandbox"),
    (12, "execution.ml-decision", "execution", "ML & Decision Intelligence"),
    (13, "trust.security-safety", "trust", "Security, Safety & Guardrails"),
    (14, "trust.governance-agentops", "trust", "Governance, Oversight & AgentOps"),
    (15, "trust.observability-finops", "trust", "Observability & FinOps"),
    (16, "trust.evaluation-assurance", "trust", "Evaluation & Assurance"),
)
AUTHORITY = (
    ("CONF-002", "mas-harness-conformance-labs", "32e21f3f7cba8b3d0d35f76dd795cbd053be2f1f", 33669602419, 33669727003),
    ("CTRL-007", "mas-harness-control-plane", "39eb8f8fc42382bbfdd8ac1e0723531282648656", 33662200783, 33662472964),
    ("KN-DATA-002", "mas-harness-knowledge-plane", "2056405d747f10bcea36f089fcd6f2de474b3ee5", 33569253853, 33569419518),
    ("TRUST-OBS-001", "mas-harness-trust-plane", "919deda20b5c2a126129de7d484dd7c9667ad11e", 33535303809, 33535602147),
    ("OP-003", "mas-harness-operator", "0fa716fae4009f4fc63861f808f9e794f8925999", 33657138276, 33657346833),
    ("DIST-004", "mas-harness-distribution", "6ef7273f0674c3d39f2bd5becf084a4fd16c590c", 33643041456, 33643205684),
)
FORBIDDEN_KEYS = {"apikey", "businesspayload", "credential", "password", "personaldata", "token"}


class ContractError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ContractError(reason)


def closed(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == fields, reason)
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_MEMBER")
        result[key] = value
    return result


def load_canonical(relative: str) -> tuple[dict[str, Any], bytes]:
    target = ROOT / relative
    require(target.is_file() and not target.is_symlink(), "FIXTURE_PATH_INVALID")
    raw = target.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("FIXTURE_JSON_INVALID") from exc
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    require(raw == canonical, "FIXTURE_NOT_CANONICAL")
    return value, raw


def _safe_tree(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(key.casefold().replace("_", "").replace("-", "") not in FORBIDDEN_KEYS, "FORBIDDEN_CONTENT_KEY")
            _safe_tree(item)
    elif isinstance(value, list):
        for item in value:
            _safe_tree(item)
    elif isinstance(value, str):
        lowered = value.casefold()
        require("http://" not in lowered and "https://" not in lowered, "PUBLIC_URL_FORBIDDEN")


def validate_journey(journey: dict[str, Any], overview: dict[str, Any], overview_raw: bytes) -> None:
    closed(journey, {"authority", "bundle", "businessContext", "dataReadiness", "domainContext", "organization", "overviewRef", "profile", "questionnaire", "schemaVersion", "stages"}, "JOURNEY_SHAPE")
    require(journey["schemaVersion"] == "harness.planeon.ai/alpha1-journey/v1alpha1", "JOURNEY_SCHEMA")
    _safe_tree(journey)

    authority = closed(journey["authority"], {"records", "source"}, "AUTHORITY_SHAPE")
    require(authority["source"] == "PUBLIC_PREDECESSOR_LOCKS_ONLY" and len(authority["records"]) == len(AUTHORITY), "AUTHORITY_COUNT")
    for record, expected in zip(authority["records"], AUTHORITY, strict=True):
        closed(record, {"commit", "exactMainRunId", "packetId", "pullRequestRunId", "repository"}, "AUTHORITY_RECORD_SHAPE")
        require((record["packetId"], record["repository"], record["commit"], record["pullRequestRunId"], record["exactMainRunId"]) == expected, "AUTHORITY_LOCK_MISMATCH")

    organization = closed(journey["organization"], {"architecture", "connectivity", "deploymentMode", "displayName", "externalEndpoints", "industry", "isolationBoundary", "organizationId", "platform", "secretReferences"}, "ORGANIZATION_SHAPE")
    require(organization == {"architecture": "arm64", "connectivity": "airgap", "deploymentMode": "air-gapped", "displayName": "Marmara Thermal Systems", "externalEndpoints": [], "industry": "white-goods", "isolationBoundary": "PHYSICAL_AIR_GAP", "organizationId": "org.marmara-thermal", "platform": "openshift", "secretReferences": []}, "ORGANIZATION_BOUNDARY")

    questionnaire = closed(journey["questionnaire"], {"answers", "questionnaireId", "state"}, "QUESTIONNAIRE_SHAPE")
    answers = closed(questionnaire["answers"], {"dataSourceKinds", "demandedHarnesses", "deploymentMode", "industry", "localOnly", "ownerRoles", "regulatoryInputs"}, "ANSWERS_SHAPE")
    require(questionnaire["state"] == "COMPLETE" and tuple(answers["demandedHarnesses"]) == DEMANDED, "QUESTIONNAIRE_INCOMPLETE")
    require(answers["industry"] == organization["industry"] and answers["deploymentMode"] == organization["deploymentMode"] and answers["localOnly"] is True, "QUESTIONNAIRE_BINDING")
    require(answers["dataSourceKinds"] == sorted(set(answers["dataSourceKinds"])) and answers["ownerRoles"] == sorted(set(answers["ownerRoles"])), "QUESTIONNAIRE_ORDER")

    business = closed(journey["businessContext"], {"kpis", "outcomes", "owners", "state"}, "BUSINESS_SHAPE")
    require(business["state"] == "FIXTURE_VALIDATED" and business["owners"] == sorted(set(business["owners"])) and business["outcomes"] == sorted(set(business["outcomes"])), "BUSINESS_STATE")
    require(isinstance(business["kpis"], list) and len(business["kpis"]) == 4, "KPI_COUNT")
    for kpi in business["kpis"]:
        closed(kpi, {"definition", "id", "ownerRole"}, "KPI_SHAPE")
        require(kpi["ownerRole"] in business["owners"] and kpi["definition"] and kpi["id"], "KPI_OWNER")

    domain = closed(journey["domainContext"], {"coverageDigest", "mappingDigest", "ontologyDigest", "state"}, "DOMAIN_SHAPE")
    require(domain["state"] == "FIXTURE_VALIDATED" and all(DIGEST.fullmatch(domain[field]) for field in ("coverageDigest", "mappingDigest", "ontologyDigest")), "DOMAIN_DIGEST")

    readiness = closed(journey["dataReadiness"], {"gates", "sourceKinds", "state"}, "READINESS_SHAPE")
    require(readiness["state"] == "FIXTURE_VALIDATED" and readiness["sourceKinds"] == answers["dataSourceKinds"], "READINESS_BINDING")
    require(tuple(item.get("gateId") for item in readiness["gates"]) == GATES, "READINESS_GATE_ORDER")
    for gate in readiness["gates"]:
        closed(gate, {"evidenceRefs", "gateId", "reasonCode", "state"}, "READINESS_GATE_SHAPE")
        require(gate["state"] == "PASS" and gate["reasonCode"] == "EVIDENCE_SATISFIED" and isinstance(gate["evidenceRefs"], list) and len(gate["evidenceRefs"]) == 1, "READINESS_GATE_NOT_EVIDENCED")

    profile = closed(journey["profile"], {"profileDigest", "profileId", "selectedModules", "state"}, "PROFILE_SHAPE")
    require(profile["state"] == "LOCKED" and DIGEST.fullmatch(profile["profileDigest"]) is not None, "PROFILE_STATE")
    module_ids = [item.get("harnessId") for item in profile["selectedModules"]]
    require(module_ids == sorted(SELECTED) and len(module_ids) == len(set(module_ids)), "PROFILE_SELECTION")
    for module in profile["selectedModules"]:
        closed(module, {"digest", "harnessId", "selectionReason"}, "MODULE_SHAPE")
        require(DIGEST.fullmatch(module["digest"]) is not None and module["selectionReason"] == SELECTED[module["harnessId"]], "MODULE_BINDING")

    bundle = closed(journey["bundle"], {"bundleDigest", "expectedModules", "images", "releaseDigest", "signatureState", "state"}, "BUNDLE_SHAPE")
    require(bundle == {"bundleDigest": None, "expectedModules": sorted(SELECTED), "images": [], "releaseDigest": None, "signatureState": "NOT_RUN_ENV_UNAVAILABLE", "state": "NOT_BUILT_IN_OFFLINE_CAMPAIGN"}, "BUNDLE_FALSE_CLAIM")

    stages = journey["stages"]
    require(isinstance(stages, list) and tuple(item.get("stageId") for item in stages) == STAGES, "STAGE_ORDER")
    for index, stage in enumerate(stages):
        closed(stage, {"evidenceAxis", "ordinal", "reasonCode", "requires", "stageId", "state"}, "STAGE_SHAPE")
        require(stage["ordinal"] == index + 1 and stage["requires"] == ([] if index == 0 else [STAGES[index - 1]]), "STAGE_DEPENDENCY")
        if index < 5:
            require(stage["state"] == "FIXTURE_VALIDATED" and stage["evidenceAxis"] == "UNIT" and stage["reasonCode"] == "PACKET_LOCAL_CONTRACT", "STAGE_FIXTURE_BOUNDARY")
        else:
            require(stage["state"] == "NOT_RUN_ENV_UNAVAILABLE" and stage["evidenceAxis"] in AXES and stage["reasonCode"].endswith("UNAVAILABLE"), "STAGE_FALSE_PASS")

    reference = closed(journey["overviewRef"], {"path", "sha256", "state"}, "OVERVIEW_REF_SHAPE")
    require(reference["path"] == "fixtures/alpha1/overview.json" and reference["state"] == "SOURCE_UNAVAILABLE", "OVERVIEW_REF_STATE")
    require(reference["sha256"] == f"sha256:{hashlib.sha256(overview_raw).hexdigest()}", "OVERVIEW_REF_DIGEST")
    require(overview["organizationId"] == organization["organizationId"] and overview["binding"]["profileDigest"] == profile["profileDigest"], "OVERVIEW_JOURNEY_BINDING")


def validate_overview(overview: dict[str, Any]) -> None:
    closed(overview, {"aggregateState", "binding", "displayName", "evidenceAxisOrder", "harnesses", "isolationBoundary", "navigation", "notFound", "organizationId", "planes", "schemaVersion", "stateCounts"}, "OVERVIEW_SHAPE")
    require(overview["schemaVersion"] == "harness.planeon.ai/alpha1-overview/v1alpha1" and tuple(overview["evidenceAxisOrder"]) == AXES, "OVERVIEW_SCHEMA")
    _safe_tree(overview)
    require(overview["organizationId"] == "org.marmara-thermal" and overview["displayName"] == "Marmara Thermal Systems" and overview["isolationBoundary"] == "PHYSICAL_AIR_GAP", "OVERVIEW_TENANT")

    binding = closed(overview["binding"], {"bundleDigest", "freshUntil", "lastVerifiedAt", "observedGeneration", "profileDigest", "releaseDigest", "sourceCursors", "state"}, "BINDING_SHAPE")
    require(binding["state"] == "SOURCE_UNAVAILABLE" and binding["bundleDigest"] is None and binding["releaseDigest"] is None and binding["observedGeneration"] == 1 and DIGEST.fullmatch(binding["profileDigest"]) is not None, "FRESHNESS_FALSE_CURRENT")
    require([item["sourceId"] for item in binding["sourceCursors"]] == ["PROFILE_LOCK", "DISTRIBUTION_RELEASE", "OPERATOR_RECONCILIATION", "TRUST_EVIDENCE"] and all(item == {"cursor": "unavailable", "sourceId": item["sourceId"], "state": "SOURCE_UNAVAILABLE"} for item in binding["sourceCursors"]), "SOURCE_CURSOR_STATE")

    harnesses = overview["harnesses"]
    require(isinstance(harnesses, list) and len(harnesses) == 16, "HARNESS_COUNT")
    selected_count = 0
    for harness, definition in zip(harnesses, HARNESS_DEFINITIONS, strict=True):
        closed(harness, {"aggregateState", "applicability", "axisStates", "evidenceRefs", "harnessId", "installationState", "name", "number", "planeId", "reasonCode", "route", "selectionReason", "selectionState"}, "HARNESS_SHAPE")
        number, harness_id, plane_id, name = definition
        require((harness["number"], harness["harnessId"], harness["planeId"], harness["name"], harness["route"]) == (number, harness_id, plane_id, name, f"/harnesses/{harness_id}"), "HARNESS_TAXONOMY")
        require(len(harness["axisStates"]) == len(AXES), "EVIDENCE_AXIS_COLLAPSED")
        if harness_id in SELECTED:
            selected_count += 1
            require((harness["selectionState"], harness["installationState"], harness["aggregateState"], harness["reasonCode"], harness["selectionReason"]) == ("SELECTED", "BLOCKED", "BLOCKED", "LIVE_FOUNDATION_ENVIRONMENT_UNAVAILABLE", SELECTED[harness_id]), "SELECTED_FALSE_READY")
            require(tuple(harness["axisStates"]) == SELECTED_STATES, "SELECTED_AXIS_STATE")
            require(set(harness["evidenceRefs"]) == {"SOURCE", "CONTRACT_UNIT"} and all(len(refs) == 1 and DIGEST.fullmatch(refs[0]) for refs in harness["evidenceRefs"].values()), "PASS_WITHOUT_EVIDENCE")
            require(harness["applicability"] == {"TENANT_ACCEPTANCE": "FOUNDATION_SCOPE_NO_TENANT_ACCEPTANCE"}, "TENANT_ACCEPTANCE_SCOPE")
        else:
            require((harness["selectionState"], harness["installationState"], harness["aggregateState"], harness["reasonCode"], harness["selectionReason"]) == ("NOT_SELECTED", "ABSENT", "EMPTY", "HARNESS_NOT_SELECTED", "NOT_SELECTED"), "UNSELECTED_HEALTH")
            require(tuple(harness["axisStates"]) == NOT_SELECTED_STATES and harness["evidenceRefs"] == {} and harness["applicability"] == {"ALL": "HARNESS_NOT_SELECTED"}, "UNSELECTED_EVIDENCE")
    require(selected_count == 5 and overview["stateCounts"] == {"BLOCKED": 5, "EMPTY": 11} and overview["aggregateState"] == "BLOCKED", "ORGANIZATION_AGGREGATE")

    expected_planes = (("runtime", 1, 3, "BLOCKED"), ("knowledge", 2, 2, "BLOCKED"), ("execution", 0, 4, "EMPTY"), ("trust", 2, 2, "BLOCKED"))
    require(len(overview["planes"]) == 4, "PLANE_COUNT")
    for plane, expected in zip(overview["planes"], expected_planes, strict=True):
        closed(plane, {"aggregateState", "notSelectedCount", "planeId", "route", "selectedCount"}, "PLANE_SHAPE")
        plane_id, selected, unselected, aggregate = expected
        require(plane == {"aggregateState": aggregate, "notSelectedCount": unselected, "planeId": plane_id, "route": f"/planes/{plane_id}", "selectedCount": selected}, "PLANE_AGGREGATE")

    navigation = closed(overview["navigation"], {"compactSemanticList", "harnessRoutes", "mainLandmarkLabel", "minimumTargetCssPixels", "overviewRoute", "planeRoutes", "zoomPercent"}, "NAVIGATION_SHAPE")
    require(navigation["overviewRoute"] == "/overview" and navigation["planeRoutes"] == [f"/planes/{item[0]}" for item in expected_planes] and navigation["harnessRoutes"] == [f"/harnesses/{item[1]}" for item in HARNESS_DEFINITIONS], "NAVIGATION_ROUTE")
    require(len(set(navigation["harnessRoutes"] + navigation["planeRoutes"])) == 20 and navigation["compactSemanticList"] is True and navigation["minimumTargetCssPixels"] >= 44 and navigation["zoomPercent"] >= 200 and bool(navigation["mainLandmarkLabel"]), "ACCESSIBILITY_MODEL")
    require(overview["notFound"] == {"crossTenant": "NOT_FOUND", "status": 404, "unknown": "NOT_FOUND"}, "ISOLATION_DISCLOSURE")


def validate_all(journey: dict[str, Any], overview: dict[str, Any], overview_raw: bytes) -> None:
    validate_overview(overview)
    validate_journey(journey, overview, overview_raw)
