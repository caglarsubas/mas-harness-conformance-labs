"""Linux evidence verification and data-only probe planning, never live authority.

This module opens no file, socket, credential or process. Its pure verification
result is explicitly UNIT_VERIFICATION_ONLY. An independently installed live
runner must supply custody, nonce storage, admission and execution; the current
repository launcher deliberately cannot manufacture such a session.
"""
from __future__ import annotations

import re
from functools import wraps
from datetime import timedelta
from typing import Any

from .canonical import byte_digest, canonical_bytes, canonical_digest, require_canonical_document
from .crypto import b64url_decode, signature_payload, verify
from .errors import ConformanceError
from .schema import closed, require_digest, require_id, require_key_id, require_object, require_time as parse_time

SCHEMA = "harness.planeon.ai/linux-readiness-evidence/v1alpha1"
PLAN_SCHEMA = "harness.planeon.ai/linux-readiness-plan/v1alpha1"
DOMAIN = "planeon.harness-linux-readiness-evidence/v1alpha1"
PACKET_DIGEST = "sha256:22f00544680f90a90b03420632bebf192a8c687549b519770fca5f98dd5fd6c9"
AXES = ("DEPLOYMENT", "RUNTIME", "SECURITY", "ASSURANCE")
ARCHITECTURES = ("amd64", "arm64")
CASE_CHECKS = {
    "HOST_ISOLATION_NEGATIVES": ("ipv4-denied", "ipv6-denied", "dns-denied", "loopback-denied", "descendants-denied", "warm-roots-hidden", "credentials-hidden", "sockets-denied", "packet-immutable"),
    "LINUX_TARGET_BUILD": ("target-local-build", "native-dependencies", "linux-executable", "cache-pinned", "sbom-pinned", "no-downloads"),
    "FULL_PREDECESSOR_REGRESSION": ("full-inventory", "all-suites-executed", "no-deselection", "no-skip-or-xfail"),
    "CONTROL_CONTAINER_STARTUP": ("standalone-started", "health-ready", "no-downloads", "telemetry-disabled"),
    "POSTGRES_MIGRATION_AND_RLS": ("forward-migration", "idempotent-migration", "cross-tenant-denied", "fixture-only"),
    "DURABLE_RESTART": ("restart-completed", "records-persisted", "tenant-boundaries-preserved"),
    "ARBITRARY_NON_ROOT_UID": ("arbitrary-nonroot-uid", "capabilities-dropped", "seccomp-enforced", "no-fixed-home"),
    "READ_ONLY_ROOT_FILESYSTEM": ("root-read-only", "declared-volumes-only", "no-privilege-escalation"),
    "KUBERNETES_SMOKE": ("namespace-pinned", "quota-pinned", "admission-enforced", "readiness-passed", "run-labelled-cleanup"),
    "DEFAULT_DENY_NETWORK": ("undeclared-egress-denied", "metadata-denied", "proxy-only", "policy-not-bypassable"),
}
CASES = tuple(CASE_CHECKS)
CASE_AXES = ("SECURITY", "DEPLOYMENT", "ASSURANCE", "RUNTIME", "RUNTIME", "RUNTIME", "SECURITY", "SECURITY", "DEPLOYMENT", "SECURITY")
REPOSITORIES = ("contracts", "control", "conformance")
IMAGES = ("control", "postgres", "kubernetes")
BUILD_FIELDS = ("recipeDigest", "toolchainDigest", "cacheDigest", "sbomDigest", "logDigest")
SIGNATURES = ("platformSignature", "tenantSignature", "capacitySignature")
AUTHORITY_FIELDS = ("packetDigest", "envelopeDigest", "capacityDigest", "releaseDigest", "planDigest", "tenantId", "environmentId", "runNonce", "endpointId", "endpointDigest", "namespace", "serviceAccountSubject", "admissionPolicyDigest", "resourceQuotaDigest")
RECORD_FIELDS = ("schemaVersion", "authority", "target", "sources", "images", "build", "preflightDigest", "observedAt", "validUntil", "cases", "platformSignerKeyId", "tenantSignerKeyId", "capacitySignerKeyId", *SIGNATURES)
STATUSES = ("PASS", "FAIL", "NOT_RUN_ENV_UNAVAILABLE")
COMMANDS = [["python3", "-m", "unittest", "discover", "-s", root, "-p", "test_*.py"] for root in
            ("tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary", "tests/platform/linux_baseline")]
COMMANDS += [["make", "campaign", "CAMPAIGN=linux-baseline"], ["make", "evidence-verify", "CAMPAIGN=linux-baseline"]]


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ConformanceError(reason, "Linux readiness binding or mandatory case is invalid")


def malformed_boundary(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ConformanceError:
            raise
        except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
            raise ConformanceError("LINUX_INPUT_MALFORMED", "malformed Linux evidence input") from exc
    return wrapped


def obj(value: Any, fields: tuple[str, ...], name: str) -> dict[str, Any]:
    result = require_object(value, name)
    closed(result, fields)
    return result


def require_time(value: Any, name: str):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value) is not None,
            "LINUX_TIME_INVALID")
    return parse_time(value, name)


def text(value: Any, name: str, maximum: int = 128) -> str:
    require(isinstance(value, str) and 0 < len(value) <= maximum
            and re.fullmatch(r"[A-Za-z0-9._:/-]+", value) is not None, "LINUX_TEXT_INVALID")
    return value


def integer(value: Any, minimum: int = 0) -> None:
    require(type(value) is int and minimum <= value <= 10000000, "LINUX_COUNT_INVALID")


def digest_map(value: Any, fields: tuple[str, ...]) -> None:
    for key, digest in obj(value, fields, "digest map").items():
        require_digest(digest, key)


def sources(value: Any) -> None:
    for source in obj(value, REPOSITORIES, "sources").values():
        obj(source, ("commit", "treeDigest"), "source")
        require(isinstance(source["commit"], str) and re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None, "LINUX_SOURCE_INVALID")
        require_digest(source["treeDigest"], "treeDigest")


def target(value: Any) -> None:
    obj(value, ("os", "kernel", "architecture", "hostArchitecture", "execution", "libc"), "target")
    require(value["os"] == "linux" and value["architecture"] in ARCHITECTURES
            and value["hostArchitecture"] == value["architecture"] and value["execution"] == "NATIVE", "LINUX_NATIVE_TARGET_REQUIRED")
    text(value["kernel"], "kernel")
    text(value["libc"], "libc")


@malformed_boundary
def validate_plan(value: Any) -> dict[str, Any]:
    canonical_bytes(value)
    obj(value, ("schemaVersion", "target", "sources", "images", "build", "preflightDigest", "endpointId", "namespace", "serviceAccountSubject", "regressions", "probes"), "Linux plan")
    require(value["schemaVersion"] == PLAN_SCHEMA, "LINUX_PLAN_SCHEMA_INVALID")
    target(value["target"])
    sources(value["sources"])
    digest_map(value["images"], IMAGES)
    digest_map(value["build"], BUILD_FIELDS)
    require_digest(value["preflightDigest"], "preflightDigest")
    for name in ("endpointId", "namespace"):
        require_id(value[name], name)
    text(value["serviceAccountSubject"], "serviceAccountSubject", 256)
    for name, regression in obj(value["regressions"], REPOSITORIES, "regressions").items():
        obj(regression, ("inventoryDigest", "testCount"), "regression")
        require_digest(regression["inventoryDigest"], "inventoryDigest")
        integer(regression["testCount"], 83 if name == "conformance" else 1)
    for probe in obj(value["probes"], CASES, "probes").values():
        digest_map(probe, ("probeDigest", "commandDigest"))
    return value


def validate_control_input(value: Any) -> dict[str, Any]:
    obj(value, ("architecture", "caseId"), "Linux control")
    require(value["architecture"] in ARCHITECTURES and value["caseId"] in CASES, "LINUX_CONTROL_INVALID")
    return value


def validate_linux_campaign(value: dict[str, Any]) -> None:
    expected = [{"controlId": architecture + "." + case.lower().replace("_", "-"),
                 "handler": "LINUX_READINESS", "required": True, "axis": axis,
                 "input": {"architecture": architecture, "caseId": case}}
                for architecture in ARCHITECTURES for case, axis in zip(CASES, CASE_AXES)]
    require(value["campaignId"] == "linux-baseline" and value["executionClass"] == "LIVE_CAMPAIGN"
            and canonical_bytes(value["controls"]) == canonical_bytes(expected), "LINUX_CAMPAIGN_INVENTORY_INVALID")


def _overall(statuses: list[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if "NOT_RUN_ENV_UNAVAILABLE" in statuses:
        return "NOT_RUN_ENV_UNAVAILABLE"
    return "PASS"


@malformed_boundary
def validate_linux_evidence(value: Any) -> dict[str, Any]:
    """Shape validation only; signatures and expected inputs are separate."""
    canonical_bytes(value)
    obj(value, RECORD_FIELDS, "Linux evidence")
    require(value["schemaVersion"] == SCHEMA, "LINUX_EVIDENCE_SCHEMA_INVALID")
    authority = obj(value["authority"], AUTHORITY_FIELDS, "Linux authority")
    for name, item in authority.items():
        if name.endswith("Digest"):
            require_digest(item, name)
        elif name == "serviceAccountSubject":
            text(item, name, 256)
        else:
            require_id(item, name)
    target(value["target"])
    sources(value["sources"])
    digest_map(value["images"], IMAGES)
    digest_map(value["build"], BUILD_FIELDS)
    require_digest(value["preflightDigest"], "preflightDigest")
    require_time(value["observedAt"], "observedAt")
    require_time(value["validUntil"], "validUntil")
    for role in ("platform", "tenant", "capacity"):
        require_key_id(value[role + "SignerKeyId"], role)
        b64url_decode(value[role + "Signature"], expected_length=64)
    cases = value["cases"]
    require(isinstance(cases, list) and len(cases) == len(CASES), "LINUX_CASE_INVENTORY_INVALID")
    for expected, case in zip(CASES, cases):
        obj(case, ("caseId", "status", "observedAt", "runNonce", "probeDigest", "commandDigest", "outputDigest", "output"), "Linux case")
        require(case["caseId"] == expected and case["status"] in STATUSES, "LINUX_CASE_INVENTORY_INVALID")
        require_time(case["observedAt"], "observedAt")
        require_id(case["runNonce"], "runNonce")
        for name in ("probeDigest", "commandDigest", "outputDigest"):
            require_digest(case[name], name)
        output = obj(case["output"], ("checks", "regressions"), "probe output")
        checks = obj(output["checks"], CASE_CHECKS[expected], "probe checks")
        require(all(item in STATUSES for item in checks.values()), "LINUX_CHECK_STATUS_INVALID")
        required_repos = REPOSITORIES if expected == "FULL_PREDECESSOR_REGRESSION" else ()
        regressions = obj(output["regressions"], required_repos, "probe regressions")
        for regression in regressions.values():
            obj(regression, ("inventoryDigest", "collected", "executed", "skipped", "failed"), "probe regression")
            require_digest(regression["inventoryDigest"], "inventoryDigest")
            for name in ("collected", "executed", "skipped", "failed"):
                integer(regression[name])
        require(case["outputDigest"] == canonical_digest(output, "planeon.linux-probe-output/v1alpha1"), "LINUX_OUTPUT_DIGEST_MISMATCH")
        statuses = list(checks.values())
        if any(item["skipped"] or item["failed"] or item["collected"] != item["executed"] for item in regressions.values()):
            statuses.append("FAIL")
        require(case["status"] == _overall(statuses), "LINUX_FALSE_CASE_STATUS")
    return value


def _release_plan(release: Any, plan_bytes: bytes, envelope: dict[str, Any], architecture: str) -> dict[str, Any]:
    obj(release, ("schemaVersion", "campaignId", "campaignDefinitionDigest", "kitDigest", "bundleDigest", "endpointPolicyDigests", "tree"), "campaign release")
    require(release["schemaVersion"] == "harness.planeon.ai/campaign-release/v1alpha1", "LINUX_RELEASE_INVALID")
    for key, other in (("campaignId", "campaignId"), ("campaignDefinitionDigest", "campaignDefinitionDigest"), ("kitDigest", "conformanceKitDigest"), ("bundleDigest", "bundleDigest")):
        require(release[key] == envelope[other], "LINUX_RELEASE_BINDING_MISMATCH")
    entries = release["tree"]
    require(isinstance(entries, list) and 0 < len(entries) <= 4096, "LINUX_RELEASE_TREE_INVALID")
    names = []
    for entry in entries:
        obj(entry, ("path", "mode", "size", "sha256"), "release entry")
        path = text(entry["path"], "path", 1024)
        require(not path.startswith("/") and all(part not in ("", ".", "..") for part in path.split("/")), "LINUX_RELEASE_PATH_INVALID")
        require(entry["mode"] in ("0444", "0555"), "LINUX_RELEASE_MODE_INVALID")
        integer(entry["size"])
        require_digest(entry["sha256"], "sha256")
        names.append(path)
    require(names == sorted(set(names), key=lambda item: item.encode()), "LINUX_RELEASE_TREE_INVALID")
    require(canonical_digest(entries, "planeon.harness-live-tree/v1alpha1") == release["kitDigest"], "LINUX_RELEASE_TREE_DIGEST_MISMATCH")
    path = f"campaigns/platform/linux-baseline/inputs/{architecture}.json"
    matches = [entry for entry in entries if entry["path"] == path]
    require(len(matches) == 1 and matches[0]["sha256"] == byte_digest(plan_bytes)
            and matches[0]["size"] == len(plan_bytes), "LINUX_PLAN_NOT_RELEASE_BOUND")
    return validate_plan(require_canonical_document(plan_bytes))


@malformed_boundary
def verify_linux_evidence(record_bytes: bytes, *, envelope_bytes: bytes, capacity_bytes: bytes,
                          release_bytes: bytes, plan_bytes: bytes, release_trust_bytes: bytes,
                          tenant_trust_bytes: bytes, now: str, expected_nonce: str,
                          expected_tenant: str, expected_environment: str, expected_release: str,
                          replayed_nonces: frozenset[str]) -> dict[str, Any]:
    """Pure cryptographic verifier. Never converts unit execution to native proof.

    Expected bindings/nonce history must come from external operator custody in
    a live consumer, never from the record being verified. This function does
    not provide that custody or claim a durable nonce reservation.
    """
    from .live import _trust_key, verify_linux_authority

    require(all(type(raw) is bytes for raw in (record_bytes, envelope_bytes, capacity_bytes, release_bytes, plan_bytes, release_trust_bytes, tenant_trust_bytes)), "LINUX_BYTES_REQUIRED")
    # Reject malformed records before doing any expensive signature work.
    record = validate_linux_evidence(require_canonical_document(record_bytes))
    require(type(replayed_nonces) is frozenset and all(isinstance(item, str) for item in replayed_nonces), "LINUX_REPLAY_HISTORY_INVALID")
    require_id(expected_nonce, "expected nonce")
    require(expected_nonce not in replayed_nonces, "LINUX_NONCE_REPLAYED")
    instant = require_time(now, "now")
    envelope, capacity, release_trust, tenant_trust = verify_linux_authority(
        envelope_bytes, capacity_bytes, release_trust_bytes, tenant_trust_bytes, now=instant)
    require(envelope["nonce"] == expected_nonce and envelope["tenantId"] == expected_tenant
            and envelope["environmentId"] == expected_environment
            and envelope["campaignReleaseDigest"] == expected_release, "LINUX_EXPECTED_SUBJECT_MISMATCH")
    require(byte_digest(release_bytes) == expected_release, "LINUX_RELEASE_DIGEST_MISMATCH")
    plan = _release_plan(require_canonical_document(release_bytes), plan_bytes, envelope, record["target"]["architecture"])
    for name in ("target", "sources", "images", "build", "preflightDigest"):
        require(canonical_bytes(record[name]) == canonical_bytes(plan[name]), "LINUX_BASELINE_CHANGED")
    endpoints = [endpoint for endpoint in envelope["endpoints"] if endpoint["endpointId"] == plan["endpointId"]]
    require(len(endpoints) == 1, "LINUX_ENDPOINT_UNAVAILABLE")
    endpoint = endpoints[0]
    require(endpoint["kind"] == "CAMPAIGN_PROXY", "LINUX_PROXY_BACKEND_UNAVAILABLE")
    policies = require_canonical_document(release_bytes)["endpointPolicyDigests"]
    require(isinstance(policies, list) and policies == sorted(set(item["authorizationPolicyDigest"] for item in envelope["endpoints"])), "LINUX_ENDPOINT_POLICY_MISMATCH")
    expected_authority = {
        "packetDigest": PACKET_DIGEST, "envelopeDigest": byte_digest(envelope_bytes),
        "capacityDigest": byte_digest(capacity_bytes), "releaseDigest": expected_release,
        "planDigest": byte_digest(plan_bytes), "tenantId": expected_tenant, "environmentId": expected_environment,
        "runNonce": expected_nonce, "endpointId": endpoint["endpointId"], "endpointDigest": canonical_digest(endpoint),
        "namespace": capacity["namespace"], "serviceAccountSubject": capacity["serviceAccountSubject"],
        "admissionPolicyDigest": envelope["admissionPolicyDigest"], "resourceQuotaDigest": envelope["resourceQuotaDigest"],
    }
    require(record["authority"] == expected_authority and plan["namespace"] == capacity["namespace"]
            and plan["serviceAccountSubject"] == capacity["serviceAccountSubject"], "LINUX_AUTHORITY_BINDING_MISMATCH")
    observed = require_time(record["observedAt"], "observedAt")
    until = require_time(record["validUntil"], "validUntil")
    require(max(require_time(capacity["validFrom"], "validFrom"), require_time(envelope["issuedAt"], "issuedAt")) <= observed <= instant < until
            <= min(require_time(capacity["expiresAt"], "expiresAt"), require_time(envelope["expiresAt"], "expiresAt"))
            and until - observed <= timedelta(hours=168), "LINUX_EVIDENCE_NOT_CURRENT")
    keys = []
    for role, trust, purpose, tenant, environment, expected_key in (
        ("platform", release_trust, "PLATFORM_RELEASE", None, None, envelope["platformSignerKeyId"]),
        ("tenant", tenant_trust, "TENANT_LIVE_EXECUTION", expected_tenant, expected_environment, envelope["tenantSignerKeyId"]),
        ("capacity", tenant_trust, "CAPACITY_OPERATOR", expected_tenant, expected_environment, capacity["signerKeyId"]),
    ):
        require(record[role + "SignerKeyId"] == expected_key, "LINUX_SIGNER_BINDING_MISMATCH")
        key = _trust_key(trust, expected_key, purpose, tenant, environment, instant)
        _trust_key(trust, expected_key, purpose, tenant, environment, observed)
        _trust_key(trust, expected_key, purpose, tenant, environment, until)
        keys.append(key)
        require(verify(key, signature_payload(DOMAIN, record, SIGNATURES), b64url_decode(record[role + "Signature"], expected_length=64)), "LINUX_EVIDENCE_SIGNATURE_INVALID")
    require(len(set(keys)) == 3, "LINUX_SIGNERS_NOT_INDEPENDENT")
    for case in record["cases"]:
        require(observed <= require_time(case["observedAt"], "case time") <= instant
                and case["runNonce"] == expected_nonce, "LINUX_CASE_REPLAYED_OR_STALE")
        for key in ("probeDigest", "commandDigest"):
            require(case[key] == plan["probes"][case["caseId"]][key], "LINUX_PROBE_DIGEST_MISMATCH")
        for name, result in case["output"]["regressions"].items():
            expected = plan["regressions"][name]
            require(result["inventoryDigest"] == expected["inventoryDigest"] and result["collected"] == expected["testCount"], "LINUX_REGRESSION_INVENTORY_MISMATCH")
        build_probe_request(envelope, capacity, plan, case["caseId"])
    return {"verificationStatus": _overall([item["status"] for item in record["cases"]]),
            "evidenceDigest": byte_digest(record_bytes), "architecture": plan["target"]["architecture"],
            "caseResults": {item["caseId"]: item["status"] for item in record["cases"]},
            "evidenceClass": "UNIT_VERIFICATION_ONLY", "nativeAcceptance": False}


@malformed_boundary
def build_probe_request(envelope: dict[str, Any], capacity: dict[str, Any], plan: dict[str, Any], case_id: str) -> dict[str, Any]:
    """Closed data-only request; caller receives neither URL nor credential.

    This is not transport admission. Even a valid request cannot execute in the
    current source kit; an installed proxy must independently enforce the same
    policy, namespace, quota, nonce and server-side zero-cost mutation limits.
    """
    require(case_id in CASES, "LINUX_OPERATION_FORBIDDEN")
    path = "/v1/linux-baseline/" + case_id.lower().replace("_", "-")
    endpoint_id = plan["endpointId"]
    endpoints = [item for item in envelope["endpoints"] if item["endpointId"] == endpoint_id]
    require(len(endpoints) == 1 and endpoints[0]["kind"] == "CAMPAIGN_PROXY", "LINUX_PROXY_BACKEND_UNAVAILABLE")
    require(endpoint_id in capacity["permittedEndpointIds"] and plan["namespace"] == capacity["namespace"], "LINUX_PROXY_SCOPE_MISMATCH")
    fields = ("endpointId", "namespace", "service", "port", "protocol", "methods", "paths", "requestMediaType", "responseMediaType", "requestMaxBytes", "responseMaxBytes", "timeoutSeconds")
    expected = {"endpointId": endpoint_id, "namespace": plan["namespace"], "service": "linux-baseline-probes",
                "port": endpoints[0]["port"], "protocol": "HTTPS", "methods": ["POST"],
                "paths": ["/v1/linux-baseline/" + item.lower().replace("_", "-") for item in CASES],
                "requestMediaType": "application/json", "responseMediaType": "application/json",
                "requestMaxBytes": 16384, "responseMaxBytes": 4194304, "timeoutSeconds": 900}
    rules = capacity["campaignProxyRules"]
    require(isinstance(rules, list) and len(rules) == 1, "LINUX_PROXY_RULES_INVALID")
    obj(rules[0], fields, "Linux proxy rule")
    require(canonical_bytes(rules[0]) == canonical_bytes(expected), "LINUX_PROXY_RULES_INVALID")
    require(endpoints[0]["authorizationPolicyDigest"] == canonical_digest(expected, "planeon.linux-proxy-policy/v1alpha1"), "LINUX_PROXY_POLICY_DIGEST_MISMATCH")
    return {"schemaVersion": "harness.planeon.ai/linux-probe-request/v1alpha1", "operation": case_id,
            "endpointId": endpoint_id, "namespace": plan["namespace"], "method": "POST", "path": path,
            "runNonce": envelope["nonce"], "architecture": plan["target"]["architecture"],
            "probeDigest": plan["probes"][case_id]["probeDigest"], "commandDigest": plan["probes"][case_id]["commandDigest"]}


def evaluate_control(control: dict[str, Any], _: dict[str, Any]) -> tuple[Any, str, Any]:
    from .live_launcher import linux_runtime_availability
    from .models import ResultStatus

    selected = validate_control_input(control["input"])
    unavailable = linux_runtime_availability()
    return ResultStatus.NOT_RUN_ENV_UNAVAILABLE, unavailable["reasonCode"], {
        "architecture": selected["architecture"], "caseId": selected["caseId"],
        "nativeAcceptance": False, "availability": unavailable["status"],
    }
