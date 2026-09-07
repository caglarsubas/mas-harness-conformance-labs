"""Deterministic UNIT-ONLY signatures and fake probe outputs; no real target."""
from copy import deepcopy
from pathlib import Path

from harness_conformance.canonical import byte_digest, canonical_bytes, canonical_digest, load_json
from harness_conformance.crypto import b64url_encode, public_key, sign, signature_payload
from harness_conformance.linux_readiness import (AXES, BUILD_FIELDS, CASE_CHECKS, CASES, COMMANDS, DOMAIN, IMAGES, PACKET_DIGEST, PLAN_SCHEMA, REPOSITORIES, SCHEMA, SIGNATURES)
from harness_conformance.live import CAPACITY_DOMAIN, CAPACITY_SCHEMA, ENVELOPE_DOMAIN, ENVELOPE_SCHEMA, command_set_digest

ROOT = Path(__file__).resolve().parents[3]
NOW = "2026-09-07T01:00:00Z"
START = "2026-09-07T00:00:00Z"
END = "2026-09-07T02:00:00Z"


def digest(label):
    return byte_digest(("UNIT_ONLY_NOT_REAL_" + label).encode())


class LinuxFixture:
    def __init__(self, architecture="amd64"):
        self.seeds = {role: bytes([index]) * 32 for index, role in enumerate(("platform", "tenant", "capacity"), 1)}
        self.plan = {
            "schemaVersion": PLAN_SCHEMA,
            "target": {"os": "linux", "kernel": "6.12.fixture", "architecture": architecture,
                       "hostArchitecture": architecture, "execution": "NATIVE", "libc": "glibc.fixture"},
            "sources": {name: {"commit": str(index) * 40, "treeDigest": digest(name + "-tree")} for index, name in enumerate(REPOSITORIES, 1)},
            "images": {name: digest(name + "-image") for name in IMAGES},
            "build": {name: digest(name) for name in BUILD_FIELDS}, "preflightDigest": digest("preflight"),
            "endpointId": "unit-proxy", "namespace": "unit-namespace",
            "serviceAccountSubject": "system:serviceaccount:unit-namespace:campaign",
            "regressions": {name: {"inventoryDigest": digest(name + "-tests"), "testCount": 83 if name == "conformance" else 100} for name in REPOSITORIES},
            "probes": {case: {"probeDigest": digest(case + "-probe"), "commandDigest": digest(case + "-command")} for case in CASES},
        }
        rule = {"endpointId": "unit-proxy", "namespace": "unit-namespace", "service": "linux-baseline-probes",
                "port": 9443, "protocol": "HTTPS", "methods": ["POST"],
                "paths": ["/v1/linux-baseline/" + case.lower().replace("_", "-") for case in CASES],
                "requestMediaType": "application/json", "responseMediaType": "application/json",
                "requestMaxBytes": 16384, "responseMaxBytes": 4194304, "timeoutSeconds": 900}
        self.endpoint = {"endpointId": "unit-proxy", "kind": "CAMPAIGN_PROXY", "ipAddress": "127.0.0.1", "port": 9443,
                         "tls": {"serverName": "unit.proxy", "serverSpkiDigest": digest("spki"), "caCertificateFileReference": "/unit-only/ca"},
                         "credentialFileReference": "/unit-only/credential-never-opened",
                         "authorizationPolicyDigest": canonical_digest(rule, "planeon.linux-proxy-policy/v1alpha1"),
                         "costDisposition": "SELF_HOSTED_OPEN_SOURCE_NON_METERED", "accessMode": "PREAUTHORIZED_PROXY", "discovery": False}
        self.capacity = {"schemaVersion": CAPACITY_SCHEMA, "authorizationId": "unit-capacity", "operatorId": "unit-operator",
                         "tenantId": "unit-tenant", "environmentId": "unit-environment", "namespace": "unit-namespace",
                         "serviceAccountSubject": self.plan["serviceAccountSubject"], "permittedEndpointIds": ["unit-proxy"],
                         "kubernetesApiRules": [], "campaignProxyRules": [rule], "permittedGvksAndVerbs": [],
                         "preexistingResourceRefs": [], "resourceQuotaDigest": digest("quota"), "limitRangeDigest": digest("limits"),
                         "preallocatedStorageRefs": [], "preallocatedAcceleratorRefs": [], "credentialIdentities": [],
                         "mutationProfile": "ZERO_INCREMENTAL_COST_KUBERNETES_V1", "admissionPolicyDigest": digest("admission"),
                         "validFrom": START, "expiresAt": END, "nonce": "unit-capacity-nonce", "signerKeyId": "capacity.unit", "signature": ""}
        self.release_trust = self.trust(["platform"])
        self.tenant_trust = self.trust(["tenant", "capacity"])
        plan_bytes = canonical_bytes(self.plan)
        tree = [{"path": "campaigns/platform/linux-baseline/inputs/" + architecture + ".json", "mode": "0444", "size": len(plan_bytes), "sha256": byte_digest(plan_bytes)}]
        campaign_bytes = canonical_bytes(load_json(ROOT / "campaigns/platform/linux-baseline/campaign.json"))
        self.release = {"schemaVersion": "harness.planeon.ai/campaign-release/v1alpha1", "campaignId": "linux-baseline",
                        "campaignDefinitionDigest": byte_digest(campaign_bytes), "kitDigest": canonical_digest(tree, "planeon.harness-live-tree/v1alpha1"),
                        "bundleDigest": digest("bundle"), "endpointPolicyDigests": [self.endpoint["authorizationPolicyDigest"]], "tree": tree}
        self.envelope = {"schemaVersion": ENVELOPE_SCHEMA, "packetId": "CONF-LINUX-001", "packetFileReference": "/unit-only/packet.yaml",
                         "packetDigest": PACKET_DIGEST, "commands": deepcopy(COMMANDS), "commandSetDigest": command_set_digest(COMMANDS),
                         "conformanceKitRoot": "/unit-only/kit", "conformanceKitDigest": self.release["kitDigest"], "campaignId": "linux-baseline",
                         "campaignDefinitionFileReference": "/unit-only/campaign.json", "campaignDefinitionDigest": self.release["campaignDefinitionDigest"],
                         "campaignReleaseFileReference": "/unit-only/release.json", "campaignReleaseDigest": byte_digest(canonical_bytes(self.release)),
                         "launcherDigest": digest("launcher"), "bundleFileReference": "/unit-only/bundle", "bundleDigest": self.release["bundleDigest"],
                         "allowedEvidenceAxes": list(AXES), "tenantId": "unit-tenant", "environmentId": "unit-environment",
                         "capacityAuthorizationId": "unit-capacity", "capacityAuthorizationFileReference": "/unit-only/capacity.json",
                         "capacityAuthorizationDigest": digest("capacity-to-be-signed"), "mutationProfile": self.capacity["mutationProfile"],
                         "admissionPolicyDigest": self.capacity["admissionPolicyDigest"], "resourceQuotaDigest": self.capacity["resourceQuotaDigest"],
                         "endpoints": [self.endpoint], "issuedAt": START, "expiresAt": END, "nonce": "unit-run-nonce",
                         "releaseTrustStoreDigest": byte_digest(canonical_bytes(self.release_trust)), "tenantTrustStoreDigest": byte_digest(canonical_bytes(self.tenant_trust)),
                         "platformSignerKeyId": "platform.unit", "platformSignature": "", "tenantSignerKeyId": "tenant.unit", "tenantSignature": ""}
        self.resign_authority()
        self.record = {"schemaVersion": SCHEMA, "authority": self.bindings(), "target": deepcopy(self.plan["target"]),
                       "sources": deepcopy(self.plan["sources"]), "images": deepcopy(self.plan["images"]), "build": deepcopy(self.plan["build"]),
                       "preflightDigest": self.plan["preflightDigest"], "observedAt": "2026-09-07T00:30:00Z", "validUntil": END, "cases": [],
                       "platformSignerKeyId": "platform.unit", "tenantSignerKeyId": "tenant.unit", "capacitySignerKeyId": "capacity.unit"}
        for case in CASES:
            output = {"checks": {name: "PASS" for name in CASE_CHECKS[case]}, "regressions": {}}
            if case == "FULL_PREDECESSOR_REGRESSION":
                output["regressions"] = {name: {"inventoryDigest": expected["inventoryDigest"], "collected": expected["testCount"],
                                               "executed": expected["testCount"], "skipped": 0, "failed": 0} for name, expected in self.plan["regressions"].items()}
            self.record["cases"].append({"caseId": case, "status": "PASS", "observedAt": "2026-09-07T00:30:00Z", "runNonce": "unit-run-nonce",
                                         **self.plan["probes"][case], "outputDigest": canonical_digest(output, "planeon.linux-probe-output/v1alpha1"), "output": output})
        self.resign_record()

    def trust(self, roles):
        keys = []
        for role in roles:
            keys.append({"keyId": role + ".unit", "purpose": {"platform": "PLATFORM_RELEASE", "tenant": "TENANT_LIVE_EXECUTION", "capacity": "CAPACITY_OPERATOR"}[role],
                         "publicKey": b64url_encode(public_key(self.seeds[role])), "owner": role + "-unit-owner",
                         "tenantId": None if role == "platform" else "unit-tenant", "environmentId": None if role == "platform" else "unit-environment",
                         "validFrom": START, "validUntil": END, "revoked": False})
        return {"schemaVersion": "harness.planeon.ai/live-trust-bundle/v1alpha1", "keys": keys, "revocationsDigest": digest("unit-revocations")}

    def resign_authority(self):
        self.capacity["signature"] = b64url_encode(sign(self.seeds["capacity"], signature_payload(CAPACITY_DOMAIN, self.capacity, ("signature",))))
        self.envelope["capacityAuthorizationDigest"] = byte_digest(canonical_bytes(self.capacity))
        self.envelope["releaseTrustStoreDigest"] = byte_digest(canonical_bytes(self.release_trust))
        self.envelope["tenantTrustStoreDigest"] = byte_digest(canonical_bytes(self.tenant_trust))
        payload = signature_payload(ENVELOPE_DOMAIN, self.envelope, ("platformSignature", "tenantSignature"))
        for role in ("platform", "tenant"):
            self.envelope[role + "Signature"] = b64url_encode(sign(self.seeds[role], payload))

    def bindings(self):
        return {"packetDigest": PACKET_DIGEST, "envelopeDigest": byte_digest(canonical_bytes(self.envelope)),
                "capacityDigest": byte_digest(canonical_bytes(self.capacity)), "releaseDigest": byte_digest(canonical_bytes(self.release)),
                "planDigest": byte_digest(canonical_bytes(self.plan)), "tenantId": "unit-tenant", "environmentId": "unit-environment",
                "runNonce": "unit-run-nonce", "endpointId": "unit-proxy", "endpointDigest": canonical_digest(self.endpoint),
                "namespace": "unit-namespace", "serviceAccountSubject": self.plan["serviceAccountSubject"],
                "admissionPolicyDigest": self.envelope["admissionPolicyDigest"], "resourceQuotaDigest": self.envelope["resourceQuotaDigest"]}

    def resign_record(self):
        for case in self.record["cases"]:
            case["outputDigest"] = canonical_digest(case["output"], "planeon.linux-probe-output/v1alpha1")
        payload = signature_payload(DOMAIN, self.record, SIGNATURES)
        for role in self.seeds:
            self.record[role + "Signature"] = b64url_encode(sign(self.seeds[role], payload))

    def inputs(self):
        return {"envelope_bytes": canonical_bytes(self.envelope), "capacity_bytes": canonical_bytes(self.capacity),
                "release_bytes": canonical_bytes(self.release), "plan_bytes": canonical_bytes(self.plan),
                "release_trust_bytes": canonical_bytes(self.release_trust), "tenant_trust_bytes": canonical_bytes(self.tenant_trust),
                "now": NOW, "expected_nonce": "unit-run-nonce", "expected_tenant": "unit-tenant", "expected_environment": "unit-environment",
                "expected_release": byte_digest(canonical_bytes(self.release)), "replayed_nonces": frozenset()}
