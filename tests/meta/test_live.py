from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from harness_conformance.canonical import byte_digest, canonical_bytes
from harness_conformance.crypto import b64url_encode, public_key, sign, signature_payload
from harness_conformance.errors import ConformanceError
from harness_conformance.live import (
    CAPACITY_DOMAIN,
    CAPACITY_SCHEMA,
    ENVELOPE_DOMAIN,
    ENVELOPE_SCHEMA,
    command_set_digest,
    preflight,
    tree_digest,
    validate_capacity,
    validate_endpoint,
    validate_envelope,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)
ZERO = "sha256:" + "0" * 64


def write(path: Path, value: object) -> bytes:
    data = canonical_bytes(value) + b"\n"
    path.write_bytes(data)
    path.chmod(0o444)
    return data


def trust_entry(seed: bytes, key_id: str, purpose: str, tenant: str | None, environment: str | None) -> dict[str, object]:
    return {
        "environmentId": environment,
        "keyId": key_id,
        "owner": "fixture-owner",
        "publicKey": b64url_encode(public_key(seed)),
        "purpose": purpose,
        "revoked": False,
        "tenantId": tenant,
        "validFrom": "2025-01-01T00:00:00Z",
        "validUntil": "2030-01-01T00:00:00Z",
    }


class LiveFixture:
    def __init__(self, root: Path):
        self.root = root
        self.platform_seed = b"\x01" * 32
        self.tenant_seed = b"\x02" * 32
        self.capacity_seed = b"\x03" * 32
        self.launcher = root / "launcher"
        self.launcher.write_bytes(b"candidate-launcher")
        self.launcher.chmod(0o555)
        self.packet = root / "packet.yaml"
        self.packet.write_bytes(b"id: CONF-A1-001\n")
        self.packet.chmod(0o444)
        self.campaign = root / "campaign.json"
        campaign_bytes = write(self.campaign, {"campaignId": "alpha1-white-goods"})
        self.release = root / "release.json"
        release_bytes = write(self.release, {"campaignId": "alpha1-white-goods", "status": "RELEASED"})
        self.bundle = root / "bundle.bin"
        self.bundle.write_bytes(b"bundle")
        self.bundle.chmod(0o444)
        self.ca = root / "ca.pem"
        self.ca.write_bytes(b"fixture-ca")
        self.ca.chmod(0o444)
        self.credential = root / "credential"
        self.credential.write_bytes(b"fixture-credential")
        self.credential.chmod(0o400)
        self.kit = root / "kit"
        self.kit.mkdir()
        kit_file = self.kit / "campaign.py"
        kit_file.write_bytes(b"pass\n")
        kit_file.chmod(0o444)
        self.release_trust = root / "release-trust.json"
        release_trust_bytes = write(self.release_trust, {"keys": [trust_entry(self.platform_seed, "platform.fixture", "PLATFORM_RELEASE", None, None)], "revocationsDigest": ZERO, "schemaVersion": "harness.planeon.ai/live-trust-bundle/v1alpha1"})
        self.tenant_trust = root / "tenant-trust.json"
        tenant_trust_bytes = write(self.tenant_trust, {"keys": [trust_entry(self.tenant_seed, "tenant.fixture", "TENANT_LIVE_EXECUTION", "fixture-tenant", "fixture-environment"), trust_entry(self.capacity_seed, "capacity.fixture", "CAPACITY_OPERATOR", "fixture-tenant", "fixture-environment")], "revocationsDigest": ZERO, "schemaVersion": "harness.planeon.ai/live-trust-bundle/v1alpha1"})
        self.endpoint = {
            "accessMode": "PREAUTHORIZED_PROXY",
            "authorizationPolicyDigest": ZERO,
            "costDisposition": "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
            "credentialFileReference": str(self.credential),
            "discovery": False,
            "endpointId": "campaign-proxy",
            "ipAddress": "127.0.0.1",
            "kind": "CAMPAIGN_PROXY",
            "port": 9443,
            "tls": {"caCertificateFileReference": str(self.ca), "serverName": "local.proxy", "serverSpkiDigest": ZERO},
        }
        capacity = {
            "admissionPolicyDigest": ZERO,
            "authorizationId": "capacity-1",
            "campaignProxyRules": [],
            "credentialIdentities": [],
            "environmentId": "fixture-environment",
            "expiresAt": "2026-01-01T02:00:00Z",
            "kubernetesApiRules": [],
            "limitRangeDigest": ZERO,
            "mutationProfile": "ZERO_INCREMENTAL_COST_KUBERNETES_V1",
            "namespace": "fixture-namespace",
            "nonce": "capacity-nonce",
            "operatorId": "fixture-operator",
            "permittedEndpointIds": ["campaign-proxy"],
            "permittedGvksAndVerbs": [],
            "preallocatedAcceleratorRefs": [],
            "preallocatedStorageRefs": [],
            "preexistingResourceRefs": [],
            "resourceQuotaDigest": ZERO,
            "schemaVersion": CAPACITY_SCHEMA,
            "serviceAccountSubject": "system:serviceaccount:fixture-namespace:campaign",
            "signerKeyId": "capacity.fixture",
            "signature": "",
            "tenantId": "fixture-tenant",
            "validFrom": "2026-01-01T00:00:00Z",
        }
        capacity["signature"] = b64url_encode(sign(self.capacity_seed, signature_payload(CAPACITY_DOMAIN, capacity, ("signature",))))
        self.capacity = root / "capacity.json"
        capacity_bytes = write(self.capacity, capacity)
        commands = [["make", "campaign", "CAMPAIGN=alpha1-white-goods"], ["make", "evidence-verify", "CAMPAIGN=alpha1-white-goods"]]
        envelope = {
            "admissionPolicyDigest": ZERO,
            "allowedEvidenceAxes": ["RUNTIME", "ASSURANCE"],
            "bundleDigest": byte_digest(self.bundle.read_bytes()),
            "bundleFileReference": str(self.bundle),
            "campaignDefinitionDigest": byte_digest(campaign_bytes),
            "campaignDefinitionFileReference": str(self.campaign),
            "campaignId": "alpha1-white-goods",
            "campaignReleaseDigest": byte_digest(release_bytes),
            "campaignReleaseFileReference": str(self.release),
            "capacityAuthorizationDigest": byte_digest(capacity_bytes),
            "capacityAuthorizationFileReference": str(self.capacity),
            "capacityAuthorizationId": "capacity-1",
            "commandSetDigest": command_set_digest(commands),
            "commands": commands,
            "conformanceKitDigest": tree_digest(self.kit),
            "conformanceKitRoot": str(self.kit),
            "endpoints": [self.endpoint],
            "environmentId": "fixture-environment",
            "expiresAt": "2026-01-01T02:00:00Z",
            "issuedAt": "2026-01-01T00:00:00Z",
            "launcherDigest": byte_digest(self.launcher.read_bytes()),
            "mutationProfile": "ZERO_INCREMENTAL_COST_KUBERNETES_V1",
            "nonce": "envelope-nonce",
            "packetDigest": byte_digest(self.packet.read_bytes()),
            "packetFileReference": str(self.packet),
            "packetId": "CONF-A1-001",
            "platformSignature": "",
            "platformSignerKeyId": "platform.fixture",
            "releaseTrustStoreDigest": byte_digest(release_trust_bytes),
            "resourceQuotaDigest": ZERO,
            "schemaVersion": ENVELOPE_SCHEMA,
            "tenantId": "fixture-tenant",
            "tenantSignature": "",
            "tenantSignerKeyId": "tenant.fixture",
            "tenantTrustStoreDigest": byte_digest(tenant_trust_bytes),
        }
        payload = signature_payload(ENVELOPE_DOMAIN, envelope, ("platformSignature", "tenantSignature"))
        envelope["platformSignature"] = b64url_encode(sign(self.platform_seed, payload))
        envelope["tenantSignature"] = b64url_encode(sign(self.tenant_seed, payload))
        self.envelope_document = envelope
        self.envelope = root / "envelope.json"
        write(self.envelope, envelope)


class LiveContractTests(unittest.TestCase):
    def test_positive_preflight_verifies_every_authority_class(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = LiveFixture(Path(temporary))
            result = preflight(fixture.envelope, launcher_path=fixture.launcher, release_trust_path=fixture.release_trust, tenant_trust_path=fixture.tenant_trust, now=NOW)
            self.assertEqual(result["authorityStatus"], "PASS")

    def test_command_axis_signature_and_capacity_mismatches_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = LiveFixture(Path(temporary))
            mutations = []
            command = copy.deepcopy(fixture.envelope_document)
            command["commands"][0][0] = "bash"
            mutations.append(command)
            digest = copy.deepcopy(fixture.envelope_document)
            digest["commandSetDigest"] = ZERO
            mutations.append(digest)
            axis = copy.deepcopy(fixture.envelope_document)
            axis["allowedEvidenceAxes"] = ["TENANT_ACCEPTANCE"]
            mutations.append(axis)
            same_signer = copy.deepcopy(fixture.envelope_document)
            same_signer["tenantSignerKeyId"] = same_signer["platformSignerKeyId"]
            mutations.append(same_signer)
            missing_signature = copy.deepcopy(fixture.envelope_document)
            missing_signature["tenantSignature"] = ""
            mutations.append(missing_signature)
            for document in mutations:
                with self.subTest(), self.assertRaises(ConformanceError):
                    validate_envelope(document, now=NOW)

    def test_public_discovered_wildcard_and_metadata_endpoints_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = LiveFixture(Path(temporary))
            cases = []
            for field, value in (("ipAddress", "8.8.8.8"), ("ipAddress", "169.254.169.254"), ("discovery", True)):
                endpoint = copy.deepcopy(fixture.endpoint)
                endpoint[field] = value
                cases.append(endpoint)
            wildcard = copy.deepcopy(fixture.endpoint)
            wildcard["tls"]["serverName"] = "*.example"
            cases.append(wildcard)
            for endpoint in cases:
                with self.subTest(), self.assertRaises(ConformanceError):
                    validate_endpoint(endpoint)

    def test_capacity_scope_and_window_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = LiveFixture(Path(temporary))
            from harness_conformance.canonical import load_json

            envelope = validate_envelope(fixture.envelope_document, now=NOW)
            capacity = load_json(fixture.capacity)
            validate_capacity(capacity, envelope, now=NOW)
            capacity["resourceQuotaDigest"] = "sha256:" + "1" * 64
            with self.assertRaises(ConformanceError):
                validate_capacity(capacity, envelope, now=NOW)

    def test_repository_candidate_refuses_ci_and_direct_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            build = subprocess.run([sys.executable, "ci/build_live_launcher.py", "--output", str(candidate)], cwd=ROOT, check=False, capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            environment = os.environ.copy()
            environment["CI"] = "true"
            completed = subprocess.run([str(candidate)], env=environment, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("CI_EXECUTION_FORBIDDEN", completed.stderr)


if __name__ == "__main__":
    unittest.main()
