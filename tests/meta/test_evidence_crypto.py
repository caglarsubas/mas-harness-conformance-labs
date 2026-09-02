from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from harness_conformance.acceptance import build_candidate, validate_candidate
from harness_conformance.campaign import run_campaign_files
from harness_conformance.crypto import b64url_encode, public_key, sign, verify
from harness_conformance.evidence import build_evidence, public_entry, sign_evidence, validate_evidence, verify_evidence
from harness_conformance.errors import ConformanceError

ROOT = Path(__file__).resolve().parents[2]
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
SIGNATURE = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


class EvidenceCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        report, _ = run_campaign_files(ROOT / "campaigns/meta/campaign.json", ROOT)
        self.evidence = build_evidence(report)
        self.key = {"schemaVersion": "harness.planeon.ai/test-signing-key/v1alpha1", "keyId": "fixture.technical", "purpose": "TECHNICAL_EVIDENCE", "seed": b64url_encode(SEED)}

    def test_rfc8032_vector(self) -> None:
        self.assertEqual(public_key(SEED), PUBLIC)
        self.assertEqual(sign(SEED, b""), SIGNATURE)
        self.assertTrue(verify(PUBLIC, b"", SIGNATURE))
        self.assertFalse(verify(PUBLIC, b"changed", SIGNATURE))

    def test_technical_evidence_sign_and_verify(self) -> None:
        signed = sign_evidence(self.evidence, self.key)
        trust = {"schemaVersion": "harness.planeon.ai/conformance-trust-bundle/v1alpha1", "keys": [public_entry(self.key, tenant_id="fixture-tenant", valid_from="2025-01-01T00:00:00Z", valid_until="2030-01-01T00:00:00Z")]}
        result = verify_evidence(signed, trust, now="2026-01-01T00:00:00Z")
        self.assertTrue(result["verified"])

    def test_tamper_revocation_scope_and_duplicate_key_fail(self) -> None:
        signed = sign_evidence(self.evidence, self.key)
        entry = public_entry(self.key, tenant_id="fixture-tenant", valid_from="2025-01-01T00:00:00Z", valid_until="2030-01-01T00:00:00Z")
        cases = []
        tampered = copy.deepcopy(signed)
        tampered["campaignId"] = "different"
        cases.append((tampered, {"schemaVersion": "harness.planeon.ai/conformance-trust-bundle/v1alpha1", "keys": [entry]}))
        revoked = copy.deepcopy(entry)
        revoked["revoked"] = True
        cases.append((signed, {"schemaVersion": "harness.planeon.ai/conformance-trust-bundle/v1alpha1", "keys": [revoked]}))
        wrong_scope = copy.deepcopy(entry)
        wrong_scope["tenantId"] = "different"
        cases.append((signed, {"schemaVersion": "harness.planeon.ai/conformance-trust-bundle/v1alpha1", "keys": [wrong_scope]}))
        cases.append((signed, {"schemaVersion": "harness.planeon.ai/conformance-trust-bundle/v1alpha1", "keys": [entry, entry]}))
        for evidence, trust in cases:
            with self.subTest(), self.assertRaises(ConformanceError):
                verify_evidence(evidence, trust, now="2026-01-01T00:00:00Z")

    def test_tenant_acceptance_signing_is_forbidden(self) -> None:
        key = dict(self.key)
        key["purpose"] = "TENANT_ACCEPTANCE"
        with self.assertRaises(ConformanceError) as raised:
            sign_evidence(self.evidence, key)
        self.assertEqual(raised.exception.reason, "SIGNING_PURPOSE_FORBIDDEN")

    def test_candidate_is_unsigned_pending_and_digest_bound(self) -> None:
        report, _ = run_campaign_files(ROOT / "campaigns/meta/campaign.json", ROOT)
        candidate = build_candidate(report, self.evidence)
        validate_candidate(candidate)
        self.assertTrue(candidate["unsigned"])
        self.assertEqual(candidate["status"], "PENDING")
        self.assertFalse(any("signature" in key.lower() for key in candidate))
        candidate["status"] = "ACCEPTED"
        with self.assertRaises(ConformanceError):
            validate_candidate(candidate)

    def test_cli_requires_private_key_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o644)
            self.assertNotEqual(os.stat(path).st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
