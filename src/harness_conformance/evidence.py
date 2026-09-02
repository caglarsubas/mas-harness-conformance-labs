from __future__ import annotations

from typing import Any

from .canonical import canonical_digest
from .crypto import b64url_decode, b64url_encode, public_key, sign, signature_payload, verify
from .errors import ConformanceError
from .models import EVIDENCE_AXES, RESULT_STATES
from .schema import closed, require_digest, require_key_id, require_object, require_time

EVIDENCE_DOMAIN = "planeon.harness-technical-evidence/v1alpha1"


def build_evidence(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("executionClass") == "OFFLINE_TEST":
        originated_axes = ["UNIT"]
    else:
        originated_axes = list(dict.fromkeys(result["axis"] for result in report["results"]))
    if "TENANT_ACCEPTANCE" in originated_axes:
        raise ConformanceError("TENANT_ACCEPTANCE_FORBIDDEN", "campaigns cannot originate tenant acceptance")
    evidence = {
        "schemaVersion": "harness.planeon.ai/technical-evidence-bundle/v1alpha1",
        "bundleId": f"{report['runId']}.evidence",
        "campaignId": report["campaignId"],
        "environmentId": report["environmentId"],
        "issuedAt": report["observedAt"],
        "originatedAxes": originated_axes,
        "producer": "planeon.harness-conformance/0.1.0",
        "reportDigest": report["reportDigest"],
        "resultStatus": report["status"],
        "subjectDigests": [report["reportDigest"]],
        "tenantId": report["tenantId"],
    }
    evidence["bundleDigest"] = canonical_digest(evidence, EVIDENCE_DOMAIN)
    return evidence


def validate_evidence(document: Any, *, signed: bool | None = None) -> dict[str, Any]:
    value = require_object(document, "technical evidence")
    base = {
        "schemaVersion",
        "bundleId",
        "campaignId",
        "environmentId",
        "issuedAt",
        "originatedAxes",
        "producer",
        "reportDigest",
        "resultStatus",
        "subjectDigests",
        "tenantId",
        "bundleDigest",
    }
    signature_fields = {"signerKeyId", "signaturePurpose", "signature"}
    if signed is True:
        closed(value, base | signature_fields)
    elif signed is False:
        closed(value, base)
    else:
        closed(value, base, signature_fields)
        present = signature_fields & value.keys()
        if present and present != signature_fields:
            raise ConformanceError("INCOMPLETE_SIGNATURE", "all technical signature fields are required")
    if value["schemaVersion"] != "harness.planeon.ai/technical-evidence-bundle/v1alpha1":
        raise ConformanceError("UNSUPPORTED_SCHEMA", "unsupported evidence schema")
    require_time(value["issuedAt"], "issuedAt")
    require_digest(value["reportDigest"], "reportDigest")
    require_digest(value["bundleDigest"], "bundleDigest")
    if value["resultStatus"] not in RESULT_STATES:
        raise ConformanceError("INVALID_RESULT", "unknown evidence result")
    if not isinstance(value["originatedAxes"], list) or not value["originatedAxes"]:
        raise ConformanceError("INVALID_AXIS", "originatedAxes must be non-empty")
    if len(value["originatedAxes"]) != len(set(value["originatedAxes"])):
        raise ConformanceError("DUPLICATE_AXIS", "originated axes must be unique")
    if any(axis not in EVIDENCE_AXES or axis == "TENANT_ACCEPTANCE" for axis in value["originatedAxes"]):
        raise ConformanceError("INVALID_AXIS", "evidence contains a forbidden axis")
    if not isinstance(value["subjectDigests"], list) or not value["subjectDigests"]:
        raise ConformanceError("INVALID_SUBJECT", "subject digests must be non-empty")
    for digest in value["subjectDigests"]:
        require_digest(digest, "subjectDigest")
    unsigned = {key: item for key, item in value.items() if key not in signature_fields | {"bundleDigest"}}
    expected = canonical_digest(unsigned, EVIDENCE_DOMAIN)
    if value["bundleDigest"] != expected:
        raise ConformanceError("EVIDENCE_DIGEST_MISMATCH", "technical evidence digest does not match")
    if signature_fields <= value.keys():
        require_key_id(value["signerKeyId"], "signerKeyId")
        if value["signaturePurpose"] != "TECHNICAL_EVIDENCE":
            raise ConformanceError("INVALID_SIGNATURE_PURPOSE", "technical evidence purpose is required")
        b64url_decode(value["signature"], expected_length=64)
    return value


def sign_evidence(evidence: dict[str, Any], key: dict[str, Any]) -> dict[str, Any]:
    validate_evidence(evidence, signed=False)
    key = require_object(key, "signing key")
    closed(key, ("schemaVersion", "keyId", "purpose", "seed"))
    if key["schemaVersion"] != "harness.planeon.ai/test-signing-key/v1alpha1":
        raise ConformanceError("UNSUPPORTED_KEY_SCHEMA", "unsupported local signing-key schema")
    key_id = require_key_id(key["keyId"], "keyId")
    if key["purpose"] != "TECHNICAL_EVIDENCE":
        raise ConformanceError("SIGNING_PURPOSE_FORBIDDEN", "only technical evidence may be signed")
    seed = b64url_decode(key["seed"], expected_length=32)
    signed = dict(evidence)
    signed["signerKeyId"] = key_id
    signed["signaturePurpose"] = "TECHNICAL_EVIDENCE"
    payload = signature_payload(EVIDENCE_DOMAIN, signed, ("signature",))
    signed["signature"] = b64url_encode(sign(seed, payload))
    return signed


def verify_evidence(evidence: dict[str, Any], trust_bundle: dict[str, Any], *, now: str) -> dict[str, Any]:
    evidence = validate_evidence(evidence, signed=True)
    trust = require_object(trust_bundle, "trust bundle")
    closed(trust, ("schemaVersion", "keys"))
    if trust["schemaVersion"] != "harness.planeon.ai/conformance-trust-bundle/v1alpha1":
        raise ConformanceError("UNSUPPORTED_TRUST_SCHEMA", "unsupported trust bundle")
    keys = trust["keys"]
    if not isinstance(keys, list):
        raise ConformanceError("INVALID_TRUST_BUNDLE", "trust keys must be an array")
    matching = [item for item in keys if isinstance(item, dict) and item.get("keyId") == evidence["signerKeyId"]]
    if len(matching) != 1:
        raise ConformanceError("AMBIGUOUS_TRUST_KEY", "signer key must resolve exactly once")
    entry = matching[0]
    closed(entry, ("keyId", "purpose", "publicKey", "tenantId", "validFrom", "validUntil", "revoked"))
    if entry["purpose"] != "TECHNICAL_EVIDENCE" or entry["tenantId"] != evidence["tenantId"]:
        raise ConformanceError("TRUST_SCOPE_MISMATCH", "signer purpose or tenant scope does not match")
    if entry["revoked"] is not False:
        raise ConformanceError("TRUST_KEY_REVOKED", "signer key is revoked")
    instant = require_time(now, "now")
    if not (require_time(entry["validFrom"], "validFrom") <= instant <= require_time(entry["validUntil"], "validUntil")):
        raise ConformanceError("TRUST_KEY_NOT_CURRENT", "signer key is outside its validity window")
    public = b64url_decode(entry["publicKey"], expected_length=32)
    signature = b64url_decode(evidence["signature"], expected_length=64)
    payload = signature_payload(EVIDENCE_DOMAIN, evidence, ("signature",))
    if not verify(public, payload, signature):
        raise ConformanceError("SIGNATURE_INVALID", "technical evidence signature is invalid")
    return {"keyId": entry["keyId"], "publicKey": b64url_encode(public), "verified": True}


def public_entry(key: dict[str, Any], *, tenant_id: str, valid_from: str, valid_until: str) -> dict[str, Any]:
    seed = b64url_decode(key["seed"], expected_length=32)
    return {
        "keyId": key["keyId"],
        "purpose": "TECHNICAL_EVIDENCE",
        "publicKey": b64url_encode(public_key(seed)),
        "revoked": False,
        "tenantId": tenant_id,
        "validFrom": valid_from,
        "validUntil": valid_until,
    }
