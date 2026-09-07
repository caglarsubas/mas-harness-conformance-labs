"""Exact CONF-LIVE-006 authority DATA verification, never installed custody.

The legacy CONF-LINUX-001 verifier is deliberately neither called nor patched.
Only existing canonical/crypto/capacity and release/probe primitives are reused.
No filesystem, network, credential, signer or execution operation is provided.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .canonical import byte_digest, require_canonical_document
from .crypto import b64url_decode
from .errors import ConformanceError
from .linux_readiness import (ARCHITECTURES, AXES, CASES, _release_plan,
                              build_probe_request, require_time)
from .live import validate_capacity, validate_envelope, verify_live_signatures
from .live_session import validate_binding
from .schema import closed, require_id, require_key_id, require_object

PACKET_ID = "CONF-LIVE-006"
# Exact published MET-LIVE-001 authority, not caller-controlled configuration.
PACKET_DIGEST = "sha256:f95c277cffdfb622f45a1b4b91a5292d9d9a5bfabc8f9388b3899cbb20c5213d"
SUITE_ROOTS = ("tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary",
               "tests/platform/linux_baseline", "tests/live_backend")
COMMANDS = tuple(("python3", "-m", "unittest", "discover", "-s", root, "-p", "test_*.py")
                 for root in SUITE_ROOTS) + (
    ("make", "campaign", "CAMPAIGN=linux-baseline"),
    ("make", "evidence-verify", "CAMPAIGN=linux-baseline"),
)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ConformanceError(code, "invalid live-backend authority data")


def verify_backend_authority(envelope_bytes: bytes, capacity_bytes: bytes,
                             release_trust_bytes: bytes, tenant_trust_bytes: bytes,
                             *, now: datetime) -> tuple[dict[str, Any], ...]:
    """Verify three independent roles, exact successor scope and all legacy checks.

Returned detached data is UNIT_VERIFICATION_ONLY, not a live session. This does
not open the envelope's reference paths or prove their installed custody.
"""
    try:
        _require(all(type(raw) is bytes for raw in (envelope_bytes, capacity_bytes,
                     release_trust_bytes, tenant_trust_bytes)), "BACKEND_BYTES_REQUIRED")
        _require(type(now) is datetime and now.utcoffset() == timedelta(0), "BACKEND_TIME_INVALID")
        envelope = validate_envelope(require_canonical_document(envelope_bytes), now=now)
        require_time(envelope["issuedAt"], "issuedAt")
        _require(envelope["packetId"] == PACKET_ID and envelope["packetDigest"] == PACKET_DIGEST
                 and envelope["campaignId"] == "linux-baseline"
                 and envelope["commands"] == [list(command) for command in COMMANDS]
                 and envelope["allowedEvidenceAxes"] == list(AXES), "BACKEND_ENVELOPE_SCOPE_MISMATCH")
        _require(now < require_time(envelope["expiresAt"], "expiresAt"), "BACKEND_ENVELOPE_EXPIRED")
        for name in ("tenantId", "environmentId", "nonce", "capacityAuthorizationId"):
            require_id(envelope[name], name)
        for raw, field in ((capacity_bytes, "capacityAuthorizationDigest"),
                           (release_trust_bytes, "releaseTrustStoreDigest"),
                           (tenant_trust_bytes, "tenantTrustStoreDigest")):
            _require(byte_digest(raw) == envelope[field], "BACKEND_AUTHORITY_DIGEST_MISMATCH")
        capacity = validate_capacity(require_canonical_document(capacity_bytes), envelope, now=now)
        require_time(capacity["validFrom"], "validFrom")
        _require(now < require_time(capacity["expiresAt"], "expiresAt"), "BACKEND_CAPACITY_EXPIRED")
        for name in ("nonce", "namespace", "operatorId"):
            require_id(capacity[name], name)
        _require(len(capacity["permittedEndpointIds"]) == len(set(capacity["permittedEndpointIds"])),
                 "BACKEND_DUPLICATE_ENDPOINT")
        for endpoint in envelope["endpoints"]:
            require_id(endpoint["endpointId"], "endpointId")
        release_trust = require_canonical_document(release_trust_bytes)
        tenant_trust = require_canonical_document(tenant_trust_bytes)
        for trust in (release_trust, tenant_trust):
            closed(require_object(trust, "backend trust"), ("schemaVersion", "keys", "revocationsDigest"))
            _require(type(trust["keys"]) is list and 0 < len(trust["keys"]) <= 128, "BACKEND_TRUST_INVALID")
            seen = set()
            for key in trust["keys"]:
                closed(require_object(key, "backend key"), ("keyId", "purpose", "publicKey", "owner",
                       "tenantId", "environmentId", "validFrom", "validUntil", "revoked"))
                require_key_id(key["keyId"], "keyId")
                _require(key["keyId"] not in seen and type(key["revoked"]) is bool, "BACKEND_TRUST_INVALID")
                seen.add(key["keyId"])
                require_id(key["owner"], "owner")
                _require(require_time(key["validFrom"], "validFrom") <
                         require_time(key["validUntil"], "validUntil"), "BACKEND_TRUST_WINDOW_INVALID")
                b64url_decode(key["publicKey"], expected_length=32)
        verify_live_signatures(envelope, capacity, release_trust, tenant_trust, now=now)
        owners = [next(item["owner"] for item in trust["keys"] if item["keyId"] == key_id)
                  for trust, key_id in ((release_trust, envelope["platformSignerKeyId"]),
                      (tenant_trust, envelope["tenantSignerKeyId"]), (tenant_trust, capacity["signerKeyId"]))]
        _require(len(set(owners)) == 3, "BACKEND_SIGNER_OWNERS_NOT_INDEPENDENT")
        return envelope, capacity, release_trust, tenant_trust
    except ConformanceError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise ConformanceError("BACKEND_AUTHORITY_MALFORMED", "malformed backend authority") from exc


def binding_from_authority(envelope_bytes: bytes, capacity_bytes: bytes,
                           release_trust_bytes: bytes, tenant_trust_bytes: bytes,
                           *, release_bytes: bytes, plan_bytes: bytes, architecture: str,
                           expected_nonce: str, expected_tenant: str,
                           expected_environment: str, expected_release: str,
                           now: str) -> dict[str, Any]:
    """Derive the closed session binding and intersect signed validity windows.

Expected values and bytes need independent protected custody in a live caller.
This pure function cannot supply it, reserve a nonce, or grant native acceptance.
"""
    try:
        _require(type(release_bytes) is bytes and type(plan_bytes) is bytes, "BACKEND_BYTES_REQUIRED")
        _require(type(architecture) is str and architecture in ARCHITECTURES, "BACKEND_ARCHITECTURE_INVALID")
        instant = require_time(now, "now")
        envelope, capacity, release_trust, tenant_trust = verify_backend_authority(
            envelope_bytes, capacity_bytes, release_trust_bytes, tenant_trust_bytes, now=instant)
        _require(envelope["nonce"] == expected_nonce and envelope["tenantId"] == expected_tenant
                 and envelope["environmentId"] == expected_environment
                 and envelope["campaignReleaseDigest"] == expected_release,
                 "BACKEND_EXPECTED_SUBJECT_MISMATCH")
        _require(byte_digest(release_bytes) == expected_release, "BACKEND_RELEASE_DIGEST_MISMATCH")
        release = require_canonical_document(release_bytes)
        plan = _release_plan(release, plan_bytes, envelope, architecture)
        _require(plan["target"]["architecture"] == architecture, "BACKEND_ARCHITECTURE_MISMATCH")
        _require(plan["namespace"] == capacity["namespace"] and
                 plan["serviceAccountSubject"] == capacity["serviceAccountSubject"], "BACKEND_PLAN_SCOPE_MISMATCH")
        _require(release["endpointPolicyDigests"] == sorted(set(e["authorizationPolicyDigest"]
                 for e in envelope["endpoints"])), "BACKEND_ENDPOINT_POLICY_MISMATCH")
        for case in CASES:
            build_probe_request(envelope, capacity, plan, case)
        starts = [envelope["issuedAt"], capacity["validFrom"]]
        ends = [envelope["expiresAt"], capacity["expiresAt"]]
        for trust, key_id in ((release_trust, envelope["platformSignerKeyId"]),
                             (tenant_trust, envelope["tenantSignerKeyId"]),
                             (tenant_trust, capacity["signerKeyId"])):
            key = next(item for item in trust["keys"] if item["keyId"] == key_id)
            starts.append(key["validFrom"])
            ends.append(key["validUntil"])
        start = max(starts, key=lambda value: require_time(value, "start"))
        end = min(ends, key=lambda value: require_time(value, "end"))
        _require(require_time(start, "start") <= instant < require_time(end, "end"), "BACKEND_WINDOW_EXPIRED")
        return validate_binding({"nonce": envelope["nonce"], "tenantId": envelope["tenantId"],
            "environmentId": envelope["environmentId"], "packetDigest": PACKET_DIGEST,
            "commandSetDigest": envelope["commandSetDigest"], "releaseDigest": expected_release,
            "capacityDigest": envelope["capacityAuthorizationDigest"], "endpointId": plan["endpointId"],
            "namespace": capacity["namespace"], "notBefore": start, "notAfter": end})
    except ConformanceError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise ConformanceError("BACKEND_AUTHORITY_MALFORMED", "malformed backend binding") from exc
