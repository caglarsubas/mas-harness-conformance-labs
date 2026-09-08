"""Closed internal DATA contracts. No object returned here grants execution.

Protected custody, kernel peers, replay reservation and descendant cleanup belong
to the independently installed supervisor, not to JSON or this pure state model.
"""
from __future__ import annotations

from typing import Any

from .canonical import canonical_bytes, canonical_digest, require_canonical_document
from .errors import ConformanceError
from .linux_readiness import (ARCHITECTURES, CASE_CHECKS, REPOSITORIES, STATUSES,
                              integer, require_time)
from .schema import closed, require_digest, require_id

SCHEMA = "harness.planeon.ai/live-backend-session/v1alpha1"
MAX_SESSION_BYTES = 16384
MAX_RESPONSE_BYTES = 4194304
MAX_DEPTH = 8
ID_FIELDS = ("nonce", "tenantId", "environmentId", "endpointId", "namespace")
DIGEST_FIELDS = ("packetDigest", "commandSetDigest", "releaseDigest", "capacityDigest")
BINDING_FIELDS = (*ID_FIELDS, *DIGEST_FIELDS, "notBefore", "notAfter")
SESSION_FIELDS = ("schemaVersion", *ID_FIELDS, *DIGEST_FIELDS, "issuedAt", "expiresAt", "state")
STATES = ("UNAVAILABLE", "VALIDATED_DATA", "RESERVED", "RUNNING", "COMPLETED",
          "FAILED", "CANCELLED", "EXPIRED")
TRANSITIONS = (
    ("VALIDATED_DATA", "RESERVED"),
    ("RESERVED", "RUNNING"), ("RESERVED", "FAILED"),
    ("RESERVED", "CANCELLED"), ("RESERVED", "EXPIRED"),
    ("RUNNING", "COMPLETED"), ("RUNNING", "FAILED"),
    ("RUNNING", "CANCELLED"), ("RUNNING", "EXPIRED"),
)
REQUEST_FIELDS = ("schemaVersion", "operation", "endpointId", "namespace", "method",
                  "path", "runNonce", "architecture", "probeDigest", "commandDigest")
RECEIPT_FIELDS = ("caseId", "status", "observedAt", "runNonce", "probeDigest",
                  "commandDigest", "outputDigest", "output")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ConformanceError(code, "invalid live-backend data; no execution authority")


def _bounded(value: Any, maximum: int, depth: int = 0, remaining: int | None = None) -> int:
    # Charge every occurrence, including aliased containers, before encoding.
    # This lower bound caps traversal and expanded output; final canonical bytes
    # enforce exact UTF-8 size. Per-node limits alone permit exponential DAGs.
    if remaining is None:
        remaining = maximum
    _require(depth <= MAX_DEPTH, "SESSION_DEPTH_EXCEEDED")
    kind = type(value)
    # Exact builtin types: do not invoke user object serialization hooks.
    if kind is str:
        _require(len(value) <= maximum, "SESSION_SIZE_EXCEEDED")
        remaining -= len(value) + 2
    elif kind in (dict, list):
        _require(len(value) <= 4096, "SESSION_COLLECTION_EXCEEDED")
        remaining -= 2 + max(0, len(value) - 1) + (len(value) if kind is dict else 0)
        _require(remaining >= 0, "SESSION_SIZE_EXCEEDED")
        if kind is dict:
            for key, item in value.items():
                _require(type(key) is str, "SESSION_TYPE_INVALID")
                remaining = _bounded(key, maximum, depth + 1, remaining)
                remaining = _bounded(item, maximum, depth + 1, remaining)
        else:
            for item in value:
                remaining = _bounded(item, maximum, depth + 1, remaining)
    else:
        _require(kind in (int, bool, type(None)), "SESSION_TYPE_INVALID")
        if kind is int:
            _require(-(2**53 - 1) <= value <= 2**53 - 1, "SESSION_TYPE_INVALID")
        remaining -= 1
    _require(remaining >= 0, "SESSION_SIZE_EXCEEDED")
    return remaining


def data_document(value: Any, maximum: int = MAX_SESSION_BYTES) -> dict[str, Any]:
    """Bounded canonical bytes or exact builtins to detached, non-authorizing data."""
    _require(type(maximum) is int and maximum in (MAX_SESSION_BYTES, MAX_RESPONSE_BYTES),
             "SESSION_SIZE_LIMIT_INVALID")
    try:
        if type(value) is bytes:
            _require(len(value) <= maximum, "SESSION_SIZE_EXCEEDED")
            value = require_canonical_document(value)
        _bounded(value, maximum)
        _require(type(value) is dict, "SESSION_TYPE_INVALID")
        encoded = canonical_bytes(value)
        _require(len(encoded) <= maximum, "SESSION_SIZE_EXCEEDED")
        return require_canonical_document(encoded)
    except ConformanceError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ConformanceError("SESSION_DATA_MALFORMED", "malformed live-backend data") from exc


def validate_binding(value: Any) -> dict[str, Any]:
    binding = data_document(value)
    closed(binding, BINDING_FIELDS)
    for name in ID_FIELDS:
        require_id(binding[name], name)
    for name in DIGEST_FIELDS:
        require_digest(binding[name], name)
    _require(require_time(binding["notBefore"], "notBefore") <
             require_time(binding["notAfter"], "notAfter"), "SESSION_WINDOW_INVALID")
    return binding


def _session(value: Any, expected_binding: Any) -> dict[str, Any]:
    session = data_document(value)
    closed(session, SESSION_FIELDS)
    _require(session["schemaVersion"] == SCHEMA, "SESSION_SCHEMA_INVALID")
    _require(type(session["state"]) is str and session["state"] in STATES, "SESSION_STATE_INVALID")
    binding = validate_binding(expected_binding)
    for name in (*ID_FIELDS, *DIGEST_FIELDS):
        _require(type(session[name]) is str and session[name] == binding[name], "SESSION_BINDING_MISMATCH")
    issued = require_time(session["issuedAt"], "issuedAt")
    expires = require_time(session["expiresAt"], "expiresAt")
    _require(require_time(binding["notBefore"], "notBefore") <= issued < expires <=
             require_time(binding["notAfter"], "notAfter"), "SESSION_WINDOW_INVALID")
    return session


def validate_session(value: Any, expected_binding: Any, now: str) -> dict[str, Any]:
    """Pure data validation only, including half-open validity [issued, expires)."""
    session = _session(value, expected_binding)
    instant = require_time(now, "now")
    _require(require_time(session["issuedAt"], "issuedAt") <= instant <
             require_time(session["expiresAt"], "expiresAt"), "SESSION_NOT_CURRENT")
    _require(session["state"] != "EXPIRED", "SESSION_NOT_CURRENT")
    return session


def transition_candidate(value: Any, next_state: str, expected_binding: Any,
                         now: str) -> dict[str, Any]:
    """Describe a transition, NEVER perform it or return a usable session handle.

Even VALIDATED_DATA -> RESERVED is only a proposed record. The supervisor must
independently authenticate its peer and durably consume the nonce first. There
is deliberately no verified/custody/FD parameter or executable transition API.
"""
    session = _session(value, expected_binding)
    _require(type(next_state) is str and (session["state"], next_state) in TRANSITIONS,
             "SESSION_TRANSITION_INVALID")
    instant = require_time(now, "now")
    _require(require_time(session["issuedAt"], "issuedAt") <= instant, "SESSION_NOT_CURRENT")
    expired = instant >= require_time(session["expiresAt"], "expiresAt")
    _require((next_state == "EXPIRED") == expired, "SESSION_TRANSITION_TIME_INVALID")
    return {"fromState": session["state"], "toState": next_state,
            "sessionDigest": canonical_digest(session), "nonce": session["nonce"],
            "requiresProtectedSupervisor": True, "evidenceClass": "UNIT_VERIFICATION_ONLY",
            "nativeAcceptance": False}


def _request(value: Any) -> dict[str, Any]:
    request = data_document(value)
    closed(request, REQUEST_FIELDS)
    case = request["operation"]
    _require(type(case) is str and case in CASE_CHECKS, "SESSION_OPERATION_INVALID")
    _require(request["schemaVersion"] == "harness.planeon.ai/linux-probe-request/v1alpha1"
             and request["method"] == "POST"
             and request["path"] == "/v1/linux-baseline/" + case.lower().replace("_", "-")
             and type(request["architecture"]) is str and request["architecture"] in ARCHITECTURES,
             "SESSION_REQUEST_INVALID")
    for name in ("endpointId", "namespace", "runNonce"):
        require_id(request[name], name)
    for name in ("probeDigest", "commandDigest"):
        require_digest(request[name], name)
    return request


def validate_request(value: Any, session: Any, expected_binding: Any,
                     expected_request: Any, now: str) -> dict[str, Any]:
    """Compare to the existing fixed builder output, not a caller-defined URL/argv."""
    current = validate_session(session, expected_binding, now)
    _require(current["state"] == "RUNNING", "SESSION_NOT_RUNNING")
    request, expected = _request(value), _request(expected_request)
    _require(request == expected, "SESSION_REQUEST_MISMATCH")
    for name, field in (("runNonce", "nonce"), ("endpointId", "endpointId"), ("namespace", "namespace")):
        _require(request[name] == current[field], "SESSION_REQUEST_SCOPE_MISMATCH")
    return request


def validate_receipt(value: Any, session: Any, expected_binding: Any,
                     expected_request: Any, expected_regressions: Any, now: str) -> dict[str, Any]:
    """Validate the unchanged Linux case-record shape; not a signature or receipt grant.

Architecture, scope and packet/release come from the independently selected
request/session. Raw case records alone cannot distinguish architectures or
authorize acceptance. CONF-LIVE-006 separately verifies the full signed record.
"""
    current = validate_session(session, expected_binding, now)
    request = validate_request(expected_request, current, expected_binding, expected_request, now)
    receipt = data_document(value, MAX_RESPONSE_BYTES)
    closed(receipt, RECEIPT_FIELDS)
    for name, field in (("caseId", "operation"), ("runNonce", "runNonce"),
                        ("probeDigest", "probeDigest"), ("commandDigest", "commandDigest")):
        _require(receipt[name] == request[field], "SESSION_RECEIPT_MISMATCH")
    _require(require_time(current["issuedAt"], "issuedAt") <=
             require_time(receipt["observedAt"], "observedAt") <= require_time(now, "now"),
             "SESSION_RECEIPT_TIME_INVALID")
    output = receipt["output"]
    _require(type(output) is dict, "SESSION_TYPE_INVALID")
    closed(output, ("checks", "regressions"))
    _require(type(output["checks"]) is dict and type(output["regressions"]) is dict,
             "SESSION_TYPE_INVALID")
    case = request["operation"]
    closed(output["checks"], CASE_CHECKS[case])
    _require(all(type(s) is str and s in STATUSES for s in output["checks"].values()),
             "SESSION_RECEIPT_STATUS_INVALID")
    expected = data_document(expected_regressions)
    repositories = REPOSITORIES if case == "FULL_PREDECESSOR_REGRESSION" else ()
    closed(output["regressions"], repositories)
    closed(expected, repositories)
    failed = False
    for name in repositories:
        result, baseline = output["regressions"][name], expected[name]
        _require(type(result) is dict and type(baseline) is dict, "SESSION_TYPE_INVALID")
        closed(result, ("inventoryDigest", "collected", "executed", "skipped", "failed"))
        closed(baseline, ("inventoryDigest", "testCount"))
        require_digest(baseline["inventoryDigest"], "inventoryDigest")
        integer(baseline["testCount"], 120 if name == "conformance" else 1)
        for field in ("collected", "executed", "skipped", "failed"):
            integer(result[field])
        _require(result["failed"] <= result["executed"] <= result["collected"]
                 and result["skipped"] <= result["collected"], "SESSION_REGRESSION_COUNTS_INVALID")
        _require(result["inventoryDigest"] == baseline["inventoryDigest"] and
                 result["collected"] == baseline["testCount"], "SESSION_REGRESSION_MISMATCH")
        failed |= bool(result["skipped"] or result["failed"] or result["collected"] != result["executed"])
    statuses = tuple(output["checks"].values())
    overall = "FAIL" if failed or "FAIL" in statuses else (
        "NOT_RUN_ENV_UNAVAILABLE" if "NOT_RUN_ENV_UNAVAILABLE" in statuses else "PASS")
    _require(receipt["status"] == overall, "SESSION_FALSE_RECEIPT_STATUS")
    _require(receipt["outputDigest"] == canonical_digest(output, "planeon.linux-probe-output/v1alpha1"),
             "SESSION_OUTPUT_DIGEST_MISMATCH")
    return receipt
