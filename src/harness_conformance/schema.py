from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable

from .errors import ConformanceError
from .models import EVIDENCE_AXES, HANDLERS, LIVE_EVIDENCE_AXES, RESULT_STATES

ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PORTING_FIELDS = {"schemaVersion", "destinationRepository", "records"}
SECRET_TERMS = ("password", "apiKey", "api_key", "accessToken", "privateKey", "secret")


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConformanceError("TYPE_MISMATCH", f"{name} must be an object")
    return value


def closed(value: dict[str, Any], required: Iterable[str], optional: Iterable[str] = ()) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - value.keys())
    extra = sorted(value.keys() - allowed)
    if missing:
        raise ConformanceError("MISSING_FIELD", f"missing fields: {', '.join(missing)}")
    if extra:
        raise ConformanceError("UNKNOWN_FIELD", f"unknown fields: {', '.join(extra)}")


def require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or not ID.fullmatch(value):
        raise ConformanceError("INVALID_IDENTIFIER", f"{name} is not a canonical identifier")
    return value


def require_key_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not KEY_ID.fullmatch(value):
        raise ConformanceError("INVALID_KEY_ID", f"{name} is not a bounded key identifier")
    return value


def require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ConformanceError("INVALID_DIGEST", f"{name} must be lowercase sha256")
    return value


def require_time(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        raise ConformanceError("INVALID_TIME", f"{name} must be UTC RFC3339")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ConformanceError("INVALID_TIME", f"{name} must be UTC RFC3339") from exc


def reject_secret_shape(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if any(term.lower() in key.lower() for term in SECRET_TERMS):
                raise ConformanceError("SECRET_SHAPED_FIELD", f"secret-shaped field at {path}.{key}")
            reject_secret_shape(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_shape(item, f"{path}[{index}]")


def validate_environment(document: Any) -> dict[str, Any]:
    value = require_object(document, "environment intake")
    closed(value, ("schemaVersion", "environmentId", "tenantId", "capturedAt", "capabilities"))
    if value["schemaVersion"] != "harness.planeon.ai/environment-intake/v1alpha1":
        raise ConformanceError("UNSUPPORTED_SCHEMA", "unsupported environment intake schema")
    require_id(value["environmentId"], "environmentId")
    require_id(value["tenantId"], "tenantId")
    require_time(value["capturedAt"], "capturedAt")
    capabilities = require_object(value["capabilities"], "capabilities")
    if len(capabilities) > 128:
        raise ConformanceError("COLLECTION_TOO_LARGE", "too many capabilities")
    for name, state in capabilities.items():
        require_id(name, "capability")
        if state not in (True, False, None):
            raise ConformanceError("INVALID_CAPABILITY", "capability values are true, false, or null")
    reject_secret_shape(value)
    return value


def validate_campaign(document: Any) -> dict[str, Any]:
    value = require_object(document, "campaign")
    closed(value, ("schemaVersion", "campaignId", "version", "description", "executionClass", "environmentFixture", "controls"))
    if value["schemaVersion"] != "harness.planeon.ai/conformance-campaign/v1alpha1":
        raise ConformanceError("UNSUPPORTED_SCHEMA", "unsupported campaign schema")
    require_id(value["campaignId"], "campaignId")
    if not isinstance(value["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]):
        raise ConformanceError("INVALID_VERSION", "campaign version must be SemVer core")
    if not isinstance(value["description"], str) or not (1 <= len(value["description"]) <= 512):
        raise ConformanceError("INVALID_DESCRIPTION", "campaign description is unbounded or empty")
    if value["executionClass"] not in ("OFFLINE_TEST", "LIVE_CAMPAIGN"):
        raise ConformanceError("INVALID_EXECUTION_CLASS", "unknown execution class")
    fixture = value["environmentFixture"]
    if not isinstance(fixture, str) or fixture.startswith("/") or ".." in fixture.split("/") or not fixture.endswith(".json"):
        raise ConformanceError("INVALID_FIXTURE_REFERENCE", "environment fixture must be a local relative JSON path")
    controls = value["controls"]
    if not isinstance(controls, list) or not controls or len(controls) > 512:
        raise ConformanceError("INVALID_CONTROLS", "controls must be a bounded non-empty array")
    seen: set[str] = set()
    for control in controls:
        control = require_object(control, "control")
        closed(control, ("controlId", "handler", "required", "axis", "input"))
        control_id = require_id(control["controlId"], "controlId")
        if control_id in seen:
            raise ConformanceError("DUPLICATE_CONTROL", f"duplicate control {control_id}")
        seen.add(control_id)
        if control["handler"] not in HANDLERS:
            raise ConformanceError("INVALID_HANDLER", f"unknown handler for {control_id}")
        if not isinstance(control["required"], bool):
            raise ConformanceError("INVALID_REQUIRED", "required must be boolean")
        if control["axis"] not in EVIDENCE_AXES:
            raise ConformanceError("INVALID_AXIS", "unknown evidence axis")
        require_object(control["input"], "control input")
    if value["executionClass"] == "OFFLINE_TEST" and any(item["axis"] != "UNIT" for item in controls):
        raise ConformanceError("OFFLINE_AXIS_ESCALATION", "offline campaigns may originate UNIT only")
    if value["executionClass"] == "LIVE_CAMPAIGN" and any(item["axis"] not in LIVE_EVIDENCE_AXES for item in controls):
        raise ConformanceError("LIVE_AXIS_ESCALATION", "live campaign axis is not allowed")
    reject_secret_shape(value)
    return value


def validate_result(document: Any) -> dict[str, Any]:
    value = require_object(document, "control result")
    closed(value, ("axis", "controlId", "handler", "observationDigest", "reasonCode", "required", "status"))
    require_id(value["controlId"], "controlId")
    if value["handler"] not in HANDLERS:
        raise ConformanceError("INVALID_HANDLER", "unknown result handler")
    if value["axis"] not in EVIDENCE_AXES:
        raise ConformanceError("INVALID_AXIS", "unknown result axis")
    require_digest(value["observationDigest"], "observationDigest")
    require_id(value["reasonCode"].lower().replace("_", "-"), "reasonCode")
    if not isinstance(value["required"], bool):
        raise ConformanceError("INVALID_REQUIRED", "required must be boolean")
    if value["status"] not in RESULT_STATES:
        raise ConformanceError("INVALID_RESULT", "unknown result state")
    return value


def validate_porting(document: Any) -> dict[str, Any]:
    value = require_object(document, "porting ledger")
    closed(value, PORTING_FIELDS)
    if value["schemaVersion"] != "harness.planeon.ai/porting-ledger/v1alpha1":
        raise ConformanceError("UNSUPPORTED_SCHEMA", "unsupported porting ledger schema")
    if value["destinationRepository"] != "mas-harness-conformance-labs":
        raise ConformanceError("WRONG_DESTINATION", "porting destination mismatch")
    records = value["records"]
    if not isinstance(records, list) or len(records) != 1:
        raise ConformanceError("PORTING_NOT_INERT", "ledger must contain exactly one sentinel")
    record = require_object(records[0], "porting sentinel")
    closed(record, ("disposition", "reason"))
    if record["disposition"] != "NO_AUTHORIZATION":
        raise ConformanceError("COPY_NOT_AUTHORIZED", "no source mapping is authorized")
    if not isinstance(record["reason"], str) or not record["reason"]:
        raise ConformanceError("INVALID_REASON", "porting sentinel needs a reason")
    return value


VALIDATORS = {
    "campaign": validate_campaign,
    "environment-intake": validate_environment,
    "control-result": validate_result,
    "porting-ledger": validate_porting,
}


def validate(kind: str, document: Any) -> dict[str, Any]:
    try:
        validator = VALIDATORS[kind]
    except KeyError as exc:
        raise ConformanceError("UNKNOWN_KIND", f"unknown document kind {kind!r}") from exc
    return validator(document)
