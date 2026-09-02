from __future__ import annotations

from typing import Any

from .errors import ConformanceError
from .schema import closed, require_id, require_object, require_time, reject_secret_shape

ALLOWED_EVENT_TYPES = (
    "harness.operation.state.changed.v1",
    "harness.approval.state.changed.v1",
    "harness.installation.state.changed.v1",
    "harness.evidence.recorded.v1",
)


def validate_event(document: Any) -> dict[str, Any]:
    value = require_object(document, "HarnessCloudEvent")
    closed(value, ("specversion", "id", "source", "type", "time", "subject", "datacontenttype", "tenantid", "data"))
    if value["specversion"] != "1.0":
        raise ConformanceError("UNSUPPORTED_CLOUDEVENTS_VERSION", "specversion must be 1.0")
    require_id(value["id"], "id")
    require_id(value["tenantid"], "tenantid")
    require_time(value["time"], "time")
    if value["type"] not in ALLOWED_EVENT_TYPES:
        raise ConformanceError("UNKNOWN_EVENT_TYPE", "event type is not canonical")
    if value["datacontenttype"] != "application/json":
        raise ConformanceError("INVALID_CONTENT_TYPE", "event data must be application/json")
    if not isinstance(value["source"], str) or not value["source"].startswith("urn:planeon:"):
        raise ConformanceError("INVALID_EVENT_SOURCE", "event source must be a Planeon URN")
    if not isinstance(value["subject"], str) or len(value["subject"]) > 256:
        raise ConformanceError("INVALID_EVENT_SUBJECT", "event subject is invalid")
    data = require_object(value["data"], "event data")
    closed(data, ("entityId", "fromState", "toState", "version", "evidenceDigest"))
    require_id(data["entityId"], "entityId")
    if not isinstance(data["fromState"], str) or not isinstance(data["toState"], str):
        raise ConformanceError("INVALID_EVENT_STATE", "event state fields must be strings")
    if not isinstance(data["version"], int) or isinstance(data["version"], bool) or data["version"] < 1:
        raise ConformanceError("INVALID_EVENT_VERSION", "event version must be positive")
    from .schema import require_digest

    require_digest(data["evidenceDigest"], "evidenceDigest")
    reject_secret_shape(value)
    return value
