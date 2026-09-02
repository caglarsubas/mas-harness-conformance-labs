from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ResultStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_RUN_ENV_UNAVAILABLE = "NOT_RUN_ENV_UNAVAILABLE"


RESULT_STATES = tuple(item.value for item in ResultStatus)
EVIDENCE_AXES = (
    "SOURCE",
    "UNIT",
    "CI",
    "MERGE",
    "ARTIFACT",
    "SIGNATURE",
    "DEPLOYMENT",
    "RUNTIME",
    "SECURITY",
    "ASSURANCE",
    "TENANT_ACCEPTANCE_CANDIDATE",
    "TENANT_ACCEPTANCE",
)
LIVE_EVIDENCE_AXES = (
    "DEPLOYMENT",
    "RUNTIME",
    "SECURITY",
    "ASSURANCE",
    "TENANT_ACCEPTANCE_CANDIDATE",
)
HANDLERS = (
    "STATIC_ASSERTION",
    "SCHEMA_ASSERTION",
    "LIFECYCLE_ASSERTION",
    "EVENT_ASSERTION",
    "ENVIRONMENT_CAPABILITY",
)


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    handler: str
    required: bool
    axis: str
    status: ResultStatus
    reason_code: str
    observation_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "axis": self.axis,
            "controlId": self.control_id,
            "handler": self.handler,
            "observationDigest": self.observation_digest,
            "reasonCode": self.reason_code,
            "required": self.required,
            "status": self.status.value,
        }
