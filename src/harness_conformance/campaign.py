from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .canonical import canonical_digest, load_json
from .errors import ConformanceError
from .events import validate_event
from .lifecycle import assert_transition
from .models import ControlResult, ResultStatus
from .schema import closed, require_object, validate, validate_campaign, validate_environment


def _observation(control_id: str, status: ResultStatus, reason: str, detail: Any) -> str:
    return canonical_digest(
        {"controlId": control_id, "detail": detail, "reasonCode": reason, "status": status.value},
        "planeon.harness-conformance-observation/v1alpha1",
    )


def _static(control: dict[str, Any], _: dict[str, Any]) -> tuple[ResultStatus, str, Any]:
    data = require_object(control["input"], "static assertion")
    closed(data, ("actual", "expected"), ("applicable", "severity"))
    if data.get("applicable", True) is False:
        return ResultStatus.NOT_APPLICABLE, "CONTROL_NOT_APPLICABLE", {"applicable": False}
    if data["actual"] == data["expected"]:
        return ResultStatus.PASS, "ASSERTION_MATCHED", {"matched": True}
    if data.get("severity", "REQUIRED") == "ADVISORY":
        return ResultStatus.WARN, "ADVISORY_ASSERTION_MISMATCH", {"matched": False}
    return ResultStatus.FAIL, "ASSERTION_MISMATCH", {"matched": False}


def _schema(control: dict[str, Any], _: dict[str, Any]) -> tuple[ResultStatus, str, Any]:
    data = require_object(control["input"], "schema assertion")
    closed(data, ("kind", "document"))
    try:
        validate(data["kind"], data["document"])
    except ConformanceError as exc:
        return ResultStatus.FAIL, exc.reason, {"valid": False, "reason": exc.reason}
    return ResultStatus.PASS, "SCHEMA_VALID", {"valid": True}


def _lifecycle(control: dict[str, Any], _: dict[str, Any]) -> tuple[ResultStatus, str, Any]:
    data = require_object(control["input"], "lifecycle assertion")
    closed(data, ("entity", "fromState", "toState"))
    try:
        assert_transition(data["entity"], data["fromState"], data["toState"])
    except ConformanceError as exc:
        return ResultStatus.FAIL, exc.reason, {"legal": False}
    return ResultStatus.PASS, "TRANSITION_LEGAL", {"legal": True}


def _event(control: dict[str, Any], _: dict[str, Any]) -> tuple[ResultStatus, str, Any]:
    data = require_object(control["input"], "event assertion")
    closed(data, ("event",))
    try:
        validate_event(data["event"])
    except ConformanceError as exc:
        return ResultStatus.FAIL, exc.reason, {"valid": False, "reason": exc.reason}
    return ResultStatus.PASS, "EVENT_VALID", {"valid": True}


def _capability(control: dict[str, Any], environment: dict[str, Any]) -> tuple[ResultStatus, str, Any]:
    data = require_object(control["input"], "environment capability")
    closed(data, ("capability", "expected"))
    name = data["capability"]
    expected = data["expected"]
    if not isinstance(name, str) or expected not in (True, False):
        raise ConformanceError("INVALID_CAPABILITY_ASSERTION", "capability assertion is malformed")
    actual = environment["capabilities"].get(name)
    if actual is None:
        return ResultStatus.NOT_RUN_ENV_UNAVAILABLE, "ENVIRONMENT_CAPABILITY_UNAVAILABLE", {"available": False}
    if actual == expected:
        return ResultStatus.PASS, "ENVIRONMENT_CAPABILITY_MATCHED", {"available": True, "matched": True}
    return ResultStatus.FAIL, "ENVIRONMENT_CAPABILITY_MISMATCH", {"available": True, "matched": False}


HANDLERS: dict[str, Callable[[dict[str, Any], dict[str, Any]], tuple[ResultStatus, str, Any]]] = {
    "STATIC_ASSERTION": _static,
    "SCHEMA_ASSERTION": _schema,
    "LIFECYCLE_ASSERTION": _lifecycle,
    "EVENT_ASSERTION": _event,
    "ENVIRONMENT_CAPABILITY": _capability,
}


def _overall(results: list[ControlResult]) -> ResultStatus:
    required = [result for result in results if result.required]
    if any(result.status is ResultStatus.FAIL for result in results):
        return ResultStatus.FAIL
    if any(result.status is ResultStatus.NOT_RUN_ENV_UNAVAILABLE for result in required):
        return ResultStatus.NOT_RUN_ENV_UNAVAILABLE
    if any(result.status is not ResultStatus.PASS for result in required):
        return ResultStatus.WARN
    if any(result.status in (ResultStatus.WARN, ResultStatus.NOT_RUN_ENV_UNAVAILABLE) for result in results):
        return ResultStatus.WARN
    if results and all(result.status is ResultStatus.NOT_APPLICABLE for result in results):
        return ResultStatus.NOT_APPLICABLE
    return ResultStatus.PASS


def run_campaign(
    campaign: dict[str, Any],
    environment: dict[str, Any],
    *,
    run_id: str,
    observed_at: str,
) -> dict[str, Any]:
    campaign = validate_campaign(campaign)
    environment = validate_environment(environment)
    results: list[ControlResult] = []
    for control in campaign["controls"]:
        try:
            status, reason, detail = HANDLERS[control["handler"]](control, environment)
        except ConformanceError as exc:
            status, reason, detail = ResultStatus.FAIL, exc.reason, {"valid": False, "reason": exc.reason}
        results.append(
            ControlResult(
                control_id=control["controlId"],
                handler=control["handler"],
                required=control["required"],
                axis=control["axis"],
                status=status,
                reason_code=reason,
                observation_digest=_observation(control["controlId"], status, reason, detail),
            )
        )
    report = {
        "schemaVersion": "harness.planeon.ai/campaign-report/v1alpha1",
        "campaignId": campaign["campaignId"],
        "campaignVersion": campaign["version"],
        "environmentId": environment["environmentId"],
        "executionClass": campaign["executionClass"],
        "observedAt": observed_at,
        "results": [result.as_dict() for result in results],
        "runId": run_id,
        "status": _overall(results).value,
        "tenantId": environment["tenantId"],
    }
    report["reportDigest"] = canonical_digest(report, "planeon.harness-conformance-report/v1alpha1")
    return report


def run_campaign_files(campaign_path: Path, repository: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    campaign = validate_campaign(load_json(campaign_path))
    environment_path = (repository / campaign["environmentFixture"]).resolve()
    if repository.resolve() not in environment_path.parents or environment_path.is_symlink():
        raise ConformanceError("FIXTURE_OUTSIDE_REPOSITORY", "environment fixture escaped repository")
    environment = validate_environment(load_json(environment_path))
    run_id = f"{campaign['campaignId']}.deterministic"
    report = run_campaign(campaign, environment, run_id=run_id, observed_at=environment["capturedAt"])
    return report, environment
