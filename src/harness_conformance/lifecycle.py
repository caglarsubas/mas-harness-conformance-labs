from __future__ import annotations

from .errors import ConformanceError

TRANSITIONS: dict[str, dict[str, frozenset[str]]] = {
    "Operation": {
        "PENDING": frozenset(("RUNNING", "CANCELLED")),
        "RUNNING": frozenset(("SUCCEEDED", "FAILED", "CANCELLED")),
        "SUCCEEDED": frozenset(),
        "FAILED": frozenset(),
        "CANCELLED": frozenset(),
    },
    "ApprovalRequest": {
        "PENDING": frozenset(("APPROVED", "REJECTED", "CANCELLED", "EXPIRED")),
        "APPROVED": frozenset(),
        "REJECTED": frozenset(),
        "CANCELLED": frozenset(),
        "EXPIRED": frozenset(),
    },
    "HarnessInstallation": {
        "NOT_SELECTED": frozenset(("SELECTED",)),
        "SELECTED": frozenset(("INSTALLING", "NOT_SELECTED")),
        "INSTALLING": frozenset(("READY", "DEGRADED", "FAILED")),
        "READY": frozenset(("UPDATING", "DEGRADED", "UNINSTALLING")),
        "DEGRADED": frozenset(("UPDATING", "READY", "FAILED", "UNINSTALLING")),
        "FAILED": frozenset(("INSTALLING", "UNINSTALLING")),
        "UPDATING": frozenset(("READY", "DEGRADED", "FAILED")),
        "UNINSTALLING": frozenset(("NOT_SELECTED", "FAILED")),
    },
}


def assert_transition(entity: str, before: str, after: str) -> None:
    try:
        targets = TRANSITIONS[entity][before]
    except KeyError as exc:
        raise ConformanceError("UNKNOWN_LIFECYCLE_STATE", "entity or source state is unknown") from exc
    if after not in targets:
        raise ConformanceError("ILLEGAL_LIFECYCLE_TRANSITION", f"{entity} cannot transition from {before} to {after}")
