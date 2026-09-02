from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from harness_conformance.canonical import canonical_bytes, canonical_digest, load_json
from harness_conformance.errors import ConformanceError


def closed(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ConformanceError("VECTOR_SHAPE_INVALID", f"{name} is not closed")
    return value


def model_usage(value: dict[str, Any]) -> dict[str, Any]:
    data = closed(value, {"attributes", "forbiddenPrefixes"}, "model usage input")
    attributes = closed(data["attributes"], set(data["attributes"]), "attributes")
    valid = bool(attributes) and all(key.startswith("mcp.integration.") and not any(key.startswith(prefix) for prefix in data["forbiddenPrefixes"]) for key in attributes)
    return {"tenantNeutral": valid}


def model_route(value: dict[str, Any]) -> dict[str, Any]:
    data = closed(value, {"enforcement", "selectedRoute"}, "model route input")
    disposition = "REFUSED" if data["enforcement"] is True and data["selectedRoute"] is None else "ROUTED"
    return {"disposition": disposition}


def upstream_retry(value: dict[str, Any]) -> dict[str, Any]:
    data = closed(value, {"attempts", "maximumAttempts"}, "retry input")
    return {"bounded": isinstance(data["attempts"], int) and 0 <= data["attempts"] <= data["maximumAttempts"] <= 8}


def data_batch(value: dict[str, Any]) -> dict[str, Any]:
    data = closed(value, {"batchId", "lineage", "records"}, "data batch input")
    lineage = data["lineage"]
    valid = isinstance(lineage, dict) and set(lineage) == {"sourceId", "watermark"} and isinstance(data["records"], list)
    return {"valid": valid}


def connector_profile(value: dict[str, Any]) -> dict[str, Any]:
    data = closed(value, {"connectorId", "discoveryMethod", "localOnly"}, "connector input")
    return {"valid": data["discoveryMethod"] == "DECLARED_SCHEMA" and data["localOnly"] is True}


def local_only(value: dict[str, Any]) -> dict[str, Any]:
    data = closed(value, {"endpointKind", "onlineFallback"}, "local-only input")
    return {"localOnly": data["endpointKind"].startswith("LOCAL_") and data["onlineFallback"] is False}


HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "MODEL_USAGE": model_usage,
    "MODEL_ROUTE": model_route,
    "UPSTREAM_RETRY": upstream_retry,
    "DATA_BATCH": data_batch,
    "CONNECTOR_PROFILE": connector_profile,
    "LOCAL_ONLY": local_only,
}


def execute(vector: dict[str, Any], registry_entry: dict[str, Any]) -> dict[str, Any]:
    closed(vector, {"vectorId", "family", "input", "expected", "exclusions"}, "vector")
    if vector["vectorId"] != registry_entry["vectorId"] or vector["family"] != registry_entry["adapter"]:
        raise ConformanceError("VECTOR_BINDING_MISMATCH", "vector and registry adapter binding differ")
    relation = registry_entry["expectedRelation"]
    if relation == "UNTESTABLE_NO_DESTINATION_TARGET":
        status, reason = "WARN", registry_entry["reason"]
        actual = {"available": False}
    else:
        try:
            handler = HANDLERS[vector["family"]]
        except KeyError as exc:
            raise ConformanceError("UNKNOWN_PARITY_FAMILY", "adapter family is not closed") from exc
        actual = handler(vector["input"])
        status = "PASS" if actual == vector["expected"] else "FAIL"
        reason = "PARITY_EQUIVALENT" if status == "PASS" else "PARITY_MISMATCH"
    result = {
        "observationDigest": canonical_digest({"actual": actual, "expected": vector["expected"]}, "planeon.harness-parity-observation/v1alpha1"),
        "provenanceRecordIds": registry_entry["records"],
        "reasonCode": reason,
        "relation": relation,
        "status": status,
        "vectorId": vector["vectorId"],
    }
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("exactly one vector ID is required", file=sys.stderr)
        return 2
    registry = load_json(ROOT / "parity/registry.yaml")
    matches = [item for item in registry["vectors"] if item["vectorId"] == argv[0]]
    if len(matches) != 1:
        print("vector is unknown or ambiguous", file=sys.stderr)
        return 2
    vector = load_json(ROOT / matches[0]["fixture"])
    try:
        result = execute(vector, matches[0])
    except ConformanceError as exc:
        print(json.dumps({"reasonCode": exc.reason, "status": "FAIL"}, separators=(",", ":")), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0 if result["status"] in {"PASS", "WARN"} else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
