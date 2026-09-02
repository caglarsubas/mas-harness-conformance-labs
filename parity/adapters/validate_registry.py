from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "parity" / "adapters"))

from harness_conformance.canonical import canonical_bytes, load_json
from harness_conformance.errors import ConformanceError

from run_parity import execute

EXPECTED_OBJECTS = {
    "model-usage-contract": "c3ac327e2989ffbbc2452209e2a32f76be911534",
    "model-routing-policy": "68340eccbe4f7784f80788967add702995d0424b",
    "model-request-identity": "657b26d35244cc28fe2ce4339af3f67082d76b29",
    "model-upstream-resilience": "c110ed4d990736b2dc126b3c218333ab7cb16899",
    "data-white-goods-pack": "b18e6d7099220d1b6a2e6797097400a9b3e4e510",
    "data-batch-schema": "aaf77198b1ef680d1f6fa8deaaca1d198f1796a8",
    "data-connector-profile": "224728dadb9c9829494c4db04fd9c90833c7bc30",
    "data-contract-tests": "4e197257af4b372e4e9d949d7b6a23d3cbfed51f",
    "data-local-only-tests": "988ed77cce9beaea8c6c5c0c15fbee2e4b02ce61",
}
RECORD_FIELDS = {"recordId", "repository", "commit", "path", "gitObject", "recordType", "reuseDisposition"}
VECTOR_FIELDS = {"vectorId", "records", "fixture", "adapter", "expectedRelation", "reason"}
FORBIDDEN_FIELDS = {"content", "bytes", "copyAuthorization", "sourceDigest", "sourceOutput", "command", "url", "credential"}


def validate_registry(root: Path = ROOT) -> list[dict[str, object]]:
    registry = load_json(root / "parity/registry.yaml")
    if set(registry) != {"schemaVersion", "provenanceAuthority", "records", "vectors", "exclusions"}:
        raise ConformanceError("REGISTRY_SHAPE_INVALID", "registry top-level shape is not closed")
    if registry["schemaVersion"] != "harness.planeon.ai/warm-parity-registry/v1alpha1":
        raise ConformanceError("REGISTRY_SCHEMA_INVALID", "registry schema is unsupported")
    authority = registry["provenanceAuthority"]
    if authority != {
        "commit": "95d14248d6bfcfbcbec48a7372d7f2d3bfb19ce6",
        "reuseMapSha256": "77a7a1613cd7584ed692d8ca8db64e0142ec536d9fa9654da3cd3867075589b8",
        "reusePathIndexSha256": "5e6843e56b0e4f884400848277c8c3a14b8d0c1d21bf66933a0f5bf0a712c283",
    }:
        raise ConformanceError("PROVENANCE_AUTHORITY_MISMATCH", "public provenance authority differs")
    if set(registry["exclusions"]) != {"CLOUD_API", "BILLING_API", "THIRD_PARTY_KEY", "PUBLIC_NETWORK", "SOURCE_EXECUTION", "MUTATION"}:
        raise ConformanceError("PARITY_EXCLUSIONS_INVALID", "cost and source exclusions are incomplete")
    records = registry["records"]
    if not isinstance(records, list) or len(records) != len(EXPECTED_OBJECTS):
        raise ConformanceError("PROVENANCE_RECORD_COUNT", "provenance record count differs")
    by_id: dict[str, dict[str, object]] = {}
    triples: set[tuple[object, object, object]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != RECORD_FIELDS or set(record) & FORBIDDEN_FIELDS:
            raise ConformanceError("PROVENANCE_RECORD_SHAPE", "provenance record is not closed")
        record_id = record["recordId"]
        if record_id in by_id or record.get("gitObject") != EXPECTED_OBJECTS.get(record_id):
            raise ConformanceError("PROVENANCE_OBJECT_MISMATCH", "provenance record ID or object differs")
        triple = (record["repository"], record["commit"], record["path"])
        if triple in triples or record["recordType"] != "BLOB_PENDING" or record["reuseDisposition"] != "REFERENCE_ONLY_PENDING_PATH_REVIEW":
            raise ConformanceError("PROVENANCE_DISPOSITION_INVALID", "record is duplicate or not reference-only")
        triples.add(triple)
        by_id[str(record_id)] = record
    vectors = registry["vectors"]
    if not isinstance(vectors, list) or not vectors:
        raise ConformanceError("PARITY_VECTOR_COUNT", "registry has no vectors")
    seen: set[str] = set()
    results: list[dict[str, object]] = []
    for entry in vectors:
        if not isinstance(entry, dict) or set(entry) != VECTOR_FIELDS or set(entry) & FORBIDDEN_FIELDS:
            raise ConformanceError("PARITY_VECTOR_SHAPE", "vector registry entry is not closed")
        vector_id = entry["vectorId"]
        if vector_id in seen or not entry["records"] or any(record not in by_id for record in entry["records"]):
            raise ConformanceError("PARITY_VECTOR_BINDING", "vector ID or provenance binding is invalid")
        seen.add(str(vector_id))
        if entry["expectedRelation"] not in {"EXACT", "INTENTIONAL_DIVERGENCE", "UNTESTABLE_NO_DESTINATION_TARGET"} or not entry["reason"]:
            raise ConformanceError("PARITY_RELATION_INVALID", "vector relation or reason is invalid")
        fixture = (root / str(entry["fixture"])).resolve()
        if root.resolve() not in fixture.parents or fixture.is_symlink():
            raise ConformanceError("PARITY_FIXTURE_PATH", "vector fixture escaped or is linked")
        vector = load_json(fixture)
        first = execute(vector, entry)
        second = execute(vector, entry)
        if canonical_bytes(first) != canonical_bytes(second):
            raise ConformanceError("PARITY_NONDETERMINISTIC", "vector result is nondeterministic")
        if entry["expectedRelation"] == "EXACT" and first["status"] != "PASS":
            raise ConformanceError("EXACT_PARITY_FAILED", "exact vector did not pass")
        if entry["expectedRelation"] == "UNTESTABLE_NO_DESTINATION_TARGET" and first["status"] != "WARN":
            raise ConformanceError("UNTESTABLE_FALSE_PASS", "untestable vector must remain WARN")
        results.append(first)
    return results


def main() -> int:
    try:
        results = validate_registry()
    except ConformanceError as exc:
        print(json.dumps({"reasonCode": exc.reason, "status": "FAIL"}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(f"parity_registry_status=PASS records={len(EXPECTED_OBJECTS)} vectors={len(results)} exact={sum(item['status'] == 'PASS' for item in results)} untestable={sum(item['status'] == 'WARN' for item in results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
