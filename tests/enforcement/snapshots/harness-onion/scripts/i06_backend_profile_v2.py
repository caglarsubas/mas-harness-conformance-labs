#!/usr/bin/env python3
"""I06 backend profile v2 (W02g-F): distribution evidence bound to an accepted W02a v3 record.

Successor of the adopted I06 backend profile (architecture/i06-backend-profile/, MET-ENFORCE-006), whose bytes
later layers pin. The writer inventory, identity closure, upstream facts, upstream bootstrap RBAC and the v1 model
(scripts/i06_backend_profile.py) stay unchanged and are read from there. v2 answers the W02g round-2 findings
carried to W02g-F:

- N1: an evidence record names one W02a v3 record by schema version and qualification digest, and that record must be
  one that W02a v3's `check_record` accepts. A test-only backend qualifies only in an explicit fixture call, as in
  W02a v3's `check_qualification`. W02a v3 admits only the test-only unit-distribution backend, and this model is
  bound to W02a v3's pinned schema, so no production call is accepted. Production evidence needs both a reviewed W02a
  revision with a production backend profile and an I06 successor bound to it (W03).
- N2: the apiserver's loopback user system:apiserver holds no resource rule at all, not only no policy-relevant one;
  an observer that finds a non-resource-URL rule on it refuses to produce the snapshot (W03).
- N3: shared and nested backend cgroups are refused by W02a v3's `check_record`, which N1 applies.

- `check_evidence` checks one distribution evidence record (SC00-SC15) against its W02a v3 record.
- `check_rbac_snapshot` checks an effective-RBAC snapshot against a checked closure (IC00-IC05).
- `check_inventory` and `check_closure` are the v1 checks; their inputs are unchanged.

DATA_CHECK_ONLY: none of them inspects a cluster, a distribution or a kernel, grants authority or selects a
distribution. Every refusal names the criterion or closure rule it breaks.
"""
from __future__ import annotations

from typing import Any

try:
    import i06_backend_profile as v1
    import native_qualification_v3 as w02a
except ImportError:
    from scripts import i06_backend_profile as v1
    from scripts import native_qualification_v3 as w02a

EVIDENCE_VERSION = "planeon.internal.i06-distribution-evidence/v2"
SNAPSHOT_VERSION = v1.SNAPSHOT_VERSION
W02A_VERSION = "planeon.internal.native-qualification/v3"
LOOPBACK_USER = ("User", "system:apiserver")
EVIDENCE_KEYS = {"schemaVersion", "w02aRecord", "implementationId", "testOnly", "kubernetesVersion", "distribution",
                 "artifacts", "components", "datastore", "apiserver", "controllerManager", "kubelet", "versioning",
                 "credentialsOnHost", "apiClients", "runtimeSocket", "sealedConfiguration"}
V1_PROFILE_KEYS = ("profile", "implementationId", "componentKeys")

require = v1.require
check_inventory = v1.check_inventory
check_closure = v1.check_closure


def record_digest(record: Any) -> str:
    """W02a's qualification digest of a record: "sha256:" and the lowercase hex SHA-256 of W02a's canonical JSON form
    (sorted keys, no whitespace, UTF-8), as W02a v3 captures spell `qualificationDigest`."""
    return "sha256:" + w02a.digest(w02a.canonical(record))


def check_evidence(record: Any, inventory: dict, w02a_record: Any, w02a_profile: Any, w02a_endpoints: Any,
                   w02a_schema: dict, test_fixture: bool = False) -> None:
    """Check one evidence record against SC00-SC15, bound by digest to one W02a v3 record that check_record accepts.

    The evidence binds to that one record (one boot, nonce set and validity window) and is re-issued for each record.
    `check_record` is not W02a's acceptance decision: combining this check with `check_qualification`'s acceptance of
    the same record is the caller's composition (W03). Callers inherit W02a v3's caller obligations 1 (the profile is
    valid under the pinned proxy profile contract) and 4 (`test_fixture=True` only when qualifying a test fixture).
    `test_fixture` must be True to accept a test-only backend; it is the only way to accept one (N1)."""
    require(type(test_fixture) is bool, "SC00 fixture flag must be a boolean")
    v1._keys(record, EVIDENCE_KEYS, "SC00 closed evidence record")
    require(record["schemaVersion"] == EVIDENCE_VERSION, "SC00 evidence version")
    reference = record["w02aRecord"]
    v1._keys(reference, {"schemaVersion", "qualificationDigest"}, "SC00 closed W02a record reference")
    require(reference["schemaVersion"] == W02A_VERSION, "SC00 evidence names a W02a record of another version")
    refusal = w02a.explain(w02a.check_record, w02a_record, w02a_profile, w02a_endpoints, w02a_schema)
    require(refusal is None, "SC00 W02a v3 refuses the backend record: %s" % refusal)
    require(type(reference["qualificationDigest"]) is str and reference["qualificationDigest"] == record_digest(w02a_record),
            "SC00 evidence names a different W02a record")
    backend = w02a_record["backendProfile"]
    require(type(record["testOnly"]) is bool and record["testOnly"] is backend["testOnly"],
            "SC00 evidence and its W02a backend disagree on test-only")
    require(test_fixture or backend["testOnly"] is False,
            "SC00 a test-only W02a backend qualifies only in an explicit fixture call")
    projection = {key: value for key, value in record.items() if key != "w02aRecord"}
    projection["schemaVersion"] = v1.EVIDENCE_VERSION
    v1.check_evidence(projection, inventory,
                      {"backendProfile": {key: backend[key] for key in V1_PROFILE_KEYS},
                       "backendComponents": w02a_record["backendComponents"]},
                      production=not test_fixture)


def check_rbac_snapshot(snapshot: Any, closure: dict, inventory: dict, bootstrap: Any, namespace: str) -> None:
    """IC00-IC05 as in v1; in addition the loopback user system:apiserver holds no resource rule at all (N2).

    The v1 snapshot shape carries resource rules only. Observer obligation: a non-resource-URL rule bound to
    system:apiserver is not dropped; the observer refuses to produce the snapshot (carried to W03)."""
    v1.check_rbac_snapshot(snapshot, closure, inventory, bootstrap, namespace)
    for subject in snapshot["subjects"]:
        if (subject["kind"], subject["name"]) == LOOPBACK_USER:
            require(subject["effectiveRules"] == [], "IC03 the loopback user system:apiserver holds an RBAC rule")


ERRORS = v1.ERRORS
explain = v1.explain
