"""TG-02 and TG-03 case catalogs (W04-3, CONF-ENF-003; owner decision Q-T8, 2026-10-13).

Every case of the plan's TG-02 (lifecycle) and TG-03 (persistence) groups that waits for W05's release set or for W06's
native hosts is fixed now to the adopted contract vectors that specify it. Each selection is a rule over the vectors'
own content, so a ledger cannot narrow it by data alone, and the expected results are those vectors' own outputs and
final snapshots. The executable source and the wire-level adapter that run these cases against W05's released build
come with W05's release set, together with TG-01's CODEC case; until then every such case is NOT_RUN_ENV_UNAVAILABLE.
Standard library only (owner decision Q-T1, 2026-10-11).
"""
from __future__ import annotations

import _models
from tg01_contract import _replays

I05, I07, SUPPLEMENT, ADMISSION = _replays.I05, _replays.I07, _replays.I05_SUPPLEMENT, _replays.ADM
ARM_MISUSE = {"ACTION_ID_OUT_OF_ORDER", "ACTION_OUTSTANDING", "MANIFEST_OUTSIDE_CASE", "MUTATION_KEY_REUSED", "TEMPLATE_MISMATCH",
              "EXECUTION_NOT_BOUND"}
# The I07 writer's own analogues: a write with no open maintenance, out of order, outside its scope or generation.
WRITE_MISUSE = {"MAINTENANCE_NOT_OPEN", "MAINTENANCE_NOT_BEGUN", "MAINTENANCE_HELD", "WRITE_ID_OUT_OF_ORDER", "SCOPE_MISMATCH",
                "GENERATION_MISMATCH"}
WRITES = ("WRITE_BEGIN", "WRITE_OBJECT", "WRITE_END")
STORAGE_FAILURES = {"STORAGE_FAIL_NEXT", "STORAGE_FAIL_AFTER"}
MISATTRIBUTION = ("M01", "M06", "M07")


def _steps(row):
    return zip(row["events"], row["outputs"])


def _response(output):
    return output["response"] if type(output.get("response")) is dict else {}


def _refused(row, operation, reasons):
    return any(event.get("operation") == operation and _response(output).get("result") == "REFUSED"
               and _response(output).get("reason") in reasons for event, output in _steps(row))


def _closed_request(row, reasons):
    return any(event["type"] == "REQUEST" and output.get("decision") == "CLOSE" and output.get("reason") in reasons
               for event, output in _steps(row))


def _flushes(row):
    return any(event.get("operation") == "ARM_ACTION" and (_response(output).get("flushedConnections") or 0) > 0
               for event, output in _steps(row))


def _closes_for_reconciliation(row):
    return any(event.get("operation") == "CLOSE_GENERATION" and type(event.get("payload")) is dict
               and event["payload"].get("reason") == "RECONCILIATION_REQUIRED" for event in row["events"])


def _records(value, key):
    """Whether `value` (a final snapshot) holds `key` set to True anywhere."""
    if type(value) is dict:
        return value.get(key) is True or any(_records(item, key) for item in value.values())
    if type(value) is list:
        return any(_records(item, key) for item in value)
    return False


def _intent(prefix):
    return lambda row: row["intent"].startswith(prefix)


def _transcripts(rule):
    return lambda vectors: [row["id"] for row in vectors["transcripts"] if rule(row)]


def _unarmed(row):
    return (_closed_request(row, {"REQUEST_MISMATCH", "STAMP_NONE", "NOT_ACTIVE", "PROTOCOL_VIOLATION"})
            or _refused(row, "ARM_ACTION", ARM_MISUSE) or _refused(row, "ACTION_OUTCOME", {"UNKNOWN_ACTION"})
            or any(_refused(row, operation, WRITE_MISUSE) for operation in WRITES))


def _old_socket(row):
    return (_closed_request(row, {"CONNECTION_CLOSED"})
            or any("refusedChannel" in output or "refusedSession" in output for output in row["outputs"])
            or any(_refused(row, operation, {"MAINTENANCE_ENDED"}) for operation in WRITES))


def _queued(row):
    return (_flushes(row) or _refused(row, "ARM_ACTION", {"ACTION_OUTSTANDING", "DRAIN_PENDING"})
            or _refused(row, "BIND_EXECUTION", {"ACTION_OUTSTANDING"}))


def _mentions(value, text):
    """Whether `value` (a final snapshot) holds the string `text` anywhere."""
    if type(value) is dict:
        return any(_mentions(item, text) for item in value.values())
    if type(value) is list:
        return any(_mentions(item, text) for item in value)
    return value == text


def _ambiguous(row):
    return _closes_for_reconciliation(row) or _mentions(row["final"], "IO_AMBIGUOUS") or any(
        output.get("classification") == "IO_AMBIGUOUS" or _response(output).get("classification") == "IO_AMBIGUOUS"
        or "lateUpstream" in output for output in row["outputs"])


def _admitted_before_invalidation(row):
    return (row["intent"].startswith("Counterexample 18") or _records(row["final"], "admittedBeforeInvalidation") or any(
        event.get("operation") == "ACTION_OUTCOME" and _response(output).get("admittedBeforeInvalidation") is True
        for event, output in _steps(row)))


def _c2_c3(row):
    return _flushes(row) or any(event["type"] == "ACCEPT" and "stamp" in output and output["stamp"] is None
                                for event, output in _steps(row))


def _restart(row):
    return any(event["type"] == "GATE_RESTART" for event in row["events"])


def _storage_failure(row):
    return any(event["type"] in STORAGE_FAILURES for event in row["events"])


def _partial(row):
    return any((event["type"] == "STORAGE_FAIL_NEXT" and event.get("torn") is True) or event["type"] == "STORAGE_FAIL_AFTER"
               for event in row["events"])


def _writer_lost_mid_session(row):
    """The writer's channel lost before its session ended with WRITE_END (an orderly end is not a lost answer)."""
    last = None
    for event in row["events"]:
        if event["type"] == "W_FRAME":
            last = event.get("operation")
        elif event["type"] == "W_CHANNEL_LOST" and last != "WRITE_END":
            return True
    return False


def _lost_acknowledgement(row):
    return _writer_lost_mid_session(row) or any(
        event["type"] in ("UPSTREAM_LOST", "UPSTREAM_TIMEOUT") or "lateUpstream" in output
        or (event["type"] == "W_UPSTREAM" and event.get("upstream") in ("LOST", "TIMEOUT"))
        or (event["type"] == "CHANNEL_LOST" and "fatal" in output) for event, output in _steps(row))


def _rollback(row):
    return (_restart(row) or any(event["type"] == "MARKER_FAIL_NEXT" for event in row["events"])
            or _refused(row, "BIND_EXECUTION", {"EXECUTION_REPLAY", "MANIFEST_REUSED"}))


def _disagreement(vectors):
    return [row["id"] for row in vectors["agreement"] if row["expect"] is not None]


def _misattribution(vectors):
    # Sections 6.2-6.3: only a GET can be resent with identical bytes; a mutation's key is refused if repeated (C7).
    return [row["id"] for row in vectors["agreement"]
            if row["verb"] == "GET" and row["expect"] is not None and row["expect"].startswith(MISATTRIBUTION)]


def _stamp_not_armed(vectors):
    return [row["id"] for row in vectors["claims"] if row["claim"].get("check") == "A1"
            and type(row["claim"].get("evidence")) is dict and row["claim"]["evidence"].get("stampEqualsArmedAction") is False]


def _a3_a4(vectors):
    return [row["id"] for row in vectors["claims"] if row["claim"].get("check") in ("A3", "A4")]


UNARMED = ("a request closed as not matching the armed action, without a stamp, while the generation is not active or as a "
           "protocol violation (a second request on one connection); an ARM refused as out of order, outstanding, outside the case "
           "manifest set, a reused mutation key, a template mismatch or with no bound execution; an outcome refused for an "
           "unknown action; or a write refused with no open maintenance, out of order, or outside its scope or generation")
UNARMED_CLAIM = "an A1 admission claim whose stamp is not the armed action's"
OLD_SOCKET = ("a request on a connection closed because it was flushed or stamped for an earlier action; a gate channel or writer "
              "session refused as already used or existing; or a write refused because its maintenance session ended")
QUEUED = ("an ARM that flushes backlogged connections (C2), or an ARM or BIND refused while another action is outstanding, or an "
          "ARM refused while a drain is pending")
CONFLICT = ("an agreement check in which the server's resource result disagrees with the gate's outcome, or a transcript "
            "whose result is IO_AMBIGUOUS (in an output or the final snapshot) or arrives late, or whose generation the "
            "broker closes as RECONCILIATION_REQUIRED")
CONFLICT_AGREEMENT = "an agreement check in which the server's resource result disagrees with the gate's outcome"
CE17 = "the transcripts whose intent is Counterexample 17"
S63 = ("the GET agreement checks that refuse a result attributed to another action (M01 action identifiers, M06 object "
       "identity, M07 UID or resourceVersion differ): HOST_INTERFACE_SPEC sections 6.2-6.3 say only a GET can be resent with "
       "identical bytes and that the misattribution appears in this check")
S63_HELD = ("the transcripts whose generation the broker closes as RECONCILIATION_REQUIRED: section 6.3's disagreement that "
            "becomes HELD")
CE18 = ("the transcripts whose intent is Counterexample 18, every outcome reported ADMITTED_BEFORE_INVALIDATION and every final "
        "snapshot that records it")
CE18_CLAIM = "the A3 (policy write waits for the drain) and A4 (admitted before invalidation) admission claims"
CE21 = "the transcripts whose intent is Counterexample 21"
CE22 = "the transcripts whose intent is Counterexample 22"
C2C3 = "an ARM that flushes backlogged connections (C2), or a connection accepted with no stamp (C3)"
KILL = "a transcript in which the gate is restarted (GATE_RESTART), whatever boundary it stopped at"
ENOSPC = "a transcript with an injected storage failure (STORAGE_FAIL_NEXT or STORAGE_FAIL_AFTER)"
PARTIAL = ("a transcript with a torn storage write (STORAGE_FAIL_NEXT with torn) or a failure part way through a transition's "
           "records (STORAGE_FAIL_AFTER)")
LOST = ("an upstream answer lost, timed out or late (the gate's or the writer's upstream); the broker channel lost with a "
        "fatal answer from the gate; or the writer's channel lost before its session ended with WRITE_END")
ROLLBACK = ("a gate restart, a failed restart marker (MARKER_FAIL_NEXT), or a BIND refused as a replayed execution or a "
            "reused manifest")

# (tag, contract, vector set, vector file prefix, basis, rule) per test group, in the plan's case order.
RULES = {
    "TG-02": [
        ("MATRIX:unarmed/duplicate/cross-case action", "I05 gate channel v3", "transcripts", I05, UNARMED, _transcripts(_unarmed)),
        ("MATRIX:unarmed/duplicate/cross-case action", "I07 policy write v3", "transcripts", I07, UNARMED, _transcripts(_unarmed)),
        ("MATRIX:unarmed/duplicate/cross-case action", "Admission semantics v3", "claims", ADMISSION, UNARMED_CLAIM, _stamp_not_armed),
        ("MATRIX:old socket", "I05 gate channel v3", "transcripts", I05, OLD_SOCKET, _transcripts(_old_socket)),
        ("MATRIX:old socket", "I07 policy write v3", "transcripts", I07, OLD_SOCKET, _transcripts(_old_socket)),
        ("MATRIX:queued action", "I05 gate channel v3", "transcripts", I05, QUEUED, _transcripts(_queued)),
        ("MATRIX:queued action", "I07 policy write v3", "transcripts", I07, QUEUED, _transcripts(_queued)),
        ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "agreement", I05, CONFLICT_AGREEMENT, _disagreement),
        ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "transcripts", I05, CONFLICT, _transcripts(_ambiguous)),
        ("MATRIX:conflicting gate/server result", "I07 policy write v3", "transcripts", I07, CONFLICT, _transcripts(_ambiguous)),
        ("MATRIX:same-generation delayed-identical-request across two armed actions", "I05 gate channel v3", "transcripts", I05,
         CE17, _transcripts(_intent("Counterexample 17"))),
        ("S63-SOURCE", "I05 gate channel v3", "agreement", I05, S63, _misattribution),
        ("S63-SOURCE", "I05 gate channel v3", "transcripts", I05, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("S63-SOURCE", "I07 policy write v3", "transcripts", I07, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("S63-NATIVE", "I05 gate channel v3", "agreement", I05, S63, _misattribution),
        ("S63-NATIVE", "I05 gate channel v3", "transcripts", I05, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("S63-NATIVE", "I07 policy write v3", "transcripts", I07, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("CE18", "I05 gate channel v3", "transcripts", I05, CE18, _transcripts(_admitted_before_invalidation)),
        ("CE18", "I07 policy write v3", "transcripts", I07, CE18, _transcripts(_admitted_before_invalidation)),
        ("CE18", "Admission semantics v3", "claims", ADMISSION, CE18_CLAIM, _a3_a4),
        ("CE22", "I05 gate channel v3", "transcripts", I05, CE22, _transcripts(_intent("Counterexample 22"))),
        ("S8-C2C3", "I05 gate channel v3", "transcripts", I05, C2C3, _transcripts(_c2_c3)),
        ("S8-C2C3", "I07 policy write v3", "transcripts", I07, C2C3, _transcripts(_c2_c3)),
    ],
    "TG-03": [
        ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "transcripts", I05, KILL, _transcripts(_restart)),
        ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "supplement", SUPPLEMENT, KILL, _transcripts(_restart)),
        ("MATRIX:kill at each fsync/send/result boundary", "I07 policy write v3", "transcripts", I07, KILL, _transcripts(_restart)),
        ("MATRIX:ENOSPC", "I05 gate channel v3", "transcripts", I05, ENOSPC, _transcripts(_storage_failure)),
        ("MATRIX:ENOSPC", "I05 gate channel v3", "supplement", SUPPLEMENT, ENOSPC, _transcripts(_storage_failure)),
        ("MATRIX:ENOSPC", "I07 policy write v3", "transcripts", I07, ENOSPC, _transcripts(_storage_failure)),
        ("MATRIX:partial records", "I05 gate channel v3", "transcripts", I05, PARTIAL, _transcripts(_partial)),
        ("MATRIX:partial records", "I05 gate channel v3", "supplement", SUPPLEMENT, PARTIAL, _transcripts(_partial)),
        ("MATRIX:partial records", "I07 policy write v3", "transcripts", I07, PARTIAL, _transcripts(_partial)),
        ("MATRIX:lost acknowledgements", "I05 gate channel v3", "transcripts", I05, LOST, _transcripts(_lost_acknowledgement)),
        ("MATRIX:lost acknowledgements", "I07 policy write v3", "transcripts", I07, LOST, _transcripts(_lost_acknowledgement)),
        ("MATRIX:restart/rollback", "I05 gate channel v3", "transcripts", I05, ROLLBACK, _transcripts(_rollback)),
        ("MATRIX:restart/rollback", "I05 gate channel v3", "supplement", SUPPLEMENT, ROLLBACK, _transcripts(_rollback)),
        ("MATRIX:restart/rollback", "I07 policy write v3", "transcripts", I07, ROLLBACK, _transcripts(_rollback)),
        ("CE21", "I05 gate channel v3", "transcripts", I05, CE21, _transcripts(_intent("Counterexample 21"))),
        ("S8-C2C3", "I05 gate channel v3", "transcripts", I05, C2C3, _transcripts(_c2_c3)),
        ("S8-C2C3", "I07 policy write v3", "transcripts", I07, C2C3, _transcripts(_c2_c3)),
    ],
}


def catalog(group):
    """The selected vectors of each gated case of `group`, by the rules above over the pinned vectors."""
    return [{"case": tag, "contract": contract, "vectorSet": vector_set, "basis": basis, "ids": rule(_models.data(prefix + "vectors.json"))}
            for tag, contract, vector_set, prefix, basis, rule in RULES[group]]


PLAN = "architecture/enforcement-test-plan/traceability.json"
SUBJECTS = {"W04_OFFLINE": "R12's reader, src/harness_conformance/live_proxy_server.py (owner decision Q-T9)",
            "AFTER_W05_RELEASE_SET": "W05's released build, through a wire-level adapter (owner decision Q-T8)",
            "W06_NATIVE_ONLY": "W05's released build on the enrolled AMD64 and ARM64 hosts in W06"}
REASONS = {"AFTER_W05_RELEASE_SET": "AFTER_W05_RELEASE_SET: the subject is W05's released build, which does not exist yet; the "
                                    "catalog fixes the contract vectors and expected results now, and the executable source and "
                                    "the wire-level adapter come with W05's release set (owner decision Q-T8)",
           "W06_NATIVE_ONLY": "W06_NATIVE_ONLY: native evidence on the enrolled hosts in W06; the catalog fixes the contract "
                              "vectors and expected results now (owner decision Q-T8)"}
RULE = ("Each plan case of the group, in plan order. A W04_OFFLINE case lists its properties (the obligation's and acceptance "
        "row's parts) with the tests that show each one in this run. A property that needs an environment this run lacks is "
        "NOT_RUN_ENV_UNAVAILABLE and names the plan's native cases that carry it; it is outside the case's own scope (owner "
        "decision Q-T11), so the case is PASS only when every property within its own scope is PASS. A case that waits for W05's release set "
        "or for W06's native hosts is NOT_RUN_ENV_UNAVAILABLE, never PASS (AGENTS rule 14), and its catalog names the contract "
        "vectors whose own outputs and final snapshots are its expected results.")
PROPERTY_FIELDS = ("property", "source", "result", "reason", "tests", "carriedBy")


def ledger(group, offline):
    """The group's case ledger: the plan's cases with their phase, subject, result, properties, evidence and catalog.

    `offline` maps each W04_OFFLINE case's tag to its property table (fields PROPERTY_FIELDS).
    """
    plan_group = next(row for row in _models.data(PLAN)["testGroups"] if row["id"] == group)
    selections = catalog(group)
    cases = []
    for case in plan_group["cases"]:
        mine = [{key: row[key] for key in ("contract", "vectorSet", "basis", "ids")} for row in selections if row["case"] == case["tag"]]
        properties = [{key: row[key] for key in PROPERTY_FIELDS} for row in offline.get(case["tag"], [])]
        if case["phase"] == "W04_OFFLINE":
            # Owner decision Q-T11 (2026-10-13): a property carried by named native cases of the plan is outside this
            # case's own scope; it stays NOT_RUN here and in the cases that carry it.
            gaps = [row for row in properties if row["result"] != "PASS" and not row["carriedBy"]]
            result = "PASS" if properties and not gaps else "NOT_RUN_ENV_UNAVAILABLE"
            reason = None if result == "PASS" else "partly not run: " + "; ".join(
                "%s (%s; carried by %s)" % (row["property"], row["reason"], ", ".join(row["carriedBy"])) for row in gaps)
        else:
            result = "NOT_RUN_ENV_UNAVAILABLE"
            reason = REASONS[case["phase"]] + "".join("; blocked by " + blocker for blocker in case["blockedBy"])
        evidence = sorted({test for row in properties if row["result"] == "PASS" for test in row["tests"]})
        cases.append({"tag": case["tag"], "phase": case["phase"], "obligations": case["obligations"], "blockedBy": case["blockedBy"],
                      "subject": SUBJECTS[case["phase"]], "result": result, "reason": reason, "properties": properties,
                      "evidence": evidence, "catalog": mine, "vectors": sum(len(row["ids"]) for row in mine)})
    return {"schemaVersion": "r12.enforcement-tg-case-ledger/v1", "packet": "CONF-ENF-003", "testGroup": group,
            "evidenceClass": plan_group["evidenceClass"], "rule": RULE, "cases": cases}
