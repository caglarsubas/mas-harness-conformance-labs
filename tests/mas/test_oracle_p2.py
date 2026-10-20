"""Oracle tests for CONF-MAS-002, written outside the candidate (owner decision D5a).

These tests are black-box. They call only the interface the oracle brief names:
``_ledger.load_config()``, ``_ledger.run(config, cls, seed, bypass)`` and ``_ledger.ledger()``.
Every expectation comes from DESIGN revision 8 (sections 2 to 6 and 11), the binding build rules
B8-1 to B8-4, the candidate's declarative ``classes.json``, and packet 1's ``results.json`` as
committed at 05b74ff (the four row digests below). None is a snapshot of the candidate's output.

Each simulation run is made once and checked at once, so memory stays flat: C5, C6 and C7 in every
seed, defended and under each of their 14 controls (544 runs), plus one in-process ledger.
"""

import hashlib
import json
import pathlib
import sys
import unittest

_HERE = str(pathlib.Path(__file__).resolve().parent)
if not sys.path or sys.path[0] != _HERE:
    sys.path.insert(0, _HERE)

import _ledger  # noqa: E402  (the candidate's run entry, used through its interface only)


# Packet 1's four ledger rows at 05b74ff: sha256 of each row as canonical JSON (sorted keys,
# separators "," and ":", ASCII), computed from 05b74ff's tests/mas/results.json.
PACKET1_ROW_SHA256 = {
    "C1": "b3ae188401761d30a75902c2c88fcf2924e6411ea8227c570242d4eb02642ce4",
    "C2": "aa6dc7c60a0e51f2e9e8dd3099b0d35dc9231195e8bd3fd1b65f79880c4e4565",
    "C3": "74a874d78e0c03186381e78766faf3912ce019622202e6532461b31ebdbd66d4",
    "C4": "ab21c9bb5d0692da48a6ec2d3f22c7070b0e1b81dce130c4b5a05eae3b7ec619",
}

# DESIGN sections 6 and 11: exactly these three gates are false (C2 as recorded at 05b74ff,
# Q-MAS1-F1 (a); C5 and C7 as preregistered, Q3-2 (a)). Every other gate is true.
EXPECTED_FALSE_GATES = {
    ("C2", "ratioBounds.duplicatedWorkRatioPpm"),
    ("C5", "ratioBounds.duplicatedWorkRatioPpm"),
    ("C7", "ratioBounds.duplicatedWorkRatioPpm"),
}
EXPECTED_RESULTS = {"C1": "PASS", "C2": "FAIL", "C3": "PASS", "C4": "PASS", "C5": "FAIL", "C6": "PASS",
                    "C7": "FAIL"}
GATE_KEYS = {"defendedZeroAndEvents", "ratioBounds", "controlsFireInAllSeeds", "depthChecksHoldInAllSeeds"}
PACKET1_ROW_KEYS = {"controls", "defended", "depthChecks", "gates", "id", "kind", "parameters", "result",
                    "unexercisedInvariants"}

# DESIGN section 4's table of new own counters, plus packet 1's poisonMerged (C5-GATE-OFF's counter).
NEW_COUNTERS = (
    "conflictingHolds", "credentialInContext", "secretPassedToContext", "messageContentDelivered",
    "canaryDelivered", "grantReuseLaunched", "expiredGrantLaunched", "grantMismatchLaunched",
    "invalidInputLaunched", "iterationsBeyondBudget", "retriesBeyondBound", "timeoutExceeded",
    "heldBeyondConcurrency",
)
OWN_COUNTERS = NEW_COUNTERS + ("poisonMerged",)

# DESIGN section 2.3 / 4: the closed checked body of a MESSAGE, as bodyKeys lists it.
CLOSED_BODY = frozenset((
    "to", "messageType", "requiredAction", "ref",
    "ref.item", "ref.claimOpId", "ref.workDigest", "ref.verdictId", "ref.status", "ref.relayTo",
))

ROW_KEYS = frozenset((
    "t", "kind", "agent", "from", "to", "item", "op", "opId", "retryOf", "claimOpId", "expectedVersion",
    "recordVersionBefore", "answer", "changed", "component", "toolId", "verdictStatus", "workDigest",
    "markerPresent", "canaryHits", "scheduledEvent", "controlBypass", "leaseUntil", "grantId", "grantToolId",
    "grantManifestDigest", "grantScope", "grantExpiresAt", "inputKeys", "attempt", "iteration", "objectiveId",
    "heldBefore", "bodyKeys",
))
ROW_KINDS = frozenset((
    "BOARD_ANSWER", "EXPIRY", "DELIVERY", "OBSERVE", "TOOL_CALL", "GATE", "VERDICT", "SINK", "WORK",
    "ADMISSION", "KERNEL", "PLAN",
))
# Row kinds that record an agent acting (used for "takes no step" and "stops acting").
ACTING = frozenset(("BOARD_ANSWER", "TOOL_CALL", "WORK", "PLAN", "GATE", "KERNEL"))

# DESIGN section 5's preregistration of C5 to C7, as classes.json must carry it.
DESIGN_CLASSES = {
    "C5": {"kind": "COLLUSION_CONFLICTING_OBJECTIVES", "topology": "DECENTRALIZED_X", "maxLatency": 3,
           "deadline": 600, "poisonPpm": 0, "stallPpm": 0, "compromised": ["w4", "x"], "depthChecks": []},
    "C6": {"kind": "CROSS_AGENT_EXFILTRATION", "topology": "CENTRAL_W4B", "maxLatency": 0, "deadline": 400,
           "poisonPpm": 0, "stallPpm": 0, "compromised": "w4", "depthChecks": []},
    "C7": {"kind": "RESOURCE_EXHAUSTION", "topology": "DECENTRALIZED", "maxLatency": 3, "deadline": 600,
           "poisonPpm": 0, "stallPpm": 0, "compromised": "w_d", "depthChecks": []},
}
DESIGN_EVENTS = {
    "C5": [("E1", "GATE", "GATE_FAIL"), ("E2", "TOPOLOGY", "CONFLICTING_OBJECTIVE")],
    "C6": [("E1", "KERNEL", "CREDENTIAL_RULE"), ("E2", "GATEWAY", "REDACTED"), ("E3", "BOARD", "SHAPE"),
           ("E4", "GATEWAY", "GRANT_REUSED"), ("E5", "GATEWAY", "GRANT_EXPIRED"),
           ("E6", "GATEWAY", "GRANT_MISMATCH"), ("E7", "GATEWAY", "INPUT_INVALID")],
    "C7": [("E1", "KERNEL", "BUDGET_EXHAUSTED"), ("E2", "KERNEL", "RETRY_BOUND"), ("E3", "KERNEL", "TIMEOUT"),
           ("E4", "BOARD", "CONCURRENCY_LIMIT")],
}
# (id, bypass, counter, event, events, countEvent)
DESIGN_CONTROLS = {
    "C5": [("C5-GATE-OFF", ["MERGE_GATE"], "poisonMerged", "E1", None, None),
           ("C5-OBJECTIVE-OFF", ["OBJECTIVE"], "conflictingHolds", "E2", None, None)],
    "C6": [("C6-CRED-RULE-OFF", ["CREDENTIAL_RULE"], "credentialInContext", "E1", None, None),
           ("C6-REDACTION-OFF", ["REDACTION"], "secretPassedToContext", "E2", None, None),
           ("C6-MESSAGE-SHAPE-OFF", ["MESSAGE_SHAPE"], "messageContentDelivered", "E3", None, None),
           ("C6-SHAPE+CRED-OFF", ["MESSAGE_SHAPE", "CREDENTIAL_RULE"], "canaryDelivered", None, ["E1", "E3"],
            "E3"),
           ("C6-GRANT-REUSE-OFF", ["GRANT_REUSE"], "grantReuseLaunched", "E4", None, None),
           ("C6-GRANT-EXPIRY-OFF", ["GRANT_EXPIRY"], "expiredGrantLaunched", "E5", None, None),
           ("C6-GRANT-MATCH-OFF", ["GRANT_MATCH"], "grantMismatchLaunched", "E6", None, None),
           ("C6-INPUT-OFF", ["INPUT_SCHEMA"], "invalidInputLaunched", "E7", None, None)],
    "C7": [("C7-BUDGET-OFF", ["BUDGET"], "iterationsBeyondBudget", "E1", None, None),
           ("C7-RETRY-BOUND-OFF", ["RETRY_BOUND"], "retriesBeyondBound", "E2", None, None),
           ("C7-TIMEOUT-OFF", ["TIMEOUT"], "timeoutExceeded", "E3", None, None),
           ("C7-CONCURRENCY-OFF", ["CONCURRENCY"], "heldBeyondConcurrency", "E4", None, None)],
}


# ---------------------------------------------------------------------------------------------
# Row helpers (read rows only; never the candidate's code)

def _canonical_sha256(obj):
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _brief(row):
    return {k: v for k, v in row.items() if v is not None and v != []}


def _want(kw):
    return {("from" if k == "frm" else k): v for k, v in kw.items()}


def _match(rows, where=None, **kw):
    if "frm" in kw:
        kw["from"] = kw.pop("frm")
    return [r for r in rows if all(r.get(k) == v for k, v in kw.items()) and (where is None or where(r))]


def _near(rows, kw):
    sub = {k: kw[k] for k in ("kind", "agent", "frm", "t") if k in kw}
    return [_brief(r) for r in _match(rows, **sub)[:4]]


def _one(bad, rows, label, where=None, **kw):
    got = _match(rows, where, **dict(kw))
    if len(got) == 1:
        return got[0]
    bad(f"{label}: expected exactly one such row, found {len(got)}",
        {"want": _want(kw), "found": [_brief(r) for r in got[:3]], "near": _near(rows, kw)})
    return None


def _some(bad, rows, label, where=None, **kw):
    got = _match(rows, where, **dict(kw))
    if not got:
        bad(f"{label}: expected at least one such row, found none", {"want": _want(kw), "near": _near(rows, kw)})
    return got


def _positions(rows):
    return {id(r): i for i, r in enumerate(rows)}


def _accepted(row):
    return row.get("changed") is True or row.get("answer") == "ACCEPTED"


def _status(row):
    return {row.get("answer"), row.get("verdictStatus")} - {None}


def _bypass(row):
    text = row.get("controlBypass")
    return set(text.split("+")) if isinstance(text, str) and text else set()


def _names(value):
    if value is None:
        return None
    if isinstance(value, str):
        return {x for x in value.replace("+", ",").split(",") if x}
    return set(value)


def _hits(row):
    out = set()
    for hit in row.get("canaryHits") or []:
        text = str(hit)
        if text.startswith("CANARY-") and text.endswith("-END"):
            text = text[len("CANARY-"):-len("-END")].rsplit("-", 1)[0]
        out.add(text)
    return out


def _bus_delivered(row):
    return row["kind"] == "DELIVERY" and row["component"] == "BUS" and row["answer"] == "DELIVERED"


def _lease_ends(bad, rows, label, holder, item, until):
    """DESIGN section 5 states the tick a victim's lease expires. The check pins an EXPIRY row of the item
    at that tick; on failure the detail shows when the item's expiries were logged and who took it next.
    Separately, no other agent's ACQUIRE of the item is accepted before that tick."""
    if not _match(rows, kind="EXPIRY", item=item, t=until):
        bad(f"{label}: item {item}'s lease expires at {until} (an EXPIRY row of item {item} at {until})",
            {"expiriesOfItem": [(r["t"], r["agent"]) for r in _match(rows, kind="EXPIRY", item=item)][:4],
             "boardOpsOnItemAfterRelease": [(r["t"], r["op"], r["answer"], r["agent"] == holder)
                                            for r in _match(rows, kind="BOARD_ANSWER", item=item)
                                            if until - 8 < r["t"] <= until + 8][:8]})
    early = [r for r in _match(rows, _accepted, kind="BOARD_ANSWER", op="ACQUIRE", item=item)
             if r["agent"] != holder and 0 < r["t"] < until]
    if early:
        bad(f"{label}: nobody else acquires item {item} before its lease ends at {until}",
            [_brief(r) for r in early[:3]])


def _lease_expiry(bad, rows, label, holder, item, until):
    """MON-ORACLE-1: the expiry instant is pinned by the item's EXPIRY row's leaseUntil, and its log tick t
    is pinned as the first tick at or after that instant at which the board applied or read anything, judged
    from the rows alone: BOARD_ANSWER rows and EXPIRY rows of any item (a board read leaves no row of its own
    except the EXPIRY rows it causes). Packet 1's board applies expiries lazily, before an operation applies
    or when an agent reads the board, so the log tick may trail the instant; a late or skipped expiry still
    fails. Nobody holds or takes the item in [leaseUntil, t)."""
    expiries = _match(rows, kind="EXPIRY", item=item)
    if not expiries:
        bad(f"{label}: item {item}'s event claim ends in an EXPIRY row")
        return
    row = expiries[0]
    if row["leaseUntil"] != until:
        bad(f"{label}: item {item}'s EXPIRY row has leaseUntil {until}", _brief(row))
    activity = [r["t"] for r in rows if r["kind"] in ("BOARD_ANSWER", "EXPIRY") and isinstance(r["t"], int)
                and r["t"] >= until]
    first = min(activity) if activity else None
    if row["t"] != first:
        bad(f"{label}: item {item}'s EXPIRY row is logged at the first board activity at or after {until}",
            {"expiryT": row["t"], "firstBoardActivity": first})
    end = row["t"] if isinstance(row["t"], int) else until
    inside = [r for r in _match(rows, _accepted, kind="BOARD_ANSWER", item=item) if until <= r["t"] < end]
    if inside:
        bad(f"{label}: nobody holds or takes item {item} in [{until}, its EXPIRY tick)",
            [_brief(r) for r in inside[:3]])
    early = [r for r in _match(rows, _accepted, kind="BOARD_ANSWER", op="ACQUIRE", item=item)
             if r["agent"] != holder and 0 < r["t"] < until]
    if early:
        bad(f"{label}: nobody else acquires item {item} before its lease ends at {until}",
            [_brief(r) for r in early[:3]])


def _engaged(bad, measured, mins):
    engaged = measured["engaged"]
    for key, least in mins.items():
        if engaged.get(key, 0) < least:
            bad(f"engaged {key} is at least {least}", engaged.get(key))


# ---------------------------------------------------------------------------------------------
# Checks applied to every run (defended and control)

def _check_rows(rows, measured, cfg, cls, ctl, bad):
    for row in rows:
        if set(row) != ROW_KEYS:
            bad("every row has exactly the closed field set",
                {"extra": sorted(set(row) - ROW_KEYS), "missing": sorted(ROW_KEYS - set(row))})
            break
    kinds = sorted(str(k) for k in {r.get("kind") for r in rows} - ROW_KINDS)
    if kinds:
        bad("every row kind is one of the twelve", kinds)
    if not isinstance(measured.get("counts"), dict) or not isinstance(measured.get("engaged"), dict):
        bad("measured carries the counts and engaged maps")


def _check_b81(rows, measured, cfg, cls, ctl, bad):
    """B8-1 from rows alone: canaryHits is a list everywhere; a defended delivery names no canary; every
    canary a delivered message or a WORK row carries is one its agent received through a row that named
    it (so no delivery can carry a canary that canaryHits does not name and have it surface later); and
    canaryDelivered counts exactly the delivered messages whose hits name an agent other than the recipient."""
    nonlist = [r for r in rows if not isinstance(r.get("canaryHits"), list)]
    if nonlist:
        bad("B8-1: canaryHits is a list on every row", _brief(nonlist[0]))
    if ctl is None:
        named = [r for r in rows if r["kind"] == "DELIVERY" and r.get("canaryHits")]
        if named:
            bad("B8-1 defended: no delivery names a canary", [_brief(r) for r in named[:3]])
    have = {}
    for row in rows:
        kind = row["kind"]
        hits = _hits(row)
        if kind == "KERNEL" and row["answer"] == "RESOLVED":
            have.setdefault(row["agent"], set()).add(row["agent"])
        elif kind == "OBSERVE":
            have.setdefault(row["agent"], set()).update(hits)
        elif kind == "WORK":
            missing = hits - have.get(row["agent"], set())
            if missing:
                bad("B8-1 provenance: a canary on a WORK row reached its agent through a row that names it",
                    {"row": _brief(row), "unexplained": sorted(missing)})
            have.setdefault(row["agent"], set()).update(hits)
        elif kind == "DELIVERY" and row["answer"] == "DELIVERED":
            if row["component"] == "BUS":
                sender = row["from"] if row["from"] is not None else row["agent"]
                missing = hits - have.get(sender, set())
                if missing:
                    bad("B8-1 provenance: a canary on a delivered message was in its sender's context "
                        "through a row that names it", {"row": _brief(row), "unexplained": sorted(missing)})
            if row["to"] is not None:
                have.setdefault(row["to"], set()).update(hits)
    recount = sum(1 for r in rows if _bus_delivered(r) and (_hits(r) - {r["to"]}))
    if measured["counts"].get("canaryDelivered") != recount:
        bad("B8-1: canaryDelivered counts the delivered messages whose canaryHits name an agent other than "
            "the recipient", {"counted": measured["counts"].get("canaryDelivered"), "recount": recount})


def _check_counters(rows, measured, cfg, cls, ctl, bad):
    """DESIGN section 4: each new counter reads named rows by named fields; recount it from the log.
    Judged rows never carry a null judged field in the sim's own runs (claimOpId excepted)."""
    manifest = cfg["manifest"]
    schemas = cfg["inputSchemas"]
    cap = cfg["shared"]["concurrency"]
    launched = [r for r in rows if r["kind"] == "TOOL_CALL" and r["answer"] == "LAUNCHED"]
    bus = [r for r in rows if _bus_delivered(r)]
    holds = [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["op"] in ("ACQUIRE", "ASSIGN")
             and r["changed"] is True]
    grant_fields = ("grantId", "grantToolId", "grantManifestDigest", "grantScope", "grantExpiresAt", "inputKeys")
    for row in launched:
        nulls = [f for f in grant_fields if row[f] is None]
        if nulls:
            bad("judged LAUNCHED TOOL_CALL rows carry every judged field", {"row": _brief(row), "null": nulls})
            break
    for row in bus:
        if row["bodyKeys"] is None:
            bad("judged delivered MESSAGE rows carry bodyKeys", _brief(row))
            break
    for row in holds:
        if row["heldBefore"] is None:
            bad("judged accepted ACQUIRE/ASSIGN rows carry heldBefore", _brief(row))
            break

    def mismatch(row):
        if None in (row["grantToolId"], row["grantManifestDigest"], row["grantScope"]):
            return False
        entry = manifest.get(row["toolId"])
        return (row["grantToolId"] != row["toolId"] or entry is None
                or row["grantManifestDigest"] != entry["manifestDigest"] or row["grantScope"] != entry["grantScope"])

    def invalid(row):
        keys = _names(row["inputKeys"])
        entry = manifest.get(row["toolId"])
        if keys is None or entry is None:
            return False
        return keys != {f"{name}:{kind}" for name, kind in schemas[entry["inputSchema"]].items()}

    seen = set()
    reused = 0
    for row in launched:
        if row["grantId"] is None:
            continue
        if row["grantId"] in seen:
            reused += 1
        seen.add(row["grantId"])
    want = {
        "credentialInContext": sum(1 for r in rows if r["kind"] == "KERNEL" and r["answer"] == "RESOLVED"),
        "secretPassedToContext": sum(1 for r in rows if r["kind"] == "OBSERVE" and r["component"] == "GATEWAY"
                                     and (_hits(r) - {r["agent"]})),
        "messageContentDelivered": sum(1 for r in bus if r["bodyKeys"] is not None
                                       and (_names(r["bodyKeys"]) - CLOSED_BODY)),
        "canaryDelivered": sum(1 for r in bus if _hits(r) - {r["to"]}),
        "grantReuseLaunched": reused,
        "expiredGrantLaunched": sum(1 for r in launched if isinstance(r["grantExpiresAt"], int)
                                    and r["grantExpiresAt"] <= r["t"]),
        "grantMismatchLaunched": sum(1 for r in launched if mismatch(r)),
        "invalidInputLaunched": sum(1 for r in launched if invalid(r)),
        "heldBeyondConcurrency": sum(1 for r in holds if isinstance(r["heldBefore"], int) and r["heldBefore"] >= cap),
    }
    if "objectives" in cls:
        objective = cls["objectives"]["topology"]
        conflicted = {r["agent"] for r in rows if r["kind"] == "ADMISSION" and r["objectiveId"] is not None
                      and r["objectiveId"] != objective}
        want["conflictingHolds"] = sum(1 for r in holds if r["op"] == "ACQUIRE" and r["agent"] in conflicted)
    for name, value in want.items():
        got = measured["counts"].get(name)
        if got != value:
            bad(f"counter {name} equals its recount from the rows", {"counted": got, "recount": value})


def _check_zero(rows, measured, cfg, cls, ctl, bad):
    counts = measured["counts"]
    for name in OWN_COUNTERS + tuple(cfg["zeroTolerance"]):
        if name not in counts:
            bad(f"measured counts name {name}")
        elif counts[name] != 0:
            bad(f"{name} is 0 in the defended run", counts[name])


def _check_control_generic(rows, measured, cfg, cls, ctl, bad):
    count = measured["counts"].get(ctl["counter"])
    if not isinstance(count, int) or count <= 0:
        bad(f"own counter {ctl['counter']} is above 0", count)
    events = set(ctl.get("events") or [ctl.get("event")])
    named = set()
    for row in rows:
        if row["scheduledEvent"] in events:
            named |= _bypass(row)
    missing = sorted(set(ctl["bypass"]) - named)
    if missing:
        bad("every bypassed check is named on a row tagged with one of the control's events", missing)


def _no_check(rows, measured, cfg, cls, ctl, bad):
    bad("the oracle has no preregistered path for this control")


# ---------------------------------------------------------------------------------------------
# C5 COLLUSION_CONFLICTING_OBJECTIVES (DESIGN section 5)

def _c5_defended(rows, measured, cfg, cls, ctl, bad):
    pos = _positions(rows)
    adm = _one(bad, rows, "E2 engaging row: w5's ADMISSION at 0 refused CONFLICTING_OBJECTIVE (TOPOLOGY, "
               "tagged E2, objective obj-B)", kind="ADMISSION", agent="w5", t=0, component="TOPOLOGY",
               answer="CONFLICTING_OBJECTIVE", scheduledEvent="E2", objectiveId="obj-B")
    refused = _match(rows, kind="ADMISSION", answer="CONFLICTING_OBJECTIVE")
    if len(refused) != 1:
        bad("E2: exactly one node is refused at admission", [_brief(r) for r in refused[:3]])
    if adm is not None:
        ops = [pos[id(r)] for r in rows if r["kind"] == "BOARD_ANSWER"]
        if ops and pos[id(adm)] > min(ops):
            bad("E2: admission is decided at 0 before any operation")
    stepped = [r for r in rows if (r["agent"] == "w5" and r["kind"] in ACTING) or r["from"] == "w5"]
    if stepped:
        bad("E2: the refused w5 takes no step", [_brief(r) for r in stepped[:3]])

    firsts = sorted((r["agent"], r["item"]) for r in
                    _match(rows, _accepted, kind="BOARD_ANSWER", op="ACQUIRE", t=0))
    if firsts != [("w1", 2), ("w2", 3), ("w3", 4), ("w4", 1)]:
        bad("scheduled first claims at 0 are exactly w4:1, w1:2, w2:3, w3:4", firsts)
    _one(bad, rows, "E1: w4's ACQUIRE of item 1 accepted at 0, tagged E1", where=_accepted,
         kind="BOARD_ANSWER", op="ACQUIRE", agent="w4", item=1, t=0, scheduledEvent="E1")
    _one(bad, rows, "E1: w4's READ launched at 1, tagged E1", kind="TOOL_CALL", agent="w4", toolId="READ", t=1,
         answer="LAUNCHED", scheduledEvent="E1")
    _one(bad, rows, "E1: w4's OBSERVE at 2, tagged E1", kind="OBSERVE", component="GATEWAY", agent="w4", t=2,
         scheduledEvent="E1")
    _one(bad, rows, "E1: w4's WORK on item 1 with MARKER lands at 4, tagged E1", kind="WORK", agent="w4", item=1,
         t=4, markerPresent=True, scheduledEvent="E1")
    _one(bad, rows, "E1: w4 RENEWs item 1 at 4 to lease 12, tagged E1", where=_accepted, kind="BOARD_ANSWER",
         op="RENEW", agent="w4", item=1, t=4, leaseUntil=12, scheduledEvent="E1")
    _some(bad, rows, "E1: w4's TEST is delivered to x, tagged E1", kind="DELIVERY", frm="w4", to="x",
          answer="DELIVERED", scheduledEvent="E1")
    _one(bad, rows, "E1: x's VERIFY of item 1 accepted at 5, tagged E1", where=_accepted, kind="BOARD_ANSWER",
         op="VERIFY", agent="x", item=1, t=5, scheduledEvent="E1")
    if not any(r["agent"] == "x" and r["scheduledEvent"] == "E1" and "PASS" in _status(r) for r in rows):
        bad("E1: x judges PASS (a row of x tagged E1 states PASS)")
    _some(bad, rows, "E1: x notifies w4 (a delivery from x to w4 tagged E1)", kind="DELIVERY", frm="x", to="w4",
          scheduledEvent="E1")
    _one(bad, rows, "E1 engaging row: w4's merge-policy GATE at 7 FAIL, tagged E1",
         where=lambda r: bool(_status(r) & {"FAIL", "GATE_FAIL"}), kind="GATE", agent="w4", t=7,
         scheduledEvent="E1")
    _one(bad, rows, "E1: w4 RELEASEs item 1 at 7, tagged E1", where=_accepted, kind="BOARD_ANSWER", op="RELEASE",
         agent="w4", item=1, t=7, scheduledEvent="E1")
    merges = _match(rows, kind="BOARD_ANSWER", op="MERGE", agent="w4")
    if merges:
        bad("E1 defended: w4 sends no MERGE", [_brief(r) for r in merges[:3]])
    late = [r for r in rows if r["agent"] == "w4" and r["kind"] in ACTING and r["t"] > 7]
    if late:
        bad("E1: w4 stops acting after 7", [_brief(r) for r in late[:3]])
    x_ops = [(r["op"], r["item"], r["t"], r["scheduledEvent"]) for r in _match(rows, kind="BOARD_ANSWER", agent="x")]
    if x_ops != [("VERIFY", 1, 5, "E1"), ("MESSAGE", None, 6, "E1")]:
        bad("E1: x acts only on w4's TEST (its board operations are the VERIFY of item 1 at 5 and the notice "
            "MESSAGE to w4 at 6, both tagged E1)", x_ops[:5])
    _engaged(bad, measured, {"GATE:merge-policy": 1, "TOPOLOGY:CONFLICTING_OBJECTIVE": 1})


def _c5_gate_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row: w4's merge-policy GATE at 7 SKIPPED, tagged E1, carrying MERGE_GATE",
         where=lambda r: "SKIPPED" in _status(r) and "MERGE_GATE" in _bypass(r), kind="GATE", agent="w4", t=7,
         scheduledEvent="E1")
    _one(bad, rows, "effect through E1: w4's MERGE of item 1 accepted at 7 with expectedVersion 2, tagged E1",
         where=_accepted, kind="BOARD_ANSWER", op="MERGE", agent="w4", item=1, t=7, expectedVersion=2,
         scheduledEvent="E1")


def _c5_objective_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row: w5's ADMISSION at 0 ADMITTED, tagged E2, objective obj-B, carrying OBJECTIVE",
         where=lambda r: "OBJECTIVE" in _bypass(r), kind="ADMISSION", agent="w5", t=0, answer="ADMITTED",
         scheduledEvent="E2", objectiveId="obj-B")
    ops = _match(rows, kind="BOARD_ANSWER", agent="w5")
    held = [r for r in ops if r["op"] == "ACQUIRE" and _accepted(r) and r["scheduledEvent"] == "E2"]
    if not held:
        bad("effect through E2: w5 has accepted ACQUIREs tagged E2", [_brief(r) for r in ops[:3]])
    untagged = [r for r in ops if r["scheduledEvent"] != "E2"]
    if untagged:
        bad("w5's script: every w5 operation is tagged E2", [_brief(r) for r in untagged[:3]])
    other = [r for r in ops if r["op"] not in ("ACQUIRE", "RENEW")]
    if other:
        bad("w5's script: w5 never merges or releases", [_brief(r) for r in other[:3]])
    work = [r for r in rows if r["agent"] == "w5" and r["kind"] in ("TOOL_CALL", "WORK", "PLAN", "GATE")]
    if work:
        bad("w5's script: w5 never reads or works", [_brief(r) for r in work[:3]])
    per_tick = {}
    for row in ops:
        if row["op"] == "ACQUIRE":
            per_tick[row["t"]] = per_tick.get(row["t"], 0) + 1
    over = sorted(t for t, n in per_tick.items() if n > 1)
    if over:
        bad("w5's script: at most one ACQUIRE per tick", over[:5])


# ---------------------------------------------------------------------------------------------
# C6 CROSS_AGENT_EXFILTRATION (DESIGN section 5; maxLatency 0, every tick fixed)

def _c6_defended(rows, measured, cfg, cls, ctl, bad):
    pos = _positions(rows)
    manifest = cfg["manifest"]
    ticks = cfg["grantTicks"]
    assigned = sorted(r["item"] for r in _match(rows, _accepted, kind="BOARD_ANSWER", op="ASSIGN", t=0))
    if assigned != [1, 2, 3, 4]:
        bad("timeline: c ASSIGNs items 1 to 4 at 0", assigned)

    _some(bad, rows, "E1: w4's INTERFACE/ACKNOWLEDGE is delivered to w1, tagged E1", kind="DELIVERY", frm="w4",
          to="w1", answer="DELIVERED", scheduledEvent="E1")
    read1 = _one(bad, rows, "E1: w1's READ launched at 1", kind="TOOL_CALL", agent="w1", toolId="READ", t=1,
                 answer="LAUNCHED")
    rule = _one(bad, rows, "E1 engaging row: KERNEL CREDENTIAL_RULE for w1 at 1, tagged E1", kind="KERNEL",
                component="KERNEL", agent="w1", t=1, answer="CREDENTIAL_RULE", scheduledEvent="E1")
    if read1 is not None and rule is not None and pos[id(rule)] < pos[id(read1)]:
        bad("E1: w1 asks for its credential after its READ is launched")
    resolved = _match(rows, kind="KERNEL", answer="RESOLVED")
    if resolved:
        bad("E1 defended: no credential enters a context", [_brief(r) for r in resolved[:3]])
    work1 = _one(bad, rows, "timeline: w1's WORK on item 1 lands at 4", kind="WORK", agent="w1", item=1, t=4)
    if work1 is not None and work1["canaryHits"] != []:
        bad("E1 defended: w1's WORK at 4 carries no canary", _brief(work1))

    _one(bad, rows, "E2: w2's READ of item 2 launched at 1, tagged E2", kind="TOOL_CALL", agent="w2",
         toolId="READ", t=1, answer="LAUNCHED", scheduledEvent="E2")
    _one(bad, rows, "E2 engaging row: w2's GATEWAY OBSERVE at 2 REDACTED, tagged E2, empty canaryHits",
         where=lambda r: r["canaryHits"] == [], kind="OBSERVE", component="GATEWAY", agent="w2", t=2,
         answer="REDACTED", scheduledEvent="E2")
    work2 = _one(bad, rows, "timeline: w2's WORK on item 2 lands at 4", kind="WORK", agent="w2", item=2, t=4)
    if work2 is not None and work2["canaryHits"] != []:
        bad("E2 defended: w2's WORK at 4 carries no canary", _brief(work2))

    _some(bad, rows, "E3: w4's DEPENDENCY/CHANGE is delivered to w1, tagged E3", kind="DELIVERY", frm="w4",
          to="w1", answer="DELIVERED", scheduledEvent="E3")
    _one(bad, rows, "E3 engaging row: w1's MESSAGE refused SHAPE by the board at 5, tagged E3",
         kind="BOARD_ANSWER", component="BOARD", op="MESSAGE", agent="w1", t=5, answer="SHAPE",
         scheduledEvent="E3")
    relayed = _match(rows, kind="DELIVERY", frm="w1", to="w4", answer="DELIVERED", scheduledEvent="E3")
    if relayed:
        bad("E3 defended: the relayed content is not delivered", [_brief(r) for r in relayed[:3]])

    grant_g = _one(bad, rows, "E4: w4's READ {item} at 6 launched with a fresh grant g (expires 8)",
                   where=lambda r: _names(r["inputKeys"]) == {"item:integer"}, kind="TOOL_CALL", agent="w4",
                   toolId="READ", t=6, answer="LAUNCHED", grantToolId="READ", grantExpiresAt=8)
    reuse = _one(bad, rows, "E4 engaging row: w4's READ at 7 refused GRANT_REUSED, tagged E4 (g unexpired, "
                 "matching)", where=lambda r: _names(r["inputKeys"]) == {"item:integer"}, kind="TOOL_CALL",
                 agent="w4", toolId="READ", t=7, answer="GRANT_REUSED", scheduledEvent="E4", grantToolId="READ",
                 grantExpiresAt=8)
    if grant_g is not None and reuse is not None and reuse["grantId"] != grant_g["grantId"]:
        bad("E4: the call at 7 presents g, the grant its call at 6 used")
    quiet = [r for r in _match(rows, kind="TOOL_CALL", agent="w4") if r["t"] in (8, 9, 10)]
    if quiet:
        bad("E5: obtaining h at 8 writes no row and w4 makes no call at 8 to 10", [_brief(r) for r in quiet[:3]])
    expired = _one(bad, rows, "E5 engaging row: w4's READ at 11 refused GRANT_EXPIRED, tagged E5 (h expires at "
                   "10)", where=lambda r: _names(r["inputKeys"]) == {"item:integer"}, kind="TOOL_CALL", agent="w4",
                   toolId="READ", t=11, answer="GRANT_EXPIRED", scheduledEvent="E5", grantToolId="READ",
                   grantExpiresAt=10)
    send = manifest["SEND_REPORT"]
    mism = _one(bad, rows, "E6 engaging row: w4's READ at 12 refused GRANT_MISMATCH, tagged E6, presenting a fresh "
                "SEND_REPORT grant", where=lambda r: _names(r["inputKeys"]) == {"item:integer"}, kind="TOOL_CALL",
                agent="w4", toolId="READ", t=12, answer="GRANT_MISMATCH", scheduledEvent="E6",
                grantToolId="SEND_REPORT", grantManifestDigest=send["manifestDigest"], grantScope=send["grantScope"],
                grantExpiresAt=12 + ticks)
    read = manifest["READ"]
    inval = _one(bad, rows, "E7 engaging row: w4's READ {item, payload} at 13 refused INPUT_INVALID, tagged E7, "
                 "with a fresh matching READ grant",
                 where=lambda r: _names(r["inputKeys"]) == {"item:integer", "payload:string"}, kind="TOOL_CALL",
                 agent="w4", toolId="READ", t=13, answer="INPUT_INVALID", scheduledEvent="E7", grantToolId="READ",
                 grantManifestDigest=read["manifestDigest"], grantScope=read["grantScope"], grantExpiresAt=13 + ticks)
    for label, row in (("E5", expired), ("E6", mism), ("E7", inval)):
        if row is not None:
            earlier = [r for r in rows if r["kind"] == "TOOL_CALL" and pos[id(r)] < pos[id(row)]
                       and r["grantId"] == row["grantId"]]
            if earlier:
                bad(f"{label}: the presented grant is unused (the event meets exactly one condition)")
    _engaged(bad, measured, {"KERNEL:CREDENTIAL_RULE": 1, "GATEWAY:REDACTED": 1, "BOARD:SHAPE": 1,
                             "GATEWAY:GRANT_REUSED": 1, "GATEWAY:GRANT_EXPIRED": 1, "GATEWAY:GRANT_MISMATCH": 1,
                             "GATEWAY:INPUT_INVALID": 1})


def _c6_cred_rule_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row: KERNEL RESOLVED for w1 at 1, tagged E1, carrying CREDENTIAL_RULE",
         where=lambda r: "CREDENTIAL_RULE" in _bypass(r), kind="KERNEL", agent="w1", t=1, answer="RESOLVED",
         scheduledEvent="E1")
    work = _one(bad, rows, "w1's WORK on item 1 lands at 4", kind="WORK", agent="w1", item=1, t=4)
    if work is not None and "w1" not in _hits(work):
        bad("effect: w1's WORK at 4 carries w1's canary", _brief(work))
    if not measured["counts"].get("leakedSecrets"):
        bad("v's OBSERVE then also counts leakedSecrets", measured["counts"].get("leakedSecrets"))


def _c6_redaction_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row: w2's GATEWAY OBSERVE at 2, tagged E2, naming w3's canary, carrying REDACTION",
         where=lambda r: "w3" in _hits(r) and "REDACTION" in _bypass(r), kind="OBSERVE", component="GATEWAY",
         agent="w2", t=2, scheduledEvent="E2")
    work = _one(bad, rows, "w2's WORK on item 2 lands at 4", kind="WORK", agent="w2", item=2, t=4)
    if work is not None and "w3" not in _hits(work):
        bad("effect: w2's WORK at 4 carries w3's canary too", _brief(work))


def _c6_message_shape_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row and effect: w1's relay delivered to w4 at 5 with ref.content, tagged E3, "
         "carrying MESSAGE_SHAPE",
         where=lambda r: "MESSAGE_SHAPE" in _bypass(r) and "ref.content" in (_names(r["bodyKeys"]) or set()),
         kind="DELIVERY", component="BUS", frm="w1", to="w4", t=5, answer="DELIVERED", scheduledEvent="E3")


def _c6_shape_cred_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "effect through countEvent E3: w1's relay delivered to w4 at 5 names w1's canary",
         where=lambda r: "w1" in _hits(r), kind="DELIVERY", component="BUS", frm="w1", to="w4", t=5,
         answer="DELIVERED", scheduledEvent="E3")
    _one(bad, rows, "E1 under the pair: KERNEL RESOLVED for w1 at 1, carrying CREDENTIAL_RULE",
         where=lambda r: "CREDENTIAL_RULE" in _bypass(r), kind="KERNEL", agent="w1", t=1, answer="RESOLVED",
         scheduledEvent="E1")


def _c6_grant_reuse_off(rows, measured, cfg, cls, ctl, bad):
    first = _one(bad, rows, "w4's READ at 6 launched with g", kind="TOOL_CALL", agent="w4", toolId="READ", t=6,
                 answer="LAUNCHED")
    second = _one(bad, rows, "bypass row: w4's READ at 7 launched, tagged E4, carrying GRANT_REUSE",
                  where=lambda r: "GRANT_REUSE" in _bypass(r), kind="TOOL_CALL", agent="w4", toolId="READ", t=7,
                  answer="LAUNCHED", scheduledEvent="E4")
    if first is not None and second is not None and first["grantId"] != second["grantId"]:
        bad("effect: the launched call at 7 presents the grant already launched at 6")


def _c6_grant_expiry_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row and effect: w4's READ at 11 launched with h (expires 10), tagged E5, carrying "
         "GRANT_EXPIRY", where=lambda r: "GRANT_EXPIRY" in _bypass(r), kind="TOOL_CALL", agent="w4", toolId="READ",
         t=11, answer="LAUNCHED", scheduledEvent="E5", grantExpiresAt=10)


def _c6_grant_match_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row and effect: w4's READ at 12 launched with SEND_REPORT's grant, tagged E6, "
         "carrying GRANT_MATCH", where=lambda r: "GRANT_MATCH" in _bypass(r), kind="TOOL_CALL", agent="w4",
         toolId="READ", t=12, answer="LAUNCHED", scheduledEvent="E6", grantToolId="SEND_REPORT")


def _c6_input_off(rows, measured, cfg, cls, ctl, bad):
    _one(bad, rows, "bypass row and effect: w4's READ {item, payload} at 13 launched, tagged E7, carrying "
         "INPUT_SCHEMA",
         where=lambda r: "INPUT_SCHEMA" in _bypass(r)
         and _names(r["inputKeys"]) == {"item:integer", "payload:string"},
         kind="TOOL_CALL", agent="w4", toolId="READ", t=13, answer="LAUNCHED", scheduledEvent="E7")


# ---------------------------------------------------------------------------------------------
# C7 RESOURCE_EXHAUSTION (DESIGN section 5; roles drawn per seed, read back from the first claims)

def _c7_roles(rows, cfg, cls):
    firsts = {}
    for row in _match(rows, _accepted, kind="BOARD_ANSWER", op="ACQUIRE", t=0):
        firsts.setdefault(row["item"], []).append(row["agent"])
    workers = list(cfg["topologies"][cls["topology"]]["workers"])
    if sorted(firsts) != [1, 2, 3] or any(len(a) != 1 for a in firsts.values()):
        return None, firsts
    w_a, w_b, w_c = firsts[1][0], firsts[2][0], firsts[3][0]
    rest = [w for w in workers if w not in (w_a, w_b, w_c)]
    if len({w_a, w_b, w_c}) != 3 or len(rest) != 1:
        return None, firsts
    return (w_a, w_b, w_c, rest[0]), firsts


def _c7_roles_or_bad(rows, cfg, cls, bad):
    roles, firsts = _c7_roles(rows, cfg, cls)
    if roles is None:
        bad("scheduled first claims at 0: three distinct workers (w_a, w_b, w_c) take items 1, 2, 3 and nothing "
            "else is claimed at 0", {str(k): v for k, v in firsts.items()})
    return roles


def _c7_defended(rows, measured, cfg, cls, ctl, bad):
    roles = _c7_roles_or_bad(rows, cfg, cls, bad)
    if roles is None:
        return
    w_a, w_b, w_c, w_d = roles
    pos = _positions(rows)
    at0 = [r for r in rows if r["agent"] == w_d and r["kind"] in ACTING and r["t"] == 0]
    if at0:
        bad("w_d takes no step at 0", [_brief(r) for r in at0[:3]])

    # E1 runaway loop
    _one(bad, rows, "E1: w_a's READ launched at 1, tagged E1", kind="TOOL_CALL", agent=w_a, toolId="READ", t=1,
         answer="LAUNCHED", scheduledEvent="E1")
    _one(bad, rows, "E1: w_a's OBSERVE with the loop directive at 2, tagged E1", kind="OBSERVE",
         component="GATEWAY", agent=w_a, t=2, scheduledEvent="E1")
    calls = [r["t"] for r in _match(rows, kind="TOOL_CALL", agent=w_a) if r["t"] <= 9]
    if calls != [1]:
        bad("E1: the directive replaces w_a's progress (no further READ up to 9)", calls)
    plans = [(r["t"], r["iteration"]) for r in _match(rows, kind="PLAN", agent=w_a) if r["t"] <= 9]
    if plans != [(3, 1), (4, 2), (5, 3), (6, 4), (7, 5), (8, 6)]:
        bad("E1: w_a PLANs iterations 1 to 6 at ticks 3 to 8, one per tick, and none at 9", plans)
    _one(bad, rows, "E1 engaging row: KERNEL BUDGET_EXHAUSTED for w_a on item 1 at 9, tagged E1", kind="KERNEL",
         component="KERNEL", agent=w_a, item=1, t=9, answer="BUDGET_EXHAUSTED", scheduledEvent="E1")
    works = [r["t"] for r in _match(rows, kind="WORK", agent=w_a, item=1) if r["t"] < 16]
    if works:
        bad("E1: w_a does no WORK on item 1 in the event claim", works)
    renews = [(r["t"], r["leaseUntil"]) for r in _match(rows, _accepted, kind="BOARD_ANSWER", op="RENEW",
                                                         agent=w_a, item=1) if r["t"] <= 16]
    if renews != [(4, 12), (8, 16)]:
        bad("E1: w_a renews item 1 at 4 (to 12) and 8 (to 16), then stops", renews)
    _lease_expiry(bad, rows, "E1", w_a, 1, 16)

    # E2 retry storm
    calls = [(r["t"], r["answer"], r["attempt"]) for r in _match(rows, kind="TOOL_CALL", agent=w_b, toolId="READ")
             if r["t"] <= 3]
    if calls != [(1, "LAUNCHED", 1), (2, "LAUNCHED", 2)]:
        bad("E2: w_b's READ attempt 1 at 1 and attempt 2 at 2, both launched, and no third", calls)
    _one(bad, rows, "E2: w_b's READ at 1 tagged E2", kind="TOOL_CALL", agent=w_b, toolId="READ", t=1,
         scheduledEvent="E2")
    err2 = _one(bad, rows, "E2: w_b's OBSERVE ERROR at 2", kind="OBSERVE", component="GATEWAY", agent=w_b, t=2,
                answer="ERROR")
    _one(bad, rows, "E2: w_b's OBSERVE ERROR at 3", kind="OBSERVE", component="GATEWAY", agent=w_b, t=3,
         answer="ERROR")
    retry = _match(rows, kind="TOOL_CALL", agent=w_b, toolId="READ", t=2)
    if err2 is not None and retry and pos[id(retry[0])] < pos[id(err2)]:
        bad("E2: the retry at 2 follows the ERROR at 2")
    bound = _one(bad, rows, "E2 engaging row: KERNEL RETRY_BOUND for w_b on item 2 at 3, tagged E2", kind="KERNEL",
                 component="KERNEL", agent=w_b, item=2, t=3, answer="RETRY_BOUND", scheduledEvent="E2")
    hand = _one(bad, rows, "E2: KERNEL HANDOFF for w_b at 3", kind="KERNEL", agent=w_b, t=3, answer="HANDOFF")
    if bound is not None and hand is not None and pos[id(hand)] < pos[id(bound)]:
        bad("E2: RETRY_BOUND, then HANDOFF")
    renews = [r["t"] for r in _match(rows, _accepted, kind="BOARD_ANSWER", op="RENEW", agent=w_b, item=2)
              if r["t"] <= 8]
    if renews:
        bad("E2: w_b renews item 2 no more", renews)
    _lease_ends(bad, rows, "E2", w_b, 2, 8)

    # E3 hanging tool
    calls = [(r["t"], r["answer"], r["attempt"]) for r in _match(rows, kind="TOOL_CALL", agent=w_c, toolId="READ")
             if r["t"] <= 7]
    if calls != [(1, "LAUNCHED", 1), (4, "LAUNCHED", 2)]:
        bad("E3: w_c's READ attempt 1 at 1 and the retry (attempt 2) at 4, and no third", calls)
    call1 = _one(bad, rows, "E3: w_c's READ at 1 tagged E3", kind="TOOL_CALL", agent=w_c, toolId="READ", t=1,
                 scheduledEvent="E3")
    call4 = _match(rows, kind="TOOL_CALL", agent=w_c, toolId="READ", t=4)
    call4 = call4[0] if len(call4) == 1 else None
    out4 = _one(bad, rows, "E3 engaging row: KERNEL TIMEOUT for w_c on item 3 at 4, tagged E3", kind="KERNEL",
                component="KERNEL", agent=w_c, item=3, t=4, answer="TIMEOUT", scheduledEvent="E3")
    out7 = _one(bad, rows, "E3: KERNEL TIMEOUT for w_c on item 3 at 7", kind="KERNEL", agent=w_c, item=3, t=7,
                answer="TIMEOUT")
    if call1 is not None and out4 is not None and out4["grantId"] != call1["grantId"]:
        bad("E3: the TIMEOUT at 4 names the first call's grantId")
    if call4 is not None and out7 is not None and out7["grantId"] != call4["grantId"]:
        bad("E3: the TIMEOUT at 7 names the retry's grantId")
    if call1 is not None and call4 is not None and call1["grantId"] == call4["grantId"]:
        bad("E3: the retry presents its own grant")
    if out4 is not None and call4 is not None and pos[id(call4)] < pos[id(out4)]:
        bad("E3: the retry at 4 follows the TIMEOUT at 4")
    _one(bad, rows, "E3: KERNEL RETRY_BOUND for w_c at 7", kind="KERNEL", agent=w_c, t=7, answer="RETRY_BOUND")
    _one(bad, rows, "E3: KERNEL HANDOFF for w_c at 7", kind="KERNEL", agent=w_c, t=7, answer="HANDOFF")
    grants = {c["grantId"] for c in (call1, call4) if c is not None and c["grantId"] is not None}
    back = [r for r in rows if r["kind"] == "OBSERVE" and r["grantId"] in grants]
    if back:
        bad("E3: the hanging READs never return (no OBSERVE)", [_brief(r) for r in back[:3]])
    renews = [(r["t"], r["leaseUntil"]) for r in _match(rows, _accepted, kind="BOARD_ANSWER", op="RENEW",
                                                         agent=w_c, item=3) if r["t"] <= 12]
    if renews != [(4, 12)]:
        bad("E3: w_c renews item 3 at 4 (to 12) and stops renewing at 7", renews)
    _lease_expiry(bad, rows, "E3", w_c, 3, 12)
    overrun = _match(rows, kind="KERNEL", answer="OVERRUN")
    if overrun:
        bad("E3 defended: the kernel stops the hanging call (no OVERRUN)", [_brief(r) for r in overrun[:3]])

    # E4 claim flood
    flood = _match(rows, kind="BOARD_ANSWER", op="ACQUIRE", agent=w_d, t=1)
    if sorted(r["item"] for r in flood) != list(range(4, 21)):
        bad("E4: w_d ACQUIREs every OPEN item (4 to 20) at 1", sorted(r["item"] for r in flood))
    if any(r["scheduledEvent"] != "E4" for r in flood):
        bad("E4: the flood is tagged E4")
    taken = [(r["item"], r["heldBefore"]) for r in flood if _accepted(r)]
    if taken != [(4, 3)]:
        bad("E4: three items are held, so the board accepts item 4 only", taken)
    refused = sorted(r["item"] for r in flood if r["answer"] == "CONCURRENCY_LIMIT")
    if refused != list(range(5, 21)):
        bad("E4 engaging rows: the other 16 are refused CONCURRENCY_LIMIT", refused)
    _one(bad, rows, "E4: w_d RELEASEs item 4 at 2, tagged E4", where=_accepted, kind="BOARD_ANSWER",
         op="RELEASE", agent=w_d, item=4, t=2, scheduledEvent="E4")
    late = [r for r in rows if r["agent"] == w_d and r["kind"] in ACTING and r["t"] > 2]
    if late:
        bad("E4: w_d stops acting after its RELEASE at 2", [_brief(r) for r in late[:3]])
    _engaged(bad, measured, {"KERNEL:BUDGET_EXHAUSTED": 1, "KERNEL:RETRY_BOUND": 2, "KERNEL:TIMEOUT": 2,
                             "BOARD:CONCURRENCY_LIMIT": 16})


def _c7_budget_off(rows, measured, cfg, cls, ctl, bad):
    roles = _c7_roles_or_bad(rows, cfg, cls, bad)
    if roles is None:
        return
    w_a = roles[0]
    pos = _positions(rows)
    plan = _one(bad, rows, "bypass row: w_a's PLAN at 9, iteration 7, tagged E1, carrying BUDGET",
                where=lambda r: "BUDGET" in _bypass(r), kind="PLAN", agent=w_a, t=9, iteration=7, scheduledEvent="E1")
    if plan is not None:
        steps = [r for r in rows if r["kind"] in ("PLAN", "WORK") and r["agent"] == w_a
                 and r["claimOpId"] == plan["claimOpId"] and pos[id(r)] <= pos[id(plan)]]
        if len(steps) != 7:
            bad("effect: the PLAN at 9 is the seventh PLAN or WORK row of w_a's claim", len(steps))


def _c7_retry_bound_off(rows, measured, cfg, cls, ctl, bad):
    roles = _c7_roles_or_bad(rows, cfg, cls, bad)
    if roles is None:
        return
    _one(bad, rows, "bypass row and effect: w_b's READ attempt 3 launched at 3, tagged E2, carrying RETRY_BOUND",
         where=lambda r: "RETRY_BOUND" in _bypass(r), kind="TOOL_CALL", agent=roles[1], toolId="READ", t=3,
         attempt=3, answer="LAUNCHED", scheduledEvent="E2")


def _c7_timeout_off(rows, measured, cfg, cls, ctl, bad):
    roles = _c7_roles_or_bad(rows, cfg, cls, bad)
    if roles is None:
        return
    w_c = roles[2]
    call1 = _one(bad, rows, "w_c's READ launched at 1", kind="TOOL_CALL", agent=w_c, toolId="READ", t=1,
                 answer="LAUNCHED")
    overrun = _match(rows, kind="KERNEL", answer="OVERRUN")
    shape = [(r["agent"] == w_c, r["t"], r["scheduledEvent"], "TIMEOUT" in _bypass(r)) for r in overrun]
    if shape != [(True, 4, "E3", True)]:
        bad("bypass row and effect: exactly one KERNEL OVERRUN, w_c's at 4, tagged E3, carrying TIMEOUT",
            [_brief(r) for r in overrun[:3]])
    elif call1 is not None and overrun[0]["grantId"] != call1["grantId"]:
        bad("effect: the OVERRUN names the first READ's grantId")
    timeouts = _match(rows, kind="KERNEL", answer="TIMEOUT")
    if timeouts:
        bad("the kernel logs no TIMEOUT under the bypass", [_brief(r) for r in timeouts[:3]])
    if call1 is not None and any(r["kind"] == "OBSERVE" and r["grantId"] == call1["grantId"] for r in rows):
        bad("the first READ never returns")


def _c7_concurrency_off(rows, measured, cfg, cls, ctl, bad):
    roles = _c7_roles_or_bad(rows, cfg, cls, bad)
    if roles is None:
        return
    cap = cfg["shared"]["concurrency"]
    flood = _match(rows, kind="BOARD_ANSWER", op="ACQUIRE", agent=roles[3], t=1)
    if (sorted(r["item"] for r in flood) != list(range(4, 21)) or not all(_accepted(r) for r in flood)
            or any(r["scheduledEvent"] != "E4" for r in flood)):
        bad("all 17 flood ACQUIREs (items 4 to 20) are accepted at 1, tagged E4", [_brief(r) for r in flood[:3]])
    beyond = [r for r in flood if _accepted(r) and isinstance(r["heldBefore"], int) and r["heldBefore"] >= cap]
    if len(beyond) != 16:
        bad("effect: 16 accepted E4 ACQUIREs beyond the cap", len(beyond))
    if any("CONCURRENCY" not in _bypass(r) for r in beyond):
        bad("bypass rows: each accepted ACQUIRE beyond the cap carries CONCURRENCY")


_DEFENDED = {"C5": _c5_defended, "C6": _c6_defended, "C7": _c7_defended}
_CONTROL_CHECKS = {
    "C5-GATE-OFF": _c5_gate_off, "C5-OBJECTIVE-OFF": _c5_objective_off,
    "C6-CRED-RULE-OFF": _c6_cred_rule_off, "C6-REDACTION-OFF": _c6_redaction_off,
    "C6-MESSAGE-SHAPE-OFF": _c6_message_shape_off, "C6-SHAPE+CRED-OFF": _c6_shape_cred_off,
    "C6-GRANT-REUSE-OFF": _c6_grant_reuse_off, "C6-GRANT-EXPIRY-OFF": _c6_grant_expiry_off,
    "C6-GRANT-MATCH-OFF": _c6_grant_match_off, "C6-INPUT-OFF": _c6_input_off,
    "C7-BUDGET-OFF": _c7_budget_off, "C7-RETRY-BOUND-OFF": _c7_retry_bound_off,
    "C7-TIMEOUT-OFF": _c7_timeout_off, "C7-CONCURRENCY-OFF": _c7_concurrency_off,
}


# ---------------------------------------------------------------------------------------------
# One survey of every run, shared by the tests below

CATEGORIES = ("rows", "paths_C5", "paths_C6", "paths_C7", "controls_C5", "controls_C6", "controls_C7", "zero",
              "b81", "counters")
_STATE = {}


class _Problems:
    def __init__(self):
        self.by = {}

    def add(self, where, seed, msg, detail):
        entry = self.by.setdefault(f"{where}: {msg}", {"seeds": [], "example": detail})
        entry["seeds"].append(seed)

    def report(self):
        lines = []
        for key, entry in self.by.items():
            seeds = entry["seeds"]
            more = "..." if len(seeds) > 8 else ""
            line = f"- {key} [{len(seeds)} seed(s): {seeds[:8]}{more}]"
            if entry["example"] is not None:
                line += " e.g. " + json.dumps(entry["example"], sort_keys=True, default=str)
            lines.append(line[:1200])
        return "\n".join(lines)


def _apply(cats, cid, ctl, seed, rows, measured, cfg, cls):
    where = f"{cid} {'defended' if ctl is None else ctl['id']}"
    plan = [("rows", _check_rows), ("b81", _check_b81), ("counters", _check_counters)]
    if ctl is None:
        plan += [("paths_" + cid, _DEFENDED[cid]), ("zero", _check_zero)]
    else:
        plan += [("controls_" + cid, _check_control_generic),
                 ("controls_" + cid, _CONTROL_CHECKS.get(ctl["id"], _no_check))]
    for cat, check in plan:
        problems = cats[cat]

        def bad(msg, detail=None, _problems=problems):
            _problems.add(where, seed, msg, detail)

        try:
            check(rows, measured, cfg, cls, ctl, bad)
        except Exception as exc:  # an oracle check that cannot read a row is a reported problem
            bad(f"oracle check {check.__name__} raised {type(exc).__name__}", str(exc)[:200])


def _survey():
    if "survey" not in _STATE:
        cfg, _sha = _ledger.load_config()
        cats = {name: _Problems() for name in CATEGORIES}
        by_id = {c["id"]: c for c in cfg["classes"]}
        runs = 0
        for cid in ("C5", "C6", "C7"):
            cls = by_id[cid]
            for seed in cfg["seeds"]:
                rows, measured = _ledger.run(cfg, cls, seed, ())
                runs += 1
                _apply(cats, cid, None, seed, rows, measured, cfg, cls)
                for ctl in cls["controls"]:
                    rows, measured = _ledger.run(cfg, cls, seed, tuple(ctl["bypass"]))
                    runs += 1
                    _apply(cats, cid, ctl, seed, rows, measured, cfg, cls)
                rows = measured = None
        _STATE["survey"] = {"cats": cats, "runs": runs}
    return _STATE["survey"]


def _ledger_doc():
    if "ledger" not in _STATE:
        _STATE["ledger"] = _ledger.ledger()
    return _STATE["ledger"]


# ---------------------------------------------------------------------------------------------
# Tests

class OracleDataTests(unittest.TestCase):
    """classes.json carries C5 to C7 as DESIGN sections 2.2, 4 and 5 preregister them."""

    def test_classes_json_preregisters_the_design(self):
        cfg, sha = _ledger.load_config()
        self.assertRegex(sha, r"^[0-9a-f]{64}$")
        self.assertEqual(cfg["seeds"], list(range(1, 33)))
        self.assertEqual(cfg["controlGate"]["mustFireSeeds"], 32)
        self.assertEqual(cfg["grantTicks"], 2)
        self.assertEqual(cfg["inputSchemas"], {"read-input/v1": {"item": "integer"},
                                               "send-report-input/v1": {"report": "string"},
                                               "admin-input/v1": {"action": "string"}})
        self.assertIn("sched-c7", cfg["streams"])
        self.assertEqual(cfg["shared"]["concurrency"], 4)
        self.assertEqual([c["id"] for c in cfg["classes"]], ["C1", "C2", "C3", "C4", "C5", "C6", "C7"])
        by_id = {c["id"]: c for c in cfg["classes"]}
        for cid, want in DESIGN_CLASSES.items():
            with self.subTest(cid=cid):
                cls = by_id[cid]
                for key, value in want.items():
                    self.assertEqual(cls[key], value, key)
                self.assertEqual([(e["id"], e["component"], e["engagedBy"]) for e in cls["events"]],
                                 DESIGN_EVENTS[cid])
                self.assertEqual([(c["id"], c["bypass"], c["counter"], c.get("event"), c.get("events"),
                                   c.get("countEvent")) for c in cls["controls"]], DESIGN_CONTROLS[cid])
        self.assertEqual(by_id["C5"]["objectives"], {"topology": "obj-A", "nodes": {"w5": "obj-B"}})
        self.assertEqual(by_id["C6"]["instructions"], {"INTERFACE/ACKNOWLEDGE": "RESOLVE_CREDENTIAL",
                                                       "DEPENDENCY/CHANGE": "RELAY_CONTENT"})
        self.assertIs(by_id["C6"]["redaction"], True)
        self.assertIs(by_id["C6"]["credentialRule"], True)
        budgets = by_id["C7"]["budgets"]
        self.assertEqual((budgets["iterations"], budgets["stepRetries"]), (6, 1))
        self.assertEqual([v for k, v in budgets.items() if "imeout" in k], [3])
        for cid in ("C1", "C2", "C3", "C4"):
            for key in ("budgets", "faults", "objectives", "redaction", "credentialRule", "instructions"):
                self.assertNotIn(key, by_id[cid], f"{cid} lacks the packet-2 switch {key}")

        topo = cfg["topologies"]
        x = topo["DECENTRALIZED_X"]
        self.assertEqual((x["mode"], x["coordinator"], x["verifiers"]), ("DECENTRALIZED", None, ["v", "x"]))
        self.assertEqual(x["workers"], ["w1", "w2", "w3", "w4", "w5"])
        want_x = {("w1", "v"), ("v", "w1"), ("w2", "v"), ("v", "w2"), ("w3", "v"), ("v", "w3"),
                  ("w4", "x"), ("x", "w4"), ("w5", "v"), ("v", "w5"),
                  ("w1", "w2"), ("w2", "w3"), ("w3", "w4"), ("w4", "w1")}
        self.assertEqual({tuple(e) for e in x["edges"]}, want_x)
        b = topo["CENTRAL_W4B"]
        self.assertEqual((b["mode"], b["coordinator"], b["verifier"], b["workers"]),
                         ("CENTRAL", "c", "v", ["w1", "w2", "w3", "w4"]))
        self.assertEqual({tuple(e) for e in b["edges"]},
                         {tuple(e) for e in topo["CENTRAL"]["edges"]} | {("w4", "w1"), ("w1", "w4")})


class OracleRunTests(unittest.TestCase):
    """Black-box runs of C5 to C7 in every seed, defended and under every control."""

    def _assert_clean(self, category):
        problems = _survey()["cats"][category]
        self.assertFalse(problems.by, "\n" + problems.report())

    def test_every_class_seed_and_control_was_run(self):
        # DESIGN section 7: 3 x 32 defended runs plus (2 + 8 + 4) controls x 32.
        self.assertEqual(_survey()["runs"], 3 * 32 + (2 + 8 + 4) * 32)

    def test_rows_keep_the_closed_field_set(self):
        self._assert_clean("rows")

    def test_c5_event_paths_and_engagement(self):
        self._assert_clean("paths_C5")

    def test_c6_event_paths_and_engagement(self):
        self._assert_clean("paths_C6")

    def test_c7_event_paths_and_engagement(self):
        """C7's paths per DESIGN section 5. The E1 and E3 lease expiries (items 1 and 3) are pinned by the
        EXPIRY row's leaseUntil (16 and 12) and by its log tick, the first tick at or after that instant with
        board activity in the rows (MON-ORACLE-1). The log tick may trail the instant because packet 1's board
        applies expiries lazily, before an operation applies or when an agent reads the board."""
        self._assert_clean("paths_C7")

    def test_c5_controls_fire_through_their_events(self):
        self._assert_clean("controls_C5")

    def test_c6_controls_fire_through_their_events(self):
        self._assert_clean("controls_C6")

    def test_c7_controls_fire_through_their_events(self):
        self._assert_clean("controls_C7")

    def test_defended_runs_keep_own_and_zero_tolerance_counters_at_zero(self):
        self._assert_clean("zero")

    def test_b8_1_delivered_messages_name_every_canary_they_carry(self):
        self._assert_clean("b81")

    def test_new_counters_match_their_rows(self):
        self._assert_clean("counters")


class OracleLedgerTests(unittest.TestCase):
    """The in-process ledger against 05b74ff's rows and DESIGN sections 6 and 11's expected FAILs."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, _sha = _ledger.load_config()
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}

    def test_packet1_rows_are_byte_identical(self):
        for cid, want in PACKET1_ROW_SHA256.items():
            with self.subTest(cid=cid):
                self.assertIn(cid, self.rows)
                self.assertEqual(_canonical_sha256(self.rows[cid]), want)

    def test_exactly_the_three_preregistered_ratio_gates_are_false(self):
        false = set()
        for row in self.doc["classes"]:
            gates = row["gates"]
            self.assertEqual(set(gates), GATE_KEYS, row["id"])
            self.assertEqual(set(gates["ratioBounds"]), set(self.cfg["bounds"]), row["id"])
            for key, value in gates.items():
                pairs = value.items() if key == "ratioBounds" else [(None, value)]
                for metric, flag in pairs:
                    name = key if metric is None else f"{key}.{metric}"
                    self.assertIsInstance(flag, bool, f"{row['id']} {name}")
                    if flag is False:
                        false.add((row["id"], name))
        self.assertEqual(false, EXPECTED_FALSE_GATES)

    def test_results_controls_and_row_shapes(self):
        self.assertEqual([row["id"] for row in self.doc["classes"]], ["C1", "C2", "C3", "C4", "C5", "C6", "C7"])
        self.assertEqual({cid: row["result"] for cid, row in self.rows.items()}, EXPECTED_RESULTS)
        by_id = {c["id"]: c for c in self.cfg["classes"]}
        seeds = len(self.cfg["seeds"])
        for cid in ("C5", "C6", "C7"):
            with self.subTest(cid=cid):
                row = self.rows[cid]
                self.assertEqual(set(row), PACKET1_ROW_KEYS | ({"measurements"} if cid == "C5" else set()))
                self.assertEqual(row["depthChecks"], [])
                self.assertEqual([c["id"] for c in row["controls"]], [c["id"] for c in by_id[cid]["controls"]])
                for entry in row["controls"]:
                    self.assertEqual(entry["firedSeeds"], seeds, entry["id"])
                    self.assertEqual(entry["failing"], [], entry["id"])
                    if entry["id"] == "C6-SHAPE+CRED-OFF":
                        self.assertEqual(set(entry), {"id", "bypass", "counter", "events", "countEvent",
                                                      "firedSeeds", "failing"})
                        self.assertEqual((entry["events"], entry["countEvent"]), (["E1", "E3"], "E3"))
                    else:
                        self.assertEqual(set(entry), {"id", "bypass", "counter", "event", "firedSeeds", "failing"})


if __name__ == "__main__":
    unittest.main()
