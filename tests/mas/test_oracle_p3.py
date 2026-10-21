"""Oracle tests for CONF-MAS-003, written outside the candidate (owner decision D5a).

These tests are black-box. They call only the interface the oracle brief names:
``_ledger.load_config()``, ``_ledger.run(config, cls, seed, bypass, arm, until_deadline)``,
``_ledger.ledger()``, ``_ledger.campaign_record()`` and ``_ledger.serialize()``. Every expectation comes
from DESIGN revision 6 (sections 2, 4 to 8 and 12 to 16), BUILD_NOTES' binding rules B5-1 to B5-4 and its
build-time additions, the candidate's declarative data files (classes.json, contracts.json,
attestation-p3.json), and packets 1 and 2's ledger as committed at c672aad (the seven row digests and the
file digest below). None is a snapshot of the candidate's output.

Each simulation run is made once and checked at once, so memory stays flat: C8, C9 and C10 in every seed,
defended, under each of their 10 controls and 6 depth checks, plus C9's 32 relay runs, which use a copy of
C9's entry carrying ``relayEvent`` and ``until_deadline`` set (640 runs); then one in-process ledger and one
campaign record.
"""

import hashlib
import json
import pathlib
import sys
import unittest

_HERE_PATH = pathlib.Path(__file__).resolve().parent
_HERE = str(_HERE_PATH)
if not sys.path or sys.path[0] != _HERE:
    sys.path.insert(0, _HERE)

import _ledger  # noqa: E402  (the candidate's run entry, used through its interface only)


# Packets 1 and 2's seven ledger rows at c672aad: sha256 of each row as canonical JSON (sorted keys,
# separators "," and ":", ASCII), computed from c672aad's tests/mas/results.json. C1 to C4 equal packet 2's
# oracle's packet-1 digests, which checks the canonical form.
PRIOR_ROW_SHA256 = {
    "C1": "b3ae188401761d30a75902c2c88fcf2924e6411ea8227c570242d4eb02642ce4",
    "C2": "aa6dc7c60a0e51f2e9e8dd3099b0d35dc9231195e8bd3fd1b65f79880c4e4565",
    "C3": "74a874d78e0c03186381e78766faf3912ce019622202e6532461b31ebdbd66d4",
    "C4": "ab21c9bb5d0692da48a6ec2d3f22c7070b0e1b81dce130c4b5a05eae3b7ec619",
    "C5": "2ee5ad5d482b77fee15925dda13763815bf4c57d91fcae530794e66d28189e10",
    "C6": "5a1988368aa2d212153ad7fc44f4427c8f70a447dfc715fd3e24126a84ea2ef3",
    "C7": "4439b7cd2675ee00a00ae406c559540029e93d894f455cae4b00b8aa2a491713",
}
# sha256 of c672aad's tests/mas/results.json as committed (DESIGN sections 4 and 8: d9871b7e...).
C672AAD_RESULTS_SHA256 = "d9871b7efe718b7e702d6200957de18cc5f519bddd50ad1745aa0dcccf76c7cd"
PACKET1_COMMIT = "05b74ff0e778f23faab1281731afa7f7b1fed85f"
PACKET1_RESULTS_PREFIX = "4343535a"  # DESIGN section 8 states only this prefix
PACKET2_COMMIT = "c672aad56960b33a3e6d281aa484c7ac507293aa"
REPIN_COMMIT = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"

# DESIGN section 2's table: the ten pinned files, byte-identical at 27c54605 and 585364b.
PINNED_FILES = [
    ("architecture/topology-coordination/README.md",
     "890af54aa39c6fbec35615bec8cadb5ffa62c33a5ccce0e21b7af5fcd3fb9c90", 28108),
    ("architecture/topology-coordination/board-transcript.schema.json",
     "8a3cc5b87953e97a4b42362df382f9b101931be1d55de84f441b16020b405b7c", 13998),
    ("architecture/topology-coordination/topology-spec.schema.json",
     "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0", 4485),
    ("architecture/agent-loop/README.md",
     "666c4221d3edbdd5187c17db9c43c122b1f7900a9fa0b3ddc430db3bee2b8e5a", 28107),
    ("architecture/agent-loop/loop-profile.schema.json",
     "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb", 6648),
    ("architecture/agent-loop/loop-trace.schema.json",
     "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e", 15434),
    ("architecture/run-manifest/README.md",
     "279d374e5ddd1b6305611f3565a7af14046b305e59cf9634a88bd358818ce826", 17769),
    ("architecture/run-manifest/distribution-gate.schema.json",
     "f521fc6691984959473ef4f184e863193c060acc0b2ed1012dcf1d2c9d3a1683", 2816),
    ("architecture/verdict-ledger/README.md",
     "dde6efc45fc2e1ad675635d0a18a1d6a82b49c960616af239f47071e2914e3f7", 22616),
    ("architecture/verdict-ledger/ledger.schema.json",
     "8a570cfb26b16fb3f7fa1cf799bd564fe717fd3d356dbca890dab747b2dc9326", 8391),
]

CLASS_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"]
PRIOR_IDS = CLASS_IDS[:7]
P3_IDS = ("C8", "C9", "C10")
PACKET_OF = {**{c: "CONF-MAS-001" for c in ("C1", "C2", "C3", "C4")},
             **{c: "CONF-MAS-002" for c in ("C5", "C6", "C7")},
             **{c: "CONF-MAS-003" for c in P3_IDS}}

# DESIGN sections 5 and 12 (Q-D3-1 (a)) with packets 1 and 2's recorded FAILs: exactly these four gates are
# false; every other gate of every class is true. A class is PASS only when every gate holds.
EXPECTED_FALSE_GATES = {(c, "ratioBounds.duplicatedWorkRatioPpm") for c in ("C2", "C5", "C7", "C9")}
EXPECTED_RESULTS = {"C1": "PASS", "C2": "FAIL", "C3": "PASS", "C4": "PASS", "C5": "FAIL", "C6": "PASS",
                    "C7": "FAIL", "C8": "PASS", "C9": "FAIL", "C10": "PASS"}
RECORDED_FAILS = {("C2", "duplicatedWorkRatioPpm", "Q-MAS1-F1"), ("C5", "duplicatedWorkRatioPpm", "Q3-2"),
                  ("C7", "duplicatedWorkRatioPpm", "Q3-2"), ("C9", "duplicatedWorkRatioPpm", "Q-D3-1")}

GATE_KEYS = {"defendedZeroAndEvents", "ratioBounds", "controlsFireInAllSeeds", "depthChecksHoldInAllSeeds"}
CLASS_ROW_KEYS = {"controls", "defended", "depthChecks", "gates", "id", "kind", "parameters", "result",
                  "unexercisedInvariants"}
LEDGER_KEYS = {"arms", "classes", "classesSha256", "contractsCommit", "packet", "profile", "rule",
               "schemaVersion", "seeds"}
CONTROL_ENTRY_KEYS = {"id", "bypass", "counter", "event", "firedSeeds", "failing"}
DEPTH_ENTRY_KEYS = {"id", "bypass", "engaged", "event", "failing", "heldSeeds"}
QUANTILE_KEYS = {"p50", "p95", "max", "min"}
ZERO_TOLERANCE = {"leakedSecrets", "doubleMerge", "nonHolderAccepted", "unexplainedDuplicate", "unclaimedWork"}

ROW_KEYS = frozenset((
    "t", "kind", "agent", "from", "to", "item", "op", "opId", "retryOf", "claimOpId", "expectedVersion",
    "recordVersionBefore", "answer", "changed", "component", "toolId", "verdictStatus", "workDigest",
    "markerPresent", "canaryHits", "scheduledEvent", "controlBypass", "leaseUntil", "grantId", "grantToolId",
    "grantManifestDigest", "grantScope", "grantExpiresAt", "inputKeys", "attempt", "iteration", "objectiveId",
    "heldBefore", "bodyKeys",
))
ROW_KINDS = frozenset((
    "BOARD_ANSWER", "EXPIRY", "DELIVERY", "OBSERVE", "TOOL_CALL", "GATE", "VERDICT", "SINK", "WORK",
    "ADMISSION", "KERNEL", "PLAN", "FAULT",
))
# Row kinds that record an agent acting (used for "takes no further step").
ACTING = frozenset(("BOARD_ANSWER", "TOOL_CALL", "WORK", "PLAN", "GATE", "KERNEL"))

# DESIGN section 5's preregistration of C8 to C10, as classes.json must carry it.
DESIGN_P3 = {
    "C8": {"kind": "AGENT_LOSS_PARTIAL_OBSERVABILITY", "topology": "CENTRAL", "maxLatency": 0, "deadline": 600,
           "poisonPpm": 0, "stallPpm": 0, "compromised": None,
           "budgets": {"iterations": 6, "readTimeout": 3, "stepRetries": 1}},
    "C9": {"kind": "DEADLOCK_LIVELOCK", "topology": "DECENTRALIZED_C9", "maxLatency": 3, "deadline": 600,
           "poisonPpm": 0, "stallPpm": 0, "compromised": "w4",
           "budgets": {"iterations": 6, "rounds": 3, "wallTicks": 100}},
    "C10": {"kind": "MERGE_CORRECTNESS", "topology": "DECENTRALIZED", "maxLatency": 3, "deadline": 600,
            "poisonPpm": 0, "stallPpm": 0, "compromised": None},
}
DESIGN_P3_EVENTS = {
    "C8": [("E1", "BOARD", "EXPIRY"), ("E2", "BOARD", "RETRY_REPEATED"), ("E3", "BOARD", "STALE_VERSION")],
    "C9": [("E1", "KERNEL", "BUDGET_EXHAUSTED"), ("E2", "KERNEL", "REVISION_BOUND")],
    "C10": [("E1", "BOARD", "VERDICT_NOT_PASS"), ("E2", "GATE", "GATE_FAIL"), ("E3", "BOARD", "NOT_HOLDER"),
            ("E4", "BOARD", "NOT_HOLDER")],
}
# (id, bypass, counter, event)
DESIGN_P3_CONTROLS = {
    "C8": [("C8-EXPIRY-OFF", ["EXPIRY"], "crashedHoldsAtDeadline", "E1"),
           ("C8-RETRY-OFF", ["RETRY", "HELD", "VERSION", "CONCURRENCY"], "retryChangedState", "E2"),
           ("C8-VERSION-OFF", ["VERSION"], "staleAccepted", "E3")],
    "C9": [("C9-WALL-OFF", ["WALL_CLOCK"], "claimsBeyondWallBudget", "E1"),
           ("C9-REVISION-OFF", ["REVISION_BOUND"], "revisionsBeyondBound", "E2"),
           ("C9-REVISION+BUDGET-OFF", ["REVISION_BOUND", "BUDGET"], "iterationsBeyondBudget", "E2")],
    "C10": [("C10-SUPERSEDE-OFF", ["SUPERSESSION"], "mergeWithoutPass", "E1"),
            ("C10-WORK-OFF", ["MERGE_GATE", "WORK_VERDICT"], "poisonMerged", "E2"),
            ("C10-RACE-OFF", ["SINGLE_MERGE", "VERSION"], "doubleMerge", "E3"),
            ("C10-HOLDER-OFF", ["HOLDER", "VERSION", "MERGE_VERDICT"], "nonHolderAccepted", "E4")],
}
# (id, event, bypass, counters, engaged)
DESIGN_P3_DEPTH = {
    "C8": [("C8-RETRY-DEPTH", "E2", ["RETRY"], ["retryChangedState"], "BOARD:HELD"),
           ("C8-RETRY-HELD-DEPTH", "E2", ["RETRY", "HELD"], ["retryChangedState"], "BOARD:STALE_VERSION")],
    "C9": [],
    "C10": [("C10-WORK-DEPTH", "E2", ["MERGE_GATE"], ["poisonMerged"], "BOARD:VERDICT_NOT_PASS"),
            ("C10-RACE-DEPTH", "E3", ["SINGLE_MERGE"], ["doubleMerge"], "BOARD:STALE_VERSION"),
            ("C10-HOLDER-DEPTH", "E4", ["HOLDER"], ["nonHolderAccepted"], "BOARD:STALE_VERSION"),
            ("C10-HOLDER-VERSION-DEPTH", "E4", ["HOLDER", "VERSION"], ["nonHolderAccepted"], "BOARD:NO_VERDICT")],
}
# DESIGN section 5: each class's violation set is these counters plus zeroTolerance.
DESIGN_P3_OWN = {
    "C8": {"crashedHoldsAtDeadline", "retryChangedState", "staleAccepted"},
    "C9": {"claimsBeyondWallBudget", "revisionsBeyondBound", "iterationsBeyondBudget"},
    "C10": {"mergeWithoutPass", "poisonMerged", "doubleMerge", "nonHolderAccepted"},
}
C8_READINGS = {"recoveryTicks", "reassignedToCrashed", "assignmentsToCrashed"}
C9_WORK_READINGS = {"mergesPer100Ticks", "maxClaimTicks", "lastMergeTick", "completionPpm", "lostWorkPpm"}
C9_RELAY_READINGS = {"relayDeliveries", "deliveriesPer100Ticks", "relayLastTick"}
C9_RELAY_EVENT = {"id": "E3", "trigger": "AT_TICK", "tick": 0, "from": "w4", "to": "w1", "messageType": "TEST",
                  "requiredAction": "CHANGE"}

# DESIGN section 6.
ARM_CLASSES = ["C2", "C3", "C4", "C5", "C7"]
ARM_POLICIES = [("A1", "maxResends", 2), ("A2", "renewAtRemaining", 6), ("A3", "maxReReads", 2)]
ARM_QUANTILES = {"duplicatedWorkRatioPpm", "lostWorkPpm", "completionPpm"}

# DESIGN section 8.
CAMPAIGN_KEYS = {"schemaVersion", "campaign", "consumer", "packets", "classes", "recordedFails", "findings",
                 "arms", "eventScopedReadings", "notClaimed"}
# MON-F-C9-3-RECORD (monitor decision, relayed under MON-ORACLE-FINDINGS (a)): F-C9-3 joins the record's findings.
FINDING_IDS = {"F-C8-1", "F-C9-1", "F-C9-2", "F-C9-3", "F-C10-1", "F-C5-1", "F-C5-2", "F-C6-1", "F-C7-1",
               "MAS1-CARRY-1"}
# DESIGN section 4: packet 1's event-scoped readings, captured from its existing depth runs.
PACKET1_EVENT_READINGS = {("C2-GATE-OFF", "E1"), ("C2-VERIFIER-OFF", "E1"), ("C3-DEDUPE-OFF", "E3"),
                          ("C3-RETRY-OFF", "E4")}

# DESIGN section 2: packet 2's closed attestation key set, schema r12.mas-attestation/v1.
ATTESTATION_FLAGS = ("warmSourceRead", "r10SourceRead", "w03WorkInProgressRead",
                     "implementationReadOrRunForExpectedResults")
ATTESTATION_KEYS = {"schemaVersion", "packet", "inputs", "inputDigests", "note"} | set(ATTESTATION_FLAGS)

# Home and scratch path markers, built from parts so that this file holds no path.
_PATH_MARKS = tuple("/" + part + "/" for part in ("Users", "home", "private", "tmp"))


# ---------------------------------------------------------------------------------------------
# Row helpers (read rows only; never the candidate's code)

def _canonical_sha256(obj):
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _is_hex64(text):
    return isinstance(text, str) and len(text) == 64 and all(c in "0123456789abcdef" for c in text)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _sorted(values):
    return sorted(values, key=repr)


def _brief(row):
    return {k: v for k, v in row.items() if v is not None and v != []}


def _want(kw):
    return {("from" if k == "frm" else k): v for k, v in kw.items()}


def _match(rows, where=None, **kw):
    if "frm" in kw:
        kw["from"] = kw.pop("frm")
    return [r for r in rows if all(r.get(k) == v for k, v in kw.items()) and (where is None or where(r))]


def _near(rows, kw):
    sub = {k: kw[k] for k in ("kind", "agent", "frm", "item") if k in kw}
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


def _applied(row):
    """An operation the board accepted and applied (a retry's historical answer changes nothing)."""
    return row.get("changed") is True or (row.get("answer") == "ACCEPTED" and row.get("changed") is not False)


def _status(row):
    return {row.get("answer"), row.get("verdictStatus")} - {None}


def _bypass(row):
    text = row.get("controlBypass")
    return set(text.split("+")) if isinstance(text, str) and text else set()


def _bus_delivered(row):
    return row["kind"] == "DELIVERY" and row["component"] == "BUS" and row["answer"] == "DELIVERED"


def _sender(row):
    return row["from"] if row["from"] is not None else row["agent"]


def _violation_set(cfg, cls):
    """DESIGN section 4: the controls' counters, the depth checks' counters and zeroTolerance."""
    out = {c["counter"] for c in cls["controls"]}
    for check in cls["depthChecks"]:
        out |= set(check["counters"])
    return out | set(cfg["zeroTolerance"])


def _engaged(bad, measured, event, key):
    total = measured["engaged"].get(key, 0)
    if not _is_int(total) or total < 1:
        bad(f"engaged {key} is at least 1", total)
    by_event = measured.get("engagedByEvent")
    got = (by_event.get(event) or {}).get(key, 0) if isinstance(by_event, dict) else None
    if not _is_int(got) or got < 1:
        bad(f"{event} engages {key} (engagedByEvent[{event}][{key}] is at least 1)", got)


def _first_claim_works(rows, agent, item):
    """The WORK rows of an agent's first claim on an item, grouped by the first WORK row's claimOpId."""
    works = _match(rows, kind="WORK", agent=agent, item=item)
    if not works:
        return None, []
    claim = works[0]["claimOpId"]
    return claim, [r for r in works if r["claimOpId"] == claim]


def _holds(quantiles, bound):
    """Packet 1's ratio bound: every stated quantile on the right side of its limit."""
    lower = bound["direction"] == "LOWER_IS_BETTER"
    for key, limit in bound.items():
        if key in ("decision", "direction"):
            continue
        value = quantiles[key]
        if (value > limit) if lower else (value < limit):
            return False
    return True


def _nearest_rank(values):
    """Nearest rank, k = (p x n + 99) // 100, as the ledger rule states."""
    ordered = sorted(values)
    n = len(ordered)

    def at(p):
        k = (p * n + 99) // 100
        return ordered[min(max(k, 1), n) - 1]

    return {"p50": at(50), "p95": at(95), "max": ordered[-1], "min": ordered[0]}


def _quantile_ok(q):
    if not isinstance(q, dict) or set(q) != QUANTILE_KEYS or not all(_is_int(v) for v in q.values()):
        return False
    return q["min"] <= q["p50"] <= q["p95"] <= q["max"]


def _personal_hits(text):
    hits = [mark for mark in _PATH_MARKS if mark in text]
    if "CANARY-" in text:
        hits.append("canary value")
    for token in text.replace('"', " ").replace("'", " ").replace(",", " ").split():
        at = token.find("@")
        if at > 0 and "." in token[at + 1:]:
            hits.append("e-mail-like token")
            break
    return hits


def _claim_spans(rows, deadline):
    """Claim intervals read from the rows: start at the accepted ACQUIRE or ASSIGN, end at the accepted MERGE
    or RELEASE, or at an expired claim's leaseUntil (never at its EXPIRY row's tick), else the deadline."""
    start = {}
    for r in rows:
        if r["kind"] == "BOARD_ANSWER" and r["op"] in ("ACQUIRE", "ASSIGN") and _applied(r):
            start[r["claimOpId"] or r["opId"]] = r["t"]
    end = {}
    for r in rows:
        claim = r["claimOpId"]
        if claim not in start or claim in end:
            continue
        if r["kind"] == "EXPIRY" and r["answer"] != "SKIPPED" and _is_int(r["leaseUntil"]):
            end[claim] = r["leaseUntil"]
        elif r["kind"] == "BOARD_ANSWER" and r["op"] in ("MERGE", "RELEASE") and _applied(r):
            end[claim] = r["t"]
    return [end.get(c, deadline) - s for c, s in start.items()]


def _work_summary(rows, cls):
    merges = [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["op"] == "MERGE" and _applied(r)
              and _is_int(r["t"])]
    last = max((r["t"] for r in merges), default=0)
    items = len({r["item"] for r in merges})
    spans = _claim_spans(rows, cls["deadline"])
    return {"lastMergeTick": last, "mergedItems": items, "mergesPer100Ticks": items * 100 // last if last else 0,
            "maxClaimTicks": max(spans) if spans else 0}


def _relay_summary(rows, cls):
    out = _work_summary(rows, cls)
    event = cls["measurements"]["event"]["id"]
    hops = [r for r in rows if _bus_delivered(r) and r["scheduledEvent"] == event]
    out["relayDeliveries"] = len(hops)
    out["deliveriesPer100Ticks"] = len(hops) * 100 // (cls["deadline"] + 1)
    out["relayLastTick"] = max((r["t"] for r in hops), default=-1)
    return out


# ---------------------------------------------------------------------------------------------
# Checks applied to every run

def _check_rows(rows, measured, cfg, cls, entry, bad):
    """Rows keep packet 2's 34 fields and its twelve kinds plus FAULT (DESIGN section 4); the new bypass rows
    appear only under their bypass, carry it, and appear once per claim."""
    bypass = set(entry["bypass"]) if entry else set()
    for row in rows:
        if set(row) != ROW_KEYS:
            bad("every row has exactly packet 2's 34 fields",
                {"extra": sorted(set(row) - ROW_KEYS), "missing": sorted(ROW_KEYS - set(row))})
            break
    kinds = sorted(str(k) for k in {r.get("kind") for r in rows} - ROW_KINDS)
    if kinds:
        bad("every row kind is one of packet 2's twelve or FAULT", kinds)
    nonlist = [r for r in rows if not isinstance(r.get("canaryHits"), list)]
    if nonlist:
        bad("canaryHits is a list on every row", _brief(nonlist[0]))
    if not all(isinstance(measured.get(k), dict) for k in ("counts", "engaged", "engagedByEvent")):
        bad("measured carries the counts, engaged and engagedByEvent maps", sorted(measured))
    faults = [r for r in rows if r.get("kind") == "FAULT"]
    if faults and "crashes" not in cls:
        bad("FAULT rows appear only in a class with crashes", _brief(faults[0]))
    odd = [r for r in faults if (r["answer"], r["component"]) != ("CRASH", "SCHEDULE") or r["scheduledEvent"] is None]
    if odd:
        bad("a FAULT row carries answer CRASH, component SCHEDULE and its event tag", _brief(odd[0]))
    skipped = [r for r in rows if r.get("kind") == "EXPIRY" and r.get("answer") == "SKIPPED"]
    if skipped and "EXPIRY" not in bypass:
        bad("SKIPPED EXPIRY rows appear only under the EXPIRY bypass", _brief(skipped[0]))
    if any("EXPIRY" not in _bypass(r) for r in skipped):
        bad("a SKIPPED EXPIRY row carries controlBypass EXPIRY")
    claims = [(r["item"], r["claimOpId"]) for r in skipped]
    if len(set(claims)) != len(claims):
        bad("one SKIPPED EXPIRY row per claim", claims[:6])
    for answer, need in (("REVISION_OVERRUN", "REVISION_BOUND"), ("WALL_OVERRUN", "WALL_CLOCK")):
        hits = [r for r in rows if r.get("kind") == "KERNEL" and r.get("answer") == answer]
        if hits and need not in bypass:
            bad(f"KERNEL {answer} appears only under the {need} bypass", _brief(hits[0]))
        if any(need not in _bypass(r) for r in hits):
            bad(f"a KERNEL {answer} row carries controlBypass {need}")
        keys = [(r["agent"], r["item"], r["claimOpId"]) for r in hits]
        if len(set(keys)) != len(keys):
            bad(f"KERNEL {answer} is logged once per claim", keys[:6])
    if "rounds" not in (cls.get("budgets") or {}):
        bounded = [r for r in rows if r.get("kind") == "KERNEL" and r.get("answer") in ("REVISION_BOUND",
                                                                                        "REVISION_OVERRUN")]
        if bounded:
            bad("a class without budgets.rounds logs no REVISION_BOUND row", _brief(bounded[0]))


def _check_zero(rows, measured, cfg, cls, entry, bad):
    counts = measured["counts"]
    for name in sorted(_violation_set(cfg, cls)):
        if name not in counts:
            bad(f"measured counts name {name}")
        elif counts[name] != 0:
            bad(f"{name} is 0 in the defended run", counts[name])


def _check_control_generic(rows, measured, cfg, cls, entry, bad):
    count = measured["counts"].get(entry["counter"])
    if not _is_int(count) or count <= 0:
        bad(f"own counter {entry['counter']} is above 0", count)
    named = set()
    for row in rows:
        if row["scheduledEvent"] == entry["event"]:
            named |= _bypass(row)
    missing = sorted(set(entry["bypass"]) - named)
    if missing:
        bad(f"every bypassed check is named on a row tagged {entry['event']}", missing)


def _check_depth_generic(rows, measured, cfg, cls, entry, bad):
    counts = measured["counts"]
    for name in sorted(_violation_set(cfg, cls)):
        if name not in counts:
            bad(f"measured counts name {name}")
        elif counts[name] != 0:
            bad(f"{name} is 0 under the depth check's bypass", counts[name])
    key, event = entry["engaged"], entry["event"]
    by_event = measured.get("engagedByEvent")
    got = (by_event.get(event) or {}).get(key, 0) if isinstance(by_event, dict) else None
    if not _is_int(got) or got < 1:
        bad(f"engagedByEvent[{event}][{key}] is at least 1 (engagement scoped to the check's event)", got)
    component, answer = key.split(":", 1)
    hits = [r for r in rows if r["scheduledEvent"] == event and r["component"] == component
            and (r["answer"] == answer or r["toolId"] == answer)]
    if not hits:
        bad(f"a row tagged {event} carries {key}")


def _no_check(rows, measured, cfg, cls, entry, bad):
    bad("the oracle has no preregistered path for this entry")


# ---------------------------------------------------------------------------------------------
# C8 AGENT_LOSS_PARTIAL_OBSERVABILITY (DESIGN section 5; CENTRAL, maxLatency 0; w_a and w_b drawn per seed
# from sched-c8 and read back from the rows: w_a from its FAULT row, w_b from the coordinator's retry)

def _c8_fault(rows, bad):
    faults = [r for r in rows if r["kind"] == "FAULT"]
    if len(faults) != 1:
        bad("E1: exactly one FAULT row (w_a's crash)", [_brief(r) for r in faults[:3]])
        return None
    fault = faults[0]
    item = fault["item"]
    if not _is_int(item) or fault["agent"] != f"w{item}":
        bad("tick 0 assigns item k to worker k, so the crashed w_a is w<k> holding item k", _brief(fault))
        return None
    return fault


def _c8_retry(rows, bad):
    retries = _match(rows, lambda r: r["retryOf"] is not None, kind="BOARD_ANSWER", agent="c")
    if len(retries) != 1:
        bad("E2: the coordinator sends exactly one overdue retry", [_brief(r) for r in retries[:3]])
        return None
    retry = retries[0]
    if (retry["t"], retry["op"], retry["scheduledEvent"], retry["expectedVersion"]) != (2, "ASSIGN", "E2", 0):
        bad("E2: the retry re-sends the tick-0 ASSIGN's exact body at 2 (expectedVersion 0), tagged E2",
            _brief(retry))
    item = retry["item"]
    if not _is_int(item):
        bad("E2: the retry names w_b's item", _brief(retry))
        return None
    orig = _one(bad, rows, "E2: c's tick-0 ASSIGN of w_b's item is accepted", where=_applied, kind="BOARD_ANSWER",
                op="ASSIGN", agent="c", item=item, t=0)
    if orig is not None and retry["retryOf"] != orig["opId"]:
        bad("E2: the retry names the tick-0 ASSIGN's opId in retryOf", {"retryOf": retry["retryOf"],
                                                                         "opId": orig["opId"]})
    return retry


def _c8_defended(rows, measured, cfg, cls, entry, bad):
    pos = _positions(rows)
    assigned = _sorted(r["item"] for r in _match(rows, _applied, kind="BOARD_ANSWER", op="ASSIGN", agent="c", t=0))
    if assigned != [1, 2, 3, 4]:
        bad("timeline: c ASSIGNs items 1 to 4 at 0, all accepted", assigned)
    fault = _c8_fault(rows, bad)
    retry = _c8_retry(rows, bad)

    # E1 holder crash, and E3 coordinator restart
    if fault is not None:
        w_a, k_a = fault["agent"], fault["item"]
        read = _one(bad, rows, "E1: w_a's READ launched at 1", kind="TOOL_CALL", agent=w_a, toolId="READ", t=1,
                    answer="LAUNCHED")
        if ((fault["t"], fault["answer"], fault["component"], fault["scheduledEvent"]) != (1, "CRASH", "SCHEDULE", "E1")
                or fault["claimOpId"] is None):
            bad("E1: FAULT CRASH of w_a at 1, component SCHEDULE, tagged E1, naming its claim", _brief(fault))
        if read is not None and pos[id(fault)] < pos[id(read)]:
            bad("E1: w_a crashes after launching its READ")
        after = [r for r in rows if r["agent"] == w_a and r["kind"] in ACTING and pos[id(r)] > pos[id(fault)]]
        if after:
            bad("E1: the crashed w_a takes no further step", [_brief(r) for r in after[:3]])
        expiry = _one(bad, rows, "E1 engaging row: EXPIRY of w_a's item at 8 (lease end 8), tagged E1",
                      where=lambda r: r["answer"] != "SKIPPED", kind="EXPIRY", item=k_a, agent=w_a, t=8, leaseUntil=8,
                      scheduledEvent="E1")
        resent = _match(rows, kind="BOARD_ANSWER", agent="c", t=8)
        if expiry is not None and resent and pos[id(expiry)] > min(pos[id(r)] for r in resent):
            bad("E1: the EXPIRY is logged at the first board activity, before E3's re-sent ASSIGNs are answered")
        merged = _sorted(r["item"] for r in _match(rows, _applied, kind="BOARD_ANSWER", op="MERGE", t=7))
        if merged != _sorted(k for k in (1, 2, 3, 4) if k != k_a):
            bad("E3 setup: the three items other than w_a's are merged at 7", merged)
        shape = _sorted((r["item"], r["op"], r["answer"], r["scheduledEvent"], r["expectedVersion"], r["retryOf"])
                        for r in resent)
        want = _sorted((k, "ASSIGN", "STALE_VERSION" if k == k_a else "MERGED", "E3", 0, None) for k in (1, 2, 3, 4))
        if shape != want:
            bad("E3 engaging rows: at 8 the coordinator only re-sends its four tick-0 ASSIGNs as new operations "
                "(expectedVersion 0, tagged E3); the three merged items are refused MERGED and w_a's item, "
                "reopened by E1's expiry, STALE_VERSION", shape)

    # E2 lost answer
    if retry is not None:
        if retry["changed"] is not False or retry["answer"] not in ("ACCEPTED", "RETRY_REPEATED"):
            bad("E2 engaging row: the retry gets the historical ACCEPTED and changes nothing", _brief(retry))
        k_b = retry["item"]
        if fault is not None and k_b == fault["item"]:
            bad("E2: w_b differs from w_a", {"w_a": fault["agent"], "w_b": f"w{k_b}"})
        drops = _match(rows, kind="DELIVERY", answer="DROPPED")
        if (len(drops) != 1 or (drops[0]["t"], drops[0]["component"], drops[0]["scheduledEvent"]) != (0, "CHANNEL", "E2")
                or drops[0]["item"] not in (None, k_b)):
            bad("E2: exactly one CHANNEL DROPPED delivery, at 0, tagged E2: the answer to c's ASSIGN of w_b's item",
                [_brief(r) for r in drops[:3]])
    _engaged(bad, measured, "E2", "BOARD:RETRY_REPEATED")
    _engaged(bad, measured, "E3", "BOARD:STALE_VERSION")


def _c8_p18(rows, measured, cfg, cls, entry, bad):
    """DESIGN section 4 and 5, P1-8 in C8: w_a's READ launched at 1 has no OBSERVE and no TIMEOUT by its due
    tick 4, and w_a has a FAULT row, so the READ is not judged and timeoutExceeded is 0."""
    got = measured["counts"].get("timeoutExceeded")
    if got != 0:
        bad("P1-8: timeoutExceeded is 0 in C8's defended run", got)
    faults = [r for r in rows if r["kind"] == "FAULT"]
    if len(faults) != 1:
        bad("P1-8: w_a has exactly one FAULT row", len(faults))
        return
    w_a = faults[0]["agent"]
    due = 1 + cls["budgets"]["readTimeout"]
    _one(bad, rows, "P1-8: w_a's READ launched at 1", kind="TOOL_CALL", agent=w_a, toolId="READ", t=1,
         answer="LAUNCHED")
    answered = [r for r in rows if r["agent"] == w_a and _is_int(r["t"]) and r["t"] <= due
                and (r["kind"] == "OBSERVE" or (r["kind"] == "KERNEL" and r["answer"] in ("TIMEOUT", "OVERRUN")))]
    if answered:
        bad(f"P1-8: w_a's READ has neither an OBSERVE nor a TIMEOUT by its due tick {due}, so only the FAULT clause "
            "leaves it unjudged", [_brief(r) for r in answered[:3]])


def _c8_expiry_off(rows, measured, cfg, cls, entry, bad):
    fault = _c8_fault(rows, bad)
    if fault is None:
        return
    w_a, k_a = fault["agent"], fault["item"]
    _one(bad, rows, "bypass row: SKIPPED EXPIRY of w_a's item at 8 (lease end 8), tagged E1, carrying EXPIRY",
         where=lambda r: "EXPIRY" in _bypass(r), kind="EXPIRY", item=k_a, agent=w_a, t=8, leaseUntil=8,
         answer="SKIPPED", scheduledEvent="E1")
    claim = fault["claimOpId"]
    ends = [r for r in rows if r["claimOpId"] == claim
            and ((r["kind"] == "EXPIRY" and r["answer"] != "SKIPPED")
                 or (r["kind"] == "BOARD_ANSWER" and r["op"] in ("RELEASE", "MERGE") and _applied(r)))]
    if ends:
        bad("effect through E1: w_a's crashed claim never ends", [_brief(r) for r in ends[:3]])
    merged = _match(rows, _applied, kind="BOARD_ANSWER", op="MERGE", item=k_a)
    if merged:
        bad("effect through E1: w_a's item is never merged", [_brief(r) for r in merged[:3]])


def _c8_retry_off(rows, measured, cfg, cls, entry, bad):
    retry = _c8_retry(rows, bad)
    if retry is not None and retry["changed"] is not True:
        bad("bypass row and effect: the retry at 2 is applied afresh and takes a second claim, tagged E2",
            _brief(retry))


def _c8_version_off(rows, measured, cfg, cls, entry, bad):
    fault = _c8_fault(rows, bad)
    if fault is None:
        return
    _one(bad, rows, "bypass row and effect: c's re-sent ASSIGN of the crashed w_a's item at 8 is accepted with "
         "expectedVersion 0, tagged E3, carrying VERSION", where=lambda r: _applied(r) and "VERSION" in _bypass(r),
         kind="BOARD_ANSWER", op="ASSIGN", agent="c", item=fault["item"], t=8, expectedVersion=0,
         scheduledEvent="E3")


def _c8_retry_depth(rows, measured, cfg, cls, entry, bad):
    retry = _c8_retry(rows, bad)
    if retry is not None and retry["answer"] != "HELD":
        bad("C8-RETRY-DEPTH: the retried ASSIGN at 2 is refused HELD", _brief(retry))


def _c8_retry_held_depth(rows, measured, cfg, cls, entry, bad):
    retry = _c8_retry(rows, bad)
    if retry is not None and retry["answer"] != "STALE_VERSION":
        bad("C8-RETRY-HELD-DEPTH: the retry names 0 and the record is at 1, so it is refused STALE_VERSION",
            _brief(retry))
    fault = _c8_fault(rows, bad)
    if fault is not None:
        _one(bad, rows, "C8-RETRY-HELD-DEPTH: E3's re-sent ASSIGN of w_a's item at 8 is still refused STALE_VERSION",
             kind="BOARD_ANSWER", op="ASSIGN", agent="c", item=fault["item"], t=8, answer="STALE_VERSION",
             scheduledEvent="E3")


# ---------------------------------------------------------------------------------------------
# C9 DEADLOCK_LIVELOCK (DESIGN section 5; DECENTRALIZED_C9, maxLatency 3; fixed roles, first claims on the lane)

def _c9_defended(rows, measured, cfg, cls, entry, bad):
    pos = _positions(rows)
    firsts = {(r["agent"], r["item"]) for r in _match(rows, _applied, kind="BOARD_ANSWER", op="ACQUIRE", t=0)}
    missing = [p for p in (("w1", 1), ("w2", 2), ("w3", 3)) if p not in firsts]
    if missing:
        bad("first claims at 0 on the lane: w1 item 1, w2 item 2, w3 item 3", missing)

    # E1 wait cycle
    for agent, item in (("w1", 1), ("w2", 2)):
        _some(bad, rows, f"E1: w4's DEPENDENCY/ACKNOWLEDGE is delivered to {agent} at 0, tagged E1",
              kind="DELIVERY", component="BUS", frm="w4", to=agent, t=0, answer="DELIVERED", scheduledEvent="E1")
        _some(bad, rows, f"E1: v's PASS notice reaches {agent} at 6", kind="DELIVERY", component="BUS", frm="v",
              to=agent, t=6, answer="DELIVERED")
        renews = [r for r in _match(rows, _applied, kind="BOARD_ANSWER", op="RENEW", agent=agent, item=item)
                  if 6 < r["t"] < 101]
        if not renews:
            bad(f"E1: {agent} keeps renewing item {item} while it waits (accepted RENEWs after 6 and before 101)")
        # MON-ORACLE-P3 re-pin: no tag check on RENEW rows. The design names the rows that carry the hold's E1 tag:
        # the KERNEL BUDGET_EXHAUSTED "tagged with the hold's event" (section 2.2) and, for the board claim, the EXPIRY
        # ("Its held claim gets the event tag, so its EXPIRY row carries it", section 4); both are pinned below. No
        # sentence says a RENEW reads the hold's event.
        sent = [r for r in _match(rows, kind="BOARD_ANSWER", op="MERGE", agent=agent, item=item) if r["t"] <= 101]
        if sent:
            bad(f"E1: {agent} sends no MERGE of item {item} while it waits", [_brief(r) for r in sent[:3]])
        _one(bad, rows, f"E1 engaging row: KERNEL BUDGET_EXHAUSTED for {agent} on item {item} at 101 (take tick 1 "
             "+ wallTicks 100), tagged E1", kind="KERNEL", component="KERNEL", agent=agent, item=item, t=101,
             answer="BUDGET_EXHAUSTED", scheduledEvent="E1")
        expiries = [r for r in _match(rows, kind="EXPIRY", item=item, scheduledEvent="E1")
                    if r["answer"] != "SKIPPED" and _is_int(r["leaseUntil"]) and r["leaseUntil"] > 101]
        if not expiries:
            bad(f"E1: the lease of {agent}'s ended hold on item {item} expires after 101 (an EXPIRY tagged E1)",
                [_brief(r) for r in _match(rows, kind="EXPIRY", item=item)][:3])
        else:
            last = expiries[0]["t"]
            late = [r for r in _match(rows, _applied, kind="BOARD_ANSWER", op="RENEW", agent=agent, item=item)
                    if 101 <= r["t"] <= last]
            if late:
                bad(f"E1: {agent}'s loop has ended at 101, so it renews item {item} no more",
                    [_brief(r) for r in late[:3]])
        merges = [r for r in _match(rows, _applied, kind="BOARD_ANSWER", op="MERGE", item=item) if r["t"] > 101]
        if not merges:
            bad(f"E1: item {item} is reclaimed and merged after the abort")
    _engaged(bad, measured, "E1", "KERNEL:BUDGET_EXHAUSTED")

    # E2 revision livelock
    claim, works = _first_claim_works(rows, "w3", 3)
    if len(works) != 4 or any(r["markerPresent"] is not True or r["scheduledEvent"] != "E2" for r in works):
        bad("E2: w3's claim on item 3 makes exactly 4 WORKs (3 revisions), every one on poisoned bytes and tagged E2",
            [_brief(r) for r in works[:6]])
    # MON-ORACLE-P3 re-pin. Section 2.2: "When the bound stops a revision, the kernel logs KERNEL REVISION_BOUND
    # before the RELEASE"; with rounds in C9's budgets this holds on every claim, so untagged bounds on other claims
    # are allowed. Section 5, C9 E2: "the kernel logs REVISION_BOUND (E2)": exactly one bound tagged E2, on w3's E2
    # claim.
    bounds = _match(rows, kind="KERNEL", answer="REVISION_BOUND")
    tagged = [r for r in bounds if r["scheduledEvent"] == "E2"]
    bound = None
    if claim is None or len(tagged) != 1 or (tagged[0]["agent"], tagged[0]["item"], tagged[0]["component"],
                                             tagged[0]["claimOpId"]) != ("w3", 3, "KERNEL", claim):
        bad("E2 engaging row: exactly one KERNEL REVISION_BOUND tagged E2, w3's on item 3, on its E2 claim",
            [_brief(r) for r in tagged[:3]])
    else:
        bound = tagged[0]
    elsewhere = [r for r in bounds if r["scheduledEvent"] != "E2"
                 and (r["scheduledEvent"] is not None or (claim is not None and r["claimOpId"] == claim))]
    if elsewhere:
        bad("E2: every other REVISION_BOUND is untagged and on another claim", [_brief(r) for r in elsewhere[:3]])
    # MON-ORACLE-P3 re-pin. Section 5, C9 E2: "After 3 revisions (4 WORKs), the kernel logs REVISION_BOUND (E2) and
    # w3 RELEASEs." The design tags the bound, not the RELEASE, so the RELEASE is pinned to w3's E2 claim.
    releases = _match(rows, lambda r: _applied(r) and claim is not None and r["claimOpId"] == claim,
                      kind="BOARD_ANSWER", op="RELEASE", agent="w3", item=3)
    if len(releases) != 1:
        bad("E2: w3 RELEASEs item 3 once, on its E2 claim", [_brief(r) for r in releases[:3]])
    else:
        if bound is not None and pos[id(bound)] > pos[id(releases[0])]:
            bad("E2: the kernel logs REVISION_BOUND before the RELEASE")
        if bound is not None and works and pos[id(bound)] < pos[id(works[-1])]:
            bad("E2: REVISION_BOUND follows the fourth WORK")
        released = releases[0]["t"]
        clean = [r for r in _match(rows, kind="WORK", item=3) if r["t"] >= released and r["markerPresent"] is False]
        merged = [r for r in _match(rows, _applied, kind="BOARD_ANSWER", op="MERGE", item=3) if r["t"] > released]
        if not clean or not merged:
            bad("E2: item 3 is reclaimed, read clean and merged after the RELEASE",
                {"cleanWorks": len(clean), "merges": len(merged)})
    over = _match(rows, kind="KERNEL", answer="BUDGET_EXHAUSTED", scheduledEvent="E2")
    if over:
        bad("E2 defended: the iterations budget is not reached (4 WORKs, budget 6)", [_brief(r) for r in over[:3]])
    _engaged(bad, measured, "E2", "KERNEL:REVISION_BOUND")

    tagged = [r for r in rows if r["scheduledEvent"] == "E3"]
    if tagged:
        bad("E3 is measured only in the relay runs: no defended row is tagged E3", [_brief(r) for r in tagged[:3]])


def _c9_wall_off(rows, measured, cfg, cls, entry, bad):
    for agent, item in (("w1", 1), ("w2", 2)):
        _one(bad, rows, f"bypass row: KERNEL WALL_OVERRUN for {agent} on item {item} at 101, tagged E1, carrying "
             "WALL_CLOCK", where=lambda r: "WALL_CLOCK" in _bypass(r), kind="KERNEL", agent=agent, item=item, t=101,
             answer="WALL_OVERRUN", scheduledEvent="E1")
        ends = [r for r in rows if r["item"] == item
                and ((r["kind"] == "EXPIRY" and r["answer"] != "SKIPPED")
                     or (r["kind"] == "BOARD_ANSWER" and r["op"] in ("RELEASE", "MERGE") and _applied(r)))]
        if ends:
            bad(f"effect through E1: {agent} holds item {item} to the deadline (no expiry, release or merge)",
                [_brief(r) for r in ends[:3]])
        aborts = _match(rows, kind="KERNEL", agent=agent, answer="BUDGET_EXHAUSTED", scheduledEvent="E1")
        if aborts:
            bad(f"effect: the wall clock no longer ends {agent}'s loop", [_brief(r) for r in aborts[:3]])
    if measured["counts"].get("claimsBeyondWallBudget", 0) < 2:
        bad("effect: both waiting claims, each with a WALL_OVERRUN row, count in claimsBeyondWallBudget",
            measured["counts"].get("claimsBeyondWallBudget"))


def _c9_revision_off(rows, measured, cfg, cls, entry, bad):
    pos = _positions(rows)
    _claim, works = _first_claim_works(rows, "w3", 3)
    if len(works) != 6:
        bad("effect through E2: w3's claim makes WORKs 5 and 6 and no seventh (six WORKs)", len(works))
    if len(works) >= 5 and any(r["scheduledEvent"] != "E2" for r in works[4:]):
        bad("effect rows: w3's fifth and sixth WORKs are tagged E2", [_brief(r) for r in works[4:6]])
    _one(bad, rows, "bypass row: KERNEL REVISION_OVERRUN for w3, tagged E2, carrying REVISION_BOUND",
         where=lambda r: "REVISION_BOUND" in _bypass(r), kind="KERNEL", agent="w3", answer="REVISION_OVERRUN",
         scheduledEvent="E2")
    refused = _one(bad, rows, "the seventh MODEL step is refused: KERNEL BUDGET_EXHAUSTED for w3 on item 3, tagged E2",
                   kind="KERNEL", agent="w3", item=3, answer="BUDGET_EXHAUSTED", scheduledEvent="E2")
    if refused is not None and works and pos[id(refused)] < pos[id(works[-1])]:
        bad("the BUDGET_EXHAUSTED follows w3's sixth WORK")
    bounds = _match(rows, kind="KERNEL", answer="REVISION_BOUND")
    if bounds:
        bad("under the REVISION_BOUND bypass the kernel logs no REVISION_BOUND", [_brief(r) for r in bounds[:3]])


def _c9_revision_budget_off(rows, measured, cfg, cls, entry, bad):
    _claim, works = _first_claim_works(rows, "w3", 3)
    if len(works) < 7:
        bad("effect through E2: w3's claim goes past six WORKs", len(works))
    else:
        seventh = works[6]
        if "BUDGET" not in _bypass(seventh) or seventh["scheduledEvent"] != "E2":
            bad("bypass row and effect: w3's seventh WORK carries BUDGET, tagged E2", _brief(seventh))
        late = [r for r in works if r["t"] > 101]
        if late:
            bad("w3's loop makes no WORK after the wall clock ends it at 101", [_brief(r) for r in late[:3]])
    _one(bad, rows, "the wall clock ends w3's loop at the take tick + 100: KERNEL BUDGET_EXHAUSTED for w3 on item 3 "
         "at 101, tagged E2", kind="KERNEL", agent="w3", item=3, t=101, answer="BUDGET_EXHAUSTED",
         scheduledEvent="E2")
    _one(bad, rows, "bypass row: KERNEL REVISION_OVERRUN for w3, tagged E2, carrying REVISION_BOUND",
         where=lambda r: "REVISION_BOUND" in _bypass(r), kind="KERNEL", agent="w3", answer="REVISION_OVERRUN",
         scheduledEvent="E2")


def _c9_recount(rows, measured, cfg, cls, entry, bad):
    """DESIGN section 4: revisionsBeyondBound counts WORK rows that are at least the (rounds + 2)-th WORK of the
    same agent and claim; claimsBeyondWallBudget counts at least every claim with a WALL_OVERRUN row."""
    rounds = cls["budgets"]["rounds"]
    seen = {}
    beyond = 0
    for r in rows:
        if r["kind"] == "WORK":
            key = (r["agent"], r["claimOpId"])
            seen[key] = seen.get(key, 0) + 1
            if seen[key] >= rounds + 2:
                beyond += 1
    got = measured["counts"].get("revisionsBeyondBound")
    if got != beyond:
        bad("revisionsBeyondBound equals its recount from the WORK rows", {"counted": got, "recount": beyond})
    overruns = {(r["agent"], r["item"], r["claimOpId"]) for r in rows
                if r["kind"] == "KERNEL" and r["answer"] == "WALL_OVERRUN"}
    if measured["counts"].get("claimsBeyondWallBudget", 0) < len(overruns):
        bad("claimsBeyondWallBudget counts every claim with a WALL_OVERRUN row",
            {"counted": measured["counts"].get("claimsBeyondWallBudget"), "overrunClaims": len(overruns)})


def _check_relay(rows, measured, cfg, cls, entry, bad):
    """DESIGN section 5, C9's relay measurement: from tick 1, on every tick, one honest worker obeys and relays
    E3 to its ring successor; the run goes on through tick 600, with no DEADLINE refusal."""
    spec = cls["measurements"]["event"]
    ring = cls["relayRing"]
    last = cls["deadline"]
    hops = [r for r in rows if _bus_delivered(r) and r["scheduledEvent"] == spec["id"]]
    ticks = [r["t"] for r in hops]
    if ticks != list(range(0, last + 1)):
        bad(f"relay: exactly one {spec['id']} delivery per tick, from 0 through the deadline {last}",
            {"deliveries": len(ticks), "firstTicks": ticks[:3], "lastTicks": ticks[-3:],
             "missing": sorted(set(range(0, last + 1)) - set(ticks))[:5]})
    if hops:
        first = hops[0]
        if (_sender(first), first["to"]) != (spec["from"], spec["to"]):
            bad(f"relay: the first hop is {spec['from']} -> {spec['to']}", _brief(first))
        broken = [(_brief(prev), _brief(cur)) for prev, cur in zip(hops, hops[1:])
                  if _sender(cur) != prev["to"] or ring.get(_sender(cur)) != cur["to"]]
        if broken:
            bad("relay: each hop is relayed by the last recipient to its ring successor (w1 -> w2 -> w3 -> w1)",
                broken[:2])
    refused = [r for r in rows if r["answer"] == "DEADLINE"]
    if refused:
        bad("relay: no DEADLINE refusal occurs (the run covers ticks 0 to the deadline)",
            [_brief(r) for r in refused[:3]])


# ---------------------------------------------------------------------------------------------
# C10 MERGE_CORRECTNESS (DESIGN section 5; DECENTRALIZED, maxLatency 3; first claims on the lane, scripted faults)

def _c10_work_a(rows, bad):
    _claim, works = _first_claim_works(rows, "w2", 2)
    if len(works) < 2 or works[0]["markerPresent"] is not True or works[1]["markerPresent"] is not False:
        bad("E2: w2's first claim makes marked work A, then clean work B", [_brief(r) for r in works[:3]])
        return None
    if any(r["scheduledEvent"] != "E2" for r in works):
        bad("E2: w2's first claim carries E2 across revisions (its WORKs are tagged E2)",
            [_brief(r) for r in works if r["scheduledEvent"] != "E2"][:3])
    return works


def _c10_pair(rows, bad):
    pair = _match(rows, kind="BOARD_ANSWER", op="MERGE", agent="w3", item=3, t=7)
    if len(pair) != 2:
        bad("E3: w3 sends its MERGE of item 3 twice at 7", [_brief(r) for r in pair[:3]])
        return None
    first, second = pair
    if (first["opId"] == second["opId"]
            or (first["expectedVersion"], first["workDigest"]) != (second["expectedVersion"], second["workDigest"])):
        bad("E3: the two MERGEs are two opIds with the same body", [_brief(first), _brief(second)])
    if first["scheduledEvent"] != "E3" or second["scheduledEvent"] != "E3":
        bad("E3: both MERGEs are tagged E3", [_brief(first), _brief(second)])
    if not _applied(first):
        bad("E3: the first MERGE is accepted", _brief(first))
    return first, second


def _c10_e4(rows, bad):
    # MON-ORACLE-P3 re-pin: section 5, C10 E4, "Its lease, renewed at 4, ends at 12", names no tag for the RENEW, and
    # no sentence says a RENEW reads the hold's event. The E4 tag stays pinned on the EXPIRY and on w4's MERGE below.
    _one(bad, rows, "E4: w4 RENEWs item 4 at 4 to lease 12", where=_applied, kind="BOARD_ANSWER",
         op="RENEW", agent="w4", item=4, t=4, leaseUntil=12)
    expiries = [r for r in _match(rows, kind="EXPIRY", item=4, leaseUntil=12, scheduledEvent="E4")
                if r["answer"] != "SKIPPED"]
    if not expiries:
        bad("E4: w4's claim expires at its lease end 12 (an EXPIRY of item 4 with leaseUntil 12, tagged E4)",
            [_brief(r) for r in _match(rows, kind="EXPIRY", item=4)][:3])
    reclaims = [r for r in _match(rows, _applied, kind="BOARD_ANSWER", op="ACQUIRE", item=4)
                if r["agent"] != "w4" and r["t"] >= 12]
    if not reclaims:
        bad("E4: an idle worker reclaims item 4 after its lease ends at 12")
        return None
    reclaim = reclaims[0]["t"]
    quiet = [r for r in _match(rows, kind="BOARD_ANSWER", agent="w4") if 7 <= r["t"] <= reclaim]
    if quiet:
        bad("E4: from 7 until the reclaim, w4 neither merges nor renews", [_brief(r) for r in quiet[:3]])
    return _one(bad, rows, f"E4: w4's MERGE of item 4 on the tick after the reclaim ({reclaim + 1}), with its old "
                "version 2, tagged E4", kind="BOARD_ANSWER", op="MERGE", agent="w4", item=4, t=reclaim + 1,
                expectedVersion=2, scheduledEvent="E4")


def _c10_defended(rows, measured, cfg, cls, entry, bad):
    pos = _positions(rows)
    firsts = {(r["agent"], r["item"]) for r in _match(rows, _applied, kind="BOARD_ANSWER", op="ACQUIRE", t=0)}
    missing = [(f"w{k}", k) for k in (1, 2, 3, 4) if (f"w{k}", k) not in firsts]
    if missing:
        bad("first claims at 0 on the lane: w1 to w4 take items 1 to 4", missing)

    # E1 MERGE on a superseded verdict
    _one(bad, rows, "E1: v's VERIFY of item 1 accepted at 5, tagged E1", where=_applied, kind="BOARD_ANSWER",
         op="VERIFY", agent="v", item=1, t=5, scheduledEvent="E1")
    _one(bad, rows, "E1: v's scripted superseding VERIFY of item 1 accepted at 6, tagged E1", where=_applied,
         kind="BOARD_ANSWER", op="VERIFY", agent="v", item=1, t=6, scheduledEvent="E1")
    if not any(r["agent"] == "v" and r["scheduledEvent"] == "E1" and _is_int(r["t"]) and r["t"] <= 5
               and "PASS" in _status(r) for r in rows):
        bad("E1: v judges w1's first work PASS by 5 (a row of v tagged E1 states PASS)")
    if not any(r["agent"] == "v" and r["scheduledEvent"] == "E1" and r["t"] == 6 and "FAIL" in _status(r)
               for r in rows):
        bad("E1: v's superseding verdict at 6 is FAIL (a row of v at 6 tagged E1 states FAIL)")
    _some(bad, rows, "E1: v's PASS notice reaches w1 at 6", kind="DELIVERY", component="BUS", frm="v", to="w1", t=6,
          answer="DELIVERED")
    _one(bad, rows, "E1 engaging row: w1's MERGE of item 1 at 7 refused VERDICT_NOT_PASS, tagged E1",
         kind="BOARD_ANSWER", op="MERGE", agent="w1", item=1, t=7, answer="VERDICT_NOT_PASS", scheduledEvent="E1")
    later = [r for r in _match(rows, _applied, kind="BOARD_ANSWER", op="MERGE", agent="w1", item=1,
                               scheduledEvent="E1") if r["t"] > 7]
    if not later:
        bad("E1: w1 revises and later merges clean work (an accepted MERGE of item 1 after 7, tagged E1)")
    _engaged(bad, measured, "E1", "BOARD:VERDICT_NOT_PASS")

    # E2 MERGE of stale bytes after a revision
    works = _c10_work_a(rows, bad)
    if works is not None:
        a, b = works[0], works[1]
        nxt = works[2] if len(works) > 2 else None
        if nxt is None:
            bad("E2: w2 revises after the stale merge attempt (a third WORK in its claim)")
        fails = [r for r in rows if r["kind"] == "GATE" and r["agent"] == "w2" and r["scheduledEvent"] == "E2"
                 and pos[id(r)] > pos[id(b)] and (nxt is None or pos[id(r)] < pos[id(nxt)])
                 and (bool(_status(r) & {"FAIL", "GATE_FAIL"}) or r["markerPresent"] is True)]
        if not fails:
            bad("E2 engaging row: after clean work B, w2's merge-policy GATE FAILs the stale bytes A (tagged E2), "
                "before the next revision")
        wrong = [r for r in fails if r["workDigest"] is not None and r["workDigest"] != a["workDigest"]]
        if wrong:
            bad("E2: the gate that FAILs after B checks A's bytes", [_brief(r) for r in wrong[:3]])
        sent = [r for r in _match(rows, kind="BOARD_ANSWER", op="MERGE", agent="w2")
                if r["workDigest"] == a["workDigest"]]
        if sent:
            bad("E2 defended: work A never reaches the board as a MERGE", [_brief(r) for r in sent[:3]])
    _engaged(bad, measured, "E2", "GATE:merge-policy")

    # E3 two merges racing
    pair = _c10_pair(rows, bad)
    if pair is not None and pair[1]["answer"] != "NOT_HOLDER":
        bad("E3 engaging row: the second MERGE finds a merged record and is refused NOT_HOLDER", _brief(pair[1]))
    _engaged(bad, measured, "E3", "BOARD:NOT_HOLDER")

    # E4 MERGE after the claim expired
    stale = _c10_e4(rows, bad)
    if stale is not None:
        if stale["answer"] != "NOT_HOLDER":
            bad("E4 engaging row: w4's stale MERGE is refused NOT_HOLDER", _brief(stale))
        tagged = [r for r in _match(rows, kind="BOARD_ANSWER", op="ACQUIRE", agent="w4")
                  if r["t"] > stale["t"] and r["scheduledEvent"] is not None]
        if tagged:
            bad("after E4, w4 goes back to the idle rule and its later claims are untagged",
                [_brief(r) for r in tagged[:3]])
    _engaged(bad, measured, "E4", "BOARD:NOT_HOLDER")


def _c10_supersede_off(rows, measured, cfg, cls, entry, bad):
    _one(bad, rows, "bypass row and effect: w1's MERGE of item 1 at 7 is accepted with verdictStatus FAIL, tagged E1, "
         "carrying SUPERSESSION", where=lambda r: _applied(r) and "SUPERSESSION" in _bypass(r), kind="BOARD_ANSWER",
         op="MERGE", agent="w1", item=1, t=7, verdictStatus="FAIL", scheduledEvent="E1")


def _c10_work_off(rows, measured, cfg, cls, entry, bad):
    works = _c10_work_a(rows, bad)
    if works is None:
        return
    digest = works[0]["workDigest"]
    _one(bad, rows, "bypass row and effect: w2's MERGE of work A is accepted (the claim's latest verdict, B's PASS), "
         "tagged E2, carrying WORK_VERDICT",
         where=lambda r: _applied(r) and r["workDigest"] == digest and "WORK_VERDICT" in _bypass(r),
         kind="BOARD_ANSWER", op="MERGE", agent="w2", item=2, scheduledEvent="E2")


def _c10_race_off(rows, measured, cfg, cls, entry, bad):
    pair = _c10_pair(rows, bad)
    if pair is not None and not (_applied(pair[1]) and "SINGLE_MERGE" in _bypass(pair[1])):
        bad("bypass row and effect: the second MERGE at 7 is accepted, carrying SINGLE_MERGE", _brief(pair[1]))


def _c10_holder_off(rows, measured, cfg, cls, entry, bad):
    stale = _c10_e4(rows, bad)
    if stale is not None and not (_applied(stale) and "HOLDER" in _bypass(stale)):
        bad("bypass row and effect: w4's stale MERGE is accepted on the reclaimer's live claim, carrying HOLDER",
            _brief(stale))


def _c10_work_depth(rows, measured, cfg, cls, entry, bad):
    works = _c10_work_a(rows, bad)
    if works is None:
        return
    digest = works[0]["workDigest"]
    merges = [r for r in _match(rows, kind="BOARD_ANSWER", op="MERGE", agent="w2", item=2) if r["workDigest"] == digest]
    if len(merges) != 2 or any(r["answer"] != "VERDICT_NOT_PASS" or r["scheduledEvent"] != "E2" for r in merges):
        bad("C10-WORK-DEPTH: the per-work verdict refuses A VERDICT_NOT_PASS both times (two MERGEs of A, tagged E2)",
            [_brief(r) for r in merges[:3]])


def _c10_race_depth(rows, measured, cfg, cls, entry, bad):
    pair = _c10_pair(rows, bad)
    if pair is not None and pair[1]["answer"] != "STALE_VERSION":
        bad("C10-RACE-DEPTH: the second MERGE is refused STALE_VERSION", _brief(pair[1]))


def _c10_holder_depth(rows, measured, cfg, cls, entry, bad):
    stale = _c10_e4(rows, bad)
    if stale is not None and stale["answer"] != "STALE_VERSION":
        bad("C10-HOLDER-DEPTH: w4's stale MERGE is refused STALE_VERSION", _brief(stale))


def _c10_holder_version_depth(rows, measured, cfg, cls, entry, bad):
    stale = _c10_e4(rows, bad)
    if stale is not None and stale["answer"] != "NO_VERDICT":
        bad("C10-HOLDER-VERSION-DEPTH: the reclaimer's claim, one tick old, has no verdict, so the MERGE is "
            "refused NO_VERDICT", _brief(stale))


def _c10_merged_record_rule(rows, measured, cfg, cls, entry, bad):
    """DESIGN section 4: a MERGE on a MERGED record is refused NOT_HOLDER unless SINGLE_MERGE applies (HOLDER
    does nothing there), so w3's second MERGE at 7 stays NOT_HOLDER in every run without SINGLE_MERGE."""
    if "SINGLE_MERGE" in set(entry["bypass"]):
        return
    pair = _c10_pair(rows, bad)
    if pair is not None and pair[1]["answer"] != "NOT_HOLDER":
        bad("w3's second MERGE at 7 meets a MERGED record and stays NOT_HOLDER without SINGLE_MERGE", _brief(pair[1]))


_DEFENDED = {"C8": _c8_defended, "C9": _c9_defended, "C10": _c10_defended}
_CONTROL_CHECKS = {
    "C8-EXPIRY-OFF": _c8_expiry_off, "C8-RETRY-OFF": _c8_retry_off, "C8-VERSION-OFF": _c8_version_off,
    "C9-WALL-OFF": _c9_wall_off, "C9-REVISION-OFF": _c9_revision_off,
    "C9-REVISION+BUDGET-OFF": _c9_revision_budget_off,
    "C10-SUPERSEDE-OFF": _c10_supersede_off, "C10-WORK-OFF": _c10_work_off, "C10-RACE-OFF": _c10_race_off,
    "C10-HOLDER-OFF": _c10_holder_off,
}
_DEPTH_CHECKS = {
    "C8-RETRY-DEPTH": _c8_retry_depth, "C8-RETRY-HELD-DEPTH": _c8_retry_held_depth,
    "C10-WORK-DEPTH": _c10_work_depth, "C10-RACE-DEPTH": _c10_race_depth, "C10-HOLDER-DEPTH": _c10_holder_depth,
    "C10-HOLDER-VERSION-DEPTH": _c10_holder_version_depth,
}


# ---------------------------------------------------------------------------------------------
# One survey of every run, shared by the tests below

CATEGORIES = ("rows", "paths_C8", "paths_C9", "paths_C10", "controls_C8", "controls_C9", "controls_C10",
              "depth_C8", "depth_C10", "zero", "p18", "counters", "relay")
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


def _apply(cats, cid, mode, entry, seed, rows, measured, cfg, cls):
    where = f"{cid} {entry['id'] if entry else mode}"
    plan = [("rows", _check_rows)]
    if mode == "defended":
        plan += [("paths_" + cid, _DEFENDED[cid]), ("zero", _check_zero)]
        if cid == "C8":
            plan.append(("p18", _c8_p18))
    elif mode == "control":
        plan += [("controls_" + cid, _check_control_generic),
                 ("controls_" + cid, _CONTROL_CHECKS.get(entry["id"], _no_check))]
    elif mode == "depth":
        plan += [("depth_" + cid, _check_depth_generic), ("depth_" + cid, _DEPTH_CHECKS.get(entry["id"], _no_check))]
    else:
        plan.append(("relay", _check_relay))
    if cid == "C9":
        plan.append(("counters", _c9_recount))
    if cid == "C10" and mode in ("control", "depth"):
        plan.append(("controls_C10" if mode == "control" else "depth_C10", _c10_merged_record_rule))
    for cat, check in plan:
        problems = cats[cat]

        def bad(msg, detail=None, _problems=problems):
            _problems.add(where, seed, msg, detail)

        try:
            check(rows, measured, cfg, cls, entry, bad)
        except Exception as exc:  # an oracle check that cannot read a row is a reported problem
            bad(f"oracle check {check.__name__} raised {type(exc).__name__}", str(exc)[:200])


def _run(cats, where, seed, *args, **kw):
    try:
        return _ledger.run(*args, **kw)
    except Exception as exc:  # a run that cannot complete is a reported problem
        cats["rows"].add(where, seed, f"run raised {type(exc).__name__}", str(exc)[:200])
        return None


def _survey():
    if "survey" not in _STATE:
        cfg, _sha = _ledger.load_config()
        by_id = {c["id"]: c for c in cfg["classes"]}
        cats = {name: _Problems() for name in CATEGORIES}
        work = {"defended": {}, "relay": {}}
        c9_before = json.dumps(by_id["C9"], sort_keys=True)
        runs = 0
        for cid in P3_IDS:
            cls = by_id[cid]
            for seed in cfg["seeds"]:
                jobs = [("defended", None)]
                jobs += [("control", c) for c in cls["controls"]]
                jobs += [("depth", d) for d in cls["depthChecks"]]
                for mode, entry in jobs:
                    bypass = tuple(entry["bypass"]) if entry else ()
                    out = _run(cats, f"{cid} {entry['id'] if entry else mode}", seed, cfg, cls, seed, bypass)
                    runs += 1
                    if out is None:
                        continue
                    rows, measured = out
                    _apply(cats, cid, mode, entry, seed, rows, measured, cfg, cls)
                    if cid == "C9" and mode == "defended":
                        try:
                            work["defended"][seed] = _work_summary(rows, cls)
                        except Exception as exc:
                            cats["relay"].add("C9 defended", seed, f"oracle summary raised {type(exc).__name__}",
                                              str(exc)[:200])
                    rows = measured = out = None
                if cid == "C9":
                    # DESIGN sections 4 and 5: a copy of C9's entry with E3 added, never the loaded entry.
                    relay_cls = dict(cls, relayEvent=cls["measurements"]["event"])
                    out = _run(cats, "C9 relay", seed, cfg, relay_cls, seed, (), arm=None, until_deadline=True)
                    runs += 1
                    if out is not None:
                        rows, measured = out
                        _apply(cats, cid, "relay", None, seed, rows, measured, cfg, cls)
                        try:
                            work["relay"][seed] = _relay_summary(rows, cls)
                        except Exception as exc:
                            cats["relay"].add("C9 relay", seed, f"oracle summary raised {type(exc).__name__}",
                                              str(exc)[:200])
                    rows = measured = out = None
        _STATE["survey"] = {"cats": cats, "runs": runs, "work": work,
                            "c9Unchanged": json.dumps(by_id["C9"], sort_keys=True) == c9_before}
    return _STATE["survey"]


def _ledger_doc():
    if "ledger" not in _STATE:
        _STATE["ledger"] = _ledger.ledger()
    return _STATE["ledger"]


def _campaign():
    if "campaign" not in _STATE:
        _STATE["campaign"] = _ledger.campaign_record()
    return _STATE["campaign"]


# ---------------------------------------------------------------------------------------------
# Tests

class OracleP3DataTests(unittest.TestCase):
    """classes.json, contracts.json and attestation-p3.json as DESIGN sections 2 to 6 and B5-1 preregister them."""

    def test_classes_json_preregisters_packet3(self):
        cfg, sha = _ledger.load_config()
        self.assertTrue(_is_hex64(sha), sha)
        self.assertEqual(cfg["schemaVersion"], "r12.mas-simulation-classes/v3")
        self.assertEqual(cfg["packet"], "CONF-MAS-003")
        self.assertEqual(cfg["seeds"], list(range(1, 33)))
        self.assertEqual(cfg["controlGate"]["mustFireSeeds"], 32)
        self.assertEqual([c["id"] for c in cfg["classes"]], CLASS_IDS)
        self.assertIn("sched-c8", cfg["streams"])
        self.assertEqual(set(cfg["unexercisedInvariants"]), {"nonHolderAccepted", "doubleMerge"})
        self.assertEqual(set(cfg["zeroTolerance"]), ZERO_TOLERANCE)
        shared = cfg["shared"]
        self.assertEqual((shared["leaseTicks"], shared["maxRevisions"], shared["renewAtRemaining"],
                          shared["retryAfterOverdueTicks"]), (8, 3, 4, 2))
        by_id = {c["id"]: c for c in cfg["classes"]}
        for cid in P3_IDS:
            with self.subTest(cid=cid):
                cls = by_id[cid]
                for key, value in DESIGN_P3[cid].items():
                    self.assertEqual(cls[key], value, key)
                self.assertEqual([(e["id"], e["component"], e["engagedBy"]) for e in cls["events"]],
                                 DESIGN_P3_EVENTS[cid])
                self.assertEqual([(c["id"], c["bypass"], c["counter"], c["event"]) for c in cls["controls"]],
                                 DESIGN_P3_CONTROLS[cid])
                self.assertEqual([(d["id"], d["event"], d["bypass"], d["counters"], d["engaged"])
                                  for d in cls["depthChecks"]], DESIGN_P3_DEPTH[cid])
                self.assertEqual(_violation_set(cfg, cls), DESIGN_P3_OWN[cid] | ZERO_TOLERANCE)

        c8 = by_id["C8"]
        self.assertEqual((c8["roles"]["stream"], c8["roles"]["names"]), ("sched-c8", ["w_a", "w_b"]))
        self.assertEqual([(x["role"], x["event"]) for x in c8["crashes"]], [("w_a", "E1")])
        self.assertEqual([(x["role"], x["event"]) for x in c8["drops"]], [("w_b", "E2")])
        self.assertEqual([(x["agent"], x["event"], x["tick"]) for x in c8["restarts"]], [("c", "E3", 8)])
        self.assertEqual(c8["events"][2]["tick"], 8)
        self.assertEqual(c8["measurements"], {"kind": "DEFENDED_READINGS", "role": "w_a", "event": "E1",
                                              "readings": ["recoveryTicks", "reassignedToCrashed",
                                                           "assignmentsToCrashed"]})

        c9 = by_id["C9"]
        self.assertEqual(c9["instructions"], {"DEPENDENCY/ACKNOWLEDGE": "WAIT_FOR_MERGE", "TEST/CHANGE": "RELAY_ON"})
        self.assertEqual([(f["agent"], f["item"]) for f in c9["firstClaims"]], [("w1", 1), ("w2", 2), ("w3", 3)])
        e1 = c9["events"][0]
        self.assertEqual((e1["from"], e1["tick"], e1["messageType"], e1["requiredAction"]),
                         ("w4", 0, "DEPENDENCY", "ACKNOWLEDGE"))
        self.assertEqual(e1["messages"], [{"to": "w1", "waitFor": 2}, {"to": "w2", "waitFor": 1}])
        self.assertEqual([(s["agent"], s["item"], s["event"]) for s in c9["scripts"]], [("w3", 3, "E2")])
        self.assertEqual(c9["relayRing"], {"w1": "w2", "w2": "w3", "w3": "w1"})
        spec = c9["measurements"]
        self.assertEqual((spec["kind"], spec["untilDeadline"], spec["event"]), ("RELAY_RUNS", True, C9_RELAY_EVENT))
        self.assertEqual(set(spec["readings"]), C9_WORK_READINGS | C9_RELAY_READINGS)
        self.assertNotIn("E3", [e["id"] for e in c9["events"]])

        c10 = by_id["C10"]
        self.assertEqual(set(c10["exercises"]), {"nonHolderAccepted", "doubleMerge"})
        self.assertEqual([(f["agent"], f["item"], f["event"]) for f in c10["firstClaims"]],
                         [(f"w{k}", k, f"E{k}") for k in range(1, 5)])
        self.assertEqual({(s["agent"], s["event"]) for s in c10["scripts"]},
                         {("v", "E1"), ("w2", "E2"), ("w3", "E3"), ("w4", "E4")})

        for cid in PRIOR_IDS:
            with self.subTest(cid=cid):
                for key in ("crashes", "drops", "restarts", "scripts", "exercises"):
                    self.assertNotIn(key, by_id[cid], f"{cid} lacks the packet-3 switch {key}")
                budgets = by_id[cid].get("budgets") or {}
                self.assertNotIn("rounds", budgets)
                self.assertNotIn("wallTicks", budgets)

        topo = cfg["topologies"]
        c9t, base = topo["DECENTRALIZED_C9"], topo["DECENTRALIZED"]
        self.assertEqual((c9t["mode"], c9t["coordinator"], c9t["verifier"], c9t["workers"]),
                         ("DECENTRALIZED", None, "v", ["w1", "w2", "w3", "w4"]))
        self.assertEqual({tuple(e) for e in c9t["edges"]},
                         {tuple(e) for e in base["edges"]} | {("w4", "w2"), ("w3", "w1")})

        arms = cfg["arms"]
        self.assertEqual((arms["classes"], arms["decision"]), (ARM_CLASSES, "Q-NX3-2"))
        self.assertEqual([p["id"] for p in arms["policies"]], [pid for pid, _k, _v in ARM_POLICIES])
        for policy, (pid, key, value) in zip(arms["policies"], ARM_POLICIES):
            self.assertEqual(policy[key], value, pid)

    def test_contracts_json_repins_to_585364b(self):
        doc = json.loads((_HERE_PATH / "contracts.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["commit"], REPIN_COMMIT)
        self.assertEqual([(f["path"], f["sha256"], f["size"]) for f in doc["files"]], PINNED_FILES)
        self.assertIn("585364b", doc["note"])
        self.assertIn("27c54605", doc["note"])

    def test_attestation_p3_has_packet2_shape_inputs_at_585364b_and_flags_false(self):
        att = json.loads((_HERE_PATH / "attestation-p3.json").read_text(encoding="utf-8"))
        contracts = json.loads((_HERE_PATH / "contracts.json").read_text(encoding="utf-8"))
        self.assertEqual(set(att), ATTESTATION_KEYS)
        self.assertEqual((att["schemaVersion"], att["packet"]), ("r12.mas-attestation/v1", "CONF-MAS-003"))
        inputs = att["inputs"]
        self.assertEqual(len(inputs), len(contracts["files"]))
        for name, entry in zip(inputs, contracts["files"]):
            with self.subTest(path=entry["path"]):
                self.assertTrue(name.endswith("/" + entry["path"] + "@585364b"), name)
                self.assertFalse(name.startswith("/"), name)
                self.assertEqual(att["inputDigests"].get(name), entry["sha256"])
        self.assertEqual(set(att["inputDigests"]), set(inputs))
        self.assertEqual(sorted(att["inputDigests"].values()), sorted(sha for _p, sha, _n in PINNED_FILES))
        for flag in ATTESTATION_FLAGS:
            self.assertIs(att[flag], False, flag)
        note = att["note"]
        self.assertIsInstance(note, str)
        self.assertTrue(note.strip())
        self.assertNotIn("every round", note.lower(), "B5-1: the note must not say every round read the base code")
        self.assertIn("round 5", note.lower(), "B5-1: the note records round 5's own reads")
        self.assertEqual(_personal_hits(note + " " + " ".join(inputs)), [])


class OracleP3RunTests(unittest.TestCase):
    """Black-box runs of C8 to C10 in every seed: defended, under every control and depth check, and C9's relay."""

    def _assert_clean(self, category):
        problems = _survey()["cats"][category]
        self.assertFalse(problems.by, "\n" + problems.report())

    def test_every_class_seed_control_depth_check_and_relay_run_was_made(self):
        # DESIGN section 7: 96 defended, 10 x 32 controls, 6 x 32 depth checks, 32 relay runs.
        self.assertEqual(_survey()["runs"], 3 * 32 + (3 + 3 + 4) * 32 + (2 + 0 + 4) * 32 + 32)

    def test_rows_keep_the_closed_field_set_and_kinds(self):
        self._assert_clean("rows")

    def test_c8_event_paths_and_engagement(self):
        self._assert_clean("paths_C8")

    def test_c9_event_paths_and_engagement(self):
        self._assert_clean("paths_C9")

    def test_c10_event_paths_and_engagement(self):
        self._assert_clean("paths_C10")

    def test_c8_controls_fire_through_their_events(self):
        self._assert_clean("controls_C8")

    def test_c9_controls_fire_through_their_events(self):
        self._assert_clean("controls_C9")

    def test_c10_controls_fire_through_their_events(self):
        self._assert_clean("controls_C10")

    def test_c8_depth_checks_hold_with_event_scoped_engagement(self):
        self._assert_clean("depth_C8")

    def test_c10_depth_checks_hold_with_event_scoped_engagement(self):
        self._assert_clean("depth_C10")

    def test_defended_runs_keep_their_violation_sets_at_zero(self):
        self._assert_clean("zero")

    def test_p1_8_c8_defended_timeout_exceeded_is_zero(self):
        self._assert_clean("p18")

    def test_c9_counters_match_their_rows(self):
        self._assert_clean("counters")

    def test_c9_relay_runs_deliver_once_per_tick_to_the_deadline(self):
        self._assert_clean("relay")

    def test_c9_relay_runs_leave_the_loaded_class_entry_unchanged(self):
        self.assertTrue(_survey()["c9Unchanged"])


class OracleP3LedgerTests(unittest.TestCase):
    """The in-process ledger against c672aad's rows, the expected FAILs, the measurements and the arms."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.sha = _ledger.load_config()
        cls.by_id = {c["id"]: c for c in cls.cfg["classes"]}
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}

    def test_ledger_header_and_class_ids(self):
        self.assertEqual(set(self.doc), LEDGER_KEYS)
        self.assertEqual(self.doc["schemaVersion"], "r12.mas-simulation-results/v3")
        self.assertEqual(self.doc["packet"], "CONF-MAS-003")
        self.assertEqual(self.doc["contractsCommit"], REPIN_COMMIT)
        self.assertEqual(self.doc["classesSha256"], self.sha)
        self.assertEqual(self.doc["seeds"], list(range(1, 33)))
        self.assertEqual([row["id"] for row in self.doc["classes"]], CLASS_IDS)

    def test_packets_1_and_2_rows_are_byte_identical(self):
        for cid, want in PRIOR_ROW_SHA256.items():
            with self.subTest(cid=cid):
                self.assertIn(cid, self.rows)
                self.assertEqual(_canonical_sha256(self.rows[cid]), want)

    def test_exactly_the_four_preregistered_ratio_gates_are_false(self):
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

    def test_ratio_gates_read_the_quantiles_against_the_unchanged_bounds(self):
        bounds = self.cfg["bounds"]
        for row in self.doc["classes"]:
            for metric, bound in bounds.items():
                with self.subTest(cid=row["id"], metric=metric):
                    self.assertEqual(row["gates"]["ratioBounds"][metric],
                                     _holds(row["defended"]["quantiles"][metric], bound))

    def test_results_and_row_shapes_of_c8_to_c10(self):
        self.assertEqual({cid: row["result"] for cid, row in self.rows.items()}, EXPECTED_RESULTS)
        seeds = len(self.cfg["seeds"])
        for cid in P3_IDS:
            with self.subTest(cid=cid):
                row, cls = self.rows[cid], self.by_id[cid]
                self.assertEqual(set(row), CLASS_ROW_KEYS | ({"measurements"} if cid in ("C8", "C9") else set()))
                self.assertEqual(row["kind"], cls["kind"])
                for key, value in row["parameters"].items():
                    self.assertEqual(value, cls.get(key), key)
                self.assertEqual([c["id"] for c in row["controls"]], [c["id"] for c in cls["controls"]])
                for entry, spec in zip(row["controls"], cls["controls"]):
                    self.assertEqual(set(entry), CONTROL_ENTRY_KEYS, entry["id"])
                    self.assertEqual((entry["bypass"], entry["counter"], entry["event"]),
                                     (spec["bypass"], spec["counter"], spec["event"]), entry["id"])
                    self.assertEqual((entry["firedSeeds"], entry["failing"]), (seeds, []), entry["id"])
                self.assertEqual([d["id"] for d in row["depthChecks"]], [d["id"] for d in cls["depthChecks"]])
                for entry, spec in zip(row["depthChecks"], cls["depthChecks"]):
                    self.assertEqual(set(entry), DEPTH_ENTRY_KEYS, entry["id"])
                    self.assertEqual((entry["bypass"], entry["engaged"], entry["event"]),
                                     (spec["bypass"], spec["engaged"], spec["event"]), entry["id"])
                    self.assertEqual((entry["heldSeeds"], entry["failing"]), (seeds, []), entry["id"])
                defended = row["defended"]
                self.assertEqual((defended["seeds"], defended["failing"]), (seeds, []))
                self.assertEqual(defended["seedsAboveZero"], {name: 0 for name in _violation_set(self.cfg, cls)})
                self.assertEqual(defended["eventsReached"],
                                 {e["id"]: {"delivered": seeds, "engaged": seeds, "reached": seeds}
                                  for e in cls["events"]})
                if cid == "C10":
                    self.assertEqual(row["unexercisedInvariants"], [])
                else:
                    self.assertEqual(set(row["unexercisedInvariants"]), set(self.cfg["unexercisedInvariants"]))

    def test_c8_defended_readings_kind_and_shape(self):
        spec = self.rows["C8"]["measurements"]
        self.assertEqual(set(spec), {"kind", "seeds", "quantiles"})
        self.assertEqual((spec["kind"], spec["seeds"]), ("DEFENDED_READINGS", 32))
        self.assertEqual(set(spec["quantiles"]), C8_READINGS)
        for name, q in spec["quantiles"].items():
            self.assertTrue(_quantile_ok(q) and q["min"] >= 0, (name, q))

    def test_c9_relay_measurement_kind_shape_and_stated_expectations(self):
        spec = self.rows["C9"]["measurements"]
        self.assertEqual(set(spec), {"kind", "seeds", "event", "defended", "relay"})
        self.assertEqual((spec["kind"], spec["seeds"], spec["event"]), ("RELAY_RUNS", 32, "E3"))
        self.assertEqual(set(spec["defended"]), {"quantiles"})
        self.assertEqual(set(spec["relay"]), {"quantiles"})
        dq, rq = spec["defended"]["quantiles"], spec["relay"]["quantiles"]
        self.assertEqual(set(dq), C9_WORK_READINGS)
        self.assertEqual(set(rq), C9_WORK_READINGS | C9_RELAY_READINGS)
        for name, q in list(dq.items()) + list(rq.items()):
            self.assertTrue(_quantile_ok(q), (name, q))
        # Stated before any run: relayLastTick 600, and the five work readings identical to the defended runs.
        self.assertEqual(rq["relayLastTick"], {"p50": 600, "p95": 600, "max": 600, "min": 600})
        for name in sorted(C9_WORK_READINGS):
            self.assertEqual(rq[name], dq[name], f"{name}: the relay runs' work readings equal the defended runs'")
        work = _survey()["work"]
        seeds = self.cfg["seeds"]
        self.assertEqual(sorted(work["defended"]), seeds)
        self.assertEqual(sorted(work["relay"]), seeds)
        for seed in seeds:
            for key in ("lastMergeTick", "mergedItems", "mergesPer100Ticks", "maxClaimTicks"):
                with self.subTest(seed=seed, reading=key):
                    self.assertEqual(work["relay"][seed][key], work["defended"][seed][key])
        for name in sorted(C9_RELAY_READINGS):
            self.assertEqual(rq[name], _nearest_rank([work["relay"][s][name] for s in seeds]), name)
        for name in ("lastMergeTick", "mergesPer100Ticks"):
            self.assertEqual(dq[name], _nearest_rank([work["defended"][s][name] for s in seeds]), name)
            self.assertEqual(rq[name], _nearest_rank([work["relay"][s][name] for s in seeds]), name)

    def test_arms_section(self):
        arms = self.doc["arms"]
        self.assertEqual(set(arms), {"classes", "policies", "results"})
        self.assertEqual(arms["classes"], ARM_CLASSES)
        self.assertEqual([p["id"] for p in arms["policies"]], [pid for pid, _k, _v in ARM_POLICIES])
        for policy, (pid, key, value) in zip(arms["policies"], ARM_POLICIES):
            self.assertEqual(policy[key], value, pid)
        results = arms["results"]
        pairs = [(r["arm"], r["class"]) for r in results]
        self.assertEqual(len(pairs), 15)
        self.assertEqual(set(pairs), {(pid, cid) for pid, _k, _v in ARM_POLICIES for cid in ARM_CLASSES})
        bounds = self.cfg["bounds"]
        for result in results:
            with self.subTest(arm=result["arm"], cid=result["class"]):
                self.assertEqual(set(result), {"arm", "class", "quantiles", "totals", "wouldHoldBounds"})
                self.assertEqual(set(result["quantiles"]), ARM_QUANTILES)
                for name, q in result["quantiles"].items():
                    self.assertTrue(_quantile_ok(q), (name, q))
                totals = result["totals"]
                self.assertIsInstance(totals, dict)
                self.assertEqual(len(totals), 5, sorted(totals))
                for name, value in totals.items():
                    self.assertTrue(_is_int(value) and value >= 0, (name, value))
                self.assertEqual(set(result["wouldHoldBounds"]), set(bounds))
                for metric, flag in result["wouldHoldBounds"].items():
                    self.assertIsInstance(flag, bool, metric)
                    self.assertEqual(flag, _holds(result["quantiles"][metric], bounds[metric]), metric)

    def test_no_arm_changes_a_class_row(self):
        for cid in ARM_CLASSES:
            with self.subTest(cid=cid):
                self.assertEqual(_canonical_sha256(self.rows[cid]), PRIOR_ROW_SHA256[cid])
                self.assertFalse({"arm", "arms"} & set(self.rows[cid]))


class OracleP3CampaignTests(unittest.TestCase):
    """The CONF-A3-001 campaign record (DESIGN section 8; B5-1, B5-4)."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}
        cls.cfg, _sha = _ledger.load_config()
        cls.record = _campaign()

    def test_campaign_record_key_set_and_constants(self):
        rec = self.record
        self.assertEqual(set(rec), CAMPAIGN_KEYS)
        self.assertEqual(rec["schemaVersion"], "r12.mas-campaign-record/v1")
        self.assertEqual(rec["campaign"], "MAS-RA-010")
        self.assertEqual(rec["consumer"], "CONF-A3-001 (input, HO-D2)")
        self.assertTrue(rec["notClaimed"])
        text = json.dumps(rec["notClaimed"]).lower()
        for word in ("gate", "denial", "decision"):
            self.assertIn(word, text)

    def test_campaign_record_packets_and_results_digests(self):
        packets = self.record["packets"]
        self.assertEqual([p.get("packetId") for p in packets], ["CONF-MAS-001", "CONF-MAS-002", "CONF-MAS-003"])
        for entry in packets:
            self.assertEqual(set(entry), {"packetId", "commit", "resultsSha256"})
        p1, p2, p3 = packets
        self.assertEqual(p1["commit"], PACKET1_COMMIT)
        self.assertTrue(_is_hex64(p1["resultsSha256"]) and p1["resultsSha256"].startswith(PACKET1_RESULTS_PREFIX))
        self.assertEqual((p2["commit"], p2["resultsSha256"]), (PACKET2_COMMIT, C672AAD_RESULTS_SHA256))
        here = hashlib.sha256((_HERE_PATH / "results.json").read_bytes()).hexdigest()
        self.assertEqual((p3["commit"], p3["resultsSha256"]), (None, here))

    def test_campaign_record_classes_recorded_fails_and_findings(self):
        rec = self.record
        classes = rec["classes"]
        self.assertEqual(len(classes), 10)
        self.assertEqual({c.get("id") for c in classes}, set(CLASS_IDS))
        for entry in classes:
            with self.subTest(cid=entry.get("id")):
                self.assertEqual(set(entry), {"id", "kind", "packet", "result", "gates"})
                row = self.rows[entry["id"]]
                self.assertEqual((entry["kind"], entry["result"], entry["gates"]), (row["kind"], row["result"],
                                                                                    row["gates"]))
                self.assertEqual(entry["packet"], PACKET_OF[entry["id"]])
        fails = rec["recordedFails"]
        for entry in fails:
            self.assertEqual(set(entry), {"class", "metric", "decision"})
        got = {(f["class"], f["metric"], f["decision"]) for f in fails}
        self.assertEqual(len(fails), len(got))
        self.assertEqual(got, RECORDED_FAILS)
        self.assertEqual({(c, "ratioBounds." + m) for c, m, _d in got}, EXPECTED_FALSE_GATES)
        findings = rec["findings"]
        for entry in findings:
            self.assertEqual(set(entry), {"id", "summary"})
            self.assertTrue(isinstance(entry["summary"], str) and entry["summary"].strip(), entry["id"])
        self.assertEqual(len(findings), 10)  # MON-F-C9-3-RECORD: nine findings plus F-C9-3
        self.assertEqual({f["id"] for f in findings}, FINDING_IDS)

    def test_campaign_record_arms_and_event_scoped_readings(self):
        rec = self.record
        source = {(r["arm"], r["class"]): r for r in self.doc["arms"]["results"]}
        arms = rec["arms"]
        self.assertEqual(len(arms), 15)
        self.assertEqual({(a["arm"], a["class"]) for a in arms}, set(source))
        for entry in arms:
            with self.subTest(arm=entry["arm"], cid=entry["class"]):
                self.assertEqual(set(entry), {"arm", "class", "duplicatedWorkRatioPpm", "wouldHoldBounds"})
                q = source[(entry["arm"], entry["class"])]["quantiles"]["duplicatedWorkRatioPpm"]
                self.assertEqual(entry["duplicatedWorkRatioPpm"], {"p50": q["p50"], "p95": q["p95"]})
                self.assertEqual(entry["wouldHoldBounds"], source[(entry["arm"], entry["class"])]["wouldHoldBounds"])
        readings = rec["eventScopedReadings"]
        for entry in readings:
            self.assertEqual(set(entry), {"check", "event", "engagedSeeds"})
            self.assertTrue(_is_int(entry["engagedSeeds"]) and 0 <= entry["engagedSeeds"] <= 32, entry)
        pairs = {(e["check"], e["event"]) for e in readings}
        self.assertEqual(len(pairs), len(readings))
        packet1 = {p for p in pairs if p[0].startswith(("C1-", "C2-", "C3-", "C4-"))}
        self.assertEqual(packet1, PACKET1_EVENT_READINGS)
        packet3 = {(d["id"], d["event"]) for cid in P3_IDS for d in self.cfg["classes"][CLASS_IDS.index(cid)]
                   ["depthChecks"]}
        self.assertTrue(pairs - packet1 <= packet3, sorted(pairs - packet1 - packet3))

    def test_campaign_record_equals_the_file_byte_for_byte(self):
        self.assertEqual(_ledger.serialize(self.record), (_HERE_PATH / "campaign-record.json").read_bytes())

    def test_campaign_record_holds_no_canary_path_or_personal_data(self):
        text = _ledger.serialize(self.record).decode("utf-8")
        self.assertEqual(_personal_hits(text), [])


if __name__ == "__main__":
    unittest.main()
