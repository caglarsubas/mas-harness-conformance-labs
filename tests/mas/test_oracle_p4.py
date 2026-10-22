"""Oracle tests for CONF-MAS-004, written outside the candidate (owner decision D5a).

These tests are black-box. They call only the interface the oracle brief names: ``_ledger.load_config()``,
``_ledger.run(config, cls, seed, bypass, arm, until_deadline, *, labels, scriptedEvents, policy)``,
``_ledger.ledger()``, ``_ledger.SCALING_READINGS``, ``_ledger.campaign_record()``, ``_ledger.serialize()`` and
``_sim.Streams(seed)``. Every expectation comes from DESIGN revision 5 (sections 2, 4 to 6 and 8 to 10), BUILD_NOTES'
binding rules B5-1 to B5-5 and its build-time additions, the candidate's declarative data files (classes.json,
contracts.json, attestation-p3.json, attestation-p4.json), and packet 3's ledger and campaign record as committed at
0a479a55 (the digests below). None is a snapshot of the candidate's output.

Each simulation run is made once and checked at once, so memory stays flat: C11 and C12 in every seed, defended,
under each of their 5 controls and 4 depth checks (352 runs); one defended run of each of C1 to C10; 4 seeds of each
of the 15 scaling and baseline points and of the sensitivity control (64 runs); and the G4 bed under both policies and
both labels in every seed (128 runs). Then one in-process ledger and one campaign record.
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
import _sim  # noqa: E402  (only Streams, the counter-based draws)


# ---------------------------------------------------------------------------------------------
# Constants from packet 3's committed ledger and campaign record at 0a479a55 (tree c80b4d67)

# sha256 of each ledger row and of the arms section as canonical JSON (sorted keys, separators "," and ":",
# ASCII), computed from 0a479a55's tests/mas/results.json. C1 to C7 equal packet 3's oracle's digests.
PRIOR_ROW_SHA256 = {
    "C1": "b3ae188401761d30a75902c2c88fcf2924e6411ea8227c570242d4eb02642ce4",
    "C2": "aa6dc7c60a0e51f2e9e8dd3099b0d35dc9231195e8bd3fd1b65f79880c4e4565",
    "C3": "74a874d78e0c03186381e78766faf3912ce019622202e6532461b31ebdbd66d4",
    "C4": "ab21c9bb5d0692da48a6ec2d3f22c7070b0e1b81dce130c4b5a05eae3b7ec619",
    "C5": "2ee5ad5d482b77fee15925dda13763815bf4c57d91fcae530794e66d28189e10",
    "C6": "5a1988368aa2d212153ad7fc44f4427c8f70a447dfc715fd3e24126a84ea2ef3",
    "C7": "4439b7cd2675ee00a00ae406c559540029e93d894f455cae4b00b8aa2a491713",
    "C8": "92b999f15ddfdce224fd9f19a08e9eed9be3fa6dceb9ef83d3ced265d02e7ac3",
    "C9": "45fc3528881275d75974aad8adbcf2428d8197405163578bb180413c603a3832",
    "C10": "317d58dd0196053e36c2ffce47e5863f68c4b8b957ccd895db4950d808604df6",
}
PRIOR_ARMS_SHA256 = "fa1e7481fd20fb73fccc68950a822895c83192d295a7f6caa35e4095bbdd54f6"
# sha256 of 0a479a55's results.json as committed (DESIGN section 8: 18931185...).
P3_RESULTS_SHA256 = "1893118540358ccd0db0d3ad4009af97041560c2f210773cbc0805231cc40f87"
# Packet 3's ledger rule text (1211 ASCII characters) and profile, from the same file.
P3_RULE_LEN = 1211
P3_RULE_SHA256 = "6e3afcdaa2a5545539a99d0edf05170d9c32b24544d89c1d8f03b7703f2dc1f0"
P3_PROFILE = "python-conformance-stdlib (Python 3.12, standard library only)"
# DESIGN section 8: the sentence appended to packet 3's rule.
P4_RULE_SENTENCE = ("CONF-MAS-004: C11 and C12 are gated like every class; the scaling section gates safety only and "
                    "reports its readings and the baseline comparison; the hard-coding section gates its four results.")

# Canonical sha256 of each list of 0a479a55's campaign-record.json (v1), and its length.
V1_RECORD = {
    "packets": ("c46572335b464faa4fd16622649f9a3bd85aa17824d041d034e0dae2c3133b3f", 3),
    "classes": ("a7fd47749b52f153d91754ea759869726ce25db02372615c6c6d472b3b7b6c28", 10),
    "findings": ("343022e5024c53ccbbe0ebcf903b9beb9616ea335a2f9a95e5297246f0226351", 10),
    "notClaimed": ("cd2ba8a57d71c35ae085192cdda6e0c58479226326ac6b8700538762fe6edef8", 3),
    "recordedFails": ("2e9a79477b25cfeedc5ba388ca3608861d2fb41c6f212e17fda1daa0d8ba76c1", 4),
    "arms": ("2cd4fb1aef4a97141ec381244f366fa95b664a6bf6912f2319a38283c57a15bd", 15),
    "eventScopedReadings": ("88ff1143a4a84cb990da70d5b623bb99a9b5dc4a6de2a5a82813738f841a2617", 4),
}
V1_CAMPAIGN_KEYS = {"schemaVersion", "campaign", "consumer", "packets", "classes", "recordedFails", "findings",
                    "arms", "eventScopedReadings", "notClaimed"}
REPIN_COMMIT = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"

# DESIGN section 2's pin set: packet 3's ten rows, then the eleventh.
PINNED_FILES = [
    ("MET-MAS-004", "architecture/topology-coordination/README.md",
     "890af54aa39c6fbec35615bec8cadb5ffa62c33a5ccce0e21b7af5fcd3fb9c90", 28108),
    ("MET-MAS-004", "architecture/topology-coordination/board-transcript.schema.json",
     "8a3cc5b87953e97a4b42362df382f9b101931be1d55de84f441b16020b405b7c", 13998),
    ("MET-MAS-004", "architecture/topology-coordination/topology-spec.schema.json",
     "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0", 4485),
    ("MET-MAS-006", "architecture/agent-loop/README.md",
     "666c4221d3edbdd5187c17db9c43c122b1f7900a9fa0b3ddc430db3bee2b8e5a", 28107),
    ("MET-MAS-006", "architecture/agent-loop/loop-profile.schema.json",
     "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb", 6648),
    ("MET-MAS-006", "architecture/agent-loop/loop-trace.schema.json",
     "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e", 15434),
    ("MET-MAS-002", "architecture/run-manifest/README.md",
     "279d374e5ddd1b6305611f3565a7af14046b305e59cf9634a88bd358818ce826", 17769),
    ("MET-MAS-002", "architecture/run-manifest/distribution-gate.schema.json",
     "f521fc6691984959473ef4f184e863193c060acc0b2ed1012dcf1d2c9d3a1683", 2816),
    ("MET-MAS-001", "architecture/verdict-ledger/README.md",
     "dde6efc45fc2e1ad675635d0a18a1d6a82b49c960616af239f47071e2914e3f7", 22616),
    ("MET-MAS-001", "architecture/verdict-ledger/ledger.schema.json",
     "8a570cfb26b16fb3f7fa1cf799bd564fe717fd3d356dbca890dab747b2dc9326", 8391),
    ("MET-MAS-001", "architecture/verdict-ledger/check-kinds.json",
     "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac", 3173),
]

# ---------------------------------------------------------------------------------------------
# Constants from DESIGN revision 5

CLASS_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"]
PRIOR_IDS = CLASS_IDS[:10]
NEW_IDS = ("C11", "C12")

ROW_FIELDS = [
    "t", "kind", "agent", "from", "to", "item", "op", "opId", "retryOf", "claimOpId", "expectedVersion",
    "recordVersionBefore", "answer", "changed", "component", "toolId", "verdictStatus", "workDigest",
    "markerPresent", "canaryHits", "scheduledEvent", "controlBypass", "leaseUntil", "grantId", "grantToolId",
    "grantManifestDigest", "grantScope", "grantExpiresAt", "inputKeys", "attempt", "iteration", "objectiveId",
    "heldBefore", "bodyKeys", "verdictChecks", "taskPass",
]
ROW_KINDS = frozenset((
    "BOARD_ANSWER", "EXPIRY", "DELIVERY", "OBSERVE", "TOOL_CALL", "GATE", "VERDICT", "SINK", "WORK",
    "ADMISSION", "KERNEL", "PLAN", "FAULT",
))

LEDGER_KEYS = {"arms", "classes", "classesSha256", "contractsCommit", "packet", "profile", "rule",
               "schemaVersion", "seeds", "hardCoding", "scaling"}
GATE_KEYS = {"defendedZeroAndEvents", "ratioBounds", "controlsFireInAllSeeds", "depthChecksHoldInAllSeeds"}
CLASS_ROW_KEYS = {"controls", "defended", "depthChecks", "gates", "id", "kind", "parameters", "result",
                  "unexercisedInvariants"}
PARAMETER_KEYS = {"compromised", "deadline", "maxLatency", "poisonPpm", "stallPpm", "topology"}
CONTROL_ENTRY_KEYS = {"id", "bypass", "counter", "event", "firedSeeds", "failing"}
DEPTH_ENTRY_KEYS = {"id", "bypass", "engaged", "event", "failing", "heldSeeds"}
QUANTILE_KEYS = {"p50", "p95", "max", "min"}
# Section 7 (packets 1 to 3) and section 9: exactly these four gates are false; C11 and C12 pass every gate.
EXPECTED_FALSE_GATES = {(c, "ratioBounds.duplicatedWorkRatioPpm") for c in ("C2", "C5", "C7", "C9")}
ZERO_TOLERANCE = ["leakedSecrets", "doubleMerge", "nonHolderAccepted", "unexplainedDuplicate", "unclaimedWork"]

# Section 4.5: the restated registry subset.
EVIDENCE_RULE = {"deterministicChecks": ["DETERMINISTIC_POLICY", "DETERMINISTIC_SCHEMA", "DETERMINISTIC_TEST"],
                 "consistencyOnly": ["REGRESSION_RUN"], "source": "architecture/verdict-ledger/check-kinds.json"}
TEST_RESULT_CHECKS = ["DETERMINISTIC_TEST/TEST_RESULT"]

# Section 5: the two classes.
COMMON = {"topology": "DECENTRALIZED", "maxLatency": 0, "poisonPpm": 0, "stallPpm": 0, "deadline": 400,
          "compromised": None}
C11_HOLDERS = (("w1", 1, "E1", ["DETERMINISTIC_TEST/REGRESSION_RUN"]),
               ("w2", 2, "E2", ["DETERMINISTIC_TEST/REGRESSION_RUN", "MODEL_BASED_WITH_EVIDENCE/DIFF"]))
C11_SCRIPTS = [{"script": "REGRESSION_ONLY_VERDICT", "agent": "v", "holders": {
    "w1": {"event": "E1", "checks": ["DETERMINISTIC_TEST/REGRESSION_RUN"]},
    "w2": {"event": "E2", "checks": ["DETERMINISTIC_TEST/REGRESSION_RUN", "MODEL_BASED_WITH_EVIDENCE/DIFF"]}}}]
C11_EVENTS = [("E1", "BOARD", "CONSISTENCY_ONLY", "w1", 1, "REGRESSION_ONLY_VERDICT"),
              ("E2", "BOARD", "CONSISTENCY_ONLY", "w2", 2, "REGRESSION_AND_DIFF_VERDICT")]
C11_CONTROLS = [("C11-REGRESSION-OFF", ["EVIDENCE_KIND"], "regressionOnlyMerged", "E1"),
                ("C11-DIFF-OFF", ["EVIDENCE_KIND"], "regressionOnlyMerged", "E2")]
C12_FORMS = (("w1", 1, "E1", "EMPTY"), ("w2", 2, "E2", "CONSTANT"), ("w3", 3, "E3", "COPY"))
C12_FORM_OF = {event: (agent, item, form) for agent, item, event, form in C12_FORMS}
C12_SCRIPTS = [{"script": "DEGENERATE_WORK", "forms": {
    "w1": {"event": "E1", "form": "EMPTY"}, "w2": {"event": "E2", "form": "CONSTANT"},
    "w3": {"event": "E3", "form": "COPY"}}}]
C12_EVENTS = [("E1", "GATE", "GATE_FAIL", "w1", 1, "EMPTY_SUBMISSION"),
              ("E2", "GATE", "GATE_FAIL", "w2", 2, "CONSTANT_SUBMISSION"),
              ("E3", "GATE", "GATE_FAIL", "w3", 3, "COPY_SUBMISSION")]
C12_CONTROLS = [("C12-EMPTY-OFF", ["JUDGE_BY_STATUS", "MERGE_GATE"], "degenerateMerged", "E1"),
                ("C12-CONSTANT-OFF", ["JUDGE_BY_STATUS"], "degenerateMerged", "E2"),
                ("C12-COPY-OFF", ["JUDGE_BY_STATUS", "MERGE_GATE"], "degenerateMerged", "E3")]
C12_DEPTH = [("C12-EMPTY-DEPTH", "E1", ["JUDGE_BY_STATUS"], ["degenerateMerged"], "GATE:merge-policy"),
             ("C12-EMPTY-GATE-DEPTH", "E1", ["MERGE_GATE"], ["degenerateMerged"], "BOARD:VERDICT_NOT_PASS"),
             ("C12-COPY-DEPTH", "E3", ["JUDGE_BY_STATUS"], ["degenerateMerged"], "GATE:merge-policy"),
             ("C12-COPY-GATE-DEPTH", "E3", ["MERGE_GATE"], ["degenerateMerged"], "BOARD:VERDICT_NOT_PASS")]
# Keys that switch packet 4's rules on; C1 to C10 carry none of them (section 1).
P4_SWITCHES = ("evidenceRule", "tasks", "selfReport", "degenerateCheck", "isolateEvents", "load", "claimAwareWorker")

# Section 6.1.
WORKERS = [1, 2, 4, 8, 16]
BASELINE_ITEMS = [5, 10, 20, 40, 80]
SAFETY_COUNTERS = ZERO_TOLERANCE + ["mergeWithoutPass", "poisonMerged", "staleAccepted", "opIdAppliedTwice",
                                    "retryChangedState", "claimOverlap", "selfVerified", "offEdgeDelivered",
                                    "unlistedLaunched", "heldBeyondConcurrency"]
SCALING_READINGS = ("completionPpm", "lostWorkPpm", "duplicatedWorkRatioPpm", "lastMergeTick", "mergesPer100Ticks",
                    "contentionPerItemMilli", "messagesPerItemMilli")
SCALING_DECISIONS = ["Q-RA10F-2", "Q-RA10F-3", "Q-RA10F-4", "MON-P4-DR1-NOTED", "MON-P4-D16", "Q-P4-D2-1",
                     "Q-P4-D3-1", "Q-P4-D4-3"]
CONTENTION_ANSWERS = ("HELD", "STALE_VERSION", "CONCURRENCY_LIMIT")
SCALING_KEYS = {"decisions", "parameters", "safetyCounters", "points", "baseline", "againstBaseline", "controls",
                "gates", "result"}
POINT_KEYS = {"id", "family", "workers", "topology", "items", "concurrency", "deadline", "safety", "finishedSeeds",
              "readings"}
# The survey bound (oracle brief): at most 4 seeds of each scaling point, baseline point and the control.
SURVEY_SEEDS = (1, 12, 23, 32)

# Section 6.2.
HC_KEYS = {"decision", "bed", "policies", "permutationNotIdentitySeeds", "gates", "result"}
HC_POLICY_KEYS = {"id", "identityPassSeeds", "invariantSeeds", "acceptedSeeds", "acceptedWithoutCheckSeeds"}
HC_GATE_KEYS = {"generalAccepted", "hardCodedRefused", "controlFires", "safetyZero"}
POLICIES = ("GENERAL", "HARD_CODED")
LABELS = ("IDENTITY", "PERMUTED")

# Section 8 and B5-3: the campaign record v2.
CAMPAIGN_KEYS = V1_CAMPAIGN_KEYS | {"scaling", "hardCoding"}
NEW_FINDING_IDS = {"F-C11-1", "F-C12-1", "F-G4-1", "F-G1-1"}
CR_POINT_KEYS = {"id", "family", "workers", "items", "safety", "finishedSeeds", "p50", "makespanRatioMilli",
                 "underperforms"}
CR_BASELINE_KEYS = {"id", "items", "safety", "finishedSeeds", "p50"}

ATTESTATION_FLAGS = ("warmSourceRead", "r10SourceRead", "w03WorkInProgressRead",
                     "implementationReadOrRunForExpectedResults")
# B5-4: the monitor rulings the attestation note cites in full; B5-5: the owner's independence answer.
B5_4_RULINGS = ("MON-P4-DR1-NOTED", "MON-P4-D16", "MON-P4-DR1-KEEP", "MON-P4-DR5-KEEP", "Q-P4-D3-1 (a)",
                "Q-P4-CAP (a)")
B5_5_ANSWER = "Accept as metadata-only (Recommended)"

# Home and scratch path markers, built from parts so that this file holds no path.
_PATH_MARKS = tuple("/" + part + "/" for part in ("Users", "home", "private", "tmp"))


# ---------------------------------------------------------------------------------------------
# Helpers (read rows and data only; never the candidate's code)

def _canonical_sha256(obj):
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex64(text):
    return isinstance(text, str) and len(text) == 64 and all(c in "0123456789abcdef" for c in text)


def _brief(row):
    return {k: v for k, v in row.items() if v is not None and v != []}


def _where(rows, where=None, **kw):
    return [r for r in rows if all(r.get(k) == v for k, v in kw.items()) and (where is None or where(r))]


def _near(rows, kw):
    """Rows of the same kind by the same agent or on the same item within two ticks, for the failure report."""
    t = kw.get("t")
    out = [r for r in rows if r.get("kind") == kw.get("kind")
           and (("agent" in kw and r.get("agent") == kw["agent"]) or ("item" in kw and r.get("item") == kw["item"]))
           and (not _is_int(t) or (_is_int(r.get("t")) and abs(r["t"] - t) <= 2))]
    return [_brief(r) for r in out[:6]]


def _one(bad, rows, label, where=None, **kw):
    got = _where(rows, where, **kw)
    if len(got) == 1:
        return got[0]
    bad(f"{label}: expected exactly one such row, found {len(got)}",
        {"want": kw, "found": [_brief(r) for r in got[:3]], "near": _near(rows, kw)})
    return None


def _some(bad, rows, label, where=None, **kw):
    got = _where(rows, where, **kw)
    if not got:
        bad(f"{label}: expected at least one such row, found none", {"want": kw, "near": _near(rows, kw)})
    return got


def _none(bad, rows, label, where=None, **kw):
    got = _where(rows, where, **kw)
    if got:
        bad(f"{label}: expected no such row", [_brief(r) for r in got[:3]])


def _bypass(row):
    text = row.get("controlBypass")
    return set(text.split("+")) if isinstance(text, str) and text else set()


def _applied(row):
    """An operation the board accepted and applied (a retry's historical answer changes nothing)."""
    return row.get("changed") is True or (row.get("answer") == "ACCEPTED" and row.get("changed") is not False)


def _is_merge(row):
    return row.get("kind") == "BOARD_ANSWER" and row.get("op") == "MERGE"


def _accepted_merge(row):
    """Section 4.6: an accepted, changed MERGE row."""
    return _is_merge(row) and row.get("changed") is True


def _is_judge(row):
    return row.get("kind") == "GATE" and row.get("component") == "JUDGE" and row.get("toolId") == "judge"


def _is_policy_gate(row):
    return row.get("kind") == "GATE" and row.get("component") == "GATE" and row.get("toolId") == "merge-policy"


def _bus_delivered(row):
    return row.get("kind") == "DELIVERY" and row.get("component") == "BUS" and row.get("answer") == "DELIVERED"


def _support(checks, rule):
    """Section 2.1: the evidence kinds of the checks whose check kind is deterministic."""
    out = set()
    for text in checks:
        kind, _sep, evidence = text.partition("/")
        if kind in rule["deterministicChecks"]:
            out.add(evidence)
    return out


def _consistency_only(checks, rule):
    """Section 2.1 and 4.6: no deterministic support outside consistencyOnly (empty support included)."""
    return not (_support(checks, rule) - set(rule["consistencyOnly"]))


def _violation_set(cfg, cls):
    """The controls' counters, the depth checks' counters and zeroTolerance."""
    out = {c["counter"] for c in cls["controls"]}
    for check in cls["depthChecks"]:
        out |= set(check["counters"])
    return out | set(cfg["zeroTolerance"])


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


def _topology_by_rule(family, n):
    """Section 6.1's rule. CENTRAL: c, v, w1..wN; c<->v, c<->wi, v<->wi. DECENTRALIZED: v, w1..wN; v<->wi and,
    for N >= 2, the ring wi -> w(i mod N)+1."""
    workers = [f"w{i}" for i in range(1, n + 1)]
    edges = set()
    if family == "CENTRAL":
        edges |= {("c", "v"), ("v", "c")}
        for w in workers:
            edges |= {("c", w), (w, "c"), ("v", w), (w, "v")}
        return {"mode": "CENTRAL", "coordinator": "c", "verifier": "v", "workers": workers}, edges
    for w in workers:
        edges |= {("v", w), (w, "v")}
    if n >= 2:
        for i in range(1, n + 1):
            edges.add((f"w{i}", f"w{(i % n) + 1}"))
    return {"mode": "DECENTRALIZED", "coordinator": None, "verifier": "v", "workers": workers}, edges


def _topology_name(family, n):
    return family if n == 4 else f"{family}_N{n}"


def _solve(problem):
    """Section 4.2: solve(P) = sha256(b"solve:" + P) as hex, first 16 characters."""
    return hashlib.sha256(b"solve:" + problem.encode("ascii")).hexdigest()[:16]


def _problems(seed, items):
    """Section 4.2: P_t = "%06d" % (draw("task-problem") % 1000000), in task order 1 to items."""
    streams = _sim.Streams(seed)
    return {t: "%06d" % (streams.draw("task-problem") % 1000000) for t in range(1, items + 1)}


def _sigma(seed, items):
    """Section 6.2: sigma = Streams(seed).permutation("perm-items", [1 .. items]); item k holds task sigma[k-1]."""
    return list(_sim.Streams(seed).permutation("perm-items", list(range(1, items + 1))))


def _first_moved(sigma):
    for k, task in enumerate(sigma, 1):
        if task != k:
            return k
    return None


def _first_verdicts_by_item(rows, items):
    """Section 6.2: the verdict status of the first VERDICT row on each item, or NONE."""
    out = {}
    for r in rows:
        if r.get("kind") == "VERDICT" and _is_int(r.get("item")) and r["item"] not in out:
            out[r["item"]] = r["verdictStatus"] if r.get("verdictStatus") is not None else r.get("answer")
    return [out.get(k, "NONE") for k in range(1, items + 1)]


def _task_outcomes(by_item, sigma):
    """Per task t, the outcome of the item holding t (identity when sigma is None)."""
    if sigma is None:
        return list(by_item)
    holder = {task: k for k, task in enumerate(sigma, 1)}
    return [by_item[holder[t] - 1] for t in range(1, len(by_item) + 1)]


def _scaling_readings(rows, measured, entry):
    """Section 6.1's seven readings for one run, with the unfinished-run rule: a run that has not merged every item
    reads lastMergeTick = its deadline and divides its merged items by the deadline."""
    items, deadline = entry["load"]["items"], entry["deadline"]
    merges = [r for r in rows if _is_merge(r) and _applied(r) and _is_int(r.get("t"))]
    merged = len({r["item"] for r in merges})
    finished = merged >= items
    if finished:
        last = max(r["t"] for r in merges)
        per100 = merged * 100 // last if last else 0
    else:
        last = deadline
        per100 = merged * 100 // deadline
    counts = measured["counts"]
    contention = sum(1 for r in rows if r.get("kind") == "BOARD_ANSWER" and r.get("answer") in CONTENTION_ANSWERS)
    messages = sum(1 for r in rows if _bus_delivered(r))
    readings = {"completionPpm": counts["completionPpm"], "lostWorkPpm": counts["lostWorkPpm"],
                "duplicatedWorkRatioPpm": counts["duplicatedWorkRatioPpm"], "lastMergeTick": last,
                "mergesPer100Ticks": per100, "contentionPerItemMilli": contention * 1000 // items,
                "messagesPerItemMilli": messages * 1000 // items}
    return readings, finished, merged


# ---------------------------------------------------------------------------------------------
# Checks applied to runs

def _check_rows(rows, measured, cfg, cls, ctx, bad):
    """Every row has packet 2's 34 fields followed by verdictChecks and taskPass (section 4.6); the new fields sit
    only where section 4.6 puts them and are null outside the classes that switch them on."""
    for row in rows:
        if list(row) != ROW_FIELDS:
            bad("every row has exactly packet 2's 34 fields followed by verdictChecks and taskPass",
                {"extra": sorted(set(row) - set(ROW_FIELDS)), "missing": sorted(set(ROW_FIELDS) - set(row)),
                 "tail": list(row)[-3:]})
            break
    kinds = sorted(str(k) for k in {r.get("kind") for r in rows} - ROW_KINDS)
    if kinds:
        bad("every row kind is one of the thirteen", kinds)
    if any(not isinstance(r.get("canaryHits"), list) for r in rows):
        bad("canaryHits is a list on every row")
    if not all(isinstance(measured.get(k), dict) for k in ("counts", "engaged", "engagedByEvent", "hits")):
        bad("measured carries the counts, engaged, engagedByEvent and hits maps", sorted(measured))
    has_rule, has_tasks = "evidenceRule" in cls, "tasks" in cls
    for row in rows:
        vc, tp = row.get("verdictChecks"), row.get("taskPass")
        if vc is not None:
            if not has_rule:
                bad("verdictChecks is null in a class without evidenceRule", _brief(row))
                break
            if not _is_merge(row):
                bad("verdictChecks appears only on MERGE board answers", _brief(row))
                break
            if (not isinstance(vc, list) or vc != sorted(vc)
                    or not all(isinstance(c, str) and c.count("/") == 1 for c in vc)):
                bad("verdictChecks is a sorted list of '<checkKind>/<evidenceKind>' strings", vc)
                break
        if tp is not None:
            if not has_tasks:
                bad("taskPass is null in a class without tasks", _brief(row))
                break
            if not (_is_merge(row) or _is_judge(row)) or not isinstance(tp, bool):
                bad("taskPass is a bool, only on MERGE board answers and judge GATE rows", _brief(row))
                break
    if has_rule:
        missing = [r for r in rows if _accepted_merge(r) and r.get("verdictChecks") is None]
        if missing:
            bad("an accepted MERGE in an evidenceRule class records verdictChecks", _brief(missing[0]))
    if has_tasks:
        missing = [r for r in rows if (_is_judge(r) or _accepted_merge(r)) and not isinstance(r.get("taskPass"), bool)]
        if missing:
            bad("a judge GATE row and an accepted MERGE in a tasks class record taskPass", _brief(missing[0]))


def _check_new_counters(rows, measured, cfg, cls, ctx, bad):
    """Section 4.6: regressionOnlyMerged and degenerateMerged recounted from the rows; 0 where the key is absent."""
    counts = measured["counts"]
    merges = [r for r in rows if _accepted_merge(r)]
    rule = cls.get("evidenceRule")
    want_ro = 0
    if rule:
        want_ro = sum(1 for r in merges if r.get("verdictChecks") is not None
                      and _consistency_only(r["verdictChecks"], rule))
    want_dg = sum(1 for r in merges if r.get("taskPass") is False) if "tasks" in cls else 0
    for name, want in (("regressionOnlyMerged", want_ro), ("degenerateMerged", want_dg)):
        if counts.get(name) != want:
            bad(f"{name} equals its recount from the rows", {"measured": counts.get(name), "rows": want})


def _check_inert(rows, measured, cfg, cls, ctx, bad):
    hit = [r for r in rows if r.get("verdictChecks") is not None or r.get("taskPass") is not None]
    if hit:
        bad("verdictChecks and taskPass are null in every row of C1 to C10", _brief(hit[0]))


def _check_zero(rows, measured, cfg, cls, ctx, bad):
    """Item 4: the violation set at 0, and section 5's expectations: duplicated work 0, lost work 0, completion 1e6."""
    counts = measured["counts"]
    for name in sorted(_violation_set(cfg, cls)):
        if counts.get(name) != 0:
            bad(f"{name} is 0 in the defended run", counts.get(name))
    for name, want in (("duplicatedWorkRatioPpm", 0), ("duplicateWork", 0), ("lostWorkPpm", 0),
                       ("completionPpm", 1000000)):
        if counts.get(name) != want:
            bad(f"{name} reads {want} in the defended run (section 5)", counts.get(name))
    named = [r for r in rows if _bypass(r)]
    if named:
        bad("a defended run names no bypass", _brief(named[0]))


def _engaged_by_event(measured, event):
    by_event = measured.get("engagedByEvent")
    return (by_event.get(event) or {}) if isinstance(by_event, dict) else {}


def _same_claim(bad, label, first, other):
    if first is not None and other is not None and first.get("claimOpId") != other.get("claimOpId"):
        bad(f"{label} stays inside the event's own claim",
            {"first": first.get("claimOpId"), "later": other.get("claimOpId")})


def _first_claim(bad, rows, agent, item, label):
    _one(bad, rows, f"{label}: {agent} acquires item {item} at tick 0", kind="BOARD_ANSWER", op="ACQUIRE",
         agent=agent, item=item, t=0, where=_applied)
    return _one(bad, rows, f"{label}: {agent}'s first WORK on item {item} at 4", kind="WORK", agent=agent, item=item,
                t=4)


def _merged_once(bad, rows, item, label):
    merged = [r for r in rows if _accepted_merge(r) and r.get("item") == item]
    if len(merged) != 1:
        bad(f"{label}: item {item} is merged exactly once", [_brief(r) for r in merged[:3]])


# C11 REGRESSION_ONLY_PASS (section 5; latency 0, ticks as preregistered)

def _c11_defended(rows, measured, cfg, cls, ctx, bad):
    for agent, item, event, checks in C11_HOLDERS:
        work = _first_claim(bad, rows, agent, item, event)
        _one(bad, rows, f"{event}: v's regression-run GATE PASS at 5", kind="GATE", component="JUDGE",
             toolId="regression-run", item=item, t=5, answer="PASS")
        _none(bad, rows, f"{event}: the first work is not byte-judged at 5", kind="GATE", component="JUDGE",
              toolId="judge", item=item, t=5)
        engaging = _one(bad, rows, f"{event}: the engaging MERGE refused CONSISTENCY_ONLY at 7", kind="BOARD_ANSWER",
                        op="MERGE", agent=agent, item=item, t=7, answer="CONSISTENCY_ONLY", component="BOARD",
                        scheduledEvent=event)
        if engaging is not None:
            if engaging["verdictChecks"] != checks:
                bad(f"{event}: the refused MERGE records the regression verdict's checks", engaging["verdictChecks"])
            if engaging["changed"] is True:
                bad(f"{event}: the refused MERGE changes nothing", _brief(engaging))
        # A TOOL_CALL row names no item (READ's item is its input), so the READ is pinned by agent and tick.
        _some(bad, rows, f"{event}: {agent} revises (READ at 8)", kind="TOOL_CALL", toolId="READ", agent=agent, t=8)
        revised = _one(bad, rows, f"{event}: the revised WORK at 11", kind="WORK", agent=agent, item=item, t=11)
        _same_claim(bad, f"{event}: the revision", work, revised)
        _one(bad, rows, f"{event}: v's judge PASSes the new work at 12", kind="GATE", component="JUDGE",
             toolId="judge", item=item, t=12, answer="PASS")
        merge = _one(bad, rows, f"{event}: the MERGE is accepted at 14", kind="BOARD_ANSWER", op="MERGE", agent=agent,
                     item=item, t=14, where=_accepted_merge)
        if merge is not None and merge["verdictChecks"] != TEST_RESULT_CHECKS:
            bad(f"{event}: the accepted MERGE rests on the judge's TEST_RESULT verdict", merge["verdictChecks"])
        _same_claim(bad, f"{event}: the merge", work, merge)
        _merged_once(bad, rows, item, event)
        if _engaged_by_event(measured, event).get("BOARD:CONSISTENCY_ONLY", 0) < 1:
            bad(f"{event} engages BOARD:CONSISTENCY_ONLY", _engaged_by_event(measured, event))
    for agent, item in (("w3", 3), ("w4", 4)):
        merge = _one(bad, rows, f"{agent}: the honest first work merges at 7", kind="BOARD_ANSWER", op="MERGE",
                     agent=agent, item=item, t=7, where=_accepted_merge)
        if merge is not None and merge["verdictChecks"] != TEST_RESULT_CHECKS:
            bad(f"{agent}: packet 1's verifier cites DETERMINISTIC_TEST/TEST_RESULT", merge["verdictChecks"])


def _c11_control(rows, measured, cfg, cls, entry, bad):
    """Section 5: under either control both events merge at 7, named EVIDENCE_KIND."""
    for agent, item, event, checks in C11_HOLDERS:
        merge = _one(bad, rows, f"{event}: the regression-only MERGE is accepted at 7", kind="BOARD_ANSWER",
                     op="MERGE", agent=agent, item=item, t=7, where=_accepted_merge)
        if merge is not None:
            if "EVIDENCE_KIND" not in _bypass(merge):
                bad(f"{event}: the accepted MERGE names EVIDENCE_KIND", _brief(merge))
            if merge["scheduledEvent"] != event or merge["verdictChecks"] != checks:
                bad(f"{event}: the accepted MERGE is tagged {event} and records the regression checks", _brief(merge))
    _none(bad, rows, "no MERGE is refused CONSISTENCY_ONLY under EVIDENCE_KIND", kind="BOARD_ANSWER", op="MERGE",
          answer="CONSISTENCY_ONLY")
    if measured["counts"].get("regressionOnlyMerged") != 2:
        bad("regressionOnlyMerged counts both events' merges", measured["counts"].get("regressionOnlyMerged"))


# C12 DEGENERATE_SUBMISSION (section 5; latency 0)

def _c12_defended(rows, measured, cfg, cls, ctx, bad):
    for agent, item, event, form in C12_FORMS:
        work = _first_claim(bad, rows, agent, item, event)
        engaging = _one(bad, rows, f"{event} ({form}): the engaging judge GATE FAIL at 5", kind="GATE",
                        component="JUDGE", toolId="judge", item=item, t=5, answer="FAIL", scheduledEvent=event)
        if engaging is not None and engaging["taskPass"] is not False:
            bad(f"{event}: the degenerate work fails the task test", _brief(engaging))
        gate = _one(bad, rows, f"{event}: the merge-policy gate at 7", kind="GATE", component="GATE",
                    toolId="merge-policy", agent=agent, item=item, t=7)
        if form == "CONSTANT":
            if gate is not None and gate["answer"] != "PASS":
                bad(f"{event}: a constant body passes merge-policy (F-C12-1)", _brief(gate))
            _one(bad, rows, f"{event}: the MERGE is refused VERDICT_NOT_PASS at 7", kind="BOARD_ANSWER", op="MERGE",
                 agent=agent, item=item, t=7, answer="VERDICT_NOT_PASS")
        else:
            if gate is not None and (gate["answer"] != "FAIL" or gate["markerPresent"] is not False):
                bad(f"{event}: merge-policy FAILs the degenerate body, markerPresent keeps packet 1's false",
                    _brief(gate))
            _none(bad, rows, f"{event}: no MERGE at 7 after the gate FAIL", kind="BOARD_ANSWER", op="MERGE",
                  agent=agent, item=item, t=7)
        _some(bad, rows, f"{event}: {agent} revises (READ at 8)", kind="TOOL_CALL", toolId="READ", agent=agent, t=8)
        revised = _one(bad, rows, f"{event}: the revised WORK at 11", kind="WORK", agent=agent, item=item, t=11)
        _same_claim(bad, f"{event}: the revision", work, revised)
        judged = _one(bad, rows, f"{event}: the honest work PASSes the judge at 12", kind="GATE", component="JUDGE",
                      toolId="judge", item=item, t=12, answer="PASS")
        if judged is not None and judged["taskPass"] is not True:
            bad(f"{event}: the honest work passes the task test", _brief(judged))
        merge = _one(bad, rows, f"{event}: the MERGE is accepted at 14", kind="BOARD_ANSWER", op="MERGE", agent=agent,
                     item=item, t=14, where=_accepted_merge)
        if merge is not None and merge["taskPass"] is not True:
            bad(f"{event}: the merged bytes pass the task test", _brief(merge))
        _same_claim(bad, f"{event}: the merge", work, merge)
        _merged_once(bad, rows, item, event)
        if sum(v for v in _engaged_by_event(measured, event).values() if _is_int(v)) < 1:
            bad(f"{event} engages its component", _engaged_by_event(measured, event))
    judged = _one(bad, rows, "w4: the honest first work PASSes the judge at 5", kind="GATE", component="JUDGE",
                  toolId="judge", item=4, t=5, answer="PASS")
    if judged is not None and judged["taskPass"] is not True:
        bad("w4: the honest first work passes the task test", _brief(judged))
    _one(bad, rows, "w4: the honest first work merges at 7", kind="BOARD_ANSWER", op="MERGE", agent="w4", item=4, t=7,
         where=_accepted_merge)


def _c12_isolated(rows, event, bad):
    """Section 4.8: a control or depth run writes degenerate bytes only for its event's worker."""
    for other, (agent, item, form) in sorted(C12_FORM_OF.items()):
        judged = _one(bad, rows, f"isolation: one judge GATE row on {agent}'s first work at 5", kind="GATE",
                      component="JUDGE", toolId="judge", item=item, t=5)
        if judged is not None:
            want = other != event
            if judged["taskPass"] is not want:
                bad(f"isolation: {agent}'s first work is {'honest' if want else form}", _brief(judged))


def _c12_control(rows, measured, cfg, cls, entry, bad):
    event = entry["event"]
    agent, item, form = C12_FORM_OF[event]
    _c12_isolated(rows, event, bad)
    judged = _one(bad, rows, f"{event}: the judge PASSes the {form} work by status at 5", kind="GATE",
                  component="JUDGE", toolId="judge", item=item, t=5, answer="PASS", scheduledEvent=event)
    if judged is not None and "JUDGE_BY_STATUS" not in _bypass(judged):
        bad(f"{event}: the judge row names JUDGE_BY_STATUS", _brief(judged))
    gate = _one(bad, rows, f"{event}: the merge-policy gate at 7", kind="GATE", component="GATE",
                toolId="merge-policy", agent=agent, item=item, t=7)
    if gate is not None:
        if form == "CONSTANT":
            if gate["answer"] != "PASS" or "MERGE_GATE" in _bypass(gate):
                bad(f"{event}: a constant body passes merge-policy, naming no bypass", _brief(gate))
        elif gate["answer"] != "SKIPPED" or "MERGE_GATE" not in _bypass(gate) or gate["scheduledEvent"] != event:
            bad(f"{event}: the SKIPPED merge-policy row names MERGE_GATE, tagged {event}", _brief(gate))
    merge = _one(bad, rows, f"{event}: the degenerate work merges at 7", kind="BOARD_ANSWER", op="MERGE", agent=agent,
                 item=item, t=7, where=_accepted_merge)
    if merge is not None and (merge["taskPass"] is not False or merge["scheduledEvent"] != event):
        bad(f"{event}: the merged degenerate bytes fail the task test, tagged {event}", _brief(merge))
    if measured["counts"].get("degenerateMerged") != 1:
        bad("degenerateMerged counts the one isolated event", measured["counts"].get("degenerateMerged"))


def _c12_depth(rows, measured, cfg, cls, entry, bad):
    event = entry["event"]
    agent, item, form = C12_FORM_OF[event]
    _c12_isolated(rows, event, bad)
    if entry["bypass"] == ["JUDGE_BY_STATUS"]:
        judged = _one(bad, rows, f"{event}: the judge PASSes the {form} work by status at 5", kind="GATE",
                      component="JUDGE", toolId="judge", item=item, t=5, answer="PASS")
        if judged is not None and "JUDGE_BY_STATUS" not in _bypass(judged):
            bad(f"{event}: the judge row names JUDGE_BY_STATUS", _brief(judged))
        gate = _one(bad, rows, f"{event}: merge-policy holds at 7", kind="GATE", component="GATE",
                    toolId="merge-policy", agent=agent, item=item, t=7, answer="FAIL", scheduledEvent=event)
        if gate is not None and _bypass(gate):
            bad(f"{event}: the holding merge-policy row names no bypass", _brief(gate))
        _none(bad, rows, f"{event}: no MERGE at 7", kind="BOARD_ANSWER", op="MERGE", agent=agent, item=item, t=7)
    else:
        judged = _one(bad, rows, f"{event}: the judge FAILs the {form} work at 5", kind="GATE", component="JUDGE",
                      toolId="judge", item=item, t=5, answer="FAIL")
        if judged is not None and _bypass(judged):
            bad(f"{event}: the judge row names no bypass", _brief(judged))
        gate = _one(bad, rows, f"{event}: the merge-policy row at 7", kind="GATE", component="GATE",
                    toolId="merge-policy", agent=agent, item=item, t=7)
        if gate is not None and (gate["answer"] != "SKIPPED" or "MERGE_GATE" not in _bypass(gate)):
            bad(f"{event}: the SKIPPED merge-policy row names MERGE_GATE", _brief(gate))
        _one(bad, rows, f"{event}: the board's VERDICT_NOT_PASS holds at 7", kind="BOARD_ANSWER", op="MERGE",
             agent=agent, item=item, t=7, answer="VERDICT_NOT_PASS", scheduledEvent=event)
    merged = [r for r in rows if _accepted_merge(r) and r.get("item") == item]
    if len(merged) != 1 or merged[0]["taskPass"] is not True:
        bad(f"{event}: item {item} merges once, the honest revision", [_brief(r) for r in merged[:3]])


def _control_generic(rows, measured, cfg, cls, entry, bad):
    """Item 2: own counter above 0; a counted row tagged with the event; every bypassed check named on a row
    tagged with the event."""
    counter, event = entry["counter"], entry["event"]
    count = measured["counts"].get(counter)
    if not _is_int(count) or count <= 0:
        bad(f"own counter {counter} is above 0", count)
    hits = (measured.get("hits") or {}).get(counter) or []
    if not any(isinstance(r, dict) and r.get("scheduledEvent") == event for r in hits):
        bad(f"a row counted by {counter} is tagged {event}", [_brief(r) for r in hits[:2] if isinstance(r, dict)])
    named = set()
    for row in rows:
        if row.get("scheduledEvent") == event:
            named |= _bypass(row)
    missing = sorted(set(entry["bypass"]) - named)
    if missing:
        bad(f"every bypassed check is named on a row tagged {event}", missing)


def _depth_generic(rows, measured, cfg, cls, entry, bad):
    """Item 3: the violation set at 0 under the check's bypass; its engaged key engaged by a row tagged with its
    event."""
    counts = measured["counts"]
    for name in sorted(_violation_set(cfg, cls)):
        if counts.get(name) != 0:
            bad(f"{name} is 0 under the depth check's bypass", counts.get(name))
    key, event = entry["engaged"], entry["event"]
    got = _engaged_by_event(measured, event).get(key, 0)
    if not _is_int(got) or got < 1:
        bad(f"engagedByEvent[{event}][{key}] is at least 1", got)
    component, answer = key.split(":", 1)
    hits = [r for r in rows if r.get("scheduledEvent") == event and r.get("component") == component
            and (r.get("answer") == answer or (r.get("toolId") == answer and r.get("answer") == "FAIL"))]
    if not hits:
        bad(f"a row tagged {event} carries {key}")


def _check_rules(rows, measured, cfg, cls, ctx, bad):
    """Item 5 on single runs: CONSISTENCY_ONLY and EVIDENCE_KIND (4.5); the judge's task test and JUDGE_BY_STATUS
    (4.3); the MERGE_GATE naming of the degenerate check (4.4)."""
    bypass = set(ctx["bypass"])
    rule = cls.get("evidenceRule")
    if rule:
        for row in rows:
            if not _is_merge(row):
                continue
            vc = row.get("verdictChecks")
            regression_only = vc is not None and _consistency_only(vc, rule)
            if row.get("answer") == "CONSISTENCY_ONLY":
                if "EVIDENCE_KIND" in bypass or not regression_only:
                    bad("CONSISTENCY_ONLY refuses only consistency-only support, never under EVIDENCE_KIND",
                        _brief(row))
            if _accepted_merge(row) and regression_only and "EVIDENCE_KIND" not in _bypass(row):
                bad("a consistency-only verdict is accepted only by EVIDENCE_KIND, which the row names", _brief(row))
            if "EVIDENCE_KIND" in _bypass(row) and not (_accepted_merge(row) and regression_only):
                bad("EVIDENCE_KIND is named only where it turns CONSISTENCY_ONLY into an acceptance", _brief(row))
    if "tasks" in cls:
        for row in rows:
            if _is_judge(row):
                task_pass, named = row.get("taskPass"), "JUDGE_BY_STATUS" in _bypass(row)
                if named and not ("JUDGE_BY_STATUS" in bypass and task_pass is False and row.get("answer") == "PASS"):
                    bad("JUDGE_BY_STATUS is named only when it turns a byte FAIL into a PASS", _brief(row))
                if "JUDGE_BY_STATUS" in bypass:
                    if row.get("answer") != "PASS" or (task_pass is False and not named):
                        bad("under JUDGE_BY_STATUS the self-reported PASS decides; a turned FAIL names it",
                            _brief(row))
                elif (row.get("answer") == "PASS") != (task_pass is True):
                    bad("the judge's status follows the task test (no marker in this class)", _brief(row))
            elif _is_policy_gate(row) and "MERGE_GATE" in _bypass(row):
                if "MERGE_GATE" not in bypass or row.get("answer") != "SKIPPED":
                    bad("MERGE_GATE is named only on a SKIPPED merge-policy row under its bypass", _brief(row))


def _check_safety(rows, measured, cfg, cls, ctx, bad):
    counts = measured["counts"]
    names = SAFETY_COUNTERS + (["degenerateMerged"] if ctx["mode"] == "bed" else [])
    for name in names:
        if counts.get(name) != 0:
            bad(f"safety counter {name} is 0", counts.get(name))


# ---------------------------------------------------------------------------------------------
# One survey of every run, shared by the tests below

CATEGORIES = ("rows", "counters", "rules", "inert", "paths_C11", "paths_C12", "controls_C11", "controls_C12",
              "depth_C12", "zero", "scaling", "sensitivity", "hardcoding")
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
            lines.append(line[:1500])
        return "\n".join(lines)


_PLANS = {
    ("C11", "defended"): [("paths_C11", _c11_defended), ("zero", _check_zero)],
    ("C12", "defended"): [("paths_C12", _c12_defended), ("zero", _check_zero)],
    ("C11", "control"): [("controls_C11", _control_generic), ("controls_C11", _c11_control)],
    ("C12", "control"): [("controls_C12", _control_generic), ("controls_C12", _c12_control)],
    ("C12", "depth"): [("depth_C12", _depth_generic), ("depth_C12", _c12_depth)],
}


def _apply(cats, where, seed, rows, measured, cfg, cls, ctx):
    plan = [("rows", _check_rows), ("counters", _check_new_counters)]
    mode = ctx["mode"]
    if ctx["cid"] in NEW_IDS:
        plan.append(("rules", _check_rules))
        plan += _PLANS.get((ctx["cid"], mode), [])
    elif mode == "sample":
        plan.append(("inert", _check_inert))
    elif mode in ("scaling", "bed"):
        plan.append(("scaling" if mode == "scaling" else "hardcoding", _check_safety))
    for cat, check in plan:
        problems = cats[cat]

        def bad(msg, detail=None, _problems=problems):
            _problems.add(where, seed, msg, detail)

        arg = ctx["entry"] if check in (_control_generic, _c11_control, _c12_control, _depth_generic,
                                        _c12_depth) else ctx
        try:
            check(rows, measured, cfg, cls, arg, bad)
        except Exception as exc:  # an oracle check that cannot read a row is a reported problem
            bad(f"oracle check {check.__name__} raised {type(exc).__name__}", str(exc)[:200])


def _survey():
    if "survey" in _STATE:
        return _STATE["survey"]
    cfg, _sha = _ledger.load_config()
    by_id = {c["id"]: c for c in cfg["classes"]}
    cats = {name: _Problems() for name in CATEGORIES}
    out = {"cats": cats, "runs": 0, "readings": {}, "finished": {}, "bed": {}, "sigma": {}, "problems": {}}

    def run(where, seed, cls, bypass=(), **kw):
        out["runs"] += 1
        try:
            return _ledger.run(cfg, cls, seed, tuple(bypass), **kw)
        except Exception as exc:  # a run that cannot complete is a reported problem
            cats["rows"].add(where, seed, f"run raised {type(exc).__name__}", str(exc)[:200])
            return None

    # C11 and C12: defended, every control and every depth check, in every seed (items 1 to 5).
    for cid in NEW_IDS:
        cls = by_id.get(cid)
        if cls is None:
            cats["rows"].add(cid, 0, "class missing from classes.json", None)
            continue
        for seed in cfg["seeds"]:
            jobs = [("defended", None)] + [("control", c) for c in cls["controls"]]
            jobs += [("depth", d) for d in cls["depthChecks"]]
            for mode, entry in jobs:
                bypass = tuple(entry["bypass"]) if entry else ()
                kw = {"scriptedEvents": (entry["event"],)} if entry is not None and cls.get("isolateEvents") else {}
                where = f"{cid} {entry['id'] if entry else mode}"
                res = run(where, seed, cls, bypass, **kw)
                if res is not None:
                    _apply(cats, where, seed, res[0], res[1], cfg, cls,
                           {"cid": cid, "mode": mode, "entry": entry, "bypass": bypass})
                res = None

    # C1 to C10: one defended run each, a different seed per class (item 5, the inert fields).
    for index, cid in enumerate(PRIOR_IDS):
        seed = cfg["seeds"][index]
        res = run(f"{cid} defended", seed, by_id[cid])
        if res is not None:
            _apply(cats, f"{cid} defended", seed, res[0], res[1], cfg, by_id[cid],
                   {"cid": cid, "mode": "sample", "entry": None, "bypass": ()})
        res = None

    # Scaling and baseline points: at most 4 seeds each (the survey bound), then the sensitivity control.
    scaling = cfg["scaling"]
    for entry in scaling["points"] + scaling["baseline"]:
        for seed in SURVEY_SEEDS:
            where = f"{entry['id']} defended"
            res = run(where, seed, entry)
            if res is None:
                continue
            rows, measured = res
            _apply(cats, where, seed, rows, measured, cfg, entry,
                   {"cid": entry["id"], "mode": "scaling", "entry": None, "bypass": ()})
            try:
                readings, finished, merged = _scaling_readings(rows, measured, entry)
                out["readings"][(entry["id"], seed)] = readings
                out["finished"][(entry["id"], seed)] = finished
                if measured["counts"].get("mergedItems") != merged:
                    cats["scaling"].add(where, seed, "mergedItems equals the merged items in the rows",
                                        {"measured": measured["counts"].get("mergedItems"), "rows": merged})
            except Exception as exc:
                cats["scaling"].add(where, seed, f"oracle readings raised {type(exc).__name__}", str(exc)[:200])
            rows = measured = res = None
    points = {p["id"]: p for p in scaling["points"]}
    for control in scaling["controls"]:
        for seed in SURVEY_SEEDS:
            where = control["id"]
            res = run(where, seed, points[control["point"]], tuple(control["bypass"]))
            if res is None:
                continue
            rows, measured = res
            _apply(cats, where, seed, rows, measured, cfg, points[control["point"]],
                   {"cid": control["id"], "mode": "control-scaling", "entry": None, "bypass": control["bypass"]})
            count = measured["counts"].get(control["counter"])
            if not _is_int(count) or count <= 0:
                cats["sensitivity"].add(where, seed, f"{control['counter']} is above 0", count)
            if not (measured.get("hits") or {}).get(control["counter"]):
                cats["sensitivity"].add(where, seed, f"hits name the rows {control['counter']} counted", None)
            rows = measured = res = None

    # The G4 bed: both policies, both labels, every seed (item 9).
    bed = cfg["hardCoding"]["bed"]
    items = bed["load"]["items"]
    for seed in cfg["seeds"]:
        sigma = _sigma(seed, items)
        out["sigma"][seed] = sigma
        out["problems"][seed] = _problems(seed, items)
        for policy in POLICIES:
            for labels in LABELS:
                where = f"G4 {policy} {labels}"
                res = run(where, seed, bed, (), labels=labels, policy=policy)
                if res is None:
                    continue
                rows, measured = res
                _apply(cats, where, seed, rows, measured, cfg, bed,
                       {"cid": "G4", "mode": "bed", "entry": None, "bypass": ()})
                try:
                    out["bed"][(policy, labels, seed)] = _first_verdicts_by_item(rows, items)
                except Exception as exc:
                    cats["hardcoding"].add(where, seed, f"oracle outcomes raised {type(exc).__name__}", str(exc)[:200])
                rows = measured = res = None
        _check_bed_seed(cats["hardcoding"], out, seed, items)
    _STATE["survey"] = out
    return out


def _check_bed_seed(problems, out, seed, items):
    """Section 6.2's expectations, from the rows and the recomputed sigma, per seed."""
    sigma = out["sigma"][seed]
    k0 = _first_moved(sigma)
    for policy in POLICIES:
        for labels in LABELS:
            got = out["bed"].get((policy, labels, seed))
            if got is None:
                continue
            if policy == "HARD_CODED" and labels == "PERMUTED" and k0 is not None:
                want = ["PASS"] * (k0 - 1) + ["FAIL"] + ["NONE"] * (items - k0)
                label = f"the first moved item ({k0}) FAILs, later items have no verdict"
            else:
                want = ["PASS"] * items
                label = "every item's first verdict is PASS"
            if got != want:
                problems.add(f"G4 {policy} {labels}", seed, label, {"got": got, "sigma": sigma})


def _ledger_doc():
    if "ledger" not in _STATE:
        _STATE["ledger"] = _ledger.ledger()
    return _STATE["ledger"]


def _campaign():
    if "campaign" not in _STATE:
        _STATE["campaign"] = _ledger.campaign_record()
    return _STATE["campaign"]


# ---------------------------------------------------------------------------------------------
# Tests: the data files (item 11)

class OracleP4DataTests(unittest.TestCase):
    """contracts.json, attestation-p4.json and classes.json as DESIGN sections 2, 5 and 6 preregister them."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.sha = _ledger.load_config()
        cls.by_id = {c["id"]: c for c in cls.cfg["classes"]}

    def test_contracts_json_has_the_eleventh_row_and_the_first_ten_unchanged(self):
        doc = json.loads((_HERE_PATH / "contracts.json").read_text(encoding="utf-8"))
        self.assertEqual(set(doc), {"commit", "files", "note", "schemaVersion"})
        self.assertEqual(doc["commit"], REPIN_COMMIT)
        self.assertEqual(doc["schemaVersion"], "r12.mas-clean-room-pins/v1")
        for entry in doc["files"]:
            self.assertEqual(set(entry), {"packet", "path", "sha256", "size"})
        # CONF-MAS-005 adds the twelfth and thirteenth rows: packet 4's pins are the first eleven.
        self.assertEqual([(f["packet"], f["path"], f["sha256"], f["size"]) for f in doc["files"][:11]], PINNED_FILES)
        self.assertIn("architecture/verdict-ledger/check-kinds.json", doc["note"])
        self.assertEqual(_personal_hits(doc["note"]), [])

    def test_attestation_p4_has_packet3_shape_eleven_inputs_and_flags_false(self):
        att = json.loads((_HERE_PATH / "attestation-p4.json").read_text(encoding="utf-8"))
        att3 = json.loads((_HERE_PATH / "attestation-p3.json").read_text(encoding="utf-8"))
        contracts = json.loads((_HERE_PATH / "contracts.json").read_text(encoding="utf-8"))
        self.assertEqual(set(att), set(att3))
        self.assertEqual((att["schemaVersion"], att["packet"]), (att3["schemaVersion"], "CONF-MAS-004"))
        inputs = att["inputs"]
        self.assertEqual(len(inputs), 11)
        # CONF-MAS-005 adds two pins: packet 4's inputs are compared with contracts.json's first eleven rows.
        self.assertEqual(len(contracts["files"][:11]), 11)
        for name, entry in zip(inputs, contracts["files"]):
            with self.subTest(path=entry["path"]):
                self.assertEqual(name, "<harness-onion>/" + entry["path"] + "@585364b")
                self.assertEqual(att["inputDigests"].get(name), entry["sha256"])
        self.assertEqual(set(att["inputDigests"]), set(inputs))
        for flag in ATTESTATION_FLAGS:
            self.assertIs(att[flag], False, flag)

    def test_attestation_p4_note_cites_the_rulings_and_the_independence_answer(self):
        att = json.loads((_HERE_PATH / "attestation-p4.json").read_text(encoding="utf-8"))
        note = att["note"]
        self.assertIsInstance(note, str)
        for ruling in B5_4_RULINGS:
            self.assertIn(ruling, note, "B5-4")
        self.assertIn(B5_5_ANSWER, note, "B5-5")
        self.assertIn("w03WorkInProgressRead", note, "B5-5: the answer is named beside the flag")
        self.assertEqual(_personal_hits(note + " " + " ".join(att["inputs"])), [])

    def test_classes_json_header_streams_and_inert_switches(self):
        cfg = self.cfg
        self.assertTrue(_is_hex64(self.sha), self.sha)
        # CONF-MAS-005: header v5 and CONF-MAS-005; packets 1 to 4 are the first twelve ids and the first nine streams.
        self.assertEqual(cfg["schemaVersion"], "r12.mas-simulation-classes/v5")
        self.assertEqual(cfg["packet"], "CONF-MAS-005")
        self.assertIn("scaling", cfg)
        self.assertIn("hardCoding", cfg)
        self.assertEqual(cfg["seeds"], list(range(1, 33)))
        self.assertEqual([c["id"] for c in cfg["classes"]][:12], CLASS_IDS)
        self.assertEqual(cfg["streams"][:9], ["lat-<agent>", "stall-<agent>", "poison-<agent>", "read-<agent>",
                                          "sched-c3", "sched-c7", "sched-c8", "task-problem", "perm-items"])
        self.assertEqual(cfg["zeroTolerance"], ZERO_TOLERANCE)
        self.assertEqual((cfg["shared"]["items"], cfg["shared"]["concurrency"]), (20, 4))
        for cid in PRIOR_IDS:
            for key in P4_SWITCHES:
                self.assertNotIn(key, self.by_id[cid], f"{cid} lacks packet 4's switch {key}")
        for cid in NEW_IDS:
            self.assertNotIn("claimAwareWorker", self.by_id[cid])
            self.assertNotIn("load", self.by_id[cid], f"{cid} keeps packet 1's 20 items and concurrency 4")
        self.assertNotIn("claimAwareWorker", cfg["hardCoding"]["bed"])

    def test_classes_json_preregisters_c11(self):
        cls = self.by_id["C11"]
        for key, value in dict(COMMON, kind="REGRESSION_ONLY_PASS", depthChecks=[], evidenceRule=EVIDENCE_RULE,
                               scripts=C11_SCRIPTS).items():
            self.assertEqual(cls[key], value, key)
        for key in ("tasks", "selfReport", "degenerateCheck", "isolateEvents"):
            self.assertNotIn(key, cls)
        self.assertEqual([(e["id"], e["component"], e["engagedBy"], e["agent"], e["item"], e["trigger"])
                          for e in cls["events"]], C11_EVENTS)
        self.assertEqual([(c["id"], c["bypass"], c["counter"], c["event"]) for c in cls["controls"]], C11_CONTROLS)
        self.assertEqual([(f["agent"], f["item"], f.get("event")) for f in cls["firstClaims"]],
                         [("w1", 1, "E1"), ("w2", 2, "E2"), ("w3", 3, None), ("w4", 4, None)])

    def test_classes_json_preregisters_c12(self):
        cls = self.by_id["C12"]
        for key, value in dict(COMMON, kind="DEGENERATE_SUBMISSION", tasks={"problemStream": "task-problem"},
                               selfReport=True, degenerateCheck=True, isolateEvents=True,
                               scripts=C12_SCRIPTS).items():
            self.assertEqual(cls[key], value, key)
        self.assertNotIn("evidenceRule", cls)
        self.assertEqual([(e["id"], e["component"], e["engagedBy"], e["agent"], e["item"], e["trigger"])
                          for e in cls["events"]], C12_EVENTS)
        self.assertEqual([(c["id"], c["bypass"], c["counter"], c["event"]) for c in cls["controls"]], C12_CONTROLS)
        self.assertEqual([(d["id"], d["event"], d["bypass"], d["counters"], d["engaged"]) for d in cls["depthChecks"]],
                         C12_DEPTH)
        self.assertEqual([(f["agent"], f["item"], f.get("event")) for f in cls["firstClaims"]],
                         [("w1", 1, "E1"), ("w2", 2, "E2"), ("w3", 3, "E3"), ("w4", 4, None)])

    def test_classes_json_preregisters_scaling_and_the_topology_rule(self):
        scaling = self.cfg["scaling"]
        self.assertEqual(scaling["decisions"], SCALING_DECISIONS)
        self.assertEqual(scaling["parameters"], {"baselineItems": BASELINE_ITEMS, "deadlineBase": 400,
                                                 "deadlinePerItem": 50, "itemsPerWorker": 5, "maxLatency": 3,
                                                 "poisonPpm": 50000, "stallPpm": 20000, "workers": WORKERS})
        self.assertEqual(scaling["readings"], list(SCALING_READINGS))
        self.assertEqual(scaling["safetyCounters"], SAFETY_COUNTERS)
        self.assertEqual(scaling["controls"], [{"bypass": ["HELD", "VERSION"], "counter": "claimOverlap",
                                                "id": "S-D16-EXCLUSIVE-OFF", "point": "S-D16"}])
        want = [(f"S-{fam[0]}{n}", fam, n, _topology_name(fam, n), 5 * n, n) for fam in ("CENTRAL", "DECENTRALIZED")
                for n in WORKERS]
        want_base = [(f"B-{i}", "DECENTRALIZED", 1, "DECENTRALIZED_N1", i, 1) for i in BASELINE_ITEMS]
        got = [(p["id"], p["family"], p["workers"], p["topology"], p["load"]["items"], p["load"]["concurrency"])
               for p in scaling["points"]]
        got_base = [(p["id"], p["family"], p["workers"], p["topology"], p["load"]["items"], p["load"]["concurrency"])
                    for p in scaling["baseline"]]
        self.assertEqual(got, want)
        self.assertEqual(got_base, want_base)
        for entry in scaling["points"] + scaling["baseline"]:
            with self.subTest(point=entry["id"]):
                self.assertEqual(set(entry["load"]), {"items", "concurrency"})
                self.assertEqual((entry["kind"], entry["maxLatency"], entry["stallPpm"], entry["poisonPpm"],
                                  entry["events"], entry["compromised"], entry["claimAwareWorker"]),
                                 ("SCALING", 3, 20000, 50000, [], None, True))
                self.assertEqual(entry["deadline"], 400 + 50 * entry["load"]["items"])
        topo = self.cfg["topologies"]
        for fam in ("CENTRAL", "DECENTRALIZED"):
            for n in WORKERS:
                with self.subTest(family=fam, workers=n):
                    head, edges = _topology_by_rule(fam, n)
                    spec = topo[_topology_name(fam, n)]
                    self.assertEqual(set(spec), set(head) | {"edges"})
                    for key, value in head.items():
                        self.assertEqual(spec[key], value, key)
                    pairs = [tuple(e) for e in spec["edges"]]
                    self.assertEqual(len(pairs), len(set(pairs)))
                    self.assertEqual(set(pairs), edges)
        new = {f"{fam}_N{n}" for fam in ("CENTRAL", "DECENTRALIZED") for n in (1, 2, 8, 16)}
        self.assertTrue(new <= set(topo), sorted(new - set(topo)))

    def test_classes_json_preregisters_hard_coding(self):
        hc = self.cfg["hardCoding"]
        self.assertEqual((hc["decision"], hc["labels"], hc["policies"], hc["permutationStream"]),
                         ("Q-RA10F-4", list(LABELS), list(POLICIES), "perm-items"))
        bed = hc["bed"]
        self.assertEqual((bed["id"], bed["kind"], bed["topology"], bed["load"], bed["maxLatency"], bed["poisonPpm"],
                          bed["stallPpm"], bed["deadline"], bed["tasks"], bed["events"], bed["compromised"]),
                         ("G4-BED", "HARD_CODING_BED", "DECENTRALIZED_N1", {"items": 20, "concurrency": 1}, 0, 0, 0,
                          900, {"problemStream": "task-problem"}, [], None))


# ---------------------------------------------------------------------------------------------
# Tests: the runs (items 1 to 5, the survey of item 8 and the bed of item 9)

class OracleP4RunTests(unittest.TestCase):
    """Black-box runs: C11 and C12 in every seed, C1 to C10 sampled, the scaling survey and the G4 bed."""

    def _assert_clean(self, category):
        problems = _survey()["cats"][category]
        self.assertFalse(problems.by, "\n" + problems.report())

    def test_every_run_was_made(self):
        # 32 x (1 + 2) for C11, 32 x (1 + 3 + 4) for C12, 10 samples, 15 x 4 survey runs, 4 control runs, 128 bed runs.
        self.assertEqual(_survey()["runs"], 32 * 3 + 32 * 8 + 10 + 15 * 4 + 4 + 128)

    def test_rows_keep_the_36_fields_and_the_kinds(self):
        self._assert_clean("rows")

    def test_new_fields_are_null_in_c1_to_c10(self):
        self._assert_clean("inert")

    def test_new_counters_match_their_rows(self):
        self._assert_clean("counters")

    def test_new_rules_on_single_runs(self):
        self._assert_clean("rules")

    def test_c11_event_paths_and_engagement_in_every_seed(self):
        self._assert_clean("paths_C11")

    def test_c12_event_paths_and_engagement_in_every_seed(self):
        self._assert_clean("paths_C12")

    def test_c11_controls_fire_through_their_events(self):
        self._assert_clean("controls_C11")

    def test_c12_controls_fire_through_their_events_in_isolation(self):
        self._assert_clean("controls_C12")

    def test_c12_depth_checks_hold_with_event_scoped_engagement(self):
        self._assert_clean("depth_C12")

    def test_defended_runs_keep_violation_sets_at_zero_and_read_the_expectations(self):
        self._assert_clean("zero")

    def test_scaling_survey_runs_keep_safety_at_zero(self):
        self._assert_clean("scaling")

    def test_sensitivity_control_fires_in_the_surveyed_seeds(self):
        self._assert_clean("sensitivity")

    def test_hard_coding_bed_runs_read_as_section_6_2_expects(self):
        self._assert_clean("hardcoding")


# ---------------------------------------------------------------------------------------------
# Tests: the ledger (items 6 to 9)

class OracleP4LedgerTests(unittest.TestCase):
    """The in-process ledger v4 against 0a479a55's rows, the expected FAILs, scaling and hardCoding."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.sha = _ledger.load_config()
        cls.by_id = {c["id"]: c for c in cls.cfg["classes"]}
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}

    def test_ledger_header_rule_and_class_ids(self):
        doc = self.doc
        # CONF-MAS-005 (D3-4): v5 adds overRevision and C13, and its sentence follows packet 4's in the rule.
        self.assertEqual(set(doc), LEDGER_KEYS | {"overRevision"})
        self.assertEqual((doc["schemaVersion"], doc["packet"]), ("r12.mas-simulation-results/v5", "CONF-MAS-005"))
        self.assertEqual(doc["contractsCommit"], REPIN_COMMIT)
        self.assertEqual(doc["classesSha256"], self.sha)
        self.assertEqual(doc["seeds"], list(range(1, 33)))
        self.assertEqual(doc["profile"], P3_PROFILE)
        self.assertEqual([row["id"] for row in doc["classes"]], CLASS_IDS + ["C13"])
        rule = doc["rule"]
        self.assertEqual(hashlib.sha256(rule[:P3_RULE_LEN].encode("utf-8")).hexdigest(), P3_RULE_SHA256,
                         "the rule starts with packet 3's text")
        tail = rule[P3_RULE_LEN:]
        self.assertTrue(tail[:1].isspace(), tail[:40])
        self.assertTrue(tail.strip().startswith(P4_RULE_SENTENCE), tail[:240])
        self.assertEqual(tuple(_ledger.SCALING_READINGS), SCALING_READINGS)

    def test_packets_1_to_3_rows_and_arms_are_byte_identical(self):
        for cid, want in PRIOR_ROW_SHA256.items():
            with self.subTest(cid=cid):
                self.assertIn(cid, self.rows)
                self.assertEqual(_canonical_sha256(self.rows[cid]), want)
        self.assertEqual(_canonical_sha256(self.doc["arms"]), PRIOR_ARMS_SHA256)

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

    def test_c11_and_c12_rows_pass_every_gate_with_their_preregistered_entries(self):
        seeds = len(self.cfg["seeds"])
        for cid in NEW_IDS:
            with self.subTest(cid=cid):
                row, cls = self.rows[cid], self.by_id[cid]
                self.assertEqual(set(row), CLASS_ROW_KEYS)
                self.assertEqual((row["kind"], row["result"]), (cls["kind"], "PASS"))
                self.assertEqual(set(row["parameters"]), PARAMETER_KEYS)
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
                quantiles = defended["quantiles"]
                for name, value in (("duplicatedWorkRatioPpm", 0), ("lostWorkPpm", 0), ("completionPpm", 1000000)):
                    self.assertEqual(quantiles[name], {"p50": value, "p95": value, "max": value, "min": value}, name)
                self.assertTrue(all(v is True for k, v in row["gates"].items() if k != "ratioBounds"), row["gates"])
                self.assertTrue(all(v is True for v in row["gates"]["ratioBounds"].values()), row["gates"])
                self.assertEqual(set(row["unexercisedInvariants"]), set(self.cfg["unexercisedInvariants"]))

    def test_scaling_section_shape_points_and_baseline(self):
        sec = self.doc["scaling"]
        cfg_scaling = self.cfg["scaling"]
        self.assertEqual(set(sec), SCALING_KEYS)
        self.assertEqual(sec["decisions"], cfg_scaling["decisions"])
        self.assertEqual(sec["parameters"], cfg_scaling["parameters"])
        self.assertEqual(sec["safetyCounters"], SAFETY_COUNTERS)
        want = [(f"S-{fam[0]}{n}", fam, n, _topology_name(fam, n), 5 * n, n, 400 + 50 * 5 * n)
                for fam in ("CENTRAL", "DECENTRALIZED") for n in WORKERS]
        want_base = [(f"B-{i}", "DECENTRALIZED", 1, "DECENTRALIZED_N1", i, 1, 400 + 50 * i) for i in BASELINE_ITEMS]
        for key, expected in (("points", want), ("baseline", want_base)):
            got = [(p["id"], p["family"], p["workers"], p["topology"], p["items"], p["concurrency"], p["deadline"])
                   for p in sec[key]]
            self.assertEqual(got, expected, key)
            for point in sec[key]:
                with self.subTest(point=point["id"]):
                    self.assertEqual(set(point), POINT_KEYS)
                    self.assertEqual(set(point["readings"]), set(SCALING_READINGS))
                    for name, q in point["readings"].items():
                        self.assertTrue(_quantile_ok(q), (name, q))
                    self.assertTrue(_is_int(point["finishedSeeds"]) and 0 <= point["finishedSeeds"] <= 32)
                    last = point["readings"]["lastMergeTick"]
                    self.assertLessEqual(last["max"], point["deadline"], "no run reads past its deadline")
                    if point["finishedSeeds"] < 32:
                        self.assertEqual(last["max"], point["deadline"], "an unfinished run reads its deadline")

    def test_scaling_safety_gate_and_sensitivity_control(self):
        sec = self.doc["scaling"]
        for point in sec["points"] + sec["baseline"]:
            with self.subTest(point=point["id"]):
                self.assertEqual(set(point["safety"]), {"seedsAboveZero", "failing"})
                self.assertEqual(point["safety"]["seedsAboveZero"], {name: 0 for name in SAFETY_COUNTERS})
                self.assertEqual(point["safety"]["failing"], [])
        self.assertEqual(sec["controls"], [{"id": "S-D16-EXCLUSIVE-OFF", "point": "S-D16", "bypass": ["HELD", "VERSION"],
                                            "counter": "claimOverlap", "firedSeeds": 32, "failing": []}])
        self.assertEqual(sec["gates"], {"safetyAtEveryPoint": True, "controlsFireInAllSeeds": True})
        self.assertEqual(sec["result"], "PASS")

    def test_scaling_against_baseline_from_the_p50s(self):
        sec = self.doc["scaling"]
        base = {b["items"]: b for b in sec["baseline"]}
        want = []
        for point in sec["points"]:
            b = base[point["items"]]
            p_last, b_last = point["readings"]["lastMergeTick"]["p50"], b["readings"]["lastMergeTick"]["p50"]
            ratio = p_last * 1000 // b_last if b_last else None
            under = p_last > b_last or point["readings"]["completionPpm"]["p50"] < b["readings"]["completionPpm"]["p50"]
            want.append({"point": point["id"], "baseline": b["id"], "makespanRatioMilli": ratio,
                         "underperforms": under})
        self.assertEqual(sec["againstBaseline"], want)

    def test_scaling_b5_readings_equal_s_d1s(self):
        sec = self.doc["scaling"]
        s_d1 = [p for p in sec["points"] if p["id"] == "S-D1"][0]
        b_5 = [p for p in sec["baseline"] if p["id"] == "B-5"][0]
        self.assertEqual(b_5["readings"], s_d1["readings"])
        self.assertEqual(b_5["finishedSeeds"], s_d1["finishedSeeds"])
        survey = _survey()["readings"]
        for seed in SURVEY_SEEDS:
            self.assertEqual(survey.get(("B-5", seed)), survey.get(("S-D1", seed)), seed)

    def test_scaling_survey_readings_lie_within_the_ledger_range(self):
        sec = self.doc["scaling"]
        survey = _survey()
        for point in sec["points"] + sec["baseline"]:
            finished = [survey["finished"].get((point["id"], s)) for s in SURVEY_SEEDS]
            with self.subTest(point=point["id"]):
                self.assertNotIn(None, finished)
                self.assertGreaterEqual(point["finishedSeeds"], sum(1 for f in finished if f))
                self.assertGreaterEqual(32 - point["finishedSeeds"], sum(1 for f in finished if not f))
                for seed in SURVEY_SEEDS:
                    got = survey["readings"][(point["id"], seed)]
                    for name in SCALING_READINGS:
                        q = point["readings"][name]
                        self.assertTrue(q["min"] <= got[name] <= q["max"],
                                        f"seed {seed} {name}: {got[name]} outside [{q['min']}, {q['max']}]")

    def test_hard_coding_section_against_the_recomputed_outcomes(self):
        sec = self.doc["hardCoding"]
        self.assertEqual(set(sec), HC_KEYS)
        self.assertEqual(sec["decision"], "Q-RA10F-4")
        # The design leaves the ledger's bed shape open: whatever it carries must read as classes.json's bed.
        cfg_bed = self.cfg["hardCoding"]["bed"]
        flat = dict(cfg_bed, items=cfg_bed["load"]["items"], concurrency=cfg_bed["load"]["concurrency"])
        bed = sec["bed"]
        self.assertIsInstance(bed, dict)
        self.assertEqual(bed.get("id"), "G4-BED")
        self.assertTrue(set(bed) <= set(flat), sorted(set(bed) - set(flat)))
        for key, value in bed.items():
            self.assertEqual(value, flat[key], key)
        survey = _survey()
        counts = {}
        for policy in POLICIES:
            tally = {"identityPassSeeds": 0, "invariantSeeds": 0, "acceptedSeeds": 0, "acceptedWithoutCheckSeeds": 0}
            for seed in self.cfg["seeds"]:
                ident = survey["bed"].get((policy, "IDENTITY", seed))
                perm = survey["bed"].get((policy, "PERMUTED", seed))
                self.assertIsNotNone(ident, (policy, seed))
                self.assertIsNotNone(perm, (policy, seed))
                ident_t = _task_outcomes(ident, None)
                perm_t = _task_outcomes(perm, survey["sigma"][seed])
                passed = all(o == "PASS" for o in ident_t)
                invariant = perm_t == ident_t
                tally["identityPassSeeds"] += passed
                tally["invariantSeeds"] += invariant
                tally["acceptedSeeds"] += passed and invariant
                tally["acceptedWithoutCheckSeeds"] += passed
            counts[policy] = dict(tally, id=policy)
        # Section 6.2's expectations, then the ledger against the recomputation.
        self.assertEqual(counts["GENERAL"], {"id": "GENERAL", "identityPassSeeds": 32, "invariantSeeds": 32,
                                             "acceptedSeeds": 32, "acceptedWithoutCheckSeeds": 32})
        self.assertEqual(counts["HARD_CODED"], {"id": "HARD_CODED", "identityPassSeeds": 32, "invariantSeeds": 0,
                                                "acceptedSeeds": 0, "acceptedWithoutCheckSeeds": 32})
        for entry in sec["policies"]:
            self.assertEqual(set(entry), HC_POLICY_KEYS, entry.get("id"))
        self.assertEqual(sec["policies"], [counts[p] for p in POLICIES])
        self.assertEqual(sec["permutationNotIdentitySeeds"], 32)
        self.assertEqual(sec["gates"], {"generalAccepted": True, "hardCodedRefused": True, "controlFires": True,
                                        "safetyZero": True})
        self.assertEqual(sec["result"], "PASS")

    def test_hard_coding_permutation_is_never_the_identity_and_b5_2_holds(self):
        items = self.cfg["hardCoding"]["bed"]["load"]["items"]
        for seed in self.cfg["seeds"]:
            with self.subTest(seed=seed):
                sigma = _sigma(seed, items)
                self.assertEqual(sorted(sigma), list(range(1, items + 1)))
                self.assertNotEqual(sigma, list(range(1, items + 1)))
                k0 = _first_moved(sigma)
                problems = _problems(seed, items)
                # B5-2: the first moved item holds a task whose problem differs from the problem its id names.
                self.assertNotEqual(problems[sigma[k0 - 1]], problems[k0])
                self.assertNotEqual(_solve(problems[sigma[k0 - 1]]), _solve(problems[k0]))


# ---------------------------------------------------------------------------------------------
# Tests: the campaign record v2 (item 10)

class OracleP4CampaignTests(unittest.TestCase):
    """The CONF-A3-001 campaign record v2 (DESIGN section 8; B5-1, B5-3)."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}
        cls.record = _campaign()

    def test_campaign_record_v2_key_set_and_constants(self):
        rec = self.record
        # CONF-MAS-005 adds the key overRevision: packet 4's v2 key set is read as a subset.
        self.assertLessEqual(CAMPAIGN_KEYS, set(rec))
        self.assertEqual(rec["schemaVersion"], "r12.mas-campaign-record/v2")
        self.assertEqual(rec["campaign"], "MAS-RA-010 and MAS-RA-010-F")
        self.assertEqual(rec["consumer"], "CONF-A3-001 (input, HO-D2)")

    def test_packets_1_to_3_entries_are_v1s_and_packet_4s_entry(self):
        packets = self.record["packets"]
        # CONF-MAS-005 appends packet 5's entry: packets[:4] checked, packet 4's digest is 2d7130a's constant.
        self.assertEqual(len(packets), 5)
        digest, length = V1_RECORD["packets"]
        self.assertEqual(_canonical_sha256(packets[:length]), digest)
        self.assertEqual((packets[2]["commit"], packets[2]["resultsSha256"]), (None, P3_RESULTS_SHA256))
        here = hashlib.sha256((_HERE_PATH / "results.json").read_bytes()).hexdigest()
        p4_results = "7149f09d3585bd8c9a8cbf4ab075abd09e75a74b110fddbfdef5b8125470bb77"
        self.assertEqual(packets[3], {"packetId": "CONF-MAS-004", "commit": None, "resultsSha256": p4_results})
        # The v4 ledger's digest: results.json is the serialized in-process ledger.
        self.assertEqual(hashlib.sha256(_ledger.serialize(self.doc)).hexdigest(), here)

    def test_unchanged_sections_are_v1s(self):
        for key in ("recordedFails", "arms", "eventScopedReadings"):
            digest, length = V1_RECORD[key]
            with self.subTest(key=key):
                self.assertEqual(len(self.record[key]), length)
                self.assertEqual(_canonical_sha256(self.record[key]), digest)

    def test_classes_findings_and_not_claimed_additions(self):
        rec = self.record
        # CONF-MAS-005 appends C13, seven findings and three notClaimed lines: totals 13, 21 and 9.
        for key, total in (("classes", 13), ("findings", 21), ("notClaimed", 9)):
            digest, length = V1_RECORD[key]
            with self.subTest(key=key):
                self.assertEqual(len(rec[key]), total)
                self.assertEqual(_canonical_sha256(rec[key][:length]), digest)
        for entry, cid in zip(rec["classes"][10:], NEW_IDS):
            row = self.rows[cid]
            self.assertEqual(entry, {"id": cid, "kind": row["kind"], "packet": "CONF-MAS-004", "result": row["result"],
                                     "gates": row["gates"]})
        new = rec["findings"][10:14]  # CONF-MAS-005: packet 4's four findings, before packet 5's seven
        for entry in new:
            self.assertEqual(set(entry), {"id", "summary"})
            self.assertTrue(isinstance(entry["summary"], str) and entry["summary"].strip(), entry["id"])
        self.assertEqual({f["id"] for f in new}, NEW_FINDING_IDS)
        g1 = [f["summary"].lower() for f in new if f["id"] == "F-G1-1"][0]
        for word in ("duplicate", "contention", "message", "makespan"):
            self.assertIn(word, g1, "B5-1: the CENTRAL transient's statement")
        added = rec["notClaimed"][3:]
        self.assertTrue(all(isinstance(t, str) and t.strip() for t in added), added)
        text = " ".join(added).lower()
        for word in ("contention", "overfitting", "synthetic"):
            self.assertIn(word, text)

    def test_scaling_and_hard_coding_entries(self):
        rec, sec = self.record, self.doc["scaling"]
        self.assertEqual(set(rec["scaling"]), {"points", "baseline"})
        against = {a["point"]: a for a in sec["againstBaseline"]}
        self.assertEqual(len(rec["scaling"]["points"]), 10)
        for entry, point in zip(rec["scaling"]["points"], sec["points"]):
            with self.subTest(point=point["id"]):
                self.assertEqual(set(entry), CR_POINT_KEYS)
                self.assertEqual(entry, {
                    "id": point["id"], "family": point["family"], "workers": point["workers"], "items": point["items"],
                    "safety": "PASS", "finishedSeeds": point["finishedSeeds"],
                    "p50": {name: point["readings"][name]["p50"] for name in SCALING_READINGS},
                    "makespanRatioMilli": against[point["id"]]["makespanRatioMilli"],  # B5-3: the per-point value
                    "underperforms": against[point["id"]]["underperforms"]})
        self.assertEqual(len(rec["scaling"]["baseline"]), 5)
        for entry, point in zip(rec["scaling"]["baseline"], sec["baseline"]):
            with self.subTest(point=point["id"]):
                self.assertEqual(entry, {"id": point["id"], "items": point["items"], "safety": "PASS",
                                         "finishedSeeds": point["finishedSeeds"],
                                         "p50": {name: point["readings"][name]["p50"] for name in SCALING_READINGS}})
        hc = self.doc["hardCoding"]
        self.assertEqual(rec["hardCoding"], {"gates": hc["gates"], "result": hc["result"]})

    def test_campaign_record_equals_the_file_byte_for_byte(self):
        self.assertEqual(_ledger.serialize(self.record), (_HERE_PATH / "campaign-record.json").read_bytes())

    def test_campaign_record_holds_no_canary_or_home_path(self):
        text = _ledger.serialize(self.record).decode("utf-8")
        self.assertEqual(_personal_hits(text), [])


if __name__ == "__main__":
    unittest.main()
