"""TG-05 clocks verdicts (W04-4a, CONF-ENF-004): one case's checks from native timelines and answer logs.

In W06, on each enrolled host, `probes/enforcement/tg05_clocks` injects one native fault and writes a timeline; W06's driver
of W05's released build writes, for the same boot, one line per exchange it has with the gate or the reader (the SERVER)
for an execution, binds and channel openings included. This module judges the two together. It runs nothing on a host:
until W06 the inputs do not exist, and the tests in this package judge synthetic inputs instead, including the
implementations each case is meant to catch.

Rules (sources: the plan's obligation rows E07, E08 and E11, docs/alpha-2/ENFORCEMENT_FEASIBILITY.md at harness-onion
a2eab93, snapshotted by owner decision Q-T13 with its confirmed reading; the I05 v3 transcripts and the reference model's
own refusal order for the gate's answers):
- E08 "Suspended/blocked roles and clock changes cannot extend authority": the deadline is the signed instant expiresAt,
  mapped by the probe onto CLOCK_BOOTTIME (which counts suspended time) before any fault; a wall-clock step neither renews
  nor shortens it. Every gate exchange for the tested execution after the deadline is refused for a reason the I05 v3
  model gives that operation on an expired execution before any other check (EXPIRY_REASONS); an exchange already in
  flight at the deadline is not judged (T119).
- E07 "PID reuse, crash, replacement and channel loss deny; no reconnect or rebinding": after the broker is killed, every
  gate exchange for the tested execution is refused for a peer-loss reason (PEER_REASONS: T26, T38, T41, T60, T93 and the
  model's order); after the broker or the observer is killed, the reader fails every request of the tested execution
  (its inspections fail sticky, LEDGER-E09) and never rebinds, while an execution the gate binds after the restart is
  served.
- E11 "never resurrect ACTIVE from stale state" with E08's original deadlines: a restarted reader serves nothing of the
  execution it held, and serves one the gate binds after the restart (its fixed factories construct over the real kernel,
  LEDGER-E09).

Scope and windows. Every check is scoped to one execution: the tested one, named in the probe's binding, or one the gate
binds after a restart. A gate check needs the tested execution to have been the gate's bound, live execution at the fault
(an authority exchange ALLOWED within LIVE_WITHIN_NS before it, and no other execution allowed since); a reader check needs
the reader to have been serving it. A check judges only exchanges that lie wholly inside a window, MARGIN_NS inside each
end, where the implementation the case is meant to catch would still allow: a timer paused by the stall, stopped in
suspend, set by the wall clock or restarted with the reader. Once the gate allows another execution after the fault, the
tested one is no longer bound (I05 v3 binds a new execution after expiry, T36): from then on any refusal of it stands, a
reader window ends, but it may never be ALLOWED. Only HTTP_REQUEST, ARM_ACTION and BIND_EXECUTION are judged by
execution and show which execution the gate bound; ACTION_OUTCOME, GENERATION_STATUS and CLOSE_GENERATION are logged but
not judged; a channel opening is judged by generation (none may open into the tested execution's generation after the
fault, T38). A gate check passes only on a judged authority exchange (HTTP_REQUEST or ARM_ACTION).

A check is PASS only when it judged what it needs and every judged answer meets the rule; FAIL when a judged answer breaks
it; otherwise NOT_RUN_ENV_UNAVAILABLE. An input that breaks its schema raises Malformed; `verdict` records such a case as
NOT_RUN_ENV_UNAVAILABLE with the reason (AGENTS rule 14), never PASS. MARGIN_NS and LIVE_WITHIN_NS are parameters of this
test, not contract values. Standard library only (owner decision Q-T1).
"""
from __future__ import annotations

import json
import re

TIMELINE = "r12.enforcement-probe-timeline/v1"
ANSWERS = "r12.enforcement-answer-log/v1"
PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT_RUN_ENV_UNAVAILABLE"
MARGIN_NS = 1_000_000_000
LIVE_WITHIN_NS = 60 * 1_000_000_000
GATE_ANSWERS = {"ALLOWED", "REFUSED", "CLOSED"}
READER_ANSWERS = {"SERVED", "FAILED"}
GATE_OPERATIONS = {"HTTP_REQUEST", "ARM_ACTION", "BIND_EXECUTION", "CHANNEL_OPEN", "ACTION_OUTCOME", "GENERATION_STATUS",
                   "CLOSE_GENERATION"}
AUTHORITY = {"HTTP_REQUEST", "ARM_ACTION"}
# The exchanges judged by execution, and the only ones that show the gate bound an execution (review D5-2): a channel
# belongs to a generation, not an execution, and the other I05 operations only observe or end a generation.
EXECUTION_EXCHANGES = AUTHORITY | {"BIND_EXECUTION"}
# I05 v3 model, refusal order per operation (scripts/i05_gate_channel_v3.py): a request is refused CONNECTION_CLOSED or
# NOT_ACTIVE, then EXECUTION_EXPIRED, before any stamp or certificate check (T36, T62); an ARM is refused NOT_ACTIVE or
# DRAIN_PENDING, then EXECUTION_NOT_BOUND (another generation or execution, review D5-3), then EXECUTION_EXPIRED; a second
# BIND of the tested execution is refused NOT_ACTIVE, ACTION_OUTSTANDING or EXECUTION_REPLAY before anything else.
REBIND = {"NOT_ACTIVE", "ACTION_OUTSTANDING", "EXECUTION_REPLAY"}
EXPIRY_REASONS = {"HTTP_REQUEST": {"CONNECTION_CLOSED", "NOT_ACTIVE", "EXECUTION_EXPIRED"},
                  "ARM_ACTION": {"NOT_ACTIVE", "DRAIN_PENDING", "EXECUTION_NOT_BOUND", "EXECUTION_EXPIRED"},
                  "BIND_EXECUTION": REBIND}
# After the broker's death (T26, T38, T41, T60, T93): the channel ends PEER_LOST or PEER_CHANGED, the generation is held
# (a request or ARM is refused NOT_ACTIVE or on its closed connection), a frame from a changed peer is fatal PEER_CHANGED,
# an ARM in a new generation is refused EXECUTION_NOT_BOUND, and a rebind is refused as above or
# PEER_QUALIFICATION_MISMATCH. One channel per generation: no channel opens into the dead generation again (T38).
PEER_REASONS = {"HTTP_REQUEST": {"CONNECTION_CLOSED", "NOT_ACTIVE"},
                "ARM_ACTION": {"NOT_ACTIVE", "DRAIN_PENDING", "EXECUTION_NOT_BOUND", "PEER_LOST", "PEER_CHANGED"},
                "BIND_EXECUTION": REBIND | {"PEER_QUALIFICATION_MISMATCH", "PEER_CHANGED"}}
ANSWER_FIELDS = {"schemaVersion", "bootId", "sentBoottime", "answeredBoottime", "party", "operation", "execution",
                 "generation", "request", "answer", "reason"}
CLOCK_FIELDS = {"realtime", "monotonic", "boottime"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# I05 v3 channel.schema.json: every frame's generation is 64 lowercase hex characters (review R4-2).
GENERATION = re.compile(r"^[0-9a-f]{64}$")
BINDING_KEYS = {"MATRIX:expiry with stalled Python": {"route", "policyDigest", "expiresAt", "execution"},
                "MATRIX:suspend": {"route", "policyDigest", "expiresAt", "execution"},
                "MATRIX:wall-clock rollback": {"route", "policyDigest", "expiresAt", "execution"},
                "MATRIX:peer death/restart": {"route", "policyDigest", "expiresAt", "peer", "execution"},
                "MATRIX:original deadlines": {"route", "policyDigest", "expiresAt", "execution"}}
# The timeline records each case reads (kind, and the fault, name or what it matches); test_probes checks that the
# probe's case function writes each one (review D4-1).
RECORDS = {
    "MATRIX:expiry with stalled Python": [("deadline", None), ("fault", "SIGSTOP"), ("fault", "SIGCONT")],
    "MATRIX:suspend": [("deadline", None), ("fault", "SUSPEND")],
    "MATRIX:wall-clock rollback": [("deadline", None), ("fault", "CLOCK_SET"), ("observation", "rolledBackAtRestore"),
                                   ("restore", "CLOCK_SET")],
    "MATRIX:peer death/restart": [("deadline", None), ("fault", "SIGKILL")],
    "MATRIX:original deadlines": [("deadline", None), ("fault", "SIGKILL"), ("observation", "restarted")],
}
# Records a case reads when present (without them its checks are NOT_RUN, not malformed).
OPTIONAL_RECORDS = {"MATRIX:peer death/restart": [("observation", "restarted")]}


class Malformed(ValueError):
    """An input breaks its schema or is not the reviewed probe's; the case cannot be judged and is never PASS."""


def _strict(line):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise Malformed("duplicate key " + key)
            value[key] = item
        return value
    def constant(name):
        raise Malformed("non-finite number " + name)
    try:
        return json.loads(line, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as error:
        raise Malformed(str(error) or type(error).__name__) from None


def _integer(value, name):
    if type(value) is not int:
        raise Malformed(name + " is not an integer")
    return value


def _clocks(value):
    if type(value) is not dict or set(value) != CLOCK_FIELDS:
        raise Malformed("clocks must hold exactly realtime, monotonic and boottime")
    return {name: _integer(value[name], "clocks." + name) for name in CLOCK_FIELDS}


def read_timeline(lines, probe_tree):
    """The probe's records: start first, end last; the start names the reviewed probe tree, a boot and the binding."""
    records = [_strict(line) for line in lines if line.strip()]
    if len(records) < 2 or any(type(record) is not dict for record in records):
        raise Malformed("a timeline is a list of records")
    if records[0].get("kind") != "start" or records[-1].get("kind") != "end":
        raise Malformed("a timeline starts with start and ends with end")
    for record in records:
        if record.get("schemaVersion") != TIMELINE:
            raise Malformed("not a " + TIMELINE + " record")
        for key in ("clocks", "clocksBefore"):
            if key in record:
                record[key] = _clocks(record[key])
    start, end = records[0], records[-1]
    if start.get("probeTree") != probe_tree:
        raise Malformed("the timeline was not written by the reviewed probe tree")
    if type(start.get("bootId")) is not str or not BOOT_ID.match(start["bootId"]):
        raise Malformed("the timeline names no boot")
    if end.get("faultResult") not in (PASS, NOT_RUN):
        raise Malformed("faultResult is PASS or NOT_RUN_ENV_UNAVAILABLE")
    case = start.get("case")
    if case not in BINDING_KEYS:
        raise Malformed("not a TG-05 probe case: %r" % (case,))
    binding = start.get("binding")
    if type(binding) is not dict or set(binding) != BINDING_KEYS[case] or not all(type(value) is str for value in binding.values()):
        raise Malformed("the binding holds exactly the case's keys")
    # Owner decision Q-T14: a judged run names its W06 route and the loaded policy's digest.
    if not TOKEN.match(binding["route"]) or not DIGEST.match(binding["policyDigest"]) or not TOKEN.match(binding["execution"]):
        raise Malformed("the binding's route, policy digest or execution is malformed")
    return start, records[1:-1], end


def read_answers(lines, boot_id):
    """The driver's answer log for the same boot (BOOTTIME is comparable only within one boot)."""
    answers = []
    for line in lines:
        if not line.strip():
            continue
        row = _strict(line)
        if type(row) is not dict or set(row) != ANSWER_FIELDS or row["schemaVersion"] != ANSWERS:
            raise Malformed("an answer line holds exactly the " + ANSWERS + " fields")
        if row["bootId"] != boot_id:
            raise Malformed("an answer from another boot")
        sent, answered = _integer(row["sentBoottime"], "sentBoottime"), _integer(row["answeredBoottime"], "answeredBoottime")
        if answered < sent:
            raise Malformed("answered before sent")
        if row["party"] == "GATE":
            if row["operation"] not in GATE_OPERATIONS or row["answer"] not in GATE_ANSWERS:
                raise Malformed("a gate exchange names one of its operations and answers")
        elif row["party"] == "SERVER":
            if row["operation"] != "REQUEST" or row["answer"] not in READER_ANSWERS:
                raise Malformed("a reader exchange is a REQUEST answered SERVED or FAILED")
        else:
            raise Malformed("party is GATE or SERVER")
        for name in ("execution", "request"):
            if type(row[name]) is not str or not row[name]:
                raise Malformed(name + " is a non-empty string")
        for name in ("generation", "reason"):
            if row[name] is not None and type(row[name]) is not str:
                raise Malformed(name + " is a string or null")
        if (row["answer"] in ("REFUSED", "CLOSED")) != (row["reason"] is not None):
            raise Malformed("a refusal or close carries its reason, and nothing else does")
        if row["party"] == "GATE" and not (type(row["generation"]) is str and GENERATION.match(row["generation"])):
            # Reviews D6-1, R1-1, R4-2: every gate exchange names the generation it was sent in (a channel opening, the one
            # it opens) in the I05 v3 form, 64 lowercase hex characters: no null, empty or placeholder generation.
            raise Malformed("a gate exchange names its generation in the I05 v3 form")
        answers.append(row)
    return answers


def _one(records, kind, **match):
    found = [row for row in records if row.get("kind") == kind and all(row.get(key) == value for key, value in match.items())]
    if len(found) != 1:
        raise Malformed("expected exactly one %s record matching %s" % (kind, match))
    return found[0]


def _at(record):
    if "clocks" not in record:
        raise Malformed("a %s record without clocks" % record.get("kind"))
    return record["clocks"]["boottime"]


def _deadline(records):
    return _integer(_one(records, "deadline")["boottime"], "deadline.boottime")


def _check(check_id, rule, judged, broken, empty_reason):
    observed = {"judged": len(judged), "broken": [row["request"] for row in broken]}
    if broken:
        return {"id": check_id, "rule": rule, "result": FAIL, "observed": observed,
                "reason": "%d judged answer(s) break the rule" % len(broken)}
    if not judged:
        return {"id": check_id, "rule": rule, "result": NOT_RUN, "observed": observed, "reason": empty_reason}
    return {"id": check_id, "rule": rule, "result": PASS, "observed": observed, "reason": None}


def _not_run(check_id, rule, reason):
    return {"id": check_id, "rule": rule, "result": NOT_RUN, "observed": {}, "reason": reason}


def _gate(answers):
    """The gate exchanges judged by execution, in send order."""
    return sorted((row for row in answers if row["party"] == "GATE" and row["operation"] in EXECUTION_EXCHANGES),
                  key=lambda row: row["sentBoottime"])


def _generation_at(answers, execution, instant):
    """The generation the tested execution was bound in at the fault: the one its last allowed BIND_EXECUTION before the
    fault names, when every allowed exchange of it since that bind names the same one (I05 v3 binds an execution in one
    generation); None when its bind is not logged or its rows disagree (reviews D6-1, R1-1, R2-1: whatever word a driver
    writes, the generation comes from the bind and is checked against the rows, never taken from one row alone)."""
    allowed = [row for row in _gate(answers) if row["execution"] == execution and row["answer"] == "ALLOWED"
               and row["sentBoottime"] < instant]
    binds = [index for index, row in enumerate(allowed) if row["operation"] == "BIND_EXECUTION"]
    if not binds:
        return None
    generation = allowed[binds[-1]]["generation"]
    return generation if all(row["generation"] == generation for row in allowed[binds[-1]:]) else None


def _reconnects(answers, generation, since):
    """Channels allowed into the tested execution's generation after the fault, at any later time, and any second allowed
    opening of one generation, whatever the labels (I05 v3: one channel per generation, T38; reviews D5-2, R1-3, R3-1):
    always broken."""
    openings = sorted((row for row in answers if row["party"] == "GATE" and row["operation"] == "CHANNEL_OPEN"
                       and row["answer"] == "ALLOWED"), key=lambda row: row["sentBoottime"])
    seen, broken = set(), []
    for row in openings:
        if row["generation"] in seen or (generation is not None and row["generation"] == generation and row["sentBoottime"] > since):
            broken.append(row)
        seen.add(row["generation"])
    return broken


def _bound_at(answers, execution, instant):
    """The tested execution was the gate's bound, live execution at the fault (reviews D3-2, D4-5): its last authority or
    bind exchange sent before the fault was ALLOWED, within LIVE_WITHIN_NS of it, and no other execution was allowed since."""
    before = [row for row in _gate(answers) if row["sentBoottime"] < instant]
    mine = [row for row in before if row["execution"] == execution]
    if not mine or mine[-1]["answer"] != "ALLOWED" or instant - mine[-1]["answeredBoottime"] > LIVE_WITHIN_NS:
        return False
    return not any(row["execution"] != execution and row["answer"] == "ALLOWED" and row["sentBoottime"] > mine[-1]["sentBoottime"]
                   for row in before)


def _served_at(answers, execution, instant):
    """The reader was serving the tested execution at the fault: its last reader answer sent before it was SERVED, within
    LIVE_WITHIN_NS."""
    mine = sorted((row for row in answers if row["party"] == "SERVER" and row["execution"] == execution
                   and row["sentBoottime"] < instant), key=lambda row: row["sentBoottime"])
    return bool(mine) and mine[-1]["answer"] == "SERVED" and instant - mine[-1]["answeredBoottime"] <= LIVE_WITHIN_NS


def _replaced(answers, execution, fault):
    """When the gate first allowed another execution after the fault (it bound a new one), or never (review D4-2)."""
    return min((row["sentBoottime"] for row in _gate(answers) if row["execution"] != execution and row["answer"] == "ALLOWED"
                and row["sentBoottime"] > fault), default=float("inf"))


def _within(rows, since, until):
    """The rows whose whole exchange lies inside (since, until), a margin inside each end (review D3-4)."""
    return [row for row in rows if row["sentBoottime"] > since + MARGIN_NS and row["answeredBoottime"] < until - MARGIN_NS]


def _gate_check(check_id, rule, answers, execution, fault, since, until, reasons, empty_reason, forbidden_from,
                judged_after=None):
    """The tested execution's gate exchanges in the window are judged. Until the gate binds another execution after the
    fault, each is refused for a reason `reasons` gives its operation; after that the execution is no longer bound and any
    refusal stands (I05 v3 binds a new execution after expiry, T36). Broken at any time, inside the window or not (review
    R1-3): an ALLOWED exchange of the tested execution sent after `forbidden_from` (the deadline, or the broker's death),
    and a channel allowed into its generation after the fault. PASS needs a judged authority exchange (sent after
    `judged_after` when given: review D5-1)."""
    generation = _generation_at(answers, execution, fault)
    mine = [row for row in _gate(answers) if row["execution"] == execution]
    window = _within(mine, since, until)
    replaced = _replaced(answers, execution, fault)
    before = [row for row in window if row["answeredBoottime"] < replaced]
    broken = [row for row in mine if row["answer"] == "ALLOWED" and row["sentBoottime"] > forbidden_from + MARGIN_NS]
    broken += [row for row in before if row["answer"] != "ALLOWED" and row["reason"] not in reasons.get(row["operation"], ())]
    broken += _reconnects(answers, generation, fault)
    judged = [row for row in before if row["operation"] in AUTHORITY
              and (judged_after is None or row["sentBoottime"] > judged_after + MARGIN_NS)]
    return _check(check_id, rule, judged, broken, empty_reason)


def _reader_check(check_id, rule, answers, execution, fault, since, deadline, empty_reason, judged_after=None):
    """The tested execution's reader answers in the window are judged: every one FAILED. The window ends at the
    execution's own deadline, or when the gate binds another execution (reviews D3-3, D4-4): after either, even a reader
    the check is meant to catch fails the old execution. A SERVED answer sent after `since` is broken at any time, inside
    the window or not (review R1-3). PASS needs a judged answer sent after `judged_after` when given (D5-1)."""
    until = min(deadline, _replaced(answers, execution, fault))
    mine = [row for row in answers if row["party"] == "SERVER" and row["execution"] == execution]
    window = _within(mine, since, until)
    judged = [row for row in window if judged_after is None or row["sentBoottime"] > judged_after + MARGIN_NS]
    broken = [row for row in mine if row["answer"] == "SERVED" and row["sentBoottime"] > since + MARGIN_NS]
    return _check(check_id, rule, judged, broken, empty_reason)


def _fresh_check(check_id, rule, answers, restarted):
    """Executions the gate bound (allowed) after the restart and that had no exchange before it: the reader's answers for
    them sent after their first allowance. PASS when some is SERVED (the construction works on the real kernel); FAIL
    when there are some and none is SERVED; NOT_RUN when there is none (review D4-3)."""
    old = {row["execution"] for row in answers if row["sentBoottime"] <= restarted}
    bound = {}
    for row in _gate(answers):
        if row["answer"] == "ALLOWED" and row["execution"] not in old and row["sentBoottime"] > restarted:
            bound.setdefault(row["execution"], row["answeredBoottime"])
    # Each fresh execution's answers end when the gate binds yet another execution (review D5-7).
    ends = {execution: _replaced(answers, execution, at) for execution, at in bound.items()}
    fresh = [row for row in answers if row["party"] == "SERVER" and row["execution"] in bound
             and bound[row["execution"]] + MARGIN_NS < row["sentBoottime"] and row["answeredBoottime"] < ends[row["execution"]]]
    observed = {"judged": len(fresh), "served": sum(row["answer"] == "SERVED" for row in fresh)}
    if not fresh:
        return {"id": check_id, "rule": rule, "result": NOT_RUN, "observed": observed,
                "reason": "no reader answer for an execution the gate bound after the restart"}
    if not observed["served"]:
        return {"id": check_id, "rule": rule, "result": FAIL, "observed": observed,
                "reason": "no execution the gate bound after the restart was served"}
    return {"id": check_id, "rule": rule, "result": PASS, "observed": observed, "reason": None}


NO_AUTHORITY = ("E08: every gate exchange for the tested execution after the deadline (expiresAt on BOOTTIME) is refused "
                "for a reason the I05 v3 model gives that operation on an expired execution; never ALLOWED")


def expiry_with_stalled_python(start, records, answers):
    """SERVER and the worker leaf's processes (the CPython roles) are stopped before the deadline and SERVER stays stopped
    past it. When SERVER resumes, the authority has already ended without it: judged are the gate's exchanges for the
    tested execution from the resume until the time a timer paused by the stall would have kept allowing."""
    execution = start["binding"]["execution"]
    deadline = _deadline(records)
    stop, resume = _at(_one(records, "fault", fault="SIGSTOP")), _at(_one(records, "fault", fault="SIGCONT"))
    if not stop < deadline < resume:
        return [_not_run("E08-STALLED", NO_AUTHORITY, "the stall did not cover the deadline")]
    if not _bound_at(answers, execution, stop):
        return [_not_run("E08-STALLED", NO_AUTHORITY, "the tested execution was not bound and live at the stall")]
    return [_gate_check("E08-STALLED", NO_AUTHORITY, answers, execution, stop, resume, resume + (deadline - stop),
                        EXPIRY_REASONS, "no gate exchange for the tested execution while a paused timer would still allow",
                        forbidden_from=deadline)]


def suspend(start, records, answers):
    """The host suspends before the deadline and resumes after it; suspended time counts (E08). Judged are the gate's
    exchanges after the resume, until the time a timer that stops in suspend (MONOTONIC) would have kept allowing."""
    execution = start["binding"]["execution"]
    deadline = _deadline(records)
    fault = _one(records, "fault", fault="SUSPEND")
    if "clocksBefore" not in fault:
        raise Malformed("a suspend record without clocksBefore")
    before, after = fault["clocksBefore"], fault["clocks"]
    awake = after["monotonic"] - before["monotonic"]
    # The deadline lies inside the suspended stretch even if all awake time of the entry and exit fell on one side.
    if not before["boottime"] + awake < deadline < after["boottime"] - awake:
        return [_not_run("E08-SUSPEND", NO_AUTHORITY, "the suspend did not cover the deadline")]
    if not _bound_at(answers, execution, before["boottime"]):
        return [_not_run("E08-SUSPEND", NO_AUTHORITY, "the tested execution was not bound and live at the suspend")]
    return [_gate_check("E08-SUSPEND", NO_AUTHORITY, answers, execution, before["boottime"], after["boottime"],
                        after["boottime"] + (deadline - before["boottime"]) - awake, EXPIRY_REASONS,
                        "no gate exchange for the tested execution while a timer stopped in suspend would still allow",
                        forbidden_from=deadline)]


def wall_clock_rollback(start, records, answers):
    """The wall clock is set back before the deadline and stays back until the restore; a step neither renews nor shortens
    the deadline (E08, Q-T13). Judged are the gate's exchanges after the deadline while the wall clock is still behind,
    until the time a timer set by the wall clock would have kept allowing."""
    execution = start["binding"]["execution"]
    deadline = _deadline(records)
    fault = _one(records, "fault", fault="CLOCK_SET")
    back = _integer(fault.get("rolledBackNs"), "rolledBackNs")
    held_record = _one(records, "observation", name="rolledBackAtRestore")
    held = _integer(held_record.get("value"), "rolledBackAtRestore")
    _one(records, "restore", what="CLOCK_SET")
    if not (_at(fault) < deadline and held >= back - MARGIN_NS):
        return [_not_run("E08-ROLLBACK", NO_AUTHORITY, "the wall clock was not set back before the deadline or did not stay back")]
    if not _bound_at(answers, execution, _at(fault)):
        return [_not_run("E08-ROLLBACK", NO_AUTHORITY, "the tested execution was not bound and live at the step")]
    # The window ends at the last reading taken while the clock was still behind, before the restore (review D3-4).
    return [_gate_check("E08-ROLLBACK", NO_AUTHORITY, answers, execution, _at(fault), deadline,
                        min(_at(held_record), deadline + back), EXPIRY_REASONS,
                        "no gate exchange for the tested execution after the deadline while the wall clock was behind",
                        forbidden_from=deadline)]


PEER_GATE = ("E07: after the broker's death every gate exchange for the tested execution is refused for the peer's loss "
             "(I05 v3: the held generation, the closed connection or channel, a changed peer, a refused rebind or second "
             "channel), never allowed in any generation, and nothing logged in the dead generation is allowed (no "
             "reconnect among the restarted broker's logged channel attempts; review R2-5)")
PEER_READER = ("E07 and LEDGER-E09 (carried): after the peer's death the reader fails every request of the tested "
               "execution, before and after the peer's restart (its inspections fail sticky; no rebinding)")
PEER_INSPECTION = ("LEDGER-E09 (carried): after the peer's restart an execution the gate binds is served, so the reader's "
                   "inspections of the restarted peer construct past their first native read on the real kernel")


def peer_death_restart(start, records, answers):
    """A peer of the reader is killed while the tested execution is bound and served, and restarts. The gate's check runs
    for the broker only (the gate's own I05 peer); the reader's for both (the owner of the observer and broker
    inspections). Every window ends at the tested execution's deadline; the E07 checks judge exchanges after the restart,
    where a reconnect or a rebinding would show (review D5-1). The case needs one run per peer."""
    peer, execution = start["binding"]["peer"], start["binding"]["execution"]
    if peer not in ("BROKER", "OBSERVER"):
        raise Malformed("peer is BROKER or OBSERVER")
    deadline = _deadline(records)
    kill = _one(records, "fault", fault="SIGKILL")
    if kill.get("role") != peer:
        raise Malformed("the killed role is not the binding's peer")
    killed = _at(kill)
    restarts = [row for row in records if row.get("kind") == "observation" and row.get("name") == "restarted"]
    if len(restarts) > 1 or (restarts and _at(restarts[0]) <= killed):
        raise Malformed("at most one restart, observed after the kill")
    rules = dict(([("E07-GATE", PEER_GATE)] if peer == "BROKER" else [])
                 + [("E07-READER-" + peer, PEER_READER), ("E09-INSPECTION-" + peer, PEER_INSPECTION)])
    if not restarts:
        # Review D6-8: each check carries its own rule.
        return [_not_run(check_id, rule, "the peer did not restart: reconnect and rebinding were not tested")
                for check_id, rule in rules.items()]
    restarted = _at(restarts[0])
    checks = []
    if peer == "BROKER":
        dead = _generation_at(answers, execution, killed)
        # The dead broker's generation is held (T26): nothing at all is allowed in it after the kill, whatever the
        # operation or execution (a reconnect, a status frame, a bind of another execution: reviews R1-2, R2-2).
        used = [row for row in answers if row["party"] == "GATE" and row["answer"] == "ALLOWED" and dead is not None
                and row["generation"] == dead and row["sentBoottime"] > killed + MARGIN_NS]
        binds = [row for row in _gate(answers) if row["execution"] == execution and row["operation"] == "BIND_EXECUTION"
                 and row["answer"] == "ALLOWED" and row["sentBoottime"] < killed]
        created = dead is not None and binds and any(
            row["party"] == "GATE" and row["operation"] == "CHANNEL_OPEN" and row["answer"] == "ALLOWED"
            and row["generation"] == dead and row["sentBoottime"] < binds[-1]["sentBoottime"] for row in answers)
        # Review R2-3: only attempts before the tested execution's deadline count (the schedule puts them first). Review
        # R5-1: they count from the kill (recorded once the old broker exited, so any later attempt is the new broker's),
        # not from the restart record, which the probe's polling may write after the new broker has already connected.
        attempts = [row for row in answers if row["party"] == "GATE" and row["operation"] == "CHANNEL_OPEN"
                    and killed < row["sentBoottime"] < deadline - MARGIN_NS]
        if not _bound_at(answers, execution, killed):
            checks.append(_not_run("E07-GATE", PEER_GATE, "the tested execution was not bound and live at the kill"))
        else:
            # Review R4-4: the judged requests come after the restarted broker's first channel attempt (the schedule).
            first_attempt = min((row["sentBoottime"] for row in attempts), default=restarted)
            check = _gate_check("E07-GATE", PEER_GATE, answers, execution, killed, killed, deadline, PEER_REASONS,
                                "no gate exchange for the tested execution after the restarted broker's channel attempt and "
                                "before its deadline", forbidden_from=killed, judged_after=first_attempt)
            # A violation that needs no generation FAILs first (review R3-2); then the reconnect part must be judgeable.
            if check["result"] == FAIL:
                checks.append(check)
            elif used:
                checks.append(_check("E07-GATE", PEER_GATE, [], used, ""))
            elif dead is None or len(binds) != 1 or not created:
                # Reviews R2-1, R3-1: the dead generation is the one the tested execution's single logged bind names, and a
                # logged channel opening created it before that bind; otherwise a reconnect cannot be judged.
                checks.append(_not_run("E07-GATE", PEER_GATE, "the tested execution's generation is not established by "
                                                             "one logged bind in a logged channel opening"))
            elif not attempts:
                # Review R1-2: a reconnect shows only in the restarted broker's channel attempts, which the driver must log.
                checks.append(_not_run("E07-GATE", PEER_GATE, "no channel attempt of the restarted broker is logged before "
                                                             "the deadline"))
            else:
                checks.append(check)
    if _served_at(answers, execution, killed):
        checks.append(_reader_check("E07-READER-" + peer, PEER_READER, answers, execution, killed, killed, deadline,
                                    "no reader answer for the tested execution after the restart and before its deadline",
                                    judged_after=restarted))
    else:
        checks.append(_not_run("E07-READER-" + peer, PEER_READER, "the reader was not serving the tested execution at the kill"))
    checks.append(_fresh_check("E09-INSPECTION-" + peer, PEER_INSPECTION, answers, restarted))
    return checks


ORIGINAL_GATE = ("E08 original deadlines: the reader's restart renews nothing; every gate exchange for the tested execution "
                 "after the original deadline is refused as expired, until the time a deadline restarted with the reader "
                 "would have kept allowing")
ORIGINAL_READER = ("E11 and LEDGER-E09 (carried): the restarted reader serves nothing of the execution it held (never "
                   "resurrect ACTIVE from stale state)")
CONSTRUCTION = ("LEDGER-E09 (carried): the restarted reader's fixed factories construct over the real kernel, so an "
                "execution the gate binds after the restart is served")


def original_deadlines(start, records, answers):
    """The reader (SERVER) is killed before the deadline while the tested execution is bound and served, and restarts."""
    execution = start["binding"]["execution"]
    deadline = _deadline(records)
    kill = _one(records, "fault", fault="SIGKILL")
    if kill.get("role") != "SERVER":
        raise Malformed("the killed role is not the SERVER")
    killed, restarted = _at(kill), _at(_one(records, "observation", name="restarted"))
    if not killed < restarted:
        raise Malformed("the restart is observed after the kill")
    if not killed < deadline:
        return [_not_run(check_id, ORIGINAL_GATE, "the reader was killed only after the deadline")
                for check_id in ("E08-ORIGINAL", "E11-STALE", "E09-CONSTRUCTION")]
    checks = []
    if _bound_at(answers, execution, killed):
        checks.append(_gate_check("E08-ORIGINAL", ORIGINAL_GATE, answers, execution, killed, deadline,
                                  restarted + (deadline - killed), EXPIRY_REASONS,
                                  "no gate exchange for the tested execution after the original deadline while a restarted "
                                  "one would allow", forbidden_from=deadline))
    else:
        checks.append(_not_run("E08-ORIGINAL", ORIGINAL_GATE, "the tested execution was not bound and live at the kill"))
    if _served_at(answers, execution, killed):
        checks.append(_reader_check("E11-STALE", ORIGINAL_READER, answers, execution, killed, restarted, deadline,
                                    "no reader answer for the tested execution between the restart and its deadline"))
    else:
        checks.append(_not_run("E11-STALE", ORIGINAL_READER, "the reader was not serving the tested execution at the kill"))
    checks.append(_fresh_check("E09-CONSTRUCTION", CONSTRUCTION, answers, restarted))
    return checks


CASES = {
    "MATRIX:expiry with stalled Python": expiry_with_stalled_python,
    "MATRIX:suspend": suspend,
    "MATRIX:wall-clock rollback": wall_clock_rollback,
    "MATRIX:peer death/restart": peer_death_restart,
    "MATRIX:original deadlines": original_deadlines,
}
# Each case's checks; the peer case needs one run per peer (BROKER and OBSERVER).
CHECKS = {
    "MATRIX:expiry with stalled Python": ["E08-STALLED"],
    "MATRIX:suspend": ["E08-SUSPEND"],
    "MATRIX:wall-clock rollback": ["E08-ROLLBACK"],
    "MATRIX:peer death/restart": ["E07-GATE", "E07-READER-BROKER", "E09-INSPECTION-BROKER", "E07-READER-OBSERVER",
                                  "E09-INSPECTION-OBSERVER"],
    "MATRIX:original deadlines": ["E08-ORIGINAL", "E11-STALE", "E09-CONSTRUCTION"],
}
# The checks that judge the reader's answers (a LEDGER-E09 property is carried only by these).
READER_CHECKS = {"E07-READER-BROKER", "E09-INSPECTION-BROKER", "E07-READER-OBSERVER", "E09-INSPECTION-OBSERVER", "E11-STALE",
                 "E09-CONSTRUCTION"}


def judge_run(timeline_lines, answer_lines, probe_tree):
    """One probe run: {"case", "faultResult", "checks"}; no checks when the fault did not take effect."""
    start, records, end = read_timeline(timeline_lines, probe_tree)
    answers = read_answers(answer_lines, start["bootId"])
    if end["faultResult"] != PASS:
        return {"case": start["case"], "faultResult": end["faultResult"], "checks": []}
    return {"case": start["case"], "faultResult": PASS, "checks": CASES[start["case"]](start, records, answers)}


def judge_case(case, runs, probe_tree):
    """A case from its runs (timeline lines, answer lines): PASS only when every one of its checks was judged PASS in a run
    whose fault took effect; FAIL when any judged check failed; NOT_RUN_ENV_UNAVAILABLE otherwise. Raises Malformed."""
    judged = [judge_run(timeline, answers, probe_tree) for timeline, answers in runs]
    if any(run["case"] != case for run in judged):
        raise Malformed("a run of another case")
    checks = [check for run in judged for check in run["checks"]]
    ids = [check["id"] for check in checks]
    if len(ids) != len(set(ids)) or not set(ids) <= set(CHECKS[case]):
        raise Malformed("a check judged twice or not the case's")
    results = {check["id"]: check["result"] for check in checks}
    if FAIL in results.values():
        result = FAIL
    elif set(results) == set(CHECKS[case]) and set(results.values()) == {PASS}:
        result = PASS
    else:
        result = NOT_RUN
    return {"case": case, "runs": [run["faultResult"] for run in judged], "checks": checks, "result": result}


def verdict(case, runs, probe_tree):
    """What W06 records for a case: judge_case's result, or NOT_RUN_ENV_UNAVAILABLE with the reason when an input is
    malformed (review D4-7: only AGENTS rule 14's results, and never PASS for an input that could not be judged)."""
    try:
        return judge_case(case, runs, probe_tree)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        # Review D5-5: an input of any wrong shape is unusable, not only one the readers name.
        return {"case": case, "runs": [], "checks": [], "result": NOT_RUN, "reason": "malformed input: %s" % error}
