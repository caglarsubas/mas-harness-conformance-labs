"""CONF-DATA-001: R12's judge for data-correctness traces (Python 3.12 standard library only).

The judge restates, in R12's own words, the seven rule families of harness-onion's data-correctness record (DATA-CORRECTNESS-001,
packet MET-007; pins in contracts.json). No bytes of the contract's reference model are copied or imported. A trace is
{id, family, setup, steps, expect}: each step states what an implementation did, with its observed outcome. judge(trace)
returns "ACCEPT" or {"refuse": code}; the families run in the record's order and the first one whose rule is broken names
the code. A malformed trace raises ValueError; that is not a code.

What each family refuses (the record's property, as R12 reads it):
- RF-1 DC_WRITE_SKEW: reservations that commit beyond the budget's units, because no covering guard (SERIALIZABLE,
  ROW_LOCK, ADVISORY_LOCK, SINGLE_WRITER) aborted a transaction whose read set had changed; or an external effect issued
  again after an earlier issuer of the same key was aborted. An abort is remembered when a retry reuses the aborted
  transaction's name (packet review CD-P1-1; the reference model at the pinned commit forgets it, finding F-CD-2).
- RF-2 DC_FENCE: a grant whose token does not exceed the newest grant; a write accepted from a holder whose lease lapsed,
  or with a token older than the newest grant.
- RF-3 DC_CLOCK: a lease reported held after its duration on the monotonic clock; a wall-clock comparison with no declared
  skew margin; an ordering keyed on wall-clock time.
- RF-4 DC_OPID: a claim of exactly-once delivery; deduplication skipped on an exception path; a NONE effect retried; a
  receipt key that changes between attempts of one operation on one edge; an effect applied twice for one operation, edge
  and class.
- RF-5 DC_VERSION: a read refused during a rollout; a stored envelope that loses its opaque extension data; a migration
  without its reader-writer pairs and its rollback. Public input may reject unknown fields and versions.
- RF-6 DC_DERIVED: a deletion that misses a derived store or has no receipt; drift found by a rebuild-and-compare audit and
  not reported.
- RF-7 DC_REPLAY_STATE: a replay that consults durable state it was not given as an input beside the log.

R12 extensions, provisional (Q-CD-4), which the reference model has no op or field for:
- RF-3 `host_replace`: a marker that the lease holder's host was replaced. Lease checks keep reading the lease store's
  clock, so a holder that restarts its countdown in memory is caught by the held-after-duration rule.
- RF-5 `extensionActedOn` on `store_envelope`: extension data that granted meaning or authority.
- RF-6 `restore`: a restore from a backup after a deletion that does not re-apply the deletion ledger.
A trace that uses one of them has parity R12_EXTENSION; every other trace has parity MODEL_OPS.
"""
from __future__ import annotations

FAMILIES = ("RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7")
CODES = ("DC_WRITE_SKEW", "DC_FENCE", "DC_CLOCK", "DC_OPID", "DC_VERSION", "DC_DERIVED", "DC_REPLAY_STATE")
CODE_OF = dict(zip(FAMILIES, CODES))
MODEL_OPS = {
    "RF-1": ("begin", "reserve", "commit", "effect"),
    "RF-2": ("acquire", "expire", "write"),
    "RF-3": ("lease_start", "wall_jump", "lease_check", "wall_compare", "order"),
    "RF-4": ("call", "claim"),
    "RF-5": ("read_record", "store_envelope", "migrate", "public_input"),
    "RF-6": ("insert", "delete", "rebuild_compare"),
    "RF-7": ("replay",),
}
EXTENSION_OPS = {"RF-3": ("host_replace",), "RF-6": ("restore",)}
EXTENSION_FIELDS = (("store_envelope", "extensionActedOn"),)
COVERING = ("SERIALIZABLE", "ROW_LOCK", "ADVISORY_LOCK", "SINGLE_WRITER")
NOT_COVERING = ("NONE", "APPEND_ONLY")
VERSIONS = ("N-1", "N")
ORDER_KEYS = ("sequence", "fencing_token", "wall")
CLASSES = ("NATIVE", "NONE", "RECEIPT_KEY")
MEMBERS = ("expect", "family", "id", "setup", "steps")

_FAMILY_OF = {}
for _fam in FAMILIES:
    for _op in MODEL_OPS[_fam] + EXTENSION_OPS.get(_fam, ()):
        _FAMILY_OF[_op] = _fam


def _req(ok, why):
    if not ok:
        raise ValueError(why)


def _whole(value, why):
    _req(type(value) is int, why)
    return value


def family_of(op):
    return _FAMILY_OF.get(op)


def parity(trace):
    """MODEL_OPS, or R12_EXTENSION when a step uses an op or field the reference model lacks."""
    for step in trace["steps"]:
        fam = _FAMILY_OF.get(step.get("op"))
        if step.get("op") in EXTENSION_OPS.get(fam, ()):
            return "R12_EXTENSION"
        if any(step.get("op") == op and field in step for op, field in EXTENSION_FIELDS):
            return "R12_EXTENSION"
    return "MODEL_OPS"


def check_shape(trace):
    _req(type(trace) is dict and tuple(sorted(trace)) == MEMBERS, "a trace has exactly id, family, setup, steps, expect")
    _req(type(trace["id"]) is str and trace["id"] != "", "the id is a non-empty string")
    _req(trace["family"] in FAMILIES, "the family is RF-1 to RF-7")
    _req(type(trace["setup"]) is dict, "setup is an object")
    _req(type(trace["steps"]) is list and len(trace["steps"]) > 0, "steps is a non-empty list")
    expect = trace["expect"]
    _req(expect == "ACCEPT" or (type(expect) is dict and list(expect) == ["refuse"] and expect["refuse"] in CODES),
         "expect is ACCEPT or {refuse: code}")
    for step in trace["steps"]:
        _req(type(step) is dict and _FAMILY_OF.get(step.get("op")) == trace["family"],
             "every step's op belongs to the trace's family")


def _rf1(setup, steps):
    units = _whole(setup.get("units"), "RF-1 setup states the units")
    guard = setup.get("guard")
    _req(guard in COVERING + NOT_COVERING, "RF-1 setup states a known guard")
    total, landed, txs, issued, aborted, begun = 0, 0, {}, [], set(), {}
    for step in steps:
        name = step.get("tx")
        _req(type(name) is str, "an RF-1 step names its transaction")
        if step["op"] == "begin":
            begun[name] = begun.get(name, 0) + 1  # each begin of a name is its own transaction instance
            txs[name] = {"room": units - total, "mark": landed, "held": 0, "aborted": False}
            continue
        _req(name in txs, "an RF-1 step follows its transaction's begin")
        tx = txs[name]
        if step["op"] == "reserve":
            n = _whole(step.get("units"), "a reservation states its units")
            _req(0 < n <= tx["room"] - tx["held"], "a reservation fits the room its transaction read")
            tx["held"] += n
        elif step["op"] == "commit":
            if guard in COVERING and tx["held"] > 0 and landed != tx["mark"]:
                tx["aborted"] = True
                aborted.add((name, begun[name]))
            else:
                total += tx["held"]
                landed += 1
        else:
            issued.append(((name, begun[name]), step.get("key")))
    for key in sorted({k for _, k in issued}, key=repr):
        by = [i for i, k in issued if k == key]
        if len(by) > 1 and any(i in aborted for i in by[:-1]):
            return True
    return total > units


def _rf2(setup, steps):
    newest, lapsed, broken = None, set(), False
    for step in steps:
        who = step.get("holder")
        _req(type(who) is str and who != "", "an RF-2 step names its holder")
        if step["op"] == "acquire":
            token = _whole(step.get("token"), "a grant states its token")
            if newest is not None and token <= newest:
                return True
            newest = token
            lapsed.discard(who)
        elif step["op"] == "expire":
            lapsed.add(who)
        elif step.get("accepted") is True:
            token = _whole(step.get("token"), "a write states its token")
            if who in lapsed or (newest is not None and token < newest):
                broken = True
    return broken


def _rf3(setup, steps):
    lease = None
    for step in steps:
        op = step["op"]
        if op == "lease_start":
            lease = (_whole(step.get("monotonicMs"), "a lease start states its monotonic time"),
                     _whole(step.get("leaseMs"), "a lease start states its duration"))
        elif op == "lease_check":
            _req(lease is not None, "a lease check follows a lease start")
            now = _whole(step.get("monotonicMs"), "a lease check states its monotonic time")
            if step.get("held") is True and now - lease[0] > lease[1]:
                return True
        elif op == "wall_compare":
            if step.get("skewMarginMs") is None:
                return True
        elif op == "order":
            _req(step.get("by") in ORDER_KEYS, "an ordering states its key")
            if step["by"] == "wall":
                return True
    return False


def _rf4(setup, steps):
    keys, applied = {}, {}
    for step in steps:
        if step["op"] == "claim":
            if step.get("exactlyOnce") is True:
                return True
            continue
        cls = step.get("class")
        _req(cls in CLASSES, "a call states its idempotency class")
        op, edge = step.get("operation"), step.get("edge")
        _req(type(op) is str and type(edge) is str, "a call states its operation ID and its edge")
        attempt = _whole(step.get("attempt"), "a call states its attempt")
        if step.get("path") == "exception" and step.get("dedup") is False:
            return True
        if cls == "NONE" and attempt > 1:
            return True
        if cls == "RECEIPT_KEY":
            _req(type(step.get("key")) is str, "a RECEIPT_KEY call states its key")
            if keys.setdefault((op, edge), step["key"]) != step["key"]:
                return True
        if step.get("applied") is True:
            where = (op, edge, cls)
            applied[where] = applied.get(where, 0) + 1
            if applied[where] > 1:
                return True
    return False


def _rf5(setup, steps):
    for step in steps:
        op = step["op"]
        if op == "read_record":
            _req(step.get("recordVersion") in VERSIONS and step.get("reader") in VERSIONS, "a read states both versions")
            if step.get("rollout") is True and step.get("accepted") is not True:
                return True
        elif op == "store_envelope":
            if step.get("extensionKept") is not True or step.get("extensionActedOn") is True:
                return True
        elif op == "migrate":
            if step.get("readerWriterPairs") is not True or step.get("rollback") is not True:
                return True
    return False


def _rf6(setup, steps):
    derived, deleted = setup.get("derived"), False
    for step in steps:
        op = step["op"]
        if op == "delete":
            _req(type(derived) is list and len(derived) > 0, "RF-6 setup states its derived stores")
            deleted = True
            if sorted(step.get("propagatedTo") or []) != sorted(derived) or step.get("receipt") is not True:
                return True
        elif op == "rebuild_compare":
            if step.get("driftFound") is True and step.get("reported") is not True:
                return True
        elif op == "restore":
            if deleted and step.get("reapplied") is not True:
                return True
    return False


def _rf7(setup, steps):
    for step in steps:
        given, read = step.get("inputs"), step.get("consulted")
        _req(type(given) is list and type(read) is list, "a replay states its inputs and what it consulted")
        if set(read) - set(given):
            return True
    return False


RULES = dict(zip(FAMILIES, (_rf1, _rf2, _rf3, _rf4, _rf5, _rf6, _rf7)))


def judge(trace):
    """ACCEPT, or {refuse: code} for the first family, in the record's order, whose rule the trace breaks."""
    check_shape(trace)
    for fam in FAMILIES:
        steps = [s for s in trace["steps"] if _FAMILY_OF[s["op"]] == fam]
        if steps and RULES[fam](trace["setup"], steps):
            return {"refuse": CODE_OF[fam]}
    return "ACCEPT"
