"""CONF-DATA-001: the deterministic data-correctness simulation (Python 3.12 standard library only).

Each case of cases.json is a small world: actors, stores, fake clocks and faults, run by a seeded scheduler. A run is a
pure function of (case, arm, seed). Nothing here reads a file, opens a network or a process, or reads a clock. The
random source is seeded by (case, seed) only, so a case's arms see the same schedule and differ in the one switch that
names the arm (HR-D1's one-variable rule).

A run returns three readings, made independently of R12's judge (_judge.py):
- trace: what the implementation did, in the vector shape {id, family, setup, steps, expect}. expect is "ACCEPT", or
  {refuse: code} when the run broke its family's rule;
- broken: whether the run broke the rule, known from what the simulation did (a missing mechanism, or a bad outcome);
- violation: whether the business outcome, read from the final state, is wrong (an overspent budget, a stale write
  applied, an expired lease or token honoured, an effect applied twice, a record lost or unreadable, an erased record
  still served, unreported drift, a replay that does not reproduce).
The ledger checks that the judge returns expect in every run, that no violation happens without a broken rule, and the
per-arm gates. [sim mapping] marks this suite's own mapping of a contract rule onto the simulation.
"""
from __future__ import annotations

import hashlib
import json
import random

SEEDS = tuple(range(1, 33))
STORES = ("cache", "embedding", "index", "memoryVectors", "projection")
RESIDUALS = ("backup copies until their retention ends", "exports delivered before the erasure",
             "opaque references to the erased record, not disclosed by default")  # DD-04, PAR-D1's honest residuals


def _rng(case, seed):
    return random.Random(f"CONF-DATA-001/{case}/{seed}")


def _interleave(rng, seqs):
    """A random interleaving that keeps each sequence's own order."""
    queues = [list(s) for s in seqs if s]
    out = []
    while queues:
        i = rng.randrange(len(queues))
        out.append(queues[i].pop(0))
        if not queues[i]:
            queues.pop(i)
    return out


def _result(case, family, setup, steps, code, broken, violation, notes=None):
    trace = {"id": case, "family": family, "setup": setup, "steps": steps,
             "expect": {"refuse": code} if broken else "ACCEPT"}
    return {"trace": trace, "broken": bool(broken), "violation": bool(violation), "notes": notes or {}}


# RF-1 WRITE_SKEW --------------------------------------------------------------------------------------------------------
LOCKING = ("ROW_LOCK", "ADVISORY_LOCK", "SINGLE_WRITER")


def _budget(rng, guard, sizes, units, effects=None, crash=None):
    """Concurrent reservation transactions on one budget row.

    The store executes the guard: NONE and APPEND_ONLY apply every commit; SERIALIZABLE aborts a commit whose read set
    (the row) was written since its begin; the locking guards admit one transaction at a time from its begin [sim mapping:
    a row lock, an advisory lock and a single writer all serialize the read-decide-write section]. Every request arrives
    before any commits (the requests are concurrent). An aborted request retries, at most three times. effects: None,
    "after_commit" or "inside_tx" (an external effect keyed by the request, at a target that does not deduplicate).
    crash: the actor that crashes before its first commit and restarts (CP-1).
    """
    actors = [{"name": chr(97 + i), "size": n, "attempt": 0, "phase": "idle", "tx": None, "room": 0, "held": 0,
               "mark": 0, "landed": 0, "done": False} for i, n in enumerate(sizes)]
    total, writes, lock, steps, applied, aborted_issuers, reissued = 0, 0, None, [], {}, set(), False
    while True:
        live = [a for a in actors if not a["done"]]
        if not live:
            break
        if guard in LOCKING and lock is not None:
            live = [a for a in live if a["name"] == lock]
        fresh = [a for a in live if a["phase"] == "idle" and a["attempt"] == 0]
        actor = rng.choice(fresh or live)
        if actor["phase"] == "idle":
            if guard in LOCKING:
                lock = actor["name"]
            actor["tx"] = f"{actor['name']}{actor['attempt']}"
            actor.update(phase="begun", room=units - total, held=0, mark=writes)
            steps.append({"op": "begin", "tx": actor["tx"]})
        elif actor["phase"] == "begun":
            if actor["size"] <= actor["room"]:
                actor["held"] = actor["size"]
                steps.append({"op": "reserve", "tx": actor["tx"], "units": actor["size"]})
                if effects == "inside_tx":
                    key = f"effect-{actor['name']}"
                    if key in aborted_issuers:
                        reissued = True
                    applied[key] = applied.get(key, 0) + 1
                    steps.append({"op": "effect", "tx": actor["tx"], "key": key})
            actor["phase"] = "reserved"
        elif crash == actor["name"] and actor["attempt"] == 0:
            actor.update(phase="idle", attempt=1)  # CP-1: the process dies before its commit; the store rolls back
            lock = None if lock == actor["name"] else lock
        else:
            step = {"op": "commit", "tx": actor["tx"]}
            steps.append(step)
            if guard == "SERIALIZABLE" and actor["held"] and writes != actor["mark"]:
                step["aborted"] = True  # informational (Q-ORC-3 (a)); no judge reads it
                if effects == "inside_tx":
                    aborted_issuers.add(f"effect-{actor['name']}")
                actor.update(phase="idle", attempt=actor["attempt"] + 1)
                actor["done"] = actor["attempt"] > 3
            else:
                total += actor["held"]
                if actor["held"]:
                    writes += 1
                    actor["landed"] += 1
                    if effects == "after_commit":
                        key = f"effect-{actor['name']}"
                        applied[key] = applied.get(key, 0) + 1
                        steps.append({"op": "effect", "tx": actor["tx"], "key": key})
                actor["done"] = True
            lock = None if lock == actor["name"] else lock
    return {"steps": steps, "total": total, "landed": [a["landed"] for a in actors], "applied": applied,
            "reissued": reissued}


def ws01(arm, seed, case="WS-01"):
    rng = _rng(case, seed)
    units = rng.randint(1, 5)
    crash = seed % 4 == 1
    n = rng.randint(3, 4) if crash else rng.randint(2, 4)
    sizes = [rng.randint(units // 2 + 1, units) for _ in range(n)]  # each fits alone; any two overspend
    run = _budget(rng, arm, sizes, units, crash="a" if crash else None)
    violation = run["total"] > units or any(x > 1 for x in run["landed"])
    return _result(case, "RF-1", {"units": units, "guard": arm}, run["steps"], "DC_WRITE_SKEW", violation, violation,
                   {"crashPoint": "CP-1" if crash else None})


def ws02(arm, seed, case="WS-02"):
    """[sim mapping] one approval request's decision is a one-unit slot; approve and reject race for it."""
    rng = _rng(case, seed)
    run = _budget(rng, arm, [1, 1], 1)
    decisions = sum(run["landed"])
    return _result(case, "RF-1", {"units": 1, "guard": arm}, run["steps"], "DC_WRITE_SKEW", decisions > 1, decisions > 1)


def ws03(arm, seed, case="WS-03"):
    """SERIALIZABLE aborts the later of two overlapping requests; its retry must not reissue its external effect.
    No crash is injected here: a restart after a crash does not abort the transaction, so a reissue after a crash is
    outside RF-1's rule (finding F-CD-1; RF-4's operation IDs cover it)."""
    rng = _rng(case, seed)
    sizes = [rng.randint(1, 4), rng.randint(1, 4)]
    units = sum(sizes) + rng.randint(0, 3)  # both fit together; the abort is the guard's, not the budget's
    run = _budget(rng, "SERIALIZABLE", sizes, units, effects="after_commit" if arm == "EFFECT_AFTER_COMMIT" else "inside_tx")
    twice = any(v > 1 for v in run["applied"].values())
    broken = twice or run["reissued"] or run["total"] > units
    return _result(case, "RF-1", {"units": units, "guard": "SERIALIZABLE"}, run["steps"], "DC_WRITE_SKEW", broken,
                   twice or run["total"] > units)


# RF-2 FENCING -----------------------------------------------------------------------------------------------------------
def _fence(arm, seed, case):
    """Holder a pauses past its lease; b takes the lease with the next token; a resumes and writes (CP-5)."""
    rng = _rng(case, seed)
    lease = rng.randint(500, 3000)
    pause = int(lease * rng.uniform(1.5, 4.0))
    token = rng.randint(1, 50)
    stale_applied, steps = False, []
    steps.append({"op": "acquire", "holder": "a", "token": token})
    steps.append({"op": "write", "holder": "a", "token": token, "accepted": True})
    steps.append({"op": "expire", "holder": "a", "afterMs": lease, "pauseMs": pause})
    newest = token + 1
    steps.append({"op": "acquire", "holder": "b", "token": newest})
    for who in _interleave(rng, [["b"], ["a"]]):
        tok = newest if who == "b" else token
        ok = True if arm == "CHECK_OFF" else tok >= newest  # the store (FN-01) or the effect target (FN-02) checks
        steps.append({"op": "write", "holder": who, "token": tok, "accepted": ok})
        stale_applied = stale_applied or (ok and who == "a")
    setup = {"fencing": "NONE" if arm == "CHECK_OFF" else arm, "leaseMs": lease}
    return _result(case, "RF-2", setup, steps, "DC_FENCE", stale_applied, stale_applied, {"crashPoint": "CP-5"})


def fn01(arm, seed):
    return _fence(arm, seed, "FN-01")


def fn02(arm, seed):
    """[sim mapping] the effect target (an external API) checks the generation the write carries."""
    return _fence(arm, seed, "FN-02")


def fn03(arm, seed, case="FN-03"):
    """The lease store fails over between grants; its token counter is persisted, or reset in memory."""
    rng = _rng(case, seed)
    t0 = rng.randint(1, 50)
    steps = [{"op": "acquire", "holder": "a", "token": t0},
             {"op": "write", "holder": "a", "token": t0, "accepted": True},
             {"op": "expire", "holder": "a"},
             {"op": "acquire", "holder": "b", "token": t0 + 1},
             {"op": "write", "holder": "b", "token": t0 + 1, "accepted": True},
             {"op": "expire", "holder": "b"}]
    issued_max = t0 + 1
    # reset: an empty counter (odd seeds) or a replica one grant behind (even seeds) issues the next token
    c_token = issued_max + 1 if arm == "PERSISTED_COUNTER" else (1 if seed % 2 else issued_max)
    regressed = c_token <= issued_max
    table_newest = c_token  # the lease table's newest grant after the failover
    steps.append({"op": "acquire", "holder": "c", "token": c_token})
    stale = False
    for who in _interleave(rng, [["c"], ["b"]]):
        tok = c_token if who == "c" else t0 + 1
        ok = tok >= table_newest  # the store checks the token against the lease table
        steps.append({"op": "write", "holder": who, "token": tok, "accepted": ok})
        stale = stale or (ok and who == "b")
    return _result(case, "RF-2", {"fencing": "STORE_CHECKED_TOKEN", "failover": arm}, steps, "DC_FENCE",
                   regressed or stale, stale)


# RF-3 CLOCKS ------------------------------------------------------------------------------------------------------------
def ck01(arm, seed, case="CK-01"):
    """The wall clock jumps forward f ms early in the lease and back f + d ms before expiry, both within 5 s (design:
    -5 s to +5 s; Q-ORC-1 (a)). A check after the forward jump shows the monotonic lease still held (a wall-clock lease
    may end early, a liveness fault, not RF-3's refusal); a check after expiry falls inside the backward jump's window."""
    rng = _rng(case, seed)
    lease, wall0 = rng.randint(500, 3000), rng.randint(10 ** 6, 10 ** 7)
    f, d = rng.randint(1, 2500), rng.randint(1, 2500)
    t_f = rng.randint(1, lease // 3)
    early, mid = rng.randint(0, t_f - 1), rng.randint(t_f + 1, 2 * lease // 3)
    t_b = rng.randint(mid, lease)
    late = lease + rng.randint(1, d)
    events = [(early, "check", 0), (t_f, "jump", f), (mid, "check", 0), (t_b, "jump", -(f + d)), (late, "check", 0)]
    steps, offset, honoured = [{"op": "lease_start", "monotonicMs": 0, "wallMs": wall0, "leaseMs": lease}], 0, False
    for mono, kind, delta in events:
        if kind == "jump":
            offset += delta
            steps.append({"op": "wall_jump", "deltaMs": delta})
            continue
        wall = wall0 + mono + offset
        held = (mono <= lease) if arm == "MONOTONIC" else (wall - wall0 <= lease)
        honoured = honoured or (held and mono > lease)
        steps.append({"op": "lease_check", "monotonicMs": mono, "wallMs": wall, "held": held})
    return _result(case, "RF-3", {"expiry": arm}, steps, "DC_CLOCK", honoured, honoured)


def ck02(arm, seed, case="CK-02"):
    """A verifier whose clock is behind by up to the declared bound checks a token or approval expiry (CP-5 on resume)."""
    rng = _rng(case, seed)
    bound, expiry = rng.randint(50, 500), rng.randint(10 ** 6, 10 ** 7)
    skew = -rng.randint(1, bound)
    subject = "approval" if seed % 2 else "token"
    checks = [expiry - bound - rng.randint(1, 1000), expiry + rng.randint(0, -skew - 1)]  # valid, then expired
    margin = bound if arm == "DECLARED_MARGIN" else None
    steps, honoured = [], False
    for true_now in checks:
        local = true_now + skew
        accepted = local + (margin or 0) < expiry
        honoured = honoured or (accepted and true_now >= expiry)
        step = {"op": "wall_compare", "subject": subject, "localWallMs": local, "expiryWallMs": expiry,
                "accepted": accepted, "onResume": subject == "approval"}
        if margin is not None:
            step["skewMarginMs"] = margin
        steps.append(step)
    return _result(case, "RF-3", {"skewBoundMs": bound}, steps, "DC_CLOCK", margin is None, honoured,
                   {"crashPoint": "CP-5" if subject == "approval" else None})


def ck03(arm, seed, case="CK-03"):
    """Two writers reach the store gap ms apart; the later one's clock is behind by more than the gap."""
    rng = _rng(case, seed)
    gap = rng.randint(1, 100)
    behind = gap + rng.randint(1, 500)
    t = rng.randint(10 ** 6, 10 ** 7)
    writes = [{"writer": "x", "seq": 1, "fence": 7, "wallMs": t}, {"writer": "y", "seq": 2, "fence": 8, "wallMs": t + gap - behind}]
    by = "wall" if arm == "WALL" else ("sequence" if seed % 2 else "fencing_token")
    key = {"sequence": "seq", "fencing_token": "fence", "wall": "wallMs"}[by]
    winner = max(writes, key=lambda w: w[key])["writer"]
    steps = [{"op": "order", "by": by, "writers": ["x", "y"], "winner": winner}]
    return _result(case, "RF-3", {}, steps, "DC_CLOCK", by == "wall", winner != "y")


def ck04(arm, seed, case="CK-04"):
    """[R12 extension, provisional] the holder's host is replaced mid-lease; checks read the lease store's clock."""
    rng = _rng(case, seed)
    lease, wall0 = rng.randint(500, 3000), rng.randint(10 ** 6, 10 ** 7)
    replaced = rng.randint(lease // 4, 3 * lease // 4)
    late = lease + rng.randint(1, replaced)
    steps = [{"op": "lease_start", "monotonicMs": 0, "wallMs": wall0, "leaseMs": lease},
             {"op": "host_replace", "monotonicMs": replaced, "expirySource": arm}]
    start = 0 if arm == "PERSISTED_EXPIRY" else replaced  # in memory, the new host restarts the countdown
    honoured = late - start <= lease
    steps.append({"op": "lease_check", "monotonicMs": late, "held": honoured})
    return _result(case, "RF-3", {"expiry": arm}, steps, "DC_CLOCK", honoured, honoured)


# RF-4 OPERATION_IDS -----------------------------------------------------------------------------------------------------
def _calls(op, edge, cls, attempts, dedup, key_of=None, restart_at=None):
    """attempts: [(applies, answered)]; the callee deduplicates by operation ID (NATIVE) or key (RECEIPT_KEY) if dedup."""
    seen, applied, steps = set(), 0, []
    for i, (reaches, answered) in enumerate(attempts, start=1):
        ident = key_of(i) if key_of else op
        lands = reaches and not (dedup and ident in seen)
        if reaches:
            seen.add(ident)
        applied += lands
        step = {"op": "call", "operation": op, "edge": edge, "class": cls, "attempt": i,
                "outcome": ("committed" if lands else "final") if answered else "unknown", "applied": lands}
        if key_of:
            step["key"] = ident
        if restart_at == i:
            step["afterRestart"] = True
        steps.append(step)
    return steps, applied


def op01(arm, seed, case="OP-01"):
    """A NATIVE call times out and is retried under the same operation ID (CP-1: the caller dies after the callee
    applied; CP-3: the caller dies before the effect)."""
    rng = _rng(case, seed)
    lost = rng.randint(1, 3)  # attempts whose answer is lost before one is answered
    cp = {0: "CP-3", 1: "CP-1"}.get(seed % 4)
    attempts = [(not (cp == "CP-3" and i == 0), False) for i in range(lost)] + [(True, True)]
    steps, applied = _calls(f"op-{seed}", "caller->callee", "NATIVE", attempts, arm == "DEDUP")
    return _result(case, "RF-4", {}, steps, "DC_OPID", applied > 1, applied > 1, {"crashPoint": cp, "lostAnswers": lost})


def op02(arm, seed, case="OP-02"):
    """The outbox relay delivers, dies before marking the record delivered (CP-2) and redelivers after restart."""
    rng = _rng(case, seed)
    again = rng.randint(1, 3)
    steps, applied = _calls(f"op-{seed}", "outbox->effect", "NATIVE", [(True, False)] * again + [(True, True)],
                            arm == "DEDUP", restart_at=2)
    for s in steps:
        s["via"] = "outbox"
    return _result(case, "RF-4", {}, steps, "DC_OPID", applied > 1, applied > 1, {"crashPoint": "CP-2"})


def op03(arm, seed, case="OP-03"):
    """A NONE call's outcome is unknown (CP-4 when it was applied); it is reconciled through the status lookup."""
    landed = seed % 4 != 0
    attempts = [(landed, False)] + ([(True, True)] if arm == "RETRY" else [])
    steps, applied = _calls(f"op-{seed}", "caller->callee", "NONE", attempts, False)
    retried = arm == "RETRY"
    return _result(case, "RF-4", {}, steps, "DC_OPID", retried, applied > 1,
                   {"crashPoint": "CP-4" if landed else None, "reconciled": "committed" if landed else "rejected"})


def op04(arm, seed, case="OP-04"):
    """A RECEIPT_KEY call is retried after the caller restarts (CP-4 when attempt 1 was applied, CP-3 when not)."""
    rng = _rng(case, seed)
    fresh = [f"k-{rng.getrandbits(32):08x}" for _ in range(2)]
    op, edge = f"op-{seed}", "caller->callee"
    landed = seed % 4 != 0
    key_of = (lambda i: f"{op}/{edge}") if arm == "OP_EDGE_KEY" else (lambda i: fresh[i - 1])
    steps, applied = _calls(op, edge, "RECEIPT_KEY", [(landed, False), (True, True)], True, key_of, restart_at=2)
    return _result(case, "RF-4", {}, steps, "DC_OPID", arm != "OP_EDGE_KEY", applied > 1,
                   {"crashPoint": "CP-4" if landed else "CP-3"})


def op05(arm, seed, case="OP-05"):
    """The callee applies the effect and then raises; the retry must still be deduplicated."""
    rng = _rng(case, seed)
    later = rng.randint(1, 2)
    op = f"op-{seed}"
    on_exception = arm == "EVERY_PATH"
    steps = [{"op": "call", "operation": op, "edge": "caller->callee", "class": "NATIVE", "attempt": 1,
              "outcome": "unknown", "applied": True, "path": "exception", "dedup": on_exception}]
    applied = 1
    for i in range(2, 2 + later):
        lands = not on_exception and i == 2
        applied += lands
        steps.append({"op": "call", "operation": op, "edge": "caller->callee", "class": "NATIVE", "attempt": i,
                      "outcome": "committed" if lands else "final", "applied": lands})
    return _result(case, "RF-4", {}, steps, "DC_OPID", not on_exception, applied > 1)


def op06(arm, seed, case="OP-06"):
    """A bounded retry against a target without deduplication can apply twice, so no exactly-once claim holds."""
    rng = _rng(case, seed)
    bound = rng.randint(2, 5)
    _, applied = _calls(f"op-{seed}", "caller->callee", "NATIVE", [(True, False), (True, True)], False)
    claims = arm == "EXACTLY_ONCE_CLAIMED"
    steps = [{"op": "claim", "exactlyOnce": claims, "maxAttempts": bound}]
    return _result(case, "RF-4", {}, steps, "DC_OPID", claims, claims and applied > 1, {"targetAppliedTimes": applied})


TOOL_CLASSES = ("READ", "IDEMPOTENT_WRITE", "NON_IDEMPOTENT", "IRREVERSIBLE")


def op07(arm, seed, case="OP-07"):
    """[sim mapping] the tool effect class drives the idempotency class: READ retries freely with no effect,
    IDEMPOTENT_WRITE is NATIVE, NON_IDEMPOTENT is RECEIPT_KEY, IRREVERSIBLE is NONE after approval and is reconciled."""
    tool = TOOL_CLASSES[seed % 4]
    op, edge = f"op-{seed}", "tool-broker->tool"
    retry = tool != "IRREVERSIBLE" or arm == "IRREVERSIBLE_RETRIED"
    attempts = [(tool != "READ", False)] + ([(tool != "READ", True)] if retry else [])
    if tool == "NON_IDEMPOTENT":
        steps, applied = _calls(op, edge, "RECEIPT_KEY", attempts, True, lambda i: f"{op}/{edge}")
    else:
        cls = {"READ": "NATIVE", "IDEMPOTENT_WRITE": "NATIVE", "IRREVERSIBLE": "NONE"}[tool]
        steps, applied = _calls(op, edge, cls, attempts, tool != "IRREVERSIBLE")
    for s in steps:
        s["toolClass"] = tool
        if tool == "IRREVERSIBLE":
            s["approved"] = True
    broken = tool == "IRREVERSIBLE" and retry
    return _result(case, "RF-4", {}, steps, "DC_OPID", broken, applied > 1, {"crashPoint": "CP-4", "toolClass": tool})


# RF-5 COMPATIBILITY -----------------------------------------------------------------------------------------------------
def _write(version, amount, extra=None):
    record = {"v": version, "amount": amount}
    if version == "N":
        record["currency"] = "EUR"
    record.update(extra or {})
    return record


def _read(reader, record, tolerant=True):
    """A reader returns its view of a record, or None when it refuses it."""
    if record["v"] not in ("N-1", "N"):
        return None
    if reader == "N-1":
        if not tolerant and set(record) - {"v", "amount"}:
            return None
        view = dict(record)  # unknown members kept, without meaning
    else:
        if not tolerant and record["v"] == "N-1":
            return None
        view = dict(record)
        view.setdefault("currency", "EUR")
    return view if "amount" in view else None


def cv01(arm, seed, case="CV-01"):
    rng = _rng(case, seed)
    store = [_write(rng.choice(("N-1", "N")), rng.randint(1, 999)) for _ in range(rng.randint(5, 12))]
    steps, lost = [], False
    for _ in range(rng.randint(5, 12)):
        rec, reader = rng.choice(store), rng.choice(("N-1", "N"))
        view = _read(reader, rec)
        lost = lost or view is None or view["amount"] != rec["amount"]
        steps.append({"op": "read_record", "recordVersion": rec["v"], "reader": reader, "rollout": True,
                      "accepted": view is not None})
    return _result(case, "RF-5", {}, steps, "DC_VERSION", lost, lost)


def _readers(rng, case, arm, seed, writer, reader, tolerant_arm):
    store = [_write(writer, rng.randint(1, 999)) for _ in range(rng.randint(2, 6))]
    steps, refused = [], False
    for rec in store:
        view = _read(reader, rec, tolerant=arm == tolerant_arm)
        refused = refused or view is None
        steps.append({"op": "read_record", "recordVersion": rec["v"], "reader": reader, "rollout": True,
                      "accepted": view is not None})
    return _result(case, "RF-5", {}, steps, "DC_VERSION", refused, refused)


def cv02(arm, seed, case="CV-02"):
    """Rollback: N-1 readers read what N writers wrote."""
    return _readers(_rng(case, seed), case, arm, seed, "N", "N-1", "N_MINUS_1_READS_N")


def cv03(arm, seed, case="CV-03"):
    """Mid-rollout: N readers read what N-1 writers wrote."""
    return _readers(_rng(case, seed), case, arm, seed, "N-1", "N", "BOTH_VERSIONS")


def cv04(arm, seed, case="CV-04"):
    """[R12 extension, provisional] an N-1 writer rewrites an envelope that carries opaque extension data, one member of
    which names a role."""
    rng = _rng(case, seed)
    ext = {"role": "admin", f"x-{rng.randint(1, 99)}": rng.randint(1, 999)}
    envelope = {"v": "N", "body": {"amount": rng.randint(1, 999)}, "ext": dict(ext)}
    rewritten = {"v": "N", "body": dict(envelope["body"])}
    if arm != "DROPPED":
        rewritten["ext"] = dict(envelope["ext"])
    granted = arm == "ACTED_ON" and rewritten.get("ext", {}).get("role") == "admin"
    kept = rewritten.get("ext") == ext
    steps = [{"op": "store_envelope", "writer": "N-1", "extensionKept": kept, "extensionActedOn": granted}]
    return _result(case, "RF-5", {}, steps, "DC_VERSION", not kept or granted, not kept or granted)


def cv05(arm, seed, case="CV-05"):
    """A migration renames a member for N; a rollback then serves N-1 readers."""
    rng = _rng(case, seed)
    rows = [{"v": "N-1", "amount": rng.randint(1, 999)} for _ in range(rng.randint(2, 6))]
    with_rollback = arm == "PAIRS_AND_ROLLBACK"  # the control's one switch: ROLLBACK_MISSING
    migrated = [{"v": "N", "amountMinor": r["amount"] * 100, **({"amount": r["amount"]} if with_rollback else {})}
                for r in rows]  # [sim mapping] the rollback path is a dual write of the old member
    steps = [{"op": "migrate", "readerWriterPairs": True, "rollback": with_rollback}]
    unreadable = False
    for rec in migrated:
        view = _read("N-1", rec)
        unreadable = unreadable or view is None
        steps.append({"op": "read_record", "recordVersion": "N", "reader": "N-1", "rollout": True,
                      "accepted": view is not None})
    return _result(case, "RF-5", {}, steps, "DC_VERSION", not with_rollback or unreadable, unreadable)


def cv06(arm, seed, case="CV-06"):
    """Public, security-sensitive input rejects an unknown member and an unknown version; that is allowed."""
    rng = _rng(case, seed)
    steps = [{"op": "public_input", "unknownField": f"x-{rng.randint(1, 99)}", "version": "N+1", "rejected": True}
             for _ in range(rng.randint(1, 3))]
    return _result(case, "RF-5", {}, steps, "DC_VERSION", False, False)


# RF-6 DERIVED_DATA ------------------------------------------------------------------------------------------------------
def dd01(arm, seed, case="DD-01"):
    rng = _rng(case, seed)
    derived = sorted(rng.sample(STORES, rng.randint(2, 5)))
    docs = [f"doc-{i}" for i in range(1, rng.randint(2, 6) + 1)]
    gone = rng.choice(docs)
    skipped = rng.choice(derived)
    stores = {s: set(docs) for s in derived}
    reached = [s for s in derived if not (arm == "ONE_MISSED" and s == skipped)]
    for s in reached:
        stores[s].discard(gone)
    receipt = arm != "NO_RECEIPT"
    steps = [{"op": "insert", "id": d} for d in docs]
    steps.append({"op": "delete", "id": gone, "propagatedTo": reached, "receipt": receipt})
    served = any(gone in v for v in stores.values())
    return _result(case, "RF-6", {"derived": derived}, steps, "DC_DERIVED", served or not receipt, served or not receipt)


def _changes(rng):
    source, log, seq = {}, [], 0
    for _ in range(rng.randint(6, 14)):
        key = f"doc-{rng.randint(1, 5)}"
        seq += 1
        if key in source and rng.random() < 0.3:
            source.pop(key)
            log.append((seq, key, None))
        else:
            source[key] = rng.randint(1, 999)
            log.append((seq, key, source[key]))
    return source, log


def _rebuild(log):
    """[sim mapping] apply the change log by sequence: a change older than the key's last applied one is skipped."""
    last, out = {}, {}
    for seq, key, value in log:
        if seq <= last.get(key, 0):
            continue
        last[key] = seq
        if value is None:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def dd02(arm, seed, case="DD-02"):
    rng = _rng(case, seed)
    source, log = _changes(rng)
    delivered = log + [c for c in log if rng.random() < 0.3]
    rng.shuffle(delivered)
    index = _rebuild(delivered)
    drift = index != source
    steps = [{"op": "insert", "id": k, "seq": s} for s, k, v in log if v is not None]
    for s, k, v in log:
        if v is None:
            steps.append({"op": "delete", "id": k, "seq": s, "propagatedTo": ["index"], "receipt": True})
    steps.append({"op": "rebuild_compare", "driftFound": drift, "reported": True})
    return _result(case, "RF-6", {"derived": ["index"]}, steps, "DC_DERIVED", drift, drift)


def dd03(arm, seed, case="DD-03"):
    rng = _rng(case, seed)
    source, log = _changes(rng)
    index = _rebuild(log)
    if seed % 2 and index:
        index.pop(sorted(index)[0])  # a missing entry
    else:
        index["doc-stale"] = 0  # a stale entry
    found = index != source
    reported = found and arm == "REPORTED"
    steps = [{"op": "insert", "id": k} for k in sorted(source)]
    steps.append({"op": "rebuild_compare", "driftFound": found, "reported": reported})
    return _result(case, "RF-6", {"derived": ["index"]}, steps, "DC_DERIVED", found and not reported, found and not reported)


def dd04(arm, seed, case="DD-04"):
    """[R12 extension, provisional] restore from a backup taken before an erasure (PAR-D1's restore scenario)."""
    rng = _rng(case, seed)
    derived = sorted(rng.sample(STORES, rng.randint(1, 3)))
    docs = [f"doc-{i}" for i in range(1, rng.randint(2, 5) + 1)]
    gone = rng.choice(docs)
    backup = {s: set(docs) for s in ["source"] + derived}  # taken at t0, before the erasure
    ledger = [gone]  # the deletion ledger: receipts after t0
    restored = {s: set(v) for s, v in backup.items()}
    reapply = arm == "REAPPLIED"
    if reapply:
        for s in restored:
            restored[s].difference_update(ledger)
    steps = [{"op": "insert", "id": d} for d in docs]
    steps.append({"op": "delete", "id": gone, "propagatedTo": derived, "receipt": True})
    steps.append({"op": "restore", "backup": "t0", "reapplied": reapply})
    served = any(gone in v for v in restored.values())
    return _result(case, "RF-6", {"derived": derived}, steps, "DC_DERIVED", served, served, {"residuals": list(RESIDUALS)})


# RF-7 REPLAY_STATE ------------------------------------------------------------------------------------------------------
def _board(rng):
    """A board assigns each logged task to its least-loaded worker; load also changes by unlogged state updates."""
    workers = [f"w{i}" for i in range(rng.randint(3, 5))]
    loads = {w: rng.randint(1, 5) for w in workers}
    loads["w0"] = max(loads.values()) + 1  # w0 wins every tie on an empty board, so a log-only replay diverges
    events = []
    for i in range(rng.randint(3, 8)):
        events.append(("task", f"t{i}"))
        if rng.random() < 0.5:
            events.append(("load", rng.choice(workers), rng.randint(0, 3)))
    return workers, loads, events


def _apply(workers, loads, events, with_state):
    loads = dict(loads) if with_state else {w: 0 for w in workers}
    placed = []
    for e in events:
        if e[0] == "load":
            if with_state:
                loads[e[1]] += e[2]
            continue
        w = min(workers, key=lambda x: (loads[x], x))
        loads[w] += 1
        placed.append((e[1], w))
    return hashlib.sha256(json.dumps([placed, sorted(loads.items())]).encode()).hexdigest()


def _replay(arm, seed, case):
    rng = _rng(case, seed)
    workers, loads, events = _board(rng)
    recorded = _apply(workers, loads, events, True)
    given = ["log", "checkpoint-state"] if arm == "STATE_AS_INPUT" else ["log"]
    replayed = _apply(workers, loads, [e for e in events if e[0] == "task"] if given == ["log"] else events, given != ["log"])
    steps = [{"op": "replay", "inputs": given, "consulted": ["log", "checkpoint-state"]}]
    return _result(case, "RF-7", {}, steps, "DC_REPLAY_STATE", given == ["log"], replayed != recorded)


def rs01(arm, seed):
    return _replay(arm, seed, "RS-01")


def rs02(arm, seed):
    return _replay(arm, seed, "RS-02")


RUNNERS = {"WS-01": ws01, "WS-02": ws02, "WS-03": ws03, "FN-01": fn01, "FN-02": fn02, "FN-03": fn03, "CK-01": ck01,
           "CK-02": ck02, "CK-03": ck03, "CK-04": ck04, "OP-01": op01, "OP-02": op02, "OP-03": op03, "OP-04": op04,
           "OP-05": op05, "OP-06": op06, "OP-07": op07, "CV-01": cv01, "CV-02": cv02, "CV-03": cv03, "CV-04": cv04,
           "CV-05": cv05, "CV-06": cv06, "DD-01": dd01, "DD-02": dd02, "DD-03": dd03, "DD-04": dd04, "RS-01": rs01,
           "RS-02": rs02}


def run(case, arm, seed):
    return RUNNERS[case](arm, seed)
