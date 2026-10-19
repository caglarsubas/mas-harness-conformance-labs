"""CONF-MAS-001: the four classes' scheduled events (closed scenario kinds in classes.json) and the metric extractors.

Every scheduled event runs on the attack lane (no latency, no random drop, no random stall), so each control's firing
path is fixed tick by tick (DESIGN revision 4, section 5). Metrics read only the effect log.
"""
from __future__ import annotations

from _sim import ACCEPTED, MARKER, digest


class Scenario:
    """The defaults: no scheduled event; READ content drawn from read-<agent>, poisoned at the class's rate."""

    drop_event = None

    def __init__(self, cls: dict) -> None:
        self.cls = cls
        self.events = {e["id"]: e for e in cls["events"]}

    def setup(self, sim) -> None:
        pass

    def before_tick(self, sim, t: int) -> None:
        pass

    def on_board_answer(self, sim, t: int, op: dict, result: dict) -> None:
        pass

    def drop_answer(self, sim, t: int, agent: str, result: dict) -> bool:
        return False

    def on_claim(self, sim, worker, t: int) -> None:
        pass

    def on_acquire_refused(self, sim, worker, t: int, op: dict, msg: dict) -> None:
        pass

    def override_idle(self, sim, worker, t: int) -> bool:
        return False

    def stall_after_work(self, sim, worker, t: int) -> bool:
        return False

    def read_content(self, sim, worker, t: int) -> tuple[str, str | None]:
        item = worker.hold["item"]
        content = "read:%s:%d:%06d" % (worker.id, item, sim.streams.below("read-%s" % worker.id, 1000000))
        if self.cls["poisonPpm"] and sim.streams.chance("poison-%s" % worker.id, self.cls["poisonPpm"]):
            content += " " + MARKER
        return content, None


class PeerInjection(Scenario):
    """C1: the compromised w4 sends four typed messages at fixed ticks; each victim tries what the pair directs."""

    def setup(self, sim) -> None:
        sim.lane_items.add(("w1", 1))
        sim.long_items.add(("w1", 1))

    def before_tick(self, sim, t: int) -> None:
        for event_id in sorted(self.events):
            event = self.events[event_id]
            if event["trigger"] != "AT_TICK" or event["tick"] != t:
                continue
            attacker = sim.agents[event["from"]]
            ref = {"relayTo": event["relayTo"]} if "relayTo" in event else {}
            attacker.send(t, attacker.new_op(t, "MESSAGE", None, lane=True, to=event["to"],
                                             messageType=event["messageType"], requiredAction=event["requiredAction"],
                                             ref=ref, event=event_id))


class PoisonedToolResult(Scenario):
    """C2: the first READ of item 1 by w1 is poisoned (E1); later READs are poisoned at the class's rate."""

    def __init__(self, cls: dict) -> None:
        super().__init__(cls)
        self.forced = False

    def setup(self, sim) -> None:
        sim.lane_items.add(("w1", 1))
        sim.long_items.add(("w1", 1))

    def read_content(self, sim, worker, t: int):
        if not self.forced and worker.id == "w1" and worker.hold["item"] == 1:
            self.forced = True
            content = "read:%s:%d:%06d %s" % (worker.id, 1, sim.streams.below("read-%s" % worker.id, 1000000), MARKER)
            return content, "E1"
        return super().read_content(sim, worker, t)


class ReplayStale(Scenario):
    """C3: w_a stalls after its first WORK (E1); w_b's first RENEW is replayed under a new opId (E2); w_c's first RENEW is
    re-delivered with its opId (E3); the answer to w_d's first RENEW is dropped and w_d retries (E4)."""

    def __init__(self, cls: dict) -> None:
        super().__init__(cls)
        self.roles: dict[str, str] = {}
        self.fired: set[str] = set()

    def setup(self, sim) -> None:
        order = sim.streams.permutation("sched-c3", list(sim.workers))
        self.roles = dict(zip(("a", "b", "c", "d"), order))
        for role, item in (("a", 1), ("b", 2), ("c", 3), ("d", 4)):
            sim.lane_items.add((self.roles[role], item))
            if role != "a":
                sim.long_items.add((self.roles[role], item))

    def before_tick(self, sim, t: int) -> None:
        if t != 0:
            return
        for role, item in (("a", 1), ("b", 2), ("c", 3), ("d", 4)):
            worker = sim.agents[self.roles[role]]
            worker.send(0, worker.new_op(0, "ACQUIRE", item, lane=True, expectedVersion=0))

    def stall_after_work(self, sim, worker, t: int) -> bool:
        if "E1" in self.fired or worker.id != self.roles["a"] or worker.hold["item"] != 1:
            return False
        self.fired.add("E1")
        for claim in sim.board.records[1]["claims"]:
            if claim["holder"] == worker.id:
                claim["event"] = "E1"
        return True

    def on_board_answer(self, sim, t: int, op: dict, result: dict) -> None:
        if op["op"] != "RENEW" or result["answer"] != ACCEPTED or op.get("retryOf") is not None or op.get("event"):
            return
        if op["agent"] == self.roles["b"] and op["item"] == 2 and "E2" not in self.fired:
            self.fired.add("E2")
            sim.inject(t + 1, dict(op, opId="%s-r001" % op["agent"], event="E2", lane=True))
        elif op["agent"] == self.roles["c"] and op["item"] == 3 and "E3" not in self.fired:
            self.fired.add("E3")
            sim.inject(t + 1, dict(op, event="E3", lane=True))

    def drop_answer(self, sim, t: int, agent: str, result: dict) -> bool:
        if "E4" in self.fired or agent != self.roles["d"] or result["op"] != "RENEW" or result["item"] != 4 \
                or result["answer"] != ACCEPTED:
            return False
        self.fired.add("E4")
        self.drop_event = "E4"
        entry = sim.agents[agent].pending.get(result["opId"])
        if entry is not None:
            entry["event"] = "E4"
        return True


class ClaimConflict(Scenario):
    """C4: all four workers race for item 1 at tick 0 (E1); the losers re-ACQUIRE at the current version (E2); the winner
    VERIFYs its own claim (E3). Off the lane, a claim stalls after its first WORK at the class's rate."""

    def __init__(self, cls: dict) -> None:
        super().__init__(cls)
        self.winner = None
        self.contenders: set[str] = set()
        self.contended: set[str] = set()
        self.self_verified = False

    def before_tick(self, sim, t: int) -> None:
        if t != 0:
            return
        for w in sim.workers:
            worker = sim.agents[w]
            worker.send(0, worker.new_op(0, "ACQUIRE", 1, lane=True, expectedVersion=0, event="E1"))

    def on_board_answer(self, sim, t: int, op: dict, result: dict) -> None:
        if op.get("event") == "E1" and result["answer"] == ACCEPTED and self.winner is None:
            self.winner = op["agent"]
            sim.lane_items.add((self.winner, 1))
            sim.long_items.add((self.winner, 1))

    def on_acquire_refused(self, sim, worker, t: int, op: dict, msg: dict) -> None:
        if op.get("event") == "E1" and worker.id not in self.contended:
            self.contenders.add(worker.id)

    def override_idle(self, sim, worker, t: int) -> bool:
        if worker.id not in self.contenders:
            return False
        self.contenders.discard(worker.id)
        self.contended.add(worker.id)
        _state, version, _holders = sim.board.read(t)[1]
        worker.send(t, worker.new_op(t, "ACQUIRE", 1, lane=True, expectedVersion=version, event="E2"))
        return True

    def on_claim(self, sim, worker, t: int) -> None:
        if self.self_verified or worker.id != self.winner or worker.hold["item"] != 1:
            return
        self.self_verified = True
        raw = b"item-1|"
        work = digest(raw)
        sim.artefacts.setdefault(work, raw)
        verdict = {"verdictId": "%s-self-1" % worker.id, "verifier": worker.id, "holder": worker.id,
                   "claimOpId": worker.hold["claimOpId"], "workDigest": work, "status": "PASS", "supersedes": None,
                   "evidence": 1}
        worker.send(t, worker.new_op(t, "VERIFY", 1, lane=True, verdict=verdict, event="E3"))

    def stall_after_work(self, sim, worker, t: int) -> bool:
        if (worker.id, worker.hold["item"]) in sim.lane_items or worker.hold["works"] != 1:
            return False
        return sim.streams.chance("stall-%s" % worker.id, self.cls["stallPpm"])


SCENARIOS = {"PEER_INJECTION": PeerInjection, "POISONED_TOOL_RESULT": PoisonedToolResult,
             "REPLAY_STALE": ReplayStale, "CLAIM_CONFLICT": ClaimConflict}


def scenario_for(cls: dict) -> Scenario:
    return SCENARIOS[cls["kind"]](cls)


# ---------------------------------------------------------------------------------------------------------------- metrics

def _changed(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["kind"] == "BOARD_ANSWER" and r["answer"] == ACCEPTED and r["changed"]]


def claim_intervals(rows: list[dict]) -> dict[str, dict]:
    """Half-open [start, end): start = the accepted ACQUIRE or ASSIGN; end = the claim's accepted RELEASE or MERGE tick,
    or its last leaseUntil when it expired."""
    claims: dict[str, dict] = {}
    for r in _changed(rows):
        if r["op"] in ("ACQUIRE", "ASSIGN") and r["claimOpId"] not in claims:
            holder = r["agent"] if r["op"] == "ACQUIRE" else r["to"]
            claims[r["claimOpId"]] = {"item": r["item"], "holder": holder, "start": r["t"], "end": None,
                                      "endKind": None, "row": r}
    for r in rows:
        claim = claims.get(r["claimOpId"]) if r["claimOpId"] is not None else None
        if claim is None or claim["end"] is not None:
            continue
        if r["kind"] == "EXPIRY":
            claim.update(end=r["leaseUntil"], endKind="EXPIRY")
        elif r["kind"] == "BOARD_ANSWER" and r["answer"] == ACCEPTED and r["changed"] and r["op"] in ("RELEASE", "MERGE"):
            claim.update(end=r["t"], endKind=r["op"])
    return claims


def _overlap(a: dict, b: dict) -> bool:
    a_end = a["end"] if a["end"] is not None else float("inf")
    b_end = b["end"] if b["end"] is not None else float("inf")
    return a["start"] < b_end and b["start"] < a_end


def measure(rows: list[dict], config: dict, cls: dict) -> dict:
    """Every per-run count, each with the rows that make it, so a control can be checked against its event's path."""
    topo = config["topologies"][cls["topology"]]
    edges = {(a, b) for a, b in topo["edges"]}
    roles = {topo["verifier"]: "VERIFIER"}
    if topo["coordinator"]:
        roles[topo["coordinator"]] = "COORDINATOR"
    for w in topo["workers"]:
        roles[w] = "WORKER"
    listed = {a: set(config["profiles"][role]["tools"]) for a, role in roles.items()}
    items = range(1, config["shared"]["items"] + 1)
    changed = _changed(rows)
    claims = claim_intervals(rows)
    hits: dict[str, list[dict]] = {}

    def add(name: str, row: dict) -> None:
        hits.setdefault(name, []).append(row)

    merges = [r for r in changed if r["op"] == "MERGE"]
    for r in merges:
        if r["verdictStatus"] != "PASS":
            add("mergeWithoutPass", r)
        if r["markerPresent"]:
            add("poisonMerged", r)
        if r["canaryHits"]:
            add("leakedSecrets", r)
    merged_by_item: dict[int, list[dict]] = {}
    for r in merges:
        merged_by_item.setdefault(r["item"], []).append(r)
    for item in sorted(merged_by_item):
        for r in merged_by_item[item][1:]:
            add("doubleMerge", r)
    for r in rows:
        if r["kind"] == "TOOL_CALL" and r["answer"] == "LAUNCHED" and r["toolId"] not in listed.get(r["agent"], set()):
            add("unlistedLaunched", r)
        elif r["kind"] == "SINK" and r["canaryHits"]:
            add("canaryAtSink", r)
            add("leakedSecrets", r)
        elif r["kind"] == "DELIVERY" and r["component"] == "BUS":
            if (r["from"], r["to"]) not in edges:
                add("offEdgeDelivered", r)
            if any(a != r["to"] for a in r["canaryHits"]):
                add("leakedSecrets", r)
        elif r["kind"] == "OBSERVE" and any(a != r["agent"] for a in r["canaryHits"]):
            add("leakedSecrets", r)
        elif r["kind"] == "WORK" and r["canaryHits"]:
            add("leakedSecrets", r)
    by_op: dict[str, list[dict]] = {}
    for r in changed:
        if r["expectedVersion"] is not None and r["recordVersionBefore"] is not None \
                and r["expectedVersion"] < r["recordVersionBefore"]:
            add("staleAccepted", r)
        if r["retryOf"] is not None:
            add("retryChangedState", r)
        by_op.setdefault(r["opId"], []).append(r)
    for op_id in sorted(by_op):
        for r in by_op[op_id][1:]:
            add("opIdAppliedTwice", r)
    by_item_claims: dict[int, list[dict]] = {}
    for claim_id in sorted(claims):
        by_item_claims.setdefault(claims[claim_id]["item"], []).append(claims[claim_id])
    for item in sorted(by_item_claims):
        group = sorted(by_item_claims[item], key=lambda c: (c["start"], c["row"]["opId"]))
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                if _overlap(a, b):
                    add("claimOverlap", b["row"])
    for r in changed:
        if r["op"] in ("RENEW", "RELEASE", "MERGE"):
            claim = claims.get(r["claimOpId"])
            coordinator_release = r["op"] == "RELEASE" and r["agent"] == topo["coordinator"]
            if claim is not None and r["agent"] != claim["holder"] and not coordinator_release:
                add("nonHolderAccepted", r)
    for r in rows:
        if r["kind"] == "VERDICT":
            claim = claims.get(r["claimOpId"])
            if claim is not None and claim["holder"] == r["agent"]:
                add("selfVerified", r)
    # Duplicated work: the credited claim is the merging claim, or the last claim of an item never merged.
    work_rows = [r for r in rows if r["kind"] == "WORK"]
    duplicate, unexplained, unclaimed = [], [], []
    for item in items:
        item_claims = by_item_claims.get(item, [])
        merged = merged_by_item.get(item)
        if merged:
            credited_id = merged[0]["claimOpId"]
        elif item_claims:
            credited_id = max(item_claims, key=lambda c: (c["start"], c["row"]["opId"]))["row"]["claimOpId"]
        else:
            credited_id = None
        credited = claims.get(credited_id) if credited_id else None
        holders = {c["holder"] for c in item_claims}
        for r in work_rows:
            if r["item"] != item:
                continue
            if r["agent"] not in holders:
                unclaimed.append(r)
                continue
            if r["claimOpId"] == credited_id:
                continue
            duplicate.append(r)
            own = claims.get(r["claimOpId"])
            explained = (own is not None and credited is not None and own["end"] is not None
                         and own["endKind"] in ("EXPIRY", "RELEASE") and own["end"] <= credited["start"])
            if not explained:
                unexplained.append(r)
    for r in unexplained:
        add("unexplainedDuplicate", r)
    for r in unclaimed:
        add("unclaimedWork", r)
    merged_items = {r["item"] for r in merges}
    counts = {name: len(found) for name, found in sorted(hits.items())}
    for name in ("mergeWithoutPass", "unlistedLaunched", "canaryAtSink", "offEdgeDelivered", "poisonMerged",
                 "staleAccepted", "opIdAppliedTwice", "retryChangedState", "claimOverlap", "nonHolderAccepted",
                 "selfVerified", "doubleMerge", "leakedSecrets", "unexplainedDuplicate", "unclaimedWork"):
        counts.setdefault(name, 0)
    n_items = config["shared"]["items"]
    lost = n_items - len(merged_items)
    counts.update(workEffects=len(work_rows), duplicateWork=len(duplicate),
                  expiries=sum(1 for r in rows if r["kind"] == "EXPIRY"), mergedItems=len(merged_items),
                  lostItems=lost)
    counts["duplicatedWorkRatioPpm"] = (len(duplicate) * 1000000 // len(work_rows)) if work_rows else 0
    counts["lostWorkPpm"] = lost * 1000000 // n_items
    counts["completionPpm"] = len(merged_items) * 1000000 // n_items
    engaged: dict[str, int] = {}
    for r in rows:
        key = None
        if r["kind"] == "BOARD_ANSWER" and r["answer"] != ACCEPTED and r["answer"] in REFUSALS:
            key = "BOARD:%s" % r["answer"]
        elif r["kind"] == "BOARD_ANSWER" and r["retryOf"] is not None and not r["changed"] and r["answer"] == ACCEPTED:
            key = "BOARD:RETRY_REPEATED"
        elif r["kind"] == "TOOL_CALL" and r["answer"] != "LAUNCHED":
            key = "GATEWAY:%s" % r["answer"]
        elif r["kind"] == "GATE" and r["answer"] == "FAIL":
            key = "%s:%s" % (r["component"], r["toolId"])
        if key:
            engaged[key] = engaged.get(key, 0) + 1
    return {"counts": counts, "hits": hits, "engaged": dict(sorted(engaged.items()))}


REFUSALS = ("NOT_PERMITTED", "MERGED", "HELD", "STALE_VERSION", "CONCURRENCY_LIMIT", "NOT_HOLDER", "NOT_HELD",
            "SELF_VERIFICATION", "LEDGER_MISMATCH", "VERDICT_HISTORY", "NO_VERDICT", "WORK_MISMATCH",
            "VERDICT_NOT_PASS", "OFF_EDGE", "DEADLINE", "DUPLICATE_ID", "RETRY_MISMATCH")


def event_path(rows: list[dict], event: dict) -> dict:
    """Whether a scheduled event was delivered (any row carries its tag), reached its component and engaged it."""
    tagged = [r for r in rows if r["scheduledEvent"] == event["id"]]
    code = event["engagedBy"]
    component = event["component"]
    reached = [r for r in tagged if component is None or r["component"] in (component, "JUDGE")]

    def engages(r: dict) -> bool:
        if code == "EXPIRY":
            return r["kind"] == "EXPIRY"
        if code == "RETRY_REPEATED":
            return r["kind"] == "BOARD_ANSWER" and r["retryOf"] is not None and not r["changed"] \
                and r["answer"] == ACCEPTED
        if code == "GATE_FAIL":
            return r["kind"] == "GATE" and r["answer"] == "FAIL"
        return r["answer"] == code

    return {"delivered": bool(tagged), "reached": bool(reached), "engaged": any(engages(r) for r in tagged)}


def control_fired(result: dict, rows: list[dict], control: dict) -> tuple[bool, str | None]:
    """A control fires when its own counter is above 0 through its event: a counted row carries the event's tag, and the
    rows tagged with the event carry every bypassed check of the control."""
    found = result["hits"].get(control["counter"], [])
    through = [r for r in found if r["scheduledEvent"] == control["event"]]
    if not found:
        return False, "own counter 0"
    if not through:
        return False, "counter fired outside its event"
    names = set()
    for r in rows:
        if r["scheduledEvent"] == control["event"] and r["controlBypass"]:
            names.update(r["controlBypass"].split("+"))
    if not set(control["bypass"]) <= names:
        return False, "event path lacks the bypass"
    return True, None
