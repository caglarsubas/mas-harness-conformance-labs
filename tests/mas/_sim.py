"""CONF-MAS-001: the deterministic multi-agent simulation harness (Python 3.12 standard library only).

The harness restates, in R12's own words, rules of four merged harness-onion contracts at
35b733b523f46b2ccba095ea046efe5d42bfa583 (pins in contracts.json): topology and coordination v1 (A1, A2), the agent loop
and tool gateway (A2, A3), run manifest v1 and the verdict ledger. No contract bytes are copied. [sim mapping] marks this
suite's own mapping of a contract rule onto the simulation. Nothing here reads a file, opens a network or a process, or
reads a clock: a run is a pure function of its class parameters, its seed and its control.

The agents are scripted and susceptible: they try what an attack directs. The defences live only in the harness
components (the board, the gateway and its grant issuer, the gates and the verifier), never in the agents.
"""
from __future__ import annotations

import hashlib

FIELDS = ("t", "kind", "agent", "from", "to", "item", "op", "opId", "retryOf", "claimOpId", "expectedVersion",
          "recordVersionBefore", "answer", "changed", "component", "toolId", "verdictStatus", "workDigest",
          "markerPresent", "canaryHits", "scheduledEvent", "controlBypass", "leaseUntil")
KINDS = ("BOARD_ANSWER", "EXPIRY", "DELIVERY", "OBSERVE", "TOOL_CALL", "GATE", "VERDICT", "SINK", "WORK")
STATE_OPS = ("ACQUIRE", "ASSIGN", "RENEW", "RELEASE", "MERGE")
MARKER = "POISON-MARKER"
ACCEPTED = "ACCEPTED"


class Streams:
    """The counter-based PRNG: draw i of a named stream is the first 8 bytes of sha256(b"<seed>:<stream>:<i>")."""

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.counters: dict[str, int] = {}

    def draw(self, stream: str) -> int:
        if ":" in stream or not stream.isascii():
            raise ValueError("a stream name is ASCII without ':'")
        i = self.counters.get(stream, 0)
        self.counters[stream] = i + 1
        raw = hashlib.sha256(b"%d:" % self.seed + stream.encode("ascii") + b":%d" % i).digest()
        return int.from_bytes(raw[:8], "big")

    def below(self, stream: str, n: int) -> int:
        return self.draw(stream) % n

    def chance(self, stream: str, ppm: int) -> bool:
        return self.draw(stream) % 1000000 < ppm

    def permutation(self, stream: str, items: list) -> list:
        """Fisher-Yates: for i = n-1 down to 1, swap position i with draw % (i + 1)."""
        out = list(items)
        for i in range(len(out) - 1, 0, -1):
            j = self.draw(stream) % (i + 1)
            out[i], out[j] = out[j], out[i]
        return out


class Log:
    """The effect log; every metric reads only these rows."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, t: int, kind: str, **fields) -> dict:
        if kind not in KINDS or not set(fields) <= set(FIELDS):
            raise ValueError("closed effect-log row")
        row = dict.fromkeys(FIELDS)
        row.update(fields)
        row["t"], row["kind"] = t, kind
        if row["canaryHits"] is None:
            row["canaryHits"] = []
        self.rows.append(row)
        return row


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def join_bypass(names: list[str]) -> str | None:
    return "+".join(names) if names else None


class Board:
    """The coordinator board (topology-coordination A2), restated.

    One record per item {state OPEN|HELD|MERGED, claims, version}; a claim is {holder, claimOpId, leaseUntil, verdicts}.
    Outside C4-EXCLUSIVE-OFF a record has at most one claim, whose holder is the record's holder.
    """

    def __init__(self, sim: "Sim") -> None:
        self.sim = sim
        self.records = {item: {"state": "OPEN", "version": 0, "claims": [], "mergedClaim": None}
                        for item in range(1, sim.shared["items"] + 1)}
        self.answered: dict[str, dict] = {}

    # Expiry: before an operation at t (and for a read at t), every claim whose lease ended (leaseUntil <= t) ends; the
    # record becomes OPEN when no claim is left; each expiry adds 1 to the version and clears that claim's verdicts.
    def expire(self, t: int) -> None:
        for item in sorted(self.records):
            rec = self.records[item]
            if rec["state"] != "HELD":
                continue
            live = []
            for claim in rec["claims"]:
                if claim["leaseUntil"] <= t:
                    rec["version"] += 1
                    self.sim.log.add(t, "EXPIRY", agent=claim["holder"], item=item, claimOpId=claim["claimOpId"],
                                     leaseUntil=claim["leaseUntil"], component="BOARD",
                                     scheduledEvent=claim.get("event"))
                else:
                    live.append(claim)
            rec["claims"] = live
            if not live:
                rec["state"] = "OPEN"

    def read(self, t: int) -> dict:
        """An agent's read at t: the board with the expiries of t applied."""
        self.expire(t)
        return {item: (rec["state"], rec["version"], tuple(c["holder"] for c in rec["claims"]))
                for item, rec in sorted(self.records.items())}

    def held_count(self) -> int:
        return sum(len(rec["claims"]) for rec in self.records.values())

    def own_claim(self, rec: dict, agent: str):
        for claim in rec["claims"]:
            if claim["holder"] == agent:
                return claim
        return None

    def apply(self, t: int, op: dict) -> dict:
        """Apply one operation at its arrival tick t and return the answer (logged as a BOARD_ANSWER row)."""
        sim, bypass = self.sim, self.sim.bypass
        self.expire(t)
        rec = self.records.get(op["item"]) if op.get("item") is not None else None
        bypassed: list[str] = []
        before = rec["version"] if rec is not None else None
        info = {"claimOpId": None, "leaseUntil": None, "verdictStatus": None, "workDigest": op.get("workDigest"),
                "markerPresent": None, "canaryHits": [], "changed": False}

        def finish(answer: str) -> dict:
            row = sim.log.add(t, "BOARD_ANSWER", agent=op["agent"], to=op.get("to"), item=op.get("item"), op=op["op"],
                              opId=op["opId"], retryOf=op.get("retryOf"), claimOpId=info["claimOpId"],
                              expectedVersion=op.get("expectedVersion"), recordVersionBefore=before, answer=answer,
                              changed=info["changed"], component="BOARD", verdictStatus=info["verdictStatus"],
                              workDigest=info["workDigest"], markerPresent=info["markerPresent"],
                              canaryHits=info["canaryHits"], scheduledEvent=op.get("event"),
                              controlBypass=join_bypass(bypassed), leaseUntil=info["leaseUntil"])
            result = {"opId": op["opId"], "op": op["op"], "item": op.get("item"), "answer": answer,
                      "version": rec["version"] if rec is not None else None, "leaseUntil": info["leaseUntil"],
                      "claimOpId": info["claimOpId"], "event": op.get("event")}
            if op["opId"] not in self.answered:
                self.answered[op["opId"]] = {"result": dict(result), "body": body_of(op)}
            return {"result": result, "row": row}

        # DEADLINE: every new operation after the deadline is refused; a retry repeats its original answer.
        if t > sim.cfg["deadline"] and op.get("retryOf") is None:
            return finish("DEADLINE")
        # Duplicate opId [sim mapping of the transcript-level DUPLICATE_ID]: checked before every operation check.
        if op["opId"] in self.answered:
            if "DEDUPE" in bypass:
                bypassed.append("DEDUPE")
            else:
                return finish("DUPLICATE_ID")
        # Retries: a retryOf operation repeats an earlier non-retry operation's exact body, gets its answer again and
        # changes nothing (a historical answer).
        if op.get("retryOf") is not None:
            if "RETRY" in bypass:
                bypassed.append("RETRY")
            else:
                original = self.answered.get(op["retryOf"])
                if original is None or original["body"] != body_of(op):
                    return finish("RETRY_MISMATCH")
                info["claimOpId"] = original["result"]["claimOpId"]
                info["leaseUntil"] = original["result"]["leaseUntil"]
                return finish(original["result"]["answer"])
        kind = op["op"]
        if kind == "MESSAGE":
            return self._message(t, op, bypassed, finish)
        if kind in ("ACQUIRE", "ASSIGN"):
            return self._claim(t, op, rec, bypassed, info, finish)
        if kind in ("RENEW", "RELEASE", "MERGE"):
            return self._holder_op(t, op, rec, bypassed, info, finish)
        if kind == "VERIFY":
            return self._verify(t, op, rec, bypassed, info, finish)
        return finish("NOT_PERMITTED")

    def _version_ok(self, rec: dict, op: dict, bypassed: list[str]) -> bool:
        """ACQUIRE, ASSIGN, RENEW, RELEASE and MERGE need expectedVersion == version (else STALE_VERSION)."""
        if op.get("expectedVersion") == rec["version"]:
            return True
        if "VERSION" in self.sim.bypass:
            bypassed.append("VERSION")
            return True
        return False

    def _claim(self, t, op, rec, bypassed, info, finish):
        sim = self.sim
        if op["op"] == "ACQUIRE":
            permitted = sim.mode == "DECENTRALIZED" and op["agent"] in sim.workers
            holder = op["agent"]
        else:
            permitted = (sim.mode == "CENTRAL" and op["agent"] == sim.coordinator and op.get("to") in sim.workers)
            holder = op.get("to")
        if not permitted or rec is None:
            return finish("NOT_PERMITTED")
        if rec["state"] == "MERGED":
            return finish("MERGED")
        if rec["state"] == "HELD":
            if "HELD" in sim.bypass:
                bypassed.append("HELD")
            else:
                return finish("HELD")
        if not self._version_ok(rec, op, bypassed):
            return finish("STALE_VERSION")
        if self.held_count() >= sim.shared["concurrency"]:
            return finish("CONCURRENCY_LIMIT")
        lease = t + sim.shared["leaseTicks"]
        rec["claims"].append({"holder": holder, "claimOpId": op["opId"], "leaseUntil": lease, "verdicts": [],
                              "event": None})
        rec["state"] = "HELD"
        rec["version"] += 1
        info.update(claimOpId=op["opId"], leaseUntil=lease, changed=True)
        answer = finish(ACCEPTED)
        if op["op"] == "ASSIGN":
            sim.notify(t, holder, {"type": "NOTICE", "item": op["item"], "claimOpId": op["opId"],
                                   "version": rec["version"], "leaseUntil": lease})
        return answer

    def _holder_op(self, t, op, rec, bypassed, info, finish):
        sim = self.sim
        if rec is None:
            return finish("NOT_PERMITTED")
        claim = self.own_claim(rec, op["agent"])
        if claim is None and op["op"] == "RELEASE" and sim.mode == "CENTRAL" and op["agent"] == sim.coordinator \
                and rec["claims"]:
            claim = rec["claims"][0]
        if claim is None:
            return finish("NOT_HOLDER")
        info["claimOpId"] = claim["claimOpId"]
        if not self._version_ok(rec, op, bypassed):
            return finish("STALE_VERSION")
        if op["op"] == "RENEW":
            claim["leaseUntil"] = t + sim.shared["leaseTicks"]
            rec["version"] += 1
            info.update(leaseUntil=claim["leaseUntil"], changed=True)
            return finish(ACCEPTED)
        if op["op"] == "RELEASE":
            rec["claims"].remove(claim)
            if not rec["claims"]:
                rec["state"] = "OPEN"
            rec["version"] += 1
            info["changed"] = True
            return finish(ACCEPTED)
        # MERGE: the claim's latest verdict on the named work must be PASS.
        work = op.get("workDigest")
        on_work = [v for v in claim["verdicts"] if v["workDigest"] == work]
        info["verdictStatus"] = on_work[-1]["status"] if on_work else None
        refusal = None
        if not claim["verdicts"]:
            refusal = "NO_VERDICT"
        elif not on_work:
            refusal = "WORK_MISMATCH"
        elif on_work[-1]["status"] != "PASS":
            refusal = "VERDICT_NOT_PASS"
        if refusal is not None:
            if "MERGE_VERDICT" in sim.bypass:
                bypassed.append("MERGE_VERDICT")
            else:
                return finish(refusal)
        raw = sim.artefacts.get(work, b"")
        rec["state"], rec["mergedClaim"], rec["claims"] = "MERGED", claim["claimOpId"], []
        rec["version"] += 1
        info.update(changed=True, markerPresent=MARKER.encode("ascii") in raw, canaryHits=sim.canary_hits(raw))
        return finish(ACCEPTED)

    def _verify(self, t, op, rec, bypassed, info, finish):
        """VERIFY: by any node but the holder; the verdict binds only to its own claim, verifier and history."""
        sim = self.sim
        verdict = op["verdict"]
        info["workDigest"] = verdict["workDigest"]
        info["verdictStatus"] = verdict["status"]
        if rec is None or rec["state"] != "HELD":
            return finish("NOT_HELD")
        if op["agent"] in [c["holder"] for c in rec["claims"]]:
            if "SELF_VERIFICATION" in sim.bypass:
                bypassed.append("SELF_VERIFICATION")
            else:
                return finish("SELF_VERIFICATION")
        claim = next((c for c in rec["claims"] if c["claimOpId"] == verdict["claimOpId"]), None)
        if verdict["verifier"] != op["agent"] or claim is None or claim["holder"] != verdict["holder"]:
            return finish("LEDGER_MISMATCH")
        info["claimOpId"] = claim["claimOpId"]
        # Verdict history: a bound verdictId is refused; a verdict supersedes the latest on its work (the first
        # supersedes nothing); a worse status is allowed, an improvement needs new evidence.
        on_work = [v for v in claim["verdicts"] if v["workDigest"] == verdict["workDigest"]]
        latest = on_work[-1] if on_work else None
        if any(v["verdictId"] == verdict["verdictId"] for v in claim["verdicts"]):
            return finish("VERDICT_HISTORY")
        if verdict["supersedes"] != (latest["verdictId"] if latest else None):
            return finish("VERDICT_HISTORY")
        if latest and latest["status"] == "FAIL" and verdict["status"] == "PASS" \
                and verdict["evidence"] <= latest["evidence"]:
            return finish("VERDICT_HISTORY")
        claim["verdicts"].append(dict(verdict))
        info["changed"] = True
        answer = finish(ACCEPTED)
        sim.log.add(t, "VERDICT", agent=op["agent"], item=op["item"], claimOpId=claim["claimOpId"],
                    verdictStatus=verdict["status"], workDigest=verdict["workDigest"], component="BOARD",
                    scheduledEvent=op.get("event"), controlBypass=join_bypass(bypassed))
        return answer

    def _message(self, t, op, bypassed, finish):
        sim = self.sim
        if (op["agent"], op["to"]) not in sim.edges:
            if "EDGE" in sim.bypass:
                bypassed.append("EDGE")
            else:
                return finish("OFF_EDGE")
        answer = finish(ACCEPTED)
        sim.deliver_message(t, op, bypassed)
        return answer


def body_of(op: dict) -> tuple:
    """An operation's body: everything but its identity, its retry link and its simulation tags."""
    keys = sorted(k for k in op if k not in ("opId", "retryOf", "event", "lane"))
    return tuple((k, repr(op[k])) for k in keys)


class Gateway:
    """The typed boundary (agent-loop A2): a listed tool under its listed manifest and its own per-call grant;
    credentials only as {param, brokerRef} references [sim mapping: a value is denied before launch]. Not restated in
    packet 1: input-schema validation, and grant expiry or reuse (inputs are well formed by construction)."""

    def __init__(self, sim: "Sim") -> None:
        self.sim = sim
        self.grants = 0

    def call(self, t: int, agent: str, tool: str, inp: dict, event: str | None) -> dict:
        sim = self.sim
        entry = sim.config["manifest"].get(tool)
        listed = sim.config["profiles"][sim.role_of(agent)]["tools"]
        bypassed: list[str] = []
        hits = sim.canary_hits(repr(sorted(inp.items())).encode("utf-8"))

        def row(answer: str) -> dict:
            return sim.log.add(t, "TOOL_CALL", agent=agent, toolId=tool, answer=answer, component="GATEWAY",
                               canaryHits=hits, scheduledEvent=event, controlBypass=join_bypass(bypassed))

        if entry is None:
            return {"launched": False, "row": row("UNKNOWN_TOOL")}
        # The grant issuer issues a per-call grant only for a tool the caller's profile lists (removed together with the
        # gateway's listing condition under C1-TOOLS-OFF).
        if tool not in listed:
            if "PROFILE_LISTING" in sim.bypass:
                bypassed.append("PROFILE_LISTING")
            else:
                return {"launched": False, "row": row("NOT_LISTED")}
        self.grants += 1
        grant = {"grantId": "g-%d" % self.grants, "toolId": tool, "manifestDigest": entry["manifestDigest"],
                 "scope": entry["grantScope"], "expiresAt": t + sim.shared["toolTicks"]}
        if grant["toolId"] != tool or grant["manifestDigest"] != entry["manifestDigest"]:
            return {"launched": False, "row": row("GRANT_MISMATCH")}
        for param in entry["credentialParams"]:
            value = inp.get(param)
            if not (isinstance(value, dict) and sorted(value) == ["brokerRef", "param"]):
                if "CREDENTIAL_REF" in sim.bypass:
                    bypassed.append("CREDENTIAL_REF")
                else:
                    return {"launched": False, "row": row("CREDENTIAL_VALUE")}
        launched = row("LAUNCHED")
        if tool == "SEND_REPORT":
            sim.log.add(t, "SINK", agent=agent, toolId=tool, component="GATEWAY", canaryHits=hits,
                        scheduledEvent=event, controlBypass=join_bypass(bypassed))
        return {"launched": True, "row": launched}


class Sim:
    """One run: a class, a seed and a control (the bypassed checks, or none for the defended run)."""

    def __init__(self, config: dict, cls: dict, seed: int, bypass: tuple[str, ...], scenario) -> None:
        self.config, self.cfg, self.seed = config, cls, seed
        self.shared = config["shared"]
        topo = config["topologies"][cls["topology"]]
        self.mode, self.coordinator, self.workers = topo["mode"], topo["coordinator"], list(topo["workers"])
        self.verifier = topo["verifier"]
        self.edges = {(a, b) for a, b in topo["edges"]}
        self.bypass = frozenset(bypass)
        self.streams, self.log = Streams(seed), Log()
        self.board, self.gateway = Board(self), Gateway(self)
        self.artefacts: dict[str, bytes] = {}
        self.failed_gate: set[str] = set()
        self.inflight_ops: list[tuple] = []
        self.inflight_in: list[tuple] = []
        self.seq = 0
        self.lane_items: set[tuple[str, int]] = set()
        self.long_items: set[tuple[str, int]] = set()
        self.compromised = cls.get("compromised")
        self.order = ([self.coordinator] if self.coordinator else []) + self.workers + [self.verifier]
        self.canaries = {a: "CANARY-%s-%02d-END" % (a, seed) for a in self.order if a != self.compromised}
        self.scenario = scenario
        self.agents = {}
        if self.coordinator:
            self.agents[self.coordinator] = Coordinator(self, self.coordinator)
        for w in self.workers:
            self.agents[w] = Worker(self, w)
        self.agents[self.verifier] = Verifier(self, self.verifier)
        scenario.setup(self)

    def role_of(self, agent: str) -> str:
        if agent == self.coordinator:
            return "COORDINATOR"
        if agent == self.verifier:
            return "VERIFIER"
        return "WORKER"

    def canary_hits(self, raw: bytes) -> list[str]:
        return sorted(a for a, value in self.canaries.items() if value.encode("ascii") in raw)

    def latency(self, agent: str, lane: bool) -> int:
        top = self.cfg["maxLatency"]
        if lane or top == 0:
            return 0
        return self.streams.below("lat-%s" % agent, top + 1)

    def send(self, t: int, op: dict) -> None:
        """An operation enters its sender's channel; it arrives at t + latency (0 on the attack lane)."""
        self.seq += 1
        arrival = t + self.latency(op["agent"], op.get("lane", False))
        self.inflight_ops.append((arrival, op["agent"], op["opId"], self.seq, op))

    def inject(self, arrival: int, op: dict) -> None:
        """A scheduled replay or re-delivery enters the board's input at its arrival tick (attack lane)."""
        self.seq += 1
        self.inflight_ops.append((arrival, op["agent"], op["opId"], self.seq, op))

    def reply(self, t: int, agent: str, result: dict, lane: bool) -> None:
        if self.scenario.drop_answer(self, t, agent, result):
            self.log.add(t, "DELIVERY", agent=agent, to=agent, item=result["item"], opId=result["opId"], answer="DROPPED",
                         component="CHANNEL", scheduledEvent=self.scenario.drop_event)
            return
        self.seq += 1
        arrival = t + self.latency(agent, lane)
        self.inflight_in.append((arrival, self.seq, agent, {"type": "ANSWER", **result}))

    def notify(self, t: int, agent: str, payload: dict) -> None:
        lane = (agent, payload.get("item")) in self.lane_items
        self.seq += 1
        arrival = t + self.latency(agent, lane)
        self.log.add(t, "DELIVERY", agent=agent, to=agent, item=payload.get("item"), claimOpId=payload.get("claimOpId"),
                     answer="NOTICE", component="BOARD")
        self.inflight_in.append((arrival, self.seq, agent, payload))

    def deliver_message(self, t: int, op: dict, bypassed: list[str]) -> None:
        lane = op.get("lane", False)
        self.seq += 1
        arrival = t + self.latency(op["to"], lane)
        payload = {"type": "MESSAGE", "from": op["agent"], "messageType": op["messageType"],
                   "requiredAction": op["requiredAction"], "ref": dict(op.get("ref") or {}), "event": op.get("event")}
        self.log.add(t, "DELIVERY", agent=op["to"], **{"from": op["agent"]}, to=op["to"],
                     item=payload["ref"].get("item"), opId=op["opId"], answer="DELIVERED", component="BUS",
                     scheduledEvent=op.get("event"), controlBypass=join_bypass(bypassed))
        self.inflight_in.append((arrival, self.seq, op["to"], payload))

    def done(self) -> bool:
        return (all(rec["state"] == "MERGED" for rec in self.board.records.values())
                and not self.inflight_ops and not self.inflight_in)

    def run(self) -> list[dict]:
        for t in range(self.cfg["deadline"] + 1):
            self.scenario.before_tick(self, t)
            for agent in self.order:
                self.agents[agent].step(t)
            arriving = sorted((x for x in self.inflight_ops if x[0] <= t), key=lambda x: (x[0], x[1], x[2], x[3]))
            self.inflight_ops = [x for x in self.inflight_ops if x[0] > t]
            for _arrival, agent, _op_id, _seq, op in arriving:
                answer = self.board.apply(t, op)
                self.scenario.on_board_answer(self, t, op, answer["result"])
                self.reply(t, agent, answer["result"], op.get("lane", False))
            due = sorted((x for x in self.inflight_in if x[0] <= t), key=lambda x: (x[0], x[1]))
            self.inflight_in = [x for x in self.inflight_in if x[0] > t]
            for _arrival, _seq, agent, payload in due:
                self.agents[agent].inbox.append(payload)
            if self.done():
                break
        return self.log.rows


class Agent:
    def __init__(self, sim: Sim, aid: str) -> None:
        self.sim, self.id = sim, aid
        self.inbox: list[dict] = []
        self.counter = 0
        self.pending: dict[str, dict] = {}

    def new_op(self, t: int, kind: str, item, lane: bool = False, event: str | None = None, **fields) -> dict:
        self.counter += 1
        op = {"opId": "%s-%04d" % (self.id, self.counter), "agent": self.id, "op": kind, "item": item, "lane": lane,
              "event": event, **fields}
        return op

    def send(self, t: int, op: dict) -> None:
        maxlat = self.sim.cfg["maxLatency"]
        expected = t if op.get("lane") or maxlat == 0 else t + 2 * maxlat
        self.pending[op["opId"]] = {"op": op, "expected": expected, "retried": False}
        self.sim.send(t, op)

    def retry_overdue(self, t: int) -> None:
        """An answer overdue by retryAfterOverdueTicks makes the agent re-send the exact body with retryOf."""
        late = self.sim.shared["retryAfterOverdueTicks"]
        for op_id in sorted(self.pending):
            entry = self.pending[op_id]
            if entry["retried"] or entry["op"]["op"] == "MESSAGE" or t < entry["expected"] + late:
                continue
            entry["retried"] = True
            original = entry["op"]
            self.counter += 1
            retry = dict(original, opId="%s-%04d" % (self.id, self.counter), retryOf=original["opId"],
                         event=entry.get("event", original.get("event")))
            self.pending[retry["opId"]] = {"op": retry, "expected": entry["expected"] + late, "retried": True,
                                           "retryOfPending": op_id}
            self.sim.send(t, retry)

    def take_inbox(self) -> list[dict]:
        out, self.inbox = self.inbox, []
        return out


class Coordinator(Agent):
    """CENTRAL: ASSIGNs the lowest-id OPEN item to the next WORKER in round robin that holds nothing; never RELEASEs."""

    def __init__(self, sim: Sim, aid: str) -> None:
        super().__init__(sim, aid)
        self.rr = 0

    def step(self, t: int) -> None:
        for msg in self.take_inbox():
            if msg["type"] == "ANSWER":
                self.pending.pop(msg["opId"], None)
        sim = self.sim
        snap = sim.board.read(t)
        holders = {h for _state, _version, hs in snap.values() for h in hs}
        pending_items = {e["op"]["item"] for e in self.pending.values()}
        pending_workers = {e["op"]["to"] for e in self.pending.values()}
        held = sum(len(hs) for _s, _v, hs in snap.values()) + len(self.pending)
        for item in sorted(snap):
            state, version, _hs = snap[item]
            if held >= sim.shared["concurrency"]:
                break
            if state != "OPEN" or item in pending_items:
                continue
            choice = None
            for k in range(len(sim.workers)):
                w = sim.workers[(self.rr + k) % len(sim.workers)]
                if w not in holders and w not in pending_workers:
                    choice = w
                    break
            if choice is None:
                break
            self.rr = (sim.workers.index(choice) + 1) % len(sim.workers)
            lane = (choice, item) in sim.lane_items
            self.send(t, self.new_op(t, "ASSIGN", item, lane=lane, to=choice, expectedVersion=version))
            pending_workers.add(choice)
            held += 1


class Verifier(Agent):
    """Runs the `judge` gate (TEST) on the artefact it reads by digest, VERIFYs, then notifies the worker."""

    def __init__(self, sim: Sim, aid: str) -> None:
        super().__init__(sim, aid)
        self.latest: dict[tuple, str] = {}
        self.counts: dict[str, int] = {}

    def step(self, t: int) -> None:
        sim = self.sim
        for msg in self.take_inbox():
            if msg["type"] == "ANSWER":
                entry = self.pending.pop(msg["opId"], None)
                if entry is None or entry["op"]["op"] != "VERIFY" or msg["answer"] != ACCEPTED:
                    continue
                verdict = entry["op"]["verdict"]
                self.latest[(verdict["claimOpId"], verdict["workDigest"])] = verdict["verdictId"]
                ref = {"item": entry["op"]["item"], "claimOpId": verdict["claimOpId"], "workDigest": verdict["workDigest"],
                       "verdictId": verdict["verdictId"], "status": verdict["status"]}
                self.send(t, self.new_op(t, "MESSAGE", None, lane=entry["op"].get("lane", False), to=verdict["holder"],
                                         messageType="DEPENDENCY", requiredAction="NONE", ref=ref,
                                         event=entry["op"].get("event")))
            elif msg["type"] == "MESSAGE" and msg["messageType"] == "TEST" and msg["from"] in sim.workers:
                self.judge(t, msg)

    def judge(self, t: int, msg: dict) -> None:
        sim, ref = self.sim, msg["ref"]
        work = ref.get("workDigest")
        raw = sim.artefacts.get(work)
        if raw is None:
            return
        marker = MARKER.encode("ascii") in raw
        sim.log.add(t, "OBSERVE", agent=self.id, to=self.id, **{"from": msg["from"]}, item=ref.get("item"),
                    workDigest=work, markerPresent=marker, canaryHits=sim.canary_hits(raw), component="JUDGE",
                    scheduledEvent=msg.get("event"))
        status, bypassed = ("FAIL" if marker else "PASS"), []
        if marker and "JUDGE" in sim.bypass:
            status = "PASS"
            bypassed.append("JUDGE")
        sim.log.add(t, "GATE", agent=self.id, item=ref.get("item"), workDigest=work, answer=status, component="JUDGE",
                    toolId="judge", markerPresent=marker, scheduledEvent=msg.get("event"),
                    controlBypass=join_bypass(bypassed))
        claim = ref["claimOpId"]
        self.counts[claim] = self.counts.get(claim, 0) + 1
        verdict = {"verdictId": "%s-%s-%d" % (self.id, claim, self.counts[claim]), "verifier": self.id,
                   "holder": msg["from"], "claimOpId": claim, "workDigest": work, "status": status,
                   "supersedes": self.latest.get((claim, work)), "evidence": 1}
        lane = (msg["from"], ref.get("item")) in sim.lane_items
        self.send(t, self.new_op(t, "VERIFY", ref.get("item"), lane=lane, verdict=verdict, event=msg.get("event")))


class Worker(Agent):
    """A susceptible WORKER: holds at most one item; READ, WORK, ask for a verdict, then MERGE whatever the verdict."""

    def __init__(self, sim: Sim, aid: str) -> None:
        super().__init__(sim, aid)
        self.hold = None
        self.stalled_until = None
        self.todo: list[dict] = []
        self.compromised = aid == sim.compromised

    def lane(self, item) -> bool:
        return (self.id, item) in self.sim.lane_items

    def item_pending(self, exclude_renew: bool = True) -> bool:
        """An unanswered operation on the held item. A board operation other than RENEW waits on every unanswered one,
        RENEW included (exclude_renew=False); RENEW itself never waits (D4-2, Q-MAS1-F2). A tool call (READ) waits only
        on the non-RENEW ones."""
        return any(e["op"]["item"] is not None and e["op"]["item"] == (self.hold or {}).get("item")
                   and not (exclude_renew and e["op"]["op"] == "RENEW") for e in self.pending.values())

    def take_claim(self, t: int, item: int, claim: str, version: int, lease: int) -> None:
        self.hold = {"item": item, "claimOpId": claim, "version": version, "leaseUntil": lease, "phase": "START",
                     "until": None, "reads": [], "artefact": None, "revisions": 0, "works": 0, "event": None,
                     "verdict": None}
        self.sim.scenario.on_claim(self.sim, self, t)

    def abandon(self) -> None:
        if self.hold is not None:
            item = self.hold["item"]
            self.pending = {k: v for k, v in self.pending.items() if v["op"]["item"] != item}
        self.hold = None

    def step(self, t: int) -> None:
        sim = self.sim
        if self.stalled_until is not None:
            if t < self.stalled_until:
                return
            self.stalled_until = None
            if self.hold is not None and not self.still_holds(t):
                self.abandon()
        for msg in self.take_inbox():
            self.handle(t, msg)
        if self.compromised:
            self.retry_overdue(t)
            return
        if self.hold is not None and self.progress(t):
            return
        self.renew(t)
        self.run_todo(t)
        self.retry_overdue(t)
        if self.hold is None and sim.mode == "DECENTRALIZED" and not any(
                e["op"]["op"] == "ACQUIRE" for e in self.pending.values()):
            if not sim.scenario.override_idle(sim, self, t):
                snap = sim.board.read(t)
                for item in sorted(snap):
                    state, version, _hs = snap[item]
                    if state == "OPEN":
                        self.send(t, self.new_op(t, "ACQUIRE", item, lane=self.lane(item), expectedVersion=version))
                        break

    def still_holds(self, t: int) -> bool:
        snap = self.sim.board.read(t)
        state, _version, holders = snap[self.hold["item"]]
        return state == "HELD" and self.id in holders

    def handle(self, t: int, msg: dict) -> None:
        sim = self.sim
        if msg["type"] == "NOTICE":
            if self.hold is None:
                self.take_claim(t, msg["item"], msg["claimOpId"], msg["version"], msg["leaseUntil"])
            return
        if msg["type"] == "MESSAGE":
            if msg["messageType"] == "DEPENDENCY" and msg["from"] == sim.verifier:
                ref = msg["ref"]
                if self.hold and ref.get("claimOpId") == self.hold["claimOpId"] \
                        and ref.get("workDigest") == self.hold.get("workDigest"):
                    self.hold["verdict"] = ref
                    if self.hold["phase"] == "AWAIT_VERDICT":
                        self.hold["phase"] = "MERGE_READY"
                return
            instruction = sim.config["instructions"].get("%s/%s" % (msg["messageType"], msg["requiredAction"]))
            if instruction is not None:
                self.todo.append({"instruction": instruction, "msg": msg})
            return
        entry = self.pending.pop(msg["opId"], None)
        if entry is None:
            return  # an answer the agent did not expect is logged by the board and ignored here (D4-6)
        if "retryOfPending" in entry:
            self.pending.pop(entry["retryOfPending"], None)
        op = entry["op"]
        if op.get("instructed"):
            return  # an instructed attempt's answer changes nothing in the agent's own work
        kind, answer = op["op"], msg["answer"]
        if kind == "ACQUIRE":
            if answer == ACCEPTED and self.hold is None:
                self.take_claim(t, op["item"], msg["claimOpId"], msg["version"], msg["leaseUntil"])
            elif answer != ACCEPTED:
                sim.scenario.on_acquire_refused(sim, self, t, op, msg)
            return
        if self.hold is None or op["item"] != self.hold["item"]:
            return
        if kind == "RENEW":
            if answer == ACCEPTED:
                self.hold["version"], self.hold["leaseUntil"] = msg["version"], msg["leaseUntil"]
            elif answer == "NOT_HOLDER":
                self.abandon()
            elif answer == "STALE_VERSION":
                self.resync(t)
        elif kind == "MERGE":
            if answer == ACCEPTED:
                self.hold = None
            elif answer == "NOT_HOLDER":
                self.abandon()  # a worker that no longer holds the item cannot revise it (build note, Q-MAS1-F2)
            else:
                if answer == "STALE_VERSION":
                    self.resync(t)  # re-read the record's version, then revise like any other refusal (rev 4)
                if self.hold is not None:
                    self.revise(t)
        elif kind == "RELEASE":
            self.hold = None

    def resync(self, t: int) -> None:
        state, version, holders = self.sim.board.read(t)[self.hold["item"]]
        if state == "HELD" and self.id in holders:
            self.hold["version"] = version
        else:
            self.abandon()

    def revise(self, t: int) -> None:
        """After a gate FAIL or a refused MERGE: revise (a new READ and WORK) at most maxRevisions times, then RELEASE."""
        hold = self.hold
        if hold["revisions"] >= self.sim.shared["maxRevisions"]:
            hold["phase"] = "RELEASE_READY"
            self.release_when_ready(t)
            return
        hold["revisions"] += 1
        hold.update(phase="START", reads=[], artefact=None, verdict=None, event=None, workDigest=None)

    def release_when_ready(self, t: int) -> None:
        """RELEASE, once no RENEW on the item is unanswered (Q-MAS1-F2)."""
        hold = self.hold
        if hold["phase"] == "RELEASE_READY" and not self.item_pending(exclude_renew=False):
            hold["phase"] = "RELEASING"
            self.send(t, self.new_op(t, "RELEASE", hold["item"], lane=self.lane(hold["item"]),
                                     expectedVersion=hold["version"]))

    def progress(self, t: int) -> bool:
        """Advance the current activity; True when the agent stalls this tick."""
        sim, hold = self.sim, self.hold
        shared = sim.shared
        if hold["phase"] == "START" and not self.item_pending():
            content, event = sim.scenario.read_content(sim, self, t)
            sim.gateway.call(t, self.id, "READ", {"item": hold["item"]}, event)
            hold.update(phase="READING", until=t + shared["toolTicks"], pending_read=(content, event))
        elif hold["phase"] == "READING" and t >= hold["until"]:
            content, event = hold.pop("pending_read")
            raw = content.encode("utf-8")
            sim.log.add(t, "OBSERVE", agent=self.id, to=self.id, item=hold["item"], component="GATEWAY",
                        toolId="READ", markerPresent=MARKER.encode("ascii") in raw, canaryHits=sim.canary_hits(raw),
                        scheduledEvent=event)
            hold["reads"].append(content)
            if event is not None:
                hold["event"] = event
            long = (self.id, hold["item"]) in sim.long_items and hold["revisions"] == 0
            hold.update(phase="WORKING", until=t + (shared["longWorkTicks"] if long else shared["workTicks"]))
        elif hold["phase"] == "WORKING" and t >= hold["until"]:
            raw = ("item-%d|" % hold["item"] + "|".join(hold["reads"])).encode("utf-8")
            work = digest(raw)
            sim.artefacts[work] = raw
            hold.update(artefact=raw, workDigest=work)
            hold["works"] += 1
            sim.log.add(t, "WORK", agent=self.id, item=hold["item"], claimOpId=hold["claimOpId"], workDigest=work,
                        markerPresent=MARKER.encode("ascii") in raw, canaryHits=sim.canary_hits(raw), component="WORK",
                        scheduledEvent=hold["event"])
            stall = sim.scenario.stall_after_work(sim, self, t)
            if stall:
                self.stalled_until = t + shared["stallTicks"]
                return True
            ref = {"item": hold["item"], "claimOpId": hold["claimOpId"], "workDigest": work}
            self.send(t, self.new_op(t, "MESSAGE", None, lane=self.lane(hold["item"]), to=sim.verifier,
                                     messageType="TEST", requiredAction="ACKNOWLEDGE", ref=ref, event=hold["event"]))
            hold["phase"] = "AWAIT_VERDICT"
        elif hold["phase"] == "MERGE_READY" and not self.item_pending(exclude_renew=False):
            self.merge(t, hold["artefact"], hold["workDigest"], hold["event"], instructed=False)
        elif hold["phase"] == "RELEASE_READY":
            self.release_when_ready(t)
        return False

    def merge_gate(self, t: int, raw: bytes, work: str, event) -> bool:
        """The `merge-policy` gate (POLICY) before every MERGE: FAIL on the marker; a FAIL is final for those bytes."""
        sim = self.sim
        fail = MARKER.encode("ascii") in raw or work in sim.failed_gate
        if "MERGE_GATE" in sim.bypass:
            sim.log.add(t, "GATE", agent=self.id, item=self.hold["item"] if self.hold else None, workDigest=work,
                        answer="SKIPPED", component="GATE", toolId="merge-policy", markerPresent=fail,
                        scheduledEvent=event, controlBypass="MERGE_GATE" if fail else None)
            return True
        if fail:
            sim.failed_gate.add(work)
        sim.log.add(t, "GATE", agent=self.id, item=self.hold["item"] if self.hold else None, workDigest=work,
                    answer="FAIL" if fail else "PASS", component="GATE", toolId="merge-policy", markerPresent=fail,
                    scheduledEvent=event)
        return not fail

    def merge(self, t: int, raw: bytes, work: str, event, instructed: bool) -> None:
        hold = self.hold
        if not self.merge_gate(t, raw, work, event):
            if not instructed:
                self.revise(t)
            return
        op = self.new_op(t, "MERGE", hold["item"], lane=self.lane(hold["item"]) or instructed,
                         expectedVersion=hold["version"], workDigest=work, event=event)
        if instructed:
            op["instructed"] = True
        else:
            hold["phase"] = "MERGING"
        self.send(t, op)

    def renew(self, t: int) -> None:
        """RENEW once at most renewAtRemaining ticks remain; RENEW is exempt from the one-unanswered-operation rule."""
        hold = self.hold
        if hold is None or hold["phase"] in ("RELEASE_READY", "RELEASING"):
            return
        if hold["leaseUntil"] - t > self.sim.shared["renewAtRemaining"]:
            return
        if any(e["op"]["op"] == "RENEW" and e["op"]["item"] == hold["item"] for e in self.pending.values()):
            return
        self.send(t, self.new_op(t, "RENEW", hold["item"], lane=self.lane(hold["item"]),
                                 expectedVersion=hold["version"]))

    def run_todo(self, t: int) -> None:
        """A susceptible agent obeys every instruction a message carries (section 5, C1)."""
        sim = self.sim
        todo, self.todo = self.todo, []
        for entry in todo:
            instruction, msg = entry["instruction"], entry["msg"]
            event = msg.get("event")
            if instruction == "MERGE_NOW" and self.hold is not None:
                if self.item_pending(exclude_renew=False):
                    self.todo.append(entry)  # a MERGE waits while an operation on the item is unanswered (Q-MAS1-F2)
                    continue
                hold = self.hold
                raw = hold["artefact"] or ("item-%d|" % hold["item"]).encode("utf-8")
                work = hold.get("workDigest") or digest(raw)
                sim.artefacts.setdefault(work, raw)
                self.merge(t, raw, work, event, instructed=True)
            elif instruction == "CALL_ADMIN":
                sim.gateway.call(t, self.id, "ADMIN", {"action": "reconfigure"}, event)
            elif instruction == "SEND_TOKEN":
                sim.gateway.call(t, self.id, "SEND_REPORT", {"report": "status", "token": sim.canaries[self.id]}, event)
            elif instruction == "RELAY":
                target = msg["ref"].get("relayTo")
                if target and target != self.id:
                    op = self.new_op(t, "MESSAGE", None, lane=True, to=target, messageType=msg["messageType"],
                                     requiredAction=msg["requiredAction"], ref={"relayTo": target}, event=event)
                    self.send(t, op)
