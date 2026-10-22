"""CONF-MAS-001 to CONF-MAS-004: the deterministic multi-agent simulation harness (Python 3.12 standard library only).

The harness restates, in R12's own words, rules of four merged harness-onion contracts at
585364b94e3e4a8bf1418ef750ce3d71cd38f95a (ten pins in contracts.json, byte-identical at 27c54605, packet 2's pin; packet
1's nine are byte-identical at 35b733b5):
topology and coordination v1 (A1, A2), the agent loop and tool gateway (A1 to A3), run manifest v1 and the verdict
ledger. No contract bytes are copied. [sim mapping] marks this suite's own mapping of a contract rule onto the
simulation. Nothing here reads a file, opens a network or a process, or reads a clock: a run is a pure function of its
class parameters, its seed and its control.

Packet 2 adds, always on and inert for packet 1: issued grants with reuse, match and expiry checks, input validity, the
closed message body and DELIVERY canary hits. Switched on only by class keys packet 1's classes lack: budgets, retries and
timeouts (the kernel), scheduled tool faults, per-node objectives and admission, redaction and the credential rule.

Packet 3 adds, switched on only by class keys or run parameters packets 1 and 2 lack (DESIGN revision 6, section 4):
crashes (FAULT rows), dropped answers to the coordinator and its gated overdue retry, coordinator restart and
resumption, the wall-clock budget and the revision bound (each kernel check under its own `budgets` key), the bypasses
EXPIRY, WALL_CLOCK, REVISION_BOUND, SINGLE_MERGE, HOLDER, WORK_VERDICT and SUPERSESSION, the run parameter
`until_deadline`, and the arms' worker policies (run parameter `arm`).

CONF-MAS-004 adds, switched on only by class keys or run parameters packets 1 to 3 lack (DESIGN revision 5, section 4):
a per-class load (`load`), tasks with drawn problems and the judge's task test (`tasks`, run parameter `labels`),
self-reported status and the bypass JUDGE_BY_STATUS (`selfReport`), the merge-policy degenerate check
(`degenerateCheck`), verdict checks and the evidence-kind rule with the refusal CONSISTENCY_ONLY and the bypass
EVIDENCE_KIND (`evidenceRule`), the run parameters `scriptedEvents` and `policy`, and the scaling points' worker switch
(`claimAwareWorker`). Two fields join the effect-log row at its end, null in every row of packets 1 to 3.

CONF-MAS-005 adds, switched on only by class keys packets 1 to 4 lack (DESIGN revision 3, section 4): the pinned view of
the tool configuration (`pinned_view`; the global objects themselves without `toolOverlay`), the run-time registry an
extension writes and the bypass MANIFEST_PIN, the trust gate (`trustTick`, refusal BEFORE_TRUST, bypass TRUST_ORDER),
the overlay tools' effects (the kernel's data rule for a fixture directive, refusal INSTRUCTION_FROM_DATA, bypass
CONTEXT_AS_DATA; the loader's lifecycle-script gate, SCRIPT_SKIPPED, bypass INSTALL_SCRIPTS; the fetch denial NO_FETCH
and the digest pin DIGEST_MISMATCH, bypasses FETCH and ARTIFACT_PIN; the closed tool environment, ENV_CLOSED, bypass
ENV_CLOSURE). No row field and no row kind is added.

The agents are scripted and susceptible: they try what an attack directs. The defences live only in the harness
components (the board, the gateway and its grant issuer, the gates and the verifier), never in the agents.
"""
from __future__ import annotations

import hashlib

FIELDS = ("t", "kind", "agent", "from", "to", "item", "op", "opId", "retryOf", "claimOpId", "expectedVersion",
          "recordVersionBefore", "answer", "changed", "component", "toolId", "verdictStatus", "workDigest",
          "markerPresent", "canaryHits", "scheduledEvent", "controlBypass", "leaseUntil",
          # CONF-MAS-002 (DESIGN revision 8, section 4); null in rows that do not use them
          "grantId", "grantToolId", "grantManifestDigest", "grantScope", "grantExpiresAt", "inputKeys", "attempt",
          "iteration", "objectiveId", "heldBefore", "bodyKeys",
          # CONF-MAS-004 (DESIGN revision 5, section 4.6); null in rows that do not use them
          "verdictChecks", "taskPass")
KINDS = ("BOARD_ANSWER", "EXPIRY", "DELIVERY", "OBSERVE", "TOOL_CALL", "GATE", "VERDICT", "SINK", "WORK", "ADMISSION",
         "KERNEL", "PLAN", "FAULT")
# The closed message body (section 2.3): the envelope keys are the sim's; everything else is the checked body.
ENVELOPE = ("opId", "agent", "op", "item", "lane", "event", "retryOf")
BODY_KEYS = ("to", "messageType", "requiredAction", "ref")
REF_TYPES = {"item": int, "claimOpId": str, "workDigest": str, "verdictId": str, "status": str, "relayTo": str}
STATE_OPS = ("ACQUIRE", "ASSIGN", "RENEW", "RELEASE", "MERGE")
MARKER = "POISON-MARKER"
ACCEPTED = "ACCEPTED"
PERMUTATION_STREAM = "perm-items"
LABELS = ("IDENTITY", "PERMUTED")
POLICIES = ("GENERAL", "HARD_CODED")


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


def shared_for(config: dict, cls: dict) -> dict:
    """CONF-MAS-004 (section 4.1): packet 1's `shared`, with `items` and `concurrency` replaced by the class's `load`."""
    load = cls.get("load")
    if not load:
        return config["shared"]
    return dict(config["shared"], items=load["items"], concurrency=load["concurrency"])


def pinned_view(config: dict, cls: dict) -> dict:
    """CONF-MAS-005 (section 4.1): the tool configuration fixed at construction. Without `toolOverlay` it is the global
    objects themselves; with one, copies with the overlay's manifest entries and input schemas added and its tools
    appended to the WORKER listing. An overlay never replaces a global entry."""
    overlay = cls.get("toolOverlay")
    if not overlay:
        return {"manifest": config["manifest"], "profiles": config["profiles"],
                "inputSchemas": config.get("inputSchemas", {})}
    manifest, schemas = dict(config["manifest"]), dict(config.get("inputSchemas", {}))
    if set(overlay["manifest"]) & set(manifest) or set(overlay["inputSchemas"]) & set(schemas):
        raise ValueError("an overlay adds entries and never replaces one")
    manifest.update(overlay["manifest"])
    schemas.update(overlay["inputSchemas"])
    profiles = {role: dict(profile) for role, profile in config["profiles"].items()}
    profiles["WORKER"]["tools"] = list(profiles["WORKER"]["tools"]) + list(overlay["workerTools"])
    return {"manifest": manifest, "profiles": profiles, "inputSchemas": schemas}


def solve(problem: str) -> str:
    """A task's answer (section 4.2): sha256(b"solve:" + P) as hex, first 16 characters."""
    return hashlib.sha256(b"solve:" + problem.encode("ascii")).hexdigest()[:16]


def last_problem(reads: list[str]) -> str:
    """The last `problem:` token in a claim's reads, or "" when there is none."""
    for read in reversed(reads):
        tokens = [x for x in read.split(" ") if x.startswith("problem:")]
        if tokens:
            return tokens[-1][len("problem:"):]
    return ""


def deterministic_support(checks: list[str] | None, rule: dict) -> list[str]:
    """The evidence kinds of a verdict's checks whose check kind is deterministic (section 2.1), sorted."""
    support = set()
    for check in checks or []:
        kind, _sep, evidence = check.partition("/")
        if kind in rule["deterministicChecks"]:
            support.add(evidence)
    return sorted(support)


def consistency_only(checks: list[str] | None, rule: dict) -> bool:
    """True when a verdict's deterministic support holds no kind outside the consistency-only list (none at all
    included): rule 8 restated [sim mapping, section 2.1]."""
    return all(kind in rule["consistencyOnly"] for kind in deterministic_support(checks, rule))


def join_bypass(names: list[str]) -> str | None:
    return "+".join(names) if names else None


def checked_body(op: dict) -> dict:
    """A MESSAGE operation's checked body: every key but the sim's envelope (section 2.3)."""
    return {k: op[k] for k in sorted(op) if k not in ENVELOPE}


def body_keys(op: dict) -> list[str]:
    """The checked body's keys at both levels, `ref` keys prefixed, plus `item` when the envelope item is not null."""
    body = checked_body(op)
    keys = list(body)
    ref = body.get("ref")
    if isinstance(ref, dict):
        keys += ["ref.%s" % k for k in ref]
    if op.get("item") is not None:
        keys.append("item")
    return sorted(keys)


def shape_ok(op: dict) -> bool:
    """The closed body: exactly to, messageType, requiredAction and an optional closed, typed ref; envelope item null."""
    body = checked_body(op)
    if op.get("item") is not None or not set(body) <= set(BODY_KEYS):
        return False
    if not {"to", "messageType", "requiredAction"} <= set(body):
        return False
    ref = body.get("ref", {})
    if not isinstance(ref, dict):
        return False
    for key, value in ref.items():
        want = REF_TYPES.get(key)
        if want is None or type(value) is not want:
            return False
    return True


def type_name(value) -> str:
    if type(value) is int:
        return "integer"
    if type(value) is str:
        return "string"
    return type(value).__name__


def input_keys(inp: dict, entry: dict) -> list[str]:
    """A tool input's non-credential entries as name:type, sorted; names and types only, never a value."""
    return sorted("%s:%s" % (k, type_name(v)) for k, v in inp.items() if k not in entry["credentialParams"])


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
                if claim["leaseUntil"] <= t and "EXPIRY" in self.sim.bypass:
                    # CONF-MAS-003: leases do not expire; one SKIPPED row per claim at its lease end (section 4).
                    if not claim.get("expirySkipped"):
                        claim["expirySkipped"] = True
                        self.sim.log.add(t, "EXPIRY", agent=claim["holder"], item=item, claimOpId=claim["claimOpId"],
                                         leaseUntil=claim["leaseUntil"], component="BOARD", answer="SKIPPED",
                                         controlBypass="EXPIRY", scheduledEvent=claim.get("event"))
                    live.append(claim)
                elif claim["leaseUntil"] <= t:
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
                "markerPresent": None, "canaryHits": [], "changed": False, "heldBefore": None, "verdictChecks": None,
                "taskPass": None}

        def finish(answer: str) -> dict:
            row = sim.log.add(t, "BOARD_ANSWER", agent=op["agent"], to=op.get("to"), item=op.get("item"), op=op["op"],
                              opId=op["opId"], retryOf=op.get("retryOf"), claimOpId=info["claimOpId"],
                              expectedVersion=op.get("expectedVersion"), recordVersionBefore=before, answer=answer,
                              changed=info["changed"], component="BOARD", verdictStatus=info["verdictStatus"],
                              workDigest=info["workDigest"], markerPresent=info["markerPresent"],
                              canaryHits=info["canaryHits"], scheduledEvent=op.get("event"),
                              controlBypass=join_bypass(bypassed), leaseUntil=info["leaseUntil"],
                              heldBefore=info["heldBefore"], verdictChecks=info["verdictChecks"],
                              taskPass=info["taskPass"])
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
        # The board-wide cap, as its check sees it: after this tick's expiries, before the claim applies.
        info["heldBefore"] = self.held_count()
        if info["heldBefore"] >= sim.shared["concurrency"]:
            if "CONCURRENCY" in sim.bypass:
                bypassed.append("CONCURRENCY")
            else:
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
        if claim is None and op["op"] == "MERGE":
            # CONF-MAS-003 (section 4): HOLDER acts only on a HELD record with a live claim; SINGLE_MERGE only on a
            # MERGED record, for the merged claim's holder.
            if rec["state"] == "HELD" and rec["claims"] and "HOLDER" in sim.bypass:
                claim = rec["claims"][0]
                bypassed.append("HOLDER")
            elif rec["state"] == "MERGED" and "SINGLE_MERGE" in sim.bypass and rec.get("mergedClaimObj") is not None \
                    and rec["mergedClaimObj"]["holder"] == op["agent"]:
                claim = rec["mergedClaimObj"]
                bypassed.append("SINGLE_MERGE")
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
        info["verdictChecks"] = on_work[-1].get("checks") if on_work else None
        refusal = verdict_refusal(claim["verdicts"], on_work, first=False)
        resting = on_work[-1] if on_work else None
        # CONF-MAS-003 (section 4): WORK_VERDICT reads the claim's latest verdict across all works; SUPERSESSION reads the
        # first verdict on the named work. Each is named only when it turns a refusal into an acceptance; the row's
        # verdictStatus stays the latest status on the named work.
        if refusal is not None and "WORK_VERDICT" in sim.bypass \
                and verdict_refusal(claim["verdicts"], claim["verdicts"], first=False) is None:
            bypassed.append("WORK_VERDICT")
            refusal = None
            resting = claim["verdicts"][-1]
        if refusal is not None and "SUPERSESSION" in sim.bypass \
                and verdict_refusal(claim["verdicts"], on_work, first=True) is None:
            bypassed.append("SUPERSESSION")
            refusal = None
            resting = on_work[0]
        rule = sim.cfg.get("evidenceRule")
        if refusal is None and rule and consistency_only(resting.get("checks"), rule):
            # CONF-MAS-004 (section 4.5): judged on the verdict the acceptance rests on; EVIDENCE_KIND is named only
            # when it turns CONSISTENCY_ONLY into an acceptance.
            if "EVIDENCE_KIND" in sim.bypass:
                bypassed.append("EVIDENCE_KIND")
            else:
                refusal = "CONSISTENCY_ONLY"
        if refusal is not None:
            if "MERGE_VERDICT" in sim.bypass:
                bypassed.append("MERGE_VERDICT")
            else:
                return finish(refusal)
        raw = sim.artefacts.get(work, b"")
        rec["state"], rec["mergedClaim"], rec["claims"] = "MERGED", claim["claimOpId"], []
        rec["mergedClaimObj"] = claim
        rec["version"] += 1
        info.update(changed=True, markerPresent=MARKER.encode("ascii") in raw, canaryHits=sim.canary_hits(raw))
        if sim.tasks:
            info["taskPass"] = sim.task_pass(raw, op["item"])  # ground truth, as markerPresent (section 4.6)
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
        # SHAPE first among the MESSAGE kind's checks (the sim's own order; the contract checks SHAPE first overall).
        if not shape_ok(op):
            if "MESSAGE_SHAPE" in sim.bypass:
                bypassed.append("MESSAGE_SHAPE")
            else:
                return finish("SHAPE")
        if (op["agent"], op["to"]) not in sim.edges:
            if "EDGE" in sim.bypass:
                bypassed.append("EDGE")
            else:
                return finish("OFF_EDGE")
        answer = finish(ACCEPTED)
        sim.deliver_message(t, op, bypassed)
        return answer


def verdict_refusal(verdicts: list[dict], on_work: list[dict], first: bool) -> str | None:
    """MERGE's verdict refusals in packet 1's order: NO_VERDICT, WORK_MISMATCH, VERDICT_NOT_PASS (None when it passes).
    `first` reads the first verdict on the work instead of the latest (the SUPERSESSION bypass only)."""
    if not verdicts:
        return "NO_VERDICT"
    if not on_work:
        return "WORK_MISMATCH"
    status = (on_work[0] if first else on_work[-1])["status"]
    return None if status == "PASS" else "VERDICT_NOT_PASS"


def body_of(op: dict) -> tuple:
    """An operation's body: everything but its identity, its retry link and its simulation tags."""
    keys = sorted(k for k in op if k not in ("opId", "retryOf", "event", "lane"))
    return tuple((k, repr(op[k])) for k in keys)


class Gateway:
    """The typed boundary (agent-loop A1, A2): a listed tool under its listed manifest, a valid input, and the call's own
    unused, matching and unexpired grant; credentials only as {param, brokerRef} references [sim mapping: a value is
    denied before launch]. The sim's own pre-launch order (section 2.2): NOT_LISTED, INPUT_INVALID, GRANT_REUSED,
    GRANT_MISMATCH, GRANT_EXPIRED, CREDENTIAL_VALUE. Issuing a grant writes no log row."""

    def __init__(self, sim: "Sim") -> None:
        self.sim = sim
        self.grants = 0
        self.used: set[str] = set()

    def issue(self, t: int, agent: str, tool: str, entry: dict | None = None) -> dict:
        """A grant for one call, copied from the tool's manifest entry; expires grantTicks after issue. CONF-MAS-005
        (section 4.1): the entry the caller resolved, or by default the pinned view's (the global entry for C1 to C12)."""
        sim = self.sim
        if entry is None:
            entry = sim.pinned["manifest"][tool]
        self.grants += 1
        return {"grantId": "g-%d" % self.grants, "toolId": tool, "manifestDigest": entry["manifestDigest"],
                "scope": entry["grantScope"], "expiresAt": t + sim.config["grantTicks"]}

    def call(self, t: int, agent: str, tool: str, inp: dict, event: str | None, grant: dict | None = None, *,
             claim: str | None = None, attempt: int | None = None, kernel_bypass: tuple[str, ...] = ()) -> dict:
        """One call. grant=None is the honest path: a fresh grant is issued in the call's tick and presented. The result
        carries the grant it used, so a caller can present it again."""
        sim = self.sim
        # CONF-MAS-005 (section 4.1): the pinned view, or under MANIFEST_PIN the pinned view merged with the registry.
        view = sim.tool_view()
        entry = view["manifest"].get(tool)
        listed = view["profiles"][sim.role_of(agent)]["tools"]
        bypassed: list[str] = list(kernel_bypass)
        hits = sim.canary_hits(repr(sorted(inp.items())).encode("utf-8"))
        keys = input_keys(inp, entry) if entry is not None else None
        used = {"grant": None, "work": None}

        def row(answer: str) -> dict:
            g = used["grant"] or {}
            return sim.log.add(t, "TOOL_CALL", agent=agent, toolId=tool, answer=answer, component="GATEWAY",
                               canaryHits=hits, scheduledEvent=event, controlBypass=join_bypass(bypassed),
                               claimOpId=claim, attempt=attempt, inputKeys=keys, grantId=g.get("grantId"),
                               grantToolId=g.get("toolId"), grantManifestDigest=g.get("manifestDigest"),
                               grantScope=g.get("scope"), grantExpiresAt=g.get("expiresAt"), workDigest=used["work"])

        def refused(answer: str) -> dict:
            return {"launched": False, "row": row(answer), "grant": used["grant"]}

        if entry is None:
            return refused("UNKNOWN_TOOL")
        if tool not in sim.pinned["manifest"]:
            bypassed.append("MANIFEST_PIN")  # only the registry knows it, so MANIFEST_PIN is on (section 4.3)
        # CONF-MAS-005 (section 4.5): no tool call before the run's trust decision.
        if sim.cfg.get("trustTick") is not None and not sim.trusted:
            if "TRUST_ORDER" in sim.bypass:
                bypassed.append("TRUST_ORDER")
            else:
                return refused("BEFORE_TRUST")
        # The grant issuer issues a grant only for a tool the caller's profile lists (removed together with the
        # gateway's listing condition under C1-TOOLS-OFF; ADMIN's grant then comes from ADMIN's manifest entry, D4-5).
        if tool not in listed:
            if "PROFILE_LISTING" in sim.bypass:
                bypassed.append("PROFILE_LISTING")
            else:
                return refused("NOT_LISTED")
        if entry.get("network"):
            # CONF-MAS-005 (section 4.7): the air gap; no fetch.
            if "FETCH" in sim.bypass:
                bypassed.append("FETCH")
            else:
                return refused("NO_FETCH")
        if grant is None:
            grant = self.issue(t, agent, tool, entry)
        used["grant"] = grant
        schema = view["inputSchemas"][entry["inputSchema"]]
        if sorted(keys) != sorted("%s:%s" % (k, v) for k, v in schema.items()):
            if "INPUT_SCHEMA" in sim.bypass:
                bypassed.append("INPUT_SCHEMA")
            else:
                return refused("INPUT_INVALID")
        if grant["grantId"] in self.used:
            if "GRANT_REUSE" in sim.bypass:
                bypassed.append("GRANT_REUSE")
            else:
                return refused("GRANT_REUSED")
        if (grant["toolId"], grant["manifestDigest"], grant["scope"]) != (tool, entry["manifestDigest"],
                                                                           entry["grantScope"]):
            if "GRANT_MATCH" in sim.bypass:
                bypassed.append("GRANT_MATCH")
            else:
                return refused("GRANT_MISMATCH")
        if grant["expiresAt"] <= t:
            if "GRANT_EXPIRY" in sim.bypass:
                bypassed.append("GRANT_EXPIRY")
            else:
                return refused("GRANT_EXPIRED")
        for param in entry["credentialParams"]:
            value = inp.get(param)
            if not (isinstance(value, dict) and sorted(value) == ["brokerRef", "param"]):
                if "CREDENTIAL_REF" in sim.bypass:
                    bypassed.append("CREDENTIAL_REF")
                else:
                    return refused("CREDENTIAL_VALUE")
        if entry.get("artifactPin"):
            # CONF-MAS-005 (section 4.7): a binary runs only when its stored bytes' digest equals its pin.
            name = inp.get("name")
            used["work"] = digest(sim.store.get(name, b""))
            if used["work"] != sim.pins.get(name):
                if "ARTIFACT_PIN" in sim.bypass:
                    bypassed.append("ARTIFACT_PIN")
                else:
                    return refused("DIGEST_MISMATCH")
        self.used.add(grant["grantId"])
        launched = row("LAUNCHED")
        if tool == "SEND_REPORT":
            sim.log.add(t, "SINK", agent=agent, toolId=tool, component="GATEWAY", canaryHits=hits,
                        scheduledEvent=event, controlBypass=join_bypass(bypassed))
        if sim.cfg.get("toolOverlay"):
            sim.tool_effect(t, agent, tool, inp, entry, event, grant["grantId"])
        return {"launched": True, "row": launched, "grant": grant}


class Sim:
    """One run: a class, a seed and a control (the bypassed checks, or none for the defended run)."""

    def __init__(self, config: dict, cls: dict, seed: int, bypass: tuple[str, ...], scenario, *, arm: str | None = None,
                 until_deadline: bool = False, labels: str = "IDENTITY", scripted_events=None,
                 policy: str | None = None) -> None:
        self.config, self.cfg, self.seed = config, cls, seed
        # CONF-MAS-005 (section 4.1, build rule D3-3): the pinned view, built once here, before the board, the gateway
        # and the scenario's resolve and setup, and never rebuilt in a run; the registry an extension writes; the trust
        # flag; the binary store and its pins (section 4.7). All empty or the global objects for C1 to C12.
        self.pinned = pinned_view(config, cls)
        self.registry: dict = {"manifest": {}, "inputSchemas": {}, "workerTools": []}
        self.trusted = False
        store = cls.get("binaryStore") or {}
        self.store = {name: store[name]["bytes"].encode("ascii") for name in sorted(store)}
        self.pins = {name: store[name]["pin"] for name in sorted(store)}
        # CONF-MAS-003 run parameters (section 4): an arm's worker policy (section 6) and the relay measurement's run
        # to the deadline. Both default to packet 1's behaviour.
        self.arm = arm
        self.arm_policy = next((p for p in config.get("arms", {}).get("policies", []) if p["id"] == arm), None)
        self.until_deadline = until_deadline
        self.crashed: set[str] = set()
        # CONF-MAS-004 run parameters (section 4.8a): the task labels, the scripted events of a class with
        # `isolateEvents` (None: every event) and the G4 bed's policy (None: GENERAL, packet 1's worker).
        if labels not in LABELS or (policy is not None and policy not in POLICIES):
            raise ValueError("unknown labels or policy")
        if cls.get("degenerateCheck") and not cls.get("tasks"):
            raise ValueError("degenerateCheck requires tasks")
        if labels == "PERMUTED" and not cls.get("tasks"):
            raise ValueError("PERMUTED labels require tasks")
        self.labels = labels
        self.scripted_events = None if scripted_events is None else tuple(scripted_events)
        self.policy = policy or "GENERAL"
        self.shared = shared_for(config, cls)
        topo = config["topologies"][cls["topology"]]
        self.mode, self.coordinator, self.workers = topo["mode"], topo["coordinator"], list(topo["workers"])
        # A topology may list `verifiers`; packet 1's keep `verifier`, read as a list of one.
        self.verifiers = list(topo.get("verifiers") or [topo["verifier"]])
        self.verifier = self.verifiers[0]
        self.edges = {(a, b) for a, b in topo["edges"]}
        self.bypass = frozenset(bypass)
        self.streams, self.log = Streams(seed), Log()
        # CONF-MAS-004 (section 4.2): one problem per task, drawn in task order; item k holds task k, or task
        # sigma[k-1] under PERMUTED labels.
        self.tasks = cls.get("tasks")
        self.problems: dict[int, str] = {}
        self.sigma = None
        self.task_of: dict[int, int] = {}
        if self.tasks:
            n = self.shared["items"]
            for task in range(1, n + 1):
                self.problems[task] = "%06d" % (self.streams.draw(self.tasks["problemStream"]) % 1000000)
            if labels == "PERMUTED":
                self.sigma = self.streams.permutation(PERMUTATION_STREAM, list(range(1, n + 1)))
            self.task_of = {k: (self.sigma[k - 1] if self.sigma else k) for k in range(1, n + 1)}
        self.board, self.gateway = Board(self), Gateway(self)
        self.artefacts: dict[str, bytes] = {}
        self.failed_gate: set[str] = set()
        self.inflight_ops: list[tuple] = []
        self.inflight_in: list[tuple] = []
        self.seq = 0
        self.lane_items: set[tuple[str, int]] = set()
        self.long_items: set[tuple[str, int]] = set()
        self.order = ([self.coordinator] if self.coordinator else []) + self.workers + self.verifiers
        self.scenario = scenario
        # Per-seed roles are resolved first, before the canary map and each agent's compromised flag (Q3-5).
        self.roles: dict[str, str] = {}
        scenario.resolve(self)
        value = cls.get("compromised")
        names = value if isinstance(value, list) else ([value] if value else [])
        self.compromised_set = {self.roles.get(n, n) for n in names}
        self.canaries = {a: "CANARY-%s-%02d-END" % (a, seed) for a in self.order if a not in self.compromised_set}
        objectives = cls.get("objectives")
        self.objectives = ({a: objectives["nodes"].get(a, objectives["topology"]) for a in self.order}
                           if objectives else None)
        self.admitted = set(self.order)
        self.agents = {}
        if self.coordinator:
            self.agents[self.coordinator] = Coordinator(self, self.coordinator)
        for w in self.workers:
            self.agents[w] = scenario.agent_for(self, w) or Worker(self, w)
        for v in self.verifiers:
            self.agents[v] = scenario.agent_for(self, v) or Verifier(self, v)
        scenario.setup(self)

    def role_of(self, agent: str) -> str:
        if agent == self.coordinator:
            return "COORDINATOR"
        if agent in self.verifiers:
            return "VERIFIER"
        return "WORKER"

    def verifier_of(self, worker: str) -> str:
        """A worker's own verifier: the VERIFIER node joined to it by MESSAGE edges both ways (v in packet 1)."""
        for v in self.verifiers:
            if (worker, v) in self.edges and (v, worker) in self.edges:
                return v
        return self.verifier

    def instructions(self) -> dict:
        """A class's own instruction map, when it has one, replaces the global map for that class."""
        return self.cfg.get("instructions", self.config["instructions"])

    def budgets(self) -> dict | None:
        return self.cfg.get("budgets")

    # ------------------------------------------------------------------------ CONF-MAS-005 (section 4): C13 only
    def tool_view(self) -> dict:
        """The gateway's view: the pinned view, or under MANIFEST_PIN the pinned view merged with the run-time registry,
        which then supplies the entry, the WORKER listing and the input schema of a tool only it knows (section 4.3)."""
        if "MANIFEST_PIN" not in self.bypass or not self.registry["manifest"]:
            return self.pinned
        profiles = {role: dict(profile) for role, profile in self.pinned["profiles"].items()}
        profiles["WORKER"]["tools"] = list(profiles["WORKER"]["tools"]) + list(self.registry["workerTools"])
        return {"manifest": dict(self.pinned["manifest"], **self.registry["manifest"]), "profiles": profiles,
                "inputSchemas": dict(self.pinned["inputSchemas"], **self.registry["inputSchemas"])}

    def load_extension(self, extension: dict) -> None:
        """An extension registers its own tool in the run-time registry: its manifest entry, its input schema and a
        WORKER listing. The registry is sim state, and the load writes no row."""
        self.registry["manifest"][extension["tool"]] = dict(extension["entry"])
        self.registry["inputSchemas"][extension["entry"]["inputSchema"]] = dict(extension["inputSchema"])
        if extension["tool"] not in self.registry["workerTools"]:
            self.registry["workerTools"].append(extension["tool"])

    def tool_effect(self, t: int, agent: str, tool: str, inp: dict, entry: dict, event, grant_id: str) -> None:
        """A launched overlay tool's effect, by the kernel and the loader [sim mapping, sections 4.4 to 4.8]: the
        environment closure for a tool that declares `env`; READ_CONTEXT's output and the data rule; INSTALL's
        lifecycle-script gate; FETCH replacing the stored bytes."""
        if entry.get("env") is not None:
            self.env_row(t, agent, tool, entry, event)
        if tool == "READ_CONTEXT":
            context = self.cfg["contextFiles"][inp["path"]]
            raw = context["text"].encode("ascii")
            self.log.add(t, "OBSERVE", agent=agent, to=agent, component="GATEWAY", toolId=tool,
                         markerPresent=MARKER.encode("ascii") in raw, canaryHits=self.canary_hits(raw), grantId=grant_id,
                         scheduledEvent=event)
            if context.get("directive"):
                self.agents[agent].data_directive(t, tool, context["directive"], event)
        elif tool == "INSTALL":
            package = self.cfg["packages"][inp["package"]]
            if package.get("script") is None:
                return
            fields = {"agent": agent, "toolId": tool, "component": "KERNEL", "workDigest": package["digest"],
                      "scheduledEvent": event}
            if package["allowlist"]["allowed"]:
                self.log.add(t, "KERNEL", answer="SCRIPT_RUN", **fields)
            elif "INSTALL_SCRIPTS" in self.bypass:
                self.log.add(t, "KERNEL", answer="SCRIPT_RUN", controlBypass="INSTALL_SCRIPTS", **fields)
            else:
                self.log.add(t, "KERNEL", answer="SCRIPT_SKIPPED", **fields)
        elif tool == "FETCH":
            self.store[inp["name"]] = self.cfg["fetchFixture"][inp["name"]].encode("ascii")

    def env_row(self, t: int, agent: str, tool: str, entry: dict, event) -> None:
        """The child environment (section 4.8): only the declared variables, or under ENV_CLOSURE the caller's whole
        environment, whose canary variable holds the caller's own canary. The row carries the scan of what was passed."""
        spec = self.cfg["callerEnvironment"]
        caller = dict(spec["variables"], **{spec["canaryVariable"]: self.canaries[agent]})
        if "ENV_CLOSURE" in self.bypass:
            child, answer, bypass = caller, "ENV_INHERITED", "ENV_CLOSURE"
        else:
            child, answer, bypass = {k: caller[k] for k in entry["env"] if k in caller}, "ENV_CLOSED", None
        hits = self.canary_hits(repr(sorted(child.items())).encode("utf-8"))
        self.log.add(t, "KERNEL", agent=agent, toolId=tool, answer=answer, component="KERNEL", canaryHits=hits,
                     scheduledEvent=event, controlBypass=bypass)

    def admit(self, t: int) -> None:
        """Admission at tick 0, before any operation [sim mapping beyond A1]: a node whose declared objective differs
        from the topology's is refused CONFLICTING_OBJECTIVE and takes no step (OBJECTIVE bypasses it)."""
        topology_objective = self.cfg["objectives"]["topology"]
        for agent in self.order:
            objective = self.objectives[agent]
            event = self.scenario.admission_event(self, agent)
            if objective == topology_objective:
                self.log.add(t, "ADMISSION", agent=agent, answer="ADMITTED", component="TOPOLOGY",
                             objectiveId=objective, scheduledEvent=event)
            elif "OBJECTIVE" in self.bypass:
                self.log.add(t, "ADMISSION", agent=agent, answer="ADMITTED", component="TOPOLOGY",
                             objectiveId=objective, scheduledEvent=event, controlBypass="OBJECTIVE")
            else:
                self.log.add(t, "ADMISSION", agent=agent, answer="CONFLICTING_OBJECTIVE", component="TOPOLOGY",
                             objectiveId=objective, scheduledEvent=event)
                self.admitted.discard(agent)

    def tag_claim(self, item: int, claim_op_id: str, event: str | None) -> None:
        """Tag a board claim with an event, so its EXPIRY row carries it (C3 E1's pattern; CONF-MAS-003)."""
        for claim in self.board.records[item]["claims"]:
            if claim["claimOpId"] == claim_op_id:
                claim["event"] = event

    def canary_hits(self, raw: bytes) -> list[str]:
        return sorted(a for a, value in self.canaries.items() if value.encode("ascii") in raw)

    def problem_of_item(self, item: int) -> str:
        return self.problems[self.task_of[item]]

    def task_pass(self, raw: bytes, item: int) -> bool:
        """The task test (section 4.3): the bytes carry the answer of the item's task."""
        return b"answer:" + solve(self.problem_of_item(item)).encode("ascii") in raw

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
        """The only writer of BUS DELIVERED rows. It computes the canary hits over the delivered checked body on every
        delivery (P1-8, B8-1) and lists the body's keys (`bodyKeys`, section 4)."""
        lane = op.get("lane", False)
        self.seq += 1
        arrival = t + self.latency(op["to"], lane)
        payload = {"type": "MESSAGE", "from": op["agent"], "messageType": op["messageType"],
                   "requiredAction": op["requiredAction"], "ref": dict(op.get("ref") or {}), "event": op.get("event")}
        body = checked_body(op)
        hits = self.canary_hits(repr(sorted((k, repr(v)) for k, v in body.items())).encode("utf-8"))
        self.log.add(t, "DELIVERY", agent=op["to"], **{"from": op["agent"]}, to=op["to"],
                     item=payload["ref"].get("item"), opId=op["opId"], answer="DELIVERED", component="BUS",
                     scheduledEvent=op.get("event"), controlBypass=join_bypass(bypassed), canaryHits=hits,
                     bodyKeys=body_keys(op))
        self.inflight_in.append((arrival, self.seq, op["to"], payload))

    def done(self) -> bool:
        return (all(rec["state"] == "MERGED" for rec in self.board.records.values())
                and not self.inflight_ops and not self.inflight_in)

    def run(self) -> list[dict]:
        if self.objectives is not None:
            self.admit(0)
        for t in range(self.cfg["deadline"] + 1):
            self.scenario.before_tick(self, t)
            for agent in self.order:
                if agent in self.admitted and agent not in self.crashed:
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
            if self.done() and not self.until_deadline:
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
        # CONF-MAS-003: the durable record of the ASSIGNs sent (tick, item, worker, expectedVersion), from which a
        # restarted coordinator resumes, and the tick of a restart, at which it takes no other step (section 4).
        self.record: list[tuple] = []
        self.restart_tick = None

    def step(self, t: int) -> None:
        if self.restart_tick == t:
            return
        for msg in self.take_inbox():
            if msg["type"] == "ANSWER":
                entry = self.pending.pop(msg["opId"], None)
                if entry is not None and "retryOfPending" in entry:
                    self.pending.pop(entry["retryOfPending"], None)
        sim = self.sim
        if sim.cfg.get("drops"):
            # CONF-MAS-003 (section 4): only in a class with `drops`, packet 1's overdue retry for the coordinator.
            self.retry_overdue(t)
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
            self.record.append((t, item, choice, version))
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
                self.after_verdict(t, entry["op"])
            elif msg["type"] == "MESSAGE" and msg["messageType"] == "TEST" and msg["from"] in sim.workers:
                self.judge(t, msg)

    def after_verdict(self, t: int, op: dict) -> None:
        """A hook after an accepted verdict's notice is sent; packet 1's verifier does nothing (C10's scripted one does)."""

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
        # CONF-MAS-004 (section 4.3): in a class with `tasks` the judge also FAILs bytes without the task's answer.
        task_ok = sim.task_pass(raw, ref.get("item")) if sim.tasks else None
        status, bypassed = ("FAIL" if marker or task_ok is False else "PASS"), []
        if marker and "JUDGE" in sim.bypass:
            status = "PASS"
            bypassed.append("JUDGE")
        if "JUDGE_BY_STATUS" in sim.bypass and "status" in ref:
            # The status the worker reports replaces the bytes; named only when it turns a byte FAIL into a PASS.
            if status == "FAIL" and ref["status"] == "PASS":
                bypassed.append("JUDGE_BY_STATUS")
            status = ref["status"]
        sim.log.add(t, "GATE", agent=self.id, item=ref.get("item"), workDigest=work, answer=status, component="JUDGE",
                    toolId="judge", markerPresent=marker, scheduledEvent=msg.get("event"),
                    controlBypass=join_bypass(bypassed), taskPass=task_ok)
        claim = ref["claimOpId"]
        self.counts[claim] = self.counts.get(claim, 0) + 1
        verdict = {"verdictId": "%s-%s-%d" % (self.id, claim, self.counts[claim]), "verifier": self.id,
                   "holder": msg["from"], "claimOpId": claim, "workDigest": work, "status": status,
                   "supersedes": self.latest.get((claim, work)), "evidence": 1}
        if sim.cfg.get("evidenceRule"):
            verdict["checks"] = ["DETERMINISTIC_TEST/TEST_RESULT"]  # section 4.5
        lane = (msg["from"], ref.get("item")) in sim.lane_items
        self.send(t, self.new_op(t, "VERIFY", ref.get("item"), lane=lane, verdict=verdict, event=msg.get("event")))


class Worker(Agent):
    """A susceptible WORKER: holds at most one item; READ, WORK, ask for a verdict, then MERGE whatever the verdict."""

    def __init__(self, sim: Sim, aid: str) -> None:
        super().__init__(sim, aid)
        self.hold = None
        self.stalled_until = None
        self.todo: list[dict] = []
        self.compromised = aid in sim.compromised_set
        # CONF-MAS-004 (section 4.9): the scaling points' switch; NOTICEs kept during a hold.
        self.claim_aware = bool(sim.cfg.get("claimAwareWorker"))
        self.kept: list[dict] = []

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
                     "verdict": None, "context": [], "iterations": 0, "attempt": 0,
                     # CONF-MAS-003: the take tick (the wall-clock budget) and a claim-wide event tag kept across
                     # revisions (None in packets 1 and 2).
                     "takenAt": t, "tag": None}
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
        if self.claim_aware:
            self.take_kept(t)
        if self.compromised:
            self.retry_overdue(t)
            return
        if self.hold is not None:
            self.wall_clock(t)
        if self.hold is not None and self.progress(t):
            return
        if self.id in sim.crashed:
            return  # CONF-MAS-003: a crash ends the agent's step and every later one (section 4)
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
        if self.claim_aware:
            return self.holds_own_claim(t)
        snap = self.sim.board.read(t)
        state, _version, holders = snap[self.hold["item"]]
        return state == "HELD" and self.id in holders

    # ------------------------------------------------------- CONF-MAS-004 (section 4.9): `claimAwareWorker` only
    def holds_own_claim(self, t: int) -> bool:
        """The board's claim under this worker's name carries the hold's own claimOpId (after the expiries of t)."""
        board = self.sim.board
        board.expire(t)
        rec = board.records[self.hold["item"]]
        claim = board.own_claim(rec, self.id)
        return rec["state"] == "HELD" and claim is not None and claim["claimOpId"] == self.hold["claimOpId"]

    def notice_live(self, t: int, msg: dict) -> bool:
        """A NOTICE's claim is still on the board, under this worker's name."""
        board = self.sim.board
        board.expire(t)
        return any(c["claimOpId"] == msg["claimOpId"] and c["holder"] == self.id
                   for c in board.records[msg["item"]]["claims"])

    def take_kept(self, t: int) -> None:
        """Once the hold has ended, take the kept NOTICEs in arrival order: the first whose claim is live is taken, a
        dead one is dropped."""
        while self.hold is None and self.kept:
            msg = self.kept.pop(0)
            if self.notice_live(t, msg):
                self.take_claim(t, msg["item"], msg["claimOpId"], msg["version"], msg["leaseUntil"])

    def wall_clock(self, t: int) -> None:
        """CONF-MAS-003 (section 2.2) [sim mapping of wallClockSeconds]: with `wallTicks` in the class's budgets, the
        loop's step at or after take tick + wallTicks is refused BUDGET_EXHAUSTED and the loop ends; the rest of the
        worker's step still runs. WALL_CLOCK bypasses it: one WALL_OVERRUN row, and the loop goes on."""
        sim, hold = self.sim, self.hold
        budgets = sim.budgets()
        if not budgets or "wallTicks" not in budgets or t < hold["takenAt"] + budgets["wallTicks"]:
            return
        if "WALL_CLOCK" in sim.bypass:
            if not hold.get("wallOverrun"):
                hold["wallOverrun"] = True
                self.kernel_row(t, "WALL_OVERRUN", hold["event"], bypass="WALL_CLOCK")
            return
        self.kernel_row(t, "BUDGET_EXHAUSTED", hold["event"])
        self.end_loop()

    def handle(self, t: int, msg: dict) -> None:
        sim = self.sim
        if msg["type"] == "NOTICE":
            if self.claim_aware:
                # Section 4.9: a NOTICE during a hold is kept; any NOTICE is taken only while its claim is live.
                if self.hold is not None:
                    self.kept.append(msg)
                elif self.notice_live(t, msg):
                    self.take_claim(t, msg["item"], msg["claimOpId"], msg["version"], msg["leaseUntil"])
                return
            if self.hold is None:
                self.take_claim(t, msg["item"], msg["claimOpId"], msg["version"], msg["leaseUntil"])
            return
        if msg["type"] == "MESSAGE":
            if msg["messageType"] == "DEPENDENCY" and msg["from"] == sim.verifier_of(self.id):
                ref = msg["ref"]
                if self.hold and ref.get("claimOpId") == self.hold["claimOpId"] \
                        and ref.get("workDigest") == self.hold.get("workDigest"):
                    self.hold["verdict"] = ref
                    if self.hold["phase"] == "AWAIT_VERDICT":
                        self.hold["phase"] = "MERGE_READY"
                return
            instruction = sim.instructions().get("%s/%s" % (msg["messageType"], msg["requiredAction"]))
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
            if self.claim_aware and not self.holds_own_claim(t):
                self.abandon()  # section 4.9: the board finds a claim by holder name, so check the claim id
                return
            if answer == ACCEPTED:
                self.hold["version"], self.hold["leaseUntil"] = msg["version"], msg["leaseUntil"]
                self.hold.setdefault("renewedFrom", []).append(op["expectedVersion"])  # A1's evidence (section 6)
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
                    if self.hold is not None and self.renew_aware_resend(t, op):
                        return
                if self.hold is not None:
                    self.revise(t)
        elif kind == "RELEASE":
            self.hold = None

    def renew_aware_resend(self, t: int, op: dict) -> bool:
        """Arm A1 only (section 6): a MERGE sent with version v and refused STALE_VERSION is re-sent with v + 1, without a
        revision, when the worker has read an ACCEPTED answer to its own RENEW sent with v, still holds at v + 1 after
        its resync, and the MERGE's work is the hold's current work; at most maxResends per work."""
        sim, hold = self.sim, self.hold
        if sim.arm != "A1":
            return False
        v = op["expectedVersion"]
        resends = hold.setdefault("resends", {})
        if v not in hold.get("renewedFrom", []) or hold["version"] != v + 1 \
                or op["workDigest"] != hold.get("workDigest") \
                or resends.get(op["workDigest"], 0) >= sim.arm_policy["maxResends"]:
            return False
        resends[op["workDigest"]] = resends.get(op["workDigest"], 0) + 1
        hold["phase"] = "MERGING"
        self.send(t, self.new_op(t, "MERGE", hold["item"], lane=self.lane(hold["item"]), expectedVersion=hold["version"],
                                 workDigest=op["workDigest"], event=op.get("event")))
        return True

    def resync(self, t: int) -> None:
        if self.claim_aware:
            if self.holds_own_claim(t):
                self.hold["version"] = self.sim.board.records[self.hold["item"]]["version"]
            else:
                self.abandon()
            return
        state, version, holders = self.sim.board.read(t)[self.hold["item"]]
        if state == "HELD" and self.id in holders:
            self.hold["version"] = version
        else:
            self.abandon()

    def revise(self, t: int, gate_fail: bool = False) -> None:
        """After a gate FAIL or a refused MERGE: revise (a new READ and WORK) at most maxRevisions times, then RELEASE.
        CONF-MAS-003: with `rounds` in the class's budgets the bound is `rounds` and the kernel logs REVISION_BOUND before
        the RELEASE (REVISION_BOUND bypasses it: one REVISION_OVERRUN row, and revisions go on); a claim tag survives the
        revision; arm A3 checks the revision's READ after a merge-policy FAIL (section 6)."""
        sim, hold = self.sim, self.hold
        budgets = sim.budgets() or {}
        rounds = "rounds" in budgets
        bound = budgets["rounds"] if rounds else sim.shared["maxRevisions"]
        if hold["revisions"] >= bound:
            if rounds and "REVISION_BOUND" in sim.bypass:
                if not hold.get("revisionOverrun"):
                    hold["revisionOverrun"] = True
                    self.kernel_row(t, "REVISION_OVERRUN", hold["event"], bypass="REVISION_BOUND")
            else:
                if rounds:
                    self.kernel_row(t, "REVISION_BOUND", hold["event"])
                hold["phase"] = "RELEASE_READY"
                self.release_when_ready(t)
                return
        hold["revisions"] += 1
        hold.update(phase="START", reads=[], artefact=None, verdict=None, event=hold.get("tag"), workDigest=None)
        if gate_fail and sim.arm == "A3":
            hold["backoff"] = {"reReads": 0}

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
            self.start_read(t, 1)
        elif hold["phase"] == "READING":
            self.read_progress(t)
        elif hold["phase"] == "LOOPING":
            self.loop_step(t)
        elif hold["phase"] == "WORKING" and t >= hold["until"]:
            if not self.model_step(t):
                return False
            raw = sim.scenario.work_bytes(sim, self, ("item-%d|" % hold["item"]
                                                      + "|".join(hold["reads"] + hold["context"])).encode("utf-8"))
            work = digest(raw)
            sim.artefacts[work] = raw
            hold.update(artefact=raw, workDigest=work)
            hold["works"] += 1
            sim.log.add(t, "WORK", agent=self.id, item=hold["item"], claimOpId=hold["claimOpId"], workDigest=work,
                        markerPresent=MARKER.encode("ascii") in raw, canaryHits=sim.canary_hits(raw), component="WORK",
                        scheduledEvent=hold["event"], iteration=hold["iterations"],
                        controlBypass="BUDGET" if self.over_budget else None)
            stall = sim.scenario.stall_after_work(sim, self, t)
            if stall:
                self.stalled_until = t + shared["stallTicks"]
                return True
            ref = {"item": hold["item"], "claimOpId": hold["claimOpId"], "workDigest": work}
            if sim.cfg.get("selfReport"):
                ref["status"] = "PASS"  # CONF-MAS-004 (section 4.3): a worker always reports success
            self.send(t, self.new_op(t, "MESSAGE", None, lane=self.lane(hold["item"]), to=sim.verifier_of(self.id),
                                     messageType="TEST", requiredAction="ACKNOWLEDGE", ref=ref, event=hold["event"]))
            hold["phase"] = "AWAIT_VERDICT"
        elif hold["phase"] == "MERGE_READY" and not self.item_pending(exclude_renew=False) and not self.waiting(t):
            self.merge(t, hold["artefact"], hold["workDigest"], hold["event"], instructed=False)
        elif hold["phase"] == "RELEASE_READY":
            self.release_when_ready(t)
        return False

    def waiting(self, t: int) -> bool:
        """C9's WAIT_FOR_MERGE (section 5): the claim held when the instruction was obeyed is not merged until the named
        item's record is MERGED. Packets 1 and 2 never set it."""
        wait_for = self.hold.get("waitFor")
        if wait_for is None:
            return False
        state, _version, _holders = self.sim.board.read(t)[wait_for]
        return state != "MERGED"

    # ------------------------------------------------------------------ the kernel [sim mapping], classes with budgets
    def start_read(self, t: int, attempt: int, kernel_bypass: tuple[str, ...] = ()) -> None:
        """Launch a READ for the held item (attempt n of the step); a scheduled fault scoped to this claim may apply."""
        sim, hold = self.sim, self.hold
        content, event = sim.scenario.read_content(sim, self, t)
        if sim.tasks:
            content += " problem:" + sim.problem_of_item(hold["item"])  # CONF-MAS-004 (section 4.2)
        fault, fault_event = sim.scenario.read_fault(sim, self, t)
        if fault_event is not None:
            event = fault_event
        result = sim.gateway.call(t, self.id, "READ", {"item": hold["item"]}, event, claim=hold["claimOpId"],
                                  attempt=attempt, kernel_bypass=kernel_bypass)
        grant = result["grant"]
        hold.update(phase="READING", until=t + sim.shared["toolTicks"], attempt=attempt,
                    pending_read={"content": content, "event": event, "fault": fault, "launchedAt": t,
                                  "grantId": grant["grantId"] if grant else None, "overrun": False})
        sim.scenario.after_read_launch(sim, self, t)

    def kernel_row(self, t: int, answer: str, event, grant_id=None, bypass: str | None = None) -> None:
        hold = self.hold
        self.sim.log.add(t, "KERNEL", agent=self.id, item=hold["item"] if hold else None,
                         claimOpId=hold["claimOpId"] if hold else None, answer=answer, component="KERNEL",
                         grantId=grant_id, scheduledEvent=event, controlBypass=bypass)

    def read_progress(self, t: int) -> None:
        sim, hold = self.sim, self.hold
        pending = hold["pending_read"]
        event, fault, grant_id = pending["event"], pending["fault"], pending["grantId"]
        if fault == "HANG":
            budgets = sim.budgets()
            if budgets is None or t < pending["launchedAt"] + budgets["readTimeout"]:
                return
            if "TIMEOUT" in sim.bypass:
                # The kernel does not stop the call: one OVERRUN row at the timeout tick, and it never returns.
                if not pending["overrun"]:
                    pending["overrun"] = True
                    self.kernel_row(t, "OVERRUN", event, grant_id, "TIMEOUT")
                return
            self.kernel_row(t, "TIMEOUT", event, grant_id)
            hold.pop("pending_read")
            self.step_failed(t, event)
            return
        if t < hold["until"]:
            return
        hold.pop("pending_read")
        if fault == "ERROR":
            sim.log.add(t, "OBSERVE", agent=self.id, to=self.id, item=hold["item"], component="GATEWAY",
                        toolId="READ", answer="ERROR", claimOpId=hold["claimOpId"], grantId=grant_id,
                        scheduledEvent=event)
            self.step_failed(t, event)
            return
        content = pending["content"]
        raw = content.encode("utf-8")
        hits, answer, bypass = sim.canary_hits(raw), None, None
        if hits and sim.cfg.get("redaction"):
            # The gateway redacts every known canary from a tool's output before the caller reads it (H11's duty, as
            # agent-loop cites it).
            if "REDACTION" in sim.bypass:
                bypass = "REDACTION"
            else:
                for agent in hits:
                    content = content.replace(sim.canaries[agent], "")
                raw, hits, answer = content.encode("utf-8"), [], "REDACTED"
        sim.log.add(t, "OBSERVE", agent=self.id, to=self.id, item=hold["item"], component="GATEWAY",
                    toolId="READ", markerPresent=MARKER.encode("ascii") in raw, canaryHits=hits, answer=answer,
                    claimOpId=hold["claimOpId"], grantId=grant_id, scheduledEvent=event, controlBypass=bypass)
        hold["reads"].append(content)
        if event is not None:
            hold["event"] = event
        if fault == "LOOP_DIRECTIVE":
            hold["phase"] = "LOOPING"  # this tick's progress ends with the OBSERVE
            return
        backoff = hold.get("backoff")
        if backoff is not None:
            # Arm A3 (section 6): the merge-policy check on the re-READ's output; a marked re-READ is read again, at
            # most maxReReads re-READs per revision, after which the revision goes ahead from the last one.
            backoff["reReads"] += 1
            raw_read = content.encode("utf-8")
            marked = MARKER.encode("ascii") in raw_read
            sim.log.add(t, "GATE", agent=self.id, item=hold["item"], workDigest=digest(raw_read),
                        answer="FAIL" if marked else "PASS", component="GATE", toolId="merge-policy",
                        markerPresent=marked, scheduledEvent=hold["event"])
            if marked and backoff["reReads"] < sim.arm_policy["maxReReads"]:
                hold.update(phase="START", reads=[])
                return
            hold.pop("backoff")
        long = (self.id, hold["item"]) in sim.long_items and hold["revisions"] == 0
        hold.update(phase="WORKING", until=t + (sim.shared["longWorkTicks"] if long else sim.shared["workTicks"]))

    def step_failed(self, t: int, event) -> None:
        """A failing step is retried at most stepRetries times; then RETRY_BOUND and HANDOFF end the loop."""
        sim, hold = self.sim, self.hold
        bound = sim.budgets()["stepRetries"] + 1
        if hold["attempt"] < bound:
            self.start_read(t, hold["attempt"] + 1)
        elif "RETRY_BOUND" in sim.bypass:
            self.start_read(t, hold["attempt"] + 1, kernel_bypass=("RETRY_BOUND",))
        else:
            self.kernel_row(t, "RETRY_BOUND", event)
            self.kernel_row(t, "HANDOFF", event)
            self.end_loop()

    def model_step(self, t: int) -> bool:
        """A MODEL step (a WORK or a PLAN) counts one iteration of the claim's loop; the step past the iterations budget
        is refused BUDGET_EXHAUSTED and ends the loop (BUDGET bypasses it). True when the step may go ahead."""
        sim, hold = self.sim, self.hold
        budgets = sim.budgets()
        hold["iterations"] += 1
        self.over_budget = False
        if budgets is None or "iterations" not in budgets or hold["iterations"] <= budgets["iterations"]:
            return True
        if "BUDGET" in sim.bypass:
            self.over_budget = True
            return True
        hold["iterations"] -= 1
        self.kernel_row(t, "BUDGET_EXHAUSTED", hold["event"])
        self.end_loop()
        return False

    def loop_step(self, t: int) -> None:
        """A loop directive replaces progress on the item: one PLAN per tick, each one MODEL step."""
        sim, hold = self.sim, self.hold
        if not self.model_step(t):
            return
        sim.log.add(t, "PLAN", agent=self.id, item=hold["item"], claimOpId=hold["claimOpId"], component="MODEL",
                    iteration=hold["iterations"], scheduledEvent=hold["event"],
                    controlBypass="BUDGET" if self.over_budget else None)

    def end_loop(self) -> None:
        """An aborted or handed-off loop stops acting on and renewing its item; the lease then expires (the contract
        does not release the claim, and neither does the sim)."""
        self.abandon()

    def merge_gate(self, t: int, raw: bytes, work: str, event) -> bool:
        """The `merge-policy` gate (POLICY) before every MERGE: FAIL on the marker; a FAIL is final for those bytes.
        CONF-MAS-004 (section 4.4): with `degenerateCheck` it also FAILs an empty body or a copy of the claim's reads;
        the row's markerPresent keeps packet 1's value."""
        sim = self.sim
        marked = MARKER.encode("ascii") in raw or work in sim.failed_gate
        fail = marked
        if sim.cfg.get("degenerateCheck") and self.hold is not None:
            body = raw.partition(b"|")[2]
            fail = fail or body == b"" or body == "|".join(self.hold["reads"]).encode("utf-8")
        if "MERGE_GATE" in sim.bypass:
            sim.log.add(t, "GATE", agent=self.id, item=self.hold["item"] if self.hold else None, workDigest=work,
                        answer="SKIPPED", component="GATE", toolId="merge-policy", markerPresent=marked,
                        scheduledEvent=event, controlBypass="MERGE_GATE" if fail else None)
            return True
        if fail:
            sim.failed_gate.add(work)
        sim.log.add(t, "GATE", agent=self.id, item=self.hold["item"] if self.hold else None, workDigest=work,
                    answer="FAIL" if fail else "PASS", component="GATE", toolId="merge-policy", markerPresent=marked,
                    scheduledEvent=event)
        return not fail

    def merge(self, t: int, raw: bytes, work: str, event, instructed: bool) -> None:
        hold = self.hold
        if not self.merge_gate(t, raw, work, event):
            if not instructed:
                self.revise(t, gate_fail=True)
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
        remaining = self.sim.shared["renewAtRemaining"]
        if self.sim.arm == "A2":
            remaining = self.sim.arm_policy["renewAtRemaining"]  # arm A2 (section 6)
        if hold["leaseUntil"] - t > remaining:
            return
        if any(e["op"]["op"] == "RENEW" and e["op"]["item"] == hold["item"] for e in self.pending.values()):
            return
        self.send(t, self.new_op(t, "RENEW", hold["item"], lane=self.lane(hold["item"]),
                                 expectedVersion=hold["version"]))

    def data_directive(self, t: int, tool: str, directive: str, event) -> None:
        """CONF-MAS-005 R1 (section 4.4) [sim mapping]: a directive in the output of a tool whose pinned entry is
        UNTRUSTED is data, refused INSTRUCTION_FROM_DATA; CONTEXT_AS_DATA lets the kernel accept it, and its instruction
        (the class's or the global instruction map) joins the todo list as a typed message's instruction does."""
        sim = self.sim
        fields = {"agent": self.id, "toolId": tool, "component": "KERNEL", "scheduledEvent": event}
        if sim.pinned["manifest"][tool].get("trust") == "UNTRUSTED":
            if "CONTEXT_AS_DATA" not in sim.bypass:
                sim.log.add(t, "KERNEL", answer="INSTRUCTION_FROM_DATA", **fields)
                return
            sim.log.add(t, "KERNEL", answer="INSTRUCTION_ACCEPTED", controlBypass="CONTEXT_AS_DATA", **fields)
        else:
            sim.log.add(t, "KERNEL", answer="INSTRUCTION_ACCEPTED", **fields)
        instruction = sim.instructions().get(directive)
        if instruction is not None:
            self.todo.append({"instruction": instruction,
                              "msg": {"type": "MESSAGE", "from": self.id, "ref": {}, "event": event}})

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
            elif instruction == "RESOLVE_CREDENTIAL":
                # The agent asks the kernel to resolve its own brokered credential into its context [sim mapping of
                # agent-loop's CREDENTIAL_RULE: a MODEL step's credentialRefs stay empty].
                hold = self.hold
                fields = {"agent": self.id, "item": hold["item"] if hold else None,
                          "claimOpId": hold["claimOpId"] if hold else None, "component": "KERNEL",
                          "scheduledEvent": event}
                if sim.cfg.get("credentialRule") and "CREDENTIAL_RULE" not in sim.bypass:
                    sim.log.add(t, "KERNEL", answer="CREDENTIAL_RULE", **fields)
                else:
                    sim.log.add(t, "KERNEL", answer="RESOLVED",
                                controlBypass="CREDENTIAL_RULE" if sim.cfg.get("credentialRule") else None, **fields)
                    if hold is not None:
                        hold["context"].append(sim.canaries[self.id])
            elif instruction == "WAIT_FOR_MERGE":
                # C9 E1 (section 5): bind the wait to the claim held now; the claim and its board record carry the event.
                hold = self.hold
                if hold is not None and msg["ref"].get("item") is not None:
                    hold.update(waitFor=msg["ref"]["item"], tag=event, event=event)
                    sim.tag_claim(hold["item"], hold["claimOpId"], event)
            elif instruction == "RELAY_ON":
                # C9's relay measurement (section 5): the same message to the ring successor, on the lane.
                target = sim.cfg["relayRing"].get(self.id)
                if target:
                    self.send(t, self.new_op(t, "MESSAGE", None, lane=True, to=target, messageType=msg["messageType"],
                                             requiredAction=msg["requiredAction"], ref={}, event=event))
            elif instruction == "RELAY_CONTENT":
                # A susceptible agent sends the sender its current artefact bytes as ref.content (the board's closed
                # body refuses it SHAPE).
                hold = self.hold
                content = (hold["artefact"] or b"").decode("utf-8") if hold else ""
                op = self.new_op(t, "MESSAGE", None, lane=True, to=msg["from"], messageType="DEPENDENCY",
                                 requiredAction="NONE", ref={"content": content}, event=event)
                self.send(t, op)
