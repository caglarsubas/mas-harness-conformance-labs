#!/usr/bin/env python3
"""I07 policy writer channel v3 (W02-ADM-F): frame envelope, closed policy-kind table and gate decisions.

DATA_CHECK_ONLY reference model for the private interface between the enrolled policy-writer
artifact and the effect gate (HOST-INTERFACE-DRAFT-002 sections 2.3, 2.4, 3.2 A3/A4, 4.3 and 5.5).
It is the W02-ADM-F successor of `i07_policy_write_v2` (adopted and frozen), which extended the I05 v2
gate, sealed the admission-policy kinds and answered the v1 review findings R1-R8. v3 extends the I05 v3
gate (`i05_gate_channel_v3.Gate`) and answers the v2 review findings W1-W4: conditional schema
constraints on responses, a bounded upstream exchange (TIMEOUT), and no unreachable CLUSTER scope.

- `check_write` applies the closed policy-kind table to one WRITE_OBJECT request: which kinds,
  scopes and operations the writer identity may change, and the exact object shape.
- `render_write` derives the one Kubernetes request a write permits (method, path, headers and
  body), including the uid and resourceVersion preconditions the apiserver enforces.
- `PolicyGate` extends the reviewed I05 v3 gate model (`i05_gate_channel_v3.Gate`, unchanged) with
  the I07 channel. A WRITE_BEGIN asks for the gate's drain; maintenance opens only when the gate's own
  A3 fence (`Gate.fence`) is OPEN, and it keeps evaluating the fence afterwards (OPEN can become HELD).
  A generation the gate rebuilt after a restart never opens a maintenance. Every write is journalled
  durably before its first upstream byte; its upstream outcome is a separate event, and its terminal
  classification is durable before its response and before the session or the maintenance ends.

None of it opens a socket, forwards a request or grants authority.
"""
from __future__ import annotations

import copy
from typing import Any

try:
    import i05_gate_channel_v3 as i05
except ImportError:
    from scripts import i05_gate_channel_v3 as i05

FRAME_VERSION = "planeon.internal.policy-write-frame/v3"
OPERATIONS = ("MAINTENANCE_STATUS", "WRITE_BEGIN", "WRITE_OBJECT", "WRITE_END")
MAINTENANCE_STATES = ("NONE", "PENDING", "OPEN", "HELD", "ENDED")
WRITE_OPERATIONS = ("CREATE", "UPDATE", "DELETE")
SCOPES = ("QUALIFICATION_NAMESPACE", "QUALIFICATION_NAMESPACE_OBJECT")   # no writable row is cluster-scoped (W4)
SUCCESS_STATUSES = {"CREATE": (201,), "UPDATE": (200, 201), "DELETE": (200, 202)}
METADATA_KEYS = ("annotations", "labels", "name", "namespace", "resourceVersion", "uid")
MAX_WRITES = 256
CLASSIFICATIONS = ("DELIVERED_RESULT", "IO_AMBIGUOUS")
ZERO_DIGEST = i05.ZERO_DIGEST
canonical, sha, require, frame_digest = i05.canonical, i05.sha, i05.require, i05.frame_digest
check_frame, decode_frame = i05.check_frame, i05.decode_frame


# ---------------------------------------------------------------- closed policy-kind table

def api_version(entry: dict) -> str:
    return entry["group"] + "/" + entry["version"] if entry["group"] else entry["version"]


def classify_resource(kinds: dict, resource: dict) -> tuple[dict | None, str | None]:
    """The table entry for a requested resource, or the refusal. Writable kinds match group, version and
    resource exactly; effect kinds and non-writable policy kinds match by group and resource at any version;
    everything else is outside the table."""
    key = (resource["group"], resource["version"], resource["resource"])
    for entry in kinds["writable"]:
        if (entry["group"], entry["version"], entry["resource"]) == key:
            return entry, None
    loose = (resource["group"], resource["resource"])
    if any((e["group"], e["resource"]) == loose for e in kinds["effectKinds"]):
        return None, "EFFECT_KIND"
    sealed = [e for e in kinds["notWritable"] if (e["group"], e["resource"]) == loose]
    if sealed:
        # W02f: admission policies and bindings live only in the sealed static manifest directory, and the
        # static guard denies every API write of them; the writer never asks for one.
        return None, "ADMISSION_OBJECT_SEALED" if sealed[0]["disposition"] == "SEALED_STATIC_MANIFEST" else "POLICY_KIND_NOT_WRITABLE"
    return None, "KIND_OUTSIDE_TABLE"


def _string_map(value: Any) -> bool:
    return type(value) is dict and all(type(v) is str for v in value.values())


def check_write(kinds: dict, namespace: str, p: dict) -> str | None:
    """None when the WRITE_OBJECT request is inside the closed table, otherwise the refusal reason.
    The gate never forwards an effect kind, a policy kind outside the writer's closure or any other kind."""
    entry, reason = classify_resource(kinds, p["resource"])
    if entry is None:
        return reason
    op = p["operation"]
    if op not in entry["operations"]:
        return "VERB_NOT_ALLOWED"
    scope = entry["scope"]
    if scope == "QUALIFICATION_NAMESPACE":
        in_scope = p["namespace"] == namespace
    else:                                 # QUALIFICATION_NAMESPACE_OBJECT, the only other scope
        in_scope = p["namespace"] is None and p["name"] == namespace
    if not in_scope:
        return "SCOPE_MISMATCH"
    if (op == "CREATE") != (p["prior"] is None):
        return "PRIOR_RULE"               # CREATE expects absence; UPDATE and DELETE name the exact prior object
    if (op == "DELETE") != (p["object"] is None):
        return "OBJECT_RULE"
    if op == "DELETE":
        return None
    obj = p["object"]
    meta = obj.get("metadata")
    allowed = {"apiVersion", "kind", "metadata"} | set(entry["topLevelKeys"])
    if not (set(obj) <= allowed and obj.get("apiVersion") == api_version(entry) and obj.get("kind") == entry["kind"]
            and type(meta) is dict and set(meta) <= set(METADATA_KEYS) and meta.get("name") == p["name"]):
        return "OBJECT_RULE"
    if scope == "QUALIFICATION_NAMESPACE":
        if meta.get("namespace") != namespace:
            return "OBJECT_RULE"
    elif "namespace" in meta:
        return "OBJECT_RULE"
    if any(key in meta and not _string_map(meta[key]) for key in ("labels", "annotations")):
        return "OBJECT_RULE"
    if op == "CREATE":
        if "uid" in meta or "resourceVersion" in meta:
            return "OBJECT_RULE"
    elif (meta.get("uid"), meta.get("resourceVersion")) != (p["prior"]["uid"], p["prior"]["resourceVersion"]):
        return "OBJECT_RULE"              # an UPDATE carries the prior object's uid and resourceVersion itself
    return None


def render_write(entry: dict, p: dict, namespace: str, authority: str) -> dict:
    """The exact Kubernetes request one write permits: head bytes and body digest. The gate forwards these
    bytes with the writer identity. CREATE posts the object (the apiserver refuses an existing name), UPDATE
    puts the object with its uid and resourceVersion, DELETE carries only uid and resourceVersion
    preconditions; a stale prior object is refused by the apiserver itself (409)."""
    base = "/api/" + entry["version"] if not entry["group"] else "/apis/%s/%s" % (entry["group"], entry["version"])
    if entry["scope"] == "QUALIFICATION_NAMESPACE":
        collection = "%s/namespaces/%s/%s" % (base, namespace, entry["resource"])
    else:                                 # QUALIFICATION_NAMESPACE_OBJECT: the cluster-scoped namespaces collection
        collection = "%s/%s" % (base, entry["resource"])
    op = p["operation"]
    if op == "CREATE":
        method, target, body = "POST", collection, canonical(p["object"])
    elif op == "UPDATE":
        method, target, body = "PUT", collection + "/" + p["name"], canonical(p["object"])
    else:
        method, target = "DELETE", collection + "/" + p["name"]
        body = canonical({"apiVersion": "v1", "kind": "DeleteOptions",
                          "preconditions": {"resourceVersion": p["prior"]["resourceVersion"], "uid": p["prior"]["uid"]}})
    head = ("%s %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\n\r\n" % (method, target, authority, len(body)))
    return {"head": head, "bodyDigest": sha(body)}


def request_digest(request: dict) -> str:
    """The write's request digest: SHA-256 of the canonical JSON object {"bodyDigest": ..., "head": ...} of the
    rendered request (`render_write`)."""
    return sha(canonical({"head": request["head"], "bodyDigest": request["bodyDigest"]}))


def write_outcome_is_final(op: str, status: int) -> bool:
    """Whether a delivered response settles a write: its success statuses or a rejection (4xx other than
    408, such as 409 for an existing name or a stale precondition). Any other status (5xx, 408, 1xx, 3xx,
    another 2xx) leaves the outcome unknown, so the write is IO_AMBIGUOUS."""
    return status in SUCCESS_STATUSES[op] or (400 <= status <= 499 and status != 408)


# ---------------------------------------------------------------- gate model

class PolicyGate(i05.Gate):
    """The I05 v3 gate with its I07 channel: one writer session at a time and one maintenance per
    generation, owned by the session that began it; never in a generation rebuilt after a restart."""

    def __init__(self, config: dict, kinds: dict):
        super().__init__(config)
        writer = config["policyWriter"]
        self.kinds = kinds
        self.namespace = writer["qualificationNamespace"]
        self.authority = writer["apiserverAuthority"]
        self.maintenance = "NONE"
        self.maintenance_reason = None
        self.session: dict | None = None
        self.writes: dict[int, dict] = {}
        self.pending: dict | None = None        # the forwarded write whose upstream outcome is outstanding
        self.write_counters = {"sessions": 0, "writesForwarded": 0, "writesRefused": 0}

    # -- the A3 fence for I07 is the I05 v3 gate's own fence (Gate.fence), evaluated after every event
    def _settle_maintenance(self) -> None:
        if self.maintenance == "PENDING" and self.fence() == "OPEN":
            if self._record("MAINT_OPEN", self.state):
                self.maintenance = "OPEN"
        if self.maintenance in ("PENDING", "OPEN") and self.fence() == "HELD":
            # OPEN is a point-in-time answer: a later HELD (RECONCILIATION_REQUIRED, a fatal channel loss,
            # a storage failure, an ambiguous write) holds the maintenance, and no further write is forwarded.
            self.maintenance = "HELD"
            self._record("MAINT_HELD", self.state)

    def _ambiguous_writes(self) -> list[int]:
        return [w for w, r in sorted(self.writes.items()) if r["classification"] == "IO_AMBIGUOUS"]

    def _end_maintenance(self, reason: str) -> None:
        self.maintenance, self.maintenance_reason = "ENDED", reason
        self._record("MAINT_ENDED", reason, len(self.writes), self._ambiguous_writes())

    def _abort_pending(self, reason: str) -> None:
        """An outstanding write whose session or gate cannot wait for its outcome: the gate aborts the upstream
        exchange and records the write IO_AMBIGUOUS (the generation is HELD) before anything that ends the
        session or the maintenance, so MAINT_ENDED and a later status never miss it."""
        if self.pending is None:
            return
        write_id = self.pending["writeId"]
        self.pending = None
        self._record("WRITE_TERMINAL", write_id, "IO_AMBIGUOUS", {"aborted": reason})
        self.writes[write_id] = {"status": "TERMINAL", "classification": "IO_AMBIGUOUS"}
        self.state = "HELD"

    def _rebuild(self) -> str:
        """Restart: I05 actions, the failure marker and torn records as in I05 v3; every write forwarded without
        a terminal record is ambiguous and the gate restarts HELD. A rebuilt generation never opens a
        maintenance: one the restart interrupted never resumes, and none begins (W02c review R1)."""
        state = super()._rebuild()
        writes: dict[int, dict] = {}
        begun, ended = False, None
        for entry in self.journal:
            kind = entry[0]
            if kind == "WRITE_FORWARDED":
                writes[entry[1]] = {"status": "FORWARDED", "classification": None}
            elif kind == "WRITE_TERMINAL":
                writes[entry[1]] = {"status": "TERMINAL", "classification": entry[2]}
            elif kind == "MAINT_REQUESTED":
                begun = True
            elif kind == "MAINT_ENDED":
                ended = entry[1]
        for record in writes.values():
            if record["status"] == "FORWARDED":
                record.update(status="TERMINAL", classification="IO_AMBIGUOUS")
        self.writes = writes
        self.maintenance = "ENDED"
        self.maintenance_reason = (ended or "GATE_RESTART") if begun else "GENERATION_REBUILT"
        return "HELD" if self._ambiguous_writes() else state

    def snapshot(self) -> dict:
        view = super().snapshot()
        view.update(maintenance=self.maintenance, maintenanceReason=self.maintenance_reason,
                    writerSession=self.session["state"] if self.session else None,
                    pendingWriteId=self.pending["writeId"] if self.pending else None,
                    writes={str(k): dict(v) for k, v in sorted(self.writes.items())},
                    writeCounters=dict(self.write_counters))
        return view

    # -- events
    def handle(self, event: dict, schemas: dict) -> dict:
        kind = event["type"]
        if kind.startswith("W_"):
            out = self._writer_event(event, schemas["i07"])
            answer = self._settle_drain()          # a writer event can hold the generation while a drain is pending
            if answer is not None:
                out = dict(out, drain=answer)
        else:                                     # I05 events, including the base STORAGE_FAIL_AFTER injection
            if kind == "GATE_RESTART":
                self.pending = None        # the restart aborts the exchange; the rebuild classifies the write
            out = super().handle(event, schemas["i05"])
            if kind == "GATE_RESTART":
                self.session = None        # deny-first: no writer session survives a restart
                out["maintenance"] = self.maintenance
        self._settle_maintenance()
        return out

    def _writer_event(self, event: dict, schema: dict) -> dict:
        kind = event["type"]
        if kind == "W_CONNECT":
            if self.session is not None:
                return {"refusedSession": "SESSION_EXISTS"}
            self.session = {"state": "UNOPENED", "challenge": None, "next": 1, "last": ZERO_DIGEST, "owner": False}
            self.write_counters["sessions"] += 1
            return {"session": "CONNECTED"}
        if kind == "W_UPSTREAM":
            return self._w_upstream(event, schema)
        if self.session is None:
            require(kind in ("W_CHANNEL_LOST", "W_PEER_CHANGED"), "writer frame without a session")
            return {}
        if kind == "W_FRAME":
            return self._w_frame(event, schema)
        if kind == "W_CHANNEL_LOST":
            self._abort_pending("WRITER_CHANNEL_LOST")
            return self._end_session("ENDED")
        require(kind == "W_PEER_CHANGED", "unknown writer event")
        # Something other than the qualified writer holds the session: an enforcement breach.
        self._abort_pending("WRITER_PEER_DEVIATION")
        self._urgent("HELD", "WRITER_PEER_DEVIATION")
        self.state = "HELD"
        out = self._end_session("FATAL")
        out["fatal"] = "PEER_CHANGED"
        return out

    def _end_session(self, how: str) -> dict:
        owner = self.session["owner"]
        self.session = None
        self._record("WRITER_SESSION_ENDED", how)
        if owner and self.maintenance != "ENDED":
            self._end_maintenance("SESSION_" + how)
        return {"sessionEnd": how, "maintenance": self.maintenance}

    def _w_fatal(self, reason: str) -> dict:
        self._abort_pending("WRITER_PROTOCOL_FAILURE")
        out = self._end_session("FATAL")
        out["fatal"] = reason
        return out

    def _respond(self, frame: dict, payload: dict, schema: dict) -> dict:
        s = self.session
        response = {"schemaVersion": FRAME_VERSION, "challenge": s["challenge"], "sequence": frame["sequence"] + 1,
                    "previousDigest": frame_digest(frame), "direction": "GATE_TO_WRITER",
                    "operation": frame["operation"], "payload": payload}
        check_frame(response, schema)
        s["next"], s["last"] = frame["sequence"] + 2, frame_digest(response)
        return {"response": payload}

    def _w_frame(self, event: dict, schema: dict) -> dict:
        s, frame = self.session, event["frame"]
        if self.pending is not None:
            return self._w_fatal("LOCKSTEP")      # a writer frame while its WRITE_OBJECT awaits its response
        try:
            check_frame(frame, schema)
        except ValueError as exc:
            return self._w_fatal(str(exc).split(" ", 1)[0] + "_INVALID_FRAME")
        if frame["direction"] != "WRITER_TO_GATE" or frame["sequence"] % 2 != 1:
            return self._w_fatal("DIRECTION")
        if frame["sequence"] != s["next"] or frame["previousDigest"] != s["last"]:
            return self._w_fatal("CHAIN_BROKEN")
        if s["state"] == "UNOPENED":
            if frame["operation"] != "MAINTENANCE_STATUS":
                return self._w_fatal("OPENING_FRAME_REQUIRED")
            s["state"], s["challenge"] = "OPEN", frame["challenge"]
        elif frame["challenge"] != s["challenge"]:
            return self._w_fatal("CHALLENGE_MISMATCH")
        payload = getattr(self, "_w_op_" + frame["operation"].lower())(frame["payload"])
        if payload.get("forwarded"):
            self.pending["frame"] = frame         # the response follows the upstream outcome (W_UPSTREAM)
            return {"forwarded": self.pending["writeId"]}
        return self._respond(frame, payload, schema)

    def _w_upstream(self, event: dict, schema: dict) -> dict:
        """The upstream outcome of the outstanding write. Its terminal record is durable before the response;
        an outcome that arrives after the gate aborted the exchange is never relayed. TIMEOUT is the expiry of the
        gate's 10-second bound on a write's exchange: the gate aborts the exchange, records the write IO_AMBIGUOUS
        {aborted: UPSTREAM_TIMEOUT}, holds the generation and answers the writer IO_AMBIGUOUS (W02c-F review W2)."""
        if self.pending is None or self.pending["writeId"] != event["writeId"]:
            require(event["writeId"] in self.writes, "upstream event without a forwarded write")
            self._record("WRITE_LATE_UPSTREAM", event["writeId"])
            return {"lateUpstream": "NOT_RELAYED"}
        pending, self.pending = self.pending, None
        upstream, op, write_id = event["upstream"], pending["operation"], pending["writeId"]
        reconciliation, details = {}, {}
        if upstream == "LOST":
            classification = "IO_AMBIGUOUS"
        elif upstream == "TIMEOUT":
            classification, reconciliation = "IO_AMBIGUOUS", {"aborted": "UPSTREAM_TIMEOUT"}
        elif not write_outcome_is_final(op, upstream["httpStatus"]):
            classification = "IO_AMBIGUOUS"
            reconciliation = {"httpStatus": upstream["httpStatus"], "resultDigest": upstream["bodyDigest"]}
        else:
            classification = "DELIVERED_RESULT"
            success = upstream["httpStatus"] in SUCCESS_STATUSES[op]
            # Object metadata is observed only from a success response; a rejection's Status body has none.
            details = {"httpStatus": upstream["httpStatus"], "resultDigest": upstream["bodyDigest"],
                       "observedUid": upstream["uid"] if success else None,
                       "observedResourceVersion": upstream["resourceVersion"] if success else None}
        if not self._record("WRITE_TERMINAL", write_id, classification, details or reconciliation):
            classification, details = "IO_AMBIGUOUS", {}
        self.writes[write_id] = {"status": "TERMINAL", "classification": classification}
        if classification == "IO_AMBIGUOUS":
            self.state = "HELD"         # an unknown write outcome holds the generation, as an ambiguous action does
        delivered = classification == "DELIVERED_RESULT"
        payload = {"result": "OK", "writeId": write_id, "classification": classification,
                   "requestDigest": pending["requestDigest"],
                   "httpStatus": details.get("httpStatus") if delivered else None,
                   "resultDigest": details.get("resultDigest") if delivered else None,
                   "observedUid": details.get("observedUid") if delivered else None,
                   "observedResourceVersion": details.get("observedResourceVersion") if delivered else None}
        if self.session is None:
            return {"classification": classification, "relayed": False}
        out = self._respond(pending["frame"], payload, schema)
        return dict(out, classification=classification, relayed=True)

    def _refused(self, reason: str) -> dict:
        return {"result": "REFUSED", "reason": reason}

    def _w_op_maintenance_status(self, p: dict) -> dict:
        in_flight = self._in_flight()
        return {"result": "OK", "generation": self.generation, "gateState": self.state, "maintenance": self.maintenance,
                "inFlightActionId": in_flight["actionId"] if in_flight else None, "writes": len(self.writes),
                "ambiguousWriteIds": self._ambiguous_writes(), "journalDigest": sha(canonical(self.journal))}

    def _w_op_write_begin(self, p: dict) -> dict:
        if p["expectedGeneration"] != self.generation:
            return self._refused("GENERATION_MISMATCH")
        if self.maintenance == "ENDED":
            return self._refused("MAINTENANCE_ENDED")
        denied: list[int] = []
        if self.maintenance == "NONE":
            armed = self._armed_ids()
            if not self._record("MAINT_REQUESTED", self.generation):
                return self._refused("STORAGE_FAILURE")
            self.session["owner"], self.maintenance = True, "PENDING"
            self._drain()                               # the I05 v3 drain; maintenance follows the fence
            denied = self._denied_since(armed)          # every action this request denied, by any path
        # A repeated WRITE_BEGIN in the owning session reports the maintenance state (polling).
        self._settle_maintenance()
        return {"result": "OK", "maintenance": self.maintenance, "gateState": self.state, "deniedActionIds": denied}

    def _w_op_write_object(self, p: dict) -> dict:
        if self.maintenance != "OPEN":
            self.write_counters["writesRefused"] += 1
            return self._refused("MAINTENANCE_HELD" if self.maintenance == "HELD" else "MAINTENANCE_NOT_OPEN")
        if p["writeId"] != len(self.writes) + 1:
            self.write_counters["writesRefused"] += 1
            return self._refused("WRITE_ID_OUT_OF_ORDER")
        reason = check_write(self.kinds, self.namespace, p)
        if reason is not None:
            self.write_counters["writesRefused"] += 1
            return self._refused(reason)
        entry, _ = classify_resource(self.kinds, p["resource"])
        digest = request_digest(render_write(entry, p, self.namespace, self.authority))
        # Durable before the first upstream byte, like A1's consumption record.
        if not self._record("WRITE_FORWARDED", p["writeId"], p["operation"], api_version(entry), entry["kind"],
                            p["namespace"], p["name"], digest, p["prior"]):
            return self._refused("STORAGE_FAILURE")
        self.writes[p["writeId"]] = {"status": "FORWARDED", "classification": None}
        self.write_counters["writesForwarded"] += 1
        self.pending = {"writeId": p["writeId"], "operation": p["operation"], "requestDigest": digest}
        return {"forwarded": True}

    def _w_op_write_end(self, p: dict) -> dict:
        if self.maintenance == "NONE":
            return self._refused("MAINTENANCE_NOT_BEGUN")
        if self.maintenance == "ENDED":
            return self._refused("MAINTENANCE_ENDED")
        if not self._record("MAINT_ENDED", "WRITE_END", len(self.writes), self._ambiguous_writes()):
            return self._refused("STORAGE_FAILURE")
        self.maintenance, self.maintenance_reason = "ENDED", "WRITE_END"
        # The generation never returns to ACTIVE: a new one needs fresh observation.
        return {"result": "OK", "maintenance": "ENDED", "gateState": self.state, "writes": len(self.writes),
                "ambiguousWriteIds": self._ambiguous_writes()}


def replay(config: dict, events: list, schemas: dict, kinds: dict) -> tuple[list, dict]:
    """Replay one transcript of I05 and I07 events. FRAME events build the next valid I05 broker frame and
    W_FRAME events the next valid writer frame of the open session (with the W_CONNECT event's challenge);
    then the event's mutations apply, so invalid frames are exact deviations from a valid one."""
    gate = PolicyGate(copy.deepcopy(config), copy.deepcopy(kinds))
    outputs, challenge = [], None
    for event in events:
        event = copy.deepcopy(event)
        if event["type"] == "FRAME":
            frame = {"schemaVersion": i05.FRAME_VERSION, "generation": config["generation"],
                     "challenge": config["brokerChallenge"], "sequence": gate.next_sequence,
                     "previousDigest": gate.last_digest, "direction": "BROKER_TO_GATE",
                     "operation": event["operation"], "payload": event["payload"]}
            event = {"type": "FRAME", "frame": i05._apply(frame, event.get("mutate", []))}
        elif event["type"] == "W_CONNECT":
            challenge = event["challenge"]
        elif event["type"] == "W_FRAME":
            session = gate.session or {"next": 1, "last": ZERO_DIGEST}
            frame = {"schemaVersion": FRAME_VERSION, "challenge": challenge, "sequence": session["next"],
                     "previousDigest": session["last"], "direction": "WRITER_TO_GATE",
                     "operation": event["operation"], "payload": event["payload"]}
            event = {**event, "frame": i05._apply(frame, event.get("mutate", []))}
        outputs.append(gate.handle(event, schemas))
    return outputs, gate.snapshot()
