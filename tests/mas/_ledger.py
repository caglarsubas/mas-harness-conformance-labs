"""CONF-MAS-001 to CONF-MAS-003: runs every class over its seeds (defended, controls and defence-in-depth checks),
computes the per-run counts, the nearest-rank quantiles and the gates, and builds the ledger
`r12.mas-simulation-results/v3` once per process. Packet 1's four and packet 2's three class rows are byte-identical to
CONF-MAS-002's. CONF-MAS-003 adds C8 to C10, the MAS1-CARRY-1 arms (top-level `arms`, ungated) and the CONF-A3-001
campaign record `r12.mas-campaign-record/v1` (built from the ledger, packet 1's event-scoped readings and constants).

The ledger holds counts and quantiles only, never canary values. It is serialized with sorted keys, compact separators
and ASCII, plus a trailing newline.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import _classes
import _sim

HERE = Path(__file__).resolve().parent
CLASSES_PATH = HERE / "classes.json"
CONTRACTS_COMMIT = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"
PROFILE = "python-conformance-stdlib (Python 3.12, standard library only)"
RULE = ("Every class runs seeds 1 to 32 defended, plus one run per control and per defence-in-depth check. Defended: "
        "every own counter and every zero-tolerance counter is 0 and every scheduled event is delivered, reaches its "
        "component and engages it, in every seed; the ratio bounds hold over the 32 seeds (nearest rank, "
        "k = (p x 32 + 99) // 100). A control fires its own counter through its event in all 32 seeds (Q-MAS1-REV2). "
        "A defence-in-depth check keeps the class's violation counters at 0 with its remaining defence engaged, in "
        "every seed. A class is PASS only when every gate holds. A PASS does not satisfy topology-coordination's "
        "'denied until MAS-RA-010 passes' (Q-M4-10 (a)). A multi-event control fires its own counter through its "
        "countEvent, with every bypassed check on a row tagged with one of its events. C5's measurements (the runs of "
        "its OBJECTIVE-OFF control) are reported and not gated: a PASS or FAIL there neither lifts nor upholds the "
        "denial. CONF-MAS-003: a depth check that names an event counts engagement only over rows tagged with that "
        "event; C8's and C9's measurements and the MAS1-CARRY-1 arms (top-level arms) are reported and not gated, and "
        "packet 1's baseline policy stays the gated one.")
RATIOS = ("duplicatedWorkRatioPpm", "lostWorkPpm", "completionPpm")

_CACHE: dict = {}
# Packet 1's depth checks read event-scoped (CONF-MAS-003, section 4): a reading for the campaign record, kept out of
# their rows.
PACKET1_EVENT_READINGS = {"C2-GATE-OFF": "E1", "C2-VERIFIER-OFF": "E1", "C3-DEDUPE-OFF": "E3", "C3-RETRY-OFF": "E4"}
EVENT_SCOPED_READINGS: dict[str, dict] = {}


def load_config() -> tuple[dict, str]:
    raw = CLASSES_PATH.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def run(config: dict, cls: dict, seed: int, bypass: tuple[str, ...] = (), arm: str | None = None,
        until_deadline: bool = False) -> tuple[list[dict], dict]:
    sim = _sim.Sim(config, cls, seed, tuple(bypass), _classes.scenario_for(cls), arm=arm, until_deadline=until_deadline)
    rows = sim.run()
    return rows, _classes.measure(rows, config, cls)


def quantile(values: list[int], percent: int) -> int:
    """Nearest rank: the k-th smallest, k = (p x n + 99) // 100."""
    ordered = sorted(values)
    k = (percent * len(ordered) + 99) // 100
    return ordered[k - 1]


def stats(values: list[int]) -> dict:
    return {"p50": quantile(values, 50), "p95": quantile(values, 95), "max": max(values), "min": min(values)}


def ratio_gate(bounds: dict, name: str, s: dict) -> bool:
    b = bounds[name]
    if b["direction"] == "LOWER_IS_BETTER":
        return s["p50"] <= b["p50"] and s["p95"] <= b["p95"] and s["max"] <= b["max"]
    return s["p50"] >= b["p50"] and s["p95"] >= b["p95"] and s["min"] >= b["min"]


def class_row(config: dict, cls: dict) -> dict:
    seeds = config["seeds"]
    own = sorted({c["counter"] for c in cls["controls"]} | {n for d in cls["depthChecks"] for n in d["counters"]})
    zero = sorted(set(config["zeroTolerance"]))
    violations = sorted(set(own) | set(zero))
    defended, events = [], {e["id"]: {"delivered": 0, "reached": 0, "engaged": 0} for e in cls["events"]}
    defended_failures = []
    engaged_total: dict[str, int] = {}
    spec = cls.get("measurements")
    c5spec = spec if spec is not None and "control" in spec else None
    readings: list[dict] = []
    for seed in seeds:
        rows, measured = run(config, cls, seed)
        defended.append(measured)
        if spec is not None and spec.get("kind") == "DEFENDED_READINGS":
            readings.append(_classes.c8_readings(rows, cls))
        elif spec is not None and spec.get("kind") == "RELAY_RUNS":
            readings.append(_classes.work_readings(rows, cls, measured["counts"]))
        for key, n in measured["engaged"].items():
            engaged_total[key] = engaged_total.get(key, 0) + n
        for event in cls["events"]:
            path = _classes.event_path(rows, event)
            for key in ("delivered", "reached", "engaged"):
                events[event["id"]][key] += int(path[key])
            if not (path["delivered"] and path["reached"] and path["engaged"]):
                defended_failures.append({"seed": seed, "cause": "%s not delivered, reached and engaged" % event["id"]})
        for name in violations:
            if measured["counts"][name]:
                defended_failures.append({"seed": seed, "cause": "%s = %d" % (name, measured["counts"][name])})
    seeds_above = {name: sum(1 for m in defended if m["counts"][name] > 0) for name in violations}
    quantiles = {name: stats([m["counts"][name] for m in defended])
                 for name in RATIOS + ("duplicateWork", "lostItems", "expiries", "workEffects")}
    controls = []
    measured_runs: list[dict] = []
    for control in cls["controls"]:
        fired, failing = 0, []
        for seed in seeds:
            rows, measured = run(config, cls, seed, tuple(control["bypass"]))
            ok, cause = _classes.control_fired(measured, rows, control)
            if ok:
                fired += 1
            else:
                failing.append({"seed": seed, "cause": cause})
            if c5spec is not None and control["id"] == c5spec["control"]:
                reach = cls_event(cls, c5spec["reachEvent"])
                measured_runs.append({**{n: measured["counts"][n] for n in RATIOS},
                                      "hoarderPeakHeld": _classes.hoarder_peak(rows, c5spec["hoarder"]),
                                      "reached": _classes.event_path(rows, reach)["reached"]})
        entry = {"id": control["id"], "bypass": control["bypass"], "counter": control["counter"],
                 "firedSeeds": fired, "failing": failing}
        if "events" in control:
            entry.update(events=control["events"], countEvent=control["countEvent"])
        else:
            entry["event"] = control["event"]
        controls.append(entry)
    depth = []
    for check in cls["depthChecks"]:
        held, failing = 0, []
        reading_event = PACKET1_EVENT_READINGS.get(check["id"])
        reading_seeds = 0
        for seed in seeds:
            _rows, measured = run(config, cls, seed, tuple(check["bypass"]))
            bad = [n for n in violations if measured["counts"][n]]
            if "event" in check:
                # CONF-MAS-003: event-scoped engagement (section 4).
                engaged = measured["engagedByEvent"].get(check["event"], {}).get(check["engaged"], 0) > 0
            else:
                engaged = measured["engaged"].get(check["engaged"], 0) > 0
            if reading_event is not None and measured["engagedByEvent"].get(reading_event, {}).get(check["engaged"], 0):
                reading_seeds += 1
            if not bad and engaged:
                held += 1
            else:
                failing.append({"seed": seed, "cause": ("violations: %s" % ", ".join(bad)) if bad
                                else "%s not engaged" % check["engaged"]})
        entry = {"id": check["id"], "bypass": check["bypass"], "engaged": check["engaged"], "heldSeeds": held,
                 "failing": failing}
        if "event" in check:
            entry["event"] = check["event"]
        depth.append(entry)
        if reading_event is not None:
            # Packet 1's event-scoped reading: kept outside its row, for the campaign record (section 8).
            EVENT_SCOPED_READINGS[check["id"]] = {"check": check["id"], "event": reading_event,
                                                  "engagedSeeds": reading_seeds}
    must = config["controlGate"]["mustFireSeeds"]
    gates = {
        "defendedZeroAndEvents": not defended_failures,
        "ratioBounds": {name: ratio_gate(config["bounds"], name, quantiles[name]) for name in RATIOS},
        "controlsFireInAllSeeds": all(c["firedSeeds"] == must for c in controls),
        "depthChecksHoldInAllSeeds": all(d["heldSeeds"] == len(seeds) for d in depth),
    }
    passed = (gates["defendedZeroAndEvents"] and all(gates["ratioBounds"].values()) and gates["controlsFireInAllSeeds"]
              and gates["depthChecksHoldInAllSeeds"])
    parameters = {k: cls[k] for k in ("topology", "deadline", "maxLatency", "poisonPpm", "stallPpm", "compromised")}
    row = {"id": cls["id"], "kind": cls["kind"], "parameters": parameters,
           "defended": {"seeds": len(seeds), "quantiles": quantiles, "seedsAboveZero": seeds_above,
                        "eventsReached": events, "engaged": dict(sorted(engaged_total.items())),
                        "failing": defended_failures},
           "unexercisedInvariants": sorted(set(config["unexercisedInvariants"]) - set(cls.get("exercises", []))),
           "controls": controls, "depthChecks": depth, "gates": gates, "result": "PASS" if passed else "FAIL"}
    if c5spec is not None:
        # Reported, not gated (DESIGN revision 8, section 5): one preregistered adversary script, a lower bound on harm.
        row["measurements"] = {
            "control": c5spec["control"], "hoarder": c5spec["hoarder"], "seeds": len(measured_runs),
            "quantiles": {name: stats([m[name] for m in measured_runs]) for name in RATIOS + ("hoarderPeakHeld",)},
            "reachEvent": c5spec["reachEvent"], "reachedSeeds": sum(1 for m in measured_runs if m["reached"])}
    elif spec is not None and spec["kind"] == "DEFENDED_READINGS":
        # CONF-MAS-003 C8 (section 5): reported, not gated.
        row["measurements"] = {"kind": spec["kind"], "seeds": len(readings),
                               "quantiles": {n: stats([r[n] for r in readings]) for n in spec["readings"]}}
    elif spec is not None and spec["kind"] == "RELAY_RUNS":
        row["measurements"] = relay_measurements(config, cls, spec, readings)
    return row


def relay_measurements(config: dict, cls: dict, spec: dict, defended: list[dict]) -> dict:
    """CONF-MAS-003 C9 (sections 4 and 5): the relay runs use a copy of C9's entry with the measured event added as
    `relayEvent` (outside `events`) and run to the deadline; reported, not gated."""
    relay_cls = dict(cls, relayEvent=spec["event"])
    runs = []
    for seed in config["seeds"]:
        rows, measured = run(config, relay_cls, seed, until_deadline=bool(spec["untilDeadline"]))
        runs.append({**_classes.work_readings(rows, cls, measured["counts"]),
                     **_classes.relay_readings(rows, cls, spec["event"]["id"])})
    work = [n for n in spec["readings"] if n in defended[0]]
    return {"kind": spec["kind"], "seeds": len(runs), "event": spec["event"]["id"],
            "defended": {"quantiles": {n: stats([r[n] for r in defended]) for n in work}},
            "relay": {"quantiles": {n: stats([r[n] for r in runs]) for n in spec["readings"]}}}


def arms_section(config: dict) -> dict:
    """CONF-MAS-003 (section 6): the MAS1-CARRY-1 arms over the defended runs of their classes, ungated."""
    spec = config["arms"]
    by_id = {c["id"]: c for c in config["classes"]}
    results = []
    for policy in spec["policies"]:
        for cid in spec["classes"]:
            cls = by_id[cid]
            per_run, totals = [], {"workEffects": 0, "duplicateWork": 0, "revisionExhaustionReleases": 0,
                                   "a1ResentMerges": 0, "a3ReReads": 0}
            for seed in config["seeds"]:
                rows, measured = run(config, cls, seed, arm=policy["id"])
                counts = measured["counts"]
                per_run.append(counts)
                totals["workEffects"] += counts["workEffects"]
                totals["duplicateWork"] += counts["duplicateWork"]
                for key, value in sorted(_classes.arm_totals(rows, config).items()):
                    totals[key] += value
            quantiles = {n: stats([c[n] for c in per_run]) for n in RATIOS}
            results.append({"arm": policy["id"], "class": cid, "quantiles": quantiles, "totals": totals,
                            "wouldHoldBounds": {n: ratio_gate(config["bounds"], n, quantiles[n]) for n in RATIOS}})
    return {"classes": spec["classes"], "policies": spec["policies"], "results": results}


def cls_event(cls: dict, event_id: str) -> dict:
    return next(e for e in cls["events"] if e["id"] == event_id)


def build() -> dict:
    config, classes_sha = load_config()
    return {"schemaVersion": "r12.mas-simulation-results/v3", "packet": "CONF-MAS-003", "profile": PROFILE,
            "seeds": config["seeds"], "classesSha256": classes_sha, "contractsCommit": CONTRACTS_COMMIT, "rule": RULE,
            "classes": [class_row(config, cls) for cls in config["classes"]], "arms": arms_section(config)}


def serialize(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def ledger() -> dict:
    """The ledger, built once per process and shared by the test modules."""
    if "ledger" not in _CACHE:
        _CACHE["ledger"] = build()
    return _CACHE["ledger"]


# ------------------------------------------------------------------------- the CONF-A3-001 campaign record (section 8)
CAMPAIGN_PACKETS = (
    ("CONF-MAS-001", "05b74ff0e778f23faab1281731afa7f7b1fed85f",
     "4343535ab16cd0df4385ee1d8c24d622721e253e57a1a88c35a00e30efecd689"),
    ("CONF-MAS-002", "c672aad56960b33a3e6d281aa484c7ac507293aa",
     "d9871b7efe718b7e702d6200957de18cc5f519bddd50ad1745aa0dcccf76c7cd"))
CLASS_PACKET = {"C1": "CONF-MAS-001", "C2": "CONF-MAS-001", "C3": "CONF-MAS-001", "C4": "CONF-MAS-001",
                "C5": "CONF-MAS-002", "C6": "CONF-MAS-002", "C7": "CONF-MAS-002",
                "C8": "CONF-MAS-003", "C9": "CONF-MAS-003", "C10": "CONF-MAS-003"}
RECORDED_DECISIONS = {"C2": "Q-MAS1-F1", "C5": "Q3-2", "C7": "Q3-2", "C9": "Q-D3-1"}
FINDINGS = (
    ("MAS1-CARRY-1", "Packet 1's carried retry-policy effect: a holder's own RENEW can overtake its MERGE at latency 3, "
                     "so revisions run out and work is duplicated."),
    ("F-C5-1", "A colluding verifier defeats verify-before-merge, because independence is declared and not "
               "authenticated."),
    ("F-C5-2", "With the denial lifted, one hoarding agent could hold the whole board-wide cap; admission refuses only a "
               "declared conflicting objective."),
    ("F-C6-1", "Each exfiltration defence is a single layer; the restated contracts name no downstream secret scan."),
    ("F-C7-1", "A hoarder within the cap is not defended by any bound."),
    ("F-C8-1", "A crashed worker keeps being assigned items; the coordinator has no liveness signal beyond the lease."),
    ("F-C9-1", "No restated rule bounds a relay cycle along declared edges before the run deadline; measured, it costs "
               "bus deliveries only."),
    ("F-C9-2", "Each waiting holder keeps renewing, so a wait cycle resolves only by the wall-clock budget or the run "
               "deadline."),
    # MON-F-C9-3-RECORD (2026-10-20): a finding made at build time, after the first ledger; only this entry was added.
    ("F-C9-3", "Found at build: in seeds 1, 8, 16 and 27 a clean C9 claim also reaches the revision bound through "
               "MAS1-CARRY-1 (a holder's own RENEW overtakes its MERGE at latency 3), an extra cause of C9's "
               "preregistered duplicated-work FAIL beyond its events' six explained duplicates."),
    ("F-C10-1", "The merge defences are layered: the gate and the per-work history; the holder or single-merge check, "
                "the version check and the verdict check."))
NOT_CLAIMED = ("Not a gate: an input to CONF-A3-001 (HO-D2).",
               "Does not lift topology-coordination's denial until MAS-RA-010 passes.",
               "No product or contract decision (Q-NX2-4 (a)).")


def campaign_record() -> dict:
    """The closed record `r12.mas-campaign-record/v1`, built from the in-process ledger, packet 1's event-scoped
    readings and the constants above; counts, digests, ids and fixed text only."""
    value = ledger()
    results_sha = hashlib.sha256(serialize(value)).hexdigest()
    packets = [{"packetId": p, "commit": c, "resultsSha256": r} for p, c, r in CAMPAIGN_PACKETS]
    packets.append({"packetId": "CONF-MAS-003", "commit": None, "resultsSha256": results_sha})
    classes = [{"id": row["id"], "kind": row["kind"], "packet": CLASS_PACKET[row["id"]], "result": row["result"],
                "gates": row["gates"]} for row in value["classes"]]
    fails = [{"class": row["id"], "metric": name, "decision": RECORDED_DECISIONS.get(row["id"])}
             for row in value["classes"] for name, ok in sorted(row["gates"]["ratioBounds"].items()) if not ok]
    arms = [{"arm": r["arm"], "class": r["class"],
             "duplicatedWorkRatioPpm": {"p50": r["quantiles"]["duplicatedWorkRatioPpm"]["p50"],
                                        "p95": r["quantiles"]["duplicatedWorkRatioPpm"]["p95"]},
             "wouldHoldBounds": r["wouldHoldBounds"]} for r in value["arms"]["results"]]
    return {"schemaVersion": "r12.mas-campaign-record/v1", "campaign": "MAS-RA-010",
            "consumer": "CONF-A3-001 (input, HO-D2)", "packets": packets, "classes": classes, "recordedFails": fails,
            "findings": [{"id": i, "summary": text} for i, text in FINDINGS], "arms": arms,
            "eventScopedReadings": [EVENT_SCOPED_READINGS[k] for k in sorted(EVENT_SCOPED_READINGS)],
            "notClaimed": list(NOT_CLAIMED)}
