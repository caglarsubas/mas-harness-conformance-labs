"""CONF-MAS-001: runs every class over its seeds (defended, controls and defence-in-depth checks), computes the per-run
counts, the nearest-rank quantiles and the gates, and builds the ledger `r12.mas-simulation-results/v1` once per process.

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
CONTRACTS_COMMIT = "35b733b523f46b2ccba095ea046efe5d42bfa583"
PROFILE = "python-conformance-stdlib (Python 3.12, standard library only)"
RULE = ("Every class runs seeds 1 to 32 defended, plus one run per control and per defence-in-depth check. Defended: "
        "every own counter and every zero-tolerance counter is 0 and every scheduled event is delivered, reaches its "
        "component and engages it, in every seed; the ratio bounds hold over the 32 seeds (nearest rank, "
        "k = (p x 32 + 99) // 100). A control fires its own counter through its event in all 32 seeds (Q-MAS1-REV2). "
        "A defence-in-depth check keeps the class's violation counters at 0 with its remaining defence engaged, in "
        "every seed. A class is PASS only when every gate holds. A PASS does not satisfy topology-coordination's "
        "'denied until MAS-RA-010 passes' (Q-M4-10 (a)).")
RATIOS = ("duplicatedWorkRatioPpm", "lostWorkPpm", "completionPpm")

_CACHE: dict = {}


def load_config() -> tuple[dict, str]:
    raw = CLASSES_PATH.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def run(config: dict, cls: dict, seed: int, bypass: tuple[str, ...] = ()) -> tuple[list[dict], dict]:
    sim = _sim.Sim(config, cls, seed, tuple(bypass), _classes.scenario_for(cls))
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
    for seed in seeds:
        rows, measured = run(config, cls, seed)
        defended.append(measured)
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
    for control in cls["controls"]:
        fired, failing = 0, []
        for seed in seeds:
            rows, measured = run(config, cls, seed, tuple(control["bypass"]))
            ok, cause = _classes.control_fired(measured, rows, control)
            if ok:
                fired += 1
            else:
                failing.append({"seed": seed, "cause": cause})
        controls.append({"id": control["id"], "bypass": control["bypass"], "counter": control["counter"],
                         "event": control["event"], "firedSeeds": fired, "failing": failing})
    depth = []
    for check in cls["depthChecks"]:
        held, failing = 0, []
        for seed in seeds:
            _rows, measured = run(config, cls, seed, tuple(check["bypass"]))
            bad = [n for n in violations if measured["counts"][n]]
            engaged = measured["engaged"].get(check["engaged"], 0) > 0
            if not bad and engaged:
                held += 1
            else:
                failing.append({"seed": seed, "cause": ("violations: %s" % ", ".join(bad)) if bad
                                else "%s not engaged" % check["engaged"]})
        depth.append({"id": check["id"], "bypass": check["bypass"], "engaged": check["engaged"], "heldSeeds": held,
                      "failing": failing})
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
    return {"id": cls["id"], "kind": cls["kind"], "parameters": parameters,
            "defended": {"seeds": len(seeds), "quantiles": quantiles, "seedsAboveZero": seeds_above,
                         "eventsReached": events, "engaged": dict(sorted(engaged_total.items())),
                         "failing": defended_failures},
            "unexercisedInvariants": sorted(config["unexercisedInvariants"]),
            "controls": controls, "depthChecks": depth, "gates": gates, "result": "PASS" if passed else "FAIL"}


def build() -> dict:
    config, classes_sha = load_config()
    return {"schemaVersion": "r12.mas-simulation-results/v1", "packet": "CONF-MAS-001", "profile": PROFILE,
            "seeds": config["seeds"], "classesSha256": classes_sha, "contractsCommit": CONTRACTS_COMMIT, "rule": RULE,
            "classes": [class_row(config, cls) for cls in config["classes"]]}


def serialize(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def ledger() -> dict:
    """The ledger, built once per process and shared by the test modules."""
    if "ledger" not in _CACHE:
        _CACHE["ledger"] = build()
    return _CACHE["ledger"]
