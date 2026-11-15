"""CONF-DATA-001: runs every case of cases.json over its seeds and arms, judges every trace, and builds the results
ledger `r12.data-correctness-results/v1` and the CONF-A3-001 campaign record `r12.data-correctness-campaign-record/v1`,
once per process.

Per arm the ledger counts runs, errored runs, runs that broke the rule, business-outcome violations, runs where the
judge returned the trace's expect, violations without a broken rule, and the judge's refusals by code. It also keeps
the sha256 over the sorted per-seed trace digests, so each arm is a regenerable fixture. It holds counts and digests
only. It is serialized with sorted keys, compact separators and ASCII, plus a trailing newline.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import _judge
import _sim

HERE = Path(__file__).resolve().parent
RULE = ("Every case runs seeds 1 to 32 in every arm; each CONTROL or NEGATIVE arm differs from its case's DEFENDED arm "
        "in one switch, and all arms of a case share the seed's schedule. In every run the judge returns the trace's expect, and no business-"
        "outcome violation happens without a broken rule. DEFENDED: no errored run, no broken rule, no violation. "
        "CONTROL and NEGATIVE: no errored run, every refusal carries the case's code, and violations reach the arm's "
        "floor. Errored runs count in the denominator. The 13 golden vectors are judged to their expect.")
NOT_CLAIMED = [
    "No plane adapter is tested: every obligation cell is adapterState PENDING.",
    "No exactly-once delivery: applied once means at the effect's own store, under that store's deduplication.",
    "The simulation shows the rules are decidable and that the judge catches each one-switch break; it is not evidence "
    "about the product.",
    "The information-lifecycle table and the per-boundary compatibility matrix are not in the record yet.",
    "Not a gate: an input to CONF-A3-001's campaign record (HO-D2).",
]
FINDINGS = [
    {"id": "F-CD-1", "family": "RF-1", "text": "RF-1's reissue rule covers a retry after a serialization failure only: a "
     "process that dies between an effect issued inside its transaction and the commit neither commits nor aborts, so "
     "its restart's reissue is not RF-1's refusal. RF-4's operation IDs, deduplicated at the effect's store, cover it. "
     "WS-03 injects no crash for that reason; forwarded to R00 through the lane monitor."},
    {"id": "F-CD-2", "family": "RF-1", "text": "The reference model at the pinned commit forgets an abort when a retry "
     "reuses the aborted transaction's name, and then accepts the reissued effect; R12's judge remembers it (packet "
     "review CD-P1-1). Forwarded to R00 through the lane monitor with F-CD-1."},
]
EXTENSION_NOTE = ("R12-authored cases (VIS-C15-SPLIT conditions 1-4): never conformance to the merged record's 13 "
                  "vectors; their expected arms are R12's until the record's successor rules, and then the case "
                  "follows the record (HO-D2).")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def load_cases():
    return json.loads((HERE / "cases.json").read_text(encoding="ascii"))


def load_contracts():
    return json.loads((HERE / "contracts.json").read_text(encoding="ascii"))


def _arm(case, arm):
    counts = {"runs": 0, "errored": 0, "broken": 0, "violations": 0, "agreements": 0, "violationWithoutBreak": 0}
    refusals, digests, parities = {}, [], set()
    for seed in _sim.SEEDS:
        counts["runs"] += 1
        try:
            run = _sim.run(case["id"], arm["name"], seed)
            got = _judge.judge(run["trace"])
        except Exception:  # an errored run stays in the denominator and fails the gate
            counts["errored"] += 1
            continue
        parities.add(_judge.parity(run["trace"]))
        counts["broken"] += run["broken"]
        counts["violations"] += run["violation"]
        counts["agreements"] += got == run["trace"]["expect"]
        counts["violationWithoutBreak"] += run["violation"] and not run["broken"]
        if got != "ACCEPT":
            refusals[got["refuse"]] = refusals.get(got["refuse"], 0) + 1
        digests.append(_sha(_canon(run["trace"])))
    n = len(_sim.SEEDS)
    common = counts["errored"] == 0 and counts["agreements"] == n and counts["violationWithoutBreak"] == 0
    if arm["kind"] == "DEFENDED":
        gate = common and counts["broken"] == 0 and counts["violations"] == 0 and not refusals
    else:
        gate = common and set(refusals) <= {arm["code"]} and counts["violations"] >= arm["floor"]
    row = dict(arm, **counts)
    row.update(refusals=refusals, traceDigest=_sha("\n".join(sorted(digests))), gate=gate)
    return row, parities


def _golden(contracts):
    rows = []
    for f in contracts["files"]:
        if not f["path"].startswith("architecture/data-correctness/vectors/"):
            continue
        name = f["path"].rsplit("/", 1)[1]
        raw = (HERE / "golden" / name).read_bytes()
        vector = json.loads(raw)
        got = _judge.judge(vector)
        rows.append({"id": vector["id"], "family": vector["family"], "expect": vector["expect"], "judged": got,
                     "pinned": hashlib.sha256(raw).hexdigest() == f["sha256"], "agree": got == vector["expect"]})
    return rows


def build():
    cases, contracts = load_cases(), load_contracts()
    rows = []
    for case in cases["cases"]:
        arms, seen = [], set()
        for arm in case["arms"]:
            row, parities = _arm(case, arm)
            arms.append(row)
            seen |= parities
        parity = "R12_EXTENSION" if "R12_EXTENSION" in seen else "MODEL_OPS"
        ok = all(a["gate"] for a in arms) and parity == case["parity"]
        rows.append({"id": case["id"], "family": case["family"], "parity": parity, "provisional": case["provisional"],
                     "expectedArmsBy": case["expectedArmsBy"], "crashPoints": case["crashPoints"], "arms": arms,
                     "result": "PASS" if ok else "FAIL"})
    golden = _golden(contracts)
    summary = {"cases": len(rows), "casesPassed": sum(r["result"] == "PASS" for r in rows),
               "arms": sum(len(r["arms"]) for r in rows), "runs": sum(a["runs"] for r in rows for a in r["arms"]),
               "golden": len(golden), "goldenAgreed": sum(g["agree"] and g["pinned"] for g in golden),
               "r12Extensions": [r["id"] for r in rows if r["parity"] == "R12_EXTENSION"]}
    return {"schemaVersion": "r12.data-correctness-results/v1", "packet": "CONF-DATA-001",
            "contractsCommit": contracts["commit"], "seeds": cases["seeds"], "rule": RULE, "golden": golden,
            "cases": rows, "summary": summary}


def campaign_record(ledger):
    return {"schemaVersion": "r12.data-correctness-campaign-record/v1", "campaign": "CONF-DATA-001",
            "consumer": "CONF-A3-001", "role": "an input to the campaign record, not a gate (HO-D2)",
            "contract": {"item": "DATA-CORRECTNESS-001", "packet": "MET-007", "commit": ledger["contractsCommit"]},
            "golden": {"vectors": ledger["summary"]["golden"], "agreed": ledger["summary"]["goldenAgreed"]},
            "cases": [{"id": r["id"], "family": r["family"], "parity": r["parity"], "result": r["result"],
                       "authoredBy": "R12" if r["parity"] == "R12_EXTENSION" else "RECORD_RULES",
                       "provisional": r["provisional"], "expectedArmsBy": r["expectedArmsBy"],
                       "crashPoints": r["crashPoints"]} for r in ledger["cases"]],
            "r12Extensions": {"cases": ledger["summary"]["r12Extensions"], "note": EXTENSION_NOTE},
            "residuals": {"DD-04": _sim.RESIDUALS},
            "findings": FINDINGS, "notClaimed": NOT_CLAIMED}


def serialize(obj):
    return (_canon(obj) + "\n").encode("ascii")


_CACHE = {}


def ledger():
    if "ledger" not in _CACHE:
        _CACHE["ledger"] = build()
    return _CACHE["ledger"]


if __name__ == "__main__":
    led = build()
    (HERE / "results.json").write_bytes(serialize(led))
    (HERE / "campaign-record.json").write_bytes(serialize(campaign_record(led)))
    print(json.dumps(led["summary"], sort_keys=True))
