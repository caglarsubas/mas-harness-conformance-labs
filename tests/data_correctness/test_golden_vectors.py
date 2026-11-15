"""CONF-DATA-001: the 13 golden vectors are byte-identical to the pinned record's and R12's judge returns each one's
expect; the judge refuses malformed traces by shape and keeps its families' order and codes."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

import _judge

HERE = Path(__file__).resolve().parent
CONTRACTS = json.loads((HERE / "contracts.json").read_text(encoding="ascii"))
VECTOR_DIR = "architecture/data-correctness/vectors/"
PINS = {f["path"][len(VECTOR_DIR):]: f for f in CONTRACTS["files"] if f["path"].startswith(VECTOR_DIR)}
PER_FAMILY = {"RF-1": 1, "RF-2": 1, "RF-3": 1, "RF-4": 6, "RF-5": 2, "RF-6": 1, "RF-7": 1}


def _vector(name):
    return json.loads((HERE / "golden" / name).read_bytes())


class GoldenVectorTests(unittest.TestCase):
    def test_the_golden_folder_holds_exactly_the_13_pinned_vectors_byte_identical(self):
        names = sorted(p.name for p in (HERE / "golden").iterdir())
        self.assertEqual(names, sorted(PINS))
        self.assertEqual(len(names), 13)
        for name in names:
            raw = (HERE / "golden" / name).read_bytes()
            self.assertEqual((hashlib.sha256(raw).hexdigest(), len(raw)), (PINS[name]["sha256"], PINS[name]["size"]), name)

    def test_the_pins_name_the_record_the_schema_and_the_model_at_one_commit(self):
        self.assertEqual(len(CONTRACTS["commit"]), 40)
        self.assertTrue(CONTRACTS["commit"].startswith("cf253506"))
        paths = [f["path"] for f in CONTRACTS["files"]]
        self.assertEqual(paths[:3], ["architecture/data-correctness/record.json", "architecture/data-correctness/schema.json",
                                     "scripts/data_correctness.py"])
        self.assertEqual({f["packet"] for f in CONTRACTS["files"]}, {"MET-007"})

    def test_the_judge_returns_every_golden_vectors_expect(self):
        families = {}
        for name in sorted(PINS):
            vector = _vector(name)
            with self.subTest(vector=vector["id"]):
                self.assertEqual(vector["id"], name[:-5])
                self.assertEqual(_judge.judge(vector), vector["expect"])
                self.assertEqual(_judge.parity(vector), "MODEL_OPS")
            families[vector["family"]] = families.get(vector["family"], 0) + 1
        self.assertEqual(families, PER_FAMILY)

    def test_a_golden_vector_with_its_expect_flipped_no_longer_agrees(self):
        for name in sorted(PINS):
            vector = _vector(name)
            got = _judge.judge(vector)
            vector["expect"] = "ACCEPT" if got != "ACCEPT" else {"refuse": _judge.CODE_OF[vector["family"]]}
            self.assertNotEqual(_judge.judge(vector), vector["expect"], name)

    def test_the_families_codes_and_order(self):
        self.assertEqual(_judge.FAMILIES, ("RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7"))
        self.assertEqual(_judge.CODES, ("DC_WRITE_SKEW", "DC_FENCE", "DC_CLOCK", "DC_OPID", "DC_VERSION", "DC_DERIVED",
                                        "DC_REPLAY_STATE"))

    def test_each_refusal_condition_alone(self):
        """One minimal trace per refusal condition, each breaking that condition only, with its passing twin."""
        def tr(family, steps, setup=None):
            return {"id": "x", "family": family, "setup": setup or {}, "steps": steps, "expect": "ACCEPT"}
        b, r, c = ({"op": "begin", "tx": "a"}, {"op": "begin", "tx": "b"}), "reserve", "commit"
        rf1 = {"units": 1, "guard": "NONE"}
        cases = [
            ("RF-1", tr("RF-1", [b[0], b[1], {"op": r, "tx": "a", "units": 1}, {"op": r, "tx": "b", "units": 1},
                                 {"op": c, "tx": "a"}, {"op": c, "tx": "b"}], rf1), True),
            ("RF-1", tr("RF-1", [b[0], {"op": r, "tx": "a", "units": 1}, {"op": c, "tx": "a"}, b[1], {"op": c, "tx": "b"}],
                        rf1), False),
            ("RF-1", tr("RF-1", [b[0], b[1], {"op": r, "tx": "a", "units": 1}, {"op": "effect", "tx": "a", "key": "k"},
                                 {"op": r, "tx": "b", "units": 1}, {"op": c, "tx": "b"}, {"op": c, "tx": "a"},
                                 {"op": "begin", "tx": "a2"}, {"op": "effect", "tx": "a2", "key": "k"}],
                        {"units": 5, "guard": "SERIALIZABLE"}), True),
            ("RF-1", tr("RF-1", [b[0], b[1], {"op": r, "tx": "a", "units": 1}, {"op": "effect", "tx": "a", "key": "k"},
                                 {"op": r, "tx": "b", "units": 1}, {"op": c, "tx": "b"}, {"op": c, "tx": "a"},
                                 {"op": "begin", "tx": "a"}, {"op": "effect", "tx": "a", "key": "k"}],
                        {"units": 5, "guard": "SERIALIZABLE"}), True),  # CD-P1-1: the retry reuses the aborted name
            ("RF-2", tr("RF-2", [{"op": "acquire", "holder": "a", "token": 3}, {"op": "acquire", "holder": "b", "token": 3}]), True),
            ("RF-2", tr("RF-2", [{"op": "acquire", "holder": "a", "token": 3}, {"op": "acquire", "holder": "b", "token": 4}]), False),
            ("RF-2", tr("RF-2", [{"op": "acquire", "holder": "a", "token": 3}, {"op": "expire", "holder": "a"},
                                 {"op": "write", "holder": "a", "token": 3, "accepted": True}]), True),
            ("RF-2", tr("RF-2", [{"op": "acquire", "holder": "a", "token": 3}, {"op": "acquire", "holder": "b", "token": 4},
                                 {"op": "write", "holder": "a", "token": 3, "accepted": True}]), True),
            ("RF-2", tr("RF-2", [{"op": "acquire", "holder": "a", "token": 3}, {"op": "expire", "holder": "a"},
                                 {"op": "write", "holder": "a", "token": 3, "accepted": False}]), False),
            ("RF-3", tr("RF-3", [{"op": "lease_start", "monotonicMs": 0, "leaseMs": 10},
                                 {"op": "lease_check", "monotonicMs": 11, "held": True}]), True),
            ("RF-3", tr("RF-3", [{"op": "lease_start", "monotonicMs": 0, "leaseMs": 10},
                                 {"op": "lease_check", "monotonicMs": 10, "held": True}]), False),
            ("RF-3", tr("RF-3", [{"op": "wall_compare"}]), True),
            ("RF-3", tr("RF-3", [{"op": "wall_compare", "skewMarginMs": 0}]), False),
            ("RF-3", tr("RF-3", [{"op": "order", "by": "wall"}]), True),
            ("RF-3", tr("RF-3", [{"op": "order", "by": "fencing_token"}]), False),
            ("RF-4", tr("RF-4", [{"op": "claim", "exactlyOnce": True}]), True),
            ("RF-4", tr("RF-4", [{"op": "claim", "exactlyOnce": False, "maxAttempts": 3}]), False),
            ("RF-4", tr("RF-4", [{"op": "call", "operation": "o", "edge": "e", "class": "NATIVE", "attempt": 1,
                                  "path": "exception", "dedup": False, "applied": True}]), True),
            ("RF-4", tr("RF-4", [{"op": "call", "operation": "o", "edge": "e", "class": "NONE", "attempt": 2,
                                  "applied": False}]), True),
            ("RF-4", tr("RF-4", [{"op": "call", "operation": "o", "edge": "e", "class": "RECEIPT_KEY", "attempt": 1,
                                  "key": "k1", "applied": False},
                                 {"op": "call", "operation": "o", "edge": "e", "class": "RECEIPT_KEY", "attempt": 2,
                                  "key": "k2", "applied": True}]), True),
            ("RF-4", tr("RF-4", [{"op": "call", "operation": "o", "edge": "e", "class": "NATIVE", "attempt": 1, "applied": True},
                                 {"op": "call", "operation": "o", "edge": "e", "class": "NATIVE", "attempt": 2, "applied": True}]), True),
            ("RF-4", tr("RF-4", [{"op": "call", "operation": "o", "edge": "e", "class": "NATIVE", "attempt": 1, "applied": True},
                                 {"op": "call", "operation": "o", "edge": "f", "class": "NATIVE", "attempt": 1, "applied": True}]), False),
            ("RF-5", tr("RF-5", [{"op": "read_record", "recordVersion": "N-1", "reader": "N", "rollout": True,
                                  "accepted": False}]), True),
            ("RF-5", tr("RF-5", [{"op": "read_record", "recordVersion": "N-1", "reader": "N", "rollout": False,
                                  "accepted": False}]), False),
            ("RF-5", tr("RF-5", [{"op": "store_envelope", "extensionKept": False}]), True),
            ("RF-5", tr("RF-5", [{"op": "migrate", "readerWriterPairs": True, "rollback": False}]), True),
            ("RF-5", tr("RF-5", [{"op": "migrate", "readerWriterPairs": False, "rollback": True}]), True),
            ("RF-5", tr("RF-5", [{"op": "public_input", "rejected": True}]), False),
            ("RF-6", tr("RF-6", [{"op": "delete", "id": "d", "propagatedTo": ["a"], "receipt": True}], {"derived": ["a", "b"]}), True),
            ("RF-6", tr("RF-6", [{"op": "delete", "id": "d", "propagatedTo": ["b", "a"], "receipt": False}], {"derived": ["a", "b"]}), True),
            ("RF-6", tr("RF-6", [{"op": "delete", "id": "d", "propagatedTo": ["b", "a"], "receipt": True}], {"derived": ["a", "b"]}), False),
            ("RF-6", tr("RF-6", [{"op": "rebuild_compare", "driftFound": True, "reported": False}]), True),
            ("RF-6", tr("RF-6", [{"op": "rebuild_compare", "driftFound": True, "reported": True}]), False),
            ("RF-6", tr("RF-6", [{"op": "restore", "reapplied": False}]), False),
            ("RF-7", tr("RF-7", [{"op": "replay", "inputs": ["log"], "consulted": ["log", "state"]}]), True),
            ("RF-7", tr("RF-7", [{"op": "replay", "inputs": ["log", "state"], "consulted": ["log"]}]), False),
        ]
        for i, (family, trace, refused) in enumerate(cases):
            with self.subTest(i=i, family=family):
                want = {"refuse": _judge.CODE_OF[family]} if refused else "ACCEPT"
                self.assertEqual(_judge.judge(trace), want)

    def test_malformed_traces_raise_value_error_not_a_code(self):
        good = _vector("rf2-paused-holder.json")
        bad = []
        for mutate in (lambda v: v.pop("expect"), lambda v: v.update(extra=1), lambda v: v.update(family="RF-8"),
                       lambda v: v.update(steps=[]), lambda v: v["steps"].append({"op": "replay"}),
                       lambda v: v["steps"].append({"op": "nope"}), lambda v: v.update(expect={"refuse": "DC_OTHER"}),
                       lambda v: v["steps"][0].pop("token"), lambda v: v["steps"][0].update(holder="")):
            vector = json.loads(json.dumps(good))
            mutate(vector)
            bad.append(vector)
        for vector in bad:
            with self.assertRaises(ValueError):
                _judge.judge(vector)

    def test_the_extension_ops_and_field_set_parity_and_are_judged(self):
        lease = {"id": "x", "family": "RF-3", "setup": {}, "expect": "ACCEPT",
                 "steps": [{"op": "lease_start", "monotonicMs": 0, "leaseMs": 100}, {"op": "host_replace"},
                           {"op": "lease_check", "monotonicMs": 150, "held": True}]}
        self.assertEqual(_judge.parity(lease), "R12_EXTENSION")
        self.assertEqual(_judge.judge(lease), {"refuse": "DC_CLOCK"})
        envelope = {"id": "x", "family": "RF-5", "setup": {}, "expect": "ACCEPT",
                    "steps": [{"op": "store_envelope", "extensionKept": True, "extensionActedOn": True}]}
        self.assertEqual(_judge.parity(envelope), "R12_EXTENSION")
        self.assertEqual(_judge.judge(envelope), {"refuse": "DC_VERSION"})
        envelope["steps"][0]["extensionActedOn"] = False
        self.assertEqual(_judge.judge(envelope), "ACCEPT")
        restore = {"id": "x", "family": "RF-6", "setup": {"derived": ["index"]}, "expect": "ACCEPT",
                   "steps": [{"op": "delete", "id": "d", "propagatedTo": ["index"], "receipt": True},
                             {"op": "restore", "reapplied": False}]}
        self.assertEqual(_judge.parity(restore), "R12_EXTENSION")
        self.assertEqual(_judge.judge(restore), {"refuse": "DC_DERIVED"})
        restore["steps"][1]["reapplied"] = True
        self.assertEqual(_judge.judge(restore), "ACCEPT")


if __name__ == "__main__":
    unittest.main()
