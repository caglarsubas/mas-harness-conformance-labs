"""Non-author oracle tests for CONF-DATA-001 (owner decision D5a).

Black-box tests written outside the candidate, from the case design note (revision 1, with
the lane monitor's dispositions D1 to D4) and the data-correctness contract at harness-onion
commit cf253506. The candidate is reached only through its documented interface:
_judge.judge / check_shape / parity and its constants, _sim.SEEDS / RUNNERS / RESIDUALS / run,
and _ledger.build / ledger / campaign_record / serialize / load_cases / load_contracts.

Every figure taken from the contract is hard-coded below, with a comment naming its source;
this file reads nothing outside its own folder.
"""

import ast
import hashlib
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _judge  # noqa: E402
import _ledger  # noqa: E402
import _sim  # noqa: E402

# ---------------------------------------------------------------------------------------
# Figures from the contract (harness-onion cf253506, architecture/data-correctness/).
# ---------------------------------------------------------------------------------------

# Design D-01: harness-onion main cf253506; record.json blob 73c8b796.
COMMIT_PREFIX = "cf253506"
RECORD_PATH = "architecture/data-correctness/record.json"
# sha256 and size of record.json at cf253506 (computed from the contract's bytes; its git
# blob id begins 73c8b796, as design D-01 states).
RECORD_SHA256 = "7a3d2aa8785d18322606ea9d394606e6394412012fd00fbe03a4b4ed0c7d6370"
RECORD_SIZE = 52698
# record.json "schema": {"path": ..., "sha256": ...}
SCHEMA_PATH = "architecture/data-correctness/schema.json"
SCHEMA_SHA256 = "f0e5e0968b6f184154f557b756e6a69a565c888a264a3652f58d2e3387f2258d"
# Design D-01: reference model scripts/data_correctness.py (its bytes are not in the
# oracle's inputs, so only its pin's presence and form are checked).
MODEL_PATH = "scripts/data_correctness.py"
VECTOR_DIR = "architecture/data-correctness/vectors/"

# record.json ruleFamilies[].vectors, in record order: (file, family, size, sha256,
# git blob id, expect). Sizes, sha256 and blob ids computed from the contract's bytes;
# family from the listing family; expect from each vector's own "expect".
VECTORS = [
    ("rf1-concurrent-reservations.json", "RF-1", 524,
     "9fdb78ca49910e49b274b0240565a95571d28909663748e0a57577b8e81e9fcb",
     "83cc9cb8759f2ce21f9dacfce6e911450e22bfac", {"refuse": "DC_WRITE_SKEW"}),
    ("rf2-paused-holder.json", "RF-2", 563,
     "3bcd4f7f787b5008c6c869c5a64274a8c470f95f825b0188594c395a122d77f0",
     "9309de6e79da26c5cd17c4b097c174891425ac43", {"refuse": "DC_FENCE"}),
    ("rf3-skew-and-jump.json", "RF-3", 408,
     "4c88c67e45c3caa6883a0569fdaef2037ed8ac4cfa03cee42c85d2054ef86622",
     "229a0e92ea660ac1595d304714aa0a681f69dfa4", {"refuse": "DC_CLOCK"}),
    ("rf4-replay-per-class.json", "RF-4", 707,
     "00ae3a52bf1df74e20d82a9e08aabf1c14c48c9746ec37e67dae6adf435b6ea3",
     "65183ca889f628e7d8005027e16d35cd727bfc11", "ACCEPT"),
    ("rf4-retry-after-unknown.json", "RF-4", 527,
     "8a549031fca07a77d7419bd05559dd3305cf1aa477baff60cda261ef1c7e7598",
     "d20751e1e54dc5f4703856f881582587da7919ca", {"refuse": "DC_OPID"}),
    ("rf4-receipt-key-restart.json", "RF-4", 595,
     "f8c01547bc17e5c96d3270e61a50bd9d37a161168d75c4cfa9a95190a5a5d4ac",
     "17eeb7057beab8e7f790688b7df73e3b7705a162", "ACCEPT"),
    ("rf4-receipt-key-per-attempt.json", "RF-4", 563,
     "bb0f1a6ba23051b621095973adc98ab81a648402d6073c239a24f9067bcf8b5f",
     "a8ea64b0c48615259d34e07801846e1381263f60", {"refuse": "DC_OPID"}),
    ("neg-bounded-not-exactly-once.json", "RF-4", 222,
     "975e128a281f7a32fbf6cf0835f38074d6318e9e4c806bc052a970450fd17670",
     "5e6184a2eaa854c41c9c22a771afbb7002d828a2", {"refuse": "DC_OPID"}),
    ("neg-exception-path-dedup.json", "RF-4", 551,
     "92279bb7bfbb8742953d9180401bd1405040dd6d00c2903696b3cb88fa5bf6a1",
     "310fa30bb6da793dd3ba27c85cbad433ce1cf2d4", {"refuse": "DC_OPID"}),
    ("rf5-mixed-versions.json", "RF-5", 655,
     "9532d688d7111ebbee29ad2db392a44e08d509698f77bb32088837c497adb198",
     "e7bc8f533afef4a716a196723597b08339b3bb0c", "ACCEPT"),
    ("rf5-reader-drops-previous-version.json", "RF-5", 419,
     "71f15bc9ae5d946a1b9ede4ab3a4f73849011b570d64f349ce14e5dffea2927a",
     "c7ad9074328cb8a0c8c569bbf9d0538de199adbe", {"refuse": "DC_VERSION"}),
    ("rf6-deletion-through-derived.json", "RF-6", 386,
     "a1293ffdf8b47f8820c398e3e68ac355139bca55ded77b8f04d1eeef935b4c75",
     "ed371140ce7c34dc465316c40600c8d31bc122c1", {"refuse": "DC_DERIVED"}),
    ("rf7-log-only-replay-diverges.json", "RF-7", 293,
     "d6f638f9d6a403b21774456eac6e09a0288ee44ab0b31f9e461244306f680e81",
     "85ec960659567afb32fd0126f8f2c3575cf09d7f", {"refuse": "DC_REPLAY_STATE"}),
]
# record.json counts.vectorsByFamily (design D-03)
VECTORS_BY_FAMILY = {"RF-1": 1, "RF-2": 1, "RF-3": 1, "RF-4": 6, "RF-5": 2, "RF-6": 1, "RF-7": 1}

# record.json ruleFamilies[].id, and design D-05 (codes in run order).
FAMILIES = ["RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7"]
CODE_OF = {
    "RF-1": "DC_WRITE_SKEW", "RF-2": "DC_FENCE", "RF-3": "DC_CLOCK", "RF-4": "DC_OPID",
    "RF-5": "DC_VERSION", "RF-6": "DC_DERIVED", "RF-7": "DC_REPLAY_STATE",
}

# The brief's trace step vocabulary per family (host_replace and restore are the R12
# extension ops; extensionActedOn is the R12 extension field).
VOCAB = {
    "RF-1": {"begin", "reserve", "commit", "effect"},
    "RF-2": {"acquire", "expire", "write"},
    "RF-3": {"lease_start", "wall_jump", "lease_check", "wall_compare", "order", "host_replace"},
    "RF-4": {"call", "claim"},
    "RF-5": {"read_record", "store_envelope", "migrate", "public_input"},
    "RF-6": {"insert", "delete", "rebuild_compare", "restore"},
    "RF-7": {"replay"},
}
EXTENSION_OPS = {"host_replace", "restore"}
EXTENSION_FIELD = "extensionActedOn"

# record.json deployables[].id and deployables[].obligations, in record order (24
# deployables, 103 cells). The two digests below were computed from the record itself and
# guard this transcription.
OBLIGATIONS = [
    ("otel-collector", ["RF-1", "RF-3", "RF-5"]),
    ("operator", ["RF-1", "RF-2", "RF-3", "RF-5"]),
    ("fleet-sync-agent", ["RF-1", "RF-3", "RF-5"]),
    ("usage-ledger", ["RF-1", "RF-3", "RF-5", "RF-7"]),
    ("governance-service", ["RF-1", "RF-3", "RF-5"]),
    ("domain-service", ["RF-1", "RF-3", "RF-5"]),
    ("registry-service", ["RF-1", "RF-3", "RF-5"]),
    ("inference-api", ["RF-1", "RF-3", "RF-5"]),
    ("connector-controller", ["RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-7"]),
    ("memory-service", ["RF-1", "RF-3", "RF-5", "RF-6"]),
    ("control-web", ["RF-1", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7"]),
    ("ingest-worker", ["RF-1", "RF-2", "RF-3", "RF-5"]),
    ("retrieval-service", ["RF-1", "RF-3", "RF-5", "RF-6"]),
    ("protocol-gateway", ["RF-1", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7"]),
    ("evidence-service", ["RF-1", "RF-3", "RF-5"]),
    ("profile-compiler-worker", ["RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-7"]),
    ("index-worker", ["RF-1", "RF-3", "RF-5", "RF-6"]),
    ("orchestration-api", ["RF-1", "RF-3", "RF-4", "RF-5", "RF-7"]),
    ("decision-service", ["RF-1", "RF-3", "RF-5"]),
    ("assurance-worker", ["RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-7"]),
    ("tool-broker", ["RF-1", "RF-3", "RF-4", "RF-5"]),
    ("orchestration-worker", ["RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-7"]),
    ("ai-gateway", ["RF-1", "RF-3", "RF-4", "RF-5", "RF-7"]),
    ("experience-gateway", ["RF-1", "RF-3", "RF-4", "RF-5", "RF-7"]),
]
# sha256(json.dumps(sorted([deployable, family] pairs))) over record.json deployables
OBLIGATION_PAIRS_SHA256 = "243361da214a6c2327146fd9c1cbc439be1d8e5e88d68d2cbad7cbc2426ace7e"
# sha256(json.dumps([deployable ids in record order]))
DEPLOYABLE_IDS_SHA256 = "faafccc50aed556373744915779bcbf1c3835bd735d37f3ab096f66a2d47ee7b"
# record.json counts.obligationsByFamily (design D-07)
OBLIGATIONS_BY_FAMILY = {"RF-1": 24, "RF-2": 6, "RF-3": 24, "RF-4": 10, "RF-5": 24, "RF-6": 5, "RF-7": 10}

# ---------------------------------------------------------------------------------------
# Figures from the design note.
# ---------------------------------------------------------------------------------------

# Section 4's table: (case, family, parity, DEFENDED arms, CONTROL arms, NEGATIVE arms).
# WS-01 names four defended mechanisms and two controls; CV-01, CV-06 and DD-02 have no
# control ("none"); CV-04 and DD-01 name two controls each; RS-01 has neither a defended nor
# a control arm, its refusal being the expected outcome (one NEGATIVE arm).
CATALOGUE = [
    ("WS-01", "RF-1", "MODEL_OPS", 4, 2, 0),
    ("WS-02", "RF-1", "MODEL_OPS", 1, 1, 0),
    ("WS-03", "RF-1", "MODEL_OPS", 1, 1, 0),
    ("FN-01", "RF-2", "MODEL_OPS", 1, 1, 0),
    ("FN-02", "RF-2", "MODEL_OPS", 1, 1, 0),
    ("FN-03", "RF-2", "MODEL_OPS", 1, 1, 0),
    ("CK-01", "RF-3", "MODEL_OPS", 1, 1, 0),
    ("CK-02", "RF-3", "MODEL_OPS", 1, 1, 0),
    ("CK-03", "RF-3", "MODEL_OPS", 1, 1, 0),
    ("CK-04", "RF-3", "R12_EXTENSION", 1, 1, 0),
    ("OP-01", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("OP-02", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("OP-03", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("OP-04", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("OP-05", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("OP-06", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("OP-07", "RF-4", "MODEL_OPS", 1, 1, 0),
    ("CV-01", "RF-5", "MODEL_OPS", 1, 0, 0),
    ("CV-02", "RF-5", "MODEL_OPS", 1, 1, 0),
    ("CV-03", "RF-5", "MODEL_OPS", 1, 1, 0),
    ("CV-04", "RF-5", "R12_EXTENSION", 1, 2, 0),
    ("CV-05", "RF-5", "MODEL_OPS", 1, 1, 0),
    ("CV-06", "RF-5", "MODEL_OPS", 1, 0, 0),
    ("DD-01", "RF-6", "MODEL_OPS", 1, 2, 0),
    ("DD-02", "RF-6", "MODEL_OPS", 1, 0, 0),
    ("DD-03", "RF-6", "MODEL_OPS", 1, 1, 0),
    ("DD-04", "RF-6", "R12_EXTENSION", 1, 1, 0),
    ("RS-01", "RF-7", "MODEL_OPS", 0, 0, 1),
    ("RS-02", "RF-7", "MODEL_OPS", 1, 1, 0),
]
CATALOGUE_IDS = [row[0] for row in CATALOGUE]
EXTENSION_CASES = {"CK-04", "CV-04", "DD-04"}  # design D-17 and Q-CD-4
PREFIX_COUNTS = {"WS": 3, "FN": 3, "CK": 4, "OP": 7, "CV": 6, "DD": 4, "RS": 2}  # design D-17

# Arm names the design gives in identifier form (section 4's table).
NAMED_ARMS = {
    "WS-01": ({"SERIALIZABLE", "ROW_LOCK", "ADVISORY_LOCK", "SINGLE_WRITER"}, {"NONE", "APPEND_ONLY"}),
    "WS-02": ({"SERIALIZABLE"}, {"NONE"}),
    "FN-01": ({"STORE_CHECKED_TOKEN"}, None),
    "FN-02": ({"TARGET_CHECKED_GENERATION"}, None),
}

# Disposition D2 (replaces section 4.8's rows); WS-03 carries no CP-1 (finding F-CD-1).
CRASH_POINTS = {
    "WS-01": {"CP-1"}, "OP-01": {"CP-1", "CP-3"}, "OP-02": {"CP-2"},
    "OP-03": {"CP-4"}, "OP-04": {"CP-3", "CP-4"}, "OP-07": {"CP-4"},
    "FN-01": {"CP-5"}, "FN-02": {"CP-5"}, "CK-02": {"CP-5"},
}

# Section 5 and the addendum's floors: 32 where the schedule forces the violation; OP-01,
# OP-03 and OP-04 at 24, OP-07 at 8.
SEED_COUNT = 32
LOWER_FLOORS = {"OP-01": 24, "OP-03": 24, "OP-04": 24, "OP-07": 8}

ACCEPT = "ACCEPT"


def refuse(code):
    return {"refuse": code}


def load_json(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def golden_bytes(name):
    return (HERE / "golden" / name).read_bytes()


def flatten_strings(obj):
    out = set()
    if isinstance(obj, str):
        out.add(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out |= flatten_strings(k)
            out |= flatten_strings(v)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            out |= flatten_strings(v)
    return out


def walk(obj):
    yield obj
    if isinstance(obj, dict):
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from walk(v)


def seeds_of(value):
    if isinstance(value, dict):
        return list(range(value["first"], value["last"] + 1))
    return list(value)


def report(failures, limit=8):
    head = "\n".join(failures[:limit])
    return "%d failure(s); first %d:\n%s" % (len(failures), min(limit, len(failures)), head)


def require_none(test, failures):
    if failures:
        test.fail(report(failures))


CASES_DOC = load_json("cases.json")
CASES = CASES_DOC["cases"]
CASE_BY_ID = {c["id"]: c for c in CASES}


def floor_of(case_id):
    return LOWER_FLOORS.get(case_id, SEED_COUNT)


# ---------------------------------------------------------------------------------------
# One cached simulation pass per process: every case, arm and seed.
# ---------------------------------------------------------------------------------------

_CACHE = {}


def all_runs():
    if "runs" not in _CACHE:
        out = {}
        for case in CASES:
            for arm in case["arms"]:
                for seed in _sim.SEEDS:
                    out[(case["id"], arm["name"], seed)] = _sim.run(case["id"], arm["name"], seed)
        _CACHE["runs"] = out
    return _CACHE["runs"]


def arm_kind(case_id, arm_name):
    for arm in CASE_BY_ID[case_id]["arms"]:
        if arm["name"] == arm_name:
            return arm["kind"]
    raise KeyError((case_id, arm_name))


def T(family, steps, expect=ACCEPT, setup=None, ident="oracle-trace"):
    return {"id": ident, "family": family, "setup": {} if setup is None else setup,
            "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------------------
# 1. Golden parity.
# ---------------------------------------------------------------------------------------


class GoldenParity(unittest.TestCase):

    def test_golden_files_byte_identical_to_contract(self):
        for name, _family, size, sha, blob, _expect in VECTORS:
            with self.subTest(vector=name):
                data = golden_bytes(name)
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
                git_blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
                self.assertEqual(git_blob, blob)

    def test_vector_families_and_counts(self):
        counts = {}
        for name, family, *_ in VECTORS:
            vec = json.loads(golden_bytes(name))
            self.assertEqual(vec["family"], family, name)
            self.assertEqual(vec["id"] + ".json", name)
            counts[family] = counts.get(family, 0) + 1
        self.assertEqual(counts, VECTORS_BY_FAMILY)
        self.assertEqual(len(VECTORS), 13)
        # Design D-04: 3 ACCEPT and 10 refusals with these codes.
        expects = [v[5] for v in VECTORS]
        self.assertEqual(expects.count(ACCEPT), 3)
        by_code = {}
        for e in expects:
            if e != ACCEPT:
                by_code[e["refuse"]] = by_code.get(e["refuse"], 0) + 1
        self.assertEqual(by_code, {"DC_WRITE_SKEW": 1, "DC_FENCE": 1, "DC_CLOCK": 1, "DC_OPID": 4,
                                   "DC_VERSION": 1, "DC_DERIVED": 1, "DC_REPLAY_STATE": 1})

    def test_contracts_json_pins(self):
        doc = load_json("contracts.json")
        commit = doc["commit"]
        self.assertEqual(len(commit), 40)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in commit))
        self.assertTrue(commit.startswith(COMMIT_PREFIX))
        files = {f["path"]: f for f in doc["files"]}
        self.assertEqual(len(files), len(doc["files"]), "duplicate pin paths")
        self.assertEqual(len(files), 3 + 13)
        for entry in doc["files"]:
            self.assertEqual(entry.get("packet"), "MET-007", entry["path"])  # disposition D3
            self.assertEqual(len(entry["sha256"]), 64)
            self.assertIsInstance(entry["size"], int)
            self.assertGreater(entry["size"], 0)
        self.assertEqual(files[RECORD_PATH]["sha256"], RECORD_SHA256)
        self.assertEqual(files[RECORD_PATH]["size"], RECORD_SIZE)
        self.assertEqual(files[SCHEMA_PATH]["sha256"], SCHEMA_SHA256)
        self.assertIn(MODEL_PATH, files)
        for name, _family, size, sha, _blob, _expect in VECTORS:
            entry = files[VECTOR_DIR + name]
            self.assertEqual(entry["sha256"], sha, name)
            self.assertEqual(entry["size"], size, name)
        # The interface's loader returns the same pins.
        loaded = _ledger.load_contracts()
        self.assertEqual(loaded, doc)

    def test_judge_returns_each_vector_expect(self):
        for name, family, *_rest in VECTORS:
            expect = _rest[-1]
            vec = json.loads(golden_bytes(name))
            with self.subTest(vector=name):
                self.assertEqual(vec["expect"], expect)
                self.assertIsNone(_judge.check_shape(vec))
                self.assertEqual(_judge.judge(vec), expect)
                self.assertEqual(_judge.parity(vec), "MODEL_OPS")

    def test_judge_reads_steps_not_expect_or_id(self):
        # A judge that echoed expect, or looked a vector up by id, would pass parity
        # trivially; its verdict must come from the steps.
        for name, family, *_rest in VECTORS:
            expect = _rest[-1]
            vec = json.loads(golden_bytes(name))
            flipped = dict(vec)
            flipped["expect"] = refuse(CODE_OF[family]) if expect == ACCEPT else ACCEPT
            renamed = dict(vec)
            renamed["id"] = "oracle-renamed"
            with self.subTest(vector=name):
                self.assertEqual(_judge.judge(flipped), expect)
                self.assertEqual(_judge.judge(renamed), expect)

    def test_extra_step_fields_are_informational(self):
        for name, family, *_rest in VECTORS:
            expect = _rest[-1]
            vec = json.loads(golden_bytes(name))
            vec["steps"] = [dict(s, oracleNote="tick-%d" % i) for i, s in enumerate(vec["steps"])]
            with self.subTest(vector=name):
                self.assertEqual(_judge.judge(vec), expect)

    def test_judge_constants(self):
        self.assertEqual(list(_judge.FAMILIES), FAMILIES)
        self.assertEqual(dict(_judge.CODE_OF), CODE_OF)
        self.assertEqual(set(_judge.CODES), set(CODE_OF.values()))
        model_ops = {f: set(ops) for f, ops in dict(_judge.MODEL_OPS).items()}
        self.assertEqual(model_ops, {f: VOCAB[f] - EXTENSION_OPS for f in FAMILIES})
        all_ops = set().union(*VOCAB.values())
        self.assertEqual(flatten_strings(_judge.EXTENSION_OPS) & all_ops, EXTENSION_OPS)
        self.assertIn(EXTENSION_FIELD, flatten_strings(_judge.EXTENSION_FIELDS))


# ---------------------------------------------------------------------------------------
# 2. The judge restates each property (own traces from the record's property texts).
# ---------------------------------------------------------------------------------------

# RF-1: "runs under SERIALIZABLE isolation or holds a lock covering its read set ... and a
# serialization-failure retry never reissues an external effect".
RF1 = [
    ("overspend without a guard",
     T("RF-1", [{"op": "begin", "tx": "a"}, {"op": "begin", "tx": "b"},
                {"op": "reserve", "tx": "a", "units": 1}, {"op": "reserve", "tx": "b", "units": 1},
                {"op": "commit", "tx": "a"}, {"op": "commit", "tx": "b"}],
       setup={"units": 1, "guard": "NONE"}), refuse("DC_WRITE_SKEW")),
    ("serializable: the second writer is aborted",
     T("RF-1", [{"op": "begin", "tx": "a"}, {"op": "begin", "tx": "b"},
                {"op": "reserve", "tx": "a", "units": 1}, {"op": "commit", "tx": "a"}],
       setup={"units": 1, "guard": "SERIALIZABLE"}), ACCEPT),
    ("serializable: both reservations fit",
     T("RF-1", [{"op": "begin", "tx": "a"}, {"op": "begin", "tx": "b"},
                {"op": "reserve", "tx": "a", "units": 1}, {"op": "reserve", "tx": "b", "units": 1},
                {"op": "commit", "tx": "a"}, {"op": "commit", "tx": "b"}],
       setup={"units": 2, "guard": "SERIALIZABLE"}), ACCEPT),
]

# "a serialization-failure retry never reissues an external effect": under SERIALIZABLE,
# writer "b" commits first, so attempt "a"'s commit fails (first committer wins); its retry
# is attempt "a2".
RF1_EFFECT = [
    ("effect issued before a failed commit and reissued by the retry",
     T("RF-1", [{"op": "begin", "tx": "a"}, {"op": "begin", "tx": "b"},
                {"op": "reserve", "tx": "b", "units": 1}, {"op": "commit", "tx": "b"},
                {"op": "reserve", "tx": "a", "units": 1}, {"op": "effect", "tx": "a", "key": "e-1"},
                {"op": "commit", "tx": "a"},
                {"op": "begin", "tx": "a2"}, {"op": "reserve", "tx": "a2", "units": 1},
                {"op": "effect", "tx": "a2", "key": "e-1"}, {"op": "commit", "tx": "a2"}],
       setup={"units": 2, "guard": "SERIALIZABLE"}), refuse("DC_WRITE_SKEW")),
    ("effect after the successful commit only",
     T("RF-1", [{"op": "begin", "tx": "a"}, {"op": "begin", "tx": "b"},
                {"op": "reserve", "tx": "b", "units": 1}, {"op": "commit", "tx": "b"},
                {"op": "reserve", "tx": "a", "units": 1}, {"op": "commit", "tx": "a"},
                {"op": "begin", "tx": "a2"}, {"op": "reserve", "tx": "a2", "units": 1},
                {"op": "commit", "tx": "a2"}, {"op": "effect", "tx": "a2", "key": "e-1"}],
       setup={"units": 2, "guard": "SERIALIZABLE"}), ACCEPT),
    # Addendum D2, finding F-CD-1: "a restart after a crash neither commits nor aborts, so
    # RF-1 does not refuse its reissue" (the reason CP-1 left WS-03). The judge restates the
    # model, so this boundary is ACCEPT.
    ("F-CD-1 boundary: reissue after a crashed attempt that never reached commit",
     T("RF-1", [{"op": "begin", "tx": "a"}, {"op": "reserve", "tx": "a", "units": 1},
                {"op": "effect", "tx": "a", "key": "e-1"},
                {"op": "begin", "tx": "a2"}, {"op": "reserve", "tx": "a2", "units": 1},
                {"op": "effect", "tx": "a2", "key": "e-1"}, {"op": "commit", "tx": "a2"}],
       setup={"units": 1, "guard": "SERIALIZABLE"}), ACCEPT),
]

# RF-2: "writes only with a monotonic fencing token that the store checks ...; a holder that
# resumes after its lease expired is refused".
RF2_SETUP = {"fencing": "STORE_CHECKED_TOKEN"}
RF2 = [
    ("expired holder's write accepted",
     T("RF-2", [{"op": "acquire", "holder": "a", "token": 1}, {"op": "expire", "holder": "a"},
                {"op": "acquire", "holder": "b", "token": 2},
                {"op": "write", "holder": "b", "token": 2, "accepted": True},
                {"op": "write", "holder": "a", "token": 1, "accepted": True}],
       setup=RF2_SETUP), refuse("DC_FENCE")),
    ("expired holder's write refused",
     T("RF-2", [{"op": "acquire", "holder": "a", "token": 1}, {"op": "expire", "holder": "a"},
                {"op": "acquire", "holder": "b", "token": 2},
                {"op": "write", "holder": "b", "token": 2, "accepted": True},
                {"op": "write", "holder": "a", "token": 1, "accepted": False}],
       setup=RF2_SETUP), ACCEPT),
    ("token reissued at the newest; the fenced-out holder's write lands",
     T("RF-2", [{"op": "acquire", "holder": "a", "token": 2}, {"op": "expire", "holder": "a"},
                {"op": "acquire", "holder": "b", "token": 2},
                {"op": "write", "holder": "b", "token": 2, "accepted": True},
                {"op": "write", "holder": "a", "token": 2, "accepted": True}],
       setup=RF2_SETUP), refuse("DC_FENCE")),
    ("persisted counter: a newer token, the stale write refused",
     T("RF-2", [{"op": "acquire", "holder": "a", "token": 2}, {"op": "expire", "holder": "a"},
                {"op": "acquire", "holder": "b", "token": 3},
                {"op": "write", "holder": "b", "token": 3, "accepted": True},
                {"op": "write", "holder": "a", "token": 2, "accepted": False}],
       setup=RF2_SETUP), ACCEPT),
]

# RF-3: "durations use a monotonic source; a wall-clock comparison carries a declared skew
# margin; a clock jump never extends a lease ...".
RF3 = [
    ("lease held past its monotonic duration after a wall jump back",
     T("RF-3", [{"op": "lease_start", "monotonicMs": 0, "wallMs": 100000, "leaseMs": 1000},
                {"op": "wall_jump", "deltaMs": -5000},
                {"op": "lease_check", "monotonicMs": 1500, "wallMs": 96500, "held": True}]),
     refuse("DC_CLOCK")),
    ("lease released at its monotonic duration",
     T("RF-3", [{"op": "lease_start", "monotonicMs": 0, "wallMs": 100000, "leaseMs": 1000},
                {"op": "wall_jump", "deltaMs": -5000},
                {"op": "lease_check", "monotonicMs": 1500, "wallMs": 96500, "held": False}]),
     ACCEPT),
    ("lease held within its monotonic duration",
     T("RF-3", [{"op": "lease_start", "monotonicMs": 0, "wallMs": 100000, "leaseMs": 1000},
                {"op": "wall_jump", "deltaMs": 4000},
                {"op": "lease_check", "monotonicMs": 900, "wallMs": 104900, "held": True}]),
     ACCEPT),
    ("wall-clock comparison without a skew margin",
     T("RF-3", [{"op": "wall_compare", "accepted": True, "localWallMs": 1000, "expiryWallMs": 5000}]),
     refuse("DC_CLOCK")),
    ("wall-clock comparison with a declared skew margin",
     T("RF-3", [{"op": "wall_compare", "skewMarginMs": 500, "accepted": True,
                 "localWallMs": 1000, "expiryWallMs": 5000}]),
     ACCEPT),
]

# RF-4: "an operation ID is minted once, carried unchanged ... and deduplicated at the
# effect's own store, so retries and outbox replays apply once"; operationIds.none: "never
# retried"; receiptKey: "a function of the operation ID and the edge, never a fresh value per
# attempt".
E = "caller->callee"
RF4 = [
    ("NONE edge retried after an unknown outcome",
     T("RF-4", [{"op": "call", "operation": "op-9", "edge": E, "class": "NONE", "attempt": 1,
                 "outcome": "unknown", "applied": True},
                {"op": "call", "operation": "op-9", "edge": E, "class": "NONE", "attempt": 2,
                 "outcome": "committed", "applied": True}]), refuse("DC_OPID")),
    ("NONE edge: unknown outcome, no retry",
     T("RF-4", [{"op": "call", "operation": "op-9", "edge": E, "class": "NONE", "attempt": 1,
                 "outcome": "unknown", "applied": True}]), ACCEPT),
    ("NATIVE retry applied twice",
     T("RF-4", [{"op": "call", "operation": "op-8", "edge": E, "class": "NATIVE", "attempt": 1,
                 "outcome": "committed", "applied": True},
                {"op": "call", "operation": "op-8", "edge": E, "class": "NATIVE", "attempt": 2,
                 "outcome": "committed", "applied": True}]), refuse("DC_OPID")),
    ("NATIVE retry deduplicated",
     T("RF-4", [{"op": "call", "operation": "op-8", "edge": E, "class": "NATIVE", "attempt": 1,
                 "outcome": "committed", "applied": True},
                {"op": "call", "operation": "op-8", "edge": E, "class": "NATIVE", "attempt": 2,
                 "outcome": "committed", "applied": False}]), ACCEPT),
    ("fresh receipt key per attempt",
     T("RF-4", [{"op": "call", "operation": "op-7", "edge": E, "class": "RECEIPT_KEY", "attempt": 1,
                 "key": "k-a", "outcome": "unknown", "applied": True},
                {"op": "call", "operation": "op-7", "edge": E, "class": "RECEIPT_KEY", "attempt": 2,
                 "key": "k-b", "outcome": "committed", "applied": True}]), refuse("DC_OPID")),
    ("receipt key from operation and edge, across a restart",
     T("RF-4", [{"op": "call", "operation": "op-7", "edge": E, "class": "RECEIPT_KEY", "attempt": 1,
                 "key": "op-7/" + E, "outcome": "unknown", "applied": True},
                {"op": "call", "operation": "op-7", "edge": E, "class": "RECEIPT_KEY", "attempt": 2,
                 "key": "op-7/" + E, "outcome": "final", "applied": False,
                 "afterRestart": True}]), ACCEPT),
    ("exactly-once claimed",
     T("RF-4", [{"op": "claim", "exactlyOnce": True, "maxAttempts": 3}]), refuse("DC_OPID")),
    ("bounded claim stated",
     T("RF-4", [{"op": "claim", "exactlyOnce": False, "maxAttempts": 3}]), ACCEPT),
    ("exception path without deduplication",
     T("RF-4", [{"op": "call", "operation": "op-6", "edge": E, "class": "NATIVE", "attempt": 1,
                 "outcome": "unknown", "applied": True},
                {"op": "call", "operation": "op-6", "edge": E, "class": "NATIVE", "attempt": 2,
                 "path": "exception", "dedup": False, "applied": True}]), refuse("DC_OPID")),
    ("exception path deduplicated",
     T("RF-4", [{"op": "call", "operation": "op-6", "edge": E, "class": "NATIVE", "attempt": 1,
                 "outcome": "unknown", "applied": True},
                {"op": "call", "operation": "op-6", "edge": E, "class": "NATIVE", "attempt": 2,
                 "path": "exception", "dedup": True, "applied": False}]), ACCEPT),
]

# RF-5: "readers accept the previous and the current version in both directions during a
# rollout. Public input may reject unknown fields and versions. Stored envelopes keep opaque
# extension data without meaning or authority. Migrations name reader-writer pairs,
# including rollback".
RF5 = [
    ("reader N refuses N-1 during a rollout",
     T("RF-5", [{"op": "read_record", "recordVersion": "N-1", "reader": "N", "rollout": True,
                 "accepted": False}]), refuse("DC_VERSION")),
    ("reader N reads N-1 during a rollout",
     T("RF-5", [{"op": "read_record", "recordVersion": "N-1", "reader": "N", "rollout": True,
                 "accepted": True}]), ACCEPT),
    ("rolled-back reader N-1 refuses N",
     T("RF-5", [{"op": "read_record", "recordVersion": "N", "reader": "N-1", "rollout": True,
                 "accepted": False}]), refuse("DC_VERSION")),
    ("rolled-back reader N-1 reads N",
     T("RF-5", [{"op": "read_record", "recordVersion": "N", "reader": "N-1", "rollout": True,
                 "accepted": True}]), ACCEPT),
    ("envelope drops its opaque extension",
     T("RF-5", [{"op": "store_envelope", "extensionKept": False}]), refuse("DC_VERSION")),
    ("envelope keeps its opaque extension",
     T("RF-5", [{"op": "store_envelope", "extensionKept": True}]), ACCEPT),
    ("extension acted on as authority",
     T("RF-5", [{"op": "store_envelope", "extensionKept": True, "extensionActedOn": True}]),
     refuse("DC_VERSION")),
    ("extension kept and inert",
     T("RF-5", [{"op": "store_envelope", "extensionKept": True, "extensionActedOn": False}]), ACCEPT),
    # migrate's value forms are not in the interface; its twins are built from the run's
    # own CV-05 defended trace in test_rf5_migration_twins below.
    ("public input rejects an unknown field (no over-refusal)",
     T("RF-5", [{"op": "public_input", "rejected": True}]), ACCEPT),
]

# RF-6: "a deletion reaches every derived store, with a receipt; a periodic rebuild-and-
# compare audit finds drift"; PAR-D1's restore: the deletion ledger is re-applied.
RF6_SETUP = {"derived": ["index", "embedding", "cache"]}
RF6 = [
    ("deletion misses a derived store",
     T("RF-6", [{"op": "insert", "id": "d-1"},
                {"op": "delete", "id": "d-1", "propagatedTo": ["index", "embedding"], "receipt": True}],
       setup=RF6_SETUP), refuse("DC_DERIVED")),
    ("deletion reaches every derived store, with a receipt",
     T("RF-6", [{"op": "insert", "id": "d-1"},
                {"op": "delete", "id": "d-1", "propagatedTo": ["index", "embedding", "cache"],
                 "receipt": True}],
       setup=RF6_SETUP), ACCEPT),
    ("deletion without a receipt",
     T("RF-6", [{"op": "insert", "id": "d-1"},
                {"op": "delete", "id": "d-1", "propagatedTo": ["index", "embedding", "cache"],
                 "receipt": False}],
       setup=RF6_SETUP), refuse("DC_DERIVED")),
    ("drift found and not reported",
     T("RF-6", [{"op": "rebuild_compare", "driftFound": True, "reported": False}],
       setup=RF6_SETUP), refuse("DC_DERIVED")),
    ("drift found and reported",
     T("RF-6", [{"op": "rebuild_compare", "driftFound": True, "reported": True}],
       setup=RF6_SETUP), ACCEPT),
    ("restore without re-applying the deletion ledger",
     T("RF-6", [{"op": "insert", "id": "d-1"},
                {"op": "delete", "id": "d-1", "propagatedTo": ["index", "embedding", "cache"],
                 "receipt": True},
                {"op": "restore", "reapplied": False}],
       setup=RF6_SETUP), refuse("DC_DERIVED")),
    ("restore re-applies the deletion ledger",
     T("RF-6", [{"op": "insert", "id": "d-1"},
                {"op": "delete", "id": "d-1", "propagatedTo": ["index", "embedding", "cache"],
                 "receipt": True},
                {"op": "restore", "reapplied": True}],
       setup=RF6_SETUP), ACCEPT),
]

# RF-7: "the durable state a replay consults is an input beside the log".
RF7 = [
    ("replay given the log alone",
     T("RF-7", [{"op": "replay", "inputs": ["log"], "consulted": ["log", "budget-state"]}]),
     refuse("DC_REPLAY_STATE")),
    ("replay given the log and the state it consults",
     T("RF-7", [{"op": "replay", "inputs": ["log", "budget-state"],
                 "consulted": ["log", "budget-state"]}]), ACCEPT),
]

OWN_TRACES = {"RF-1": RF1, "RF-2": RF2, "RF-3": RF3, "RF-4": RF4, "RF-5": RF5, "RF-6": RF6, "RF-7": RF7}


class JudgeRestatesProperties(unittest.TestCase):

    def _check(self, family):
        rows = OWN_TRACES[family]
        self.assertTrue(any(v == ACCEPT for _, _, v in rows))
        self.assertTrue(any(v != ACCEPT for _, _, v in rows))
        for label, trace, verdict in rows:
            trace = dict(trace, expect=verdict)
            with self.subTest(family=family, trace=label):
                self.assertIsNone(_judge.check_shape(trace))
                self.assertEqual(_judge.judge(trace), verdict)

    def test_rf1_write_skew(self):
        self._check("RF-1")

    def test_rf1_retry_never_reissues_an_effect(self):
        control = [a["name"] for a in CASE_BY_ID["WS-03"]["arms"] if a["kind"] == "CONTROL"][0]
        sample = all_runs()[("WS-03", control, 1)]["trace"]
        for label, trace, verdict in RF1_EFFECT:
            trace = dict(trace, expect=verdict)
            with self.subTest(trace=label):
                self.assertIsNone(_judge.check_shape(trace))
                self.assertEqual(_judge.judge(trace), verdict,
                                 "for comparison, WS-03 %s seed 1: %s"
                                 % (control, json.dumps(sample["steps"], sort_keys=True)[:900]))

    def test_rf2_fencing(self):
        self._check("RF-2")

    def test_rf3_clocks(self):
        self._check("RF-3")

    def test_rf4_operation_ids(self):
        self._check("RF-4")

    def test_rf5_compatibility(self):
        self._check("RF-5")

    def test_rf6_derived_data(self):
        self._check("RF-6")

    def test_rf7_replay_state(self):
        self._check("RF-7")

    def test_rf5_migration_twins(self):
        # RF-5: "Migrations name reader-writer pairs, including rollback". The value forms of
        # migrate's fields are not in the interface, so the passing twin takes the migrate
        # step of CV-05's defended run (seed 1) and the breaking twins empty one field each.
        defended = [a["name"] for a in CASE_BY_ID["CV-05"]["arms"] if a["kind"] == "DEFENDED"][0]
        trace = all_runs()[("CV-05", defended, 1)]["trace"]
        migrations = steps_of(trace, "migrate")
        self.assertTrue(migrations, "CV-05's defended trace states no migration")
        step = dict(migrations[0])
        self.assertTrue(step.get("readerWriterPairs"))
        self.assertTrue(step.get("rollback"))
        self.assertEqual(_judge.judge(T("RF-5", [step])), ACCEPT)

        def emptied(value):
            return type(value)() if isinstance(value, (list, dict, str, bool)) else None

        for field in ("rollback", "readerWriterPairs"):
            broken = dict(step)
            broken[field] = emptied(step[field])
            with self.subTest(missing=field):
                self.assertEqual(_judge.judge(T("RF-5", [broken], expect=refuse("DC_VERSION"))),
                                 refuse("DC_VERSION"))

    def test_parity_of_own_traces(self):
        for family, rows in OWN_TRACES.items():
            for label, trace, _verdict in rows:
                ops = {s["op"] for s in trace["steps"]}
                ext = bool(ops & EXTENSION_OPS) or any(EXTENSION_FIELD in s for s in trace["steps"])
                with self.subTest(trace=label):
                    self.assertEqual(_judge.parity(trace), "R12_EXTENSION" if ext else "MODEL_OPS")

    def test_r12_extensions_set_parity(self):
        host = T("RF-3", [{"op": "lease_start", "monotonicMs": 0, "wallMs": 100000, "leaseMs": 1000},
                          {"op": "host_replace", "monotonicMs": 0},
                          {"op": "lease_check", "monotonicMs": 500, "wallMs": 100500, "held": True}])
        restore = T("RF-6", [{"op": "insert", "id": "d-1"},
                             {"op": "delete", "id": "d-1", "propagatedTo": ["index"], "receipt": True},
                             {"op": "restore", "reapplied": True}], setup={"derived": ["index"]})
        acted = T("RF-5", [{"op": "store_envelope", "extensionKept": True, "extensionActedOn": False}])
        for name, trace in (("host_replace", host), ("restore", restore), ("extensionActedOn", acted)):
            with self.subTest(extension=name):
                self.assertIsNone(_judge.check_shape(trace))
                self.assertEqual(_judge.parity(trace), "R12_EXTENSION")
                verdict = _judge.judge(trace)
                self.assertIn(verdict, (ACCEPT, refuse(CODE_OF[trace["family"]])))

    def test_malformed_traces_raise_value_error(self):
        good = T("RF-7", [{"op": "replay", "inputs": ["log"], "consulted": ["log"]}])
        self.assertIsNone(_judge.check_shape(good))
        self.assertEqual(_judge.judge(good), ACCEPT)
        missing = dict(good)
        del missing["expect"]
        extra = dict(good, notes="x")
        bad = {
            "not a dict": [good],
            "missing expect": missing,
            "extra top-level key": extra,
            "unknown family": dict(good, family="RF-9"),
            "steps not a list": dict(good, steps="replay"),
            "step without op": dict(good, steps=[{"inputs": ["log"], "consulted": ["log"]}]),
            "unknown op": dict(good, steps=[{"op": "teleport"}]),
            "expect neither ACCEPT nor a refusal": dict(good, expect="MAYBE"),
            "setup not an object": dict(good, setup=[]),
        }
        for label, trace in bad.items():
            with self.subTest(malformed=label):
                with self.assertRaises(ValueError):
                    _judge.check_shape(trace)
                with self.assertRaises(ValueError):
                    _judge.judge(trace)


# ---------------------------------------------------------------------------------------
# 3. The catalogue.
# ---------------------------------------------------------------------------------------


class Catalogue(unittest.TestCase):

    def test_29_cases_in_design_order(self):
        self.assertEqual([c["id"] for c in CASES], CATALOGUE_IDS)
        self.assertEqual(len(CASES), 29)
        prefixes = {}
        for cid in CATALOGUE_IDS:
            prefixes[cid[:2]] = prefixes.get(cid[:2], 0) + 1
        self.assertEqual(prefixes, PREFIX_COUNTS)
        self.assertEqual(CASES_DOC.get("packet"), "CONF-DATA-001")
        self.assertEqual(seeds_of(CASES_DOC["seeds"]), list(range(1, 33)))
        loaded = _ledger.load_cases()
        self.assertIn(loaded, (CASES_DOC, CASES))

    def test_families_parity_and_labels(self):
        for cid, family, parity, *_ in CATALOGUE:
            case = CASE_BY_ID[cid]
            with self.subTest(case=cid):
                self.assertEqual(case["family"], family)
                self.assertEqual(case["parity"], parity)
                if cid in EXTENSION_CASES:
                    # VIS-C15-SPLIT condition 4: expected arms by R12, provisional.
                    self.assertEqual(case["expectedArmsBy"], "R12")
                    self.assertIs(case["provisional"], True)
                else:
                    self.assertNotEqual(case["expectedArmsBy"], "R12")
                    self.assertIs(case["provisional"], False)
        self.assertEqual({c["id"] for c in CASES if c["parity"] == "R12_EXTENSION"}, EXTENSION_CASES)

    def test_arms_kind_code_floor(self):
        total = 0
        for cid, family, _parity, n_def, n_ctl, n_neg in CATALOGUE:
            arms = CASE_BY_ID[cid]["arms"]
            total += len(arms)
            kinds = [a["kind"] for a in arms]
            with self.subTest(case=cid):
                self.assertEqual(len({a["name"] for a in arms}), len(arms), "arm names unique")
                self.assertEqual(kinds.count("DEFENDED"), n_def)
                self.assertEqual(kinds.count("CONTROL"), n_ctl)
                self.assertEqual(kinds.count("NEGATIVE"), n_neg)
                self.assertEqual(len(arms), n_def + n_ctl + n_neg)
                for arm in arms:
                    if arm["kind"] == "DEFENDED":
                        self.assertIsNone(arm["code"])
                        self.assertIn(arm["floor"], (0, None))
                    else:
                        self.assertEqual(arm["code"], CODE_OF[family])
                        self.assertEqual(arm["floor"], floor_of(cid))
                if cid in NAMED_ARMS:
                    defended, controls = NAMED_ARMS[cid]
                    self.assertEqual({a["name"] for a in arms if a["kind"] == "DEFENDED"}, defended)
                    if controls is not None:
                        self.assertEqual({a["name"] for a in arms if a["kind"] == "CONTROL"}, controls)
        self.assertEqual(total, 60)

    def test_crash_points_per_d2(self):
        for cid in CATALOGUE_IDS:
            with self.subTest(case=cid):
                self.assertEqual(set(CASE_BY_ID[cid]["crashPoints"]), CRASH_POINTS.get(cid, set()))
        self.assertNotIn("CP-1", CASE_BY_ID["WS-03"]["crashPoints"])  # finding F-CD-1

    def test_sim_seeds_and_runners(self):
        self.assertEqual(list(_sim.SEEDS), list(range(1, 33)))
        self.assertEqual(list(_sim.RUNNERS), CATALOGUE_IDS)


# ---------------------------------------------------------------------------------------
# 4. The simulation in every case, arm and seed.
# ---------------------------------------------------------------------------------------


class Simulation(unittest.TestCase):

    def test_every_run_is_well_formed(self):
        runs = all_runs()
        self.assertEqual(len(runs), 60 * 32)
        failures = []
        for (cid, arm, seed), r in runs.items():
            case = CASE_BY_ID[cid]
            where = "%s/%s/seed %d" % (cid, arm, seed)
            if set(r) != {"trace", "broken", "violation", "notes"}:
                failures.append(where + ": result keys")
                continue
            trace = r["trace"]
            if not isinstance(trace, dict) or set(trace) != {"id", "family", "setup", "steps", "expect"}:
                failures.append(where + ": trace keys")
                continue
            try:
                if _judge.check_shape(trace) is not None:
                    failures.append(where + ": check_shape returned a value")
            except ValueError as exc:
                failures.append(where + ": check_shape raised " + str(exc)[:80])
            if trace["id"] != cid:
                failures.append(where + ": trace id " + repr(trace["id"]))
            if trace["family"] != case["family"]:
                failures.append(where + ": trace family")
            if _judge.parity(trace) != case["parity"]:
                failures.append(where + ": parity " + _judge.parity(trace))
            if not isinstance(r["broken"], bool) or not isinstance(r["violation"], bool):
                failures.append(where + ": broken/violation not bool")
            bad_ops = {s.get("op") for s in trace["steps"]} - VOCAB[case["family"]]
            if bad_ops:
                failures.append(where + ": ops outside the family vocabulary " + repr(sorted(map(str, bad_ops))))
        require_none(self, failures)

    def test_d1_agreement(self):
        failures = []
        for (cid, arm, seed), r in all_runs().items():
            where = "%s/%s/seed %d" % (cid, arm, seed)
            code = CODE_OF[CASE_BY_ID[cid]["family"]]
            expect = refuse(code) if r["broken"] else ACCEPT
            if r["trace"]["expect"] != expect:
                failures.append(where + ": expect does not follow broken")
            if _judge.judge(r["trace"]) != r["trace"]["expect"]:
                failures.append(where + ": judge disagrees with expect")
            if r["violation"] and not r["broken"]:
                failures.append(where + ": violation without a broken rule")
        require_none(self, failures)

    def test_defended_arms_never_break_or_violate(self):
        failures = []
        for (cid, arm, seed), r in all_runs().items():
            if arm_kind(cid, arm) != "DEFENDED":
                continue
            if r["broken"] or r["violation"] or _judge.judge(r["trace"]) != ACCEPT:
                failures.append("%s/%s/seed %d" % (cid, arm, seed))
        require_none(self, failures)

    def test_control_and_negative_arms_reach_their_floor(self):
        runs = all_runs()
        for case in CASES:
            for arm in case["arms"]:
                if arm["kind"] == "DEFENDED":
                    continue
                code = CODE_OF[case["family"]]
                with self.subTest(case=case["id"], arm=arm["name"]):
                    rs = [runs[(case["id"], arm["name"], s)] for s in _sim.SEEDS]
                    verdicts = [_judge.judge(r["trace"]) for r in rs]
                    for v in verdicts:
                        self.assertIn(v, (ACCEPT, refuse(code)))
                    violations = sum(r["violation"] for r in rs)
                    broken = sum(r["broken"] for r in rs)
                    # Section 5: "the outcome is violated in at least the case's declared
                    # power floor"; a control that never violates proves nothing.
                    self.assertGreaterEqual(violations, floor_of(case["id"]))
                    self.assertGreater(violations, 0)
                    self.assertGreaterEqual(broken, violations)

    def test_r12_extension_ops_only_in_extension_cases(self):
        marker = {"CK-04": "host_replace", "DD-04": "restore"}
        failures = []
        for (cid, arm, seed), r in all_runs().items():
            steps = r["trace"]["steps"]
            ops = {s.get("op") for s in steps}
            has_field = any(EXTENSION_FIELD in s for s in steps)
            where = "%s/%s/seed %d" % (cid, arm, seed)
            if cid in marker:
                if marker[cid] not in ops:
                    failures.append(where + ": missing " + marker[cid])
            elif cid == "CV-04":
                if not has_field:
                    failures.append(where + ": missing " + EXTENSION_FIELD)
            elif (ops & EXTENSION_OPS) or has_field:
                failures.append(where + ": extension in a MODEL_OPS case")
        require_none(self, failures)

    def test_second_run_is_identical(self):
        runs = all_runs()
        failures = []
        for (cid, arm, seed), r in runs.items():
            if _sim.run(cid, arm, seed) != r:
                failures.append("%s/%s/seed %d" % (cid, arm, seed))
        require_none(self, failures)

    def test_judge_ignores_expect_on_sim_traces(self):
        runs = all_runs()
        for case in CASES:
            code = CODE_OF[case["family"]]
            for arm in case["arms"]:
                for seed in (1, 32):
                    trace = runs[(case["id"], arm["name"], seed)]["trace"]
                    verdict = _judge.judge(trace)
                    flipped = dict(trace, expect=ACCEPT if verdict != ACCEPT else refuse(code))
                    self.assertEqual(_judge.judge(flipped), verdict, (case["id"], arm["name"], seed))

    def test_ck01_wall_jumps_span_design_range(self):
        # Section 4, CK-01: "wall clock jumps of -5 s to +5 s during a lease".
        deltas = []
        for (cid, arm, seed), r in all_runs().items():
            if cid != "CK-01":
                continue
            for s in r["trace"]["steps"]:
                if s.get("op") == "wall_jump":
                    deltas.append(s["deltaMs"])
        self.assertTrue(deltas, "CK-01 traces carry no wall_jump step")
        self.assertTrue(all(-5000 <= d <= 5000 for d in deltas), (min(deltas), max(deltas)))
        self.assertTrue(any(d < 0 for d in deltas), "no backward jump drawn")
        self.assertTrue(any(d > 0 for d in deltas), "no forward jump drawn (design: -5 s to +5 s)")

    def test_cv01_interleaves_both_versions(self):
        # Section 4, CV-01: "N-1 and N writers and readers interleave across a rolling upgrade".
        pairs = set()
        for (cid, arm, seed), r in all_runs().items():
            if cid != "CV-01":
                continue
            for s in r["trace"]["steps"]:
                if s.get("op") == "read_record":
                    pairs.add((s["recordVersion"], s["reader"]))
                    self.assertTrue(s["accepted"], (seed, s))
        self.assertEqual(pairs, {("N-1", "N-1"), ("N-1", "N"), ("N", "N-1"), ("N", "N")})

    def test_ws01_runs_concurrent_reservations(self):
        # Section 4, WS-01: "2 to 4 concurrent budget reservations".
        for (cid, arm, seed), r in all_runs().items():
            if cid != "WS-01":
                continue
            # A lock-defended writer may never reserve, so count the writers that begin.
            txs = {s["tx"] for s in r["trace"]["steps"] if s.get("op") == "begin"}
            self.assertGreaterEqual(len(txs), 2, (arm, seed))


# ---------------------------------------------------------------------------------------
# 5. Own reading of traces: recompute the outcome from the steps.
# ---------------------------------------------------------------------------------------


def steps_of(trace, op):
    return [s for s in trace["steps"] if s.get("op") == op]


def rf1_overspent(trace):
    units = trace["setup"]["units"]
    pending, committed = {}, 0
    for s in trace["steps"]:
        if s["op"] == "begin":
            pending[s["tx"]] = 0
        elif s["op"] == "reserve":
            pending[s["tx"]] = pending.get(s["tx"], 0) + s["units"]
        elif s["op"] == "commit":
            committed += pending.pop(s["tx"], 0)
    return committed > units


def rf1_overspent_first_committer_wins(trace):
    # SERIALIZABLE read as snapshot isolation with first-committer-wins: a writer's commit
    # fails when another writer that also reserved committed after it began.
    units = trace["setup"]["units"]
    began, reserved, won, committed = {}, {}, [], 0
    for i, s in enumerate(trace["steps"]):
        if s["op"] == "begin":
            began[s["tx"]], reserved[s["tx"]] = i, 0
        elif s["op"] == "reserve":
            reserved[s["tx"]] = reserved.get(s["tx"], 0) + s["units"]
        elif s["op"] == "commit":
            tx = s["tx"]
            mine = reserved.get(tx, 0)
            if mine and any(at > began.get(tx, -1) and theirs for at, theirs in won):
                continue  # serialization failure: this commit aborts
            won.append((i, mine))
            committed += mine
    return committed > units


def rf1_effect_reissued(trace):
    keys = [s["key"] for s in steps_of(trace, "effect")]
    return len(keys) != len(set(keys))


def rf2_stale_write_accepted(trace):
    current = None
    for s in trace["steps"]:
        if s["op"] == "acquire":
            current = s["holder"]
        elif s["op"] == "expire" and s["holder"] == current:
            current = None
        elif s["op"] == "write" and s.get("accepted") and s["holder"] != current:
            return True
    return False


def rf3_overheld(trace):
    start, strict, weak = None, False, False
    for s in trace["steps"]:
        if s["op"] == "lease_start":
            start = (s["monotonicMs"], s["leaseMs"])
        elif s["op"] == "lease_check" and s.get("held") and start is not None:
            elapsed = s["monotonicMs"] - start[0]
            strict = strict or elapsed > start[1]
            weak = weak or elapsed >= start[1]
    return strict, weak


def rf3_margin_missing(trace):
    return any(s.get("skewMarginMs") is None for s in steps_of(trace, "wall_compare"))


def rf4_applied_twice(trace):
    counts = {}
    for s in steps_of(trace, "call"):
        if s.get("applied") and s.get("class") != "READ":
            key = (s.get("operation"), s.get("edge"), s.get("class"))
            counts[key] = counts.get(key, 0) + 1
    return any(n > 1 for n in counts.values())


def rf4_none_retried(trace):
    return any(s.get("class") == "NONE" and s.get("attempt", 1) >= 2 for s in steps_of(trace, "call"))


def rf4_receipt_key_changed(trace):
    keys = {}
    for s in steps_of(trace, "call"):
        if s.get("class") == "RECEIPT_KEY":
            keys.setdefault((s.get("operation"), s.get("edge")), set()).add(s.get("key"))
    return any(len(v) > 1 for v in keys.values())


def rf4_exactly_once_claimed(trace):
    return any(s.get("exactlyOnce") for s in steps_of(trace, "claim"))


def rf5_rollout_read_refused(trace):
    both = {"N-1", "N"}
    return any(s.get("rollout") and not s.get("accepted") and s["recordVersion"] in both
               and s["reader"] in both for s in steps_of(trace, "read_record"))


def rf5_envelope_misused(trace):
    return any(not s.get("extensionKept") or s.get("extensionActedOn")
               for s in steps_of(trace, "store_envelope"))


def rf6_missed(trace):
    derived = set(trace["setup"]["derived"])
    return any(not derived <= set(s["propagatedTo"]) for s in steps_of(trace, "delete"))


def rf6_missed_or_no_receipt(trace):
    return rf6_missed(trace) or any(not s.get("receipt") for s in steps_of(trace, "delete"))


def rf6_drift_unreported(trace):
    return any(s.get("driftFound") and not s.get("reported") for s in steps_of(trace, "rebuild_compare"))


def rf6_restored_without_reapply(trace):
    return any(not s.get("reapplied") for s in steps_of(trace, "restore"))


def rf7_state_not_given(trace):
    return any(not set(s["consulted"]) <= set(s["inputs"]) for s in steps_of(trace, "replay"))


# (case, reading, the run flag it must equal[, arms left to a separate test])
READINGS = [
    ("WS-01", rf1_overspent, "violation", {"SERIALIZABLE"}),
    ("WS-02", rf1_overspent, "violation", {"SERIALIZABLE"}),
    ("WS-03", rf1_effect_reissued, "violation"),
    ("FN-01", rf2_stale_write_accepted, "violation"),
    ("FN-02", rf2_stale_write_accepted, "violation"),
    ("FN-03", rf2_stale_write_accepted, "violation"),
    ("CK-02", rf3_margin_missing, "broken"),
    ("OP-01", rf4_applied_twice, "violation"),
    ("OP-02", rf4_applied_twice, "violation"),
    ("OP-03", rf4_applied_twice, "violation"),
    ("OP-03", rf4_none_retried, "broken"),
    ("OP-04", rf4_applied_twice, "violation"),
    ("OP-04", rf4_receipt_key_changed, "broken"),
    ("OP-05", rf4_applied_twice, "violation"),
    ("OP-06", rf4_exactly_once_claimed, "broken"),
    ("OP-07", rf4_applied_twice, "violation"),
    ("CV-02", rf5_rollout_read_refused, "violation"),
    ("CV-03", rf5_rollout_read_refused, "violation"),
    ("CV-04", rf5_envelope_misused, "broken"),
    ("DD-01", rf6_missed_or_no_receipt, "broken"),
    ("DD-03", rf6_drift_unreported, "broken"),
    ("DD-04", rf6_restored_without_reapply, "violation"),
    ("RS-01", rf7_state_not_given, "broken"),
    ("RS-02", rf7_state_not_given, "broken"),
]


class OwnReading(unittest.TestCase):

    def test_readings_agree_with_the_run(self):
        runs = all_runs()
        for cid, reading, flag, *rest in READINGS:
            skip = rest[0] if rest else set()
            with self.subTest(case=cid, reading=reading.__name__):
                failures, seen_true = [], False
                for arm in CASE_BY_ID[cid]["arms"]:
                    if arm["name"] in skip:
                        continue
                    for seed in _sim.SEEDS:
                        r = runs[(cid, arm["name"], seed)]
                        mine = reading(r["trace"])
                        seen_true = seen_true or mine
                        if mine != r[flag] or (arm["kind"] == "DEFENDED" and mine):
                            note = "%s/seed %d: reading %s, %s %s" % (arm["name"], seed, mine, flag, r[flag])
                            if not failures:
                                note += "\n  trace: " + json.dumps(r["trace"], sort_keys=True)[:900]
                            failures.append(note)
                require_none(self, failures)
                self.assertTrue(seen_true, "reading never true: the case shows nothing")

    def test_ws_serializable_traces_under_first_committer_wins(self):
        # Section 4 (WS-03): under SERIALIZABLE "a serialization failure aborts a transaction".
        # The trace marks no abort, so a commit step is an attempt; read with snapshot
        # isolation and first committer wins, the SERIALIZABLE arms must show no overspend
        # exactly when the final state shows none.
        runs = all_runs()
        failures, seen_conflict = [], False
        for cid in ("WS-01", "WS-02"):
            for seed in _sim.SEEDS:
                r = runs[(cid, "SERIALIZABLE", seed)]
                mine = rf1_overspent_first_committer_wins(r["trace"])
                seen_conflict = seen_conflict or rf1_overspent(r["trace"])
                if mine != r["violation"]:
                    failures.append("%s/SERIALIZABLE/seed %d: reading %s, violation %s"
                                    % (cid, seed, mine, r["violation"]))
        require_none(self, failures)
        self.assertTrue(seen_conflict, "no serialization conflict was ever drawn")

    def test_ck01_lease_held_past_monotonic_duration(self):
        runs = all_runs()
        failures, seen = [], False
        for arm in CASE_BY_ID["CK-01"]["arms"]:
            for seed in _sim.SEEDS:
                r = runs[("CK-01", arm["name"], seed)]
                strict, weak = rf3_overheld(r["trace"])
                seen = seen or strict
                ok = (r["violation"] == strict) if strict == weak else r["violation"] in (strict, weak)
                if not ok:
                    failures.append("%s/seed %d: reading %s, violation %s" % (arm["name"], seed, strict, r["violation"]))
        require_none(self, failures)
        self.assertTrue(seen)

    def test_dd01_missed_store_is_a_violation(self):
        runs = all_runs()
        for arm in CASE_BY_ID["DD-01"]["arms"]:
            for seed in _sim.SEEDS:
                r = runs[("DD-01", arm["name"], seed)]
                if rf6_missed(r["trace"]):
                    self.assertTrue(r["violation"], (arm["name"], seed))

    def test_rs_replay_divergence_follows_the_rule(self):
        runs = all_runs()
        for cid in ("RS-01", "RS-02"):
            for arm in CASE_BY_ID[cid]["arms"]:
                for seed in _sim.SEEDS:
                    r = runs[(cid, arm["name"], seed)]
                    if r["violation"]:
                        self.assertTrue(rf7_state_not_given(r["trace"]), (cid, arm["name"], seed))


# ---------------------------------------------------------------------------------------
# 6. The ledger and the records.
# ---------------------------------------------------------------------------------------


class LedgerAndRecords(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ledger = _ledger.ledger()

    def test_results_json_is_the_ledger(self):
        self.assertEqual(_ledger.serialize(self.ledger), (HERE / "results.json").read_bytes())

    def test_campaign_record_json(self):
        record = _ledger.campaign_record(self.ledger)
        self.assertEqual(_ledger.serialize(record), (HERE / "campaign-record.json").read_bytes())

    def test_fresh_build_replays_every_arm(self):
        # Section 5's replay rule: a re-run of every arm reproduces the recorded digests.
        self.assertEqual(_ledger.serialize(_ledger.build()), (HERE / "results.json").read_bytes())

    def test_header(self):
        led = self.ledger
        for key in ("schemaVersion", "packet", "contractsCommit", "seeds", "rule", "golden", "cases", "summary"):
            self.assertIn(key, led)
        self.assertEqual(led["packet"], "CONF-DATA-001")
        self.assertEqual(led["contractsCommit"], load_json("contracts.json")["commit"])
        self.assertTrue(led["contractsCommit"].startswith(COMMIT_PREFIX))
        self.assertEqual(seeds_of(led["seeds"]), list(range(1, 33)))

    def test_golden_rows(self):
        rows = self.ledger["golden"]
        self.assertEqual(len(rows), 13)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(set(by_id), {v[0][:-5] for v in VECTORS})
        for name, family, *_rest in VECTORS:
            expect = _rest[-1]
            row = by_id[name[:-5]]
            with self.subTest(vector=name):
                self.assertEqual(row["family"], family)
                self.assertEqual(row["expect"], expect)
                # "pinned": the golden bytes match their pin (a flag), or the pinned expect.
                self.assertIn(row["pinned"], (True, expect))
                self.assertEqual(row["judged"], expect)
                self.assertIs(row["agree"], True)
        # Condition 1: the R12 extensions are never conformance to the 13 vectors.
        self.assertFalse(set(by_id) & EXTENSION_CASES)

    def test_case_rows_and_arm_counts(self):
        runs = all_runs()
        rows = self.ledger["cases"]
        self.assertEqual([row["id"] for row in rows], CATALOGUE_IDS)
        for row in rows:
            case = CASE_BY_ID[row["id"]]
            with self.subTest(case=row["id"]):
                for key in ("family", "parity", "provisional", "expectedArmsBy"):
                    self.assertEqual(row[key], case[key])
                self.assertEqual(set(row["crashPoints"]), set(case["crashPoints"]))
                self.assertIn(row["result"], ("PASS", "PASSED", True))
                self.assertEqual([a["name"] for a in row["arms"]], [a["name"] for a in case["arms"]])
                for arm, spec in zip(row["arms"], case["arms"]):
                    rs = [runs[(row["id"], arm["name"], s)] for s in _sim.SEEDS]
                    verdicts = [_judge.judge(r["trace"]) for r in rs]
                    self.assertEqual(arm["kind"], spec["kind"])
                    self.assertEqual(arm["code"], spec["code"])
                    self.assertEqual(arm["floor"], spec["floor"])
                    self.assertEqual(arm["runs"], 32)
                    self.assertEqual(arm["errored"], 0)
                    self.assertEqual(arm["broken"], sum(r["broken"] for r in rs))
                    self.assertEqual(arm["violations"], sum(r["violation"] for r in rs))
                    refused = sum(v != ACCEPT for v in verdicts)
                    if isinstance(arm["refusals"], dict):  # refusals by code
                        self.assertLessEqual(set(arm["refusals"]), {CODE_OF[case["family"]]})
                        self.assertEqual(sum(arm["refusals"].values()), refused)
                    else:
                        self.assertEqual(arm["refusals"], refused)
                    self.assertEqual(arm["agreements"],
                                     sum(v == r["trace"]["expect"] for v, r in zip(verdicts, rs)))
                    self.assertEqual(arm["agreements"], 32)
                    self.assertEqual(arm["violationWithoutBreak"], 0)
                    self.assertIs(arm["gate"], True)
                    self.assertEqual(len(arm["traceDigest"]), 64)
                    if spec["kind"] == "DEFENDED":
                        self.assertEqual((arm["broken"], arm["violations"], refused), (0, 0, 0))
                    else:
                        self.assertGreaterEqual(arm["violations"], spec["floor"])

    def test_summary(self):
        s = self.ledger["summary"]
        self.assertEqual(s["cases"], 29)
        self.assertEqual(s["casesPassed"], 29)
        self.assertEqual(s["arms"], 60)
        self.assertEqual(s["runs"], 60 * 32)
        self.assertEqual(s["golden"], 13)
        self.assertEqual(s["goldenAgreed"], 13)
        ext = s["r12Extensions"]
        if isinstance(ext, int):
            self.assertEqual(ext, 3)
        else:
            self.assertEqual(set(ext), EXTENSION_CASES)

    def test_campaign_record_consumer_and_role(self):
        record = _ledger.campaign_record(self.ledger)
        consumers, roles, gate_flags = set(), [], []
        for node in walk(record):
            if not isinstance(node, dict):
                continue
            for k, v in node.items():
                lk = k.lower()
                if "consumer" in lk:
                    consumers |= flatten_strings(v)
                if lk == "role":
                    roles.append(v)
                if lk in ("gate", "isgate", "asgate") and isinstance(v, bool):
                    gate_flags.append(v)
        self.assertIn("CONF-A3-001", consumers)
        self.assertTrue(roles, "no role stated")
        for role in roles:
            self.assertIsInstance(role, str)
            self.assertIn("input", role.lower())
            self.assertNotEqual(role.strip().lower(), "gate")
        self.assertFalse(any(gate_flags), "the record is an input, not a gate")

    def test_campaign_record_labels_r12_extensions(self):
        record = _ledger.campaign_record(self.ledger)
        for cid in sorted(EXTENSION_CASES):
            with self.subTest(case=cid):
                entries = [n for n in walk(record) if isinstance(n, dict)
                           and any(n.get(k) == cid for k in ("id", "case", "caseId"))]
                self.assertTrue(entries, "no entry names " + cid)
                labelled = [n for n in entries
                            if "R12_EXTENSION" in flatten_strings(n)
                            and n.get("provisional") is True and n.get("expectedArmsBy") == "R12"]
                self.assertTrue(labelled, cid + " not labelled R12_EXTENSION / provisional / R12")
                for n in entries:
                    for k, v in n.items():
                        if "conform" in k.lower() and v and not (isinstance(v, str) and
                                                                 ("not" in v.lower() or "never" in v.lower())):
                            self.fail("%s claims conformance via %s" % (cid, k))

    def test_dd04_residuals(self):
        residuals = list(_sim.RESIDUALS)
        self.assertEqual(len(residuals), 3)
        low = [r.lower() for r in residuals]
        # Section 4.9's three residuals.
        self.assertTrue(any("backup" in r and "retention" in r for r in low))
        self.assertTrue(any("export" in r for r in low))
        self.assertTrue(any("opaque" in r and "disclos" in r for r in low))
        stated = _ledger.serialize(self.ledger) + _ledger.serialize(_ledger.campaign_record(self.ledger))
        for text in residuals:
            self.assertIn(json.dumps(text)[1:-1].encode("utf-8"), stated, text)


# ---------------------------------------------------------------------------------------
# 7. The obligation matrix.
# ---------------------------------------------------------------------------------------


class ObligationMatrix(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.doc = load_json("obligations.json")

    def test_transcription_matches_record_digests(self):
        pairs = sorted([d, f] for d, fams in OBLIGATIONS for f in fams)
        self.assertEqual(hashlib.sha256(json.dumps(pairs).encode()).hexdigest(), OBLIGATION_PAIRS_SHA256)
        ids = [d for d, _ in OBLIGATIONS]
        self.assertEqual(hashlib.sha256(json.dumps(ids).encode()).hexdigest(), DEPLOYABLE_IDS_SHA256)

    def test_cells(self):
        cells = self.doc["cells"]
        self.assertEqual(len(cells), 103)
        pairs = [(c["deployable"], c["family"]) for c in cells]
        self.assertEqual(len(set(pairs)), 103, "duplicate (deployable, family) cells")
        expected = {(d, f) for d, fams in OBLIGATIONS for f in fams}
        self.assertEqual(set(pairs), expected)
        self.assertEqual({c["deployable"] for c in cells}, {d for d, _ in OBLIGATIONS})
        self.assertEqual(len({c["deployable"] for c in cells}), 24)
        counts = {}
        for c in cells:
            counts[c["family"]] = counts.get(c["family"], 0) + 1
        self.assertEqual(counts, OBLIGATIONS_BY_FAMILY)
        self.assertEqual(self.doc["byFamily"], OBLIGATIONS_BY_FAMILY)

    def test_cells_pending_and_cases_kept_apart(self):
        model_cases = {f: sorted(c for c, fam, p, *_ in CATALOGUE if fam == f and p == "MODEL_OPS")
                       for f in FAMILIES}
        ext_cases = {f: sorted(c for c, fam, p, *_ in CATALOGUE if fam == f and p == "R12_EXTENSION")
                     for f in FAMILIES}
        for c in self.doc["cells"]:
            with self.subTest(cell=(c["deployable"], c["family"])):
                self.assertEqual(c["adapterState"], "PENDING")  # section 8
                self.assertEqual(sorted(c["cases"]), model_cases[c["family"]])
                self.assertEqual(sorted(c["r12Extensions"]), ext_cases[c["family"]])
                self.assertFalse(set(c["cases"]) & set(c["r12Extensions"]))

    def test_record_pin(self):
        pin = self.doc["record"]
        self.assertEqual(pin["path"], RECORD_PATH)
        self.assertEqual(pin["sha256"], RECORD_SHA256)
        self.assertTrue(pin["commit"].startswith(COMMIT_PREFIX))


# ---------------------------------------------------------------------------------------
# 8. The design's limits: standard library only, no clock, no network, no process.
# ---------------------------------------------------------------------------------------

FORBIDDEN = {
    "time", "datetime", "zoneinfo",  # clock reads
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "poplib", "imaplib", "asyncio",
    "selectors", "select",  # network
    "subprocess", "multiprocessing", "concurrent", "threading", "signal",  # processes
    "importlib",  # dynamic imports
}
SIBLINGS = {"_judge", "_sim", "_ledger"}


class DesignLimits(unittest.TestCase):

    def test_modules_import_stdlib_only_and_read_no_clock(self):
        for name in ("_judge.py", "_sim.py", "_ledger.py"):
            tree = ast.parse((HERE / name).read_text(encoding="utf-8"))
            mods = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module:
                        mods.add(node.module.split(".")[0])
                    else:
                        mods |= {a.name for a in node.names}
                elif isinstance(node, ast.Name) and node.id == "__import__":
                    self.fail(name + " calls __import__")
            with self.subTest(module=name):
                self.assertTrue(mods <= set(sys.stdlib_module_names) | SIBLINGS, sorted(mods))
                self.assertFalse(mods & FORBIDDEN, sorted(mods & FORBIDDEN))


if __name__ == "__main__":
    unittest.main()
