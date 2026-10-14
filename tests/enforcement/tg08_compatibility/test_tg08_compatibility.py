"""TG-08 compatibility (W04-6, CONF-ENF-007): the case ledger, S44's properties and the catalog of every case.

tg08_compatibility/results.json must equal what _catalog.ledger gives: the plan's TG-08 cases in order and in two parts kept
apart, SOURCE and INSTALLED. S44 (offline) lists one property per sentence of W02D section 4.4, each served by the
catalog rows whose basis starts with it; a property's result is what replaying its native v3 vectors through the
snapshotted reference model gives in this run (owner decision Q-T20, 2026-10-14). The native v3 model imports jsonschema,
which the verifier profile lacks (gap G-JSONSCHEMA, owner decision Q-T4), so every property is NOT_RUN_ENV_UNAVAILABLE
here; an environment that gains jsonschema fails here (TG-01's replay refuses until it is written), so the ledger is
redone, never stale. The three source MATRIX cases wait for W05's release set (owner decision Q-T8) and INSTALLED for W06's
hosts (D-W02A-F2); their catalogs fix the contract vectors now. The anchors and the exact selection pins (size and digest
of each id list) are a second pin on the catalog.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

import _catalog
import _models
from tg01_contract import _replays

HERE = Path(__file__).resolve().parent
GROUP = "TG-08"
NATIVE_V3, I06_V2, I05_V3 = "Native qualification profile v3", "I06 backend profile v2", "I05 gate channel v3"
NOT_RUN_REASON = ("its vectors replay through the native qualification v3 reference model, which imports jsonschema, absent "
                  "from the verifier profile (gap G-JSONSCHEMA; owner decisions Q-T4 and Q-T20); the replay is written, and "
                  "its inputs outside the snapshots are added (gap G-REPLAY-INPUTS), with the jsonschema root bundle")
PROPERTIES = [{"property": name, "source": _catalog.S44_SOURCE, "result": "NOT_RUN_ENV_UNAVAILABLE", "reason": NOT_RUN_REASON,
               "tests": [], "carriedBy": []} for name in _catalog.S44_PROPERTIES]
# Vectors each selection must keep (from the vectors' own intents and refusals).
ANCHORS = {
    ("S44", NATIVE_V3, "crossVersion", _catalog.CROSS_VERSION): {"X01", "X05", "X09", "X14"},
    ("S44", NATIVE_V3, "negative", _catalog.EARLIER_NEGATIVES): {"R01", "R07"},
    ("S44", NATIVE_V3, "negative", _catalog.GATE_MISSING): {"R02"},
    ("S44", NATIVE_V3, "negative", _catalog.EXTRA_ROLE): {"R03"},
    ("S44", NATIVE_V3, "negative", _catalog.GATE_BROKER): {"R04", "R05", "R75"},
    ("S44", NATIVE_V3, "negative", _catalog.ALIAS): {"R43", "V43", "V56"},
    ("S44", NATIVE_V3, "negative", _catalog.LIFECYCLE): {"R50", "R51"},
    ("S44", NATIVE_V3, "negative", _catalog.BACKEND_KEYS): {"R55"},
    ("MATRIX:old profile rejection", NATIVE_V3, "crossVersion", _catalog.OLD_RECORDS): {"X01", "X05", "X09", "X14"},
    ("MATRIX:old profile rejection", NATIVE_V3, "negative", _catalog.OLD_RECORDS): {"R01"},
    ("MATRIX:old profile rejection", I06_V2, "vectors", _catalog.OLD_I06): {"G03", "G17", "X01"},
    ("MATRIX:old profile rejection", I05_V3, "frames", _catalog.OLD_I05): {"G10", "G34"},
    ("MATRIX:old profile rejection", I05_V3, "configRefusals", _catalog.OLD_I05): {"K04"},
    ("MATRIX:new profile missing gate/backend", NATIVE_V3, "negative", _catalog.MISSING): {"R02", "R55", "R56", "Q01", "Q02"},
    ("MATRIX:new profile missing gate/backend", NATIVE_V3, "negative", _catalog.GATE_BROKER): {"R04", "R05", "R75"},
    ("MATRIX:new profile missing gate/backend", I06_V2, "vectors", _catalog.MISSING_I06): {"E70", "E71"},
    ("MATRIX:export/upgrade/rollback without nonce reuse", NATIVE_V3, "migration", _catalog.MIGRATION): {"M02", "M03", "M04", "M11"},
}
# Each selection exactly: (size, the first 16 hex of sha256 over its ids joined by newlines).
SELECTION_PINS = {
    ("S44", NATIVE_V3, "crossVersion", _catalog.CROSS_VERSION): (14, "c4ef58d91d19474c"),
    ("S44", NATIVE_V3, "negative", _catalog.EARLIER_NEGATIVES): (3, "cbde293be2621ba8"),
    ("S44", NATIVE_V3, "negative", _catalog.GATE_MISSING): (1, "c719df3d28484a1a"),
    ("S44", NATIVE_V3, "negative", _catalog.EXTRA_ROLE): (1, "721ba03d5fe40ec7"),
    ("S44", NATIVE_V3, "negative", _catalog.GATE_BROKER): (4, "075bba575abf4a4f"),
    ("S44", NATIVE_V3, "negative", _catalog.ALIAS): (6, "f0694795401245dc"),
    ("S44", NATIVE_V3, "negative", _catalog.LIFECYCLE): (2, "757d2c7bac5c7e15"),
    ("S44", NATIVE_V3, "negative", _catalog.BACKEND_KEYS): (1, "2cb41c1f89daac49"),
    ("MATRIX:old profile rejection", NATIVE_V3, "crossVersion", _catalog.OLD_RECORDS): (14, "c4ef58d91d19474c"),
    ("MATRIX:old profile rejection", NATIVE_V3, "negative", _catalog.OLD_RECORDS): (3, "cbde293be2621ba8"),
    ("MATRIX:old profile rejection", I06_V2, "vectors", _catalog.OLD_I06): (8, "bc47797ec83d5abb"),
    ("MATRIX:old profile rejection", I05_V3, "frames", _catalog.OLD_I05): (3, "d3da2ddb291a4909"),
    ("MATRIX:old profile rejection", I05_V3, "configRefusals", _catalog.OLD_I05): (1, "51921225f9b265dd"),
    ("MATRIX:new profile missing gate/backend", NATIVE_V3, "negative", _catalog.MISSING): (8, "368145d4f2e9429b"),
    ("MATRIX:new profile missing gate/backend", NATIVE_V3, "negative", _catalog.GATE_BROKER): (4, "075bba575abf4a4f"),
    ("MATRIX:new profile missing gate/backend", I06_V2, "vectors", _catalog.MISSING_I06): (4, "0dc092c6a1602dea"),
    ("MATRIX:export/upgrade/rollback without nonce reuse", NATIVE_V3, "migration", _catalog.MIGRATION): (14, "cb52b5b61264c027"),
}
SOURCE_CASES = ("MATRIX:old profile rejection", "MATRIX:new profile missing gate/backend",
                "MATRIX:export/upgrade/rollback without nonce reuse")
I06_SETS = ("evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative", "crossVersion")


def ledger():
    return _models._strict(_models._regular(HERE / "results.json"))


def pin(ids):
    return len(ids), hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]


def set_ids(contract, vector_set):
    if contract == I06_V2:
        vectors = _models.data(_catalog.I06 + "vectors.json")
        return [row["id"] for key in I06_SETS for row in vectors[key]]
    prefix = {NATIVE_V3: _catalog.NAT, I05_V3: _catalog.I05}[contract]
    return [row["id"] for row in _models.data(prefix + "vectors.json")[vector_set]]


def selections():
    return {(row["case"], row["contract"], row["vectorSet"], row["basis"]): row["ids"] for row in _catalog.catalog(GROUP)}


def property_of(basis):
    """The S44 property a catalog row serves: the one its basis starts with, followed by ': '."""
    owners = [name for name in _catalog.S44_PROPERTIES if basis.startswith(name + ": ")]
    return owners[0] if len(owners) == 1 else None


def replayed_properties():
    """Each S44 property as replaying its native v3 vectors gives it in this run: PASS only when every vector passed."""
    tally = _replays.native_v3_vectors().ids
    results = []
    for name in _catalog.S44_PROPERTIES:
        ids = [ident for (case, _, _, basis), selected in selections().items() if case == "S44" and property_of(basis) == name
               for ident in selected]
        passed = bool(ids) and set(ids) <= set(tally["PASS"])
        results.append({"property": name, "source": _catalog.S44_SOURCE, "result": "PASS" if passed else "NOT_RUN_ENV_UNAVAILABLE",
                        "reason": None if passed else NOT_RUN_REASON, "tests": [], "carriedBy": []})
    return results


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_the_plans_cases_with_their_parts_catalog_and_properties(self):
        self.assertEqual(ledger(), _catalog.ledger(GROUP, {"S44": PROPERTIES}))

    def test_the_source_and_installed_parts_are_kept_apart(self):
        rows = ledger()["cases"]
        self.assertEqual([(row["tag"], row["part"]) for row in rows],
                         [("S44", "SOURCE")] + [(tag, "SOURCE") for tag in SOURCE_CASES] + [("INSTALLED", "INSTALLED")])
        # The installed case repeats exactly the source MATRIX cases' contract rows, on the enrolled hosts in W06.
        source = [item for row in rows if row["tag"] in SOURCE_CASES for item in row["catalog"]]
        installed = next(row for row in rows if row["tag"] == "INSTALLED")
        self.assertEqual(installed["catalog"], source)
        self.assertEqual((installed["phase"], installed["blockedBy"]), ("W06_NATIVE_ONLY", ["D-W02A-F2"]))

    def test_no_case_passes_before_its_subject_exists_or_while_a_property_was_not_run(self):
        for row in ledger()["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual(row["result"] == "PASS", row["phase"] == "W04_OFFLINE" and bool(row["properties"])
                                 and all(item["result"] == "PASS" for item in row["properties"]))
                self.assertEqual(row["reason"] is None, row["result"] == "PASS")
                self.assertTrue(row["catalog"])
                self.assertEqual(bool(row["properties"]), row["tag"] == "S44")


class S44Tests(unittest.TestCase):
    def test_each_property_is_the_replay_of_its_vectors_in_this_run(self):
        # Owner decision Q-T20: no property is PASS unless every vector it names replayed and passed here.
        self.assertEqual(replayed_properties(), PROPERTIES)

    def test_every_s44_row_serves_one_property_and_every_property_has_rows(self):
        served = {}
        for (case, contract, _, basis), ids in selections().items():
            if case != "S44":
                continue
            with self.subTest(basis=basis):
                self.assertEqual(contract, NATIVE_V3)
                self.assertIsNotNone(property_of(basis))
                served.setdefault(property_of(basis), []).extend(ids)
        self.assertEqual(set(served), set(_catalog.S44_PROPERTIES))
        self.assertTrue(all(served.values()))

    def test_the_properties_are_the_sentences_of_section_4_4(self):
        text = _models.snapshot_bytes(_catalog.W02D_SPEC).decode("utf-8")
        # The section's words with its line breaks folded, so a phrase may span lines.
        section = " ".join(text[text.index("### 4.4 Rejection vectors"):text.index("## 5. ")].split())
        for phrase in ("refuses (no fallback)", "missing EFFECT_GATE", "has an extra role", "under the BROKER key or path",
                       "aliases a role path", "lifecycle subject running inside a resident role cgroup",
                       "unknown backendComponents keys refuses", "never reuses a v1 generation or nonce"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, section)


class CatalogTests(unittest.TestCase):
    def test_every_selection_is_pinned_and_names_real_vectors(self):
        found = selections()
        # The installed case's rows are the source MATRIX cases' rows (same contract, set and basis), pinned through them.
        source_keys = {key[1:]: key for key in ANCHORS if key[0] in SOURCE_CASES}
        self.assertEqual(set(found), set(ANCHORS) | {("INSTALLED",) + rest for rest in source_keys})
        own = {key: ids for key, ids in found.items() if key[0] != "INSTALLED"}
        self.assertEqual({key: pin(ids) for key, ids in own.items()}, SELECTION_PINS)
        for key, ids in found.items():
            with self.subTest(selection=key[:3]):
                self.assertLessEqual(ANCHORS[source_keys[key[1:]] if key[0] == "INSTALLED" else key], set(ids))
                self.assertEqual(len(set(ids)), len(ids))
                self.assertLessEqual(set(ids), set(set_ids(key[1], key[2])))

    def test_the_gate_and_broker_rule_selects_path_fields_set_to_the_other_roles_value(self):
        vectors = _models.data(_catalog.NAT + "vectors.json")
        rows = {row["id"]: row for row in vectors["negative"]}
        for ident in _catalog._gate_under_broker(vectors):
            row = rows[ident]
            roles = vectors["positive"][row["positive"]]["record"]["roles"]
            with self.subTest(vector=ident):
                self.assertEqual(row["target"], "record")
                self.assertTrue(any(op["path"][1] in ("EFFECT_GATE", "BROKER") and op["value"].startswith("/")
                                    and _replays._at(roles[_catalog.GATE_AND_BROKER[op["path"][1]]], op["path"][2:]) == op["value"]
                                    for op in row["ops"] if op["op"] == "set" and len(op["path"]) >= 3))


if __name__ == "__main__":
    unittest.main()
