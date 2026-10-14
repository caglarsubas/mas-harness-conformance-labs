"""TG-08 compatibility (W04-6, CONF-ENF-007): the case ledger, S44's properties and the catalog of every case.

tg08_compatibility/results.json must equal what _catalog.ledger gives: the plan's TG-08 cases in order and in two parts kept
apart, SOURCE and INSTALLED. S44 (offline) lists one property per item of the plan's S44 case, W02D section 4.4's rejection
list, each served by the S44 catalog rows whose basis starts with it. A property's result is what replaying its native v3
vectors through the snapshotted reference model gives in this run (owner decision Q-T20, 2026-10-14): the ledger's table
is derived from that replay, so once TG-01's native v3 replay runs, regenerating the ledger is all TG-08 needs. Today the
model cannot load without jsonschema (gap G-JSONSCHEMA, owner decision Q-T4), so every property is NOT_RUN_ENV_UNAVAILABLE;
an environment that gains jsonschema makes TG-01's replay refuse until it is written (gap G-REPLAY-INPUTS), so this
module errors instead of going stale. The three source MATRIX cases wait for W05's release set (owner decision Q-T8) and
INSTALLED for W06's hosts (D-W02A-F2); their catalogs fix the contract vectors now. The anchors and the exact selection
pins (size and digest of each id list) are a second pin on the catalog.
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
                  "from the verifier profile (gap G-JSONSCHEMA; owner decisions Q-T4 and Q-T20); TG-01 writes that replay, and "
                  "adds its inputs outside the snapshots (gap G-REPLAY-INPUTS), with the jsonschema root bundle")
REPLAY_TEST = "S44Tests.test_each_property_is_the_replay_of_its_vectors_in_this_run"
RESOLVED_SPEC = "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md"
# Vectors each selection must keep (from the vectors' own intents and refusals).
ANCHORS = {
    ("S44", NATIVE_V3, "crossVersion", _catalog.CROSS_VERSION): {"X01", "X05", "X09", "X14"},
    ("S44", NATIVE_V3, "negative", _catalog.EARLIER_NEGATIVES): {"R01", "R07", "V29"},
    ("S44", NATIVE_V3, "negative", _catalog.GATE_MISSING): {"R02"},
    ("S44", NATIVE_V3, "negative", _catalog.EXTRA_ROLE): {"R03"},
    ("S44", NATIVE_V3, "negative", _catalog.GATE_BROKER): {"R04", "R05", "R75"},
    ("S44", NATIVE_V3, "negative", _catalog.ALIAS): {"R05", "R43", "V43", "V56"},
    ("S44", NATIVE_V3, "negative", _catalog.LIFECYCLE): {"R50", "C14", "C15", "C30"},
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
    ("MATRIX:export/upgrade/rollback without nonce reuse", NATIVE_V3, "crossVersion", _catalog.ROLLED_BACK): {"X05", "X12", "X14"},
    ("MATRIX:export/upgrade/rollback without nonce reuse", I05_V3, "transcripts", _catalog.REUSED): {"T75", "T95"},
    ("MATRIX:export/upgrade/rollback without nonce reuse", I05_V3, "configRefusals", _catalog.REINTERPRET): {"K04"},
}
# Each selection exactly: (size, the first 16 hex of sha256 over its ids joined by newlines).
SELECTION_PINS = {
    ("S44", NATIVE_V3, "crossVersion", _catalog.CROSS_VERSION): (14, "c4ef58d91d19474c"),
    ("S44", NATIVE_V3, "negative", _catalog.EARLIER_NEGATIVES): (4, "c08b423502740a84"),
    ("S44", NATIVE_V3, "negative", _catalog.GATE_MISSING): (1, "c719df3d28484a1a"),
    ("S44", NATIVE_V3, "negative", _catalog.EXTRA_ROLE): (1, "721ba03d5fe40ec7"),
    ("S44", NATIVE_V3, "negative", _catalog.GATE_BROKER): (4, "075bba575abf4a4f"),
    ("S44", NATIVE_V3, "negative", _catalog.ALIAS): (8, "610fd93b4848492b"),
    ("S44", NATIVE_V3, "negative", _catalog.LIFECYCLE): (5, "14b2f6df67d4d4c1"),
    ("S44", NATIVE_V3, "negative", _catalog.BACKEND_KEYS): (1, "2cb41c1f89daac49"),
    ("MATRIX:old profile rejection", NATIVE_V3, "crossVersion", _catalog.OLD_RECORDS): (14, "c4ef58d91d19474c"),
    ("MATRIX:old profile rejection", NATIVE_V3, "negative", _catalog.OLD_RECORDS): (4, "c08b423502740a84"),
    ("MATRIX:old profile rejection", I06_V2, "vectors", _catalog.OLD_I06): (8, "bc47797ec83d5abb"),
    ("MATRIX:old profile rejection", I05_V3, "frames", _catalog.OLD_I05): (3, "d3da2ddb291a4909"),
    ("MATRIX:old profile rejection", I05_V3, "configRefusals", _catalog.OLD_I05): (1, "51921225f9b265dd"),
    ("MATRIX:new profile missing gate/backend", NATIVE_V3, "negative", _catalog.MISSING): (8, "368145d4f2e9429b"),
    ("MATRIX:new profile missing gate/backend", NATIVE_V3, "negative", _catalog.GATE_BROKER): (4, "075bba575abf4a4f"),
    ("MATRIX:new profile missing gate/backend", I06_V2, "vectors", _catalog.MISSING_I06): (4, "0dc092c6a1602dea"),
    ("MATRIX:export/upgrade/rollback without nonce reuse", NATIVE_V3, "migration", _catalog.MIGRATION): (14, "cb52b5b61264c027"),
    ("MATRIX:export/upgrade/rollback without nonce reuse", NATIVE_V3, "crossVersion", _catalog.ROLLED_BACK): (7, "5b3e776637e2f2af"),
    ("MATRIX:export/upgrade/rollback without nonce reuse", I05_V3, "transcripts", _catalog.REUSED): (3, "f9bf7e1125cb1476"),
    ("MATRIX:export/upgrade/rollback without nonce reuse", I05_V3, "configRefusals", _catalog.REINTERPRET): (1, "51921225f9b265dd"),
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
    """The S44 property a row serves: the one its basis starts with, followed by ': '."""
    owners = [name for name in _catalog.S44_PROPERTIES if basis.startswith(name + ": ")]
    return owners[0] if len(owners) == 1 else None


def property_ids():
    """Each S44 property's native v3 vector ids, from the S44 rows that serve it."""
    found = {name: [] for name in _catalog.S44_PROPERTIES}
    for (case, _, _, basis), ids in selections().items():
        if case == "S44":
            found[property_of(basis)].extend(ids)
    return found


def replayed_properties():
    """S44's property table as replaying its vectors gives it in this run (owner decision Q-T20): a property is PASS only
    when every one of its vectors replayed and passed, and then names the test that checks this."""
    passed = set(_replays.native_v3_vectors().ids["PASS"])
    rows = []
    for name, ids in property_ids().items():
        ok = bool(ids) and set(ids) <= passed
        rows.append({"property": name, "source": _catalog.S44_SOURCE, "result": "PASS" if ok else "NOT_RUN_ENV_UNAVAILABLE",
                     "reason": None if ok else NOT_RUN_REASON, "tests": [REPLAY_TEST] if ok else [], "carriedBy": []})
    return rows


def spec_section(relative):
    text = _models.snapshot_bytes(relative).decode("utf-8")
    return text[text.index("### 4.4 Rejection vectors"):text.index("## 5. ")]


class LedgerTests(unittest.TestCase):
    def test_the_ledger_is_the_plans_cases_with_their_parts_catalog_and_properties(self):
        self.assertEqual(ledger(), _catalog.ledger(GROUP, {"S44": replayed_properties()}))

    def test_the_source_and_installed_parts_are_kept_apart(self):
        rows = ledger()["cases"]
        self.assertEqual([(row["tag"], row["part"]) for row in rows],
                         [("S44", "SOURCE")] + [(tag, "SOURCE") for tag in SOURCE_CASES] + [("INSTALLED", "INSTALLED")])
        # The installed case repeats exactly the source MATRIX cases' contract rows, on the enrolled hosts in W06.
        source = [item for row in rows if row["tag"] in SOURCE_CASES for item in row["catalog"]]
        installed = next(row for row in rows if row["tag"] == "INSTALLED")
        self.assertEqual(installed["catalog"], source)
        self.assertEqual((installed["phase"], installed["blockedBy"]), ("W06_NATIVE_ONLY", ["D-W02A-F2"]))

    def test_s44_names_the_reference_model_as_its_subject(self):
        # Review D1-2: Q-T9's subject (R12's reader) is LEDGER-E09's; S44's evidence is the contract model's replay.
        s44 = next(row for row in ledger()["cases"] if row["tag"] == "S44")
        self.assertEqual(s44["subject"], _catalog.CASE_SUBJECTS[(GROUP, "S44")])
        self.assertNotIn("live_proxy_server", s44["subject"])
        # Review R1-5: the source cases test W05's build on its records, evidence and frames; INSTALLED keeps W06's subject.
        subjects = {row["tag"]: row["subject"] for row in ledger()["cases"]}
        for tag in SOURCE_CASES:
            self.assertEqual(subjects[tag], _catalog.CASE_SUBJECTS[(GROUP, tag)])
        self.assertEqual(subjects["INSTALLED"], _catalog.SUBJECTS["W06_NATIVE_ONLY"])

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
        # Owner decision Q-T20: every vector a property names was replayed (none skipped), and the property is PASS only
        # when all of them passed.
        tally = _replays.native_v3_vectors().ids
        properties = {row["property"]: row for row in next(row for row in ledger()["cases"] if row["tag"] == "S44")["properties"]}
        self.assertEqual(list(properties), list(_catalog.S44_PROPERTIES))
        for name, ids in property_ids().items():
            with self.subTest(property=name):
                self.assertTrue(ids)
                self.assertLessEqual(set(ids), set(tally["PASS"]) | set(tally["NOT_RUN_ENV_UNAVAILABLE"]))
                self.assertEqual(properties[name]["result"] == "PASS", set(ids) <= set(tally["PASS"]))

    def test_the_s44_evidence_is_only_the_replay_test(self):
        # A PASS property names the replay test above, which this module runs; nothing else counts as S44's evidence.
        s44 = next(row for row in ledger()["cases"] if row["tag"] == "S44")
        self.assertLessEqual(set(s44["evidence"]), {REPLAY_TEST})
        self.assertTrue(hasattr(S44Tests, REPLAY_TEST.split(".", 1)[1]))

    def test_every_s44_row_serves_one_property_and_every_property_has_rows(self):
        for (case, contract, _, basis), ids in selections().items():
            if case == "S44":
                with self.subTest(basis=basis[:60]):
                    self.assertEqual(contract, NATIVE_V3)
                    self.assertIsNotNone(property_of(basis))
        self.assertTrue(all(property_ids().values()))

    def test_the_properties_are_the_items_of_the_plans_s44_case(self):
        # Review D1-4: one property per item of the plan's S44 case text, in its order.
        plan_group = next(row for row in _models.data(_catalog.PLAN)["testGroups"] if row["id"] == GROUP)
        text = next(case["case"] for case in plan_group["cases"] if case["tag"] == "S44")
        self.assertTrue(all(name.startswith("a record ") and name.endswith(" refuses") for name in _catalog.S44_PROPERTIES[1:]))
        items = [_catalog.S44_VERSION] + [name[len("a record "):-len(" refuses")] for name in _catalog.S44_PROPERTIES[1:]]
        for item in items:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(sorted(items, key=text.index), items)

    def test_section_4_4_is_the_same_in_the_plans_source_and_w02d_and_places_migration_elsewhere(self):
        # Review D1-11: the plan cites the resolved spec, S44's source also names W02D's; the two sections are identical.
        self.assertEqual(spec_section(RESOLVED_SPEC), spec_section(_catalog.W02D_SPEC))
        section = " ".join(spec_section(_catalog.W02D_SPEC).split())
        for phrase in ("refuses (no fallback)", "missing EFFECT_GATE", "has an extra role", "under the BROKER key or path",
                       "aliases a role path", "lifecycle subject running inside a resident role cgroup",
                       "unknown backendComponents keys refuses"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, section)
        # 4.4's migration sentence is MATRIX:export/upgrade/rollback's, as the plan places it.
        self.assertIn("never reuses a v1 generation or nonce", section)
        self.assertIn("never reuses a v1 generation or nonce", _catalog.MIGRATION)


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

    def test_the_path_rules_select_path_fields_set_to_another_roles_value(self):
        vectors = _models.data(_catalog.NAT + "vectors.json")
        rows = {row["id"]: row for row in vectors["negative"]}
        aliased = set(_catalog._aliased_path(vectors))
        for ident in _catalog._gate_under_broker(vectors):
            row = rows[ident]
            roles = vectors["positive"][row["positive"]]["record"]["roles"]
            with self.subTest(vector=ident):
                self.assertEqual(row["target"], "record")
                self.assertIn(ident, aliased)
                self.assertTrue(any(op["path"][1] in _catalog.GATE_AND_BROKER and op["value"].startswith("/")
                                    and _replays._at(roles[_catalog.GATE_AND_BROKER[op["path"][1]]], op["path"][2:]) == op["value"]
                                    for op in row["ops"] if op["op"] == "set" and len(op["path"]) >= 3))

    def test_the_lifecycle_rule_selects_lifecycle_subjects_in_resident_role_cgroups(self):
        vectors = _models.data(_catalog.NAT + "vectors.json")
        rows = {row["id"]: row for row in vectors["negative"]}
        for ident in _catalog._lifecycle_in_role_cgroup(vectors):
            row = rows[ident]
            with self.subTest(vector=ident):
                if row["target"] != "capture":
                    self.assertIn(row["refusal"], _catalog.LIFECYCLE_SCHEMA)
                    continue
                labels = {subject["processLabel"] for subject in
                          vectors["positive"][row["positive"]]["record"]["lifecycleSubjects"].values()}
                values = [op["value"].get("processLabel") if type(op["value"]) is dict else op["value"] for op in row["ops"]]
                self.assertTrue(set(values) & labels)


if __name__ == "__main__":
    unittest.main()
