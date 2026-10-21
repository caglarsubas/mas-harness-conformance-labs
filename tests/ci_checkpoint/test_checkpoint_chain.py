"""CONF-ENF-001: R12's registry-pinned checkpoint chain (owner decision Q-T3 = (a), 2026-10-11).

fixtures/ci/checkpoints.json registers CONF-CI-002's record as entry 0 and one closed record per later packet. The records
are checked newest first against the git tree and projected away in turn, down to the CONF-CI-002 head view that
CONF-CI-002's layer and tests read; the chain adds nothing to that view.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("checkpoint_chain_successor_inventory",
                                              ROOT / "tests/platform/linux_baseline/_successor_inventory.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
CI_002_HEAD = "029abe70acae5286a3fd0e943d71a0f081b857e0"
ENF_001_RECORD = "fixtures/ci/conf-enf-001-checkpoint.json"
ENF_001_CHANGED = {"tests/platform/linux_baseline/_successor_inventory.py", "tests/live_backend/_inventory.py"}
ENF_001_ADDED_OUTSIDE_AREA = {"task-packets/CONF-ENF-001.yaml", "tests/ci_checkpoint/test_checkpoint_chain.py"}
ENF_001_DECISIONS = ["Q-T1", "Q-T2", "Q-T3"]
CI_002_VIEW_FILES = 140
ENF_001_HEAD = "83d2c55c4499163ad00113cfe260a2005ccdb7c9"
ENF_002_RECORD = "fixtures/ci/conf-enf-002-checkpoint.json"
ENF_002_CHANGED = {"tests/enforcement/README.md", "tests/enforcement/snapshots/manifest.json", "tests/enforcement/test_bootstrap.py",
                   "tests/enforcement/toolchains.json", "tests/ci_checkpoint/test_checkpoint_chain.py"}
ENF_002_ADDED_OUTSIDE_AREA = {"task-packets/CONF-ENF-002.yaml"}
ENF_002_DECISIONS = ["Q-T4", "Q-T5", "Q-T6", "Q-T7"]
ENF_002_HEAD = "21ae371291b20056094cedfff11a31415c947495"
ENF_003_RECORD = "fixtures/ci/conf-enf-003-checkpoint.json"
ENF_003_CHANGED = {"tests/enforcement/README.md", "tests/enforcement/snapshots/manifest.json", "tests/enforcement/test_bootstrap.py",
                   "tests/enforcement/tg01_contract/_replays.py", "tests/enforcement/tg01_contract/results.json",
                   "tests/enforcement/tg01_contract/test_tg01_contract.py", "tests/ci_checkpoint/test_checkpoint_chain.py"}
ENF_003_ADDED_OUTSIDE_AREA = {"task-packets/CONF-ENF-003.yaml"}
ENF_003_DECISIONS = ["Q-T8", "Q-T9", "Q-T10", "Q-T11"]
ENF_003_HEAD = "25f38a51144e1b6a9042b52a75cca5b3c3bc13d6"
ENF_004_RECORD = "fixtures/ci/conf-enf-004-checkpoint.json"
ENF_004_CHANGED = {"tests/enforcement/README.md", "tests/enforcement/snapshots/manifest.json", "tests/enforcement/test_bootstrap.py",
                   "tests/enforcement/toolchains.json", "tests/enforcement/_catalog.py", "tests/ci_checkpoint/test_checkpoint_chain.py"}
ENF_004_DECISIONS = ["Q-T2-B", "Q-T2-TOOL", "Q-T12", "Q-T13", "Q-T14", "Q-T15", "Q-T16"]
# CONF-ENF-004 adds the native probe source outside the enforcement area (W04-4a; owner decision Q-T2-B).
ENF_004_PROBE_FILES = 20
ENF_004_HEAD = "09a765231bc7d215aba6c9777dc33bf51182a1e6"
# CONF-ENF-007 (W04-6, TG-08) follows CONF-ENF-004: W04-4b and W04-4c (CONF-ENF-005, CONF-ENF-006) stay open (owner
# decision RESUME-2, 2026-10-14).
ENF_007_RECORD = "fixtures/ci/conf-enf-007-checkpoint.json"
ENF_007_CHANGED = {"tests/enforcement/README.md", "tests/enforcement/test_bootstrap.py", "tests/enforcement/_catalog.py",
                   "tests/ci_checkpoint/test_checkpoint_chain.py"}
ENF_007_DECISIONS = ["RESUME-2", "Q-T20", "Q-T21", "Q-T20-ACK"]
ENF_007_HEAD = "094b5539395d83a1b57e0e65881aa1b063a01b05"
# CONF-ENF-009 (W04, the jsonschema ledger conversion; owner decisions Q-LC-1..4, 2026-10-18) follows CONF-ENF-007; it adds
# the eight G-REPLAY-INPUTS snapshots and the TG-01 child process. CONF-ENF-005, -006 and -008 stay reserved (Q-LC-3).
ENF_009_RECORD = "fixtures/ci/conf-enf-009-checkpoint.json"
ENF_009_CHANGED = {"tests/ci_checkpoint/test_checkpoint_chain.py",
                   "tests/enforcement/README.md",
                   "tests/enforcement/_catalog.py",
                   "tests/enforcement/snapshots/manifest.json",
                   "tests/enforcement/test_bootstrap.py",
                   "tests/enforcement/tg01_contract/_replays.py",
                   "tests/enforcement/tg01_contract/results.json",
                   "tests/enforcement/tg01_contract/test_tg01_contract.py",
                   "tests/enforcement/tg08_compatibility/results.json",
                   "tests/enforcement/tg08_compatibility/test_tg08_compatibility.py",
                   "tests/enforcement/toolchains.json"}
ENF_009_DECISIONS = ["Q-LC-1", "Q-LC-2", "Q-LC-3", "Q-LC-4"]
ENF_009_SNAPSHOTS = {"architecture/i06-backend-profile/vectors.json", "architecture/i06-backend-profile/writer-inventory.json",
                     "architecture/i06-backend-profile/identity-closure.json",
                     "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
                     "architecture/native-profile-v2/vectors.json", "architecture/native-profile-v2/qualification.schema.json",
                     "architecture/native-qualification-inputs/qualification.schema.json",
                     "architecture/native-qualification-inputs/vectors.json"}
ENF_009_HEAD = "d024a03ac664189e6b6e004e8a44e440841747cd"
# CONF-MAS-001 (MAS-RA-010 packet 1; owner decisions Q-NX-1..6, Q-MAS1-1..3, Q-MAS1-REV2 and Q-MAS1-F1, 2026-10-19)
# follows CONF-ENF-009; it adds the tests/mas simulation area and acceptance argv 14, and changes only this test.
MAS_001_RECORD = "fixtures/ci/conf-mas-001-checkpoint.json"
MAS_001_CHANGED = {"tests/ci_checkpoint/test_checkpoint_chain.py"}
MAS_001_ADDED = {"task-packets/CONF-MAS-001.yaml",
                 "tests/mas/README.md",
                 "tests/mas/_classes.py",
                 "tests/mas/_ledger.py",
                 "tests/mas/_sim.py",
                 "tests/mas/attestation.json",
                 "tests/mas/classes.json",
                 "tests/mas/contracts.json",
                 "tests/mas/results.json",
                 "tests/mas/test_classes.py",
                 "tests/mas/test_extractors.py",
                 "tests/mas/test_ledger.py",
                 "tests/mas/test_sim.py"}
MAS_001_DECISIONS = ["Q-NX-1", "Q-NX-2", "Q-NX-3", "Q-NX-4", "Q-NX-5", "Q-NX-6", "Q-MAS1-1", "Q-MAS1-2", "Q-MAS1-3",
                     "Q-MAS1-REV2", "Q-MAS1-F1"]
MAS_001_HEAD = "05b74ff0e778f23faab1281731afa7f7b1fed85f"
# CONF-MAS-002 (MAS-RA-010 packet 2, the security half; owner decisions Q-NX2-1..6, 2026-10-19, and Q3-2, Q-C5-LANE and
# Q-R8-CAP, 2026-10-20) follows CONF-MAS-001; it changes packet 1's tests/mas files and this test, and adds three
# tests/mas test files and its packet YAML. Acceptance argv 14 is unchanged.
MAS_002_RECORD = "fixtures/ci/conf-mas-002-checkpoint.json"
MAS_002_CHANGED = {"tests/ci_checkpoint/test_checkpoint_chain.py",
                   "tests/mas/README.md",
                   "tests/mas/_classes.py",
                   "tests/mas/_ledger.py",
                   "tests/mas/_sim.py",
                   "tests/mas/attestation.json",
                   "tests/mas/classes.json",
                   "tests/mas/contracts.json",
                   "tests/mas/results.json",
                   "tests/mas/test_classes.py",
                   "tests/mas/test_ledger.py",
                   "tests/mas/test_sim.py"}
MAS_002_ADDED = {"task-packets/CONF-MAS-002.yaml",
                 "tests/mas/test_oracle_p2.py",
                 "tests/mas/test_p2_classes.py",
                 "tests/mas/test_p2_rules.py"}
MAS_002_DECISIONS = ["Q-NX2-1", "Q-NX2-2", "Q-NX2-3", "Q-NX2-4", "Q-NX2-5", "Q-NX2-6", "Q3-2", "Q-C5-LANE", "Q-R8-CAP"]
MAS_002_HEAD = "c672aad56960b33a3e6d281aa484c7ac507293aa"
# CONF-MAS-003 (MAS-RA-010 packet 3, the resilience half; owner decisions Q-NX3-1..6, Q-D3-1 and Q-R5-CAP, 2026-10-20)
# follows CONF-MAS-002; it changes packets 1 and 2's tests/mas files and this test, and adds three tests/mas test files,
# the packet-3 attestation, the CONF-A3-001 campaign record and its packet YAML. Acceptance argv 14 is unchanged.
MAS_003_RECORD = "fixtures/ci/conf-mas-003-checkpoint.json"
MAS_003_CHANGED = {"tests/ci_checkpoint/test_checkpoint_chain.py",
                   "tests/mas/README.md",
                   "tests/mas/_classes.py",
                   "tests/mas/_ledger.py",
                   "tests/mas/_sim.py",
                   "tests/mas/classes.json",
                   "tests/mas/contracts.json",
                   "tests/mas/results.json",
                   "tests/mas/test_classes.py",
                   "tests/mas/test_ledger.py",
                   "tests/mas/test_oracle_p2.py"}
MAS_003_ADDED = {"task-packets/CONF-MAS-003.yaml",
                 "tests/mas/attestation-p3.json",
                 "tests/mas/campaign-record.json",
                 "tests/mas/test_oracle_p3.py",
                 "tests/mas/test_p3_classes.py",
                 "tests/mas/test_p3_rules.py"}
MAS_003_DECISIONS = ["Q-NX3-1", "Q-NX3-2", "Q-NX3-3", "Q-NX3-4", "Q-NX3-5", "Q-NX3-6", "Q-D3-1", "Q-R5-CAP"]


def head():
    return HELPER.head_tracked_inventory(ROOT)


def entries():
    return HELPER.chain_registry(*head())


def enf_001():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=2)
    return HELPER.chain_record(entries()[:2], 1, sources), rows, sources


def enf_002():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=3)
    return HELPER.chain_record(entries()[:3], 2, sources), rows, sources


def enf_003():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=4)
    return HELPER.chain_record(entries()[:4], 3, sources), rows, sources


def enf_004():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=5)
    return HELPER.chain_record(entries()[:5], 4, sources), rows, sources


def enf_007():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=6)
    return HELPER.chain_record(entries()[:6], 5, sources), rows, sources


def enf_009():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=7)
    return HELPER.chain_record(entries()[:7], 6, sources), rows, sources


def mas_001():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=8)
    return HELPER.chain_record(entries()[:8], 7, sources), rows, sources


def mas_002():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=9)
    return HELPER.chain_record(entries()[:9], 8, sources), rows, sources


def mas_003():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=10)
    return HELPER.chain_record(entries()[:10], 9, sources), rows, sources


class ChainRegistryTests(unittest.TestCase):
    def test_the_registry_starts_with_conf_ci_002_and_then_conf_enf_001(self):
        rows, sources = head()
        value = entries()
        self.assertEqual(value[0], {"packetId": "CONF-CI-002", "path": HELPER.CI_002_RECORD_PATH,
                                    "sha256": HELPER.CI_002_RECORD_SHA256})
        self.assertEqual(value[1]["packetId"], "CONF-ENF-001")
        self.assertEqual(value[1]["path"], ENF_001_RECORD)
        self.assertEqual((value[2]["packetId"], value[2]["path"]), ("CONF-ENF-002", ENF_002_RECORD))
        self.assertEqual((value[3]["packetId"], value[3]["path"]), ("CONF-ENF-003", ENF_003_RECORD))
        self.assertEqual((value[4]["packetId"], value[4]["path"]), ("CONF-ENF-004", ENF_004_RECORD))
        self.assertEqual((value[5]["packetId"], value[5]["path"]), ("CONF-ENF-007", ENF_007_RECORD))
        self.assertEqual((value[6]["packetId"], value[6]["path"]), ("CONF-ENF-009", ENF_009_RECORD))
        self.assertEqual((value[7]["packetId"], value[7]["path"]), ("CONF-MAS-001", MAS_001_RECORD))
        self.assertEqual((value[8]["packetId"], value[8]["path"]), ("CONF-MAS-002", MAS_002_RECORD))
        self.assertEqual((value[9]["packetId"], value[9]["path"]), ("CONF-MAS-003", MAS_003_RECORD))
        self.assertEqual(sources[HELPER.CHAIN_REGISTRY_PATH], HELPER.chain_registry_bytes(value))
        for entry in value:
            self.assertEqual(hashlib.sha256(sources[entry["path"]]).hexdigest(), entry["sha256"])

    def test_the_conf_enf_001_record_names_exactly_its_paths_and_decisions(self):
        record, rows, sources = enf_001()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-CI-002", "sha256": HELPER.CI_002_RECORD_SHA256})
        self.assertEqual(record["baseCommit"], CI_002_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), ENF_001_CHANGED)
        area = {row["path"] for row in rows if row["path"].startswith("tests/enforcement/")}
        self.assertEqual(set(record["added"]), area | ENF_001_ADDED_OUTSIDE_AREA)
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], ENF_001_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-11" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_enf_002_record_names_exactly_its_paths_and_decisions(self):
        # CONF-ENF-002 (W04-2): data and tests only, as Q-T3 promised; no frozen helper, no ci/ path, no deletion.
        record, rows, sources = enf_002()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-ENF-001", "sha256": entries()[1]["sha256"]})
        self.assertEqual(record["baseCommit"], ENF_001_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), ENF_002_CHANGED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"]) if path.startswith("ci/")])
        self.assertEqual({path for path in record["added"] if not path.startswith("tests/enforcement/")}, ENF_002_ADDED_OUTSIDE_AREA)
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], ENF_002_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-11" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_enf_003_record_names_exactly_its_paths_and_decisions(self):
        # CONF-ENF-003 (W04-3): data and tests only, as Q-T3 promised; no frozen helper, no ci/ path, no deletion.
        record, rows, sources = enf_003()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-ENF-002", "sha256": entries()[2]["sha256"]})
        self.assertEqual(record["baseCommit"], ENF_002_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), ENF_003_CHANGED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"]) if path.startswith("ci/")])
        self.assertEqual({path for path in record["added"] if not path.startswith("tests/enforcement/")}, ENF_003_ADDED_OUTSIDE_AREA)
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], ENF_003_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-13" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_enf_004_record_names_exactly_its_paths_and_decisions(self):
        # CONF-ENF-004 (W04-4a): data, tests and the native probe source; no frozen helper, no ci/ path, no deletion.
        record, rows, sources = enf_004()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-ENF-003", "sha256": entries()[3]["sha256"]})
        self.assertEqual(record["baseCommit"], ENF_003_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), ENF_004_CHANGED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"]) if path.startswith(("ci/", "src/"))])
        outside = {path for path in record["added"] if not path.startswith("tests/enforcement/")}
        probes = {path for path in outside if path.startswith("probes/enforcement/")}
        self.assertEqual(outside - probes, {"task-packets/CONF-ENF-004.yaml"})
        self.assertEqual(len(probes), ENF_004_PROBE_FILES)
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], ENF_004_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-13" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_enf_007_record_names_exactly_its_paths_and_decisions(self):
        # CONF-ENF-007 (W04-6): TG-08 data and tests only; no frozen helper, no ci/ or src/ path, no snapshot, no deletion.
        record, rows, sources = enf_007()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-ENF-004", "sha256": entries()[4]["sha256"]})
        self.assertEqual(record["baseCommit"], ENF_004_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), ENF_007_CHANGED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"])
                          if path.startswith(("ci/", "src/", "probes/", "tests/enforcement/snapshots/"))])
        self.assertEqual({path for path in record["added"] if not path.startswith("tests/enforcement/")},
                         {"task-packets/CONF-ENF-007.yaml"})
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], ENF_007_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-14" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_enf_009_record_names_exactly_its_paths_and_decisions(self):
        # CONF-ENF-009: the enforcement area only; the eight recorded-addition snapshots are its only snapshot paths, no
        # existing snapshot changes, and no frozen helper, ci/, src/ or probe path is touched.
        record, rows, sources = enf_009()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-ENF-007", "sha256": entries()[5]["sha256"]})
        self.assertEqual(record["baseCommit"], ENF_007_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), ENF_009_CHANGED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"]) if path.startswith(("ci/", "src/", "probes/"))])
        root = "tests/enforcement/snapshots/harness-onion/"
        self.assertEqual({path for path in record["added"] if path.startswith("tests/enforcement/snapshots/")},
                         {root + path for path in ENF_009_SNAPSHOTS})
        self.assertEqual([path for path in record["changed"] if path.startswith("tests/enforcement/snapshots/")],
                         ["tests/enforcement/snapshots/manifest.json"])
        self.assertEqual({path for path in record["added"] if not path.startswith("tests/enforcement/")},
                         {"task-packets/CONF-ENF-009.yaml"})
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], ENF_009_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-18" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_mas_001_record_names_exactly_its_paths_and_decisions(self):
        # CONF-MAS-001: a new tests/mas area and its packet YAML; the only changed path is this test, and no frozen
        # helper, ci/, src/, probe or enforcement path is touched.
        record, rows, sources = mas_001()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-ENF-009", "sha256": entries()[6]["sha256"]})
        self.assertEqual(record["baseCommit"], ENF_009_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), MAS_001_CHANGED)
        self.assertEqual(set(record["added"]), MAS_001_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], MAS_001_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-19" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_mas_002_record_names_exactly_its_paths_and_decisions(self):
        # CONF-MAS-002: packet 1's tests/mas files and this test change; three test files and the packet YAML are added;
        # no frozen helper, ci/, src/, probe or enforcement path is touched. Its decisions are dated 2026-10-19 and
        # 2026-10-20 (packet 1's single-date rule is not copied).
        record, rows, sources = mas_002()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-MAS-001", "sha256": entries()[7]["sha256"]})
        self.assertEqual(record["baseCommit"], MAS_001_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), MAS_002_CHANGED)
        self.assertEqual(set(record["added"]), MAS_002_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], MAS_002_DECISIONS)
        self.assertTrue(all(row["date"] in ("2026-10-19", "2026-10-20") for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_mas_003_record_names_exactly_its_paths_and_decisions(self):
        # CONF-MAS-003: packets 1 and 2's tests/mas files and this test change; three test files, the packet-3
        # attestation, the campaign record and the packet YAML are added; no frozen helper, ci/, src/, probe or
        # enforcement path is touched. Its decisions are dated 2026-10-20.
        record, rows, sources = mas_003()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-MAS-002", "sha256": entries()[8]["sha256"]})
        self.assertEqual(record["baseCommit"], MAS_002_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), MAS_003_CHANGED)
        self.assertEqual(set(record["added"]), MAS_003_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], MAS_003_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-20" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_every_stage_view_is_checked_and_the_first_is_the_conf_ci_002_head(self):
        rows, sources = head()
        value = entries()
        for keep in range(1, len(value) + 1):
            with self.subTest(keep=keep):
                view_rows, view_sources = HELPER.checkpoint_chain_project(ROOT, rows, sources, keep=keep)
                paths = [row["path"] for row in view_rows]
                self.assertEqual(paths, sorted(paths, key=str.encode))
                self.assertEqual(set(paths), set(view_sources))
                for row in view_rows:
                    raw = view_sources[row["path"]]
                    self.assertEqual((row["size"], row["sha256"]), (len(raw), hashlib.sha256(raw).hexdigest()))
                if keep == 1:
                    self.assertNotIn(HELPER.CHAIN_REGISTRY_PATH, view_sources)
                else:
                    self.assertEqual(view_sources[HELPER.CHAIN_REGISTRY_PATH], HELPER.chain_registry_bytes(value[:keep]))
        view_rows, view_sources = HELPER.current_tracked_inventory(ROOT)
        self.assertEqual(len(view_rows), CI_002_VIEW_FILES)
        self.assertFalse(any(path.startswith("tests/enforcement/") for path in view_sources))
        record = enf_001()[0]
        for path, entry in record["changed"].items():
            self.assertEqual(view_sources[path], base64.b64decode(entry["beforeSourceBase64"]))
        HELPER.ci_002_project(ROOT, view_rows, view_sources)


class ChainRefusalTests(unittest.TestCase):
    def assert_refused(self, mutate, message):
        rows, sources = head()
        rows, sources = copy.deepcopy(rows), dict(sources)
        mutate(rows, sources)
        with self.assertRaisesRegex(ValueError, "checkpoint chain: " + message):
            HELPER.checkpoint_chain_project(ROOT, rows, sources)

    def forge(self, change, message, index=-1):
        """Forge registered record `index` (the newest by default) and re-pin its registry entry to the forged bytes."""
        def mutate(rows, sources):
            registry = json.loads(sources[HELPER.CHAIN_REGISTRY_PATH])["records"]
            value = json.loads(sources[registry[index]["path"]])
            change(value)
            forged = json.dumps(value).encode()
            registry[index]["sha256"] = hashlib.sha256(forged).hexdigest()
            sources[registry[index]["path"]] = forged
            sources[HELPER.CHAIN_REGISTRY_PATH] = HELPER.chain_registry_bytes(registry)
        self.assert_refused(mutate, message)

    def test_a_missing_or_reshaped_registry_is_refused(self):
        self.assert_refused(lambda rows, sources: rows.__setitem__(slice(None), [row for row in rows if row["path"] != HELPER.CHAIN_REGISTRY_PATH]),
                            "registry tracked")
        self.assert_refused(lambda rows, sources: sources.__setitem__(HELPER.CHAIN_REGISTRY_PATH, sources[HELPER.CHAIN_REGISTRY_PATH][:-1] + b" \n"),
                            "canonical registry bytes")
        def first(rows, sources):
            registry = json.loads(sources[HELPER.CHAIN_REGISTRY_PATH])["records"]
            sources[HELPER.CHAIN_REGISTRY_PATH] = HELPER.chain_registry_bytes(registry[1:] + registry[:1])
        self.assert_refused(first, "entry 0 is CONF-CI-002")
        def dropped(rows, sources):
            registry = json.loads(sources[HELPER.CHAIN_REGISTRY_PATH])["records"]
            sources[HELPER.CHAIN_REGISTRY_PATH] = HELPER.chain_registry_bytes(registry[:1])
        self.assert_refused(dropped, "closed registry")

    def test_entry_0_must_be_the_tracked_conf_ci_002_record(self):
        # Review E1-1: a zeroed entry 0 (and so a zeroed predecessor pin) is refused before any record is read.
        def zeroed(rows, sources):
            registry = json.loads(sources[HELPER.CHAIN_REGISTRY_PATH])["records"]
            registry[0]["sha256"] = "0" * 64
            sources[HELPER.CHAIN_REGISTRY_PATH] = HELPER.chain_registry_bytes(registry)
        self.assert_refused(zeroed, "entry 0 digest")
        self.assert_refused(lambda rows, sources: sources.__setitem__(HELPER.CI_002_RECORD_PATH, sources[HELPER.CI_002_RECORD_PATH] + b" "),
                            "entry 0 digest")

    def test_a_changed_or_untracked_record_is_refused(self):
        self.assert_refused(lambda rows, sources: sources.__setitem__(ENF_001_RECORD, sources[ENF_001_RECORD] + b" "),
                            "record digest: CONF-ENF-001")
        self.assert_refused(lambda rows, sources: next(row for row in rows if row["path"] == ENF_001_RECORD).update(mode="100755"),
                            "record tracked: CONF-ENF-001")

    def test_a_missing_or_changed_admitted_path_is_refused(self):
        record = enf_001()[0]
        samples = sorted(ENF_001_CHANGED | ENF_001_ADDED_OUTSIDE_AREA | {"tests/enforcement/test_bootstrap.py",
                                                                          "tests/enforcement/snapshots/manifest.json"})
        self.assertTrue(set(samples) <= set(record["added"]) | set(record["changed"]))
        for path in samples:
            def missing(rows, sources, path=path):
                rows[:] = [row for row in rows if row["path"] != path]
            def changed(rows, sources, path=path):
                sources[path] = sources[path] + b"\n"
            def mode(rows, sources, path=path):
                row = next(row for row in rows if row["path"] == path)
                row["mode"] = "100644" if row["mode"] == "100755" else "100755"
            for name, mutate in (("missing", missing), ("bytes", changed), ("mode", mode)):
                with self.subTest(path=path, change=name):
                    self.assert_refused(mutate, "exact after-pin: " + path)

    def test_a_forged_record_is_refused(self):
        # CONF-ENF-002: the newest record is forged, whichever packet registered it last; record-scoped refusals name it.
        newest = entries()[-1]["packetId"]
        before = {"mode": "100644", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
        for change, message in ((lambda value: value.update(extra=1), "closed record: " + newest),
                                (lambda value: value.update(nativeAcceptance=True), "closed record: " + newest),
                                (lambda value: value["predecessor"].update(sha256="0" * 64), "closed record: " + newest),
                                (lambda value: value.update(ownerDecisions=[{"id": "Q-T1"}]), "owner decisions: " + newest),
                                (lambda value: value["added"].update({HELPER.CHAIN_REGISTRY_PATH: before}), "each path named once: " + newest),
                                (lambda value: value["added"].update({HELPER.CI_002_RECORD_PATH: before}), "each path named once: " + newest),
                                (lambda value: value["deleted"].update({"a/b": {"before": dict(before, size=2),
                                                                                "beforeSourceBase64": "eA=="}}), "before-image"),
                                (lambda value: value["deleted"].update({"README.md": {"before": before, "beforeSourceBase64": "eA=="}}),
                                 "deleted path present: README.md"),
                                # Review E1-3: an empty decision list, a non-integer size, non-canonical base64.
                                (lambda value: value.update(ownerDecisions=[]), "owner decisions: " + newest),
                                (lambda value: next(iter(value["added"].values())).update(size=5.0), "closed after-pin"),
                                (lambda value: value["deleted"].update({"a/b": {"before": before, "beforeSourceBase64": "eB=="}}),
                                 "canonical before-image: a/b"),
                                # Review E2-2, E2-3: a restored path under a file, a repeated decision id.
                                (lambda value: value["deleted"].update({"README.md/x": {"before": before, "beforeSourceBase64": "eA=="}}),
                                 "path collision: README.md/x"),
                                (lambda value: value["ownerDecisions"].append(dict(value["ownerDecisions"][0])), "owner decisions: " + newest)):
            with self.subTest(message=message):
                self.forge(change, message)

    def test_a_forged_earlier_record_breaks_its_successors_predecessor_pin(self):
        # CONF-ENF-002: re-pinning an earlier record's registry entry is refused at the next record, whose predecessor pin
        # names the original digest. (Rewriting every later record too is outside what code can detect; E1-2, review.)
        value = entries()
        self.assertGreaterEqual(len(value), 3)
        for index in range(1, len(value) - 1):
            with self.subTest(record=value[index]["packetId"]):
                self.forge(lambda record: record.update(baseCommit="0" * 40), "closed record: " + value[index + 1]["packetId"], index)

    def test_a_stage_out_of_range_is_refused(self):
        for keep in (0, len(entries()) + 1, True):
            with self.subTest(keep=keep), self.assertRaisesRegex(ValueError, "checkpoint chain: stage out of range"):
                HELPER.checkpoint_chain_project(ROOT, *head(), keep=keep)


if __name__ == "__main__":
    unittest.main()
