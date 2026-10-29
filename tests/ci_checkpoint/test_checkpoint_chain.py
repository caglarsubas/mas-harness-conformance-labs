"""CONF-ENF-001: R12's registry-pinned checkpoint chain (owner decision Q-T3 = (a), 2026-10-11).

fixtures/ci/checkpoints.json registers CONF-CI-002's record as entry 0 and one closed record per later packet. The records
are checked newest first against the git tree and projected away in turn, down to the CONF-CI-002 head view that
CONF-CI-002's layer and tests read; the chain adds nothing to that view.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import importlib.util
import json
import re
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
MAS_003_HEAD = "dbc45c708f342cfcac6b2c417ef8b8f94aa186cd"
# CONF-MAS-004 (MAS-RA-010-F packet 1, evaluation integrity; owner decisions RA010F-PICK and Q-RA10F-1..8, 2026-10-21,
# Q-P4-D2-1 and Q-P4-D4-3, 2026-10-22) follows CONF-MAS-003; it changes packets 1 to 3's tests/mas files and this test,
# and adds three tests/mas test files, the packet-4 attestation and its packet YAML. Acceptance argv 14 is unchanged.
MAS_004_RECORD = "fixtures/ci/conf-mas-004-checkpoint.json"
MAS_004_CHANGED = {"tests/ci_checkpoint/test_checkpoint_chain.py",
                   "tests/mas/README.md",
                   "tests/mas/_classes.py",
                   "tests/mas/_ledger.py",
                   "tests/mas/_sim.py",
                   "tests/mas/campaign-record.json",
                   "tests/mas/classes.json",
                   "tests/mas/contracts.json",
                   "tests/mas/results.json",
                   "tests/mas/test_ledger.py",
                   "tests/mas/test_oracle_p2.py",
                   "tests/mas/test_oracle_p3.py",
                   "tests/mas/test_p3_rules.py"}
MAS_004_ADDED = {"task-packets/CONF-MAS-004.yaml",
                 "tests/mas/attestation-p4.json",
                 "tests/mas/test_oracle_p4.py",
                 "tests/mas/test_p4_classes.py",
                 "tests/mas/test_p4_rules.py"}
MAS_004_DECISIONS = ["RA010F-PICK"] + ["Q-RA10F-%d" % n for n in range(1, 9)] + ["Q-P4-D2-1", "Q-P4-D4-3"]
MAS_004_HEAD = "e038772d1c28cd86c50a469662d71ee2737f0143"
# CONF-MAS-005 (MAS-RA-010-F packet 2, the trust boundary; owner decisions RA010F-PICK and Q-RA10F-1..8, 2026-10-21)
# follows CONF-MAS-004; it changes packets 1 to 4's tests/mas files and this test, and adds three tests/mas test files,
# the packet-5 attestation and its packet YAML. Acceptance argv 14 is unchanged.
MAS_005_RECORD = "fixtures/ci/conf-mas-005-checkpoint.json"
MAS_005_CHANGED = {"tests/ci_checkpoint/test_checkpoint_chain.py",
                   "tests/mas/README.md",
                   "tests/mas/_classes.py",
                   "tests/mas/_ledger.py",
                   "tests/mas/_sim.py",
                   "tests/mas/campaign-record.json",
                   "tests/mas/classes.json",
                   "tests/mas/contracts.json",
                   "tests/mas/results.json",
                   "tests/mas/test_ledger.py",
                   "tests/mas/test_oracle_p3.py",
                   "tests/mas/test_oracle_p4.py",
                   "tests/mas/test_p3_rules.py",
                   "tests/mas/test_p4_rules.py"}
MAS_005_ADDED = {"task-packets/CONF-MAS-005.yaml",
                 "tests/mas/attestation-p5.json",
                 "tests/mas/test_oracle_p5.py",
                 "tests/mas/test_p5_classes.py",
                 "tests/mas/test_p5_rules.py"}
MAS_005_DECISIONS = ["RA010F-PICK"] + ["Q-RA10F-%d" % n for n in range(1, 9)]
MAS_005_HEAD = "c17bcfe32df26eab13844b73f65666bb0fa4e0a0"
# CONF-LINUX-002 (the signers disclosure on the CONF-LINUX-001 path; owner decisions Q-LHA-1 (a), 2026-10-23, and Q-SG-6,
# Q-SG-7/8 and Q-SG-9, 2026-10-24) follows CONF-MAS-005. Under Q-SG-6's scoped exception to Q-T3 it changes live.py
# (additions only), linux_readiness.py and this test, and adds the three schemas/v1alpha2 files (gate material, Q-SG-7/8),
# the tests/linux_signers root with its D5a oracle (MON-CL2-ORACLE-PATH), the signers doc and its packet YAML.
LINUX_002_RECORD = "fixtures/ci/conf-linux-002-checkpoint.json"
LINUX_002_CHANGED = {"src/harness_conformance/linux_readiness.py",
                     "src/harness_conformance/live.py",
                     "tests/ci_checkpoint/test_checkpoint_chain.py"}
LINUX_002_ADDED = {"docs/live-backend/signers.md",
                   "schemas/v1alpha2/linux-readiness-evidence.schema.json",
                   "schemas/v1alpha2/live-campaign-execution-envelope.schema.json",
                   "schemas/v1alpha2/live-capacity-authorization.schema.json",
                   "task-packets/CONF-LINUX-002.yaml",
                   "tests/linux_signers/__init__.py",
                   "tests/linux_signers/_fixtures.py",
                   "tests/linux_signers/test_oracle.py",
                   "tests/linux_signers/test_signers.py"}
# Each decision with its own date (the single-date pattern of the earlier record tests, widened).
LINUX_002_DECISION_DATES = {"Q-LHA-1": "2026-10-23", "Q-SG-6": "2026-10-24", "Q-SG-7/8": "2026-10-24", "Q-SG-9": "2026-10-24"}
LINUX_002_HEAD = "bee5ad4f3d673aef496f1fd83956658a095dec8a"
# CONF-LIVE-004A (O-SERVER-MEMFD, CONF-LIVE-004's prerequisite; owner decision Q-MEMFD-5, 2026-10-28, closing
# W01-AMEND-QW3 = M-a, 2026-10-10) follows CONF-LINUX-002. Under Q-MEMFD-5's scoped exception to Q-T3 it changes
# live_linux_boundary.py (the memfd flags, the coded refusal and the F_SEAL_EXEC assertion only), its unit rig and this
# test, and adds its packet YAML.
LIVE_004A_RECORD = "fixtures/ci/conf-live-004a-checkpoint.json"
LIVE_004A_CHANGED = {"src/harness_conformance/live_linux_boundary.py",
                     "tests/ci_checkpoint/test_checkpoint_chain.py",
                     "tests/live_backend/test_linux_boundary.py"}
LIVE_004A_ADDED = {"task-packets/CONF-LIVE-004A.yaml"}
LIVE_004A_DECISION_DATES = {"Q-MEMFD-5": "2026-10-28", "W01-AMEND-QW3": "2026-10-10"}
LIVE_004A_HEAD = "81a885d1cf995dfe5d38a6fe696cd5d9ce0821a4"
# CONF-LIVE-003C (CONF-LIVE-003 closed for R12's client surface; owner decisions Q-PK-2 and Q-LPK0-4, 2026-10-22, and
# Q-L3-3 and Q-L3-5, 2026-10-28) follows CONF-LIVE-004A. Data, tests and one doc section only, with no src change: it
# changes docs/live-backend/proxy.md (one appended closing section) and this test, and adds the closure record and its
# packet YAML.
LIVE_003C_RECORD = "fixtures/ci/conf-live-003c-checkpoint.json"
LIVE_003C_CHANGED = {"docs/live-backend/proxy.md",
                     "tests/ci_checkpoint/test_checkpoint_chain.py"}
LIVE_003C_ADDED = {"fixtures/live-backend/conf-live-003-closure.json",
                   "task-packets/CONF-LIVE-003C.yaml"}
LIVE_003C_DECISION_DATES = {"Q-PK-2": "2026-10-22", "Q-LPK0-4": "2026-10-22", "Q-L3-3": "2026-10-28", "Q-L3-5": "2026-10-28"}
# The CONF-LIVE-003 closure record (fixtures/live-backend/conf-live-003-closure.json): its closed members, the classes of
# the published packet's eight allowedPaths and of the 32 CONF-LIVE-003 rows of proxy.md's "Roadmap and evidence" table.
LIVE_003_CLOSURE = "fixtures/live-backend/conf-live-003-closure.json"
LIVE_003_CLOSURE_FIELDS = {"schemaVersion", "packetId", "closedBy", "evidenceClass", "nativeAcceptance", "tenantAcceptance",
                           "publishedPacket", "productMerge", "publishedCorrection", "paths", "rows", "retiredPackets",
                           "closedDraftPrs", "decisions"}
LIVE_003_GUIDE = "docs/live-backend/proxy.md"
LIVE_003_SECTION = "## CONF-LIVE-003 closure (CONF-LIVE-003C)"
LIVE_003_KIT = "LINUX-PROBE-KIT-001"
LIVE_003_PATH_CLASSES = {"src/harness_conformance/live_proxy_client.py": "KEPT_R12",
                         "tests/live_backend/test_proxy_client.py": "KEPT_R12",
                         "src/harness_conformance/live_proxy_server.py": "MOVED_RETAINED",
                         "src/harness_conformance/live_mutation_admission.py": "MOVED_RETAINED",
                         "tests/live_backend/test_proxy_server.py": "MOVED_RETAINED",
                         "tests/live_backend/test_mutation_admission.py": "MOVED_RETAINED",
                         "fixtures/live-backend/proxy-vectors.json": "SHARED",
                         "docs/live-backend/proxy.md": "SHARED"}
LIVE_003_MOVED_ROWS = {"CONF-LIVE-003 server-only API authentication": "IMPLEMENTED_NOT_ACCEPTED",
                       "CONF-LIVE-003 returned-identity accounting": "IMPLEMENTED_NOT_ACCEPTED",
                       "CONF-LIVE-003 CREATED result delivery": "IMPLEMENTED_NOT_ACCEPTED",
                       "CONF-LIVE-003 local CREATE retirement": "IMPLEMENTED_NOT_ACCEPTED",
                       "CONF-LIVE-003 native inspector / broker / API": "ONGOING"}
LIVE_003_CLIENT_CLOSED_ROWS = {"CONF-LIVE-003 required CI", "CONF-LIVE-003 source completion / merge / exact-main"}
# Q-L3-2 (a): the published correction exactly as Build-R00 relayed it (MON-R12-L3C-LAUNCH); the lane never reads it.
LIVE_003_CORRECTION_FILES = [
    {"path": "architecture/probe-kit-scope/amendment.json",
     "sha256": "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b"},
    {"path": "architecture/probe-kit-scope/README.md",
     "sha256": "b2761f010983fbac4f84e6b7653a3a5a7c26dd7c758e1ab7ee1d5f1d94c6dd0c"}]
LIVE_003_CORRECTION_ROWS = {
    "dispositions": [{"index": 0, "packetId": "CONF-LIVE-003", "disposition": "CONSUMED",
                      "deliverables": {"1": "KEPT_R12", "2": "SUPERSEDED_UNACCEPTED_HISTORY",
                                       "3": "SUPERSEDED_UNACCEPTED_HISTORY", "4": "SUPERSEDED_UNACCEPTED_HISTORY"}}],
    "moved": [{"index": index, "item": item, "fromPacket": "CONF-LIVE-003", "to": LIVE_003_KIT}
              for index, item in ((0, "ADMISSION_MODULE"), (3, "RECORD_INSPECTOR"), (4, "SERVER"), (5, "UID_LEDGER"))],
    "retained": [{"index": 1, "item": "CLIENT", "text": "The campaign client (CONF-LIVE-003 deliverable 1)"}]}
LIVE_003_DECISIONS = {"Q-PK-2": ("2026-10-22", "owner (via the lane monitor)"),
                      "Q-LPK0-4": ("2026-10-22", "owner (via the lane monitor)"),
                      "Q-L3-3": ("2026-10-28", "owner (via the lane monitor)"),
                      "Q-L3-5": ("2026-10-28", "owner (via the lane monitor)"),
                      "Q-L3-PRS": ("2026-10-28", "owner (via the lane monitor)"),
                      "Q-L3-1": ("2026-10-29", "lane monitor (owner delegation 2026-10-22)"),
                      "Q-L3-2": ("2026-10-29", "lane monitor (owner delegation 2026-10-22)"),
                      "Q-L3-4": ("2026-10-29", "lane monitor (owner delegation 2026-10-22)"),
                      "Q-L3-6": ("2026-10-29", "lane monitor (owner delegation 2026-10-22)"),
                      "MON-R12-L3-STEP2": ("2026-10-29", "lane monitor (owner delegation 2026-10-22)")}


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


def mas_004():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=11)
    return HELPER.chain_record(entries()[:11], 10, sources), rows, sources


def mas_005():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=12)
    return HELPER.chain_record(entries()[:12], 11, sources), rows, sources


def conf_linux_002():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=13)
    return HELPER.chain_record(entries()[:13], 12, sources), rows, sources


def conf_live_004a():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=14)
    return HELPER.chain_record(entries()[:14], 13, sources), rows, sources


def conf_live_003c():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=15)
    return HELPER.chain_record(entries()[:15], 14, sources), rows, sources


def live_003_table(guide):
    """(ID cell, status cell) of each row of proxy.md's "Roadmap and evidence" table whose ID cell starts with
    'CONF-LIVE-003 ', in table order; cells are split on '|' and stripped of spaces only."""
    lines = guide.decode("utf-8").split("\n")
    start = [index for index, line in enumerate(lines) if line == "## Roadmap and evidence"]
    if len(start) != 1:
        raise AssertionError("one Roadmap and evidence heading required")
    index = start[0] + 1
    while not lines[index].startswith("|"):
        index += 1
    if lines[index] != "| Phase | ID / gate | Status | Description |" or lines[index + 1] != "|---|---|---|---|":
        raise AssertionError("the roadmap table header changed")
    found = []
    for line in lines[index + 2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip(" ") for cell in line.strip(" ")[1:-1].split("|")]
        if len(cells) != 4 or not line.endswith("|"):
            raise AssertionError("four cells required")
        if cells[1].startswith("CONF-LIVE-003 "):
            found.append((cells[1], cells[2]))
    return found


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
        self.assertEqual((value[10]["packetId"], value[10]["path"]), ("CONF-MAS-004", MAS_004_RECORD))
        self.assertEqual((value[11]["packetId"], value[11]["path"]), ("CONF-MAS-005", MAS_005_RECORD))
        self.assertEqual((value[12]["packetId"], value[12]["path"]), ("CONF-LINUX-002", LINUX_002_RECORD))
        self.assertEqual((value[13]["packetId"], value[13]["path"]), ("CONF-LIVE-004A", LIVE_004A_RECORD))
        self.assertEqual((value[14]["packetId"], value[14]["path"]), ("CONF-LIVE-003C", LIVE_003C_RECORD))
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

    def test_the_conf_mas_004_record_names_exactly_its_paths_and_decisions(self):
        # CONF-MAS-004: packets 1 to 3's tests/mas files and this test change; three test files, the packet-4
        # attestation and the packet YAML are added; the record names neither itself nor the registry; no frozen
        # helper, ci/, src/, probe or enforcement path is touched. Its decisions are dated 2026-10-21 and 2026-10-22.
        record, rows, sources = mas_004()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-MAS-003", "sha256": entries()[9]["sha256"]})
        self.assertEqual(record["baseCommit"], MAS_003_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), MAS_004_CHANGED)
        self.assertEqual(set(record["added"]), MAS_004_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], MAS_004_DECISIONS)
        self.assertTrue(all(row["date"] in ("2026-10-21", "2026-10-22") for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_mas_005_record_names_exactly_its_paths_and_decisions(self):
        # CONF-MAS-005: packets 1 to 4's tests/mas files and this test change; three test files, the packet-5
        # attestation and the packet YAML are added; the record names neither itself nor the registry; no frozen
        # helper, ci/, src/, probe or enforcement path is touched. Its decisions are dated 2026-10-21.
        record, rows, sources = mas_005()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-MAS-004", "sha256": entries()[10]["sha256"]})
        self.assertEqual(record["baseCommit"], MAS_004_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), MAS_005_CHANGED)
        self.assertEqual(set(record["added"]), MAS_005_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], MAS_005_DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-21" for row in record["ownerDecisions"]))
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_linux_002_record_names_exactly_its_paths_and_decisions(self):
        # CONF-LINUX-002: live.py (additions only), linux_readiness.py and this test change under Q-SG-6's scoped exception;
        # the three schemas/v1alpha2 files, the tests/linux_signers root with its D5a oracle, the signers doc and the packet
        # YAML are added; the record names neither itself nor the registry; there is no deletion and no ci/, probes/ or
        # tests/enforcement/ path. Each decision carries its own date, 2026-10-23 or 2026-10-24.
        record, rows, sources = conf_linux_002()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-MAS-005", "sha256": entries()[11]["sha256"]})
        self.assertEqual(record["baseCommit"], MAS_005_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), LINUX_002_CHANGED)
        self.assertEqual(set(record["added"]), LINUX_002_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"])
                          if path.startswith(("ci/", "probes/", "tests/enforcement/"))])
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], list(LINUX_002_DECISION_DATES))
        for row in record["ownerDecisions"]:
            with self.subTest(decision=row["id"]):
                self.assertEqual(row["date"], LINUX_002_DECISION_DATES[row["id"]])
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_live_004a_record_names_exactly_its_paths_and_decisions(self):
        # CONF-LIVE-004A: live_linux_boundary.py (three changes only), its unit rig and this test change under Q-MEMFD-5's
        # scoped exception; the packet YAML is added; the record names neither itself nor the registry; there is no
        # deletion and no ci/, probes/, tests/enforcement/ or schemas/ path. Each decision carries its own date.
        record, rows, sources = conf_live_004a()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-LINUX-002", "sha256": entries()[12]["sha256"]})
        self.assertEqual(record["baseCommit"], LINUX_002_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), LIVE_004A_CHANGED)
        self.assertEqual(set(record["added"]), LIVE_004A_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"])
                          if path.startswith(("ci/", "probes/", "tests/enforcement/", "schemas/"))])
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], list(LIVE_004A_DECISION_DATES))
        for row in record["ownerDecisions"]:
            with self.subTest(decision=row["id"]):
                self.assertEqual(row["date"], LIVE_004A_DECISION_DATES[row["id"]])
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_live_003c_record_names_exactly_its_paths_and_decisions(self):
        # CONF-LIVE-003C: proxy.md (one appended section) and this test change, the closure record and the packet YAML are
        # added; the record names neither itself nor the registry; there is no deletion and no src/, ci/, probes/,
        # tests/enforcement/ or schemas/ path. Each decision carries its own date.
        record, rows, sources = conf_live_003c()
        self.assertEqual(record["predecessor"], {"packetId": "CONF-LIVE-004A", "sha256": entries()[13]["sha256"]})
        self.assertEqual(record["baseCommit"], LIVE_004A_HEAD)
        self.assertEqual(record["deleted"], {})
        self.assertEqual(set(record["changed"]), LIVE_003C_CHANGED)
        self.assertEqual(set(record["added"]), LIVE_003C_ADDED)
        self.assertFalse(ENF_001_CHANGED & (set(record["changed"]) | set(record["added"])))
        self.assertFalse([path for path in (*record["changed"], *record["added"])
                          if path.startswith(("src/", "ci/", "probes/", "tests/enforcement/", "schemas/"))])
        self.assertEqual([row["id"] for row in record["ownerDecisions"]], list(LIVE_003C_DECISION_DATES))
        for row in record["ownerDecisions"]:
            with self.subTest(decision=row["id"]):
                self.assertEqual(row["date"], LIVE_003C_DECISION_DATES[row["id"]])
        self.assertTrue(all(pin["mode"] == "100644" for pin in record["added"].values()))

    def test_the_conf_live_003_closure_record_matches_the_tree(self):
        # CONF-LIVE-003C: the closure record is canonical and closed, names the published packet's eight allowedPaths in
        # order with HEAD's bytes, keeps every KEPT_R12 and MOVED_RETAINED path byte-unchanged from the base, classes every
        # CONF-LIVE-003 row of proxy.md's table once, in order, with its status verbatim, and pins the Q-L3-4 import
        # freeze; proxy.md's base bytes are its exact prefix and the suffix is the one closing section.
        chain, rows, sources = conf_live_003c()
        base_rows, base_sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=14)
        raw = sources[LIVE_003_CLOSURE]
        closure = HELPER.parse(raw)
        self.assertEqual(raw, HELPER.canonical(closure) + b"\n")
        self.assertEqual(set(closure), LIVE_003_CLOSURE_FIELDS)
        self.assertEqual((closure["schemaVersion"], closure["packetId"], closure["closedBy"], closure["evidenceClass"]),
                         ("r12.conf-live-003-closure/v1", "CONF-LIVE-003", "CONF-LIVE-003C", "SOURCE_DELTA_ONLY"))
        self.assertIs(closure["nativeAcceptance"], False)
        self.assertIs(closure["tenantAcceptance"], False)
        self.assertEqual(closure["productMerge"], {"pr": 12, "commit": "092fcf475c6f3ebd455e3c354cddb7664ea1f900"})
        # The published packet as R12 pins it, and its eight allowedPaths read from those pinned bytes, in order.
        published = json.loads(sources["fixtures/platform/linux-baseline/scalar-repair.json"])["publishedPackets"]["CONF-LIVE-003"]
        self.assertEqual(hashlib.sha256(published["raw"].encode()).hexdigest(), published["sha256"])
        self.assertEqual(closure["publishedPacket"], {"path": "task-packets/CONF-LIVE-003.yaml", "sha256": published["sha256"]})
        allowed = [json.loads(line[len("allowedPaths: "):]) for line in published["raw"].split("\n")
                   if line.startswith("allowedPaths: ")]
        self.assertEqual(len(allowed), 1)
        self.assertEqual([entry["path"] for entry in closure["paths"]], allowed[0])
        self.assertEqual(set(allowed[0]), set(LIVE_003_PATH_CLASSES))
        named = {*chain["deleted"], *chain["changed"], *chain["added"]}
        self.assertFalse([path for path in named if path.startswith("src/")])
        for entry in closure["paths"]:
            path, kind = entry["path"], LIVE_003_PATH_CLASSES[entry["path"]]
            with self.subTest(path=path):
                self.assertEqual(entry["class"], kind)
                self.assertEqual(entry["sha256"], hashlib.sha256(sources[path]).hexdigest())
                if kind == "MOVED_RETAINED":
                    self.assertEqual(set(entry), {"path", "sha256", "class", "retainedBecause", "furtherDevelopment"})
                    self.assertEqual(entry["furtherDevelopment"], LIVE_003_KIT)
                    self.assertTrue(entry["retainedBecause"] and all(type(item) is str and item for item in entry["retainedBecause"]))
                else:
                    self.assertEqual(set(entry), {"path", "sha256", "class"})
                if kind in ("KEPT_R12", "MOVED_RETAINED"):
                    self.assertNotIn(path, named)
                    self.assertEqual(sources[path], base_sources[path])
        # Every CONF-LIVE-003 row of the table, once each, in order, status verbatim, with its one class.
        expected = []
        for row_id, status in live_003_table(sources[LIVE_003_GUIDE]):
            rules = []
            if status in ("LOCAL_AND_CI_PASS_RECORDED", "LOCAL_PASS_RECORDED"):
                rules.append({"class": "HISTORY"})
            if LIVE_003_MOVED_ROWS.get(row_id) == status:
                rules.append({"class": "MOVED", "owner": LIVE_003_KIT})
            if row_id == "CONF-LIVE-003 checkpoint / transport":
                rules.append({"class": "KEPT_R12"})
            if row_id in LIVE_003_CLIENT_CLOSED_ROWS:
                rules.append({"class": "CLIENT_CLOSED_HERE", "movedRemainderOwner": LIVE_003_KIT})
            with self.subTest(row=row_id):
                self.assertEqual(len(rules), 1)
            expected.append({"id": row_id, "status": status, **rules[0]})
        self.assertEqual(len(expected), 32)
        self.assertEqual(len({row["id"] for row in expected}), 32)
        self.assertEqual(closure["rows"], expected)
        # The published correction as relayed (Q-L3-2), the retired packets, the closed draft PRs and each decision.
        correction = closure["publishedCorrection"]
        self.assertEqual(set(correction), {"packetId", "repository", "slot", "merge", "files", "rows", "readmeLines",
                                           "receiptVerification", "source"})
        self.assertEqual((correction["packetId"], correction["repository"], correction["slot"], correction["merge"]),
                         ("MET-LIVE-002", "harness-onion", 260, "b821ed65"))
        self.assertEqual(correction["files"], LIVE_003_CORRECTION_FILES)
        self.assertEqual(correction["rows"], LIVE_003_CORRECTION_ROWS)
        self.assertEqual(correction["receiptVerification"], {"packetId": "CONF-LIVE-004", "retainedAs": "RECEIPT_VERIFICATION",
                                                             "scope": "CONF-LIVE-004's narrowed scope", "claimedHere": False})
        self.assertEqual(closure["retiredPackets"],
                         [{"packetId": packet, "class": "NON_DISPATCHABLE_RETAINED_HISTORY", "decision": decision}
                          for packet, decision in (("CONF-FIX-007", "Q-L3-3"), ("CONF-FIX-008", "Q-L3-3"),
                                                   ("CONF-FIX-009", "Q-LPK0-4"), ("CONF-FIX-010", "Q-LPK0-4"))])
        self.assertEqual(closure["closedDraftPrs"], [18, 20])
        self.assertEqual([row["id"] for row in closure["decisions"]], list(LIVE_003_DECISIONS))
        for row in closure["decisions"]:
            with self.subTest(decision=row["id"]):
                self.assertEqual(set(row), {"id", "date", "by", "ruling"})
                self.assertEqual((row["date"], row["by"]), LIVE_003_DECISIONS[row["id"]])
                self.assertTrue(type(row["ruling"]) is str and row["ruling"])
        # Q-L3-4: the supervisor takes only execute_protected from the client, and the client takes exactly require,
        # retained_profile and _time from the frozen admission module (by ast; nothing is imported or executed).
        def imported(path, module):
            tree = ast.parse(sources[path])
            names = [[alias.name for alias in node.names] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[-1] == module]
            plain = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names if alias.name.split(".")[-1] == module]
            return names, plain
        self.assertEqual(imported("src/harness_conformance/live_supervisor.py", "live_proxy_client"), ([["execute_protected"]], []))
        self.assertEqual(imported("src/harness_conformance/live_proxy_client.py", "live_mutation_admission"),
                         ([["require", "retained_profile", "_time"]], []))
        # proxy.md: the base bytes (this record's before-image) are an exact prefix; the suffix is the one closing section,
        # at most 25 lines, pointing to the closure record by path and carrying no digest.
        guide, before = sources[LIVE_003_GUIDE], base_sources[LIVE_003_GUIDE]
        self.assertEqual(before, base64.b64decode(chain["changed"][LIVE_003_GUIDE]["beforeSourceBase64"]))
        self.assertTrue(before.endswith(b"\n<!-- CONF-PERF-006 SOURCE_DELTA_ONLY END -->\n"))
        self.assertEqual(guide[:len(before)], before)
        suffix = guide[len(before):].decode("utf-8")
        self.assertTrue(suffix.startswith(LIVE_003_SECTION + "\n") and suffix.endswith("\n"))
        lines = suffix.split("\n")[:-1]
        self.assertLessEqual(len(lines), 25)
        self.assertEqual([line for line in lines if line.startswith("#")], [LIVE_003_SECTION])
        self.assertNotIn("<!--", suffix)
        self.assertIn(LIVE_003_CLOSURE, suffix)
        self.assertIsNone(re.search("[0-9a-f]{40,64}", suffix))

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
