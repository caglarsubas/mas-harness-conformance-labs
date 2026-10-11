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


def head():
    return HELPER.head_tracked_inventory(ROOT)


def entries():
    return HELPER.chain_registry(*head())


def enf_001():
    rows, sources = HELPER.checkpoint_chain_project(ROOT, *head(), keep=2)
    return HELPER.chain_record(entries()[:2], 1, sources), rows, sources


class ChainRegistryTests(unittest.TestCase):
    def test_the_registry_starts_with_conf_ci_002_and_then_conf_enf_001(self):
        rows, sources = head()
        value = entries()
        self.assertEqual(value[0], {"packetId": "CONF-CI-002", "path": HELPER.CI_002_RECORD_PATH,
                                    "sha256": HELPER.CI_002_RECORD_SHA256})
        self.assertEqual(value[1]["packetId"], "CONF-ENF-001")
        self.assertEqual(value[1]["path"], ENF_001_RECORD)
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

    def forge(self, change, message):
        def mutate(rows, sources):
            value = json.loads(sources[ENF_001_RECORD])
            change(value)
            forged = json.dumps(value).encode()
            registry = json.loads(sources[HELPER.CHAIN_REGISTRY_PATH])["records"]
            registry[1]["sha256"] = hashlib.sha256(forged).hexdigest()
            sources[ENF_001_RECORD] = forged
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
        before = {"mode": "100644", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
        for change, message in ((lambda value: value.update(extra=1), "closed record"),
                                (lambda value: value.update(nativeAcceptance=True), "closed record"),
                                (lambda value: value["predecessor"].update(sha256="0" * 64), "closed record"),
                                (lambda value: value.update(ownerDecisions=[{"id": "Q-T1"}]), "owner decisions"),
                                (lambda value: value["added"].update({HELPER.CHAIN_REGISTRY_PATH: before}), "each path named once"),
                                (lambda value: value["added"].update({HELPER.CI_002_RECORD_PATH: before}), "each path named once"),
                                (lambda value: value["deleted"].update({"a/b": {"before": dict(before, size=2),
                                                                                "beforeSourceBase64": "eA=="}}), "before-image"),
                                (lambda value: value["deleted"].update({"README.md": {"before": before, "beforeSourceBase64": "eA=="}}),
                                 "deleted path present: README.md"),
                                # Review E1-3: an empty decision list, a non-integer size, non-canonical base64.
                                (lambda value: value.update(ownerDecisions=[]), "owner decisions"),
                                (lambda value: next(iter(value["added"].values())).update(size=5.0), "closed after-pin"),
                                (lambda value: value["deleted"].update({"a/b": {"before": before, "beforeSourceBase64": "eB=="}}),
                                 "canonical before-image: a/b")):
            with self.subTest(message=message):
                self.forge(change, message)

    def test_a_stage_out_of_range_is_refused(self):
        for keep in (0, len(entries()) + 1, True):
            with self.subTest(keep=keep), self.assertRaisesRegex(ValueError, "checkpoint chain: stage out of range"):
                HELPER.checkpoint_chain_project(ROOT, *head(), keep=keep)


if __name__ == "__main__":
    unittest.main()
