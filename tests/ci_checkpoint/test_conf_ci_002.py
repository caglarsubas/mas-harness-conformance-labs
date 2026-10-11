"""CONF-CI-002: the closed CI checkpoint record and the 3a81c8f view every older layer reads (owner decisions D1-D5).

The record names every path CONF-CI-001 and CONF-CI-002 deleted, changed or added, with exact after-pins and 3a81c8f
before-images. tracked_inventory checks the current tree against it first and then restores 3a81c8f for those paths;
every path the record does not name passes through unchanged for the older layers to check.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ci_002_successor_inventory",
                                              ROOT / "tests/platform/linux_baseline/_successor_inventory.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
BASE_FILES = 135
DELETED = {".github/workflows/verify.yml"}
BOOTSTRAP_CHANGED = {"ci/network_canary.py", "ci/run_packet_argv.py", "ci/verify-offline.sh"}
BOOTSTRAP_ADDED = {"ci/warm-source-isolation.sh", "task-packets/CONF-CI-001.yaml"}
CI_002_CHANGED = {"ci/zero_bill.py", "tests/meta/test_porting_zero_bill.py", "tests/parity/test_packet_runner.py",
                  "tests/fixes/runner_boundary/test_boundaries.py", "tests/platform/linux_baseline/_successor_inventory.py",
                  "tests/platform/linux_baseline/test_linux_inventory.py", "tests/live_backend/_inventory.py"}
CI_002_ADDED = {"ci/targets/conf-ci-002.json", "task-packets/CONF-CI-002.yaml", "tests/ci_checkpoint/test_conf_ci_002.py"}
DECISIONS = ["Q-M", "D1", "D2", "D3", "D4", "D5"]


def record():
    return HELPER.ci_002_record(ROOT)


def current():
    return HELPER.current_tracked_inventory(ROOT)


class CheckpointRecordTests(unittest.TestCase):
    def test_record_names_exactly_the_ci_admitted_paths_with_owner_decisions(self):
        value = record()
        self.assertEqual(set(value["deleted"]), DELETED)
        self.assertEqual(set(value["changed"]), BOOTSTRAP_CHANGED | CI_002_CHANGED)
        self.assertEqual(set(value["added"]), BOOTSTRAP_ADDED | CI_002_ADDED)
        self.assertEqual(value["baseCommit"], "3a81c8ffb17be9e288c4368d443c57361d5a4fc8")
        self.assertEqual(value["bootstrapCommit"], "9766c9cb02383968499a109c36f4b7a18ec532b0")
        self.assertEqual([row["id"] for row in value["ownerDecisions"]], DECISIONS)
        self.assertTrue(all(row["date"] == "2026-10-11" for row in value["ownerDecisions"]))
        self.assertEqual({path: entry["after"]["mode"] for path, entry in value["changed"].items() if path in BOOTSTRAP_CHANGED},
                         {"ci/network_canary.py": "100755", "ci/run_packet_argv.py": "100755", "ci/verify-offline.sh": "100755"})
        self.assertEqual(value["changed"]["ci/network_canary.py"]["before"]["mode"], "100644")
        self.assertEqual(value["changed"]["ci/run_packet_argv.py"]["before"]["mode"], "100644")

    def test_current_tree_carries_every_admitted_change_and_the_view_is_3a81c8f(self):
        rows, sources = current()
        self.assertEqual(len(rows), BASE_FILES - len(DELETED) + len(BOOTSTRAP_ADDED) + len(CI_002_ADDED) + 1)
        view_rows, view_sources = HELPER.tracked_inventory(ROOT)
        self.assertEqual(len(view_rows), BASE_FILES)
        paths = [row["path"] for row in view_rows]
        self.assertEqual(paths, sorted(paths, key=str.encode))
        view = {row["path"]: row for row in view_rows}
        self.assertTrue(DELETED <= set(view) and not (BOOTSTRAP_ADDED | CI_002_ADDED | {HELPER.CI_002_RECORD_PATH}) & set(view))
        for path, entry in {**record()["deleted"], **record()["changed"]}.items():
            with self.subTest(path=path):
                before = base64.b64decode(entry["beforeSourceBase64"])
                self.assertEqual(view_sources[path], before)
                self.assertEqual((view[path]["mode"], view[path]["size"], view[path]["sha256"]),
                                 (entry["before"]["mode"], len(before), hashlib.sha256(before).hexdigest()))
        untouched = {row["path"]: row for row in rows if row["path"] in view and row["path"] not in record()["changed"]}
        for path, row in untouched.items():
            self.assertEqual(view_sources[path], sources[path])
            self.assertEqual(view[path], row)

    def test_the_checkpoint_layer_keeps_the_record_digest_and_live_helper_pin_consistent(self):
        raw = (ROOT / HELPER.CI_002_RECORD_PATH).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), HELPER.CI_002_RECORD_SHA256)
        live = (ROOT / "tests/live_backend/_inventory.py").read_text(encoding="utf-8")
        helper = hashlib.sha256((ROOT / "tests/platform/linux_baseline/_successor_inventory.py").read_bytes()).hexdigest()
        self.assertIn('HELPER_SHA256 = "%s"' % helper, live)


class CheckpointRefusalTests(unittest.TestCase):
    def project(self, mutate):
        rows, sources = current()
        rows, sources = copy.deepcopy(rows), dict(sources)
        mutate(rows, sources)
        return HELPER.ci_002_project(ROOT, rows, sources)

    def assert_refused(self, mutate, message):
        with self.assertRaisesRegex(ValueError, "CONF-CI-002 checkpoint: " + message):
            self.project(mutate)

    def test_a_deleted_path_present_again_is_refused(self):
        def mutate(rows, sources):
            rows.append({"path": ".github/workflows/verify.yml", "mode": "100644", "size": 1, "sha256": "0" * 64,
                         "kind": "file", "nlink": 1, "linkedAncestry": False})
            sources[".github/workflows/verify.yml"] = b"x"
        self.assert_refused(mutate, "deleted path present")

    def test_a_missing_or_changed_admitted_path_is_refused(self):
        for path in sorted(BOOTSTRAP_ADDED | CI_002_ADDED | BOOTSTRAP_CHANGED | CI_002_CHANGED):
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

    def test_an_untracked_record_is_refused(self):
        self.assert_refused(lambda rows, sources: rows.__setitem__(slice(None), [row for row in rows if row["path"] != HELPER.CI_002_RECORD_PATH]),
                            "record tracked")
        # The record leaves the view, so its own mode is pinned here (review K1-2).
        self.assert_refused(lambda rows, sources: next(row for row in rows if row["path"] == HELPER.CI_002_RECORD_PATH).update(mode="100755"),
                            "record tracked")

    def test_a_changed_record_is_refused(self):
        with mock.patch.object(HELPER, "CI_002_RECORD_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "CONF-CI-002 checkpoint: record changed"):
                HELPER.tracked_inventory(ROOT)

    def test_a_reshaped_record_is_refused(self):
        raw = (ROOT / HELPER.CI_002_RECORD_PATH).read_bytes()
        original = HELPER.regular_bytes
        for change, message in ((lambda value: value.update(extra=1), "closed record"),
                                (lambda value: value.update(nativeAcceptance=True), "closed record"),
                                (lambda value: value["added"].update({"ci/zero_bill.py": value["added"]["ci/targets/conf-ci-002.json"]}),
                                 "each path named once"),
                                (lambda value: next(iter(value["changed"].values()))["before"].update(size=0), "before-image")):
            value = json.loads(raw)
            change(value)
            forged = json.dumps(value).encode()
            with self.subTest(message=message), mock.patch.object(HELPER, "CI_002_RECORD_SHA256", hashlib.sha256(forged).hexdigest()), \
                    mock.patch.object(HELPER, "regular_bytes", side_effect=lambda root, path: forged if path == HELPER.CI_002_RECORD_PATH else original(root, path)):
                with self.assertRaisesRegex(ValueError, "CONF-CI-002 checkpoint: " + message):
                    HELPER.ci_002_record(ROOT)


if __name__ == "__main__":
    unittest.main()
