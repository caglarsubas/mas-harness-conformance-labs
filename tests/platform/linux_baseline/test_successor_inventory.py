"""Twenty independent source regressions; stage-six replacement is inert bytes."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("successor_test_helper", Path(__file__).with_name("_successor_inventory.py"))
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
FIXTURE = json.loads((ROOT / HELPER.FIXTURE_PATH).read_bytes())
RECORD = FIXTURE["record"]
BASELINE = json.loads(FIXTURE["baselineRaw"])
COUNTS = (110, 120, 127, 135, 141, 146, 151)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def vector(stage):
    # Independent expected vectors: no production/helper transformation routine.
    rows = {path: {"path": path, "mode": value["mode"], "size": value["size"], "sha256": value["sha256"],
                   "kind": "file", "nlink": 1, "linkedAncestry": False} for path, value in BASELINE["files"].items()}
    corrected = FIXTURE["testBefore"].encode()
    for hunk in RECORD["change"]["hunks"]:
        corrected = corrected.replace(hunk["beforeBlock"].encode(), hunk["afterBlock"].encode(), 1)
    rows[RECORD["change"]["path"]].update(size=len(corrected), sha256=sha(corrected))
    additions = set(RECORD["repairPaths"])
    for step in RECORD["stages"][:stage]:
        additions.update(step["paths"])
    for path in additions - set(rows):
        raw = ("INERT UNIT VECTOR: " + path + "\n").encode()
        rows[path] = {"path": path, "mode": "100644", "size": len(raw), "sha256": sha(raw),
                      "kind": "file", "nlink": 1, "linkedAncestry": False}
    after, proof = FIXTURE["launcherBefore"].encode(), None
    if stage == 6:
        hook = RECORD["hook"]
        # This fake replacement is never imported, compiled, evaluated or run.
        replacement = "        result = {\"status\": \"NOT_RUN_ENV_UNAVAILABLE\"}\n"
        after = after.replace(hook["beforeBlock"].encode(), replacement.encode(), 1)
        proof = {"schemaVersion": hook["proofSchemaVersion"], "evidenceClass": "SOURCE_DELTA_ONLY",
                 **{k: hook[k] for k in ("packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256")},
                 "replacement": replacement, "afterSha256": sha(after)}
        rows[hook["path"]].update(size=len(after), sha256=sha(after))
    return [list(rows.values()), after, proof]


def proof_document(proof):
    return b"# Unit source only\n\n```harness-launcher-source-proof\n" + json.dumps(proof).encode() + b"\n```\n"


COLLECTIBLE = "import unittest\nclass Check(unittest.TestCase):\n    def test_present(self):\n        pass\n"


class SuccessorInventoryTests(unittest.TestCase):
    def test_all_seven_complete_stage_vectors(self):
        for stage, count in enumerate(COUNTS):
            with self.subTest(stage=stage):
                result = HELPER.validate_composition(*vector(stage))
                self.assertEqual(result, {"stage": stage, "baselineFiles": 106, "trackedFiles": count,
                                          "evidenceClass": "SOURCE_INVENTORY_ONLY", "nativeAcceptance": False})

    def test_current_repository(self):
        result = HELPER.verify_repository(ROOT)
        self.assertEqual(result["trackedFiles"], COUNTS[result["stage"]])
        self.assertEqual(result["baselineFiles"], 106)
        self.assertFalse(result["nativeAcceptance"])

    def test_current_test_guard_not_exempt(self):
        _, historical_sources, _ = HELPER.performance_current(ROOT)
        path = RECORD["change"]["path"]
        self.assertEqual(sha(historical_sources[path]), "e1491e4407ff6d221871b45bbd775beb28afba11d418ae001847a512bb4b6fe6")
        for stage in range(7):
            args = vector(stage)
            next(row for row in args[0] if row["path"] == path)["sha256"] = RECORD["change"]["beforeSha256"]
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                HELPER.validate_composition(*args)

    def test_every_missing_stage_path_refuses(self):
        for stage in range(7):
            original = vector(stage)
            for i, row in enumerate(original[0]):
                args = deepcopy(original)
                args[0].pop(i)
                with self.subTest(stage=stage, path=row["path"]), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)

    def test_exact_scalar_test_patch(self):
        _, historical_sources, _ = HELPER.performance_current(ROOT)
        before = FIXTURE["testBefore"].encode()
        after = HELPER.corrected_test(before)
        self.assertEqual(after, historical_sources[RECORD["change"]["path"]])
        self.assertEqual(len(RECORD["change"]["hunks"]), 3)
        methods = lambda raw: re.findall(rb"^    def (test_[A-Za-z0-9_]+)\(", raw, re.M)
        self.assertEqual(methods(before), methods(after))
        self.assertEqual(len(methods(after)), 30)
        restored = after
        for hunk in reversed(RECORD["change"]["hunks"]):
            restored = restored.replace(hunk["afterBlock"].encode(), hunk["beforeBlock"].encode(), 1)
        self.assertEqual(restored, before)
        for raw in (before + b"\n", before[:-1], b"", None, before.decode()):
            with self.subTest(raw=type(raw).__name__), self.assertRaises(ValueError):
                HELPER.corrected_test(raw)

    def test_fixture_tamper_and_duplicate_json_refuse(self):
        raw = (ROOT / HELPER.FIXTURE_PATH).read_bytes()
        self.assertEqual(sha(raw), "44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86")
        for bad in (raw + b"\n", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"\xff", b"[]", None,
                    raw.replace(b'"nativeAcceptance": false', b'"nativeAcceptance": true', 1)):
            with self.subTest(value=str(bad)[:30]), self.assertRaises((ValueError, UnicodeError)):
                HELPER.load_fixture(bad)

    def test_hook_prefix_suffix_and_replacement_tamper_refuse(self):
        for operation in ("prefix", "suffix", "old", "missing", "extra"):
            args = vector(6)
            if operation == "prefix": args[1] = b"# altered\n" + args[1]
            elif operation == "suffix": args[1] += b"\n"
            elif operation == "old": args[1] = FIXTURE["launcherBefore"].encode()
            elif operation == "missing": del args[2]["replacement"]
            else: args[2]["executionAuthorized"] = "true"
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                HELPER.validate_composition(*args)
        bad_replacements = ("", "pass\n", "        pass", "        pass\r\n", "        \0\n", "        é\n",
                            "        " + "x" * 8192 + "\n", RECORD["hook"]["beforeBlock"], "        pass\npass\n")
        for replacement in bad_replacements:
            args = vector(6)
            args[2]["replacement"] = replacement
            with self.subTest(replacement=replacement[:40]), self.assertRaises(ValueError):
                HELPER.validate_composition(*args)

    def test_hook_proof_identity_digest_type_and_scope_refuse(self):
        for field in vector(6)[2]:
            for value in ("WRONG", None, True, 1, [], {}):
                args = vector(6)
                args[2][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)
        document = proof_document(vector(6)[2])
        bad = (b"", document + document, document[:-5], b"x" * 262145,
               document[:-4] + b"```garbage\n", document[:-4] + b"```\r\n",
               b"inline " + document[document.index(b"```"):],
               b'```harness-launcher-source-proof\n{"x":1,"x":2}\n```\n',
               b'```harness-launcher-source-proof\n{"x":NaN}\n```\n',
               b'```harness-launcher-source-proof\n' + b" " * 16385 + b'{}\n```\n')
        for raw in bad:
            with self.subTest(document=raw[:50]), self.assertRaises(ValueError):
                HELPER.parse_hook_proof(raw)

    def test_old_guard_rejects_legitimate_stage_one(self):
        # Reproduce only the frozen set predicate, not execution of old snapshots.
        frozen = set(BASELINE["files"])
        draft_only = frozen | set(RECORD["stages"][0]["paths"])
        self.assertEqual(len(draft_only), 116)
        self.assertNotEqual(frozen, draft_only)
        self.assertIn('self.assertEqual(set(files), set(BASELINE["files"]) | ADDED_PATHS)', FIXTURE["testBefore"])
        self.assertEqual(HELPER.validate_composition(*vector(1))["trackedFiles"], 120)
        self.assertEqual(RECORD["diagnosis"]["class"], "SOURCE_INSPECTION_ONLY")
        self.assertEqual(RECORD["diagnosis"]["testsExecuted"], 0)

    def test_original_106_file_and_150_test_history(self):
        _, historical_sources, _ = HELPER.performance_current(ROOT)
        historical = json.loads(BASELINE["historical103Raw"])
        self.assertEqual(sha(BASELINE["historical103Raw"].encode()), BASELINE["historical103Sha256"])
        self.assertEqual((len(historical["files"]), sum(map(len, historical["tests"].values()))), (103, 120))
        self.assertEqual((len(BASELINE["files"]), sum(map(len, BASELINE["tests"].values()))), (106, 150))
        for path, ids in historical["tests"].items():
            self.assertEqual(BASELINE["tests"][path], ids)
        self.assertEqual(BASELINE["commit"], "8519225b1564834fab5bcd001c263688e6fba7fe")
        self.assertEqual(FIXTURE["authority"]["commit"], "3b1ea6b9b8514fbb51e37ba4703f5d06298bd938")
        self.assertEqual(RECORD["checkpoint"]["ci"]["runId"], 34137197794)
        self.assertEqual(RECORD["checkpoint"]["mainReplay"]["tests"], 150)
        for path, checksum in RECORD["checkpoint"]["inventory"]["exactEdits"].items():
            self.assertEqual(sha(historical_sources[path]), checksum)

    def test_original_test_ids_and_new_tests_collected(self):
        observed = HELPER.verify_tests(ROOT)
        self.assertEqual(sum(map(len, observed.values())), 170)
        self.assertEqual(len(observed[HELPER.NEW_TEST_PATH]), 20)
        self.assertEqual(observed[HELPER.NEW_TEST_PATH], sorted(RECORD["repairTestIds"]))
        # Same basename in different roots must not reuse sys.modules entries.
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            for i in range(2):
                root = parent / str(i)
                root.mkdir()
                source = ("from harness_conformance.errors import ConformanceError\n"
                          + COLLECTIBLE.replace("test_present", "test_root_" + str(i)))
                (root / "test_collision.py").write_text(source)
                self.assertEqual(HELPER.discover_inventory(root), {"test_collision.py": ["Check.test_root_" + str(i)]})
        print("successor-test-inventory roots=5 predecessor=150 added=20 skipped=0 status=PASS", flush=True)

    def test_out_of_order_and_partial_stages_refuse(self):
        final_rows = {row["path"]: row for row in vector(6)[0]}
        for stage in range(1, 7):
            paths = set(RECORD["stages"][stage - 1]["paths"]) - set(BASELINE["files"])
            if stage > 1:
                args = vector(0)
                args[0].extend(final_rows[p] for p in paths)
                with self.subTest(out_of_order=stage), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)
            for added_count in range(1, len(paths)):
                args = vector(stage - 1)
                args[0].extend(final_rows[p] for p in sorted(paths)[:added_count])
                with self.subTest(partial_stage=stage, added=added_count), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)

    def test_predecessor_hash_size_and_mode_tampering_refuses(self):
        original = vector(0)
        for i, row in enumerate(original[0]):
            if row["path"] not in BASELINE["files"]:
                continue
            for field, value in (("sha256", "0" * 64), ("size", row["size"] + 1),
                                 ("mode", "100644" if row["mode"] == "100755" else "100755")):
                args = deepcopy(original)
                args[0][i][field] = value
                with self.subTest(path=row["path"], field=field), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)
        for row in original[0]:
            if row["path"] not in BASELINE["files"]:
                args = deepcopy(original)
                next(r for r in args[0] if r["path"] == row["path"])["mode"] = "100755"
                with self.subTest(new_mode=row["path"]), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)

    def test_premature_hook_or_proof_refuses(self):
        for stage in range(6):
            for operation in ("proof", "bytes", "both"):
                args = vector(stage)
                if operation in ("proof", "both"): args[2] = vector(6)[2]
                if operation in ("bytes", "both"): args[1] += b"\n"
                with self.subTest(stage=stage, operation=operation), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)

    def test_presence_or_environment_does_not_authorize(self):
        environment = {"HARNESS_SUCCESSOR_STAGE": "6", "HARNESS_LIVE_SESSION": "verified",
                       "HARNESS_NATIVE_ACCEPTANCE": "PASS", "SOURCE_PROOF_VERIFIED": "1"}
        with mock.patch.dict(os.environ, environment):
            self.assertEqual(HELPER.validate_composition(*vector(0))["stage"], 0)
            for stage in range(1, 7):
                args = vector(stage)
                args[0].pop()
                with self.subTest(stage=stage), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)
            args = vector(6)
            args[2] = {"verified": True}
            with self.assertRaises(ValueError):
                HELPER.validate_composition(*args)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            # Presence of plausible paths in a non-repository is not authority.
            (root / "qualification.md").write_bytes(proof_document(vector(6)[2]))
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                HELPER.verify_repository(root)

    def test_source_evidence_is_never_native_acceptance(self):
        for stage in range(7):
            result = HELPER.validate_composition(*vector(stage))
            self.assertIs(result["nativeAcceptance"], False)
            self.assertEqual(result["evidenceClass"], "SOURCE_INVENTORY_ONLY")
            self.assertEqual(set(result), {"stage", "baselineFiles", "trackedFiles", "evidenceClass", "nativeAcceptance"})
        self.assertIs(FIXTURE["nativeAcceptance"], False)
        self.assertIs(RECORD["hook"]["runtimeAuthority"], False)
        self.assertEqual(RECORD["dispatchGate"]["requiresCompletedPacket"], "CONF-FIX-003")
        self.assertFalse(RECORD["dispatchGate"]["rewritePacketYaml"])

    def test_stage_six_requires_exact_hook_proof(self):
        args = vector(6)
        proof = HELPER.parse_hook_proof(proof_document(args[2]))
        self.assertEqual(proof, args[2])
        self.assertEqual(proof["evidenceClass"], "SOURCE_DELTA_ONLY")
        self.assertEqual(HELPER.validate_composition(args[0], args[1], proof)["stage"], 6)
        for missing in (None, {}, "verified"):
            with self.subTest(proof=missing), self.assertRaises(ValueError):
                HELPER.validate_composition(args[0], args[1], missing)

    def test_symlinks_hardlinks_and_nonregular_files_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            good = root / "regular"
            good.write_bytes(b"inert source")
            self.assertEqual(HELPER.regular_bytes(root, "regular"), b"inert source")
            (root / "symbolic").symlink_to(good)
            os.link(good, root / "hard")
            (root / "directory").mkdir()
            os.mkfifo(root / "fifo")
            (root / "linked-parent").symlink_to(root / "directory", target_is_directory=True)
            (root / "directory" / "child").write_bytes(b"inert")
            for path in ("regular", "hard", "symbolic", "directory", "fifo", "linked-parent/child"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    HELPER.regular_bytes(root, path)
            with self.assertRaises(ValueError):
                HELPER.regular_bytes(root / "linked-parent", "child")
        for field, value in (("kind", "symlink"), ("kind", "fifo"), ("kind", "directory"), ("nlink", 2),
                             ("nlink", True), ("linkedAncestry", True), ("linkedAncestry", 0)):
            args = vector(0)
            args[0][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                HELPER.validate_composition(*args)

    def test_test_omissions_skips_and_xfails_refuse(self):
        variants = {
            "empty": "",
            "filtered": COLLECTIBLE + "\ndef load_tests(loader, suite, pattern):\n    return unittest.TestSuite()\n",
            "duplicate": COLLECTIBLE + "\ndef load_tests(loader, suite, pattern):\n    return unittest.TestSuite([suite, suite])\n",
            "skipped": COLLECTIBLE.replace("    def test_present", "    @unittest.skip('unit')\n    def test_present"),
            "class_skipped": COLLECTIBLE.replace("class Check", "@unittest.skip('unit')\nclass Check"),
            "xfail": COLLECTIBLE.replace("    def test_present", "    @unittest.expectedFailure\n    def test_present"),
            "deselected": COLLECTIBLE + "\ndel Check.test_present\n",
            "substituted": COLLECTIBLE + "\nfrom other import Check\n",
            "duplicate_method": COLLECTIBLE + "    def test_present(self):\n        pass\n",
            "namespace": COLLECTIBLE,
        }
        for name, source in variants.items():
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                target = root
                if name == "namespace":
                    target = root / "without_init"
                    target.mkdir()
                if name == "substituted": (root / "other.py").write_text(COLLECTIBLE)
                (target / "test_vector.py").write_text(source)
                with self.subTest(mutation=name), self.assertRaises(ValueError):
                    HELPER.discover_inventory(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.assertRaises(ValueError):
                HELPER.discover_inventory(root)
            with self.assertRaises(ValueError):
                HELPER.discover_inventory(root / "missing")
        # Even a coherent shortened collector result cannot replace pinned IDs.
        with mock.patch.object(HELPER, "discover_inventory", return_value={"test_omitted.py": ["Fake.test_one"]}):
            with self.assertRaises(ValueError):
                HELPER.verify_tests(ROOT)

    def test_unknown_duplicate_and_traversal_paths_refuse(self):
        for stage in range(7):
            for operation in ("unknown", "duplicate", "equal_count_substitution"):
                args = vector(stage)
                row = dict(args[0][0])
                if operation != "duplicate": row["path"] = "unapproved.txt"
                if operation == "equal_count_substitution": args[0].pop()
                args[0].append(row)
                with self.subTest(stage=stage, operation=operation), self.assertRaises(ValueError):
                    HELPER.validate_composition(*args)
        bad_fields = (("path", "../escape"), ("path", "/absolute"), ("path", "a//b"), ("path", "a/./b"),
                      ("path", "a\\b"), ("path", "a\0b"), ("path", None), ("size", True), ("size", -1),
                      ("size", 16777217), ("sha256", None), ("mode", "120000"))
        for field, value in bad_fields:
            args = vector(0)
            args[0][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                HELPER.validate_composition(*args)
        for operation in ("missing_field", "extra_field", "row_type", "rows_type"):
            args = vector(0)
            if operation == "missing_field": del args[0][0]["mode"]
            elif operation == "extra_field": args[0][0]["verified"] = True
            elif operation == "row_type": args[0][0] = None
            else: args[0] = {}
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                HELPER.validate_composition(*args)
