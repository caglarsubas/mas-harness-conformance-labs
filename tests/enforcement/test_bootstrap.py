"""CONF-ENF-001 (W04-1): the enforcement test area's snapshots, independence attestations and toolchain record.

Standard library unittest only (owner decision Q-T1, 2026-10-11). Nothing here reads or runs an implementation.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AREA = ROOT / "tests/enforcement"
SNAPSHOTS = AREA / "snapshots"
MANIFEST = SNAPSHOTS / "manifest.json"
PLAN_PATH = "architecture/enforcement-test-plan/traceability.json"
# Review E1-4: the source commit and the plan's own digest are pinned here, not only by the manifest.
SOURCE_COMMIT = "a2eab9365c8663cc1ae23a666e864b821f600fa6"
# Owner decision Q-T10 (2026-10-13): manifest v2 pins each file's own source commit; the I05 v3 supplement comes from
# harness-onion 93d32e1 (packet 227), everything else from SOURCE_COMMIT.
SUPPLEMENT_COMMIT = "93d32e1cc5125b5878f51de31c61ada29e1fa6da"
PLAN_SHA256 = "762c2dfa4356b5ac59491fc51359dc4e6ef26f6a22f08c7cca6982c0b2979f72"
MANIFEST_FIELDS = {"schemaVersion", "sourceRepository", "root", "rule", "files"}
FILE_FIELDS = {"contract", "path", "sha256", "size", "sourceCommit"}
# Recorded gap (tests/enforcement/toolchains.json): the only non-stdlib import. CONF-ENF-002 closed G-I06-V1 by the
# recorded addition below, so no snapshotted model imports a sibling that is not snapshotted.
EXTERNAL_IMPORTS = {"scripts/i05_gate_channel_v3.py": {"jsonschema"}, "scripts/native_qualification_v3.py": {"jsonschema"}}
MISSING_SIBLINGS = {}
# Owner-decided additions to the plan's contract set, in manifest order after the plan's files. Review R1-3: each is
# pinned here by sha256 and size (a2eab93's bytes), as the plan pins its own files, not only by the manifest.
ADDITIONS = [("I06 backend profile v1 (recorded addition, owner decision Q-T5)", "scripts/i06_backend_profile.py",
              "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e", 44806),
             ("W01 amendment W02D input (recorded addition, owner decision Q-T7)", "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
              "8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4", 41971),
             ("W01 amendment W02D input (recorded addition, owner decision Q-T7)", "architecture/seccomp-allowlists/status.json",
              "08a541be25eb126d541a56242091eb953c8c7ec1c7fda8136ec47505fd0a6c0a", 4478)]
# Owner decision Q-T10: the I05 v3 supplement, pinned the same way, from its own source commit.
SUPPLEMENT = [("I05 gate channel v3 supplement (recorded addition, owner decision Q-T10)", "architecture/i05-gate-channel-v3-supplement/vectors.json",
               "1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac", 29077),
              ("I05 gate channel v3 supplement (recorded addition, owner decision Q-T10)", "architecture/i05-gate-channel-v3-supplement/status.json",
               "59c582724ad6621b8961f26b250c4badda440d0552703f138a20175472d8f35b", 763)]
# Owner decision Q-T13 (2026-10-13): the plan's obligation rows (E01-E12), the TG-05 basis (E07, E08, E11) and LEDGER-E01/
# E02's source, snapshotted from SOURCE_COMMIT after the supplement.
FEASIBILITY = [("Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)", "docs/alpha-2/ENFORCEMENT_FEASIBILITY.md",
                "9fac4492e1b5f6255993374a6642072855a5855a40bcc68706a25b78fd822965", 20359)]
# Owner decision Q-LC-4 (2026-10-18, CONF-ENF-009): the eight inputs the I06 v2 and native v3 replays read beyond the
# snapshots (closed gap G-REPLAY-INPUTS), snapshotted from SOURCE_COMMIT after the feasibility rows and pinned here too.
REPLAY_INPUTS = [
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/i06-backend-profile/vectors.json",
                  "b9c57d64eab03f307e10b02152426a10ebac2fd27102e27ef5873b5865be4cee", 155251),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/i06-backend-profile/writer-inventory.json",
                  "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077", 40914),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/i06-backend-profile/identity-closure.json",
                  "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb", 46703),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
                  "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e", 88532),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/native-profile-v2/vectors.json",
                  "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396", 481933),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/native-profile-v2/qualification.schema.json",
                  "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0", 65003),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/native-qualification-inputs/qualification.schema.json",
                  "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3", 37185),
                 ("G-REPLAY-INPUTS (recorded addition, owner decision Q-LC-4)", "architecture/native-qualification-inputs/vectors.json",
                  "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f", 212215)]
# The closed gap's readBy for each input, rewritten by CONF-ENF-009 to name the R12 replay that reads it (design review
# D3-2): identity-closure is read only by the I06 v2 RBAC-snapshot replay.
REPLAY_READERS = {
    "architecture/i06-backend-profile/vectors.json": "I06 v2 (its v1Vectors pin; the cross-version bases)",
    "architecture/i06-backend-profile/writer-inventory.json": "I06 v2",
    "architecture/i06-backend-profile/identity-closure.json": "I06 v2 (the RBAC-snapshot replays' closure)",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "I06 v2",
    "architecture/native-profile-v2/vectors.json": "I06 v2 and native v3",
    "architecture/native-profile-v2/qualification.schema.json": "native v3",
    "architecture/native-qualification-inputs/qualification.schema.json": "native v3",
    "architecture/native-qualification-inputs/vectors.json": "native v3",
}
# Area-local modules area code may import (CONF-ENF-002); _models.py is the one module allowed to load code by path.
AREA_MODULES = {"_models", "_catalog", "_probes", "tg01_contract", "tg02_lifecycle", "tg03_persistence", "tg04_host",
                "tg05_clocks", "tg08_compatibility", "."}
# Owner decision Q-T9 (2026-10-13): LEDGER-E09's subject is R12's own reader, imported by this one test module only.
SUBJECT_IMPORTS = {"tests/enforcement/tg02_lifecycle/test_reader_guards.py": {"harness_conformance"}}
PATH_LOADERS = {"tests/enforcement/_models.py"}
ALLOWED_TOP = set(sys.stdlib_module_names) | {"__future__"}
# Review E1-4/E2-1/E3-1: dynamic and path-based loading is reported too, called by name, as an attribute, through getattr
# with a constant name, or imported under another name. This is a best-effort static check, not a proof: a computed
# name or an indirect lookup can evade it, so review of each packet's diff remains the guard (review E3-1).
DYNAMIC_LOADERS = {"import_module", "spec_from_file_location", "exec_module", "run_path", "run_module", "SourceFileLoader"}
DYNAMIC_BUILTINS = {"__import__", "exec", "eval", "compile"}
# As an attribute or a getattr name, "compile" is re.compile and the like; the builtin alone loads nothing without exec.
DYNAMIC_ATTRS = DYNAMIC_LOADERS | DYNAMIC_BUILTINS - {"compile"}


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key " + key)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def left_by(packet, relative):
    """The pin of `relative` as `packet` left it: the after-pin of the latest record, up to `packet`'s own in the append-only
    registry, that added or changed it; None if none did or a later one deleted it (review D2-5)."""
    records = strict(regular(ROOT / "fixtures/ci/checkpoints.json"))["records"]
    ids = [row["packetId"] for row in records]
    found = None
    for row in records[:ids.index(packet) + 1]:
        record = strict(regular(ROOT / row["path"]))
        if relative in record.get("deleted", {}):
            found = None
        found = record["added"].get(relative) or record["changed"].get(relative, {}).get("after") or found
    return found


def regular(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("regular unlinked file required: %s" % path)
    return Path(path).read_bytes()


def manifest():
    return strict(regular(MANIFEST))


def plan():
    return strict(regular(SNAPSHOTS / "harness-onion" / PLAN_PATH))


def imported_tops(raw):
    """Top-level module names an AST imports; relative imports are reported as '.'."""
    tops = set()
    for node in ast.walk(ast.parse(raw)):
        if isinstance(node, ast.Import):
            tops |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            tops.add("." if node.level else node.module.split(".")[0])
            if any(alias.name in DYNAMIC_LOADERS | DYNAMIC_BUILTINS for alias in node.names):
                tops.add("<dynamic>")
        elif isinstance(node, ast.Call) and (getattr(node.func, "attr", None) in DYNAMIC_ATTRS
                                             or getattr(node.func, "id", None) in DYNAMIC_LOADERS | DYNAMIC_BUILTINS
                                             # Review E3-2: a constant loader name only counts as a getattr argument.
                                             or (getattr(node.func, "id", None) == "getattr"
                                                 and any(isinstance(arg, ast.Constant) and arg.value in DYNAMIC_ATTRS for arg in node.args))):
            tops.add("<dynamic>")
    return tops


def walk_files(top, skip=()):
    found = []
    for current, directories, files in os.walk(top, followlinks=False):
        directories[:] = sorted(d for d in directories if d != "__pycache__" and Path(current, d) not in skip)
        for name in directories + files:
            if stat.S_ISLNK(os.lstat(Path(current, name)).st_mode):
                raise ValueError("link in the enforcement area: %s" % Path(current, name))
        found += [Path(current, name) for name in files if not name.endswith(".pyc")]
    return sorted(found)


class SnapshotTests(unittest.TestCase):
    def test_manifest_is_closed_and_pins_every_snapshot_byte_exactly(self):
        value = manifest()
        self.assertEqual(set(value), MANIFEST_FIELDS)
        self.assertEqual(value["schemaVersion"], "r12.enforcement-snapshot-manifest/v2")
        self.assertEqual(value["sourceRepository"], "harness-onion")
        self.assertEqual(value["root"], "tests/enforcement/snapshots/harness-onion")
        paths = [row["path"] for row in value["files"]]
        self.assertEqual(len(paths), len(set(paths)))
        for row in value["files"]:
            with self.subTest(path=row["path"]):
                self.assertEqual(set(row), FILE_FIELDS)
                self.assertFalse(row["path"].startswith("/") or ".." in row["path"].split("/") or "\\" in row["path"])
                raw = regular(ROOT / value["root"] / row["path"])
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (row["size"], row["sha256"]))

    def test_snapshot_tree_holds_exactly_the_manifest_files(self):
        value = manifest()
        top = ROOT / value["root"]
        found = {path.relative_to(top).as_posix() for path in walk_files(top)}
        self.assertEqual(found, {row["path"] for row in value["files"]})
        self.assertEqual({path.name for path in SNAPSHOTS.iterdir()}, {"manifest.json", "harness-onion"})

    def test_manifest_is_exactly_the_plans_contract_set(self):
        source = plan()
        self.assertEqual(source["schemaVersion"], "planeon.internal.enforcement-test-plan/v1")
        self.assertEqual(source["planLabel"], "W04-0")
        self.assertEqual(hashlib.sha256(regular(SNAPSHOTS / "harness-onion" / PLAN_PATH)).hexdigest(), PLAN_SHA256)
        expected = [{"contract": "W04-0 enforcement test plan", "path": PLAN_PATH}]
        expected += [{"contract": contract["name"], "path": row["path"], "sha256": row["sha256"]}
                     for contract in source["contracts"] for row in contract["files"]]
        expected += [{"contract": contract, "path": path, "sha256": sha, "size": size} for contract, path, sha, size in ADDITIONS]
        expected = [dict(row, sourceCommit=SOURCE_COMMIT) for row in expected]
        expected += [{"contract": contract, "path": path, "sha256": sha, "size": size, "sourceCommit": SUPPLEMENT_COMMIT}
                     for contract, path, sha, size in SUPPLEMENT]
        expected += [{"contract": contract, "path": path, "sha256": sha, "size": size, "sourceCommit": SOURCE_COMMIT}
                     for contract, path, sha, size in FEASIBILITY + REPLAY_INPUTS]
        observed = [{key: row[key] for key in ("contract", "path", "sha256", "size", "sourceCommit") if key in expected[index]}
                    for index, row in enumerate(manifest()["files"])]
        self.assertEqual(observed, expected)
        self.assertEqual(len(expected), 37 + len(ADDITIONS) + len(SUPPLEMENT) + len(FEASIBILITY) + len(REPLAY_INPUTS))
        self.assertEqual(len(expected), 51)

    def test_reference_model_imports_are_exactly_the_recorded_gaps(self):
        value = manifest()
        models = {row["path"]: row for row in value["files"] if row["path"].endswith(".py")}
        self.assertEqual(len(models), 9)
        siblings = {Path(path).stem for path in models}
        external, missing = {}, {}
        for path in models:
            tops = imported_tops(regular(ROOT / value["root"] / path)) - ALLOWED_TOP - {"scripts"}
            outside = tops - {Path(path).stem for path in models} - set(MISSING_SIBLINGS.get(path, ()))
            if outside:
                external[path] = outside
            absent = (tops - siblings) & set(MISSING_SIBLINGS.get(path, ()))
            if absent:
                missing[path] = absent
        self.assertEqual(external, EXTERNAL_IMPORTS)
        self.assertEqual(missing, {path: set(names) for path, names in MISSING_SIBLINGS.items()})
        record = strict(regular(AREA / "toolchains.json"))
        # CONF-ENF-009 (owner decisions Q-LC-1..4): both gaps are closed. The models still import jsonschema, which the
        # child process provides; each closed row keeps the snapshots it binds.
        self.assertEqual(record["gaps"], [])
        closed = {row["id"]: row for row in record["closedGaps"]}
        self.assertEqual({name: row["snapshots"] for name, row in closed.items() if "snapshots" in row},
                         {"G-JSONSCHEMA": sorted(EXTERNAL_IMPORTS),
                          "G-REPLAY-INPUTS": ["scripts/i06_backend_profile_v2.py", "scripts/native_qualification_v3.py"]})
        # Review R1-5: the I06 v2 and native v3 replays need inputs beyond the model snapshots; they are now snapshotted.
        inputs = closed["G-REPLAY-INPUTS"]["missingInputs"]
        self.assertEqual([(row["path"], row["sha256"], row["size"]) for row in inputs],
                         [(path, sha, size) for _, path, sha, size in REPLAY_INPUTS])
        self.assertEqual({row["path"]: row["readBy"] for row in inputs}, REPLAY_READERS)
        files = {row["path"]: row for row in value["files"]}
        self.assertTrue(all((files[row["path"]]["sha256"], files[row["path"]]["size"]) == (row["sha256"], row["size"])
                            for row in inputs))
        self.assertEqual([(row["id"], row["closedBy"]) for row in record["closedGaps"]],
                         [("G-I06-V1", "Q-T5"), ("G-JSONSCHEMA", "Q-LC-1..4"), ("G-REPLAY-INPUTS", "Q-LC-1..4")])
        self.assertEqual({name: row["packet"] for name, row in closed.items()},
                         {"G-I06-V1": "CONF-ENF-002", "G-JSONSCHEMA": "CONF-ENF-009", "G-REPLAY-INPUTS": "CONF-ENF-009"})
        self.assertFalse({"decideIn", "affectsW04_2"} & {key for row in record["closedGaps"] for key in row})


class IndependenceTests(unittest.TestCase):
    def test_every_attestation_is_closed_with_the_plans_fields(self):
        fields = plan()["independence"]["attestationFields"]
        files = sorted((AREA / "attestations").iterdir())
        self.assertIn(AREA / "attestations/conf-enf-001.json", files)
        for path in files:
            with self.subTest(path=path.name):
                value = strict(regular(path))
                self.assertEqual(set(value), set(fields) | {"schemaVersion"})
                self.assertEqual(value["schemaVersion"], "r12.enforcement-independence-attestation/v1")
                self.assertEqual(path.name, value["packet"].lower() + ".json")
                self.assertIs(value["r10SourceRead"], False)
                self.assertIs(value["w03WorkInProgressRead"], False)
                self.assertIs(value["implementationReadOrRunForExpectedResults"], False)
                # Review E1-4: closed shapes and at least one digest-checked input.
                self.assertTrue(type(value["inputs"]) is list and value["inputs"] and all(type(row) is str and row for row in value["inputs"]))
                self.assertTrue(all(type(value[key]) is str and value[key] for key in ("lane", "reviewer")))
                self.assertTrue(type(value["inputDigests"]) is dict and value["inputDigests"])
                # An input digest is the file as that packet left it (CONF-ENF-002): its own checkpoint record's after-pin,
                # or, for an input the packet does not change, the after-pin of the latest earlier record in the registry
                # that added or changed it (review D1-3 of CONF-ENF-007).
                for relative, sha in value["inputDigests"].items():
                    pin = left_by(value["packet"], relative)
                    self.assertIsNotNone(pin, relative)
                    self.assertEqual(pin["sha256"], sha)

    def test_the_reader_never_imports_the_enforcement_area(self):
        for path in walk_files(ROOT / "src"):
            if path.suffix != ".py":
                continue
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                raw = regular(path)
                self.assertLessEqual(imported_tops(raw) - {"harness_conformance", "."}, ALLOWED_TOP)
                self.assertNotIn(b"enforcement/", raw)
                self.assertIsNone(re.search(rb"tests\.enforcement|\benforcement_tests\b", raw))

    def test_the_area_code_is_stdlib_only(self):
        for path in walk_files(AREA, skip=(SNAPSHOTS,)):
            if path.suffix != ".py":
                continue
            relative = path.relative_to(ROOT).as_posix()
            with self.subTest(path=relative):
                tops = imported_tops(regular(path)) - AREA_MODULES - SUBJECT_IMPORTS.get(relative, set())
                if relative in PATH_LOADERS:
                    tops.discard("<dynamic>")
                self.assertLessEqual(tops, ALLOWED_TOP)


class DetectorTests(unittest.TestCase):
    def test_dynamic_loading_is_reported_in_every_call_form(self):
        for source in ("__import__('jsonschema')", "import builtins\nbuiltins.__import__('jsonschema')",
                       "import importlib\nimportlib.import_module('jsonschema')", "exec('import jsonschema')",
                       "import builtins\nbuiltins.exec('import jsonschema')", "import importlib\ngetattr(importlib, 'import_module')('x')",
                       "import importlib.util\nimportlib.util.spec_from_file_location('m', 'p.py')", "import runpy\nrunpy.run_path('p.py')"):
            with self.subTest(source=source):
                self.assertIn("<dynamic>", imported_tops(source.encode()))
        for source in ("from importlib import import_module as im\nim('jsonschema')", "from builtins import __import__ as imp"):
            with self.subTest(source=source):
                self.assertIn("<dynamic>", imported_tops(source.encode()))
        for source in ("import re\nre.compile('x')", "print('eval')", "assert 'exec' == 'exec'"):
            with self.subTest(source=source):
                self.assertNotIn("<dynamic>", imported_tops(source.encode()))


class ToolchainTests(unittest.TestCase):
    def test_the_toolchain_record_holds_the_owner_amendments(self):
        value = strict(regular(AREA / "toolchains.json"))
        self.assertEqual(set(value), {"schemaVersion", "packet", "planDecision", "amendments", "toolchains", "gaps", "closedGaps"})
        tool = next(row for row in plan()["ownerDecisions"] if row["id"] == "D-TOOL")
        self.assertEqual(value["planDecision"], {key: tool[key] for key in ("id", "date", "decision")})
        self.assertEqual([(row["id"], row["date"]) for row in value["amendments"]],
                         [("Q-T1", "2026-10-11"), ("Q-T2", "2026-10-11"), ("Q-T4", "2026-10-11"), ("Q-T5", "2026-10-11"),
                          ("Q-T2-B", "2026-10-13"), ("Q-T2-TOOL", "2026-10-13"), ("Q-LC-1", "2026-10-18"),
                          ("Q-LC-2", "2026-10-18"), ("Q-LC-3", "2026-10-18"), ("Q-LC-4", "2026-10-18")])
        states = {row["id"]: row["state"] for row in value["toolchains"]}
        # Owner decision Q-T2 (b) (2026-10-13): the probe source is checked by the stdlib gates; it compiles only on the
        # author's machine until the R12 Rust profile exists.
        self.assertEqual(states, {"python-stdlib-unittest": "IN_USE", "rust-musl-static-probes": "SOURCE_ONLY",
                                  "python-met-001-child": "IN_USE"})
        # CONF-ENF-009 (Q-LC-2, AGENTS rule 16): the child interpreter is the third row, pinned, not a dependency.
        self.assertEqual([row["id"] for row in value["toolchains"]],
                         ["python-stdlib-unittest", "rust-musl-static-probes", "python-met-001-child"])
        self.assertEqual(value["toolchains"][2]["decidedBy"], "Q-LC-2")
        self.assertIs(value["toolchains"][1]["installed"], False)
        self.assertEqual(value["toolchains"][0]["dependencies"], [])

    def test_the_area_runs_as_one_offline_command(self):
        runner = strict(regular(AREA / "toolchains.json"))["toolchains"][0]["runner"]
        packet = regular(ROOT / "task-packets/CONF-ENF-001.yaml").decode()
        line = next(line for line in packet.splitlines() if line.startswith("offlineAcceptanceCommands: "))
        commands = strict(line.split(": ", 1)[1])
        self.assertEqual(commands[-1], runner)
        self.assertEqual(len(commands), 13)

    def test_no_dependency_is_added(self):
        self.assertIn("dependencies = []", regular(ROOT / "pyproject.toml").decode())
        self.assertEqual(strict(regular(ROOT / "toolchain.lock"))["dependencies"], [])


if __name__ == "__main__":
    unittest.main()
