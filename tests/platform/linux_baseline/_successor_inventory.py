"""Test-only cumulative source accounting. Inert snapshots are never executed.

Stage recognition describes reviewed source ownership, not permission to execute
or a safety certificate for the eventual launcher replacement.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_PATH = "fixtures/platform/linux-baseline/successor-inventory.json"
FIXTURE_SHA256 = "44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86"
AUTHORITY_SHA256 = "491c3ee536b0be231be7f29e3580f357659c7012ec54077268e23aa1f08f48e0"
NEW_TEST_PATH = "tests/platform/linux_baseline/test_successor_inventory.py"
ROW_FIELDS = {"path", "mode", "size", "sha256", "kind", "nlink", "linkedAncestry"}
PROOF_FIELDS = {"schemaVersion", "evidenceClass", "packetId", "packetSha256", "path",
                "beforeSha256", "prefixSha256", "suffixSha256", "replacement", "afterSha256"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def nonfinite(_):
    raise ValueError("nonfinite JSON number")


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def canonical_path(relative):
    if (type(relative) is not str or not relative or relative.startswith("/")
            or "\\" in relative or any(ord(c) < 32 or ord(c) == 127 for c in relative)
            or any(p in ("", ".", "..") for p in relative.split("/"))):
        raise ValueError("canonical relative path required")
    return relative.split("/")


def checked_directory(root):
    root = Path(root)
    if not root.is_absolute() or any(p in (".", "..") for p in root.parts):
        raise ValueError("absolute canonical root required")
    for path in reversed((root, *root.parents)):
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError("linked or non-directory ancestry")
    return root


def regular_bytes(root, relative):
    path = checked_directory(root)
    parts = canonical_path(relative)
    for part in parts[:-1]:
        path /= part
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError("linked source ancestor")
    path /= parts[-1]
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 16777216:
        raise ValueError("bounded regular unlinked source required")
    # Refuse last-component replacement and recheck inode custody after reading.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(opened) != identity(before):
            raise ValueError("source changed before read")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(16777217)
        after = os.fstat(fd)
        if (len(raw) != before.st_size or len(raw) > 16777216
                or identity(after) != identity(opened) or identity(path.lstat()) != identity(opened)):
            raise ValueError("source changed during read")
    finally:
        os.close(fd)
    checked_directory(path.parent)
    return raw


def load_fixture(raw):
    if type(raw) is not bytes or len(raw) > 1048576:
        raise ValueError("bounded fixture bytes required")
    fixture = parse(raw)
    if digest(raw) != FIXTURE_SHA256 or digest(canonical(fixture["record"])) != AUTHORITY_SHA256:
        raise ValueError("unreviewed fixture or authority")
    record = fixture["record"]
    for name, authority_path in (("baselineRaw", "baseline.json"), ("testBefore", "test_packet_scalars.before.txt"),
                                 ("launcherBefore", "live_launcher.before.txt")):
        if digest(fixture[name].encode()) != record["inputFiles"]["architecture/successor-inventory-inputs/" + authority_path]:
            raise ValueError("historical input bytes changed")
    return fixture


FIXTURE = load_fixture(regular_bytes(ROOT, FIXTURE_PATH))
RECORD = FIXTURE["record"]
BASELINE = parse(FIXTURE["baselineRaw"])


def corrected_test(before):
    """Apply three fixed byte hunks only; no parsing or execution of snapshots."""
    change = RECORD["change"]
    if type(before) is not bytes or digest(before) != change["beforeSha256"]:
        raise ValueError("wrong historical test bytes")
    result = before
    for hunk in change["hunks"]:
        old, new = hunk["beforeBlock"].encode(), hunk["afterBlock"].encode()
        if result.count(old) != 1:
            raise ValueError("nonunique test hunk")
        prefix, suffix = result.split(old)
        if digest(prefix) != hunk["prefixSha256"] or digest(suffix) != hunk["suffixSha256"]:
            raise ValueError("test context changed")
        result = prefix + new + suffix
    if digest(result) != change["afterSha256"]:
        raise ValueError("unapproved test delta")
    return result


def parse_hook_proof(document):
    if type(document) is not bytes or len(document) > 262144:
        raise ValueError("bounded qualification document required")
    lines = document.split(b"\n")
    marker = b"```harness-launcher-source-proof"
    if document.count(marker) != 1 or lines.count(marker) != 1:
        raise ValueError("one exact source proof opening fence required")
    following = lines[lines.index(marker) + 1:]
    closing = next((i for i, line in enumerate(following) if line.startswith(b"```")), None)
    if closing is None or following[closing] != b"```":
        raise ValueError("one exact source proof closing fence required")
    raw = b"\n".join(following[:closing])
    if len(raw) > 16384:
        raise ValueError("source proof too large")
    proof = parse(raw)
    if type(proof) is not dict or set(proof) != PROOF_FIELDS or any(type(v) is not str for v in proof.values()):
        raise ValueError("closed string-only proof required")
    return proof


def validate_hook(after, proof):
    hook = RECORD["hook"]
    if type(after) is not bytes or type(proof) is not dict or set(proof) != PROOF_FIELDS:
        raise ValueError("closed proof and current launcher bytes required")
    if any(type(v) is not str for v in proof.values()) or len(canonical(proof)) > hook["maxProofBytes"]:
        raise ValueError("bounded string-only proof required")
    expected = {"schemaVersion": hook["proofSchemaVersion"], "evidenceClass": "SOURCE_DELTA_ONLY",
                **{k: hook[k] for k in ("packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256")}}
    if any(proof[k] != v for k, v in expected.items()):
        raise ValueError("source proof identity or scope mismatch")
    before, old = FIXTURE["launcherBefore"].encode(), hook["beforeBlock"].encode()
    if digest(before) != hook["beforeSha256"] or before.count(old) != 1:
        raise ValueError("wrong launcher history")
    prefix, suffix = before.split(old)
    replacement = proof["replacement"].encode("ascii")
    if (not replacement or len(replacement) > 8192 or replacement == old
            or b"\r" in replacement or b"\0" in replacement or not replacement.endswith(b"\n")
            or any(line and not line.startswith(b"        ") for line in replacement.splitlines())):
        raise ValueError("unapproved replacement region")
    if (digest(prefix) != hook["prefixSha256"] or digest(suffix) != hook["suffixSha256"]
            or after != prefix + replacement + suffix or digest(after) != proof["afterSha256"]):
        raise ValueError("source delta changed protected bytes")


def validate_composition(rows, launcher_after, proof=None):
    """Pure closed-row/byte check; no caller-selected stage or execution flag."""
    if type(rows) is not list or type(launcher_after) is not bytes:
        raise ValueError("inventory rows and launcher bytes required")
    historical_rows = None
    if type(proof) is dict and set(proof) == {"performanceSources", "hookProof"}:
        historical_rows, _, _ = performance_history(rows, proof["performanceSources"])
        proof = proof["hookProof"]
    observed = {}
    for row in rows:
        if type(row) is not dict or set(row) != ROW_FIELDS:
            raise ValueError("closed inventory row required")
        path = row["path"]
        canonical_path(path)
        if (path in observed or row["kind"] != "file" or type(row["nlink"]) is not int or row["nlink"] != 1
                or row["linkedAncestry"] is not False or row["mode"] not in ("100644", "100755")
                or type(row["size"]) is not int or not 0 <= row["size"] <= 16777216
                or type(row["sha256"]) is not str or not re.fullmatch("[0-9a-f]{64}", row["sha256"])):
            raise ValueError("duplicate, linked or malformed source row")
        observed[path] = row
    paths = set(BASELINE["files"]) | set(RECORD["repairPaths"])
    matches = []
    for stage in range(7):
        if stage:
            paths.update(RECORD["stages"][stage - 1]["paths"])
        if paths == set(observed):
            matches.append(stage)
    if len(matches) != 1:
        raise ValueError("only complete ordered stage prefixes permitted")
    stage = matches[0]
    if len(observed) != RECORD["stageCounts"][stage]:
        raise ValueError("stage count mismatch")
    if stage < 6:
        if proof is not None or launcher_after != FIXTURE["launcherBefore"].encode():
            raise ValueError("premature hook or proof")
    else:
        validate_hook(launcher_after, proof)
    # Actual custody and complete delta were checked above; only the legacy
    # byte comparisons use this explicit historical view, never collection.
    comparisons = {r["path"]: r for r in historical_rows} if historical_rows is not None else observed
    corrected = corrected_test(FIXTURE["testBefore"].encode())
    for path, expected in BASELINE["files"].items():
        size, sha = expected["size"], expected["sha256"]
        if path == RECORD["change"]["path"]:
            size, sha = len(corrected), digest(corrected)
        elif path == RECORD["hook"]["path"]:
            size, sha = len(launcher_after), digest(launcher_after)
        if tuple(comparisons[path][k] for k in ("mode", "size", "sha256")) != (expected["mode"], size, sha):
            raise ValueError("predecessor changed: " + path)
    if any(observed[p]["mode"] != "100644" for p in set(observed) - set(BASELINE["files"])):
        raise ValueError("new source must be non-executable")
    return {"stage": stage, "baselineFiles": 106, "trackedFiles": len(observed),
            "evidenceClass": "SOURCE_INVENTORY_ONLY", "nativeAcceptance": False}


def tracked_inventory(root):
    root = checked_directory(root)
    env = {"PATH": os.defpath, "LANG": "C", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}
    def git(*args):
        result = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                                cwd=root, env=env, capture_output=True, check=True, timeout=30)
        return result.stdout
    if git("rev-parse", "--show-toplevel").decode().rstrip("\n") != str(root):
        raise ValueError("exact repository root required")
    rows, sources, seen = [], {}, set()
    for entry in git("ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.decode().split("\t", 1)
        mode, oid, index_stage = metadata.split(" ")
        canonical_path(path)
        if path in seen or index_stage != "0" or mode not in ("100644", "100755") or not re.fullmatch("[0-9a-f]{40,64}", oid):
            raise ValueError("duplicate, conflicted or nonregular index entry")
        seen.add(path)
        raw = regular_bytes(root, path)
        info = (root / path).lstat()
        disk_mode = "100755" if info.st_mode & 0o111 else "100644"
        if mode != disk_mode or info.st_nlink != 1:
            raise ValueError("index/disk mode or link mismatch")
        sources[path] = raw
        rows.append({"path": path, "mode": disk_mode, "size": len(raw), "sha256": digest(raw),
                     "kind": "file", "nlink": info.st_nlink, "linkedAncestry": False})
    if not rows:
        raise ValueError("empty tracked inventory")
    return rows, sources


def leaves(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from leaves(item)
        else:
            yield item


def collect_in_child(root):
    """Only current on-disk test modules are parsed/imported, never snapshots."""
    root = checked_directory(root)
    expected = {}
    for path in sorted(root.rglob("test_*.py")):
        relative = path.relative_to(root).as_posix()
        tree = ast.parse(regular_bytes(root, relative), filename=str(path))
        methods = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "load_tests":
                raise ValueError("load_tests may not control collection")
            if isinstance(node, ast.ClassDef):
                methods.extend(node.name + "." + method.name for method in node.body
                               if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_"))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                methods.append(node.name)
        if not methods or len(methods) != len(set(methods)):
            raise ValueError("empty or duplicate AST test inventory")
        expected[relative] = sorted(methods)
    if not expected:
        raise ValueError("empty test root")
    loader = unittest.TestLoader()
    with contextlib.redirect_stdout(sys.stderr):
        suite = loader.discover(str(root), pattern="test_*.py")
    tests = list(leaves(suite))
    if loader.errors or not tests or suite.countTestCases() != len(tests):
        raise ValueError("failed or empty actual collection: " + "\n".join(loader.errors))
    observed = {}
    for test in tests:
        cls, name = type(test), test._testMethodName
        method = getattr(test, name)
        if any(getattr(target, flag, False) for target in (test, cls, method)
               for flag in ("__unittest_skip__", "__unittest_expecting_failure__")):
            raise ValueError("skip/expected failure cannot establish closure")
        source = Path(inspect.getfile(cls))
        relative = source.relative_to(root).as_posix()
        regular_bytes(root, relative)
        module = sys.modules[cls.__module__]
        if Path(module.__file__) != source or Path(inspect.getfile(method)) != source:
            raise ValueError("substituted test module or method")
        observed.setdefault(relative, []).append(cls.__name__ + "." + name)
    observed = {path: sorted(ids) for path, ids in observed.items()}
    if observed != expected:
        raise ValueError("omitted, duplicated or substituted actual tests")
    return observed


def discover_inventory(root):
    # A fresh interpreter per root prevents same-named helper/module collisions.
    result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--collect", str(root)],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise ValueError("fresh-child collection refused: " + result.stderr[-2000:])
    return parse(result.stdout)


def verify_tests(root):
    observed = {}
    for relative in BASELINE["suiteRoots"]:
        observed.update({relative + "/" + p: ids for p, ids in discover_inventory(root / relative).items()})
    expected = {**BASELINE["tests"], NEW_TEST_PATH: sorted(RECORD["repairTestIds"])}
    if observed != expected or sum(map(len, observed.values())) != 170:
        raise ValueError("all 150 predecessor and 20 repair identities required")
    return observed


def verify_repository(root):
    rows, sources = tracked_inventory(root)
    # The fixture itself is read from the repository under test, not a cache.
    load_fixture(sources.get(FIXTURE_PATH))
    hook = RECORD["hook"]
    proof = parse_hook_proof(sources[hook["proofPath"]]) if hook["proofPath"] in sources else None
    result = validate_composition(rows, sources.get(hook["path"]), {"performanceSources": sources, "hookProof": proof})
    verify_tests(Path(root))
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--collect":
        raise SystemExit("only fresh-child test collection is supported")
    # -I deliberately ignores PYTHONPATH; import only this checkout's approved
    # package root explicitly, never an inherited or caller-selected path.
    sys.path.insert(0, str(checked_directory(ROOT / "src")))
    print(json.dumps(collect_in_child(Path(sys.argv[2])), sort_keys=True))


# CONF-PERF-002: current-byte validation precedes inert historical comparison.
PERFORMANCE_AUTHORITY = "7f9ab986281fe6de0d5875e97121bdbe96d41b66567cd5f1e2727204355eb686"
PERFORMANCE_BASE = "9df7dd7f2df8ac64096ef37d8df259761947d552"
PERFORMANCE_DOC = "docs/live-backend/linux-boundary.md"
PERFORMANCE_TEST = "tests/live_backend/test_supervisor.py"
PERFORMANCE_SPECS = {'src/harness_conformance/crypto.py': {'regions': ['_add'], 'append': 0, 'maxRegionBytes': 4096}, 'tests/platform/linux_baseline/_successor_inventory.py': {'regions': ['validate_composition', 'verify_repository'], 'append': 65536, 'maxRegionBytes': 16384}, 'tests/platform/linux_baseline/test_linux_inventory.py': {'regions': ['LinuxInventoryTests.test_original_files_are_unchanged_except_ten_authorized_integrations'], 'append': 0, 'maxRegionBytes': 4096}, 'tests/live_backend/_inventory.py': {'regions': ['validate_checkpoint'], 'append': 0, 'maxRegionBytes': 8192, 'constant': 'HELPER_SHA256'}, 'tests/live_backend/test_supervisor.py': {'regions': ['SupervisorPredecessorTests.test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable', '_credential_inputs', '_credential_repository'], 'append': 131072, 'maxRegionBytes': 16384}, 'docs/live-backend/linux-boundary.md': {'regions': [], 'append': 2097152, 'maxRegionBytes': 0}, 'tests/platform/linux_baseline/test_packet_scalars.py': {'regions': ['ScalarIntegrityTests.test_two_exact_source_transformations_preserve_all_other_bytes'], 'append': 0, 'maxRegionBytes': 4096, 'fixedRegions': {'ScalarIntegrityTests.test_two_exact_source_transformations_preserve_all_other_bytes': '    def test_two_exact_source_transformations_preserve_all_other_bytes(self):\n        helper = load_local("performance_historical_consumer", "tests/platform/linux_baseline/_successor_inventory.py")\n        _, historical_sources, _ = helper.performance_current(ROOT)\n        for path, change in FIXTURE["changes"].items():\n            before = FIXTURE["beforeSources"][path].encode()\n            with self.subTest(path=path):\n                check_edit(path, before, historical_sources[path])\n                self.assertEqual(BASELINE["files"][path]["sha256"], "sha256:" + sha(before))\n'}}, 'tests/platform/linux_baseline/test_successor_inventory.py': {'regions': ['SuccessorInventoryTests.test_original_106_file_and_150_test_history'], 'append': 0, 'maxRegionBytes': 4096, 'fixedRegions': {'SuccessorInventoryTests.test_original_106_file_and_150_test_history': '    def test_original_106_file_and_150_test_history(self):\n        _, historical_sources, _ = HELPER.performance_current(ROOT)\n        historical = json.loads(BASELINE["historical103Raw"])\n        self.assertEqual(sha(BASELINE["historical103Raw"].encode()), BASELINE["historical103Sha256"])\n        self.assertEqual((len(historical["files"]), sum(map(len, historical["tests"].values()))), (103, 120))\n        self.assertEqual((len(BASELINE["files"]), sum(map(len, BASELINE["tests"].values()))), (106, 150))\n        for path, ids in historical["tests"].items():\n            self.assertEqual(BASELINE["tests"][path], ids)\n        self.assertEqual(BASELINE["commit"], "8519225b1564834fab5bcd001c263688e6fba7fe")\n        self.assertEqual(FIXTURE["authority"]["commit"], "3b1ea6b9b8514fbb51e37ba4703f5d06298bd938")\n        self.assertEqual(RECORD["checkpoint"]["ci"]["runId"], 34137197794)\n        self.assertEqual(RECORD["checkpoint"]["mainReplay"]["tests"], 150)\n        for path, checksum in RECORD["checkpoint"]["inventory"]["exactEdits"].items():\n            self.assertEqual(sha(historical_sources[path]), checksum)\n'}}}
PERFORMANCE_PINS = {'.github/workflows/verify.yml': {'mode': '100644', 'blob': '48af47e6d1ca5c5198d934c1dd10c3ba947c3192', 'size': 615, 'sha256': 'sha256:91090dc69c12837e8b73eb41a868b3afca7dcb34b304c7b409ac716310ddd3a6'}, '.gitignore': {'mode': '100644', 'blob': 'd9d863a13c2bfc70183b59f43ddfa236f7fa7e34', 'size': 158, 'sha256': 'sha256:0672c3d34147eb3a4b4aa4298d4d88f647d6d28aa22cffdb705508df11bda33a'}, 'AGENTS.md': {'mode': '100644', 'blob': '3bef97c6f3d501a0b5528179880053f787147de2', 'size': 3064, 'sha256': 'sha256:0b8faaf320feae214a47000b924c9a9c717e73e6d220edf1d16f0ff14381e843'}, 'CONTRIBUTING.md': {'mode': '100644', 'blob': '21f949ba69f148982b99313a6fc319ed5caf3527', 'size': 460, 'sha256': 'sha256:d947eeaf23f47ad60e26bb2e0f236f08a8bd74ca7f8e80d378248ef4477d5964'}, 'LICENSE': {'mode': '100644', 'blob': '94f474d4d34ef439ac1bb0f1961d5cc9e9096c7e', 'size': 774, 'sha256': 'sha256:2d3b806e6fd270f11819d0f797f721747adb0d497760e1b9053b6cd1fae4cf54'}, 'Makefile': {'mode': '100644', 'blob': '729893b50ddf19f0be9a3024f435af789a283897', 'size': 661, 'sha256': 'sha256:bb652db371113bab5d9d8924f0b10b1f85793c0cc84178d447ab1095f4e7b981'}, 'NOTICE': {'mode': '100644', 'blob': '0c12f4d5afbb8d0b984d4e3b094735be11607cf5', 'size': 169, 'sha256': 'sha256:a70fc36aa7b6f295c4a662b6443a0599c4c89e9b6e62feb29763967d79ce382f'}, 'PORTING.yaml': {'mode': '100644', 'blob': 'cdd098dabfe545c4f513a6821d32cb6da17ee047', 'size': 253, 'sha256': 'sha256:69af26b731e28920bb4cc5dd25f6d1d1c18aa75308d75517d6a61f214fa238c4'}, 'README.md': {'mode': '100644', 'blob': 'f04615d13827a0412fa15e7f37f2ffea5c9e4a2d', 'size': 1228, 'sha256': 'sha256:652e3abc12e4cd6d405eb80018a7c29c68d7d3094c2858196d9b83ea7dd566ea'}, 'SECURITY.md': {'mode': '100644', 'blob': '5d25e68338f66ca93863af7783affebc252ecc9f', 'size': 555, 'sha256': 'sha256:1b5594cb9074fb98aa77768df57aeab45c469b60337ba9662e71367b92aa9cc7'}, 'campaigns/alpha1/campaign.json': {'mode': '100644', 'blob': 'a68dd8467599be5349e9cbfb217a1930867ffc62', 'size': 702, 'sha256': 'sha256:17ad9b40b5518e3432c926b5604073fb922df08be38055310dbc851d1a18cef6'}, 'campaigns/meta/campaign.json': {'mode': '100644', 'blob': 'dadfca33c5ed23ceb111cbeae6c5289a364fafe0', 'size': 2341, 'sha256': 'sha256:22091f996b03eae43f8d00da3ec08c85ad12aef2cbb7d0d4ca8b79df8b705386'}, 'campaigns/parity/campaign.json': {'mode': '100644', 'blob': 'f5ae7920b55249d1c35a15dd167ce2bf94c8d653', 'size': 627, 'sha256': 'sha256:cd2ce011470ffef7dc7a08a4fc994a81f3d2f58899276991e02efb1c431956f4'}, 'campaigns/platform/linux-baseline/campaign.json': {'mode': '100644', 'blob': '47ccd6bce2df7569eb2a9e2620e918a10e3b4949', 'size': 5429, 'sha256': 'sha256:3f4da90f48f61e3ee99b002b969eecbffbe60ac65d650abc82cdc6052df9e50e'}, 'ci/acceptance_package_contract.py': {'mode': '100644', 'blob': '12e0ca1ddb11d6533ca5e30023c1afb660051c3f', 'size': 1753, 'sha256': 'sha256:e5872ce6a4af9ead7c1cf130e47ca028fb7dc85b63ef5801abae82151938df6d'}, 'ci/build_live_launcher.py': {'mode': '100644', 'blob': 'f5e37e0a02494893c4d4db356892a2c3f1dd9585', 'size': 2425, 'sha256': 'sha256:873dba7a314405a6ff7c446ee4c0333e34c7cc3400c01141f2c8929dc58c35ad'}, 'ci/network_canary.py': {'mode': '100644', 'blob': '453da00b448d2514ac7070539444d7c55d19616c', 'size': 1499, 'sha256': 'sha256:8eb07e2c974fd4a5040869ef0eee43963826dc8b32f7dd93fa18a91931e56500'}, 'ci/prefetch.py': {'mode': '100644', 'blob': 'b38fb5d15a9cf6df2891c1da368f4db4d505fc04', 'size': 3824, 'sha256': 'sha256:341e6e102b93e74a0e7b3688ad88faacf4fd23dad2d6100884039d1a207947a1'}, 'ci/run_make_target.py': {'mode': '100644', 'blob': '0e05e3879fbd2ad165adf2e7e54c4ec6d08052db', 'size': 5807, 'sha256': 'sha256:0a0f5c2d6305a1772848ba2e58b8c3d17321de3fe5fdc99377515e09c1138389'}, 'ci/run_packet.py': {'mode': '100644', 'blob': '795ef5590e292b3096bddb919c66857a110e7672', 'size': 8302, 'sha256': 'sha256:397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1'}, 'ci/run_packet_argv.py': {'mode': '100644', 'blob': '9b76420194a17a92ccff6fa6e18d2e8c80f31a9f', 'size': 226, 'sha256': 'sha256:523bda5db30faba4c027332a40f36c36e1efdb7e5bd39b68045bcdf817f94fdd'}, 'ci/targets/conf-001.json': {'mode': '100644', 'blob': '9082a2d49ba5dbe0cd8098274c597bee44da9d27', 'size': 692, 'sha256': 'sha256:dc2d49619485436c5cf4540b60c5432e847f96433bc60aa3da88577ffa9887b7'}, 'ci/targets/conf-002.json': {'mode': '100644', 'blob': 'ef49a2be8314bb16ee456cff30bce9ced734bf97', 'size': 339, 'sha256': 'sha256:0e2d0b28b83567cd5cf8fd46f30a377d255995af4450f4675ae08bf27fd757c1'}, 'ci/trust/live-runner-root.pub': {'mode': '100644', 'blob': 'e10a1ac95a5738f59b78c3f7aa999bed90d800a8', 'size': 82, 'sha256': 'sha256:6b22a99cab70c60b7cc345962ae220e32b2dbc89c72b419c79a9c92ec5f6c012'}, 'ci/verify-live-campaign.py': {'mode': '100644', 'blob': '6d666e9cc402ed99b91cbf170a1ffc11da369922', 'size': 630, 'sha256': 'sha256:ed7fa0f9a5d933c257a93f9be9ac5a3321c0b2451aa31e0f698a6053e8f46004'}, 'ci/verify-offline.sh': {'mode': '100755', 'blob': '6ceda876eb6e83d17c7ba48e962bc55bb81e905d', 'size': 912, 'sha256': 'sha256:b058780b727d2e4c7b5f77d3c7f623a7dafdac621c5b505238297e2ea2524c47'}, 'ci/zero_bill.py': {'mode': '100644', 'blob': '6715ef0f0a9b4a1215ff4fd411a13affd6c4a321', 'size': 2177, 'sha256': 'sha256:6e9c7f5aa2ea527a1b1d9472bbab164be4ba051f27dae90005695ff3f04cda14'}, 'docs/live-backend/linux-boundary.md': {'mode': '100644', 'blob': 'd50487bf13b39dc835053a578612e1ac53936afe', 'size': 1223775, 'sha256': 'sha256:8ec776a229e42a67195c740d343aee67d27af19adf93a2d61f694b63cb174aae'}, 'docs/live-backend/session.md': {'mode': '100644', 'blob': '3261b634fe39c4cd6bac109db10169490388d9d4', 'size': 10811, 'sha256': 'sha256:41319d8f1a7fa9441fded7efe23c8254929cc5ea15d7d1f59c125e33b29fc767'}, 'docs/parity.md': {'mode': '100644', 'blob': '7a6e06eb12db130a3893360e5ef6bcb82d3e207f', 'size': 1083, 'sha256': 'sha256:70fb8b95ee95eb7219c3b9ed0eea4c00c280ecf93dba6765418fa559d92b8dc4'}, 'docs/reports/alpha1-template.md': {'mode': '100644', 'blob': '857b5db337b41b07a1be30b10faa1a674fe3ac26', 'size': 2179, 'sha256': 'sha256:70f572dc3d3fef6d45e14c93c09352aea9b7bbdad189cc5167e3d57628c933a9'}, 'docs/reports/linux-baseline.md': {'mode': '100644', 'blob': '8c20f40e9130f50e4a2e22488ca6f60671c72ba3', 'size': 10913, 'sha256': 'sha256:99096cc71b49d662cb3c1a71137724eb1748aa633a7a24c8b56fa4b467605919'}, 'docs/reports/packet-scalar-repair.md': {'mode': '100644', 'blob': '348af063b6acf6f4c4860e40bfa1b6e8e211a86b', 'size': 6081, 'sha256': 'sha256:d824ddb953d31f1a20e19951ef743611e1943f5b6b8d6fe4679721d3146e355a'}, 'docs/reports/runner-boundary-repair.md': {'mode': '100644', 'blob': 'a3484dd5932307bf1cc1cbaab05a4e937841b943', 'size': 6595, 'sha256': 'sha256:e5700f158b640364f15565cbbea8dee7e86e88c045c8cde07cfaa8fe77a525bf'}, 'docs/reports/successor-inventory-repair.md': {'mode': '100644', 'blob': '55c4fbcec0f4412c4efe2143ba739f4fc3efdf33', 'size': 7131, 'sha256': 'sha256:c930632d1e8674d9516976a5d07d385ac6211ade937fd16b6b875607f8498ab2'}, 'fixtures/alpha1/environment-unavailable.json': {'mode': '100644', 'blob': 'da2bbfff05610ac26d574a49436d22e508ace7d4', 'size': 244, 'sha256': 'sha256:71ae29d6bafffc062dcaa358929cdc5224d29f415b6a3a327714f9013dca345d'}, 'fixtures/alpha1/journey.json': {'mode': '100644', 'blob': 'a1be9b330b42820803b572548d8a57edda7c95c0', 'size': 7677, 'sha256': 'sha256:0399a95811cafc48c8deae07b45fadb8082b3be99db838da8b09fbddc1614bd8'}, 'fixtures/alpha1/overview.json': {'mode': '100644', 'blob': 'bafa30410741034579954865f92aaad13c977b9c', 'size': 12726, 'sha256': 'sha256:c840c2f0c8e3094cdaaa08a10ea57d859d969c24546c3a23107189e63d7b626b'}, 'fixtures/environments/meta-complete.json': {'mode': '100644', 'blob': '8fc90838acc3ee792146bd2251592d43882734d8', 'size': 225, 'sha256': 'sha256:6ea4589266ff02ea3c42bf86d72ac5bca9c593203bf35177ecb7da4ab2df1cbe'}, 'fixtures/environments/meta-unavailable.json': {'mode': '100644', 'blob': 'acca65615c5f77cbb97cd2abed3b7e210e27330b', 'size': 207, 'sha256': 'sha256:3bec392601ed731f34f00dd55c835986b758a501d54a1ac0213d1e85eb8e2838'}, 'fixtures/live-backend/baseline.json': {'mode': '100644', 'blob': '10df51d5621ae3f4be5771a458750dded949bf2d', 'size': 174441, 'sha256': 'sha256:c3dd610a748e018c9e015668567fbea9820a050022dc33375912f8f4aaa51a00'}, 'fixtures/live-backend/session-vectors.json': {'mode': '100644', 'blob': 'fd86c220345e46ec6cdf3a0bb9923a7b98a8e7de', 'size': 2822, 'sha256': 'sha256:4999510bbaba2ae4faed7b9afa6d17ba3bbecb733f40f7bf92c69a6d9313a3fd'}, 'fixtures/platform/linux-baseline/environment-unavailable.json': {'mode': '100644', 'blob': 'e85351d42f4894aebb45d158aba7ce1e0c070d4a', 'size': 219, 'sha256': 'sha256:c79b375f07694835f616b51243b92305b96f29088424673457582103078307aa'}, 'fixtures/platform/linux-baseline/predecessor-inventory.json': {'mode': '100644', 'blob': '46236ffaaedffe326c703a88544e918671f1ede7', 'size': 18630, 'sha256': 'sha256:f47c088f150ce7c61a14707aad71c634001037fd423eb43ace3acb055be86a58'}, 'fixtures/platform/linux-baseline/predecessor-sources.json': {'mode': '100644', 'blob': '4470b6fef50a58f626792abe83caa99fd712baa4', 'size': 23010, 'sha256': 'sha256:3fb88e3358c25fb65369e73a3decf9fe111797b1f44b2cc1deeabea8c5d8defc'}, 'fixtures/platform/linux-baseline/scalar-repair.json': {'mode': '100644', 'blob': '1ce1e8efddb2bba302d93e624a01cf5bbe840a87', 'size': 114585, 'sha256': 'sha256:0e04f3878efd8196fc33aa47a80ecbf5a48e7df262f08b98030acfd4c565fd06'}, 'fixtures/platform/linux-baseline/successor-inventory.json': {'mode': '100644', 'blob': 'b99530a2c6df2f32fa1618843103965cc9c03d2d', 'size': 171701, 'sha256': 'sha256:44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86'}, 'parity/adapters/run_parity.py': {'mode': '100644', 'blob': 'd3de27cf2f33a1c74d746f12d5fb1cb7c3267e29', 'size': 4849, 'sha256': 'sha256:650c17312390ec0f4382dad3c9279be0bb50522374c7ec01a079d9a7db8eefac'}, 'parity/adapters/validate_registry.py': {'mode': '100644', 'blob': '8f59afa4c1e14d9cd1a2f6ed5bb8942f541c027a', 'size': 6185, 'sha256': 'sha256:14d00741194d4de4bd3e14adb2829b3612217b9185905220ff8d6c0be39c12d9'}, 'parity/registry.yaml': {'mode': '100644', 'blob': '1cad50d5d694df6dfc127b39025518601db54285', 'size': 5544, 'sha256': 'sha256:0fac00ae1575b5c86996d32f3a9f01a69f6d77743170df1ecf6aff7243569af5'}, 'parity/vectors/data-batch-lineage.json': {'mode': '100644', 'blob': '70c82ac4d21e439139f47ae7aa4ee22e22e3d9f0', 'size': 239, 'sha256': 'sha256:67c46555d13dd0b48f2e7fe8cbad9f09da7708baf816527f32ea9e96eb264d2d'}, 'parity/vectors/data-connector-closed-discovery.json': {'mode': '100644', 'blob': '34ec386fff24d08c70ff2ea3594c3830d953d0b0', 'size': 240, 'sha256': 'sha256:86279c3564392e353ba8537c2cba9d11f4449fc140a02398a146fd6f73e47de0'}, 'parity/vectors/data-local-only-no-fallback.json': {'mode': '100644', 'blob': 'd1e3f2a65cc5aa39244e2f1511aa8eca21541c81', 'size': 207, 'sha256': 'sha256:fe3698e550940e90f71d497d0e0024ad99dbc8026684e77ebecb666b1577904f'}, 'parity/vectors/model-route-fail-closed.json': {'mode': '100644', 'blob': '3168f7be8c41152efe67924537d953a697002a56', 'size': 198, 'sha256': 'sha256:6eb0342fea804721e30ed38657d44c1578d20b4f829b76a3215df635f504a5de'}, 'parity/vectors/model-upstream-bounded-retry.json': {'mode': '100644', 'blob': 'be842691179449079ecb52c87fbcea7b8f4305df', 'size': 192, 'sha256': 'sha256:f0a3cdf305e1f63f0edd05e074373cf6f98f09063bed101a100a74b3b920e854'}, 'parity/vectors/model-usage-tenant-neutral.json': {'mode': '100644', 'blob': 'b596b1dc64bb2dca2128c9be1d7f74d65c19d06f', 'size': 299, 'sha256': 'sha256:410f55e3e3453a19754c52cecb689349aba41a95b015aceca7d35ff2e4f9f1ce'}, 'parity/vectors/white-goods-foundation-boundary.json': {'mode': '100644', 'blob': '1265779205f37c842941abb201b8bf253f6f128f', 'size': 277, 'sha256': 'sha256:49f3a5a70f32c00cebc69594832300939942dc6b80f8a57d60f2c577e728ac2d'}, 'pyproject.toml': {'mode': '100644', 'blob': '4b42959660c2d19e0190b5e5f885f826d84264e3', 'size': 500, 'sha256': 'sha256:4180e069f0bfb7b38f99b367f9a6f29e914a61717bd0797343f3d2b99720409c'}, 'schemas/v1alpha1/campaign-release.schema.json': {'mode': '100644', 'blob': '310a5b6506656a547bacdd071a44a481654749fa', 'size': 1189, 'sha256': 'sha256:50053c212b0e9a40dcf4e7dd4c155c8c3da6a81a77a82ae7f59aadc2d6d0cfa9'}, 'schemas/v1alpha1/campaign-report.schema.json': {'mode': '100644', 'blob': '3726b8f1298f85c5482ec5cf28a9d69512bd418b', 'size': 1073, 'sha256': 'sha256:3e775c55dbc5dff84fb5aab90525814ef03595a69583e8239640583cac7036a9'}, 'schemas/v1alpha1/conformance-campaign.schema.json': {'mode': '100644', 'blob': 'a9102ed14316481f18bc0936493b56cd469eaafe', 'size': 10324, 'sha256': 'sha256:dd4fb4f5fda756613d5f69056460abdbd05b675dbddb4c9606bc9324321bb89f'}, 'schemas/v1alpha1/conformance-trust-bundle.schema.json': {'mode': '100644', 'blob': '25e5054c6fe449249419c76fded16a482bb339ba', 'size': 1151, 'sha256': 'sha256:587e9e4fcc48fa98cf316b73a3cccabd9713fa0cbae48067f5f43f181404c245'}, 'schemas/v1alpha1/control-result.schema.json': {'mode': '100644', 'blob': 'fcccd2c59e23ee4cdd003d09afe14cd6e8068eae', 'size': 1056, 'sha256': 'sha256:2113a19ec9e077dcb7ab6f2c299c4756d09b0d1e3d3a32195d2103ff8d54e182'}, 'schemas/v1alpha1/environment-intake.schema.json': {'mode': '100644', 'blob': 'b303695d6f954b95e218726db6d0fac6e519c8fd', 'size': 776, 'sha256': 'sha256:b69ef4bda6fe209b0416ef1c250747a38179d4cef0cf9bc8c72b1f0de1e3d621'}, 'schemas/v1alpha1/linux-readiness-evidence.schema.json': {'mode': '100644', 'blob': '7032d8ada2da1ab7bc46f329505656b9b98562de', 'size': 61742, 'sha256': 'sha256:8f4cf17273b097e39420b2394be43259c9bea30b684a58bcdc739c60b5059c0e'}, 'schemas/v1alpha1/live-backend-session.schema.json': {'mode': '100644', 'blob': 'ac9fee798700c8f558674132897bc306293d802a', 'size': 2504, 'sha256': 'sha256:7c4ad7c69feb4e9e9f8509f2cdd6c1bcccbf8acb60711810c2e0df8ef7cb737d'}, 'schemas/v1alpha1/live-campaign-execution-envelope.schema.json': {'mode': '100644', 'blob': '0276cd0438895d8874ea076262a6bb9071bfd3c5', 'size': 4272, 'sha256': 'sha256:d4720d28fd0cfb8f4979f8d1bb808c5244c6e8121c4a97b0303cfed033c4d1fd'}, 'schemas/v1alpha1/live-capacity-authorization.schema.json': {'mode': '100644', 'blob': '4902a75d338b4242cf54642bc005b90cd40513a9', 'size': 2177, 'sha256': 'sha256:196cafdba0cc168b8dbab7cb02aeda003b1b0cb2f0ae8e9b233b883629949235'}, 'schemas/v1alpha1/technical-evidence-bundle.schema.json': {'mode': '100644', 'blob': '8c66a359cd84085b4729cf8bae263bb523494cec', 'size': 1524, 'sha256': 'sha256:0d1e7ad8413733c63b18bb0b658a93f541800c604b2f56c8842fe4ac7760d513'}, 'schemas/v1alpha1/tenant-acceptance-candidate.schema.json': {'mode': '100644', 'blob': '69c535c74b5dc71454fac60c066ac03c785ef75f', 'size': 995, 'sha256': 'sha256:37c57329bb835d7aa091be9de41bcfaed9305b1e0359ec1289d114f31bbf426a'}, 'src/harness_conformance/__init__.py': {'mode': '100644', 'blob': '7d8e8ae786e942135fae50701e31ac25d700869e', 'size': 236, 'sha256': 'sha256:748cd4a32689b1856ef53f51793e3f85303a25658846bb9a6965440ceeed769f'}, 'src/harness_conformance/__main__.py': {'mode': '100644', 'blob': 'eb53e2f31b2f703ad32ef64b8a41faa3e7d18e08', 'size': 48, 'sha256': 'sha256:935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d'}, 'src/harness_conformance/acceptance.py': {'mode': '100644', 'blob': '85fba5611d427772e8f0a4a71aaed3f13824b8cb', 'size': 2613, 'sha256': 'sha256:81a562a983f1d662e78d95d7e3e29f070471b3e304c13bac5162e0b05108c933'}, 'src/harness_conformance/build_backend.py': {'mode': '100644', 'blob': '779090a50431f086f497e26319de9265d664666c', 'size': 2399, 'sha256': 'sha256:d7ed81b4e0ffd865093679ef51a033a7bc74024b20300b098520306a05243e99'}, 'src/harness_conformance/campaign.py': {'mode': '100644', 'blob': 'c07495f1c0df2532a2e37bd80d01f93b9a027b04', 'size': 7026, 'sha256': 'sha256:da0a25fba8336f658948ab1018a9db5c518bcc52849bdfcf295058906a26272a'}, 'src/harness_conformance/canonical.py': {'mode': '100644', 'blob': '18ab1dd28aeea326c177748aa357e85d56df0086', 'size': 5645, 'sha256': 'sha256:eb16aee5dda8f512b78b637361f0a057c7e944cd1b9eb888c88182c867e7794d'}, 'src/harness_conformance/cli.py': {'mode': '100644', 'blob': 'f78f09f9845fd187107d45c3b2ddeb859702b848', 'size': 4482, 'sha256': 'sha256:c6fe0356d835db4bb0ae43d2484ca107f32bbf9046ff04c1a5a5ab47703ce8c1'}, 'src/harness_conformance/crypto.py': {'mode': '100644', 'blob': 'efda93c52fe47c15d4238676a0a2aede8e1ddda6', 'size': 4787, 'sha256': 'sha256:2684b08b73d0379b8bf09e90f70839f6bccb0e947f3f999f6fa2f0e71c873035'}, 'src/harness_conformance/errors.py': {'mode': '100644', 'blob': '3c78aa2fd3f372fa45df8eba47c1958e70376ea8', 'size': 308, 'sha256': 'sha256:c30216c02cfa449063b77ca922a3c7cd32e0c6a8010365e093d730e7bc37807a'}, 'src/harness_conformance/events.py': {'mode': '100644', 'blob': 'c5294e469638af15d9616a08594c99b3ca48ecd2', 'size': 2197, 'sha256': 'sha256:2cc8855e5fe02c9874e3653b5f094b4095eed483e2446ba32735ddc57c6b422a'}, 'src/harness_conformance/evidence.py': {'mode': '100644', 'blob': 'cb5ac52a8cdab8f23cc3dee05d063c0eedada7cc', 'size': 7683, 'sha256': 'sha256:670a8c4f6b06caf8af7749b0fe5bf6210d746cd6a823430a387890add135b3e6'}, 'src/harness_conformance/lifecycle.py': {'mode': '100644', 'blob': '0e3874da1b086941ec6319386ecb379238e25f42', 'size': 1582, 'sha256': 'sha256:86c7f62bea77d963e087d2b244f8479a5a81bd1dac8ab5ec5579ad9b0a35f69c'}, 'src/harness_conformance/linux_readiness.py': {'mode': '100644', 'blob': 'f0be4c7607bf66d993fe712bb6f2062787632d6c', 'size': 22629, 'sha256': 'sha256:1d40b52a05a85cf0d2179d5545bc8325b8035a24340c5a52b8b66f28e0476fc8'}, 'src/harness_conformance/live.py': {'mode': '100644', 'blob': 'cf510b0a5e9623e21a431c9b061c26311035ce38', 'size': 23002, 'sha256': 'sha256:8f6d033292801930cd280f3611aed3c6012cf4d39ec63d4324eb92590e44a022'}, 'src/harness_conformance/live_backend_authority.py': {'mode': '100644', 'blob': 'ecac59b706d8d8f0ec37c844d2fb91162d5adf16', 'size': 9916, 'sha256': 'sha256:b57f241e1c0c76be3d86682e9a1a1d62f40115aaa917d2e124d589c84880e42d'}, 'src/harness_conformance/live_launcher.py': {'mode': '100644', 'blob': 'ad7ebd930586d383ce2b947a9c433c73f9b5baf6', 'size': 5281, 'sha256': 'sha256:0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27'}, 'src/harness_conformance/live_linux_boundary.py': {'mode': '100644', 'blob': '349ccc21d9d861461863bfabec362d2fe197badc', 'size': 52544, 'sha256': 'sha256:7c590b4078e4bd024c0798749f5d1e1197f9a30c15cc6d1a2b0d7b9131ae54fe'}, 'src/harness_conformance/live_replay_store.py': {'mode': '100644', 'blob': '84b054eab30e318552866076e5291dca842734d1', 'size': 10076, 'sha256': 'sha256:ff512b35ce7761b5dccc2c57989a6888b0daa9c99fba404f7be0be6878dae3f7'}, 'src/harness_conformance/live_session.py': {'mode': '100644', 'blob': '6a22fd233cfd52c357d03dfd60dc8cc1d563a1cc', 'size': 12361, 'sha256': 'sha256:dc15ebe6d919093cb1842c77c19c9e7846d7ef62e3b04946114824befa9e4454'}, 'src/harness_conformance/live_supervisor.py': {'mode': '100644', 'blob': 'dd02d0e0c87044e3568f8521cb74d9fb14ea3c6f', 'size': 38977, 'sha256': 'sha256:4dfeb1780c5fc6b2e116f027fbbde6b8a0fec401911f11c4f45900e7ad84b03e'}, 'src/harness_conformance/models.py': {'mode': '100644', 'blob': 'e2e1d24ec4822b86d10efb8c864281a81730518b', 'size': 1430, 'sha256': 'sha256:3d095046632c640bd679b730cc76c90276a73c18263de227ad8a5692c34730dc'}, 'src/harness_conformance/registry.py': {'mode': '100644', 'blob': '539cfbb0f1177dd9614f83e333e2a342a97fabf1', 'size': 1595, 'sha256': 'sha256:fa32c26a773a93d60c3f1cd512a99d1213258f944846e028bf7c92aca7049139'}, 'src/harness_conformance/schema.py': {'mode': '100644', 'blob': '51e9e4a9e38278771979bc89e612a0371312f4dc', 'size': 9908, 'sha256': 'sha256:cd3fefc33833cf5fbccb97a0ac75524ecd967cfa10064a79f64a837f75397ee5'}, 'tests/alpha1/__init__.py': {'mode': '100644', 'blob': '68a01f42298a8f26633b2142b6a0005197345c61', 'size': 48, 'sha256': 'sha256:1c4b4913127e929661e104454b7900591e39681401eb19594436b1a860c49a6a'}, 'tests/alpha1/contract.py': {'mode': '100644', 'blob': 'cab06a287c4bb3af9b46d6aad540463494572429', 'size': 16927, 'sha256': 'sha256:20034c14d493cac5f730440b27833c5fa87722fda0a1574ce0f81836764749a7'}, 'tests/alpha1/test_alpha1.py': {'mode': '100644', 'blob': '27d0f87d11dd4db53c9b2ac0e96ff8c8e8ce08b7', 'size': 7371, 'sha256': 'sha256:b528290f311a5e41e2b163028bb5212a022d15319a7a9fb218fd7e272480e9c7'}, 'tests/fixes/runner_boundary/_inventory.py': {'mode': '100644', 'blob': 'fdf58c985872348225fcf9706890349dcceb8a2c', 'size': 2443, 'sha256': 'sha256:fb50aba04fe963a89b74ad1aca57b1242fa54481e01989ac18a189a080ade94c'}, 'tests/fixes/runner_boundary/legacy-tests.json': {'mode': '100644', 'blob': 'f0fd3094ae447ae25840d8a13d29d89fdaecbd26', 'size': 4603, 'sha256': 'sha256:9fff3fb6bd66789b18bc8f38885d2bfd287124f9a32b4f7a0d645c27ee500dbd'}, 'tests/fixes/runner_boundary/test_boundaries.py': {'mode': '100644', 'blob': 'ee6aaffe5e7a8b067f5051208f9fb7080f192400', 'size': 15192, 'sha256': 'sha256:2e33efe165cf46912a426285dabd0bbe98b17acdf18f3d7a8bf3cb56a71247e4'}, 'tests/fixes/runner_boundary/test_inventory.py': {'mode': '100644', 'blob': 'b32df3cf7b119502baa187661589145446fe317b', 'size': 3569, 'sha256': 'sha256:1fbacb25aea922a37fb552e91f6b95dded7c1774d1ba2a80f5989cd926cad5e6'}, 'tests/live_backend/_fixtures.py': {'mode': '100644', 'blob': 'c304516fcc8700038748a535280f607dde9026ac', 'size': 3383, 'sha256': 'sha256:edec764c067e538fa9709dc7dce59a357ae996ba36c6121482cc3b24d86b8a28'}, 'tests/live_backend/_inventory.py': {'mode': '100644', 'blob': 'e0712948f964919b3c3f26d13c5b7c1939e75c89', 'size': 4653, 'sha256': 'sha256:0040fcade2ff722c64673cc2b6b6fc19ad469d22b75082f7b4866d0ab94a5e14'}, 'tests/live_backend/test_inventory.py': {'mode': '100644', 'blob': 'aaa7c95f79868172637bb95a4118dff083cd573f', 'size': 10197, 'sha256': 'sha256:f128f05fc395c26de0c13c34953bfff297fa64f857f3f70aab56dbc9e3bcc8a1'}, 'tests/live_backend/test_linux_boundary.py': {'mode': '100644', 'blob': '012da5892daafbb7c92c09944d9f97a5e180fffa', 'size': 62720, 'sha256': 'sha256:06d16e4c833dc818a084b655b4f767dbe601212adc9525c47dc94241c32ee238'}, 'tests/live_backend/test_replay_store.py': {'mode': '100644', 'blob': 'c905fc0bf1775c1a01c15e068c0a8ae5cc7f387a', 'size': 9971, 'sha256': 'sha256:492d6569edb1d271199a3d52b93e82f7295ae478d90b01376125313ee1af8213'}, 'tests/live_backend/test_session.py': {'mode': '100644', 'blob': '5970c237d3d60f5cbfa33ace88e7d37b0e885f34', 'size': 32978, 'sha256': 'sha256:4348b898c1d8cab9fbc94b7bfceff5442a21c0e49fc2645277ae706506c25e90'}, 'tests/live_backend/test_supervisor.py': {'mode': '100644', 'blob': 'd68da58d76e9b72655d61d8ae2a565fac5b33907', 'size': 172181, 'sha256': 'sha256:1767e15dc54c67ca1a75b82c5c020a4359cff489f197455cda641b409c1739e2'}, 'tests/meta/test_build_cli.py': {'mode': '100644', 'blob': '7b71afb1541acc77c25af4edd83e42807e9bad99', 'size': 2781, 'sha256': 'sha256:989c58c63a8cc5234e0396c4bee1c667da133c6893ca24dd96bd95822f43a4e6'}, 'tests/meta/test_campaign.py': {'mode': '100644', 'blob': '01bbbfb3a347dc97562597744c3940e11cd67185', 'size': 3007, 'sha256': 'sha256:85fc9c47556fa0db78ed1948cba696cea0da9d895848169785d227a6e66efc8d'}, 'tests/meta/test_canonical_schema.py': {'mode': '100644', 'blob': 'e9f4e4ebab1d8ad8c4cbccd21f6f64684548faf1', 'size': 3187, 'sha256': 'sha256:f3c233226c5dc400f225eeb16bde754fd73b3e332a2cc85c7795571537845a35'}, 'tests/meta/test_evidence_crypto.py': {'mode': '100644', 'blob': 'deb7af4af91219aa7a688e67bd66cfb856897ed7', 'size': 4501, 'sha256': 'sha256:b0b87f6e4f726ebc7af82be7ab9b6b83a73ec130e1559cb5d9800396b91436c4'}, 'tests/meta/test_live.py': {'mode': '100644', 'blob': 'cd6f7ea911bd1fe55132723f30f9924b2dcdb63b', 'size': 11715, 'sha256': 'sha256:9ac39858b40468a10b2a20ae43e0aaa92f64fde6ab63d275143d654774ec10a3'}, 'tests/meta/test_porting_zero_bill.py': {'mode': '100644', 'blob': 'eef6f33647b7ef061616939b1f8c5a03472e9aee', 'size': 4182, 'sha256': 'sha256:f8ed0fdffc245541d332d78c66d6e9045c3bfc85e0683c3cb7e87b263c1bd448'}, 'tests/meta/test_registry_dispatch.py': {'mode': '100644', 'blob': 'c6283b1028a659c3d1ef48863280eb1c9a6349f8', 'size': 3756, 'sha256': 'sha256:b021ddeb2a7a534427edf7db594b0d9532711bec4fcfac76405dcded73adbc1d'}, 'tests/parity/test_adapters.py': {'mode': '100644', 'blob': 'bac9d9424411a7441f721f31c10b6e92992f67d9', 'size': 2337, 'sha256': 'sha256:9e4217daee3c0e6f5f7dc0a292c4ff55cb1a3b7259b477ee65dfc13315e49c4a'}, 'tests/parity/test_packet_runner.py': {'mode': '100644', 'blob': '756551e665a844d2dcec790becb31a82c4a82cfd', 'size': 6066, 'sha256': 'sha256:0054ccd9312c59a77194a17152191a80bc82d98a5b27ee6e83183b2e62bf7d97'}, 'tests/parity/test_registry.py': {'mode': '100644', 'blob': '50e8fc23c9bbf139b0eed861817977157316c03a', 'size': 2638, 'sha256': 'sha256:88d007d59c2da7dc45fdb4da0d7787725ff6a4d6d120a7f38d843a94baf2b5ff'}, 'tests/platform/linux_baseline/_fixtures.py': {'mode': '100644', 'blob': 'd1d152fffec06019d0501a982d2108e1e06eff06', 'size': 11573, 'sha256': 'sha256:579ff77d11e66776884ccf4a3343c417393767215b09abc5aacc1a19c10bcb7d'}, 'tests/platform/linux_baseline/_successor_inventory.py': {'mode': '100644', 'blob': 'f9c8aa8739b46e9d272c59eeb42e4b1cbf6f56f1', 'size': 16803, 'sha256': 'sha256:a50f5702345b69957878d520693934f0a1ded3d322c34d549305792b0484d20c'}, 'tests/platform/linux_baseline/test_linux_campaign.py': {'mode': '100644', 'blob': 'd14aa009675231ef49fbac95c9bcd9559a61e0f1', 'size': 8618, 'sha256': 'sha256:e4501ef5df6a3a1e9f3755aee40592f81ccdcab069d187215f612b97f9773094'}, 'tests/platform/linux_baseline/test_linux_evidence.py': {'mode': '100644', 'blob': '85d3983ddf743dd5ed4bde41e81063bc6b32d525', 'size': 14548, 'sha256': 'sha256:b6e162808c471d3d2ed7caa2ed2c056af33819d91ae46a66ff5298da982912b3'}, 'tests/platform/linux_baseline/test_linux_inventory.py': {'mode': '100644', 'blob': '58b6a8090818e38fdf7c3437ef65dedf4d4baf5d', 'size': 5521, 'sha256': 'sha256:9111de6b6e167c2eca41801bffc5430b1af8c85f7da696c11a20cce577a1bb29'}, 'tests/platform/linux_baseline/test_linux_protocol.py': {'mode': '100644', 'blob': '3f09672575ac51b8d979431adf058f11941b63df', 'size': 8232, 'sha256': 'sha256:2057b427ba366717c506d561978695e27b53208b4e3fbf318b00671fe672254d'}, 'tests/platform/linux_baseline/test_packet_scalars.py': {'mode': '100644', 'blob': '3ad7af1d8e11b430e77d888f267a1ead515e1d7b', 'size': 27101, 'sha256': 'sha256:e1491e4407ff6d221871b45bbd775beb28afba11d418ae001847a512bb4b6fe6'}, 'tests/platform/linux_baseline/test_successor_inventory.py': {'mode': '100644', 'blob': 'fa3a645e538d63ffc7138cf30b3f471b99c72dc5', 'size': 20850, 'sha256': 'sha256:85b67d291794b41c248b0f34cc9806ff3a05fc5bf3b38d7b588710c1980212a1'}, 'toolchain.lock': {'mode': '100644', 'blob': '1a9f18620f9d55bb5308b5a817ae671cf07a7246', 'size': 2153, 'sha256': 'sha256:40a0cbb9fc244a8484b22494b6bfa070fbc76aec0edd86ab690026f6a8027bfc'}, 'uv.lock': {'mode': '100644', 'blob': 'c9043e59c92f5861c567a815a866257459b1b409', 'size': 150, 'sha256': 'sha256:bd9cb528f2c6ad6a74e3dc1998978e029144fcee2535387cc5ef3db7907dcfbc'}}
PERFORMANCE_TEST_COUNT = 327


def performance_require(ok, reason):
    if not ok:
        raise ValueError("performance scope: " + reason)


def performance_region(raw, name):
    return _performance_region_parsed(ast.parse(raw), raw.splitlines(keepends=True), name)


def _performance_region_parsed(tree, lines, name):
    nodes = tree.body
    for part in name.split("."):
        selected = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == part]
        performance_require(len(selected) == 1, "unique region")
        node = selected[0]
        nodes = node.body
    performance_require(isinstance(node, ast.FunctionDef) and not node.decorator_list, "plain function")
    return sum(map(len, lines[:node.lineno - 1])), sum(map(len, lines[:node.end_lineno])), node


def performance_ids(raw):
    return _performance_ids_parsed(ast.parse(raw))


def _performance_ids_parsed(tree):
    found = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                found.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(tree.body)
    performance_require(len(found) == len(set(found)), "duplicate test identity")
    return sorted(found)


def performance_reconstruct(path, before, row):
    return _performance_reconstruct_details(path, before, row)[0]


def _performance_reconstruct_details(path, before, row):
    # These trees live for this call only: no source, decision or signature cache.
    tree, lines = ast.parse(before), before.splitlines(keepends=True)
    spec = PERFORMANCE_SPECS[path]
    performance_require(type(row) is dict and set(row) == {"regions", "append", "afterSha256", "constant"}, "closed row")
    performance_require(type(row["regions"]) is dict and set(row["regions"]) == set(spec["regions"])
                        and type(row["append"]) is str and len(row["append"].encode()) <= spec["append"], "bounded regions")
    if "fixedRegions" in spec:
        performance_require(row["regions"] == spec["fixedRegions"], "exact historical-consumer bridge")
    edits = []
    for name in spec["regions"]:
        start, end, old = _performance_region_parsed(tree, lines, name)
        replacement = row["regions"][name]
        performance_require(type(replacement) is str and replacement.endswith("\n")
                            and 0 < len(replacement.encode()) <= spec["maxRegionBytes"], "bounded replacement")
        dedented = "\n".join(line[old.col_offset:] if line else line for line in replacement.splitlines()) + "\n"
        parsed = ast.parse(dedented).body
        annotation = lambda n: ast.dump(n) if n is not None else None
        performance_require(len(parsed) == 1 and isinstance(parsed[0], ast.FunctionDef)
                            and parsed[0].name == old.name and not parsed[0].decorator_list
                            and ast.dump(parsed[0].args) == ast.dump(old.args)
                            and annotation(parsed[0].returns) == annotation(old.returns), "function interface")
        if path == "src/harness_conformance/crypto.py":
            forbidden = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.Attribute,
                         ast.With, ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.Lambda)
            performance_require(not any(isinstance(n, forbidden) for n in ast.walk(parsed[0])), "arithmetic only")
            performance_require(all(isinstance(n.func, ast.Name) and n.func.id == "pow"
                                    for n in ast.walk(parsed[0]) if isinstance(n, ast.Call)), "no runtime service")
        if old.name.startswith("test_") and "fixedRegions" not in spec:
            assertions = lambda node: [ast.dump(n) for n in ast.walk(node)
                if isinstance(n, ast.Assert) or isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr.startswith("assert")]
            performance_require(assertions(old) == assertions(parsed[0]), "old comparisons preserved")
        edits.append((start, end, replacement.encode()))
    current = before
    for start, end, replacement in sorted(edits, reverse=True):
        current = current[:start] + replacement + current[end:]
    if "constant" in spec:
        performance_require(type(row["constant"]) is str and re.fullmatch("[0-9a-f]{64}", row["constant"]), "helper pin")
        pattern = rb'^HELPER_SHA256 = "[0-9a-f]{64}"$'
        performance_require(len(re.findall(pattern, current, re.M)) == 1, "unique pin")
        current = re.sub(pattern, ('HELPER_SHA256 = "' + row["constant"] + '"').encode(), current, flags=re.M)
    else:
        performance_require(row["constant"] is None, "unexpected constant")
    if row["append"]:
        added = ast.parse(row["append"])
        definitions = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        existing = {n.name for n in tree.body if isinstance(n, definitions)}
        names = [n.name for n in added.body if isinstance(n, definitions)]
        performance_require(not existing.intersection(names) and len(names) == len(set(names)), "shadowed definition")
        performance_require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                            n.name in ("load_tests", "run", "discover") for n in ast.walk(added)), "collection override")
        performance_require(not any(isinstance(n, ast.Attribute) and n.attr in
                            ("skip", "skipIf", "skipUnless", "expectedFailure") for n in ast.walk(added)), "omitted test")
    current += row["append"].encode()
    old_ids, current_ids = _performance_ids_parsed(tree), _performance_ids_parsed(ast.parse(current))
    performance_require(set(old_ids) <= set(current_ids), "old test lost")
    performance_require(digest(current) == row["afterSha256"], "after hash")
    return current, old_ids, current_ids


def performance_proof(sources):
    """Pure eight-source oracle. Stored source strings are parsed, never executed."""
    performance_require(type(sources) is dict and set(PERFORMANCE_SPECS) <= set(sources), "eight actual sources")
    document = sources[PERFORMANCE_DOC]
    pin = PERFORMANCE_PINS[PERFORMANCE_DOC]
    performance_require(type(document) is bytes and len(document) <= pin["size"] + 2097152, "bounded document")
    before_doc = document[:pin["size"]]
    performance_require("sha256:" + digest(before_doc) == pin["sha256"], "document prefix")
    marker = b"\n```harness-performance-source-proof\n"
    addition = document[pin["size"]:]
    performance_require(addition.count(marker) == 1 and addition.endswith(b"\n```\n"), "one final proof fence")
    suffix, raw = addition.split(marker)
    raw = raw[:-5]
    proof = parse(raw)
    performance_require(type(proof) is dict and set(proof) == {"schemaVersion", "evidenceClass", "packetId",
        "authorityDigest", "baseCommit", "sources", "newTestIds", "beforeSources", "documentSuffix"}, "closed proof")
    performance_require(canonical(proof) == raw and proof["schemaVersion"] == "planeon.conformance-performance-delta/v2"
                        and proof["evidenceClass"] == "SOURCE_DELTA_ONLY" and proof["packetId"] == "CONF-PERF-002"
                        and proof["authorityDigest"] == PERFORMANCE_AUTHORITY and proof["baseCommit"] == PERFORMANCE_BASE,
                        "canonical identity")
    python_paths = set(PERFORMANCE_SPECS) - {PERFORMANCE_DOC}
    performance_require(type(proof["sources"]) is type(proof["beforeSources"]) is dict
                        and set(proof["sources"]) == set(proof["beforeSources"]) == python_paths, "exact source set")
    performance_require(type(proof["documentSuffix"]) is str and len(suffix) <= 65536
                        and proof["documentSuffix"].encode() == suffix
                        and b"```harness-performance-source-proof" not in suffix, "document suffix")
    historical = {PERFORMANCE_DOC: before_doc}
    test_ids = None
    for path in sorted(python_paths):
        old = proof["beforeSources"][path]
        performance_require(type(old) is str, "inert before string")
        before = old.encode()
        pin = PERFORMANCE_PINS[path]
        performance_require(len(before) == pin["size"] and "sha256:" + digest(before) == pin["sha256"], "before pin")
        reconstructed, old_ids, current_ids = _performance_reconstruct_details(path, before, proof["sources"][path])
        performance_require(type(sources[path]) is bytes and reconstructed == sources[path], "actual delta")
        if path == PERFORMANCE_TEST:
            test_ids = (old_ids, current_ids)
        historical[path] = before
    helper = "tests/platform/linux_baseline/_successor_inventory.py"
    performance_require(proof["sources"]["tests/live_backend/_inventory.py"]["constant"] == digest(sources[helper]), "current helper pin")
    added = sorted(set(test_ids[1]) - set(test_ids[0]))
    performance_require(added and proof["newTestIds"] == added, "exact added IDs")
    return historical, proof


def performance_history(rows, sources):
    """Validate actual custody/bytes first; return a labelled historical view."""
    historical, proof = performance_proof(sources)
    actual = {}
    for row in rows:
        performance_require(type(row) is dict and set(row) == ROW_FIELDS, "closed current row")
        path = row["path"]
        canonical_path(path)
        performance_require(path not in actual and row["kind"] == "file" and type(row["nlink"]) is int
                            and row["nlink"] == 1 and row["linkedAncestry"] is False
                            and row["mode"] in ("100644", "100755") and type(row["size"]) is int
                            and 0 <= row["size"] <= 16777216 and type(sources.get(path)) is bytes
                            and row["size"] == len(sources[path]) and row["sha256"] == digest(sources[path]), "actual row custody/hash")
        actual[path] = row
    performance_require(set(actual) == set(sources) and set(PERFORMANCE_PINS) <= set(actual), "complete current checkpoint")
    paths, stages = set(BASELINE["files"]) | set(RECORD["repairPaths"]), []
    for stage in range(7):
        if stage:
            paths.update(RECORD["stages"][stage - 1]["paths"])
        if paths == set(actual):
            stages.append(stage)
    performance_require(len(stages) == 1 and stages[0] >= 2, "complete ordered stage")
    history_sources = dict(sources)
    history_sources.update(historical)
    for path, pin in PERFORMANCE_PINS.items():
        performance_require(actual[path]["mode"] == pin["mode"], "accepted source mode")
        if path == RECORD["hook"]["path"] and stages[0] == 6:
            validate_hook(sources[path], parse_hook_proof(sources[RECORD["hook"]["proofPath"]]))
            continue
        raw = history_sources[path]
        performance_require(len(raw) == pin["size"] and "sha256:" + digest(raw) == pin["sha256"]
                            and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == pin["blob"], "accepted history")
    history_rows = [dict(row, size=len(history_sources[row["path"]]), sha256=digest(history_sources[row["path"]])) for row in rows]
    return history_rows, history_sources, proof


def performance_current(root):
    rows, sources = tracked_inventory(root)
    return performance_history(rows, sources)
