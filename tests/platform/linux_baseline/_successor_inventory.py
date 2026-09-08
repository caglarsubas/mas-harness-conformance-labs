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
    corrected = corrected_test(FIXTURE["testBefore"].encode())
    for path, expected in BASELINE["files"].items():
        size, sha = expected["size"], expected["sha256"]
        if path == RECORD["change"]["path"]:
            size, sha = len(corrected), digest(corrected)
        elif path == RECORD["hook"]["path"]:
            size, sha = len(launcher_after), digest(launcher_after)
        if tuple(observed[path][k] for k in ("mode", "size", "sha256")) != (expected["mode"], size, sha):
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
    result = validate_composition(rows, sources.get(hook["path"]), proof)
    verify_tests(Path(root))
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--collect":
        raise SystemExit("only fresh-child test collection is supported")
    # -I deliberately ignores PYTHONPATH; import only this checkout's approved
    # package root explicitly, never an inherited or caller-selected path.
    sys.path.insert(0, str(checked_directory(ROOT / "src")))
    print(json.dumps(collect_in_child(Path(sys.argv[2])), sort_keys=True))
