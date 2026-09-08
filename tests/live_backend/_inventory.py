"""Cumulative source accounting only; all collection stays in the offline tree.

Use the accepted CONF-FIX-003 verifier, including its complete ordered stages
and final source-delta proof. No filename-presence exemption or execution grant.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = "tests/platform/linux_baseline/_successor_inventory.py"
HELPER_SHA256 = "a50f5702345b69957878d520693934f0a1ded3d322c34d549305792b0484d20c"
BASELINE_PATH = "fixtures/live-backend/baseline.json"
BASELINE_SHA256 = "c3dd610a748e018c9e015668567fbea9820a050022dc33375912f8f4aaa51a00"

# Only this fixed, already accepted test helper may be imported. No snapshots.
helper_path = ROOT / HELPER_PATH
for ancestor in helper_path.parents:
    if not stat.S_ISDIR(ancestor.lstat().st_mode):
        raise ValueError("linked helper ancestor")
info = helper_path.lstat()
if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or hashlib.sha256(helper_path.read_bytes()).hexdigest() != HELPER_SHA256):
    raise ValueError("accepted source helper changed")
spec = importlib.util.spec_from_file_location("live_backend_accepted_inventory", helper_path)
SUCCESSOR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SUCCESSOR)


def load_baseline(raw):
    if type(raw) is not bytes or len(raw) > 1048576:
        raise ValueError("bounded baseline bytes required")
    value = SUCCESSOR.parse(raw)
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA256:
        raise ValueError("baseline fixture changed")
    return value


BASELINE = load_baseline(SUCCESSOR.regular_bytes(ROOT, BASELINE_PATH))
CURRENT = BASELINE["acceptedCheckpoint"]


def source_inventory(root):
    root = SUCCESSOR.checked_directory(root)
    files = sorted(root.rglob("test_*.py"))
    if not files:
        raise ValueError("empty inventory")
    expected = {}
    for path in files:
        if path.parent != root:
            raise ValueError("test root must remain flat")
        tree = ast.parse(SUCCESSOR.regular_bytes(root, path.name))
        if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "load_tests"
               for n in tree.body):
            raise ValueError("load_tests selection is forbidden")
        methods = [f"{node.name}.{method.name}" for node in tree.body if isinstance(node, ast.ClassDef)
                   for method in node.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and method.name.startswith("test_")]
        if not methods or len(methods) != len(set(methods)):
            raise ValueError("empty or duplicate AST inventory")
        expected[path.name] = sorted(methods)
    return expected


def isolated_inventory(root):
    expected = source_inventory(root)
    # Accepted collector uses -I -B and explicitly selects only this repo's src.
    observed = SUCCESSOR.discover_inventory(root)
    if observed != expected:
        raise ValueError("child inventory drift")
    return observed


def validate_checkpoint(rows, sources):
    load_baseline(sources.get(BASELINE_PATH))
    hook = SUCCESSOR.RECORD["hook"]
    proof = SUCCESSOR.parse_hook_proof(sources[hook["proofPath"]]) if hook["proofPath"] in sources else None
    result = SUCCESSOR.validate_composition(rows, sources.get(hook["path"]), proof)
    if result["stage"] < 1:
        raise ValueError("complete session packet required")
    actual = {row["path"]: row for row in rows}
    for path, expected in CURRENT["files"].items():
        # Only the accepted exact proof can account for the final launcher delta.
        if path == hook["path"] and result["stage"] == 6:
            continue
        row = actual[path]
        raw = sources[path]
        if ((row["mode"], row["size"], "sha256:" + row["sha256"]) !=
                (expected["mode"], expected["size"], expected["sha256"])
                or row["sha256"] != hashlib.sha256(raw).hexdigest()
                or len(raw) != row["size"]
                or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != expected["blob"]):
            raise ValueError("accepted predecessor changed: " + path)
    return result


def verify_repository(root):
    rows, sources = SUCCESSOR.tracked_inventory(root)
    result = validate_checkpoint(rows, sources)
    observed = SUCCESSOR.verify_tests(root)
    if observed != CURRENT["tests"] or sum(map(len, observed.values())) != CURRENT["testCount"]:
        raise ValueError("all 170 accepted predecessor identities required")
    return result
