"""AST/actual discovery accounting; no test body is run by this helper.

Each root is collected in a fresh child of the SAME offline isolated process
tree. Flat roots reuse names such as _fixtures and test_inventory; sharing an
import cache would substitute a different suite's helpers. Legacy files stay
unchanged and each suite's actual test execution is a separate packet command.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import subprocess
import sys
import unittest


def source_inventory(root):
    root = Path(root).resolve(strict=True)
    files = sorted(root.rglob("test_*.py"))
    if not files:
        raise ValueError("empty inventory")
    expected = {}
    for path in files:
        if path.is_symlink() or path.parent != root:
            raise ValueError("test root must remain flat and unlinked")
        tree = ast.parse(path.read_bytes())
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


def leaves(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from leaves(item)
        else:
            yield item


def collect(root):
    root = Path(root).resolve(strict=True)
    expected = source_inventory(root)
    loader = unittest.TestLoader()
    suite = loader.discover(str(root), pattern="test_*.py")
    tests = list(leaves(suite))
    if loader.errors or not tests or len(tests) != suite.countTestCases():
        raise ValueError("failed or empty actual discovery")
    observed = {}
    for test in tests:
        method = getattr(test, test._testMethodName)
        if any(getattr(obj, "__unittest_skip__", False) or
               getattr(obj, "__unittest_expecting_failure__", False) for obj in (test, method)):
            raise ValueError("skip or expected failure is forbidden")
        source = Path(inspect.getfile(type(test))).resolve(strict=True)
        if source.parent != root:
            raise ValueError("substituted discovery module")
        observed.setdefault(source.name, []).append(type(test).__name__ + "." + test._testMethodName)
    observed = {name: sorted(ids) for name, ids in observed.items()}
    if observed != expected:
        raise ValueError("omitted, duplicated or substituted test identity")
    return observed


def isolated_inventory(root):
    result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), str(root)],
                            capture_output=True, text=True, timeout=60, check=False)
    if result.returncode:
        raise ValueError("inventory subprocess failed: " + result.stderr[-2000:])
    observed = json.loads(result.stdout)
    if observed != source_inventory(root):
        raise ValueError("child inventory drift")
    return observed


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("one flat root required")
    print(json.dumps(collect(sys.argv[1]), sort_keys=True))
