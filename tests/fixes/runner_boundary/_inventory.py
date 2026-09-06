"""Discovery accounting only; test bodies still run via separate packet argv."""
from __future__ import annotations

import ast
import inspect
import sys
import unittest
from pathlib import Path


def leaves(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from leaves(item)
        else:
            yield item


def discover_inventory(root: Path) -> dict[str, list[str]]:
    root = root.resolve(strict=True)
    files = sorted(root.rglob("test_*.py"))
    if not files or any(path.is_symlink() for path in files):
        raise ValueError("missing, empty or linked test inventory")
    expected = {}
    for path in files:
        tree = ast.parse(path.read_bytes())
        methods = [f"{node.name}.{method.name}" for node in tree.body if isinstance(node, ast.ClassDef)
                   for method in node.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and method.name.startswith("test_")]
        if not methods or len(methods) != len(set(methods)):
            raise ValueError("empty or duplicate test module inventory")
        expected[str(path.relative_to(root))] = sorted(methods)
    previous_path = sys.path[:]
    try:
        loader = unittest.TestLoader()
        suite = loader.discover(str(root), pattern="test_*.py")
        tests = list(leaves(suite))
        if loader.errors or not tests or suite.countTestCases() != len(tests):
            raise ValueError("failed or empty discovery")
        observed = {}
        for test in tests:
            source = Path(inspect.getfile(type(test))).resolve(strict=True)
            method = getattr(test, test._testMethodName)
            if getattr(test, "__unittest_skip__", False) or getattr(method, "__unittest_skip__", False):
                raise ValueError("skipped tests cannot establish inventory closure")
            if getattr(method, "__unittest_expecting_failure__", False):
                raise ValueError("expected failure cannot establish inventory closure")
            key = str(source.relative_to(root))
            observed.setdefault(key, []).append(type(test).__name__ + "." + test._testMethodName)
        observed = {key: sorted(value) for key, value in observed.items()}
        if observed != expected:
            raise ValueError("discovery omitted, duplicated or substituted tests")
        return observed
    finally:
        sys.path[:] = previous_path
