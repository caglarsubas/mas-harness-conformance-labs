"""CONF-ENF-002: the one reviewed loader for the snapshotted reference models and contract data.

Every file is read as a regular unlinked file and checked against snapshots/manifest.json (sha256 and size) before it is
parsed or executed; nothing outside the manifest is loaded. A model is executed from its pinned bytes under its own
module name, after the sibling models it imports, so its `import <sibling>` resolves to the pinned sibling and never to
an outside module. This is the only module in the enforcement area that loads code by path (tests/enforcement
test_bootstrap admits it by name). Standard library only (owner decision Q-T1, 2026-10-11).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

AREA = Path(__file__).resolve().parent
MANIFEST = AREA / "snapshots" / "manifest.json"
# Sibling imports of each snapshotted model, in load order (from the models' own import statements).
SIBLINGS = {
    "i05_gate_channel_v3": (),
    "i07_policy_write_v3": ("i05_gate_channel_v3",),
    "i06_backend_profile": (),
    "native_qualification_v3": (),
    "i06_backend_profile_v2": ("i06_backend_profile", "native_qualification_v3"),
    "admission_semantics_v3": (),
    "selinux_matrix_v2": (),
    "seccomp_allowlists_v2": (),
    "host_interface_amendment": (),
}
_LOADED: dict[str, object] = {}


def _strict(raw: bytes):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key " + key)
            value[key] = item
        return value
    def constant(name):
        raise ValueError("non-finite number " + name)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _manifest() -> dict:
    return _strict(_regular(MANIFEST))


def _regular(path: Path) -> bytes:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("regular unlinked file required: %s" % path)
    return path.read_bytes()


def snapshot_bytes(relative: str) -> bytes:
    """The pinned bytes of one snapshotted harness-onion path, checked against the manifest."""
    manifest = _manifest()
    rows = [row for row in manifest["files"] if row["path"] == relative]
    if len(rows) != 1:
        raise ValueError("not a snapshotted path: " + relative)
    raw = _regular(AREA.parent.parent / manifest["root"] / relative)
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (rows[0]["size"], rows[0]["sha256"]):
        raise ValueError("snapshot bytes changed: " + relative)
    return raw


def data(relative: str):
    """A snapshotted JSON file, parsed strictly (duplicate keys and non-finite numbers refused)."""
    return _strict(snapshot_bytes(relative))


def model(name: str):
    """A snapshotted reference model, executed once from its pinned bytes after its pinned siblings."""
    if name in _LOADED:
        return _LOADED[name]
    if name not in SIBLINGS:
        raise ValueError("not a snapshotted model: " + name)
    for sibling in SIBLINGS[name]:
        model(sibling)
        # Review R1-2: the model's `import <sibling>` reads sys.modules, so the name must still hold the pinned sibling.
        if sys.modules.get(sibling) is not _LOADED[sibling]:
            raise ValueError("an outside module holds the sibling name " + sibling)
    raw = snapshot_bytes("scripts/%s.py" % name)
    if name in sys.modules and sys.modules[name] is not _LOADED.get(name):
        raise ValueError("an outside module already holds the name " + name)
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(AREA / "snapshots/harness-onion/scripts" / (name + ".py"))
    sys.modules[name] = module
    try:
        # Review R1-10: the model compiles with its own future imports only, not this loader's.
        exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        del sys.modules[name]
        raise
    _LOADED[name] = module
    return module
