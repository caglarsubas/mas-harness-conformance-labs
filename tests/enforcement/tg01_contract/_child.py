"""CONF-ENF-009: TG-01's jsonschema replays in a child process on the pinned met-001 venv python.

Owner decisions Q-LC-1..4 (2026-10-18): the nine vector sets whose reference models need jsonschema run in a child
process, `/opt/planeon/toolchains/met-001/.venv/bin/python3 -I -B`, launched by absolute path; R12's own interpreter and
code stay standard library only (Q-T1, Q-T4); a missing or changed interpreter or jsonschema fails closed. The owner's
G-JSONSCHEMA root bundle (policy d9b99bd6, Q-JS-1..4) installed the venv for R12's profile; nothing is prefetched or
added as a dependency (AGENTS rule 16, Q-LC-2).

Parent side (standard library only): `run()` checks the interpreter and the venv tree against the pins in
toolchains.json, launches the child once per process, refuses any report that is not exactly the closed shape and the
pinned results, and caches the outcome, a failure included; `tally(key)` gives one child set's Tally.

Child side: `python3 -I -B _child.py --report`. The area directory is put on sys.path explicitly (-I adds none), and
tg01_contract._replays.child_report() runs every child set and its pinned flip; the report is printed as one JSON
object. Nothing may be written to stderr.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

AREA = Path(__file__).resolve().parent.parent
TOOLCHAINS = AREA / "toolchains.json"
ROW_ID = "python-met-001-child"
REPORT_KEYS = ("interpreter", "jsonschema", "tallies", "flips")
INTERPRETER_KEYS = ("versionInfo", "prefix", "basePrefix", "isolated", "dontWriteBytecode")
TIMEOUT_SECONDS = 300
_OUTCOME: dict = {}


class ChildError(AssertionError):
    pass


def require(ok, message):
    if not ok:
        raise ChildError("jsonschema child process: " + message)


def pins() -> dict:
    """The child interpreter's pinned row in toolchains.json."""
    import _models
    record = _models._strict(_models._regular(TOOLCHAINS))
    rows = [row for row in record["toolchains"] if row.get("id") == ROW_ID]
    require(len(rows) == 1, "one pinned child toolchain row")
    return rows[0]


def tree_digest(root: str) -> str:
    """sha256 over the canonical list [relative path, kind, executable bit, sha256 or link target] of every entry under
    root, links not followed, sorted by path: any added, removed or edited file, link or .pth changes it."""
    entries = []
    base = Path(root)
    for folder, directories, files in os.walk(base, followlinks=False):
        for name in sorted(directories + files):
            path = Path(folder) / name
            info = os.lstat(path)
            relative = path.relative_to(base).as_posix()
            if stat.S_ISLNK(info.st_mode):
                entries.append([relative, "link", False, os.readlink(path)])
            elif stat.S_ISDIR(info.st_mode):
                entries.append([relative, "directory", bool(info.st_mode & 0o111), None])
            else:
                require(stat.S_ISREG(info.st_mode), "only files, links and directories in the venv: " + relative)
                entries.append([relative, "file", bool(info.st_mode & 0o111), hashlib.sha256(path.read_bytes()).hexdigest()])
    entries.sort(key=lambda entry: entry[0])
    raw = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def check_report(report, pin: dict) -> dict:
    """The verified tallies from one child report, or ChildError."""
    from tg01_contract import _replays
    require(type(report) is dict and tuple(report) == REPORT_KEYS, "closed report")
    interpreter = report["interpreter"]
    require(type(interpreter) is dict and tuple(interpreter) == INTERPRETER_KEYS
            and interpreter["versionInfo"] == pin["versionInfo"] and interpreter["prefix"] == pin["prefix"]
            and interpreter["basePrefix"] == pin["basePrefix"] and interpreter["isolated"] == 1
            and interpreter["dontWriteBytecode"] is True, "the pinned interpreter, isolated and without bytecode")
    require(report["jsonschema"] == pin["jsonschema"], "the pinned jsonschema distribution")
    names = ["|".join(key) for key in _replays.CHILD_SETS]
    tallies, flips = report["tallies"], report["flips"]
    require(type(tallies) is dict and list(tallies) == names and type(flips) is dict and list(flips) == names,
            "every child set, in order")
    for key, name in zip(_replays.CHILD_SETS, names):
        ids = tallies[name]
        require(type(ids) is dict and tuple(ids) == ("PASS", "NOT_RUN_ENV_UNAVAILABLE"), "closed tally " + name)
        require(ids["NOT_RUN_ENV_UNAVAILABLE"] == [], "no child vector is NOT_RUN: " + name)
        require(ids["PASS"] == _replays.expected_ids(key), "every pinned vector of the set, in order: " + name)
        path, list_key, ident, field = _replays.FLIPS[key]
        require(flips[name] == {"id": ident, "field": field, "caught": True}, "the pinned flip is caught: " + name)
    return tallies


def _launch() -> dict:
    pin = pins()
    path = pin["path"]
    require(os.path.isabs(path) and os.access(path, os.X_OK), "the pinned interpreter exists and is executable")
    require(os.path.realpath(path).startswith(pin["realpathRoot"].rstrip("/") + "/"), "the interpreter resolves into its base root")
    require(tree_digest(pin["prefix"]) == pin["venvTreeSha256"], "the venv tree is the pinned one")
    try:
        done = subprocess.run([path, "-I", "-B", str(Path(__file__).resolve()), "--report"], cwd=str(AREA),
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, capture_output=True,
                              timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ChildError("jsonschema child process: launch failed: %s" % type(exc).__name__) from None
    require(done.returncode == 0, "exit status 0 (got %d)" % done.returncode)
    require(done.stderr == b"", "nothing on stderr")
    import _models
    try:
        report = _models._strict(done.stdout)
    except ValueError:
        raise ChildError("jsonschema child process: stdout is one strict JSON object") from None
    return check_report(report, pin)


def run() -> dict:
    """The verified tallies, launching the child once per process; a failure is cached and raised again."""
    if not _OUTCOME:
        try:
            _OUTCOME["tallies"] = _launch()
        except ChildError as exc:
            _OUTCOME["error"] = exc
    if "error" in _OUTCOME:
        raise _OUTCOME["error"]
    return _OUTCOME["tallies"]


def tally(key):
    """One child set's verified Tally."""
    from tg01_contract import _replays
    result = _replays.Tally()
    ids = run()["|".join(key)]
    result.ids["PASS"].extend(ids["PASS"])
    result.ids["NOT_RUN_ENV_UNAVAILABLE"].extend(ids["NOT_RUN_ENV_UNAVAILABLE"])
    return result


def _report() -> dict:
    import importlib.metadata
    sys.path.insert(0, str(AREA))
    from tg01_contract import _replays
    tallies, flips = _replays.child_report()
    return {"interpreter": {"versionInfo": list(sys.version_info[:5]), "prefix": sys.prefix, "basePrefix": sys.base_prefix,
                            "isolated": sys.flags.isolated, "dontWriteBytecode": sys.dont_write_bytecode},
            "jsonschema": importlib.metadata.version("jsonschema"), "tallies": tallies, "flips": flips}


if __name__ == "__main__" and sys.argv[1:] == ["--report"]:
    sys.stdout.write(json.dumps(_report(), ensure_ascii=False, separators=(",", ":")) + "\n")
