"""The native probe workspace's CI gates (W04-4a, CONF-ENF-004; owner decision Q-T2 (b), 2026-10-13).

The probes compile only on the author's machine until the R12 Rust profile exists, so these standard-library tests are
what CI checks: the closed file set and manifests (standard library only, no build scripts or patches, the author-only
linker setting), where `unsafe` and foreign code may appear, that the probes record and never judge, the generated files
and the tree digest, the probe map against the TG-04/TG-05 ledgers, and the author's compile evidence for this exact tree.
"""
from __future__ import annotations

import json
import re
import tomllib
import unittest

import _catalog
import _models
import _probes
from tg05_clocks import _verdicts

PROBES = _probes.PROBES
CRATES = ("common", "tg04_host", "tg05_clocks")
# The tree reviewed in CONF-ENF-004; a change to any probe file changes it and needs fresh compile evidence.
PROBE_TREE = "46887c7a8978e64c5c72dc95e2548ed898f566c308624590541ae53938c24e8b"
SOURCES = {
    "common": {"binding.rs", "cgroup.rs", "lib.rs", "nr.rs", "proc.rs", "read.rs", "role.rs", "sys.rs", "time.rs", "timeline.rs",
               "tree.rs"},
    "tg04_host": {"main.rs"},
    "tg05_clocks": {"expected.rs", "main.rs"},
}
FILES = ({"Cargo.lock", "Cargo.toml", _probes.EVIDENCE_FILE}
         | {"%s/Cargo.toml" % crate for crate in CRATES}
         | {"%s/src/%s" % (crate, name) for crate, names in SOURCES.items() for name in names})
RELEASE = {"panic": "unwind", "opt-level": 2, "codegen-units": 1, "debug": False, "strip": "symbols"}
TARGETS = ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl")
# Tokens no probe source may hold: code or data from outside the tree, the build environment, or foreign linkage.
FORBIDDEN = ("extern crate", "include!", "include_str!", "include_bytes!", "env!", "option_env!", "#[path", "#![path",
             "proc_macro", "asm!", "global_asm!", "no_mangle", "#[link", "export_name", "link_section",
             # Review D2-13: no process spawning, networking or environment reads in a probe.
             "Command", "std::net", "TcpStream", "TcpListener", "UdpSocket", "UnixStream", "UnixListener", "UnixDatagram",
             "std::os::unix::net", "env::var", "env::vars", "set_var")
EVIDENCE_FIELDS = {"schemaVersion", "packet", "kind", "decision", "probeTree", "toolchain", "environment", "commands", "binaries"}


def text(relative):
    return _models._regular(PROBES / relative).decode("utf-8")


def toml(relative):
    return tomllib.loads(text(relative))


def rust_sources():
    return {"%s/src/%s" % (crate, name): text("%s/src/%s" % (crate, name)) for crate, names in SOURCES.items() for name in names}


def code(source):
    """The source without its comments, string literals kept (review D2-13: a "//" inside a string is not a comment, so
    nothing after it on the line can hide). Handles line and nested block comments, strings with escapes, raw strings
    (r"..", r#".."#), byte strings and char literals; a lifetime ('a) is code."""
    out, i, n = [], 0, len(source)
    while i < n:
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
        elif source.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif source.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    out.append("\n" if source[i] == "\n" else "")
                    i += 1
        elif re.match(r'b?r#*"', source[i:]):
            prefix = re.match(r'b?r(#*)"', source[i:])
            end = source.find('"' + prefix.group(1), i + len(prefix.group(0)))
            if end < 0:
                raise ValueError("unterminated raw string")
            stop = end + 1 + len(prefix.group(1))
            out.append(source[i:stop])
            i = stop
        elif source[i] == '"':
            j = i + 1
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            if j >= n:
                raise ValueError("unterminated string")
            out.append(source[i:j + 1])
            i = j + 1
        elif source[i] == "'" and re.match(r"'(\\.|\\u\{[0-9a-fA-F]+\}|[^\\'])'", source[i:]):
            literal = re.match(r"'(\\.|\\u\{[0-9a-fA-F]+\}|[^\\'])'", source[i:]).group(0)
            out.append(literal)
            i += len(literal)
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


class TreeTests(unittest.TestCase):
    def test_the_tree_is_exactly_the_reviewed_file_set(self):
        # Review D1-15: a target/ directory, a build script, a toolchain or cargo config file or any other file is
        # refused, not skipped. The author's linker setting lives in the build environment (BUILD_EVIDENCE.json).
        self.assertEqual(set(_probes.tree_files()), FILES)

    def test_generated_files_regenerate_byte_exactly(self):
        for relative, make in _probes.GENERATED.items():
            with self.subTest(file=relative):
                self.assertEqual(text(relative), make())

    def test_the_tree_digest_is_the_reviewed_one(self):
        self.assertEqual(_probes.tree_digest(), PROBE_TREE)
        self.assertIn('"%s"' % PROBE_TREE, text(_probes.TREE_FILE))


class ManifestTests(unittest.TestCase):
    def test_the_workspace_has_three_members_and_the_release_profile(self):
        workspace = toml("Cargo.toml")
        self.assertEqual(set(workspace), {"workspace", "profile"})
        self.assertEqual(workspace["workspace"], {"members": list(CRATES), "resolver": "2",
                                                  "package": {"version": "0.1.0", "edition": "2021", "publish": False}})
        self.assertEqual(workspace["profile"], {"release": RELEASE})

    def test_each_crate_is_std_only_with_no_build_script(self):
        for crate in CRATES:
            with self.subTest(crate=crate):
                manifest = toml("%s/Cargo.toml" % crate)
                package = {"name": crate, "version": {"workspace": True}, "edition": {"workspace": True},
                           "publish": {"workspace": True}}
                expected = {"package": package}
                if crate != "common":
                    expected["dependencies"] = {"common": {"path": "../common"}}
                # No build key, links, features, targets, dev or build dependencies, patch or replace.
                self.assertEqual(manifest, expected)

    def test_the_lock_file_holds_only_the_workspace(self):
        lock = toml("Cargo.lock")
        self.assertEqual(lock, {"version": 4, "package": [
            {"name": "common", "version": "0.1.0"},
            {"name": "tg04_host", "version": "0.1.0", "dependencies": ["common"]},
            {"name": "tg05_clocks", "version": "0.1.0", "dependencies": ["common"]}]})


class SourceTests(unittest.TestCase):
    def test_unsafe_code_and_foreign_functions_live_only_in_sys(self):
        for relative, source in rust_sources().items():
            with self.subTest(file=relative):
                body = code(source)
                if relative == "common/src/sys.rs":
                    self.assertIn('extern "C"', body)
                    continue
                self.assertNotRegex(body, r"\bunsafe\b")
                self.assertNotIn('extern "C"', body)
        lib = code(text("common/src/lib.rs"))
        self.assertIn("#![deny(unsafe_code)]", lib)
        # Review D2-13: exactly one allow(unsafe_code) in the whole tree, on `mod sys`.
        self.assertEqual(sum(code(source).count("allow(unsafe_code)") for source in rust_sources().values()), 1)
        self.assertIn("#[allow(unsafe_code)]\npub mod sys;", lib)
        for crate in ("tg04_host", "tg05_clocks"):
            self.assertIn("#![forbid(unsafe_code)]", code(text("%s/src/main.rs" % crate)))

    def test_no_source_reaches_outside_the_tree(self):
        for relative, source in rust_sources().items():
            for token in FORBIDDEN:
                with self.subTest(file=relative, token=token):
                    self.assertNotIn(token, code(source))

    def test_syscalls_are_only_the_generated_ones(self):
        sys_code = code(text("common/src/sys.rs"))
        used = set(re.findall(r"crate::nr::([A-Z_]+)", sys_code))
        self.assertEqual(used, {name.upper() for name in _probes.SYSCALLS})
        self.assertEqual(set(re.findall(r"\bsyscall\(", sys_code)), {"syscall("})

    def test_the_probes_record_and_never_judge(self):
        # Review D1-8: the only PASS a probe writes is its faultResult; no case result, check or verdict comes from Rust.
        passes = {relative: code(source).count('"PASS"') for relative, source in rust_sources().items()}
        self.assertEqual({relative: count for relative, count in passes.items() if count}, {"tg05_clocks/src/main.rs": 1})
        self.assertIn('record("end", &[("faultResult", string("PASS"))', code(text("tg05_clocks/src/main.rs")))
        for word in ('"FAIL"', "verdict", '"result"'):
            for relative, source in rust_sources().items():
                with self.subTest(file=relative, word=word):
                    self.assertNotIn(word, code(source))


class ProbeMapTests(unittest.TestCase):
    def test_every_tg05_probe_case_is_one_registered_function(self):
        main = code(text("tg05_clocks/src/main.rs"))
        entries = re.findall(r'Case \{ tag: "([^"]+)", name: "([a-z_]+)",\s+keys: &\[[^\]]*\],\s+run: ([a-z_]+) \}', main)
        # Review D2-13: each entry runs the function its name says.
        self.assertTrue(entries)
        self.assertTrue(all(name == run for _, name, run in entries))
        self.assertEqual(len(entries), main.count("Case { tag:"))
        registered = {tag: name for tag, name, _ in entries}
        ledger = {row["tag"]: row["probe"]["case"] for row in _catalog.ledger("TG-05", {})["cases"] if row["probe"]}
        self.assertEqual(registered, ledger)
        for name in ledger.values():
            self.assertEqual(len(re.findall(r"\nfn %s\(" % name, main)), 1)

    def test_each_probe_case_writes_every_record_its_verdict_reads(self):
        # Review D4-1: the verdicts refuse a timeline missing a record, so each case function must write (directly or
        # through the helper named here) every record _verdicts.RECORDS lists for it.
        main = code(text("tg05_clocks/src/main.rs"))
        writers = {("deadline", None): "deadline(binding)?", ("fault", "SIGKILL"): "kill(", ("observation", "restarted"): "restarted(",
                   ("fault", "SIGCONT"): "Continue(", ("restore", "CLOCK_SET"): "Restore(",
                   ("fault", "SIGSTOP"): 'string("SIGSTOP")', ("fault", "SUSPEND"): 'string("SUSPEND")',
                   ("fault", "CLOCK_SET"): 'string("CLOCK_SET")', ("observation", "rolledBackAtRestore"): 'string("rolledBackAtRestore")'}
        # The helpers write what they are named for.
        for helper, literal in (("fn deadline(", 'record("deadline"'), ("fn kill(", 'string("SIGKILL")'),
                                ("fn restarted(", 'string("restarted")'), ("impl Drop for Continue", 'string("SIGCONT")'),
                                ("impl Drop for Restore", 'string("CLOCK_SET")')):
            body = main[main.index(helper):]
            body = body[:body.index("\n}\n")]
            self.assertIn(literal, body, helper)
        registered = dict(re.findall(r'Case \{ tag: "([^"]+)", name: "([a-z_]+)"', main))
        for tag, needed in ((tag, items + _verdicts.OPTIONAL_RECORDS.get(tag, [])) for tag, items in _verdicts.RECORDS.items()):
            body = main[main.index("\nfn %s(" % registered[tag]):]
            body = body[:body.index("\n}\n")]
            for record in needed:
                with self.subTest(case=tag, record=record):
                    self.assertIn(writers[record], body)

    def test_every_tg04_case_waits_for_conf_enf_005(self):
        for row in _catalog.ledger("TG-04", {})["cases"]:
            with self.subTest(case=row["tag"]):
                self.assertEqual((row["probe"], row["probeIn"]), (None, "CONF-ENF-005"))


class EvidenceTests(unittest.TestCase):
    def test_the_author_compile_evidence_names_this_tree_and_no_local_path(self):
        # Owner decision Q-T2 (b): author evidence, not CI evidence; review D1-16: tied to the tree digest, with
        # placeholders instead of local paths.
        raw = text(_probes.EVIDENCE_FILE)
        evidence = _models._strict(raw.encode())
        self.assertEqual(set(evidence), EVIDENCE_FIELDS)
        self.assertEqual((evidence["packet"], evidence["kind"], evidence["decision"], evidence["probeTree"]),
                         ("CONF-ENF-004", "AUTHOR_EVIDENCE_NOT_CI", "Q-T2-B", PROBE_TREE))
        self.assertEqual(evidence["toolchain"]["inventorySha256"],
                         "97ebc29febe842f316f0d569cd777a43067b9f326f7683779ee0647a39ec372f")
        self.assertEqual(sorted((row["target"], row["crate"]) for row in evidence["binaries"]),
                         sorted((target, crate) for target in TARGETS for crate in ("tg04_host", "tg05_clocks")))
        for row in evidence["binaries"]:
            with self.subTest(binary=(row["target"], row["crate"])):
                self.assertRegex(row["sha256"], "^[0-9a-f]{64}$")
                self.assertIn("statically linked" if row["target"].startswith("aarch64") else "static", row["file"])
        # Review D2-13: no local path, home directory or temporary directory of the author's machine.
        self.assertNotRegex(raw, r"/Users/|/home/|/private/|/var/folders/|/tmp/|/root/|~/")


if __name__ == "__main__":
    unittest.main()
