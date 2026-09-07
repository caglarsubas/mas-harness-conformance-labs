"""Real local parser regressions; stored before-source remains inert data."""
from __future__ import annotations

import contextlib
from copy import deepcopy
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_PATH = "fixtures/platform/linux-baseline/scalar-repair.json"
FIXTURE_SHA256 = "0e04f3878efd8196fc33aa47a80ecbf5a48e7df262f08b98030acfd4c565fd06"
TEST_PATH = "tests/platform/linux_baseline/test_packet_scalars.py"
ADDED_PATHS = {FIXTURE_PATH, TEST_PATH, "docs/reports/packet-scalar-repair.md"}
SCALARS = ("id", "repository", "warmSourceAccess")
FIELDS = (*SCALARS, "prefetchCommands", "offlineAcceptanceCommands", "offlineExecution")
NEW_TEST_IDS = (
    "ScalarParsingTests.test_all_six_published_packets_decode_to_independent_views",
    "ScalarParsingTests.test_all_bare_quoted_and_mixed_forms_preserve_values",
    "ScalarParsingTests.test_json_ascii_escapes_decode_without_reserializing_packet",
    "ScalarParsingTests.test_identifier_length_and_ascii_grammar_boundaries",
    "ScalarParsingTests.test_malformed_quotes_escapes_and_trailing_values_refuse",
    "ScalarParsingTests.test_quoted_control_whitespace_and_non_ascii_refuse",
    "ScalarParsingTests.test_bare_indirection_numeric_and_container_values_refuse",
    "ScalarParsingTests.test_duplicate_scalar_and_structured_fields_refuse",
    "ScalarParsingTests.test_missing_fields_refuse",
    "ScalarParsingTests.test_non_string_decoder_values_refuse",
    "ScalarParsingTests.test_field_order_and_outer_yaml_whitespace_preserve_values",
    "ScalarParsingTests.test_structured_fields_remain_inline_json_only",
    "ScalarAuthorizationTests.test_extraction_does_not_authorize_wrong_identity",
    "ScalarAuthorizationTests.test_boolean_and_null_words_never_authorize_identity",
    "ScalarAuthorizationTests.test_all_offline_contract_members_are_enforced",
    "ScalarAuthorizationTests.test_command_phase_types_and_bounds_refuse",
    "ScalarAuthorizationTests.test_shell_download_and_recursive_transports_refuse",
    "ScalarAuthorizationTests.test_command_order_and_arguments_are_not_normalized",
    "ScalarIntegrityTests.test_fixture_and_authority_remain_exact_source_only_inputs",
    "ScalarIntegrityTests.test_fixture_tamper_duplicate_and_nonfinite_values_refuse",
    "ScalarIntegrityTests.test_two_exact_source_transformations_preserve_all_other_bytes",
    "ScalarIntegrityTests.test_unapproved_source_mutations_and_unknown_paths_refuse",
    "ScalarIntegrityTests.test_all_103_original_files_and_only_three_additions_remain",
    "ScalarIntegrityTests.test_missing_extra_or_modified_original_inventory_refuses",
    "ScalarIntegrityTests.test_all_120_predecessor_and_all_new_test_ids_are_collected",
    "ScalarIntegrityTests.test_baseline_history_and_failed_draft_are_not_promoted",
    "ScalarExecutionTests.test_real_parser_drives_all_six_ordered_mocked_sessions",
    "ScalarExecutionTests.test_prefetch_order_and_failure_short_circuit_remain",
    "ScalarExecutionTests.test_invalid_identity_fails_before_any_child",
    "ScalarExecutionTests.test_digest_refusal_stops_before_acceptance",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate fixture key")
        result[key] = value
    return result


def nonfinite(value):
    raise ValueError("nonfinite fixture value")


def load_fixture(raw):
    document = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    if sha(raw) != FIXTURE_SHA256:
        raise ValueError("unpinned fixture")
    return document


def regular(relative):
    path = ROOT
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("invalid source path")
    for index, part in enumerate(parts):
        path = path / part
        check = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not check(path.lstat().st_mode):
            raise ValueError("linked or nonregular source")
    return path


FIXTURE = load_fixture(regular(FIXTURE_PATH).read_bytes())
BASELINE = json.loads(FIXTURE["baselineRaw"], object_pairs_hook=pairs, parse_constant=nonfinite)


def load_local(name, relative):
    spec = importlib.util.spec_from_file_location(name, regular(relative))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load_local("scalar_local_packet_reader", "ci/run_packet.py")


def text_view(view, quoted=SCALARS):
    return "\n".join(name + ": " + (view[name] if name in SCALARS and name not in quoted
                                  else json.dumps(view[name], separators=(",", ":")))
                     for name in FIELDS) + "\n"


def replace_field(text, field, raw):
    lines = text.splitlines()
    indexes = [i for i, line in enumerate(lines) if line.startswith(field + ":")]
    if len(indexes) != 1:
        raise ValueError("fixture field is not unique")
    lines[indexes[0]] = field + ": " + raw
    return "\n".join(lines) + "\n"


def check_edit(path, before, after):
    if path not in FIXTURE["changes"] or type(before) is not bytes or type(after) is not bytes:
        raise ValueError("unknown edit or wrong byte type")
    change = FIXTURE["changes"][path]
    old, new = change["beforeBlock"].encode(), change["afterBlock"].encode()
    if sha(before) != change["beforeSha256"] or before.count(old) != 1:
        raise ValueError("wrong original source")
    prefix, suffix = before.split(old)
    if (sha(prefix) != change["prefixSha256"] or sha(suffix) != change["suffixSha256"]
            or after != prefix + new + suffix or sha(after) != change["afterSha256"]):
        raise ValueError("unapproved transformation")


def expected_original_files():
    return {path: {"mode": value["mode"], "sha256": (
        "sha256:" + FIXTURE["changes"][path]["afterSha256"] if path in FIXTURE["changes"]
        else value["sha256"])} for path, value in BASELINE["files"].items()}


def check_original_files(observed):
    if observed != expected_original_files():
        raise ValueError("original inventory omitted, expanded or changed")


def require_refusal(case, callback):
    with contextlib.redirect_stderr(io.StringIO()), case.assertRaises(SystemExit) as raised:
        callback()
    case.assertEqual(raised.exception.code, 2)


class ScalarParsingTests(unittest.TestCase):
    def test_all_six_published_packets_decode_to_independent_views(self):
        self.assertEqual(tuple(FIXTURE["publishedPackets"]), tuple(f"CONF-LIVE-{i:03}" for i in range(1, 7)))
        for packet_id, packet in FIXTURE["publishedPackets"].items():
            with self.subTest(packet=packet_id):
                self.assertEqual(sha(packet["raw"].encode()), packet["sha256"])
                self.assertEqual(RUNNER.extract(packet["raw"]), packet["view"])
                self.assertEqual(RUNNER.validate_packet(RUNNER.extract(packet["raw"])),
                                 ([], packet["view"]["offlineAcceptanceCommands"]))
                self.assertEqual(len(packet["view"]["offlineAcceptanceCommands"]), 8)

    def test_all_bare_quoted_and_mixed_forms_preserve_values(self):
        for mask in itertools.product((False, True), repeat=3):
            view = FIXTURE["correctionView"]
            quoted = {field for field, value in zip(SCALARS, mask) if value}
            with self.subTest(quoted=quoted):
                parsed = RUNNER.extract(text_view(view, quoted))
                self.assertEqual(parsed, view)
                self.assertEqual(RUNNER.validate_packet(parsed), ([], view["offlineAcceptanceCommands"]))

    def test_json_ascii_escapes_decode_without_reserializing_packet(self):
        packet = FIXTURE["publishedPackets"]["CONF-LIVE-001"]
        text = replace_field(packet["raw"], "id", '"\\u0043ONF\\u002dLIVE-001"')
        before = text.encode()
        self.assertEqual(RUNNER.extract(text), packet["view"])
        RUNNER.validate_packet(RUNNER.extract(text))
        self.assertEqual(text.encode(), before)
        self.assertNotEqual(sha(before), packet["sha256"])

    def test_identifier_length_and_ascii_grammar_boundaries(self):
        text = text_view(FIXTURE["correctionView"])
        for value in ("A", "a", "A-_09", "A" * 128):
            for quoted in (False, True):
                raw = json.dumps(value) if quoted else value
                with self.subTest(value=value, quoted=quoted):
                    self.assertEqual(RUNNER.extract(replace_field(text, "id", raw))["id"], value)
        for value in ("", "A" * 129, "0A", "-A", "_A", "A.B", "A/B", "A:B", "A B"):
            for quoted in (False, True):
                raw = json.dumps(value) if quoted else value
                with self.subTest(value=value, quoted=quoted):
                    require_refusal(self, lambda: RUNNER.extract(replace_field(text, "id", raw)))

    def test_malformed_quotes_escapes_and_trailing_values_refuse(self):
        bad = ('"', '"unterminated', '"A" "B"', '"A",', '"A" # comment',
               '"A\\x20B"', '"A\\u00ZZ"', '"A\\"', "'CONF-FIX-002'", '"A";false')
        for field, raw in itertools.product(SCALARS, bad):
            with self.subTest(field=field, raw=raw):
                require_refusal(self, lambda: RUNNER.extract(replace_field(text_view(FIXTURE["correctionView"]), field, raw)))

    def test_quoted_control_whitespace_and_non_ascii_refuse(self):
        values = ["A" + chr(code) + "B" for code in (*range(33), 127)]
        values += [" A", "A ", "Ａ", "CÖNF", "А", "A\u200bB", "A\ufeffB", "A\ud800B"]
        for field, value in itertools.product(SCALARS, values):
            with self.subTest(field=field, value=repr(value)):
                require_refusal(self, lambda: RUNNER.extract(replace_field(text_view(FIXTURE["correctionView"]), field, json.dumps(value))))

    def test_bare_indirection_numeric_and_container_values_refuse(self):
        for raw in ("&anchor A", "*alias", "!tag A", "!!str A", "|", ">", "[A]", "{x: A}",
                    "[]", "{}", "123", "0.5", "-1", "# missing", "A # comment", "A\tB"):
            with self.subTest(raw=raw):
                require_refusal(self, lambda: RUNNER.extract(replace_field(text_view(FIXTURE["correctionView"]), "id", raw)))

    def test_duplicate_scalar_and_structured_fields_refuse(self):
        text = text_view(FIXTURE["correctionView"])
        for field in FIELDS:
            line = next(line for line in text.splitlines() if line.startswith(field + ":"))
            with self.subTest(field=field):
                require_refusal(self, lambda: RUNNER.extract(text + line + "\n"))

    def test_missing_fields_refuse(self):
        text = text_view(FIXTURE["correctionView"])
        for field in FIELDS:
            missing = "\n".join(line for line in text.splitlines() if not line.startswith(field + ":"))
            with self.subTest(field=field):
                require_refusal(self, lambda: RUNNER.extract(missing))

    def test_non_string_decoder_values_refuse(self):
        text = text_view(FIXTURE["correctionView"])
        for value in (None, True, False, 1, 1.5, [], {}):
            with self.subTest(value=value), mock.patch.object(RUNNER.json, "loads", return_value=value):
                require_refusal(self, lambda: RUNNER.extract(text))

    def test_field_order_and_outer_yaml_whitespace_preserve_values(self):
        view = FIXTURE["correctionView"]
        text = "\r\n".join(line.replace(": ", ":\t ", 1) + " \t" for line in reversed(text_view(view).splitlines()))
        self.assertEqual(RUNNER.extract(text), view)

    def test_structured_fields_remain_inline_json_only(self):
        text = text_view(FIXTURE["correctionView"])
        for field, raw in itertools.product(FIELDS[3:], ("", "[bad]", "{bad}", "|", "*alias", "[] trailing")):
            with self.subTest(field=field, raw=raw):
                require_refusal(self, lambda: RUNNER.extract(replace_field(text, field, raw)))


class ScalarAuthorizationTests(unittest.TestCase):
    def test_extraction_does_not_authorize_wrong_identity(self):
        values = {"id": ("MET-001", "CONF", "conf-FIX-002", "CONF_fix_002"),
                  "repository": ("Harness-Engineering", "other-repository"),
                  "warmSourceAccess": ("COPY_AUTHORIZED", "AUTHORIZED_READ_ONLY_OBSERVATION")}
        for field, cases in values.items():
            for value in cases:
                with self.subTest(field=field, value=value):
                    view = RUNNER.extract(replace_field(text_view(FIXTURE["correctionView"]), field, json.dumps(value)))
                    self.assertEqual(view[field], value)
                    require_refusal(self, lambda: RUNNER.validate_packet(view))

    def test_boolean_and_null_words_never_authorize_identity(self):
        for field, word in itertools.product(SCALARS, ("true", "false", "null", "yes", "no", "NaN", "Infinity")):
            with self.subTest(field=field, word=word):
                parsed = RUNNER.extract(replace_field(text_view(FIXTURE["correctionView"]), field, word))
                self.assertIs(type(parsed[field]), str)
                require_refusal(self, lambda: RUNNER.validate_packet(parsed))

    def test_all_offline_contract_members_are_enforced(self):
        for field in FIXTURE["correctionView"]["offlineExecution"]:
            view = deepcopy(FIXTURE["correctionView"])
            view["offlineExecution"][field] = "UNAUTHORIZED"
            with self.subTest(field=field):
                require_refusal(self, lambda: RUNNER.validate_packet(RUNNER.extract(text_view(view))))

    def test_command_phase_types_and_bounds_refuse(self):
        bad = (None, True, {}, "argv", [None], [[]], [["python3", ""]], [["python3", 1]],
               [["python3", "A" * 4097]], [["python3"] + ["x"] * 32])
        for field, value in itertools.product(("prefetchCommands", "offlineAcceptanceCommands"), bad):
            view = deepcopy(FIXTURE["correctionView"])
            view[field] = value
            with self.subTest(field=field, value=value):
                require_refusal(self, lambda: RUNNER.validate_packet(RUNNER.extract(text_view(view))))
        view = deepcopy(FIXTURE["correctionView"])
        view["offlineAcceptanceCommands"] = []
        require_refusal(self, lambda: RUNNER.validate_packet(RUNNER.extract(text_view(view))))

    def test_shell_download_and_recursive_transports_refuse(self):
        cases = [[name, "unit"] for name in ("sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh", "curl", "wget", "pip", "npm", "npx")]
        cases += [["python3", name] for name in ("fetch", "download", "install", "pull", "clone")]
        cases += [["make", "verify-offline"], ["make", "prefetch"]]
        for argv in cases:
            view = deepcopy(FIXTURE["correctionView"])
            view["offlineAcceptanceCommands"] = [argv]
            with self.subTest(argv=argv):
                require_refusal(self, lambda: RUNNER.validate_packet(RUNNER.extract(text_view(view))))

    def test_command_order_and_arguments_are_not_normalized(self):
        original = FIXTURE["correctionView"]["offlineAcceptanceCommands"]
        for commands in (original, list(reversed(original)), [["python3", "argument with spaces"]]):
            view = deepcopy(FIXTURE["correctionView"])
            view["offlineAcceptanceCommands"] = commands
            self.assertEqual(RUNNER.validate_packet(RUNNER.extract(text_view(view))), ([], commands))
        # Valid argv are preserved, not authorized against a different packet digest.
        view = deepcopy(FIXTURE["correctionView"])
        view["offlineAcceptanceCommands"] = list(reversed(original))
        self.assertNotEqual(sha(text_view(view).encode()), sha(text_view(FIXTURE["correctionView"]).encode()))


class ScalarIntegrityTests(unittest.TestCase):
    def test_fixture_and_authority_remain_exact_source_only_inputs(self):
        self.assertEqual(sha(regular(FIXTURE_PATH).read_bytes()), FIXTURE_SHA256)
        self.assertEqual(FIXTURE["authority"]["commit"], "c526ccaa293b2113032c5a5b4a037e35baacb196")
        self.assertEqual(FIXTURE["packetSha256"], "c8639e527496660b8211f5bdcdb8f7470129b7d00f938c061d34630c797d8af4")
        self.assertEqual(FIXTURE["evidenceClass"], "UNIT_REGRESSION_INPUTS_ONLY")
        self.assertIs(FIXTURE["nativeAcceptance"], False)
        self.assertEqual(sha(FIXTURE["baselineRaw"].encode()), FIXTURE["baselineRawSha256"])
        self.assertEqual(len(BASELINE["files"]), 103)
        self.assertEqual(sum(map(len, BASELINE["tests"].values())), 120)

    def test_fixture_tamper_duplicate_and_nonfinite_values_refuse(self):
        raw = regular(FIXTURE_PATH).read_bytes()
        for changed in (raw + b"\n", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"nativeAcceptance":true}'):
            with self.subTest(changed=changed[:40]), self.assertRaises(ValueError):
                load_fixture(changed)

    def test_two_exact_source_transformations_preserve_all_other_bytes(self):
        for path, change in FIXTURE["changes"].items():
            before = FIXTURE["beforeSources"][path].encode()
            with self.subTest(path=path):
                check_edit(path, before, regular(path).read_bytes())
                self.assertEqual(BASELINE["files"][path]["sha256"], "sha256:" + sha(before))

    def test_unapproved_source_mutations_and_unknown_paths_refuse(self):
        for path, change in FIXTURE["changes"].items():
            before = FIXTURE["beforeSources"][path].encode()
            old, new = change["beforeBlock"].encode(), change["afterBlock"].encode()
            correct = before.replace(old, new, 1)
            for after in (before, b"# change\n" + correct, correct + b"\n", before.replace(old, b"", 1),
                          before.replace(old, new + new, 1), before.replace(old, b"    pass\n", 1), correct.decode()):
                with self.subTest(path=path, mutation=str(after)[:40]), self.assertRaises(ValueError):
                    check_edit(path, before, after)
            with self.assertRaises(ValueError):
                check_edit(path, before + b"\n", correct)
        with self.assertRaises(ValueError):
            check_edit("ci/arbitrary.py", b"", b"")

    def test_all_103_original_files_and_only_three_additions_remain(self):
        observed = {}
        for path in BASELINE["files"]:
            file = regular(path)
            observed[path] = {"mode": "100755" if file.stat().st_mode & 0o111 else "100644", "sha256": "sha256:" + sha(file.read_bytes())}
        check_original_files(observed)
        files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout.decode().rstrip("\0").split("\0")
        self.assertEqual(set(files), set(BASELINE["files"]) | ADDED_PATHS)
        for path in ADDED_PATHS:
            self.assertTrue(stat.S_ISREG(regular(path).stat().st_mode))

    def test_missing_extra_or_modified_original_inventory_refuses(self):
        good = expected_original_files()
        check_original_files(good)
        for operation in ("missing", "extra", "hash", "mode"):
            changed = deepcopy(good)
            if operation == "missing":
                changed.pop("ci/run_packet.py")
            elif operation == "extra":
                changed["arbitrary.py"] = changed["ci/run_packet.py"]
            else:
                changed["ci/run_packet.py"]["sha256" if operation == "hash" else "mode"] = "changed"
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                check_original_files(changed)

    def test_all_120_predecessor_and_all_new_test_ids_are_collected(self):
        helper = load_local("scalar_predecessor_inventory", "tests/fixes/runner_boundary/_inventory.py")
        self.assertEqual(BASELINE["suiteRoots"], ["tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary", "tests/platform/linux_baseline"])
        observed = {}
        for root in BASELINE["suiteRoots"]:
            observed.update({root + "/" + path: ids for path, ids in helper.discover_inventory(ROOT / root).items()})
        expected = deepcopy(BASELINE["tests"])
        expected[TEST_PATH] = sorted(NEW_TEST_IDS)
        self.assertEqual(len(NEW_TEST_IDS), 30)
        self.assertEqual(len(set(NEW_TEST_IDS)), 30)
        self.assertEqual(observed, expected)
        print("scalar-test-inventory roots=5 predecessor=120 added=30 skipped=0 status=PASS", flush=True)

    def test_baseline_history_and_failed_draft_are_not_promoted(self):
        self.assertEqual(BASELINE["commit"], "88de1d9b7272a25678b01129e51d5756dbe608ed")
        self.assertFalse(BASELINE["nativeAcceptance"])
        failed = FIXTURE["failedDraft"]
        self.assertEqual((failed["commandsExecuted"], failed["testsExecuted"], failed["exitCode"]), (0, 0, 2))
        self.assertEqual(failed["ciStatus"], "CANCELLED_NOT_PASS")
        self.assertIs(failed["accepted"], False)
        self.assertEqual(FIXTURE["dispatchGate"]["requiresCompletedPacket"], "CONF-FIX-002")
        self.assertFalse(FIXTURE["dispatchGate"]["rewritePacketYaml"])
        self.assertFalse(FIXTURE["dispatchGate"]["nativeAcceptance"])


class ScalarExecutionTests(unittest.TestCase):
    def session(self, text, os_name, failure_at=None, digest_refusal=False):
        events = []
        raw = text.encode()
        environment = {"HARNESS_OFFLINE_ENFORCED": "1", "HARNESS_OFFLINE_SESSION_ID": "UNIT_ONLY",
                       "HARNESS_OFFLINE_BACKEND": "darwin-sandbox" if os_name == "darwin" else "linux-firejail",
                       "HARNESS_TASK_PACKET": "/unit/hidden-packet", "UNKNOWN": "unit-only"}
        def run(argv, *, env, check):
            index = sum(event[0] == "run" for event in events)
            self.assertNotIn("HARNESS_TASK_PACKET", env)
            self.assertNotIn("UNKNOWN", env)
            events.append(("run", argv))
            return mock.Mock(returncode=37 if index == failure_at else 0)
        def unchanged(*args):
            self.assertEqual(args[-1], sha(raw))
            events.append(("digest", sha(raw)))
            if digest_refusal:
                raise SystemExit(2)
        with tempfile.TemporaryFile() as file:
            file.write(raw)
            file.flush()
            descriptor = os.dup(file.fileno())
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(RUNNER.sys, "platform", os_name), \
                    mock.patch.object(RUNNER, "read_once", return_value=(descriptor, os.fstat(descriptor), raw)), \
                    mock.patch.object(RUNNER, "still_same", side_effect=unchanged), \
                    mock.patch.object(RUNNER.subprocess, "run", side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    result = RUNNER.main(["/unit/packet.yaml"])
                except SystemExit as exc:
                    result = exc.code
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        return result, events

    def test_real_parser_drives_all_six_ordered_mocked_sessions(self):
        for os_name, packet in itertools.product(("darwin", "linux"), FIXTURE["publishedPackets"].values()):
            with self.subTest(os=os_name, packet=packet["view"]["id"]):
                result, events = self.session(packet["raw"], os_name)
                self.assertEqual(result, 0)
                expected = [[sys.executable, "ci/network_canary.py"], *packet["view"]["offlineAcceptanceCommands"]]
                self.assertEqual([value for kind, value in events if kind == "run"], expected)
                self.assertEqual([kind for kind, _ in events], ["run", "digest"] * 9)

    def test_prefetch_order_and_failure_short_circuit_remain(self):
        view = deepcopy(FIXTURE["correctionView"])
        view["prefetchCommands"] = [["python3", "unit-prefetch-a.py"], ["python3", "unit-prefetch-b.py"]]
        expected = [[sys.executable, "ci/network_canary.py"], *view["prefetchCommands"], *view["offlineAcceptanceCommands"]]
        for failure_at in (None, *range(len(expected))):
            with self.subTest(failure=failure_at):
                result, events = self.session(text_view(view), "linux", failure_at=failure_at)
                count = len(expected) if failure_at is None else failure_at + 1
                self.assertEqual(result, 0 if failure_at is None else 37)
                self.assertEqual([value for kind, value in events if kind == "run"], expected[:count])
                self.assertEqual([kind for kind, _ in events], ["run", "digest"] * count)

    def test_invalid_identity_fails_before_any_child(self):
        for field in SCALARS:
            with self.subTest(field=field):
                text = replace_field(text_view(FIXTURE["correctionView"]), field, '"WRONG"')
                result, events = self.session(text, "linux")
                self.assertEqual(result, 2)
                self.assertEqual(events, [])

    def test_digest_refusal_stops_before_acceptance(self):
        result, events = self.session(text_view(FIXTURE["correctionView"]), "linux", digest_refusal=True)
        self.assertEqual(result, 2)
        self.assertEqual([kind for kind, _ in events], ["run", "digest"])
