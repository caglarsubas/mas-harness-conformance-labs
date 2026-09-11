from copy import deepcopy
import hashlib
import json
import pickle
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from _fixtures import (END, NOW, ROOT, VECTORS, authority_args, backend_fixture, binding_args, receipt_from)
from _inventory import SUCCESSOR, isolated_inventory, verify_repository
from test_replay_store import MemoryJournal
from harness_conformance.canonical import canonical_bytes, canonical_digest
from harness_conformance.errors import ConformanceError
from harness_conformance.linux_readiness import CASES, build_probe_request
from harness_conformance.live_backend_authority import SUITE_ROOTS, binding_from_authority
from harness_conformance.live_replay_store import UnitReplayStore, parse_journal, replay_key
from harness_conformance import live_supervisor as supervisor

BASELINE_SHA256 = "f2bc15e777afa6545c3fcfcdd63a0ddcba3d162783767083acb59e1744b115ac"


class FakeBoundary:
    """Explicit offline adapter. No native constructor, socket or syscall."""
    def __init__(self, fixture, io):
        self.fixture, self.io = fixture, io
        self.events = io.events
        self.failure = None
        self.on_execute = None

    def establish(self, binding, plan, deadline):
        self.events.append("establish")
        if parse_journal(self.io.raw)[0][replay_key(binding)]["state"] != "RESERVED":
            raise AssertionError("child before reservation")
        if self.failure == "establish":
            raise OSError("unit establish failure")

    def check_peer(self):
        self.events.append("peer")
        if self.failure == "peer":
            raise ConformanceError("PEER_DIED", "unit parent death or identity change")

    def request(self, case):
        return build_probe_request(self.fixture.envelope, self.fixture.capacity, self.fixture.plan, case)

    def execute(self, request, deadline):
        self.events.append("execute")
        if self.on_execute:
            self.on_execute()
        if self.failure == "execute":
            raise OSError("unit interrupted I/O")
        raw = receipt_from(self.fixture, request["operation"])
        if self.failure == "receipt":
            raw["nativeAcceptance"] = True
        if self.failure == "unavailable":
            raw["status"] = "NOT_RUN_ENV_UNAVAILABLE"
            raw["output"]["checks"] = dict.fromkeys(raw["output"]["checks"], "NOT_RUN_ENV_UNAVAILABLE")
            raw["outputDigest"] = canonical_digest(raw["output"], "planeon.linux-probe-output/v1alpha1")
        return canonical_bytes(raw)

    def interrupt(self):
        self.events.append("interrupt")

    def cleanup(self):
        self.events.append("cleanup")
        if self.failure == "cleanup":
            raise ConformanceError("DESCENDANTS_NOT_REAPED", "unit failed cleanup")


class SupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = backend_fixture()
        cls.binding = binding_from_authority(*authority_args(cls.fixture), **binding_args(cls.fixture))

    def setUp(self):
        self.io = MemoryJournal()
        self.boundary = FakeBoundary(self.fixture, self.io)
        self.wall, self.mono = NOW, 1
        self.subject = supervisor.UnitSupervisor(UnitReplayStore(self.io), self.boundary,
            clock=lambda: self.wall, monotonic=lambda: self.mono)

    def open(self):
        return self.subject.open_session(self.binding, self.fixture.plan)

    def state(self):
        return parse_journal(self.io.raw)[0][replay_key(self.binding)]["state"]

    def test_all_ten_operations_complete_once_with_only_unsigned_unit_receipts(self):
        handle = self.open()
        self.assertEqual(self.state(), "RUNNING")
        self.assertLess(self.io.events.index("fsync"), self.io.events.index("establish"))
        for case in CASES:
            result = self.subject.execute_fixed(handle, case, "amd64")
            self.assertEqual(result["evidenceClass"], "UNIT_VERIFICATION_ONLY")
            self.assertIs(result["nativeAcceptance"], False)
            self.assertNotIn("signature", result["receipt"])
        self.assertEqual(self.state(), "COMPLETED")
        self.assertEqual(self.io.events.count("execute"), 10)
        self.assertEqual(self.io.events.count("cleanup"), 1)
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        with self.assertRaises(ConformanceError):
            self.open()

    def test_each_ambiguous_reservation_failure_has_no_child_or_execution(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.io.fail = fault
            with self.subTest(fault=fault), self.assertRaises((ConformanceError, OSError)):
                self.open()
            self.assertNotIn("establish", self.io.events)
            self.assertNotIn("execute", self.io.events)

    def test_establish_and_kernel_peer_failure_consume_nonce_and_clean_up(self):
        for fault in ("establish", "peer"):
            self.setUp()
            self.boundary.failure = fault
            with self.subTest(fault=fault), self.assertRaises((ConformanceError, OSError)):
                self.open()
            self.assertEqual(self.state(), "FAILED")
            self.assertNotIn("execute", self.io.events)
            self.assertIn("cleanup", self.io.events)
            with self.assertRaises(ConformanceError):
                UnitReplayStore(self.io).reserve_nonce(self.binding, NOW)

    def test_dictionary_fd_serial_clone_foreign_and_pickled_handles_are_not_authority(self):
        handle = self.open()
        for forged in (None, 3, {"fd": 3, "verified": True}, supervisor._Handle(self.subject, handle.serial),
                       supervisor._Handle(object(), handle.serial)):
            with self.subTest(handle=type(forged).__name__), self.assertRaises(ConformanceError):
                self.subject.execute_fixed(forged, CASES[0], "amd64")
        with self.assertRaises(TypeError):
            pickle.dumps(handle)
        native_shell = object.__new__(supervisor.NativeSupervisor)
        native_shell._active = self.subject._active
        with self.assertRaises(ConformanceError):
            native_shell._get(handle)
        self.assertNotIn("execute", self.io.events)
        self.subject.close()

    def test_unknown_duplicate_and_wrong_architecture_operations_invalidate_session(self):
        for case, arch in (("arbitrary-argv", "amd64"), (CASES[0], "arm64"), (CASES[0], "duplicate")):
            self.setUp()
            handle = self.open()
            if arch == "duplicate":
                self.subject.execute_fixed(handle, case, "amd64")
                arch = "amd64"
            with self.subTest(case=case, arch=arch), self.assertRaises(ConformanceError):
                self.subject.execute_fixed(handle, case, arch)
            self.assertEqual(self.state(), "FAILED")

    def test_expiry_before_operation_reaps_without_execution(self):
        handle = self.open()
        self.wall = END
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertNotIn("execute", self.io.events)
        self.assertEqual(self.state(), "EXPIRED")
        self.assertIn("cleanup", self.io.events)

    def test_expiry_during_io_never_returns_a_late_pass(self):
        handle = self.open()
        def expire():
            self.wall = END
        self.boundary.on_execute = expire
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertEqual(self.state(), "EXPIRED")
        self.assertIn("cleanup", self.io.events)

    def test_monotonic_deadline_is_bounded_even_if_wall_clock_stalls(self):
        handle = self.open()
        self.mono = 902
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertEqual(self.state(), "FAILED")
        self.assertNotIn("execute", self.io.events)

    def test_wall_clock_rollback_invalidates_but_does_not_rewrite_journal_history(self):
        handle = self.open()
        self.wall = "2026-09-07T00:59:59Z"
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertIsNone(self.subject._active)
        self.assertEqual(self.state(), "RUNNING")
        self.assertIn("cleanup", self.io.events)
        with self.assertRaises(ConformanceError):
            UnitReplayStore(self.io).reserve_nonce(self.binding, NOW)

    def test_peer_dies_during_io_invalidates_return_and_cleans_tree(self):
        handle = self.open()
        self.boundary.on_execute = lambda: setattr(self.boundary, "failure", "peer")
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertEqual(self.state(), "FAILED")

    def test_malformed_receipt_cannot_promote_native_acceptance(self):
        handle = self.open()
        self.boundary.failure = "receipt"
        with self.assertRaises(ConformanceError):
            self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertEqual(self.state(), "FAILED")

    def test_unavailable_operation_remains_unavailable_not_native_or_pass(self):
        handle = self.open()
        self.boundary.failure = "unavailable"
        result = self.subject.execute_fixed(handle, CASES[0], "amd64")
        self.assertEqual(result["receipt"]["status"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertFalse(result["nativeAcceptance"])
        self.assertEqual(self.state(), "FAILED")

    def test_failed_cleanup_leaves_consumed_running_record_not_a_false_terminal(self):
        handle = self.open()
        self.boundary.failure = "cleanup"
        with self.assertRaises(ConformanceError):
            self.subject.cancel(handle)
        self.assertIsNone(self.subject._active)
        self.assertEqual(self.state(), "RUNNING")
        with self.assertRaises(ConformanceError):
            UnitReplayStore(self.io).reserve_nonce(self.binding, NOW)

    def test_cancel_is_terminal_non_reusable_and_idempotent_close_has_no_new_work(self):
        handle = self.open()
        self.subject.cancel(handle)
        self.assertEqual(self.state(), "CANCELLED")
        self.subject.close()
        self.subject.close()
        self.assertEqual(self.io.events.count("cleanup"), 1)
        with self.assertRaises(ConformanceError):
            self.subject.cancel(handle)

    def test_concurrent_operation_is_rejected_and_cancellation_interrupts_inflight_io(self):
        handle = self.open()
        entered, released = threading.Event(), threading.Event()
        result = []
        def blocking():
            entered.set()
            if not released.wait(3):
                raise AssertionError("unit bounded wait expired")
            raise OSError("unit cancellation")
        self.boundary.on_execute = blocking
        def execute():
            try:
                self.subject.execute_fixed(handle, CASES[0], "amd64")
            except OSError:
                result.append("cancelled-io")
        worker = threading.Thread(target=execute)
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            with self.assertRaises(ConformanceError):
                self.subject.execute_fixed(handle, CASES[1], "amd64")
            original = self.boundary.interrupt
            def interrupt():
                original()
                released.set()
            self.boundary.interrupt = interrupt
            self.subject.cancel(handle)
        finally:
            released.set()
            worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, ["cancelled-io"])
        self.assertIn(self.state(), ("FAILED", "CANCELLED"))
        self.assertEqual(self.io.events.count("execute"), 1)
        self.assertEqual(self.io.events.count("cleanup"), 1)

    def test_native_factory_has_no_caller_context_backend_or_storage_entry(self):
        with self.assertRaises(TypeError):
            supervisor.NativeSupervisor(backend=self.boundary)
        with self.assertRaises(TypeError):
            supervisor.InstalledContext(verified=True)
        shell = object.__new__(supervisor.NativeSupervisor)
        with self.assertRaises(ConformanceError):
            shell.open_session(b"{}", {"verified": True, "fd": 3})
        with patch.object(supervisor, "installed_process", side_effect=ConformanceError("UNIT_CUSTODY_DENIED", "unit")), patch.object(
                supervisor, "LinuxSyscalls") as syscalls, self.assertRaises(ConformanceError):
            supervisor.NativeSupervisor()
        syscalls.assert_not_called()

    def test_forged_envelope_cannot_open_an_unverified_capacity_reference(self):
        for changes in ({"capacityAuthorizationFileReference": "/unit-only/forged-path"},
                        {"capacityAuthorizationDigest": "sha256:" + "f" * 64},
                        {"nonce": "other-nonce"}):
            shell = object.__new__(supervisor.NativeSupervisor)
            shell._mutex, shell._closed, shell._context = threading.Lock(), False, None
            envelope = {**self.fixture.envelope, **changes}
            records = {str(supervisor.FIXED_RELEASE_TRUST): canonical_bytes(self.fixture.release_trust),
                       str(supervisor.FIXED_TENANT_TRUST): canonical_bytes(self.fixture.tenant_trust)}
            with patch.object(supervisor, "utc_now", return_value=NOW), patch.object(
                    supervisor, "read_owned", side_effect=lambda path, **kwargs: records[path]) as reader:
                with self.subTest(changes=changes), self.assertRaises(ConformanceError):
                    shell.open_session(canonical_bytes(envelope))
            self.assertEqual([call.args[0] for call in reader.call_args_list], list(records))

    def test_only_valid_dual_signed_reference_reaches_capacity_read(self):
        shell = object.__new__(supervisor.NativeSupervisor)
        shell._mutex, shell._closed, shell._context = threading.Lock(), False, None
        records = {str(supervisor.FIXED_RELEASE_TRUST): canonical_bytes(self.fixture.release_trust),
                   str(supervisor.FIXED_TENANT_TRUST): canonical_bytes(self.fixture.tenant_trust)}
        def read(path, **kwargs):
            if path in records:
                return records[path]
            self.assertEqual(path, self.fixture.envelope["capacityAuthorizationFileReference"])
            self.assertEqual(kwargs["expected_digest"], self.fixture.envelope["capacityAuthorizationDigest"])
            raise ConformanceError("UNIT_CAPACITY_UNAVAILABLE", "no actual reference is opened")
        with patch.object(supervisor, "utc_now", return_value=NOW), patch.object(
                supervisor, "read_owned", side_effect=read) as reader, self.assertRaises(ConformanceError) as caught:
            shell.open_session(canonical_bytes(self.fixture.envelope))
        self.assertEqual(caught.exception.reason, "UNIT_CAPACITY_UNAVAILABLE")
        self.assertEqual(reader.call_count, 3)

    def test_reference_authority_expiry_wrong_packet_and_trust_substitution_fail(self):
        release_raw, tenant_raw = canonical_bytes(self.fixture.release_trust), canonical_bytes(self.fixture.tenant_trust)
        supervisor._verify_reference_authority(self.fixture.envelope, release_raw, tenant_raw, NOW)
        for envelope, release, tenant, now in (
                (self.fixture.envelope, release_raw, tenant_raw, END),
                ({**self.fixture.envelope, "packetId": "CONF-LINUX-001"}, release_raw, tenant_raw, NOW),
                (self.fixture.envelope, tenant_raw, release_raw, NOW)):
            with self.assertRaises(ConformanceError):
                supervisor._verify_reference_authority(envelope, release, tenant, now)

    def test_native_pre_fork_failure_closes_all_channels_and_gate_descriptors(self):
        # Exercise the native algorithm only with every OS operation replaced.
        channel = object.__new__(supervisor._NativeChannel)
        channel.syscalls = Mock()
        parent, child = Mock(), Mock()
        with patch.object(supervisor.socket, "socketpair", return_value=(parent, child)), patch.object(
                supervisor.os, "pipe2", return_value=(901, 902), create=True), patch.object(
                supervisor.os, "fork", side_effect=OSError("unit fork unavailable")), patch.object(
                supervisor.os, "close") as closed, self.assertRaises(OSError):
            channel.establish(self.binding, self.fixture.plan, 99)
        parent.close.assert_called_once()
        child.close.assert_called_once()
        self.assertEqual([call.args for call in closed.call_args_list], [(901,), (902,)])

    def test_native_cleanup_failure_still_closes_channel_and_pidfd(self):
        channel = object.__new__(supervisor._NativeChannel)
        channel.child_pid, channel.pidfd = 123, 901
        channel.channel = Mock()
        sock = channel.channel
        channel.lease = SimpleNamespace(owned=True, closed=False,
            kill_and_reap=Mock(side_effect=ConformanceError("DESCENDANTS_NOT_REAPED", "unit")))
        with patch.object(supervisor.os, "close") as closed, self.assertRaises(ConformanceError):
            channel.cleanup()
        sock.close.assert_called_once()
        closed.assert_called_once_with(901)
        self.assertIsNone(channel.pidfd)


class SupervisorPredecessorTests(unittest.TestCase):
    def baseline(self):
        document = SUCCESSOR.regular_bytes(ROOT, "docs/live-backend/linux-boundary.md")
        marker = b"<!-- CONF-LIVE-001-BASELINE -->\n```json\n"
        self.assertEqual(document.count(marker), 1)
        raw = document.split(marker, 1)[1].split(b"\n```", 1)[0]
        self.assertEqual(hashlib.sha256(raw).hexdigest(), BASELINE_SHA256)
        return json.loads(raw)

    def test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable(self):
        baseline = self.baseline()
        self.assertEqual(baseline["commit"], "d734b80a3a5acebfd0e0d289437c0f53f3539054")
        self.assertEqual(baseline["tree"], "5cf9cb3e1b286f6c16dcf77ccb4b5524ff568a44")
        self.assertEqual((len(baseline["files"]), baseline["testCount"]), (120, 216))
        result = verify_repository(ROOT)
        self.assertGreaterEqual(result["stage"], 2)
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        _, historical_sources, _ = SUCCESSOR.performance_history(rows, sources)
        actual = {row["path"]: row for row in rows}
        for path, expected in baseline["files"].items():
            # Only the already accepted exact final-hook proof permits the
            # closed CONF-LIVE-006 launcher delta; presence alone never does.
            if result["stage"] == 6 and path == SUCCESSOR.RECORD["hook"]["path"]:
                continue
            raw, observed = historical_sources[path], actual[path]
            self.assertEqual(observed["mode"], expected["mode"], path)
            self.assertEqual(len(raw), expected["size"], path)
            self.assertEqual("sha256:" + hashlib.sha256(raw).hexdigest(), expected["sha256"], path)
            self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), expected["blob"], path)

    def test_all_216_immediate_predecessor_ids_are_in_fresh_six_root_discovery(self):
        baseline = self.baseline()
        observed = {}
        for root in SUITE_ROOTS:
            for path, methods in isolated_inventory(ROOT / root).items():
                observed[root + "/" + path] = methods
        for path, expected in baseline["tests"].items():
            self.assertEqual(observed[path], expected, path)
        self.assertEqual(sum(map(len, baseline["tests"].values())), 216)
        self.assertGreater(sum(map(len, observed.values())), 216)
        self.assertFalse(baseline["nativeAcceptance"])


def _custody_oracle():
    # Exact pure-data region oracle from MET-REPAIR-011, locally closed over
    # stdlib parsers only. Stored source is parsed, never imported or executed.
    import ast
    import textwrap
    RECORD_SHA256 = "26d0301045c60908850ec225fa497d73da4c4125c377e74a931d41c83d57c491"
    BEFORE_PATH = "architecture/custody-handoff-inputs/baseline.json"
    DOC_PATH = "docs/live-backend/linux-boundary.md"
    PROOF_FIELDS = {"schemaVersion", "evidenceClass", "packetId", "packetSha256", "authorityDigest",
                    "baseCommit", "baseTree", "sources", "tests", "baseline", "before"}
    canonical, digest, parse = SUCCESSOR.canonical, SUCCESSOR.digest, SUCCESSOR.parse
    def require(ok, reason):
        if not ok:
            raise ValueError(reason)


    def pinned(record):
        require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
                "exact reviewed custody authority required")


    def definitions(raw):
        """Read AST locations only. No compile, import, eval or snapshot execution."""
        require(type(raw) is bytes and len(raw) <= 2097152, "bounded source bytes required")
        tree = ast.parse(raw)
        lines = raw.splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line))
        result = {}
        def save(name, node):
            require(name not in result, "duplicate source definition")
            start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
            result[name] = (offsets[start - 1], offsets[node.end_lineno], node)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                save(node.name, node)
                if isinstance(node, ast.ClassDef):
                    for child in node.body:
                        if isinstance(child, ast.FunctionDef):
                            save(node.name + "." + child.name, child)
                        elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                            save(node.name + "." + child.targets[0].id, child)
        return tree, result


    def _literal(node):
        # This deliberately small grammar also rejects executable defaults/bases.
        if isinstance(node, ast.Constant):
            return type(node.value) in (str, bytes, int, bool, type(None))
        return isinstance(node, (ast.Tuple, ast.List)) and all(_literal(n) for n in node.elts)


    def appended_definitions(raw, original, *, tests=False):
        tree, old = definitions(original)
        appended, names = definitions(raw)
        seen = set(k for k in old if "." not in k)
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                seen.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                seen.update(n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name))
        seen.update(("load_tests", "__getattr__", "__dir__"))
        require(appended.body, "nonempty definition append required")
        def safe_definition(node):
            require(isinstance(node, (ast.FunctionDef, ast.ClassDef)), "definitions only at append boundary")
            require(not node.decorator_list, "append decorators forbidden")
            if isinstance(node, ast.FunctionDef):
                require(node.returns is None and all(arg.annotation is None for arg in
                        [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                         *([node.args.vararg] if node.args.vararg else []),
                         *([node.args.kwarg] if node.args.kwarg else [])]), "append annotations forbidden")
                require(all(_literal(v) for v in [*node.args.defaults,
                        *(v for v in node.args.kw_defaults if v is not None)]), "executable default")
            else:
                require(not node.keywords, "class metaclass selection forbidden")
                for base in node.bases:
                    require(isinstance(base, ast.Name) and base.id == "object" or tests
                            and isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name)
                            and base.value.id == "unittest" and base.attr == "TestCase", "unapproved class base")
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                        safe_definition(child)
                    else:
                        require(isinstance(child, ast.Pass) or isinstance(child, ast.Expr)
                                and isinstance(child.value, ast.Constant) and type(child.value.value) is str
                                or isinstance(child, ast.Assign) and _literal(child.value)
                                and all(isinstance(t, ast.Name) for t in child.targets), "executable class body")
        for node in appended.body:
            safe_definition(node)
            require(node.name not in seen, "existing definition rebound by append")
            seen.add(node.name)
        return sorted(name for name, (_, _, n) in names.items()
                      if "." in name and isinstance(n, ast.FunctionDef) and n.name.startswith("test_"))


    def reconstruct_source(before, row, allowed, limits):
        require(type(row) is dict and set(row) == {"beforeSha256", "afterSha256", "regions", "append"},
                "closed source delta required")
        require(row["beforeSha256"] == digest(before) and type(row["regions"]) is dict
                and set(row["regions"]) <= set(allowed), "wrong original or region")
        _, locations = definitions(before)
        chunks = []
        for name, replacement in row["regions"].items():
            require(type(replacement) is str, "string replacement required")
            raw = replacement.encode("utf-8")
            require(0 < len(raw) <= limits["maxReplacementBytes"] and raw.endswith(b"\n")
                    and b"\r" not in raw and b"\0" not in raw, "bounded complete replacement required")
            start, end, original = locations[name]
            parsed = ast.parse(textwrap.dedent(replacement))
            require(len(parsed.body) == 1 and type(parsed.body[0]) is type(original), "one matching definition required")
            changed = parsed.body[0]
            if isinstance(original, ast.FunctionDef):
                require(changed.name == original.name and ast.dump(changed.args) == ast.dump(original.args)
                        and (ast.dump(changed.returns) if changed.returns is not None else None)
                        == (ast.dump(original.returns) if original.returns is not None else None)
                        and changed.type_comment == original.type_comment
                        and [ast.dump(p) for p in changed.type_params] == [ast.dump(p) for p in original.type_params]
                        and not changed.decorator_list, "function interface or decorator changed")
            else:
                require(name == "InstalledContext.__slots__" and len(changed.targets) == 1
                        and ast.dump(changed.targets[0]) == ast.dump(original.targets[0])
                        and isinstance(changed.value, ast.Tuple) and all(isinstance(v, ast.Constant)
                        and type(v.value) is str for v in changed.value.elts), "literal context slots required")
                old_slots = [v.value for v in original.value.elts]
                new_slots = [v.value for v in changed.value.elts]
                require(new_slots[:len(old_slots)] == old_slots and len(new_slots) == len(set(new_slots))
                        and all(s.startswith("_") for s in new_slots), "original/private context slots required")
            # Preserve indentation at the original boundary, not just AST semantics.
            indentation = before[start:end].splitlines()[0][:original.col_offset]
            require(all(not line or line.startswith(indentation) for line in raw.splitlines()), "region indentation changed")
            chunks.append((start, end, raw))
        current, cursor = b"", 0
        for start, end, raw in sorted(chunks):
            require(start >= cursor, "overlapping source regions")
            current += before[cursor:start] + raw
            cursor = end
        current += before[cursor:]
        require(type(row["append"]) is str, "string append required")
        appended = row["append"].encode("utf-8")
        require(len(appended) <= limits["maxAppendBytes"], "append too large")
        if appended:
            require(appended.startswith(b"\n") and appended.endswith(b"\n"), "append line boundary required")
            appended_definitions(appended, current)
        current += appended
        definitions(current)
        require(current != before and digest(current) == row["afterSha256"], "source after digest mismatch")
        return current


    def validate_delta(after, proof, record, before_raw):
        """Pure source compatibility only; no returned data grants execution."""
        try:
            pinned(record)
            require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][BEFORE_PATH],
                    "original before snapshot required")
            before = parse(before_raw)["files"]
            require(type(after) is dict and set(after) == set(before)
                    and all(type(v) is bytes and len(v) <= 2097152 for v in after.values()), "exact bounded five-path map")
            require(type(proof) is dict and set(proof) == PROOF_FIELDS
                    and len(canonical(proof)) <= record["change"]["maxProofBytes"], "bounded closed proof required")
            expected = dict(schemaVersion=record["change"]["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
                packetId="CONF-FIX-004", packetSha256=record["inputFiles"]["task-packets/CONF-FIX-004.yaml"],
                authorityDigest=RECORD_SHA256, baseCommit=record["sourceBaseline"]["commit"],
                baseTree=record["sourceBaseline"]["tree"])
            require(all(proof[k] == v for k, v in expected.items()), "proof authority mismatch")
            require(type(proof["before"]) is str and proof["before"].encode() == before_raw, "snapshot substitution")
            baseline_raw = proof["baseline"].encode() if type(proof["baseline"]) is str else b""
            baseline_path = record["sourceBaseline"]["path"]
            require(digest(baseline_raw) == record["protectedFiles"][baseline_path], "baseline substitution")
            baseline = parse(baseline_raw)
            require(type(proof["sources"]) is dict and set(proof["sources"]) == set(record["change"]["sourceRegions"]),
                    "two source deltas required")
            for path, allowed in record["change"]["sourceRegions"].items():
                require(reconstruct_source(before[path].encode(), proof["sources"][path], allowed, record["change"])
                        == after[path], "unreviewed source bytes")
            tests = set(record["change"]["appendOnlyPaths"]) - {DOC_PATH}
            require(type(proof["tests"]) is dict and set(proof["tests"]) == tests, "exact test proofs required")
            for path in tests:
                raw = before[path].encode()
                require(after[path].startswith(raw), "historical test changed")
                appended = after[path][len(raw):]
                require(0 < len(appended) <= record["change"]["maxAppendBytes"]
                        and appended.startswith(b"\n") and appended.endswith(b"\n"), "bounded test append required")
                ids = appended_definitions(appended, raw, tests=True)
                require(ids and not set(ids) & set(baseline["tests"][path]), "new noncolliding regressions required")
                require(proof["tests"][path] == dict(beforeSha256=digest(raw), afterSha256=digest(after[path]), newTestIds=ids),
                        "test prefix/hash/ID mismatch")
            doc = after[DOC_PATH]
            require(doc.startswith(before[DOC_PATH].encode()) and len(doc) > len(before[DOC_PATH].encode()),
                    "original document prefix required")
            marker = ("```" + record["change"]["proofFence"] + "\n").encode()
            require(doc.count(marker) == 1, "one proof fence required")
            encoded, closing = doc.split(marker, 1)[1].split(b"\n```", 1)
            require((not closing or closing.startswith(b"\n")) and encoded == canonical(proof), "noncanonical/mismatched proof fence")
            return []
        except (TypeError, ValueError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError):
            return ["invalid custody source delta; no execution authority"]
    return validate_delta, reconstruct_source, appended_definitions


def _custody_record():
    return json.loads("{\"schemaVersion\":\"planeon.internal.custody-handoff-amendment/v1\",\"authorityPacket\":\"MET-REPAIR-011\",\"approvalDate\":\"2026-09-08\",\"metaBaseline\":\"108e61953d522106db7c8de65ee19120a952853b\",\"historicalPacketCount\":136,\"currentPacketCount\":138,\"protectedFiles\":{\".github/workflows/verify.yml\":\"b6b8c87fc5f9615c193594c7a861a59e55022acfdb1dc9970c903af9fca22dee\",\"AGENTS.md\":\"b797986ce9d311ebafd946cbe0dface3ee4fa9f4bb6891bad53c96036f6c6694\",\"architecture/base-scope-sources.yaml\":\"38b19648432f8394f28a0115ffd11995f0d9843891f864af0c2dd6ac677dd2eb\",\"architecture/dependency-graph.yaml\":\"47986eff1832f2ed990bb9ceb2cd9aab574475df0bc20f2a39ac91c985cfd50f\",\"architecture/linux-readiness-amendment.json\":\"3a59552dbadd6a9e7579038523787926b921c35a3c71d036d2705b1c95b804a6\",\"architecture/linux-readiness.json\":\"2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762\",\"architecture/linux-test-ownership-amendment.json\":\"5aa1e79de247ebed7550b56db48266182941232d9036840beade99fbcf11172f\",\"architecture/live-backend-roadmap.json\":\"06d55fab0d0e56cbbdedab975fd4e2371f06896a6298e96c8c4e23c5e50916e7\",\"architecture/model-api-inventory-amendment.json\":\"7f298fdb1db878105d9925b5b07500f9cb6298f8b887d87d91edbc6210b48c7b\",\"architecture/model-api-inventory-inputs/CON-MODEL-001.before.yaml\":\"fff08209e76c2287c257a8d37a29aba159f82019e70f51d36bcaebf9d6805f33\",\"architecture/model-api-inventory-inputs/test_lifecycle_contracts.before.txt\":\"53f528db6e9d3ce00a8c16e8cf24345a992b2b6130cdfb7d5a6dee02dbaed81e\",\"architecture/model-evidence-boundary.json\":\"5be8de011a0cc4769b919ce0a416cb73d791c92181920abca7e8793abb788b48\",\"architecture/model-fixture-inputs/CON-MODEL-001.before.yaml\":\"807efc83ddd77e27e19d0e7d53811321c9b00c95972b53e78b263f385fd41d48\",\"architecture/model-fixture-inputs/test_generated_contracts.before.txt\":\"856b1d14e0f4d4ee84f6c4f973db412f9905559124091355bec7de85cc818080\",\"architecture/model-fixture-scope-amendment.json\":\"e46ea246e0ab64d7d6882822739b3029659138711f2bb426ea26fea064e08bd3\",\"architecture/observations/agent-hook-v2-tree.json\":\"0c94377f0ae6bf7ec7d70d521c411ff6883614cb2cebca2a1243cea1ce775339\",\"architecture/observations/data-harness-v1.json\":\"5c559a6ef3d59fa40e74ab2fb36603752751f523249da884f8e0d8daa06cfe10\",\"architecture/observations/model-usage-v2.json\":\"aa5488bad4528bd4119dfe9134f517403986b6fd45408f34c508929924e764f9\",\"architecture/observations/orchestra-openshift-reference-lab-tree.json\":\"c0cab3b3c294ab0db09f19215ad51f3ca5b09c71bb007fef2b894f7588d3f41b\",\"architecture/observations/planeon-orchestra-python-sdk-tree.json\":\"aa41c2d2b781e6776724367b3cf931d23b6812cc14ecb4a27c4f6c0b69ef61d7\",\"architecture/packet-scalar-amendment.json\":\"56b270f8d211f598cbf0183088430bd5ccc16e64eb089b865e117748c762b4e1\",\"architecture/packet-scalar-inputs/baseline.json\":\"d88c8f22877cf7269135ef53c08ff3a4921edb0946db0d9c9c1d38209256bfb6\",\"architecture/packet-scalar-inputs/run_packet.before.txt\":\"3128dd48c486d74c3a109eb0d6655c57033011d508afadce35756e485d94e83a\",\"architecture/packet-scalar-inputs/test_linux_inventory.before.txt\":\"1f5587f857927ca645e1c79edd4b4cd560f0eb70a881fb670b5047739421b7ef\",\"architecture/policy-observation-amendment.json\":\"0df7e72a65fc5eb1c20d59b8c62ebff377f160214192d681ea7f3d29b57e38c7\",\"architecture/policy-observation-inputs/channel.schema.json\":\"fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e\",\"architecture/policy-observation-inputs/vectors.json\":\"1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124\",\"architecture/porting-authorization-index.yaml\":\"a9768c8a75c2a9d3469271c60861c4ceb0b45cd3304d9c6be2dc1783ff1e7ec3\",\"architecture/providers.yaml\":\"9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02\",\"architecture/proxy-contract-amendment.json\":\"6c93e7db962cffa0281331c5220cdd8d5e453ab38ae39b4baa2e62be21a60600\",\"architecture/proxy-contract-inputs/baseline.json\":\"980ff63a57a6a167020f6d64297f946c92d7ce56b8c274b3fec56fb18bd837c1\",\"architecture/proxy-contract-inputs/profile.schema.json\":\"209349ccf44989566ffb39e2654fc91323b5eb2d9cbe895a4b18f33a349a226d\",\"architecture/proxy-contract-inputs/vectors.json\":\"edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7\",\"architecture/readiness-repair-amendment.json\":\"c3caa938557f1b9bb195188e35edc946fbdea36f0f1b235ab23f2689ffc54912\",\"architecture/readiness-repairs.json\":\"30db784918bb651cc81f26d23cb4b1d7f790ef260ef5e48a2d7ae2ae94c12a0d\",\"architecture/repositories.yaml\":\"02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d\",\"architecture/reuse-map.schema.json\":\"a9f2980e12679a7292fc394f1e53c437a4e60dc16ba22129c0cb66dce1b759a3\",\"architecture/reuse-map.yaml\":\"a4c612d46fbec6e098d3d48dfd1706a5529967207c04bef40f7900c0f269d741\",\"architecture/reuse-path-index.yaml\":\"4146194a2833840c02369725727d61bd9b2c626eca89b95280f49683647a25c1\",\"architecture/services.yaml\":\"857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6\",\"architecture/successor-inventory-amendment.json\":\"d6bd95af8bc7dd3d497907df58cc843a1732dc12e74a401692e47449444c349d\",\"architecture/successor-inventory-inputs/baseline.json\":\"f84ab0aeac644670b6a36ca52af1493af29bfacc8f04c4602a9e650dfca0c645\",\"architecture/successor-inventory-inputs/live_launcher.before.txt\":\"0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27\",\"architecture/successor-inventory-inputs/test_packet_scalars.before.txt\":\"c340e47f5eb8286e2e76ae5b38dc0bed6073701de44859b3356aed4c708f42e8\",\"architecture/taxonomy.yaml\":\"3d77bad7f84ff2f6a203fa074dce8ceaabf8e471711a8249daa53d8cf3f0fa24\",\"docs/alpha-2/POLICY_OBSERVATION_READINESS.md\":\"65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c\",\"docs/alpha-2/PROXY_CONTRACT_READINESS.md\":\"3e3bf310ebd8a7b1aed696ed9b8d4d26cb67160aab3f862877e2b2a2e0c9f3d0\",\"legal/source-reuse-authorization.yaml\":\"15db98cbaef76c942f7bd230c245f506653311b9cfec4596255b5770eb6e45fa\",\"legal/third-party-license-policy.yaml\":\"fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0\",\"policies/zero-bill-policy.yaml\":\"77c1385d014db8562be215f03a806deafb66e38c6e7faed9167f53299dadd43e\",\"release/evidence-policy.yaml\":\"ead30b57628a7479152c94f6a9496d90ec9d60701d7214cfcf3e36765dbda069\",\"release/fixture-release-set.yaml\":\"7597ebe4754a501de67dc2ee620dba4a8413e8b87761437d562194bac595b2f9\",\"release/repos.lock.json\":\"6067ca5e86c759c3efd914b037243e82577b40448d084df339b0abbf0d2999c4\",\"requirements.lock\":\"f78e95f80f5cd159802ab08b997121af14810513c4b34d08588ee34382e137b7\",\"schemas/dependency-graph.schema.json\":\"9c6f18bcc26e2b574297ba3e50d2e440f67f9bb78b3b5b7cfffa179c7141c870\",\"schemas/live-campaign-execution-envelope.schema.json\":\"ee5ce21417760c941b70b03fc7d48c6462104268f374a424f4cd01f7ed5ca6ee\",\"schemas/porting-authorization.schema.json\":\"1c5675728c9c13fde47d644b654bdff9eebe19d9210a5987832c8ef6224c9d56\",\"schemas/porting-record.schema.json\":\"492c510f1ddf1080eb8a59c4a7478518f035f6c5b0a466de5f95e5ae3fd8107b\",\"schemas/provider-module.schema.json\":\"f177ca68e4c3e62b5b4c8a8bd909589e755b722478ce341d4781169cf8730b9d\",\"schemas/release-set.schema.json\":\"f8efb2cf71f272eaf51ee962401fdc2c608342beb6f266f3cc8d14a031ee777b\",\"schemas/repositories.schema.json\":\"8b1841a75925c2b059909424656cf85d20691c50d5585da5b9ae7e5971271f27\",\"schemas/reuse-path-index.schema.json\":\"237169f0e8e65f557133e1c484e6bee602c7b1119935b0be8dbbdd575446d0d3\",\"schemas/services.schema.json\":\"7aa4eedb210650120496ea5858cbde3067dfa7d9c3b5b54bf39e3655f4010f0a\",\"schemas/task-packet.schema.json\":\"1e6d75398fb6571a1fd752b1ed597d0465c4031f9271bdda27a3075c88fb39f0\",\"schemas/taxonomy.schema.json\":\"b952d10ef9eb52012c3aabb58648b86f28600e006089b6685a2be2474964022d\",\"schemas/trusted-runner-manifest.schema.json\":\"157ad117269e9244b143c8bc6a80e1faf34678c1b538adb92b2e55444189d480\",\"task-packets/CON-001.yaml\":\"88383a2c8bc66c959df0abc8bc1c8d86a852cac654cd1833327f8b06e2cf41b4\",\"task-packets/CON-002.yaml\":\"1e266163e2990ca7412338e878cb6b41e8a769abc27802083c352d1fc7e6da20\",\"task-packets/CON-003.yaml\":\"f54c40fba3c9ef2889851981e93f282ff069c4c40de222a18005d57241b7bb1a\",\"task-packets/CON-004.yaml\":\"1613ae0d5f5f113d0208f811f36c998168094109b96d68f8e7c31798e62733a3\",\"task-packets/CON-005.yaml\":\"1e5c7ac03625c08a7ff46b133e2b7689e5ef43de4782a5948f5f63823bcca4d6\",\"task-packets/CON-006.yaml\":\"e05a3f0c7c9c51857ae8afa774cad5fcb75483bcca49f44da54375327fdafec0\",\"task-packets/CON-007.yaml\":\"b5ab9498ff950345c0198a7a54fd3d62052f13a978f5113c69900f199dfb38ea\",\"task-packets/CON-FIX-001.yaml\":\"15040a4811277880118d58121a7d23721d8a91b4ab6d3211f960189d6a351a14\",\"task-packets/CON-MODEL-001.yaml\":\"d5f7ccf98a8dfa8862c204bd9be99cbfbc2307b98be00f0112f6e9dcb59abd9e\",\"task-packets/CONF-001.yaml\":\"2ad6741244eb83c152b0880ffb3518b10a02d5cc65bf2e1012b879866069de48\",\"task-packets/CONF-002.yaml\":\"7130dfaa116bcadd99cb29506be8cda8864643bb26b9216f7466c5e9085ebaab\",\"task-packets/CONF-A1-001.yaml\":\"c076b578b6655c70b7ca7309d3a5b43e9e5cad79138b44c89025ab6e6b20b1b4\",\"task-packets/CONF-A2-001.yaml\":\"574e85c20d97db27fa23ede3f5d7ebf043ff7980e237d21623aa05b331852bd8\",\"task-packets/CONF-A3-001.yaml\":\"70c53e57e6d140bf088993e0db0a7e6da1a2cdda5f0810eb89dbe3215c2ea624\",\"task-packets/CONF-AIR-001.yaml\":\"f6c08f690d1588db15b939beb0b86c5ecce40b19b33cea1db04413c2ecb8a666\",\"task-packets/CONF-FIX-001.yaml\":\"b02d7c6f2872c61fbde5be10451ac8de08e8336ee032e85b468e40dfaf8790ac\",\"task-packets/CONF-FIX-002.yaml\":\"c8639e527496660b8211f5bdcdb8f7470129b7d00f938c061d34630c797d8af4\",\"task-packets/CONF-FIX-003.yaml\":\"19089018ab6b1e2dada65d1dc3715940037b0881c1db02217622455a8a91d5a1\",\"task-packets/CONF-K3S-001.yaml\":\"6178307a2845df6a369d666fec60653b167bfbb9b5086e8dbd58217d33229dc5\",\"task-packets/CONF-K8S-001.yaml\":\"6626cd491cf266209e77b9f90c66cabc8c1fc36195ef87ea6278fa5c07db5056\",\"task-packets/CONF-LINUX-001.yaml\":\"22f00544680f90a90b03420632bebf192a8c687549b519770fca5f98dd5fd6c9\",\"task-packets/CONF-LIVE-001.yaml\":\"5c7ceb5094b1c5a29192b7bdea913b23f777698bd31224ca5d1958a793dba3b3\",\"task-packets/CONF-LIVE-002.yaml\":\"05a6f03d19a1e12fafe278e5ec72c8adc6304766697b8682bc8d63092d47427f\",\"task-packets/CONF-LIVE-003.yaml\":\"15d13434edf833d4803618a7aa73ccc5e93baa29596e08903e623dbee338bba5\",\"task-packets/CONF-LIVE-004.yaml\":\"3cb0e1f7d163d7a420fbf2134b7ca5a7c70174acfca8646c341be83e6c23ff23\",\"task-packets/CONF-LIVE-005.yaml\":\"b25b9a828907a25d46fea9ccce74d3f05f30cfb9623acd0b21e8dd359e1d9623\",\"task-packets/CONF-LIVE-006.yaml\":\"f95c277cffdfb622f45a1b4b91a5292d9d9a5bfabc8f9388b3899cbb20c5213d\",\"task-packets/CONF-OCP-001.yaml\":\"04e8bc10f8b9bf5e84b6d55fecd96985f991054d4ba0346cd7316667ecd93ee3\",\"task-packets/CONF-SEC-001.yaml\":\"39eeaa83876002f57e29fffac39847f5d058aea128f447558213baa70687abdd\",\"task-packets/CONF-UPG-001.yaml\":\"4c2cc8bdaae80a30f3a8492be724a8920b1ea6fb66dbce7383713ecdd24c2a42\",\"task-packets/CONF-WG-001.yaml\":\"cd0685d9cdf8a018f4465d5223d950a557e4d523320891cc5d907496111442cd\",\"task-packets/CTRL-001.yaml\":\"5e8d3d18a8245ccd985c77d8269b73333b510a2689a341edffd17dcfde77a8c3\",\"task-packets/CTRL-002.yaml\":\"d0045acba54f420d6543581eebca1ae88e78c516576e2e8c1399762761bdcf25\",\"task-packets/CTRL-003.yaml\":\"0bd59f60ae73a7e19c97f5d797cb8955f28a5f3a181326c5c4af8d57ed5d2bbe\",\"task-packets/CTRL-004.yaml\":\"425faffab20090282bd60b17ac7cfc7942eeaaef0c2ff046b77d9736d77968d4\",\"task-packets/CTRL-005.yaml\":\"da414f08217a1b60351a3c7da42784a4cb749c12520f2250f6526f17df72976f\",\"task-packets/CTRL-006.yaml\":\"5b9f6ba920cb6d6eb5c192dfc104851d395772c57347ca69bc68aec6328709d1\",\"task-packets/CTRL-007.yaml\":\"4a70eac5a350e7b48d2b8b180c02455a5953837050c57f46cd7dbafb86291822\",\"task-packets/CTRL-FIX-001.yaml\":\"f1084924fe765b8d905a3156448bea636aec111b71a93e4a842dfbcab563b401\",\"task-packets/CTRL-FIX-002.yaml\":\"621e7ba7ad0b8852cc7bc63e666c5ac25e92fe5a769481b491bb850f1eecdd97\",\"task-packets/CTRL-FIX-003.yaml\":\"42876f9ab5ab8c227920fe6eee3a913b72f6940a989a8d128d627fbfea43c48f\",\"task-packets/CTRL-INTEGRATE-001.yaml\":\"28441f4febf41c7228b516ca8f674785d28842aa6c3443f8fefebeb4a6e7de95\",\"task-packets/DIST-001.yaml\":\"8de07c6a51176005765ef44aa4613b4443f610350d452daadbeae271b46bf48d\",\"task-packets/DIST-002.yaml\":\"785b079851cbb207cbeb012adab16f9dbcbcd555eb49ec835147d77899d359a0\",\"task-packets/DIST-003.yaml\":\"47a2951fd7957b780352cd0300d5b98af101509f43293c4daeaeae7626b9b5eb\",\"task-packets/DIST-004.yaml\":\"f1ea5c7b9df565a3c28d3b7fd24cb4878fccfaa0e75cc9ef1f57171d56e60633\",\"task-packets/DIST-005.yaml\":\"1cf1826b8c69c2030112899344577e0c5ea761b528eb978655cb098b29434d4f\",\"task-packets/DIST-AIR-001.yaml\":\"7a16e99750dd6044d56194a815ab2182d09759e27dea1cf6669d6366276ccb20\",\"task-packets/DIST-FIX-001.yaml\":\"d65fd678adb17be1c6875eb0e8ca7e955d59e4df32bc263b20213f1de845c983\",\"task-packets/DIST-OCI-001.yaml\":\"7211a4874c3236df8b257e2d8889180493ab8a0ece0812ef01fcf38ae257158e\",\"task-packets/EXEC-001.yaml\":\"7a6a95f429315d157c8f2ee4bcfb63584bbfd2ae9dcfb26420adaf30fbf76108\",\"task-packets/EXEC-002.yaml\":\"a8eeb8d1a1c56c87329818c827d398a329356420fdc2dd0b9df8e8d23f4c76c5\",\"task-packets/EXEC-ML-001.yaml\":\"ce65bd9b74e405b4dbc153430d9a05b245ba904c2372adc3a406a5de88e9c969\",\"task-packets/EXEC-ORCH-001.yaml\":\"bab8ff0d2a85f22484c29011836c2458449755634bf27b3462199ef445354d75\",\"task-packets/EXEC-PROT-001.yaml\":\"8dda3de5062124d3c2080ab5eaf68dd3d9b73f5e0f9c4fe646ec9284263201c2\",\"task-packets/EXEC-SBX-001.yaml\":\"8fb5e9035117761d9cb0e66600e246103f08392f342ddff69143018c60bdb517\",\"task-packets/EXEC-SBX-002.yaml\":\"fdec3da0f03a4e3cff03c642317616554454fc4767afee8180c141128b04cf49\",\"task-packets/EXEC-TOOL-001.yaml\":\"c0d160591f0f5eed5f28ce0db0ff2c5f3a609beb3e253ed21a7caa354e83816d\",\"task-packets/IND-001.yaml\":\"3d5778712ed09558c4df4c881745785311ca4f3be5ba7df4556930dd131cf86f\",\"task-packets/IND-FIX-001.yaml\":\"0d3b1bf1a1b167275c5c7916a845c658f14e7fa69dc0383963ba4648c202145c\",\"task-packets/IND-WG-001.yaml\":\"2766279b611409c8c0bc376b1161d3508e2485fa72c109222e90ceb60b13611c\",\"task-packets/IND-WG-002.yaml\":\"78bd0d87b54b9987621c1c42d8363fcd73d67c46677fe354d9f39229778a10d9\",\"task-packets/IND-WG-003.yaml\":\"897dc36776c08f73c93019cbcbe841a0f1ad2710385b28141b05602b53e3882e\",\"task-packets/IND-WG-004.yaml\":\"20ed881b6010aa5b5bca07d85b92d49b053641e88b05884c61e6a1661902fb7f\",\"task-packets/IND-WG-005.yaml\":\"033db2dd187457a94a8a346baf6aa11bd07ad6ac25cfc3d4d315a60b2e78ae38\",\"task-packets/KN-001.yaml\":\"5e1790e09f99c70f41288fde9767447f8b655ec821f029d266aa9973301d81e2\",\"task-packets/KN-002.yaml\":\"96a61677ee41b973a9282f858c4f355d54afe4b2c5f47d6cc18aea2114226fb6\",\"task-packets/KN-DATA-001.yaml\":\"73422c32a67d78cbcb6e74447482022f3552b24fd8ca356da5da91c9c538e0d2\",\"task-packets/KN-DATA-002.yaml\":\"ddd3b5f0f21705eb1ea07103dc91b194703dea50935e0e37c9796101e3239e40\",\"task-packets/KN-DOM-001.yaml\":\"452fd1e14baa779023ca27511af9b9a8b4281ddc8dea51327b93e594700e9f56\",\"task-packets/KN-MEM-001.yaml\":\"4ab3568fdfd01d500f205a2c5976526639a775c21ec09b8cf99cfdcfaaff3483\",\"task-packets/KN-RET-001.yaml\":\"d417da2b27707a0b69590019e556f35cf6d6f737c37858c9099481323415a5b1\",\"task-packets/MET-001.yaml\":\"43af6889dcf50d3ee8370cd5e761acc1a9fd989a44538b4db84a62df21f67880\",\"task-packets/MET-002.yaml\":\"e93658d831f7dc2f1b228f03986117ca59af276fefe901e3802df117a2eb34c7\",\"task-packets/MET-003.yaml\":\"d0bf1bc8cb15c536433528bf7b30aa3713e5ae44cb809d749fe8f344bccf3eea\",\"task-packets/MET-004.yaml\":\"942bae46d9b7e8561f7a4474f465eb2397df7bbc48a34b90e8c91403f126012f\",\"task-packets/MET-005.yaml\":\"aee54bd4c5219eb9ab7a751fb4d42008a5e05abc3188b9484a1eee8a1f628cba\",\"task-packets/MET-A2-001.yaml\":\"fcee128a05f6e53e60461a53108bb652187ae7e67c1056a4f2dcb6fd6477b413\",\"task-packets/MET-LINUX-001.yaml\":\"b54b47708b13bf9c184345308466e6a23af159040aacdc62744d43135c8f5f04\",\"task-packets/MET-LINUX-002.yaml\":\"7e2efb3daad8e5152028cfd35ced7449cd145a51fd3573b4e71981d29a8ee787\",\"task-packets/MET-LIVE-001.yaml\":\"c37fa6eabc16e7a424b894c8b3863931a4fa6bb56baa20b75d447923bc38007c\",\"task-packets/MET-OBS-AH-001.yaml\":\"9a527e5343d99e679c850a1dd416de9c4ed19f100caec0d1872f1dfc1424001a\",\"task-packets/MET-OBS-MODEL-001.yaml\":\"7493f8f788f982df4cd6b32f3647c82f41b8989feee54fea8740fff5e61f1a9b\",\"task-packets/MET-OBS-OCP-001.yaml\":\"9028852eaa2ddc2f7dc3559e38ab4d83bc3c6598dab97d10fb80846ed17fe711\",\"task-packets/MET-OBS-SDK-001.yaml\":\"fe44c76c6160847435869accd0ec895ec0ff700bca3f7ec09843b535a0a21e95\",\"task-packets/MET-P0-001.yaml\":\"41d838c56aa88e5c60e4b6768d28d3b24073fc63955309c89a49315c641192dc\",\"task-packets/MET-P0-002.yaml\":\"6ffd3057b377f1d6c7fc47cae26472f010e83090b5c31d90cbb46c4e0a7d9611\",\"task-packets/MET-P0-FIX-001.yaml\":\"1845f579a807d30e2880d4aee46b52e849092b0374fbf59f4ca31f8e66d45194\",\"task-packets/MET-P0-FIX-002.yaml\":\"b12012d45b0b9f968816a21be7cc714491ba94fcb7ee1af348da9bcd520a6ef2\",\"task-packets/MET-P0-FIX-003.yaml\":\"bf18a928240f0e0991287564d193a45a2699efa9aeb949b31dc112815a83cef2\",\"task-packets/MET-P0-FIX-004.yaml\":\"c3614e7cace9d83299e70add53c6650c8668d156850f941904f64f871ad29807\",\"task-packets/MET-REPAIR-001.yaml\":\"45ea3a94514ae1b7b06608fa4629603fbe3c908c726da66fa733ccaffcb03986\",\"task-packets/MET-REPAIR-002.yaml\":\"75cd79e37a9a3a2adc645e322d8b8b6f27abf546d52b6fb821c275dedf4078e4\",\"task-packets/MET-REPAIR-003.yaml\":\"6f07a6fe38f305ffc226999b19fedb5ec4082069c8d14dede36bd001e550abf1\",\"task-packets/MET-REPAIR-004.yaml\":\"3217293d977e25f0c6e7f6e6bb0134c27d840fd8769dc285494ecc7f351f6d94\",\"task-packets/MET-REPAIR-005.yaml\":\"680335751aab8ac403f73db751d67c0ba98fce09017d51eebd7fa36d7b9fb5d0\",\"task-packets/MET-REPAIR-006.yaml\":\"365207085a6bc661164660008d9248f1414a821898497851da9f17cba9366e92\",\"task-packets/MET-REPAIR-007.yaml\":\"e4bbc961a86663fd4e8f52a74524e335b579b75031c2fdc97ff3ed0b9714d756\",\"task-packets/MET-REPAIR-008.yaml\":\"3a25b0653760488a41575696cf722bccce76d51bd2653ca8f1ccdef162cfc476\",\"task-packets/MET-REPAIR-009.yaml\":\"15dc67a95231ca39755bd91ff5056e5cf5c1769340e09104ca0878715ce9bf97\",\"task-packets/MET-REPAIR-010.yaml\":\"735b5bd31ddb8ce72d7a08f50658e3d34e4953c780be5ea0e704aded2f86b488\",\"task-packets/MODEL-001.yaml\":\"753847ad57b2247a281b23c8f7db1956da3ae5d33f32433b25e80d44585160c0\",\"task-packets/MODEL-002.yaml\":\"25ac59868a1805845ab244ee7ab08590dd72c928c6821bd22bc47eb1c5c819c5\",\"task-packets/MODEL-003.yaml\":\"25403133eb4bd1272f6719903832e4182d899c6c6d2613b9240ce417bd6af09f\",\"task-packets/MODEL-004.yaml\":\"2b7260bd8bc5bf06880be4d2a06adab877ec6b956d1fe7b4ed40a619dad34ab3\",\"task-packets/MODEL-LLAMACPP-001.yaml\":\"f151b3393cb61b9133f21488fb53f01117e0960078077b6439bdc612adda793d\",\"task-packets/MODEL-OLLAMA-001.yaml\":\"31fd06d3fab1227e42661af30e025c33deb51e49fcdf291ab443b6f80780d768\",\"task-packets/MODEL-VLLM-001.yaml\":\"681a93edcbead7333b8439e6ddc849bc7a4ee0b9008b8bbab60cd494cac00f4e\",\"task-packets/OP-001.yaml\":\"9a64698615c1c1fa8ef899b50495d5249bec0a877f0e7f7a92e9058ef196b07b\",\"task-packets/OP-002.yaml\":\"caeea13c1efffc147fd0ca2d4c270916ca12e61c2a7122962eff4b024d2bf2f4\",\"task-packets/OP-003.yaml\":\"86fd96fc4cf016331ebe1c8c95a5c0faba9b8155439f324c381991ea7b1eba1b\",\"task-packets/OP-004.yaml\":\"6b585f709a0f69283534e0fadbe90502bd335fc9754bb5c30b0624d26e3eb241\",\"task-packets/OP-005.yaml\":\"9529029015e992d5cfffc4d0c2bcfe88e579834b8e27aff31607fb550799f09d\",\"task-packets/OP-006.yaml\":\"fa376aee945c301717e12b79aa5c4ebd7869e6b924b6afabd3f184db32d1595e\",\"task-packets/OP-007.yaml\":\"f4508ad47659315581d551939576d2307aa0043de4b71eabf99878de126b2548\",\"task-packets/RUN-001.yaml\":\"4fa60ad4793d2268ccd5f84e0cbc4ce3d45340abf2ba824b30cc895b5a618457\",\"task-packets/RUN-002.yaml\":\"cbda98c7e8f70f404c2316fa50e09eb66d18778a82ae2d64a16d20451a03c67e\",\"task-packets/RUN-EXP-001.yaml\":\"2a134a3b0e344b18a35ef3b82f1d34aa74f79ef83ab0730cda2eb740bce4a541\",\"task-packets/RUN-GW-001.yaml\":\"3695dc7de22d757f70528d9f23d0c4b46865b70a22c5c15f4bd423590544069a\",\"task-packets/RUN-GW-002.yaml\":\"3745467874e1293eb93e8a32c36c50493568389d718b1e66650952352a733996\",\"task-packets/SDK-001.yaml\":\"737990fc853fd50c22d211f0ada320585b304fe116cab881581575a9a6dca941\",\"task-packets/SDK-002.yaml\":\"b791f5f514dec76ebfd37ea17c7b0ca024057fbe4ebc2443bcdf15e7ca18c151\",\"task-packets/SDK-003.yaml\":\"49b413cbd44e8fefdb20b7c817c676b0b95d671a25f07a11c47fb9276ab1a7b5\",\"task-packets/SDK-004.yaml\":\"8c24a6bc4429e29e97a64746d12de95d9b47bd7b3d48ca312d8c9a3aea8ec23a\",\"task-packets/SDK-005.yaml\":\"b6db3bd5595dcae7aeaea71a3a5ca49b4044abfbe13d687d8cb49c1013c45a7a\",\"task-packets/SDK-006.yaml\":\"dc7771e61400288b5b7e6c6b69b802430ededa03947bed2adaa5f6542a063edc\",\"task-packets/SDK-007.yaml\":\"054feee9dfc45e76959a7182e47672dc95fb68558d2f1f7d97445eada3566054\",\"task-packets/TRUST-001.yaml\":\"d4fec1372836a3c85458b1e489fabda0869cc38a8bc480a709dc94e0e5fb8b19\",\"task-packets/TRUST-002.yaml\":\"cf80bc33b5517177e00f2d9e8bddb92c41f1c59b18a0cc2f54688a693a4ac151\",\"task-packets/TRUST-003.yaml\":\"b0d1ccdb6a7545fbc58d8c32fa5e9835383608ba945ad948da06c8c6996af350\",\"task-packets/TRUST-EVAL-001.yaml\":\"c0f5eaa5e35ea34fff04eb49ae4b500b4dbcc01221e11ece6b95b845c376828c\",\"task-packets/TRUST-FIX-001.yaml\":\"68d753be5f9eb9edaaf696bb48ea7c40448c4205d2778a3172a62a5f5707cc6c\",\"task-packets/TRUST-FIX-002.yaml\":\"f74a5004b51b8b16aa7a9c01036ac76bb1b396ddc692cc5736233639ee314893\",\"task-packets/TRUST-GOV-001.yaml\":\"af7591bd4b20237ad54e942c65d4149540f4dca3d72b6478db6bb9e0afff3221\",\"task-packets/TRUST-OBS-001.yaml\":\"760c4a519ec39f1a4a9523eca563d4e22597b06c8b8929913a7953d0f30f0290\",\"task-packets/TRUST-REG-001.yaml\":\"83fc22106c0eeb31b032bd3f5820eb359855d5c928f9bf3be9cd7edf1563427e\",\"uv.lock\":\"78b80f44219e09eb34b83812d01e870edc70af2c8d6eaaa08ae26a8f45a2a7a9\"},\"inputFiles\":{\"task-packets/MET-REPAIR-011.yaml\":\"68308a56b7d60b4083330f479868bf10b378a84c9d1cf25fcc1b055bf1444964\",\"task-packets/CONF-FIX-004.yaml\":\"6a41b419c4e5b02311e148b846d339216f1b512cf8025ae75de77e72ea3d8db0\",\"architecture/custody-handoff-inputs/baseline.json\":\"9053162f5249e75584c334fc6898444e6c7220b1cf116f8efb348a6658165ca6\",\"docs/alpha-2/CUSTODY_HANDOFF_REPAIR.md\":\"0a095725bf71fb26ab8500391c1c214fef63f124b7a29ec171a552d0a211b025\"},\"packetSpecifications\":{\"MET-REPAIR-011\":{\"id\":\"MET-REPAIR-011\",\"repository\":\"Harness-Engineering\",\"branch\":\"codex/met-repair-011-custody-handoff\",\"objective\":\"Publish the approved retained-custody handoff correction and bounded CONF-FIX-004 prerequisite; source authority only.\",\"predecessors\":[\"MET-REPAIR-010\",\"CONF-LIVE-002\"],\"allowedPaths\":[\"task-packets/MET-REPAIR-011.yaml\",\"task-packets/CONF-FIX-004.yaml\",\"architecture/custody-handoff-amendment.json\",\"architecture/custody-handoff-inputs/baseline.json\",\"scripts/validate_custody_handoff.py\",\"tests/test_custody_handoff.py\",\"docs/alpha-2/CUSTODY_HANDOFF_REPAIR.md\",\"scripts/validate_policy_observation.py\",\"tests/test_policy_observation.py\",\"scripts/validate_proxy_contract.py\",\"tests/test_proxy_contract.py\",\"scripts/validate_readiness.py\",\"scripts/validate_reuse.py\",\"scripts/validate_readiness_repairs.py\",\"scripts/validate_linux_readiness.py\",\"scripts/validate_linux_repair.py\",\"scripts/validate_linux_test_ownership.py\",\"scripts/validate_model_fixture_scope.py\",\"scripts/validate_model_api_inventory.py\",\"scripts/validate_live_backend_readiness.py\",\"scripts/validate_packet_scalar_repair.py\",\"scripts/validate_successor_inventory.py\",\"tests/test_alpha2_readiness.py\",\"tests/test_live_backend_readiness.py\",\"tests/test_reuse.py\",\"tests/test_linux_test_ownership.py\",\"tests/test_model_fixture_scope.py\",\"tests/test_successor_inventory.py\",\"tests/test_model_api_inventory.py\",\"tests/test_task_packets.py\",\"tests/test_packet_scalar_repair.py\",\"tests/test_linux_repair.py\",\"tests/test_linux_readiness.py\",\"docs/MASTER_DEVELOPMENT_PLAN.md\",\"docs/READINESS_INDEX.md\",\"docs/adr/0004-sol-high-packet-boundary.md\",\"docs/DEVELOPMENT_STATUS.md\",\"docs/repositories/00-harness-engineering.md\",\"docs/repositories/12-mas-harness-conformance-labs.md\",\"task-packets/README.md\",\"docs/alpha-2/LIVE_BACKEND_READINESS.md\",\"docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md\"],\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\",\"sourceReuse\":[],\"contracts\":[\"Consumes meta main 108e61953d522106db7c8de65ee19120a952853b and conformance main 7205075d2f234b622dd61072803b754f1dffeb79, tree c48d71a7c8d5ddf245e1aab8063ecd9ae2b59834: 127 files / 279 original test IDs. The custody handoff gap is SOURCE_INSPECTION_ONLY, not a reproduced runtime exploit.\",\"Add exactly MET-REPAIR-011 and CONF-FIX-004: 138 packets, thirteen repositories, four planes, sixteen harnesses and twelve unchanged possible manual live declarations. Preserve all 136 predecessor packet YAML and existing architecture/legal/policy/release/schema bytes.\",\"CONF-FIX-004 is a five-existing-path corrective checkpoint within stage two, not an additional stage or runtime permission. Keep 110/120/127/135/141/146/151 source path counts, six suites/eight product commands, all historical guards, and the later CONF-LIVE-003 eight-path grant unchanged.\",\"Source/local/required self-hosted CI/merge/local exact-main closure is required separately for this publication and CONF-FIX-004 before CONF-LIVE-003. Only explicitly bounded custody source changes and append-only regression/document additions may supersede the original 127-file checkpoint.\"],\"deliverables\":[\"Pin the complete historical 127-file/279-ID source inventory and inert before bytes of only the five corrective paths. Never import or execute a stored product snapshot. Publish a closed region-delta data oracle that rejects unknown paths/regions, altered protected source, changed historical tests/docs and incomplete correction records.\",\"Define retained no-follow file/ancestor custody, immutable verified authority bytes, a supervisor-owned handoff, repeated metadata/three-signer validity checks, and exhaustive release on failure/cancel/expiry/close. Forbid pathname reopening, caller-owned handles, credential access before isolation/reservation, native-test shortcuts and silent trust refresh.\",\"Publish CONF-FIX-004 with exact existing source regions, unchanged legacy reader call contracts and predecessor tests preserved as byte prefixes; append independent regressions and a bounded source-delta record to the existing document. No new product path, dispatcher edit, public API change or root installation.\",\"Reconcile future proxy consumers with the corrected checkpoint through explicit before/after evidence, never rewriting the original baseline or adding hash exemptions. Keep server containment, observer availability, fixed probes, packaging and native qualification independently waiting.\",\"Update deterministic catalog, ownership, current dispatch and phase labels. Preserve the unresolved prior nested-test timing failures and one unchanged retry policy; do not relax timeouts, isolation, coverage or add profiling/performance changes.\",\"Run all seventeen declared commands only through the installed signed localhost offline launcher, required PR CI and separate local exact-main replay. No product execution occurs in this meta packet.\"],\"excluded\":[\"Product edits/tests/execution; any consumed packet, architecture/legal/policy/release/schema rewrite; warm-source access; new credential/key/certificate generation; downloads or dependencies; root runner/policy/toolchain/workflow changes; cloud/VM provisioning, hosted runners, artifacts uploads, paid APIs; unrelated timing/performance fixes; source-to-runtime or tenant-acceptance promotion.\"],\"prefetchCommands\":[],\"offlineAcceptanceCommands\":[[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_reuse.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_alpha2_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_readiness_repairs.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_repair.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_test_ownership.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_model_fixture_scope.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_model_api_inventory.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_live_backend_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_packet_scalar_repair.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_successor_inventory.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_proxy_contract.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_policy_observation.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_custody_handoff.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"-m\",\"pytest\",\"tests\",\"ci/test_offline_runner.py\",\"ci/test_warm_snapshot.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/zero_bill_scan.py\",\".\"]],\"offlineExecution\":{\"wrapperArgv\":[\"./ci/verify-offline.sh\"],\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"prefetchOutsideSession\":false,\"offlineEnvironment\":{\"UV_OFFLINE\":\"1\",\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\"}},\"expectedEvidence\":[\"138 exact schema-valid owned packets; all 136 predecessor packet and immutable authority bytes preserved. Independent data-only region/append/checkpoint mutation tests; original 127-file/279-ID history remains pinned.\",\"Product source correction is unexecuted; installed backend, native Linux, runtime and tenant acceptance remain NOT_RUN_ENV_UNAVAILABLE. No product test is performed by a source-delta oracle.\",\"Separate local/head/CI/merge/local exact-main evidence; preserve all failures. Alpha 2 ONGOING; effort transition NOT_DUE. Existing nonroot signed activation only, no new administrator authentication or billing surface.\"],\"rollback\":\"Before consumption revert this additive publication as one reviewed unit; after consumption issue a bounded successor. Preserve accepted source hashes, historical test/CI evidence, immutable packet bytes, trust/replay history and tenant data.\"},\"CONF-FIX-004\":{\"id\":\"CONF-FIX-004\",\"repository\":\"mas-harness-conformance-labs\",\"branch\":\"codex/conf-fix-004-retained-custody\",\"objective\":\"Repair retained authority custody and supervisor-to-proxy handoff while preserving the 127-file stage and all 279 predecessor test IDs.\",\"predecessors\":[\"MET-REPAIR-011\",\"CONF-LIVE-002\"],\"allowedPaths\":[\"src/harness_conformance/live_linux_boundary.py\",\"src/harness_conformance/live_supervisor.py\",\"tests/live_backend/test_linux_boundary.py\",\"tests/live_backend/test_supervisor.py\",\"docs/live-backend/linux-boundary.md\"],\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\",\"sourceReuse\":[],\"contracts\":[\"Consume exact merged MET-REPAIR-011 and its inert baseline/region oracle before edits. Begin from conformance main 7205075d2f234b622dd61072803b754f1dffeb79; no warm source or different product checkout.\",\"Only the two explicitly scoped custody/supervisor modules may alter existing source regions. Existing test_linux_boundary.py, test_supervisor.py and linux-boundary.md must remain exact byte prefixes; append new test classes/helpers and the correction report. All 122 other files, original assertions, 279 test IDs, old 120-file baseline fence and source guards remain unchanged.\",\"Preserve all six later packet YAML/digests, paths and eight-command inventories. This is an in-place stage-two correction: 127 files, no new stage or filename. CONF-LIVE-003 must pin its actual corrected predecessor and retain original-versus-corrected evidence.\",\"Retained bytes or a descriptor alone are not authority. Only fixed installed custody, three independent valid roles, verified scope, durable reservation and active kernel-bound session may hand verified inputs to the proxy. No new public schema, signature purpose, backend selector, path option or live execution.\"],\"deliverables\":[\"Implement retained no-follow file and ancestor handles plus verified immutable bytes for installed identity, trust, capacity, release, packet/campaign/bundle and every signed kit member required downstream. Establish first-read custody once and retain it through the owning session; do not reconstruct custody by reopening a validated path.\",\"Keep read_owned and read_owned_kit legacy return types and call behavior for existing consumers. Native custody capture/handoff is internal and non-authorizing unless the installed factory and complete owned handle registry verify it. Legacy cached digest or mocked bytes cannot supply a production custody lease.\",\"Construct InstalledContext only in NativeSupervisor, bind it to its owner/process/active session and hand off verified release/profile/CA/observation-binding bytes with retained identities. Reuse the verified rootfs directory handle; no second rootfs path lookup. No caller context, callback, FD, token or verified flag is admitted.\",\"Recheck file and named inode, every parent-chain identity/owner/mode, content-change metadata, signer validity/revocation and wall/monotonic deadlines before operations and after blocking I/O. Detect changed/replaced trust and enrollment without refresh or reopening. Existing ambient-FD rejection remains: only internally owned verified custody FDs may be recognized, never a caller allowlist.\",\"Close and invalidate retained custody on every initialization failure, reservation/boundary failure, cancel, expiry, terminal operation and close; continue cleanup after one close error without resurrecting nonce or reporting successful cleanup. Prevent leaks, double-close/recycled-FD use, cross-owner/fork/subclass/serialized handle reuse; child receives no authority file path/FD/bytes.\",\"Preserve every predecessor test byte and append flat independently discovered regressions for the full native factory-to-fixed-proxy handoff using explicit OS-mocked unit fixtures. Test no reopening, source substitution, each stale trust/ancestor change, ambient descriptor injection, rootfs replacement, exhaustion and all cleanup paths. Existing unit adapters never become native execution.\",\"Append a canonical SOURCE_DELTA_ONLY proof/report to docs/live-backend/linux-boundary.md binding MET-REPAIR-011, this packet digest, exact old/new source hashes, allowed regions, original 279 IDs and the current inventory. Reuse the pinned data-only oracle in appended tests; no snapshot compile/import/exec, relaxed hashes, skipped tests or modified existing assertions.\",\"Run exactly all eight declared commands under one signed offline process tree, zero skipped/xfail/deselected product tests, then required localhost PR CI and independent local exact-main. Hand off the corrected commit/tree/inventory/test counts to CONF-LIVE-003; source success grants no live installation or native acceptance.\"],\"excluded\":[\"All other product files including public schemas, crypto/canonical/live authority helpers, replay store, Makefile/dispatcher, baseline fixtures, workflow/toolchain/PORTING and every predecessor test body; warm sources; new dependencies/downloads; live/native probes, networking, credentials or OS policy installation during coding/CI; client/server transport or observer implementation; unrelated isolation redesign, timing fixes, tenant data or trust/replay history changes.\"],\"prefetchCommands\":[],\"offlineAcceptanceCommands\":[[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/meta\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/parity\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/alpha1\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/fixes/runner_boundary\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/platform/linux_baseline\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/live_backend\",\"-p\",\"test_*.py\"],[\"make\",\"campaign\",\"CAMPAIGN=linux-baseline\"],[\"make\",\"evidence-verify\",\"CAMPAIGN=linux-baseline\"]],\"offlineExecution\":{\"wrapperArgv\":[\"./ci/verify-offline.sh\"],\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"prefetchOutsideSession\":false,\"offlineEnvironment\":{\"UV_OFFLINE\":\"1\",\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\"}},\"expectedEvidence\":[\"Exactly five existing modified paths; 122 original files byte-identical; all 279 original methods and assertions plus new custody regressions collected, zero skips/xfails/deselection. Same complete stage-two 127-path set and all original later stage counts.\",\"Native initialization/order/handoff/cleanup algorithms covered with explicit unit adapters, no kernel/live execution or test-only production bypass. Bounded source-delta proof preserves unaffected source regions and historical test/document prefixes.\",\"Separate source/local/required CI/merge/local exact-main; no artifact, deployment, native AMD64/ARM64, runtime, assurance or tenant-acceptance promotion. No new administrator authentication or billing.\"],\"rollback\":\"Before successor consumption revert only this reviewed five-path correction. After consumption use a separately reviewed correction; retain original and corrected inventories, all failed evidence and immutable trust/replay/tenant data. Never mix custody handles across installed versions.\"}},\"sourceBaseline\":{\"commit\":\"7205075d2f234b622dd61072803b754f1dffeb79\",\"tree\":\"c48d71a7c8d5ddf245e1aab8063ecd9ae2b59834\",\"files\":127,\"tests\":279,\"path\":\"architecture/proxy-contract-inputs/baseline.json\",\"beforePath\":\"architecture/custody-handoff-inputs/baseline.json\"},\"diagnosis\":{\"classification\":\"SOURCE_INSPECTION_ONLY\",\"productTestsRun\":0,\"liveRequestsRun\":0,\"runtimeEscapeDemonstrated\":false,\"finding\":\"Verified trust/release/kit bytes and original custody handles are not retained in the supervisor context before the fixed proxy hook; reopening references would violate read-once custody.\"},\"change\":{\"sourceRegions\":{\"src/harness_conformance/live_linux_boundary.py\":[\"installed_process\",\"_installed_manifest_digest\",\"ambient_custody\",\"read_owned\",\"read_owned_kit\"],\"src/harness_conformance/live_supervisor.py\":[\"_Lifecycle._now\",\"_Lifecycle._open\",\"_Lifecycle._terminate\",\"InstalledContext.__slots__\",\"_NativeChannel.check_peer\",\"_NativeChannel.request\",\"_NativeChannel.execute\",\"_NativeChannel.cleanup\",\"NativeSupervisor.__init__\",\"NativeSupervisor.open_session\",\"NativeSupervisor.close\"]},\"appendOnlyPaths\":[\"tests/live_backend/test_linux_boundary.py\",\"tests/live_backend/test_supervisor.py\",\"docs/live-backend/linux-boundary.md\"],\"appendedSource\":\"DEFINITIONS_ONLY_NO_TOP_LEVEL_EXECUTION\",\"maxReplacementBytes\":131072,\"maxAppendBytes\":1048576,\"maxProofBytes\":2097152,\"proofSchemaVersion\":\"planeon.internal.custody-source-delta/v1\",\"proofFence\":\"harness-custody-source-proof\",\"unchangedProductFiles\":122,\"existingProductPaths\":127,\"minimumPredecessorTests\":279,\"legacyReaderContractsUnchanged\":true,\"predecessorTestsBytePrefixes\":true,\"originalBaselineFenceUnchanged\":true,\"snapshotsExecutable\":false},\"dispatchGate\":{\"requiresCompletedPacket\":\"MET-REPAIR-011\",\"then\":\"CONF-FIX-004\",\"before\":\"CONF-LIVE-003\",\"requiredEvidence\":[\"SOURCE\",\"LOCAL_OFFLINE\",\"REQUIRED_PR_CI\",\"MERGE\",\"LOCAL_EXACT_MAIN\"],\"stageCounts\":[110,120,127,135,141,146,151],\"productCommands\":8,\"consumerPathsUnchanged\":true,\"packetRewrite\":false,\"runtimeUnblocked\":false},\"previousClosure\":{\"packet\":\"MET-REPAIR-010\",\"pr\":104,\"main\":\"108e61953d522106db7c8de65ee19120a952853b\",\"ci\":34196959000,\"headTests\":2284,\"existingNestedSkips\":10,\"mainAttempt1\":\"NOT_PASS_NESTED_TIMEOUT_420_SECONDS\",\"mainAttempt2\":\"PASS_UNCHANGED_RETRY\",\"timingStability\":\"UNRESOLVED\",\"timeoutChangeAuthorized\":false},\"evidence\":{\"phase\":\"Alpha 2\",\"product\":\"NOT_RUN\",\"nativeLinux\":\"NOT_RUN_ENV_UNAVAILABLE\",\"runtime\":\"NOT_RUN_ENV_UNAVAILABLE\",\"tenantAcceptance\":\"NOT_RUN_ENV_UNAVAILABLE\",\"nativeAcceptance\":false,\"modelEffortTransition\":\"NOT_DUE\"}}")


class RetainedSupervisorTests(unittest.TestCase):
    def rig(self):
        from test_linux_boundary import _CustodyRig
        return _CustodyRig()

    def test_full_native_factory_to_fixed_hook_uses_original_bytes_without_reopening(self):
        with self.rig() as rig:
            handle = rig.open()
            context, custody = rig.owner._context, rig.owner._custody
            before = list(rig.fs.opens)
            for case in CASES:
                result = rig.owner.execute_fixed(handle, case, "amd64")
                self.assertFalse(result["nativeAcceptance"])
            self.assertEqual(len(rig.hook_calls), 10)
            self.assertEqual(rig.fs.opens, before)
            self.assertTrue(all(item[1] is context for item in rig.hook_calls))
            self.assertTrue(custody.closed)
            self.assertIsNone(context._root_fd)
            self.assertIsNone(rig.owner._active)
            self.assertEqual(parse_journal(rig.journal.raw)[0][replay_key(context._binding)]["state"], "COMPLETED")
            rig.lease.kill_and_reap.assert_called_once()
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
        self.assertFalse(rig.fs.fds)
        self.assertEqual(len(rig.fs.closes), len(set(rig.fs.closes)))

    def test_each_authority_kit_member_and_full_ancestor_change_refuses_before_hook(self):
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            # A check failure is restored only in this observation fixture;
            # execute itself invalidates on the first failure (tested below).
            for path in tuple(context._custody.handles):
                original = rig.fs.nodes[path]
                with self.subTest(path=path):
                    rig.fs.nodes[path] = deepcopy(original)
                    rig.fs.nodes[path].st_ino += 10000
                    with self.assertRaises(ConformanceError):
                        rig.owner._boundary.check_peer()
                    rig.fs.nodes[path] = original
            self.assertFalse(rig.hook_calls)
            root = rig.fixture.envelope["conformanceKitRoot"] + "/rootfs"
            rig.fs.nodes[root].st_ctime_ns += 1
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertTrue(context._custody.closed)
            self.assertFalse(rig.hook_calls)

    def test_post_blocking_mutation_refuses_receipt_and_consumes_session(self):
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            channel = rig.owner._boundary.channel
            original = channel.recvmsg
            def receive(*args):
                value = original(*args)
                rig.fs.nodes[str(supervisor.FIXED_TENANT_TRUST)].st_ctime_ns += 1
                return value
            channel.recvmsg = receive
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertFalse(rig.hook_calls)
            self.assertTrue(context._custody.closed)
            self.assertIsNone(rig.owner._active)

    def test_each_signer_expiry_and_initial_revocation_remain_non_authorizing(self):
        for role in ("platform", "tenant", "capacity"):
            rig = self.rig()
            trust = rig.fixture.release_trust if role == "platform" else rig.fixture.tenant_trust
            key = next(k for k in trust["keys"] if k["keyId"] == role + ".unit")
            key["validUntil"] = "2026-09-07T01:00:01Z"
            rig.refresh()
            with self.subTest(role=role), rig:
                handle = rig.open()
                context = rig.owner._context
                rig.wall = "2026-09-07T01:00:01Z"
                with self.assertRaises(ConformanceError):
                    rig.owner.execute_fixed(handle, CASES[0], "amd64")
                self.assertTrue(context._custody.closed)
                self.assertFalse(rig.hook_calls)
            rig = self.rig()
            trust = rig.fixture.release_trust if role == "platform" else rig.fixture.tenant_trust
            next(k for k in trust["keys"] if k["keyId"] == role + ".unit")["revoked"] = True
            rig.refresh()
            with self.subTest(revoked=role), rig:
                with self.assertRaises(ConformanceError):
                    rig.open()
                self.assertFalse(rig.hook_calls)
                self.assertFalse(rig.fs.fds)

    def test_forged_foreign_subclass_serialized_and_forked_contexts_fail_closed(self):
        from test_linux_boundary import linux
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            channel = rig.owner._boundary
            for fake in (None, {}, SimpleNamespace(_owner=rig.owner), object.__new__(supervisor.InstalledContext)):
                with self.subTest(fake=type(fake).__name__):
                    channel.context = fake
                    with self.assertRaises((ConformanceError, AttributeError)):
                        channel.check_peer()
                    channel.context = context
            with self.assertRaises((TypeError, AttributeError)):
                pickle.dumps(context)
            with patch.object(supervisor.os, "getpid", return_value=43), self.assertRaises(ConformanceError):
                channel.check_peer()
            original_owner = context._owner
            context._owner = object.__new__(supervisor.NativeSupervisor)
            with self.assertRaises((ConformanceError, AttributeError)):
                channel.check_peer()
            context._owner = original_owner
            class Foreign(supervisor.NativeSupervisor):
                pass
            with self.assertRaises(ConformanceError):
                Foreign()
            self.assertIs(linux._capture(), context._custody)
            self.assertFalse(rig.hook_calls)

    def test_snapshot_deadline_and_request_tampering_never_reaches_hook(self):
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            context._plan["namespace"] = "foreign"
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertFalse(rig.hook_calls)
        with self.rig() as rig:
            handle = rig.open()
            rig.owner._active["deadline"] += 1
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertFalse(rig.hook_calls)
        with self.rig() as rig:
            rig.open()
            request = rig.owner._boundary.request(CASES[0])
            request["namespace"] = "foreign"
            with self.assertRaises(ConformanceError):
                rig.owner._boundary.execute(request, rig.owner._active["deadline"])
            self.assertFalse(rig.hook_calls)

    def test_reservation_and_boundary_failures_close_all_custody(self):
        for failure in ("before", "partial", "after", "sync", "readback", "boundary"):
            rig = self.rig()
            with self.subTest(failure=failure), rig:
                custody = rig.owner._custody
                if failure == "boundary":
                    rig.lease.attach.side_effect = OSError("unit attach failure")
                else:
                    rig.journal.fail = failure
                with self.assertRaises((ConformanceError, OSError)):
                    rig.open()
                self.assertTrue(custody.closed)
                self.assertFalse(rig.fs.fds)
                self.assertFalse(rig.hook_calls)
                with self.assertRaises(ConformanceError):
                    rig.open()
            self.assertEqual(len(rig.fs.closes), len(set(rig.fs.closes)))

    def test_cancel_expiry_failure_and_close_never_reuse_nonce_or_descriptors(self):
        for reason in ("cancel", "expiry", "rollback", "monotonic", "clock-error", "close"):
            with self.subTest(reason=reason), self.rig() as rig:
                handle = rig.open()
                context = rig.owner._context
                if reason == "cancel":
                    rig.owner.cancel(handle)
                elif reason == "close":
                    rig.owner.close()
                else:
                    if reason == "expiry":
                        rig.wall = END
                    elif reason == "rollback":
                        rig.wall = "2026-09-07T00:59:59Z"
                    elif reason == "monotonic":
                        rig.mono = 0
                    else:
                        rig.owner._clock = Mock(side_effect=RuntimeError("unit clock unavailable"))
                    with self.assertRaises((ConformanceError, RuntimeError)):
                        rig.owner.execute_fixed(handle, CASES[0], "amd64")
                self.assertTrue(context._custody.closed)
                self.assertIsNone(rig.owner._active)
                self.assertIn(replay_key(context._binding), parse_journal(rig.journal.raw)[0])
                rig.owner.close()
                count = len(rig.fs.closes)
                rig.owner.close()
                self.assertEqual(len(rig.fs.closes), count)
            self.assertFalse(rig.fs.fds)

    def test_cleanup_failure_still_releases_remaining_resources_without_terminal_success(self):
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            rig.lease.kill_and_reap.side_effect = OSError("unit reap failed")
            rig.fs.fail_close = str(supervisor.FIXED_RELEASE_TRUST)
            with self.assertRaises(OSError):
                rig.owner.cancel(handle)
            self.assertTrue(context._custody.closed)
            self.assertIsNone(rig.owner._active)
            self.assertEqual(parse_journal(rig.journal.raw)[0][replay_key(context._binding)]["state"], "RUNNING")
            rig.owner.close()
        self.assertFalse(rig.fs.fds)

    def test_data_only_mocked_readers_and_cached_digest_never_form_native_context(self):
        fixture = backend_fixture()
        shell = object.__new__(supervisor.NativeSupervisor)
        shell._mutex, shell._closed, shell._context = threading.Lock(), False, None
        with patch.object(supervisor, "utc_now", return_value=NOW), patch.object(
                supervisor, "read_owned", side_effect=[
                    canonical_bytes(fixture.release_trust), canonical_bytes(fixture.tenant_trust),
                    canonical_bytes(fixture.capacity)]) as reader, self.assertRaises(ConformanceError):
            shell.open_session(canonical_bytes(fixture.envelope))
        self.assertEqual(reader.call_count, 3)
        self.assertIsNone(shell._context)

    def test_missing_fixed_proxy_module_never_falls_back(self):
        import sys
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            with patch.dict(sys.modules, {"harness_conformance.live_proxy_client": None}), self.assertRaises(ConformanceError) as raised:
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertEqual(raised.exception.reason, "PROTECTED_PROXY_UNAVAILABLE")
            self.assertTrue(context._custody.closed)
            self.assertFalse(rig.hook_calls)


    def test_proxy_result_after_authority_mutation_is_not_accepted(self):
        import sys
        with self.rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            def hook(request, supplied_context, deadline):
                result = rig.hook(request, supplied_context, deadline)
                rig.fs.nodes[str(supervisor.FIXED_RELEASE_TRUST)].st_ctime_ns += 1
                return result
            with patch.dict(sys.modules, {"harness_conformance.live_proxy_client": SimpleNamespace(execute_protected=hook)}):
                with self.assertRaises(ConformanceError):
                    rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertEqual(len(rig.hook_calls), 1)
            self.assertIsNone(rig.owner._active)
            self.assertTrue(context._custody.closed)
            self.assertEqual(parse_journal(rig.journal.raw)[0][replay_key(context._binding)]["state"], "FAILED")

    def test_journal_close_failure_does_not_skip_other_owned_descriptors(self):
        with self.rig() as rig:
            custody = rig.owner._custody
            rig.fs.fail_close = "/unit-kernel/journal"
            with self.assertRaises(OSError):
                rig.owner.close()
            self.assertTrue(custody.closed)
            self.assertFalse(rig.fs.fds)
            rig.lease.close.assert_called_once()

    def test_descriptor_injected_after_construction_or_during_io_is_not_admitted(self):
        for timing in ("before-open", "before-operation", "during-io"):
            with self.subTest(timing=timing), self.rig() as rig:
                extra = None
                if timing == "before-open":
                    extra = rig.fs.kernel_fd("/unit-rogue")
                    with self.assertRaises(ConformanceError):
                        rig.open()
                else:
                    handle = rig.open()
                    if timing == "before-operation":
                        extra = rig.fs.kernel_fd("/unit-rogue")
                    else:
                        channel = rig.owner._boundary.channel
                        original = channel.recvmsg
                        def receive(*args):
                            nonlocal extra
                            value = original(*args)
                            extra = rig.fs.kernel_fd("/unit-rogue")
                            return value
                        channel.recvmsg = receive
                    with self.assertRaises(ConformanceError):
                        rig.owner.execute_fixed(handle, CASES[0], "amd64")
                self.assertFalse(rig.hook_calls)
                # The registry must not close or adopt an unrelated descriptor.
                self.assertIn(extra, rig.fs.fds)
                rig.fs.close(extra)


class CustodySourceProofTests(unittest.TestCase):
    def inputs(self):
        # Validate actual current bytes FIRST; old oracle tests remain historical.
        _, _, _, _, historical, legacy = _credential_inputs()
        return historical, legacy, _custody_record()

    def test_exact_five_path_delta_uses_pinned_data_only_oracle(self):
        after, proof, record = self.inputs()
        validate, _, _ = _custody_oracle()
        self.assertEqual(validate(after, proof, record, proof["before"].encode()), [])

    def test_actual_127_path_inventory_preserves_other_122_complete_file_bytes(self):
        result = _credential_repository()
        self.assertGreaterEqual(result["stage"], 2)
        self.assertEqual(result["unchangedAtCorrection"], 122)

    def test_original_279_methods_and_every_added_method_are_freshly_collected(self):
        result = _credential_repository()
        self.assertEqual(result["priorTestCount"], 305)
        self.assertGreater(result["testCount"], 305)

    def test_oracle_rejects_snapshot_prefix_scope_and_source_substitution(self):
        after, proof, record = self.inputs()
        validate, _, _ = _custody_oracle()
        for field, value in (("authorityDigest", "0" * 64), ("baseCommit", "0" * 40),
                             ("before", "{}"), ("baseline", "{}"), ("extra", True)):
            changed = deepcopy(proof)
            changed[field] = value
            with self.subTest(field=field):
                self.assertTrue(validate(after, changed, record, proof["before"].encode()))
        for path in after:
            changed = dict(after)
            changed[path] = b"# substituted\n" + changed[path]
            with self.subTest(path=path):
                self.assertTrue(validate(changed, proof, record, proof["before"].encode()))


def _credential_oracle():
    # Pinned pure-data MET-REPAIR-012 oracle; no source snapshot execution.
    import ast
    RECORD_SHA256 = "851fd80ddeec7367405a3e8445e330290341e2b4d68bccf372c24a4b965c341c"
    BEFORE_PATH = "architecture/credential-lifecycle-inputs/before.json"
    CHECKPOINT_PATH = "architecture/credential-lifecycle-inputs/checkpoint.json"
    DOC_PATH = "docs/live-backend/linux-boundary.md"
    PROOF_FIELDS = {"schemaVersion", "evidenceClass", "packetId", "packetSha256", "authorityDigest",
                    "baseCommit", "baseTree", "before", "checkpoint", "sources", "tests"}
    canonical, digest, parse = SUCCESSOR.canonical, SUCCESSOR.digest, SUCCESSOR.parse
    _, reconstruct_source, appended_definitions = _custody_oracle()
    def require(ok, reason):
        if not ok:
            raise ValueError(reason)

    def definitions(raw):
        """Read AST locations only. No compile, import, eval or snapshot execution."""
        require(type(raw) is bytes and len(raw) <= 2097152, "bounded source bytes required")
        tree = ast.parse(raw)
        lines = raw.splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line))
        result = {}
        def save(name, node):
            require(name not in result, "duplicate source definition")
            start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
            result[name] = (offsets[start - 1], offsets[node.end_lineno], node)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                save(node.name, node)
                if isinstance(node, ast.ClassDef):
                    for child in node.body:
                        if isinstance(child, ast.FunctionDef):
                            save(node.name + "." + child.name, child)
                        elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                            save(node.name + "." + child.targets[0].id, child)
        return tree, result

    def pinned(record):
        require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
                "exact credential authority required")

    def test_ids(raw):
        """Independent AST identities only. Not discovery or behavioral acceptance."""
        tree, names = definitions(raw)
        require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "load_tests"
                        for n in tree.body), "custom discovery forbidden")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for decorator in node.decorator_list:
                    text = ast.unparse(decorator)
                    require(not any(word in text for word in ("skip", "expectedFailure", "xfail")), "hidden test")
        return sorted(k for k, (_, _, node) in names.items()
                      if "." in k and isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))

    def region_delta(before, row, allowed, limits, *, tests=False):
        require(type(row) is dict and set(row) == {"beforeSha256", "afterSha256", "regions", "append"},
                "closed region delta required")
        require(type(row["append"]) is str, "append text required")
        # Reuse the unchanged source-region oracle; test append has its own grammar.
        base_row = dict(row)
        appended = row["append"].encode()
        require(len(appended) <= limits["maxAppendBytes"], "append limit")
        if not tests:
            return reconstruct_source(before, row, allowed, limits)
        require(type(row["regions"]) is dict and set(row["regions"]) <= set(allowed), "test region scope")
        _, locations = definitions(before)
        chunks = [(locations[name][0], locations[name][1], value.encode()) for name, value in row["regions"].items()]
        base, cursor = b"", 0
        for start, end, raw in sorted(chunks):
            require(start >= cursor, "overlapping test region")
            base += before[cursor:start] + raw
            cursor = end
        base += before[cursor:]
        if chunks:
            base_row.update(append="", afterSha256=digest(base))
            require(reconstruct_source(before, base_row, allowed, limits) == base, "test region mismatch")
        else:
            require(row["beforeSha256"] == digest(before), "test before mismatch")
        require(appended.startswith(b"\n") and appended.endswith(b"\n"), "new test append required")
        ids = appended_definitions(appended, base, tests=True)
        require(ids and not set(ids) & set(test_ids(before)), "new test IDs required")
        after = base + appended
        require(digest(after) == row["afterSha256"] and set(test_ids(before)) <= set(test_ids(after)),
                "test hash or old ID changed")
        return after

    def validate_delta(after, proof, record, before_raw, checkpoint_raw):
        try:
            pinned(record)
            require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][BEFORE_PATH]
                    and type(checkpoint_raw) is bytes and digest(checkpoint_raw) == record["inputFiles"][CHECKPOINT_PATH],
                    "exact before checkpoint required")
            before = parse(before_raw)["files"]
            require(type(after) is dict and set(after) == set(before)
                    and all(type(v) is bytes and len(v) <= 2097152 for v in after.values()), "five bounded files required")
            require(type(proof) is dict and set(proof) == PROOF_FIELDS
                    and len(canonical(proof)) <= record["change"]["maxProofBytes"], "closed bounded proof required")
            expected = dict(schemaVersion=record["change"]["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
                packetId="CONF-FIX-005", packetSha256=record["inputFiles"]["task-packets/CONF-FIX-005.yaml"],
                authorityDigest=RECORD_SHA256, baseCommit=record["sourceBaseline"]["commit"],
                baseTree=record["sourceBaseline"]["tree"], before=before_raw.decode(), checkpoint=checkpoint_raw.decode())
            require(all(proof[k] == v for k, v in expected.items()), "proof authority mismatch")
            for field, rules, tests in (("sources", "sourceRegions", False), ("tests", "testRegions", True)):
                require(type(proof[field]) is dict and set(proof[field]) == set(record["change"][rules]), "exact delta paths required")
                for path, regions in record["change"][rules].items():
                    require(region_delta(before[path].encode(), proof[field][path], regions,
                                         record["change"], tests=tests) == after[path], "current source substitution")
            doc = after[DOC_PATH]
            require(doc.startswith(before[DOC_PATH].encode()), "historical document changed")
            marker = ("```" + record["change"]["proofFence"] + "\n").encode()
            require(doc.count(marker) == 1, "unique credential proof required")
            raw, closing = doc.split(marker, 1)[1].split(b"\n```", 1)
            require(raw == canonical(proof) and (not closing or closing.startswith(b"\n")), "proof fence mismatch")
            return []
        except (ValueError, TypeError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError):
            return ["invalid credential source delta; no execution authority"]

    return validate_delta, test_ids


def _credential_record():
    return SUCCESSOR.parse("{\"approvalDate\":\"2026-09-09\",\"authorityPacket\":\"MET-REPAIR-012\",\"change\":{\"allBehavioralTestBodiesUnchanged\":true,\"documentPath\":\"docs/live-backend/linux-boundary.md\",\"existingProductPaths\":127,\"maxAppendBytes\":1048576,\"maxProofBytes\":2097152,\"maxReplacementBytes\":131072,\"minimumPredecessorTests\":305,\"originalDocumentBytePrefix\":true,\"proofFence\":\"harness-credential-source-proof\",\"proofSchemaVersion\":\"planeon.internal.credential-source-delta/v1\",\"snapshotsExecutable\":false,\"sourceRegions\":{\"src/harness_conformance/live_linux_boundary.py\":[\"_RetainedCustody.__init__\",\"_RetainedCustody.check_ambient\",\"_RetainedCustody.close\"],\"src/harness_conformance/live_supervisor.py\":[\"_Lifecycle._now\",\"_Lifecycle._terminate\",\"InstalledContext.__slots__\",\"_NativeChannel.check_peer\",\"_NativeChannel.execute\",\"_NativeChannel.cleanup\",\"_open_retained_session\",\"_check_retained_context\",\"_cleanup_native\"]},\"testRegions\":{\"tests/live_backend/test_linux_boundary.py\":[],\"tests/live_backend/test_supervisor.py\":[\"CustodySourceProofTests.inputs\",\"CustodySourceProofTests.test_actual_127_path_inventory_preserves_other_122_complete_file_bytes\",\"CustodySourceProofTests.test_original_279_methods_and_every_added_method_are_freshly_collected\"]},\"unchangedProductFiles\":122},\"currentPacketCount\":141,\"diagnosis\":{\"classification\":\"SOURCE_INSPECTION_ONLY\",\"finding\":\"Sealed initial custody has no post-isolation credential slot; ambient checks reject retained late credential handles. Three source-accounting regions also require bounded cumulative-stage adaptation.\",\"liveRequestsRun\":0,\"productTestsRun\":0,\"runtimeEscapeDemonstrated\":false},\"dispatchGate\":{\"before\":\"CONF-LIVE-003\",\"consumerPathsUnchanged\":true,\"packetRewrite\":false,\"productCommands\":8,\"requiredEvidence\":[\"SOURCE\",\"LOCAL_OFFLINE\",\"REQUIRED_PR_CI\",\"MERGE\",\"LOCAL_EXACT_MAIN\"],\"requiresCompletedPacket\":\"MET-REPAIR-012\",\"runtimeUnblocked\":false,\"stageCounts\":[110,120,127,135,141,146,151],\"then\":\"CONF-FIX-005\"},\"evidence\":{\"modelEffortTransition\":\"NOT_DUE\",\"nativeAcceptance\":false,\"nativeLinux\":\"NOT_RUN_ENV_UNAVAILABLE\",\"phase\":\"Alpha 2\",\"product\":\"NOT_RUN\",\"runtime\":\"NOT_RUN_ENV_UNAVAILABLE\",\"tenantAcceptance\":\"NOT_RUN_ENV_UNAVAILABLE\"},\"historicalPacketCount\":139,\"inputFiles\":{\"architecture/credential-lifecycle-inputs/before.json\":\"9176a8d22bab88e48111d53540815ea8be9b2987c43ddfe824de6664971b640e\",\"architecture/credential-lifecycle-inputs/checkpoint.json\":\"88b02e2cea777d57723f3d5f6f1309213c93389343084c714ddd92393e5fae95\",\"architecture/credential-lifecycle-inputs/meta-tests.before.json\":\"432d5dd6b85df90eba864cf73aa9d5e2cbebf999f7ccde85f72be4e4982f8a53\",\"docs/alpha-2/CREDENTIAL_LIFECYCLE_REPAIR.md\":\"b736e1f808ef31ffa28df7702e3ac4a3325cdcaaaef544bdec1f79c55fd4bd41\",\"task-packets/CONF-FIX-005.yaml\":\"6e3d31d5facfa69b9e38299317e4d6b9c7356566c5ded0594cbdeb965acdde0e\",\"task-packets/MET-REPAIR-012.yaml\":\"98df418a71f5e42a50c92b7b118698ea9278f2f8c239dc80288fdbedb3739845\",\"tests/test_alpha2_readiness.py\":\"aabe17d602a40416bfb12fcaa3e209115c513554c732ea3615f5bf2eafa4f7d9\",\"tests/test_architecture.py\":\"4950bc15a766718f7841fdb3a549507c99e2eb67805eda952f536190d87301fa\",\"tests/test_ci_performance.py\":\"1b47f4fecfa71d6e6906bf848fa4e6afcb978e2eadf564c91974ab4b639a57c7\",\"tests/test_custody_handoff.py\":\"4ab3e50cc05efea713c03291e4555a73a62417e4239e95fba8c636b4ba1d25e7\",\"tests/test_linux_readiness.py\":\"506a88a6d370339ec1fce632d7b3d900a01fc10175a86c0579dc40eb9fb29363\",\"tests/test_linux_repair.py\":\"2596f152007113127f844c2f64a999bf7725bd74bce841c61b414f7e06d8dc8e\",\"tests/test_linux_test_ownership.py\":\"d4147b61ec597990e175cffd2981c04567c3a700bb69aafe52b3f76922feb15f\",\"tests/test_live_backend_readiness.py\":\"505bddd3fd298a4977d7b2d421d3db971f2ee5f7ac094a12353093d9d39ab91a\",\"tests/test_model_api_inventory.py\":\"cac85c63f65881164f3284bb3f52cebc17fb67bfe3deae5d825f6f31eddb54c9\",\"tests/test_model_fixture_scope.py\":\"87ad33e9dd5e8fa3c72366a1ccb4f23505f3c98789ea78d328e34e4164a81016\",\"tests/test_model_usage_observation.py\":\"3b6edd26186344584d7257eac61cc1e8b57b7de6fb34f16e865571a581b78e07\",\"tests/test_packet_scalar_repair.py\":\"a1dee5a65007066a02c9ff854e952e991046893c80dea3b6886b1ce635c2b3f4\",\"tests/test_policy_observation.py\":\"a3c4306e4384009a4071d96b82d385826c7b8df4d4b2e6b3542c6cdee836255b\",\"tests/test_proxy_contract.py\":\"21fbcbd92cdf051424ac835434cefe5f3753d23aeaf9c9ddf74af1ac0c53469b\",\"tests/test_readiness.py\":\"9694b99697768d759542b5d0cacb44ae8f04a75591254bda94555f1dc70ba280\",\"tests/test_readiness_repairs.py\":\"2647e5b195cfeb891429d17e28a3b34714f74cacab83c08b11af5f0b29a20147\",\"tests/test_release_lock.py\":\"41f1e77372f5536d2812041fb32e79f2bc7b8ccd3f776e59bc5f0bc5a0b10521\",\"tests/test_reuse.py\":\"16827a8031d56fcb26d32697b6c4fe2360cfb4dfb332e776fe9d87170501eec0\",\"tests/test_successor_inventory.py\":\"ec1ee87141400af5cbc1b5406610f1aa01f5f0a392a96c82bcaed3fea7f06b42\",\"tests/test_task_packets.py\":\"6387d51b4bb99b80737edfa5e60ccf6971459057af03fbb5b1f78e1fe4e08d67\",\"tests/test_validator_units.py\":\"fc301539333e3f9a833577fd1c879b9d23b969a9056a4c9ab5b721d80f363db6\"},\"lifecycle\":{\"ancestryDepth\":64,\"arbitraryDescriptorAdoption\":false,\"closeOwner\":\"NATIVE_SUPERVISOR\",\"credentialBytes\":262144,\"credentialFiles\":1,\"credentialPathSource\":\"VERIFIED_CAMPAIGN_PROXY_ONLY\",\"credentialsBeforeReservationOrIsolation\":false,\"initialAuthority\":\"SEALED_IMMUTABLE\",\"persistentDescriptorLimit\":66,\"policyBypass\":false,\"refreshAuthority\":false,\"sealedMemfds\":1,\"states\":[\"ABSENT\",\"ACQUIRING\",\"RETAINED\",\"IO_ACTIVE\",\"CLOSED\",\"FAILED\"],\"transientDescriptorLimit\":2,\"transportSockets\":1},\"metaBaseline\":\"e367e89463b86ebc1b1e20563d677bdfe6694060\",\"metaReconciliation\":{\"baseCommit\":\"e367e89463b86ebc1b1e20563d677bdfe6694060\",\"currentCorpusFiles\":157,\"currentPacketCount\":141,\"fullReplays\":2,\"historicalPacketCount\":139,\"limits\":{\"hostSeconds\":900,\"nestedSeconds\":420,\"workflowMinutes\":15},\"performancePacket\":\"MET-PERF-001\",\"performancePr\":107,\"testRecipes\":{\"tests/test_alpha2_readiness.py\":{\"afterSha256\":\"aabe17d602a40416bfb12fcaa3e209115c513554c732ea3615f5bf2eafa4f7d9\",\"beforeSha256\":\"a279d31fa366810686b95e1310396b09c14e83950bd1ccd611495e30fcd25643\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_architecture.py\":{\"afterSha256\":\"4950bc15a766718f7841fdb3a549507c99e2eb67805eda952f536190d87301fa\",\"beforeSha256\":\"4950bc15a766718f7841fdb3a549507c99e2eb67805eda952f536190d87301fa\",\"replacements\":[]},\"tests/test_ci_performance.py\":{\"afterSha256\":\"1b47f4fecfa71d6e6906bf848fa4e6afcb978e2eadf564c91974ab4b639a57c7\",\"beforeSha256\":\"e8c0a23822c5801be56202f248af532244e3d9874b6e10989cc152583bc3a6d4\",\"replacements\":[{\"after\":\"    expected_current_test_source as expected_test_source, load_performance_inputs, test_definitions as source_test_names,\",\"before\":\"    expected_test_source, load_performance_inputs, test_definitions as source_test_names,\",\"count\":1},{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":2},{\"after\":\"assert len(paths) == 157\",\"before\":\"assert len(paths) == 155\",\"count\":1},{\"after\":\"## Historical MET-PERF-001 publication checkpoint\",\"before\":\"## Historical MET-REPAIR-011 publication checkpoint\",\"count\":1},{\"after\":\"during `MET-REPAIR-012` publication\",\"before\":\"during `MET-PERF-001` publication\",\"count\":1},{\"after\":\"MET-REPAIR-012 / PR106 | ONGOING\",\"before\":\"MET-REPAIR-012 / PR106 | WAITING\",\"count\":1}]},\"tests/test_custody_handoff.py\":{\"afterSha256\":\"4ab3e50cc05efea713c03291e4555a73a62417e4239e95fba8c636b4ba1d25e7\",\"beforeSha256\":\"0e6a33d705cb0fc6095a77cf4427ecf714f9d3e05b885fb0971f739100f731e5\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1},{\"after\":\"## Historical MET-PERF-001 publication checkpoint\",\"before\":\"## Historical MET-REPAIR-010 publication checkpoint\",\"count\":1},{\"after\":\"during `MET-REPAIR-012` publication\",\"before\":\"during `MET-REPAIR-011` publication\",\"count\":1}]},\"tests/test_linux_readiness.py\":{\"afterSha256\":\"506a88a6d370339ec1fce632d7b3d900a01fc10175a86c0579dc40eb9fb29363\",\"beforeSha256\":\"77e248e1040c429fdb1e3df6e34863da47536e9851d4556ace3ca002591be132\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_linux_repair.py\":{\"afterSha256\":\"2596f152007113127f844c2f64a999bf7725bd74bce841c61b414f7e06d8dc8e\",\"beforeSha256\":\"69bddb666d411f00a793a4cb68cecbb2a7aec70f230d35d796649edd936a8de1\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_linux_test_ownership.py\":{\"afterSha256\":\"d4147b61ec597990e175cffd2981c04567c3a700bb69aafe52b3f76922feb15f\",\"beforeSha256\":\"80cfe5cc524187a0c31dd8ba8182e51870ddeacf5f10eaf57c8d9068d9143743\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_live_backend_readiness.py\":{\"afterSha256\":\"505bddd3fd298a4977d7b2d421d3db971f2ee5f7ac094a12353093d9d39ab91a\",\"beforeSha256\":\"765e5a79c7e08d1ac46ecaa2c79c7dfa8a144c7194efb8b91b0e6262a88ff919\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_model_api_inventory.py\":{\"afterSha256\":\"cac85c63f65881164f3284bb3f52cebc17fb67bfe3deae5d825f6f31eddb54c9\",\"beforeSha256\":\"0cf81e3c7082b2b4f84d8e70fbfe5568baa5366f8ad9a474941628199ccdcc19\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_model_fixture_scope.py\":{\"afterSha256\":\"87ad33e9dd5e8fa3c72366a1ccb4f23505f3c98789ea78d328e34e4164a81016\",\"beforeSha256\":\"59f24614ff3b47de9bce24be238cb7c8ecd5a0002aae045627a85681814e98aa\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_model_usage_observation.py\":{\"afterSha256\":\"3b6edd26186344584d7257eac61cc1e8b57b7de6fb34f16e865571a581b78e07\",\"beforeSha256\":\"3b6edd26186344584d7257eac61cc1e8b57b7de6fb34f16e865571a581b78e07\",\"replacements\":[]},\"tests/test_packet_scalar_repair.py\":{\"afterSha256\":\"a1dee5a65007066a02c9ff854e952e991046893c80dea3b6886b1ce635c2b3f4\",\"beforeSha256\":\"4b64e6ed51e8ef33192e3b887f361cc055e16fa764681563709c1d29e5392bde\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_policy_observation.py\":{\"afterSha256\":\"a3c4306e4384009a4071d96b82d385826c7b8df4d4b2e6b3542c6cdee836255b\",\"beforeSha256\":\"fd8a8934adbe46c0c3138a7d54250c85b3d98e9310f7045c7f103d895988e2d3\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_proxy_contract.py\":{\"afterSha256\":\"21fbcbd92cdf051424ac835434cefe5f3753d23aeaf9c9ddf74af1ac0c53469b\",\"beforeSha256\":\"0a4447e8cbc366f3f7f0d34c1b2dcfde27197008328fd2fc620b85871c1ac08b\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_readiness.py\":{\"afterSha256\":\"9694b99697768d759542b5d0cacb44ae8f04a75591254bda94555f1dc70ba280\",\"beforeSha256\":\"9694b99697768d759542b5d0cacb44ae8f04a75591254bda94555f1dc70ba280\",\"replacements\":[]},\"tests/test_readiness_repairs.py\":{\"afterSha256\":\"2647e5b195cfeb891429d17e28a3b34714f74cacab83c08b11af5f0b29a20147\",\"beforeSha256\":\"2647e5b195cfeb891429d17e28a3b34714f74cacab83c08b11af5f0b29a20147\",\"replacements\":[]},\"tests/test_release_lock.py\":{\"afterSha256\":\"41f1e77372f5536d2812041fb32e79f2bc7b8ccd3f776e59bc5f0bc5a0b10521\",\"beforeSha256\":\"41f1e77372f5536d2812041fb32e79f2bc7b8ccd3f776e59bc5f0bc5a0b10521\",\"replacements\":[]},\"tests/test_reuse.py\":{\"afterSha256\":\"16827a8031d56fcb26d32697b6c4fe2360cfb4dfb332e776fe9d87170501eec0\",\"beforeSha256\":\"17ef064dcfdd4df0f599de30292f5a3ae14107ac902f2fe691f8cb04fa9febc1\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_successor_inventory.py\":{\"afterSha256\":\"ec1ee87141400af5cbc1b5406610f1aa01f5f0a392a96c82bcaed3fea7f06b42\",\"beforeSha256\":\"e427551b0cfb0be25858488b0c28e0df285829ac3619cfe2ebb18c2f8dd702d2\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_task_packets.py\":{\"afterSha256\":\"6387d51b4bb99b80737edfa5e60ccf6971459057af03fbb5b1f78e1fe4e08d67\",\"beforeSha256\":\"50005bf2c2c73385d0ced2a3c4ff07c699efdc5b1298b9a954f1c67cbe081d07\",\"replacements\":[{\"after\":\"== 141\",\"before\":\"== 139\",\"count\":1}]},\"tests/test_validator_units.py\":{\"afterSha256\":\"fc301539333e3f9a833577fd1c879b9d23b969a9056a4c9ab5b721d80f363db6\",\"beforeSha256\":\"fc301539333e3f9a833577fd1c879b9d23b969a9056a4c9ab5b721d80f363db6\",\"replacements\":[]}}},\"packetSpecifications\":{\"CONF-FIX-005\":{\"allowedPaths\":[\"src/harness_conformance/live_linux_boundary.py\",\"src/harness_conformance/live_supervisor.py\",\"tests/live_backend/test_linux_boundary.py\",\"tests/live_backend/test_supervisor.py\",\"docs/live-backend/linux-boundary.md\"],\"branch\":\"codex/conf-fix-005-credential-lifecycle\",\"contracts\":[\"Consume exact merged MET-REPAIR-012, its corrected checkpoint and inert before bytes. Begin at conformance main 0aa3ef3027f4a156d7ebed1b56af244e021d080a, tree 332d823a750828cfa345cf9332a2a251d6503d15; 127 files / 305 tests. Never rewrite original CONF-LIVE-002 or CONF-FIX-004 proof history.\",\"Only exact credential-lifecycle source regions and three named cumulative source-accounting regions may change. Preserve all 305 test IDs and all behavioral assertion bodies; append new regressions and a separate canonical source proof. The other 122 files and old document remain byte-identical.\",\"Keep stages 110/120/127/135/141/146/151 and later YAML/digests/eight commands unchanged. Future accounting validates exact authorized paths, original bytes or approved deltas and every freshly discovered test; no filename-presence, hash exemption or hidden suite.\",\"Only installed NativeSupervisor ownership, active kernel peer, all three signing roles, durable reservation and required current policy can admit credential use. Sealed initial authority stays immutable. No public contract, signature role, generic resource registration or weaker observation/billing boundary.\"],\"deliverables\":[\"Add bounded separate credential custody created only by the fixed native supervisor/hook lifecycle after reservation and isolation. Derive the sole CAMPAIGN_PROXY credential path from the independently verified envelope/profile/capacity; never accept a caller path or FD. Fail unavailable when fixed proxy/policy eligibility is absent.\",\"Retain one first-read root-owned 0400 credential and complete no-follow ancestry through the session; expose only verified immutable bytes to the fixed trusted proxy module. Check substitution, expiry/revocation and owner/process/channel before use and after blocking I/O, without refresh or premature credential opening.\",\"Track only internally created, non-inherited, bounded temporary memfd/transport handles during the active fixed hook; separate persistent credentials from transient I/O. No ambient adoption, arbitrary socket/FD list, monkeypatch or caller callback. Seals and cryptographic/TLS transport validation remain CONF-LIVE-003 responsibilities.\",\"Integrate ownership into peer/ambient checks and invalidation/cleanup on return, exception, cancellation, expiry, initialization failure and close. Close transient handles before hook return while preserving credential custody between operations. Attempt all cleanup after error, retain consumed nonce and never double-close reused FDs.\",\"Preserve behavioral tests and append factory-to-fixed-hook unit regressions for two successive operations, credential first-read ordering, unknown handle injection, substitution, expiry and cleanup. Mock only native OS observations; no test flag grants production eligibility.\",\"Adapt only three source-accounting regions in CustodySourceProofTests: inputs, test_actual_127_path_inventory_preserves_other_122_complete_file_bytes and test_original_279_methods_and_every_added_method_are_freshly_collected. Independently verify actual deltas, all 305 prior IDs and exact approved later inventories with fresh AST-versus-unittest collection. Old proof checking remains historical, never current behavior.\",\"Append one canonical SOURCE_DELTA_ONLY credential proof to unchanged linux-boundary.md prefix, binding authority, exact checkpoint, bounded source/accounting deltas and new IDs. Preserve both prior fences and historical hashes. The meta oracle is data-only, not behavior approval.\",\"Run all eight declared commands in one signed offline tree, zero skipped/xfail/deselected product tests; required localhost PR CI, merge and independent local exact-main. Hand the actual corrected checkpoint to CONF-LIVE-003; no native or tenant acceptance.\"],\"excluded\":[\"All other product files; predecessor behavioral test bodies and all IDs; source-accounting rewrites outside three named regions; public schemas/crypto/canonical/live/replay store, Makefile/dispatcher, baseline fixtures, workflow/toolchain/PORTING; warm sources; dependencies/downloads; live probes/network/credentials or OS installation during coding; TLS/proxy/server/observer implementation; weakened policy observation; unrelated timing/security redesign or tenant/trust/replay data changes.\"],\"expectedEvidence\":[\"Exactly five existing changed paths, 122 untouched files; all 305 prior IDs and behavioral assertions retained, exact scoped accounting corrections plus appended tests; unchanged stage paths.\",\"Factory-to-fixed-hook credential ownership and failure matrix with explicit OS-mocked unit fixtures; no secret reads, network, native isolation or test-only production bypass during acceptance.\",\"Independent source/local/required CI/merge/local exact-main; no artifact, deployment, native AMD64/ARM64, runtime, assurance or tenant acceptance promotion. No administrator authentication or billing.\"],\"id\":\"CONF-FIX-005\",\"objective\":\"Correct bounded post-isolation credential/transport handle ownership and cumulative source accounting without weakening sealed authority custody.\",\"offlineAcceptanceCommands\":[[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/meta\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/parity\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/alpha1\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/fixes/runner_boundary\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/platform/linux_baseline\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/live_backend\",\"-p\",\"test_*.py\"],[\"make\",\"campaign\",\"CAMPAIGN=linux-baseline\"],[\"make\",\"evidence-verify\",\"CAMPAIGN=linux-baseline\"]],\"offlineExecution\":{\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"offlineEnvironment\":{\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\",\"UV_OFFLINE\":\"1\"},\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"prefetchOutsideSession\":false,\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"wrapperArgv\":[\"./ci/verify-offline.sh\"]},\"predecessors\":[\"MET-REPAIR-012\",\"CONF-FIX-004\"],\"prefetchCommands\":[],\"repository\":\"mas-harness-conformance-labs\",\"rollback\":\"Before successor consumption revert only this reviewed five-path correction. After consumption use a separately reviewed correction; retain original and corrected inventories, all failed evidence and immutable trust/replay/tenant data. Never mix custody handles across installed versions.\",\"sourceReuse\":[],\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\"},\"MET-REPAIR-012\":{\"allowedPaths\":[\"task-packets/MET-REPAIR-012.yaml\",\"task-packets/CONF-FIX-005.yaml\",\"architecture/credential-lifecycle-amendment.json\",\"architecture/credential-lifecycle-inputs/before.json\",\"scripts/validate_credential_lifecycle.py\",\"tests/test_credential_lifecycle.py\",\"docs/alpha-2/CREDENTIAL_LIFECYCLE_REPAIR.md\",\"scripts/validate_policy_observation.py\",\"tests/test_policy_observation.py\",\"scripts/validate_proxy_contract.py\",\"tests/test_proxy_contract.py\",\"scripts/validate_readiness.py\",\"scripts/validate_reuse.py\",\"scripts/validate_readiness_repairs.py\",\"scripts/validate_linux_readiness.py\",\"scripts/validate_linux_repair.py\",\"scripts/validate_linux_test_ownership.py\",\"scripts/validate_model_fixture_scope.py\",\"scripts/validate_model_api_inventory.py\",\"scripts/validate_live_backend_readiness.py\",\"scripts/validate_packet_scalar_repair.py\",\"scripts/validate_successor_inventory.py\",\"tests/test_alpha2_readiness.py\",\"tests/test_live_backend_readiness.py\",\"tests/test_reuse.py\",\"tests/test_linux_test_ownership.py\",\"tests/test_model_fixture_scope.py\",\"tests/test_successor_inventory.py\",\"tests/test_model_api_inventory.py\",\"tests/test_task_packets.py\",\"tests/test_packet_scalar_repair.py\",\"tests/test_linux_repair.py\",\"tests/test_linux_readiness.py\",\"docs/MASTER_DEVELOPMENT_PLAN.md\",\"docs/READINESS_INDEX.md\",\"docs/adr/0004-sol-high-packet-boundary.md\",\"docs/DEVELOPMENT_STATUS.md\",\"docs/repositories/00-harness-engineering.md\",\"docs/repositories/12-mas-harness-conformance-labs.md\",\"task-packets/README.md\",\"docs/alpha-2/LIVE_BACKEND_READINESS.md\",\"docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md\",\"architecture/credential-lifecycle-inputs/checkpoint.json\",\"scripts/validate_custody_handoff.py\",\"tests/test_custody_handoff.py\",\"architecture/credential-lifecycle-inputs/meta-tests.before.json\",\"scripts/validate_ci_performance.py\",\"tests/test_ci_performance.py\"],\"branch\":\"codex/met-repair-012-credential-lifecycle\",\"contracts\":[\"Consume meta main e367e89463b86ebc1b1e20563d677bdfe6694060 and corrected conformance main 0aa3ef3027f4a156d7ebed1b56af244e021d080a, tree 332d823a750828cfa345cf9332a2a251d6503d15: 127 files / 305 tests. Keep the original 127-file/279-ID checkpoint and CONF-FIX-004 source proof as immutable history.\",\"Add exactly MET-REPAIR-012 and CONF-FIX-005: 141 packets, thirteen repositories, four planes, sixteen harnesses; twelve unchanged possible manual campaigns. Preserve all 139 predecessor YAML and existing architecture/legal/policy/release/schema bytes.\",\"CONF-FIX-005 owns the same five existing correction paths, narrowly named source regions and three cumulative source-accounting helper/test regions. Preserve all 305 test IDs, all behavioral assertion bodies, and complete bytes outside those exact regions; no hidden collection or broad hash exemptions.\",\"One packet/run/branch/PR. Publish this authority with local/head, required self-hosted CI, merge and independent local exact-main before product correction; close product gates separately before CONF-LIVE-003. No new stage or runtime permission.\",\"Reconcile the unmerged PR106 with accepted MET-PERF-001 without changing its packet, immutable authority, parser helper, measurement, historical test snapshots, isolation or timeouts. Exact meta-test byte transformations may update current catalog 139 to 141, current corpus 155 to 157, and named current-status/import bindings; preserve all prior behavioral assertions, IDs, parameters and markers.\"],\"deliverables\":[\"Pin corrected checkpoint, complete file/test inventory and inert before bytes of the five paths; verify original and corrected source proof lineage without importing or executing product source. Implement independent bounded source-delta and cumulative inventory data oracles with negative tests.\",\"Define supervisor-owned post-isolation credential custody separate from sealed initial authority, fixed endpoint-derived path, retained no-follow ancestry and bytes, bounded temporary transport handles, single close ownership, revocation/deadline checks and fail-closed cleanup. No generic FD/path registration, caller flag, callback or execution authority from data.\",\"Publish CONF-FIX-005 with exact region grants; retain old proof/document bytes. Permit only explicitly named cumulative source-accounting adaptations needed to validate corrected actual bytes and approved later stages; retain all 305 IDs and every behavioral test.\",\"Update current catalog, deterministic packet ownership and Alpha-2 dispatch. Retain unresolved prior 420-second nested-test timing failures and bounded unchanged retry policy; do not change timeouts, coverage, dependencies, isolation or billing boundaries.\",\"Run all twenty direct-argv commands only through existing signed localhost offline isolation, required PR CI, merge and independent local exact-main. Product correction, proxy transport and native execution remain separate.\",\"Pin the accepted performance checkpoint and every protected predecessor input. Reconcile the closed performance validator with the two exact new packets and exact current meta-test byte recipes; reject unreviewed test edits and preserve historical 139-packet reconstruction. Keep both complete replays and add independent bridge-negative tests. No blanket hash, path, count or future-packet exemptions.\"],\"excluded\":[\"Product edits/tests/execution; any consumed packet or architecture/legal/policy/release/schema rewrite; warm-source access; new credential/key/certificate generation; downloads/dependencies; root runner/policy/toolchain/workflow changes; cloud/VM provisioning, hosted runner, artifact upload, paid API; unrelated performance/isolation redesign; source-to-runtime or tenant acceptance promotion.\"],\"expectedEvidence\":[\"141 exact schema-valid owned packets; all 139 predecessor YAML and immutable authority bytes preserved. Independent closed region/prefix/proof/inventory/collection mutation tests. Both 127/279 original and 127/305 corrected histories retained.\",\"No product test or live request performed; DATA_CHECK_ONLY and SOURCE_DELTA_ONLY do not grant installed custody, native acceptance, credentials or policy approval.\",\"Separate local/head, required CI, merge and local exact-main; preserve failures. Alpha 2 ONGOING, effort transition NOT_DUE. Existing nonroot signed activation only, no new administrator authentication or billing.\"],\"id\":\"MET-REPAIR-012\",\"objective\":\"Publish the approved bounded post-isolation credential lifecycle and CONF-FIX-005 prerequisite; source authority only.\",\"offlineAcceptanceCommands\":[[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"ci/measure_yaml_parsing.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_reuse.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_alpha2_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_readiness_repairs.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_repair.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_test_ownership.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_model_fixture_scope.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_model_api_inventory.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_live_backend_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_packet_scalar_repair.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_successor_inventory.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_proxy_contract.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_policy_observation.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_custody_handoff.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_ci_performance.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_credential_lifecycle.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"-m\",\"pytest\",\"tests\",\"ci/test_offline_runner.py\",\"ci/test_warm_snapshot.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/zero_bill_scan.py\",\".\"]],\"offlineExecution\":{\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"offlineEnvironment\":{\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\",\"UV_OFFLINE\":\"1\"},\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"prefetchOutsideSession\":false,\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"wrapperArgv\":[\"./ci/verify-offline.sh\"]},\"predecessors\":[\"MET-REPAIR-011\",\"CONF-FIX-004\",\"MET-PERF-001\"],\"prefetchCommands\":[],\"repository\":\"Harness-Engineering\",\"rollback\":\"Before consumption revert this additive publication as one reviewed unit; after consumption issue a bounded successor. Preserve accepted source hashes, historical test/CI evidence, immutable packet bytes, trust/replay history and tenant data.\",\"sourceReuse\":[],\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\"}},\"performanceClosure\":{\"ci\":34310950326,\"combinedHeadAccepted\":false,\"evidenceClass\":\"PREDECESSOR_SOURCE_GATES_ONLY\",\"exactMainLogSha256\":\"b2092f6a33ea65986a7d454b2550193c9df66dda95181d35b9dda106ecfd1718\",\"headSkips\":10,\"headTests\":2390,\"main\":\"e367e89463b86ebc1b1e20563d677bdfe6694060\"},\"previousClosure\":{\"ci\":34251687066,\"ciLog\":\"6268868625dabb7b2bc3d56e09e3efed816304fb5d7b581ff0780c300fffdd1a\",\"closureSha256\":\"4356446c8889fc17c798454ad9796266c5e1c3787c4efaa151b2affbbbb3ae9c\",\"commands\":8,\"localExactMainLog\":\"37af0b10ea88389bffd6fa15027678866a3b195ffb5acd6eec63d90ceedd2e4b\",\"localHeadLog\":\"8b3207ecb3015f5b45764d8c4eefde87270035a8f156fae97caea13573d7ca96\",\"main\":\"0aa3ef3027f4a156d7ebed1b56af244e021d080a\",\"packet\":\"CONF-FIX-004\",\"pr\":10,\"skips\":0,\"tests\":305,\"timeoutChangeAuthorized\":false,\"timingStability\":\"UNRESOLVED\",\"tree\":\"332d823a750828cfa345cf9332a2a251d6503d15\"},\"protectedFiles\":{\".github/workflows/verify.yml\":\"b6b8c87fc5f9615c193594c7a861a59e55022acfdb1dc9970c903af9fca22dee\",\"AGENTS.md\":\"b797986ce9d311ebafd946cbe0dface3ee4fa9f4bb6891bad53c96036f6c6694\",\"BILLING_POLICY.md\":\"a6cc00dd61373ba9b062174862f4232f19df7bf6790115c2fc9d189719ce87fd\",\"Makefile\":\"c12c2ec279c033f91fd0ccee94df05090e012eb592485b3398ebc58e8c062afa\",\"architecture/base-scope-sources.yaml\":\"38b19648432f8394f28a0115ffd11995f0d9843891f864af0c2dd6ac677dd2eb\",\"architecture/ci-performance-amendment.json\":\"2716be38eee78aefa1b3269a3a30659ae101794da25b9ee6ab30afefbbd19b38\",\"architecture/ci-performance-inputs/tests.before.json\":\"11fe1351bd83f0ccb36487897bbc8b8171c26c4074156e512288348a16c836c3\",\"architecture/custody-handoff-amendment.json\":\"81a95c9d1b84aae1ae71d7fa293931fc1118eacd2083051d353875e7b55e2180\",\"architecture/custody-handoff-inputs/baseline.json\":\"9053162f5249e75584c334fc6898444e6c7220b1cf116f8efb348a6658165ca6\",\"architecture/dependency-graph.yaml\":\"47986eff1832f2ed990bb9ceb2cd9aab574475df0bc20f2a39ac91c985cfd50f\",\"architecture/linux-readiness-amendment.json\":\"3a59552dbadd6a9e7579038523787926b921c35a3c71d036d2705b1c95b804a6\",\"architecture/linux-readiness.json\":\"2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762\",\"architecture/linux-test-ownership-amendment.json\":\"5aa1e79de247ebed7550b56db48266182941232d9036840beade99fbcf11172f\",\"architecture/live-backend-roadmap.json\":\"06d55fab0d0e56cbbdedab975fd4e2371f06896a6298e96c8c4e23c5e50916e7\",\"architecture/model-api-inventory-amendment.json\":\"7f298fdb1db878105d9925b5b07500f9cb6298f8b887d87d91edbc6210b48c7b\",\"architecture/model-api-inventory-inputs/CON-MODEL-001.before.yaml\":\"fff08209e76c2287c257a8d37a29aba159f82019e70f51d36bcaebf9d6805f33\",\"architecture/model-api-inventory-inputs/test_lifecycle_contracts.before.txt\":\"53f528db6e9d3ce00a8c16e8cf24345a992b2b6130cdfb7d5a6dee02dbaed81e\",\"architecture/model-evidence-boundary.json\":\"5be8de011a0cc4769b919ce0a416cb73d791c92181920abca7e8793abb788b48\",\"architecture/model-fixture-inputs/CON-MODEL-001.before.yaml\":\"807efc83ddd77e27e19d0e7d53811321c9b00c95972b53e78b263f385fd41d48\",\"architecture/model-fixture-inputs/test_generated_contracts.before.txt\":\"856b1d14e0f4d4ee84f6c4f973db412f9905559124091355bec7de85cc818080\",\"architecture/model-fixture-scope-amendment.json\":\"e46ea246e0ab64d7d6882822739b3029659138711f2bb426ea26fea064e08bd3\",\"architecture/observations/agent-hook-v2-tree.json\":\"0c94377f0ae6bf7ec7d70d521c411ff6883614cb2cebca2a1243cea1ce775339\",\"architecture/observations/data-harness-v1.json\":\"5c559a6ef3d59fa40e74ab2fb36603752751f523249da884f8e0d8daa06cfe10\",\"architecture/observations/model-usage-v2.json\":\"aa5488bad4528bd4119dfe9134f517403986b6fd45408f34c508929924e764f9\",\"architecture/observations/orchestra-openshift-reference-lab-tree.json\":\"c0cab3b3c294ab0db09f19215ad51f3ca5b09c71bb007fef2b894f7588d3f41b\",\"architecture/observations/planeon-orchestra-python-sdk-tree.json\":\"aa41c2d2b781e6776724367b3cf931d23b6812cc14ecb4a27c4f6c0b69ef61d7\",\"architecture/packet-scalar-amendment.json\":\"56b270f8d211f598cbf0183088430bd5ccc16e64eb089b865e117748c762b4e1\",\"architecture/packet-scalar-inputs/baseline.json\":\"d88c8f22877cf7269135ef53c08ff3a4921edb0946db0d9c9c1d38209256bfb6\",\"architecture/packet-scalar-inputs/run_packet.before.txt\":\"3128dd48c486d74c3a109eb0d6655c57033011d508afadce35756e485d94e83a\",\"architecture/packet-scalar-inputs/test_linux_inventory.before.txt\":\"1f5587f857927ca645e1c79edd4b4cd560f0eb70a881fb670b5047739421b7ef\",\"architecture/policy-observation-amendment.json\":\"0df7e72a65fc5eb1c20d59b8c62ebff377f160214192d681ea7f3d29b57e38c7\",\"architecture/policy-observation-inputs/channel.schema.json\":\"fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e\",\"architecture/policy-observation-inputs/vectors.json\":\"1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124\",\"architecture/porting-authorization-index.yaml\":\"a9768c8a75c2a9d3469271c60861c4ceb0b45cd3304d9c6be2dc1783ff1e7ec3\",\"architecture/providers.yaml\":\"9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02\",\"architecture/proxy-contract-amendment.json\":\"6c93e7db962cffa0281331c5220cdd8d5e453ab38ae39b4baa2e62be21a60600\",\"architecture/proxy-contract-inputs/baseline.json\":\"980ff63a57a6a167020f6d64297f946c92d7ce56b8c274b3fec56fb18bd837c1\",\"architecture/proxy-contract-inputs/profile.schema.json\":\"209349ccf44989566ffb39e2654fc91323b5eb2d9cbe895a4b18f33a349a226d\",\"architecture/proxy-contract-inputs/vectors.json\":\"edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7\",\"architecture/readiness-repair-amendment.json\":\"c3caa938557f1b9bb195188e35edc946fbdea36f0f1b235ab23f2689ffc54912\",\"architecture/readiness-repairs.json\":\"30db784918bb651cc81f26d23cb4b1d7f790ef260ef5e48a2d7ae2ae94c12a0d\",\"architecture/repositories.yaml\":\"02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d\",\"architecture/reuse-map.schema.json\":\"a9f2980e12679a7292fc394f1e53c437a4e60dc16ba22129c0cb66dce1b759a3\",\"architecture/reuse-map.yaml\":\"a4c612d46fbec6e098d3d48dfd1706a5529967207c04bef40f7900c0f269d741\",\"architecture/reuse-path-index.yaml\":\"4146194a2833840c02369725727d61bd9b2c626eca89b95280f49683647a25c1\",\"architecture/services.yaml\":\"857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6\",\"architecture/successor-inventory-amendment.json\":\"d6bd95af8bc7dd3d497907df58cc843a1732dc12e74a401692e47449444c349d\",\"architecture/successor-inventory-inputs/baseline.json\":\"f84ab0aeac644670b6a36ca52af1493af29bfacc8f04c4602a9e650dfca0c645\",\"architecture/successor-inventory-inputs/live_launcher.before.txt\":\"0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27\",\"architecture/successor-inventory-inputs/test_packet_scalars.before.txt\":\"c340e47f5eb8286e2e76ae5b38dc0bed6073701de44859b3356aed4c708f42e8\",\"architecture/taxonomy.yaml\":\"3d77bad7f84ff2f6a203fa074dce8ceaabf8e471711a8249daa53d8cf3f0fa24\",\"ci/linux-runner/build.py\":\"bfef77f1bdfae16e596a12fe9d3136ec6ba325468ffb0662a6e1a7bdafe51331\",\"ci/linux-runner/common.py\":\"cd1e468d4ce3f6e9760f2169d873b42ecc409c9ea3dac4945c9615cd8b4a3946\",\"ci/linux-runner/ed25519.py\":\"6ca5eb106c6567feb28ec1dbd5d988cec1d15b838c192306c2fc74357ea851c9\",\"ci/linux-runner/launcher.py\":\"e1f2e0166c82e01c6eedeec542584d8d0d4bb27c3f2eaf5e5e2298b7d53d1861\",\"ci/linux-runner/preflight.py\":\"636a1df537125b72d0396963dc848281d359c2fd6806712aaf4848599a9184cc\",\"ci/linux-runner/prepare.py\":\"5dc2158b69e9f7623f613e7015c97deb5c7184c7ba48554b0f5230ab2582bb04\",\"ci/lock_warm_snapshot.py\":\"d7e3d7507300ed21b011021f4323cefb85563add57fb40d3a7b16337e6bbd67f\",\"ci/measure_yaml_parsing.py\":\"2adf3490b7f54bf8bca5ae20e1f0ea1819830c635cdf5d0ca06f42e07061f0b3\",\"ci/network_canary.py\":\"1be4a837c4a5baee900db20007c4841361b8c823a1b5e521badcf28890d82099\",\"ci/prefetch.sh\":\"069a5eddb73a9b12f0620323b0638fa2b616fafe1210daa90484788815bd6785\",\"ci/run_packet_argv.py\":\"5a635f1694892354722afa14be103cf1c2efed70d6198fe163889eca3e211826\",\"ci/test_offline_runner.py\":\"46444c4218502f889f9d3e923c60604f6eff5434ab248a9cfc96976f38f06fcb\",\"ci/test_warm_snapshot.py\":\"929be52a3835a0b0d28d355fd4b4f85fc0e5e210502c3b6c62c2b24348fafa24\",\"ci/verify-offline.sh\":\"881a6f8c8bf7f5c01896578e960685545b8b7ec02e672808571836e73d132ae2\",\"ci/warm-source-isolation.sh\":\"f717f62fb1c9fdaec9eb594c733f25b17394bae6b90a311b9ccc08d4eaf9233b\",\"docs/alpha-2/CI_PERFORMANCE_REPAIR.md\":\"9ba4b315b96d45b070165529ab476b500ff2aa56e4ee2f9f5b678e9fe3d290cc\",\"docs/alpha-2/CUSTODY_HANDOFF_REPAIR.md\":\"0a095725bf71fb26ab8500391c1c214fef63f124b7a29ec171a552d0a211b025\",\"docs/alpha-2/POLICY_OBSERVATION_READINESS.md\":\"65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c\",\"docs/alpha-2/PROXY_CONTRACT_READINESS.md\":\"3e3bf310ebd8a7b1aed696ed9b8d4d26cb67160aab3f862877e2b2a2e0c9f3d0\",\"legal/source-reuse-authorization.yaml\":\"15db98cbaef76c942f7bd230c245f506653311b9cfec4596255b5770eb6e45fa\",\"legal/third-party-license-policy.yaml\":\"fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0\",\"policies/zero-bill-policy.yaml\":\"77c1385d014db8562be215f03a806deafb66e38c6e7faed9167f53299dadd43e\",\"pyproject.toml\":\"3876fa86bb79bb1951b017527a83278491c21ce9f1e017e38a0558f00b89ed2b\",\"release/evidence-policy.yaml\":\"ead30b57628a7479152c94f6a9496d90ec9d60701d7214cfcf3e36765dbda069\",\"release/fixture-release-set.yaml\":\"7597ebe4754a501de67dc2ee620dba4a8413e8b87761437d562194bac595b2f9\",\"release/repos.lock.json\":\"6067ca5e86c759c3efd914b037243e82577b40448d084df339b0abbf0d2999c4\",\"requirements.lock\":\"f78e95f80f5cd159802ab08b997121af14810513c4b34d08588ee34382e137b7\",\"schemas/dependency-graph.schema.json\":\"9c6f18bcc26e2b574297ba3e50d2e440f67f9bb78b3b5b7cfffa179c7141c870\",\"schemas/live-campaign-execution-envelope.schema.json\":\"ee5ce21417760c941b70b03fc7d48c6462104268f374a424f4cd01f7ed5ca6ee\",\"schemas/porting-authorization.schema.json\":\"1c5675728c9c13fde47d644b654bdff9eebe19d9210a5987832c8ef6224c9d56\",\"schemas/porting-record.schema.json\":\"492c510f1ddf1080eb8a59c4a7478518f035f6c5b0a466de5f95e5ae3fd8107b\",\"schemas/provider-module.schema.json\":\"f177ca68e4c3e62b5b4c8a8bd909589e755b722478ce341d4781169cf8730b9d\",\"schemas/release-set.schema.json\":\"f8efb2cf71f272eaf51ee962401fdc2c608342beb6f266f3cc8d14a031ee777b\",\"schemas/repositories.schema.json\":\"8b1841a75925c2b059909424656cf85d20691c50d5585da5b9ae7e5971271f27\",\"schemas/reuse-path-index.schema.json\":\"237169f0e8e65f557133e1c484e6bee602c7b1119935b0be8dbbdd575446d0d3\",\"schemas/services.schema.json\":\"7aa4eedb210650120496ea5858cbde3067dfa7d9c3b5b54bf39e3655f4010f0a\",\"schemas/task-packet.schema.json\":\"1e6d75398fb6571a1fd752b1ed597d0465c4031f9271bdda27a3075c88fb39f0\",\"schemas/taxonomy.schema.json\":\"b952d10ef9eb52012c3aabb58648b86f28600e006089b6685a2be2474964022d\",\"schemas/trusted-runner-manifest.schema.json\":\"157ad117269e9244b143c8bc6a80e1faf34678c1b538adb92b2e55444189d480\",\"scripts/check_release_lock.py\":\"50fd3de0bd75e088a8ef5e1b6af68577e64380409818b147da13c28db85bfc03\",\"scripts/safe_yaml.py\":\"99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7\",\"scripts/zero_bill_scan.py\":\"57fa7e94bf5657f0daf959d5229dfc2a53a0ab94793d1d5fa03a7513b1272fd7\",\"task-packets/CON-001.yaml\":\"88383a2c8bc66c959df0abc8bc1c8d86a852cac654cd1833327f8b06e2cf41b4\",\"task-packets/CON-002.yaml\":\"1e266163e2990ca7412338e878cb6b41e8a769abc27802083c352d1fc7e6da20\",\"task-packets/CON-003.yaml\":\"f54c40fba3c9ef2889851981e93f282ff069c4c40de222a18005d57241b7bb1a\",\"task-packets/CON-004.yaml\":\"1613ae0d5f5f113d0208f811f36c998168094109b96d68f8e7c31798e62733a3\",\"task-packets/CON-005.yaml\":\"1e5c7ac03625c08a7ff46b133e2b7689e5ef43de4782a5948f5f63823bcca4d6\",\"task-packets/CON-006.yaml\":\"e05a3f0c7c9c51857ae8afa774cad5fcb75483bcca49f44da54375327fdafec0\",\"task-packets/CON-007.yaml\":\"b5ab9498ff950345c0198a7a54fd3d62052f13a978f5113c69900f199dfb38ea\",\"task-packets/CON-FIX-001.yaml\":\"15040a4811277880118d58121a7d23721d8a91b4ab6d3211f960189d6a351a14\",\"task-packets/CON-MODEL-001.yaml\":\"d5f7ccf98a8dfa8862c204bd9be99cbfbc2307b98be00f0112f6e9dcb59abd9e\",\"task-packets/CONF-001.yaml\":\"2ad6741244eb83c152b0880ffb3518b10a02d5cc65bf2e1012b879866069de48\",\"task-packets/CONF-002.yaml\":\"7130dfaa116bcadd99cb29506be8cda8864643bb26b9216f7466c5e9085ebaab\",\"task-packets/CONF-A1-001.yaml\":\"c076b578b6655c70b7ca7309d3a5b43e9e5cad79138b44c89025ab6e6b20b1b4\",\"task-packets/CONF-A2-001.yaml\":\"574e85c20d97db27fa23ede3f5d7ebf043ff7980e237d21623aa05b331852bd8\",\"task-packets/CONF-A3-001.yaml\":\"70c53e57e6d140bf088993e0db0a7e6da1a2cdda5f0810eb89dbe3215c2ea624\",\"task-packets/CONF-AIR-001.yaml\":\"f6c08f690d1588db15b939beb0b86c5ecce40b19b33cea1db04413c2ecb8a666\",\"task-packets/CONF-FIX-001.yaml\":\"b02d7c6f2872c61fbde5be10451ac8de08e8336ee032e85b468e40dfaf8790ac\",\"task-packets/CONF-FIX-002.yaml\":\"c8639e527496660b8211f5bdcdb8f7470129b7d00f938c061d34630c797d8af4\",\"task-packets/CONF-FIX-003.yaml\":\"19089018ab6b1e2dada65d1dc3715940037b0881c1db02217622455a8a91d5a1\",\"task-packets/CONF-FIX-004.yaml\":\"6a41b419c4e5b02311e148b846d339216f1b512cf8025ae75de77e72ea3d8db0\",\"task-packets/CONF-K3S-001.yaml\":\"6178307a2845df6a369d666fec60653b167bfbb9b5086e8dbd58217d33229dc5\",\"task-packets/CONF-K8S-001.yaml\":\"6626cd491cf266209e77b9f90c66cabc8c1fc36195ef87ea6278fa5c07db5056\",\"task-packets/CONF-LINUX-001.yaml\":\"22f00544680f90a90b03420632bebf192a8c687549b519770fca5f98dd5fd6c9\",\"task-packets/CONF-LIVE-001.yaml\":\"5c7ceb5094b1c5a29192b7bdea913b23f777698bd31224ca5d1958a793dba3b3\",\"task-packets/CONF-LIVE-002.yaml\":\"05a6f03d19a1e12fafe278e5ec72c8adc6304766697b8682bc8d63092d47427f\",\"task-packets/CONF-LIVE-003.yaml\":\"15d13434edf833d4803618a7aa73ccc5e93baa29596e08903e623dbee338bba5\",\"task-packets/CONF-LIVE-004.yaml\":\"3cb0e1f7d163d7a420fbf2134b7ca5a7c70174acfca8646c341be83e6c23ff23\",\"task-packets/CONF-LIVE-005.yaml\":\"b25b9a828907a25d46fea9ccce74d3f05f30cfb9623acd0b21e8dd359e1d9623\",\"task-packets/CONF-LIVE-006.yaml\":\"f95c277cffdfb622f45a1b4b91a5292d9d9a5bfabc8f9388b3899cbb20c5213d\",\"task-packets/CONF-OCP-001.yaml\":\"04e8bc10f8b9bf5e84b6d55fecd96985f991054d4ba0346cd7316667ecd93ee3\",\"task-packets/CONF-SEC-001.yaml\":\"39eeaa83876002f57e29fffac39847f5d058aea128f447558213baa70687abdd\",\"task-packets/CONF-UPG-001.yaml\":\"4c2cc8bdaae80a30f3a8492be724a8920b1ea6fb66dbce7383713ecdd24c2a42\",\"task-packets/CONF-WG-001.yaml\":\"cd0685d9cdf8a018f4465d5223d950a557e4d523320891cc5d907496111442cd\",\"task-packets/CTRL-001.yaml\":\"5e8d3d18a8245ccd985c77d8269b73333b510a2689a341edffd17dcfde77a8c3\",\"task-packets/CTRL-002.yaml\":\"d0045acba54f420d6543581eebca1ae88e78c516576e2e8c1399762761bdcf25\",\"task-packets/CTRL-003.yaml\":\"0bd59f60ae73a7e19c97f5d797cb8955f28a5f3a181326c5c4af8d57ed5d2bbe\",\"task-packets/CTRL-004.yaml\":\"425faffab20090282bd60b17ac7cfc7942eeaaef0c2ff046b77d9736d77968d4\",\"task-packets/CTRL-005.yaml\":\"da414f08217a1b60351a3c7da42784a4cb749c12520f2250f6526f17df72976f\",\"task-packets/CTRL-006.yaml\":\"5b9f6ba920cb6d6eb5c192dfc104851d395772c57347ca69bc68aec6328709d1\",\"task-packets/CTRL-007.yaml\":\"4a70eac5a350e7b48d2b8b180c02455a5953837050c57f46cd7dbafb86291822\",\"task-packets/CTRL-FIX-001.yaml\":\"f1084924fe765b8d905a3156448bea636aec111b71a93e4a842dfbcab563b401\",\"task-packets/CTRL-FIX-002.yaml\":\"621e7ba7ad0b8852cc7bc63e666c5ac25e92fe5a769481b491bb850f1eecdd97\",\"task-packets/CTRL-FIX-003.yaml\":\"42876f9ab5ab8c227920fe6eee3a913b72f6940a989a8d128d627fbfea43c48f\",\"task-packets/CTRL-INTEGRATE-001.yaml\":\"28441f4febf41c7228b516ca8f674785d28842aa6c3443f8fefebeb4a6e7de95\",\"task-packets/DIST-001.yaml\":\"8de07c6a51176005765ef44aa4613b4443f610350d452daadbeae271b46bf48d\",\"task-packets/DIST-002.yaml\":\"785b079851cbb207cbeb012adab16f9dbcbcd555eb49ec835147d77899d359a0\",\"task-packets/DIST-003.yaml\":\"47a2951fd7957b780352cd0300d5b98af101509f43293c4daeaeae7626b9b5eb\",\"task-packets/DIST-004.yaml\":\"f1ea5c7b9df565a3c28d3b7fd24cb4878fccfaa0e75cc9ef1f57171d56e60633\",\"task-packets/DIST-005.yaml\":\"1cf1826b8c69c2030112899344577e0c5ea761b528eb978655cb098b29434d4f\",\"task-packets/DIST-AIR-001.yaml\":\"7a16e99750dd6044d56194a815ab2182d09759e27dea1cf6669d6366276ccb20\",\"task-packets/DIST-FIX-001.yaml\":\"d65fd678adb17be1c6875eb0e8ca7e955d59e4df32bc263b20213f1de845c983\",\"task-packets/DIST-OCI-001.yaml\":\"7211a4874c3236df8b257e2d8889180493ab8a0ece0812ef01fcf38ae257158e\",\"task-packets/EXEC-001.yaml\":\"7a6a95f429315d157c8f2ee4bcfb63584bbfd2ae9dcfb26420adaf30fbf76108\",\"task-packets/EXEC-002.yaml\":\"a8eeb8d1a1c56c87329818c827d398a329356420fdc2dd0b9df8e8d23f4c76c5\",\"task-packets/EXEC-ML-001.yaml\":\"ce65bd9b74e405b4dbc153430d9a05b245ba904c2372adc3a406a5de88e9c969\",\"task-packets/EXEC-ORCH-001.yaml\":\"bab8ff0d2a85f22484c29011836c2458449755634bf27b3462199ef445354d75\",\"task-packets/EXEC-PROT-001.yaml\":\"8dda3de5062124d3c2080ab5eaf68dd3d9b73f5e0f9c4fe646ec9284263201c2\",\"task-packets/EXEC-SBX-001.yaml\":\"8fb5e9035117761d9cb0e66600e246103f08392f342ddff69143018c60bdb517\",\"task-packets/EXEC-SBX-002.yaml\":\"fdec3da0f03a4e3cff03c642317616554454fc4767afee8180c141128b04cf49\",\"task-packets/EXEC-TOOL-001.yaml\":\"c0d160591f0f5eed5f28ce0db0ff2c5f3a609beb3e253ed21a7caa354e83816d\",\"task-packets/IND-001.yaml\":\"3d5778712ed09558c4df4c881745785311ca4f3be5ba7df4556930dd131cf86f\",\"task-packets/IND-FIX-001.yaml\":\"0d3b1bf1a1b167275c5c7916a845c658f14e7fa69dc0383963ba4648c202145c\",\"task-packets/IND-WG-001.yaml\":\"2766279b611409c8c0bc376b1161d3508e2485fa72c109222e90ceb60b13611c\",\"task-packets/IND-WG-002.yaml\":\"78bd0d87b54b9987621c1c42d8363fcd73d67c46677fe354d9f39229778a10d9\",\"task-packets/IND-WG-003.yaml\":\"897dc36776c08f73c93019cbcbe841a0f1ad2710385b28141b05602b53e3882e\",\"task-packets/IND-WG-004.yaml\":\"20ed881b6010aa5b5bca07d85b92d49b053641e88b05884c61e6a1661902fb7f\",\"task-packets/IND-WG-005.yaml\":\"033db2dd187457a94a8a346baf6aa11bd07ad6ac25cfc3d4d315a60b2e78ae38\",\"task-packets/KN-001.yaml\":\"5e1790e09f99c70f41288fde9767447f8b655ec821f029d266aa9973301d81e2\",\"task-packets/KN-002.yaml\":\"96a61677ee41b973a9282f858c4f355d54afe4b2c5f47d6cc18aea2114226fb6\",\"task-packets/KN-DATA-001.yaml\":\"73422c32a67d78cbcb6e74447482022f3552b24fd8ca356da5da91c9c538e0d2\",\"task-packets/KN-DATA-002.yaml\":\"ddd3b5f0f21705eb1ea07103dc91b194703dea50935e0e37c9796101e3239e40\",\"task-packets/KN-DOM-001.yaml\":\"452fd1e14baa779023ca27511af9b9a8b4281ddc8dea51327b93e594700e9f56\",\"task-packets/KN-MEM-001.yaml\":\"4ab3568fdfd01d500f205a2c5976526639a775c21ec09b8cf99cfdcfaaff3483\",\"task-packets/KN-RET-001.yaml\":\"d417da2b27707a0b69590019e556f35cf6d6f737c37858c9099481323415a5b1\",\"task-packets/MET-001.yaml\":\"43af6889dcf50d3ee8370cd5e761acc1a9fd989a44538b4db84a62df21f67880\",\"task-packets/MET-002.yaml\":\"e93658d831f7dc2f1b228f03986117ca59af276fefe901e3802df117a2eb34c7\",\"task-packets/MET-003.yaml\":\"d0bf1bc8cb15c536433528bf7b30aa3713e5ae44cb809d749fe8f344bccf3eea\",\"task-packets/MET-004.yaml\":\"942bae46d9b7e8561f7a4474f465eb2397df7bbc48a34b90e8c91403f126012f\",\"task-packets/MET-005.yaml\":\"aee54bd4c5219eb9ab7a751fb4d42008a5e05abc3188b9484a1eee8a1f628cba\",\"task-packets/MET-A2-001.yaml\":\"fcee128a05f6e53e60461a53108bb652187ae7e67c1056a4f2dcb6fd6477b413\",\"task-packets/MET-LINUX-001.yaml\":\"b54b47708b13bf9c184345308466e6a23af159040aacdc62744d43135c8f5f04\",\"task-packets/MET-LINUX-002.yaml\":\"7e2efb3daad8e5152028cfd35ced7449cd145a51fd3573b4e71981d29a8ee787\",\"task-packets/MET-LIVE-001.yaml\":\"c37fa6eabc16e7a424b894c8b3863931a4fa6bb56baa20b75d447923bc38007c\",\"task-packets/MET-OBS-AH-001.yaml\":\"9a527e5343d99e679c850a1dd416de9c4ed19f100caec0d1872f1dfc1424001a\",\"task-packets/MET-OBS-MODEL-001.yaml\":\"7493f8f788f982df4cd6b32f3647c82f41b8989feee54fea8740fff5e61f1a9b\",\"task-packets/MET-OBS-OCP-001.yaml\":\"9028852eaa2ddc2f7dc3559e38ab4d83bc3c6598dab97d10fb80846ed17fe711\",\"task-packets/MET-OBS-SDK-001.yaml\":\"fe44c76c6160847435869accd0ec895ec0ff700bca3f7ec09843b535a0a21e95\",\"task-packets/MET-P0-001.yaml\":\"41d838c56aa88e5c60e4b6768d28d3b24073fc63955309c89a49315c641192dc\",\"task-packets/MET-P0-002.yaml\":\"6ffd3057b377f1d6c7fc47cae26472f010e83090b5c31d90cbb46c4e0a7d9611\",\"task-packets/MET-P0-FIX-001.yaml\":\"1845f579a807d30e2880d4aee46b52e849092b0374fbf59f4ca31f8e66d45194\",\"task-packets/MET-P0-FIX-002.yaml\":\"b12012d45b0b9f968816a21be7cc714491ba94fcb7ee1af348da9bcd520a6ef2\",\"task-packets/MET-P0-FIX-003.yaml\":\"bf18a928240f0e0991287564d193a45a2699efa9aeb949b31dc112815a83cef2\",\"task-packets/MET-P0-FIX-004.yaml\":\"c3614e7cace9d83299e70add53c6650c8668d156850f941904f64f871ad29807\",\"task-packets/MET-PERF-001.yaml\":\"761c004a56df4e626c6e984e8fe0e0e7d4cec2a87bdb57a5f4ae40430930256a\",\"task-packets/MET-REPAIR-001.yaml\":\"45ea3a94514ae1b7b06608fa4629603fbe3c908c726da66fa733ccaffcb03986\",\"task-packets/MET-REPAIR-002.yaml\":\"75cd79e37a9a3a2adc645e322d8b8b6f27abf546d52b6fb821c275dedf4078e4\",\"task-packets/MET-REPAIR-003.yaml\":\"6f07a6fe38f305ffc226999b19fedb5ec4082069c8d14dede36bd001e550abf1\",\"task-packets/MET-REPAIR-004.yaml\":\"3217293d977e25f0c6e7f6e6bb0134c27d840fd8769dc285494ecc7f351f6d94\",\"task-packets/MET-REPAIR-005.yaml\":\"680335751aab8ac403f73db751d67c0ba98fce09017d51eebd7fa36d7b9fb5d0\",\"task-packets/MET-REPAIR-006.yaml\":\"365207085a6bc661164660008d9248f1414a821898497851da9f17cba9366e92\",\"task-packets/MET-REPAIR-007.yaml\":\"e4bbc961a86663fd4e8f52a74524e335b579b75031c2fdc97ff3ed0b9714d756\",\"task-packets/MET-REPAIR-008.yaml\":\"3a25b0653760488a41575696cf722bccce76d51bd2653ca8f1ccdef162cfc476\",\"task-packets/MET-REPAIR-009.yaml\":\"15dc67a95231ca39755bd91ff5056e5cf5c1769340e09104ca0878715ce9bf97\",\"task-packets/MET-REPAIR-010.yaml\":\"735b5bd31ddb8ce72d7a08f50658e3d34e4953c780be5ea0e704aded2f86b488\",\"task-packets/MET-REPAIR-011.yaml\":\"68308a56b7d60b4083330f479868bf10b378a84c9d1cf25fcc1b055bf1444964\",\"task-packets/MODEL-001.yaml\":\"753847ad57b2247a281b23c8f7db1956da3ae5d33f32433b25e80d44585160c0\",\"task-packets/MODEL-002.yaml\":\"25ac59868a1805845ab244ee7ab08590dd72c928c6821bd22bc47eb1c5c819c5\",\"task-packets/MODEL-003.yaml\":\"25403133eb4bd1272f6719903832e4182d899c6c6d2613b9240ce417bd6af09f\",\"task-packets/MODEL-004.yaml\":\"2b7260bd8bc5bf06880be4d2a06adab877ec6b956d1fe7b4ed40a619dad34ab3\",\"task-packets/MODEL-LLAMACPP-001.yaml\":\"f151b3393cb61b9133f21488fb53f01117e0960078077b6439bdc612adda793d\",\"task-packets/MODEL-OLLAMA-001.yaml\":\"31fd06d3fab1227e42661af30e025c33deb51e49fcdf291ab443b6f80780d768\",\"task-packets/MODEL-VLLM-001.yaml\":\"681a93edcbead7333b8439e6ddc849bc7a4ee0b9008b8bbab60cd494cac00f4e\",\"task-packets/OP-001.yaml\":\"9a64698615c1c1fa8ef899b50495d5249bec0a877f0e7f7a92e9058ef196b07b\",\"task-packets/OP-002.yaml\":\"caeea13c1efffc147fd0ca2d4c270916ca12e61c2a7122962eff4b024d2bf2f4\",\"task-packets/OP-003.yaml\":\"86fd96fc4cf016331ebe1c8c95a5c0faba9b8155439f324c381991ea7b1eba1b\",\"task-packets/OP-004.yaml\":\"6b585f709a0f69283534e0fadbe90502bd335fc9754bb5c30b0624d26e3eb241\",\"task-packets/OP-005.yaml\":\"9529029015e992d5cfffc4d0c2bcfe88e579834b8e27aff31607fb550799f09d\",\"task-packets/OP-006.yaml\":\"fa376aee945c301717e12b79aa5c4ebd7869e6b924b6afabd3f184db32d1595e\",\"task-packets/OP-007.yaml\":\"f4508ad47659315581d551939576d2307aa0043de4b71eabf99878de126b2548\",\"task-packets/RUN-001.yaml\":\"4fa60ad4793d2268ccd5f84e0cbc4ce3d45340abf2ba824b30cc895b5a618457\",\"task-packets/RUN-002.yaml\":\"cbda98c7e8f70f404c2316fa50e09eb66d18778a82ae2d64a16d20451a03c67e\",\"task-packets/RUN-EXP-001.yaml\":\"2a134a3b0e344b18a35ef3b82f1d34aa74f79ef83ab0730cda2eb740bce4a541\",\"task-packets/RUN-GW-001.yaml\":\"3695dc7de22d757f70528d9f23d0c4b46865b70a22c5c15f4bd423590544069a\",\"task-packets/RUN-GW-002.yaml\":\"3745467874e1293eb93e8a32c36c50493568389d718b1e66650952352a733996\",\"task-packets/SDK-001.yaml\":\"737990fc853fd50c22d211f0ada320585b304fe116cab881581575a9a6dca941\",\"task-packets/SDK-002.yaml\":\"b791f5f514dec76ebfd37ea17c7b0ca024057fbe4ebc2443bcdf15e7ca18c151\",\"task-packets/SDK-003.yaml\":\"49b413cbd44e8fefdb20b7c817c676b0b95d671a25f07a11c47fb9276ab1a7b5\",\"task-packets/SDK-004.yaml\":\"8c24a6bc4429e29e97a64746d12de95d9b47bd7b3d48ca312d8c9a3aea8ec23a\",\"task-packets/SDK-005.yaml\":\"b6db3bd5595dcae7aeaea71a3a5ca49b4044abfbe13d687d8cb49c1013c45a7a\",\"task-packets/SDK-006.yaml\":\"dc7771e61400288b5b7e6c6b69b802430ededa03947bed2adaa5f6542a063edc\",\"task-packets/SDK-007.yaml\":\"054feee9dfc45e76959a7182e47672dc95fb68558d2f1f7d97445eada3566054\",\"task-packets/TRUST-001.yaml\":\"d4fec1372836a3c85458b1e489fabda0869cc38a8bc480a709dc94e0e5fb8b19\",\"task-packets/TRUST-002.yaml\":\"cf80bc33b5517177e00f2d9e8bddb92c41f1c59b18a0cc2f54688a693a4ac151\",\"task-packets/TRUST-003.yaml\":\"b0d1ccdb6a7545fbc58d8c32fa5e9835383608ba945ad948da06c8c6996af350\",\"task-packets/TRUST-EVAL-001.yaml\":\"c0f5eaa5e35ea34fff04eb49ae4b500b4dbcc01221e11ece6b95b845c376828c\",\"task-packets/TRUST-FIX-001.yaml\":\"68d753be5f9eb9edaaf696bb48ea7c40448c4205d2778a3172a62a5f5707cc6c\",\"task-packets/TRUST-FIX-002.yaml\":\"f74a5004b51b8b16aa7a9c01036ac76bb1b396ddc692cc5736233639ee314893\",\"task-packets/TRUST-GOV-001.yaml\":\"af7591bd4b20237ad54e942c65d4149540f4dca3d72b6478db6bb9e0afff3221\",\"task-packets/TRUST-OBS-001.yaml\":\"760c4a519ec39f1a4a9523eca563d4e22597b06c8b8929913a7953d0f30f0290\",\"task-packets/TRUST-REG-001.yaml\":\"83fc22106c0eeb31b032bd3f5820eb359855d5c928f9bf3be9cd7edf1563427e\",\"tests/fixtures/zero-bill/cases.yaml\":\"d0399b8c7f0baacdbc57f904caaefdc258a20e5977bc767076fcdf31f4c129f5\",\"tests/linux_runner/conftest.py\":\"414b64d997172139aa984294dbb9b9d136ac9197f8245580f6d8c05e84b3a0d4\",\"tests/linux_runner/test_authority.py\":\"1a29bb42ca3a6fda8281c6e9e9fa79266107b1e244510563950e69ff3aa7cf90\",\"tests/linux_runner/test_build_and_predecessors.py\":\"6990993b16abdd8b548e6edfba37e7c40ab6bdd10478a45ab029a3a06765c0c6\",\"tests/linux_runner/test_isolation.py\":\"e5f6b98874ace99fb27667264b44deb797f18e5fafbda392b70476184e91c9f9\",\"tests/linux_runner/test_manifest_gate.py\":\"3dcaa594833c855e2f5df621ae2786cb21e2d9aeeaae6833ca534f680a92098f\",\"tests/linux_runner/test_toolchain.py\":\"19333875ae259280b4d64ee3dfb1c37618362fd94e3086381e92b636680941bf\",\"tests/test_data_harness_v1_observation.py\":\"5404c7e707f159c4dbe5a279ca67bc47f9cc0da6839e49b8d9fdb6c254c9180f\",\"tests/test_live_campaign_envelope.py\":\"c86fba5f72c8285ced6ab6039d65f6cc0ab78d8f79aa571e11879b14fc5424fd\",\"tests/test_reference_observer.py\":\"1ee810ee459404ff6d74cf7ce4ed1d62c139db6264a848acb57dd257474781d1\",\"tests/test_repository_tree_observation.py\":\"555987fc9bc8d43400f9f7dcd5bc0a1e5a6bcc7c171097a8b1922c5487c37f8e\",\"tests/test_zero_bill.py\":\"0a3f0a4480afa0382737d52da976b7d72b7a2d79c9c5c22b2f8812caa33a2821\",\"uv.lock\":\"78b80f44219e09eb34b83812d01e870edc70af2c8d6eaaa08ae26a8f45a2a7a9\"},\"schemaVersion\":\"planeon.internal.credential-lifecycle-authority/v1\",\"sourceBaseline\":{\"beforePath\":\"architecture/credential-lifecycle-inputs/before.json\",\"commit\":\"0aa3ef3027f4a156d7ebed1b56af244e021d080a\",\"files\":127,\"originalCommit\":\"7205075d2f234b622dd61072803b754f1dffeb79\",\"originalPath\":\"architecture/proxy-contract-inputs/baseline.json\",\"originalTests\":279,\"path\":\"architecture/credential-lifecycle-inputs/checkpoint.json\",\"tests\":305,\"tree\":\"332d823a750828cfa345cf9332a2a251d6503d15\"}}")


def _credential_inputs():
    _, performance_history, _ = SUCCESSOR.performance_current(ROOT)
    doc = performance_history["docs/live-backend/linux-boundary.md"]
    marker = b"```harness-credential-source-proof\n"
    if doc.count(marker) != 1:
        raise ValueError("unique credential proof required")
    raw = doc.split(marker, 1)[1].split(b"\n```", 1)[0]
    proof = SUCCESSOR.parse(raw)
    if SUCCESSOR.canonical(proof) != raw:
        raise ValueError("canonical credential proof required")
    record = _credential_record()
    paths = set(record["change"]["sourceRegions"]) | set(record["change"]["testRegions"]) | {record["change"]["documentPath"]}
    after = {p: performance_history[p] for p in paths}  # exact validated 9df history, inert only
    validate, _ = _credential_oracle()
    if validate(after, proof, record, proof["before"].encode(), proof["checkpoint"].encode()):
        raise ValueError("actual credential correction is not the declared delta")
    historical = {p: raw.encode() for p, raw in SUCCESSOR.parse(proof["before"])["files"].items()}
    marker = b"```harness-custody-source-proof\n"
    historical_doc = historical[record["change"]["documentPath"]]
    if historical_doc.count(marker) != 1:
        raise ValueError("unique historical custody proof required")
    legacy_raw = historical_doc.split(marker, 1)[1].split(b"\n```", 1)[0]
    legacy = SUCCESSOR.parse(legacy_raw)
    old_validate, _, _ = _custody_oracle()
    if SUCCESSOR.canonical(legacy) != legacy_raw or old_validate(historical, legacy, _custody_record(), legacy["before"].encode()):
        raise ValueError("historical custody proof changed")
    return after, proof, record, SUCCESSOR.parse(proof["checkpoint"]), historical, legacy


def _credential_repository():
    # Current bytes plus exact predecessor/future composition, never filename
    # presence as a hash exemption. Stored snapshots remain inert data.
    after, proof, record, checkpoint, _, _ = _credential_inputs()
    rows, sources = SUCCESSOR.tracked_inventory(ROOT)
    hook = SUCCESSOR.RECORD["hook"]
    hook_proof = SUCCESSOR.parse_hook_proof(sources[hook["proofPath"]]) if hook["proofPath"] in sources else None
    result = SUCCESSOR.validate_composition(rows, sources[hook["path"]], {"performanceSources": sources, "hookProof": hook_proof})
    history_rows, history_sources, performance = SUCCESSOR.performance_history(rows, sources)
    history_comparisons = {r["path"]: r for r in history_rows}
    if result["stage"] < 2:
        raise ValueError("credential correction requires stage two or later")
    current = {r["path"]: r for r in rows}
    for path, expected in checkpoint["files"].items():
        raw = history_sources[path]
        digest, size, blob = expected["sha256"], expected["size"], expected["blob"]
        if path in after or path == hook["path"] and result["stage"] == 6:
            # Exact five-file proof or the independently checked final-hook
            # delta, not a permissive current-file hash exception.
            if path in after and raw != after[path]:
                raise ValueError("inventory and proof bytes differ")
            digest, size = "sha256:" + hashlib.sha256(raw).hexdigest(), len(raw)
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        observed = history_comparisons[path]
        if ((observed["mode"], observed["size"], "sha256:" + observed["sha256"])
                != (expected["mode"], size, digest)
                or "sha256:" + hashlib.sha256(raw).hexdigest() != digest
                or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != blob):
            raise ValueError("unapproved cumulative source bytes: " + path)
    _, ids = _credential_oracle()
    expected = deepcopy(checkpoint["tests"])
    if sum(map(len, expected.values())) != 305:
        raise ValueError("exact prior 305-ID checkpoint required")
    new_paths = {p for p in current if p not in checkpoint["files"]
                 and any(p.startswith(root + "/") for root in SUITE_ROOTS)
                 and p.rsplit("/", 1)[-1].startswith("test_") and p.endswith(".py")}
    for path in set(proof["tests"]) | new_paths:
        found = ids(sources[path])
        if not found or not set(expected.get(path, [])) <= set(found):
            raise ValueError("prior or new test identity lost")
        expected[path] = found
    # The historical oracle above never supplies current test collection.
    exact = {p: SUCCESSOR.performance_ids(history_sources[p]) for p in SUCCESSOR.PERFORMANCE_PINS
             if p.startswith("tests/") and p.rsplit("/", 1)[-1].startswith("test_") and p.endswith(".py")}
    if sum(map(len, exact.values())) != SUCCESSOR.PERFORMANCE_TEST_COUNT:
        raise ValueError("exact historical 327 test identities required")
    test_path = SUCCESSOR.PERFORMANCE_TEST
    exact[test_path] = sorted(exact[test_path] + performance["newTestIds"])
    for path, methods in exact.items():
        if sorted(expected.get(path, [])) != methods:
            raise ValueError("all 327 old and exact new test identities required")
    observed = {}
    for root in SUITE_ROOTS:
        observed.update({root + "/" + p: methods for p, methods in isolated_inventory(ROOT / root).items()})
    if observed != expected:
        raise ValueError("fresh AST/discovery differs from exact cumulative test identities")
    return dict(stage=result["stage"], unchangedAtCorrection=122, priorTestCount=305,
                testCount=sum(map(len, observed.values())))


class CredentialSupervisorTests(unittest.TestCase):
    def test_post_io_expiry_cancel_and_policy_loss_never_accept_a_receipt(self):
        from test_linux_boundary import _credential_rig
        for failure in ("wall", "monotonic", "cancel", "policy"):
            with self.subTest(failure=failure), _credential_rig() as rig:
                rig.io_enabled = True
                handle = rig.open()
                resources = rig.owner._context._late_resources
                def after():
                    if failure == "wall":
                        rig.wall = END
                    elif failure == "monotonic":
                        rig.mono = 902
                    elif failure == "cancel":
                        rig.owner._boundary.interrupt()
                    else:
                        rig.policy_available = False
                rig.after_io = after
                with self.assertRaises(ConformanceError):
                    rig.owner.execute_fixed(handle, CASES[0], "amd64")
                self.assertIsNone(rig.owner._active)
                self.assertFalse(resources.io)
                self.assertFalse(resources.handles)
                self.assertIsNone(resources.raw)
                self.assertIn(replay_key(resources.context._binding), parse_journal(rig.journal.raw)[0])

    def test_close_errors_do_not_retry_recycled_fds_or_skip_other_cleanup(self):
        from test_linux_boundary import _credential_rig
        for failure in ("credential", "transport"):
            with self.subTest(failure=failure), _credential_rig() as rig:
                handle = rig.open()
                resources = rig.owner._context._late_resources
                if failure == "transport":
                    rig.io_enabled = True
                    rig.fs.fail_close = "/unit-transport-1"
                    with self.assertRaises(OSError):
                        rig.owner.execute_fixed(handle, CASES[0], "amd64")
                else:
                    rig.owner.execute_fixed(handle, CASES[0], "amd64")
                    rig.fs.fail_close = rig.credential_path
                    with self.assertRaises(OSError):
                        rig.owner.cancel(handle)
                self.assertFalse(resources.io)
                self.assertFalse(resources.handles)
                self.assertIsNone(rig.owner._active)
            self.assertFalse(rig.fs.fds)
            self.assertEqual(len(rig.fs.closes), len(set(rig.fs.closes)))

    def test_foreign_forked_thread_and_substituted_resource_owner_refuse(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            rig.owner.execute_fixed(handle, CASES[0], "amd64")
            resources = rig.owner._context._late_resources
            for attribute, foreign in (("owner", object()), ("pid", 43), ("thread", -1), ("scope", b"forged")):
                old = getattr(resources, attribute)
                setattr(resources, attribute, foreign)
                with self.subTest(attribute=attribute), self.assertRaises(ConformanceError):
                    rig.owner._boundary.check_peer()
                setattr(resources, attribute, old)
            resources.context._late_resources = object()
            with self.assertRaises((ConformanceError, AttributeError)):
                rig.owner._boundary.check_peer()
            resources.context._late_resources = resources
            self.assertEqual(len(rig.hook_calls), 1)

    def test_unknown_descriptor_during_fixed_hook_is_not_adopted_or_closed(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            extra = []
            rig.after_io = lambda: extra.append(rig.fs.kernel_fd("/unit-unlisted-credential-fd"))
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertIn(extra[0], rig.fs.fds)
            self.assertNotIn(extra[0], rig.fs.closes)
            rig.fs.close(extra[0])

    def test_duplicate_operation_and_late_direct_access_cannot_reuse_custody(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            resources = rig.owner._context._late_resources
            rig.owner.execute_fixed(handle, CASES[0], "amd64")
            before = list(rig.fs.opens)
            with self.assertRaises(ConformanceError):
                resources.credential_bytes()
            self.assertEqual(rig.fs.opens, before)
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertIsNone(rig.owner._active)

    def test_mid_read_expiry_stops_partial_acquisition_and_preserves_first_error(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            def expire(path):
                if path == rig.credential_path:
                    rig.wall = END
            rig.fs.after_read = expire
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertFalse(rig.hook_calls)
            self.assertFalse(rig.owner._context._late_resources.handles)


class CredentialSourceProofTests(unittest.TestCase):
    def test_actual_and_historical_source_proofs_are_independently_required(self):
        after, proof, record, checkpoint, historical, legacy = _credential_inputs()
        validate, _ = _credential_oracle()
        old_validate, _, _ = _custody_oracle()
        self.assertEqual(validate(after, proof, record, proof["before"].encode(), proof["checkpoint"].encode()), [])
        self.assertEqual(old_validate(historical, legacy, _custody_record(), legacy["before"].encode()), [])
        self.assertEqual((len(checkpoint["files"]), checkpoint["testCount"]), (127, 305))
        self.assertNotEqual(after, historical)

    def test_exact_five_paths_and_all_prior_and_added_methods_are_checked(self):
        result = _credential_repository()
        self.assertGreaterEqual(result["stage"], 2)
        self.assertEqual(result["priorTestCount"], 305)
        self.assertGreater(result["testCount"], 305)

    def test_changed_authority_snapshot_scope_and_current_bytes_fail_closed(self):
        after, proof, record, _, _, _ = _credential_inputs()
        validate, _ = _credential_oracle()
        for field, value in (("authorityDigest", "0" * 64), ("baseCommit", "0" * 40),
                             ("before", "{}"), ("checkpoint", "{}"), ("extra", True)):
            changed = deepcopy(proof)
            changed[field] = value
            with self.subTest(field=field):
                self.assertTrue(validate(after, changed, record, proof["before"].encode(), proof["checkpoint"].encode()))
        for path in after:
            changed = dict(after)
            changed[path] = b"# unreviewed substitution\n" + changed[path]
            with self.subTest(path=path):
                self.assertTrue(validate(changed, proof, record, proof["before"].encode(), proof["checkpoint"].encode()))

    def test_behavioral_test_rewrite_or_hidden_collection_cannot_fit_source_proof(self):
        after, proof, record, _, _, _ = _credential_inputs()
        validate, ids = _credential_oracle()
        for raw in (b"def load_tests(a, b, c):\n    return b\n", b"class X:\n    @unittest.skip('hidden')\n    def test_x(self):\n        pass\n"):
            with self.assertRaises(ValueError):
                ids(raw)
        changed = deepcopy(proof)
        changed["tests"]["tests/live_backend/test_supervisor.py"]["regions"]["SupervisorTests.test_all_ten_operations_complete_once_with_only_unsigned_unit_receipts"] = "    def test_all_ten_operations_complete_once_with_only_unsigned_unit_receipts(self):\n        pass\n"
        self.assertTrue(validate(after, changed, record, proof["before"].encode(), proof["checkpoint"].encode()))

    def test_current_inventory_rejects_unrelated_file_mutation_and_partial_future_stage(self):
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        changed = dict(sources)
        changed["README.md"] += b"\nunreviewed\n"
        with patch.object(SUCCESSOR, "tracked_inventory", return_value=(rows, changed)), self.assertRaises(ValueError):
            _credential_repository()
        extra = dict(path="src/harness_conformance/live_proxy_client.py", mode="100644", size=0,
                     sha256=hashlib.sha256(b"").hexdigest())
        with patch.object(SUCCESSOR, "tracked_inventory", return_value=(rows + [extra], sources)), self.assertRaises(ValueError):
            _credential_repository()


class CredentialCleanupTests(unittest.TestCase):
    def test_retained_credential_expires_before_the_outer_session_deadline(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            rig.owner.execute_fixed(handle, CASES[0], "amd64")
            rig.wall = "2026-09-07T01:10:00Z"
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[1], "amd64")
            self.assertEqual(len(rig.hook_calls), 1)
            self.assertIsNone(rig.owner._active)

    def test_io_failure_preserves_first_error_and_unproven_cleanup_never_claims_terminal(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            original = RuntimeError("unit first I/O error")
            def fail():
                rig.fs.fail_close = rig.credential_path
                raise original
            rig.after_io = fail
            with self.assertRaises(RuntimeError) as raised:
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertIs(raised.exception, original)
            self.assertIsNone(rig.owner._active)
            self.assertEqual(parse_journal(rig.journal.raw)[0][replay_key(context._binding)]["state"], "RUNNING")
            self.assertIsNotNone(context._late_resources.cleanup_failure)
        self.assertFalse(rig.fs.fds)

    def test_truthy_policy_return_value_is_not_an_observation_capability(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            rig.proxy._require_current_credential_policy = lambda *args: True
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            self.assertNotIn(rig.credential_path, [p for p, _, _ in rig.fs.opens])

    def test_recycled_socket_detaches_stale_owner_without_closing_foreign_fd(self):
        from test_linux_boundary import _credential_rig
        with _credential_rig() as rig:
            handle = rig.open()
            rig.io_enabled = True
            replaced = []
            def replace():
                row = rig.owner._context._late_resources.io["transport"]
                node = rig.fs.add("/unit-recycled-socket-fd", b"not-owned")
                replaced.append((row["fd"], row["socket"]))
                rig.fs.fds[row["fd"]] = ("/unit-recycled-socket-fd", node)
            rig.after_io = replace
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, CASES[0], "amd64")
            fd, sock = replaced[0]
            self.assertIsNone(sock.fd)
            self.assertIn(fd, rig.fs.fds)
            self.assertNotIn(fd, rig.fs.closes)
            self.assertIsNotNone(rig.owner._context._late_resources.cleanup_failure)
            rig.fs.close(fd)


# Complete fixed-workload observation and independent correctness regressions.
def _performance_reference_add(left, right):
    # Independently stated affine Edwards formula; never evaluates a snapshot.
    from harness_conformance.crypto import D, Q
    a, b = left
    c, d = right
    product = D * a * b * c * d % Q
    def reciprocal(value):
        reduced = value % Q
        return 0 if reduced == 0 else pow(reduced, -1, Q)
    return ((a * d + b * c) * reciprocal(1 + product) % Q,
            (b * d + a * c) * reciprocal(1 - product) % Q)


class PerformanceArithmeticTests(unittest.TestCase):
    def test_published_rfc8032_vectors_and_mutations(self):
        from harness_conformance import crypto
        # Public RFC8032 fixtures already present in accepted meta authority
        # tests/linux_runner/test_authority.py; no downloaded vector or service.
        vectors = (
            ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        )
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(crypto.public_key(seed).hex(), vectors[0][0])
        self.assertEqual(crypto.sign(seed, b"").hex(), vectors[0][2])
        for public, message, signature in vectors:
            pub, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
            with self.subTest(public=public):
                self.assertTrue(crypto.verify(pub, msg, sig))
                self.assertFalse(crypto.verify(pub, msg + b"!", sig))
                for index in (0, 31, 32, 63):
                    altered = bytearray(sig)
                    altered[index] ^= 1
                    self.assertFalse(crypto.verify(pub, msg, bytes(altered)))

    def test_independent_affine_points_extremes_and_unreduced_coordinates(self):
        from harness_conformance import crypto
        q = crypto.Q
        points = [crypto.IDENTITY, crypto.BASE, (0, 0), (q - 1, q - 1), (-1, -1),
                  (-crypto.BX, crypto.BY), (crypto.BX + q * 3, crypto.BY - q * 4), (2**512, -(2**511))]
        for left in points:
            for right in points:
                with self.subTest(left=left, right=right):
                    self.assertEqual(crypto._add(left, right), _performance_reference_add(left, right))
        point = crypto.IDENTITY
        for _ in range(8):
            expected = _performance_reference_add(point, crypto.BASE)
            point = crypto._add(point, crypto.BASE)
            self.assertEqual(point, expected)

    def test_both_zero_denominator_branches_preserve_total_integer_behavior(self):
        from harness_conformance import crypto
        inverse_d = pow(crypto.D, -1, crypto.Q)
        for sign in (-1, 1):
            left, right = (1, 1), (1, sign * inverse_d)
            result = crypto._add(left, right)
            self.assertEqual(result, _performance_reference_add(left, right))
            self.assertEqual(result[0 if sign == -1 else 1], 0)

    def test_scalar_extremes_match_independent_addition_reference(self):
        from harness_conformance import crypto
        for scalar in (0, 1, 2, 7, crypto.L - 1, crypto.L, crypto.L + 1, 2**255 - 1):
            point = crypto.IDENTITY
            # Left-to-right reference, independent of production's right-to-left loop.
            for bit in bin(scalar)[2:]:
                point = _performance_reference_add(point, point)
                if bit == "1":
                    point = _performance_reference_add(point, crypto.BASE)
            self.assertEqual(crypto._scalar_mult(scalar, crypto.BASE), point)

    def test_invalid_lengths_scalar_and_point_encodings_refuse(self):
        from harness_conformance import crypto
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        for length in (0, 1, 31, 33, 63, 65):
            self.assertFalse(crypto.verify(b"x" * length, b"", sig))
            self.assertFalse(crypto.verify(pub, b"", b"x" * length))
        for scalar in (crypto.L, crypto.L + 1, 2**256 - 1):
            self.assertFalse(crypto.verify(pub, b"", sig[:32] + scalar.to_bytes(32, "little")))
        for encoded in (crypto.Q, crypto.Q + 1, 2**255 - 1, 1, 1 + 2**255, 0):
            point = encoded.to_bytes(32, "little")
            self.assertFalse(crypto.verify(point, b"", sig))
            self.assertFalse(crypto.verify(pub, b"", point + sig[32:]))

    def test_canonical_payload_fields_remain_order_independent_and_domain_bound(self):
        from harness_conformance.crypto import signature_payload
        one = {"tenant": "fixture", "operation": "read", "signature": "ignored"}
        two = {"operation": "read", "signature": "different", "tenant": "fixture"}
        self.assertEqual(signature_payload("role-one", one, ("signature",)), signature_payload("role-one", two, ("signature",)))
        self.assertNotEqual(signature_payload("role-one", one, ("signature",)), signature_payload("role-two", two, ("signature",)))
        self.assertNotEqual(signature_payload("role-one", one, ()), signature_payload("role-one", two, ()))

    def test_fixed_three_sample_workload(self):
        import ast
        import cProfile
        import platform
        import sys
        import time
        from harness_conformance import crypto
        # One exact workload in both reference-only replay and full discovery.
        # No acceptance authority is inferred from this self-reported data.
        SUCCESSOR.performance_current(ROOT)
        source_path = "src/harness_conformance/crypto.py"
        test_path = "tests/live_backend/test_supervisor.py"
        source = SUCCESSOR.regular_bytes(ROOT, source_path)
        test_source = SUCCESSOR.regular_bytes(ROOT, test_path)
        tree = ast.parse(test_source)
        owners = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PerformanceArithmeticTests"]
        self.assertEqual(len(owners), 1)
        methods = [n for n in owners[0].body if isinstance(n, ast.FunctionDef) and n.name == "test_fixed_three_sample_workload"]
        self.assertEqual(len(methods), 1)
        node = methods[0]
        template = b"".join(test_source.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
        previous = sys.getprofile()
        if previous is not None:
            raise RuntimeError("existing observer: matched benchmark unavailable")
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        profile = cProfile.Profile(subcalls=False, builtins=True)
        samples, checksums = [], []
        started = time.perf_counter()
        try:
            profile.enable()
            for _ in range(3):
                results = []
                sample_start = time.perf_counter()
                for length in (0, 1, 32, 1024):
                    message = b"a" * length
                    for repetition in range(2):
                        public = crypto.public_key(seed)
                        signature = crypto.sign(seed, message)
                        valid = crypto.verify(public, message, signature)
                        tampered = crypto.verify(public, message + b"!", signature)
                        self.assertTrue(valid)
                        self.assertFalse(tampered)
                        self.assertEqual(public.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                        results.append([length, repetition, public.hex(), signature.hex(), valid, tampered])
                samples.append(time.perf_counter() - sample_start)
                checksums.append(hashlib.sha256(canonical_bytes(results)).hexdigest())
        finally:
            try:
                profile.disable()
            finally:
                sys.setprofile(previous)
        elapsed = time.perf_counter() - started
        self.assertEqual(checksums, ["bc73cd3ec5c69705dbde5bd15e2f9def320744d44e5b9e48985c59cdc384ba8b"] * 3)
        functions = []
        expected = {"_add", "_scalar_mult", "public_key", "sign", "verify", "builtins.pow"}
        for entry in profile.getstats():
            code = entry.code
            if isinstance(code, str):
                name = "builtins.pow" if code == "<built-in method builtins.pow>" else ""
            else:
                name = code.co_name if code.co_filename.endswith("harness_conformance/crypto.py") else ""
            if name in expected:
                functions.append(dict(function=name, calls=entry.callcount,
                    primitiveCalls=entry.callcount-entry.reccallcount, selfSeconds=entry.inlinetime,
                    cumulativeSeconds=entry.totaltime))
        self.assertEqual(sorted(row["function"] for row in functions), sorted(expected))
        SUCCESSOR.performance_current(ROOT)
        self.assertEqual(SUCCESSOR.regular_bytes(ROOT, source_path), source)
        self.assertEqual(SUCCESSOR.regular_bytes(ROOT, test_path), test_source)
        report = dict(schemaVersion="planeon.conformance-fixed-benchmark/v1", evidenceClass="OBSERVATION_DATA_ONLY",
            complete=True, scope="FIXED_WORKLOAD_ONLY", observerIdentity="cProfile.Profile(subcalls=False,builtins=True);default-timer;fixed-workload-v1",
            subcalls=False, builtins=True, timer="default", crossCallCache=False,
            sampleIdentity="rfc8032-seed1-a-lengths-0-1-32-1024-repetitions2-samples3-v1",
            warmColdDefinition="fresh process; imported module warm; no result cache; three consecutive full samples",
            interpreter=sys.version, platform=platform.platform(), sourceSha256=hashlib.sha256(source).hexdigest(),
            benchmarkSha256=hashlib.sha256(template).hexdigest(), recipeSha256="a3e6d70906d65058d1bd89bf12c8f07ab7f4544ac1b08859fa32d7d91630b999",
            samplesSeconds=samples, resultDigests=checksums, benchmarkWallSeconds=elapsed,
            functions=sorted(functions, key=lambda row: row["function"]))
        print("PERFORMANCE_BENCHMARK " + json.dumps(report, sort_keys=True, allow_nan=False), flush=True)


class PerformanceSourceProofTests(unittest.TestCase):
    def inputs(self):
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        historical, proof = SUCCESSOR.performance_proof(sources)
        return rows, sources, historical, proof

    def assemble(self, sources, historical, proof):
        changed = dict(sources)
        changed[SUCCESSOR.PERFORMANCE_DOC] = (historical[SUCCESSOR.PERFORMANCE_DOC] + proof["documentSuffix"].encode()
            + b"\n```harness-performance-source-proof\n" + SUCCESSOR.canonical(proof) + b"\n```\n")
        return changed

    def reseal(self, sources, historical, proof, outside=None):
        # Independent byte assembler: no call to the production reconstruction
        # or proof oracle. Resealing means source hashes, not credentials.
        import ast
        import re
        changed = dict(sources)
        for path, row in proof["sources"].items():
            original = proof["beforeSources"][path].encode()
            tree, lines = ast.parse(original), original.splitlines(keepends=True)
            replacements = []
            for name, replacement in row["regions"].items():
                nodes = tree.body
                for part in name.split("."):
                    found = [n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == part]
                    self.assertEqual(len(found), 1)
                    node = found[0]
                    nodes = node.body
                start, end = sum(map(len, lines[:node.lineno - 1])), sum(map(len, lines[:node.end_lineno]))
                replacements.append((start, end, replacement.encode()))
            current = original
            for start, end, replacement in sorted(replacements, reverse=True):
                current = current[:start] + replacement + current[end:]
            if row["constant"] is not None:
                current, count = re.subn(rb'^HELPER_SHA256 = "[0-9a-f]{64}"$',
                    ('HELPER_SHA256 = "' + row["constant"] + '"').encode(), current, flags=re.M)
                self.assertEqual(count, 1)
            current += row["append"].encode()
            if outside and path == outside[0]:
                self.assertEqual(current.count(outside[1]), 1)
                current = current.replace(outside[1], outside[2])
            changed[path] = current
            row["afterSha256"] = hashlib.sha256(current).hexdigest()
        return self.assemble(changed, historical, proof)

    def test_exact_checkpoint_scope_and_all_fresh_test_roots(self):
        rows, sources, historical, proof = self.inputs()
        self.assertEqual(len(historical), 8)
        self.assertEqual(SUCCESSOR.PERFORMANCE_TEST_COUNT, 327)
        history_rows, history_sources, found = SUCCESSOR.performance_history(rows, sources)
        self.assertEqual(found, proof)
        self.assertEqual(len(history_rows), len(rows))
        self.assertEqual(set(history_sources), set(sources))
        hook = SUCCESSOR.RECORD["hook"]
        hook_proof = SUCCESSOR.parse_hook_proof(sources[hook["proofPath"]]) if hook["proofPath"] in sources else None
        result = SUCCESSOR.validate_composition(rows, sources.get(hook["path"]),
            {"performanceSources": sources, "hookProof": hook_proof})
        stage = result["stage"]
        self.assertIn(stage, (2, 3, 4, 5, 6))
        self.assertEqual(len(rows), {2: 127, 3: 135, 4: 141, 5: 146, 6: 151}[stage])
        expected = {p: SUCCESSOR.performance_ids(history_sources[p]) for p in SUCCESSOR.PERFORMANCE_PINS
                    if p.startswith("tests/") and p.rsplit("/", 1)[-1].startswith("test_") and p.endswith(".py")}
        self.assertEqual(sum(map(len, expected.values())), 327)
        expected[SUCCESSOR.PERFORMANCE_TEST] = sorted(expected[SUCCESSOR.PERFORMANCE_TEST] + proof["newTestIds"])
        for successor in SUCCESSOR.RECORD["stages"][2:stage]:
            for path in successor["paths"]:
                if path.startswith("tests/") and path.rsplit("/", 1)[-1].startswith("test_") and path.endswith(".py"):
                    self.assertNotIn(path, expected)
                    expected[path] = sorted(SUCCESSOR.performance_ids(sources[path]))
                    self.assertTrue(expected[path])
        observed = {}
        for root in SUITE_ROOTS:
            observed.update({root + "/" + p: methods for p, methods in isolated_inventory(ROOT / root).items()})
        self.assertEqual(observed, expected)

    def test_unrelated_bytes_and_current_hashes_are_not_exempt(self):
        rows, sources, _, _ = self.inputs()
        for path in ("README.md", "src/harness_conformance/crypto.py", SUCCESSOR.PERFORMANCE_DOC):
            changed = dict(sources)
            changed[path] += b"\nunreviewed\n"
            changed_rows = [dict(row, size=len(changed[path]), sha256=hashlib.sha256(changed[path]).hexdigest())
                            if row["path"] == path else row for row in rows]
            with self.subTest(path=path), self.assertRaises(ValueError):
                SUCCESSOR.performance_history(changed_rows, changed)

    def test_proof_identity_scope_and_before_after_pins_are_closed(self):
        _, sources, historical, proof = self.inputs()
        for key, value in (("extra", True), ("authorityDigest", "0" * 64), ("baseCommit", "0" * 40),
                           ("packetId", "CONF-LIVE-003"), ("evidenceClass", "PASS"), ("sources", {}), ("beforeSources", {})):
            changed = deepcopy(proof)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                SUCCESSOR.performance_proof(self.assemble(sources, historical, changed))
        for path in proof["sources"]:
            changed = deepcopy(proof)
            changed["sources"][path]["afterSha256"] = "0" * 64
            with self.subTest(path=path), self.assertRaises(ValueError):
                SUCCESSOR.performance_proof(self.assemble(sources, historical, changed))

    def test_document_prefix_suffix_duplicate_keys_and_oversize_refuse(self):
        _, sources, historical, proof = self.inputs()
        path = SUCCESSOR.PERFORMANCE_DOC
        for document in (b"!" + sources[path][1:], sources[path] + b"!", sources[path] + sources[path],
                         sources[path].replace(b'"packetId":"CONF-PERF-004"', b'"packetId":"CONF-PERF-004","packetId":"CONF-PERF-004"'),
                         sources[path].replace(b'"newTestIds":', b'"newTestIds" :')):
            with self.assertRaises(ValueError):
                SUCCESSOR.performance_proof(dict(sources, **{path: document}))
        changed = deepcopy(proof)
        changed["documentSuffix"] = "x" * 65537
        with self.assertRaises(ValueError):
            SUCCESSOR.performance_proof(self.assemble(sources, historical, changed))

    def test_wrong_helper_pin_and_unknown_region_refuse(self):
        _, sources, historical, proof = self.inputs()
        for path in proof["sources"]:
            row = deepcopy(proof["sources"][path])
            row["regions"]["unknown"] = "def unknown():\n    return None\n"
            with self.subTest(path=path), self.assertRaises(ValueError):
                SUCCESSOR.performance_reconstruct(path, historical[path], row)
        changed = deepcopy(proof)
        changed["sources"]["tests/live_backend/_inventory.py"]["constant"] = "0" * 64
        resealed = self.reseal(sources, historical, changed)
        backend = "tests/live_backend/_inventory.py"
        self.assertEqual(hashlib.sha256(resealed[backend]).hexdigest(), changed["sources"][backend]["afterSha256"])
        with self.assertRaisesRegex(ValueError, "current helper pin"):
            SUCCESSOR.performance_proof(resealed)

    def test_missing_extra_duplicate_test_identity_refuse(self):
        _, sources, historical, proof = self.inputs()
        for ids in ([], proof["newTestIds"][:-1], proof["newTestIds"] + ["Extra.test_hidden"], proof["newTestIds"] * 2):
            changed = deepcopy(proof)
            changed["newTestIds"] = ids
            with self.assertRaises(ValueError):
                SUCCESSOR.performance_proof(self.assemble(sources, historical, changed))

    def test_collection_overrides_shadowing_and_oversize_append_refuse(self):
        _, sources, historical, proof = self.inputs()
        path = SUCCESSOR.PERFORMANCE_TEST
        for addition, reason in (
            ("\ndef load_tests(a, b, c):\n    return b\n", "collection override"),
            ("\ndef run():\n    pass\n", "collection override"),
            ("\nclass Omitted:\n    @unittest.skip('hidden')\n    def test_hidden(self):\n        pass\n", "omitted test"),
            ("\nclass Omitted:\n    @unittest.expectedFailure\n    def test_hidden(self):\n        pass\n", "omitted test"),
            ("\ndef _credential_inputs():\n    pass\n", "shadowed definition"),
            ("\n" * 131073, "bounded regions")):
            changed = deepcopy(proof)
            changed["sources"][path]["append"] += addition
            resealed = self.reseal(sources, historical, changed)
            self.assertEqual(hashlib.sha256(resealed[path]).hexdigest(), changed["sources"][path]["afterSha256"])
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                SUCCESSOR.performance_proof(resealed)

    def test_resealed_fixed_bridges_and_old_assertions_refuse(self):
        _, sources, historical, proof = self.inputs()
        for path in ("tests/platform/linux_baseline/test_packet_scalars.py",
                     "tests/platform/linux_baseline/test_successor_inventory.py"):
            changed = deepcopy(proof)
            name = next(iter(changed["sources"][path]["regions"]))
            changed["sources"][path]["regions"][name] += "        pass\n"
            resealed = self.reseal(sources, historical, changed)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "exact historical-consumer bridge"):
                SUCCESSOR.performance_proof(resealed)
        path = SUCCESSOR.PERFORMANCE_TEST
        name = "SupervisorPredecessorTests.test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable"
        changed = deepcopy(proof)
        region = changed["sources"][path]["regions"][name]
        self.assertEqual(region.count("(120, 216)"), 1)
        changed["sources"][path]["regions"][name] = region.replace("(120, 216)", "(120, 215)")
        resealed = self.reseal(sources, historical, changed)
        with self.assertRaisesRegex(ValueError, "old comparisons preserved"):
            SUCCESSOR.performance_proof(resealed)

    def test_resealed_outside_region_and_forged_before_refuse(self):
        _, sources, historical, proof = self.inputs()
        path = "src/harness_conformance/crypto.py"
        changed = deepcopy(proof)
        resealed = self.reseal(sources, historical, changed,
                              (path, b"Q = 2**255 - 19", b"Q = 2**255 - 20"))
        self.assertEqual(hashlib.sha256(resealed[path]).hexdigest(), changed["sources"][path]["afterSha256"])
        with self.assertRaisesRegex(ValueError, "after hash"):
            SUCCESSOR.performance_proof(resealed)
        changed = deepcopy(proof)
        changed["beforeSources"][path] += "\n# forged historical bytes\n"
        resealed = self.reseal(sources, historical, changed)
        self.assertEqual(hashlib.sha256(resealed[path]).hexdigest(), changed["sources"][path]["afterSha256"])
        with self.assertRaisesRegex(ValueError, "before pin"):
            SUCCESSOR.performance_proof(resealed)

    def test_mode_link_duplicate_partial_and_future_inventory_refuse(self):
        rows, sources, _, _ = self.inputs()
        for key, value in (("mode", "100755"), ("nlink", 2), ("linkedAncestry", True), ("kind", "symlink"), ("size", -1)):
            changed = deepcopy(rows)
            row = next(r for r in changed if r["path"] == "src/harness_conformance/crypto.py")
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                SUCCESSOR.performance_history(changed, sources)
        for changed in (rows[:-1], rows + [rows[0]]):
            with self.assertRaises(ValueError):
                SUCCESSOR.performance_history(changed, sources)
        path = "src/harness_conformance/live_proxy_client.py"
        extra = dict(path=path, mode="100644", size=0, sha256=hashlib.sha256(b"").hexdigest(), kind="file", nlink=1, linkedAncestry=False)
        with self.assertRaises(ValueError):
            SUCCESSOR.performance_history(rows + [extra], dict(sources, **{path: b""}))

    def test_regular_reader_rejects_symlink_hardlink_and_nonregular_sources(self):
        import os
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "target").write_bytes(b"fixture")
            (root / "link").symlink_to(root / "target")
            with self.assertRaises(ValueError):
                SUCCESSOR.regular_bytes(root, "link")
            os.link(root / "target", root / "hard")
            with self.assertRaises(ValueError):
                SUCCESSOR.regular_bytes(root, "hard")
            (root / "folder").mkdir()
            with self.assertRaises(ValueError):
                SUCCESSOR.regular_bytes(root, "folder")

    def _assert_new_bridge_mutations(self, method, changes):
        import ast
        _, sources, historical, proof = self.inputs()
        path = "tests/platform/linux_baseline/test_successor_inventory.py"
        name = "SuccessorInventoryTests." + method
        original = proof["sources"][path]["regions"][name]
        validation = "        _, historical_sources, _ = HELPER.performance_current(ROOT)\n"
        self.assertEqual(original.count(validation), 1)
        before = historical[path]
        old_class = next(n for n in ast.parse(before).body
                         if isinstance(n, ast.ClassDef) and n.name == "SuccessorInventoryTests")
        old_method = next(n for n in old_class.body
                          if isinstance(n, ast.FunctionDef) and n.name == method)
        old_lines = before.splitlines(keepends=True)
        historical_method = b"".join(old_lines[old_method.lineno - 1:old_method.end_lineno]).decode()
        variants = {"missing-current-validation": original.replace(validation, ""),
                    "extra-statement": original + "        pass\n",
                    "original-direct-reader": historical_method,
                    "wrong-method": original.replace("def " + method + "(", "def unauthorized_method(")}
        for fault, old, new in changes:
            self.assertEqual(original.count(old), 1, fault)
            variants[fault] = original.replace(old, new)
        for fault, replacement in variants.items():
            changed = deepcopy(proof)
            changed["sources"][path]["regions"][name] = replacement
            resealed = self.reseal(sources, historical, changed)
            self.assertEqual(hashlib.sha256(resealed[path]).hexdigest(), changed["sources"][path]["afterSha256"])
            with self.subTest(method=method, fault=fault), self.assertRaisesRegex(ValueError, "exact historical-consumer bridge"):
                SUCCESSOR.performance_proof(resealed)

    def test_current_scalar_hash_bridge_rejects_independently_resealed_mutations(self):
        self._assert_new_bridge_mutations("test_current_test_guard_not_exempt", (
            ("current-disk", "sha(historical_sources[path])", "sha((ROOT / path).read_bytes())"),
            ("expected-hash", "e1491e4407ff6d221871b45bbd775beb28afba11d418ae001847a512bb4b6fe6", "0" * 64),
            ("lost-stage", "range(7)", "range(6)"),
        ))

    def test_exact_scalar_patch_bridge_rejects_independently_resealed_mutations(self):
        self._assert_new_bridge_mutations("test_exact_scalar_test_patch", (
            ("current-disk", 'historical_sources[RECORD["change"]["path"]]', '(ROOT / RECORD["change"]["path"]).read_bytes()'),
            ("lost-hunk", 'len(RECORD["change"]["hunks"]), 3', 'len(RECORD["change"]["hunks"]), 2'),
            ("lost-id", "len(methods(after)), 30", "len(methods(after)), 29"),
            ("changed-oracle-operand", "HELPER.corrected_test(before)", 'HELPER.corrected_test(b"")'),
        ))

    def test_all_python_sources_and_four_current_before_historical_consumers_are_bound(self):
        import ast
        rows, sources, _, proof = self.inputs()
        _, historical_sources, _ = SUCCESSOR.performance_history(rows, sources)
        python_paths = {path for path in SUCCESSOR.PERFORMANCE_PINS if path.endswith(".py")}
        self.assertEqual(len(python_paths), 65)
        historical_ids = 0
        for path in sorted(python_paths):
            raw, pin = historical_sources[path], SUCCESSOR.PERFORMANCE_PINS[path]
            self.assertEqual(len(raw), pin["size"], path)
            self.assertEqual("sha256:" + hashlib.sha256(raw).hexdigest(), pin["sha256"], path)
            self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), pin["blob"], path)
            if path.startswith("tests/") and path.rsplit("/", 1)[-1].startswith("test_"):
                historical_ids += len(SUCCESSOR.performance_ids(raw))
        self.assertEqual(historical_ids, 327)
        fixed = [(path, name, replacement) for path, spec in SUCCESSOR.PERFORMANCE_SPECS.items()
                 for name, replacement in spec.get("fixedRegions", {}).items()]
        self.assertEqual(len(fixed), 4)
        for path, name, replacement in fixed:
            self.assertEqual(proof["sources"][path]["regions"][name], replacement)
            tree = ast.parse("\n".join(line[4:] if line else line for line in replacement.splitlines()))
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
            self.assertEqual(sum(isinstance(node.func, ast.Attribute) and node.func.attr == "performance_current"
                                 for node in calls), 1, name)
            self.assertFalse(any(isinstance(node.func, ast.Attribute) and node.func.attr in ("read_bytes", "read_text")
                                 for node in calls), name)

    def test_resealed_matched_benchmark_method_changes_refuse(self):
        _, sources, historical, proof = self.inputs()
        changed = deepcopy(proof)
        row = changed["sources"][SUCCESSOR.PERFORMANCE_TEST]
        before = 'recipeSha256="a3e6d70906d65058d1bd89bf12c8f07ab7f4544ac1b08859fa32d7d91630b999"'
        # The literal also occurs in this negative fixture; edit only the method.
        start, end, _ = SUCCESSOR.performance_region(row["append"],
            "PerformanceArithmeticTests.test_fixed_three_sample_workload")
        method = row["append"][start:end]
        self.assertEqual(method.count(before), 1)
        row["append"] = row["append"][:start] + method.replace(before, 'recipeSha256="' + "0" * 64 + '"') + row["append"][end:]
        resealed = self.reseal(sources, historical, changed)
        with self.assertRaisesRegex(ValueError, "exact matched benchmark method"):
            SUCCESSOR.performance_proof(resealed)

    def test_resealed_full_module_observers_refuse(self):
        _, sources, historical, proof = self.inputs()
        for name in ("setUpModule", "tearDownModule", "_performance_finish_profile"):
            changed = deepcopy(proof)
            changed["sources"][SUCCESSOR.PERFORMANCE_TEST]["append"] += "\n\ndef " + name + "():\n    pass\n"
            resealed = self.reseal(sources, historical, changed)
            with self.subTest(observer=name), self.assertRaisesRegex(ValueError, "no full-module profiling overlay"):
                SUCCESSOR.performance_proof(resealed)

    def test_required_regression_cannot_be_replaced_by_another_identity(self):
        _, sources, historical, proof = self.inputs()
        changed = deepcopy(proof)
        old = "test_published_rfc8032_vectors_and_mutations"
        new = "test_unreviewed_replacement"
        row = changed["sources"][SUCCESSOR.PERFORMANCE_TEST]
        self.assertEqual(row["append"].count("def " + old + "("), 1)
        row["append"] = row["append"].replace("def " + old + "(", "def " + new + "(")
        changed["newTestIds"] = sorted(x.replace("PerformanceArithmeticTests." + old,
            "PerformanceArithmeticTests." + new) for x in changed["newTestIds"])
        resealed = self.reseal(sources, historical, changed)
        with self.assertRaisesRegex(ValueError, "required regression identities"):
            SUCCESSOR.performance_proof(resealed)

    def test_current_custody_is_fresh_on_every_call(self):
        from unittest.mock import patch
        rows, sources, _, _ = self.inputs()
        changed = dict(sources)
        changed["README.md"] += b"\nunreviewed\n"
        changed_rows = [dict(row, size=len(changed[row["path"]]),
            sha256=hashlib.sha256(changed[row["path"]]).hexdigest()) for row in rows]
        with patch.object(SUCCESSOR, "tracked_inventory", side_effect=[(rows, sources), (changed_rows, changed)]) as observed:
            SUCCESSOR.performance_current(ROOT)
            with self.assertRaisesRegex(ValueError, "accepted history"):
                SUCCESSOR.performance_current(ROOT)
            self.assertEqual(observed.call_count, 2)

    def test_benchmark_restores_observer_after_workload_exception(self):
        import sys
        from unittest.mock import patch
        from harness_conformance import crypto
        previous = sys.getprofile()
        self.assertIsNone(previous)
        case = PerformanceArithmeticTests("test_fixed_three_sample_workload")
        with patch.object(crypto, "public_key", side_effect=RuntimeError("fixture workload failure")):
            with self.assertRaisesRegex(RuntimeError, "fixture workload failure"):
                case.test_fixed_three_sample_workload()
        self.assertIs(sys.getprofile(), previous)

    def test_benchmark_refuses_ambient_observer_without_replacing_it(self):
        import sys
        previous = sys.getprofile()
        self.assertIsNone(previous)
        def observer(frame, event, arg):
            return None
        try:
            sys.setprofile(observer)
            case = PerformanceArithmeticTests("test_fixed_three_sample_workload")
            with self.assertRaisesRegex(RuntimeError, "existing observer"):
                case.test_fixed_three_sample_workload()
            self.assertIs(sys.getprofile(), observer)
        finally:
            sys.setprofile(previous)


# CONF-FIX-006: independent SOURCE_DATA_ONLY correction and regression boundary.
def _successor_correction_spec():
    return SUCCESSOR.parse("{\"afterMethod\":\"    def test_exact_checkpoint_scope_and_all_fresh_test_roots(self):\\n        rows, sources, historical, proof = self.inputs()\\n        self.assertEqual(len(historical), 8)\\n        self.assertEqual(SUCCESSOR.PERFORMANCE_TEST_COUNT, 327)\\n        history_rows, history_sources, found = SUCCESSOR.performance_history(rows, sources)\\n        self.assertEqual(found, proof)\\n        self.assertEqual(len(history_rows), len(rows))\\n        self.assertEqual(set(history_sources), set(sources))\\n        hook = SUCCESSOR.RECORD[\\\"hook\\\"]\\n        hook_proof = SUCCESSOR.parse_hook_proof(sources[hook[\\\"proofPath\\\"]]) if hook[\\\"proofPath\\\"] in sources else None\\n        result = SUCCESSOR.validate_composition(rows, sources.get(hook[\\\"path\\\"]),\\n            {\\\"performanceSources\\\": sources, \\\"hookProof\\\": hook_proof})\\n        stage = result[\\\"stage\\\"]\\n        self.assertIn(stage, (2, 3, 4, 5, 6))\\n        self.assertEqual(len(rows), {2: 127, 3: 135, 4: 141, 5: 146, 6: 151}[stage])\\n        expected = {p: SUCCESSOR.performance_ids(history_sources[p]) for p in SUCCESSOR.PERFORMANCE_PINS\\n                    if p.startswith(\\\"tests/\\\") and p.rsplit(\\\"/\\\", 1)[-1].startswith(\\\"test_\\\") and p.endswith(\\\".py\\\")}\\n        self.assertEqual(sum(map(len, expected.values())), 327)\\n        expected[SUCCESSOR.PERFORMANCE_TEST] = sorted(expected[SUCCESSOR.PERFORMANCE_TEST] + proof[\\\"newTestIds\\\"])\\n        for successor in SUCCESSOR.RECORD[\\\"stages\\\"][2:stage]:\\n            for path in successor[\\\"paths\\\"]:\\n                if path.startswith(\\\"tests/\\\") and path.rsplit(\\\"/\\\", 1)[-1].startswith(\\\"test_\\\") and path.endswith(\\\".py\\\"):\\n                    self.assertNotIn(path, expected)\\n                    expected[path] = sorted(SUCCESSOR.performance_ids(sources[path]))\\n                    self.assertTrue(expected[path])\\n        observed = {}\\n        for root in SUITE_ROOTS:\\n            observed.update({root + \\\"/\\\" + p: methods for p, methods in isolated_inventory(ROOT / root).items()})\\n        self.assertEqual(observed, expected)\\n\",\"authorityDigest\":\"cb0845f4fb906ce345a6490e46cfb1b6cb6b942fd917c260404143f9c8289d53\",\"beforeMethod\":\"    def test_exact_checkpoint_scope_and_all_fresh_test_roots(self):\\n        rows, sources, historical, proof = self.inputs()\\n        self.assertEqual(len(rows), 127)\\n        self.assertEqual(len(historical), 8)\\n        self.assertEqual(SUCCESSOR.PERFORMANCE_TEST_COUNT, 327)\\n        history_rows, history_sources, found = SUCCESSOR.performance_history(rows, sources)\\n        self.assertEqual(found, proof)\\n        self.assertEqual(len(history_rows), len(rows))\\n        self.assertEqual(set(history_sources), set(sources))\\n        expected = {p: SUCCESSOR.performance_ids(history_sources[p]) for p in SUCCESSOR.PERFORMANCE_PINS\\n                    if p.startswith(\\\"tests/\\\") and p.rsplit(\\\"/\\\", 1)[-1].startswith(\\\"test_\\\") and p.endswith(\\\".py\\\")}\\n        self.assertEqual(sum(map(len, expected.values())), 327)\\n        expected[SUCCESSOR.PERFORMANCE_TEST] = sorted(expected[SUCCESSOR.PERFORMANCE_TEST] + proof[\\\"newTestIds\\\"])\\n        observed = {}\\n        for root in SUITE_ROOTS:\\n            observed.update({root + \\\"/\\\" + p: methods for p, methods in isolated_inventory(ROOT / root).items()})\\n        self.assertEqual(observed, expected)\\n\",\"checkpoint\":{\"addedTests\":27,\"authorityMain\":\"2e882d0a4e8288c124bce0a7f9fef315d78c5147\",\"commit\":\"b7586c4b8315dc92051f0b5445b2a9a0204a97bf\",\"evidenceClass\":\"SOURCE_OFFLINE_CHECKPOINT_ONLY\",\"fileCount\":127,\"files\":{\".github/workflows/verify.yml\":{\"blob\":\"48af47e6d1ca5c5198d934c1dd10c3ba947c3192\",\"mode\":\"100644\",\"sha256\":\"sha256:91090dc69c12837e8b73eb41a868b3afca7dcb34b304c7b409ac716310ddd3a6\",\"size\":615},\".gitignore\":{\"blob\":\"d9d863a13c2bfc70183b59f43ddfa236f7fa7e34\",\"mode\":\"100644\",\"sha256\":\"sha256:0672c3d34147eb3a4b4aa4298d4d88f647d6d28aa22cffdb705508df11bda33a\",\"size\":158},\"AGENTS.md\":{\"blob\":\"3bef97c6f3d501a0b5528179880053f787147de2\",\"mode\":\"100644\",\"sha256\":\"sha256:0b8faaf320feae214a47000b924c9a9c717e73e6d220edf1d16f0ff14381e843\",\"size\":3064},\"CONTRIBUTING.md\":{\"blob\":\"21f949ba69f148982b99313a6fc319ed5caf3527\",\"mode\":\"100644\",\"sha256\":\"sha256:d947eeaf23f47ad60e26bb2e0f236f08a8bd74ca7f8e80d378248ef4477d5964\",\"size\":460},\"LICENSE\":{\"blob\":\"94f474d4d34ef439ac1bb0f1961d5cc9e9096c7e\",\"mode\":\"100644\",\"sha256\":\"sha256:2d3b806e6fd270f11819d0f797f721747adb0d497760e1b9053b6cd1fae4cf54\",\"size\":774},\"Makefile\":{\"blob\":\"729893b50ddf19f0be9a3024f435af789a283897\",\"mode\":\"100644\",\"sha256\":\"sha256:bb652db371113bab5d9d8924f0b10b1f85793c0cc84178d447ab1095f4e7b981\",\"size\":661},\"NOTICE\":{\"blob\":\"0c12f4d5afbb8d0b984d4e3b094735be11607cf5\",\"mode\":\"100644\",\"sha256\":\"sha256:a70fc36aa7b6f295c4a662b6443a0599c4c89e9b6e62feb29763967d79ce382f\",\"size\":169},\"PORTING.yaml\":{\"blob\":\"cdd098dabfe545c4f513a6821d32cb6da17ee047\",\"mode\":\"100644\",\"sha256\":\"sha256:69af26b731e28920bb4cc5dd25f6d1d1c18aa75308d75517d6a61f214fa238c4\",\"size\":253},\"README.md\":{\"blob\":\"f04615d13827a0412fa15e7f37f2ffea5c9e4a2d\",\"mode\":\"100644\",\"sha256\":\"sha256:652e3abc12e4cd6d405eb80018a7c29c68d7d3094c2858196d9b83ea7dd566ea\",\"size\":1228},\"SECURITY.md\":{\"blob\":\"5d25e68338f66ca93863af7783affebc252ecc9f\",\"mode\":\"100644\",\"sha256\":\"sha256:1b5594cb9074fb98aa77768df57aeab45c469b60337ba9662e71367b92aa9cc7\",\"size\":555},\"campaigns/alpha1/campaign.json\":{\"blob\":\"a68dd8467599be5349e9cbfb217a1930867ffc62\",\"mode\":\"100644\",\"sha256\":\"sha256:17ad9b40b5518e3432c926b5604073fb922df08be38055310dbc851d1a18cef6\",\"size\":702},\"campaigns/meta/campaign.json\":{\"blob\":\"dadfca33c5ed23ceb111cbeae6c5289a364fafe0\",\"mode\":\"100644\",\"sha256\":\"sha256:22091f996b03eae43f8d00da3ec08c85ad12aef2cbb7d0d4ca8b79df8b705386\",\"size\":2341},\"campaigns/parity/campaign.json\":{\"blob\":\"f5ae7920b55249d1c35a15dd167ce2bf94c8d653\",\"mode\":\"100644\",\"sha256\":\"sha256:cd2ce011470ffef7dc7a08a4fc994a81f3d2f58899276991e02efb1c431956f4\",\"size\":627},\"campaigns/platform/linux-baseline/campaign.json\":{\"blob\":\"47ccd6bce2df7569eb2a9e2620e918a10e3b4949\",\"mode\":\"100644\",\"sha256\":\"sha256:3f4da90f48f61e3ee99b002b969eecbffbe60ac65d650abc82cdc6052df9e50e\",\"size\":5429},\"ci/acceptance_package_contract.py\":{\"blob\":\"12e0ca1ddb11d6533ca5e30023c1afb660051c3f\",\"mode\":\"100644\",\"sha256\":\"sha256:e5872ce6a4af9ead7c1cf130e47ca028fb7dc85b63ef5801abae82151938df6d\",\"size\":1753},\"ci/build_live_launcher.py\":{\"blob\":\"f5e37e0a02494893c4d4db356892a2c3f1dd9585\",\"mode\":\"100644\",\"sha256\":\"sha256:873dba7a314405a6ff7c446ee4c0333e34c7cc3400c01141f2c8929dc58c35ad\",\"size\":2425},\"ci/network_canary.py\":{\"blob\":\"453da00b448d2514ac7070539444d7c55d19616c\",\"mode\":\"100644\",\"sha256\":\"sha256:8eb07e2c974fd4a5040869ef0eee43963826dc8b32f7dd93fa18a91931e56500\",\"size\":1499},\"ci/prefetch.py\":{\"blob\":\"b38fb5d15a9cf6df2891c1da368f4db4d505fc04\",\"mode\":\"100644\",\"sha256\":\"sha256:341e6e102b93e74a0e7b3688ad88faacf4fd23dad2d6100884039d1a207947a1\",\"size\":3824},\"ci/run_make_target.py\":{\"blob\":\"0e05e3879fbd2ad165adf2e7e54c4ec6d08052db\",\"mode\":\"100644\",\"sha256\":\"sha256:0a0f5c2d6305a1772848ba2e58b8c3d17321de3fe5fdc99377515e09c1138389\",\"size\":5807},\"ci/run_packet.py\":{\"blob\":\"795ef5590e292b3096bddb919c66857a110e7672\",\"mode\":\"100644\",\"sha256\":\"sha256:397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1\",\"size\":8302},\"ci/run_packet_argv.py\":{\"blob\":\"9b76420194a17a92ccff6fa6e18d2e8c80f31a9f\",\"mode\":\"100644\",\"sha256\":\"sha256:523bda5db30faba4c027332a40f36c36e1efdb7e5bd39b68045bcdf817f94fdd\",\"size\":226},\"ci/targets/conf-001.json\":{\"blob\":\"9082a2d49ba5dbe0cd8098274c597bee44da9d27\",\"mode\":\"100644\",\"sha256\":\"sha256:dc2d49619485436c5cf4540b60c5432e847f96433bc60aa3da88577ffa9887b7\",\"size\":692},\"ci/targets/conf-002.json\":{\"blob\":\"ef49a2be8314bb16ee456cff30bce9ced734bf97\",\"mode\":\"100644\",\"sha256\":\"sha256:0e2d0b28b83567cd5cf8fd46f30a377d255995af4450f4675ae08bf27fd757c1\",\"size\":339},\"ci/trust/live-runner-root.pub\":{\"blob\":\"e10a1ac95a5738f59b78c3f7aa999bed90d800a8\",\"mode\":\"100644\",\"sha256\":\"sha256:6b22a99cab70c60b7cc345962ae220e32b2dbc89c72b419c79a9c92ec5f6c012\",\"size\":82},\"ci/verify-live-campaign.py\":{\"blob\":\"6d666e9cc402ed99b91cbf170a1ffc11da369922\",\"mode\":\"100644\",\"sha256\":\"sha256:ed7fa0f9a5d933c257a93f9be9ac5a3321c0b2451aa31e0f698a6053e8f46004\",\"size\":630},\"ci/verify-offline.sh\":{\"blob\":\"6ceda876eb6e83d17c7ba48e962bc55bb81e905d\",\"mode\":\"100755\",\"sha256\":\"sha256:b058780b727d2e4c7b5f77d3c7f623a7dafdac621c5b505238297e2ea2524c47\",\"size\":912},\"ci/zero_bill.py\":{\"blob\":\"6715ef0f0a9b4a1215ff4fd411a13affd6c4a321\",\"mode\":\"100644\",\"sha256\":\"sha256:6e9c7f5aa2ea527a1b1d9472bbab164be4ba051f27dae90005695ff3f04cda14\",\"size\":2177},\"docs/live-backend/linux-boundary.md\":{\"blob\":\"dedd5b605924490057ae379a0692b8b008fa7b8b\",\"mode\":\"100644\",\"sha256\":\"sha256:010e2e8eed70822742dad16a11ba5373b229e34889dbd3b628ff22d45d6a0521\",\"size\":1597014},\"docs/live-backend/session.md\":{\"blob\":\"3261b634fe39c4cd6bac109db10169490388d9d4\",\"mode\":\"100644\",\"sha256\":\"sha256:41319d8f1a7fa9441fded7efe23c8254929cc5ea15d7d1f59c125e33b29fc767\",\"size\":10811},\"docs/parity.md\":{\"blob\":\"7a6e06eb12db130a3893360e5ef6bcb82d3e207f\",\"mode\":\"100644\",\"sha256\":\"sha256:70fb8b95ee95eb7219c3b9ed0eea4c00c280ecf93dba6765418fa559d92b8dc4\",\"size\":1083},\"docs/reports/alpha1-template.md\":{\"blob\":\"857b5db337b41b07a1be30b10faa1a674fe3ac26\",\"mode\":\"100644\",\"sha256\":\"sha256:70f572dc3d3fef6d45e14c93c09352aea9b7bbdad189cc5167e3d57628c933a9\",\"size\":2179},\"docs/reports/linux-baseline.md\":{\"blob\":\"8c20f40e9130f50e4a2e22488ca6f60671c72ba3\",\"mode\":\"100644\",\"sha256\":\"sha256:99096cc71b49d662cb3c1a71137724eb1748aa633a7a24c8b56fa4b467605919\",\"size\":10913},\"docs/reports/packet-scalar-repair.md\":{\"blob\":\"348af063b6acf6f4c4860e40bfa1b6e8e211a86b\",\"mode\":\"100644\",\"sha256\":\"sha256:d824ddb953d31f1a20e19951ef743611e1943f5b6b8d6fe4679721d3146e355a\",\"size\":6081},\"docs/reports/runner-boundary-repair.md\":{\"blob\":\"a3484dd5932307bf1cc1cbaab05a4e937841b943\",\"mode\":\"100644\",\"sha256\":\"sha256:e5700f158b640364f15565cbbea8dee7e86e88c045c8cde07cfaa8fe77a525bf\",\"size\":6595},\"docs/reports/successor-inventory-repair.md\":{\"blob\":\"55c4fbcec0f4412c4efe2143ba739f4fc3efdf33\",\"mode\":\"100644\",\"sha256\":\"sha256:c930632d1e8674d9516976a5d07d385ac6211ade937fd16b6b875607f8498ab2\",\"size\":7131},\"fixtures/alpha1/environment-unavailable.json\":{\"blob\":\"da2bbfff05610ac26d574a49436d22e508ace7d4\",\"mode\":\"100644\",\"sha256\":\"sha256:71ae29d6bafffc062dcaa358929cdc5224d29f415b6a3a327714f9013dca345d\",\"size\":244},\"fixtures/alpha1/journey.json\":{\"blob\":\"a1be9b330b42820803b572548d8a57edda7c95c0\",\"mode\":\"100644\",\"sha256\":\"sha256:0399a95811cafc48c8deae07b45fadb8082b3be99db838da8b09fbddc1614bd8\",\"size\":7677},\"fixtures/alpha1/overview.json\":{\"blob\":\"bafa30410741034579954865f92aaad13c977b9c\",\"mode\":\"100644\",\"sha256\":\"sha256:c840c2f0c8e3094cdaaa08a10ea57d859d969c24546c3a23107189e63d7b626b\",\"size\":12726},\"fixtures/environments/meta-complete.json\":{\"blob\":\"8fc90838acc3ee792146bd2251592d43882734d8\",\"mode\":\"100644\",\"sha256\":\"sha256:6ea4589266ff02ea3c42bf86d72ac5bca9c593203bf35177ecb7da4ab2df1cbe\",\"size\":225},\"fixtures/environments/meta-unavailable.json\":{\"blob\":\"acca65615c5f77cbb97cd2abed3b7e210e27330b\",\"mode\":\"100644\",\"sha256\":\"sha256:3bec392601ed731f34f00dd55c835986b758a501d54a1ac0213d1e85eb8e2838\",\"size\":207},\"fixtures/live-backend/baseline.json\":{\"blob\":\"10df51d5621ae3f4be5771a458750dded949bf2d\",\"mode\":\"100644\",\"sha256\":\"sha256:c3dd610a748e018c9e015668567fbea9820a050022dc33375912f8f4aaa51a00\",\"size\":174441},\"fixtures/live-backend/session-vectors.json\":{\"blob\":\"fd86c220345e46ec6cdf3a0bb9923a7b98a8e7de\",\"mode\":\"100644\",\"sha256\":\"sha256:4999510bbaba2ae4faed7b9afa6d17ba3bbecb733f40f7bf92c69a6d9313a3fd\",\"size\":2822},\"fixtures/platform/linux-baseline/environment-unavailable.json\":{\"blob\":\"e85351d42f4894aebb45d158aba7ce1e0c070d4a\",\"mode\":\"100644\",\"sha256\":\"sha256:c79b375f07694835f616b51243b92305b96f29088424673457582103078307aa\",\"size\":219},\"fixtures/platform/linux-baseline/predecessor-inventory.json\":{\"blob\":\"46236ffaaedffe326c703a88544e918671f1ede7\",\"mode\":\"100644\",\"sha256\":\"sha256:f47c088f150ce7c61a14707aad71c634001037fd423eb43ace3acb055be86a58\",\"size\":18630},\"fixtures/platform/linux-baseline/predecessor-sources.json\":{\"blob\":\"4470b6fef50a58f626792abe83caa99fd712baa4\",\"mode\":\"100644\",\"sha256\":\"sha256:3fb88e3358c25fb65369e73a3decf9fe111797b1f44b2cc1deeabea8c5d8defc\",\"size\":23010},\"fixtures/platform/linux-baseline/scalar-repair.json\":{\"blob\":\"1ce1e8efddb2bba302d93e624a01cf5bbe840a87\",\"mode\":\"100644\",\"sha256\":\"sha256:0e04f3878efd8196fc33aa47a80ecbf5a48e7df262f08b98030acfd4c565fd06\",\"size\":114585},\"fixtures/platform/linux-baseline/successor-inventory.json\":{\"blob\":\"b99530a2c6df2f32fa1618843103965cc9c03d2d\",\"mode\":\"100644\",\"sha256\":\"sha256:44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86\",\"size\":171701},\"parity/adapters/run_parity.py\":{\"blob\":\"d3de27cf2f33a1c74d746f12d5fb1cb7c3267e29\",\"mode\":\"100644\",\"sha256\":\"sha256:650c17312390ec0f4382dad3c9279be0bb50522374c7ec01a079d9a7db8eefac\",\"size\":4849},\"parity/adapters/validate_registry.py\":{\"blob\":\"8f59afa4c1e14d9cd1a2f6ed5bb8942f541c027a\",\"mode\":\"100644\",\"sha256\":\"sha256:14d00741194d4de4bd3e14adb2829b3612217b9185905220ff8d6c0be39c12d9\",\"size\":6185},\"parity/registry.yaml\":{\"blob\":\"1cad50d5d694df6dfc127b39025518601db54285\",\"mode\":\"100644\",\"sha256\":\"sha256:0fac00ae1575b5c86996d32f3a9f01a69f6d77743170df1ecf6aff7243569af5\",\"size\":5544},\"parity/vectors/data-batch-lineage.json\":{\"blob\":\"70c82ac4d21e439139f47ae7aa4ee22e22e3d9f0\",\"mode\":\"100644\",\"sha256\":\"sha256:67c46555d13dd0b48f2e7fe8cbad9f09da7708baf816527f32ea9e96eb264d2d\",\"size\":239},\"parity/vectors/data-connector-closed-discovery.json\":{\"blob\":\"34ec386fff24d08c70ff2ea3594c3830d953d0b0\",\"mode\":\"100644\",\"sha256\":\"sha256:86279c3564392e353ba8537c2cba9d11f4449fc140a02398a146fd6f73e47de0\",\"size\":240},\"parity/vectors/data-local-only-no-fallback.json\":{\"blob\":\"d1e3f2a65cc5aa39244e2f1511aa8eca21541c81\",\"mode\":\"100644\",\"sha256\":\"sha256:fe3698e550940e90f71d497d0e0024ad99dbc8026684e77ebecb666b1577904f\",\"size\":207},\"parity/vectors/model-route-fail-closed.json\":{\"blob\":\"3168f7be8c41152efe67924537d953a697002a56\",\"mode\":\"100644\",\"sha256\":\"sha256:6eb0342fea804721e30ed38657d44c1578d20b4f829b76a3215df635f504a5de\",\"size\":198},\"parity/vectors/model-upstream-bounded-retry.json\":{\"blob\":\"be842691179449079ecb52c87fbcea7b8f4305df\",\"mode\":\"100644\",\"sha256\":\"sha256:f0a3cdf305e1f63f0edd05e074373cf6f98f09063bed101a100a74b3b920e854\",\"size\":192},\"parity/vectors/model-usage-tenant-neutral.json\":{\"blob\":\"b596b1dc64bb2dca2128c9be1d7f74d65c19d06f\",\"mode\":\"100644\",\"sha256\":\"sha256:410f55e3e3453a19754c52cecb689349aba41a95b015aceca7d35ff2e4f9f1ce\",\"size\":299},\"parity/vectors/white-goods-foundation-boundary.json\":{\"blob\":\"1265779205f37c842941abb201b8bf253f6f128f\",\"mode\":\"100644\",\"sha256\":\"sha256:49f3a5a70f32c00cebc69594832300939942dc6b80f8a57d60f2c577e728ac2d\",\"size\":277},\"pyproject.toml\":{\"blob\":\"4b42959660c2d19e0190b5e5f885f826d84264e3\",\"mode\":\"100644\",\"sha256\":\"sha256:4180e069f0bfb7b38f99b367f9a6f29e914a61717bd0797343f3d2b99720409c\",\"size\":500},\"schemas/v1alpha1/campaign-release.schema.json\":{\"blob\":\"310a5b6506656a547bacdd071a44a481654749fa\",\"mode\":\"100644\",\"sha256\":\"sha256:50053c212b0e9a40dcf4e7dd4c155c8c3da6a81a77a82ae7f59aadc2d6d0cfa9\",\"size\":1189},\"schemas/v1alpha1/campaign-report.schema.json\":{\"blob\":\"3726b8f1298f85c5482ec5cf28a9d69512bd418b\",\"mode\":\"100644\",\"sha256\":\"sha256:3e775c55dbc5dff84fb5aab90525814ef03595a69583e8239640583cac7036a9\",\"size\":1073},\"schemas/v1alpha1/conformance-campaign.schema.json\":{\"blob\":\"a9102ed14316481f18bc0936493b56cd469eaafe\",\"mode\":\"100644\",\"sha256\":\"sha256:dd4fb4f5fda756613d5f69056460abdbd05b675dbddb4c9606bc9324321bb89f\",\"size\":10324},\"schemas/v1alpha1/conformance-trust-bundle.schema.json\":{\"blob\":\"25e5054c6fe449249419c76fded16a482bb339ba\",\"mode\":\"100644\",\"sha256\":\"sha256:587e9e4fcc48fa98cf316b73a3cccabd9713fa0cbae48067f5f43f181404c245\",\"size\":1151},\"schemas/v1alpha1/control-result.schema.json\":{\"blob\":\"fcccd2c59e23ee4cdd003d09afe14cd6e8068eae\",\"mode\":\"100644\",\"sha256\":\"sha256:2113a19ec9e077dcb7ab6f2c299c4756d09b0d1e3d3a32195d2103ff8d54e182\",\"size\":1056},\"schemas/v1alpha1/environment-intake.schema.json\":{\"blob\":\"b303695d6f954b95e218726db6d0fac6e519c8fd\",\"mode\":\"100644\",\"sha256\":\"sha256:b69ef4bda6fe209b0416ef1c250747a38179d4cef0cf9bc8c72b1f0de1e3d621\",\"size\":776},\"schemas/v1alpha1/linux-readiness-evidence.schema.json\":{\"blob\":\"7032d8ada2da1ab7bc46f329505656b9b98562de\",\"mode\":\"100644\",\"sha256\":\"sha256:8f4cf17273b097e39420b2394be43259c9bea30b684a58bcdc739c60b5059c0e\",\"size\":61742},\"schemas/v1alpha1/live-backend-session.schema.json\":{\"blob\":\"ac9fee798700c8f558674132897bc306293d802a\",\"mode\":\"100644\",\"sha256\":\"sha256:7c4ad7c69feb4e9e9f8509f2cdd6c1bcccbf8acb60711810c2e0df8ef7cb737d\",\"size\":2504},\"schemas/v1alpha1/live-campaign-execution-envelope.schema.json\":{\"blob\":\"0276cd0438895d8874ea076262a6bb9071bfd3c5\",\"mode\":\"100644\",\"sha256\":\"sha256:d4720d28fd0cfb8f4979f8d1bb808c5244c6e8121c4a97b0303cfed033c4d1fd\",\"size\":4272},\"schemas/v1alpha1/live-capacity-authorization.schema.json\":{\"blob\":\"4902a75d338b4242cf54642bc005b90cd40513a9\",\"mode\":\"100644\",\"sha256\":\"sha256:196cafdba0cc168b8dbab7cb02aeda003b1b0cb2f0ae8e9b233b883629949235\",\"size\":2177},\"schemas/v1alpha1/technical-evidence-bundle.schema.json\":{\"blob\":\"8c66a359cd84085b4729cf8bae263bb523494cec\",\"mode\":\"100644\",\"sha256\":\"sha256:0d1e7ad8413733c63b18bb0b658a93f541800c604b2f56c8842fe4ac7760d513\",\"size\":1524},\"schemas/v1alpha1/tenant-acceptance-candidate.schema.json\":{\"blob\":\"69c535c74b5dc71454fac60c066ac03c785ef75f\",\"mode\":\"100644\",\"sha256\":\"sha256:37c57329bb835d7aa091be9de41bcfaed9305b1e0359ec1289d114f31bbf426a\",\"size\":995},\"src/harness_conformance/__init__.py\":{\"blob\":\"7d8e8ae786e942135fae50701e31ac25d700869e\",\"mode\":\"100644\",\"sha256\":\"sha256:748cd4a32689b1856ef53f51793e3f85303a25658846bb9a6965440ceeed769f\",\"size\":236},\"src/harness_conformance/__main__.py\":{\"blob\":\"eb53e2f31b2f703ad32ef64b8a41faa3e7d18e08\",\"mode\":\"100644\",\"sha256\":\"sha256:935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d\",\"size\":48},\"src/harness_conformance/acceptance.py\":{\"blob\":\"85fba5611d427772e8f0a4a71aaed3f13824b8cb\",\"mode\":\"100644\",\"sha256\":\"sha256:81a562a983f1d662e78d95d7e3e29f070471b3e304c13bac5162e0b05108c933\",\"size\":2613},\"src/harness_conformance/build_backend.py\":{\"blob\":\"779090a50431f086f497e26319de9265d664666c\",\"mode\":\"100644\",\"sha256\":\"sha256:d7ed81b4e0ffd865093679ef51a033a7bc74024b20300b098520306a05243e99\",\"size\":2399},\"src/harness_conformance/campaign.py\":{\"blob\":\"c07495f1c0df2532a2e37bd80d01f93b9a027b04\",\"mode\":\"100644\",\"sha256\":\"sha256:da0a25fba8336f658948ab1018a9db5c518bcc52849bdfcf295058906a26272a\",\"size\":7026},\"src/harness_conformance/canonical.py\":{\"blob\":\"18ab1dd28aeea326c177748aa357e85d56df0086\",\"mode\":\"100644\",\"sha256\":\"sha256:eb16aee5dda8f512b78b637361f0a057c7e944cd1b9eb888c88182c867e7794d\",\"size\":5645},\"src/harness_conformance/cli.py\":{\"blob\":\"f78f09f9845fd187107d45c3b2ddeb859702b848\",\"mode\":\"100644\",\"sha256\":\"sha256:c6fe0356d835db4bb0ae43d2484ca107f32bbf9046ff04c1a5a5ab47703ce8c1\",\"size\":4482},\"src/harness_conformance/crypto.py\":{\"blob\":\"19e4c49aa220147e9f1294b5895b9b5a5b84abba\",\"mode\":\"100644\",\"sha256\":\"sha256:bf4cd892d5a7b0dd38bf38b88f72657821d7f21575fce450e60a5a13950c0ca9\",\"size\":5148},\"src/harness_conformance/errors.py\":{\"blob\":\"3c78aa2fd3f372fa45df8eba47c1958e70376ea8\",\"mode\":\"100644\",\"sha256\":\"sha256:c30216c02cfa449063b77ca922a3c7cd32e0c6a8010365e093d730e7bc37807a\",\"size\":308},\"src/harness_conformance/events.py\":{\"blob\":\"c5294e469638af15d9616a08594c99b3ca48ecd2\",\"mode\":\"100644\",\"sha256\":\"sha256:2cc8855e5fe02c9874e3653b5f094b4095eed483e2446ba32735ddc57c6b422a\",\"size\":2197},\"src/harness_conformance/evidence.py\":{\"blob\":\"cb5ac52a8cdab8f23cc3dee05d063c0eedada7cc\",\"mode\":\"100644\",\"sha256\":\"sha256:670a8c4f6b06caf8af7749b0fe5bf6210d746cd6a823430a387890add135b3e6\",\"size\":7683},\"src/harness_conformance/lifecycle.py\":{\"blob\":\"0e3874da1b086941ec6319386ecb379238e25f42\",\"mode\":\"100644\",\"sha256\":\"sha256:86c7f62bea77d963e087d2b244f8479a5a81bd1dac8ab5ec5579ad9b0a35f69c\",\"size\":1582},\"src/harness_conformance/linux_readiness.py\":{\"blob\":\"f0be4c7607bf66d993fe712bb6f2062787632d6c\",\"mode\":\"100644\",\"sha256\":\"sha256:1d40b52a05a85cf0d2179d5545bc8325b8035a24340c5a52b8b66f28e0476fc8\",\"size\":22629},\"src/harness_conformance/live.py\":{\"blob\":\"cf510b0a5e9623e21a431c9b061c26311035ce38\",\"mode\":\"100644\",\"sha256\":\"sha256:8f6d033292801930cd280f3611aed3c6012cf4d39ec63d4324eb92590e44a022\",\"size\":23002},\"src/harness_conformance/live_backend_authority.py\":{\"blob\":\"ecac59b706d8d8f0ec37c844d2fb91162d5adf16\",\"mode\":\"100644\",\"sha256\":\"sha256:b57f241e1c0c76be3d86682e9a1a1d62f40115aaa917d2e124d589c84880e42d\",\"size\":9916},\"src/harness_conformance/live_launcher.py\":{\"blob\":\"ad7ebd930586d383ce2b947a9c433c73f9b5baf6\",\"mode\":\"100644\",\"sha256\":\"sha256:0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27\",\"size\":5281},\"src/harness_conformance/live_linux_boundary.py\":{\"blob\":\"349ccc21d9d861461863bfabec362d2fe197badc\",\"mode\":\"100644\",\"sha256\":\"sha256:7c590b4078e4bd024c0798749f5d1e1197f9a30c15cc6d1a2b0d7b9131ae54fe\",\"size\":52544},\"src/harness_conformance/live_replay_store.py\":{\"blob\":\"84b054eab30e318552866076e5291dca842734d1\",\"mode\":\"100644\",\"sha256\":\"sha256:ff512b35ce7761b5dccc2c57989a6888b0daa9c99fba404f7be0be6878dae3f7\",\"size\":10076},\"src/harness_conformance/live_session.py\":{\"blob\":\"6a22fd233cfd52c357d03dfd60dc8cc1d563a1cc\",\"mode\":\"100644\",\"sha256\":\"sha256:dc15ebe6d919093cb1842c77c19c9e7846d7ef62e3b04946114824befa9e4454\",\"size\":12361},\"src/harness_conformance/live_supervisor.py\":{\"blob\":\"dd02d0e0c87044e3568f8521cb74d9fb14ea3c6f\",\"mode\":\"100644\",\"sha256\":\"sha256:4dfeb1780c5fc6b2e116f027fbbde6b8a0fec401911f11c4f45900e7ad84b03e\",\"size\":38977},\"src/harness_conformance/models.py\":{\"blob\":\"e2e1d24ec4822b86d10efb8c864281a81730518b\",\"mode\":\"100644\",\"sha256\":\"sha256:3d095046632c640bd679b730cc76c90276a73c18263de227ad8a5692c34730dc\",\"size\":1430},\"src/harness_conformance/registry.py\":{\"blob\":\"539cfbb0f1177dd9614f83e333e2a342a97fabf1\",\"mode\":\"100644\",\"sha256\":\"sha256:fa32c26a773a93d60c3f1cd512a99d1213258f944846e028bf7c92aca7049139\",\"size\":1595},\"src/harness_conformance/schema.py\":{\"blob\":\"51e9e4a9e38278771979bc89e612a0371312f4dc\",\"mode\":\"100644\",\"sha256\":\"sha256:cd3fefc33833cf5fbccb97a0ac75524ecd967cfa10064a79f64a837f75397ee5\",\"size\":9908},\"tests/alpha1/__init__.py\":{\"blob\":\"68a01f42298a8f26633b2142b6a0005197345c61\",\"mode\":\"100644\",\"sha256\":\"sha256:1c4b4913127e929661e104454b7900591e39681401eb19594436b1a860c49a6a\",\"size\":48},\"tests/alpha1/contract.py\":{\"blob\":\"cab06a287c4bb3af9b46d6aad540463494572429\",\"mode\":\"100644\",\"sha256\":\"sha256:20034c14d493cac5f730440b27833c5fa87722fda0a1574ce0f81836764749a7\",\"size\":16927},\"tests/alpha1/test_alpha1.py\":{\"blob\":\"27d0f87d11dd4db53c9b2ac0e96ff8c8e8ce08b7\",\"mode\":\"100644\",\"sha256\":\"sha256:b528290f311a5e41e2b163028bb5212a022d15319a7a9fb218fd7e272480e9c7\",\"size\":7371},\"tests/fixes/runner_boundary/_inventory.py\":{\"blob\":\"fdf58c985872348225fcf9706890349dcceb8a2c\",\"mode\":\"100644\",\"sha256\":\"sha256:fb50aba04fe963a89b74ad1aca57b1242fa54481e01989ac18a189a080ade94c\",\"size\":2443},\"tests/fixes/runner_boundary/legacy-tests.json\":{\"blob\":\"f0fd3094ae447ae25840d8a13d29d89fdaecbd26\",\"mode\":\"100644\",\"sha256\":\"sha256:9fff3fb6bd66789b18bc8f38885d2bfd287124f9a32b4f7a0d645c27ee500dbd\",\"size\":4603},\"tests/fixes/runner_boundary/test_boundaries.py\":{\"blob\":\"ee6aaffe5e7a8b067f5051208f9fb7080f192400\",\"mode\":\"100644\",\"sha256\":\"sha256:2e33efe165cf46912a426285dabd0bbe98b17acdf18f3d7a8bf3cb56a71247e4\",\"size\":15192},\"tests/fixes/runner_boundary/test_inventory.py\":{\"blob\":\"b32df3cf7b119502baa187661589145446fe317b\",\"mode\":\"100644\",\"sha256\":\"sha256:1fbacb25aea922a37fb552e91f6b95dded7c1774d1ba2a80f5989cd926cad5e6\",\"size\":3569},\"tests/live_backend/_fixtures.py\":{\"blob\":\"c304516fcc8700038748a535280f607dde9026ac\",\"mode\":\"100644\",\"sha256\":\"sha256:edec764c067e538fa9709dc7dce59a357ae996ba36c6121482cc3b24d86b8a28\",\"size\":3383},\"tests/live_backend/_inventory.py\":{\"blob\":\"47d5306bd5f6376618aa3418b09f3a79d6dfd76f\",\"mode\":\"100644\",\"sha256\":\"sha256:d341edcdf49dadf182c3fcc9926d373d13c83aa004d3cc74363312861a7f1e46\",\"size\":4839},\"tests/live_backend/test_inventory.py\":{\"blob\":\"aaa7c95f79868172637bb95a4118dff083cd573f\",\"mode\":\"100644\",\"sha256\":\"sha256:f128f05fc395c26de0c13c34953bfff297fa64f857f3f70aab56dbc9e3bcc8a1\",\"size\":10197},\"tests/live_backend/test_linux_boundary.py\":{\"blob\":\"012da5892daafbb7c92c09944d9f97a5e180fffa\",\"mode\":\"100644\",\"sha256\":\"sha256:06d16e4c833dc818a084b655b4f767dbe601212adc9525c47dc94241c32ee238\",\"size\":62720},\"tests/live_backend/test_replay_store.py\":{\"blob\":\"c905fc0bf1775c1a01c15e068c0a8ae5cc7f387a\",\"mode\":\"100644\",\"sha256\":\"sha256:492d6569edb1d271199a3d52b93e82f7295ae478d90b01376125313ee1af8213\",\"size\":9971},\"tests/live_backend/test_session.py\":{\"blob\":\"5970c237d3d60f5cbfa33ace88e7d37b0e885f34\",\"mode\":\"100644\",\"sha256\":\"sha256:4348b898c1d8cab9fbc94b7bfceff5442a21c0e49fc2645277ae706506c25e90\",\"size\":32978},\"tests/live_backend/test_supervisor.py\":{\"blob\":\"beea17c92944c00275b2454474a7ce4f2612735d\",\"mode\":\"100644\",\"sha256\":\"sha256:28129cc7c25c8815a4414d31c7348abecd02bf7f3e91550f68a93bd0e3fcada8\",\"size\":205702},\"tests/meta/test_build_cli.py\":{\"blob\":\"7b71afb1541acc77c25af4edd83e42807e9bad99\",\"mode\":\"100644\",\"sha256\":\"sha256:989c58c63a8cc5234e0396c4bee1c667da133c6893ca24dd96bd95822f43a4e6\",\"size\":2781},\"tests/meta/test_campaign.py\":{\"blob\":\"01bbbfb3a347dc97562597744c3940e11cd67185\",\"mode\":\"100644\",\"sha256\":\"sha256:85fc9c47556fa0db78ed1948cba696cea0da9d895848169785d227a6e66efc8d\",\"size\":3007},\"tests/meta/test_canonical_schema.py\":{\"blob\":\"e9f4e4ebab1d8ad8c4cbccd21f6f64684548faf1\",\"mode\":\"100644\",\"sha256\":\"sha256:f3c233226c5dc400f225eeb16bde754fd73b3e332a2cc85c7795571537845a35\",\"size\":3187},\"tests/meta/test_evidence_crypto.py\":{\"blob\":\"deb7af4af91219aa7a688e67bd66cfb856897ed7\",\"mode\":\"100644\",\"sha256\":\"sha256:b0b87f6e4f726ebc7af82be7ab9b6b83a73ec130e1559cb5d9800396b91436c4\",\"size\":4501},\"tests/meta/test_live.py\":{\"blob\":\"cd6f7ea911bd1fe55132723f30f9924b2dcdb63b\",\"mode\":\"100644\",\"sha256\":\"sha256:9ac39858b40468a10b2a20ae43e0aaa92f64fde6ab63d275143d654774ec10a3\",\"size\":11715},\"tests/meta/test_porting_zero_bill.py\":{\"blob\":\"eef6f33647b7ef061616939b1f8c5a03472e9aee\",\"mode\":\"100644\",\"sha256\":\"sha256:f8ed0fdffc245541d332d78c66d6e9045c3bfc85e0683c3cb7e87b263c1bd448\",\"size\":4182},\"tests/meta/test_registry_dispatch.py\":{\"blob\":\"c6283b1028a659c3d1ef48863280eb1c9a6349f8\",\"mode\":\"100644\",\"sha256\":\"sha256:b021ddeb2a7a534427edf7db594b0d9532711bec4fcfac76405dcded73adbc1d\",\"size\":3756},\"tests/parity/test_adapters.py\":{\"blob\":\"bac9d9424411a7441f721f31c10b6e92992f67d9\",\"mode\":\"100644\",\"sha256\":\"sha256:9e4217daee3c0e6f5f7dc0a292c4ff55cb1a3b7259b477ee65dfc13315e49c4a\",\"size\":2337},\"tests/parity/test_packet_runner.py\":{\"blob\":\"756551e665a844d2dcec790becb31a82c4a82cfd\",\"mode\":\"100644\",\"sha256\":\"sha256:0054ccd9312c59a77194a17152191a80bc82d98a5b27ee6e83183b2e62bf7d97\",\"size\":6066},\"tests/parity/test_registry.py\":{\"blob\":\"50e8fc23c9bbf139b0eed861817977157316c03a\",\"mode\":\"100644\",\"sha256\":\"sha256:88d007d59c2da7dc45fdb4da0d7787725ff6a4d6d120a7f38d843a94baf2b5ff\",\"size\":2638},\"tests/platform/linux_baseline/_fixtures.py\":{\"blob\":\"d1d152fffec06019d0501a982d2108e1e06eff06\",\"mode\":\"100644\",\"sha256\":\"sha256:579ff77d11e66776884ccf4a3343c417393767215b09abc5aacc1a19c10bcb7d\",\"size\":11573},\"tests/platform/linux_baseline/_successor_inventory.py\":{\"blob\":\"f5185d45b614809bdf3050b16c587b53bad56b1f\",\"mode\":\"100644\",\"sha256\":\"sha256:0ab36ab0055b72d25dced1d0339a1dbacfafe29ea450b2935c171912405ea733\",\"size\":63700},\"tests/platform/linux_baseline/test_linux_campaign.py\":{\"blob\":\"d14aa009675231ef49fbac95c9bcd9559a61e0f1\",\"mode\":\"100644\",\"sha256\":\"sha256:e4501ef5df6a3a1e9f3755aee40592f81ccdcab069d187215f612b97f9773094\",\"size\":8618},\"tests/platform/linux_baseline/test_linux_evidence.py\":{\"blob\":\"85d3983ddf743dd5ed4bde41e81063bc6b32d525\",\"mode\":\"100644\",\"sha256\":\"sha256:b6e162808c471d3d2ed7caa2ed2c056af33819d91ae46a66ff5298da982912b3\",\"size\":14548},\"tests/platform/linux_baseline/test_linux_inventory.py\":{\"blob\":\"8e7e0809c52bd73cd2621770913a21434765353c\",\"mode\":\"100644\",\"sha256\":\"sha256:3fdd36f47cfb3deb7edaab8685dbead5c90519a92844b5bc2266441d5160c338\",\"size\":5683},\"tests/platform/linux_baseline/test_linux_protocol.py\":{\"blob\":\"3f09672575ac51b8d979431adf058f11941b63df\",\"mode\":\"100644\",\"sha256\":\"sha256:2057b427ba366717c506d561978695e27b53208b4e3fbf318b00671fe672254d\",\"size\":8232},\"tests/platform/linux_baseline/test_packet_scalars.py\":{\"blob\":\"60e666600661fe45cb8b44b2753a6d31a82568c2\",\"mode\":\"100644\",\"sha256\":\"sha256:c2ce177f7a462abcae70ae5c51cc2c50d1a3041dc7b9afa527a2e0c582932fe9\",\"size\":27287},\"tests/platform/linux_baseline/test_successor_inventory.py\":{\"blob\":\"81aca1c5b694532850387a492f3224acfa97f5f2\",\"mode\":\"100644\",\"sha256\":\"sha256:46417d8566acedf4c60e396dfe27dcd94743e288eda9f1aeea2db5c27efd0b9e\",\"size\":21048},\"toolchain.lock\":{\"blob\":\"1a9f18620f9d55bb5308b5a817ae671cf07a7246\",\"mode\":\"100644\",\"sha256\":\"sha256:40a0cbb9fc244a8484b22494b6bfa070fbc76aec0edd86ab690026f6a8027bfc\",\"size\":2153},\"uv.lock\":{\"blob\":\"c9043e59c92f5861c567a815a866257459b1b409\",\"mode\":\"100644\",\"sha256\":\"sha256:bd9cb528f2c6ad6a74e3dc1998978e029144fcee2535387cc5ef3db7907dcfbc\",\"size\":150}},\"nativeAcceptance\":false,\"packetId\":\"CONF-PERF-004\",\"predecessorCommit\":\"9df7dd7f2df8ac64096ef37d8df259761947d552\",\"predecessorTests\":327,\"tenantAcceptance\":false,\"testCount\":354,\"tests\":{\"tests/alpha1/test_alpha1.py\":[\"Alpha1CampaignTests.test_campaign_and_evidence_are_reproducible\",\"Alpha1CampaignTests.test_offline_campaign_is_honestly_unavailable\",\"Alpha1CampaignTests.test_report_template_preserves_authority_boundaries\",\"Alpha1ContractTests.test_complete_journey_and_overview_are_closed\",\"Alpha1ContractTests.test_fixture_has_no_public_request_or_secret_material\",\"Alpha1ContractTests.test_fixture_reads_and_canonical_outputs_are_deterministic\",\"Alpha1ContractTests.test_journey_mutations_fail_closed\",\"Alpha1ContractTests.test_navigation_and_evidence_axes_are_complete\",\"Alpha1ContractTests.test_overview_mutations_fail_closed\"],\"tests/fixes/runner_boundary/test_boundaries.py\":[\"CanaryTests.test_absent_unknown_mismatched_marker_never_opens_socket\",\"CanaryTests.test_backend_specific_permission_denials_pass\",\"CanaryTests.test_route_dns_timeout_and_unsupported_family_are_not_isolation\",\"CanaryTests.test_successful_socket_or_connect_is_not_isolation\",\"CanaryTests.test_wrong_stage_permission_denials_fail\",\"RetiredLiveTests.test_adapter_has_no_execution_or_io_imports\",\"RetiredLiveTests.test_arbitrary_argv_invalid_descriptor_and_removed_ci_are_refused\",\"RetiredLiveTests.test_caller_created_pipe_file_and_memfd_magic_are_not_authority\",\"RunnerBoundaryTests.test_backend_os_mismatch_unknown_missing_or_warm_marker_stops_before_io\",\"RunnerBoundaryTests.test_both_os_backends_keep_order_digest_rechecks_and_short_circuit\",\"RunnerBoundaryTests.test_bridge_delegates_exact_argv_without_another_process\",\"RunnerBoundaryTests.test_closed_child_environment_uses_only_local_source_imports\",\"RunnerBoundaryTests.test_content_change_even_with_fixed_metadata_is_detected\",\"RunnerBoundaryTests.test_packet_custody_refuses_user_file_symlink_hardlink_and_fifo\",\"RunnerBoundaryTests.test_real_wrapper_rejects_missing_unknown_and_wrong_os_backend\",\"RunnerBoundaryTests.test_wrapper_binds_os_and_executes_only_the_fixed_bridge\"],\"tests/fixes/runner_boundary/test_inventory.py\":[\"InventoryTests.test_added_file_is_collected_without_manual_registration\",\"InventoryTests.test_all_four_suites_collect_every_module_and_keep_legacy_cases\",\"InventoryTests.test_empty_or_import_broken_module_fails\",\"InventoryTests.test_load_tests_cannot_hide_or_duplicate_a_case\",\"InventoryTests.test_missing_or_empty_root_fails\",\"InventoryTests.test_nested_unimportable_new_file_cannot_be_silently_omitted\",\"InventoryTests.test_skipped_or_expected_failure_cannot_hide_a_case\"],\"tests/live_backend/test_inventory.py\":[\"BackendInventoryTests.test_all_110_accepted_files_are_fixed_with_only_closed_final_hook_proof\",\"BackendInventoryTests.test_all_four_accepted_correction_additions_are_hash_bound\",\"BackendInventoryTests.test_all_six_roots_ast_equal_actual_and_all_170_predecessors_preserved\",\"BackendInventoryTests.test_authority_source_and_model_release_are_exact_nonexecuting_pins\",\"BackendInventoryTests.test_baseline_tampering_and_duplicate_members_refuse\",\"BackendInventoryTests.test_inventory_rejects_empty_duplicate_hidden_and_non_test_method\",\"BackendInventoryTests.test_inventory_rejects_skip_and_expected_failure_and_namespace_omission\",\"BackendInventoryTests.test_inventory_roots_with_colliding_module_names_remain_independent\",\"BackendInventoryTests.test_linked_root_ancestor_and_hardlinked_test_are_rejected\",\"BackendInventoryTests.test_new_runtime_modules_have_no_io_signing_or_legacy_verifier_substitution\",\"BackendInventoryTests.test_original_103_120_and_scalar_106_150_histories_remain_separate\",\"BackendInventoryTests.test_presence_of_integration_file_never_exempts_launcher\",\"BackendInventoryTests.test_tracked_inventory_has_only_complete_ordered_packet_stages\"],\"tests/live_backend/test_linux_boundary.py\":[\"CredentialBoundaryTests.test_credential_wrong_mode_symlink_hardlink_size_and_metadata_refuse\",\"CredentialBoundaryTests.test_direct_constructor_caller_path_and_foreign_hook_are_not_authority\",\"CredentialBoundaryTests.test_missing_policy_or_fixed_module_identity_opens_no_credential\",\"CredentialBoundaryTests.test_partial_acquisition_exhaustion_and_write_failure_release_all\",\"CredentialBoundaryTests.test_retained_credential_and_ancestry_mutation_refuse_without_reopening\",\"CredentialBoundaryTests.test_temporary_socket_and_sealed_memfd_close_before_receipt\",\"CredentialBoundaryTests.test_two_operations_retain_one_credential_without_unsealing_authority\",\"LinuxBoundaryTests.test_all_network_families_dns_and_metadata_have_no_direct_socket_grant\",\"LinuxBoundaryTests.test_all_received_descriptors_are_closed_even_after_malformed_ancillary\",\"LinuxBoundaryTests.test_ambient_environment_credentials_proxy_and_import_paths_are_rejected\",\"LinuxBoundaryTests.test_ambient_extra_fd_or_socket_stdio_refuse_but_closed_listdir_fd_is_ignored\",\"LinuxBoundaryTests.test_bpf_abi_x32_and_unknown_architecture_fail_closed\",\"LinuxBoundaryTests.test_cgroup_attach_ambiguity_retains_cleanup_ownership\",\"LinuxBoundaryTests.test_cgroup_filesystem_magic_is_checked_by_fixed_native_abi\",\"LinuxBoundaryTests.test_cgroup_kernel_files_require_root_nonwritable_custody\",\"LinuxBoundaryTests.test_cgroup_kill_reaps_direct_and_adopted_double_fork_children\",\"LinuxBoundaryTests.test_cgroup_nonempty_or_unreaped_tree_never_certifies_cleanup\",\"LinuxBoundaryTests.test_every_reviewed_unsafe_syscall_is_denied_on_both_abis\",\"LinuxBoundaryTests.test_fixed_native_struct_layouts_are_64_bit_without_syscall_execution\",\"LinuxBoundaryTests.test_kernel_peer_pid_reuse_and_every_scope_identity_change_refuse\",\"LinuxBoundaryTests.test_namespace_clone_escape_and_clone3_are_denied_but_plain_fork_is_contained\",\"LinuxBoundaryTests.test_native_constructor_refuses_workstation_and_injection_before_libc\",\"LinuxBoundaryTests.test_noncanonical_custody_paths_refuse_before_open\",\"LinuxBoundaryTests.test_only_one_exact_kernel_credential_message_is_accepted\",\"LinuxBoundaryTests.test_owned_file_and_kit_use_single_read_content_and_exact_digest\",\"LinuxBoundaryTests.test_owned_file_read_rejects_hardlink_and_writable_file\",\"LinuxBoundaryTests.test_root_and_ci_flags_cannot_replace_installed_module_custody\",\"LinuxBoundaryTests.test_root_manifest_bytes_are_read_once_verified_and_retained_not_path_reopened\",\"LinuxBoundaryTests.test_self_consistent_privileged_unisolated_peer_still_refuses\",\"LinuxBoundaryTests.test_symlink_hardlink_write_mode_and_extra_file_kit_tampering_refuse\",\"LinuxBoundaryTests.test_unit_boundary_all_steps_ordered_and_each_failure_stops\",\"RetainedBoundaryTests.test_ambient_unknown_descriptor_and_forked_registry_never_authorize\",\"RetainedBoundaryTests.test_close_error_attempts_all_handles_once_and_invalidates_first\",\"RetainedBoundaryTests.test_closed_recycled_descriptor_is_never_closed_as_new_authority\",\"RetainedBoundaryTests.test_each_retained_file_and_ancestor_substitution_is_detected\",\"RetainedBoundaryTests.test_every_custody_metadata_field_is_rechecked\",\"RetainedBoundaryTests.test_fixed_identity_read_once_and_cached_digest_cannot_replace_registry\",\"RetainedBoundaryTests.test_kit_rootfs_is_borrowed_once_and_signed_bytes_are_immutable\",\"RetainedBoundaryTests.test_native_constructor_exhaustion_or_bad_installed_read_closes_every_handle\"],\"tests/live_backend/test_replay_store.py\":[\"ReplayStoreTests.test_all_unsigned_reservation_scope_fields_are_validated\",\"ReplayStoreTests.test_backward_time_and_terminal_without_receipt_refuse\",\"ReplayStoreTests.test_concurrent_nonce_reservations_have_at_most_one_success\",\"ReplayStoreTests.test_crash_at_every_append_sync_boundary_never_grants_execution\",\"ReplayStoreTests.test_expiry_is_exclusive_and_cannot_be_reported_early\",\"ReplayStoreTests.test_forged_transition_and_rebound_session_are_refused\",\"ReplayStoreTests.test_full_journal_fails_without_rotation_truncation_or_reset\",\"ReplayStoreTests.test_hash_chain_reordering_and_state_tampering_refuse\",\"ReplayStoreTests.test_nonce_key_cannot_be_reset_by_release_environment_or_command_change\",\"ReplayStoreTests.test_owner_mode_kind_and_hardlink_checks_are_independent\",\"ReplayStoreTests.test_production_constructor_has_no_storage_or_path_injection\",\"ReplayStoreTests.test_reservation_append_sync_readback_before_return\",\"ReplayStoreTests.test_restart_keeps_incomplete_reserved_or_running_nonce_consumed\",\"ReplayStoreTests.test_tenant_and_nonce_keys_are_separate_without_raw_nonce_storage\",\"ReplayStoreTests.test_terminal_lifecycle_is_durable_and_never_releases_nonce\",\"ReplayStoreTests.test_torn_duplicate_noncanonical_oversized_and_nonfinite_journal_refuse\"],\"tests/live_backend/test_session.py\":[\"BackendAuthorityTests.test_all_command_and_packet_scope_mutations_reject_even_when_signed\",\"BackendAuthorityTests.test_all_signed_envelope_and_capacity_fields_are_closed\",\"BackendAuthorityTests.test_authority_raw_digest_and_canonical_transport_cannot_be_substituted\",\"BackendAuthorityTests.test_binding_uses_all_three_trust_windows_and_no_file_access\",\"BackendAuthorityTests.test_each_selected_key_expiry_is_exclusive_in_direct_authority_adapter\",\"BackendAuthorityTests.test_each_signature_is_required_and_covers_immutable_release_endpoint_bytes\",\"BackendAuthorityTests.test_each_trust_role_owner_scope_revocation_window_and_duplicate_is_checked\",\"BackendAuthorityTests.test_every_capacity_scope_digest_array_and_validity_boundary_is_preserved\",\"BackendAuthorityTests.test_expected_nonce_tenant_environment_release_and_architecture_are_external_bindings\",\"BackendAuthorityTests.test_release_plan_and_proxy_policy_are_checked_even_after_signer_approval\",\"BackendAuthorityTests.test_signed_unsafe_endpoint_values_cannot_expand_network_or_cost_scope\",\"BackendAuthorityTests.test_successor_and_legacy_are_independently_pinned_and_mutually_exclusive\",\"RequestReceiptDataTests.test_all_mandatory_assertions_and_status_aggregation_are_checked\",\"RequestReceiptDataTests.test_each_request_field_is_closed_and_bound_no_url_argv_or_cross_scope\",\"RequestReceiptDataTests.test_every_fixed_case_on_each_architecture_retains_existing_wire_bytes\",\"RequestReceiptDataTests.test_impossible_regression_counts_are_not_valid_failure_receipts\",\"RequestReceiptDataTests.test_only_current_running_data_can_describe_a_request_or_receipt\",\"RequestReceiptDataTests.test_receipt_fields_nonce_probe_command_output_and_observation_are_bound\",\"RequestReceiptDataTests.test_receipts_have_closed_bounded_bytes_and_never_evidence_promotion\",\"RequestReceiptDataTests.test_regression_omission_wrong_inventory_skips_failures_and_false_pass_reject\",\"SessionDataTests.test_all_64_state_edges_are_exact_and_return_proposals_not_sessions\",\"SessionDataTests.test_every_expected_binding_is_required_and_cannot_be_self_asserted\",\"SessionDataTests.test_every_session_field_is_required_closed_and_strictly_typed\",\"SessionDataTests.test_exact_size_and_depth_limits_apply_before_field_validation\",\"SessionDataTests.test_expiry_cannot_be_early_or_replaced_by_success_or_reuse\",\"SessionDataTests.test_half_open_time_window_and_signed_intersection_are_enforced\",\"SessionDataTests.test_identifiers_digests_and_utc_time_grammar_reuse_closed_contract\",\"SessionDataTests.test_independent_canonical_golden_bytes_and_detached_validated_data\",\"SessionDataTests.test_no_verified_flag_fd_or_environment_can_supply_execution_authority\",\"SessionDataTests.test_noncanonical_duplicate_nonfinite_utf8_and_deep_input_fail_closed\",\"SessionDataTests.test_python_objects_subclasses_and_cycles_never_serialize_or_execute\",\"SessionDataTests.test_session_schema_and_runtime_fields_states_and_patterns_agree\",\"SessionDataTests.test_shared_container_expansion_is_bounded_before_canonical_encoding\"],\"tests/live_backend/test_supervisor.py\":[\"CredentialCleanupTests.test_io_failure_preserves_first_error_and_unproven_cleanup_never_claims_terminal\",\"CredentialCleanupTests.test_recycled_socket_detaches_stale_owner_without_closing_foreign_fd\",\"CredentialCleanupTests.test_retained_credential_expires_before_the_outer_session_deadline\",\"CredentialCleanupTests.test_truthy_policy_return_value_is_not_an_observation_capability\",\"CredentialSourceProofTests.test_actual_and_historical_source_proofs_are_independently_required\",\"CredentialSourceProofTests.test_behavioral_test_rewrite_or_hidden_collection_cannot_fit_source_proof\",\"CredentialSourceProofTests.test_changed_authority_snapshot_scope_and_current_bytes_fail_closed\",\"CredentialSourceProofTests.test_current_inventory_rejects_unrelated_file_mutation_and_partial_future_stage\",\"CredentialSourceProofTests.test_exact_five_paths_and_all_prior_and_added_methods_are_checked\",\"CredentialSupervisorTests.test_close_errors_do_not_retry_recycled_fds_or_skip_other_cleanup\",\"CredentialSupervisorTests.test_duplicate_operation_and_late_direct_access_cannot_reuse_custody\",\"CredentialSupervisorTests.test_foreign_forked_thread_and_substituted_resource_owner_refuse\",\"CredentialSupervisorTests.test_mid_read_expiry_stops_partial_acquisition_and_preserves_first_error\",\"CredentialSupervisorTests.test_post_io_expiry_cancel_and_policy_loss_never_accept_a_receipt\",\"CredentialSupervisorTests.test_unknown_descriptor_during_fixed_hook_is_not_adopted_or_closed\",\"CustodySourceProofTests.test_actual_127_path_inventory_preserves_other_122_complete_file_bytes\",\"CustodySourceProofTests.test_exact_five_path_delta_uses_pinned_data_only_oracle\",\"CustodySourceProofTests.test_oracle_rejects_snapshot_prefix_scope_and_source_substitution\",\"CustodySourceProofTests.test_original_279_methods_and_every_added_method_are_freshly_collected\",\"PerformanceArithmeticTests.test_both_zero_denominator_branches_preserve_total_integer_behavior\",\"PerformanceArithmeticTests.test_canonical_payload_fields_remain_order_independent_and_domain_bound\",\"PerformanceArithmeticTests.test_fixed_three_sample_workload\",\"PerformanceArithmeticTests.test_independent_affine_points_extremes_and_unreduced_coordinates\",\"PerformanceArithmeticTests.test_invalid_lengths_scalar_and_point_encodings_refuse\",\"PerformanceArithmeticTests.test_published_rfc8032_vectors_and_mutations\",\"PerformanceArithmeticTests.test_scalar_extremes_match_independent_addition_reference\",\"PerformanceSourceProofTests.test_all_python_sources_and_four_current_before_historical_consumers_are_bound\",\"PerformanceSourceProofTests.test_benchmark_refuses_ambient_observer_without_replacing_it\",\"PerformanceSourceProofTests.test_benchmark_restores_observer_after_workload_exception\",\"PerformanceSourceProofTests.test_collection_overrides_shadowing_and_oversize_append_refuse\",\"PerformanceSourceProofTests.test_current_custody_is_fresh_on_every_call\",\"PerformanceSourceProofTests.test_current_scalar_hash_bridge_rejects_independently_resealed_mutations\",\"PerformanceSourceProofTests.test_document_prefix_suffix_duplicate_keys_and_oversize_refuse\",\"PerformanceSourceProofTests.test_exact_checkpoint_scope_and_all_fresh_test_roots\",\"PerformanceSourceProofTests.test_exact_scalar_patch_bridge_rejects_independently_resealed_mutations\",\"PerformanceSourceProofTests.test_missing_extra_duplicate_test_identity_refuse\",\"PerformanceSourceProofTests.test_mode_link_duplicate_partial_and_future_inventory_refuse\",\"PerformanceSourceProofTests.test_proof_identity_scope_and_before_after_pins_are_closed\",\"PerformanceSourceProofTests.test_regular_reader_rejects_symlink_hardlink_and_nonregular_sources\",\"PerformanceSourceProofTests.test_required_regression_cannot_be_replaced_by_another_identity\",\"PerformanceSourceProofTests.test_resealed_fixed_bridges_and_old_assertions_refuse\",\"PerformanceSourceProofTests.test_resealed_full_module_observers_refuse\",\"PerformanceSourceProofTests.test_resealed_matched_benchmark_method_changes_refuse\",\"PerformanceSourceProofTests.test_resealed_outside_region_and_forged_before_refuse\",\"PerformanceSourceProofTests.test_unrelated_bytes_and_current_hashes_are_not_exempt\",\"PerformanceSourceProofTests.test_wrong_helper_pin_and_unknown_region_refuse\",\"RetainedSupervisorTests.test_cancel_expiry_failure_and_close_never_reuse_nonce_or_descriptors\",\"RetainedSupervisorTests.test_cleanup_failure_still_releases_remaining_resources_without_terminal_success\",\"RetainedSupervisorTests.test_data_only_mocked_readers_and_cached_digest_never_form_native_context\",\"RetainedSupervisorTests.test_descriptor_injected_after_construction_or_during_io_is_not_admitted\",\"RetainedSupervisorTests.test_each_authority_kit_member_and_full_ancestor_change_refuses_before_hook\",\"RetainedSupervisorTests.test_each_signer_expiry_and_initial_revocation_remain_non_authorizing\",\"RetainedSupervisorTests.test_forged_foreign_subclass_serialized_and_forked_contexts_fail_closed\",\"RetainedSupervisorTests.test_full_native_factory_to_fixed_hook_uses_original_bytes_without_reopening\",\"RetainedSupervisorTests.test_journal_close_failure_does_not_skip_other_owned_descriptors\",\"RetainedSupervisorTests.test_missing_fixed_proxy_module_never_falls_back\",\"RetainedSupervisorTests.test_post_blocking_mutation_refuses_receipt_and_consumes_session\",\"RetainedSupervisorTests.test_proxy_result_after_authority_mutation_is_not_accepted\",\"RetainedSupervisorTests.test_reservation_and_boundary_failures_close_all_custody\",\"RetainedSupervisorTests.test_snapshot_deadline_and_request_tampering_never_reaches_hook\",\"SupervisorPredecessorTests.test_all_216_immediate_predecessor_ids_are_in_fresh_six_root_discovery\",\"SupervisorPredecessorTests.test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable\",\"SupervisorTests.test_all_ten_operations_complete_once_with_only_unsigned_unit_receipts\",\"SupervisorTests.test_cancel_is_terminal_non_reusable_and_idempotent_close_has_no_new_work\",\"SupervisorTests.test_concurrent_operation_is_rejected_and_cancellation_interrupts_inflight_io\",\"SupervisorTests.test_dictionary_fd_serial_clone_foreign_and_pickled_handles_are_not_authority\",\"SupervisorTests.test_each_ambiguous_reservation_failure_has_no_child_or_execution\",\"SupervisorTests.test_establish_and_kernel_peer_failure_consume_nonce_and_clean_up\",\"SupervisorTests.test_expiry_before_operation_reaps_without_execution\",\"SupervisorTests.test_expiry_during_io_never_returns_a_late_pass\",\"SupervisorTests.test_failed_cleanup_leaves_consumed_running_record_not_a_false_terminal\",\"SupervisorTests.test_forged_envelope_cannot_open_an_unverified_capacity_reference\",\"SupervisorTests.test_malformed_receipt_cannot_promote_native_acceptance\",\"SupervisorTests.test_monotonic_deadline_is_bounded_even_if_wall_clock_stalls\",\"SupervisorTests.test_native_cleanup_failure_still_closes_channel_and_pidfd\",\"SupervisorTests.test_native_factory_has_no_caller_context_backend_or_storage_entry\",\"SupervisorTests.test_native_pre_fork_failure_closes_all_channels_and_gate_descriptors\",\"SupervisorTests.test_only_valid_dual_signed_reference_reaches_capacity_read\",\"SupervisorTests.test_peer_dies_during_io_invalidates_return_and_cleans_tree\",\"SupervisorTests.test_reference_authority_expiry_wrong_packet_and_trust_substitution_fail\",\"SupervisorTests.test_unavailable_operation_remains_unavailable_not_native_or_pass\",\"SupervisorTests.test_unknown_duplicate_and_wrong_architecture_operations_invalidate_session\",\"SupervisorTests.test_wall_clock_rollback_invalidates_but_does_not_rewrite_journal_history\"],\"tests/meta/test_build_cli.py\":[\"BuildCliTests.test_build_backend_wheel_is_reproducible\",\"BuildCliTests.test_cli_report_and_evidence_are_deterministic\",\"BuildCliTests.test_live_inner_adapter_refuses_direct_and_ci\",\"BuildCliTests.test_reproducible_live_candidate\"],\"tests/meta/test_campaign.py\":[\"CampaignTests.test_all_handlers_and_non_failing_states_are_exercised\",\"CampaignTests.test_illegal_lifecycle_and_event_fail\",\"CampaignTests.test_required_failure_blocks\",\"CampaignTests.test_required_unavailable_is_honest\",\"CampaignTests.test_two_runs_are_byte_identical\",\"CampaignTests.test_unknown_result_aliases_do_not_exist\"],\"tests/meta/test_canonical_schema.py\":[\"CanonicalSchemaTests.test_campaign_and_environment_are_closed\",\"CanonicalSchemaTests.test_canonical_bytes_are_stable\",\"CanonicalSchemaTests.test_closed_vocabularies\",\"CanonicalSchemaTests.test_duplicate_and_noncanonical_numbers_are_rejected\",\"CanonicalSchemaTests.test_every_published_schema_is_closed_and_valid_json\",\"CanonicalSchemaTests.test_secure_read_refuses_symlink\"],\"tests/meta/test_evidence_crypto.py\":[\"EvidenceCryptoTests.test_candidate_is_unsigned_pending_and_digest_bound\",\"EvidenceCryptoTests.test_cli_requires_private_key_mode\",\"EvidenceCryptoTests.test_rfc8032_vector\",\"EvidenceCryptoTests.test_tamper_revocation_scope_and_duplicate_key_fail\",\"EvidenceCryptoTests.test_technical_evidence_sign_and_verify\",\"EvidenceCryptoTests.test_tenant_acceptance_signing_is_forbidden\"],\"tests/meta/test_live.py\":[\"LiveContractTests.test_capacity_scope_and_window_are_exact\",\"LiveContractTests.test_command_axis_signature_and_capacity_mismatches_fail\",\"LiveContractTests.test_positive_preflight_verifies_every_authority_class\",\"LiveContractTests.test_public_discovered_wildcard_and_metadata_endpoints_fail\",\"LiveContractTests.test_repository_candidate_refuses_ci_and_direct_authority\"],\"tests/meta/test_porting_zero_bill.py\":[\"PortingZeroBillTests.test_every_copy_claim_is_rejected\",\"PortingZeroBillTests.test_porting_ledger_is_exact_inert_sentinel\",\"PortingZeroBillTests.test_workflow_and_toolchain_are_zero_bill\",\"PortingZeroBillTests.test_zero_bill_scanner_rejects_each_declared_vector\"],\"tests/meta/test_registry_dispatch.py\":[\"RegistryDispatchTests.test_descriptor_is_closed_direct_argv\",\"RegistryDispatchTests.test_duplicate_campaign_fails_closed\",\"RegistryDispatchTests.test_generic_campaign_has_no_shell_injection\",\"RegistryDispatchTests.test_makefile_never_interpolates_campaign\",\"RegistryDispatchTests.test_packet_campaigns_resolve_additively\",\"RegistryDispatchTests.test_unknown_and_undeclared_dispatch_fail\"],\"tests/parity/test_adapters.py\":[\"AdapterTests.test_altered_expectation_fails_exact\",\"AdapterTests.test_every_vector_is_deterministic\",\"AdapterTests.test_unknown_family_and_unbound_vector_fail\",\"AdapterTests.test_vector_shape_rejects_command_url_and_credentials\"],\"tests/parity/test_packet_runner.py\":[\"PacketRunnerTests.test_alias_and_empty_acceptance_are_rejected\",\"PacketRunnerTests.test_current_packet_inline_authority_parses\",\"PacketRunnerTests.test_duplicate_inline_authority_is_rejected\",\"PacketRunnerTests.test_main_preserves_phase_order_and_hides_authority\",\"PacketRunnerTests.test_packet_replacement_is_detected\",\"PacketRunnerTests.test_shell_download_recursive_and_strings_fail\",\"PacketRunnerTests.test_wrong_execution_and_warm_access_fail\"],\"tests/parity/test_registry.py\":[\"RegistryTests.test_registry_and_vectors_pass_without_source_access\",\"RegistryTests.test_registry_contains_no_content_or_copy_authority\",\"RegistryTests.test_unknown_object_relation_and_binding_fail\"],\"tests/platform/linux_baseline/test_linux_campaign.py\":[\"LinuxCampaignTests.test_all_handler_views_keep_exact_order_and_no_aliases\",\"LinuxCampaignTests.test_cli_keeps_unavailable_results_and_unsigned_acceptance\",\"LinuxCampaignTests.test_environment_flags_and_session_variables_never_create_native_authority\",\"LinuxCampaignTests.test_legacy_reports_evidence_and_candidates_are_byte_identical_to_predecessor\",\"LinuxCampaignTests.test_twenty_required_cases_are_closed_in_runtime_and_published_schema\",\"LinuxCampaignTests.test_validate_cli_is_explicitly_structural_not_signature_acceptance\"],\"tests/platform/linux_baseline/test_linux_evidence.py\":[\"LinuxEvidenceTests.test_all_cases_are_required_ordered_and_unique\",\"LinuxEvidenceTests.test_both_native_architecture_vectors_are_unit_only\",\"LinuxEvidenceTests.test_duplicate_json_floats_invalid_utf8_and_malformed_inputs_fail\",\"LinuxEvidenceTests.test_duplicate_keys_changed_trust_bytes_and_same_signers_fail\",\"LinuxEvidenceTests.test_each_missing_check_and_false_pass_is_rejected\",\"LinuxEvidenceTests.test_each_probe_command_output_nonce_and_time_is_bound\",\"LinuxEvidenceTests.test_emulated_cross_arch_and_non_linux_never_qualify\",\"LinuxEvidenceTests.test_every_binding_is_compared_even_with_valid_record_signatures\",\"LinuxEvidenceTests.test_every_record_field_is_mandatory\",\"LinuxEvidenceTests.test_every_signature_is_independently_required\",\"LinuxEvidenceTests.test_every_source_image_build_and_host_binding_is_exact\",\"LinuxEvidenceTests.test_executed_failure_and_missing_environment_remain_distinct\",\"LinuxEvidenceTests.test_expired_future_boundary_and_replay_inputs_fail\",\"LinuxEvidenceTests.test_observation_and_expiration_fit_both_authorizations\",\"LinuxEvidenceTests.test_only_precise_utc_rfc3339_timestamps_are_accepted\",\"LinuxEvidenceTests.test_plan_rejects_missing_extra_or_incomplete_regression_fields\",\"LinuxEvidenceTests.test_regression_inventory_counts_skips_and_hidden_deselection_fail\",\"LinuxEvidenceTests.test_release_tree_paths_modes_sizes_and_baseline_pins_are_closed\",\"LinuxEvidenceTests.test_role_scope_owner_revocation_and_validity_fail_closed\",\"LinuxEvidenceTests.test_unknown_nested_fields_and_verification_booleans_are_rejected\"],\"tests/platform/linux_baseline/test_linux_inventory.py\":[\"LinuxInventoryTests.test_all_five_suites_collect_every_module_and_preserve_all_83_predecessors\",\"LinuxInventoryTests.test_legacy_comparison_sources_are_pinned_owned_baseline_bytes\",\"LinuxInventoryTests.test_legacy_three_file_edits_and_registry_addition_are_exact\",\"LinuxInventoryTests.test_original_files_are_unchanged_except_ten_authorized_integrations\",\"LinuxInventoryTests.test_pure_verifier_has_no_execution_network_or_signing_primitive\"],\"tests/platform/linux_baseline/test_linux_protocol.py\":[\"LinuxProtocolTests.test_dual_envelope_commands_axes_endpoint_and_capacity_mismatch_fail\",\"LinuxProtocolTests.test_fake_proxy_is_unit_only_and_cannot_supply_runtime_authority\",\"LinuxProtocolTests.test_proxy_operations_are_fixed_data_only_and_do_not_open_io\",\"LinuxProtocolTests.test_published_schema_covers_all_nested_records_and_plans\",\"LinuxProtocolTests.test_schema_and_runtime_both_reject_structural_mutations\",\"LinuxProtocolTests.test_unknown_operations_and_scope_or_policy_expansion_fail\"],\"tests/platform/linux_baseline/test_packet_scalars.py\":[\"ScalarAuthorizationTests.test_all_offline_contract_members_are_enforced\",\"ScalarAuthorizationTests.test_boolean_and_null_words_never_authorize_identity\",\"ScalarAuthorizationTests.test_command_order_and_arguments_are_not_normalized\",\"ScalarAuthorizationTests.test_command_phase_types_and_bounds_refuse\",\"ScalarAuthorizationTests.test_extraction_does_not_authorize_wrong_identity\",\"ScalarAuthorizationTests.test_shell_download_and_recursive_transports_refuse\",\"ScalarExecutionTests.test_digest_refusal_stops_before_acceptance\",\"ScalarExecutionTests.test_invalid_identity_fails_before_any_child\",\"ScalarExecutionTests.test_prefetch_order_and_failure_short_circuit_remain\",\"ScalarExecutionTests.test_real_parser_drives_all_six_ordered_mocked_sessions\",\"ScalarIntegrityTests.test_all_103_original_files_and_only_three_additions_remain\",\"ScalarIntegrityTests.test_all_120_predecessor_and_all_new_test_ids_are_collected\",\"ScalarIntegrityTests.test_baseline_history_and_failed_draft_are_not_promoted\",\"ScalarIntegrityTests.test_fixture_and_authority_remain_exact_source_only_inputs\",\"ScalarIntegrityTests.test_fixture_tamper_duplicate_and_nonfinite_values_refuse\",\"ScalarIntegrityTests.test_missing_extra_or_modified_original_inventory_refuses\",\"ScalarIntegrityTests.test_two_exact_source_transformations_preserve_all_other_bytes\",\"ScalarIntegrityTests.test_unapproved_source_mutations_and_unknown_paths_refuse\",\"ScalarParsingTests.test_all_bare_quoted_and_mixed_forms_preserve_values\",\"ScalarParsingTests.test_all_six_published_packets_decode_to_independent_views\",\"ScalarParsingTests.test_bare_indirection_numeric_and_container_values_refuse\",\"ScalarParsingTests.test_duplicate_scalar_and_structured_fields_refuse\",\"ScalarParsingTests.test_field_order_and_outer_yaml_whitespace_preserve_values\",\"ScalarParsingTests.test_identifier_length_and_ascii_grammar_boundaries\",\"ScalarParsingTests.test_json_ascii_escapes_decode_without_reserializing_packet\",\"ScalarParsingTests.test_malformed_quotes_escapes_and_trailing_values_refuse\",\"ScalarParsingTests.test_missing_fields_refuse\",\"ScalarParsingTests.test_non_string_decoder_values_refuse\",\"ScalarParsingTests.test_quoted_control_whitespace_and_non_ascii_refuse\",\"ScalarParsingTests.test_structured_fields_remain_inline_json_only\"],\"tests/platform/linux_baseline/test_successor_inventory.py\":[\"SuccessorInventoryTests.test_all_seven_complete_stage_vectors\",\"SuccessorInventoryTests.test_current_repository\",\"SuccessorInventoryTests.test_current_test_guard_not_exempt\",\"SuccessorInventoryTests.test_every_missing_stage_path_refuses\",\"SuccessorInventoryTests.test_exact_scalar_test_patch\",\"SuccessorInventoryTests.test_fixture_tamper_and_duplicate_json_refuse\",\"SuccessorInventoryTests.test_hook_prefix_suffix_and_replacement_tamper_refuse\",\"SuccessorInventoryTests.test_hook_proof_identity_digest_type_and_scope_refuse\",\"SuccessorInventoryTests.test_old_guard_rejects_legitimate_stage_one\",\"SuccessorInventoryTests.test_original_106_file_and_150_test_history\",\"SuccessorInventoryTests.test_original_test_ids_and_new_tests_collected\",\"SuccessorInventoryTests.test_out_of_order_and_partial_stages_refuse\",\"SuccessorInventoryTests.test_predecessor_hash_size_and_mode_tampering_refuses\",\"SuccessorInventoryTests.test_premature_hook_or_proof_refuses\",\"SuccessorInventoryTests.test_presence_or_environment_does_not_authorize\",\"SuccessorInventoryTests.test_source_evidence_is_never_native_acceptance\",\"SuccessorInventoryTests.test_stage_six_requires_exact_hook_proof\",\"SuccessorInventoryTests.test_symlinks_hardlinks_and_nonregular_files_refuse\",\"SuccessorInventoryTests.test_test_omissions_skips_and_xfails_refuse\",\"SuccessorInventoryTests.test_unknown_duplicate_and_traversal_paths_refuse\"]},\"tree\":\"ef7e5afc04c31651bd3f29acc03f59c6c901c130\"},\"originalProofSha256\":\"999c0d23c4bdeb5acea89104dcab8f4ad312f1dcb3b714ceecdd11712357cc67\",\"performanceIds\":[\"PerformanceArithmeticTests.test_both_zero_denominator_branches_preserve_total_integer_behavior\",\"PerformanceArithmeticTests.test_canonical_payload_fields_remain_order_independent_and_domain_bound\",\"PerformanceArithmeticTests.test_fixed_three_sample_workload\",\"PerformanceArithmeticTests.test_independent_affine_points_extremes_and_unreduced_coordinates\",\"PerformanceArithmeticTests.test_invalid_lengths_scalar_and_point_encodings_refuse\",\"PerformanceArithmeticTests.test_published_rfc8032_vectors_and_mutations\",\"PerformanceArithmeticTests.test_scalar_extremes_match_independent_addition_reference\",\"PerformanceSourceProofTests.test_all_python_sources_and_four_current_before_historical_consumers_are_bound\",\"PerformanceSourceProofTests.test_benchmark_refuses_ambient_observer_without_replacing_it\",\"PerformanceSourceProofTests.test_benchmark_restores_observer_after_workload_exception\",\"PerformanceSourceProofTests.test_collection_overrides_shadowing_and_oversize_append_refuse\",\"PerformanceSourceProofTests.test_current_custody_is_fresh_on_every_call\",\"PerformanceSourceProofTests.test_current_scalar_hash_bridge_rejects_independently_resealed_mutations\",\"PerformanceSourceProofTests.test_document_prefix_suffix_duplicate_keys_and_oversize_refuse\",\"PerformanceSourceProofTests.test_exact_checkpoint_scope_and_all_fresh_test_roots\",\"PerformanceSourceProofTests.test_exact_scalar_patch_bridge_rejects_independently_resealed_mutations\",\"PerformanceSourceProofTests.test_missing_extra_duplicate_test_identity_refuse\",\"PerformanceSourceProofTests.test_mode_link_duplicate_partial_and_future_inventory_refuse\",\"PerformanceSourceProofTests.test_proof_identity_scope_and_before_after_pins_are_closed\",\"PerformanceSourceProofTests.test_regular_reader_rejects_symlink_hardlink_and_nonregular_sources\",\"PerformanceSourceProofTests.test_required_regression_cannot_be_replaced_by_another_identity\",\"PerformanceSourceProofTests.test_resealed_fixed_bridges_and_old_assertions_refuse\",\"PerformanceSourceProofTests.test_resealed_full_module_observers_refuse\",\"PerformanceSourceProofTests.test_resealed_matched_benchmark_method_changes_refuse\",\"PerformanceSourceProofTests.test_resealed_outside_region_and_forged_before_refuse\",\"PerformanceSourceProofTests.test_unrelated_bytes_and_current_hashes_are_not_exempt\",\"PerformanceSourceProofTests.test_wrong_helper_pin_and_unknown_region_refuse\"],\"region\":\"PerformanceSourceProofTests.test_exact_checkpoint_scope_and_all_fresh_test_roots\",\"requiredIds\":[\"SuccessorCheckpointRepairTests.test_all_five_current_stages_keep_exact_path_and_method_sets\",\"SuccessorCheckpointRepairTests.test_changed_current_predecessor_bytes_refuse\",\"SuccessorCheckpointRepairTests.test_current_correction_is_checked_before_historical_comparison\",\"SuccessorCheckpointRepairTests.test_final_hook_delta_is_verified_not_exempted\",\"SuccessorCheckpointRepairTests.test_legacy_projection_and_corrective_binding_tampering_refuse\",\"SuccessorCheckpointRepairTests.test_missing_duplicate_or_shadowed_methods_refuse\",\"SuccessorCheckpointRepairTests.test_partial_future_and_unapproved_paths_refuse\",\"SuccessorCheckpointRepairTests.test_scope_excludes_runtime_arithmetic_and_benchmark_changes\"],\"successorPaths\":{\"3\":[\"src/harness_conformance/live_proxy_client.py\",\"src/harness_conformance/live_proxy_server.py\",\"src/harness_conformance/live_mutation_admission.py\",\"tests/live_backend/test_proxy_client.py\",\"tests/live_backend/test_proxy_server.py\",\"tests/live_backend/test_mutation_admission.py\",\"fixtures/live-backend/proxy-vectors.json\",\"docs/live-backend/proxy.md\"],\"4\":[\"src/harness_conformance/live_fixed_probes.py\",\"src/harness_conformance/live_probe_receipts.py\",\"fixtures/live-backend/probe-vectors.json\",\"tests/live_backend/test_fixed_probes.py\",\"tests/live_backend/test_probe_receipts.py\",\"docs/live-backend/probes.md\"],\"5\":[\"ci/build_live_backend.py\",\"src/harness_conformance/live_backend_package.py\",\"tests/live_backend/test_package.py\",\"fixtures/live-backend/package-vectors.json\",\"docs/live-backend/operator-handoff.md\"],\"6\":[\"src/harness_conformance/live_backend_campaign.py\",\"src/harness_conformance/live_backend_evidence.py\",\"tests/live_backend/test_campaign_integration.py\",\"tests/live_backend/test_cumulative_release.py\",\"docs/live-backend/qualification.md\"]}}")


def _successor_correction_require(condition, reason):
    if not condition:
        raise ValueError("successor correction: " + reason)


def _successor_correction_region(raw, name):
    import ast
    nodes = ast.parse(raw).body
    for part in name.split("."):
        matches = [n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == part]
        _successor_correction_require(len(matches) == 1, "unique named region")
        node = matches[0]
        nodes = node.body
    _successor_correction_require(isinstance(node, ast.FunctionDef) and not node.decorator_list, "plain method")
    lines = raw.splitlines(keepends=True)
    return sum(map(len, lines[:node.lineno - 1])), sum(map(len, lines[:node.end_lineno]))


def _successor_correction_ids(raw):
    import ast
    _successor_correction_require(type(raw) is bytes, "test source bytes")
    tree = ast.parse(raw)
    ids = []
    for scope in [tree, *[n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]]:
        definitions = [n for n in scope.body if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
        names = [n.name for n in definitions]
        _successor_correction_require(len(names) == len(set(names)), "shadowed definition")
    _successor_correction_require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == "load_tests" for n in tree.body), "custom collection")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                text = ast.unparse(decorator)
                _successor_correction_require(not any(word in text for word in
                    ("skip", "expectedFailure", "xfail")), "hidden test")
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            ids.extend(node.name + "." + method.name for method in node.body
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_"))
    _successor_correction_require(ids and len(ids) == len(set(ids)), "nonempty unique methods")
    return sorted(ids)


def _successor_correction_parts(sources):
    """Invert only the approved correction and bind the untouched b758 bytes."""
    import ast
    spec = _successor_correction_spec()
    sup, doc = SUCCESSOR.PERFORMANCE_TEST, SUCCESSOR.PERFORMANCE_DOC
    test, document = sources[sup], sources[doc]
    require = _successor_correction_require
    require(type(test) is type(document) is bytes, "current bytes")
    marker = b"\n\n# CONF-FIX-006: independent SOURCE_DATA_ONLY correction and regression boundary.\n"
    require(test.count(marker) == 1, "unique correction appendix")
    offset = test.index(marker)
    prefix, append = test[:offset], test[offset:]
    require(0 < len(append) <= 131072, "bounded correction appendix")
    start, end = _successor_correction_region(prefix, spec["region"])
    require(prefix[start:end] == spec["afterMethod"].encode(), "exact replacement method")
    old = prefix[:start] + spec["beforeMethod"].encode() + prefix[end:]
    require("sha256:" + hashlib.sha256(old).hexdigest() == spec["checkpoint"]["files"][sup]["sha256"], "accepted test bytes")
    old_tree, added = ast.parse(old), ast.parse(append)
    definitions = (ast.FunctionDef, ast.ClassDef)
    old_names = {n.name for n in old_tree.body if isinstance(n, definitions)}
    names = [n.name for n in added.body if isinstance(n, definitions)]
    require(len(names) == len(added.body) and len(names) == len(set(names))
        and not old_names.intersection(names), "definition-only nonshadowing appendix")
    forbidden = {"load_tests", "run", "discover", "setUpModule", "tearDownModule", "setUpClass",
                 "tearDownClass", "setUp", "tearDown", "__getattribute__", "__getattr__", "__init__"}
    for node in ast.walk(added):
        if isinstance(node, definitions):
            require(not node.decorator_list and node.name not in forbidden, "ordinary regression definition")
        require(not isinstance(node, (ast.AsyncFunctionDef, ast.Global, ast.Nonlocal)), "isolated regression scope")
        if isinstance(node, ast.Attribute):
            require(node.attr not in ("skip", "skipIf", "skipUnless", "expectedFailure", "skipTest"), "no omitted regression")
    prior, current = _successor_correction_ids(old), _successor_correction_ids(test)
    require(prior == sorted(spec["checkpoint"]["tests"][sup]) and set(prior) <= set(current), "accepted method identities")
    new_ids = sorted(set(current) - set(prior))
    require(set(spec["requiredIds"]) <= set(new_ids), "required correction identities")
    legacy_marker = b"\n```harness-performance-source-proof\n"
    correction_marker = b"\n```harness-successor-checkpoint-correction\n"
    require(document.count(legacy_marker) == 1 and document.endswith(b"\n```\n"), "final legacy projection")
    current_prefix, encoded = document.split(legacy_marker)
    legacy = SUCCESSOR.parse(encoded[:-5])
    require(SUCCESSOR.canonical(legacy) == encoded[:-5], "canonical legacy projection")
    require(current_prefix.count(correction_marker) == 1, "unique independent binding")
    original_prefix, encoded_binding = current_prefix.split(correction_marker)
    require(encoded_binding.endswith(b"\n```\n"), "final corrective binding")
    binding = SUCCESSOR.parse(encoded_binding[:-5])
    expected_binding = dict(schemaVersion="planeon.internal.successor-checkpoint-correction/v1",
        evidenceClass="SOURCE_DELTA_ONLY", packetId="CONF-FIX-006", authorityDigest=spec["authorityDigest"],
        baseCommit=spec["checkpoint"]["commit"], beforeTestSha256=hashlib.sha256(old).hexdigest(),
        afterTestSha256=hashlib.sha256(test).hexdigest(), originalProofSha256=spec["originalProofSha256"],
        replacementSha256=hashlib.sha256(spec["afterMethod"].encode()).hexdigest(), addedTestIds=new_ids)
    require(SUCCESSOR.canonical(binding) == encoded_binding[:-5]
        and binding == expected_binding, "exact independent binding")
    suffix = correction_marker + encoded_binding
    # The original v4 proof is reconstructed as inert JSON, not re-executed.
    original = deepcopy(legacy)
    row = original["sources"][sup]
    require(row["append"].endswith(append.decode()), "exact appendix projection")
    retained = row["append"][:-len(append.decode())]
    require(retained.count(spec["afterMethod"]) == 1, "single legacy method projection")
    row["append"] = retained.replace(spec["afterMethod"], spec["beforeMethod"])
    require(row["afterSha256"] == hashlib.sha256(test).hexdigest(), "current test projection hash")
    row["afterSha256"] = hashlib.sha256(old).hexdigest()
    require(legacy["newTestIds"] == sorted(spec["performanceIds"] + new_ids), "exact projected method set")
    original["newTestIds"] = spec["performanceIds"]
    require(original["documentSuffix"].endswith(suffix.decode()), "exact binding suffix projection")
    original["documentSuffix"] = original["documentSuffix"][:-len(suffix.decode())]
    require(hashlib.sha256(SUCCESSOR.canonical(original)).hexdigest() == spec["originalProofSha256"], "original proof unchanged")
    original_document = original_prefix + legacy_marker + SUCCESSOR.canonical(original) + b"\n```\n"
    require("sha256:" + hashlib.sha256(original_document).hexdigest() == spec["checkpoint"]["files"][doc]["sha256"], "accepted document bytes")
    return {sup: old, doc: original_document}, binding, legacy


def _successor_correction_validate(rows, sources):
    # The independent current correction must pass before any legacy view.
    before, binding, legacy = _successor_correction_parts(sources)
    spec = _successor_correction_spec()
    hook = SUCCESSOR.RECORD["hook"]
    hook_proof = SUCCESSOR.parse_hook_proof(sources[hook["proofPath"]]) if hook["proofPath"] in sources else None
    result = SUCCESSOR.validate_composition(rows, sources.get(hook["path"]),
        {"performanceSources": sources, "hookProof": hook_proof})
    current = {row["path"]: row for row in rows}
    for path, pin in spec["checkpoint"]["files"].items():
        if path == hook["path"] and result["stage"] == 6:
            # The exact original final-hook verifier has just checked this delta.
            continue
        raw = before.get(path, sources[path])
        require = _successor_correction_require
        require(current[path]["mode"] == pin["mode"] and len(raw) == pin["size"]
            and "sha256:" + hashlib.sha256(raw).hexdigest() == pin["sha256"]
            and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == pin["blob"], "accepted predecessor bytes: " + path)
    expected = deepcopy(spec["checkpoint"]["tests"])
    expected[SUCCESSOR.PERFORMANCE_TEST] = sorted(expected[SUCCESSOR.PERFORMANCE_TEST] + binding["addedTestIds"])
    for stage in range(3, result["stage"] + 1):
        for path in spec["successorPaths"][str(stage)]:
            if path.startswith("tests/") and path.rsplit("/", 1)[-1].startswith("test_") and path.endswith(".py"):
                expected[path] = _successor_correction_ids(sources[path])
    for path, methods in expected.items():
        _successor_correction_require(_successor_correction_ids(sources[path]) == sorted(methods), "exact current method map")
    return result, expected, before, binding, legacy


class SuccessorCheckpointRepairTests(unittest.TestCase):
    def vector(self, stage):
        # Source-data-only synthetic successors; never compiled/imported/run.
        rows, current = SUCCESSOR.tracked_inventory(ROOT)
        spec = _successor_correction_spec()
        _successor_correction_validate(rows, current)
        sources = {p: current[p] for p in spec["checkpoint"]["files"]}
        expected = deepcopy(spec["checkpoint"]["tests"])
        expected[SUCCESSOR.PERFORMANCE_TEST] = sorted(expected[SUCCESSOR.PERFORMANCE_TEST] + spec["requiredIds"])
        hook = SUCCESSOR.RECORD["hook"]
        sources[hook["path"]] = SUCCESSOR.FIXTURE["launcherBefore"].encode()
        for number in range(3, stage + 1):
            for path in spec["successorPaths"][str(number)]:
                sources[path] = ("INERT SOURCE VECTOR: " + path + "\n").encode()
                if path.startswith("tests/") and path.rsplit("/", 1)[-1].startswith("test_") and path.endswith(".py"):
                    owner = "FutureStage" + str(number)
                    sources[path] = ("class " + owner + ":\n    def test_inventory_probe(self):\n        return None\n").encode()
                    expected[path] = [owner + ".test_inventory_probe"]
        if stage == 6:
            replacement = "        result = {\"status\": \"NOT_RUN_ENV_UNAVAILABLE\"}\n"
            sources[hook["path"]] = sources[hook["path"]].replace(hook["beforeBlock"].encode(), replacement.encode(), 1)
            proof = dict(schemaVersion=hook["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
                **{k: hook[k] for k in ("packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256")},
                replacement=replacement, afterSha256=hashlib.sha256(sources[hook["path"]]).hexdigest())
            sources[hook["proofPath"]] = b"# SOURCE_DATA_ONLY\n\n```harness-launcher-source-proof\n" + SUCCESSOR.canonical(proof) + b"\n```\n"
        return self.rows(sources), sources, expected

    def rows(self, sources):
        pins = _successor_correction_spec()["checkpoint"]["files"]
        return [dict(path=p, mode=pins[p]["mode"] if p in pins else "100644", size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(), kind="file", nlink=1, linkedAncestry=False) for p, raw in sorted(sources.items())]

    def exercise_method(self, rows, sources, expected):
        historical, proof = SUCCESSOR.performance_proof(sources)
        def collect(root):
            prefix = str(root.relative_to(ROOT)) + "/"
            return {p[len(prefix):]: methods for p, methods in expected.items() if p.startswith(prefix)}
        with patch.object(PerformanceSourceProofTests, "inputs", return_value=(rows, sources, historical, proof)), patch(
                __name__ + ".isolated_inventory", side_effect=collect) as collector:
            PerformanceSourceProofTests().test_exact_checkpoint_scope_and_all_fresh_test_roots()
        self.assertEqual(collector.call_count, 6)

    def rebind_document(self, sources, binding=None, legacy=None):
        changed = dict(sources)
        marker = b"\n```harness-performance-source-proof\n"
        correction = b"\n```harness-successor-checkpoint-correction\n"
        prefix, encoded = changed[SUCCESSOR.PERFORMANCE_DOC].split(marker)
        original_prefix, encoded_binding = prefix.split(correction)
        current_binding = SUCCESSOR.parse(encoded_binding[:-5]) if binding is None else binding
        current_legacy = SUCCESSOR.parse(encoded[:-5]) if legacy is None else legacy
        old_suffix = correction + encoded_binding
        suffix = correction + SUCCESSOR.canonical(current_binding) + b"\n```\n"
        self.assertTrue(current_legacy["documentSuffix"].endswith(old_suffix.decode()))
        current_legacy["documentSuffix"] = current_legacy["documentSuffix"][:-len(old_suffix.decode())] + suffix.decode()
        changed[SUCCESSOR.PERFORMANCE_DOC] = original_prefix + suffix + marker + SUCCESSOR.canonical(current_legacy) + b"\n```\n"
        return changed

    def test_all_five_current_stages_keep_exact_path_and_method_sets(self):
        for stage, count in ((2,127), (3,135), (4,141), (5,146), (6,151)):
            with self.subTest(stage=stage):
                rows, sources, expected = self.vector(stage)
                result, methods, _, binding, _ = _successor_correction_validate(rows, sources)
                self.assertEqual((result["stage"], len(rows)), (stage, count))
                self.assertEqual(methods, expected)
                self.assertEqual(len(binding["addedTestIds"]), 8)
                self.assertFalse(result["nativeAcceptance"])
                self.exercise_method(rows, sources, expected)
        actual_rows, actual_sources = SUCCESSOR.tracked_inventory(ROOT)
        _, methods, _, _, _ = _successor_correction_validate(actual_rows, actual_sources)
        observed = {}
        for root in SUITE_ROOTS:
            observed.update({root + "/" + p: ids for p, ids in isolated_inventory(ROOT / root).items()})
        self.assertEqual(observed, methods)

    def test_partial_future_and_unapproved_paths_refuse(self):
        rows, sources, _ = self.vector(3)
        for fault in ("missing", "extra", "partial", "duplicate", "out-of-order"):
            changed = dict(sources)
            if fault == "missing": changed.pop("src/harness_conformance/live_proxy_client.py")
            if fault == "extra": changed["src/harness_conformance/unapproved.py"] = b"inert"
            if fault == "partial": changed["src/harness_conformance/live_fixed_probes.py"] = b"inert"
            if fault == "out-of-order":
                for path in _successor_correction_spec()["successorPaths"]["4"]: changed[path] = b"inert"
                changed.pop("src/harness_conformance/live_proxy_client.py")
            candidate = self.rows(changed)
            if fault == "duplicate": candidate.append(candidate[0])
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                _successor_correction_validate(candidate, changed)

    def test_missing_duplicate_or_shadowed_methods_refuse(self):
        rows, sources, expected = self.vector(3)
        path = "tests/live_backend/test_proxy_client.py"
        fixtures = (b"class Empty: pass\n", b"class Duplicate:\n def test_a(self): pass\n def test_a(self): pass\n",
            b"class Shadow:\n def test_a(self): pass\nclass Shadow:\n def test_b(self): pass\n",
            b"def load_tests(a,b,c): return b\nclass T:\n def test_a(self): pass\n",
            b"class T:\n @unittest.skip('hidden')\n def test_a(self): pass\n")
        for raw in fixtures:
            changed = dict(sources, **{path: raw})
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                _successor_correction_validate(self.rows(changed), changed)
        for fault in ("missing-module", "missing-method", "extra-method", "duplicate-method"):
            observed = deepcopy(expected)
            if fault == "missing-module": observed.pop(path)
            if fault == "missing-method": observed[path] = []
            if fault == "extra-method": observed[path] += ["Unapproved.test_extra"]
            if fault == "duplicate-method": observed[path] *= 2
            with self.subTest(fault=fault), self.assertRaises(AssertionError):
                self.exercise_method(rows, sources, observed)

    def test_final_hook_delta_is_verified_not_exempted(self):
        _, sources, _ = self.vector(6)
        hook = SUCCESSOR.RECORD["hook"]
        for fault in ("prefix", "suffix", "missing-proof", "identity", "repeated-proof"):
            changed = dict(sources)
            if fault == "prefix": changed[hook["path"]] = b"# unreviewed\n" + changed[hook["path"]]
            if fault == "suffix": changed[hook["path"]] += b"\n"
            if fault == "missing-proof": changed[hook["proofPath"]] = b"# absent\n"
            if fault == "identity": changed[hook["proofPath"]] = changed[hook["proofPath"]].replace(b'"SOURCE_DELTA_ONLY"', b'"NATIVE_PASS"')
            if fault == "repeated-proof": changed[hook["proofPath"]] *= 2
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                _successor_correction_validate(self.rows(changed), changed)

    def test_changed_current_predecessor_bytes_refuse(self):
        _, sources, _ = self.vector(3)
        for path in ("README.md", "src/harness_conformance/crypto.py", "tests/live_backend/_inventory.py", "toolchain.lock"):
            changed = dict(sources)
            changed[path] += b"\n# unreviewed\n"
            with self.subTest(path=path), self.assertRaises(ValueError):
                _successor_correction_validate(self.rows(changed), changed)

    def test_legacy_projection_and_corrective_binding_tampering_refuse(self):
        rows, sources, _ = self.vector(2)
        _, binding, legacy = _successor_correction_parts(sources)
        for field in binding:
            changed = deepcopy(binding)
            changed[field] = ["Wrong.test_identity"] if field == "addedTestIds" else "WRONG"
            resealed = self.rebind_document(sources, binding=changed)
            with self.subTest(binding=field), self.assertRaises(ValueError):
                _successor_correction_validate(self.rows(resealed), resealed)
        for field in ("packetId", "authorityDigest", "baseCommit"):
            changed = deepcopy(legacy)
            changed[field] = "WRONG"
            resealed = self.rebind_document(sources, legacy=changed)
            with self.subTest(legacy=field), self.assertRaisesRegex(ValueError, "original proof unchanged"):
                _successor_correction_validate(self.rows(resealed), resealed)
        for field in ("nativeAcceptance", "tenantAcceptance"):
            changed = dict(binding, **{field: True})
            resealed = self.rebind_document(sources, binding=changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                _successor_correction_validate(self.rows(resealed), resealed)

    def test_scope_excludes_runtime_arithmetic_and_benchmark_changes(self):
        _, sources, _ = self.vector(2)
        before, _, legacy = _successor_correction_parts(sources)
        spec = _successor_correction_spec()
        self.assertEqual(set(before), {SUCCESSOR.PERFORMANCE_DOC, SUCCESSOR.PERFORMANCE_TEST})
        self.assertEqual(len(spec["checkpoint"]["files"]) - len(before), 125)
        self.assertEqual(sum(map(len, spec["checkpoint"]["tests"].values())), 354)
        name = "PerformanceArithmeticTests.test_fixed_three_sample_workload"
        start, end = _successor_correction_region(sources[SUCCESSOR.PERFORMANCE_TEST], name)
        self.assertEqual(hashlib.sha256(sources[SUCCESSOR.PERFORMANCE_TEST][start:end]).hexdigest(), SUCCESSOR.PERFORMANCE_BENCHMARK_SHA256)
        # Reseal a syntactically admissible private arithmetic edit. The old v4
        # grammar can represent it, but this two-path correction must refuse it.
        path = "src/harness_conformance/crypto.py"
        changed = deepcopy(legacy)
        changed["sources"][path]["regions"]["_add"] += "    # unreviewed arithmetic scope\n"
        changed_sources = dict(sources)
        original = changed["beforeSources"][path].encode()
        start, end = _successor_correction_region(original, "_add")
        raw = original[:start] + changed["sources"][path]["regions"]["_add"].encode() + original[end:]
        changed["sources"][path]["afterSha256"] = hashlib.sha256(raw).hexdigest()
        changed_sources[path] = raw
        resealed = self.rebind_document(changed_sources, legacy=changed)
        with self.assertRaisesRegex(ValueError, "original proof unchanged"):
            _successor_correction_validate(self.rows(resealed), resealed)

    def test_current_correction_is_checked_before_historical_comparison(self):
        rows, sources, _ = self.vector(2)
        _, binding, _ = _successor_correction_parts(sources)
        forged = dict(binding, afterTestSha256="0" * 64)
        changed = self.rebind_document(sources, binding=forged)
        for name in ("performance_history", "validate_composition"):
            with patch.object(SUCCESSOR, name, side_effect=AssertionError("legacy view reached")) as historical:
                with self.assertRaisesRegex(ValueError, "exact independent binding"):
                    _successor_correction_validate(self.rows(changed), changed)
                historical.assert_not_called()
        _successor_correction_validate(rows, sources)
        with self.assertRaises(ValueError):
            _successor_correction_validate(self.rows(changed), changed)
