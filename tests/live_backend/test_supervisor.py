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
        actual = {row["path"]: row for row in rows}
        for path, expected in baseline["files"].items():
            # Only the already accepted exact final-hook proof permits the
            # closed CONF-LIVE-006 launcher delta; presence alone never does.
            if result["stage"] == 6 and path == SUCCESSOR.RECORD["hook"]["path"]:
                continue
            raw, observed = sources[path], actual[path]
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
    doc = SUCCESSOR.regular_bytes(ROOT, "docs/live-backend/linux-boundary.md")
    marker = b"```harness-credential-source-proof\n"
    if doc.count(marker) != 1:
        raise ValueError("unique credential proof required")
    raw = doc.split(marker, 1)[1].split(b"\n```", 1)[0]
    proof = SUCCESSOR.parse(raw)
    if SUCCESSOR.canonical(proof) != raw:
        raise ValueError("canonical credential proof required")
    record = _credential_record()
    paths = set(record["change"]["sourceRegions"]) | set(record["change"]["testRegions"]) | {record["change"]["documentPath"]}
    after = {p: SUCCESSOR.regular_bytes(ROOT, p) for p in paths}
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
    result = SUCCESSOR.validate_composition(rows, sources[hook["path"]], hook_proof)
    if result["stage"] < 2:
        raise ValueError("credential correction requires stage two or later")
    current = {r["path"]: r for r in rows}
    for path, expected in checkpoint["files"].items():
        raw = sources[path]
        digest, size, blob = expected["sha256"], expected["size"], expected["blob"]
        if path in after or path == hook["path"] and result["stage"] == 6:
            # Exact five-file proof or the independently checked final-hook
            # delta, not a permissive current-file hash exception.
            if path in after and raw != after[path]:
                raise ValueError("inventory and proof bytes differ")
            digest, size = "sha256:" + hashlib.sha256(raw).hexdigest(), len(raw)
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        observed = current[path]
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
        self.assertEqual(result["stage"], 2)
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
