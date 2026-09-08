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
