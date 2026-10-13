"""LEDGER-E09 (TG-02, W04-3, CONF-ENF-003): the R12 reader's private factory and dynamic guards.

Subject: R12's own reader, src/harness_conformance/live_proxy_server.py (owner decision Q-T9, 2026-10-13). Its source was
read only to locate the factory-owned classes, their guard state and their cleanup rows. Every expected outcome comes
from the plan's obligation E09 (docs/alpha-2/ENFORCEMENT_FEASIBILITY.md row E09: reentrancy, wrong owner, partial
construction and state corruption fail sticky; an explicit trusted-code boundary) and acceptance A02
(docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md: real fixed factories, wrong roles and owners, sticky failure, original
deadlines, partial acquisition and original-resource-only cleanup). A refusal is the reader's own ConformanceError.

Trusted-code boundary (declared, not tested): the guards check state the reader keeps in ordinary Python objects. A
process that rewrites a guard's code, or every guarded field consistently, is outside what in-process checks can detect
(E09: no assumption that a kernel policy prevents Python attribute corruption); external enforcement owns that boundary.
These tests show that each single inconsistent field, owner, thread, process or deadline is refused, and that failure,
reentrancy and cleanup are sticky. Not covered here: the per-tick peer substitution checks of the observer and broker
inspections, which need a constructed server with live sockets and pidfds (Linux only).
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from harness_conformance import live_proxy_server as reader  # noqa: E402
from harness_conformance.errors import ConformanceError  # noqa: E402

# Factory-owned kernel views whose custody tick depends only on their own state (the others tick their parent view).
LEAF_VIEWS = (reader._KernelNativeReads, reader._KernelRootViews, reader._KernelProcessView, reader._KernelPolicyView,
              reader._KernelCodeFiles)
# Views whose phase runs only their own ticks, so failure and reentrancy can be shown without a parent view.
PHASED_VIEWS = (reader._KernelNativeReads, reader._KernelRootViews)
# Views that own descriptors: (class, rows container, extra fields close() reads).
OWNING_VIEWS = (
    (reader._KernelRootViews, list, {}),
    (reader._KernelProcessView, list, {"pidfd": [None, None]}),
    (reader._KernelPolicyView, list, {"epoch_original": None, "epoch_mapping": None}),
    (reader._KernelCodeFiles, dict, {"layouts": {}}),
    (reader._KernelProcessCode, dict, {"original": None}),
    (reader._KernelCgroupView, list, {}),
)


@contextmanager
def active(server):
    """The reader's one installed server for the duration of a test, restored afterwards."""
    previous, reader._ACTIVE = reader._ACTIVE, server
    try:
        yield
    finally:
        reader._ACTIVE = previous


def in_custody(cls, **fields):
    """An instance in the guard state its own phase holds, built without the Linux-only constructor."""
    view = object.__new__(cls)
    view.pid, view.thread = os.getpid(), threading.get_ident()
    view.closed = view.failed = False
    view.busy = True
    view.last = time.monotonic()
    view.end = view.last + 2
    view.pidfd = [None, None]  # only _KernelProcessView reads it, as "no pidfd retained"
    for name, value in fields.items():
        setattr(view, name, value)
    return view


def from_another_thread(call):
    caught = []
    def run():
        try:
            call()
        except BaseException as exc:  # recorded for the asserting thread
            caught.append(exc)
    worker = threading.Thread(target=run)
    worker.start()
    worker.join(10)
    return caught


def identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


class CustodyTickTests(unittest.TestCase):
    """Wrong owner, thread, process, state corruption and original deadlines (E09, A02)."""

    def test_the_custody_state_itself_is_accepted(self):
        # Control: each refusal below differs from this accepted state in exactly one respect.
        for cls in LEAF_VIEWS:
            with self.subTest(view=cls.__name__):
                in_custody(cls)._tick()

    def test_each_inconsistent_state_field_is_refused(self):
        now = time.monotonic()
        changes = {"closed": {"closed": True}, "failed": {"failed": True}, "outside a phase": {"busy": False},
                   "another process": {"pid": os.getpid() + 1}, "clock before the last tick": {"last": now + 60},
                   "deadline passed": {"last": now - 10, "end": now - 5}}
        for cls in LEAF_VIEWS:
            for name, fields in changes.items():
                with self.subTest(view=cls.__name__, change=name), self.assertRaises(ConformanceError):
                    in_custody(cls, **fields)._tick()

    def test_another_thread_is_refused(self):
        for cls in LEAF_VIEWS:
            with self.subTest(view=cls.__name__):
                caught = from_another_thread(in_custody(cls)._tick)
                self.assertEqual([type(exc) for exc in caught], [ConformanceError])

    def test_a_subclass_instance_is_refused(self):
        for cls in LEAF_VIEWS:
            with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                in_custody(type("Imitation", (cls,), {}))._tick()

    def test_a_foreign_inspection_owner_is_refused(self):
        for cls in LEAF_VIEWS:
            with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                in_custody(cls, _inspection_owner=object())._tick()

    def test_an_unbound_view_is_refused_while_a_server_is_installed(self):
        for cls in LEAF_VIEWS:
            with self.subTest(view=cls.__name__), active(object()), self.assertRaises(ConformanceError):
                in_custody(cls)._tick()


class StickyPhaseTests(unittest.TestCase):
    """Failure, reentrancy and an overrun deadline inside a phase stay failed (E09 sticky failure)."""

    def assert_unusable(self, view):
        for _ in range(2):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    pass

    def test_an_idle_view_runs_a_phase(self):
        # Control for the refusals below.
        for cls in PHASED_VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with view._phase():
                    pass
                with view._phase():
                    pass

    def test_a_failure_inside_a_phase_is_sticky(self):
        for cls in PHASED_VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with self.assertRaises(RuntimeError):
                    with view._phase():
                        raise RuntimeError("failure inside the phase")
                self.assert_unusable(view)

    def test_reentrancy_is_refused_and_sticky(self):
        for cls in PHASED_VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with self.assertRaises(ConformanceError):
                    with view._phase():
                        with view._phase():
                            pass
                self.assert_unusable(view)

    def test_an_overrun_deadline_fails_the_phase_and_sticks(self):
        for cls in PHASED_VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with self.assertRaises(ConformanceError):
                    with view._phase():
                        view.end = time.monotonic() - 1
                self.assert_unusable(view)

    def test_a_closed_view_refuses_a_phase(self):
        for cls in PHASED_VIEWS:
            with self.subTest(view=cls.__name__):
                self.assert_unusable(in_custody(cls, busy=False, closed=True))


class PartialConstructionTests(unittest.TestCase):
    """An object that did not pass through its fixed factory never gets custody (E09 partial construction, A02)."""

    def test_a_view_built_without_its_constructor_is_never_usable(self):
        for cls in LEAF_VIEWS:
            view = object.__new__(cls)
            for _ in range(2):
                with self.subTest(view=cls.__name__), self.assertRaises((AttributeError, ConformanceError)):
                    view._tick()
                with self.subTest(view=cls.__name__), self.assertRaises((AttributeError, ConformanceError)):
                    with view._phase():
                        pass

    @unittest.skipIf(sys.platform == "linux", "on Linux the fixed factory may succeed; this host fact holds elsewhere")
    def test_the_fixed_factories_refuse_an_unsupported_host(self):
        # Unsupported hosts stay unavailable: construction fails closed and returns nothing.
        for cls in (reader._KernelNativeReads, reader._KernelRootViews):
            with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                cls()


class OwnerTests(unittest.TestCase):
    """Only the installed server, in its own process and thread, owns the qualification factory (E09, A02)."""

    def server(self, cls=None, **fields):
        server = object.__new__(cls or reader.NativeProxyServer)
        server.pid, server.thread, server.closed = os.getpid(), threading.get_ident(), False
        server.qualification_binding = None
        for name, value in fields.items():
            setattr(server, name, value)
        return server

    def test_the_installed_server_passes_its_owner_check(self):
        server = self.server()
        with active(server):
            server._owner_check()

    def test_a_server_that_is_not_the_installed_one_is_refused(self):
        server = self.server()
        for installed in (None, object(), self.server()):
            with self.subTest(installed=type(installed).__name__), active(installed), self.assertRaises(ConformanceError):
                server._owner_check()

    def test_a_closed_server_another_thread_or_an_imitation_is_refused(self):
        closed = self.server(closed=True)
        with active(closed), self.assertRaises(ConformanceError):
            closed._owner_check()
        server = self.server()
        with active(server):
            self.assertEqual([type(exc) for exc in from_another_thread(server._owner_check)], [ConformanceError])
        imitation = self.server(type("Imitation", (reader.NativeProxyServer,), {}))
        with active(imitation), self.assertRaises(ConformanceError):
            imitation._owner_check()

    def test_no_caller_constructs_a_qualification_binding(self):
        # A wrong owner is refused, and so is the installed server when it did not ask for this binding.
        with self.assertRaises(ConformanceError):
            reader._ServerQualificationBinding(object())
        server = self.server()
        with active(server), self.assertRaises(ConformanceError):
            reader._ServerQualificationBinding(server)

    def test_inspections_refuse_a_wrong_owner_or_peer(self):
        for cls, argument in ((reader._KernelSelfInspection, object()), (reader._KernelObserverInspection, object()),
                              (reader._KernelBrokerInspection, object()), (reader._KernelObserverInspection, self.server()),
                              (reader._KernelBrokerInspection, self.server())):
            with self.subTest(inspection=cls.__name__, argument=type(argument).__name__), self.assertRaises(ConformanceError):
                cls(argument)


class CleanupTests(unittest.TestCase):
    """Partial acquisition and original-resource-only cleanup under resource substitution (A02); the failure sticks."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.fds = []

    def tearDown(self):
        for fd in self.fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.scratch.cleanup()

    def open(self, name):
        fd = os.open(os.path.join(self.scratch.name, name), os.O_RDWR | os.O_CREAT, 0o600)
        self.fds.append(fd)
        return fd

    def rows(self, container, entries):
        if container is dict:
            return {"row%d" % index: entry for index, entry in enumerate(entries)}
        return list(entries)

    def test_cleanup_closes_only_original_resources_and_the_failure_sticks(self):
        for cls, container, extra in OWNING_VIEWS:
            with self.subTest(view=cls.__name__):
                original, replaced, substitute = self.open("a-" + cls.__name__), self.open("b-" + cls.__name__), self.open("c-" + cls.__name__)
                pins = identity(original), identity(replaced)
                os.dup2(substitute, replaced)  # the descriptor number now names another resource
                view = in_custody(cls, busy=False, cleanup_failure=None, **extra)
                if cls is reader._KernelRootViews:
                    view.native = object.__new__(reader._KernelNativeReads)
                # An original row, a row never acquired (partial acquisition) and a substituted row.
                view.rows = self.rows(container, [(original, pins[0], None), (None, None, None), (replaced, pins[1], None)])
                with self.assertRaises(ConformanceError) as first:
                    view.close()
                with self.assertRaises(OSError):
                    os.fstat(original)  # the original resource was released
                self.assertEqual(identity(replaced), identity(substitute))  # the substitute was left alone
                with self.assertRaises(ConformanceError) as second:
                    view.close()
                self.assertIs(second.exception, first.exception)  # sticky: the same failure, no retry
                self.assertEqual(identity(replaced), identity(substitute))

    def test_cleanup_of_only_original_resources_succeeds(self):
        # Control: without a substitution every acquired row is released and nothing is retained.
        for cls, container, extra in OWNING_VIEWS:
            with self.subTest(view=cls.__name__):
                first, second = self.open("d-" + cls.__name__), self.open("e-" + cls.__name__)
                view = in_custody(cls, busy=False, cleanup_failure=None, **extra)
                if cls is reader._KernelRootViews:
                    view.native = object.__new__(reader._KernelNativeReads)
                view.rows = self.rows(container, [(first, identity(first), None), (None, None, None), (second, identity(second), None)])
                view.close()
                for fd in (first, second):
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                view.close()


if __name__ == "__main__":
    unittest.main()
