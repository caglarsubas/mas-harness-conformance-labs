"""LEDGER-E09 (TG-02, W04-3, CONF-ENF-003): the R12 reader's private factory and dynamic guards.

Subject: R12's own reader, src/harness_conformance/live_proxy_server.py (owner decision Q-T9, 2026-10-13). Its source was
read only to locate the factory-owned classes, their guard state and their cleanup rows. Every expected outcome comes
from the plan's obligation E09 (docs/alpha-2/ENFORCEMENT_FEASIBILITY.md row E09: reentrancy, wrong owner, partial
construction and state corruption fail sticky; an explicit trusted-code boundary) and acceptance A02
(docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md: real fixed factories, wrong roles and owners, dynamic peer overrides,
sticky failure, original deadlines, partial acquisition and original-resource-only cleanup). A refusal is the reader's
own ConformanceError; no test depends on a reason code. PROPERTIES maps each E09/A02 property to the tests that show it,
or to the reason it is not run here; the TG-02 ledger reads it, and the case is PASS only when every property ran.

Trusted-code boundary (declared): the guards check state the reader keeps in ordinary Python objects. A process that
rewrites a guard's code, or every guarded field consistently, is outside what in-process checks can detect (E09: no
assumption that a kernel policy prevents Python attribute corruption); external enforcement owns that boundary. The
tests show that each single inconsistent field, owner, role, thread, process, resource or deadline is refused, and that
failure, reentrancy and cleanup are sticky.

Not run here (both need the enrolled Linux host; W06's native run): fixed factories on an enrolled Linux host, and the
per-tick peer substitution checks of the observer and broker inspections.
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

# Every factory-owned kernel view with a custody tick and a phase, and the attribute naming its parent view (if any).
VIEWS = {reader._KernelNativeReads: None, reader._KernelRootViews: None, reader._KernelProcessView: "roots",
         reader._KernelPolicyView: "roots", reader._KernelCodeFiles: "roots", reader._KernelProcessCode: "process",
         reader._KernelCgroupView: "process", reader._KernelBpfView: "cgroup"}
# Views that own descriptors: (class, rows container, row tail, extra fields close() reads).
OWNING_VIEWS = (
    (reader._KernelRootViews, list, (None,), {}),
    (reader._KernelProcessView, list, (None,), {"pidfd": [None, None]}),
    (reader._KernelPolicyView, list, (None,), {"epoch_original": None, "epoch_mapping": None}),
    (reader._KernelCodeFiles, dict, (None,), {"layouts": {}}),
    (reader._KernelProcessCode, dict, (None,), {"original": None}),
    (reader._KernelCgroupView, list, (None,), {}),
    (reader._KernelBpfView, list, ("program", None), {}),  # (fd, identity, name, observed); no program ID rechecked
)

PROPERTIES = [
    {"property": "reentrancy fails sticky", "source": "E09", "result": "PASS", "reason": None,
     "tests": ["StickyPhaseTests.test_a_busy_view_refuses_a_second_phase", "StickyPhaseTests.test_reentrancy_is_refused_and_sticky"]},
    {"property": "wrong owner, process or thread is refused", "source": "E09; A02 wrong owners", "result": "PASS", "reason": None,
     "tests": ["CustodyTickTests.test_another_thread_is_refused", "CustodyTickTests.test_a_subclass_instance_is_refused",
               "CustodyTickTests.test_a_foreign_inspection_owner_is_refused",
               "CustodyTickTests.test_an_unbound_view_is_refused_while_a_server_is_installed",
               "OwnerTests.test_the_installed_server_passes_its_owner_check",
               "OwnerTests.test_a_server_that_is_not_the_installed_one_is_refused",
               "OwnerTests.test_a_closed_server_another_process_or_thread_or_an_imitation_is_refused",
               "OwnerTests.test_no_caller_constructs_a_qualification_binding",
               "OwnerTests.test_the_self_inspection_takes_its_binding_only_from_the_installed_server",
               "OwnerTests.test_inspections_refuse_a_wrong_owner_or_peer"]},
    {"property": "partial construction never grants custody and fails sticky", "source": "E09", "result": "PASS", "reason": None,
     "tests": ["PartialConstructionTests.test_a_view_built_without_its_constructor_is_never_usable",
               "PartialConstructionTests.test_a_binding_whose_load_fails_is_poisoned_for_good"]},
    {"property": "state corruption fails sticky", "source": "E09; A02 sticky failure", "result": "PASS", "reason": None,
     "tests": ["CustodyTickTests.test_the_custody_state_itself_is_accepted", "CustodyTickTests.test_each_inconsistent_state_field_is_refused",
               "StickyPhaseTests.test_an_idle_view_runs_a_phase", "StickyPhaseTests.test_a_closed_or_failed_view_refuses_a_phase",
               "StickyPhaseTests.test_a_failure_inside_a_phase_is_sticky", "StickyPhaseTests.test_a_parent_view_failure_is_sticky"]},
    {"property": "an explicit trusted-code boundary", "source": "E09", "result": "PASS", "reason": None,
     "tests": ["BoundaryTests.test_the_trusted_code_boundary_and_the_gaps_are_declared"]},
    {"property": "fixed factories fail closed outside their fixed host ABI", "source": "A02 real fixed factories", "result": "PASS",
     "reason": None, "tests": ["PartialConstructionTests.test_the_fixed_factories_refuse_a_host_outside_their_abi"]},
    {"property": "fixed factories on an enrolled Linux host: construction and original deadlines over real kernel I/O",
     "source": "A02 real fixed factories", "result": "NOT_RUN_ENV_UNAVAILABLE", "tests": [],
     "reason": "needs the enrolled Linux host and its kernel views; W06's native run"},
    {"property": "wrong roles are refused", "source": "A02 wrong roles", "result": "PASS", "reason": None,
     "tests": ["RoleTests.test_a_process_view_refuses_a_role_outside_the_fixed_set"]},
    {"property": "dynamic peer overrides at inspection construction", "source": "A02 dynamic peer overrides", "result": "PASS",
     "reason": None, "tests": ["OwnerTests.test_an_inspection_refuses_a_peer_that_is_not_bound_to_it",
                               "OwnerTests.test_inspections_refuse_a_wrong_owner_or_peer"]},
    {"property": "dynamic peer overrides: per-tick peer substitution of the observer and broker inspections",
     "source": "A02 dynamic peer overrides", "result": "NOT_RUN_ENV_UNAVAILABLE", "tests": [],
     "reason": "needs a constructed server with live peer sockets and pidfds (Linux only); W06's native run"},
    {"property": "original deadlines and fresh clocks", "source": "A02 original deadlines", "result": "PASS", "reason": None,
     "tests": ["CustodyTickTests.test_each_inconsistent_state_field_is_refused",
               "StickyPhaseTests.test_an_overrun_deadline_fails_the_phase_and_sticks"]},
    {"property": "a retained original resource that is replaced or ends is refused", "source": "A02 original resources",
     "result": "PASS", "reason": None,
     "tests": ["RetainedResourceTests.test_the_retained_pidfd_must_stay_the_original_and_alive"]},
    {"property": "partial acquisition", "source": "A02 partial acquisition", "result": "PASS", "reason": None,
     "tests": ["CleanupTests.test_cleanup_of_only_original_resources_succeeds",
               "CleanupTests.test_cleanup_closes_only_original_resources_and_the_failure_sticks"]},
    {"property": "original-resource-only cleanup under substitution", "source": "A02 original-resource-only cleanup", "result": "PASS",
     "reason": None,
     "tests": ["CleanupTests.test_cleanup_closes_only_original_resources_and_the_failure_sticks",
               "CleanupTests.test_a_process_view_closes_its_original_pidfd_only",
               "CleanupTests.test_the_server_files_close_only_their_original_descriptors",
               "CleanupTests.test_an_inspection_closes_its_retained_resources_not_substitutes",
               "CleanupTests.test_the_server_closes_its_original_broker_not_a_substitute"]},
]


class Reached(Exception):
    """Raised by a stand-in to show that the subject got past the guard under test."""


class Parent:
    """A stand-in parent or root view: its ticks, checks and phase succeed, or fail on demand."""

    def __init__(self, failing=False):
        self.failing = failing

    def _tick(self):
        if self.failing:
            raise RuntimeError("parent view failure")

    check = _compare = _observe = _tick

    @contextmanager
    def _phase(self):
        self._tick()
        yield
        self._tick()


class Closable:
    """A stand-in owned resource that records whether it was closed."""

    def __init__(self):
        self.closed, self.calls = False, 0

    def close(self):
        self.closed, self.calls = True, self.calls + 1


@contextmanager
def active(server):
    """The reader's one installed server for the duration of a test, restored afterwards."""
    previous, reader._ACTIVE = reader._ACTIVE, server
    try:
        yield
    finally:
        reader._ACTIVE = previous


@contextmanager
def patched(owner, name, value):
    previous = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield
    finally:
        setattr(owner, name, previous)


def in_custody(cls, busy=True, parent=None, **fields):
    """An instance in the guard state its own phase holds, built without the Linux-only constructor."""
    view = object.__new__(cls)
    view.pid, view.thread = os.getpid(), threading.get_ident()
    view.closed = view.failed = False
    view.busy = busy
    view.last = time.monotonic()
    view.end = view.last + 2
    view.pidfd = [None, None]  # only _KernelProcessView reads it, as "no pidfd retained"
    if VIEWS.get(cls):
        setattr(view, VIEWS[cls], parent or Parent())
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


def server(cls=None, **fields):
    value = object.__new__(cls or reader.NativeProxyServer)
    value.pid, value.thread, value.closed = os.getpid(), threading.get_ident(), False
    value.qualification_binding = value.self_inspection = None
    for name, item in fields.items():
        setattr(value, name, item)
    return value


class CustodyTickTests(unittest.TestCase):
    """Wrong owner, thread, process, state corruption and original deadlines (E09, A02)."""

    def test_the_custody_state_itself_is_accepted(self):
        # Control: each refusal below differs from this accepted state in exactly one respect.
        for cls in VIEWS:
            with self.subTest(view=cls.__name__):
                in_custody(cls)._tick()

    def test_each_inconsistent_state_field_is_refused(self):
        now = time.monotonic()
        changes = {"closed": {"closed": True}, "failed": {"failed": True}, "outside a phase": {"busy": False},
                   "another process": {"pid": os.getpid() + 1}, "clock before the last tick": {"last": now + 60},
                   "deadline passed": {"last": now - 10, "end": now - 5}}
        for cls in VIEWS:
            for name, fields in changes.items():
                with self.subTest(view=cls.__name__, change=name), self.assertRaises(ConformanceError):
                    in_custody(cls, **fields)._tick()

    def test_another_thread_is_refused(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__):
                self.assertEqual([type(exc) for exc in from_another_thread(in_custody(cls)._tick)], [ConformanceError])

    def test_a_subclass_instance_is_refused(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                in_custody(type("Imitation", (cls,), {}))._tick()

    def test_a_foreign_inspection_owner_is_refused(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                in_custody(cls, _inspection_owner=object())._tick()

    def test_an_unbound_view_is_refused_while_a_server_is_installed(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__), active(object()), self.assertRaises(ConformanceError):
                in_custody(cls)._tick()


class StickyPhaseTests(unittest.TestCase):
    """Failure, reentrancy and an overrun deadline inside a phase leave the view failed for good (E09, A02)."""

    def assert_unusable(self, view):
        for _ in range(2):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    pass

    def test_an_idle_view_runs_a_phase(self):
        # Control for the refusals below.
        for cls in VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                for _ in range(2):
                    with view._phase():
                        pass

    def test_a_closed_or_failed_view_refuses_a_phase(self):
        for cls in VIEWS:
            for name in ("closed", "failed"):
                with self.subTest(view=cls.__name__, state=name):
                    self.assert_unusable(in_custody(cls, busy=False, **{name: True}))

    def test_a_busy_view_refuses_a_second_phase(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                with in_custody(cls, busy=True)._phase():
                    pass

    def test_a_failure_inside_a_phase_is_sticky(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with self.assertRaises(RuntimeError):
                    with view._phase():
                        raise RuntimeError("failure inside the phase")
                self.assert_unusable(view)

    def test_a_parent_view_failure_is_sticky(self):
        for cls, parent in VIEWS.items():
            if parent is None:
                continue
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False, parent=Parent(failing=True))
                with self.assertRaises(RuntimeError):
                    with view._phase():
                        pass
                setattr(view, parent, Parent())  # the parent recovers; the view stays failed
                self.assert_unusable(view)

    def test_reentrancy_is_refused_and_sticky(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with self.assertRaises(ConformanceError):
                    with view._phase():
                        with view._phase():
                            pass
                self.assert_unusable(view)

    def test_an_overrun_deadline_fails_the_phase_and_sticks(self):
        for cls in VIEWS:
            with self.subTest(view=cls.__name__):
                view = in_custody(cls, busy=False)
                with self.assertRaises(ConformanceError):
                    with view._phase():
                        view.end = time.monotonic() - 1
                self.assert_unusable(view)


class PartialConstructionTests(unittest.TestCase):
    """An object that did not pass through its fixed factory never gets custody (E09 partial construction, A02)."""

    def test_a_view_built_without_its_constructor_is_never_usable(self):
        # Never usable: every guard entry fails, on a missing field or a refusal.
        for cls in VIEWS:
            view = object.__new__(cls)
            for _ in range(2):
                with self.subTest(view=cls.__name__), self.assertRaises((AttributeError, ConformanceError)):
                    view._tick()
                with self.subTest(view=cls.__name__), self.assertRaises((AttributeError, ConformanceError)):
                    with view._phase():
                        pass

    def test_a_binding_whose_load_fails_is_poisoned_for_good(self):
        # Refused at the owner boundary before loading anything when the server is not the installed one; poisoned
        # for good when its load fails part way, so the half-built binding is never usable.
        for installed in (False, True):
            with self.subTest(installed=installed):
                owner = server(deadline=time.monotonic() + 100)
                binding = object.__new__(reader._ServerQualificationBinding)
                owner.qualification_binding, owner.files = binding, reader._Files(owner)
                with active(owner if installed else None):
                    with self.assertRaises(Exception):
                        binding.__init__(owner)
                    self.assertIs(binding.poisoned, installed)
                    if installed:
                        with self.assertRaises(ConformanceError):
                            binding.check()

    def test_the_fixed_factories_refuse_a_host_outside_their_abi(self):
        # Hosts outside the fixed ABI stay unavailable: construction fails closed and returns nothing.
        with patched(sys, "platform", "unsupported-host"):
            for cls in (reader._KernelNativeReads, reader._KernelRootViews):
                with self.subTest(view=cls.__name__), self.assertRaises(ConformanceError):
                    cls()


class OwnerTests(unittest.TestCase):
    """Only the installed server, in its own process and thread, owns the qualification factory (E09, A02)."""

    def test_the_installed_server_passes_its_owner_check(self):
        owner = server()
        with active(owner):
            owner._owner_check()

    def test_a_server_that_is_not_the_installed_one_is_refused(self):
        owner = server()
        for installed in (None, object(), server()):
            with self.subTest(installed=type(installed).__name__), active(installed), self.assertRaises(ConformanceError):
                owner._owner_check()

    def test_a_closed_server_another_process_or_thread_or_an_imitation_is_refused(self):
        for fields in ({"closed": True}, {"pid": os.getpid() + 1}):
            changed = server(**fields)
            with self.subTest(change=sorted(fields)), active(changed), self.assertRaises(ConformanceError):
                changed._owner_check()
        owner = server()
        with active(owner):
            self.assertEqual([type(exc) for exc in from_another_thread(owner._owner_check)], [ConformanceError])
        imitation = server(type("Imitation", (reader.NativeProxyServer,), {}))
        with active(imitation), self.assertRaises(ConformanceError):
            imitation._owner_check()

    def test_no_caller_constructs_a_qualification_binding(self):
        # A wrong owner is refused, and so is the installed server when it did not ask for this binding.
        with self.assertRaises(ConformanceError):
            reader._ServerQualificationBinding(object())
        owner = server()
        with active(owner), self.assertRaises(ConformanceError):
            reader._ServerQualificationBinding(owner)

    def test_the_self_inspection_takes_its_binding_only_from_the_installed_server(self):
        for installed in (False, True):
            with self.subTest(installed=installed):
                owner = server(deadline=time.monotonic() + 100)
                binding = object.__new__(reader._ServerQualificationBinding)
                binding.owner = owner
                inspection = object.__new__(reader._KernelSelfInspection)
                owner.qualification_binding, owner.self_inspection = binding, inspection
                with active(owner if installed else None), self.assertRaises(Exception):
                    inspection.__init__(owner)
                self.assertEqual(getattr(inspection, "binding", None) is binding, installed)

    def test_an_inspection_refuses_a_peer_that_is_not_bound_to_it(self):
        # The peer must name this inspection as its own; only then is the installed server's binding taken.
        for cls, kind, slots in ((reader._KernelObserverInspection, reader._Observer, ("observer",)),
                                 (reader._KernelBrokerInspection, reader._Broker, ("broker", "_broker_original"))):
            for bound in (False, True):
                with self.subTest(inspection=cls.__name__, bound=bound):
                    owner = server()
                    peer = object.__new__(kind)
                    inspection = object.__new__(cls)
                    peer.owner, peer.inspection = owner, inspection if bound else None
                    for slot in slots:
                        setattr(owner, slot, peer)
                    with active(owner), self.assertRaises(Exception):
                        inspection.__init__(peer)
                    self.assertEqual(hasattr(inspection, "binding"), bound)

    def test_inspections_refuse_a_wrong_owner_or_peer(self):
        for cls, argument in ((reader._KernelSelfInspection, object()), (reader._KernelObserverInspection, object()),
                              (reader._KernelBrokerInspection, object()), (reader._KernelObserverInspection, server()),
                              (reader._KernelBrokerInspection, server())):
            with self.subTest(inspection=cls.__name__, argument=type(argument).__name__), self.assertRaises(ConformanceError):
                cls(argument)


class RoleTests(unittest.TestCase):
    """A02 wrong roles: a process view is only ever built for one of the fixed roles."""

    def test_a_process_view_refuses_a_role_outside_the_fixed_set(self):
        def reached(*args, **kwargs):
            raise Reached()
        roots = object.__new__(reader._KernelRootViews)
        other = os.getpid() + 1
        with patched(reader, "document", reached):
            for role, pid in (("OBSERVER", 2), ("BROKER", other), ("WORKER", other), ("SERVER", os.getpid())):
                with self.subTest(role=role, pid=pid), self.assertRaises(Reached):
                    reader._KernelProcessView(roots, pid, role, {})
            for role, pid in (("ADMIN", 2), ("server", 2), (None, 2), ("SERVER", other)):
                with self.subTest(role=role, pid=pid), self.assertRaises(ConformanceError):
                    reader._KernelProcessView(roots, pid, role, {})


class RetainedResourceTests(unittest.TestCase):
    """A02: a retained original resource is rechecked on every tick; a replaced or ended one is refused."""

    def test_the_retained_pidfd_must_stay_the_original_and_alive(self):
        changes = ("replaced", "inheritable", "ended")
        for change in (None, *changes):
            with self.subTest(change=change):
                read, write = os.pipe()
                other_read, other_write = os.pipe()
                try:
                    view = in_custody(reader._KernelProcessView, pidfd=[read, identity(read)])
                    if change == "replaced":
                        os.dup2(other_read, read, inheritable=False)
                    elif change == "inheritable":
                        os.set_inheritable(read, True)
                    elif change == "ended":
                        os.close(write)
                        write = None
                    if change is None:
                        view._tick()  # control
                    else:
                        with self.assertRaises(ConformanceError):
                            view._tick()
                finally:
                    for fd in (read, write, other_read, other_write):
                        if fd is not None:
                            os.close(fd)


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

    def substituted(self, name):
        """A descriptor whose recorded identity is of one file while its number now names another."""
        replaced, substitute = self.open(name + "-b"), self.open(name + "-c")
        pin = identity(replaced)
        os.dup2(substitute, replaced)
        return replaced, pin, substitute

    def rows(self, container, entries):
        if container is dict:
            return {"row%d" % index: entry for index, entry in enumerate(entries)}
        return list(entries)

    def view(self, cls, extra):
        view = in_custody(cls, busy=False, cleanup_failure=None, **extra)
        if cls is reader._KernelRootViews:
            view.native = object.__new__(reader._KernelNativeReads)
        return view

    def assert_sticky_close(self, close, replaced, substitute):
        with self.assertRaises(ConformanceError) as first:
            close()
        self.assertEqual(identity(replaced), identity(substitute))  # the substitute was left alone
        with self.assertRaises(ConformanceError) as second:
            close()
        self.assertIs(second.exception, first.exception)  # sticky: the same failure, no retry
        self.assertEqual(identity(replaced), identity(substitute))

    def test_cleanup_closes_only_original_resources_and_the_failure_sticks(self):
        for cls, container, tail, extra in OWNING_VIEWS:
            with self.subTest(view=cls.__name__):
                original = self.open("a-" + cls.__name__)
                replaced, pin, substitute = self.substituted(cls.__name__)
                view = self.view(cls, extra)
                # An original row, a row never acquired (partial acquisition) and a substituted row.
                view.rows = self.rows(container, [(original, identity(original), *tail), (None, None, *tail),
                                                  (replaced, pin, *tail)])
                self.assert_sticky_close(view.close, replaced, substitute)
                with self.assertRaises(OSError):
                    os.fstat(original)  # the original resource was released

    def test_cleanup_of_only_original_resources_succeeds(self):
        # Control: without a substitution every acquired row is released and nothing is retained.
        for cls, container, tail, extra in OWNING_VIEWS:
            with self.subTest(view=cls.__name__):
                first, second = self.open("d-" + cls.__name__), self.open("e-" + cls.__name__)
                view = self.view(cls, extra)
                view.rows = self.rows(container, [(first, identity(first), *tail), (None, None, *tail),
                                                  (second, identity(second), *tail)])
                view.close()
                for fd in (first, second):
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                view.close()

    def test_a_process_view_closes_its_original_pidfd_only(self):
        original = self.open("pidfd-a")
        view = self.view(reader._KernelProcessView, {"pidfd": [original, identity(original)]})
        view.rows = []
        view.close()
        with self.assertRaises(OSError):
            os.fstat(original)
        replaced, pin, substitute = self.substituted("pidfd")
        view = self.view(reader._KernelProcessView, {"pidfd": [replaced, pin]})
        view.rows = []
        self.assert_sticky_close(view.close, replaced, substitute)

    def test_the_server_files_close_only_their_original_descriptors(self):
        original, replaced, substitute = self.open("files-a"), self.open("files-b"), self.open("files-c")
        pins = {fd: reader._custody_identity(os.fstat(fd)) for fd in (original, replaced)}  # the server's own pin form
        os.dup2(substitute, replaced)
        files = reader._Files(None)
        files.rows = {"/a": (original, None, "a", pins[original]), "/b": (replaced, None, "b", pins[replaced])}
        self.assert_sticky_close(files.close, replaced, substitute)
        with self.assertRaises(OSError):
            os.fstat(original)

    def test_an_inspection_closes_its_retained_resources_not_substitutes(self):
        inspection = object.__new__(reader._KernelSelfInspection)
        inspection.closed, inspection.cleanup_failure = False, None
        retained, current, untouched = Closable(), Closable(), Closable()
        inspection.owned = [("roots", retained), ("policy", untouched)]
        inspection.roots, inspection.policy = current, untouched
        inspection.close()
        self.assertEqual((retained.calls, current.calls, untouched.calls), (1, 0, 1))
        self.assertIs(inspection.roots, current)  # a substitute is neither closed nor adopted
        inspection.close()
        self.assertEqual((retained.calls, current.calls, untouched.calls), (1, 0, 1))

    def test_the_server_closes_its_original_broker_not_a_substitute(self):
        original, substitute = Closable(), Closable()
        owner = server(_broker_original=original, broker=substitute, memfd=None)
        with active(owner):
            owner.close()
            self.assertIsNone(reader._ACTIVE)
        self.assertEqual((original.calls, substitute.calls), (1, 0))


class BoundaryTests(unittest.TestCase):
    def test_the_trusted_code_boundary_and_the_gaps_are_declared(self):
        # E09's explicit trusted-code boundary, and every property not run here, are stated in this module.
        text = " ".join((__doc__ or "").split())
        self.assertIn("Trusted-code boundary (declared)", text)
        self.assertIn("external enforcement owns that boundary", text)
        gaps = [row for row in PROPERTIES if row["result"] != "PASS"]
        self.assertEqual(len(gaps), 2)
        self.assertIn("fixed factories on an enrolled Linux host", text)
        self.assertIn("per-tick peer substitution checks of the observer and broker inspections", text)


if __name__ == "__main__":
    unittest.main()
