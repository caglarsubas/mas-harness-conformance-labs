"""LEDGER-E09 (TG-02, W04-3, CONF-ENF-003): the R12 reader's private factory and dynamic guards.

Subject: R12's own reader, src/harness_conformance/live_proxy_server.py (owner decision Q-T9, 2026-10-13). Its source was
read only to locate the factory-owned classes, their guard state and their cleanup rows. Every expected outcome comes
from the plan's obligation E09 (docs/alpha-2/ENFORCEMENT_FEASIBILITY.md row E09: reentrancy, wrong owner, partial
construction and state corruption fail sticky; an explicit trusted-code boundary) and acceptance A02
(docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md: real fixed factories, wrong roles and owners, dynamic peer overrides,
sticky failure, original deadlines, partial acquisition and original-resource-only cleanup), with the parts of E07
(pidfds, exact peer credentials and broker parentage: replacement and channel loss deny, no rebinding) that the reader's
guards carry. A refusal is the reader's own ConformanceError (a view that never passed its constructor may instead fail on
a missing field). Where two guards in a row would both refuse, RoleTests reads a refusal's reason only to show which of
them refused; the expected outcome is still the refusal. PROPERTIES maps each property to the tests that show it, or to
the reason it is not run here and the plan case that carries it; the TG-02 ledger reads it.

Trusted-code boundary (declared): the guards check state the reader keeps in ordinary Python objects. A process that
rewrites a guard's code, or every guarded field consistently, is outside what in-process checks can detect (E09: no
assumption that a kernel policy prevents Python attribute corruption); external enforcement owns that boundary. The
tests show that each single inconsistent field, owner, role, thread, process, resource or deadline is refused, and that
failure, reentrancy and cleanup are sticky.

Not run here (both need the enrolled Linux host, and both are carried by W06 native cases of the plan): fixed factories on
an enrolled Linux host (TG-05 MATRIX:original deadlines), and the peer's kernel rechecks on each inspection tick
(SO_PEERCRED credentials, pidfd liveness and the socket path; TG-04 MATRIX:parent/FD spoof, TG-05 MATRIX:peer
death/restart).
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
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
    {"property": "reentrancy fails sticky", "source": "E09", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["StickyPhaseTests.test_a_busy_view_refuses_a_second_phase", "StickyPhaseTests.test_reentrancy_is_refused_and_sticky",
               "InspectionPhaseTests.test_a_reentrant_inspection_phase_is_refused_and_sticky"]},
    {"property": "wrong owner, process or thread is refused", "source": "E09; A02 wrong owners", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["CustodyTickTests.test_another_thread_is_refused", "CustodyTickTests.test_a_subclass_instance_is_refused",
               "CustodyTickTests.test_a_foreign_inspection_owner_is_refused",
               "CustodyTickTests.test_an_unbound_view_is_refused_while_a_server_is_installed",
               "OwnerTests.test_the_installed_server_passes_its_owner_check",
               "OwnerTests.test_a_server_that_is_not_the_installed_one_is_refused",
               "OwnerTests.test_a_closed_server_another_process_or_thread_or_an_imitation_is_refused",
               "OwnerTests.test_no_caller_constructs_a_qualification_binding",
               "OwnerTests.test_the_self_inspection_takes_its_binding_only_from_the_installed_server",
               "OwnerTests.test_child_views_are_built_only_on_their_own_idle_parent",
               "OwnerTests.test_inspections_refuse_a_wrong_owner_or_peer",
               "InspectionPhaseTests.test_an_inspection_whose_server_or_binding_changed_is_refused",
               "InspectionPhaseTests.test_an_inspection_refuses_a_reader_it_does_not_own"]},
    {"property": "partial construction never grants custody and fails sticky", "source": "E09", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["PartialConstructionTests.test_a_view_built_without_its_constructor_is_never_usable",
               "PartialConstructionTests.test_a_binding_whose_load_fails_is_poisoned_for_good",
               "CleanupTests.test_an_inspection_closes_a_half_built_root_views_native_reads"]},
    {"property": "state corruption fails sticky", "source": "E09; A02 sticky failure", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["CustodyTickTests.test_the_custody_state_itself_is_accepted", "CustodyTickTests.test_each_inconsistent_state_field_is_refused",
               "StickyPhaseTests.test_an_idle_view_runs_a_phase", "StickyPhaseTests.test_a_closed_or_failed_view_refuses_a_phase",
               "StickyPhaseTests.test_a_failure_inside_a_phase_is_sticky", "StickyPhaseTests.test_a_parent_view_failure_is_sticky",
               "InspectionPhaseTests.test_an_inspection_in_custody_runs_its_phases",
               "InspectionPhaseTests.test_a_failure_inside_an_inspection_phase_is_sticky",
               "InspectionPhaseTests.test_a_replaced_owned_view_fails_the_inspection_for_good"]},
    {"property": "an explicit trusted-code boundary", "source": "E09", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["BoundaryTests.test_the_trusted_code_boundary_and_the_gaps_are_declared"]},
    {"property": "fixed factories fail closed outside their fixed host ABI", "source": "A02 real fixed factories", "result": "PASS",
     "reason": None, "carriedBy": [], "tests": ["PartialConstructionTests.test_the_fixed_factories_refuse_a_host_outside_their_abi"]},
    {"property": "fixed factories on an enrolled Linux host: construction and original deadlines over real kernel I/O",
     "source": "A02 real fixed factories", "result": "NOT_RUN_ENV_UNAVAILABLE", "tests": [],
     "reason": "needs the enrolled Linux host and its kernel views", "carriedBy": ["TG-05 MATRIX:original deadlines"]},
    {"property": "wrong roles are refused", "source": "A02 wrong roles", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["RoleTests.test_a_process_view_refuses_a_role_outside_the_fixed_set",
               "RoleTests.test_code_and_cgroup_views_hold_only_their_process_views_role"]},
    {"property": "dynamic peer overrides at inspection construction", "source": "A02 dynamic peer overrides; E07 no rebinding",
     "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["OwnerTests.test_an_inspection_refuses_a_peer_or_server_that_is_not_bound_to_it",
               "OwnerTests.test_inspections_refuse_a_wrong_owner_or_peer"]},
    {"property": "dynamic peer overrides on every inspection tick: the in-process peer, server and pin checks",
     "source": "A02 dynamic peer overrides; E07 replacement, no rebinding", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["PeerTickTests.test_the_bound_peer_passes_its_tick_checks", "PeerTickTests.test_a_substituted_peer_or_pin_is_refused"]},
    {"property": "the peer's kernel rechecks on every inspection tick: SO_PEERCRED credentials, pidfd liveness and the socket path",
     "source": "E07 exact peer credentials, broker parentage and channel loss; A02 dynamic peer overrides",
     "result": "NOT_RUN_ENV_UNAVAILABLE", "tests": [], "reason": "needs live peer sockets and pidfds on the enrolled Linux host",
     "carriedBy": ["TG-04 MATRIX:parent/FD spoof", "TG-05 MATRIX:peer death/restart"]},
    {"property": "original deadlines and fresh clocks", "source": "A02 original deadlines", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["CustodyTickTests.test_each_inconsistent_state_field_is_refused",
               "StickyPhaseTests.test_an_overrun_deadline_fails_the_phase_and_sticks",
               "InspectionPhaseTests.test_an_inspection_whose_server_or_binding_changed_is_refused",
               "InspectionPhaseTests.test_an_inspection_phase_ends_at_the_servers_deadline"]},
    {"property": "a retained original resource that is replaced or ends is refused",
     "source": "A02 original resources; E07 PID reuse, crash and replacement", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["RetainedResourceTests.test_the_retained_pidfd_must_stay_the_original_and_alive"]},
    {"property": "partial acquisition", "source": "A02 partial acquisition", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["CleanupTests.test_cleanup_of_only_original_resources_succeeds",
               "CleanupTests.test_cleanup_closes_only_original_resources_and_the_failure_sticks",
               "CleanupTests.test_an_inspection_closes_a_half_built_root_views_native_reads"]},
    {"property": "original-resource-only cleanup under substitution", "source": "A02 original-resource-only cleanup", "result": "PASS",
     "reason": None, "carriedBy": [],
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
        # Only the installed server that names this inspection as its own hands over its binding (the observable).
        for change in (None, "server not installed", "server names another inspection"):
            with self.subTest(change=change):
                owner = server(deadline=time.monotonic() + 100)
                binding = object.__new__(reader._ServerQualificationBinding)
                binding.owner = owner
                inspection = object.__new__(reader._KernelSelfInspection)
                owner.qualification_binding = binding
                owner.self_inspection = object.__new__(reader._KernelSelfInspection) if change == "server names another inspection" else inspection
                with active(None if change == "server not installed" else owner), self.assertRaises(Exception):
                    inspection.__init__(owner)
                self.assertEqual(getattr(inspection, "binding", None) is binding, change is None)

    def test_an_inspection_refuses_a_peer_or_server_that_is_not_bound_to_it(self):
        # The peer must name this inspection, and the installed server must name this peer in every peer slot; only then
        # is the server's binding taken (the observable). Each change below is the only difference from the control.
        for cls, kind, slots in ((reader._KernelObserverInspection, reader._Observer, ("observer",)),
                                 (reader._KernelBrokerInspection, reader._Broker, ("broker", "_broker_original"))):
            changes = [None, "peer names another inspection", "server not installed"] + ["%s names another peer" % slot for slot in slots]
            for change in changes:
                with self.subTest(inspection=cls.__name__, change=change):
                    owner = server()
                    peer, other = object.__new__(kind), object.__new__(kind)
                    inspection = object.__new__(cls)
                    peer.owner, peer.inspection = owner, inspection
                    for slot in slots:
                        setattr(owner, slot, other if change == "%s names another peer" % slot else peer)
                    if change == "peer names another inspection":
                        peer.inspection = object.__new__(cls)
                    with active(None if change == "server not installed" else owner), self.assertRaises(Exception):
                        inspection.__init__(peer)
                    self.assertEqual(hasattr(inspection, "binding"), change is None)

    def test_child_views_are_built_only_on_their_own_idle_parent(self):
        # A code, cgroup or BPF view is built only on an idle, healthy parent view of the exact type (and a code view only
        # on a process view sharing its root views); reaching the next step shows the owner check passed.
        def reached(*args, **kwargs):
            raise Reached()
        roots, other_roots = object.__new__(reader._KernelRootViews), object.__new__(reader._KernelRootViews)
        def idle(cls, **fields):
            return in_custody(cls, busy=False, **fields)
        with patched(reader, "document", reached):
            for name, build in (
                    ("process code", lambda process, code: reader._KernelProcessCode(process, code, {})),
                    ("cgroup", lambda process, code: reader._KernelCgroupView(process, {}))):
                for change in (None, "closed", "failed", "busy", "imitation"):
                    with self.subTest(view=name, change=change):
                        process = idle(type("Imitation", (reader._KernelProcessView,), {}) if change == "imitation"
                                       else reader._KernelProcessView, roots=roots)
                        if change in ("closed", "failed", "busy"):
                            setattr(process, change, True)
                        with self.assertRaises(Reached if change is None else ConformanceError):
                            build(process, idle(reader._KernelCodeFiles, roots=roots))
            for change in ("closed", "failed", "busy", "other roots"):
                with self.subTest(view="process code", code_change=change), self.assertRaises(ConformanceError):
                    code = idle(reader._KernelCodeFiles, roots=other_roots if change == "other roots" else roots)
                    if change != "other roots":
                        setattr(code, change, True)
                    reader._KernelProcessCode(idle(reader._KernelProcessView, roots=roots), code, {})
            for change in (None, "closed", "failed", "busy", "imitation"):
                with self.subTest(view="bpf", change=change):
                    cgroup = idle(type("Imitation", (reader._KernelCgroupView,), {}) if change == "imitation"
                                  else reader._KernelCgroupView)
                    if change in ("closed", "failed", "busy"):
                        setattr(cgroup, change, True)
                    with self.assertRaises(Reached if change is None else ConformanceError):
                        reader._KernelBpfView(cgroup, {})

    def test_inspections_refuse_a_wrong_owner_or_peer(self):
        for cls, argument in ((reader._KernelSelfInspection, object()), (reader._KernelObserverInspection, object()),
                              (reader._KernelBrokerInspection, object()), (reader._KernelObserverInspection, server()),
                              (reader._KernelBrokerInspection, server())):
            with self.subTest(inspection=cls.__name__, argument=type(argument).__name__), self.assertRaises(ConformanceError):
                cls(argument)


class StandInBinding:
    """A stand-in for the server's qualification binding: the fields the inspection's guards compare, and a check()."""

    def __init__(self, owner, files):
        self.owner, self.files, self.closed, self.poisoned = owner, files, False, False
        self.authority = ("authority",)

    def check(self):
        pass


class StandInFiles:
    """The server's file owner as the per-tick peer checks see it; reaching its check() shows the peer checks passed."""

    def check(self):
        raise Reached()


def now_wall():
    return reader.require_time(reader.utc_now(), "now")


def inspection(busy=False):
    """The server's own inspection in custody of an installed server, built without its Linux-only constructor."""
    owner = server(deadline=time.monotonic() + 100, authority=("authority",), binding={"session": 1})
    owner.files = reader._Files(owner)
    binding = StandInBinding(owner, owner.files)
    view = object.__new__(reader._KernelSelfInspection)
    view.owner, view.binding, view.deadline = owner, binding, owner.deadline
    owner.self_inspection, owner.qualification_binding = view, binding
    view.roots, view.policy = Closable(), Closable()
    view.owned = [("roots", view.roots), ("policy", view.policy)]
    view.closed = view.failed = False
    view.busy, view.cleanup_failure = busy, None
    view.last = time.monotonic()
    view.end = view.last + 2
    view.wall = view.phase_wall = now_wall()
    view.authority, view.session_raw = ("authority",), reader.canonical_bytes(owner.binding)
    view.authority_window = (view.wall - timedelta(hours=1), view.wall + timedelta(hours=1))
    view.epoch_ready = view.epoch_sampling = False
    return view


class InspectionPhaseTests(unittest.TestCase):
    """The server's own inspection: its phase and tick guards, and the readers it may serve (E09, A02)."""

    def assert_unusable(self, view):
        for _ in range(2):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    pass

    def test_an_inspection_in_custody_runs_its_phases(self):
        # Control for the refusals below.
        view = inspection()
        with active(view.owner):
            for _ in range(2):
                with view._phase():
                    view._tick()

    def test_a_reentrant_inspection_phase_is_refused_and_sticky(self):
        view = inspection()
        with active(view.owner):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    with view._phase():
                        pass
            self.assert_unusable(view)

    def test_a_failure_inside_an_inspection_phase_is_sticky(self):
        view = inspection()
        with active(view.owner):
            with self.assertRaises(RuntimeError):
                with view._phase():
                    raise RuntimeError("failure inside the phase")
            self.assert_unusable(view)

    def test_a_replaced_owned_view_fails_the_inspection_for_good(self):
        view = inspection()
        original = view.roots
        with active(view.owner):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    view.roots = Closable()
            view.roots = original  # putting the original back does not revive the inspection
            self.assert_unusable(view)

    def test_an_inspection_whose_server_or_binding_changed_is_refused(self):
        changes = {"server names another inspection": lambda view: setattr(view.owner, "self_inspection", object()),
                   "server names another binding": lambda view: setattr(view.owner, "qualification_binding", object()),
                   "binding closed": lambda view: setattr(view.binding, "closed", True),
                   "binding poisoned": lambda view: setattr(view.binding, "poisoned", True),
                   "server files replaced": lambda view: setattr(view.owner, "files", reader._Files(view.owner)),
                   "server deadline moved": lambda view: setattr(view.owner, "deadline", view.deadline + 10),
                   "server not installed": None}
        for name, change in changes.items():
            with self.subTest(change=name):
                view = inspection(busy=True)
                if change is not None:
                    change(view)
                with active(None if change is None else view.owner), self.assertRaises(ConformanceError):
                    view._tick()

    def test_an_inspection_phase_ends_at_the_servers_deadline(self):
        # The phase window never outlives the server's original deadline.
        view = inspection()
        view.deadline = view.owner.deadline = time.monotonic() + 0.05
        with active(view.owner):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    time.sleep(0.1)
            self.assert_unusable(view)

    def test_an_inspection_refuses_a_reader_it_does_not_own(self):
        for change in (None, "unowned", "foreign owner"):
            with self.subTest(change=change):
                view = inspection()
                reader_view = view.roots if change is None else Closable()
                reader_view._inspection_owner = object() if change == "foreign owner" else view
                with active(view.owner):
                    if change is None:
                        with view._phase():
                            reader._kernel_inspection_tick(reader_view)  # control
                    else:
                        with self.assertRaises(ConformanceError):
                            with view._phase():
                                reader._kernel_inspection_tick(reader_view)
                        self.assert_unusable(view)


def peer_inspection(cls, kind, slots):
    """An observer or broker inspection mid-tick, bound to its peer and the installed server, without Linux sockets."""
    owner = server(deadline=time.monotonic() + 100)
    owner.files = StandInFiles()
    binding = StandInBinding(owner, owner.files)
    server_inspection = object.__new__(reader._KernelSelfInspection)
    server_inspection.closed = server_inspection.failed = False
    owner.qualification_binding, owner.self_inspection = binding, server_inspection
    view, peer = object.__new__(cls), object.__new__(kind)
    for slot in slots:
        setattr(owner, slot, peer)
    identity = {"pid": 4100, "start": 900001, "parent": 1, "uid": [0], "gid": [0], "capabilities": [], "seccomp": 2,
                "noNewPrivs": True, "cgroup": "/planeon", "namespaces": {"net": 1}}
    sock = object()
    peer.owner, peer.inspection, peer.closed, peer.failed, peer.busy = owner, view, False, False, True
    peer.deadline, peer.end = owner.deadline, time.monotonic() + 2
    peer.sock = peer._socket_original = sock
    peer.pidfd = peer._pidfd_original = 7
    peer._socket_fd, peer._socket_pin, peer._pidfd_pin, peer.parent, peer.socket_identity = 5, "socket-pin", "pidfd-pin", 9, "path-pin"
    peer.peer = peer._peer_original = (4100, 0, 0)
    peer.identity = identity
    peer._process_original = kind._process_pin(identity)
    view.owner, view.peer, view.binding, view.server_inspection, view.deadline = owner, peer, binding, server_inspection, owner.deadline
    view.closed = view.failed = False
    view.busy, view.owned, view.socket = True, [], sock
    view.last = time.monotonic()
    view.end = view.last + 2
    view.wall = view.phase_wall = now_wall()
    view.peer_pins = (5, "socket-pin", 7, "pidfd-pin", (4100, 0, 0), kind._process_pin(identity), 9, "path-pin")
    return view


class PeerTickTests(unittest.TestCase):
    """A02 dynamic peer overrides, E07 replacement: the in-process peer checks of every observer and broker tick."""

    PEERS = ((reader._KernelObserverInspection, reader._Observer, ("observer",)),
             (reader._KernelBrokerInspection, reader._Broker, ("broker", "_broker_original")))

    def test_the_bound_peer_passes_its_tick_checks(self):
        # Control: the tick gets past every in-process check to the server's file check (the stand-in signals there).
        for cls, kind, slots in self.PEERS:
            with self.subTest(inspection=cls.__name__):
                view = peer_inspection(cls, kind, slots)
                with active(view.owner), self.assertRaises(Reached):
                    view._tick()

    def test_a_substituted_peer_or_pin_is_refused(self):
        changes = {"socket": lambda view: setattr(view.peer, "sock", object()),
                   "original socket": lambda view: setattr(view.peer, "_socket_original", object()),
                   "pidfd": lambda view: setattr(view.peer, "pidfd", 8),
                   "socket descriptor pin": lambda view: setattr(view.peer, "_socket_fd", 6),
                   "parent": lambda view: setattr(view.peer, "parent", 10),
                   "credentials": lambda view: setattr(view.peer, "peer", (4101, 0, 0)),
                   "process identity": lambda view: view.peer.identity.update(pid=4101),
                   "peer names another inspection": lambda view: setattr(view.peer, "inspection", object()),
                   "peer closed": lambda view: setattr(view.peer, "closed", True),
                   "server inspection failed": lambda view: setattr(view.server_inspection, "failed", True)}
        for cls, kind, slots in self.PEERS:
            slot_changes = {"%s names another peer" % slot: (lambda slot: lambda view: setattr(view.owner, slot, object()))(slot)
                            for slot in slots}
            for name, change in {**changes, **slot_changes}.items():
                with self.subTest(inspection=cls.__name__, change=name):
                    view = peer_inspection(cls, kind, slots)
                    change(view)
                    with active(view.owner), self.assertRaises(ConformanceError):
                        view._tick()


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

    def test_code_and_cgroup_views_hold_only_their_process_views_role(self):
        # The code view's executable and the cgroup view's path must be the process view's own role's. Each expectation
        # is otherwise invalid further on, so the control is refused too, only by a later guard (the reason shows which).
        roots = object.__new__(reader._KernelRootViews)
        def process(cgroup=b"0::/planeon-live/policy-observer\n"):
            return in_custody(reader._KernelProcessView, busy=False, roots=roots, role="OBSERVER", cgroup=cgroup)
        def code(executable):
            return {"executable": executable, "artifactDigest": "-", "interpreterPath": None, "filePaths": "-"}
        def cgroup(path):
            return {"path": path, "inode": "-", "memoryMaxBytes": 0, "pidsMax": 0, "cpuQuotaMicros": 0, "cpuPeriodMicros": 0}
        cases = (
            ("code", lambda: reader._KernelProcessCode(process(), in_custody(reader._KernelCodeFiles, busy=False, roots=roots),
                                                       code(reader.OBSERVER)), False),
            ("code", lambda: reader._KernelProcessCode(process(), in_custody(reader._KernelCodeFiles, busy=False, roots=roots),
                                                       code("/opt/planeon/bin/harness-capacity-broker")), True),
            ("cgroup", lambda: reader._KernelCgroupView(process(), cgroup("/sys/fs/cgroup/planeon-live/policy-observer")), False),
            ("cgroup", lambda: reader._KernelCgroupView(process(), cgroup("/sys/fs/cgroup/planeon-live/capacity-broker")), True),
            ("cgroup", lambda: reader._KernelCgroupView(process(cgroup=b"0::/planeon-live/capacity-broker\n"),
                                                        cgroup("/sys/fs/cgroup/planeon-live/policy-observer")), True))
        roles = {"code": "KERNEL_PROCESS_CODE_ROLE", "cgroup": "KERNEL_CGROUP_ROLE"}
        with patched(reader, "document", lambda value, *args: value):
            for index, (view, build, wrong) in enumerate(cases):
                with self.subTest(view=view, case=index), self.assertRaises(ConformanceError) as refused:
                    build()
                self.assertEqual(refused.exception.reason == roles[view], wrong)


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

    def test_an_inspection_closes_a_half_built_root_views_native_reads(self):
        # A root view whose constructor failed before it set its own state still has its native reads closed.
        view = object.__new__(reader._KernelSelfInspection)
        view.closed, view.cleanup_failure = False, None
        half_built = object.__new__(reader._KernelRootViews)
        half_built.native = Closable()
        view.owned, view.roots = [("roots", half_built)], half_built
        view.close()
        self.assertEqual(half_built.native.calls, 1)

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
        self.assertIn("the peer's kernel rechecks on each inspection tick", text)
        for row in gaps:
            for case in row["carriedBy"]:
                self.assertIn(case, text)


if __name__ == "__main__":
    unittest.main()
