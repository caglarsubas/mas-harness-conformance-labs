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
the reason it is not run here and the plan cases that carry it; the TG-02 ledger reads it (owner decision Q-T11: a carried
property is outside this case's own scope and stays NOT_RUN in the cases that carry it).

Trusted-code boundary (declared): the guards check state the reader keeps in ordinary Python objects. A process that
rewrites a guard's code, or every guarded field consistently, is outside what in-process checks can detect (E09: no
assumption that a kernel policy prevents Python attribute corruption); external enforcement owns that boundary. The
tests show that each single inconsistent field, owner, role, thread, process, resource or deadline is refused, and that
failure, reentrancy and cleanup are sticky.

Not run here (each needs the enrolled Linux host and is carried by W06 native cases of the plan; owner decision Q-T11):
fixed factories on an enrolled Linux host (TG-05 MATRIX:original deadlines); the peer's kernel rechecks on each inspection
tick (its descriptors, SO_PEERCRED credentials, pidfd liveness and the socket path; TG-04 MATRIX:parent/FD spoof, TG-05 MATRIX:peer
death/restart); and the inspections' construction past their first native read (kernel views, policy epoch retention,
page size and the peer's role pins) with the BPF view's program ID recheck on cleanup (TG-04 MATRIX:parent/FD spoof,
TG-04 MATRIX:effective BPF ancestors, TG-04 S8-KERNEL-FACTS, TG-05 MATRIX:peer death/restart).

Stand-ins: where a guard sits behind a Linux-only or cryptographic step, a stand-in reduces that step to what the guard
sees (the binding's load and signature verification, a parent view's tick, the owning inspection's reader tick, the
server's file owner on the per-tick peer path, the wall clock in two clock tests); every guard under test is the reader's
own code.
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
               "InspectionPhaseTests.test_a_reentrant_inspection_phase_is_refused_and_sticky",
               "InspectionPhaseTests.test_a_busy_inspection_refuses_a_phase",
               "InspectionPhaseTests.test_epoch_sampling_rechecks_mounts_and_epoch_and_refuses_recursion"]},
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
               "InspectionPhaseTests.test_an_inspection_refuses_a_reader_it_does_not_own",
               "InspectionPhaseTests.test_each_inconsistent_inspection_state_is_refused",
               "OwnerTests.test_the_self_inspection_checks_its_binding_and_lifetime_before_its_first_phase",
               "OwnerTests.test_peer_inspections_check_the_servers_binding_inspection_and_lifetime",
               "OwnerTests.test_an_imitation_inspection_is_refused_before_it_takes_its_peer",
               "FilesCheckTests.test_each_change_to_a_retained_file_is_refused",
               "BindingCheckTests.test_each_change_is_refused_and_poisons_the_binding",
               "BindingCheckTests.test_construction_checks_the_server_files_its_load_window_and_itself"]},
    {"property": "partial construction never grants custody and fails sticky", "source": "E09", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["PartialConstructionTests.test_a_view_built_without_its_constructor_is_never_usable",
               "PartialConstructionTests.test_a_binding_whose_load_fails_is_poisoned_for_good",
               "CleanupTests.test_an_inspection_closes_a_half_built_root_views_native_reads",
               "BindingCheckTests.test_construction_checks_the_server_files_its_load_window_and_itself"]},
    {"property": "state corruption fails sticky", "source": "E09; A02 sticky failure", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["CustodyTickTests.test_the_custody_state_itself_is_accepted", "CustodyTickTests.test_each_inconsistent_state_field_is_refused",
               "StickyPhaseTests.test_an_idle_view_runs_a_phase", "StickyPhaseTests.test_a_closed_or_failed_view_refuses_a_phase",
               "StickyPhaseTests.test_a_failure_inside_a_phase_is_sticky", "StickyPhaseTests.test_a_parent_view_failure_is_sticky",
               "StickyPhaseTests.test_a_closed_or_failed_child_view_never_enters_its_parent_views_phase",
               "InspectionPhaseTests.test_an_inspection_in_custody_runs_its_phases",
               "InspectionPhaseTests.test_a_failure_inside_an_inspection_phase_is_sticky",
               "InspectionPhaseTests.test_a_replaced_owned_view_fails_the_inspection_for_good",
               "InspectionPhaseTests.test_each_inconsistent_inspection_state_is_refused",
               "InspectionPhaseTests.test_a_refusing_binding_check_fails_the_phase_for_good",
               "InspectionPhaseTests.test_a_reader_tick_needs_the_original_authority_session_and_window",
               "InspectionPhaseTests.test_epoch_sampling_rechecks_mounts_and_epoch_and_refuses_recursion",
               "InspectionPhaseTests.test_a_reader_tick_outside_the_inspections_phase_fails_it_for_good",
               "BindingCheckTests.test_a_loaded_binding_passes_its_check",
               "BindingCheckTests.test_each_change_is_refused_and_poisons_the_binding"]},
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
               "OwnerTests.test_inspections_refuse_a_wrong_owner_or_peer",
               "OwnerTests.test_peer_inspections_check_the_servers_binding_inspection_and_lifetime"]},
    {"property": "dynamic peer overrides on every inspection tick: the in-process peer, server and pin checks",
     "source": "A02 dynamic peer overrides; E07 replacement, no rebinding", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["PeerTickTests.test_the_bound_peer_passes_its_tick_checks", "PeerTickTests.test_a_substituted_peer_or_pin_is_refused"]},
    {"property": "the peer's kernel rechecks on every inspection tick: its descriptors, SO_PEERCRED credentials, pidfd liveness and the socket path",
     "source": "E07 exact peer credentials, broker parentage and channel loss; A02 dynamic peer overrides",
     "result": "NOT_RUN_ENV_UNAVAILABLE", "tests": [], "reason": "needs live peer sockets and pidfds on the enrolled Linux host",
     "carriedBy": ["TG-04 MATRIX:parent/FD spoof", "TG-05 MATRIX:peer death/restart"]},
    {"property": "the inspections' construction past their first native read (kernel views, policy epoch retention, page size and "
                 "the peer's role pins) and the BPF view's program ID recheck on cleanup",
     "source": "E09 partial construction; A02 real fixed factories, wrong roles, original-resource-only cleanup; E07 broker parentage",
     "result": "NOT_RUN_ENV_UNAVAILABLE", "tests": [],
     "reason": "construction continues only after the enrolled Linux host's kernel views and the peer's kernel rechecks succeed, "
               "and the program ID recheck is a bpf system call",
     "carriedBy": ["TG-04 MATRIX:parent/FD spoof", "TG-04 MATRIX:effective BPF ancestors", "TG-04 S8-KERNEL-FACTS",
                   "TG-05 MATRIX:peer death/restart"]},
    {"property": "original deadlines and fresh clocks", "source": "A02 original deadlines", "result": "PASS", "reason": None,
     "carriedBy": [],
     "tests": ["CustodyTickTests.test_each_inconsistent_state_field_is_refused",
               "StickyPhaseTests.test_an_overrun_deadline_fails_the_phase_and_sticks",
               "InspectionPhaseTests.test_an_inspection_whose_server_or_binding_changed_is_refused",
               "InspectionPhaseTests.test_an_inspection_phase_ends_at_the_servers_deadline",
               "InspectionPhaseTests.test_each_inconsistent_inspection_state_is_refused",
               "InspectionPhaseTests.test_a_reader_tick_needs_the_original_authority_session_and_window",
               "OwnerTests.test_the_self_inspection_checks_its_binding_and_lifetime_before_its_first_phase",
               "OwnerTests.test_peer_inspections_check_the_servers_binding_inspection_and_lifetime",
               "CustodyTickTests.test_a_child_view_checks_its_deadline_before_and_after_its_parent_view_ticks",
               "CustodyTickTests.test_a_process_view_checks_its_deadline_around_its_owners_inspection_tick",
               "BindingCheckTests.test_each_change_is_refused_and_poisons_the_binding",
               "BindingCheckTests.test_a_check_that_outlasts_its_window_or_sees_the_files_change_is_refused",
               "BindingCheckTests.test_construction_checks_the_server_files_its_load_window_and_itself"]},
    {"property": "a retained original resource that is replaced or ends is refused",
     "source": "A02 original resources; E07 PID reuse, crash and replacement", "result": "PASS", "reason": None, "carriedBy": [],
     "tests": ["RetainedResourceTests.test_the_retained_pidfd_must_stay_the_original_and_alive",
               "InspectionPhaseTests.test_a_retained_server_file_replaced_on_disk_is_refused",
               "FilesCheckTests.test_each_change_to_a_retained_file_is_refused",
               "BindingCheckTests.test_a_check_that_outlasts_its_window_or_sees_the_files_change_is_refused"]},
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


# The properties carried by the plan's W06 native cases (owner decision Q-T11), pinned by name and carrier (review R3-5).
CARRIED = {
    "fixed factories on an enrolled Linux host: construction and original deadlines over real kernel I/O":
        ["TG-05 MATRIX:original deadlines"],
    "the peer's kernel rechecks on every inspection tick: its descriptors, SO_PEERCRED credentials, pidfd liveness and the socket path":
        ["TG-04 MATRIX:parent/FD spoof", "TG-05 MATRIX:peer death/restart"],
    "the inspections' construction past their first native read (kernel views, policy epoch retention, page size and the "
    "peer's role pins) and the BPF view's program ID recheck on cleanup":
        ["TG-04 MATRIX:parent/FD spoof", "TG-04 MATRIX:effective BPF ancestors", "TG-04 S8-KERNEL-FACTS", "TG-05 MATRIX:peer death/restart"],
}


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

    def test_a_child_view_checks_its_deadline_before_and_after_its_parent_view_ticks(self):
        # Before: a passed deadline or a clock behind the last tick is refused before the parent view is asked (the
        # signalling parent would show it was). After: a parent tick that outlasts the view's deadline is refused too.
        class Signalling(Parent):
            def _tick(self):
                raise Reached()

        class Slow(Parent):
            def _tick(self):
                time.sleep(0.05)
        for cls, parent in VIEWS.items():
            if parent is None or cls is reader._KernelProcessView or VIEWS[cls] == "roots":
                continue
            now = time.monotonic()
            for name, fields in (("deadline passed", {"last": now - 10, "end": now - 5}), ("clock before the last tick", {"last": now + 60})):
                with self.subTest(view=cls.__name__, before=name), self.assertRaises(ConformanceError):
                    in_custody(cls, parent=Signalling(), **fields)._tick()
            with self.subTest(view=cls.__name__, after="parent tick outlasts the deadline"), self.assertRaises(ConformanceError):
                view = in_custody(cls, parent=Slow())
                view.end = time.monotonic() + 0.02
                view._tick()

    def test_a_process_view_checks_its_deadline_around_its_owners_inspection_tick(self):
        # Review R4-1: the process view ticks its owning inspection twice (before and after its pidfd recheck). A passed
        # deadline is refused before the second inspection tick, and a second inspection tick that outlasts the view's
        # deadline is refused after it. The owning inspection's reader tick is a stand-in that counts its calls.
        def owned_view(second_call):
            owner = object.__new__(reader._KernelSelfInspection)
            calls = []
            def reader_tick(view):
                calls.append(view)
                if len(calls) == 2:
                    second_call()
            owner._reader_tick = reader_tick
            return in_custody(reader._KernelProcessView, _inspection_owner=owner), calls
        def signal():
            raise Reached()
        view, calls = owned_view(signal)
        with self.assertRaises(Reached):
            view._tick()  # control: both inspection ticks are reached
        now = time.monotonic()
        for name, fields in (("deadline passed", {"last": now - 10, "end": now - 5}), ("clock before the last tick", {"last": now + 60})):
            with self.subTest(before=name):
                view, calls = owned_view(signal)
                for field, value in fields.items():
                    setattr(view, field, value)
                with self.assertRaises(ConformanceError):
                    view._tick()
        with self.subTest(after="inspection tick outlasts the deadline"):
            view, calls = owned_view(lambda: time.sleep(0.6))
            view.end = time.monotonic() + 0.5
            with self.assertRaises(ConformanceError):
                view._tick()
            self.assertEqual(len(calls), 2)

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

    def test_a_closed_or_failed_child_view_never_enters_its_parent_views_phase(self):
        # Review R4-3: the refusal comes before the parent view's phase, so a dead child never touches its parent.
        class Recording(Parent):
            def __init__(self):
                super().__init__()
                self.entered = 0

            @contextmanager
            def _phase(self):
                self.entered += 1
                yield
        for cls, parent in VIEWS.items():
            if parent not in ("process", "cgroup"):
                continue
            for name in ("closed", "failed"):
                with self.subTest(view=cls.__name__, state=name):
                    recording = Recording()
                    view = in_custody(cls, busy=False, parent=recording, **{name: True})
                    with self.assertRaises(ConformanceError):
                        with view._phase():
                            pass
                    self.assertEqual(recording.entered, 0)

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

    def test_the_self_inspection_checks_its_binding_and_lifetime_before_its_first_phase(self):
        # Review R3-4: the binding must be the server's real one and its own, and the server's deadline within 900 s;
        # reaching the first phase (it records phase_wall) shows every one of these checks passed.
        changes = {None: None,
                   "binding is not the server's binding type": lambda owner: setattr(owner, "qualification_binding",
                                                                                     StandInBinding(owner, None)),
                   "binding owned by another server": lambda owner: setattr(owner.qualification_binding, "owner", server()),
                   "deadline beyond 900 s": lambda owner: setattr(owner, "deadline", time.monotonic() + 1000),
                   "deadline already passed": lambda owner: setattr(owner, "deadline", time.monotonic() - 1)}
        for name, change in changes.items():
            with self.subTest(change=name):
                owner = server(deadline=time.monotonic() + 100)
                binding = object.__new__(reader._ServerQualificationBinding)
                binding.owner = owner
                inspection_view = object.__new__(reader._KernelSelfInspection)
                owner.qualification_binding, owner.self_inspection = binding, inspection_view
                if change is not None:
                    change(owner)
                with active(owner), self.assertRaises(Exception):
                    inspection_view.__init__(owner)
                self.assertEqual(hasattr(inspection_view, "phase_wall"), name is None)

    def test_peer_inspections_check_the_servers_binding_inspection_and_lifetime(self):
        def imitation_inspection(owner):
            value = object.__new__(type("Imitation", (reader._KernelSelfInspection,), {}))
            value.owner = owner  # owned by the server, so only its type differs
            return value
        # Review R3-4: for the observer and broker inspections the server's binding and its own inspection must be the
        # real types and its own, and the deadline within 900 s; taking the peer's socket shows every check passed.
        changes = {None: None,
                   "binding is not the server's binding type": lambda owner: setattr(owner, "qualification_binding",
                                                                                     StandInBinding(owner, None)),
                   "binding owned by another server": lambda owner: setattr(owner.qualification_binding, "owner", server()),
                   "server inspection is not an inspection": lambda owner: setattr(owner, "self_inspection", imitation_inspection(owner)),
                   "server inspection owned by another server": lambda owner: setattr(owner.self_inspection, "owner", server()),
                   "deadline beyond 900 s": lambda owner: setattr(owner, "deadline", time.monotonic() + 1000),
                   "deadline already passed": lambda owner: setattr(owner, "deadline", time.monotonic() - 1)}
        lenient = type("Lenient", (reader.NativeProxyServer,), {"_owner_check": lambda self: None})
        changes["server is an imitation whose own owner check passes"] = "lenient"  # review R4-2
        for cls, kind, slots in ((reader._KernelObserverInspection, reader._Observer, ("observer",)),
                                 (reader._KernelBrokerInspection, reader._Broker, ("broker", "_broker_original"))):
            for name, change in changes.items():
                with self.subTest(inspection=cls.__name__, change=name):
                    owner = server(lenient if change == "lenient" else None, deadline=time.monotonic() + 100)
                    binding = object.__new__(reader._ServerQualificationBinding)
                    own_inspection = object.__new__(reader._KernelSelfInspection)
                    binding.owner = own_inspection.owner = owner
                    owner.qualification_binding, owner.self_inspection = binding, own_inspection
                    peer, view = object.__new__(kind), object.__new__(cls)
                    peer.owner, peer.inspection, peer._socket_original = owner, view, object()
                    for slot in slots:
                        setattr(owner, slot, peer)
                    if callable(change):
                        change(owner)
                    with active(owner), self.assertRaises(Exception):
                        view.__init__(peer)
                    self.assertEqual(hasattr(view, "socket"), name is None)

    def test_an_imitation_inspection_is_refused_before_it_takes_its_peer(self):
        for cls, kind in ((reader._KernelObserverInspection, reader._Observer), (reader._KernelBrokerInspection, reader._Broker)):
            for imitation in (False, True):
                with self.subTest(inspection=cls.__name__, imitation=imitation):
                    view = object.__new__(type("Imitation", (cls,), {}) if imitation else cls)
                    peer = object.__new__(kind)
                    peer.owner = server()
                    with self.assertRaises(Exception):
                        view.__init__(peer)
                    self.assertEqual(hasattr(view, "peer"), not imitation)

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
    """A stand-in for the server's qualification binding: the fields the inspection's guards compare, and a check()
    that refuses on demand as the real binding's does."""

    def __init__(self, owner, files):
        self.owner, self.files, self.closed, self.poisoned = owner, files, False, False
        self.authority, self._record_raw, self.refusing = ("authority",), b"record", False

    def check(self):
        if self.refusing:
            raise ConformanceError("STAND_IN_BINDING", "the stand-in binding refuses")


class StandInFiles:
    """The server's file owner as the per-tick peer checks see it: each check() is counted and signals that the
    in-process peer checks before it passed."""

    def __init__(self):
        self.calls = 0

    def check(self):
        self.calls += 1
        raise Reached()


class StandInRoots(Closable):
    """A root view for the inspection's epoch sampling: its native reads and its mount recheck, which can report a change."""

    def __init__(self):
        super().__init__()
        self.native, self.mounts = Closable(), [None, None]

    def _reader_mounts(self):
        return self.mounts.pop(0) if self.mounts else None


class StandInPolicy(Closable):
    def __init__(self):
        super().__init__()
        self.epoch = None

    def _reader_epoch(self):
        return self.epoch


def now_wall():
    return reader.require_time(reader.utc_now(), "now")


def stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def valid_scope(wall):
    return {"validFrom": stamp(wall - timedelta(hours=1)), "expiresAt": stamp(wall + timedelta(hours=1))}


def inspection(busy=False):
    """The server's own inspection in custody of an installed server, built without its Linux-only constructor."""
    owner = server(deadline=time.monotonic() + 100, authority=("authority",), binding={"session": 1})
    owner.files = reader._Files(owner)
    binding = StandInBinding(owner, owner.files)
    view = object.__new__(reader._KernelSelfInspection)
    view.owner, view.binding, view.deadline = owner, binding, owner.deadline
    owner.self_inspection, owner.qualification_binding = view, binding
    view.roots, view.policy, view.code = StandInRoots(), StandInPolicy(), Closable()
    view.owned = [("roots", view.roots), ("policy", view.policy), ("code", view.code)]
    view.closed = view.failed = False
    view.busy, view.cleanup_failure = busy, None
    view.last = time.monotonic()
    view.end = view.last + 2
    view.wall = view.phase_wall = now_wall()
    view.authority, view.session_raw = ("authority",), reader.canonical_bytes(owner.binding)
    view.authority_window = (view.wall - timedelta(hours=1), view.wall + timedelta(hours=1))
    view.record_raw, view.scope = b"record", valid_scope(view.wall)  # a constructed inspection always holds both
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
        # Review R3-2: the nested phase is refused at its entry, so its body never runs.
        view, ran = inspection(), []
        with active(view.owner):
            with self.assertRaises(ConformanceError):
                with view._phase():
                    with view._phase():
                        ran.append(True)
            self.assertEqual(ran, [])
            self.assert_unusable(view)

    def test_a_busy_inspection_refuses_a_phase(self):
        view, ran = inspection(busy=True), []
        with active(view.owner), self.assertRaises(ConformanceError):
            with view._phase():
                ran.append(True)
        self.assertEqual(ran, [])

    def test_each_inconsistent_inspection_state_is_refused(self):
        # Review R3-1: one change at a time against the tick's control state (test_an_inspection_in_custody_runs_its_phases).
        def imitation(view):
            view.__class__ = type("Imitation", (reader._KernelSelfInspection,), {})
        later = lambda: now_wall() + timedelta(hours=1)
        changes = {"imitation": imitation, "closed": lambda view: setattr(view, "closed", True),
                   "failed": lambda view: setattr(view, "failed", True), "outside a phase": lambda view: setattr(view, "busy", False),
                   "binding owned by another server": lambda view: setattr(view.binding, "owner", server()),
                   "clock before the last tick": lambda view: setattr(view, "last", time.monotonic() + 60),
                   "deadline passed": lambda view: setattr(view, "end", time.monotonic() - 1),
                   "wall clock before the last tick": lambda view: setattr(view, "wall", later()),
                   "phase started long ago": lambda view: setattr(view, "phase_wall", now_wall() - timedelta(seconds=10)),
                   "record changed": lambda view: setattr(view.binding, "_record_raw", b"other record"),
                   "scope expired": lambda view: view.scope.update(expiresAt=stamp(now_wall() - timedelta(minutes=1))),
                   "scope not yet valid": lambda view: view.scope.update(validFrom=stamp(later()))}
        for name, change in changes.items():
            with self.subTest(change=name):
                view = inspection(busy=True)
                change(view)
                with active(view.owner), self.assertRaises(ConformanceError):
                    view._tick()

    def test_a_refusing_binding_check_fails_the_phase_for_good(self):
        # The phase rechecks the server's binding on entry and on exit; a refusal at either fails the inspection for good.
        for at_exit in (False, True):
            with self.subTest(at_exit=at_exit):
                view, ran = inspection(), []
                with active(view.owner):
                    with self.assertRaises(ConformanceError):
                        view.binding.refusing = not at_exit
                        with view._phase():
                            ran.append(True)
                            view.binding.refusing = True
                    self.assertEqual(ran, [True] if at_exit else [])  # refused at entry: the body never runs
                    view.binding.refusing = False
                    self.assert_unusable(view)

    def test_a_retained_server_file_replaced_on_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = os.path.join(scratch, "kit")
            with open(path, "w") as handle:
                handle.write("kit")
            directory, fd = os.open(scratch, os.O_RDONLY), os.open(path, os.O_RDONLY)
            try:
                for replaced in (False, True):
                    with self.subTest(replaced=replaced):
                        view = inspection(busy=True)
                        view.owner.files.rows = {path: (fd, directory, "kit", reader._custody_identity(os.fstat(fd)))}
                        if replaced:
                            with open(path + ".new", "w") as handle:
                                handle.write("kit")
                            os.replace(path + ".new", path)
                        with active(view.owner):
                            if replaced:
                                with self.assertRaises(ConformanceError):
                                    view._tick()
                            else:
                                view._tick()  # control
            finally:
                os.close(fd)
                os.close(directory)

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

    def assert_reader_tick(self, view, reader_view, refused, direct=False):
        call = (lambda: view._reader_tick(reader_view)) if direct else (lambda: reader._kernel_inspection_tick(reader_view))
        with active(view.owner):
            if not refused:
                with view._phase():
                    call()  # control
                return
            with self.assertRaises(ConformanceError):
                with view._phase():
                    call()
            self.assert_unusable(view)

    def test_an_inspection_refuses_a_reader_it_does_not_own(self):
        for change in (None, "unowned", "foreign owner", "owned but naming a foreign owner"):
            with self.subTest(change=change):
                view = inspection()
                reader_view = view.code if change in (None, "owned but naming a foreign owner") else Closable()
                reader_view._inspection_owner = object() if "foreign owner" in (change or "") else view
                # The last case calls the inspection directly: dispatch by the reader's own owner field would not reach it.
                self.assert_reader_tick(view, reader_view, change is not None, direct=change == "owned but naming a foreign owner")

    def test_a_reader_tick_outside_the_inspections_phase_fails_it_for_good(self):
        # Review R5-1: with no inspection phase on the stack, the reader tick itself must record the failure.
        for name in ("owned reader called directly", "unowned native reads in their own phase"):
            with self.subTest(case=name):
                view = inspection()
                with active(view.owner):
                    with self.assertRaises(ConformanceError):
                        if name == "owned reader called directly":
                            view.code._inspection_owner = view
                            view._reader_tick(view.code)
                        else:
                            with in_custody(reader._KernelNativeReads, busy=False, _inspection_owner=view)._phase():
                                pass
                    self.assert_unusable(view)
        for cls, kind, slots in PeerTickTests.PEERS:
            with self.subTest(case="peer inspection", inspection=cls.__name__):
                view = peer_inspection(cls, kind, slots)
                view.busy = False
                stranger = Closable()
                stranger._inspection_owner = view
                with active(view.owner):
                    with self.assertRaises(ConformanceError):
                        view._reader_tick(stranger)
                    view.busy = True  # the control state of PeerTickTests, which reaches the file check
                    with self.assertRaises(ConformanceError):
                        view._tick()

    def test_a_reader_tick_needs_the_original_authority_session_and_window(self):
        changes = {None: None,
                   "server authority changed": lambda view: setattr(view.owner, "authority", ("other",)),
                   "binding authority changed": lambda view: setattr(view.binding, "authority", ("other",)),
                   "session changed": lambda view: setattr(view.owner, "binding", {"session": 2}),
                   "authority expired": lambda view: setattr(view, "authority_window", (view.wall - timedelta(hours=2), view.wall - timedelta(hours=1))),
                   "authority not yet valid": lambda view: setattr(view, "authority_window", (view.wall + timedelta(hours=1), view.wall + timedelta(hours=2)))}
        for name, change in changes.items():
            with self.subTest(change=name):
                view = inspection()
                if change is not None:
                    change(view)
                view.code._inspection_owner = view
                self.assert_reader_tick(view, view.code, name is not None)

    def test_epoch_sampling_rechecks_mounts_and_epoch_and_refuses_recursion(self):
        # Once the epoch is retained, a reader tick samples the mounts, the policy epoch and the mounts again; a change
        # at any of them is refused, and so is any other reader that ticks while the sample runs.
        changes = {None: None, "mounts changed first": lambda view: view.roots.mounts.__setitem__(0, "changed"),
                   "mounts changed after the epoch": lambda view: view.roots.mounts.__setitem__(1, "changed"),
                   "policy epoch changed": lambda view: setattr(view.policy, "epoch", "changed")}
        for name, change in changes.items():
            with self.subTest(change=name):
                view = inspection()
                view.epoch_ready = True
                if change is not None:
                    change(view)
                view.code._inspection_owner = view
                self.assert_reader_tick(view, view.code, name is not None)
        for name, reader_of in (("roots", lambda view: view.roots), ("policy", lambda view: view.policy),
                                ("the roots' native reads", lambda view: view.roots.native), ("code", lambda view: view.code)):
            with self.subTest(sampling=name):
                view = inspection()
                view.epoch_ready = view.epoch_sampling = True
                if name == "the roots' native reads":
                    # The root view's own native reads are served only when they are its original ones.
                    roots, native = object.__new__(reader._KernelRootViews), object.__new__(reader._KernelNativeReads)
                    roots.native = roots._native_original = native
                    view.roots, view.owned[0] = roots, ("roots", roots)
                reader_view = reader_of(view)
                reader_view._inspection_owner = view
                self.assert_reader_tick(view, reader_view, name == "code", direct=True)


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
    view.busy, view.socket, view.roots = True, sock, Closable()
    view.owned = [("roots", view.roots)]
    view.last = time.monotonic()
    view.end = view.last + 2
    view.wall = view.phase_wall = now_wall()
    view.record_raw, view.scope = b"record", valid_scope(view.wall)  # a constructed inspection always holds both
    view.peer_pins = (5, "socket-pin", 7, "pidfd-pin", (4100, 0, 0), kind._process_pin(identity), 9, "path-pin")
    return view


class PeerTickTests(unittest.TestCase):
    """A02 dynamic peer overrides, E07 replacement: the in-process peer checks of every observer and broker tick."""

    PEERS = ((reader._KernelObserverInspection, reader._Observer, ("observer",)),
             (reader._KernelBrokerInspection, reader._Broker, ("broker", "_broker_original")))

    def test_the_bound_peer_passes_its_tick_checks(self):
        # Control: the tick gets past every in-process check to the server's file check, both before its kernel rechecks
        # and again on its way out (the stand-in counts and signals there).
        for cls, kind, slots in self.PEERS:
            with self.subTest(inspection=cls.__name__):
                view = peer_inspection(cls, kind, slots)
                with active(view.owner), self.assertRaises(Reached):
                    view._tick()
                self.assertEqual(view.owner.files.calls, 2)

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
                   "server inspection failed": lambda view: setattr(view.server_inspection, "failed", True),
                   # Review R3-3: the peer, server and clock checks that come before the pins.
                   "socket and its original both replaced": lambda view: [setattr(view.peer, name, replacement)
                                                                          for replacement in (object(),)
                                                                          for name in ("sock", "_socket_original")],
                   "peer owned by another server": lambda view: setattr(view.peer, "owner", server()),
                   "peer failed": lambda view: setattr(view.peer, "failed", True),
                   "peer idle": lambda view: setattr(view.peer, "busy", False),
                   "peer deadline moved": lambda view: setattr(view.peer, "deadline", view.deadline + 10),
                   "peer phase ended": lambda view: setattr(view.peer, "end", time.monotonic() - 1),
                   "server names another binding": lambda view: setattr(view.owner, "qualification_binding", object()),
                   "binding owned by another server": lambda view: setattr(view.binding, "owner", server()),
                   "binding closed": lambda view: setattr(view.binding, "closed", True),
                   "binding poisoned": lambda view: setattr(view.binding, "poisoned", True),
                   "server files replaced": lambda view: setattr(view.owner, "files", StandInFiles()),
                   "server deadline moved": lambda view: setattr(view.owner, "deadline", view.deadline + 10),
                   "server names another inspection": lambda view: setattr(view.owner, "self_inspection", object()),
                   "server inspection closed": lambda view: setattr(view.server_inspection, "closed", True),
                   "owned view replaced": lambda view: setattr(view, "roots", Closable()),
                   "closed": lambda view: setattr(view, "closed", True), "failed": lambda view: setattr(view, "failed", True),
                   "outside a phase": lambda view: setattr(view, "busy", False),
                   "imitation": lambda view: setattr(view, "__class__", type("Imitation", (type(view),), {})),
                   "deadline passed": lambda view: setattr(view, "end", time.monotonic() - 1),
                   "clock before the last tick": lambda view: setattr(view, "last", time.monotonic() + 60),
                   "wall clock before the last tick": lambda view: setattr(view, "wall", now_wall() + timedelta(hours=1)),
                   "phase started long ago": lambda view: setattr(view, "phase_wall", now_wall() - timedelta(seconds=10)),
                   "phase starts in the future": lambda view: setattr(view, "phase_wall", now_wall() + timedelta(seconds=10)),
                   "record changed": lambda view: setattr(view.binding, "_record_raw", b"other record"),
                   "scope expired": lambda view: view.scope.update(expiresAt=stamp(now_wall() - timedelta(minutes=1))),
                   "scope not yet valid": lambda view: view.scope.update(validFrom=stamp(now_wall() + timedelta(hours=1)))}
        for cls, kind, slots in self.PEERS:
            slot_changes = {"%s names another peer" % slot: (lambda slot: lambda view: setattr(view.owner, slot, object()))(slot)
                            for slot in slots}
            for name, change in {**changes, **slot_changes, "server not installed": None}.items():
                with self.subTest(inspection=cls.__name__, change=name):
                    view = peer_inspection(cls, kind, slots)
                    if change is not None:
                        change(view)
                    with active(None if change is None else view.owner), self.assertRaises(ConformanceError):
                        view._tick()


class FilesCheckTests(unittest.TestCase):
    """The server's retained files (A02 original resources): each row must still be its original file, by descriptor and
    by name, never inheritable, held by the installed server."""

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

    def file(self, name):
        path = os.path.join(self.scratch.name, name)
        with open(path, "w") as handle:
            handle.write(name)
        fd = os.open(path, os.O_RDONLY)
        self.fds.append(fd)
        return fd

    def files(self):
        owner = server()
        files = reader._Files(owner)
        directory = os.open(self.scratch.name, os.O_RDONLY)
        self.fds.append(directory)
        fd = self.file("kit")
        files.rows = {"/kit": (fd, directory, "kit", reader._custody_identity(os.fstat(fd)))}
        return owner, files, fd

    def test_each_change_to_a_retained_file_is_refused(self):
        def substitute(owner, files, fd):
            os.dup2(self.file("other"), fd, inheritable=False)  # the descriptor now names another file

        def swap_descriptor_and_pin(owner, files, fd):
            other = self.file("other")  # descriptor and pin both name another file, while the name still holds the original
            files.rows["/kit"] = (other, files.rows["/kit"][1], "kit", reader._custody_identity(os.fstat(other)))
        changes = {None: None, "closed": lambda owner, files, fd: setattr(files, "closed", True),
                   "server not installed": "not installed", "descriptor substituted": substitute,
                   "descriptor and pin swapped": swap_descriptor_and_pin,
                   "descriptor inheritable": lambda owner, files, fd: os.set_inheritable(fd, True)}
        for name, change in changes.items():
            with self.subTest(change=name):
                owner, files, fd = self.files()
                if callable(change):
                    change(owner, files, fd)
                with active(None if change == "not installed" else owner):
                    if change is None:
                        files.check()  # control
                    else:
                        with self.assertRaises(ConformanceError):
                            files.check()


def loaded_binding(deadline=100):
    """The server's qualification binding as its constructor leaves it, with every input the reader would load."""
    owner = server(deadline=time.monotonic() + deadline, envelope_path="/envelope", authority=(b"envelope",), envelope={},
                   capacity={}, plan={}, binding={}, profile={}, observation_binding={}, endpoint={}, ca=b"ca", manifest={},
                   artifact_digest="sha256:" + "0" * 64, snapshot=b"snapshot", kit={"kit/file": b"kit"})
    owner.files = reader._Files(owner)
    binding = object.__new__(reader._ServerQualificationBinding)
    owner.qualification_binding = binding
    binding.owner, binding.files, binding.deadline, binding.closed, binding.poisoned = owner, owner.files, owner.deadline, False, False
    binding.last_wall, binding.last_mono = now_wall(), time.monotonic()
    binding.authority = owner.authority
    binding._record_raw = reader.canonical_bytes({"scope": valid_scope(now_wall())})
    binding._broker_raw = b"broker"
    binding._original = binding._inputs()
    binding._record_digests = (reader.byte_digest(binding._record_raw), reader.byte_digest(binding._broker_raw))
    return owner, binding


class BindingCheckTests(unittest.TestCase):
    """The server's qualification binding (E09, A02): its recheck refuses each changed owner, file, clock, authority,
    input or scope and is poisoned for good; its construction fails closed. The signature verification of the
    authority (verify_backend_authority) and the Linux-only load are stand-ins here; everything around them is real."""

    def verified(self, effect=None):
        def verify(*authority, now):
            if effect is not None:
                effect()
        return patched(reader, "verify_backend_authority", verify)

    def test_a_loaded_binding_passes_its_check(self):
        owner, binding = loaded_binding()
        with active(owner), self.verified():
            binding.check()
            binding.check()

    def test_each_change_is_refused_and_poisons_the_binding(self):
        def refuse():
            raise ConformanceError("STAND_IN_AUTHORITY", "the stand-in signature check refuses")
        later = lambda: now_wall() + timedelta(hours=1)
        changes = {"closed": lambda owner, binding: setattr(binding, "closed", True),
                   "poisoned": lambda owner, binding: setattr(binding, "poisoned", True),
                   "server not installed": None,
                   "server names another binding": lambda owner, binding: setattr(owner, "qualification_binding", object()),
                   "server files replaced": lambda owner, binding: setattr(owner, "files", reader._Files(owner)),
                   "files held by another server": lambda owner, binding: [setattr(holder, "files", files)
                                                                           for files in (reader._Files(server()),)
                                                                           for holder in (owner, binding)],
                   "server deadline moved": lambda owner, binding: setattr(owner, "deadline", binding.deadline + 10),
                   "files closed": lambda owner, binding: setattr(binding.files, "closed", True),
                   # Review R4-2: files held by an imitation server whose own owner check passes.
                   "files held by a lenient imitation server": lambda owner, binding: setattr(
                       binding.files, "owner", server(type("Lenient", (reader.NativeProxyServer,), {"_owner_check": lambda self: None}))),
                   "wall clock before the last check": lambda owner, binding: setattr(binding, "last_wall", later()),
                   "clock before the last check": lambda owner, binding: setattr(binding, "last_mono", time.monotonic() + 60),
                   "deadline passed": lambda owner, binding: [setattr(holder, "deadline", time.monotonic() - 1) for holder in (owner, binding)],
                   "inputs substituted": lambda owner, binding: setattr(owner, "envelope", {"substituted": True}),
                   "record bytes changed": lambda owner, binding: setattr(binding, "_broker_raw", b"other broker"),
                   "scope expired": lambda owner, binding: setattr(binding, "_record_raw", reader.canonical_bytes(
                       {"scope": {"validFrom": stamp(now_wall() - timedelta(hours=2)), "expiresAt": stamp(now_wall() - timedelta(minutes=1))}})),
                   "scope not yet valid": lambda owner, binding: setattr(binding, "_record_raw", reader.canonical_bytes(
                       {"scope": {"validFrom": stamp(later()), "expiresAt": stamp(later() + timedelta(hours=1))}}))}
        for name, change in changes.items():
            with self.subTest(change=name):
                owner, binding = loaded_binding()
                if name in ("scope expired", "scope not yet valid", "record bytes changed"):
                    change(owner, binding)
                    if name != "record bytes changed":
                        binding._record_digests = (reader.byte_digest(binding._record_raw), reader.byte_digest(binding._broker_raw))
                elif change is not None:
                    change(owner, binding)
                with active(None if change is None else owner), self.verified():
                    with self.assertRaises(ConformanceError):
                        binding.check()
                    self.assertIs(binding.poisoned, True)
                with active(owner), self.verified(), self.assertRaises(ConformanceError):
                    binding.check()  # sticky
        with self.subTest(change="authority refused"):
            owner, binding = loaded_binding()
            with active(owner), self.verified(refuse), self.assertRaises(ConformanceError):
                binding.check()
            self.assertIs(binding.poisoned, True)

    def test_a_check_that_outlasts_its_window_or_sees_the_files_change_is_refused(self):
        # The recheck ends with the files rechecked and the clocks inside the deadline and the scope.
        cases = {"files closed during the check": lambda owner, binding: lambda: setattr(binding.files, "closed", True),
                 "the check outlasts the deadline": lambda owner, binding: lambda: time.sleep(0.1)}
        for name, effect_of in cases.items():
            with self.subTest(case=name):
                owner, binding = loaded_binding(deadline=0.05 if "deadline" in name else 100)
                if "deadline" in name:
                    binding.deadline = owner.deadline
                with active(owner), self.verified(effect_of(owner, binding)), self.assertRaises(ConformanceError):
                    binding.check()
                self.assertIs(binding.poisoned, True)
        with self.subTest(case="files closed before the check and reopened during it"):
            # The first files recheck runs before the authority is verified, not only the last one.
            owner, binding = loaded_binding()
            binding.files.closed = True
            with active(owner), self.verified(lambda: setattr(binding.files, "closed", False)), self.assertRaises(ConformanceError):
                binding.check()
        for name, offset in (("the wall clock goes back during the check", timedelta(seconds=-10)),
                             ("the wall clock jumps ahead during the check", timedelta(seconds=3))):
            with self.subTest(case=name):
                owner, binding = loaded_binding()
                readings = []
                def clock(real=reader.utc_now, offset=offset, readings=readings):
                    # A stand-in wall clock: the first reading is real, later ones are moved by the offset.
                    readings.append(reader.require_time(real(), "now"))
                    moment = readings[0] + (offset if len(readings) > 1 else timedelta(0))
                    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")
                with active(owner), self.verified(), patched(reader, "utc_now", clock), self.assertRaises(ConformanceError):
                    binding.check()
        with self.subTest(case="the scope expires during the check"):
            owner, binding = loaded_binding()
            binding._record_raw = reader.canonical_bytes({"scope": {"validFrom": stamp(now_wall() - timedelta(hours=1)),
                                                                    "expiresAt": stamp(now_wall() + timedelta(seconds=1))}})
            binding._record_digests = (reader.byte_digest(binding._record_raw), reader.byte_digest(binding._broker_raw))
            with active(owner), self.verified(lambda: time.sleep(1.2)), self.assertRaises(ConformanceError):
                binding.check()

    def test_construction_checks_the_server_files_its_load_window_and_itself(self):
        # Refused before loading (not poisoned) when the server's files are not its own open file owner; poisoned when
        # the load outlasts its window, the wall clock goes back during it, or the first recheck refuses; constructed,
        # unpoisoned, only when everything holds.
        def attempt(owner, files_change, load, scope):
            binding = object.__new__(reader._ServerQualificationBinding)
            owner.qualification_binding, owner.files = binding, reader._Files(owner)
            if files_change is not None:
                files_change(owner)
            def stand_in_load():
                binding.authority = owner.authority
                binding._record_raw = reader.canonical_bytes({"scope": scope or valid_scope(now_wall())})
                binding._broker_raw = b"broker"
                if load is not None:
                    load(binding)
            binding._load = stand_in_load  # the Linux-only load, reduced to the inputs it leaves behind
            try:
                binding.__init__(owner)
            except Exception:
                return binding, True
            return binding, False
        def imitation_files(owner):
            files = object.__new__(type("Imitation", (reader._Files,), {}))
            files.owner, files.sealed, files.closed, files.rows = owner, False, False, {}  # only its type differs
            return files
        expired = {"validFrom": stamp(now_wall() - timedelta(hours=2)), "expiresAt": stamp(now_wall() - timedelta(minutes=1))}
        cases = {None: (None, None, None, False),
                 "files are an imitation": (lambda owner: setattr(owner, "files", imitation_files(owner)), None, None, False),
                 "files held by another server": (lambda owner: setattr(owner.files, "owner", server()), None, None, False),
                 "files already sealed": (lambda owner: setattr(owner.files, "sealed", True), None, None, False),
                 "load outlasts its window": (None, lambda binding: time.sleep(0.1), None, True),
                 # The load's own 2 s window, by each clock (a stand-in for the time the Linux-only load took).
                 "load took over 2 s": (None, lambda binding: setattr(binding, "last_mono", time.monotonic() - 3), None, True),
                 "load took over 2 s by the wall clock": (None, lambda binding: setattr(binding, "last_wall", now_wall() - timedelta(seconds=3)),
                                                          None, True),
                 "wall clock goes back during the load": (None, lambda binding: setattr(binding, "last_wall", now_wall() + timedelta(hours=1)),
                                                          None, True),
                 "first recheck refuses": (None, None, expired, True)}
        for name, (files_change, load, scope, poisoned) in cases.items():
            with self.subTest(case=name):
                owner, _ = loaded_binding(deadline=0.05 if name == "load outlasts its window" else 100)
                with active(owner), self.verified():
                    binding, refused = attempt(owner, files_change, load, scope)
                self.assertEqual(refused, name is not None)
                self.assertIs(binding.poisoned, poisoned)


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
        # Review R3-5: exactly these Linux-only properties are carried, by exactly these cases (owner decision Q-T11).
        self.assertEqual({row["property"]: row["carriedBy"] for row in PROPERTIES if row["result"] != "PASS"}, CARRIED)
        self.assertIn("fixed factories on an enrolled Linux host", text)
        self.assertIn("the peer's kernel rechecks on each inspection tick", text)
        self.assertIn("the inspections' construction past their first native read", text)
        for cases in CARRIED.values():
            for case in cases:
                self.assertIn(case, text)


if __name__ == "__main__":
    unittest.main()
