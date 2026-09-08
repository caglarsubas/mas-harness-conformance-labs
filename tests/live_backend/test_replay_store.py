from contextlib import contextmanager
from copy import deepcopy
import json
import os
import stat
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from _fixtures import VECTORS, NOW, END
from harness_conformance.canonical import canonical_bytes, canonical_digest
from harness_conformance.errors import ConformanceError
from harness_conformance.live_replay_store import (MAX_JOURNAL, MAX_RECORDS, ReplayStore,
    UnitReplayStore, check_stat, parse_journal, replay_key)


class MemoryJournal:
    def __init__(self):
        self.raw = b""
        self.events = []
        self.lock = threading.Lock()
        self.fail = None

    @contextmanager
    def transaction(self):
        if not self.lock.acquire(False):
            raise ConformanceError("REPLAY_BUSY", "unit contention")
        try:
            self.events.append("lock")
            yield self
        finally:
            self.events.append("unlock")
            self.lock.release()

    def read(self):
        self.events.append("read")
        return self.raw

    def append(self, raw):
        self.events.append("append")
        if self.fail == "before":
            raise OSError("unit before append")
        if self.fail == "partial":
            self.raw += raw[:20]
            raise OSError("unit torn append")
        self.raw += raw
        if self.fail == "after":
            raise OSError("unit after append")

    def sync(self):
        self.events.append("fsync")
        if self.fail == "sync":
            raise OSError("unit fsync")
        if self.fail == "readback":
            self.raw += b"broken"


class ReplayStoreTests(unittest.TestCase):
    def setUp(self):
        self.binding = deepcopy(VECTORS["binding"])
        self.io = MemoryJournal()
        self.store = UnitReplayStore(self.io)
        self.receipt = "sha256:" + "a" * 64

    def test_reservation_append_sync_readback_before_return(self):
        digest = self.store.reserve_nonce(self.binding, NOW)
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        rows, _, count = parse_journal(self.io.raw)
        self.assertEqual(count, 1)
        self.assertEqual(digest, canonical_digest(rows[replay_key(self.binding)]))

    def test_terminal_lifecycle_is_durable_and_never_releases_nonce(self):
        for terminal in ("COMPLETED", "FAILED", "CANCELLED", "EXPIRED"):
            io = MemoryJournal()
            store = UnitReplayStore(io)
            store.reserve_nonce(self.binding, NOW)
            store.running(self.binding, NOW)
            store.terminal(self.binding, terminal, END if terminal == "EXPIRED" else NOW, self.receipt)
            with self.subTest(state=terminal), self.assertRaises(ConformanceError):
                UnitReplayStore(io).reserve_nonce(self.binding, NOW)
            self.assertEqual(parse_journal(io.raw)[2], 3)

    def test_all_unsigned_reservation_scope_fields_are_validated(self):
        for key in self.binding:
            altered = deepcopy(self.binding)
            del altered[key]
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                self.store.reserve_nonce(altered, NOW)
        self.assertEqual(self.io.raw, b"")

    def test_nonce_key_cannot_be_reset_by_release_environment_or_command_change(self):
        self.store.reserve_nonce(self.binding, NOW)
        for key in ("releaseDigest", "environmentId", "commandSetDigest", "capacityDigest"):
            altered = {**self.binding, key: "sha256:" + "f" * 64 if key.endswith("Digest") else "other"}
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                UnitReplayStore(self.io).reserve_nonce(altered, NOW)

    def test_tenant_and_nonce_keys_are_separate_without_raw_nonce_storage(self):
        self.store.reserve_nonce(self.binding, NOW)
        self.store.reserve_nonce({**self.binding, "tenantId": "other-tenant"}, NOW)
        self.store.reserve_nonce({**self.binding, "nonce": "other-nonce"}, NOW)
        self.assertEqual(len(parse_journal(self.io.raw)[0]), 3)
        self.assertNotIn(self.binding["nonce"].encode(), self.io.raw)
        self.assertNotIn(self.binding["tenantId"].encode(), self.io.raw)

    def test_concurrent_nonce_reservations_have_at_most_one_success(self):
        gate = threading.Barrier(3)
        results = []
        def reserve():
            gate.wait()
            try:
                UnitReplayStore(self.io).reserve_nonce(self.binding, NOW)
                results.append("reserved")
            except ConformanceError:
                results.append("denied")
        threads = [threading.Thread(target=reserve) for _ in range(2)]
        for thread in threads:
            thread.start()
        gate.wait()
        for thread in threads:
            thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(results), ["denied", "reserved"])

    def test_crash_at_every_append_sync_boundary_never_grants_execution(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            io = MemoryJournal()
            io.fail = fault
            store = UnitReplayStore(io)
            with self.subTest(fault=fault), self.assertRaises((OSError, ConformanceError)):
                store.reserve_nonce(self.binding, NOW)
            io.fail = None
            with self.assertRaises(ConformanceError):
                store.reserve_nonce(self.binding, NOW)
            if io.raw:
                with self.assertRaises(ConformanceError):
                    UnitReplayStore(io).reserve_nonce(self.binding, NOW)

    def test_restart_keeps_incomplete_reserved_or_running_nonce_consumed(self):
        self.store.reserve_nonce(self.binding, NOW)
        with self.assertRaises(ConformanceError):
            UnitReplayStore(self.io).reserve_nonce(self.binding, NOW)
        self.store.running(self.binding, NOW)
        with self.assertRaises(ConformanceError):
            UnitReplayStore(self.io).reserve_nonce(self.binding, NOW)

    def test_forged_transition_and_rebound_session_are_refused(self):
        self.store.reserve_nonce(self.binding, NOW)
        for state in ("COMPLETED", "RESERVED", "invented"):
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                self.store._record(self.binding, state, NOW, self.receipt)
        with self.assertRaises(ConformanceError):
            self.store.running({**self.binding, "releaseDigest": self.receipt}, NOW)

    def test_expiry_is_exclusive_and_cannot_be_reported_early(self):
        with self.assertRaises(ConformanceError):
            self.store.reserve_nonce(self.binding, END)
        self.store.reserve_nonce(self.binding, NOW)
        with self.assertRaises(ConformanceError):
            self.store.running(self.binding, END)
        with self.assertRaises(ConformanceError):
            self.store.terminal(self.binding, "EXPIRED", NOW, self.receipt)

    def test_backward_time_and_terminal_without_receipt_refuse(self):
        self.store.reserve_nonce(self.binding, NOW)
        for time in ("2026-09-07T00:59:59Z",):
            with self.assertRaises(ConformanceError):
                self.store.running(self.binding, time)
        with self.assertRaises(ConformanceError):
            self.store.terminal(self.binding, "FAILED", NOW, None)

    def test_torn_duplicate_noncanonical_oversized_and_nonfinite_journal_refuse(self):
        self.store.reserve_nonce(self.binding, NOW)
        for raw in (self.io.raw[:-1], self.io.raw + b"\n", b'{"a":1,"a":2}\n', b'{"x":NaN}\n',
                    b" " + self.io.raw, b"x" * (MAX_JOURNAL + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(ConformanceError):
                parse_journal(raw)

    def test_hash_chain_reordering_and_state_tampering_refuse(self):
        self.store.reserve_nonce(self.binding, NOW)
        self.store.running(self.binding, NOW)
        rows = [json.loads(line) for line in self.io.raw.splitlines()]
        for key, value in (("sequence", 5), ("sequence", True), ("previousDigest", self.receipt),
                           ("bindingDigest", self.receipt), ("state", "RESERVED")):
            altered = deepcopy(rows)
            altered[1][key] = value
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                parse_journal(b"".join(canonical_bytes(row) + b"\n" for row in altered))

    def test_full_journal_fails_without_rotation_truncation_or_reset(self):
        self.store.reserve_nonce(self.binding, NOW)
        with patch("harness_conformance.live_replay_store.MAX_RECORDS", 1):
            with self.assertRaises(ConformanceError):
                self.store.running(self.binding, NOW)
        self.assertEqual(parse_journal(self.io.raw)[2], 1)

    def test_owner_mode_kind_and_hardlink_checks_are_independent(self):
        good = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
        check_stat(SimpleNamespace(**good), private=True)
        for field, value in (("st_uid", 501), ("st_gid", 501), ("st_nlink", 2),
                             ("st_mode", stat.S_IFLNK | 0o600), ("st_mode", stat.S_IFIFO | 0o600),
                             ("st_mode", stat.S_IFREG | 0o660), ("st_mode", stat.S_IFREG | 0o644)):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                check_stat(SimpleNamespace(**{**good, field: value}), private=True)

    def test_production_constructor_has_no_storage_or_path_injection(self):
        with self.assertRaises(TypeError):
            ReplayStore(self.io)
        with patch("harness_conformance.live_replay_store.os.geteuid", return_value=501), patch(
                "harness_conformance.live_replay_store._FileIO", side_effect=AssertionError("opened native storage")):
            with self.assertRaises(ConformanceError):
                ReplayStore()
