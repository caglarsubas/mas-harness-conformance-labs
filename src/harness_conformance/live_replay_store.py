"""Append-only replay custody. No expiry, crash, or terminal state frees a nonce.

The production store opens only the operator-precreated root-owned journal.
Unit adapters exercise the same transaction logic without accessing that path.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import stat

from .canonical import canonical_bytes, canonical_digest, require_canonical_document
from .errors import ConformanceError
from .linux_readiness import require_time
from .live_session import validate_binding
from .schema import closed, require_digest

JOURNAL = "/var/lib/planeon/live-backend/replay.jsonl"
MAX_JOURNAL = 4194304
MAX_RECORD = 2048
MAX_RECORDS = 4096
TERMINAL = ("COMPLETED", "FAILED", "CANCELLED", "EXPIRED")
EDGES = {"RESERVED": ("RUNNING", "FAILED", "CANCELLED", "EXPIRED"),
         "RUNNING": TERMINAL, **{state: () for state in TERMINAL}}
FIELDS = ("sequence", "previousDigest", "replayKey", "bindingDigest", "state", "observedAt", "receiptDigest")
ZERO = "sha256:" + "0" * 64


def require(condition, reason):
    if not condition:
        raise ConformanceError(reason, "protected replay operation refused")


def replay_key(binding):
    value = validate_binding(binding)
    # Scope + nonce, never a release/version key that would allow nonce reuse.
    return canonical_digest({"tenantId": value["tenantId"], "nonce": value["nonce"]},
                            "planeon.live-replay-key/v1alpha1")


def check_stat(info, *, directory=False, private=False, uid=0):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    mode = stat.S_IMODE(info.st_mode)
    require(kind(info.st_mode) and info.st_uid == uid and info.st_gid == (0 if uid == 0 else os.getgid()),
            "REPLAY_CUSTODY_INVALID")
    require(not mode & 0o022 and (directory or info.st_nlink == 1), "REPLAY_CUSTODY_INVALID")
    if private:
        require(mode == (0o700 if directory else 0o600), "REPLAY_CUSTODY_INVALID")


def open_directory(path, *, private=False, uid=0):
    """Walk retained directory descriptors; never resolve or reopen a symlink."""
    require(type(path) is str and path.startswith("/") and "\\" not in path
            and all(p not in ("", ".", "..") for p in path[1:].split("/")), "REPLAY_PATH_INVALID")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        check_stat(os.fstat(fd), directory=True)
        parts = path[1:].split("/")
        for index, name in enumerate(parts):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                check_stat(os.fstat(child), directory=True, private=private and index == len(parts) - 1,
                           uid=uid if index == len(parts) - 1 else 0)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class _FileIO:
    """Existing file only. Root-only writes, no truncate/rename/delete/recovery."""
    def __init__(self):
        self.directory = open_directory(str(Path(JOURNAL).parent), private=True)
        try:
            self.fd = os.open(Path(JOURNAL).name, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW |
                              os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.directory)
            check_stat(os.fstat(self.fd), private=True)
        except BaseException:
            if hasattr(self, "fd"):
                os.close(self.fd)
            os.close(self.directory)
            raise

    @contextmanager
    def transaction(self):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ConformanceError("REPLAY_BUSY", "another journal transaction is active") from exc
        try:
            opened = os.fstat(self.fd)
            check_stat(opened, private=True)
            check_stat(os.fstat(self.directory), directory=True, private=True)
            named = os.stat(Path(JOURNAL).name, dir_fd=self.directory, follow_symlinks=False)
            require((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino), "REPLAY_CUSTODY_CHANGED")
            yield self
        finally:
            fcntl.flock(self.fd, fcntl.LOCK_UN)

    def read(self):
        size = os.fstat(self.fd).st_size
        require(0 <= size <= MAX_JOURNAL, "REPLAY_JOURNAL_FULL")
        raw = os.pread(self.fd, size + 1, 0)
        require(len(raw) == size, "REPLAY_CUSTODY_CHANGED")
        return raw

    def append(self, raw):
        # A short write is deliberately NOT repaired or truncated. Recovery
        # refuses a partial record; execution never follows ambiguous storage.
        require(os.write(self.fd, raw) == len(raw), "REPLAY_SHORT_WRITE")

    def sync(self):
        os.fsync(self.fd)
        os.fsync(self.directory)

    def close(self):
        os.close(self.fd)
        os.close(self.directory)


def parse_journal(raw):
    require(type(raw) is bytes and len(raw) <= MAX_JOURNAL, "REPLAY_JOURNAL_FULL")
    require(not raw or raw.endswith(b"\n"), "REPLAY_JOURNAL_CORRUPT")
    lines = raw.splitlines(keepends=True)
    require(len(lines) <= MAX_RECORDS, "REPLAY_JOURNAL_FULL")
    latest, previous = {}, ZERO
    for sequence, line in enumerate(lines, 1):
        require(0 < len(line) <= MAX_RECORD, "REPLAY_JOURNAL_CORRUPT")
        row = require_canonical_document(line)
        closed(row, FIELDS)
        require(type(row["sequence"]) is int and row["sequence"] == sequence
                and row["previousDigest"] == previous, "REPLAY_JOURNAL_CORRUPT")
        for field in ("replayKey", "bindingDigest"):
            require_digest(row[field], field)
        require_time(row["observedAt"], "observedAt")
        prior = latest.get(row["replayKey"])
        require(type(row["state"]) is str and row["state"] in EDGES, "REPLAY_JOURNAL_CORRUPT")
        if prior is None:
            require(row["state"] == "RESERVED", "REPLAY_JOURNAL_CORRUPT")
        else:
            require(row["state"] in EDGES[prior["state"]] and row["bindingDigest"] == prior["bindingDigest"]
                    and require_time(row["observedAt"], "now") >= require_time(prior["observedAt"], "prior"),
                    "REPLAY_JOURNAL_CORRUPT")
        if row["state"] in TERMINAL:
            require_digest(row["receiptDigest"], "receiptDigest")
        else:
            require(row["receiptDigest"] is None, "REPLAY_JOURNAL_CORRUPT")
        latest[row["replayKey"]] = row
        previous = canonical_digest(row)
    return latest, previous, len(lines)


class _Journal:
    """Shared transaction algorithm; injected instances are unit-only."""
    evidence_class = "UNIT_VERIFICATION_ONLY"

    def __init__(self, storage):
        self._storage = storage
        self._poisoned = False

    def _record(self, binding, state, now, receipt_digest=None):
        value = validate_binding(binding)
        instant = require_time(now, "now")
        require(not self._poisoned, "REPLAY_STORAGE_AMBIGUOUS")
        require(type(state) is str and state in EDGES, "REPLAY_TRANSITION_INVALID")
        with self._storage.transaction() as io:
            raw = io.read()
            latest, previous, count = parse_journal(raw)
            key, binding_digest = replay_key(value), canonical_digest(value)
            prior = latest.get(key)
            if state == "RESERVED":
                require(prior is None, "REPLAY_DETECTED")
                require(require_time(value["notBefore"], "start") <= instant < require_time(value["notAfter"], "end"),
                        "REPLAY_EXPIRED")
            else:
                require(prior is not None and prior["bindingDigest"] == binding_digest
                        and state in EDGES[prior["state"]], "REPLAY_TRANSITION_INVALID")
                require(instant >= require_time(prior["observedAt"], "prior"), "REPLAY_CLOCK_ROLLBACK")
                if state == "EXPIRED":
                    require(instant >= require_time(value["notAfter"], "end"), "REPLAY_EARLY_EXPIRY")
                elif state in ("RUNNING", "COMPLETED"):
                    require(instant < require_time(value["notAfter"], "end"), "REPLAY_EXPIRED")
            if state in TERMINAL:
                require_digest(receipt_digest, "receiptDigest")
            else:
                require(receipt_digest is None, "REPLAY_RECEIPT_INVALID")
            row = dict(sequence=count + 1, previousDigest=previous, replayKey=key,
                       bindingDigest=binding_digest, state=state, observedAt=now, receiptDigest=receipt_digest)
            encoded = canonical_bytes(row) + b"\n"
            require(count < MAX_RECORDS and len(encoded) <= MAX_RECORD and len(raw) + len(encoded) <= MAX_JOURNAL,
                    "REPLAY_JOURNAL_FULL")
            try:
                io.append(encoded)
                io.sync()
                require(io.read() == raw + encoded, "REPLAY_CUSTODY_CHANGED")
            except BaseException:
                self._poisoned = True
                raise
            return canonical_digest(row)

    def reserve_nonce(self, binding, now):
        return self._record(binding, "RESERVED", now)

    def running(self, binding, now):
        return self._record(binding, "RUNNING", now)

    def terminal(self, binding, state, now, receipt_digest):
        require(state in TERMINAL, "REPLAY_TRANSITION_INVALID")
        return self._record(binding, state, now, receipt_digest)


class ReplayStore(_Journal):
    """No path, identity, callback, or storage parameter in production."""
    evidence_class = "PROTECTED_REPLAY_JOURNAL"

    def __init__(self):
        require(os.geteuid() == 0 and os.getegid() == 0, "REPLAY_ROOT_REQUIRED")
        super().__init__(_FileIO())

    def close(self):
        self._storage.close()


class UnitReplayStore(_Journal):
    """Explicit test adapter. Never accepted by the production supervisor."""
    pass
