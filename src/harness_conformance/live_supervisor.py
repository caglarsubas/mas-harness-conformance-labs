"""Protected supervisor source candidate, not an installed/native qualification.

The native constructor is fixed and custody-checked. UnitSupervisor is a
separate non-authorizing model; its handles cannot enter NativeSupervisor.
No source-selected backend, executable, shell, credential or socket path API.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import stat
import threading
import time

from .canonical import canonical_bytes, canonical_digest, require_canonical_document
from .errors import ConformanceError
from .linux_readiness import ARCHITECTURES, CASES, build_probe_request, require_time
from .live import EXPECTED_LAUNCHER, FIXED_RELEASE_TRUST, FIXED_TENANT_TRUST
from .live_backend_authority import binding_from_authority, verify_backend_authority
from .live_linux_boundary import (CHILD_UID, CHILD_GID, CgroupLease, LinuxSyscalls, credentials,
    installed_process, process_identity, read_owned, read_owned_kit, require, validate_peer)
from .live_replay_store import ReplayStore, UnitReplayStore, open_directory
from .live_session import SCHEMA, validate_binding, validate_receipt, validate_session


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class _Handle:
    __slots__ = ("owner", "serial")

    def __init__(self, owner, serial):
        self.owner, self.serial = owner, serial

    def __reduce__(self):
        raise TypeError("protected session handles are not serializable")


class _Lifecycle:
    """State/ordering shared by native and explicit unit adapters, not authority."""
    evidence_class = "UNIT_VERIFICATION_ONLY"

    def __init__(self, journal, boundary, clock=utc_now, monotonic=time.monotonic):
        self._journal, self._boundary = journal, boundary
        self._clock, self._monotonic = clock, monotonic
        self._active = None
        self._mutex = threading.Lock()
        self._serial = 0
        self._opened = False

    def _now(self, active):
        now = self._clock()
        instant = require_time(now, "now")
        require(instant >= active["lastWall"], "SUPERVISOR_CLOCK_ROLLBACK")
        active["lastWall"] = instant
        require(instant < require_time(active["binding"]["notAfter"], "end")
                and self._monotonic() < active["deadline"], "SUPERVISOR_EXPIRED")
        return now

    def _open(self, binding, plan):
        binding = validate_binding(binding)
        require(self._active is None and not self._opened, "SUPERVISOR_BUSY")
        now = self._clock()
        state = {**{k: v for k, v in binding.items() if k not in ("notBefore", "notAfter")},
                 "schemaVersion": SCHEMA, "issuedAt": binding["notBefore"], "expiresAt": binding["notAfter"],
                 "state": "RESERVED"}
        validate_session(state, binding, now)
        require(plan["target"]["architecture"] in ARCHITECTURES, "SUPERVISOR_ARCHITECTURE_INVALID")
        duration = (require_time(binding["notAfter"], "end") - require_time(now, "now")).total_seconds()
        active = {"binding": binding, "session": state, "plan": plan, "done": {}, "handle": None,
                  "deadline": self._monotonic() + min(duration, 900), "lastWall": require_time(now, "now")}
        # No child, credential, or operation exists before durable reservation.
        self._journal.reserve_nonce(binding, now)
        self._opened = True
        self._active = active
        try:
            self._boundary.establish(binding, plan, active["deadline"])
            self._boundary.check_peer()
            self._journal.running(binding, self._now(active))
            state["state"] = "RUNNING"
            self._serial += 1
            handle = _Handle(self, self._serial)
            active["handle"] = handle
            return handle
        except BaseException:
            self._terminate("FAILED")
            raise

    def _get(self, handle):
        active = self._active
        require(type(handle) is _Handle and handle.owner is self and active is not None
                and active["handle"] is handle, "SUPERVISOR_HANDLE_INVALID")
        return active

    def execute_fixed(self, handle, case_id, architecture):
        require(self._mutex.acquire(blocking=False), "SUPERVISOR_BUSY")
        try:
            active = self._get(handle)
            try:
                require(type(case_id) is str and case_id in CASES and case_id not in active["done"],
                        "SUPERVISOR_OPERATION_INVALID")
                require(architecture == active["plan"]["target"]["architecture"], "SUPERVISOR_ARCHITECTURE_MISMATCH")
                self._now(active)
                self._boundary.check_peer()
                request = self._boundary.request(case_id)
                raw = self._boundary.execute(request, active["deadline"])
                # Expiry and peer are checked again after every blocking operation.
                now = self._now(active)
                self._boundary.check_peer()
                expected = active["plan"]["regressions"] if case_id == "FULL_PREDECESSOR_REGRESSION" else {}
                receipt = validate_receipt(raw, active["session"], active["binding"], request, expected, now)
                active["done"][case_id] = canonical_digest(receipt)
                if receipt["status"] != "PASS":
                    self._terminate("FAILED")
                elif len(active["done"]) == len(CASES):
                    self._terminate("COMPLETED")
                return {"receipt": receipt, "evidenceClass": self.evidence_class, "nativeAcceptance": False}
            except BaseException:
                if self._active is not None:
                    self._terminate("FAILED")
                raise
        finally:
            self._mutex.release()

    def _terminate(self, state):
        active = self._active
        if active is None:
            return
        # Invalidate first. Failure to clean up or persist never resurrects it.
        self._active = None
        now = self._clock()
        if (require_time(now, "now") >= require_time(active["binding"]["notAfter"], "end")
                or self._monotonic() >= active["deadline"]):
            # A monotonic timeout earlier than signed wall expiry is FAILED,
            # not a fabricated wall-time EXPIRED transition.
            state = "EXPIRED" if require_time(now, "now") >= require_time(active["binding"]["notAfter"], "end") else "FAILED"
        try:
            self._boundary.cleanup()
        except BaseException:
            # Leave durable RESERVED/RUNNING consumed; never certify cleanup.
            raise
        self._journal.terminal(active["binding"], state, now, canonical_digest(
            {"state": state, "receipts": active["done"], "nativeAcceptance": False}))

    def cancel(self, handle):
        # A concurrent execute is interrupted by the boundary's cancellation
        # primitive. No new operation can be admitted while its lock is held.
        self._get(handle)
        self._boundary.interrupt()
        with self._mutex:
            if self._active is not None:
                self._terminate("CANCELLED")

    def close(self):
        with self._mutex:
            self._terminate("FAILED")


class UnitSupervisor(_Lifecycle):
    """Offline-only adapters; never accepted as a native installed context."""
    def open_session(self, binding, plan):
        require(type(self._journal) is UnitReplayStore, "UNIT_STORAGE_REQUIRED")
        with self._mutex:
            return self._open(binding, plan)


class InstalledContext:
    """Factory-owned custody, not a dict or caller-provided FD/verified flag."""
    __slots__ = ("_owner", "_binding", "_plan", "_envelope", "_capacity", "_source_digest", "_root_fd")

    def __new__(cls, *args, **kwargs):
        raise TypeError("only NativeSupervisor.open_session may construct installed context")


class _NativeChannel:
    def __init__(self, context, syscalls, lease):
        self.context, self.syscalls, self.lease = context, syscalls, lease
        self.parent_namespaces = {n: (Path("/proc/self/ns") / n).stat().st_ino for n in ("user", "mnt", "pid", "net")}
        self.channel = self.child_pid = self.pidfd = self.peer = None
        self.cancelled = False

    def establish(self, binding, plan, deadline):
        self.deadline = deadline
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.channel = parent
        gate_r = gate_w = None
        try:
            parent.setsockopt(socket.SOL_SOCKET, 16, 1)  # SO_PASSCRED, per-message credentials
            gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
            self.syscalls.prctl(36, 1)  # child subreaper, before any fork
            supervisor_pid = os.getpid()
            pid = os.fork()
        except BaseException:
            child.close()
            parent.close()
            for fd in (gate_r, gate_w):
                if fd is not None:
                    os.close(fd)
            raise
        if pid == 0:
            try:
                parent.close()
                os.close(gate_w)
                self.syscalls.protect_parent(supervisor_pid)
                require(os.read(gate_r, 1) == b"G", "CHILD_GATE_CLOSED")
                os.close(gate_r)
                os.setgroups([])
                self.syscalls.namespaces()
                # Parent is the only UID/GID-map writer; this is trusted setup,
                # before child checkout/import or credential access.
                child.send(b"MAP")
                require(child.recv(1) == b"M", "CHILD_MAP_GATE_CLOSED")
                os.setresgid(0, 0, 0)
                os.setresuid(0, 0, 0)
                self.syscalls.protect_parent(supervisor_pid)
                parent_identity_fd = os.pidfd_open(os.getpid(), 0)
                init = os.fork()
                if init:
                    os.close(parent_identity_fd)
                    child.close()
                    os.waitpid(init, 0)
                    os._exit(0)
                # PID-namespace init dies on intermediate parent death; kernel
                # kills namespace descendants even after a double fork.
                # getppid() is zero for a parent outside this PID namespace.
                # A retained pidfd closes the death-before-prctl race instead.
                self.syscalls.prctl(1, signal.SIGKILL)
                require(not select.select([parent_identity_fd], [], [], 0)[0], "SUPERVISOR_PARENT_DIED")
                os.close(parent_identity_fd)
                self.syscalls.readonly_root(self.context._root_fd)
                channel_fd = child.fileno()
                # Only this owned local channel survives. Never inherit a root,
                # cgroup, trust, journal, network or credential descriptor.
                os.closerange(0, channel_fd)
                os.closerange(channel_fd + 1, 1048576)
                self.syscalls.drop_privileges()
                self.syscalls.seccomp()
                child.send(b"READY")
                # The isolated custodian holds the channel until cancellation,
                # deadline or EOF. Probe execution is the later fixed proxy
                # component, not an arbitrary argv/callback in this packet.
                while time.monotonic() < deadline:
                    child.settimeout(max(0.001, deadline - time.monotonic()))
                    if child.recv(1) != b"P":
                        break
                    child.send(b"P")
                os._exit(0)
            except BaseException:
                os._exit(125)
        self.child_pid = pid
        child.close()
        os.close(gate_r)
        try:
            self.lease.attach(pid)
            os.write(gate_w, b"G")
        finally:
            os.close(gate_w)
        raw, cred = self._receive(8)
        require(raw == b"MAP" and cred[0] == pid and cred[1:] == (0, 0), "CHILD_MAP_PEER_INVALID")
        for name, value in (("setgroups", b"deny"), ("uid_map", f"0 {CHILD_UID} 1".encode()),
                            ("gid_map", f"0 {CHILD_GID} 1".encode())):
            # Exact kernel child paths while the unreaped, owned child is gated.
            fd = os.open(f"/proc/{pid}/{name}", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                require(os.write(fd, value) == len(value), "CHILD_MAP_WRITE_FAILED")
            finally:
                os.close(fd)
        parent.send(b"M")
        raw, cred = self._receive(8)
        require(raw == b"READY" and cred[1:] == (CHILD_UID, CHILD_GID), "CHILD_PEER_INVALID")
        self.pidfd = os.pidfd_open(cred[0], 0)
        self.peer = process_identity(cred[0])
        require(self.peer["parent"] == pid, "CHILD_PARENT_MISMATCH")
        self.channel_identity = os.fstat(parent.fileno()).st_ino
        self.check_peer()

    def _receive(self, size):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0 and not self.cancelled, "SUPERVISOR_EXPIRED")
        self.channel.settimeout(min(remaining, 1))
        while time.monotonic() < self.deadline and not self.cancelled:
            try:
                raw, ancillary, flags, _ = self.channel.recvmsg(size, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4))
                peer = credentials(ancillary, flags)
                require(raw, "CHILD_CHANNEL_EOF")
                return raw, peer
            except socket.timeout:
                continue
        raise ConformanceError("SUPERVISOR_EXPIRED", "bounded channel deadline reached")

    def check_peer(self):
        require(self.peer is not None and not self.cancelled
                and os.fstat(self.channel.fileno()).st_ino == self.channel_identity, "PEER_CHANNEL_CHANGED")
        require(not select.select([self.pidfd], [], [], 0)[0], "PEER_DIED")
        validate_peer(process_identity(self.peer["pid"]), self.peer, self.parent_namespaces)

    def request(self, case_id):
        return build_probe_request(self.context._envelope, self.context._capacity, self.context._plan, case_id)

    def execute(self, request, deadline):
        self.check_peer()
        self.channel.send(b"P")
        raw, peer = self._receive(1)
        require(raw == b"P" and peer == (self.peer["pid"], CHILD_UID, CHILD_GID), "PEER_CHANNEL_CHANGED")
        # Only the fixed, installed successor module is eligible. No registry,
        # module name, callback or command comes from caller data. It must enforce
        # the signed endpoint and server-side admission under CONF-LIVE-003.
        try:
            from .live_proxy_client import execute_protected
        except ImportError as exc:
            raise ConformanceError("PROTECTED_PROXY_UNAVAILABLE", "CONF-LIVE-003 is not installed") from exc
        return execute_protected(request, self.context, deadline)

    def interrupt(self):
        self.cancelled = True
        if self.lease.owned and not self.lease.closed:
            self.lease.write("cgroup.kill", b"1")

    def cleanup(self):
        try:
            if self.child_pid is not None and self.lease.owned and not self.lease.closed:
                self.lease.kill_and_reap(self.child_pid, time.monotonic() + 10)
        finally:
            if self.channel is not None:
                self.channel.close()
                self.channel = None
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None


class NativeSupervisor(_Lifecycle):
    """Fixed production dependencies; no unit/test/backend/path parameters."""
    evidence_class = "UNSIGNED_PROTECTED_RECEIPT_CANDIDATE"

    def __init__(self):
        installed_process()
        self._syscalls = LinuxSyscalls()
        directory = open_directory("/var/lib/planeon/live-backend", private=True)
        try:
            self._lease_fd = os.open("session.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            info = os.fstat(self._lease_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, "SUPERVISOR_LEASE_INVALID")
            fcntl.flock(self._lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            if hasattr(self, "_lease_fd"):
                os.close(self._lease_fd)
            raise
        finally:
            os.close(directory)
        try:
            self._lease = CgroupLease()
            super().__init__(ReplayStore(), None)
        except BaseException:
            if hasattr(self, "_lease"):
                self._lease.close()
            os.close(self._lease_fd)
            raise
        self._context = None
        self._closed = False

    def open_session(self, envelope_bytes, installed_context=None):
        # The sole context is generated here from independently owned files.
        # No caller-owned context (even another native instance's) is accepted.
        require(installed_context is None, "CALLER_CONTEXT_FORBIDDEN")
        with self._mutex:
            require(not self._closed and self._context is None, "SUPERVISOR_ONE_SHOT")
            from .live import validate_envelope
            now = utc_now()
            envelope = validate_envelope(require_canonical_document(envelope_bytes), now=require_time(now, "now"))
            capacity = read_owned(envelope["capacityAuthorizationFileReference"], expected_digest=envelope["capacityAuthorizationDigest"])
            release_trust = read_owned(str(FIXED_RELEASE_TRUST))
            tenant_trust = read_owned(str(FIXED_TENANT_TRUST))
            envelope, capacity_data, _, _ = verify_backend_authority(envelope_bytes, capacity, release_trust, tenant_trust,
                                                                  now=require_time(now, "now"))
            read_owned(str(EXPECTED_LAUNCHER), expected_digest=envelope["launcherDigest"])
            release_raw = read_owned(envelope["campaignReleaseFileReference"], expected_digest=envelope["campaignReleaseDigest"])
            release = require_canonical_document(release_raw)
            architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
            require(architecture is not None, "LINUX_ARCHITECTURE_UNAVAILABLE")
            # The signed release already names each architecture's plan.
            plan_path = f"campaigns/platform/linux-baseline/inputs/{architecture}.json"
            match = [row for row in release["tree"] if row["path"] == plan_path]
            require(len(match) == 1, "RELEASE_PLAN_UNAVAILABLE")
            kit_sources = read_owned_kit(envelope["conformanceKitRoot"], envelope["conformanceKitDigest"])
            require(plan_path in kit_sources, "RELEASE_PLAN_UNAVAILABLE")
            plan_raw = kit_sources[plan_path]
            binding = binding_from_authority(envelope_bytes, capacity, release_trust, tenant_trust,
                release_bytes=release_raw, plan_bytes=plan_raw, architecture=architecture,
                expected_nonce=envelope["nonce"], expected_tenant=envelope["tenantId"],
                expected_environment=envelope["environmentId"], expected_release=envelope["campaignReleaseDigest"], now=now)
            for path_field, digest_field in (("packetFileReference", "packetDigest"),
                    ("campaignDefinitionFileReference", "campaignDefinitionDigest"), ("bundleFileReference", "bundleDigest")):
                read_owned(envelope[path_field], expected_digest=envelope[digest_field])
            # All rootfs bytes must belong to the signed kit. No host filesystem
            # fallback, runtime download, or arbitrary mount selected by a child.
            context = object.__new__(InstalledContext)
            context._owner, context._binding = self, binding
            context._plan = require_canonical_document(plan_raw)
            context._envelope, context._capacity = envelope, capacity_data
            context._source_digest = envelope["conformanceKitDigest"]
            context._root_fd = open_directory(envelope["conformanceKitRoot"] + "/rootfs")
            self._context = context
            self._boundary = _NativeChannel(context, self._syscalls, self._lease)
            return self._open(binding, context._plan)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            super().close()
        finally:
            if self._context is not None:
                os.close(self._context._root_fd)
                self._context = None
            self._journal.close()
            self._lease.close()
            os.close(self._lease_fd)
