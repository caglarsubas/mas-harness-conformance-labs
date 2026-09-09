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

from .canonical import byte_digest, canonical_bytes, canonical_digest, require_canonical_document
from .crypto import b64url_decode, signature_payload, verify
from .errors import ConformanceError
from .linux_readiness import ARCHITECTURES, CASES, build_probe_request, require_time
from .live import ENVELOPE_DOMAIN, FIXED_RELEASE_TRUST, FIXED_TENANT_TRUST, _trust_key
from .live_backend_authority import COMMANDS, PACKET_ID, PACKET_DIGEST, binding_from_authority, verify_backend_authority
from .live_linux_boundary import (CHILD_UID, CHILD_GID, CgroupLease, LinuxSyscalls, credentials,
    ambient_custody, installed_process, process_identity, read_owned, read_owned_kit, require, validate_peer)
from .live_replay_store import ReplayStore, UnitReplayStore, open_directory
from .live_session import SCHEMA, validate_binding, validate_receipt, validate_session


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _verify_reference_authority(envelope, release_raw, tenant_raw, now):
    """Verify BOTH signatures before opening any envelope-selected reference.

    Capacity's independent third signature is verified after reading its exact
    now-authenticated reference. This early check grants no session/execution.
    """
    instant = require_time(now, "now")
    require(envelope["packetId"] == PACKET_ID and envelope["packetDigest"] == PACKET_DIGEST
            and envelope["campaignId"] == "linux-baseline"
            and envelope["commands"] == [list(command) for command in COMMANDS]
            and instant < require_time(envelope["expiresAt"], "expiresAt"), "REFERENCE_AUTHORITY_SCOPE_INVALID")
    require(byte_digest(release_raw) == envelope["releaseTrustStoreDigest"]
            and byte_digest(tenant_raw) == envelope["tenantTrustStoreDigest"], "REFERENCE_TRUST_DIGEST_MISMATCH")
    payload = signature_payload(ENVELOPE_DOMAIN, envelope, ("platformSignature", "tenantSignature"))
    selected = []
    for raw, role, field, signature, tenant, environment in (
            (release_raw, "PLATFORM_RELEASE", "platformSignerKeyId", "platformSignature", None, None),
            (tenant_raw, "TENANT_LIVE_EXECUTION", "tenantSignerKeyId", "tenantSignature",
             envelope["tenantId"], envelope["environmentId"])):
        trust = require_canonical_document(raw)
        key = _trust_key(trust, envelope[field], role, tenant, environment, instant)
        record = next(item for item in trust["keys"] if item["keyId"] == envelope[field])
        require(instant < require_time(record["validUntil"], "validUntil"), "REFERENCE_TRUST_EXPIRED")
        require(verify(key, payload, b64url_decode(envelope[signature], expected_length=64)),
                "REFERENCE_SIGNATURE_INVALID")
        selected.append((key, record["owner"]))
    require(selected[0][0] != selected[1][0] and selected[0][1] != selected[1][1], "SIGNER_ROLES_NOT_INDEPENDENT")


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
        import math
        now = self._clock()
        instant = require_time(now, "now")
        monotonic = self._monotonic()
        require(type(monotonic) in (int, float) and math.isfinite(monotonic)
                and monotonic >= active["lastMonotonic"], "SUPERVISOR_MONOTONIC_ROLLBACK")
        require(instant >= active["lastWall"], "SUPERVISOR_CLOCK_ROLLBACK")
        active["lastWall"] = instant
        active["lastMonotonic"] = monotonic
        require(instant < require_time(active["binding"]["notAfter"], "end")
                and monotonic < active["deadline"], "SUPERVISOR_EXPIRED")
        if type(self) is NativeSupervisor:
            _check_retained_context(self._context, self._boundary, now)
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
        import math
        monotonic = self._monotonic()
        require(type(monotonic) in (int, float) and math.isfinite(monotonic), "SUPERVISOR_MONOTONIC_INVALID")
        active = {"binding": binding, "session": state, "plan": plan, "done": {}, "handle": None,
                  "deadline": monotonic + min(duration, 900), "lastWall": require_time(now, "now"),
                  "lastMonotonic": monotonic, "reserved": False}
        if type(self) is NativeSupervisor:
            require(self._context._deadline is None, "SUPERVISOR_DEADLINE_CHANGED")
            self._context._deadline = active["deadline"]
        # No child, credential, or operation exists before durable reservation.
        # Even an ambiguous reservation makes this instance one-shot.
        self._opened = True
        try:
            self._journal.reserve_nonce(binding, now)
            active["reserved"] = True
            self._active = active
            self._now(active)
            if type(self) is NativeSupervisor:
                self._custody.check_ambient(None)
            self._boundary.establish(binding, plan, active["deadline"])
            self._boundary.check_peer()
            self._journal.running(binding, self._now(active))
            state["state"] = "RUNNING"
            self._serial += 1
            handle = _Handle(self, self._serial)
            active["handle"] = handle
            return handle
        except BaseException:
            if self._active is not None:
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
        import sys
        original_failure = sys.exc_info()[1]
        active = self._active
        if active is None:
            return
        # Invalidate first. Failure to clean up or persist never resurrects it.
        self._active = None
        failure = None
        try:
            import math
            now = self._clock()
            instant, monotonic = require_time(now, "now"), self._monotonic()
            require(instant >= active["lastWall"], "SUPERVISOR_CLOCK_ROLLBACK")
            require(type(monotonic) in (int, float) and math.isfinite(monotonic)
                    and monotonic >= active["lastMonotonic"], "SUPERVISOR_MONOTONIC_ROLLBACK")
            if instant >= require_time(active["binding"]["notAfter"], "end"):
                state = "EXPIRED"
            elif monotonic >= active["deadline"]:
                state = "FAILED"
        except BaseException as exc:
            failure = exc
        try:
            self._boundary.cleanup()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            # Consumed nonce, no terminal claim when time or cleanup is unproven.
            raise original_failure if original_failure is not None else failure
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
    __slots__ = ("_owner", "_binding", "_plan", "_envelope", "_capacity", "_source_digest", "_root_fd",
                 "_custody", "_bytes", "_kit", "_authority", "_snapshot", "_pid", "_deadline", "_late_resources")

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
                os.environ.clear()
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
        require(type(self) is _NativeChannel and type(self.context) is InstalledContext
                and type(self.context._owner) is NativeSupervisor, "CUSTODY_CONTEXT_INVALID")
        self.context._owner._now(self.context._owner._active)
        require(self.peer is not None and not self.cancelled
                and os.fstat(self.channel.fileno()).st_ino == self.channel_identity, "PEER_CHANNEL_CHANGED")
        require(not select.select([self.pidfd], [], [], 0)[0], "PEER_DIED")
        validate_peer(process_identity(self.peer["pid"]), self.peer, self.parent_namespaces)
        self.context._custody.check_ambient(self)

    def request(self, case_id):
        self.check_peer()
        return build_probe_request(self.context._envelope, self.context._capacity, self.context._plan, case_id)

    def execute(self, request, deadline):
        self.check_peer()
        require(type(request) is dict and request.get("operation") in CASES
                and request == self.request(request["operation"]), "SUPERVISOR_OPERATION_INVALID")
        self.channel.send(b"P")
        raw, peer = self._receive(1)
        require(raw == b"P" and peer == (self.peer["pid"], CHILD_UID, CHILD_GID), "PEER_CHANNEL_CHANGED")
        self.check_peer()
        require(deadline == self.context._owner._active["deadline"], "SUPERVISOR_DEADLINE_CHANGED")
        # Only the fixed, installed successor module is eligible. No registry,
        # module name, callback or command comes from caller data. It must enforce
        # the signed endpoint and server-side admission under CONF-LIVE-003.
        try:
            from .live_proxy_client import execute_protected
        except ImportError as exc:
            raise ConformanceError("PROTECTED_PROXY_UNAVAILABLE", "CONF-LIVE-003 is not installed") from exc
        resources = _begin_fixed_resources(self, request, deadline)
        try:
            result = execute_protected(request, self.context, deadline)
            self.check_peer()
            if resources.raw is not None:
                _require_current_credential_policy(self.context)
            # No transport or secret memfd survives a returned receipt.
            resources.finish()
            self.check_peer()
            return result
        except BaseException:
            resources._fail()
            raise

    def interrupt(self):
        self.cancelled = True
        if self.lease.owned and not self.lease.closed:
            self.lease.write("cgroup.kill", b"1")

    def cleanup(self):
        self.cancelled = True
        failure = None
        try:
            if self.child_pid is not None and self.lease.owned and not self.lease.closed:
                self.lease.kill_and_reap(self.child_pid, time.monotonic() + 10)
        except BaseException as exc:
            failure = exc
        channel, pidfd = self.channel, self.pidfd
        self.channel = self.pidfd = None
        operations = []
        if channel is not None:
            operations.append(channel.close)
        if pidfd is not None:
            operations.append(lambda: os.close(pidfd))
        # Partial construction may have no context; absence permits cleanup
        # only, never any check_peer/request/execute authority.
        context = getattr(self, "context", None)
        if type(context) is InstalledContext:
            context._root_fd = None
            operations.append(context._custody.close)
        for operation in operations:
            try:
                operation()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure


class NativeSupervisor(_Lifecycle):
    """Fixed production dependencies; no unit/test/backend/path parameters."""
    evidence_class = "UNSIGNED_PROTECTED_RECEIPT_CANDIDATE"

    def __init__(self):
        from .live_linux_boundary import _begin_custody
        self._context = self._custody = self._journal = self._lease = self._lease_fd = None
        self._closed = False
        directory = None
        try:
            self._custody = _begin_custody(self)
            self._launcher_digest = installed_process()
            require(self._custody.manifest_digest == self._launcher_digest, "CUSTODY_INCOMPLETE")
            ambient_custody()
            self._syscalls = LinuxSyscalls()
            directory = open_directory("/var/lib/planeon/live-backend", private=True)
            self._lease_fd = os.open("session.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            info = os.fstat(self._lease_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, "SUPERVISOR_LEASE_INVALID")
            fcntl.flock(self._lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            retained_directory, directory = directory, None
            os.close(retained_directory)
            self._lease = CgroupLease()
            super().__init__(ReplayStore(), None)
            self._custody.bind_runtime()
        except BaseException:
            self._closed = True
            _cleanup_native(self, directory)
            raise

    def open_session(self, envelope_bytes, installed_context=None):
        # Keep dual-signature first-read ordering even for data-only unit mocks.
        require(installed_context is None, "CALLER_CONTEXT_FORBIDDEN")
        with self._mutex:
            require(not self._closed and self._context is None, "SUPERVISOR_ONE_SHOT")
            try:
                return _open_retained_session(self, envelope_bytes)
            except BaseException:
                self._closed = True
                _cleanup_native(self, None)
                raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        failure = None
        try:
            super().close()
        except BaseException as exc:
            failure = exc
        try:
            _cleanup_native(self, None)
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            raise failure


def _cleanup_native(owner, directory):
    operations = []
    custody = getattr(owner, "_custody", None)
    if directory is not None:
        operations.append(lambda: os.close(directory))
    context = getattr(owner, "_context", None)
    owner._context = None
    if type(context) is InstalledContext:
        context._root_fd = None
    for name in ("_custody", "_journal", "_lease"):
        resource = getattr(owner, name, None)
        setattr(owner, name, None)
        if resource is not None:
            if name == "_journal":
                operations.append(lambda resource=resource: _close_replay_handles(resource, custody))
            else:
                operations.append(lambda resource=resource: resource.close())
    fd = getattr(owner, "_lease_fd", None)
    owner._lease_fd = None
    if fd is not None:
        operations.append(lambda: os.close(fd))
    failure = None
    for operation in operations:
        try:
            operation()
        except BaseException as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        raise failure


def _close_replay_handles(journal, custody):
    # The fixed ReplayStore has two close-owned FDs. Its legacy close method
    # stops after its first error; take both once so that directory custody is
    # not leaked. No journal bytes/history or transaction logic is changed.
    storage = journal._storage
    fd, directory = storage.fd, storage.directory
    storage.fd = storage.directory = None
    retained = None if custody is None else custody.replay_handles
    descriptors = (fd, directory) if retained is None else retained
    failure = None
    if descriptors != (fd, directory):
        failure = ConformanceError("CUSTODY_RUNTIME_CHANGED", "replay descriptors changed")
    for descriptor in descriptors:
        try:
            if custody is not None and custody.runtime_handles is not None:
                expected = custody.runtime_handles[descriptor]
                info = os.fstat(descriptor)
                require((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                        == (expected[0], expected[1], stat.S_IFMT(expected[4])), "CUSTODY_DESCRIPTOR_REUSED")
            os.close(descriptor)
        except BaseException as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        raise failure


def _open_retained_session(owner, envelope_bytes):
    from .live import validate_envelope
    from .live_linux_boundary import _owned_custody
    now = utc_now()
    envelope = validate_envelope(require_canonical_document(envelope_bytes), now=require_time(now, "now"))
    release_trust = read_owned(str(FIXED_RELEASE_TRUST))
    tenant_trust = read_owned(str(FIXED_TENANT_TRUST))
    _verify_reference_authority(envelope, release_trust, tenant_trust, now)
    capacity = read_owned(envelope["capacityAuthorizationFileReference"], expected_digest=envelope["capacityAuthorizationDigest"])
    envelope, capacity_data, _, _ = verify_backend_authority(envelope_bytes, capacity, release_trust, tenant_trust,
                                                          now=require_time(now, "now"))
    custody = _owned_custody(owner)
    custody.check_ambient(None)
    require(owner._custody is custody and owner._launcher_digest == envelope["launcherDigest"], "LAUNCHER_DIGEST_MISMATCH")
    expected = {str(FIXED_RELEASE_TRUST): release_trust, str(FIXED_TENANT_TRUST): tenant_trust,
                envelope["capacityAuthorizationFileReference"]: capacity}
    custody.require_bytes(expected)
    release_raw = read_owned(envelope["campaignReleaseFileReference"], expected_digest=envelope["campaignReleaseDigest"])
    expected[envelope["campaignReleaseFileReference"]] = release_raw
    release = require_canonical_document(release_raw)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
    require(architecture is not None, "LINUX_ARCHITECTURE_UNAVAILABLE")
    plan_path = f"campaigns/platform/linux-baseline/inputs/{architecture}.json"
    require(len([row for row in release["tree"] if row["path"] == plan_path]) == 1, "RELEASE_PLAN_UNAVAILABLE")
    kit_sources = read_owned_kit(envelope["conformanceKitRoot"], envelope["conformanceKitDigest"])
    require(plan_path in kit_sources, "RELEASE_PLAN_UNAVAILABLE")
    plan_raw = kit_sources[plan_path]
    binding = binding_from_authority(envelope_bytes, capacity, release_trust, tenant_trust,
        release_bytes=release_raw, plan_bytes=plan_raw, architecture=architecture,
        expected_nonce=envelope["nonce"], expected_tenant=envelope["tenantId"],
        expected_environment=envelope["environmentId"], expected_release=envelope["campaignReleaseDigest"], now=now)
    for path_field, digest_field in (("packetFileReference", "packetDigest"),
            ("campaignDefinitionFileReference", "campaignDefinitionDigest"), ("bundleFileReference", "bundleDigest")):
        expected[envelope[path_field]] = read_owned(envelope[path_field], expected_digest=envelope[digest_field])
    root_fd = custody.seal(expected, envelope["conformanceKitRoot"], envelope["conformanceKitDigest"], kit_sources)
    context = object.__new__(InstalledContext)
    context._owner, context._binding, context._custody = owner, binding, custody
    context._plan = require_canonical_document(plan_raw)
    context._envelope, context._capacity = envelope, capacity_data
    context._source_digest, context._root_fd = envelope["conformanceKitDigest"], root_fd
    context._bytes, context._kit = custody.files, custody.kit_sources
    context._authority = (envelope_bytes, capacity, release_trust, tenant_trust)
    context._pid = os.getpid()
    context._deadline = None
    context._snapshot = canonical_bytes([binding, context._plan, envelope, capacity_data])
    context._late_resources = None
    owner._context = context
    _new_late_resources(context)
    owner._boundary = _NativeChannel(context, owner._syscalls, owner._lease)
    return owner._open(binding, context._plan)


def _check_retained_context(context, channel, now):
    from .live_linux_boundary import _owned_custody
    require(type(context) is InstalledContext and type(context._owner) is NativeSupervisor
            and context._pid == os.getpid(), "CUSTODY_CONTEXT_INVALID")
    owner = context._owner
    custody = _owned_custody(owner)
    require(owner._context is context and owner._custody is custody and context._custody is custody
            and not owner._closed and custody.sealed and type(channel) is _NativeChannel and owner._boundary is channel
            and channel.context is context and not channel.cancelled
            and owner._active is not None and owner._active["reserved"], "CUSTODY_SESSION_INVALID")
    require(owner._active["binding"] == context._binding
            and owner._active["deadline"] == context._deadline
            and context._snapshot == canonical_bytes([context._binding, context._plan, context._envelope, context._capacity])
            and context._bytes is custody.files and context._kit is custody.kit_sources
            and context._source_digest == custody.kit_digest
            and context._root_fd == custody.handles[custody.kit_root + "/rootfs"]["fd"], "CUSTODY_CONTEXT_CHANGED")
    custody.check()
    envelope, capacity, _, _ = verify_backend_authority(*context._authority, now=require_time(now, "now"))
    require(envelope == context._envelope and capacity == context._capacity, "CUSTODY_AUTHORITY_CHANGED")
    context._late_resources.check()


def _new_late_resources(context):
    import sys
    from .live_linux_boundary import _LateResources
    require(sys._getframe(1).f_code is _open_retained_session.__code__
            and type(context) is InstalledContext and context._owner._context is context
            and context._late_resources is None and context._custody.late_resources is None,
            "CREDENTIAL_FACTORY_REQUIRED")
    resource = object.__new__(_LateResources)
    resource.context, resource.owner = context, context._owner
    resource.pid, resource.thread = os.getpid(), threading.get_ident()
    resource.scope = context._snapshot
    resource.state, resource.operation, resource.deadline = "ABSENT", None, None
    resource.handles, resource.io = [], {}
    resource.raw, resource.endpoint = None, None
    resource.credential_path = None
    resource.cleanup_failure = None
    context._late_resources = context._custody.late_resources = resource


def _begin_fixed_resources(channel, request, deadline):
    import sys
    frame = sys._getframe(1)
    require(frame.f_code is _NativeChannel.execute.__code__ and frame.f_locals.get("self") is channel,
            "CREDENTIAL_HOOK_REQUIRED")
    # The exact execute frame has just validated this request, deadline and
    # post-receive peer. This definition-only state transition performs no
    # blocking work; do not repeat the entire signed-authority verification.
    resource = channel.context._late_resources
    require(resource.state in ("ABSENT", "RETAINED") and resource.operation is None and not resource.io
            and request == build_probe_request(channel.context._envelope, channel.context._capacity,
                                                channel.context._plan, request["operation"])
            and request["operation"] not in channel.context._owner._active["done"]
            and deadline == channel.context._deadline, "CREDENTIAL_OPERATION_INVALID")
    resource.operation, resource.deadline = request["operation"], deadline
    resource.state = "IO_ACTIVE"
    resource.check()
    return resource


def _fixed_credential_proxy(context):
    """Only the installed fixed module, never a caller callback or import name."""
    from types import ModuleType, FunctionType
    from .live import EXPECTED_LAUNCHER
    try:
        from . import live_proxy_client as proxy
    except ImportError as exc:
        raise ConformanceError("PROTECTED_PROXY_UNAVAILABLE", "CONF-LIVE-003 is not installed") from exc
    require(type(proxy) is ModuleType and proxy.__name__ == "harness_conformance.live_proxy_client"
            and getattr(getattr(proxy, "__loader__", None), "archive", None) == str(EXPECTED_LAUNCHER)
            and type(getattr(proxy, "execute_protected", None)) is FunctionType,
            "CREDENTIAL_PROXY_CUSTODY_REQUIRED")
    return proxy


def _require_current_credential_policy(context):
    # CONF-LIVE-003 owns actual independently current observation/admission and
    # strict profile/TLS checks. It must implement this fixed private guard;
    # absence is unavailable. Neither data, a callback nor a truthy token is
    # accepted here as a substitute for that installed verification path.
    from types import FunctionType
    proxy = _fixed_credential_proxy(context)
    guard = getattr(proxy, "_require_current_credential_policy", None)
    require(type(guard) is FunctionType, "CREDENTIAL_POLICY_UNAVAILABLE")
    channel = context._owner._boundary
    channel.check_peer()
    require(guard(context, context._deadline) is None, "CREDENTIAL_POLICY_RESULT_INVALID")
    channel.check_peer()


def _check_proxy_resource_access(context):
    import sys
    proxy = _fixed_credential_proxy(context)
    # Anchor both ends of the active call stack. A copied context, direct
    # helper call or invocation after the hook returned grants nothing.
    frame, proxy_seen, owner_seen = sys._getframe(1), False, False
    for _ in range(32):
        if frame is None:
            break
        if frame.f_code is proxy.execute_protected.__code__:
            require(frame.f_locals.get("context") is context, "CREDENTIAL_HOOK_REQUIRED")
            proxy_seen = True
        if frame.f_code is _NativeChannel.execute.__code__:
            require(proxy_seen and frame.f_locals.get("self") is context._owner._boundary
                    and frame.f_locals.get("deadline") == context._deadline, "CREDENTIAL_HOOK_REQUIRED")
            owner_seen = True
            break
        frame = frame.f_back
    require(proxy_seen and owner_seen and context._late_resources.operation is not None,
            "CREDENTIAL_HOOK_REQUIRED")
    _require_current_credential_policy(context)


def _credential_spec(context):
    """Origin/binding checks, not a replacement for the strict proxy validator."""
    import ipaddress
    import sys
    from .live_linux_boundary import _LateResources
    frame = sys._getframe(1)
    require(frame.f_code in (_LateResources._guard.__code__, _LateResources.credential_bytes.__code__)
            and frame.f_locals.get("self") is context._late_resources, "CREDENTIAL_HOOK_REQUIRED")
    # Both fixed callers just performed the full peer/policy/peer guard. This
    # helper only derives data from already retained bytes; it opens no resource
    # and does no blocking I/O. Every actual I/O retains its full post-check.
    raw = context._kit.get("campaigns/platform/linux-baseline/proxy-profile.json")
    require(type(raw) is bytes and 0 < len(raw) <= 262144, "CREDENTIAL_PROFILE_UNAVAILABLE")
    profile = require_canonical_document(raw)
    require(profile.get("profileId") == "CAMPAIGN_PROXY_MTLS_ZERO_COST_V1", "CREDENTIAL_PROFILE_UNAVAILABLE")
    envelope, capacity, binding = context._envelope, context._capacity, profile["binding"]
    for field, expected in (("tenantId", envelope["tenantId"]), ("environmentId", envelope["environmentId"]),
            ("runNonce", envelope["nonce"]), ("capacityNonce", capacity["nonce"]),
            ("namespace", context._plan["namespace"])):
        require(binding[field] == expected, "CREDENTIAL_PROFILE_SCOPE")
    entries = profile["capacityEntries"]
    require(type(entries) is dict and entries and all(capacity.get(k) == v for k, v in entries.items()),
            "CREDENTIAL_CAPACITY_CHANGED")
    endpoints = [e for e in envelope["endpoints"] if e["kind"] == "CAMPAIGN_PROXY"
                 and e["endpointId"] == binding["endpointId"]]
    require(len(endpoints) == 1, "CREDENTIAL_ENDPOINT_INVALID")
    endpoint = endpoints[0]
    # The unchanged session wire binding carries endpointId, not a per-endpoint
    # digest. Exact endpoint bytes remain bound by the verified envelope and
    # immutable context snapshot checked above; do not invent a wire field.
    require(context._binding["endpointId"] == endpoint["endpointId"] == context._plan["endpointId"],
            "CREDENTIAL_ENDPOINT_CHANGED")
    identities = [e for e in capacity["credentialIdentities"] if e["endpointId"] == endpoint["endpointId"]]
    require(len(identities) == 1 and identities[0]["purpose"] == "CAMPAIGN_PROXY_CLIENT_MTLS"
            and identities[0]["subject"] == binding["serviceAccountSubject"]
            and identities[0]["expiresAt"] == binding["expiresAt"], "CREDENTIAL_IDENTITY_INVALID")
    instant = require_time(context._owner._clock(), "now")
    require(require_time(binding["validFrom"], "validFrom") <= instant
            < require_time(binding["expiresAt"], "expiresAt"), "CREDENTIAL_EXPIRED")
    address = ipaddress.ip_address(endpoint["ipAddress"])
    require(str(address) == endpoint["ipAddress"] and type(endpoint["port"]) is int
            and 0 < endpoint["port"] < 65536, "CREDENTIAL_ENDPOINT_INVALID")
    return endpoint["credentialFileReference"], endpoint
