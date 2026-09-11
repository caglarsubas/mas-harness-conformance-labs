"""Independent, fixed installed proxy owner; never a campaign-selected service.

The policy producer, enforced capacity broker and native fixed probes must be
independently installed/qualified. Missing prerequisites refuse startup/effects.
This source packet does not install them or qualify a native architecture.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import importlib
import ipaddress
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import threading
import time
from types import FunctionType

from .canonical import byte_digest, canonical_bytes, canonical_digest, require_canonical_document
from .crypto import b64url_decode, verify
from .errors import ConformanceError
from .linux_readiness import CASES, build_probe_request, require_time
from .live import FIXED_RELEASE_TRUST, FIXED_TENANT_TRUST, PINNED_ROOT_PUBLIC_KEY_SHA256
from .live_backend_authority import verify_backend_authority, binding_from_authority
from .live_linux_boundary import credentials, process_identity, _custody_identity
from .live_mutation_admission import (require, document, retained_profile, validate_messages,
    _time, ZERO, admission_binding, _AdmissionLog, parse_reservations, cleanup_receipt)
from .live_proxy_client import (_TLS, tls_context, credential_leaf, _check_certificate,
                                read_http, http_message)
from .live_supervisor import utc_now, _verify_reference_authority
from .schema import closed, require_digest

EXECUTABLE = "/opt/planeon/bin/harness-live-proxy-serve"
MANIFEST = "/etc/planeon/harness-live-proxy-manifest.json"
PUBLIC_KEY = "/etc/planeon/harness-live-runner-manifest.pub"
IDENTITY = "/etc/planeon/live-proxy/server-identity.pem"
STATE = "/var/lib/planeon/live-proxy"
OBSERVER = "/opt/planeon/bin/harness-policy-observer"
OBSERVER_MANIFEST = "/etc/planeon/harness-policy-observer-manifest.json"
OBSERVER_SOCKET = "/run/planeon/live-proxy/policy-observer.sock"
_ACTIVE = None


def _installed_entry():
    require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "PROXY_NATIVE_INSTALLATION_UNAVAILABLE")
    require(getattr(globals().get("__loader__"), "archive", None) == EXECUTABLE
            and sys.argv == [EXECUTABLE], "PROXY_INSTALLED_CODE_REQUIRED")
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "HARNESS_LIVE_EXECUTION_ENVELOPE"}
    require(not set(os.environ) - allowed and len(os.listdir("/proc/self/task")) == 1,
            "PROXY_AMBIENT_CONTEXT_FORBIDDEN")
    require(not Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "PROXY_DEDICATED_PROCESS_REQUIRED")
    for name in os.listdir("/proc/self/fd"):
        try:
            info = os.fstat(int(name))
        except OSError:
            continue
        require(int(name) <= 2 and not stat.S_ISSOCK(info.st_mode), "PROXY_AMBIENT_FD_FORBIDDEN")


class _Files:
    """One close owner; bounded first read with retained complete ancestry."""
    def __init__(self, owner):
        self.owner, self.rows, self.raw = owner, {}, {}
        self.sealed, self.closed, self.total = False, False, 0
        self.cleanup_failure = None

    def check(self):
        self.owner._owner_check()
        require(not self.closed, "PROXY_FILES_CLOSED")
        for row in self.rows.values():
            require(row[3] is not None and _custody_identity(os.fstat(row[0])) == row[3]
                    and _custody_identity(os.stat(row[2], dir_fd=row[1], follow_symlinks=False)) == row[3]
                    and not os.get_inheritable(row[0]), "PROXY_FILE_CHANGED")

    def _open(self, path, directory, mode=None, writable=False):
        self.check()
        require(type(path) is str and path.startswith("/") and "\\" not in path
                and len(path.encode()) <= 4096 and len(path.split("/")) <= 65
                and (path == "/" or all(p not in ("", ".", "..") for p in path[1:].split("/"))),
                "PROXY_PATH_INVALID")
        if path in self.rows:
            fd = self.rows[path][0]
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) == directory and (mode is None or stat.S_IMODE(info.st_mode) == mode),
                    "PROXY_FILE_MODE")
            return fd
        require(not self.sealed and len(self.rows) < 8448, "PROXY_FILES_SEALED")
        parent_path, name = path.rsplit("/", 1) if path != "/" else (None, "/")
        parent = None if path == "/" else self._open(parent_path or "/", True)
        flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        flags |= os.O_DIRECTORY | os.O_RDONLY if directory else os.O_RDWR | os.O_APPEND if writable else os.O_RDONLY
        fd = os.open(name, flags, dir_fd=parent)
        self.rows[path] = [fd, parent, name, None]
        info = os.fstat(fd)
        self.rows[path][3] = _custody_identity(info)
        require(2 < fd < 1048576 and info.st_uid == info.st_gid == 0
                and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                and not stat.S_IMODE(info.st_mode) & (0o022 if directory or writable else 0o222)
                and (mode is None or stat.S_IMODE(info.st_mode) == mode), "PROXY_FILE_CUSTODY")
        self.check()
        return fd

    def read(self, path, digest=None, mode=None, maximum=4194304):
        self.check()
        if path not in self.raw:
            require(not self.sealed and len(self.raw) < 4112, "PROXY_FILES_SEALED")
            fd = self._open(path, False, mode)
            size = os.fstat(fd).st_size
            require(0 < size <= maximum and self.total + size <= 100663296, "PROXY_FILE_SIZE")
            chunks, size_read = [], 0
            while size_read <= size:
                chunk = os.read(fd, min(65536, size + 1 - size_read))
                self.check()
                if not chunk:
                    break
                chunks.append(chunk)
                size_read += len(chunk)
            require(size_read == size, "PROXY_FILE_CHANGED")
            self.raw[path] = b"".join(chunks)
            self.total += size
        raw = self.raw[path]
        require(len(raw) <= maximum and (digest is None or byte_digest(raw) == digest), "PROXY_FILE_DIGEST")
        return raw

    def kit(self, root, expected_tree):
        require(type(expected_tree) is list and len(expected_tree) <= 4096, "PROXY_KIT_INVENTORY")
        result, actual, entries = {}, [], 0
        def walk(path, prefix, depth):
            nonlocal entries
            require(depth <= 32, "PROXY_KIT_DEPTH")
            fd = self._open(path, True)
            info = os.fstat(fd)
            require(not stat.S_IMODE(info.st_mode) & 0o222, "PROXY_KIT_WRITABLE")
            for name in sorted(os.listdir(fd), key=lambda n: n.encode()):
                entries += 1
                require(entries <= 8192 and name not in ("", ".", "..") and "/" not in name and "\\" not in name,
                        "PROXY_KIT_INVENTORY")
                observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(observed.st_dev == info.st_dev, "PROXY_KIT_MOUNT_CHANGED")
                relative, absolute = prefix + name, path + "/" + name
                if stat.S_ISDIR(observed.st_mode):
                    walk(absolute, relative + "/", depth + 1)
                else:
                    require(len(actual) < 4096, "PROXY_KIT_INVENTORY")
                    raw = self.read(absolute)
                    result[relative] = raw
                    actual.append({"path": relative, "mode": f"{stat.S_IMODE(observed.st_mode):04o}",
                                   "size": len(raw), "sha256": byte_digest(raw)})
            self.check()
        walk(root, "", 0)
        require(sorted(actual, key=lambda r: r["path"].encode()) == expected_tree, "PROXY_KIT_INVENTORY")
        return result

    def close(self):
        if self.closed:
            if self.cleanup_failure is not None:
                raise self.cleanup_failure
            return
        self.closed = True
        rows, self.rows, self.raw = self.rows, {}, {}
        failure = None
        for fd, _, _, identity in reversed(tuple(rows.values())):
            try:
                if identity is not None:
                    current = _custody_identity(os.fstat(fd))
                    require((current[0], current[1], stat.S_IFMT(current[4])) ==
                            (identity[0], identity[1], stat.S_IFMT(identity[4])), "PROXY_FD_REUSED")
                os.close(fd)
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            self.cleanup_failure = failure
            raise failure


def _manifest(files, path, executable):
    key_raw = files.read(PUBLIC_KEY, PINNED_ROOT_PUBLIC_KEY_SHA256)
    public = require_canonical_document(key_raw)
    closed(public, ("algorithm", "publicKey"))
    require(public["algorithm"] == "ED25519", "PROXY_ROOT_ALGORITHM")
    raw = files.read(path)
    signature = b64url_decode(files.read(path + ".sig").decode("ascii").strip(), expected_length=64)
    require(verify(b64url_decode(public["publicKey"], expected_length=32), raw, signature), "PROXY_MANIFEST_SIGNATURE")
    value = require_canonical_document(raw)
    closed(value, ("schemaVersion", "launcher", "fixedTrustMounts", "isolation", "preflightEvidenceDigest"))
    executable_raw = files.read(executable, mode=0o555)
    require(value["schemaVersion"] == "harness.planeon.ai/live-runner-manifest/v1alpha1"
            and value["launcher"] == {"path": executable, "version": "0.1.0", "sha256": byte_digest(executable_raw),
                "ownerUid": 0, "ownerGid": 0, "mode": "0555"}
            and value["fixedTrustMounts"] == [str(FIXED_RELEASE_TRUST), str(FIXED_TENANT_TRUST)]
            and value["isolation"] == {"backend": "PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1",
                "networkPolicy": "DENY_ALL_EXCEPT_DUAL_SIGNED_ENDPOINTS", "credentialSocketsDenied": True,
                "ciDenied": True}, "PROXY_MANIFEST_INVALID")
    require_digest(value["preflightEvidenceDigest"], "preflightEvidenceDigest")
    return value, byte_digest(raw), byte_digest(executable_raw)


def _fixed_probes():
    try:
        from . import live_fixed_probes as module
    except ImportError as exc:
        raise ConformanceError("PROXY_FIXED_PROBES_UNAVAILABLE", "CONF-LIVE-004 is not installed") from exc
    require(getattr(getattr(module, "__loader__", None), "archive", None) == EXECUTABLE,
            "PROXY_PROBE_CUSTODY")
    for name in ("require_server_containment", "require_observer_containment", "execute_server_probe"):
        require(type(getattr(module, name, None)) is FunctionType, "PROXY_FIXED_PROBES_UNAVAILABLE")
    return module


class _Observer:
    def __init__(self, owner):
        self.owner, self.sock, self.pidfd, self.previous = owner, None, None, None
        self.last_wall, self.last_mono = None, time.monotonic()
        value, manifest_digest, executable_digest = _manifest(owner.files, OBSERVER_MANIFEST, OBSERVER)
        require(owner.observation_binding["observer"] == {"manifestDigest": manifest_digest,
            "executableDigest": executable_digest}, "OBSERVER_ENROLLMENT_MISMATCH")
        self.parent = owner.files._open(OBSERVER_SOCKET.rsplit("/", 1)[0], True, 0o700)
        self.socket_identity = _custody_identity(os.stat("policy-observer.sock", dir_fd=self.parent, follow_symlinks=False))
        info = os.stat("policy-observer.sock", dir_fd=self.parent, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600, "OBSERVER_SOCKET_CUSTODY")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.set_inheritable(False)
        self.sock.setsockopt(socket.SOL_SOCKET, 16, 1)
        self.sock.settimeout(min(2, owner.deadline - time.monotonic()))
        self.sock.connect(OBSERVER_SOCKET)
        self.peer = struct.unpack("3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(self.peer[0] > 1 and self.peer[1:] == (0, 0), "OBSERVER_PEER_INVALID")
        self.identity = process_identity(self.peer[0])
        self.pidfd = os.pidfd_open(self.peer[0], 0)
        require(owner.files.raw[OBSERVER].startswith(b"\x7fELF"), "OBSERVER_NATIVE_ELF_REQUIRED")
        self.check()

    def check(self):
        self.owner._base_check()
        require(_custody_identity(os.stat("policy-observer.sock", dir_fd=self.parent, follow_symlinks=False))
                == self.socket_identity and not select.select([self.pidfd], [], [], 0)[0]
                and process_identity(self.peer[0]) == self.identity, "OBSERVER_PEER_CHANGED")
        actual = os.stat(f"/proc/{self.peer[0]}/exe")
        expected = self.owner.files.rows[OBSERVER][3]
        require((actual.st_dev, actual.st_ino) == expected[:2], "OBSERVER_EXECUTABLE_CHANGED")
        require(_fixed_probes().require_observer_containment(self.owner, self.peer[0], self.identity) is None,
                "OBSERVER_CONTAINMENT_UNAVAILABLE")

    def observe(self):
        self.check()
        previous = self.previous
        request = {"schemaVersion": "planeon.internal.policy-observation-request/v1", "operation": "OBSERVE_POLICY",
            "bindingDigest": canonical_digest(self.owner.observation_binding), "runNonce": self.owner.envelope["nonce"],
            "challenge": os.urandom(32).hex(), "sequence": 1 if previous is None else previous["sequence"] + 1,
            "previousObservationDigest": ZERO if previous is None else canonical_digest(previous)}
        deadline = min(self.owner.deadline, time.monotonic() + 2)
        encoded = canonical_bytes(request)
        self.sock.settimeout(deadline - time.monotonic())
        require(self.sock.send(encoded) == len(encoded), "OBSERVER_SEND_AMBIGUOUS")
        self.check()
        require(time.monotonic() < deadline, "OBSERVER_DEADLINE")
        self.sock.settimeout(deadline - time.monotonic())
        raw, ancillary, flags, _ = self.sock.recvmsg(65537, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4))
        require(credentials(ancillary, flags) == self.peer, "OBSERVER_MESSAGE_PEER")
        self.check()
        mono, now = time.monotonic(), utc_now()
        instant = require_time(now, "now")
        require(self.last_mono <= mono < deadline and (self.last_wall is None or self.last_wall <= instant),
                "OBSERVER_CLOCK_OR_DEADLINE")
        self.previous = validate_messages(self.owner.observation_binding, request, raw, self.owner.profile,
                                         instant.strftime("%Y-%m-%dT%H:%M:%SZ"), previous)
        self.last_mono, self.last_wall = mono, instant
        return self.previous

    def close(self):
        operations = []
        sock, self.sock = self.sock, None
        pidfd, self.pidfd = self.pidfd, None
        if sock is not None:
            operations.append(sock.close)
        if pidfd is not None:
            operations.append(lambda: os.close(pidfd))
        failure = None
        for operation in operations:
            try:
                operation()
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            raise failure


class _State:
    """Exclusive precreated store. Never create, truncate, repair or rotate it."""
    def __init__(self, owner):
        self.owner, self.lock, self.fd = owner, None, None
        self.identities = {}
        self.directory = owner.files._open(STATE, True, 0o700)
        for name, attr in (("admission.lock", "lock"), ("reservations.jsonl", "fd")):
            descriptor = os.open(name, os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=self.directory)
            setattr(self, attr, descriptor)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "ADMISSION_STORE_CUSTODY")
            self.identities[attr] = _custody_identity(info)[:6]
        # Held for this entire independently placed run, including all probes.
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.floor = b""
        self.check()

    def check(self):
        self.owner._owner_check()
        self.owner.files.check()
        for attr, name in (("lock", "admission.lock"), ("fd", "reservations.jsonl")):
            expected = self.identities[attr]
            require(_custody_identity(os.fstat(getattr(self, attr)))[:6] == expected
                    and _custody_identity(os.stat(name, dir_fd=self.directory, follow_symlinks=False))[:6] == expected,
                    "ADMISSION_STORE_CHANGED")

    @contextmanager
    def transaction(self):
        self.check()
        # Separate journal flock also serializes transaction readers. The run
        # lock remains held until close; a competing owner cannot enter startup.
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield self
        finally:
            fcntl.flock(self.fd, fcntl.LOCK_UN)

    def read(self):
        self.check()
        size = os.fstat(self.fd).st_size
        require(0 <= size <= 4194304, "ADMISSION_STORE_FULL")
        raw = os.pread(self.fd, size + 1, 0)
        self.check()
        require(len(raw) == size and raw.startswith(self.floor), "ADMISSION_STORE_ROLLBACK")
        self.floor = raw
        return raw

    def append(self, raw):
        self.check()
        require(os.write(self.fd, raw) == len(raw), "ADMISSION_STORE_SHORT_WRITE")
        self.check()

    def sync(self):
        self.check()
        os.fsync(self.fd)
        os.fsync(self.directory)
        self.check()

    def close(self):
        failure = None
        for attr in ("fd", "lock"):
            fd = getattr(self, attr, None)
            setattr(self, attr, None)
            if fd is not None:
                try:
                    expected = self.identities.get(attr)
                    require(expected is None or _custody_identity(os.fstat(fd))[:6] == expected, "ADMISSION_FD_REUSED")
                    os.close(fd)
                except BaseException as exc:
                    failure = failure or exc
        if failure is not None:
            raise failure


class NativeProxyServer:
    """No caller backend, context, socket, credential or selector parameters."""
    def __init__(self):
        global _ACTIVE
        _installed_entry()
        require(_ACTIVE is None, "PROXY_ALREADY_ACTIVE")
        _ACTIVE = self
        self.pid, self.thread, self.closed = os.getpid(), threading.get_ident(), False
        self.files, self.secrets = _Files(self), _Files(self)
        self.observer = self.storage = self.listener = self.connection = None
        self.memfd = None
        self.active_operation = None
        self.reserved = False
        self.last_wall, self.last_mono = require_time(utc_now(), "now"), time.monotonic()
        try:
            self.manifest, _, self.artifact_digest = _manifest(self.files, MANIFEST, EXECUTABLE)
            envelope_path = os.environ.get("HARNESS_LIVE_EXECUTION_ENVELOPE")
            require(type(envelope_path) is str, "PROXY_ENVELOPE_UNAVAILABLE")
            envelope_raw = self.files.read(envelope_path)
            release_trust, tenant_trust = self.files.read(str(FIXED_RELEASE_TRUST)), self.files.read(str(FIXED_TENANT_TRUST))
            envelope = require_canonical_document(envelope_raw)
            _verify_reference_authority(envelope, release_trust, tenant_trust, utc_now())
            capacity_raw = self.files.read(envelope["capacityAuthorizationFileReference"], envelope["capacityAuthorizationDigest"])
            self.authority = (envelope_raw, capacity_raw, release_trust, tenant_trust)
            self.envelope, self.capacity, _, _ = verify_backend_authority(*self.authority, now=require_time(utc_now(), "now"))
            release_raw = self.files.read(envelope["campaignReleaseFileReference"], envelope["campaignReleaseDigest"])
            release = require_canonical_document(release_raw)
            self.kit = self.files.kit(envelope["conformanceKitRoot"], release["tree"])
            require(canonical_digest(release["tree"], "planeon.harness-live-tree/v1alpha1") == envelope["conformanceKitDigest"],
                    "PROXY_KIT_DIGEST")
            architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
            require(architecture is not None, "PROXY_ARCHITECTURE_UNAVAILABLE")
            plan_raw = self.kit["campaigns/platform/linux-baseline/inputs/" + architecture + ".json"]
            self.plan = require_canonical_document(plan_raw)
            self.binding = binding_from_authority(*self.authority, release_bytes=release_raw, plan_bytes=plan_raw,
                architecture=architecture, expected_nonce=envelope["nonce"], expected_tenant=envelope["tenantId"],
                expected_environment=envelope["environmentId"], expected_release=envelope["campaignReleaseDigest"], now=utc_now())
            for path, digest in (("packetFileReference", "packetDigest"),
                    ("campaignDefinitionFileReference", "campaignDefinitionDigest"), ("bundleFileReference", "bundleDigest")):
                self.files.read(envelope[path], envelope[digest])
            self.profile, self.observation_binding, self.endpoint, self.ca = retained_profile(
                self.envelope, self.capacity, self.plan, release, self.kit)
            require(self.manifest["preflightEvidenceDigest"] == self.observation_binding["enforcementPins"]["hostPreflightDigest"],
                    "PROXY_PREFLIGHT_BINDING")
            remaining = (min(require_time(self.binding["notAfter"], "end"), _time(self.profile["binding"]["expiresAt"]))
                         - require_time(utc_now(), "now")).total_seconds()
            require(0 < remaining <= 900, "PROXY_EXPIRED")
            self.deadline = time.monotonic() + remaining
            self.snapshot = canonical_bytes([self.envelope, self.capacity, self.plan, self.binding,
                                             self.profile, self.observation_binding, self.endpoint])
            require(_fixed_probes().require_server_containment(self) is None, "PROXY_CONTAINMENT_UNAVAILABLE")
            self.storage = object.__new__(_State)
            self.storage.__init__(self)
            self.log = _AdmissionLog(self.storage)
            self.observer = object.__new__(_Observer)
            self.observer.__init__(self)
            self.files.sealed = True
            self.observer.observe()
            self.reservation = admission_binding(self.envelope, self.capacity, self.profile)
            self.log.record(self.reservation, "RESERVED", None, utc_now())
            self.reserved = True
            self._transport_check()
            # The independent SERVER identity receives no client-side exception.
            raw = self.secrets.read(IDENTITY, mode=0o400, maximum=262144)
            self._transport_check()
            _check_certificate(credential_leaf(raw), self.profile, self.endpoint, client=False)
            self.memfd = os.memfd_create("planeon-proxy-identity", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            offset = 0
            while offset < len(raw):
                count = os.write(self.memfd, raw[offset:])
                require(count > 0, "PROXY_CREDENTIAL_SHORT_WRITE")
                offset += count
                self._transport_check()
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
            fcntl.fcntl(self.memfd, fcntl.F_ADD_SEALS, seals)
            require(fcntl.fcntl(self.memfd, fcntl.F_GET_SEALS) & seals == seals, "PROXY_CREDENTIAL_SEALS")
            self.tls = tls_context(self.ca, self.memfd, server=True)
            fd, self.memfd = self.memfd, None
            os.close(fd)
            self._transport_check()
            address = ipaddress.ip_address(self.endpoint["ipAddress"])
            self.target = (str(address), self.endpoint["port"]) if address.version == 4 else (str(address), self.endpoint["port"], 0, 0)
            self.listener = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
            self.listener.set_inheritable(False)
            if address.version == 6:
                self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.listener.bind(self.target)
            self.listener.listen(1)
            self._transport_check()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    def _owner_check(self):
        require(type(self) is NativeProxyServer and _ACTIVE is self and not self.closed
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "PROXY_OWNER_INVALID")

    def _base_check(self):
        self._owner_check()
        self.files.check()
        self.secrets.check()
        now, mono = require_time(utc_now(), "now"), time.monotonic()
        require(now >= self.last_wall and self.last_mono <= mono < self.deadline
                and _time(self.profile["binding"]["validFrom"]) <= now < _time(self.profile["binding"]["expiresAt"]),
                "PROXY_CLOCK_OR_EXPIRY")
        self.last_wall, self.last_mono = now, mono
        envelope, capacity, _, _ = verify_backend_authority(*self.authority, now=now)
        require(envelope == self.envelope and capacity == self.capacity
                and self.snapshot == canonical_bytes([self.envelope, self.capacity, self.plan, self.binding,
                                                       self.profile, self.observation_binding, self.endpoint]),
                "PROXY_AUTHORITY_CHANGED")
        require(_fixed_probes().require_server_containment(self) is None, "PROXY_CONTAINMENT_UNAVAILABLE")

    def _transport_check(self):
        self._base_check()
        require(self.reserved and not self.log.poisoned, "PROXY_RESERVATION_REQUIRED")
        self.storage.check()
        self.observer.observe()

    def _accept(self):
        require(self.connection is None, "PROXY_CONNECTION_ALREADY_OWNED")
        deadline = min(self.deadline, time.monotonic() + 10)
        while self.connection is None:
            self._transport_check()
            before = time.monotonic()
            require(before < deadline, "PROXY_ACCEPT_DEADLINE")
            self.listener.settimeout(min(2, deadline - before))
            try:
                # Retain ownership before any post-I/O guard can fail.
                self.connection, _ = self.listener.accept()
                self.connection.set_inheritable(False)
            except TimeoutError:
                if self.connection is not None:
                    raise  # an acquired connection must never be overwritten
            finally:
                self._transport_check()
                now = time.monotonic()
                require(before <= now < deadline, "PROXY_ACCEPT_DEADLINE")

    def serve(self):
        from .live_session import SCHEMA, validate_receipt
        for _ in CASES:
            try:
                self._accept()
                self._transport_check()
                require(self.listener.getsockname() == self.target, "PROXY_LISTENER_CHANGED")
                tls = _TLS(self.connection, self.tls, self.endpoint, self, self.deadline, server=True)
                tls.handshake(self.profile, self.endpoint, server=True)
                first, raw = read_http(tls, response=False, host=self.endpoint["tls"]["serverName"])
                request = document(raw, 16384)
                operation = request.get("operation")
                require(type(operation) is str and operation in CASES and request == build_probe_request(
                    self.envelope, self.capacity, self.plan, operation)
                    and first == ("POST " + request["path"] + " HTTP/1.1").encode(), "PROXY_REQUEST_BINDING")
                self._transport_check()
                self.log.record(self.reservation, "RUNNING", operation, utc_now())
                self.active_operation = operation
                # CONF-LIVE-004 owns actual probes and the broker-fenced native
                # execution adapter. An absent adapter never returns a receipt.
                result = _fixed_probes().execute_server_probe(request, self, self.deadline)
                require(type(result) is tuple and len(result) == 2 and type(result[0]) is bytes
                        and type(result[1]) is list, "PROXY_PROBE_RESULT_INVALID")
                self._transport_check()
                states, _, _ = parse_reservations(self.storage.read())
                prior = states[(self.envelope["tenantId"], self.envelope["nonce"])]
                cleanup = cleanup_receipt(canonical_digest(self.reservation), operation, utc_now(), result[1], prior["cleanupDigest"])
                session = {k: v for k, v in self.binding.items() if k not in ("notBefore", "notAfter")}
                session.update(schemaVersion=SCHEMA, issuedAt=self.binding["notBefore"], expiresAt=self.binding["notAfter"], state="RUNNING")
                receipt = validate_receipt(result[0], session, self.binding, request,
                    self.plan["regressions"] if operation == "FULL_PREDECESSOR_REGRESSION" else {}, utc_now())
                require(receipt["status"] != "PASS" or not result[1], "PROXY_CLEANUP_NOT_PROVEN")
                self.log.record(self.reservation, "RECORDED", operation, cleanup["observedAt"], cleanup)
                self.active_operation = None
                self._transport_check()
                tls.write(http_message("HTTP/1.1 200 OK", canonical_bytes(receipt)))
                tls.notify_close()
                if receipt["status"] != "PASS":
                    return
            finally:
                connection, self.connection = self.connection, None
                if connection is not None:
                    connection.close()

    def close(self):
        global _ACTIVE
        if self.closed:
            return
        self.closed = True
        operations, failure = [], None
        for attr in ("connection", "listener", "observer", "storage", "secrets", "files"):
            resource = getattr(self, attr, None)
            setattr(self, attr, None)
            if resource is not None:
                operations.append(resource.close)
        fd, self.memfd = self.memfd, None
        if fd is not None:
            operations.append(lambda: os.close(fd))
        for operation in operations:
            try:
                operation()
            except BaseException as exc:
                failure = failure or exc
        if _ACTIVE is self:
            _ACTIVE = None
        if failure is not None:
            raise failure


def main():
    server = None
    try:
        server = NativeProxyServer()
        server.serve()
        return 0
    except (ConformanceError, OSError, ValueError, KeyError):
        # No arbitrary exception text, authority paths, credentials or report
        # containing a native/tenant PASS is written by the server entry point.
        return 2
    finally:
        if server is not None:
            server.close()
