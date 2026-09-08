"""Fixed Linux containment primitives; importing this module changes no policy.

Only an independently installed, manifest-pinned launcher may construct the
native adapter. Unit tests inject syscall adapters into the explicit unit model.
"""
from __future__ import annotations

import array
import ctypes
import errno
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
import time

from .canonical import byte_digest, canonical_digest
from .canonical import load_json_bytes
from .crypto import b64url_decode, verify
from .errors import ConformanceError
from .live_replay_store import open_directory
from .schema import closed

CHILD_UID = CHILD_GID = 65532
CGROUP = "/sys/fs/cgroup/planeon-live/session"
CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET = 0x10000000, 0x20000, 0x20000000, 0x40000000
PR_SET_PDEATHSIG, PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS = 1, 4, 38
PR_SET_CHILD_SUBREAPER, PR_CAPBSET_DROP, PR_SET_SECCOMP = 36, 24, 22
MS_PRIVATE, MS_REC, MS_BIND = 1 << 18, 16384, 4096
ARCHES = {"x86_64": (0xC000003E, 56, (41, 42, 49, 50, 101, 165, 166, 272, 308, 321, 323, 425, 426, 427, 435, 438)),
          "aarch64": (0xC00000B7, 220, (198, 203, 200, 201, 117, 40, 39, 97, 268, 280, 282, 425, 426, 427, 435, 438))}
NAMESPACE_MASK = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | 0x04000000 | 0x08000000 | 0x02000000
_VERIFIED_MANIFEST = None


def require(condition, reason):
    if not condition:
        raise ConformanceError(reason, "protected Linux boundary refused")


def installed_process():
    # No flag, argv spoof or UID alone establishes installed code custody.
    require(sys.platform == "linux", "LINUX_BACKEND_UNAVAILABLE")
    require(os.geteuid() == 0 and os.getegid() == 0, "LINUX_ROOT_REQUIRED")
    require(not any(os.environ.get(k) for k in ("CI", "GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "BUILDKITE", "JENKINS_URL")),
            "CI_EXECUTION_FORBIDDEN")
    from .live import EXPECTED_LAUNCHER
    loader = globals().get("__loader__")
    require(type(getattr(loader, "archive", None)) is str and loader.archive == str(EXPECTED_LAUNCHER)
            and sys.argv[0] == str(EXPECTED_LAUNCHER), "INSTALLED_CODE_CUSTODY_REQUIRED")
    require(len(os.listdir("/proc/self/task")) == 1, "SINGLE_THREAD_SUPERVISOR_REQUIRED")
    require(not Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip()
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "DEDICATED_SUPERVISOR_REQUIRED")
    return _installed_manifest_digest()


def _installed_manifest_digest():
    """Retain independently verified installed bytes; never re-open to execute.

    Same closed manifest/key contract as the immutable predecessor launcher.
    Internal per-process custody is not a caller-supplied verified flag.
    """
    global _VERIFIED_MANIFEST
    custody = _capture()
    if custody is not None and custody.manifest_digest is not None:
        custody.check()
        return custody.manifest_digest
    if custody is None and _VERIFIED_MANIFEST is not None and _VERIFIED_MANIFEST[0] == os.getpid():
        return _VERIFIED_MANIFEST[1]
    from .live import (EXPECTED_LAUNCHER, FIXED_MANIFEST, FIXED_MANIFEST_PUBLIC,
                      FIXED_MANIFEST_SIGNATURE, PINNED_ROOT_PUBLIC_KEY_SHA256)
    public_raw = read_owned(str(FIXED_MANIFEST_PUBLIC), expected_digest=PINNED_ROOT_PUBLIC_KEY_SHA256)
    public_record = load_json_bytes(public_raw)
    closed(public_record, ("algorithm", "publicKey"))
    require(public_record["algorithm"] == "ED25519", "ROOT_KEY_ALGORITHM")
    raw = read_owned(str(FIXED_MANIFEST))
    signature = b64url_decode(read_owned(str(FIXED_MANIFEST_SIGNATURE)).decode("ascii").strip(), expected_length=64)
    public = b64url_decode(public_record["publicKey"], expected_length=32)
    require(verify(public, raw, signature), "ROOT_MANIFEST_SIGNATURE_INVALID")
    manifest = load_json_bytes(raw)
    closed(manifest, ("schemaVersion", "launcher", "fixedTrustMounts", "isolation", "preflightEvidenceDigest"))
    require(manifest["schemaVersion"] == "harness.planeon.ai/live-runner-manifest/v1alpha1", "ROOT_MANIFEST_SCHEMA")
    launcher_raw = read_owned(str(EXPECTED_LAUNCHER), expected_mode=0o555)
    digest = byte_digest(launcher_raw)
    require(manifest["launcher"] == {"path": str(EXPECTED_LAUNCHER), "version": "0.1.0", "sha256": digest,
            "ownerUid": 0, "ownerGid": 0, "mode": "0555"}, "LAUNCHER_CUSTODY_INVALID")
    # read_owned checked actual owner/mode custody. Retain the source digest;
    # no later pathname becomes authority.
    require(manifest["fixedTrustMounts"] == ["/etc/planeon/trust/release-trust-bundle.json",
            "/etc/planeon/trust/tenant-trust-bundle.json"], "TRUST_MOUNTS_INVALID")
    require(manifest["isolation"] == {"backend": "PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1",
            "networkPolicy": "DENY_ALL_EXCEPT_DUAL_SIGNED_ENDPOINTS", "credentialSocketsDenied": True,
            "ciDenied": True}, "ISOLATION_MANIFEST_INVALID")
    _VERIFIED_MANIFEST = (os.getpid(), digest)
    if custody is not None:
        custody.require_bytes({str(FIXED_MANIFEST_PUBLIC): public_raw,
            str(FIXED_MANIFEST): raw, str(EXPECTED_LAUNCHER): launcher_raw})
        require(str(FIXED_MANIFEST_SIGNATURE) in custody.files, "CUSTODY_INCOMPLETE")
        custody.manifest_digest = digest
    return digest


def ambient_custody():
    # Only fixed launcher input plus non-authorizing locale/stdio metadata.
    # Short-lived credentials are opened later from signed references, never env.
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "HARNESS_LIVE_EXECUTION_ENVELOPE"}
    require(not set(os.environ) - allowed, "AMBIENT_ENVIRONMENT_FORBIDDEN")
    custody = _capture()
    owned = set() if custody is None else custody.checked_fds()
    for name in os.listdir("/proc/self/fd"):
        require(name.isdigit(), "AMBIENT_DESCRIPTOR_FORBIDDEN")
        fd = int(name)
        try:
            info = os.fstat(fd)
        except OSError as exc:
            # listdir's transient descriptor has already been closed.
            if exc.errno == errno.EBADF:
                continue
            raise
        require((fd <= 2 or fd in owned) and not stat.S_ISSOCK(info.st_mode), "AMBIENT_DESCRIPTOR_FORBIDDEN")


def read_owned(path, maximum=4194304, expected_digest=None, expected_mode=None):
    """Retained no-follow ancestry and exact inode/metadata/read-only custody."""
    custody = _capture()
    if custody is not None:
        return custody.read(path, maximum, expected_digest, expected_mode)
    require(type(path) is str and path.startswith("/") and "\\" not in path
            and all(p not in ("", ".", "..") for p in path[1:].split("/")),
            "CUSTODY_PATH_INVALID")
    parent = open_directory(str(Path(path).parent))
    fd = None
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o222
                and before.st_size <= maximum, "CUSTODY_FILE_INVALID")
        require(expected_mode is None or stat.S_IMODE(before.st_mode) == expected_mode, "CUSTODY_MODE_INVALID")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        named, after = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False), os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(after) == identity(named),
                "CUSTODY_FILE_CHANGED")
        raw = bytes(raw)
        require(expected_digest is None or byte_digest(raw) == expected_digest, "CUSTODY_DIGEST_MISMATCH")
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def read_owned_kit(root, expected_digest):
    """Read each signed kit file once, from retained no-follow directory FDs.

    Reject mount crossings, hard links, writable/extraneous files and unbounded
    inventories. Returning bytes is verification data, not an execution grant.
    """
    custody = _capture()
    if custody is not None:
        return custody.read_kit(root, expected_digest)
    root_fd = open_directory(root)
    rows, sources = [], {}
    total, entries = 0, 0
    device = os.fstat(root_fd).st_dev
    def walk(directory, prefix, depth):
        nonlocal total, entries
        require(depth <= 32, "KIT_DEPTH_EXCEEDED")
        before = os.fstat(directory)
        require(before.st_dev == device and before.st_uid == before.st_gid == 0
                and not stat.S_IMODE(before.st_mode) & 0o222, "KIT_MOUNT_OR_CUSTODY_INVALID")
        names = sorted(os.listdir(directory), key=lambda name: name.encode("utf-8"))
        require(len(names) <= 4096, "KIT_INVENTORY_FULL")
        entries += len(names)
        require(entries <= 8192, "KIT_INVENTORY_FULL")
        for name in names:
            require(name not in ("", ".", "..") and "/" not in name and "\\" not in name, "KIT_PATH_INVALID")
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(info.st_uid == info.st_gid == 0 and info.st_dev == device
                    and not stat.S_IMODE(info.st_mode) & 0o222, "KIT_CUSTODY_INVALID")
            relative = prefix + name
            if stat.S_ISDIR(info.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (info.st_dev, info.st_ino), "KIT_CHANGED")
                    walk(fd, relative + "/", depth + 1)
                finally:
                    os.close(fd)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= 4194304,
                        "KIT_FILE_INVALID")
                require(len(rows) < 4096 and total + info.st_size <= 67108864, "KIT_INVENTORY_FULL")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
                try:
                    identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                                          s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                    require(identity(os.fstat(fd)) == identity(info), "KIT_CHANGED")
                    raw = bytearray()
                    while len(raw) <= info.st_size:
                        chunk = os.read(fd, min(65536, info.st_size + 1 - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
                    require(len(raw) == info.st_size and identity(os.fstat(fd)) == identity(info)
                            == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), "KIT_CHANGED")
                finally:
                    os.close(fd)
                sources[relative] = bytes(raw)
                total += len(raw)
                rows.append(dict(mode=f"{stat.S_IMODE(info.st_mode):04o}", path=relative,
                                 sha256=byte_digest(bytes(raw)), size=len(raw)))
        after = os.fstat(directory)
        require((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns), "KIT_CHANGED")
    try:
        walk(root_fd, "", 0)
        rows.sort(key=lambda row: row["path"].encode("utf-8"))
        require(rows and canonical_digest(rows, "planeon.harness-live-tree/v1alpha1") == expected_digest,
                "KIT_DIGEST_MISMATCH")
        return sources
    finally:
        os.close(root_fd)


def seccomp_program(machine):
    """Classic BPF with architecture check, x32 rejection and namespace denial.

    Direct network creation/connect/bind/listen is denied. Only the inherited
    supervisor-owned local channel survives; no raw CRI/network socket grant.
    Ordinary fork/exec remains possible inside the cgroup and PID namespace.
    """
    require(machine in ARCHES, "LINUX_ARCHITECTURE_UNAVAILABLE")
    arch, clone, denied = ARCHES[machine]
    load, equal, bits, ret = 0x20, 0x15, 0x45, 0x06
    kill, allow, refuse = 0x80000000, 0x7FFF0000, 0x00050000 | errno.EPERM
    code = [(load, 0, 0, 4), (equal, 1, 0, arch), (ret, 0, 0, kill), (load, 0, 0, 0)]
    if machine == "x86_64":
        code += [(bits, 0, 1, 0x40000000), (ret, 0, 0, kill)]
    for number in denied:
        # clone3 pointer flags cannot be inspected by classic BPF; ENOSYS
        # permits libc's ordinary clone fallback, still filtered below.
        action = (0x00050000 | errno.ENOSYS) if number == 435 else refuse
        code += [(equal, 0, 1, number), (ret, 0, 0, action)]
    code += [(equal, 0, 3, clone), (load, 0, 0, 16), (bits, 0, 1, NAMESPACE_MASK),
             (ret, 0, 0, refuse), (ret, 0, 0, allow)]
    return tuple(code)


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint), ("pid", ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint), ("permitted", ctypes.c_uint), ("inheritable", ctypes.c_uint)]


class MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_ulonglong), ("attr_clr", ctypes.c_ulonglong),
                ("propagation", ctypes.c_ulonglong), ("userns_fd", ctypes.c_ulonglong)]


class StatFS(ctypes.Structure):
    _fields_ = [("type", ctypes.c_long), ("bsize", ctypes.c_long),
                ("blocks", ctypes.c_ulonglong), ("bfree", ctypes.c_ulonglong), ("bavail", ctypes.c_ulonglong),
                ("files", ctypes.c_ulonglong), ("ffree", ctypes.c_ulonglong), ("fsid", ctypes.c_int * 2),
                ("namelen", ctypes.c_long), ("frsize", ctypes.c_long), ("flags", ctypes.c_long),
                ("spare", ctypes.c_long * 4)]


class LinuxSyscalls:
    def __init__(self):
        installed_process()
        self.machine = os.uname().machine
        require(self.machine in ARCHES, "LINUX_ARCHITECTURE_UNAVAILABLE")
        self.libc = ctypes.CDLL(None, use_errno=True)
        declarations = {"unshare": ([ctypes.c_int], ctypes.c_int),
                        "prctl": ([ctypes.c_int] + [ctypes.c_ulong] * 4, ctypes.c_int),
                        "mount": ([ctypes.c_char_p] * 3 + [ctypes.c_ulong, ctypes.c_void_p], ctypes.c_int),
                        "capset": ([ctypes.POINTER(CapHeader), ctypes.POINTER(CapData)], ctypes.c_int),
                        "fstatfs": ([ctypes.c_int, ctypes.POINTER(StatFS)], ctypes.c_int)}
        for name, (args, result) in declarations.items():
            function = getattr(self.libc, name)
            function.argtypes, function.restype = args, result
        # Fixed-number mount_setattr(442) on both supported 64-bit Linux ABIs.
        self.libc.syscall.restype = ctypes.c_long

    def call(self, name, *args):
        result = getattr(self.libc, name)(*args)
        if result < 0:
            raise OSError(ctypes.get_errno(), "required Linux primitive unavailable")
        return result

    def prctl(self, option, value):
        self.call("prctl", option, value, 0, 0, 0)

    def protect_parent(self, parent_pid):
        self.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
        require(os.getppid() == parent_pid, "SUPERVISOR_PARENT_DIED")

    def namespaces(self):
        self.call("unshare", CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)

    def require_cgroup2(self, fd):
        info = StatFS()
        self.call("fstatfs", fd, ctypes.byref(info))
        require(info.type == 0x63677270, "CGROUP_FILESYSTEM_REQUIRED")

    def readonly_root(self, root_fd):
        self.call("mount", None, b"/", None, MS_REC | MS_PRIVATE, None)
        os.fchdir(root_fd)
        self.call("mount", b".", b".", None, MS_BIND | MS_REC, None)
        attrs = MountAttr(1 | 2 | 4, 0, 0, 0)  # RDONLY, NOSUID, NODEV recursively
        self.call("syscall", ctypes.c_long(442), ctypes.c_int(-100), ctypes.c_char_p(b"."),
                  ctypes.c_uint(0x8000), ctypes.byref(attrs), ctypes.c_size_t(ctypes.sizeof(attrs)))
        os.chroot(".")
        os.chdir("/")

    def drop_privileges(self):
        self.prctl(PR_SET_NO_NEW_PRIVS, 1)
        self.prctl(PR_SET_DUMPABLE, 0)
        for capability in range(64):
            try:
                self.prctl(PR_CAPBSET_DROP, capability)
            except OSError as exc:
                if exc.errno != errno.EINVAL:
                    raise
        header, data = CapHeader(0x20080522, 0), (CapData * 2)()
        self.call("capset", ctypes.byref(header), data)

    def seccomp(self):
        rules = seccomp_program(self.machine)
        filters = (SockFilter * len(rules))(*(SockFilter(*row) for row in rules))
        program = SockFprog(len(rules), filters)
        self.call("prctl", PR_SET_SECCOMP, 2, ctypes.addressof(program), 0, 0)


def process_identity(pid):
    require(type(pid) is int and pid > 1, "PEER_PID_INVALID")
    # proc magic links below are fixed kernel identities, never caller paths.
    prefix = Path("/proc") / str(pid)
    raw = (prefix / "stat").read_text()
    end = raw.rfind(")")
    require(end > 0 and raw[:raw.find(" ")] == str(pid), "PEER_STAT_INVALID")
    fields = raw[end + 2:].split()
    require(len(fields) >= 20, "PEER_STAT_INVALID")
    status = dict(line.split(":", 1) for line in (prefix / "status").read_text().splitlines() if ":" in line)
    cgroup = (prefix / "cgroup").read_text()
    return {"pid": pid, "start": int(fields[19]), "parent": int(fields[1]),
            "uid": tuple(map(int, status["Uid"].split())), "gid": tuple(map(int, status["Gid"].split())),
            "capabilities": tuple(int(status[k].strip(), 16) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
            "seccomp": int(status["Seccomp"]), "noNewPrivs": int(status["NoNewPrivs"]),
            "cgroup": cgroup, "namespaces": {name: (prefix / "ns" / name).stat().st_ino
                for name in ("user", "mnt", "pid", "net")}}


def validate_peer(observed, expected, parent_namespaces):
    require(observed == expected and observed["pid"] > 1 and observed["start"] > 0,
            "PEER_IDENTITY_CHANGED")
    require(observed["uid"] == (CHILD_UID,) * 4 and observed["gid"] == (CHILD_GID,) * 4
            and observed["capabilities"] == (0,) * 5 and observed["seccomp"] == 2
            and observed["noNewPrivs"] == 1, "PEER_PRIVILEGE_INVALID")
    require(observed["cgroup"] == "0::/planeon-live/session\n", "PEER_CGROUP_MISMATCH")
    require(set(observed["namespaces"]) == {"user", "mnt", "pid", "net"}
            and all(observed["namespaces"][k] != parent_namespaces[k] for k in parent_namespaces),
            "PEER_NAMESPACE_MISMATCH")


def credentials(ancillary, flags):
    # Close every received descriptor even when another malformed message is
    # encountered first. Ancillary data never constitutes a capability grant.
    values, unexpected = [], False
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(raw[:len(raw) - len(raw) % fds.itemsize])
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    unexpected = True
            unexpected = True
        elif level == socket.SOL_SOCKET and kind == 2 and len(raw) == 12:  # Linux SCM_CREDENTIALS
            values.append(struct.unpack("3i", raw))
        else:
            unexpected = True
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and not unexpected and len(values) == 1,
            "PEER_CHANNEL_INVALID")
    return values[0]


class CgroupLease:
    """Use one preallocated empty leaf under an exclusive operator-owned lease.

    No cgroup or resource provisioning; never kill by recycled numeric PID.
    """
    def __init__(self):
        native = LinuxSyscalls()
        self.fd = open_directory(CGROUP)
        self.closed = False
        self.owned = False
        try:
            native.require_cgroup2(self.fd)
            require(self.read("cgroup.type") == b"domain\n", "CGROUP_TYPE_INVALID")
            require(self.read("cgroup.events").splitlines().count(b"populated 0") == 1, "CGROUP_NOT_EMPTY")
            for name in ("memory.max", "pids.max"):
                raw = self.read(name).strip()
                require(raw.isdigit() and int(raw) > 0, "CGROUP_LIMIT_REQUIRED")
            cpu = self.read("cpu.max").split()
            require(len(cpu) == 2 and all(v.isdigit() and int(v) > 0 for v in cpu), "CGROUP_LIMIT_REQUIRED")
        except BaseException:
            os.close(self.fd)
            raise

    def read(self, name):
        require(name in ("cgroup.type", "cgroup.events", "memory.max", "pids.max", "cpu.max"), "CGROUP_FIELD_INVALID")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            self._field_custody(fd)
            return os.read(fd, 4096)
        finally:
            os.close(fd)

    def write(self, name, value):
        require(name in ("cgroup.procs", "cgroup.kill") and type(value) is bytes, "CGROUP_FIELD_INVALID")
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            self._field_custody(fd)
            require(os.write(fd, value) == len(value), "CGROUP_WRITE_FAILED")
        finally:
            os.close(fd)

    def _field_custody(self, fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_dev == os.fstat(self.fd).st_dev and not stat.S_IMODE(info.st_mode) & 0o022,
                "CGROUP_FIELD_CUSTODY_INVALID")

    def attach(self, pid):
        require(type(pid) is int and pid > 1 and not self.owned, "CGROUP_ATTACH_INVALID")
        # Custody is held even when the kernel write's result is ambiguous.
        # The child gate is still closed; cleanup kills only this leased leaf.
        self.owned = True
        self.write("cgroup.procs", str(pid).encode())

    def kill_and_reap(self, child_pid, deadline):
        require(self.owned and not self.closed, "CGROUP_NOT_OWNED")
        self.write("cgroup.kill", b"1")
        while time.monotonic() < deadline:
            # This dedicated, single-thread subreaper had no children before
            # its gated fork. Drain direct AND adopted descendants, not just
            # the first child. PID values here are wait identities, not kill.
            no_children = False
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if pid == 0:
                        break
                except ChildProcessError:
                    no_children = True
                    break
            if b"populated 0" in self.read("cgroup.events").splitlines() and no_children:
                self.close()
                return
            time.sleep(0.01)
        raise ConformanceError("DESCENDANTS_NOT_REAPED", "cleanup did not prove an empty process tree")

    def close(self):
        if not self.closed:
            os.close(self.fd)
            self.closed = True


class UnitBoundary:
    """Deterministic dependency-injected ordering model, never native authority."""
    evidence_class = "UNIT_VERIFICATION_ONLY"

    def __init__(self, syscalls):
        self.syscalls = syscalls

    def establish(self):
        for step in ("parent_death", "cgroup_attach", "user_mount_pid_network_namespaces", "uid_gid_maps",
                     "readonly_root", "close_ambient_fds", "drop_capabilities", "no_new_privs", "seccomp", "peer_check"):
            self.syscalls.step(step)
        return {"evidenceClass": self.evidence_class, "nativeAcceptance": False}


def _capture():
    """Process-private registry, never a caller-supplied descriptor allowlist."""
    custody = getattr(_capture, "current", None)
    if custody is not None:
        require(type(custody) is _RetainedCustody, "CUSTODY_OWNER_INVALID")
        custody.owner_check()
    return custody


def _begin_custody(owner):
    from .live_supervisor import NativeSupervisor
    require(type(owner) is NativeSupervisor
            and sys._getframe(1).f_code is NativeSupervisor.__init__.__code__
            and sys._getframe(1).f_locals.get("self") is owner,
            "CUSTODY_FACTORY_REQUIRED")
    require(getattr(_capture, "current", None) is None, "CUSTODY_ALREADY_OWNED")
    custody = _RetainedCustody(owner)
    _capture.current = custody
    return custody


def _owned_custody(owner):
    custody = _capture()
    require(custody is not None and custody.owner is owner, "CUSTODY_OWNER_INVALID")
    return custody


def _custody_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _RetainedCustody:
    """Single close owner for bounded, read-once authority and full ancestry.

    Instances alone grant nothing: the factory registry, current process, fixed
    installed verification and active supervisor must all agree. No raw-FD API.
    """
    def __init__(self, owner):
        import threading
        self.owner, self.pid, self.thread = owner, os.getpid(), threading.get_ident()
        self.handles, self.files = {}, {}
        self.total = 0
        self.manifest_digest = None
        self.kit_root = self.kit_digest = None
        self.kit_sources = {}
        self.closed = self.sealed = False

    def __reduce__(self):
        raise TypeError("retained custody is not serializable")

    def owner_check(self):
        import threading
        from .live_supervisor import NativeSupervisor
        require(not self.closed and type(self.owner) is NativeSupervisor
                and self.pid == os.getpid() and self.thread == threading.get_ident()
                and getattr(_capture, "current", None) is self, "CUSTODY_OWNER_INVALID")

    def path(self, path):
        require(type(path) is str and path.startswith("/") and "\\" not in path
                and len(path.encode("utf-8")) <= 4096
                and all(p not in ("", ".", "..") for p in path[1:].split("/"))
                and len(path[1:].split("/")) <= 64, "CUSTODY_PATH_INVALID")
        return path[1:].split("/")

    def acquire(self, path, parent, name, directory, strict=False):
        self.owner_check()
        require(not self.sealed and path not in self.handles and len(self.handles) < 8448,
                "CUSTODY_DESCRIPTOR_LIMIT")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=parent)
        # Register immediately: even a failing fstat owns a close attempt.
        row = dict(fd=fd, parent=parent, name=name, identity=None)
        self.handles[path] = row
        require(2 < fd < 1048576, "CUSTODY_DESCRIPTOR_RANGE")
        info = os.fstat(fd)
        row["identity"] = _custody_identity(info)
        require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and info.st_uid == info.st_gid == 0
                and (directory or info.st_nlink == 1)
                and not stat.S_IMODE(info.st_mode) & (0o222 if strict or not directory else 0o022),
                "CUSTODY_FILE_INVALID")
        self.check_row(row)
        return fd

    def directory(self, path, strict=False):
        self.owner_check()
        parts = self.path(path)
        if "/" not in self.handles:
            self.acquire("/", None, "/", True)
        parent, current = self.handles["/"]["fd"], ""
        for part in parts:
            current += "/" + part
            if current not in self.handles:
                self.acquire(current, parent, part, True, strict and current == path)
            row = self.handles[current]
            self.check_row(row)
            require(stat.S_ISDIR(row["identity"][4]), "CUSTODY_DIRECTORY_REQUIRED")
            parent = row["fd"]
        if strict:
            require(not stat.S_IMODE(self.handles[path]["identity"][4]) & 0o222, "KIT_CUSTODY_INVALID")
        return parent

    def check_row(self, row):
        expected = row["identity"]
        require(expected is not None
                and _custody_identity(os.fstat(row["fd"])) == expected
                and _custody_identity(os.stat(row["name"], dir_fd=row["parent"], follow_symlinks=False)) == expected,
                "CUSTODY_FILE_CHANGED")

    def check(self):
        self.owner_check()
        for row in self.handles.values():
            self.check_row(row)

    def checked_fds(self):
        self.check()
        return {row["fd"] for row in self.handles.values()}

    def read(self, path, maximum, expected_digest, expected_mode):
        try:
            self.check()
            self.path(path)
            require(type(maximum) is int and 0 < maximum <= 4194304, "CUSTODY_READ_LIMIT")
            if path not in self.files:
                require(not self.sealed and len(self.files) < 4112, "CUSTODY_FILE_LIMIT")
                parent_path = path.rsplit("/", 1)[0]
                if not parent_path:
                    if "/" not in self.handles:
                        self.acquire("/", None, "/", True)
                    parent = self.handles["/"]["fd"]
                else:
                    parent = self.directory(parent_path)
                fd = self.acquire(path, parent, path.rsplit("/", 1)[1], False)
                size = self.handles[path]["identity"][6]
                require(0 <= size <= maximum and self.total + size <= 100663296, "CUSTODY_READ_LIMIT")
                data = bytearray()
                while len(data) <= size:
                    chunk = os.read(fd, min(65536, size + 1 - len(data)))
                    self.check()
                    if not chunk:
                        break
                    data.extend(chunk)
                require(len(data) == size, "CUSTODY_FILE_CHANGED")
                self.files[path] = bytes(data)
                self.total += size
            raw = self.files[path]
            require(len(raw) <= maximum, "CUSTODY_READ_LIMIT")
            require(expected_mode is None or stat.S_IMODE(self.handles[path]["identity"][4]) == expected_mode,
                    "CUSTODY_MODE_INVALID")
            require(expected_digest is None or byte_digest(raw) == expected_digest, "CUSTODY_DIGEST_MISMATCH")
            return raw
        except BaseException:
            self.close()
            raise

    def read_kit(self, root, expected_digest):
        try:
            self.check()
            require(not self.sealed and self.kit_root is None, "KIT_ALREADY_READ")
            root_fd = self.directory(root, strict=True)
            device = self.handles[root]["identity"][0]
            rows, sources = [], {}
            entries = total = 0
            def walk(path, prefix, depth):
                nonlocal entries, total
                require(depth <= 32, "KIT_DEPTH_EXCEEDED")
                fd = self.directory(path, strict=True)
                require(self.handles[path]["identity"][0] == device, "KIT_MOUNT_OR_CUSTODY_INVALID")
                names = sorted(os.listdir(fd), key=lambda name: name.encode("utf-8"))
                self.check()
                require(len(names) <= 4096, "KIT_INVENTORY_FULL")
                entries += len(names)
                require(entries <= 8192, "KIT_INVENTORY_FULL")
                for name in names:
                    require(type(name) is str and name not in ("", ".", "..")
                            and "/" not in name and "\\" not in name, "KIT_PATH_INVALID")
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(info.st_dev == device and info.st_uid == info.st_gid == 0
                            and not stat.S_IMODE(info.st_mode) & 0o222, "KIT_CUSTODY_INVALID")
                    child, relative = path + "/" + name, prefix + name
                    if stat.S_ISDIR(info.st_mode):
                        walk(child, relative + "/", depth + 1)
                    else:
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                                and 0 <= info.st_size <= 4194304, "KIT_FILE_INVALID")
                        require(len(rows) < 4096 and total + info.st_size <= 67108864, "KIT_INVENTORY_FULL")
                        raw = self.read(child, 4194304, None, None)
                        require(self.handles[child]["identity"] == _custody_identity(info), "KIT_CHANGED")
                        sources[relative] = raw
                        total += len(raw)
                        rows.append(dict(mode=f"{stat.S_IMODE(info.st_mode):04o}", path=relative,
                                         sha256=byte_digest(raw), size=len(raw)))
                self.check()
            walk(root, "", 0)
            rows.sort(key=lambda row: row["path"].encode("utf-8"))
            require(canonical_digest(rows, "planeon.harness-live-tree/v1alpha1") == expected_digest,
                    "KIT_DIGEST_MISMATCH")
            require(root + "/rootfs" in self.handles
                    and stat.S_ISDIR(self.handles[root + "/rootfs"]["identity"][4]), "KIT_ROOTFS_REQUIRED")
            self.kit_root, self.kit_digest, self.kit_sources = root, expected_digest, sources
            return dict(sources)
        except BaseException:
            self.close()
            raise

    def require_bytes(self, expected):
        self.check()
        require(all(type(raw) is bytes and self.files.get(path) == raw for path, raw in expected.items()),
                "CUSTODY_INCOMPLETE")

    def seal(self, expected, kit_root, kit_digest, kit_sources):
        self.require_bytes(expected)
        require(self.manifest_digest is not None and not self.sealed
                and self.kit_root == kit_root and self.kit_digest == kit_digest
                and self.kit_sources == kit_sources and bool(self.kit_sources), "CUSTODY_INCOMPLETE")
        from types import MappingProxyType
        self.files = MappingProxyType(dict(self.files))
        self.kit_sources = MappingProxyType(dict(self.kit_sources))
        self.sealed = True
        return self.handles[kit_root + "/rootfs"]["fd"]

    def close(self):
        if self.closed:
            return
        self.closed = True
        # Invalidate before any close. Never retry a descriptor number that the
        # OS may have released even when close reports an error.
        if getattr(_capture, "current", None) is self:
            _capture.current = None
        rows, self.handles = self.handles, {}
        self.files, self.kit_sources = {}, {}
        failure = None
        for row in reversed(tuple(rows.values())):
            try:
                expected = row["identity"]
                if expected is not None:
                    info = os.fstat(row["fd"])
                    require((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                            == (expected[0], expected[1], stat.S_IFMT(expected[4])), "CUSTODY_DESCRIPTOR_REUSED")
                os.close(row["fd"])
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure
