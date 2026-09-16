"""Independent, fixed installed proxy owner; never a campaign-selected service.

The policy producer, enforced capacity broker and native fixed probes must be
independently installed/qualified. Missing prerequisites refuse startup/effects.
This source packet does not install them or qualify a native architecture.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import fcntl
import importlib
import ipaddress
import mmap
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import sys
import threading
import time

from .canonical import byte_digest, canonical_bytes, canonical_digest, require_canonical_document
from .crypto import b64url_decode, verify
from .errors import ConformanceError
from .linux_readiness import CASES, build_probe_request, require_time
from .live import FIXED_RELEASE_TRUST, FIXED_TENANT_TRUST, PINNED_ROOT_PUBLIC_KEY_SHA256
from .live_backend_authority import verify_backend_authority, binding_from_authority
from .live_linux_boundary import credentials, process_identity, _custody_identity
from .live_mutation_admission import (require, document, retained_profile, validate_messages,
    _time, ZERO, admission_binding, _AdmissionLog, parse_reservations, cleanup_receipt,
    retained_qualification_record, retained_broker_binding, QUALIFICATION_PATH,
    BrokerTranscript, broker_document, _create_record, validate_observed_manifest,
    validate_absent_status, _absence_record, delete_request_body, validate_delete_response,
    _completion_frame, _completion_terminal, _failure_cleanup)
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
BROKER = "/opt/planeon/bin/harness-capacity-broker"
BROKER_MANIFEST = "/etc/planeon/harness-capacity-broker-manifest.json"
BROKER_SOCKET = "/run/planeon/live-proxy/capacity-broker.sock"
WORKER = "/opt/planeon/bin/harness-live-probe-exec"
WORKER_MANIFEST = "/etc/planeon/harness-live-probe-manifest.json"
_ACTIVE = None


def _selinux_status_fields(raw):
    """Decode an already fenced status-page slice, not an enforcing-policy grant."""
    require(type(raw) is bytes and len(raw) == 20, "KERNEL_STATUS_LAYOUT")
    version, sequence, enforcing, policyload, deny_unknown = struct.unpack("<5I", raw)
    require(version == 1 and sequence % 2 == 0 and enforcing == deny_unknown == 1
            and policyload > 0, "KERNEL_STATUS_INVALID")
    return dict(version=version, sequence=sequence, enforcing=enforcing,
                policyload=policyload, denyUnknown=deny_unknown)


def _verity_measurement(raw):
    """Decode FS_IOC_MEASURE_VERITY output; never substitute a content digest."""
    require(type(raw) is bytes and len(raw) == 36, "KERNEL_VERITY_LAYOUT")
    algorithm, size = struct.unpack_from("<HH", raw)
    require(algorithm == 1 and size == 32, "KERNEL_VERITY_ALGORITHM")
    return "sha256:" + raw[4:].hex()


def _native_auxv(raw):
    """Bounded native ELF64 auxiliary-vector data. No proc path or I/O here."""
    require(type(raw) is bytes and 16 <= len(raw) <= 65536 and len(raw) % 16 == 0,
            "KERNEL_AUXV_LAYOUT")
    result = {}
    for offset in range(0, len(raw), 16):
        key, value = struct.unpack_from("<QQ", raw, offset)
        if key == 0:
            require(value == 0 and offset + 16 == len(raw), "KERNEL_AUXV_TERMINATOR")
            break
        require(key not in result, "KERNEL_AUXV_DUPLICATE")
        result[key] = value
    else:
        require(False, "KERNEL_AUXV_TERMINATOR")
    require(result.get(6) in (4096, 16384, 65536) and result.get(33, 0) > 0
            and result[33] % result[6] == 0, "KERNEL_AUXV_REQUIRED")
    return result


def _elf_code_layout(raw, machine, page_size):
    """Decode complete ELF64 LE PT_LOADs without loading or executing the file.

    Native custody, verity, policy and maps must be checked separately. Returned
    addresses are link-time offsets, not proof of a running process's identity.
    """
    require(type(raw) is bytes and 64 <= len(raw) <= 67108864, "KERNEL_ELF_SIZE")
    require(type(machine) is str and machine in ("x86_64", "aarch64")
            and type(page_size) is int and page_size in (4096, 16384, 65536), "KERNEL_ELF_ABI")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    ident, kind, architecture, version, _, phoff, _, flags, ehsize, phsize, count, _, _, _ = header
    require(ident[:7] == b"\x7fELF\x02\x01\x01" and ident[7] in (0, 3)
            and ident[8:] == b"\0" * 8 and kind in (2, 3) and version == 1 and flags == 0
            and architecture == {"x86_64": 62, "aarch64": 183}[machine]
            and ehsize == 64 and phsize == 56 and 1 <= count <= 128
            and phoff >= 64 and phoff % 8 == 0 and phoff + count * phsize <= len(raw), "KERNEL_ELF_LAYOUT")
    segments, interpreter, last_load_end = [], None, 0
    for index in range(count):
        tag, perms, offset, address, _, size, memory, alignment = struct.unpack_from("<IIQQQQQQ", raw, phoff + index * 56)
        require(offset + size <= len(raw) and address + memory <= 2 ** 64, "KERNEL_ELF_BOUNDS")
        if tag == 0x6474e551:
            require(not perms & 1, "KERNEL_ELF_EXECUTABLE_STACK")
        if tag == 3:
            require(interpreter is None and 2 <= size <= 4096, "KERNEL_ELF_INTERPRETER")
            data = raw[offset:offset + size]
            require(data.endswith(b"\0") and b"\0" not in data[:-1], "KERNEL_ELF_INTERPRETER")
            require(re.fullmatch(rb"/[A-Za-z0-9_./+-]+", data[:-1]) is not None, "KERNEL_ELF_INTERPRETER")
            interpreter = data[:-1].decode("ascii")
            require(all(part not in ("", ".", "..") for part in interpreter[1:].split("/")), "KERNEL_ELF_INTERPRETER")
        if tag != 1:
            continue
        require(perms <= 7 and size <= memory and memory > 0 and address >= last_load_end
                and (alignment in (0, 1) or alignment & (alignment - 1) == 0)
                and (alignment <= 1 or address % alignment == offset % alignment)
                and address % page_size == offset % page_size, "KERNEL_ELF_LOAD_LAYOUT")
        last_load_end = address + memory
        if not perms & 1:
            continue
        require(not perms & 2 and size > 0 and len(segments) < 16, "KERNEL_ELF_EXECUTABLE_LOAD")
        start = offset - offset % page_size
        file_end = ((offset + size + page_size - 1) // page_size) * page_size
        memory_end = ((offset + memory + page_size - 1) // page_size) * page_size
        require(memory_end == file_end and file_end - start <= 67108864, "KERNEL_ELF_ANONYMOUS_CODE")
        segments.append(dict(offset=start, length=file_end - start,
                             permissions=("r" if perms & 4 else "-") + "-xp",
                             virtualAddress=address - address % page_size))
    require(bool(segments), "KERNEL_ELF_CODE_MISSING")
    identities = [(s["offset"], s["length"]) for s in segments]
    require(len(identities) == len(set(identities)), "KERNEL_ELF_DUPLICATE_CODE")
    return dict(kind=kind, interpreter=interpreter, segments=segments)


def _proc_code_maps(raw, machine, auxv):
    """Parse a complete maps read; special kernel names alone prove nothing.

    The native inspector must obtain auxv and maps itself, retain the process,
    match every returned file against enrolled ELF/descriptor identities, and
    compare fresh reads under the same kernel-policy epoch. This is data only.
    """
    require(type(raw) is bytes and 0 < len(raw) <= 1048576 and raw.endswith(b"\n")
            and b"\0" not in raw and b"\r" not in raw, "KERNEL_MAPS_SIZE")
    require(type(machine) is str and machine in ("x86_64", "aarch64"), "KERNEL_MAPS_ABI")
    auxiliary = _native_auxv(auxv)
    page_size, vdso_address = auxiliary[6], auxiliary[33]
    maps, special, previous_end = [], {}, 0
    lines = raw.splitlines()
    require(0 < len(lines) <= 16384, "KERNEL_MAPS_COUNT")
    pattern = rb"([0-9a-f]{1,16})-([0-9a-f]{1,16}) ([r-][w-][x-][ps]) ([0-9a-f]{1,16}) ([0-9a-f]{2,8}):([0-9a-f]{2,8}) +([0-9]{1,20})(?: +([^\n]*))?"
    for line in lines:
        require(len(line) <= 8192, "KERNEL_MAPS_LINE_SIZE")
        match = re.fullmatch(pattern, line)
        require(match is not None, "KERNEL_MAPS_LAYOUT")
        begin, end, perms, offset, major, minor, inode, path = match.groups()
        begin, end, offset = int(begin, 16), int(end, 16), int(offset, 16)
        major, minor, inode = int(major, 16), int(minor, 16), int(inode)
        require(previous_end <= begin < end and begin % page_size == end % page_size == offset % page_size == 0
                and inode < 2 ** 64 and not (b"w" in perms and b"x" in perms), "KERNEL_MAPS_RANGE")
        previous_end = end
        if b"x" not in perms:
            continue
        require(len(maps) + len(special) < 256 and path is not None, "KERNEL_MAPS_ANONYMOUS_CODE")
        if path in (b"[vdso]", b"[vsyscall]"):
            name = path.decode("ascii")
            require(name not in special and (offset, major, minor, inode) == (0, 0, 0, 0), "KERNEL_MAPS_SPECIAL")
            if name == "[vdso]":
                require(begin == vdso_address and perms == b"r-xp" and end - begin <= 1048576, "KERNEL_MAPS_VDSO")
            else:
                require(machine == "x86_64" and begin == 0xffffffffff600000 and end - begin == 4096
                        and perms == b"--xp", "KERNEL_MAPS_VSYSCALL")
            special[name] = dict(start=begin, end=end, permissions=perms.decode("ascii"))
            continue
        require(re.fullmatch(rb"/[A-Za-z0-9_./+-]+", path) is not None and inode > 0, "KERNEL_MAPS_FILE_PATH")
        path = path.decode("ascii")
        require(all(part not in ("", ".", "..") for part in path[1:].split("/")), "KERNEL_MAPS_FILE_PATH")
        maps.append(dict(path=path, start=begin, end=end, permissions=perms.decode("ascii"),
                         offset=offset, deviceMajor=major, deviceMinor=minor, inode=inode))
    require(bool(maps) and "[vdso]" in special, "KERNEL_MAPS_CODE_MISSING")
    return dict(files=maps, kernel=special, pageSize=page_size)


def _proc_process_fields(raw, status):
    """Bounded Linux 6.12 proc data, never a process/namespace authority grant."""
    require(type(raw) is bytes and 0 < len(raw) <= 8192 and raw.endswith(b"\n")
            and b"\0" not in raw, "KERNEL_PROCESS_STAT_LAYOUT")
    prefix, separator, rest = raw.partition(b" (")
    end = rest.rfind(b") ")
    require(separator and re.fullmatch(rb"[1-9][0-9]{0,9}", prefix) is not None
            and 0 < end <= 256, "KERNEL_PROCESS_STAT_LAYOUT")
    fields = rest[end + 2:-1].split(b" ")
    require(len(fields) == 50 and fields[0] in (b"R", b"S", b"D", b"T", b"t", b"I")
            and all(re.fullmatch(rb"-?(?:0|[1-9][0-9]{0,19})", v) for v in fields[1:]),
            "KERNEL_PROCESS_STAT_LAYOUT")
    numbers = [int(v) for v in fields[1:]]
    require(all(-(2 ** 63) <= v < 2 ** 64 for v in numbers), "KERNEL_PROCESS_STAT_RANGE")
    pid, parent, threads, start = int(prefix), numbers[0], numbers[16], numbers[18]
    require(1 < pid < 2 ** 31 and 0 < parent < 2 ** 31 and 1 <= threads <= 4096
            and 0 < start <= 9007199254740991, "KERNEL_PROCESS_STAT_RANGE")
    require(type(status) is bytes and 0 < len(status) <= 65536 and status.endswith(b"\n")
            and b"\0" not in status and len(status.splitlines()) <= 512, "KERNEL_PROCESS_STATUS_LAYOUT")
    rows = {}
    for line in status.splitlines():
        key, colon, value = line.partition(b":")
        require(colon and re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]{0,63}", key)
                and key not in rows, "KERNEL_PROCESS_STATUS_LAYOUT")
        rows[key] = value.split()
    def integers(key, minimum, maximum, count):
        values = rows.get(key, [])
        require(len(values) == count and all(re.fullmatch(rb"(?:0|[1-9][0-9]{0,15})", v) for v in values),
                "KERNEL_PROCESS_STATUS_FIELD")
        values = tuple(int(v) for v in values)
        require(all(minimum <= v <= maximum for v in values), "KERNEL_PROCESS_STATUS_RANGE")
        return values
    require(integers(b"Pid", 2, 2147483647, 1) == integers(b"Tgid", 2, 2147483647, 1) == (pid,)
            and integers(b"PPid", 1, 2147483647, 1) == (parent,)
            and integers(b"Threads", 1, 4096, 1) == (threads,)
            and integers(b"TracerPid", 0, 0, 1) == (0,), "KERNEL_PROCESS_STATUS_MISMATCH")
    chain_size = len(rows.get(b"NSpid", []))
    require(1 <= chain_size <= 32, "KERNEL_PROCESS_PID_NAMESPACE")
    chain = integers(b"NSpid", 1, 2147483647, chain_size)
    require(chain[0] == pid and integers(b"NStgid", 1, 2147483647, chain_size) == chain,
            "KERNEL_PROCESS_PID_NAMESPACE")
    groups = integers(b"Groups", 0, 2147483647, len(rows.get(b"Groups", [])))
    require(b"Groups" in rows and len(groups) <= 256 and len(set(groups)) == len(groups),
            "KERNEL_PROCESS_GROUPS")
    capabilities = []
    for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        values = rows.get(key, [])
        require(len(values) == 1 and re.fullmatch(rb"[0-9a-f]{16}", values[0]), "KERNEL_PROCESS_CAPABILITIES")
        capabilities.append(int(values[0], 16))
    return dict(pid=pid, parent=parent, startTicks=start, threads=threads,
                uid=integers(b"Uid", 0, 2147483647, 4), gid=integers(b"Gid", 0, 2147483647, 4),
                namespacePids=chain, groups=groups, capabilities=tuple(capabilities),
                seccompMode=integers(b"Seccomp", 2, 2, 1)[0],
                noNewPrivs=integers(b"NoNewPrivs", 0, 1, 1)[0])


class _KernelStatfs(ctypes.Structure):
    """Linux 6.12 native LP64 layout on the two explicitly supported ABIs."""
    _fields_ = [(name, ctypes.c_long) for name in
                ("kind", "block_size", "blocks", "free_blocks", "available_blocks", "files", "free_files")]
    _fields_ += [("fsid", ctypes.c_int * 2)]
    _fields_ += [(name, ctypes.c_long) for name in ("name_length", "fragment_size", "flags")]
    _fields_ += [("spare", ctypes.c_long * 4)]


class _KernelStatx(ctypes.Structure):
    """An aligned, zero-initialized Linux 6.12 statx result, decoded by offset."""
    _fields_ = [("words", ctypes.c_uint64 * 32)]


def _kernel_mount_pins(views, count):
    # Private native data, not JSON/wire values: retain exact uint64 mount IDs.
    require(type(count) is int and count in (3, 7) and type(views) is list
            and len(views) == count, "KERNEL_EPOCH_MOUNT_LAYOUT")
    pins = []
    for view in views:
        require(type(view) is dict and set(view) == {"identity", "mountId", "filesystem"},
                "KERNEL_EPOCH_MOUNT_LAYOUT")
        identity, fs = view["identity"], view["filesystem"]
        require(type(identity) is tuple and len(identity) == 5
                and all(type(v) is int for v in identity)
                and type(view["mountId"]) is int and 0 < view["mountId"] < 2 ** 64
                and type(fs) is dict and set(fs) == {"kind", "fsid", "blockSize", "flags"}
                and type(fs["fsid"]) is list and len(fs["fsid"]) == 2
                and all(type(v) is int for v in (*fs["fsid"], fs["kind"], fs["blockSize"], fs["flags"])),
                "KERNEL_EPOCH_MOUNT_LAYOUT")
        pins.append((identity, view["mountId"], fs["kind"], tuple(fs["fsid"]), fs["blockSize"], fs["flags"]))
    return tuple(pins)


def _kernel_inspection_tick(reader):
    """Carry the installed owner's custody/lifetime into component I/O ticks.

    Standalone readers are observations only, never qualification. Once a
    server exists they must be retained by its exact inspection owner. No
    callback, caller context or transferable descriptor selects this guard.
    Epoch sampling and external change exclusion remain separate obligations.
    """
    owner = getattr(reader, "_inspection_owner", None)
    if owner is None:
        require(_ACTIVE is None, "KERNEL_INSPECTION_READER_UNBOUND")
        return
    require(type(owner) in (_KernelSelfInspection, _KernelObserverInspection, _KernelBrokerInspection),
            "KERNEL_INSPECTION_READER_OWNER")
    owner._reader_tick(reader)


class _KernelNativeReads:
    """Fixed read primitives, not a qualification factory or authority handle.

    Only an eventual installed inspector may interpret these observations after
    retaining canonical ancestry, mount/namespace identity and signed custody.
    A caller's fd, a matching filesystem magic or a valid epoch grants nothing.
    No library discovery, command runner, injected adapter or privilege repair.
    """
    def __init__(self):
        require(sys.platform == "linux" and sys.byteorder == "little"
                and ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_long) == 8
                and ctypes.sizeof(_KernelStatfs) == 120 and _KernelStatfs.fsid.offset == 56
                and _KernelStatfs.flags.offset == 80, "KERNEL_NATIVE_ABI_UNAVAILABLE")
        self.machine = os.uname().machine
        require(self.machine in ("x86_64", "aarch64"), "KERNEL_NATIVE_ABI_UNAVAILABLE")
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.closed = self.failed = self.busy = self.registered = False
        _kernel_inspection_tick(self)
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.lib.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_KernelStatfs))
        self.lib.fstatfs.restype = ctypes.c_int
        # syscall is variadic: every fixed argument below is explicitly typed.
        self.lib.syscall.restype = ctypes.c_long
        self.number = {"x86_64": 324, "aarch64": 283}[self.machine]

    def _tick(self):
        require(type(self) is _KernelNativeReads and not self.closed and not self.failed
                and self.busy and self.pid == os.getpid() and self.thread == threading.get_ident(),
                "KERNEL_READER_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_INSPECTION_DEADLINE")
        self.last = now

    @contextmanager
    def _phase(self):
        require(not self.busy and not self.closed and not self.failed, "KERNEL_READER_UNAVAILABLE")
        self.busy = True
        self.last = time.monotonic()
        self.end = self.last + 2
        try:
            self._tick()
            yield
            self._tick()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _descriptor(self, fd):
        self._tick()
        require(type(fd) is int and 2 < fd < 1048576, "KERNEL_DESCRIPTOR_INVALID")
        try:
            info = os.fstat(fd)
        finally:
            self._tick()
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        finally:
            self._tick()
        try:
            inherited = os.get_inheritable(fd)
        finally:
            self._tick()
        # O_PATH is deliberately excluded: inspection uses retained readable fds.
        require(not inherited and flags & os.O_ACCMODE == os.O_RDONLY and not flags & 0o10000000,
                "KERNEL_DESCRIPTOR_ACCESS")
        return info, _custody_identity(info)

    def _same(self, fd, identity):
        _, current = self._descriptor(fd)
        require(current == identity, "KERNEL_DESCRIPTOR_CHANGED")

    def _filesystem(self, fd):
        self._tick()
        value = _KernelStatfs()  # including reserved tail, initially all zero
        try:
            result = self.lib.fstatfs(ctypes.c_int(fd), ctypes.byref(value))
        finally:
            self._tick()
        require(result == 0, "KERNEL_FILESYSTEM_UNAVAILABLE")
        require(not any(value.spare) and 512 <= value.block_size <= 65536
                and value.block_size & (value.block_size - 1) == 0
                and 0 < value.name_length <= 4096, "KERNEL_FILESYSTEM_LAYOUT")
        # Dynamic allocation counters are not stable filesystem identity.
        return dict(kind=value.kind & (2 ** 64 - 1), fsid=list(value.fsid),
                    blockSize=value.block_size, flags=value.flags)

    def filesystem(self, fd):
        with self._phase():
            _, identity = self._descriptor(fd)
            value = self._filesystem(fd)
            self._same(fd, identity)
            return value

    def directory_identity(self, fd):
        """Observe a readable directory and its non-recycled mount ID, not trust.

        procfs directory counters/timestamps can change with process churn. Only
        stable inode/owner/mode, filesystem identity and mount ID are returned.
        A later fixed owner must validate namespace and canonical ancestry.
        """
        return self._inode_identity(fd, True)

    def proc_file_identity(self, fd):
        """Stable regular-file and mount identity; proc size/times are dynamic."""
        return self._inode_identity(fd, False)

    def _inode_identity(self, fd, directory):
        with self._phase():
            info, _ = self._descriptor(fd)
            require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
                    "KERNEL_DIRECTORY_REQUIRED" if directory else "KERNEL_PROC_FILE_REQUIRED")
            identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
            (major, minor, inode, uid, gid, mode), mount_id = self._statx_identity(fd, b"")
            require((uid, gid, mode, inode, major, minor) ==
                    (info.st_uid, info.st_gid, info.st_mode, info.st_ino,
                     os.major(info.st_dev), os.minor(info.st_dev)), "KERNEL_STATX_IDENTITY")
            filesystem = self._filesystem(fd)
            after, _ = self._descriptor(fd)
            require((after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode) == identity,
                    "KERNEL_DIRECTORY_CHANGED")
            return dict(identity=identity, mountId=mount_id, filesystem=filesystem)

    def _statx_identity(self, fd, path):
        # Retained descriptors, the fixed root and fixed single-component names.
        # No symlink following, automount, recycled mount-ID or stat fallback.
        self._tick()
        require(type(fd) is int and 2 < fd < 1048576 and type(path) is bytes
                and path in (b"", b"/", b"proc", b"sys", b"kernel", b"fs", b"cgroup", b"status", b"selinux"),
                "KERNEL_STATX_FIXED_PATH")
        require(ctypes.sizeof(_KernelStatx) == 256 and ctypes.alignment(_KernelStatx) == 8,
                "KERNEL_STATX_ABI")
        call = self.lib.statx
        call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_uint, ctypes.POINTER(_KernelStatx))
        call.restype = ctypes.c_int
        output = _KernelStatx()
        required = 0x411b  # TYPE | MODE | UID | GID | INO | MNT_ID_UNIQUE
        try:
            result = call(fd, path, 0x900 if path else 0x1900, required, ctypes.byref(output))
        finally:
            self._tick()
        require(type(result) is int and result == 0, "KERNEL_MOUNT_ID_UNAVAILABLE")
        raw = bytes(output)
        mask = struct.unpack_from("<I", raw)[0]
        uid, gid, mode, reserved = struct.unpack_from("<IIHH", raw, 20)
        inode = struct.unpack_from("<Q", raw, 32)[0]
        major, minor = struct.unpack_from("<II", raw, 136)
        mount_id = struct.unpack_from("<Q", raw, 144)[0]
        require(mask & required == required and not mask & ~0x1ffff
                and reserved == 0 and raw[180:] == b"\0" * 76 and mount_id > 0
                and all(raw[offset:offset + 4] == b"\0" * 4 for offset in (76, 92, 108, 124)),
                "KERNEL_STATX_LAYOUT")
        return (major, minor, inode, uid, gid, mode), mount_id

    def _status_mounts(self, fd, parent, ancestry):
        # Called inside the original native phase, also during nested epochs.
        # Return observations only; the policy owner compares its frozen pins.
        views = self._mount_views((fd, parent, ancestry))
        for descriptor, name, expected in ((parent, b"status", views[0]), (ancestry, b"selinux", views[1])):
            inode, mount_id = self._statx_identity(descriptor, name)
            dev, ino, uid, gid, mode = expected["identity"]
            require(inode == (os.major(dev), os.minor(dev), ino, uid, gid, mode)
                    and mount_id == expected["mountId"], "KERNEL_EPOCH_MOUNT_PATH_CHANGED")
        return views

    def _mount_views(self, descriptors):
        require(type(descriptors) is tuple and len(descriptors) in (3, 7), "KERNEL_MOUNT_DESCRIPTOR_LAYOUT")
        views = []
        for descriptor in descriptors:
            info, _ = self._descriptor(descriptor)
            inode, mount_id = self._statx_identity(descriptor, b"")
            require(inode == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino,
                              info.st_uid, info.st_gid, info.st_mode), "KERNEL_STATX_IDENTITY")
            filesystem = self._filesystem(descriptor)
            after, _ = self._descriptor(descriptor)
            require((after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode) ==
                    (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode), "KERNEL_DIRECTORY_CHANGED")
            views.append(dict(identity=(info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode),
                              mountId=mount_id, filesystem=filesystem))
        return views

    def _root_mounts(self, descriptors):
        # Fixed topology, never a supplied path map. The absolute root lookup
        # binds the current namespace view, not just the retained original FD.
        require(type(descriptors) is tuple and len(descriptors) == 7
                and all(type(fd) is int for fd in descriptors)
                and len(set(descriptors)) == 7, "KERNEL_ROOT_MOUNT_DESCRIPTORS")
        views = self._mount_views(descriptors)
        layout = ((b"/", 0), (b"proc", 0), (b"sys", 0), (b"kernel", 2),
                  (b"fs", 2), (b"selinux", 4), (b"cgroup", 4))
        for expected, (name, parent) in zip(views, layout):
            inode, mount_id = self._statx_identity(descriptors[parent], name)
            dev, ino, uid, gid, mode = expected["identity"]
            require(inode == (os.major(dev), os.minor(dev), ino, uid, gid, mode)
                    and mount_id == expected["mountId"], "KERNEL_ROOT_MOUNT_PATH_CHANGED")
        return views

    def namespace_identity(self, fd):
        """Inspect only an already-open nsfs fd; no namespace entry or mutation."""
        with self._phase():
            info, identity = self._descriptor(fd)
            require(stat.S_ISREG(info.st_mode), "KERNEL_NAMESPACE_DESCRIPTOR")
            filesystem = self._filesystem(fd)
            require(filesystem["kind"] == 0x6e736673, "KERNEL_NAMESPACE_FILESYSTEM")
            try:
                kind = fcntl.ioctl(fd, 0xb703, 0)  # NS_GET_NSTYPE, read only
            finally:
                self._tick()
            require(type(kind) is int and kind in (0x10000000, 0x20000, 0x20000000, 0x40000000),
                    "KERNEL_NAMESPACE_TYPE")
            require(self._filesystem(fd) == filesystem, "KERNEL_NAMESPACE_CHANGED")
            self._same(fd, identity)
            return dict(identity=identity, filesystem=filesystem, kind=kind)

    def measure_verity(self, fd):
        with self._phase():
            info, identity = self._descriptor(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o222
                    and 0 < info.st_size <= 67108864, "KERNEL_CODE_FILE_CUSTODY")
            output = bytearray(struct.pack("<HH", 0, 32) + b"\0" * 32)
            try:
                result = fcntl.ioctl(fd, 0xc0046686, output, True)
            finally:
                self._tick()
            require(type(result) is int and result == 0, "KERNEL_VERITY_UNAVAILABLE")
            digest = _verity_measurement(bytes(output))
            self._same(fd, identity)
            return digest

    def _barrier(self, command):
        self._tick()
        require(type(command) is int and command in (0, 16, 8), "KERNEL_BARRIER_COMMAND")
        try:
            result = self.lib.syscall(ctypes.c_long(self.number), ctypes.c_int(command),
                                      ctypes.c_int(0), ctypes.c_int(0))
        finally:
            self._tick()
        require(type(result) is int and result >= 0, "KERNEL_BARRIER_UNAVAILABLE")
        return result

    def _fence(self):
        if not self.registered:
            require(self._barrier(0) & 24 == 24, "KERNEL_PRIVATE_BARRIER_UNAVAILABLE")
            require(self._barrier(16) == 0, "KERNEL_PRIVATE_BARRIER_REGISTRATION")
            self.registered = True
        require(self._barrier(8) == 0, "KERNEL_PRIVATE_BARRIER_FAILED")

    def status_epoch(self, fd):
        """One fenced kernel status observation; a policy digest is still required.

        The inspector must retain this exact epoch across fresh policy opens and
        all I/O. This method neither validates a policy nor authorizes a peer.
        """
        with self._phase():
            info, identity = self._descriptor(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o222, "KERNEL_STATUS_CUSTODY")
            filesystem = self._filesystem(fd)
            require(filesystem["kind"] == 0xf97cff8c, "KERNEL_STATUS_FILESYSTEM")
            mapping = None
            try:
                page_size = os.sysconf("SC_PAGESIZE")
                self._tick()
                require(type(page_size) is int and page_size in (4096, 16384, 65536),
                        "KERNEL_STATUS_PAGE_SIZE")
                mapping = mmap.mmap(fd, page_size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
                self._tick()
                sequence = bytes(mapping[4:8])
                require(len(sequence) == 4 and struct.unpack("<I", sequence)[0] % 2 == 0,
                        "KERNEL_STATUS_UNSTABLE")
                self._fence()
                fields = _selinux_status_fields(bytes(mapping[:20]))
                self._fence()
                require(bytes(mapping[4:8]) == sequence
                        and fields["sequence"] == struct.unpack("<I", sequence)[0],
                        "KERNEL_STATUS_UNSTABLE")
                self._same(fd, identity)
                require(self._filesystem(fd) == filesystem, "KERNEL_STATUS_FILESYSTEM_CHANGED")
                return fields
            finally:
                if mapping is not None:
                    # This mapping owns its internal duplicate; the input fd
                    # remains exclusively owned by the installed inspector.
                    mapping.close()
                    self._tick()

    def _mapped_status(self, mapping):
        # Internal sample in the ORIGINAL native phase, even when the caller
        # is paused in a native read tick. Do not enter/reset that phase here.
        self._tick()
        sequence = bytes(mapping[4:8])
        self._tick()
        require(len(sequence) == 4 and struct.unpack("<I", sequence)[0] % 2 == 0,
                "KERNEL_STATUS_UNSTABLE")
        self._fence()
        fields = _selinux_status_fields(bytes(mapping[:20]))
        self._tick()
        self._fence()
        ending = bytes(mapping[4:8])
        self._tick()
        require(ending == sequence and fields["sequence"] == struct.unpack("<I", sequence)[0],
                "KERNEL_STATUS_UNSTABLE")
        return fields

    def close(self):
        # No caller-owned fd is closed and no process registration is undone.
        self.closed = True


class _KernelRootViews:
    """Own only the fixed no-follow kernel-view roots and their original fds.

    This is a custody component, never a qualification handle. Initial views
    still require the installed factory's signed namespace/process authority.
    Reopening every component detects replacements, including same-inode bind
    mounts. Checks do not replace the independent operator's execution fence.
    """
    def __init__(self):
        _kernel_inspection_tick(self)
        self.native = object.__new__(_KernelNativeReads)
        self._native_original = self.native
        self.native._inspection_owner = getattr(self, "_inspection_owner", None)
        self.native.__init__()
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows = []
        self.closed = self.failed = self.busy = False
        self.mount_busy = False
        self.cleanup_failure = None
        try:
            with self._phase():
                self._acquire(self.rows)
            self.check()
            self.mount_pin = self._mount_inputs()
            self.mount_last = time.monotonic()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # retain cleanup_failure; construction never grants custody
            raise

    def _tick(self):
        require(type(self) is _KernelRootViews and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_ROOT_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_ROOT_DEADLINE")
        self.last = now

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_ROOT_UNAVAILABLE")
        self.busy = True
        self.last = time.monotonic()
        self.end = self.last + 2
        try:
            self._tick()
            yield
            self._tick()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _acquire(self, rows):
        # Parent indexes are fixed topological ancestry, never caller paths.
        layout = (("/", None, None), ("proc", 0, 0x9fa0), ("sys", 0, 0x62656572),
                  ("kernel", 2, 0x62656572), ("fs", 2, 0x62656572),
                  ("selinux", 4, 0xf97cff8c), ("cgroup", 4, 0x63677270))
        for name, parent_index, magic in layout:
            self._tick()
            parent = None if parent_index is None else rows[parent_index][0]
            row = [None, None, None]
            rows.append(row)
            try:
                row[0] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            finally:
                self._tick()
            # Capture close identity before any later validation can fail.
            try:
                info = os.fstat(row[0])
                row[1] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
            finally:
                self._tick()
            try:
                row[2] = self.native.directory_identity(row[0])
            finally:
                self._tick()
            observed = row[2]
            require(observed["identity"][2:4] == (0, 0)
                    and not stat.S_IMODE(observed["identity"][4]) & 0o022,
                    "KERNEL_ROOT_OWNER_MODE")
            require(magic is None or observed["filesystem"]["kind"] == magic, "KERNEL_ROOT_FILESYSTEM")
        self._relationships(rows)

    def _relationships(self, rows):
        require(len(rows) == 7, "KERNEL_ROOT_INVENTORY")
        # /sys/kernel and /sys/fs must remain children on the original sysfs
        # mount, not separately bind-mounted views of the same filesystem.
        for index in (3, 4):
            require(rows[index][2]["mountId"] == rows[2][2]["mountId"]
                    and rows[index][2]["filesystem"] == rows[2][2]["filesystem"], "KERNEL_SYSFS_SUBMOUNT")
        mounts = [rows[index][2]["mountId"] for index in (0, 1, 2, 5, 6)]
        require(len(set(mounts)) == len(mounts), "KERNEL_ROOT_MOUNT_ALIAS")

    def _mount_inputs(self):
        return tuple(row[0] for row in self.rows), _kernel_mount_pins([row[2] for row in self.rows], 7)

    def _reader_mounts(self):
        # Retained fixed roots only. Nested native reads keep their original
        # phase deadline; sampling never opens or replaces a descriptor.
        require(not self.closed and not self.failed and not self.mount_busy,
                "KERNEL_ROOT_MOUNT_UNAVAILABLE")
        self.mount_busy = True
        before = time.monotonic()
        def guard():
            require(type(self) is _KernelRootViews and not self.closed and not self.failed
                    and self.pid == os.getpid() and self.thread == threading.get_ident(),
                    "KERNEL_ROOT_MOUNT_CUSTODY")
            _kernel_inspection_tick(self)
            now = time.monotonic()
            require(self.mount_last <= now < before + 2, "KERNEL_ROOT_MOUNT_DEADLINE")
            self.mount_last = now
            if self.busy:
                require(self.last <= now < self.end, "KERNEL_ROOT_DEADLINE")
                self.last = now
            require(self._mount_inputs() == self.mount_pin, "KERNEL_ROOT_MOUNT_REPLACED")
            require(type(self.native) is _KernelNativeReads and self.native is self._native_original
                    and not self.native.closed and not self.native.failed, "KERNEL_ROOT_NATIVE_CHANGED")
        try:
            guard()
            native = self.native
            def sample():
                guard()
                try:
                    views = native._root_mounts(self.mount_pin[0])
                finally:
                    guard()
                require(_kernel_mount_pins(views, 7) == self.mount_pin[1], "KERNEL_ROOT_MOUNT_CHANGED")
            if native.busy:
                sample()
            else:
                with native._phase():
                    sample()
            guard()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.mount_busy = False

    def _retained(self):
        for fd, _, expected in self.rows:
            self._tick()
            try:
                observed = self.native.directory_identity(fd)
            finally:
                self._tick()
            require(observed == expected, "KERNEL_ROOT_CHANGED")

    def check(self):
        with self._phase():
            temporary = []
            try:
                self._retained()
                self._acquire(temporary)
                require([row[2] for row in temporary] == [row[2] for row in self.rows],
                        "KERNEL_ROOT_PATH_REPLACED")
                self._retained()
            finally:
                self._close_rows(temporary)

    def _close_rows(self, rows):
        failure = None
        while rows:
            fd, identity, _ = rows.pop()
            if fd is None:
                continue
            try:
                if identity is not None:
                    current = os.fstat(fd)
                    require((current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode)) == identity,
                            "KERNEL_ROOT_FD_REUSED")
                os.close(fd)  # no retry: an error may already have released it
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            self.cleanup_failure = self.cleanup_failure or failure
            raise failure

    def close(self):
        if self.closed:
            if self.cleanup_failure is not None:
                raise self.cleanup_failure
            return
        self.closed = True
        try:
            self._close_rows(self.rows)
        finally:
            self.native.close()
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


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


class _KernelProcessView:
    """Retained proc/pidfd/ns observations matched to expected role data only.

    This component cannot authenticate its expected data or grant qualification.
    The future installed qualifier must own it, supply independently verified
    role pins and the actual retained socket peer, and enforce boot/code/policy/
    cgroup/BPF custody. No caller fd, path, backend or function is accepted.
    """
    def __init__(self, roots, pid, role, expected):
        require(type(roots) is _KernelRootViews and type(pid) is int and 1 < pid < 2 ** 31,
                "KERNEL_PROCESS_INPUT")
        groups = {"SERVER": "proxy-server", "OBSERVER": "policy-observer",
                  "BROKER": "capacity-broker", "WORKER": "probe-worker"}
        require(type(role) is str and role in groups and (role != "SERVER" or pid == os.getpid()),
                "KERNEL_PROCESS_ROLE")
        expected = document(expected)
        require(type(expected) is dict and all(key in expected for key in
                ("uid", "gid", "processLabel", "namespaceInodes", "cgroup", "seccompMode")),
                "KERNEL_PROCESS_PINS")
        uid, gid, label, namespaces = (expected[key] for key in ("uid", "gid", "processLabel", "namespaceInodes"))
        require(type(uid) is type(gid) is int and (10000 <= uid < 2 ** 31 and 10000 <= gid < 2 ** 31
                if role == "WORKER" else uid == gid == 0)
                and type(label) is str and 1 <= len(label) <= 256 and all(32 <= ord(c) <= 126 for c in label)
                and type(namespaces) is dict and set(namespaces) == {"user", "mnt", "pid", "net"}
                and all(type(v) is int and 0 < v <= 9007199254740991 for v in namespaces.values())
                and type(expected["seccompMode"]) is int and expected["seccompMode"] == 2
                and type(expected["cgroup"]) is dict
                and expected["cgroup"].get("path") == "/sys/fs/cgroup/planeon-live/" + groups[role],
                "KERNEL_PROCESS_PINS")
        self.roots, self.target, self.role = roots, pid, role
        self.pin = (uid, gid, label, tuple(namespaces[name] for name in ("user", "mnt", "pid", "net")))
        self.cgroup = ("0::/planeon-live/" + groups[role] + "\n").encode("ascii")
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows, self.pidfd = [], [None, None]
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        try:
            with self._phase():
                self.pidfd[0] = os.pidfd_open(pid, 0)
                self.pidfd[1] = self._close_identity(self.pidfd[0])
                self._tick()
                self._acquire(self.rows)
                self.original = self._snapshot()
                self._compare()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    @staticmethod
    def _close_identity(fd):
        require(type(fd) is int and 2 < fd < 1048576, "KERNEL_PROCESS_FD")
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def _tick(self):
        require(type(self) is _KernelProcessView and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_PROCESS_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_PROCESS_DEADLINE")
        self.last = now
        fd, identity = self.pidfd
        if fd is not None and identity is not None:
            require(self._close_identity(fd) == identity and not os.get_inheritable(fd)
                    and select.select([fd], [], [fd], 0) == ([], [], []), "KERNEL_PROCESS_EXITED_OR_REUSED")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_PROCESS_DEADLINE")
        self.last = now

    def _io(self, function, *args, **kwargs):
        self._tick()
        try:
            return function(*args, **kwargs)
        finally:
            self._tick()

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_PROCESS_UNAVAILABLE")
        self.busy, self.last = True, time.monotonic()
        self.end = self.last + 2
        try:
            self._io(self.roots.check)
            yield
            self._io(self.roots.check)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _open(self, rows, name, parent, directory=True, namespace=False):
        row = [None, None, None]
        rows.append(row)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        flags |= os.O_DIRECTORY if directory else 0
        flags |= 0 if namespace else os.O_NOFOLLOW
        self._tick()
        try:
            row[0] = os.open(name, flags, dir_fd=parent)
        finally:
            self._tick()
        row[1] = self._io(self._close_identity, row[0])
        method = (self.roots.native.namespace_identity if namespace else
                  self.roots.native.directory_identity if directory else self.roots.native.proc_file_identity)
        row[2] = self._io(method, row[0])
        if not namespace:
            proc = self.roots.rows[1][2]
            require(row[2]["mountId"] == proc["mountId"] and row[2]["filesystem"] == proc["filesystem"],
                    "KERNEL_PROCESS_PROC_MOUNT")
        return row[0]

    def _acquire(self, rows):
        proc = self._open(rows, str(self.target), self.roots.rows[1][0])
        ns = self._open(rows, "ns", proc)
        self._open(rows, "attr", proc)
        task = self._open(rows, "task", proc)
        if self.role == "SERVER":
            self._open(rows, str(self.target), task)
        for index, (name, kind) in enumerate((("user", 0x10000000), ("mnt", 0x20000),
                                            ("pid", 0x20000000), ("net", 0x40000000))):
            # The only followed links are these four fixed proc namespace links.
            before = self._io(os.stat, name, dir_fd=ns, follow_symlinks=False)
            require(stat.S_ISLNK(before.st_mode) and before.st_dev == rows[1][2]["identity"][0],
                    "KERNEL_PROCESS_NAMESPACE_LINK")
            self._open(rows, name, ns, directory=False, namespace=True)
            after = self._io(os.stat, name, dir_fd=ns, follow_symlinks=False)
            require(_custody_identity(before) == _custody_identity(after)
                    and rows[-1][2]["kind"] == kind and rows[-1][2]["identity"][1] == self.pin[3][index],
                    "KERNEL_PROCESS_NAMESPACE_PIN")

    def _read(self, parent, name, maximum):
        temporary = []
        try:
            fd = self._open(temporary, name, parent, directory=False)
            chunks, size = [], 0
            while size <= maximum:
                chunk = self._io(os.read, fd, min(4096, maximum + 1 - size))
                require(type(chunk) is bytes, "KERNEL_PROCESS_READ")
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            require(size <= maximum, "KERNEL_PROCESS_READ_SIZE")
            require(self._io(self.roots.native.proc_file_identity, fd) == temporary[0][2],
                    "KERNEL_PROCESS_FILE_CHANGED")
            named = self._io(os.stat, name, dir_fd=parent, follow_symlinks=False)
            require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) ==
                    temporary[0][2]["identity"], "KERNEL_PROCESS_FILE_CHANGED")
            return b"".join(chunks)
        finally:
            self._close_rows(temporary)

    def _snapshot(self):
        proc, attr, task = self.rows[0][0], self.rows[2][0], self.rows[3][0]
        before = self._read(proc, "stat", 8192)
        status = self._read(proc, "status", 65536)
        value = _proc_process_fields(before, status)
        require(_proc_process_fields(self._read(proc, "stat", 8192), status) == value,
                "KERNEL_PROCESS_CHANGED")
        label = self._read(attr, "current", 257)
        if label.endswith(b"\0"):
            label = label[:-1]
        require(label == self.pin[2].encode("ascii") and self._read(proc, "cgroup", 4096) == self.cgroup
                and value["pid"] == self.target and value["uid"] == (self.pin[0],) * 4
                and value["gid"] == (self.pin[1],) * 4, "KERNEL_PROCESS_PIN_MISMATCH")
        tids = []
        with self._io(os.scandir, task) as entries:
            for entry in entries:
                self._tick()
                require(len(tids) < 4096 and type(entry.name) is str
                        and re.fullmatch(r"[1-9][0-9]{0,9}", entry.name)
                        and 0 < int(entry.name) < 2 ** 31, "KERNEL_PROCESS_TASKS")
                tids.append(int(entry.name))
        self._tick()
        require(len(tids) == len(set(tids)) == value["threads"] and self.target in tids,
                "KERNEL_PROCESS_TASKS")
        if self.role == "SERVER":
            require(tids == [self.target] and not self._read(self.rows[4][0], "children", 16384).strip(),
                    "KERNEL_PROCESS_SERVER_DESCENDANTS")
        return {**value, "tasks": tuple(sorted(tids))}

    def _compare(self):
        temporary = []
        try:
            self._acquire(temporary)
            require([row[2] for row in temporary] == [row[2] for row in self.rows], "KERNEL_PROCESS_PATH_CHANGED")
            require(self._snapshot() == self.original, "KERNEL_PROCESS_CHANGED")
            for index, (fd, _, expected) in enumerate(self.rows):
                method = self.roots.native.namespace_identity if index >= (5 if self.role == "SERVER" else 4) else self.roots.native.directory_identity
                require(self._io(method, fd) == expected, "KERNEL_PROCESS_RETAINED_CHANGED")
        finally:
            self._close_rows(temporary)

    def check(self):
        with self._phase():
            self._compare()

    def _close_rows(self, rows):
        failure = None
        while rows:
            fd, identity, *_ = rows.pop()
            if fd is None:
                continue
            try:
                require(identity is None or self._close_identity(fd) == identity, "KERNEL_PROCESS_FD_REUSED")
                os.close(fd)  # no retry of an uncertain close
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            self.cleanup_failure = self.cleanup_failure or failure
            raise failure

    def close(self):
        if not self.closed:
            self.closed = True
            rows, self.rows = self.rows, []
            rows.insert(0, self.pidfd)
            self.pidfd = [None, None]
            self._close_rows(rows)
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _KernelPolicyView:
    """Fresh kernel/boot/policy observations; matching expected data grants nothing.

    The installed qualifier must still authenticate these pins, retain process,
    code and filter ownership, and enforce the independent execution fence.
    Policy is a fresh-open kernel snapshot, never a retained or cached image.
    This component neither opens credentials nor changes host policy.
    """
    def __init__(self, roots, host, selinux):
        require(type(roots) is _KernelRootViews, "KERNEL_POLICY_ROOTS")
        host, selinux = document(host), document(selinux)
        require(type(host) is dict and set(host) == {"machine", "kernelRelease", "kernelNotesDigest", "bootId"}
                and type(selinux) is dict and set(selinux) == {"policyDigest", "status"}, "KERNEL_POLICY_PINS")
        require(host["machine"] in ("x86_64", "aarch64") and type(host["kernelRelease"]) is str
                and 1 <= len(host["kernelRelease"]) <= 128
                and all(32 <= ord(c) <= 126 for c in host["kernelRelease"])
                and type(host["bootId"]) is str
                and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", host["bootId"]),
                "KERNEL_POLICY_HOST_PINS")
        require_digest(host["kernelNotesDigest"], "kernel notes")
        require_digest(selinux["policyDigest"], "kernel policy")
        epoch = selinux["status"]
        require(type(epoch) is dict and set(epoch) == {"version", "sequence", "enforcing", "policyload", "denyUnknown"}
                and all(type(v) is int and 0 <= v < 2 ** 32 for v in epoch.values()), "KERNEL_POLICY_EPOCH_PINS")
        require(_selinux_status_fields(struct.pack("<5I", *(epoch[key] for key in
                ("version", "sequence", "enforcing", "policyload", "denyUnknown")))) == epoch,
                "KERNEL_POLICY_EPOCH_PINS")
        self.roots, self.host, self.selinux = roots, host, selinux
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows, self.policy_identity = [], None
        self.closed = self.failed = self.busy = False
        self.cleanup_failure, self.last = None, time.monotonic()
        self.epoch_mapping = self.epoch_original = None
        self.epoch_busy = False
        try:
            with self._phase():
                self._acquire(self.rows)
                self._observe()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # cleanup uncertainty is retained; no qualification granted
            raise

    def _tick(self):
        require(type(self) is _KernelPolicyView and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_POLICY_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_POLICY_DEADLINE")
        self.last = now

    def _io(self, function, *args, **kwargs):
        self._tick()
        try:
            return function(*args, **kwargs)
        finally:
            self._tick()

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_POLICY_UNAVAILABLE")
        self.busy = True
        self.end = time.monotonic() + 2
        try:
            self._io(self.roots.check)
            yield
            self._io(self.roots.check)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _open(self, rows, name, parent, root_index, directory=False):
        row = [None, None, None]
        rows.append(row)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        self._tick()
        try:
            row[0] = os.open(name, flags, dir_fd=parent)
        finally:
            self._tick()
        row[1] = self._io(_KernelProcessView._close_identity, row[0])
        reader = self.roots.native.directory_identity if directory else self.roots.native.proc_file_identity
        row[2] = self._io(reader, row[0])
        root = self.roots.rows[root_index][2]
        require(row[2]["mountId"] == root["mountId"] and row[2]["filesystem"] == root["filesystem"]
                and row[2]["identity"][2:4] == (0, 0)
                and not stat.S_IMODE(row[2]["identity"][4]) & 0o022, "KERNEL_POLICY_FILE_CUSTODY")
        return row[0]

    def _acquire(self, rows):
        # Fixed proc ancestry and exact kernel interfaces, no caller paths.
        parent = self.roots.rows[1][0]
        for name in ("sys", "kernel", "random"):
            parent = self._open(rows, name, parent, 1, True)
        self._open(rows, "boot_id", parent, 1)
        self._open(rows, "notes", self.roots.rows[3][0], 3)
        for name in ("status", "enforce", "deny_unknown"):
            self._open(rows, name, self.roots.rows[5][0], 5)

    def _retained(self):
        for index, (fd, _, expected) in enumerate(self.rows):
            reader = self.roots.native.directory_identity if index < 3 else self.roots.native.proc_file_identity
            require(self._io(reader, fd) == expected, "KERNEL_POLICY_RETAINED_CHANGED")

    def _epoch(self):
        fd, _, identity = self.rows[5]
        require(self._io(self.roots.native.proc_file_identity, fd) == identity, "KERNEL_POLICY_STATUS_CHANGED")
        observed = self._io(self.roots.native.status_epoch, fd)
        require(observed == self.selinux["status"], "KERNEL_POLICY_EPOCH_CHANGED")
        named = self._io(os.stat, "status", dir_fd=self.roots.rows[5][0], follow_symlinks=False)
        require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) == identity["identity"],
                "KERNEL_POLICY_STATUS_CHANGED")

    def _read(self, name, parent, root_index, maximum, expected=None):
        temporary = []
        try:
            self._epoch()
            fd = self._open(temporary, name, parent, root_index)
            self._epoch()  # includes the fresh policy open and any kernel wait
            require(expected is None or temporary[0][2] == expected, "KERNEL_POLICY_PATH_CHANGED")
            chunks, size = [], 0
            while size <= maximum:
                self._epoch()
                limit = min(65536, maximum + 1 - size)
                chunk = self._io(os.read, fd, limit)
                self._epoch()
                require(type(chunk) is bytes and len(chunk) <= limit, "KERNEL_POLICY_READ")
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            require(0 < size <= maximum, "KERNEL_POLICY_READ_SIZE")
            require(self._io(self.roots.native.proc_file_identity, fd) == temporary[0][2],
                    "KERNEL_POLICY_FILE_CHANGED")
            named = self._io(os.stat, name, dir_fd=parent, follow_symlinks=False)
            require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) ==
                    temporary[0][2]["identity"], "KERNEL_POLICY_FILE_CHANGED")
            self._epoch()
            return b"".join(chunks), temporary[0][2]
        finally:
            self._close_rows(temporary)  # release the policy snapshot promptly, once
            self._tick()

    def _host(self):
        native = self._io(os.uname)
        require(native.sysname == "Linux" and native.machine == self.host["machine"] == self.roots.native.machine
                and native.release == self.host["kernelRelease"], "KERNEL_POLICY_KERNEL_CHANGED")
        boot, _ = self._read("boot_id", self.rows[2][0], 1, 37, self.rows[3][2])
        notes, _ = self._read("notes", self.roots.rows[3][0], 3, 67108864, self.rows[4][2])
        require(boot == (self.host["bootId"] + "\n").encode("ascii")
                and byte_digest(notes) == self.host["kernelNotesDigest"], "KERNEL_POLICY_HOST_CHANGED")

    def _controls(self):
        for name, index in (("enforce", 6), ("deny_unknown", 7)):
            raw, _ = self._read(name, self.roots.rows[5][0], 5, 2, self.rows[index][2])
            require(raw == b"1", "KERNEL_POLICY_CONTROLS_CHANGED")

    def _observe(self):
        temporary = []
        try:
            self._retained()
            self._acquire(temporary)
            require([r[2] for r in temporary] == [r[2] for r in self.rows], "KERNEL_POLICY_PATH_CHANGED")
        finally:
            self._close_rows(temporary)
            self._tick()
        self._epoch()
        self._host()
        self._controls()
        policy, identity = self._read("policy", self.roots.rows[5][0], 5, 67108864, self.policy_identity)
        require(byte_digest(policy) == self.selinux["policyDigest"], "KERNEL_POLICY_DIGEST_CHANGED")
        self.policy_identity = identity  # inode/mount only; never cache policy bytes
        del policy
        self._epoch()
        self._controls()
        self._host()
        self._retained()
        self._epoch()

    def check(self):
        with self._phase():
            self._observe()

    def _epoch_inputs(self):
        fd, _, status = self.rows[5]
        parent, _, root = self.roots.rows[5]
        return (fd, tuple(status["identity"]), parent, tuple(root["identity"]),
                tuple(sorted(self.selinux["status"].items())))

    def _epoch_mount_inputs(self):
        rows = (self.rows[5], self.roots.rows[5], self.roots.rows[4])
        return tuple(row[0] for row in rows), self._mount_pins([row[2] for row in rows])

    @staticmethod
    def _mount_pins(views):
        return _kernel_mount_pins(views, 3)

    def _retain_epoch(self):
        # The fixed inspection factory calls this once, after full policy
        # observation. Never accept a mapping, fd, epoch or callback as input.
        require(not self.closed and not self.failed and self.epoch_original is None,
                "KERNEL_EPOCH_RETAIN_UNAVAILABLE")
        try:
            with self._phase():
                self._epoch()
                self.epoch_pin = self._epoch_inputs()
                self.epoch_mount_pin = self._epoch_mount_inputs()
                page_size = self._io(os.sysconf, "SC_PAGESIZE")
                require(type(page_size) is int and page_size in (4096, 16384, 65536), "KERNEL_STATUS_PAGE_SIZE")
                # Retain before the following tick can refuse. The mmap owns
                # its internal duplicate; rows[5]'s fd remains policy-owned.
                try:
                    self.epoch_mapping = mmap.mmap(self.epoch_pin[0], page_size,
                        flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
                    self.epoch_original = self.epoch_mapping
                finally:
                    self._tick()
                self._reader_epoch()
        except BaseException:
            self.failed = True
            raise

    def _reader_epoch(self):
        require(not self.closed and not self.failed and not self.epoch_busy,
                "KERNEL_EPOCH_UNAVAILABLE")
        self.epoch_busy = True
        before = last = time.monotonic()
        def guard():
            nonlocal last
            require(type(self) is _KernelPolicyView and not self.closed and not self.failed
                    and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_EPOCH_CUSTODY")
            _kernel_inspection_tick(self)
            now = time.monotonic()
            require(last <= now < before + 2, "KERNEL_EPOCH_DEADLINE")
            last = now
            require(self.epoch_original is not None and self.epoch_mapping is self.epoch_original
                    and self._epoch_inputs() == self.epoch_pin
                    and self._epoch_mount_inputs() == self.epoch_mount_pin, "KERNEL_EPOCH_REPLACED")
        def observed(function, *args, **kwargs):
            guard()
            try:
                return function(*args, **kwargs)
            finally:
                guard()
        try:
            guard()
            native = self.roots.native
            require(type(native) is _KernelNativeReads and native is self.roots._native_original
                    and not native.closed and not native.failed, "KERNEL_EPOCH_NATIVE_CHANGED")
            fd, identity, parent, root_identity, expected = self.epoch_pin
            def custody():
                for descriptor, pin in ((fd, identity), (parent, root_identity)):
                    info = observed(os.fstat, descriptor)
                    require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == pin,
                            "KERNEL_EPOCH_FD_CHANGED")
                    flags = observed(fcntl.fcntl, descriptor, fcntl.F_GETFL)
                    require(not observed(os.get_inheritable, descriptor)
                            and flags & os.O_ACCMODE == os.O_RDONLY and not flags & 0o10000000,
                            "KERNEL_EPOCH_FD_ACCESS")
                named = observed(os.stat, "status", dir_fd=parent, follow_symlinks=False)
                require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) == identity,
                        "KERNEL_EPOCH_PATH_CHANGED")
            custody()
            def sample():
                descriptors, pins = self.epoch_mount_pin
                require(self._mount_pins(observed(native._status_mounts, *descriptors)) == pins,
                        "KERNEL_EPOCH_MOUNT_CHANGED")
                fields = observed(native._mapped_status, self.epoch_original)
                require(self._mount_pins(observed(native._status_mounts, *descriptors)) == pins,
                        "KERNEL_EPOCH_MOUNT_CHANGED")
                return fields
            if native.busy:
                fields = sample()
            else:
                with native._phase():
                    fields = sample()
            require(tuple(sorted(fields.items())) == expected, "KERNEL_POLICY_EPOCH_CHANGED")
            custody()
            guard()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.epoch_busy = False

    def _close_rows(self, rows):
        failure = None
        while rows:
            fd, identity, *_ = rows.pop()
            if fd is None:
                continue
            try:
                require(identity is None or _KernelProcessView._close_identity(fd) == identity,
                        "KERNEL_POLICY_FD_REUSED")
                os.close(fd)  # uncertain close is not retried on a recycled fd
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            self.cleanup_failure = self.cleanup_failure or failure
            raise failure

    def close(self):
        if not self.closed:
            self.closed = True
            mapping, self.epoch_original = self.epoch_original, None
            self.epoch_mapping = None
            try:
                if mapping is not None:
                    mapping.close()  # no retry, including uncertain close
            except BaseException as exc:
                self.cleanup_failure = self.cleanup_failure or exc
            try:
                self._close_rows(self.rows)
            except BaseException as exc:
                self.cleanup_failure = self.cleanup_failure or exc
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _KernelCodeFiles:
    """Closed, retained code-file observations; not a qualification authority.

    Expected pins are detached data. The installed qualifier must authenticate
    them, bind process exe/maps and enclose this component in the independently
    enforced policy/change fence. No caller fd, loader or path discovery is used.
    """
    def __init__(self, roots, expected, page_size):
        require(type(roots) is _KernelRootViews and type(page_size) is int
                and page_size in (4096, 16384, 65536), "KERNEL_CODE_OWNER")
        expected = document(expected)
        require(type(expected) is list and 1 <= len(expected) <= 128, "KERNEL_CODE_INVENTORY")
        self.pins = {}
        for entry in expected:
            require(type(entry) is dict and set(entry) == {"path", "mode", "size", "sha256",
                    "verityDigest", "selinuxLabel", "executableSegments"}, "KERNEL_CODE_PINS")
            path = entry["path"]
            require(type(path) is str and 1 < len(path) <= 4096
                    and re.fullmatch(r"/[A-Za-z0-9_./+-]+", path)
                    and 1 <= len(path[1:].split("/")) <= 64
                    and all(p not in ("", ".", "..") for p in path[1:].split("/"))
                    and path not in self.pins, "KERNEL_CODE_PATH")
            require(entry["mode"] in ("0444", "0555") and type(entry["size"]) is int
                    and 0 < entry["size"] <= 67108864, "KERNEL_CODE_SIZE_MODE")
            require_digest(entry["sha256"], "code bytes")
            require_digest(entry["verityDigest"], "code verity")
            require(entry["sha256"] != entry["verityDigest"], "KERNEL_CODE_DISTINCT_DIGESTS")
            label = entry["selinuxLabel"]
            require(type(label) is str and 1 <= len(label) <= 256
                    and all(32 <= ord(c) <= 126 for c in label), "KERNEL_CODE_LABEL_PIN")
            segments = entry["executableSegments"]
            require(type(segments) is list and len(segments) <= 16, "KERNEL_CODE_SEGMENTS")
            for segment in segments:
                require(type(segment) is dict and set(segment) == {"offset", "length", "permissions"}
                        and type(segment["offset"]) is int and 0 <= segment["offset"] < entry["size"]
                        and type(segment["length"]) is int and 0 < segment["length"] <= 67108864
                        and segment["offset"] % page_size == segment["length"] % page_size == 0
                        and segment["permissions"] in ("r-xp", "--xp", "r-xs", "--xs"), "KERNEL_CODE_SEGMENTS")
            self.pins[path] = entry
        require(sum(e["size"] for e in expected) <= 536870912, "KERNEL_CODE_TOTAL_SIZE")
        require(not any(parent in self.pins for path in self.pins
                for parent in (str(p) for p in Path(path).parents)), "KERNEL_CODE_PATH_OVERLAP")
        self.roots, self.page_size = roots, page_size
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows, self.layouts = {}, {}
        self.closed = self.failed = self.busy = False
        self.cleanup_failure, self.last = None, time.monotonic()
        try:
            with self._phase():
                self._acquire(self.rows)
                self._observe()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # construction grants nothing, even if cleanup is uncertain
            raise

    def _tick(self):
        require(type(self) is _KernelCodeFiles and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_CODE_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_CODE_DEADLINE")
        self.last = now

    def _io(self, function, *args, **kwargs):
        self._tick()
        try:
            return function(*args, **kwargs)
        finally:
            self._tick()

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_CODE_UNAVAILABLE")
        self.busy = True
        self.end = time.monotonic() + 2
        try:
            self._io(self.roots.check)
            yield
            self._io(self.roots.check)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _identity(self, fd, directory):
        reader = self.roots.native.directory_identity if directory else self.roots.native.proc_file_identity
        identity = self._io(reader, fd)
        info = self._io(os.fstat, fd)
        require(info.st_uid == info.st_gid == 0
                and not stat.S_IMODE(info.st_mode) & (0o022 if directory else 0o222), "KERNEL_CODE_OWNER_MODE")
        # Directory times/counters may vary; code bytes/metadata may not.
        fingerprint = None if directory else _custody_identity(info)
        return identity, fingerprint

    def _acquire(self, rows):
        def descend(path, directory):
            if path == "/":
                return self.roots.rows[0][0]
            if path in rows:
                require(rows[path][3] == directory, "KERNEL_CODE_PATH_OVERLAP")
                return rows[path][0]
            parent_path, name = path.rsplit("/", 1)
            parent = descend(parent_path or "/", True)
            require(len(rows) < 8192, "KERNEL_CODE_ANCESTRY_SIZE")
            row = [None, None, None, directory]
            rows[path] = row
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            self._tick()
            try:
                row[0] = os.open(name, flags, dir_fd=parent)
            finally:
                self._tick()
            row[1] = self._io(_KernelProcessView._close_identity, row[0])
            row[2] = self._identity(row[0], directory)
            return row[0]
        for path in self.pins:
            descend(path, False)
        identities = [rows[p][2][0]["identity"][:2] for p in self.pins]
        require(len(identities) == len(set(identities)), "KERNEL_CODE_FILE_ALIAS")

    def _retained(self):
        for fd, _, expected, directory in self.rows.values():
            require(self._identity(fd, directory) == expected, "KERNEL_CODE_RETAINED_CHANGED")

    def _paths(self):
        temporary = {}
        try:
            self._acquire(temporary)
            require({p: r[2:] for p, r in temporary.items()} == {p: r[2:] for p, r in self.rows.items()},
                    "KERNEL_CODE_PATH_CHANGED")
        finally:
            self._close_rows(temporary)
            self._tick()

    def _file(self, path, pin):
        fd, _, identity, _ = self.rows[path]
        info = self._io(os.fstat, fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == pin["size"]
                and stat.S_IMODE(info.st_mode) == int(pin["mode"], 8), "KERNEL_CODE_FILE_PIN")
        def integrity():
            require(self._identity(fd, False) == identity, "KERNEL_CODE_FILE_CHANGED")
            label = self._io(os.getxattr, fd, "security.selinux")
            encoded = pin["selinuxLabel"].encode("ascii")
            require(type(label) is bytes and label in (encoded, encoded + b"\0"), "KERNEL_CODE_LABEL_CHANGED")
            require(self._io(self.roots.native.measure_verity, fd) == pin["verityDigest"],
                    "KERNEL_CODE_VERITY_CHANGED")
        integrity()
        chunks, size = [], 0
        while size <= pin["size"]:
            limit = min(65536, pin["size"] + 1 - size)
            chunk = self._io(os.pread, fd, limit, size)
            require(type(chunk) is bytes and len(chunk) <= limit, "KERNEL_CODE_READ")
            require(self._identity(fd, False) == identity, "KERNEL_CODE_FILE_CHANGED")
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        require(size == pin["size"], "KERNEL_CODE_READ_SIZE")
        raw = b"".join(chunks)
        require(byte_digest(raw) == pin["sha256"], "KERNEL_CODE_DIGEST_CHANGED")
        layout = _elf_code_layout(raw, self.roots.native.machine, self.page_size) if raw.startswith(b"\x7fELF") else None
        segments = [] if layout is None else [{k: v for k, v in s.items() if k != "virtualAddress"}
                                             for s in layout["segments"]]
        # ELF records R/W/X, not mmap's private/shared choice. The record pins
        # that separate choice; retain it for the exact subsequent maps match.
        normalized = [dict(s, permissions=s["permissions"][:3] + "p") for s in pin["executableSegments"]]
        require(segments == normalized, "KERNEL_CODE_ELF_PIN")
        if layout is not None:
            for segment, expected in zip(layout["segments"], pin["executableSegments"]):
                segment["permissions"] = expected["permissions"]
        del raw, chunks  # never retain an executable image or substitute cached bytes
        integrity()
        return layout

    def _observe(self):
        self._retained()
        self._paths()
        layouts = {p: self._file(p, pin) for p, pin in self.pins.items()}
        for layout in layouts.values():
            if layout is not None and layout["interpreter"] is not None:
                interpreter = layouts.get(layout["interpreter"])
                require(interpreter is not None and interpreter["interpreter"] is None,
                        "KERNEL_CODE_LOADER_NOT_ENROLLED")
        require(not self.layouts or self.layouts == layouts, "KERNEL_CODE_LAYOUT_CHANGED")
        self.layouts = layouts
        self._paths()
        self._retained()

    def check(self):
        with self._phase():
            self._observe()

    def match_maps(self, raw, auxv):
        """Match supplied map bytes to retained files; no native-map provenance.

        The eventual process owner must read maps/auxv from its original proc
        descriptors, twice under the same process/policy custody. This returns
        no handle and cannot authenticate a caller-supplied proc snapshot.
        """
        with self._phase():
            self._observe()
            maps = _proc_code_maps(raw, self.roots.native.machine, auxv)
            require(maps["pageSize"] == self.page_size, "KERNEL_CODE_MAP_PAGE_SIZE")
            grouped = {}
            for mapping in maps["files"]:
                path = mapping["path"]
                require(path in self.pins and self.layouts[path] is not None, "KERNEL_CODE_MAP_UNENROLLED")
                dev, inode, *_ = self.rows[path][2][0]["identity"]
                require((mapping["deviceMajor"], mapping["deviceMinor"], mapping["inode"]) ==
                        (os.major(dev), os.minor(dev), inode), "KERNEL_CODE_MAP_FILE_IDENTITY")
                grouped.setdefault(path, []).append(mapping)
            for path, actual in grouped.items():
                layout, bias = self.layouts[path], None
                remaining = list(actual)
                for segment in layout["segments"]:
                    cursor = segment["offset"]
                    end = cursor + segment["length"]
                    while cursor < end:
                        matches = [m for m in remaining if m["offset"] == cursor]
                        require(len(matches) == 1, "KERNEL_CODE_MAP_SEGMENT_COVERAGE")
                        mapping = matches[0]
                        size = mapping["end"] - mapping["start"]
                        observed_bias = mapping["start"] - segment["virtualAddress"] - (cursor - segment["offset"])
                        require(mapping["permissions"] == segment["permissions"] and cursor + size <= end
                                and observed_bias >= 0 and observed_bias % self.page_size == 0
                                and (layout["kind"] != 2 or observed_bias == 0)
                                and (bias is None or observed_bias == bias), "KERNEL_CODE_MAP_LAYOUT")
                        bias = observed_bias
                        cursor += size
                        remaining.remove(mapping)
                require(not remaining, "KERNEL_CODE_MAP_EXTRA_SEGMENT")
                require(layout["interpreter"] is None or layout["interpreter"] in grouped,
                        "KERNEL_CODE_MAP_LOADER_MISSING")
            self._observe()

    def _close_rows(self, rows):
        failure = None
        while rows:
            _, (fd, identity, *_) = rows.popitem()
            if fd is None:
                continue
            try:
                require(identity is None or _KernelProcessView._close_identity(fd) == identity,
                        "KERNEL_CODE_FD_REUSED")
                os.close(fd)  # never retry an uncertain close
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            self.cleanup_failure = self.cleanup_failure or failure
            raise failure

    def close(self):
        if not self.closed:
            self.closed = True
            self.layouts = {}
            self._close_rows(self.rows)
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _KernelProcessCode:
    """Retain original proc code observations, never authenticate role authority.

    The installed qualifier must bind signed manifests, original socket peers,
    kernel/policy and the external change fence before these observations grant
    anything. Kernel-special maps still need that host/policy corroboration.
    No caller-selected proc path, fd, backend, argv or mapping data is accepted.
    """
    def __init__(self, process, code, expected):
        require(type(process) is _KernelProcessView and type(code) is _KernelCodeFiles
                and process.roots is code.roots and not process.closed and not process.failed
                and not process.busy and not code.closed and not code.failed and not code.busy,
                "KERNEL_PROCESS_CODE_OWNER")
        expected = document(expected)
        require(type(expected) is dict and set(expected) ==
                {"executable", "artifactDigest", "interpreterPath", "filePaths"}, "KERNEL_PROCESS_CODE_PINS")
        python = "/opt/planeon/python/3.12.14/bin/python3.12"
        fixed = {"SERVER": (EXECUTABLE, python), "OBSERVER": (OBSERVER, None),
                 "BROKER": ("/opt/planeon/bin/harness-capacity-broker", None),
                 "WORKER": ("/opt/planeon/bin/harness-live-probe-exec", python)}
        require((expected["executable"], expected["interpreterPath"]) == fixed[process.role],
                "KERNEL_PROCESS_CODE_ROLE")
        selected = expected["filePaths"]
        require(type(selected) is list and 1 <= len(selected) <= 128
                and all(type(p) is str for p in selected) and len(set(selected)) == len(selected)
                and set(selected) <= code.pins.keys() and expected["executable"] in selected,
                "KERNEL_PROCESS_CODE_INVENTORY")
        require_digest(expected["artifactDigest"], "role artifact")
        artifact = code.pins[expected["executable"]]
        require(artifact["sha256"] == expected["artifactDigest"] and artifact["mode"] == "0555",
                "KERNEL_PROCESS_CODE_ARTIFACT")
        native = expected["interpreterPath"] or expected["executable"]
        require(native in selected and code.pins[native]["mode"] == "0555"
                and code.layouts[native] is not None, "KERNEL_PROCESS_CODE_INTERPRETER")
        if expected["interpreterPath"] is not None:
            require(code.layouts[expected["executable"]] is None, "KERNEL_PROCESS_CODE_ARCHIVE")
        self.process, self.code, self.roots = process, code, code.roots
        self.expected, self.native = expected, native
        self.cmdline = b"\0".join(p.encode("ascii") for p in
            ((native, expected["executable"]) if expected["interpreterPath"] else (native,))) + b"\0"
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows, self.link, self.original = {}, None, None
        self.closed = self.failed = self.busy = False
        self.cleanup_failure, self.last = None, time.monotonic()
        try:
            with self._phase():
                self.link = self._acquire(self.rows)
                self._observe()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # partial cleanup cannot turn a failure into an observation
            raise

    def _tick(self):
        require(type(self) is _KernelProcessCode and self.busy and not self.closed and not self.failed
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_PROCESS_CODE_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_PROCESS_CODE_DEADLINE")
        self.last = now
        self.process._tick()  # retained pidfd liveness and process/thread custody
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_PROCESS_CODE_DEADLINE")
        self.last = now

    def _io(self, function, *args, **kwargs):
        self._tick()
        try:
            return function(*args, **kwargs)
        finally:
            self._tick()

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_PROCESS_CODE_UNAVAILABLE")
        self.busy = True
        self.end = time.monotonic() + 2
        try:
            with self.process._phase():
                self._io(self.process._compare)
                yield
                self._io(self.process._compare)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _exe_link(self):
        proc = self.process.rows[0][0]
        before = self._io(os.stat, "exe", dir_fd=proc, follow_symlinks=False)
        require(stat.S_ISLNK(before.st_mode) and before.st_dev == self.roots.rows[1][2]["identity"][0]
                and (before.st_uid, before.st_gid) == self.process.pin[:2], "KERNEL_PROCESS_CODE_EXE_LINK")
        # Read only this fixed kernel magic link. Never open its returned value.
        path = self._io(os.readlink, "exe", dir_fd=proc)
        after = self._io(os.stat, "exe", dir_fd=proc, follow_symlinks=False)
        require(type(path) is str and path == self.native
                and _custody_identity(before) == _custody_identity(after), "KERNEL_PROCESS_CODE_EXE_LINK")
        return _custody_identity(after)

    def _identity(self, name, fd):
        identity = self._io(self.roots.native.proc_file_identity, fd)
        if name == "exe":
            fingerprint = _custody_identity(self._io(os.fstat, fd))
            require((identity, fingerprint) == self.code.rows[self.native][2], "KERNEL_PROCESS_CODE_EXE_CHANGED")
            return identity, fingerprint
        proc = self.process.rows[0][2]
        require(identity["mountId"] == proc["mountId"] and identity["filesystem"] == proc["filesystem"]
                and identity["identity"][2:4] == self.process.pin[:2]
                and not stat.S_IMODE(identity["identity"][4]) & 0o022, "KERNEL_PROCESS_CODE_PROC_IDENTITY")
        return identity

    def _acquire(self, rows):
        link = self._exe_link()
        for name in ("exe", "maps", "auxv", "cmdline"):
            row = [None, None, None]
            rows[name] = row
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
            if name != "exe":
                flags |= os.O_NOFOLLOW
            self._tick()
            try:
                row[0] = os.open(name, flags, dir_fd=self.process.rows[0][0])
            finally:
                self._tick()
            row[1] = self._io(_KernelProcessView._close_identity, row[0])
            row[2] = self._identity(name, row[0])
        require(self._exe_link() == link, "KERNEL_PROCESS_CODE_EXE_LINK")
        return link

    def _retained(self):
        for name, (fd, _, identity) in self.rows.items():
            require(self._identity(name, fd) == identity, "KERNEL_PROCESS_CODE_RETAINED_CHANGED")
        require(self._exe_link() == self.link, "KERNEL_PROCESS_CODE_EXE_LINK")

    def _paths(self):
        temporary = {}
        try:
            require(self._acquire(temporary) == self.link
                    and {n: r[2] for n, r in temporary.items()} == {n: r[2] for n, r in self.rows.items()},
                    "KERNEL_PROCESS_CODE_PATH_CHANGED")
        finally:
            self._close_rows(temporary)
            self._tick()

    def _read(self, name):
        maximum = {"maps": 1048576, "auxv": 65536, "cmdline": 8192}[name]
        fd, _, identity = self.rows[name]
        chunks, size = [], 0
        while size <= maximum:
            limit = min(4096, maximum + 1 - size)
            chunk = self._io(os.pread, fd, limit, size)
            require(type(chunk) is bytes and len(chunk) <= limit, "KERNEL_PROCESS_CODE_READ")
            require(self._identity(name, fd) == identity, "KERNEL_PROCESS_CODE_RETAINED_CHANGED")
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        require(0 < size <= maximum, "KERNEL_PROCESS_CODE_READ_SIZE")
        return b"".join(chunks)

    def _snapshot(self):
        auxv, cmdline, raw = self._read("auxv"), self._read("cmdline"), self._read("maps")
        require(cmdline == self.cmdline, "KERNEL_PROCESS_CODE_CMDLINE")
        parsed = _proc_code_maps(raw, self.roots.native.machine, auxv)
        native_page = self._io(os.sysconf, "SC_PAGESIZE")
        require(type(native_page) is int and native_page == parsed["pageSize"] == self.code.page_size,
                "KERNEL_PROCESS_CODE_PAGE_SIZE")
        selected = {p for p in self.expected["filePaths"] if self.code.layouts[p] is not None}
        require({m["path"] for m in parsed["files"]} == selected and self.native in selected,
                "KERNEL_PROCESS_CODE_MAPPING_INVENTORY")
        self._io(self.code.match_maps, raw, auxv)
        return dict(auxv=auxv, cmdline=cmdline, maps=parsed)

    def _observe(self):
        self._io(self.code.check)
        self._retained()
        self._paths()
        first = self._snapshot()
        self._io(self.process._compare)
        self._retained()
        second = self._snapshot()
        require(first == second and (self.original is None or first == self.original),
                "KERNEL_PROCESS_CODE_MAPPING_CHANGED")
        self._paths()
        self._retained()
        self.original = first  # ignore normal non-executable heap/stack churn

    def check(self):
        with self._phase():
            self._observe()

    def _close_rows(self, rows):
        failure = None
        while rows:
            _, (fd, identity, *_) = rows.popitem()
            if fd is None:
                continue
            try:
                require(identity is None or _KernelProcessView._close_identity(fd) == identity,
                        "KERNEL_PROCESS_CODE_FD_REUSED")
                os.close(fd)  # uncertain close is never retried
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            self.cleanup_failure = self.cleanup_failure or failure
            raise failure

    def close(self):
        if not self.closed:
            self.closed = True
            self.original = None
            self._close_rows(self.rows)
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _KernelCgroupView:
    """Read only the retained role cgroup; observations are not enforcement.

    The installed qualifier must authenticate the pins and namespace, compose
    active policy/code/BPF checks, and retain the external change fence. This
    reader neither migrates a process nor grants capacity, execution or cleanup.
    """
    def __init__(self, process, expected):
        require(type(process) is _KernelProcessView and not process.closed and not process.failed
                and not process.busy, "KERNEL_CGROUP_OWNER")
        expected = document(expected)
        require(type(expected) is dict and set(expected) == {"path", "inode", "memoryMaxBytes",
                "pidsMax", "cpuQuotaMicros", "cpuPeriodMicros"}, "KERNEL_CGROUP_PINS")
        group = {"SERVER": "proxy-server", "OBSERVER": "policy-observer",
                 "BROKER": "capacity-broker", "WORKER": "probe-worker"}[process.role]
        require(expected["path"] == "/sys/fs/cgroup/planeon-live/" + group
                and process.cgroup == ("0::/planeon-live/" + group + "\n").encode("ascii"),
                "KERNEL_CGROUP_ROLE")
        for key, minimum, maximum in (("inode", 1, 9007199254740991),
                ("memoryMaxBytes", 1048576, 1099511627776), ("pidsMax", 1, 4096),
                ("cpuQuotaMicros", 1000, 1000000), ("cpuPeriodMicros", 1000, 1000000)):
            require(type(expected[key]) is int and minimum <= expected[key] <= maximum, "KERNEL_CGROUP_PINS")
        self.process, self.roots, self.expected, self.group = process, process.roots, expected, group
        self.controls = {"memory.max": (str(expected["memoryMaxBytes"]) + "\n").encode("ascii"),
                         "pids.max": (str(expected["pidsMax"]) + "\n").encode("ascii"),
                         "cpu.max": (str(expected["cpuQuotaMicros"]) + " " +
                                     str(expected["cpuPeriodMicros"]) + "\n").encode("ascii")}
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows = []
        self.closed = self.failed = self.busy = False
        self.cleanup_failure, self.last = None, time.monotonic()
        try:
            with self._phase():
                self._acquire(self.rows)
                self._observe()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # partial/uncertain cleanup cannot produce qualification
            raise

    def _tick(self):
        require(type(self) is _KernelCgroupView and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_CGROUP_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_CGROUP_DEADLINE")
        self.last = now
        self.process._tick()  # original pidfd, process and namespace owner
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_CGROUP_DEADLINE")
        self.last = now

    def _io(self, function, *args, **kwargs):
        self._tick()
        try:
            return function(*args, **kwargs)
        finally:
            self._tick()

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_CGROUP_UNAVAILABLE")
        self.busy = True
        self.end = time.monotonic() + 2
        try:
            with self.process._phase():
                self._io(self.process._compare)
                yield
                self._io(self.process._compare)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _identity(self, fd, directory):
        reader = self.roots.native.directory_identity if directory else self.roots.native.proc_file_identity
        identity = self._io(reader, fd)
        root = self.roots.rows[6][2]
        require(identity["mountId"] == root["mountId"] and identity["filesystem"] == root["filesystem"]
                and identity["identity"][2:4] == (0, 0)
                and not stat.S_IMODE(identity["identity"][4]) & 0o022, "KERNEL_CGROUP_IDENTITY")
        return identity

    def _open(self, rows, name, parent, directory=False):
        row = [None, None, None, directory]
        rows.append(row)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        self._tick()
        try:
            row[0] = os.open(name, flags, dir_fd=parent)
        finally:
            self._tick()
        row[1] = self._io(_KernelProcessView._close_identity, row[0])
        row[2] = self._identity(row[0], directory)
        return row[0]

    def _acquire(self, rows):
        parent = self._open(rows, "planeon-live", self.roots.rows[6][0], True)
        group = self._open(rows, self.group, parent, True)
        require(rows[1][2]["identity"][1] == self.expected["inode"], "KERNEL_CGROUP_INODE")
        for name in (*self.controls, "cgroup.procs"):
            self._open(rows, name, group)
        require(len({tuple(row[2]["identity"][:2]) for row in rows}) == len(rows), "KERNEL_CGROUP_ALIAS")

    def _retained(self):
        for fd, _, identity, directory in self.rows:
            require(self._identity(fd, directory) == identity, "KERNEL_CGROUP_RETAINED_CHANGED")

    def _paths(self):
        temporary = []
        try:
            self._acquire(temporary)
            require([r[2:] for r in temporary] == [r[2:] for r in self.rows], "KERNEL_CGROUP_PATH_CHANGED")
        finally:
            self._close_rows(temporary)
            self._tick()

    def _read(self, name, index, maximum):
        # Fresh-open each kernfs sequence; a retained fd's old seq-file buffer
        # is not a fresh control/membership observation. Never return that fd.
        temporary = []
        try:
            fd = self._open(temporary, name, self.rows[1][0])
            identity = self.rows[index][2]
            require(temporary[0][2] == identity, "KERNEL_CGROUP_PATH_CHANGED")
            chunks, size = [], 0
            while size <= maximum:
                limit = min(4096, maximum + 1 - size)
                raw = self._io(os.read, fd, limit)
                require(type(raw) is bytes and len(raw) <= limit, "KERNEL_CGROUP_READ")
                require(self._identity(fd, False) == identity, "KERNEL_CGROUP_READ_CHANGED")
                if not raw:
                    break
                chunks.append(raw)
                size += len(raw)
            require(0 < size <= maximum, "KERNEL_CGROUP_READ_SIZE")
            named = self._io(os.stat, name, dir_fd=self.rows[1][0], follow_symlinks=False)
            require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) ==
                    identity["identity"], "KERNEL_CGROUP_PATH_CHANGED")
            return b"".join(chunks)
        finally:
            self._close_rows(temporary)
            self._tick()

    def _membership(self):
        raw = self._read("cgroup.procs", 5, 65536)
        require(raw.endswith(b"\n"), "KERNEL_CGROUP_MEMBERSHIP")
        lines = raw[:-1].split(b"\n")
        require(1 <= len(lines) <= 4096 and all(re.fullmatch(rb"[1-9][0-9]{0,9}", p) for p in lines),
                "KERNEL_CGROUP_MEMBERSHIP")
        pids = [int(p) for p in lines]
        require(all(p < 2 ** 31 for p in pids) and len(pids) == len(set(pids))
                and self.process.target in pids, "KERNEL_CGROUP_MEMBERSHIP")
        # Linux does not sort this list. Duplicates indicate an uncertain read;
        # unrelated member churn is not target drift or proof of worker reaping.

    def _snapshot(self):
        self._membership()
        for index, (name, expected) in enumerate(self.controls.items(), 2):
            require(self._read(name, index, 64) == expected, "KERNEL_CGROUP_LIMIT_CHANGED")
        self._membership()

    def _observe(self):
        self._retained()
        self._paths()
        self._snapshot()
        self._io(self.process._compare)
        self._retained()
        self._snapshot()
        self._paths()
        self._retained()

    def check(self):
        with self._phase():
            self._observe()

    def _close_rows(self, rows):
        failure = None
        while rows:
            fd, identity, *_ = rows.pop()
            if fd is None:
                continue
            try:
                require(identity is None or _KernelProcessView._close_identity(fd) == identity,
                        "KERNEL_CGROUP_FD_REUSED")
                os.close(fd)  # an uncertain close is never retried
            except BaseException as exc:
                failure = failure or exc
        if failure is not None:
            self.cleanup_failure = self.cleanup_failure or failure
            raise failure

    def close(self):
        if not self.closed:
            self.closed = True
            self._close_rows(self.rows)
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _KernelBpfAttr(ctypes.Structure):
    _fields_ = [("words", ctypes.c_uint64 * 8)]


class _KernelBpfInfo(ctypes.Structure):
    # Linux 6.12's 232 bytes plus a zero extension sentinel: require the kernel
    # to return exactly 232, not silently accept a shorter/newer info layout.
    _fields_ = [("words", ctypes.c_uint64 * 30)]


class _KernelBpfView:
    """Observe seven fixed hooks; never install filters or mint qualification.

    Borrow the original cgroup/process owner and retain only program fds.
    Authenticated pins, independent semantic review, active policy/code checks
    and the external execution/change fence remain the qualifier's obligations.
    """
    HOOKS = (("INET_SOCK_CREATE", 2, 9), ("INET4_BIND", 8, 18),
             ("INET6_BIND", 9, 18), ("INET4_CONNECT", 10, 18),
             ("INET6_CONNECT", 11, 18), ("UDP4_SENDMSG", 14, 18), ("UDP6_SENDMSG", 15, 18))

    def __init__(self, cgroup, expected):
        require(type(cgroup) is _KernelCgroupView and not cgroup.closed and not cgroup.failed
                and not cgroup.busy, "KERNEL_BPF_OWNER")
        expected = document(expected)
        require(type(expected) is dict and set(expected) == {r[0] for r in self.HOOKS}, "KERNEL_BPF_PINS")
        for name, _, kind in self.HOOKS:
            pin = expected[name]
            require(type(pin) is dict and set(pin) == {"programId", "programType", "translatedSha256",
                    "instructionBytes", "mapIds", "ifindex"}, "KERNEL_BPF_PINS")
            require(type(pin["programId"]) is int and 1 <= pin["programId"] <= 4294967295
                    and type(pin["programType"]) is int and pin["programType"] == kind
                    and type(pin["instructionBytes"]) is int and 8 <= pin["instructionBytes"] <= 65536
                    and pin["instructionBytes"] % 8 == 0 and type(pin["mapIds"]) is list and not pin["mapIds"]
                    and type(pin["ifindex"]) is int and pin["ifindex"] == 0, "KERNEL_BPF_PINS")
            require_digest(pin["translatedSha256"], "KERNEL_BPF_TRANSLATED_DIGEST")
        require(ctypes.sizeof(_KernelBpfAttr) == 64 and ctypes.alignment(_KernelBpfAttr) == 8
                and ctypes.sizeof(_KernelBpfInfo) == 240 and ctypes.alignment(_KernelBpfInfo) == 8,
                "KERNEL_BPF_ABI")
        self.cgroup, self.expected = cgroup, expected
        self.native = cgroup.roots.native
        self.number = {"x86_64": 321, "aarch64": 280}[self.native.machine]
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.closed = self.failed = self.busy = False
        self.cleanup_failure, self.last = None, time.monotonic()
        self.rows, self.baseline = [], None
        try:
            with self._phase():
                self.baseline = self._queries()
                for name, _, _ in self.HOOKS:
                    self._acquire(name)
                self._observe()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    def _tick(self):
        require(type(self) is _KernelBpfView and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_BPF_CUSTODY")
        _kernel_inspection_tick(self)
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_BPF_DEADLINE")
        self.last = now
        self.cgroup._tick()
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_BPF_DEADLINE")
        self.last = now

    def _io(self, function, *args):
        self._tick()
        try:
            return function(*args)
        finally:
            self._tick()

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_BPF_UNAVAILABLE")
        self.busy = True
        self.end = time.monotonic() + 2
        try:
            with self.cgroup._phase():
                self._io(self.cgroup._observe)
                yield
                self._io(self.cgroup._observe)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _call(self, command, attr):
        require(type(command) is int and command in (13, 15, 16)
                and type(attr) is _KernelBpfAttr, "KERNEL_BPF_COMMAND")
        return self.native.lib.syscall(ctypes.c_long(self.number), ctypes.c_uint(command),
                                       ctypes.byref(attr), ctypes.c_uint(64))

    def _queries(self):
        result = []
        for name, hook, _ in self.HOOKS:
            for effective in (0, 1):
                self._io(self.cgroup._retained)
                attr, ids = _KernelBpfAttr(), (ctypes.c_uint32 * 16)()
                target = self.cgroup.rows[1][0]
                pointer = ctypes.addressof(ids)
                struct.pack_into("<4IQI", attr, 0, target, hook, effective, 0, pointer, 16)
                require(self._io(self._call, 16, attr) == 0, "KERNEL_BPF_QUERY_UNAVAILABLE")
                raw = bytes(attr)
                fd, actual_hook, flags, attach, returned, count = struct.unpack_from("<4IQI", raw)
                require((fd, actual_hook, flags, returned) == (target, hook, effective, pointer)
                        and raw[28:] == b"\0" * 36 and count == 1
                        and ids[0] == self.expected[name]["programId"] and not any(ids[1:])
                        and (attach == 0 if effective else attach in (0, 1, 2)), "KERNEL_BPF_QUERY_CHANGED")
                self._io(self.cgroup._retained)
                result.append((name, effective, attach, ids[0]))
        return tuple(result)

    def _descriptor(self, fd):
        identity = self._io(_KernelProcessView._close_identity, fd)
        require(not self._io(os.get_inheritable, fd), "KERNEL_BPF_FD_INHERITABLE")
        flags = self._io(fcntl.fcntl, fd, fcntl.F_GETFL)
        # The kernel creates bpf-prog anonymous descriptors O_RDWR|O_CLOEXEC.
        # This is not permission to write them or pass them to another process.
        require(flags & os.O_ACCMODE == os.O_RDWR and not flags & 0x200000, "KERNEL_BPF_FD_MODE")
        return identity

    def _acquire(self, name):
        row = [None, None, name, None]
        self.rows.append(row)
        attr = _KernelBpfAttr()
        struct.pack_into("<I", attr, 0, self.expected[name]["programId"])
        before = bytes(attr)
        self._tick()
        try:
            fd = self._call(13, attr)
            # Record ownership before the post-call clock/custody check, so a
            # successful acquisition followed by expiry cannot leak the fd.
            if type(fd) is int and fd >= 0:
                row[0] = fd
        finally:
            self._tick()
        require(row[0] is not None and bytes(attr) == before, "KERNEL_BPF_OPEN_UNAVAILABLE")
        row[1] = self._descriptor(row[0])
        row[3] = self._info(row)

    def _info(self, row):
        fd, identity, name, _ = row
        require(self._descriptor(fd) == identity, "KERNEL_BPF_FD_REUSED")
        attr, info = _KernelBpfAttr(), _KernelBpfInfo()
        instructions = (ctypes.c_ubyte * 65536)()
        pointer = ctypes.addressof(instructions)
        struct.pack_into("<I", info, 20, 65536)
        struct.pack_into("<Q", info, 32, pointer)
        struct.pack_into("<IIQ", attr, 0, fd, 240, ctypes.addressof(info))
        require(self._io(self._call, 15, attr) == 0, "KERNEL_BPF_INFO_UNAVAILABLE")
        raw, out = bytes(info), bytes(attr)
        require(struct.unpack_from("<IIQ", out) == (fd, 232, ctypes.addressof(info))
                and out[16:] == b"\0" * 48 and raw[228:] == b"\0" * 12, "KERNEL_BPF_INFO_LAYOUT")
        pin = self.expected[name]
        require(struct.unpack_from("<II", raw) == (pin["programType"], pin["programId"])
                and struct.unpack_from("<I", raw, 20)[0] == pin["instructionBytes"]
                and struct.unpack_from("<Q", raw, 32)[0] == pointer, "KERNEL_BPF_PROGRAM_CHANGED")
        require(all(struct.unpack_from("<Q", raw, offset)[0] == 0
                    for offset in (24, 56, 88, 96, 112, 120, 136, 152, 160, 184))
                and struct.unpack_from("<I", raw, 52)[0] == 0
                and struct.unpack_from("<I", raw, 80)[0] == 0
                and struct.unpack_from("<I", raw, 84)[0] in (0, 1)
                and tuple(struct.unpack_from("<I", raw, o)[0] for o in (132, 172, 176)) == (8, 16, 8),
                "KERNEL_BPF_PROGRAM_UNSUPPORTED")
        require(byte_digest(bytes(instructions[:pin["instructionBytes"]])) == pin["translatedSha256"]
                and not any(instructions[pin["instructionBytes"]:]), "KERNEL_BPF_INSTRUCTIONS_CHANGED")
        require(self._descriptor(fd) == identity, "KERNEL_BPF_FD_REUSED")
        # Runtime counters may advance. Do not turn legitimate executions into
        # identity drift; the program, tag, load identity and other fields bind.
        stable = bytearray(raw[:232])
        stable[32:40] = b"\0" * 8
        stable[192:216] = b"\0" * 24
        return bytes(stable)

    def _observe(self):
        require(self._queries() == self.baseline, "KERNEL_BPF_ATTACHMENT_DRIFT")
        for row in self.rows:
            require(self._info(row) == row[3], "KERNEL_BPF_INFO_DRIFT")
        require(self._queries() == self.baseline, "KERNEL_BPF_ATTACHMENT_DRIFT")

    def check(self):
        with self._phase():
            self._observe()

    def _close_program(self, fd, identity, name, observed):
        require(identity is None or _KernelProcessView._close_identity(fd) == identity,
                "KERNEL_BPF_FD_REUSED")
        if observed is not None:
            # anon_inode fstat identity can be shared by different programs.
            # On cleanup, recheck the actual ID too, without re-entering failed
            # inspection or treating a matching ID as execution authority.
            started = time.monotonic()
            attr, info = _KernelBpfAttr(), _KernelBpfInfo()
            struct.pack_into("<IIQ", attr, 0, fd, 240, ctypes.addressof(info))
            result = self._call(15, attr)
            now = time.monotonic()
            require(started <= now < started + 2 and self.pid == os.getpid()
                    and self.thread == threading.get_ident() and result == 0
                    and struct.unpack_from("<IIQ", attr) == (fd, 232, ctypes.addressof(info))
                    and bytes(attr)[16:] == b"\0" * 48 and bytes(info)[228:] == b"\0" * 12
                    and struct.unpack_from("<II", info) ==
                        (self.expected[name]["programType"], self.expected[name]["programId"])
                    and _KernelProcessView._close_identity(fd) == identity, "KERNEL_BPF_CLOSE_UNCERTAIN")
        os.close(fd)  # never retry an uncertain close or close a substituted program

    def close(self):
        if not self.closed:
            self.closed = True
            failure = None
            while self.rows:
                fd, identity, name, observed = self.rows.pop()
                if fd is None:
                    continue
                try:
                    self._close_program(fd, identity, name, observed)
                except BaseException as exc:
                    failure = failure or exc
            self.cleanup_failure = failure
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


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


class _ServerQualificationBinding:
    """Authenticated expected values, NOT native containment or execution authority.

    Only the active installed server may construct this from its retained files.
    No caller record, descriptor or success callback is accepted. The native
    readers still have to prove actual policy/process/code/cgroup/BPF custody.
    This object borrows the server's file owner and must never close its FDs.
    """
    def __init__(self, owner):
        self.owner, self.closed, self.poisoned = owner, False, False
        require(type(owner) is NativeProxyServer, "QUALIFICATION_OWNER_INVALID")
        owner._owner_check()
        require(owner.qualification_binding is self and type(owner.files) is _Files
                and owner.files.owner is owner and not owner.files.sealed,
                "QUALIFICATION_OWNER_INVALID")
        self.files, self.deadline = owner.files, owner.deadline
        self.last_wall, self.last_mono = require_time(utc_now(), "now"), time.monotonic()
        try:
            self._load()
            require(self.last_mono <= time.monotonic() < min(self.last_mono + 2, self.deadline)
                    and 0 <= (require_time(utc_now(), "now") - self.last_wall).total_seconds() < 2,
                    "QUALIFICATION_LOAD_DEADLINE")
            self._original = self._inputs()
            self._record_digests = (byte_digest(self._record_raw), byte_digest(self._broker_raw))
            self.check()
        except BaseException:
            self.poisoned = True
            raise

    def _inputs(self):
        owner = self.owner
        return canonical_bytes([owner.envelope_path, [byte_digest(raw) for raw in owner.authority],
            owner.envelope, owner.capacity, owner.plan, owner.binding, owner.profile,
            owner.observation_binding, owner.endpoint, byte_digest(owner.ca), owner.manifest,
            owner.artifact_digest, byte_digest(owner.snapshot),
            {path: byte_digest(raw) for path, raw in owner.kit.items()}])

    def _load(self):
        owner, files = self.owner, self.files
        envelope_raw = files.read(owner.envelope_path)
        release_trust = files.read(str(FIXED_RELEASE_TRUST))
        tenant_trust = files.read(str(FIXED_TENANT_TRUST))
        envelope = require_canonical_document(envelope_raw)
        # Authenticate selected references before even reading the capacity file.
        _verify_reference_authority(envelope, release_trust, tenant_trust, utc_now())
        capacity_raw = files.read(envelope["capacityAuthorizationFileReference"], envelope["capacityAuthorizationDigest"])
        self.authority = (envelope_raw, capacity_raw, release_trust, tenant_trust)
        envelope, capacity, _, _ = verify_backend_authority(*self.authority, now=self.last_wall)
        release_raw = files.read(envelope["campaignReleaseFileReference"], envelope["campaignReleaseDigest"])
        release = require_canonical_document(release_raw)
        kit = files.kit(envelope["conformanceKitRoot"], release["tree"])
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
        require(architecture is not None, "QUALIFICATION_ARCHITECTURE_UNAVAILABLE")
        plan_raw = kit["campaigns/platform/linux-baseline/inputs/" + architecture + ".json"]
        plan = require_canonical_document(plan_raw)
        binding = binding_from_authority(*self.authority, release_bytes=release_raw, plan_bytes=plan_raw,
            architecture=architecture, expected_nonce=envelope["nonce"], expected_tenant=envelope["tenantId"],
            expected_environment=envelope["environmentId"], expected_release=envelope["campaignReleaseDigest"], now=utc_now())
        profile, observation, endpoint, ca = retained_profile(envelope, capacity, plan, release, kit)
        require(self.authority == owner.authority and kit == owner.kit and ca == owner.ca
                and owner.snapshot == canonical_bytes([envelope, capacity, plan, binding, profile, observation, endpoint])
                == canonical_bytes([owner.envelope, owner.capacity, owner.plan, owner.binding, owner.profile,
                                    owner.observation_binding, owner.endpoint]),
                "QUALIFICATION_INPUT_SUBSTITUTION")
        endpoints = [{"endpointId": row["endpointId"], "kind": row["kind"],
            "addressFamily": "IPV4" if ipaddress.ip_address(row["ipAddress"]).version == 4 else "IPV6",
            "ipAddress": row["ipAddress"], "port": row["port"]} for row in envelope["endpoints"]]
        record = retained_qualification_record(profile, endpoints, observation, release, kit)
        require(record["host"]["machine"] == os.uname().machine, "QUALIFICATION_HOST_MISMATCH")
        broker = retained_broker_binding(profile, observation, release, kit)
        preflight = byte_digest(kit[QUALIFICATION_PATH])
        installed = {}
        for role, path, executable in (("SERVER", MANIFEST, EXECUTABLE),
                ("OBSERVER", OBSERVER_MANIFEST, OBSERVER), ("BROKER", BROKER_MANIFEST, BROKER),
                ("WORKER", WORKER_MANIFEST, WORKER)):
            value, manifest_digest, artifact_digest = _manifest(files, path, executable)
            require(value["preflightEvidenceDigest"] == preflight
                    and record["roles"][role]["executable"] == executable
                    and record["roles"][role]["artifactDigest"] == artifact_digest,
                    "QUALIFICATION_INSTALLED_ROLE_MISMATCH")
            installed[role] = {"manifestDigest": manifest_digest, "executableDigest": artifact_digest}
            if role == "SERVER":
                require(value == owner.manifest and artifact_digest == owner.artifact_digest,
                        "QUALIFICATION_SERVER_SUBSTITUTION")
        require(observation["observer"] == installed["OBSERVER"]
                and broker["brokerManifestDigest"] == installed["BROKER"]["manifestDigest"]
                and broker["brokerExecutableDigest"] == installed["BROKER"]["executableDigest"]
                and broker["workerManifestDigest"] == installed["WORKER"]["manifestDigest"]
                and broker["workerArtifactDigest"] == installed["WORKER"]["executableDigest"],
                "QUALIFICATION_PEER_ENROLLMENT_MISMATCH")
        self._record_raw, self._broker_raw = canonical_bytes(record), canonical_bytes(broker)

    def check(self):
        try:
            require(not self.closed and not self.poisoned, "QUALIFICATION_BINDING_CLOSED")
            owner = self.owner
            owner._owner_check()
            require(owner.qualification_binding is self and owner.files is self.files
                    and self.files.owner is owner and owner.deadline == self.deadline,
                    "QUALIFICATION_OWNER_CHANGED")
            self.files.check()
            now, before = require_time(utc_now(), "now"), time.monotonic()
            require(now >= self.last_wall and self.last_mono <= before < self.deadline,
                    "QUALIFICATION_CLOCK_OR_EXPIRY")
            verify_backend_authority(*self.authority, now=now)
            require(self._inputs() == self._original and self._record_digests ==
                    (byte_digest(self._record_raw), byte_digest(self._broker_raw)), "QUALIFICATION_INPUT_SUBSTITUTION")
            scope = document(self._record_raw)["scope"]
            require(_time(scope["validFrom"]) <= now < _time(scope["expiresAt"]), "QUALIFICATION_CLOCK_OR_EXPIRY")
            self.files.check()
            after_wall, after = require_time(utc_now(), "now"), time.monotonic()
            require(now <= after_wall < _time(scope["expiresAt"])
                    and before <= after < min(before + 2, self.deadline)
                    and (after_wall - now).total_seconds() < 2,
                    "QUALIFICATION_CLOCK_OR_EXPIRY")
            self.last_wall, self.last_mono = after_wall, after
        except BaseException:
            self.poisoned = True
            raise

    @property
    def record(self):
        self.check()
        return document(self._record_raw)

    @property
    def broker_binding(self):
        self.check()
        return document(self._broker_raw, 65536)

    def close(self):
        self.closed = True  # borrowed files remain exclusively server-owned


class _KernelSelfInspection:
    """Server-owned composition of authenticated expected data and read views.

    The private _KernelQualification owns this self reader; original peer
    channels own their role readers. Neither observation grants execution:
    the independently installed broker owns the active enforcement gate.
    No PID, role, backend, callback, record or descriptor is caller-selectable.
    """
    def __init__(self, owner):
        self.owner, self.owned = owner, []
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        self.epoch_ready = self.epoch_sampling = False
        for name in ("roots", "policy", "process", "code", "mappings", "cgroup", "filters"):
            setattr(self, name, None)
        try:
            require(type(owner) is NativeProxyServer, "KERNEL_INSPECTION_OWNER")
            owner._owner_check()
            require(owner.self_inspection is self
                    and type(owner.qualification_binding) is _ServerQualificationBinding
                    and owner.qualification_binding.owner is owner,
                    "KERNEL_INSPECTION_BINDING")
            self.binding = owner.qualification_binding
            self.deadline = owner.deadline
            self.last, self.wall = time.monotonic(), require_time(utc_now(), "now")
            require(self.last < self.deadline <= self.last + 900, "KERNEL_INSPECTION_LIFETIME")
            with self._phase():
                record = self.binding.record
                self.authority = self.binding.authority
                self.session_raw = canonical_bytes(owner.binding)
                self.authority_window = (_time(owner.binding["notBefore"]), _time(owner.binding["notAfter"]))
                self.record_raw = canonical_bytes(record)
                self.scope = record["scope"]
                self.role = record["roles"]["SERVER"]
                self._own("roots", _KernelRootViews)
                self._own("policy", _KernelPolicyView, self.roots, record["host"], record["selinux"])
                require(self.policy._retain_epoch() is None, "KERNEL_EPOCH_CHECK_RESULT")
                self.epoch_ready = True
                self._policy_check()
                self._own("process", _KernelProcessView, self.roots, os.getpid(), "SERVER", self.role)
                self._policy_check()
                self._tick()
                page_size = os.sysconf("SC_PAGESIZE")
                self._tick()
                require(type(page_size) is int and page_size in (4096, 16384, 65536), "KERNEL_INSPECTION_PAGE_SIZE")
                self._own("code", _KernelCodeFiles, self.roots, record["files"], page_size)
                self._policy_check()
                code_pins = {k: self.role[k] for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")}
                self._own("mappings", _KernelProcessCode, self.process, self.code, code_pins)
                self._policy_check()
                self._own("cgroup", _KernelCgroupView, self.process, self.role["cgroup"])
                self._policy_check()
                self._own("filters", _KernelBpfView, self.cgroup, self.role["bpfPrograms"])
                self._observe()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass  # original refusal plus sticky cleanup uncertainty
            raise

    def _tick(self):
        require(type(self) is _KernelSelfInspection and not self.closed and not self.failed and self.busy,
                "KERNEL_INSPECTION_UNAVAILABLE")
        self.owner._owner_check()
        require(self.owner.self_inspection is self and self.owner.qualification_binding is self.binding
                and self.binding.owner is self.owner and not self.binding.closed and not self.binding.poisoned
                and self.owner.files is self.binding.files and self.owner.deadline == self.deadline,
                "KERNEL_INSPECTION_OWNER_CHANGED")
        require(all(getattr(self, name) is resource for name, resource in self.owned), "KERNEL_INSPECTION_VIEW_REPLACED")
        self.binding.files.check()
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(self.last <= now < self.end and self.wall <= wall
                and (wall - self.phase_wall).total_seconds() < 2, "KERNEL_INSPECTION_DEADLINE")
        if hasattr(self, "record_raw"):
            require(self.binding._record_raw == self.record_raw, "KERNEL_INSPECTION_RECORD_CHANGED")
            require(_time(self.scope["validFrom"]) <= wall < _time(self.scope["expiresAt"]), "KERNEL_INSPECTION_EXPIRED")
        self.last, self.wall = now, wall

    def _reader_tick(self, reader):
        try:
            self._tick()
            require(getattr(reader, "_inspection_owner", None) is self, "KERNEL_INSPECTION_READER_OWNER")
            retained = any(reader is resource for _, resource in self.owned)
            roots = self.roots
            native = (type(reader) is _KernelNativeReads and type(roots) is _KernelRootViews
                      and any(name == "roots" and resource is roots for name, resource in self.owned)
                      and getattr(roots, "native", None) is reader
                      and getattr(roots, "_native_original", None) is reader)
            require(retained or native, "KERNEL_INSPECTION_READER_UNOWNED")
            require(self.binding.authority == self.authority == self.owner.authority
                    and canonical_bytes(self.owner.binding) == self.session_raw,
                    "KERNEL_INSPECTION_AUTHORITY_CHANGED")
            require(self.authority_window[0] <= self.wall < self.authority_window[1],
                    "KERNEL_INSPECTION_AUTHORITY_EXPIRED")
            if self.epoch_ready:
                if self.epoch_sampling:
                    require(reader is self.roots or reader is self.policy or reader is self.roots.native,
                            "KERNEL_EPOCH_RECURSIVE_READER")
                else:
                    self.epoch_sampling = True
                    try:
                        require(self.roots._reader_mounts() is None, "KERNEL_ROOT_MOUNT_CHECK_RESULT")
                        require(self.policy._reader_epoch() is None, "KERNEL_EPOCH_CHECK_RESULT")
                        require(self.roots._reader_mounts() is None, "KERNEL_ROOT_MOUNT_CHECK_RESULT")
                    finally:
                        self.epoch_sampling = False
        except BaseException:
            # Unwind the reader's own acquired resources before the outer
            # phase closes its owners. Never close a still-returning FD here.
            self.failed = True
            raise

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "KERNEL_INSPECTION_UNAVAILABLE")
        self.busy = True
        self.end = min(time.monotonic() + 2, self.deadline)
        self.phase_wall = require_time(utc_now(), "now")
        try:
            self._tick()
            self.binding.check()
            self._tick()
            yield
            self._tick()
            self.binding.check()
            self._tick()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass
            raise
        finally:
            self.busy = False

    def _own(self, name, kind, *args):
        self._tick()
        resource = object.__new__(kind)
        resource._inspection_owner = self
        setattr(self, name, resource)
        self.owned.append((name, resource))  # retain before constructor can fail
        try:
            resource.__init__(*args)
        finally:
            self._tick()

    def _checked(self, resource):
        self._tick()
        try:
            require(resource.check() is None, "KERNEL_INSPECTION_CHECK_RESULT")
        finally:
            self._tick()

    def _policy_check(self):
        self._checked(self.policy)

    def _observe(self):
        # Fresh active policy surrounds the combined component observations.
        # These brackets detect drift, not an in-between change/ABA exclusion.
        self._policy_check()
        for resource in (self.roots, self.process, self.code, self.mappings, self.cgroup, self.filters):
            self._checked(resource)
            self._policy_check()
        self._checked(self.roots)

    def check(self):
        with self._phase():
            self._observe()

    def close(self):
        if not self.closed:
            self.closed = True
            while self.owned:
                name, resource = self.owned.pop()
                if getattr(self, name) is resource:
                    setattr(self, name, None)
                try:
                    # Existing readers validate arguments before setting closed;
                    # no descriptor exists before that initialization boundary.
                    if hasattr(resource, "closed"):
                        resource.close()
                    elif name == "roots" and hasattr(resource, "native"):
                        resource.native.close()
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _KernelObserverInspection(_KernelSelfInspection):
    """Fixed observer-role reader composition, not an execution permit.

    Borrows only the original installed server binding and observer channel.
    Owns its own seven kernel/code readers. No caller role, PID, record, FD or
    containment callback is accepted. Broker/fleet qualification is separate.
    """
    def __init__(self, peer):
        self.owned = []
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        self.epoch_ready = self.epoch_sampling = False
        for name in ("roots", "policy", "process", "code", "mappings", "cgroup", "filters"):
            setattr(self, name, None)
        try:
            require(type(self) is _KernelObserverInspection and type(peer) is _Observer,
                    "KERNEL_OBSERVER_OWNER")
            self.peer, self.owner = peer, peer.owner
            require(type(self.owner) is NativeProxyServer and self.owner.observer is peer
                    and peer.inspection is self, "KERNEL_OBSERVER_OWNER")
            self.owner._owner_check()
            self.binding, self.server_inspection = self.owner.qualification_binding, self.owner.self_inspection
            require(type(self.binding) is _ServerQualificationBinding and self.binding.owner is self.owner
                    and type(self.server_inspection) is _KernelSelfInspection
                    and self.server_inspection.owner is self.owner, "KERNEL_OBSERVER_BINDING")
            self.deadline = self.owner.deadline
            self.last, self.wall = time.monotonic(), require_time(utc_now(), "now")
            require(self.last < self.deadline <= self.last + 900, "KERNEL_INSPECTION_LIFETIME")
            self.socket = peer._socket_original
            self.peer_pins = (peer._socket_fd, peer._socket_pin, peer._pidfd_original,
                peer._pidfd_pin, peer._peer_original, peer._process_original,
                peer.parent, peer.socket_identity)
            with self._phase():
                record = self.binding.record
                self.authority = self.binding.authority
                self.session_raw = canonical_bytes(self.owner.binding)
                self.authority_window = (_time(self.owner.binding["notBefore"]), _time(self.owner.binding["notAfter"]))
                self.record_raw, self.scope = canonical_bytes(record), record["scope"]
                self.role = record["roles"]["OBSERVER"]
                require(self.peer_pins[4][1:] == (self.role["uid"], self.role["gid"])
                        and self.role["executable"] == OBSERVER and self.role["interpreterPath"] is None,
                        "KERNEL_OBSERVER_ROLE")
                self._own("roots", _KernelRootViews)
                self._own("policy", _KernelPolicyView, self.roots, record["host"], record["selinux"])
                require(self.policy._retain_epoch() is None, "KERNEL_EPOCH_CHECK_RESULT")
                self.epoch_ready = True
                self._policy_check()
                self._own("process", _KernelProcessView, self.roots, self.peer_pins[4][0], "OBSERVER", self.role)
                self._process_binding()
                self._policy_check()
                self._tick()
                page_size = os.sysconf("SC_PAGESIZE")
                self._tick()
                require(type(page_size) is int and page_size in (4096, 16384, 65536), "KERNEL_INSPECTION_PAGE_SIZE")
                self._own("code", _KernelCodeFiles, self.roots, record["files"], page_size)
                self._policy_check()
                code_pins = {k: self.role[k] for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")}
                self._own("mappings", _KernelProcessCode, self.process, self.code, code_pins)
                self._policy_check()
                self._own("cgroup", _KernelCgroupView, self.process, self.role["cgroup"])
                self._policy_check()
                self._own("filters", _KernelBpfView, self.cgroup, self.role["bpfPrograms"])
                self._observe()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass
            raise

    def _clock_and_owner(self):
        require(type(self) is _KernelObserverInspection and not self.closed and not self.failed and self.busy,
                "KERNEL_OBSERVER_UNAVAILABLE")
        self.owner._owner_check()
        peer = self.peer
        require(self.owner.observer is peer and peer.owner is self.owner and peer.inspection is self
                and not peer.closed and not peer.failed and peer.busy and peer.deadline == self.deadline
                and self.owner.qualification_binding is self.binding and self.binding.owner is self.owner
                and not self.binding.closed and not self.binding.poisoned
                and self.owner.files is self.binding.files and self.owner.deadline == self.deadline
                and self.owner.self_inspection is self.server_inspection
                and not self.server_inspection.closed and not self.server_inspection.failed,
                "KERNEL_OBSERVER_OWNER_CHANGED")
        require(all(getattr(self, name) is resource for name, resource in self.owned), "KERNEL_INSPECTION_VIEW_REPLACED")
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(self.last <= now < min(self.end, peer.end) and self.wall <= wall
                and 0 <= (wall - self.phase_wall).total_seconds() < 2,
                "KERNEL_OBSERVER_DEADLINE")
        if hasattr(self, "record_raw"):
            require(self.binding._record_raw == self.record_raw, "KERNEL_INSPECTION_RECORD_CHANGED")
            require(_time(self.scope["validFrom"]) <= wall < _time(self.scope["expiresAt"]), "KERNEL_INSPECTION_EXPIRED")
        self.last, self.wall = now, wall

    def _tick(self):
        # Deliberately no peer.check/_base_check: that would recurse into the
        # inspector or observer transport. These are original-channel queries.
        self._clock_and_owner()
        peer = self.peer
        socket_fd, socket_pin, pidfd, pidfd_pin, credentials_pin, process_pin, parent, path_pin = self.peer_pins
        require(peer.sock is peer._socket_original is self.socket and peer.pidfd == pidfd
                and (peer._socket_fd, peer._socket_pin, peer._pidfd_original, peer._pidfd_pin,
                     peer._peer_original, peer._process_original, peer.parent, peer.socket_identity) == self.peer_pins
                and peer.peer == credentials_pin and _Observer._process_pin(peer.identity) == process_pin,
                "KERNEL_OBSERVER_PEER_SUBSTITUTED")
        try:
            self.binding.files.check()
            require(self.socket.fileno() == socket_fd and _Observer._fd_pin(socket_fd) == socket_pin
                    and _Observer._fd_pin(pidfd) == pidfd_pin and not os.get_inheritable(socket_fd)
                    and not os.get_inheritable(pidfd), "KERNEL_OBSERVER_DESCRIPTOR_CHANGED")
            require(struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == credentials_pin
                    and select.select([pidfd], [], [pidfd], 0) == ([], [], [])
                    and _custody_identity(os.stat("policy-observer.sock", dir_fd=parent, follow_symlinks=False)) == path_pin,
                    "KERNEL_OBSERVER_PEER_CHANGED")
        finally:
            self._clock_and_owner()
            self.binding.files.check()
            self._clock_and_owner()

    def _process_binding(self):
        # Join the independently retained proc reader to the process originally
        # observed on this socket, not merely a matching PID/role record.
        self._tick()
        value = self.process.original
        actual = (value["pid"], value["startTicks"], value["parent"], value["uid"], value["gid"],
            value["capabilities"], value["seccompMode"], value["noNewPrivs"], self.process.cgroup.decode("ascii"),
            tuple(sorted(zip(("user", "mnt", "pid", "net"), self.process.pin[3]))))
        require(actual == self.peer_pins[5], "KERNEL_OBSERVER_PROCESS_CHANGED")

    def _observe(self):
        super()._observe()
        self._process_binding()


class _KernelBrokerInspection(_KernelSelfInspection):
    """Fixed broker-role reader composition, not an execution permit.

    Borrows only the original installed server binding and broker channel.
    Owns its own seven kernel/code readers. No caller role, PID, record, FD or
    containment callback is accepted. Broker execution/fencing is separate.
    """
    def __init__(self, peer):
        self.owned = []
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        self.epoch_ready = self.epoch_sampling = False
        for name in ("roots", "policy", "process", "code", "mappings", "cgroup", "filters"):
            setattr(self, name, None)
        try:
            require(type(self) is _KernelBrokerInspection and type(peer) is _Broker,
                    "KERNEL_BROKER_OWNER")
            self.peer, self.owner = peer, peer.owner
            require(type(self.owner) is NativeProxyServer and self.owner.broker is peer
                    and self.owner._broker_original is peer and peer.inspection is self, "KERNEL_BROKER_OWNER")
            self.owner._owner_check()
            self.binding, self.server_inspection = self.owner.qualification_binding, self.owner.self_inspection
            require(type(self.binding) is _ServerQualificationBinding and self.binding.owner is self.owner
                    and type(self.server_inspection) is _KernelSelfInspection
                    and self.server_inspection.owner is self.owner, "KERNEL_BROKER_BINDING")
            self.deadline = self.owner.deadline
            self.last, self.wall = time.monotonic(), require_time(utc_now(), "now")
            require(self.last < self.deadline <= self.last + 900, "KERNEL_INSPECTION_LIFETIME")
            self.socket = peer._socket_original
            self.peer_pins = (peer._socket_fd, peer._socket_pin, peer._pidfd_original,
                peer._pidfd_pin, peer._peer_original, peer._process_original,
                peer.parent, peer.socket_identity)
            with self._phase():
                record = self.binding.record
                self.authority = self.binding.authority
                self.session_raw = canonical_bytes(self.owner.binding)
                self.authority_window = (_time(self.owner.binding["notBefore"]), _time(self.owner.binding["notAfter"]))
                self.record_raw, self.scope = canonical_bytes(record), record["scope"]
                self.role = record["roles"]["BROKER"]
                require(self.peer_pins[4][1:] == (self.role["uid"], self.role["gid"])
                        and self.role["executable"] == BROKER and self.role["interpreterPath"] is None,
                        "KERNEL_BROKER_ROLE")
                self._own("roots", _KernelRootViews)
                self._own("policy", _KernelPolicyView, self.roots, record["host"], record["selinux"])
                require(self.policy._retain_epoch() is None, "KERNEL_EPOCH_CHECK_RESULT")
                self.epoch_ready = True
                self._policy_check()
                self._own("process", _KernelProcessView, self.roots, self.peer_pins[4][0], "BROKER", self.role)
                self._process_binding()
                self._policy_check()
                self._tick()
                page_size = os.sysconf("SC_PAGESIZE")
                self._tick()
                require(type(page_size) is int and page_size in (4096, 16384, 65536), "KERNEL_INSPECTION_PAGE_SIZE")
                self._own("code", _KernelCodeFiles, self.roots, record["files"], page_size)
                self._policy_check()
                code_pins = {k: self.role[k] for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")}
                self._own("mappings", _KernelProcessCode, self.process, self.code, code_pins)
                self._policy_check()
                self._own("cgroup", _KernelCgroupView, self.process, self.role["cgroup"])
                self._policy_check()
                self._own("filters", _KernelBpfView, self.cgroup, self.role["bpfPrograms"])
                self._observe()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass
            raise

    def _clock_and_owner(self):
        require(type(self) is _KernelBrokerInspection and not self.closed and not self.failed and self.busy,
                "KERNEL_BROKER_UNAVAILABLE")
        self.owner._owner_check()
        peer = self.peer
        require(self.owner.broker is peer and self.owner._broker_original is peer and peer.owner is self.owner and peer.inspection is self
                and not peer.closed and not peer.failed and peer.busy and peer.deadline == self.deadline
                and self.owner.qualification_binding is self.binding and self.binding.owner is self.owner
                and not self.binding.closed and not self.binding.poisoned
                and self.owner.files is self.binding.files and self.owner.deadline == self.deadline
                and self.owner.self_inspection is self.server_inspection
                and not self.server_inspection.closed and not self.server_inspection.failed,
                "KERNEL_BROKER_OWNER_CHANGED")
        require(all(getattr(self, name) is resource for name, resource in self.owned), "KERNEL_INSPECTION_VIEW_REPLACED")
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(self.last <= now < min(self.end, peer.end) and self.wall <= wall
                and 0 <= (wall - self.phase_wall).total_seconds() < 2,
                "KERNEL_BROKER_DEADLINE")
        if hasattr(self, "record_raw"):
            require(self.binding._record_raw == self.record_raw, "KERNEL_INSPECTION_RECORD_CHANGED")
            require(_time(self.scope["validFrom"]) <= wall < _time(self.scope["expiresAt"]), "KERNEL_INSPECTION_EXPIRED")
        self.last, self.wall = now, wall

    def _tick(self):
        # Deliberately no peer.check/_base_check: that would recurse into the
        # inspector or broker transport. These are original-channel queries.
        self._clock_and_owner()
        peer = self.peer
        socket_fd, socket_pin, pidfd, pidfd_pin, credentials_pin, process_pin, parent, path_pin = self.peer_pins
        require(peer.sock is peer._socket_original is self.socket and peer.pidfd == pidfd
                and (peer._socket_fd, peer._socket_pin, peer._pidfd_original, peer._pidfd_pin,
                     peer._peer_original, peer._process_original, peer.parent, peer.socket_identity) == self.peer_pins
                and peer.peer == credentials_pin and _Broker._process_pin(peer.identity) == process_pin,
                "KERNEL_BROKER_PEER_SUBSTITUTED")
        try:
            self.binding.files.check()
            require(self.socket.fileno() == socket_fd and _Broker._fd_pin(socket_fd) == socket_pin
                    and _Broker._fd_pin(pidfd) == pidfd_pin and not os.get_inheritable(socket_fd)
                    and not os.get_inheritable(pidfd), "KERNEL_BROKER_DESCRIPTOR_CHANGED")
            require(struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == credentials_pin
                    and select.select([pidfd], [], [pidfd], 0) == ([], [], [])
                    and _custody_identity(os.stat("capacity-broker.sock", dir_fd=parent, follow_symlinks=False)) == path_pin,
                    "KERNEL_BROKER_PEER_CHANGED")
        finally:
            self._clock_and_owner()
            self.binding.files.check()
            self._clock_and_owner()

    def _process_binding(self):
        # Join the independently retained proc reader to the process originally
        # observed on this socket, not merely a matching PID/role record.
        self._tick()
        value = self.process.original
        actual = (value["pid"], value["startTicks"], value["parent"], value["uid"], value["gid"],
            value["capabilities"], value["seccompMode"], value["noNewPrivs"], self.process.cgroup.decode("ascii"),
            tuple(sorted(zip(("user", "mnt", "pid", "net"), self.process.pin[3]))))
        require(actual == self.peer_pins[5], "KERNEL_BROKER_PROCESS_CHANGED")

    def _observe(self):
        super()._observe()
        self._process_binding()


class _KernelQualification:
    """One installed-server qualification lifetime, never a worker grant.

    Owns the fixed self-reader composition and borrows the two original peer
    channels. A channel retains/qualifies its own socket, pidfd and role readers;
    this owner joins those lifetimes without closing their borrowed descriptors.
    No worker is inspected or started here. Records remain expected values,
    while the fixed native readers provide the actual kernel/code observations.
    """
    def __init__(self, owner):
        self.owner = owner
        self.closed = self.failed = self._self_checking = self._peer_checking = False
        self.cleanup_failure = None
        self._self_original = None
        self._peers = {}
        try:
            require(type(self) is _KernelQualification and type(owner) is NativeProxyServer,
                    "KERNEL_QUALIFICATION_OWNER")
            owner._owner_check()
            require(owner.qualification is owner._qualification_original is self
                    and owner.self_inspection is None
                    and type(owner.qualification_binding) is _ServerQualificationBinding
                    and owner.qualification_binding.owner is owner,
                    "KERNEL_QUALIFICATION_OWNER")
            self.binding, self.files, self.deadline = owner.qualification_binding, owner.files, owner.deadline
            self.pid, self.thread = owner.pid, owner.thread
            self.last, self.wall = time.monotonic(), require_time(utc_now(), "now")
            self._self_original = owner.self_inspection = object.__new__(_KernelSelfInspection)
            # Retain before construction: partial readers still have exactly
            # one close owner if an OS read or its post-I/O guard refuses.
            _KernelSelfInspection.__init__(self._self_original, owner)
            self._guard()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass  # keep the original refusal and sticky close uncertainty
            raise

    def _guard(self):
        require(type(self) is _KernelQualification and not self.closed and not self.failed,
                "KERNEL_QUALIFICATION_UNAVAILABLE")
        owner = self.owner
        require(type(owner) is NativeProxyServer, "KERNEL_QUALIFICATION_OWNER")
        owner._owner_check()
        require(owner.qualification is owner._qualification_original is self
                and (owner.pid, owner.thread, owner.deadline) == (self.pid, self.thread, self.deadline)
                and owner.qualification_binding is self.binding and owner.files is self.files
                and self.binding.owner is owner and self.binding.files is self.files
                and not self.binding.closed and not self.binding.poisoned
                and type(self._self_original) is _KernelSelfInspection
                and owner.self_inspection is self._self_original
                and self._self_original.owner is owner
                and not self._self_original.closed and not self._self_original.failed,
                "KERNEL_QUALIFICATION_OWNER_CHANGED")
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(self.last <= now < self.deadline and self.wall <= wall,
                "KERNEL_QUALIFICATION_CLOCK_OR_EXPIRY")
        self.last, self.wall = now, wall
        for role, pin in self._peers.items():
            require(self._peer_pin(role, pin[0]) == pin, "KERNEL_QUALIFICATION_PEER_REPLACED")

    def check_self(self):
        try:
            require(not self._self_checking, "KERNEL_QUALIFICATION_REENTRANT")
            self._self_checking = True
            self._guard()
            before, wall = self.last, self.wall
            require(_KernelSelfInspection.check(self._self_original) is None,
                    "KERNEL_QUALIFICATION_CHECK_RESULT")
            self._guard()
            require(self.last < before + 2 and (self.wall - wall).total_seconds() < 2,
                    "KERNEL_QUALIFICATION_DEADLINE")
        except BaseException:
            self.failed = True
            raise
        finally:
            self._self_checking = False

    def _peer_pin(self, role, peer):
        owner = self.owner
        if role == "OBSERVER":
            require(type(peer) is _Observer and owner.observer is peer,
                    "KERNEL_QUALIFICATION_PEER_OWNER")
            kind = _KernelObserverInspection
        elif role == "BROKER":
            require(type(peer) is _Broker and owner.broker is owner._broker_original is peer,
                    "KERNEL_QUALIFICATION_PEER_OWNER")
            kind = _KernelBrokerInspection
        else:
            require(False, "KERNEL_QUALIFICATION_ROLE")
        require(peer.owner is owner and not peer.closed and not peer.failed
                and peer.deadline == self.deadline and type(peer.inspection) is kind
                and peer.inspection is peer._inspection_original
                and peer.inspection.peer is peer and peer.inspection.owner is owner
                and peer.inspection.binding is self.binding
                and peer.inspection.server_inspection is self._self_original
                and not peer.inspection.closed and not peer.inspection.failed,
                "KERNEL_QUALIFICATION_PEER_CHANGED")
        return (peer, peer._inspection_original, peer._socket_original,
                peer._socket_fd, peer._socket_pin, peer._pidfd_original,
                peer._pidfd_pin, peer._peer_original, peer._process_original,
                peer.parent, peer.socket_identity)

    def check_peer(self, role, retained_peer):
        try:
            require(type(role) is str and not self._peer_checking and not self._self_checking,
                    "KERNEL_QUALIFICATION_REENTRANT")
            self._peer_checking = True
            self._guard()
            before, wall = self.last, self.wall
            pin = self._peer_pin(role, retained_peer)
            if role not in self._peers:
                self._peers[role] = pin  # no replacement/re-enrollment, even on failure
            require(self._peers[role] == pin, "KERNEL_QUALIFICATION_PEER_REPLACED")
            # Class dispatch prevents an instance callback from granting a
            # qualification. Native role readers run within the channel's
            # original two-second phase, including all post-I/O custody checks.
            checker = _Observer.check if role == "OBSERVER" else _Broker.check
            require(checker(retained_peer) is None, "KERNEL_QUALIFICATION_CHECK_RESULT")
            self._guard()
            require(self._peer_pin(role, retained_peer) == pin,
                    "KERNEL_QUALIFICATION_PEER_REPLACED")
            require(self.last < before + 2 and (self.wall - wall).total_seconds() < 2,
                    "KERNEL_QUALIFICATION_DEADLINE")
        except BaseException:
            self.failed = True
            raise
        finally:
            self._peer_checking = False

    def close(self):
        if not self.closed:
            self.closed = True
            resource, self._self_original = self._self_original, None
            # Peer channels close their own role readers, sockets and pidfds.
            # Do not close a caller-substituted owner attribute or borrowed file.
            if resource is not None and hasattr(resource, "closed"):
                try:
                    _KernelSelfInspection.close(resource)
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _Observer:
    def __init__(self, owner):
        self.owner, self.sock, self.pidfd, self.previous = owner, None, None, None
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        self._socket_original = self._pidfd_original = None
        self._socket_fd = self._socket_pin = self._pidfd_pin = None
        self._previous_raw = None
        self.inspection = self._inspection_original = None
        self.deadline = owner.deadline
        self.last_wall, self.last_mono = None, time.monotonic()
        try:
            with self._phase():
                self._connect()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass  # retain the original refusal and sticky cleanup failure
            raise

    def _connect(self):
        owner = self.owner
        value, manifest_digest, executable_digest = self._io(_manifest, owner.files, OBSERVER_MANIFEST, OBSERVER)
        require(owner.observation_binding["observer"] == {"manifestDigest": manifest_digest,
            "executableDigest": executable_digest}, "OBSERVER_ENROLLMENT_MISMATCH")
        self.parent = self._io(owner.files._open, OBSERVER_SOCKET.rsplit("/", 1)[0], True, 0o700)
        info = self._io(os.stat, "policy-observer.sock", dir_fd=self.parent, follow_symlinks=False)
        self.socket_identity = _custody_identity(info)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600, "OBSERVER_SOCKET_CUSTODY")
        # Retain newly acquired resources BEFORE any post-I/O guard can fail.
        try:
            self.sock = self._socket_original = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._socket_fd = self.sock.fileno()
            self._socket_pin = self._fd_pin(self._socket_fd)
        finally:
            self._guard()
        self._io(self.sock.set_inheritable, False)
        self._io(self.sock.setsockopt, socket.SOL_SOCKET, 16, 1)
        self._prepare_wait()
        try:
            self.sock.connect(OBSERVER_SOCKET)
        finally:
            self._guard()
        self.peer = struct.unpack("3i", self._io(self.sock.getsockopt, socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(self.peer[0] > 1 and self.peer[1:] == (0, 0), "OBSERVER_PEER_INVALID")
        self._peer_original = self.peer
        self.identity = self._io(process_identity, self.peer[0])
        self._process_original = self._process_pin(self.identity)
        try:
            self.pidfd = self._pidfd_original = os.pidfd_open(self.peer[0], 0)
            self._pidfd_pin = self._fd_pin(self.pidfd)
        finally:
            self._guard()
        require(owner.files.raw[OBSERVER].startswith(b"\x7fELF"), "OBSERVER_NATIVE_ELF_REQUIRED")
        self.inspection = self._inspection_original = object.__new__(_KernelObserverInspection)
        self.inspection.__init__(self)
        self._check_peer()

    @staticmethod
    def _fd_pin(fd):
        require(type(fd) is int and 2 < fd < 1048576, "OBSERVER_DESCRIPTOR_INVALID")
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    @staticmethod
    def _process_pin(value):
        return (value["pid"], value["start"], value["parent"], tuple(value["uid"]), tuple(value["gid"]),
                tuple(value["capabilities"]), value["seccomp"], value["noNewPrivs"], value["cgroup"],
                tuple(sorted(value["namespaces"].items())))

    def _guard(self):
        require(type(self) is _Observer and not self.closed and not self.failed and self.busy
                and type(self.owner) is NativeProxyServer and self.owner.observer is self
                and self.owner.deadline == self.deadline, "OBSERVER_OWNER_CHANGED")
        self.owner._base_check()  # no observer I/O or credential acquisition
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(self.last_mono <= now < self.end
                and (self.last_wall is None or self.last_wall <= wall)
                and 0 <= (wall - self.phase_wall).total_seconds() < 2, "OBSERVER_CLOCK_OR_DEADLINE")
        self.last_mono, self.last_wall = now, wall

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "OBSERVER_UNAVAILABLE")
        self.busy = True
        self.end = min(self.deadline, time.monotonic() + 2)
        self.phase_wall = require_time(utc_now(), "now")
        try:
            self._guard()
            yield
            self._guard()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _io(self, function, *args, **kwargs):
        self._guard()
        try:
            return function(*args, **kwargs)
        finally:
            self._guard()  # unsuccessful I/O never skips retained authority

    def _prepare_wait(self):
        # Calculate the relative socket timeout AFTER expensive qualification
        # and authority checks. No further inspector runs before the I/O starts.
        self._guard()
        before = time.monotonic()
        require(self.last_mono <= before < self.end, "OBSERVER_CLOCK_OR_DEADLINE")
        try:
            self.sock.settimeout(self.end - before)
        except BaseException:
            self._guard()
            raise
        # settimeout itself is nonblocking, but still reject late/rollback OS
        # returns before starting a connection, send or receive.
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(before <= now < self.end and self.last_wall <= wall
                and 0 <= (wall - self.phase_wall).total_seconds() < 2, "OBSERVER_CLOCK_OR_DEADLINE")
        self.last_mono, self.last_wall = now, wall

    def _check_peer(self):
        require(self.sock is self._socket_original and self.pidfd == self._pidfd_original
                and self.peer == self._peer_original and self._process_pin(self.identity) == self._process_original,
                "OBSERVER_RETAINED_PEER_CHANGED")
        require(self._io(self.sock.fileno) == self._socket_fd
                and self._io(self._fd_pin, self._socket_fd) == self._socket_pin
                and self._io(self._fd_pin, self.pidfd) == self._pidfd_pin
                and not self._io(os.get_inheritable, self._socket_fd)
                and not self._io(os.get_inheritable, self.pidfd), "OBSERVER_DESCRIPTOR_CHANGED")
        require(struct.unpack("3i", self._io(self.sock.getsockopt, socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                == self._peer_original, "OBSERVER_PEER_CHANGED")
        require(_custody_identity(self._io(os.stat, "policy-observer.sock", dir_fd=self.parent, follow_symlinks=False))
                == self.socket_identity and self._io(select.select, [self.pidfd], [], [self.pidfd], 0) == ([], [], [])
                and self._process_pin(self._io(process_identity, self.peer[0])) == self._process_original,
                "OBSERVER_PEER_CHANGED")
        actual = self._io(os.stat, f"/proc/{self.peer[0]}/exe")
        expected = self.owner.files.rows[OBSERVER][3]
        require((actual.st_dev, actual.st_ino) == expected[:2], "OBSERVER_EXECUTABLE_CHANGED")
        require(type(self.inspection) is _KernelObserverInspection
                and self.inspection is self._inspection_original and self.inspection.peer is self,
                "OBSERVER_INSPECTION_CHANGED")
        require(self._io(self.inspection.check) is None, "OBSERVER_CONTAINMENT_UNAVAILABLE")
        require(self._process_pin(self.identity) == self._process_original, "OBSERVER_RETAINED_PEER_CHANGED")

    def check(self):
        with self._phase():
            self._check_peer()

    def observe(self):
        with self._phase():
            self._check_peer()
            require((None if self.previous is None else canonical_bytes(self.previous)) == self._previous_raw,
                    "OBSERVER_HISTORY_CHANGED")
            previous = None if self._previous_raw is None else document(self._previous_raw, 65536)
            request = {"schemaVersion": "planeon.internal.policy-observation-request/v1", "operation": "OBSERVE_POLICY",
                "bindingDigest": canonical_digest(self.owner.observation_binding), "runNonce": self.owner.envelope["nonce"],
                "challenge": self._io(os.urandom, 32).hex(), "sequence": 1 if previous is None else previous["sequence"] + 1,
                "previousObservationDigest": ZERO if previous is None else canonical_digest(previous)}
            encoded = canonical_bytes(request)
            self._check_peer()
            self._prepare_wait()
            try:
                require(self.sock.send(encoded) == len(encoded), "OBSERVER_SEND_AMBIGUOUS")
            finally:
                self._check_peer()  # no replay, including timeout or partial send
            self._check_peer()
            self._prepare_wait()
            try:
                raw, ancillary, flags, _ = self.sock.recvmsg(65537, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4))
                # Drain/reject received rights even if the subsequent custody
                # guard fails. Untrusted ancillary FDs never become owned peers.
                require(credentials(ancillary, flags) == self._peer_original, "OBSERVER_MESSAGE_PEER")
            finally:
                self._check_peer()
            observed = validate_messages(self.owner.observation_binding, request, raw, self.owner.profile,
                                         require_time(utc_now(), "now").strftime("%Y-%m-%dT%H:%M:%SZ"), previous)
            self._guard()
            self._previous_raw = canonical_bytes(observed)
            self.previous = document(self._previous_raw, 65536)
            return document(self._previous_raw, 65536)  # no mutable history alias

    def close(self):
        if not self.closed:
            self.closed = True
            inspection, self._inspection_original, self.inspection = self._inspection_original, None, None
            if inspection is not None:
                try:
                    inspection.close()  # borrowed socket/files remain separately owned
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
            sock, self._socket_original, self.sock = self._socket_original, None, None
            pidfd, self._pidfd_original, self.pidfd = self._pidfd_original, None, None
            for resource, fd, pin in ((pidfd, pidfd, self._pidfd_pin), (sock, self._socket_fd, self._socket_pin)):
                if resource is None:
                    continue
                try:
                    if pin is not None and self._fd_pin(fd) != pin:
                        require(False, "OBSERVER_CLOSE_FD_REUSED")
                    if resource is sock:
                        require(fd is None or sock.fileno() == fd, "OBSERVER_CLOSE_SOCKET_CHANGED")
                        sock.close()
                    else:
                        os.close(fd)
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
                    if resource is sock:
                        try:
                            sock.detach()  # no destructor close after uncertain identity/close
                        except BaseException:
                            pass  # preserve the first error; never retry close
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _Broker:
    """Fixed retained broker peer, never a local execution grant.

    Only the installed server constructs this channel. Bootstrap/check sends
    no frame. The separate begin phase sends only its internally bound DISPATCH;
    the broker alone owns workers. API effects use separate server-owned action
    objects and do not make a received broker frame an execution permit.
    """
    def __init__(self, owner):
        self.owner, self.sock, self.pidfd = owner, None, None
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        self._socket_original = self._pidfd_original = None
        self._socket_fd = self._socket_pin = self._pidfd_pin = None
        self.binding = owner.qualification_binding
        self._binding_raw = None
        self.inspection = self._inspection_original = None
        self.dispatch = self._dispatch_original = None
        self.events = self._events_original = None
        self.api = self._api_original = None
        self.intent = self._intent_original = None
        self.exchange = self._exchange_original = None
        self.created = self._created_original = None
        self.result = self._result_original = None
        self.retirement = self._retirement_original = None
        self.credential = self._credential_original = None
        self.get_action = self._get_action_original = None
        self.absence = self._absence_original = None
        self.last_get = self._last_get_original = None
        self.last_get_raw = self._last_get_raw_original = None
        self.delete_action = self._delete_action_original = None
        self.completion = self._completion_original = None
        self._attempted_cases = set()
        self.case_history, self.case_history_raw = (), b"[]"
        self.deadline = owner.deadline
        self.last_wall, self.last_mono = None, time.monotonic()
        try:
            with self._phase():
                self._connect()
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass  # retain the original refusal and sticky cleanup failure
            raise

    def _connect(self):
        owner = self.owner
        value, manifest_digest, executable_digest = self._io(_manifest, owner.files, BROKER_MANIFEST, BROKER)
        binding = self._io(getattr, self.binding, "broker_binding")
        require(binding["brokerManifestDigest"] == manifest_digest
                and binding["brokerExecutableDigest"] == executable_digest,
                "BROKER_ENROLLMENT_MISMATCH")
        self._binding_raw = canonical_bytes(binding)
        self.parent = self._io(owner.files._open, BROKER_SOCKET.rsplit("/", 1)[0], True, 0o700)
        info = self._io(os.stat, "capacity-broker.sock", dir_fd=self.parent, follow_symlinks=False)
        self.socket_identity = _custody_identity(info)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600, "BROKER_SOCKET_CUSTODY")
        # Retain newly acquired resources BEFORE any post-I/O guard can fail.
        try:
            self.sock = self._socket_original = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._socket_fd = self.sock.fileno()
            self._socket_pin = self._fd_pin(self._socket_fd)
        finally:
            self._guard()
        self._io(self.sock.set_inheritable, False)
        self._io(self.sock.setsockopt, socket.SOL_SOCKET, 16, 1)
        self._prepare_wait()
        try:
            self.sock.connect(BROKER_SOCKET)
        finally:
            self._guard()
        self.peer = struct.unpack("3i", self._io(self.sock.getsockopt, socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(self.peer[0] > 1 and self.peer[1:] == (0, 0), "BROKER_PEER_INVALID")
        self._peer_original = self.peer
        self.identity = self._io(process_identity, self.peer[0])
        self._process_original = self._process_pin(self.identity)
        try:
            self.pidfd = self._pidfd_original = os.pidfd_open(self.peer[0], 0)
            self._pidfd_pin = self._fd_pin(self.pidfd)
        finally:
            self._guard()
        require(owner.files.raw[BROKER].startswith(b"\x7fELF"), "BROKER_NATIVE_ELF_REQUIRED")
        self.inspection = self._inspection_original = object.__new__(_KernelBrokerInspection)
        self.inspection.__init__(self)
        self._check_peer()

    @staticmethod
    def _fd_pin(fd):
        require(type(fd) is int and 2 < fd < 1048576, "BROKER_DESCRIPTOR_INVALID")
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    @staticmethod
    def _process_pin(value):
        return (value["pid"], value["start"], value["parent"], tuple(value["uid"]), tuple(value["gid"]),
                tuple(value["capabilities"]), value["seccomp"], value["noNewPrivs"], value["cgroup"],
                tuple(sorted(value["namespaces"].items())))

    def _guard(self):
        require(type(self) is _Broker and not self.closed and not self.failed and self.busy
                and type(self.owner) is NativeProxyServer and self.owner.broker is self
                and self.owner._broker_original is self and self.owner.deadline == self.deadline
                and type(self.binding) is _ServerQualificationBinding
                and self.owner.qualification_binding is self.binding and self.binding.owner is self.owner,
                "BROKER_OWNER_CHANGED")
        require(type(self.case_history) is tuple and len(self.case_history) <= len(CASES)
                and all(type(raw) is bytes for raw in self.case_history)
                and canonical_bytes([byte_digest(raw) for raw in self.case_history]) == self.case_history_raw,
                "BROKER_CASE_HISTORY_CHANGED")
        self.owner._base_check()  # no broker/observer I/O or credential acquisition
        require(self.binding.check() is None, "BROKER_BINDING_CHECK_RESULT")
        require(self._binding_raw is None or self.binding._broker_raw == self._binding_raw,
                "BROKER_BINDING_CHANGED")
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(self.last_mono <= now < self.end
                and (self.last_wall is None or self.last_wall <= wall)
                and 0 <= (wall - self.phase_wall).total_seconds() < 2, "BROKER_CLOCK_OR_DEADLINE")
        self.last_mono, self.last_wall = now, wall

    @contextmanager
    def _phase(self):
        require(not self.closed and not self.failed and not self.busy, "BROKER_UNAVAILABLE")
        self.busy = True
        self.end = min(self.deadline, time.monotonic() + 2)
        self.phase_wall = require_time(utc_now(), "now")
        try:
            self._guard()
            yield
            self._guard()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def _io(self, function, *args, **kwargs):
        self._guard()
        try:
            return function(*args, **kwargs)
        finally:
            self._guard()  # unsuccessful I/O never skips retained authority

    def _prepare_wait(self):
        # Calculate the relative socket timeout AFTER expensive qualification
        # and authority checks. No further inspector runs before the I/O starts.
        self._guard()
        before = time.monotonic()
        require(self.last_mono <= before < self.end, "BROKER_CLOCK_OR_DEADLINE")
        try:
            self.sock.settimeout(self.end - before)
        except BaseException:
            self._guard()
            raise
        # settimeout itself is nonblocking, but still reject late/rollback OS
        # returns before starting a connection, send or receive.
        now, wall = time.monotonic(), require_time(utc_now(), "now")
        require(before <= now < self.end and self.last_wall <= wall
                and 0 <= (wall - self.phase_wall).total_seconds() < 2, "BROKER_CLOCK_OR_DEADLINE")
        self.last_mono, self.last_wall = now, wall

    def _check_peer(self):
        require(self.sock is self._socket_original and self.pidfd == self._pidfd_original
                and self.peer == self._peer_original and self._process_pin(self.identity) == self._process_original,
                "BROKER_RETAINED_PEER_CHANGED")
        require(self._io(self.sock.fileno) == self._socket_fd
                and self._io(self._fd_pin, self._socket_fd) == self._socket_pin
                and self._io(self._fd_pin, self.pidfd) == self._pidfd_pin
                and not self._io(os.get_inheritable, self._socket_fd)
                and not self._io(os.get_inheritable, self.pidfd), "BROKER_DESCRIPTOR_CHANGED")
        require(struct.unpack("3i", self._io(self.sock.getsockopt, socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                == self._peer_original, "BROKER_PEER_CHANGED")
        require(_custody_identity(self._io(os.stat, "capacity-broker.sock", dir_fd=self.parent, follow_symlinks=False))
                == self.socket_identity and self._io(select.select, [self.pidfd], [], [self.pidfd], 0) == ([], [], [])
                and self._process_pin(self._io(process_identity, self.peer[0])) == self._process_original,
                "BROKER_PEER_CHANGED")
        actual = self._io(os.stat, f"/proc/{self.peer[0]}/exe")
        expected = self.owner.files.rows[BROKER][3]
        require((actual.st_dev, actual.st_ino) == expected[:2], "BROKER_EXECUTABLE_CHANGED")
        require(type(self.inspection) is _KernelBrokerInspection
                and self.inspection is self._inspection_original and self.inspection.peer is self,
                "BROKER_INSPECTION_CHANGED")
        require(self._io(self.inspection.check) is None, "BROKER_CONTAINMENT_UNAVAILABLE")
        require(self._process_pin(self.identity) == self._process_original, "BROKER_RETAINED_PEER_CHANGED")

    def check(self):
        with self._phase():
            self._check_peer()

    def begin(self):
        # No caller request, observation, descriptor or backend. This does not
        # return a worker handle or permit: only the broker owns execution.
        try:
            with self._phase():
                require(self.dispatch is None and self._dispatch_original is None,
                        "BROKER_DISPATCH_ALREADY_OWNED")
                self.dispatch = self._dispatch_original = object.__new__(_BrokerStart)
                self.dispatch.__init__(self)
            self.dispatch.started = self.dispatch._started_raw
        except BaseException:
            if self._dispatch_original is not None:
                self._dispatch_original.failed = True
            try:
                self.close()  # peer loss is not an implicit retry or lease renewal
            except BaseException:
                pass  # sticky cleanup failure retained; preserve the first refusal
            raise

    def poll(self):
        """Receive one bounded event, or None for idle; never execute an action."""
        try:
            with self._phase():
                if self.events is None and self._events_original is None:
                    self.events = self._events_original = object.__new__(_BrokerEvents)
                    self.events.__init__(self)
                require(type(self.events) is _BrokerEvents and self.events is self._events_original,
                        "BROKER_EVENTS_OWNER_CHANGED")
                raw = self.events.receive()
            return raw  # publish only after the enclosing phase's last guard
        except BaseException:
            if self._events_original is not None:
                self._events_original.failed = True
            try:
                self.close()
            except BaseException:
                pass  # retained cleanup error is sticky; never reconnect/retry
            raise

    def prepare_api(self):
        """Authenticate one pending action's fixed API leg; send no HTTP/effect."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.api is self._api_original is None, "BROKER_API_ALREADY_ATTEMPTED")
            self.api = self._api_original = object.__new__(_BrokerApi)
            self.api.__init__(self)
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass  # original cleanup failure stays sticky; never reconnect
            raise

    def check_action_ownership(self):
        """Driver pre-credential check, not a substitute for per-I/O admission."""
        try:
            with self._phase():
                events = self.events
                require(type(events) is _BrokerEvents and events is self._events_original
                        and self.api is self._api_original is None, "BROKER_ACTION_PREFLIGHT_OWNER")
                _BrokerEvents._check(events)
                action = document(events.transcript.pending, 16384)
                require(type(action) is dict and set(action) == {"actionId", "verb", "manifestDigest"}
                        and action["verb"] in ("CREATE", "GET", "DELETE")
                        and action["manifestDigest"] in document(events.binding_raw)["caseResourceDigests"][events.start.operation],
                        "BROKER_ACTION_PREFLIGHT_SCOPE")
                if action["verb"] == "CREATE":
                    require(type(self.intent) is _BrokerIntent and self.intent is self._intent_original
                            and self.intent.committed and not self.intent.failed, "BROKER_CREATE_INTENT_REQUIRED")
                    _BrokerIntent._check(self.intent)
                else:
                    manifests = [row["manifest"] for row in self.owner.profile["resources"]
                                 if row["manifestDigest"] == action["manifestDigest"]]
                    require(len(manifests) == 1, "BROKER_GET_MANIFEST_REQUIRED")
                    manifest = manifests[0]
                    states, _, _ = parse_reservations(events.start.ledger_raw)
                    current = states[(self.owner.envelope["tenantId"], self.owner.envelope["nonce"])]
                    key = (manifest["apiVersion"], manifest["kind"], manifest["metadata"]["namespace"],
                           manifest["metadata"]["name"])
                    row = current.get("resources", {}).get(key)
                    require(current["held"] and current["current"] == events.start.operation
                            and row is not None and row["state"] == "CREATED"
                            and row["operation"] == events.start.operation
                            and row["manifestDigest"] == action["manifestDigest"]
                            and type(row["uid"]) is str and row["uid"]
                            and row["actionId"] < action["actionId"], "BROKER_GET_CREATED_UID_REQUIRED")
                    if action["verb"] == "DELETE":
                        prior = self.last_get
                        require(type(prior) is _BrokerGetAction and prior is self._last_get_original
                                and prior.events is events and prior.start is events.start
                                and prior.retired and prior.advanced and prior.sent and not prior.failed
                                and prior.outcome == "PRESENT" and prior.deadline == self.deadline
                                and self.last_get_raw == self._last_get_raw_original == prior._cleanup_snapshot()
                                and events.handoffs and document(events.handoffs[-1])["verb"] == "GET"
                                and document(events.handoffs[-1])["actionId"] == document(prior.action_raw)["actionId"]
                                and document(prior.action_raw)["manifestDigest"] == action["manifestDigest"]
                                and prior.observed_mono <= time.monotonic() < min(self.deadline, prior.observed_mono + 5),
                                "BROKER_DELETE_FRESH_GET_REQUIRED")
                        require(not any(document(raw)["verb"] == "DELETE"
                            and document(raw)["manifestDigest"] == action["manifestDigest"] for raw in events.handoffs),
                            "BROKER_DELETE_ALREADY_ATTEMPTED")
                        validate_observed_manifest(prior.response_raw, canonical_bytes(manifest), row["uid"])
                _BrokerEvents._check(events)
        except BaseException:
            self.failed = True
            try:
                _Broker.close(self)
            except BaseException:
                pass  # no credential, API socket or corrective deletion is acquired
            raise

    def record_create_intent(self):
        """Retain this pending CREATE's durable intent; no caller data or effect."""
        try:
            with self._phase():
                require(self.intent is self._intent_original is None, "BROKER_INTENT_ALREADY_ATTEMPTED")
                self.intent = self._intent_original = object.__new__(_BrokerIntent)
                self.intent.__init__(self)
            require(type(self.intent) is _BrokerIntent and self.intent is self._intent_original
                    and not self.intent.failed and not self.intent.log.poisoned
                    and self.intent.start.ledger_raw == self.intent.after,
                    "BROKER_INTENT_PUBLICATION_CHANGED")
            self.intent.committed = True  # only after the enclosing phase guard
        except BaseException:
            self.failed = True
            if self._intent_original is not None:
                self._intent_original._poison()
            try:
                self.close()
            except BaseException:
                pass  # retained journal is never rolled back; keep first refusal
            raise

    def exchange_api_create(self):
        """One original pending CREATE exchange; no caller bytes or result grant."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.exchange is self._exchange_original is None,
                    "BROKER_EXCHANGE_ALREADY_ATTEMPTED")
            self.exchange = self._exchange_original = object.__new__(_BrokerCreateExchange)
            self.exchange.__init__(self)
            require(type(self.exchange) is _BrokerCreateExchange
                    and self.exchange is self._exchange_original and not self.exchange.failed
                    and self.exchange.response_raw is not None, "BROKER_EXCHANGE_PUBLICATION_CHANGED")
            self.exchange.complete = True  # data only; CREATED still needs durable accounting
        except BaseException:
            self.failed = True
            if self._exchange_original is not None:
                self._exchange_original.failed = True
            if self._intent_original is not None:
                self._intent_original._poison()
            try:
                self.close()
            except BaseException:
                pass  # intent/possible effect stays held, never retry or adopt
            raise

    def record_api_created(self):
        """Persist the original returned identity; no caller data or broker reply."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.created is self._created_original is None,
                    "BROKER_CREATED_ALREADY_ATTEMPTED")
            self.created = self._created_original = object.__new__(_BrokerCreated)
            self.created.__init__(self)
            require(type(self.created) is _BrokerCreated and self.created is self._created_original
                    and not self.created.failed and self.created.advanced,
                    "BROKER_CREATED_PUBLICATION_CHANGED")
            self.created._state_check()
            self.created.committed = True  # durable accounting only; action stays pending
        except BaseException:
            self.failed = True
            if self._created_original is not None:
                _BrokerCreated._poison(self._created_original)
            if self._intent_original is not None:
                self._intent_original._poison()
            try:
                self.close()
            except BaseException:
                pass  # preserve the exact held record and first refusal; never retry
            raise

    def send_create_result(self):
        """Send the original durable CREATED fact once; no caller frame or grant."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.result is self._result_original is None,
                    "BROKER_RESULT_ALREADY_ATTEMPTED")
            self.result = self._result_original = object.__new__(_BrokerCreateResult)
            self.result.__init__(self)
            require(type(self.result) is _BrokerCreateResult and self.result is self._result_original
                    and not self.result.failed and self.result.attempted,
                    "BROKER_RESULT_PUBLICATION_CHANGED")
            self.result._state_check()
            self.result.complete = True  # local send completion, not peer receipt/retirement
        except BaseException:
            if self._result_original is not None:
                _BrokerCreateResult._poison(self._result_original)
            self.failed = True
            try:
                _Broker.close(self)
            except BaseException:
                pass  # preserve the first refusal and held accounting; never retry
            raise

    def retire_create_result(self):
        """Retire one delivered CREATE locally; no next-action or cleanup grant."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.retirement is self._retirement_original is None,
                    "BROKER_RETIREMENT_ALREADY_ATTEMPTED")
            self.retirement = self._retirement_original = object.__new__(_BrokerCreateRetirement)
            self.retirement.__init__(self)
            require(type(self.retirement) is _BrokerCreateRetirement
                    and self.retirement is self._retirement_original
                    and self.retirement.retired and self.retirement.advanced
                    and not self.retirement.failed, "BROKER_RETIREMENT_PUBLICATION_CHANGED")
            _BrokerCreateRetirement._state_check(self.retirement)
            self.retirement.complete = True
        except BaseException:
            if self._retirement_original is not None:
                _BrokerCreateRetirement._poison(self._retirement_original)
            self.failed = True
            try:
                _Broker.close(self)
            except BaseException:
                pass  # never undo the transcript, retry a close, or release accounting
            raise

    def handoff_create_result(self):
        """Consume retired CREATE owners; preserve the original run and channel.

        This authorizes no API call, cleanup, worker or new lifetime. It only
        makes the existing receiver eligible to validate the next chained frame.
        The durable UID stays held and old action objects can never be reused.
        """
        try:
            require(not self.closed and not self.failed and not self.busy,
                    "BROKER_HANDOFF_UNAVAILABLE")
            events = self.events
            require(type(events) is _BrokerEvents and events is self._events_original,
                    "BROKER_HANDOFF_EVENTS_REQUIRED")
            with self._phase():
                _BrokerEvents._handoff_create(events)
            require(self.events is self._events_original is events,
                    "BROKER_HANDOFF_OWNER_CHANGED")
        except BaseException:
            self.failed = True
            try:
                _Broker.close(self)
            except BaseException:
                pass  # retired FDs and consumed resources are never reopened
            raise

    def exchange_api_get(self):
        """Read only the original pending GET's recorded UID; send no result."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.get_action is self._get_action_original is None,
                    "BROKER_GET_ALREADY_ATTEMPTED")
            self.get_action = self._get_action_original = object.__new__(_BrokerGetAction)
            self.get_action.__init__(self)
            _BrokerGetAction._check(self.get_action)
            self.get_action.complete = True
        except BaseException:
            self._fail_get()
            raise

    def send_get_result(self):
        """Deliver the original bounded PRESENT observation once, not cleanup."""
        try:
            action = self.get_action
            require(type(action) is _BrokerGetAction and action is self._get_action_original,
                    "BROKER_GET_OWNER_CHANGED")
            _BrokerGetAction.send_result(action)
        except BaseException:
            self._fail_get()
            raise

    def record_get_absence(self):
        """Persist only the original authenticated GET's scoped NotFound fact."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.absence is self._absence_original is None,
                    "BROKER_ABSENCE_ALREADY_ATTEMPTED")
            self.absence = self._absence_original = object.__new__(_BrokerAbsence)
            self.absence.__init__(self)
            _BrokerAbsence._state_check(self.absence)
            self.absence.committed = True
        except BaseException:
            if type(self._absence_original) is _BrokerAbsence:
                _BrokerAbsence._poison(self._absence_original)
            self._fail_get()
            raise

    def handoff_get_result(self):
        """Close the original GET connection before advancing the same channel."""
        try:
            action = self.get_action
            require(type(action) is _BrokerGetAction and action is self._get_action_original,
                    "BROKER_GET_OWNER_CHANGED")
            _BrokerGetAction.handoff(action)
        except BaseException:
            self._fail_get()
            raise

    def _fail_get(self):
        self.failed = True
        if type(self._get_action_original) is _BrokerGetAction:
            self._get_action_original.failed = True
        try:
            _Broker.close(self)
        except BaseException:
            pass  # no read retry, guessed absence, journal rollback or resource release

    def exchange_api_delete(self):
        """Delete only the original UID/version from the immediately prior GET."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.delete_action is self._delete_action_original is None,
                    "BROKER_DELETE_ALREADY_ATTEMPTED")
            self.delete_action = self._delete_action_original = object.__new__(_BrokerDeleteAction)
            self.delete_action.__init__(self)
            _BrokerDeleteAction._check(self.delete_action)
            self.delete_action.complete = True
        except BaseException:
            self._fail_delete()
            raise

    def send_delete_result(self):
        """Deliver a bounded DELETE acknowledgement, never an absence claim."""
        try:
            action = self.delete_action
            require(type(action) is _BrokerDeleteAction and action is self._delete_action_original,
                    "BROKER_DELETE_OWNER_CHANGED")
            _BrokerDeleteAction.send_result(action)
        except BaseException:
            self._fail_delete()
            raise

    def handoff_delete_result(self):
        """Retire this connection, retaining the UID until a later absence GET."""
        try:
            action = self.delete_action
            require(type(action) is _BrokerDeleteAction and action is self._delete_action_original,
                    "BROKER_DELETE_OWNER_CHANGED")
            _BrokerDeleteAction.handoff(action)
        except BaseException:
            self._fail_delete()
            raise

    def _fail_delete(self):
        self.failed = True
        if type(self._delete_action_original) is _BrokerDeleteAction:
            self._delete_action_original.failed = True
        try:
            _Broker.close(self)
        except BaseException:
            pass  # retain CREATED accounting; never retry or weaken a precondition

    def seal_cleanup(self):
        """Seal the server's receipt/cleanup facts, without claiming terminal delivery."""
        try:
            require(not self.closed and not self.failed and not self.busy
                    and self.completion is self._completion_original is None, "BROKER_COMPLETION_ALREADY_OWNED")
            self.completion = self._completion_original = object.__new__(_BrokerCompletion)
            self.completion.__init__(self)
            _BrokerCompletion._check(self.completion)
            self.completion.committed = True
        except BaseException:
            self._fail_completion()
            raise

    def send_cleanup(self):
        try:
            require(type(self.completion) is _BrokerCompletion and self.completion is self._completion_original,
                    "BROKER_COMPLETION_OWNER_CHANGED")
            _BrokerCompletion.send_cleanup(self.completion)
        except BaseException:
            self._fail_completion()
            raise

    def poll_terminal(self):
        """One bounded same-channel poll; no reconnect and no new execution lifetime."""
        try:
            require(type(self.completion) is _BrokerCompletion and self.completion is self._completion_original,
                    "BROKER_COMPLETION_OWNER_CHANGED")
            return _BrokerCompletion.poll_terminal(self.completion)
        except BaseException:
            self._fail_completion()
            raise

    def record_terminal(self):
        try:
            require(type(self.completion) is _BrokerCompletion and self.completion is self._completion_original,
                    "BROKER_COMPLETION_OWNER_CHANGED")
            _BrokerCompletion.record_terminal(self.completion)
        except BaseException:
            self._fail_completion()
            raise

    def finish_case(self):
        """Retire one clean completed case without reopening its nonce or channel."""
        try:
            completion = self.completion
            require(type(completion) is _BrokerCompletion and completion is self._completion_original
                    and completion.complete and completion.terminal_advanced and not completion.failed,
                    "BROKER_CASE_TERMINAL_REQUIRED")
            _BrokerCompletion._check(completion)
            with self._phase():
                _BrokerCompletion._guard(completion)
                cleanup, terminal = document(completion.cleanup_raw), document(completion.terminal_raw)
                require(completion.receipt_status == "PASS" and cleanup["state"] == "CLEAN"
                        and terminal["payload"]["status"] == "COMPLETED", "BROKER_CASE_NOT_CLEAN_COMPLETED")
                states, _, _ = parse_reservations(completion.final_ledger)
                current = states[(self.owner.envelope["tenantId"], self.owner.envelope["nonce"])]
                previous = [document(raw) for raw in self.case_history]
                cases = [row["caseId"] for row in previous] + [completion.operation]
                require(len(cases) == len(set(cases)) <= len(CASES)
                        and set(cases) == self._attempted_cases
                        and current["current"] is None and current["done"] == current["terminalCases"] == cases
                        and "pendingCompletion" not in current
                        and current["lastTerminalDigest"] == byte_digest(completion.terminal_raw)
                        and current["held"] is (len(cases) < len(CASES)), "BROKER_CASE_HISTORY_CHANGED")
                require(self._io(select.select, [self.sock], [], [self.sock], 0) == ([], [], []),
                        "BROKER_CASE_TRAILING_DATA")
                _BrokerCompletion._guard(completion)
                dispatch = document(completion.dispatch_raw)
                archive = canonical_bytes({"caseId": completion.operation, "challenge": dispatch["challenge"],
                    "executionId": terminal["executionId"], "receiptDigest": byte_digest(completion.receipt_raw),
                    "terminalDigest": byte_digest(completion.terminal_raw),
                    "ledgerDigest": byte_digest(completion.final_ledger),
                    "observerBootId": completion.start.observation_pin[0], "generation": dispatch["generation"]})
                self.case_history += (archive,)
                self.case_history_raw = canonical_bytes([byte_digest(raw) for raw in self.case_history])
                # Retire only completed local owners. The peer, credential cache,
                # ledger, deadline, attempted cases and all UID history survive.
                for name in ("dispatch", "events", "completion", "last_get", "last_get_raw"):
                    setattr(self, name, None)
                    setattr(self, "_" + name + "_original", None)
                self.owner.active_operation = None
                self._check_peer()
                require(self._io(completion.storage.read) == completion.final_ledger,
                        "BROKER_CASE_HISTORY_CHANGED")
            # No old completion can be reused: its owner check now refuses.
        except BaseException:
            self._fail_completion()
            raise

    def _fail_completion(self):
        self.failed = True
        if type(self._completion_original) is _BrokerCompletion:
            _BrokerCompletion._poison(self._completion_original)
        try:
            _Broker.close(self)
        except BaseException:
            pass  # never undo sealed cleanup or invent an unreceived terminal

    def close(self):
        if not self.closed:
            self.closed = True
            api, self._api_original, self.api = self._api_original, None, None
            if api is not None:
                try:
                    require(type(api) is _BrokerApi, "BROKER_CLOSE_API_OWNER_CHANGED")
                    _BrokerApi.close(api)
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
            inspection, self._inspection_original, self.inspection = self._inspection_original, None, None
            if inspection is not None:
                try:
                    inspection.close()  # borrowed socket/files remain separately owned
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
            sock, self._socket_original, self.sock = self._socket_original, None, None
            pidfd, self._pidfd_original, self.pidfd = self._pidfd_original, None, None
            for resource, fd, pin in ((pidfd, pidfd, self._pidfd_pin), (sock, self._socket_fd, self._socket_pin)):
                if resource is None:
                    continue
                try:
                    if pin is not None and self._fd_pin(fd) != pin:
                        require(False, "BROKER_CLOSE_FD_REUSED")
                    if resource is sock:
                        require(fd is None or sock.fileno() == fd, "BROKER_CLOSE_SOCKET_CHANGED")
                        sock.close()
                    else:
                        os.close(fd)
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
                    if resource is sock:
                        try:
                            sock.detach()  # no destructor close after uncertain identity/close
                        except BaseException:
                            pass  # preserve the first error; never retry close
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _BrokerStart:
    """One fixed DISPATCH/STARTED phase, not a completed execution or API grant.

    Borrows the original broker and server resources; owns only private data.
    Receipt/action/cleanup owners and the server driver compose later phases.
    No caller frame, action or operation is accepted here.
    """
    def __init__(self, broker):
        self.failed, self.started = False, None
        self.transcript = self._transcript_original = None
        try:
            require(type(self) is _BrokerStart and type(broker) is _Broker,
                    "BROKER_START_OWNER")
            self.broker, self.owner = broker, broker.owner
            self._owner_check()
            owner = self.owner
            self.storage, self.log, self.observer = owner.storage, owner.log, owner.observer
            require(type(self.storage) is _State and self.storage.owner is owner
                    and type(self.log) is _AdmissionLog and self.log.storage is self.storage
                    and type(self.observer) is _Observer and self.observer.owner is owner,
                    "BROKER_START_PREREQUISITES")
            self.operation = owner.active_operation
            require(type(self.operation) is str and self.operation in CASES
                    and type(broker._attempted_cases) is set
                    and self.operation not in broker._attempted_cases, "BROKER_DISPATCH_REPLAY")
            self.reservation_raw = canonical_bytes(admission_binding(owner.envelope, owner.capacity, owner.profile))
            self.request_raw = canonical_bytes(build_probe_request(owner.envelope, owner.capacity, owner.plan, self.operation))
            self.binding_raw = broker._binding_raw
            broker._check_peer()
            self.ledger_raw = broker._io(self.storage.read)
            states, _, _ = parse_reservations(self.ledger_raw)
            current = states.get((owner.envelope["tenantId"], owner.envelope["nonce"]))
            require(current is not None and current["current"] == self.operation and current["held"] is True
                    and current["last"] <= require_time(utc_now(), "now")
                    and canonical_bytes(current["binding"]) == self.reservation_raw, "BROKER_RUNNING_REQUIRED")
            last = document(self.ledger_raw.splitlines()[-1], 32768)
            require(last["state"] == "RUNNING" and last["operation"] == self.operation
                    and last["cleanup"] is None and canonical_bytes(last["binding"]) == self.reservation_raw,
                    "BROKER_RUNNING_REQUIRED")
            self.observation_pin = None
            observed = self._check()
            challenge = broker._io(os.urandom, 32)
            require(type(challenge) is bytes and len(challenge) == 32, "BROKER_CHALLENGE_INVALID")
            require(all(document(raw)["challenge"] != challenge.hex() for raw in broker.case_history),
                    "BROKER_CHALLENGE_REPLAY")
            dispatch = {"schemaVersion": "planeon.internal.broker-dispatch/v1",
                "operation": "EXECUTE_FIXED_PROBE",
                "bindingDigest": byte_digest(self.binding_raw), "reservationDigest": byte_digest(self.reservation_raw),
                "runNonce": owner.envelope["nonce"], "caseId": self.operation,
                "requestDigest": byte_digest(self.request_raw), "observationDigest": canonical_digest(observed),
                "generation": observed["generation"], "challenge": challenge.hex()}
            self.dispatch_raw = canonical_bytes(broker_document(dispatch, "dispatch"))
            self._check()
            broker._prepare_wait()
            # Mark attempted BEFORE send, including timeout/partial delivery.
            broker._attempted_cases.add(self.operation)
            try:
                require(broker.sock.send(self.dispatch_raw) == len(self.dispatch_raw), "BROKER_SEND_AMBIGUOUS")
            finally:
                self._check()
            self._check()
            broker._prepare_wait()
            try:
                raw, ancillary, flags, _ = broker.sock.recvmsg(65537, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4))
                # Drain rights BEFORE a post-I/O refusal can lose ownership.
                require(credentials(ancillary, flags) == broker._peer_original, "BROKER_MESSAGE_PEER")
            finally:
                self._check()
            # Keep the data parser private until all post-I/O guards complete.
            transcript = BrokerTranscript(self.binding_raw, self.dispatch_raw)
            frame = transcript.accept(raw, "BROKER")
            require(frame["kind"] == "STARTED", "BROKER_CONTROLLED_START_REQUIRED")
            require(all(document(raw)["executionId"] != frame["executionId"] for raw in broker.case_history),
                    "BROKER_EXECUTION_REPLAY")
            self._check()
            self.transcript = self._transcript_original = transcript
            # Publish only after the enclosing broker phase's last guard passes.
            self._started_raw = canonical_bytes(frame)  # observation, never a permit
        except BaseException:
            self.failed = True
            raise

    def _owner_check(self):
        broker, owner = self.broker, self.owner
        require(type(self) is _BrokerStart and not self.failed
                and type(broker) is _Broker and type(owner) is NativeProxyServer
                and owner.broker is owner._broker_original is broker and broker.owner is owner
                and broker.dispatch is broker._dispatch_original is self,
                "BROKER_START_OWNER_CHANGED")
        broker._guard()

    def _state_check(self):
        self._owner_check()
        owner, broker = self.owner, self.broker
        require(owner.storage is self.storage and self.storage.owner is owner
                and owner.log is self.log and self.log.storage is self.storage and not self.log.poisoned
                and owner.observer is self.observer and self.observer.owner is owner
                and owner.reserved is True and owner.files.sealed is True
                and owner.active_operation == self.operation
                and canonical_bytes(owner.reservation) == self.reservation_raw
                and canonical_bytes(admission_binding(owner.envelope, owner.capacity, owner.profile)) == self.reservation_raw
                and canonical_bytes(build_probe_request(owner.envelope, owner.capacity, owner.plan, self.operation)) == self.request_raw
                and broker._binding_raw == self.binding_raw, "BROKER_START_STATE_CHANGED")
        require(broker._io(self.storage.read) == self.ledger_raw, "BROKER_RUNNING_CHANGED")

    def _check(self):
        self._state_check()
        owner, broker = self.owner, self.broker
        broker._check_peer()
        try:
            observed = self.observer.observe()
        finally:
            broker._check_peer()
        require(type(observed) is dict and self.observer._previous_raw == canonical_bytes(observed)
                and canonical_bytes(self.observer.previous) == self.observer._previous_raw
                and observed["bindingDigest"] == canonical_digest(owner.observation_binding)
                and observed["runNonce"] == owner.envelope["nonce"], "BROKER_OBSERVATION_BINDING")
        # Runtime UTC includes microseconds; only wire observations are seconds.
        now = require_time(utc_now(), "now")
        start, end = _time(observed["observedAt"]), _time(observed["expiresAt"])
        require(start <= now < end and 0 < (end - start).total_seconds() <= 5, "BROKER_OBSERVATION_EXPIRED")
        pin = (observed["observerBootId"], observed["generation"])
        require(self.observation_pin is None or self.observation_pin == pin, "BROKER_GENERATION_CHANGED")
        require(all((document(raw)["observerBootId"], document(raw)["generation"]) == pin
                    for raw in broker.case_history), "BROKER_GENERATION_CHANGED")
        self.observation_pin = pin
        # The observer call cannot change the durable operation or owned objects.
        self._state_check()
        return observed


class _BrokerEvents:
    """Original-channel inbound data after STARTED, not a resource/API grant.

    This receiver cannot acknowledge an action or cleanup, accept completion,
    release a reservation, start a worker or extend the operation's lifetime.
    A pending action must be handled by the separately owned server driver.
    """
    def __init__(self, broker):
        self.failed = False
        self.handoffs, self.handoffs_raw = (), b"[]"
        try:
            require(type(broker) is _Broker, "BROKER_EVENTS_OWNER")
            self.broker, self.owner = broker, broker.owner
            self.start = broker.dispatch
            require(type(self.start) is _BrokerStart and self.start is broker._dispatch_original
                    and type(self.start.started) is bytes and self.start.started == self.start._started_raw,
                    "BROKER_STARTED_REQUIRED")
            self.started_raw = self.start.started
            self.binding_raw, self.dispatch_raw = self.start.binding_raw, self.start.dispatch_raw
            self.deadline = broker.deadline
            self.transcript = self.start.transcript
            require(type(self.transcript) is BrokerTranscript
                    and self.transcript is self.start._transcript_original, "BROKER_TRANSCRIPT_OWNER")
            # Rebuild only the already received STARTED data, not an execution.
            expected = BrokerTranscript(self.binding_raw, self.dispatch_raw)
            expected.accept(self.started_raw, "BROKER")
            self.transcript_raw = self._snapshot(expected)
            self._check()
        except BaseException:
            self.failed = True
            raise

    @staticmethod
    def _snapshot(transcript):
        require(type(transcript) is BrokerTranscript, "BROKER_TRANSCRIPT_OWNER")
        values = vars(transcript)
        require(set(values) == {"binding", "dispatch", "sequence", "previous", "execution", "pending",
                "cleanup", "terminal", "actions", "chunks", "receipt_size", "failed_action", "poisoned"}
                and type(transcript.actions) is set
                and all(type(action) is int for action in transcript.actions)
                and type(transcript.chunks) is list
                and all(type(chunk) is bytes for chunk in transcript.chunks), "BROKER_TRANSCRIPT_STATE")
        return canonical_bytes({**values, "actions": sorted(transcript.actions),
            "chunks": [{"size": len(chunk), "sha256": byte_digest(chunk)} for chunk in transcript.chunks]})

    def _state_check(self):
        broker, owner, start = self.broker, self.owner, self.start
        require(type(self) is _BrokerEvents and not self.failed
                and type(broker) is _Broker and type(owner) is NativeProxyServer
                and broker.owner is owner and owner.broker is owner._broker_original is broker
                and broker.events is broker._events_original is self
                and broker.dispatch is broker._dispatch_original is start
                and type(start) is _BrokerStart and start.broker is broker and start.owner is owner
                and not start.failed and start.started == start._started_raw == self.started_raw
                and start.binding_raw == self.binding_raw and start.dispatch_raw == self.dispatch_raw
                and self.deadline == broker.deadline == owner.deadline
                and self.transcript is start.transcript is start._transcript_original,
                "BROKER_EVENTS_OWNER_CHANGED")
        broker._guard()
        require(self._snapshot(self.transcript) == self.transcript_raw
                and not self.transcript.poisoned, "BROKER_TRANSCRIPT_CHANGED")
        require(type(self.handoffs) is tuple and len(self.handoffs) <= 256
                and all(type(raw) is bytes for raw in self.handoffs)
                and canonical_bytes([byte_digest(raw) for raw in self.handoffs]) == self.handoffs_raw,
                "BROKER_HANDOFF_HISTORY_CHANGED")

    def _check(self):
        self._state_check()
        self.start._check()  # original RUNNING history, observer generation and native peer
        self._state_check()

    def _handoff_create(self):
        self._check()
        broker, retirement = self.broker, self.broker.retirement
        require(type(retirement) is _BrokerCreateRetirement
                and retirement is broker._retirement_original and retirement.complete is True
                and retirement.retired is True and retirement.advanced is True
                and retirement.events is self and not retirement.failed,
                "BROKER_HANDOFF_RETIREMENT_REQUIRED")
        _BrokerCreateRetirement._check(retirement)
        require(self.transcript.pending is self.transcript.cleanup is self.transcript.terminal is None
                and not self.transcript.chunks and len(self.handoffs) < 256,
                "BROKER_HANDOFF_PHASE")
        action = document(retirement.result.action_raw, 16384)
        require(action["verb"] == "CREATE" and action["actionId"] in self.transcript.actions
                and self.transcript_raw == retirement.after
                and self.start.ledger_raw == retirement.ledger_raw,
                "BROKER_HANDOFF_STATE")
        archive = canonical_bytes({"actionId": action["actionId"], "verb": "CREATE", "manifestDigest": action["manifestDigest"],
            "resultDigest": byte_digest(retirement.frame_raw), "createdDigest": retirement.created.digest,
            "ledgerDigest": byte_digest(retirement.ledger_raw), "transcriptDigest": byte_digest(retirement.after)})
        require(all(document(raw)["actionId"] != action["actionId"] for raw in self.handoffs),
                "BROKER_HANDOFF_REPLAY")
        # Consume only the already-closed action owners, with no I/O between
        # final retired-state validation and the local one-way handoff.
        for name in ("api", "intent", "exchange", "created", "result", "retirement"):
            setattr(broker, name, None)
            setattr(broker, "_" + name + "_original", None)
        self.handoffs += (archive,)
        self.handoffs_raw = canonical_bytes([byte_digest(raw) for raw in self.handoffs])
        self._check()  # unchanged deadline, original peer/generation and exact UID history

    def receive(self):
        try:
            self._check()
            transcript, broker = self.transcript, self.broker
            require(broker.retirement is broker._retirement_original is None,
                    "BROKER_ACTION_HANDOFF_REQUIRED")
            require(broker.get_action is broker._get_action_original is None,
                    "BROKER_GET_HANDOFF_REQUIRED")
            require(broker.delete_action is broker._delete_action_original is None,
                    "BROKER_DELETE_HANDOFF_REQUIRED")
            require(broker.completion is broker._completion_original is None, "BROKER_CLEANUP_ALREADY_SEALED")
            require(transcript.pending is None, "BROKER_RESOURCE_RESULT_REQUIRED")
            require(transcript.cleanup is None and transcript.terminal is None,
                    "BROKER_INBOUND_PHASE_CLOSED")
            before = time.monotonic()
            require(broker.last_mono <= before < broker.end <= self.deadline,
                    "BROKER_CLOCK_OR_DEADLINE")
            # Idle readiness polls do not resend DISPATCH or renew the deadline.
            # Leave time for the mandatory post-wait guards inside this phase.
            wait = min(0.25, (broker.end - before) / 2)
            try:
                ready = select.select([broker.sock], [], [broker.sock], wait)
            finally:
                self._check()
            require(type(ready) is tuple and len(ready) == 3 and ready[1:] == ([], [])
                    and ready[0] in ([], [broker.sock]), "BROKER_READINESS_INVALID")
            if not ready[0]:
                return None
            self._check()
            broker._prepare_wait()
            try:
                raw, ancillary, flags, _ = broker.sock.recvmsg(65537, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4))
                # Descriptors must be drained before any post-I/O refusal.
                require(credentials(ancillary, flags) == broker._peer_original, "BROKER_MESSAGE_PEER")
            finally:
                self._check()
            frame = broker_document(raw, "frame")
            require(frame["kind"] in ("RESOURCE_ACTION", "RECEIPT_CHUNK"), "BROKER_INBOUND_KIND_UNAVAILABLE")
            if frame["kind"] == "RESOURCE_ACTION":
                require(len(raw) <= 16384, "BROKER_ACTION_SIZE")
            else:
                require(len(transcript.chunks) < 171, "BROKER_RECEIPT_CHUNK_LIMIT")
            transcript.accept(raw, "BROKER")
            self.transcript_raw = self._snapshot(transcript)
            self._check()
            return canonical_bytes(frame)  # immutable data, not an effect/receipt permit
        except BaseException:
            self.failed = True
            raise


class _BrokerIntent:
    """One original pending CREATE, durably recorded without granting API use.

    No caller supplies a row, resource, observed response or new history. The
    immutable expected append is derived before writing, and only that exact
    durable result may advance the original dispatch's retained history pin.
    """
    def __init__(self, broker):
        self.failed = self.committed = self.writing = self.advanced = False
        self.log = None
        try:
            require(type(self) is _BrokerIntent and type(broker) is _Broker
                    and broker.intent is broker._intent_original is self, "BROKER_INTENT_OWNER")
            self.broker, self.owner = broker, broker.owner
            self.events = broker.events
            require(type(self.events) is _BrokerEvents and self.events is broker._events_original,
                    "BROKER_INTENT_EVENTS_REQUIRED")
            self.events._check()
            self.start = self.events.start
            self.storage, self.log = self.start.storage, self.start.log
            self.before = self.start.ledger_raw
            self.action_raw = canonical_bytes(self.events.transcript.pending)
            self.profile_raw = canonical_bytes(self.owner.profile)
            self.reservation_raw, self.binding_raw = self.start.reservation_raw, self.start.binding_raw
            self.operation, self.deadline = self.start.operation, broker.deadline
            self._check()
            action = document(self.action_raw, 16384)
            require(type(action) is dict and action.get("verb") == "CREATE", "BROKER_CREATE_INTENT_REQUIRED")
            now = utc_now()
            resource = _create_record(document(self.reservation_raw), self.operation,
                self.profile_raw, self.binding_raw, action)
            _, previous, count = parse_reservations(self.before)
            self.row_raw = canonical_bytes(dict(sequence=count + 1, previousDigest=previous,
                binding=document(self.reservation_raw), state="CREATE_INTENT", operation=self.operation,
                observedAt=now, cleanup=None, resource=resource))
            self.after = self.before + self.row_raw + b"\n"
            parse_reservations(self.after)
            self.digest = byte_digest(self.row_raw)
            self._check()  # exact original history, current peer/observer before write
            self.writing = True
            result = broker._io(_AdmissionLog.record_resource, self.log,
                document(self.reservation_raw), "CREATE_INTENT", self.operation, now,
                self.profile_raw, self.binding_raw, action, expected_history=self.before)
            require(type(result) is str and result == self.digest, "BROKER_INTENT_COMMIT_MISMATCH")
            require(broker._io(self.storage.read) == self.after, "BROKER_INTENT_READBACK_MISMATCH")
            # Until this point the old history guard is unchanged. Validate
            # original objects and pending action before advancing its pin.
            self._pending_check()
            require(self.start.ledger_raw == self.before, "BROKER_INTENT_HISTORY_CHANGED")
            self.start.ledger_raw = self.after
            self.advanced = True
            self._check()  # fresh observer/peer and full exact new history guard
        except BaseException:
            self._poison()
            raise

    def _pending_check(self):
        broker, owner = self.broker, self.owner
        require(type(self) is _BrokerIntent and not self.failed
                and type(broker) is _Broker and broker.intent is broker._intent_original is self
                and broker.owner is owner and owner.broker is owner._broker_original is broker
                and broker.events is broker._events_original is self.events
                and broker.dispatch is broker._dispatch_original is self.start
                and self.events.start is self.start and self.start.owner is owner
                and owner.storage is self.start.storage is self.storage
                and owner.log is self.start.log is self.log and self.log.storage is self.storage
                and not self.log.poisoned and self.start.operation == self.operation
                and self.start.reservation_raw == self.reservation_raw and self.start.binding_raw == self.binding_raw
                and canonical_bytes(owner.profile) == self.profile_raw
                and self.deadline == broker.deadline == owner.deadline, "BROKER_INTENT_OWNER_CHANGED")
        self.events._state_check()
        require(canonical_bytes(self.events.transcript.pending) == self.action_raw, "BROKER_INTENT_ACTION_CHANGED")

    def _check(self):
        self._pending_check()
        self._history_check()
        self.events._check()
        self._pending_check()

    def _history_check(self):
        # Only the original, exact CREATED append may advance this intent's
        # history. Arbitrary external appends still fail the dispatch guard.
        created = self.broker._created_original
        if created is not None or self.broker.created is not None:
            require(type(created) is _BrokerCreated and self.broker.created is created
                    and created.intent is self and self.advanced and self.committed,
                    "BROKER_CREATED_OWNER_CHANGED")
            _BrokerCreated._state_check(created)
        else:
            require(self.start.ledger_raw == (self.after if self.advanced else self.before),
                    "BROKER_INTENT_HISTORY_CHANGED")

    def check(self):
        try:
            require(self.committed, "BROKER_INTENT_NOT_COMMITTED")
            with self.broker._phase():
                self._check()
        except BaseException:
            self._poison()
            self.broker.failed = True
            try:
                self.broker.close()
            except BaseException:
                pass  # borrowed state remains held, never repaired or released
            raise

    def _poison(self):
        self.failed = True
        if self.writing and self.log is not None:
            self.log.poisoned = True


class _BrokerApi:
    """Server-only retained TCP/TLS owner, not an action executor or UID ledger.

    One pending broker action selects the endpoint from retained signed inputs.
    This increment exposes no HTTP send, action acknowledgement or cleanup path.
    """
    def __init__(self, broker):
        self.closed = self.failed = self.ready = self.checking = False
        self.cleanup_failure = None
        self.sock = self._socket_original = self.tls = self._tls_original = None
        self.memfd = self._memfd_original = None
        self._socket_fd = self._socket_pin = self._memfd_pin = None
        self.connected = False
        try:
            require(type(broker) is _Broker and broker.api is broker._api_original is self,
                    "API_OWNER_INVALID")
            self.broker, self.owner = broker, broker.owner
            self.events = broker.events
            require(type(self.events) is _BrokerEvents and self.events is broker._events_original,
                    "API_BROKER_EVENTS_REQUIRED")
            self.secrets = self.owner.secrets
            require(type(self.secrets) is _Files and self.secrets.owner is self.owner,
                    "API_SECRET_OWNER_INVALID")
            self.deadline, self.last = broker.deadline, time.monotonic()
            self.action_raw = canonical_bytes(self.events.transcript.pending)
            self.endpoint_raw, self.ca = self._inputs()
            self.endpoint = document(self.endpoint_raw)
            address = ipaddress.ip_address(self.endpoint["ipAddress"])
            # The closed signed envelope carries the IP literal, not the
            # qualification record's derived addressFamily field. Derive from
            # that authenticated literal; a supplied private projection must
            # still agree. Never add fields to or re-sign the envelope here.
            family = "IPV4" if address.version == 4 else "IPV6"
            require(str(address) == self.endpoint["ipAddress"] and not address.is_unspecified
                    and not address.is_multicast and not (address.version == 6 and
                    (address.ipv4_mapped is not None or address.scope_id is not None))
                    and self.endpoint.get("addressFamily", family) == family,
                    "API_ENDPOINT_ADDRESS")
            self.target = (str(address), self.endpoint["port"]) if address.version == 4 else (str(address), self.endpoint["port"], 0, 0)
            self._target_original = self.target
            self._transport_check()
            path = self.endpoint["credentialFileReference"]
            credential = broker._credential_original
            require(broker.credential is credential, "API_CREDENTIAL_OWNER_CHANGED")
            if credential is None:
                require(path not in self.secrets.raw, "API_CREDENTIAL_ALREADY_READ")
                raw = self._io(self.secrets.read, path, mode=0o400, maximum=262144)
            else:
                require(type(credential) is tuple and len(credential) == 3
                        and credential[0] is self.secrets and credential[1] == path
                        and type(self.secrets.raw.get(path)) is bytes
                        and byte_digest(self.secrets.raw[path]) == credential[2],
                        "API_CREDENTIAL_OWNER_CHANGED")
                raw = self.secrets.raw[path]  # original retained read, never reopen a credential
                self._transport_check()
            self._io(_check_certificate, credential_leaf(raw), self.owner.profile, self.endpoint, client=True)
            try:
                self.memfd = self._memfd_original = os.memfd_create("planeon-api-identity", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                self._memfd_pin = _Broker._fd_pin(self.memfd)
                require(self._memfd_pin[2] == stat.S_IFREG, "API_MEMFD_TYPE")
            finally:
                self._transport_check()
            offset = 0
            while offset < len(raw):
                count = self._io(os.write, self.memfd, raw[offset:])
                require(type(count) is int and 0 < count <= len(raw) - offset, "API_CREDENTIAL_SHORT_WRITE")
                offset += count
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
            self._io(fcntl.fcntl, self.memfd, fcntl.F_ADD_SEALS, seals)
            require(self._io(fcntl.fcntl, self.memfd, fcntl.F_GET_SEALS) & seals == seals, "API_CREDENTIAL_SEALS")
            self._io(os.lseek, self.memfd, 0, os.SEEK_SET)
            require(self._io(os.read, self.memfd, len(raw) + 1) == raw, "API_CREDENTIAL_MEMFD_CHANGED")
            context = self._io(tls_context, self.ca, self.memfd)
            self._close_memfd()
            self._transport_check()
            try:
                self.sock = self._socket_original = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6,
                                                                socket.SOCK_STREAM)
                self._socket_fd = self.sock.fileno()
                self._socket_pin = _Broker._fd_pin(self._socket_fd)
                require(self._socket_pin[2] == stat.S_IFSOCK, "API_SOCKET_TYPE")
            finally:
                self._transport_check()
            self._io(self.sock.set_inheritable, False)
            if address.version == 6:
                self._io(self.sock.setsockopt, socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            end = min(self.deadline, time.monotonic() + 10)
            self._transport_check()
            before = time.monotonic()
            require(self.last <= before < end, "API_CONNECT_DEADLINE")
            self._io(self.sock.settimeout, min(2, end - before))
            # Recompute after all potentially expensive checks, before connect.
            before = time.monotonic()
            require(self.last <= before < end, "API_CONNECT_DEADLINE")
            try:
                self.sock.settimeout(min(2, end - before))
                require(before <= time.monotonic() < end, "API_CONNECT_DEADLINE")
                self.sock.connect(self.target)
                self.connected = True  # retained before post-I/O refusal
            finally:
                self._transport_check()
                require(before <= time.monotonic() < end, "API_CONNECT_DEADLINE")
            self.tls = self._tls_original = _TLS(self.sock, context, self.endpoint, self, self.deadline)
            self._transport_check()
            require(self.tls.handshake(self.owner.profile, self.endpoint) is None, "API_HANDSHAKE_RESULT")
            self._transport_check()
            if credential is None:
                require(broker.credential is broker._credential_original is None,
                        "API_CREDENTIAL_OWNER_CHANGED")
                broker.credential = broker._credential_original = (self.secrets, path, byte_digest(raw))
            self.ready = True
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass
            raise

    def check(self):
        """Retained authentication readiness only; never acknowledge an action."""
        try:
            require(self.ready, "API_NOT_READY")
            self._transport_check()
        except BaseException:
            self.failed = True
            self.broker.failed = True
            try:
                self.broker.close()
            except BaseException:
                pass
            raise

    def _inputs(self):
        owner, events = self.owner, self.events
        action = document(self.action_raw, 16384)
        require(type(action) is dict and set(action) == {"actionId", "verb", "manifestDigest"}
                and action["verb"] in ("CREATE", "GET", "DELETE") and owner.profile["resources"], "API_ACTION_REQUIRED")
        binding = broker_document(events.start.binding_raw, "binding")
        require(action["manifestDigest"] in binding["caseResourceDigests"][events.start.operation], "API_ACTION_CASE")
        resources = [r for r in owner.profile["resources"] if r["manifestDigest"] == action["manifestDigest"]]
        require(len(resources) == 1, "API_ACTION_MANIFEST")
        scope = owner.profile["binding"]
        endpoints = [e for e in owner.envelope["endpoints"] if e["endpointId"] == scope["apiEndpointId"]]
        require(len(endpoints) == 1 and endpoints[0]["kind"] == "KUBERNETES_API_PROXY"
                and endpoints[0]["endpointId"] != scope["endpointId"], "API_ENDPOINT_REQUIRED")
        endpoint = endpoints[0]
        require(endpoint["credentialFileReference"] != IDENTITY and all(
            endpoint["credentialFileReference"] != e["credentialFileReference"] for e in owner.envelope["endpoints"]
            if e["endpointId"] != endpoint["endpointId"]), "API_CREDENTIAL_REUSE")
        credential = [r for r in owner.profile["capacityEntries"]["credentialIdentities"]
                      if r["endpointId"] == endpoint["endpointId"] and r["purpose"] == "KUBERNETES_PROXY_SERVER_MTLS"]
        require(len(credential) == 1, "API_CREDENTIAL_ENROLLMENT")
        manifest = resources[0]["manifest"]
        resource = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[manifest["kind"]]
        grant = dict(endpointId=endpoint["endpointId"], verb=action["verb"].lower(), resource=resource,
                     namespace=scope["namespace"], name=manifest["metadata"]["name"], apiGroup="", apiVersion="v1",
                     subresource="", requestMediaType="application/json", responseMediaType="application/json",
                     requestMaxBytes=16384, responseMaxBytes=4194304)
        require(grant in owner.profile["capacityEntries"]["kubernetesApiRules"], "API_EXACT_GRANT_REQUIRED")
        prefix = owner.envelope["conformanceKitRoot"] + "/"
        path = endpoint["tls"]["caCertificateFileReference"]
        require(path.startswith(prefix) and all(p not in ("", ".", "..") for p in path[len(prefix):].split("/")),
                "API_CA_NOT_RELEASED")
        relative = path[len(prefix):]
        ca = owner.kit.get(relative)
        release_raw = owner.files.raw[owner.envelope["campaignReleaseFileReference"]]
        require(byte_digest(release_raw) == owner.envelope["campaignReleaseDigest"], "API_RELEASE_CHANGED")
        release = require_canonical_document(release_raw)
        rows = [r for r in release["tree"] if r["path"] == relative]
        require(type(ca) is bytes and 0 < len(ca) <= 262144 and ca.startswith(b"-----BEGIN CERTIFICATE-----")
                and b"PRIVATE KEY" not in ca and rows == [{"path": relative, "mode": "0444", "size": len(ca),
                                                          "sha256": byte_digest(ca)}], "API_CA_CHANGED")
        return canonical_bytes(endpoint), ca

    def _transport_check(self):
        require(not self.checking, "API_REENTRANT_CHECK")
        self.checking = True
        try:
            broker, owner = self.broker, self.owner
            require(type(self) is _BrokerApi and not self.closed and not self.failed
                    and type(broker) is _Broker and broker.api is broker._api_original is self
                    and broker.owner is owner and owner.broker is owner._broker_original is broker
                    and broker.events is broker._events_original is self.events
                    and owner.secrets is self.secrets and self.secrets.owner is owner
                    and self.deadline == broker.deadline == owner.deadline, "API_OWNER_CHANGED")
            with broker._phase():
                self.events._check()
                if broker.exchange is not None or broker._exchange_original is not None:
                    require(type(broker.exchange) is _BrokerCreateExchange
                            and broker.exchange is broker._exchange_original, "API_EXCHANGE_OWNER_CHANGED")
                    broker.exchange._state_check()
                    broker.exchange.intent._check()
                if broker.get_action is not None or broker._get_action_original is not None:
                    require(type(broker.get_action) is _BrokerGetAction
                            and broker.get_action is broker._get_action_original,
                            "API_GET_OWNER_CHANGED")
                    _BrokerGetAction._state_check(broker.get_action)
                if broker.delete_action is not None or broker._delete_action_original is not None:
                    require(type(broker.delete_action) is _BrokerDeleteAction
                            and broker.delete_action is broker._delete_action_original,
                            "API_DELETE_OWNER_CHANGED")
                    _BrokerDeleteAction._state_check(broker.delete_action)
            self.secrets.check()
            credential = broker._credential_original
            require(broker.credential is credential, "API_CREDENTIAL_OWNER_CHANGED")
            if credential is not None:
                require(type(credential) is tuple and len(credential) == 3
                        and credential[0] is self.secrets
                        and credential[1] == self.endpoint["credentialFileReference"]
                        and type(self.secrets.raw.get(credential[1])) is bytes
                        and byte_digest(self.secrets.raw[credential[1]]) == credential[2],
                        "API_CREDENTIAL_OWNER_CHANGED")
            require(canonical_bytes(self.events.transcript.pending) == self.action_raw
                    and self._inputs() == (self.endpoint_raw, self.ca)
                    and canonical_bytes(self.endpoint) == self.endpoint_raw
                    and self.target == self._target_original, "API_INPUTS_CHANGED")
            for fd, pin in ((self.memfd, self._memfd_pin), (self._socket_fd, self._socket_pin)):
                if fd is not None:
                    require(_Broker._fd_pin(fd) == pin and not os.get_inheritable(fd), "API_DESCRIPTOR_CHANGED")
            require(self.memfd == self._memfd_original and self.sock is self._socket_original
                    and self.tls is self._tls_original, "API_TRANSPORT_CHANGED")
            if self.sock is not None:
                require(self.sock.fileno() == self._socket_fd, "API_DESCRIPTOR_CHANGED")
                if self.connected:
                    require(self.sock.getpeername() == self.target, "API_PEER_CHANGED")
            if self.tls is not None:
                require(type(self.tls) is _TLS and self.tls.owner is self and self.tls.sock is self.sock
                        and self.tls.deadline == self.deadline, "API_TLS_OWNER_CHANGED")
            now = time.monotonic()
            require(self.last <= now < self.deadline, "API_CLOCK_OR_DEADLINE")
            self.last = now
            if broker.exchange is not None or broker._exchange_original is not None:
                require(type(broker.exchange) is _BrokerCreateExchange
                        and broker.exchange is broker._exchange_original, "API_EXCHANGE_OWNER_CHANGED")
                broker.exchange._state_check()
            if broker.get_action is not None or broker._get_action_original is not None:
                require(type(broker.get_action) is _BrokerGetAction
                        and broker.get_action is broker._get_action_original,
                        "API_GET_OWNER_CHANGED")
                _BrokerGetAction._state_check(broker.get_action)
            if broker.delete_action is not None or broker._delete_action_original is not None:
                require(type(broker.delete_action) is _BrokerDeleteAction
                        and broker.delete_action is broker._delete_action_original,
                        "API_DELETE_OWNER_CHANGED")
                _BrokerDeleteAction._state_check(broker.delete_action)
        finally:
            self.checking = False

    def _io(self, function, *args, **kwargs):
        self._transport_check()
        try:
            return function(*args, **kwargs)
        finally:
            self._transport_check()

    def _close_memfd(self):
        fd, self.memfd, self._memfd_original = self._memfd_original, None, None
        if fd is not None:
            try:
                require(_Broker._fd_pin(fd) == self._memfd_pin, "API_CLOSE_FD_REUSED")
                os.close(fd)
            except BaseException as exc:
                self.cleanup_failure = self.cleanup_failure or exc
                raise

    def close(self):
        if not self.closed:
            self.closed, self.ready = True, False
            self.tls = self._tls_original = None
            try:
                self._close_memfd()
            except BaseException:
                pass  # continue retiring independently owned socket; failure retained
            sock, self.sock, self._socket_original = self._socket_original, None, None
            if sock is not None:
                try:
                    require(sock.fileno() == self._socket_fd and _Broker._fd_pin(self._socket_fd) == self._socket_pin,
                            "API_CLOSE_FD_REUSED")
                    sock.close()
                except BaseException as exc:
                    self.cleanup_failure = self.cleanup_failure or exc
                    try:
                        sock.detach()  # never destructor-close a possibly recycled descriptor
                    except BaseException:
                        pass  # preserve the first cleanup error; no retry
        if self.cleanup_failure is not None:
            raise self.cleanup_failure


class _BrokerCreateExchange:
    """Retained request/response data for one CREATE on the original API owner.

    This is not a CREATED journal record, action acknowledgement, cleanup proof
    or native execution grant. The exact intent remains held throughout.
    """
    def __init__(self, broker):
        self.failed = self.complete = self.attempted = False
        self.response_raw = self._response_original = None
        try:
            require(type(self) is _BrokerCreateExchange and type(broker) is _Broker
                    and broker.exchange is broker._exchange_original is self, "API_EXCHANGE_OWNER")
            self.broker, self.owner = broker, broker.owner
            self.api, self.intent, self.events = broker.api, broker.intent, broker.events
            require(type(self.api) is _BrokerApi and self.api is broker._api_original and self.api.ready,
                    "API_EXCHANGE_AUTHENTICATION_REQUIRED")
            require(type(self.intent) is _BrokerIntent and self.intent is broker._intent_original
                    and self.intent.committed and not self.intent.failed, "API_EXCHANGE_INTENT_REQUIRED")
            self.action_raw, self.deadline = self.intent.action_raw, broker.deadline
            self.request_raw = self._request()
            self._state_check()
            self.api._transport_check()  # includes original intent, observer and peer
            self.attempted = True  # even partial writes/late returns never retry
            _TLS.write(self.api.tls, self.request_raw)
            self.api._transport_check()
            _, raw = read_http(self.api.tls, response=True)
            self.api._transport_check()
            # Preserve the existing strict HTTP/canonical-object profile. No new
            # success codes, normalization, endpoint or response wrapper is added.
            require(type(raw) is bytes and 0 < len(raw) <= 16384, "API_EXCHANGE_RESPONSE_SIZE")
            _create_record(document(self.intent.reservation_raw), self.intent.operation,
                self.intent.profile_raw, self.intent.binding_raw, document(self.action_raw), observed=raw)
            self.response_raw = self._response_original = raw
            self.api._transport_check()
        except BaseException:
            self.failed = True
            raise

    def _request(self):
        action = document(self.action_raw, 16384)
        require(action.get("verb") == "CREATE", "API_EXCHANGE_CREATE_REQUIRED")
        profile = document(self.intent.profile_raw)
        resources = [r for r in profile["resources"] if r["manifestDigest"] == action["manifestDigest"]]
        require(len(resources) == 1, "API_EXCHANGE_MANIFEST_REQUIRED")
        manifest = resources[0]["manifest"]
        plural = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[manifest["kind"]]
        namespace = manifest["metadata"]["namespace"]
        require(manifest["apiVersion"] == "v1" and namespace == profile["binding"]["namespace"]
                and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", namespace), "API_EXCHANGE_PATH_SCOPE")
        body = canonical_bytes(manifest)
        require(0 < len(body) <= 16384 and byte_digest(body) == action["manifestDigest"], "API_EXCHANGE_BODY_SCOPE")
        return http_message("POST /api/v1/namespaces/" + namespace + "/" + plural + " HTTP/1.1",
                            body, self.api.endpoint["tls"]["serverName"])

    def _state_check(self):
        broker, api, intent = self.broker, self.api, self.intent
        require(type(self) is _BrokerCreateExchange and not self.failed
                and type(broker) is _Broker and broker.exchange is broker._exchange_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and broker.api is broker._api_original is api and type(api) is _BrokerApi
                and api.broker is broker and api.owner is self.owner and api.ready
                and broker.events is broker._events_original is self.events and api.events is self.events
                and broker.intent is broker._intent_original is intent and type(intent) is _BrokerIntent
                and intent.broker is broker and intent.owner is self.owner and intent.events is self.events
                and intent.committed and not intent.failed and not intent.log.poisoned
                and self.action_raw == intent.action_raw == api.action_raw
                and canonical_bytes(self.events.transcript.pending) == self.action_raw
                and self.deadline == broker.deadline == api.deadline == self.owner.deadline,
                "API_EXCHANGE_STATE_CHANGED")
        intent._history_check()
        require(type(self.request_raw) is bytes and self.request_raw == self._request(), "API_EXCHANGE_REQUEST_CHANGED")
        require(self.response_raw == self._response_original
                and (self.response_raw is None or type(self.response_raw) is bytes), "API_EXCHANGE_RESPONSE_CHANGED")

    def check(self):
        """Recheck retained candidate data; never return a resource or permission."""
        try:
            require(self.complete, "API_EXCHANGE_NOT_COMPLETE")
            self._state_check()
            self.api._transport_check()
            self._state_check()
        except BaseException:
            self.failed = self.broker.failed = True
            self.intent._poison()
            try:
                self.broker.close()
            except BaseException:
                pass
            raise


def _read_api_get_response(tls):
    """Strict server-only resource response; HTTP404 stays a negative status.

    No change to the campaign HTTP codec, no generic status fallback and no
    automatic retry. A404 body still needs original resource/UID validation.
    """
    require(type(tls) is _TLS and type(tls.owner) is _BrokerApi
            and tls.owner.tls is tls.owner._tls_original is tls, "API_GET_TLS_REQUIRED")
    data = bytearray()
    header_deadline = min(tls.deadline, time.monotonic() + 10)
    while b"\r\n\r\n" not in data:
        require(len(data) < 16384, "HTTP_HEADERS_SIZE")
        part = tls.read(min(4096, 16384 - len(data)), header_deadline)
        require(part, "HTTP_TRUNCATED_HEADERS")
        data.extend(part)
    headers, body = bytes(data).split(b"\r\n\r\n", 1)
    require(len(headers) + 4 <= 16384, "HTTP_HEADERS_INVALID")
    lines, fields = headers.split(b"\r\n"), {}
    require(1 <= len(lines) <= 32, "HTTP_HEADERS_INVALID")
    require(lines[0] in (b"HTTP/1.1 200 OK", b"HTTP/1.1 404 Not Found"), "HTTP_STATUS_INVALID")
    for line in lines[1:]:
        require(b": " in line and not line.startswith((b" ", b"\t")), "HTTP_HEADERS_INVALID")
        name, value = line.split(b": ", 1)
        name = name.lower()
        require(name in (b"content-type", b"content-length", b"connection") and name not in fields
                and value and all(32 <= n <= 126 for n in value), "HTTP_HEADER_FORBIDDEN")
        fields[name] = value
    require(set(fields) == {b"content-type", b"content-length", b"connection"}
            and fields[b"content-type"] == b"application/json" and fields[b"connection"] == b"close"
            and re.fullmatch(b"0|[1-9][0-9]{0,6}", fields[b"content-length"]), "HTTP_HEADERS_INVALID")
    size = int(fields[b"content-length"])
    require(0 < size <= 16384, "BROKER_GET_RESPONSE_SIZE")
    require(len(body) <= size, "HTTP_SURPLUS")
    while len(body) < size:
        part = tls.read(min(65536, size + 1 - len(body)))
        require(part, "HTTP_TRUNCATED_BODY")
        body += part
        require(len(body) <= size, "HTTP_SURPLUS")
    require(tls.ssl.pending() == 0, "HTTP_PIPELINING")
    require(tls.read(1) == b"", "HTTP_SURPLUS")
    return lines[0], body


class _BrokerGetAction:
    """One server-owned GET exchange, result and retirement.

    The recorded CREATE UID is the upper bound, not an invitation to adopt a
    named object. A generic transport error is never ABSENT. This owner writes
    no journal row; the separate absence recorder must commit before an ABSENT
    result. Neither object alone can release capacity or complete cleanup.
    """
    def __init__(self, broker):
        self.failed = self.complete = self.attempted = self.send_attempted = False
        self.sent = self.retired = self.advanced = False
        self.response_raw = self._response_original = None
        self.response_status = self._status_original = None
        self.outcome = None
        self.frame_raw = self.after = None
        self.observed_mono = self._observed_mono_original = None
        try:
            require(type(self) is _BrokerGetAction and type(broker) is _Broker
                    and broker.get_action is broker._get_action_original is self,
                    "BROKER_GET_OWNER")
            self.broker, self.owner = broker, broker.owner
            self.api, self.events, self.start = broker.api, broker.events, broker.dispatch
            self._cleanup_api_original = self.api
            require(type(self.api) is _BrokerApi and self.api is broker._api_original
                    and self.api.ready and not self.api.closed and not self.api.failed
                    and type(self.events) is _BrokerEvents and self.events is broker._events_original
                    and type(self.start) is _BrokerStart and self.start is broker._dispatch_original,
                    "BROKER_GET_PREREQUISITES")
            self.action_raw = self.api.action_raw
            self.profile_raw = canonical_bytes(self.owner.profile)
            self.ledger_raw, self.before = self.start.ledger_raw, self.events.transcript_raw
            self.deadline = broker.deadline
            self.record_raw, self.manifest_raw = self._record()
            self.socket, self.tls = self.api._socket_original, self.api._tls_original
            self.secrets = self.api.secrets
            self.transport_pin = (self.api._socket_fd, self.api._socket_pin, self.api._memfd_pin,
                                  self.api.endpoint_raw, self.api.ca, self.api._target_original)
            self.request_raw = self._request()
            self._check()
            self.attempted = True  # no automatic retry, including a late/partial read
            _TLS.write(self.tls, self.request_raw)
            self._check()
            status_line, raw = _read_api_get_response(self.tls)
            self._check()
            require(type(raw) is bytes and 0 < len(raw) <= 16384, "BROKER_GET_RESPONSE_SIZE")
            if status_line == b"HTTP/1.1 200 OK":
                validate_observed_manifest(raw, self.manifest_raw, document(self.record_raw)["uid"])
                self.outcome = "PRESENT"
            else:
                validate_absent_status(raw, self.manifest_raw, document(self.record_raw)["uid"])
                self.outcome = "ABSENT"
            self.response_status = self._status_original = status_line
            self.response_raw = self._response_original = raw
            self.observed_mono = self._observed_mono_original = time.monotonic()
            self.frame_raw, self.after = self._candidate()
            self._check()
        except BaseException:
            self.failed = True
            raise

    def _record(self):
        action = document(self.action_raw, 16384)
        require(set(action) == {"actionId", "verb", "manifestDigest"} and action["verb"] == "GET",
                "BROKER_GET_ACTION_REQUIRED")
        profile = document(self.profile_raw)
        manifests = [r["manifest"] for r in profile["resources"]
                     if r["manifestDigest"] == action["manifestDigest"]]
        require(len(manifests) == 1, "BROKER_GET_MANIFEST_REQUIRED")
        manifest = manifests[0]
        states, _, _ = parse_reservations(self.ledger_raw)
        prior = states.get((self.owner.envelope["tenantId"], self.owner.envelope["nonce"]))
        require(prior is not None and prior["held"] is True and prior["current"] == self.start.operation
                and canonical_bytes(prior["binding"]) == self.start.reservation_raw,
                "BROKER_GET_RUNNING_REQUIRED")
        key = (manifest["apiVersion"], manifest["kind"], manifest["metadata"]["namespace"],
               manifest["metadata"]["name"])
        record = prior.get("resources", {}).get(key)
        require(record is not None and record["state"] == "CREATED"
                and record["operation"] == self.start.operation
                and record["manifestDigest"] == action["manifestDigest"]
                and type(action["actionId"]) is int and record["actionId"] < action["actionId"]
                and type(record["uid"]) is str and record["uid"], "BROKER_GET_CREATED_UID_REQUIRED")
        require(tuple(record[k] for k in ("apiVersion", "kind", "namespace", "name")) == key,
                "BROKER_GET_RESOURCE_CHANGED")
        return canonical_bytes(record), canonical_bytes(manifest)

    def _request(self):
        manifest = document(self.manifest_raw, 16384)
        namespace, name = (manifest["metadata"][k] for k in ("namespace", "name"))
        plural = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[manifest["kind"]]
        require(manifest["apiVersion"] == "v1"
                and namespace == document(self.profile_raw)["binding"]["namespace"]
                and all(type(v) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", v)
                        for v in (namespace, name)), "BROKER_GET_PATH_SCOPE")
        return http_message("GET /api/v1/namespaces/" + namespace + "/" + plural + "/" + name + " HTTP/1.1",
                            b"", self.api.endpoint["tls"]["serverName"])

    def _candidate(self):
        import base64
        require(type(self.response_raw) is bytes and 0 < len(self.response_raw) <= 16384,
                "BROKER_GET_RESPONSE_SIZE")
        if self.response_status == b"HTTP/1.1 200 OK":
            require(self.outcome == "PRESENT", "BROKER_GET_OUTCOME_CHANGED")
            validate_observed_manifest(self.response_raw, self.manifest_raw, document(self.record_raw)["uid"])
        else:
            require(self.response_status == b"HTTP/1.1 404 Not Found" and self.outcome == "ABSENT",
                    "BROKER_GET_OUTCOME_CHANGED")
            validate_absent_status(self.response_raw, self.manifest_raw, document(self.record_raw)["uid"])
        before = document(self.before)
        action = document(self.action_raw, 16384)
        require(before["pending"] == action and not before["chunks"]
                and before["cleanup"] is before["terminal"] is None, "BROKER_GET_RESULT_PHASE")
        candidate = BrokerTranscript(self.events.binding_raw, self.events.dispatch_raw)
        for field in ("sequence", "previous", "execution", "pending", "cleanup", "terminal",
                      "receipt_size", "failed_action", "poisoned"):
            setattr(candidate, field, before[field])
        candidate.actions = set(before["actions"])
        require(_BrokerEvents._snapshot(candidate) == self.before, "BROKER_GET_TRANSCRIPT_CHANGED")
        raw = candidate.server_frame("RESOURCE_RESULT", {"actionId": action["actionId"], "outcome": self.outcome,
            "objectBase64": base64.b64encode(self.response_raw).decode("ascii") if self.outcome == "PRESENT" else None})
        require(0 < len(raw) <= 65536, "BROKER_GET_RESULT_SIZE")
        return raw, _BrokerEvents._snapshot(candidate)

    def _state_check(self, closing=False):
        broker, api = self.broker, self.api
        require(type(self) is _BrokerGetAction and not self.failed and type(broker) is _Broker
                and not broker.closed and not broker.failed
                and broker.get_action is broker._get_action_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and type(api) is _BrokerApi and broker.api is broker._api_original is api
                and api.broker is broker and api.owner is self.owner and not api.failed
                and api.events is broker.events is broker._events_original is self.events
                and self.events.start is broker.dispatch is broker._dispatch_original is self.start
                and self.owner.secrets is api.secrets is self.secrets and self.secrets.owner is self.owner
                and all(getattr(broker, n) is getattr(broker, "_" + n + "_original") is None
                        for n in ("intent", "exchange", "created", "result", "retirement", "delete_action")),
                "BROKER_GET_OWNER_CHANGED")
        require(self.deadline == api.deadline == broker.deadline == self.owner.deadline
                and self.action_raw == api.action_raw
                and self.profile_raw == canonical_bytes(self.owner.profile)
                and (self.record_raw, self.manifest_raw) == self._record()
                and self.request_raw == self._request()
                and self.response_raw == self._response_original
                and self.response_status == self._status_original, "BROKER_GET_INPUT_CHANGED")
        absence = broker.absence
        if absence is None and broker._absence_original is None:
            require(self.ledger_raw == self.start.ledger_raw, "BROKER_GET_INPUT_CHANGED")
        else:
            require(type(absence) is _BrokerAbsence and absence is broker._absence_original
                    and absence.action is self, "BROKER_GET_ABSENCE_OWNER_CHANGED")
            _BrokerAbsence._state_check(absence)
        require(self.transport_pin == (api._socket_fd, api._socket_pin, api._memfd_pin,
                                       api.endpoint_raw, api.ca, api._target_original)
                and api.target == api._target_original and canonical_bytes(api.endpoint) == api.endpoint_raw
                and _BrokerApi._inputs(api) == (api.endpoint_raw, api.ca), "BROKER_GET_TRANSPORT_CHANGED")
        flags = (self.complete, self.attempted, self.send_attempted, self.sent, self.retired, self.advanced)
        require(all(type(flag) is bool for flag in flags) and (not self.complete or self.attempted)
                and (not self.sent or self.send_attempted and self.complete)
                and (not self.retired or self.sent) and (not self.advanced or self.retired),
                "BROKER_GET_LIFETIME_CHANGED")
        expected = self.after if self.advanced else self.before
        require(self.events.transcript_raw == expected
                and _BrokerEvents._snapshot(self.events.transcript) == expected, "BROKER_GET_TRANSCRIPT_CHANGED")
        if self.response_raw is None:
            require(not self.complete and self.frame_raw is self.after is self.response_status is self.outcome is None,
                    "BROKER_GET_RESULT_CHANGED")
        else:
            require((self.frame_raw, self.after) == self._candidate(), "BROKER_GET_RESULT_CHANGED")
            require(type(self.observed_mono) in (int, float)
                    and self.observed_mono == self._observed_mono_original
                    and 0 <= self.observed_mono < self.deadline, "BROKER_GET_OBSERVATION_CLOCK")
        if closing or self.retired:
            require(api.closed is True and api.ready is False and api.checking is False
                    and api.cleanup_failure is None and api.sock is api._socket_original is None
                    and api.tls is api._tls_original is None and api.memfd is api._memfd_original is None,
                    "BROKER_GET_API_NOT_CLOSED")
        else:
            require(api.closed is False and api.ready is True and api.cleanup_failure is None
                    and api.sock is api._socket_original is self.socket
                    and api.tls is api._tls_original is self.tls and api.memfd is api._memfd_original is None,
                    "BROKER_GET_API_CHANGED")

    def _guard(self, closing=False):
        self._state_check(closing)
        _BrokerEvents._check(self.events)
        self._state_check(closing)

    def _check(self):
        self._state_check()
        _BrokerApi.check(self.api)
        self._state_check()

    def send_result(self):
        require(self.complete and not self.send_attempted and not self.sent and not self.retired,
                "BROKER_GET_DELIVERY_ORDER")
        self._check()
        if self.outcome == "ABSENT":
            absence = self.broker.absence
            require(type(absence) is _BrokerAbsence and absence is self.broker._absence_original
                    and absence.committed and absence.advanced, "BROKER_GET_ABSENCE_NOT_RECORDED")
            _BrokerAbsence._state_check(absence)
        with self.broker._phase():
            self._guard()
            raw = self.frame_raw
            self.broker._prepare_wait()
            self.send_attempted = True
            try:
                sent = self.broker.sock.send(raw)
                require(type(sent) is int and sent == len(raw), "BROKER_GET_SEND_AMBIGUOUS")
            finally:
                self._guard()
        self._check()
        self.sent = True  # local send, not proof of broker receipt or cleanup

    def handoff(self):
        try:
            require(self.sent and not self.retired and not self.advanced, "BROKER_GET_DELIVERY_REQUIRED")
            self._check()
            broker, events = self.broker, self.events
            with broker._phase():
                self._guard()
                action = document(self.action_raw, 16384)
                require(len(events.handoffs) < 256 and all(document(raw)["actionId"] != action["actionId"]
                        for raw in events.handoffs), "BROKER_GET_HANDOFF_REPLAY")
                try:
                    require(_BrokerApi.close(self.api) is None, "BROKER_GET_CLOSE_RESULT")
                except BaseException:
                    try:
                        _BrokerEvents._check(events)
                        self._guard(closing=True)
                    except BaseException:
                        pass  # preserve original close failure and held ownership
                    raise
                else:
                    self._guard(closing=True)
                self.retired = True
                self._guard()
                BrokerTranscript.accept(events.transcript, self.frame_raw, "SERVER")
                require(_BrokerEvents._snapshot(events.transcript) == self.after, "BROKER_GET_ADVANCE_MISMATCH")
                events.transcript_raw = self.after
                self.advanced = True
                self._guard()
            with broker._phase():
                self._guard()  # fresh final guard; no new lifetime or peer
                archive = canonical_bytes({"actionId": action["actionId"], "verb": "GET",
                    "manifestDigest": action["manifestDigest"], "resultDigest": byte_digest(self.frame_raw),
                    "recordDigest": byte_digest(self.record_raw), "ledgerDigest": byte_digest(self.start.ledger_raw),
                    "transcriptDigest": byte_digest(self.after)})
                events.handoffs += (archive,)
                events.handoffs_raw = canonical_bytes([byte_digest(raw) for raw in events.handoffs])
                broker.api = broker._api_original = None
                broker.get_action = broker._get_action_original = None
                broker.absence = broker._absence_original = None
                broker.last_get = broker._last_get_original = self if self.outcome == "PRESENT" else None
                broker.last_get_raw = broker._last_get_raw_original = (
                    _BrokerGetAction._cleanup_snapshot(self) if self.outcome == "PRESENT" else None)
                _BrokerEvents._check(events)
        except BaseException:
            self.failed = True
            raise

    def _cleanup_snapshot(self):
        """Immutable local observation data, not a reusable delete permission."""
        require(type(self) is _BrokerGetAction and not self.failed and self.complete and self.sent
                and self.retired and self.advanced and self.outcome == "PRESENT"
                and self.response_status == self._status_original == b"HTTP/1.1 200 OK"
                and self.response_raw == self._response_original
                and self.observed_mono == self._observed_mono_original
                and self.api is self._cleanup_api_original,
                "BROKER_DELETE_GET_REQUIRED")
        return canonical_bytes({"action": document(self.action_raw), "record": document(self.record_raw),
            "manifest": document(self.manifest_raw), "response": document(self.response_raw),
            "profileDigest": byte_digest(self.profile_raw), "ledgerDigest": byte_digest(self.ledger_raw),
            "bindingDigest": byte_digest(self.events.binding_raw), "dispatchDigest": byte_digest(self.events.dispatch_raw),
            "resultDigest": byte_digest(self.frame_raw), "transcriptDigest": byte_digest(self.after),
            "observedMonotonic": float(self.observed_mono).hex(), "deadline": float(self.deadline).hex()})


class _BrokerDeleteAction:
    """One guarded UID/version DELETE following the original delivered GET.

    A successful response means only acknowledgement. The original CREATED
    journal record remains held until a separate authenticated GET and durable
    ABSENT record. No response loss, conflict or stale observation permits retry.
    """
    def __init__(self, broker):
        self.failed = self.complete = self.attempted = self.request_written = False
        self.send_attempted = self.sent = self.retired = self.advanced = False
        self.response_raw = self._response_original = self.frame_raw = self.after = None
        try:
            require(type(self) is _BrokerDeleteAction and type(broker) is _Broker
                    and broker.delete_action is broker._delete_action_original is self,
                    "BROKER_DELETE_OWNER")
            self.broker, self.owner = broker, broker.owner
            self.api, self.events, self.start = broker.api, broker.events, broker.dispatch
            require(type(self.api) is _BrokerApi and self.api is broker._api_original
                    and self.api.ready and not self.api.closed and not self.api.failed
                    and type(self.events) is _BrokerEvents and self.events is broker._events_original
                    and type(self.start) is _BrokerStart and self.start is broker._dispatch_original,
                    "BROKER_DELETE_PREREQUISITES")
            self.get = broker.last_get
            require(type(self.get) is _BrokerGetAction and self.get is broker._last_get_original,
                    "BROKER_DELETE_GET_REQUIRED")
            self.get_raw = broker.last_get_raw
            self.action_raw, self.before = self.api.action_raw, self.events.transcript_raw
            self.profile_raw, self.ledger_raw = canonical_bytes(self.owner.profile), self.start.ledger_raw
            self.manifest_raw, self.record_raw = self.get.manifest_raw, self.get.record_raw
            self.deadline, self.observation_pin = broker.deadline, self.start.observation_pin
            self.socket, self.tls, self.secrets = self.api._socket_original, self.api._tls_original, self.api.secrets
            self.transport_pin = (self.api._socket_fd, self.api._socket_pin, self.api._memfd_pin,
                                  self.api.endpoint_raw, self.api.ca, self.api._target_original)
            self.request_raw = self._request()
            self._check()
            self.attempted = True
            _TLS.write(self.tls, self.request_raw)
            self.request_written = True
            self._check()
            status_line, raw = _read_api_get_response(self.tls)
            self._check()
            require(status_line == b"HTTP/1.1 200 OK", "BROKER_DELETE_STATUS_INVALID")
            validate_delete_response(raw, self.manifest_raw, document(self.record_raw)["uid"])
            self.response_raw = self._response_original = raw
            self.frame_raw, self.after = self._candidate()
            self._check()
        except BaseException:
            self.failed = True
            raise

    def _request(self):
        manifest = document(self.manifest_raw, 16384)
        namespace, name = (manifest["metadata"][k] for k in ("namespace", "name"))
        plural = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[manifest["kind"]]
        require(manifest["apiVersion"] == "v1"
                and namespace == document(self.profile_raw)["binding"]["namespace"]
                and all(type(v) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", v)
                        for v in (namespace, name)), "BROKER_DELETE_PATH_SCOPE")
        body = delete_request_body(self.get.response_raw, self.manifest_raw, document(self.record_raw)["uid"])
        return http_message("DELETE /api/v1/namespaces/" + namespace + "/" + plural + "/" + name + " HTTP/1.1",
                            body, self.api.endpoint["tls"]["serverName"])

    def _get_check(self):
        get, broker, events = self.get, self.broker, self.events
        require(type(get) is _BrokerGetAction and broker.last_get is broker._last_get_original is get
                and self.get_raw == broker.last_get_raw == broker._last_get_raw_original
                and _BrokerGetAction._cleanup_snapshot(get) == self.get_raw
                and get.broker is broker and get.owner is self.owner and get.events is events and get.start is self.start
                and get.profile_raw == self.profile_raw and get.ledger_raw == self.ledger_raw
                and get.record_raw == self.record_raw and get.manifest_raw == self.manifest_raw
                and get.deadline == self.deadline and get.api is not self.api
                and type(get.api) is _BrokerApi and get.api.closed and not get.api.ready
                and get.api.cleanup_failure is None and get.api.sock is get.api.tls is get.api.memfd is None,
                "BROKER_DELETE_GET_CHANGED")
        require((self.record_raw, self.manifest_raw) == _BrokerGetAction._record(get),
                "BROKER_DELETE_CREATED_UID_REQUIRED")
        action, previous = document(self.action_raw, 16384), document(get.action_raw, 16384)
        require(set(action) == {"actionId", "verb", "manifestDigest"} and action["verb"] == "DELETE"
                and action["manifestDigest"] == previous["manifestDigest"]
                and type(action["actionId"]) is int and previous["actionId"] < action["actionId"] <= 256,
                "BROKER_DELETE_ACTION_REQUIRED")
        require(events.handoffs and type(events.handoffs[-1]) is bytes, "BROKER_DELETE_GET_REQUIRED")
        archive = document(events.handoffs[-1])
        require(archive == {"actionId": previous["actionId"], "verb": "GET",
            "manifestDigest": previous["manifestDigest"], "resultDigest": byte_digest(get.frame_raw),
            "recordDigest": byte_digest(self.record_raw), "ledgerDigest": byte_digest(self.ledger_raw),
            "transcriptDigest": byte_digest(get.after)}, "BROKER_DELETE_GET_NOT_LAST")
        require(not any(document(raw)["verb"] == "DELETE" and
                        document(raw)["manifestDigest"] == action["manifestDigest"] for raw in events.handoffs),
                "BROKER_DELETE_RETRY_FORBIDDEN")
        frame = document(get.frame_raw)
        incoming = {**frame, "sequence": frame["sequence"] + 1, "previousDigest": byte_digest(get.frame_raw),
                    "kind": "RESOURCE_ACTION", "payload": action}
        before, after_get = document(self.before), document(get.after)
        require(before == {**after_get, "sequence": incoming["sequence"], "previous": canonical_digest(incoming),
                           "pending": action, "actions": sorted(after_get["actions"] + [action["actionId"]])},
                "BROKER_DELETE_GET_NOT_IMMEDIATE")
        # Observation and exact UID/version are both required. The short freshness
        # window never renews the signed deadline; after the one write it grants no retry.
        require(self.observation_pin == self.start.observation_pin, "BROKER_DELETE_GENERATION_CHANGED")
        if not self.request_written:
            now = time.monotonic()
            require(get.observed_mono <= now < min(get.observed_mono + 5, self.deadline),
                    "BROKER_DELETE_GET_STALE")

    def _candidate(self):
        validate_delete_response(self.response_raw, self.manifest_raw, document(self.record_raw)["uid"])
        before, action = document(self.before), document(self.action_raw, 16384)
        require(before["pending"] == action and not before["chunks"]
                and before["cleanup"] is before["terminal"] is None, "BROKER_DELETE_RESULT_PHASE")
        candidate = BrokerTranscript(self.events.binding_raw, self.events.dispatch_raw)
        for field in ("sequence", "previous", "execution", "pending", "cleanup", "terminal",
                      "receipt_size", "failed_action", "poisoned"):
            setattr(candidate, field, before[field])
        candidate.actions = set(before["actions"])
        require(_BrokerEvents._snapshot(candidate) == self.before, "BROKER_DELETE_TRANSCRIPT_CHANGED")
        raw = candidate.server_frame("RESOURCE_RESULT", {"actionId": action["actionId"],
                                    "outcome": "DELETED", "objectBase64": None})
        return raw, _BrokerEvents._snapshot(candidate)

    def _state_check(self, closing=False):
        broker, api = self.broker, self.api
        require(type(self) is _BrokerDeleteAction and not self.failed and type(broker) is _Broker
                and not broker.closed and not broker.failed
                and broker.delete_action is broker._delete_action_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and type(api) is _BrokerApi and broker.api is broker._api_original is api
                and api.broker is broker and api.owner is self.owner and not api.failed
                and api.events is broker.events is broker._events_original is self.events
                and self.events.start is broker.dispatch is broker._dispatch_original is self.start
                and self.owner.secrets is api.secrets is self.secrets and self.secrets.owner is self.owner
                and all(getattr(broker, n) is getattr(broker, "_" + n + "_original") is None for n in
                        ("intent", "exchange", "created", "result", "retirement", "get_action", "absence")),
                "BROKER_DELETE_OWNER_CHANGED")
        require(self.deadline == api.deadline == broker.deadline == self.owner.deadline
                and self.action_raw == api.action_raw and self.profile_raw == canonical_bytes(self.owner.profile)
                and self.ledger_raw == self.start.ledger_raw and self.request_raw == self._request()
                and self.response_raw == self._response_original, "BROKER_DELETE_INPUT_CHANGED")
        self._get_check()
        require(self.transport_pin == (api._socket_fd, api._socket_pin, api._memfd_pin,
                                       api.endpoint_raw, api.ca, api._target_original)
                and api.target == api._target_original and canonical_bytes(api.endpoint) == api.endpoint_raw
                and _BrokerApi._inputs(api) == (api.endpoint_raw, api.ca), "BROKER_DELETE_TRANSPORT_CHANGED")
        flags = (self.complete, self.attempted, self.request_written, self.send_attempted,
                 self.sent, self.retired, self.advanced)
        require(all(type(v) is bool for v in flags) and (not self.request_written or self.attempted)
                and (not self.complete or self.request_written) and (not self.sent or self.send_attempted and self.complete)
                and (not self.retired or self.sent) and (not self.advanced or self.retired),
                "BROKER_DELETE_LIFETIME_CHANGED")
        expected = self.after if self.advanced else self.before
        require(self.events.transcript_raw == expected and _BrokerEvents._snapshot(self.events.transcript) == expected,
                "BROKER_DELETE_TRANSCRIPT_CHANGED")
        if self.response_raw is None:
            require(not self.complete and self.frame_raw is self.after is None, "BROKER_DELETE_RESULT_CHANGED")
        else:
            require((self.frame_raw, self.after) == self._candidate(), "BROKER_DELETE_RESULT_CHANGED")
        if closing or self.retired:
            require(api.closed is True and api.ready is False and api.checking is False
                    and api.cleanup_failure is None and api.sock is api._socket_original is None
                    and api.tls is api._tls_original is None and api.memfd is api._memfd_original is None,
                    "BROKER_DELETE_API_NOT_CLOSED")
        else:
            require(api.closed is False and api.ready is True and api.cleanup_failure is None
                    and api.sock is api._socket_original is self.socket and api.tls is api._tls_original is self.tls
                    and api.memfd is api._memfd_original is None, "BROKER_DELETE_API_CHANGED")

    def _guard(self, closing=False):
        self._state_check(closing)
        _BrokerEvents._check(self.events)
        self._state_check(closing)

    def _check(self):
        self._state_check()
        _BrokerApi.check(self.api)
        self._state_check()

    def send_result(self):
        require(self.complete and not self.send_attempted and not self.sent and not self.retired,
                "BROKER_DELETE_DELIVERY_ORDER")
        self._check()
        with self.broker._phase():
            self._guard()
            self.broker._prepare_wait()
            self.send_attempted = True
            try:
                sent = self.broker.sock.send(self.frame_raw)
                require(type(sent) is int and sent == len(self.frame_raw), "BROKER_DELETE_SEND_AMBIGUOUS")
            finally:
                self._guard()
        self._check()
        self.sent = True

    def handoff(self):
        require(self.sent and not self.retired and not self.advanced, "BROKER_DELETE_DELIVERY_REQUIRED")
        self._check()
        broker, events = self.broker, self.events
        with broker._phase():
            self._guard()
            action = document(self.action_raw)
            require(len(events.handoffs) < 256 and all(document(raw)["actionId"] != action["actionId"]
                    for raw in events.handoffs), "BROKER_DELETE_HANDOFF_REPLAY")
            try:
                require(_BrokerApi.close(self.api) is None, "BROKER_DELETE_CLOSE_RESULT")
            except BaseException:
                try:
                    self._guard(closing=True)
                except BaseException:
                    pass  # preserve original close failure, never release the UID
                raise
            self._guard(closing=True)
            self.retired = True
            self._guard()
            BrokerTranscript.accept(events.transcript, self.frame_raw, "SERVER")
            require(_BrokerEvents._snapshot(events.transcript) == self.after, "BROKER_DELETE_ADVANCE_MISMATCH")
            events.transcript_raw, self.advanced = self.after, True
            self._guard()
        with broker._phase():
            self._guard()
            archive = canonical_bytes({"actionId": action["actionId"], "verb": "DELETE",
                "manifestDigest": action["manifestDigest"], "resultDigest": byte_digest(self.frame_raw),
                "recordDigest": byte_digest(self.record_raw), "ledgerDigest": byte_digest(self.ledger_raw),
                "transcriptDigest": byte_digest(self.after)})
            events.handoffs += (archive,)
            events.handoffs_raw = canonical_bytes([byte_digest(raw) for raw in events.handoffs])
            broker.api = broker._api_original = None
            broker.delete_action = broker._delete_action_original = None
            broker.last_get = broker._last_get_original = None
            broker.last_get_raw = broker._last_get_raw_original = None
            _BrokerEvents._check(events)


class _BrokerAbsence:
    """One durable original-UID absence fact; not terminal or tenant acceptance."""
    def __init__(self, broker):
        self.failed = self.committed = self.writing = self.advanced = False
        self.log = None
        try:
            require(type(self) is _BrokerAbsence and type(broker) is _Broker
                    and broker.absence is broker._absence_original is self, "BROKER_ABSENCE_OWNER")
            self.broker, self.action = broker, broker.get_action
            require(type(self.action) is _BrokerGetAction and self.action is broker._get_action_original
                    and self.action.complete and self.action.outcome == "ABSENT"
                    and not self.action.send_attempted and not self.action.retired,
                    "BROKER_ABSENCE_GET_REQUIRED")
            self.owner, self.events, self.start = broker.owner, self.action.events, self.action.start
            self.log, self.storage = self.owner.log, self.owner.storage
            require(type(self.log) is _AdmissionLog and type(self.storage) is _State
                    and self.log.storage is self.storage and self.storage.owner is self.owner,
                    "BROKER_ABSENCE_STORAGE_OWNER")
            self.before, self.response_raw = self.action.ledger_raw, self.action.response_raw
            self.action_raw, self.profile_raw = self.action.action_raw, self.action.profile_raw
            self.reservation_raw, self.binding_raw = self.start.reservation_raw, self.start.binding_raw
            self.operation, self.deadline = self.start.operation, broker.deadline
            self.now = utc_now()
            resource, proof = _absence_record(self.reservation_raw, self.operation, self.profile_raw,
                self.binding_raw, self.action_raw, self.before, self.response_raw)
            _, previous, count = parse_reservations(self.before)
            self.row_raw = canonical_bytes({"sequence": count + 1, "previousDigest": previous,
                "binding": document(self.reservation_raw), "state": "ABSENT", "operation": self.operation,
                "observedAt": self.now, "cleanup": None, "resource": resource, "absence": proof})
            self.after, self.digest = self.before + self.row_raw + b"\n", byte_digest(self.row_raw)
            parse_reservations(self.after)
            self._state_check()
            _BrokerGetAction._check(self.action)
            with broker._phase():
                self.events._check()
                self._state_check()
                self.writing = True
                digest = broker._io(_AdmissionLog.record_absence, self.log, document(self.reservation_raw),
                    self.operation, self.now, self.profile_raw, self.binding_raw, document(self.action_raw),
                    expected_history=self.before, observed=self.response_raw)
                require(type(digest) is str and digest == self.digest, "BROKER_ABSENCE_COMMIT_MISMATCH")
                require(broker._io(self.storage.read) == self.after, "BROKER_ABSENCE_READBACK_MISMATCH")
                self._state_check()
                self.start.ledger_raw = self.after
                self.advanced = True
                self.events._check()
                self._state_check()
            _BrokerGetAction._check(self.action)
        except BaseException:
            self._poison()
            raise

    def _state_check(self):
        broker, action = self.broker, self.action
        require(type(self) is _BrokerAbsence and not self.failed and type(broker) is _Broker
                and not broker.closed and not broker.failed
                and broker.absence is broker._absence_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and type(action) is _BrokerGetAction and broker.get_action is broker._get_action_original is action
                and action.broker is broker and action.complete and not action.failed and action.outcome == "ABSENT"
                and action.response_status == action._status_original == b"HTTP/1.1 404 Not Found"
                and action.response_raw == action._response_original == self.response_raw
                and action.action_raw == self.action_raw and action.profile_raw == self.profile_raw
                and action.ledger_raw == self.before and action.events is self.events and action.start is self.start
                and type(self.events) is _BrokerEvents and type(self.start) is _BrokerStart
                and broker.events is broker._events_original is self.events
                and broker.dispatch is broker._dispatch_original is self.start
                and self.events.start is self.start and self.start.owner is self.owner and self.start.broker is broker
                and self.owner.log is self.log is self.start.log and type(self.log) is _AdmissionLog
                and not self.log.poisoned and self.log.storage is self.storage is self.owner.storage is self.start.storage
                and type(self.storage) is _State
                and self.storage.owner is self.owner and self.deadline == broker.deadline == self.owner.deadline,
                "BROKER_ABSENCE_INPUT_CHANGED")
        resource, proof = _absence_record(self.reservation_raw, self.operation, self.profile_raw,
            self.binding_raw, self.action_raw, self.before, self.response_raw)
        _, previous, count = parse_reservations(self.before)
        require(self.reservation_raw == self.start.reservation_raw and self.binding_raw == self.start.binding_raw
                and self.operation == self.start.operation
                and self.row_raw == canonical_bytes({"sequence": count + 1, "previousDigest": previous,
                    "binding": document(self.reservation_raw), "state": "ABSENT", "operation": self.operation,
                    "observedAt": self.now, "cleanup": None, "resource": resource, "absence": proof})
                and self.digest == byte_digest(self.row_raw) and self.after == self.before + self.row_raw + b"\n"
                and type(self.advanced) is bool and type(self.writing) is bool and type(self.committed) is bool
                and (not self.advanced or self.writing) and (not self.committed or self.advanced)
                and self.start.ledger_raw == (self.after if self.advanced else self.before),
                "BROKER_ABSENCE_HISTORY_CHANGED")

    def _poison(self):
        self.failed = True
        if self.writing and type(self.log) is _AdmissionLog:
            self.log.poisoned = True


class _BrokerCreated:
    """Exact durable accounting for the original validated CREATE response.

    Borrows the existing owners and advances only the exact expected history.
    No API I/O, broker result, cleanup permission or capacity release is issued.
    """
    def __init__(self, broker):
        self.failed = self.committed = self.writing = self.advanced = False
        self.log = self._log_original = None
        self.broker = self._broker_original = None
        self.intent = self._intent_original = None
        try:
            require(type(self) is _BrokerCreated and type(broker) is _Broker
                    and broker.created is broker._created_original is self, "BROKER_CREATED_OWNER")
            self.broker = self._broker_original = broker
            self.owner, self.exchange = broker.owner, broker.exchange
            self.intent = self._intent_original = broker.intent
            require(type(self.exchange) is _BrokerCreateExchange
                    and self.exchange is broker._exchange_original and self.exchange.complete
                    and self.exchange.attempted and not self.exchange.failed,
                    "BROKER_CREATED_EXCHANGE_REQUIRED")
            require(type(self.intent) is _BrokerIntent and self.intent is broker._intent_original
                    and self.intent.committed and self.intent.advanced and not self.intent.failed,
                    "BROKER_CREATED_INTENT_REQUIRED")
            self.events, self.start = self.intent.events, self.intent.start
            self.api, self.storage = self.exchange.api, self.intent.storage
            self.log = self._log_original = self.intent.log
            self.before = self.intent.after
            self.response_raw = self.exchange.response_raw
            self.action_raw, self.deadline = self.intent.action_raw, broker.deadline
            now = utc_now()
            resource = _create_record(document(self.intent.reservation_raw), self.intent.operation,
                self.intent.profile_raw, self.intent.binding_raw, document(self.action_raw), observed=self.response_raw)
            _, previous, count = parse_reservations(self.before)
            self.row_raw = self._row_original = canonical_bytes(dict(sequence=count + 1,
                previousDigest=previous, binding=document(self.intent.reservation_raw), state="CREATED",
                operation=self.intent.operation, observedAt=now, cleanup=None, resource=resource))
            self.after = self.before + self.row_raw + b"\n"
            parse_reservations(self.after)
            self.digest = byte_digest(self.row_raw)
            self._check()  # original response, API owner, history, observer and peer
            with broker._phase():
                self.events._check()
                self._state_check()
                self.writing = True
                result = broker._io(_AdmissionLog.record_resource, self.log,
                    document(self.intent.reservation_raw), "CREATED", self.intent.operation, now,
                    self.intent.profile_raw, self.intent.binding_raw, document(self.action_raw),
                    expected_history=self.before, observed=self.response_raw)
                require(type(result) is str and result == self.digest, "BROKER_CREATED_COMMIT_MISMATCH")
                require(broker._io(self.storage.read) == self.after, "BROKER_CREATED_READBACK_MISMATCH")
                self.intent._pending_check()
                self._state_check()  # old pin is still required until exact readback
                self.start.ledger_raw = self.after
                self.advanced = True
                self.events._check()  # full exact new history and current observation
                self._state_check()
            self._check()  # post-phase API custody and current peer; no HTTP sent
        except BaseException:
            self._poison()
            raise

    def _state_check(self):
        broker, intent, exchange = self.broker, self.intent, self.exchange
        require(type(self) is _BrokerCreated and not self.failed
                and type(broker) is _Broker and broker is self._broker_original
                and broker.created is broker._created_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and broker.intent is broker._intent_original is intent is self._intent_original
                and type(intent) is _BrokerIntent
                and intent.broker is broker and intent.owner is self.owner and intent.committed
                and intent.advanced and not intent.failed
                and broker.exchange is broker._exchange_original is exchange
                and type(exchange) is _BrokerCreateExchange and exchange.broker is broker
                and exchange.owner is self.owner and exchange.intent is intent
                and exchange.complete and exchange.attempted and not exchange.failed
                and broker.api is broker._api_original is self.api and type(self.api) is _BrokerApi
                and exchange.api is self.api and self.api.ready and not self.api.closed and not self.api.failed
                and broker.events is broker._events_original is self.events
                and self.events is intent.events is exchange.events is self.api.events
                and broker.dispatch is broker._dispatch_original is self.start
                and self.start is intent.start is self.events.start
                and self.owner.storage is self.storage is intent.storage is self.start.storage
                and self.owner.log is self.log is self._log_original is intent.log is self.start.log
                and self.log.storage is self.storage and not self.log.poisoned,
                "BROKER_CREATED_OWNER_CHANGED")
        require(type(self.response_raw) is bytes and 0 < len(self.response_raw) <= 16384
                and self.response_raw == exchange.response_raw == exchange._response_original
                and self.action_raw == exchange.action_raw == intent.action_raw == self.api.action_raw
                and canonical_bytes(self.events.transcript.pending) == self.action_raw
                and self.deadline == broker.deadline == self.owner.deadline == self.api.deadline,
                "BROKER_CREATED_INPUT_CHANGED")
        require(type(self.before) is bytes and self.before == intent.after
                and type(self.row_raw) is bytes and self.row_raw == self._row_original
                and self.digest == byte_digest(self.row_raw)
                and self.after == self.before + self.row_raw + b"\n"
                and type(self.advanced) is bool and type(self.writing) is bool
                and (not self.advanced or self.writing)
                and self.start.ledger_raw == (self.after if self.advanced else self.before),
                "BROKER_CREATED_HISTORY_CHANGED")

    def _check(self):
        self._state_check()
        _BrokerCreateExchange.check(self.exchange)
        self._state_check()

    def check(self):
        """Revalidate durable accounting only; not a result or cleanup grant."""
        try:
            require(self.committed and self.advanced, "BROKER_CREATED_NOT_COMMITTED")
            self._check()
        except BaseException:
            self._poison()
            if type(self._intent_original) is _BrokerIntent:
                _BrokerIntent._poison(self._intent_original)
            broker = self._broker_original
            if type(broker) is not _Broker:
                raise
            broker.failed = True
            try:
                _Broker.close(broker)
            except BaseException:
                pass  # no repair, adoption, retry or foreign resource cleanup
            raise

    def _poison(self):
        self.failed = True
        if self.writing and type(self._log_original) is _AdmissionLog:
            self._log_original.poisoned = True


class _BrokerCreateResult:
    """One original-channel CREATED datagram, not a distributed commit.

    Retains proposed transcript data but does not advance the original parser,
    retire an API connection, receive another action or release any capacity.
    Those transitions require a separately guarded continuation of this owner.
    """
    def __init__(self, broker):
        self.failed = self.complete = self.attempted = False
        self.broker = self._broker_original = None
        self.created = self._created_original = None
        self.intent = None
        try:
            require(type(self) is _BrokerCreateResult and type(broker) is _Broker
                    and broker.result is broker._result_original is self, "BROKER_RESULT_OWNER")
            self.broker = self._broker_original = broker
            self.owner = broker.owner
            self.created = self._created_original = broker.created
            require(type(self.created) is _BrokerCreated and self.created is broker._created_original
                    and self.created.committed and self.created.advanced and not self.created.failed,
                    "BROKER_RESULT_CREATED_REQUIRED")
            self.intent, self.events, self.start = self.created.intent, self.created.events, self.created.start
            self.before = self.events.transcript_raw
            self.response_raw, self.record_raw = self.created.response_raw, self.created.row_raw
            self.action_raw, self.ledger_raw = self.created.action_raw, self.created.after
            self.deadline = broker.deadline
            self.frame_raw, self.after = self._candidate()
            self._check()  # exact durable accounting, API custody and original pending action
            with broker._phase():
                self._guard()
                raw = self.frame_raw  # immutable bytes captured before preparing I/O
                broker._prepare_wait()
                self.attempted = True  # short/error/late sends never restart a datagram
                try:
                    sent = broker.sock.send(raw)
                    require(type(sent) is int and sent == len(raw), "BROKER_RESULT_SEND_AMBIGUOUS")
                finally:
                    self._guard()
            self._check()  # last current API/observer/peer checks before publication
        except BaseException:
            self._poison()
            raise

    def _candidate(self):
        import base64
        before = document(self.before)
        action = document(self.action_raw, 16384)
        require(before["pending"] == action and action["verb"] == "CREATE"
                and not before["chunks"] and before["cleanup"] is None and before["terminal"] is None,
                "BROKER_RESULT_PHASE_INVALID")
        # Reconstruct only detached, validated DATA for the existing codec.
        # No original parser is advanced and no native owner is constructed.
        candidate = BrokerTranscript(self.events.binding_raw, self.events.dispatch_raw)
        for field in ("sequence", "previous", "execution", "pending", "cleanup", "terminal",
                      "receipt_size", "failed_action", "poisoned"):
            setattr(candidate, field, before[field])
        candidate.actions = set(before["actions"])
        require(_BrokerEvents._snapshot(candidate) == self.before, "BROKER_RESULT_TRANSCRIPT_CHANGED")
        frame = {**document(self.events.started_raw, 16384), "sequence": candidate.sequence + 1,
            "previousDigest": candidate.previous, "kind": "RESOURCE_RESULT",
            "payload": {"actionId": action["actionId"], "outcome": "CREATED",
                        "objectBase64": base64.b64encode(self.response_raw).decode("ascii")}}
        raw = canonical_bytes(frame)
        require(0 < len(raw) <= 65536, "BROKER_RESULT_FRAME_SIZE")
        BrokerTranscript.accept(candidate, raw, "SERVER")
        return raw, _BrokerEvents._snapshot(candidate)

    def _state_check(self):
        broker, created = self.broker, self.created
        require(type(self) is _BrokerCreateResult and not self.failed
                and type(broker) is _Broker and broker is self._broker_original
                and broker.result is broker._result_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and type(created) is _BrokerCreated and created is self._created_original
                and broker.created is broker._created_original is created
                and created.broker is broker and created.owner is self.owner
                and created.committed and created.advanced and not created.failed
                and created.intent is self.intent and broker.intent is broker._intent_original is self.intent
                and created.events is self.events and broker.events is broker._events_original is self.events
                and created.start is self.start and broker.dispatch is broker._dispatch_original is self.start,
                "BROKER_RESULT_OWNER_CHANGED")
        _BrokerCreated._state_check(created)
        require(self.before == self.events.transcript_raw == _BrokerEvents._snapshot(self.events.transcript)
                and self.action_raw == created.action_raw and self.response_raw == created.response_raw
                and self.record_raw == created.row_raw and self.ledger_raw == created.after == self.start.ledger_raw
                and self.deadline == broker.deadline == self.owner.deadline,
                "BROKER_RESULT_INPUT_CHANGED")
        require((self.frame_raw, self.after) == self._candidate(), "BROKER_RESULT_CANDIDATE_CHANGED")

    def _guard(self):
        self._state_check()
        self.events._check()  # original broker phase: full current history, observer and peer
        self._state_check()

    def _check(self):
        self._state_check()
        _BrokerCreated.check(self.created)
        self._state_check()

    def check(self):
        """Recheck the retained send; no retransmit, acknowledgement or retirement."""
        try:
            require(self.complete and self.attempted, "BROKER_RESULT_NOT_COMPLETE")
            self._check()
        except BaseException:
            self._poison()
            broker = self._broker_original
            if type(broker) is _Broker:
                broker.failed = True
                try:
                    _Broker.close(broker)
                except BaseException:
                    pass  # only original resources; no broad cleanup or resend
            raise

    def _poison(self):
        self.failed = True
        if type(self._created_original) is _BrokerCreated:
            _BrokerCreated._poison(self._created_original)


class _BrokerCreateRetirement:
    """One-way local retirement, not broker receipt or next-action authority.

    Old pending-action guards are consumed before close. A sealed original-owner
    record then guards the closed API and advanced transcript; it never reopens
    the API, resets the action owners, writes the journal or releases capacity.
    """
    def __init__(self, broker):
        self.failed = self.complete = self.retired = self.advanced = False
        self.broker = self._broker_original = None
        self.result = self._result_original = None
        try:
            require(type(self) is _BrokerCreateRetirement and type(broker) is _Broker
                    and broker.retirement is broker._retirement_original is self,
                    "BROKER_RETIREMENT_OWNER")
            self.broker = self._broker_original = broker
            self.result = self._result_original = broker.result
            require(type(self.result) is _BrokerCreateResult and self.result is broker._result_original
                    and self.result.complete is True and self.result.attempted is True
                    and not self.result.failed, "BROKER_RETIREMENT_DELIVERY_REQUIRED")
            _BrokerCreateResult.check(self.result)  # last full live-API/pending-action guard
            self.owner, self.created = broker.owner, self.result.created
            self.intent, self.exchange, self.api = self.created.intent, self.created.exchange, self.created.api
            self.events, self.start = self.result.events, self.result.start
            self.log, self.storage, self.secrets = self.created.log, self.created.storage, self.api.secrets
            self.socket = self._socket_original = self.api._socket_original
            self.tls = self._tls_original = self.api._tls_original
            self.before, self.after, self.frame_raw = self.result.before, self.result.after, self.result.frame_raw
            self.ledger_raw, self.deadline = self.result.ledger_raw, broker.deadline
            self.data_pin = self._retained_data()
            with broker._phase():
                self._check()
                try:
                    require(_BrokerApi.close(self.api) is None, "BROKER_RETIREMENT_CLOSE_RESULT")
                except BaseException:
                    # Recheck even a failed close, without hiding its first error.
                    try:
                        self._check(closing=True)
                    except BaseException:
                        pass  # original close error and sticky cleanup remain authoritative
                    raise
                else:
                    self._check(closing=True)
                self.retired = True
                self._check()
                # This is the exact frame already attempted on the original channel.
                # No send, receive, acknowledgement or detached parser substitution.
                BrokerTranscript.accept(self.events.transcript, self.frame_raw, "SERVER")
                require(_BrokerEvents._snapshot(self.events.transcript) == self.after,
                        "BROKER_RETIREMENT_ADVANCE_MISMATCH")
                self.events.transcript_raw = self.after
                self.advanced = True
                self._check()
            # An independent final phase catches authority loss before publication.
            with broker._phase():
                self._check()
        except BaseException:
            self._poison()
            raise

    def _retained_data(self):
        result, created, intent, exchange, api = self.result, self.created, self.intent, self.exchange, self.api
        require(type(api._socket_pin) is tuple and type(api._memfd_pin) is tuple
                and len(api._socket_pin) == len(api._memfd_pin) == 3
                and all(type(value) is int for value in (*api._socket_pin, *api._memfd_pin)),
                "BROKER_RETIREMENT_DESCRIPTOR_PIN")
        values = (result.before, result.after, result.frame_raw, result.response_raw, result.record_raw,
            result.action_raw, result.ledger_raw, result.deadline, result.complete, result.attempted,
            created.before, created.after, created.row_raw, created._row_original, created.digest,
            created.response_raw, created.action_raw, created.deadline, created.committed, created.writing, created.advanced,
            intent.before, intent.after, intent.row_raw, intent.digest, intent.action_raw, intent.profile_raw,
            intent.reservation_raw, intent.binding_raw, intent.operation, intent.deadline,
            intent.committed, intent.writing, intent.advanced,
            exchange.request_raw, exchange.response_raw, exchange._response_original, exchange.action_raw,
            exchange.deadline, exchange.complete, exchange.attempted,
            api.action_raw, api.endpoint_raw, api.ca, api.deadline, api._socket_fd,
            *api._socket_pin, *api._memfd_pin,
            canonical_bytes(api.endpoint), canonical_bytes(self.owner.profile))
        require(all(type(value) in (bytes, str, int, float, bool, type(None)) for value in values),
                "BROKER_RETIREMENT_DATA_TYPE")
        return tuple((type(value), value) for value in values)  # immutable, exact builtin types

    def _owners_check(self):
        broker, result, created, intent, exchange, api = (
            self.broker, self.result, self.created, self.intent, self.exchange, self.api)
        require(type(self) is _BrokerCreateRetirement and not self.failed
                and type(broker) is _Broker and broker is self._broker_original
                and not broker.closed and not broker.failed
                and broker.retirement is broker._retirement_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and type(result) is _BrokerCreateResult and result is self._result_original
                and broker.result is broker._result_original is result and not result.failed
                and result.broker is result._broker_original is broker and result.owner is self.owner
                and type(created) is _BrokerCreated and broker.created is broker._created_original is created
                and result.created is result._created_original is created and not created.failed
                and created.broker is created._broker_original is broker and created.owner is self.owner
                and type(intent) is _BrokerIntent and broker.intent is broker._intent_original is intent
                and result.intent is created.intent is created._intent_original is intent and not intent.failed
                and intent.broker is broker and intent.owner is self.owner
                and type(exchange) is _BrokerCreateExchange
                and broker.exchange is broker._exchange_original is created.exchange is exchange
                and exchange.broker is broker and exchange.owner is self.owner
                and exchange.intent is intent and not exchange.failed
                and type(api) is _BrokerApi and broker.api is broker._api_original is created.api is exchange.api is api
                and api.broker is broker and api.owner is self.owner and not api.failed
                and type(self.events) is _BrokerEvents and type(self.start) is _BrokerStart
                and type(self.storage) is _State and type(self.log) is _AdmissionLog
                and type(self.secrets) is _Files
                and broker.events is broker._events_original is result.events is created.events is intent.events
                    is exchange.events is api.events is self.events
                and broker.dispatch is broker._dispatch_original is result.start is created.start is intent.start is self.start
                and self.owner.storage is self.storage is created.storage is intent.storage is self.start.storage
                and self.owner.log is self.log is created.log is created._log_original is intent.log is self.start.log
                and self.log.storage is self.storage and not self.log.poisoned
                and self.owner.secrets is api.secrets is self.secrets and self.secrets.owner is self.owner,
                "BROKER_RETIREMENT_OWNER_CHANGED")

    def _state_check(self, closing=False):
        self._owners_check()
        broker, result, api = self.broker, self.result, self.api
        require(self._retained_data() == self.data_pin
                and self.result.before == self.before and self.result.after == self.after
                and self.result.frame_raw == self.frame_raw and self.result.ledger_raw == self.ledger_raw
                and self.start.ledger_raw == self.ledger_raw
                and self.deadline == broker.deadline == self.owner.deadline
                and _BrokerCreateResult._candidate(result) == (self.frame_raw, self.after)
                and _BrokerApi._inputs(api) == (api.endpoint_raw, api.ca)
                and api.target == api._target_original, "BROKER_RETIREMENT_DATA_CHANGED")
        expected = self.after if self.advanced else self.before
        require(type(self.retired) is bool and type(self.advanced) is bool
                and (not self.advanced or self.retired)
                and self.events.transcript_raw == expected
                and _BrokerEvents._snapshot(self.events.transcript) == expected,
                "BROKER_RETIREMENT_TRANSCRIPT_CHANGED")
        if closing or self.retired:
            require(api.closed is True and api.ready is False and api.checking is False
                    and api.cleanup_failure is None and api.sock is api._socket_original is None
                    and api.tls is api._tls_original is None and api.memfd is api._memfd_original is None,
                    "BROKER_RETIREMENT_API_NOT_CLOSED")
        else:
            require(api.closed is False and api.ready is True and api.cleanup_failure is None,
                    "BROKER_RETIREMENT_API_NOT_READY")
            require(api.sock is api._socket_original is self.socket is self._socket_original
                    and api.tls is api._tls_original is self.tls is self._tls_original
                    and api.memfd is api._memfd_original is None,
                    "BROKER_RETIREMENT_TRANSPORT_CHANGED")

    def _check(self, closing=False):
        # Fresh independently owned authority/history/observer/peer checks bracket
        # the closed-owner data view. Never call the retired API's live checks.
        self._owners_check()
        _BrokerEvents._check(self.events)
        self._state_check(closing)
        _BrokerEvents._check(self.events)
        self._state_check(closing)

    def check(self):
        try:
            require(self.complete is True and self.retired is True and self.advanced is True,
                    "BROKER_RETIREMENT_NOT_COMPLETE")
            require(type(self.broker) is _Broker and self.broker is self._broker_original,
                    "BROKER_RETIREMENT_OWNER_CHANGED")
            with self.broker._phase():
                self._check()
        except BaseException:
            self._poison()
            broker = self._broker_original
            if type(broker) is _Broker:
                broker.failed = True
                try:
                    _Broker.close(broker)
                except BaseException:
                    pass  # retained journal and first cleanup failure survive
            raise

    def _poison(self):
        self.failed = True
        if type(self._result_original) is _BrokerCreateResult:
            _BrokerCreateResult._poison(self._result_original)


def _receipt_chunks_complete(chunks):
    """Bounded object boundary detection only, never receipt validation or EOF.

    The existing wire format has no end-of-chunks marker. A top-level object
    boundary permits the full strict receipt validator to run; it does not
    authorize cleanup or waive the terminal digest/trailing-frame checks.
    Scan bytes so a UTF-8 code point split between frames is not misdecoded.
    """
    require(type(chunks) is list and 0 < len(chunks) <= 171
            and all(type(part) is bytes and 0 < len(part) <= 24576 for part in chunks)
            and sum(map(len, chunks)) <= 4194304, "BROKER_RECEIPT_CHUNKS_INVALID")
    stack, quoted, escaped, started, ended = [], False, False, False, False
    for part in chunks:
        for value in part:
            if ended:
                require(value in (9, 10, 13, 32), "BROKER_RECEIPT_TRAILING_BYTES")
            elif not started:
                if value in (9, 10, 13, 32):
                    continue
                require(value == 123, "BROKER_RECEIPT_OBJECT_REQUIRED")
                stack.append(125)
                started = True
            elif quoted:
                require(value >= 32, "BROKER_RECEIPT_STRING_CONTROL")
                if escaped:
                    escaped = False
                elif value == 92:
                    escaped = True
                elif value == 34:
                    quoted = False
            elif value == 34:
                quoted = True
            elif value in (123, 91):
                require(len(stack) < 16, "BROKER_RECEIPT_DEPTH")
                stack.append(125 if value == 123 else 93)
            elif value in (125, 93):
                require(stack and stack.pop() == value, "BROKER_RECEIPT_DELIMITER")
                ended = not stack
    return ended  # malformed complete JSON still fails the unchanged validator


class _BrokerCompletion:
    """Owned receipt/cleanup/terminal phases; no worker or client acceptance grant."""
    def __init__(self, broker):
        self.failed = self.writing = self.sealed = self.committed = False
        self.send_attempted = self.delivered = self.cleanup_advanced = self.sent = False
        self.receive_attempted = self.received = self.terminal_advanced = self.complete = False
        self.terminal_raw = self.terminal_after = self.final_row = self.final_ledger = None
        self.log = None
        try:
            require(type(self) is _BrokerCompletion and type(broker) is _Broker
                    and broker.completion is broker._completion_original is self, "BROKER_COMPLETION_OWNER")
            self.broker, self.owner = broker, broker.owner
            self.events, self.start = broker.events, broker.dispatch
            require(type(self.events) is _BrokerEvents and self.events is broker._events_original
                    and type(self.start) is _BrokerStart and self.start is broker._dispatch_original,
                    "BROKER_COMPLETION_PREREQUISITES")
            self.log, self.storage = self.owner.log, self.owner.storage
            self.before, self.ledger_before = self.events.transcript_raw, self.start.ledger_raw
            self.chunks = tuple(self.events.transcript.chunks)
            require(self.chunks and len(self.chunks) <= 171 and all(type(c) is bytes and 0 < len(c) <= 24576
                    for c in self.chunks) and 0 < sum(map(len, self.chunks)) <= 4194304,
                    "BROKER_COMPLETION_CHUNKS_REQUIRED")
            self.receipt_raw = b"".join(self.chunks)
            self.profile_raw = canonical_bytes(self.owner.profile)
            self.session_binding_raw = canonical_bytes(self.owner.binding)
            self.regressions_raw = canonical_bytes(self.owner.plan["regressions"]
                if self.start.operation == "FULL_PREDECESSOR_REGRESSION" else {})
            self.reservation_raw, self.binding_raw, self.dispatch_raw = (
                self.start.reservation_raw, self.start.binding_raw, self.start.dispatch_raw)
            self.operation, self.deadline = self.start.operation, broker.deadline
            self.now = utc_now()
            self.receipt_status = self._receipt()["status"]
            states, _, _ = parse_reservations(self.ledger_before)
            prior = states.get((self.owner.envelope["tenantId"], self.owner.envelope["nonce"]))
            require(prior is not None and prior["current"] == self.operation and prior["held"]
                    and canonical_bytes(prior["binding"]) == self.reservation_raw,
                    "BROKER_COMPLETION_RUNNING_REQUIRED")
            remaining = []
            for key, row in sorted(prior.get("resources", {}).items()):
                if row["operation"] == self.operation and row["state"] != "ABSENT":
                    remaining.append({**{k: row[k] for k in
                        ("apiVersion", "kind", "namespace", "name", "uid", "manifestDigest")},
                        "reasonCode": "IO_AMBIGUOUS" if row["uid"] is None else "OBSERVATION_UNAVAILABLE"})
            self.cleanup_raw = canonical_bytes(cleanup_receipt(byte_digest(self.reservation_raw), self.operation,
                self.now, remaining, prior["cleanupDigest"]))
            before = document(self.before)
            require(before["pending"] is before["cleanup"] is before["terminal"] is None,
                    "BROKER_COMPLETION_OUTSTANDING_ACTION")
            self.proof_raw = canonical_bytes({"dispatch": document(self.dispatch_raw), "executionId": before["execution"],
                "receiptDigest": byte_digest(self.receipt_raw), "receiptSize": len(self.receipt_raw),
                "receiptStatus": self.receipt_status, "failedAction": before["failed_action"],
                "cleanupSequence": before["sequence"] + 1, "cleanupPreviousDigest": before["previous"]})
            self.cleanup_frame_raw = canonical_bytes(_completion_frame(document(self.reservation_raw), self.operation,
                document(self.cleanup_raw), document(self.proof_raw)))
            candidate = self._transcript(self.before)
            BrokerTranscript.accept(candidate, self.cleanup_frame_raw, "SERVER")
            self.cleanup_after = _BrokerEvents._snapshot(candidate)
            self.seal_row, self.sealed_ledger = self._row("CLEANUP_SEALED", self.ledger_before, self.now,
                cleanup=document(self.cleanup_raw), completion=document(self.proof_raw))
            self._check()
            with broker._phase():
                self._guard()
                self.writing = True
                digest = broker._io(_AdmissionLog.record_completion, self.log, document(self.reservation_raw),
                    "CLEANUP_SEALED", self.operation, self.now, expected_history=self.ledger_before,
                    cleanup=document(self.cleanup_raw), completion=document(self.proof_raw))
                require(digest == byte_digest(self.seal_row), "BROKER_COMPLETION_COMMIT_MISMATCH")
                require(broker._io(self.storage.read) == self.sealed_ledger, "BROKER_COMPLETION_READBACK_MISMATCH")
                self.start.ledger_raw, self.sealed = self.sealed_ledger, True
                self._guard()
            self._check()
        except BaseException:
            self._poison()
            raise

    def _receipt(self):
        from .live_session import SCHEMA, validate_receipt
        binding = document(self.session_binding_raw)
        session = {k: v for k, v in binding.items() if k not in ("notBefore", "notAfter")}
        session.update(schemaVersion=SCHEMA, issuedAt=binding["notBefore"], expiresAt=binding["notAfter"], state="RUNNING")
        return validate_receipt(self.receipt_raw, session, binding, document(self.start.request_raw),
                                document(self.regressions_raw), self.now)

    def _transcript(self, snapshot):
        before = document(snapshot)
        candidate = BrokerTranscript(self.binding_raw, self.dispatch_raw)
        for field in ("sequence", "previous", "execution", "pending", "cleanup", "terminal",
                      "receipt_size", "failed_action", "poisoned"):
            setattr(candidate, field, before[field])
        candidate.actions, candidate.chunks = set(before["actions"]), list(self.chunks)
        require(_BrokerEvents._snapshot(candidate) == snapshot, "BROKER_COMPLETION_TRANSCRIPT_CHANGED")
        return candidate

    def _row(self, state, history, now, **extra):
        _, previous, count = parse_reservations(history)
        row = canonical_bytes({"sequence": count + 1, "previousDigest": previous,
            "binding": document(self.reservation_raw), "state": state, "operation": self.operation,
            "observedAt": now, "cleanup": None, **extra})
        after = history + row + b"\n"
        parse_reservations(after)
        return row, after

    def _state_check(self):
        broker, events, start = self.broker, self.events, self.start
        require(type(self) is _BrokerCompletion and not self.failed and type(broker) is _Broker
                and not broker.closed and not broker.failed and broker.completion is broker._completion_original is self
                and broker.owner is self.owner and self.owner.broker is self.owner._broker_original is broker
                and broker.events is broker._events_original is events and events.start is start
                and broker.dispatch is broker._dispatch_original is start
                and type(self.log) is _AdmissionLog and not self.log.poisoned
                and self.log is self.owner.log is start.log and self.log.storage is self.storage
                and type(self.storage) is _State and self.storage is self.owner.storage is start.storage
                and self.storage.owner is self.owner and self.deadline == broker.deadline == self.owner.deadline
                and all(getattr(broker, n) is getattr(broker, "_" + n + "_original") is None for n in
                        ("api", "intent", "exchange", "created", "result", "retirement", "get_action", "absence", "delete_action")),
                "BROKER_COMPLETION_OWNER_CHANGED")
        require(self.profile_raw == canonical_bytes(self.owner.profile)
                and self.session_binding_raw == canonical_bytes(self.owner.binding)
                and self.regressions_raw == canonical_bytes(self.owner.plan["regressions"]
                    if self.operation == "FULL_PREDECESSOR_REGRESSION" else {})
                and self.reservation_raw == start.reservation_raw and self.operation == start.operation
                and self.binding_raw == events.binding_raw == start.binding_raw
                and self.dispatch_raw == events.dispatch_raw == start.dispatch_raw
                and self.receipt_raw == b"".join(self.chunks) and tuple(events.transcript.chunks) == self.chunks
                and self.receipt_status == self._receipt()["status"], "BROKER_COMPLETION_INPUT_CHANGED")
        proof, before = document(self.proof_raw), document(self.before)
        require(proof == {"dispatch": document(self.dispatch_raw), "executionId": before["execution"],
            "receiptDigest": byte_digest(self.receipt_raw), "receiptSize": len(self.receipt_raw),
            "receiptStatus": self.receipt_status, "failedAction": before["failed_action"],
            "cleanupSequence": before["sequence"] + 1, "cleanupPreviousDigest": before["previous"]},
            "BROKER_COMPLETION_PROOF_CHANGED")
        require(self.cleanup_frame_raw == canonical_bytes(_completion_frame(document(self.reservation_raw),
            self.operation, document(self.cleanup_raw), proof)), "BROKER_COMPLETION_FRAME_CHANGED")
        require((self.seal_row, self.sealed_ledger) == self._row("CLEANUP_SEALED", self.ledger_before, self.now,
            cleanup=document(self.cleanup_raw), completion=proof), "BROKER_COMPLETION_HISTORY_CHANGED")
        flags = (self.sealed, self.committed, self.send_attempted, self.delivered, self.cleanup_advanced,
                 self.sent, self.receive_attempted, self.received, self.terminal_advanced, self.complete)
        require(all(type(flag) is bool for flag in flags) and (not self.committed or self.sealed)
                and (not self.delivered or self.send_attempted and self.committed)
                and (not self.cleanup_advanced or self.delivered) and (not self.sent or self.cleanup_advanced)
                and (not self.receive_attempted or self.sent) and (not self.received or self.receive_attempted)
                and (not self.terminal_advanced or self.received) and (not self.complete or self.terminal_advanced),
                "BROKER_COMPLETION_LIFETIME_CHANGED")
        expected = self.terminal_after if self.received else (self.cleanup_after if self.cleanup_advanced else self.before)
        require(events.transcript_raw == expected and _BrokerEvents._snapshot(events.transcript) == expected,
                "BROKER_COMPLETION_TRANSCRIPT_CHANGED")
        candidate = self._transcript(self.before)
        BrokerTranscript.accept(candidate, self.cleanup_frame_raw, "SERVER")
        require(_BrokerEvents._snapshot(candidate) == self.cleanup_after, "BROKER_COMPLETION_FRAME_CHANGED")
        if self.received:
            _completion_terminal(document(self.reservation_raw), self.operation, document(self.cleanup_raw), proof,
                                 self.terminal_raw)
            BrokerTranscript.accept(candidate, self.terminal_raw, "BROKER")
            require(_BrokerEvents._snapshot(candidate) == self.terminal_after, "BROKER_COMPLETION_TERMINAL_CHANGED")
        else:
            require(self.terminal_raw is self.terminal_after is None, "BROKER_COMPLETION_TERMINAL_CHANGED")
        if self.terminal_advanced:
            row = document(self.final_row, 32768)
            require((self.final_row, self.final_ledger) == self._row("TERMINAL_RECORDED", self.sealed_ledger,
                row["observedAt"], terminal=document(self.terminal_raw)), "BROKER_COMPLETION_HISTORY_CHANGED")
        require(start.ledger_raw == (self.final_ledger if self.terminal_advanced else
            self.sealed_ledger if self.sealed else self.ledger_before), "BROKER_COMPLETION_HISTORY_CHANGED")

    def _guard(self):
        self._state_check()
        _BrokerEvents._check(self.events)
        self._state_check()

    def _check(self):
        with self.broker._phase():
            self._guard()

    def send_cleanup(self):
        require(self.committed and not self.send_attempted and not self.sent, "BROKER_COMPLETION_SEND_ORDER")
        broker, events = self.broker, self.events
        with broker._phase():
            self._guard()
            broker._prepare_wait()
            self.send_attempted = True
            try:
                count = broker.sock.send(self.cleanup_frame_raw)
                require(type(count) is int and count == len(self.cleanup_frame_raw), "BROKER_CLEANUP_SEND_AMBIGUOUS")
            finally:
                self._guard()
        self._check()
        self.delivered = True
        with broker._phase():
            self._guard()
            BrokerTranscript.accept(events.transcript, self.cleanup_frame_raw, "SERVER")
            events.transcript_raw, self.cleanup_advanced = self.cleanup_after, True
            self._guard()
        self.sent = True  # local send only; no durable terminal or capacity release

    def poll_terminal(self):
        require(self.sent and not self.receive_attempted and not self.received, "BROKER_TERMINAL_RECEIVE_ORDER")
        broker, events = self.broker, self.events
        with broker._phase():
            self._guard()
            before = time.monotonic()
            require(broker.last_mono <= before < broker.end <= self.deadline, "BROKER_CLOCK_OR_DEADLINE")
            try:
                ready = select.select([broker.sock], [], [broker.sock], min(0.25, (broker.end - before) / 2))
            finally:
                self._guard()
            require(type(ready) is tuple and len(ready) == 3 and ready[1:] == ([], [])
                    and ready[0] in ([], [broker.sock]), "BROKER_READINESS_INVALID")
            if not ready[0]:
                return None
            broker._prepare_wait()
            self.receive_attempted = True
            try:
                raw, ancillary, flags, _ = broker.sock.recvmsg(65537, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4))
                require(credentials(ancillary, flags) == broker._peer_original, "BROKER_MESSAGE_PEER")
            finally:
                self._guard()
            terminal = _completion_terminal(document(self.reservation_raw), self.operation,
                document(self.cleanup_raw), document(self.proof_raw), raw)
            candidate = self._transcript(self.cleanup_after)
            BrokerTranscript.accept(candidate, raw, "BROKER")
            require(broker._io(select.select, [broker.sock], [], [broker.sock], 0) == ([], [], []),
                    "BROKER_TERMINAL_TRAILING_DATA")
            self._guard()
            BrokerTranscript.accept(events.transcript, raw, "BROKER")
            self.terminal_raw, self.terminal_after = canonical_bytes(terminal), _BrokerEvents._snapshot(candidate)
            events.transcript_raw, self.received = self.terminal_after, True
            self._guard()
        self._check()
        return self.terminal_raw  # data only; durable recording remains mandatory

    def record_terminal(self):
        require(self.received and not self.terminal_advanced and not self.complete, "BROKER_TERMINAL_RECORD_ORDER")
        self._check()
        now = utc_now()
        self.final_row, self.final_ledger = self._row("TERMINAL_RECORDED", self.sealed_ledger, now,
                                                   terminal=document(self.terminal_raw))
        with self.broker._phase():
            self._guard()
            self.writing = True
            digest = self.broker._io(_AdmissionLog.record_completion, self.log, document(self.reservation_raw),
                "TERMINAL_RECORDED", self.operation, now, expected_history=self.sealed_ledger,
                terminal=document(self.terminal_raw))
            require(digest == byte_digest(self.final_row), "BROKER_TERMINAL_COMMIT_MISMATCH")
            require(self.broker._io(self.storage.read) == self.final_ledger, "BROKER_TERMINAL_READBACK_MISMATCH")
            self.start.ledger_raw, self.terminal_advanced = self.final_ledger, True
            self._guard()
        self._check()
        self.complete = True  # source-side completion only; never tenant/native acceptance

    def _poison(self):
        self.failed = True
        if self.writing and type(self.log) is _AdmissionLog:
            self.log.poisoned = True


def _failure_reason(error):
    """Closed accounting reason only; never persist arbitrary exception text."""
    reason = error.reason if type(error) is ConformanceError and type(error.reason) is str else None
    if reason in ("BROKER_CLOCK_OR_DEADLINE", "PROXY_CLOCK_OR_EXPIRY", "PROXY_EXPIRED",
                  "BROKER_OBSERVATION_EXPIRED", "API_CONNECT_DEADLINE", "TLS_DEADLINE",
                  "HTTP_HEADER_DEADLINE"):
        return "DEADLINE"
    if reason == "ADMISSION_UID_CHANGED":
        return "UID_CHANGED"
    if reason == "ADMISSION_DELETE_DENIED":
        return "DELETE_DENIED"
    if isinstance(error, OSError) or reason in ("BROKER_SEND_AMBIGUOUS", "BROKER_GET_SEND_AMBIGUOUS",
            "BROKER_DELETE_SEND_AMBIGUOUS", "BROKER_CLEANUP_SEND_AMBIGUOUS", "HTTP_TRUNCATED"):
        return "IO_AMBIGUOUS"
    return "OBSERVATION_UNAVAILABLE"


class _FailureAccounting:
    """Original server's fail-only local append, never a cleanup/execution grant.

    Constructed while the real transport boundary is valid, before dispatch.
    After failure it may use only the original intact journal and file custody;
    it never contacts an observer/broker/API, reads a credential, reopens a file,
    supplies a worker result or extends the execution deadline.
    """
    def __init__(self, owner):
        require(type(owner) is NativeProxyServer and owner.failure_accounting is
                owner._failure_accounting_original is self, "FAILURE_ACCOUNTING_OWNER")
        self.owner, self.broker = owner, owner.broker
        self.storage, self.log, self.files = owner.storage, owner.log, owner.files
        self.store_pin = (self.storage.directory, self.storage.lock, self.storage.fd,
                          canonical_bytes({k: list(v) for k, v in self.storage.identities.items()}))
        self.operation, self.deadline = owner.active_operation, owner.deadline
        self.reservation_raw = canonical_bytes(owner.reservation)
        self.inputs_raw = canonical_bytes([owner.envelope, owner.capacity, owner.profile, owner.plan])
        self.attempted = self.writing = self.complete = False
        self.before = self.after = self.row_raw = None
        self.refusal = None
        self._state_check()
        require(not self.broker.closed and not self.broker.failed and not self.log.poisoned
                and self.log._storage_ambiguous is False and type(self.log._verified_history) is bytes,
                "FAILURE_ACCOUNTING_PREREQUISITES")
        _State.check(self.storage)

    def _state_check(self):
        owner = self.owner
        require(type(self) is _FailureAccounting and type(owner) is NativeProxyServer
                and owner.failure_accounting is owner._failure_accounting_original is self
                and type(self.broker) is _Broker and owner.broker is owner._broker_original is self.broker
                and self.broker.owner is owner and self.broker.deadline == self.deadline == owner.deadline
                and type(self.storage) is _State and owner.storage is self.storage and self.storage.owner is owner
                and self.store_pin == (self.storage.directory, self.storage.lock, self.storage.fd,
                                       canonical_bytes({k: list(v) for k, v in self.storage.identities.items()}))
                and type(self.log) is _AdmissionLog and owner.log is self.log and self.log.storage is self.storage
                and type(self.files) is _Files and owner.files is self.files and self.files.owner is owner
                and owner.reserved is True and owner.active_operation == self.operation and self.operation in CASES
                and self.reservation_raw == canonical_bytes(owner.reservation)
                and self.inputs_raw == canonical_bytes([owner.envelope, owner.capacity, owner.profile, owner.plan]),
                "FAILURE_ACCOUNTING_OWNER_CHANGED")
        NativeProxyServer._owner_check(owner)
        if self.writing:
            require(self.attempted and self.broker.closed and self.broker.failed
                    and self.storage._failure_accounting is self
                    and self.log._storage_ambiguous is False
                    and self.log._verified_history in (self.before, self.after), "FAILURE_ACCOUNTING_STATE_CHANGED")

    def record(self, error):
        # This input is an exception already caught by the fixed driver, not a
        # caller-provided resource list, cleanup result or authority override.
        require(not self.attempted, "FAILURE_ACCOUNTING_ALREADY_ATTEMPTED")
        self.attempted = True
        require(isinstance(error, BaseException), "FAILURE_ACCOUNTING_ERROR_REQUIRED")
        self._state_check()
        require(self.broker.closed and self.broker.failed and self.log._storage_ambiguous is False
                and getattr(self.storage, "_failure_accounting", None) is None,
                "FAILURE_ACCOUNTING_UNAVAILABLE")
        self.before = self.log._verified_history
        require(type(self.before) is bytes, "FAILURE_ACCOUNTING_HISTORY_REQUIRED")
        states, previous, count = parse_reservations(self.before)
        binding = document(self.reservation_raw)
        prior = states.get((binding["tenantId"], binding["runNonce"]))
        require(prior is not None and prior["current"] == self.operation and prior["held"],
                "FAILURE_ACCOUNTING_ACTIVE_CASE_REQUIRED")
        now, reason = utc_now(), _failure_reason(error)
        events = self.broker._events_original
        if (type(error) is ConformanceError and error.reason == "API_EXACT_GRANT_REQUIRED"
                and type(events) is _BrokerEvents and events is self.broker.events
                and events.owner is self.owner and events.start.operation == self.operation
                and type(events.transcript.pending) is dict
                and events.transcript.pending.get("verb") == "DELETE"):
            reason = "DELETE_DENIED"  # accounting only, never a renewed DELETE grant
        cleanup = _failure_cleanup(binding, self.operation, now, prior, reason)
        self.row_raw = canonical_bytes({"sequence": count + 1, "previousDigest": previous,
            "binding": binding, "state": "FAILURE_RECORDED", "operation": self.operation,
            "observedAt": now, "cleanup": cleanup, "failure": {"reasonCode": reason}})
        self.after = self.before + self.row_raw + b"\n"
        parse_reservations(self.after)
        self.storage._failure_accounting = self
        self.writing = True
        self._state_check()
        digest = _AdmissionLog.record_failure(self.log, binding, self.operation, now, reason,
                                             expected_history=self.before)
        self._state_check()
        require(digest == byte_digest(self.row_raw) and self.storage.read() == self.after,
                "FAILURE_ACCOUNTING_READBACK_CHANGED")
        self._state_check()
        self.complete = True  # retained failure evidence only; never an HTTP success


class _State:
    """Exclusive precreated store. Never create, truncate, repair or rotate it."""
    def __init__(self, owner):
        self.owner, self.lock, self.fd = owner, None, None
        self._failure_accounting = None
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
        accounting = getattr(self, "_failure_accounting", None)
        if accounting is not None:
            require(type(accounting) is _FailureAccounting and accounting.storage is self,
                    "ADMISSION_FAILURE_OWNER_CHANGED")
            _FailureAccounting._state_check(accounting)
        self.owner._owner_check()
        self.owner.files.check()
        for attr, name in (("lock", "admission.lock"), ("fd", "reservations.jsonl")):
            expected = self.identities[attr]
            require(_custody_identity(os.fstat(getattr(self, attr)))[:6] == expected
                    and _custody_identity(os.stat(name, dir_fd=self.directory, follow_symlinks=False))[:6] == expected,
                    "ADMISSION_STORE_CHANGED")
        if accounting is not None:
            _FailureAccounting._state_check(accounting)

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
        self.broker = self._broker_original = None
        self.qualification_binding = None
        self.qualification = self._qualification_original = None
        self.self_inspection = None
        self.memfd = None
        self.active_operation = None
        self.failure_accounting = self._failure_accounting_original = None
        self.reserved = False
        self.last_wall, self.last_mono = require_time(utc_now(), "now"), time.monotonic()
        try:
            self.manifest, _, self.artifact_digest = _manifest(self.files, MANIFEST, EXECUTABLE)
            envelope_path = os.environ.get("HARNESS_LIVE_EXECUTION_ENVELOPE")
            require(type(envelope_path) is str, "PROXY_ENVELOPE_UNAVAILABLE")
            self.envelope_path = envelope_path
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
            self.qualification_binding = object.__new__(_ServerQualificationBinding)
            self.qualification_binding.__init__(self)
            self.qualification = self._qualification_original = object.__new__(_KernelQualification)
            self.qualification.__init__(self)
            self.storage = object.__new__(_State)
            self.storage.__init__(self)
            self.log = _AdmissionLog(self.storage)
            self.observer = object.__new__(_Observer)
            self.observer.__init__(self)
            self.qualification.check_peer("OBSERVER", self.observer)
            self.broker = self._broker_original = object.__new__(_Broker)
            self.broker.__init__(self)
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
        require(type(self.qualification) is _KernelQualification
                and self.qualification is self._qualification_original,
                "PROXY_QUALIFICATION_REQUIRED")
        require(_KernelQualification.check_self(self.qualification) is None,
                "PROXY_CONTAINMENT_UNAVAILABLE")

    def _broker_check(self):
        self._owner_check()
        require(type(self.broker) is _Broker and self.broker is self._broker_original
                and self.broker.owner is self, "PROXY_BROKER_REQUIRED")
        require(_KernelQualification.check_peer(self.qualification, "BROKER", self.broker) is None,
                "PROXY_BROKER_CHECK_RESULT")

    def _transport_check(self):
        self._base_check()
        self._broker_check()
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
                receipt_raw = self._drive_case()
                receipt = document(receipt_raw, 4194304)
                self._transport_check()
                tls.write(http_message("HTTP/1.1 200 OK", receipt_raw))
                tls.notify_close()
                if receipt["status"] != "PASS":
                    return
            finally:
                connection, self.connection = self.connection, None
                if connection is not None:
                    connection.close()

    def _drive_case(self):
        """Drive the fixed original broker; never import, call or spawn a worker."""
        self._transport_check()
        broker = self.broker
        require(type(broker) is _Broker and broker is self._broker_original and broker.owner is self
                and self.active_operation in CASES, "PROXY_DRIVER_OWNER_INVALID")
        require(self.failure_accounting is self._failure_accounting_original is None,
                "FAILURE_ACCOUNTING_ALREADY_OWNED")
        self.failure_accounting = self._failure_accounting_original = object.__new__(_FailureAccounting)
        self.failure_accounting.__init__(self)
        try:
            _Broker.begin(broker)
            while True:
                self._transport_check()
                raw = _Broker.poll(broker)
                if raw is None:
                    continue  # bounded poll guards retain the original deadline
                frame = broker_document(raw, "frame")
                if frame["kind"] == "RESOURCE_ACTION":
                    verb = frame["payload"]["verb"]
                    if verb == "CREATE":
                        _Broker.record_create_intent(broker)
                    _Broker.check_action_ownership(broker)
                    _Broker.prepare_api(broker)
                    if verb == "CREATE":
                        _Broker.exchange_api_create(broker)
                        _Broker.record_api_created(broker)
                        _Broker.send_create_result(broker)
                        _Broker.retire_create_result(broker)
                        _Broker.handoff_create_result(broker)
                    elif verb == "GET":
                        _Broker.exchange_api_get(broker)
                        if broker.get_action.outcome == "ABSENT":
                            _Broker.record_get_absence(broker)
                        _Broker.send_get_result(broker)
                        _Broker.handoff_get_result(broker)
                    elif verb == "DELETE":
                        _Broker.exchange_api_delete(broker)
                        _Broker.send_delete_result(broker)
                        _Broker.handoff_delete_result(broker)
                    else:
                        require(False, "BROKER_RESOURCE_VERB_INVALID")
                else:
                    require(frame["kind"] == "RECEIPT_CHUNK", "BROKER_INBOUND_KIND_UNAVAILABLE")
                    if _receipt_chunks_complete(broker.events.transcript.chunks):
                        break
            _Broker.seal_cleanup(broker)
            _Broker.send_cleanup(broker)
            while _Broker.poll_terminal(broker) is None:
                self._transport_check()
            _Broker.record_terminal(broker)
            completion = broker.completion
            require(type(completion) is _BrokerCompletion and completion is broker._completion_original
                    and completion.complete and not completion.failed, "PROXY_TERMINAL_REQUIRED")
            _BrokerCompletion._check(completion)
            receipt_raw = completion.receipt_raw
            if completion.receipt_status == "PASS":
                _Broker.finish_case(broker)
            # FAIL/UNAVAILABLE cannot advance the case or release its capacity.
            self._transport_check()
            self.failure_accounting = self._failure_accounting_original = None
            return receipt_raw
        except BaseException as error:
            broker.failed = True
            try:
                _Broker.close(broker)
            except BaseException:
                pass  # retain every intent/UID/cleanup row; no retry or wider effect
            accounting = self._failure_accounting_original
            try:
                require(type(accounting) is _FailureAccounting, "FAILURE_ACCOUNTING_UNAVAILABLE")
                _FailureAccounting.record(accounting, error)
            except BaseException:
                # An uncertain journal/custody cannot be repaired or bypassed.
                # Preserve the original refusal and all previously durable facts.
                if type(accounting) is _FailureAccounting:
                    accounting.refusal = "ACCOUNTING_UNAVAILABLE"
            raise

    def close(self):
        global _ACTIVE
        if self.closed:
            return
        self.closed = True
        operations, failure = [], None
        broker = getattr(self, "_broker_original", None)
        self.broker = self._broker_original = None
        if broker is not None:
            operations.append(broker.close)  # never close a substituted current attribute
        qualification = getattr(self, "_qualification_original", None)
        self.qualification = self._qualification_original = self.self_inspection = None
        for attr in ("connection", "listener", "observer", "storage"):
            resource = getattr(self, attr, None)
            setattr(self, attr, None)
            if resource is not None:
                operations.append(resource.close)
        if qualification is not None:
            operations.append(qualification.close)
        for attr in ("qualification_binding", "secrets", "files"):
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
