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
from types import FunctionType

from .canonical import byte_digest, canonical_bytes, canonical_digest, require_canonical_document
from .crypto import b64url_decode, verify
from .errors import ConformanceError
from .linux_readiness import CASES, build_probe_request, require_time
from .live import FIXED_RELEASE_TRUST, FIXED_TENANT_TRUST, PINNED_ROOT_PUBLIC_KEY_SHA256
from .live_backend_authority import verify_backend_authority, binding_from_authority
from .live_linux_boundary import credentials, process_identity, _custody_identity
from .live_mutation_admission import (require, document, retained_profile, validate_messages,
    _time, ZERO, admission_binding, _AdmissionLog, parse_reservations, cleanup_receipt,
    retained_qualification_record, retained_broker_binding, QUALIFICATION_PATH)
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
            require(ctypes.sizeof(_KernelStatx) == 256 and ctypes.alignment(_KernelStatx) == 8,
                    "KERNEL_STATX_ABI")
            call = self.lib.statx
            call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_uint, ctypes.POINTER(_KernelStatx))
            call.restype = ctypes.c_int
            output = _KernelStatx()
            # Empty retained fd only; no path lookup, automount or sync fallback.
            required = 0x411b  # TYPE | MODE | UID | GID | INO | MNT_ID_UNIQUE
            try:
                result = call(fd, b"", 0x1900, required, ctypes.byref(output))
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
            require((uid, gid, mode, inode, major, minor) ==
                    (info.st_uid, info.st_gid, info.st_mode, info.st_ino,
                     os.major(info.st_dev), os.minor(info.st_dev)), "KERNEL_STATX_IDENTITY")
            filesystem = self._filesystem(fd)
            after, _ = self._descriptor(fd)
            require((after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode) == identity,
                    "KERNEL_DIRECTORY_CHANGED")
            return dict(identity=identity, mountId=mount_id, filesystem=filesystem)

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
        self.native = _KernelNativeReads()
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.rows = []
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
        try:
            with self._phase():
                self._acquire(self.rows)
            self.check()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # retain cleanup_failure; construction never grants custody
            raise

    def _tick(self):
        require(type(self) is _KernelRootViews and not self.closed and not self.failed and self.busy
                and self.pid == os.getpid() and self.thread == threading.get_ident(), "KERNEL_ROOT_CUSTODY")
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
        now = time.monotonic()
        require(self.last <= now < self.end, "KERNEL_PROCESS_DEADLINE")
        self.last = now
        fd, identity = self.pidfd
        if fd is not None and identity is not None:
            require(self._close_identity(fd) == identity and not os.get_inheritable(fd)
                    and select.select([fd], [], [fd], 0) == ([], [], []), "KERNEL_PROCESS_EXITED_OR_REUSED")
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
            self._close_rows(self.rows)
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

    This is NOT the completed _KernelQualification or an execution permit.
    Peer custody, per-I/O cross-reader fencing and external broker enforcement
    remain separate obligations. The server's containment refusal is unchanged.
    No PID, role, backend, callback, record or descriptor is caller-selectable.
    """
    def __init__(self, owner):
        self.owner, self.owned = owner, []
        self.closed = self.failed = self.busy = False
        self.cleanup_failure = None
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
                self.record_raw = canonical_bytes(record)
                self.scope = record["scope"]
                self.role = record["roles"]["SERVER"]
                self._own("roots", _KernelRootViews)
                self._own("policy", _KernelPolicyView, self.roots, record["host"], record["selinux"])
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
        self.qualification_binding = None
        self.self_inspection = None
        self.memfd = None
        self.active_operation = None
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
            self.self_inspection = object.__new__(_KernelSelfInspection)
            self.self_inspection.__init__(self)
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
        self.qualification_binding.check()
        self.self_inspection.check()
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
        for attr in ("connection", "listener", "observer", "storage", "self_inspection", "qualification_binding", "secrets", "files"):
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
