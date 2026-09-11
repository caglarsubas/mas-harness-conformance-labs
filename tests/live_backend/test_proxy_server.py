"""Data qualification, source preservation and OS-mocked custody refusals.

These tests do not substitute for the pending fixed native inspector and server
broker/API integration. Matching fixture data is explicitly not qualification.
"""
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import json
import stat
from types import SimpleNamespace
import unittest
from time import perf_counter as _wall_clock
from unittest.mock import Mock, patch

from _fixtures import ROOT
from _inventory import BASELINE, SUCCESSOR, isolated_inventory, validate_checkpoint
from harness_conformance import live_mutation_admission as admission
from test_proxy_client import load_proxy_modules
from harness_conformance.canonical import byte_digest, canonical_bytes
from harness_conformance.errors import ConformanceError
from harness_conformance.live_backend_authority import SUITE_ROOTS

VECTORS = json.loads((ROOT / "fixtures/live-backend/proxy-vectors.json").read_bytes())


def current_checkpoint(value):
    if byte_digest(canonical_bytes(value)) != "sha256:a9422d02a7b44ef0780de9634121f468badb1638ae7f0859dccc48b0202b58b8":
        raise ValueError("exact accepted successor-correction checkpoint required")
    return value


def setUpModule():
    # Diagnostic only: do not intercept TestCase.run, discovery or any guard.
    global _module_started
    _module_started = _wall_clock()


def tearDownModule():
    print(f"CONF-LIVE-003 module-timing module={__name__} "
          f"elapsedSeconds={_wall_clock() - _module_started:.6f} evidenceClass=DIAGNOSTIC_ONLY", flush=True)
_client_module, server = load_proxy_modules()


def sample(index=0):
    return deepcopy(VECTORS["qualification"]["positive"][index])


def record_check(value):
    return admission.validate_qualification_record(value["record"], value["profile"], value["endpoints"])


def capture_check(value, capture, role=None, previous=None):
    return admission.validate_qualification_capture(value["record"], capture, value["profile"], value["endpoints"],
                                                    role=capture["role"] if role is None else role, previous=previous)


class KernelInputCodecTests(unittest.TestCase):
    """Inert independently constructed bytes, never loaded as native code."""
    def elf(self, machine="x86_64"):
        raw = bytearray(8192)
        ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        server.struct.pack_into("<16sHHIQQQIHHHHHH", raw, 0, ident, 3,
            62 if machine == "x86_64" else 183, 1, 4096, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        server.struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 4096, 0, 4096, 4096, 4096)
        server.struct.pack_into("<IIQQQQQQ", raw, 120, 1, 6, 4096, 12288, 0, 4096, 4096, 4096)
        return bytes(raw)

    def auxv(self, address=28672):
        return server.struct.pack("<6Q", 6, 4096, 33, address, 0, 0)

    def maps(self):
        return (b"00001000-00002000 r-xp 00000000 08:01 71 /opt/planeon/python\n"
                b"00003000-00004000 rw-p 00001000 08:01 71 /opt/planeon/python\n"
                b"00005000-00006000 rw-p 00000000 00:00 0 [heap]\n"
                b"00007000-00008000 r-xp 00000000 00:00 0 [vdso]\n")

    def test_selinux_status_layout_has_distinct_sequence_and_policyload(self):
        raw = bytes.fromhex("01000000 02000000 01000000 09000000 01000000")
        self.assertEqual(server._selinux_status_fields(raw),
            dict(version=1, sequence=2, enforcing=1, policyload=9, denyUnknown=1))

    def test_selinux_status_rejects_odd_permissive_unknown_or_truncated_bytes(self):
        for fields in ((2, 2, 1, 9, 1), (1, 3, 1, 9, 1), (1, 2, 0, 9, 1),
                       (1, 2, 1, 0, 1), (1, 2, 1, 9, 0)):
            with self.subTest(fields=fields), self.assertRaises(ConformanceError):
                server._selinux_status_fields(server.struct.pack("<5I", *fields))
        for raw in (b"", b"\0" * 19, b"\0" * 21, bytearray(20), "x" * 20):
            with self.subTest(kind=type(raw)), self.assertRaises(ConformanceError):
                server._selinux_status_fields(raw)

    def test_verity_measurement_decodes_distinct_kernel_digest(self):
        raw = b"\x01\x00\x20\x00" + bytes(range(32))
        self.assertEqual(server._verity_measurement(raw), "sha256:" + bytes(range(32)).hex())
        for changed in (raw[:-1], raw + b"x", b"\x02" + raw[1:], raw[:2] + b"\x1f\x00" + raw[4:]):
            with self.subTest(raw=changed[:4]), self.assertRaises(ConformanceError):
                server._verity_measurement(changed)

    def test_auxv_requires_unique_complete_native_pairs_and_exact_terminator(self):
        self.assertEqual(server._native_auxv(self.auxv()), {6: 4096, 33: 28672})
        for raw in (self.auxv()[:-1], self.auxv()[:-16], self.auxv() + b"\0" * 16,
                    self.auxv()[:-16] + server.struct.pack("<4Q", 6, 4096, 0, 0),
                    server.struct.pack("<6Q", 6, 8192, 33, 28672, 0, 0), self.auxv(address=1),
                    b"\0" * 16, b"\0" * 65552):
            with self.subTest(size=len(raw)), self.assertRaises(ConformanceError):
                server._native_auxv(raw)

    def test_elf_both_native_machines_have_exact_executable_loads(self):
        for machine in ("x86_64", "aarch64"):
            self.assertEqual(server._elf_code_layout(self.elf(machine), machine, 4096),
                dict(kind=3, interpreter=None, segments=[dict(offset=0, length=4096,
                    permissions="r-xp", virtualAddress=4096)]))

    def test_elf_rejects_other_endian_class_machine_and_header_shapes(self):
        for offset, value in ((0, b"x"), (4, b"\x01"), (5, b"\x02"), (7, b"\x09"),
                              (8, b"\x01"), (16, b"\x01\0"), (18, b"\xb7\0"),
                              (52, b"\x3f\0"), (54, b"\x38\x01"), (56, b"\xff\xff")):
            raw = bytearray(self.elf())
            raw[offset:offset + len(value)] = value
            with self.subTest(offset=offset), self.assertRaises(ConformanceError):
                server._elf_code_layout(bytes(raw), "x86_64", 4096)
        for machine, size in (("arm64", 4096), ("x86_64", True), ("x86_64", 8192)):
            with self.assertRaises(ConformanceError):
                server._elf_code_layout(self.elf(), machine, size)

    def test_elf_refuses_short_tables_ranges_and_overflow(self):
        for offset, value in ((32, 8192), (72, 8192), (80, 2 ** 64 - 1), (96, 8193), (104, 4095), (112, 3)):
            raw = bytearray(self.elf())
            server.struct.pack_into("<Q", raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ConformanceError):
                server._elf_code_layout(bytes(raw), "x86_64", 4096)
        for raw in (b"", self.elf()[:63], self.elf()[:119]):
            with self.assertRaises(ConformanceError):
                server._elf_code_layout(raw, "x86_64", 4096)

    def test_elf_refuses_writable_executable_anonymous_and_duplicate_loads(self):
        for fault in ("writable", "anonymous", "duplicate", "empty", "exec-stack"):
            raw = bytearray(self.elf())
            if fault == "writable": server.struct.pack_into("<I", raw, 68, 7)
            if fault == "anonymous": server.struct.pack_into("<Q", raw, 104, 8192)
            if fault == "duplicate": raw[120:176] = raw[64:120]
            if fault == "empty": server.struct.pack_into("<I", raw, 68, 4)
            if fault == "exec-stack": server.struct.pack_into("<II", raw, 120, 0x6474e551, 7)
            with self.subTest(fault=fault), self.assertRaises(ConformanceError):
                server._elf_code_layout(bytes(raw), "x86_64", 4096)

    def test_elf_interpreter_is_data_not_a_loadable_path(self):
        path = b"/lib/ld-linux.so.2\0"
        raw = bytearray(self.elf())
        server.struct.pack_into("<IIQQQQQQ", raw, 120, 3, 4, 4096, 0, 0, len(path), len(path), 1)
        raw[4096:4096 + len(path)] = path
        self.assertEqual(server._elf_code_layout(bytes(raw), "x86_64", 4096)["interpreter"], path[:-1].decode())
        for replacement in (b"/../", b"/a//", b"/a\0x", b"/a x"):
            changed = bytearray(raw)
            changed[4096:4100] = replacement
            with self.subTest(path=replacement), self.assertRaises(ConformanceError):
                server._elf_code_layout(bytes(changed), "x86_64", 4096)

    def test_maps_preserve_aslr_device_inode_permissions_and_offset(self):
        result = server._proc_code_maps(self.maps(), "x86_64", self.auxv())
        self.assertEqual(result["files"], [dict(path="/opt/planeon/python", start=4096, end=8192,
            permissions="r-xp", offset=0, deviceMajor=8, deviceMinor=1, inode=71)])
        self.assertEqual(result["kernel"], {"[vdso]": dict(start=28672, end=32768, permissions="r-xp")})
        self.assertEqual(result["pageSize"], 4096)

    def test_maps_reject_truncation_malformed_rows_and_overlapping_addresses(self):
        for raw in (self.maps()[:-1], b"\n", self.maps() + b"broken\n", self.maps().replace(b"r-xp", b"r-xz", 1),
                    self.maps().replace(b"00003000", b"00001000"), self.maps().replace(b"00001000-", b"00001001-", 1),
                    self.maps() + b"\0\n", self.maps().replace(b" 71 ", b" 18446744073709551616 ")):
            with self.subTest(size=len(raw)), self.assertRaises(ConformanceError):
                server._proc_code_maps(raw, "x86_64", self.auxv())

    def test_maps_reject_unknown_anonymous_deleted_memfd_and_writable_code(self):
        for path in (b"[anon:code]", b"/memfd:code", b"/opt/planeon/python (deleted)",
                     b"/opt/../python", b"/opt//python", b"/opt/code\\040alias"):
            raw = self.maps().replace(b"/opt/planeon/python", path, 1)
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                server._proc_code_maps(raw, "x86_64", self.auxv())
        with self.assertRaises(ConformanceError):
            server._proc_code_maps(self.maps().replace(b"r-xp", b"rwxp", 1), "x86_64", self.auxv())
        with self.assertRaises(ConformanceError):
            server._proc_code_maps(self.maps().replace(b" 71 /opt/planeon/python", b" 0", 1), "x86_64", self.auxv())

    def test_maps_kernel_names_require_auxv_architecture_and_exact_shapes(self):
        with self.assertRaises(ConformanceError):
            server._proc_code_maps(self.maps(), "x86_64", self.auxv(address=32768))
        for replacement in (b"08:01 0 [vdso]", b"00:00 1 [vdso]", b"00:00 0 [anon:vdso]"):
            with self.assertRaises(ConformanceError):
                server._proc_code_maps(self.maps().replace(b"00:00 0 [vdso]", replacement), "x86_64", self.auxv())
        syscall = b"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n"
        result = server._proc_code_maps(self.maps() + syscall, "x86_64", self.auxv())
        self.assertEqual(set(result["kernel"]), {"[vdso]", "[vsyscall]"})
        with self.assertRaises(ConformanceError):
            server._proc_code_maps(self.maps() + syscall, "aarch64", self.auxv())
        with self.assertRaises(ConformanceError):
            server._proc_code_maps(self.maps() + syscall.replace(b"--xp", b"r-xp"), "x86_64", self.auxv())

    def test_codecs_never_open_execute_or_return_native_authority(self):
        with patch.object(server.os, "open", side_effect=AssertionError("no native read")), patch.object(
                server.os, "execve", side_effect=AssertionError("no execution")), patch.object(
                server.socket, "socket", side_effect=AssertionError("no network")):
            decoded = server._elf_code_layout(self.elf(), "x86_64", 4096)
            maps = server._proc_code_maps(self.maps(), "x86_64", self.auxv())
        self.assertEqual(set(decoded), {"kind", "interpreter", "segments"})
        self.assertEqual(set(maps), {"files", "kernel", "pageSize"})


class KernelNativeReadTests(unittest.TestCase):
    """Real read-primitive methods with all native entry points OS-mocked."""
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.now = 100.0
        self.page_size = 4096
        self.info = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_gid=0,
            st_mode=stat.S_IFREG | 0o444, st_nlink=1, st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
        self.fs = dict(kind=0xf97cff8c, block_size=4096, name_length=255, flags=1)
        self.raw = server.struct.pack("<5I", 1, 2, 1, 9, 1)
        self.lib = SimpleNamespace(fstatfs=Mock(side_effect=self.filesystem), syscall=Mock(side_effect=self.barrier))
        def patched(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        patched(server.sys, "platform", new="linux")
        patched(server.sys, "byteorder", new="little")
        patched(server.os, "uname", return_value=SimpleNamespace(machine="x86_64"))
        patched(server.os, "sysconf", side_effect=lambda name: self.page_size if name == "SC_PAGESIZE" else None)
        patched(server.os, "getpid", return_value=411)
        patched(server.threading, "get_ident", return_value=721)
        patched(server.time, "monotonic", side_effect=lambda: self.now)
        self.load = patched(server.ctypes, "CDLL", return_value=self.lib)
        self.fstat = patched(server.os, "fstat", side_effect=lambda fd: self.info)
        self.flags = patched(server.fcntl, "fcntl", return_value=server.os.O_RDONLY)
        self.inheritable = patched(server.os, "get_inheritable", return_value=False)
        self.ioctl = patched(server.fcntl, "ioctl", side_effect=self.verity)
        self.maps = []
        self.mapper = patched(server.mmap, "mmap", side_effect=self.mapping)
        self.opened = patched(server.os, "open", side_effect=AssertionError("unexpected open"))
        self.closed_fd = patched(server.os, "close", side_effect=AssertionError("caller fd closed"))
        self.sockets = patched(server.socket, "socket", side_effect=AssertionError("unexpected network"))
        self.reader = server._KernelNativeReads()

    def filesystem(self, fd, pointer):
        self.assertEqual(fd.value, 71)
        value = pointer._obj
        self.assertEqual(bytes(value), b"\0" * 120)
        for key, item in self.fs.items():
            setattr(value, key, item)
        value.fsid[:] = (17, -9)
        return 0

    def barrier(self, number, command, flags, cpu):
        self.assertEqual(number.value, 324 if self.reader.machine == "x86_64" else 283)
        self.assertEqual((flags.value, cpu.value), (0, 0))
        self.assertIn(command.value, (0, 16, 8))
        return 24 if command.value == 0 else 0

    def verity(self, fd, command, output, mutate):
        self.assertEqual((fd, command, mutate), (71, 0xc0046686, True))
        self.assertIs(type(output), bytearray)
        self.assertEqual(bytes(output), bytes.fromhex("00002000") + b"\0" * 32)
        output[:] = bytes.fromhex("01002000") + b"v" * 32
        return 0

    def mapping(self, fd, length, *, flags, prot):
        self.assertEqual((fd, length, flags, prot), (71, self.page_size, server.mmap.MAP_SHARED, server.mmap.PROT_READ))
        owner = self
        class Mapping:
            def __init__(self):
                self.slices, self.closes = [], 0

            def __getitem__(self, key):
                self.slices.append((key.start, key.stop))
                return owner.raw[key]

            def close(self):
                self.closes += 1
        value = Mapping()
        self.maps.append(value)
        return value

    def fresh(self):
        self.reader = server._KernelNativeReads()
        return self.reader

    def test_fixed_constructor_and_native_lp64_layout(self):
        self.load.assert_called_once_with(None, use_errno=True)
        self.assertEqual(server.ctypes.sizeof(server._KernelStatfs), 120)
        self.assertEqual((server._KernelStatfs.fsid.offset, server._KernelStatfs.flags.offset), (56, 80))
        self.assertEqual(self.lib.fstatfs.argtypes[0], server.ctypes.c_int)
        self.assertEqual(self.lib.syscall.restype, server.ctypes.c_long)
        for kwargs in ({"backend": Mock()}, {"lib": self.lib}, {"fd": 71}, {"qualified": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                server._KernelNativeReads(**kwargs)
        self.lib.syscall.assert_not_called()

    def test_unsupported_os_endianness_machine_and_word_size_never_load_library(self):
        cases = [(server.sys, "platform", "darwin"), (server.sys, "byteorder", "big")]
        for obj, name, value in cases:
            with self.subTest(name=name), patch.object(obj, name, value):
                self.load.reset_mock()
                with self.assertRaises(ConformanceError):
                    self.fresh()
                self.load.assert_not_called()
        with patch.object(server.os, "uname", return_value=SimpleNamespace(machine="i686")):
            self.load.reset_mock()
            with self.assertRaises(ConformanceError):
                self.fresh()
            self.load.assert_not_called()
        with patch.object(server.ctypes, "sizeof", return_value=4):
            self.load.reset_mock()
            with self.assertRaises(ConformanceError):
                self.fresh()
            self.load.assert_not_called()

    def test_filesystem_returns_stable_data_not_dynamic_counters_or_a_grant(self):
        self.fs.update(blocks=10, free_blocks=5)
        expected = dict(kind=0xf97cff8c, fsid=[17, -9], blockSize=4096, flags=1)
        self.assertEqual(self.reader.filesystem(71), expected)
        self.fs.update(blocks=20, free_blocks=1)
        self.assertEqual(self.reader.filesystem(71), expected)
        self.ioctl.assert_not_called()
        self.closed_fd.assert_not_called()

    def test_filesystem_rejects_error_unknown_layout_and_reserved_tail(self):
        for values in ({"block_size": 0}, {"block_size": 513}, {"block_size": 131072}, {"name_length": 0}, {"name_length": 4097}):
            with self.subTest(values=values), patch.dict(self.fs, values):
                with self.assertRaises(ConformanceError):
                    self.fresh().filesystem(71)
                self.assertTrue(self.reader.failed)
        for result in (-1, 1):
            with patch.object(self.lib, "fstatfs", Mock(return_value=result)):
                with self.assertRaises(ConformanceError):
                    self.fresh().filesystem(71)
        def spare(fd, pointer):
            self.filesystem(fd, pointer)
            pointer._obj.spare[3] = 1
            return 0
        with patch.object(self.lib, "fstatfs", Mock(side_effect=spare)), self.assertRaises(ConformanceError):
            self.fresh().filesystem(71)

    def test_descriptor_type_range_access_and_inheritance_before_native_reads(self):
        class Descriptor(int):
            pass
        for fd in (True, None, "71", Descriptor(71), 2, 1048576):
            with self.subTest(fd=fd), self.assertRaises(ConformanceError):
                self.fresh().filesystem(fd)
        self.lib.fstatfs.assert_not_called()
        for flags in (server.os.O_WRONLY, server.os.O_RDWR, 0o10000000):
            self.flags.return_value = flags
            with self.subTest(flags=flags), self.assertRaises(ConformanceError):
                self.fresh().filesystem(71)
        self.flags.return_value = server.os.O_RDONLY
        self.inheritable.return_value = True
        with self.assertRaises(ConformanceError):
            self.fresh().filesystem(71)
        self.lib.fstatfs.assert_not_called()

    def test_changed_descriptor_refuses_result_without_closing_reused_fd(self):
        def replace(fd, pointer):
            result = self.filesystem(fd, pointer)
            self.info.st_ino += 1
            return result
        self.lib.fstatfs.side_effect = replace
        with self.assertRaises(ConformanceError):
            self.reader.filesystem(71)
        self.reader.close()
        self.reader.close()
        self.closed_fd.assert_not_called()

    def test_verity_uses_exact_measure_ioctl_and_distinct_kernel_digest(self):
        result = self.reader.measure_verity(71)
        self.assertEqual(result, "sha256:" + (b"v" * 32).hex())
        self.assertNotEqual(result, byte_digest(b"v" * 32))
        self.ioctl.assert_called_once()
        self.lib.syscall.assert_not_called()
        self.mapper.assert_not_called()

    def test_verity_refuses_unowned_mutable_linked_or_unbounded_code(self):
        for values in ({"st_mode": stat.S_IFDIR | 0o555}, {"st_mode": stat.S_IFREG | 0o644},
                       {"st_uid": 1}, {"st_gid": 1}, {"st_nlink": 2}, {"st_size": 0}, {"st_size": 67108865}):
            original = self.info
            self.info = SimpleNamespace(**{**vars(original), **values})
            with self.subTest(values=values), self.assertRaises(ConformanceError):
                self.fresh().measure_verity(71)
            self.info = original
        self.ioctl.assert_not_called()

    def test_verity_errors_and_wrong_measurement_never_fallback_or_enable(self):
        for result in (-1, 1, b"digest", True):
            with self.subTest(result=result), patch.object(server.fcntl, "ioctl", Mock(return_value=result)):
                with self.assertRaises(ConformanceError):
                    self.fresh().measure_verity(71)
        for raw in (bytes.fromhex("02002000") + b"v" * 32, bytes.fromhex("01004000") + b"v" * 32):
            def wrong(fd, command, output, mutate):
                output[:] = raw
                return 0
            with patch.object(server.fcntl, "ioctl", Mock(side_effect=wrong)), self.assertRaises(ConformanceError):
                self.fresh().measure_verity(71)
        with patch.object(server.fcntl, "ioctl", Mock(side_effect=PermissionError("unit"))), self.assertRaises(PermissionError):
            self.fresh().measure_verity(71)
        self.assertTrue(self.reader.failed)
        self.opened.assert_not_called()

    def test_verity_changed_metadata_and_late_result_are_refused(self):
        for change in ("metadata", "deadline"):
            def mutated(fd, command, output, mutate):
                result = self.verity(fd, command, output, mutate)
                if change == "metadata":
                    self.info.st_ctime_ns += 1
                else:
                    self.now += 2
                return result
            with self.subTest(change=change), patch.object(server.fcntl, "ioctl", Mock(side_effect=mutated)):
                with self.assertRaises(ConformanceError):
                    self.fresh().measure_verity(71)

    def test_status_uses_shared_readonly_mapping_and_private_fences_only(self):
        expected = dict(version=1, sequence=2, enforcing=1, policyload=9, denyUnknown=1)
        self.assertEqual(self.reader.status_epoch(71), expected)
        self.assertEqual([call.args[1].value for call in self.lib.syscall.call_args_list], [0, 16, 8, 8])
        self.assertEqual(self.maps[0].slices, [(4, 8), (None, 20), (4, 8)])
        self.assertEqual(self.maps[0].closes, 1)
        self.assertEqual(self.reader.status_epoch(71), expected)
        self.assertEqual([call.args[1].value for call in self.lib.syscall.call_args_list], [0, 16, 8, 8, 8, 8])
        self.assertEqual(len(self.maps), 2)
        self.assertEqual(self.maps[1].closes, 1)
        self.ioctl.assert_not_called()

    def test_status_both_native_machines_use_exact_syscall_numbers(self):
        for machine, number in (("x86_64", 324), ("aarch64", 283)):
            with self.subTest(machine=machine), patch.object(server.os, "uname", return_value=SimpleNamespace(machine=machine)):
                self.lib.syscall.reset_mock()
                self.fresh().status_epoch(71)
                self.assertEqual({call.args[0].value for call in self.lib.syscall.call_args_list}, {number})

    def test_status_wrong_filesystem_and_custody_refuse_before_mapping(self):
        for magic in (0x9fa0, 0x62656572, 0):
            with patch.dict(self.fs, kind=magic), self.assertRaises(ConformanceError):
                self.fresh().status_epoch(71)
        original = self.info
        for values in ({"st_uid": 1}, {"st_gid": 1}, {"st_mode": stat.S_IFREG | 0o644}, {"st_mode": stat.S_IFDIR | 0o555}):
            self.info = SimpleNamespace(**{**vars(original), **values})
            with self.subTest(values=values), self.assertRaises(ConformanceError):
                self.fresh().status_epoch(71)
        self.mapper.assert_not_called()
        self.lib.syscall.assert_not_called()

    def test_status_odd_changed_epoch_and_invalid_fields_always_unmap(self):
        for fields in ((1, 3, 1, 9, 1), (2, 2, 1, 9, 1), (1, 2, 0, 9, 1), (1, 2, 1, 9, 0), (1, 2, 1, 0, 1)):
            self.raw = server.struct.pack("<5I", *fields)
            with self.subTest(fields=fields), self.assertRaises(ConformanceError):
                self.fresh().status_epoch(71)
            self.assertEqual(self.maps[-1].closes, 1)
        self.raw = server.struct.pack("<5I", 1, 2, 1, 9, 1)
        def change(number, command, flags, cpu):
            result = self.barrier(number, command, flags, cpu)
            if command.value == 8:
                self.raw = server.struct.pack("<5I", 1, 4, 1, 10, 1)
            return result
        with patch.object(self.lib, "syscall", Mock(side_effect=change)), self.assertRaises(ConformanceError):
            self.fresh().status_epoch(71)
        self.assertEqual(self.maps[-1].closes, 1)

    def test_private_barrier_missing_permissions_and_commands_poison_reader(self):
        for responses in ([0], [8], [-1], [24, -1], [24, 1], [24, 0, -1], [24, 0, 1]):
            with self.subTest(responses=responses), patch.object(self.lib, "syscall", Mock(side_effect=responses)):
                with self.assertRaises(ConformanceError):
                    self.fresh().status_epoch(71)
                self.assertTrue(self.reader.failed)
                self.assertEqual(self.maps[-1].closes, 1)
        with patch.object(self.lib, "syscall", Mock(side_effect=OSError("unit"))), self.assertRaises(OSError):
            self.fresh().status_epoch(71)
        self.assertEqual(self.maps[-1].closes, 1)

    def test_status_mapping_partial_failure_and_close_failure_are_not_retried(self):
        with patch.object(server.mmap, "mmap", Mock(side_effect=OSError("unit"))), self.assertRaises(OSError):
            self.reader.status_epoch(71)
        self.assertEqual(self.maps, [])
        def cannot_close(*args, **kwargs):
            result = self.mapping(*args, **kwargs)
            result.close = Mock(side_effect=OSError("unit"))
            return result
        with patch.object(server.mmap, "mmap", Mock(side_effect=cannot_close)), self.assertRaises(OSError):
            self.fresh().status_epoch(71)
        self.maps[-1].close.assert_called_once()
        self.assertTrue(self.reader.failed)
        self.reader.close()
        self.maps[-1].close.assert_called_once()
        self.closed_fd.assert_not_called()

    def test_process_thread_clock_and_closed_reader_refuse_native_operation(self):
        for obj, name, result in ((server.os, "getpid", 999), (server.threading, "get_ident", 999)):
            self.fresh()
            with patch.object(obj, name, return_value=result), self.assertRaises(ConformanceError):
                self.reader.filesystem(71)
        self.fresh()
        with patch.object(server.time, "monotonic", side_effect=[100, 99]), self.assertRaises(ConformanceError):
            self.reader.filesystem(71)
        self.fresh().close()
        with self.assertRaises(ConformanceError):
            self.reader.filesystem(71)
        self.lib.fstatfs.assert_not_called()

    def test_status_rechecks_filesystem_and_fd_after_fenced_read(self):
        for change in ("filesystem", "descriptor", "time"):
            def mutate(number, command, flags, cpu):
                result = self.barrier(number, command, flags, cpu)
                if command.value == 8:
                    if change == "filesystem":
                        self.fs["flags"] += 1
                    elif change == "descriptor":
                        self.info.st_ino += 1
                    else:
                        self.now += 2
                return result
            with self.subTest(change=change), patch.object(self.lib, "syscall", Mock(side_effect=mutate)):
                with self.assertRaises(ConformanceError):
                    self.fresh().status_epoch(71)
                self.assertEqual(self.maps[-1].closes, 1)


    def test_status_maps_one_native_page_for_both_supported_abis(self):
        for machine in ("x86_64", "aarch64"):
            for size in (4096, 16384, 65536):
                self.page_size = size
                with self.subTest(machine=machine, page=size), patch.object(
                        server.os, "uname", return_value=SimpleNamespace(machine=machine)):
                    self.fresh()
                    self.assertEqual(self.reader.status_epoch(71)["sequence"], 2)
                    self.assertEqual(self.maps[-1].closes, 1)

    def test_status_rejects_unknown_or_late_page_size_before_mapping(self):
        for size in (True, 0, 8192, 131072, "4096"):
            self.page_size = size
            with self.subTest(size=size), self.assertRaisesRegex(ConformanceError, "PAGE_SIZE"):
                self.fresh().status_epoch(71)
        self.mapper.assert_not_called()
        def late(name):
            self.now += 2
            return 4096
        with patch.object(server.os, "sysconf", side_effect=late), self.assertRaises(ConformanceError):
            self.fresh().status_epoch(71)
        self.mapper.assert_not_called()


class KernelRootCustodyTests(unittest.TestCase):
    """Fixed root owner and native statx/fstatfs methods; only OS edges mocked."""
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.now = 100.0
        self.handles, self.closed, self.opens = {}, [], []
        self.next_fd = 71
        self.nodes = {}
        paths = ("/", "/proc", "/sys", "/sys/kernel", "/sys/fs", "/sys/fs/selinux", "/sys/fs/cgroup")
        for index, path in enumerate(paths):
            group = (0, 1, 2, 2, 2, 3, 4)[index]
            self.nodes[path] = dict(st_dev=server.os.makedev(0, 10 + group), st_ino=20 + index,
                st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755, st_nlink=2, st_size=0,
                st_mtime_ns=1, st_ctime_ns=1, mountId=101 + group,
                magic=(0xef53, 0x9fa0, 0x62656572, 0xf97cff8c, 0x63677270)[group])
        self.lib = SimpleNamespace(statx=Mock(side_effect=self.statx),
            fstatfs=Mock(side_effect=self.statfs), syscall=Mock(side_effect=AssertionError("unexpected syscall")))
        def patched(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        patched(server.sys, "platform", new="linux")
        patched(server.sys, "byteorder", new="little")
        patched(server.os, "uname", return_value=SimpleNamespace(machine="x86_64"))
        patched(server.os, "getpid", return_value=411)
        patched(server.threading, "get_ident", return_value=721)
        patched(server.time, "monotonic", side_effect=lambda: self.now)
        patched(server.ctypes, "CDLL", return_value=self.lib)
        self.opened = patched(server.os, "open", side_effect=self.open_fd)
        self.fstat = patched(server.os, "fstat", side_effect=self.stat_fd)
        self.close_fd_mock = patched(server.os, "close", side_effect=self.close_fd)
        patched(server.os, "get_inheritable", return_value=False)
        patched(server.fcntl, "fcntl", return_value=server.os.O_RDONLY)
        self.ioctl = patched(server.fcntl, "ioctl", side_effect=AssertionError("unexpected ioctl"))
        self.mapper = patched(server.mmap, "mmap", side_effect=AssertionError("unexpected mapping"))
        patched(server.socket, "socket", side_effect=AssertionError("unexpected network"))

    def open_fd(self, name, flags, *, dir_fd):
        expected = server.os.O_RDONLY | server.os.O_DIRECTORY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK
        self.assertEqual(flags, expected)
        if dir_fd is None:
            self.assertEqual(name, "/")
            path = "/"
        else:
            self.assertNotIn("/", name)
            parent = self.handles[dir_fd][0]
            path = parent.rstrip("/") + "/" + name
        self.assertIn(path, self.nodes)
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        # Like retained descriptors, this row does not follow later path replacement.
        self.handles[fd] = (path, self.nodes[path])
        self.opens.append((path, fd, dir_fd))
        return fd

    def stat_fd(self, fd):
        node = self.handles[fd][1]
        return SimpleNamespace(**{key: value for key, value in node.items() if key.startswith("st_")})

    def statfs(self, fd, pointer):
        node, output = self.handles[fd.value][1], pointer._obj
        self.assertEqual(bytes(output), b"\0" * 120)
        output.kind, output.block_size, output.name_length, output.flags = node["magic"], 4096, 255, 1
        output.fsid[:] = (node["magic"] & 0x7fffffff, 1)
        return 0

    def statx(self, fd, path, flags, mask, pointer):
        self.assertEqual((path, flags, mask), (b"", 0x1900, 0x411b))
        self.assertEqual(bytes(pointer._obj), b"\0" * 256)
        node = self.handles[fd][1]
        raw = bytearray(256)
        server.struct.pack_into("<I", raw, 0, 0x47ff)
        server.struct.pack_into("<IIH", raw, 20, node["st_uid"], node["st_gid"], node["st_mode"])
        server.struct.pack_into("<Q", raw, 32, node["st_ino"])
        server.struct.pack_into("<IIQ", raw, 136, server.os.major(node["st_dev"]),
                                server.os.minor(node["st_dev"]), node["mountId"])
        pointer._obj.words[:] = server.struct.unpack("<32Q", raw)
        return 0

    def close_fd(self, fd):
        self.assertIn(fd, self.handles, "double close or unowned descriptor")
        self.closed.append(fd)
        del self.handles[fd]

    def owner(self):
        value = server._KernelRootViews()
        self.addCleanup(value.close)
        return value

    def test_statx_fixed_layout_empty_path_and_unique_mount_identity(self):
        fd = self.open_fd("/", server.os.O_DIRECTORY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK, dir_fd=None)
        for machine in ("x86_64", "aarch64"):
            with self.subTest(machine=machine), patch.object(server.os, "uname", return_value=SimpleNamespace(machine=machine)):
                reader = server._KernelNativeReads()
                observed = reader.directory_identity(fd)
                self.assertEqual(observed["mountId"], 101)
                self.assertEqual(observed["identity"][1], 20)
                self.assertEqual(server.ctypes.sizeof(server._KernelStatx), 256)
                self.assertEqual(server.ctypes.alignment(server._KernelStatx), 8)
                reader.close()
        self.lib.syscall.assert_not_called()
        self.ioctl.assert_not_called()
        self.mapper.assert_not_called()
        self.close_fd(fd)

    def test_statx_missing_symbol_or_unique_id_never_falls_back(self):
        fd = self.open_fd("/", server.os.O_DIRECTORY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK, dir_fd=None)
        original = self.lib.statx
        del self.lib.statx
        with self.assertRaises(AttributeError):
            server._KernelNativeReads().directory_identity(fd)
        self.lib.statx = original
        for mask in (0, 0x17ff, 0x47fe, 0x4000):
            def missing(*args):
                self.statx(*args)
                raw = bytearray(bytes(args[-1]._obj))
                server.struct.pack_into("<I", raw, 0, mask)
                args[-1]._obj.words[:] = server.struct.unpack("<32Q", raw)
                return 0
            with self.subTest(mask=mask), patch.object(self.lib, "statx", Mock(side_effect=missing)), self.assertRaises(ConformanceError):
                server._KernelNativeReads().directory_identity(fd)
        self.close_fd(fd)

    def test_statx_rejects_errors_reserved_fields_and_changed_identity(self):
        fd = self.open_fd("/", server.os.O_DIRECTORY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK, dir_fd=None)
        for offset in (0, 20, 24, 28, 30, 32, 76, 92, 108, 124, 136, 140, 180, 255):
            def changed(*args):
                self.statx(*args)
                raw = bytearray(bytes(args[-1]._obj))
                raw[offset] ^= 0x80 if offset == 0 else 1
                if offset == 0:
                    raw[3] |= 0x80
                args[-1]._obj.words[:] = server.struct.unpack("<32Q", raw)
                return 0
            with self.subTest(offset=offset), patch.object(self.lib, "statx", Mock(side_effect=changed)), self.assertRaises(ConformanceError):
                server._KernelNativeReads().directory_identity(fd)
        for result in (-1, 1, True):
            with patch.object(self.lib, "statx", Mock(return_value=result)), self.assertRaises(ConformanceError):
                server._KernelNativeReads().directory_identity(fd)
        with patch.object(self.lib, "statx", Mock(side_effect=PermissionError("unit"))), self.assertRaises(PermissionError):
            server._KernelNativeReads().directory_identity(fd)
        self.close_fd(fd)

    def test_directory_changes_after_statx_and_late_reads_are_refused(self):
        fd = self.open_fd("/", server.os.O_DIRECTORY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK, dir_fd=None)
        for change in ("inode", "deadline"):
            def mutate(*args):
                self.statx(*args)
                if change == "inode":
                    self.nodes["/"]["st_ino"] += 1
                else:
                    self.now += 2
                return 0
            with self.subTest(change=change), patch.object(self.lib, "statx", Mock(side_effect=mutate)), self.assertRaises(ConformanceError):
                server._KernelNativeReads().directory_identity(fd)
        self.close_fd(fd)

    def test_fixed_roots_retain_seven_fds_and_reopen_only_fixed_ancestry(self):
        views = self.owner()
        self.assertEqual(len(views.rows), 7)
        self.assertEqual(len(self.handles), 7)
        self.assertEqual(len(self.opens), 14)
        self.assertIsNone(views.check())
        self.assertEqual(len(self.handles), 7)
        self.assertEqual(len(self.opens), 21)
        self.assertEqual([path for path, _, _ in self.opens[:7]], list(self.nodes))
        views.close()
        self.assertFalse(self.handles)
        self.assertEqual(len(self.closed), 21)
        views.close()
        self.assertEqual(len(self.closed), 21)

    def test_root_factory_has_no_path_backend_or_descriptor_selector(self):
        for kwargs in ({"root": "/tmp"}, {"backend": Mock()}, {"fd": 71}, {"context": {}}, {"qualified": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                server._KernelRootViews(**kwargs)
        self.opened.assert_not_called()

    def test_normal_directory_churn_is_not_identity_drift(self):
        views = self.owner()
        for node in self.nodes.values():
            node.update(st_nlink=99, st_size=8192, st_mtime_ns=99, st_ctime_ns=99)
        self.assertIsNone(views.check())
        self.assertEqual(len(self.handles), 7)

    def test_same_inode_bind_replacement_is_caught_by_unique_mount_id(self):
        views = self.owner()
        prior = self.nodes["/proc"]
        self.nodes["/proc"] = {**prior, "mountId": prior["mountId"] + 100}
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_PATH_REPLACED"):
            views.check()
        self.assertTrue(views.failed)
        self.assertEqual(len(self.handles), 7)
        before = self.opened.call_count
        with self.assertRaises(ConformanceError):
            views.check()
        self.assertEqual(self.opened.call_count, before)

    def test_root_path_inode_replacement_is_not_followed_through_old_parent(self):
        views = self.owner()
        self.nodes["/"] = {**self.nodes["/"], "st_ino": 999}
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_PATH_REPLACED"):
            views.check()
        self.assertEqual(len(self.handles), 7)

    def test_retained_mount_change_is_refused_before_any_new_open(self):
        views = self.owner()
        self.nodes["/sys/fs/cgroup"]["mountId"] += 100
        before = self.opened.call_count
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_CHANGED"):
            views.check()
        self.assertEqual(self.opened.call_count, before)

    def test_bootstrap_refuses_wrong_filesystem_owner_and_writable_ancestry(self):
        for path, key, value in (("/proc", "magic", 0xef53), ("/sys", "st_uid", 9),
                                 ("/sys/fs", "st_gid", 9), ("/sys/fs/selinux", "st_mode", stat.S_IFDIR | 0o777)):
            original = self.nodes[path][key]
            self.nodes[path][key] = value
            with self.subTest(path=path, key=key), self.assertRaises(ConformanceError):
                server._KernelRootViews()
            self.nodes[path][key] = original
            self.assertFalse(self.handles)

    def test_sysfs_child_bind_mounts_and_root_mount_aliases_are_refused(self):
        for path, target in (("/sys/kernel", 999), ("/sys/fs", 999), ("/sys/fs/cgroup", 104)):
            original = self.nodes[path]["mountId"]
            self.nodes[path]["mountId"] = target
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                server._KernelRootViews()
            self.nodes[path]["mountId"] = original
            self.assertFalse(self.handles)

    def test_symlink_or_missing_root_refusal_closes_only_acquired_descriptors(self):
        for fail_path in self.nodes:
            def refuse(name, flags, *, dir_fd):
                parent = "" if dir_fd is None else self.handles[dir_fd][0].rstrip("/")
                path = "/" if dir_fd is None else parent + "/" + name
                if path == fail_path:
                    raise OSError("symlink or unavailable")
                return self.open_fd(name, flags, dir_fd=dir_fd)
            with self.subTest(path=fail_path), patch.object(server.os, "open", Mock(side_effect=refuse)), self.assertRaises(OSError):
                server._KernelRootViews()
            self.assertFalse(self.handles)

    def test_failure_before_fstat_still_retains_close_ownership(self):
        with patch.object(server.os, "fstat", Mock(side_effect=OSError("unavailable"))), self.assertRaises(OSError):
            server._KernelRootViews()
        self.assertFalse(self.handles)
        self.assertEqual(len(self.closed), 1)

    def test_failed_temporary_acquisition_keeps_original_roots_for_close(self):
        views = self.owner()
        original_fds = set(self.handles)
        def refuse(name, flags, *, dir_fd):
            if name == "selinux":
                raise PermissionError("unit")
            return self.open_fd(name, flags, dir_fd=dir_fd)
        with patch.object(server.os, "open", Mock(side_effect=refuse)), self.assertRaises(PermissionError):
            views.check()
        self.assertEqual(set(self.handles), original_fds)
        views.close()
        self.assertFalse(self.handles)

    def test_cleanup_continues_after_error_and_never_retries_released_fd(self):
        views = server._KernelRootViews()
        original = set(self.handles)
        fail = views.rows[-1][0]
        def fail_once(fd):
            self.close_fd(fd)
            if fd == fail:
                raise OSError("released but reported failure")
        with patch.object(server.os, "close", Mock(side_effect=fail_once)), self.assertRaises(OSError):
            views.close()
        self.assertFalse(self.handles)
        self.assertTrue(original <= set(self.closed))
        before = len(self.closed)
        with self.assertRaises(OSError):
            views.close()
        self.assertEqual(len(self.closed), before)

    def test_recycled_descriptor_is_not_closed_and_other_roots_are_retired(self):
        views = server._KernelRootViews()
        fd = views.rows[-1][0]
        path, original = self.handles[fd]
        self.handles[fd] = (path, {**original, "st_ino": 999})
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_FD_REUSED"):
            views.close()
        self.assertEqual(set(self.handles), {fd})
        self.assertNotIn(fd, self.closed)
        with self.assertRaises(ConformanceError):
            views.close()

    def test_temporary_cleanup_failure_remains_sticky_after_originals_close(self):
        views = server._KernelRootViews()
        originals = set(self.handles)
        def fail_temporary(fd):
            self.close_fd(fd)
            if fd not in originals:
                raise OSError("temporary cleanup uncertainty")
        with patch.object(server.os, "close", Mock(side_effect=fail_temporary)), self.assertRaises(OSError):
            views.check()
        self.assertEqual(set(self.handles), originals)
        with self.assertRaises(OSError):
            views.close()
        self.assertFalse(self.handles)
        before = len(self.closed)
        with self.assertRaises(OSError):
            views.close()
        self.assertEqual(len(self.closed), before)

    def test_pid_thread_clock_and_closed_custody_refuse_reopen(self):
        for obj, name, value in ((server.os, "getpid", 999), (server.threading, "get_ident", 999)):
            views = self.owner()
            before = self.opened.call_count
            with patch.object(obj, name, return_value=value), self.assertRaises(ConformanceError):
                views.check()
            self.assertEqual(self.opened.call_count, before)
            views.close()
        views = self.owner()
        with patch.object(server.time, "monotonic", side_effect=[100, 99]), self.assertRaises(ConformanceError):
            views.check()
        views.close()
        with self.assertRaises(ConformanceError):
            views.check()

    def test_root_acquisition_has_one_deadline_not_one_per_child(self):
        def slow(name, flags, *, dir_fd):
            result = self.open_fd(name, flags, dir_fd=dir_fd)
            self.now += 0.5
            return result
        with patch.object(server.os, "open", Mock(side_effect=slow)), self.assertRaises(ConformanceError):
            server._KernelRootViews()
        self.assertEqual(len(self.opens), 4)
        self.assertFalse(self.handles)


class KernelProcessCustodyTests(unittest.TestCase):
    """Real process/root/native readers with synthetic OS edges, never live proc."""
    stat_fd = KernelRootCustodyTests.stat_fd
    statfs = KernelRootCustodyTests.statfs
    statx = KernelRootCustodyTests.statx
    close_fd = KernelRootCustodyTests.close_fd

    def setUp(self):
        KernelRootCustodyTests.setUp(self)
        self.expected = sample()["record"]["roles"]["SERVER"]
        self.target, self.dead, self.offsets, self.links = 411, False, {}, {}
        self.stat_raw = self.process_stat()
        self.status_raw = self.process_status()
        self.task_names, self.scan_closes, self.views = ["411"], 0, []
        proc = self.nodes["/proc"]
        for index, suffix in enumerate(("", "/ns", "/attr", "/task", "/task/411", "/stat", "/status",
                                        "/cgroup", "/attr/current", "/task/411/children")):
            self.nodes["/proc/411" + suffix] = {**proc, "st_ino": 100 + index,
                "st_mode": stat.S_IFDIR | 0o555 if index < 5 else stat.S_IFREG | 0o444}
        for index, (name, kind) in enumerate((("user", 0x10000000), ("mnt", 0x20000),
                                            ("pid", 0x20000000), ("net", 0x40000000))):
            path = "/proc/411/ns/" + name
            self.links[path] = {**proc, "st_ino": 200 + index, "st_mode": stat.S_IFLNK | 0o777}
            self.nodes[path] = {**proc, "st_ino": self.expected["namespaceInodes"][name],
                "st_dev": server.os.makedev(0, 22), "magic": 0x6e736673,
                "st_mode": stat.S_IFREG | 0o444, "kind": kind}
        self.nodes["/pidfd/411"] = {**proc, "st_ino": 800, "st_mode": stat.S_IFREG | 0o700}
        def patched(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        self.pid_open = patched(server.os, "pidfd_open", side_effect=self.pidfd_open, create=True)
        self.poll = patched(server.select, "select", side_effect=self.poll_pid)
        self.read_fd = patched(server.os, "read", side_effect=self.read)
        self.stat_path = patched(server.os, "stat", side_effect=self.named_stat)
        self.scanner = patched(server.os, "scandir", side_effect=self.scandir)
        self.ioctl.side_effect = self.namespace_type
        self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        self.addCleanup(self.close_views)
        self.root_fds = set(self.handles)
        self.cgroup_raw = b"0::/planeon-live/proxy-server\n"
        self.label_raw = self.expected["processLabel"].encode("ascii") + b"\0"
        self.children_raw = b""

    def close_views(self):
        for value in self.views:
            if not value.closed:
                value.close()

    def process_stat(self, comm=b"unit ) name\nwith ( brackets", **changes):
        fields = [b"S"] + [b"0"] * 49
        for index, value in {1: "100", 17: "1", 19: "999", **{int(k): v for k, v in changes.items()}}.items():
            fields[index] = str(value).encode("ascii")
        return b"411 (" + comm + b") " + b" ".join(fields) + b"\n"

    def process_status(self, **changes):
        fields = dict(Name="unit", Tgid="411", Pid="411", PPid="100", TracerPid="0",
            Uid="0\t0\t0\t0", Gid="0\t0\t0\t0", Threads="1", NSpid="411", NStgid="411",
            Groups="0 ", Seccomp="2", NoNewPrivs="1", VmSize="123 kB",
            CapInh="0000000000000000", CapPrm="0000000000000001", CapEff="0000000000000001",
            CapBnd="0000000000000001", CapAmb="0000000000000000")
        fields.update(changes)
        return "".join(key + ":\t" + value + "\n" for key, value in fields.items()).encode("ascii")

    def allocate(self, path, parent=None):
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.handles[fd] = (path, self.nodes[path])
        self.offsets[fd] = 0
        self.opens.append((path, fd, parent))
        return fd

    def open_fd(self, name, flags, *, dir_fd):
        if dir_fd is None or (dir_fd in self.handles and self.handles[dir_fd][0] in ("/", "/sys", "/sys/fs")):
            return KernelRootCustodyTests.open_fd(self, name, flags, dir_fd=dir_fd)
        self.assertIs(type(name), str)
        self.assertNotIn("/", name)
        path = self.handles[dir_fd][0].rstrip("/") + "/" + name
        self.assertIn(path, self.nodes)
        expected = server.os.O_RDONLY | server.os.O_CLOEXEC | server.os.O_NONBLOCK
        if path in self.links:
            self.assertIn(name, ("user", "mnt", "pid", "net"))
        else:
            expected |= server.os.O_NOFOLLOW
            if stat.S_ISDIR(self.nodes[path]["st_mode"]):
                expected |= server.os.O_DIRECTORY
        self.assertEqual(flags, expected)
        return self.allocate(path, dir_fd)

    def pidfd_open(self, pid, flags):
        self.assertEqual((pid, flags), (411, 0))
        return self.allocate("/pidfd/411")

    def poll_pid(self, reads, writes, errors, timeout):
        self.assertEqual((writes, timeout), ([], 0))
        self.assertEqual(reads, errors)
        self.assertEqual(len(reads), 1)
        self.assertEqual(self.handles[reads[0]][0], "/pidfd/411")
        return (reads if self.dead else [], [], [])

    def named_stat(self, name, *, dir_fd, follow_symlinks):
        self.assertFalse(follow_symlinks)
        path = self.handles[dir_fd][0] + "/" + name
        node = self.links[path] if path in self.links else self.nodes[path]
        return SimpleNamespace(**{k: v for k, v in node.items() if k.startswith("st_")})

    def namespace_type(self, fd, operation, argument):
        self.assertEqual((operation, argument), (0xb703, 0))
        return self.handles[fd][1]["kind"]

    def read(self, fd, size):
        self.assertTrue(0 < size <= 4096)
        path = self.handles[fd][0]
        raw = {"/proc/411/stat": self.stat_raw, "/proc/411/status": self.status_raw,
               "/proc/411/cgroup": self.cgroup_raw, "/proc/411/attr/current": self.label_raw,
               "/proc/411/task/411/children": self.children_raw}[path]
        position = self.offsets[fd]
        self.offsets[fd] += size
        return raw[position:position + size]

    def scandir(self, fd):
        self.assertEqual(self.handles[fd][0], "/proc/411/task")
        owner = self
        class Entries:
            def __enter__(self):
                return iter(SimpleNamespace(name=name) for name in owner.task_names)

            def __exit__(self, *args):
                owner.scan_closes += 1
        return Entries()

    def view(self, role="SERVER", expected=None):
        value = server._KernelProcessView(self.roots, 411, role, self.expected if expected is None else expected)
        self.views.append(value)
        return value

    def test_process_stat_handles_delimiters_newlines_and_ignores_cpu_memory_churn(self):
        observed = server._proc_process_fields(self.stat_raw, self.status_raw)
        self.assertEqual((observed["pid"], observed["parent"], observed["startTicks"], observed["threads"]), (411, 100, 999, 1))
        self.assertEqual(observed["uid"], (0, 0, 0, 0))
        self.assertEqual(server._proc_process_fields(self.process_stat(**{"11": "982", "20": "32768"}),
                                                   self.process_status(VmSize="9999 kB")), observed)

    def test_stat_rejects_truncated_extra_overflow_dead_and_inconsistent_processes(self):
        cases = [b"", self.stat_raw[:-1], self.stat_raw + b"\n", self.stat_raw.replace(b"411 (", b"0411 ("),
                 self.stat_raw[:-1] + b" 0\n", self.stat_raw + b"x" * 8192]
        cases += [self.process_stat(**{key: value}) for key, value in
                  (("0", "Z"), ("0", "X"), ("19", "0"), ("19", "9007199254740992"),
                   ("17", "0"), ("17", "4097"), ("1", "0"), ("30", str(2 ** 64)), ("17", "2"))]
        for raw in cases:
            with self.subTest(raw=raw[:60]), self.assertRaises(ConformanceError):
                server._proc_process_fields(raw, self.status_raw)

    def test_status_rejects_duplicates_missing_fields_credentials_tracing_and_namespace_mismatch(self):
        cases = [b"", self.status_raw[:-1], self.status_raw + b"Pid:\t411\n", self.status_raw + b"broken\n",
                 self.status_raw.replace(b"Seccomp:\t2\n", b""), self.status_raw + b"x" * 65536]
        cases += [self.process_status(**{key: value}) for key, value in
                  (("Pid", "412"), ("Tgid", "412"), ("PPid", "101"), ("TracerPid", "1"),
                   ("Uid", "0 0 0"), ("Uid", "-1 0 0 0"), ("Gid", "True 0 0 0"),
                   ("NSpid", "0"), ("NStgid", "411 2"), ("Seccomp", "0"), ("NoNewPrivs", "2"),
                   ("CapEff", "0"), ("Groups", "0 0"))]
        for raw in cases:
            with self.subTest(raw=raw[-100:]), self.assertRaises(ConformanceError):
                server._proc_process_fields(self.stat_raw, raw)

    def test_fixed_native_factory_retains_original_roots_proc_pid_and_namespace_fds(self):
        view = self.view()
        self.pid_open.assert_called_once_with(411, 0)
        self.assertEqual(len(view.rows), 9)
        self.assertEqual(len(self.handles), len(self.root_fds) + 10)
        self.assertIsNone(view.check())
        self.assertEqual(view.pin[3], tuple(self.expected["namespaceInodes"][k] for k in ("user", "mnt", "pid", "net")))
        view.close()
        view.close()
        self.assertEqual(set(self.handles), self.root_fds)
        self.assertIsNone(self.roots.check())
        self.mapper.assert_not_called()
        self.lib.syscall.assert_not_called()

    def test_factory_refuses_invalid_pid_roots_role_and_caller_backend_before_acquisition(self):
        for pid in (True, "411", 1, 412, 2 ** 31):
            with self.subTest(pid=pid), self.assertRaises(ConformanceError):
                server._KernelProcessView(self.roots, pid, "SERVER", self.expected)
        for roots, role in ((Mock(), "SERVER"), (self.roots, "TENANT"), (self.roots, True)):
            with self.assertRaises(ConformanceError):
                server._KernelProcessView(roots, 411, role, self.expected)
        for extra in ({"backend": Mock()}, {"fd": 72}, {"path": "/tmp"}, {"qualified": True}):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                server._KernelProcessView(self.roots, 411, "SERVER", self.expected, **extra)
        self.pid_open.assert_not_called()

    def test_role_pins_are_detached_and_invalid_pins_do_not_open_process(self):
        for key, value in (("uid", True), ("gid", 1), ("processLabel", "bad\nlabel"),
                           ("namespaceInodes", {"user": 1}), ("cgroup", {"path": "/tmp"}), ("seccompMode", True)):
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                self.view(expected={**self.expected, key: value})
        self.pid_open.assert_not_called()
        view = self.view()
        self.expected["namespaceInodes"]["mnt"] += 1
        self.expected["processLabel"] = "changed"
        self.assertIsNone(view.check())

    def test_uid_gid_label_and_cgroup_mismatch_refuse_and_close_partial_custody(self):
        original = self.status_raw, self.label_raw, self.cgroup_raw
        cases = [(self.process_status(Uid="0 1 0 0"), original[1], original[2]),
                 (self.process_status(Gid="0 0 1 0"), original[1], original[2]),
                 (original[0], original[1] + b"x", original[2]),
                 (original[0], original[1], b"0::/foreign\n"),
                 (original[0], original[1], original[2] + b"1:name=extra:/\n")]
        for values in cases:
            self.status_raw, self.label_raw, self.cgroup_raw = values
            with self.subTest(values=values), self.assertRaises(ConformanceError):
                self.view()
            self.assertEqual(set(self.handles), self.root_fds)
        self.status_raw, self.label_raw, self.cgroup_raw = original

    def test_pid_exit_and_pidfd_replacement_fail_without_reacquisition(self):
        view = self.view()
        self.dead = True
        with self.assertRaisesRegex(ConformanceError, "EXITED_OR_REUSED"):
            view.check()
        self.dead = False
        with self.assertRaises(ConformanceError):
            view.check()
        self.pid_open.assert_called_once()
        view.close()
        changed = self.view()
        fd = changed.pidfd[0]
        path, node = self.handles[fd]
        self.handles[fd] = (path, {**node, "st_ino": node["st_ino"] + 1})
        with self.assertRaises(ConformanceError):
            changed.check()
        with self.assertRaisesRegex(ConformanceError, "FD_REUSED"):
            changed.close()
        self.assertIn(fd, self.handles)
        self.handles[fd] = (path, node)
        self.close_fd(fd)

    def test_start_time_parent_credentials_and_privilege_drift_invalidate_lifetime(self):
        for kind in ("start", "parent", "credentials", "capabilities", "nnp", "groups"):
            view = self.view()
            original_stat, original_status = self.stat_raw, self.status_raw
            if kind == "start":
                self.stat_raw = self.process_stat(**{"19": "1000"})
            elif kind == "parent":
                self.stat_raw, self.status_raw = self.process_stat(**{"1": "101"}), self.process_status(PPid="101")
            else:
                self.status_raw = self.process_status(**{"credentials": {"Uid": "0 1 0 0"},
                    "capabilities": {"CapEff": "0000000000000002"}, "nnp": {"NoNewPrivs": "0"}, "groups": {"Groups": "1"}}[kind])
            with self.subTest(kind=kind), self.assertRaises(ConformanceError):
                view.check()
            self.stat_raw, self.status_raw = original_stat, original_status
            view.close()

    def test_namespace_inode_type_link_and_retained_descriptor_changes_are_refused(self):
        for kind in ("inode", "type", "link", "retained"):
            view = self.view()
            path = "/proc/411/ns/mnt"
            original, link = self.nodes[path], self.links[path]
            if kind == "inode":
                self.nodes[path] = {**original, "st_ino": original["st_ino"] + 1}
            elif kind == "type":
                self.nodes[path] = {**original, "kind": 0x40000000}
            elif kind == "link":
                self.links[path] = {**link, "st_mode": stat.S_IFREG | 0o444}
            else:
                original["st_uid"] = 1
            with self.subTest(kind=kind), self.assertRaises(ConformanceError):
                view.check()
            original["st_uid"] = 0
            self.nodes[path], self.links[path] = original, link
            view.close()

    def test_namespace_native_read_rejects_wrong_fs_missing_ioctl_and_changed_descriptor(self):
        fd = self.allocate("/proc/411/ns/net")
        original = self.handles[fd][1]
        for kind in ("filesystem", "type", "permission", "identity"):
            reader = server._KernelNativeReads()
            def call(*args):
                if kind == "permission":
                    raise PermissionError("unit")
                if kind == "identity":
                    self.handles[fd][1]["st_ino"] += 1
                return 0 if kind == "type" else 0x40000000
            if kind == "filesystem":
                self.handles[fd] = ("/proc/411/ns/net", {**original, "magic": 0x9fa0})
            with patch.object(server.fcntl, "ioctl", Mock(side_effect=call)), self.subTest(kind=kind):
                with self.assertRaises((ConformanceError, PermissionError)):
                    reader.namespace_identity(fd)
            self.handles[fd] = ("/proc/411/ns/net", original)
        self.close_fd(fd)

    def test_bound_proc_views_reject_same_inode_submount_and_process_path_replacement(self):
        for suffix, field in (("/status", "mountId"), ("/ns", "mountId"), ("", "st_ino"), ("/task", "st_ino")):
            view = self.view()
            path = "/proc/411" + suffix
            original = self.nodes[path]
            self.nodes[path] = {**original, field: original[field] + 1000}
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                view.check()
            self.nodes[path] = original
            view.close()

    def test_server_extra_threads_children_and_invalid_directory_entries_are_denied(self):
        for names, children, threads in ((["411", "412"], b"", "2"), (["411"], b"900 ", "1"),
                                          (["411", "411"], b"", "2"), (["../411"], b"", "1")):
            self.task_names, self.children_raw = names, children
            self.stat_raw, self.status_raw = self.process_stat(**{"17": threads}), self.process_status(Threads=threads)
            with self.subTest(names=names, children=children), self.assertRaises(ConformanceError):
                self.view()
            self.assertEqual(set(self.handles), self.root_fds)
        self.assertGreater(self.scan_closes, 0)

    def test_proc_reads_are_bounded_fresh_and_detect_truncation_and_named_replacement(self):
        for kind in ("oversize", "truncated", "replacement"):
            view = self.view()
            original = self.nodes["/proc/411/status"]
            def changed(fd, size):
                raw = self.read(fd, size)
                if self.handles[fd][0] == "/proc/411/status":
                    if kind == "oversize":
                        return b"x" * size
                    if kind == "truncated":
                        return b""
                    self.nodes["/proc/411/status"] = {**original, "st_ino": original["st_ino"] + 1}
                return raw
            with patch.object(server.os, "read", Mock(side_effect=changed)), self.subTest(kind=kind):
                with self.assertRaises(ConformanceError):
                    view.check()
            self.nodes["/proc/411/status"] = original
            view.close()
        self.assertGreater(len([p for p, _, _ in self.opens if p == "/proc/411/status"]), 6)

    def test_late_read_and_whole_phase_budget_refuse_without_renewal(self):
        for step in (2, 0.1):
            original = self.now
            def delayed(fd, size):
                raw = self.read(fd, size)
                self.now += step
                return raw
            with patch.object(server.os, "read", Mock(side_effect=delayed)), self.subTest(step=step):
                with self.assertRaisesRegex(ConformanceError, "DEADLINE"):
                    self.view()
            self.assertEqual(set(self.handles), self.root_fds)
            self.now = original

    def test_partial_open_fstat_and_namespace_failures_close_only_owned_fds(self):
        for failure in ("open", "fstat", "namespace"):
            def open_failure(name, *args, **kwargs):
                if name == "attr":
                    raise PermissionError("unit")
                return self.open_fd(name, *args, **kwargs)
            def stat_failure(fd):
                if self.handles[fd][0] == "/proc/411/attr":
                    raise PermissionError("unit")
                return self.stat_fd(fd)
            target, name, operation = {"open": (server.os, "open", open_failure),
                "fstat": (server.os, "fstat", stat_failure),
                "namespace": (server.fcntl, "ioctl", Mock(side_effect=PermissionError("unit")))}[failure]
            with patch.object(target, name, Mock(side_effect=operation)), self.subTest(failure=failure):
                with self.assertRaises(PermissionError):
                    self.view()
            self.assertEqual(set(self.handles), self.root_fds)

    def test_temporary_cleanup_failure_remains_sticky_and_cleanup_continues(self):
        view = self.view()
        failed_fd = []
        def uncertain(fd):
            path = self.handles[fd][0]
            self.close_fd(fd)
            if path == "/proc/411/status" and not failed_fd:
                failed_fd.append(fd)
                raise OSError("unit uncertain close")
        with patch.object(server.os, "close", Mock(side_effect=uncertain)), self.assertRaises(OSError):
            view.check()
        with self.assertRaises(OSError):
            view.close()
        with self.assertRaises(OSError):
            view.close()
        self.assertEqual(self.closed.count(failed_fd[0]), 1)
        self.assertEqual(set(self.handles), self.root_fds)

    def test_wrong_process_thread_closed_root_and_backward_clock_refuse(self):
        for obj, name, result in ((server.os, "getpid", 412), (server.threading, "get_ident", 722)):
            view = self.view()
            with patch.object(obj, name, return_value=result), self.assertRaises(ConformanceError):
                view.check()
            view.close()
        view = self.view()
        with patch.object(server.time, "monotonic", side_effect=[100, 99]), self.assertRaises(ConformanceError):
            view.check()
        view.close()
        self.roots.close()
        with self.assertRaises(ConformanceError):
            self.view()

    def test_all_four_role_paths_and_worker_nonroot_pins_use_only_enrolled_namespaces(self):
        for role, path in (("OBSERVER", "policy-observer"), ("BROKER", "capacity-broker"), ("WORKER", "probe-worker")):
            expected = deepcopy(self.expected)
            expected["cgroup"]["path"] = "/sys/fs/cgroup/planeon-live/" + path
            self.cgroup_raw = ("0::/planeon-live/" + path + "\n").encode()
            if role == "WORKER":
                expected["uid"] = expected["gid"] = 12345
                self.status_raw = self.process_status(Uid="12345 12345 12345 12345", Gid="12345 12345 12345 12345")
            view = self.view(role, expected)
            self.assertIsNone(view.check())
            self.assertEqual(len(view.rows), 8)
            view.close()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_namespace_readonly_ioctl_is_identical_on_both_supported_abis(self):
        fd = self.allocate("/proc/411/ns/user")
        for machine in ("x86_64", "aarch64"):
            with self.subTest(machine=machine), patch.object(server.os, "uname", return_value=SimpleNamespace(machine=machine)):
                reader = server._KernelNativeReads()
                observed = reader.namespace_identity(fd)
                self.assertEqual(observed["kind"], 0x10000000)
                self.assertEqual(observed["identity"][1], self.expected["namespaceInodes"]["user"])
                reader.close()
        self.assertTrue(all(call.args == (fd, 0xb703, 0) for call in self.ioctl.call_args_list))
        self.lib.syscall.assert_not_called()
        self.close_fd(fd)

    def test_missing_pidfd_permission_inheritance_and_late_acquisition_are_unavailable(self):
        with patch.object(server.os, "pidfd_open", Mock(side_effect=PermissionError("unit"))), self.assertRaises(PermissionError):
            self.view()
        self.assertEqual(set(self.handles), self.root_fds)
        def inherited(fd):
            return self.handles[fd][0] == "/pidfd/411"
        with patch.object(server.os, "get_inheritable", Mock(side_effect=inherited)), self.assertRaises(ConformanceError):
            self.view()
        self.assertEqual(set(self.handles), self.root_fds)
        def delayed(pid, flags):
            fd = self.pidfd_open(pid, flags)
            self.now += 2
            return fd
        with patch.object(server.os, "pidfd_open", Mock(side_effect=delayed)), self.assertRaisesRegex(ConformanceError, "DEADLINE"):
            self.view()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_exit_during_a_blocking_read_refuses_the_returned_bytes(self):
        view = self.view()
        def dies(fd, size):
            raw = self.read(fd, size)
            self.dead = True
            return raw
        with patch.object(server.os, "read", Mock(side_effect=dies)), self.assertRaisesRegex(ConformanceError, "EXITED_OR_REUSED"):
            view.check()
        self.dead = False
        view.close()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_namespace_link_change_during_open_refuses_the_acquired_view(self):
        def changed(name, flags, *, dir_fd):
            fd = self.open_fd(name, flags, dir_fd=dir_fd)
            if name == "net":
                self.links["/proc/411/ns/net"]["st_ino"] += 1
            return fd
        with patch.object(server.os, "open", Mock(side_effect=changed)), self.assertRaisesRegex(ConformanceError, "NAMESPACE_PIN"):
            self.view()
        self.assertEqual(set(self.handles), self.root_fds)


class KernelPolicyCustodyTests(unittest.TestCase):
    """Real policy/root/status factories with only synthetic OS edges."""
    stat_fd = KernelRootCustodyTests.stat_fd
    statfs = KernelRootCustodyTests.statfs
    statx = KernelRootCustodyTests.statx
    close_fd = KernelRootCustodyTests.close_fd

    def setUp(self):
        KernelRootCustodyTests.setUp(self)
        self.host = deepcopy(sample()["record"]["host"])
        self.selinux = deepcopy(sample()["record"]["selinux"])
        self.machine, self.release, self.page_size = self.host["machine"], self.host["kernelRelease"], 4096
        self.raw_status = server.struct.pack("<5I", *(self.selinux["status"][key] for key in
            ("version", "sequence", "enforcing", "policyload", "denyUnknown")))
        self.contents = {"/proc/sys/kernel/random/boot_id": (self.host["bootId"] + "\n").encode(),
            "/sys/kernel/notes": b"independent kernel note bytes",
            "/sys/fs/selinux/enforce": b"1", "/sys/fs/selinux/deny_unknown": b"1",
            "/sys/fs/selinux/policy": b"independent unit-only policy image"}
        self.host["kernelNotesDigest"] = byte_digest(self.contents["/sys/kernel/notes"])
        self.selinux["policyDigest"] = byte_digest(self.contents["/sys/fs/selinux/policy"])
        self.offsets, self.snapshots, self.views, self.events, self.maps = {}, {}, [], [], []
        for index, path in enumerate(("/proc/sys", "/proc/sys/kernel", "/proc/sys/kernel/random",
                "/proc/sys/kernel/random/boot_id", "/sys/kernel/notes", "/sys/fs/selinux/status",
                "/sys/fs/selinux/enforce", "/sys/fs/selinux/deny_unknown", "/sys/fs/selinux/policy")):
            root = self.nodes["/proc" if path.startswith("/proc/") else
                              "/sys/fs/selinux" if path.startswith("/sys/fs/") else "/sys/kernel"]
            self.nodes[path] = {**root, "st_ino": 200 + index,
                "st_mode": stat.S_IFDIR | 0o555 if index < 3 else stat.S_IFREG | (0o644 if index == 6 else 0o444),
                "st_size": 4096 if index == 5 else 0}
        def patched(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        patched(server.os, "uname", side_effect=lambda: SimpleNamespace(
            sysname="Linux", machine=self.machine, release=self.release))
        patched(server.os, "sysconf", side_effect=lambda name: self.page_size if name == "SC_PAGESIZE" else None)
        self.read_fd = patched(server.os, "read", side_effect=self.read)
        self.named = patched(server.os, "stat", side_effect=self.named_stat)
        self.lib.syscall = Mock(side_effect=self.barrier)
        self.mapper.side_effect = self.mapping
        patched(server.os, "write", side_effect=AssertionError("no policy writes"))
        patched(server.os, "execve", side_effect=AssertionError("no execution"))
        self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        self.addCleanup(self.close_views)
        self.root_fds = set(self.handles)

    def open_fd(self, name, flags, *, dir_fd):
        path = "/" if dir_fd is None else self.handles[dir_fd][0].rstrip("/") + "/" + name
        self.assertIn(path, self.nodes)
        self.assertTrue(name == "/" or "/" not in name)
        expected = server.os.O_RDONLY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK
        if stat.S_ISDIR(self.nodes[path]["st_mode"]):
            expected |= server.os.O_DIRECTORY
        self.assertEqual(flags, expected)
        if path == "/sys/fs/selinux/policy":
            self.assertFalse(any(p == path for p, _ in self.handles.values()), "policy snapshot retained across opens")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.handles[fd] = (path, self.nodes[path])
        self.opens.append((path, fd, dir_fd))
        self.offsets[fd] = 0
        if path in self.contents:
            self.snapshots[fd] = self.contents[path]  # kernel policy is snapshotted on open
        self.events.append(("open", path, fd))
        return fd

    def named_stat(self, name, *, dir_fd, follow_symlinks):
        self.assertFalse(follow_symlinks)
        node = self.nodes[self.handles[dir_fd][0].rstrip("/") + "/" + name]
        return SimpleNamespace(**{key: value for key, value in node.items() if key.startswith("st_")})

    def read(self, fd, limit):
        self.assertTrue(0 < limit <= 65536)
        self.events.append(("read", self.handles[fd][0], fd))
        offset = self.offsets[fd]
        chunk = self.snapshots[fd][offset:offset + limit]
        self.offsets[fd] += len(chunk)
        return chunk

    def barrier(self, number, command, flags, cpu):
        self.assertEqual(number.value, 324 if self.machine == "x86_64" else 283)
        self.assertEqual((flags.value, cpu.value), (0, 0))
        self.assertIn(command.value, (0, 16, 8))
        return 24 if command.value == 0 else 0

    def mapping(self, fd, length, *, flags, prot):
        self.assertEqual(self.handles[fd][0], "/sys/fs/selinux/status")
        self.assertEqual((length, flags, prot), (self.page_size, server.mmap.MAP_SHARED, server.mmap.PROT_READ))
        owner = self
        class Mapping:
            closes = 0
            def __getitem__(self, key):
                return owner.raw_status[key]
            def close(self):
                self.closes += 1
        value = Mapping()
        self.maps.append(value)
        self.events.append(("epoch", "status", fd))
        return value

    def close_views(self):
        for value in self.views:
            if not value.closed:
                value.close()

    def view(self, host=None, selinux=None):
        value = server._KernelPolicyView(self.roots, self.host if host is None else host,
                                          self.selinux if selinux is None else selinux)
        self.views.append(value)
        return value

    def test_fresh_policy_open_each_check_retains_only_fixed_kernel_views(self):
        value = self.view()
        self.assertEqual(len(value.rows), 8)
        self.assertEqual(len(self.handles), len(self.root_fds) + 8)
        self.assertIsNone(value.check())
        policy_fds = [fd for path, fd, _ in self.opens if path == "/sys/fs/selinux/policy"]
        self.assertEqual(len(policy_fds), 2)
        self.assertEqual(len(set(policy_fds)), 2)
        self.assertTrue(all(fd in self.closed for fd in policy_fds))
        self.assertFalse(any(p == "/sys/fs/selinux/policy" for p, _ in self.handles.values()))
        self.assertTrue(all(item.closes == 1 for item in self.maps))
        self.assertFalse(any(type(item) is bytes for item in vars(value).values()))
        value.close()
        value.close()
        self.assertEqual(set(self.handles), self.root_fds)
        self.assertIsNone(self.roots.check())

    def test_factory_has_no_backend_path_descriptor_or_qualified_selector(self):
        before = len(self.opens)
        for extra in ({"backend": Mock()}, {"path": "/tmp/policy"}, {"fd": 77}, {"qualified": True}):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                server._KernelPolicyView(self.roots, self.host, self.selinux, **extra)
        with self.assertRaises(ConformanceError):
            server._KernelPolicyView(Mock(), self.host, self.selinux)
        self.assertEqual(len(self.opens), before)

    def test_closed_host_policy_pins_refuse_before_kernel_access(self):
        changes = [("host", "bootId", "not-a-uuid"), ("host", "machine", "emulated"),
            ("host", "kernelRelease", "bad\nrelease"), ("host", "kernelNotesDigest", "mutable"),
            ("selinux", "policyDigest", "latest"), ("selinux", "status", {"sequence": 2})]
        before = len(self.opens)
        for target, key, bad in changes:
            host, selinux = deepcopy(self.host), deepcopy(self.selinux)
            (host if target == "host" else selinux)[key] = bad
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                self.view(host, selinux)
        for target in ("host", "selinux"):
            host, selinux = deepcopy(self.host), deepcopy(self.selinux)
            (host if target == "host" else selinux)["verified"] = True
            with self.assertRaises(ConformanceError):
                self.view(host, selinux)
        for key, bad in (("sequence", True), ("sequence", 3), ("sequence", 2 ** 32), ("policyload", 0)):
            selinux = deepcopy(self.selinux)
            selinux["status"][key] = bad
            with self.assertRaises(ConformanceError):
                self.view(selinux=selinux)
        self.assertEqual(len(self.opens), before)

    def test_expected_pins_are_detached_without_authenticating_them(self):
        value = self.view()
        self.host["bootId"] = "00000000-0000-0000-0000-000000000000"
        self.selinux["status"]["sequence"] += 2
        self.selinux["policyDigest"] = admission.ZERO
        self.assertIsNone(value.check())
        self.assertFalse(hasattr(value, "qualified"))

    def test_boot_kernel_release_machine_and_notes_mismatches_refuse(self):
        for fault in ("boot", "release", "machine", "notes"):
            host = deepcopy(self.host)
            if fault == "boot":
                host["bootId"] = "00000000-0000-0000-0000-000000000000"
            elif fault == "release":
                host["kernelRelease"] += "-other"
            elif fault == "machine":
                host["machine"] = "aarch64"
            else:
                host["kernelNotesDigest"] = admission.ZERO
            with self.subTest(fault=fault), self.assertRaises(ConformanceError):
                self.view(host=host)
            self.assertEqual(set(self.handles), self.root_fds)

    def test_policy_digest_change_is_not_hidden_by_retained_snapshot(self):
        value = self.view()
        self.contents["/sys/fs/selinux/policy"] += b"changed"
        with self.assertRaisesRegex(ConformanceError, "POLICY_DIGEST_CHANGED"):
            value.check()
        self.assertTrue(value.failed)
        before = len(self.opens)
        with self.assertRaises(ConformanceError):
            value.check()
        self.assertEqual(len(self.opens), before)

    def test_policy_epoch_change_during_read_refuses_even_if_hash_would_match(self):
        value = self.view()
        def changed(fd, limit):
            raw = self.read(fd, limit)
            if self.handles[fd][0] == "/sys/fs/selinux/policy":
                fields = list(server.struct.unpack("<5I", self.raw_status))
                fields[1] += 2
                self.raw_status = server.struct.pack("<5I", *fields)
            return raw
        with patch.object(server.os, "read", side_effect=changed), self.assertRaisesRegex(ConformanceError, "EPOCH_CHANGED"):
            value.check()
        self.assertFalse(any(p == "/sys/fs/selinux/policy" for p, _ in self.handles.values()))

    def test_policy_read_is_bracketed_by_real_status_reader(self):
        self.view()
        indexes = [i for i, event in enumerate(self.events) if event[:2] == ("read", "/sys/fs/selinux/policy")]
        self.assertGreaterEqual(len(indexes), 2)
        for index in indexes:
            self.assertEqual(self.events[index - 1][:2], ("epoch", "status"))
            self.assertEqual(self.events[index + 1][:2], ("epoch", "status"))
        self.assertGreater(self.lib.syscall.call_count, 4)

    def test_enforce_deny_unknown_and_status_controls_refuse(self):
        for name in ("enforce", "deny_unknown"):
            for raw in (b"0", b"1\n", b"", b"11"):
                self.contents["/sys/fs/selinux/" + name] = raw
                with self.subTest(name=name, raw=raw), self.assertRaises(ConformanceError):
                    self.view()
                self.assertEqual(set(self.handles), self.root_fds)
            self.contents["/sys/fs/selinux/" + name] = b"1"
        for index in (1, 2, 3, 4):
            original = self.raw_status
            fields = list(server.struct.unpack("<5I", original))
            fields[index] = fields[index] + 1 if index in (1, 3) else 0
            self.raw_status = server.struct.pack("<5I", *fields)
            with self.subTest(field=index), self.assertRaises(ConformanceError):
                self.view()
            self.raw_status = original

    def test_boot_change_during_policy_read_is_detected_after_read(self):
        value = self.view()
        def changed(fd, limit):
            raw = self.read(fd, limit)
            if self.handles[fd][0] == "/sys/fs/selinux/policy":
                self.contents["/proc/sys/kernel/random/boot_id"] = b"00000000-0000-0000-0000-000000000000\n"
            return raw
        with patch.object(server.os, "read", side_effect=changed), self.assertRaisesRegex(ConformanceError, "HOST_CHANGED"):
            value.check()

    def test_busy_policy_open_is_unavailable_without_cache_retry_or_write(self):
        value = self.view()
        attempts = []
        def busy(name, flags, *, dir_fd):
            if name == "policy":
                attempts.append(name)
                raise BlockingIOError(16, "unit policy busy")
            return self.open_fd(name, flags, dir_fd=dir_fd)
        with patch.object(server.os, "open", side_effect=busy), self.assertRaises(BlockingIOError):
            value.check()
        self.assertEqual(attempts, ["policy"])
        self.assertTrue(value.failed)
        self.assertEqual(len(self.handles), len(self.root_fds) + 8)

    def test_policy_permission_or_read_error_never_uses_old_digest(self):
        for error in (PermissionError("unit read denied"), OSError("unit read unavailable")):
            value = self.view()
            def refused(fd, limit):
                if self.handles[fd][0] == "/sys/fs/selinux/policy":
                    raise error
                return self.read(fd, limit)
            with patch.object(server.os, "read", side_effect=refused), self.assertRaises(OSError):
                value.check()
            value.close()
            self.assertEqual(set(self.handles), self.root_fds)

    def test_empty_oversize_and_wrong_type_policy_reads_refuse(self):
        for fault in ("empty", "oversize", "type"):
            value = self.view()
            def invalid(fd, limit):
                if self.handles[fd][0] != "/sys/fs/selinux/policy":
                    return self.read(fd, limit)
                if fault == "empty":
                    return b""
                if fault == "type":
                    return bytearray(b"unit")
                return b"x" * limit  # stream crosses the fixed64MiB bound
            with patch.object(server.os, "read", side_effect=invalid), self.assertRaises(ConformanceError):
                value.check()
            value.close()
            self.assertEqual(set(self.handles), self.root_fds)

    def test_partial_reads_hash_complete_fresh_policy(self):
        def partial(fd, limit):
            return self.read(fd, min(limit, 3))
        with patch.object(server.os, "read", side_effect=partial):
            value = self.view()
            self.assertIsNone(value.check())

    def test_substituted_kernel_file_mount_owner_or_mode_refuses(self):
        for path, field, bad in (("/proc/sys", "mountId", 900), ("/sys/kernel/notes", "st_uid", 1),
            ("/sys/fs/selinux/policy", "st_gid", 1), ("/sys/fs/selinux/enforce", "st_mode", stat.S_IFREG | 0o666)):
            old = self.nodes[path][field]
            self.nodes[path][field] = bad
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.view()
            self.nodes[path][field] = old
            self.assertEqual(set(self.handles), self.root_fds)

    def test_named_file_replacement_and_retained_fd_replacement_refuse(self):
        for fault in ("path", "fd"):
            value = self.view()
            path = "/proc/sys/kernel/random/boot_id"
            old = self.nodes[path]
            if fault == "path":
                self.nodes[path] = {**old, "st_ino": old["st_ino"] + 1}
            else:
                fd = value.rows[3][0]
                self.handles[fd] = (path, {**old, "st_ino": old["st_ino"] + 1})
            with self.assertRaises(ConformanceError):
                value.check()
            if fault == "path":
                self.nodes[path] = old
                value.close()
            else:
                with self.assertRaisesRegex(ConformanceError, "FD_REUSED"):
                    value.close()
                self.assertIn(fd, self.handles)
                self.close_fd(fd)  # synthetic foreign owner, not the product
            self.assertEqual(set(self.handles), self.root_fds)

    def test_status_path_replacement_during_fence_is_detected(self):
        value = self.view()
        changed = False
        def fence(*args):
            nonlocal changed
            result = self.barrier(*args)
            if args[1].value == 8 and not changed:
                path = "/sys/fs/selinux/status"
                self.nodes[path] = {**self.nodes[path], "st_ino": 999}
                changed = True
            return result
        with patch.object(self.lib, "syscall", Mock(side_effect=fence)), self.assertRaisesRegex(ConformanceError, "STATUS_CHANGED"):
            value.check()

    def test_policy_path_replacement_between_checks_refuses_even_same_bytes(self):
        value = self.view()
        path = "/sys/fs/selinux/policy"
        self.nodes[path] = {**self.nodes[path], "st_ino": 999}
        with self.assertRaisesRegex(ConformanceError, "PATH_CHANGED"):
            value.check()

    def test_late_partial_acquisition_closes_just_owned_handles(self):
        def slow(name, flags, *, dir_fd):
            fd = self.open_fd(name, flags, dir_fd=dir_fd)
            if name == "random":
                self.now += 2
            return fd
        with patch.object(server.os, "open", side_effect=slow), self.assertRaisesRegex(ConformanceError, "DEADLINE"):
            self.view()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_complete_policy_phase_has_one_budget_not_per_chunk(self):
        value = self.view()
        def slow(fd, limit):
            raw = self.read(fd, min(limit, 4))
            self.now += 0.25
            return raw
        with patch.object(server.os, "read", side_effect=slow), self.assertRaisesRegex(ConformanceError, "DEADLINE"):
            value.check()
        value.close()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_wrong_process_thread_backward_clock_and_closed_state_refuse(self):
        for obj, name in ((server.os, "getpid"), (server.threading, "get_ident")):
            value = self.view()
            before = len(self.opens)
            with patch.object(obj, name, return_value=999), self.assertRaises(ConformanceError):
                value.check()
            self.assertEqual(len(self.opens), before)
            value.close()
        value = self.view()
        self.now -= 1
        with self.assertRaises(ConformanceError):
            value.check()
        self.now += 1
        value.close()
        with self.assertRaises(ConformanceError):
            value.check()

    def test_cleanup_uncertainty_is_sticky_and_never_retries_close(self):
        value = self.view()
        closed = []
        def uncertain(fd):
            self.close_fd(fd)
            closed.append(fd)
            if len(closed) == 1:
                raise OSError("unit close uncertain")
        with patch.object(server.os, "close", side_effect=uncertain), self.assertRaises(OSError):
            value.close()
        self.assertEqual(len(closed), 8)
        self.assertEqual(set(self.handles), self.root_fds)
        with self.assertRaises(OSError):
            value.close()
        self.assertEqual(len(closed), 8)

    def test_temporary_policy_close_failure_invalidates_reader_and_keeps_roots(self):
        value = self.view()
        failed = []
        def uncertain(fd):
            path = self.handles[fd][0]
            self.close_fd(fd)
            if path == "/sys/fs/selinux/policy":
                failed.append(fd)
                raise OSError("unit policy close uncertain")
        with patch.object(server.os, "close", side_effect=uncertain), self.assertRaises(OSError):
            value.check()
        with self.assertRaises(OSError):
            value.close()
        self.assertEqual(len(failed), 1)
        self.assertEqual(self.closed.count(failed[0]), 1)
        self.assertEqual(set(self.handles), self.root_fds)

    def test_arm64_kernel_policy_uses_actual_page_and_private_fences(self):
        self.roots.close()
        self.machine = self.host["machine"] = "aarch64"
        self.page_size = 65536
        self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        self.root_fds = set(self.handles)
        self.assertIsNone(self.view().check())
        self.assertTrue(all(item.closes == 1 for item in self.maps))
        self.ioctl.assert_not_called()


class ProxyQualificationTests(unittest.TestCase):
    def test_four_architecture_resource_profiles_and_sixteen_captures_are_data_only(self):
        self.assertEqual(len(VECTORS["qualification"]["positive"]), 4)
        for value in VECTORS["qualification"]["positive"]:
            self.assertEqual(record_check(value), value["record"])
            for capture in value["captures"]:
                self.assertIsNone(capture_check(value, capture))
                self.assertEqual(capture["evidenceClass"], "DATA_CHECK_ONLY")

    def test_every_nested_record_object_is_closed(self):
        value = sample()
        paths = []
        def visit(node, path):
            if type(node) is dict:
                paths.append(path)
                for key, child in node.items():
                    visit(child, path + [key])
            elif type(node) is list:
                for key, child in enumerate(node):
                    visit(child, path + [key])
        visit(value["record"], [])
        self.assertGreater(len(paths), 40)
        for path in paths:
            current = sample()
            target = current["record"]
            for key in path:
                target = target[key]
            target["nativeQualified"] = True
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                record_check(current)

    def test_unknown_capture_grants_and_wrong_role_never_qualify(self):
        value = sample()
        for flag in ("verified", "nativeAcceptance", "tenantAcceptance", "handle", "backend"):
            with self.subTest(flag=flag), self.assertRaises(ConformanceError):
                capture_check(value, {**value["captures"][0], flag: True})
        with self.assertRaises(ConformanceError):
            capture_check(value, value["captures"][0], "BROKER")

    def test_record_rejects_circular_digest_unknown_profile_and_scope_substitution(self):
        for key in ("releaseDigest", "bindingDigest", "manifestDigest", "signature", "selfDigest"):
            value = sample()
            value["record"][key] = admission.ZERO
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                record_check(value)
        for field in sample()["record"]["scope"]:
            value = sample()
            value["record"]["scope"][field] = "foreign"
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                record_check(value)

    def test_boolean_control_characters_floats_and_noncanonical_record_bytes_refused(self):
        value = sample()
        for field, bad in (("sequence", True), ("enforcing", True), ("policyload", 1.0), ("sequence", 3)):
            current = sample()
            current["record"]["selinux"]["status"][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ConformanceError):
                record_check(current)
        for raw in (canonical_bytes(value["record"]) + b"\n", b'{"a":1,"a":2}'):
            with self.assertRaises((ConformanceError, ValueError)):
                admission.validate_qualification_record(raw, value["profile"], value["endpoints"])
        value["record"]["roles"]["SERVER"]["processLabel"] += "\u0000"
        with self.assertRaises(ConformanceError):
            record_check(value)

    def test_endpoint_tuple_pins_and_ambiguous_addresses_refused(self):
        for ip, family in (("0.0.0.0", "IPV4"), ("224.0.0.1", "IPV4"), ("::", "IPV6"),
                           ("::ffff:127.0.0.1", "IPV6"), ("fe80::1%eth0", "IPV6"),
                           ("0:0:0:0:0:0:0:1", "IPV6"), ("proxy.example", "IPV4")):
            value = sample()
            value["endpoints"][0].update(ipAddress=ip, addressFamily=family)
            value["record"]["endpointTuples"] = deepcopy(value["endpoints"])
            with self.subTest(ip=ip), self.assertRaises(ConformanceError):
                record_check(value)
        value = sample()
        value["record"]["endpointTuples"][0]["port"] += 1
        with self.assertRaises(ConformanceError):
            record_check(value)

    def test_code_inventory_duplicate_alias_missing_and_conflated_hashes_refused(self):
        for fault in ("duplicate", "missing", "alias", "verity", "unowned", "segment"):
            value = sample()
            files = value["record"]["files"]
            if fault == "duplicate":
                files.append(deepcopy(files[0]))
            elif fault == "missing":
                files.pop()
            elif fault == "alias":
                files[0]["path"] = "/opt/planeon/../planeon/bin/harness-live-proxy-serve"
            elif fault == "verity":
                files[0]["verityDigest"] = files[0]["sha256"]
            elif fault == "unowned":
                files.append({**files[0], "path": "/opt/planeon/unused"})
            else:
                files[-1]["executableSegments"][0]["length"] = 4097
            with self.subTest(fault=fault), self.assertRaises(ConformanceError):
                record_check(value)

    def test_worker_network_and_server_extra_connect_grants_refused(self):
        for index, role in ((0, "SERVER"), (0, "WORKER"), (1, "SERVER"), (1, "WORKER")):
            value = sample(index)
            value["record"]["roles"][role]["outboundEndpointIds"] = [value["profile"]["binding"]["endpointId"]]
            with self.subTest(index=index, role=role), self.assertRaises(ConformanceError):
                record_check(value)

    def test_program_type_alignment_maps_offload_and_missing_hook_refused(self):
        for field, bad in (("programType", 18), ("instructionBytes", 9), ("mapIds", [1]), ("ifindex", 1)):
            value = sample()
            value["record"]["roles"]["SERVER"]["bpfPrograms"]["INET_SOCK_CREATE"][field] = bad
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                record_check(value)
        value = sample()
        del value["record"]["roles"]["SERVER"]["bpfPrograms"]["UDP6_SENDMSG"]
        with self.assertRaises(ConformanceError):
            record_check(value)

    def test_policy_epoch_or_kernel_digest_change_refused(self):
        for key in ("selinuxBefore", "selinuxAfter"):
            value = sample()
            capture = value["captures"][0]
            capture[key]["sequence"] += 2
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                capture_check(value, capture)
        value = sample()
        value["captures"][0]["kernelPolicyDigest"] = admission.ZERO
        with self.assertRaises(ConformanceError):
            capture_check(value, value["captures"][0])

    def test_injected_missing_or_writable_executable_mapping_refused(self):
        for fault in ("missing", "extra", "inode", "permissions", "offset"):
            value = sample()
            capture = value["captures"][0]
            maps = capture["executableMaps"]
            if fault == "missing":
                maps.clear()
            elif fault == "extra":
                maps.append(deepcopy(maps[0]))
            else:
                maps[0][fault] = "rwxp" if fault == "permissions" else maps[0][fault] + 1
            with self.subTest(fault=fault), self.assertRaises(ConformanceError):
                capture_check(value, capture)

    def test_local_and_effective_programs_both_must_be_exact(self):
        for field in ("localIds", "effectiveIds"):
            for bad in ([], [123456], [1000, 123456]):
                value = sample()
                capture = value["captures"][0]
                capture["bpfPrograms"]["INET_SOCK_CREATE"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(ConformanceError):
                    capture_check(value, capture)

    def test_inspection_deadlines_expiry_and_clock_renewal_refused(self):
        for key, bad in (("inspectionFinishedMs", 3001), ("inspectionStartedMs", 1101),
                         ("deadlineMs", 1100), ("deadlineMs", 901001),
                         ("observedAt", "2026-09-08T00:10:00Z")):
            value = sample()
            value["captures"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                capture_check(value, value["captures"][0])

    def test_retained_pid_start_file_namespace_and_deadline_cannot_change(self):
        value = sample()
        previous = value["captures"][0]
        current = deepcopy(previous)
        current.update(inspectionStartedMs=1200, inspectionFinishedMs=1300)
        self.assertIsNone(capture_check(value, current, previous=previous))
        for field in ("pid", "startTicks"):
            changed = deepcopy(current)
            changed["process"][field] += 1
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                capture_check(value, changed, previous=previous)
        current["deadlineMs"] += 1
        with self.assertRaises(ConformanceError):
            capture_check(value, current, previous=previous)

    def test_fixed_release_member_preflight_mode_size_digest_and_duplicates(self):
        value = sample()
        raw = canonical_bytes(value["record"])
        row = {"path": admission.QUALIFICATION_PATH, "mode": "0444", "size": len(raw), "sha256": byte_digest(raw)}
        observation = {"enforcementPins": {"hostPreflightDigest": byte_digest(raw)}}
        args = (value["profile"], value["endpoints"], observation)
        kit = {admission.QUALIFICATION_PATH: raw}
        self.assertEqual(admission.retained_qualification_record(*args, {"tree": [row]}, kit), value["record"])
        for rows in ([], [row, row], [{**row, "mode": "0644"}], [{**row, "size": 1}], [{**row, "sha256": admission.ZERO}]):
            with self.subTest(rows=rows), self.assertRaises(ConformanceError):
                admission.retained_qualification_record(*args, {"tree": rows}, kit)
        with self.assertRaises(ConformanceError):
            admission.retained_qualification_record(*args, {"tree": [row]}, {admission.QUALIFICATION_PATH: raw + b"\n"})


class ProxyServerCustodyTests(unittest.TestCase):
    def accept_owner(self):
        owner = object.__new__(server.NativeProxyServer)
        owner.connection = None
        owner.deadline = 100
        owner.listener = Mock()
        owner._transport_check = Mock()
        return owner

    def test_accept_polls_same_listener_without_renewing_phase(self):
        owner = self.accept_owner()
        connection = Mock()
        owner.listener.accept.side_effect = [TimeoutError(), (connection, ("127.0.0.1", 1))]
        with patch.object(server.time, "monotonic", side_effect=[0, 0, 2, 2, 3]):
            owner._accept()
        self.assertIs(owner.connection, connection)
        self.assertEqual(owner.listener.settimeout.call_args_list, [unittest.mock.call(2)] * 2)
        self.assertEqual(owner._transport_check.call_count, 4)
        connection.set_inheritable.assert_called_once_with(False)

    def test_accept_slow_trickle_cannot_extend_ten_second_phase(self):
        owner = self.accept_owner()
        owner.listener.accept.side_effect = TimeoutError()
        with patch.object(server.time, "monotonic", side_effect=[0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10]):
            with self.assertRaises(ConformanceError):
                owner._accept()
        self.assertEqual(owner.listener.accept.call_count, 5)
        self.assertEqual(owner._transport_check.call_count, 10)
        self.assertIsNone(owner.connection)

    def test_accept_retains_connection_when_post_io_policy_fails(self):
        owner = self.accept_owner()
        connection = Mock()
        owner.listener.accept.return_value = connection, ("127.0.0.1", 1)
        owner._transport_check.side_effect = [None, TimeoutError("unit policy failure")]
        with patch.object(server.time, "monotonic", return_value=0), self.assertRaises(TimeoutError):
            owner._accept()
        self.assertIs(owner.connection, connection)
        owner.listener.accept.assert_called_once()
        # The actual serve-finally path, not a mock cleanup, owns the connection.
        owner._transport_check.side_effect = None
        with self.assertRaises(ConformanceError):
            owner.serve()
        connection.close.assert_called_once()
        self.assertIsNone(owner.connection)

    def test_real_factory_refuses_uninstalled_nonlinux_before_credentials_or_socket(self):
        with patch.object(server.sys, "platform", "darwin"), patch.object(server.os, "open") as opened, patch.object(server.socket, "socket") as sockets:
            with self.assertRaises(ConformanceError):
                server.NativeProxyServer()
            opened.assert_not_called()
            sockets.assert_not_called()

    def test_factory_accepts_no_caller_backend_descriptor_or_context(self):
        for kwargs in ({"backend": Mock()}, {"context": {}}, {"fd": 12}, {"qualified": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                server.NativeProxyServer(**kwargs)

    def test_files_reject_uncanonical_paths_before_os_open(self):
        owner = Mock()
        files = server._Files(owner)
        class Alias:
            def __eq__(self, value):
                return True
        for path in (None, Alias(), "/tmp/../secret", "/tmp//secret", "/tmp/", "relative", "/tmp\\secret"):
            with self.subTest(path=type(path).__name__), patch.object(server.os, "open") as opened, self.assertRaises(ConformanceError):
                files._open(path, False)
            opened.assert_not_called()

    def test_custody_partial_open_failure_closes_acquired_fd_once(self):
        files = server._Files(Mock())
        with patch.object(server.os, "open", return_value=71), patch.object(server.os, "fstat", side_effect=OSError("unit")), patch.object(server.os, "close") as close:
            with self.assertRaises(OSError):
                files._open("/", True)
            files.close()
            files.close()
            close.assert_called_once_with(71)

    def test_recycled_descriptor_is_not_closed_and_other_cleanup_continues(self):
        files = server._Files(Mock())
        info = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o444,
                               st_nlink=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
        original = server._custody_identity(info)
        files.rows = {"/one": [71, None, "one", original], "/two": [72, None, "two", original]}
        def observed(fd):
            return SimpleNamespace(**{**vars(info), "st_ino": 999 if fd == 72 else 2})
        with patch.object(server.os, "fstat", side_effect=observed), patch.object(server.os, "close") as close:
            with self.assertRaises(ConformanceError):
                files.close()
            close.assert_called_once_with(71)
            with self.assertRaises(ConformanceError):
                files.close()
            self.assertEqual(close.call_count, 1)


class ProxyPredecessorTests(unittest.TestCase):
    def test_all_127_predecessor_files_preserved_through_closed_successor_stages(self):
        baseline = VECTORS["acceptedCheckpoint"]
        self.assertEqual(baseline["commit"], "9df7dd7f2df8ac64096ef37d8df259761947d552")
        self.assertEqual(baseline["tree"], "1310cc74cc0ed39cfeb1068e998a0f78502a4be4")
        self.assertEqual(baseline["fileCount"], 127)
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        result = validate_checkpoint(rows, sources)
        _, historical_sources, _ = SUCCESSOR.performance_history(rows, sources)
        self.assertIn(result["stage"], (3, 4, 5, 6))
        self.assertEqual(len(rows), (135, 141, 146, 151)[result["stage"] - 3])
        indexed = {row["path"]: row for row in rows}
        for path, expected in baseline["files"].items():
            if result["stage"] == 6 and path == SUCCESSOR.RECORD["hook"]["path"]:
                # The accepted validator above has already checked the exact
                # final hook delta proof. Mere filename presence grants nothing.
                continue
            raw = historical_sources[path]
            with self.subTest(path=path):
                self.assertEqual(byte_digest(raw), expected["sha256"])
                self.assertEqual(len(raw), expected["size"])
                self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), expected["blob"])
                self.assertEqual(indexed[path]["mode"], expected["mode"])
        current = current_checkpoint(VECTORS["currentCheckpoint"])
        self.assertEqual((current["commit"], current["tree"], current["fileCount"], current["testCount"]),
                         ("f988c78e93b28257810ed99e7f0c072e9b76bae5", "542d2e8e49389bb387a84f76700138c3de833f4e", 127, 362))
        for path, expected in current["files"].items():
            if result["stage"] == 6 and path == SUCCESSOR.RECORD["hook"]["path"]:
                continue  # validate_checkpoint already verifies the exact hook proof
            raw = sources[path]
            with self.subTest(currentPath=path):
                self.assertEqual(byte_digest(raw), expected["sha256"])
                self.assertEqual(len(raw), expected["size"])
                self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), expected["blob"])
                self.assertEqual(indexed[path]["mode"], expected["mode"])

    def test_all_327_exact_predecessor_methods_freshly_collected_without_replacement(self):
        baseline = VECTORS["acceptedCheckpoint"]
        observed = {}
        for root in SUITE_ROOTS:
            modules = isolated_inventory(ROOT / root)
            observed.update({root + "/" + path: methods for path, methods in modules.items()})
        self.assertEqual(sum(map(len, baseline["tests"].values())), 327)
        for path, methods in baseline["tests"].items():
            self.assertTrue(set(methods) <= set(observed[path]), path)
        current = current_checkpoint(VECTORS["currentCheckpoint"])
        self.assertEqual(sum(map(len, current["tests"].values())), 362)
        for path, methods in current["tests"].items():
            self.assertEqual(observed[path], methods, path)
        additions = set(observed) - set(baseline["tests"])
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        stage = validate_checkpoint(rows, sources)["stage"]
        expected = {path for number in range(3, stage + 1)
                    for path in BASELINE["packetPaths"][f"CONF-LIVE-{number:03d}"]
                    if path.startswith("tests/live_backend/test_") and path.endswith(".py")}
        self.assertEqual(additions, expected)
        print("CONF-LIVE-003 predecessor inventory: current 127 files / 362 methods; historical 327 and 354 retained; nativeAcceptance=false", flush=True)

    def test_current_checkpoint_pin_rejects_relabelled_history_and_altered_inventory(self):
        for field, value in (("commit", "9df7dd7f2df8ac64096ef37d8df259761947d552"),
                             ("testCount", 327), ("nativeAcceptance", True), ("tree", "0" * 40)):
            changed = deepcopy(VECTORS["currentCheckpoint"])
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                current_checkpoint(changed)
        for field in ("files", "tests"):
            changed = deepcopy(VECTORS["currentCheckpoint"])
            changed[field].pop(next(iter(changed[field])))
            with self.subTest(field=field), self.assertRaises(ValueError):
                current_checkpoint(changed)

    def test_corrected_checkpoint_preserves_the_original_performance_record(self):
        current = current_checkpoint(VECTORS["currentCheckpoint"])
        prior = VECTORS["performanceCheckpoint"]
        self.assertEqual(byte_digest(canonical_bytes(prior)),
                         "sha256:bbec5245350891df2207cd4b885908106f0d0ded7274c67873d0cf5396889506")
        self.assertEqual(current["predecessorCommit"], prior["commit"])
        self.assertEqual((current["packetId"], current["predecessorTests"], current["addedTests"]),
                         ("CONF-FIX-006", 354, 8))
        self.assertEqual(set(current["files"]), set(prior["files"]))
        self.assertEqual({p for p in current["files"] if current["files"][p] != prior["files"][p]},
                         {"tests/live_backend/test_supervisor.py", "docs/live-backend/linux-boundary.md"})
        for path, methods in prior["tests"].items():
            self.assertTrue(set(methods) <= set(current["tests"][path]), path)
        with self.assertRaises(ValueError):
            current_checkpoint(prior)
