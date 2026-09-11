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
        self.assertEqual((fd, length, flags, prot), (71, 4096, server.mmap.MAP_SHARED, server.mmap.PROT_READ))
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
            with patch.object(self.lib.fstatfs, "side_effect", None), patch.object(self.lib.fstatfs, "return_value", result):
                with self.assertRaises(ConformanceError):
                    self.fresh().filesystem(71)
        def spare(fd, pointer):
            self.filesystem(fd, pointer)
            pointer._obj.spare[3] = 1
            return 0
        with patch.object(self.lib.fstatfs, "side_effect", spare), self.assertRaises(ConformanceError):
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
            with self.subTest(result=result), patch.object(self.ioctl, "side_effect", None), patch.object(self.ioctl, "return_value", result):
                with self.assertRaises(ConformanceError):
                    self.fresh().measure_verity(71)
        for raw in (bytes.fromhex("02002000") + b"v" * 32, bytes.fromhex("01004000") + b"v" * 32):
            def wrong(fd, command, output, mutate):
                output[:] = raw
                return 0
            with patch.object(self.ioctl, "side_effect", wrong), self.assertRaises(ConformanceError):
                self.fresh().measure_verity(71)
        with patch.object(self.ioctl, "side_effect", PermissionError("unit")), self.assertRaises(PermissionError):
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
            with self.subTest(change=change), patch.object(self.ioctl, "side_effect", mutated):
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
        with patch.object(self.lib.syscall, "side_effect", change), self.assertRaises(ConformanceError):
            self.fresh().status_epoch(71)
        self.assertEqual(self.maps[-1].closes, 1)

    def test_private_barrier_missing_permissions_and_commands_poison_reader(self):
        for responses in ([0], [8], [-1], [24, -1], [24, 1], [24, 0, -1], [24, 0, 1]):
            with self.subTest(responses=responses), patch.object(self.lib.syscall, "side_effect", responses):
                with self.assertRaises(ConformanceError):
                    self.fresh().status_epoch(71)
                self.assertTrue(self.reader.failed)
                self.assertEqual(self.maps[-1].closes, 1)
        with patch.object(self.lib.syscall, "side_effect", OSError("unit")), self.assertRaises(OSError):
            self.fresh().status_epoch(71)
        self.assertEqual(self.maps[-1].closes, 1)

    def test_status_mapping_partial_failure_and_close_failure_are_not_retried(self):
        with patch.object(self.mapper, "side_effect", OSError("unit")), self.assertRaises(OSError):
            self.reader.status_epoch(71)
        self.assertEqual(self.maps, [])
        def cannot_close(*args, **kwargs):
            result = self.mapping(*args, **kwargs)
            result.close = Mock(side_effect=OSError("unit"))
            return result
        with patch.object(self.mapper, "side_effect", cannot_close), self.assertRaises(OSError):
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
            with self.subTest(change=change), patch.object(self.lib.syscall, "side_effect", mutate):
                with self.assertRaises(ConformanceError):
                    self.fresh().status_epoch(71)
                self.assertEqual(self.maps[-1].closes, 1)


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
