"""Data qualification, source preservation and OS-mocked custody refusals.

These tests do not substitute for the pending fixed native inspector and server
broker/API integration. Matching fixture data is explicitly not qualification.
"""
from copy import deepcopy
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
