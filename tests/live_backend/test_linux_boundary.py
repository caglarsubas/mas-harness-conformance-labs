import array
from contextlib import contextmanager
from copy import deepcopy
import ctypes
import errno
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from harness_conformance.errors import ConformanceError
from harness_conformance.canonical import byte_digest, canonical_bytes, canonical_digest
from harness_conformance.crypto import b64url_encode, public_key, sign
from harness_conformance import live
from harness_conformance import live_linux_boundary as linux


def interpret(code, architecture, syscall, argument=0):
    """Independent classic-BPF unit interpreter; never installs a filter."""
    accumulator, pc = 0, 0
    for _ in range(512):
        operation, yes, no, value = code[pc]
        if operation == 0x20:
            accumulator = {0: syscall, 4: architecture, 16: argument}[value]
        elif operation == 0x15:
            pc += yes if accumulator == value else no
        elif operation == 0x45:
            pc += yes if accumulator & value else no
        elif operation == 0x06:
            return value
        else:
            raise AssertionError("unexpected BPF instruction")
        pc += 1
    raise AssertionError("unbounded BPF program")


def peer_fixture():
    return dict(pid=120, start=345, parent=100, uid=(65532,) * 4, gid=(65532,) * 4,
        capabilities=(0,) * 5, seccomp=2, noNewPrivs=1, cgroup="0::/planeon-live/session\n",
        namespaces=dict(user=2, mnt=3, pid=4, net=5))


@contextmanager
def unit_file_custody(root):
    """Root UID is simulated only here; real temp FDs test no-follow/read logic."""
    real_stat, real_fstat = os.stat, os.fstat
    def owner(info):
        fields = {key: getattr(info, key) for key in ("st_mode", "st_uid", "st_gid", "st_dev", "st_ino",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
        return SimpleNamespace(**{**fields, "st_uid": 0, "st_gid": 0})
    def directory(path):
        if path != str(root):
            raise AssertionError("unit fixture attempted another path")
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    with patch.object(linux, "open_directory", side_effect=directory), patch.object(
            linux.os, "stat", side_effect=lambda *a, **kw: owner(real_stat(*a, **kw))), patch.object(
            linux.os, "fstat", side_effect=lambda *a, **kw: owner(real_fstat(*a, **kw))):
        yield


class LinuxBoundaryTests(unittest.TestCase):
    def test_ambient_environment_credentials_proxy_and_import_paths_are_rejected(self):
        for name in ("AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS", "SSH_AUTH_SOCK", "KUBECONFIG",
                     "HTTP_PROXY", "HTTPS_PROXY", "PYTHONPATH", "HARNESS_LIVE_BACKEND", "VERIFIED"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "unit-only"}, clear=True), patch.object(
                    linux.os, "listdir") as listing, self.assertRaises(ConformanceError):
                linux.ambient_custody()
            listing.assert_not_called()

    def test_ambient_extra_fd_or_socket_stdio_refuse_but_closed_listdir_fd_is_ignored(self):
        file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        with patch.dict(os.environ, {"LANG": "C", "HARNESS_LIVE_EXECUTION_ENVELOPE": "/unit-only/envelope"}, clear=True):
            for names, information in ((["0", "3"], file_info), (["0"], SimpleNamespace(st_mode=stat.S_IFSOCK))):
                with patch.object(linux.os, "listdir", return_value=names), patch.object(
                        linux.os, "fstat", return_value=information), self.assertRaises(ConformanceError):
                    linux.ambient_custody()
            with patch.object(linux.os, "listdir", return_value=["0", "1", "2", "3"]), patch.object(
                    linux.os, "fstat", side_effect=[file_info] * 3 + [OSError(errno.EBADF, "unit closed directory fd")]):
                linux.ambient_custody()

    def test_root_manifest_bytes_are_read_once_verified_and_retained_not_path_reopened(self):
        seed = bytes([31]) * 32  # Public deterministic UNIT fixture, not an operator key.
        public = canonical_bytes({"algorithm": "ED25519", "publicKey": b64url_encode(public_key(seed))})
        launcher = b"UNIT_ONLY_NOT_AN_EXECUTABLE"
        manifest = dict(schemaVersion="harness.planeon.ai/live-runner-manifest/v1alpha1",
            launcher=dict(path=str(live.EXPECTED_LAUNCHER), version="0.1.0", sha256=byte_digest(launcher),
                          ownerUid=0, ownerGid=0, mode="0555"),
            fixedTrustMounts=[str(live.FIXED_RELEASE_TRUST), str(live.FIXED_TENANT_TRUST)],
            isolation=dict(backend="PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1",
                networkPolicy="DENY_ALL_EXCEPT_DUAL_SIGNED_ENDPOINTS", credentialSocketsDenied=True, ciDenied=True),
            preflightEvidenceDigest="sha256:" + "a" * 64)
        raw = canonical_bytes(manifest)
        records = {str(live.FIXED_MANIFEST_PUBLIC): public, str(live.FIXED_MANIFEST): raw,
                   str(live.FIXED_MANIFEST_SIGNATURE): b64url_encode(sign(seed, raw)).encode(),
                   str(live.EXPECTED_LAUNCHER): launcher}
        def read(path, **kwargs):
            if "expected_digest" in kwargs:
                self.assertEqual(byte_digest(records[path]), kwargs["expected_digest"])
            if path == str(live.EXPECTED_LAUNCHER):
                self.assertEqual(kwargs["expected_mode"], 0o555)
            return records[path]
        with patch.object(linux, "_VERIFIED_MANIFEST", None), patch.object(
                live, "PINNED_ROOT_PUBLIC_KEY_SHA256", byte_digest(public)), patch.object(linux, "read_owned", side_effect=read) as reader:
            self.assertEqual(linux._installed_manifest_digest(), byte_digest(launcher))
            self.assertEqual(reader.call_count, 4)
            self.assertEqual(linux._installed_manifest_digest(), byte_digest(launcher))
            self.assertEqual(reader.call_count, 4)
        records[str(live.FIXED_MANIFEST_SIGNATURE)] = b64url_encode(bytes(64)).encode()
        with patch.object(linux, "_VERIFIED_MANIFEST", None), patch.object(
                live, "PINNED_ROOT_PUBLIC_KEY_SHA256", byte_digest(public)), patch.object(linux, "read_owned", side_effect=read), self.assertRaises(ConformanceError):
            linux._installed_manifest_digest()

    def test_owned_file_and_kit_use_single_read_content_and_exact_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            path = root / "unit.json"
            path.write_bytes(b"unit-custody")
            path.chmod(0o444)
            root.chmod(0o555)
            row = dict(mode="0444", path="unit.json", sha256=byte_digest(b"unit-custody"), size=12)
            digest = canonical_digest([row], "planeon.harness-live-tree/v1alpha1")
            try:
                with unit_file_custody(root):
                    self.assertEqual(linux.read_owned(str(path), expected_digest=row["sha256"]), b"unit-custody")
                    self.assertEqual(linux.read_owned_kit(str(root), digest), {"unit.json": b"unit-custody"})
                    with self.assertRaises(ConformanceError):
                        linux.read_owned(str(path), expected_digest="sha256:" + "f" * 64)
                    with self.assertRaises(ConformanceError):
                        linux.read_owned_kit(str(root), "sha256:" + "f" * 64)
            finally:
                root.chmod(0o700)

    def test_symlink_hardlink_write_mode_and_extra_file_kit_tampering_refuse(self):
        for kind in ("symlink", "hardlink", "writable", "extra"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                target = root / "target"
                target.write_bytes(b"x")
                target.chmod(0o444)
                row = dict(mode="0444", path="target", sha256=byte_digest(b"x"), size=1)
                digest = canonical_digest([row], "planeon.harness-live-tree/v1alpha1")
                if kind == "symlink":
                    (root / "alias").symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, root / "alias")
                elif kind == "writable":
                    target.chmod(0o644)
                else:
                    (root / "extra").write_bytes(b"unsigned")
                    (root / "extra").chmod(0o444)
                root.chmod(0o555)
                try:
                    with unit_file_custody(root), self.assertRaises((ConformanceError, OSError)):
                        linux.read_owned_kit(str(root), digest)
                finally:
                    root.chmod(0o700)

    def test_owned_file_read_rejects_hardlink_and_writable_file(self):
        for kind in ("hardlink", "writable", "symlink"):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                target = root / "target"
                target.write_bytes(b"x")
                target.chmod(0o444)
                if kind == "hardlink":
                    os.link(target, root / "alias")
                elif kind == "writable":
                    target.chmod(0o644)
                else:
                    (root / "alias").symlink_to(target)
                    target = root / "alias"
                with unit_file_custody(root), self.assertRaises((ConformanceError, OSError)):
                    linux.read_owned(str(target))

    def test_bpf_abi_x32_and_unknown_architecture_fail_closed(self):
        for machine, (arch, _, _) in linux.ARCHES.items():
            code = linux.seccomp_program(machine)
            self.assertEqual(interpret(code, arch ^ 1, 0), 0x80000000)
            self.assertEqual(interpret(code, arch, 0), 0x7FFF0000)
        self.assertEqual(interpret(linux.seccomp_program("x86_64"), 0xC000003E, 0x40000000), 0x80000000)
        with self.assertRaises(ConformanceError):
            linux.seccomp_program("emulated")

    def test_all_network_families_dns_and_metadata_have_no_direct_socket_grant(self):
        # Family vectors describe attempted transports, not observed networking.
        for machine, socket_nr, connect_nr, bind_nr, listen_nr in (
                ("x86_64", 41, 42, 49, 50), ("aarch64", 198, 203, 200, 201)):
            code = linux.seccomp_program(machine)
            arch = linux.ARCHES[machine][0]
            for label, family in (("ipv4", 2), ("ipv6", 10), ("dns-udp", 2),
                                  ("metadata-169.254.169.254", 2), ("unix-escape", 1), ("netlink", 16)):
                with self.subTest(machine=machine, target=label):
                    self.assertEqual(interpret(code, arch, socket_nr, family), 0x50000 | errno.EPERM)
            for number in (connect_nr, bind_nr, listen_nr):
                self.assertEqual(interpret(code, arch, number), 0x50000 | errno.EPERM)

    def test_namespace_clone_escape_and_clone3_are_denied_but_plain_fork_is_contained(self):
        for machine, (arch, clone, _) in linux.ARCHES.items():
            code = linux.seccomp_program(machine)
            self.assertEqual(interpret(code, arch, clone, 17), 0x7FFF0000)
            for bit in range(32):
                if linux.NAMESPACE_MASK & (1 << bit):
                    self.assertEqual(interpret(code, arch, clone, (1 << bit) | 17), 0x50000 | errno.EPERM)
            self.assertEqual(interpret(code, arch, 435), 0x50000 | errno.ENOSYS)

    def test_every_reviewed_unsafe_syscall_is_denied_on_both_abis(self):
        for machine, (arch, _, denied) in linux.ARCHES.items():
            for number in denied:
                with self.subTest(machine=machine, syscall=number):
                    result = interpret(linux.seccomp_program(machine), arch, number)
                    self.assertEqual(result, 0x50000 | (errno.ENOSYS if number == 435 else errno.EPERM))

    def test_fixed_native_struct_layouts_are_64_bit_without_syscall_execution(self):
        self.assertEqual(ctypes.sizeof(linux.SockFilter), 8)
        self.assertEqual(ctypes.sizeof(linux.CapHeader), 8)
        self.assertEqual(ctypes.sizeof(linux.CapData), 12)
        self.assertEqual(ctypes.sizeof(linux.MountAttr), 32)
        self.assertEqual(ctypes.sizeof(linux.StatFS), 120)
        self.assertEqual(linux.SockFprog.filter.offset, 8)

    def test_unit_boundary_all_steps_ordered_and_each_failure_stops(self):
        steps = ["parent_death", "cgroup_attach", "user_mount_pid_network_namespaces", "uid_gid_maps",
                 "readonly_root", "close_ambient_fds", "drop_capabilities", "no_new_privs", "seccomp", "peer_check"]
        observed = []
        result = linux.UnitBoundary(SimpleNamespace(step=observed.append)).establish()
        self.assertEqual(observed, steps)
        self.assertEqual(result, dict(evidenceClass="UNIT_VERIFICATION_ONLY", nativeAcceptance=False))
        for index in range(len(steps)):
            observed = []
            def step(name):
                observed.append(name)
                if name == steps[index]:
                    raise OSError("explicit unit primitive unavailable")
            with self.subTest(step=steps[index]), self.assertRaises(OSError):
                linux.UnitBoundary(SimpleNamespace(step=step)).establish()
            self.assertEqual(observed, steps[:index + 1])

    def test_kernel_peer_pid_reuse_and_every_scope_identity_change_refuse(self):
        peer = peer_fixture()
        parent = dict.fromkeys(peer["namespaces"], 1)
        linux.validate_peer(peer, deepcopy(peer), parent)
        for key, value in (("pid", 121), ("start", 346), ("parent", 99), ("uid", (0,) * 4),
                ("gid", (0,) * 4), ("capabilities", (1,) * 5), ("seccomp", 0), ("noNewPrivs", 0),
                ("cgroup", "0::/other\n"), ("namespaces", dict.fromkeys(parent, 1))):
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                linux.validate_peer({**peer, key: value}, peer, parent)

    def test_self_consistent_privileged_unisolated_peer_still_refuses(self):
        peer = peer_fixture()
        parent = dict.fromkeys(peer["namespaces"], 1)
        for changes in ({"uid": (0,) * 4}, {"gid": (0,) * 4}, {"capabilities": (0, 0, 0, 1, 0)},
                        {"seccomp": 0}, {"noNewPrivs": 0}, {"cgroup": "0::/\n"}, {"start": 0},
                        {"namespaces": {**peer["namespaces"], "net": 1}}):
            altered = {**peer, **changes}
            with self.subTest(changes=changes), self.assertRaises(ConformanceError):
                linux.validate_peer(altered, deepcopy(altered), parent)

    def test_only_one_exact_kernel_credential_message_is_accepted(self):
        credential = (socket.SOL_SOCKET, 2, struct.pack("3i", 123, 65532, 65532))
        self.assertEqual(linux.credentials([credential], 0), (123, 65532, 65532))
        for messages, flags in (([], 0), ([credential, credential], 0), ([credential], socket.MSG_TRUNC),
                ([credential], socket.MSG_CTRUNC), ([(socket.SOL_SOCKET, 2, b"short")], 0),
                ([(0, 2, credential[2])], 0), ([(socket.SOL_SOCKET, 99, b"flag")], 0)):
            with self.subTest(messages=messages, flags=flags), self.assertRaises(ConformanceError):
                linux.credentials(messages, flags)

    def test_all_received_descriptors_are_closed_even_after_malformed_ancillary(self):
        first, second = os.pipe()
        try:
            rights = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [first, second]).tobytes())
            with self.assertRaises(ConformanceError):
                linux.credentials([(0, 0, b"bad"), rights], socket.MSG_CTRUNC)
            for fd in (first, second):
                with self.assertRaises(OSError):
                    os.fstat(fd)
        finally:
            for fd in (first, second):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_native_constructor_refuses_workstation_and_injection_before_libc(self):
        with patch.object(linux.sys, "platform", "darwin"), patch.object(linux.ctypes, "CDLL") as library:
            with self.assertRaises(ConformanceError):
                linux.LinuxSyscalls()
            library.assert_not_called()
        with self.assertRaises(TypeError):
            linux.LinuxSyscalls(backend="unit")

    def test_root_and_ci_flags_cannot_replace_installed_module_custody(self):
        with patch.object(linux.sys, "platform", "linux"), patch.object(linux.os, "geteuid", return_value=0), patch.object(
                linux.os, "getegid", return_value=0), patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConformanceError) as caught:
                linux.installed_process()
            self.assertEqual(caught.exception.reason, "INSTALLED_CODE_CUSTODY_REQUIRED")
            with patch.dict(os.environ, {"CI": "true"}), self.assertRaises(ConformanceError) as caught:
                linux.installed_process()
            self.assertEqual(caught.exception.reason, "CI_EXECUTION_FORBIDDEN")

    def test_noncanonical_custody_paths_refuse_before_open(self):
        with patch.object(linux, "open_directory") as opened:
            for path in ("relative", "/a/../b", "/a//b", "/a/./b", "/a/b/", "/a\\b"):
                with self.subTest(path=path), self.assertRaises(ConformanceError):
                    linux.read_owned(path)
            opened.assert_not_called()

    def test_cgroup_attach_ambiguity_retains_cleanup_ownership(self):
        lease = object.__new__(linux.CgroupLease)
        lease.owned, lease.closed = False, False
        lease.write = Mock(side_effect=OSError("ambiguous cgroup write"))
        with self.assertRaises(OSError):
            lease.attach(123)
        self.assertTrue(lease.owned)
        lease.write.assert_called_once_with("cgroup.procs", b"123")

    def test_cgroup_kill_reaps_direct_and_adopted_double_fork_children(self):
        lease = object.__new__(linux.CgroupLease)
        lease.owned, lease.closed, lease.fd = True, False, 901
        lease.write = Mock()
        lease.read = Mock(return_value=b"populated 0\nfrozen 0\n")
        with patch.object(linux.os, "waitpid", side_effect=[(123, 9), (124, 9), (125, 9), ChildProcessError()]) as wait, patch.object(
                linux.os, "close") as close, patch.object(linux.time, "monotonic", return_value=1):
            lease.kill_and_reap(123, 2)
        lease.write.assert_called_once_with("cgroup.kill", b"1")
        self.assertEqual(wait.call_count, 4)
        self.assertTrue(all(call.args == (-1, os.WNOHANG) for call in wait.call_args_list))
        close.assert_called_once_with(901)
        self.assertTrue(lease.closed)

    def test_cgroup_nonempty_or_unreaped_tree_never_certifies_cleanup(self):
        for events, wait_result in ((b"populated 1\n", ChildProcessError()), (b"populated 0\n", (0, 0))):
            lease = object.__new__(linux.CgroupLease)
            lease.owned, lease.closed = True, False
            lease.write, lease.read = Mock(), Mock(return_value=events)
            with patch.object(linux.os, "waitpid", side_effect=wait_result if isinstance(wait_result, Exception) else None,
                    return_value=wait_result), patch.object(linux.time, "monotonic", side_effect=[1, 3]), patch.object(
                    linux.time, "sleep"), self.assertRaises(ConformanceError):
                lease.kill_and_reap(123, 2)
            self.assertFalse(lease.closed)

    def test_cgroup_kernel_files_require_root_nonwritable_custody(self):
        lease = object.__new__(linux.CgroupLease)
        lease.fd = 99
        good = dict(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0, st_dev=10)
        for changes in ({"st_uid": 501}, {"st_gid": 501}, {"st_dev": 11},
                        {"st_mode": stat.S_IFREG | 0o666}, {"st_mode": stat.S_IFLNK | 0o644}):
            with patch.object(linux.os, "fstat", side_effect=[SimpleNamespace(**{**good, **changes}),
                    SimpleNamespace(**good)]), self.assertRaises(ConformanceError):
                lease._field_custody(98)

    def test_cgroup_filesystem_magic_is_checked_by_fixed_native_abi(self):
        native = object.__new__(linux.LinuxSyscalls)
        def call(name, fd, pointer):
            self.assertEqual((name, fd), ("fstatfs", 9))
            pointer._obj.type = 0x63677270
        native.call = call
        native.require_cgroup2(9)
        native.call = lambda *args: None
        with self.assertRaises(ConformanceError):
            native.require_cgroup2(9)
