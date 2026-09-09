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


def _custody_packet_bytes():
    # Exact public successor packet bytes; inert fixture, never executed.
    return "id: \"CONF-LIVE-006\"\nrepository: \"mas-harness-conformance-labs\"\nbranch: \"codex/conf-live-006-campaign-integration\"\nobjective: \"Trusted campaign integration and manual qualification declaration under the approved trusted backend roadmap; source coding only.\"\npredecessors: [\"CONF-LIVE-005\"]\nallowedPaths: [\"src/harness_conformance/live_launcher.py\",\"src/harness_conformance/live_backend_campaign.py\",\"src/harness_conformance/live_backend_evidence.py\",\"tests/live_backend/test_campaign_integration.py\",\"tests/live_backend/test_cumulative_release.py\",\"docs/live-backend/qualification.md\"]\nwarmSourceAccess: \"PROHIBITED_DURING_IMPLEMENTATION\"\nsourceReuse: []\ncontracts: [\"Consumes docs/alpha-2/LIVE_BACKEND_READINESS.md and architecture/live-backend-roadmap.json from the exact merged MET-LIVE-001 authority, the existing trusted live-runner contract and unchanged CONF-LINUX-001/CON-007 wire contracts. Pin exact merged predecessor SHA and complete source inventory before edits.\",\"Source-only enablement before the native gate is limited to these six packets. No installation or live execution occurs in a coding run. Missing authority, supported OS backend or native capacity fails closed; offline fakes remain UNIT_VERIFICATION_ONLY with nativeAcceptance=false.\",\"Preserve all 120 original test identities across tests/meta, tests/parity, tests/alpha1, tests/fixes/runner_boundary and tests/platform/linux_baseline. Add flat tests/live_backend discovery, run all six roots on every packet and prove no module/test omission, skip, xfail, deselection or test-only runtime shortcut.\",\"Python 3.12.14 standard library and existing pinned conformance crypto/canonical helpers only; no new dependency, public API/signature schema/role, Makefile/dispatcher, PORTING ledger, warm-source, workflow or toolchain change. Kernel primitives and fixed operator prerequisites are preinstalled, never downloaded.\"]\ndeliverables: [\"Add the sole existing-file integration hook in live_launcher.py, after independent installed-manifest/signature/custody checks and before any checked-out code/credential access. Delegate to the fixed installed supervisor implementation, never import checkout-selected modules. Preserve the direct/unauthorized CLI refusal and pure linux_readiness.py UNIT_VERIFICATION_ONLY behavior.\",\"Implement the authenticated external campaign context path in live_backend_campaign.py. Reuse the existing pure validators and data-only request builder, but obtain all transport/session authority and signed receipts from the protected channel. The offline campaign API and its three predecessor campaign outputs remain byte-identical; environment flags and fixture evidence never enter the live path.\",\"Run all eight cumulative commands and inventory checks, rebuild the complete candidate via the new builder from tests, and prove every original test and all newly added packet tests are discovered. Bind all six source increments, final release inputs and current packet/command digests; never reuse a seven-command historical envelope.\",\"Declare the future manual post-merge linux-baseline run through only the external root-owned launcher with an independent installed candidate, dual-signed exact eight-command envelope, capacity authorization and existing native target. This declaration does not perform or authorize an installation, network call or live run in coding/CI. Missing prerequisites remain NOT_RUN_ENV_UNAVAILABLE.\",\"Publish per-architecture/per-case runtime evidence references separately from source/head/CI/merge/exact-main/package/preflight. Ten fresh mandatory AMD64 cases plus all original gate conditions are required before runtime product dispatch; ARM64 remains separate. No campaign signature becomes tenant acceptance.\",\"Implement the separate pure live_backend_evidence verifier using the new authority adapter and the existing Linux evidence shape/plan/request primitives. Bind authority.packetDigest to the exact CONF-LIVE-006 packet and eight commands, not the old hardcoded digest. Preserve all three independent evidence signatures, every release/plan/case/freshness check and UNIT_VERIFICATION_ONLY/nativeAcceptance=false for pure verification. Only the protected installed supervisor plus independently verified real receipts can support a separate native qualification decision; no substitution or monkeypatch of old constants.\"]\nexcluded: [\"No administrator installation, provisioning, kernel/cluster policy modification on this workstation, live network/probe argv, emulation-based native PASS, paid API or third-party key, mutable artifact, warm-source access, external telemetry or source-to-runtime evidence promotion.\",\"No edits to predecessor tests, crypto.py, canonical.py, models.py, schema.py, registry.py, campaign.py, live.py, cli.py, linux_readiness.py, existing schemas, ci/build_live_launcher.py, Makefile, dispatcher, toolchain, workflow or PORTING.yaml. New tests independently preserve old source guards; no relaxing immutable baseline hashes. The sole permitted existing-file exception is live_launcher.py as specified above.\"]\nprefetchCommands: []\nofflineAcceptanceCommands: [[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/meta\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/parity\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/alpha1\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/fixes/runner_boundary\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/platform/linux_baseline\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/live_backend\",\"-p\",\"test_*.py\"],[\"make\",\"campaign\",\"CAMPAIGN=linux-baseline\"],[\"make\",\"evidence-verify\",\"CAMPAIGN=linux-baseline\"]]\nofflineExecution: {\"wrapperArgv\":[\"./ci/verify-offline.sh\"],\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"prefetchOutsideSession\":false,\"offlineEnvironment\":{\"UV_OFFLINE\":\"1\",\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\"}}\nliveCampaignExecution: {\"launcherArgv\":[\"/opt/planeon/bin/harness-live-campaign-launch\"],\"commandTransport\":\"ARGV_ARRAY_V1\",\"executionPlacement\":\"PREINSTALLED_TARGET_LOCAL_EPHEMERAL_RUNNER\",\"executionEnvelopeEnvironment\":\"HARNESS_LIVE_EXECUTION_ENVELOPE\",\"executionEnvelopeMode\":\"DUAL_SIGNED_PACKET_COMMAND_CAMPAIGN_ENDPOINT_BINDING_V1\",\"releaseTrustStoreMount\":\"/etc/planeon/trust/release-trust-bundle.json\",\"tenantTrustStoreMount\":\"/etc/planeon/trust/tenant-trust-bundle.json\",\"trustStoreMode\":\"HASH_PINNED_LOCAL_PUBLIC_KEYS_VALIDITY_PURPOSE_AND_REVOCATION_V1\",\"revocationRequired\":true,\"networkIsolation\":\"OS_ENFORCED_DENY_ALL_EXCEPT_SIGNED_ENDPOINTS\",\"endpointAuthority\":\"TENANT_CONTROLLED_PREEXISTING_CAPACITY_ONLY\",\"dynamicEndpointTransport\":\"PREAUTHORIZED_API_OR_CAMPAIGN_PROXY_ONLY\",\"mutationAdmission\":\"SERVER_SIDE_SIGNED_ZERO_INCREMENTAL_COST_POLICY_AND_RBAC_REQUIRED\",\"capacityAuthorization\":\"INDEPENDENT_OPERATOR_SIGNED_FIXED_PREEXISTING_CAPACITY\",\"publicInternetDiscovery\":\"DENIED\",\"cloudManagementApis\":\"DENIED\",\"billingApis\":\"DENIED\",\"thirdPartyApiKeys\":\"DENIED\",\"credentialMode\":\"TENANT_LOCAL_SHORT_LIVED_FILE_REFERENCE\",\"unavailableResult\":\"NOT_RUN_ENV_UNAVAILABLE\",\"ciEvidenceUse\":\"FORBIDDEN\",\"allowedEvidenceAxes\":[\"DEPLOYMENT\",\"RUNTIME\",\"SECURITY\",\"ASSURANCE\"],\"commands\":[[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/meta\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/parity\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/alpha1\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/fixes/runner_boundary\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/platform/linux_baseline\",\"-p\",\"test_*.py\"],[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/live_backend\",\"-p\",\"test_*.py\"],[\"make\",\"campaign\",\"CAMPAIGN=linux-baseline\"],[\"make\",\"evidence-verify\",\"CAMPAIGN=linux-baseline\"]]}\nexpectedEvidence: [\"Direct inner-launcher invocation, forged context, unsigned/mismatched/expired/revoked/replayed envelopes, wrong command count, credential-open ordering, source/native conflation, regression output drift, integration bypass and incomplete final-package inventory.\",\"All eight offline commands run in one signed deny-all process tree; all original 120 test identities and every predecessor backend test remain discovered and passing. New tests never replace real native qualification.\",\"Source/CI/merge/exact-main and unsigned candidate/package evidence are separate from installed preflight, native artifacts, runtime, assurance and tenant acceptance. Missing independent backend/target/authority is NOT_RUN_ENV_UNAVAILABLE; no phase completion claim.\"]\nrollback: \"Revert unconsumed integration source only. Independently installed artifacts require operator-reviewed rollback retaining replay/trust history; no tenant data or capacity destruction. Preserve completed evidence and mark mismatched native qualification stale.\"\n".encode("utf-8")


class _CustodyOS:
    """In-memory OS observation fixture. No native files, sockets or policies."""
    def __init__(self):
        self.nodes, self.fds, self.offsets = {}, {}, {}
        self.opens, self.closes, self.reads = [], [], []
        self.next_fd, self.next_inode = 1000, 100
        self.fail_open = self.fail_read = self.fail_close = self.after_read = None
        self.max_open = 9000
        self.add("/", None, 0o555)

    def add(self, path, raw, mode=0o444):
        parent = path.rsplit("/", 1)[0] or "/"
        if path != "/" and parent not in self.nodes:
            self.add(parent, None, 0o555)
        self.next_inode += 1
        self.nodes[path] = SimpleNamespace(st_dev=1, st_ino=self.next_inode,
            st_uid=0, st_gid=0, st_mode=(stat.S_IFDIR if raw is None else stat.S_IFREG) | mode,
            st_nlink=2 if raw is None else 1, st_size=0 if raw is None else len(raw),
            st_mtime_ns=1, st_ctime_ns=1, raw=raw)
        return self.nodes[path]

    def path(self, name, dir_fd=None):
        return str(name) if dir_fd is None else self.fds[dir_fd][0].rstrip("/") + "/" + str(name)

    def open(self, name, flags, mode=0o777, *, dir_fd=None):
        path = self.path(name, dir_fd)
        if path == self.fail_open or len(self.fds) >= self.max_open:
            raise OSError(errno.EMFILE, "unit descriptor exhaustion")
        if path not in self.nodes:
            raise FileNotFoundError(path)
        node = self.nodes[path]
        if flags & os.O_NOFOLLOW and stat.S_ISLNK(node.st_mode):
            raise OSError(errno.ELOOP, "unit no-follow")
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(node.st_mode):
            raise NotADirectoryError(path)
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.fds[fd], self.offsets[fd] = (path, node), 0
        self.opens.append((path, fd, flags))
        return fd

    def fstat(self, fd):
        if fd <= 2:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        if fd not in self.fds:
            raise OSError(errno.EBADF, "unit closed descriptor")
        return deepcopy(self.fds[fd][1])

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        path = self.path(name, dir_fd)
        if path.startswith("/proc/self/ns/"):
            return SimpleNamespace(st_ino=900)
        return deepcopy(self.nodes[path])

    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("duplicate/recycled close")
        path = self.fds.pop(fd)[0]
        self.closes.append(fd)
        if self.fail_close == path:
            raise OSError(errno.EIO, "unit close reported failure")

    def read(self, fd, size):
        path, node = self.fds[fd]
        self.reads.append(path)
        if path == self.fail_read:
            raise OSError(errno.EIO, "unit read failed")
        start = self.offsets[fd]
        raw = node.raw[start:start + size]
        self.offsets[fd] += len(raw)
        if self.after_read is not None:
            self.after_read(path)
        return raw

    def listdir(self, path):
        if path == "/proc/self/task":
            return ["42"]
        if path == "/proc/self/fd":
            return ["0", "1", "2"] + [str(fd) for fd in self.fds]
        root = self.fds[path][0] if type(path) is int else path
        prefix = root.rstrip("/") + "/"
        return sorted(name[len(prefix):] for name in self.nodes
                      if name.startswith(prefix) and "/" not in name[len(prefix):])

    def kernel_fd(self, name):
        self.add(name, b"", 0o600)
        return self.open(name, os.O_RDONLY)

    def pipe2(self, flags):
        return self.kernel_fd("/unit-kernel/gate-r"), self.kernel_fd("/unit-kernel/gate-w")


class _CustodySocket:
    def __init__(self, fs, name, parent):
        self.fs, self.fd, self.parent = fs, fs.kernel_fd(name), parent
        fs.fds[self.fd][1].st_mode = stat.S_IFSOCK | 0o600
        self.receives = 0

    def fileno(self):
        return self.fd

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            self.fs.close(fd)

    def setsockopt(self, *args):
        pass

    def settimeout(self, value):
        if not 0 < value <= 1:
            raise AssertionError("unbounded receive")

    def send(self, raw):
        return len(raw)

    def recvmsg(self, *args):
        self.receives += 1
        raw, peer = ((b"MAP", (100, 0, 0)) if self.receives == 1 else
                     (b"READY", (120, 65532, 65532)) if self.receives == 2 else
                     (b"P", (120, 65532, 65532)))
        return raw, [(socket.SOL_SOCKET, 2, struct.pack("3i", *peer))], 0, None


class _CustodyRig:
    """Real factory, signatures, custody, lifecycle and channel; OS observations mocked."""
    def __init__(self):
        from _fixtures import ROOT, NOW, backend_fixture
        from harness_conformance import live_supervisor as module
        from harness_conformance.live_replay_store import UnitReplayStore
        from test_replay_store import MemoryJournal
        self.module, self.fixture, self.fs = module, backend_fixture(), _CustodyOS()
        self.wall, self.mono, self.owner = NOW, 1, None
        self.journal = MemoryJournal()
        self.store = UnitReplayStore(self.journal)
        self.store.close = Mock()  # Unit store has no OS descriptors to release.
        self.lease = Mock(owned=True, closed=False)
        self.syscalls = Mock()
        self.kernel_failure = None
        self.hook_calls = []
        seed = bytes([31]) * 32
        public = canonical_bytes(dict(algorithm="ED25519", publicKey=b64url_encode(public_key(seed))))
        launcher = b"UNIT_ONLY_NOT_REAL_launcher"
        manifest = dict(schemaVersion="harness.planeon.ai/live-runner-manifest/v1alpha1",
            launcher=dict(path=str(live.EXPECTED_LAUNCHER), version="0.1.0", sha256=byte_digest(launcher),
                ownerUid=0, ownerGid=0, mode="0555"),
            fixedTrustMounts=[str(live.FIXED_RELEASE_TRUST), str(live.FIXED_TENANT_TRUST)],
            isolation=dict(backend="PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1",
                networkPolicy="DENY_ALL_EXCEPT_DUAL_SIGNED_ENDPOINTS", credentialSocketsDenied=True, ciDenied=True),
            preflightEvidenceDigest="sha256:" + "a" * 64)
        raw = canonical_bytes(manifest)
        for path, data in ((live.FIXED_MANIFEST_PUBLIC, public), (live.FIXED_MANIFEST, raw),
                           (live.FIXED_MANIFEST_SIGNATURE, b64url_encode(sign(seed, raw)).encode()),
                           (live.EXPECTED_LAUNCHER, launcher)):
            self.fs.add(str(path), data, 0o555 if path == live.EXPECTED_LAUNCHER else 0o444)
        self.public_digest = byte_digest(public)
        kit = self.fixture.envelope["conformanceKitRoot"]
        self.kit = {"campaigns/platform/linux-baseline/inputs/amd64.json": canonical_bytes(self.fixture.plan),
                    "profiles/proxy.json": b'{"unit":"profile"}', "certificates/ca.pem": b"UNIT_CA_BYTES",
                    "observations/binding.json": b'{"unit":"observation-binding"}', "rootfs/README": b"UNIT_ROOTFS"}
        for path, raw in self.kit.items():
            self.fs.add(kit + "/" + path, raw)
        rows = [dict(path=path, mode="0444", size=len(raw), sha256=byte_digest(raw))
                for path, raw in sorted(self.kit.items())]
        self.fixture.release["tree"] = rows
        self.fixture.release["kitDigest"] = canonical_digest(rows, "planeon.harness-live-tree/v1alpha1")
        self.fixture.envelope["conformanceKitDigest"] = self.fixture.release["kitDigest"]
        self.fixture.envelope["campaignReleaseDigest"] = byte_digest(canonical_bytes(self.fixture.release))
        self.fixture.resign_authority()
        self.fs.add("/var/lib/planeon/live-backend", None, 0o700)
        self.fs.add("/var/lib/planeon/live-backend/session.lock", b"", 0o600)
        for name in ("setgroups", "uid_map", "gid_map"):
            self.fs.add("/proc/100/" + name, b"", 0o600)
        self.packet = _custody_packet_bytes()
        self.campaign = canonical_bytes(__import__("json").loads((ROOT / "campaigns/platform/linux-baseline/campaign.json").read_bytes()))
        self.refresh()

    def refresh(self):
        self.fixture.resign_authority()
        env = self.fixture.envelope
        for path, raw in ((str(live.FIXED_RELEASE_TRUST), canonical_bytes(self.fixture.release_trust)),
                (str(live.FIXED_TENANT_TRUST), canonical_bytes(self.fixture.tenant_trust)),
                (env["capacityAuthorizationFileReference"], canonical_bytes(self.fixture.capacity)),
                (env["campaignReleaseFileReference"], canonical_bytes(self.fixture.release)),
                (env["packetFileReference"], self.packet), (env["campaignDefinitionFileReference"], self.campaign),
                (env["bundleFileReference"], b"UNIT_ONLY_NOT_REAL_bundle")):
            self.fs.add(path, raw)

    def lease_factory(self):
        self.lease.fd = self.fs.kernel_fd("/unit-kernel/cgroup")
        self.lease.close.side_effect = lambda: self.fs.close(self.lease.fd)
        return self.lease

    def journal_factory(self):
        self.journal.fd = self.fs.kernel_fd("/unit-kernel/journal")
        self.journal.directory = self.fs.kernel_fd("/unit-kernel/journal-directory")
        return self.store

    def __enter__(self):
        import sys
        from contextlib import ExitStack
        self.stack = ExitStack()
        patchers = [
            patch.dict(os.environ, {}, clear=True), patch.object(linux.sys, "platform", "linux"),
            patch.object(linux.sys, "argv", [str(live.EXPECTED_LAUNCHER)]),
            patch.object(linux, "__loader__", SimpleNamespace(archive=str(live.EXPECTED_LAUNCHER))),
            patch.object(linux, "_VERIFIED_MANIFEST", None),
            patch.object(live, "PINNED_ROOT_PUBLIC_KEY_SHA256", self.public_digest),
            patch.object(os, "geteuid", return_value=0), patch.object(os, "getegid", return_value=0),
            patch.object(os, "getpid", return_value=42),
            patch.object(os, "uname", return_value=SimpleNamespace(machine="x86_64")),
            patch.object(os, "open", side_effect=self.fs.open), patch.object(os, "close", side_effect=self.fs.close),
            patch.object(os, "read", side_effect=self.fs.read), patch.object(os, "fstat", side_effect=self.fs.fstat),
            patch.object(os, "stat", side_effect=self.fs.stat), patch.object(os, "listdir", side_effect=self.fs.listdir),
            patch.object(os, "write", side_effect=lambda fd, raw: len(raw)),
            patch.object(os, "pipe2", side_effect=self.fs.pipe2, create=True),
            patch.object(os, "fork", return_value=100),
            patch.object(os, "pidfd_open", side_effect=lambda *args: self.fs.kernel_fd("/unit-kernel/pidfd"), create=True),
            patch.object(Path, "read_text", return_value=""),
            patch.object(self.module.signal, "getsignal", return_value=self.module.signal.SIG_DFL),
            patch.object(self.module.fcntl, "flock"),
            patch.object(self.module, "LinuxSyscalls", return_value=self.syscalls),
            patch.object(self.module, "CgroupLease", side_effect=self.lease_factory),
            patch.object(self.module, "ReplayStore", side_effect=self.journal_factory),
            patch.object(self.module, "utc_now", side_effect=lambda: self.wall),
            patch.object(self.module.time, "monotonic", side_effect=lambda: self.mono),
            patch.object(self.module.select, "select", return_value=([], [], [])),
            patch.object(self.module, "process_identity", side_effect=lambda pid: peer_fixture()),
            patch.object(socket, "socketpair", side_effect=lambda *args: (
                _CustodySocket(self.fs, "/unit-kernel/parent", True), _CustodySocket(self.fs, "/unit-kernel/child", False))),
            patch.dict(sys.modules, {"harness_conformance.live_proxy_client": SimpleNamespace(execute_protected=self.hook)}),
        ]
        try:
            for patcher in patchers:
                self.stack.enter_context(patcher)
            self.owner = self.module.NativeSupervisor()
            # Explicit unit clocks; neither creates custody nor skips any gate.
            self.owner._clock, self.owner._monotonic = lambda: self.wall, lambda: self.mono
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *args):
        try:
            if self.owner is not None:
                self.owner.close()
        finally:
            self.stack.close()

    def open(self):
        return self.owner.open_session(canonical_bytes(self.fixture.envelope))

    def hook(self, request, context, deadline):
        from _fixtures import receipt_from
        self.hook_calls.append((request, context, deadline))
        return canonical_bytes(receipt_from(self.fixture, request["operation"]))


class RetainedBoundaryTests(unittest.TestCase):
    def test_fixed_identity_read_once_and_cached_digest_cannot_replace_registry(self):
        with _CustodyRig() as rig:
            expected = {str(live.FIXED_MANIFEST_PUBLIC), str(live.FIXED_MANIFEST),
                        str(live.FIXED_MANIFEST_SIGNATURE), str(live.EXPECTED_LAUNCHER)}
            self.assertEqual(set(rig.owner._custody.files), expected)
            count = len(rig.fs.opens)
            self.assertEqual(linux._installed_manifest_digest(), rig.fixture.envelope["launcherDigest"])
            self.assertEqual(len(rig.fs.opens), count)
            self.assertTrue(expected <= {p for p, _, _ in rig.fs.opens})
            self.assertEqual(len(rig.owner._custody.checked_fds()), len(rig.owner._custody.handles))
        self.assertFalse(rig.fs.fds)

    def test_each_retained_file_and_ancestor_substitution_is_detected(self):
        with _CustodyRig() as rig:
            custody = rig.owner._custody
            for path in tuple(custody.handles):
                with self.subTest(path=path):
                    old = rig.fs.nodes[path]
                    rig.fs.nodes[path] = deepcopy(old)
                    rig.fs.nodes[path].st_ino += 10000
                    with self.assertRaises(ConformanceError):
                        custody.check()
                    rig.fs.nodes[path] = old
            custody.check()

    def test_every_custody_metadata_field_is_rechecked(self):
        with _CustodyRig() as rig:
            custody = rig.owner._custody
            for path in ("/", str(live.FIXED_MANIFEST)):
                node = rig.fs.nodes[path]
                for field in ("st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "st_dev", "st_ino"):
                    original = getattr(node, field)
                    with self.subTest(path=path, field=field):
                        setattr(node, field, original + 1)
                        with self.assertRaises(ConformanceError):
                            custody.check()
                        setattr(node, field, original)

    def test_ambient_unknown_descriptor_and_forked_registry_never_authorize(self):
        with _CustodyRig() as rig:
            # Session lock is independently owned but NOT an authority FD.
            # An arbitrary extra descriptor never enters the custody allowlist.
            with self.assertRaises(ConformanceError):
                linux.ambient_custody()
            with patch.object(os, "getpid", return_value=43), self.assertRaises(ConformanceError):
                linux._capture()
            with self.assertRaises(TypeError):
                __import__("pickle").dumps(rig.owner._custody)
            with self.assertRaises(ConformanceError):
                linux._owned_custody(object.__new__(rig.module.NativeSupervisor))

    def test_native_constructor_exhaustion_or_bad_installed_read_closes_every_handle(self):
        for mode in ("limit", "open", "read", "short", "substitution"):
            rig = _CustodyRig()
            path = str(live.FIXED_MANIFEST)
            if mode == "limit":
                rig.fs.max_open = 3
            elif mode == "open":
                rig.fs.fail_open = path
            elif mode == "read":
                rig.fs.fail_read = path
            elif mode == "short":
                rig.fs.nodes[path].st_size += 1
            else:
                rig.fs.after_read = lambda observed: setattr(rig.fs.nodes[path], "st_ctime_ns", 2) if observed == path else None
            with self.subTest(mode=mode), self.assertRaises((OSError, ConformanceError)):
                with rig:
                    self.fail("partial custody accepted")
            self.assertFalse(rig.fs.fds)
            self.assertEqual(len(rig.fs.closes), len(set(rig.fs.closes)))
            self.assertIsNone(linux._capture())

    def test_close_error_attempts_all_handles_once_and_invalidates_first(self):
        with _CustodyRig() as rig:
            custody = rig.owner._custody
            owned = custody.checked_fds()
            rig.fs.fail_close = str(live.FIXED_MANIFEST)
            with self.assertRaises(OSError):
                custody.close()
            self.assertTrue(custody.closed)
            self.assertIsNone(linux._capture())
            self.assertTrue(owned <= set(rig.fs.closes))
            count = len(rig.fs.closes)
            custody.close()
            self.assertEqual(len(rig.fs.closes), count)

    def test_closed_recycled_descriptor_is_never_closed_as_new_authority(self):
        with _CustodyRig() as rig:
            custody = rig.owner._custody
            fd = custody.handles[str(live.FIXED_MANIFEST)]["fd"]
            other = rig.fs.add("/unit-other", b"not-authority")
            rig.fs.fds[fd] = ("/unit-other", other)
            with self.assertRaises(ConformanceError):
                custody.close()
            self.assertNotIn(fd, rig.fs.closes)
            self.assertIn(fd, rig.fs.fds)
            rig.fs.close(fd)

    def test_kit_rootfs_is_borrowed_once_and_signed_bytes_are_immutable(self):
        with _CustodyRig() as rig:
            handle = rig.open()
            context = rig.owner._context
            self.assertEqual(dict(context._kit), rig.kit)
            root = rig.fixture.envelope["conformanceKitRoot"] + "/rootfs"
            self.assertEqual(context._root_fd, rig.owner._custody.handles[root]["fd"])
            self.assertEqual(sum(path == root for path, _, _ in rig.fs.opens), 1)
            with self.assertRaises(TypeError):
                context._kit["certificates/ca.pem"] = b"replacement"
            with self.assertRaises(TypeError):
                context._bytes[str(live.FIXED_MANIFEST)] = b"replacement"
            before = len(rig.fs.opens)
            rig.owner.execute_fixed(handle, rig.module.CASES[0], "amd64")
            self.assertEqual(len(rig.fs.opens), before)
            self.assertEqual(len(rig.hook_calls), 1)


def _credential_rig():
    """OS-mocked custody exercise; the proxy/policy adapter is NOT live proof."""
    import sys
    import json
    from contextlib import contextmanager, ExitStack
    from types import ModuleType
    from _fixtures import NOW, receipt_from
    rig = _CustodyRig()
    fixture = rig.fixture
    expiry = "2026-09-07T01:10:00Z"
    identity = dict(endpointId="unit-proxy", purpose="CAMPAIGN_PROXY_CLIENT_MTLS",
                    subject=fixture.plan["serviceAccountSubject"], expiresAt=expiry,
                    certificateDigest="sha256:" + "1" * 64, clientSpkiDigest="sha256:" + "2" * 64)
    fixture.capacity["credentialIdentities"] = [identity]
    fields = ("kubernetesApiRules", "campaignProxyRules", "permittedGvksAndVerbs", "preexistingResourceRefs",
              "preallocatedStorageRefs", "preallocatedAcceleratorRefs", "credentialIdentities")
    profile = dict(profileId="CAMPAIGN_PROXY_MTLS_ZERO_COST_V1", binding=dict(
        tenantId=fixture.envelope["tenantId"], environmentId=fixture.envelope["environmentId"],
        runNonce=fixture.envelope["nonce"], capacityNonce=fixture.capacity["nonce"],
        namespace=fixture.plan["namespace"], endpointId="unit-proxy", apiEndpointId=None,
        serviceAccountSubject=fixture.plan["serviceAccountSubject"], validFrom=NOW, expiresAt=expiry),
        capacityEntries={key: deepcopy(fixture.capacity[key]) for key in fields})
    # Only origin/binding data for the ownership unit tests. This deliberately
    # is not a complete strict proxy profile or a policy-observation producer.
    rig.kit["campaigns/platform/linux-baseline/proxy-profile.json"] = canonical_bytes(profile)
    kit_root = fixture.envelope["conformanceKitRoot"]
    for path, raw in rig.kit.items():
        rig.fs.add(kit_root + "/" + path, raw)
    rows = [dict(path=p, mode="0444", size=len(raw), sha256=byte_digest(raw)) for p, raw in sorted(rig.kit.items())]
    fixture.release["tree"] = rows
    fixture.release["kitDigest"] = canonical_digest(rows, "planeon.harness-live-tree/v1alpha1")
    fixture.envelope["conformanceKitDigest"] = fixture.release["kitDigest"]
    fixture.envelope["campaignReleaseDigest"] = byte_digest(canonical_bytes(fixture.release))
    rig.refresh()
    rig.credential_path = fixture.endpoint["credentialFileReference"]
    rig.credential_raw = b"UNIT_ONLY_NO_PRIVATE_KEY_OR_CERTIFICATE"
    rig.fs.add(rig.credential_path, rig.credential_raw, 0o400)
    rig.events, rig.seals, rig.transports = [], {}, []
    rig.policy_available, rig.io_enabled, rig.before_io, rig.after_io = True, False, None, None
    rig.fail_write = False

    def policy(context, deadline):
        # Explicit non-authorizing unit adapter at the missing successor seam;
        # never installed, never selected by an environment flag in product.
        if (not rig.policy_available or context is not rig.owner._context
                or not rig.owner._active["reserved"] or rig.owner._active["session"]["state"] != "RUNNING"
                or rig.owner._boundary.peer is None or deadline != context._deadline):
            raise ConformanceError("CREDENTIAL_POLICY_UNAVAILABLE", "unit unavailable observation")
        rig.events.append("unit-policy-check")

    def execute_protected(request, context, deadline):
        rig.events.append("unit-hook")
        if rig.before_io is not None:
            rig.before_io()
        resources = context._late_resources
        data = resources.credential_bytes()
        if data != rig.credential_raw:
            raise AssertionError("unit custody bytes differ")
        if rig.io_enabled:
            resources.transport()
            memfd = resources.tls_memfd()
            if rig.fs.fstat(memfd).st_size != len(data):
                raise AssertionError("unit secret transport size differs")
            resources.close_memfd()
        if rig.after_io is not None:
            rig.after_io()
        rig.hook_calls.append((request, context, deadline))
        return canonical_bytes(receipt_from(fixture, request["operation"]))

    proxy = ModuleType("harness_conformance.live_proxy_client")
    proxy.__loader__ = SimpleNamespace(archive=str(live.EXPECTED_LAUNCHER))
    proxy.execute_protected = execute_protected
    proxy._require_current_credential_policy = policy
    rig.proxy = proxy

    def transport(family, kind, protocol):
        rig.transports.append((family, kind, protocol))
        sock = _CustodySocket(rig.fs, "/unit-transport-" + str(len(rig.transports)), False)
        sock.set_inheritable = lambda value: None if value is False else (_ for _ in ()).throw(AssertionError("inherited"))
        return sock

    def memfd(name, flags):
        if name != "planeon-client-credential" or flags != 3:
            raise AssertionError("unbounded memfd selection")
        fd = rig.fs.kernel_fd("/unit-memfd-" + str(len(rig.seals)))
        rig.seals[fd] = 0
        return fd

    def write(fd, raw):
        if fd not in rig.seals:
            return len(raw)
        if rig.fail_write:
            return 0
        node = rig.fs.fds[fd][1]
        node.raw += raw
        node.st_size = len(node.raw)
        return len(raw)

    def seal(fd, operation, argument=0):
        if operation == 1033:
            rig.seals[fd] |= argument
            return 0
        if operation == 1034:
            return rig.seals[fd]
        raise AssertionError("unreviewed memfd operation")

    @contextmanager
    def managed():
        with rig:
            with ExitStack() as stack:
                for patcher in (patch.dict(sys.modules, {proxy.__name__: proxy}),
                        patch.object(os, "get_inheritable", return_value=False),
                        patch.object(socket, "socket", side_effect=transport),
                        patch.object(os, "memfd_create", side_effect=memfd, create=True),
                        patch.object(os, "MFD_CLOEXEC", 1, create=True),
                        patch.object(os, "MFD_ALLOW_SEALING", 2, create=True),
                        patch.object(os, "write", side_effect=write),
                        patch.object(rig.module.fcntl, "fcntl", side_effect=seal)):
                    stack.enter_context(patcher)
                for name, value in dict(F_ADD_SEALS=1033, F_GET_SEALS=1034, F_SEAL_SEAL=1,
                                        F_SEAL_SHRINK=2, F_SEAL_GROW=4, F_SEAL_WRITE=8).items():
                    stack.enter_context(patch.object(rig.module.fcntl, name, value, create=True))
                try:
                    yield rig
                finally:
                    rig.owner.close()
    return managed()


class CredentialBoundaryTests(unittest.TestCase):
    def test_two_operations_retain_one_credential_without_unsealing_authority(self):
        with _credential_rig() as rig:
            handle = rig.open()
            context = rig.owner._context
            initial = dict(context._custody.handles)
            self.assertNotIn(rig.credential_path, context._custody.files)
            for case in rig.module.CASES[:2]:
                self.assertFalse(rig.owner.execute_fixed(handle, case, "amd64")["nativeAcceptance"])
                self.assertEqual(context._late_resources.state, "RETAINED")
                self.assertEqual(context._late_resources.io, {})
            self.assertEqual(sum(p == rig.credential_path for p, _, _ in rig.fs.opens), 1)
            self.assertEqual(context._custody.handles, initial)
            self.assertTrue(context._custody.sealed)
            self.assertNotIn(rig.credential_path, context._bytes)
            self.assertEqual(len(rig.hook_calls), 2)
        self.assertFalse(rig.fs.fds)
        self.assertEqual(len(rig.fs.closes), len(set(rig.fs.closes)))

    def test_temporary_socket_and_sealed_memfd_close_before_receipt(self):
        with _credential_rig() as rig:
            rig.io_enabled = True
            handle = rig.open()
            for case in rig.module.CASES[:2]:
                rig.owner.execute_fixed(handle, case, "amd64")
                self.assertFalse(rig.owner._context._late_resources.io)
                self.assertFalse(any(p.startswith(("/unit-transport-", "/unit-memfd-")) for p, n in rig.fs.fds.values()))
            self.assertEqual(rig.transports, [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)] * 2)
            self.assertTrue(all(value == 15 for value in rig.seals.values()))

    def test_missing_policy_or_fixed_module_identity_opens_no_credential(self):
        for fault in ("policy", "missing-guard", "boolean", "loader"):
            with self.subTest(fault=fault), _credential_rig() as rig:
                handle = rig.open()
                if fault == "policy":
                    rig.policy_available = False
                elif fault == "missing-guard":
                    del rig.proxy._require_current_credential_policy
                elif fault == "boolean":
                    rig.proxy._require_current_credential_policy = True
                else:
                    rig.proxy.__loader__.archive = "/unit-foreign"
                with self.assertRaises(ConformanceError):
                    rig.owner.execute_fixed(handle, rig.module.CASES[0], "amd64")
                self.assertNotIn(rig.credential_path, [p for p, _, _ in rig.fs.opens])
                self.assertIsNone(rig.owner._active)

    def test_credential_wrong_mode_symlink_hardlink_size_and_metadata_refuse(self):
        for fault in ("mode", "symlink", "hardlink", "oversize", "short", "substitution"):
            with self.subTest(fault=fault), _credential_rig() as rig:
                handle = rig.open()
                node = rig.fs.nodes[rig.credential_path]
                if fault == "mode":
                    node.st_mode = stat.S_IFREG | 0o600
                elif fault == "symlink":
                    node.st_mode = stat.S_IFLNK | 0o400
                elif fault == "hardlink":
                    node.st_nlink = 2
                elif fault == "oversize":
                    node.st_size = 262145
                elif fault == "short":
                    node.st_size += 1
                else:
                    rig.fs.after_read = lambda path: setattr(node, "st_ctime_ns", 2) if path == rig.credential_path else None
                with self.assertRaises((OSError, ConformanceError)):
                    rig.owner.execute_fixed(handle, rig.module.CASES[0], "amd64")
                self.assertFalse(rig.hook_calls)
            self.assertFalse(rig.fs.fds)

    def test_partial_acquisition_exhaustion_and_write_failure_release_all(self):
        for fault in ("open", "limit", "read", "memfd-write"):
            with self.subTest(fault=fault), _credential_rig() as rig:
                handle = rig.open()
                if fault == "open":
                    rig.fs.fail_open = rig.credential_path
                elif fault == "limit":
                    rig.fs.max_open = len(rig.fs.fds) + 2
                elif fault == "read":
                    rig.fs.fail_read = rig.credential_path
                else:
                    rig.io_enabled = rig.fail_write = True
                with self.assertRaises((OSError, ConformanceError)):
                    rig.owner.execute_fixed(handle, rig.module.CASES[0], "amd64")
                self.assertIsNone(rig.owner._active)
            self.assertFalse(rig.fs.fds)

    def test_retained_credential_and_ancestry_mutation_refuse_without_reopening(self):
        with _credential_rig() as rig:
            handle = rig.open()
            rig.owner.execute_fixed(handle, rig.module.CASES[0], "amd64")
            resource = rig.owner._context._late_resources
            before = list(rig.fs.opens)
            for row in resource.handles:
                node = rig.fs.fds[row["fd"]][1]
                old = node.st_ctime_ns
                node.st_ctime_ns += 1
                with self.assertRaises(ConformanceError):
                    rig.owner._boundary.check_peer()
                node.st_ctime_ns = old
            rig.fs.nodes[rig.credential_path].st_ctime_ns += 1
            with self.assertRaises(ConformanceError):
                rig.owner.execute_fixed(handle, rig.module.CASES[1], "amd64")
            self.assertEqual(rig.fs.opens, before)
            self.assertEqual(len(rig.hook_calls), 1)

    def test_direct_constructor_caller_path_and_foreign_hook_are_not_authority(self):
        with self.assertRaises(TypeError):
            linux._LateResources()
        with _credential_rig() as rig:
            rig.open()
            resources = rig.owner._context._late_resources
            with self.assertRaises(TypeError):
                resources.credential_bytes("/unit-caller-path")
            with self.assertRaises(ConformanceError):
                resources.credential_bytes()
            self.assertNotIn(rig.credential_path, [p for p, _, _ in rig.fs.opens])
            with self.assertRaises(TypeError):
                __import__("pickle").dumps(resources)
