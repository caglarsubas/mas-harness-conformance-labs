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


class _QualificationBindingFixture:
    """Unit-only signed release plus virtual OS files, never installed artifacts.

    The parent server context is assembled, not a native startup success. All
    binding, canonical, crypto, manifest and retained-file code stays real.
    """
    def __init__(self, architecture="amd64", ipv6=False):
        from _fixtures import backend_fixture
        from harness_conformance.crypto import b64url_encode, public_key
        from harness_conformance.canonical import canonical_digest
        self.fixture = backend_fixture(architecture)
        self.profile, self.record = sample()["profile"], sample()["record"]
        self.observation = deepcopy(VECTORS["observation"]["positive"]["binding"])
        self.broker = deepcopy(VECTORS["broker"]["positive"][0]["binding"])
        self.machine = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
        self.now, self.mono = "2026-09-07T01:00:00Z", 100.0
        self.raw, self.modes, self.fds, self.positions, self.read_paths = {}, {}, {}, {}, []
        self.next_fd, self.closed_fds = 700000, []
        self.seed = bytes([17]) * 32  # deterministic UNIT key, no operator key
        self.raw[server.PUBLIC_KEY] = canonical_bytes({"algorithm": "ED25519", "publicKey": b64url_encode(public_key(self.seed))})
        self.key_digest = byte_digest(self.raw[server.PUBLIC_KEY])
        scope = self.profile["binding"]
        scope.update(runNonce=self.fixture.envelope["nonce"], validFrom=self.now, expiresAt="2026-09-07T01:10:00Z")
        self.profile["capacityEntries"]["credentialIdentities"][0]["expiresAt"] = scope["expiresAt"]
        for key, projection in self.observation["projections"].items():
            value = {"apiVersion": projection["apiVersion"], "kind": projection["kind"],
                "metadata": {k: projection[k] for k in ("name", "namespace", "uid")}, "spec": {}}
            raw = canonical_bytes(value)
            projection["projectionDigest"] = self.profile["policy"][key + "Digest"] = byte_digest(raw)
            for ref in self.profile["capacityEntries"]["preexistingResourceRefs"]:
                if ref["uid"] == projection["uid"]:
                    ref["observedDigest"] = byte_digest(raw)
            self.raw["/unit-only/kit/campaigns/platform/linux-baseline/proxy-policy/" + key + ".json"] = raw
        self.fixture.capacity.update(deepcopy(self.profile["capacityEntries"]))
        for field in ("admissionPolicyDigest", "resourceQuotaDigest", "limitRangeDigest"):
            self.fixture.capacity[field] = self.profile["policy"][field]
            if field != "limitRangeDigest":
                self.fixture.envelope[field] = self.profile["policy"][field]
        endpoint = self.fixture.envelope["endpoints"][0]
        endpoint["tls"]["caCertificateFileReference"] = "/unit-only/kit/ca.pem"
        if ipv6:
            endpoint["ipAddress"] = "fd00::1"
        self.raw["/unit-only/kit/ca.pem"] = b"-----BEGIN CERTIFICATE-----\nUNIT_DATA_NOT_TLS\n"
        self.raw["/unit-only/kit/campaigns/platform/linux-baseline/inputs/" + architecture + ".json"] = canonical_bytes(self.fixture.plan)
        self.record.update(profileDigest=canonical_digest(self.profile),
            scope={k: scope[k] for k in self.record["scope"]})
        self.record["host"]["machine"] = self.machine
        self.record["endpointTuples"] = [{"endpointId": endpoint["endpointId"], "kind": endpoint["kind"],
            "addressFamily": "IPV6" if ipv6 else "IPV4", "ipAddress": endpoint["ipAddress"], "port": endpoint["port"]}]
        for row in self.record["files"]:
            raw = ("UNIT_INERT_" + row["path"]).encode().ljust(row["size"], b"_")
            self.raw[row["path"]], self.modes[row["path"]] = raw, 0o555
            row["sha256"] = byte_digest(raw)
        for role in self.record["roles"].values():
            role["artifactDigest"] = byte_digest(self.raw[role["executable"]])
        self.raw["/unit-only/kit/" + admission.QUALIFICATION_PATH] = canonical_bytes(self.record)
        preflight = byte_digest(canonical_bytes(self.record))
        self.paths = (("SERVER", server.MANIFEST, server.EXECUTABLE),
            ("OBSERVER", server.OBSERVER_MANIFEST, server.OBSERVER),
            ("BROKER", server.BROKER_MANIFEST, server.BROKER),
            ("WORKER", server.WORKER_MANIFEST, server.WORKER))
        for _, path, executable in self.paths:
            value = {"schemaVersion": "harness.planeon.ai/live-runner-manifest/v1alpha1",
                "launcher": {"path": executable, "version": "0.1.0", "sha256": byte_digest(self.raw[executable]),
                    "ownerUid": 0, "ownerGid": 0, "mode": "0555"},
                "fixedTrustMounts": [str(server.FIXED_RELEASE_TRUST), str(server.FIXED_TENANT_TRUST)],
                "isolation": {"backend": "PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1",
                    "networkPolicy": "DENY_ALL_EXCEPT_DUAL_SIGNED_ENDPOINTS", "credentialSocketsDenied": True, "ciDenied": True},
                "preflightEvidenceDigest": preflight}
            self.manifest(path, value)
        self.observation.update(profileDigest=canonical_digest(self.profile),
            scope={k: v for k, v in scope.items() if k != "apiEndpointId"},
            observer={"manifestDigest": byte_digest(self.raw[server.OBSERVER_MANIFEST]),
                      "executableDigest": byte_digest(self.raw[server.OBSERVER])})
        self.observation["enforcementPins"]["hostPreflightDigest"] = preflight
        self.broker.update(profileDigest=canonical_digest(self.profile), observationBindingDigest=canonical_digest(self.observation),
            brokerManifestDigest=byte_digest(self.raw[server.BROKER_MANIFEST]), brokerExecutableDigest=byte_digest(self.raw[server.BROKER]),
            workerManifestDigest=byte_digest(self.raw[server.WORKER_MANIFEST]), workerArtifactDigest=byte_digest(self.raw[server.WORKER]))
        for path, value in ((admission.PROFILE_PATH, self.profile), (admission.OBSERVATION_PATH, self.observation),
                            (admission.BROKER_BINDING_PATH, self.broker)):
            self.raw["/unit-only/kit/" + path] = canonical_bytes(value)
        self.release()

    def manifest(self, path, value):
        from harness_conformance.crypto import b64url_encode, sign
        raw = canonical_bytes(value)
        self.raw[path], self.raw[path + ".sig"] = raw, b64url_encode(sign(self.seed, raw)).encode()

    def release(self):
        from harness_conformance.canonical import canonical_digest
        fixture = self.fixture
        tree = [{"path": path.removeprefix("/unit-only/kit/"), "mode": "0444", "size": len(raw), "sha256": byte_digest(raw)}
                for path, raw in sorted(self.raw.items()) if path.startswith("/unit-only/kit/")]
        fixture.release.update(tree=tree, kitDigest=canonical_digest(tree, "planeon.harness-live-tree/v1alpha1"))
        fixture.envelope.update(conformanceKitDigest=fixture.release["kitDigest"], campaignReleaseDigest=byte_digest(canonical_bytes(fixture.release)))
        fixture.resign_authority()
        for path, value in (("/unit-only/envelope.json", fixture.envelope), ("/unit-only/capacity.json", fixture.capacity),
                ("/unit-only/release.json", fixture.release), (str(server.FIXED_RELEASE_TRUST), fixture.release_trust),
                (str(server.FIXED_TENANT_TRUST), fixture.tenant_trust)):
            self.raw[path] = canonical_bytes(value)

    def context(self, stack):
        from _fixtures import authority_args, binding_args
        owner = object.__new__(server.NativeProxyServer)
        owner.pid, owner.thread, owner.closed = server.os.getpid(), server.threading.get_ident(), False
        owner.files, owner.deadline, owner.envelope_path = server._Files(owner), self.mono + 600, "/unit-only/envelope.json"
        owner.authority = authority_args(self.fixture)
        owner.envelope, owner.capacity = deepcopy(self.fixture.envelope), deepcopy(self.fixture.capacity)
        owner.plan = deepcopy(self.fixture.plan)
        owner.binding = server.binding_from_authority(*owner.authority, **binding_args(self.fixture))
        owner.kit = {p.removeprefix("/unit-only/kit/"): raw for p, raw in self.raw.items() if p.startswith("/unit-only/kit/")}
        owner.profile, owner.observation_binding = deepcopy(self.profile), deepcopy(self.observation)
        owner.endpoint = deepcopy(self.fixture.envelope["endpoints"][0])
        owner.ca, owner.manifest = self.raw["/unit-only/kit/ca.pem"], json.loads(self.raw[server.MANIFEST])
        owner.artifact_digest = byte_digest(self.raw[server.EXECUTABLE])
        owner.snapshot = canonical_bytes([owner.envelope, owner.capacity, owner.plan, owner.binding,
                                          owner.profile, owner.observation_binding, owner.endpoint])
        owner.qualification_binding = object.__new__(server._ServerQualificationBinding)
        self.owner = owner
        self.filesystem_context(stack)
        stack.enter_context(patch.object(server, "_ACTIVE", owner))
        stack.callback(owner.files.close)
        return owner

    def filesystem_context(self, stack):
        # Shared OS data only. The full-constructor fixture calls this without
        # constructing, registering or pre-populating a NativeProxyServer.
        self.nodes = {path: SimpleNamespace(st_dev=91, st_ino=100 + i, st_nlink=1,
            st_mode=stat.S_IFREG | self.modes.get(path, 0o444), st_uid=0, st_gid=0, st_size=len(raw),
            st_mtime_ns=1, st_ctime_ns=1) for i, (path, raw) in enumerate(self.raw.items())}
        for path in tuple(self.nodes):
            parent = path.rsplit("/", 1)[0] or "/"
            while parent not in self.nodes:
                self.nodes[parent] = SimpleNamespace(st_dev=91, st_ino=100 + len(self.nodes), st_nlink=1,
                    st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
                if parent == "/":
                    break
                parent = parent.rsplit("/", 1)[0] or "/"
        original_stat = server.os.stat
        def path_stat(path, *, dir_fd=None, follow_symlinks=True):
            absolute = self.resolve(path, dir_fd)
            return self.nodes[absolute] if absolute in self.nodes else original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        stack.enter_context(patch.object(server, "PINNED_ROOT_PUBLIC_KEY_SHA256", self.key_digest))
        stack.enter_context(patch.object(server, "utc_now", side_effect=lambda: self.now))
        stack.enter_context(patch.object(server.time, "monotonic", side_effect=lambda: self.mono))
        stack.enter_context(patch.object(server.os, "uname", return_value=SimpleNamespace(machine=self.machine)))
        for name, fn in (("open", self.open), ("stat", path_stat), ("fstat", lambda fd: self.nodes[self.fds[fd]]),
                ("read", self.read), ("close", self.close), ("get_inheritable", lambda fd: False),
                ("listdir", lambda fd: sorted(p[len(self.fds[fd].rstrip("/")) + 1:] for p in self.nodes
                    if p != "/" and p.rsplit("/", 1)[0] == self.fds[fd]))):
            stack.enter_context(patch.object(server.os, name, side_effect=fn))
        self.socket = stack.enter_context(patch.object(server.socket, "socket", side_effect=AssertionError("no socket in binding")))

    def resolve(self, path, parent):
        path = str(path)
        return path if path.startswith("/") else self.fds[parent].rstrip("/") + "/" + path

    def open(self, path, flags, *, dir_fd=None):
        absolute = self.resolve(path, dir_fd)
        if absolute not in self.nodes:
            raise FileNotFoundError(absolute)
        self.next_fd += 1
        self.fds[self.next_fd], self.positions[self.next_fd] = absolute, 0
        return self.next_fd

    def read(self, fd, count):
        path, offset = self.fds[fd], self.positions[fd]
        self.read_paths.append(path)
        raw = self.raw[path][offset:offset + count]
        self.positions[fd] += len(raw)
        return raw

    def close(self, fd):
        self.closed_fds.append(fd)
        del self.fds[fd]


class QualificationBindingTests(unittest.TestCase):
    def exercise(self, fixture=None, action=None):
        fixture = fixture or _QualificationBindingFixture()
        with ExitStack() as stack:
            owner = fixture.context(stack)
            owner.qualification_binding.__init__(owner)
            if action:
                action(owner, fixture)
            self.assertFalse(fixture.socket.called)
            self.assertNotIn(server.IDENTITY, fixture.read_paths)
            return owner.qualification_binding

    def test_signed_record_and_all_four_manifests_bind_without_native_authority(self):
        def action(owner, fixture):
            binding = owner.qualification_binding
            self.assertEqual(binding.record, fixture.record)
            self.assertEqual(binding.broker_binding, fixture.broker)
            self.assertFalse(hasattr(binding, "check_self"))
            self.assertFalse(hasattr(binding, "check_peer"))
            for _, path, executable in fixture.paths:
                self.assertIn(path + ".sig", fixture.read_paths)
                self.assertIn(executable, fixture.read_paths)
        self.exercise(action=action)

    def test_arm64_ipv6_uses_only_the_signed_numeric_endpoint(self):
        self.exercise(_QualificationBindingFixture("arm64", ipv6=True),
            lambda owner, _: self.assertEqual(owner.qualification_binding.record["endpointTuples"][0]["ipAddress"], "fd00::1"))

    def test_returned_record_and_broker_are_detached(self):
        def action(owner, fixture):
            owner.qualification_binding.record["roles"]["SERVER"]["artifactDigest"] = admission.ZERO
            owner.qualification_binding.broker_binding["workerArtifactDigest"] = admission.ZERO
            self.assertEqual(owner.qualification_binding.record, fixture.record)
            self.assertEqual(owner.qualification_binding.broker_binding, fixture.broker)
        self.exercise(action=action)

    def test_all_role_signature_forgeries_refuse(self):
        for _, path, _ in _QualificationBindingFixture().paths:
            fixture = _QualificationBindingFixture()
            fixture.raw[path + ".sig"] = b"A" * 86
            with self.subTest(path=path), self.assertRaisesRegex(ConformanceError, "PROXY_MANIFEST_SIGNATURE"):
                self.exercise(fixture)

    def test_all_role_preflight_substitutions_refuse_even_when_root_signed(self):
        for _, path, _ in _QualificationBindingFixture().paths:
            fixture = _QualificationBindingFixture()
            value = json.loads(fixture.raw[path])
            value["preflightEvidenceDigest"] = admission.ZERO
            fixture.manifest(path, value)
            with self.subTest(path=path), self.assertRaisesRegex(ConformanceError, "QUALIFICATION_INSTALLED_ROLE_MISMATCH"):
                self.exercise(fixture)

    def test_artifact_substitution_refuses_for_each_role(self):
        for _, _, executable in _QualificationBindingFixture().paths:
            fixture = _QualificationBindingFixture()
            fixture.raw[executable] = b"x" + fixture.raw[executable][1:]
            with self.subTest(executable=executable), self.assertRaisesRegex(ConformanceError, "PROXY_MANIFEST_INVALID"):
                self.exercise(fixture)

    def test_retained_file_mode_and_owner_are_enforced_before_binding(self):
        for field, value in (("st_uid", 1000), ("st_gid", 1000), ("st_mode", stat.S_IFREG | 0o755)):
            fixture = _QualificationBindingFixture()
            with self.subTest(field=field), ExitStack() as stack:
                owner = fixture.context(stack)
                setattr(fixture.nodes[server.WORKER], field, value)
                with self.assertRaisesRegex(ConformanceError, "PROXY_FILE_CUSTODY"):
                    owner.qualification_binding.__init__(owner)

    def test_missing_record_or_broker_binding_does_not_fallback(self):
        for path in (admission.QUALIFICATION_PATH, admission.BROKER_BINDING_PATH):
            fixture = _QualificationBindingFixture()
            del fixture.raw["/unit-only/kit/" + path]
            fixture.release()
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.exercise(fixture)

    def test_release_signed_broker_peer_digest_substitution_refuses(self):
        for field in ("brokerManifestDigest", "brokerExecutableDigest", "workerManifestDigest", "workerArtifactDigest"):
            fixture = _QualificationBindingFixture()
            fixture.broker[field] = admission.ZERO
            fixture.raw["/unit-only/kit/" + admission.BROKER_BINDING_PATH] = canonical_bytes(fixture.broker)
            fixture.release()
            with self.subTest(field=field), self.assertRaisesRegex(ConformanceError, "QUALIFICATION_PEER_ENROLLMENT_MISMATCH"):
                self.exercise(fixture)

    def test_release_signed_endpoint_substitution_refuses(self):
        fixture = _QualificationBindingFixture()
        fixture.fixture.envelope["endpoints"][0]["ipAddress"] = "127.0.0.2"
        fixture.release()
        with self.assertRaises(ConformanceError):
            self.exercise(fixture)

    def test_unretained_release_tree_member_refuses(self):
        fixture = _QualificationBindingFixture()
        fixture.raw["/unit-only/kit/" + admission.QUALIFICATION_PATH] += b"\n"
        with self.assertRaisesRegex(ConformanceError, "PROXY_KIT_INVENTORY"):
            self.exercise(fixture)

    def test_capacity_forgery_refuses_before_release_read(self):
        fixture = _QualificationBindingFixture()
        fixture.raw["/unit-only/capacity.json"] = b"{}"
        with self.assertRaisesRegex(ConformanceError, "PROXY_FILE_DIGEST"):
            self.exercise(fixture)
        self.assertNotIn("/unit-only/release.json", fixture.read_paths)

    def test_envelope_forgery_refuses_before_capacity_read(self):
        fixture = _QualificationBindingFixture()
        value = json.loads(fixture.raw["/unit-only/envelope.json"])
        value["tenantSignature"] = "A" * 86
        fixture.raw["/unit-only/envelope.json"] = canonical_bytes(value)
        with self.assertRaises(ConformanceError):
            self.exercise(fixture)
        self.assertNotIn("/unit-only/capacity.json", fixture.read_paths)

    def test_parent_snapshot_does_not_hide_mutated_projection(self):
        fixture = _QualificationBindingFixture()
        with ExitStack() as stack:
            owner = fixture.context(stack)
            owner.profile["binding"]["tenantId"] = "other"
            with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_INPUT_SUBSTITUTION"):
                owner.qualification_binding.__init__(owner)

    def test_changed_owner_and_file_owner_poison_binding(self):
        for fault in ("active", "files", "file_owner", "deadline"):
            def action(owner, fixture):
                binding = owner.qualification_binding
                if fault == "active":
                    with patch.object(server, "_ACTIVE", None), self.assertRaises(ConformanceError):
                        binding.check()
                else:
                    target, field = (owner.files, "owner") if fault == "file_owner" else (owner, fault)
                    original = getattr(target, field)
                    setattr(target, field, owner.deadline + 1 if fault == "deadline" else None)
                    try:
                        with self.assertRaises(ConformanceError):
                            binding.check()
                    finally:
                        setattr(target, field, original)
                with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_BINDING_CLOSED"):
                    binding.check()
            with self.subTest(fault=fault):
                self.exercise(action=action)

    def test_retained_inode_change_poisoned_even_after_restoration(self):
        def action(owner, fixture):
            node = fixture.nodes[server.WORKER_MANIFEST]
            node.st_ino += 1
            with self.assertRaisesRegex(ConformanceError, "PROXY_FILE_CHANGED"):
                owner.qualification_binding.check()
            node.st_ino -= 1
            with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_BINDING_CLOSED"):
                owner.qualification_binding.check()
        self.exercise(action=action)

    def test_clock_reversal_and_original_deadline_cannot_be_reset(self):
        for fault in ("wall", "mono", "expiry"):
            def action(owner, fixture):
                if fault == "wall":
                    fixture.now = "2026-09-07T00:59:59Z"
                else:
                    fixture.mono = 99 if fault == "mono" else owner.deadline
                with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_CLOCK_OR_EXPIRY"):
                    owner.qualification_binding.check()
            with self.subTest(fault=fault):
                self.exercise(action=action)

    def test_check_deadline_overrun_is_sticky(self):
        def action(owner, fixture):
            binding = owner.qualification_binding
            with patch.object(server.time, "monotonic", side_effect=[100.0, 102.0]), self.assertRaises(ConformanceError):
                binding.check()
            with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_BINDING_CLOSED"):
                binding.check()
        self.exercise(action=action)

    def test_initial_load_cannot_extend_its_two_second_phase(self):
        fixture = _QualificationBindingFixture()
        with ExitStack() as stack:
            owner = fixture.context(stack)
            with patch.object(server.time, "monotonic", side_effect=[100.0, 102.0]), self.assertRaisesRegex(
                    ConformanceError, "QUALIFICATION_LOAD_DEADLINE"):
                owner.qualification_binding.__init__(owner)
            self.assertTrue(owner.qualification_binding.poisoned)

    def test_changed_retained_input_or_record_cannot_refresh_binding(self):
        for fault in ("kit", "profile", "record", "broker"):
            def action(owner, fixture):
                binding = owner.qualification_binding
                if fault == "kit":
                    owner.kit[admission.QUALIFICATION_PATH] += b"\n"
                elif fault == "profile":
                    owner.profile["binding"]["tenantId"] = "other"
                else:
                    setattr(binding, "_record_raw" if fault == "record" else "_broker_raw", b"{}")
                with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_INPUT_SUBSTITUTION"):
                    binding.check()
            with self.subTest(fault=fault):
                self.exercise(action=action)

    def test_record_expiry_is_not_extended_to_the_longer_signed_envelope_window(self):
        def action(owner, fixture):
            fixture.now = "2026-09-07T01:10:00Z"
            with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_CLOCK_OR_EXPIRY"):
                owner.qualification_binding.check()
        self.exercise(action=action)

    def test_close_never_closes_borrowed_files_and_refuses_reuse(self):
        def action(owner, fixture):
            count = len(fixture.fds)
            owner.qualification_binding.close()
            owner.qualification_binding.close()
            self.assertEqual(len(fixture.fds), count)
            self.assertFalse(owner.files.closed)
            with self.assertRaisesRegex(ConformanceError, "QUALIFICATION_BINDING_CLOSED"):
                owner.qualification_binding.check()
        self.exercise(action=action)

    def test_caller_data_descriptors_callbacks_or_alternate_owner_cannot_construct(self):
        for value in ({}, Mock(), 9, lambda: True):
            with self.subTest(kind=type(value)), self.assertRaises(ConformanceError):
                server._ServerQualificationBinding(value)
        with self.assertRaises(TypeError):
            server._ServerQualificationBinding(record=sample()["record"])


class KernelSelfInspectionTests(unittest.TestCase):
    """Real coordinator/binding; typed reader doubles for lifecycle fault injection.

    The 694 predecessor tests retain separate OS-edge coverage of each reader.
    These composition tests are NOT a combined native-reader or installed-server
    qualification. There is no production switch for selecting the doubles.
    """
    CLASSES = (("roots", server._KernelRootViews), ("policy", server._KernelPolicyView),
        ("process", server._KernelProcessView), ("code", server._KernelCodeFiles),
        ("mappings", server._KernelProcessCode), ("cgroup", server._KernelCgroupView),
        ("filters", server._KernelBpfView))

    def environment(self, stack, *, double_readers=True):
        self.fixture = _QualificationBindingFixture()
        self.owner = self.fixture.context(stack)
        self.owner.qualification_binding.__init__(self.owner)
        self.owner.self_inspection = object.__new__(server._KernelSelfInspection)
        self.events, self.resources, self.args = [], {}, {}
        self.on_build = self.on_check = self.on_close = lambda name, resource: None
        stack.enter_context(patch.object(server.os, "sysconf", return_value=4096))
        def initializer(name):
            def initialize(resource, *args):
                self.events.append(("acquire", name))
                self.resources[name], self.args[name] = resource, args
                resource.closed, resource.close_count = False, 0
                self.on_build(name, resource)
            return initialize
        def checker(name):
            def check(resource):
                self.assertIs(self.resources[name], resource)
                self.assertFalse(resource.closed)
                self.events.append(("check", name))
                return self.on_check(name, resource)
            return check
        def closer(name):
            def close(resource):
                self.assertFalse(resource.closed, "double close")
                resource.closed = True
                resource.close_count += 1
                self.events.append(("close", name))
                self.on_close(name, resource)
            return close
        if double_readers:
            # These existing tests intentionally double component operations;
            # the new retained epoch has separate real OS-edge tests below.
            stack.enter_context(patch.object(server._KernelRootViews, "_reader_mounts", return_value=None))
            for method in ("_retain_epoch", "_reader_epoch"):
                stack.enter_context(patch.object(server._KernelPolicyView, method, return_value=None))
            for name, kind in self.CLASSES:
                for method, value in (("__init__", initializer(name)), ("check", checker(name)), ("close", closer(name))):
                    stack.enter_context(patch.object(kind, method, value))
        subject = self.owner.self_inspection
        def cleanup():
            if hasattr(subject, "closed"):
                failure = subject.cleanup_failure
                if failure is None:
                    subject.close()
                else:
                    with self.assertRaises(type(failure)):
                        subject.close()  # verify sticky error; never reset it
        stack.callback(cleanup)
        return subject

    def start(self, stack):
        subject = self.environment(stack)
        subject.__init__(self.owner)
        return subject

    def fail(self, code="UNIT_READER_UNAVAILABLE"):
        raise ConformanceError(code, "unit lifecycle fault, no native proof")

    def test_fixed_composition_uses_authenticated_server_pins_and_current_pid_only(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            record, resources = self.fixture.record, self.resources
            self.assertEqual([n for e, n in self.events if e == "acquire"], [n for n, _ in self.CLASSES])
            self.assertEqual(self.args["roots"], ())
            self.assertEqual(self.args["policy"], (resources["roots"], record["host"], record["selinux"]))
            self.assertEqual(self.args["process"], (resources["roots"], server.os.getpid(), "SERVER", record["roles"]["SERVER"]))
            self.assertEqual(self.args["code"], (resources["roots"], record["files"], 4096))
            self.assertEqual(self.args["mappings"][:2], (resources["process"], resources["code"]))
            self.assertEqual(self.args["mappings"][2], {k: record["roles"]["SERVER"][k]
                for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")})
            self.assertEqual(self.args["cgroup"], (resources["process"], record["roles"]["SERVER"]["cgroup"]))
            self.assertEqual(self.args["filters"], (resources["cgroup"], record["roles"]["SERVER"]["bpfPrograms"]))
            self.assertIsNone(subject.check())
            self.assertFalse(hasattr(subject, "check_self"))
            self.assertFalse(hasattr(subject, "check_peer"))
            self.assertFalse(self.fixture.socket.called)
            self.assertNotIn(server.IDENTITY, self.fixture.read_paths)

    def test_policy_checks_surround_every_other_component_observation(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.events.clear()
            subject.check()
            names = [n for event, n in self.events if event == "check"]
            self.assertEqual(names, ["policy", "roots", "policy", "process", "policy", "code", "policy",
                "mappings", "policy", "cgroup", "policy", "filters", "policy", "roots"])

    def test_reverse_cleanup_closes_only_owned_readers_and_not_binding_files(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            original_files = set(self.fixture.fds)
            self.events.clear()
            subject.close()
            subject.close()
            self.assertEqual(self.events, [("close", n) for n, _ in reversed(self.CLASSES)])
            self.assertTrue(all(r.close_count == 1 for r in self.resources.values()))
            self.assertEqual(set(self.fixture.fds), original_files)
            self.assertFalse(self.owner.qualification_binding.closed)
            self.assertFalse(self.owner.files.closed)

    def test_each_partial_constructor_is_retained_and_closed_on_failure(self):
        for index, (fault, _) in enumerate(self.CLASSES):
            with self.subTest(fault=fault), ExitStack() as stack:
                subject = self.environment(stack)
                self.on_build = lambda name, resource: self.fail() if name == fault else None
                with self.assertRaisesRegex(ConformanceError, "UNIT_READER_UNAVAILABLE"):
                    subject.__init__(self.owner)
                self.assertEqual([n for e, n in self.events if e == "close"],
                    [n for n, _ in reversed(self.CLASSES[:index + 1])])
                self.assertTrue(subject.closed and subject.failed)
                with self.assertRaises(ConformanceError):
                    subject.check()

    def test_each_reader_failure_poisoned_and_all_owned_views_closed(self):
        for fault, _ in self.CLASSES:
            with self.subTest(fault=fault), ExitStack() as stack:
                subject = self.start(stack)
                self.on_check = lambda name, resource: self.fail() if name == fault else None
                with self.assertRaises(ConformanceError):
                    subject.check()
                self.assertTrue(all(r.closed and r.close_count == 1 for r in self.resources.values()))
                self.on_check = lambda name, resource: None
                with self.assertRaises(ConformanceError):
                    subject.check()

    def test_boolean_or_data_success_cannot_replace_reader_contract(self):
        for result in (True, False, {}, [], "PASS"):
            with self.subTest(result=result), ExitStack() as stack:
                subject = self.start(stack)
                self.on_check = lambda name, resource: result if name == "filters" else None
                with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_CHECK_RESULT"):
                    subject.check()

    def test_cleanup_failure_is_sticky_and_never_retries_close(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.on_close = lambda name, resource: self.fail("UNIT_CLOSE_UNCERTAIN") if name == "filters" else None
            with self.assertRaisesRegex(ConformanceError, "UNIT_CLOSE_UNCERTAIN"):
                subject.close()
            self.assertTrue(all(r.close_count == 1 for r in self.resources.values()))
            with self.assertRaisesRegex(ConformanceError, "UNIT_CLOSE_UNCERTAIN"):
                subject.close()
            self.assertTrue(all(r.close_count == 1 for r in self.resources.values()))

    def test_replaced_component_never_closes_the_unowned_replacement(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            replacement, original = Mock(), subject.filters
            subject.filters = replacement
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_VIEW_REPLACED"):
                subject.check()
            replacement.close.assert_not_called()
            self.assertTrue(original.closed)
            self.assertEqual(original.close_count, 1)

    def test_early_root_failure_does_not_acquire_other_readers(self):
        with ExitStack() as stack:
            subject = self.environment(stack, double_readers=False)
            with patch.object(server.sys, "platform", "unsupported"), patch.object(server.ctypes, "CDLL") as load:
                with self.assertRaises(ConformanceError):
                    subject.__init__(self.owner)
                load.assert_not_called()
            self.assertTrue(subject.closed)
            self.assertEqual(subject.owned, [])
            self.assertFalse(self.fixture.socket.called)

    def test_alternate_owner_and_unsigned_record_refused_before_reader_acquisition(self):
        for owner in ({}, Mock(), 77, lambda: None):
            with self.subTest(kind=type(owner)), self.assertRaises(ConformanceError):
                server._KernelSelfInspection(owner)
        with self.assertRaises(TypeError):
            server._KernelSelfInspection(record=sample()["record"])

    def test_same_class_but_unregistered_inspection_cannot_construct(self):
        with ExitStack() as stack:
            self.environment(stack)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_BINDING"):
                server._KernelSelfInspection(self.owner)
            self.assertEqual(self.events, [])

    def test_binding_failure_precedes_any_kernel_view(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            self.owner.qualification_binding.poisoned = True
            with self.assertRaises(ConformanceError):
                subject.__init__(self.owner)
            self.assertEqual(self.events, [])

    def test_parent_binding_or_owner_replacement_closes_existing_views(self):
        for fault in ("active", "binding", "deadline"):
            with self.subTest(fault=fault), ExitStack() as stack:
                subject = self.start(stack)
                if fault == "active":
                    with patch.object(server, "_ACTIVE", None), self.assertRaises(ConformanceError):
                        subject.check()
                else:
                    field = "qualification_binding" if fault == "binding" else "deadline"
                    original = getattr(self.owner, field)
                    setattr(self.owner, field, None if fault == "binding" else original + 1)
                    try:
                        with self.assertRaises(ConformanceError):
                            subject.check()
                    finally:
                        setattr(self.owner, field, original)
                self.assertTrue(all(r.closed for r in self.resources.values()))

    def test_record_change_during_component_acquisition_closes_partial_owner(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            def change(name, resource):
                if name == "code":
                    self.owner.qualification_binding._record_raw = b"{}"
            self.on_build = change
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_RECORD_CHANGED"):
                subject.__init__(self.owner)
            self.assertEqual(set(self.resources), {"roots", "policy", "process", "code"})
            self.assertTrue(all(r.closed for r in self.resources.values()))

    def test_retained_authority_file_drift_stops_a_reader_transition(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            node = self.fixture.nodes[server.WORKER_MANIFEST]
            original = node.st_ino
            self.on_check = lambda name, resource: setattr(node, "st_ino", original + 1) if name == "code" else None
            try:
                with self.assertRaisesRegex(ConformanceError, "PROXY_FILE_CHANGED"):
                    subject.check()
            finally:
                node.st_ino = original
            self.assertTrue(all(r.closed for r in self.resources.values()))

    def test_slow_constructor_cannot_reset_the_outer_two_second_budget(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            self.on_build = lambda name, resource: setattr(self.fixture, "mono", 102.0) if name == "code" else None
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_DEADLINE"):
                subject.__init__(self.owner)
            self.assertNotIn("mappings", self.resources)
            self.assertTrue(all(r.closed for r in self.resources.values()))

    def test_nested_reader_delay_and_wall_jump_are_bounded(self):
        for clock in ("mono", "wall"):
            with self.subTest(clock=clock), ExitStack() as stack:
                subject = self.start(stack)
                def delay(name, resource):
                    if name == "mappings":
                        if clock == "mono":
                            self.fixture.mono += 2
                        else:
                            self.fixture.now = "2026-09-07T01:00:02Z"
                self.on_check = delay
                with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_DEADLINE"):
                    subject.check()
                self.assertTrue(all(r.closed for r in self.resources.values()))

    def test_original_deadline_and_clock_reversals_refuse_without_observation(self):
        for clock in ("deadline", "mono", "wall"):
            with self.subTest(clock=clock), ExitStack() as stack:
                subject = self.start(stack)
                if clock == "wall":
                    self.fixture.now = "2026-09-07T00:59:59Z"
                else:
                    self.fixture.mono = self.owner.deadline if clock == "deadline" else 99.0
                self.events.clear()
                with self.assertRaises(ConformanceError):
                    subject.check()
                self.assertFalse(any(event == "check" for event, _ in self.events))

    def test_recursive_inspection_poisoned_instead_of_reentering_views(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.on_check = lambda name, resource: subject.check() if name == "policy" else None
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_UNAVAILABLE"):
                subject.check()
            self.assertTrue(subject.failed and subject.closed)

    def test_unsupported_page_size_stops_before_code_or_mapping_reads(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            with patch.object(server.os, "sysconf", return_value=8192), self.assertRaisesRegex(
                    ConformanceError, "KERNEL_INSPECTION_PAGE_SIZE"):
                subject.__init__(self.owner)
            self.assertEqual(set(self.resources), {"roots", "policy", "process"})

    def test_startup_keeps_containment_refusal_before_storage_observer_and_credentials(self):
        import ast
        tree = ast.parse((ROOT / "src/harness_conformance/live_proxy_server.py").read_bytes())
        owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "NativeProxyServer")
        init = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
        source = ast.unparse(init)
        stages = ["self.qualification_binding.__init__(self)", "self.qualification.__init__(self)",
                  "self.storage.__init__(self)",
                  "self.observer.__init__(self)", "self.secrets.read(IDENTITY"]
        self.assertEqual(sorted(source.index(s) for s in stages), [source.index(s) for s in stages])
        self.assertNotIn("require_server_containment", source)
        self.assertNotIn("check_self", ast.unparse(next(n for n in tree.body
            if isinstance(n, ast.ClassDef) and n.name == "_KernelSelfInspection")))


class KernelInspectionReadBoundaryTests(unittest.TestCase):
    """Real binding/coordinator/tick methods with typed component and OS doubles.

    This is boundary wiring/refusal evidence, not a combined native factory or
    per-I/O policy-epoch qualification. Existing individual OS-edge tests stay.
    """
    CLASSES = KernelSelfInspectionTests.CLASSES
    environment = KernelSelfInspectionTests.environment
    start = KernelSelfInspectionTests.start
    fail = KernelSelfInspectionTests.fail

    def readers(self, subject):
        native = object.__new__(server._KernelNativeReads)
        native._inspection_owner = subject
        subject.roots.native = native
        subject.roots._native_original = native
        readers = list(self.resources.values()) + [native]
        for reader in readers:
            reader.pid, reader.thread = self.owner.pid, self.owner.thread
            reader.closed = reader.failed = False
            reader.busy, reader.last, reader.end = True, self.fixture.mono, self.fixture.mono + 2
        subject.process.pidfd = [None, None]
        subject.mappings.process = subject.cgroup.process = subject.process
        subject.filters.cgroup = subject.cgroup
        return readers

    def test_every_component_is_bound_before_its_constructor(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            seen = []
            def acquired(name, reader):
                self.assertIs(reader._inspection_owner, subject)
                self.assertIsNone(server._kernel_inspection_tick(reader))
                seen.append(name)
            self.on_build = acquired
            subject.__init__(self.owner)
            self.assertEqual(seen, [name for name, _ in self.CLASSES])
            self.assertFalse(self.fixture.socket.called)
            self.assertNotIn(server.IDENTITY, self.fixture.read_paths)

    def test_all_eight_real_reader_ticks_retain_original_owner(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            readers = self.readers(subject)
            with subject._phase():
                for reader in readers:
                    self.assertIsNone(reader._tick())
            self.assertFalse(subject.failed)
            self.assertFalse(self.fixture.socket.called)

    def test_real_io_wrappers_guard_before_and_after_an_observation(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            with subject._phase():
                for name in ("process", "policy", "code", "mappings", "cgroup", "filters"):
                    operation = Mock(return_value=b"UNIT_READ_ONLY")
                    self.assertEqual(getattr(subject, name)._io(operation, 71), b"UNIT_READ_ONLY")
                    operation.assert_called_once_with(71)

    def test_owner_disappearing_inside_io_stops_before_second_observation(self):
        for name in ("process", "policy", "code", "mappings", "cgroup", "filters"):
            with self.subTest(name=name), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                operation, next_read = Mock(), Mock()
                operation.side_effect = lambda: stack.enter_context(patch.object(server, "_ACTIVE", None))
                with self.assertRaises(ConformanceError), subject._phase():
                    getattr(subject, name)._io(operation)
                    next_read()
                operation.assert_called_once_with()
                next_read.assert_not_called()
                self.assertTrue(subject.failed and subject.closed)

    def test_guard_failure_before_io_never_calls_the_operation(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            operation = Mock()
            with self.assertRaises(ConformanceError), subject._phase():
                self.owner.qualification_binding.poisoned = True
                subject.code._io(operation)
            operation.assert_not_called()

    def test_authority_file_replacement_inside_io_poisoned_before_next_read(self):
        for path in (str(server.FIXED_RELEASE_TRUST), str(server.FIXED_TENANT_TRUST), server.PUBLIC_KEY):
            with self.subTest(path=path), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                node = self.fixture.nodes[path]
                original = node.st_ino
                operation = Mock(side_effect=lambda: setattr(node, "st_ino", original + 1))
                try:
                    with self.assertRaises(ConformanceError), subject._phase():
                        subject.policy._io(operation)
                finally:
                    node.st_ino = original  # unit OS restoration for borrowed-file cleanup
                operation.assert_called_once_with()
                self.assertTrue(subject.failed and subject.closed)

    def test_authority_bytes_replaced_during_read_cannot_use_prior_signature(self):
        for field in ("owner", "binding"):
            with self.subTest(field=field), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                target = self.owner if field == "owner" else subject.binding
                original = target.authority
                try:
                    with self.assertRaises(ConformanceError), subject._phase():
                        subject.code._io(lambda: setattr(target, "authority", (b"{}",) * 4))
                finally:
                    target.authority = original
                self.assertTrue(subject.failed and subject.closed)

    def test_session_window_replacement_inside_read_cannot_extend_authority(self):
        from datetime import timedelta
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            original = self.owner.binding["notAfter"]
            extended = (server._time(original) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.assertNotEqual(extended, original)
            try:
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._io(lambda: self.owner.binding.update(notAfter=extended))
            finally:
                self.owner.binding["notAfter"] = original
            self.assertTrue(subject.failed and subject.closed)

    def test_signed_window_is_retained_separately_from_record_expiry(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            self.assertEqual(subject.authority_window, tuple(server._time(self.owner.binding[k])
                for k in ("notBefore", "notAfter")))
            # A deliberately shortened private pin proves this separate guard;
            # this test does not claim an independently signed shorter fixture.
            subject.authority_window = (subject.authority_window[0], server._time(self.fixture.now))
            with self.assertRaises(ConformanceError), subject._phase():
                subject.code._tick()

    def test_delayed_io_cannot_reset_original_combined_deadline(self):
        for clock in ("mono", "wall"):
            with self.subTest(clock=clock), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                def delay():
                    if clock == "mono":
                        self.fixture.mono += 2
                    else:
                        self.fixture.now = "2026-09-07T01:00:02Z"
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._io(delay)
                self.assertTrue(subject.failed and subject.closed)

    def test_reversed_wall_or_monotonic_clock_inside_read_refuses(self):
        for field, value in (("mono", 99.0), ("now", "2026-09-07T00:59:59Z")):
            with self.subTest(field=field), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._io(lambda: setattr(self.fixture, field, value))
                self.assertTrue(subject.failed and subject.closed)

    def test_unowned_same_class_and_copied_owner_reference_refused(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            substitute = object.__new__(server._KernelCodeFiles)
            substitute._inspection_owner = subject
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_READER_UNOWNED"), subject._phase():
                server._kernel_inspection_tick(substitute)
            self.assertTrue(subject.closed)

    def test_replaced_native_reader_cannot_reuse_the_previous_lifetime(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            original = self.readers(subject)[-1]
            subject.roots.native = object.__new__(server._KernelNativeReads)
            with self.assertRaises(ConformanceError), subject._phase():
                original._tick()
            self.assertTrue(subject.failed and subject.closed)

    def test_missing_owner_binding_during_active_server_is_not_standalone_mode(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            del subject.code._inspection_owner
            with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_READER_UNBOUND"), subject._phase():
                subject.code._tick()

    def test_callback_dictionary_or_raw_fd_cannot_select_a_guard(self):
        for value in (Mock(), {}, 71, lambda: None):
            with self.subTest(kind=type(value)), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                subject.code._inspection_owner = value
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._tick()

    def test_failure_stays_poisoned_after_unit_owner_is_restored(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            reader = self.readers(subject)[3]
            with self.assertRaises(ConformanceError), subject._phase():
                with patch.object(server, "_ACTIVE", None), self.assertRaises(ConformanceError):
                    reader._tick()
                self.assertTrue(subject.failed)
                with self.assertRaises(ConformanceError):
                    reader._tick()
                # The outer phase must still reject even when an inner caller
                # caught the initial refusal; exercise that below on exit.

    def test_native_constructor_refuses_unbound_reader_before_loading_libc(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            with patch.object(server.sys, "platform", "linux"), patch.object(server.ctypes, "CDLL") as load:
                with self.assertRaisesRegex(ConformanceError, "KERNEL_INSPECTION_READER_UNBOUND"):
                    server._KernelNativeReads()
                load.assert_not_called()
            self.assertFalse(self.fixture.socket.called)

    def test_source_retains_native_owner_and_all_eight_read_hooks(self):
        import ast
        tree = ast.parse((ROOT / "src/harness_conformance/live_proxy_server.py").read_bytes())
        classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
        for kind in (server._KernelNativeReads,) + tuple(kind for _, kind in self.CLASSES):
            tick = next(n for n in classes[kind.__name__].body if isinstance(n, ast.FunctionDef) and n.name == "_tick")
            self.assertIn("_kernel_inspection_tick(self)", ast.unparse(tick))
        root_init = next(n for n in classes["_KernelRootViews"].body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
        source = ast.unparse(root_init)
        self.assertLess(source.index("self.native._inspection_owner"), source.index("self.native.__init__()"))
        guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_kernel_inspection_tick")
        self.assertEqual([a.arg for a in guard.args.args], ["reader"])
        self.assertFalse(guard.args.defaults or guard.args.kwonlyargs)


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
        if path:
            self.assertEqual((flags, mask), (0x900, 0x411b))
            self.assertIn((self.handles[fd][0], path),
                (("/sys/fs/selinux", b"status"), ("/sys/fs", b"selinux"), ("/", b"/"),
                 ("/", b"proc"), ("/", b"sys"), ("/sys", b"kernel"), ("/sys", b"fs"),
                 ("/sys/fs", b"cgroup")))
            node = self.nodes["/" if path == b"/" else self.handles[fd][0].rstrip("/") + "/" + path.decode("ascii")]
        else:
            self.assertEqual((path, flags, mask), (b"", 0x1900, 0x411b))
            node = self.handles[fd][1]
        self.assertEqual(bytes(pointer._obj), b"\0" * 256)
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


class KernelRetainedEpochTests(unittest.TestCase):
    """Real policy/root/native/mapping flow with OS edges mocked, no active server."""
    def setUp(self):
        self.source_stat = server.os.stat
        KernelPolicyCustodyTests.setUp(self)

    def named_stat(self, name, *, dir_fd=None, follow_symlinks=True):
        if dir_fd is None:
            # unittest/linecache inspect source files when formatting failures;
            # native policy lookups always use a retained directory descriptor.
            return self.source_stat(name, follow_symlinks=follow_symlinks)
        return KernelPolicyCustodyTests.named_stat(self, name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    stat_fd = KernelPolicyCustodyTests.stat_fd
    statfs = KernelPolicyCustodyTests.statfs
    statx = KernelPolicyCustodyTests.statx
    close_fd = KernelPolicyCustodyTests.close_fd
    open_fd = KernelPolicyCustodyTests.open_fd
    read = KernelPolicyCustodyTests.read
    barrier = KernelPolicyCustodyTests.barrier
    mapping = KernelPolicyCustodyTests.mapping
    close_views = KernelPolicyCustodyTests.close_views
    view = KernelPolicyCustodyTests.view

    def retained(self):
        value = self.view()
        value._retain_epoch()
        return value

    def test_retained_mapping_is_read_only_and_reused_without_fresh_policy_open(self):
        value = self.retained()
        original, maps, opens = value.epoch_original, len(self.maps), len(self.opens)
        self.assertIsNotNone(original)
        self.assertEqual(original.closes, 0)
        self.assertIsNone(value._reader_epoch())
        self.assertIsNone(value._reader_epoch())
        self.assertEqual((len(self.maps), len(self.opens)), (maps, opens))
        self.assertIs(value.epoch_original, original)
        value.close()
        self.assertEqual(original.closes, 1)
        self.assertEqual(set(self.handles), self.root_fds)

    def test_already_busy_native_phase_is_not_reentered_or_renewed(self):
        value = self.retained()
        native = self.roots.native
        with native._phase():
            deadline = native.end
            self.assertIsNone(value._reader_epoch())
            self.assertTrue(native.busy)
            self.assertEqual(native.end, deadline)

    def test_policy_check_still_fresh_opens_hashes_and_closes_policy(self):
        value = self.retained()
        count = len([p for p, _, _ in self.opens if p == "/sys/fs/selinux/policy"])
        original = value.epoch_original
        self.assertIsNone(value.check())
        self.assertEqual(len([p for p, _, _ in self.opens if p == "/sys/fs/selinux/policy"]), count + 1)
        self.assertIs(value.epoch_original, original)
        self.assertEqual(original.closes, 0)

    def test_changed_even_epoch_refuses_and_cannot_be_restored(self):
        value = self.retained()
        original = self.raw_status
        fields = list(server.struct.unpack("<5I", original))
        fields[1] += 2
        self.raw_status = server.struct.pack("<5I", *fields)
        with self.assertRaisesRegex(ConformanceError, "EPOCH_CHANGED"):
            value._reader_epoch()
        self.raw_status = original
        with self.assertRaises(ConformanceError):
            value._reader_epoch()
        self.assertTrue(value.failed)

    def changed_field_refuses(self, index):
        value = self.retained()
        fields = list(server.struct.unpack("<5I", self.raw_status))
        fields[index] = fields[index] + 1 if index in (1, 3) else 0
        self.raw_status = server.struct.pack("<5I", *fields)
        with self.assertRaises(ConformanceError):
            value._reader_epoch()
        self.assertTrue(value.failed)

    def test_odd_sequence_and_changed_controls_refuse(self):
        self.changed_field_refuses(1)

    def test_enforcement_disabled_refuses_in_fresh_reader_lifetime(self):
        self.changed_field_refuses(2)

    def test_policyload_changed_refuses_in_fresh_reader_lifetime(self):
        self.changed_field_refuses(3)

    def test_deny_unknown_disabled_refuses_in_fresh_reader_lifetime(self):
        self.changed_field_refuses(4)

    def test_epoch_change_during_fence_is_rejected(self):
        value = self.retained()
        changed = False
        def change(*args):
            nonlocal changed
            result = self.barrier(*args)
            if not changed:
                changed = True
                fields = list(server.struct.unpack("<5I", self.raw_status))
                fields[1] += 2
                self.raw_status = server.struct.pack("<5I", *fields)
            return result
        self.lib.syscall.side_effect = change
        with self.assertRaises(ConformanceError):
            value._reader_epoch()
        self.assertTrue(changed)

    def test_status_path_changed_during_sample_is_not_hidden_by_retained_map(self):
        value = self.retained()
        path = "/sys/fs/selinux/status"
        original = self.nodes[path]
        def changed(*args):
            self.nodes[path] = {**original, "st_ino": original["st_ino"] + 1}
            return self.barrier(*args)
        self.lib.syscall.side_effect = changed
        with self.assertRaisesRegex(ConformanceError, "PATH_CHANGED"):
            value._reader_epoch()
        self.nodes[path] = original

    def test_status_or_parent_fd_replacement_refuses(self):
        for role in ("status", "parent"):
            value = self.retained()
            fd = value.rows[5][0] if role == "status" else self.roots.rows[5][0]
            original = self.handles[fd]
            self.handles[fd] = (original[0], {**original[1], "st_ino": original[1]["st_ino"] + 1})
            with self.subTest(role=role), self.assertRaisesRegex(ConformanceError, "FD_CHANGED"):
                value._reader_epoch()
            self.handles[fd] = original  # restore synthetic foreign owner for cleanup
            value.close()

    def test_inheritable_or_write_access_refuses_before_status_sample(self):
        for fault in ("inherit", "write", "path"):
            value = self.retained()
            calls = self.lib.syscall.call_count
            manager = patch.object(server.os, "get_inheritable", return_value=True) if fault == "inherit" else (
                patch.object(server.fcntl, "fcntl", return_value=server.os.O_WRONLY if fault == "write" else 0o10000000))
            with manager, self.subTest(fault=fault), self.assertRaisesRegex(ConformanceError, "FD_ACCESS"):
                value._reader_epoch()
            self.assertEqual(self.lib.syscall.call_count, calls)
            value.close()

    def test_mapping_substitution_closes_only_original_mapping(self):
        value = self.retained()
        original, replacement = value.epoch_original, Mock()
        value.epoch_mapping = replacement
        with self.assertRaisesRegex(ConformanceError, "REPLACED"):
            value._reader_epoch()
        value.close()
        self.assertEqual(original.closes, 1)
        replacement.close.assert_not_called()

    def test_mutated_expected_status_cannot_reenroll_a_changed_epoch(self):
        value = self.retained()
        value.selinux["status"]["sequence"] += 2
        with self.assertRaisesRegex(ConformanceError, "REPLACED"):
            value._reader_epoch()

    def test_native_reader_substitution_refuses(self):
        value = self.retained()
        original = self.roots.native
        self.roots.native = object.__new__(server._KernelNativeReads)
        try:
            with self.assertRaisesRegex(ConformanceError, "NATIVE_CHANGED"):
                value._reader_epoch()
        finally:
            self.roots.native = original

    def test_barrier_error_never_reuses_a_previous_sample(self):
        value = self.retained()
        self.lib.syscall.return_value = -1
        self.lib.syscall.side_effect = None
        with self.assertRaises(ConformanceError):
            value._reader_epoch()
        self.assertTrue(value.failed)

    def test_delayed_barrier_cannot_reset_a_busy_native_deadline(self):
        value = self.retained()
        def delayed(*args):
            result = self.barrier(*args)
            self.now += 2
            return result
        self.lib.syscall.side_effect = delayed
        with self.assertRaises(ConformanceError), self.roots.native._phase():
            value._reader_epoch()
        self.assertTrue(value.failed)

    def test_duplicate_retention_and_closed_reader_refuse(self):
        value = self.retained()
        count = len(self.maps)
        with self.assertRaises(ConformanceError):
            value._retain_epoch()
        self.assertEqual(len(self.maps), count)
        value.close()
        with self.assertRaises(ConformanceError):
            value._reader_epoch()
        with self.assertRaises(ConformanceError):
            value._retain_epoch()

    def test_failed_retention_keeps_original_mapping_owned_for_cleanup(self):
        value = self.view()
        mapper = self.mapping
        created = []
        def allocate(*args, **kwargs):
            mapping = mapper(*args, **kwargs)
            created.append(mapping)
            if len(created) == 2:  # first is the original short-lived _epoch check
                self.now += 2
            return mapping
        self.mapper.side_effect = allocate
        with self.assertRaises(ConformanceError):
            value._retain_epoch()
        self.assertEqual(len(created), 2)
        self.assertIs(value.epoch_original, created[-1])
        value.close()
        self.assertTrue(all(m.closes == 1 for m in created))

    def test_uncertain_mapping_close_is_sticky_and_still_closes_policy_fds(self):
        value = self.retained()
        original = value.epoch_original
        original.close = Mock(side_effect=OSError("unit close uncertain"))
        for _ in range(2):
            with self.assertRaises(OSError):
                value.close()
        original.close.assert_called_once_with()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_read_only_page_sizes_and_both_abis_remain_explicit(self):
        for machine in ("x86_64", "aarch64"):
            # Construct the actual primitive reader against each mocked OS ABI.
            self.machine = machine
            self.host["machine"] = machine
            original = self.roots.native
            self.roots.native = self.roots._native_original = server._KernelNativeReads()
            try:
                for size in (4096, 16384, 65536):
                    self.page_size = size
                    with self.subTest(machine=machine, size=size):
                        value = self.retained()
                        self.assertIsNone(value._reader_epoch())
                        value.close()
            finally:
                self.roots.native.close()
                self.roots.native = self.roots._native_original = original


class KernelEpochMountTests(unittest.TestCase):
    """Actual epoch/native/root readers; fixed OS boundaries are synthetic."""
    setUp = KernelRetainedEpochTests.setUp
    named_stat = KernelRetainedEpochTests.named_stat
    stat_fd = KernelRetainedEpochTests.stat_fd
    statfs = KernelRetainedEpochTests.statfs
    statx = KernelRetainedEpochTests.statx
    close_fd = KernelRetainedEpochTests.close_fd
    open_fd = KernelRetainedEpochTests.open_fd
    read = KernelRetainedEpochTests.read
    barrier = KernelRetainedEpochTests.barrier
    mapping = KernelRetainedEpochTests.mapping
    close_views = KernelRetainedEpochTests.close_views
    view = KernelRetainedEpochTests.view
    retained = KernelRetainedEpochTests.retained

    def replace_named(self, path, **changes):
        original = self.nodes[path]
        self.nodes[path] = {**original, **changes}
        self.addCleanup(self.nodes.__setitem__, path, original)

    def mount_refusal(self, role):
        value = self.retained()
        fd = {"status": value.rows[5][0], "parent": self.roots.rows[5][0],
              "ancestry": self.roots.rows[4][0]}[role]
        original = self.handles[fd]
        self.handles[fd] = (original[0], {**original[1], "mountId": original[1]["mountId"] + 100})
        try:
            with self.assertRaisesRegex(ConformanceError, "MOUNT.*CHANGED"):
                value._reader_epoch()
            self.assertTrue(value.failed)
        finally:
            self.handles[fd] = original
        with self.assertRaises(ConformanceError):
            value._reader_epoch()  # restoration never renews a failed lifetime

    def corrupt_statx(self, offset, fmt, changed):
        value = self.retained()
        def corrupt(*args):
            result = self.statx(*args)
            raw = bytearray(bytes(args[-1]._obj))
            server.struct.pack_into(fmt, raw, offset, changed)
            args[-1]._obj.words[:] = server.struct.unpack("<32Q", raw)
            return result
        self.lib.statx.side_effect = corrupt
        with self.assertRaises(ConformanceError):
            value._reader_epoch()
        self.assertTrue(value.failed)

    def test_samples_mounts_without_new_descriptors_mappings_or_policy_opens(self):
        value = self.retained()
        before = (len(self.opens), len(self.maps), set(self.handles))
        self.lib.statx.reset_mock()
        self.assertIsNone(value._reader_epoch())
        calls = [(c.args[0], c.args[1], c.args[2], c.args[3]) for c in self.lib.statx.call_args_list]
        fd, parent, ancestry = value.epoch_mount_pin[0]
        expected = [(fd, b"", 0x1900, 0x411b), (parent, b"", 0x1900, 0x411b),
                    (ancestry, b"", 0x1900, 0x411b), (parent, b"status", 0x900, 0x411b),
                    (ancestry, b"selinux", 0x900, 0x411b)]
        self.assertEqual(calls, expected * 2)
        self.assertEqual((len(self.opens), len(self.maps), set(self.handles)), before)
        value.close()
        self.assertEqual(set(self.handles), self.root_fds)

    def test_same_inode_status_bind_mount_is_not_hidden_by_retained_mapping(self):
        value = self.retained()
        path = "/sys/fs/selinux/status"
        self.replace_named(path, mountId=self.nodes[path]["mountId"] + 1)
        count = self.lib.syscall.call_count
        with self.assertRaisesRegex(ConformanceError, "MOUNT_PATH_CHANGED"):
            value._reader_epoch()
        self.assertEqual(self.lib.syscall.call_count, count)

    def test_same_inode_selinux_parent_bind_mount_refuses(self):
        value = self.retained()
        path = "/sys/fs/selinux"
        self.replace_named(path, mountId=self.nodes[path]["mountId"] + 1)
        with self.assertRaisesRegex(ConformanceError, "MOUNT_PATH_CHANGED"):
            value._reader_epoch()

    def test_retained_status_mount_change_refuses(self):
        self.mount_refusal("status")

    def test_retained_parent_mount_change_refuses(self):
        self.mount_refusal("parent")

    def test_retained_sysfs_ancestry_mount_change_refuses(self):
        self.mount_refusal("ancestry")

    def test_retained_filesystem_identity_change_refuses(self):
        value = self.retained()
        def changed(fd, pointer):
            result = self.statfs(fd, pointer)
            pointer._obj.fsid[1] += 1
            return result
        self.lib.fstatfs.side_effect = changed
        with self.assertRaisesRegex(ConformanceError, "MOUNT_CHANGED"):
            value._reader_epoch()

    def test_symlink_status_output_never_matches_regular_inode(self):
        value = self.retained()
        self.replace_named("/sys/fs/selinux/status", st_mode=stat.S_IFLNK | 0o777)
        with self.assertRaisesRegex(ConformanceError, "PATH_CHANGED"):
            value._reader_epoch()

    def test_missing_unique_mount_bit_cannot_use_recycled_id(self):
        self.corrupt_statx(0, "<I", 0x17ff)

    def test_unknown_statx_fields_are_not_accepted(self):
        self.corrupt_statx(0, "<I", 0x247ff)

    def test_nonzero_reserved_statx_bytes_refuse(self):
        self.corrupt_statx(184, "<Q", 1)

    def test_mount_change_during_epoch_fence_is_seen_after_sample(self):
        value = self.retained()
        path = "/sys/fs/selinux/status"
        original = self.nodes[path]
        def changed(*args):
            self.nodes[path] = {**original, "mountId": original["mountId"] + 1}
            return self.barrier(*args)
        self.lib.syscall.side_effect = changed
        try:
            with self.assertRaisesRegex(ConformanceError, "MOUNT_PATH_CHANGED"):
                value._reader_epoch()
        finally:
            self.nodes[path] = original

    def test_delayed_mount_query_keeps_original_busy_phase_deadline(self):
        value = self.retained()
        def delayed(*args):
            result = self.statx(*args)
            self.now += 2
            return result
        self.lib.statx.side_effect = delayed
        native = self.roots.native
        with self.assertRaises(ConformanceError), native._phase():
            deadline = native.end
            try:
                value._reader_epoch()
            finally:
                self.assertEqual(native.end, deadline)
        self.assertTrue(value.failed and native.failed)

    def test_failed_query_still_checks_post_io_owner_custody(self):
        value = self.retained()
        pid = self.roots.native.pid
        def failed(*args):
            self.roots.native.pid = pid + 1
            raise OSError("unit unavailable statx")
        self.lib.statx.side_effect = failed
        try:
            with self.assertRaisesRegex(ConformanceError, "READER_CUSTODY"):
                value._reader_epoch()
        finally:
            self.roots.native.pid = pid
        self.assertTrue(value.failed)

    def test_inheritable_sysfs_ancestry_is_refused(self):
        value = self.retained()
        ancestry = self.roots.rows[4][0]
        with patch.object(server.os, "get_inheritable", side_effect=lambda fd: fd == ancestry):
            with self.assertRaisesRegex(ConformanceError, "DESCRIPTOR_ACCESS"):
                value._reader_epoch()

    def test_mutated_mount_pins_cannot_reenroll_the_view(self):
        value = self.retained()
        value.rows[5][2]["mountId"] += 1
        with self.assertRaisesRegex(ConformanceError, "EPOCH_REPLACED"):
            value._reader_epoch()

    def test_replaced_sysfs_descriptor_is_not_adopted(self):
        value = self.retained()
        row = self.roots.rows[4]
        original = row[0]
        row[0] = self.roots.rows[2][0]
        try:
            with self.assertRaisesRegex(ConformanceError, "EPOCH_REPLACED"):
                value._reader_epoch()
        finally:
            row[0] = original

    def test_dynamic_directory_counters_are_not_mount_custody(self):
        value = self.retained()
        def dynamic(fd):
            node = self.handles[fd][1]
            node["st_size"] += 1
            node["st_mtime_ns"] += 1
            node["st_ctime_ns"] += 1
            return self.stat_fd(fd)
        with patch.object(server.os, "fstat", side_effect=dynamic):
            self.assertIsNone(value._reader_epoch())

    def test_same_fixed_queries_on_both_mocked_native_abis(self):
        for machine in ("x86_64", "aarch64"):
            self.machine = self.host["machine"] = machine
            original = self.roots.native
            self.roots.native = self.roots._native_original = server._KernelNativeReads()
            try:
                value = self.retained()
                with self.subTest(machine=machine):
                    self.assertIsNone(value._reader_epoch())
                value.close()
            finally:
                self.roots.native.close()
                self.roots.native = self.roots._native_original = original

    def test_statx_helper_has_no_arbitrary_path_or_fd_fallback(self):
        value = self.retained()
        calls = self.lib.statx.call_count
        with self.assertRaisesRegex(ConformanceError, "FIXED_PATH"), self.roots.native._phase():
            self.roots.native._statx_identity(value.rows[5][0], b"../policy")
        self.assertEqual(self.lib.statx.call_count, calls)

    def test_statx_inode_disagreement_with_retained_fd_refuses(self):
        self.corrupt_statx(32, "<Q", 999999)

    def test_unavailable_named_query_never_falls_back_to_stat(self):
        value = self.retained()
        def failed(*args):
            return -1 if args[1] else self.statx(*args)
        self.lib.statx.side_effect = failed
        with self.assertRaisesRegex(ConformanceError, "MOUNT_ID_UNAVAILABLE"):
            value._reader_epoch()
        self.assertTrue(value.failed)

    def test_large_unique_mount_ids_preserve_native_uint64_precision(self):
        self.roots.close()
        for node in self.nodes.values():
            node["mountId"] += 2 ** 53
        self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        self.root_fds = set(self.handles)
        value = self.retained()
        self.assertGreater(value.epoch_mount_pin[1][0][1], 2 ** 53)
        self.assertIsNone(value._reader_epoch())
        value.close()

    def test_mount_pin_has_no_mutable_filesystem_alias(self):
        value = self.retained()
        original = value.epoch_mount_pin
        value.rows[5][2]["filesystem"]["fsid"][1] += 1
        self.assertEqual(value.epoch_mount_pin, original)
        with self.assertRaisesRegex(ConformanceError, "EPOCH_REPLACED"):
            value._reader_epoch()


class KernelRootBoundaryMountTests(unittest.TestCase):
    """Real root/native methods; fixed statx/fstatfs and OS edges are mocked."""
    stat_fd = KernelRootCustodyTests.stat_fd
    statfs = KernelRootCustodyTests.statfs
    statx = KernelRootCustodyTests.statx
    close_fd = KernelRootCustodyTests.close_fd
    open_fd = KernelRootCustodyTests.open_fd
    owner = KernelRootCustodyTests.owner

    def setUp(self):
        self.case_started = _wall_clock()
        KernelRootCustodyTests.setUp(self)

    def tearDown(self):
        # Diagnostic output only. Do not replace discovery, run, result state,
        # clocks, assertions, or the launcher's unchanged acceptance deadline.
        result = self._outcome.result
        for case, detail in result.failures + result.errors:
            if case is self or getattr(case, "test_case", None) is self:
                print("CONF-LIVE-003 root-boundary diagnostic " + detail, flush=True)
        print(f"CONF-LIVE-003 case-timing case={self.id()} "
              f"elapsedSeconds={_wall_clock() - self.case_started:.6f} evidenceClass=DIAGNOSTIC_ONLY", flush=True)

    def named_replacement(self, path):
        roots = self.owner()
        original = self.nodes[path]
        self.nodes[path] = dict(original, mountId=original["mountId"] + 100)
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_PATH_CHANGED"):
            roots._reader_mounts()
        self.assertTrue(roots.failed)
        self.nodes[path] = original
        with self.assertRaises(ConformanceError):
            roots._reader_mounts()
        self.assertEqual(len(self.handles), 7)  # owner, not sampler, closes

    def test_fixed_queries_retain_descriptors_without_open_mapping_or_syscall(self):
        roots = self.owner()
        before = (list(self.opens), list(self.closed), set(self.handles))
        self.lib.statx.reset_mock()
        self.assertIsNone(roots._reader_mounts())
        self.assertEqual((self.opens, self.closed, set(self.handles)), before)
        self.assertEqual(self.lib.statx.call_count, 14)
        self.assertEqual([call.args[1] for call in self.lib.statx.call_args_list],
            [b""] * 7 + [b"/", b"proc", b"sys", b"kernel", b"fs", b"selinux", b"cgroup"])
        self.mapper.assert_not_called()
        self.ioctl.assert_not_called()
        self.lib.syscall.assert_not_called()

    def test_same_inode_current_root_replacement_refuses(self):
        self.named_replacement("/")

    def test_same_inode_proc_replacement_refuses(self):
        self.named_replacement("/proc")

    def test_same_inode_sys_replacement_refuses(self):
        self.named_replacement("/sys")

    def test_same_inode_kernel_replacement_refuses(self):
        self.named_replacement("/sys/kernel")

    def test_same_inode_fs_replacement_refuses(self):
        self.named_replacement("/sys/fs")

    def test_same_inode_selinux_replacement_refuses(self):
        self.named_replacement("/sys/fs/selinux")

    def test_same_inode_cgroup_replacement_refuses(self):
        self.named_replacement("/sys/fs/cgroup")

    def test_retained_mount_change_refuses_even_if_named_view_agrees(self):
        roots = self.owner()
        self.nodes["/proc"]["mountId"] += 100
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_CHANGED"):
            roots._reader_mounts()
        self.assertTrue(roots.failed)

    def test_frozen_filesystem_pins_reject_mutable_alias(self):
        roots = self.owner()
        original = roots.mount_pin
        roots.rows[0][2]["filesystem"]["fsid"][0] += 1
        self.assertEqual(roots.mount_pin, original)
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_REPLACED"):
            roots._reader_mounts()

    def test_frozen_descriptor_inventory_rejects_reordered_rows(self):
        roots = self.owner()
        roots.rows[0], roots.rows[1] = roots.rows[1], roots.rows[0]
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_REPLACED"):
            roots._reader_mounts()

    def test_native_replacement_is_refused_and_not_closed_by_sampler(self):
        roots = self.owner()
        original = roots.native
        substitute = object.__new__(server._KernelNativeReads)
        roots.native = substitute
        try:
            with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_NATIVE_CHANGED"):
                roots._reader_mounts()
            self.assertFalse(original.closed)
            self.assertEqual(len(self.handles), 7)
        finally:
            roots.native = original

    def test_filesystem_identity_substitution_refuses(self):
        roots = self.owner()
        def changed(fd, pointer):
            result = self.statfs(fd, pointer)
            pointer._obj.fsid[1] += 1
            return result
        self.lib.fstatfs.side_effect = changed
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_CHANGED"):
            roots._reader_mounts()

    def test_writable_descriptor_is_refused(self):
        roots = self.owner()
        with patch.object(server.fcntl, "fcntl", return_value=server.os.O_RDWR):
            with self.assertRaisesRegex(ConformanceError, "KERNEL_DESCRIPTOR_ACCESS"):
                roots._reader_mounts()

    def test_inheritable_descriptor_is_refused(self):
        roots = self.owner()
        with patch.object(server.os, "get_inheritable", return_value=True):
            with self.assertRaisesRegex(ConformanceError, "KERNEL_DESCRIPTOR_ACCESS"):
                roots._reader_mounts()

    def test_symlink_replacement_is_not_followed(self):
        roots = self.owner()
        self.nodes["/proc"] = dict(self.nodes["/proc"], st_mode=stat.S_IFLNK | 0o777)
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_PATH_CHANGED"):
            roots._reader_mounts()

    def test_delayed_success_keeps_original_native_phase_deadline(self):
        roots = self.owner()
        def late(*args):
            result = self.statx(*args)
            self.now += 0.2
            return result
        with self.assertRaises(ConformanceError), roots.native._phase():
            original_end = roots.native.end
            self.now += 1.9
            self.lib.statx.side_effect = late
            try:
                roots._reader_mounts()
            finally:
                self.assertEqual(roots.native.end, original_end)
        self.assertTrue(roots.failed and roots.native.failed)

    def test_delayed_success_keeps_original_root_phase_deadline(self):
        roots = self.owner()
        delayed = False
        def late(*args):
            nonlocal delayed
            result = self.statx(*args)
            if not delayed:
                self.now += 0.2
                delayed = True
            return result
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_DEADLINE"), roots._phase():
            original_end = roots.end
            self.now += 1.9
            self.lib.statx.side_effect = late
            try:
                roots._reader_mounts()
            finally:
                self.assertEqual(roots.end, original_end)

    def test_backward_clock_between_samples_is_refused(self):
        roots = self.owner()
        roots._reader_mounts()
        self.now -= 1
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_DEADLINE"):
            roots._reader_mounts()

    def test_exception_still_checks_deadline_and_retains_cleanup_owner(self):
        roots = self.owner()
        def late(*args):
            self.now += 2
            raise OSError("unit delayed kernel refusal")
        self.lib.statx.side_effect = late
        with self.assertRaisesRegex(ConformanceError, "DEADLINE"):
            roots._reader_mounts()
        self.assertTrue(roots.failed)
        self.assertFalse(roots.mount_busy or roots.native.busy)
        self.assertEqual(len(self.handles), 7)
        roots.close()
        self.assertFalse(self.handles)

    def test_query_exception_is_sticky_without_retry(self):
        roots = self.owner()
        self.lib.statx.side_effect = OSError("unit unavailable")
        with self.assertRaises(OSError):
            roots._reader_mounts()
        self.lib.statx.side_effect = self.statx
        with self.assertRaises(ConformanceError):
            roots._reader_mounts()

    def test_reentrant_sampling_poisoned_without_recursive_native_calls(self):
        roots = self.owner()
        self.lib.statx.side_effect = lambda *args: roots._reader_mounts()
        with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_UNAVAILABLE"):
            roots._reader_mounts()
        self.assertTrue(roots.failed)
        self.assertFalse(roots.mount_busy)

    def test_wrong_thread_refuses_before_any_query(self):
        roots = self.owner()
        self.lib.statx.reset_mock()
        with patch.object(server.threading, "get_ident", return_value=722):
            with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_CUSTODY"):
                roots._reader_mounts()
        self.lib.statx.assert_not_called()

    def test_closed_owner_refuses_without_query_or_double_close(self):
        roots = self.owner()
        roots.close()
        self.lib.statx.reset_mock()
        count = len(self.closed)
        with self.assertRaises(ConformanceError):
            roots._reader_mounts()
        roots.close()
        self.assertEqual(len(self.closed), count)
        self.lib.statx.assert_not_called()

    def test_full_root_reopen_check_remains_required_and_available(self):
        roots = self.owner()
        roots._reader_mounts()
        before = len(self.opens)
        roots.check()
        self.assertEqual(len(self.opens), before + 7)
        self.assertEqual(len(self.handles), 7)

    def test_dynamic_directory_counters_are_not_mount_identity(self):
        roots = self.owner()
        for node in self.nodes.values():
            node.update(st_nlink=42, st_size=1024, st_mtime_ns=27, st_ctime_ns=28)
        self.assertIsNone(roots._reader_mounts())

    def test_full_uint64_mount_ids_are_not_json_numbers(self):
        for node in self.nodes.values():
            node["mountId"] += 2 ** 63
        roots = self.owner()
        self.assertIsNone(roots._reader_mounts())
        self.assertGreater(roots.mount_pin[1][0][1], 2 ** 63)

    def test_both_mocked_linux_abis_use_the_same_fixed_root_layout(self):
        for machine in ("x86_64", "aarch64"):
            with self.subTest(machine=machine), patch.object(server.os, "uname", return_value=SimpleNamespace(machine=machine)):
                roots = self.owner()
                self.assertIsNone(roots._reader_mounts())
                roots.close()


class KernelInspectionRootWiringTests(unittest.TestCase):
    """Real reader-boundary routing with explicit root/epoch operation doubles."""
    CLASSES = KernelSelfInspectionTests.CLASSES
    environment = KernelSelfInspectionTests.environment
    start = KernelSelfInspectionTests.start
    fail = KernelSelfInspectionTests.fail
    readers = KernelInspectionReadBoundaryTests.readers
    tearDown = KernelRootBoundaryMountTests.tearDown

    def setUp(self):
        self.case_started = _wall_clock()

    def test_roots_surround_epoch_at_both_io_boundaries(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            order = []
            with patch.object(server._KernelRootViews, "_reader_mounts", side_effect=lambda: order.append("roots")), \
                 patch.object(server._KernelPolicyView, "_reader_epoch", side_effect=lambda: order.append("epoch")):
                with subject._phase():
                    subject.code._io(lambda: order.append("read"))
            self.assertEqual(order, ["roots", "epoch", "roots", "read", "roots", "epoch", "roots"])

    def test_initial_root_refusal_prevents_epoch_and_observation(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            operation = Mock()
            with patch.object(server._KernelRootViews, "_reader_mounts", side_effect=self.fail), \
                 patch.object(server._KernelPolicyView, "_reader_epoch") as epoch:
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._io(operation)
            epoch.assert_not_called()
            operation.assert_not_called()

    def test_root_change_during_observation_prevents_the_next_read(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            changed, reads = False, []
            def roots():
                if changed:
                    self.fail("UNIT_ROOT_CHANGED")
            def operation():
                nonlocal changed
                reads.append("first")
                changed = True
            with patch.object(server._KernelRootViews, "_reader_mounts", side_effect=roots):
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._io(operation)
                    reads.append("second")
            self.assertEqual(reads, ["first"])
            self.assertTrue(subject.closed and subject.failed)

    def test_root_and_original_native_nested_ticks_do_not_resample(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            def roots():
                server._kernel_inspection_tick(subject.roots)
                server._kernel_inspection_tick(subject.roots.native)
            with patch.object(server._KernelRootViews, "_reader_mounts", side_effect=roots) as sample:
                with subject._phase():
                    subject.code._tick()
            self.assertEqual(sample.call_count, 2)

    def test_unrelated_reader_reentry_during_root_sample_refuses(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            with patch.object(server._KernelRootViews, "_reader_mounts", side_effect=lambda: subject.process._tick()):
                with self.assertRaisesRegex(ConformanceError, "KERNEL_EPOCH_RECURSIVE_READER"), subject._phase():
                    subject.code._tick()

    def test_boolean_or_data_root_result_never_grants_readiness(self):
        for result in (True, False, "PASS", {}):
            with self.subTest(result=result), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                with patch.object(server._KernelRootViews, "_reader_mounts", return_value=result):
                    with self.assertRaisesRegex(ConformanceError, "KERNEL_ROOT_MOUNT_CHECK_RESULT"), subject._phase():
                        subject.code._tick()


class KernelInspectionEpochWiringTests(unittest.TestCase):
    """Real owner routing; explicit epoch doubles, not native qualification."""
    CLASSES = KernelSelfInspectionTests.CLASSES
    environment = KernelSelfInspectionTests.environment
    start = KernelSelfInspectionTests.start
    fail = KernelSelfInspectionTests.fail
    readers = KernelInspectionReadBoundaryTests.readers

    def test_all_reader_ticks_sample_the_epoch_before_and_after_io(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            readers = self.readers(subject)
            with patch.object(server._KernelPolicyView, "_reader_epoch", return_value=None) as epoch:
                with subject._phase():
                    for reader in readers:
                        before = epoch.call_count
                        reader._tick()
                        self.assertGreater(epoch.call_count, before)
                    order = []
                    epoch.side_effect = lambda: order.append("epoch")
                    subject.code._io(lambda: order.append("read"))
                    self.assertEqual(order, ["epoch", "read", "epoch"])

    def test_epoch_refusal_during_io_prevents_any_following_read(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            changed, reads = False, []
            def sample_epoch():
                if changed:
                    self.fail("UNIT_EPOCH_CHANGED")
            def operation():
                nonlocal changed
                reads.append("first")
                changed = True
            with patch.object(server._KernelPolicyView, "_reader_epoch", side_effect=sample_epoch):
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._io(operation)
                    reads.append("second")
            self.assertEqual(reads, ["first"])
            self.assertTrue(subject.failed and subject.closed)

    def test_epoch_inner_checks_allow_only_policy_and_original_native_reader(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            seen = []
            def sample_epoch():
                seen.append("sample")
                server._kernel_inspection_tick(subject.policy)
                server._kernel_inspection_tick(subject.roots.native)
            with patch.object(server._KernelPolicyView, "_reader_epoch", side_effect=sample_epoch):
                with subject._phase():
                    subject.code._tick()
            self.assertEqual(seen, ["sample"])

    def test_other_reader_reentry_during_epoch_check_refuses(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.readers(subject)
            with patch.object(server._KernelPolicyView, "_reader_epoch", side_effect=lambda: subject.process._tick()):
                with self.assertRaises(ConformanceError), subject._phase():
                    subject.code._tick()
            self.assertTrue(subject.failed and subject.closed)

    def test_boolean_epoch_result_cannot_replace_the_fixed_check(self):
        for result in (True, False, "PASS", {}):
            with self.subTest(result=result), ExitStack() as stack:
                subject = self.start(stack)
                self.readers(subject)
                with patch.object(server._KernelPolicyView, "_reader_epoch", return_value=result):
                    with self.assertRaises(ConformanceError), subject._phase():
                        subject.code._tick()

    def test_failed_retention_precedes_process_storage_observer_and_credentials(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            with patch.object(server._KernelPolicyView, "_retain_epoch", side_effect=ConformanceError("UNIT_EPOCH_MISSING", "unit")):
                with self.assertRaises(ConformanceError):
                    subject.__init__(self.owner)
            self.assertEqual(set(self.resources), {"roots", "policy"})
            self.assertFalse(self.fixture.socket.called)
            self.assertNotIn(server.IDENTITY, self.fixture.read_paths)


class KernelCodeCustodyTests(unittest.TestCase):
    """Real code/root/native factories with independent bytes and OS edges only."""
    stat_fd = KernelRootCustodyTests.stat_fd
    statfs = KernelRootCustodyTests.statfs
    statx = KernelRootCustodyTests.statx
    close_fd = KernelRootCustodyTests.close_fd
    elf = KernelInputCodecTests.elf
    auxv = KernelInputCodecTests.auxv

    def setUp(self):
        KernelRootCustodyTests.setUp(self)
        self.reads, self.labels, self.measures = [], [], []
        self.pins = []
        for path in ("/opt", "/opt/planeon"):
            self.nodes[path] = dict(self.nodes["/"], st_ino=100 + len(self.nodes))
        self.add_file("/opt/planeon/python", self.elf(), [dict(offset=0, length=4096, permissions="r-xp")])
        self.add_file("/opt/planeon/app", b"PK\x03\x04inert archive", [])
        self.stack.enter_context(patch.object(server.fcntl, "ioctl", side_effect=self.verity))
        self.stack.enter_context(patch.object(server.os, "pread", side_effect=self.pread))
        self.stack.enter_context(patch.object(server.os, "getxattr", side_effect=self.label, create=True))
        self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)

    def add_file(self, path, raw, segments):
        node = dict(self.nodes["/"], st_ino=200 + len(self.nodes), st_mode=stat.S_IFREG | 0o555,
                    st_size=len(raw), st_nlink=1, raw=raw, label=b"system_u:object_r:code_t:s0\0",
                    verity=hashlib.sha256(b"independent verity descriptor:" + raw).digest())
        self.nodes[path] = node
        self.pins.append(dict(path=path, mode="0555", size=len(raw), sha256=server.byte_digest(raw),
                              verityDigest="sha256:" + node["verity"].hex(),
                              selinuxLabel="system_u:object_r:code_t:s0", executableSegments=segments))

    def open_fd(self, name, flags, *, dir_fd):
        path = "/" if dir_fd is None else self.handles[dir_fd][0].rstrip("/") + "/" + name
        self.assertNotIn("/", name if dir_fd is not None else "root")
        node = self.nodes[path]
        directory = stat.S_ISDIR(node["st_mode"])
        expected = server.os.O_RDONLY | server.os.O_NOFOLLOW | server.os.O_CLOEXEC | server.os.O_NONBLOCK
        # Kernel open would reject a symlink; retain the flag assertion here.
        if flags & server.os.O_DIRECTORY:
            expected |= server.os.O_DIRECTORY
            self.assertTrue(directory)
        self.assertEqual(flags, expected)
        if stat.S_ISLNK(node["st_mode"]):
            raise OSError("unit nofollow")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.handles[fd] = (path, node)
        self.opens.append((path, fd, dir_fd))
        return fd

    def pread(self, fd, count, offset):
        path, node = self.handles[fd]
        self.reads.append((path, count, offset))
        self.assertTrue(0 < count <= 65536 and offset >= 0)
        return node["raw"][offset:offset + count]

    def label(self, fd, name):
        self.assertEqual(name, "security.selinux")
        self.assertIs(type(fd), int)
        self.labels.append(self.handles[fd][0])
        return self.handles[fd][1]["label"]

    def verity(self, fd, command, output, mutate):
        self.assertEqual((command, mutate), (0xc0046686, True))
        self.assertEqual(output, server.struct.pack("<HH", 0, 32) + b"\0" * 32)
        self.measures.append(self.handles[fd][0])
        output[:] = server.struct.pack("<HH", 1, 32) + self.handles[fd][1]["verity"]
        return 0

    def view(self, pins=None, page_size=4096):
        value = server._KernelCodeFiles(self.roots, self.pins if pins is None else pins, page_size)
        self.addCleanup(value.close)
        return value

    def maps(self, path="/opt/planeon/python", start=4096, end=8192, offset=0, permissions="r-xp"):
        node = self.nodes[path]
        return (f"{start:08x}-{end:08x} {permissions} {offset:08x} "
                f"{server.os.major(node['st_dev']):02x}:{server.os.minor(node['st_dev']):02x} "
                f"{node['st_ino']} {path}\n".encode()
                + b"00007000-00008000 r-xp 00000000 00:00 0 [vdso]\n")

    def loader(self):
        raw = bytearray(self.elf())
        server.struct.pack_into("<H", raw, 56, 3)
        value = b"/opt/planeon/loader\0"
        server.struct.pack_into("<IIQQQQQQ", raw, 176, 3, 4, 300, 0, 0, len(value), len(value), 1)
        raw[300:300 + len(value)] = value
        self.nodes["/opt/planeon/python"]["raw"] = bytes(raw)
        self.pins[0]["sha256"] = server.byte_digest(bytes(raw))
        self.add_file("/opt/planeon/loader", self.elf(), [dict(offset=0, length=4096, permissions="r-xp")])

    def test_retains_complete_ancestry_separate_measurements_and_fresh_reads(self):
        value = self.view()
        self.assertEqual(set(value.rows), {"/opt", "/opt/planeon", "/opt/planeon/python", "/opt/planeon/app"})
        count = len(self.reads)
        self.assertIsNone(value.check())
        self.assertEqual(len(self.reads), count * 2)
        self.assertEqual(len(self.measures), 8)
        self.assertEqual(len(self.labels), 8)
        self.assertIsNone(value.layouts["/opt/planeon/app"])
        value.close()
        self.assertFalse(self.roots.closed)
        self.assertEqual(set(self.handles), {r[0] for r in self.roots.rows})
        self.lib.syscall.assert_not_called()
        self.mapper.assert_not_called()

    def test_arm64_uses_same_fixed_file_interfaces_and_its_own_elf_architecture(self):
        self.roots.close()
        with patch.object(server.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
            self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        raw = self.elf("aarch64")
        self.nodes["/opt/planeon/python"]["raw"] = raw
        self.pins[0]["sha256"] = server.byte_digest(raw)
        self.assertIsNone(self.view().match_maps(self.maps(), self.auxv()))

    def test_closed_inventory_shapes_and_duplicate_paths_fail_before_file_io(self):
        for pins in ([], {}, self.pins * 65, self.pins * 2, [dict(self.pins[0], extra=1)],
                     [{k: v for k, v in self.pins[0].items() if k != "size"}]):
            with self.subTest(pins_type=type(pins)), self.assertRaises(ConformanceError):
                self.view(pins)
        self.assertEqual(self.reads, [])

    def test_noncanonical_paths_and_file_directory_overlap_are_rejected_before_io(self):
        for path in ("/", "relative", "/opt//x", "/opt/../x", "/opt/./x", "/opt/x (deleted)",
                     "/opt/é", "/" + "x/" * 65 + "x", "/" + "x" * 4096):
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.view([dict(self.pins[0], path=path)])
        with self.assertRaises(ConformanceError):
            self.view(self.pins + [dict(self.pins[0], path="/opt")])
        self.assertEqual(self.reads, [])

    def test_file_and_aggregate_bounds_and_distinct_digest_pins(self):
        for field, values in (("size", (True, 0, 67108865)), ("mode", ("0755", "04555", 555)),
                              ("selinuxLabel", ("", "x\n", "x" * 257)),
                              ("sha256", ("mutable", self.pins[0]["verityDigest"]))):
            for changed in values:
                with self.subTest(field=field, value=changed), self.assertRaises(ConformanceError):
                    self.view([dict(self.pins[0], **{field: changed})])
        with self.assertRaises(ConformanceError):
            self.view([dict(self.pins[0], path=f"/x{i}", size=67108864) for i in range(9)])
        self.assertEqual(self.reads, [])

    def test_bad_segment_pins_and_page_size_fail_closed(self):
        for segments in ({}, [dict(offset=True, length=4096, permissions="r-xp")],
                         [dict(offset=0, length=1, permissions="r-xp")],
                         [dict(offset=0, length=4096, permissions="r-wp")],
                         [dict(offset=0, length=4096, permissions="r-xp", extra=1)]):
            with self.assertRaises(ConformanceError):
                self.view([dict(self.pins[0], executableSegments=segments)])
        for size in (True, 8192, 0):
            with self.assertRaises(ConformanceError):
                self.view(page_size=size)

    def test_exact_root_owner_mode_size_and_single_link_are_required(self):
        node = self.nodes["/opt/planeon/python"]
        for key, value in (("st_uid", 10000), ("st_gid", 10000), ("st_mode", stat.S_IFREG | 0o755),
                           ("st_mode", stat.S_IFREG | 0o4555), ("st_nlink", 2), ("st_size", 8191)):
            original = node[key]
            node[key] = value
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                self.view()
            node[key] = original
            self.assertEqual(set(self.handles), {r[0] for r in self.roots.rows})

    def test_symlink_and_nonregular_leaf_are_not_followed(self):
        node = self.nodes["/opt/planeon/python"]
        for mode in (stat.S_IFLNK | 0o555, stat.S_IFIFO | 0o555):
            node["st_mode"] = mode
            with self.assertRaises((ConformanceError, OSError)):
                self.view()
        node["st_mode"] = stat.S_IFREG | 0o555
        self.assertEqual(self.reads, [])

    def test_writable_or_unowned_parent_is_refused(self):
        for key, value in (("st_uid", 1), ("st_gid", 1), ("st_mode", stat.S_IFDIR | 0o777)):
            original = self.nodes["/opt"][key]
            self.nodes["/opt"][key] = value
            with self.assertRaises(ConformanceError):
                self.view()
            self.nodes["/opt"][key] = original

    def test_hardlink_alias_even_with_claimed_single_link_is_refused(self):
        self.nodes["/opt/planeon/app"]["st_ino"] = self.nodes["/opt/planeon/python"]["st_ino"]
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_FILE_ALIAS"):
            self.view()

    def test_parent_or_leaf_named_substitution_is_sticky(self):
        for path in ("/opt", "/opt/planeon/python"):
            value = self.view()
            original = self.nodes[path]
            self.nodes[path] = dict(original, st_ino=9999)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_PATH_CHANGED"):
                value.check()
            self.nodes[path] = original
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_UNAVAILABLE"):
                value.check()
            value.close()

    def test_same_inode_mount_substitution_is_refused(self):
        value = self.view()
        original = self.nodes["/opt"]
        self.nodes["/opt"] = dict(original, mountId=999)
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_PATH_CHANGED"):
            value.check()
        self.nodes["/opt"] = original

    def test_content_digest_is_checked_even_when_verity_response_is_unchanged(self):
        value = self.view()
        node = self.nodes["/opt/planeon/python"]
        node["raw"] = node["raw"][:-1] + b"x"
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_DIGEST_CHANGED"):
            value.check()

    def test_verity_mismatch_or_missing_ioctl_never_falls_back_to_content_hash(self):
        for behavior in ("mismatch", "unavailable"):
            value = self.view()
            original = self.nodes["/opt/planeon/python"]["verity"]
            if behavior == "mismatch":
                self.nodes["/opt/planeon/python"]["verity"] = bytes(32)
                with self.assertRaises(ConformanceError):
                    value.check()
            else:
                with patch.object(server.fcntl, "ioctl", side_effect=OSError("unit unavailable")), self.assertRaises(OSError):
                    value.check()
            self.nodes["/opt/planeon/python"]["verity"] = original
            value.close()

    def test_file_labels_are_exact_and_missing_labels_do_not_fall_back(self):
        node = self.nodes["/opt/planeon/python"]
        for label in (b"other", b"system_u:object_r:code_t:s0\0\0", "system_u:object_r:code_t:s0"):
            original, node["label"] = node["label"], label
            with self.assertRaises(ConformanceError):
                self.view()
            node["label"] = original
        with patch.object(server.os, "getxattr", side_effect=OSError("unit missing label")), self.assertRaises(OSError):
            self.view()
        node["label"] = node["label"][:-1]
        self.assertIsNone(self.view().check())

    def test_short_chunk_reads_are_complete_and_offset_based(self):
        def short(fd, count, offset):
            return self.pread(fd, min(count, 101), offset)
        with patch.object(server.os, "pread", side_effect=short):
            self.assertIsNone(self.view().check())
        self.assertGreater(len(self.reads), 100)

    def test_truncation_growth_wrong_types_and_oversize_read_results_are_rejected(self):
        for reader in (lambda fd, n, off: b"", lambda fd, n, off: b"x" * (n + 1),
                       lambda fd, n, off: bytearray(n), lambda fd, n, off: self.pread(fd, n, off) or b"x"):
            with patch.object(server.os, "pread", side_effect=reader), self.assertRaises(ConformanceError):
                self.view()

    def test_metadata_label_or_named_path_change_during_read_is_detected(self):
        for kind in ("metadata", "label", "path"):
            original = deepcopy(self.nodes["/opt/planeon/python"])
            def change(fd, count, offset):
                raw = self.pread(fd, count, offset)
                if self.handles[fd][0] == "/opt/planeon/python":
                    if kind == "metadata":
                        self.nodes["/opt/planeon/python"]["st_ctime_ns"] += 1
                    elif kind == "label":
                        self.nodes["/opt/planeon/python"]["label"] = b"changed"
                    else:
                        self.nodes["/opt/planeon/python"] = dict(original, st_ino=9001)
                return raw
            with patch.object(server.os, "pread", side_effect=change), self.assertRaises(ConformanceError):
                self.view()
            self.nodes["/opt/planeon/python"] = original

    def test_one_phase_budget_covers_all_reads_and_does_not_restart_per_chunk(self):
        value = self.view()
        def slow(fd, n, off):
            self.now += 0.75
            return self.pread(fd, n, off)
        with patch.object(server.os, "pread", side_effect=slow), self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_DEADLINE"):
            value.check()
        self.assertTrue(value.failed)

    def test_late_open_retains_and_closes_the_new_descriptor(self):
        retained = set(self.handles)
        def late(*args, **kwargs):
            fd = self.open_fd(*args, **kwargs)
            if self.handles[fd][0] == "/opt/planeon/app":
                self.now += 2
            return fd
        with patch.object(server.os, "open", side_effect=late), self.assertRaises(ConformanceError):
            self.view()
        self.assertEqual(set(self.handles), retained)

    def test_clock_rollback_process_and_thread_changes_are_not_reacquired(self):
        for kind in ("clock", "pid", "thread"):
            value = self.view()
            with ExitStack() as stack:
                if kind == "clock":
                    self.now -= 1
                elif kind == "pid":
                    stack.enter_context(patch.object(server.os, "getpid", return_value=412))
                else:
                    stack.enter_context(patch.object(server.threading, "get_ident", return_value=722))
                with self.assertRaises(ConformanceError):
                    value.check()
            if kind == "clock":
                self.now += 1
            value.close()

    def test_closed_or_failed_owner_never_grants_custody(self):
        value = self.view()
        value.close()
        with self.assertRaises(ConformanceError):
            value.check()
        self.roots.close()
        with self.assertRaises(ConformanceError):
            self.view()

    def test_expected_inventory_is_detached_from_caller_mutation(self):
        pins = deepcopy(self.pins)
        value = self.view(pins)
        pins[0]["sha256"] = "sha256:" + "0" * 64
        pins[0]["executableSegments"][0]["length"] = 8192
        self.assertIsNone(value.check())

    def test_loader_must_be_enrolled_actual_elf_not_an_archive(self):
        self.loader()
        self.assertIsNone(self.view().check())
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_LOADER_NOT_ENROLLED"):
            self.view(self.pins[:-1])
        self.nodes["/opt/planeon/loader"]["raw"] = b"P" * 8192
        self.pins[-1]["sha256"] = server.byte_digest(b"P" * 8192)
        self.pins[-1]["executableSegments"] = []
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_LOADER_NOT_ENROLLED"):
            self.view()

    def test_executable_segment_pins_must_match_actual_file_and_not_hide_elf(self):
        for segments in ([], [dict(offset=4096, length=4096, permissions="r-xp")],
                         [dict(offset=0, length=4096, permissions="--xp")]):
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_ELF_PIN"):
                self.view([dict(self.pins[0], executableSegments=segments), self.pins[1]])
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_ELF_PIN"):
            self.view([self.pins[0], dict(self.pins[1], executableSegments=self.pins[0]["executableSegments"])])

    def test_mapping_match_is_data_only_and_allows_observed_pie_bias(self):
        value = self.view()
        for start in (4096, 12288):
            self.assertIsNone(value.match_maps(self.maps(start=start, end=start + 4096), self.auxv()))
        self.assertIsNone(value.match_maps(self.maps().replace(b"00007000", b"00009000").replace(b"00008000", b"0000a000"),
                                          self.auxv(36864)))

    def test_mapping_path_device_inode_and_permissions_are_closed(self):
        raw = self.maps()
        for changed in (raw.replace(b"/opt/planeon/python", b"/unknown"), raw.replace(b"00:0a", b"08:01"),
                        raw.replace(f" {self.nodes['/opt/planeon/python']['st_ino']} ".encode(), b" 999 "),
                        raw.replace(b"r-xp", b"r-xs", 1), raw.replace(b"r-xp", b"rwxp", 1)):
            value = self.view()
            with self.assertRaises(ConformanceError):
                value.match_maps(changed, self.auxv())
            value.close()

    def test_shared_mapping_selection_is_pinned_separately_from_elf_rwx_flags(self):
        for permissions, elf_flags in (("r-xs", 5), ("--xs", 1)):
            raw = bytearray(self.elf())
            server.struct.pack_into("<I", raw, 68, elf_flags)
            self.nodes["/opt/planeon/python"]["raw"] = bytes(raw)
            self.pins[0]["sha256"] = server.byte_digest(bytes(raw))
            self.pins[0]["executableSegments"][0]["permissions"] = permissions
            value = self.view()
            self.assertIsNone(value.match_maps(self.maps(permissions=permissions), self.auxv()))
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_LAYOUT"):
                value.match_maps(self.maps(permissions=permissions[:3] + "p"), self.auxv())
            value.close()

    def test_mapping_missing_extra_or_oversize_segments_are_refused(self):
        for changed in (self.maps(offset=4096), self.maps(end=12288),
                        self.maps().splitlines(keepends=True)[0] + self.maps(start=12288, end=16384)):
            value = self.view()
            with self.assertRaises(ConformanceError):
                value.match_maps(changed, self.auxv())
            value.close()

    def test_mapping_cannot_execute_an_enrolled_archive(self):
        value = self.view()
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_UNENROLLED"):
            value.match_maps(self.maps(path="/opt/planeon/app"), self.auxv())

    def test_mapping_static_executable_cannot_claim_pie_bias(self):
        raw = bytearray(self.nodes["/opt/planeon/python"]["raw"])
        server.struct.pack_into("<H", raw, 16, 2)
        self.nodes["/opt/planeon/python"]["raw"] = bytes(raw)
        self.pins[0]["sha256"] = server.byte_digest(bytes(raw))
        value = self.view()
        self.assertIsNone(value.match_maps(self.maps(), self.auxv()))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_LAYOUT"):
            value.match_maps(self.maps(start=12288, end=16384), self.auxv())

    def test_mapping_requires_enrolled_loader_to_be_mapped_too(self):
        self.loader()
        value = self.view()
        mapped = self.maps().splitlines(keepends=True)[0] + self.maps(path="/opt/planeon/loader", start=12288, end=16384)
        self.assertIsNone(value.match_maps(mapped, self.auxv()))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_LOADER_MISSING"):
            value.match_maps(self.maps(), self.auxv())

    def test_split_mapping_must_cover_the_complete_segment_at_one_bias(self):
        raw = bytearray(self.elf())
        server.struct.pack_into("<H", raw, 56, 1)
        server.struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 4096, 0, 8192, 8192, 4096)
        self.nodes["/opt/planeon/python"]["raw"] = bytes(raw)
        self.pins[0]["sha256"] = server.byte_digest(bytes(raw))
        self.pins[0]["executableSegments"][0]["length"] = 8192
        value = self.view()
        first = self.maps().splitlines(keepends=True)[0]
        self.assertIsNone(value.match_maps(first + self.maps(start=8192, end=12288, offset=4096), self.auxv()))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_LAYOUT"):
            value.match_maps(first + self.maps(start=12288, end=16384, offset=4096), self.auxv())

    def test_multiple_executable_segments_require_complete_consistent_address_bias(self):
        raw = bytearray(self.elf())
        server.struct.pack_into("<I", raw, 124, 5)
        self.nodes["/opt/planeon/python"]["raw"] = bytes(raw)
        self.pins[0]["sha256"] = server.byte_digest(bytes(raw))
        self.pins[0]["executableSegments"].append(dict(offset=4096, length=4096, permissions="r-xp"))
        value = self.view()
        first = self.maps().splitlines(keepends=True)[0]
        self.assertIsNone(value.match_maps(first + self.maps(start=12288, end=16384, offset=4096), self.auxv()))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_SEGMENT_COVERAGE"):
            value.match_maps(self.maps(), self.auxv())
        value.close()
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_MAP_LAYOUT"):
            self.view().match_maps(first + self.maps(start=16384, end=20480, offset=4096), self.auxv())

    def test_partial_acquisition_failure_closes_owned_fds_but_not_roots(self):
        retained = set(self.handles)
        def denied(*args, **kwargs):
            if args[0] == "app":
                raise PermissionError("unit denied")
            return self.open_fd(*args, **kwargs)
        with patch.object(server.os, "open", side_effect=denied), self.assertRaises(PermissionError):
            self.view()
        self.assertEqual(set(self.handles), retained)

    def test_uncertain_close_is_sticky_and_never_retried(self):
        value = server._KernelCodeFiles(self.roots, self.pins, 4096)
        target = value.rows["/opt/planeon/app"][0]
        def uncertain(fd):
            self.close_fd(fd)
            if fd == target:
                raise OSError("unit ambiguous close")
        with patch.object(server.os, "close", side_effect=uncertain), self.assertRaises(OSError):
            value.close()
        for _ in range(2):
            with self.assertRaises(OSError):
                value.close()
        self.assertEqual(self.closed.count(target), 1)
        self.assertEqual(set(self.handles), {r[0] for r in self.roots.rows})

    def test_recycled_fd_is_not_closed_as_if_still_owned(self):
        value = server._KernelCodeFiles(self.roots, self.pins, 4096)
        target = value.rows["/opt/planeon/app"][0]
        original = self.handles[target]
        self.handles[target] = ("/replacement", dict(original[1], st_ino=9999))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CODE_FD_REUSED"):
            value.close()
        self.assertNotIn(target, self.closed)
        self.handles[target] = original
        self.close_fd(target)  # mock owner retires its simulated replacement


class KernelProcessCodeTests(unittest.TestCase):
    """Original proc/root/code factories; only kernel edges use synthetic data."""
    stat_fd = KernelRootCustodyTests.stat_fd
    statfs = KernelRootCustodyTests.statfs
    statx = KernelRootCustodyTests.statx
    close_fd = KernelRootCustodyTests.close_fd
    allocate = KernelProcessCustodyTests.allocate
    pidfd_open = KernelProcessCustodyTests.pidfd_open
    poll_pid = KernelProcessCustodyTests.poll_pid
    named_stat = KernelProcessCustodyTests.named_stat
    namespace_type = KernelProcessCustodyTests.namespace_type
    read = KernelProcessCustodyTests.read
    scandir = KernelProcessCustodyTests.scandir
    close_views = KernelProcessCustodyTests.close_views
    process_stat = KernelProcessCustodyTests.process_stat
    process_status = KernelProcessCustodyTests.process_status
    elf = KernelInputCodecTests.elf
    auxv = KernelInputCodecTests.auxv
    add_file = KernelCodeCustodyTests.add_file
    label = KernelCodeCustodyTests.label
    verity = KernelCodeCustodyTests.verity

    def setUp(self):
        KernelProcessCustodyTests.setUp(self)
        self.roles = deepcopy(sample()["record"]["roles"])
        self.pins, self.reads, self.labels, self.measures, self.proc_reads = [], [], [], [], []
        self.python = "/opt/planeon/python/3.12.14/bin/python3.12"
        for path in ("/opt", "/opt/planeon", "/opt/planeon/bin", "/opt/planeon/python",
                     "/opt/planeon/python/3.12.14", "/opt/planeon/python/3.12.14/bin"):
            self.nodes[path] = dict(self.nodes["/"], st_ino=500 + len(self.nodes))
        segment = [dict(offset=0, length=4096, permissions="r-xp")]
        self.add_file(self.python, self.elf(), deepcopy(segment))
        for role, expected in self.roles.items():
            raw = b"PK\x03\x04unit-only archive " + role.encode() if expected["interpreterPath"] else self.elf()
            self.add_file(expected["executable"], raw, [] if expected["interpreterPath"] else deepcopy(segment))
            expected["artifactDigest"] = server.byte_digest(raw)
            expected["filePaths"] = [expected["executable"]] + ([self.python] if expected["interpreterPath"] else [])
        for index, name in enumerate(("maps", "auxv", "cmdline")):
            self.nodes["/proc/411/" + name] = dict(self.nodes["/proc/411/status"], st_ino=700 + index)
        self.links["/proc/411/exe"] = dict(self.nodes["/proc"], st_ino=799, st_mode=stat.S_IFLNK | 0o777)
        self.stack.enter_context(patch.object(server.os, "pread", side_effect=self.pread))
        self.stack.enter_context(patch.object(server.os, "getxattr", side_effect=self.label, create=True))
        self.stack.enter_context(patch.object(server.os, "readlink", side_effect=self.readlink))
        self.stack.enter_context(patch.object(server.os, "sysconf", return_value=4096))
        self.stack.enter_context(patch.object(server.fcntl, "ioctl", side_effect=self.query))
        self.configure("SERVER")

    def configure(self, role):
        self.role, self.expected = role, deepcopy(self.roles[role])
        uid, gid = self.expected["uid"], self.expected["gid"]
        self.status_raw = self.process_status(Uid=" ".join([str(uid)] * 4), Gid=" ".join([str(gid)] * 4))
        group = {"SERVER": "proxy-server", "OBSERVER": "policy-observer", "BROKER": "capacity-broker", "WORKER": "probe-worker"}[role]
        self.cgroup_raw = ("0::/planeon-live/" + group + "\n").encode()
        self.label_raw = self.expected["processLabel"].encode() + b"\0"
        for path, node in self.nodes.items():
            if path.startswith("/proc/411") and path != "/proc/411/exe":
                node["st_uid"], node["st_gid"] = uid, gid
        for path, node in self.links.items():
            node["st_uid"], node["st_gid"] = uid, gid
            if path != "/proc/411/exe":
                self.nodes[path]["st_ino"] = self.expected["namespaceInodes"][path.rsplit("/", 1)[1]]
        self.native = self.expected["interpreterPath"] or self.expected["executable"]
        self.nodes["/proc/411/exe"] = self.nodes[self.native]
        self.exe_target = self.native
        argv = [self.native, self.expected["executable"]] if self.expected["interpreterPath"] else [self.native]
        self.proc_data = dict(auxv=self.auxv(), maps=self.maps(), cmdline=b"\0".join(p.encode() for p in argv) + b"\0")

    def open_fd(self, name, flags, *, dir_fd):
        if name == "exe":
            self.assertEqual(self.handles[dir_fd][0], "/proc/411")
            self.assertEqual(flags, server.os.O_RDONLY | server.os.O_CLOEXEC | server.os.O_NONBLOCK)
            return self.allocate("/proc/411/exe", dir_fd)
        return KernelProcessCustodyTests.open_fd(self, name, flags, dir_fd=dir_fd)

    def query(self, fd, command, *args):
        if command == 0xb703:
            return self.namespace_type(fd, command, *args)
        return self.verity(fd, command, *args)

    def pread(self, fd, count, offset):
        path = self.handles[fd][0]
        if path.startswith("/proc/411/"):
            name = path.rsplit("/", 1)[1]
            self.assertIn(name, ("maps", "auxv", "cmdline"))
            self.assertTrue(0 < count <= 4096 and offset >= 0)
            self.proc_reads.append((name, fd, offset, count))
            return self.proc_data[name][offset:offset + count]
        return KernelCodeCustodyTests.pread(self, fd, count, offset)

    def readlink(self, name, *, dir_fd):
        self.assertEqual((name, self.handles[dir_fd][0]), ("exe", "/proc/411"))
        return self.exe_target

    def maps(self, start=4096, path=None):
        path = self.native if path is None else path
        node = self.nodes[path]
        return (f"{start:08x}-{start + 4096:08x} r-xp 00000000 "
                f"{server.os.major(node['st_dev']):02x}:{server.os.minor(node['st_dev']):02x} "
                f"{node['st_ino']} {path}\n".encode()
                + b"00007000-00008000 r-xp 00000000 00:00 0 [vdso]\n")

    def components(self):
        process = KernelProcessCustodyTests.view(self, self.role, self.expected)
        code = server._KernelCodeFiles(self.roots, self.pins, 4096)
        self.addCleanup(code.close)
        pins = {k: self.expected[k] for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")}
        return process, code, pins

    def fresh(self):
        value = server._KernelProcessCode(*self.components())
        self.addCleanup(value.close)
        return value

    def test_actual_factories_retain_four_interfaces_and_never_accept_map_input(self):
        value = self.fresh()
        self.assertEqual(set(value.rows), {"exe", "maps", "auxv", "cmdline"})
        self.assertIsNone(value.check())
        self.assertEqual(len([r for r in self.proc_reads if r[0] == "maps" and r[2] == 0]), 4)
        self.assertEqual({r[1] for r in self.proc_reads}, {value.rows[n][0] for n in ("maps", "auxv", "cmdline")})
        self.assertEqual(value.original["maps"]["files"][0]["path"], self.python)
        with self.assertRaises(TypeError):
            value.check(maps=self.maps())
        self.mapper.assert_not_called()
        self.lib.syscall.assert_not_called()

    def test_native_observer_and_broker_bind_their_own_executable(self):
        for role in ("OBSERVER", "BROKER"):
            self.configure(role)
            value = self.fresh()
            self.assertIsNone(value.check())
            self.assertEqual(value.native, self.roles[role]["executable"])
            value.close()
            value.process.close()
            value.code.close()

    def test_worker_uses_its_enrolled_uid_and_fixed_python_archive(self):
        self.configure("WORKER")
        value = self.fresh()
        self.assertGreaterEqual(value.process.pin[0], 10000)
        self.assertIsNone(value.check())

    def test_arm64_process_reads_bind_arm64_elf_without_emulation(self):
        self.roots.close()
        with patch.object(server.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
            self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        for entry in self.pins:
            node = self.nodes[entry["path"]]
            if entry["executableSegments"]:
                node["raw"] = self.elf("aarch64")
                entry["sha256"] = server.byte_digest(node["raw"])
        self.assertIsNone(self.fresh().check())

    def test_unknown_role_paths_artifact_or_inventory_are_rejected_before_proc_io(self):
        process, code, pins = self.components()
        variants = [dict(pins, extra=True), dict(pins, executable="/unknown"), dict(pins, interpreterPath=None),
                    dict(pins, artifactDigest="sha256:" + "0" * 64), dict(pins, filePaths=[]),
                    dict(pins, filePaths=pins["filePaths"] * 2), dict(pins, filePaths=[self.python]),
                    dict(pins, filePaths=[pins["executable"], "/unknown"])]
        for variant in variants:
            with self.assertRaises(ConformanceError):
                server._KernelProcessCode(process, code, variant)
        self.assertEqual(self.proc_reads, [])

    def test_copied_owners_and_mixed_roots_are_refused(self):
        process, code, pins = self.components()
        for other in (None, {}, SimpleNamespace(**process.__dict__)):
            with self.assertRaises(ConformanceError):
                server._KernelProcessCode(other, code, pins)
        roots = server._KernelRootViews()
        self.addCleanup(roots.close)
        other_code = server._KernelCodeFiles(roots, self.pins, 4096)
        self.addCleanup(other_code.close)
        with self.assertRaises(ConformanceError):
            server._KernelProcessCode(process, other_code, pins)

    def test_expected_data_is_detached_and_original_process_is_borrowed(self):
        process, code, pins = self.components()
        value = server._KernelProcessCode(process, code, pins)
        self.addCleanup(value.close)
        pins["filePaths"].clear()
        self.assertIsNone(value.check())
        value.close()
        self.assertFalse(process.closed or code.closed or self.roots.closed)

    def test_exe_magic_link_target_must_be_exact_and_never_opened_as_a_path(self):
        for path in (self.python + " (deleted)", "/unknown", "/opt/../python", self.python.encode()):
            self.exe_target = path
            with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_EXE_LINK"):
                self.fresh()
        self.exe_target = self.python
        self.assertFalse(any(p == "/unknown" for p, *_ in self.opens))

    def test_exe_link_owner_type_and_named_identity_must_stay_original(self):
        value = self.fresh()
        self.links["/proc/411/exe"]["st_uid"] = 17
        with self.assertRaises(ConformanceError):
            value.check()

    def test_exe_descriptor_cannot_reference_different_inode_or_mount(self):
        original = self.nodes["/proc/411/exe"]
        for change in (dict(st_ino=9999), dict(mountId=9999)):
            process, code, pins = self.components()
            self.nodes["/proc/411/exe"] = dict(original, **change)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_EXE_CHANGED"):
                server._KernelProcessCode(process, code, pins)
            self.nodes["/proc/411/exe"] = original

    def test_deleted_executable_link_count_cannot_be_hidden_by_matching_bytes(self):
        value = self.fresh()
        self.nodes[self.python]["st_nlink"] = 0
        with self.assertRaises(ConformanceError):
            value.check()

    def test_named_proc_file_and_mount_replacements_are_refused(self):
        for name, change in (("maps", dict(st_ino=8888)), ("auxv", dict(mountId=8888)),
                             ("cmdline", dict(st_uid=123))):
            value = self.fresh()
            path = "/proc/411/" + name
            original = self.nodes[path]
            self.nodes[path] = dict(original, **change)
            with self.assertRaises(ConformanceError):
                value.check()
            self.nodes[path] = original
            value.close()

    def test_fixed_command_line_has_no_user_arguments_or_alternate_archive(self):
        original = self.proc_data["cmdline"]
        for raw in (b"", original[:-1], original + b"--unsafe\0", original.replace(b"proxy-serve", b"other-entry")):
            self.proc_data["cmdline"] = raw
            with self.assertRaises(ConformanceError):
                self.fresh()
        self.proc_data["cmdline"] = original

    def test_mapping_inode_permission_and_unenrolled_code_are_rejected(self):
        raw = self.maps()
        for changed in (raw.replace(b"00:0a", b"08:01"), raw.replace(b"r-xp", b"rwxp", 1),
                        raw.replace(self.python.encode(), b"/unknown")):
            self.proc_data["maps"] = changed
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_role_cannot_use_another_globally_enrolled_executable(self):
        self.proc_data["maps"] = self.maps(path=self.roles["BROKER"]["executable"])
        with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_MAPPING_INVENTORY"):
            self.fresh()

    def test_all_role_executable_dependencies_must_be_mapped(self):
        self.expected["filePaths"].append(self.roles["BROKER"]["executable"])
        with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_MAPPING_INVENTORY"):
            self.fresh()

    def test_two_fresh_maps_reject_between_read_changes(self):
        process, code, pins = self.components()
        reads = 0
        def changed(fd, n, off):
            nonlocal reads
            if self.handles[fd][0] == "/proc/411/maps" and off == 0:
                reads += 1
                if reads == 2:
                    self.proc_data["maps"] = self.maps(start=12288)
            return self.pread(fd, n, off)
        with patch.object(server.os, "pread", side_effect=changed), self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_MAPPING_CHANGED"):
            server._KernelProcessCode(process, code, pins)
        self.assertEqual(reads, 2)

    def test_retained_aslr_and_auxv_cannot_change_between_checks(self):
        value = self.fresh()
        self.proc_data["maps"] = self.maps(start=12288)
        with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_MAPPING_CHANGED"):
            value.check()
        self.proc_data["maps"] = self.maps()
        with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_UNAVAILABLE"):
            value.check()

    def test_auxv_change_is_detected_even_when_executable_maps_match(self):
        value = self.fresh()
        self.proc_data["auxv"] = self.auxv()[:-16] + server.struct.pack("<4Q", 25, 123456, 0, 0)
        with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_MAPPING_CHANGED"):
            value.check()

    def test_normal_nonexecutable_heap_changes_do_not_become_code_drift(self):
        value = self.fresh()
        lines = self.maps().splitlines(keepends=True)
        self.proc_data["maps"] = lines[0] + b"00003000-00005000 rw-p 00000000 00:00 0 [heap]\n" + lines[1]
        self.assertIsNone(value.check())

    def test_native_page_size_and_actual_auxv_vdso_must_agree(self):
        value = self.fresh()
        with patch.object(server.os, "sysconf", return_value=16384), self.assertRaises(ConformanceError):
            value.check()
        self.proc_data["auxv"] = self.auxv(36864)
        with self.assertRaises(ConformanceError):
            self.fresh()

    def test_partial_short_reads_use_retained_offsets_and_complete_eof(self):
        def short(fd, n, off):
            if self.handles[fd][0] in ("/proc/411/maps", "/proc/411/auxv", "/proc/411/cmdline"):
                return self.pread(fd, min(n, 17), off)
            return self.pread(fd, n, off)
        with patch.object(server.os, "pread", side_effect=short):
            self.assertIsNone(self.fresh().check())
        self.assertGreater(len(self.proc_reads), 40)

    def test_oversize_truncated_and_wrong_type_proc_reads_fail_closed(self):
        for name, raw in (("maps", self.maps()[:-1]), ("auxv", b"\0" * 15), ("cmdline", b"x" * 8193)):
            original = self.proc_data[name]
            self.proc_data[name] = raw
            with self.assertRaises(ConformanceError):
                self.fresh()
            self.proc_data[name] = original
        process, code, pins = self.components()
        def wrong(fd, n, off):
            return bytearray(n) if self.handles[fd][0] == "/proc/411/maps" else self.pread(fd, n, off)
        with patch.object(server.os, "pread", side_effect=wrong), self.assertRaises(ConformanceError):
            server._KernelProcessCode(process, code, pins)

    def test_process_death_during_a_read_prevents_returning_an_observation(self):
        value = self.fresh()
        def die(fd, n, off):
            raw = self.pread(fd, n, off)
            if self.handles[fd][0] == "/proc/411/maps":
                self.dead = True
            return raw
        with patch.object(server.os, "pread", side_effect=die), self.assertRaises(ConformanceError):
            value.check()

    def test_one_whole_budget_includes_all_proc_reads_and_code_checks(self):
        value = self.fresh()
        def slow(fd, n, off):
            if self.handles[fd][0] == "/proc/411/auxv":
                self.now += 0.6
            return self.pread(fd, n, off)
        with patch.object(server.os, "pread", side_effect=slow), self.assertRaises(ConformanceError):
            value.check()
        self.assertTrue(value.failed)

    def test_clock_rollback_cannot_restart_a_phase(self):
        value = self.fresh()
        self.now -= 1
        with self.assertRaises(ConformanceError):
            value.check()
        self.now += 1
        with self.assertRaises(ConformanceError):
            value.check()

    def test_inspector_process_change_is_refused(self):
        value = self.fresh()
        with patch.object(server.os, "getpid", return_value=412), self.assertRaises(ConformanceError):
            value.check()

    def test_inspector_thread_change_is_refused(self):
        value = self.fresh()
        with patch.object(server.threading, "get_ident", return_value=722), self.assertRaises(ConformanceError):
            value.check()

    def test_start_identity_change_during_maps_read_is_detected_before_return(self):
        value = self.fresh()
        def changed(fd, n, off):
            raw = self.pread(fd, n, off)
            if self.handles[fd][0] == "/proc/411/maps":
                self.stat_raw = self.process_stat(**{"19": "1000"})
            return raw
        with patch.object(server.os, "pread", side_effect=changed), self.assertRaises(ConformanceError):
            value.check()

    def test_failed_partial_acquisition_closes_only_newly_owned_descriptors(self):
        process, code, pins = self.components()
        retained = set(self.handles)
        def denied(name, *args, **kwargs):
            if name == "cmdline":
                raise PermissionError("unit denied")
            return self.open_fd(name, *args, **kwargs)
        with patch.object(server.os, "open", side_effect=denied), self.assertRaises(PermissionError):
            server._KernelProcessCode(process, code, pins)
        self.assertEqual(set(self.handles), retained)

    def test_late_exe_open_is_owned_before_deadline_check_and_cleaned_once(self):
        process, code, pins = self.components()
        retained = set(self.handles)
        def late(name, *args, **kwargs):
            fd = self.open_fd(name, *args, **kwargs)
            if name == "exe":
                self.now += 2
            return fd
        with patch.object(server.os, "open", side_effect=late), self.assertRaises(ConformanceError):
            server._KernelProcessCode(process, code, pins)
        self.assertEqual(set(self.handles), retained)

    def test_uncertain_close_is_sticky_without_closing_borrowed_owners(self):
        process, code, pins = self.components()
        value = server._KernelProcessCode(process, code, pins)
        target = value.rows["cmdline"][0]
        def uncertain(fd):
            self.close_fd(fd)
            if fd == target:
                raise OSError("unit uncertain close")
        with patch.object(server.os, "close", side_effect=uncertain), self.assertRaises(OSError):
            value.close()
        with self.assertRaises(OSError):
            value.close()
        self.assertEqual(self.closed.count(target), 1)
        self.assertFalse(process.closed or code.closed)

    def test_recycled_descriptor_is_not_closed_as_the_original(self):
        process, code, pins = self.components()
        value = server._KernelProcessCode(process, code, pins)
        target = value.rows["maps"][0]
        original = self.handles[target]
        self.handles[target] = ("/replacement", dict(original[1], st_ino=9999))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_PROCESS_CODE_FD_REUSED"):
            value.close()
        self.assertNotIn(target, self.closed)
        self.handles[target] = original
        self.close_fd(target)


class KernelCgroupCustodyTests(unittest.TestCase):
    """Production process/root/cgroup factories with independent OS-edge data."""
    stat_fd = KernelRootCustodyTests.stat_fd
    statfs = KernelRootCustodyTests.statfs
    statx = KernelRootCustodyTests.statx
    close_fd = KernelRootCustodyTests.close_fd
    allocate = KernelProcessCustodyTests.allocate
    pidfd_open = KernelProcessCustodyTests.pidfd_open
    poll_pid = KernelProcessCustodyTests.poll_pid
    named_stat = KernelProcessCustodyTests.named_stat
    namespace_type = KernelProcessCustodyTests.namespace_type
    scandir = KernelProcessCustodyTests.scandir
    close_views = KernelProcessCustodyTests.close_views
    process_stat = KernelProcessCustodyTests.process_stat
    process_status = KernelProcessCustodyTests.process_status

    def setUp(self):
        self.contents, self.snapshots, self.reads = {}, {}, []
        KernelProcessCustodyTests.setUp(self)
        self.role = "SERVER"
        self.configure(self.role)
        for name in ("write", "mkdir", "rmdir", "execve"):
            self.stack.enter_context(patch.object(server.os, name, side_effect=AssertionError("no cgroup mutation or execution")))

    def configure(self, role):
        self.role = role
        self.expected = deepcopy(sample()["record"]["roles"][role])
        uid, gid = self.expected["uid"], self.expected["gid"]
        self.status_raw = self.process_status(Uid=" ".join([str(uid)] * 4), Gid=" ".join([str(gid)] * 4))
        self.label_raw = self.expected["processLabel"].encode() + b"\0"
        self.group = self.expected["cgroup"]["path"]
        self.cgroup_raw = ("0::" + self.group.removeprefix("/sys/fs/cgroup") + "\n").encode()
        for path, node in self.nodes.items():
            if path.startswith("/proc/411"):
                node["st_uid"], node["st_gid"] = uid, gid
        for path, node in self.links.items():
            node["st_uid"], node["st_gid"] = uid, gid
            self.nodes[path]["st_ino"] = self.expected["namespaceInodes"][path.rsplit("/", 1)[1]]
        root = self.nodes["/sys/fs/cgroup"]
        self.nodes["/sys/fs/cgroup/planeon-live"] = dict(root, st_ino=899)
        self.nodes[self.group] = dict(root, st_ino=self.expected["cgroup"]["inode"])
        for index, name in enumerate(("memory.max", "pids.max", "cpu.max", "cgroup.procs")):
            self.nodes[self.group + "/" + name] = dict(root, st_ino=900 + index, st_mode=stat.S_IFREG | 0o644)
        pins = self.expected["cgroup"]
        self.contents = {self.group + "/memory.max": (str(pins["memoryMaxBytes"]) + "\n").encode(),
                         self.group + "/pids.max": (str(pins["pidsMax"]) + "\n").encode(),
                         self.group + "/cpu.max": (str(pins["cpuQuotaMicros"]) + " " + str(pins["cpuPeriodMicros"]) + "\n").encode(),
                         self.group + "/cgroup.procs": b"411\n"}

    def open_fd(self, name, flags, *, dir_fd):
        fd = KernelProcessCustodyTests.open_fd(self, name, flags, dir_fd=dir_fd)
        path = self.handles[fd][0]
        if path in self.contents:
            self.snapshots[fd] = self.contents[path]
        return fd

    def read(self, fd, count):
        path = self.handles[fd][0]
        if path not in self.contents:
            return KernelProcessCustodyTests.read(self, fd, count)
        self.assertTrue(0 < count <= 4096)
        self.reads.append((path, fd, self.offsets[fd], count))
        raw = self.snapshots[fd][self.offsets[fd]:self.offsets[fd] + count]
        self.offsets[fd] += len(raw)
        return raw

    def process(self):
        return KernelProcessCustodyTests.view(self, self.role, self.expected)

    def fresh(self):
        value = server._KernelCgroupView(self.process(), self.expected["cgroup"])
        self.addCleanup(value.close)
        return value

    def test_real_factories_retain_original_cgroup_and_fresh_open_each_control(self):
        value = self.fresh()
        self.assertEqual(len(value.rows), 6)
        self.assertEqual(self.handles[value.rows[1][0]][0], self.group)
        self.assertIsNone(value.check())
        reads = [r for r in self.reads if r[0].endswith("/memory.max") and r[2] == 0]
        self.assertEqual(len(reads), 4)
        self.assertEqual(len({r[1] for r in reads}), 4)
        self.assertFalse({r[1] for r in self.reads} & {r[0] for r in value.rows})
        self.mapper.assert_not_called()
        self.lib.syscall.assert_not_called()

    def test_each_role_uses_its_fixed_existing_group_and_worker_stays_nonroot(self):
        for role in ("OBSERVER", "BROKER", "WORKER"):
            self.configure(role)
            value = self.fresh()
            self.assertIsNone(value.check())
            self.assertEqual(value.expected["path"], self.group)
            if role == "WORKER":
                self.assertGreaterEqual(value.process.pin[0], 10000)
            value.close()
            value.process.close()

    def test_arm64_uses_the_same_readonly_cgroup_contract_without_native_execution(self):
        self.roots.close()
        with patch.object(server.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
            self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        self.assertIsNone(self.fresh().check())
        self.lib.syscall.assert_not_called()

    def test_closed_pins_reject_wrong_roles_unknown_fields_and_invalid_numbers(self):
        process = self.process()
        pins = self.expected["cgroup"]
        cases = [dict(pins, path="/sys/fs/cgroup/planeon-live/probe-worker"), dict(pins, extra=True),
                 {k: v for k, v in pins.items() if k != "inode"}]
        cases += [dict(pins, **{key: value}) for key, value in (("inode", True), ("inode", 0),
                  ("inode", 9007199254740992), ("memoryMaxBytes", "1048576"), ("memoryMaxBytes", 1048575),
                  ("memoryMaxBytes", 1099511627777), ("pidsMax", 0), ("pidsMax", 4097),
                  ("cpuQuotaMicros", 999), ("cpuQuotaMicros", 1000001), ("cpuPeriodMicros", 999),
                  ("cpuPeriodMicros", 1000001))]
        opened = len(self.opens)
        for pins in cases:
            with self.assertRaises(ConformanceError):
                server._KernelCgroupView(process, pins)
        self.assertEqual(len(self.opens), opened)

    def test_copied_or_failed_owner_and_caller_backend_are_not_admitted(self):
        process = self.process()
        for owner in (None, {}, SimpleNamespace(**process.__dict__)):
            with self.assertRaises(ConformanceError):
                server._KernelCgroupView(owner, self.expected["cgroup"])
        for extra in ({"path": "/tmp"}, {"fd": 3}, {"backend": Mock()}, {"qualified": True}):
            with self.assertRaises(TypeError):
                server._KernelCgroupView(process, self.expected["cgroup"], **extra)
        process.close()
        with self.assertRaises(ConformanceError):
            server._KernelCgroupView(process, self.expected["cgroup"])

    def test_expected_pins_are_detached_and_closing_does_not_close_borrowed_process(self):
        value = self.fresh()
        self.expected["cgroup"]["memoryMaxBytes"] += 1
        self.assertIsNone(value.check())
        value.close()
        value.close()
        self.assertFalse(value.process.closed or self.roots.closed)
        self.assertIsNone(value.process.check())
        with self.assertRaises(ConformanceError):
            value.check()

    def test_finite_limit_changes_and_unlimited_or_noncanonical_values_are_refused(self):
        for name, raw in (("memory.max", b"max\n"), ("pids.max", b"max\n"),
                          ("cpu.max", b"max 100000\n"), ("memory.max", b"1048576\n"),
                          ("pids.max", b"0\n"), ("cpu.max", b"1000 1000\n")):
            value = self.fresh()
            path = self.group + "/" + name
            original = self.contents[path]
            self.contents[path] = raw
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_LIMIT_CHANGED"):
                value.check()
            self.contents[path] = original
            value.close()

    def test_no_whitespace_coercion_truncation_or_extra_control_fields(self):
        path = self.group + "/cpu.max"
        original = self.contents[path]
        for raw in (original[:-1], b" " + original, original + b"\n", original.replace(b" ", b"\t"), original + b"1\n"):
            self.contents[path] = raw
            with self.assertRaises(ConformanceError):
                self.fresh()
        self.contents[path] = original

    def test_actual_group_inode_must_equal_enrolled_pin(self):
        self.expected["cgroup"]["inode"] += 1
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_INODE"):
            self.fresh()

    def test_ancestor_replacement_and_same_inode_submount_are_refused(self):
        for path, change in (("/sys/fs/cgroup/planeon-live", {"st_ino": 9999}),
                             (self.group, {"mountId": 9999}), (self.group + "/memory.max", {"mountId": 9999})):
            value = self.fresh()
            original = self.nodes[path]
            self.nodes[path] = dict(original, **change)
            with self.assertRaises(ConformanceError):
                value.check()
            self.nodes[path] = original
            value.close()

    def test_control_and_membership_path_replacements_cannot_adopt_new_inodes(self):
        for name in ("memory.max", "pids.max", "cpu.max", "cgroup.procs"):
            value = self.fresh()
            path = self.group + "/" + name
            original = self.nodes[path]
            self.nodes[path] = dict(original, st_ino=123456)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_PATH_CHANGED"):
                value.check()
            self.nodes[path] = original
            value.close()

    def test_group_and_controls_must_be_root_owned_not_tenant_writable(self):
        for suffix, key, replacement in (("", "st_uid", 12345), ("/memory.max", "st_gid", 12345),
                                          ("/cgroup.procs", "st_mode", stat.S_IFREG | 0o666)):
            path = self.group + suffix
            original = self.nodes[path][key]
            self.nodes[path][key] = replacement
            with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_IDENTITY"):
                self.fresh()
            self.nodes[path][key] = original

    def test_control_inode_aliases_are_refused(self):
        self.nodes[self.group + "/pids.max"]["st_ino"] = self.nodes[self.group + "/memory.max"]["st_ino"]
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_ALIAS"):
            self.fresh()

    def test_membership_is_unsorted_and_other_member_churn_is_not_target_drift(self):
        path = self.group + "/cgroup.procs"
        self.contents[path] = b"901\n411\n503\n"
        value = self.fresh()
        self.contents[path] = b"411\n701\n"
        self.assertIsNone(value.check())

    def test_membership_must_include_original_live_process_without_duplicates(self):
        path = self.group + "/cgroup.procs"
        for raw in (b"", b"\n", b"412\n", b"411\n411\n", b"0411\n", b"411", b"411 \n",
                    b"411\n0\n", b"411\n2147483648\n", b"411\n-1\n", b"411\n\x00\n"):
            self.contents[path] = raw
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_process_migration_during_controls_read_is_detected_before_return(self):
        value = self.fresh()
        def moved(fd, n):
            raw = self.read(fd, n)
            if self.handles[fd][0].endswith("/memory.max"):
                self.cgroup_raw = b"0::/planeon-live/foreign\n"
            return raw
        with patch.object(server.os, "read", side_effect=moved), self.assertRaises(ConformanceError):
            value.check()

    def test_second_fresh_control_snapshot_rejects_between_open_drift(self):
        value = self.fresh()
        count = 0
        def changed(name, *args, **kwargs):
            nonlocal count
            if name == "memory.max":
                count += 1
                if count == 3:  # named-path check, then the two actual snapshot opens
                    self.contents[self.group + "/memory.max"] = b"max\n"
            return self.open_fd(name, *args, **kwargs)
        with patch.object(server.os, "open", side_effect=changed), self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_LIMIT_CHANGED"):
            value.check()
        self.assertEqual(count, 3)

    def test_membership_removal_during_control_read_is_not_hidden_by_old_sequence_buffer(self):
        value = self.fresh()
        def removed(fd, n):
            raw = self.read(fd, n)
            if self.handles[fd][0].endswith("/memory.max"):
                self.contents[self.group + "/cgroup.procs"] = b"412\n"
            return raw
        with patch.object(server.os, "read", side_effect=removed), self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_MEMBERSHIP"):
            value.check()

    def test_short_reads_continue_to_complete_eof(self):
        def short(fd, n):
            return self.read(fd, min(n, 2) if self.handles[fd][0] in self.contents else n)
        with patch.object(server.os, "read", side_effect=short):
            self.assertIsNone(self.fresh().check())
        self.assertTrue(any(r[2] > 2 for r in self.reads))

    def test_oversize_and_nonbytes_reads_do_not_yield_observations(self):
        for path, raw in ((self.group + "/memory.max", b"1" * 65),
                          (self.group + "/cgroup.procs", b"1\n" * 4097)):
            original = self.contents[path]
            self.contents[path] = raw
            with self.assertRaises(ConformanceError):
                self.fresh()
            self.contents[path] = original
        value = self.fresh()
        def wrong(fd, n):
            return bytearray(n) if self.handles[fd][0] in self.contents else self.read(fd, n)
        with patch.object(server.os, "read", side_effect=wrong), self.assertRaises(ConformanceError):
            value.check()

    def test_retained_descriptor_change_during_read_is_refused(self):
        value = self.fresh()
        def changed(fd, n):
            raw = self.read(fd, n)
            if self.handles[fd][0].endswith("/memory.max"):
                self.nodes[self.group]["st_mode"] = stat.S_IFDIR | 0o777
            return raw
        with patch.object(server.os, "read", side_effect=changed), self.assertRaises(ConformanceError):
            value.check()

    def test_dead_pidfd_during_read_never_returns_matching_limits(self):
        value = self.fresh()
        def dies(fd, n):
            raw = self.read(fd, n)
            if self.handles[fd][0] in self.contents:
                self.dead = True
            return raw
        with patch.object(server.os, "read", side_effect=dies), self.assertRaises(ConformanceError):
            value.check()

    def test_restarted_process_cannot_reuse_same_cgroup_and_limits(self):
        value = self.fresh()
        self.stat_raw = self.process_stat(**{"19": "1000"})
        with self.assertRaises(ConformanceError):
            value.check()

    def test_inspection_has_one_two_second_budget_across_all_nested_reads(self):
        value = self.fresh()
        def slow(fd, n):
            if self.handles[fd][0] in self.contents:
                self.now += 0.4
            return self.read(fd, n)
        with patch.object(server.os, "read", side_effect=slow), self.assertRaises(ConformanceError):
            value.check()
        self.assertTrue(value.failed)

    def test_clock_rollback_and_failure_cannot_renew_inspection(self):
        value = self.fresh()
        self.now -= 1
        with self.assertRaises(ConformanceError):
            value.check()
        self.now += 1
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_UNAVAILABLE"):
            value.check()

    def test_inspector_pid_change_refuses_before_cgroup_io(self):
        value = self.fresh()
        count = len(self.reads)
        with patch.object(server.os, "getpid", return_value=412), self.assertRaises(ConformanceError):
            value.check()
        self.assertEqual(len(self.reads), count)

    def test_inspector_thread_change_refuses_before_cgroup_io(self):
        value = self.fresh()
        count = len(self.reads)
        with patch.object(server.threading, "get_ident", return_value=722), self.assertRaises(ConformanceError):
            value.check()
        self.assertEqual(len(self.reads), count)

    def test_missing_symlinked_or_unreadable_control_is_not_repaired(self):
        process = self.process()
        retained = set(self.handles)
        def missing(name, *args, **kwargs):
            if name == "cpu.max":
                raise PermissionError("unit missing or symlinked control")
            return self.open_fd(name, *args, **kwargs)
        with patch.object(server.os, "open", side_effect=missing), self.assertRaises(PermissionError):
            server._KernelCgroupView(process, self.expected["cgroup"])
        self.assertEqual(set(self.handles), retained)

    def test_late_open_is_owned_and_closed_even_before_identity_capture(self):
        process = self.process()
        retained = set(self.handles)
        def late(name, *args, **kwargs):
            fd = self.open_fd(name, *args, **kwargs)
            if name == "planeon-live":
                self.now += 2
            return fd
        with patch.object(server.os, "open", side_effect=late), self.assertRaises(ConformanceError):
            server._KernelCgroupView(process, self.expected["cgroup"])
        self.assertEqual(set(self.handles), retained)

    def test_uncertain_temporary_close_sticks_and_never_closes_borrowed_owners(self):
        value = server._KernelCgroupView(self.process(), self.expected["cgroup"])
        retained = {r[0] for r in value.rows}
        failed = []
        def uncertain(fd):
            path = self.handles[fd][0]
            self.close_fd(fd)
            if path.endswith("/memory.max") and fd not in retained and not failed:
                failed.append(fd)
                raise OSError("unit uncertain close")
        with patch.object(server.os, "close", side_effect=uncertain), self.assertRaises(OSError):
            value.check()
        with self.assertRaises(OSError):
            value.close()
        with self.assertRaises(OSError):
            value.close()
        self.assertEqual(self.closed.count(failed[0]), 1)
        self.assertFalse(value.process.closed or self.roots.closed)

    def test_recycled_group_descriptor_is_never_closed_as_original(self):
        value = server._KernelCgroupView(self.process(), self.expected["cgroup"])
        target = value.rows[1][0]
        original = self.handles[target]
        self.handles[target] = ("/replacement", dict(original[1], st_ino=999999))
        with self.assertRaisesRegex(ConformanceError, "KERNEL_CGROUP_FD_REUSED"):
            value.close()
        self.assertNotIn(target, self.closed)
        self.handles[target] = original
        self.close_fd(target)


class KernelBpfCustodyTests(unittest.TestCase):
    """Fixed factories and independent Linux-UAPI OS mocks; no native BPF."""
    stat_fd = KernelCgroupCustodyTests.stat_fd
    statfs = KernelCgroupCustodyTests.statfs
    statx = KernelCgroupCustodyTests.statx
    close_fd = KernelCgroupCustodyTests.close_fd
    allocate = KernelCgroupCustodyTests.allocate
    pidfd_open = KernelCgroupCustodyTests.pidfd_open
    poll_pid = KernelCgroupCustodyTests.poll_pid
    namespace_type = KernelCgroupCustodyTests.namespace_type
    scandir = KernelCgroupCustodyTests.scandir
    close_views = KernelCgroupCustodyTests.close_views
    process_stat = KernelCgroupCustodyTests.process_stat
    process_status = KernelCgroupCustodyTests.process_status
    configure = KernelCgroupCustodyTests.configure
    open_fd = KernelCgroupCustodyTests.open_fd
    read = KernelCgroupCustodyTests.read
    process = KernelCgroupCustodyTests.process

    def named_stat(self, name, *, dir_fd=None, follow_symlinks=True):
        # unittest's traceback renderer can stat a source filename while an OS
        # mock is active. Report it absent, not a malformed native observation.
        if dir_fd is None and str(name) not in self.nodes:
            raise FileNotFoundError(str(name))
        return KernelCgroupCustodyTests.named_stat(self, name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def setUp(self):
        KernelCgroupCustodyTests.setUp(self)
        self.hooks = (("INET_SOCK_CREATE", 2, 9), ("INET4_BIND", 8, 18), ("INET6_BIND", 9, 18),
                      ("INET4_CONNECT", 10, 18), ("INET6_CONNECT", 11, 18),
                      ("UDP4_SENDMSG", 14, 18), ("UDP6_SENDMSG", 15, 18))
        self.pins, self.programs, self.calls, self.program_fds = {}, {}, [], []
        self.after = lambda command, attr: None
        for index, (name, hook, kind) in enumerate(self.hooks):
            # Inert bytes, never loaded as a program or used as semantic proof.
            raw = bytes([index + 1]) * 16
            pin = dict(programId=1000 + index, programType=kind, instructionBytes=len(raw),
                       translatedSha256=byte_digest(raw), mapIds=[], ifindex=0)
            self.pins[name] = pin
            self.programs[1000 + index] = (hook, kind, raw)
        self.lib.syscall.side_effect = self.syscall
        self.stack.enter_context(patch.object(server.fcntl, "fcntl", side_effect=self.fd_flags))

    def fd_flags(self, fd, command):
        self.assertEqual(command, server.fcntl.F_GETFL)
        return server.os.O_RDWR if self.handles[fd][0].startswith("bpf:") else server.os.O_RDONLY

    def syscall(self, number, command, pointer, size):
        self.assertIs(type(number), server.ctypes.c_long)
        self.assertIs(type(command), server.ctypes.c_uint)
        self.assertIs(type(size), server.ctypes.c_uint)
        self.assertEqual(number.value, 321 if self.roots.native.machine == "x86_64" else 280)
        self.assertEqual(size.value, 64)
        attr, command = pointer._obj, command.value
        raw = bytes(attr)
        self.calls.append((number.value, command, raw))
        if command == 16:
            target, hook, effective, flags, ids, count = server.struct.unpack_from("<4IQI", raw)
            self.assertEqual(self.handles[target][0], self.group)
            self.assertIn(hook, [r[1] for r in self.hooks])
            self.assertIn(effective, (0, 1))
            self.assertEqual((flags, count, raw[28:]), (0, 16, b"\0" * 36))
            output = (server.ctypes.c_uint32 * 16).from_address(ids)
            self.assertEqual(bytes(output), b"\0" * 64)
            output[0] = next(key for key, value in self.programs.items() if value[0] == hook)
            server.struct.pack_into("<I", attr, 24, 1)
            result = 0
        elif command == 13:
            program = server.struct.unpack_from("<I", raw)[0]
            self.assertIn(program, self.programs)
            self.assertEqual(raw[4:], b"\0" * 60)
            path = "bpf:" + str(program)
            # bpf-prog anonymous fds can share an inode; it is NOT a program ID.
            self.nodes[path] = dict(self.nodes["/"], st_dev=99, st_ino=22, st_mode=0o600)
            result = self.allocate(path)
            self.program_fds.append(result)
        elif command == 15:
            fd, length, address = server.struct.unpack_from("<IIQ", raw)
            self.assertEqual((length, raw[16:]), (240, b"\0" * 48))
            program = int(self.handles[fd][0].split(":")[1])
            _, kind, instructions = self.programs[program]
            info = (server.ctypes.c_ubyte * 240).from_address(address)
            output = server.struct.unpack_from("<Q", info, 32)[0]
            expected = bytearray(240)
            if output:
                server.struct.pack_into("<I", expected, 20, 65536)
                server.struct.pack_into("<Q", expected, 32, output)
            self.assertEqual(bytes(info), bytes(expected))
            if output:
                code = (server.ctypes.c_ubyte * 65536).from_address(output)
                self.assertFalse(any(code))
                code[:len(instructions)] = instructions
            server.struct.pack_into("<II", info, 0, kind, program)
            server.struct.pack_into("<I", info, 20, len(instructions))
            server.struct.pack_into("<Q", info, 40, 76543)
            for offset, value in ((84, 1), (104, 1), (108, 1), (132, 8), (172, 16), (176, 8)):
                server.struct.pack_into("<I", info, offset, value)
            server.struct.pack_into("<I", attr, 4, 232)
            result = 0
        else:
            raise AssertionError("forbidden BPF command")
        self.after(command, attr)
        return result

    def fresh(self):
        group = KernelCgroupCustodyTests.fresh(self)
        value = server._KernelBpfView(group, self.pins)
        self.addCleanup(self.close_bpf, value)
        return value

    def close_bpf(self, value):
        self.after = lambda command, attr: None
        value.close()

    def changed_info(self, offset, value, fmt="<I"):
        def change(command, attr):
            if command == 15:
                address = server.struct.unpack_from("<Q", attr, 8)[0]
                info = (server.ctypes.c_ubyte * 240).from_address(address)
                server.struct.pack_into(fmt, info, offset, value)
        self.after = change

    def test_retains_seven_programs_and_queries_local_and_effective_before_after(self):
        value = self.fresh()
        self.assertEqual(len(value.rows), 7)
        self.assertIsNone(value.check())
        self.assertEqual({c[1] for c in self.calls}, {13, 15, 16})
        self.assertEqual(sum(c[1] == 13 for c in self.calls), 7)
        self.assertEqual(sum(c[1] == 16 for c in self.calls), 70)
        self.assertEqual(sum(c[1] == 15 for c in self.calls), 21)
        self.assertEqual({server.struct.unpack_from("<II", c[2], 4) for c in self.calls if c[1] == 16},
                         {(hook, flags) for _, hook, _ in self.hooks for flags in (0, 1)})
        self.mapper.assert_not_called()

    def test_arm64_uses_fixed_280_and_no_architecture_fallback(self):
        self.roots.close()
        with patch.object(server.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
            self.roots = server._KernelRootViews()
        self.addCleanup(self.roots.close)
        self.assertIsNone(self.fresh().check())
        self.assertEqual({c[0] for c in self.calls}, {280})

    def test_all_four_roles_query_only_their_retained_cgroup(self):
        for role in ("SERVER", "OBSERVER", "BROKER", "WORKER"):
            self.configure(role)
            value = self.fresh()
            self.assertIsNone(value.check())
            value.close()
            value.cgroup.close()
            value.cgroup.process.close()

    def test_owner_copies_raw_fds_and_injected_backends_are_refused(self):
        group = KernelCgroupCustodyTests.fresh(self)
        for owner in (None, {}, 3, SimpleNamespace(**group.__dict__)):
            with self.assertRaises(ConformanceError):
                server._KernelBpfView(owner, self.pins)
        with self.assertRaises(TypeError):
            server._KernelBpfView(group, self.pins, backend=Mock())
        group.close()
        with self.assertRaises(ConformanceError):
            server._KernelBpfView(group, self.pins)
        self.assertEqual(self.calls, [])

    def test_pin_shape_hook_set_and_values_are_closed_before_native_calls(self):
        group = KernelCgroupCustodyTests.fresh(self)
        key = "INET_SOCK_CREATE"
        cases = [{}, dict(self.pins, UNKNOWN=self.pins[key])]
        for change in ({"programId": True}, {"programId": 0}, {"programId": 4294967296},
                       {"programType": 18}, {"instructionBytes": 9}, {"instructionBytes": 65544},
                       {"mapIds": [1]}, {"ifindex": False}, {"ifindex": 1},
                       {"translatedSha256": "tag-only"}, {"extra": True}):
            cases.append(dict(self.pins, **{key: dict(self.pins[key], **change)}))
        for pins in cases:
            with self.subTest(pins=pins), self.assertRaises((ConformanceError, ValueError)):
                server._KernelBpfView(group, pins)
        self.assertEqual(self.calls, [])

    def test_missing_attachment_refuses_without_acquiring_programs(self):
        self.after = lambda cmd, attr: server.struct.pack_into("<I", attr, 24, 0) if cmd == 16 else None
        with self.assertRaises(ConformanceError):
            self.fresh()
        self.assertEqual(self.program_fds, [])

    def test_extra_or_oversized_attachment_count_is_not_truncated_or_retried(self):
        for count in (2, 16, 17, 4294967295):
            self.after = lambda cmd, attr: server.struct.pack_into("<I", attr, 24, count) if cmd == 16 else None
            with self.assertRaises(ConformanceError):
                self.fresh()
        self.assertEqual(self.program_fds, [])

    def test_effective_inherited_program_mismatch_refuses(self):
        def change(cmd, attr):
            if cmd == 16 and server.struct.unpack_from("<I", attr, 8)[0] == 1:
                pointer = server.struct.unpack_from("<Q", attr, 16)[0]
                (server.ctypes.c_uint32 * 16).from_address(pointer)[0] = 999
        self.after = change
        with self.assertRaises(ConformanceError):
            self.fresh()

    def test_query_unknown_tail_or_changed_input_refuses(self):
        for offset in (0, 4, 8, 16, 28, 32, 40, 48, 56):
            self.after = lambda cmd, attr: server.struct.pack_into("<I", attr, offset, 255) if cmd == 16 else None
            with self.subTest(offset=offset), self.assertRaises(ConformanceError):
                self.fresh()

    def test_effective_flags_and_unknown_local_flags_refuse(self):
        for flags, mode in ((1, 1), (2, 1), (3, 0), (4, 0)):
            def change(cmd, attr):
                if cmd == 16 and server.struct.unpack_from("<I", attr, 8)[0] == mode:
                    server.struct.pack_into("<I", attr, 12, flags)
            self.after = change
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_valid_local_flags_are_retained_and_changes_poison_view(self):
        def multi(cmd, attr):
            if cmd == 16 and server.struct.unpack_from("<I", attr, 8)[0] == 0:
                server.struct.pack_into("<I", attr, 12, 2)
        self.after = multi
        value = self.fresh()
        self.assertIsNone(value.check())
        self.after = lambda cmd, attr: None
        with self.assertRaises(ConformanceError):
            value.check()
        self.assertTrue(value.failed)

    def test_query_unused_id_slots_cannot_hide_additional_output(self):
        def change(cmd, attr):
            if cmd == 16:
                pointer = server.struct.unpack_from("<Q", attr, 16)[0]
                (server.ctypes.c_uint32 * 16).from_address(pointer)[15] = 999
        self.after = change
        with self.assertRaises(ConformanceError):
            self.fresh()

    def test_syscall_errors_do_not_retry_or_acquire_privileges(self):
        for command in (13, 15, 16):
            def fail(number, cmd, pointer, size):
                return -1 if cmd.value == command else self.syscall(number, cmd, pointer, size)
            with patch.object(self.lib, "syscall", Mock(side_effect=fail)), self.assertRaises(ConformanceError):
                self.fresh()
            self.assertTrue(all(fd not in self.handles for fd in self.program_fds))

    def test_redacted_instruction_length_refuses(self):
        self.changed_info(20, 0)
        with self.assertRaises(ConformanceError):
            self.fresh()
        self.assertTrue(all(fd not in self.handles for fd in self.program_fds))

    def test_redacted_instruction_pointer_refuses_even_with_matching_length(self):
        self.changed_info(32, 0, "<Q")
        with self.assertRaises(ConformanceError):
            self.fresh()

    def test_actual_id_or_type_mismatch_refuses(self):
        for offset, value in ((0, 18), (4, 999)):
            self.changed_info(offset, value)
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_maps_and_offload_are_not_accepted(self):
        for offset in (52, 56, 80, 88, 96):
            self.changed_info(offset, 1)
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_unrequested_pointers_reserved_bits_and_record_layouts_refuse(self):
        for offset, value in ((24, 1), (84, 2), (112, 1), (120, 1), (132, 9), (136, 1),
                              (152, 1), (160, 1), (172, 17), (176, 9), (184, 1), (228, 1), (232, 1)):
            self.changed_info(offset, value)
            with self.subTest(offset=offset), self.assertRaises(ConformanceError):
                self.fresh()

    def test_short_new_or_changed_info_response_layouts_refuse(self):
        for offset, value in ((0, 1), (4, 224), (4, 240), (8, 1), (16, 1)):
            self.after = lambda cmd, attr: server.struct.pack_into("<I", attr, offset, value) if cmd == 15 else None
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_translated_bytes_not_tag_or_stored_artifact_determine_identity(self):
        self.programs[1000] = (2, 9, b"x" * 16)
        with self.assertRaises(ConformanceError):
            self.fresh()

    def test_oversized_or_truncated_instructions_refuse_without_second_allocation(self):
        for count in (8, 17, 65537, 4294967295):
            self.changed_info(20, count)
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_runtime_counters_may_advance_but_load_identity_must_not(self):
        value = self.fresh()
        self.changed_info(192, 999, "<Q")
        self.assertIsNone(value.check())
        self.changed_info(40, 999, "<Q")
        with self.assertRaises(ConformanceError):
            value.check()

    def test_replacement_after_program_read_is_caught_by_final_queries(self):
        value = self.fresh()
        original = self.programs[1000]
        def change(cmd, attr):
            if cmd == 15:
                self.programs[999] = self.programs.pop(1000)
                self.after = lambda cmd, attr: None
        self.after = change
        with self.assertRaises(ConformanceError):
            value.check()
        self.programs[1000] = original

    def test_pid_death_or_cgroup_migration_after_query_poison_owner(self):
        for field, raw in (("stat_raw", self.process_stat(**{"19": "77"})), ("cgroup_raw", b"0::/foreign\n")):
            before = getattr(self, field)
            value = self.fresh()
            self.after = lambda cmd, attr: setattr(self, field, raw)
            with self.assertRaises(ConformanceError):
                value.check()
            setattr(self, field, before)
            self.after = lambda cmd, attr: None

    def test_changed_cgroup_control_during_query_fails_before_return(self):
        value = self.fresh()
        self.after = lambda cmd, attr: self.contents.update({self.group + "/pids.max": b"2\n"})
        with self.assertRaises(ConformanceError):
            value.check()

    def test_inheritable_or_wrong_mode_program_descriptors_refuse(self):
        with patch.object(server.os, "get_inheritable", side_effect=lambda fd: fd in self.program_fds):
            with self.assertRaises(ConformanceError):
                self.fresh()
        with patch.object(server.fcntl, "fcntl", return_value=server.os.O_RDONLY):
            with self.assertRaises(ConformanceError):
                self.fresh()

    def test_expected_pins_detach_and_program_close_preserves_borrowed_owners(self):
        value = self.fresh()
        self.pins["INET4_BIND"]["programId"] = 999
        self.assertIsNone(value.check())
        value.close()
        value.close()
        self.assertTrue(all(fd not in self.handles for fd in self.program_fds))
        self.assertFalse(value.cgroup.closed or value.cgroup.process.closed or self.roots.closed)
        self.assertIsNone(value.cgroup.check())
        with self.assertRaises(ConformanceError):
            value.check()

    def test_post_acquisition_timeout_closes_new_descriptor_before_raising(self):
        def expire(cmd, attr):
            if cmd == 13:
                self.now += 2
        self.after = expire
        with self.assertRaises(ConformanceError):
            self.fresh()
        self.assertEqual(len(self.program_fds), 1)
        self.assertNotIn(self.program_fds[0], self.handles)

    def test_syscall_timeout_and_backwards_clock_refuse(self):
        for delta in (2, -1):
            self.after = lambda cmd, attr: setattr(self, "now", self.now + delta)
            with self.assertRaises(ConformanceError):
                self.fresh()
            self.after = lambda cmd, attr: None

    def test_cross_process_thread_or_reentrant_use_refuses(self):
        for obj, key in ((server.os, "getpid"), (server.threading, "get_ident")):
            value = self.fresh()
            with patch.object(obj, key, return_value=999), self.assertRaises(ConformanceError):
                value.check()
        value = self.fresh()
        value.busy = True
        with self.assertRaises(ConformanceError):
            value.check()
        value.busy = False

    def test_shared_anonymous_inode_cannot_hide_fd_substitution_on_close(self):
        value = self.fresh()
        self._cleanups.pop()  # this test explicitly verifies sticky close failure
        fd = value.rows[0][0]
        self.handles[fd] = ("bpf:1001", self.handles[fd][1])
        with self.assertRaises(ConformanceError):
            value.close()
        self.assertIn(fd, self.handles)
        self.assertTrue(all(other not in self.handles for other in self.program_fds if other != fd))
        called = len(self.calls)
        with self.assertRaises(ConformanceError):
            value.close()
        self.assertEqual(len(self.calls), called)
        self.close_fd(fd)  # test-owned substituted handle, not production cleanup

    def test_uncertain_os_close_is_never_retried_and_other_owned_fds_close(self):
        value = self.fresh()
        self._cleanups.pop()
        fd = value.rows[-1][0]
        calls = []
        def fail(number):
            calls.append(number)
            self.close_fd(number)
            if number == fd:
                raise OSError("unit close uncertainty")
        with patch.object(server.os, "close", side_effect=fail):
            with self.assertRaises(OSError):
                value.close()
            with self.assertRaises(OSError):
                value.close()
        self.assertEqual(calls.count(fd), 1)
        self.assertEqual(len(calls), 7)

    def test_same_inode_different_program_id_is_detected_during_recheck(self):
        value = self.fresh()
        fd = value.rows[0][0]
        original = self.handles[fd]
        self.handles[fd] = ("bpf:1001", original[1])
        with self.assertRaises(ConformanceError):
            value.check()
        self.handles[fd] = original

    def test_program_fd_acquisition_partial_failure_releases_only_owned_handles(self):
        count = 0
        def fail(number, command, pointer, size):
            nonlocal count
            if command.value == 13:
                count += 1
                if count == 4:
                    return -1
            return self.syscall(number, command, pointer, size)
        with patch.object(self.lib, "syscall", side_effect=fail), self.assertRaises(ConformanceError):
            self.fresh()
        self.assertEqual(len(self.program_fds), 3)
        self.assertTrue(all(fd not in self.handles for fd in self.program_fds))
        self.assertFalse(self.roots.closed)

    def test_private_syscall_surface_rejects_mutation_commands(self):
        value = self.fresh()
        before = len(self.calls)
        for command in (0, 1, 2, 5, 8, 9, 10, 28, 29, True, "16"):
            with self.assertRaises(ConformanceError):
                value._call(command, server._KernelBpfAttr())
        self.assertEqual(len(self.calls), before)


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


class KernelObserverInspectionTests(unittest.TestCase):
    """Real signed binding/composition; OS channel and typed reader doubles.

    Component OS-edge coverage remains separate. This is not a native or
    combined all-kernel-readers qualification, and creates no production bypass.
    """
    CLASSES = KernelSelfInspectionTests.CLASSES
    fail = KernelSelfInspectionTests.fail

    def environment(self, stack):
        self.server_inspection = KernelSelfInspectionTests.environment(self, stack)
        self.server_inspection.__init__(self.owner)
        self.peer = object.__new__(server._Observer)
        peer, self.owner.observer = self.peer, self.peer
        peer.owner, peer.closed, peer.failed, peer.busy = self.owner, False, False, True
        peer.deadline, peer.end = self.owner.deadline, self.fixture.mono + 2
        peer.sock = peer._socket_original = Mock()
        peer.sock.fileno.return_value = 71
        peer._socket_fd, peer._socket_pin = 71, (1, 31, stat.S_IFSOCK)
        peer.pidfd = peer._pidfd_original = 72
        peer._pidfd_pin = (1, 32, stat.S_IFREG)
        peer.peer = peer._peer_original = (811, 0, 0)
        role = self.fixture.record["roles"]["OBSERVER"]
        peer.identity = dict(pid=811, start=71, parent=1, uid=(0,) * 4, gid=(0,) * 4,
            capabilities=(0,) * 5, seccomp=2, noNewPrivs=1,
            cgroup="0::/planeon-live/policy-observer\n", namespaces=deepcopy(role["namespaceInodes"]))
        peer._process_original = server._Observer._process_pin(peer.identity)
        peer.parent = 75
        self.path = SimpleNamespace(st_dev=1, st_ino=21, st_uid=0, st_gid=0, st_mode=stat.S_IFSOCK | 0o600,
            st_nlink=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
        peer.socket_identity = server._custody_identity(self.path)
        self.fd_rows = {71: SimpleNamespace(st_dev=1, st_ino=31, st_mode=stat.S_IFSOCK | 0o600),
                        72: SimpleNamespace(st_dev=1, st_ino=32, st_mode=stat.S_IFREG | 0o600)}
        old_stat, old_fstat = server.os.stat, server.os.fstat
        stack.enter_context(patch.object(server.os, "stat", side_effect=lambda name, **kw:
            self.path if name == "policy-observer.sock" and kw.get("dir_fd") == 75 else old_stat(name, **kw)))
        stack.enter_context(patch.object(server.os, "fstat", side_effect=lambda fd:
            self.fd_rows[fd] if fd in self.fd_rows else old_fstat(fd)))
        stack.enter_context(patch.object(server.socket, "SO_PEERCRED", 17, create=True))
        self.poll = stack.enter_context(patch.object(server.select, "select", return_value=([], [], [])))
        self.peer_credentials = (811, 0, 0)
        peer.sock.getsockopt.side_effect = lambda *args: server.struct.pack("3i", *self.peer_credentials)
        self.native_process = dict(pid=811, startTicks=71, parent=1, uid=(0,) * 4, gid=(0,) * 4,
                                   capabilities=(0,) * 5, seccompMode=2, noNewPrivs=1)
        def on_build(name, resource):
            if name == "process":
                resource.original = deepcopy(self.native_process)
                resource.cgroup = peer.identity["cgroup"].encode()
                resource.pin = (0, 0, role["processLabel"], tuple(role["namespaceInodes"][k]
                    for k in ("user", "mnt", "pid", "net")))
        self.on_build = on_build
        self.events.clear()
        subject = peer.inspection = peer._inspection_original = object.__new__(server._KernelObserverInspection)
        def cleanup():
            if hasattr(subject, "closed"):
                if subject.cleanup_failure is None:
                    subject.close()
                else:
                    with self.assertRaises(type(subject.cleanup_failure)):
                        subject.close()
        stack.callback(cleanup)
        return subject

    def start(self, stack):
        subject = self.environment(stack)
        subject.__init__(self.peer)
        return subject

    def test_fixed_observer_role_uses_original_peer_not_server_pid(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.assertEqual([n for event, n in self.events if event == "acquire"], [n for n, _ in self.CLASSES])
            self.assertEqual(self.args["process"], (subject.roots, 811, "OBSERVER", self.fixture.record["roles"]["OBSERVER"]))
            self.assertEqual(self.args["code"][1], self.fixture.record["files"])
            self.assertEqual(self.args["mappings"][2], {k: self.fixture.record["roles"]["OBSERVER"][k]
                for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")})
            self.assertIsNone(subject.check())
            self.assertFalse(self.fixture.socket.called)
            self.peer.sock.send.assert_not_called()
            self.peer.sock.recvmsg.assert_not_called()
            self.assertNotIn(server.IDENTITY, self.fixture.read_paths)

    def test_proc_start_must_join_original_socket_process_before_code_reads(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            self.native_process["startTicks"] += 1
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_PROCESS_CHANGED"):
                subject.__init__(self.peer)
            self.assertNotIn(("acquire", "code"), self.events)
            self.assertTrue(subject.closed and subject.failed)

    def test_each_partial_reader_is_owned_before_constructor_failure(self):
        for index, (fault, _) in enumerate(self.CLASSES):
            with self.subTest(reader=fault), ExitStack() as stack:
                subject = self.environment(stack)
                original = self.on_build
                def build(name, resource):
                    original(name, resource)
                    if name == fault:
                        self.fail()
                self.on_build = build
                with self.assertRaises(ConformanceError):
                    subject.__init__(self.peer)
                self.assertEqual([n for event, n in self.events if event == "close"],
                                 [n for n, _ in reversed(self.CLASSES[:index + 1])])

    def test_failed_reader_poisoned_and_cleanup_does_not_own_channel_or_server(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.on_check = lambda name, resource: self.fail() if name == "filters" else None
            with self.assertRaises(ConformanceError):
                subject.check()
            self.assertTrue(subject.closed and subject.failed)
            self.assertFalse(self.server_inspection.closed or self.owner.files.closed)
            self.peer.sock.close.assert_not_called()

    def test_original_socket_credentials_are_checked_at_reader_boundaries(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_PEER_CHANGED"):
                with subject._phase():
                    self.peer_credentials = (812, 0, 0)
                    server._kernel_inspection_tick(subject.filters)
            self.assertTrue(subject.failed)

    def test_nonroot_peer_credentials_are_not_role_enrollment(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            self.peer.peer = self.peer._peer_original = self.peer_credentials = (811, 10000, 10000)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_ROLE"):
                subject.__init__(self.peer)
            self.assertNotIn(("acquire", "roots"), self.events)

    def test_replaced_pidfd_is_not_adopted(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.peer.pidfd = 73
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_PEER_SUBSTITUTED"):
                subject.check()

    def test_reused_descriptor_is_refused_without_closing_borrowed_fd(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.fd_rows[72].st_ino += 1
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_DESCRIPTOR_CHANGED"):
                subject.check()
            self.assertNotIn(72, self.fixture.closed_fds)

    def test_exceptional_pidfd_liveness_refuses(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.poll.return_value = ([], [], [72])
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_PEER_CHANGED"):
                subject.check()

    def test_named_observer_socket_replacement_refuses(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.path.st_ino += 1
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_PEER_CHANGED"):
                subject.check()

    def test_observer_phase_deadline_cannot_be_renewed_by_inspection(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.fixture.mono = self.peer.end
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_DEADLINE"):
                subject.check()

    def test_late_channel_query_is_rechecked_even_on_exception(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            def late(*args):
                self.fixture.mono += 2
                raise OSError("unit late query")
            self.peer.sock.getsockopt.side_effect = late
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_DEADLINE"):
                subject.check()

    def test_replaced_self_inspector_refuses_before_peer_reader_check(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.owner.self_inspection = Mock()
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_OWNER_CHANGED"):
                subject.check()
            self.owner.self_inspection = self.server_inspection

    def test_poisoned_server_self_inspection_cannot_support_peer_qualification(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.server_inspection.failed = True
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_OWNER_CHANGED"):
                subject.check()

    def test_detached_peer_inspection_is_not_an_ambient_capability(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.peer.busy = False
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_OWNER_CHANGED"):
                subject.check()

    def test_copied_owner_and_subclass_are_refused(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            class Substitute(server._KernelObserverInspection):
                pass
            impostor = object.__new__(Substitute)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_OWNER"):
                impostor.__init__(self.peer)
            self.peer.inspection = Mock()
            with self.assertRaisesRegex(ConformanceError, "KERNEL_OBSERVER_OWNER"):
                subject.__init__(self.peer)

    def test_record_change_remains_sticky_and_cannot_reenroll_peer(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.owner.qualification_binding._record_raw += b" "
            with self.assertRaises(ConformanceError):
                subject.check()
            self.assertTrue(subject.failed)

    def test_cleanup_error_preserves_other_reader_closes_without_retry(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.events.clear()
            self.on_close = lambda name, resource: self.fail() if name == "mappings" else None
            for _ in range(2):
                with self.assertRaises(ConformanceError):
                    subject.close()
            self.assertEqual([n for event, n in self.events if event == "close"],
                             [n for n, _ in reversed(self.CLASSES)])
            self.on_close = lambda name, resource: None


class KernelBrokerInspectionTests(unittest.TestCase):
    """Real signed binding/composition; OS channel and typed reader doubles.

    Component OS-edge coverage remains separate. This is not a native or
    combined all-kernel-readers qualification, and creates no production bypass.
    """
    CLASSES = KernelSelfInspectionTests.CLASSES
    fail = KernelSelfInspectionTests.fail

    def environment(self, stack):
        self.server_inspection = KernelSelfInspectionTests.environment(self, stack)
        self.server_inspection.__init__(self.owner)
        self.peer = object.__new__(server._Broker)
        peer, self.owner.broker = self.peer, self.peer
        self.owner._broker_original = peer
        peer.owner, peer.closed, peer.failed, peer.busy = self.owner, False, False, True
        peer.deadline, peer.end = self.owner.deadline, self.fixture.mono + 2
        peer.sock = peer._socket_original = Mock()
        peer.sock.fileno.return_value = 71
        peer._socket_fd, peer._socket_pin = 71, (1, 31, stat.S_IFSOCK)
        peer.pidfd = peer._pidfd_original = 72
        peer._pidfd_pin = (1, 32, stat.S_IFREG)
        peer.peer = peer._peer_original = (811, 0, 0)
        role = self.fixture.record["roles"]["BROKER"]
        peer.identity = dict(pid=811, start=71, parent=1, uid=(0,) * 4, gid=(0,) * 4,
            capabilities=(0,) * 5, seccomp=2, noNewPrivs=1,
            cgroup="0::/planeon-live/capacity-broker\n", namespaces=deepcopy(role["namespaceInodes"]))
        peer._process_original = server._Broker._process_pin(peer.identity)
        peer.parent = 75
        self.path = SimpleNamespace(st_dev=1, st_ino=21, st_uid=0, st_gid=0, st_mode=stat.S_IFSOCK | 0o600,
            st_nlink=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
        peer.socket_identity = server._custody_identity(self.path)
        self.fd_rows = {71: SimpleNamespace(st_dev=1, st_ino=31, st_mode=stat.S_IFSOCK | 0o600),
                        72: SimpleNamespace(st_dev=1, st_ino=32, st_mode=stat.S_IFREG | 0o600)}
        old_stat, old_fstat = server.os.stat, server.os.fstat
        stack.enter_context(patch.object(server.os, "stat", side_effect=lambda name, **kw:
            self.path if name == "capacity-broker.sock" and kw.get("dir_fd") == 75 else old_stat(name, **kw)))
        stack.enter_context(patch.object(server.os, "fstat", side_effect=lambda fd:
            self.fd_rows[fd] if fd in self.fd_rows else old_fstat(fd)))
        stack.enter_context(patch.object(server.socket, "SO_PEERCRED", 17, create=True))
        self.poll = stack.enter_context(patch.object(server.select, "select", return_value=([], [], [])))
        self.peer_credentials = (811, 0, 0)
        peer.sock.getsockopt.side_effect = lambda *args: server.struct.pack("3i", *self.peer_credentials)
        self.native_process = dict(pid=811, startTicks=71, parent=1, uid=(0,) * 4, gid=(0,) * 4,
                                   capabilities=(0,) * 5, seccompMode=2, noNewPrivs=1)
        def on_build(name, resource):
            if name == "process":
                resource.original = deepcopy(self.native_process)
                resource.cgroup = peer.identity["cgroup"].encode()
                resource.pin = (0, 0, role["processLabel"], tuple(role["namespaceInodes"][k]
                    for k in ("user", "mnt", "pid", "net")))
        self.on_build = on_build
        self.events.clear()
        subject = peer.inspection = peer._inspection_original = object.__new__(server._KernelBrokerInspection)
        def cleanup():
            if hasattr(subject, "closed"):
                if subject.cleanup_failure is None:
                    subject.close()
                else:
                    with self.assertRaises(type(subject.cleanup_failure)):
                        subject.close()
        stack.callback(cleanup)
        return subject

    def start(self, stack):
        subject = self.environment(stack)
        subject.__init__(self.peer)
        return subject

    def test_fixed_broker_role_uses_original_peer_not_server_pid(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.assertEqual([n for event, n in self.events if event == "acquire"], [n for n, _ in self.CLASSES])
            self.assertEqual(self.args["process"], (subject.roots, 811, "BROKER", self.fixture.record["roles"]["BROKER"]))
            self.assertEqual(self.args["code"][1], self.fixture.record["files"])
            self.assertEqual(self.args["mappings"][2], {k: self.fixture.record["roles"]["BROKER"][k]
                for k in ("executable", "artifactDigest", "interpreterPath", "filePaths")})
            self.assertIsNone(subject.check())
            self.assertFalse(self.fixture.socket.called)
            self.peer.sock.send.assert_not_called()
            self.peer.sock.recvmsg.assert_not_called()
            self.assertNotIn(server.IDENTITY, self.fixture.read_paths)

    def test_proc_start_must_join_original_socket_process_before_code_reads(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            self.native_process["startTicks"] += 1
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_PROCESS_CHANGED"):
                subject.__init__(self.peer)
            self.assertNotIn(("acquire", "code"), self.events)
            self.assertTrue(subject.closed and subject.failed)

    def test_each_partial_reader_is_owned_before_constructor_failure(self):
        for index, (fault, _) in enumerate(self.CLASSES):
            with self.subTest(reader=fault), ExitStack() as stack:
                subject = self.environment(stack)
                original = self.on_build
                def build(name, resource):
                    original(name, resource)
                    if name == fault:
                        self.fail()
                self.on_build = build
                with self.assertRaises(ConformanceError):
                    subject.__init__(self.peer)
                self.assertEqual([n for event, n in self.events if event == "close"],
                                 [n for n, _ in reversed(self.CLASSES[:index + 1])])

    def test_failed_reader_poisoned_and_cleanup_does_not_own_channel_or_server(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.on_check = lambda name, resource: self.fail() if name == "filters" else None
            with self.assertRaises(ConformanceError):
                subject.check()
            self.assertTrue(subject.closed and subject.failed)
            self.assertFalse(self.server_inspection.closed or self.owner.files.closed)
            self.peer.sock.close.assert_not_called()

    def test_original_socket_credentials_are_checked_at_reader_boundaries(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_PEER_CHANGED"):
                with subject._phase():
                    self.peer_credentials = (812, 0, 0)
                    server._kernel_inspection_tick(subject.filters)
            self.assertTrue(subject.failed)

    def test_nonroot_peer_credentials_are_not_role_enrollment(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            self.peer.peer = self.peer._peer_original = self.peer_credentials = (811, 10000, 10000)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_ROLE"):
                subject.__init__(self.peer)
            self.assertNotIn(("acquire", "roots"), self.events)

    def test_replaced_pidfd_is_not_adopted(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.peer.pidfd = 73
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_PEER_SUBSTITUTED"):
                subject.check()

    def test_reused_descriptor_is_refused_without_closing_borrowed_fd(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.fd_rows[72].st_ino += 1
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_DESCRIPTOR_CHANGED"):
                subject.check()
            self.assertNotIn(72, self.fixture.closed_fds)

    def test_exceptional_pidfd_liveness_refuses(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.poll.return_value = ([], [], [72])
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_PEER_CHANGED"):
                subject.check()

    def test_named_broker_socket_replacement_refuses(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.path.st_ino += 1
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_PEER_CHANGED"):
                subject.check()

    def test_broker_phase_deadline_cannot_be_renewed_by_inspection(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.fixture.mono = self.peer.end
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_DEADLINE"):
                subject.check()

    def test_late_channel_query_is_rechecked_even_on_exception(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            def late(*args):
                self.fixture.mono += 2
                raise OSError("unit late query")
            self.peer.sock.getsockopt.side_effect = late
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_DEADLINE"):
                subject.check()

    def test_replaced_self_inspector_refuses_before_peer_reader_check(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.owner.self_inspection = Mock()
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER_CHANGED"):
                subject.check()
            self.owner.self_inspection = self.server_inspection

    def test_poisoned_server_self_inspection_cannot_support_peer_qualification(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.server_inspection.failed = True
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER_CHANGED"):
                subject.check()

    def test_detached_peer_inspection_is_not_an_ambient_capability(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.peer.busy = False
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER_CHANGED"):
                subject.check()

    def test_copied_owner_and_subclass_are_refused(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            class Substitute(server._KernelBrokerInspection):
                pass
            impostor = object.__new__(Substitute)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER"):
                impostor.__init__(self.peer)
            self.peer.inspection = Mock()
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER"):
                subject.__init__(self.peer)

    def test_record_change_remains_sticky_and_cannot_reenroll_peer(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.owner.qualification_binding._record_raw += b" "
            with self.assertRaises(ConformanceError):
                subject.check()
            self.assertTrue(subject.failed)

    def test_cleanup_error_preserves_other_reader_closes_without_retry(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.events.clear()
            self.on_close = lambda name, resource: self.fail() if name == "mappings" else None
            for _ in range(2):
                with self.assertRaises(ConformanceError):
                    subject.close()
            self.assertEqual([n for event, n in self.events if event == "close"],
                             [n for n, _ in reversed(self.CLASSES)])
            self.on_close = lambda name, resource: None


    def test_server_original_channel_pin_cannot_be_rebound(self):
        with ExitStack() as stack:
            subject = self.start(stack)
            self.owner._broker_original = Mock()
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER_CHANGED"):
                subject.check()

    def test_observer_peer_type_cannot_supply_broker_native_inspection(self):
        with ExitStack() as stack:
            subject = self.environment(stack)
            foreign = object.__new__(server._Observer)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_BROKER_OWNER"):
                subject.__init__(foreign)
            self.assertNotIn(("acquire", "roots"), self.events)


class BrokerTransportCustodyTests(unittest.TestCase):
    """Real fixed broker channel; OS and binding/native-inspector doubles.

    No frame, worker, API operation or credential is used. These component
    tests are not combined native-reader or installed-service qualification.
    """
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.now, self.wall = 100.0, "2026-09-08T00:00:02.000000Z"
        self.events = []
        self.fixture = deepcopy(VECTORS["broker"]["positive"][0])
        self.peer = (811, 0, 0)
        self.process = dict(pid=811, start=71, parent=1, uid=(0,) * 4, gid=(0,) * 4,
            capabilities=(0,) * 5, seccomp=2, noNewPrivs=1, cgroup="0::/planeon-live/capacity-broker\n",
            namespaces=dict(user=1, mnt=2, pid=3, net=4))
        def info(inode, mode):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_uid=0, st_gid=0, st_mode=mode,
                st_nlink=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
        self.path = info(21, stat.S_IFSOCK | 0o600)
        self.exe = info(22, stat.S_IFREG | 0o555)
        self.fds = {71: info(31, stat.S_IFSOCK | 0o600), 72: info(32, stat.S_IFREG | 0o600)}
        self.socket = Mock()
        self.socket.fileno.return_value = 71
        self.socket.getsockopt.side_effect = lambda *args: server.struct.pack("3i", *self.peer)
        self.owner = object.__new__(server.NativeProxyServer)
        self.owner.deadline = 500
        self.owner._base_check = Mock(side_effect=lambda: self.events.append("owner"))
        self.owner.files = Mock()
        self.owner.files.raw = {server.BROKER: b"\x7fELFunit-only"}
        self.owner.files.rows = {server.BROKER: [75, None, "broker", server._custody_identity(self.exe)]}
        self.owner.files._open.return_value = 75
        self.owner.profile = deepcopy(VECTORS["proxy"]["positive"])
        # Explicit signed-binding owner double; native composition tests above
        # exercise the real authenticated binding. No runtime bypass is added.
        binding = self.owner.qualification_binding = object.__new__(server._ServerQualificationBinding)
        binding.owner = self.owner
        binding._broker_raw = canonical_bytes(self.fixture["binding"])
        self.binding_check = Mock(return_value=None)
        self.stack.enter_context(patch.object(server._ServerQualificationBinding, "check", self.binding_check))
        self.subject = self.owner.broker = self.owner._broker_original = object.__new__(server._Broker)
        self.containment = Mock(return_value=None)
        # This class tests transport, not native reader qualification.
        # Keep the explicit containment double at the fixed owned component.
        def inspection_init(resource, peer):
            resource.peer, resource.closed = peer, False
        self.stack.enter_context(patch.object(server._KernelBrokerInspection, "__init__", inspection_init))
        self.stack.enter_context(patch.object(server._KernelBrokerInspection, "check", self.containment))
        self.stack.enter_context(patch.object(server._KernelBrokerInspection, "close",
            lambda resource: setattr(resource, "closed", True)))
        real_stat = server.os.stat
        patches = ((server.time, "monotonic", dict(side_effect=lambda: self.now)),
            (server, "utc_now", dict(side_effect=lambda: self.wall)),
            (server, "_manifest", dict(return_value=({}, self.fixture["binding"]["brokerManifestDigest"],
                self.fixture["binding"]["brokerExecutableDigest"]))),
            (server, "process_identity", dict(side_effect=lambda pid: deepcopy(self.process))),
            (server.os, "stat", dict(side_effect=lambda path, **kw:
                self.path if path == "capacity-broker.sock" and kw.get("dir_fd") == 75
                else self.exe if path == "/proc/811/exe" else real_stat(path, **kw))),
            (server.os, "fstat", dict(side_effect=lambda fd: self.fds[fd])),
            (server.os, "get_inheritable", dict(return_value=False)),
            (server.os, "pidfd_open", dict(return_value=72, create=True)),
            (server.os, "close", dict(side_effect=lambda fd: self.events.append(("close", fd)))),
            (server.socket, "socket", dict(return_value=self.socket)),
            (server.socket, "SO_PEERCRED", dict(new=17, create=True)),
            (server.select, "select", dict(return_value=([], [], []))))
        self.mocks = {}
        for obj, name, arguments in patches:
            self.mocks[name] = self.stack.enter_context(patch.object(obj, name, **arguments))
        self.stack.callback(self.cleanup)

    def cleanup(self):
        if hasattr(self.subject, "closed"):
            if self.subject.cleanup_failure is None:
                self.subject.close()
            else:
                with self.assertRaises(type(self.subject.cleanup_failure)):
                    self.subject.close()

    def start(self):
        self.subject.__init__(self.owner)
        return self.subject

    def test_pidfd_exceptional_liveness_refuses_before_send(self):
        subject = self.start()
        self.mocks["select"].return_value = ([], [], [72])
        with self.assertRaisesRegex(ConformanceError, "BROKER_PEER_CHANGED"):
            subject.check()
        self.socket.send.assert_not_called()

    def test_changed_process_start_time_refuses_before_send(self):
        subject = self.start()
        self.process["start"] += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_PEER_CHANGED"):
            subject.check()
        self.socket.send.assert_not_called()

    def test_socket_path_replacement_refuses_before_send(self):
        subject = self.start()
        self.path.st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_PEER_CHANGED"):
            subject.check()
        self.socket.send.assert_not_called()

    def test_inheritable_retained_descriptors_refuse_before_send(self):
        subject = self.start()
        self.mocks["get_inheritable"].side_effect = lambda fd: fd == 72
        with self.assertRaisesRegex(ConformanceError, "BROKER_DESCRIPTOR_CHANGED"):
            subject.check()
        self.socket.send.assert_not_called()

    def test_mutated_local_process_pin_is_not_new_enrollment(self):
        subject = self.start()
        subject.identity["namespaces"]["net"] += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETAINED_PEER_CHANGED"):
            subject.check()

    def test_monotonic_rollback_is_sticky(self):
        subject = self.start()
        self.now = 99
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOCK_OR_DEADLINE"):
            subject.check()
        self.now = 100
        with self.assertRaises(ConformanceError):
            subject.check()

    def test_wall_rollback_is_sticky(self):
        subject = self.start()
        self.wall = "2026-09-08T00:00:01Z"
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOCK_OR_DEADLINE"):
            subject.check()

    def test_partial_constructor_connect_error_closes_only_acquired_socket(self):
        self.socket.connect.side_effect = OSError("unit connect")
        with self.assertRaises(OSError):
            self.start()
        self.socket.close.assert_called_once()
        self.mocks["pidfd_open"].assert_not_called()
        self.owner.files.close.assert_not_called()
        self.assertTrue(self.subject.closed and self.subject.failed)

    def test_post_pidfd_acquisition_failure_keeps_cleanup_ownership(self):
        def acquired(*args):
            self.owner._base_check.side_effect = OSError("unit post acquisition")
            return 72
        self.mocks["pidfd_open"].side_effect = acquired
        with self.assertRaises(OSError):
            self.start()
        self.assertEqual(self.events.count(("close", 72)), 1)
        self.socket.close.assert_called_once()

    def test_replaced_socket_object_is_refused_and_foreign_socket_not_closed(self):
        subject = self.start()
        foreign = Mock()
        subject.sock = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETAINED_PEER_CHANGED"):
            subject.check()
        subject.close()
        self.socket.close.assert_called_once()
        foreign.close.assert_not_called()

    def test_reused_socket_descriptor_detaches_without_closing_foreign_fd(self):
        subject = self.start()
        self.fds[71].st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_DESCRIPTOR_CHANGED"):
            subject.check()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOSE_FD_REUSED"):
            subject.close()
        self.socket.detach.assert_called_once()
        self.socket.close.assert_not_called()
        self.assertEqual(self.events.count(("close", 72)), 1)

    def test_reused_pidfd_is_not_closed_and_socket_cleanup_continues(self):
        subject = self.start()
        self.fds[72].st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOSE_FD_REUSED"):
            subject.close()
        self.assertNotIn(("close", 72), self.events)
        self.socket.close.assert_called_once()

    def test_close_error_is_sticky_without_retry_and_other_cleanup_continues(self):
        subject = self.start()
        self.mocks["close"].side_effect = OSError("unit uncertain close")
        for _ in range(2):
            with self.assertRaises(OSError):
                subject.close()
        self.mocks["close"].assert_called_once_with(72)
        self.socket.close.assert_called_once()

    def test_owner_replacement_refuses_before_transport(self):
        subject = self.start()
        self.owner.broker = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_OWNER_CHANGED"):
            subject.check()
        self.socket.send.assert_not_called()


class BrokerInspectionWiringTests(unittest.TestCase):
    """Fixed channel with explicit boundary doubles, not a native startup PASS."""
    setUp = BrokerTransportCustodyTests.setUp
    cleanup = BrokerTransportCustodyTests.cleanup
    start = BrokerTransportCustodyTests.start

    def test_fixed_factory_retains_one_channel_without_sending_frames(self):
        subject = self.start()
        self.assertIsNone(subject.check())
        self.mocks["socket"].assert_called_once_with(server.socket.AF_UNIX, server.socket.SOCK_SEQPACKET)
        self.socket.connect.assert_called_once_with(server.BROKER_SOCKET)
        self.mocks["_manifest"].assert_called_once_with(self.owner.files, server.BROKER_MANIFEST, server.BROKER)
        self.owner.files._open.assert_called_once_with("/run/planeon/live-proxy", True, 0o700)
        self.socket.setsockopt.assert_called_once_with(server.socket.SOL_SOCKET, 16, 1)
        self.socket.send.assert_not_called()
        self.socket.sendmsg.assert_not_called()
        self.socket.recvmsg.assert_not_called()
        self.owner.files.read.assert_not_called()

    def test_manifest_mismatch_refuses_before_socket_or_inspector(self):
        for index in (1, 2):
            with self.subTest(digest=index):
                values = list(self.mocks["_manifest"].return_value)
                values[index] = admission.ZERO
                self.mocks["_manifest"].return_value = tuple(values)
                with self.assertRaisesRegex(ConformanceError, "BROKER_ENROLLMENT_MISMATCH"):
                    self.start()
        self.mocks["socket"].assert_not_called()
        self.containment.assert_not_called()

    def test_wrong_socket_mode_or_owner_refuses_before_connect(self):
        for field, value in (("st_mode", stat.S_IFSOCK | 0o666), ("st_uid", 1), ("st_gid", 1)):
            original = getattr(self.path, field)
            with self.subTest(field=field):
                setattr(self.path, field, value)
                with self.assertRaisesRegex(ConformanceError, "BROKER_SOCKET_CUSTODY"):
                    self.start()
                setattr(self.path, field, original)
        self.mocks["socket"].assert_not_called()

    def test_nonroot_peer_never_gets_a_pidfd_or_native_inspector(self):
        self.peer = (811, 10000, 10000)
        with self.assertRaisesRegex(ConformanceError, "BROKER_PEER_INVALID"):
            self.start()
        self.mocks["pidfd_open"].assert_not_called()
        self.containment.assert_not_called()
        self.socket.close.assert_called_once()

    def test_non_elf_peer_is_not_a_broker_wrapper_fallback(self):
        self.owner.files.raw[server.BROKER] = b"#!/bin/sh\n"
        with self.assertRaisesRegex(ConformanceError, "BROKER_NATIVE_ELF_REQUIRED"):
            self.start()
        self.containment.assert_not_called()
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)

    def test_binding_success_boolean_is_not_accepted(self):
        self.binding_check.return_value = True
        with self.assertRaisesRegex(ConformanceError, "BROKER_BINDING_CHECK_RESULT"):
            self.start()
        self.mocks["_manifest"].assert_not_called()
        self.mocks["socket"].assert_not_called()

    def test_binding_object_and_enrollment_bytes_cannot_be_replaced(self):
        subject = self.start()
        self.owner.qualification_binding._broker_raw += b" "
        with self.assertRaisesRegex(ConformanceError, "BROKER_BINDING_CHANGED"):
            subject.check()
        self.owner.qualification_binding = Mock()
        with self.assertRaises(ConformanceError):
            subject.check()
        self.socket.connect.assert_called_once()

    def test_binding_owner_replacement_refuses_before_peer_queries(self):
        subject = self.start()
        self.owner.qualification_binding = Mock()
        self.socket.getsockopt.reset_mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_OWNER_CHANGED"):
            subject.check()
        self.socket.getsockopt.assert_not_called()

    def test_server_original_channel_slot_cannot_be_rebound(self):
        subject = self.start()
        self.owner._broker_original = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_OWNER_CHANGED"):
            subject.check()

    def test_original_peer_credentials_are_rechecked_after_connection(self):
        subject = self.start()
        self.peer = (812, 0, 0)
        with self.assertRaisesRegex(ConformanceError, "BROKER_PEER_CHANGED"):
            subject.check()
        self.socket.send.assert_not_called()

    def test_executable_inode_substitution_refuses(self):
        subject = self.start()
        self.exe.st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_EXECUTABLE_CHANGED"):
            subject.check()

    def test_inspector_constructor_failure_retains_partial_cleanup(self):
        with patch.object(server._KernelBrokerInspection, "__init__", side_effect=ConformanceError("UNIT_INSPECTOR", "unit")):
            with self.assertRaisesRegex(ConformanceError, "UNIT_INSPECTOR"):
                self.start()
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)
        self.socket.send.assert_not_called()

    def test_inspector_refusal_is_sticky_without_reconnect(self):
        subject = self.start()
        self.containment.side_effect = ConformanceError("UNIT_INSPECTOR", "unit")
        with self.assertRaisesRegex(ConformanceError, "UNIT_INSPECTOR"):
            subject.check()
        self.containment.side_effect = None
        with self.assertRaisesRegex(ConformanceError, "BROKER_UNAVAILABLE"):
            subject.check()
        self.socket.connect.assert_called_once()

    def test_truthy_inspector_result_is_not_containment(self):
        self.containment.return_value = True
        with self.assertRaisesRegex(ConformanceError, "BROKER_CONTAINMENT_UNAVAILABLE"):
            self.start()
        self.socket.send.assert_not_called()

    def test_replaced_inspector_refuses_and_foreign_inspector_is_not_closed(self):
        subject = self.start()
        original, foreign = subject.inspection, Mock()
        subject.inspection = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_INSPECTION_CHANGED"):
            subject.check()
        subject.close()
        self.assertTrue(original.closed)
        foreign.close.assert_not_called()

    def test_inspector_close_error_keeps_channel_cleanup_without_retry(self):
        subject = self.start()
        with patch.object(server._KernelBrokerInspection, "close", side_effect=OSError("unit cleanup")) as closed:
            for _ in range(2):
                with self.assertRaises(OSError):
                    subject.close()
            closed.assert_called_once()
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)

    def test_late_connect_error_rechecks_budget_and_never_reconnects(self):
        def late(*args):
            self.now += 2
            raise OSError("unit late connect")
        self.socket.connect.side_effect = late
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOCK_OR_DEADLINE"):
            self.start()
        self.socket.connect.assert_called_once()
        self.socket.close.assert_called_once()
        self.mocks["pidfd_open"].assert_not_called()

    def test_timeout_setter_cannot_extend_connection_phase(self):
        self.socket.settimeout.side_effect = lambda timeout: setattr(self, "now", self.subject.end)
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOCK_OR_DEADLINE"):
            self.start()
        self.socket.connect.assert_not_called()

    def test_native_check_cannot_extend_two_second_phase(self):
        subject = self.start()
        self.containment.side_effect = lambda: setattr(self, "now", self.now + 2)
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOCK_OR_DEADLINE"):
            subject.check()
        self.assertEqual(subject.end, 102)

    def test_session_deadline_caps_later_check(self):
        subject = self.start()
        self.now = 499.5
        self.containment.side_effect = lambda: setattr(self, "now", 500)
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLOCK_OR_DEADLINE"):
            subject.check()
        self.assertEqual(subject.end, 500)

    def test_transport_refuses_bad_broker_before_observation_or_storage(self):
        self.start()
        self.owner._owner_check = Mock(return_value=None)
        self.owner.storage, self.owner.observer = Mock(), Mock()
        self.containment.side_effect = ConformanceError("UNIT_INSPECTOR", "unit")
        with self.assertRaisesRegex(ConformanceError, "UNIT_INSPECTOR"):
            server.NativeProxyServer._transport_check(self.owner)
        self.owner.storage.check.assert_not_called()
        self.owner.observer.observe.assert_not_called()

    def test_server_close_uses_only_original_broker_and_continues_after_failure(self):
        original = self.start()
        foreign = self.owner.broker = Mock()
        self.owner.closed, self.owner.memfd = False, None
        with patch.object(server._KernelBrokerInspection, "close", side_effect=OSError("unit cleanup")):
            with self.assertRaises(OSError):
                self.owner.close()
        foreign.close.assert_not_called()
        self.assertTrue(original.closed)
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)

class BrokerDispatchStartTests(unittest.TestCase):
    """Real dispatch/ledger/parser and channel; explicit installed-boundary doubles.

    No native service, worker, API, credential or durable store is exercised.
    """
    cleanup = BrokerTransportCustodyTests.cleanup
    start = BrokerTransportCustodyTests.start

    def setUp(self):
        from _fixtures import backend_fixture
        # Load signed fixture files before the transport's fd-only OS doubles.
        fixture = backend_fixture()
        BrokerTransportCustodyTests.setUp(self)
        owner = self.owner
        owner.envelope, owner.capacity, owner.plan = fixture.envelope, fixture.capacity, fixture.plan
        owner.profile = deepcopy(self.fixture["profile"])
        owner.observation_binding = deepcopy(self.fixture["observationBinding"])
        owner.active_operation = "HOST_ISOLATION_NEGATIVES"
        owner.reserved, owner.files.sealed = True, True
        owner.reservation = server.admission_binding(owner.envelope, owner.capacity, owner.profile)
        owner.storage = object.__new__(server._State)
        owner.storage.owner = owner
        owner.log = server._AdmissionLog(owner.storage)
        owner.observer = object.__new__(server._Observer)
        owner.observer.owner = owner
        self.history = []
        self.append_row("RESERVED", None)
        self.append_row("RUNNING", owner.active_operation)
        self.read_store = Mock(side_effect=lambda: self.ledger)
        self.stack.enter_context(patch.object(server._State, "read", self.read_store))
        self.observed = deepcopy(VECTORS["observation"]["positive"]["observation"])
        self.observed.update(bindingDigest=server.canonical_digest(owner.observation_binding),
            runNonce=owner.envelope["nonce"], observedAt="2026-09-08T00:00:02Z", expiresAt="2026-09-08T00:00:05Z")
        self.on_observe = lambda: None
        self.observations = []
        def observe(resource):
            self.assertIs(resource, owner.observer)
            self.on_observe()
            self.observed["sequence"] += 1
            resource.previous = deepcopy(self.observed)
            resource._previous_raw = canonical_bytes(self.observed)
            self.observations.append(deepcopy(self.observed))
            self.events.append("observe")
            return deepcopy(self.observed)
        self.stack.enter_context(patch.object(server._Observer, "observe", observe))
        self.challenge = self.stack.enter_context(patch.object(server.os, "urandom", return_value=b"\xee" * 32))
        self.socket.send.side_effect = self.send
        self.socket.recvmsg.side_effect = self.receive
        self.on_send = lambda: None
        self.on_receive = lambda: None
        self.message_peer = self.peer
        self.flags, self.extra_ancillary = 0, []
        self.start()

    def append_row(self, state, operation):
        self.history.append(dict(sequence=len(self.history) + 1,
            previousDigest=server.canonical_digest(self.history[-1]) if self.history else admission.ZERO,
            binding=deepcopy(self.owner.reservation), state=state, operation=operation,
            observedAt=self.wall, cleanup=None))
        self.ledger = b"".join(canonical_bytes(row) + b"\n" for row in self.history)

    def send(self, raw):
        self.events.append("dispatch")
        dispatch = json.loads(raw)
        self.frame = {**{k: dispatch[k] for k in admission.BROKER_COMMON},
            "schemaVersion": "planeon.internal.broker-frame/v1", "executionId": "c" * 64,
            "sequence": 1, "previousDigest": admission.ZERO, "kind": "STARTED",
            "payload": {"workerPid": 1234, "workerStartTicks": 123}}
        self.on_send()
        return len(raw)

    def receive(self, *args):
        self.events.append("receive")
        self.on_receive()
        return canonical_bytes(self.frame), [(server.socket.SOL_SOCKET, 2,
            server.struct.pack("3i", *self.message_peer)), *self.extra_ancillary], self.flags, None

    def refused(self, reason=None):
        with self.assertRaisesRegex(ConformanceError, reason or ".+"):
            self.subject.begin()
        self.assertTrue(self.subject.failed)
        if self.subject.dispatch is not None:
            self.assertIsNone(self.subject.dispatch.started)

    def test_dispatch_is_derived_from_owned_running_record_and_fresh_observation(self):
        self.assertIsNone(self.subject.begin())
        value = json.loads(self.socket.send.call_args.args[0])
        expected = server.build_probe_request(self.owner.envelope, self.owner.capacity, self.owner.plan,
                                             self.owner.active_operation)
        self.assertEqual(value["requestDigest"], server.canonical_digest(expected))
        self.assertEqual(value["reservationDigest"], server.canonical_digest(self.owner.reservation))
        self.assertEqual(value["bindingDigest"], server.canonical_digest(self.fixture["binding"]))
        self.assertEqual(value["observationDigest"], server.canonical_digest(self.observations[0]))
        self.assertEqual(value["challenge"], "ee" * 32)
        self.assertEqual(value["operation"], "EXECUTE_FIXED_PROBE")
        self.assertEqual(json.loads(self.subject.dispatch.started), self.frame)
        self.assertIs(self.subject.dispatch.transcript, self.subject.dispatch._transcript_original)
        with self.assertRaises(ConformanceError):
            self.subject.dispatch.transcript.receipt()
        self.socket.send.assert_called_once()
        self.socket.recvmsg.assert_called_once()
        self.assertEqual(self.events.count("dispatch"), 1)
        self.assertGreaterEqual(self.events.count("observe"), 4)
        self.owner.files.read.assert_not_called()

    def test_begin_accepts_no_caller_request_backend_or_observation(self):
        for value in ({}, True, self.fixture["request"], Mock()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.begin(value)
        self.socket.send.assert_not_called()

    def test_reserved_without_running_cannot_dispatch(self):
        self.ledger = canonical_bytes(self.history[0]) + b"\n"
        self.refused("BROKER_RUNNING_REQUIRED")
        self.socket.send.assert_not_called()

    def test_future_running_timestamp_is_not_current_admission(self):
        self.history[-1]["observedAt"] = "2026-09-08T00:00:04Z"
        self.ledger = b"".join(canonical_bytes(row) + b"\n" for row in self.history)
        self.refused("BROKER_RUNNING_REQUIRED")
        self.socket.send.assert_not_called()

    def test_wrong_running_operation_cannot_dispatch(self):
        self.owner.active_operation = "LINUX_TARGET_BUILD"
        self.refused("BROKER_RUNNING_REQUIRED")
        self.socket.send.assert_not_called()

    def test_foreign_tenant_cannot_reuse_running_history(self):
        self.owner.envelope["tenantId"] = "foreign-tenant"
        self.refused("BROKER_RUNNING_REQUIRED")
        self.socket.send.assert_not_called()

    def test_unsealed_server_registry_denies_dispatch(self):
        self.owner.files.sealed = False
        self.refused("BROKER_START_STATE_CHANGED")
        self.socket.send.assert_not_called()

    def test_poisoned_durable_log_denies_dispatch(self):
        self.owner.log.poisoned = True
        self.refused("BROKER_START_STATE_CHANGED")
        self.socket.send.assert_not_called()

    def test_unowned_store_or_observer_cannot_supply_prerequisites(self):
        self.owner.storage = Mock()
        self.refused("BROKER_START_PREREQUISITES")
        self.socket.send.assert_not_called()

    def test_replayed_begin_cannot_reuse_started_exchange(self):
        self.subject.begin()
        first = self.subject.dispatch.started
        with self.assertRaisesRegex(ConformanceError, "BROKER_DISPATCH_ALREADY_OWNED"):
            self.subject.begin()
        self.assertTrue(self.subject.failed)
        self.assertEqual(self.subject.dispatch.started, first)
        self.socket.send.assert_called_once()

    def test_attempted_case_cannot_be_restarted_through_a_reset_slot(self):
        self.subject._attempted_cases.add(self.owner.active_operation)
        self.refused("BROKER_DISPATCH_REPLAY")
        self.socket.send.assert_not_called()

    def test_record_drift_during_observation_denies_before_send(self):
        self.on_observe = lambda: setattr(self, "ledger", self.ledger + b" ")
        self.refused("BROKER_RUNNING_CHANGED")
        self.socket.send.assert_not_called()

    def test_reservation_flag_drift_during_observation_denies_before_send(self):
        self.on_observe = lambda: setattr(self.owner, "reserved", False)
        self.refused("BROKER_START_STATE_CHANGED")
        self.socket.send.assert_not_called()

    def test_generation_drift_is_not_refreshed_into_new_dispatch(self):
        def drift():
            if self.observations:
                self.observed["generation"] = "f" * 64
        self.on_observe = drift
        self.refused("BROKER_GENERATION_CHANGED")
        self.socket.send.assert_not_called()

    def test_observer_restart_during_response_refuses(self):
        self.on_receive = lambda: self.observed.update(observerBootId="changed")
        self.refused("BROKER_GENERATION_CHANGED")

    def test_expired_observation_never_sends(self):
        self.observed["expiresAt"] = "2026-09-08T00:00:02Z"
        self.refused("BROKER_OBSERVATION_EXPIRED")
        self.socket.send.assert_not_called()

    def test_subsecond_runtime_clock_accepts_current_whole_second_observation(self):
        self.wall = "2026-09-08T00:00:02.125000Z"
        self.subject.begin()
        self.assertEqual(json.loads(self.subject.dispatch.started), self.frame)
        self.socket.send.assert_called_once()

    def test_fractional_wire_observation_is_not_relaxed_with_runtime_clock(self):
        self.observed["observedAt"] = "2026-09-08T00:00:02.000000Z"
        self.refused("PROXY_TIME_INVALID")
        self.socket.send.assert_not_called()

    def test_foreign_observation_nonce_never_sends(self):
        self.observed["runNonce"] = "foreign-nonce"
        self.refused("BROKER_OBSERVATION_BINDING")
        self.socket.send.assert_not_called()

    def test_invalid_random_challenge_never_sends(self):
        self.challenge.return_value = b"short"
        self.refused("BROKER_CHALLENGE_INVALID")
        self.socket.send.assert_not_called()

    def test_partial_send_is_consumed_without_receive_or_retry(self):
        self.socket.send.side_effect = lambda raw: len(raw) - 1
        self.refused("BROKER_SEND_AMBIGUOUS")
        self.assertIn(self.owner.active_operation, self.subject._attempted_cases)
        self.socket.recvmsg.assert_not_called()
        with self.assertRaises(ConformanceError):
            self.subject.begin()
        self.socket.send.assert_called_once()

    def test_send_exception_keeps_post_io_observation_and_no_retry(self):
        def fail(raw):
            self.events.append("failed-send")
            raise TimeoutError("unit ambiguous dispatch")
        self.socket.send.side_effect = fail
        with self.assertRaises(TimeoutError):
            self.subject.begin()
        self.assertIn("observe", self.events[self.events.index("failed-send") + 1:])
        self.assertTrue(self.subject.failed)
        self.socket.recvmsg.assert_not_called()

    def test_receive_timeout_is_not_a_new_handshake(self):
        self.socket.recvmsg.side_effect = TimeoutError("unit control timeout")
        with self.assertRaises(TimeoutError):
            self.subject.begin()
        self.assertTrue(self.subject.failed)
        self.socket.recvmsg.assert_called_once()
        self.socket.send.assert_called_once()

    def test_changed_kernel_peer_after_receive_refuses(self):
        self.on_receive = lambda: setattr(self, "peer", (812, 0, 0))
        self.refused("BROKER_PEER_CHANGED")

    def test_message_credentials_must_match_original_peer(self):
        self.message_peer = (812, 0, 0)
        self.refused("BROKER_MESSAGE_PEER")

    def test_received_rights_are_drained_before_post_io_authority_failure(self):
        self.extra_ancillary = [(server.socket.SOL_SOCKET, server.socket.SCM_RIGHTS, server.struct.pack("i", 99))]
        self.on_receive = lambda: setattr(self.owner._base_check, "side_effect", ConformanceError("UNIT_REVOKED", "unit"))
        self.refused()
        self.assertEqual(self.events.count(("close", 99)), 1)

    def test_truncated_datagram_never_becomes_started(self):
        self.flags = server.socket.MSG_TRUNC
        self.refused("PEER_CHANNEL_INVALID")

    def test_duplicate_credentials_never_become_started(self):
        self.extra_ancillary = [(server.socket.SOL_SOCKET, 2, server.struct.pack("3i", *self.peer))]
        self.refused("PEER_CHANNEL_INVALID")

    def test_wrong_challenge_echo_never_becomes_started(self):
        self.on_receive = lambda: self.frame.update(challenge="a" * 64)
        self.refused("BROKER_TRANSCRIPT_BINDING")

    def test_skipped_first_sequence_is_rejected(self):
        self.on_receive = lambda: self.frame.update(sequence=2)
        self.refused("BROKER_TRANSCRIPT_BINDING")

    def test_first_resource_action_is_not_controlled_start(self):
        self.on_receive = lambda: self.frame.update(kind="RESOURCE_ACTION",
            payload={"actionId": 1, "verb": "GET", "manifestDigest": admission.ZERO})
        self.refused("BROKER_CONTROLLED_START_REQUIRED")

    def test_oversize_response_is_bounded_before_parsing(self):
        self.socket.recvmsg.side_effect = lambda *args: (b" " * 65537,
            [(server.socket.SOL_SOCKET, 2, server.struct.pack("3i", *self.peer))], 0, None)
        self.refused()

    def test_complete_handshake_budget_includes_observation(self):
        self.on_observe = lambda: setattr(self, "now", self.now + 0.5)
        self.refused("BROKER_CLOCK_OR_DEADLINE")
        self.assertEqual(self.subject.end, 102)

    def test_late_received_frame_does_not_extend_deadline(self):
        self.on_receive = lambda: setattr(self, "now", self.subject.end)
        self.refused("BROKER_CLOCK_OR_DEADLINE")

    def test_failed_native_inspection_prevents_dispatch(self):
        self.containment.side_effect = ConformanceError("UNIT_NATIVE_REFUSAL", "unit")
        self.refused("UNIT_NATIVE_REFUSAL")
        self.socket.send.assert_not_called()

    def test_last_phase_guard_failure_cannot_publish_started(self):
        def guard():
            current = self.subject.dispatch
            if current is not None and hasattr(current, "_started_raw"):
                raise ConformanceError("UNIT_LAST_GUARD", "unit")
        self.owner._base_check.side_effect = guard
        self.refused("UNIT_LAST_GUARD")

    def test_observer_replacement_after_send_is_not_adopted(self):
        self.on_send = lambda: setattr(self.owner, "observer", Mock())
        self.refused("BROKER_START_STATE_CHANGED")
        self.socket.recvmsg.assert_not_called()

    def test_durable_record_is_not_written_or_repaired_by_dispatch(self):
        original = self.ledger
        with patch.object(server._State, "append") as append, patch.object(server._State, "sync") as sync:
            self.subject.begin()
        append.assert_not_called()
        sync.assert_not_called()
        self.assertEqual(self.ledger, original)

    def test_failed_start_closes_original_channel_but_not_borrowed_store(self):
        self.message_peer = (812, 0, 0)
        with patch.object(server._State, "close") as store_close:
            self.refused("BROKER_MESSAGE_PEER")
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)
        self.owner.files.close.assert_not_called()
        store_close.assert_not_called()



class _BrokerEventFixture:
    """Actual handshake/receiver/parser; installed OS/store/observer doubles only."""
    profile_index = 1
    cleanup = BrokerDispatchStartTests.cleanup
    append_row = BrokerDispatchStartTests.append_row
    send = BrokerDispatchStartTests.send
    receive = BrokerDispatchStartTests.receive

    def start(self):
        # Enroll the selected fixture BEFORE the real broker constructor pins it.
        self.fixture = deepcopy(VECTORS["broker"]["positive"][self.profile_index])
        owner = self.owner
        owner.profile = deepcopy(self.fixture["profile"])
        owner.observation_binding = deepcopy(self.fixture["observationBinding"])
        owner.reservation = server.admission_binding(owner.envelope, owner.capacity, owner.profile)
        owner.qualification_binding._broker_raw = canonical_bytes(self.fixture["binding"])
        self.history = []
        self.append_row("RESERVED", None)
        self.append_row("RUNNING", owner.active_operation)
        self.observed["bindingDigest"] = server.canonical_digest(owner.observation_binding)
        return BrokerTransportCustodyTests.start(self)

    def setUp(self):
        BrokerDispatchStartTests.setUp(self)
        self.subject.begin()
        self.last_event = deepcopy(self.frame)
        self.socket.send.reset_mock()
        self.socket.recvmsg.reset_mock()
        self.ready, self.waits = True, []
        self.on_wait = self.on_event = lambda: None
        self.raw_override = None
        self.mocks["select"].side_effect = self.select
        self.socket.recvmsg.side_effect = self.event_receive
        self.chunk(0, b"unit receipt bytes")

    def select(self, readers, writers, exceptional, timeout):
        if readers == [self.socket]:
            self.events.append("event-wait")
            self.waits.append(timeout)
            self.on_wait()
            return ([self.socket] if self.ready else [], [], [])
        self.assertEqual((readers, writers, exceptional, timeout), ([72], [], [72], 0))
        return [], [], []

    def event_receive(self, *args):
        self.events.append("event-receive")
        self.on_event()
        raw = self.raw_override if self.raw_override is not None else canonical_bytes(self.event_frame)
        return raw, [(server.socket.SOL_SOCKET, 2, server.struct.pack("3i", *self.message_peer)),
                     *self.extra_ancillary], self.flags, None

    def queue(self, kind, payload):
        self.event_frame = {**deepcopy(self.last_event), "sequence": self.last_event["sequence"] + 1,
            "previousDigest": server.canonical_digest(self.last_event), "kind": kind, "payload": payload}

    def chunk(self, index, raw):
        import base64
        self.queue("RECEIPT_CHUNK", {"index": index, "dataBase64": base64.b64encode(raw).decode("ascii")})

    def action(self, digest=None):
        digest = digest or self.fixture["binding"]["caseResourceDigests"][self.owner.active_operation][0]
        self.queue("RESOURCE_ACTION", {"actionId": 1, "verb": "GET", "manifestDigest": digest})

    def take(self):
        raw = self.subject.poll()
        if raw is not None:
            self.last_event = json.loads(raw)
        return raw

    def refused(self, reason):
        with self.assertRaisesRegex(ConformanceError, reason):
            self.subject.poll()
        self.assertTrue(self.subject.failed)
        if self.subject.events is not None:
            self.assertTrue(self.subject.events.failed)


class BrokerEventTests(_BrokerEventFixture, unittest.TestCase):
    def test_one_chunk_is_immutable_data_not_a_complete_receipt_or_action(self):
        raw = self.take()
        self.assertIs(type(raw), bytes)
        self.assertEqual(raw, canonical_bytes(self.event_frame))
        self.assertEqual(self.subject.events.transcript.chunks, [b"unit receipt bytes"])
        self.socket.send.assert_not_called()
        self.owner.files.read.assert_not_called()
        self.socket.recvmsg.assert_called_once()
        with self.assertRaises(ConformanceError):
            self.subject.events.transcript.receipt()

    def test_contiguous_chunks_use_the_single_retained_transcript(self):
        self.take()
        original = self.subject.events
        self.chunk(1, b"second")
        self.take()
        self.assertIs(self.subject.events, original)
        self.assertIs(original.transcript, self.subject.dispatch.transcript)
        self.assertEqual(original.transcript.chunks, [b"unit receipt bytes", b"second"])
        self.assertEqual(original.transcript.sequence, 3)

    def test_idle_wait_returns_none_without_resend_or_consumption(self):
        self.ready = False
        before = self.subject.dispatch.transcript.sequence
        self.assertIsNone(self.take())
        self.assertEqual(self.subject.dispatch.transcript.sequence, before)
        self.assertEqual(self.waits, [0.25])
        self.socket.send.assert_not_called()
        self.socket.recvmsg.assert_not_called()
        self.assertFalse(self.subject.failed)

    def test_idle_then_event_keeps_original_deadline_and_channel(self):
        self.ready = False
        self.take()
        self.now += 1
        self.ready = True
        self.take()
        self.assertEqual(self.subject.events.deadline, 500)
        self.assertEqual(self.subject.deadline, 500)
        self.socket.send.assert_not_called()
        self.assertIs(self.subject.sock, self.socket)

    def test_session_expiry_cannot_be_extended_by_polling(self):
        self.ready = False
        self.take()
        self.now = self.owner.deadline
        self.refused("BROKER_CLOCK_OR_DEADLINE")
        self.socket.recvmsg.assert_not_called()

    def test_wait_budget_leaves_room_inside_short_remaining_lifetime(self):
        self.now = 499.75
        self.ready = False
        self.take()
        self.assertEqual(self.waits, [0.125])
        self.assertEqual(self.subject.end, 500)

    def test_late_readiness_result_is_rejected(self):
        self.on_wait = lambda: setattr(self, "now", self.subject.end)
        self.refused("BROKER_CLOCK_OR_DEADLINE")
        self.socket.recvmsg.assert_not_called()

    def test_late_received_event_is_not_returned(self):
        self.on_event = lambda: setattr(self, "now", self.subject.end)
        self.refused("BROKER_CLOCK_OR_DEADLINE")

    def test_poll_does_not_accept_caller_backend_frame_or_timeout(self):
        for value in ({}, Mock(), b"frame", 900):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.poll(value)
        self.socket.recvmsg.assert_not_called()

    def test_start_observation_must_still_be_the_original_bytes(self):
        self.subject.dispatch.started = b"{}"
        self.refused("BROKER_STARTED_REQUIRED")
        self.socket.recvmsg.assert_not_called()

    def test_initial_transcript_tampering_cannot_bootstrap_a_receiver(self):
        self.subject.dispatch.transcript.sequence = 8
        self.refused("BROKER_TRANSCRIPT_CHANGED")
        self.socket.recvmsg.assert_not_called()

    def test_transcript_replacement_is_not_adopted(self):
        self.ready = False
        self.take()
        self.subject.dispatch.transcript = Mock()
        self.refused("BROKER_EVENTS_OWNER_CHANGED")

    def test_retained_transcript_scalar_mutation_is_detected(self):
        self.take()
        self.subject.events.transcript.sequence += 1
        self.refused("BROKER_TRANSCRIPT_CHANGED")

    def test_retained_chunk_mutation_is_detected(self):
        self.take()
        self.subject.events.transcript.chunks[0] = b"changed"
        self.refused("BROKER_TRANSCRIPT_CHANGED")

    def test_retained_binding_mutation_is_detected(self):
        self.take()
        self.subject.events.transcript.binding["profileDigest"] = admission.ZERO
        self.refused("BROKER_TRANSCRIPT_CHANGED")

    def test_unknown_transcript_attribute_is_rejected(self):
        self.take()
        self.subject.events.transcript.extra = True
        self.refused("BROKER_TRANSCRIPT_STATE")

    def test_replaced_event_owner_is_not_adopted_or_closed(self):
        self.ready = False
        self.take()
        original, foreign = self.subject.events, Mock()
        self.subject.events = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_EVENTS_OWNER_CHANGED"):
            self.subject.poll()
        self.assertTrue(original.failed)
        foreign.close.assert_not_called()

    def test_valid_action_is_data_and_blocks_a_second_receive_until_response(self):
        self.action()
        self.assertEqual(json.loads(self.take())["kind"], "RESOURCE_ACTION")
        self.assertEqual(self.subject.events.transcript.pending, self.event_frame["payload"])
        self.refused("BROKER_RESOURCE_RESULT_REQUIRED")
        self.socket.recvmsg.assert_called_once()
        self.socket.send.assert_not_called()
        self.owner.files.read.assert_not_called()

    def test_unknown_manifest_action_is_rejected(self):
        self.action(admission.ZERO)
        self.refused("BROKER_RESOURCE_ACTION_INVALID")

    def test_action_after_receipt_chunks_is_rejected(self):
        self.take()
        self.action()
        self.refused("BROKER_RESOURCE_ACTION_INVALID")

    def test_duplicate_chunk_sequence_is_rejected(self):
        self.take()
        self.refused("BROKER_TRANSCRIPT_BINDING")

    def test_skipped_chunk_index_is_rejected(self):
        self.chunk(1, b"skip")
        self.refused("BROKER_CHUNK_ORDER")

    def test_changed_challenge_is_rejected(self):
        self.event_frame["challenge"] = "a" * 64
        self.refused("BROKER_TRANSCRIPT_BINDING")

    def test_changed_previous_digest_is_rejected(self):
        self.event_frame["previousDigest"] = admission.ZERO
        self.refused("BROKER_TRANSCRIPT_BINDING")

    def test_changed_execution_id_is_rejected(self):
        self.event_frame["executionId"] = "d" * 64
        self.refused("BROKER_EXECUTION_REPLAY")

    def test_oversized_decoded_chunk_is_rejected(self):
        self.chunk(0, b"x" * 24577)
        self.refused("PROXY_SHAPE_INVALID")  # encoded size already violates the closed wire schema

    def test_chunk_index_outside_wire_schema_is_rejected(self):
        self.chunk(171, b"x")
        self.refused("PROXY_SHAPE_INVALID")

    def test_at_most_171_chunks_even_when_total_bytes_are_small(self):
        for index in range(171):
            self.chunk(index, b"x")
            self.take()
        self.assertEqual(len(self.subject.events.transcript.chunks), 171)
        # A schema-valid index reaches the independent transport count guard.
        self.chunk(170, b"x")
        self.refused("BROKER_RECEIPT_CHUNK_LIMIT")

    def test_full_receipt_size_limit_applies_to_transport(self):
        for index in range(170):
            self.chunk(index, b"x" * 24576)
            self.take()
        self.chunk(170, b"x" * 24576)
        self.refused("BROKER_RECEIPT_SIZE")

    def test_terminal_cannot_bypass_unimplemented_server_cleanup(self):
        payload = deepcopy(self.fixture["frames"][-1]["payload"])
        self.assertTrue(payload["workerReaped"])
        self.queue("TERMINAL", payload)
        self.refused("BROKER_INBOUND_KIND_UNAVAILABLE")

    def test_terminal_without_worker_reaping_field_is_rejected(self):
        payload = deepcopy(self.fixture["frames"][-1]["payload"])
        del payload["workerReaped"]
        self.queue("TERMINAL", payload)
        self.refused("PROXY_SHAPE_INVALID")

    def test_replayed_started_frame_cannot_reset_the_stream(self):
        self.event_frame = deepcopy(self.last_event)
        self.refused("BROKER_INBOUND_KIND_UNAVAILABLE")

    def test_unsolicited_server_result_is_rejected(self):
        self.queue("RESOURCE_RESULT", {"actionId": 1, "outcome": "ABSENT", "objectBase64": None})
        self.refused("BROKER_INBOUND_KIND_UNAVAILABLE")

    def test_wrong_message_credentials_are_rejected(self):
        self.message_peer = (812, 0, 0)
        self.refused("BROKER_MESSAGE_PEER")

    def test_received_rights_are_closed_even_when_post_guard_refuses(self):
        self.extra_ancillary = [(server.socket.SOL_SOCKET, server.socket.SCM_RIGHTS, server.struct.pack("i", 99))]
        self.on_event = lambda: setattr(self.owner._base_check, "side_effect", ConformanceError("UNIT_REVOKED", "unit"))
        self.refused("UNIT_REVOKED")
        self.assertEqual(self.events.count(("close", 99)), 1)

    def test_truncated_message_is_rejected(self):
        self.flags = server.socket.MSG_TRUNC
        self.refused("PEER_CHANNEL_INVALID")

    def test_oversize_datagram_is_rejected(self):
        self.raw_override = b"x" * 65537
        self.refused("PROXY_DATA_SIZE")

    def test_eof_is_not_idle_or_a_complete_receipt(self):
        self.raw_override = b""
        self.refused("PROXY_DATA_SIZE")

    def test_receive_timeout_after_readiness_is_not_retried(self):
        self.socket.recvmsg.side_effect = TimeoutError("unit lost readiness")
        with self.assertRaises(TimeoutError):
            self.subject.poll()
        self.assertTrue(self.subject.failed)
        self.socket.recvmsg.assert_called_once()
        self.socket.send.assert_not_called()

    def test_readiness_exception_keeps_post_wait_guards(self):
        def fail():
            self.events.append("wait-failed")
            raise OSError("unit readiness")
        self.on_wait = fail
        with self.assertRaises(OSError):
            self.subject.poll()
        self.assertIn("observe", self.events[self.events.index("wait-failed") + 1:])
        self.assertTrue(self.subject.failed)

    def test_foreign_readiness_descriptor_is_rejected(self):
        original = self.mocks["select"].side_effect
        self.mocks["select"].side_effect = lambda r, w, e, t: ([Mock()], [], []) if r == [self.socket] else original(r, w, e, t)
        self.refused("BROKER_READINESS_INVALID")

    def test_generation_change_while_idle_is_rejected(self):
        self.ready = False
        self.on_wait = lambda: self.observed.update(generation="f" * 64)
        self.refused("BROKER_GENERATION_CHANGED")

    def test_journal_change_during_receive_is_rejected(self):
        self.on_event = lambda: setattr(self, "ledger", self.ledger + b" ")
        self.refused("BROKER_RUNNING_CHANGED")

    def test_native_peer_change_after_readiness_is_rejected(self):
        self.on_wait = lambda: setattr(self, "peer", (812, 0, 0))
        self.refused("BROKER_PEER_CHANGED")

    def test_last_phase_guard_failure_does_not_return_an_event(self):
        def guard():
            current = self.subject.events
            if current is not None and hasattr(current, "transcript_raw") and current.transcript.sequence == 2:
                # receive's own post-parse checks also refuse before publication.
                raise ConformanceError("UNIT_LAST_GUARD", "unit")
        self.owner._base_check.side_effect = guard
        self.refused("UNIT_LAST_GUARD")

    def test_poll_never_writes_or_releases_durable_state(self):
        original = self.ledger
        with patch.object(server._State, "append") as append, patch.object(server._State, "sync") as sync:
            self.take()
        append.assert_not_called()
        sync.assert_not_called()
        self.assertEqual(self.ledger, original)

    def test_failure_closes_original_channel_not_borrowed_store(self):
        self.message_peer = (812, 0, 0)
        with patch.object(server._State, "close") as store_close:
            self.refused("BROKER_MESSAGE_PEER")
        self.socket.close.assert_called_once()
        self.owner.files.close.assert_not_called()
        store_close.assert_not_called()


class BrokerZeroResourceEventTests(_BrokerEventFixture, unittest.TestCase):
    profile_index = 0

    def test_zero_resource_profile_refuses_actions_without_api_or_credentials(self):
        self.action(admission.ZERO)
        self.refused("BROKER_RESOURCE_ACTION_INVALID")
        self.socket.send.assert_not_called()
        self.owner.files.read.assert_not_called()


class BrokerIntentTests(_BrokerEventFixture, unittest.TestCase):
    """Real broker/event/intent/journal code; explicit OS and storage doubles."""
    def start(self):
        # Align these unit-only inputs BEFORE the real broker pins its request,
        # reservation and observation. Keep all predecessor fixtures untouched.
        nonce = VECTORS["broker"]["positive"][self.profile_index]["profile"]["binding"]["runNonce"]
        self.owner.envelope["nonce"] = self.observed["runNonce"] = nonce
        return _BrokerEventFixture.start(self)

    def setUp(self):
        from contextlib import contextmanager
        _BrokerEventFixture.setUp(self)
        self.action()
        self.event_frame["payload"]["verb"] = "CREATE"
        self.take()
        self.original_history = self.ledger
        self.io_events, self.writes = [], []
        self.locked = False
        self.fail = None
        self.on_lock = self.on_append = self.on_sync = self.on_exit = lambda: None
        self.on_read = lambda: None
        @contextmanager
        def transaction(resource):
            self.assertIs(resource, self.owner.storage)
            if self.locked:
                raise ConformanceError("UNIT_STORAGE_BUSY", "unit contention")
            self.locked = True
            self.io_events.append("lock")
            try:
                self.on_lock()
                yield resource
            finally:
                self.io_events.append("unlock")
                self.locked = False
                self.on_exit()
        self.stack.enter_context(patch.object(server._State, "transaction", transaction))
        self.append_call = self.stack.enter_context(patch.object(server._State, "append", side_effect=self.append_intent))
        self.sync_call = self.stack.enter_context(patch.object(server._State, "sync", side_effect=self.sync_intent))
        self.read_store.side_effect = self.read_intent
        self.socket.send.reset_mock()
        self.socket.recvmsg.reset_mock()

    def read_intent(self):
        self.io_events.append("read")
        self.on_read()
        return self.ledger

    def append_intent(self, raw):
        self.io_events.append("append")
        self.on_append()
        if self.fail == "before":
            raise OSError("unit before append")
        if self.fail == "partial":
            self.ledger += raw[:20]
            raise OSError("unit torn append")
        self.ledger += raw
        self.writes.append(raw)
        if self.fail == "after":
            raise OSError("unit after append")

    def sync_intent(self):
        self.io_events.append("fsync")
        self.on_sync()
        if self.fail == "sync":
            raise OSError("unit fsync ambiguity")
        if self.fail == "readback":
            self.ledger += b"corrupt"

    def refuse_intent(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason):
            self.subject.record_create_intent()
        self.assertTrue(self.subject.closed and self.subject.failed)
        self.assertTrue(self.subject._intent_original is None or self.subject._intent_original.failed)
        self.socket.send.assert_not_called()
        self.owner.files.read.assert_not_called()

    def held(self):
        return admission.parse_reservations(self.ledger)[0][(self.owner.envelope["tenantId"], self.owner.envelope["nonce"])]

    def test_bound_create_intent_commits_before_retained_history_advances(self):
        seen = []
        self.on_append = lambda: seen.append(self.subject.dispatch.ledger_raw)
        self.on_sync = lambda: seen.append(self.subject.dispatch.ledger_raw)
        self.assertIsNone(self.subject.record_create_intent())
        intent = self.subject.intent
        self.assertEqual(seen, [self.original_history, self.original_history])
        self.assertTrue(intent.committed and intent.advanced)
        self.assertIs(intent, self.subject._intent_original)
        self.assertEqual(self.subject.dispatch.ledger_raw, intent.after)
        self.assertEqual(self.ledger, intent.after)
        row = json.loads(self.writes[0])
        self.assertEqual(row["state"], "CREATE_INTENT")
        self.assertEqual(row["resource"]["manifestDigest"], self.event_frame["payload"]["manifestDigest"])
        self.assertIsNone(row["resource"]["uid"])
        self.assertIsNone(row["resource"]["resourceVersion"])
        self.assertEqual(self.io_events[self.io_events.index("lock"):self.io_events.index("unlock") + 1],
                         ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertTrue(self.held()["held"])

    def test_committed_intent_rechecks_original_live_owners_without_more_writes(self):
        self.subject.record_create_intent()
        before = self.ledger
        observations = len(self.observations)
        self.assertIsNone(self.subject.intent.check())
        self.assertGreater(len(self.observations), observations)
        self.assertEqual(self.ledger, before)
        self.assertEqual(len(self.writes), 1)
        self.socket.send.assert_not_called()

    def test_method_accepts_no_caller_resource_history_or_backend(self):
        for value in ({}, self.original_history, self.event_frame, Mock()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.record_create_intent(value)
        self.assertEqual(self.io_events, [])
        self.assertIsNone(self.subject.intent)

    def test_unowned_constructor_cannot_append(self):
        with self.assertRaisesRegex(ConformanceError, "BROKER_INTENT_OWNER"):
            server._BrokerIntent(self.subject)
        self.assertEqual(self.io_events, [])

    def test_missing_event_owner_refuses_before_write(self):
        self.subject.events = self.subject._events_original = None
        self.refuse_intent("BROKER_INTENT_EVENTS_REQUIRED")
        self.assertEqual(self.writes, [])

    def test_get_action_cannot_be_promoted_to_create_intent(self):
        # Rebuild the legitimate GET transcript before asking for an intent.
        original = self.subject.events
        transcript = admission.BrokerTranscript(original.binding_raw, original.dispatch_raw)
        transcript.accept(original.started_raw, "BROKER")
        frame = deepcopy(self.event_frame)
        frame["payload"]["verb"] = "GET"
        transcript.accept(frame, "BROKER")
        original.transcript = self.subject.dispatch.transcript = self.subject.dispatch._transcript_original = transcript
        original.transcript_raw = original._snapshot(transcript)
        self.refuse_intent("BROKER_CREATE_INTENT_REQUIRED")
        self.assertEqual(self.writes, [])

    def test_changed_pending_action_is_not_accepted_as_new_scope(self):
        self.subject.events.transcript.pending["manifestDigest"] = admission.ZERO
        self.refuse_intent("BROKER_TRANSCRIPT_CHANGED")
        self.assertEqual(self.writes, [])

    def test_stale_running_history_is_not_adopted(self):
        self.ledger = self.original_history + b"unknown"
        self.refuse_intent("BROKER_RUNNING_CHANGED")
        self.assertEqual(self.writes, [])

    def test_foreign_store_is_never_used(self):
        foreign = self.owner.storage = Mock()
        self.refuse_intent("BROKER_START_STATE_CHANGED")
        foreign.read.assert_not_called()
        foreign.transaction.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_foreign_log_is_never_used(self):
        foreign = self.owner.log = Mock()
        self.refuse_intent("BROKER_START_STATE_CHANGED")
        foreign.record_resource.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_instance_shadow_writer_is_not_an_execution_hook(self):
        self.owner.log.record_resource = Mock(side_effect=AssertionError("untrusted shadow must not run"))
        self.subject.record_create_intent()
        self.owner.log.record_resource.assert_not_called()
        self.assertEqual(len(self.writes), 1)

    def test_revoked_generation_before_write_prevents_append(self):
        self.on_observe = lambda: self.observed.update(generation="f" * 64)
        self.refuse_intent("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.writes, [])

    def test_expired_operation_prevents_append(self):
        self.now = self.subject.deadline
        self.refuse_intent("BROKER_CLOCK_OR_DEADLINE")
        self.assertEqual(self.writes, [])

    def test_expired_observation_prevents_append(self):
        self.observed["expiresAt"] = "2026-09-08T00:00:02Z"
        self.refuse_intent("BROKER_OBSERVATION_EXPIRED")
        self.assertEqual(self.writes, [])

    def test_peer_identity_loss_prevents_append(self):
        self.process["start"] += 1
        self.refuse_intent("BROKER_PEER_CHANGED")
        self.assertEqual(self.writes, [])

    def test_all_write_ambiguities_poison_without_retry_or_pin_advance(self):
        # Separate fresh fixture/ExitStack per fault; all original tests remain.
        for fault in ("before", "partial", "after", "sync", "readback"):
            with self.subTest(fault=fault):
                self.fail = fault
                self.refuse_intent()
                intent = self.subject._intent_original
                self.assertTrue(self.owner.log.poisoned)
                self.assertFalse(intent.committed or intent.advanced)
                self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)
                attempts = self.append_call.call_count
                with self.assertRaises(ConformanceError):
                    self.subject.record_create_intent()
                self.assertEqual(self.append_call.call_count, attempts)
            if fault != "readback":
                self.stack.close()
                self.setUp()

    def test_fsync_revocation_retains_intent_but_never_publishes_success(self):
        self.on_sync = lambda: self.observed.update(generation="f" * 64)
        self.refuse_intent("BROKER_GENERATION_CHANGED")
        self.assertEqual(len(self.writes), 1)
        self.assertTrue(self.held()["held"])
        self.assertTrue(self.owner.log.poisoned)
        self.assertFalse(self.subject.intent.committed)

    def test_late_transaction_cannot_extend_two_second_phase(self):
        self.on_sync = lambda: setattr(self, "now", self.subject.end)
        self.refuse_intent("BROKER_CLOCK_OR_DEADLINE")
        self.assertEqual(len(self.writes), 1)
        self.assertFalse(self.subject.intent.committed or self.subject.intent.advanced)
        self.assertTrue(self.owner.log.poisoned)

    def test_lock_contention_refuses_without_append(self):
        self.locked = True
        self.refuse_intent("UNIT_STORAGE_BUSY")
        self.assertEqual(self.writes, [])

    def test_history_changed_under_lock_is_not_accepted(self):
        self.on_lock = lambda: setattr(self, "ledger", self.ledger + b"unexpected")
        self.refuse_intent("ADMISSION_RESOURCE_HISTORY_CHANGED")
        self.assertEqual(self.writes, [])
        self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)

    def test_unlock_failure_is_ambiguous_after_durable_write(self):
        def fail():
            raise OSError("unit unlock ambiguity")
        self.on_exit = fail
        self.refuse_intent("unit unlock ambiguity")
        self.assertEqual(len(self.writes), 1)
        self.assertTrue(self.owner.log.poisoned)
        self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)

    def test_post_transaction_extra_bytes_refuse_without_repin(self):
        self.on_exit = lambda: setattr(self, "ledger", self.ledger + b"unexpected")
        self.refuse_intent("BROKER_INTENT_READBACK_MISMATCH")
        self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)
        self.assertTrue(self.owner.log.poisoned)

    def test_fake_commit_digest_without_write_is_not_durable_evidence(self):
        with patch.object(server._AdmissionLog, "record_resource", side_effect=lambda *a, **k: self.subject.intent.digest):
            self.refuse_intent("BROKER_INTENT_READBACK_MISMATCH")
        self.assertEqual(self.writes, [])
        self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)

    def test_wrong_commit_result_refuses_even_when_original_append_happened(self):
        original = server._AdmissionLog.record_resource
        def wrong(*args, **kwargs):
            original(*args, **kwargs)
            return admission.ZERO
        with patch.object(server._AdmissionLog, "record_resource", wrong):
            self.refuse_intent("BROKER_INTENT_COMMIT_MISMATCH")
        self.assertEqual(len(self.writes), 1)
        self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)

    def test_pending_action_change_during_commit_refuses_before_repin(self):
        self.on_sync = lambda: self.subject.events.transcript.pending.update(actionId=2)
        self.refuse_intent("BROKER_TRANSCRIPT_CHANGED")
        self.assertEqual(self.subject.dispatch.ledger_raw, self.original_history)
        self.assertTrue(self.owner.log.poisoned)

    def test_dispatch_pin_change_during_commit_is_not_repaired(self):
        self.on_sync = lambda: setattr(self.subject.dispatch, "ledger_raw", b"foreign")
        self.refuse_intent("BROKER_INTENT_HISTORY_CHANGED")
        self.assertEqual(self.subject.dispatch.ledger_raw, b"foreign")
        self.assertTrue(self.owner.log.poisoned)

    def test_reentrant_attempt_closes_owner_and_never_retries(self):
        self.on_sync = self.subject.record_create_intent
        self.refuse_intent("BROKER_UNAVAILABLE|BROKER_OWNER_CHANGED")
        self.assertEqual(self.append_call.call_count, 1)
        self.assertTrue(self.owner.log.poisoned)
        self.assertFalse(self.subject.intent.committed)

    def test_repeated_committed_create_is_refused_without_second_append(self):
        self.subject.record_create_intent()
        before = self.ledger
        self.refuse_intent("BROKER_INTENT_ALREADY_ATTEMPTED")
        self.assertEqual(self.ledger, before)
        self.assertEqual(self.append_call.call_count, 1)

    def test_fresh_check_detects_post_commit_history_substitution(self):
        self.subject.record_create_intent()
        self.ledger += b"foreign"
        with self.assertRaisesRegex(ConformanceError, "BROKER_RUNNING_CHANGED"):
            self.subject.intent.check()
        self.assertTrue(self.subject.closed and self.owner.log.poisoned)

    def test_fresh_check_detects_post_commit_generation_loss(self):
        self.subject.record_create_intent()
        self.observed["generation"] = "f" * 64
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.intent.check()
        self.assertTrue(self.subject.closed and self.owner.log.poisoned)
        self.assertTrue(self.held()["held"])

    def test_intent_replacement_does_not_close_or_use_foreign_object(self):
        self.subject.record_create_intent()
        original, foreign = self.subject.intent, Mock()
        self.subject.intent = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_INTENT_OWNER_CHANGED"):
            original.check()
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()
        self.assertTrue(original.failed)

    def test_accounting_does_not_acknowledge_action_or_acquire_api(self):
        before = self.subject.events.transcript_raw
        self.subject.record_create_intent()
        self.assertEqual(self.subject.events.transcript_raw, before)
        self.assertEqual(self.subject.events.transcript.pending["verb"], "CREATE")
        self.assertIsNone(self.subject.api)
        self.assertIsNone(self.subject.events.transcript.cleanup)
        self.assertIsNone(self.subject.events.transcript.terminal)
        self.socket.send.assert_not_called()
        self.socket.recvmsg.assert_not_called()
        self.owner.files.read.assert_not_called()
        self.mocks["socket"].assert_called_once()  # original broker channel only

    def test_cleanup_failure_preserves_first_refusal_and_durable_intent(self):
        self.on_sync = lambda: self.observed.update(generation="f" * 64)
        self.socket.close.side_effect = OSError("unit socket close")
        self.refuse_intent("BROKER_GENERATION_CHANGED")
        self.assertIsInstance(self.subject.cleanup_failure, OSError)
        self.assertTrue(self.held()["held"])
        self.socket.close.assert_called_once()

    def test_final_enclosing_guard_failure_never_publishes_committed_intent(self):
        original = server._BrokerIntent.__init__
        def complete_then_revoke(resource, broker):
            original(resource, broker)
            self.owner._base_check.side_effect = ConformanceError("UNIT_FINAL_GUARD", "unit revocation")
        with patch.object(server._BrokerIntent, "__init__", complete_then_revoke):
            self.refuse_intent("UNIT_FINAL_GUARD")
        self.assertTrue(self.subject.intent.advanced)
        self.assertFalse(self.subject.intent.committed)
        self.assertTrue(self.owner.log.poisoned)
        self.assertTrue(self.held()["held"])

    def test_final_guard_cannot_replace_the_owned_publication_target(self):
        original = server._BrokerIntent.__init__
        foreign = Mock()
        def complete_then_replace(resource, broker):
            original(resource, broker)
            self.owner._base_check.side_effect = lambda: setattr(broker, "intent", foreign)
        with patch.object(server._BrokerIntent, "__init__", complete_then_replace):
            self.refuse_intent("BROKER_INTENT_PUBLICATION_CHANGED")
        self.assertFalse(self.subject._intent_original.committed)
        self.assertTrue(self.owner.log.poisoned)
        foreign.close.assert_not_called()
        self.assertNotIn("committed", vars(foreign))


class BrokerApiConnectionTests(_BrokerEventFixture, unittest.TestCase):
    """Actual broker/API factory and MemoryBIO codec; OS/OpenSSL are doubles.

    Certificate bytes are deliberately unsigned DER data, not issued credentials.
    No network service, private key, native containment or API effect is exercised.
    """
    def start(self):
        import base64
        from test_proxy_client import der, identity_data
        self.fixture = deepcopy(VECTORS["broker"]["positive"][1])
        owner = self.owner
        profile = self.fixture["profile"]
        scope = profile["binding"]
        san = ("urn:planeon:capacity-proxy:" + ":".join(scope[k] for k in
               ("tenantId", "environmentId", "runNonce", "apiEndpointId"))).encode()
        extension = lambda oid, value: der(0x30, der(6, bytes.fromhex(oid)) + der(4, value))
        extensions = der(0xA3, der(0x30, extension("551d13", der(0x30, b"")) +
            extension("551d25", der(0x30, der(6, bytes.fromhex("2b06010505070302")))) +
            extension("551d11", der(0x30, der(0x86, san)))))
        spki = der(0x30, der(0x30, b"") + der(3, b"\0unit-api-not-a-key"))
        algorithm = der(0x30, der(6, b"\x2b\x65\x70"))
        tbs = der(0x30, b"\xa0\x03\x02\x01\x02" + der(2, b"\x01") + algorithm + der(0x30, b"") +
                  der(0x30, der(0x17, b"260908000000Z") + der(0x17, b"260908001000Z")) +
                  der(0x30, b"") + spki + extensions)
        leaf = der(0x30, tbs + algorithm + der(3, b"\0unsigned"))
        profile["capacityEntries"]["credentialIdentities"][1].update(
            certificateDigest=server.byte_digest(leaf), clientSpkiDigest=server.byte_digest(spki))
        self.api_pem = (b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(leaf) +
                        b"\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n" +
                        base64.b64encode(der(0x30, b"")) + b"\n-----END PRIVATE KEY-----\n")
        self.peer_der, _, tls_endpoint = identity_data(False)
        self.api_ca = b"-----BEGIN CERTIFICATE-----\nunit-only-ca\n-----END CERTIFICATE-----\n"
        campaign = owner.envelope["endpoints"][0]
        self.api_endpoint = deepcopy(campaign)
        self.api_endpoint.update(endpointId=scope["apiEndpointId"], kind="KUBERNETES_API_PROXY",
            addressFamily="IPV4", ipAddress="127.0.0.2", port=7443,
            credentialFileReference="/etc/planeon/live-proxy/unit-api.pem")
        self.api_endpoint["tls"] = {**tls_endpoint["tls"],
            "caCertificateFileReference": owner.envelope["conformanceKitRoot"] + "/unit-api-ca.pem"}
        owner.envelope["endpoints"] = [campaign, self.api_endpoint]
        release = {"tree": [{"path": "unit-api-ca.pem", "mode": "0444", "size": len(self.api_ca),
                             "sha256": server.byte_digest(self.api_ca)}]}
        release_raw = canonical_bytes(release)
        owner.files.raw[owner.envelope["campaignReleaseFileReference"]] = release_raw
        owner.envelope["campaignReleaseDigest"] = server.byte_digest(release_raw)
        owner.kit = {"unit-api-ca.pem": self.api_ca}
        owner.profile = deepcopy(profile)
        owner.capacity.update(deepcopy(profile["capacityEntries"]))
        owner.observation_binding = deepcopy(self.fixture["observationBinding"])
        owner.observation_binding["profileDigest"] = server.canonical_digest(owner.profile)
        self.fixture["binding"]["profileDigest"] = server.canonical_digest(owner.profile)
        self.fixture["binding"]["observationBindingDigest"] = server.canonical_digest(owner.observation_binding)
        owner.qualification_binding._broker_raw = canonical_bytes(self.fixture["binding"])
        owner.reservation = server.admission_binding(owner.envelope, owner.capacity, owner.profile)
        owner.secrets = server._Files(owner)
        self.secret_checks = Mock(return_value=None)
        self.stack.enter_context(patch.object(server._Files, "check", self.secret_checks))
        self.secret_reads = Mock(side_effect=self.read_secret)
        self.stack.enter_context(patch.object(server._Files, "read", self.secret_reads))
        self.history = []
        self.append_row("RESERVED", None)
        self.append_row("RUNNING", owner.active_operation)
        self.observed["bindingDigest"] = server.canonical_digest(owner.observation_binding)
        return BrokerTransportCustodyTests.start(self)

    def read_secret(self, path, **kwargs):
        self.events.append("api-secret")
        self.assertEqual(path, self.api_endpoint["credentialFileReference"])
        self.assertEqual(kwargs, dict(mode=0o400, maximum=262144))
        self.on_secret()
        self.owner.secrets.raw[path] = self.api_pem
        return self.api_pem

    def setUp(self):
        _BrokerEventFixture.setUp(self)
        self.on_secret = self.on_connect = self.on_handshake = lambda: None
        self.on_context = lambda: None
        self.api_socket = Mock()
        self.api_socket.fileno.return_value = 81
        self.api_socket.getpeername.side_effect = lambda: self.api_peer
        self.api_socket.connect.side_effect = self.connect_api
        self.api_socket.send.side_effect = lambda raw: len(raw)
        self.api_peer = ("127.0.0.2", 7443)
        self.fds[81] = SimpleNamespace(st_dev=1, st_ino=81, st_mode=stat.S_IFSOCK | 0o600)
        self.fds[82] = SimpleNamespace(st_dev=1, st_ino=82, st_mode=stat.S_IFREG | 0o600)
        self.mocks["socket"].return_value = self.api_socket
        self.fd_bytes = bytearray()
        self.seals = 15
        self.memfd = self.stack.enter_context(patch.object(server.os, "memfd_create", return_value=82, create=True))
        for name, value in (("MFD_CLOEXEC", 1), ("MFD_ALLOW_SEALING", 2)):
            self.stack.enter_context(patch.object(server.os, name, value, create=True))
        for name, value in (("F_ADD_SEALS", 1033), ("F_GET_SEALS", 1034), ("F_SEAL_SEAL", 1),
                            ("F_SEAL_SHRINK", 2), ("F_SEAL_GROW", 4), ("F_SEAL_WRITE", 8)):
            self.stack.enter_context(patch.object(server.fcntl, name, value, create=True))
        self.memfd_write = self.stack.enter_context(patch.object(server.os, "write", side_effect=self.write_memfd))
        self.stack.enter_context(patch.object(server.os, "lseek", return_value=0))
        self.memfd_read = self.stack.enter_context(patch.object(server.os, "read",
            side_effect=lambda fd, maximum: bytes(self.fd_bytes[:maximum])))
        self.seal_call = self.stack.enter_context(patch.object(server.fcntl, "fcntl",
            side_effect=lambda fd, op, *args: self.seals if op == 1034 else 0))
        self.ssl = Mock()
        self.ssl.version.return_value = "TLSv1.3"
        self.ssl.session_reused = False
        self.ssl.selected_alpn_protocol.return_value = "http/1.1"
        self.ssl.getpeercert.return_value = self.peer_der
        self.ssl.do_handshake.side_effect = self.handshake
        self.context = Mock()
        self.context.wrap_bio.side_effect = self.wrap
        self.context_call = self.stack.enter_context(patch.object(server, "tls_context", side_effect=self.make_context))
        self.action()
        self.take()
        self.before = list(self.events)

    def connect_api(self, target):
        self.events.append("api-connect")
        self.assertEqual(target, self.api_peer)
        self.on_connect()

    def write_memfd(self, fd, raw):
        self.assertEqual(fd, 82)
        self.fd_bytes.extend(raw)
        return len(raw)

    def make_context(self, ca, fd):
        self.assertEqual((ca, fd), (self.api_ca, 82))
        self.events.append("api-context")
        self.on_context()
        return self.context

    def wrap(self, incoming, outgoing, **kwargs):
        self.assertEqual(kwargs, dict(server_side=False, server_hostname="proxy.unit"))
        self.outgoing = outgoing
        return self.ssl

    def handshake(self):
        self.events.append("api-handshake")
        self.on_handshake()
        self.outgoing.write(b"unit-encrypted-handshake-only")

    def prepare(self):
        self.assertIsNone(self.subject.prepare_api())
        self.api = self.subject.api
        self.assertIs(type(self.api), server._BrokerApi)
        self.assertTrue(self.api.ready)
        return self.api

    def deny(self, reason):
        with self.assertRaisesRegex(ConformanceError, reason):
            self.subject.prepare_api()
        self.assertTrue(self.subject.closed)
        self.assertTrue(self.subject.failed)

    def test_original_pending_action_opens_separate_authenticated_channel_only(self):
        api = self.prepare()
        self.assertIsNone(api.check())
        self.assertIs(self.subject.sock, self.socket)
        self.assertIs(api.sock, self.api_socket)
        self.assertEqual(self.secret_reads.call_count, 1)
        self.api_socket.send.assert_called_once_with(b"unit-encrypted-handshake-only")
        self.api_socket.recv.assert_not_called()
        self.socket.send.assert_not_called()
        self.assertIsNotNone(self.subject.events.transcript.pending)
        self.assertEqual(self.subject.events.transcript.sequence, 2)
        self.assertIsNone(api.memfd)
        self.assertEqual(self.events.count(("close", 82)), 1)

    def test_factory_accepts_no_caller_endpoint_credential_or_socket(self):
        with self.assertRaises(TypeError):
            self.subject.prepare_api({"endpoint": "foreign"})
        self.secret_reads.assert_not_called()

    def test_missing_event_owner_refuses_before_credential(self):
        self.subject.events = None
        self.deny("API_BROKER_EVENTS_REQUIRED")
        self.secret_reads.assert_not_called()

    def test_no_pending_action_refuses_before_credential(self):
        self.subject.events.transcript.pending = None
        self.deny("API_ACTION_REQUIRED")
        self.secret_reads.assert_not_called()

    def test_changed_generation_refuses_before_credential(self):
        self.observed["generation"] = "f" * 64
        self.deny("BROKER_GENERATION_CHANGED")
        self.secret_reads.assert_not_called()

    def test_changed_journal_refuses_before_credential(self):
        self.ledger += b" "
        self.deny("BROKER_RUNNING_CHANGED")
        self.secret_reads.assert_not_called()

    def test_expiry_refuses_before_credential(self):
        self.now = 500
        self.deny("BROKER_CLOCK_OR_DEADLINE")
        self.secret_reads.assert_not_called()

    def test_substituted_api_kind_refuses_before_credential(self):
        self.api_endpoint["kind"] = "CAMPAIGN_PROXY"
        self.deny("API_ENDPOINT_REQUIRED")
        self.secret_reads.assert_not_called()

    def test_missing_api_endpoint_refuses_before_credential(self):
        self.owner.envelope["endpoints"].pop()
        self.deny("API_ENDPOINT_REQUIRED")
        self.secret_reads.assert_not_called()

    def test_duplicate_api_endpoint_refuses_before_credential(self):
        self.owner.envelope["endpoints"].append(deepcopy(self.api_endpoint))
        self.deny("API_ENDPOINT_REQUIRED")

    def test_server_identity_reuse_refuses_before_credential(self):
        self.api_endpoint["credentialFileReference"] = server.IDENTITY
        self.deny("API_CREDENTIAL_REUSE")
        self.secret_reads.assert_not_called()

    def test_campaign_credential_reuse_refuses_before_credential(self):
        self.api_endpoint["credentialFileReference"] = self.owner.envelope["endpoints"][0]["credentialFileReference"]
        self.deny("API_CREDENTIAL_REUSE")
        self.secret_reads.assert_not_called()

    def test_numeric_family_mismatch_refuses_without_socket_or_secret(self):
        self.api_endpoint["addressFamily"] = "IPV6"
        self.deny("API_ENDPOINT_ADDRESS")
        self.secret_reads.assert_not_called()

    def test_dns_name_cannot_be_used_as_numeric_address(self):
        self.api_endpoint["ipAddress"] = "localhost"
        with self.assertRaises(ValueError):
            self.subject.prepare_api()
        self.secret_reads.assert_not_called()

    def test_ipv4_mapped_ipv6_is_refused(self):
        self.api_endpoint.update(ipAddress="::ffff:127.0.0.2", addressFamily="IPV6")
        self.deny("API_ENDPOINT_ADDRESS")

    def test_scoped_ipv6_is_refused(self):
        self.api_endpoint.update(ipAddress="fe80::1%en0", addressFamily="IPV6")
        self.deny("API_ENDPOINT_ADDRESS")

    def test_ipv6_uses_one_family_without_fallback(self):
        self.api_endpoint.update(ipAddress="::1", addressFamily="IPV6")
        self.api_peer = ("::1", 7443, 0, 0)
        self.prepare()
        self.mocks["socket"].assert_called_with(server.socket.AF_INET6, server.socket.SOCK_STREAM)
        self.api_socket.setsockopt.assert_called_once_with(server.socket.IPPROTO_IPV6, server.socket.IPV6_V6ONLY, 1)

    def test_ca_outside_signed_kit_is_refused(self):
        self.api_endpoint["tls"]["caCertificateFileReference"] = "/etc/ssl/cert.pem"
        self.deny("API_CA_NOT_RELEASED")

    def test_ca_bytes_substitution_is_refused(self):
        self.owner.kit["unit-api-ca.pem"] += b"changed"
        self.deny("API_CA_CHANGED")
        self.secret_reads.assert_not_called()

    def test_release_bytes_substitution_is_refused(self):
        self.owner.files.raw[self.owner.envelope["campaignReleaseFileReference"]] = b"{}"
        self.deny("API_RELEASE_CHANGED")

    def test_previously_read_credential_cannot_be_reopened(self):
        self.owner.secrets.raw[self.api_endpoint["credentialFileReference"]] = self.api_pem
        self.deny("API_CREDENTIAL_ALREADY_READ")
        self.secret_reads.assert_not_called()

    def test_revocation_after_credential_read_stops_before_memfd(self):
        self.on_secret = lambda: self.observed.update(generation="e" * 64)
        self.deny("BROKER_GENERATION_CHANGED")
        self.memfd.assert_not_called()

    def test_wrong_leaf_certificate_refuses_before_memfd(self):
        import base64
        self.api_pem = (b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(self.peer_der) +
            b"\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----" +
            self.api_pem.split(b"-----BEGIN PRIVATE KEY-----")[1])
        with self.assertRaisesRegex(ConformanceError, "TLS_CERT_EKU"):
            self.subject.prepare_api()
        self.memfd.assert_not_called()

    def test_zero_memfd_write_refuses_and_closes_original(self):
        self.memfd_write.side_effect = None
        self.memfd_write.return_value = 0
        self.deny("API_CREDENTIAL_SHORT_WRITE")
        self.assertEqual(self.events.count(("close", 82)), 1)
        self.api_socket.connect.assert_not_called()

    def test_missing_seals_refuses_before_context(self):
        self.seals = 7
        self.deny("API_CREDENTIAL_SEALS")
        self.context_call.assert_not_called()
        self.assertEqual(self.events.count(("close", 82)), 1)

    def test_memfd_readback_mismatch_refuses_before_context(self):
        self.memfd_read.side_effect = lambda *args: b"changed"
        self.deny("API_CREDENTIAL_MEMFD_CHANGED")
        self.context_call.assert_not_called()

    def test_context_failure_closes_memfd_without_connect(self):
        self.on_context = lambda: (_ for _ in ()).throw(OSError("unit context"))
        with self.assertRaises(OSError):
            self.subject.prepare_api()
        self.assertEqual(self.events.count(("close", 82)), 1)
        self.api_socket.connect.assert_not_called()

    def test_revocation_after_context_stops_before_connect(self):
        self.on_context = lambda: self.observed.update(generation="a" * 64)
        self.deny("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.events.count(("close", 82)), 1)
        self.api_socket.connect.assert_not_called()

    def test_inheritable_api_socket_is_refused(self):
        self.mocks["get_inheritable"].side_effect = lambda fd: fd == 81
        self.deny("API_DESCRIPTOR_CHANGED")
        self.api_socket.close.assert_called_once()

    def test_connected_peer_substitution_is_refused_before_tls(self):
        self.api_socket.getpeername.side_effect = lambda: ("127.0.0.3", 7443)
        self.deny("API_PEER_CHANGED")
        self.ssl.do_handshake.assert_not_called()

    def test_connect_failure_has_post_observation_and_no_retry(self):
        def fail():
            self.events.append("connect-failed")
            raise TimeoutError("unit connect")
        self.on_connect = fail
        with self.assertRaises(TimeoutError):
            self.subject.prepare_api()
        self.assertIn("observe", self.events[self.events.index("connect-failed") + 1:])
        self.api_socket.connect.assert_called_once()
        self.api_socket.close.assert_called_once()

    def test_late_connect_refuses_before_handshake(self):
        self.on_connect = lambda: setattr(self, "now", 111)
        self.deny("API_CONNECT_DEADLINE")
        self.ssl.do_handshake.assert_not_called()

    def test_revocation_after_connect_refuses_before_handshake(self):
        self.on_connect = lambda: self.observed.update(generation="a" * 64)
        self.deny("BROKER_GENERATION_CHANGED")
        self.ssl.do_handshake.assert_not_called()

    def test_tls_resumption_is_refused(self):
        self.ssl.session_reused = True
        self.deny("TLS_PROTOCOL_INVALID")

    def test_wrong_tls_version_is_refused(self):
        self.ssl.version.return_value = "TLSv1.2"
        self.deny("TLS_PROTOCOL_INVALID")

    def test_wrong_alpn_is_refused(self):
        self.ssl.selected_alpn_protocol.return_value = "h2"
        self.deny("TLS_PROTOCOL_INVALID")

    def test_wrong_server_certificate_is_refused(self):
        self.ssl.getpeercert.return_value = b"not DER"
        with self.assertRaises(ConformanceError):
            self.subject.prepare_api()
        self.api_socket.close.assert_called_once()

    def test_revocation_during_handshake_does_not_publish_ready(self):
        self.on_handshake = lambda: self.observed.update(generation="a" * 64)
        self.deny("BROKER_GENERATION_CHANGED")

    def test_repeated_prepare_never_reconnects_or_reopens_credential(self):
        self.prepare()
        self.deny("BROKER_API_ALREADY_ATTEMPTED")
        self.assertEqual(self.secret_reads.call_count, 1)
        self.api_socket.connect.assert_called_once()

    def test_mutated_endpoint_after_ready_refuses_and_closes(self):
        api = self.prepare()
        self.api_endpoint["ipAddress"] = "127.0.0.3"
        with self.assertRaisesRegex(ConformanceError, "API_INPUTS_CHANGED"):
            api.check()
        self.api_socket.close.assert_called_once()

    def test_recycled_api_descriptor_is_not_closed(self):
        api = self.prepare()
        self.fds[81].st_ino += 1
        with self.assertRaises(ConformanceError):
            api.check()
        self.api_socket.close.assert_not_called()
        self.api_socket.detach.assert_called_once()
        self.assertIsNotNone(self.subject.cleanup_failure)

    def test_foreign_current_socket_is_not_adopted_or_closed(self):
        api = self.prepare()
        foreign = api.sock = Mock()
        with self.assertRaises(ConformanceError):
            api.check()
        foreign.close.assert_not_called()
        self.api_socket.close.assert_called_once()

    def test_foreign_current_api_owner_is_not_closed(self):
        api = self.prepare()
        foreign = self.subject.api = Mock()
        with self.assertRaises(ConformanceError):
            api.check()
        foreign.close.assert_not_called()
        self.api_socket.close.assert_called_once()

    def test_api_close_is_idempotent_and_preserves_borrowed_resources(self):
        api = self.prepare()
        api.close()
        api.close()
        self.api_socket.close.assert_called_once()
        self.socket.close.assert_not_called()
        self.owner.files.close.assert_not_called()
        self.assertEqual(self.events.count(("close", 82)), 1)

    def test_api_transport_never_writes_durable_intent_or_cleanup(self):
        before = self.ledger
        with patch.object(server._State, "append") as append, patch.object(server._State, "sync") as sync:
            self.prepare()
        self.assertEqual(before, self.ledger)
        append.assert_not_called()
        sync.assert_not_called()

    def test_pending_action_change_after_ready_refuses(self):
        api = self.prepare()
        api.events.transcript.pending["actionId"] += 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_TRANSCRIPT_CHANGED"):
            api.check()
        self.api_socket.close.assert_called_once()

class BrokerCreateExchangeTests(_BrokerEventFixture, unittest.TestCase):
    """Real broker/intent/API/TLS/HTTP code; OS, OpenSSL and storage doubles."""
    read_secret = BrokerApiConnectionTests.read_secret
    connect_api = BrokerApiConnectionTests.connect_api
    write_memfd = BrokerApiConnectionTests.write_memfd
    make_context = BrokerApiConnectionTests.make_context
    wrap = BrokerApiConnectionTests.wrap
    handshake = BrokerApiConnectionTests.handshake
    read_intent = BrokerIntentTests.read_intent
    append_intent = BrokerIntentTests.append_intent
    sync_intent = BrokerIntentTests.sync_intent
    held = BrokerIntentTests.held

    def start(self):
        nonce = VECTORS["broker"]["positive"][1]["profile"]["binding"]["runNonce"]
        self.owner.envelope["nonce"] = self.observed["runNonce"] = nonce
        return BrokerApiConnectionTests.start(self)

    def action(self, digest=None):
        _BrokerEventFixture.action(self, digest)
        self.event_frame["payload"]["verb"] = "CREATE"

    def setUp(self):
        from contextlib import contextmanager
        BrokerApiConnectionTests.setUp(self)
        self.io_events, self.writes = [], []
        self.fail = None
        self.on_read = self.on_append = self.on_sync = lambda: None
        @contextmanager
        def transaction(resource):
            self.assertIs(resource, self.owner.storage)
            yield resource
        self.stack.enter_context(patch.object(server._State, "transaction", transaction))
        self.stack.enter_context(patch.object(server._State, "append", side_effect=self.append_intent))
        self.stack.enter_context(patch.object(server._State, "sync", side_effect=self.sync_intent))
        self.read_store.side_effect = self.read_intent
        self.on_http_write = self.on_http_read = lambda: None
        self.plain_requests, self.wire_requests = [], []
        self.ssl.write.side_effect = self.http_write
        self.ssl.read.side_effect = self.http_read
        self.ssl.pending.return_value = 0
        self.manifest = deepcopy(self.owner.profile["resources"][0]["manifest"])
        self.actual = deepcopy(self.manifest)
        self.actual["metadata"].update(uid="created-unit-uid", resourceVersion="123")
        self.reply(canonical_bytes(self.actual))

    def reply(self, body, status="HTTP/1.1 200 OK"):
        self.http_bytes = bytearray(server.http_message(status, body))

    def http_write(self, raw):
        self.on_http_write()
        self.plain_requests.append(bytes(raw))
        self.outgoing.write(b"unit-encrypted-api-request")
        return len(raw)

    def http_read(self, maximum):
        self.on_http_read()
        part = bytes(self.http_bytes[:maximum])
        del self.http_bytes[:maximum]
        return part

    def prepare(self, intent=True):
        if intent:
            self.subject.record_create_intent()
        BrokerApiConnectionTests.prepare(self)
        self.api_socket.send.reset_mock()
        self.api_socket.send.side_effect = lambda raw: self.wire_requests.append(bytes(raw)) or len(raw)
        self.socket.send.reset_mock()
        self.socket.recvmsg.reset_mock()
        return self.api

    def refuse_exchange(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason):
            self.subject.exchange_api_create()
        self.assertTrue(self.subject.failed and self.subject.closed)
        if self.subject._exchange_original is not None:
            self.assertTrue(self.subject._exchange_original.failed)
        self.socket.send.assert_not_called()

    def test_original_intent_precedes_exact_fixed_create_request(self):
        self.prepare()
        before = self.ledger
        seen = []
        self.on_http_write = lambda: seen.append(self.held()["resources"])
        self.assertIsNone(self.subject.exchange_api_create())
        exchange = self.subject.exchange
        self.assertTrue(exchange.complete and exchange.attempted)
        self.assertIs(exchange, self.subject._exchange_original)
        expected = server.http_message("POST /api/v1/namespaces/" + self.manifest["metadata"]["namespace"]
            + "/configmaps HTTP/1.1", canonical_bytes(self.manifest), "proxy.unit")
        self.assertEqual(self.plain_requests, [expected])
        self.assertEqual(self.wire_requests, [b"unit-encrypted-api-request"])
        self.assertEqual(exchange.response_raw, canonical_bytes(self.actual))
        self.assertEqual(self.ledger, before)
        self.assertTrue(all(r["state"] == "CREATE_INTENT" and r["uid"] is None for r in seen[0].values()))
        self.assertEqual(len(self.writes), 1)

    def test_success_remains_candidate_not_broker_result_or_created_record(self):
        self.prepare()
        snapshot = self.subject.events.transcript_raw
        self.subject.exchange_api_create()
        self.assertEqual(self.subject.events.transcript_raw, snapshot)
        self.assertIsNotNone(self.subject.events.transcript.pending)
        self.assertIsNone(self.subject.events.transcript.cleanup)
        self.assertIsNone(self.subject.events.transcript.terminal)
        self.assertTrue(self.held()["held"])
        self.socket.send.assert_not_called()
        self.socket.recvmsg.assert_not_called()
        self.assertEqual(self.secret_reads.call_count, 1)
        self.api_socket.connect.assert_called_once()

    def test_fresh_candidate_check_does_not_resend_or_reconnect(self):
        self.prepare()
        self.subject.exchange_api_create()
        observations = len(self.observations)
        self.assertIsNone(self.subject.exchange.check())
        self.assertGreater(len(self.observations), observations)
        self.assertEqual(len(self.plain_requests), 1)
        self.assertEqual(self.secret_reads.call_count, 1)

    def test_no_caller_request_response_path_or_backend_argument(self):
        for value in ({}, b"request", "https://untrusted.invalid", Mock()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.exchange_api_create(value)
        self.assertIsNone(self.subject.exchange)
        self.assertEqual(self.plain_requests, [])

    def test_unowned_exchange_constructor_never_sends(self):
        self.prepare()
        with self.assertRaisesRegex(ConformanceError, "API_EXCHANGE_OWNER"):
            server._BrokerCreateExchange(self.subject)
        self.assertEqual(self.plain_requests, [])

    def test_missing_api_authentication_refuses_before_request(self):
        self.subject.record_create_intent()
        self.refuse_exchange("API_EXCHANGE_AUTHENTICATION_REQUIRED")
        self.assertEqual(self.plain_requests, [])
        self.secret_reads.assert_not_called()

    def test_authenticated_api_without_intent_cannot_send(self):
        self.prepare(intent=False)
        self.refuse_exchange("API_EXCHANGE_INTENT_REQUIRED")
        self.assertEqual(self.plain_requests, [])

    def test_uncommitted_intent_cannot_send(self):
        self.prepare()
        self.subject.intent.committed = False
        self.refuse_exchange("API_EXCHANGE_INTENT_REQUIRED")
        self.assertEqual(self.plain_requests, [])

    def test_changed_action_refuses_without_http_write(self):
        self.prepare()
        self.subject.events.transcript.pending["verb"] = "GET"
        self.refuse_exchange("API_EXCHANGE_STATE_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_changed_durable_history_refuses_without_http_write(self):
        self.prepare()
        self.ledger += b"unknown"
        self.refuse_exchange("BROKER_RUNNING_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_revoked_generation_refuses_before_http_write(self):
        self.prepare()
        self.observed["generation"] = "f" * 64
        self.refuse_exchange("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_peer_change_refuses_before_http_write(self):
        self.prepare()
        self.api_peer = ("127.0.0.3", 7443)
        self.refuse_exchange("API_PEER_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_signed_deadline_refuses_before_http_write(self):
        self.prepare()
        self.now = self.subject.deadline
        self.refuse_exchange("BROKER_CLOCK_OR_DEADLINE")
        self.assertEqual(self.plain_requests, [])

    def test_short_or_ambiguous_write_never_retries(self):
        self.prepare()
        self.api_socket.send.side_effect = OSError("unit lost send")
        self.refuse_exchange("unit lost send")
        self.api_socket.send.assert_called_once()
        with self.assertRaises(ConformanceError):
            self.subject.exchange_api_create()
        self.api_socket.send.assert_called_once()
        self.assertTrue(self.owner.log.poisoned)
        self.assertTrue(self.held()["held"])

    def test_partial_send_then_error_does_not_restart_http(self):
        self.prepare()
        self.api_socket.send.side_effect = [1, OSError("unit partial send")]
        self.refuse_exchange("unit partial send")
        self.assertEqual(self.api_socket.send.call_count, 2)
        self.assertEqual(len(self.plain_requests), 1)

    def test_write_time_revocation_blocks_outgoing_ciphertext(self):
        self.prepare()
        self.on_http_write = lambda: self.observed.update(generation="f" * 64)
        self.refuse_exchange("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.wire_requests, [])

    def test_lost_response_keeps_unknown_uid_and_capacity_held(self):
        self.prepare()
        self.http_bytes = bytearray()
        self.refuse_exchange("HTTP_TRUNCATED_HEADERS")
        self.assertEqual(len(self.plain_requests), 1)
        self.assertTrue(all(r["uid"] is None for r in self.held()["resources"].values()))
        self.assertTrue(self.owner.log.poisoned)

    def test_conflict_is_not_adopted_or_deleted(self):
        self.prepare()
        self.reply(b"{}", "HTTP/1.1 409 Conflict")
        self.refuse_exchange("HTTP_STATUS_INVALID")
        self.assertEqual(len(self.plain_requests), 1)
        self.assertEqual(len(self.writes), 1)

    def test_non_200_created_response_is_not_silently_added_to_profile(self):
        self.prepare()
        self.reply(canonical_bytes(self.actual), "HTTP/1.1 201 Created")
        self.refuse_exchange("HTTP_STATUS_INVALID")

    def test_redirect_does_not_follow_or_reconnect(self):
        self.prepare()
        self.reply(b"{}", "HTTP/1.1 302 Found")
        self.refuse_exchange("HTTP_STATUS_INVALID")
        self.api_socket.connect.assert_called_once()

    def test_duplicate_response_header_refuses(self):
        self.prepare()
        self.http_bytes = self.http_bytes.replace(b"Connection: close", b"Connection: close\r\nConnection: close")
        self.refuse_exchange("HTTP_HEADER_FORBIDDEN")

    def test_truncated_response_body_refuses(self):
        self.prepare()
        del self.http_bytes[-1]
        self.refuse_exchange("HTTP_TRUNCATED_BODY")

    def test_surplus_response_refuses(self):
        self.prepare()
        self.http_bytes.extend(b"extra")
        self.refuse_exchange("HTTP_SURPLUS")

    def test_missing_uid_cannot_be_created_candidate(self):
        self.prepare()
        del self.actual["metadata"]["uid"]
        self.reply(canonical_bytes(self.actual))
        self.refuse_exchange("ADMISSION_IDENTITY_MISSING")

    def test_post_defaulting_manifest_change_refuses(self):
        self.prepare()
        self.actual["metadata"]["labels"]["untrusted"] = "injected"
        self.reply(canonical_bytes(self.actual))
        self.refuse_exchange("ADMISSION_POST_MUTATION_MISMATCH")

    def test_noncanonical_response_is_not_normalized(self):
        self.prepare()
        self.reply(json.dumps(self.actual).encode())
        self.refuse_exchange()

    def test_response_time_revocation_never_publishes_candidate(self):
        self.prepare()
        self.on_http_read = lambda: self.observed.update(generation="f" * 64)
        self.refuse_exchange("BROKER_GENERATION_CHANGED")
        self.assertIsNone(self.subject.exchange.response_raw)
        self.assertTrue(self.held()["held"])

    def test_slow_response_cannot_extend_original_deadline(self):
        self.prepare()
        self.on_http_read = lambda: setattr(self, "now", self.subject.deadline)
        self.refuse_exchange("BROKER_CLOCK_OR_DEADLINE")
        self.assertIsNone(self.subject.exchange.response_raw)

    def test_header_phase_keeps_ten_second_cap(self):
        self.prepare()
        start = self.now
        def trickle(maximum):
            self.now += 1
            return b"H"
        self.ssl.read.side_effect = trickle
        self.refuse_exchange("TLS_DEADLINE")
        self.assertEqual(self.now, start + 10)

    def test_repeated_completed_exchange_never_sends_again(self):
        self.prepare()
        self.subject.exchange_api_create()
        self.refuse_exchange("BROKER_EXCHANGE_ALREADY_ATTEMPTED")
        self.assertEqual(len(self.plain_requests), 1)

    def test_reentrant_exchange_does_not_send_or_reconnect(self):
        self.prepare()
        self.on_http_write = self.subject.exchange_api_create
        self.refuse_exchange("BROKER_EXCHANGE_ALREADY_ATTEMPTED")
        self.assertEqual(self.wire_requests, [])
        self.api_socket.connect.assert_called_once()

    def test_request_substitution_during_write_is_refused(self):
        self.prepare()
        self.on_http_write = lambda: setattr(self.subject.exchange, "request_raw", b"foreign")
        self.refuse_exchange("API_EXCHANGE_REQUEST_CHANGED")
        self.assertEqual(self.wire_requests, [])

    def test_original_candidate_refuses_foreign_exchange_without_using_it(self):
        self.prepare()
        self.subject.exchange_api_create()
        original = self.subject.exchange
        foreign = self.subject.exchange = Mock()
        with self.assertRaisesRegex(ConformanceError, "API_EXCHANGE_STATE_CHANGED"):
            original.check()
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()

    def test_candidate_response_change_is_detected(self):
        self.prepare()
        self.subject.exchange_api_create()
        self.subject.exchange.response_raw = b"{}"
        with self.assertRaisesRegex(ConformanceError, "API_EXCHANGE_RESPONSE_CHANGED"):
            self.subject.exchange.check()

    def test_final_check_cannot_replace_publication_target(self):
        self.prepare()
        original = server._BrokerCreateExchange.__init__
        foreign = Mock()
        def completed(resource, broker):
            original(resource, broker)
            broker.exchange = foreign
        with patch.object(server._BrokerCreateExchange, "__init__", completed):
            self.refuse_exchange("BROKER_EXCHANGE_PUBLICATION_CHANGED")
        self.assertFalse(self.subject._exchange_original.complete)
        self.assertNotIn("complete", vars(foreign))
        foreign.close.assert_not_called()


class BrokerCreatedTests(_BrokerEventFixture, unittest.TestCase):
    """Actual journal/transport owners; OS, TLS and storage are unit-only doubles."""
    start = BrokerCreateExchangeTests.start
    action = BrokerCreateExchangeTests.action
    read_secret = BrokerCreateExchangeTests.read_secret
    connect_api = BrokerCreateExchangeTests.connect_api
    write_memfd = BrokerCreateExchangeTests.write_memfd
    make_context = BrokerCreateExchangeTests.make_context
    wrap = BrokerCreateExchangeTests.wrap
    handshake = BrokerCreateExchangeTests.handshake
    read_intent = BrokerCreateExchangeTests.read_intent
    append_intent = BrokerCreateExchangeTests.append_intent
    sync_intent = BrokerCreateExchangeTests.sync_intent
    held = BrokerCreateExchangeTests.held
    reply = BrokerCreateExchangeTests.reply
    http_write = BrokerCreateExchangeTests.http_write
    http_read = BrokerCreateExchangeTests.http_read
    prepare = BrokerCreateExchangeTests.prepare

    def setUp(self):
        from contextlib import contextmanager
        BrokerCreateExchangeTests.setUp(self)
        self.locked = False
        self.on_lock = self.on_exit = lambda: None
        @contextmanager
        def transaction(resource):
            self.assertIs(resource, self.owner.storage)
            if self.locked:
                raise ConformanceError("UNIT_STORAGE_BUSY", "unit contention")
            self.locked = True
            self.io_events.append("lock")
            try:
                self.on_lock()
                yield resource
            finally:
                self.io_events.append("unlock")
                self.locked = False
                self.on_exit()
        self.stack.enter_context(patch.object(server._State, "transaction", transaction))

    def complete(self):
        self.prepare()
        self.subject.exchange_api_create()
        self.before_created = self.ledger
        self.io_events.clear()

    def refuse_created(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason) as caught:
            self.subject.record_api_created()
        self.assertTrue(self.subject.failed and self.subject.closed)
        if self.subject._created_original is not None:
            self.assertTrue(self.subject._created_original.failed)
            self.assertFalse(self.subject._created_original.committed)
        self.socket.send.assert_not_called()
        return caught.exception

    def test_validated_identity_is_exactly_recorded_under_original_lock(self):
        self.complete()
        seen = []
        self.on_append = self.on_sync = lambda: seen.append(self.subject.dispatch.ledger_raw)
        self.assertIsNone(self.subject.record_api_created())
        created = self.subject.created
        self.assertIs(created, self.subject._created_original)
        self.assertTrue(created.committed and created.advanced and created.writing)
        self.assertEqual(seen, [self.before_created, self.before_created])
        self.assertEqual(self.ledger, created.after)
        self.assertEqual(self.subject.dispatch.ledger_raw, created.after)
        self.assertEqual(self.subject.intent.after, self.before_created)
        row = json.loads(self.writes[1])
        self.assertEqual(row["state"], "CREATED")
        self.assertEqual(row["resource"], dict(actionId=self.event_frame["payload"]["actionId"],
            apiVersion="v1", kind="ConfigMap", namespace=self.manifest["metadata"]["namespace"],
            name=self.manifest["metadata"]["name"], manifestDigest=self.event_frame["payload"]["manifestDigest"],
            uid="created-unit-uid", resourceVersion="123"))
        self.assertEqual(self.io_events[self.io_events.index("lock"):self.io_events.index("unlock") + 1],
                         ["lock", "read", "append", "fsync", "read", "unlock"])

    def test_created_is_accounting_not_ack_cleanup_or_capacity_release(self):
        self.complete()
        transcript = self.subject.events.transcript_raw
        self.subject.record_api_created()
        self.assertEqual(self.subject.events.transcript_raw, transcript)
        self.assertIsNotNone(self.subject.events.transcript.pending)
        self.assertIsNone(self.subject.events.transcript.cleanup)
        self.assertIsNone(self.subject.events.transcript.terminal)
        self.assertTrue(self.held()["held"])
        self.assertTrue(all(r["state"] == "CREATED" for r in self.held()["resources"].values()))
        self.socket.send.assert_not_called()
        self.socket.recvmsg.assert_not_called()
        self.assertEqual(len(self.plain_requests), 1)
        self.assertEqual(len(self.wire_requests), 1)
        self.assertEqual(self.secret_reads.call_count, 1)
        self.api_socket.connect.assert_called_once()

    def test_original_intent_exchange_and_created_checks_keep_exact_new_history(self):
        self.complete()
        self.subject.record_api_created()
        before, observations = self.ledger, len(self.observations)
        self.assertIsNone(self.subject.intent.check())
        self.assertIsNone(self.subject.exchange.check())
        self.assertIsNone(self.subject.created.check())
        self.assertGreater(len(self.observations), observations)
        self.assertEqual(self.ledger, before)
        self.assertEqual(len(self.writes), 2)
        self.assertEqual(len(self.plain_requests), 1)

    def test_no_caller_identity_response_history_or_backend(self):
        for value in ({}, b"response", "foreign-uid", Mock()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.record_api_created(value)
        self.assertIsNone(self.subject.created)
        self.assertEqual(self.writes, [])

    def test_unowned_constructor_never_writes(self):
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_OWNER"):
            server._BrokerCreated(self.subject)
        self.assertEqual(self.writes, [])

    def test_missing_exchange_never_invents_returned_identity(self):
        self.subject.record_create_intent()
        self.refuse_created("BROKER_CREATED_EXCHANGE_REQUIRED")
        self.assertEqual(len(self.writes), 1)
        self.assertTrue(all(r["uid"] is None for r in self.held()["resources"].values()))

    def test_incomplete_exchange_is_not_durable_ownership(self):
        self.complete()
        self.subject.exchange.complete = False
        self.refuse_created("BROKER_CREATED_EXCHANGE_REQUIRED")
        self.assertEqual(self.ledger, self.before_created)

    def test_uncommitted_intent_cannot_be_promoted(self):
        self.complete()
        self.subject.intent.committed = False
        self.refuse_created("BROKER_CREATED_INTENT_REQUIRED")
        self.assertEqual(self.ledger, self.before_created)

    def test_response_replacement_is_rejected_without_append(self):
        self.complete()
        different = deepcopy(self.actual)
        different["metadata"]["uid"] = "foreign-uid"
        self.subject.exchange.response_raw = canonical_bytes(different)
        self.refuse_created("BROKER_CREATED_INPUT_CHANGED")
        self.assertEqual(self.ledger, self.before_created)

    def test_response_is_revalidated_against_signed_manifest(self):
        self.complete()
        self.actual["metadata"]["labels"]["foreign"] = "injected"
        self.subject.exchange.response_raw = self.subject.exchange._response_original = canonical_bytes(self.actual)
        self.refuse_created("ADMISSION_POST_MUTATION_MISMATCH")
        self.assertEqual(self.ledger, self.before_created)

    def test_response_without_resource_version_is_not_recorded(self):
        self.complete()
        del self.actual["metadata"]["resourceVersion"]
        self.subject.exchange.response_raw = self.subject.exchange._response_original = canonical_bytes(self.actual)
        self.refuse_created("ADMISSION_IDENTITY_MISSING")
        self.assertEqual(self.ledger, self.before_created)

    def test_foreign_exchange_is_not_called(self):
        self.complete()
        foreign = self.subject.exchange = Mock()
        self.refuse_created("BROKER_CREATED_EXCHANGE_REQUIRED")
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()

    def test_foreign_storage_is_not_read_or_written(self):
        self.complete()
        foreign = self.owner.storage = Mock()
        self.refuse_created("BROKER_CREATED_OWNER_CHANGED")
        foreign.read.assert_not_called()
        foreign.transaction.assert_not_called()
        self.assertEqual(self.ledger, self.before_created)

    def test_foreign_log_is_not_an_execution_hook(self):
        self.complete()
        foreign = self.owner.log = Mock()
        self.refuse_created("BROKER_CREATED_OWNER_CHANGED")
        foreign.record_resource.assert_not_called()
        self.assertEqual(self.ledger, self.before_created)

    def test_instance_shadow_writer_and_checker_are_not_used(self):
        self.complete()
        self.owner.log.record_resource = Mock(side_effect=AssertionError("shadow writer"))
        self.subject.exchange.check = Mock(side_effect=AssertionError("shadow check"))
        self.subject.record_api_created()
        self.owner.log.record_resource.assert_not_called()
        self.subject.exchange.check.assert_not_called()
        self.assertEqual(len(self.writes), 2)

    def test_unknown_history_before_write_is_not_adopted(self):
        self.complete()
        self.ledger += b"unexpected"
        self.refuse_created("BROKER_RUNNING_CHANGED")
        self.assertEqual(len(self.writes), 1)

    def test_history_change_under_lock_cannot_be_rebased(self):
        self.complete()
        self.on_lock = lambda: setattr(self, "ledger", self.ledger + b"unexpected")
        self.refuse_created("ADMISSION_RESOURCE_HISTORY_CHANGED")
        self.assertEqual(self.subject.dispatch.ledger_raw, self.before_created)
        self.assertEqual(len(self.writes), 1)

    def test_lock_contention_does_not_append(self):
        self.complete()
        self.locked = True
        self.refuse_created("UNIT_STORAGE_BUSY")
        self.assertEqual(self.ledger, self.before_created)
        self.assertTrue(self.owner.log.poisoned)

    def test_every_write_ambiguity_stays_held_without_pin_advance_or_retry(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            with self.subTest(fault=fault):
                self.complete()
                self.fail = fault
                self.refuse_created()
                created = self.subject.created
                self.assertFalse(created.committed or created.advanced)
                self.assertTrue(self.owner.log.poisoned)
                self.assertEqual(self.subject.dispatch.ledger_raw, self.before_created)
                history, writes = self.ledger, len(self.writes)
                with self.assertRaises(ConformanceError):
                    self.subject.record_api_created()
                self.assertEqual(self.ledger, history)
                self.assertEqual(len(self.writes), writes)
                self.assertEqual(len(self.plain_requests), 1)
            if fault != "readback":
                self.stack.close()
                self.setUp()

    def test_unlock_failure_does_not_publish_durable_success(self):
        self.complete()
        def fail():
            raise OSError("unit unlock ambiguity")
        self.on_exit = fail
        self.refuse_created("unit unlock ambiguity")
        self.assertEqual(len(self.writes), 2)
        self.assertTrue(self.held()["held"])
        self.assertTrue(self.owner.log.poisoned)
        self.assertFalse(self.subject.created.advanced)

    def test_wrong_returned_digest_does_not_advance_pin(self):
        self.complete()
        original = server._AdmissionLog.record_resource
        def wrong(log, *args, **kwargs):
            original(log, *args, **kwargs)
            return admission.ZERO
        with patch.object(server._AdmissionLog, "record_resource", wrong):
            self.refuse_created("BROKER_CREATED_COMMIT_MISMATCH")
        self.assertEqual(len(self.writes), 2)
        self.assertEqual(self.subject.dispatch.ledger_raw, self.before_created)

    def test_fsync_generation_loss_keeps_uid_held_without_ack(self):
        self.complete()
        self.on_sync = lambda: self.observed.update(generation="f" * 64)
        self.refuse_created("BROKER_GENERATION_CHANGED")
        self.assertEqual(len(self.writes), 2)
        self.assertTrue(self.held()["held"])
        self.assertTrue(all(r["uid"] == "created-unit-uid" for r in self.held()["resources"].values()))
        self.assertTrue(self.owner.log.poisoned)

    def test_fsync_cannot_extend_two_second_phase(self):
        self.complete()
        self.on_sync = lambda: setattr(self, "now", self.subject.end)
        self.refuse_created("BROKER_CLOCK_OR_DEADLINE")
        self.assertFalse(self.subject.created.advanced)
        self.assertTrue(self.owner.log.poisoned)
        self.assertEqual(len(self.writes), 2)

    def test_api_peer_change_refuses_before_write(self):
        self.complete()
        self.api_peer = ("127.0.0.3", 7443)
        self.refuse_created("API_PEER_CHANGED")
        self.assertEqual(self.ledger, self.before_created)

    def test_api_peer_change_at_fsync_cannot_publish_success(self):
        self.complete()
        self.on_sync = lambda: setattr(self, "api_peer", ("127.0.0.3", 7443))
        self.refuse_created("API_PEER_CHANGED")
        self.assertEqual(len(self.writes), 2)
        self.assertTrue(self.held()["held"])

    def test_pending_action_change_at_fsync_is_not_acknowledged(self):
        self.complete()
        self.on_sync = lambda: self.subject.events.transcript.pending.update(verb="DELETE")
        self.refuse_created("BROKER_TRANSCRIPT_CHANGED")
        self.assertEqual(len(self.writes), 2)
        self.assertTrue(self.owner.log.poisoned)

    def test_reentrant_record_never_repeats_create_or_append(self):
        self.complete()
        self.on_append = self.subject.record_api_created
        failure = self.refuse_created("BROKER_OWNER_CHANGED")
        self.assertIn("BROKER_CREATED_ALREADY_ATTEMPTED", str(failure.__context__))
        self.assertEqual(self.ledger, self.before_created)
        self.assertEqual(len(self.plain_requests), 1)

    def test_repeated_committed_record_never_appends_again(self):
        self.complete()
        self.subject.record_api_created()
        before = self.ledger
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_ALREADY_ATTEMPTED"):
            self.subject.record_api_created()
        self.assertEqual(self.ledger, before)
        self.assertTrue(self.owner.log.poisoned)
        self.assertEqual(len(self.plain_requests), 1)

    def test_retained_check_refuses_unknown_append_after_created(self):
        self.complete()
        self.subject.record_api_created()
        self.ledger += b"unexpected"
        with self.assertRaisesRegex(ConformanceError, "BROKER_RUNNING_CHANGED"):
            self.subject.created.check()
        self.assertTrue(self.owner.log.poisoned)

    def test_retained_check_refuses_rollback_to_intent_history(self):
        self.complete()
        self.subject.record_api_created()
        self.ledger = self.before_created
        with self.assertRaisesRegex(ConformanceError, "BROKER_RUNNING_CHANGED"):
            self.subject.created.check()
        self.assertTrue(self.owner.log.poisoned)

    def test_retained_check_refuses_changed_row(self):
        self.complete()
        self.subject.record_api_created()
        self.subject.created.row_raw = b"{}"
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_HISTORY_CHANGED"):
            self.subject.created.check()
        self.assertTrue(self.owner.log.poisoned)

    def test_foreign_created_owner_is_not_checked_or_closed(self):
        self.complete()
        self.subject.record_api_created()
        original = self.subject.created
        foreign = self.subject.created = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_OWNER_CHANGED"):
            original.check()
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()

    def test_final_publication_cannot_target_a_replacement(self):
        self.complete()
        original = server._BrokerCreated.__init__
        foreign = Mock()
        def completed(resource, broker):
            original(resource, broker)
            broker.created = foreign
        with patch.object(server._BrokerCreated, "__init__", completed):
            self.refuse_created("BROKER_CREATED_PUBLICATION_CHANGED")
        self.assertNotIn("committed", vars(foreign))
        foreign.close.assert_not_called()
        self.assertEqual(len(self.writes), 2)

    def test_changed_local_broker_reference_closes_only_original_broker(self):
        self.complete()
        self.subject.record_api_created()
        original = self.subject.created
        foreign = original.broker = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_OWNER_CHANGED"):
            original.check()
        foreign.close.assert_not_called()
        self.assertNotIn("failed", vars(foreign))
        self.assertTrue(self.subject.closed and self.subject.failed and self.owner.log.poisoned)

    def test_changed_local_intent_reference_never_calls_foreign_poison(self):
        self.complete()
        self.subject.record_api_created()
        original = self.subject.created
        foreign = original.intent = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_OWNER_CHANGED"):
            original.check()
        foreign._poison.assert_not_called()
        foreign.close.assert_not_called()
        self.assertTrue(self.subject.intent.failed and self.owner.log.poisoned)

    def test_changed_local_log_reference_never_poisons_foreign_log(self):
        self.complete()
        self.subject.record_api_created()
        original = self.subject.created
        foreign = original.log = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATED_OWNER_CHANGED"):
            original.check()
        self.assertNotIn("poisoned", vars(foreign))
        foreign.close.assert_not_called()
        self.assertTrue(self.owner.log.poisoned)


class BrokerCreateResultTests(_BrokerEventFixture, unittest.TestCase):
    """Real broker/result/accounting code with explicit unit-only OS/TLS/store I/O."""
    start = BrokerCreatedTests.start
    action = BrokerCreatedTests.action
    read_secret = BrokerCreatedTests.read_secret
    connect_api = BrokerCreatedTests.connect_api
    write_memfd = BrokerCreatedTests.write_memfd
    make_context = BrokerCreatedTests.make_context
    wrap = BrokerCreatedTests.wrap
    handshake = BrokerCreatedTests.handshake
    read_intent = BrokerCreatedTests.read_intent
    append_intent = BrokerCreatedTests.append_intent
    sync_intent = BrokerCreatedTests.sync_intent
    held = BrokerCreatedTests.held
    reply = BrokerCreatedTests.reply
    http_write = BrokerCreatedTests.http_write
    http_read = BrokerCreatedTests.http_read
    prepare = BrokerCreatedTests.prepare

    def setUp(self):
        BrokerCreatedTests.setUp(self)
        self.sent_results = []
        self.on_result_send = lambda raw: None
        self.result_count = None

    def accounted(self):
        BrokerCreatedTests.complete(self)
        self.subject.record_api_created()
        self.before_result = self.ledger
        self.transcript_before = self.subject.events.transcript_raw
        self.socket.send.side_effect = self.result_send

    def result_send(self, raw):
        self.on_result_send(raw)
        self.sent_results.append(bytes(raw))
        return len(raw) if self.result_count is None else self.result_count

    def refuse_result(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason) as caught:
            self.subject.send_create_result()
        self.assertTrue(self.subject.failed and self.subject.closed)
        if self.subject._result_original is not None:
            self.assertTrue(self.subject._result_original.failed)
            self.assertFalse(self.subject._result_original.complete)
        return caught.exception

    def test_exact_created_frame_uses_recorded_identity_and_original_chain(self):
        import base64
        self.accounted()
        seen = []
        self.on_result_send = lambda raw: seen.append(deepcopy(self.held()["resources"]))
        self.assertIsNone(self.subject.send_create_result())
        result = self.subject.result
        self.assertIs(result, self.subject._result_original)
        self.assertTrue(result.complete and result.attempted)
        self.assertEqual(self.sent_results, [result.frame_raw])
        frame = json.loads(result.frame_raw)
        before = json.loads(self.transcript_before)
        self.assertEqual(frame["kind"], "RESOURCE_RESULT")
        self.assertEqual(frame["sequence"], before["sequence"] + 1)
        self.assertEqual(frame["previousDigest"], before["previous"])
        for field in ("bindingDigest", "reservationDigest", "runNonce", "caseId", "requestDigest",
                      "observationDigest", "generation", "challenge", "executionId"):
            self.assertEqual(frame[field], self.last_event[field])
        self.assertEqual(frame["payload"], dict(actionId=self.event_frame["payload"]["actionId"],
            outcome="CREATED", objectBase64=base64.b64encode(canonical_bytes(self.actual)).decode("ascii")))
        self.assertTrue(all(r["state"] == "CREATED" and r["uid"] == "created-unit-uid"
                            for r in seen[0].values()))
        self.socket.send.assert_called_once_with(result.frame_raw)

    def test_local_send_does_not_advance_original_transcript_or_release_capacity(self):
        self.accounted()
        self.subject.send_create_result()
        self.assertEqual(self.subject.events.transcript_raw, self.transcript_before)
        self.assertIsNotNone(self.subject.events.transcript.pending)
        self.assertIsNone(json.loads(self.subject.result.after)["pending"])
        self.assertIsNone(self.subject.events.transcript.cleanup)
        self.assertIsNone(self.subject.events.transcript.terminal)
        self.assertEqual(self.ledger, self.before_result)
        self.assertTrue(self.held()["held"])
        self.assertFalse(self.api.closed)
        self.assertEqual(len(self.writes), 2)

    def test_delivery_reads_no_new_credential_or_api_response(self):
        self.accounted()
        reads, sends = self.ssl.read.call_count, self.api_socket.send.call_count
        self.subject.send_create_result()
        self.assertEqual(self.secret_reads.call_count, 1)
        self.assertEqual(self.ssl.read.call_count, reads)
        self.assertEqual(self.api_socket.send.call_count, sends)
        self.api_socket.connect.assert_called_once()
        self.socket.recvmsg.assert_not_called()

    def test_original_accounting_and_result_checks_do_not_resend(self):
        self.accounted()
        self.subject.send_create_result()
        observations = len(self.observations)
        self.assertIsNone(self.subject.result.check())
        self.assertIsNone(self.subject.created.check())
        self.assertIsNone(self.subject.intent.check())
        self.assertIsNone(self.subject.exchange.check())
        self.assertGreater(len(self.observations), observations)
        self.socket.send.assert_called_once()
        self.assertEqual(self.ledger, self.before_result)

    def test_next_event_is_blocked_until_separate_retirement_transition(self):
        self.accounted()
        self.subject.send_create_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RESOURCE_RESULT_REQUIRED"):
            self.subject.poll()
        self.socket.recvmsg.assert_not_called()
        self.assertTrue(self.held()["held"])

    def test_no_caller_frame_outcome_identity_or_backend(self):
        for value in ({}, b"frame", "CREATED", Mock()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.send_create_result(value)
        self.socket.send.assert_not_called()
        self.assertIsNone(self.subject.result)

    def test_unowned_constructor_never_sends(self):
        self.accounted()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RESULT_OWNER"):
            server._BrokerCreateResult(self.subject)
        self.socket.send.assert_not_called()
        self.assertFalse(self.owner.log.poisoned)

    def test_intent_without_returned_identity_cannot_send_created(self):
        self.subject.record_create_intent()
        self.refuse_result("BROKER_RESULT_CREATED_REQUIRED")
        self.socket.send.assert_not_called()
        self.assertTrue(all(r["uid"] is None for r in self.held()["resources"].values()))

    def test_response_candidate_without_durable_created_record_cannot_send(self):
        BrokerCreatedTests.complete(self)
        self.refuse_result("BROKER_RESULT_CREATED_REQUIRED")
        self.socket.send.assert_not_called()
        self.assertEqual(len(self.writes), 1)

    def test_uncommitted_created_record_is_not_a_delivery_grant(self):
        self.accounted()
        self.subject.created.committed = False
        self.refuse_result("BROKER_RESULT_CREATED_REQUIRED")
        self.socket.send.assert_not_called()

    def test_changed_created_record_is_not_sent(self):
        self.accounted()
        self.subject.created.row_raw = b"{}"
        self.refuse_result("BROKER_CREATED_HISTORY_CHANGED")
        self.socket.send.assert_not_called()

    def test_changed_returned_object_is_not_sent(self):
        self.accounted()
        different = deepcopy(self.actual)
        different["metadata"]["uid"] = "foreign-uid"
        self.subject.created.response_raw = canonical_bytes(different)
        self.refuse_result("BROKER_CREATED_INPUT_CHANGED")
        self.socket.send.assert_not_called()

    def test_rollback_to_intent_history_refuses_before_send(self):
        self.accounted()
        self.ledger = self.before_created
        self.refuse_result("BROKER_RUNNING_CHANGED")
        self.socket.send.assert_not_called()

    def test_unexpected_append_refuses_before_send(self):
        self.accounted()
        self.ledger += b"unexpected"
        self.refuse_result("BROKER_RUNNING_CHANGED")
        self.socket.send.assert_not_called()

    def test_revoked_generation_refuses_before_send(self):
        self.accounted()
        self.observed["generation"] = "f" * 64
        self.refuse_result("BROKER_GENERATION_CHANGED")
        self.socket.send.assert_not_called()

    def test_broker_peer_replacement_refuses_before_send(self):
        self.accounted()
        self.process["start"] += 1
        self.refuse_result("BROKER_PEER_CHANGED")
        self.socket.send.assert_not_called()

    def test_api_peer_replacement_refuses_before_send(self):
        self.accounted()
        self.api_peer = ("127.0.0.3", 7443)
        self.refuse_result("API_PEER_CHANGED")
        self.socket.send.assert_not_called()

    def test_original_deadline_refuses_before_send(self):
        self.accounted()
        self.now = self.subject.deadline
        self.refuse_result("BROKER_CLOCK_OR_DEADLINE")
        self.socket.send.assert_not_called()

    def test_short_zero_boolean_or_float_send_is_ambiguous_and_never_retried(self):
        for count in (0, 1, True, 1.0):
            with self.subTest(count=count):
                self.accounted()
                self.result_count = count
                self.refuse_result("BROKER_RESULT_SEND_AMBIGUOUS")
                self.socket.send.assert_called_once()
                self.assertEqual(self.ledger, self.before_result)
                self.assertTrue(self.owner.log.poisoned and self.held()["held"])
                with self.assertRaises(ConformanceError):
                    self.subject.send_create_result()
                self.socket.send.assert_called_once()
            if type(count) is not float:
                self.stack.close()
                self.setUp()

    def test_send_error_keeps_created_uid_without_retry(self):
        self.accounted()
        def fail(raw):
            raise OSError("unit lost datagram")
        self.on_result_send = fail
        self.refuse_result("unit lost datagram")
        self.socket.send.assert_called_once()
        self.assertEqual(self.ledger, self.before_result)
        self.assertTrue(self.owner.log.poisoned)

    def test_generation_loss_during_send_prevents_success_publication(self):
        self.accounted()
        self.on_result_send = lambda raw: self.observed.update(generation="f" * 64)
        self.refuse_result("BROKER_GENERATION_CHANGED")
        self.assertEqual(len(self.sent_results), 1)
        self.assertEqual(self.subject.events.transcript_raw, self.transcript_before)
        self.assertTrue(self.owner.log.poisoned)

    def test_broker_peer_loss_during_send_prevents_success_publication(self):
        self.accounted()
        self.on_result_send = lambda raw: self.process.update(start=self.process["start"] + 1)
        self.refuse_result("BROKER_PEER_CHANGED")
        self.assertEqual(len(self.sent_results), 1)

    def test_api_peer_loss_during_send_prevents_success_publication(self):
        self.accounted()
        self.on_result_send = lambda raw: setattr(self, "api_peer", ("127.0.0.3", 7443))
        self.refuse_result("API_PEER_CHANGED")
        self.assertEqual(len(self.sent_results), 1)
        self.assertTrue(self.owner.log.poisoned)

    def test_late_send_cannot_extend_two_second_control_phase(self):
        self.accounted()
        self.on_result_send = lambda raw: setattr(self, "now", self.subject.end)
        self.refuse_result("BROKER_CLOCK_OR_DEADLINE")
        self.assertEqual(len(self.sent_results), 1)
        self.assertEqual(self.ledger, self.before_result)

    def test_frame_substitution_during_send_cannot_be_published(self):
        self.accounted()
        self.on_result_send = lambda raw: setattr(self.subject.result, "frame_raw", b"foreign")
        self.refuse_result("BROKER_RESULT_CANDIDATE_CHANGED")
        self.assertNotEqual(self.sent_results, [b"foreign"])

    def test_proposed_transcript_substitution_is_detected(self):
        self.accounted()
        self.on_result_send = lambda raw: setattr(self.subject.result, "after", b"{}")
        self.refuse_result("BROKER_RESULT_CANDIDATE_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.transcript_before)

    def test_history_loss_during_send_cannot_be_published(self):
        self.accounted()
        self.on_result_send = lambda raw: setattr(self, "ledger", self.before_created)
        self.refuse_result("BROKER_RUNNING_CHANGED")
        self.assertEqual(len(self.sent_results), 1)

    def test_repeated_completed_send_never_retransmits(self):
        self.accounted()
        self.subject.send_create_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RESULT_ALREADY_ATTEMPTED"):
            self.subject.send_create_result()
        self.socket.send.assert_called_once()
        self.assertTrue(self.owner.log.poisoned)

    def test_reentrant_send_is_refused_without_second_datagram(self):
        self.accounted()
        self.on_result_send = lambda raw: self.subject.send_create_result()
        self.refuse_result()
        self.socket.send.assert_called_once()
        self.assertEqual(self.sent_results, [])
        self.assertEqual(self.ledger, self.before_result)

    def test_foreign_created_owner_is_not_called_or_poisoned(self):
        self.accounted()
        self.subject.send_create_result()
        original = self.subject.result
        foreign = original.created = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RESULT_OWNER_CHANGED"):
            original.check()
        foreign.check.assert_not_called()
        foreign._poison.assert_not_called()
        self.assertTrue(self.owner.log.poisoned)

    def test_foreign_broker_is_not_closed(self):
        self.accounted()
        self.subject.send_create_result()
        original = self.subject.result
        foreign = original.broker = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RESULT_OWNER_CHANGED"):
            original.check()
        foreign.close.assert_not_called()
        self.assertNotIn("failed", vars(foreign))
        self.assertTrue(self.subject.closed and self.subject.failed)

    def test_foreign_result_is_not_checked_or_closed(self):
        self.accounted()
        self.subject.send_create_result()
        original = self.subject.result
        foreign = self.subject.result = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RESULT_OWNER_CHANGED"):
            original.check()
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()
        self.assertTrue(self.owner.log.poisoned)

    def test_instance_shadow_created_check_is_not_used(self):
        self.accounted()
        self.subject.created.check = Mock(side_effect=AssertionError("foreign check"))
        self.subject.send_create_result()
        self.subject.created.check.assert_not_called()
        self.socket.send.assert_called_once()

    def test_final_publication_cannot_target_replacement_result(self):
        self.accounted()
        original = server._BrokerCreateResult.__init__
        foreign = Mock()
        def completed(resource, broker):
            original(resource, broker)
            broker.result = foreign
        with patch.object(server._BrokerCreateResult, "__init__", completed):
            self.refuse_result("BROKER_RESULT_PUBLICATION_CHANGED")
        self.assertNotIn("complete", vars(foreign))
        foreign.close.assert_not_called()
        self.socket.send.assert_called_once()


class BrokerCreateRetirementTests(_BrokerEventFixture, unittest.TestCase):
    """Real retirement/result/codec owners, with unit-only OS/TLS/storage doubles."""
    start = BrokerCreateResultTests.start
    action = BrokerCreateResultTests.action
    read_secret = BrokerCreateResultTests.read_secret
    connect_api = BrokerCreateResultTests.connect_api
    write_memfd = BrokerCreateResultTests.write_memfd
    make_context = BrokerCreateResultTests.make_context
    wrap = BrokerCreateResultTests.wrap
    handshake = BrokerCreateResultTests.handshake
    read_intent = BrokerCreateResultTests.read_intent
    append_intent = BrokerCreateResultTests.append_intent
    sync_intent = BrokerCreateResultTests.sync_intent
    held = BrokerCreateResultTests.held
    reply = BrokerCreateResultTests.reply
    http_write = BrokerCreateResultTests.http_write
    http_read = BrokerCreateResultTests.http_read
    prepare = BrokerCreateResultTests.prepare
    accounted = BrokerCreateResultTests.accounted
    result_send = BrokerCreateResultTests.result_send

    def setUp(self):
        BrokerCreateResultTests.setUp(self)
        self.on_api_close = lambda: None
        self.api_socket.close.side_effect = self.close_api

    def close_api(self):
        self.events.append("retire-api-close")
        self.on_api_close()

    def delivered(self):
        self.accounted()
        self.subject.send_create_result()
        self.result = self.subject.result
        self.retire_ledger = self.ledger
        self.retire_before = self.subject.events.transcript_raw
        self.retire_after = self.result.after
        self.parser = self.subject.events.transcript

    def refuse_retirement(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason) as caught:
            self.subject.retire_create_result()
        self.assertTrue(self.subject.failed and self.subject.closed)
        if self.subject._retirement_original is not None:
            self.assertTrue(self.subject._retirement_original.failed)
            self.assertFalse(self.subject._retirement_original.complete)
        return caught.exception

    def test_success_closes_original_api_then_advances_original_parser_once(self):
        self.delivered()
        seen = []
        self.on_api_close = lambda: seen.append(self.subject.events.transcript_raw)
        self.assertIsNone(self.subject.retire_create_result())
        retired = self.subject.retirement
        self.assertIs(retired, self.subject._retirement_original)
        self.assertTrue(retired.complete and retired.retired and retired.advanced)
        self.assertEqual(seen, [self.retire_before])
        self.assertIs(self.subject.events.transcript, self.parser)
        self.assertIs(self.subject.dispatch.transcript, self.parser)
        self.assertEqual(self.subject.events.transcript_raw, self.retire_after)
        self.assertIsNone(self.parser.pending)
        self.assertEqual(self.parser.previous, server.byte_digest(self.result.frame_raw))
        self.assertEqual(self.parser.sequence, json.loads(self.retire_before)["sequence"] + 1)
        self.assertTrue(self.api.closed)
        self.assertFalse(self.api.ready)
        self.assertIsNone(self.api.sock)
        self.assertIsNone(self.api.tls)
        self.api_socket.close.assert_called_once_with()
        self.socket.close.assert_not_called()
        self.socket.send.assert_called_once_with(self.result.frame_raw)

    def test_retirement_does_not_release_resources_write_history_or_claim_cleanup(self):
        self.delivered()
        writes = len(self.writes)
        mutations = [event for event in self.io_events if event != "read"]
        self.subject.retire_create_result()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertEqual(len(self.writes), writes)
        self.assertEqual([event for event in self.io_events if event != "read"], mutations)
        self.assertTrue(self.held()["held"])
        self.assertTrue(all(r["state"] == "CREATED" for r in self.held()["resources"].values()))
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)

    def test_retirement_reads_no_new_credential_and_performs_no_transport_io(self):
        self.delivered()
        calls = self.secret_reads.call_count, self.ssl.read.call_count, self.api_socket.send.call_count
        self.subject.retire_create_result()
        self.assertEqual(calls, (self.secret_reads.call_count, self.ssl.read.call_count, self.api_socket.send.call_count))
        self.socket.recvmsg.assert_not_called()
        self.api_socket.connect.assert_called_once()
        self.assertEqual(self.sent_results, [self.result.frame_raw])

    def test_retained_checks_reobserve_without_reclosing_or_replaying(self):
        self.delivered()
        self.subject.retire_create_result()
        before = len(self.observations)
        self.assertIsNone(self.subject.retirement.check())
        self.assertGreater(len(self.observations), before)
        self.assertEqual(self.subject.events.transcript_raw, self.retire_after)
        self.api_socket.close.assert_called_once()
        self.socket.send.assert_called_once()

    def test_next_event_waits_for_separate_action_owner_handoff(self):
        self.delivered()
        self.subject.retire_create_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_ACTION_HANDOFF_REQUIRED"):
            self.subject.poll()
        self.socket.recvmsg.assert_not_called()
        self.assertTrue(self.held()["held"])

    def test_closed_api_cannot_be_reused_for_another_action(self):
        self.delivered()
        self.subject.retire_create_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_API_ALREADY_ATTEMPTED"):
            self.subject.prepare_api()
        self.api_socket.connect.assert_called_once()
        self.secret_reads.assert_called_once()

    def test_no_caller_result_frame_or_cleanup_selector(self):
        for value in ({}, b"frame", True, Mock()):
            with self.subTest(kind=type(value).__name__), self.assertRaises(TypeError):
                self.subject.retire_create_result(value)
        self.assertIsNone(self.subject.retirement)
        self.api_socket.close.assert_not_called()

    def test_unowned_constructor_never_retires_or_advances(self):
        self.delivered()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETIREMENT_OWNER"):
            server._BrokerCreateRetirement(self.subject)
        self.api_socket.close.assert_not_called()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)
        self.assertFalse(self.owner.log.poisoned)

    def test_no_created_result_cannot_retire(self):
        self.refuse_retirement("BROKER_RETIREMENT_DELIVERY_REQUIRED")
        self.api_socket.close.assert_not_called()
        self.socket.send.assert_not_called()

    def test_recorded_but_unsent_result_cannot_retire(self):
        self.accounted()
        before = self.subject.events.transcript_raw
        self.refuse_retirement("BROKER_RETIREMENT_DELIVERY_REQUIRED")
        self.assertEqual(self.subject.events.transcript_raw, before)
        self.socket.send.assert_not_called()

    def test_unpublished_send_is_not_a_retirement_grant(self):
        self.delivered()
        self.result.complete = False
        self.refuse_retirement("BROKER_RETIREMENT_DELIVERY_REQUIRED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_ambiguous_send_cannot_be_retired_as_success(self):
        self.accounted()
        self.result_count = 1
        with self.assertRaises(ConformanceError):
            self.subject.send_create_result()
        before = self.subject.events.transcript_raw
        self.refuse_retirement("BROKER_RETIREMENT_ALREADY_ATTEMPTED")
        self.assertEqual(self.subject.events.transcript_raw, before)
        self.socket.send.assert_called_once()

    def test_changed_result_frame_refuses_before_advancement(self):
        self.delivered()
        self.result.frame_raw = b"foreign"
        self.refuse_retirement("BROKER_RESULT_CANDIDATE_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_changed_created_identity_refuses_before_advancement(self):
        self.delivered()
        self.subject.created.response_raw = b"{}"
        self.refuse_retirement("BROKER_CREATED_INPUT_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_api_peer_replacement_before_close_is_rejected(self):
        self.delivered()
        self.api_peer = ("127.0.0.3", 7443)
        self.refuse_retirement("API_PEER_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_history_rollback_before_close_is_rejected(self):
        self.delivered()
        self.ledger = self.before_created
        self.refuse_retirement("BROKER_RUNNING_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_close_failure_preserves_first_error_and_holds_capacity(self):
        self.delivered()
        failure = OSError("unit close ambiguous")
        def fail():
            raise failure
        self.on_api_close = fail
        error = self.refuse_retirement("unit close ambiguous")
        self.assertIs(error, failure)
        self.assertIs(self.api.cleanup_failure, failure)
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)
        self.assertTrue(self.owner.log.poisoned and self.held()["held"])
        self.api_socket.close.assert_called_once()
        self.api_socket.detach.assert_called_once()
        self.assertIn("observe", self.events[self.events.index("retire-api-close") + 1:])

    def test_close_does_not_touch_recycled_descriptor(self):
        self.delivered()
        original = server._BrokerApi.close
        def recycled(api):
            self.fds[81].st_ino += 1
            return original(api)
        with patch.object(server._BrokerApi, "close", recycled):
            self.refuse_retirement("API_CLOSE_FD_REUSED")
        self.api_socket.close.assert_not_called()
        self.api_socket.detach.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_instance_shadow_close_is_not_invoked(self):
        self.delivered()
        self.api.close = Mock(side_effect=AssertionError("foreign close"))
        self.subject.retire_create_result()
        self.api.close.assert_not_called()
        self.api_socket.close.assert_called_once()

    def test_close_noop_cannot_advance_transcript(self):
        self.delivered()
        with patch.object(server._BrokerApi, "close", return_value=None):
            self.refuse_retirement("BROKER_RETIREMENT_API_NOT_CLOSED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)
        # The deliberately inert unit close did not release its original owner.
        server._BrokerApi.close(self.api)

    def test_non_none_close_result_is_rejected(self):
        self.delivered()
        original = server._BrokerApi.close
        def wrong(api):
            original(api)
            return True
        with patch.object(server._BrokerApi, "close", wrong):
            self.refuse_retirement("BROKER_RETIREMENT_CLOSE_RESULT")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_generation_loss_during_close_prevents_advancement(self):
        self.delivered()
        self.on_api_close = lambda: self.observed.update(generation="f" * 64)
        self.refuse_retirement("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)
        self.api_socket.close.assert_called_once()

    def test_peer_loss_during_close_prevents_advancement(self):
        self.delivered()
        self.on_api_close = lambda: self.process.update(start=self.process["start"] + 1)
        self.refuse_retirement("BROKER_PEER_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_history_append_during_close_prevents_advancement(self):
        self.delivered()
        self.on_api_close = lambda: setattr(self, "ledger", self.ledger + b"unexpected")
        self.refuse_retirement("BROKER_RUNNING_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_close_deadline_cannot_be_renewed(self):
        self.delivered()
        self.on_api_close = lambda: setattr(self, "now", self.subject.end)
        self.refuse_retirement("BROKER_CLOCK_OR_DEADLINE")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_result_data_substitution_during_close_is_rejected(self):
        self.delivered()
        self.on_api_close = lambda: setattr(self.result, "record_raw", b"{}")
        self.refuse_retirement("BROKER_RETIREMENT_DATA_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_reentrant_retirement_never_advances_or_closes_twice(self):
        self.delivered()
        self.on_api_close = lambda: self.subject.retire_create_result()
        self.refuse_retirement("BROKER_RETIREMENT_ALREADY_ATTEMPTED")
        self.api_socket.close.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_repeated_retirement_never_replays_or_recloses(self):
        self.delivered()
        self.subject.retire_create_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETIREMENT_ALREADY_ATTEMPTED"):
            self.subject.retire_create_result()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_after)
        self.api_socket.close.assert_called_once()
        self.socket.send.assert_called_once()
        self.assertTrue(self.owner.log.poisoned)

    def test_codec_failure_leaves_closed_api_and_held_accounting(self):
        self.delivered()
        original = server.BrokerTranscript.accept
        def fail(parser, raw, sender):
            if parser is self.parser:
                raise ConformanceError("UNIT_CODEC_REFUSED", "unit refusal")
            return original(parser, raw, sender)
        with patch.object(server.BrokerTranscript, "accept", fail):
            self.refuse_retirement("UNIT_CODEC_REFUSED")
        self.assertTrue(self.api.closed and self.held()["held"])
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_post_advance_guard_failure_does_not_undo_transcript_or_publish(self):
        self.delivered()
        original = server.BrokerTranscript.accept
        def revoke(parser, raw, sender):
            value = original(parser, raw, sender)
            if parser is self.parser:
                self.observed["generation"] = "f" * 64
            return value
        with patch.object(server.BrokerTranscript, "accept", revoke):
            self.refuse_retirement("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.subject.events.transcript_raw, self.retire_after)
        self.assertTrue(self.api.closed and self.owner.log.poisoned)

    def test_closed_owner_check_rejects_later_history_rollback(self):
        self.delivered()
        self.subject.retire_create_result()
        self.ledger = self.before_created
        with self.assertRaisesRegex(ConformanceError, "BROKER_RUNNING_CHANGED"):
            self.subject.retirement.check()
        self.assertTrue(self.subject.failed and self.owner.log.poisoned)
        self.api_socket.close.assert_called_once()

    def test_closed_owner_check_rejects_transcript_rewind(self):
        self.delivered()
        self.subject.retire_create_result()
        self.subject.events.transcript_raw = self.retire_before
        with self.assertRaisesRegex(ConformanceError, "BROKER_TRANSCRIPT_CHANGED"):
            self.subject.retirement.check()
        self.api_socket.close.assert_called_once()

    def test_foreign_retirement_is_not_published_or_called(self):
        self.delivered()
        original = server._BrokerCreateRetirement.__init__
        foreign = Mock()
        def replace(resource, broker):
            original(resource, broker)
            broker.retirement = foreign
        with patch.object(server._BrokerCreateRetirement, "__init__", replace):
            self.refuse_retirement("BROKER_RETIREMENT_PUBLICATION_CHANGED")
        self.assertNotIn("complete", vars(foreign))
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()

    def test_foreign_api_reference_is_not_checked_or_closed(self):
        self.delivered()
        self.subject.retire_create_result()
        original = self.subject.retirement
        foreign = original.api = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETIREMENT_OWNER_CHANGED"):
            original.check()
        foreign.check.assert_not_called()
        foreign.close.assert_not_called()
        self.api_socket.close.assert_called_once()

    def test_foreign_events_reference_is_not_checked(self):
        self.delivered()
        self.subject.retire_create_result()
        original = self.subject.retirement
        foreign = original.events = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETIREMENT_OWNER_CHANGED"):
            original.check()
        foreign._check.assert_not_called()
        foreign._state_check.assert_not_called()

    def test_foreign_broker_reference_is_not_closed(self):
        self.delivered()
        self.subject.retire_create_result()
        original = self.subject.retirement
        foreign = original.broker = Mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETIREMENT_OWNER_CHANGED"):
            original.check()
        foreign.close.assert_not_called()
        self.assertTrue(self.subject.failed and self.owner.log.poisoned)


    def test_socket_substitution_after_live_check_cannot_retire_or_close_foreign(self):
        self.delivered()
        foreign = Mock()
        def replace():
            retired = self.subject.retirement
            if retired is not None and hasattr(retired, "data_pin"):
                self.api.sock = foreign
        self.on_observe = replace
        self.refuse_retirement("BROKER_RETIREMENT_TRANSPORT_CHANGED")
        foreign.close.assert_not_called()
        foreign.fileno.assert_not_called()
        self.api_socket.close.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_tls_substitution_after_live_check_cannot_retire(self):
        self.delivered()
        foreign = Mock()
        def replace():
            retired = self.subject.retirement
            if retired is not None and hasattr(retired, "data_pin"):
                self.api.tls = foreign
        self.on_observe = replace
        self.refuse_retirement("BROKER_RETIREMENT_TRANSPORT_CHANGED")
        foreign.close.assert_not_called()
        self.api_socket.close.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_descriptor_pin_substitution_after_live_check_refuses_before_close(self):
        self.delivered()
        def replace():
            retired = self.subject.retirement
            if retired is not None and hasattr(retired, "data_pin"):
                self.api._socket_pin = (9, 99, stat.S_IFSOCK)
        self.on_observe = replace
        self.refuse_retirement("BROKER_RETIREMENT_DATA_CHANGED")
        self.api_socket.close.assert_not_called()
        self.api_socket.detach.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, self.retire_before)

    def test_closed_descriptor_metadata_is_pinned_without_reopening_it(self):
        self.delivered()
        self.subject.retire_create_result()
        self.api._socket_fd = 89
        with self.assertRaisesRegex(ConformanceError, "BROKER_RETIREMENT_DATA_CHANGED"):
            self.subject.retirement.check()
        self.api_socket.close.assert_called_once()
        self.api_socket.connect.assert_called_once()


class BrokerActionHandoffTests(_BrokerEventFixture, unittest.TestCase):
    """Real CREATE/retirement/handoff/receiver; inherited OS/TLS/store fixture.

    These are action-lifecycle regressions, not the separate C6 full-server
    factory acceptance or independently installed native qualification.
    """
    start = BrokerCreateRetirementTests.start
    action = BrokerCreateRetirementTests.action
    read_secret = BrokerCreateRetirementTests.read_secret
    connect_api = BrokerCreateRetirementTests.connect_api
    write_memfd = BrokerCreateRetirementTests.write_memfd
    make_context = BrokerCreateRetirementTests.make_context
    wrap = BrokerCreateRetirementTests.wrap
    handshake = BrokerCreateRetirementTests.handshake
    read_intent = BrokerCreateRetirementTests.read_intent
    append_intent = BrokerCreateRetirementTests.append_intent
    sync_intent = BrokerCreateRetirementTests.sync_intent
    held = BrokerCreateRetirementTests.held
    reply = BrokerCreateRetirementTests.reply
    http_write = BrokerCreateRetirementTests.http_write
    http_read = BrokerCreateRetirementTests.http_read
    prepare = BrokerCreateRetirementTests.prepare
    accounted = BrokerCreateRetirementTests.accounted
    result_send = BrokerCreateRetirementTests.result_send
    close_api = BrokerCreateRetirementTests.close_api
    delivered = BrokerCreateRetirementTests.delivered

    def setUp(self):
        BrokerCreateRetirementTests.setUp(self)

    def retired(self):
        self.delivered()
        self.subject.retire_create_result()
        self.retirement = self.subject.retirement
        self.last_event = json.loads(self.result.frame_raw)
        self.action_digest = json.loads(self.result.action_raw)["manifestDigest"]

    def test_retired_create_handoff_keeps_uid_and_allows_next_get_frame(self):
        self.retired()
        before = self.subject.deadline, self.ledger, self.secret_reads.call_count, len(self.sent_results)
        self.assertIsNone(self.subject.handoff_create_result())
        self.assertEqual(before, (self.subject.deadline, self.ledger, self.secret_reads.call_count, len(self.sent_results)))
        self.assertIs(self.subject.events.transcript, self.parser)
        self.assertTrue(self.held()["held"])
        for name in ("api", "intent", "exchange", "created", "result", "retirement"):
            self.assertIsNone(getattr(self.subject, name))
            self.assertIsNone(getattr(self.subject, "_" + name + "_original"))
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "GET", "manifestDigest": self.action_digest})
        self.assertEqual(json.loads(self.take())["payload"]["verb"], "GET")
        self.assertEqual(self.parser.actions, {1, 2})
        self.assertEqual(self.parser.pending["actionId"], 2)
        self.api_socket.close.assert_called_once()
        self.assertEqual(self.secret_reads.call_count, before[2])

    def test_handoff_cannot_skip_retirement_or_acknowledge_an_unsent_result(self):
        self.delivered()
        with self.assertRaisesRegex(ConformanceError, "BROKER_HANDOFF_RETIREMENT_REQUIRED"):
            self.subject.handoff_create_result()
        self.assertTrue(self.subject.closed and self.held()["held"])
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_duplicate_handoff_does_not_reopen_api_or_release_resources(self):
        self.retired()
        self.subject.handoff_create_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_HANDOFF_RETIREMENT_REQUIRED"):
            self.subject.handoff_create_result()
        self.api_socket.connect.assert_called_once()
        self.api_socket.close.assert_called_once()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_action_id_replay_after_handoff_still_refuses(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 1, "verb": "GET", "manifestDigest": self.action_digest})
        self.refused("BROKER_RESOURCE_ACTION_INVALID")
        self.assertTrue(self.held()["held"])

    def test_original_generation_loss_refuses_before_handoff(self):
        self.retired()
        self.observed["generation"] = "f" * 64
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.handoff_create_result()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertEqual(self.subject.events.handoffs, ())
        self.api_socket.close.assert_called_once()

    def test_substituted_retirement_is_never_called_or_closed(self):
        self.retired()
        foreign = Mock()
        self.subject.retirement = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_HANDOFF_RETIREMENT_REQUIRED"):
            self.subject.handoff_create_result()
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_changed_handoff_archive_refuses_before_next_frame(self):
        self.retired()
        self.subject.handoff_create_result()
        self.subject.events.handoffs = ()
        self.socket.recvmsg.reset_mock()
        self.refused("BROKER_HANDOFF_HISTORY_CHANGED")
        self.socket.recvmsg.assert_not_called()

    def test_no_caller_frame_history_or_new_deadline_parameter(self):
        for value in ({}, b"frame", True, Mock()):
            with self.subTest(value_type=type(value)), self.assertRaises(TypeError):
                self.subject.handoff_create_result(value)
        self.api_socket.connect.assert_not_called()

    def test_next_get_authenticates_new_channel_from_original_read_once_identity(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "GET", "manifestDigest": self.action_digest})
        self.take()
        first_api = self.api
        next_socket = Mock()
        next_socket.fileno.return_value = 83
        next_socket.getpeername.side_effect = lambda: self.api_peer
        next_socket.connect.side_effect = self.connect_api
        next_socket.send.side_effect = lambda raw: len(raw)
        self.fds[83] = SimpleNamespace(st_dev=1, st_ino=83, st_mode=stat.S_IFSOCK | 0o600)
        self.mocks["socket"].return_value = next_socket
        self.fd_bytes.clear()  # a new synthetic memfd, not retained old contents
        self.subject.prepare_api()
        self.assertIsNot(first_api, self.subject.api)
        self.assertTrue(first_api.closed)
        self.assertIs(self.subject.api.sock, next_socket)
        self.assertTrue(self.subject.api.ready)
        self.secret_reads.assert_called_once()
        next_socket.connect.assert_called_once_with(self.api_peer)
        self.assertEqual(self.subject.deadline, first_api.deadline)
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_changed_retained_identity_refuses_next_get_before_reopening_or_connect(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "GET", "manifestDigest": self.action_digest})
        self.take()
        self.owner.secrets.raw[self.api_endpoint["credentialFileReference"]] = b"unit substituted identity"
        with self.assertRaisesRegex(ConformanceError, "API_CREDENTIAL_OWNER_CHANGED"):
            self.subject.prepare_api()
        self.secret_reads.assert_called_once()
        self.api_socket.connect.assert_called_once()
        self.assertEqual(self.ledger, self.retire_ledger)


class BrokerGetActionTests(_BrokerEventFixture, unittest.TestCase):
    """Real sequential CREATE/GET owners; unit OS, observer, TLS and store edges.

    These action tests do not stand in for C6 actual NativeProxyServer factories.
    """
    start = BrokerActionHandoffTests.start
    action = BrokerActionHandoffTests.action
    read_secret = BrokerActionHandoffTests.read_secret
    connect_api = BrokerActionHandoffTests.connect_api
    write_memfd = BrokerActionHandoffTests.write_memfd
    make_context = BrokerActionHandoffTests.make_context
    wrap = BrokerActionHandoffTests.wrap
    handshake = BrokerActionHandoffTests.handshake
    read_intent = BrokerActionHandoffTests.read_intent
    append_intent = BrokerActionHandoffTests.append_intent
    sync_intent = BrokerActionHandoffTests.sync_intent
    held = BrokerActionHandoffTests.held
    reply = BrokerActionHandoffTests.reply
    http_write = BrokerActionHandoffTests.http_write
    http_read = BrokerActionHandoffTests.http_read
    prepare = BrokerActionHandoffTests.prepare
    accounted = BrokerActionHandoffTests.accounted
    result_send = BrokerActionHandoffTests.result_send
    close_api = BrokerActionHandoffTests.close_api
    delivered = BrokerActionHandoffTests.delivered
    retired = BrokerActionHandoffTests.retired

    def setUp(self):
        BrokerActionHandoffTests.setUp(self)

    def next_get(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "GET", "manifestDigest": self.action_digest})
        self.take()
        self.get_socket = Mock()
        self.get_socket.fileno.return_value = 83
        self.get_socket.getpeername.side_effect = lambda: self.api_peer
        self.get_socket.connect.side_effect = self.connect_api
        self.get_socket.send.side_effect = lambda raw: len(raw)
        self.get_socket.close.side_effect = self.close_api
        self.fds[83] = SimpleNamespace(st_dev=1, st_ino=83, st_mode=stat.S_IFSOCK | 0o600)
        self.mocks["socket"].return_value = self.get_socket
        self.fd_bytes.clear()
        self.subject.prepare_api()
        self.get_api = self.subject.api
        self.plain_requests.clear()
        self.sent_results.clear()
        self.socket.send.reset_mock()
        self.get_socket.send.reset_mock()
        self.ssl.read.reset_mock()
        self.reply(canonical_bytes(self.actual))
        self.get_before = self.subject.events.transcript_raw

    def refused_get(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason):
            self.subject.exchange_api_get()
        self.assertTrue(self.subject.failed and self.subject.closed)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)
        self.socket.send.assert_not_called()

    def test_get_reads_exact_created_uid_without_rewriting_ledger_or_result(self):
        self.next_get()
        writes = len(self.writes)
        self.assertIsNone(self.subject.exchange_api_get())
        action = self.subject.get_action
        self.assertIs(type(action), server._BrokerGetAction)
        self.assertIs(action, self.subject._get_action_original)
        self.assertTrue(action.complete and action.attempted)
        self.assertFalse(action.sent or action.retired or action.advanced)
        expected = server.http_message("GET /api/v1/namespaces/" + self.manifest["metadata"]["namespace"]
            + "/configmaps/" + self.manifest["metadata"]["name"] + " HTTP/1.1", b"", "proxy.unit")
        self.assertEqual(self.plain_requests, [expected])
        self.assertEqual(action.response_raw, canonical_bytes(self.actual))
        self.assertEqual(json.loads(action.record_raw)["uid"], "created-unit-uid")
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertEqual(len(self.writes), writes)
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.secret_reads.assert_called_once()
        self.socket.send.assert_not_called()

    def test_get_result_then_handoff_keeps_original_parser_and_next_action_chain(self):
        import base64
        self.next_get()
        self.subject.exchange_api_get()
        action = self.subject.get_action
        self.assertIsNone(self.subject.send_get_result())
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        frame = json.loads(action.frame_raw)
        self.assertEqual(frame["payload"], {"actionId": 2, "outcome": "PRESENT",
            "objectBase64": base64.b64encode(canonical_bytes(self.actual)).decode("ascii")})
        self.assertEqual(self.sent_results, [action.frame_raw])
        seen = []
        self.on_api_close = lambda: seen.append(self.subject.events.transcript_raw)
        self.assertIsNone(self.subject.handoff_get_result())
        self.assertEqual(seen, [self.get_before])
        self.get_socket.close.assert_called_once()
        self.assertTrue(action.retired and action.advanced and self.get_api.closed)
        self.assertIsNone(self.subject.get_action)
        self.assertIsNone(self.subject.api)
        self.assertIs(self.subject.events.transcript, self.parser)
        self.assertEqual(self.parser.actions, {1, 2})
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])
        self.assertEqual(len(self.subject.events.handoffs), 2)
        self.last_event = frame
        self.queue("RESOURCE_ACTION", {"actionId": 3, "verb": "GET", "manifestDigest": self.action_digest})
        self.take()
        self.assertEqual(self.parser.pending["actionId"], 3)
        self.assertEqual(self.parser.actions, {1, 2, 3})
        self.assertEqual(action.deadline, self.subject.deadline)

    def test_updated_resource_version_does_not_change_recorded_ownership(self):
        self.next_get()
        self.actual["metadata"]["resourceVersion"] = "124"
        self.reply(canonical_bytes(self.actual))
        self.subject.exchange_api_get()
        self.assertEqual(json.loads(self.subject.get_action.response_raw)["metadata"]["resourceVersion"], "124")
        self.assertEqual(json.loads(self.subject.get_action.record_raw)["resourceVersion"], "123")
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_changed_uid_refuses_without_adopting_or_sending_a_result(self):
        self.next_get()
        self.actual["metadata"]["uid"] = "foreign-uid"
        self.reply(canonical_bytes(self.actual))
        self.refused_get("ADMISSION_UID_CHANGED")
        self.assertEqual(len(self.plain_requests), 1)
        self.assertEqual(next(iter(self.held()["resources"].values()))["uid"], "created-unit-uid")

    def test_changed_labels_refuse_without_claiming_absence(self):
        self.next_get()
        labels = self.actual["metadata"]["labels"]
        labels[next(iter(labels))] = "foreign-tenant"
        self.reply(canonical_bytes(self.actual))
        self.refused_get("ADMISSION_POST_MUTATION_MISMATCH")

    def test_changed_manifest_refuses_without_overwriting_tenant_data(self):
        self.next_get()
        self.actual["data"] = {"foreign": "replacement"}
        self.reply(canonical_bytes(self.actual))
        self.refused_get("ADMISSION_POST_MUTATION_MISMATCH")
        self.assertTrue(all(raw.startswith(b"GET ") for raw in self.plain_requests))

    def test_http_404_is_not_silently_interpreted_as_absence(self):
        self.next_get()
        self.reply(b'{"reason":"NotFound"}', status="HTTP/1.1 404 Not Found")
        self.refused_get("MISSING_FIELD")
        self.assertEqual(len(self.plain_requests), 1)

    def test_http_200_error_object_is_not_a_present_resource(self):
        self.next_get()
        self.reply(b'{"reason":"NotFound","status":"Failure"}')
        self.refused_get("ADMISSION_IDENTITY_MISSING")

    def test_surplus_response_refuses_before_any_resource_result(self):
        self.next_get()
        self.http_bytes.extend(b"surplus")
        self.refused_get("HTTP_SURPLUS")

    def test_oversized_response_refuses_without_result_or_cleanup(self):
        self.next_get()
        self.reply(b" " * 16385)
        self.refused_get("BROKER_GET_RESPONSE_SIZE")

    def test_duplicate_json_keys_refuse_without_result(self):
        self.next_get()
        raw = canonical_bytes(self.actual)
        self.reply(raw[:-1] + b',"kind":"ConfigMap"}')
        self.refused_get()

    def test_generation_loss_during_read_holds_uid_and_sends_no_result(self):
        self.next_get()
        self.on_http_read = lambda: self.observed.update(generation="f" * 64)
        self.refused_get("BROKER_GENERATION_CHANGED")
        self.assertEqual(len(self.plain_requests), 1)

    def test_generation_loss_before_get_sends_no_http(self):
        self.next_get()
        self.observed["generation"] = "f" * 64
        self.refused_get("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_no_create_record_refuses_get_before_http(self):
        # The existing API unit fixture permits authentication independently of
        # execution. A GET owner still requires an original durable CREATED UID.
        frame = self.event_frame
        frame["payload"]["verb"] = "GET"
        self.raw_override = canonical_bytes(frame)
        # Reconstruct the pending data from the original STARTED and changed
        # broker frame; do not mock the action's ownership decision.
        transcript = server.BrokerTranscript(self.subject.dispatch.binding_raw, self.subject.dispatch.dispatch_raw)
        transcript.accept(self.subject.dispatch.started, "BROKER")
        transcript.accept(self.raw_override, "BROKER")
        self.subject.dispatch.transcript = self.subject.dispatch._transcript_original = transcript
        self.subject.events.transcript = transcript
        self.subject.events.transcript_raw = server._BrokerEvents._snapshot(transcript)
        BrokerApiConnectionTests.prepare(self)
        self.plain_requests.clear()
        self.socket.send.reset_mock()
        before = self.ledger
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_CREATED_UID_REQUIRED"):
            self.subject.exchange_api_get()
        self.assertEqual(self.plain_requests, [])
        self.assertEqual(self.ledger, before)
        self.socket.send.assert_not_called()
        self.assertTrue(self.held()["held"])

    def test_changed_retained_response_refuses_before_delivery(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.subject.get_action.response_raw = b"{}"
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_INPUT_CHANGED"):
            self.subject.send_get_result()
        self.socket.send.assert_not_called()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_partial_result_delivery_cannot_advance_or_retry(self):
        self.next_get()
        self.subject.exchange_api_get()
        action = self.subject.get_action
        self.result_count = 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_SEND_AMBIGUOUS"):
            self.subject.send_get_result()
        self.assertFalse(action.sent or action.retired or action.advanced)
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.assertEqual(self.ledger, self.retire_ledger)
        with self.assertRaises(ConformanceError):
            self.subject.send_get_result()
        self.socket.send.assert_called_once()

    def test_post_send_generation_loss_does_not_advance_transcript(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.on_result_send = lambda raw: self.observed.update(generation="f" * 64)
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.send_get_result()
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.socket.send.assert_called_once()

    def test_handoff_without_delivery_cannot_skip_pending_action(self):
        self.next_get()
        self.subject.exchange_api_get()
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_DELIVERY_REQUIRED"):
            self.subject.handoff_get_result()
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.socket.send.assert_not_called()

    def test_post_close_generation_loss_does_not_advance_or_accept_next_action(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.subject.send_get_result()
        self.on_api_close = lambda: self.observed.update(generation="f" * 64)
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.handoff_get_result()
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.get_socket.close.assert_called_once()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_substituted_get_owner_is_never_called(self):
        self.next_get()
        self.subject.exchange_api_get()
        foreign = Mock()
        self.subject.get_action = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_OWNER_CHANGED"):
            self.subject.send_get_result()
        self.assertEqual(foreign.mock_calls, [])
        self.socket.send.assert_not_called()

    def test_failed_original_api_close_is_retained_without_transcript_advance(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.subject.send_get_result()
        failure = OSError("unit get close failure")
        self.get_socket.close.side_effect = failure
        with self.assertRaises(OSError) as caught:
            self.subject.handoff_get_result()
        self.assertIs(caught.exception, failure)
        self.assertIs(self.get_api.cleanup_failure, failure)
        self.assertIs(self.subject.cleanup_failure, failure)
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.get_socket.close.assert_called_once()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])

    def test_no_caller_response_fd_or_cleanup_argument_is_accepted(self):
        for operation in (self.subject.exchange_api_get, self.subject.send_get_result, self.subject.handoff_get_result):
            for value in (b"{}", {}, True, 83, Mock()):
                with self.subTest(operation=operation.__name__, value_type=type(value)), self.assertRaises(TypeError):
                    operation(value)
        self.api_socket.connect.assert_not_called()

    def test_repeated_get_exchange_cannot_issue_another_request(self):
        self.next_get()
        self.subject.exchange_api_get()
        requests = list(self.plain_requests)
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_ALREADY_ATTEMPTED"):
            self.subject.exchange_api_get()
        self.assertEqual(self.plain_requests, requests)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.socket.send.assert_not_called()

    def test_duplicate_get_result_is_not_retransmitted(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.subject.send_get_result()
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_DELIVERY_ORDER"):
            self.subject.send_get_result()
        self.socket.send.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_recycled_api_descriptor_refuses_before_get_http(self):
        self.next_get()
        self.fds[83] = SimpleNamespace(st_dev=1, st_ino=999, st_mode=stat.S_IFSOCK | 0o600)
        self.refused_get("API_DESCRIPTOR_CHANGED")
        self.assertEqual(self.plain_requests, [])
        self.get_socket.close.assert_not_called()
        self.get_socket.detach.assert_called_once()

    def test_changed_history_refuses_before_get_http(self):
        self.next_get()
        expected = self.ledger
        self.ledger += b" "
        with self.assertRaisesRegex(ConformanceError, "BROKER_RUNNING_CHANGED"):
            self.subject.exchange_api_get()
        self.assertEqual(self.plain_requests, [])
        self.assertEqual(self.ledger, expected + b" ")  # no silent store repair
        self.socket.send.assert_not_called()

    def test_receiver_cannot_skip_get_delivery_and_retirement(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.socket.recvmsg.reset_mock()
        self.refused("BROKER_GET_HANDOFF_REQUIRED")
        self.socket.recvmsg.assert_not_called()
        self.socket.send.assert_not_called()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_action_replay_after_get_handoff_still_refuses(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.subject.send_get_result()
        action = self.subject.get_action
        self.subject.handoff_get_result()
        self.last_event = json.loads(action.frame_raw)
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "GET", "manifestDigest": self.action_digest})
        self.refused("BROKER_RESOURCE_ACTION_INVALID")
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])

    def test_duplicate_get_handoff_cannot_reopen_a_retired_connection(self):
        self.next_get()
        self.subject.exchange_api_get()
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        before = self.subject.events.transcript_raw
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_OWNER_CHANGED"):
            self.subject.handoff_get_result()
        self.get_socket.connect.assert_called_once()
        self.get_socket.close.assert_called_once()
        self.assertEqual(self.subject.events.transcript_raw, before)
        self.assertEqual(self.ledger, self.retire_ledger)

    def not_found_reply(self):
        name = self.manifest["metadata"]["name"]
        self.not_found = {"apiVersion": "v1", "kind": "Status", "metadata": {}, "status": "Failure",
            "message": 'configmaps "' + name + '" not found', "reason": "NotFound", "code": 404,
            "details": {"name": name, "kind": "configmaps"}}
        self.reply(canonical_bytes(self.not_found), status="HTTP/1.1 404 Not Found")

    def read_absent(self):
        self.next_get()
        self.not_found_reply()
        self.subject.exchange_api_get()
        self.get_action = self.subject.get_action
        self.assertEqual(self.get_action.outcome, "ABSENT")

    def test_scoped_get_404_is_data_until_absence_is_durably_recorded(self):
        self.read_absent()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertEqual(next(iter(self.held()["resources"].values()))["state"], "CREATED")
        self.assertEqual(json.loads(self.get_action.frame_raw)["payload"],
                         {"actionId": 2, "outcome": "ABSENT", "objectBase64": None})
        self.assertIsNone(self.parser.cleanup)
        self.socket.send.assert_not_called()
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_ABSENCE_NOT_RECORDED"):
            self.subject.send_get_result()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.socket.send.assert_not_called()

    def test_original_absence_fact_fsync_readback_precedes_result_delivery(self):
        self.read_absent()
        self.io_events.clear()
        seen = []
        self.on_append = self.on_sync = lambda: seen.append(self.subject.dispatch.ledger_raw)
        self.assertIsNone(self.subject.record_get_absence())
        absence = self.subject.absence
        self.assertIs(type(absence), server._BrokerAbsence)
        self.assertIs(absence, self.subject._absence_original)
        self.assertTrue(absence.committed and absence.advanced and absence.writing)
        self.assertEqual(seen, [self.retire_ledger, self.retire_ledger])
        start, end = self.io_events.index("lock"), self.io_events.index("unlock")
        self.assertEqual(self.io_events[start:end + 1], ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertEqual(self.subject.dispatch.ledger_raw, absence.after)
        self.assertEqual(self.ledger, absence.after)
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        record = next(iter(self.held()["resources"].values()))
        self.assertEqual((record["state"], record["uid"], record["actionId"]), ("ABSENT", "created-unit-uid", 1))
        self.assertTrue(self.held()["held"])
        self.socket.send.assert_not_called()
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        self.assertEqual(self.sent_results, [self.get_action.frame_raw])
        self.assertEqual(self.ledger, absence.after)
        self.assertEqual(self.parser.previous, server.byte_digest(self.get_action.frame_raw))
        self.assertIsNone(self.subject.absence)
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)
        self.get_socket.close.assert_called_once()

    def test_present_object_cannot_enter_absence_recorder(self):
        self.next_get()
        self.subject.exchange_api_get()
        with self.assertRaisesRegex(ConformanceError, "BROKER_ABSENCE_GET_REQUIRED"):
            self.subject.record_get_absence()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.socket.send.assert_not_called()

    def test_absence_cannot_be_recorded_twice_or_retried(self):
        self.read_absent()
        self.subject.record_get_absence()
        before, writes = self.ledger, list(self.writes)
        with self.assertRaisesRegex(ConformanceError, "BROKER_ABSENCE_ALREADY_ATTEMPTED"):
            self.subject.record_get_absence()
        self.assertEqual(self.ledger, before)
        self.assertEqual(self.writes, writes)
        self.assertTrue(self.held()["held"])
        self.socket.send.assert_not_called()

    def test_absence_fsync_failure_retains_held_identity_without_reply(self):
        self.read_absent()
        self.fail = "sync"
        with self.assertRaises((ConformanceError, OSError)):
            self.subject.record_get_absence()
        self.assertTrue(self.owner.log.poisoned)
        self.assertTrue(self.subject.failed and self.subject.closed)
        self.assertFalse(self.subject.absence.committed)
        self.assertEqual(self.subject.dispatch.ledger_raw, self.retire_ledger)
        self.socket.send.assert_not_called()
        self.assertTrue(self.held()["held"])
        self.assertEqual(next(iter(self.held()["resources"].values()))["uid"], "created-unit-uid")

    def test_post_commit_generation_loss_cannot_deliver_absent(self):
        self.read_absent()
        self.on_sync = lambda: self.observed.update(generation="f" * 64)
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.record_get_absence()
        self.assertTrue(self.owner.log.poisoned)
        self.assertFalse(self.subject.absence.committed)
        self.assertTrue(self.ledger.startswith(self.retire_ledger))
        self.assertTrue(self.held()["held"])
        self.socket.send.assert_not_called()
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)

    def test_stale_generation_before_absence_record_does_not_write(self):
        self.read_absent()
        self.observed["generation"] = "f" * 64
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.record_get_absence()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertFalse(self.owner.log.poisoned)
        self.socket.send.assert_not_called()

    def test_replaced_absence_owner_is_never_called(self):
        self.read_absent()
        self.subject.record_get_absence()
        before = self.ledger
        foreign = Mock()
        self.subject.absence = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_ABSENCE_OWNER_CHANGED"):
            self.subject.send_get_result()
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.ledger, before)
        self.socket.send.assert_not_called()

    def test_modified_absence_response_cannot_change_recorded_uid_fact(self):
        self.read_absent()
        self.subject.record_get_absence()
        before = self.ledger
        self.subject.absence.response_raw = b"{}"
        with self.assertRaisesRegex(ConformanceError, "BROKER_ABSENCE_INPUT_CHANGED"):
            self.subject.send_get_result()
        self.assertEqual(self.ledger, before)
        self.socket.send.assert_not_called()

    def test_absence_send_failure_retains_durable_uid_and_pending_transcript(self):
        self.read_absent()
        self.subject.record_get_absence()
        before = self.ledger
        self.result_count = 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_GET_SEND_AMBIGUOUS"):
            self.subject.send_get_result()
        self.assertEqual(self.ledger, before)
        self.assertTrue(self.held()["held"])
        self.assertEqual(self.subject.events.transcript_raw, self.get_before)
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)

    def test_wrong_named_404_is_not_absence_of_the_recorded_resource(self):
        self.next_get()
        self.not_found_reply()
        self.not_found["details"]["name"] = "foreign"
        self.reply(canonical_bytes(self.not_found), status="HTTP/1.1 404 Not Found")
        self.refused_get("ADMISSION_ABSENCE_STATUS_INVALID")

    def test_namespace_404_is_not_resource_absence(self):
        self.next_get()
        self.not_found_reply()
        self.not_found["details"]["kind"] = "namespaces"
        self.reply(canonical_bytes(self.not_found), status="HTTP/1.1 404 Not Found")
        self.refused_get("ADMISSION_ABSENCE_STATUS_INVALID")

    def test_error_object_under_http200_cannot_be_an_absence_observation(self):
        self.next_get()
        self.not_found_reply()
        self.reply(canonical_bytes(self.not_found))
        self.refused_get("ADMISSION_IDENTITY_MISSING")

    def test_404_duplicate_content_length_refuses_before_absence(self):
        self.next_get()
        self.not_found_reply()
        raw = bytes(self.http_bytes)
        line = next(line for line in raw.split(b"\r\n") if line.startswith(b"Content-Length: "))
        self.http_bytes = bytearray(raw.replace(line, line + b"\r\n" + line, 1))
        self.refused_get("HTTP_HEADER_FORBIDDEN")

    def test_404_transfer_encoding_refuses_before_absence(self):
        self.next_get()
        self.not_found_reply()
        self.http_bytes = bytearray(bytes(self.http_bytes).replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n", 1))
        self.refused_get("HTTP_HEADER_FORBIDDEN")

    def test_404_surplus_and_truncated_responses_do_not_become_absent(self):
        self.next_get()
        self.not_found_reply()
        del self.http_bytes[-5:]
        self.refused_get("HTTP_TRUNCATED_BODY")

    def test_404_surplus_bytes_do_not_become_absent(self):
        self.next_get()
        self.not_found_reply()
        self.http_bytes.extend(b"surplus")
        self.refused_get("HTTP_SURPLUS")

    def test_wrong_status_transport_never_falls_back_to_not_found_body(self):
        self.next_get()
        self.not_found_reply()
        self.reply(canonical_bytes(self.not_found), status="HTTP/1.1 403 Forbidden")
        self.refused_get("HTTP_STATUS_INVALID")

    def test_no_caller_uid_status_or_journal_argument_can_record_absence(self):
        for value in ({}, "created-unit-uid", b"{}", True, Mock()):
            with self.subTest(value_type=type(value)), self.assertRaises(TypeError):
                self.subject.record_get_absence(value)
        self.api_socket.connect.assert_not_called()


class BrokerDeleteActionTests(_BrokerEventFixture, unittest.TestCase):
    """Sequential owned actions with leaf OS/observer/TLS/store doubles, not C6."""
    start = BrokerGetActionTests.start
    action = BrokerGetActionTests.action
    read_secret = BrokerGetActionTests.read_secret
    connect_api = BrokerGetActionTests.connect_api
    write_memfd = BrokerGetActionTests.write_memfd
    make_context = BrokerGetActionTests.make_context
    wrap = BrokerGetActionTests.wrap
    handshake = BrokerGetActionTests.handshake
    read_intent = BrokerGetActionTests.read_intent
    append_intent = BrokerGetActionTests.append_intent
    sync_intent = BrokerGetActionTests.sync_intent
    held = BrokerGetActionTests.held
    reply = BrokerGetActionTests.reply
    http_write = BrokerGetActionTests.http_write
    http_read = BrokerGetActionTests.http_read
    prepare = BrokerGetActionTests.prepare
    accounted = BrokerGetActionTests.accounted
    result_send = BrokerGetActionTests.result_send
    close_api = BrokerGetActionTests.close_api
    delivered = BrokerGetActionTests.delivered
    retired = BrokerGetActionTests.retired
    next_get = BrokerGetActionTests.next_get
    not_found_reply = BrokerGetActionTests.not_found_reply

    def setUp(self):
        BrokerGetActionTests.setUp(self)

    def failure_owner(self):
        _failure_custody_fixture(self)
        actor = self.owner.failure_accounting = self.owner._failure_accounting_original = object.__new__(server._FailureAccounting)
        actor.__init__(self.owner)
        return actor

    def test_lost_create_response_records_null_uid_failure_without_retry(self):
        self.prepare()
        actor = self.failure_owner()
        def lose_response():
            raise OSError("unit response lost after request")
        self.on_http_read = lose_response
        with self.assertRaises(OSError) as caught:
            self.subject.exchange_api_create()
        sends = len(self.plain_requests)
        reads, sockets = self.secret_reads.call_count, self.mocks["socket"].call_count
        self.assertTrue(self.owner.log.poisoned)
        self.assertFalse(self.owner.log._storage_ambiguous)
        actor.record(caught.exception)
        self.assertTrue(actor.complete)
        cleanup = json.loads(self.writes[-1])["cleanup"]
        self.assertEqual(cleanup["state"], "CLEANUP_PENDING")
        row = cleanup["remainingResources"][0]
        self.assertIsNone(row["uid"])
        self.assertEqual(row["reasonCode"], "IO_AMBIGUOUS")
        self.assertEqual(row["name"], self.manifest["metadata"]["name"])
        self.assertTrue(self.held()["held"])
        self.assertEqual((len(self.plain_requests), self.secret_reads.call_count, self.mocks["socket"].call_count),
                         (sends, reads, sockets))
        self.socket.send.assert_not_called()

    def test_known_uid_is_retained_when_cleanup_authority_expires(self):
        self.accounted()
        actor = self.failure_owner()
        resource = deepcopy(next(iter(self.held()["resources"].values())))
        self.subject.failed = True
        self.subject.close()
        before_requests = list(self.plain_requests)
        self.now = self.subject.deadline
        actor.record(ConformanceError("BROKER_CLOCK_OR_DEADLINE", "unit expired"))
        cleanup = json.loads(self.writes[-1])["cleanup"]
        self.assertEqual(cleanup["remainingResources"][0]["uid"], resource["uid"])
        self.assertEqual(cleanup["remainingResources"][0]["reasonCode"], "DEADLINE")
        self.assertEqual(next(iter(self.held()["resources"].values())), resource)
        self.assertEqual(self.plain_requests, before_requests)
        self.assertTrue(self.held()["held"])

    def test_original_delete_grant_refusal_records_denied_not_broader_deletion(self):
        self.confirmed_get()
        self.queue("RESOURCE_ACTION", {"actionId": 3, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        actor = self.failure_owner()
        self.subject.failed = True
        self.subject.close()
        before_requests = list(self.plain_requests)
        actor.record(ConformanceError("API_EXACT_GRANT_REQUIRED", "unit refused"))
        row = json.loads(self.writes[-1])
        self.assertEqual(row["failure"]["reasonCode"], "DELETE_DENIED")
        self.assertEqual(row["cleanup"]["remainingResources"][0]["reasonCode"], "DELETE_DENIED")
        self.assertEqual(self.plain_requests, before_requests)
        self.assertTrue(self.held()["held"])

    def test_failure_after_confirmed_absence_never_erases_original_uid_history(self):
        self.post_delete_get()
        self.subject.exchange_api_get()
        self.subject.record_get_absence()
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        actor = self.failure_owner()
        resource = deepcopy(next(iter(self.held()["resources"].values())))
        self.assertEqual(resource["state"], "ABSENT")
        self.subject.failed = True
        self.subject.close()
        actor.record(OSError("unit terminal unavailable"))
        self.assertIsNone(json.loads(self.writes[-1])["cleanup"])
        self.assertEqual(next(iter(self.held()["resources"].values())), resource)
        self.assertTrue(self.held()["held"])
        self.assertNotIn("terminalCases", self.held())

    def test_driver_get_preflight_requires_owned_created_uid_before_new_api(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "GET", "manifestDigest": self.action_digest})
        self.take()
        sockets, history = self.mocks["socket"].call_count, self.ledger
        self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, sockets)
        self.secret_reads.assert_called_once()
        self.assertIsNone(self.subject.api)
        self.assertEqual(self.ledger, history)

    def test_driver_delete_without_fresh_get_refuses_before_new_api(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        sockets, history = self.mocks["socket"].call_count, self.ledger
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_FRESH_GET_REQUIRED"):
            self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, sockets)
        self.secret_reads.assert_called_once()
        self.assertEqual(self.ledger, history)

    def test_driver_fresh_delete_preflight_acquires_no_api_or_credential(self):
        self.confirmed_get()
        self.queue("RESOURCE_ACTION", {"actionId": 3, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        sockets, history = self.mocks["socket"].call_count, self.ledger
        self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, sockets)
        self.secret_reads.assert_called_once()
        self.assertIsNone(self.subject.api)
        self.assertEqual(self.ledger, history)

    def test_driver_stale_delete_preflight_denies_before_new_api(self):
        self.confirmed_get()
        self.queue("RESOURCE_ACTION", {"actionId": 3, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        self.now += 5
        sockets = self.mocks["socket"].call_count
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_FRESH_GET_REQUIRED"):
            self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, sockets)
        self.secret_reads.assert_called_once()
        self.assertTrue(self.held()["held"])

    def test_driver_changed_last_get_owner_cannot_reauthorize_delete(self):
        self.confirmed_get()
        self.queue("RESOURCE_ACTION", {"actionId": 3, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        self.subject.last_get = Mock()
        sockets = self.mocks["socket"].call_count
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_FRESH_GET_REQUIRED"):
            self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, sockets)
        self.secret_reads.assert_called_once()

    def confirmed_get(self):
        self.next_get()
        if hasattr(self, "current_version"):
            self.actual["metadata"]["resourceVersion"] = self.current_version
            self.reply(canonical_bytes(self.actual))
        self.subject.exchange_api_get()
        self.ownership_get = self.subject.get_action
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        self.last_event = json.loads(self.ownership_get.frame_raw)
        self.assertIs(self.subject.last_get, self.ownership_get)

    def next_api(self, fd):
        sock = Mock()
        sock.fileno.return_value = fd
        sock.getpeername.side_effect = lambda: self.api_peer
        sock.connect.side_effect = self.connect_api
        sock.send.side_effect = lambda raw: len(raw)
        sock.close.side_effect = self.close_api
        self.fds[fd] = SimpleNamespace(st_dev=1, st_ino=fd, st_mode=stat.S_IFSOCK | 0o600)
        self.mocks["socket"].return_value = sock
        self.fd_bytes.clear()
        self.subject.prepare_api()
        self.plain_requests.clear()
        self.sent_results.clear()
        self.socket.send.reset_mock()
        self.ssl.read.reset_mock()
        return sock

    def pending_delete(self):
        self.confirmed_get()
        self.queue("RESOURCE_ACTION", {"actionId": 3, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        self.delete_socket = self.next_api(85)
        self.delete_api = self.subject.api
        self.delete_before = self.subject.events.transcript_raw
        self.deleted = {"apiVersion": "v1", "kind": "Status", "metadata": {}, "status": "Success", "code": 200,
            "details": {"name": self.manifest["metadata"]["name"], "kind": "configmaps", "uid": "created-unit-uid"}}
        self.reply(canonical_bytes(self.deleted))

    def refused_delete(self, reason=".+"):
        with self.assertRaisesRegex((ConformanceError, OSError), reason):
            self.subject.exchange_api_delete()
        self.assertTrue(self.subject.failed and self.subject.closed)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])
        self.assertTrue(all(row["state"] == "CREATED" for row in self.held()["resources"].values()))
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)
        self.socket.send.assert_not_called()

    def retired_delete(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        self.deletion = self.subject.delete_action
        self.subject.send_delete_result()
        self.subject.handoff_delete_result()
        self.last_event = json.loads(self.deletion.frame_raw)

    def post_delete_get(self):
        self.retired_delete()
        self.queue("RESOURCE_ACTION", {"actionId": 4, "verb": "GET", "manifestDigest": self.action_digest})
        self.take()
        self.absence_socket = self.next_api(87)
        self.not_found_reply()

    def test_delete_uses_exact_recorded_uid_and_fresh_version_not_force(self):
        self.pending_delete()
        self.assertIsNone(self.subject.exchange_api_delete())
        action = self.subject.delete_action
        self.assertIs(type(action), server._BrokerDeleteAction)
        self.assertTrue(action.attempted and action.request_written and action.complete)
        self.assertFalse(action.sent or action.advanced)
        self.assertEqual(len(self.plain_requests), 1)
        header, raw = self.plain_requests[0].split(b"\r\n\r\n")
        path = "DELETE /api/v1/namespaces/" + self.manifest["metadata"]["namespace"]
        path += "/configmaps/" + self.manifest["metadata"]["name"] + " HTTP/1.1"
        self.assertEqual(header.split(b"\r\n")[0], path.encode())
        self.assertEqual(json.loads(raw), {"apiVersion": "v1", "kind": "DeleteOptions",
            "preconditions": {"uid": "created-unit-uid", "resourceVersion": "123"}})
        self.assertEqual(self.ledger, self.retire_ledger)
        self.secret_reads.assert_called_once()
        self.socket.send.assert_not_called()

    def test_delete_acknowledgement_preserves_created_uid_until_separate_get(self):
        self.retired_delete()
        self.assertTrue(self.deletion.sent and self.deletion.retired and self.deletion.advanced)
        self.assertEqual(self.last_event["payload"], {"actionId": 3, "outcome": "DELETED", "objectBase64": None})
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])
        self.assertTrue(all(row["state"] == "CREATED" for row in self.held()["resources"].values()))
        self.assertIsNone(self.subject.last_get)
        self.assertIsNone(self.subject.delete_action)
        self.assertEqual(self.parser.actions, {1, 2, 3})
        self.delete_socket.close.assert_called_once()
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)

    def test_version_precondition_uses_new_get_version_but_keeps_create_history(self):
        self.current_version = "124"
        self.pending_delete()
        self.subject.exchange_api_delete()
        self.assertIn(b'"resourceVersion":"124"', self.plain_requests[0])
        self.assertTrue(all(row["resourceVersion"] == "123" for row in self.held()["resources"].values()))
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_fractional_monotonic_clock_stays_private_not_a_float_wire_extension(self):
        self.now += 0.125
        self.pending_delete()
        proof = json.loads(self.subject.last_get_raw)
        self.assertEqual(proof["observedMonotonic"], self.now.hex())
        self.subject.exchange_api_delete()
        self.assertTrue(self.subject.delete_action.complete)

    def test_create_get_uid_delete_get_absence_persists_before_absent_result(self):
        self.post_delete_get()
        self.subject.exchange_api_get()
        absence = self.subject.get_action
        self.assertEqual(self.ledger, self.retire_ledger)
        self.subject.record_get_absence()
        self.assertTrue(all(row["state"] == "ABSENT" and row["uid"] == "created-unit-uid"
                            and row["absenceActionId"] == 4 for row in self.held()["resources"].values()))
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        self.assertEqual(json.loads(absence.frame_raw)["payload"]["outcome"], "ABSENT")
        self.assertEqual(self.parser.actions, {1, 2, 3, 4})
        self.assertEqual(len(self.subject.events.handoffs), 4)
        self.assertIs(self.parser, self.subject.events.transcript)
        self.assertTrue(self.held()["held"])
        self.assertEqual(absence.deadline, self.deletion.deadline)
        self.assertIsNone(self.parser.cleanup)
        self.assertIsNone(self.parser.terminal)
        self.secret_reads.assert_called_once()

    def test_delete_cannot_use_create_response_instead_of_independent_get(self):
        self.retired()
        self.subject.handoff_create_result()
        self.queue("RESOURCE_ACTION", {"actionId": 2, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        self.next_api(85)
        self.refused_delete("BROKER_DELETE_GET_REQUIRED")
        self.assertEqual(self.plain_requests, [])

    def test_expired_get_cannot_authorize_delete(self):
        self.pending_delete()
        self.now += 5
        self.refused_delete("BROKER_DELETE_GET_STALE")
        self.assertEqual(self.plain_requests, [])

    def test_get_owner_replacement_is_not_called(self):
        self.pending_delete()
        foreign = Mock()
        self.subject.last_get = foreign
        self.refused_delete("BROKER_DELETE_GET_REQUIRED")
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.plain_requests, [])

    def test_changed_retained_get_labels_refuse_without_delete(self):
        self.pending_delete()
        actual = deepcopy(self.actual)
        actual["metadata"]["labels"]["foreign"] = "changed"
        self.ownership_get.response_raw = canonical_bytes(actual)
        self.refused_delete()
        self.assertEqual(self.plain_requests, [])

    def test_changed_get_snapshot_refuses_without_delete(self):
        self.pending_delete()
        self.subject.last_get_raw = b"{}"
        self.refused_delete("BROKER_DELETE_GET_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_original_closed_get_api_cannot_be_substituted(self):
        self.pending_delete()
        foreign = object.__new__(server._BrokerApi)
        self.ownership_get.api = foreign
        self.refused_delete("BROKER_DELETE_GET_REQUIRED")
        self.assertEqual(self.plain_requests, [])
        self.assertEqual(vars(foreign), {})

    def test_get_freshness_cannot_be_extended_during_delete_write(self):
        self.pending_delete()
        self.on_http_write = lambda: setattr(self, "now", self.now + 5)
        self.refused_delete()
        self.assertEqual(len(self.plain_requests), 1)
        self.ssl.read.assert_not_called()

    def test_changed_delete_request_precondition_is_refused_before_result(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        self.subject.delete_action.request_raw = b"DELETE / HTTP/1.1\r\n\r\n"
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_INPUT_CHANGED"):
            self.subject.send_delete_result()
        self.socket.send.assert_not_called()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_overlapping_action_cannot_skip_delete_retirement(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        self.socket.recvmsg.reset_mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_HANDOFF_REQUIRED"):
            self.subject.poll()
        self.socket.recvmsg.assert_not_called()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_stale_generation_before_delete_keeps_uid_held(self):
        self.pending_delete()
        self.observed["generation"] = "f" * 64
        self.refused_delete("BROKER_GENERATION_CHANGED")
        self.assertEqual(self.plain_requests, [])

    def test_removed_delete_grant_prevents_write(self):
        self.pending_delete()
        rules = self.owner.profile["capacityEntries"]["kubernetesApiRules"]
        self.owner.profile["capacityEntries"]["kubernetesApiRules"] = [r for r in rules if r["verb"] != "delete"]
        self.refused_delete()
        self.assertEqual(self.plain_requests, [])

    def test_conflict_never_retries_without_resource_version(self):
        self.pending_delete()
        self.reply(canonical_bytes({"kind": "Status", "code": 409}), status="HTTP/1.1 409 Conflict")
        self.refused_delete("HTTP_STATUS_INVALID")
        self.assertEqual(len(self.plain_requests), 1)
        self.delete_socket.connect.assert_called_once()
        self.assertIn(b'"resourceVersion":"123"', self.plain_requests[0])

    def test_delete_404_is_not_post_delete_absence_evidence(self):
        self.pending_delete()
        self.not_found_reply()
        self.refused_delete("BROKER_DELETE_STATUS_INVALID")
        self.assertEqual(len(self.plain_requests), 1)

    def test_failed_status_under_http200_does_not_report_deleted(self):
        self.pending_delete()
        self.deleted["status"] = "Failure"
        self.reply(canonical_bytes(self.deleted))
        self.refused_delete("ADMISSION_DELETE_RESPONSE_INVALID")

    def test_delete_response_cannot_claim_a_replacement_uid(self):
        self.pending_delete()
        self.deleted["details"]["uid"] = "foreign"
        self.reply(canonical_bytes(self.deleted))
        self.refused_delete("ADMISSION_DELETE_RESPONSE_INVALID")

    def test_object_delete_response_does_not_release_uid(self):
        self.pending_delete()
        self.reply(canonical_bytes(self.actual))
        self.subject.exchange_api_delete()
        self.assertTrue(self.subject.delete_action.complete)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])

    def test_lost_delete_response_keeps_original_record_and_never_retries(self):
        self.pending_delete()
        self.http_bytes = bytearray()
        self.refused_delete("HTTP_TRUNCATED_HEADERS")
        self.assertEqual(len(self.plain_requests), 1)
        with self.assertRaises(ConformanceError):
            self.subject.exchange_api_delete()
        self.assertEqual(len(self.plain_requests), 1)

    def test_delete_response_surplus_cannot_be_acknowledged(self):
        self.pending_delete()
        self.http_bytes.extend(b"surplus")
        self.refused_delete("HTTP_SURPLUS")

    def test_delete_response_header_cannot_expand_transport(self):
        self.pending_delete()
        self.http_bytes = bytearray(bytes(self.http_bytes).replace(b"\r\n\r\n",
            b"\r\nTransfer-Encoding: chunked\r\n\r\n", 1))
        self.refused_delete("HTTP_HEADER_FORBIDDEN")

    def test_generation_loss_after_write_keeps_possible_effect_held(self):
        self.pending_delete()
        self.on_http_write = lambda: self.observed.update(generation="f" * 64)
        self.refused_delete("BROKER_GENERATION_CHANGED")
        self.assertEqual(len(self.plain_requests), 1)
        self.ssl.read.assert_not_called()

    def test_delete_api_descriptor_reuse_refuses_without_closing_recycled_fd(self):
        self.pending_delete()
        self.fds[85].st_ino += 1
        self.refused_delete("API_DESCRIPTOR_CHANGED")
        self.assertEqual(self.plain_requests, [])
        self.delete_socket.close.assert_not_called()
        self.delete_socket.detach.assert_called_once()

    def test_send_failure_does_not_advance_or_retry_delete(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        self.result_count = 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_SEND_AMBIGUOUS"):
            self.subject.send_delete_result()
        self.assertEqual(self.subject.events.transcript_raw, self.delete_before)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertEqual(len(self.plain_requests), 1)
        self.assertTrue(self.held()["held"])

    def test_handoff_requires_delivered_delete_result(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_DELIVERY_REQUIRED"):
            self.subject.handoff_delete_result()
        self.assertEqual(self.subject.events.transcript_raw, self.delete_before)
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_delete_close_failure_preserves_first_error_and_original_transcript(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        self.subject.send_delete_result()
        self.on_api_close = lambda: (_ for _ in ()).throw(OSError("unit delete close failed"))
        with self.assertRaisesRegex(OSError, "unit delete close failed"):
            self.subject.handoff_delete_result()
        self.assertEqual(self.subject.events.transcript_raw, self.delete_before)
        self.assertEqual(self.ledger, self.retire_ledger)
        self.delete_socket.close.assert_called_once()

    def test_replaced_delete_owner_is_not_invoked(self):
        self.pending_delete()
        self.subject.exchange_api_delete()
        foreign = Mock()
        self.subject.delete_action = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_DELETE_OWNER_CHANGED"):
            self.subject.send_delete_result()
        self.assertEqual(foreign.mock_calls, [])
        self.socket.send.assert_not_called()
        self.assertEqual(self.ledger, self.retire_ledger)

    def test_post_delete_present_object_stays_held(self):
        self.post_delete_get()
        self.reply(canonical_bytes(self.actual))
        self.subject.exchange_api_get()
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])
        self.assertIsNone(self.parser.cleanup)

    def test_post_delete_replacement_is_not_adopted_or_deleted(self):
        self.post_delete_get()
        actual = deepcopy(self.actual)
        actual["metadata"]["uid"] = "replacement"
        self.reply(canonical_bytes(actual))
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_UID_CHANGED"):
            self.subject.exchange_api_get()
        self.assertEqual(self.ledger, self.retire_ledger)
        self.assertTrue(self.held()["held"])

    def test_second_delete_cannot_retry_even_after_another_present_get(self):
        self.post_delete_get()
        self.reply(canonical_bytes(self.actual))
        self.subject.exchange_api_get()
        get = self.subject.get_action
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        self.last_event = json.loads(get.frame_raw)
        self.queue("RESOURCE_ACTION", {"actionId": 5, "verb": "DELETE", "manifestDigest": self.action_digest})
        self.take()
        self.next_api(89)
        self.refused_delete("BROKER_DELETE_RETRY_FORBIDDEN")
        self.assertEqual(self.plain_requests, [])

    def test_no_caller_uid_response_or_force_argument_is_accepted(self):
        for method in (self.subject.exchange_api_delete, self.subject.send_delete_result,
                       self.subject.handoff_delete_result):
            for value in ({"force": True}, "created-unit-uid", b"{}", Mock()):
                with self.subTest(method=method.__name__), self.assertRaises(TypeError):
                    method(value)
        self.api_socket.connect.assert_not_called()

    def test_resource_completion_seals_clean_only_after_durable_absence(self):
        self.post_delete_get()
        self.subject.exchange_api_get()
        absence = self.subject.get_action
        self.subject.record_get_absence()
        self.subject.send_get_result()
        self.subject.handoff_get_result()
        self.last_event = json.loads(absence.frame_raw)
        _BrokerCompletionFixture.configure(self)
        _BrokerCompletionFixture.chunks(self)
        self.subject.seal_cleanup()
        completion = self.subject.completion
        self.assertEqual(json.loads(completion.cleanup_raw)["state"], "CLEAN")
        self.assertEqual(json.loads(completion.cleanup_raw)["remainingResources"], [])
        self.assertTrue(self.held()["held"])
        self.assertFalse(completion.complete)
        self.assertTrue(all(r["state"] == "ABSENT" and r["uid"] == "created-unit-uid"
                            for r in self.held()["resources"].values()))
        self.secret_reads.assert_called_once()

    def test_present_uid_with_pass_receipt_cannot_be_sealed_clean(self):
        self.retired_delete()
        _BrokerCompletionFixture.configure(self)
        _BrokerCompletionFixture.chunks(self)
        before = self.ledger
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_COMPLETION_FALSE_PASS"):
            self.subject.seal_cleanup()
        self.assertEqual(self.ledger, before)
        self.assertTrue(self.held()["held"])
        self.socket.send.assert_not_called()

    def test_failed_resource_receipt_seals_exact_unresolved_uid_without_deleting(self):
        self.retired_delete()
        _BrokerCompletionFixture.configure(self, "FAIL")
        _BrokerCompletionFixture.chunks(self)
        requests = list(self.plain_requests)
        self.subject.seal_cleanup()
        completion = self.subject.completion
        cleanup = json.loads(completion.cleanup_raw)
        self.assertEqual(cleanup["state"], "CLEANUP_PENDING")
        self.assertEqual(cleanup["remainingResources"], [{"apiVersion": "v1", "kind": "ConfigMap",
            "namespace": self.manifest["metadata"]["namespace"], "name": self.manifest["metadata"]["name"],
            "uid": "created-unit-uid", "manifestDigest": self.action_digest,
            "reasonCode": "OBSERVATION_UNAVAILABLE"}])
        self.subject.send_cleanup()
        self.assertEqual(self.plain_requests, requests)
        self.assertTrue(self.held()["held"])
        self.assertEqual(self.held()["current"], self.owner.active_operation)
        self.assertFalse(completion.complete)


class BrokerApiZeroResourceTests(_BrokerEventFixture, unittest.TestCase):
    profile_index = 0

    def test_zero_resource_execution_opens_no_api_socket_or_credential(self):
        self.take()  # only receipt data; no resource action exists
        self.owner.secrets = server._Files(self.owner)
        with patch.object(server._Files, "read") as read:
            with self.assertRaisesRegex(ConformanceError, "API_ACTION_REQUIRED"):
                self.subject.prepare_api()
        read.assert_not_called()
        self.assertEqual(self.mocks["socket"].call_count, 1)  # original broker only


class _BrokerCompletionFixture(_BrokerEventFixture):
    """Leaf transport/storage/observer doubles; never C6 whole-server evidence."""
    profile_index = 0
    read_intent = BrokerIntentTests.read_intent
    append_intent = BrokerIntentTests.append_intent
    sync_intent = BrokerIntentTests.sync_intent
    held = BrokerIntentTests.held
    result_send = BrokerCreateResultTests.result_send

    def setUp(self):
        _BrokerEventFixture.setUp(self)
        self.configure()

    def configure(self, status="PASS"):
        from contextlib import contextmanager
        from harness_conformance.linux_readiness import CASE_CHECKS
        owner = self.owner
        request = server.build_probe_request(owner.envelope, owner.capacity, owner.plan, owner.active_operation)
        # Valid contract data only. The existing fixture explicitly doubles the
        # installed authority edge; validate_receipt and the owner are real here.
        owner.binding = {"nonce": request["runNonce"], "tenantId": owner.envelope["tenantId"],
            "environmentId": owner.envelope["environmentId"], "endpointId": request["endpointId"],
            "namespace": request["namespace"], "packetDigest": owner.envelope["packetDigest"],
            "commandSetDigest": owner.envelope["commandSetDigest"], "releaseDigest": owner.envelope["campaignReleaseDigest"],
            "capacityDigest": byte_digest(canonical_bytes(owner.capacity)),
            "notBefore": "2026-09-08T00:00:00Z", "notAfter": "2026-09-08T00:10:00Z"}
        output = {"checks": {check: status for check in CASE_CHECKS[owner.active_operation]}, "regressions": {}}
        self.case_receipt = {"caseId": owner.active_operation, "status": status, "observedAt": self.wall,
            "runNonce": request["runNonce"], "probeDigest": request["probeDigest"], "commandDigest": request["commandDigest"],
            "outputDigest": server.canonical_digest(output, "planeon.linux-probe-output/v1alpha1"), "output": output}
        self.receipt_bytes = canonical_bytes(self.case_receipt)
        self.io_events, self.writes = [], []
        self.fail = None
        self.on_read = self.on_append = self.on_sync = lambda: None
        @contextmanager
        def transaction(resource):
            self.assertIs(resource, owner.storage)
            yield resource
        self.stack.enter_context(patch.object(server._State, "transaction", transaction))
        self.stack.enter_context(patch.object(server._State, "append", side_effect=self.append_intent))
        self.stack.enter_context(patch.object(server._State, "sync", side_effect=self.sync_intent))
        self.read_store.side_effect = self.read_intent
        self.sent_results, self.result_count = [], None
        self.on_result_send = lambda raw: None
        self.socket.send.side_effect = self.result_send

    def chunks(self, raw=None):
        data = self.receipt_bytes if raw is None else raw
        at = len(data) // 2
        for index, part in enumerate((data[:at], data[at:])):
            self.chunk(index, part)
            self.take()
        self.before_completion = self.ledger
        self.before_cleanup = self.subject.events.transcript_raw
        self.socket.send.reset_mock()

    def sealed(self):
        self.chunks()
        self.subject.seal_cleanup()
        self.completion = self.subject.completion
        self.sealed_history = self.ledger

    def sent_cleanup(self):
        self.sealed()
        self.subject.send_cleanup()
        self.last_event = json.loads(self.completion.cleanup_frame_raw)
        payload = {"status": {"PASS": "COMPLETED", "FAIL": "FAILED",
            "NOT_RUN_ENV_UNAVAILABLE": "UNAVAILABLE"}[self.case_receipt["status"]],
            "receiptSize": len(self.receipt_bytes), "receiptDigest": byte_digest(self.receipt_bytes),
            "cleanupDigest": byte_digest(self.completion.cleanup_raw), "workerReaped": True}
        self.queue("TERMINAL", payload)
        self.on_event = lambda: setattr(self, "ready", False)


class BrokerCompletionTests(_BrokerCompletionFixture, unittest.TestCase):
    def test_zero_resource_seal_persists_before_any_cleanup_send(self):
        self.sealed()
        self.assertTrue(self.completion.sealed and self.completion.committed)
        self.assertEqual(json.loads(self.ledger.splitlines()[-1])["state"], "CLEANUP_SEALED")
        self.assertTrue(self.held()["held"])
        self.assertEqual(self.held()["current"], self.owner.active_operation)
        self.assertEqual(self.subject.events.transcript_raw, self.before_cleanup)
        self.assertIsNone(self.subject.events.transcript.cleanup)
        self.assertIsNone(self.subject.events.transcript.terminal)
        self.socket.send.assert_not_called()
        self.assertEqual(self.mocks["socket"].call_count, 1)
        self.owner.files.read.assert_not_called()

    def test_cleanup_digest_send_follows_durable_seal_and_preserves_pending_case(self):
        self.sealed()
        observed = []
        self.on_result_send = lambda raw: observed.append(self.ledger)
        self.subject.send_cleanup()
        self.assertEqual(observed, [self.sealed_history])
        self.assertEqual(self.sent_results, [self.completion.cleanup_frame_raw])
        self.assertTrue(self.completion.sent and self.completion.cleanup_advanced)
        self.assertTrue(self.held()["held"])
        self.assertEqual(self.held()["current"], self.owner.active_operation)
        self.assertFalse(self.completion.received or self.completion.complete)

    def test_real_terminal_echo_precedes_durable_completion(self):
        self.sent_cleanup()
        received = self.subject.poll_terminal()
        self.assertEqual(json.loads(received), self.event_frame)
        self.assertEqual(self.ledger, self.sealed_history)
        self.assertTrue(self.completion.received)
        self.assertFalse(self.completion.complete)
        self.subject.record_terminal()
        self.assertEqual(json.loads(self.ledger.splitlines()[-1])["state"], "TERMINAL_RECORDED")
        self.assertTrue(self.completion.complete)
        self.assertIsNone(self.held()["current"])
        self.assertTrue(self.held()["held"])  # one case is not the ten-case campaign
        self.assertEqual(self.completion.receipt_raw, self.receipt_bytes)
        self.assertEqual(self.completion.deadline, self.subject.deadline)
        self.assertEqual(self.mocks["socket"].call_count, 1)

    def test_terminal_loss_never_releases_or_records_success(self):
        self.sent_cleanup()
        self.raw_override = b""
        with self.assertRaises(ConformanceError):
            self.subject.poll_terminal()
        self.assertEqual(self.ledger, self.sealed_history)
        self.assertTrue(self.held()["held"])
        self.assertFalse(self.completion.complete)
        self.assertNotIn("terminalCases", self.held())

    def test_idle_terminal_poll_does_not_resend_or_extend_deadline(self):
        self.sent_cleanup()
        self.ready = False
        deadline, sends = self.subject.deadline, self.socket.send.call_count
        self.assertIsNone(self.subject.poll_terminal())
        self.assertIsNone(self.subject.poll_terminal())
        self.assertEqual(self.socket.send.call_count, sends)
        self.assertEqual(self.subject.deadline, deadline)
        self.assertEqual(self.ledger, self.sealed_history)
        self.assertFalse(self.completion.receive_attempted)

    def test_wrong_cleanup_digest_cannot_complete(self):
        self.sent_cleanup()
        self.event_frame["payload"]["cleanupDigest"] = admission.ZERO
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_TERMINAL_MISMATCH"):
            self.subject.poll_terminal()
        self.assertEqual(self.ledger, self.sealed_history)
        self.assertTrue(self.held()["held"])

    def test_wrong_receipt_digest_or_count_cannot_complete(self):
        self.sent_cleanup()
        self.event_frame["payload"]["receiptSize"] += 1
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_TERMINAL_MISMATCH"):
            self.subject.poll_terminal()
        self.assertEqual(self.ledger, self.sealed_history)

    def test_terminal_cannot_claim_failed_execution_as_pass(self):
        self.sent_cleanup()
        self.event_frame["payload"]["status"] = "FAILED"
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_TERMINAL_MISMATCH"):
            self.subject.poll_terminal()
        self.assertFalse(self.completion.complete)
        self.assertEqual(self.ledger, self.sealed_history)

    def test_trailing_frame_after_terminal_prevents_receipt_publication(self):
        self.sent_cleanup()
        self.on_event = lambda: None  # readiness remains true after TERMINAL
        with self.assertRaisesRegex(ConformanceError, "BROKER_TERMINAL_TRAILING_DATA"):
            self.subject.poll_terminal()
        self.assertFalse(self.completion.received or self.completion.complete)
        self.assertEqual(self.ledger, self.sealed_history)

    def test_extra_chunk_after_cleanup_cannot_become_terminal(self):
        self.sent_cleanup()
        self.chunk(2, b"trailing")
        with self.assertRaises(ConformanceError):
            self.subject.poll_terminal()
        self.assertEqual(self.ledger, self.sealed_history)

    def test_missing_truncated_receipt_never_seals_cleanup(self):
        self.chunks(self.receipt_bytes[:-1])
        with self.assertRaises(ConformanceError):
            self.subject.seal_cleanup()
        self.assertEqual(self.ledger, self.before_completion)
        self.socket.send.assert_not_called()

    def test_surplus_receipt_bytes_never_seal_cleanup(self):
        self.chunks(self.receipt_bytes + b"{}")
        with self.assertRaises(ConformanceError):
            self.subject.seal_cleanup()
        self.assertEqual(self.ledger, self.before_completion)

    def test_seal_without_chunks_cannot_acknowledge_cleanup(self):
        self.ready = False
        self.take()
        before = self.ledger
        with self.assertRaisesRegex(ConformanceError, "BROKER_COMPLETION_CHUNKS_REQUIRED"):
            self.subject.seal_cleanup()
        self.assertEqual(self.ledger, before)

    def test_cleanup_send_loss_preserves_sealed_held_record(self):
        self.sealed()
        self.result_count = 1
        with self.assertRaisesRegex(ConformanceError, "BROKER_CLEANUP_SEND_AMBIGUOUS"):
            self.subject.send_cleanup()
        self.assertEqual(self.ledger, self.sealed_history)
        self.assertEqual(self.subject.events.transcript_raw, self.before_cleanup)
        self.assertTrue(self.held()["held"])

    def test_original_completion_owner_cannot_be_replaced(self):
        self.sealed()
        foreign = Mock()
        self.subject.completion = foreign
        with self.assertRaisesRegex(ConformanceError, "BROKER_COMPLETION_OWNER_CHANGED"):
            self.subject.send_cleanup()
        self.assertEqual(foreign.mock_calls, [])
        self.assertEqual(self.ledger, self.sealed_history)

    def test_modified_receipt_bytes_cannot_change_sealed_evidence(self):
        self.sealed()
        self.completion.receipt_raw = b"{}"
        with self.assertRaises(ConformanceError):
            self.subject.send_cleanup()
        self.socket.send.assert_not_called()
        self.assertEqual(self.ledger, self.sealed_history)

    def test_failed_and_unavailable_receipts_never_close_case(self):
        # This case exercises actual failure receipt validation and fixed native
        # completion owners; it does not substitute a cleanup/driver result.
        self.case_receipt["status"] = "NOT_RUN_ENV_UNAVAILABLE"
        checks = self.case_receipt["output"]["checks"]
        for check in checks:
            checks[check] = "NOT_RUN_ENV_UNAVAILABLE"
        self.case_receipt["outputDigest"] = server.canonical_digest(self.case_receipt["output"],
                                                                  "planeon.linux-probe-output/v1alpha1")
        self.receipt_bytes = canonical_bytes(self.case_receipt)
        self.sent_cleanup()
        self.subject.poll_terminal()
        self.subject.record_terminal()
        self.assertTrue(self.completion.complete and self.held()["held"])
        self.assertEqual(self.held()["current"], self.owner.active_operation)
        self.assertEqual(self.completion.receipt_status, "NOT_RUN_ENV_UNAVAILABLE")

    def test_stale_generation_before_seal_prevents_append(self):
        self.chunks()
        self.observed["generation"] = "f" * 64
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.seal_cleanup()
        self.assertEqual(self.ledger, self.before_completion)
        self.socket.send.assert_not_called()

    def test_seal_fsync_failure_poisoned_without_cleanup_send(self):
        self.chunks()
        self.fail = "sync"
        with self.assertRaises((ConformanceError, OSError)):
            self.subject.seal_cleanup()
        self.assertTrue(self.owner.log.poisoned)
        self.assertTrue(self.ledger.startswith(self.before_completion))
        self.socket.send.assert_not_called()

    def test_terminal_append_failure_never_publishes_complete(self):
        self.sent_cleanup()
        self.subject.poll_terminal()
        self.fail = "before"
        with self.assertRaises((ConformanceError, OSError)):
            self.subject.record_terminal()
        self.assertEqual(self.ledger, self.sealed_history)
        self.assertFalse(self.completion.complete)
        self.assertTrue(self.owner.log.poisoned and self.held()["held"])

    def test_terminal_rights_are_drained_before_post_receive_refusal(self):
        self.sent_cleanup()
        self.extra_ancillary = [(server.socket.SOL_SOCKET, server.socket.SCM_RIGHTS, server.struct.pack("i", 99))]
        with self.assertRaises(ConformanceError):
            self.subject.poll_terminal()
        self.assertEqual(self.events.count(("close", 99)), 1)
        self.assertEqual(self.ledger, self.sealed_history)

    def test_cannot_record_or_repeat_unreceived_terminal(self):
        self.sent_cleanup()
        with self.assertRaisesRegex(ConformanceError, "BROKER_TERMINAL_RECORD_ORDER"):
            self.subject.record_terminal()
        self.assertEqual(self.ledger, self.sealed_history)


class BrokerStartupSourceOrderTests(unittest.TestCase):
    """Source ordering only; separate from every OS-mocked channel fixture."""
    def test_server_constructor_order_keeps_broker_before_credentials(self):
        import inspect
        source = inspect.getsource(server.NativeProxyServer.__init__)
        positions = [source.index(fragment) for fragment in (
            'self.qualification.__init__(self)', 'self.observer.__init__(self)',
            'self.broker.__init__(self)', 'self.files.sealed = True',
            'self._transport_check()', 'self.secrets.read(IDENTITY')]
        self.assertEqual(positions, sorted(positions))
        # Source ordering is not execution of the complete native factory.
        self.assertIn('self.broker = self._broker_original = object.__new__(_Broker)', source)


class BrokerCreatePreflightTests(_BrokerEventFixture, unittest.TestCase):
    """Driver pre-credential boundary using the existing intent/storage leaf fixture."""
    start = BrokerIntentTests.start
    setUp = BrokerIntentTests.setUp
    read_intent = BrokerIntentTests.read_intent
    append_intent = BrokerIntentTests.append_intent
    sync_intent = BrokerIntentTests.sync_intent

    def test_missing_durable_intent_refuses_before_credential_or_socket(self):
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATE_INTENT_REQUIRED"):
            self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, 1)
        self.owner.files.read.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_committed_intent_preflight_is_not_an_api_or_effect(self):
        self.subject.record_create_intent()
        history = self.ledger
        self.subject.check_action_ownership()
        self.assertIsNone(self.subject.api)
        self.assertEqual(self.mocks["socket"].call_count, 1)
        self.owner.files.read.assert_not_called()
        self.socket.send.assert_not_called()
        self.assertEqual(self.ledger, history)

    def test_uncommitted_intent_cannot_be_accepted_as_durable(self):
        self.subject.record_create_intent()
        self.subject.intent.committed = False
        with self.assertRaisesRegex(ConformanceError, "BROKER_CREATE_INTENT_REQUIRED"):
            self.subject.check_action_ownership()
        self.assertEqual(self.mocks["socket"].call_count, 1)
        self.owner.files.read.assert_not_called()


class ReceiptChunkBoundaryTests(unittest.TestCase):
    """Data framing only; a detected boundary never supplies receipt acceptance."""
    def test_object_boundary_can_cross_every_byte_offset(self):
        raw = canonical_bytes({"x": ["quote\" slash\\ brace} [", {"z": True}], "y": None})
        for at in range(1, len(raw)):
            with self.subTest(at=at):
                self.assertFalse(server._receipt_chunks_complete([raw[:at]]))
                self.assertTrue(server._receipt_chunks_complete([raw[:at], raw[at:]]))

    def test_split_multibyte_utf8_does_not_end_the_object(self):
        raw = '{"x":"ö"}'.encode()
        at = raw.index(b'\xc3') + 1
        self.assertFalse(server._receipt_chunks_complete([raw[:at]]))
        self.assertTrue(server._receipt_chunks_complete([raw[:at], raw[at:]]))

    def test_missing_outer_close_remains_incomplete(self):
        for raw in (b'{', b'{"x":', b'{"x":"', b'{"x":"\\', b'{"x":{}}'[:-1]):
            with self.subTest(raw=raw):
                self.assertFalse(server._receipt_chunks_complete([raw]))

    def test_array_scalar_or_garbage_cannot_supply_receipt_object(self):
        for raw in (b'[]', b'null', b'1', b'"{}"', b'not-json'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ConformanceError, "BROKER_RECEIPT_OBJECT_REQUIRED"):
                server._receipt_chunks_complete([raw])

    def test_trailing_object_or_bytes_refuse_even_in_separate_chunk(self):
        for suffix in (b'{}', b'[]', b'x', b'\x00'):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ConformanceError, "BROKER_RECEIPT_TRAILING_BYTES"):
                server._receipt_chunks_complete([b'{}', suffix])

    def test_wrong_bracket_and_literal_string_control_refuse(self):
        for raw in (b'{]', b'{"x":[}', b'{"x":"\x00"}', b'{"x":"\n"}'):
            with self.subTest(raw=raw), self.assertRaises(ConformanceError):
                server._receipt_chunks_complete([raw])

    def test_empty_oversize_nonbytes_and_excess_chunk_count_refuse(self):
        for chunks in ([], [b''], ['{}'], [bytearray(b'{}')], (b'{}',),
                       [b'{' * 24577], [b' '] * 172, [b' ' * 24576] * 171):
            with self.subTest(kind=type(chunks).__name__, count=len(chunks)), self.assertRaises(ConformanceError):
                server._receipt_chunks_complete(chunks)

    def test_depth_limit_is_not_reset_between_frames(self):
        with self.assertRaisesRegex(ConformanceError, "BROKER_RECEIPT_DEPTH"):
            server._receipt_chunks_complete([b'{' * 8, b'{' * 9])

    def test_complete_but_invalid_json_still_requires_strict_validation(self):
        raw = b'{garbage}'
        self.assertTrue(server._receipt_chunks_complete([raw]))
        with self.assertRaises(ConformanceError):
            server.document(raw)


class BrokerCaseHandoffTests(_BrokerCompletionFixture, unittest.TestCase):
    """Actual completion/handoff/start owners; existing leaf boundary doubles."""
    def completed(self):
        self.sent_cleanup()
        self.subject.poll_terminal()
        self.subject.record_terminal()
        self.completed_case = self.owner.active_operation
        self.final_history = self.ledger
        self.original_channel = self.subject.sock
        self.original_deadline = self.subject.deadline

    def next_case(self):
        operation = next(case for case in server.CASES if case != self.completed_case)
        self.owner.log.record(self.owner.reservation, "RUNNING", operation, self.wall)
        self.owner.active_operation = operation
        self.socket.send.side_effect = self.send
        self.socket.recvmsg.side_effect = self.receive
        self.challenge.return_value = b'\xab' * 32
        self.on_send = lambda: self.frame.update(executionId='d' * 64)

    def test_handoff_retains_original_channel_deadline_and_all_history(self):
        self.completed()
        old = self.completion
        self.subject.finish_case()
        self.assertIsNone(self.owner.active_operation)
        self.assertIsNone(self.subject.dispatch)
        self.assertIsNone(self.subject.events)
        self.assertIsNone(self.subject.completion)
        self.assertIsNone(self.subject.last_get)
        self.assertEqual(self.subject._attempted_cases, {self.completed_case})
        self.assertEqual(self.ledger, self.final_history)
        self.assertTrue(self.held()["held"])
        self.assertIs(self.subject.sock, self.original_channel)
        self.assertEqual(self.subject.deadline, self.original_deadline)
        archive = json.loads(self.subject.case_history[0])
        self.assertEqual(archive["terminalDigest"], byte_digest(old.terminal_raw))
        self.assertEqual(archive["receiptDigest"], byte_digest(self.receipt_bytes))
        self.assertEqual(archive["ledgerDigest"], byte_digest(self.final_history))
        self.socket.connect.assert_called_once()
        self.socket.close.assert_not_called()

    def test_next_case_dispatch_uses_new_challenge_same_channel_and_nonce(self):
        self.completed()
        self.subject.finish_case()
        self.next_case()
        history = self.ledger
        self.subject.begin()
        dispatch = json.loads(self.subject.dispatch.dispatch_raw)
        self.assertEqual(dispatch["challenge"], 'ab' * 32)
        self.assertEqual(dispatch["runNonce"], self.owner.envelope["nonce"])
        self.assertEqual(json.loads(self.subject.dispatch.started)["executionId"], 'd' * 64)
        self.assertEqual(self.subject._attempted_cases, {self.completed_case, self.owner.active_operation})
        self.assertIs(self.subject.sock, self.original_channel)
        self.assertEqual(self.subject.deadline, self.original_deadline)
        self.assertEqual(self.ledger, history)
        self.socket.connect.assert_called_once()

    def test_missing_terminal_cannot_retire_case(self):
        self.sealed()
        history = self.ledger
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_TERMINAL_REQUIRED"):
            self.subject.finish_case()
        self.assertEqual(self.ledger, history)
        self.assertTrue(self.held()["held"])
        self.assertEqual(self.subject.case_history, ())

    def test_received_but_unrecorded_terminal_cannot_retire(self):
        self.sent_cleanup()
        self.subject.poll_terminal()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_TERMINAL_REQUIRED"):
            self.subject.finish_case()
        self.assertEqual(self.subject.case_history, ())
        self.assertTrue(self.held()["held"])

    def test_failed_receipt_and_terminal_cannot_enable_next_case(self):
        self.configure("FAIL")
        self.completed()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_NOT_CLEAN_COMPLETED"):
            self.subject.finish_case()
        self.assertEqual(self.owner.active_operation, self.completed_case)
        self.assertEqual(self.subject.case_history, ())
        self.assertEqual(self.ledger, self.final_history)
        self.assertTrue(self.held()["held"])

    def test_unavailable_receipt_and_terminal_cannot_enable_next_case(self):
        self.configure("NOT_RUN_ENV_UNAVAILABLE")
        self.completed()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_NOT_CLEAN_COMPLETED"):
            self.subject.finish_case()
        self.assertEqual(self.held()["current"], self.completed_case)
        self.assertTrue(self.held()["held"])

    def test_second_handoff_refuses_without_erasing_first_archive(self):
        self.completed()
        self.subject.finish_case()
        history = self.subject.case_history
        with self.assertRaises(ConformanceError):
            self.subject.finish_case()
        self.assertEqual(self.subject.case_history, history)
        self.assertEqual(self.ledger, self.final_history)

    def test_retired_completion_object_cannot_be_reused(self):
        self.completed()
        old = self.completion
        self.subject.finish_case()
        with self.assertRaisesRegex(ConformanceError, "BROKER_COMPLETION_OWNER_CHANGED"):
            server._BrokerCompletion._check(old)
        self.assertEqual(self.ledger, self.final_history)

    def test_late_trailing_frame_refuses_before_retirement(self):
        self.completed()
        self.ready = True
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_TRAILING_DATA"):
            self.subject.finish_case()
        self.assertEqual(self.subject.case_history, ())
        self.assertEqual(self.ledger, self.final_history)

    def test_changed_final_ledger_refuses_before_retirement(self):
        self.completed()
        self.ledger += b' '
        with self.assertRaisesRegex(ConformanceError, "BROKER_RUNNING_CHANGED"):
            self.subject.finish_case()
        self.assertEqual(self.subject.case_history, ())

    def test_attempted_case_archive_mismatch_refuses_retirement(self):
        self.completed()
        self.subject._attempted_cases.add(next(case for case in server.CASES if case != self.completed_case))
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_HISTORY_CHANGED"):
            self.subject.finish_case()
        self.assertEqual(self.subject.case_history, ())

    def test_next_case_cannot_reuse_challenge(self):
        self.completed()
        self.subject.finish_case()
        self.next_case()
        self.challenge.return_value = b'\xee' * 32
        self.socket.send.reset_mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CHALLENGE_REPLAY"):
            self.subject.begin()
        self.socket.send.assert_not_called()

    def test_next_case_cannot_reuse_broker_execution_id(self):
        self.completed()
        self.subject.finish_case()
        self.next_case()
        self.on_send = lambda: None  # existing transport emits the previous c*64 ID
        with self.assertRaisesRegex(ConformanceError, "BROKER_EXECUTION_REPLAY"):
            self.subject.begin()
        self.assertIsNone(self.subject.dispatch.started)

    def test_next_case_generation_change_refuses_before_dispatch(self):
        self.completed()
        self.subject.finish_case()
        self.next_case()
        self.observed["generation"] = 'f' * 64
        self.socket.send.reset_mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.begin()
        self.socket.send.assert_not_called()

    def test_next_case_observer_restart_refuses_before_dispatch(self):
        self.completed()
        self.subject.finish_case()
        self.next_case()
        self.observed["observerBootId"] = "changed-boot"
        self.socket.send.reset_mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_GENERATION_CHANGED"):
            self.subject.begin()
        self.socket.send.assert_not_called()

    def test_case_archive_substitution_refuses_before_any_new_io(self):
        self.completed()
        self.subject.finish_case()
        self.subject.case_history = (b'{}',)
        self.socket.send.reset_mock()
        with self.assertRaisesRegex(ConformanceError, "BROKER_CASE_HISTORY_CHANGED"):
            self.subject.check()
        self.socket.send.assert_not_called()

    def test_handoff_accepts_no_caller_result_or_reset_flag(self):
        for value in (True, {}, Mock(), b'PASS'):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                self.subject.finish_case(value)


def _failure_custody_fixture(test):
    """Original owner/files/store custody with leaf OS and journal-I/O doubles.

    This is not full server/qualification construction. It restores the actual
    custody checks around the earlier leaf's journal primitives, not a successful
    failure-accounting, admission or cleanup substitute.
    """
    owner = test.owner
    owner.pid, owner.thread, owner.closed = server.os.getpid(), server.threading.get_ident(), False
    owner.failure_accounting = owner._failure_accounting_original = None
    test.stack.enter_context(patch.object(server, "_ACTIVE", owner))
    if type(owner.files) is not server._Files:
        old = owner.files
        owner.files = server._Files(owner)
        owner.files.rows, owner.files.raw, owner.files.read = old.rows, old.raw, old.read
        owner.files.sealed = True
    test.fds[75] = test.exe
    def info(inode, mode):
        return SimpleNamespace(st_dev=1, st_ino=inode, st_uid=0, st_gid=0, st_mode=mode,
            st_nlink=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
    directory = info(90, stat.S_IFDIR | 0o700)
    lock, journal = info(91, stat.S_IFREG | 0o600), info(92, stat.S_IFREG | 0o600)
    test.fds.update({90: directory, 91: lock, 92: journal})
    owner.files.rows[server.STATE] = [90, None, "failure-store", server._custody_identity(directory)]
    previous_stat = test.mocks["stat"].side_effect
    def current_stat(path, **kwargs):
        if path == "broker":
            return test.exe
        if path == "failure-store":
            return directory
        if kwargs.get("dir_fd") == 90 and path in ("admission.lock", "reservations.jsonl"):
            return lock if path == "admission.lock" else journal
        return previous_stat(path, **kwargs)
    test.mocks["stat"].side_effect = current_stat
    store = owner.storage
    store.directory, store.lock, store.fd, store.floor = 90, 91, 92, b""
    store._failure_accounting = None
    store.identities = {"lock": server._custody_identity(lock)[:6], "fd": server._custody_identity(journal)[:6]}
    read, append, sync = store.read, store.append, store.sync
    def guarded_read(resource):
        server._State.check(resource)
        try:
            return read()
        finally:
            server._State.check(resource)
    def guarded_append(resource, raw):
        server._State.check(resource)
        try:
            return append(raw)
        finally:
            server._State.check(resource)
    def guarded_sync(resource):
        server._State.check(resource)
        try:
            return sync()
        finally:
            server._State.check(resource)
    test.stack.enter_context(patch.object(server._State, "read", guarded_read))
    test.stack.enter_context(patch.object(server._State, "append", guarded_append))
    test.stack.enter_context(patch.object(server._State, "sync", guarded_sync))


class ProxyCaseDriverTests(_BrokerCompletionFixture, unittest.TestCase):
    """Real driver/handshake/journal/receipt path, NOT C6 constructor evidence.

    The earlier leaf fixture still doubles installed qualification/observer
    boundaries. Only transport/storage data are scripted here; no successful
    driver, admission or cleanup result is substituted.
    """
    def setUp(self):
        BrokerDispatchStartTests.setUp(self)  # original broker, not yet dispatched
        self.configure()
        self.owner._broker_check = self.subject.check
        _failure_custody_fixture(self)
        self.ledger = b""
        self.owner.log.record(self.owner.reservation, "RESERVED", None, self.wall)
        self.owner.log.record(self.owner.reservation, "RUNNING", self.owner.active_operation, self.wall)
        self.writes.clear()
        self.io_events.clear()
        self.incoming, self.outgoing = [], []
        self.script_chunks = None
        self.script_status = None
        self.script_action = None
        self.lost_terminal = self.extra_terminal = False
        self.on_driver_receive = self.on_driver_send = lambda frame: None
        self.socket.send.side_effect = self.driver_send
        self.socket.recvmsg.side_effect = self.driver_receive
        self.mocks["select"].side_effect = self.driver_select

    def driver_select(self, readers, writers, exceptional, timeout):
        if readers == [self.socket]:
            if not self.incoming:
                self.now += timeout
            return ([self.socket] if self.incoming else [], [], [])
        self.assertEqual((readers, writers, exceptional, timeout), ([72], [], [72], 0))
        return [], [], []

    def enqueue(self, kind, payload):
        frame = {**deepcopy(self.wire_last), "kind": kind, "payload": payload,
            "sequence": self.wire_last["sequence"] + 1,
            "previousDigest": byte_digest(canonical_bytes(self.wire_last))}
        self.incoming.append(canonical_bytes(frame))
        self.wire_last = frame

    def driver_send(self, raw):
        import base64
        frame = json.loads(raw)
        self.on_driver_send(frame)
        self.outgoing.append(frame)
        if frame.get("operation") == "EXECUTE_FIXED_PROBE":
            self.wire_last = {**{k: frame[k] for k in admission.BROKER_COMMON},
                "schemaVersion": "planeon.internal.broker-frame/v1", "executionId": 'c' * 64,
                "sequence": 1, "previousDigest": admission.ZERO, "kind": "STARTED",
                "payload": {"workerPid": 1234, "workerStartTicks": 123}}
            self.incoming.append(canonical_bytes(self.wire_last))
            if self.script_action is not None:
                self.enqueue("RESOURCE_ACTION", self.script_action)
            else:
                parts = self.script_chunks if self.script_chunks is not None else [
                    self.receipt_bytes[:90], self.receipt_bytes[90:]]
                for index, part in enumerate(parts):
                    self.enqueue("RECEIPT_CHUNK", {"index": index,
                        "dataBase64": base64.b64encode(part).decode("ascii")})
        elif frame["kind"] == "CLEANUP_RECORDED":
            self.wire_last = frame
            if self.lost_terminal:
                self.incoming.append(b'')  # authenticated channel EOF, not absence
            else:
                self.enqueue("TERMINAL", {"status": self.script_status or {
                    "PASS": "COMPLETED", "FAIL": "FAILED", "NOT_RUN_ENV_UNAVAILABLE": "UNAVAILABLE"
                    }[self.case_receipt["status"]], "receiptSize": len(self.receipt_bytes),
                    "receiptDigest": byte_digest(self.receipt_bytes),
                    "cleanupDigest": frame["payload"]["cleanupDigest"], "workerReaped": True})
                if self.extra_terminal:
                    self.incoming.append(self.incoming[-1])
        else:
            raise AssertionError("unexpected zero-resource server frame")
        return len(raw)

    def driver_receive(self, *args):
        raw = self.incoming.pop(0)
        self.on_driver_receive(json.loads(raw) if raw else {})
        return raw, [(server.socket.SOL_SOCKET, 2, server.struct.pack("3i", *self.message_peer))], 0, None

    def drive_refused(self):
        with self.assertRaises((ConformanceError, OSError)):
            self.owner._drive_case()
        self.assertTrue(self.subject.failed and self.subject.closed)
        self.assertTrue(self.held()["held"])
        self.assertNotIn("TERMINAL_RECORDED", [json.loads(row)["state"] for row in self.writes])
        self.assertIsNotNone(self.held()["current"])
        self.assertEqual(self.mocks["socket"].call_count, 1)
        self.owner.files.read.assert_not_called()

    def test_real_driver_completes_zero_resource_case_without_future_module(self):
        self.assertFalse(hasattr(server, "_fixed_probes"))
        result = self.owner._drive_case()
        self.assertEqual(result, self.receipt_bytes)
        self.assertEqual([json.loads(row)["state"] for row in self.writes],
                         ["CLEANUP_SEALED", "TERMINAL_RECORDED"])
        self.assertEqual(len(self.subject.case_history), 1)
        self.assertIsNone(self.owner.active_operation)
        self.assertTrue(self.held()["held"])
        self.assertEqual(self.mocks["socket"].call_count, 1)
        self.owner.files.read.assert_not_called()
        self.assertEqual([frame.get("kind", "DISPATCH") for frame in self.outgoing],
                         ["DISPATCH", "CLEANUP_RECORDED"])

    def test_real_driver_does_not_advance_failed_case(self):
        self.configure("FAIL")
        self.socket.send.side_effect = self.driver_send
        result = self.owner._drive_case()
        self.assertEqual(json.loads(result)["status"], "FAIL")
        self.assertEqual(self.subject.case_history, ())
        self.assertIsNotNone(self.owner.active_operation)
        self.assertTrue(self.held()["held"])

    def test_real_driver_does_not_upgrade_unavailable_to_pass(self):
        self.configure("NOT_RUN_ENV_UNAVAILABLE")
        self.socket.send.side_effect = self.driver_send
        result = self.owner._drive_case()
        self.assertEqual(json.loads(result)["status"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(self.subject.case_history, ())
        self.assertTrue(self.held()["held"])

    def test_zero_resource_action_is_denied_before_upstream_acquisition(self):
        self.script_action = {"actionId": 1, "verb": "CREATE", "manifestDigest": admission.ZERO}
        self.drive_refused()
        self.assertEqual([json.loads(row)["state"] for row in self.writes], ["FAILURE_RECORDED"])
        self.assertIsNone(json.loads(self.writes[-1])["cleanup"])
        self.assertIsNone(self.subject.intent)

    def test_lost_terminal_keeps_durable_cleanup_and_held_case(self):
        self.lost_terminal = True
        self.drive_refused()
        self.assertEqual([json.loads(row)["state"] for row in self.writes], ["CLEANUP_SEALED", "FAILURE_RECORDED"])

    def test_duplicate_terminal_cannot_be_returned_as_receipt(self):
        self.extra_terminal = True
        self.drive_refused()

    def test_failed_terminal_cannot_match_pass_receipt(self):
        self.script_status = "FAILED"
        self.drive_refused()

    def test_complete_invalid_receipt_fails_before_cleanup_append(self):
        self.script_chunks = [b'{garbage}']
        self.drive_refused()
        self.assertEqual([json.loads(row)["state"] for row in self.writes], ["FAILURE_RECORDED"])
        self.assertIsNone(json.loads(self.writes[-1])["cleanup"])

    def test_trailing_receipt_object_fails_before_cleanup_append(self):
        self.script_chunks = [self.receipt_bytes + b'{}']
        self.drive_refused()
        self.assertEqual([json.loads(row)["state"] for row in self.writes], ["FAILURE_RECORDED"])

    def test_receipt_truncation_expires_without_new_dispatch(self):
        self.script_chunks = [self.receipt_bytes[:-1]]
        self.owner.deadline = self.subject.deadline = self.now + 0.5
        self.drive_refused()
        self.assertEqual([json.loads(row)["state"] for row in self.writes], ["FAILURE_RECORDED"])
        self.assertEqual(len(self.outgoing), 1)

    def test_denial_after_receipt_receive_prevents_cleanup_append(self):
        def revoke(frame):
            if frame.get("kind") == "RECEIPT_CHUNK":
                self.owner._base_check.side_effect = ConformanceError("UNIT_REVOKED", "unit")
        self.on_driver_receive = revoke
        self.drive_refused()
        self.assertEqual([json.loads(row)["state"] for row in self.writes], ["FAILURE_RECORDED"])

    def test_cleanup_append_failure_cannot_send_acknowledgement(self):
        self.fail = "sync"
        self.drive_refused()
        self.assertEqual([frame.get("kind", "DISPATCH") for frame in self.outgoing], ["DISPATCH"])
        self.assertTrue(self.owner.log._storage_ambiguous)
        self.assertEqual(self.owner.failure_accounting.refusal, "ACCOUNTING_UNAVAILABLE")

    def test_failed_driver_keeps_original_error_and_emits_only_failure_facts(self):
        def refuse(frame):
            if frame.get("kind") == "RECEIPT_CHUNK":
                raise OSError("unit secret text must never enter journal")
        self.on_driver_receive = refuse
        with self.assertRaisesRegex(OSError, "unit secret text"):
            self.owner._drive_case()
        accounting = self.owner.failure_accounting
        self.assertIs(type(accounting), server._FailureAccounting)
        self.assertTrue(accounting.complete)
        self.assertNotIn(b"unit secret text", self.ledger)
        self.assertEqual(json.loads(self.writes[-1])["failure"], {"reasonCode": "IO_AMBIGUOUS"})
        self.assertTrue(self.held()["held"])

    def test_failure_accounting_never_rechecks_observer_or_opens_transport(self):
        counts = []
        def receive(frame):
            if frame.get("kind") == "RECEIPT_CHUNK":
                self.owner._base_check.side_effect = ConformanceError("UNIT_REVOKED", "unit")
        def append():
            if self.subject.closed:
                counts.append((len(self.observations), self.mocks["socket"].call_count))
        self.on_driver_receive, self.on_append = receive, append
        self.drive_refused()
        self.assertTrue(self.owner.failure_accounting.complete)
        self.assertEqual(counts, [(len(self.observations), 1)])

    def test_failure_append_readback_ambiguity_cannot_retry(self):
        self.script_chunks = [b'{garbage}']
        self.fail = "readback"
        with self.assertRaises(ConformanceError):
            self.owner._drive_case()
        accounting = self.owner.failure_accounting
        self.assertFalse(accounting.complete)
        self.assertTrue(self.owner.log.poisoned and self.owner.log._storage_ambiguous)
        history = self.ledger
        with self.assertRaisesRegex(ConformanceError, "FAILURE_ACCOUNTING_ALREADY_ATTEMPTED"):
            accounting.record(OSError("retry"))
        self.assertEqual(self.ledger, history)

    def test_custody_loss_prevents_even_a_failure_append(self):
        def receive(frame):
            if frame.get("kind") == "RECEIPT_CHUNK":
                self.fds[92].st_ino = 123456
                raise OSError("unit journal replaced")
        self.on_driver_receive = receive
        with self.assertRaises(OSError):
            self.owner._drive_case()
        self.assertEqual(self.writes, [])
        self.assertFalse(self.owner.failure_accounting.complete)
        self.assertEqual(self.owner.failure_accounting.refusal, "ACCOUNTING_UNAVAILABLE")

    def test_owner_change_during_failure_append_refuses_before_fsync(self):
        self.script_chunks = [b'{garbage}']
        def change_owner():
            self.owner._failure_accounting_original = None
        self.on_append = change_owner
        with self.assertRaises(ConformanceError):
            self.owner._drive_case()
        self.assertTrue(self.owner.log._storage_ambiguous)
        self.assertFalse(self.owner.failure_accounting.complete)
        at = self.io_events.index("append")
        self.assertNotIn("fsync", self.io_events[at + 1:])

    def test_failure_accounting_cannot_run_before_broker_is_closed(self):
        actor = self.owner.failure_accounting = self.owner._failure_accounting_original = object.__new__(server._FailureAccounting)
        actor.__init__(self.owner)
        with self.assertRaisesRegex(ConformanceError, "FAILURE_ACCOUNTING_UNAVAILABLE"):
            actor.record(OSError("unit"))
        self.assertEqual(self.writes, [])
        self.socket.close.assert_not_called()

    def test_failure_cannot_switch_to_a_different_valid_looking_journal_fd(self):
        self.script_chunks = [b'{garbage}']
        def swap(frame):
            if frame.get("kind") == "RECEIPT_CHUNK":
                self.fds[93] = self.fds[92]
                self.owner.storage.fd = 93
                raise OSError("unit journal descriptor replaced")
        self.on_driver_receive = swap
        with self.assertRaises(OSError):
            self.owner._drive_case()
        self.assertEqual(self.writes, [])
        self.assertFalse(self.owner.failure_accounting.complete)
        self.assertEqual(self.owner.failure_accounting.refusal, "ACCOUNTING_UNAVAILABLE")

    def test_failure_accounting_cannot_be_constructed_from_caller_owner(self):
        with self.assertRaisesRegex(ConformanceError, "FAILURE_ACCOUNTING_OWNER"):
            server._FailureAccounting(self.owner)
        self.assertEqual(self.writes, [])

    def test_foreign_failure_owner_cannot_touch_original_journal(self):
        self.script_chunks = [b'{garbage}']
        self.drive_refused()
        actor, before = self.owner.failure_accounting, self.ledger
        self.owner.failure_accounting = Mock()
        with self.assertRaises(ConformanceError):
            actor._state_check()
        self.assertEqual(self.ledger, before)

    def test_closed_reason_mapping_never_uses_arbitrary_messages(self):
        for error, expected in ((ConformanceError("TLS_DEADLINE", "secret"), "DEADLINE"),
                (ConformanceError("ADMISSION_UID_CHANGED", "secret"), "UID_CHANGED"),
                (ConformanceError("ADMISSION_DELETE_DENIED", "secret"), "DELETE_DENIED"),
                (OSError("secret"), "IO_AMBIGUOUS"), (ValueError("secret"), "OBSERVATION_UNAVAILABLE"),
                (ConformanceError("BROKER_DELETE_FRESH_GET_REQUIRED", "secret"), "OBSERVATION_UNAVAILABLE")):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(server._failure_reason(error), expected)


class ObserverTransportCustodyTests(unittest.TestCase):
    """Real observer factory/codec, OS mocks and explicit owner/containment doubles.

    These transport tests do not complete or bypass native qualification in
    production. No real socket, process reader, credential or probe is used.
    """
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.now, self.wall = 100.0, "2026-09-08T00:00:02.000000Z"
        self.events, self.replies = [], []
        self.fixture = deepcopy(VECTORS["observation"]["positive"])
        self.peer = (811, 0, 0)
        self.process = dict(pid=811, start=71, parent=1, uid=(0,) * 4, gid=(0,) * 4,
            capabilities=(0,) * 5, seccomp=2, noNewPrivs=1, cgroup="0::/planeon-live/policy-observer\n",
            namespaces=dict(user=1, mnt=2, pid=3, net=4))
        def info(inode, mode):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_uid=0, st_gid=0, st_mode=mode,
                st_nlink=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1)
        self.path = info(21, stat.S_IFSOCK | 0o600)
        self.exe = info(22, stat.S_IFREG | 0o555)
        self.fds = {71: info(31, stat.S_IFSOCK | 0o600), 72: info(32, stat.S_IFREG | 0o600)}
        self.socket = Mock()
        self.socket.fileno.return_value = 71
        self.socket.getsockopt.side_effect = lambda *args: server.struct.pack("3i", *self.peer)
        self.socket.send.side_effect = self.send
        self.socket.recvmsg.side_effect = self.receive
        self.owner = object.__new__(server.NativeProxyServer)
        self.owner.deadline = 500
        self.owner._base_check = Mock(side_effect=lambda: self.events.append("owner"))
        self.owner.files = Mock()
        self.owner.files.raw = {server.OBSERVER: b"\x7fELFunit-only"}
        self.owner.files.rows = {server.OBSERVER: [75, None, "observer", server._custody_identity(self.exe)]}
        self.owner.files._open.return_value = 75
        self.owner.observation_binding = deepcopy(self.fixture["binding"])
        self.owner.profile = deepcopy(VECTORS["proxy"]["positive"])
        self.owner.envelope = {"nonce": self.fixture["request"]["runNonce"]}
        self.subject = self.owner.observer = object.__new__(server._Observer)
        self.containment = Mock(return_value=None)
        # This existing class tests transport, not native reader qualification.
        # Keep its explicit containment double at the new fixed owned component.
        def inspection_init(resource, peer):
            resource.peer, resource.closed = peer, False
        self.stack.enter_context(patch.object(server._KernelObserverInspection, "__init__", inspection_init))
        self.stack.enter_context(patch.object(server._KernelObserverInspection, "check", self.containment))
        self.stack.enter_context(patch.object(server._KernelObserverInspection, "close",
            lambda resource: setattr(resource, "closed", True)))
        patches = ((server.time, "monotonic", dict(side_effect=lambda: self.now)),
            (server, "utc_now", dict(side_effect=lambda: self.wall)),
            (server, "_manifest", dict(return_value=({}, self.fixture["binding"]["observer"]["manifestDigest"],
                self.fixture["binding"]["observer"]["executableDigest"]))),
            (server, "_fixed_probes", dict(return_value=SimpleNamespace(require_observer_containment=self.containment), create=True)),
            (server, "process_identity", dict(side_effect=lambda pid: deepcopy(self.process))),
            (server.os, "stat", dict(side_effect=lambda path, **kw: self.path if path == "policy-observer.sock" else self.exe)),
            (server.os, "fstat", dict(side_effect=lambda fd: self.fds[fd])),
            (server.os, "get_inheritable", dict(return_value=False)),
            (server.os, "pidfd_open", dict(return_value=72, create=True)),
            (server.os, "close", dict(side_effect=lambda fd: self.events.append(("close", fd)))),
            (server.os, "urandom", dict(side_effect=[b"\xaa" * 32, b"\xbb" * 32, b"\xcc" * 32])),
            (server.socket, "socket", dict(return_value=self.socket)),
            (server.socket, "SO_PEERCRED", dict(new=17, create=True)),
            (server.select, "select", dict(return_value=([], [], []))))
        self.mocks = {}
        for obj, name, arguments in patches:
            self.mocks[name] = self.stack.enter_context(patch.object(obj, name, **arguments))
        self.stack.callback(self.cleanup)

    def cleanup(self):
        if hasattr(self.subject, "closed"):
            if self.subject.cleanup_failure is None:
                self.subject.close()
            else:
                with self.assertRaises(type(self.subject.cleanup_failure)):
                    self.subject.close()

    def start(self):
        self.subject.__init__(self.owner)
        return self.subject

    def send(self, raw):
        self.events.append("send")
        request = json.loads(raw)
        response = deepcopy(self.fixture["observation"])
        for key in ("bindingDigest", "runNonce", "challenge", "sequence", "previousObservationDigest"):
            response[key] = request[key]
        self.replies.append(canonical_bytes(response))
        return len(raw)

    def receive(self, *args):
        self.events.append("receive")
        return self.replies.pop(0), [(server.socket.SOL_SOCKET, 2, server.struct.pack("3i", *self.peer))], 0, None

    def test_fixed_factory_observes_two_bound_datagrams_without_history_alias(self):
        subject = self.start()
        first = subject.observe()
        original = deepcopy(first)
        first["projections"]["rbac"]["resourceVersion"] = "caller-change"
        self.assertEqual(subject.previous, original)
        second = subject.observe()
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(second["previousObservationDigest"], server.canonical_digest(original))
        self.assertNotEqual(first["challenge"], second["challenge"])
        self.mocks["socket"].assert_called_once_with(server.socket.AF_UNIX, server.socket.SOCK_SEQPACKET)
        self.socket.connect.assert_called_once_with(server.OBSERVER_SOCKET)
        self.assertEqual(self.socket.send.call_count, 2)
        self.assertFalse(self.owner.files.read.called)

    def test_each_send_exception_runs_post_io_custody_without_retry(self):
        subject = self.start()
        def failed(raw):
            self.events.append("failed-send")
            raise TimeoutError("unit ambiguous send")
        self.socket.send.side_effect = failed
        with self.assertRaises(TimeoutError):
            subject.observe()
        self.assertIn("owner", self.events[self.events.index("failed-send") + 1:])
        self.assertTrue(subject.failed)
        with self.assertRaises(ConformanceError):
            subject.observe()
        self.socket.send.assert_called_once()
        self.socket.recvmsg.assert_not_called()

    def test_receive_exception_runs_post_io_custody_without_retry(self):
        subject = self.start()
        def failed(*args):
            self.events.append("failed-receive")
            raise OSError("unit receive")
        self.socket.recvmsg.side_effect = failed
        with self.assertRaises(OSError):
            subject.observe()
        self.assertIn("owner", self.events[self.events.index("failed-receive") + 1:])
        self.socket.recvmsg.assert_called_once()
        self.assertIsNone(subject.previous)
        self.assertTrue(subject.failed)

    def test_partial_datagram_send_is_ambiguous_and_never_replayed(self):
        subject = self.start()
        self.socket.send.side_effect = lambda raw: len(raw) - 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_SEND_AMBIGUOUS"):
            subject.observe()
        self.socket.send.assert_called_once()
        self.socket.recvmsg.assert_not_called()
        self.assertTrue(subject.failed)

    def test_socket_peer_credentials_rechecked_after_receive(self):
        subject = self.start()
        def changed(*args):
            result = self.receive(*args)
            self.peer = (812, 0, 0)
            return result
        self.socket.recvmsg.side_effect = changed
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_PEER_CHANGED"):
            subject.observe()
        self.assertIsNone(subject.previous)

    def test_pidfd_exceptional_liveness_refuses_before_send(self):
        subject = self.start()
        self.mocks["select"].return_value = ([], [], [72])
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_PEER_CHANGED"):
            subject.observe()
        self.socket.send.assert_not_called()

    def test_changed_process_start_time_refuses_before_send(self):
        subject = self.start()
        self.process["start"] += 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_PEER_CHANGED"):
            subject.observe()
        self.socket.send.assert_not_called()

    def test_socket_path_replacement_refuses_before_send(self):
        subject = self.start()
        self.path.st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_PEER_CHANGED"):
            subject.observe()
        self.socket.send.assert_not_called()

    def test_inheritable_retained_descriptors_refuse_before_send(self):
        subject = self.start()
        self.mocks["get_inheritable"].side_effect = lambda fd: fd == 72
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_DESCRIPTOR_CHANGED"):
            subject.observe()
        self.socket.send.assert_not_called()

    def test_mutated_local_process_pin_is_not_new_enrollment(self):
        subject = self.start()
        subject.identity["namespaces"]["net"] += 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_RETAINED_PEER_CHANGED"):
            subject.check()

    def test_mutated_observation_history_is_not_accepted_as_a_chain(self):
        subject = self.start()
        subject.observe()
        subject.previous["sequence"] += 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_HISTORY_CHANGED"):
            subject.observe()
        self.socket.send.assert_called_once()

    def test_one_phase_budget_includes_initial_check_send_receive_and_final_check(self):
        subject = self.start()
        def delayed_send(raw):
            self.now += 1.5
            return self.send(raw)
        def delayed_receive(*args):
            self.now += 0.5
            return self.receive(*args)
        self.socket.send.side_effect = delayed_send
        self.socket.recvmsg.side_effect = delayed_receive
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOCK_OR_DEADLINE"):
            subject.observe()
        self.assertEqual(subject.end, 102)
        self.assertIsNone(subject.previous)

    def test_session_deadline_is_not_extended_by_new_exchange(self):
        subject = self.start()
        self.now = 499.5
        def late(*args):
            self.now = 500
            return self.receive(*args)
        self.socket.recvmsg.side_effect = late
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOCK_OR_DEADLINE"):
            subject.observe()
        self.assertEqual(subject.end, 500)

    def test_monotonic_rollback_is_sticky(self):
        subject = self.start()
        self.now = 99
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOCK_OR_DEADLINE"):
            subject.check()
        self.now = 100
        with self.assertRaises(ConformanceError):
            subject.check()

    def test_wall_rollback_is_sticky(self):
        subject = self.start()
        self.wall = "2026-09-08T00:00:01Z"
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOCK_OR_DEADLINE"):
            subject.check()

    def test_received_rights_closed_even_when_post_io_authority_fails(self):
        subject = self.start()
        def injected(*args):
            raw, ancillary, flags, address = self.receive(*args)
            ancillary.append((server.socket.SOL_SOCKET, server.socket.SCM_RIGHTS, server.struct.pack("i", 99)))
            self.owner._base_check.side_effect = ConformanceError("UNIT_AUTHORITY_DRIFT", "unit")
            return raw, ancillary, flags, address
        self.socket.recvmsg.side_effect = injected
        with self.assertRaises(ConformanceError):
            subject.observe()
        self.assertIn(("close", 99), self.events)
        self.assertIsNone(subject.previous)

    def test_truncated_datagram_is_rejected_by_real_ancillary_parser(self):
        subject = self.start()
        def truncated(*args):
            raw, ancillary, _, address = self.receive(*args)
            return raw, ancillary, server.socket.MSG_TRUNC, address
        self.socket.recvmsg.side_effect = truncated
        with self.assertRaisesRegex(ConformanceError, "PEER_CHANNEL_INVALID"):
            subject.observe()

    def test_invalid_response_never_advances_history(self):
        subject = self.start()
        self.socket.recvmsg.side_effect = lambda *args: (b"{}", [(server.socket.SOL_SOCKET, 2,
            server.struct.pack("3i", *self.peer))], 0, None)
        with self.assertRaises(ConformanceError):
            subject.observe()
        self.assertIsNone(subject.previous)
        self.assertTrue(subject.failed)

    def test_partial_constructor_connect_error_closes_only_acquired_socket(self):
        self.socket.connect.side_effect = OSError("unit connect")
        with self.assertRaises(OSError):
            self.start()
        self.socket.close.assert_called_once()
        self.mocks["pidfd_open"].assert_not_called()
        self.owner.files.close.assert_not_called()
        self.assertTrue(self.subject.closed and self.subject.failed)

    def test_post_pidfd_acquisition_failure_keeps_cleanup_ownership(self):
        def acquired(*args):
            self.owner._base_check.side_effect = OSError("unit post acquisition")
            return 72
        self.mocks["pidfd_open"].side_effect = acquired
        with self.assertRaises(OSError):
            self.start()
        self.assertEqual(self.events.count(("close", 72)), 1)
        self.socket.close.assert_called_once()

    def test_replaced_socket_object_is_refused_and_foreign_socket_not_closed(self):
        subject = self.start()
        foreign = Mock()
        subject.sock = foreign
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_RETAINED_PEER_CHANGED"):
            subject.check()
        subject.close()
        self.socket.close.assert_called_once()
        foreign.close.assert_not_called()

    def test_reused_socket_descriptor_detaches_without_closing_foreign_fd(self):
        subject = self.start()
        self.fds[71].st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_DESCRIPTOR_CHANGED"):
            subject.check()
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOSE_FD_REUSED"):
            subject.close()
        self.socket.detach.assert_called_once()
        self.socket.close.assert_not_called()
        self.assertEqual(self.events.count(("close", 72)), 1)

    def test_reused_pidfd_is_not_closed_and_socket_cleanup_continues(self):
        subject = self.start()
        self.fds[72].st_ino += 1
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOSE_FD_REUSED"):
            subject.close()
        self.assertNotIn(("close", 72), self.events)
        self.socket.close.assert_called_once()

    def test_close_error_is_sticky_without_retry_and_other_cleanup_continues(self):
        subject = self.start()
        self.mocks["close"].side_effect = OSError("unit uncertain close")
        for _ in range(2):
            with self.assertRaises(OSError):
                subject.close()
        self.mocks["close"].assert_called_once_with(72)
        self.socket.close.assert_called_once()

    def test_owner_replacement_refuses_before_transport(self):
        subject = self.start()
        self.owner.observer = Mock()
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_OWNER_CHANGED"):
            subject.observe()
        self.socket.send.assert_not_called()


class ObserverInspectionWiringTests(unittest.TestCase):
    """Real channel factory; explicit inspector double for ownership failures."""
    setUp = ObserverTransportCustodyTests.setUp
    cleanup = ObserverTransportCustodyTests.cleanup
    start = ObserverTransportCustodyTests.start
    send = ObserverTransportCustodyTests.send
    receive = ObserverTransportCustodyTests.receive

    def test_inspector_constructor_failure_closes_channel_before_any_datagram(self):
        with patch.object(server._KernelObserverInspection, "__init__", side_effect=ConformanceError("UNIT_INSPECTOR", "unit")):
            with self.assertRaisesRegex(ConformanceError, "UNIT_INSPECTOR"):
                self.start()
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)
        self.socket.send.assert_not_called()

    def test_inspector_check_failure_prevents_observation(self):
        subject = self.start()
        self.containment.side_effect = ConformanceError("UNIT_INSPECTOR", "unit")
        with self.assertRaisesRegex(ConformanceError, "UNIT_INSPECTOR"):
            subject.observe()
        self.socket.send.assert_not_called()
        self.assertTrue(subject.failed)

    def test_truthy_inspector_result_is_not_containment(self):
        self.containment.return_value = True
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CONTAINMENT_UNAVAILABLE"):
            self.start()
        self.socket.send.assert_not_called()

    def test_replaced_inspector_is_refused_without_closing_foreign_owner(self):
        subject = self.start()
        original = subject.inspection
        foreign = Mock()
        subject.inspection = foreign
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_INSPECTION_CHANGED"):
            subject.check()
        subject.close()
        self.assertTrue(original.closed)
        foreign.close.assert_not_called()

    def test_inspector_close_error_does_not_skip_channel_cleanup(self):
        subject = self.start()
        with patch.object(server._KernelObserverInspection, "close", side_effect=OSError("unit cleanup")) as closed:
            for _ in range(2):
                with self.assertRaises(OSError):
                    subject.close()
            closed.assert_called_once()
        self.socket.close.assert_called_once()
        self.assertEqual(self.events.count(("close", 72)), 1)

    def test_observer_no_longer_requests_legacy_probe_containment(self):
        with patch.object(server, "_fixed_probes", side_effect=AssertionError("no legacy observer hook"), create=True):
            subject = self.start()
            self.assertEqual(subject.observe()["sequence"], 1)
        self.assertGreater(self.containment.call_count, 0)

    def test_socket_wait_budgets_exclude_time_spent_in_inspection(self):
        subject = self.start()
        def delayed_check():
            self.now += 0.25
        self.containment.side_effect = delayed_check
        self.socket.settimeout.reset_mock()
        subject.observe()
        self.assertEqual(self.socket.settimeout.call_args_list,
                         [unittest.mock.call(1.5), unittest.mock.call(1.0)])

    def test_late_timeout_setter_refuses_before_datagram_send(self):
        subject = self.start()
        def late(timeout):
            self.now = subject.end
        self.socket.settimeout.side_effect = late
        with self.assertRaisesRegex(ConformanceError, "OBSERVER_CLOCK_OR_DEADLINE"):
            subject.observe()
        self.socket.send.assert_not_called()
        self.assertTrue(subject.failed)


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


# Exact public META authority bytes from MET-REPAIR-017's accepted predecessor.
# Test data only: never execute this declaration or read a META checkout at test
# runtime. The constructor's real hash check must remain enabled.
_FULL_FACTORY_PACKET_006 = b'''id: "CONF-LIVE-006"
repository: "mas-harness-conformance-labs"
branch: "codex/conf-live-006-campaign-integration"
objective: "Trusted campaign integration and manual qualification declaration under the approved trusted backend roadmap; source coding only."
predecessors: ["CONF-LIVE-005"]
allowedPaths: ["src/harness_conformance/live_launcher.py","src/harness_conformance/live_backend_campaign.py","src/harness_conformance/live_backend_evidence.py","tests/live_backend/test_campaign_integration.py","tests/live_backend/test_cumulative_release.py","docs/live-backend/qualification.md"]
warmSourceAccess: "PROHIBITED_DURING_IMPLEMENTATION"
sourceReuse: []
contracts: ["Consumes docs/alpha-2/LIVE_BACKEND_READINESS.md and architecture/live-backend-roadmap.json from the exact merged MET-LIVE-001 authority, the existing trusted live-runner contract and unchanged CONF-LINUX-001/CON-007 wire contracts. Pin exact merged predecessor SHA and complete source inventory before edits.","Source-only enablement before the native gate is limited to these six packets. No installation or live execution occurs in a coding run. Missing authority, supported OS backend or native capacity fails closed; offline fakes remain UNIT_VERIFICATION_ONLY with nativeAcceptance=false.","Preserve all 120 original test identities across tests/meta, tests/parity, tests/alpha1, tests/fixes/runner_boundary and tests/platform/linux_baseline. Add flat tests/live_backend discovery, run all six roots on every packet and prove no module/test omission, skip, xfail, deselection or test-only runtime shortcut.","Python 3.12.14 standard library and existing pinned conformance crypto/canonical helpers only; no new dependency, public API/signature schema/role, Makefile/dispatcher, PORTING ledger, warm-source, workflow or toolchain change. Kernel primitives and fixed operator prerequisites are preinstalled, never downloaded."]
deliverables: ["Add the sole existing-file integration hook in live_launcher.py, after independent installed-manifest/signature/custody checks and before any checked-out code/credential access. Delegate to the fixed installed supervisor implementation, never import checkout-selected modules. Preserve the direct/unauthorized CLI refusal and pure linux_readiness.py UNIT_VERIFICATION_ONLY behavior.","Implement the authenticated external campaign context path in live_backend_campaign.py. Reuse the existing pure validators and data-only request builder, but obtain all transport/session authority and signed receipts from the protected channel. The offline campaign API and its three predecessor campaign outputs remain byte-identical; environment flags and fixture evidence never enter the live path.","Run all eight cumulative commands and inventory checks, rebuild the complete candidate via the new builder from tests, and prove every original test and all newly added packet tests are discovered. Bind all six source increments, final release inputs and current packet/command digests; never reuse a seven-command historical envelope.","Declare the future manual post-merge linux-baseline run through only the external root-owned launcher with an independent installed candidate, dual-signed exact eight-command envelope, capacity authorization and existing native target. This declaration does not perform or authorize an installation, network call or live run in coding/CI. Missing prerequisites remain NOT_RUN_ENV_UNAVAILABLE.","Publish per-architecture/per-case runtime evidence references separately from source/head/CI/merge/exact-main/package/preflight. Ten fresh mandatory AMD64 cases plus all original gate conditions are required before runtime product dispatch; ARM64 remains separate. No campaign signature becomes tenant acceptance.","Implement the separate pure live_backend_evidence verifier using the new authority adapter and the existing Linux evidence shape/plan/request primitives. Bind authority.packetDigest to the exact CONF-LIVE-006 packet and eight commands, not the old hardcoded digest. Preserve all three independent evidence signatures, every release/plan/case/freshness check and UNIT_VERIFICATION_ONLY/nativeAcceptance=false for pure verification. Only the protected installed supervisor plus independently verified real receipts can support a separate native qualification decision; no substitution or monkeypatch of old constants."]
excluded: ["No administrator installation, provisioning, kernel/cluster policy modification on this workstation, live network/probe argv, emulation-based native PASS, paid API or third-party key, mutable artifact, warm-source access, external telemetry or source-to-runtime evidence promotion.","No edits to predecessor tests, crypto.py, canonical.py, models.py, schema.py, registry.py, campaign.py, live.py, cli.py, linux_readiness.py, existing schemas, ci/build_live_launcher.py, Makefile, dispatcher, toolchain, workflow or PORTING.yaml. New tests independently preserve old source guards; no relaxing immutable baseline hashes. The sole permitted existing-file exception is live_launcher.py as specified above."]
prefetchCommands: []
offlineAcceptanceCommands: [["python3","-m","unittest","discover","-s","tests/meta","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/parity","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/alpha1","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/fixes/runner_boundary","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/platform/linux_baseline","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py"],["make","campaign","CAMPAIGN=linux-baseline"],["make","evidence-verify","CAMPAIGN=linux-baseline"]]
offlineExecution: {"wrapperArgv":["./ci/verify-offline.sh"],"packetPathEnvironment":"HARNESS_TASK_PACKET","packetPathMode":"HASH_PINNED_READ_ONCE_NO_CHILD_PATH","commandTransport":"ARGV_ARRAY_V1","isolation":"OS_ENFORCED_DENY_ALL_OUTBOUND","sessionScope":"SINGLE_PROCESS_TREE","prefetchOutsideSession":false,"offlineEnvironment":{"UV_OFFLINE":"1","UV_FROZEN":"1","UV_NO_SYNC":"1"}}
liveCampaignExecution: {"launcherArgv":["/opt/planeon/bin/harness-live-campaign-launch"],"commandTransport":"ARGV_ARRAY_V1","executionPlacement":"PREINSTALLED_TARGET_LOCAL_EPHEMERAL_RUNNER","executionEnvelopeEnvironment":"HARNESS_LIVE_EXECUTION_ENVELOPE","executionEnvelopeMode":"DUAL_SIGNED_PACKET_COMMAND_CAMPAIGN_ENDPOINT_BINDING_V1","releaseTrustStoreMount":"/etc/planeon/trust/release-trust-bundle.json","tenantTrustStoreMount":"/etc/planeon/trust/tenant-trust-bundle.json","trustStoreMode":"HASH_PINNED_LOCAL_PUBLIC_KEYS_VALIDITY_PURPOSE_AND_REVOCATION_V1","revocationRequired":true,"networkIsolation":"OS_ENFORCED_DENY_ALL_EXCEPT_SIGNED_ENDPOINTS","endpointAuthority":"TENANT_CONTROLLED_PREEXISTING_CAPACITY_ONLY","dynamicEndpointTransport":"PREAUTHORIZED_API_OR_CAMPAIGN_PROXY_ONLY","mutationAdmission":"SERVER_SIDE_SIGNED_ZERO_INCREMENTAL_COST_POLICY_AND_RBAC_REQUIRED","capacityAuthorization":"INDEPENDENT_OPERATOR_SIGNED_FIXED_PREEXISTING_CAPACITY","publicInternetDiscovery":"DENIED","cloudManagementApis":"DENIED","billingApis":"DENIED","thirdPartyApiKeys":"DENIED","credentialMode":"TENANT_LOCAL_SHORT_LIVED_FILE_REFERENCE","unavailableResult":"NOT_RUN_ENV_UNAVAILABLE","ciEvidenceUse":"FORBIDDEN","allowedEvidenceAxes":["DEPLOYMENT","RUNTIME","SECURITY","ASSURANCE"],"commands":[["python3","-m","unittest","discover","-s","tests/meta","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/parity","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/alpha1","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/fixes/runner_boundary","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/platform/linux_baseline","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py"],["make","campaign","CAMPAIGN=linux-baseline"],["make","evidence-verify","CAMPAIGN=linux-baseline"]]}
expectedEvidence: ["Direct inner-launcher invocation, forged context, unsigned/mismatched/expired/revoked/replayed envelopes, wrong command count, credential-open ordering, source/native conflation, regression output drift, integration bypass and incomplete final-package inventory.","All eight offline commands run in one signed deny-all process tree; all original 120 test identities and every predecessor backend test remain discovered and passing. New tests never replace real native qualification.","Source/CI/merge/exact-main and unsigned candidate/package evidence are separate from installed preflight, native artifacts, runtime, assurance and tenant acceptance. Missing independent backend/target/authority is NOT_RUN_ENV_UNAVAILABLE; no phase completion claim."]
rollback: "Revert unconsumed integration source only. Independently installed artifacts require operator-reviewed rollback retaining replay/trust history; no tenant data or capacity destruction. Preserve completed evidence and mark mismatched native qualification stale."
'''


class _QualificationKernelOS(_QualificationBindingFixture):
    """One synthetic Linux OS for the real binding and all native factories.

    No qualifier, inspector, admission or driver method is replaced. Files,
    libc/syscall outputs, clock and transport are unit-only OS doubles; inert
    ELF/program bytes are never executed, installed, or called native evidence.
    """
    hooks = (("INET_SOCK_CREATE", 2), ("INET4_BIND", 8), ("INET6_BIND", 9),
             ("INET4_CONNECT", 10), ("INET6_CONNECT", 11),
             ("UDP4_SENDMSG", 14), ("UDP6_SENDMSG", 15))

    def __init__(self, case, architecture="amd64"):
        super().__init__(architecture)
        self.case = case
        self.events, self.handles, self.links, self.flags, self.maps = [], {}, {}, {}, []
        self.after = lambda operation, path: None
        self.processes = {"SERVER": server.os.getpid(), "OBSERVER": 9401, "BROKER": 9402}
        self.programs, self.code_pins = {}, {}
        self.kernel_raw = {
            "/proc/sys/kernel/random/boot_id": (self.record["host"]["bootId"] + "\n").encode(),
            "/sys/kernel/notes": b"C1 unit kernel notes, not native evidence",
            "/sys/fs/selinux/policy": b"C1 unit SELinux policy, not enforcement",
            "/sys/fs/selinux/enforce": b"1", "/sys/fs/selinux/deny_unknown": b"1"}
        self.raw_status = server.struct.pack("<5I", 1, 2, 1, 1, 1)
        self.record["host"]["kernelNotesDigest"] = byte_digest(self.kernel_raw["/sys/kernel/notes"])
        self.record["selinux"]["policyDigest"] = byte_digest(self.kernel_raw["/sys/fs/selinux/policy"])
        for row in self.record["files"]:
            path = row["path"]
            raw = (KernelInputCodecTests.elf(self, self.machine) if row["executableSegments"]
                   else b"PK\x03\x04C1 inert archive " + path.encode())
            self.raw[path] = raw
            row.update(size=len(raw), sha256=byte_digest(raw),
                verityDigest=byte_digest(b"C1 independent verity measurement:" + raw))
            self.code_pins[path] = row
        for role, pins in self.record["roles"].items():
            pins["artifactDigest"] = byte_digest(self.raw[pins["executable"]])
            for name, hook in self.hooks:
                program = pins["bpfPrograms"][name]
                raw = server.struct.pack("<4I", program["programId"], hook, 0, 0)
                program.update(instructionBytes=len(raw), translatedSha256=byte_digest(raw))
                self.programs[program["programId"]] = (pins["cgroup"]["path"], hook, program["programType"], raw)
        preflight = byte_digest(canonical_bytes(self.record))
        self.raw["/unit-only/kit/" + admission.QUALIFICATION_PATH] = canonical_bytes(self.record)
        for _, path, executable in self.paths:
            value = json.loads(self.raw[path])
            value["launcher"]["sha256"] = byte_digest(self.raw[executable])
            value["preflightEvidenceDigest"] = preflight
            self.manifest(path, value)
        self.observation["observer"] = dict(manifestDigest=byte_digest(self.raw[server.OBSERVER_MANIFEST]),
            executableDigest=byte_digest(self.raw[server.OBSERVER]))
        self.observation["enforcementPins"]["hostPreflightDigest"] = preflight
        self.broker.update(observationBindingDigest=server.canonical_digest(self.observation),
            brokerManifestDigest=byte_digest(self.raw[server.BROKER_MANIFEST]),
            brokerExecutableDigest=byte_digest(self.raw[server.BROKER]),
            workerManifestDigest=byte_digest(self.raw[server.WORKER_MANIFEST]),
            workerArtifactDigest=byte_digest(self.raw[server.WORKER]))
        for path, value in ((admission.OBSERVATION_PATH, self.observation),
                            (admission.BROKER_BINDING_PATH, self.broker)):
            self.raw["/unit-only/kit/" + path] = canonical_bytes(value)
        self.release()

    def node(self, path, *, directory=False, raw=None, **changes):
        if path not in self.nodes:
            parent = path.rsplit("/", 1)[0] or "/"
            if parent != path and parent not in self.nodes:
                self.node(parent, directory=True)
            self.nodes[path] = SimpleNamespace(st_dev=91, st_ino=5000 + len(self.nodes), st_nlink=1,
                st_uid=0, st_gid=0, st_mode=(stat.S_IFDIR | 0o555) if directory else (stat.S_IFREG | 0o444),
                st_size=0 if raw is None else len(raw), st_mtime_ns=1, st_ctime_ns=1)
        node = self.nodes[path]
        group = ("/sys/fs/cgroup" if path.startswith("/sys/fs/cgroup") else
                 "/sys/fs/selinux" if path.startswith("/sys/fs/selinux") else
                 "/sys" if path.startswith("/sys") else
                 "/proc" if path.startswith("/proc") else "/")
        index = ("/", "/proc", "/sys", "/sys/fs/selinux", "/sys/fs/cgroup").index(group)
        node.st_dev, node.mountId = server.os.makedev(0, 10 + index), 101 + index
        node.magic = (0xef53, 0x9fa0, 0x62656572, 0xf97cff8c, 0x63677270)[index]
        for key, value in changes.items():
            setattr(node, key, value)
        if raw is not None:
            self.kernel_raw[path] = raw
        return node

    def context(self, stack):
        owner = super().context(stack)
        self.kernel_context(stack)
        owner.secrets = server._Files(owner)
        owner.last_mono, owner.last_wall = self.mono, server.require_time(self.now, "now")
        owner.self_inspection = owner.observer = owner.broker = owner._broker_original = None
        owner.qualification = owner._qualification_original = object.__new__(server._KernelQualification)
        owner.qualification_binding.__init__(owner)
        def close_qualification():
            if hasattr(owner.qualification, "closed"):
                owner.qualification.close()
        stack.callback(close_qualification)
        return owner

    def kernel_context(self, stack):
        # Turn the signed file fixture into one consistent virtual kernel VFS.
        # Descriptor rows retain node objects; replacing a path is not silently
        # reflected in an old descriptor's metadata.
        for path in tuple(self.nodes):
            self.node(path)
        for path in ("/proc", "/sys", "/sys/kernel", "/sys/fs", "/sys/fs/selinux", "/sys/fs/cgroup"):
            self.node(path, directory=True)
        for path, raw in tuple(self.kernel_raw.items()):
            self.node(path, raw=raw)
        self.node("/sys/fs/selinux/status", st_size=4096)
        for role, pid in self.processes.items():
            pins = self.record["roles"][role]
            prefix = "/proc/" + str(pid)
            for suffix in ("", "/ns", "/attr", "/task", "/task/" + str(pid)):
                self.node(prefix + suffix, directory=True)
            fields = ["S"] + ["0"] * 49
            fields[1], fields[17], fields[19] = "100", "1", str(9000 + pid)
            status = dict(Name="unit", Tgid=str(pid), Pid=str(pid), PPid="100", TracerPid="0",
                Uid="0 0 0 0", Gid="0 0 0 0", Threads="1", NSpid=str(pid), NStgid=str(pid),
                Groups="0 ", Seccomp="2", NoNewPrivs="1", CapInh="0000000000000000", CapPrm="0000000000000001",
                CapEff="0000000000000001", CapBnd="0000000000000001", CapAmb="0000000000000000")
            values = {"stat": (str(pid) + " (unit) " + " ".join(fields) + "\n").encode(),
                "status": "".join(k + ":\t" + v + "\n" for k, v in status.items()).encode(),
                "cgroup": ("0::" + pins["cgroup"]["path"].removeprefix("/sys/fs/cgroup") + "\n").encode(),
                "attr/current": pins["processLabel"].encode() + b"\0", "task/" + str(pid) + "/children": b""}
            for suffix, raw in values.items():
                self.node(prefix + "/" + suffix, raw=raw)
            for name, kind in (("user", 0x10000000), ("mnt", 0x20000), ("pid", 0x20000000), ("net", 0x40000000)):
                path = prefix + "/ns/" + name
                node = self.node(path, st_ino=pins["namespaceInodes"][name], st_dev=server.os.makedev(0, 22),
                    magic=0x6e736673, kind=kind)
                self.links[path] = SimpleNamespace(**{**vars(node), "st_dev": self.nodes[prefix].st_dev,
                                                      "st_ino": 50000 + len(self.links),
                                                      "st_mode": stat.S_IFLNK | 0o777})
            native = pins["interpreterPath"] or pins["executable"]
            self.nodes[prefix + "/exe"] = self.nodes[native]
            self.links[prefix + "/exe"] = SimpleNamespace(**{**vars(self.nodes[prefix]),
                "st_ino": 50000 + len(self.links), "st_mode": stat.S_IFLNK | 0o777, "target": native})
            node = self.nodes[native]
            maps = (f"00001000-00002000 r-xp 00000000 {server.os.major(node.st_dev):02x}:"
                    f"{server.os.minor(node.st_dev):02x} {node.st_ino} {native}\n".encode()
                    + b"00007000-00008000 r-xp 00000000 00:00 0 [vdso]\n")
            argv = [native, pins["executable"]] if pins["interpreterPath"] else [native]
            for name, raw in (("maps", maps), ("auxv", KernelInputCodecTests.auxv(self)),
                              ("cmdline", b"\0".join(x.encode() for x in argv) + b"\0")):
                self.node(prefix + "/" + name, raw=raw)
            self.node("/pidfd/" + str(pid), st_mode=stat.S_IFREG | 0o700)
            group = pins["cgroup"]
            self.node(group["path"], directory=True, st_ino=group["inode"])
            for name, raw in (("memory.max", str(group["memoryMaxBytes"])), ("pids.max", str(group["pidsMax"])),
                    ("cpu.max", str(group["cpuQuotaMicros"]) + " " + str(group["cpuPeriodMicros"])), ("cgroup.procs", str(pid))):
                self.node(group["path"] + "/" + name, st_mode=stat.S_IFREG | 0o644, raw=(raw + "\n").encode())
        # Function doubles intentionally do not accumulate mock-call objects
        # for every retained kernel read. The actual factories/checks still run.
        self.lib = SimpleNamespace(fstatfs=lambda *a: self.statfs(*a), statx=lambda *a: self.statx(*a),
                                  syscall=lambda *a: self.syscall(*a))
        for obj, name, options in (
                (server.sys, "platform", dict(new="linux")), (server.sys, "byteorder", dict(new="little")),
                (server.os, "uname", dict(new=lambda: SimpleNamespace(machine=self.machine,
                    release=self.record["host"]["kernelRelease"], sysname="Linux"))),
                (server.os, "sysconf", dict(new=lambda name: 4096)),
                (server, "utc_now", dict(new=lambda: self.now)),
                (server.time, "monotonic", dict(new=lambda: self.mono)),
                (server.ctypes, "CDLL", dict(new=lambda *a, **kw: self.lib)),
                (server.os, "open", dict(new=self.open)), (server.os, "read", dict(new=self.read)),
                (server.os, "close", dict(new=self.close)), (server.os, "get_inheritable", dict(new=lambda fd: False)),
                (server.os, "fstat", dict(new=lambda fd: self.handles[fd][1])),
                (server.os, "stat", dict(new=self.stat_path)),
                (server.os, "pread", dict(new=self.pread)),
                (server.os, "readlink", dict(new=lambda name, dir_fd: self.links[self.resolve(name, dir_fd)].target)),
                (server.os, "getxattr", dict(new=self.getxattr, create=True)),
                (server.os, "pidfd_open", dict(new=lambda pid, flags: self.open("/pidfd/" + str(pid), 0), create=True)),
                (server.os, "scandir", dict(new=self.scandir)),
                (server.select, "select", dict(new=self.poll)),
                (server.fcntl, "fcntl", dict(new=self.fcntl)),
                (server.fcntl, "ioctl", dict(new=self.ioctl)),
                (server.mmap, "mmap", dict(new=self.mapping)),
                (server.Path, "read_text", dict(new=lambda path, *args, **kwargs: self.kernel_raw[str(path)].decode()))):
            stack.enter_context(patch.object(obj, name, **options))
        self.network = stack.enter_context(patch.object(server.socket, "socket", side_effect=self.socket_factory))
        for name in ("write", "execve", "mkdir", "rmdir"):
            stack.enter_context(patch.object(server.os, name, side_effect=AssertionError("no effects during qualification")))

    def open(self, path, flags, *, dir_fd=None):
        absolute = self.resolve(path, dir_fd)
        self.case.assertIn(absolute, self.nodes)
        if absolute in self.links:
            self.case.assertFalse(flags & server.os.O_NOFOLLOW)
        self.next_fd += 1
        fd = self.next_fd
        self.fds[fd], self.handles[fd], self.positions[fd], self.flags[fd] = absolute, (absolute, self.nodes[absolute]), 0, flags
        self.events.append(("open", absolute))
        self.after("open", absolute)
        return fd

    def stat_path(self, path, *, dir_fd=None, follow_symlinks=True):
        absolute = self.resolve(path, dir_fd)
        source = self.nodes if follow_symlinks or absolute not in self.links else self.links
        if absolute not in source:
            raise FileNotFoundError(absolute)
        return source[absolute]

    def read(self, fd, count):
        path, position = self.fds[fd], self.positions[fd]
        raw = self.kernel_raw[path] if path in self.kernel_raw else self.raw[path]
        result = raw[position:position + count]
        self.positions[fd] += len(result)
        self.read_paths.append(path)
        self.after("read", path)
        return result

    def pread(self, fd, count, offset):
        path = self.fds[fd]
        raw = self.kernel_raw[path] if path in self.kernel_raw else self.raw[path]
        result = raw[offset:offset + count]
        self.after("pread", path)
        return result

    def close(self, fd):
        super().close(fd)
        del self.handles[fd]

    def statfs(self, fd, pointer):
        node, output = self.handles[fd.value][1], pointer._obj
        self.case.assertEqual(bytes(output), b"\0" * 120)
        output.kind, output.block_size, output.name_length, output.flags = node.magic, 4096, 255, 1
        output.fsid[:] = (node.magic & 0x7fffffff, 1)
        return 0

    def statx(self, fd, path, flags, mask, pointer):
        node = self.stat_path(path.decode(), dir_fd=fd, follow_symlinks=False) if path else self.handles[fd][1]
        self.case.assertEqual((flags, mask), (0x900 if path else 0x1900, 0x411b))
        self.case.assertEqual(bytes(pointer._obj), b"\0" * 256)
        raw = bytearray(256)
        server.struct.pack_into("<I", raw, 0, 0x47ff)
        server.struct.pack_into("<IIH", raw, 20, node.st_uid, node.st_gid, node.st_mode)
        server.struct.pack_into("<Q", raw, 32, node.st_ino)
        server.struct.pack_into("<IIQ", raw, 136, server.os.major(node.st_dev), server.os.minor(node.st_dev), node.mountId)
        pointer._obj.words[:] = server.struct.unpack("<32Q", raw)
        return 0

    def fcntl(self, fd, command):
        self.case.assertEqual(command, server.fcntl.F_GETFL)
        return server.os.O_RDWR if self.fds[fd].startswith("bpf:") else server.os.O_RDONLY

    def ioctl(self, fd, command, *args):
        path = self.fds[fd]
        if command == 0xb703:
            self.case.assertEqual(args, (0,))
            return self.handles[fd][1].kind
        self.case.assertEqual(command, 0xc0046686)
        output, mutate = args
        self.case.assertTrue(mutate)
        self.case.assertEqual(output, server.struct.pack("<HH", 0, 32) + b"\0" * 32)
        output[:] = server.struct.pack("<HH", 1, 32) + bytes.fromhex(self.code_pins[path]["verityDigest"][7:])
        self.after("verity", path)
        return 0

    def getxattr(self, fd, name):
        self.case.assertEqual(name, "security.selinux")
        return self.code_pins[self.fds[fd]]["selinuxLabel"].encode() + b"\0"

    def mapping(self, fd, length, *, flags, prot):
        self.case.assertEqual(self.fds[fd], "/sys/fs/selinux/status")
        self.case.assertEqual((length, flags, prot), (4096, server.mmap.MAP_SHARED, server.mmap.PROT_READ))
        fixture = self
        class Mapping:
            closes = 0
            def __getitem__(self, item):
                result = fixture.raw_status[item]
                fixture.after("epoch", "/sys/fs/selinux/status")
                return result
            def close(self):
                self.closes += 1
                fixture.case.assertEqual(self.closes, 1)
        result = Mapping()
        self.maps.append(result)
        return result

    def syscall(self, number, command, *args):
        if number.value in (324, 283):
            self.case.assertEqual(number.value, 324 if self.machine == "x86_64" else 283)
            self.case.assertEqual(tuple(arg.value for arg in args), (0, 0))
            self.case.assertIn(command.value, (0, 16, 8))
            return 24 if command.value == 0 else 0
        self.case.assertEqual(number.value, 321 if self.machine == "x86_64" else 280)
        pointer, size = args
        self.case.assertEqual(size.value, 64)
        attr, operation = pointer._obj, command.value
        raw = bytes(attr)
        if operation == 16:
            target, hook, effective, flags, address, count = server.struct.unpack_from("<4IQI", raw)
            self.case.assertEqual((flags, count, raw[28:]), (0, 16, b"\0" * 36))
            self.case.assertIn(effective, (0, 1))
            program = next(pid for pid, (path, h, _, _) in self.programs.items() if path == self.fds[target] and h == hook)
            output = (server.ctypes.c_uint32 * 16).from_address(address)
            output[0] = program
            server.struct.pack_into("<I", attr, 24, 1)
            result = 0
        elif operation == 13:
            program = server.struct.unpack_from("<I", raw)[0]
            self.case.assertIn(program, self.programs)
            self.case.assertEqual(raw[4:], b"\0" * 60)
            path = "bpf:" + str(program)
            self.nodes[path] = SimpleNamespace(st_dev=99, st_ino=22, st_mode=0o600, st_uid=0, st_gid=0,
                st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
            # BPF returns an anonymous FD, not a filesystem open.
            self.next_fd += 1
            result = self.next_fd
            self.fds[result], self.handles[result] = path, (path, self.nodes[path])
        elif operation == 15:
            fd, length, address = server.struct.unpack_from("<IIQ", raw)
            self.case.assertEqual((length, raw[16:]), (240, b"\0" * 48))
            program = int(self.fds[fd].split(":")[1])
            _, _, kind, code = self.programs[program]
            info = (server.ctypes.c_ubyte * 240).from_address(address)
            output = server.struct.unpack_from("<Q", info, 32)[0]
            if output:
                (server.ctypes.c_ubyte * 65536).from_address(output)[:len(code)] = code
            server.struct.pack_into("<II", info, 0, kind, program)
            server.struct.pack_into("<I", info, 20, len(code))
            server.struct.pack_into("<Q", info, 40, 76543)
            for offset, value in ((84, 1), (104, 1), (108, 1), (132, 8), (172, 16), (176, 8)):
                server.struct.pack_into("<I", info, offset, value)
            server.struct.pack_into("<I", attr, 4, 232)
            result = 0
        else:
            raise AssertionError("no BPF mutation or execution")
        self.after("bpf", str(operation))
        return result

    def scandir(self, fd):
        prefix = self.fds[fd]
        entries = [SimpleNamespace(name=path.rsplit("/", 1)[1]) for path in self.nodes
                   if path.rsplit("/", 1)[0] == prefix]
        class Scan:
            def __enter__(self):
                return iter(entries)
            def __exit__(self, *args):
                return False
        return Scan()

    def poll(self, reads, writes, errors, timeout):
        self.case.assertEqual((writes, timeout), ([], 0))
        self.case.assertEqual(reads, errors)
        return [], [], []

    def socket_factory(self, family, kind):
        self.case.assertEqual((family, kind), (server.socket.AF_UNIX, server.socket.SOCK_SEQPACKET))
        fixture = self
        class Channel:
            def __init__(self):
                self.fd, fixture.next_fd = fixture.next_fd + 1, fixture.next_fd + 1
                node = SimpleNamespace(st_dev=99, st_ino=self.fd, st_mode=stat.S_IFSOCK | 0o600,
                    st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
                fixture.fds[self.fd], fixture.handles[self.fd] = "socket:", ("socket:", node)
                self.path = None
            def fileno(self):
                return self.fd
            def set_inheritable(self, value):
                fixture.case.assertIs(value, False)
            def setsockopt(self, *args):
                fixture.case.assertEqual(args, (server.socket.SOL_SOCKET, 16, 1))
            def settimeout(self, value):
                fixture.case.assertTrue(0 < value <= 2)
            def connect(self, path):
                fixture.case.assertIn(path, (server.OBSERVER_SOCKET, server.BROKER_SOCKET))
                self.path = path
            def getsockopt(self, *args):
                fixture.case.assertEqual(args, (server.socket.SOL_SOCKET, server.socket.SO_PEERCRED, 12))
                role = "OBSERVER" if self.path == server.OBSERVER_SOCKET else "BROKER"
                return server.struct.pack("3i", fixture.processes[role], 0, 0)
            def close(self):
                fixture.close(self.fd)
            def detach(self):
                return self.fd
            def send(self, raw):
                raise AssertionError("qualification sends no datagram or DISPATCH")
        return Channel()

    def peer(self, role):
        owner = self.owner
        kind, path, attr = ((server._Observer, server.OBSERVER_SOCKET, "observer") if role == "OBSERVER"
                           else (server._Broker, server.BROKER_SOCKET, "broker"))
        self.node(path.rsplit("/", 1)[0], directory=True, st_mode=stat.S_IFDIR | 0o700)
        self.node(path, st_mode=stat.S_IFSOCK | 0o600)
        peer = object.__new__(kind)
        setattr(owner, attr, peer)
        if role == "BROKER":
            owner._broker_original = peer
        kind.__init__(peer, owner)
        return peer


class _NativeServerKernelOS(_QualificationKernelOS):
    """Full constructor and case driver against one synthetic OS, not Linux QA.

    Only OS/SSL library primitives and inert peer wire bytes are doubled. No
    server, qualifier, observer, broker, journal, admission, receipt or cleanup
    method is replaced or manually initialized. No usable key, TLS session,
    worker, native binary, installed launcher or real network is involved.
    """
    journal_path = server.STATE + "/reservations.jsonl"

    def __init__(self, case):
        import base64
        from test_proxy_client import identity_data
        super().__init__(case)
        case.assertEqual(byte_digest(_FULL_FACTORY_PACKET_006), self.fixture.envelope["packetDigest"])
        self.raw[self.fixture.envelope["packetFileReference"]] = _FULL_FACTORY_PACKET_006
        self.raw[self.fixture.envelope["campaignDefinitionFileReference"]] = canonical_bytes(
            json.loads((ROOT / "campaigns/platform/linux-baseline/campaign.json").read_bytes()))
        self.raw[self.fixture.envelope["bundleFileReference"]] = b"UNIT_ONLY_NOT_REAL_bundle"
        leaf, _, endpoint = identity_data(False)
        # Equal-length replacements keep the DER codec data structurally valid;
        # the unsigned bytes and empty key remain unusable by a real TLS engine.
        self.server_leaf = leaf.replace(b"260908000000Z", b"260907010000Z").replace(
            b"260908001000Z", b"260907011000Z").replace(b"proxy.unit", b"unit.proxy")
        self.raw[server.IDENTITY] = (b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(self.server_leaf)
            + b"\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n")
        self.modes[server.IDENTITY] = 0o400
        self.fixture.envelope["endpoints"][0]["tls"]["serverSpkiDigest"] = endpoint["tls"]["serverSpkiDigest"]
        self.release()
        self.channels, self.listeners, self.tls_contexts = [], [], []
        self.memfds, self.seals = [], {}
        self.broker_incoming, self.broker_outgoing, self.observations = [], [], []
        self.receipt_raw = self.wire_last = None
        self.durable_journal, self.random_count = b"", 0
        self.driver_fault = None
        self.on_io = lambda operation, path, value: None

    def context(self, stack):
        # These two helpers register only OS data. In particular they do not
        # create the object.__new__ owner used by the separate binding tests.
        self.filesystem_context(stack)
        self.kernel_context(stack)
        for path in (server.OBSERVER_SOCKET, server.BROKER_SOCKET):
            self.node(path.rsplit("/", 1)[0], directory=True, st_mode=stat.S_IFDIR | 0o700)
            self.node(path, st_mode=stat.S_IFSOCK | 0o600)
        self.node(server.STATE, directory=True, st_mode=stat.S_IFDIR | 0o700)
        for path in (server.STATE + "/admission.lock", self.journal_path):
            self.node(path, st_mode=stat.S_IFREG | 0o600, raw=b"")
        for fd in range(3):
            path = "stdio:" + str(fd)
            node = SimpleNamespace(st_dev=99, st_ino=fd + 1, st_mode=stat.S_IFCHR | 0o600,
                st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
            self.fds[fd], self.handles[fd] = path, (path, node)
        self.kernel_raw["/proc/self/task/" + str(self.processes["SERVER"]) + "/children"] = b""
        for obj, name, options in (
                (server, "_ACTIVE", dict(new=None)),
                (server, "__loader__", dict(new=SimpleNamespace(archive=server.EXECUTABLE))),
                (server.sys, "argv", dict(new=[server.EXECUTABLE])),
                (server.os, "geteuid", dict(new=lambda: 0)), (server.os, "getegid", dict(new=lambda: 0)),
                (server.os, "listdir", dict(new=self.listdir)),
                (server.os, "urandom", dict(new=self.urandom)),
                (server.os, "write", dict(new=self.write)),
                (server.os, "fsync", dict(new=self.fsync)),
                (server.os, "memfd_create", dict(new=self.memfd_create, create=True)),
                (server.os, "MFD_CLOEXEC", dict(new=1, create=True)),
                (server.os, "MFD_ALLOW_SEALING", dict(new=2, create=True)),
                (server.fcntl, "flock", dict(new=self.flock)),
                (_client_module.ssl, "SSLContext", dict(new=self.ssl_context))):
            stack.enter_context(patch.object(obj, name, **options))
        for name, value in (("F_ADD_SEALS", 1033), ("F_GET_SEALS", 1034),
                ("F_SEAL_SEAL", 1), ("F_SEAL_SHRINK", 2), ("F_SEAL_GROW", 4), ("F_SEAL_WRITE", 8)):
            stack.enter_context(patch.object(server.fcntl, name, value, create=True))
        stack.enter_context(patch.dict(server.os.environ,
            {"HARNESS_LIVE_EXECUTION_ENVELOPE": "/unit-only/envelope.json"}, clear=True))

    def start(self, stack):
        self.context(stack)
        owner = server.NativeProxyServer()
        self.owner = owner  # record the returned owner, never supply one
        stack.callback(owner.close)
        return owner

    def listdir(self, path):
        if path == "/proc/self/task":
            return [str(self.processes["SERVER"])]
        if path == "/proc/self/fd":
            return [str(fd) for fd in self.handles]
        prefix = self.fds[path] if type(path) is int else path
        return sorted(p.rsplit("/", 1)[1] for p in self.nodes
                      if p != "/" and p.rsplit("/", 1)[0] == prefix)

    def urandom(self, count):
        self.case.assertEqual(count, 32)
        self.random_count += 1
        return self.random_count.to_bytes(32, "big")

    def write(self, fd, raw):
        path = self.fds[fd]
        self.case.assertTrue(path == self.journal_path or fd in self.memfds)
        self.kernel_raw[path] += raw
        self.nodes[path].st_size = len(self.kernel_raw[path])
        self.events.append(("write", path))
        self.on_io("write", path, raw)
        return len(raw)

    def fsync(self, fd):
        path = self.fds[fd]
        self.case.assertIn(path, (server.STATE, self.journal_path))
        self.events.append(("fsync", path))
        if path == server.STATE:
            self.durable_journal = self.kernel_raw[self.journal_path]
        self.on_io("fsync", path, None)

    def flock(self, fd, flags):
        self.case.assertIn(self.fds[fd], (server.STATE + "/admission.lock", self.journal_path))
        self.case.assertIn(flags, (server.fcntl.LOCK_EX | server.fcntl.LOCK_NB, server.fcntl.LOCK_UN))
        self.on_io("flock", self.fds[fd], flags)

    def memfd_create(self, name, flags):
        self.case.assertEqual((name, flags), ("planeon-proxy-identity", 3))
        path = "/memfd/unit-" + str(len(self.memfds))
        self.nodes[path] = SimpleNamespace(st_dev=99, st_ino=80000 + len(self.memfds),
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=0,
            st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        self.kernel_raw[path] = b""
        fd = self.open(path, server.os.O_RDWR)
        self.memfds.append(fd)
        self.seals[fd] = 0
        return fd

    def fcntl(self, fd, command, *args):
        if fd in self.memfds:
            if command == server.fcntl.F_ADD_SEALS:
                self.case.assertEqual(args, (15,))
                self.seals[fd] = args[0]
                return 0
            self.case.assertEqual((command, args), (server.fcntl.F_GET_SEALS, ()))
            return self.seals[fd]
        self.case.assertEqual(args, ())
        return super().fcntl(fd, command)

    def ssl_context(self, protocol):
        fixture = self
        self.case.assertEqual(protocol, _client_module.ssl.PROTOCOL_TLS_SERVER)
        class Context:
            options = verify_flags = 0
            def set_alpn_protocols(self, names):
                fixture.case.assertEqual(names, ["http/1.1"])
            def load_verify_locations(self, *, cadata):
                fixture.case.assertEqual(cadata.encode(), fixture.raw["/unit-only/kit/ca.pem"])
            def load_cert_chain(self, path, *, password):
                fd = int(path.rsplit("/", 1)[1])
                fixture.case.assertIs(password, _client_module._no_password)
                fixture.case.assertEqual(fixture.seals[fd], 15)
                fixture.case.assertEqual(fixture.kernel_raw[fixture.fds[fd]], fixture.raw[server.IDENTITY])
            def wrap_bio(self, *args, **kwargs):
                raise AssertionError("full HTTP/SSL transport extension is not supplied by this fixture")
        context = Context()
        self.tls_contexts.append(context)
        return context

    def socket_factory(self, family, kind):
        fixture = self
        if family == server.socket.AF_UNIX:
            channel = super().socket_factory(family, kind)
            self.channels.append(channel)
            def send(raw):
                if channel.path == server.OBSERVER_SOCKET:
                    request = json.loads(raw)
                    response = deepcopy(VECTORS["observation"]["positive"]["observation"])
                    for key in ("bindingDigest", "runNonce", "challenge", "sequence", "previousObservationDigest"):
                        response[key] = request[key]
                    response.update(observedAt=self.now, expiresAt="2026-09-07T01:00:05Z")
                    response["projections"] = {name: {**value, "resourceVersion": "100"}
                                               for name, value in self.observation["projections"].items()}
                    response["enforcement"].update(self.observation["enforcementPins"])
                    channel.incoming.append(canonical_bytes(response))
                    self.observations.append(request)
                else:
                    self.broker_send(raw)
                self.on_io("send", channel.path, raw)
                return len(raw)
            def receive(*args):
                expected = (65537, server.socket.CMSG_SPACE(12) + server.socket.CMSG_SPACE(253 * 4))
                self.case.assertEqual(args, expected)
                role = "OBSERVER" if channel.path == server.OBSERVER_SOCKET else "BROKER"
                raw = (channel.incoming if role == "OBSERVER" else self.broker_incoming).pop(0)
                self.on_io("recvmsg", channel.path, raw)
                return raw, [(server.socket.SOL_SOCKET, 2,
                    server.struct.pack("3i", self.processes[role], 0, 0))], 0, None
            channel.incoming, channel.send, channel.recvmsg = [], send, receive
            return channel
        self.case.assertEqual((family, kind), (server.socket.AF_INET, server.socket.SOCK_STREAM))
        class Listener:
            closed = False
            def set_inheritable(self, value):
                fixture.case.assertIs(value, False)
            def bind(self, target):
                endpoint = fixture.fixture.envelope["endpoints"][0]
                fixture.case.assertEqual(target, (endpoint["ipAddress"], endpoint["port"]))
                self.target = target
            def listen(self, backlog):
                fixture.case.assertEqual(backlog, 1)
            def getsockname(self):
                return self.target
            def close(self):
                fixture.case.assertFalse(self.closed)
                self.closed = True
        listener = Listener()
        self.listeners.append(listener)
        return listener

    def poll(self, reads, writes, errors, timeout):
        if reads and reads[0] in self.channels:
            self.case.assertEqual((writes, errors), ([], reads))
            self.case.assertEqual(reads[0].path, server.BROKER_SOCKET)
            self.case.assertTrue(0 <= timeout <= 2)
            if not self.broker_incoming:
                self.mono += timeout
            return (reads if self.broker_incoming else []), [], []
        return super().poll(reads, writes, errors, timeout)

    def enqueue(self, kind, payload):
        frame = {**deepcopy(self.wire_last), "kind": kind, "payload": payload,
            "sequence": self.wire_last["sequence"] + 1,
            "previousDigest": byte_digest(canonical_bytes(self.wire_last))}
        self.broker_incoming.append(canonical_bytes(frame))
        self.wire_last = frame

    def broker_send(self, raw):
        import base64
        frame = json.loads(raw)
        self.broker_outgoing.append(frame)
        self.case.assertEqual(self.durable_journal, self.kernel_raw[self.journal_path])
        state = json.loads(self.durable_journal.splitlines()[-1])["state"]
        if frame.get("operation") == "EXECUTE_FIXED_PROBE":
            self.case.assertEqual(state, "RUNNING")
            self.wire_last = {**{key: frame[key] for key in admission.BROKER_COMMON},
                "schemaVersion": "planeon.internal.broker-frame/v1", "executionId": "c" * 64,
                "sequence": 1, "previousDigest": admission.ZERO, "kind": "STARTED",
                "payload": {"workerPid": 9600, "workerStartTicks": 5000}}
            self.broker_incoming.append(canonical_bytes(self.wire_last))
            if self.driver_fault == "zero-resource-action":
                self.enqueue("RESOURCE_ACTION", {"actionId": 1, "verb": "CREATE", "manifestDigest": admission.ZERO})
            else:
                for index, chunk in enumerate((self.receipt_raw[:90], self.receipt_raw[90:])):
                    self.enqueue("RECEIPT_CHUNK", {"index": index, "dataBase64": base64.b64encode(chunk).decode()})
        else:
            self.case.assertEqual((frame["kind"], state), ("CLEANUP_RECORDED", "CLEANUP_SEALED"))
            self.wire_last = frame
            if self.driver_fault == "lost-terminal":
                self.broker_incoming.append(b"")
            else:
                self.enqueue("TERMINAL", {"status": "COMPLETED", "receiptSize": len(self.receipt_raw),
                    "receiptDigest": byte_digest(self.receipt_raw), "cleanupDigest": frame["payload"]["cleanupDigest"],
                    "workerReaped": True})

    def prepare_case(self, owner):
        from harness_conformance.linux_readiness import CASE_CHECKS
        operation = server.CASES[0]
        request = server.build_probe_request(owner.envelope, owner.capacity, owner.plan, operation)
        output = {"checks": {key: "PASS" for key in CASE_CHECKS[operation]}, "regressions": {}}
        self.receipt_raw = canonical_bytes({"caseId": operation, "status": "PASS", "observedAt": self.now,
            "runNonce": request["runNonce"], "probeDigest": request["probeDigest"], "commandDigest": request["commandDigest"],
            "outputDigest": server.canonical_digest(output, "planeon.linux-probe-output/v1alpha1"), "output": output})
        owner.log.record(owner.reservation, "RUNNING", operation, self.now)
        owner.active_operation = operation


class _NativeServerHTTPOS(_NativeServerKernelOS):
    """Full serve() fixture: real factories/MemoryBIO owner, inert SSL codec.

    H/D/C below are deliberately non-TLS library-double records. Certificate
    bytes are unsigned DER and keys are empty ASN.1 values; no TLS, Kubernetes,
    broker enforcement or native qualification is claimed by these tests.
    """
    def __init__(self, case, resources=False):
        super().__init__(case)
        self.resource_mode = resources
        self.accepted, self.api_streams, self.codecs, self.responses = [], [], [], []
        self.api_requests, self.receipts, self.requests = [], {}, []
        self.tls_fault = self.http_fault = self.api_fault = None
        self.on_stream = lambda operation, stream, value: None
        self.api_path = "/etc/planeon/live-proxy/unit-api.pem"
        self.status = "PASS"
        scope = self.profile["binding"]
        self.client_leaf, spki = self.leaf("campaign-proxy", scope["endpointId"])
        self.profile["capacityEntries"]["credentialIdentities"][0].update(
            certificateDigest=byte_digest(self.client_leaf), clientSpkiDigest=byte_digest(spki))
        if resources:
            template = sample(1)["profile"]
            scope["apiEndpointId"] = template["binding"]["apiEndpointId"]
            for key in ("kubernetesApiRules", "permittedGvksAndVerbs"):
                self.profile["capacityEntries"][key] = deepcopy(template["capacityEntries"][key])
            self.profile["quota"] = deepcopy(template["quota"])
            self.profile["resources"] = deepcopy(template["resources"])
            row = self.profile["resources"][0]
            row["manifest"]["metadata"]["labels"].update({
                "planeon.ai/run-nonce": scope["runNonce"], "planeon.ai/tenant-id": scope["tenantId"]})
            row["manifestDigest"] = byte_digest(canonical_bytes(row["manifest"]))
            self.resource = row
            self.created = deepcopy(row["manifest"])
            self.created["metadata"].update(uid="unit-owned-uid", resourceVersion="100")
            self.present = deepcopy(self.created)
            self.present["metadata"]["resourceVersion"] = "101"
            api_leaf, api_spki = self.leaf("capacity-proxy", scope["apiEndpointId"])
            self.raw[self.api_path], self.modes[self.api_path] = self.pem(api_leaf), 0o400
            identity = deepcopy(template["capacityEntries"]["credentialIdentities"][1])
            identity.update(expiresAt=scope["expiresAt"], certificateDigest=byte_digest(api_leaf),
                            clientSpkiDigest=byte_digest(api_spki))
            self.profile["capacityEntries"]["credentialIdentities"].append(identity)
            endpoint = deepcopy(self.fixture.envelope["endpoints"][0])
            endpoint.update(endpointId=scope["apiEndpointId"], kind="KUBERNETES_API_PROXY",
                ipAddress="127.0.0.2", port=9444, credentialFileReference=self.api_path)
            endpoint["authorizationPolicyDigest"] = byte_digest(
                canonical_bytes(self.profile["capacityEntries"]["kubernetesApiRules"]))
            self.fixture.envelope["endpoints"].append(endpoint)
            self.record["roles"]["SERVER"]["outboundEndpointIds"] = [endpoint["endpointId"]]
            self.broker["caseResourceDigests"][server.CASES[0]] = [row["manifestDigest"]]
        self.rebind()

    def leaf(self, prefix, endpoint_id):
        from test_proxy_client import der
        scope = self.profile["binding"]
        san = ("urn:planeon:" + prefix + ":" + ":".join(scope[key] for key in
               ("tenantId", "environmentId", "runNonce")) + ":" + endpoint_id).encode()
        extension = lambda oid, value: der(0x30, der(6, bytes.fromhex(oid)) + der(4, value))
        extensions = der(0xa3, der(0x30, extension("551d13", der(0x30, b""))
            + extension("551d25", der(0x30, der(6, bytes.fromhex("2b06010505070302"))))
            + extension("551d11", der(0x30, der(0x86, san)))))
        spki = der(0x30, der(0x30, b"") + der(3, b"\0unit-" + prefix.encode() + b"-not-a-key"))
        algorithm = der(0x30, der(6, b"\x2b\x65\x70"))
        tbs = der(0x30, b"\xa0\x03\x02\x01\x02" + der(2, b"\x01") + algorithm + der(0x30, b"")
            + der(0x30, der(0x17, b"260907010000Z") + der(0x17, b"260907011000Z"))
            + der(0x30, b"") + spki + extensions)
        return der(0x30, tbs + algorithm + der(3, b"\0unsigned-unit-data")), spki

    @staticmethod
    def pem(leaf):
        import base64
        return (b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(leaf)
            + b"\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n")

    def rebind(self):
        """Re-sign input DATA before construction; never alter an active owner."""
        self.fixture.capacity.update(deepcopy(self.profile["capacityEntries"]))
        self.fixture.capacity["permittedEndpointIds"] = [row["endpointId"] for row in self.fixture.envelope["endpoints"]]
        self.fixture.release["endpointPolicyDigests"] = sorted({row["authorizationPolicyDigest"]
            for row in self.fixture.envelope["endpoints"]})
        digest = byte_digest(canonical_bytes(self.profile))
        self.record["profileDigest"] = self.observation["profileDigest"] = self.broker["profileDigest"] = digest
        self.record["endpointTuples"] = [{**{key: endpoint[key] for key in
            ("endpointId", "kind", "ipAddress", "port")},
            "addressFamily": "IPV6" if ":" in endpoint["ipAddress"] else "IPV4"}
            for endpoint in self.fixture.envelope["endpoints"]]
        preflight = byte_digest(canonical_bytes(self.record))
        for _, path, _ in self.paths:
            value = json.loads(self.raw[path])
            value["preflightEvidenceDigest"] = preflight
            self.manifest(path, value)
        self.observation["observer"]["manifestDigest"] = byte_digest(self.raw[server.OBSERVER_MANIFEST])
        self.observation["enforcementPins"]["hostPreflightDigest"] = preflight
        self.broker.update(observationBindingDigest=byte_digest(canonical_bytes(self.observation)),
            brokerManifestDigest=byte_digest(self.raw[server.BROKER_MANIFEST]),
            workerManifestDigest=byte_digest(self.raw[server.WORKER_MANIFEST]))
        for path, value in ((admission.PROFILE_PATH, self.profile), (admission.QUALIFICATION_PATH, self.record),
                (admission.OBSERVATION_PATH, self.observation), (admission.BROKER_BINDING_PATH, self.broker)):
            self.raw["/unit-only/kit/" + path] = canonical_bytes(value)
        self.release()

    def context(self, stack):
        super().context(stack)
        stack.enter_context(patch.object(server.os, "lseek", self.lseek))

    def lseek(self, fd, offset, whence):
        self.case.assertIn(fd, self.memfds)
        self.case.assertEqual((offset, whence), (0, server.os.SEEK_SET))
        self.positions[fd] = 0
        return 0

    def memfd_create(self, name, flags):
        self.case.assertIn(name, ("planeon-proxy-identity", "planeon-api-identity"))
        fd = super().memfd_create("planeon-proxy-identity", flags)
        self.events.append(("memfd", name))
        return fd

    def ssl_context(self, protocol):
        fixture = self
        is_server = protocol == _client_module.ssl.PROTOCOL_TLS_SERVER
        self.case.assertIn(protocol, (_client_module.ssl.PROTOCOL_TLS_SERVER, _client_module.ssl.PROTOCOL_TLS_CLIENT))
        class Context:
            options = verify_flags = 0
            def set_alpn_protocols(self, names):
                fixture.case.assertEqual(names, ["http/1.1"])
            def load_verify_locations(self, *, cadata):
                fixture.case.assertEqual(cadata.encode(), fixture.raw["/unit-only/kit/ca.pem"])
            def load_cert_chain(self, path, *, password):
                fd = int(path.rsplit("/", 1)[1])
                fixture.case.assertIs(password, _client_module._no_password)
                fixture.case.assertEqual(fixture.seals[fd], 15)
                fixture.case.assertEqual(fixture.kernel_raw[fixture.fds[fd]],
                    fixture.raw[server.IDENTITY if is_server else fixture.api_path])
            def wrap_bio(self, incoming, outgoing, *, server_side, server_hostname):
                fixture.case.assertEqual((server_side, server_hostname),
                    (is_server, None if is_server else fixture.fixture.envelope["endpoints"][1]["tls"]["serverName"]))
                # Exercise the real MemoryBIO objects and _TLS pumping logic;
                # only OpenSSL's byte codec is a deliberately inert substitute.
                fixture.case.assertIs(type(incoming), _client_module.ssl.MemoryBIO)
                class Codec:
                    plain = b""
                    hello_sent = False
                    session_reused = False
                    def do_handshake(self):
                        if not self.hello_sent:
                            outgoing.write(b"H")
                            self.hello_sent = True
                        if not incoming.pending:
                            raise _client_module.ssl.SSLWantReadError()
                        fixture.case.assertEqual(incoming.read(), b"H")
                    def version(self):
                        return "TLSv1.2" if fixture.tls_fault == "version" else "TLSv1.3"
                    def selected_alpn_protocol(self):
                        return "h2" if fixture.tls_fault == "alpn" else "http/1.1"
                    def getpeercert(self, *, binary_form):
                        fixture.case.assertIs(binary_form, True)
                        if fixture.tls_fault == "identity":
                            return fixture.server_leaf if is_server else fixture.client_leaf
                        return fixture.client_leaf if is_server else fixture.server_leaf
                    def write(self, raw):
                        outgoing.write(b"D" + len(raw).to_bytes(4, "big") + raw)
                        return len(raw)
                    def read(self, maximum):
                        if not self.plain:
                            if not incoming.pending:
                                raise _client_module.ssl.SSLWantReadError()
                            kind = incoming.read(1)
                            if kind == b"C":
                                return b""
                            fixture.case.assertEqual(kind, b"D")
                            size = int.from_bytes(incoming.read(4), "big")
                            self.plain = incoming.read(size)
                            fixture.case.assertEqual(len(self.plain), size)
                        raw, self.plain = self.plain[:maximum], self.plain[maximum:]
                        return raw
                    def pending(self):
                        return len(self.plain)
                    def unwrap(self):
                        outgoing.write(b"C")
                        raise _client_module.ssl.SSLWantReadError()
                codec = Codec()
                fixture.codecs.append(codec)
                return codec
        context = Context()
        self.tls_contexts.append(context)
        return context

    def socket_factory(self, family, kind):
        if family == server.socket.AF_UNIX:
            return super().socket_factory(family, kind)
        self.case.assertEqual((family, kind), (server.socket.AF_INET, server.socket.SOCK_STREAM))
        fixture = self
        class Stream:
            def __init__(self):
                fixture.next_fd += 1
                self.fd, self.closed, self.incoming, self.sent = fixture.next_fd, False, [b"H"], []
                node = SimpleNamespace(st_dev=99, st_ino=self.fd, st_mode=stat.S_IFSOCK | 0o600,
                    st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
                fixture.fds[self.fd], fixture.handles[self.fd] = "tcp:", ("tcp:", node)
                self.mode, self.target = None, None
            def fileno(self):
                return self.fd
            def set_inheritable(self, value):
                fixture.case.assertIs(value, False)
            def settimeout(self, value):
                fixture.case.assertTrue(0 < value <= 2)
            def bind(self, target):
                endpoint = fixture.fixture.envelope["endpoints"][0]
                fixture.case.assertEqual(target, (endpoint["ipAddress"], endpoint["port"]))
                self.mode, self.target = "listener", target
                fixture.listeners.append(self)
            def listen(self, backlog):
                fixture.case.assertEqual(backlog, 1)
            def getsockname(self):
                return self.target
            def accept(self):
                fixture.case.assertEqual(self.mode, "listener")
                fixture.case.assertTrue(fixture.requests, "serve attempted an undeclared extra request")
                stream = Stream()
                stream.mode = "campaign"
                raw = fixture.requests.pop(0)
                stream.incoming.append(b"D" + len(raw).to_bytes(4, "big") + raw)
                fixture.accepted.append(stream)
                fixture.on_stream("accept", stream, None)
                return stream, ("127.0.0.3", 9000)
            def connect(self, target):
                endpoint = fixture.fixture.envelope["endpoints"][1]
                fixture.case.assertEqual(target, (endpoint["ipAddress"], endpoint["port"]))
                self.mode, self.target = "api", target
                fixture.api_streams.append(self)
                fixture.on_stream("connect", self, target)
            def getpeername(self):
                return self.target
            def recv(self, maximum):
                fixture.case.assertEqual(maximum, 65536)
                fixture.case.assertTrue(self.incoming, "unexpected receive without peer bytes")
                raw = self.incoming.pop(0)
                fixture.on_stream("recv", self, raw)
                return raw
            def send(self, raw):
                self.sent.append(raw)
                if raw[:1] == b"D":
                    body = raw[5:]
                    fixture.case.assertEqual(len(body), int.from_bytes(raw[1:5], "big"))
                    if self.mode == "api":
                        reply = fixture.api_reply(body)
                        self.incoming += [b"D" + len(reply).to_bytes(4, "big") + reply, b"C"]
                    else:
                        fixture.case.assertEqual(self.mode, "campaign")
                        fixture.responses.append(body)
                        rows = fixture.durable_journal.splitlines()
                        fixture.case.assertEqual(json.loads(rows[-1])["state"], "TERMINAL_RECORDED")
                else:
                    fixture.case.assertIn(raw, (b"H", b"C"))
                fixture.on_stream("send", self, raw)
                return len(raw)
            def close(self):
                fixture.case.assertFalse(self.closed)
                self.closed = True
                fixture.close(self.fd)
                fixture.on_stream("close", self, None)
            def detach(self):
                return self.fd
        return Stream()

    def prepare_http(self, operations=None):
        from harness_conformance.linux_readiness import CASE_CHECKS
        operations = list(server.CASES if operations is None else operations)
        for operation in operations:
            request = server.build_probe_request(self.fixture.envelope, self.fixture.capacity, self.fixture.plan, operation)
            output = {"checks": {key: self.status for key in CASE_CHECKS[operation]}, "regressions": {}}
            if operation == "FULL_PREDECESSOR_REGRESSION":
                output["regressions"] = {name: {"inventoryDigest": row["inventoryDigest"],
                    "collected": row["testCount"], "executed": row["testCount"], "skipped": 0, "failed": 0}
                    for name, row in self.fixture.plan["regressions"].items()}
            receipt = {"caseId": operation, "status": self.status, "observedAt": self.now,
                "runNonce": request["runNonce"], "probeDigest": request["probeDigest"],
                "commandDigest": request["commandDigest"],
                "outputDigest": server.canonical_digest(output, "planeon.linux-probe-output/v1alpha1"), "output": output}
            self.receipts[operation] = canonical_bytes(receipt)
            if self.http_fault == "nonce":
                request["runNonce"] = "foreign-run"
            raw = server.http_message("POST " + request["path"] + " HTTP/1.1", canonical_bytes(request),
                                      self.fixture.envelope["endpoints"][0]["tls"]["serverName"])
            if self.http_fault == "host":
                raw = raw.replace(b"Host: unit.proxy", b"Host: evil.proxy")
            if self.http_fault == "surplus":
                raw += b"unexpected"
            self.requests.append(raw)

    def enqueue_receipt(self):
        import base64
        for index, chunk in enumerate((self.receipt_raw[:90], self.receipt_raw[90:])):
            self.enqueue("RECEIPT_CHUNK", {"index": index, "dataBase64": base64.b64encode(chunk).decode()})

    def broker_send(self, raw):
        frame = json.loads(raw)
        self.broker_outgoing.append(frame)
        self.case.assertEqual(self.durable_journal, self.kernel_raw[self.journal_path])
        state = json.loads(self.durable_journal.splitlines()[-1])["state"]
        if frame.get("operation") == "EXECUTE_FIXED_PROBE":
            self.case.assertEqual(state, "RUNNING")
            self.receipt_raw = self.receipts[frame["caseId"]]
            self.wire_last = {**{key: frame[key] for key in admission.BROKER_COMMON},
                "schemaVersion": "planeon.internal.broker-frame/v1", "executionId": frame["challenge"],
                "sequence": 1, "previousDigest": admission.ZERO, "kind": "STARTED",
                "payload": {"workerPid": 9600, "workerStartTicks": 5000}}
            self.broker_incoming.append(canonical_bytes(self.wire_last))
            if self.resource_mode and frame["caseId"] == server.CASES[0]:
                self.enqueue("RESOURCE_ACTION", {"actionId": 1, "verb": "CREATE",
                    "manifestDigest": self.resource["manifestDigest"]})
            elif self.driver_fault == "zero-resource-action":
                self.enqueue("RESOURCE_ACTION", {"actionId": 1, "verb": "CREATE", "manifestDigest": admission.ZERO})
            else:
                self.enqueue_receipt()
        elif frame["kind"] == "RESOURCE_RESULT":
            self.wire_last = frame
            action = frame["payload"]["actionId"]
            final_outcome = "PRESENT" if self.api_fault == "still-present" else "ABSENT"
            self.case.assertEqual(frame["payload"]["outcome"],
                {1: "CREATED", 2: "PRESENT", 3: "DELETED", 4: final_outcome}[action])
            if action < 4:
                self.enqueue("RESOURCE_ACTION", {"actionId": action + 1,
                    "verb": {1: "GET", 2: "DELETE", 3: "GET"}[action],
                    "manifestDigest": self.resource["manifestDigest"]})
            else:
                if self.api_fault != "still-present":
                    self.case.assertEqual(state, "ABSENT")
                self.enqueue_receipt()
        else:
            self.case.assertEqual((frame["kind"], state), ("CLEANUP_RECORDED", "CLEANUP_SEALED"))
            self.wire_last = frame
            if self.driver_fault == "lost-terminal":
                self.broker_incoming.append(b"")
                return
            self.enqueue("TERMINAL", {"status": {"PASS": "COMPLETED", "FAIL": "FAILED",
                "NOT_RUN_ENV_UNAVAILABLE": "UNAVAILABLE"}[self.status], "receiptSize": len(self.receipt_raw),
                "receiptDigest": byte_digest(self.receipt_raw),
                "cleanupDigest": admission.ZERO if self.driver_fault == "terminal-digest" else frame["payload"]["cleanupDigest"],
                "workerReaped": True})

    def api_reply(self, raw):
        self.api_requests.append(raw)
        headers, body = raw.split(b"\r\n\r\n", 1)
        verb = headers.split(b" ", 1)[0]
        index = len(self.api_requests)
        self.case.assertEqual(verb, {1: b"POST", 2: b"GET", 3: b"DELETE", 4: b"GET"}[index])
        base = b"/api/v1/namespaces/unit-namespace/configmaps"
        self.case.assertEqual(headers.split(b"\r\n", 1)[0],
            verb + b" " + base + (b"" if index == 1 else b"/unit-fixture") + b" HTTP/1.1")
        self.case.assertIn(b"Host: unit.proxy", headers)
        self.case.assertEqual(self.durable_journal, self.kernel_raw[self.journal_path])
        if index == 1:
            self.case.assertEqual(json.loads(self.durable_journal.splitlines()[-1])["state"], "CREATE_INTENT")
            self.case.assertEqual(json.loads(body), self.resource["manifest"])
            if self.api_fault == "lost-create":
                raise OSError("unit ambiguous CREATE")
            value = deepcopy(self.created)
        elif index == 2:
            self.case.assertEqual(body, b"")
            value = deepcopy(self.present)
            if self.api_fault == "changed-uid":
                value["metadata"]["uid"] = "foreign-uid"
        elif index == 3:
            self.case.assertEqual(json.loads(body), {"apiVersion": "v1", "kind": "DeleteOptions",
                "preconditions": {"uid": "unit-owned-uid", "resourceVersion": "101"}})
            value = {"apiVersion": "v1", "kind": "Status", "metadata": {}, "status": "Success",
                "code": 200, "details": {"name": "unit-fixture", "kind": "configmaps", "uid": "unit-owned-uid"}}
        else:
            self.case.assertEqual(body, b"")
            if self.api_fault == "still-present":
                return server.http_message("HTTP/1.1 200 OK", canonical_bytes(self.present))
            value = {"apiVersion": "v1", "kind": "Status", "metadata": {}, "status": "Failure",
                "code": 404, "reason": "NotFound", "details": {"name": "unit-fixture", "kind": "configmaps"},
                "message": 'configmaps "unit-fixture" not found'}
        return server.http_message("HTTP/1.1 404 Not Found" if index == 4 else "HTTP/1.1 200 OK", canonical_bytes(value))


class NativeServerHTTPFactoryTests(unittest.TestCase):
    """C6 real serve()/HTTP/admission/cleanup composition, OS-double source only."""
    def assert_closed(self, fixture):
        self.assertEqual(set(fixture.handles), {0, 1, 2})
        self.assertTrue(all(stream.closed for stream in fixture.accepted + fixture.api_streams + fixture.listeners))
        self.assertTrue(all(mapping.closes == 1 for mapping in fixture.maps))

    def test_all_ten_zero_resource_requests_use_real_server_and_terminal_journal(self):
        fixture = _NativeServerHTTPOS(self)
        fixture.prepare_http()
        with ExitStack() as stack:
            owner = fixture.start(stack)
            owner.serve()
            self.assertEqual(len(fixture.responses), 10)
            self.assertEqual([json.loads(raw.split(b"\r\n\r\n", 1)[1])["caseId"] for raw in fixture.responses], list(server.CASES))
            self.assertEqual(len(owner.broker.case_history), 10)
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            self.assertFalse(states[(owner.envelope["tenantId"], owner.envelope["nonce"])]["held"])
            self.assertEqual(len(fixture.accepted), 10)
            self.assertEqual(fixture.api_requests, [])
            self.assertEqual(fixture.api_streams, [])
            self.assertEqual(set(owner.secrets.raw), {server.IDENTITY})
        self.assert_closed(fixture)

    def test_resource_round_trip_uses_actual_api_tls_uid_cleanup_and_ten_case_handoff(self):
        fixture = _NativeServerHTTPOS(self, resources=True)
        self.assertTrue(all("addressFamily" not in row for row in fixture.fixture.envelope["endpoints"]))
        fixture.prepare_http()
        with ExitStack() as stack:
            owner = fixture.start(stack)
            owner.serve()
            self.assertEqual(len(fixture.responses), 10)
            self.assertEqual(len(fixture.api_streams), 4)
            self.assertEqual([raw.split(b" ", 1)[0] for raw in fixture.api_requests], [b"POST", b"GET", b"DELETE", b"GET"])
            self.assertEqual([frame["payload"]["outcome"] for frame in fixture.broker_outgoing
                if frame.get("kind") == "RESOURCE_RESULT"], ["CREATED", "PRESENT", "DELETED", "ABSENT"])
            self.assertEqual(fixture.events.count(("open", fixture.api_path)), 1)
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            state = states[(owner.envelope["tenantId"], owner.envelope["nonce"])]
            self.assertFalse(state["held"])
            self.assertEqual(len(state["terminalCases"]), 10)
            self.assertIn("ABSENT", [json.loads(raw)["state"] for raw in fixture.durable_journal.splitlines()])
        self.assert_closed(fixture)

    def denied_request(self, *, tls=None, http=None):
        fixture = _NativeServerHTTPOS(self)
        fixture.tls_fault, fixture.http_fault = tls, http
        fixture.prepare_http([server.CASES[0]])
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(ConformanceError):
                owner.serve()
            self.assertEqual(fixture.broker_outgoing, [])
            self.assertEqual(fixture.responses, [])
            self.assertEqual(fixture.api_requests, [])
            self.assertEqual([json.loads(row)["state"] for row in fixture.durable_journal.splitlines()], ["RESERVED"])
        self.assert_closed(fixture)

    def test_wrong_tls_peer_is_denied_before_dispatch(self):
        self.denied_request(tls="identity")

    def test_wrong_tls_version_is_denied_before_dispatch(self):
        self.denied_request(tls="version")

    def test_wrong_alpn_is_denied_before_dispatch(self):
        self.denied_request(tls="alpn")

    def test_wrong_request_nonce_is_denied_before_running_append(self):
        self.denied_request(http="nonce")

    def test_wrong_http_host_is_denied_before_running_append(self):
        self.denied_request(http="host")

    def test_extra_request_bytes_are_denied_before_dispatch(self):
        self.denied_request(http="surplus")

    def failed_case(self, *, driver=None, api=None, expected_api=0):
        fixture = _NativeServerHTTPOS(self, resources=api is not None)
        fixture.driver_fault, fixture.api_fault = driver, api
        fixture.prepare_http([server.CASES[0]])
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises((ConformanceError, OSError, AssertionError)) as caught:
                owner.serve()
            # An OS-double assertion is NOT a product denial. Keep it a failing
            # test so a broken fixture cannot satisfy this negative case.
            self.assertNotIsInstance(caught.exception, AssertionError)
            self.assertEqual(len(fixture.api_requests), expected_api)
            self.assertEqual(fixture.responses, [])
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            state = states[(owner.envelope["tenantId"], owner.envelope["nonce"])]
            self.assertTrue(state["held"])
            self.assertEqual(state.get("terminalCases", []), [])
            self.assertEqual(json.loads(fixture.durable_journal.splitlines()[-1])["state"], "FAILURE_RECORDED")
        self.assert_closed(fixture)
        return fixture

    def test_zero_resource_action_is_denied_before_api_identity(self):
        fixture = self.failed_case(driver="zero-resource-action")
        self.assertNotIn(fixture.api_path, fixture.read_paths)

    def test_lost_terminal_sends_no_client_success(self):
        self.failed_case(driver="lost-terminal")

    def test_terminal_digest_mismatch_sends_no_client_success(self):
        self.failed_case(driver="terminal-digest")

    def test_lost_create_retains_null_uid_and_never_retries(self):
        fixture = self.failed_case(api="lost-create", expected_api=1)
        cleanup = json.loads(fixture.durable_journal.splitlines()[-1])["cleanup"]
        self.assertEqual(cleanup["remainingResources"][0]["uid"], None)
        self.assertEqual(cleanup["remainingResources"][0]["reasonCode"], "IO_AMBIGUOUS")

    def test_replaced_uid_stops_before_delete(self):
        self.failed_case(api="changed-uid", expected_api=2)

    def test_still_present_after_delete_cannot_become_clean(self):
        fixture = self.failed_case(api="still-present", expected_api=4)
        cleanup = json.loads(fixture.durable_journal.splitlines()[-1])["cleanup"]
        self.assertEqual(cleanup["remainingResources"][0]["uid"], "unit-owned-uid")
        self.assertNotIn("ABSENT", [json.loads(row)["state"] for row in fixture.durable_journal.splitlines()])

    def nonpass_receipt(self, status):
        fixture = _NativeServerHTTPOS(self)
        fixture.status = status
        fixture.prepare_http([server.CASES[0]])
        with ExitStack() as stack:
            owner = fixture.start(stack)
            owner.serve()
            self.assertEqual(len(fixture.responses), 1)
            self.assertEqual(json.loads(fixture.responses[0].split(b"\r\n\r\n", 1)[1])["status"], status)
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            state = states[(owner.envelope["tenantId"], owner.envelope["nonce"])]
            self.assertTrue(state["held"])
            self.assertEqual(state["current"], server.CASES[0])
            self.assertEqual(len(state["terminalCases"]), 1)
            self.assertEqual(len(owner.broker.case_history), 0)
            self.assertEqual(len(fixture.accepted), 1)
            self.assertEqual(fixture.api_requests, [])
        self.assert_closed(fixture)

    def test_failed_receipt_is_returned_as_failed_without_releasing_capacity(self):
        self.nonpass_receipt("FAIL")

    def test_unavailable_receipt_never_becomes_pass_or_advances_the_case(self):
        self.nonpass_receipt("NOT_RUN_ENV_UNAVAILABLE")

    def test_false_pass_receipt_is_denied_before_cleanup_or_client_response(self):
        fixture = _NativeServerHTTPOS(self)
        fixture.status = "FAIL"
        fixture.prepare_http([server.CASES[0]])
        receipt = json.loads(fixture.receipts[server.CASES[0]])
        receipt["status"] = "PASS"
        fixture.receipts[server.CASES[0]] = canonical_bytes(receipt)
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(ConformanceError) as caught:
                owner.serve()
            self.assertEqual(caught.exception.reason, "SESSION_FALSE_RECEIPT_STATUS")
            self.assertEqual([row.get("kind", "DISPATCH") for row in fixture.broker_outgoing], ["DISPATCH"])
            self.assertEqual(fixture.responses, [])
            self.assertEqual(json.loads(fixture.durable_journal.splitlines()[-1])["state"], "FAILURE_RECORDED")
        self.assert_closed(fixture)

    def api_boundary_denial(self, boundary):
        fixture = _NativeServerHTTPOS(self, resources=True)
        fixture.prepare_http([server.CASES[0]])
        observed = []
        def revoke():
            observed.append(boundary)
            fixture.raw_status = server.struct.pack("<5I", 1, 4, 0, 2, 1)
        if boundary == "credential-read":
            def after(operation, path):
                if operation == "read" and path == fixture.api_path and not observed:
                    revoke()
            fixture.after = after
        else:
            def connected(operation, stream, value):
                if operation == "connect":
                    revoke()
            fixture.on_stream = connected
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(ConformanceError):
                owner.serve()
            self.assertEqual(observed, [boundary])
            self.assertEqual(fixture.api_requests, [])
            self.assertEqual(fixture.responses, [])
            self.assertEqual(len(fixture.codecs), 1)  # campaign codec only; no API handshake
            self.assertEqual(len(fixture.api_streams), 0 if boundary == "credential-read" else 1)
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            self.assertTrue(states[(owner.envelope["tenantId"], owner.envelope["nonce"])]["held"])
            last = json.loads(fixture.durable_journal.splitlines()[-1])
            self.assertEqual(last["state"], "FAILURE_RECORDED")
            self.assertIsNone(last["cleanup"]["remainingResources"][0]["uid"])
        self.assert_closed(fixture)

    def test_post_api_credential_policy_loss_stops_before_identity_copy_or_socket(self):
        self.api_boundary_denial("credential-read")

    def test_post_api_connect_policy_loss_stops_before_handshake_or_mutation(self):
        self.api_boundary_denial("api-connect")

    def test_cleanup_sync_ambiguity_sends_no_cleanup_ack_or_client_response(self):
        fixture = _NativeServerHTTPOS(self)
        fixture.prepare_http([server.CASES[0]])
        def fail_sync(operation, path, value):
            if operation == "fsync" and path == fixture.journal_path:
                if json.loads(fixture.kernel_raw[path].splitlines()[-1])["state"] == "CLEANUP_SEALED":
                    raise OSError("unit ambiguous cleanup sync")
        fixture.on_io = fail_sync
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(OSError):
                owner.serve()
            self.assertEqual([row.get("kind", "DISPATCH") for row in fixture.broker_outgoing], ["DISPATCH"])
            self.assertEqual(fixture.responses, [])
            self.assertEqual(json.loads(fixture.durable_journal.splitlines()[-1])["state"], "RUNNING")
            self.assertEqual(json.loads(fixture.kernel_raw[fixture.journal_path].splitlines()[-1])["state"], "CLEANUP_SEALED")
            self.assertTrue(owner.log.poisoned)
            self.assertEqual(owner.failure_accounting.refusal, "ACCOUNTING_UNAVAILABLE")
        self.assert_closed(fixture)

    def test_completed_case_replay_cannot_dispatch_or_reply_twice(self):
        fixture = _NativeServerHTTPOS(self)
        fixture.prepare_http([server.CASES[0], server.CASES[0]])
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(ConformanceError):
                owner.serve()
            self.assertEqual(len(fixture.responses), 1)
            self.assertEqual(len([row for row in fixture.broker_outgoing if "operation" in row]), 1)
            self.assertEqual(len(owner.broker.case_history), 1)
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            self.assertTrue(states[(owner.envelope["tenantId"], owner.envelope["nonce"])]["held"])
        self.assert_closed(fixture)

    def test_ambiguous_client_write_keeps_terminal_facts_without_next_dispatch(self):
        fixture = _NativeServerHTTPOS(self)
        fixture.prepare_http([server.CASES[0]])
        def lost_response(operation, stream, value):
            if operation == "send" and stream.mode == "campaign" and value[:1] == b"D":
                raise OSError("unit ambiguous client delivery")
        fixture.on_stream = lost_response
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(OSError):
                owner.serve()
            self.assertEqual(len(fixture.responses), 1)  # bytes offered, not client receipt
            self.assertEqual(len(fixture.accepted), 1)
            self.assertEqual(len(owner.broker.case_history), 1)
            self.assertEqual(json.loads(fixture.durable_journal.splitlines()[-1])["state"], "TERMINAL_RECORDED")
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            self.assertTrue(states[(owner.envelope["tenantId"], owner.envelope["nonce"])]["held"])
        self.assert_closed(fixture)

    def test_post_accept_policy_loss_prevents_tls_handshake_and_dispatch(self):
        fixture = _NativeServerHTTPOS(self)
        fixture.prepare_http([server.CASES[0]])
        def revoke(operation, stream, value):
            if operation == "accept":
                fixture.raw_status = server.struct.pack("<5I", 1, 4, 0, 2, 1)
        fixture.on_stream = revoke
        with ExitStack() as stack:
            owner = fixture.start(stack)
            with self.assertRaises(ConformanceError):
                owner.serve()
            self.assertEqual(fixture.codecs, [])
            self.assertEqual(fixture.broker_outgoing, [])
            self.assertEqual(fixture.accepted[0].sent, [])
        self.assert_closed(fixture)


class NativeServerFactoryTests(unittest.TestCase):
    """Real constructor plus zero-resource driver, not native or full HTTP QA."""
    def test_full_constructor_keeps_real_qualification_observer_broker_and_journal(self):
        fixture = _NativeServerKernelOS(self)
        with ExitStack() as stack:
            owner = fixture.start(stack)
            self.assertIs(type(owner), server.NativeProxyServer)
            self.assertIs(type(owner.qualification), server._KernelQualification)
            self.assertIs(type(owner.self_inspection), server._KernelSelfInspection)
            self.assertIs(type(owner.observer), server._Observer)
            self.assertIs(type(owner.broker), server._Broker)
            self.assertIs(type(owner.storage), server._State)
            self.assertIs(type(owner.log), admission._AdmissionLog)
            self.assertEqual(json.loads(fixture.durable_journal.splitlines()[-1])["state"], "RESERVED")
            self.assertTrue(owner.reserved)
            self.assertEqual(len(fixture.channels), 2)
            self.assertEqual(len(fixture.listeners), 1)
            self.assertEqual(len(fixture.memfds), 1)
            self.assertEqual(fixture.broker_outgoing, [])
            self.assertGreater(len(fixture.observations), 0)
            first_secret = fixture.events.index(("open", server.IDENTITY))
            durable = fixture.events.index(("fsync", server.STATE))
            self.assertLess(durable, first_secret)
            self.assertEqual(set(owner.secrets.raw), {server.IDENTITY})
            self.assertEqual(owner.deadline, 700.0)
        self.assertEqual(set(fixture.handles), {0, 1, 2})
        self.assertTrue(all(mapping.closes == 1 for mapping in fixture.maps))
        self.assertTrue(fixture.listeners[0].closed)

    def test_full_constructor_and_real_zero_resource_driver_preserve_durable_terminal_order(self):
        fixture = _NativeServerKernelOS(self)
        with ExitStack() as stack:
            owner = fixture.start(stack)
            fixture.prepare_case(owner)
            broker = owner.broker
            result = owner._drive_case()
            self.assertEqual(result, fixture.receipt_raw)
            self.assertEqual([json.loads(raw)["state"] for raw in fixture.durable_journal.splitlines()],
                ["RESERVED", "RUNNING", "CLEANUP_SEALED", "TERMINAL_RECORDED"])
            self.assertEqual([frame.get("kind", "DISPATCH") for frame in fixture.broker_outgoing],
                ["DISPATCH", "CLEANUP_RECORDED"])
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            state = states[(owner.envelope["tenantId"], owner.envelope["nonce"])]
            self.assertTrue(state["held"])  # one of ten cases, not release acceptance
            self.assertIsNone(state["current"])
            self.assertIsNone(owner.active_operation)
            self.assertEqual(len(broker.case_history), 1)
            self.assertIsNone(broker.credential)
            self.assertEqual(len(fixture.channels), 2)
            self.assertEqual(len(fixture.listeners), 1)

    def test_full_factory_rejects_bad_envelope_before_opening_capacity_or_state(self):
        fixture = _NativeServerKernelOS(self)
        value = json.loads(fixture.raw["/unit-only/envelope.json"])
        value["nonce"] = "unit-forged-nonce"
        fixture.raw["/unit-only/envelope.json"] = canonical_bytes(value)
        with ExitStack() as stack:
            fixture.context(stack)
            with self.assertRaises(ConformanceError):
                server.NativeProxyServer()
            self.assertIsNone(server._ACTIVE)
        self.assertNotIn("/unit-only/capacity.json", fixture.read_paths)
        self.assertNotIn(("open", fixture.journal_path), fixture.events)
        self.assertEqual(fixture.channels, [])
        self.assertEqual(set(fixture.handles), {0, 1, 2})

    def test_full_factory_rejects_packet_digest_drift_before_qualification_and_state(self):
        fixture = _NativeServerKernelOS(self)
        fixture.raw["/unit-only/packet.yaml"] += b"\n"
        with ExitStack() as stack:
            fixture.context(stack)
            with self.assertRaisesRegex(ConformanceError, "PROXY_FILE_DIGEST"):
                server.NativeProxyServer()
        self.assertNotIn(("open", fixture.journal_path), fixture.events)
        self.assertNotIn(server.IDENTITY, fixture.read_paths)
        self.assertEqual(fixture.channels, [])

    def test_full_factory_policy_loss_prevents_state_observer_and_credentials(self):
        fixture = _NativeServerKernelOS(self)
        fixture.raw_status = server.struct.pack("<5I", 1, 2, 0, 1, 1)
        with ExitStack() as stack:
            fixture.context(stack)
            with self.assertRaises(ConformanceError):
                server.NativeProxyServer()
        self.assertNotIn(("open", fixture.journal_path), fixture.events)
        self.assertNotIn(server.IDENTITY, fixture.read_paths)
        self.assertEqual(fixture.channels, [])
        self.assertEqual(fixture.memfds, [])

    def test_full_factory_state_custody_loss_prevents_observer_and_credentials(self):
        fixture = _NativeServerKernelOS(self)
        with ExitStack() as stack:
            fixture.context(stack)
            fixture.nodes[fixture.journal_path].st_mode = stat.S_IFREG | 0o644
            with self.assertRaisesRegex(ConformanceError, "ADMISSION_STORE_CUSTODY"):
                server.NativeProxyServer()
        self.assertEqual(fixture.channels, [])
        self.assertNotIn(server.IDENTITY, fixture.read_paths)
        self.assertEqual(fixture.kernel_raw[fixture.journal_path], b"")

    def test_full_factory_zero_resource_action_is_denied_before_upstream_or_cleanup(self):
        fixture = _NativeServerKernelOS(self)
        fixture.driver_fault = "zero-resource-action"
        with ExitStack() as stack:
            owner = fixture.start(stack)
            fixture.prepare_case(owner)
            broker = owner.broker
            with self.assertRaises(ConformanceError):
                owner._drive_case()
            self.assertTrue(broker.failed and broker.closed)
            self.assertEqual([json.loads(raw)["state"] for raw in fixture.durable_journal.splitlines()],
                             ["RESERVED", "RUNNING", "FAILURE_RECORDED"])
            self.assertIsNone(json.loads(fixture.durable_journal.splitlines()[-1])["cleanup"])
            self.assertIsNone(broker.credential)
            self.assertEqual(len(fixture.channels), 2)
            self.assertEqual(len(fixture.listeners), 1)
            self.assertEqual(len(fixture.broker_outgoing), 1)

    def test_full_factory_lost_terminal_retains_cleanup_seal_without_success(self):
        fixture = _NativeServerKernelOS(self)
        fixture.driver_fault = "lost-terminal"
        with ExitStack() as stack:
            owner = fixture.start(stack)
            fixture.prepare_case(owner)
            with self.assertRaises(ConformanceError):
                owner._drive_case()
            self.assertEqual([json.loads(raw)["state"] for raw in fixture.durable_journal.splitlines()],
                             ["RESERVED", "RUNNING", "CLEANUP_SEALED", "FAILURE_RECORDED"])
            states, _, _ = admission.parse_reservations(fixture.durable_journal)
            state = states[(owner.envelope["tenantId"], owner.envelope["nonce"])]
            self.assertTrue(state["held"])
            self.assertIsNotNone(state["pendingCompletion"])
            self.assertEqual(state.get("terminalCases", []), [])
            self.assertEqual(len(fixture.broker_outgoing), 2)


class KernelQualificationFactoryTests(unittest.TestCase):
    """C1 real binding/composition/channel factories; OS doubles only."""
    def environment(self, stack, architecture="amd64"):
        fixture = _QualificationKernelOS(self, architecture)
        owner = fixture.context(stack)
        return fixture, owner, owner.qualification

    def test_real_self_and_both_peer_factories_without_worker_or_credentials(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            self.assertIsNone(subject.check_self())
            self.assertEqual({name for name, _ in owner.self_inspection.owned},
                             {"roots", "policy", "process", "code", "mappings", "cgroup", "filters"})
            for role in ("OBSERVER", "BROKER"):
                peer = fixture.peer(role)
                stack.callback(peer.close)
                self.assertIsNone(subject.check_peer(role, peer))
            self.assertEqual(set(subject._peers), {"OBSERVER", "BROKER"})
            self.assertEqual(owner.secrets.raw, {})
            self.assertNotIn("WORKER", fixture.processes)
            self.assertEqual(fixture.network.call_count, 2)
            self.assertTrue(fixture.maps)

    def test_real_arm64_self_factory_and_partial_policy_failure_close_owned_views(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack, "arm64")
            # Fail a real policy read after resources have been retained. The
            # absence is an OS error, never a successful inspector substitute.
            def deny(operation, path):
                if operation == "read" and path == "/sys/fs/selinux/policy":
                    raise PermissionError("unit missing inspection permission")
            fixture.after = deny
            with self.assertRaises(PermissionError):
                subject.__init__(owner)
            self.assertTrue(subject.closed and subject.failed)
            self.assertEqual(set(fixture.fds), {row[0] for row in owner.files.rows.values()})
            self.assertEqual(owner.secrets.raw, {})
            fixture.network.assert_not_called()

    def test_policy_epoch_loss_inside_real_read_is_sticky_and_closes_originals(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            def change(operation, path):
                if operation == "pread" and path == server.EXECUTABLE:
                    fixture.raw_status = server.struct.pack("<5I", 1, 4, 1, 2, 1)
            fixture.after = change
            with self.assertRaises(ConformanceError):
                subject.check_self()
            fixture.after = lambda *args: None
            fixture.raw_status = server.struct.pack("<5I", 1, 2, 1, 1, 1)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_QUALIFICATION_UNAVAILABLE"):
                subject.check_self()
            subject.close()
            self.assertEqual(set(fixture.fds), {row[0] for row in owner.files.rows.values()})
            self.assertEqual(owner.secrets.raw, {})

    def test_unregistered_owner_and_caller_context_cannot_construct(self):
        for value in ({"qualified": True}, 3, lambda: None, SimpleNamespace()):
            with self.subTest(value_type=type(value)), self.assertRaisesRegex(ConformanceError, "KERNEL_QUALIFICATION_OWNER"):
                server._KernelQualification(value)
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_QUALIFICATION_OWNER"):
                server._KernelQualification(owner)
            fixture.network.assert_not_called()
            self.assertIs(owner.qualification, subject)

    def test_real_factory_wrong_peer_role_never_becomes_broker_qualification(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            peer = fixture.peer("OBSERVER")
            stack.callback(peer.close)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_QUALIFICATION_PEER_OWNER"):
                subject.check_peer("BROKER", peer)
            self.assertTrue(subject.failed)
            self.assertEqual(subject._peers, {})
            self.assertFalse(peer.closed)
            self.assertEqual(owner.secrets.raw, {})

    def test_real_factory_original_owner_replacement_refuses_before_credentials(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            original = owner.self_inspection
            owner.self_inspection = Mock()
            with self.assertRaisesRegex(ConformanceError, "KERNEL_QUALIFICATION_OWNER_CHANGED"):
                subject.check_self()
            subject.close()
            self.assertTrue(original.closed)
            owner.self_inspection.close.assert_not_called()
            self.assertEqual(owner.secrets.raw, {})
            fixture.network.assert_not_called()

    def test_real_factory_peer_fd_reuse_is_not_an_accepted_new_channel(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            peer = fixture.peer("BROKER")
            stack.callback(peer.close)
            subject.check_peer("BROKER", peer)
            fd = peer._socket_fd
            saved = fixture.handles[fd]
            fixture.handles[fd] = (saved[0], SimpleNamespace(**{**vars(saved[1]), "st_ino": saved[1].st_ino + 1}))
            try:
                with self.assertRaises(ConformanceError):
                    subject.check_peer("BROKER", peer)
                self.assertTrue(subject.failed)
                self.assertIn(fd, fixture.handles)  # do not close a recycled descriptor
                self.assertEqual(owner.secrets.raw, {})
            finally:
                fixture.handles[fd] = saved  # restore the OS double only for original-owner cleanup

    def test_real_factory_peer_pid_reuse_is_sticky_without_reenrollment(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            peer = fixture.peer("BROKER")
            stack.callback(peer.close)
            subject.check_peer("BROKER", peer)
            path = "/proc/" + str(fixture.processes["BROKER"]) + "/stat"
            prefix, body = fixture.kernel_raw[path].split(b") ", 1)
            fields = body.split()
            fields[19] = str(int(fields[19]) + 1).encode()
            fixture.kernel_raw[path] = prefix + b") " + b" ".join(fields) + b"\n"
            with self.assertRaises(ConformanceError):
                subject.check_peer("BROKER", peer)
            self.assertTrue(subject.failed)
            with self.assertRaisesRegex(ConformanceError, "KERNEL_QUALIFICATION_UNAVAILABLE"):
                subject.check_self()
            self.assertEqual(owner.secrets.raw, {})
            self.assertEqual(fixture.network.call_count, 1)

    def test_real_factory_code_byte_drift_cannot_use_old_expected_measurement(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            raw = fixture.raw[server.EXECUTABLE]
            fixture.raw[server.EXECUTABLE] = raw[:-1] + bytes([raw[-1] ^ 1])
            with self.assertRaises(ConformanceError):
                subject.check_self()
            self.assertTrue(subject.failed)
            self.assertEqual(owner.secrets.raw, {})
            fixture.network.assert_not_called()

    def test_real_factory_post_io_deadline_loss_never_renews_lifetime(self):
        with ExitStack() as stack:
            fixture, owner, subject = self.environment(stack)
            subject.__init__(owner)
            original = subject.deadline
            def expire(operation, path):
                if operation == "pread" and path == server.EXECUTABLE:
                    fixture.mono = original
            fixture.after = expire
            with self.assertRaises(ConformanceError):
                subject.check_self()
            self.assertTrue(subject.failed)
            self.assertEqual(subject.deadline, original)
            self.assertEqual(owner.secrets.raw, {})
            fixture.network.assert_not_called()


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
