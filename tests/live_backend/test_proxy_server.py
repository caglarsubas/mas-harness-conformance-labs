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
from unittest.mock import Mock, patch

from _fixtures import ROOT
from _inventory import BASELINE, SUCCESSOR, isolated_inventory, validate_checkpoint
from harness_conformance import live_mutation_admission as admission
from test_proxy_client import load_proxy_modules
from harness_conformance.canonical import byte_digest, canonical_bytes
from harness_conformance.errors import ConformanceError
from harness_conformance.live_backend_authority import SUITE_ROOTS

VECTORS = json.loads((ROOT / "fixtures/live-backend/proxy-vectors.json").read_bytes())
_client_module, server = load_proxy_modules()


def sample(index=0):
    return deepcopy(VECTORS["qualification"]["positive"][index])


def record_check(value):
    return admission.validate_qualification_record(value["record"], value["profile"], value["endpoints"])


def capture_check(value, capture, role=None, previous=None):
    return admission.validate_qualification_capture(value["record"], capture, value["profile"], value["endpoints"],
                                                    role=capture["role"] if role is None else role, previous=previous)


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
        self.assertIn(result["stage"], (3, 4, 5, 6))
        self.assertEqual(len(rows), (135, 141, 146, 151)[result["stage"] - 3])
        indexed = {row["path"]: row for row in rows}
        for path, expected in baseline["files"].items():
            if result["stage"] == 6 and path == SUCCESSOR.RECORD["hook"]["path"]:
                # The accepted validator above has already checked the exact
                # final hook delta proof. Mere filename presence grants nothing.
                continue
            raw = sources[path]
            with self.subTest(path=path):
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
            self.assertEqual(observed[path], methods, path)
        additions = set(observed) - set(baseline["tests"])
        rows, sources = SUCCESSOR.tracked_inventory(ROOT)
        stage = validate_checkpoint(rows, sources)["stage"]
        expected = {path for number in range(3, stage + 1)
                    for path in BASELINE["packetPaths"][f"CONF-LIVE-{number:03d}"]
                    if path.startswith("tests/live_backend/test_") and path.endswith(".py")}
        self.assertEqual(additions, expected)
        print("CONF-LIVE-003 predecessor inventory: 127 files / 327 methods preserved; nativeAcceptance=false", flush=True)
