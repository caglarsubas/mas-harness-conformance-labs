from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("run_packet", ROOT / "ci/run_packet.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def packet(prefetch=None, acceptance=None, execution=None):
    expected_execution = {
        "wrapperArgv": ["./ci/verify-offline.sh"],
        "packetPathEnvironment": "HARNESS_TASK_PACKET",
        "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
        "commandTransport": "ARGV_ARRAY_V1",
        "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
        "sessionScope": "SINGLE_PROCESS_TREE",
        "prefetchOutsideSession": False,
        "offlineEnvironment": {"UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1"},
    }
    return {"id": "CONF-002", "repository": "mas-harness-conformance-labs", "warmSourceAccess": "PROHIBITED_DURING_IMPLEMENTATION", "prefetchCommands": [["make", "prefetch"]] if prefetch is None else prefetch, "offlineAcceptanceCommands": [["python3", "ci/run_make_target.py", "parity-meta"]] if acceptance is None else acceptance, "offlineExecution": expected_execution if execution is None else execution}


class PacketRunnerTests(unittest.TestCase):
    def test_current_packet_inline_authority_parses(self) -> None:
        document = packet(
            acceptance=[["python3", "ci/run_make_target.py", "parity-registry-check"], ["python3", "ci/run_make_target.py", "parity-meta"]]
        )
        text = "\n".join(
            f"{field}: {json.dumps(document[field], separators=(',', ':'))}"
            if field in ("prefetchCommands", "offlineAcceptanceCommands", "offlineExecution")
            else f"{field}: {document[field]}"
            for field in MODULE.FIELDS
        )
        extracted = MODULE.extract(text)
        prefetch, acceptance = MODULE.validate_packet(extracted)
        self.assertEqual(prefetch, [["make", "prefetch"]])
        self.assertEqual(acceptance, [["python3", "ci/run_make_target.py", "parity-registry-check"], ["python3", "ci/run_make_target.py", "parity-meta"]])

    def test_shell_download_recursive_and_strings_fail(self) -> None:
        cases = [["bash", "-c", "true"], ["curl", "invalid"], ["make", "verify-offline"], "make parity-meta"]
        for command in cases:
            with self.subTest(command=command), self.assertRaises(SystemExit):
                MODULE.validate_packet(packet(acceptance=[command]))

    def test_wrong_execution_and_warm_access_fail(self) -> None:
        wrong = packet(execution={})
        with self.assertRaises(SystemExit):
            MODULE.validate_packet(wrong)
        warm = packet()
        warm["warmSourceAccess"] = "REFERENCE_ONLY"
        with self.assertRaises(SystemExit):
            MODULE.validate_packet(warm)

    def test_duplicate_inline_authority_is_rejected(self) -> None:
        text = "\n".join(f"{name}: {json.dumps([]) if name.endswith('Commands') else '{}'}" for name in MODULE.FIELDS)
        text += "\nid: CONF-002\n"
        with self.assertRaises(SystemExit):
            MODULE.extract(text)

    def test_alias_and_empty_acceptance_are_rejected(self) -> None:
        document = packet(acceptance=[])
        with self.assertRaises(SystemExit):
            MODULE.validate_packet(document)
        text = "\n".join(
            f"{field}: &indirection value" if field == "id" else f"{field}: value"
            for field in MODULE.FIELDS
        )
        with self.assertRaises(SystemExit):
            MODULE.extract(text)

    def test_main_preserves_phase_order_and_hides_authority(self) -> None:
        calls = []
        descriptor, temporary_path = tempfile.mkstemp()
        os.write(descriptor, b"packet")
        info = os.fstat(descriptor)

        def run(command, *, env, check):
            self.assertNotIn("HARNESS_TASK_PACKET", env)
            self.assertNotIn("HARNESS_WARM_SOURCE_ROOTS", env)
            calls.append(command)
            return mock.Mock(returncode=0)

        document = packet(
            prefetch=[["make", "prefetch"]],
            acceptance=[["python3", "ci/run_make_target.py", "parity-meta"]],
        )
        environment = {
            "HARNESS_OFFLINE_ENFORCED": "1",
            "HARNESS_OFFLINE_BACKEND": "darwin-sandbox",
            "HARNESS_OFFLINE_SESSION_ID": "test-session",
            "HARNESS_TASK_PACKET": "/hidden/from/children",
        }
        try:
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                MODULE, "read_once", return_value=(descriptor, info, b"packet")
            ), mock.patch.object(MODULE, "extract", return_value=document), mock.patch.object(
                MODULE, "still_same"
            ), mock.patch.object(MODULE.subprocess, "run", side_effect=run):
                self.assertEqual(MODULE.main(["/authority/packet.yaml"]), 0)
        finally:
            Path(temporary_path).unlink(missing_ok=True)
        self.assertEqual(
            calls,
            [
                [MODULE.sys.executable, "ci/network_canary.py"],
                ["make", "prefetch"],
                ["python3", "ci/run_make_target.py", "parity-meta"],
            ],
        )

    def test_packet_replacement_is_detected(self) -> None:
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(b"packet")
            stream.flush()
            descriptor = os.open(stream.name, os.O_RDONLY)
            info = os.fstat(descriptor)
            stream.write(b"changed")
            stream.flush()
            try:
                with self.assertRaises(SystemExit):
                    MODULE.still_same(Path(stream.name), descriptor, info, MODULE.hashlib.sha256(b"packet").hexdigest())
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
