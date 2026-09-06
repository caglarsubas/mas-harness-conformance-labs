from __future__ import annotations

import ast
import builtins
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import runpy
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ci" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load("boundary_runner", "run_packet.py")
CANARY = load("boundary_canary", "network_canary.py")
LIVE = load("retired_live", "verify-live-campaign.py")


def environment(os_name="darwin"):
    return {"HARNESS_OFFLINE_ENFORCED": "1", "HARNESS_OFFLINE_SESSION_ID": "unit-only",
            "HARNESS_OFFLINE_BACKEND": "darwin-sandbox" if os_name == "darwin" else "linux-firejail"}


class RunnerBoundaryTests(unittest.TestCase):
    def test_backend_os_mismatch_unknown_missing_or_warm_marker_stops_before_io(self):
        cases = [(name, value) for name in ("darwin", "linux", "win32")
                 for value in ({}, environment("darwin"), environment("linux"))
                 if name == "win32" or value != environment(name)]
        cases += [("darwin", {**environment(), field: value}) for field, value in (
            ("HARNESS_OFFLINE_ENFORCED", "0"), ("HARNESS_OFFLINE_BACKEND", "unknown"),
            ("HARNESS_OFFLINE_SESSION_ID", ""), ("HARNESS_WARM_SOURCE_ROOTS", "unit-forbidden"))]
        for os_name, env in cases:
            with self.subTest(os=os_name, env=env), mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(RUNNER.sys, "platform", os_name), mock.patch.object(RUNNER, "read_once") as read, \
                    mock.patch.object(RUNNER.subprocess, "run") as child:
                with self.assertRaises(SystemExit):
                    RUNNER.main(["/unit/packet.yaml"])
                read.assert_not_called()
                child.assert_not_called()

    def test_closed_child_environment_uses_only_local_source_imports(self):
        forbidden = {name: "unit-secret-or-path" for name in (
            "HARNESS_TASK_PACKET", "HARNESS_WARM_SOURCE_ROOTS", "HARNESS_LIVE_SESSION_FD",
            "AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "OPENAI_API_KEY",
            "SSH_AUTH_SOCK", "KUBECONFIG", "DOCKER_HOST", "PYTHONHOME", "PYTHONSTARTUP",
            "PYTHONPATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "UNKNOWN_FUTURE_FIELD")}
        allowed = {key: "local" for key in RUNNER.CHILD_ENVIRONMENT}
        with mock.patch.dict(os.environ, {**allowed, **forbidden}, clear=True):
            child = RUNNER.child_environment()
        self.assertEqual(set(child), RUNNER.CHILD_ENVIRONMENT | {"PYTHONPATH", "PYTHONDONTWRITEBYTECODE"})
        self.assertEqual(child["PYTHONPATH"], str(ROOT / "src"))
        self.assertEqual(child["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertFalse(set(forbidden) - {"PYTHONPATH"} & set(child))

    def test_both_os_backends_keep_order_digest_rechecks_and_short_circuit(self):
        for os_name in ("darwin", "linux"):
            for failure_at in (None, 0, 1, 2):
                with self.subTest(os=os_name, failure=failure_at), tempfile.TemporaryFile() as file:
                    file.write(b"packet")
                    file.flush()
                    fd = os.dup(file.fileno())
                    commands = [["python3", "unit-prefetch.py"], ["python3", "unit-accept.py"]]
                    events = []
                    def run(argv, *, env, check):
                        index = sum(item[0] == "run" for item in events)
                        events.append(("run", argv))
                        self.assertNotIn("HARNESS_TASK_PACKET", env)
                        self.assertNotIn("UNKNOWN", env)
                        return mock.Mock(returncode=19 if failure_at == index else 0)
                    with mock.patch.dict(os.environ, {**environment(os_name), "UNKNOWN": "secret"}, clear=True), \
                            mock.patch.object(RUNNER.sys, "platform", os_name), \
                            mock.patch.object(RUNNER, "read_once", return_value=(fd, os.fstat(fd), b"packet")), \
                            mock.patch.object(RUNNER, "extract", return_value={"id": "CONF-FIX-001"}), \
                            mock.patch.object(RUNNER, "validate_packet", return_value=([commands[0]], [commands[1]])), \
                            mock.patch.object(RUNNER, "still_same", side_effect=lambda *args: events.append(("digest", args[-1]))), \
                            mock.patch.object(RUNNER.subprocess, "run", side_effect=run):
                        result = RUNNER.main(["/unit/packet.yaml"])
                    count = 3 if failure_at is None else failure_at + 1
                    self.assertEqual(result, 0 if failure_at is None else 19)
                    self.assertEqual([x[0] for x in events], ["run", "digest"] * count)
                    self.assertEqual([x[1] for x in events if x[0] == "run"],
                                     [[RUNNER.sys.executable, "ci/network_canary.py"], *commands][:count])
                    self.assertTrue(all(x[1] == hashlib.sha256(b"packet").hexdigest() for x in events if x[0] == "digest"))
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_packet_custody_refuses_user_file_symlink_hardlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            file = root / "packet"
            file.write_text("unit-only")
            file.chmod(0o444)
            linked = root / "linked"
            linked.symlink_to(file)
            hard = root / "hard"
            os.link(file, hard)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            for path in (file, linked, hard, fifo, root, Path("relative.yaml")):
                with self.subTest(path=path), self.assertRaises(SystemExit):
                    RUNNER.read_once(path)

    def test_content_change_even_with_fixed_metadata_is_detected(self):
        with tempfile.TemporaryFile() as file:
            file.write(b"packet")
            file.flush()
            info = os.fstat(file.fileno())
            with mock.patch.object(RUNNER.os, "fstat", return_value=info), \
                    mock.patch.object(Path, "stat", return_value=info), \
                    mock.patch.object(RUNNER.os, "pread", return_value=b"tamper"), self.assertRaises(SystemExit):
                RUNNER.still_same(Path("/unit/packet"), file.fileno(), info, hashlib.sha256(b"packet").hexdigest())

    def test_bridge_delegates_exact_argv_without_another_process(self):
        delegate = mock.Mock()
        delegate.main.return_value = 23
        with mock.patch.dict(sys.modules, {"run_packet": delegate}), \
                mock.patch.object(sys, "argv", ["ci/run_packet_argv.py", "/unit/packet.yaml"]), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected child")):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(ROOT / "ci/run_packet_argv.py"), run_name="__main__")
        self.assertEqual(result.exception.code, 23)
        delegate.main.assert_called_once_with(["/unit/packet.yaml"])

    def test_wrapper_binds_os_and_executes_only_the_fixed_bridge(self):
        source = (ROOT / "ci/verify-offline.sh").read_text()
        self.assertIn('case "$(/usr/bin/uname -s):${HARNESS_OFFLINE_BACKEND:-}" in', source)
        self.assertIn('Darwin:darwin-sandbox|Linux:linux-firejail) ;;', source)
        self.assertIn('*) refuse "isolation backend does not match the operating system" ;;', source)
        self.assertEqual([line for line in source.splitlines() if line.startswith("exec ")],
                         ['exec python3 -B ci/run_packet_argv.py "$packet_path"'])
        self.assertLess(source.index("unset HARNESS_TASK_PACKET"), source.index("exec python3"))

    def test_real_wrapper_rejects_missing_unknown_and_wrong_os_backend(self):
        wrong = "linux-firejail" if sys.platform == "darwin" else "darwin-sandbox"
        for backend in ("", "unknown", wrong):
            with self.subTest(backend=backend):
                result = subprocess.run([str(ROOT / "ci/verify-offline.sh")], cwd=ROOT,
                    env={"PATH": "/usr/bin:/bin", "HARNESS_OFFLINE_ENFORCED": "1",
                         "HARNESS_OFFLINE_BACKEND": backend, "HARNESS_OFFLINE_SESSION_ID": "unit"},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn("backend does not match the operating system", result.stderr)
                self.assertNotIn("offline_network_status=PASS", result.stdout)


class CanaryTests(unittest.TestCase):
    def invoke(self, os_name, *, create_error=None, connect_error=None, configure_error=None, env=None):
        fake = mock.Mock()
        fake.connect.side_effect = connect_error
        fake.settimeout.side_effect = configure_error
        with mock.patch.dict(os.environ, environment(os_name) if env is None else env, clear=True), \
                mock.patch.object(CANARY.sys, "platform", os_name), \
                mock.patch.object(CANARY.socket, "socket", return_value=fake, side_effect=create_error) as factory:
            try:
                return CANARY.main()
            finally:
                if create_error is None and env is None:
                    fake.close.assert_called_once_with()
                if env is not None:
                    factory.assert_not_called()

    def test_backend_specific_permission_denials_pass(self):
        for error in (errno.EPERM, errno.EACCES):
            with self.subTest(error=error):
                self.assertEqual(self.invoke("linux", create_error=OSError(error, "unit denial")), 0)
                self.assertEqual(self.invoke("darwin", connect_error=OSError(error, "unit denial")), 0)

    def test_wrong_stage_permission_denials_fail(self):
        for error in (errno.EPERM, errno.EACCES):
            with self.subTest(error=error), self.assertRaises(OSError):
                self.invoke("darwin", create_error=OSError(error, "wrong stage"))
            with self.subTest(error=error), self.assertRaises(OSError):
                self.invoke("darwin", configure_error=OSError(error, "wrong stage"))
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                self.invoke("linux", connect_error=OSError(error, "creation allowed"))

    def test_route_dns_timeout_and_unsupported_family_are_not_isolation(self):
        errors = [OSError(code, "unit non-proof") for code in (
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT, errno.ECONNREFUSED,
            errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT)] + [TimeoutError(), socket.gaierror(-2, "unit DNS")]
        for error in errors:
            for name, kwargs in (("linux", {"create_error": error}), ("darwin", {"connect_error": error})):
                with self.subTest(os=name, error=error), self.assertRaises(OSError):
                    self.invoke(name, **kwargs)

    def test_successful_socket_or_connect_is_not_isolation(self):
        for os_name in ("linux", "darwin"):
            with self.subTest(os=os_name), self.assertRaises(RuntimeError):
                self.invoke(os_name)

    def test_absent_unknown_mismatched_marker_never_opens_socket(self):
        for name, env in (("linux", {}), ("darwin", environment("linux")), ("linux", environment("darwin")),
                          ("win32", environment()), ("darwin", {**environment(), "HARNESS_OFFLINE_BACKEND": "unknown"}),
                          ("darwin", {**environment(), "HARNESS_OFFLINE_SESSION_ID": ""})):
            with self.subTest(os=name, env=env), self.assertRaises(RuntimeError):
                self.invoke(name, env=env)


class RetiredLiveTests(unittest.TestCase):
    def assert_retired(self, fd, argv, ci):
        env = {"HARNESS_LIVE_SESSION_FD": str(fd), "HARNESS_LIVE_VERIFIED": "1", "CI": ci,
               "GITHUB_ACTIONS": ci, "GITHUB_EVENT_NAME": ci}
        error = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(error), \
                mock.patch.object(os, "read", side_effect=AssertionError("descriptor read")), \
                mock.patch.object(os, "open", side_effect=AssertionError("credential open")), \
                mock.patch.object(builtins, "open", side_effect=AssertionError("file open")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("child execution")), \
                mock.patch.object(os, "execve", side_effect=AssertionError("exec")), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("network")):
            with self.assertRaises(SystemExit) as result:
                LIVE.main(argv)
        self.assertEqual(result.exception.code, 2)
        record = json.loads(error.getvalue())
        self.assertEqual((record["reasonCode"], record["status"]), ("DIRECT_LIVE_ADAPTER_FORBIDDEN", "FAIL"))

    def test_arbitrary_argv_invalid_descriptor_and_removed_ci_are_refused(self):
        for fd in ("", "unknown", -1, 0, 999999):
            for argv in ([], ["--"], ["--", "/unit/never-run"], ["--", "python3", "-c", "raise Exception()"]):
                for ci in ("", "true"):
                    with self.subTest(fd=fd, argv=argv, ci=ci):
                        self.assert_retired(fd, argv, ci)

    def test_caller_created_pipe_file_and_memfd_magic_are_not_authority(self):
        magic = b'{"boundary":"SIGNED_ENDPOINT_ALLOWLIST","status":"ENTERED"}\n'
        read_fd, write_fd = os.pipe()
        with tempfile.TemporaryFile() as file:
            file.write(magic)
            file.seek(0)
            os.write(write_fd, magic)
            descriptors = [read_fd, file.fileno()]
            memfd = None
            if hasattr(os, "memfd_create"):
                memfd = os.memfd_create("unit-forged-proof", 0)
                os.write(memfd, magic)
                os.lseek(memfd, 0, os.SEEK_SET)
                descriptors.append(memfd)
            try:
                for fd in descriptors:
                    for inheritable in (False, True):
                        os.set_inheritable(fd, inheritable)
                        self.assert_retired(fd, ["--", "/unit/never-run"], "")
                self.assertEqual(os.read(read_fd, 4096), magic)
                self.assertEqual(file.read(), magic)
            finally:
                os.close(read_fd)
                os.close(write_fd)
                if memfd is not None:
                    os.close(memfd)

    def test_adapter_has_no_execution_or_io_imports(self):
        tree = ast.parse((ROOT / "ci/verify-live-campaign.py").read_bytes())
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imports, {"json", "sys"})
