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
                            mock.patch.object(RUNNER.subprocess, "run", side_effect=run), \
                            contextlib.redirect_stdout(io.StringIO()):
                        # CONF-CI-002: the legacy runner's evidence-format lines stay in the test, never in a verify log.
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
        # CONF-CI-002: the adopted bridge (harness-onion contract) runs the packet itself; it takes no argv, reads the
        # packet only from HARNESS_TASK_PACKET and starts no process before the packet and its contract are validated.
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / "packet.yaml"
            packet.write_text("id: \"UNIT-001\"\n", encoding="utf-8")
            for argv, env, reason in (
                    (["ci/run_packet_argv.py", "/unit/packet.yaml"], {**environment(), "HARNESS_TASK_PACKET": str(packet)},
                     "unrecognized arguments"),
                    (["ci/run_packet_argv.py"], {**environment(), "HARNESS_TASK_PACKET": str(packet)},
                     "packet must contain one inline JSON offlineExecution field"),
                    (["ci/run_packet_argv.py"], environment(), "HARNESS_TASK_PACKET is required")):
                with self.subTest(argv=argv, env=sorted(env)), mock.patch.dict(os.environ, env, clear=True), \
                        mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()) as error, \
                        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected child")), \
                        mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected child")):
                    with self.assertRaises(SystemExit) as result:
                        runpy.run_path(str(ROOT / "ci/run_packet_argv.py"), run_name="__main__")
                    self.assertEqual(result.exception.code, 2)
                    self.assertIn(reason, error.getvalue())
        tree = ast.parse((ROOT / "ci/run_packet_argv.py").read_bytes())
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse({name for name in imported if name.split(".")[0] == "run_packet"})

    def test_wrapper_binds_os_and_executes_only_the_fixed_bridge(self):
        # CONF-CI-002: without trusted outer isolation the adopted wrapper isolates itself and names the backend from
        # uname (Darwin: sandbox-exec denying network; Linux: firejail --net=none); under trusted outer isolation it
        # keeps the launcher's marker. Every exec runs only the fixed bridge, as `python3 -I`.
        source = (ROOT / "ci/verify-offline.sh").read_text()
        self.assertIn('runner="${ci_dir}/run_packet_argv.py"', source)
        self.assertIn('case "$(uname -s)" in', source)
        darwin = source[source.index("  Darwin)"):source.index("  Linux)")]
        linux = source[source.index("  Linux)"):source.index("  *)")]
        self.assertIn("(deny network*)", darwin)
        self.assertIn("HARNESS_OFFLINE_BACKEND=darwin-sandbox", darwin)
        self.assertNotIn("linux-firejail", darwin)
        self.assertIn("--net=none", linux)
        self.assertIn("HARNESS_OFFLINE_BACKEND=linux-firejail", linux)
        self.assertNotIn("darwin-sandbox", linux)
        self.assertIn('echo "offline verification refused: unsupported isolation platform $(uname -s)" >&2', source)
        self.assertEqual(source.count('python3 -I "$runner"'), 3)
        self.assertEqual([line.strip() for line in source.splitlines() if line.strip().startswith("exec ")],
                         ['exec python3 -I "$runner"', 'exec /usr/bin/sandbox-exec \\', 'exec firejail "${firejail_arguments[@]}" \\'])
        self.assertIn('echo "offline verification accepts no shell command arguments" >&2', source)

    def test_real_wrapper_rejects_missing_unknown_and_wrong_os_backend(self):
        # CONF-CI-002: under trusted outer isolation the adopted wrapper refuses a missing backend or session and a
        # missing uv offline setting, and the adopted canary refuses an unknown backend before any socket or command.
        # The launcher, not the wrapper, binds the backend to the operating system in that mode.
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / "packet.yaml"
            packet.write_text(_ADOPTED_PACKET, encoding="utf-8")
            base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HARNESS_TASK_PACKET": str(packet),
                    "HARNESS_OFFLINE_ENFORCED": "1", "HARNESS_OFFLINE_SESSION_ID": "unit",
                    "UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1"}
            cases = (({**base, "HARNESS_OFFLINE_BACKEND": ""}, "trusted outer isolation must name its backend and session"),
                     ({**base, "HARNESS_OFFLINE_BACKEND": "darwin-sandbox", "HARNESS_OFFLINE_SESSION_ID": ""},
                      "trusted outer isolation must name its backend and session"),
                     ({**{k: v for k, v in base.items() if k != "UV_NO_SYNC"}, "HARNESS_OFFLINE_BACKEND": "darwin-sandbox"},
                      "trusted outer isolation requires UV_NO_SYNC=1"),
                     ({**base, "HARNESS_OFFLINE_BACKEND": "unknown"}, "recognized isolation backend required"))
            for env, message in cases:
                with self.subTest(message=message, backend=env.get("HARNESS_OFFLINE_BACKEND")):
                    result = subprocess.run([str(ROOT / "ci/verify-offline.sh")], cwd=ROOT, env=env,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("packet=", result.stdout)
                    self.assertNotIn("offline-acceptance argv:", result.stdout)
            result = subprocess.run([str(ROOT / "ci/verify-offline.sh"), "extra"], cwd=ROOT, env=base,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual((result.returncode, result.stderr.strip()), (2, "offline verification accepts no shell command arguments"))


_ADOPTED_PACKET = (
    'id: "UNIT-001"\nrepository: "mas-harness-conformance-labs"\nwarmSourceAccess: "PROHIBITED_DURING_IMPLEMENTATION"\n'
    "prefetchCommands: []\n"
    'offlineAcceptanceCommands: [["python3","-c","raise SystemExit(7)"]]\n'
    'offlineExecution: {"wrapperArgv":["./ci/verify-offline.sh"],"packetPathEnvironment":"HARNESS_TASK_PACKET",'
    '"packetPathMode":"HASH_PINNED_READ_ONCE_NO_CHILD_PATH","commandTransport":"ARGV_ARRAY_V1",'
    '"isolation":"OS_ENFORCED_DENY_ALL_OUTBOUND","sessionScope":"SINGLE_PROCESS_TREE","prefetchOutsideSession":false,'
    '"offlineEnvironment":{"UV_OFFLINE":"1","UV_FROZEN":"1","UV_NO_SYNC":"1"}}\n')


class CanaryTests(unittest.TestCase):
    # CONF-CI-002: the adopted canary (harness-onion contract) proves isolation only by a denial errno the named
    # backend is expected to produce: EACCES or EPERM for darwin-sandbox; EACCES, EPERM, ENETUNREACH or EHOSTUNREACH
    # for linux-firejail (firejail --net=none has no route). Anything else fails, and an absent or unrecognized backend
    # is refused before any socket. Unlike the retired R12 canary, it accepts that errno at socket creation, settimeout
    # or connect alike (no stage binding), and it reads only HARNESS_OFFLINE_BACKEND: the bridge requires
    # HARNESS_OFFLINE_ENFORCED=1 and the wrapper a session ID before the canary runs.
    def invoke(self, backend, *, result=None, create_error=None, configure_error=None, connect_error=None):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.connect_ex.return_value = result
        client.connect_ex.side_effect = connect_error
        client.settimeout.side_effect = configure_error
        env = {} if backend is None else {**environment(), "HARNESS_OFFLINE_BACKEND": backend}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(CANARY.socket, "socket", return_value=client, side_effect=create_error) as factory:
            code = CANARY.main()
        return code, factory, client

    def test_backend_specific_permission_denials_pass(self):
        for backend, codes in (("darwin-sandbox", (errno.EPERM, errno.EACCES)),
                               ("linux-firejail", (errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH))):
            for code in codes:
                for kind in ("result", "create_error", "connect_error"):
                    with self.subTest(backend=backend, errno=code, kind=kind):
                        value = code if kind == "result" else OSError(code, "unit denial")
                        self.assertEqual(self.invoke(backend, **{kind: value})[0], 0)

    def test_wrong_stage_permission_denials_fail(self):
        # The adopted canary has no stage binding: its backend's own denial passes at any stage (asserted below), and
        # a denial that is not the named backend's own proof fails, wherever it is raised.
        for stage in ("create_error", "configure_error", "connect_error"):
            with self.subTest(stage=stage):
                self.assertEqual(self.invoke("darwin-sandbox", **{stage: OSError(errno.EPERM, "any stage")})[0], 0)
        for backend, code in (("darwin-sandbox", errno.ENETUNREACH), ("darwin-sandbox", errno.EHOSTUNREACH),
                              ("darwin-sandbox", errno.ECONNREFUSED), ("linux-firejail", errno.ECONNREFUSED)):
            for kind in ("result", "create_error", "configure_error"):
                with self.subTest(backend=backend, errno=code, kind=kind):
                    value = code if kind == "result" else OSError(code, "wrong stage")
                    self.assertEqual(self.invoke(backend, **{kind: value})[0], 1)

    def test_route_dns_timeout_and_unsupported_family_are_not_isolation(self):
        common = [OSError(code, "unit non-proof") for code in (errno.ETIMEDOUT, errno.ECONNREFUSED, errno.EAFNOSUPPORT,
                                                              errno.EPROTONOSUPPORT)] + [TimeoutError(), socket.gaierror(-2, "unit DNS")]
        for backend, errors in (("darwin-sandbox", common + [OSError(errno.ENETUNREACH, "route"), OSError(errno.EHOSTUNREACH, "route")]),
                                ("linux-firejail", common)):
            for error in errors:
                for kind in ("create_error", "connect_error"):
                    with self.subTest(backend=backend, error=error, kind=kind):
                        self.assertEqual(self.invoke(backend, **{kind: error})[0], 1)

    def test_successful_socket_or_connect_is_not_isolation(self):
        for backend in ("darwin-sandbox", "linux-firejail"):
            with self.subTest(backend=backend):
                code, _, client = self.invoke(backend, result=0)
                self.assertEqual(code, 1)
                client.connect_ex.assert_called_once_with(("1.1.1.1", 443))

    def test_absent_unknown_mismatched_marker_never_opens_socket(self):
        for backend in (None, "", "unknown", "Darwin-Sandbox", "linux-firejail ", "firejail"):
            with self.subTest(backend=backend):
                code, factory, _ = self.invoke(backend)
                self.assertEqual(code, 2)
                factory.assert_not_called()


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
