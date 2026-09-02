from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

FIELDS = ("id", "repository", "warmSourceAccess", "prefetchCommands", "offlineAcceptanceCommands", "offlineExecution")
SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"}
DOWNLOAD_TOKENS = {"fetch", "download", "install", "pull", "clone", "curl", "wget", "pip", "npm", "npx"}


def refuse(message: str) -> "NoReturn":
    print(f"packet runner refused: {message}", file=sys.stderr)
    raise SystemExit(2)


def read_once(path: Path) -> tuple[int, os.stat_result, bytes]:
    if not path.is_absolute() or ".." in path.parts:
        refuse("packet path must be absolute and canonical")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        refuse("packet path is unavailable")
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o444:
        os.close(descriptor)
        refuse("packet custody is invalid")
    data = b""
    while len(data) <= 4 * 1024 * 1024:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        data += block
    if len(data) != info.st_size or len(data) > 4 * 1024 * 1024:
        os.close(descriptor)
        refuse("packet size or read stability is invalid")
    return descriptor, info, data


def extract(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in FIELDS:
        matches = re.findall(rf"(?m)^{re.escape(field)}:[ \t]*(.*)$", text)
        if len(matches) != 1:
            refuse(f"packet has missing or duplicate {field}")
        raw = matches[0].strip()
        if field in ("prefetchCommands", "offlineAcceptanceCommands", "offlineExecution"):
            try:
                result[field] = json.loads(raw)
            except json.JSONDecodeError:
                refuse(f"packet {field} must be inline JSON")
        else:
            if not raw or raw[0] in "[{&*!|>":
                refuse(f"packet {field} must be a scalar without YAML indirection")
            result[field] = raw
    return result


def validate_commands(value: Any, *, allow_empty: bool, phase: str) -> list[list[str]]:
    if not isinstance(value, list) or (not value and not allow_empty):
        refuse("command phase is not a valid array")
    commands: list[list[str]] = []
    for command in value:
        if not isinstance(command, list) or not command or len(command) > 32:
            refuse("command must be a bounded argv array")
        if any(not isinstance(item, str) or not item or len(item) > 4096 for item in command):
            refuse("command arguments must be bounded strings")
        executable = Path(command[0]).name.lower()
        tokens = {Path(item).name.lower() for item in command}
        if executable in SHELLS or executable in DOWNLOAD_TOKENS or tokens & DOWNLOAD_TOKENS:
            refuse("shell or download transport is forbidden")
        if command[:2] == ["make", "verify-offline"] or (
            phase == "offline" and command[:2] == ["make", "prefetch"]
        ):
            refuse("recursive offline or hidden prefetch command is forbidden")
        commands.append(command)
    return commands


def validate_packet(document: dict[str, Any]) -> tuple[list[list[str]], list[list[str]]]:
    if document["repository"] != "mas-harness-conformance-labs" or not re.fullmatch(r"CONF-[A-Z0-9-]+", document["id"]):
        refuse("packet repository or ID is invalid")
    if document["warmSourceAccess"] != "PROHIBITED_DURING_IMPLEMENTATION":
        refuse("warm-source prohibition is absent")
    expected = {
        "wrapperArgv": ["./ci/verify-offline.sh"],
        "packetPathEnvironment": "HARNESS_TASK_PACKET",
        "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
        "commandTransport": "ARGV_ARRAY_V1",
        "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
        "sessionScope": "SINGLE_PROCESS_TREE",
        "prefetchOutsideSession": False,
        "offlineEnvironment": {"UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1"},
    }
    if document["offlineExecution"] != expected:
        refuse("offlineExecution contract mismatch")
    return (
        validate_commands(document["prefetchCommands"], allow_empty=True, phase="prefetch"),
        validate_commands(document["offlineAcceptanceCommands"], allow_empty=False, phase="offline"),
    )


def still_same(path: Path, descriptor: int, original: os.stat_result, digest: str) -> None:
    current_fd = os.fstat(descriptor)
    try:
        current_path = path.stat(follow_symlinks=False)
    except OSError:
        refuse("packet path disappeared")
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_mode, item.st_uid, item.st_gid)
    if identity(current_fd) != identity(original) or identity(current_path) != identity(original):
        refuse("packet changed during execution")
    if hashlib.sha256(os.pread(descriptor, original.st_size, 0)).hexdigest() != digest:
        refuse("packet digest changed during execution")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        refuse("one packet path is required")
    if os.environ.get("HARNESS_OFFLINE_ENFORCED") != "1" or os.environ.get("HARNESS_OFFLINE_BACKEND") != "darwin-sandbox" or not os.environ.get("HARNESS_OFFLINE_SESSION_ID"):
        refuse("existing OS-isolated session is required")
    if os.environ.get("HARNESS_WARM_SOURCE_ROOTS"):
        refuse("warm-source roots reached the packet runner")
    path = Path(argv[0])
    descriptor, info, data = read_once(path)
    try:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            refuse("packet is not UTF-8")
        packet = extract(text)
        prefetch, acceptance = validate_packet(packet)
        packet_digest = hashlib.sha256(data).hexdigest()
        child_environment = os.environ.copy()
        child_environment.pop("HARNESS_TASK_PACKET", None)
        child_environment.pop("HARNESS_WARM_SOURCE_ROOTS", None)
        network = subprocess.run([sys.executable, "ci/network_canary.py"], env=child_environment, check=False)
        if network.returncode:
            return network.returncode
        still_same(path, descriptor, info, packet_digest)
        for phase, commands in (("prefetch", prefetch), ("offline", acceptance)):
            for command in commands:
                print(f"{phase}-argv=" + json.dumps(command, separators=(",", ":")))
                completed = subprocess.run(command, env=child_environment, check=False)
                still_same(path, descriptor, info, packet_digest)
                if completed.returncode:
                    return completed.returncode
        print(f"packet={packet_digest} packetId={packet['id']} phases=prefetch,offline session={os.environ['HARNESS_OFFLINE_SESSION_ID']}")
        return 0
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
