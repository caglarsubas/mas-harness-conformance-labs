from __future__ import annotations

import json
import os
import subprocess
import sys


def refuse(message: str) -> "NoReturn":
    print(json.dumps({"reasonCode": "DIRECT_LIVE_ADAPTER_FORBIDDEN", "status": "FAIL", "message": message}, separators=(",", ":")), file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str]) -> int:
    if any(os.environ.get(name) for name in ("CI", "GITHUB_ACTIONS", "GITHUB_EVENT_NAME")):
        refuse("live adapter cannot run in CI")
    descriptor_value = os.environ.get("HARNESS_LIVE_SESSION_FD")
    if not descriptor_value or not descriptor_value.isdecimal():
        refuse("external live session proof descriptor is absent")
    descriptor = int(descriptor_value)
    try:
        inheritable = os.get_inheritable(descriptor)
        proof = os.read(descriptor, 4096)
    except OSError:
        refuse("external live session proof descriptor is invalid")
    if inheritable or proof != b'{"boundary":"SIGNED_ENDPOINT_ALLOWLIST","status":"ENTERED"}\n':
        refuse("external live session proof is invalid")
    if not argv or argv[0] != "--" or len(argv) < 2:
        refuse("verified direct argv is required")
    if os.path.basename(argv[1]) in {"sh", "bash", "zsh", "fish", "dash"}:
        refuse("shell transport is forbidden")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("HARNESS_LIVE_")}
    return subprocess.run(argv[1:], env=environment, check=False, close_fds=True).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
