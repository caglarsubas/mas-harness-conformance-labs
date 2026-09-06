from __future__ import annotations

import errno
import os
import socket
import sys


def main() -> int:
    backend = {"darwin": "darwin-sandbox", "linux": "linux-firejail"}.get(sys.platform)
    if (backend is None or os.environ.get("HARNESS_OFFLINE_ENFORCED") != "1"
            or os.environ.get("HARNESS_OFFLINE_BACKEND") != backend
            or not os.environ.get("HARNESS_OFFLINE_SESSION_ID")):
        raise RuntimeError("matching pre-established OS boundary is absent")
    # Firejail's protocol restriction denies inet socket creation; Darwin's
    # sandbox permits creation but denies connect. Other failures are not proof.
    probe = None
    stage = "socket"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if backend == "linux-firejail":
            raise RuntimeError("Linux inet socket creation was not denied")
        stage = "configure"
        probe.settimeout(0.25)
        stage = "connect"
        probe.connect(("1.1.1.1", 443))
    except OSError as exc:
        expected_stage = "socket" if backend == "linux-firejail" else "connect"
        if stage != expected_stage or exc.errno not in (errno.EPERM, errno.EACCES):
            raise
        print(f"offline_network_status=PASS backend={backend} stage={stage} errno={exc.errno}")
        return 0
    finally:
        if probe is not None:
            probe.close()
    raise RuntimeError("outbound network was not denied")


if __name__ == "__main__":
    raise SystemExit(main())
