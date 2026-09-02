from __future__ import annotations

import errno
import os
import socket


def main() -> int:
    if os.environ.get("HARNESS_OFFLINE_ENFORCED") != "1":
        raise RuntimeError("offline enforcement marker is absent")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.25)
    try:
        probe.connect(("1.1.1.1", 443))
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT):
            raise
        print(f"offline_network_status=PASS errno={exc.errno}")
        return 0
    finally:
        probe.close()
    raise RuntimeError("outbound network was not denied")


if __name__ == "__main__":
    raise SystemExit(main())
