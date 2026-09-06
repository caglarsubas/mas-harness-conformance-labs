from __future__ import annotations

import json
import sys


def refuse(message: str) -> "NoReturn":
    print(json.dumps({"reasonCode": "DIRECT_LIVE_ADAPTER_FORBIDDEN", "status": "FAIL", "message": message}, separators=(",", ":")), file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str]) -> int:
    # Retired: caller-controlled descriptors and markers cannot prove authority.
    # A future usable bridge requires separately reviewed external installation.
    refuse("repository live adapter is retired; no caller input grants live authority")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
