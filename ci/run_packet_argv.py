"""Fixed transport bridge; only the external launcher establishes isolation."""
from __future__ import annotations

import sys

from run_packet import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
