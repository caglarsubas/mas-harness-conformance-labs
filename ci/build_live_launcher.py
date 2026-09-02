from __future__ import annotations

import argparse
import hashlib
import io
import os
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "harness_conformance"
SHEBANG = b"#!/usr/bin/env python3\n"


def build(output: Path) -> str:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_STORED) as archive:
        entry = zipfile.ZipInfo("__main__.py", (1980, 1, 1, 0, 0, 0))
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, b"from harness_conformance.live_launcher import main\nraise SystemExit(main())\n")
        for path in sorted(SOURCE.glob("*.py"), key=lambda item: item.name.encode("utf-8")):
            info = zipfile.ZipInfo(f"harness_conformance/{path.name}", (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
        root_key = ROOT / "ci/trust/live-runner-root.pub"
        info = zipfile.ZipInfo("harness_conformance/live-runner-root.pub", (1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o100444 << 16
        archive.writestr(info, root_key.read_bytes())
    data = SHEBANG + archive_bytes.getvalue()
    output.write_bytes(data)
    output.chmod(0o555)
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--verify-reproducible", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify_reproducible:
        with tempfile.TemporaryDirectory(prefix="planeon-live-build-") as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            first_digest = build(first)
            second_digest = build(second)
            if first_digest != second_digest or first.read_bytes() != second.read_bytes():
                raise SystemExit("live launcher build is not reproducible")
            print(f"live_launcher_candidate_status=PASS sha256={first_digest} authority=UNINSTALLED_CANDIDATE")
            return 0
    if args.output is None or not args.output.is_absolute():
        raise SystemExit("--output must be an absolute local path")
    digest = build(args.output)
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
