from __future__ import annotations

import base64
import csv
import hashlib
import io
import zipfile
from pathlib import Path

NAME = "planeon_harness_conformance"
VERSION = "0.1.0"


def _wheel_bytes() -> bytes:
    root = Path(__file__).parent
    records: list[tuple[str, str, str]] = []
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for source in sorted(root.glob("*.py"), key=lambda item: item.name.encode("utf-8")):
            target = f"harness_conformance/{source.name}"
            data = source.read_bytes()
            info = zipfile.ZipInfo(target, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            records.append((target, f"sha256={digest}", str(len(data))))
        dist = f"{NAME}-{VERSION}.dist-info"
        metadata = f"Metadata-Version: 2.3\nName: planeon-harness-conformance\nVersion: {VERSION}\nLicense-Expression: Apache-2.0\n\n".encode()
        wheel = b"Wheel-Version: 1.0\nGenerator: planeon\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        for target, data in ((f"{dist}/METADATA", metadata), (f"{dist}/WHEEL", wheel)):
            info = zipfile.ZipInfo(target, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            records.append((target, f"sha256={digest}", str(len(data))))
        record_path = f"{dist}/RECORD"
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerows(records + [(record_path, "", "")])
        info = zipfile.ZipInfo(record_path, (1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o100644 << 16
        archive.writestr(info, stream.getvalue().encode())
    return output.getvalue()


def build_wheel(wheel_directory: str, config_settings=None, metadata_directory=None) -> str:
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    (Path(wheel_directory) / filename).write_bytes(_wheel_bytes())
    return filename


def build_sdist(sdist_directory: str, config_settings=None) -> str:
    raise RuntimeError("sdist construction is intentionally outside CONF-001")
