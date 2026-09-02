from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FORBIDDEN = (
    "ubuntu-latest", "macos-latest", "windows-latest", "schedule:",
    "upload-artifact", "download-artifact", "actions/cache", "docker/login-action",
    "packages: write", "id-token: write",
)
SOURCE_FORBIDDEN = (
    "import requests", "import urllib", "boto3", "google.cloud", "azure.identity",
    "subprocess.run([\"curl\"", "subprocess.run([\"wget\"",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate(root: Path) -> None:
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    require(len(workflows) == 1, "exactly one pinned workflow is permitted")
    workflow = workflows[0].read_text(encoding="utf-8").lower()
    for token in WORKFLOW_FORBIDDEN:
        require(token not in workflow, f"forbidden workflow billing vector: {token}")
    require("self-hosted" in workflow and "credential-free" in workflow and "persist-credentials: false" in workflow, "self-hosted credential-free workflow boundary is missing")
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    require("dependencies = []" in project and "https://" not in project, "external package dependency is forbidden")
    lock = json.loads((root / "toolchain.lock").read_text(encoding="utf-8"))
    require(lock["dependencies"] == [] and lock["workflow"]["hostedRunner"] is False, "toolchain lock permits a billable dependency")
    source_text = "\n".join(path.read_text(encoding="utf-8") for path in sorted((root / "src").glob("**/*.py")))
    for token in SOURCE_FORBIDDEN:
        require(token not in source_text, f"runtime network or provider dependency is forbidden: {token}")
    for path in root.rglob("*"):
        if path.is_symlink():
            require(False, f"repository symlink is forbidden: {path.relative_to(root)}")


def main() -> int:
    validate(ROOT)
    print("zero_bill_status=PASS hosted_runners=0 remote_artifacts=0 paid_apis=0 runtime_downloads=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
