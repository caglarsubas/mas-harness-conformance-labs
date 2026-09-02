from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LOCK_FIELDS = {"schemaVersion", "packetId", "repositorySeed", "authorities", "runtime", "workflow", "dependencies"}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    lock_path = ROOT / "toolchain.lock"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    check(set(lock) == EXPECTED_LOCK_FIELDS, "toolchain lock is not closed")
    check(lock["schemaVersion"] == "harness.planeon.ai/conformance-toolchain-lock/v1alpha1", "toolchain schema mismatch")
    check(lock["packetId"] == "CONF-001" and lock["dependencies"] == [], "packet or dependency lock mismatch")
    check(sys.version_info[:3] == (3, 12, 14), "CPython 3.12.14 is required")
    runtime = lock["runtime"]
    check(sha(Path(runtime["inventoryPath"])) == runtime["inventorySha256"], "Python inventory digest mismatch")
    check(sha(Path(runtime["interpreterPath"])) == runtime["interpreterSha256"], "Python interpreter digest mismatch")
    check(sha(Path(runtime["uvPath"])) == runtime["uvSha256"], "uv digest mismatch")
    uv_version = subprocess.run([runtime["uvPath"], "--version"], check=True, capture_output=True, text=True).stdout
    check(uv_version.startswith("uv 0.12.7 "), "uv version mismatch")
    seed = lock["repositorySeed"]["commit"]
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", seed, "HEAD"], cwd=ROOT, check=False)
    check(ancestry.returncode == 0, "repository seed is not an ancestor")
    seed_tree = subprocess.run(["git", "rev-parse", f"{seed}^{{tree}}"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    check(seed_tree == lock["repositorySeed"]["tree"], "repository seed tree mismatch")
    workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
    check(lock["workflow"]["checkoutCommit"] in workflow and "persist-credentials: false" in workflow, "workflow pin mismatch")
    check("ubuntu-latest" not in workflow and "macos-latest" not in workflow and "windows-latest" not in workflow, "hosted runner is forbidden")
    check((ROOT / "uv.lock").read_text(encoding="utf-8").count("[[package]]") == 1, "dependency-free uv closure mismatch")
    check("HARNESS_WARM_SOURCE_ROOTS" not in os.environ, "warm-source roots reached a packet child")
    for schema in sorted((ROOT / "schemas").glob("**/*.json")):
        value = json.loads(schema.read_text(encoding="utf-8"))
        check(value.get("additionalProperties") is False, f"schema is not closed: {schema.name}")
    from harness_conformance.canonical import load_json
    from harness_conformance.registry import campaign_registry
    from harness_conformance.schema import validate_environment, validate_porting

    campaign_registry(ROOT)
    for fixture in (ROOT / "fixtures/environments").glob("*.json"):
        validate_environment(load_json(fixture))
    porting_text = (ROOT / "PORTING.yaml").read_text(encoding="utf-8")
    check("NO_AUTHORIZATION" in porting_text and "sourceRepository" not in porting_text and "sourcePath" not in porting_text, "PORTING ledger is not inert")
    check(os.environ.get("UV_OFFLINE") == "1" and os.environ.get("UV_NO_SYNC") == "1" and os.environ.get("UV_FROZEN") == "1", "offline uv boundary is absent")
    print("prefetch_status=PASS dependencies=0 network=unused warm_sources=hidden")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
