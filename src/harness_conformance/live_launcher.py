from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from .canonical import byte_digest, load_json_bytes, secure_read
from .crypto import b64url_decode, verify
from .errors import ConformanceError
from .live import (
    EXPECTED_LAUNCHER,
    FIXED_MANIFEST,
    FIXED_MANIFEST_PUBLIC,
    FIXED_MANIFEST_SIGNATURE,
    PINNED_ROOT_PUBLIC_KEY_SHA256,
    preflight,
)
from .schema import closed


def _verify_root_manifest() -> None:
    public_bytes = secure_read(FIXED_MANIFEST_PUBLIC, require_absolute=True)
    if byte_digest(public_bytes) != PINNED_ROOT_PUBLIC_KEY_SHA256:
        raise ConformanceError("ROOT_KEY_DIGEST_MISMATCH", "live-runner root key digest does not match")
    public_record = load_json_bytes(public_bytes)
    closed(public_record, ("algorithm", "publicKey"))
    if public_record["algorithm"] != "ED25519":
        raise ConformanceError("ROOT_KEY_ALGORITHM", "live-runner root key algorithm is invalid")
    manifest_bytes = secure_read(FIXED_MANIFEST, require_absolute=True)
    signature = b64url_decode(secure_read(FIXED_MANIFEST_SIGNATURE, require_absolute=True).decode("ascii").strip(), expected_length=64)
    public = b64url_decode(public_record["publicKey"], expected_length=32)
    if not verify(public, manifest_bytes, signature):
        raise ConformanceError("ROOT_MANIFEST_SIGNATURE_INVALID", "live-runner manifest signature is invalid")
    manifest = load_json_bytes(manifest_bytes)
    closed(manifest, ("schemaVersion", "launcher", "fixedTrustMounts", "isolation", "preflightEvidenceDigest"))
    if manifest["schemaVersion"] != "harness.planeon.ai/live-runner-manifest/v1alpha1":
        raise ConformanceError("ROOT_MANIFEST_SCHEMA", "live-runner manifest schema is invalid")
    launcher = manifest["launcher"]
    closed(launcher, ("path", "version", "sha256", "ownerUid", "ownerGid", "mode"))
    info = EXPECTED_LAUNCHER.stat()
    expected = {
        "path": str(EXPECTED_LAUNCHER),
        "version": "0.1.0",
        "sha256": byte_digest(secure_read(EXPECTED_LAUNCHER, require_absolute=True)),
        "ownerUid": 0,
        "ownerGid": 0,
        "mode": "0555",
    }
    actual = dict(launcher)
    if actual != expected or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o555:
        raise ConformanceError("LAUNCHER_CUSTODY_INVALID", "installed launcher custody does not match")
    if manifest["fixedTrustMounts"] != ["/etc/planeon/trust/release-trust-bundle.json", "/etc/planeon/trust/tenant-trust-bundle.json"]:
        raise ConformanceError("TRUST_MOUNTS_INVALID", "fixed trust mounts do not match")
    isolation = manifest["isolation"]
    closed(isolation, ("backend", "networkPolicy", "credentialSocketsDenied", "ciDenied"))
    if isolation != {
        "backend": "PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1",
        "networkPolicy": "DENY_ALL_EXCEPT_DUAL_SIGNED_ENDPOINTS",
        "credentialSocketsDenied": True,
        "ciDenied": True,
    }:
        raise ConformanceError("ISOLATION_MANIFEST_INVALID", "live isolation manifest is invalid")


def main() -> int:
    try:
        if any(os.environ.get(name) for name in ("CI", "GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "BUILDKITE", "JENKINS_URL")):
            raise ConformanceError("CI_EXECUTION_FORBIDDEN", "live launcher cannot run in CI")
        extra = sorted(name for name in os.environ if name.startswith("HARNESS_LIVE_") and name != "HARNESS_LIVE_EXECUTION_ENVELOPE")
        if extra:
            raise ConformanceError("LIVE_ENVIRONMENT_FORBIDDEN", "unexpected live authority environment")
        envelope = os.environ.get("HARNESS_LIVE_EXECUTION_ENVELOPE")
        if not envelope:
            raise ConformanceError("LIVE_AUTHORITY_UNAVAILABLE", "live execution envelope is unavailable")
        if Path(sys.argv[0]).resolve() != EXPECTED_LAUNCHER:
            raise ConformanceError("DIRECT_LAUNCH_FORBIDDEN", "candidate has no authority outside the installed path")
        _verify_root_manifest()
        result = preflight(Path(envelope), launcher_path=EXPECTED_LAUNCHER)
        raise ConformanceError("ISOLATION_BACKEND_UNAVAILABLE", "preinstalled signed endpoint isolation has not entered a child session")
    except ConformanceError as exc:
        unavailable = exc.reason in {"LIVE_AUTHORITY_UNAVAILABLE", "ISOLATION_BACKEND_UNAVAILABLE", "REFERENCE_UNAVAILABLE"}
        status = "NOT_RUN_ENV_UNAVAILABLE" if unavailable else "FAIL"
        sys.stderr.write(json.dumps({"reasonCode": exc.reason, "status": status}, separators=(",", ":")) + "\n")
        return 3 if unavailable else 2
    else:
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
        return 0
