"""UNIT-only deterministic inputs. Never load a warm source or live credential."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

from harness_conformance.canonical import byte_digest, canonical_bytes, canonical_digest
from harness_conformance.live import command_set_digest
from harness_conformance.live_backend_authority import COMMANDS, PACKET_DIGEST

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-09-07T01:00:00Z"
START = "2026-09-07T00:00:00Z"
END = "2026-09-07T02:00:00Z"
VECTORS = json.loads((ROOT / "fixtures/live-backend/session-vectors.json").read_bytes())


def legacy_fixture(architecture="amd64"):
    # A unique module name avoids flat unittest discovery's _fixtures collision.
    spec = importlib.util.spec_from_file_location("live_backend_legacy_fixture",
        ROOT / "tests/platform/linux_baseline/_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.LinuxFixture(architecture)


def backend_fixture(architecture="amd64"):
    fixture = legacy_fixture(architecture)
    fixture.envelope["packetId"] = "CONF-LIVE-006"
    fixture.envelope["packetDigest"] = PACKET_DIGEST
    fixture.envelope["commands"] = [list(argv) for argv in COMMANDS]
    fixture.envelope["commandSetDigest"] = command_set_digest(fixture.envelope["commands"])
    fixture.plan["regressions"]["conformance"]["testCount"] = 120
    refresh_plan(fixture)
    return fixture


def refresh_plan(fixture):
    raw = canonical_bytes(fixture.plan)
    fixture.release["tree"][0]["sha256"] = byte_digest(raw)
    fixture.release["tree"][0]["size"] = len(raw)
    fixture.release["kitDigest"] = canonical_digest(fixture.release["tree"], "planeon.harness-live-tree/v1alpha1")
    fixture.envelope["conformanceKitDigest"] = fixture.release["kitDigest"]
    fixture.envelope["campaignReleaseDigest"] = byte_digest(canonical_bytes(fixture.release))
    fixture.resign_authority()


def authority_args(fixture):
    return tuple(canonical_bytes(value) for value in (
        fixture.envelope, fixture.capacity, fixture.release_trust, fixture.tenant_trust))


def binding_args(fixture):
    return dict(release_bytes=canonical_bytes(fixture.release), plan_bytes=canonical_bytes(fixture.plan),
        architecture=fixture.plan["target"]["architecture"], expected_nonce=fixture.envelope["nonce"],
        expected_tenant=fixture.envelope["tenantId"], expected_environment=fixture.envelope["environmentId"],
        expected_release=fixture.envelope["campaignReleaseDigest"], now=NOW)


def session_from(binding, state="RUNNING"):
    result = {key: value for key, value in binding.items() if key not in ("notBefore", "notAfter")}
    return {**result, "schemaVersion": VECTORS["session"]["schemaVersion"], "state": state,
            "issuedAt": binding["notBefore"], "expiresAt": binding["notAfter"]}


def receipt_from(fixture, case):
    receipt = deepcopy(next(item for item in fixture.record["cases"] if item["caseId"] == case))
    for name, result in receipt["output"]["regressions"].items():
        result["collected"] = result["executed"] = fixture.plan["regressions"][name]["testCount"]
    receipt["outputDigest"] = canonical_digest(receipt["output"], "planeon.linux-probe-output/v1alpha1")
    return receipt
