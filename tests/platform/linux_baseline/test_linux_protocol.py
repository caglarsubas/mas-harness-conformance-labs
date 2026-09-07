from copy import deepcopy
import re
import unittest
from unittest.mock import patch

from _fixtures import LinuxFixture, ROOT, digest
from harness_conformance.canonical import canonical_bytes, load_json
from harness_conformance.errors import ConformanceError
from harness_conformance.linux_readiness import CASES, build_probe_request, validate_linux_evidence, verify_linux_evidence


def schema_assert(value, schema):
    """Independent test-only interpreter for the published schema vocabulary."""
    if "const" in schema:
        assert canonical_bytes(value) == canonical_bytes(schema["const"])
    if "enum" in schema:
        assert any(canonical_bytes(value) == canonical_bytes(item) for item in schema["enum"])
    if "type" in schema:
        assert type(value) is {"object": dict, "array": list, "integer": int, "string": str, "boolean": bool}[schema["type"]]
    for conditional in schema.get("allOf", []):
        if "if" in conditional:
            try:
                schema_assert(value, conditional["if"])
            except AssertionError:
                continue
            schema_assert(value, conditional["then"])
        else:
            schema_assert(value, conditional)
    if isinstance(value, dict):
        assert set(schema.get("required", [])) <= value.keys()
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            assert value.keys() <= properties.keys()
        for key in value.keys() & properties.keys():
            schema_assert(value[key], properties[key])
    if isinstance(value, list):
        assert schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10000000)
        prefix = schema.get("prefixItems", [])
        if schema.get("items") is False:
            assert len(value) <= len(prefix)
        for item, definition in zip(value, prefix):
            schema_assert(item, definition)
        if isinstance(schema.get("items"), dict):
            for item in value[len(prefix):]:
                schema_assert(item, schema["items"])
    if isinstance(value, str):
        assert schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 10000000)
        if "pattern" in schema:
            assert re.search(schema["pattern"], value)
    if type(value) is int:
        assert schema.get("minimum", 0) <= value <= schema.get("maximum", 10000000)


class LinuxProtocolTests(unittest.TestCase):
    def test_published_schema_covers_all_nested_records_and_plans(self):
        schema = load_json(ROOT / "schemas/v1alpha1/linux-readiness-evidence.schema.json")
        for arch in ("amd64", "arm64"):
            fixture = LinuxFixture(arch)
            schema_assert(fixture.record, schema)
            schema_assert(fixture.plan, schema["$defs"]["plan"])
        self.assertEqual([item["properties"]["caseId"]["const"] for item in schema["properties"]["cases"]["prefixItems"]], list(CASES))

    def test_schema_and_runtime_both_reject_structural_mutations(self):
        schema = load_json(ROOT / "schemas/v1alpha1/linux-readiness-evidence.schema.json")
        original = LinuxFixture().record
        for path, value in ((("target", "execution"), "EMULATED"), (("target", "hostArchitecture"), "arm64"),
                            (("target", "os"), "darwin"), (("cases",), []), (("images", "control"), "latest"),
                            (("cases", 0, "status"), "WARN"), (("cases", 0, "runNonce"), ""),
                            (("cases", 2, "output", "regressions", "control", "executed"), True)):
            changed = deepcopy(original)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(AssertionError):
                schema_assert(changed, schema)
            with self.subTest(runtime=path), self.assertRaises(ConformanceError):
                validate_linux_evidence(changed)

    def test_proxy_operations_are_fixed_data_only_and_do_not_open_io(self):
        fixture = LinuxFixture()
        with patch("builtins.open", side_effect=AssertionError("file access")), patch("socket.socket", side_effect=AssertionError("socket access")), patch("subprocess.run", side_effect=AssertionError("process access")):
            for case in CASES:
                request = build_probe_request(fixture.envelope, fixture.capacity, fixture.plan, case)
                self.assertEqual(request["operation"], case)
                self.assertEqual(request["method"], "POST")
                self.assertEqual(request["runNonce"], "unit-run-nonce")
                self.assertEqual(request["namespace"], "unit-namespace")
                self.assertEqual(request["path"], "/v1/linux-baseline/" + case.lower().replace("_", "-"))
                self.assertNotIn("credential", str(request).lower())
                self.assertNotIn("url", request)

    def test_fake_proxy_is_unit_only_and_cannot_supply_runtime_authority(self):
        fixture = LinuxFixture()
        requests = [build_probe_request(fixture.envelope, fixture.capacity, fixture.plan, case) for case in CASES]
        self.assertEqual([request["operation"] for request in requests], list(CASES))
        result = verify_linux_evidence(canonical_bytes(fixture.record), **fixture.inputs())
        self.assertEqual(result["verificationStatus"], "PASS")
        self.assertEqual(result["evidenceClass"], "UNIT_VERIFICATION_ONLY")
        self.assertFalse(result["nativeAcceptance"])

    def test_unknown_operations_and_scope_or_policy_expansion_fail(self):
        original = LinuxFixture()
        for operation in ("EXEC", "PROVISION", "DELETE_NAMESPACE", "sh", "/bin/true", "https://example.invalid", None, []):
            with self.subTest(operation=operation), self.assertRaises(ConformanceError):
                build_probe_request(original.envelope, original.capacity, original.plan, operation)
        for field, value in (("namespace", "other"), ("methods", ["GET", "POST"]), ("paths", ["/*"]),
                             ("service", "other"), ("port", 443), ("requestMaxBytes", True), ("timeoutSeconds", 10000),
                             ("protocol", "HTTP"), ("endpointId", "other"), ("responseMediaType", "text/plain")):
            fixture = deepcopy(original)
            fixture.capacity["campaignProxyRules"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                build_probe_request(fixture.envelope, fixture.capacity, fixture.plan, CASES[0])
        fixture = deepcopy(original)
        fixture.envelope["endpoints"][0]["authorizationPolicyDigest"] = digest("wrong")
        with self.assertRaises(ConformanceError):
            build_probe_request(fixture.envelope, fixture.capacity, fixture.plan, CASES[0])

    def test_dual_envelope_commands_axes_endpoint_and_capacity_mismatch_fail(self):
        original = LinuxFixture()
        mutations = [("packetId", "CONF-A1-001"), ("packetDigest", digest("wrong")), ("campaignId", "other"),
                     ("commands", [["sh", "-c", "true"]]), ("allowedEvidenceAxes", ["TENANT_ACCEPTANCE"]),
                     ("nonce", "other-run"), ("tenantId", "other-tenant"), ("mutationProfile", "ALLOW_ALL")]
        for field, value in mutations:
            fixture = deepcopy(original)
            fixture.envelope[field] = value
            fixture.resign_authority()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                verify_linux_evidence(canonical_bytes(fixture.record), **fixture.inputs())
        for field, value in (("ipAddress", "8.8.8.8"), ("ipAddress", "169.254.169.254"), ("discovery", True),
                             ("kind", "LOCAL_REGISTRY"), ("costDisposition", "METERED"), ("port", True)):
            fixture = deepcopy(original)
            fixture.endpoint[field] = value
            fixture.resign_authority()
            fixture.record["authority"] = fixture.bindings()
            fixture.resign_record()
            with self.subTest(endpoint=field), self.assertRaises(ConformanceError):
                verify_linux_evidence(canonical_bytes(fixture.record), **fixture.inputs())
