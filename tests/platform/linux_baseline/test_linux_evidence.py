from copy import deepcopy
import unittest

from _fixtures import LinuxFixture, NOW, digest
from harness_conformance.canonical import canonical_bytes, canonical_digest
from harness_conformance.crypto import b64url_encode
from harness_conformance.errors import ConformanceError
from harness_conformance.linux_readiness import (AUTHORITY_FIELDS, BUILD_FIELDS, CASES, IMAGES, RECORD_FIELDS, REPOSITORIES, SCHEMA, SIGNATURES, validate_linux_evidence, validate_plan, verify_linux_evidence)


class LinuxEvidenceTests(unittest.TestCase):
    def verify(self, fixture, **overrides):
        return verify_linux_evidence(canonical_bytes(fixture.record), **(fixture.inputs() | overrides))

    def test_both_native_architecture_vectors_are_unit_only(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                fixture = LinuxFixture(arch)
                result = self.verify(fixture)
                self.assertEqual(result["verificationStatus"], "PASS")
                self.assertEqual(result["architecture"], arch)
                self.assertFalse(result["nativeAcceptance"])
                self.assertEqual(result["evidenceClass"], "UNIT_VERIFICATION_ONLY")
                self.assertEqual(list(result["caseResults"]), list(CASES))
                self.assertEqual(result, self.verify(fixture))

    def test_every_record_field_is_mandatory(self):
        original = LinuxFixture()
        for field in RECORD_FIELDS:
            fixture = deepcopy(original)
            del fixture.record[field]
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_unknown_nested_fields_and_verification_booleans_are_rejected(self):
        original = LinuxFixture()
        paths = [(), ("authority",), ("target",), ("build",), ("sources",), ("images",),
                 ("cases", 0), ("cases", 0, "output"), ("cases", 0, "output", "checks")]
        for path in paths:
            fixture = deepcopy(original)
            target = fixture.record
            for key in path:
                target = target[key]
            target["signatureVerified"] = True
            fixture.resign_record()
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_every_binding_is_compared_even_with_valid_record_signatures(self):
        original = LinuxFixture()
        for field in AUTHORITY_FIELDS:
            fixture = deepcopy(original)
            fixture.record["authority"][field] = digest("wrong") if field.endswith("Digest") else "wrong-binding"
            fixture.resign_record()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_every_source_image_build_and_host_binding_is_exact(self):
        paths = [("sources", name, field) for name in REPOSITORIES for field in ("commit", "treeDigest")]
        paths += [("images", name) for name in IMAGES] + [("build", name) for name in BUILD_FIELDS]
        paths += [("preflightDigest",), ("target", "kernel"), ("target", "libc")]
        original = LinuxFixture()
        for path in paths:
            fixture = deepcopy(original)
            obj = fixture.record
            for key in path[:-1]:
                obj = obj[key]
            obj[path[-1]] = "f" * 40 if path[-1] == "commit" else "wrong" if path[-1] in ("kernel", "libc") else digest("wrong")
            fixture.resign_record()
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_emulated_cross_arch_and_non_linux_never_qualify(self):
        for field, value in (("os", "darwin"), ("execution", "EMULATED"), ("hostArchitecture", "arm64"), ("architecture", "riscv64"), ("architecture", ["amd64"])):
            fixture = LinuxFixture()
            fixture.record["target"][field] = value
            fixture.resign_record()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_all_cases_are_required_ordered_and_unique(self):
        original = LinuxFixture()
        for index in range(len(CASES)):
            for operation in ("remove", "duplicate", "reorder"):
                fixture = deepcopy(original)
                if operation == "remove":
                    fixture.record["cases"].pop(index)
                elif operation == "duplicate":
                    fixture.record["cases"][index] = deepcopy(fixture.record["cases"][(index + 1) % len(CASES)])
                else:
                    fixture.record["cases"].append(fixture.record["cases"].pop(index))
                    if index == len(CASES) - 1:
                        fixture.record["cases"].reverse()
                fixture.resign_record()
                with self.subTest(index=index, operation=operation), self.assertRaises(ConformanceError):
                    self.verify(fixture)

    def test_each_probe_command_output_nonce_and_time_is_bound(self):
        original = LinuxFixture()
        for index in range(len(CASES)):
            for field in ("probeDigest", "commandDigest", "outputDigest", "runNonce", "observedAt"):
                fixture = deepcopy(original)
                value = "old-run" if field == "runNonce" else "2025-01-01T00:00:00Z" if field == "observedAt" else digest("wrong")
                fixture.record["cases"][index][field] = value
                if field != "outputDigest":
                    fixture.resign_record()
                with self.subTest(index=index, field=field), self.assertRaises(ConformanceError):
                    self.verify(fixture)

    def test_each_missing_check_and_false_pass_is_rejected(self):
        original = LinuxFixture()
        for index, case in enumerate(original.record["cases"]):
            for check in case["output"]["checks"]:
                for state in (None, "FAIL", "NOT_RUN_ENV_UNAVAILABLE", True):
                    fixture = deepcopy(original)
                    if state is None:
                        del fixture.record["cases"][index]["output"]["checks"][check]
                    else:
                        fixture.record["cases"][index]["output"]["checks"][check] = state
                    fixture.resign_record()
                    with self.subTest(case=index, check=check, state=state), self.assertRaises(ConformanceError):
                        self.verify(fixture)

    def test_executed_failure_and_missing_environment_remain_distinct(self):
        for status in ("FAIL", "NOT_RUN_ENV_UNAVAILABLE"):
            fixture = LinuxFixture()
            case = fixture.record["cases"][0]
            case["output"]["checks"]["ipv4-denied"] = status
            case["status"] = status
            fixture.resign_record()
            self.assertEqual(self.verify(fixture)["verificationStatus"], status)

    def test_regression_inventory_counts_skips_and_hidden_deselection_fail(self):
        original = LinuxFixture()
        for name in REPOSITORIES:
            for field, value in (("inventoryDigest", digest("wrong")), ("collected", 0), ("executed", 0), ("skipped", 1), ("failed", 1), ("collected", True)):
                fixture = deepcopy(original)
                fixture.record["cases"][2]["output"]["regressions"][name][field] = value
                fixture.resign_record()
                with self.subTest(name=name, field=field), self.assertRaises(ConformanceError):
                    self.verify(fixture)

    def test_every_signature_is_independently_required(self):
        original = LinuxFixture()
        for field in SIGNATURES:
            fixture = deepcopy(original)
            fixture.record[field] = b64url_encode(b"\x00" * 64)
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_expired_future_boundary_and_replay_inputs_fail(self):
        fixture = LinuxFixture()
        overrides = [{"now": "2026-09-07T02:00:00Z"}, {"now": "2026-09-06T23:00:00Z"},
                     {"expected_nonce": "another-run"}, {"expected_tenant": "another-tenant"},
                     {"expected_environment": "another-environment"}, {"expected_release": digest("wrong")},
                     {"replayed_nonces": frozenset({"unit-run-nonce"})}, {"replayed_nonces": set()},
                     {"now": "2026-09-14T02:00:00Z"}]
        for values in overrides:
            with self.subTest(values=values), self.assertRaises(ConformanceError):
                self.verify(fixture, **values)
        for field, value in (("observedAt", "2026-09-07T01:01:00Z"), ("observedAt", "2026-08-01T00:00:00Z"),
                             ("validUntil", NOW), ("validUntil", "2026-09-15T00:00:00Z")):
            changed = deepcopy(fixture)
            changed.record[field] = value
            changed.resign_record()
            with self.subTest(field=field, value=value), self.assertRaises(ConformanceError):
                self.verify(changed)

    def test_role_scope_owner_revocation_and_validity_fail_closed(self):
        original = LinuxFixture()
        for bundle_name, indexes in (("release_trust", [0]), ("tenant_trust", [0, 1])):
            for index in indexes:
                for field, value in (("purpose", "TECHNICAL_EVIDENCE"), ("tenantId", "other-tenant"), ("environmentId", "other-environment"),
                                     ("revoked", True), ("revoked", 0), ("validFrom", "2027-01-01T00:00:00Z"),
                                     ("validUntil", "2026-09-07T00:59:00Z"), ("publicKey", b64url_encode(b"\x00" * 32))):
                    fixture = deepcopy(original)
                    getattr(fixture, bundle_name)["keys"][index][field] = value
                    fixture.resign_authority()
                    fixture.record["authority"] = fixture.bindings()
                    fixture.resign_record()
                    with self.subTest(bundle=bundle_name, index=index, field=field), self.assertRaises(ConformanceError):
                        self.verify(fixture)
        fixture = deepcopy(original)
        fixture.tenant_trust["keys"][1]["owner"] = fixture.tenant_trust["keys"][0]["owner"]
        fixture.resign_authority()
        fixture.record["authority"] = fixture.bindings()
        fixture.resign_record()
        with self.assertRaises(ConformanceError):
            self.verify(fixture)

    def test_observation_and_expiration_fit_both_authorizations(self):
        for field, value in (("issuedAt", "2026-09-07T00:45:00Z"), ("expiresAt", "2026-09-07T01:30:00Z")):
            fixture = LinuxFixture()
            fixture.envelope[field] = value
            fixture.resign_authority()
            fixture.record["authority"] = fixture.bindings()
            fixture.resign_record()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_duplicate_keys_changed_trust_bytes_and_same_signers_fail(self):
        fixture = LinuxFixture()
        for field in ("release_trust_bytes", "tenant_trust_bytes", "capacity_bytes", "release_bytes", "plan_bytes"):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture, **{field: fixture.inputs()[field] + b"\n"})
        fixture.tenant_trust["keys"].append(deepcopy(fixture.tenant_trust["keys"][0]))
        fixture.resign_authority()
        with self.assertRaises(ConformanceError):
            self.verify(fixture)
        fixture = LinuxFixture()
        fixture.record["tenantSignerKeyId"] = fixture.record["platformSignerKeyId"]
        fixture.resign_record()
        with self.assertRaises(ConformanceError):
            self.verify(fixture)

    def test_release_tree_paths_modes_sizes_and_baseline_pins_are_closed(self):
        original = LinuxFixture()
        for field, value in (("path", "../inputs/amd64.json"), ("path", "/absolute"), ("path", "other.json"),
                             ("mode", "0644"), ("size", 0), ("sha256", digest("wrong"))):
            fixture = deepcopy(original)
            fixture.release["tree"][0][field] = value
            fixture.release["kitDigest"] = canonical_digest(fixture.release["tree"], "planeon.harness-live-tree/v1alpha1")
            fixture.envelope["conformanceKitDigest"] = fixture.release["kitDigest"]
            from harness_conformance.canonical import byte_digest
            fixture.envelope["campaignReleaseDigest"] = byte_digest(canonical_bytes(fixture.release))
            fixture.resign_authority()
            fixture.record["authority"] = fixture.bindings()
            fixture.resign_record()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.verify(fixture)

    def test_plan_rejects_missing_extra_or_incomplete_regression_fields(self):
        fixture = LinuxFixture()
        for key in fixture.plan:
            changed = deepcopy(fixture.plan)
            del changed[key]
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                validate_plan(changed)
        for count in (0, 82, True, -1, 10000001):
            changed = deepcopy(fixture.plan)
            changed["regressions"]["conformance"]["testCount"] = count
            with self.subTest(count=count), self.assertRaises(ConformanceError):
                validate_plan(changed)

    def test_duplicate_json_floats_invalid_utf8_and_malformed_inputs_fail(self):
        fixture = LinuxFixture()
        for raw in (b'{"x":1,"x":2}', b'{"x":1.2}', b'{"x":NaN}', b'\xff', b'[]', b'null', b'{}', b'{}' * 2200000, b'[' * 2000 + b'0' + b']' * 2000):
            with self.subTest(raw=raw[:30]), self.assertRaises(ConformanceError):
                verify_linux_evidence(raw, **fixture.inputs())
        for value in (None, [], True, 1, "record", {"schemaVersion": SCHEMA}):
            with self.subTest(value=value), self.assertRaises(ConformanceError):
                validate_linux_evidence(value)

    def test_only_precise_utc_rfc3339_timestamps_are_accepted(self):
        fixture = LinuxFixture()
        for value in ("20260907T003000Z", "2026-09-07X00:30:00Z", "2026-09-07T00:30Z", "2026-09-07T00:30:00.1234567Z", "2026-02-30T00:30:00Z"):
            record = deepcopy(fixture.record)
            record["observedAt"] = value
            with self.subTest(time=value), self.assertRaises(ConformanceError):
                validate_linux_evidence(record)
