from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch

from _fixtures import (END, NOW, ROOT, START, VECTORS, authority_args, backend_fixture,
                       binding_args, legacy_fixture, receipt_from, refresh_plan, session_from)
from harness_conformance.canonical import byte_digest, canonical_bytes, canonical_digest
from harness_conformance.crypto import b64url_encode
from harness_conformance.errors import ConformanceError
from harness_conformance.linux_readiness import CASES, build_probe_request, require_time
from harness_conformance.live import command_set_digest, verify_linux_authority
from harness_conformance.live_backend_authority import (COMMANDS, PACKET_DIGEST,
    binding_from_authority, verify_backend_authority)
from harness_conformance.live_session import (MAX_RESPONSE_BYTES, MAX_SESSION_BYTES,
    SESSION_FIELDS, STATES, TRANSITIONS, data_document, transition_candidate,
    validate_binding, validate_receipt, validate_request, validate_session)


class SessionDataTests(unittest.TestCase):
    def setUp(self):
        self.session = deepcopy(VECTORS["session"])
        self.binding = deepcopy(VECTORS["binding"])

    def test_independent_canonical_golden_bytes_and_detached_validated_data(self):
        self.assertEqual(canonical_bytes(self.session), VECTORS["canonicalUtf8"].encode())
        for value in (self.session, VECTORS["canonicalUtf8"].encode(), VECTORS["canonicalUtf8"].encode() + b"\n"):
            result = validate_session(value, self.binding, NOW)
            self.assertEqual(result, self.session)
            self.assertIsNot(result, self.session)
        self.assertEqual(VECTORS["evidenceClass"], "UNIT_VERIFICATION_ONLY")
        self.assertIs(VECTORS["nativeAcceptance"], False)

    def test_every_session_field_is_required_closed_and_strictly_typed(self):
        for name in SESSION_FIELDS:
            altered = deepcopy(self.session)
            del altered[name]
            with self.subTest(missing=name), self.assertRaises(ConformanceError):
                validate_session(altered, self.binding, NOW)
            for bad in (None, True, 1, [], {}, 1.5):
                altered = {**self.session, name: bad}
                with self.subTest(field=name, value=bad), self.assertRaises(ConformanceError):
                    validate_session(altered, self.binding, NOW)
        for name, value in (("verified", True), ("fd", 3), ("path", "/tmp/session"),
                            ("header", "trusted"), ("memfd", 7), ("authority", True)):
            with self.subTest(field=name), self.assertRaises(ConformanceError):
                validate_session({**self.session, name: value}, self.binding, NOW)

    def test_every_expected_binding_is_required_and_cannot_be_self_asserted(self):
        for name in self.binding:
            altered = deepcopy(self.binding)
            del altered[name]
            with self.subTest(field=name), self.assertRaises(ConformanceError):
                validate_session(self.session, altered, NOW)
        for name in self.binding:
            if name in ("notBefore", "notAfter"):
                continue
            changed = "sha256:" + "a" * 64 if name.endswith("Digest") else "other-scope"
            with self.subTest(field=name), self.assertRaises(ConformanceError):
                validate_session({**self.session, name: changed}, self.binding, NOW)
        with self.assertRaises(ConformanceError):
            validate_binding({**self.binding, "verified": True})

    def test_identifiers_digests_and_utc_time_grammar_reuse_closed_contract(self):
        for name in ("nonce", "tenantId", "environmentId", "endpointId", "namespace"):
            for bad in ("", "Upper", "bad_value", "x" * 129, "x\n", "a..b", "å"):
                with self.subTest(field=name, value=bad), self.assertRaises(ConformanceError):
                    validate_session({**self.session, name: bad}, {**self.binding, name: bad}, NOW)
        for name in ("packetDigest", "commandSetDigest", "releaseDigest", "capacityDigest"):
            for bad in ("sha256:" + "A" * 64, "sha256:0", "latest", "sha512:" + "0" * 64):
                with self.subTest(field=name), self.assertRaises(ConformanceError):
                    validate_session({**self.session, name: bad}, {**self.binding, name: bad}, NOW)
        for bad in ("2026-09-07", "2026-09-07 00:00:00Z", "2026-09-07T00:00:00+00:00",
                    "2026-02-30T00:00:00Z", "2026-09-07T00:00:60Z", "2026-09-07T00:00:00.1234567Z"):
            for name in ("issuedAt", "expiresAt"):
                with self.subTest(field=name, value=bad), self.assertRaises(ConformanceError):
                    validate_session({**self.session, name: bad}, self.binding, NOW)

    def test_half_open_time_window_and_signed_intersection_are_enforced(self):
        self.assertEqual(validate_session(self.session, self.binding, START), self.session)
        for now in ("2026-09-06T23:59:59Z", END, "2026-09-08T00:00:00Z"):
            with self.subTest(now=now), self.assertRaises(ConformanceError):
                validate_session(self.session, self.binding, now)
        for changes in ({"issuedAt": END}, {"expiresAt": START},
                        {"issuedAt": "2026-09-06T23:59:59Z"}, {"expiresAt": "2026-09-07T02:00:01Z"}):
            with self.subTest(changes=changes), self.assertRaises(ConformanceError):
                validate_session({**self.session, **changes}, self.binding, NOW)
        for changes in ({"notBefore": NOW}, {"notAfter": NOW}, {"notAfter": START}):
            with self.subTest(changes=changes), self.assertRaises(ConformanceError):
                validate_session(self.session, {**self.binding, **changes}, NOW)

    def test_noncanonical_duplicate_nonfinite_utf8_and_deep_input_fail_closed(self):
        valid = VECTORS["canonicalUtf8"].encode()
        invalid = [b'{"nonce":"a","nonce":"b"}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1.0}',
                   b'\xff', b'{} garbage', b'\xef\xbb\xbf{}', b'{"a":"\\ud800"}',
                   b'{"x":' + b'[' * 1000 + b'0' + b']' * 1000 + b'}', b" " + valid, valid + b"\n\n"]
        for raw in invalid:
            with self.subTest(raw=raw[:50]), self.assertRaises(ConformanceError):
                data_document(raw)

    def test_exact_size_and_depth_limits_apply_before_field_validation(self):
        at_limit = b'{"a":"' + b'x' * (MAX_SESSION_BYTES - 8) + b'"}'
        self.assertEqual(len(at_limit), MAX_SESSION_BYTES)
        self.assertEqual(len(data_document(at_limit)["a"]), MAX_SESSION_BYTES - 8)
        for bad in (at_limit + b"\n", {"a": "x" * MAX_SESSION_BYTES}):
            with self.assertRaises(ConformanceError):
                data_document(bad)
        depth = "leaf"
        for _ in range(8):
            depth = {"a": depth}
        data_document(depth)
        with self.assertRaises(ConformanceError):
            data_document({"a": depth})
        with self.assertRaises(ConformanceError):
            data_document({}, MAX_SESSION_BYTES + 1)

    def test_python_objects_subclasses_and_cycles_never_serialize_or_execute(self):
        class Forged(dict):
            def items(self):
                raise AssertionError("object hook invoked")
        for value in (Forged(self.session), object(), {"a": object()}, bytearray(b"{}"),
                      {"a": float("nan")}, {1: "key"}):
            with self.subTest(type=type(value)), self.assertRaises(ConformanceError):
                data_document(value)
        cyclic = {}
        cyclic["self"] = cyclic
        with self.assertRaises(ConformanceError):
            data_document(cyclic)

    def test_all_64_state_edges_are_exact_and_return_proposals_not_sessions(self):
        expected = {(source, target) for source, targets in VECTORS["transitions"].items() for target in targets}
        self.assertEqual(set(TRANSITIONS), expected)
        self.assertEqual(list(STATES), VECTORS["states"])
        for source in STATES:
            for target in STATES:
                value = {**self.session, "state": source}
                at = END if target == "EXPIRED" else NOW
                with self.subTest(source=source, target=target):
                    if (source, target) not in expected:
                        with self.assertRaises(ConformanceError):
                            transition_candidate(value, target, self.binding, at)
                    else:
                        proposal = transition_candidate(value, target, self.binding, at)
                        self.assertEqual(proposal["fromState"], source)
                        self.assertEqual(proposal["toState"], target)
                        self.assertIs(proposal["requiresProtectedSupervisor"], True)
                        self.assertIs(proposal["nativeAcceptance"], False)
                        self.assertEqual(proposal["evidenceClass"], "UNIT_VERIFICATION_ONLY")
                        self.assertEqual(value["state"], source)
                        with self.assertRaises(ConformanceError):
                            validate_session(proposal, self.binding, at)

    def test_expiry_cannot_be_early_or_replaced_by_success_or_reuse(self):
        for source in ("RESERVED", "RUNNING"):
            value = {**self.session, "state": source}
            with self.assertRaises(ConformanceError):
                transition_candidate(value, "EXPIRED", self.binding, NOW)
            for target in VECTORS["transitions"][source]:
                if target != "EXPIRED":
                    with self.assertRaises(ConformanceError):
                        transition_candidate(value, target, self.binding, END)
        for state in ("COMPLETED", "FAILED", "CANCELLED", "EXPIRED", "UNAVAILABLE"):
            with self.assertRaises(ConformanceError):
                transition_candidate({**self.session, "state": state}, "RESERVED", self.binding, NOW)

    def test_no_verified_flag_fd_or_environment_can_supply_execution_authority(self):
        with patch("builtins.open", side_effect=AssertionError("no I/O in data validation")):
            self.assertEqual(validate_session(self.session, self.binding, NOW), self.session)
            candidate = transition_candidate(self.session, "RESERVED", self.binding, NOW)
            self.assertNotIn("state", candidate)
        with self.assertRaises(TypeError):
            transition_candidate(self.session, "RESERVED", self.binding, NOW, verified=True)
        with self.assertRaises(ConformanceError):
            validate_session(3, self.binding, NOW)

    def test_session_schema_and_runtime_fields_states_and_patterns_agree(self):
        schema = json.loads((ROOT / "schemas/v1alpha1/live-backend-session.schema.json").read_bytes())
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), set(SESSION_FIELDS))
        self.assertEqual(set(schema["properties"]), set(SESSION_FIELDS))
        self.assertEqual(schema["properties"]["state"]["enum"], list(STATES))
        self.assertEqual(schema["properties"]["schemaVersion"]["const"], self.session["schemaVersion"])
        import re
        for name, rule in schema["properties"].items():
            if "pattern" in rule:
                self.assertIsNotNone(re.fullmatch(rule["pattern"], self.session[name]))


class BackendAuthorityTests(unittest.TestCase):
    def check(self, fixture):
        return verify_backend_authority(*authority_args(fixture), now=require_time(NOW, "now"))

    def test_successor_and_legacy_are_independently_pinned_and_mutually_exclusive(self):
        old, new = legacy_fixture(), backend_fixture()
        before = deepcopy(old.envelope)
        verify_linux_authority(*authority_args(old), now=require_time(NOW, "now"))
        self.check(new)
        with self.assertRaises(ConformanceError):
            self.check(old)
        with self.assertRaises(ConformanceError):
            verify_linux_authority(*authority_args(new), now=require_time(NOW, "now"))
        self.assertEqual(old.envelope, before)
        self.assertEqual(len(old.envelope["commands"]), 7)
        self.assertEqual(len(COMMANDS), 8)

    def test_all_command_and_packet_scope_mutations_reject_even_when_signed(self):
        original = backend_fixture()
        cases = [("packetId", "CONF-LINUX-001"), ("packetDigest", "sha256:" + "0" * 64),
                 ("campaignId", "alpha1"), ("allowedEvidenceAxes", ["TENANT_ACCEPTANCE"]),
                 ("allowedEvidenceAxes", ["RUNTIME"])]
        commands = original.envelope["commands"]
        for index in range(len(commands)):
            cases.append(("commands", commands[:index] + commands[index + 1:]))
        cases.extend([("commands", list(reversed(commands))), ("commands", commands + [commands[0]]),
                      ("commands", [["sh", "-c", "true"]])])
        for key, value in cases:
            fixture = deepcopy(original)
            fixture.envelope[key] = value
            if key == "commands":
                fixture.envelope["commandSetDigest"] = command_set_digest(value)
            fixture.resign_authority()
            with self.subTest(field=key, value=value), self.assertRaises(ConformanceError):
                self.check(fixture)

    def test_all_signed_envelope_and_capacity_fields_are_closed(self):
        fixture = backend_fixture()
        for index in (0, 1):
            raw = list(authority_args(fixture))
            original = json.loads(raw[index])
            for key in original:
                altered = deepcopy(original)
                del altered[key]
                args = raw[:]
                args[index] = canonical_bytes(altered)
                with self.subTest(document=index, missing=key), self.assertRaises(ConformanceError):
                    verify_backend_authority(*args, now=require_time(NOW, "now"))
            original["verified"] = True
            raw[index] = canonical_bytes(original)
            with self.assertRaises(ConformanceError):
                verify_backend_authority(*raw, now=require_time(NOW, "now"))

    def test_each_signature_is_required_and_covers_immutable_release_endpoint_bytes(self):
        original = backend_fixture()
        for role in ("platform", "tenant", "capacity"):
            fixture = deepcopy(original)
            if role == "capacity":
                fixture.capacity["signature"] = b64url_encode(bytes(64))
                fixture.envelope["capacityAuthorizationDigest"] = byte_digest(canonical_bytes(fixture.capacity))
                # Sign the unchanged envelope roles only; retain invalid capacity.
                from harness_conformance.crypto import sign, signature_payload
                from harness_conformance.live import ENVELOPE_DOMAIN
                payload = signature_payload(ENVELOPE_DOMAIN, fixture.envelope, ("platformSignature", "tenantSignature"))
                for signer in ("platform", "tenant"):
                    fixture.envelope[signer + "Signature"] = b64url_encode(sign(fixture.seeds[signer], payload))
            else:
                fixture.envelope[role + "Signature"] = b64url_encode(bytes(64))
            with self.subTest(role=role), self.assertRaises(ConformanceError):
                self.check(fixture)
        for key in ("campaignReleaseDigest", "conformanceKitDigest", "bundleDigest", "launcherDigest",
                    "packetDigest", "campaignDefinitionDigest", "nonce"):
            fixture = deepcopy(original)
            fixture.envelope[key] = "other-nonce" if key == "nonce" else "sha256:" + "a" * 64
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                self.check(fixture)
        fixture = deepcopy(original)
        fixture.envelope["endpoints"][0]["port"] += 1
        with self.assertRaises(ConformanceError):
            self.check(fixture)

    def test_authority_raw_digest_and_canonical_transport_cannot_be_substituted(self):
        original = list(authority_args(backend_fixture()))
        for index in range(4):
            for value in (original[index] + b"\n\n", b'{"x":1,"x":2}', b'{"x":NaN}',
                          b'\xff', b'[' * 1000, bytearray(original[index]), None):
                args = original[:]
                args[index] = value
                with self.subTest(document=index), self.assertRaises(ConformanceError):
                    verify_backend_authority(*args, now=require_time(NOW, "now"))
        for index in (1, 2, 3):
            args = original[:]
            args[index] += b"\n"  # canonical-but-different signed file bytes
            with self.assertRaises(ConformanceError):
                verify_backend_authority(*args, now=require_time(NOW, "now"))

    def test_each_trust_role_owner_scope_revocation_window_and_duplicate_is_checked(self):
        original = backend_fixture()
        for trust_name, index in (("release_trust", 0), ("tenant_trust", 0), ("tenant_trust", 1)):
            for key, value in (("purpose", "OTHER"), ("tenantId", "wrong"), ("environmentId", "wrong"),
                               ("revoked", True), ("revoked", 0), ("owner", "invalid_owner"),
                               ("validFrom", "2026-09-08T00:00:00Z"), ("validUntil", START),
                               ("validUntil", "2026-09-07 02:00:00Z"), ("publicKey", "bad"), ("keyId", "unknown.key")):
                fixture = deepcopy(original)
                getattr(fixture, trust_name)["keys"][index][key] = value
                fixture.resign_authority()
                with self.subTest(trust=trust_name, index=index, field=key), self.assertRaises(ConformanceError):
                    self.check(fixture)
            fixture = deepcopy(original)
            trust = getattr(fixture, trust_name)
            trust["keys"].append(deepcopy(trust["keys"][index]))
            fixture.resign_authority()
            with self.assertRaises(ConformanceError):
                self.check(fixture)
        for role in ("tenant", "capacity"):
            fixture = deepcopy(original)
            key = fixture.tenant_trust["keys"][0 if role == "tenant" else 1]
            key["owner"] = fixture.release_trust["keys"][0]["owner"]
            fixture.resign_authority()
            with self.assertRaises(ConformanceError):
                self.check(fixture)
            key["owner"] = role + "-unit-owner"
            fixture.seeds[role] = fixture.seeds["platform"]
            key["publicKey"] = fixture.release_trust["keys"][0]["publicKey"]
            fixture.resign_authority()
            with self.assertRaises(ConformanceError):
                self.check(fixture)

    def test_every_capacity_scope_digest_array_and_validity_boundary_is_preserved(self):
        original = backend_fixture()
        mutations = [(name, "wrong-scope") for name in ("authorizationId", "tenantId", "environmentId")]
        mutations += [(name, "sha256:" + "0" * 64) for name in ("resourceQuotaDigest", "admissionPolicyDigest")]
        mutations += [("mutationProfile", "PAID"), ("limitRangeDigest", "latest"),
                      ("permittedEndpointIds", []), ("permittedEndpointIds", ["unit-proxy", "unit-proxy"]),
                      ("validFrom", END), ("expiresAt", START), ("expiresAt", "2026-09-07T03:00:00Z")]
        mutations += [(name, {}) for name in ("kubernetesApiRules", "campaignProxyRules", "permittedGvksAndVerbs",
                      "preexistingResourceRefs", "preallocatedStorageRefs", "preallocatedAcceleratorRefs", "credentialIdentities")]
        for key, value in mutations:
            fixture = deepcopy(original)
            fixture.capacity[key] = value
            fixture.resign_authority()
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                self.check(fixture)
        for now in (require_time(END, "end"), require_time("2026-09-06T23:59:59Z", "before"), datetime(2026, 9, 7), None):
            with self.subTest(now=now), self.assertRaises(ConformanceError):
                verify_backend_authority(*authority_args(original), now=now)

    def test_signed_unsafe_endpoint_values_cannot_expand_network_or_cost_scope(self):
        original = backend_fixture()
        for field, value in (("kind", "CLOUD_API"), ("discovery", True), ("accessMode", "DIRECT"),
                             ("ipAddress", "8.8.8.8"), ("ipAddress", "169.254.169.254"),
                             ("ipAddress", "ff02::1"), ("ipAddress", "cloud.example"),
                             ("port", True), ("port", 65536), ("costDisposition", "METERED"),
                             ("credentialFileReference", "relative")):
            fixture = deepcopy(original)
            fixture.envelope["endpoints"][0][field] = value
            fixture.resign_authority()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                self.check(fixture)
        fixture = deepcopy(original)
        fixture.envelope["endpoints"].append(deepcopy(fixture.envelope["endpoints"][0]))
        fixture.resign_authority()
        with self.assertRaises(ConformanceError):
            self.check(fixture)

    def test_binding_uses_all_three_trust_windows_and_no_file_access(self):
        fixture = backend_fixture()
        fixture.capacity["validFrom"] = "2026-09-07T00:10:00Z"
        fixture.tenant_trust["keys"][1]["validFrom"] = "2026-09-07T00:20:00Z"
        fixture.release_trust["keys"][0]["validUntil"] = "2026-09-07T01:30:00Z"
        fixture.resign_authority()
        args, kwargs = authority_args(fixture), binding_args(fixture)
        with patch("builtins.open", side_effect=AssertionError("no file custody in pure adapter")):
            binding = binding_from_authority(*args, **kwargs)
        self.assertEqual(binding["notBefore"], "2026-09-07T00:20:00Z")
        self.assertEqual(binding["notAfter"], "2026-09-07T01:30:00Z")
        validate_session(session_from(binding), binding, NOW)
        with self.assertRaises(ConformanceError):
            validate_session({**session_from(binding), "expiresAt": END}, binding, NOW)

    def test_expected_nonce_tenant_environment_release_and_architecture_are_external_bindings(self):
        fixture = backend_fixture()
        for field in ("expected_nonce", "expected_tenant", "expected_environment", "expected_release", "architecture"):
            args = binding_args(fixture)
            args[field] = "wrong"
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                binding_from_authority(*authority_args(fixture), **args)
        for field in ("release_bytes", "plan_bytes"):
            args = binding_args(fixture)
            args[field] += b"\n"
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                binding_from_authority(*authority_args(fixture), **args)

    def test_release_plan_and_proxy_policy_are_checked_even_after_signer_approval(self):
        original = backend_fixture()
        mutations = [("namespace", "other-namespace"), ("serviceAccountSubject", "other-subject")]
        for key, value in mutations:
            fixture = deepcopy(original)
            fixture.plan[key] = value
            refresh_plan(fixture)
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                binding_from_authority(*authority_args(fixture), **binding_args(fixture))
        for field, value in (("timeoutSeconds", 901), ("requestMaxBytes", 16385),
                             ("paths", ["/arbitrary"]), ("methods", ["DELETE"]), ("namespace", "other")):
            fixture = deepcopy(original)
            fixture.capacity["campaignProxyRules"][0][field] = value
            fixture.resign_authority()
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                binding_from_authority(*authority_args(fixture), **binding_args(fixture))
        fixture = deepcopy(original)
        fixture.release["endpointPolicyDigests"] = []
        fixture.envelope["campaignReleaseDigest"] = byte_digest(canonical_bytes(fixture.release))
        fixture.resign_authority()
        with self.assertRaises(ConformanceError):
            binding_from_authority(*authority_args(fixture), **binding_args(fixture))


class RequestReceiptDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = backend_fixture()
        cls.binding = binding_from_authority(*authority_args(cls.fixture), **binding_args(cls.fixture))
        cls.session = session_from(cls.binding)

    def request(self, case=CASES[0]):
        return build_probe_request(self.fixture.envelope, self.fixture.capacity, self.fixture.plan, case)

    def receipt(self, value, case=CASES[0], **kwargs):
        return validate_receipt(value, self.session, self.binding, self.request(case),
            self.fixture.plan["regressions"] if case == "FULL_PREDECESSOR_REGRESSION" else {}, kwargs.get("now", NOW))

    def test_every_fixed_case_on_each_architecture_retains_existing_wire_bytes(self):
        for architecture in ("amd64", "arm64"):
            fixture = backend_fixture(architecture)
            binding = binding_from_authority(*authority_args(fixture), **binding_args(fixture))
            session = session_from(binding)
            for case in CASES:
                request = build_probe_request(fixture.envelope, fixture.capacity, fixture.plan, case)
                receipt = receipt_from(fixture, case)
                with self.subTest(architecture=architecture, case=case):
                    self.assertEqual(validate_request(canonical_bytes(request), session, binding, request, NOW), request)
                    expected = fixture.plan["regressions"] if case == "FULL_PREDECESSOR_REGRESSION" else {}
                    self.assertEqual(validate_receipt(canonical_bytes(receipt), session, binding, request, expected, NOW), receipt)

    def test_each_request_field_is_closed_and_bound_no_url_argv_or_cross_scope(self):
        request = self.request()
        for key in request:
            missing = deepcopy(request)
            del missing[key]
            for value in (missing, {**request, key: None}, {**request, key: "wrong"}):
                with self.subTest(field=key), self.assertRaises(ConformanceError):
                    validate_request(value, self.session, self.binding, request, NOW)
        for key in ("argv", "url", "credential", "verified", "fd"):
            with self.subTest(field=key), self.assertRaises(ConformanceError):
                validate_request({**request, key: True}, self.session, self.binding, request, NOW)
        for key in ("runNonce", "namespace", "endpointId"):
            forged = {**request, key: "other"}
            with self.assertRaises(ConformanceError):
                validate_request(forged, self.session, self.binding, forged, NOW)

    def test_only_current_running_data_can_describe_a_request_or_receipt(self):
        request, receipt = self.request(), receipt_from(self.fixture, CASES[0])
        for state in STATES:
            if state == "RUNNING":
                continue
            session = {**self.session, "state": state}
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                validate_request(request, session, self.binding, request, NOW)
            with self.assertRaises(ConformanceError):
                validate_receipt(receipt, session, self.binding, request, {}, NOW)
        with self.assertRaises(ConformanceError):
            self.receipt(receipt, now=END)

    def test_receipt_fields_nonce_probe_command_output_and_observation_are_bound(self):
        original = receipt_from(self.fixture, CASES[0])
        for key in original:
            missing = deepcopy(original)
            del missing[key]
            for value in (missing, {**original, key: None}, {**original, key: "wrong"}):
                with self.subTest(field=key), self.assertRaises(ConformanceError):
                    self.receipt(value)
        for changes in ({"verified": True}, {"observedAt": "2026-09-06T23:59:59Z"},
                        {"observedAt": "2026-09-07T01:00:01Z"}, {"architecture": "arm64"}):
            with self.assertRaises(ConformanceError):
                self.receipt({**original, **changes})

    def test_all_mandatory_assertions_and_status_aggregation_are_checked(self):
        for case in CASES:
            original = receipt_from(self.fixture, case)
            for check in original["output"]["checks"]:
                for state in ("FAIL", "NOT_RUN_ENV_UNAVAILABLE"):
                    receipt = deepcopy(original)
                    receipt["output"]["checks"][check] = state
                    receipt["outputDigest"] = canonical_digest(receipt["output"], "planeon.linux-probe-output/v1alpha1")
                    with self.subTest(case=case, check=check, state=state), self.assertRaises(ConformanceError):
                        self.receipt(receipt, case)
                    receipt["status"] = state
                    self.assertEqual(self.receipt(receipt, case)["status"], state)
                receipt = deepcopy(original)
                del receipt["output"]["checks"][check]
                with self.assertRaises(ConformanceError):
                    self.receipt(receipt, case)

    def test_regression_omission_wrong_inventory_skips_failures_and_false_pass_reject(self):
        case = "FULL_PREDECESSOR_REGRESSION"
        original = receipt_from(self.fixture, case)
        for name in original["output"]["regressions"]:
            for field, value in (("inventoryDigest", "sha256:" + "0" * 64), ("collected", 1),
                                  ("executed", 0), ("skipped", 1), ("failed", 1), ("failed", True)):
                receipt = deepcopy(original)
                receipt["output"]["regressions"][name][field] = value
                receipt["outputDigest"] = canonical_digest(receipt["output"], "planeon.linux-probe-output/v1alpha1")
                with self.subTest(repo=name, field=field), self.assertRaises(ConformanceError):
                    self.receipt(receipt, case)
        expected = deepcopy(self.fixture.plan["regressions"])
        expected["conformance"]["testCount"] = 119
        with self.assertRaises(ConformanceError):
            validate_receipt(original, self.session, self.binding, self.request(case), expected, NOW)

    def test_receipts_have_closed_bounded_bytes_and_never_evidence_promotion(self):
        original = receipt_from(self.fixture, CASES[0])
        for bad in (b" " + canonical_bytes(original), b'{"status":"PASS","status":"FAIL"}',
                    {**original, "output": {"checks": {}, "regressions": {}, "extra": True}},
                    b"x" * (MAX_RESPONSE_BYTES + 1)):
            with self.assertRaises(ConformanceError):
                self.receipt(bad)
        result = self.receipt(original)
        self.assertNotIn("nativeAcceptance", result)
        self.assertNotIn("signature", result)
        self.assertNotIn("verified", result)
