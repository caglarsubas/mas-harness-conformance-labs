"""CONF-LINUX-002: every vector of design rev 4 section 5, each with its expected reason code (UNIT-ONLY keys and data).

The root runs as the packet's command 15 runs it, with no PYTHONPATH:
    python3 -m unittest discover -s tests/linux_signers -p test_*.py
`src` goes first on sys.path, as tests/alpha1/test_alpha1.py does. This root's builder, and through it the base
linux_baseline fixture, are then loaded by path under distinct module names, so no module name collides (SG1-11).

The re-binding rule (SG2-1, SG3-1): after a vector changes a document, it re-binds every digest that binds that
document unless it says it does not, and re-signs only the documents it means to keep valid, each over its own domain.
Each vector's docstring names what it re-bound and what it re-signed.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

_SPEC = importlib.util.spec_from_file_location("linux_signers_fixtures", ROOT / "tests/linux_signers/_fixtures.py")
F = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(F)

from harness_conformance import cli, linux_readiness, live  # noqa: E402
from harness_conformance.canonical import canonical_bytes, load_json  # noqa: E402
from harness_conformance.crypto import b64url_encode  # noqa: E402
from harness_conformance.errors import ConformanceError  # noqa: E402
from harness_conformance.schema import require_id, require_time, validate  # noqa: E402

INSTANT = require_time(F.NOW, "now")
NAMES = ("envelope", "capacity", "record")
UNKNOWN_SIGNERS = "SHARED_PRINCIPAL"
UNKNOWN_VERSION = {"envelope": "harness.planeon.ai/live-campaign-execution-envelope/v1alpha3",
                   "capacity": "harness.planeon.ai/live-capacity-authorization/v1alpha3",
                   "record": "harness.planeon.ai/linux-readiness-evidence/v1alpha3"}
SCHEMA_FILES = {"envelope": "live-campaign-execution-envelope", "capacity": "live-capacity-authorization",
                "record": "linux-readiness-evidence"}
_BUILT = {}
_BUILDERS = {"single": lambda: F.SignersFixture(F.SINGLE), "independent": lambda: F.SignersFixture(F.INDEPENDENT),
             "legacy": F.SignersFixture.v1alpha1}


def fresh(kind):
    """A deep copy of one signed set: `single` and `independent` (v1alpha2) or `legacy` (the base v1alpha1 set)."""
    if kind not in _BUILT:
        _BUILT[kind] = _BUILDERS[kind]()
    return deepcopy(_BUILT[kind])


def load_schema(version, name):
    return load_json(ROOT / "schemas" / version / (SCHEMA_FILES[name] + ".schema.json"))


def _check(condition, message):
    if not condition:
        raise AssertionError(message)


def schema_check(value, schema, root, seen, pointer="#"):
    """Test-local schema interpreter (MON-SG2-NEXT; SG2-4, SG3-4).

    A local copy of the rules of tests/platform/linux_baseline/test_linux_protocol.py's schema_assert (lines 12-51),
    not an import of that module. It adds two keywords: `$ref`, resolved only within the same file's `$defs`, and
    `uniqueItems`. An external or unresolvable `$ref` fails. `format` is not asserted, a stated limit. Every resolved
    `$ref` use is recorded in `seen` by its JSON pointer, so a test can show that every use was checked.
    """
    if "$ref" in schema:
        reference = schema["$ref"]
        name = reference[len("#/$defs/"):] if isinstance(reference, str) and reference.startswith("#/$defs/") else None
        _check(name is not None and "/" not in name and name in root.get("$defs", {}), f"external or unresolvable $ref at {pointer}")
        seen.add(pointer)
        schema_check(value, root["$defs"][name], root, seen, "#/$defs/" + name)
    if "const" in schema:
        _check(canonical_bytes(value) == canonical_bytes(schema["const"]), f"const at {pointer}")
    if "enum" in schema:
        _check(any(canonical_bytes(value) == canonical_bytes(item) for item in schema["enum"]), f"enum at {pointer}")
    if "type" in schema:
        _check(type(value) is {"object": dict, "array": list, "integer": int, "string": str, "boolean": bool}[schema["type"]], f"type at {pointer}")
    for index, conditional in enumerate(schema.get("allOf", [])):
        where = f"{pointer}/allOf/{index}"
        if "if" in conditional:
            try:
                schema_check(value, conditional["if"], root, seen, where + "/if")
            except AssertionError:
                continue
            schema_check(value, conditional["then"], root, seen, where + "/then")
        else:
            schema_check(value, conditional, root, seen, where)
    if isinstance(value, dict):
        _check(set(schema.get("required", [])) <= value.keys(), f"required at {pointer}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            _check(value.keys() <= properties.keys(), f"additionalProperties at {pointer}")
        for key in value.keys() & properties.keys():
            schema_check(value[key], properties[key], root, seen, f"{pointer}/properties/{key}")
    if isinstance(value, list):
        _check(schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10000000), f"item count at {pointer}")
        if schema.get("uniqueItems") is True:
            _check(len({canonical_bytes(item) for item in value}) == len(value), f"uniqueItems at {pointer}")
        prefix = schema.get("prefixItems", [])
        if schema.get("items") is False:
            _check(len(value) <= len(prefix), f"items at {pointer}")
        for index, (item, definition) in enumerate(zip(value, prefix)):
            schema_check(item, definition, root, seen, f"{pointer}/prefixItems/{index}")
        if isinstance(schema.get("items"), dict):
            for item in value[len(prefix):]:
                schema_check(item, schema["items"], root, seen, f"{pointer}/items")
    if isinstance(value, str):
        _check(schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 10000000), f"length at {pointer}")
        if "pattern" in schema:
            _check(re.search(schema["pattern"], value) is not None, f"pattern at {pointer}")
    if type(value) is int:
        _check(schema.get("minimum", 0) <= value <= schema.get("maximum", 10000000), f"range at {pointer}")


def ref_uses(node, pointer="#"):
    """Every `$ref` use in a schema file, by JSON pointer."""
    if isinstance(node, dict):
        found = [pointer] if "$ref" in node else []
        for key, item in node.items():
            found += ref_uses(item, f"{pointer}/{key}")
        return found
    if isinstance(node, list):
        return [use for index, item in enumerate(node) for use in ref_uses(item, f"{pointer}/{index}")]
    return []


class SignersCase(unittest.TestCase):
    def assertReason(self, expected, observed):
        self.assertEqual(observed, expected)

    def refused(self, code, function, *args, **kwargs):
        with self.assertRaises(ConformanceError) as raised:
            function(*args, **kwargs)
        self.assertReason(code, raised.exception.reason)
        return raised.exception

    def verify(self, fixture, **overrides):
        return linux_readiness.verify_linux_evidence(canonical_bytes(fixture.record), **(fixture.inputs() | overrides))

    def authority(self, fixture, function):
        inputs = fixture.inputs()
        return function(inputs["envelope_bytes"], inputs["capacity_bytes"], inputs["release_trust_bytes"],
                        inputs["tenant_trust_bytes"], now=INSTANT)

    def passes(self, fixture):
        result = self.verify(fixture)
        self.assertReason("PASS", result["verificationStatus"])
        self.assertEqual(result["evidenceClass"], "UNIT_VERIFICATION_ONLY")
        self.assertIs(result["nativeAcceptance"], False)
        return result


class PositiveVectors(SignersCase):
    def test_single_principal_separated_keys_verifies_unit_only(self):
        """All three trust-key owners are `single-principal`, with three distinct keys and key ids; both architectures."""
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                fixture = F.SignersFixture(F.SINGLE, architecture=architecture)
                self.assertEqual(fixture.owners(), [F.LABEL] * 3)
                keys = [key["publicKey"] for key in fixture.release_trust["keys"] + fixture.tenant_trust["keys"]]
                key_ids = [key["keyId"] for key in fixture.release_trust["keys"] + fixture.tenant_trust["keys"]]
                self.assertEqual((len(set(keys)), len(set(key_ids))), (3, 3))
                self.assertEqual(self.passes(fixture)["architecture"], architecture)

    def test_independent_principals_verifies_unit_only(self):
        """Three distinct owners, none of them `single-principal`."""
        fixture = fresh("independent")
        self.assertEqual(len(set(fixture.owners())), 3)
        self.assertNotIn(F.LABEL, fixture.owners())
        self.passes(fixture)

    def test_authority_v2_returns_the_originals_and_the_agreed_signers(self):
        for kind, signers in (("single", F.SINGLE), ("independent", F.INDEPENDENT)):
            with self.subTest(kind=kind):
                fixture = fresh(kind)
                envelope, capacity, release_trust, tenant_trust, agreed = self.authority(fixture, live.verify_linux_authority_v2)
                self.assertEqual(agreed, signers)
                self.assertEqual((envelope, capacity), (fixture.envelope, fixture.capacity))
                self.assertEqual((envelope["schemaVersion"], capacity["schemaVersion"]), (F.ENVELOPE_SCHEMA_V2, F.CAPACITY_SCHEMA_V2))
                self.assertEqual((release_trust, tenant_trust), (fixture.release_trust, fixture.tenant_trust))

    def test_v2_validators_return_the_original_documents(self):
        """SG1-2 and SG2-3: each v2 validator returns the original v1alpha2 object, unchanged."""
        fixture = fresh("single")
        envelope, capacity, record = deepcopy(fixture.envelope), deepcopy(fixture.capacity), deepcopy(fixture.record)
        self.assertIs(live.validate_envelope_v2(envelope, now=INSTANT), envelope)
        self.assertIs(live.validate_capacity_v2(capacity, envelope, now=INSTANT), capacity)
        self.assertIs(linux_readiness._validate_linux_evidence_v2(record), record)
        self.assertEqual((envelope, capacity, record), (fixture.envelope, fixture.capacity, fixture.record))

    def test_v1alpha1_path_is_unchanged(self):
        """The base v1alpha1 set still verifies through today's path, and verify_linux_authority still returns four items."""
        fixture = fresh("legacy")
        self.passes(fixture)
        self.assertEqual(len(self.authority(fixture, live.verify_linux_authority)), 4)
        self.assertEqual(fixture.owners(), list(F.DISTINCT_OWNERS))

    def test_v1alpha1_path_keeps_todays_owner_rule_only(self):
        """Re-signed over the v1alpha1 domains: three `single-principal` owners stay refused on v1alpha1, and the
        reserved-label rule is the v1alpha2 path's only."""
        self.refused("LINUX_SIGNER_OWNERS_NOT_INDEPENDENT", self.verify, F.SignersFixture.v1alpha1(owners=(F.LABEL,) * 3))
        self.passes(F.SignersFixture.v1alpha1(owners=(F.LABEL, "tenant-unit-owner", "capacity-unit-owner")))


class LiteralConstants(SignersCase):
    def test_the_four_v2_domain_and_schema_constants_are_literal(self):
        """SG3-5: live.py's four v2 constants, each against its literal string."""
        self.assertEqual(live.ENVELOPE_SCHEMA_V2, "harness.planeon.ai/live-campaign-execution-envelope/v1alpha2")
        self.assertEqual(live.CAPACITY_SCHEMA_V2, "harness.planeon.ai/live-capacity-authorization/v1alpha2")
        self.assertEqual(live.ENVELOPE_DOMAIN_V2, "planeon.harness-live-execution-envelope/v1alpha2")
        self.assertEqual(live.CAPACITY_DOMAIN_V2, "planeon.harness-live-capacity-authorization/v1alpha2")

    def test_the_record_constants_and_the_disclosure_values_are_literal(self):
        self.assertEqual(linux_readiness.SCHEMA_V2, "harness.planeon.ai/linux-readiness-evidence/v1alpha2")
        self.assertEqual(linux_readiness.DOMAIN_V2, "planeon.harness-linux-readiness-evidence/v1alpha2")
        self.assertEqual(linux_readiness.RECORD_FIELDS_V2, (*linux_readiness.RECORD_FIELDS, "signers"))
        self.assertEqual(live.SIGNERS, ("INDEPENDENT_PRINCIPALS", "SINGLE_PRINCIPAL_SEPARATED_KEYS"))
        self.assertEqual(live.SINGLE_PRINCIPAL_OWNER, "single-principal")
        self.assertEqual(require_id(live.SINGLE_PRINCIPAL_OWNER, "owner"), "single-principal")

    def test_the_v1alpha1_constants_are_unchanged(self):
        self.assertEqual(live.ENVELOPE_SCHEMA, "harness.planeon.ai/live-campaign-execution-envelope/v1alpha1")
        self.assertEqual(live.CAPACITY_SCHEMA, "harness.planeon.ai/live-capacity-authorization/v1alpha1")
        self.assertEqual(live.ENVELOPE_DOMAIN, "planeon.harness-live-execution-envelope/v1alpha1")
        self.assertEqual(live.CAPACITY_DOMAIN, "planeon.harness-live-capacity-authorization/v1alpha1")
        self.assertEqual(linux_readiness.SCHEMA, "harness.planeon.ai/linux-readiness-evidence/v1alpha1")
        self.assertEqual(linux_readiness.DOMAIN, "planeon.harness-linux-readiness-evidence/v1alpha1")
        self.assertEqual(linux_readiness.PLAN_SCHEMA, "harness.planeon.ai/linux-readiness-plan/v1alpha1")

    def test_linux_readiness_adds_no_top_level_import(self):
        """SG1-5: the v2 names come from .live only inside the two functions that use them; SIGNERS is defined once."""
        tree = ast.parse((ROOT / "src/harness_conformance/linux_readiness.py").read_bytes())
        top = [(node.module, node.level) if isinstance(node, ast.ImportFrom) else tuple(alias.name for alias in node.names)
               for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(top, [("__future__", 0), ("re",), ("functools", 0), ("datetime", 0), ("typing", 0),
                               ("canonical", 1), ("crypto", 1), ("errors", 1), ("schema", 1)])
        local = {}
        for function in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
            for node in ast.walk(function):
                if isinstance(node, ast.ImportFrom) and node.module == "live" and node.level == 1:
                    local[function.name] = sorted(alias.name for alias in node.names)
        self.assertEqual(local, {"_validate_linux_evidence_v2": ["SIGNERS"],
                                 "verify_linux_evidence": ["_trust_key", "verify_linux_authority", "verify_linux_authority_v2"]})
        self.assertFalse(hasattr(linux_readiness, "SIGNERS") or hasattr(linux_readiness, "SINGLE_PRINCIPAL_OWNER"))


class SG12SigningBoundary(SignersCase):
    """Design section 10's table: SG1-2's three steps, one vector each."""

    def test_the_closed_original_check_comes_first(self):
        """`signers` missing from a v1alpha2 envelope; the envelope re-signed over ENVELOPE_DOMAIN_V2, the record
        re-bound and re-signed over DOMAIN_V2."""
        fixture = fresh("single")
        del fixture.envelope["signers"]
        fixture.sign_envelope()
        fixture.keep_record()
        self.refused("MISSING_FIELD", self.verify, fixture)

    def test_the_copy_is_validated_for_refusals_only(self):
        """Equal platform and tenant key ids in a v1alpha2 envelope, refused at live.py line 149 inside validate_envelope
        on the copy; the envelope re-signed over ENVELOPE_DOMAIN_V2, the record re-bound and re-signed."""
        fixture = fresh("single")
        fixture.envelope["tenantSignerKeyId"] = fixture.envelope["platformSignerKeyId"]
        fixture.sign_envelope()
        fixture.keep_record()
        self.refused("SIGNER_ROLES_NOT_INDEPENDENT", self.verify, fixture)

    def test_every_payload_is_over_the_original_with_the_v2_domains(self):
        """(a)'s capacity tamper: the capacity's `signers` changed, not re-signed; the envelope's capacity digest
        re-bound and the envelope re-signed over ENVELOPE_DOMAIN_V2; the record re-bound, not re-signed."""
        fixture = fresh("single")
        fixture.capacity["signers"] = F.INDEPENDENT
        fixture.bind_envelope()
        fixture.sign_envelope()
        fixture.bind_record()
        self.refused("CAPACITY_SIGNATURE_INVALID", self.verify, fixture)


class SG31TamperingAfterSigning(SignersCase):
    """SG3-1 (binding) and (a). A changed capacity or trust bundle first meets LINUX_AUTHORITY_DIGEST_MISMATCH unless the
    envelope's digest of it is re-bound. A changed envelope meets PLATFORM_SIGNATURE_INVALID before the record's
    envelopeDigest is compared, whether or not that digest is re-bound. A changed record, bound by no digest, meets
    LINUX_EVIDENCE_SIGNATURE_INVALID."""

    def test_envelope_signers_changed_record_rebound_nothing_resigned(self):
        fixture = fresh("single")
        fixture.envelope["signers"] = F.INDEPENDENT
        fixture.bind_record()
        self.refused("PLATFORM_SIGNATURE_INVALID", self.verify, fixture)

    def test_changed_envelope_meets_its_signature_whatever_is_rebound(self):
        """The same change with nothing re-bound, and with the record re-bound and re-signed over DOMAIN_V2."""
        for mode in ("nothing re-bound", "record re-bound and re-signed"):
            with self.subTest(mode=mode):
                fixture = fresh("single")
                fixture.envelope["signers"] = F.INDEPENDENT
                if mode != "nothing re-bound":
                    fixture.keep_record()
                self.refused("PLATFORM_SIGNATURE_INVALID", self.verify, fixture)

    def test_capacity_signers_changed_rebound_envelope_resigned(self):
        """The envelope's capacity digest re-bound and the envelope re-signed over ENVELOPE_DOMAIN_V2; the record
        re-bound, not re-signed; the capacity not re-signed."""
        fixture = fresh("single")
        fixture.capacity["signers"] = F.INDEPENDENT
        fixture.bind_envelope()
        fixture.sign_envelope()
        fixture.bind_record()
        self.refused("CAPACITY_SIGNATURE_INVALID", self.verify, fixture)

    def test_record_signers_changed_nothing_resigned(self):
        fixture = fresh("single")
        fixture.record["signers"] = F.INDEPENDENT
        self.refused("LINUX_EVIDENCE_SIGNATURE_INVALID", self.verify, fixture)

    def test_all_three_changed_every_digest_rebound_nothing_resigned(self):
        fixture = fresh("single")
        for name in NAMES:
            fixture.document(name)["signers"] = F.INDEPENDENT
        fixture.bind_envelope()
        fixture.bind_record()
        self.refused("PLATFORM_SIGNATURE_INVALID", self.verify, fixture)

    def test_one_unrebound_tamper_capacity_signers_changed_nothing_rebound(self):
        fixture = fresh("single")
        fixture.capacity["signers"] = F.INDEPENDENT
        self.refused("LINUX_AUTHORITY_DIGEST_MISMATCH", self.verify, fixture)

    def test_changed_trust_bundle_not_rebound_meets_the_digest_check(self):
        """An owner changed in either trust bundle; nothing re-bound, nothing re-signed."""
        for bundle in ("release_trust", "tenant_trust"):
            with self.subTest(bundle=bundle):
                fixture = fresh("single")
                getattr(fixture, bundle)["keys"][0]["owner"] = "other-owner"
                self.refused("LINUX_AUTHORITY_DIGEST_MISMATCH", self.verify, fixture)


class SG32RecordVersion(SignersCase):
    """SG3-2 (binding): a record carrying `signers` under v1alpha1 or an unknown version takes today's path and is
    refused as UNKNOWN_FIELD (linux_readiness.py line 160); the v2 version check is defensive, pinned by a direct call."""

    def test_v1alpha1_record_carrying_signers_takes_todays_path(self):
        """Relabelled v1alpha1 with `signers` kept, re-signed over the v1alpha1 DOMAIN."""
        fixture = fresh("single")
        fixture.relabel("record", linux_readiness.SCHEMA, F.SINGLE)
        fixture.sign_record(linux_readiness.DOMAIN)
        self.refused("UNKNOWN_FIELD", self.verify, fixture)

    def test_unknown_version_record_carrying_signers_takes_todays_path(self):
        """Relabelled to an unknown version with `signers` kept; not re-signed (the shape refusal comes first)."""
        fixture = fresh("single")
        fixture.relabel("record", UNKNOWN_VERSION["record"], F.SINGLE)
        self.refused("UNKNOWN_FIELD", self.verify, fixture)

    def test_the_v2_version_check_is_defensive_and_pinned_by_a_direct_call(self):
        for schema in (linux_readiness.SCHEMA, UNKNOWN_VERSION["record"]):
            with self.subTest(schema=schema):
                record = deepcopy(fresh("single").record)
                record["schemaVersion"] = schema
                self.refused("LINUX_EVIDENCE_SCHEMA_INVALID", linux_readiness._validate_linux_evidence_v2, record)

    def test_the_exact_predicate_sends_only_v1alpha2_records_to_the_v2_branch(self):
        """With the v2 validator replaced by a tripwire, only a dict whose schemaVersion is SCHEMA_V2 reaches it."""
        single, legacy = fresh("single"), fresh("legacy")
        with patch.object(linux_readiness, "_validate_linux_evidence_v2", side_effect=AssertionError("v1alpha2 branch")):
            with self.assertRaisesRegex(AssertionError, "v1alpha2 branch"):
                self.verify(single)
            self.passes(legacy)
            for raw in (b"[]", b"null"):
                self.refused("TYPE_MISMATCH", linux_readiness.verify_linux_evidence, raw, **legacy.inputs())


class OwnerRule(SignersCase):
    """Each changes owners or keys in a trust bundle, then re-binds and re-signs the envelope over ENVELOPE_DOMAIN_V2
    and re-binds and re-signs the record over DOMAIN_V2; the capacity is unchanged."""

    def changed(self, kind, owners):
        fixture = fresh(kind)
        fixture.set_owners(*owners)
        fixture.keep_envelope_and_record()
        return fixture

    def test_single_principal_with_two_plus_one_owners(self):
        for position in range(3):
            owners = [F.LABEL] * 3
            owners[position] = "other-owner"
            with self.subTest(owners=owners):
                self.refused("LINUX_SIGNER_OWNERS_NOT_SINGLE_PRINCIPAL", self.verify, self.changed("single", owners))

    def test_single_principal_with_three_equal_owners_other_than_the_label(self):
        self.refused("LINUX_SIGNER_OWNERS_NOT_SINGLE_PRINCIPAL", self.verify, self.changed("single", ["shared-owner"] * 3))

    def test_single_principal_with_a_shared_public_key(self):
        for first, second in (("platform", "tenant"), ("platform", "capacity"), ("tenant", "capacity")):
            with self.subTest(shared=(first, second)):
                fixture = fresh("single")
                keys = {"platform": fixture.release_trust["keys"][0], "tenant": fixture.tenant_trust["keys"][0],
                        "capacity": fixture.tenant_trust["keys"][1]}
                keys[second]["publicKey"] = keys[first]["publicKey"]
                fixture.keep_envelope_and_record()
                self.refused("SIGNER_ROLES_NOT_INDEPENDENT", self.verify, fixture)

    def test_single_principal_with_equal_platform_and_tenant_key_ids(self):
        """Refused at live.py line 149; the envelope re-signed, the record re-bound and re-signed."""
        fixture = fresh("single")
        fixture.envelope["tenantSignerKeyId"] = fixture.envelope["platformSignerKeyId"]
        fixture.sign_envelope()
        fixture.keep_record()
        self.refused("SIGNER_ROLES_NOT_INDEPENDENT", self.verify, fixture)

    def test_independent_principals_with_a_shared_owner(self):
        """The pairwise-distinct check comes first, also when the shared owner is the reserved label (SG2-3)."""
        for owners in (["shared-owner", "shared-owner", "capacity-unit-owner"], ["platform-unit-owner", "tenant-unit-owner", "platform-unit-owner"],
                       [F.LABEL, F.LABEL, "capacity-unit-owner"]):
            with self.subTest(owners=owners):
                self.refused("LINUX_SIGNER_OWNERS_NOT_INDEPENDENT", self.verify, self.changed("independent", owners))

    def test_independent_principals_with_the_reserved_label(self):
        for position in range(3):
            owners = list(F.DISTINCT_OWNERS)
            owners[position] = F.LABEL
            with self.subTest(owners=owners):
                self.refused("LINUX_RESERVED_OWNER_LABEL", self.verify, self.changed("independent", owners))

    def test_g_missing_owner(self):
        """(g): the existing trust-key check, live.py line 326."""
        for kind in ("single", "independent"):
            for bundle, index in (("release_trust", 0), ("tenant_trust", 0), ("tenant_trust", 1)):
                with self.subTest(kind=kind, bundle=bundle, index=index):
                    fixture = fresh(kind)
                    del getattr(fixture, bundle)["keys"][index]["owner"]
                    fixture.keep_envelope_and_record()
                    self.refused("MISSING_FIELD", self.verify, fixture)

    def test_g_non_identifier_owner(self):
        """(g): the existing trust-key check, live.py line 330."""
        for kind in ("single", "independent"):
            for owner in ("Single Principal", "single_principal", ""):
                with self.subTest(kind=kind, owner=owner):
                    fixture = fresh(kind)
                    fixture.tenant_trust["keys"][1]["owner"] = owner
                    fixture.keep_envelope_and_record()
                    self.refused("INVALID_IDENTIFIER", self.verify, fixture)


class Disclosure(SignersCase):
    """The three documents must carry one closed value. Every vector here is properly signed and re-bound unless its
    docstring says otherwise."""

    def test_envelope_against_capacity(self):
        """The envelope alone says INDEPENDENT_PRINCIPALS: re-signed over ENVELOPE_DOMAIN_V2, the record re-bound and
        re-signed. Refused at verify_linux_authority_v2's agreement check."""
        fixture = fresh("single")
        fixture.envelope["signers"] = F.INDEPENDENT
        fixture.sign_envelope()
        fixture.keep_record()
        self.refused("LINUX_SIGNERS_DISCLOSURE_MISMATCH", self.verify, fixture)

    def test_capacity_against_record(self):
        """The capacity alone says INDEPENDENT_PRINCIPALS: re-signed over CAPACITY_DOMAIN_V2, the envelope re-bound and
        re-signed, the record re-bound and re-signed. Refused at the agreement check, before the record's."""
        fixture = fresh("single")
        fixture.capacity["signers"] = F.INDEPENDENT
        fixture.sign_capacity()
        fixture.keep_envelope_and_record()
        self.refused("LINUX_SIGNERS_DISCLOSURE_MISMATCH", self.verify, fixture)

    def test_envelope_against_record(self):
        """The record alone says INDEPENDENT_PRINCIPALS, re-signed over DOMAIN_V2. Refused at the record's check."""
        fixture = fresh("single")
        fixture.record["signers"] = F.INDEPENDENT
        fixture.sign_record()
        self.refused("LINUX_SIGNERS_DISCLOSURE_MISMATCH", self.verify, fixture)

    def test_unknown_value_in_the_envelope(self):
        fixture = fresh("single")
        fixture.envelope["signers"] = UNKNOWN_SIGNERS
        fixture.sign_envelope()
        fixture.keep_record()
        self.refused("LINUX_SIGNERS_INVALID", self.verify, fixture)

    def test_unknown_value_in_the_capacity(self):
        fixture = fresh("single")
        fixture.capacity["signers"] = UNKNOWN_SIGNERS
        fixture.sign_capacity()
        fixture.keep_envelope_and_record()
        self.refused("LINUX_SIGNERS_INVALID", self.verify, fixture)

    def test_unknown_value_in_the_record(self):
        fixture = fresh("single")
        fixture.record["signers"] = UNKNOWN_SIGNERS
        fixture.sign_record()
        self.refused("LINUX_SIGNERS_INVALID", self.verify, fixture)

    def test_signers_missing_from_each_v2_document(self):
        for name in NAMES:
            with self.subTest(document=name):
                fixture = fresh("single")
                del fixture.document(name)["signers"]
                if name == "envelope":
                    fixture.sign_envelope()
                    fixture.keep_record()
                elif name == "capacity":
                    fixture.sign_capacity()
                    fixture.keep_envelope_and_record()
                else:
                    fixture.sign_record()
                self.refused("MISSING_FIELD", self.verify, fixture)

    def test_envelope_with_signers_under_v1alpha1_or_unknown_version(self):
        """The envelope relabelled with `signers` kept, not re-signed (the version refusal comes first); the record
        re-bound and re-signed."""
        for schema in (live.ENVELOPE_SCHEMA, UNKNOWN_VERSION["envelope"]):
            with self.subTest(schema=schema):
                fixture = fresh("single")
                fixture.relabel("envelope", schema, F.SINGLE)
                fixture.keep_record()
                self.refused("UNSUPPORTED_ENVELOPE", self.verify, fixture)

    def test_capacity_with_signers_under_v1alpha1_or_unknown_version(self):
        """The capacity relabelled with `signers` kept, not re-signed; the envelope re-bound and re-signed, the record
        re-bound and re-signed."""
        for schema in (live.CAPACITY_SCHEMA, UNKNOWN_VERSION["capacity"]):
            with self.subTest(schema=schema):
                fixture = fresh("single")
                fixture.relabel("capacity", schema, F.SINGLE)
                fixture.keep_envelope_and_record()
                self.refused("UNSUPPORTED_CAPACITY", self.verify, fixture)


class ReplayAcrossVersions(SignersCase):
    """(b), each with the envelope's capacity digest re-bound."""

    def test_v1alpha1_pair_relabelled_v1alpha2_with_old_signatures(self):
        """The base v1alpha1-signed envelope and capacity relabelled v1alpha2 with `signers` added; old signatures kept;
        the record relabelled v1alpha2, re-bound and re-signed over DOMAIN_V2."""
        fixture = fresh("legacy")
        for name in NAMES:
            fixture.relabel(name, F.V2[name][0], F.INDEPENDENT)
        fixture.bind_envelope()
        fixture.keep_record()
        self.refused("PLATFORM_SIGNATURE_INVALID", self.verify, fixture)

    def test_v1alpha2_pair_relabelled_v1alpha1_on_the_v1alpha1_path(self):
        """A v1alpha2-signed envelope and capacity relabelled v1alpha1 with `signers` removed; old signatures kept; the
        record relabelled v1alpha1, re-bound and re-signed over the v1alpha1 DOMAIN."""
        fixture = fresh("independent")
        for name in NAMES:
            fixture.relabel(name, F.V1[name][0])
        fixture.bind_envelope()
        fixture.keep_record(linux_readiness.DOMAIN)
        self.refused("PLATFORM_SIGNATURE_INVALID", self.verify, fixture)

    def test_capacity_domain_replay(self):
        """A capacity signed as v1alpha1 over CAPACITY_DOMAIN, relabelled v1alpha2 with `signers` added, its signature
        kept; the v1alpha2 envelope re-bound to it and re-signed over ENVELOPE_DOMAIN_V2; the record re-bound and
        re-signed."""
        fixture = fresh("independent")
        fixture.relabel("capacity", live.CAPACITY_SCHEMA)
        fixture.sign_capacity(live.CAPACITY_DOMAIN)
        fixture.relabel("capacity", F.CAPACITY_SCHEMA_V2, F.INDEPENDENT)
        fixture.keep_envelope_and_record()
        self.refused("CAPACITY_SIGNATURE_INVALID", self.verify, fixture)


class MixedDomain(SignersCase):
    """(c)."""

    def test_record_signed_over_the_v1alpha1_domain(self):
        """The v1alpha2 envelope and capacity signed over their v2 domains; the record re-signed over DOMAIN."""
        fixture = fresh("single")
        fixture.sign_record(linux_readiness.DOMAIN)
        self.refused("LINUX_EVIDENCE_SIGNATURE_INVALID", self.verify, fixture)

    def test_envelope_signed_over_the_v1alpha1_domain(self):
        """The original v1alpha2 envelope re-signed over ENVELOPE_DOMAIN; the record re-bound and re-signed (SG3-5)."""
        fixture = fresh("single")
        fixture.sign_envelope(live.ENVELOPE_DOMAIN)
        fixture.keep_record()
        self.refused("PLATFORM_SIGNATURE_INVALID", self.verify, fixture)

    def test_capacity_signed_over_the_v1alpha1_domain(self):
        """The original v1alpha2 capacity re-signed over CAPACITY_DOMAIN; the envelope re-bound to it and re-signed over
        ENVELOPE_DOMAIN_V2; the record re-bound and re-signed. This isolates CAPACITY_DOMAIN_V2 (SG3-5)."""
        fixture = fresh("single")
        fixture.sign_capacity(live.CAPACITY_DOMAIN)
        fixture.keep_envelope_and_record()
        self.refused("CAPACITY_SIGNATURE_INVALID", self.verify, fixture)


class MixedVersions(SignersCase):
    """Restored from revision 1 (SG2-2)."""

    def test_v1alpha2_record_with_a_v1alpha1_envelope(self):
        """The envelope relabelled v1alpha1 without `signers` and re-signed over ENVELOPE_DOMAIN (its own); the record
        re-bound and re-signed over DOMAIN_V2."""
        fixture = fresh("independent")
        fixture.relabel("envelope", live.ENVELOPE_SCHEMA)
        fixture.sign_envelope(live.ENVELOPE_DOMAIN)
        fixture.keep_record()
        self.refused("MISSING_FIELD", self.verify, fixture)

    def test_v1alpha2_record_with_a_v1alpha1_capacity(self):
        """The capacity relabelled v1alpha1 without `signers` and re-signed over CAPACITY_DOMAIN (its own); the envelope
        re-bound and re-signed over ENVELOPE_DOMAIN_V2; the record re-bound and re-signed."""
        fixture = fresh("independent")
        fixture.relabel("capacity", live.CAPACITY_SCHEMA)
        fixture.sign_capacity(live.CAPACITY_DOMAIN)
        fixture.keep_envelope_and_record()
        self.refused("MISSING_FIELD", self.verify, fixture)

    def test_v1alpha1_record_with_a_v1alpha2_envelope_and_capacity(self):
        """The record relabelled v1alpha1 without `signers`, re-bound and re-signed over DOMAIN: today's path."""
        fixture = fresh("independent")
        fixture.relabel("record", linux_readiness.SCHEMA)
        fixture.keep_record(linux_readiness.DOMAIN)
        self.refused("UNKNOWN_FIELD", self.verify, fixture)

    def test_v1alpha1_labelled_envelope_carrying_signers_on_the_v2_path(self):
        """The envelope relabelled v1alpha1 with `signers` kept and re-signed over ENVELOPE_DOMAIN; the record re-bound
        and re-signed over DOMAIN_V2."""
        fixture = fresh("independent")
        fixture.relabel("envelope", live.ENVELOPE_SCHEMA, F.INDEPENDENT)
        fixture.sign_envelope(live.ENVELOPE_DOMAIN)
        fixture.keep_record()
        self.refused("UNSUPPORTED_ENVELOPE", self.verify, fixture)


class Isolation(SignersCase):
    """(d): a v1alpha2 document is UNKNOWN_FIELD on every shared path; its no-`signers` variant is UNSUPPORTED_*."""

    def variants(self, name):
        document = deepcopy(fresh("single").document(name))
        without = {key: value for key, value in document.items() if key != "signers"}
        return (("v1alpha2 with signers", document, "UNKNOWN_FIELD"),
                ("v1alpha2 without signers", without, {"envelope": "UNSUPPORTED_ENVELOPE", "capacity": "UNSUPPORTED_CAPACITY"}[name]))

    def test_v2_envelope_at_validate_envelope(self):
        """live.py line 115 (and 117)."""
        for label, document, code in self.variants("envelope"):
            with self.subTest(label):
                self.refused(code, live.validate_envelope, document, now=INSTANT)

    def test_v2_capacity_at_validate_capacity(self):
        """live.py line 157 (and 159)."""
        envelope = fresh("legacy").envelope
        for label, document, code in self.variants("capacity"):
            with self.subTest(label):
                self.refused(code, live.validate_capacity, document, envelope, now=INSTANT)

    def test_v2_envelope_at_the_preflight(self):
        """live.py line 267."""
        for label, document, code in self.variants("envelope"):
            with self.subTest(label), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "unit-only-envelope.json"
                path.write_bytes(canonical_bytes(document))
                self.refused(code, live.preflight, path, launcher_path=Path(folder) / "unit-only-launcher", now=INSTANT)

    def test_v2_envelope_at_the_supervisor_envelope_check(self):
        """live_supervisor.py line 566."""
        from harness_conformance.live_supervisor import _open_retained_session

        for label, document, code in self.variants("envelope"):
            with self.subTest(label):
                self.refused(code, _open_retained_session, None, canonical_bytes(document))

    def test_v2_envelope_at_verify_backend_authority(self):
        """live_backend_authority.py line 50."""
        from harness_conformance.live_backend_authority import verify_backend_authority

        inputs = fresh("single").inputs()
        for label, document, code in self.variants("envelope"):
            with self.subTest(label):
                self.refused(code, verify_backend_authority, canonical_bytes(document), inputs["capacity_bytes"],
                             inputs["release_trust_bytes"], inputs["tenant_trust_bytes"], now=INSTANT)

    def test_v2_documents_at_the_unchanged_verify_linux_authority(self):
        """The v1alpha2 envelope at line 301; and a v1alpha2 capacity under a v1alpha1 envelope at line 313, the
        envelope re-bound to it and re-signed over ENVELOPE_DOMAIN."""
        inputs = fresh("single").inputs()
        for label, document, code in self.variants("envelope"):
            with self.subTest(label):
                self.refused(code, live.verify_linux_authority, canonical_bytes(document), inputs["capacity_bytes"],
                             inputs["release_trust_bytes"], inputs["tenant_trust_bytes"], now=INSTANT)
        for label, document, code in self.variants("capacity"):
            with self.subTest("capacity " + label):
                fixture = fresh("legacy")
                fixture.capacity = document
                fixture.bind_envelope()
                fixture.sign_envelope(live.ENVELOPE_DOMAIN)
                self.refused(code, self.authority, fixture, live.verify_linux_authority)


class SchemaAndRuntimeAgree(SignersCase):
    """(e), with the test-local interpreter above."""

    def test_the_v2_fixtures_pass_all_three_v2_schemas(self):
        for kind in ("single", "independent"):
            fixture = fresh(kind)
            for name in NAMES:
                with self.subTest(kind=kind, document=name):
                    schema = load_schema("v1alpha2", name)
                    schema_check(fixture.document(name), schema, schema, set())
        schema = load_schema("v1alpha2", "record")
        arm = F.SignersFixture(F.SINGLE, architecture="arm64")
        schema_check(arm.record, schema, schema, set())
        schema_check(arm.plan, schema["$defs"]["plan"], schema, set())
        self.assertEqual(schema["$defs"]["plan"]["properties"]["schemaVersion"]["const"], "harness.planeon.ai/linux-readiness-plan/v1alpha1")

    def test_every_ref_use_is_resolved_and_checked_in_full(self):
        """22 `$ref` uses in the envelope schema and 3 in the capacity schema, each resolved and applied; none in the
        evidence schema. The v1alpha1 files have the same counts."""
        fixture = fresh("single")
        for name, count in (("envelope", 22), ("capacity", 3), ("record", 0)):
            with self.subTest(document=name):
                schema = load_schema("v1alpha2", name)
                uses = ref_uses(schema)
                self.assertEqual((len(uses), len(set(uses))), (count, count))
                self.assertEqual(len(ref_uses(load_schema("v1alpha1", name))), count)
                seen = set()
                schema_check(fixture.document(name), schema, schema, seen)
                self.assertEqual(seen, set(uses))

    def test_missing_or_unknown_signers_fail_schema_and_runtime(self):
        fixture = fresh("single")
        runtime = {"envelope": lambda document: live.validate_envelope_v2(document, now=INSTANT),
                   "capacity": lambda document: live.validate_capacity_v2(document, fixture.envelope, now=INSTANT),
                   "record": linux_readiness._validate_linux_evidence_v2}
        for name in NAMES:
            schema = load_schema("v1alpha2", name)
            for change, code in (("missing", "MISSING_FIELD"), ("unknown", "LINUX_SIGNERS_INVALID")):
                with self.subTest(document=name, change=change):
                    document = deepcopy(fixture.document(name))
                    if change == "missing":
                        del document["signers"]
                    else:
                        document["signers"] = UNKNOWN_SIGNERS
                    with self.assertRaises(AssertionError):
                        schema_check(document, schema, schema, set())
                    self.refused(code, runtime[name], document)

    def test_v1alpha1_documents_fail_the_v2_schemas(self):
        """The base documents fail the v1alpha2 schemas and still pass their v1alpha1 ones."""
        legacy = fresh("legacy")
        for name in NAMES:
            with self.subTest(document=name):
                schema = load_schema("v1alpha2", name)
                with self.assertRaises(AssertionError):
                    schema_check(legacy.document(name), schema, schema, set())
                schema = load_schema("v1alpha1", name)
                schema_check(legacy.document(name), schema, schema, set())

    def test_the_interpreter_fails_closed_on_an_external_or_unresolvable_ref(self):
        root = {"$defs": {"digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}}}
        for reference in ("other.schema.json#/$defs/digest", "#/$defs/missing", "#/$defs/digest/pattern", "#/properties/x", 7):
            with self.subTest(reference=reference), self.assertRaises(AssertionError):
                schema_check("sha256:" + "0" * 64, {"$ref": reference}, root, set())
        with self.assertRaises(AssertionError):
            schema_check("not-a-digest", {"$ref": "#/$defs/digest"}, root, set())
        with self.assertRaises(AssertionError):
            schema_check(["a", "a"], {"type": "array", "uniqueItems": True}, root, set())
        seen = set()
        schema_check("sha256:" + "0" * 64, {"$ref": "#/$defs/digest"}, root, seen)
        self.assertEqual(seen, {"#"})

    def test_the_v2_schemas_are_v1alpha1_with_exactly_section_4s_changes(self):
        for name in NAMES:
            with self.subTest(document=name):
                v1, v2 = load_schema("v1alpha1", name), load_schema("v1alpha2", name)
                expected = deepcopy(v1)
                expected["$id"] = v1["$id"].replace("/v1alpha1/", "/v1alpha2/")
                const = v1["properties"]["schemaVersion"]["const"]
                self.assertTrue(const.endswith("/v1alpha1"))
                expected["properties"]["schemaVersion"]["const"] = const[:-len("v1alpha1")] + "v1alpha2"
                expected["required"] = v1["required"] + ["signers"]
                expected["properties"]["signers"] = {"enum": ["INDEPENDENT_PRINCIPALS", "SINGLE_PRINCIPAL_SEPARATED_KEYS"]}
                self.assertEqual(v2, expected)
                self.assertIs(v2["additionalProperties"], False)


class PacketScope(SignersCase):
    """(f), MON-SG-PKTID."""

    def test_the_v2_envelope_keeps_conf_linux_001_and_its_packet_digest(self):
        envelope = fresh("single").envelope
        self.assertEqual((envelope["packetId"], envelope["packetDigest"]), ("CONF-LINUX-001", linux_readiness.PACKET_DIGEST))

    def test_another_packet_id_or_packet_digest(self):
        """The envelope re-signed over ENVELOPE_DOMAIN_V2, the record re-bound and re-signed."""
        for field, value in (("packetId", "CONF-LINUX-002"), ("packetDigest", F.digest("other-packet"))):
            with self.subTest(field=field):
                fixture = fresh("single")
                fixture.envelope[field] = value
                fixture.sign_envelope()
                fixture.keep_record()
                self.refused("LINUX_ENVELOPE_SCOPE_MISMATCH", self.verify, fixture)


class OtherFindings(SignersCase):
    """(h)."""

    def test_v2_record_through_schema_validate(self):
        self.refused("UNKNOWN_FIELD", validate, "linux-readiness-evidence", fresh("single").record)

    def test_v2_record_through_the_cli(self):
        """`validate --kind linux-readiness-evidence` keeps refusing v1alpha2 (SG1-3)."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unit-only-v1alpha2.json"
            path.write_bytes(canonical_bytes(fresh("single").record))
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                code = cli.main(["validate", "--kind", "linux-readiness-evidence", str(path)])
        self.assertEqual((code, stdout.getvalue()), (2, ""))
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["status"], "FAIL")
        self.assertReason("UNKNOWN_FIELD", failure["reasonCode"])

    def test_non_object_record_at_verify_linux_evidence(self):
        inputs = fresh("single").inputs()
        for raw in (b"[]", b'"record"', b"7", b"null"):
            with self.subTest(raw=raw):
                self.refused("TYPE_MISMATCH", linux_readiness.verify_linux_evidence, raw, **inputs)

    def test_v1alpha1_record_carrying_signers(self):
        """The base v1alpha1 record with `signers` added, re-signed over DOMAIN."""
        fixture = fresh("legacy")
        fixture.record["signers"] = F.INDEPENDENT
        fixture.sign_record(linux_readiness.DOMAIN)
        self.refused("UNKNOWN_FIELD", self.verify, fixture)

    def test_record_without_signers_and_with_an_unknown_version(self):
        """The base v1alpha1 record relabelled to an unknown version; not re-signed (the shape refusal comes first)."""
        fixture = fresh("legacy")
        fixture.relabel("record", UNKNOWN_VERSION["record"])
        self.refused("LINUX_EVIDENCE_SCHEMA_INVALID", self.verify, fixture)

    def test_malformed_input_inside_verify_linux_authority_v2(self):
        """SG3-3: a v1alpha2 capacity whose permittedEndpointIds holds a list, an unhashable item, raises TypeError at
        live.py line 176 inside validate_capacity on the copy, inside the `try`. The capacity re-signed over
        CAPACITY_DOMAIN_V2, the envelope re-bound and re-signed, the record re-bound and re-signed."""
        fixture = fresh("single")
        fixture.capacity["permittedEndpointIds"] = [["unit-proxy"]]
        fixture.sign_capacity()
        fixture.keep_envelope_and_record()
        error = self.refused("LINUX_AUTHORITY_MALFORMED", self.verify, fixture)
        self.assertIsInstance(error.__cause__, TypeError)
        self.refused("LINUX_AUTHORITY_MALFORMED", self.authority, fixture, live.verify_linux_authority_v2)


class SignaturesStillRequired(SignersCase):
    """Section 2: the disclosure never removes a signature. Each v1alpha2 signature, replaced by a valid-encoding wrong
    one, is refused with today's code."""

    def test_each_v2_authority_signature_is_required(self):
        zero = b64url_encode(b"\x00" * 64)
        for field, code in (("platformSignature", "PLATFORM_SIGNATURE_INVALID"), ("tenantSignature", "TENANT_SIGNATURE_INVALID"),
                            ("signature", "CAPACITY_SIGNATURE_INVALID")):
            with self.subTest(field=field):
                fixture = fresh("single")
                if field == "signature":
                    fixture.capacity[field] = zero
                    fixture.keep_envelope_and_record()
                else:
                    fixture.envelope[field] = zero
                    fixture.keep_record()
                self.refused(code, self.verify, fixture)


if __name__ == "__main__":
    unittest.main()
