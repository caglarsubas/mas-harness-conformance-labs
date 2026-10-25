"""CONF-LINUX-002: the v1alpha2 `signers` builder, derived from the unchanged linux_baseline fixture (UNIT-ONLY keys).

The base fixture is loaded by path under a distinct module name (design rev 4 section 5, SG1-11), and its file stays
unchanged. Callers put `src` first on sys.path before loading this module, as test_signers.py does. The builder turns
the base's signed v1alpha1 set into a v1alpha2 set and signs the original v1alpha2 documents over the v2 domains.

Each helper does one thing and says so: `relabel` and `set_owners` change a document without re-binding or re-signing;
`bind_*` recompute the digests that bind a changed document; `sign_*` re-sign one document over the domain it is given.
A vector composes them, so it states exactly which documents it re-bound and re-signed (SG2-1, SG3-1).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("linux_signers_base_fixtures", ROOT / "tests/platform/linux_baseline/_fixtures.py")
BASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(BASE)

from harness_conformance.canonical import byte_digest, canonical_bytes  # noqa: E402
from harness_conformance.crypto import b64url_encode, sign, signature_payload  # noqa: E402
from harness_conformance.linux_readiness import DOMAIN, SCHEMA, SIGNATURES  # noqa: E402
from harness_conformance.live import CAPACITY_DOMAIN, CAPACITY_SCHEMA, ENVELOPE_DOMAIN, ENVELOPE_SCHEMA  # noqa: E402

NOW = BASE.NOW
digest = BASE.digest

# Literal values, independent of src: the tests assert src's constants against these strings (SG3-5).
INDEPENDENT = "INDEPENDENT_PRINCIPALS"
SINGLE = "SINGLE_PRINCIPAL_SEPARATED_KEYS"
LABEL = "single-principal"
DISTINCT_OWNERS = ("platform-unit-owner", "tenant-unit-owner", "capacity-unit-owner")
ENVELOPE_SCHEMA_V2 = "harness.planeon.ai/live-campaign-execution-envelope/v1alpha2"
CAPACITY_SCHEMA_V2 = "harness.planeon.ai/live-capacity-authorization/v1alpha2"
RECORD_SCHEMA_V2 = "harness.planeon.ai/linux-readiness-evidence/v1alpha2"
ENVELOPE_DOMAIN_V2 = "planeon.harness-live-execution-envelope/v1alpha2"
CAPACITY_DOMAIN_V2 = "planeon.harness-live-capacity-authorization/v1alpha2"
RECORD_DOMAIN_V2 = "planeon.harness-linux-readiness-evidence/v1alpha2"
V1 = {"envelope": (ENVELOPE_SCHEMA, ENVELOPE_DOMAIN), "capacity": (CAPACITY_SCHEMA, CAPACITY_DOMAIN), "record": (SCHEMA, DOMAIN)}
V2 = {"envelope": (ENVELOPE_SCHEMA_V2, ENVELOPE_DOMAIN_V2), "capacity": (CAPACITY_SCHEMA_V2, CAPACITY_DOMAIN_V2),
      "record": (RECORD_SCHEMA_V2, RECORD_DOMAIN_V2)}


class SignersFixture(BASE.LinuxFixture):
    """One consistent, signed v1alpha2 set: the envelope, the capacity and the record carry the same `signers` value.

    SINGLE gives all three selected trust keys the owner `single-principal`; INDEPENDENT keeps the base fixture's three
    distinct owners, none of them the label. The three keys, key ids and seeds stay the base fixture's distinct ones.
    """

    def __init__(self, signers=SINGLE, owners=None, architecture="amd64"):
        super().__init__(architecture)
        for name in ("envelope", "capacity", "record"):
            self.relabel(name, V2[name][0], signers)
        self.set_owners(*(owners or ((LABEL,) * 3 if signers == SINGLE else DISTINCT_OWNERS)))
        self.resign_v2()

    @classmethod
    def v1alpha1(cls, owners=None, architecture="amd64"):
        """The base fixture's v1alpha1 set, with these helpers; given owners, it is re-signed over the v1alpha1 domains."""
        fixture = cls.__new__(cls)
        BASE.LinuxFixture.__init__(fixture, architecture)
        if owners is not None:
            fixture.set_owners(*owners)
            fixture.sign_capacity(CAPACITY_DOMAIN)
            fixture.bind_envelope()
            fixture.sign_envelope(ENVELOPE_DOMAIN)
            fixture.bind_record()
            fixture.sign_record(DOMAIN)
        return fixture

    def document(self, name):
        return {"envelope": self.envelope, "capacity": self.capacity, "record": self.record}[name]

    def relabel(self, name, schema, signers=None):
        """Set one document's schemaVersion and set its `signers`, or drop it when signers is None. Signs nothing."""
        document = self.document(name)
        document["schemaVersion"] = schema
        if signers is None:
            document.pop("signers", None)
        else:
            document["signers"] = signers

    def set_owners(self, platform, tenant, capacity):
        """The owners of the three selected trust keys (both trust bundles change). Re-binds and signs nothing."""
        self.release_trust["keys"][0]["owner"] = platform
        self.tenant_trust["keys"][0]["owner"] = tenant
        self.tenant_trust["keys"][1]["owner"] = capacity

    def owners(self):
        return [self.release_trust["keys"][0]["owner"], self.tenant_trust["keys"][0]["owner"], self.tenant_trust["keys"][1]["owner"]]

    def sign_capacity(self, domain=CAPACITY_DOMAIN_V2):
        """Re-sign the capacity (CAPACITY_OPERATOR) over `domain`."""
        self.capacity["signature"] = b64url_encode(sign(self.seeds["capacity"], signature_payload(domain, self.capacity, ("signature",))))

    def bind_envelope(self):
        """Re-bind the envelope's capacityAuthorizationDigest and both trust-bundle digests. Signs nothing."""
        self.envelope["capacityAuthorizationDigest"] = byte_digest(canonical_bytes(self.capacity))
        self.envelope["releaseTrustStoreDigest"] = byte_digest(canonical_bytes(self.release_trust))
        self.envelope["tenantTrustStoreDigest"] = byte_digest(canonical_bytes(self.tenant_trust))

    def sign_envelope(self, domain=ENVELOPE_DOMAIN_V2):
        """Re-sign the envelope (PLATFORM_RELEASE and TENANT_LIVE_EXECUTION) over `domain`."""
        payload = signature_payload(domain, self.envelope, ("platformSignature", "tenantSignature"))
        for role in ("platform", "tenant"):
            self.envelope[role + "Signature"] = b64url_encode(sign(self.seeds[role], payload))

    def bind_record(self):
        """Re-bind the record's `authority` (envelopeDigest, capacityDigest and the rest). Signs nothing."""
        self.record["authority"] = self.bindings()

    def sign_record(self, domain=RECORD_DOMAIN_V2):
        """Re-sign the record (all three roles) over `domain`."""
        payload = signature_payload(domain, self.record, SIGNATURES)
        for role in ("platform", "tenant", "capacity"):
            self.record[role + "Signature"] = b64url_encode(sign(self.seeds[role], payload))

    def resign_v2(self):
        """Sign the capacity, re-bind and sign the envelope, re-bind and sign the record: all over the v2 domains."""
        self.sign_capacity()
        self.keep_envelope_and_record()

    def keep_envelope_and_record(self, envelope_domain=ENVELOPE_DOMAIN_V2, record_domain=RECORD_DOMAIN_V2):
        """After a capacity or trust-bundle change: re-bind and re-sign the envelope, then re-bind and re-sign the record."""
        self.bind_envelope()
        self.sign_envelope(envelope_domain)
        self.keep_record(record_domain)

    def keep_record(self, record_domain=RECORD_DOMAIN_V2):
        """After an envelope or capacity change: re-bind and re-sign the record."""
        self.bind_record()
        self.sign_record(record_domain)
