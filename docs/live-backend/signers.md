# CONF-LINUX-002 — the `signers` disclosure on the CONF-LINUX-001 path

Source implementation checkpoint. It records what the R12 code checks. It does not predict a run, claim an installed
backend, or turn unit verification into native evidence: every result stays `UNIT_VERIFICATION_ONLY` with
`nativeAcceptance: false`.

## Why

The owner's answer Q-LHA-1 (a), "Separated keys, disclosed (Recommended)", lets one principal hold the three separated
keys of PLATFORM_RELEASE, TENANT_LIVE_EXECUTION and CAPACITY_OPERATOR. Today's `live.verify_linux_authority` requires
the three selected trust keys to have three distinct `owner`s (`LINUX_SIGNER_OWNERS_NOT_INDEPENDENT`), so it refuses
every such record. This packet adds a disclosed, signed alternative on the CONF-LINUX-001 path only. Apart from the
owner rule, which the disclosure selects, it removes no check and no signature.

## The disclosure and its two values

`signers` is a closed string with exactly two values. Each value selects one owner rule over the three selected trust
keys; nothing else changes.

| Value | Owner rule | Refusal |
| --- | --- | --- |
| `INDEPENDENT_PRINCIPALS` | the three owners are pairwise distinct, then none equals the reserved label `single-principal` | `LINUX_SIGNER_OWNERS_NOT_INDEPENDENT`, then `LINUX_RESERVED_OWNER_LABEL` |
| `SINGLE_PRINCIPAL_SEPARATED_KEYS` | all three owners equal the fixed label `single-principal` | `LINUX_SIGNER_OWNERS_NOT_SINGLE_PRINCIPAL` (two plus one, or any other shared value) |

A missing owner stays `MISSING_FIELD` and a non-identifier owner stays `INVALID_IDENTIFIER`, from the trust-key
checks that `verify_linux_authority_v2` repeats from `verify_linux_authority`. The label passes `require_id`; it is
role-free and carries no person's or account's name.

Unchanged under both values: the three distinct public keys, the distinct platform and tenant key ids, the key
purposes, tenant and environment scopes, revocation and validity windows, every signature, the evidence class and
`nativeAcceptance: false`.

## Where it lives

The same value appears in three signed documents, and any disagreement is `LINUX_SIGNERS_DISCLOSURE_MISMATCH`:

- the v1alpha2 execution envelope, signed by PLATFORM_RELEASE and TENANT_LIVE_EXECUTION;
- the v1alpha2 capacity authorization, signed by CAPACITY_OPERATOR;
- the v1alpha2 Linux evidence record, signed by all three.

So every authority signs the disclosure before the run, and the evidence restates it. An unknown value is
`LINUX_SIGNERS_INVALID`; a v1alpha2 document without `signers` is `MISSING_FIELD`.

## The v1alpha2 path

- **Schemas** (gate material, Q-SG-7/8): `schemas/v1alpha2/live-campaign-execution-envelope.schema.json`,
  `live-capacity-authorization.schema.json` and `linux-readiness-evidence.schema.json`. Each is its v1alpha1 file with
  the `$id` and the `schemaVersion` const moved to v1alpha2 and `signers` added to `required` and `properties`. The
  evidence schema's nested plan const stays `linux-readiness-plan/v1alpha1`. The v1alpha1 files are byte-identical.
- **Domains:** the v1alpha2 envelope, capacity and record signatures are verified over their own `/v1alpha2`
  domains, so a v1alpha1 signature never verifies over a v1alpha2 document, and the reverse.
- **Code** (Q-SG-6, the scoped exception): `live.py` only adds lines: six constants (`ENVELOPE_SCHEMA_V2`,
  `CAPACITY_SCHEMA_V2`, `ENVELOPE_DOMAIN_V2`, `CAPACITY_DOMAIN_V2`, `SIGNERS` and `SINGLE_PRINCIPAL_OWNER`) and four
  functions. `linux_readiness.py` adds three constants (`SCHEMA_V2`, `DOMAIN_V2` and `RECORD_FIELDS_V2`) and one
  private function (`_validate_linux_evidence_v2`), and in `verify_linux_evidence` it extends the local import and
  adds the dispatch. Neither file signs anything; both verify signatures.
  - `validate_envelope_v2` and `validate_capacity_v2`, like `linux_readiness`'s private `_validate_linux_evidence_v2`,
    check the closed v1alpha2 original first, run the unchanged v1alpha1 validator on a copy for its refusals only,
    and return the original.
  - `verify_live_signatures_v2` is `verify_live_signatures` under five substitutions: its def line (the name and the
    parameters `envelope_v2` and `capacity_v2`) and docstring; `envelope_v2[` for `envelope[` (8 times);
    `capacity_v2[` for `capacity[` (2 times); and the envelope and capacity payloads over `ENVELOPE_DOMAIN_V2` and
    `CAPACITY_DOMAIN_V2`. So it repeats its original's steps inline, in the same order, over the original v1alpha2
    documents and the v2 domains.
  - `verify_linux_authority_v2` is `verify_linux_authority` under five substitutions: its def lines (the name, their
    alignment and the return annotation `tuple[Any, ...]`) and docstring; `validate_envelope_v2` for
    `validate_envelope`; `validate_capacity_v2` for `validate_capacity`; `verify_live_signatures_v2` for
    `verify_live_signatures`, followed by the `signers` agreement (`LINUX_SIGNERS_DISCLOSURE_MISMATCH`); and today's
    owner check, now under `INDEPENDENT_PRINCIPALS` and followed by the reserved-label check, with the single-label
    check for `SINGLE_PRINCIPAL_SEPARATED_KEYS` beside it and the agreed `signers` returned as a fifth item.
  - `verify_linux_evidence` sends only an object whose `schemaVersion` is `SCHEMA_V2` to the new branch. The branch
    validates the record with `_validate_linux_evidence_v2(doc)` where today's body uses
    `validate_linux_evidence(doc)`, then repeats the rest of today's body inline, indented one level, under three
    substitutions: `verify_linux_authority_v2` for `verify_linux_authority`, with its fifth item unpacked as
    `signers`; the record signatures over `DOMAIN_V2`; and the record's `signers` agreement after its distinct-key
    check. Every other document takes today's body: today's `validate_linux_evidence` on the same parsed document,
    then today's remaining lines byte for byte, so it meets today's refusals with today's codes.
  - The drift tests (`DriftAgainstV1alpha1` in `tests/linux_signers/test_signers.py`) hold each of the three inline
    copies equal to its original under its substitution table there (`SIGNATURES_SUBSTITUTIONS`,
    `AUTHORITY_SUBSTITUTIONS` and `BRANCH_SUBSTITUTIONS`; for the branch, after its record-validation line and with
    today's body indented one level), and pin the originals by the sha256 of their base bytes. Those tables, not
    this summary, are the exact statement of the differences.
- **The packet id:** a v1alpha2 envelope keeps `packetId` CONF-LINUX-001 and its packet digest (MON-SG-PKTID). The
  documents' schema versions distinguish the path.
- **Isolation:** the shared validators are unchanged, so a v1alpha2 envelope or capacity is refused as
  `UNKNOWN_FIELD` (or `UNSUPPORTED_ENVELOPE` / `UNSUPPORTED_CAPACITY` without `signers`) by the preflight, the
  CONF-LIVE-006 backend authority, the supervisor and the unchanged `verify_linux_authority`. `schema.validate` and
  `validate --kind linux-readiness-evidence` keep refusing a v1alpha2 record as `UNKNOWN_FIELD`. A record carrying
  `signers` under v1alpha1 or an unknown version takes today's path and is `UNKNOWN_FIELD`.

## The binding order

Today's order, kept on the v1alpha2 path, with the disclosure's checks added (the agreement in step 3 and the
restatement at the end of step 4):

1. the envelope binds the capacity and both trust bundles by digest (`LINUX_AUTHORITY_DIGEST_MISMATCH`);
2. then the envelope and capacity signatures are checked;
3. then the envelope's and the capacity's `signers` must agree, and the owner rule runs;
4. the evidence record binds the envelope and the capacity by digest in its `authority` member
   (`LINUX_AUTHORITY_BINDING_MISMATCH`), before its own three signatures, then restates `signers`.

So, for a change that every earlier check still admits: a capacity or trust bundle changed after signing first fails
`LINUX_AUTHORITY_DIGEST_MISMATCH`, unless the envelope's digest of it is re-bound. A changed envelope fails its own
signature, `PLATFORM_SIGNATURE_INVALID`, before the record's `envelopeDigest` is compared. A changed record is bound by
no digest and fails `LINUX_EVIDENCE_SIGNATURE_INVALID`.

## The custody reading and its limits

> **Note (LHA-CN-2's reading).** Owner labels are self-asserted in the trust bundles. R12 code can check that the
> three keys are distinct, that the labels follow the disclosed rule and that all three authorities signed the same
> disclosure. It cannot show who holds the keys. The disclosure's honesty rests on the owner's custody of the trust
> bundles, not on R12 code. A single-principal run therefore uses the v1alpha2 path with
> `SINGLE_PRINCIPAL_SEPARATED_KEYS`, and all three trust keys carry the label `single-principal`.

## Not in scope

CONF-LIVE-006's adapter and its owner rule, the preflight, the supervisor, the backend, `schema.validate`, the CLI
and every v1alpha1 document stay as they are. `linux-boundary.md` is unchanged. No run is implied by this document.
