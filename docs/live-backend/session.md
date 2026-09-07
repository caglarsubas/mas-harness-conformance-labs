# Alpha 2 · CONF-LIVE-001 — session contracts and cumulative inventory

Source implementation checkpoint. Local offline, PR CI, merge and independent
exact-main evidence are recorded separately in this packet's PR closure; this
document does not predict those results or claim an installed backend.

## Immutable inputs

The implementation consumes MET-LIVE-001 meta main
`50cfd3f13c6942bc7a6995d463482a390db0a98e`, conformance main
`88de1d9b7272a25678b01129e51d5756dbe608ed` and model-contracts main
`e9de8e53cf036a90a03b1e114eba08fc0ba89ae3`. The data-only
`fixtures/live-backend/baseline.json` contains every original tracked path,
mode, size, Git blob and SHA-256: **103 files, 120 test identities, five roots**.
It also pins the source-only model release manifest, model-input lock, exact
authority guide/runner contract/roadmap and all six packet digests and path grants.
No warm-source code, original-source execution or behavioral parity is claimed.

The new adapter hard-pins CONF-LIVE-006 to
`sha256:f95c277cffdfb622f45a1b4b91a5292d9d9a5bfabc8f9388b3899cbb20c5213d`
and the ordered eight commands from that published packet. The old
`live.verify_linux_authority`, seven commands, Linux verifier, wire schemas,
tests, launcher and builder are unchanged. The old and new authority adapters
reject each other's envelope even with otherwise valid independent signatures.

## Pure APIs and ownership

| API | Result / validation | Never grants |
| --- | --- | --- |
| `verify_backend_authority(..., now=datetime)` | Detached envelope/capacity/trust data, three signatures, independent key bytes and owners, scopes, exact successor packet/commands, digest/time/revocation checks | Installed custody, path opening, replay reservation |
| `binding_from_authority(..., now=UTC_string)` | Exact nonce/tenant/environment/release, released plan, fixed proxy policy and all ten request builders; intersection of envelope, capacity and three selected trust-key windows | Native evidence, server admission, live channel |
| `validate_session(value, expected_binding, now)` | Closed detached session data with half-open validity `[issuedAt, expiresAt)` | A verified boolean, token, FD, memfd or executable capability |
| `transition_candidate(value, next_state, expected_binding, now)` | Non-session proposed edge, digest/nonce and `requiresProtectedSupervisor=true`; always `UNIT_VERIFICATION_ONLY`, `nativeAcceptance=false` | An applied state change, nonce reservation, running process |
| `validate_request(value, session, expected_binding, expected_request, now)` | Exact existing `build_probe_request` shape/bytes and running-session data binding | URL, credential, argv or transport admission |
| `validate_receipt(value, session, expected_binding, expected_request, expected_regressions, now)` | Unchanged Linux eight-field case record, nonce/probe/command/time/output digest and mandatory assertion/count checks | Signature verification or native/tenant acceptance |

The expected binding contains exactly nonce, tenantId, environmentId,
packetDigest, commandSetDigest, releaseDigest, capacityDigest, endpointId,
namespace, notBefore and notAfter. The final two values are the signed validity
intersection. Selecting that data from caller-owned JSON alone is not authority;
the future protected supervisor must supply independent installed custody,
authenticated kernel peer/process provenance and one-use durable replay storage.

Sessions add schemaVersion, issuedAt, expiresAt and state, and do not serialize
notBefore/notAfter. No additional field is accepted. Identifiers and digests use
the predecessor grammar; UTC timestamps use its strict RFC3339 subset (up to
six fractional digits). Strict canonical JSON accepts the predecessor's optional
single final LF. Both transport bytes and canonical content must fit the bound.
Session/request limit: **16 KiB**; receipt limit: **4 MiB**; nesting: **8**.
Duplicate members, floats/non-finite numbers, invalid UTF-8, non-normalized
strings, cycles, object hooks and builtin subclasses are rejected. Runtime
validation additionally checks cross-field constraints not expressible in JSON
Schema; the schema never claims to validate custody or signatures.

## State model, not an executor

| State | Possible next state in protected supervisor | This packet |
| --- | --- | --- |
| UNAVAILABLE | None for this attempt | Terminal data; no operation |
| VALIDATED_DATA | RESERVED after independent custody and durable nonce consumption | Proposal only, never reserve from data |
| RESERVED | RUNNING, FAILED, CANCELLED, EXPIRED | Proposal only |
| RUNNING | COMPLETED, FAILED, CANCELLED, EXPIRED | Proposal only; one operation at a time is future supervisor responsibility |
| COMPLETED / FAILED / CANCELLED / EXPIRED | None | Cannot restart/re-reserve/reuse |

Expiry is exclusive: at or after expiry only the eligible EXPIRED edge can be
proposed, never successful completion; early expiry is invalid. Expired records
are not current sessions. Malformed values raise stable `ConformanceError`
reason codes; missing protected backend/capacity is still
`NOT_RUN_ENV_UNAVAILABLE`, not an executable fallback. The later supervisor
must fsync reservation before credentials/execution, retain terminal receipts,
consume crashed/expired nonces permanently, and reap all descendants. Nothing
in this source packet implements those protected effects.

Request scope and architecture are inherited from the protected session and
independently selected fixed request. A raw case record does not carry its own
architecture/signature and cannot establish either; it must remain inside the
later verified full signed Linux record/channel context. Full-regression receipts
must bind all three repository inventories and at least the original 120
conformance identities. Future source increments supply their larger exact
inventory; skipped/failed/unexecuted cases cannot report PASS. Executed failure
remains FAIL, unavailable assertions remain NOT_RUN_ENV_UNAVAILABLE.

## Cumulative regression and evidence

The packet declares all five original roots plus flat `tests/live_backend`,
then the unchanged linux-baseline campaign and evidence commands. Run only the
exact packet via the signed installed deny-all offline launcher: never invoke
these suites, helper, Make targets or inner wrapper separately as acceptance.

New inventory tests compare AST identities with actual unittest collection for
each root in a fresh child of the same isolated process tree, avoiding collisions
between `_fixtures` and `test_inventory` module names. Test bodies still run in
their separately declared suite commands. No namespace omission, load_tests
deselection, skip, expected failure, inherited extra or substituted module is
accepted. The complete tracked inventory is the baseline plus exact declared
new paths; no broad directory exemptions. All old file hashes remain enforced.
Only the final CONF-LIVE-006 hook may later change old `live_launcher.py`, and
the old inventory guards continue to execute unchanged.

Negative vectors cover all session fields and bindings, canonical/size/depth
boundaries, every one of 64 state pairs, forged flags/FDs, the full original
inventory, mutually exclusive authorities, each signature/role/trust/capacity
boundary, released plan/proxy scope, and every fixed case on both architecture
labels. All fixture keys/observations are deterministic **unit-only**; labels
are not observations of native targets. No dependencies, downloads, installation,
cloud/VM provisioning, billable API, hosted runner or source/native promotion.

## Backlog and rollback

| Phase | ID | Status at source implementation | Description |
| --- | --- | --- | --- |
| Alpha 2 | MET-LIVE-001 | DONE | Published source authority, separate exact-main closure |
| Alpha 2 | CONF-LIVE-001 | ONGOING verification | This bounded source increment; terminal status in PR closure |
| Alpha 2 | CONF-LIVE-002 | WAITING | Protected Linux supervisor and isolation candidate |
| Alpha 2 | CONF-LIVE-003 | WAITING | Fixed proxy and server-side zero-cost admission |
| Alpha 2 | CONF-LIVE-004 | WAITING | Native build and ten fixed probe adapters |
| Alpha 2 | CONF-LIVE-005 | WAITING | Reproducible source packaging and operator handoff |
| Alpha 2 | CONF-LIVE-006 | WAITING | Integration, cumulative package and manual declaration |
| Alpha 2 | Native AMD64 / ARM64 qualification | NOT_RUN_ENV_UNAVAILABLE | Independent installation/capacity/signatures and real observations |
| Alpha 2 | CTRL-INTEGRATE-001 / MODEL-001 / EXEC-001 / RUN-001 | WAITING | Fresh native AMD64 gate remains closed |
| Alpha 3–4 | Governed actions / enterprise matrix | WAITING | Existing downstream packet gates and tenant acceptance |

Revert this unconsumed increment before successor work. Once consumed, use a
reviewed corrective packet. Never alter installation, tenant data, keys, trust,
replay history or historical evidence. Alpha 2 is not complete; no phase-end
model-effort transition is due.
