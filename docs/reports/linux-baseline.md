# CONF-LINUX-001: early Linux qualification source kit

Phase: **Alpha 2 qualification**. Source implementation and offline verification
are distinct from native Linux acceptance. This report is a source snapshot;
exact candidate, PR/CI, merge and post-merge replay receipts belong to the PR
closure record and external operator evidence, not self-referential commit pins.

## Authority and predecessor baseline

- Packet: `CONF-LINUX-001`, SHA-256
  `22f00544680f90a90b03420632bebf192a8c687549b519770fca5f98dd5fd6c9`.
- Meta authority: `a50f878296295abf42dc48093904d99f046f0d2b`
  (MET-REPAIR-004, meta PR 97).
- Owned conformance predecessor: `07453d3e6313c836426545c454380176bc2a2ee1`
  (CONF-FIX-001, conformance PR 4; required source run 34052209212).
- Control prerequisite: `1de7c405329f4458970be0187838145b4da222d8`
  (CTRL-FIX-003); this is a source prerequisite, not a Linux-built image pin.
- Before edits, the exact predecessor was replayed with this packet through
  the existing signed offline host launcher: meta 37, parity 14, Alpha 1 nine,
  runner-boundary 23 tests passed (83 total). The fifth command correctly
  failed because the Linux test directory did not yet exist. This is a
  preserved baseline failure, not packet acceptance. Log SHA-256:
  `7b5c6e15e00c980b65668a662cb9b446b3508de350f175d22dca570a33982ddf`.

No warm repository was accessed, copied or modified. The four legacy modules
in `predecessor-sources.json` are owned conformance code from the exact baseline;
their Git blob hashes are checked against the 91-file predecessor inventory.
They support byte-for-byte comparison of all three older campaign reports,
evidence summaries and unsigned acceptance candidates, not a substitute for
running every predecessor test against current shared code.

## Implemented source surface

`LINUX_READINESS` is the sole added handler. The closed campaign contains ten
mandatory cases for **each** of native AMD64 and native ARM64, in fixed order:

1. Host isolation negatives: IPv4/IPv6/DNS/loopback, descendants, warm roots,
   credentials, sockets and immutable packet handling.
2. Linux-target build: native dependencies/executable, pinned offline cache,
   recipe/toolchain/SBOM/log, and no downloads.
3. Full predecessor regression: contracts, control and conformance inventory
   digests and counts; no skipped, failed, deselected or expected-failure cases.
4. Standalone control-container startup, health and disabled telemetry.
5. PostgreSQL forward/idempotent fixture migration and cross-tenant RLS denial.
6. Durable restart with persisted records and tenant boundaries preserved.
7. Arbitrary non-root UID, dropped capabilities and enforced seccomp.
8. Read-only root filesystem and only declared writable volumes.
9. Namespace/quota/admission-bound Kubernetes smoke and run-labelled cleanup.
10. Default-deny networking, metadata denial and non-bypassable proxy policy.

The schema closes every nested member. Structural validation is explicitly
`STRUCTURAL_ONLY`; it does not verify signatures or originate native acceptance.
The pure verifier checks canonical bytes; envelope/capacity/release/trust/plan
digests; source commits/trees; images; OS/kernel/libc/architecture; build/cache
inputs; every probe, command and output digest; all mandatory checks; full test
inventory/counts; tenant/environment/namespace/service-account scope; freshness
(at most 168 hours, bounded by both authorizations and keys); and the run nonce.
Recomputing a digest does not make a false PASS valid. FAIL and unavailable
remain distinct states.

The record requires three independent signatures and owners using the existing
`PLATFORM_RELEASE`, `TENANT_LIVE_EXECUTION` and `CAPACITY_OPERATOR` purposes.
Test seeds and records are deterministic, in-memory **UNIT ONLY**, never
operator keys or native evidence. Even a fully signed positive synthetic vector
returns `evidenceClass: UNIT_VERIFICATION_ONLY` and `nativeAcceptance: false`.
Expected release/tenant/environment/nonce and replay history are explicit
verifier inputs; a future live caller must obtain them from external custody.
The pure verifier does **not** implement durable nonce reservation, trusted
wall-clock custody, current revocation acquisition or filesystem ownership.

A released per-architecture input plan is pinned in the campaign release tree
at `campaigns/platform/linux-baseline/inputs/<amd64|arm64>.json`. Its closed
shape is published under `$defs.plan` in the evidence schema. Actual plans,
images, offline caches, build/probe helpers and native output records are absent;
no fake deployment inputs are checked in at those release paths. The minimum
83 conformance tests is only the historical floor: a real plan must pin the
complete current five-suite inventory, including the new Linux tests.

## Live boundary and remaining implementation

The source module opens no socket, file, credential or process. Its fixed
data-only request builder maps ten operations to POST paths under
`/v1/linux-baseline/`, with one exact namespace-scoped CAMPAIGN_PROXY rule,
HTTPS, endpoint/policy digest, bounded request/response sizes and timeout.
Requests contain no arbitrary argv, executable, URL or credential. This is a
protocol definition and unit-tested request construction, **not** implemented
network transport, server-side admission or a live execution grant.
KUBERNETES_API_PROXY transport is not implemented and is explicitly unavailable;
there is no permissive fallback.

The previously retired inner live adapter stays retired and byte-identical.
The current installed environment has no independently reviewed usable Linux
endpoint-isolation/proxy session. Therefore every real campaign control returns
`NOT_RUN_ENV_UNAVAILABLE` / `LINUX_LIVE_BACKEND_UNAVAILABLE`, even if fixture
capabilities or caller environment variables say "verified". Pure verification
cannot be fed back into the campaign to manufacture a PASS. The handler is
intentionally unavailable until a separately reviewed external backend exists;
end-to-end live execution is **not completed** by this source packet.

Only the external root-owned dual-signed live launcher may eventually execute
this campaign post-merge. It must establish trusted mounts, independent capacity
authorization, target-local isolation, hash-pinned probe/build helpers, exact
endpoint/namespace/quota limits, server-side zero-incremental-cost admission,
credential custody and durable replay protection before any checked-out code.
Repository code must not install or replace those controls. A reviewed future
integration must preserve all these boundaries and the unavailable fallback.

## Verification and evidence ledger

All acceptance runs use the exact packet through the preinstalled signed offline
launcher. The seven direct-argv commands collect meta, parity, Alpha 1,
runner-boundary and Linux suites independently, then run `campaign` and
`evidence-verify` for `linux-baseline` through the unchanged dispatcher. The
unchanged predecessor discovery helper checks nonempty inventory and all 83
original IDs. Narrow legacy handler/assertion edits are reversed and compared
to pinned original hashes. Every other original file outside the ten authorized
integration files remains byte-identical, including the retired inner adapter.

Negative tests cover malformed/duplicate JSON, missing/extra fields, handler
aliases/order/duplication/omission, each missing case/check, false PASS,
emulation/cross-architecture/non-Linux substitution, source/image/build drift,
digest mismatch, scope changes, signatures/owners/purposes, revoked/expired keys,
stale/future/replayed evidence, hidden regression skips and proxy scope expansion.

The first exact candidate, `5e5d631cdfa029ea083d1d003da61b265f477f10`,
passed all seven commands with 119 tests (83 predecessors plus 36 Linux tests),
no skips, and unchanged tracked files. Its signed local replay log SHA-256 is
`67c00e00b5d10b7780e9961a6e42e67693629e71f322340270482c672b28ed46`.
Subsequent malformed-depth/strict-UTC hardening and this report require a fresh
exact-candidate replay before PR CI; this earlier receipt does not cover them.

| Evidence axis | Source snapshot state | What it does not establish |
| --- | --- | --- |
| Source implementation | Implemented; candidate verification pending | Runtime transport or native qualification |
| Offline / PR CI / merge / exact-main | Separate receipts required in closure | Linux build, deployment or tenant acceptance |
| Operator host maintenance | Existing signed data-only activation only | New backend installation or policy authorization |
| Native Linux AMD64 | NOT_RUN_ENV_UNAVAILABLE | Mandatory early runtime-coding gate remains closed |
| Native Linux ARM64 | NOT_RUN_ENV_UNAVAILABLE | Cannot advertise or release this target |
| Emulated Linux / macOS | Ineligible for native qualification | Cannot substitute for either architecture |
| Artifact / SBOM / deployment / runtime | NOT_RUN_ENV_UNAVAILABLE | No Linux images or live probe output supplied |
| Assurance / tenant acceptance | NOT_RUN_ENV_UNAVAILABLE | No phase completion or tenant signature |

The campaign CLI exits successfully when it produces a valid unavailable
report. Likewise `evidence-verify` may report structural PASS while explicitly
retaining `resultStatus: NOT_RUN_ENV_UNAVAILABLE`, `STRUCTURAL_ONLY` and
`nativeAcceptance: false`. Neither exit code nor structural PASS opens the gate.

## Roadmap and next gate

- DONE prerequisite: MET-REPAIR-004 / CONF-FIX-001 source authority and regression
  corrections (separate recorded source/CI/main evidence).
- ONGOING CONF-LINUX-001: source kit and its exact offline/PR/main verification.
- WAITING CONF-LINUX-001: approved existing zero-cost native AMD64 capacity,
  reviewed installed Linux isolation/proxy/build/probe helpers and released
  digest-pinned inputs, followed by all ten independently executed cases.
- WAITING native ARM64: its own capacity and full qualification before release.
- WAITING CTRL-INTEGRATE-001, MODEL-001, EXEC-001, RUN-001 runtime coding:
  fresh native AMD64 PASS is a strict predecessor, not waived by this source PR.
- WAITING later phases: full enterprise K8s/K3s/OCP/air-gap, upgrade, GPU,
  assurance and tenant acceptance. Alpha 2 is not complete; no phase-end model
  effort transition is due.

## Cleanup and rollback

This offline source work creates no capacity or tenant resources. Local test
fixtures are confined to temporary directories. Future live cleanup may remove
only run-labelled resources in the preauthorized namespace through the signed
proxy. Preserve tenant data, output evidence and existing capacity; never
delete a namespace or automatically reverse destructive migrations. Restoring
a verified checkpoint requires separate data-owner authority. Roll back source
via a reviewed revert; no root launcher, key, policy or sudoers change is part
of this packet.
