# CONF-LIVE-003 — Proxy source implementation

## Alpha 2: ONGOING / SOURCE_IMPLEMENTATION_INCOMPLETE

This packet has not completed acceptance. Do not package, install or merge this
work in progress. Source tests and data consistency do not establish native
qualification, policy enforcement, an installed service or tenant acceptance.

The qualification decision previously recorded here is resolved by merged
MET-REPAIR-015 (PR110). No additional operator decision is requested. B1 and B2
are closed **in authority**, not yet in the product integration.

## Exact consumed authority and ownership

- Meta main: `3f52d53c39b2565cb74d527fdcb4215ff0e37b76` (MET-REPAIR-015).
- Product predecessor: `9df7dd7f2df8ac64096ef37d8df259761947d552`.
- Product predecessor tree: `1310cc74cc0ed39cfeb1068e998a0f78502a4be4`.
- Immutable baseline: 127 files and 327 test identities. The complete hashes,
  Git blobs, modes and methods are in `proxy-vectors.json`, independently pinned
  to the accepted credential-ordering checkpoint.
- Packet YAML SHA256:
  `15d13434edf833d4803618a7aa73ccc5e93baa29596e08903e623dbee338bba5`.
- Exactly the eight CONF-LIVE-003 paths; no predecessor, meta, workflow,
  Makefile, dispatcher, lock, PORTING ledger or warm-source edits.
- The four inherited unvalidated drafts were preserved outside this repository
  before changes. That snapshot is not an accepted predecessor.

Consumed contracts: trusted live runner and LIVE_BACKEND_READINESS, proxy009,
observation010, custody011, credential lifecycle012, ordering013, broker014 and
native qualification015. All existing signature/tenant/capacity/zero-cost
boundaries remain unchanged. The source-owned private schemas are inert data
from this project's meta authority, not imported warm-source implementation.

## Work added in this continuation

The qualification parser validates the closed private record, profile/scope and
numeric endpoint tuples; the acyclic fixed release member; the observation
preflight pin; four-role code inventories; separate raw and fs-verity hashes;
SELinux epochs; exact mappings and local/effective BPF program data. The capture
cross-check additionally rejects PID/start-time replacement, renewed deadlines,
changed retained identities and out-of-window observations. Its return is None,
never an execution handle or native PASS. Its inputs are not kernel observations.

The three flat test modules now cover qualification records/captures, existing
proxy data/observation vectors, broker direction/hash chains/chunks/terminal
consistency, reservation replay/contention/ambiguous writes, exact HTTP framing,
DER identity extraction, TLS configuration, refused native entry and mocked
descriptor cleanup. Unsigned DER-shaped codec inputs contain no usable key or
signature; no certificates are issued, trust files read or network calls made.

Fresh inventory tests preserve all327 old methods and all127 old files. They
also honor the already-approved future141/146/151 stages and the exact final
launcher-delta proof; they do not introduce a successor-blocking scalar135 check.
The original120 and historical279/305 counts remain separate evidence histories.

The first replay exposed discovery-state contamination in the new tests: eagerly
importing the real client left a parent-package attribute behind, while accepted
credential fixtures substitute the missing-successor seam through sys.modules.
The new tests now restore both import surfaces after loading their real subjects.
No predecessor fixture, runtime verification, loader metadata or test selection
is changed. The complete eight-command replay of exact head
`4175299368fffd15bc9e67153cdf4d81ce8ef6a3` passed all385 tests (327 predecessor
plus58 new), without skips. That is a historical local result, not acceptance
of later changes or completion of the packet.

Review also corrected mutable aliasing between returned broker frames and retained
parser state, and made descriptor-cleanup failures sticky without retrying a
recycled descriptor. Dedicated regression cases cover both corrections.

## Timing investigation

Required PR CI run34436974320 was cancelled in both attempts. Attempt1 emitted
all385 passing test summaries and structural output but did not receive a green
job conclusion. Attempt2 reached the trusted launcher's900-second timeout before
the backend suite completed. Neither attempt establishes green required CI.

The accepted earlier CONF-FIX-005 exact-main log already records222.471 seconds
for87 Linux-baseline tests and635.330 seconds for157 backend tests. These are
historical timings, not a controlled comparison with this candidate. Static
inspection identifies repeated signature construction/verification in inherited
fixtures as a candidate bottleneck, not yet a measured attribution.

This continuation adds diagnostic-only elapsed time around each of the three
packet-owned test modules using standard unittest module setup/teardown. It
does not replace TestCase.run, alter discovery, intercept runtime verification,
cache signature outcomes, omit tests or change acceptance argv/timeouts. New
timings must come from the full eight-command signed isolated recipe. Shared
crypto.py and predecessor fixtures remain outside this packet's allowedPaths;
they may not be optimized through monkeypatches or edits here.

## Integration remaining before packet completion

1. Implement the real fixed factory-owned `_KernelQualification` reader in
   live_proxy_server.py. Actual procfs/sysfs/SELinux/cgroup/BPF/fs-verity/ELF and
   retained peer inspections must be OS-mocked through production factories in
   source tests. The new data validator cannot be substituted for this reader.
2. Replace all inherited `_fixed_probes` containment/execution callbacks with the
   fixed observer/broker interfaces. Packet004 must not supply server containment
   or execute through a callback; the broker owns stopped/contained worker startup.
3. Implement the distinct server-only API transport, durable create intents and
   observed UID/version ledger, exact signed manifest dispatch, no-adoption
   handling, lost-response accounting and independent UID-scoped cleanup.
   Broker-returned empty resource lists are not evidence of CLEAN.
4. Complete pre/post-blocking-I/O custody checks, <=2-second observation checks,
   TLS/HTTP surplus/timeout cases, all partial-acquisition cleanup, and credentials
   gated behind real self/peer qualification, observation and durable admission.
5. Add end-to-end OS-mocked tests through the actual completed server, client and
   original supervisor factories; prove no credential/effect occurs on any failed
   authority, qualification, observation, broker or cleanup gate.
6. Run the complete recipe, required localhost PR CI, green-only completion review
   and merge, then an independent LOCAL exact-main replay. A passing interim
   test suite cannot establish that these unfinished deliverables are complete.

## Verification boundary

This is an in-progress source snapshot, not a self-attested run result. Exact
commit-pinned local/CI logs are retained outside the product repository. The
first candidate's replay is not acceptance of subsequent source changes. No
product command is allowed outside the signed host launcher. The recipe is:

1. unittest discovery: tests/meta
2. unittest discovery: tests/parity
3. unittest discovery: tests/alpha1
4. unittest discovery: tests/fixes/runner_boundary
5. unittest discovery: tests/platform/linux_baseline
6. unittest discovery: tests/live_backend
7. make campaign CAMPAIGN=linux-baseline
8. make evidence-verify CAMPAIGN=linux-baseline

All eight commands run in the same deny-all process tree with the exact hash-pinned
packet and commit. No subset replay, direct import/compile/test invocation, native
probe, live launcher, runtime download or cloud/billable service is authorized.

## Roadmap and evidence

| Phase | ID / gate | Status | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundations | DONE_RECORDED | Historical source/offline closure; no new live evidence |
| Alpha 2 | MET-REPAIR-014 / 015 | DONE_SOURCE_GATES_RECORDED | Broker and qualification authority merged |
| Alpha 2 | CONF-LIVE-003 data/codecs | LOCAL_PASS_RECORDED | Head4175299 passed385 tests; subsequent changes require fresh replay |
| Alpha 2 | CONF-LIVE-003 timing investigation | ONGOING | Diagnostic module timings; no relaxed timeout or inherited-code edit |
| Alpha 2 | CONF-LIVE-003 native inspector / broker / API | ONGOING | Required implementation listed above |
| Alpha 2 | CONF-LIVE-003 required CI | NOT_GREEN | Both previous attempts cancelled at the fixed time boundary |
| Alpha 2 | CONF-LIVE-003 source completion / merge / exact-main | NOT_RUN | Packet is incomplete; no completion claim |
| Alpha 2 | CONF-LIVE-004 | WAITING | Fixed worker and ten native probes |
| Alpha 2 | CONF-LIVE-005 | WAITING | Reproducible candidates and operator handoff |
| Alpha 2 | CONF-LIVE-006 | WAITING | Trusted campaign integration |
| Alpha 2 | Linux AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed/native qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | No phase promotion |

Model-effort transition: NOT_DUE. Alpha 2 remains open.
