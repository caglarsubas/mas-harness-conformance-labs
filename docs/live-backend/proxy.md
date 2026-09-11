# CONF-LIVE-003 — Proxy source implementation

## Alpha 2: ONGOING / IMPLEMENTATION_INCOMPLETE

This packet has not completed acceptance. Do not package, install or merge this
work in progress. Source tests and data consistency do not establish native
qualification, policy enforcement, an installed service or tenant acceptance.

The qualification decision previously recorded here is resolved by merged
MET-REPAIR-015 (PR110). No additional operator decision is requested. B1 and B2
are closed **in authority**, not yet in the product integration.

## Exact consumed authority and ownership

- Current consumed meta main: `9010ef0280d301eb18071266bda17e4c1ad5ebcc`
  (MET-REPAIR-016), including the unchanged MET-REPAIR-015 qualification authority
  at `3f52d53c39b2565cb74d527fdcb4215ff0e37b76`.
- Current product predecessor: `f988c78e93b28257810ed99e7f0c072e9b76bae5`
  (CONF-FIX-006 / PR17), tree `542d2e8e49389bb387a84f76700138c3de833f4e`.
- Current immutable baseline: 127 files / 362 test identities, separately pinned
  as `currentCheckpoint` in `proxy-vectors.json`, including complete hashes,
  Git blobs, modes and method identities.
- The prior 127-file / 354-test performance checkpoint is preserved unchanged as
  `performanceCheckpoint`, including its original canonical digest and identity.
- Historical credential checkpoint remains unchanged in `acceptedCheckpoint`:
  `9df7dd7f2df8ac64096ef37d8df259761947d552`, tree
  `1310cc74cc0ed39cfeb1068e998a0f78502a4be4`, 127 files / 327 identities.
  The accepted performance proof must verify actual source before returning
  historical bytes. A historical reconstruction is not the current checkpoint.
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

Fresh inventory tests preserve all362 current methods and all127 current files,
as well as the separately verified historical327 identity set and source bytes. They
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

## Checkpoint and transport continuation — 2026-09-11

Accepted CONF-PERF-004 source/local/required localhost CI/merge/LOCAL exact-main
closure supersedes the timing blocker above; the cancelled PR12 attempts remain
historical failures. This draft merges accepted main without rebasing or rewriting
its history. No inherited crypto/helper/test/proof bytes are edited by this packet.

The source-owned transport now caps each socket wait at two seconds and checks
custody after exceptions as well as successful I/O. Only a raw receive timeout
may poll the same retained stream again; policy-check timeouts propagate. Sends,
connects, requests and ambiguous mutations are never retried. The original
absolute session and ten-second connect/handshake/header bounds remain; a slow
probe can still finish within its signed lifetime. Listener polling likewise
keeps one ten-second phase, retains any accepted connection before post-I/O
checks and closes it on partial acquisition failure.

Request framing rejects encrypted data already buffered in the input MemoryBIO
after the complete request, in addition to decrypted surplus. It does not wait
for client EOF before responding. This is an already-received-byte check, not a
claim to predict future network input or prove native enforcement. One request
per connection and no connection reuse remain mandatory. The distinction between
decrypted SSL pending bytes and encrypted MemoryBIO bytes follows the
[Python 3.12 SSL interfaces](https://docs.python.org/3.12/library/ssl.html#memory-bio-support).

Thirteen added regression methods cover exact checkpoint substitution, poll
budgets, no replay, policy failure versus read timeout, post-I/O rollback/refusal,
partial writes, raw EOF/size limits, buffered records and partial accept ownership.
All tests use OS/SSL mocks inside the full signed offline recipe. No real socket,
credential, certificate issuance, installation or native qualification is run.
This continuation targets 425 methods: 354 accepted + 58 existing draft + 13 new.
Actual pass/failure and exact commits are recorded in external operator evidence
and PR12; this source document alone is not acceptance of its own bytes.

## Integration remaining before packet completion

### Historical reproduced predecessor blocker — exact head e5cecc6

Resolved by the accepted CONF-FIX-006 checkpoint above. The original failed run
below remains historical evidence; no failure is relabelled PASS.

Signed LOCAL replay of `e5cecc64b237f3f06f17e1178258aae017bc05ea`
(activation166) ran all six full test roots: 425 methods, 424 passing,
one failure, no skips, 143.499375 seconds through the trusted launcher.
Log SHA256 `88adb4db5c35bc08ef67b088875b7ec61d0839c625493d294032a011ff2f5de9`.
The recipe stopped after command6; campaign/evidence commands7/8 were NOT_RUN.
This is FAILED acceptance, not a partial PASS or acceptance of later doc edits.

The unchanged accepted predecessor method
`PerformanceSourceProofTests.test_exact_checkpoint_scope_and_all_fresh_test_roots`
in `tests/live_backend/test_supervisor.py` asserts `len(rows) == 127` and fails
on the approved135-file CONF-LIVE-003 stage. Source inspection also shows its
later exact test-map equality excludes the new approved test modules; execution
did not reach that second assertion. The cumulative source validator itself
accepts the ordered stage; the failing test's assumptions are narrower.

That file and its source-proof bindings are outside003 ownership. No existing
unconsumed corrective packet authorized this accepted-main repair at that time. Do not edit
the predecessor here, filter the inventory, monkeypatch collection, drop tests,
revert the accepted performance repair or relabel native evidence. A separately
reviewed successor must preserve both accepted histories and exact future-stage
path/test closure, including negative tests for omitted or unapproved paths/IDs.
Then reconcile this draft with the newly accepted checkpoint and rerun all8.

### Current checkpoint and native byte-reader continuation — 2026-09-11

PR17 closed local, required localhost CI, merge and independent LOCAL exact-main
on `f988c78`. All362 tests and all8 commands passed, zero skips. This draft merges
that exact accepted main without rebasing, rewriting failed history or editing
any of its127 predecessor files. Its owned fixture binds the new checkpoint and
retains the original354-method performance record separately. A new regression
checks exact two-file correction ownership and rejects substituting the older
record for the current one. All71 existing draft test identities are preserved.

The new private server byte parsers decode complete ELF64 little-endian headers
and executable PT_LOAD segments for x86_64/aarch64, bounded proc maps and auxv,
the SELinux version1 status layout and SHA256 fs-verity ioctl output. They reject
truncation, duplicate/overlapping identities, malformed interpreter paths,
writable/anonymous/deleted/memfd executable code, invalid special kernel mappings,
odd/non-enforcing status and alternate verity algorithms. Mapping addresses,
device/inode/offset and permissions remain explicit data for retained comparison.
The layouts are grounded in [Linux6.12 ELF UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/elf.h),
[procfs documentation](https://www.kernel.org/doc/html/v6.12/filesystems/proc.html),
and the [SELinux status layout](https://raw.githubusercontent.com/SELinuxProject/selinux/3.8/libselinux/src/sestatus.c).
No upstream implementation code was copied; no external dependency is introduced.

Fourteen new codec methods exercise inert independent bytes; no ELF is loaded or
executed and no native syscall, kernel view, socket or credential is accessed.
The helpers return only data, never a qualification handle. A matching vDSO name
or auxiliary vector is not native proof. Real kernel-filesystem validation,
retained PID/FD/namespace/code ownership, fenced status reads, active policy and
BPF checks and factory integration are still mandatory unfinished work below.
The interim source inventory targets448 methods:362 accepted +71 preserved draft
+14 codec +1 checkpoint regression. Full-recipe results must be recorded for the
exact commit externally; these source claims alone are not acceptance.

PR12 remains DRAFT/unmerged. Further native integration work below is unfinished,
independent of this new acceptance blocker. No phase completion is claimed.

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
4. Finish native-inspection, observer and broker pre/post-I/O integration,
   remaining TLS/HTTP factory-level cases, all partial-acquisition cleanup, and credentials
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
| Alpha 2 | CONF-PERF-004 | DONE_SOURCE_GATES_RECORDED | PR16/main b7586c4; current127/354 checkpoint, earlier failures retained |
| Alpha 2 | CONF-LIVE-003 checkpoint / transport | IMPLEMENTED_NOT_ACCEPTED |13 new methods pass in425-method replay; one inherited stage-scalar failure |
| Alpha 2 | MET-REPAIR-016 / CONF-FIX-006 | DONE_SOURCE_GATES_RECORDED | PR115 / PR17; corrected127-file/362-method checkpoint accepted |
| Alpha 2 | CONF-LIVE-003 checkpoint / kernel byte parsers | IMPLEMENTED_NOT_ACCEPTED | Current checkpoint reconciled; fifteen new regressions await exact full-recipe evidence |
| Alpha 2 | CONF-LIVE-003 native inspector / broker / API | ONGOING | Required implementation listed above |
| Alpha 2 | CONF-LIVE-003 required CI | WAITING | Fresh exact-head localhost evidence required; prior failures retained |
| Alpha 2 | CONF-LIVE-003 source completion / merge / exact-main | NOT_RUN | Packet is incomplete; no completion claim |
| Alpha 2 | CONF-LIVE-004 | WAITING | Fixed worker and ten native probes |
| Alpha 2 | CONF-LIVE-005 | WAITING | Reproducible candidates and operator handoff |
| Alpha 2 | CONF-LIVE-006 | WAITING | Trusted campaign integration |
| Alpha 2 | Linux AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed/native qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | No phase promotion |

Model-effort transition: NOT_DUE. Alpha 2 remains open.
