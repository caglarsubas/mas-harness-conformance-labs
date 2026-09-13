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

Head `179245275258b0d895d5170009e12deeac42b701` subsequently passed all eight
commands and all 448 tests, zero skips, in signed LOCAL activation174 and required
localhost CI run34570861429 (activation175). Runner41 was retired with zero
registered runners and zero uploaded artifacts. These are historical interim
source/CI results, not full packet completion or acceptance of later edits.

### Fixed native read primitives — 2026-09-11

The private `_KernelNativeReads` constructor accepts no backend, library path,
function or context. It binds only the current process's libc and the two native
Linux LP64 little-endian ABIs. Its filesystem reader uses the explicit 120-byte
statfs layout; fs-verity uses only the measure ioctl with a 32-byte capacity.
Read-only/non-inheritable descriptors and retained metadata are rechecked around
reads. Unknown layouts, writable code, descriptor replacement, OS errors and
results outside a two-second phase poison the reader; no retry or fallback.

The status reader maps only read-only shared kernel status bytes, verifies
selinuxfs, and uses sequence/fence/fields/fence/sequence ordering. Only private
membarrier QUERY, REGISTER_PRIVATE_EXPEDITED and PRIVATE_EXPEDITED are reachable,
with flags/cpu zero and fixed architecture syscall numbers. A mapping acquired
before failure is closed once; the caller's descriptor is never closed. A reused
reader is bound to its original process/thread and never renews a failed phase.

Layout references are [Linux 6.12 statfs](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/asm-generic/statfs.h),
[membarrier](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/membarrier.h)
and [fs-verity UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/fsverity.h).
These are independently authored stdlib adapters, not imported implementations.
Eighteen new OS-mocked methods exercise the real primitive methods, including both
ABI selections, refusing missing permissions, changed epochs/FDs, late results
and partial mapping/cleanup failures. All 448 prior tests remain; the new target
is 466 methods. Full exact-commit evidence is retained externally after replay.

The first full replay of `7a5e489` found 16 error reports in the new test mock
cleanup: patching Mock's side_effect/return_value properties repeatedly made
unittest.mock delete descriptor attributes on restoration. The tests now replace
the mocked OS/library function on its owning module/object instead. Runtime
primitives, all test identities/assertions, predecessor source, commands and
limits are unchanged. The failed activation176/log remains external history;
the corrected commit requires a fresh full eight-command replay.

This is still only an inspector component. A matching filesystem magic or status
epoch is not qualification. Canonical root/mount/namespace ancestry, retained
peer and code ownership, fresh active-policy reads under the same boot/epoch,
BPF queries, whole-operation custody/deadline checks and the fixed factory
integration below remain required. No server gate or credential path is enabled
by these primitives. Tests mock every OS entry point and perform no native read,
policy registration, credential access, socket operation or installation.

### Fixed kernel-root custody — 2026-09-11

Corrected head `22de588ac3000502a87e52da801626f3e929ebca` passed all 466 tests,
zero skips and all eight commands in signed LOCAL activation177 and required
localhost CI run34575890279 / activation178. Runner42 was retired with zero
registered runners and zero uploaded artifacts. This records that prior interim
increment only; the changes below need their own exact-commit evidence.

The new private `_KernelRootViews` owns only the fixed `/proc`, `/sys/kernel`,
`/sys/fs/selinux`, `/sys/fs/cgroup` roots and their ancestry. Its constructor has
no path, descriptor or backend arguments. Every open uses readonly, directory,
no-follow, close-on-exec and nonblocking flags. Checks retain original descriptors,
reopen the complete fixed ancestry, compare both views, then recheck originals.
They reject path/inode/owner/mode/filesystem drift, separate bind mounts under
the sysfs ancestry and mount replacement even when inode/filesystem match.

The fixed native read uses an aligned 256-byte
[Linux 6.12 statx layout](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/stat.h),
requests `STATX_MNT_ID_UNIQUE` on an empty retained descriptor path, and requires
the returned mask to prove support. Missing symbols/permissions, fallback to
recycled mount IDs, unknown fields and identity mismatch fail closed. Dynamic
directory link counts, size and timestamps are not stable procfs custody and
are deliberately excluded; owner/mode, device/inode, filesystem and mount IDs
remain pinned. This is independently authored stdlib code, not imported source.

Each acquire/check phase has one two-second deadline across all children, not a
renewed per-child budget. Partial acquisition retains close ownership immediately;
cleanup continues after errors, does not retry an uncertain close or close a
detectably recycled descriptor, and preserves cleanup failure on later close.
Twenty new OS-mocked tests exercise the real root owner and native read methods.
All 466 prior identities and 127 accepted source files remain; target 486 tests.
The fixture, signatures, locks, predecessor tests and server gates are unchanged.

These observations do not establish initial namespace trust. Signed process and
mount-namespace binding, fresh active-policy reads under the same boot/status
epoch, PID/code/cgroup/BPF custody and the full installed qualification factory
are still required. Reopening detects substitution across observations, not an
in-between ABA attack; the independent operator's execution fence is mandatory.
No native root, mount, syscall or host policy is inspected/changed in these tests.

### Retained process and namespace observations — 2026-09-11

Head `c435f7c2574358ce0d5e4d09b2c4f50db0389305` passed all 486 tests,
zero skips and all eight commands in signed LOCAL activation179 and required
localhost CI run34585011767 / activation180. Runner43 was retired; zero registered
runners and zero artifacts were verified. These are the preceding root-custody
increment's results, not acceptance of the following changes.

The private `_KernelProcessView` retains its own pidfd, numeric proc directory,
fixed ancestry and four namespace descriptors. It accepts no descriptor, path,
backend or function selector. SERVER observation must target the current process;
the future installed qualifier must derive peer PIDs from its actual retained
kernel-authenticated channel. It checks pidfd liveness/identity/inheritance and
process/thread ownership before and after bounded I/O, and binds start ticks,
parent, all four UID/GID values, supplementary groups, capabilities, seccomp,
namespace PID chains and task identities across the component's lifetime.

Fresh stat/status/label/cgroup/children reads use readonly/no-follow descriptors
on the same verified proc mount. Proc size/timestamps and CPU/memory counters
are not stable process identity. The bounded parser handles parentheses and
newlines in the comm field, rejects duplicate/truncated/overflowing records,
tracing/dead processes and inconsistent status fields, and requires all four
credential IDs to match the expected role. SERVER additionally has one thread
and no children. Only the four fixed ns/{user,mnt,pid,net} magic links may be
followed; readonly nsfs/type observations and retained inode identities must
match the expected namespace pins. No setns, ptrace, namespace creation, signal,
credential, worker execution or policy mutation is used.

The fixed read-only `NS_GET_NSTYPE` interface and proc layouts are grounded in
[Linux 6.12 nsfs UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/nsfs.h)
and [proc field emission](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/proc/array.c).
This is independently authored stdlib code, not imported implementation.
Each complete construction/check has one two-second budget, including the
original root-owner checks. PID exit, replaced mounts/paths/namespace FDs,
late results and changed process fields invalidate the instance without retry.
Partial resources are closed once; cleanup continues after failures, records
sticky uncertainty and never closes a detectably recycled descriptor. The
borrowed original root owner remains separately owned and is never closed here.

Twenty-three new OS-mocked methods exercise the actual process, root and native
reader methods, including both supported ABI selections and all four role
cgroup paths. They preserve all 486 prior tests and all 127 accepted files;
the new full-recipe target is 509 tests. Exact commit/local/CI evidence must be
recorded externally. No native proc, pidfd, namespace or host policy is used by
these tests, and no existing server credential/containment gate is enabled.

Expected role data is detached, not authenticated by this component. A matching
record or successful check grants no qualification. The installed owner must
still bind the independently signed release/role record, original socket peer,
boot/kernel identity, active policy epoch, executable/verity/mappings, actual
cgroup controls/BPF and execution fence before any credential or dispatch.
These snapshots detect changes across observations, not between-check ABA or
hostile kernel/operator behavior. Full `_KernelQualification` and its production
server/observer/broker integration remain unfinished.

### Fresh kernel-policy custody — 2026-09-12

The preceding process increment at `6dcd8e72859037839915c2f928e0fb55641e458a`
passed all eight commands and509 tests, zero skips, in signed LOCAL activation181
and required localhost CI34588680815 / activation182. Runner44 retired with
zero registered runners and artifacts. That evidence is historical, not acceptance
of the new source below. Current meta main `451cfc708bd6e708d20d905ca44165ae896a647b`
adds the provider adoption roadmap; packet003 and the native qualification contract
remain unchanged. Product predecessor remains accepted127-file/362-methodf988c78.

The private `_KernelPolicyView` owns retained fixed proc ancestry, boot ID,
kernel notes and SELinux status/control descriptors. Each complete check freshly
opens the active kernel policy, reads/hashes its full bounded image, and promptly
closes that snapshot. It does not reuse an open policy image or cached digest.
Actual boot/kernel identity and enforcing/deny-unknown controls are compared
before and after. The real fenced status reader checks the same enrolled epoch
around the policy open and every read; unexpected sequence/policyload changes,
missing permission, busy policy snapshots, changed inode/mount/path, malformed or
oversize bytes and late reads refuse without retry or a copied-policy fallback.

There is one two-second inspection budget across all children and chunks, with
process/thread custody and monotonic ordering retained between checks. All opens
are read-only/no-follow/non-inheritable and on the original verified kernel
mounts. Partial resources are closed once; uncertain cleanup remains sticky and
never widens ownership or retries a potentially recycled descriptor. Borrowed
root handles are not closed. The status mapping explicitly uses the supported
native page size (4/16/64KiB), with unknown or unavailable sizes refused.

The fresh-open snapshot, enforcing-control bytes and read-only status-page
behavior follow the [Linux6.12 SELinux interface](https://raw.githubusercontent.com/torvalds/linux/v6.12/security/selinux/selinuxfs.c).
This independently authored component does not import upstream implementation.
Tests drive actual policy/root/native-reader methods with only OS edges mocked;
no native filesystem, policy, syscall, socket, credential or installation runs.
All509 previous methods and127 accepted files remain preserved. Exact candidate
counts and local/CI results are recorded externally after the complete recipe.

Expected policy data is detached but is not independently authenticated by this
component. Successful comparisons return no qualification handle. The full
installed qualifier must still bind signed authority and the original peer,
code/verity/mappings, cgroup/BPF enforcement and operator execution fence. Native
ordering, between-check ABA exclusion and hostile-kernel behavior are not proved
by snapshots or unit tests. No existing server credential gate is enabled here.

PR12 remains DRAFT/unmerged while the native integration below is unfinished.
The predecessor blocker is resolved; no new operator decision or phase
completion is claimed.

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

## Code-file custody continuation — 2026-09-12

Prior head `2adf60a06e24e76aae6367659efda8e6f3276c61` passed all eight LOCAL
commands and required localhost CI run34650854215:535 tests, zero skips.
Runner45 retired. This records the preceding kernel-policy component, not
acceptance of the code-file changes below. Accepted main and all127 predecessor
files remain unchanged. Meta main451cfc7 published MET-ADOPT-001 without changing
this packet or its native-qualification authority.

The private `_KernelCodeFiles` component retains a closed, bounded inventory of
root-owned regular files and complete no-follow ancestry. It checks exact mode,
single link, size, device/inode, non-recycled mount identity, SELinux label,
ordinary SHA256 and a separately measured fs-verity digest. Every check performs
fresh bounded offset reads; no executable bytes, loader or measurement fallback
is cached. ELF executable segments and enrolled loader closure are checked
against actual file bytes. Reopened ancestry before/after reads detects named
substitution. One two-second phase includes every child/chunk and cleanup;
failure is sticky, partial acquisition is closed, uncertain closes are not
retried, and borrowed kernel roots remain separately owned.

`match_maps` checks **supplied data**, not native proc provenance. It binds every
parsed executable mapping to an enrolled retained file, exact device/inode,
permissions and complete ELF segment coverage at one observed ASLR bias. Split
segments must be contiguous; static ELF cannot claim a relocation bias; mapped
ELF loaders must be enrolled and mapped. Unknown executable files/archives,
extra/missing mappings and writable code are refused. Its return is None, not
an execution/qualification handle. Host auxv/kernel-special corroboration and
two fresh reads from original process descriptors remain with the unfinished
process-code integration. Caller-provided map snapshots do not prove those gates.

Expected inventory is detached data, not authenticated authority. Full record/
manifest/role binding, `/proc/<pid>/exe`, process maps/auxv custody, active-policy
and operator change-fence integration, cgroup/BPF, broker/API and factory tests
remain required before enabling credentials. fs-verity and snapshots do not
prevent private-page/ABA code injection without independently enforced policy.

The first code-file candidatecda0edc passed571 tests/all8 commands locally and
in required localhost CI run34662349456; runner46 retired. Final contract
cross-check found that the approved file/segment schema permits both private
and shared mappings, while this candidate accepted private mappings only.
The bounded correction separates ELF's R/W/X flags from the record's pinned
private/shared selection. It permits either expressly pinned choice, never a
mapping-mode wildcard, and tests rejection of a mode substitution. No signature,
schema, source lock, enforcement policy or credential gate changes.

37 new OS-mocked methods target572 total, preserving all571 preceding identities.
No native calls, host installation, root policy/key change, dependencies,
downloads, hosted runner, API key or warm-source access occur in this increment.
Fresh exact-commit LOCAL and required CI evidence is pending outside this source
snapshot. PR12 stays draft; sourceComplete=false and nativeAcceptance=false.

## Retained process-code continuation — 2026-09-12

Preceding head1475d3c passed all8 LOCAL commands/572 tests and required localhost
CI run34662894243; runner47 retired with zero runners/artifacts. That evidence
belongs to the preceding code-file component, not this new source snapshot.
All127 accepted files and572 preceding test methods remain preserved.

The new private `_KernelProcessCode` composes the real retained process/root and
code-file components. It accepts only fixed role-code pins, not caller proc
paths, descriptors, argv or map snapshots. It owns readable non-inheritable
descriptors for the original process's exe/maps/auxv/cmdline. Only the fixed exe
kernel magic link is followed; its returned path is compared, never opened.
The actual executable descriptor must match the already-enrolled interpreter or
native ELF's inode/mount/metadata. Reopened proc interfaces and the retained
descriptors are compared before/after reads; partial acquisition closes only
this component's descriptors, never the borrowed process/code/root owners.

Two complete bounded offset reads of actual maps/auxv/cmdline surround file
integrity and process checks. Mappings must cover exactly that role's enrolled
executable files, including the real interpreter, not another role's globally
enrolled code. Exact fixed argv is checked as supporting evidence, not standalone
proof of which Python archive was loaded. The native host page size must match
the observed auxv and enrolled code. Changed executable mappings, ASLR, auxiliary
data, PID/start identity, proc paths, flags, executable link or file are refused;
normal non-executable heap/stack changes do not become code drift. One two-second
phase covers nested checks and all reads; owner/clock/PID liveness checks surround
I/O. Failures and uncertain closes are sticky and never trigger reacquisition.

This remains a **supporting observation component**. Expected pins still need
independent manifest/record authentication and original socket-peer binding.
Kernel-special maps need full host/kernel/active-policy corroboration; proc
snapshots and command lines do not defeat ABA or certify loaded archive identity
without reviewed enforcement and the operator change fence. Full signed clocks,
policy/cgroup/BPF, qualifier/broker/API and production factory integration remain
unfinished. No existing credential gate is enabled and no native PASS is claimed.

33 added OS-mocked methods target605 total; all six suites and both structural
commands must run again through the exact signed launcher. No native syscall,
host installation, policy/key change, dependency, download, hosted runner, paid
API or warm-source access is introduced. Current exact-commit LOCAL/CI results
are retained externally; this source snapshot is not self-attested acceptance.

## Retained cgroup continuation — 2026-09-12

Preceding head `263e9e2` passed 605 tests and all eight declared commands locally
and in required localhost CI run `34670621024`. Runner 48 retired with zero
registered runners or uploaded artifacts. All 127 accepted files and all 605
preceding test methods remain preserved. That evidence is not acceptance of this
new source snapshot.

The private `_KernelCgroupView` borrows the original process/root owner and owns
only the fixed role's pre-existing cgroup ancestry and four control interfaces.
It checks root ownership, non-tenant-writable modes, cgroup2 filesystem identity,
original mount/inode and finite memory/pids/CPU limits against the closed
expected record. A matching path or PID alone never grants qualification.

Fresh opens prevent a retained sequence buffer from masquerading as a fresh
control observation. Each bounded complete read must match the original retained
file identity; temporary descriptors close promptly. Two control snapshots are
surrounded by process and membership checks. Membership must contain the original
live process, while PID reuse, migration, substituted paths, changed limits,
truncation, unknown bytes, oversized reads and unavailable interfaces fail closed.
The [Linux 6.12 cgroup-v2 reference](https://www.kernel.org/doc/html/v6.12/admin-guide/cgroup-v2.html)
defines the finite control interfaces and unordered membership list. Duplicate
PIDs are treated as an uncertain observation, not normalized away. Other-member
churn is not itself target drift and never proves descendants were reaped.

One two-second phase includes nested process checks and all I/O. Inspector
PID/thread, retained pidfd, monotonic time and descriptor custody are checked;
failures and uncertain closes stay sticky. No cgroup is created, migrated,
configured, repaired or deleted. No control file is opened writable.

This remains a supporting observation component, not capacity reservation,
headroom proof or an endpoint enforcement grant. Signed pin authentication,
active policy/code/BPF composition, external change fencing, original signed
lifetime and the full qualifier/broker/API integration remain unfinished.
OS-mocked real-factory tests do not establish native Linux qualification.
Fresh full signed LOCAL/CI acceptance is mandatory for this exact source.

## Retained endpoint-filter continuation — 2026-09-12

Preceding head `e53af04` passed 636 tests and all eight declared commands locally
and in required localhost CI run `34672058700`. Runner 49 retired with zero
registered runners or uploaded artifacts. This is historical evidence, not
acceptance of this source increment. All 127 accepted files and all preceding
methods/classes remain unchanged.

The private `_KernelBpfView` borrows the original `_KernelCgroupView` and retains
seven program descriptors. Every fixed hook is queried locally and effectively
against that exact cgroup; each view must contain exactly its enrolled program.
Queries surround acquisition and repeated translated-byte reads. Program ID,
type, length/hash, map-free/non-offloaded identity and stable metadata must match;
redaction, extra programs, changed attachment flags, layout changes and failed
inspection are unavailable, never repaired or retried into success.

The fixed little-endian LP64 reader uses explicitly aligned Linux 6.12 query and
program-info buffers. Arrays are bounded to 16 IDs and 64 KiB of translated
instructions. A zero extension sentinel requires the exact 232-byte returned
program-info layout; unused pointers, reserved fields and unexpected output are
rejected. Runtime counters may advance without changing program identity.
The [Linux 6.12 UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h),
[syscall implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
and [cgroup query implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/cgroup.c)
are interface references, not imported upstream implementation.

Only query (16), program-FD lookup (13) and object-info read (15) are used with
fixed syscall numbers 321/280. Program descriptors are kernel-created
O_RDWR/CLOEXEC anonymous fds, not ordinary read-only files; the reader never
writes them. Cleanup checks program ID in addition to inode identity because
anonymous inodes may be shared. Partial acquisitions close only owned resources;
uncertain cleanup remains sticky and never retries a close. Borrowed cgroup,
process and root owners stay separate. No filter load/attach/detach, map access,
link update, test-run, capability acquisition or installer is introduced.

Inspection has one two-second phase including nested cgroup/process checks and
pre/post syscall custody/clock guards. This component does not authenticate
caller-supplied pins, review program semantics, enforce an endpoint tuple or
exclude an in-between policy/filter replacement. The independently installed
qualifier, active policy/code composition, signed lifetime, external change fence
and broker/API credential ordering remain unfinished. OS-edge mocks exercise the
real factories; neither architecture has native qualification from these tests.

### Authenticated qualification-record binding — 2026-09-12

The server now creates a private `_ServerQualificationBinding` before entering
the still-unfinished containment gate. It accepts only its active server owner,
re-reads the envelope and fixed trust files under retained custody, authenticates
selected capacity references before opening them, and verifies the independent
platform/tenant/capacity signatures. It reconstructs the exact release, kit,
architecture-specific plan and profile instead of trusting a supplied record.

The fixed qualification member must match the signed tree, profile, numeric
endpoint tuples and observation preflight digest. All four separately installed
role manifests/signatures and artifact bytes must match the record. Observer
enrollment and the release-listed broker/worker handoff digests are cross-bound;
matching a root-signed manifest from another release is insufficient. No worker
PID is invented and no observer, broker, credential or network operation occurs.

The binding preserves original owner/file identities, signed windows and the
server deadline, applies two-second load/check limits, detects input replacement
and remains poisoned after failure. Returned record/broker documents are detached.
Closing it never closes the server's borrowed file descriptors. Server cleanup
and base checks include this binding; all existing containment refusals remain.

Twenty-three new methods exercise the real binding, cryptographic verifiers,
manifest parsing and retained-file reader against deterministic unit signatures
and mocked OS filesystem edges. The parent server context is explicitly assembled
in these tests: this is not a full native server-factory startup test. Both
architecture/address-family data paths, forgeries, missing/substituted inputs,
ownership, deadline, expiry and cleanup refusals are covered. All671 prior test
identities and all127 accepted predecessor files remain unchanged; the new source
target is694 methods, not a self-reported test result.

This object supplies authenticated **expected values only**. It exposes neither
`check_self` nor `check_peer` and grants no execution. Composing the native readers
with authenticated peers, independent change fencing, broker dispatch and the
API/cleanup lifecycle remains unfinished. No native/tenant evidence is promoted.

### Server-owned native inspection composition — 2026-09-12

The new `_KernelSelfInspection` connects the authenticated server binding to the
fixed root, active-policy, process, code-file, process-mapping, cgroup and BPF
readers. It derives only the current SERVER PID and signed SERVER pins; caller
PID/role/record/backend/FD selectors are not constructor inputs. The complete
record's code inventory is retained, without inventing a running WORKER or peer.

One owner retains each resource before its constructor can fail and closes
acquired resources in reverse dependency order. Partial failures and uncertain
closes remain sticky; no close retry, substituted-component cleanup or borrowed
binding/file closure. Combined construction/check phases have one two-second
budget within the original signed/server lifetime, with monotonic and wall-clock
guards. Retained authority, owner and record identity are checked at component
boundaries; fresh active-policy checks surround component observations.

The server creates this composition after authenticated binding and before its
existing containment refusal, storage, observer and credentials. Base checks and
cleanup include it. It is intentionally **not** the completed `_KernelQualification`:
it exposes neither `check_self` nor `check_peer`, supplies no execution permit,
and does not replace the containment gate. Peer ownership, per-I/O cross-reader
trust/epoch fencing, independent external change exclusion and broker/API
integration remain required. Snapshot brackets cannot exclude an in-between ABA.

Twenty-one new tests exercise the real composition and authenticated binding with
typed reader doubles for lifecycle fault injection; a separate unsupported-OS
case invokes the real root constructor and refuses before loading libc. The
694 predecessor methods retain OS-edge tests of each individual reader. These
new composition tests are not a combined OS-edge/native positive or a full
installed-server factory test. Those remain required before packet completion.
The source target is715 methods, with all127 accepted files and all694 prior
methods preserved. Exact-commit LOCAL and CI evidence is recorded externally
only after running the complete declared recipe; source counts alone are not PASS.

### Reader-boundary custody and lifetime continuation — 2026-09-12

The original inspection owner is now retained before each component constructor,
including the root-owned native primitive reader. All eight reader `_tick`
methods reach that exact owner. During an active server, an unbound reader,
copied owner reference on an unowned component, replaced native reader or lost
active server refuses further observation. Standalone components remain data
readers only and cannot establish qualification or bypass server startup.

These hooks carry retained authority-file custody, original record/owner identity,
the combined two-second inspection deadline and the original signed validity
intersection into existing read/query boundaries. Authority bytes and the
authenticated session binding cannot be substituted mid-read. A failure poisons
the inspection even if an inner caller catches it; component cleanup unwinds
before the outer owner closes its resources. No credential or observer I/O is
introduced, and no budget is renewed by nested readers.

Full cryptographic verification remains at phase boundaries; these intermediate
checks reject changes to the original authenticated bytes and their retained
files and enforce the signed trust/envelope/capacity time intersection. This is
**not yet full per-I/O qualification**: cross-reader policy-epoch sampling,
complete OS-call coverage, independent host-change exclusion and combined native
factory performance still require implementation/testing. Individual syscall
timeouts and post-read deadline checks are not evidence of forced interruption
of a blocked kernel call. No native or execution grant is added.

Eighteen new methods exercise actual coordinator/binding/reader ticks and I/O
wrappers with typed components and OS doubles. They cover pre-read denial,
mid-read authority/clock/owner loss, sticky refusal, ownership before construction
and libc-load ordering. These are not combined OS-edge positive tests. All715
prior methods and127 accepted source files remain; new source target733 methods.
Fresh exact-commit full8 LOCAL and required self-hosted CI are mandatory.

### Retained policy-epoch continuation — 2026-09-12

After full initial policy observation, the fixed inspection factory retains a
read-only shared SELinux status mapping before constructing process/code/cgroup/
filter readers. The policy owner closes the original mapping before its retained
status descriptor; failure and uncertain cleanup remain sticky with no retry.
The mapping is never an execution permit or a caller-selectable input.

Every existing owner-bound reader tick now samples the pinned epoch. The sample
checks status FD, parent FD, access flags, named status identity and immutable
expected values before/after reading the mapping. Sequence and status fields are
read with the existing private membarrier operations and must remain even,
unchanged and equal to the enrolled values. A native reader already inside its
phase is sampled without entering a second phase or renewing its deadline.
Nested epoch checks admit only the original policy/native readers for custody
and clock checks; a different reader reentering during sampling refuses.

This retains the initial fresh policy hashing and all later full policy checks;
an epoch sample does not replace policy/boot/root/mount/code observations or the
independent host-change fence. In-between ABA exclusion, complete syscall/path
coverage, combined factory performance and real native matrix evidence remain
unfinished. Source/OS-mocked results cannot qualify the platform or authorize
effects. Existing containment refusal still precedes observer and credentials.

Twenty-seven new tests cover real policy/root/native/mapping methods with OS
edges mocked, plus explicit owner-routing doubles. Existing component-lifecycle
tests now double the two new epoch operations alongside their already doubled
policy operations; no previous test body, identity or accepted file is changed.
All733 prior methods remain, with source target760 methods. Fresh full8 LOCAL
and required localhost CI are mandatory for this exact source increment.

### Retained epoch mount custody — 2026-09-13

The preceding retained-epoch head `99652a1` passed all8 declared commands and
760 tests, zero skips, in LOCAL activation211 and required localhost CI
run34702314811 / activation212. Runner54 retired; this is historical source/CI
evidence, not acceptance of the following changes or native qualification.

Epoch samples now compare immutable mount/filesystem pins for the retained
status FD, its selinuxfs parent and the retained sysfs ancestry. Fixed no-follow
`statx` lookups of `status` and `selinux` also compare unique mount IDs: a
same-inode bind mount cannot hide behind the original status mapping. Both
descriptor and named checks surround the fenced status read, with no new open,
mapping, cached policy image, phase or deadline. Dynamic directory counters and
timestamps are not stable custody and remain excluded.

The shared statx decoder preserves the existing LP64 layout/mask/reserved-field
checks and accepts only empty retained-FD paths or those two fixed names. It
requests non-recycled mount IDs, disables symlink following and automount, and
refuses missing support/errors without a stat fallback. The interface is grounded
in [Linux6.12 statx UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/stat.h)
and [fixed lookup flags](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/fcntl.h);
no upstream implementation or dependency was imported.

Twenty-four new OS-mocked tests exercise the real epoch/root/native readers.
They cover same-inode mount changes, retained FD/filesystem substitutions,
missing/unknown layout fields, query failures/delay, immutable pins, original
deadline and both mocked ABIs. All760 prior test bodies and127 accepted source
files remain unchanged. The existing statx OS double now models only the two
additional fixed names; it does not bypass production validation. Source target
784 methods; exact-commit full8 LOCAL and required CI remain mandatory.

The first candidate `b43db38` completed all six discovery suites but failed in
the new mount-pin storage: native identity tuples were passed to the strict JSON
serializer. Its failed full log is preserved (commands7/8 were NOT_RUN). The
corrected internal pin is a deep immutable tuple, not a wire/JSON document; it
also preserves the full native uint64 mount-ID range. Added regressions cover
IDs above the JSON safe-integer range and mutable filesystem aliases. Shared
canonical.py, predecessor tests, timeouts and the full recipe are unchanged.

This closes this status-view mount comparison, not complete per-syscall ancestry
or independent ABA exclusion. Full combined native-factory performance, retained
peers, broker/API integration and real AMD64/ARM64 qualification remain unfinished.
The containment refusal and credential/observer ordering are unchanged.

## Fixed root ancestry at reader boundaries — source increment

The self-inspection owner now brackets each retained policy-epoch sample with
root-mount comparisons. Each root sample checks the seven original readable
descriptors and the fixed current `/`, `proc`, `sys`, `kernel`, `fs`, `selinux`
and `cgroup` names against immutable inode/filesystem/unique-mount pins. Named
queries retain no-follow/no-automount flags; the absolute `/` query checks the
current namespace root rather than only its retained FD. This follows the
[Linux6.12 statx lookup interface](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/stat.c);
no upstream source was imported.

Sampling opens no new descriptors, maps no pages and does not renew an existing
native/root/inspection deadline. It retains thread/process/owner authority,
rejects backwards time, substitutions and reentry, and leaves cleanup with the
original owner. Full root reopen checks remain. The existing status-only epoch
sample still makes its original ten statx queries; root sampling is a distinct
owner-boundary operation, not a recursive epoch callback.

Twenty-eight additional OS-mocked root/native tests and six explicit-component
wiring tests cover all seven same-inode path replacements, immutable pins,
read-only access, original deadlines, exceptional cleanup, both mocked ABIs,
uint64 mount IDs and root/epoch/read ordering. All784 prior test bodies and all127
accepted files remain unchanged. Only the existing OS statx fixture and typed
component fixture gain the new fixed observations. Source target818 methods;
fresh exact-commit all8 LOCAL and required localhost CI are still required.

These are source and OS-mocked checks, not native installation evidence. Remaining
syscall/path coverage, full combined native-factory performance, peer custody,
broker/API wiring and independent AMD64/ARM64 qualification stay open. Snapshot
comparisons do not replace independent exclusion of intervening changes (ABA).
No execution authority, credentials, control-plane contract or host policy changed.

The first root-boundary candidate `923b872` hit the unchanged900-second trusted
launcher limit after one backend failure was reported; the suite-end diagnostic
was not emitted. Commands7/8 were NOT_RUN, and the complete interrupted log is
retained externally. The next snapshot emits diagnostic-only timing/failure text
for its34 new cases, without intercepting TestCase.run or altering results. Its
original-root-deadline regression now injects one delayed query so it distinguishes
that pre-existing deadline from the separate two-second sample deadline. This
does not retroactively diagnose or accept the interrupted candidate. Earlier
accepted suites also ran more slowly in that replay; cause remains unproven.

## Retained observer transport — source increment

Preceding heada853c67 completed all8 LOCAL commands /818 tests in activation218
and required localhost CI34714164106 attempt2 /activation219. Runner57 retired,
zero registered runners/artifacts. The two earlier900-second local timeouts and
cancelled attempt1 remain historical non-passes; the successful replay did not
change source bytes or deadlines. This evidence does not accept the increment
below or complete packet003.

Source inspection found that observer send/receive exceptions skipped post-I/O
custody checks, and later checks did not resample SO_PEERCRED or retain socket/
pidfd descriptor identities. The fixed observer now pins its original socket,
pidfd and process identity, rechecks peer credentials, exceptional pidfd liveness,
non-inheritance and socket-path identity, and brackets successful AND failed
datagrams with retained authority/peer checks. No reconnection or ambiguous-send
retry exists. One original two-second phase includes initial checks, send,
receive, parsing and final checks within the unchanged signed session deadline.

Newly acquired descriptors are retained before post-I/O refusal. Cleanup closes
only original resources, keeps uncertain failure sticky, and does not close a
reused descriptor or a substituted socket object. Received SCM_RIGHTS descriptors
are drained/rejected before a subsequent authority check can fail. Observation
history is pinned as immutable canonical bytes; returned data cannot mutate its
hash chain, and local history substitution refuses rather than re-enrolling it.

Twenty-five new methods drive the real observer factory and message validator
with OS mocks and explicit server-owner/legacy-containment component doubles.
They do NOT exercise the full NativeProxyServer or completed kernel qualification
factory. All818 previous test bodies and127 accepted files remain unchanged;
source target843 methods. All8 exact-commit LOCAL and required CI checks remain
mandatory; only external logs establish results.

The legacy containment hooks, retained proc readers and complete peer/native
qualification integration still require replacement/completion as listed above.
This transport correction grants no containment, observation-derived lease,
credential eligibility or execution permission. No actual socket/proc read,
native syscall, credential, host policy, installation or live campaign is run.

## Fixed observer-role inspection — source increment

Preceding head9e1a706 passed843 tests/all8 commands in LOCAL activation220 and
required localhost CI34733027083 /activation221; runner58 retired with zero
registered runners and artifacts. Those logs are external historical evidence,
not acceptance of the new source below. All127 accepted files and843 preceding
test bodies remain unchanged; meta/packet/native authority is unchanged.

The observer now owns a fixed `_KernelObserverInspection` instead of calling
`require_observer_containment` from a future probe module. This private component
consumes only the original server's authenticated binding and OBSERVER role; no
caller PID, role, descriptor, callback or record selects its scope. It owns its
own root, active-policy, retained-process, code, mapping, cgroup and filter
readers. Their existing custody/epoch machinery is reused without changing the
server-only reader's exact owner checks or allowing arbitrary subclasses.

The retained proc snapshot must match the process originally observed on the
socket, including start time, UID/GID, capabilities, namespace set and cgroup.
The original socket/pidfd, SO_PEERCRED, named socket identity and liveness are
checked at reader boundaries. These checks never call observer transport or the
server's recursive base guard. Inspection cannot outlive either its own two-
second phase or the containing observer exchange. Acquired readers close in
reverse order; socket, server and binding-file ownership remain separate. A
failed inspector constructor/check/close cannot be replaced with a success flag,
foreign inspector or legacy callback. The server-containment and execution
callbacks remain unfinished and are NOT enabled by this observer increment.

New tests exercise the real authenticated binding/observer composition with
typed component doubles and mocked channel queries, plus actual observer-factory
failure wiring. They do not claim combined OS-only/native qualification or a
complete NativeProxyServer startup. Prior transport tests keep their explicit
containment double at the new fixed inspector boundary; every old test body is
preserved. Independent native ordering/performance, full all-reader factories,
broker/server qualification, API integration and execution-fence evidence remain
required. No credential, live endpoint, native probe, policy change or installation
is used. Fresh exact-commit full8 LOCAL/CI acceptance is pending externally.

Final timing review identified a relative socket timeout calculated before the
new inspector ran. The remaining connect/send/receive budget is now set after
the last expensive check, immediately before I/O; a late timeout setter refuses
before a datagram is sent. Two added regressions retain the original two-second
exchange bound. Earlier exact-commit replay evidence is preserved separately
and cannot accept these later bytes. Current source target869 methods.

## Retained broker peer continuation

The preceding observer increment at `dc7f728976bc4460c97e9b746e09ddb842087f7b`
passed all869 tests and the full eight-command recipe in signed LOCAL acceptance
and required localhost CI34737704899 attempt3. The exact CI merge was
`216bd546023b0c5787201d566898bdc6b80baf02`; runner61 was retired. Earlier dispatch
failures remain recorded and are not product test passes. This evidence does
not accept the broker changes below.

The fixed broker channel now pins the signed broker manifest/enrollment, root
SO_PEERCRED identity, original socket object/descriptor, pidfd, PID start and
native executable. It connects only to
`/run/planeon/live-proxy/capacity-broker.sock` using AF_UNIX/SOCK_SEQPACKET;
there is no selectable path, role, reconnect, frame send, worker dispatch or API
operation in this component. Every check retains the original two-second phase
and overall session deadline. Partial acquisition retains cleanup ownership;
substituted objects and recycled descriptor numbers are not adopted or closed.

The broker-specific inspector composes the existing seven native read components
against the authenticated BROKER role and original peer. It joins retained proc
identity to that original socket process before code reads and repeats policy,
root, channel and deadline checks at reader boundaries. Reader cleanup owns
neither the borrowed channel nor server authority. Startup and transport checks
require the original broker before server credential use; the existing independent
server-containment refusal remains in place. This is not the completed qualifier,
dispatch protocol, per-message credential verification or execution fence.

New tests use real signed binding/composition with typed reader/OS doubles, plus
the real channel with explicit binding/inspector doubles. They cover enrollment,
peer substitution, deadlines, constructor failures and cleanup without changing
any of the869 preceding test bodies. Source-order checks are labeled as source
checks, not full native startup evidence. Fresh exact-head full8 LOCAL and required
localhost CI remain pending externally for these bytes.

The first broker candidate's replay stopped in a source-order test because its
socket-stat fixture also intercepted Python source-file metadata and traceback
formatting. The broker fixture now intercepts only its two declared peer paths;
source ordering has its own unmocked test class. The failed exact-commit log is
retained. Production code, original tests and acceptance commands are unchanged
by this fixture correction; all eight commands must be rerun on the new commit.

## Broker dispatch/start continuation

Candidate `64e2858dae44fa7ef7d6b1726c1db5b1e534106f` failed its signed full
offline replay: the37 new cases loaded fixture files after installing fd-only
transport doubles, so setup raised `KeyError` before testing the new behavior.
Load those fixtures before installing the doubles; no inherited test body or
production acceptance boundary changes. The failed log remains external
operator evidence, not PASS. The corrected head requires a fresh full8 replay.

Candidate `676ef10aa3da8204ffc893d419e8974dc37f0ba6` then exposed a production
clock-format error in the new handshake: the strict whole-second wire parser
rejected the installed runtime clock's RFC3339 microseconds. Runtime comparisons
now use the existing RFC3339 parser without rounding; observer wire timestamps
retain their strict whole-second format. Two additional regressions distinguish
these inputs. The new observer fixture uses canonical wire time, and its
out-of-order action vector uses a schema-valid integer action ID so it reaches
the intended ordering guard. The24 failures/five errors and the entire failed
replay remain retained; no subset, inherited-test or acceptance-policy change.

Preceding head `acb2da5cba9fef6f35b3316f5c005534a8e8b20b` passed926 tests,
zero skips and all8 commands in signed LOCAL activation228 and required localhost
CI34741454274/activation229. Runner62 retired, zero runners/artifacts verified.
That checkpoint does not accept the following source changes.

The original broker now owns a no-argument dispatch/start phase. It derives the
fixed case/request, signed binding and reservation digests from the installed
server, checks the exact held RUNNING journal record, and binds a fresh observation
and random256-bit challenge. Caller requests, frames, paths and execution handles
are not inputs. A mutable RUNNING flag or a schema-valid dictionary is insufficient.
Journal/owner/observation changes, generation restart, expiry and failed native
inspection refuse. This phase reads existing durable state; it does not append,
repair, release or reconstruct the journal.

One DISPATCH and first STARTED response use the original retained channel, within
one two-second phase and the original session deadline. Both sides of blocking
I/O recheck peer/authority, journal and current observer state. The receive path
drains unexpected descriptors before post-I/O refusal, requires original message
credentials, rejects truncation/oversize/malformed or rebound frames, and validates
the first transcript sequence/echoes. A partial send or lost response consumes
the attempted case locally and is never retried/reconnected. Failure closes the
original channel without closing the borrowed journal or server files; uncertain
cleanup remains a sticky failure. STARTED is published
as data only after the last phase guard; it is not a local execution permit,
worker qualification, successful receipt or tenant acceptance.

This increment is intentionally not wired into `NativeProxyServer.serve` yet.
The complete broker action/chunk/cleanup/terminal driver, server-only API and UID
ledger, fixed qualifier replacement and full native factory composition are still
unfinished. Existing startup/execution refusal remains. Tests exercise the real
request/ledger/transcript parser and fixed channel with explicit installed-owner,
observer, store and native-inspector doubles. They do not start a worker, open a
credential/API endpoint, or prove a real durable transaction/native environment.
All926 earlier test bodies and all127 accepted baseline files remain immutable.
Fresh exact-head full8 LOCAL and required localhost CI must pass independently.

## Broker inbound-event continuation

Preceding head `fd64ffa5bd8ed7198a6bf16f46b1a9ab34afddb8` passed 965 tests,
zero skips and all eight commands in signed LOCAL activation 232 and required
localhost CI 34745275207 / activation 233. Runner 63 retired; zero runners and
uploaded artifacts were independently verified. Its source tree and CI merge
tree match. That checkpoint does not accept the following source changes.

The original broker now has a no-argument `poll()` that receives at most one
inbound event or returns `None` for a bounded idle wait. It reuses the original
channel, STARTED observation, transcript and absolute session deadline; no
DISPATCH resend, keepalive grant, reconnect or caller-selected timeout exists.
Each phase stays within two seconds, with readiness waits capped at 250 ms and
half the remaining phase budget so post-wait inspection remains mandatory.
Original RUNNING history, current policy generation, native peer and retained
transcript checks surround readiness/receive and precede returning event data.
Unexpected descriptors are drained before post-I/O refusal. Any malformed,
late, lost, substituted or out-of-order response closes the original channel
without retrying or releasing the durable reservation.

Only bounded RESOURCE_ACTION and RECEIPT_CHUNK data are admitted. A case-bound
resource action is not executed and pauses further reception until the separate
server response driver exists. Zero-resource profiles refuse every action.
Receipt chunks enforce contiguous sequence/index/digest binding, 24 KiB decoded
per chunk, at most 171 chunks and 4 MiB total; retained transcript mutations are
rejected. No terminal or cleanup acknowledgement is accepted by this receiver.
Polling writes no journal, reads no credential and opens no API connection.

Tests exercise the real handshake, receiver and data parser with explicit OS,
installed-owner, observer and durable-store doubles. They prove no native
execution, resource effect, cleanup, completed receipt or tenant acceptance.
All 965 prior test bodies, all 127 accepted baseline files and the published
fixture bytes remain unchanged. The server driver/API/UID ledger, cleanup and
terminal exchange, fixed qualifier and complete native factory integration are
still unfinished; `NativeProxyServer.serve` is not connected to this receiver.
Fresh exact-head full LOCAL and required localhost CI remain mandatory.

Candidate `16ff3ed3798e0ccc38e0edede8302d41f9d71b78` completed all six suites
with three new-test failures: the chunk-count vector exceeded the wire index
range before its intended transport guard, the oversized encoded chunk was
correctly rejected by the earlier schema guard, and the terminal vector lacked
the mandatory `workerReaped` field. Correct only these new vectors/expectations;
retain separate malformed-index/terminal cases and the entire failed replay.
Production code, all predecessor tests and the acceptance recipe are unchanged.
The corrected exact head requires a fresh full eight-command replay.

## Server-only API authentication continuation

Prior head `1419ff373ebae5b173c99ce3ef7dd005f7b97146` passed 1,013 tests,
zero skips and all eight commands in LOCAL activation235 and required localhost
CI34747686579/activation236. Both trees were70646d1; runner64 retired with zero
runners/artifacts. Failed initial inbound-event vectors remain recorded above.
That evidence does not accept this later source increment.

The original broker now owns one no-argument `prepare_api()` for its original
pending, case-bound resource action. It verifies current RUNNING history,
observer generation, peer/authority and exact manifest/API grant before opening
the distinct server-only API credential. Zero-resource runs have no such path.
The endpoint, numeric address/family/port, TLS name/SPKI, separate credential and
release-listed CA all come from retained inputs, never caller parameters.
No DNS, fallback family, kubeconfig, bearer token or ambient CA is introduced.

The one-read 0400 credential is checked, copied to an owned CLOEXEC memfd,
sealed and read back before context loading. The memfd closes before TCP use.
The API socket is independently owned and non-inheritable, with retained FD and
connected-peer checks. Shared MemoryBIO TLS1.3/certificate logic surrounds I/O
with the original broker/observer checks and session deadline. Connect is one
attempt with a maximum two-second wait inside its ten-second phase cap; no
reconnect or credential reopen is permitted. Partial failure closes original
resources, preserves ambiguous-close errors and never closes a substituted FD.

This step authenticates only: it sends no HTTP request, Kubernetes mutation,
RESOURCE_RESULT, CLEANUP_RECORDED or terminal acknowledgement. It creates no
durable intent/UID ledger and does not release a reservation. API authentication
cannot prove independently enforced generation admission. The resource driver,
durable intent/observed identity accounting, cleanup and completed native factory
integration remain unfinished; `NativeProxyServer.serve` is not wired to this leg.

Tests use the real broker/API factories, data checks and MemoryBIO codec with
explicit OS, installed-owner/observer/store and OpenSSL context/handshake doubles.
Certificate inputs are unsigned DER-shaped data, not issued keys or a live TLS
session. Tests do not establish native containment, chain trust or API effects.
All1,013 predecessor methods,127 accepted files and existing fixture bytes remain
unchanged. Fresh exact-commit full LOCAL and required localhost CI are mandatory.

## Durable create-accounting checkpoint (source-only)

The existing `reservations.jsonl` journal now accepts two closed, private
resource-record variants: `CREATE_INTENT` and `CREATED`. They retain the same
sequence/hash chain, binding, operation, time, transaction lock, size limits and
precreated store. No new file, migration, public schema or installation is added.
Existing reservation/cleanup row bytes remain valid and are never rewritten.

`_AdmissionLog.record_resource` derives identity from the validated profile,
its exact admission binding, disjoint broker case ownership and a bounded CREATE
action. It compares the caller-retained history under the journal lock and returns
only after append, fsync, exact readback and transaction exit. Any write, sync,
readback or exit ambiguity poisons the owner and forbids retry. Storage is still
owned by the original server; this data algorithm is not an execution grant.

Intent stores an exact name/manifest/action with null UID and resourceVersion.
CREATED must follow that same intent and validates the actual returned manifest
before retaining UID/resourceVersion. Repeated creates, name/action/manifest
reuse, identity replacement, unsupported scope, adoption without intent and
cross-case/run substitutions refuse. Replay checks the same closed transitions;
at most32 resource identities are retained for the whole reserved run.
Another create intent is refused while an earlier intent remains unresolved.

An unresolved intent remains a held name, with null UID and `IO_AMBIGUOUS` when
recorded in a pending cleanup receipt. Known identities likewise remain held.
A cleanup receipt cannot silently omit, substitute or invent these resources;
an empty list cannot release them. No new resource record is accepted after
that operation's cleanup record. Independent absence accounting is deliberately
not implemented yet, so these new resource states cannot reach CLEAN in this
checkpoint. Crash/restart is not reconciliation and never reopens a nonce.

This increment does not send an API request, acknowledge a broker action, delete
a resource or wire the journal into `_BrokerStart`/`NativeProxyServer.serve`.
The original RUNNING-history guard still refuses changed history; a subsequent
guarded driver must adopt only its own successfully committed journal transition.
Connecting that driver, independently verifying absence and completing the native
factory remain mandatory before API effects. Existing macOS unit tests exercise
the real data/journal algorithms with in-memory storage, not native durability,
generation enforcement or tenant acceptance. All1,060 preceding tests and the127
accepted baseline files remain unchanged; a fresh full signed LOCAL and required
localhost CI run must validate this exact increment.

## Guarded create-intent checkpoint (source-only)

The fixed, no-argument `_Broker.record_create_intent()` now connects a pending
broker CREATE action to the existing server-owned journal. `_BrokerIntent` is
retained before any write and derives the entire expected row from the original
admission/profile/case/action binding. Callers cannot supply a resource, observed
object, history, backend or replacement writer. The original journal class method
is used, not an instance-supplied callback.

The full original event/peer/observer/history guard runs before the transaction.
The existing storage owner checks protect its individual storage operations;
the complete transaction remains inside the original two-second broker phase.
Only a matching digest, exact readback of the single expected append and original
owner/pending-action checks can advance the dispatch's retained history pin.
Full policy/observer/peer/history checks run again after that advance; publication
waits for the enclosing phase's final guard. This does not relax or replace
`_BrokerStart._state_check`: unexpected history changes still refuse.

Write, sync, readback, unlock, late return or post-write policy/ownership ambiguity
closes the original broker and poisons the original journal owner. A conservative
intent already on disk stays held even when the call fails; its nonce, name and
quota are not repaired or released. Repeated or reentrant calls do not retry.
The retained intent's no-argument `check()` revalidates current ownership, history,
policy and deadline before subsequent use; it is not an API permission token.

This checkpoint writes **only CREATE_INTENT**. It sends no HTTP request or broker
RESOURCE_RESULT, records no CREATED/absence/cleanup/terminal result, opens no API
connection and reads no upstream credential. The action stays pending. The API
driver, guarded response accounting, independent exact-UID cleanup, completed
qualification/native factory and `NativeProxyServer.serve` integration remain
unfinished. Native generation enforcement is an external prerequisite, not a
claim established by observing before and after a journal write.

Tests exercise the real broker/event/intent and journal algorithms with explicit
OS, installed-boundary, observer and in-memory storage doubles. They do not prove
native filesystem durability, atomic generation enforcement or tenant acceptance.
All1,097 preceding test methods,127 accepted files and fixture bytes are preserved.
Fresh exact-commit full signed LOCAL and required localhost CI remain mandatory.

## One-shot CREATE exchange checkpoint (source-only)

`_Broker.exchange_api_create()` now owns one bounded exchange on the original
authenticated API connection, after the original CREATE_INTENT is committed.
The method takes no caller request, URL, resource, response, or backend. It derives
the fixed namespaced v1 POST path and canonical body only from the retained
profile/action. The API transport guard now also checks the exact exchange and
intent before and after I/O; generation, peer, history, ownership and deadline
loss cannot publish a successful candidate. Partial sends never restart a request.

The existing strict HTTP profile is unchanged: one request/connection, fixed Host,
exact length, no redirects/chunking/pipelining, bounded header/body and absolute
deadlines, canonical observed object, and only HTTP 200 success transport. In
particular, 201 is not silently enabled and 409 is never adopted. This is not a
claim of compatibility with an unqualified raw Kubernetes API; any different
API-proxy response profile requires explicit contract review before support.

The returned object is checked against the exact signed manifest, including
UID/resourceVersion and post-defaulting restrictions, and retained as private
candidate bytes only. No CREATED journal row, RESOURCE_RESULT, next action,
cleanup, terminal, capacity release or tenant/native acceptance is emitted here.
The durable intent remains held, including when a response is lost or malformed.
Guarded returned-identity persistence and result/retirement lifecycle must follow
before the complete server driver can use this candidate. It is not wired into
`NativeProxyServer.serve` yet. No live request runs in coding or CI.

New tests exercise actual broker, journal, API owner, MemoryBIO transport and HTTP
parsing with explicit OS/OpenSSL/observer/storage doubles. All 1,132 preceding
tests and the 127 baseline files remain unchanged. Full signed LOCAL and required
localhost CI remain mandatory; mocks do not qualify native effects or durability.

## Returned-identity accounting checkpoint (source-only)

`_Broker.record_api_created()` persists the original completed CREATE exchange's
validated UID/resourceVersion using the existing `_AdmissionLog.record_resource`
algorithm. No caller identity, response, history, path or backend is accepted.
The original intent, API owner, pending action and response remain bound together;
the response is revalidated against the signed manifest before deriving one exact
CREATED row. The original journal transaction compares the expected history,
appends, fsyncs and reads back. Only that exact append may advance the dispatch
history pin. The intent's original `after` bytes remain unchanged; its guard
recognizes only this separately retained CREATED owner, not arbitrary new history.

Current ownership, peer, observer, API custody and deadline checks bracket the
transaction and publication. Partial append, sync/readback/unlock ambiguity,
generation loss, changed response/owner or a late return poisons the original
journal owner and closes the original broker. An already-written UID remains
held, including when post-write checks fail. No automatic retry, history repair,
resource adoption or capacity release follows. Repeated/reentrant calls refuse.
The retained no-argument `check()` revalidates this accounting but grants no
cleanup or action permission.

The broker action remains pending: this step sends no RESOURCE_RESULT, HTTP
request, GET/DELETE, cleanup receipt or terminal frame and reads no new credential.
Result acknowledgement, connection retirement/next-action lifecycle, exact-UID
cleanup and full native factory/serve integration remain unfinished. This is
not wired into `NativeProxyServer.serve` and is not native durability evidence.

New tests use the actual broker/exchange/journal algorithms with explicit
OS/OpenSSL/observer/storage doubles, covering exact append ordering, contention,
write and unlock failures, changed history/identity, deadlines and lost policy.
All 1,167 predecessor test bodies, 127 baseline files and fixture bytes are
preserved. Fresh full signed LOCAL and required localhost CI are mandatory.

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
| Alpha 2 | CONF-LIVE-003 checkpoint / kernel byte parsers | LOCAL_AND_CI_PASS_RECORDED | Head1792452 passed448 tests and all8 commands; packet still incomplete |
| Alpha 2 | CONF-LIVE-003 native read primitives | LOCAL_AND_CI_PASS_RECORDED | Head22de588 passed466 tests and all8 commands |
| Alpha 2 | CONF-LIVE-003 fixed kernel-root custody | LOCAL_AND_CI_PASS_RECORDED | Headc435f7c passed486 tests and all8 commands; runner43 retired |
| Alpha 2 | CONF-LIVE-003 retained process / namespace component | LOCAL_AND_CI_PASS_RECORDED | Head6dcd8e7,509 tests,all8 commands; runner44 retired |
| Alpha 2 | CONF-LIVE-003 fresh kernel-policy custody | LOCAL_AND_CI_PASS_RECORDED | Head2adf60a,535 tests,all8 commands; runner45 retired |
| Alpha 2 | CONF-LIVE-003 code-file custody / mapping data | LOCAL_AND_CI_PASS_RECORDED | Head1475d3c,572 tests,all8 commands; runner47 retired |
| Alpha 2 | CONF-LIVE-003 retained process-code component | LOCAL_AND_CI_PASS_RECORDED | Head263e9e2, 605 tests, all8 commands; runner48 retired |
| Alpha 2 | CONF-LIVE-003 retained cgroup component | LOCAL_AND_CI_PASS_RECORDED | Heade53af04, 636 tests, all8 commands; runner49 retired |
| Alpha 2 | CONF-LIVE-003 retained endpoint-filter component | LOCAL_AND_CI_PASS_RECORDED | Head6812922, 671 tests, all8 commands; runner50 retired; initial failed replay retained |
| Alpha 2 | CONF-LIVE-003 authenticated qualification binding | LOCAL_AND_CI_PASS_RECORDED | Heade4003fc, 694 tests, all8 commands; runner51 retired; failed IPv6 fixture replay retained |
| Alpha 2 | CONF-LIVE-003 self-inspection composition | LOCAL_AND_CI_PASS_RECORDED | Head3520721,715 tests,all8 commands; runner52 retired |
| Alpha 2 | CONF-LIVE-003 reader-boundary custody / lifetime | LOCAL_AND_CI_PASS_RECORDED | Head87c743a,733 tests,all8 commands; runner53 retired; failed fixture replay retained |
| Alpha 2 | CONF-LIVE-003 retained policy epoch | LOCAL_AND_CI_PASS_RECORDED | Head99652a1,760 tests,all8 commands; runner54 retired; failed fixture replay retained |
| Alpha 2 | CONF-LIVE-003 epoch mount custody | LOCAL_AND_CI_PASS_RECORDED | Heada196f32,784 tests,all8 commands; runner56 retired; failed local replay and failed pre-listener startup preserved |
| Alpha 2 | CONF-LIVE-003 reader-boundary root ancestry | LOCAL_AND_CI_PASS_RECORDED | Heada853c67 /818 tests/all8; CI34714164106 attempt2; earlier timeouts retained |
| Alpha 2 | CONF-LIVE-003 retained observer transport | LOCAL_AND_CI_PASS_RECORDED | Head9e1a706 /843 tests/all8; CI34733027083; runner58 retired |
| Alpha 2 | CONF-LIVE-003 fixed observer-role inspection | LOCAL_AND_CI_PASS_RECORDED | Headdc7f728 /869 tests/all8; CI34737704899 attempt3; runner61 retired |
| Alpha 2 | CONF-LIVE-003 retained broker peer / native composition | LOCAL_AND_CI_PASS_RECORDED | Headacb2da5 /926 tests/all8; CI34741454274; runner62 retired |
| Alpha 2 | CONF-LIVE-003 broker dispatch / first STARTED | LOCAL_AND_CI_PASS_RECORDED | Head fd64ffa / 965 tests / all eight; CI 34745275207; runner 63 retired |
| Alpha 2 | CONF-LIVE-003 bounded inbound events | LOCAL_AND_CI_PASS_RECORDED | Head1419ff3 /1,013 tests/all8; CI34747686579; runner64 retired |
| Alpha 2 | CONF-LIVE-003 server-only API authentication | IMPLEMENTED_NOT_ACCEPTED | Original pending action, separate credential/socket/TLS; no HTTP/effect/cleanup |
| Alpha 2 | CONF-LIVE-003 CREATE exchange | LOCAL_AND_CI_PASS_RECORDED | Head13e716f /1,167 tests/all8; CI34756347888; runner68 retired |
| Alpha 2 | CONF-LIVE-003 returned-identity accounting | IMPLEMENTED_NOT_ACCEPTED | Exact CREATED journal append; action still pending; fresh full acceptance required |
| Alpha 2 | CONF-LIVE-003 native inspector / broker / API | ONGOING | Required implementation listed above |
| Alpha 2 | CONF-LIVE-003 required CI | WAITING | Fresh exact-head localhost evidence required; prior failures retained |
| Alpha 2 | CONF-LIVE-003 source completion / merge / exact-main | NOT_RUN | Packet is incomplete; no completion claim |
| Alpha 2 | CONF-LIVE-004 | WAITING | Fixed worker and ten native probes |
| Alpha 2 | CONF-LIVE-005 | WAITING | Reproducible candidates and operator handoff |
| Alpha 2 | CONF-LIVE-006 | WAITING | Trusted campaign integration |
| Alpha 2 | Linux AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed/native qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | No phase promotion |

Model-effort transition: NOT_DUE. Alpha 2 remains open.
