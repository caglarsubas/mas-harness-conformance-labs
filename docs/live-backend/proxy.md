# CONF-LIVE-003 — Proxy source implementation

## Current correction — Alpha 2 / CONF-FIX-007 / ONGOING

This section supersedes the publication-status headings below without rewriting
their historical evidence. CONF-LIVE-003 source publication is recorded at PR12,
main `092fcf475c6f3ebd455e3c354cddb7664ea1f900`, tree
`f5a25661c2df6c87e5d3429b0b5f62511c2e5988`; its implementation was incomplete.
MET-REPAIR-017 was accepted separately at meta main
`a92b78f9bca51bed4836f5100e58caebadf4b3fb` (PR122).

CONF-FIX-007 is the sole current corrective owner, on branch
`codex/conf-fix-007-conformance-completion`. Its five existing paths are the
server, admission module, their two test files and this guide. All other130
files, all135 baseline paths and all1277 predecessor test identities remain
mandatory. No new product stage, public protocol, dependency or live permission.

| Check | Current source checkpoint | Remaining acceptance |
|---|---|---|
| C1 | DRAFT: `_KernelQualification` owns the fixed self reader and joins original observer/broker lifetimes; OS-double factory regressions added | Execute full isolated recipe; complete ownership/drift review and C6 integration |
| C2 | DRAFT: future containment/execution callbacks removed; serve loop drives the original broker | Actual complete factory acceptance without004; failure-path closure |
| C3 | DRAFT: CREATE handoff, original read-once credential reuse and guarded GET/DELETE result/retirement | Complete sequential driver acceptance |
| C4 | DRAFT: fresh GET, exact UID/version DELETE, confirmed absence and fail-only cleanup journal integrated | Full factory failure-path verification and isolated acceptance |
| C5 | DRAFT: complete receipt validation, durable cleanup seal, terminal journal and one-way clean case handoff | Integrated failure/driver acceptance remains unproven |
| C6 | DRAFT: full `serve()`/HTTP/MemoryBIO and zero/resource-mode factory cases added | Review and execute the full recipe; no successful qualifier/driver substitutes |
| C7 | ONGOING: source/test mapping below; no completion certificate | Finish independent exact-tree review, full local/required localhost CI, protected merge and separate local exact-main |

LOCAL1 on candidate `6405c014bded2f975576ccd753804e3b12d50b20` failed at the
unchanged900-second trusted deadline. The first five suites passed170 tests;
the sixth reported an error and never completed. Its unfinished progress is
not a pass count. The original log SHA256 is
`03d20f32743575c7bb42c73f9616992d772d4e32a492895416a735809aa4ad9c`.
Draft PR18 preserves that failure; its unassigned CI queue was canceled without
execution. LOCAL2 on `c366a3fac47d53a52a4fbe76618796e9fe196848` also timed out
at900 seconds. Five suites passed170 tests; backend inventory1390 did not
complete.956 progress characters without E/F are not a full acceptance result.
No new factory diagnostic was reached. Its log SHA256 is
`9855fa1836c1eade40ae2dfc589d0db33b0f82957d4af1fba1410aa44bc1ab7a`.
LOCAL2/3 is consumed; CI0/2 and LOCAL_EXACT_MAIN0/1 remain unexecuted.

The broker transport leaf fixture now supplies the original qualification-owner
and inspector data required by the fixed private join. Actual
`_KernelQualification.check_peer`, `_guard`, `_peer_pin` and `_Broker.check`
remain active. The predecessor UNIT_INSPECTOR denial and storage/observation
assertions are unchanged; an added regression verifies sticky refusal and the
original peer pin. This manually assembled leaf is not C1/C6 evidence.

The timeout remains unresolved. New full-factory tests emit start/finish timing
and a30-second repeating stack-only diagnostic so a complete replay can locate
the stalled code. It does not stop cases, alter clocks/guards, replace factories,
filter discovery or extend any deadline. Unit stacks print no local values or
credentials. A watchdog stack dump is diagnostic, not an acceptance result.
C7 remains OPEN; no successful factory/HTTP completion is yet established.

The next bounded correction targets private `_time`: the existing exact ASCII
grammar still runs first; valid values use the stdlib ISO parser instead of
locale-dependent general format parsing. Invalid calendar values fall back to
the exact former parser outside the exception handler, preserving its error
type/args without adding exception context. Values are parsed afresh on every
call; no expiry, authority, signature, kernel observation or I/O guard is cached.
No crypto/canonical helper, wire schema or checking cadence changes.

Seven additional StrictTimestampParserTests compare the former parser with
calendar/century/leap-second boundaries, invalid grammar and types, error
precedence/context, UTC values and fresh calls. A bounded ABBA timing sample
prints diagnostic measurements only: no speed assertion, native benchmark or
claimed whole-suite gain. These new tests and the correction remain unaccepted
until an exact full isolated replay. The earlier slowdown's root cause is not
established: six unchanged root-wiring tests took3.443–4.120x their LOCAL1 wall
time and host load also increased. Neither fact alone proves contention or
justifies weaker guards. The final LOCAL attempt must not be reset or pooled.

Static syntax/scope and identity checks do not execute or qualify the product.
Reserve each attempt durably before signing/activation; limits remain3 LOCAL,2 CI and1
LOCAL_EXACT_MAIN, with the full original eight-command recipe and unchanged
isolation/time limits. Do not merge this correction or begin CONF-LIVE-004 until
C1–C7 and the independent source gates are complete.

`_KernelQualification` checks the original installed server owner, deadline and
binding; it owns only its self-reader resources. Observer/broker channels own
their native readers, sockets and pidfds. Partial failures close acquired
resources only; a failed lifetime cannot be restored by replacing a field or
resetting a clock. It neither constructs a worker nor grants execution. The
existing independently installed broker remains the enforcement owner.

`handoff_create_result()` consumes only an already-delivered, durably accounted,
locally retired CREATE. The receiver retains a bounded digest archive and the
original transcript, used action IDs, RUNNING ledger, peer, generation and
deadline. It sends no frame, reopens no retired socket and releases no resource.
The CREATE handoff archive now explicitly records its verb, matching the
GET/DELETE replay guard. Source review caught this missing discriminator in the
previous unexecuted draft; this fix has not been test-accepted yet.
After handoff a subsequent authorized API connection may use the original
server-retained identity bytes, with custody, digest and certificate validation;
it may not reopen the credential path, adopt preloaded bytes or refresh authority.
`exchange_api_get()` now derives the exact named GET from that pending action
and the retained profile, requires a durable server-created UID for this case,
and validates the returned UID/labels/manifest with the existing strict checker.
A changed resourceVersion remains an observation, not an ownership change.
`send_get_result()` sends the original bounded PRESENT fact once;
`handoff_get_result()` closes the original API connection before advancing the
same transcript and archiving the result. All paths retain the original
deadline, generation, action history and durable UID accounting. Read, send or
close ambiguity cannot retry, adopt, erase a ledger row or certify cleanup.

The GET increment now distinguishes PRESENT from a narrowly validated ABSENT
observation on the server-only API leg. The immutable campaign HTTP parser still
rejects non-200 transport; it is not changed or used to normalize an error into
success. `_read_api_get_response` accepts only200 or404, preserving strict
headers, original TLS ownership, ten-second header and original overall deadline,
exact Content-Length/EOF and a16KiB object bound. Every other status, duplicate or
unknown header, compression, chunking, surplus, truncation and ambiguous read
refuses. A200 error object is not a resource or an absence observation.

For404, `validate_absent_status` requires the known server-created UID and the
exact v1 `Status`/Failure/NotFound/code404 shape, empty metadata, core group,
selected plural resource/name and canonical NotFound message. Generic route,
namespace, permission or foreign-resource errors do not satisfy it. This is a
strict subset of Kubernetes' [NotFound construction](https://github.com/kubernetes/apimachinery/blob/master/pkg/api/errors/errors.go)
and [StatusDetails](https://kubernetes.io/docs/reference/kubernetes-api/definitions/status-details-v1-meta/),
used only after the original authenticated, generation-guarded named GET.
Upstream documentation explains wire semantics; it grants no endpoint,
permission, network access, package adoption or native qualification.

`record_get_absence()` owns the separate `_BrokerAbsence` transaction. It pins
the original GET/status/UID/profile/action/history, appends an ABSENT fact to the
same root-custodied journal, fsyncs and verifies readback before advancing the
retained history. An ABSENT broker result cannot be sent before this succeeds.
The private row retains the original CREATE identity and a closed GET/status
proof; it is data, not authenticated evidence in isolation. It does not delete
history, permit name/UID reuse, reopen a case or release whole-run capacity.
Ambiguous CREATE with null UID cannot be recorded absent. Storage ambiguity or
post-I/O authority loss poisons the active owner and prevents result delivery.
Cleanup receipts must contain exactly the unresolved identities; a CLEAN receipt
cannot omit a still-created or ambiguous resource. ABSENT alone is not a terminal
acknowledgement, assurance result or tenant acceptance.

`exchange_api_delete()` now owns one exact DELETE on its original API connection.
It requires the immediately preceding, successfully delivered and retired PRESENT
GET from the same original broker, case, transcript, generation, profile and held
CREATED ledger. The retained GET object and its immutable private snapshot cannot
be substituted. A five-second maximum age is checked before and throughout the
single request write; this never extends the original signed operation deadline.
It validates the current manifest/labels/UID again and derives only the signed
named resource path. `DeleteOptions` contains the original UID and the version
observed by that GET, not just the older CREATE version. The extra version
precondition conservatively prevents a label/manifest update between GET and
DELETE from being ignored. A conflict refuses; there is no retry without the
version, no force/grace override, finalizer manipulation, selector or collection
delete. The [Kubernetes DeleteOptions reference](https://kubernetes.io/zh-cn/docs/reference/kubernetes-api/common-definitions/delete-options)
describes these preconditions; it is a wire-semantics reference, not qualification
or permission to contact a cluster.

The existing server-only resource response codec retains all its bounds. DELETE
accepts only200 plus a scoped Success Status with the recorded UID or a validated
resource acknowledgement. Graceful-deletion timestamp/period fields in that
response do not become an absence claim. DELETE404 is not a substitute for the
separate GET404 proof; conflicts, permission errors, surplus/unknown framing,
changed owners/UIDs, late writes, response loss and ambiguous broker send/close
retain the original CREATED history. `send_delete_result()` and
`handoff_delete_result()` acknowledge and retire only this action/connection.
They write no ABSENT or cleanup row, release no capacity and cannot repeat a
DELETE already consumed in this case, even after another PRESENT GET.

`BrokerDeleteActionTests` adds the sequential CREATE/GET/DELETE/GET-absence leaf
path and refusal coverage. `DeleteDataTests` checks request/response data without
I/O or execution authority. All new tests are still unexecuted source drafts.
Full C4/C5/C6 factory verification remains unfinished; this draft must not be
described as complete server cleanup or qualification.

### C5 draft — durable cleanup is not terminal delivery

`_BrokerCompletion` now owns the original receipt chunks and completion phases.
It requires no outstanding action or unretired API owner, preserves the original
transcript/chunk bytes and bounds, and validates the complete unchanged Linux
receipt against the retained session, request and regression expectations.
Partial, surplus, mismatched or false-status data cannot be sealed. Cleanup
comes only from the server's current journal: known unresolved UIDs remain
OBSERVATION_UNAVAILABLE and null-UID CREATE intents remain IO_AMBIGUOUS. A PASS
candidate with unresolved resources or a failed action is rejected. Broker lists
cannot waive remaining resources, provide a UID or grant cleanup permission.

The new native path uses two closed private journal transitions:

- `CLEANUP_SEALED`: append/fsync/readback the cleanup and receipt/transcript proof
  before sending CLEANUP_RECORDED. The current case and capacity remain held,
  including after the tenth cleanup. This is not terminal acceptance.
- `TERMINAL_RECORDED`: only after the original authenticated broker frame echoes
  the exact cleanup and receipt digest/size, sequence, execution, scope,
  generation/challenge, matching status and worker-reaped field, and immediate
  trailing data has been refused. A separate append/fsync/readback records that
  received fact. Only all ten completed clean cases release run capacity; nonce
  and resource histories are retained. FAILED/UNAVAILABLE keep the case held.

`seal_cleanup`, `send_cleanup`, `poll_terminal` and `record_terminal` accept no
caller frame, cleanup list or result override. Original owner/observer/peer,
history, authority and two-second phase/original operation deadlines bracket
I/O. Idle polling neither resends cleanup nor renews a lifetime. Loss, timeout,
SCM_RIGHTS, stale generation, changed bytes, partial writes or ambiguous delivery
fail closed; no reconnect, retry, journal rollback or fabricated terminal.

Historical RECORDED rows retain their original data-replay semantics, but cannot
be mixed with the new native terminal mode in one reservation. The new driver
must exclusively use the sealed/terminal path. No wire schema, existing fixture,
signing role or external acceptance state was changed. These private rows are
data, not proof of authenticated execution in isolation.

`CompletionJournalTests` and `BrokerCompletionTests` add journal and real leaf
owner/channel tests, including ten-case capacity retention and terminal-loss
failure paths. Resource leaf tests cover confirmed absence and pending cleanup.
These are not C6 full NativeProxyServer tests. The serve loop and clean case
handoff are now drafted as described below. Action-failure disposition, complete
factory tests and C7 review/isolated runs remain pending.
The appended `BrokerGetActionTests` exercise real CREATE/GET/result/retirement
owners with unit-only OS/observer/TLS/storage doubles. They do not replace C6
actual server-factory acceptance or native qualification. No tests have run for
this corrective draft; the static audit preserves all1277 predecessor IDs and
the130 out-of-scope files, including the unchanged client and wire-schema data.
New `AbsenceJournalTests` cover detached status/journal rules using in-memory
storage only. Neither those data tests nor the OS/TLS-mocked action tests supply
independent absence proof outside their explicit unit boundary.

### C2/C5/C6 draft — fixed driver and case handoff

`NativeProxyServer.serve` now invokes only its fixed `_drive_case`. The future
`_fixed_probes` importer and containment/execution callbacks have been removed,
not replaced with a plugin, callback or local worker invocation. The original
broker owns execution; the server sequences its existing intent, API, result,
retirement, receipt and terminal owners. CREATE intent precedes upstream
credential acquisition; zero-resource actions refuse before an API is acquired.
`check_action_ownership` adds a pre-credential check for durable intent/known
created UID and, for DELETE, the retained fresh PRESENT GET. It is not a cached
permit: the existing full guards still bracket every subsequent I/O/effect.

`_receipt_chunks_complete` only detects a bounded top-level object boundary
across the existing chunks. It handles split strings, escapes and UTF-8 bytes,
rejects wrong delimiters, excessive depth and trailing objects/bytes, and
changes no wire framing. A structural boundary is not valid JSON or a valid
receipt: the unchanged strict receipt validator must still succeed before
cleanup is sealed. Missing data expires under the original operation deadline;
extra chunks/frames cannot pass the terminal phase.

The native serve loop no longer writes legacy RECORDED rows. A response can be
returned only after CLEANUP_SEALED, its same-channel acknowledgement and a matching
durable TERMINAL_RECORDED fact. `finish_case` retires only a clean PASS/COMPLETED
case with exact readback, no outstanding owner and no queued trailing data.
It clears only completed local phase owners. It retains the original broker
socket/pidfd, credential cache, deadline, used cases, nonce and all resource
history, plus a bounded digest archive of the completed cases. A subsequent
DISPATCH must use a new challenge and execution ID but the same original
observer boot/generation. Failed/unavailable cases cannot advance; lost terminal
data cannot retire a case or become a success response.

The new `ProxyCaseDriverTests` exercise the real driver and broker/journal/receipt
implementations with the earlier leaf boundary doubles. They explicitly do NOT
prove C6: combined constructor/qualification OS-double coverage is a separate
increment described below and remains incomplete. `BrokerCaseHandoffTests`,
`ReceiptChunkBoundaryTests`, `BrokerCreatePreflightTests` and new resource-leaf
preflight tests cover the additional data/ownership paths. All remain unexecuted.

The removed private helper requires one additional predecessor test adaptation:
`ObserverInspectionWiringTests.test_observer_no_longer_requests_legacy_probe_containment`
adds only `create=True` to its existing raising mock. The same no-callback trap
and all assertions remain; the corresponding observer fixture mock receives the
same setup adaptation. No obsolete production helper is retained for the test.
The static audit verifies this exact before/after transformation, in addition
to the two earlier constructor-order spelling adaptations.

### C4 failure-accounting draft — retained failure is not renewed authority

The fixed driver now captures a `_FailureAccounting` owner before DISPATCH.
On refusal it first closes the original broker/API path, then may append only a
local failure fact to the original intact journal. It never recontacts the
observer, broker or API, rereads a credential, runs cleanup, sends a terminal,
returns a success receipt or grants a new execution lifetime. Deadline expiry
does not prevent recording a failure against retained custody; it never permits
a post-expiry resource action. Lost file/owner custody blocks even this append.

The admission log separately retains the exact history from its last completed
append/fsync/readback/transaction exit. Execution poisoning remains sticky, but
is distinguished from storage ambiguity. A known intact original history may
receive one fail-only append after an execution refusal. Partial writes, failed
fsync/readback/transaction exit, foreign or rolled-back history, a reopened log,
or any second attempt cannot use that path. Nothing clears the active-work
poison flag, repairs/truncates the journal, or adopts a valid-looking extra row.

`FAILURE_RECORDED` is a closed private journal transition, not a new wire message.
Its cleanup is derived from the exact unresolved identities already in that
journal. Known UIDs retain their original name/manifest/ownership; unknown CREATE
outcomes retain `uid=null` and IO_AMBIGUOUS, including after expiry. Fixed reason
mapping uses the existing enum only. It never persists arbitrary exception
messages, URLs, credentials or caller resource lists. A zero-resource or already
confirmed-absence failure has no fabricated cleanup entry or CLEAN case result.

The transition keeps the active case, nonce, capacity, UID/name history and any
previous cleanup seal. It creates no worker-reaped/terminal claim, and every
subsequent transition for that run is refused. A prior completed terminal is
not relabelled or erased. If failure accounting itself cannot complete, the
original refusal and durable facts remain; ACCOUNTING_UNAVAILABLE is not a pass
and does not trigger another append, socket or deletion.

The actual `_State` custody checker brackets fail-only journal I/O with the
original failure-owner checks. New `FailureJournalTests` exercise the data
transactions and refusal matrix. Expanded `ProxyCaseDriverTests` and resource
leaf tests cover driver error propagation, no new network/credential access,
null/known UID accounting, post-absence preservation and custody/write failures.
The driver fixture now uses actual file/store custody checks around its journal
primitive doubles. Its qualification/observer boundaries remain explicitly
leaf-only; none of these tests substitutes for full C6 factory construction.

Six additional `KernelQualificationFactoryTests` use the real C1 factories with
OS doubles for wrong peer role, replaced owner, reused peer descriptor/PID,
changed code bytes and post-I/O deadline loss. All new tests remain UNEXECUTED.
The static preservation audit is not a product test or native qualification.

### C6 factory draft — real startup and zero-resource driver

The new `_NativeServerKernelOS` fixture calls the real `NativeProxyServer()`
constructor. Its shared filesystem/kernel setup does not manually create,
register or populate a server. Qualification binding, self/peer factories,
observer exchanges, journal reservation and driver/cleanup/terminal methods all
remain real. Only OS/libc/SSL-library primitives and inert peer wire data are
simulated. This is neither installed/native evidence nor a real TLS session.

The fixture embeds the exact 9,041-byte public CONF-LIVE-006 packet snapshot with
SHA256 `f95c277cffdfb622f45a1b4b91a5292d9d9a5bfabc8f9388b3899cbb20c5213d`.
It supplies those bytes through the virtual filesystem, alongside the unchanged
campaign data and inert bundle. No META checkout is read during product tests;
the actual constructor digest check and immutable authority constant remain
enabled. Deterministic unsigned DER and an empty non-key exercise the real
credential codec but cannot authenticate to a real server. SSL configuration
calls are checked at the library double, not replaced by a successful product
credential or transport method.

Eight new `NativeServerFactoryTests` cover startup ownership, durable reservation
before the server credential, full startup plus zero-resource driver completion,
forged envelope, packet-byte drift, kernel policy loss, journal custody loss,
zero-resource action denial and lost terminal. Original fd/pidfd, file, code,
SELinux, cgroup/BPF and observer checks stay active in the positive fixture.
Broker replies assert journal synchronization before DISPATCH and cleanup
acknowledgement. No worker or resource-API socket is created by these tests.

Those eight constructor/driver tests are still leaf-integration coverage, not
full HTTP coverage. The shared fixture refactor separates OS setup from leaf
owner construction without changing any predecessor assertion. All added tests
remain UNEXECUTED.

### C6 HTTP/resource draft — actual serve loop, library-level codec only

`_NativeServerHTTPOS` extends the synthetic OS with original accepted sockets,
real `ssl.MemoryBIO` instances and an inert SSL-library codec. Its H/D/C records
are deliberately not TLS records. The actual `_TLS` pump, HTTP parser, certificate
identity parser, server constructor, qualification/observer/broker factories,
admission journal, resource actions and completion logic remain active. All
signatures over unit authority data are verified normally. Deterministic unit
signing seeds, unsigned certificate DER and empty non-keys are not credentials
for a real service. These tests neither install nor contact Linux/Kubernetes.

Twenty-three appended `NativeServerHTTPFactoryTests` cover:

- Ten zero-resource requests and ten original-channel case handoffs, with no API
  credential acquisition or resource socket. No manually seeded RUNNING owner.
- A signed resource-bearing profile through CREATE, GET, UID/resourceVersion
  DELETE and an independent GET404. The original API identity is read once;
  each connection authenticates independently. A DELETE acknowledgement cannot
  substitute for the durable ABSENT row or the subsequent terminal exchange.
- Wrong TLS identity/version/ALPN, wrong request nonce/Host and extra HTTP bytes
  before DISPATCH. Policy loss after accept must prevent even the handshake.
- Zero-resource action denial, policy loss during API identity read or after
  connect, lost CREATE, replacement UID and still-present post-DELETE object.
  Unknown outcomes retain null UID; known ownership is not lost or adopted.
- Lost/mismatched terminal, false PASS receipt, FAIL/UNAVAILABLE propagation,
  cleanup fsync ambiguity, completed-case replay and ambiguous client delivery.
  Bytes offered to a socket are not proof that the client received them.

The tests inspect original FD ownership and close counts, actual durable journal
rows, peer frames and API request bytes. Negative cases must be product refusals
or the deliberately injected OS error; an assertion inside the OS fixture is
not accepted as a successful refusal test. Still-present fixture data is sent
as PRESENT so the real completion owner, not a simulated peer assertion, must
reject the false cleanup/PASS claim.

Static composition review found a production bug: `_BrokerApi` indexed
`addressFamily` in an authenticated envelope endpoint, although that closed
public shape contains only the IP literal. `addressFamily` belongs to the native
qualification projection. The API owner now derives it from the pinned literal;
any supplied private projection must still match. It does not add an envelope
field, change a schema, weaken the canonical-IP restriction or bypass the
existing family-mismatch tests. The full resource case explicitly uses signed
endpoints without the projection field. This correction remains unexecuted.

### C7 source/test map — review input, not completion evidence

All source symbols below are in `src/harness_conformance/live_proxy_server.py`
unless prefixed `admission`, which means `live_mutation_admission.py`. Test
classes are in `tests/live_backend/test_proxy_server.py`, except the journal and
delete-data classes in `test_mutation_admission.py`. Each class expands to its
exact `test_*` identities in the external data-only preservation audit; it is
not a test selector or permission to run a shortened recipe.

| Check | Owning source symbols | Regression groups and independent review focus |
|---|---|---|
| C1 | `_KernelQualification.__init__/check_self/check_peer/close` | `KernelQualificationFactoryTests`, `NativeServerFactoryTests`: actual reader composition, original owner/FD/PID, partial cleanup, code and policy drift; no qualifier-success double |
| C2 | `NativeProxyServer.__init__/serve/_drive_case`; `_Broker.begin` | `NativeServerFactoryTests`, `NativeServerHTTPFactoryTests`, `ProxyCaseDriverTests`: no004 callback/import or worker execution; server-owned admission before dispatch/credentials |
| C3 | `_BrokerEvents._handoff_create`; `_BrokerGetAction`; `_Broker.check_action_ownership`; `_Broker.finish_case` | `BrokerActionHandoffTests`, `BrokerGetActionTests`, `BrokerCaseHandoffTests`, `BrokerCreatePreflightTests`: same transcript/channel/generation/deadline, one pending action, no replay or reused owner |
| C4 | `_BrokerDeleteAction`; `_BrokerAbsence`; `_FailureAccounting`; `admission.delete_request_body/validate_delete_response/validate_absent_status/_absence_record/_failure_cleanup`; `admission._AdmissionLog.record_absence/record_failure` | `BrokerDeleteActionTests`, `BrokerGetActionTests`, `DeleteDataTests`, `AbsenceJournalTests`, `FailureJournalTests`, `ProxyCaseDriverTests`, `NativeServerHTTPFactoryTests`: UID/version preconditions, independent GET absence, ambiguity, retained ownership, no broader/retried deletion |
| C5 | `_receipt_chunks_complete`; `_BrokerCompletion`; `admission._completion_frame/_completion_terminal`; `admission.parse_reservations`; `admission._AdmissionLog.record_completion` | `ReceiptChunkBoundaryTests`, `BrokerCompletionTests`, `CompletionJournalTests`, `BrokerCaseHandoffTests`, `ProxyCaseDriverTests`, `NativeServerHTTPFactoryTests`: strict receipt then durable seal then exact terminal, no false PASS or release on loss/FAIL/UNAVAILABLE |
| C6 | `NativeProxyServer.serve/_drive_case`; `_BrokerApi` | `NativeServerHTTPFactoryTests`: actual HTTP/MemoryBIO/factory composition and denial before subsequent effects in both resource modes; zero runtime qualification claims |

This table is a source-review input. Symbol/test presence, static parsing and a
passing count cannot certify C7. Remaining work is the independent review tied
to the full exact candidate tree, followed by exclusively reserved full isolated
LOCAL, required localhost CI, protected merge and separate LOCAL exact-main.
Preserve all135 paths, all130 immutable out-of-scope files and1277 predecessor
test identities/assertions. No merge or004 work until the full C1-C7 gate closes.

Historical source/publication records below remain historical. Native AMD64,
native ARM64, installation, runtime, assurance and tenant acceptance are still
separate unproven gates. Alpha2 is ONGOING; model-effort transition NOT_DUE.

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

Refusal cleanup uses separately retained original broker, intent and log owners;
replaced references cannot become cleanup callbacks or receive poisoned state.

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

## One-shot CREATED result delivery checkpoint (source-only)

`_Broker.send_create_result()` sends one bounded RESOURCE_RESULT datagram on the
original authenticated broker channel, only after original CREATED accounting
has committed. There is no caller frame, outcome, identity, URL or backend.
The action ID, sequence, previous-frame digest and execution/scope bindings come
from the retained transcript; the object is exactly the validated, recorded
response. The existing BrokerTranscript codec validates a detached proposed
transition before any send. This data copy is not an execution authority.

Original durable history, pending action, owner, API custody, current observation,
broker peer and deadlines are rechecked before and after I/O and publication.
The datagram is attempted only once inside the original two-second control phase.
Short/error/late delivery, lost policy, changed objects or reentrancy closes the
original broker and poisons/holds the original accounting. There is no automatic
resend, reconnect, UID adoption, repair or quota release. Refusal cleanup never
uses substituted result, broker or created-record references as callbacks.

This checkpoint records local send completion, **not broker receipt, distributed
commit or a completed action lifecycle**. The detached proposed transcript is
retained, but the original parser and pending action remain unchanged. Receiving
another event still refuses until the separately guarded transcript-advancement
and connection-retirement step is implemented. No additional API request,
credential read, GET/DELETE, absence/cleanup/terminal evidence or native grant is
added. NativeProxyServer.serve is still not wired to this in-progress driver.

Tests use real result/accounting/codec code with explicit OS/TLS/observer/storage
doubles. All 1,203 predecessor test bodies, 127 baseline files and fixture bytes
remain unchanged; exact full signed LOCAL and localhost CI are required anew.
No source test or successful local send establishes native broker enforcement.

## Guarded CREATE retirement continuation — 2026-09-14

The preceding result-delivery checkpoint `699a00c` passed all eight commands and
1,237 tests, zero skips, in exact signed LOCAL and localhost PR CI. CI run
34763907272 used runner70, which was retired. That is source/CI evidence, not
acceptance of this new continuation or native execution.

`_Broker.retire_create_result()` consumes only its original completed local
CREATED send. It first revalidates the full original pending-action, durable
identity and API-custody chain. It retains an immutable typed data snapshot and
the exact original owners, closes that API through the fixed class method, and
requires successful closure before advancing the original transcript with the
exact already-sent frame. The transcript object is not replaced. Current history,
authority, observer generation, peer and deadline checks surround closure and
advancement; a final guarded phase precedes local completion publication.

Short/ambiguous or failed closure, descriptor reuse, changed owners/data/history,
expiry and reentrancy fail closed. A close error remains the first error while
post-error guards still run. An advanced transcript is never rolled back after a
later guard failure. The original CREATED accounting stays held and poisoned on
failure; no retry, adoption, new credential, network request or journal write is
added. A retained retirement check observes current original authority without
reusing the now-closed API or applying old pending-action guards to retired state.

This is **local retirement, not broker receipt, distributed commit, resource
cleanup or next-action readiness**. Old action owners remain retained; receive
refuses `BROKER_ACTION_HANDOFF_REQUIRED` until their separately guarded handoff
is implemented. GET/exact-UID cleanup, absence/cleanup/terminal handling and the
complete qualifier/factory/server integration remain unfinished. No installation,
native probes, new public contracts or platform acceptance are introduced.

New tests use the real retirement/result/accounting/codec code with explicit
OS/TLS/storage doubles. All 1,237 predecessor test bodies, 127 baseline files and
fixture bytes remain unchanged. Fresh full signed LOCAL and localhost CI are
required; this source document does not self-attest those future results.

The first candidate `e3ea986` ran all 1,273 tests but failed one new test during
cleanup: retirement correctly bypassed an instance-shadowed API close method,
while the later broker cleanup invoked that shadow. The correction makes broker
cleanup type-check the original API owner and use its fixed class close method;
the failing test remains unchanged. The full failed replay is retained externally.
Additional guards/tests pin original socket/TLS references and descriptor metadata
between the last live-API check and closure, without querying a closed descriptor.

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
| Alpha 2 | CONF-LIVE-003 identity-accounting checkpoint | LOCAL_AND_CI_PASS_RECORDED | Headb8c5c10 /1,203 tests/all8; CI34761635544; runner69 retired |
| Alpha 2 | CONF-LIVE-003 CREATED result delivery | IMPLEMENTED_NOT_ACCEPTED | One-shot bound datagram; transcript advancement and retirement remain gated |
| Alpha 2 | CONF-LIVE-003 result-delivery checkpoint | LOCAL_AND_CI_PASS_RECORDED | Head699a00c /1,237 tests/all8; CI34763907272; runner70 retired |
| Alpha 2 | CONF-LIVE-003 local CREATE retirement | IMPLEMENTED_NOT_ACCEPTED | Original API close then exact transcript advancement; next-action handoff remains gated |
| Alpha 2 | CONF-LIVE-003 native inspector / broker / API | ONGOING | Required implementation listed above |
| Alpha 2 | CONF-LIVE-003 required CI | WAITING | Fresh exact-head localhost evidence required; prior failures retained |
| Alpha 2 | CONF-LIVE-003 source completion / merge / exact-main | NOT_RUN | Packet is incomplete; no completion claim |
| Alpha 2 | CONF-LIVE-004 | WAITING | Fixed worker and ten native probes |
| Alpha 2 | CONF-LIVE-005 | WAITING | Reproducible candidates and operator handoff |
| Alpha 2 | CONF-LIVE-006 | WAITING | Trusted campaign integration |
| Alpha 2 | Linux AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed/native qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | No phase promotion |

Model-effort transition: NOT_DUE. Alpha 2 remains open.


## CONF-PERF-006 — exact document-validation candidate

Status: SOURCE_DELTA_ONLY / WAITING_MATCHED_COMPARISON_AND_FULL_ACCEPTANCE.
Authority: MET-PERF-012, accepted META 9b8b30b4c0b718d3aa0083d518f4ff5892c7d715.
Product baseline: 092fcf475c6f3ebd455e3c354cddb7664ea1f900; no draft is a baseline.

Only the document function changes: exact built-in bytes with an exact built-in
int maximum retain all size, canonical, byte-equality and bounded-traversal checks
but return the newly parsed value without the redundant final encode/parse.
The original fallback remains byte-identical. There is no cache, public API,
canonical helper, permission, resource mutation or dependency change.

The original test/doc prefixes and all 132 other files remain exact. Thirty-two
independent regression methods are appended; static expected totals are 1309
overall and 1139 backend, not claims of test execution. The normalized extension
hash below replaces only its one proof-hash assignment with 64 zeroes to avoid a
self-referential digest; all test/helper definitions otherwise remain byte-bound.
Historical source is compared as data only and is never compiled or executed.

Next: freeze both exact commits/trees and full file/toolchain inventories. Run
CONF-BENCH-002 separately in fixed B,C,C,B order, four runs and no retries. Only
complete practical-gain/noise evidence permits the eight-command product LOCAL,
required localhost CI, protected merge and independent LOCAL exact-main gates.
A candidate change invalidates its comparison; it never resets a consumed budget.

Neither this source proof nor a helper benchmark establishes PR18 improvement,
native Linux qualification, artifacts, deployment, runtime or tenant acceptance.
Draft PRs13/14/15/18 remain untouched. Alpha 2 remains open; effort change NOT_DUE.

| Phase | ID | Status | Description |
|---|---|---|---|
| Alpha 2 | MET-PERF-012 | DONE_SOURCE_GATES_RECORDED | Exact META repair authority |
| Alpha 2 | CONF-PERF-006 | SOURCE_CANDIDATE | This three-path repair, acceptance pending |
| Alpha 2 | CONF-BENCH-002 | WAITING_EXACT_CANDIDATE_FREEZE | Separate matched comparison |
| Alpha 2 | CONF-FIX-007 / PR18 | BLOCKED_UNCHANGED | Separate completion-integration authority |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Native probes, packaging and integration |
| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 / 4 | Later roadmap | WAITING | Governed actions and enterprise qualification |

The following closed record is SOURCE_DELTA_ONLY, never execution authority.

<!-- CONF-PERF-006 SOURCE_DELTA_ONLY BEGIN -->
{"acceptance":false,"addedTestIds":["DocumentRepairTests.test_bool_maximum","DocumentRepairTests.test_bytes_subclass","DocumentRepairTests.test_changed_bytes","DocumentRepairTests.test_collection_boundaries","DocumentRepairTests.test_compact_containers","DocumentRepairTests.test_compact_primitives","DocumentRepairTests.test_consumer_history_preserved","DocumentRepairTests.test_container_subclasses","DocumentRepairTests.test_depth_boundaries","DocumentRepairTests.test_detached_input","DocumentRepairTests.test_detached_result","DocumentRepairTests.test_duplicate_members","DocumentRepairTests.test_effectful_maximum","DocumentRepairTests.test_exact_error_contract","DocumentRepairTests.test_exact_owner_regions","DocumentRepairTests.test_final_newline","DocumentRepairTests.test_float_maximum","DocumentRepairTests.test_global_document_bound","DocumentRepairTests.test_integer_bounds","DocumentRepairTests.test_integer_subclass_maximum","DocumentRepairTests.test_invalid_utf8","DocumentRepairTests.test_malformed_json","DocumentRepairTests.test_mutable_buffers","DocumentRepairTests.test_noncanonical_numbers","DocumentRepairTests.test_noncanonical_wire","DocumentRepairTests.test_object_budget_and_encoded_size","DocumentRepairTests.test_ordinary_object_fallback","DocumentRepairTests.test_repeated_bytes","DocumentRepairTests.test_resealed_substitutions","DocumentRepairTests.test_unchanged_inventory","DocumentRepairTests.test_unicode_nfc_and_surrogates","DocumentRepairTests.test_wire_size_precedence"],"allowedPaths":["src/harness_conformance/live_mutation_admission.py","tests/live_backend/test_mutation_admission.py","docs/live-backend/proxy.md"],"baselineCommit":"092fcf475c6f3ebd455e3c354cddb7664ea1f900","baselineFiles":{".github/workflows/verify.yml":{"blob":"48af47e6d1ca5c5198d934c1dd10c3ba947c3192","mode":"100644","sha256":"91090dc69c12837e8b73eb41a868b3afca7dcb34b304c7b409ac716310ddd3a6","size":615},".gitignore":{"blob":"d9d863a13c2bfc70183b59f43ddfa236f7fa7e34","mode":"100644","sha256":"0672c3d34147eb3a4b4aa4298d4d88f647d6d28aa22cffdb705508df11bda33a","size":158},"AGENTS.md":{"blob":"3bef97c6f3d501a0b5528179880053f787147de2","mode":"100644","sha256":"0b8faaf320feae214a47000b924c9a9c717e73e6d220edf1d16f0ff14381e843","size":3064},"CONTRIBUTING.md":{"blob":"21f949ba69f148982b99313a6fc319ed5caf3527","mode":"100644","sha256":"d947eeaf23f47ad60e26bb2e0f236f08a8bd74ca7f8e80d378248ef4477d5964","size":460},"LICENSE":{"blob":"94f474d4d34ef439ac1bb0f1961d5cc9e9096c7e","mode":"100644","sha256":"2d3b806e6fd270f11819d0f797f721747adb0d497760e1b9053b6cd1fae4cf54","size":774},"Makefile":{"blob":"729893b50ddf19f0be9a3024f435af789a283897","mode":"100644","sha256":"bb652db371113bab5d9d8924f0b10b1f85793c0cc84178d447ab1095f4e7b981","size":661},"NOTICE":{"blob":"0c12f4d5afbb8d0b984d4e3b094735be11607cf5","mode":"100644","sha256":"a70fc36aa7b6f295c4a662b6443a0599c4c89e9b6e62feb29763967d79ce382f","size":169},"PORTING.yaml":{"blob":"cdd098dabfe545c4f513a6821d32cb6da17ee047","mode":"100644","sha256":"69af26b731e28920bb4cc5dd25f6d1d1c18aa75308d75517d6a61f214fa238c4","size":253},"README.md":{"blob":"f04615d13827a0412fa15e7f37f2ffea5c9e4a2d","mode":"100644","sha256":"652e3abc12e4cd6d405eb80018a7c29c68d7d3094c2858196d9b83ea7dd566ea","size":1228},"SECURITY.md":{"blob":"5d25e68338f66ca93863af7783affebc252ecc9f","mode":"100644","sha256":"1b5594cb9074fb98aa77768df57aeab45c469b60337ba9662e71367b92aa9cc7","size":555},"campaigns/alpha1/campaign.json":{"blob":"a68dd8467599be5349e9cbfb217a1930867ffc62","mode":"100644","sha256":"17ad9b40b5518e3432c926b5604073fb922df08be38055310dbc851d1a18cef6","size":702},"campaigns/meta/campaign.json":{"blob":"dadfca33c5ed23ceb111cbeae6c5289a364fafe0","mode":"100644","sha256":"22091f996b03eae43f8d00da3ec08c85ad12aef2cbb7d0d4ca8b79df8b705386","size":2341},"campaigns/parity/campaign.json":{"blob":"f5ae7920b55249d1c35a15dd167ce2bf94c8d653","mode":"100644","sha256":"cd2ce011470ffef7dc7a08a4fc994a81f3d2f58899276991e02efb1c431956f4","size":627},"campaigns/platform/linux-baseline/campaign.json":{"blob":"47ccd6bce2df7569eb2a9e2620e918a10e3b4949","mode":"100644","sha256":"3f4da90f48f61e3ee99b002b969eecbffbe60ac65d650abc82cdc6052df9e50e","size":5429},"ci/acceptance_package_contract.py":{"blob":"12e0ca1ddb11d6533ca5e30023c1afb660051c3f","mode":"100644","sha256":"e5872ce6a4af9ead7c1cf130e47ca028fb7dc85b63ef5801abae82151938df6d","size":1753},"ci/build_live_launcher.py":{"blob":"f5e37e0a02494893c4d4db356892a2c3f1dd9585","mode":"100644","sha256":"873dba7a314405a6ff7c446ee4c0333e34c7cc3400c01141f2c8929dc58c35ad","size":2425},"ci/network_canary.py":{"blob":"453da00b448d2514ac7070539444d7c55d19616c","mode":"100644","sha256":"8eb07e2c974fd4a5040869ef0eee43963826dc8b32f7dd93fa18a91931e56500","size":1499},"ci/prefetch.py":{"blob":"b38fb5d15a9cf6df2891c1da368f4db4d505fc04","mode":"100644","sha256":"341e6e102b93e74a0e7b3688ad88faacf4fd23dad2d6100884039d1a207947a1","size":3824},"ci/run_make_target.py":{"blob":"0e05e3879fbd2ad165adf2e7e54c4ec6d08052db","mode":"100644","sha256":"0a0f5c2d6305a1772848ba2e58b8c3d17321de3fe5fdc99377515e09c1138389","size":5807},"ci/run_packet.py":{"blob":"795ef5590e292b3096bddb919c66857a110e7672","mode":"100644","sha256":"397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1","size":8302},"ci/run_packet_argv.py":{"blob":"9b76420194a17a92ccff6fa6e18d2e8c80f31a9f","mode":"100644","sha256":"523bda5db30faba4c027332a40f36c36e1efdb7e5bd39b68045bcdf817f94fdd","size":226},"ci/targets/conf-001.json":{"blob":"9082a2d49ba5dbe0cd8098274c597bee44da9d27","mode":"100644","sha256":"dc2d49619485436c5cf4540b60c5432e847f96433bc60aa3da88577ffa9887b7","size":692},"ci/targets/conf-002.json":{"blob":"ef49a2be8314bb16ee456cff30bce9ced734bf97","mode":"100644","sha256":"0e2d0b28b83567cd5cf8fd46f30a377d255995af4450f4675ae08bf27fd757c1","size":339},"ci/trust/live-runner-root.pub":{"blob":"e10a1ac95a5738f59b78c3f7aa999bed90d800a8","mode":"100644","sha256":"6b22a99cab70c60b7cc345962ae220e32b2dbc89c72b419c79a9c92ec5f6c012","size":82},"ci/verify-live-campaign.py":{"blob":"6d666e9cc402ed99b91cbf170a1ffc11da369922","mode":"100644","sha256":"ed7fa0f9a5d933c257a93f9be9ac5a3321c0b2451aa31e0f698a6053e8f46004","size":630},"ci/verify-offline.sh":{"blob":"6ceda876eb6e83d17c7ba48e962bc55bb81e905d","mode":"100755","sha256":"b058780b727d2e4c7b5f77d3c7f623a7dafdac621c5b505238297e2ea2524c47","size":912},"ci/zero_bill.py":{"blob":"6715ef0f0a9b4a1215ff4fd411a13affd6c4a321","mode":"100644","sha256":"6e9c7f5aa2ea527a1b1d9472bbab164be4ba051f27dae90005695ff3f04cda14","size":2177},"docs/live-backend/linux-boundary.md":{"blob":"2dcef6bcc17285a68f51dd3ff8e7e1a86d53bafd","mode":"100644","sha256":"157a7733b5df9dddc656d086f54e585b1508ef161e6849cdcc54cebc0b1ed7b3","size":1697376},"docs/live-backend/proxy.md":{"blob":"982b64e4d0f91fb98242f3978ab199f24cf40e0f","mode":"100644","sha256":"f21d8b04b1c1c00b4ac6c7de5e5afab532baca4c19ed1b79db9c3d77c59b349b","size":91412},"docs/live-backend/session.md":{"blob":"3261b634fe39c4cd6bac109db10169490388d9d4","mode":"100644","sha256":"41319d8f1a7fa9441fded7efe23c8254929cc5ea15d7d1f59c125e33b29fc767","size":10811},"docs/parity.md":{"blob":"7a6e06eb12db130a3893360e5ef6bcb82d3e207f","mode":"100644","sha256":"70fb8b95ee95eb7219c3b9ed0eea4c00c280ecf93dba6765418fa559d92b8dc4","size":1083},"docs/reports/alpha1-template.md":{"blob":"857b5db337b41b07a1be30b10faa1a674fe3ac26","mode":"100644","sha256":"70f572dc3d3fef6d45e14c93c09352aea9b7bbdad189cc5167e3d57628c933a9","size":2179},"docs/reports/linux-baseline.md":{"blob":"8c20f40e9130f50e4a2e22488ca6f60671c72ba3","mode":"100644","sha256":"99096cc71b49d662cb3c1a71137724eb1748aa633a7a24c8b56fa4b467605919","size":10913},"docs/reports/packet-scalar-repair.md":{"blob":"348af063b6acf6f4c4860e40bfa1b6e8e211a86b","mode":"100644","sha256":"d824ddb953d31f1a20e19951ef743611e1943f5b6b8d6fe4679721d3146e355a","size":6081},"docs/reports/runner-boundary-repair.md":{"blob":"a3484dd5932307bf1cc1cbaab05a4e937841b943","mode":"100644","sha256":"e5700f158b640364f15565cbbea8dee7e86e88c045c8cde07cfaa8fe77a525bf","size":6595},"docs/reports/successor-inventory-repair.md":{"blob":"55c4fbcec0f4412c4efe2143ba739f4fc3efdf33","mode":"100644","sha256":"c930632d1e8674d9516976a5d07d385ac6211ade937fd16b6b875607f8498ab2","size":7131},"fixtures/alpha1/environment-unavailable.json":{"blob":"da2bbfff05610ac26d574a49436d22e508ace7d4","mode":"100644","sha256":"71ae29d6bafffc062dcaa358929cdc5224d29f415b6a3a327714f9013dca345d","size":244},"fixtures/alpha1/journey.json":{"blob":"a1be9b330b42820803b572548d8a57edda7c95c0","mode":"100644","sha256":"0399a95811cafc48c8deae07b45fadb8082b3be99db838da8b09fbddc1614bd8","size":7677},"fixtures/alpha1/overview.json":{"blob":"bafa30410741034579954865f92aaad13c977b9c","mode":"100644","sha256":"c840c2f0c8e3094cdaaa08a10ea57d859d969c24546c3a23107189e63d7b626b","size":12726},"fixtures/environments/meta-complete.json":{"blob":"8fc90838acc3ee792146bd2251592d43882734d8","mode":"100644","sha256":"6ea4589266ff02ea3c42bf86d72ac5bca9c593203bf35177ecb7da4ab2df1cbe","size":225},"fixtures/environments/meta-unavailable.json":{"blob":"acca65615c5f77cbb97cd2abed3b7e210e27330b","mode":"100644","sha256":"3bec392601ed731f34f00dd55c835986b758a501d54a1ac0213d1e85eb8e2838","size":207},"fixtures/live-backend/baseline.json":{"blob":"10df51d5621ae3f4be5771a458750dded949bf2d","mode":"100644","sha256":"c3dd610a748e018c9e015668567fbea9820a050022dc33375912f8f4aaa51a00","size":174441},"fixtures/live-backend/proxy-vectors.json":{"blob":"a3995cedbf8de23950b5fcfb149e981a06519d3a","mode":"100644","sha256":"ba3cff195f1f615fddb98e2db6713c359d8dbd05699cb1710157fe374b27760f","size":500997},"fixtures/live-backend/session-vectors.json":{"blob":"fd86c220345e46ec6cdf3a0bb9923a7b98a8e7de","mode":"100644","sha256":"4999510bbaba2ae4faed7b9afa6d17ba3bbecb733f40f7bf92c69a6d9313a3fd","size":2822},"fixtures/platform/linux-baseline/environment-unavailable.json":{"blob":"e85351d42f4894aebb45d158aba7ce1e0c070d4a","mode":"100644","sha256":"c79b375f07694835f616b51243b92305b96f29088424673457582103078307aa","size":219},"fixtures/platform/linux-baseline/predecessor-inventory.json":{"blob":"46236ffaaedffe326c703a88544e918671f1ede7","mode":"100644","sha256":"f47c088f150ce7c61a14707aad71c634001037fd423eb43ace3acb055be86a58","size":18630},"fixtures/platform/linux-baseline/predecessor-sources.json":{"blob":"4470b6fef50a58f626792abe83caa99fd712baa4","mode":"100644","sha256":"3fb88e3358c25fb65369e73a3decf9fe111797b1f44b2cc1deeabea8c5d8defc","size":23010},"fixtures/platform/linux-baseline/scalar-repair.json":{"blob":"1ce1e8efddb2bba302d93e624a01cf5bbe840a87","mode":"100644","sha256":"0e04f3878efd8196fc33aa47a80ecbf5a48e7df262f08b98030acfd4c565fd06","size":114585},"fixtures/platform/linux-baseline/successor-inventory.json":{"blob":"b99530a2c6df2f32fa1618843103965cc9c03d2d","mode":"100644","sha256":"44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86","size":171701},"parity/adapters/run_parity.py":{"blob":"d3de27cf2f33a1c74d746f12d5fb1cb7c3267e29","mode":"100644","sha256":"650c17312390ec0f4382dad3c9279be0bb50522374c7ec01a079d9a7db8eefac","size":4849},"parity/adapters/validate_registry.py":{"blob":"8f59afa4c1e14d9cd1a2f6ed5bb8942f541c027a","mode":"100644","sha256":"14d00741194d4de4bd3e14adb2829b3612217b9185905220ff8d6c0be39c12d9","size":6185},"parity/registry.yaml":{"blob":"1cad50d5d694df6dfc127b39025518601db54285","mode":"100644","sha256":"0fac00ae1575b5c86996d32f3a9f01a69f6d77743170df1ecf6aff7243569af5","size":5544},"parity/vectors/data-batch-lineage.json":{"blob":"70c82ac4d21e439139f47ae7aa4ee22e22e3d9f0","mode":"100644","sha256":"67c46555d13dd0b48f2e7fe8cbad9f09da7708baf816527f32ea9e96eb264d2d","size":239},"parity/vectors/data-connector-closed-discovery.json":{"blob":"34ec386fff24d08c70ff2ea3594c3830d953d0b0","mode":"100644","sha256":"86279c3564392e353ba8537c2cba9d11f4449fc140a02398a146fd6f73e47de0","size":240},"parity/vectors/data-local-only-no-fallback.json":{"blob":"d1e3f2a65cc5aa39244e2f1511aa8eca21541c81","mode":"100644","sha256":"fe3698e550940e90f71d497d0e0024ad99dbc8026684e77ebecb666b1577904f","size":207},"parity/vectors/model-route-fail-closed.json":{"blob":"3168f7be8c41152efe67924537d953a697002a56","mode":"100644","sha256":"6eb0342fea804721e30ed38657d44c1578d20b4f829b76a3215df635f504a5de","size":198},"parity/vectors/model-upstream-bounded-retry.json":{"blob":"be842691179449079ecb52c87fbcea7b8f4305df","mode":"100644","sha256":"f0a3cdf305e1f63f0edd05e074373cf6f98f09063bed101a100a74b3b920e854","size":192},"parity/vectors/model-usage-tenant-neutral.json":{"blob":"b596b1dc64bb2dca2128c9be1d7f74d65c19d06f","mode":"100644","sha256":"410f55e3e3453a19754c52cecb689349aba41a95b015aceca7d35ff2e4f9f1ce","size":299},"parity/vectors/white-goods-foundation-boundary.json":{"blob":"1265779205f37c842941abb201b8bf253f6f128f","mode":"100644","sha256":"49f3a5a70f32c00cebc69594832300939942dc6b80f8a57d60f2c577e728ac2d","size":277},"pyproject.toml":{"blob":"4b42959660c2d19e0190b5e5f885f826d84264e3","mode":"100644","sha256":"4180e069f0bfb7b38f99b367f9a6f29e914a61717bd0797343f3d2b99720409c","size":500},"schemas/v1alpha1/campaign-release.schema.json":{"blob":"310a5b6506656a547bacdd071a44a481654749fa","mode":"100644","sha256":"50053c212b0e9a40dcf4e7dd4c155c8c3da6a81a77a82ae7f59aadc2d6d0cfa9","size":1189},"schemas/v1alpha1/campaign-report.schema.json":{"blob":"3726b8f1298f85c5482ec5cf28a9d69512bd418b","mode":"100644","sha256":"3e775c55dbc5dff84fb5aab90525814ef03595a69583e8239640583cac7036a9","size":1073},"schemas/v1alpha1/conformance-campaign.schema.json":{"blob":"a9102ed14316481f18bc0936493b56cd469eaafe","mode":"100644","sha256":"dd4fb4f5fda756613d5f69056460abdbd05b675dbddb4c9606bc9324321bb89f","size":10324},"schemas/v1alpha1/conformance-trust-bundle.schema.json":{"blob":"25e5054c6fe449249419c76fded16a482bb339ba","mode":"100644","sha256":"587e9e4fcc48fa98cf316b73a3cccabd9713fa0cbae48067f5f43f181404c245","size":1151},"schemas/v1alpha1/control-result.schema.json":{"blob":"fcccd2c59e23ee4cdd003d09afe14cd6e8068eae","mode":"100644","sha256":"2113a19ec9e077dcb7ab6f2c299c4756d09b0d1e3d3a32195d2103ff8d54e182","size":1056},"schemas/v1alpha1/environment-intake.schema.json":{"blob":"b303695d6f954b95e218726db6d0fac6e519c8fd","mode":"100644","sha256":"b69ef4bda6fe209b0416ef1c250747a38179d4cef0cf9bc8c72b1f0de1e3d621","size":776},"schemas/v1alpha1/linux-readiness-evidence.schema.json":{"blob":"7032d8ada2da1ab7bc46f329505656b9b98562de","mode":"100644","sha256":"8f4cf17273b097e39420b2394be43259c9bea30b684a58bcdc739c60b5059c0e","size":61742},"schemas/v1alpha1/live-backend-session.schema.json":{"blob":"ac9fee798700c8f558674132897bc306293d802a","mode":"100644","sha256":"7c4ad7c69feb4e9e9f8509f2cdd6c1bcccbf8acb60711810c2e0df8ef7cb737d","size":2504},"schemas/v1alpha1/live-campaign-execution-envelope.schema.json":{"blob":"0276cd0438895d8874ea076262a6bb9071bfd3c5","mode":"100644","sha256":"d4720d28fd0cfb8f4979f8d1bb808c5244c6e8121c4a97b0303cfed033c4d1fd","size":4272},"schemas/v1alpha1/live-capacity-authorization.schema.json":{"blob":"4902a75d338b4242cf54642bc005b90cd40513a9","mode":"100644","sha256":"196cafdba0cc168b8dbab7cb02aeda003b1b0cb2f0ae8e9b233b883629949235","size":2177},"schemas/v1alpha1/technical-evidence-bundle.schema.json":{"blob":"8c66a359cd84085b4729cf8bae263bb523494cec","mode":"100644","sha256":"0d1e7ad8413733c63b18bb0b658a93f541800c604b2f56c8842fe4ac7760d513","size":1524},"schemas/v1alpha1/tenant-acceptance-candidate.schema.json":{"blob":"69c535c74b5dc71454fac60c066ac03c785ef75f","mode":"100644","sha256":"37c57329bb835d7aa091be9de41bcfaed9305b1e0359ec1289d114f31bbf426a","size":995},"src/harness_conformance/__init__.py":{"blob":"7d8e8ae786e942135fae50701e31ac25d700869e","mode":"100644","sha256":"748cd4a32689b1856ef53f51793e3f85303a25658846bb9a6965440ceeed769f","size":236},"src/harness_conformance/__main__.py":{"blob":"eb53e2f31b2f703ad32ef64b8a41faa3e7d18e08","mode":"100644","sha256":"935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d","size":48},"src/harness_conformance/acceptance.py":{"blob":"85fba5611d427772e8f0a4a71aaed3f13824b8cb","mode":"100644","sha256":"81a562a983f1d662e78d95d7e3e29f070471b3e304c13bac5162e0b05108c933","size":2613},"src/harness_conformance/build_backend.py":{"blob":"779090a50431f086f497e26319de9265d664666c","mode":"100644","sha256":"d7ed81b4e0ffd865093679ef51a033a7bc74024b20300b098520306a05243e99","size":2399},"src/harness_conformance/campaign.py":{"blob":"c07495f1c0df2532a2e37bd80d01f93b9a027b04","mode":"100644","sha256":"da0a25fba8336f658948ab1018a9db5c518bcc52849bdfcf295058906a26272a","size":7026},"src/harness_conformance/canonical.py":{"blob":"18ab1dd28aeea326c177748aa357e85d56df0086","mode":"100644","sha256":"eb16aee5dda8f512b78b637361f0a057c7e944cd1b9eb888c88182c867e7794d","size":5645},"src/harness_conformance/cli.py":{"blob":"f78f09f9845fd187107d45c3b2ddeb859702b848","mode":"100644","sha256":"c6fe0356d835db4bb0ae43d2484ca107f32bbf9046ff04c1a5a5ab47703ce8c1","size":4482},"src/harness_conformance/crypto.py":{"blob":"19e4c49aa220147e9f1294b5895b9b5a5b84abba","mode":"100644","sha256":"bf4cd892d5a7b0dd38bf38b88f72657821d7f21575fce450e60a5a13950c0ca9","size":5148},"src/harness_conformance/errors.py":{"blob":"3c78aa2fd3f372fa45df8eba47c1958e70376ea8","mode":"100644","sha256":"c30216c02cfa449063b77ca922a3c7cd32e0c6a8010365e093d730e7bc37807a","size":308},"src/harness_conformance/events.py":{"blob":"c5294e469638af15d9616a08594c99b3ca48ecd2","mode":"100644","sha256":"2cc8855e5fe02c9874e3653b5f094b4095eed483e2446ba32735ddc57c6b422a","size":2197},"src/harness_conformance/evidence.py":{"blob":"cb5ac52a8cdab8f23cc3dee05d063c0eedada7cc","mode":"100644","sha256":"670a8c4f6b06caf8af7749b0fe5bf6210d746cd6a823430a387890add135b3e6","size":7683},"src/harness_conformance/lifecycle.py":{"blob":"0e3874da1b086941ec6319386ecb379238e25f42","mode":"100644","sha256":"86c7f62bea77d963e087d2b244f8479a5a81bd1dac8ab5ec5579ad9b0a35f69c","size":1582},"src/harness_conformance/linux_readiness.py":{"blob":"f0be4c7607bf66d993fe712bb6f2062787632d6c","mode":"100644","sha256":"1d40b52a05a85cf0d2179d5545bc8325b8035a24340c5a52b8b66f28e0476fc8","size":22629},"src/harness_conformance/live.py":{"blob":"cf510b0a5e9623e21a431c9b061c26311035ce38","mode":"100644","sha256":"8f6d033292801930cd280f3611aed3c6012cf4d39ec63d4324eb92590e44a022","size":23002},"src/harness_conformance/live_backend_authority.py":{"blob":"ecac59b706d8d8f0ec37c844d2fb91162d5adf16","mode":"100644","sha256":"b57f241e1c0c76be3d86682e9a1a1d62f40115aaa917d2e124d589c84880e42d","size":9916},"src/harness_conformance/live_launcher.py":{"blob":"ad7ebd930586d383ce2b947a9c433c73f9b5baf6","mode":"100644","sha256":"0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27","size":5281},"src/harness_conformance/live_linux_boundary.py":{"blob":"349ccc21d9d861461863bfabec362d2fe197badc","mode":"100644","sha256":"7c590b4078e4bd024c0798749f5d1e1197f9a30c15cc6d1a2b0d7b9131ae54fe","size":52544},"src/harness_conformance/live_mutation_admission.py":{"blob":"eabfd4de3ef683a315786644cf581ba505821cc6","mode":"100644","sha256":"b3a92d485716fb5df6b01273a0d0e4277813b052ce6720e7a90c27db29faea23","size":137925},"src/harness_conformance/live_proxy_client.py":{"blob":"2eafd20ef33ff86ac5833eefdf9d77ec5a9b5658","mode":"100644","sha256":"f82bf0fe70c3782db1cec798b3d4a3fe2b36be68e4ae9ffe56b6e600895b24ff","size":18956},"src/harness_conformance/live_proxy_server.py":{"blob":"2e18f80967bd188341b3a94f658e2cc0bc1b956c","mode":"100644","sha256":"ee5435b63d9dc515992cde29c7dd3cd0aeddd81de7b9c865643a8b8d3ffd5ae9","size":269008},"src/harness_conformance/live_replay_store.py":{"blob":"84b054eab30e318552866076e5291dca842734d1","mode":"100644","sha256":"ff512b35ce7761b5dccc2c57989a6888b0daa9c99fba404f7be0be6878dae3f7","size":10076},"src/harness_conformance/live_session.py":{"blob":"6a22fd233cfd52c357d03dfd60dc8cc1d563a1cc","mode":"100644","sha256":"dc15ebe6d919093cb1842c77c19c9e7846d7ef62e3b04946114824befa9e4454","size":12361},"src/harness_conformance/live_supervisor.py":{"blob":"dd02d0e0c87044e3568f8521cb74d9fb14ea3c6f","mode":"100644","sha256":"4dfeb1780c5fc6b2e116f027fbbde6b8a0fec401911f11c4f45900e7ad84b03e","size":38977},"src/harness_conformance/models.py":{"blob":"e2e1d24ec4822b86d10efb8c864281a81730518b","mode":"100644","sha256":"3d095046632c640bd679b730cc76c90276a73c18263de227ad8a5692c34730dc","size":1430},"src/harness_conformance/registry.py":{"blob":"539cfbb0f1177dd9614f83e333e2a342a97fabf1","mode":"100644","sha256":"fa32c26a773a93d60c3f1cd512a99d1213258f944846e028bf7c92aca7049139","size":1595},"src/harness_conformance/schema.py":{"blob":"51e9e4a9e38278771979bc89e612a0371312f4dc","mode":"100644","sha256":"cd3fefc33833cf5fbccb97a0ac75524ecd967cfa10064a79f64a837f75397ee5","size":9908},"tests/alpha1/__init__.py":{"blob":"68a01f42298a8f26633b2142b6a0005197345c61","mode":"100644","sha256":"1c4b4913127e929661e104454b7900591e39681401eb19594436b1a860c49a6a","size":48},"tests/alpha1/contract.py":{"blob":"cab06a287c4bb3af9b46d6aad540463494572429","mode":"100644","sha256":"20034c14d493cac5f730440b27833c5fa87722fda0a1574ce0f81836764749a7","size":16927},"tests/alpha1/test_alpha1.py":{"blob":"27d0f87d11dd4db53c9b2ac0e96ff8c8e8ce08b7","mode":"100644","sha256":"b528290f311a5e41e2b163028bb5212a022d15319a7a9fb218fd7e272480e9c7","size":7371},"tests/fixes/runner_boundary/_inventory.py":{"blob":"fdf58c985872348225fcf9706890349dcceb8a2c","mode":"100644","sha256":"fb50aba04fe963a89b74ad1aca57b1242fa54481e01989ac18a189a080ade94c","size":2443},"tests/fixes/runner_boundary/legacy-tests.json":{"blob":"f0fd3094ae447ae25840d8a13d29d89fdaecbd26","mode":"100644","sha256":"9fff3fb6bd66789b18bc8f38885d2bfd287124f9a32b4f7a0d645c27ee500dbd","size":4603},"tests/fixes/runner_boundary/test_boundaries.py":{"blob":"ee6aaffe5e7a8b067f5051208f9fb7080f192400","mode":"100644","sha256":"2e33efe165cf46912a426285dabd0bbe98b17acdf18f3d7a8bf3cb56a71247e4","size":15192},"tests/fixes/runner_boundary/test_inventory.py":{"blob":"b32df3cf7b119502baa187661589145446fe317b","mode":"100644","sha256":"1fbacb25aea922a37fb552e91f6b95dded7c1774d1ba2a80f5989cd926cad5e6","size":3569},"tests/live_backend/_fixtures.py":{"blob":"c304516fcc8700038748a535280f607dde9026ac","mode":"100644","sha256":"edec764c067e538fa9709dc7dce59a357ae996ba36c6121482cc3b24d86b8a28","size":3383},"tests/live_backend/_inventory.py":{"blob":"47d5306bd5f6376618aa3418b09f3a79d6dfd76f","mode":"100644","sha256":"d341edcdf49dadf182c3fcc9926d373d13c83aa004d3cc74363312861a7f1e46","size":4839},"tests/live_backend/test_inventory.py":{"blob":"aaa7c95f79868172637bb95a4118dff083cd573f","mode":"100644","sha256":"f128f05fc395c26de0c13c34953bfff297fa64f857f3f70aab56dbc9e3bcc8a1","size":10197},"tests/live_backend/test_linux_boundary.py":{"blob":"012da5892daafbb7c92c09944d9f97a5e180fffa","mode":"100644","sha256":"06d16e4c833dc818a084b655b4f767dbe601212adc9525c47dc94241c32ee238","size":62720},"tests/live_backend/test_mutation_admission.py":{"blob":"335b915e5cadcb91c064b0f2522fa6343211823d","mode":"100644","sha256":"b3bce862631f82dedb67928b7c81ca4cc2cf03fc78111d77b814cc549a7e4be1","size":36648},"tests/live_backend/test_proxy_client.py":{"blob":"c8d5832c55f1edd80dde8ffb3be2f1e5d1ed3f92","mode":"100644","sha256":"90399c359d8e97fa526597b8097b5d73bf052e02f48b3fa6fad6db5453729227","size":21302},"tests/live_backend/test_proxy_server.py":{"blob":"631a6af49cd05e9fbb4ccde416433c886af6995a","mode":"100644","sha256":"05e715db5e27b4560dc397ad15f4522490a9122e8efd0daa52563db1cd8f4a3c","size":498101},"tests/live_backend/test_replay_store.py":{"blob":"c905fc0bf1775c1a01c15e068c0a8ae5cc7f387a","mode":"100644","sha256":"492d6569edb1d271199a3d52b93e82f7295ae478d90b01376125313ee1af8213","size":9971},"tests/live_backend/test_session.py":{"blob":"5970c237d3d60f5cbfa33ace88e7d37b0e885f34","mode":"100644","sha256":"4348b898c1d8cab9fbc94b7bfceff5442a21c0e49fc2645277ae706506c25e90","size":32978},"tests/live_backend/test_supervisor.py":{"blob":"3e47b206e625fbf153f9978d23e014feae0d3e5a","mode":"100644","sha256":"2c6fc822b453e57f0354e2a6876b016ea9d536216e77b2390f1026befaef7db1","size":295260},"tests/meta/test_build_cli.py":{"blob":"7b71afb1541acc77c25af4edd83e42807e9bad99","mode":"100644","sha256":"989c58c63a8cc5234e0396c4bee1c667da133c6893ca24dd96bd95822f43a4e6","size":2781},"tests/meta/test_campaign.py":{"blob":"01bbbfb3a347dc97562597744c3940e11cd67185","mode":"100644","sha256":"85fc9c47556fa0db78ed1948cba696cea0da9d895848169785d227a6e66efc8d","size":3007},"tests/meta/test_canonical_schema.py":{"blob":"e9f4e4ebab1d8ad8c4cbccd21f6f64684548faf1","mode":"100644","sha256":"f3c233226c5dc400f225eeb16bde754fd73b3e332a2cc85c7795571537845a35","size":3187},"tests/meta/test_evidence_crypto.py":{"blob":"deb7af4af91219aa7a688e67bd66cfb856897ed7","mode":"100644","sha256":"b0b87f6e4f726ebc7af82be7ab9b6b83a73ec130e1559cb5d9800396b91436c4","size":4501},"tests/meta/test_live.py":{"blob":"cd6f7ea911bd1fe55132723f30f9924b2dcdb63b","mode":"100644","sha256":"9ac39858b40468a10b2a20ae43e0aaa92f64fde6ab63d275143d654774ec10a3","size":11715},"tests/meta/test_porting_zero_bill.py":{"blob":"eef6f33647b7ef061616939b1f8c5a03472e9aee","mode":"100644","sha256":"f8ed0fdffc245541d332d78c66d6e9045c3bfc85e0683c3cb7e87b263c1bd448","size":4182},"tests/meta/test_registry_dispatch.py":{"blob":"c6283b1028a659c3d1ef48863280eb1c9a6349f8","mode":"100644","sha256":"b021ddeb2a7a534427edf7db594b0d9532711bec4fcfac76405dcded73adbc1d","size":3756},"tests/parity/test_adapters.py":{"blob":"bac9d9424411a7441f721f31c10b6e92992f67d9","mode":"100644","sha256":"9e4217daee3c0e6f5f7dc0a292c4ff55cb1a3b7259b477ee65dfc13315e49c4a","size":2337},"tests/parity/test_packet_runner.py":{"blob":"756551e665a844d2dcec790becb31a82c4a82cfd","mode":"100644","sha256":"0054ccd9312c59a77194a17152191a80bc82d98a5b27ee6e83183b2e62bf7d97","size":6066},"tests/parity/test_registry.py":{"blob":"50e8fc23c9bbf139b0eed861817977157316c03a","mode":"100644","sha256":"88d007d59c2da7dc45fdb4da0d7787725ff6a4d6d120a7f38d843a94baf2b5ff","size":2638},"tests/platform/linux_baseline/_fixtures.py":{"blob":"d1d152fffec06019d0501a982d2108e1e06eff06","mode":"100644","sha256":"579ff77d11e66776884ccf4a3343c417393767215b09abc5aacc1a19c10bcb7d","size":11573},"tests/platform/linux_baseline/_successor_inventory.py":{"blob":"f5185d45b614809bdf3050b16c587b53bad56b1f","mode":"100644","sha256":"0ab36ab0055b72d25dced1d0339a1dbacfafe29ea450b2935c171912405ea733","size":63700},"tests/platform/linux_baseline/test_linux_campaign.py":{"blob":"d14aa009675231ef49fbac95c9bcd9559a61e0f1","mode":"100644","sha256":"e4501ef5df6a3a1e9f3755aee40592f81ccdcab069d187215f612b97f9773094","size":8618},"tests/platform/linux_baseline/test_linux_evidence.py":{"blob":"85d3983ddf743dd5ed4bde41e81063bc6b32d525","mode":"100644","sha256":"b6e162808c471d3d2ed7caa2ed2c056af33819d91ae46a66ff5298da982912b3","size":14548},"tests/platform/linux_baseline/test_linux_inventory.py":{"blob":"8e7e0809c52bd73cd2621770913a21434765353c","mode":"100644","sha256":"3fdd36f47cfb3deb7edaab8685dbead5c90519a92844b5bc2266441d5160c338","size":5683},"tests/platform/linux_baseline/test_linux_protocol.py":{"blob":"3f09672575ac51b8d979431adf058f11941b63df","mode":"100644","sha256":"2057b427ba366717c506d561978695e27b53208b4e3fbf318b00671fe672254d","size":8232},"tests/platform/linux_baseline/test_packet_scalars.py":{"blob":"60e666600661fe45cb8b44b2753a6d31a82568c2","mode":"100644","sha256":"c2ce177f7a462abcae70ae5c51cc2c50d1a3041dc7b9afa527a2e0c582932fe9","size":27287},"tests/platform/linux_baseline/test_successor_inventory.py":{"blob":"81aca1c5b694532850387a492f3224acfa97f5f2","mode":"100644","sha256":"46417d8566acedf4c60e396dfe27dcd94743e288eda9f1aeea2db5c27efd0b9e","size":21048},"toolchain.lock":{"blob":"1a9f18620f9d55bb5308b5a817ae671cf07a7246","mode":"100644","sha256":"40a0cbb9fc244a8484b22494b6bfa070fbc76aec0edd86ab690026f6a8027bfc","size":2153},"uv.lock":{"blob":"c9043e59c92f5861c567a815a866257459b1b409","mode":"100644","sha256":"bd9cb528f2c6ad6a74e3dc1998978e029144fcee2535387cc5ef3db7907dcfbc","size":150}},"baselineTestIds":{"tests/alpha1/test_alpha1.py":["Alpha1CampaignTests.test_campaign_and_evidence_are_reproducible","Alpha1CampaignTests.test_offline_campaign_is_honestly_unavailable","Alpha1CampaignTests.test_report_template_preserves_authority_boundaries","Alpha1ContractTests.test_complete_journey_and_overview_are_closed","Alpha1ContractTests.test_fixture_has_no_public_request_or_secret_material","Alpha1ContractTests.test_fixture_reads_and_canonical_outputs_are_deterministic","Alpha1ContractTests.test_journey_mutations_fail_closed","Alpha1ContractTests.test_navigation_and_evidence_axes_are_complete","Alpha1ContractTests.test_overview_mutations_fail_closed"],"tests/fixes/runner_boundary/test_boundaries.py":["CanaryTests.test_absent_unknown_mismatched_marker_never_opens_socket","CanaryTests.test_backend_specific_permission_denials_pass","CanaryTests.test_route_dns_timeout_and_unsupported_family_are_not_isolation","CanaryTests.test_successful_socket_or_connect_is_not_isolation","CanaryTests.test_wrong_stage_permission_denials_fail","RetiredLiveTests.test_adapter_has_no_execution_or_io_imports","RetiredLiveTests.test_arbitrary_argv_invalid_descriptor_and_removed_ci_are_refused","RetiredLiveTests.test_caller_created_pipe_file_and_memfd_magic_are_not_authority","RunnerBoundaryTests.test_backend_os_mismatch_unknown_missing_or_warm_marker_stops_before_io","RunnerBoundaryTests.test_both_os_backends_keep_order_digest_rechecks_and_short_circuit","RunnerBoundaryTests.test_bridge_delegates_exact_argv_without_another_process","RunnerBoundaryTests.test_closed_child_environment_uses_only_local_source_imports","RunnerBoundaryTests.test_content_change_even_with_fixed_metadata_is_detected","RunnerBoundaryTests.test_packet_custody_refuses_user_file_symlink_hardlink_and_fifo","RunnerBoundaryTests.test_real_wrapper_rejects_missing_unknown_and_wrong_os_backend","RunnerBoundaryTests.test_wrapper_binds_os_and_executes_only_the_fixed_bridge"],"tests/fixes/runner_boundary/test_inventory.py":["InventoryTests.test_added_file_is_collected_without_manual_registration","InventoryTests.test_all_four_suites_collect_every_module_and_keep_legacy_cases","InventoryTests.test_empty_or_import_broken_module_fails","InventoryTests.test_load_tests_cannot_hide_or_duplicate_a_case","InventoryTests.test_missing_or_empty_root_fails","InventoryTests.test_nested_unimportable_new_file_cannot_be_silently_omitted","InventoryTests.test_skipped_or_expected_failure_cannot_hide_a_case"],"tests/live_backend/test_inventory.py":["BackendInventoryTests.test_all_110_accepted_files_are_fixed_with_only_closed_final_hook_proof","BackendInventoryTests.test_all_four_accepted_correction_additions_are_hash_bound","BackendInventoryTests.test_all_six_roots_ast_equal_actual_and_all_170_predecessors_preserved","BackendInventoryTests.test_authority_source_and_model_release_are_exact_nonexecuting_pins","BackendInventoryTests.test_baseline_tampering_and_duplicate_members_refuse","BackendInventoryTests.test_inventory_rejects_empty_duplicate_hidden_and_non_test_method","BackendInventoryTests.test_inventory_rejects_skip_and_expected_failure_and_namespace_omission","BackendInventoryTests.test_inventory_roots_with_colliding_module_names_remain_independent","BackendInventoryTests.test_linked_root_ancestor_and_hardlinked_test_are_rejected","BackendInventoryTests.test_new_runtime_modules_have_no_io_signing_or_legacy_verifier_substitution","BackendInventoryTests.test_original_103_120_and_scalar_106_150_histories_remain_separate","BackendInventoryTests.test_presence_of_integration_file_never_exempts_launcher","BackendInventoryTests.test_tracked_inventory_has_only_complete_ordered_packet_stages"],"tests/live_backend/test_linux_boundary.py":["CredentialBoundaryTests.test_credential_wrong_mode_symlink_hardlink_size_and_metadata_refuse","CredentialBoundaryTests.test_direct_constructor_caller_path_and_foreign_hook_are_not_authority","CredentialBoundaryTests.test_missing_policy_or_fixed_module_identity_opens_no_credential","CredentialBoundaryTests.test_partial_acquisition_exhaustion_and_write_failure_release_all","CredentialBoundaryTests.test_retained_credential_and_ancestry_mutation_refuse_without_reopening","CredentialBoundaryTests.test_temporary_socket_and_sealed_memfd_close_before_receipt","CredentialBoundaryTests.test_two_operations_retain_one_credential_without_unsealing_authority","LinuxBoundaryTests.test_all_network_families_dns_and_metadata_have_no_direct_socket_grant","LinuxBoundaryTests.test_all_received_descriptors_are_closed_even_after_malformed_ancillary","LinuxBoundaryTests.test_ambient_environment_credentials_proxy_and_import_paths_are_rejected","LinuxBoundaryTests.test_ambient_extra_fd_or_socket_stdio_refuse_but_closed_listdir_fd_is_ignored","LinuxBoundaryTests.test_bpf_abi_x32_and_unknown_architecture_fail_closed","LinuxBoundaryTests.test_cgroup_attach_ambiguity_retains_cleanup_ownership","LinuxBoundaryTests.test_cgroup_filesystem_magic_is_checked_by_fixed_native_abi","LinuxBoundaryTests.test_cgroup_kernel_files_require_root_nonwritable_custody","LinuxBoundaryTests.test_cgroup_kill_reaps_direct_and_adopted_double_fork_children","LinuxBoundaryTests.test_cgroup_nonempty_or_unreaped_tree_never_certifies_cleanup","LinuxBoundaryTests.test_every_reviewed_unsafe_syscall_is_denied_on_both_abis","LinuxBoundaryTests.test_fixed_native_struct_layouts_are_64_bit_without_syscall_execution","LinuxBoundaryTests.test_kernel_peer_pid_reuse_and_every_scope_identity_change_refuse","LinuxBoundaryTests.test_namespace_clone_escape_and_clone3_are_denied_but_plain_fork_is_contained","LinuxBoundaryTests.test_native_constructor_refuses_workstation_and_injection_before_libc","LinuxBoundaryTests.test_noncanonical_custody_paths_refuse_before_open","LinuxBoundaryTests.test_only_one_exact_kernel_credential_message_is_accepted","LinuxBoundaryTests.test_owned_file_and_kit_use_single_read_content_and_exact_digest","LinuxBoundaryTests.test_owned_file_read_rejects_hardlink_and_writable_file","LinuxBoundaryTests.test_root_and_ci_flags_cannot_replace_installed_module_custody","LinuxBoundaryTests.test_root_manifest_bytes_are_read_once_verified_and_retained_not_path_reopened","LinuxBoundaryTests.test_self_consistent_privileged_unisolated_peer_still_refuses","LinuxBoundaryTests.test_symlink_hardlink_write_mode_and_extra_file_kit_tampering_refuse","LinuxBoundaryTests.test_unit_boundary_all_steps_ordered_and_each_failure_stops","RetainedBoundaryTests.test_ambient_unknown_descriptor_and_forked_registry_never_authorize","RetainedBoundaryTests.test_close_error_attempts_all_handles_once_and_invalidates_first","RetainedBoundaryTests.test_closed_recycled_descriptor_is_never_closed_as_new_authority","RetainedBoundaryTests.test_each_retained_file_and_ancestor_substitution_is_detected","RetainedBoundaryTests.test_every_custody_metadata_field_is_rechecked","RetainedBoundaryTests.test_fixed_identity_read_once_and_cached_digest_cannot_replace_registry","RetainedBoundaryTests.test_kit_rootfs_is_borrowed_once_and_signed_bytes_are_immutable","RetainedBoundaryTests.test_native_constructor_exhaustion_or_bad_installed_read_closes_every_handle"],"tests/live_backend/test_mutation_admission.py":["ProxyAdmissionTests.test_approved_profile_and_all_30_adversarial_vectors","ProxyAdmissionTests.test_binding_requires_disjoint_complete_case_resource_ownership","ProxyAdmissionTests.test_both_complete_broker_transcripts_are_non_authorizing_data","ProxyAdmissionTests.test_each_frame_wrong_direction_and_replay_refused","ProxyAdmissionTests.test_every_broker_binding_field_substitution_poisoned","ProxyAdmissionTests.test_exact_builtin_canonical_bounds_and_duplicates","ProxyAdmissionTests.test_no_alias_to_caller_profile","ProxyAdmissionTests.test_noncanonical_or_oversize_base64_and_chunk_order","ProxyAdmissionTests.test_observer_positive_and_all_27_negative_vectors","ProxyAdmissionTests.test_postmutation_object_requires_exact_uid_version_and_signed_manifest","ProxyAdmissionTests.test_receipt_not_exposed_before_terminal","ProxyAdmissionTests.test_remaining_unknown_uid_cannot_be_claimed_clean_or_deleted","ProxyAdmissionTests.test_returned_frames_do_not_alias_retained_actions_cleanup_or_terminal","ProxyAdmissionTests.test_terminal_requires_actual_chunk_digest_size_cleanup_and_reaped","ProxyAdmissionTests.test_zero_and_resource_profiles_have_exact_integer_reservation_units","ProxyReservationTests.test_concurrent_journal_owner_never_writes","ProxyReservationTests.test_each_ambiguous_write_sync_or_readback_poisoned_without_retry","ProxyReservationTests.test_history_corruption_torn_tail_and_foreign_binding_do_not_repair","ProxyReservationTests.test_other_run_capacity_held_until_all_ten_distinct_clean_operations","ProxyReservationTests.test_whole_run_reservation_is_durable_before_return","ResourceJournalTests.test_action_is_closed_create_only_and_bounded_exact_integer","ResourceJournalTests.test_all_reservation_binding_substitutions_refused","ResourceJournalTests.test_broker_binding_requires_exact_disjoint_complete_resource_sets","ResourceJournalTests.test_clean_receipt_cannot_erase_unresolved_intent_or_created_uid","ResourceJournalTests.test_cleanup_cannot_omit_substitute_or_invent_owned_resources","ResourceJournalTests.test_concurrent_owner_cannot_append_intent","ResourceJournalTests.test_created_identity_cannot_be_overwritten_or_recorded_twice","ResourceJournalTests.test_created_must_match_original_action_id","ResourceJournalTests.test_created_without_intent_cannot_adopt_existing_object","ResourceJournalTests.test_created_write_faults_preserve_intent_without_retry","ResourceJournalTests.test_input_mutation_after_commit_cannot_rewrite_durable_identity","ResourceJournalTests.test_intent_fsync_readback_before_return_and_null_identity","ResourceJournalTests.test_intent_write_sync_readback_faults_poison_and_never_retry","ResourceJournalTests.test_invalid_or_substituted_profile_cannot_write","ResourceJournalTests.test_known_uid_pending_receipt_retains_version_and_capacity","ResourceJournalTests.test_lost_response_pending_receipt_retains_exact_name_and_null_uid","ResourceJournalTests.test_no_resource_rows_after_cleanup_record_even_if_pending","ResourceJournalTests.test_observed_object_is_required_only_for_created","ResourceJournalTests.test_observed_uid_version_persist_only_after_validated_intent","ResourceJournalTests.test_parser_bounds_total_resources_and_prevents_action_or_manifest_reuse","ResourceJournalTests.test_parser_refuses_intent_with_guessed_uid_or_resource_version","ResourceJournalTests.test_parser_refuses_uid_reuse_between_distinct_created_resources","ResourceJournalTests.test_parser_rejects_cross_binding_time_chain_scope_and_nonnull_cleanup","ResourceJournalTests.test_parser_rejects_unknown_fields_noncanonical_torn_and_nondict_rows","ResourceJournalTests.test_parser_validates_created_uid_and_version_not_just_writer","ResourceJournalTests.test_post_defaulting_substitution_and_missing_identity_preserve_null_intent","ResourceJournalTests.test_replayed_resource_scope_is_closed_and_bounded","ResourceJournalTests.test_requires_existing_exact_running_reservation","ResourceJournalTests.test_returned_state_is_detached_and_restart_does_not_adopt","ResourceJournalTests.test_second_create_cannot_reuse_name_even_with_new_action_id","ResourceJournalTests.test_stale_history_and_nonbytes_history_never_append","ResourceJournalTests.test_transaction_exit_failure_is_ambiguous_even_after_readback","ResourceJournalTests.test_unknown_manifest_digest_refused_without_storage_write","ResourceJournalTests.test_unresolved_intent_blocks_another_create_not_just_name_reuse","ResourceJournalTests.test_unresolved_resources_block_other_case_and_other_run","ResourceJournalTests.test_wrong_active_case_and_foreign_case_ownership_rejected","ResourceJournalTests.test_zero_resource_profile_cannot_create_an_intent"],"tests/live_backend/test_proxy_client.py":["ProxyClientTests.test_authentication_guard_cannot_manufacture_context","ProxyClientTests.test_client_leaf_spki_san_purpose_and_expiry_pins","ProxyClientTests.test_content_length_duplicate_casefold_smuggling_and_surplus_headers","ProxyClientTests.test_der_length_and_tag_encodings_are_strict","ProxyClientTests.test_discovery_import_restores_both_package_attributes_and_module_cache","ProxyClientTests.test_foreign_context_refused_before_any_resource_or_transport","ProxyClientTests.test_header_injection_and_oversize_refused","ProxyClientTests.test_one_key_and_bounded_chain_pem_structure_only","ProxyClientTests.test_redirect_host_port_query_method_and_unknown_header_refused","ProxyClientTests.test_request_rejects_buffered_encrypted_records_without_waiting_for_eof","ProxyClientTests.test_response_body_fragmentation_and_authenticated_close","ProxyClientTests.test_response_surplus_pipelining_and_truncation_refused","ProxyClientTests.test_ten_exact_post_targets_and_framing","ProxyClientTests.test_tls_config_has_no_defaults_resumption_keylog_or_prompt","ProxyClientTests.test_tls_failed_send_and_connect_still_check_custody_and_never_retry","ProxyClientTests.test_tls_guard_checks_owner_before_wait_and_rejects_clock_rollback","ProxyClientTests.test_tls_guard_refusal_prevents_network_and_post_read_refusal_discards_bytes","ProxyClientTests.test_tls_handshake_requires_no_resumption_and_exact_alpn","ProxyClientTests.test_tls_partial_writes_keep_exact_suffix_and_guard_each_send","ProxyClientTests.test_tls_post_io_policy_timeout_is_not_a_read_poll","ProxyClientTests.test_tls_raw_eof_and_ciphertext_budget_refuse_before_bio_input","ProxyClientTests.test_tls_receive_detects_clock_rollback_after_socket_returns","ProxyClientTests.test_tls_receive_poll_cannot_extend_absolute_budget","ProxyClientTests.test_tls_receive_timeouts_poll_same_stream_without_retrying_request","ProxyClientTests.test_unsigned_identity_codec_does_not_verify_a_signature"],"tests/live_backend/test_proxy_server.py":["BrokerApiConnectionTests.test_api_close_is_idempotent_and_preserves_borrowed_resources","BrokerApiConnectionTests.test_api_transport_never_writes_durable_intent_or_cleanup","BrokerApiConnectionTests.test_ca_bytes_substitution_is_refused","BrokerApiConnectionTests.test_ca_outside_signed_kit_is_refused","BrokerApiConnectionTests.test_campaign_credential_reuse_refuses_before_credential","BrokerApiConnectionTests.test_changed_generation_refuses_before_credential","BrokerApiConnectionTests.test_changed_journal_refuses_before_credential","BrokerApiConnectionTests.test_connect_failure_has_post_observation_and_no_retry","BrokerApiConnectionTests.test_connected_peer_substitution_is_refused_before_tls","BrokerApiConnectionTests.test_context_failure_closes_memfd_without_connect","BrokerApiConnectionTests.test_dns_name_cannot_be_used_as_numeric_address","BrokerApiConnectionTests.test_duplicate_api_endpoint_refuses_before_credential","BrokerApiConnectionTests.test_expiry_refuses_before_credential","BrokerApiConnectionTests.test_factory_accepts_no_caller_endpoint_credential_or_socket","BrokerApiConnectionTests.test_foreign_current_api_owner_is_not_closed","BrokerApiConnectionTests.test_foreign_current_socket_is_not_adopted_or_closed","BrokerApiConnectionTests.test_inheritable_api_socket_is_refused","BrokerApiConnectionTests.test_ipv4_mapped_ipv6_is_refused","BrokerApiConnectionTests.test_ipv6_uses_one_family_without_fallback","BrokerApiConnectionTests.test_late_connect_refuses_before_handshake","BrokerApiConnectionTests.test_memfd_readback_mismatch_refuses_before_context","BrokerApiConnectionTests.test_missing_api_endpoint_refuses_before_credential","BrokerApiConnectionTests.test_missing_event_owner_refuses_before_credential","BrokerApiConnectionTests.test_missing_seals_refuses_before_context","BrokerApiConnectionTests.test_mutated_endpoint_after_ready_refuses_and_closes","BrokerApiConnectionTests.test_no_pending_action_refuses_before_credential","BrokerApiConnectionTests.test_numeric_family_mismatch_refuses_without_socket_or_secret","BrokerApiConnectionTests.test_original_pending_action_opens_separate_authenticated_channel_only","BrokerApiConnectionTests.test_pending_action_change_after_ready_refuses","BrokerApiConnectionTests.test_previously_read_credential_cannot_be_reopened","BrokerApiConnectionTests.test_recycled_api_descriptor_is_not_closed","BrokerApiConnectionTests.test_release_bytes_substitution_is_refused","BrokerApiConnectionTests.test_repeated_prepare_never_reconnects_or_reopens_credential","BrokerApiConnectionTests.test_revocation_after_connect_refuses_before_handshake","BrokerApiConnectionTests.test_revocation_after_context_stops_before_connect","BrokerApiConnectionTests.test_revocation_after_credential_read_stops_before_memfd","BrokerApiConnectionTests.test_revocation_during_handshake_does_not_publish_ready","BrokerApiConnectionTests.test_scoped_ipv6_is_refused","BrokerApiConnectionTests.test_server_identity_reuse_refuses_before_credential","BrokerApiConnectionTests.test_substituted_api_kind_refuses_before_credential","BrokerApiConnectionTests.test_tls_resumption_is_refused","BrokerApiConnectionTests.test_wrong_alpn_is_refused","BrokerApiConnectionTests.test_wrong_leaf_certificate_refuses_before_memfd","BrokerApiConnectionTests.test_wrong_server_certificate_is_refused","BrokerApiConnectionTests.test_wrong_tls_version_is_refused","BrokerApiConnectionTests.test_zero_memfd_write_refuses_and_closes_original","BrokerApiZeroResourceTests.test_zero_resource_execution_opens_no_api_socket_or_credential","BrokerCreateExchangeTests.test_authenticated_api_without_intent_cannot_send","BrokerCreateExchangeTests.test_candidate_response_change_is_detected","BrokerCreateExchangeTests.test_changed_action_refuses_without_http_write","BrokerCreateExchangeTests.test_changed_durable_history_refuses_without_http_write","BrokerCreateExchangeTests.test_conflict_is_not_adopted_or_deleted","BrokerCreateExchangeTests.test_duplicate_response_header_refuses","BrokerCreateExchangeTests.test_final_check_cannot_replace_publication_target","BrokerCreateExchangeTests.test_fresh_candidate_check_does_not_resend_or_reconnect","BrokerCreateExchangeTests.test_header_phase_keeps_ten_second_cap","BrokerCreateExchangeTests.test_lost_response_keeps_unknown_uid_and_capacity_held","BrokerCreateExchangeTests.test_missing_api_authentication_refuses_before_request","BrokerCreateExchangeTests.test_missing_uid_cannot_be_created_candidate","BrokerCreateExchangeTests.test_no_caller_request_response_path_or_backend_argument","BrokerCreateExchangeTests.test_non_200_created_response_is_not_silently_added_to_profile","BrokerCreateExchangeTests.test_noncanonical_response_is_not_normalized","BrokerCreateExchangeTests.test_original_candidate_refuses_foreign_exchange_without_using_it","BrokerCreateExchangeTests.test_original_intent_precedes_exact_fixed_create_request","BrokerCreateExchangeTests.test_partial_send_then_error_does_not_restart_http","BrokerCreateExchangeTests.test_peer_change_refuses_before_http_write","BrokerCreateExchangeTests.test_post_defaulting_manifest_change_refuses","BrokerCreateExchangeTests.test_redirect_does_not_follow_or_reconnect","BrokerCreateExchangeTests.test_reentrant_exchange_does_not_send_or_reconnect","BrokerCreateExchangeTests.test_repeated_completed_exchange_never_sends_again","BrokerCreateExchangeTests.test_request_substitution_during_write_is_refused","BrokerCreateExchangeTests.test_response_time_revocation_never_publishes_candidate","BrokerCreateExchangeTests.test_revoked_generation_refuses_before_http_write","BrokerCreateExchangeTests.test_short_or_ambiguous_write_never_retries","BrokerCreateExchangeTests.test_signed_deadline_refuses_before_http_write","BrokerCreateExchangeTests.test_slow_response_cannot_extend_original_deadline","BrokerCreateExchangeTests.test_success_remains_candidate_not_broker_result_or_created_record","BrokerCreateExchangeTests.test_surplus_response_refuses","BrokerCreateExchangeTests.test_truncated_response_body_refuses","BrokerCreateExchangeTests.test_uncommitted_intent_cannot_send","BrokerCreateExchangeTests.test_unowned_exchange_constructor_never_sends","BrokerCreateExchangeTests.test_write_time_revocation_blocks_outgoing_ciphertext","BrokerCreateResultTests.test_api_peer_loss_during_send_prevents_success_publication","BrokerCreateResultTests.test_api_peer_replacement_refuses_before_send","BrokerCreateResultTests.test_broker_peer_loss_during_send_prevents_success_publication","BrokerCreateResultTests.test_broker_peer_replacement_refuses_before_send","BrokerCreateResultTests.test_changed_created_record_is_not_sent","BrokerCreateResultTests.test_changed_returned_object_is_not_sent","BrokerCreateResultTests.test_delivery_reads_no_new_credential_or_api_response","BrokerCreateResultTests.test_exact_created_frame_uses_recorded_identity_and_original_chain","BrokerCreateResultTests.test_final_publication_cannot_target_replacement_result","BrokerCreateResultTests.test_foreign_broker_is_not_closed","BrokerCreateResultTests.test_foreign_created_owner_is_not_called_or_poisoned","BrokerCreateResultTests.test_foreign_result_is_not_checked_or_closed","BrokerCreateResultTests.test_frame_substitution_during_send_cannot_be_published","BrokerCreateResultTests.test_generation_loss_during_send_prevents_success_publication","BrokerCreateResultTests.test_history_loss_during_send_cannot_be_published","BrokerCreateResultTests.test_instance_shadow_created_check_is_not_used","BrokerCreateResultTests.test_intent_without_returned_identity_cannot_send_created","BrokerCreateResultTests.test_late_send_cannot_extend_two_second_control_phase","BrokerCreateResultTests.test_local_send_does_not_advance_original_transcript_or_release_capacity","BrokerCreateResultTests.test_next_event_is_blocked_until_separate_retirement_transition","BrokerCreateResultTests.test_no_caller_frame_outcome_identity_or_backend","BrokerCreateResultTests.test_original_accounting_and_result_checks_do_not_resend","BrokerCreateResultTests.test_original_deadline_refuses_before_send","BrokerCreateResultTests.test_proposed_transcript_substitution_is_detected","BrokerCreateResultTests.test_reentrant_send_is_refused_without_second_datagram","BrokerCreateResultTests.test_repeated_completed_send_never_retransmits","BrokerCreateResultTests.test_response_candidate_without_durable_created_record_cannot_send","BrokerCreateResultTests.test_revoked_generation_refuses_before_send","BrokerCreateResultTests.test_rollback_to_intent_history_refuses_before_send","BrokerCreateResultTests.test_send_error_keeps_created_uid_without_retry","BrokerCreateResultTests.test_short_zero_boolean_or_float_send_is_ambiguous_and_never_retried","BrokerCreateResultTests.test_uncommitted_created_record_is_not_a_delivery_grant","BrokerCreateResultTests.test_unexpected_append_refuses_before_send","BrokerCreateResultTests.test_unowned_constructor_never_sends","BrokerCreateRetirementTests.test_ambiguous_send_cannot_be_retired_as_success","BrokerCreateRetirementTests.test_api_peer_replacement_before_close_is_rejected","BrokerCreateRetirementTests.test_changed_created_identity_refuses_before_advancement","BrokerCreateRetirementTests.test_changed_result_frame_refuses_before_advancement","BrokerCreateRetirementTests.test_close_deadline_cannot_be_renewed","BrokerCreateRetirementTests.test_close_does_not_touch_recycled_descriptor","BrokerCreateRetirementTests.test_close_failure_preserves_first_error_and_holds_capacity","BrokerCreateRetirementTests.test_close_noop_cannot_advance_transcript","BrokerCreateRetirementTests.test_closed_api_cannot_be_reused_for_another_action","BrokerCreateRetirementTests.test_closed_descriptor_metadata_is_pinned_without_reopening_it","BrokerCreateRetirementTests.test_closed_owner_check_rejects_later_history_rollback","BrokerCreateRetirementTests.test_closed_owner_check_rejects_transcript_rewind","BrokerCreateRetirementTests.test_codec_failure_leaves_closed_api_and_held_accounting","BrokerCreateRetirementTests.test_descriptor_pin_substitution_after_live_check_refuses_before_close","BrokerCreateRetirementTests.test_foreign_api_reference_is_not_checked_or_closed","BrokerCreateRetirementTests.test_foreign_broker_reference_is_not_closed","BrokerCreateRetirementTests.test_foreign_events_reference_is_not_checked","BrokerCreateRetirementTests.test_foreign_retirement_is_not_published_or_called","BrokerCreateRetirementTests.test_generation_loss_during_close_prevents_advancement","BrokerCreateRetirementTests.test_history_append_during_close_prevents_advancement","BrokerCreateRetirementTests.test_history_rollback_before_close_is_rejected","BrokerCreateRetirementTests.test_instance_shadow_close_is_not_invoked","BrokerCreateRetirementTests.test_next_event_waits_for_separate_action_owner_handoff","BrokerCreateRetirementTests.test_no_caller_result_frame_or_cleanup_selector","BrokerCreateRetirementTests.test_no_created_result_cannot_retire","BrokerCreateRetirementTests.test_non_none_close_result_is_rejected","BrokerCreateRetirementTests.test_peer_loss_during_close_prevents_advancement","BrokerCreateRetirementTests.test_post_advance_guard_failure_does_not_undo_transcript_or_publish","BrokerCreateRetirementTests.test_recorded_but_unsent_result_cannot_retire","BrokerCreateRetirementTests.test_reentrant_retirement_never_advances_or_closes_twice","BrokerCreateRetirementTests.test_repeated_retirement_never_replays_or_recloses","BrokerCreateRetirementTests.test_result_data_substitution_during_close_is_rejected","BrokerCreateRetirementTests.test_retained_checks_reobserve_without_reclosing_or_replaying","BrokerCreateRetirementTests.test_retirement_does_not_release_resources_write_history_or_claim_cleanup","BrokerCreateRetirementTests.test_retirement_reads_no_new_credential_and_performs_no_transport_io","BrokerCreateRetirementTests.test_socket_substitution_after_live_check_cannot_retire_or_close_foreign","BrokerCreateRetirementTests.test_success_closes_original_api_then_advances_original_parser_once","BrokerCreateRetirementTests.test_tls_substitution_after_live_check_cannot_retire","BrokerCreateRetirementTests.test_unowned_constructor_never_retires_or_advances","BrokerCreateRetirementTests.test_unpublished_send_is_not_a_retirement_grant","BrokerCreatedTests.test_api_peer_change_at_fsync_cannot_publish_success","BrokerCreatedTests.test_api_peer_change_refuses_before_write","BrokerCreatedTests.test_changed_local_broker_reference_closes_only_original_broker","BrokerCreatedTests.test_changed_local_intent_reference_never_calls_foreign_poison","BrokerCreatedTests.test_changed_local_log_reference_never_poisons_foreign_log","BrokerCreatedTests.test_created_is_accounting_not_ack_cleanup_or_capacity_release","BrokerCreatedTests.test_every_write_ambiguity_stays_held_without_pin_advance_or_retry","BrokerCreatedTests.test_final_publication_cannot_target_a_replacement","BrokerCreatedTests.test_foreign_created_owner_is_not_checked_or_closed","BrokerCreatedTests.test_foreign_exchange_is_not_called","BrokerCreatedTests.test_foreign_log_is_not_an_execution_hook","BrokerCreatedTests.test_foreign_storage_is_not_read_or_written","BrokerCreatedTests.test_fsync_cannot_extend_two_second_phase","BrokerCreatedTests.test_fsync_generation_loss_keeps_uid_held_without_ack","BrokerCreatedTests.test_history_change_under_lock_cannot_be_rebased","BrokerCreatedTests.test_incomplete_exchange_is_not_durable_ownership","BrokerCreatedTests.test_instance_shadow_writer_and_checker_are_not_used","BrokerCreatedTests.test_lock_contention_does_not_append","BrokerCreatedTests.test_missing_exchange_never_invents_returned_identity","BrokerCreatedTests.test_no_caller_identity_response_history_or_backend","BrokerCreatedTests.test_original_intent_exchange_and_created_checks_keep_exact_new_history","BrokerCreatedTests.test_pending_action_change_at_fsync_is_not_acknowledged","BrokerCreatedTests.test_reentrant_record_never_repeats_create_or_append","BrokerCreatedTests.test_repeated_committed_record_never_appends_again","BrokerCreatedTests.test_response_is_revalidated_against_signed_manifest","BrokerCreatedTests.test_response_replacement_is_rejected_without_append","BrokerCreatedTests.test_response_without_resource_version_is_not_recorded","BrokerCreatedTests.test_retained_check_refuses_changed_row","BrokerCreatedTests.test_retained_check_refuses_rollback_to_intent_history","BrokerCreatedTests.test_retained_check_refuses_unknown_append_after_created","BrokerCreatedTests.test_uncommitted_intent_cannot_be_promoted","BrokerCreatedTests.test_unknown_history_before_write_is_not_adopted","BrokerCreatedTests.test_unlock_failure_does_not_publish_durable_success","BrokerCreatedTests.test_unowned_constructor_never_writes","BrokerCreatedTests.test_validated_identity_is_exactly_recorded_under_original_lock","BrokerCreatedTests.test_wrong_returned_digest_does_not_advance_pin","BrokerDispatchStartTests.test_attempted_case_cannot_be_restarted_through_a_reset_slot","BrokerDispatchStartTests.test_begin_accepts_no_caller_request_backend_or_observation","BrokerDispatchStartTests.test_changed_kernel_peer_after_receive_refuses","BrokerDispatchStartTests.test_complete_handshake_budget_includes_observation","BrokerDispatchStartTests.test_dispatch_is_derived_from_owned_running_record_and_fresh_observation","BrokerDispatchStartTests.test_duplicate_credentials_never_become_started","BrokerDispatchStartTests.test_durable_record_is_not_written_or_repaired_by_dispatch","BrokerDispatchStartTests.test_expired_observation_never_sends","BrokerDispatchStartTests.test_failed_native_inspection_prevents_dispatch","BrokerDispatchStartTests.test_failed_start_closes_original_channel_but_not_borrowed_store","BrokerDispatchStartTests.test_first_resource_action_is_not_controlled_start","BrokerDispatchStartTests.test_foreign_observation_nonce_never_sends","BrokerDispatchStartTests.test_foreign_tenant_cannot_reuse_running_history","BrokerDispatchStartTests.test_fractional_wire_observation_is_not_relaxed_with_runtime_clock","BrokerDispatchStartTests.test_future_running_timestamp_is_not_current_admission","BrokerDispatchStartTests.test_generation_drift_is_not_refreshed_into_new_dispatch","BrokerDispatchStartTests.test_invalid_random_challenge_never_sends","BrokerDispatchStartTests.test_last_phase_guard_failure_cannot_publish_started","BrokerDispatchStartTests.test_late_received_frame_does_not_extend_deadline","BrokerDispatchStartTests.test_message_credentials_must_match_original_peer","BrokerDispatchStartTests.test_observer_replacement_after_send_is_not_adopted","BrokerDispatchStartTests.test_observer_restart_during_response_refuses","BrokerDispatchStartTests.test_oversize_response_is_bounded_before_parsing","BrokerDispatchStartTests.test_partial_send_is_consumed_without_receive_or_retry","BrokerDispatchStartTests.test_poisoned_durable_log_denies_dispatch","BrokerDispatchStartTests.test_receive_timeout_is_not_a_new_handshake","BrokerDispatchStartTests.test_received_rights_are_drained_before_post_io_authority_failure","BrokerDispatchStartTests.test_record_drift_during_observation_denies_before_send","BrokerDispatchStartTests.test_replayed_begin_cannot_reuse_started_exchange","BrokerDispatchStartTests.test_reservation_flag_drift_during_observation_denies_before_send","BrokerDispatchStartTests.test_reserved_without_running_cannot_dispatch","BrokerDispatchStartTests.test_send_exception_keeps_post_io_observation_and_no_retry","BrokerDispatchStartTests.test_skipped_first_sequence_is_rejected","BrokerDispatchStartTests.test_subsecond_runtime_clock_accepts_current_whole_second_observation","BrokerDispatchStartTests.test_truncated_datagram_never_becomes_started","BrokerDispatchStartTests.test_unowned_store_or_observer_cannot_supply_prerequisites","BrokerDispatchStartTests.test_unsealed_server_registry_denies_dispatch","BrokerDispatchStartTests.test_wrong_challenge_echo_never_becomes_started","BrokerDispatchStartTests.test_wrong_running_operation_cannot_dispatch","BrokerEventTests.test_action_after_receipt_chunks_is_rejected","BrokerEventTests.test_at_most_171_chunks_even_when_total_bytes_are_small","BrokerEventTests.test_changed_challenge_is_rejected","BrokerEventTests.test_changed_execution_id_is_rejected","BrokerEventTests.test_changed_previous_digest_is_rejected","BrokerEventTests.test_chunk_index_outside_wire_schema_is_rejected","BrokerEventTests.test_contiguous_chunks_use_the_single_retained_transcript","BrokerEventTests.test_duplicate_chunk_sequence_is_rejected","BrokerEventTests.test_eof_is_not_idle_or_a_complete_receipt","BrokerEventTests.test_failure_closes_original_channel_not_borrowed_store","BrokerEventTests.test_foreign_readiness_descriptor_is_rejected","BrokerEventTests.test_full_receipt_size_limit_applies_to_transport","BrokerEventTests.test_generation_change_while_idle_is_rejected","BrokerEventTests.test_idle_then_event_keeps_original_deadline_and_channel","BrokerEventTests.test_idle_wait_returns_none_without_resend_or_consumption","BrokerEventTests.test_initial_transcript_tampering_cannot_bootstrap_a_receiver","BrokerEventTests.test_journal_change_during_receive_is_rejected","BrokerEventTests.test_last_phase_guard_failure_does_not_return_an_event","BrokerEventTests.test_late_readiness_result_is_rejected","BrokerEventTests.test_late_received_event_is_not_returned","BrokerEventTests.test_native_peer_change_after_readiness_is_rejected","BrokerEventTests.test_one_chunk_is_immutable_data_not_a_complete_receipt_or_action","BrokerEventTests.test_oversize_datagram_is_rejected","BrokerEventTests.test_oversized_decoded_chunk_is_rejected","BrokerEventTests.test_poll_does_not_accept_caller_backend_frame_or_timeout","BrokerEventTests.test_poll_never_writes_or_releases_durable_state","BrokerEventTests.test_readiness_exception_keeps_post_wait_guards","BrokerEventTests.test_receive_timeout_after_readiness_is_not_retried","BrokerEventTests.test_received_rights_are_closed_even_when_post_guard_refuses","BrokerEventTests.test_replaced_event_owner_is_not_adopted_or_closed","BrokerEventTests.test_replayed_started_frame_cannot_reset_the_stream","BrokerEventTests.test_retained_binding_mutation_is_detected","BrokerEventTests.test_retained_chunk_mutation_is_detected","BrokerEventTests.test_retained_transcript_scalar_mutation_is_detected","BrokerEventTests.test_session_expiry_cannot_be_extended_by_polling","BrokerEventTests.test_skipped_chunk_index_is_rejected","BrokerEventTests.test_start_observation_must_still_be_the_original_bytes","BrokerEventTests.test_terminal_cannot_bypass_unimplemented_server_cleanup","BrokerEventTests.test_terminal_without_worker_reaping_field_is_rejected","BrokerEventTests.test_transcript_replacement_is_not_adopted","BrokerEventTests.test_truncated_message_is_rejected","BrokerEventTests.test_unknown_manifest_action_is_rejected","BrokerEventTests.test_unknown_transcript_attribute_is_rejected","BrokerEventTests.test_unsolicited_server_result_is_rejected","BrokerEventTests.test_valid_action_is_data_and_blocks_a_second_receive_until_response","BrokerEventTests.test_wait_budget_leaves_room_inside_short_remaining_lifetime","BrokerEventTests.test_wrong_message_credentials_are_rejected","BrokerInspectionWiringTests.test_binding_object_and_enrollment_bytes_cannot_be_replaced","BrokerInspectionWiringTests.test_binding_owner_replacement_refuses_before_peer_queries","BrokerInspectionWiringTests.test_binding_success_boolean_is_not_accepted","BrokerInspectionWiringTests.test_executable_inode_substitution_refuses","BrokerInspectionWiringTests.test_fixed_factory_retains_one_channel_without_sending_frames","BrokerInspectionWiringTests.test_inspector_close_error_keeps_channel_cleanup_without_retry","BrokerInspectionWiringTests.test_inspector_constructor_failure_retains_partial_cleanup","BrokerInspectionWiringTests.test_inspector_refusal_is_sticky_without_reconnect","BrokerInspectionWiringTests.test_late_connect_error_rechecks_budget_and_never_reconnects","BrokerInspectionWiringTests.test_manifest_mismatch_refuses_before_socket_or_inspector","BrokerInspectionWiringTests.test_native_check_cannot_extend_two_second_phase","BrokerInspectionWiringTests.test_non_elf_peer_is_not_a_broker_wrapper_fallback","BrokerInspectionWiringTests.test_nonroot_peer_never_gets_a_pidfd_or_native_inspector","BrokerInspectionWiringTests.test_original_peer_credentials_are_rechecked_after_connection","BrokerInspectionWiringTests.test_replaced_inspector_refuses_and_foreign_inspector_is_not_closed","BrokerInspectionWiringTests.test_server_close_uses_only_original_broker_and_continues_after_failure","BrokerInspectionWiringTests.test_server_original_channel_slot_cannot_be_rebound","BrokerInspectionWiringTests.test_session_deadline_caps_later_check","BrokerInspectionWiringTests.test_timeout_setter_cannot_extend_connection_phase","BrokerInspectionWiringTests.test_transport_refuses_bad_broker_before_observation_or_storage","BrokerInspectionWiringTests.test_truthy_inspector_result_is_not_containment","BrokerInspectionWiringTests.test_wrong_socket_mode_or_owner_refuses_before_connect","BrokerIntentTests.test_accounting_does_not_acknowledge_action_or_acquire_api","BrokerIntentTests.test_all_write_ambiguities_poison_without_retry_or_pin_advance","BrokerIntentTests.test_bound_create_intent_commits_before_retained_history_advances","BrokerIntentTests.test_changed_pending_action_is_not_accepted_as_new_scope","BrokerIntentTests.test_cleanup_failure_preserves_first_refusal_and_durable_intent","BrokerIntentTests.test_committed_intent_rechecks_original_live_owners_without_more_writes","BrokerIntentTests.test_dispatch_pin_change_during_commit_is_not_repaired","BrokerIntentTests.test_expired_observation_prevents_append","BrokerIntentTests.test_expired_operation_prevents_append","BrokerIntentTests.test_fake_commit_digest_without_write_is_not_durable_evidence","BrokerIntentTests.test_final_enclosing_guard_failure_never_publishes_committed_intent","BrokerIntentTests.test_final_guard_cannot_replace_the_owned_publication_target","BrokerIntentTests.test_foreign_log_is_never_used","BrokerIntentTests.test_foreign_store_is_never_used","BrokerIntentTests.test_fresh_check_detects_post_commit_generation_loss","BrokerIntentTests.test_fresh_check_detects_post_commit_history_substitution","BrokerIntentTests.test_fsync_revocation_retains_intent_but_never_publishes_success","BrokerIntentTests.test_get_action_cannot_be_promoted_to_create_intent","BrokerIntentTests.test_history_changed_under_lock_is_not_accepted","BrokerIntentTests.test_instance_shadow_writer_is_not_an_execution_hook","BrokerIntentTests.test_intent_replacement_does_not_close_or_use_foreign_object","BrokerIntentTests.test_late_transaction_cannot_extend_two_second_phase","BrokerIntentTests.test_lock_contention_refuses_without_append","BrokerIntentTests.test_method_accepts_no_caller_resource_history_or_backend","BrokerIntentTests.test_missing_event_owner_refuses_before_write","BrokerIntentTests.test_peer_identity_loss_prevents_append","BrokerIntentTests.test_pending_action_change_during_commit_refuses_before_repin","BrokerIntentTests.test_post_transaction_extra_bytes_refuse_without_repin","BrokerIntentTests.test_reentrant_attempt_closes_owner_and_never_retries","BrokerIntentTests.test_repeated_committed_create_is_refused_without_second_append","BrokerIntentTests.test_revoked_generation_before_write_prevents_append","BrokerIntentTests.test_stale_running_history_is_not_adopted","BrokerIntentTests.test_unlock_failure_is_ambiguous_after_durable_write","BrokerIntentTests.test_unowned_constructor_cannot_append","BrokerIntentTests.test_wrong_commit_result_refuses_even_when_original_append_happened","BrokerStartupSourceOrderTests.test_server_constructor_order_keeps_broker_before_credentials","BrokerTransportCustodyTests.test_changed_process_start_time_refuses_before_send","BrokerTransportCustodyTests.test_close_error_is_sticky_without_retry_and_other_cleanup_continues","BrokerTransportCustodyTests.test_inheritable_retained_descriptors_refuse_before_send","BrokerTransportCustodyTests.test_monotonic_rollback_is_sticky","BrokerTransportCustodyTests.test_mutated_local_process_pin_is_not_new_enrollment","BrokerTransportCustodyTests.test_owner_replacement_refuses_before_transport","BrokerTransportCustodyTests.test_partial_constructor_connect_error_closes_only_acquired_socket","BrokerTransportCustodyTests.test_pidfd_exceptional_liveness_refuses_before_send","BrokerTransportCustodyTests.test_post_pidfd_acquisition_failure_keeps_cleanup_ownership","BrokerTransportCustodyTests.test_replaced_socket_object_is_refused_and_foreign_socket_not_closed","BrokerTransportCustodyTests.test_reused_pidfd_is_not_closed_and_socket_cleanup_continues","BrokerTransportCustodyTests.test_reused_socket_descriptor_detaches_without_closing_foreign_fd","BrokerTransportCustodyTests.test_socket_path_replacement_refuses_before_send","BrokerTransportCustodyTests.test_wall_rollback_is_sticky","BrokerZeroResourceEventTests.test_zero_resource_profile_refuses_actions_without_api_or_credentials","KernelBpfCustodyTests.test_actual_id_or_type_mismatch_refuses","KernelBpfCustodyTests.test_all_four_roles_query_only_their_retained_cgroup","KernelBpfCustodyTests.test_arm64_uses_fixed_280_and_no_architecture_fallback","KernelBpfCustodyTests.test_changed_cgroup_control_during_query_fails_before_return","KernelBpfCustodyTests.test_cross_process_thread_or_reentrant_use_refuses","KernelBpfCustodyTests.test_effective_flags_and_unknown_local_flags_refuse","KernelBpfCustodyTests.test_effective_inherited_program_mismatch_refuses","KernelBpfCustodyTests.test_expected_pins_detach_and_program_close_preserves_borrowed_owners","KernelBpfCustodyTests.test_extra_or_oversized_attachment_count_is_not_truncated_or_retried","KernelBpfCustodyTests.test_inheritable_or_wrong_mode_program_descriptors_refuse","KernelBpfCustodyTests.test_maps_and_offload_are_not_accepted","KernelBpfCustodyTests.test_missing_attachment_refuses_without_acquiring_programs","KernelBpfCustodyTests.test_oversized_or_truncated_instructions_refuse_without_second_allocation","KernelBpfCustodyTests.test_owner_copies_raw_fds_and_injected_backends_are_refused","KernelBpfCustodyTests.test_pid_death_or_cgroup_migration_after_query_poison_owner","KernelBpfCustodyTests.test_pin_shape_hook_set_and_values_are_closed_before_native_calls","KernelBpfCustodyTests.test_post_acquisition_timeout_closes_new_descriptor_before_raising","KernelBpfCustodyTests.test_private_syscall_surface_rejects_mutation_commands","KernelBpfCustodyTests.test_program_fd_acquisition_partial_failure_releases_only_owned_handles","KernelBpfCustodyTests.test_query_unknown_tail_or_changed_input_refuses","KernelBpfCustodyTests.test_query_unused_id_slots_cannot_hide_additional_output","KernelBpfCustodyTests.test_redacted_instruction_length_refuses","KernelBpfCustodyTests.test_redacted_instruction_pointer_refuses_even_with_matching_length","KernelBpfCustodyTests.test_replacement_after_program_read_is_caught_by_final_queries","KernelBpfCustodyTests.test_retains_seven_programs_and_queries_local_and_effective_before_after","KernelBpfCustodyTests.test_runtime_counters_may_advance_but_load_identity_must_not","KernelBpfCustodyTests.test_same_inode_different_program_id_is_detected_during_recheck","KernelBpfCustodyTests.test_shared_anonymous_inode_cannot_hide_fd_substitution_on_close","KernelBpfCustodyTests.test_short_new_or_changed_info_response_layouts_refuse","KernelBpfCustodyTests.test_syscall_errors_do_not_retry_or_acquire_privileges","KernelBpfCustodyTests.test_syscall_timeout_and_backwards_clock_refuse","KernelBpfCustodyTests.test_translated_bytes_not_tag_or_stored_artifact_determine_identity","KernelBpfCustodyTests.test_uncertain_os_close_is_never_retried_and_other_owned_fds_close","KernelBpfCustodyTests.test_unrequested_pointers_reserved_bits_and_record_layouts_refuse","KernelBpfCustodyTests.test_valid_local_flags_are_retained_and_changes_poison_view","KernelBrokerInspectionTests.test_broker_phase_deadline_cannot_be_renewed_by_inspection","KernelBrokerInspectionTests.test_cleanup_error_preserves_other_reader_closes_without_retry","KernelBrokerInspectionTests.test_copied_owner_and_subclass_are_refused","KernelBrokerInspectionTests.test_detached_peer_inspection_is_not_an_ambient_capability","KernelBrokerInspectionTests.test_each_partial_reader_is_owned_before_constructor_failure","KernelBrokerInspectionTests.test_exceptional_pidfd_liveness_refuses","KernelBrokerInspectionTests.test_failed_reader_poisoned_and_cleanup_does_not_own_channel_or_server","KernelBrokerInspectionTests.test_fixed_broker_role_uses_original_peer_not_server_pid","KernelBrokerInspectionTests.test_late_channel_query_is_rechecked_even_on_exception","KernelBrokerInspectionTests.test_named_broker_socket_replacement_refuses","KernelBrokerInspectionTests.test_nonroot_peer_credentials_are_not_role_enrollment","KernelBrokerInspectionTests.test_observer_peer_type_cannot_supply_broker_native_inspection","KernelBrokerInspectionTests.test_original_socket_credentials_are_checked_at_reader_boundaries","KernelBrokerInspectionTests.test_poisoned_server_self_inspection_cannot_support_peer_qualification","KernelBrokerInspectionTests.test_proc_start_must_join_original_socket_process_before_code_reads","KernelBrokerInspectionTests.test_record_change_remains_sticky_and_cannot_reenroll_peer","KernelBrokerInspectionTests.test_replaced_pidfd_is_not_adopted","KernelBrokerInspectionTests.test_replaced_self_inspector_refuses_before_peer_reader_check","KernelBrokerInspectionTests.test_reused_descriptor_is_refused_without_closing_borrowed_fd","KernelBrokerInspectionTests.test_server_original_channel_pin_cannot_be_rebound","KernelCgroupCustodyTests.test_actual_group_inode_must_equal_enrolled_pin","KernelCgroupCustodyTests.test_ancestor_replacement_and_same_inode_submount_are_refused","KernelCgroupCustodyTests.test_arm64_uses_the_same_readonly_cgroup_contract_without_native_execution","KernelCgroupCustodyTests.test_clock_rollback_and_failure_cannot_renew_inspection","KernelCgroupCustodyTests.test_closed_pins_reject_wrong_roles_unknown_fields_and_invalid_numbers","KernelCgroupCustodyTests.test_control_and_membership_path_replacements_cannot_adopt_new_inodes","KernelCgroupCustodyTests.test_control_inode_aliases_are_refused","KernelCgroupCustodyTests.test_copied_or_failed_owner_and_caller_backend_are_not_admitted","KernelCgroupCustodyTests.test_dead_pidfd_during_read_never_returns_matching_limits","KernelCgroupCustodyTests.test_each_role_uses_its_fixed_existing_group_and_worker_stays_nonroot","KernelCgroupCustodyTests.test_expected_pins_are_detached_and_closing_does_not_close_borrowed_process","KernelCgroupCustodyTests.test_finite_limit_changes_and_unlimited_or_noncanonical_values_are_refused","KernelCgroupCustodyTests.test_group_and_controls_must_be_root_owned_not_tenant_writable","KernelCgroupCustodyTests.test_inspection_has_one_two_second_budget_across_all_nested_reads","KernelCgroupCustodyTests.test_inspector_pid_change_refuses_before_cgroup_io","KernelCgroupCustodyTests.test_inspector_thread_change_refuses_before_cgroup_io","KernelCgroupCustodyTests.test_late_open_is_owned_and_closed_even_before_identity_capture","KernelCgroupCustodyTests.test_membership_is_unsorted_and_other_member_churn_is_not_target_drift","KernelCgroupCustodyTests.test_membership_must_include_original_live_process_without_duplicates","KernelCgroupCustodyTests.test_membership_removal_during_control_read_is_not_hidden_by_old_sequence_buffer","KernelCgroupCustodyTests.test_missing_symlinked_or_unreadable_control_is_not_repaired","KernelCgroupCustodyTests.test_no_whitespace_coercion_truncation_or_extra_control_fields","KernelCgroupCustodyTests.test_oversize_and_nonbytes_reads_do_not_yield_observations","KernelCgroupCustodyTests.test_process_migration_during_controls_read_is_detected_before_return","KernelCgroupCustodyTests.test_real_factories_retain_original_cgroup_and_fresh_open_each_control","KernelCgroupCustodyTests.test_recycled_group_descriptor_is_never_closed_as_original","KernelCgroupCustodyTests.test_restarted_process_cannot_reuse_same_cgroup_and_limits","KernelCgroupCustodyTests.test_retained_descriptor_change_during_read_is_refused","KernelCgroupCustodyTests.test_second_fresh_control_snapshot_rejects_between_open_drift","KernelCgroupCustodyTests.test_short_reads_continue_to_complete_eof","KernelCgroupCustodyTests.test_uncertain_temporary_close_sticks_and_never_closes_borrowed_owners","KernelCodeCustodyTests.test_arm64_uses_same_fixed_file_interfaces_and_its_own_elf_architecture","KernelCodeCustodyTests.test_bad_segment_pins_and_page_size_fail_closed","KernelCodeCustodyTests.test_clock_rollback_process_and_thread_changes_are_not_reacquired","KernelCodeCustodyTests.test_closed_inventory_shapes_and_duplicate_paths_fail_before_file_io","KernelCodeCustodyTests.test_closed_or_failed_owner_never_grants_custody","KernelCodeCustodyTests.test_content_digest_is_checked_even_when_verity_response_is_unchanged","KernelCodeCustodyTests.test_exact_root_owner_mode_size_and_single_link_are_required","KernelCodeCustodyTests.test_executable_segment_pins_must_match_actual_file_and_not_hide_elf","KernelCodeCustodyTests.test_expected_inventory_is_detached_from_caller_mutation","KernelCodeCustodyTests.test_file_and_aggregate_bounds_and_distinct_digest_pins","KernelCodeCustodyTests.test_file_labels_are_exact_and_missing_labels_do_not_fall_back","KernelCodeCustodyTests.test_hardlink_alias_even_with_claimed_single_link_is_refused","KernelCodeCustodyTests.test_late_open_retains_and_closes_the_new_descriptor","KernelCodeCustodyTests.test_loader_must_be_enrolled_actual_elf_not_an_archive","KernelCodeCustodyTests.test_mapping_cannot_execute_an_enrolled_archive","KernelCodeCustodyTests.test_mapping_match_is_data_only_and_allows_observed_pie_bias","KernelCodeCustodyTests.test_mapping_missing_extra_or_oversize_segments_are_refused","KernelCodeCustodyTests.test_mapping_path_device_inode_and_permissions_are_closed","KernelCodeCustodyTests.test_mapping_requires_enrolled_loader_to_be_mapped_too","KernelCodeCustodyTests.test_mapping_static_executable_cannot_claim_pie_bias","KernelCodeCustodyTests.test_metadata_label_or_named_path_change_during_read_is_detected","KernelCodeCustodyTests.test_multiple_executable_segments_require_complete_consistent_address_bias","KernelCodeCustodyTests.test_noncanonical_paths_and_file_directory_overlap_are_rejected_before_io","KernelCodeCustodyTests.test_one_phase_budget_covers_all_reads_and_does_not_restart_per_chunk","KernelCodeCustodyTests.test_parent_or_leaf_named_substitution_is_sticky","KernelCodeCustodyTests.test_partial_acquisition_failure_closes_owned_fds_but_not_roots","KernelCodeCustodyTests.test_recycled_fd_is_not_closed_as_if_still_owned","KernelCodeCustodyTests.test_retains_complete_ancestry_separate_measurements_and_fresh_reads","KernelCodeCustodyTests.test_same_inode_mount_substitution_is_refused","KernelCodeCustodyTests.test_shared_mapping_selection_is_pinned_separately_from_elf_rwx_flags","KernelCodeCustodyTests.test_short_chunk_reads_are_complete_and_offset_based","KernelCodeCustodyTests.test_split_mapping_must_cover_the_complete_segment_at_one_bias","KernelCodeCustodyTests.test_symlink_and_nonregular_leaf_are_not_followed","KernelCodeCustodyTests.test_truncation_growth_wrong_types_and_oversize_read_results_are_rejected","KernelCodeCustodyTests.test_uncertain_close_is_sticky_and_never_retried","KernelCodeCustodyTests.test_verity_mismatch_or_missing_ioctl_never_falls_back_to_content_hash","KernelCodeCustodyTests.test_writable_or_unowned_parent_is_refused","KernelEpochMountTests.test_delayed_mount_query_keeps_original_busy_phase_deadline","KernelEpochMountTests.test_dynamic_directory_counters_are_not_mount_custody","KernelEpochMountTests.test_failed_query_still_checks_post_io_owner_custody","KernelEpochMountTests.test_inheritable_sysfs_ancestry_is_refused","KernelEpochMountTests.test_large_unique_mount_ids_preserve_native_uint64_precision","KernelEpochMountTests.test_missing_unique_mount_bit_cannot_use_recycled_id","KernelEpochMountTests.test_mount_change_during_epoch_fence_is_seen_after_sample","KernelEpochMountTests.test_mount_pin_has_no_mutable_filesystem_alias","KernelEpochMountTests.test_mutated_mount_pins_cannot_reenroll_the_view","KernelEpochMountTests.test_nonzero_reserved_statx_bytes_refuse","KernelEpochMountTests.test_replaced_sysfs_descriptor_is_not_adopted","KernelEpochMountTests.test_retained_filesystem_identity_change_refuses","KernelEpochMountTests.test_retained_parent_mount_change_refuses","KernelEpochMountTests.test_retained_status_mount_change_refuses","KernelEpochMountTests.test_retained_sysfs_ancestry_mount_change_refuses","KernelEpochMountTests.test_same_fixed_queries_on_both_mocked_native_abis","KernelEpochMountTests.test_same_inode_selinux_parent_bind_mount_refuses","KernelEpochMountTests.test_same_inode_status_bind_mount_is_not_hidden_by_retained_mapping","KernelEpochMountTests.test_samples_mounts_without_new_descriptors_mappings_or_policy_opens","KernelEpochMountTests.test_statx_helper_has_no_arbitrary_path_or_fd_fallback","KernelEpochMountTests.test_statx_inode_disagreement_with_retained_fd_refuses","KernelEpochMountTests.test_symlink_status_output_never_matches_regular_inode","KernelEpochMountTests.test_unavailable_named_query_never_falls_back_to_stat","KernelEpochMountTests.test_unknown_statx_fields_are_not_accepted","KernelInputCodecTests.test_auxv_requires_unique_complete_native_pairs_and_exact_terminator","KernelInputCodecTests.test_codecs_never_open_execute_or_return_native_authority","KernelInputCodecTests.test_elf_both_native_machines_have_exact_executable_loads","KernelInputCodecTests.test_elf_interpreter_is_data_not_a_loadable_path","KernelInputCodecTests.test_elf_refuses_short_tables_ranges_and_overflow","KernelInputCodecTests.test_elf_refuses_writable_executable_anonymous_and_duplicate_loads","KernelInputCodecTests.test_elf_rejects_other_endian_class_machine_and_header_shapes","KernelInputCodecTests.test_maps_kernel_names_require_auxv_architecture_and_exact_shapes","KernelInputCodecTests.test_maps_preserve_aslr_device_inode_permissions_and_offset","KernelInputCodecTests.test_maps_reject_truncation_malformed_rows_and_overlapping_addresses","KernelInputCodecTests.test_maps_reject_unknown_anonymous_deleted_memfd_and_writable_code","KernelInputCodecTests.test_selinux_status_layout_has_distinct_sequence_and_policyload","KernelInputCodecTests.test_selinux_status_rejects_odd_permissive_unknown_or_truncated_bytes","KernelInputCodecTests.test_verity_measurement_decodes_distinct_kernel_digest","KernelInspectionEpochWiringTests.test_all_reader_ticks_sample_the_epoch_before_and_after_io","KernelInspectionEpochWiringTests.test_boolean_epoch_result_cannot_replace_the_fixed_check","KernelInspectionEpochWiringTests.test_epoch_inner_checks_allow_only_policy_and_original_native_reader","KernelInspectionEpochWiringTests.test_epoch_refusal_during_io_prevents_any_following_read","KernelInspectionEpochWiringTests.test_failed_retention_precedes_process_storage_observer_and_credentials","KernelInspectionEpochWiringTests.test_other_reader_reentry_during_epoch_check_refuses","KernelInspectionReadBoundaryTests.test_all_eight_real_reader_ticks_retain_original_owner","KernelInspectionReadBoundaryTests.test_authority_bytes_replaced_during_read_cannot_use_prior_signature","KernelInspectionReadBoundaryTests.test_authority_file_replacement_inside_io_poisoned_before_next_read","KernelInspectionReadBoundaryTests.test_callback_dictionary_or_raw_fd_cannot_select_a_guard","KernelInspectionReadBoundaryTests.test_delayed_io_cannot_reset_original_combined_deadline","KernelInspectionReadBoundaryTests.test_every_component_is_bound_before_its_constructor","KernelInspectionReadBoundaryTests.test_failure_stays_poisoned_after_unit_owner_is_restored","KernelInspectionReadBoundaryTests.test_guard_failure_before_io_never_calls_the_operation","KernelInspectionReadBoundaryTests.test_missing_owner_binding_during_active_server_is_not_standalone_mode","KernelInspectionReadBoundaryTests.test_native_constructor_refuses_unbound_reader_before_loading_libc","KernelInspectionReadBoundaryTests.test_owner_disappearing_inside_io_stops_before_second_observation","KernelInspectionReadBoundaryTests.test_real_io_wrappers_guard_before_and_after_an_observation","KernelInspectionReadBoundaryTests.test_replaced_native_reader_cannot_reuse_the_previous_lifetime","KernelInspectionReadBoundaryTests.test_reversed_wall_or_monotonic_clock_inside_read_refuses","KernelInspectionReadBoundaryTests.test_session_window_replacement_inside_read_cannot_extend_authority","KernelInspectionReadBoundaryTests.test_signed_window_is_retained_separately_from_record_expiry","KernelInspectionReadBoundaryTests.test_source_retains_native_owner_and_all_eight_read_hooks","KernelInspectionReadBoundaryTests.test_unowned_same_class_and_copied_owner_reference_refused","KernelInspectionRootWiringTests.test_boolean_or_data_root_result_never_grants_readiness","KernelInspectionRootWiringTests.test_initial_root_refusal_prevents_epoch_and_observation","KernelInspectionRootWiringTests.test_root_and_original_native_nested_ticks_do_not_resample","KernelInspectionRootWiringTests.test_root_change_during_observation_prevents_the_next_read","KernelInspectionRootWiringTests.test_roots_surround_epoch_at_both_io_boundaries","KernelInspectionRootWiringTests.test_unrelated_reader_reentry_during_root_sample_refuses","KernelNativeReadTests.test_changed_descriptor_refuses_result_without_closing_reused_fd","KernelNativeReadTests.test_descriptor_type_range_access_and_inheritance_before_native_reads","KernelNativeReadTests.test_filesystem_rejects_error_unknown_layout_and_reserved_tail","KernelNativeReadTests.test_filesystem_returns_stable_data_not_dynamic_counters_or_a_grant","KernelNativeReadTests.test_fixed_constructor_and_native_lp64_layout","KernelNativeReadTests.test_private_barrier_missing_permissions_and_commands_poison_reader","KernelNativeReadTests.test_process_thread_clock_and_closed_reader_refuse_native_operation","KernelNativeReadTests.test_status_both_native_machines_use_exact_syscall_numbers","KernelNativeReadTests.test_status_mapping_partial_failure_and_close_failure_are_not_retried","KernelNativeReadTests.test_status_maps_one_native_page_for_both_supported_abis","KernelNativeReadTests.test_status_odd_changed_epoch_and_invalid_fields_always_unmap","KernelNativeReadTests.test_status_rechecks_filesystem_and_fd_after_fenced_read","KernelNativeReadTests.test_status_rejects_unknown_or_late_page_size_before_mapping","KernelNativeReadTests.test_status_uses_shared_readonly_mapping_and_private_fences_only","KernelNativeReadTests.test_status_wrong_filesystem_and_custody_refuse_before_mapping","KernelNativeReadTests.test_unsupported_os_endianness_machine_and_word_size_never_load_library","KernelNativeReadTests.test_verity_changed_metadata_and_late_result_are_refused","KernelNativeReadTests.test_verity_errors_and_wrong_measurement_never_fallback_or_enable","KernelNativeReadTests.test_verity_refuses_unowned_mutable_linked_or_unbounded_code","KernelNativeReadTests.test_verity_uses_exact_measure_ioctl_and_distinct_kernel_digest","KernelObserverInspectionTests.test_cleanup_error_preserves_other_reader_closes_without_retry","KernelObserverInspectionTests.test_copied_owner_and_subclass_are_refused","KernelObserverInspectionTests.test_detached_peer_inspection_is_not_an_ambient_capability","KernelObserverInspectionTests.test_each_partial_reader_is_owned_before_constructor_failure","KernelObserverInspectionTests.test_exceptional_pidfd_liveness_refuses","KernelObserverInspectionTests.test_failed_reader_poisoned_and_cleanup_does_not_own_channel_or_server","KernelObserverInspectionTests.test_fixed_observer_role_uses_original_peer_not_server_pid","KernelObserverInspectionTests.test_late_channel_query_is_rechecked_even_on_exception","KernelObserverInspectionTests.test_named_observer_socket_replacement_refuses","KernelObserverInspectionTests.test_nonroot_peer_credentials_are_not_role_enrollment","KernelObserverInspectionTests.test_observer_phase_deadline_cannot_be_renewed_by_inspection","KernelObserverInspectionTests.test_original_socket_credentials_are_checked_at_reader_boundaries","KernelObserverInspectionTests.test_poisoned_server_self_inspection_cannot_support_peer_qualification","KernelObserverInspectionTests.test_proc_start_must_join_original_socket_process_before_code_reads","KernelObserverInspectionTests.test_record_change_remains_sticky_and_cannot_reenroll_peer","KernelObserverInspectionTests.test_replaced_pidfd_is_not_adopted","KernelObserverInspectionTests.test_replaced_self_inspector_refuses_before_peer_reader_check","KernelObserverInspectionTests.test_reused_descriptor_is_refused_without_closing_borrowed_fd","KernelPolicyCustodyTests.test_arm64_kernel_policy_uses_actual_page_and_private_fences","KernelPolicyCustodyTests.test_boot_change_during_policy_read_is_detected_after_read","KernelPolicyCustodyTests.test_boot_kernel_release_machine_and_notes_mismatches_refuse","KernelPolicyCustodyTests.test_busy_policy_open_is_unavailable_without_cache_retry_or_write","KernelPolicyCustodyTests.test_cleanup_uncertainty_is_sticky_and_never_retries_close","KernelPolicyCustodyTests.test_closed_host_policy_pins_refuse_before_kernel_access","KernelPolicyCustodyTests.test_complete_policy_phase_has_one_budget_not_per_chunk","KernelPolicyCustodyTests.test_empty_oversize_and_wrong_type_policy_reads_refuse","KernelPolicyCustodyTests.test_enforce_deny_unknown_and_status_controls_refuse","KernelPolicyCustodyTests.test_expected_pins_are_detached_without_authenticating_them","KernelPolicyCustodyTests.test_factory_has_no_backend_path_descriptor_or_qualified_selector","KernelPolicyCustodyTests.test_fresh_policy_open_each_check_retains_only_fixed_kernel_views","KernelPolicyCustodyTests.test_late_partial_acquisition_closes_just_owned_handles","KernelPolicyCustodyTests.test_named_file_replacement_and_retained_fd_replacement_refuse","KernelPolicyCustodyTests.test_partial_reads_hash_complete_fresh_policy","KernelPolicyCustodyTests.test_policy_digest_change_is_not_hidden_by_retained_snapshot","KernelPolicyCustodyTests.test_policy_epoch_change_during_read_refuses_even_if_hash_would_match","KernelPolicyCustodyTests.test_policy_path_replacement_between_checks_refuses_even_same_bytes","KernelPolicyCustodyTests.test_policy_permission_or_read_error_never_uses_old_digest","KernelPolicyCustodyTests.test_policy_read_is_bracketed_by_real_status_reader","KernelPolicyCustodyTests.test_status_path_replacement_during_fence_is_detected","KernelPolicyCustodyTests.test_substituted_kernel_file_mount_owner_or_mode_refuses","KernelPolicyCustodyTests.test_temporary_policy_close_failure_invalidates_reader_and_keeps_roots","KernelPolicyCustodyTests.test_wrong_process_thread_backward_clock_and_closed_state_refuse","KernelProcessCodeTests.test_actual_factories_retain_four_interfaces_and_never_accept_map_input","KernelProcessCodeTests.test_all_role_executable_dependencies_must_be_mapped","KernelProcessCodeTests.test_arm64_process_reads_bind_arm64_elf_without_emulation","KernelProcessCodeTests.test_auxv_change_is_detected_even_when_executable_maps_match","KernelProcessCodeTests.test_clock_rollback_cannot_restart_a_phase","KernelProcessCodeTests.test_copied_owners_and_mixed_roots_are_refused","KernelProcessCodeTests.test_deleted_executable_link_count_cannot_be_hidden_by_matching_bytes","KernelProcessCodeTests.test_exe_descriptor_cannot_reference_different_inode_or_mount","KernelProcessCodeTests.test_exe_link_owner_type_and_named_identity_must_stay_original","KernelProcessCodeTests.test_exe_magic_link_target_must_be_exact_and_never_opened_as_a_path","KernelProcessCodeTests.test_expected_data_is_detached_and_original_process_is_borrowed","KernelProcessCodeTests.test_failed_partial_acquisition_closes_only_newly_owned_descriptors","KernelProcessCodeTests.test_fixed_command_line_has_no_user_arguments_or_alternate_archive","KernelProcessCodeTests.test_inspector_process_change_is_refused","KernelProcessCodeTests.test_inspector_thread_change_is_refused","KernelProcessCodeTests.test_late_exe_open_is_owned_before_deadline_check_and_cleaned_once","KernelProcessCodeTests.test_mapping_inode_permission_and_unenrolled_code_are_rejected","KernelProcessCodeTests.test_named_proc_file_and_mount_replacements_are_refused","KernelProcessCodeTests.test_native_observer_and_broker_bind_their_own_executable","KernelProcessCodeTests.test_native_page_size_and_actual_auxv_vdso_must_agree","KernelProcessCodeTests.test_normal_nonexecutable_heap_changes_do_not_become_code_drift","KernelProcessCodeTests.test_one_whole_budget_includes_all_proc_reads_and_code_checks","KernelProcessCodeTests.test_oversize_truncated_and_wrong_type_proc_reads_fail_closed","KernelProcessCodeTests.test_partial_short_reads_use_retained_offsets_and_complete_eof","KernelProcessCodeTests.test_process_death_during_a_read_prevents_returning_an_observation","KernelProcessCodeTests.test_recycled_descriptor_is_not_closed_as_the_original","KernelProcessCodeTests.test_retained_aslr_and_auxv_cannot_change_between_checks","KernelProcessCodeTests.test_role_cannot_use_another_globally_enrolled_executable","KernelProcessCodeTests.test_start_identity_change_during_maps_read_is_detected_before_return","KernelProcessCodeTests.test_two_fresh_maps_reject_between_read_changes","KernelProcessCodeTests.test_uncertain_close_is_sticky_without_closing_borrowed_owners","KernelProcessCodeTests.test_unknown_role_paths_artifact_or_inventory_are_rejected_before_proc_io","KernelProcessCodeTests.test_worker_uses_its_enrolled_uid_and_fixed_python_archive","KernelProcessCustodyTests.test_all_four_role_paths_and_worker_nonroot_pins_use_only_enrolled_namespaces","KernelProcessCustodyTests.test_bound_proc_views_reject_same_inode_submount_and_process_path_replacement","KernelProcessCustodyTests.test_exit_during_a_blocking_read_refuses_the_returned_bytes","KernelProcessCustodyTests.test_factory_refuses_invalid_pid_roots_role_and_caller_backend_before_acquisition","KernelProcessCustodyTests.test_fixed_native_factory_retains_original_roots_proc_pid_and_namespace_fds","KernelProcessCustodyTests.test_late_read_and_whole_phase_budget_refuse_without_renewal","KernelProcessCustodyTests.test_missing_pidfd_permission_inheritance_and_late_acquisition_are_unavailable","KernelProcessCustodyTests.test_namespace_inode_type_link_and_retained_descriptor_changes_are_refused","KernelProcessCustodyTests.test_namespace_link_change_during_open_refuses_the_acquired_view","KernelProcessCustodyTests.test_namespace_native_read_rejects_wrong_fs_missing_ioctl_and_changed_descriptor","KernelProcessCustodyTests.test_namespace_readonly_ioctl_is_identical_on_both_supported_abis","KernelProcessCustodyTests.test_partial_open_fstat_and_namespace_failures_close_only_owned_fds","KernelProcessCustodyTests.test_pid_exit_and_pidfd_replacement_fail_without_reacquisition","KernelProcessCustodyTests.test_proc_reads_are_bounded_fresh_and_detect_truncation_and_named_replacement","KernelProcessCustodyTests.test_process_stat_handles_delimiters_newlines_and_ignores_cpu_memory_churn","KernelProcessCustodyTests.test_role_pins_are_detached_and_invalid_pins_do_not_open_process","KernelProcessCustodyTests.test_server_extra_threads_children_and_invalid_directory_entries_are_denied","KernelProcessCustodyTests.test_start_time_parent_credentials_and_privilege_drift_invalidate_lifetime","KernelProcessCustodyTests.test_stat_rejects_truncated_extra_overflow_dead_and_inconsistent_processes","KernelProcessCustodyTests.test_status_rejects_duplicates_missing_fields_credentials_tracing_and_namespace_mismatch","KernelProcessCustodyTests.test_temporary_cleanup_failure_remains_sticky_and_cleanup_continues","KernelProcessCustodyTests.test_uid_gid_label_and_cgroup_mismatch_refuse_and_close_partial_custody","KernelProcessCustodyTests.test_wrong_process_thread_closed_root_and_backward_clock_refuse","KernelRetainedEpochTests.test_already_busy_native_phase_is_not_reentered_or_renewed","KernelRetainedEpochTests.test_barrier_error_never_reuses_a_previous_sample","KernelRetainedEpochTests.test_changed_even_epoch_refuses_and_cannot_be_restored","KernelRetainedEpochTests.test_delayed_barrier_cannot_reset_a_busy_native_deadline","KernelRetainedEpochTests.test_deny_unknown_disabled_refuses_in_fresh_reader_lifetime","KernelRetainedEpochTests.test_duplicate_retention_and_closed_reader_refuse","KernelRetainedEpochTests.test_enforcement_disabled_refuses_in_fresh_reader_lifetime","KernelRetainedEpochTests.test_epoch_change_during_fence_is_rejected","KernelRetainedEpochTests.test_failed_retention_keeps_original_mapping_owned_for_cleanup","KernelRetainedEpochTests.test_inheritable_or_write_access_refuses_before_status_sample","KernelRetainedEpochTests.test_mapping_substitution_closes_only_original_mapping","KernelRetainedEpochTests.test_mutated_expected_status_cannot_reenroll_a_changed_epoch","KernelRetainedEpochTests.test_native_reader_substitution_refuses","KernelRetainedEpochTests.test_odd_sequence_and_changed_controls_refuse","KernelRetainedEpochTests.test_policy_check_still_fresh_opens_hashes_and_closes_policy","KernelRetainedEpochTests.test_policyload_changed_refuses_in_fresh_reader_lifetime","KernelRetainedEpochTests.test_read_only_page_sizes_and_both_abis_remain_explicit","KernelRetainedEpochTests.test_retained_mapping_is_read_only_and_reused_without_fresh_policy_open","KernelRetainedEpochTests.test_status_or_parent_fd_replacement_refuses","KernelRetainedEpochTests.test_status_path_changed_during_sample_is_not_hidden_by_retained_map","KernelRetainedEpochTests.test_uncertain_mapping_close_is_sticky_and_still_closes_policy_fds","KernelRootBoundaryMountTests.test_backward_clock_between_samples_is_refused","KernelRootBoundaryMountTests.test_both_mocked_linux_abis_use_the_same_fixed_root_layout","KernelRootBoundaryMountTests.test_closed_owner_refuses_without_query_or_double_close","KernelRootBoundaryMountTests.test_delayed_success_keeps_original_native_phase_deadline","KernelRootBoundaryMountTests.test_delayed_success_keeps_original_root_phase_deadline","KernelRootBoundaryMountTests.test_dynamic_directory_counters_are_not_mount_identity","KernelRootBoundaryMountTests.test_exception_still_checks_deadline_and_retains_cleanup_owner","KernelRootBoundaryMountTests.test_filesystem_identity_substitution_refuses","KernelRootBoundaryMountTests.test_fixed_queries_retain_descriptors_without_open_mapping_or_syscall","KernelRootBoundaryMountTests.test_frozen_descriptor_inventory_rejects_reordered_rows","KernelRootBoundaryMountTests.test_frozen_filesystem_pins_reject_mutable_alias","KernelRootBoundaryMountTests.test_full_root_reopen_check_remains_required_and_available","KernelRootBoundaryMountTests.test_full_uint64_mount_ids_are_not_json_numbers","KernelRootBoundaryMountTests.test_inheritable_descriptor_is_refused","KernelRootBoundaryMountTests.test_native_replacement_is_refused_and_not_closed_by_sampler","KernelRootBoundaryMountTests.test_query_exception_is_sticky_without_retry","KernelRootBoundaryMountTests.test_reentrant_sampling_poisoned_without_recursive_native_calls","KernelRootBoundaryMountTests.test_retained_mount_change_refuses_even_if_named_view_agrees","KernelRootBoundaryMountTests.test_same_inode_cgroup_replacement_refuses","KernelRootBoundaryMountTests.test_same_inode_current_root_replacement_refuses","KernelRootBoundaryMountTests.test_same_inode_fs_replacement_refuses","KernelRootBoundaryMountTests.test_same_inode_kernel_replacement_refuses","KernelRootBoundaryMountTests.test_same_inode_proc_replacement_refuses","KernelRootBoundaryMountTests.test_same_inode_selinux_replacement_refuses","KernelRootBoundaryMountTests.test_same_inode_sys_replacement_refuses","KernelRootBoundaryMountTests.test_symlink_replacement_is_not_followed","KernelRootBoundaryMountTests.test_writable_descriptor_is_refused","KernelRootBoundaryMountTests.test_wrong_thread_refuses_before_any_query","KernelRootCustodyTests.test_bootstrap_refuses_wrong_filesystem_owner_and_writable_ancestry","KernelRootCustodyTests.test_cleanup_continues_after_error_and_never_retries_released_fd","KernelRootCustodyTests.test_directory_changes_after_statx_and_late_reads_are_refused","KernelRootCustodyTests.test_failed_temporary_acquisition_keeps_original_roots_for_close","KernelRootCustodyTests.test_failure_before_fstat_still_retains_close_ownership","KernelRootCustodyTests.test_fixed_roots_retain_seven_fds_and_reopen_only_fixed_ancestry","KernelRootCustodyTests.test_normal_directory_churn_is_not_identity_drift","KernelRootCustodyTests.test_pid_thread_clock_and_closed_custody_refuse_reopen","KernelRootCustodyTests.test_recycled_descriptor_is_not_closed_and_other_roots_are_retired","KernelRootCustodyTests.test_retained_mount_change_is_refused_before_any_new_open","KernelRootCustodyTests.test_root_acquisition_has_one_deadline_not_one_per_child","KernelRootCustodyTests.test_root_factory_has_no_path_backend_or_descriptor_selector","KernelRootCustodyTests.test_root_path_inode_replacement_is_not_followed_through_old_parent","KernelRootCustodyTests.test_same_inode_bind_replacement_is_caught_by_unique_mount_id","KernelRootCustodyTests.test_statx_fixed_layout_empty_path_and_unique_mount_identity","KernelRootCustodyTests.test_statx_missing_symbol_or_unique_id_never_falls_back","KernelRootCustodyTests.test_statx_rejects_errors_reserved_fields_and_changed_identity","KernelRootCustodyTests.test_symlink_or_missing_root_refusal_closes_only_acquired_descriptors","KernelRootCustodyTests.test_sysfs_child_bind_mounts_and_root_mount_aliases_are_refused","KernelRootCustodyTests.test_temporary_cleanup_failure_remains_sticky_after_originals_close","KernelSelfInspectionTests.test_alternate_owner_and_unsigned_record_refused_before_reader_acquisition","KernelSelfInspectionTests.test_binding_failure_precedes_any_kernel_view","KernelSelfInspectionTests.test_boolean_or_data_success_cannot_replace_reader_contract","KernelSelfInspectionTests.test_cleanup_failure_is_sticky_and_never_retries_close","KernelSelfInspectionTests.test_each_partial_constructor_is_retained_and_closed_on_failure","KernelSelfInspectionTests.test_each_reader_failure_poisoned_and_all_owned_views_closed","KernelSelfInspectionTests.test_early_root_failure_does_not_acquire_other_readers","KernelSelfInspectionTests.test_fixed_composition_uses_authenticated_server_pins_and_current_pid_only","KernelSelfInspectionTests.test_nested_reader_delay_and_wall_jump_are_bounded","KernelSelfInspectionTests.test_original_deadline_and_clock_reversals_refuse_without_observation","KernelSelfInspectionTests.test_parent_binding_or_owner_replacement_closes_existing_views","KernelSelfInspectionTests.test_policy_checks_surround_every_other_component_observation","KernelSelfInspectionTests.test_record_change_during_component_acquisition_closes_partial_owner","KernelSelfInspectionTests.test_recursive_inspection_poisoned_instead_of_reentering_views","KernelSelfInspectionTests.test_replaced_component_never_closes_the_unowned_replacement","KernelSelfInspectionTests.test_retained_authority_file_drift_stops_a_reader_transition","KernelSelfInspectionTests.test_reverse_cleanup_closes_only_owned_readers_and_not_binding_files","KernelSelfInspectionTests.test_same_class_but_unregistered_inspection_cannot_construct","KernelSelfInspectionTests.test_slow_constructor_cannot_reset_the_outer_two_second_budget","KernelSelfInspectionTests.test_startup_keeps_containment_refusal_before_storage_observer_and_credentials","KernelSelfInspectionTests.test_unsupported_page_size_stops_before_code_or_mapping_reads","ObserverInspectionWiringTests.test_inspector_check_failure_prevents_observation","ObserverInspectionWiringTests.test_inspector_close_error_does_not_skip_channel_cleanup","ObserverInspectionWiringTests.test_inspector_constructor_failure_closes_channel_before_any_datagram","ObserverInspectionWiringTests.test_late_timeout_setter_refuses_before_datagram_send","ObserverInspectionWiringTests.test_observer_no_longer_requests_legacy_probe_containment","ObserverInspectionWiringTests.test_replaced_inspector_is_refused_without_closing_foreign_owner","ObserverInspectionWiringTests.test_socket_wait_budgets_exclude_time_spent_in_inspection","ObserverInspectionWiringTests.test_truthy_inspector_result_is_not_containment","ObserverTransportCustodyTests.test_changed_process_start_time_refuses_before_send","ObserverTransportCustodyTests.test_close_error_is_sticky_without_retry_and_other_cleanup_continues","ObserverTransportCustodyTests.test_each_send_exception_runs_post_io_custody_without_retry","ObserverTransportCustodyTests.test_fixed_factory_observes_two_bound_datagrams_without_history_alias","ObserverTransportCustodyTests.test_inheritable_retained_descriptors_refuse_before_send","ObserverTransportCustodyTests.test_invalid_response_never_advances_history","ObserverTransportCustodyTests.test_monotonic_rollback_is_sticky","ObserverTransportCustodyTests.test_mutated_local_process_pin_is_not_new_enrollment","ObserverTransportCustodyTests.test_mutated_observation_history_is_not_accepted_as_a_chain","ObserverTransportCustodyTests.test_one_phase_budget_includes_initial_check_send_receive_and_final_check","ObserverTransportCustodyTests.test_owner_replacement_refuses_before_transport","ObserverTransportCustodyTests.test_partial_constructor_connect_error_closes_only_acquired_socket","ObserverTransportCustodyTests.test_partial_datagram_send_is_ambiguous_and_never_replayed","ObserverTransportCustodyTests.test_pidfd_exceptional_liveness_refuses_before_send","ObserverTransportCustodyTests.test_post_pidfd_acquisition_failure_keeps_cleanup_ownership","ObserverTransportCustodyTests.test_receive_exception_runs_post_io_custody_without_retry","ObserverTransportCustodyTests.test_received_rights_closed_even_when_post_io_authority_fails","ObserverTransportCustodyTests.test_replaced_socket_object_is_refused_and_foreign_socket_not_closed","ObserverTransportCustodyTests.test_reused_pidfd_is_not_closed_and_socket_cleanup_continues","ObserverTransportCustodyTests.test_reused_socket_descriptor_detaches_without_closing_foreign_fd","ObserverTransportCustodyTests.test_session_deadline_is_not_extended_by_new_exchange","ObserverTransportCustodyTests.test_socket_path_replacement_refuses_before_send","ObserverTransportCustodyTests.test_socket_peer_credentials_rechecked_after_receive","ObserverTransportCustodyTests.test_truncated_datagram_is_rejected_by_real_ancillary_parser","ObserverTransportCustodyTests.test_wall_rollback_is_sticky","ProxyPredecessorTests.test_all_127_predecessor_files_preserved_through_closed_successor_stages","ProxyPredecessorTests.test_all_327_exact_predecessor_methods_freshly_collected_without_replacement","ProxyPredecessorTests.test_corrected_checkpoint_preserves_the_original_performance_record","ProxyPredecessorTests.test_current_checkpoint_pin_rejects_relabelled_history_and_altered_inventory","ProxyQualificationTests.test_boolean_control_characters_floats_and_noncanonical_record_bytes_refused","ProxyQualificationTests.test_code_inventory_duplicate_alias_missing_and_conflated_hashes_refused","ProxyQualificationTests.test_endpoint_tuple_pins_and_ambiguous_addresses_refused","ProxyQualificationTests.test_every_nested_record_object_is_closed","ProxyQualificationTests.test_fixed_release_member_preflight_mode_size_digest_and_duplicates","ProxyQualificationTests.test_four_architecture_resource_profiles_and_sixteen_captures_are_data_only","ProxyQualificationTests.test_injected_missing_or_writable_executable_mapping_refused","ProxyQualificationTests.test_inspection_deadlines_expiry_and_clock_renewal_refused","ProxyQualificationTests.test_local_and_effective_programs_both_must_be_exact","ProxyQualificationTests.test_policy_epoch_or_kernel_digest_change_refused","ProxyQualificationTests.test_program_type_alignment_maps_offload_and_missing_hook_refused","ProxyQualificationTests.test_record_rejects_circular_digest_unknown_profile_and_scope_substitution","ProxyQualificationTests.test_retained_pid_start_file_namespace_and_deadline_cannot_change","ProxyQualificationTests.test_unknown_capture_grants_and_wrong_role_never_qualify","ProxyQualificationTests.test_worker_network_and_server_extra_connect_grants_refused","ProxyServerCustodyTests.test_accept_polls_same_listener_without_renewing_phase","ProxyServerCustodyTests.test_accept_retains_connection_when_post_io_policy_fails","ProxyServerCustodyTests.test_accept_slow_trickle_cannot_extend_ten_second_phase","ProxyServerCustodyTests.test_custody_partial_open_failure_closes_acquired_fd_once","ProxyServerCustodyTests.test_factory_accepts_no_caller_backend_descriptor_or_context","ProxyServerCustodyTests.test_files_reject_uncanonical_paths_before_os_open","ProxyServerCustodyTests.test_real_factory_refuses_uninstalled_nonlinux_before_credentials_or_socket","ProxyServerCustodyTests.test_recycled_descriptor_is_not_closed_and_other_cleanup_continues","QualificationBindingTests.test_all_role_preflight_substitutions_refuse_even_when_root_signed","QualificationBindingTests.test_all_role_signature_forgeries_refuse","QualificationBindingTests.test_arm64_ipv6_uses_only_the_signed_numeric_endpoint","QualificationBindingTests.test_artifact_substitution_refuses_for_each_role","QualificationBindingTests.test_caller_data_descriptors_callbacks_or_alternate_owner_cannot_construct","QualificationBindingTests.test_capacity_forgery_refuses_before_release_read","QualificationBindingTests.test_changed_owner_and_file_owner_poison_binding","QualificationBindingTests.test_changed_retained_input_or_record_cannot_refresh_binding","QualificationBindingTests.test_check_deadline_overrun_is_sticky","QualificationBindingTests.test_clock_reversal_and_original_deadline_cannot_be_reset","QualificationBindingTests.test_close_never_closes_borrowed_files_and_refuses_reuse","QualificationBindingTests.test_envelope_forgery_refuses_before_capacity_read","QualificationBindingTests.test_initial_load_cannot_extend_its_two_second_phase","QualificationBindingTests.test_missing_record_or_broker_binding_does_not_fallback","QualificationBindingTests.test_parent_snapshot_does_not_hide_mutated_projection","QualificationBindingTests.test_record_expiry_is_not_extended_to_the_longer_signed_envelope_window","QualificationBindingTests.test_release_signed_broker_peer_digest_substitution_refuses","QualificationBindingTests.test_release_signed_endpoint_substitution_refuses","QualificationBindingTests.test_retained_file_mode_and_owner_are_enforced_before_binding","QualificationBindingTests.test_retained_inode_change_poisoned_even_after_restoration","QualificationBindingTests.test_returned_record_and_broker_are_detached","QualificationBindingTests.test_signed_record_and_all_four_manifests_bind_without_native_authority","QualificationBindingTests.test_unretained_release_tree_member_refuses"],"tests/live_backend/test_replay_store.py":["ReplayStoreTests.test_all_unsigned_reservation_scope_fields_are_validated","ReplayStoreTests.test_backward_time_and_terminal_without_receipt_refuse","ReplayStoreTests.test_concurrent_nonce_reservations_have_at_most_one_success","ReplayStoreTests.test_crash_at_every_append_sync_boundary_never_grants_execution","ReplayStoreTests.test_expiry_is_exclusive_and_cannot_be_reported_early","ReplayStoreTests.test_forged_transition_and_rebound_session_are_refused","ReplayStoreTests.test_full_journal_fails_without_rotation_truncation_or_reset","ReplayStoreTests.test_hash_chain_reordering_and_state_tampering_refuse","ReplayStoreTests.test_nonce_key_cannot_be_reset_by_release_environment_or_command_change","ReplayStoreTests.test_owner_mode_kind_and_hardlink_checks_are_independent","ReplayStoreTests.test_production_constructor_has_no_storage_or_path_injection","ReplayStoreTests.test_reservation_append_sync_readback_before_return","ReplayStoreTests.test_restart_keeps_incomplete_reserved_or_running_nonce_consumed","ReplayStoreTests.test_tenant_and_nonce_keys_are_separate_without_raw_nonce_storage","ReplayStoreTests.test_terminal_lifecycle_is_durable_and_never_releases_nonce","ReplayStoreTests.test_torn_duplicate_noncanonical_oversized_and_nonfinite_journal_refuse"],"tests/live_backend/test_session.py":["BackendAuthorityTests.test_all_command_and_packet_scope_mutations_reject_even_when_signed","BackendAuthorityTests.test_all_signed_envelope_and_capacity_fields_are_closed","BackendAuthorityTests.test_authority_raw_digest_and_canonical_transport_cannot_be_substituted","BackendAuthorityTests.test_binding_uses_all_three_trust_windows_and_no_file_access","BackendAuthorityTests.test_each_selected_key_expiry_is_exclusive_in_direct_authority_adapter","BackendAuthorityTests.test_each_signature_is_required_and_covers_immutable_release_endpoint_bytes","BackendAuthorityTests.test_each_trust_role_owner_scope_revocation_window_and_duplicate_is_checked","BackendAuthorityTests.test_every_capacity_scope_digest_array_and_validity_boundary_is_preserved","BackendAuthorityTests.test_expected_nonce_tenant_environment_release_and_architecture_are_external_bindings","BackendAuthorityTests.test_release_plan_and_proxy_policy_are_checked_even_after_signer_approval","BackendAuthorityTests.test_signed_unsafe_endpoint_values_cannot_expand_network_or_cost_scope","BackendAuthorityTests.test_successor_and_legacy_are_independently_pinned_and_mutually_exclusive","RequestReceiptDataTests.test_all_mandatory_assertions_and_status_aggregation_are_checked","RequestReceiptDataTests.test_each_request_field_is_closed_and_bound_no_url_argv_or_cross_scope","RequestReceiptDataTests.test_every_fixed_case_on_each_architecture_retains_existing_wire_bytes","RequestReceiptDataTests.test_impossible_regression_counts_are_not_valid_failure_receipts","RequestReceiptDataTests.test_only_current_running_data_can_describe_a_request_or_receipt","RequestReceiptDataTests.test_receipt_fields_nonce_probe_command_output_and_observation_are_bound","RequestReceiptDataTests.test_receipts_have_closed_bounded_bytes_and_never_evidence_promotion","RequestReceiptDataTests.test_regression_omission_wrong_inventory_skips_failures_and_false_pass_reject","SessionDataTests.test_all_64_state_edges_are_exact_and_return_proposals_not_sessions","SessionDataTests.test_every_expected_binding_is_required_and_cannot_be_self_asserted","SessionDataTests.test_every_session_field_is_required_closed_and_strictly_typed","SessionDataTests.test_exact_size_and_depth_limits_apply_before_field_validation","SessionDataTests.test_expiry_cannot_be_early_or_replaced_by_success_or_reuse","SessionDataTests.test_half_open_time_window_and_signed_intersection_are_enforced","SessionDataTests.test_identifiers_digests_and_utc_time_grammar_reuse_closed_contract","SessionDataTests.test_independent_canonical_golden_bytes_and_detached_validated_data","SessionDataTests.test_no_verified_flag_fd_or_environment_can_supply_execution_authority","SessionDataTests.test_noncanonical_duplicate_nonfinite_utf8_and_deep_input_fail_closed","SessionDataTests.test_python_objects_subclasses_and_cycles_never_serialize_or_execute","SessionDataTests.test_session_schema_and_runtime_fields_states_and_patterns_agree","SessionDataTests.test_shared_container_expansion_is_bounded_before_canonical_encoding"],"tests/live_backend/test_supervisor.py":["CredentialCleanupTests.test_io_failure_preserves_first_error_and_unproven_cleanup_never_claims_terminal","CredentialCleanupTests.test_recycled_socket_detaches_stale_owner_without_closing_foreign_fd","CredentialCleanupTests.test_retained_credential_expires_before_the_outer_session_deadline","CredentialCleanupTests.test_truthy_policy_return_value_is_not_an_observation_capability","CredentialSourceProofTests.test_actual_and_historical_source_proofs_are_independently_required","CredentialSourceProofTests.test_behavioral_test_rewrite_or_hidden_collection_cannot_fit_source_proof","CredentialSourceProofTests.test_changed_authority_snapshot_scope_and_current_bytes_fail_closed","CredentialSourceProofTests.test_current_inventory_rejects_unrelated_file_mutation_and_partial_future_stage","CredentialSourceProofTests.test_exact_five_paths_and_all_prior_and_added_methods_are_checked","CredentialSupervisorTests.test_close_errors_do_not_retry_recycled_fds_or_skip_other_cleanup","CredentialSupervisorTests.test_duplicate_operation_and_late_direct_access_cannot_reuse_custody","CredentialSupervisorTests.test_foreign_forked_thread_and_substituted_resource_owner_refuse","CredentialSupervisorTests.test_mid_read_expiry_stops_partial_acquisition_and_preserves_first_error","CredentialSupervisorTests.test_post_io_expiry_cancel_and_policy_loss_never_accept_a_receipt","CredentialSupervisorTests.test_unknown_descriptor_during_fixed_hook_is_not_adopted_or_closed","CustodySourceProofTests.test_actual_127_path_inventory_preserves_other_122_complete_file_bytes","CustodySourceProofTests.test_exact_five_path_delta_uses_pinned_data_only_oracle","CustodySourceProofTests.test_oracle_rejects_snapshot_prefix_scope_and_source_substitution","CustodySourceProofTests.test_original_279_methods_and_every_added_method_are_freshly_collected","PerformanceArithmeticTests.test_both_zero_denominator_branches_preserve_total_integer_behavior","PerformanceArithmeticTests.test_canonical_payload_fields_remain_order_independent_and_domain_bound","PerformanceArithmeticTests.test_fixed_three_sample_workload","PerformanceArithmeticTests.test_independent_affine_points_extremes_and_unreduced_coordinates","PerformanceArithmeticTests.test_invalid_lengths_scalar_and_point_encodings_refuse","PerformanceArithmeticTests.test_published_rfc8032_vectors_and_mutations","PerformanceArithmeticTests.test_scalar_extremes_match_independent_addition_reference","PerformanceSourceProofTests.test_all_python_sources_and_four_current_before_historical_consumers_are_bound","PerformanceSourceProofTests.test_benchmark_refuses_ambient_observer_without_replacing_it","PerformanceSourceProofTests.test_benchmark_restores_observer_after_workload_exception","PerformanceSourceProofTests.test_collection_overrides_shadowing_and_oversize_append_refuse","PerformanceSourceProofTests.test_current_custody_is_fresh_on_every_call","PerformanceSourceProofTests.test_current_scalar_hash_bridge_rejects_independently_resealed_mutations","PerformanceSourceProofTests.test_document_prefix_suffix_duplicate_keys_and_oversize_refuse","PerformanceSourceProofTests.test_exact_checkpoint_scope_and_all_fresh_test_roots","PerformanceSourceProofTests.test_exact_scalar_patch_bridge_rejects_independently_resealed_mutations","PerformanceSourceProofTests.test_missing_extra_duplicate_test_identity_refuse","PerformanceSourceProofTests.test_mode_link_duplicate_partial_and_future_inventory_refuse","PerformanceSourceProofTests.test_proof_identity_scope_and_before_after_pins_are_closed","PerformanceSourceProofTests.test_regular_reader_rejects_symlink_hardlink_and_nonregular_sources","PerformanceSourceProofTests.test_required_regression_cannot_be_replaced_by_another_identity","PerformanceSourceProofTests.test_resealed_fixed_bridges_and_old_assertions_refuse","PerformanceSourceProofTests.test_resealed_full_module_observers_refuse","PerformanceSourceProofTests.test_resealed_matched_benchmark_method_changes_refuse","PerformanceSourceProofTests.test_resealed_outside_region_and_forged_before_refuse","PerformanceSourceProofTests.test_unrelated_bytes_and_current_hashes_are_not_exempt","PerformanceSourceProofTests.test_wrong_helper_pin_and_unknown_region_refuse","RetainedSupervisorTests.test_cancel_expiry_failure_and_close_never_reuse_nonce_or_descriptors","RetainedSupervisorTests.test_cleanup_failure_still_releases_remaining_resources_without_terminal_success","RetainedSupervisorTests.test_data_only_mocked_readers_and_cached_digest_never_form_native_context","RetainedSupervisorTests.test_descriptor_injected_after_construction_or_during_io_is_not_admitted","RetainedSupervisorTests.test_each_authority_kit_member_and_full_ancestor_change_refuses_before_hook","RetainedSupervisorTests.test_each_signer_expiry_and_initial_revocation_remain_non_authorizing","RetainedSupervisorTests.test_forged_foreign_subclass_serialized_and_forked_contexts_fail_closed","RetainedSupervisorTests.test_full_native_factory_to_fixed_hook_uses_original_bytes_without_reopening","RetainedSupervisorTests.test_journal_close_failure_does_not_skip_other_owned_descriptors","RetainedSupervisorTests.test_missing_fixed_proxy_module_never_falls_back","RetainedSupervisorTests.test_post_blocking_mutation_refuses_receipt_and_consumes_session","RetainedSupervisorTests.test_proxy_result_after_authority_mutation_is_not_accepted","RetainedSupervisorTests.test_reservation_and_boundary_failures_close_all_custody","RetainedSupervisorTests.test_snapshot_deadline_and_request_tampering_never_reaches_hook","SuccessorCheckpointRepairTests.test_all_five_current_stages_keep_exact_path_and_method_sets","SuccessorCheckpointRepairTests.test_changed_current_predecessor_bytes_refuse","SuccessorCheckpointRepairTests.test_current_correction_is_checked_before_historical_comparison","SuccessorCheckpointRepairTests.test_final_hook_delta_is_verified_not_exempted","SuccessorCheckpointRepairTests.test_legacy_projection_and_corrective_binding_tampering_refuse","SuccessorCheckpointRepairTests.test_missing_duplicate_or_shadowed_methods_refuse","SuccessorCheckpointRepairTests.test_partial_future_and_unapproved_paths_refuse","SuccessorCheckpointRepairTests.test_scope_excludes_runtime_arithmetic_and_benchmark_changes","SupervisorPredecessorTests.test_all_216_immediate_predecessor_ids_are_in_fresh_six_root_discovery","SupervisorPredecessorTests.test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable","SupervisorTests.test_all_ten_operations_complete_once_with_only_unsigned_unit_receipts","SupervisorTests.test_cancel_is_terminal_non_reusable_and_idempotent_close_has_no_new_work","SupervisorTests.test_concurrent_operation_is_rejected_and_cancellation_interrupts_inflight_io","SupervisorTests.test_dictionary_fd_serial_clone_foreign_and_pickled_handles_are_not_authority","SupervisorTests.test_each_ambiguous_reservation_failure_has_no_child_or_execution","SupervisorTests.test_establish_and_kernel_peer_failure_consume_nonce_and_clean_up","SupervisorTests.test_expiry_before_operation_reaps_without_execution","SupervisorTests.test_expiry_during_io_never_returns_a_late_pass","SupervisorTests.test_failed_cleanup_leaves_consumed_running_record_not_a_false_terminal","SupervisorTests.test_forged_envelope_cannot_open_an_unverified_capacity_reference","SupervisorTests.test_malformed_receipt_cannot_promote_native_acceptance","SupervisorTests.test_monotonic_deadline_is_bounded_even_if_wall_clock_stalls","SupervisorTests.test_native_cleanup_failure_still_closes_channel_and_pidfd","SupervisorTests.test_native_factory_has_no_caller_context_backend_or_storage_entry","SupervisorTests.test_native_pre_fork_failure_closes_all_channels_and_gate_descriptors","SupervisorTests.test_only_valid_dual_signed_reference_reaches_capacity_read","SupervisorTests.test_peer_dies_during_io_invalidates_return_and_cleans_tree","SupervisorTests.test_reference_authority_expiry_wrong_packet_and_trust_substitution_fail","SupervisorTests.test_unavailable_operation_remains_unavailable_not_native_or_pass","SupervisorTests.test_unknown_duplicate_and_wrong_architecture_operations_invalidate_session","SupervisorTests.test_wall_clock_rollback_invalidates_but_does_not_rewrite_journal_history"],"tests/meta/test_build_cli.py":["BuildCliTests.test_build_backend_wheel_is_reproducible","BuildCliTests.test_cli_report_and_evidence_are_deterministic","BuildCliTests.test_live_inner_adapter_refuses_direct_and_ci","BuildCliTests.test_reproducible_live_candidate"],"tests/meta/test_campaign.py":["CampaignTests.test_all_handlers_and_non_failing_states_are_exercised","CampaignTests.test_illegal_lifecycle_and_event_fail","CampaignTests.test_required_failure_blocks","CampaignTests.test_required_unavailable_is_honest","CampaignTests.test_two_runs_are_byte_identical","CampaignTests.test_unknown_result_aliases_do_not_exist"],"tests/meta/test_canonical_schema.py":["CanonicalSchemaTests.test_campaign_and_environment_are_closed","CanonicalSchemaTests.test_canonical_bytes_are_stable","CanonicalSchemaTests.test_closed_vocabularies","CanonicalSchemaTests.test_duplicate_and_noncanonical_numbers_are_rejected","CanonicalSchemaTests.test_every_published_schema_is_closed_and_valid_json","CanonicalSchemaTests.test_secure_read_refuses_symlink"],"tests/meta/test_evidence_crypto.py":["EvidenceCryptoTests.test_candidate_is_unsigned_pending_and_digest_bound","EvidenceCryptoTests.test_cli_requires_private_key_mode","EvidenceCryptoTests.test_rfc8032_vector","EvidenceCryptoTests.test_tamper_revocation_scope_and_duplicate_key_fail","EvidenceCryptoTests.test_technical_evidence_sign_and_verify","EvidenceCryptoTests.test_tenant_acceptance_signing_is_forbidden"],"tests/meta/test_live.py":["LiveContractTests.test_capacity_scope_and_window_are_exact","LiveContractTests.test_command_axis_signature_and_capacity_mismatches_fail","LiveContractTests.test_positive_preflight_verifies_every_authority_class","LiveContractTests.test_public_discovered_wildcard_and_metadata_endpoints_fail","LiveContractTests.test_repository_candidate_refuses_ci_and_direct_authority"],"tests/meta/test_porting_zero_bill.py":["PortingZeroBillTests.test_every_copy_claim_is_rejected","PortingZeroBillTests.test_porting_ledger_is_exact_inert_sentinel","PortingZeroBillTests.test_workflow_and_toolchain_are_zero_bill","PortingZeroBillTests.test_zero_bill_scanner_rejects_each_declared_vector"],"tests/meta/test_registry_dispatch.py":["RegistryDispatchTests.test_descriptor_is_closed_direct_argv","RegistryDispatchTests.test_duplicate_campaign_fails_closed","RegistryDispatchTests.test_generic_campaign_has_no_shell_injection","RegistryDispatchTests.test_makefile_never_interpolates_campaign","RegistryDispatchTests.test_packet_campaigns_resolve_additively","RegistryDispatchTests.test_unknown_and_undeclared_dispatch_fail"],"tests/parity/test_adapters.py":["AdapterTests.test_altered_expectation_fails_exact","AdapterTests.test_every_vector_is_deterministic","AdapterTests.test_unknown_family_and_unbound_vector_fail","AdapterTests.test_vector_shape_rejects_command_url_and_credentials"],"tests/parity/test_packet_runner.py":["PacketRunnerTests.test_alias_and_empty_acceptance_are_rejected","PacketRunnerTests.test_current_packet_inline_authority_parses","PacketRunnerTests.test_duplicate_inline_authority_is_rejected","PacketRunnerTests.test_main_preserves_phase_order_and_hides_authority","PacketRunnerTests.test_packet_replacement_is_detected","PacketRunnerTests.test_shell_download_recursive_and_strings_fail","PacketRunnerTests.test_wrong_execution_and_warm_access_fail"],"tests/parity/test_registry.py":["RegistryTests.test_registry_and_vectors_pass_without_source_access","RegistryTests.test_registry_contains_no_content_or_copy_authority","RegistryTests.test_unknown_object_relation_and_binding_fail"],"tests/platform/linux_baseline/test_linux_campaign.py":["LinuxCampaignTests.test_all_handler_views_keep_exact_order_and_no_aliases","LinuxCampaignTests.test_cli_keeps_unavailable_results_and_unsigned_acceptance","LinuxCampaignTests.test_environment_flags_and_session_variables_never_create_native_authority","LinuxCampaignTests.test_legacy_reports_evidence_and_candidates_are_byte_identical_to_predecessor","LinuxCampaignTests.test_twenty_required_cases_are_closed_in_runtime_and_published_schema","LinuxCampaignTests.test_validate_cli_is_explicitly_structural_not_signature_acceptance"],"tests/platform/linux_baseline/test_linux_evidence.py":["LinuxEvidenceTests.test_all_cases_are_required_ordered_and_unique","LinuxEvidenceTests.test_both_native_architecture_vectors_are_unit_only","LinuxEvidenceTests.test_duplicate_json_floats_invalid_utf8_and_malformed_inputs_fail","LinuxEvidenceTests.test_duplicate_keys_changed_trust_bytes_and_same_signers_fail","LinuxEvidenceTests.test_each_missing_check_and_false_pass_is_rejected","LinuxEvidenceTests.test_each_probe_command_output_nonce_and_time_is_bound","LinuxEvidenceTests.test_emulated_cross_arch_and_non_linux_never_qualify","LinuxEvidenceTests.test_every_binding_is_compared_even_with_valid_record_signatures","LinuxEvidenceTests.test_every_record_field_is_mandatory","LinuxEvidenceTests.test_every_signature_is_independently_required","LinuxEvidenceTests.test_every_source_image_build_and_host_binding_is_exact","LinuxEvidenceTests.test_executed_failure_and_missing_environment_remain_distinct","LinuxEvidenceTests.test_expired_future_boundary_and_replay_inputs_fail","LinuxEvidenceTests.test_observation_and_expiration_fit_both_authorizations","LinuxEvidenceTests.test_only_precise_utc_rfc3339_timestamps_are_accepted","LinuxEvidenceTests.test_plan_rejects_missing_extra_or_incomplete_regression_fields","LinuxEvidenceTests.test_regression_inventory_counts_skips_and_hidden_deselection_fail","LinuxEvidenceTests.test_release_tree_paths_modes_sizes_and_baseline_pins_are_closed","LinuxEvidenceTests.test_role_scope_owner_revocation_and_validity_fail_closed","LinuxEvidenceTests.test_unknown_nested_fields_and_verification_booleans_are_rejected"],"tests/platform/linux_baseline/test_linux_inventory.py":["LinuxInventoryTests.test_all_five_suites_collect_every_module_and_preserve_all_83_predecessors","LinuxInventoryTests.test_legacy_comparison_sources_are_pinned_owned_baseline_bytes","LinuxInventoryTests.test_legacy_three_file_edits_and_registry_addition_are_exact","LinuxInventoryTests.test_original_files_are_unchanged_except_ten_authorized_integrations","LinuxInventoryTests.test_pure_verifier_has_no_execution_network_or_signing_primitive"],"tests/platform/linux_baseline/test_linux_protocol.py":["LinuxProtocolTests.test_dual_envelope_commands_axes_endpoint_and_capacity_mismatch_fail","LinuxProtocolTests.test_fake_proxy_is_unit_only_and_cannot_supply_runtime_authority","LinuxProtocolTests.test_proxy_operations_are_fixed_data_only_and_do_not_open_io","LinuxProtocolTests.test_published_schema_covers_all_nested_records_and_plans","LinuxProtocolTests.test_schema_and_runtime_both_reject_structural_mutations","LinuxProtocolTests.test_unknown_operations_and_scope_or_policy_expansion_fail"],"tests/platform/linux_baseline/test_packet_scalars.py":["ScalarAuthorizationTests.test_all_offline_contract_members_are_enforced","ScalarAuthorizationTests.test_boolean_and_null_words_never_authorize_identity","ScalarAuthorizationTests.test_command_order_and_arguments_are_not_normalized","ScalarAuthorizationTests.test_command_phase_types_and_bounds_refuse","ScalarAuthorizationTests.test_extraction_does_not_authorize_wrong_identity","ScalarAuthorizationTests.test_shell_download_and_recursive_transports_refuse","ScalarExecutionTests.test_digest_refusal_stops_before_acceptance","ScalarExecutionTests.test_invalid_identity_fails_before_any_child","ScalarExecutionTests.test_prefetch_order_and_failure_short_circuit_remain","ScalarExecutionTests.test_real_parser_drives_all_six_ordered_mocked_sessions","ScalarIntegrityTests.test_all_103_original_files_and_only_three_additions_remain","ScalarIntegrityTests.test_all_120_predecessor_and_all_new_test_ids_are_collected","ScalarIntegrityTests.test_baseline_history_and_failed_draft_are_not_promoted","ScalarIntegrityTests.test_fixture_and_authority_remain_exact_source_only_inputs","ScalarIntegrityTests.test_fixture_tamper_duplicate_and_nonfinite_values_refuse","ScalarIntegrityTests.test_missing_extra_or_modified_original_inventory_refuses","ScalarIntegrityTests.test_two_exact_source_transformations_preserve_all_other_bytes","ScalarIntegrityTests.test_unapproved_source_mutations_and_unknown_paths_refuse","ScalarParsingTests.test_all_bare_quoted_and_mixed_forms_preserve_values","ScalarParsingTests.test_all_six_published_packets_decode_to_independent_views","ScalarParsingTests.test_bare_indirection_numeric_and_container_values_refuse","ScalarParsingTests.test_duplicate_scalar_and_structured_fields_refuse","ScalarParsingTests.test_field_order_and_outer_yaml_whitespace_preserve_values","ScalarParsingTests.test_identifier_length_and_ascii_grammar_boundaries","ScalarParsingTests.test_json_ascii_escapes_decode_without_reserializing_packet","ScalarParsingTests.test_malformed_quotes_escapes_and_trailing_values_refuse","ScalarParsingTests.test_missing_fields_refuse","ScalarParsingTests.test_non_string_decoder_values_refuse","ScalarParsingTests.test_quoted_control_whitespace_and_non_ascii_refuse","ScalarParsingTests.test_structured_fields_remain_inline_json_only"],"tests/platform/linux_baseline/test_successor_inventory.py":["SuccessorInventoryTests.test_all_seven_complete_stage_vectors","SuccessorInventoryTests.test_current_repository","SuccessorInventoryTests.test_current_test_guard_not_exempt","SuccessorInventoryTests.test_every_missing_stage_path_refuses","SuccessorInventoryTests.test_exact_scalar_test_patch","SuccessorInventoryTests.test_fixture_tamper_and_duplicate_json_refuse","SuccessorInventoryTests.test_hook_prefix_suffix_and_replacement_tamper_refuse","SuccessorInventoryTests.test_hook_proof_identity_digest_type_and_scope_refuse","SuccessorInventoryTests.test_old_guard_rejects_legitimate_stage_one","SuccessorInventoryTests.test_original_106_file_and_150_test_history","SuccessorInventoryTests.test_original_test_ids_and_new_tests_collected","SuccessorInventoryTests.test_out_of_order_and_partial_stages_refuse","SuccessorInventoryTests.test_predecessor_hash_size_and_mode_tampering_refuses","SuccessorInventoryTests.test_premature_hook_or_proof_refuses","SuccessorInventoryTests.test_presence_or_environment_does_not_authorize","SuccessorInventoryTests.test_source_evidence_is_never_native_acceptance","SuccessorInventoryTests.test_stage_six_requires_exact_hook_proof","SuccessorInventoryTests.test_symlinks_hardlinks_and_nonregular_files_refuse","SuccessorInventoryTests.test_test_omissions_skips_and_xfails_refuse","SuccessorInventoryTests.test_unknown_duplicate_and_traversal_paths_refuse"]},"baselineTree":"f5a25661c2df6c87e5d3429b0b5f62511c2e5988","evidenceClass":"SOURCE_DELTA_ONLY","guideIntroduction":"\n\n## CONF-PERF-006 — exact document-validation candidate\n\nStatus: SOURCE_DELTA_ONLY / WAITING_MATCHED_COMPARISON_AND_FULL_ACCEPTANCE.\nAuthority: MET-PERF-012, accepted META 9b8b30b4c0b718d3aa0083d518f4ff5892c7d715.\nProduct baseline: 092fcf475c6f3ebd455e3c354cddb7664ea1f900; no draft is a baseline.\n\nOnly the document function changes: exact built-in bytes with an exact built-in\nint maximum retain all size, canonical, byte-equality and bounded-traversal checks\nbut return the newly parsed value without the redundant final encode/parse.\nThe original fallback remains byte-identical. There is no cache, public API,\ncanonical helper, permission, resource mutation or dependency change.\n\nThe original test/doc prefixes and all 132 other files remain exact. Thirty-two\nindependent regression methods are appended; static expected totals are 1309\noverall and 1139 backend, not claims of test execution. The normalized extension\nhash below replaces only its one proof-hash assignment with 64 zeroes to avoid a\nself-referential digest; all test/helper definitions otherwise remain byte-bound.\nHistorical source is compared as data only and is never compiled or executed.\n\nNext: freeze both exact commits/trees and full file/toolchain inventories. Run\nCONF-BENCH-002 separately in fixed B,C,C,B order, four runs and no retries. Only\ncomplete practical-gain/noise evidence permits the eight-command product LOCAL,\nrequired localhost CI, protected merge and independent LOCAL exact-main gates.\nA candidate change invalidates its comparison; it never resets a consumed budget.\n\nNeither this source proof nor a helper benchmark establishes PR18 improvement,\nnative Linux qualification, artifacts, deployment, runtime or tenant acceptance.\nDraft PRs13/14/15/18 remain untouched. Alpha 2 remains open; effort change NOT_DUE.\n\n| Phase | ID | Status | Description |\n|---|---|---|---|\n| Alpha 2 | MET-PERF-012 | DONE_SOURCE_GATES_RECORDED | Exact META repair authority |\n| Alpha 2 | CONF-PERF-006 | SOURCE_CANDIDATE | This three-path repair, acceptance pending |\n| Alpha 2 | CONF-BENCH-002 | WAITING_EXACT_CANDIDATE_FREEZE | Separate matched comparison |\n| Alpha 2 | CONF-FIX-007 / PR18 | BLOCKED_UNCHANGED | Separate completion-integration authority |\n| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Native probes, packaging and integration |\n| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |\n| Alpha 3 / 4 | Later roadmap | WAITING | Governed actions and enterprise qualification |\n\nThe following closed record is SOURCE_DELTA_ONLY, never execution authority.\n\n","metaCommit":"9b8b30b4c0b718d3aa0083d518f4ff5892c7d715","nativeAcceptance":false,"packetId":"CONF-PERF-006","runtime":{"beforeSha256":"6b9080531cc0e10346982d9ef43ba2caf1b698fcd9577c6b672db8c7faa713b3","beforeSource":"def document(value, maximum=262144):\n    if type(value) is bytes:\n        require(0 < len(value) <= maximum, \"PROXY_DATA_SIZE\")\n        raw, value = value, require_canonical_document(value)\n        require(canonical_bytes(value) == raw, \"PROXY_NONCANONICAL_BYTES\")\n    _bounded(value, maximum)\n    raw = canonical_bytes(value)\n    require(len(raw) <= maximum, \"PROXY_DATA_SIZE\")\n    return require_canonical_document(raw)\n","candidateSha256":"fe3b468872cb14db63f1b2bc1b5c4579703d1e8909c037f8e657ed2d2c26d97c","prefixSha256":"318eda1aaad79a827bc5fe32060b010f087020ee6f32b310d636427a30f8cd83","suffixSha256":"5ff98d1dd3e30928550a2e434c237d687a5b4db92e32b04d5bc40f074075ae00"},"schemaVersion":"planeon.internal.document-source-delta/v1","semanticManifestSha256":"bc6ef8507e1749a6b47b988be5734603d5c21f7a01e68163de0b1ad34cbe15e9","sourceScopeSha256":"b073b8588915edc01b344e5dfe0043a2baec3f116545457a4a6f36ca7ba78dd0","tenantAcceptance":false,"testExtensionSha256":"2403b8fb09775df2ac1c55bbb35d5edb29b35130fbc074027f1303c6842423c9"}
<!-- CONF-PERF-006 SOURCE_DELTA_ONLY END -->


## CONF-FIX-008 — completion integration from accepted main

Alpha 2: SOURCE_CANDIDATE, not accepted or qualified. Authority: MET-REPAIR-018
at `5b082fba8df155782b558d2afe4e902ae361c96c`. This distinct successor starts at
accepted `3a81c8ffb17be9e288c4368d443c57361d5a4fc8`; PR #18 remains untouched.
All earlier status sections and the CONF-PERF-006 proof above are historical
records, not acceptance of this candidate or instructions to resume old budgets.

The five-path integration retains PR #18's reviewed completion delta and the
accepted exact `document()` implementation. All 130 other tracked files stay
byte/mode-identical. The inherited union is 1,599 test identities (1,429 backend).
Eighteen additional current-source regression tests are appended: 1,617 total,
1,447 backend, pending genuine discovery and the complete eight-command recipe.

Only `_doc_current_sources` and the named historical collection test are
adapted. Actual current bytes, closed metadata, immutable paths and the exact
current test identities must pass first; only then are the exact 1,309-test
accepted sources reconstructed as comparison data. The original verifier,
original proof and all other accepted repair method bodies remain unchanged.
No stored source is imported or executed; genuine collection uses current files.

The separate proof below binds normalized current sources, immutable accepted
files, ordered reversible edits and exact test-inventory digests. Only its one
hash assignment is normalized in the admission test; the guide prefix stops
before this new proof. The complete resulting candidate, including those two
regions, must be independently frozen by the external operator before execution.
No source proof, normalization or self-updated digest grants acceptance.

Required next gates: independent C1–C7 symbol/test review on the exact candidate;
full isolated LOCAL; required localhost CI; protected merge; independent exact-main.
The finite allowance is LOCAL2, CI2, exact-main1, with no diagnostic/benchmark
allowance. Preserve the 750/420/900-second and 15-minute limits and old failures.
No retry resets, source overlays, test subsets, skips or native/live effects.

| Phase | ID | Status | Description |
|---|---|---|---|
| Alpha 2 | MET-REPAIR-018 | DONE_SOURCE_GATES_RECORDED | Accepted independent META gates |
| Alpha 2 | CONF-FIX-008 | SOURCE_CANDIDATE | Integration and current-first source accounting; review and acceptance pending |
| Alpha 2 | CONF-FIX-007 / PR #18 | BLOCKED_UNCHANGED | Historical draft; exhausted allowance retained |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Probes, packaging and integrated qualification |
| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 / Alpha 4 | Later packets | WAITING | Governed actions and enterprise qualification |

All native controls remain NOT_RUN_ENV_UNAVAILABLE. There is no product release,
Linux/OpenShift qualification, deployment, runtime assurance or tenant acceptance.
Alpha 2 remains open; no model-effort transition is due.

<!-- CONF-FIX-008 SOURCE_DELTA_ONLY BEGIN -->
{
  "acceptedCommit": "3a81c8ffb17be9e288c4368d443c57361d5a4fc8",
  "acceptedFiles": {
    ".github/workflows/verify.yml": {
      "mode": "100644",
      "sha256": "91090dc69c12837e8b73eb41a868b3afca7dcb34b304c7b409ac716310ddd3a6",
      "size": 615
    },
    ".gitignore": {
      "mode": "100644",
      "sha256": "0672c3d34147eb3a4b4aa4298d4d88f647d6d28aa22cffdb705508df11bda33a",
      "size": 158
    },
    "AGENTS.md": {
      "mode": "100644",
      "sha256": "0b8faaf320feae214a47000b924c9a9c717e73e6d220edf1d16f0ff14381e843",
      "size": 3064
    },
    "CONTRIBUTING.md": {
      "mode": "100644",
      "sha256": "d947eeaf23f47ad60e26bb2e0f236f08a8bd74ca7f8e80d378248ef4477d5964",
      "size": 460
    },
    "LICENSE": {
      "mode": "100644",
      "sha256": "2d3b806e6fd270f11819d0f797f721747adb0d497760e1b9053b6cd1fae4cf54",
      "size": 774
    },
    "Makefile": {
      "mode": "100644",
      "sha256": "bb652db371113bab5d9d8924f0b10b1f85793c0cc84178d447ab1095f4e7b981",
      "size": 661
    },
    "NOTICE": {
      "mode": "100644",
      "sha256": "a70fc36aa7b6f295c4a662b6443a0599c4c89e9b6e62feb29763967d79ce382f",
      "size": 169
    },
    "PORTING.yaml": {
      "mode": "100644",
      "sha256": "69af26b731e28920bb4cc5dd25f6d1d1c18aa75308d75517d6a61f214fa238c4",
      "size": 253
    },
    "README.md": {
      "mode": "100644",
      "sha256": "652e3abc12e4cd6d405eb80018a7c29c68d7d3094c2858196d9b83ea7dd566ea",
      "size": 1228
    },
    "SECURITY.md": {
      "mode": "100644",
      "sha256": "1b5594cb9074fb98aa77768df57aeab45c469b60337ba9662e71367b92aa9cc7",
      "size": 555
    },
    "campaigns/alpha1/campaign.json": {
      "mode": "100644",
      "sha256": "17ad9b40b5518e3432c926b5604073fb922df08be38055310dbc851d1a18cef6",
      "size": 702
    },
    "campaigns/meta/campaign.json": {
      "mode": "100644",
      "sha256": "22091f996b03eae43f8d00da3ec08c85ad12aef2cbb7d0d4ca8b79df8b705386",
      "size": 2341
    },
    "campaigns/parity/campaign.json": {
      "mode": "100644",
      "sha256": "cd2ce011470ffef7dc7a08a4fc994a81f3d2f58899276991e02efb1c431956f4",
      "size": 627
    },
    "campaigns/platform/linux-baseline/campaign.json": {
      "mode": "100644",
      "sha256": "3f4da90f48f61e3ee99b002b969eecbffbe60ac65d650abc82cdc6052df9e50e",
      "size": 5429
    },
    "ci/acceptance_package_contract.py": {
      "mode": "100644",
      "sha256": "e5872ce6a4af9ead7c1cf130e47ca028fb7dc85b63ef5801abae82151938df6d",
      "size": 1753
    },
    "ci/build_live_launcher.py": {
      "mode": "100644",
      "sha256": "873dba7a314405a6ff7c446ee4c0333e34c7cc3400c01141f2c8929dc58c35ad",
      "size": 2425
    },
    "ci/network_canary.py": {
      "mode": "100644",
      "sha256": "8eb07e2c974fd4a5040869ef0eee43963826dc8b32f7dd93fa18a91931e56500",
      "size": 1499
    },
    "ci/prefetch.py": {
      "mode": "100644",
      "sha256": "341e6e102b93e74a0e7b3688ad88faacf4fd23dad2d6100884039d1a207947a1",
      "size": 3824
    },
    "ci/run_make_target.py": {
      "mode": "100644",
      "sha256": "0a0f5c2d6305a1772848ba2e58b8c3d17321de3fe5fdc99377515e09c1138389",
      "size": 5807
    },
    "ci/run_packet.py": {
      "mode": "100644",
      "sha256": "397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1",
      "size": 8302
    },
    "ci/run_packet_argv.py": {
      "mode": "100644",
      "sha256": "523bda5db30faba4c027332a40f36c36e1efdb7e5bd39b68045bcdf817f94fdd",
      "size": 226
    },
    "ci/targets/conf-001.json": {
      "mode": "100644",
      "sha256": "dc2d49619485436c5cf4540b60c5432e847f96433bc60aa3da88577ffa9887b7",
      "size": 692
    },
    "ci/targets/conf-002.json": {
      "mode": "100644",
      "sha256": "0e2d0b28b83567cd5cf8fd46f30a377d255995af4450f4675ae08bf27fd757c1",
      "size": 339
    },
    "ci/trust/live-runner-root.pub": {
      "mode": "100644",
      "sha256": "6b22a99cab70c60b7cc345962ae220e32b2dbc89c72b419c79a9c92ec5f6c012",
      "size": 82
    },
    "ci/verify-live-campaign.py": {
      "mode": "100644",
      "sha256": "ed7fa0f9a5d933c257a93f9be9ac5a3321c0b2451aa31e0f698a6053e8f46004",
      "size": 630
    },
    "ci/verify-offline.sh": {
      "mode": "100755",
      "sha256": "b058780b727d2e4c7b5f77d3c7f623a7dafdac621c5b505238297e2ea2524c47",
      "size": 912
    },
    "ci/zero_bill.py": {
      "mode": "100644",
      "sha256": "6e9c7f5aa2ea527a1b1d9472bbab164be4ba051f27dae90005695ff3f04cda14",
      "size": 2177
    },
    "docs/live-backend/linux-boundary.md": {
      "mode": "100644",
      "sha256": "157a7733b5df9dddc656d086f54e585b1508ef161e6849cdcc54cebc0b1ed7b3",
      "size": 1697376
    },
    "docs/live-backend/proxy.md": {
      "mode": "100644",
      "sha256": "e76fdcf46628e175bc641057e36a5daec1268c6bf55f4c1784c1b747d4710ad1",
      "size": 232252
    },
    "docs/live-backend/session.md": {
      "mode": "100644",
      "sha256": "41319d8f1a7fa9441fded7efe23c8254929cc5ea15d7d1f59c125e33b29fc767",
      "size": 10811
    },
    "docs/parity.md": {
      "mode": "100644",
      "sha256": "70fb8b95ee95eb7219c3b9ed0eea4c00c280ecf93dba6765418fa559d92b8dc4",
      "size": 1083
    },
    "docs/reports/alpha1-template.md": {
      "mode": "100644",
      "sha256": "70f572dc3d3fef6d45e14c93c09352aea9b7bbdad189cc5167e3d57628c933a9",
      "size": 2179
    },
    "docs/reports/linux-baseline.md": {
      "mode": "100644",
      "sha256": "99096cc71b49d662cb3c1a71137724eb1748aa633a7a24c8b56fa4b467605919",
      "size": 10913
    },
    "docs/reports/packet-scalar-repair.md": {
      "mode": "100644",
      "sha256": "d824ddb953d31f1a20e19951ef743611e1943f5b6b8d6fe4679721d3146e355a",
      "size": 6081
    },
    "docs/reports/runner-boundary-repair.md": {
      "mode": "100644",
      "sha256": "e5700f158b640364f15565cbbea8dee7e86e88c045c8cde07cfaa8fe77a525bf",
      "size": 6595
    },
    "docs/reports/successor-inventory-repair.md": {
      "mode": "100644",
      "sha256": "c930632d1e8674d9516976a5d07d385ac6211ade937fd16b6b875607f8498ab2",
      "size": 7131
    },
    "fixtures/alpha1/environment-unavailable.json": {
      "mode": "100644",
      "sha256": "71ae29d6bafffc062dcaa358929cdc5224d29f415b6a3a327714f9013dca345d",
      "size": 244
    },
    "fixtures/alpha1/journey.json": {
      "mode": "100644",
      "sha256": "0399a95811cafc48c8deae07b45fadb8082b3be99db838da8b09fbddc1614bd8",
      "size": 7677
    },
    "fixtures/alpha1/overview.json": {
      "mode": "100644",
      "sha256": "c840c2f0c8e3094cdaaa08a10ea57d859d969c24546c3a23107189e63d7b626b",
      "size": 12726
    },
    "fixtures/environments/meta-complete.json": {
      "mode": "100644",
      "sha256": "6ea4589266ff02ea3c42bf86d72ac5bca9c593203bf35177ecb7da4ab2df1cbe",
      "size": 225
    },
    "fixtures/environments/meta-unavailable.json": {
      "mode": "100644",
      "sha256": "3bec392601ed731f34f00dd55c835986b758a501d54a1ac0213d1e85eb8e2838",
      "size": 207
    },
    "fixtures/live-backend/baseline.json": {
      "mode": "100644",
      "sha256": "c3dd610a748e018c9e015668567fbea9820a050022dc33375912f8f4aaa51a00",
      "size": 174441
    },
    "fixtures/live-backend/proxy-vectors.json": {
      "mode": "100644",
      "sha256": "ba3cff195f1f615fddb98e2db6713c359d8dbd05699cb1710157fe374b27760f",
      "size": 500997
    },
    "fixtures/live-backend/session-vectors.json": {
      "mode": "100644",
      "sha256": "4999510bbaba2ae4faed7b9afa6d17ba3bbecb733f40f7bf92c69a6d9313a3fd",
      "size": 2822
    },
    "fixtures/platform/linux-baseline/environment-unavailable.json": {
      "mode": "100644",
      "sha256": "c79b375f07694835f616b51243b92305b96f29088424673457582103078307aa",
      "size": 219
    },
    "fixtures/platform/linux-baseline/predecessor-inventory.json": {
      "mode": "100644",
      "sha256": "f47c088f150ce7c61a14707aad71c634001037fd423eb43ace3acb055be86a58",
      "size": 18630
    },
    "fixtures/platform/linux-baseline/predecessor-sources.json": {
      "mode": "100644",
      "sha256": "3fb88e3358c25fb65369e73a3decf9fe111797b1f44b2cc1deeabea8c5d8defc",
      "size": 23010
    },
    "fixtures/platform/linux-baseline/scalar-repair.json": {
      "mode": "100644",
      "sha256": "0e04f3878efd8196fc33aa47a80ecbf5a48e7df262f08b98030acfd4c565fd06",
      "size": 114585
    },
    "fixtures/platform/linux-baseline/successor-inventory.json": {
      "mode": "100644",
      "sha256": "44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86",
      "size": 171701
    },
    "parity/adapters/run_parity.py": {
      "mode": "100644",
      "sha256": "650c17312390ec0f4382dad3c9279be0bb50522374c7ec01a079d9a7db8eefac",
      "size": 4849
    },
    "parity/adapters/validate_registry.py": {
      "mode": "100644",
      "sha256": "14d00741194d4de4bd3e14adb2829b3612217b9185905220ff8d6c0be39c12d9",
      "size": 6185
    },
    "parity/registry.yaml": {
      "mode": "100644",
      "sha256": "0fac00ae1575b5c86996d32f3a9f01a69f6d77743170df1ecf6aff7243569af5",
      "size": 5544
    },
    "parity/vectors/data-batch-lineage.json": {
      "mode": "100644",
      "sha256": "67c46555d13dd0b48f2e7fe8cbad9f09da7708baf816527f32ea9e96eb264d2d",
      "size": 239
    },
    "parity/vectors/data-connector-closed-discovery.json": {
      "mode": "100644",
      "sha256": "86279c3564392e353ba8537c2cba9d11f4449fc140a02398a146fd6f73e47de0",
      "size": 240
    },
    "parity/vectors/data-local-only-no-fallback.json": {
      "mode": "100644",
      "sha256": "fe3698e550940e90f71d497d0e0024ad99dbc8026684e77ebecb666b1577904f",
      "size": 207
    },
    "parity/vectors/model-route-fail-closed.json": {
      "mode": "100644",
      "sha256": "6eb0342fea804721e30ed38657d44c1578d20b4f829b76a3215df635f504a5de",
      "size": 198
    },
    "parity/vectors/model-upstream-bounded-retry.json": {
      "mode": "100644",
      "sha256": "f0a3cdf305e1f63f0edd05e074373cf6f98f09063bed101a100a74b3b920e854",
      "size": 192
    },
    "parity/vectors/model-usage-tenant-neutral.json": {
      "mode": "100644",
      "sha256": "410f55e3e3453a19754c52cecb689349aba41a95b015aceca7d35ff2e4f9f1ce",
      "size": 299
    },
    "parity/vectors/white-goods-foundation-boundary.json": {
      "mode": "100644",
      "sha256": "49f3a5a70f32c00cebc69594832300939942dc6b80f8a57d60f2c577e728ac2d",
      "size": 277
    },
    "pyproject.toml": {
      "mode": "100644",
      "sha256": "4180e069f0bfb7b38f99b367f9a6f29e914a61717bd0797343f3d2b99720409c",
      "size": 500
    },
    "schemas/v1alpha1/campaign-release.schema.json": {
      "mode": "100644",
      "sha256": "50053c212b0e9a40dcf4e7dd4c155c8c3da6a81a77a82ae7f59aadc2d6d0cfa9",
      "size": 1189
    },
    "schemas/v1alpha1/campaign-report.schema.json": {
      "mode": "100644",
      "sha256": "3e775c55dbc5dff84fb5aab90525814ef03595a69583e8239640583cac7036a9",
      "size": 1073
    },
    "schemas/v1alpha1/conformance-campaign.schema.json": {
      "mode": "100644",
      "sha256": "dd4fb4f5fda756613d5f69056460abdbd05b675dbddb4c9606bc9324321bb89f",
      "size": 10324
    },
    "schemas/v1alpha1/conformance-trust-bundle.schema.json": {
      "mode": "100644",
      "sha256": "587e9e4fcc48fa98cf316b73a3cccabd9713fa0cbae48067f5f43f181404c245",
      "size": 1151
    },
    "schemas/v1alpha1/control-result.schema.json": {
      "mode": "100644",
      "sha256": "2113a19ec9e077dcb7ab6f2c299c4756d09b0d1e3d3a32195d2103ff8d54e182",
      "size": 1056
    },
    "schemas/v1alpha1/environment-intake.schema.json": {
      "mode": "100644",
      "sha256": "b69ef4bda6fe209b0416ef1c250747a38179d4cef0cf9bc8c72b1f0de1e3d621",
      "size": 776
    },
    "schemas/v1alpha1/linux-readiness-evidence.schema.json": {
      "mode": "100644",
      "sha256": "8f4cf17273b097e39420b2394be43259c9bea30b684a58bcdc739c60b5059c0e",
      "size": 61742
    },
    "schemas/v1alpha1/live-backend-session.schema.json": {
      "mode": "100644",
      "sha256": "7c4ad7c69feb4e9e9f8509f2cdd6c1bcccbf8acb60711810c2e0df8ef7cb737d",
      "size": 2504
    },
    "schemas/v1alpha1/live-campaign-execution-envelope.schema.json": {
      "mode": "100644",
      "sha256": "d4720d28fd0cfb8f4979f8d1bb808c5244c6e8121c4a97b0303cfed033c4d1fd",
      "size": 4272
    },
    "schemas/v1alpha1/live-capacity-authorization.schema.json": {
      "mode": "100644",
      "sha256": "196cafdba0cc168b8dbab7cb02aeda003b1b0cb2f0ae8e9b233b883629949235",
      "size": 2177
    },
    "schemas/v1alpha1/technical-evidence-bundle.schema.json": {
      "mode": "100644",
      "sha256": "0d1e7ad8413733c63b18bb0b658a93f541800c604b2f56c8842fe4ac7760d513",
      "size": 1524
    },
    "schemas/v1alpha1/tenant-acceptance-candidate.schema.json": {
      "mode": "100644",
      "sha256": "37c57329bb835d7aa091be9de41bcfaed9305b1e0359ec1289d114f31bbf426a",
      "size": 995
    },
    "src/harness_conformance/__init__.py": {
      "mode": "100644",
      "sha256": "748cd4a32689b1856ef53f51793e3f85303a25658846bb9a6965440ceeed769f",
      "size": 236
    },
    "src/harness_conformance/__main__.py": {
      "mode": "100644",
      "sha256": "935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d",
      "size": 48
    },
    "src/harness_conformance/acceptance.py": {
      "mode": "100644",
      "sha256": "81a562a983f1d662e78d95d7e3e29f070471b3e304c13bac5162e0b05108c933",
      "size": 2613
    },
    "src/harness_conformance/build_backend.py": {
      "mode": "100644",
      "sha256": "d7ed81b4e0ffd865093679ef51a033a7bc74024b20300b098520306a05243e99",
      "size": 2399
    },
    "src/harness_conformance/campaign.py": {
      "mode": "100644",
      "sha256": "da0a25fba8336f658948ab1018a9db5c518bcc52849bdfcf295058906a26272a",
      "size": 7026
    },
    "src/harness_conformance/canonical.py": {
      "mode": "100644",
      "sha256": "eb16aee5dda8f512b78b637361f0a057c7e944cd1b9eb888c88182c867e7794d",
      "size": 5645
    },
    "src/harness_conformance/cli.py": {
      "mode": "100644",
      "sha256": "c6fe0356d835db4bb0ae43d2484ca107f32bbf9046ff04c1a5a5ab47703ce8c1",
      "size": 4482
    },
    "src/harness_conformance/crypto.py": {
      "mode": "100644",
      "sha256": "bf4cd892d5a7b0dd38bf38b88f72657821d7f21575fce450e60a5a13950c0ca9",
      "size": 5148
    },
    "src/harness_conformance/errors.py": {
      "mode": "100644",
      "sha256": "c30216c02cfa449063b77ca922a3c7cd32e0c6a8010365e093d730e7bc37807a",
      "size": 308
    },
    "src/harness_conformance/events.py": {
      "mode": "100644",
      "sha256": "2cc8855e5fe02c9874e3653b5f094b4095eed483e2446ba32735ddc57c6b422a",
      "size": 2197
    },
    "src/harness_conformance/evidence.py": {
      "mode": "100644",
      "sha256": "670a8c4f6b06caf8af7749b0fe5bf6210d746cd6a823430a387890add135b3e6",
      "size": 7683
    },
    "src/harness_conformance/lifecycle.py": {
      "mode": "100644",
      "sha256": "86c7f62bea77d963e087d2b244f8479a5a81bd1dac8ab5ec5579ad9b0a35f69c",
      "size": 1582
    },
    "src/harness_conformance/linux_readiness.py": {
      "mode": "100644",
      "sha256": "1d40b52a05a85cf0d2179d5545bc8325b8035a24340c5a52b8b66f28e0476fc8",
      "size": 22629
    },
    "src/harness_conformance/live.py": {
      "mode": "100644",
      "sha256": "8f6d033292801930cd280f3611aed3c6012cf4d39ec63d4324eb92590e44a022",
      "size": 23002
    },
    "src/harness_conformance/live_backend_authority.py": {
      "mode": "100644",
      "sha256": "b57f241e1c0c76be3d86682e9a1a1d62f40115aaa917d2e124d589c84880e42d",
      "size": 9916
    },
    "src/harness_conformance/live_launcher.py": {
      "mode": "100644",
      "sha256": "0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27",
      "size": 5281
    },
    "src/harness_conformance/live_linux_boundary.py": {
      "mode": "100644",
      "sha256": "7c590b4078e4bd024c0798749f5d1e1197f9a30c15cc6d1a2b0d7b9131ae54fe",
      "size": 52544
    },
    "src/harness_conformance/live_mutation_admission.py": {
      "mode": "100644",
      "sha256": "7a9b2170e99bb7b50ad5e17090a12f42876b7f463d661d8d2b0d83c7d27262fe",
      "size": 138318
    },
    "src/harness_conformance/live_proxy_client.py": {
      "mode": "100644",
      "sha256": "f82bf0fe70c3782db1cec798b3d4a3fe2b36be68e4ae9ffe56b6e600895b24ff",
      "size": 18956
    },
    "src/harness_conformance/live_proxy_server.py": {
      "mode": "100644",
      "sha256": "ee5435b63d9dc515992cde29c7dd3cd0aeddd81de7b9c865643a8b8d3ffd5ae9",
      "size": 269008
    },
    "src/harness_conformance/live_replay_store.py": {
      "mode": "100644",
      "sha256": "ff512b35ce7761b5dccc2c57989a6888b0daa9c99fba404f7be0be6878dae3f7",
      "size": 10076
    },
    "src/harness_conformance/live_session.py": {
      "mode": "100644",
      "sha256": "dc15ebe6d919093cb1842c77c19c9e7846d7ef62e3b04946114824befa9e4454",
      "size": 12361
    },
    "src/harness_conformance/live_supervisor.py": {
      "mode": "100644",
      "sha256": "4dfeb1780c5fc6b2e116f027fbbde6b8a0fec401911f11c4f45900e7ad84b03e",
      "size": 38977
    },
    "src/harness_conformance/models.py": {
      "mode": "100644",
      "sha256": "3d095046632c640bd679b730cc76c90276a73c18263de227ad8a5692c34730dc",
      "size": 1430
    },
    "src/harness_conformance/registry.py": {
      "mode": "100644",
      "sha256": "fa32c26a773a93d60c3f1cd512a99d1213258f944846e028bf7c92aca7049139",
      "size": 1595
    },
    "src/harness_conformance/schema.py": {
      "mode": "100644",
      "sha256": "cd3fefc33833cf5fbccb97a0ac75524ecd967cfa10064a79f64a837f75397ee5",
      "size": 9908
    },
    "tests/alpha1/__init__.py": {
      "mode": "100644",
      "sha256": "1c4b4913127e929661e104454b7900591e39681401eb19594436b1a860c49a6a",
      "size": 48
    },
    "tests/alpha1/contract.py": {
      "mode": "100644",
      "sha256": "20034c14d493cac5f730440b27833c5fa87722fda0a1574ce0f81836764749a7",
      "size": 16927
    },
    "tests/alpha1/test_alpha1.py": {
      "mode": "100644",
      "sha256": "b528290f311a5e41e2b163028bb5212a022d15319a7a9fb218fd7e272480e9c7",
      "size": 7371
    },
    "tests/fixes/runner_boundary/_inventory.py": {
      "mode": "100644",
      "sha256": "fb50aba04fe963a89b74ad1aca57b1242fa54481e01989ac18a189a080ade94c",
      "size": 2443
    },
    "tests/fixes/runner_boundary/legacy-tests.json": {
      "mode": "100644",
      "sha256": "9fff3fb6bd66789b18bc8f38885d2bfd287124f9a32b4f7a0d645c27ee500dbd",
      "size": 4603
    },
    "tests/fixes/runner_boundary/test_boundaries.py": {
      "mode": "100644",
      "sha256": "2e33efe165cf46912a426285dabd0bbe98b17acdf18f3d7a8bf3cb56a71247e4",
      "size": 15192
    },
    "tests/fixes/runner_boundary/test_inventory.py": {
      "mode": "100644",
      "sha256": "1fbacb25aea922a37fb552e91f6b95dded7c1774d1ba2a80f5989cd926cad5e6",
      "size": 3569
    },
    "tests/live_backend/_fixtures.py": {
      "mode": "100644",
      "sha256": "edec764c067e538fa9709dc7dce59a357ae996ba36c6121482cc3b24d86b8a28",
      "size": 3383
    },
    "tests/live_backend/_inventory.py": {
      "mode": "100644",
      "sha256": "d341edcdf49dadf182c3fcc9926d373d13c83aa004d3cc74363312861a7f1e46",
      "size": 4839
    },
    "tests/live_backend/test_inventory.py": {
      "mode": "100644",
      "sha256": "f128f05fc395c26de0c13c34953bfff297fa64f857f3f70aab56dbc9e3bcc8a1",
      "size": 10197
    },
    "tests/live_backend/test_linux_boundary.py": {
      "mode": "100644",
      "sha256": "06d16e4c833dc818a084b655b4f767dbe601212adc9525c47dc94241c32ee238",
      "size": 62720
    },
    "tests/live_backend/test_mutation_admission.py": {
      "mode": "100644",
      "sha256": "1754bed560ce691b8cdc41db288549c712428f2f2ada843c2a578088307bf1f1",
      "size": 59988
    },
    "tests/live_backend/test_proxy_client.py": {
      "mode": "100644",
      "sha256": "90399c359d8e97fa526597b8097b5d73bf052e02f48b3fa6fad6db5453729227",
      "size": 21302
    },
    "tests/live_backend/test_proxy_server.py": {
      "mode": "100644",
      "sha256": "05e715db5e27b4560dc397ad15f4522490a9122e8efd0daa52563db1cd8f4a3c",
      "size": 498101
    },
    "tests/live_backend/test_replay_store.py": {
      "mode": "100644",
      "sha256": "492d6569edb1d271199a3d52b93e82f7295ae478d90b01376125313ee1af8213",
      "size": 9971
    },
    "tests/live_backend/test_session.py": {
      "mode": "100644",
      "sha256": "4348b898c1d8cab9fbc94b7bfceff5442a21c0e49fc2645277ae706506c25e90",
      "size": 32978
    },
    "tests/live_backend/test_supervisor.py": {
      "mode": "100644",
      "sha256": "2c6fc822b453e57f0354e2a6876b016ea9d536216e77b2390f1026befaef7db1",
      "size": 295260
    },
    "tests/meta/test_build_cli.py": {
      "mode": "100644",
      "sha256": "989c58c63a8cc5234e0396c4bee1c667da133c6893ca24dd96bd95822f43a4e6",
      "size": 2781
    },
    "tests/meta/test_campaign.py": {
      "mode": "100644",
      "sha256": "85fc9c47556fa0db78ed1948cba696cea0da9d895848169785d227a6e66efc8d",
      "size": 3007
    },
    "tests/meta/test_canonical_schema.py": {
      "mode": "100644",
      "sha256": "f3c233226c5dc400f225eeb16bde754fd73b3e332a2cc85c7795571537845a35",
      "size": 3187
    },
    "tests/meta/test_evidence_crypto.py": {
      "mode": "100644",
      "sha256": "b0b87f6e4f726ebc7af82be7ab9b6b83a73ec130e1559cb5d9800396b91436c4",
      "size": 4501
    },
    "tests/meta/test_live.py": {
      "mode": "100644",
      "sha256": "9ac39858b40468a10b2a20ae43e0aaa92f64fde6ab63d275143d654774ec10a3",
      "size": 11715
    },
    "tests/meta/test_porting_zero_bill.py": {
      "mode": "100644",
      "sha256": "f8ed0fdffc245541d332d78c66d6e9045c3bfc85e0683c3cb7e87b263c1bd448",
      "size": 4182
    },
    "tests/meta/test_registry_dispatch.py": {
      "mode": "100644",
      "sha256": "b021ddeb2a7a534427edf7db594b0d9532711bec4fcfac76405dcded73adbc1d",
      "size": 3756
    },
    "tests/parity/test_adapters.py": {
      "mode": "100644",
      "sha256": "9e4217daee3c0e6f5f7dc0a292c4ff55cb1a3b7259b477ee65dfc13315e49c4a",
      "size": 2337
    },
    "tests/parity/test_packet_runner.py": {
      "mode": "100644",
      "sha256": "0054ccd9312c59a77194a17152191a80bc82d98a5b27ee6e83183b2e62bf7d97",
      "size": 6066
    },
    "tests/parity/test_registry.py": {
      "mode": "100644",
      "sha256": "88d007d59c2da7dc45fdb4da0d7787725ff6a4d6d120a7f38d843a94baf2b5ff",
      "size": 2638
    },
    "tests/platform/linux_baseline/_fixtures.py": {
      "mode": "100644",
      "sha256": "579ff77d11e66776884ccf4a3343c417393767215b09abc5aacc1a19c10bcb7d",
      "size": 11573
    },
    "tests/platform/linux_baseline/_successor_inventory.py": {
      "mode": "100644",
      "sha256": "0ab36ab0055b72d25dced1d0339a1dbacfafe29ea450b2935c171912405ea733",
      "size": 63700
    },
    "tests/platform/linux_baseline/test_linux_campaign.py": {
      "mode": "100644",
      "sha256": "e4501ef5df6a3a1e9f3755aee40592f81ccdcab069d187215f612b97f9773094",
      "size": 8618
    },
    "tests/platform/linux_baseline/test_linux_evidence.py": {
      "mode": "100644",
      "sha256": "b6e162808c471d3d2ed7caa2ed2c056af33819d91ae46a66ff5298da982912b3",
      "size": 14548
    },
    "tests/platform/linux_baseline/test_linux_inventory.py": {
      "mode": "100644",
      "sha256": "3fdd36f47cfb3deb7edaab8685dbead5c90519a92844b5bc2266441d5160c338",
      "size": 5683
    },
    "tests/platform/linux_baseline/test_linux_protocol.py": {
      "mode": "100644",
      "sha256": "2057b427ba366717c506d561978695e27b53208b4e3fbf318b00671fe672254d",
      "size": 8232
    },
    "tests/platform/linux_baseline/test_packet_scalars.py": {
      "mode": "100644",
      "sha256": "c2ce177f7a462abcae70ae5c51cc2c50d1a3041dc7b9afa527a2e0c582932fe9",
      "size": 27287
    },
    "tests/platform/linux_baseline/test_successor_inventory.py": {
      "mode": "100644",
      "sha256": "46417d8566acedf4c60e396dfe27dcd94743e288eda9f1aeea2db5c27efd0b9e",
      "size": 21048
    },
    "toolchain.lock": {
      "mode": "100644",
      "sha256": "40a0cbb9fc244a8484b22494b6bfa070fbc76aec0edd86ab690026f6a8027bfc",
      "size": 2153
    },
    "uv.lock": {
      "mode": "100644",
      "sha256": "bd9cb528f2c6ad6a74e3dc1998978e029144fcee2535387cc5ef3db7907dcfbc",
      "size": 150
    }
  },
  "backendCount": 1447,
  "currentCount": 1617,
  "currentFiles": {
    ".github/workflows/verify.yml": {
      "mode": "100644",
      "sha256": "91090dc69c12837e8b73eb41a868b3afca7dcb34b304c7b409ac716310ddd3a6",
      "size": 615
    },
    ".gitignore": {
      "mode": "100644",
      "sha256": "0672c3d34147eb3a4b4aa4298d4d88f647d6d28aa22cffdb705508df11bda33a",
      "size": 158
    },
    "AGENTS.md": {
      "mode": "100644",
      "sha256": "0b8faaf320feae214a47000b924c9a9c717e73e6d220edf1d16f0ff14381e843",
      "size": 3064
    },
    "CONTRIBUTING.md": {
      "mode": "100644",
      "sha256": "d947eeaf23f47ad60e26bb2e0f236f08a8bd74ca7f8e80d378248ef4477d5964",
      "size": 460
    },
    "LICENSE": {
      "mode": "100644",
      "sha256": "2d3b806e6fd270f11819d0f797f721747adb0d497760e1b9053b6cd1fae4cf54",
      "size": 774
    },
    "Makefile": {
      "mode": "100644",
      "sha256": "bb652db371113bab5d9d8924f0b10b1f85793c0cc84178d447ab1095f4e7b981",
      "size": 661
    },
    "NOTICE": {
      "mode": "100644",
      "sha256": "a70fc36aa7b6f295c4a662b6443a0599c4c89e9b6e62feb29763967d79ce382f",
      "size": 169
    },
    "PORTING.yaml": {
      "mode": "100644",
      "sha256": "69af26b731e28920bb4cc5dd25f6d1d1c18aa75308d75517d6a61f214fa238c4",
      "size": 253
    },
    "README.md": {
      "mode": "100644",
      "sha256": "652e3abc12e4cd6d405eb80018a7c29c68d7d3094c2858196d9b83ea7dd566ea",
      "size": 1228
    },
    "SECURITY.md": {
      "mode": "100644",
      "sha256": "1b5594cb9074fb98aa77768df57aeab45c469b60337ba9662e71367b92aa9cc7",
      "size": 555
    },
    "campaigns/alpha1/campaign.json": {
      "mode": "100644",
      "sha256": "17ad9b40b5518e3432c926b5604073fb922df08be38055310dbc851d1a18cef6",
      "size": 702
    },
    "campaigns/meta/campaign.json": {
      "mode": "100644",
      "sha256": "22091f996b03eae43f8d00da3ec08c85ad12aef2cbb7d0d4ca8b79df8b705386",
      "size": 2341
    },
    "campaigns/parity/campaign.json": {
      "mode": "100644",
      "sha256": "cd2ce011470ffef7dc7a08a4fc994a81f3d2f58899276991e02efb1c431956f4",
      "size": 627
    },
    "campaigns/platform/linux-baseline/campaign.json": {
      "mode": "100644",
      "sha256": "3f4da90f48f61e3ee99b002b969eecbffbe60ac65d650abc82cdc6052df9e50e",
      "size": 5429
    },
    "ci/acceptance_package_contract.py": {
      "mode": "100644",
      "sha256": "e5872ce6a4af9ead7c1cf130e47ca028fb7dc85b63ef5801abae82151938df6d",
      "size": 1753
    },
    "ci/build_live_launcher.py": {
      "mode": "100644",
      "sha256": "873dba7a314405a6ff7c446ee4c0333e34c7cc3400c01141f2c8929dc58c35ad",
      "size": 2425
    },
    "ci/network_canary.py": {
      "mode": "100644",
      "sha256": "8eb07e2c974fd4a5040869ef0eee43963826dc8b32f7dd93fa18a91931e56500",
      "size": 1499
    },
    "ci/prefetch.py": {
      "mode": "100644",
      "sha256": "341e6e102b93e74a0e7b3688ad88faacf4fd23dad2d6100884039d1a207947a1",
      "size": 3824
    },
    "ci/run_make_target.py": {
      "mode": "100644",
      "sha256": "0a0f5c2d6305a1772848ba2e58b8c3d17321de3fe5fdc99377515e09c1138389",
      "size": 5807
    },
    "ci/run_packet.py": {
      "mode": "100644",
      "sha256": "397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1",
      "size": 8302
    },
    "ci/run_packet_argv.py": {
      "mode": "100644",
      "sha256": "523bda5db30faba4c027332a40f36c36e1efdb7e5bd39b68045bcdf817f94fdd",
      "size": 226
    },
    "ci/targets/conf-001.json": {
      "mode": "100644",
      "sha256": "dc2d49619485436c5cf4540b60c5432e847f96433bc60aa3da88577ffa9887b7",
      "size": 692
    },
    "ci/targets/conf-002.json": {
      "mode": "100644",
      "sha256": "0e2d0b28b83567cd5cf8fd46f30a377d255995af4450f4675ae08bf27fd757c1",
      "size": 339
    },
    "ci/trust/live-runner-root.pub": {
      "mode": "100644",
      "sha256": "6b22a99cab70c60b7cc345962ae220e32b2dbc89c72b419c79a9c92ec5f6c012",
      "size": 82
    },
    "ci/verify-live-campaign.py": {
      "mode": "100644",
      "sha256": "ed7fa0f9a5d933c257a93f9be9ac5a3321c0b2451aa31e0f698a6053e8f46004",
      "size": 630
    },
    "ci/verify-offline.sh": {
      "mode": "100755",
      "sha256": "b058780b727d2e4c7b5f77d3c7f623a7dafdac621c5b505238297e2ea2524c47",
      "size": 912
    },
    "ci/zero_bill.py": {
      "mode": "100644",
      "sha256": "6e9c7f5aa2ea527a1b1d9472bbab164be4ba051f27dae90005695ff3f04cda14",
      "size": 2177
    },
    "docs/live-backend/linux-boundary.md": {
      "mode": "100644",
      "sha256": "157a7733b5df9dddc656d086f54e585b1508ef161e6849cdcc54cebc0b1ed7b3",
      "size": 1697376
    },
    "docs/live-backend/proxy.md": {
      "mode": "100644",
      "sha256": "ab1025e21fbd78ab7ed212b313d3c285566d05528e523e81d418b7ec189d4c54",
      "size": 265364
    },
    "docs/live-backend/session.md": {
      "mode": "100644",
      "sha256": "41319d8f1a7fa9441fded7efe23c8254929cc5ea15d7d1f59c125e33b29fc767",
      "size": 10811
    },
    "docs/parity.md": {
      "mode": "100644",
      "sha256": "70fb8b95ee95eb7219c3b9ed0eea4c00c280ecf93dba6765418fa559d92b8dc4",
      "size": 1083
    },
    "docs/reports/alpha1-template.md": {
      "mode": "100644",
      "sha256": "70f572dc3d3fef6d45e14c93c09352aea9b7bbdad189cc5167e3d57628c933a9",
      "size": 2179
    },
    "docs/reports/linux-baseline.md": {
      "mode": "100644",
      "sha256": "99096cc71b49d662cb3c1a71137724eb1748aa633a7a24c8b56fa4b467605919",
      "size": 10913
    },
    "docs/reports/packet-scalar-repair.md": {
      "mode": "100644",
      "sha256": "d824ddb953d31f1a20e19951ef743611e1943f5b6b8d6fe4679721d3146e355a",
      "size": 6081
    },
    "docs/reports/runner-boundary-repair.md": {
      "mode": "100644",
      "sha256": "e5700f158b640364f15565cbbea8dee7e86e88c045c8cde07cfaa8fe77a525bf",
      "size": 6595
    },
    "docs/reports/successor-inventory-repair.md": {
      "mode": "100644",
      "sha256": "c930632d1e8674d9516976a5d07d385ac6211ade937fd16b6b875607f8498ab2",
      "size": 7131
    },
    "fixtures/alpha1/environment-unavailable.json": {
      "mode": "100644",
      "sha256": "71ae29d6bafffc062dcaa358929cdc5224d29f415b6a3a327714f9013dca345d",
      "size": 244
    },
    "fixtures/alpha1/journey.json": {
      "mode": "100644",
      "sha256": "0399a95811cafc48c8deae07b45fadb8082b3be99db838da8b09fbddc1614bd8",
      "size": 7677
    },
    "fixtures/alpha1/overview.json": {
      "mode": "100644",
      "sha256": "c840c2f0c8e3094cdaaa08a10ea57d859d969c24546c3a23107189e63d7b626b",
      "size": 12726
    },
    "fixtures/environments/meta-complete.json": {
      "mode": "100644",
      "sha256": "6ea4589266ff02ea3c42bf86d72ac5bca9c593203bf35177ecb7da4ab2df1cbe",
      "size": 225
    },
    "fixtures/environments/meta-unavailable.json": {
      "mode": "100644",
      "sha256": "3bec392601ed731f34f00dd55c835986b758a501d54a1ac0213d1e85eb8e2838",
      "size": 207
    },
    "fixtures/live-backend/baseline.json": {
      "mode": "100644",
      "sha256": "c3dd610a748e018c9e015668567fbea9820a050022dc33375912f8f4aaa51a00",
      "size": 174441
    },
    "fixtures/live-backend/proxy-vectors.json": {
      "mode": "100644",
      "sha256": "ba3cff195f1f615fddb98e2db6713c359d8dbd05699cb1710157fe374b27760f",
      "size": 500997
    },
    "fixtures/live-backend/session-vectors.json": {
      "mode": "100644",
      "sha256": "4999510bbaba2ae4faed7b9afa6d17ba3bbecb733f40f7bf92c69a6d9313a3fd",
      "size": 2822
    },
    "fixtures/platform/linux-baseline/environment-unavailable.json": {
      "mode": "100644",
      "sha256": "c79b375f07694835f616b51243b92305b96f29088424673457582103078307aa",
      "size": 219
    },
    "fixtures/platform/linux-baseline/predecessor-inventory.json": {
      "mode": "100644",
      "sha256": "f47c088f150ce7c61a14707aad71c634001037fd423eb43ace3acb055be86a58",
      "size": 18630
    },
    "fixtures/platform/linux-baseline/predecessor-sources.json": {
      "mode": "100644",
      "sha256": "3fb88e3358c25fb65369e73a3decf9fe111797b1f44b2cc1deeabea8c5d8defc",
      "size": 23010
    },
    "fixtures/platform/linux-baseline/scalar-repair.json": {
      "mode": "100644",
      "sha256": "0e04f3878efd8196fc33aa47a80ecbf5a48e7df262f08b98030acfd4c565fd06",
      "size": 114585
    },
    "fixtures/platform/linux-baseline/successor-inventory.json": {
      "mode": "100644",
      "sha256": "44f5dc37ad2ef258302e2454a163dde80ad9350a64f43b290d2049af33b77b86",
      "size": 171701
    },
    "parity/adapters/run_parity.py": {
      "mode": "100644",
      "sha256": "650c17312390ec0f4382dad3c9279be0bb50522374c7ec01a079d9a7db8eefac",
      "size": 4849
    },
    "parity/adapters/validate_registry.py": {
      "mode": "100644",
      "sha256": "14d00741194d4de4bd3e14adb2829b3612217b9185905220ff8d6c0be39c12d9",
      "size": 6185
    },
    "parity/registry.yaml": {
      "mode": "100644",
      "sha256": "0fac00ae1575b5c86996d32f3a9f01a69f6d77743170df1ecf6aff7243569af5",
      "size": 5544
    },
    "parity/vectors/data-batch-lineage.json": {
      "mode": "100644",
      "sha256": "67c46555d13dd0b48f2e7fe8cbad9f09da7708baf816527f32ea9e96eb264d2d",
      "size": 239
    },
    "parity/vectors/data-connector-closed-discovery.json": {
      "mode": "100644",
      "sha256": "86279c3564392e353ba8537c2cba9d11f4449fc140a02398a146fd6f73e47de0",
      "size": 240
    },
    "parity/vectors/data-local-only-no-fallback.json": {
      "mode": "100644",
      "sha256": "fe3698e550940e90f71d497d0e0024ad99dbc8026684e77ebecb666b1577904f",
      "size": 207
    },
    "parity/vectors/model-route-fail-closed.json": {
      "mode": "100644",
      "sha256": "6eb0342fea804721e30ed38657d44c1578d20b4f829b76a3215df635f504a5de",
      "size": 198
    },
    "parity/vectors/model-upstream-bounded-retry.json": {
      "mode": "100644",
      "sha256": "f0a3cdf305e1f63f0edd05e074373cf6f98f09063bed101a100a74b3b920e854",
      "size": 192
    },
    "parity/vectors/model-usage-tenant-neutral.json": {
      "mode": "100644",
      "sha256": "410f55e3e3453a19754c52cecb689349aba41a95b015aceca7d35ff2e4f9f1ce",
      "size": 299
    },
    "parity/vectors/white-goods-foundation-boundary.json": {
      "mode": "100644",
      "sha256": "49f3a5a70f32c00cebc69594832300939942dc6b80f8a57d60f2c577e728ac2d",
      "size": 277
    },
    "pyproject.toml": {
      "mode": "100644",
      "sha256": "4180e069f0bfb7b38f99b367f9a6f29e914a61717bd0797343f3d2b99720409c",
      "size": 500
    },
    "schemas/v1alpha1/campaign-release.schema.json": {
      "mode": "100644",
      "sha256": "50053c212b0e9a40dcf4e7dd4c155c8c3da6a81a77a82ae7f59aadc2d6d0cfa9",
      "size": 1189
    },
    "schemas/v1alpha1/campaign-report.schema.json": {
      "mode": "100644",
      "sha256": "3e775c55dbc5dff84fb5aab90525814ef03595a69583e8239640583cac7036a9",
      "size": 1073
    },
    "schemas/v1alpha1/conformance-campaign.schema.json": {
      "mode": "100644",
      "sha256": "dd4fb4f5fda756613d5f69056460abdbd05b675dbddb4c9606bc9324321bb89f",
      "size": 10324
    },
    "schemas/v1alpha1/conformance-trust-bundle.schema.json": {
      "mode": "100644",
      "sha256": "587e9e4fcc48fa98cf316b73a3cccabd9713fa0cbae48067f5f43f181404c245",
      "size": 1151
    },
    "schemas/v1alpha1/control-result.schema.json": {
      "mode": "100644",
      "sha256": "2113a19ec9e077dcb7ab6f2c299c4756d09b0d1e3d3a32195d2103ff8d54e182",
      "size": 1056
    },
    "schemas/v1alpha1/environment-intake.schema.json": {
      "mode": "100644",
      "sha256": "b69ef4bda6fe209b0416ef1c250747a38179d4cef0cf9bc8c72b1f0de1e3d621",
      "size": 776
    },
    "schemas/v1alpha1/linux-readiness-evidence.schema.json": {
      "mode": "100644",
      "sha256": "8f4cf17273b097e39420b2394be43259c9bea30b684a58bcdc739c60b5059c0e",
      "size": 61742
    },
    "schemas/v1alpha1/live-backend-session.schema.json": {
      "mode": "100644",
      "sha256": "7c4ad7c69feb4e9e9f8509f2cdd6c1bcccbf8acb60711810c2e0df8ef7cb737d",
      "size": 2504
    },
    "schemas/v1alpha1/live-campaign-execution-envelope.schema.json": {
      "mode": "100644",
      "sha256": "d4720d28fd0cfb8f4979f8d1bb808c5244c6e8121c4a97b0303cfed033c4d1fd",
      "size": 4272
    },
    "schemas/v1alpha1/live-capacity-authorization.schema.json": {
      "mode": "100644",
      "sha256": "196cafdba0cc168b8dbab7cb02aeda003b1b0cb2f0ae8e9b233b883629949235",
      "size": 2177
    },
    "schemas/v1alpha1/technical-evidence-bundle.schema.json": {
      "mode": "100644",
      "sha256": "0d1e7ad8413733c63b18bb0b658a93f541800c604b2f56c8842fe4ac7760d513",
      "size": 1524
    },
    "schemas/v1alpha1/tenant-acceptance-candidate.schema.json": {
      "mode": "100644",
      "sha256": "37c57329bb835d7aa091be9de41bcfaed9305b1e0359ec1289d114f31bbf426a",
      "size": 995
    },
    "src/harness_conformance/__init__.py": {
      "mode": "100644",
      "sha256": "748cd4a32689b1856ef53f51793e3f85303a25658846bb9a6965440ceeed769f",
      "size": 236
    },
    "src/harness_conformance/__main__.py": {
      "mode": "100644",
      "sha256": "935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d",
      "size": 48
    },
    "src/harness_conformance/acceptance.py": {
      "mode": "100644",
      "sha256": "81a562a983f1d662e78d95d7e3e29f070471b3e304c13bac5162e0b05108c933",
      "size": 2613
    },
    "src/harness_conformance/build_backend.py": {
      "mode": "100644",
      "sha256": "d7ed81b4e0ffd865093679ef51a033a7bc74024b20300b098520306a05243e99",
      "size": 2399
    },
    "src/harness_conformance/campaign.py": {
      "mode": "100644",
      "sha256": "da0a25fba8336f658948ab1018a9db5c518bcc52849bdfcf295058906a26272a",
      "size": 7026
    },
    "src/harness_conformance/canonical.py": {
      "mode": "100644",
      "sha256": "eb16aee5dda8f512b78b637361f0a057c7e944cd1b9eb888c88182c867e7794d",
      "size": 5645
    },
    "src/harness_conformance/cli.py": {
      "mode": "100644",
      "sha256": "c6fe0356d835db4bb0ae43d2484ca107f32bbf9046ff04c1a5a5ab47703ce8c1",
      "size": 4482
    },
    "src/harness_conformance/crypto.py": {
      "mode": "100644",
      "sha256": "bf4cd892d5a7b0dd38bf38b88f72657821d7f21575fce450e60a5a13950c0ca9",
      "size": 5148
    },
    "src/harness_conformance/errors.py": {
      "mode": "100644",
      "sha256": "c30216c02cfa449063b77ca922a3c7cd32e0c6a8010365e093d730e7bc37807a",
      "size": 308
    },
    "src/harness_conformance/events.py": {
      "mode": "100644",
      "sha256": "2cc8855e5fe02c9874e3653b5f094b4095eed483e2446ba32735ddc57c6b422a",
      "size": 2197
    },
    "src/harness_conformance/evidence.py": {
      "mode": "100644",
      "sha256": "670a8c4f6b06caf8af7749b0fe5bf6210d746cd6a823430a387890add135b3e6",
      "size": 7683
    },
    "src/harness_conformance/lifecycle.py": {
      "mode": "100644",
      "sha256": "86c7f62bea77d963e087d2b244f8479a5a81bd1dac8ab5ec5579ad9b0a35f69c",
      "size": 1582
    },
    "src/harness_conformance/linux_readiness.py": {
      "mode": "100644",
      "sha256": "1d40b52a05a85cf0d2179d5545bc8325b8035a24340c5a52b8b66f28e0476fc8",
      "size": 22629
    },
    "src/harness_conformance/live.py": {
      "mode": "100644",
      "sha256": "8f6d033292801930cd280f3611aed3c6012cf4d39ec63d4324eb92590e44a022",
      "size": 23002
    },
    "src/harness_conformance/live_backend_authority.py": {
      "mode": "100644",
      "sha256": "b57f241e1c0c76be3d86682e9a1a1d62f40115aaa917d2e124d589c84880e42d",
      "size": 9916
    },
    "src/harness_conformance/live_launcher.py": {
      "mode": "100644",
      "sha256": "0635ca7494e29c495fcf8188c167d82bb27f109102fc46f91052e1d509817d27",
      "size": 5281
    },
    "src/harness_conformance/live_linux_boundary.py": {
      "mode": "100644",
      "sha256": "7c590b4078e4bd024c0798749f5d1e1197f9a30c15cc6d1a2b0d7b9131ae54fe",
      "size": 52544
    },
    "src/harness_conformance/live_mutation_admission.py": {
      "mode": "100644",
      "sha256": "e9b8d99e2930df1eff5c30d327e15450ba5d715c1003c05180e5a40747a048b1",
      "size": 159125
    },
    "src/harness_conformance/live_proxy_client.py": {
      "mode": "100644",
      "sha256": "f82bf0fe70c3782db1cec798b3d4a3fe2b36be68e4ae9ffe56b6e600895b24ff",
      "size": 18956
    },
    "src/harness_conformance/live_proxy_server.py": {
      "mode": "100644",
      "sha256": "704e1a9c716aec9cf6b4a4f70b543ffea0206009cc8831ab144d69bc8eed528a",
      "size": 370057
    },
    "src/harness_conformance/live_replay_store.py": {
      "mode": "100644",
      "sha256": "ff512b35ce7761b5dccc2c57989a6888b0daa9c99fba404f7be0be6878dae3f7",
      "size": 10076
    },
    "src/harness_conformance/live_session.py": {
      "mode": "100644",
      "sha256": "dc15ebe6d919093cb1842c77c19c9e7846d7ef62e3b04946114824befa9e4454",
      "size": 12361
    },
    "src/harness_conformance/live_supervisor.py": {
      "mode": "100644",
      "sha256": "4dfeb1780c5fc6b2e116f027fbbde6b8a0fec401911f11c4f45900e7ad84b03e",
      "size": 38977
    },
    "src/harness_conformance/models.py": {
      "mode": "100644",
      "sha256": "3d095046632c640bd679b730cc76c90276a73c18263de227ad8a5692c34730dc",
      "size": 1430
    },
    "src/harness_conformance/registry.py": {
      "mode": "100644",
      "sha256": "fa32c26a773a93d60c3f1cd512a99d1213258f944846e028bf7c92aca7049139",
      "size": 1595
    },
    "src/harness_conformance/schema.py": {
      "mode": "100644",
      "sha256": "cd3fefc33833cf5fbccb97a0ac75524ecd967cfa10064a79f64a837f75397ee5",
      "size": 9908
    },
    "tests/alpha1/__init__.py": {
      "mode": "100644",
      "sha256": "1c4b4913127e929661e104454b7900591e39681401eb19594436b1a860c49a6a",
      "size": 48
    },
    "tests/alpha1/contract.py": {
      "mode": "100644",
      "sha256": "20034c14d493cac5f730440b27833c5fa87722fda0a1574ce0f81836764749a7",
      "size": 16927
    },
    "tests/alpha1/test_alpha1.py": {
      "mode": "100644",
      "sha256": "b528290f311a5e41e2b163028bb5212a022d15319a7a9fb218fd7e272480e9c7",
      "size": 7371
    },
    "tests/fixes/runner_boundary/_inventory.py": {
      "mode": "100644",
      "sha256": "fb50aba04fe963a89b74ad1aca57b1242fa54481e01989ac18a189a080ade94c",
      "size": 2443
    },
    "tests/fixes/runner_boundary/legacy-tests.json": {
      "mode": "100644",
      "sha256": "9fff3fb6bd66789b18bc8f38885d2bfd287124f9a32b4f7a0d645c27ee500dbd",
      "size": 4603
    },
    "tests/fixes/runner_boundary/test_boundaries.py": {
      "mode": "100644",
      "sha256": "2e33efe165cf46912a426285dabd0bbe98b17acdf18f3d7a8bf3cb56a71247e4",
      "size": 15192
    },
    "tests/fixes/runner_boundary/test_inventory.py": {
      "mode": "100644",
      "sha256": "1fbacb25aea922a37fb552e91f6b95dded7c1774d1ba2a80f5989cd926cad5e6",
      "size": 3569
    },
    "tests/live_backend/_fixtures.py": {
      "mode": "100644",
      "sha256": "edec764c067e538fa9709dc7dce59a357ae996ba36c6121482cc3b24d86b8a28",
      "size": 3383
    },
    "tests/live_backend/_inventory.py": {
      "mode": "100644",
      "sha256": "d341edcdf49dadf182c3fcc9926d373d13c83aa004d3cc74363312861a7f1e46",
      "size": 4839
    },
    "tests/live_backend/test_inventory.py": {
      "mode": "100644",
      "sha256": "f128f05fc395c26de0c13c34953bfff297fa64f857f3f70aab56dbc9e3bcc8a1",
      "size": 10197
    },
    "tests/live_backend/test_linux_boundary.py": {
      "mode": "100644",
      "sha256": "06d16e4c833dc818a084b655b4f767dbe601212adc9525c47dc94241c32ee238",
      "size": 62720
    },
    "tests/live_backend/test_mutation_admission.py": {
      "mode": "100644",
      "sha256": "67e6c34885063a3a7d2a58914713243093509073624bab99999af7ccd55ce6dd",
      "size": 123590
    },
    "tests/live_backend/test_proxy_client.py": {
      "mode": "100644",
      "sha256": "90399c359d8e97fa526597b8097b5d73bf052e02f48b3fa6fad6db5453729227",
      "size": 21302
    },
    "tests/live_backend/test_proxy_server.py": {
      "mode": "100644",
      "sha256": "7edcc67ae1f0463a0f2df9f2a06d6c9a0eda35290e30aa09099dd414f9369d81",
      "size": 710578
    },
    "tests/live_backend/test_replay_store.py": {
      "mode": "100644",
      "sha256": "492d6569edb1d271199a3d52b93e82f7295ae478d90b01376125313ee1af8213",
      "size": 9971
    },
    "tests/live_backend/test_session.py": {
      "mode": "100644",
      "sha256": "4348b898c1d8cab9fbc94b7bfceff5442a21c0e49fc2645277ae706506c25e90",
      "size": 32978
    },
    "tests/live_backend/test_supervisor.py": {
      "mode": "100644",
      "sha256": "2c6fc822b453e57f0354e2a6876b016ea9d536216e77b2390f1026befaef7db1",
      "size": 295260
    },
    "tests/meta/test_build_cli.py": {
      "mode": "100644",
      "sha256": "989c58c63a8cc5234e0396c4bee1c667da133c6893ca24dd96bd95822f43a4e6",
      "size": 2781
    },
    "tests/meta/test_campaign.py": {
      "mode": "100644",
      "sha256": "85fc9c47556fa0db78ed1948cba696cea0da9d895848169785d227a6e66efc8d",
      "size": 3007
    },
    "tests/meta/test_canonical_schema.py": {
      "mode": "100644",
      "sha256": "f3c233226c5dc400f225eeb16bde754fd73b3e332a2cc85c7795571537845a35",
      "size": 3187
    },
    "tests/meta/test_evidence_crypto.py": {
      "mode": "100644",
      "sha256": "b0b87f6e4f726ebc7af82be7ab9b6b83a73ec130e1559cb5d9800396b91436c4",
      "size": 4501
    },
    "tests/meta/test_live.py": {
      "mode": "100644",
      "sha256": "9ac39858b40468a10b2a20ae43e0aaa92f64fde6ab63d275143d654774ec10a3",
      "size": 11715
    },
    "tests/meta/test_porting_zero_bill.py": {
      "mode": "100644",
      "sha256": "f8ed0fdffc245541d332d78c66d6e9045c3bfc85e0683c3cb7e87b263c1bd448",
      "size": 4182
    },
    "tests/meta/test_registry_dispatch.py": {
      "mode": "100644",
      "sha256": "b021ddeb2a7a534427edf7db594b0d9532711bec4fcfac76405dcded73adbc1d",
      "size": 3756
    },
    "tests/parity/test_adapters.py": {
      "mode": "100644",
      "sha256": "9e4217daee3c0e6f5f7dc0a292c4ff55cb1a3b7259b477ee65dfc13315e49c4a",
      "size": 2337
    },
    "tests/parity/test_packet_runner.py": {
      "mode": "100644",
      "sha256": "0054ccd9312c59a77194a17152191a80bc82d98a5b27ee6e83183b2e62bf7d97",
      "size": 6066
    },
    "tests/parity/test_registry.py": {
      "mode": "100644",
      "sha256": "88d007d59c2da7dc45fdb4da0d7787725ff6a4d6d120a7f38d843a94baf2b5ff",
      "size": 2638
    },
    "tests/platform/linux_baseline/_fixtures.py": {
      "mode": "100644",
      "sha256": "579ff77d11e66776884ccf4a3343c417393767215b09abc5aacc1a19c10bcb7d",
      "size": 11573
    },
    "tests/platform/linux_baseline/_successor_inventory.py": {
      "mode": "100644",
      "sha256": "0ab36ab0055b72d25dced1d0339a1dbacfafe29ea450b2935c171912405ea733",
      "size": 63700
    },
    "tests/platform/linux_baseline/test_linux_campaign.py": {
      "mode": "100644",
      "sha256": "e4501ef5df6a3a1e9f3755aee40592f81ccdcab069d187215f612b97f9773094",
      "size": 8618
    },
    "tests/platform/linux_baseline/test_linux_evidence.py": {
      "mode": "100644",
      "sha256": "b6e162808c471d3d2ed7caa2ed2c056af33819d91ae46a66ff5298da982912b3",
      "size": 14548
    },
    "tests/platform/linux_baseline/test_linux_inventory.py": {
      "mode": "100644",
      "sha256": "3fdd36f47cfb3deb7edaab8685dbead5c90519a92844b5bc2266441d5160c338",
      "size": 5683
    },
    "tests/platform/linux_baseline/test_linux_protocol.py": {
      "mode": "100644",
      "sha256": "2057b427ba366717c506d561978695e27b53208b4e3fbf318b00671fe672254d",
      "size": 8232
    },
    "tests/platform/linux_baseline/test_packet_scalars.py": {
      "mode": "100644",
      "sha256": "c2ce177f7a462abcae70ae5c51cc2c50d1a3041dc7b9afa527a2e0c582932fe9",
      "size": 27287
    },
    "tests/platform/linux_baseline/test_successor_inventory.py": {
      "mode": "100644",
      "sha256": "46417d8566acedf4c60e396dfe27dcd94743e288eda9f1aeea2db5c27efd0b9e",
      "size": 21048
    },
    "toolchain.lock": {
      "mode": "100644",
      "sha256": "40a0cbb9fc244a8484b22494b6bfa070fbc76aec0edd86ab690026f6a8027bfc",
      "size": 2153
    },
    "uv.lock": {
      "mode": "100644",
      "sha256": "bd9cb528f2c6ad6a74e3dc1998978e029144fcee2535387cc5ef3db7907dcfbc",
      "size": 150
    }
  },
  "currentTestIdsSha256": "c190aac750f3a5de3a378aaedc2f7c8200d0c9a8e3e82c5b35c80d5e14ec54f0",
  "draftCommit": "25fab12c168ff686e863291098fce0f3dba629bd",
  "evidenceClass": "SOURCE_DELTA_ONLY",
  "inheritedTestIdsSha256": "e4067c6b53268c8b905e6dd0d52d62952b3108563132b978f1962f18fb3d4acd",
  "metaCommit": "5b082fba8df155782b558d2afe4e902ae361c96c",
  "nativeAcceptance": false,
  "newTestIds": {
    "tests/live_backend/test_mutation_admission.py": [
      "CompletionIntegrationSourceTests.test_altered_before_image_cannot_reseal",
      "CompletionIntegrationSourceTests.test_collection_filter_skip_and_loader_refuse",
      "CompletionIntegrationSourceTests.test_current_first_exact_history",
      "CompletionIntegrationSourceTests.test_current_inventory_does_not_return_historical_ids",
      "CompletionIntegrationSourceTests.test_document_and_fallback_immutable",
      "CompletionIntegrationSourceTests.test_duplicate_json_and_duplicate_proof_refuse",
      "CompletionIntegrationSourceTests.test_fresh_read_after_source_mutation",
      "CompletionIntegrationSourceTests.test_historical_bytes_are_data_not_executable",
      "CompletionIntegrationSourceTests.test_metadata_links_modes_and_unknown_fields",
      "CompletionIntegrationSourceTests.test_missing_extra_and_duplicate_paths",
      "CompletionIntegrationSourceTests.test_missing_renamed_and_duplicate_identity",
      "CompletionIntegrationSourceTests.test_missing_reordered_and_unknown_transform",
      "CompletionIntegrationSourceTests.test_original_proof_and_old_assertions_immutable",
      "CompletionIntegrationSourceTests.test_reader_rejects_linked_file_and_ancestry",
      "CompletionIntegrationSourceTests.test_resealed_every_owned_source",
      "CompletionIntegrationSourceTests.test_resealed_non_owned_source",
      "CompletionIntegrationSourceTests.test_stale_actual_bytes",
      "CompletionIntegrationSourceTests.test_unknown_authority_and_forged_current_pin"
    ]
  },
  "packetId": "CONF-FIX-008",
  "schemaVersion": "planeon.internal.completion-source-delta/v1",
  "tenantAcceptance": false,
  "transforms": [
    {
      "path": "src/harness_conformance/live_proxy_server.py",
      "steps": [
        {
          "beforeBase64": "ICAgICAgICBmb3IgYXR0ciBpbiAoImNvbm5lY3Rpb24iLCAibGlzdGVuZXIiLCAib2JzZXJ2ZXIiLCAic3RvcmFnZSIsICJzZWxmX2luc3BlY3Rpb24iLCAicXVhbGlmaWNhdGlvbl9iaW5kaW5nIiwgInNlY3JldHMiLCAiZmlsZXMiKToK",
          "beforeSha256": "3da6182e93d70eb1f78981a37b2ae701afbd303e5e736c50591c2fdf6c5ccc08",
          "inputSha256": "704e1a9c716aec9cf6b4a4f70b543ffea0206009cc8831ab144d69bc8eed528a",
          "offset": 368499,
          "outputSha256": "6207091a8c38b609de3a89da2c449a73218154238577e723fb9ade19a2a9da87",
          "removeSize": 560,
          "removedSha256": "114f57e84f3e3087a564c8fc879cebd00dd948991fb35ea5d44efeccddd73f39"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "6207091a8c38b609de3a89da2c449a73218154238577e723fb9ade19a2a9da87",
          "offset": 363888,
          "outputSha256": "67dcf338a98ce094ee8548089a60aa123e500f35a3fe486de17f6f40f25eb47b",
          "removeSize": 4227,
          "removedSha256": "fb8911db46eacbdd08627b936a7af3fa44de663a6a082979afbf7e5dc6baca89"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgIHN0YXRlcywgXywgXyA9IHBhcnNlX3Jlc2VydmF0aW9ucyhzZWxmLnN0b3JhZ2UucmVhZCgpKQogICAgICAgICAgICAgICAgcHJpb3IgPSBzdGF0ZXNbKHNlbGYuZW52ZWxvcGVbInRlbmFudElkIl0sIHNlbGYuZW52ZWxvcGVbIm5vbmNlIl0pXQogICAgICAgICAgICAgICAgY2xlYW51cCA9IGNsZWFudXBfcmVjZWlwdChjYW5vbmljYWxfZGlnZXN0KHNlbGYucmVzZXJ2YXRpb24pLCBvcGVyYXRpb24sIHV0Y19ub3coKSwgcmVzdWx0WzFdLCBwcmlvclsiY2xlYW51cERpZ2VzdCJdKQogICAgICAgICAgICAgICAgc2Vzc2lvbiA9IHtrOiB2IGZvciBrLCB2IGluIHNlbGYuYmluZGluZy5pdGVtcygpIGlmIGsgbm90IGluICgibm90QmVmb3JlIiwgIm5vdEFmdGVyIil9CiAgICAgICAgICAgICAgICBzZXNzaW9uLnVwZGF0ZShzY2hlbWFWZXJzaW9uPVNDSEVNQSwgaXNzdWVkQXQ9c2VsZi5iaW5kaW5nWyJub3RCZWZvcmUiXSwgZXhwaXJlc0F0PXNlbGYuYmluZGluZ1sibm90QWZ0ZXIiXSwgc3RhdGU9IlJVTk5JTkciKQogICAgICAgICAgICAgICAgcmVjZWlwdCA9IHZhbGlkYXRlX3JlY2VpcHQocmVzdWx0WzBdLCBzZXNzaW9uLCBzZWxmLmJpbmRpbmcsIHJlcXVlc3QsCiAgICAgICAgICAgICAgICAgICAgc2VsZi5wbGFuWyJyZWdyZXNzaW9ucyJdIGlmIG9wZXJhdGlvbiA9PSAiRlVMTF9QUkVERUNFU1NPUl9SRUdSRVNTSU9OIiBlbHNlIHt9LCB1dGNfbm93KCkpCiAgICAgICAgICAgICAgICByZXF1aXJlKHJlY2VpcHRbInN0YXR1cyJdICE9ICJQQVNTIiBvciBub3QgcmVzdWx0WzFdLCAiUFJPWFlfQ0xFQU5VUF9OT1RfUFJPVkVOIikKICAgICAgICAgICAgICAgIHNlbGYubG9nLnJlY29yZChzZWxmLnJlc2VydmF0aW9uLCAiUkVDT1JERUQiLCBvcGVyYXRpb24sIGNsZWFudXBbIm9ic2VydmVkQXQiXSwgY2xlYW51cCkKICAgICAgICAgICAgICAgIHNlbGYuYWN0aXZlX29wZXJhdGlvbiA9IE5vbmUKICAgICAgICAgICAgICAgIHNlbGYuX3RyYW5zcG9ydF9jaGVjaygpCiAgICAgICAgICAgICAgICB0bHMud3JpdGUoaHR0cF9tZXNzYWdlKCJIVFRQLzEuMSAyMDAgT0siLCBjYW5vbmljYWxfYnl0ZXMocmVjZWlwdCkpKQo=",
          "beforeSha256": "1126edd667313a8c87d85d25c75857df9f2076fe289ecef617bd6081ad0b2315",
          "inputSha256": "67dcf338a98ce094ee8548089a60aa123e500f35a3fe486de17f6f40f25eb47b",
          "offset": 363535,
          "outputSha256": "0b6e490aab6b86c4421915993ecbb52e9ffd270fa8062645fd76978027367871",
          "removeSize": 72,
          "removedSha256": "8e928cb79efdc3526ed13b2244b7ccc99806138bb55a6611d358fc397b119de6"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgICMgQ09ORi1MSVZFLTAwNCBvd25zIGFjdHVhbCBwcm9iZXMgYW5kIHRoZSBicm9rZXItZmVuY2VkIG5hdGl2ZQogICAgICAgICAgICAgICAgIyBleGVjdXRpb24gYWRhcHRlci4gQW4gYWJzZW50IGFkYXB0ZXIgbmV2ZXIgcmV0dXJucyBhIHJlY2VpcHQuCiAgICAgICAgICAgICAgICByZXN1bHQgPSBfZml4ZWRfcHJvYmVzKCkuZXhlY3V0ZV9zZXJ2ZXJfcHJvYmUocmVxdWVzdCwgc2VsZiwgc2VsZi5kZWFkbGluZSkKICAgICAgICAgICAgICAgIHJlcXVpcmUodHlwZShyZXN1bHQpIGlzIHR1cGxlIGFuZCBsZW4ocmVzdWx0KSA9PSAyIGFuZCB0eXBlKHJlc3VsdFswXSkgaXMgYnl0ZXMKICAgICAgICAgICAgICAgICAgICAgICAgYW5kIHR5cGUocmVzdWx0WzFdKSBpcyBsaXN0LCAiUFJPWFlfUFJPQkVfUkVTVUxUX0lOVkFMSUQiKQo=",
          "beforeSha256": "cac0fe97a9c19d91cc080d04a2981dd5c3697c0d03ef19f2a394d20f95e3c965",
          "inputSha256": "0b6e490aab6b86c4421915993ecbb52e9ffd270fa8062645fd76978027367871",
          "offset": 363389,
          "outputSha256": "9cb7bc8dab0bbb318a85db7307542c7d2ab272c1b5a69b9783eed58a6f35e707",
          "removeSize": 106,
          "removedSha256": "fa428186f27b5e7c3352a546afe5e290223edb57e33ee1b8efa7f929271afb86"
        },
        {
          "beforeBase64": "ICAgICAgICBmcm9tIC5saXZlX3Nlc3Npb24gaW1wb3J0IFNDSEVNQSwgdmFsaWRhdGVfcmVjZWlwdAo=",
          "beforeSha256": "98e9c5aa49408a680300d5a1a51eea107283919dba35031418a674b6f027f6df",
          "inputSha256": "9cb7bc8dab0bbb318a85db7307542c7d2ab272c1b5a69b9783eed58a6f35e707",
          "offset": 362346,
          "outputSha256": "2dfadc7d1b09445153fef4e457d8b3d1e44840fc02263548d8694684f5eaf5b0",
          "removeSize": 0,
          "removedSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        {
          "beforeBase64": "ICAgICAgICByZXF1aXJlKHNlbGYuYnJva2VyLmNoZWNrKCkgaXMgTm9uZSwgIlBST1hZX0JST0tFUl9DSEVDS19SRVNVTFQiKQo=",
          "beforeSha256": "eeaec6c62b4988548b845eb30b0f97b6dbdfff7d23603375710fb22c3c0530cf",
          "inputSha256": "2dfadc7d1b09445153fef4e457d8b3d1e44840fc02263548d8694684f5eaf5b0",
          "offset": 361004,
          "outputSha256": "b7ad4a2b9df43bd1ccec827165159ff62090e4381ec2b9826b8b72c8356ace6e",
          "removeSize": 145,
          "removedSha256": "20fd28bd102e99b01e0be9357bee86c9f72422f78412d0a4666b235b67b4fbe0"
        },
        {
          "beforeBase64": "ICAgICAgICBzZWxmLnF1YWxpZmljYXRpb25fYmluZGluZy5jaGVjaygpCiAgICAgICAgc2VsZi5zZWxmX2luc3BlY3Rpb24uY2hlY2soKQogICAgICAgIHJlcXVpcmUoX2ZpeGVkX3Byb2JlcygpLnJlcXVpcmVfc2VydmVyX2NvbnRhaW5tZW50KHNlbGYpIGlzIE5vbmUsICJQUk9YWV9DT05UQUlOTUVOVF9VTkFWQUlMQUJMRSIpCg==",
          "beforeSha256": "c3e0800bdda036c9647d6f1e9052097cffb1801aff0e3a5bc14243796ef157fa",
          "inputSha256": "b7ad4a2b9df43bd1ccec827165159ff62090e4381ec2b9826b8b72c8356ace6e",
          "offset": 360477,
          "outputSha256": "e07251c322a74bac13b92befb3c06105e7cab993521e89d4dc1c353315868fef",
          "removeSize": 311,
          "removedSha256": "30494871244b02b02e4ab6cb0d97dbae052527f4e96d58f68103cb711c42634a"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "e07251c322a74bac13b92befb3c06105e7cab993521e89d4dc1c353315868fef",
          "offset": 357001,
          "outputSha256": "32c1b4045696749c77326dff41d9e6741b9a8273018e27d966ef5a12dc25b520",
          "removeSize": 69,
          "removedSha256": "aed83617e3686a161ec7b9d72a110735406c4ff776fdfe316d99b4c14ac56ff1"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgc2VsZi5zZWxmX2luc3BlY3Rpb24gPSBvYmplY3QuX19uZXdfXyhfS2VybmVsU2VsZkluc3BlY3Rpb24pCiAgICAgICAgICAgIHNlbGYuc2VsZl9pbnNwZWN0aW9uLl9faW5pdF9fKHNlbGYpCiAgICAgICAgICAgIHJlcXVpcmUoX2ZpeGVkX3Byb2JlcygpLnJlcXVpcmVfc2VydmVyX2NvbnRhaW5tZW50KHNlbGYpIGlzIE5vbmUsICJQUk9YWV9DT05UQUlOTUVOVF9VTkFWQUlMQUJMRSIpCg==",
          "beforeSha256": "a35cacea26ea49b3f52efd03f3a07459edb66d9f48e854205cd78868a8e26705",
          "inputSha256": "32c1b4045696749c77326dff41d9e6741b9a8273018e27d966ef5a12dc25b520",
          "offset": 356618,
          "outputSha256": "2977ed365c7aa83c17ff7aa8cc8c83e0a2c9a5f00f9bdedd40100709929a6cbf",
          "removeSize": 147,
          "removedSha256": "e3c8b731fec99f97f46358897f12acd2fcf54b1b362fbf7d8482fbe337680161"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "2977ed365c7aa83c17ff7aa8cc8c83e0a2c9a5f00f9bdedd40100709929a6cbf",
          "offset": 353025,
          "outputSha256": "aa10aa576fe789de25faa1f121522a2df1a922186729f2023f888cd8dc816f7c",
          "removeSize": 75,
          "removedSha256": "9b2aa41a836747ed1a48278f16fca7ec050e4550d94642928fb83237ca283e99"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "aa10aa576fe789de25faa1f121522a2df1a922186729f2023f888cd8dc816f7c",
          "offset": 352861,
          "outputSha256": "fa6d163390535b0c1c602a500c51ec1fb7390157d4c232caa1803f0b23006ede",
          "removeSize": 65,
          "removedSha256": "d452f7c09b2a323260e4f8757352190a331082ed036bd1ee6cb2dd5310d5d943"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "fa6d163390535b0c1c602a500c51ec1fb7390157d4c232caa1803f0b23006ede",
          "offset": 350604,
          "outputSha256": "e821b27d051894b3ca51d93bbd8c4f5ddaaf68a7dfee7d7af244c173e3d520ba",
          "removeSize": 91,
          "removedSha256": "731b3a83c68cc8826ca71e15562f19df05f9e65cbd6f94a8fa5f7d8d03ba355d"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "e821b27d051894b3ca51d93bbd8c4f5ddaaf68a7dfee7d7af244c173e3d520ba",
          "offset": 349853,
          "outputSha256": "41bc459d43927e93d764b41d8693ca1a1419767cc67cb8e299c4d7417a640698",
          "removeSize": 301,
          "removedSha256": "44de16501557554070d6c7d436b72369a9024bc3abde16e96a5b45d8f9315ac2"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "41bc459d43927e93d764b41d8693ca1a1419767cc67cb8e299c4d7417a640698",
          "offset": 348917,
          "outputSha256": "cb5b414560263bec2da876b32daa73beb490988e6c26eaa5a188237f5c0bf1e8",
          "removeSize": 40,
          "removedSha256": "8460681e223f75d3a0d57e3d8cca79668aa8f3bd2b026eddc5fabea976cfbf2e"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "cb5b414560263bec2da876b32daa73beb490988e6c26eaa5a188237f5c0bf1e8",
          "offset": 323081,
          "outputSha256": "1c2e2b62902accf4e0bc9d65ea9bd4fd7dacc0e444b3c578db1b4b1f9e1ccce3",
          "removeSize": 25649,
          "removedSha256": "5a790decf3427bbdb77cf11bd6129ed5dbbe5682725cf6e4e3228e3ef9fd2c35"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "1c2e2b62902accf4e0bc9d65ea9bd4fd7dacc0e444b3c578db1b4b1f9e1ccce3",
          "offset": 255732,
          "outputSha256": "7e39f51d170eb999e91336b99ea5ae53dc5c91cb87bb3a3cf04ff38a5b2a168d",
          "removeSize": 41094,
          "removedSha256": "e76b42caa5b76721c25bfbeb5da2f6ed9c0cd16611fd0582535668b4cf5e99a5"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "7e39f51d170eb999e91336b99ea5ae53dc5c91cb87bb3a3cf04ff38a5b2a168d",
          "offset": 247729,
          "outputSha256": "c053b15641f18506a2d10ed8ce0e2b21cb0d1b797a4320978b6a0a8eed0f262b",
          "removeSize": 725,
          "removedSha256": "172597a156e77fd14e7dc7c377dd1c68edeb15e480e70eb6baf4785d093ca053"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "c053b15641f18506a2d10ed8ce0e2b21cb0d1b797a4320978b6a0a8eed0f262b",
          "offset": 245439,
          "outputSha256": "77a74179dae2d9e88830ad7d31ae1b087fbc886f4989bb13c57be19dc34ae9f5",
          "removeSize": 622,
          "removedSha256": "2627b48c8d640705f80ee1bad47f0d0b3bc9b651946ad69d4efc0753b1c1500b"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "77a74179dae2d9e88830ad7d31ae1b087fbc886f4989bb13c57be19dc34ae9f5",
          "offset": 244641,
          "outputSha256": "7b1f8a26251e3ad20961906354cc4393ff711f588f4e29d79af2fb518f7c44c9",
          "removeSize": 765,
          "removedSha256": "aeaf129f5bd015768cc15d4130914dcacf88de60fb84238f1f388d45485c20a0"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "7b1f8a26251e3ad20961906354cc4393ff711f588f4e29d79af2fb518f7c44c9",
          "offset": 239244,
          "outputSha256": "8ec3148eab6f0dc552f101d1488373644d36dd57fc418c50acf1d78bccac9025",
          "removeSize": 278,
          "removedSha256": "583c45f1b41f2fded29bec35e68117d3ed03b892fdcb3ea3edd3869d611a4231"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgcmVxdWlyZShwYXRoIG5vdCBpbiBzZWxmLnNlY3JldHMucmF3LCAiQVBJX0NSRURFTlRJQUxfQUxSRUFEWV9SRUFEIikKICAgICAgICAgICAgcmF3ID0gc2VsZi5faW8oc2VsZi5zZWNyZXRzLnJlYWQsIHBhdGgsIG1vZGU9MG80MDAsIG1heGltdW09MjYyMTQ0KQo=",
          "beforeSha256": "3d3482ae31e80a71248efce76d09a2ee7deb0fd842afb5085ea728b22a09ade6",
          "inputSha256": "8ec3148eab6f0dc552f101d1488373644d36dd57fc418c50acf1d78bccac9025",
          "offset": 235226,
          "outputSha256": "faeb2f28a6df7f8b6a50578d22379d1934c860f9cf09c60a72445b4ca6510b5c",
          "removeSize": 865,
          "removedSha256": "2137f13f36f8426de51cd64cf5bb0e8b8d24c5d6e73e40d5cc06c56dda2602f0"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgICAgICBhbmQgc2VsZi5lbmRwb2ludFsiYWRkcmVzc0ZhbWlseSJdID09ICgiSVBWNCIgaWYgYWRkcmVzcy52ZXJzaW9uID09IDQgZWxzZSAiSVBWNiIpLAo=",
          "beforeSha256": "eca88365630d9fd2cea121a787c193624cb0425f145f157de35bfeb2c9048ca1",
          "inputSha256": "faeb2f28a6df7f8b6a50578d22379d1934c860f9cf09c60a72445b4ca6510b5c",
          "offset": 234823,
          "outputSha256": "e4e9a8672a4cf986b824143fe843dde6b5fab0d46c369c8c1c81e35353a9659a",
          "removeSize": 78,
          "removedSha256": "1c98683c41bdf7ac49cf82a963ba0dfba930b3d32e3f834216983c1b6ddadc2a"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "e4e9a8672a4cf986b824143fe843dde6b5fab0d46c369c8c1c81e35353a9659a",
          "offset": 234190,
          "outputSha256": "d0748fa9457a2d0ca21b051d607099ee88588bb2125459c6db342b4f208b8e6d",
          "removeSize": 369,
          "removedSha256": "4cdab3e70c350ea2107bcca7cabf44ba2223c4f27e79ccbc5fb2713c77e6d0ab"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "d0748fa9457a2d0ca21b051d607099ee88588bb2125459c6db342b4f208b8e6d",
          "offset": 224085,
          "outputSha256": "572134a0acdd691d87deace103ab93677bb1b0e74ecd91b7a42b8dc5ab741b68",
          "removeSize": 378,
          "removedSha256": "afae89a25ba39dea56cf39ec3a711d3f2c6f499a2acf728ed24d43a1bad9aed0"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "572134a0acdd691d87deace103ab93677bb1b0e74ecd91b7a42b8dc5ab741b68",
          "offset": 221714,
          "outputSha256": "28a2ba81579ce50ab6b72f22ec46ae97ae1a720321cd64942606c23a4c343f35",
          "removeSize": 2114,
          "removedSha256": "826d86eaf3771b80e66db799dd9a622ea198ceea74bf143f566957479222788d"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "28a2ba81579ce50ab6b72f22ec46ae97ae1a720321cd64942606c23a4c343f35",
          "offset": 221245,
          "outputSha256": "b68166bc90bf1ceda171cf01915a02760400724537d8fc57f77002d5382abda9",
          "removeSize": 297,
          "removedSha256": "50abdc02f641650af2f31cc24c9f4b3422862e16c8c4c6e51213b57374b46c9c"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "b68166bc90bf1ceda171cf01915a02760400724537d8fc57f77002d5382abda9",
          "offset": 217966,
          "outputSha256": "410a12d68a09e14e182d26f4ba3881352769543dc4cba7a2ffb825321269aac4",
          "removeSize": 53,
          "removedSha256": "609f46c1dc2f056a6cbad7962d63c4fdff783e24cc0efcd9c7bd97bac44539b7"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "410a12d68a09e14e182d26f4ba3881352769543dc4cba7a2ffb825321269aac4",
          "offset": 217223,
          "outputSha256": "c0d01b89299ffd482f098208653b53679bd37915a57d6e029a569d46fd2701bb",
          "removeSize": 172,
          "removedSha256": "a5929a58bec512149bb6fb5228a836f2564b99d50e9d24609851e8118d7f925f"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "c0d01b89299ffd482f098208653b53679bd37915a57d6e029a569d46fd2701bb",
          "offset": 214122,
          "outputSha256": "f46083073045b215df31f753e8e8f41731fd0e99ab40e5652d55b629903aa398",
          "removeSize": 157,
          "removedSha256": "59b3ac964a3cdfa365013d694f1d68aad219c0040ebbef8c422d6422f0ba67ad"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "f46083073045b215df31f753e8e8f41731fd0e99ab40e5652d55b629903aa398",
          "offset": 212256,
          "outputSha256": "0b8ec6ffc5206e1b4d12d9a4c110f7c00a0fcb57c2ea806710ac9a9af2e7e35e",
          "removeSize": 150,
          "removedSha256": "acb64368d72e0330791a35c59f2f9cfeeed7b7a7207ad320072bfd906853d114"
        },
        {
          "beforeBase64": "ICAgIFRoZSBjb21wbGV0ZSByZWNlaXB0L2FjdGlvbi9jbGVhbnVwIGRyaXZlciBhbmQgbmF0aXZlIGZhY3RvcnkgaW50ZWdyYXRpb24KICAgIHJlbWFpbiBzZXBhcmF0ZS4gTm8gY2FsbGVyIGZyYW1lLCBhY3Rpb24gb3Igb3BlcmF0aW9uIGlzIGFjY2VwdGVkIGhlcmUuCg==",
          "beforeSha256": "d55dfb7aab82fbbc4965be2422f087d363f11501f9e0d757ad0855beaa45c1c4",
          "inputSha256": "0b8ec6ffc5206e1b4d12d9a4c110f7c00a0fcb57c2ea806710ac9a9af2e7e35e",
          "offset": 209650,
          "outputSha256": "7e3df4855b3c5de68462bca4a041be6966583a5e5c046dfda9ffe4f0fe3aee8d",
          "removeSize": 137,
          "removedSha256": "8e8517e37fbcde154953619dd84c7ac5a87021c46c3645a540a1684d6151e4ee"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "7e3df4855b3c5de68462bca4a041be6966583a5e5c046dfda9ffe4f0fe3aee8d",
          "offset": 196240,
          "outputSha256": "3550beaab7ce64b2e17f4ed5315fd984d246a1f68590d50ef64ccc4f14138cdc",
          "removeSize": 11160,
          "removedSha256": "7123ffabf7fd86d74befa6caa387727f4fad15baef0497c9ab1e5cb3557f3bc0"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "3550beaab7ce64b2e17f4ed5315fd984d246a1f68590d50ef64ccc4f14138cdc",
          "offset": 185859,
          "outputSha256": "aaa61256b5add5df065b215401c77372f92989158b8f24032c9748b0097d3597",
          "removeSize": 4225,
          "removedSha256": "4b57f3fbee41180155587745539138a38f6ae7d7f6646eb03ac389ab548b1c17"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "aaa61256b5add5df065b215401c77372f92989158b8f24032c9748b0097d3597",
          "offset": 178861,
          "outputSha256": "ccc12b87d998f9c6fd607abc32146011a81e8a7aef2b4af0ea972deaa4ef31de",
          "removeSize": 321,
          "removedSha256": "7e1d2d2526b6db18eae83f9dc1b0684f632c8007f68cc569deef14ffa4167dcc"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "ccc12b87d998f9c6fd607abc32146011a81e8a7aef2b4af0ea972deaa4ef31de",
          "offset": 175041,
          "outputSha256": "9b0f55d828079424c653911b93beb0ee2d10a6ceb44683cb65fe5435f30b0a3d",
          "removeSize": 61,
          "removedSha256": "fd5e9377aecc4ceb791035991c6f66e78c0d41029c4ca8f06d014c92170d7316"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "9b0f55d828079424c653911b93beb0ee2d10a6ceb44683cb65fe5435f30b0a3d",
          "offset": 174590,
          "outputSha256": "e911c5e6898700b5d16d93568d38168048d01c81797b4f96e82ed1fb1ee2cc62",
          "removeSize": 413,
          "removedSha256": "a92e4d6deb4f5b07c9b7f6be427b5fc0a6c31e1231d704ab4b2b2e7f3ead6a75"
        },
        {
          "beforeBase64": "ICAgIHRoZSBicm9rZXIgYWxvbmUgb3ducyB3b3JrZXJzIGFuZCBubyBBUEkgb3BlcmF0aW9uIGlzIGltcGxlbWVudGVkIGhlcmUuCg==",
          "beforeSha256": "e0643f82817dec1b6979d6f3530f2a718e048620189dbe968942bffc09193db5",
          "inputSha256": "e911c5e6898700b5d16d93568d38168048d01c81797b4f96e82ed1fb1ee2cc62",
          "offset": 173555,
          "outputSha256": "686cdf11aec60857da68edb5357eeb3332b8510f2eb1cef722f647900db6235e",
          "removeSize": 153,
          "removedSha256": "2f1afd2f26ce99e52fa65aa896d72cbb9763ea73d67bf09f583b5ab5a0d5c7b9"
        },
        {
          "beforeBase64": "ZGVmIF9maXhlZF9wcm9iZXMoKToKICAgIHRyeToKICAgICAgICBmcm9tIC4gaW1wb3J0IGxpdmVfZml4ZWRfcHJvYmVzIGFzIG1vZHVsZQogICAgZXhjZXB0IEltcG9ydEVycm9yIGFzIGV4YzoKICAgICAgICByYWlzZSBDb25mb3JtYW5jZUVycm9yKCJQUk9YWV9GSVhFRF9QUk9CRVNfVU5BVkFJTEFCTEUiLCAiQ09ORi1MSVZFLTAwNCBpcyBub3QgaW5zdGFsbGVkIikgZnJvbSBleGMKICAgIHJlcXVpcmUoZ2V0YXR0cihnZXRhdHRyKG1vZHVsZSwgIl9fbG9hZGVyX18iLCBOb25lKSwgImFyY2hpdmUiLCBOb25lKSA9PSBFWEVDVVRBQkxFLAogICAgICAgICAgICAiUFJPWFlfUFJPQkVfQ1VTVE9EWSIpCiAgICBmb3IgbmFtZSBpbiAoInJlcXVpcmVfc2VydmVyX2NvbnRhaW5tZW50IiwgImV4ZWN1dGVfc2VydmVyX3Byb2JlIik6CiAgICAgICAgcmVxdWlyZSh0eXBlKGdldGF0dHIobW9kdWxlLCBuYW1lLCBOb25lKSkgaXMgRnVuY3Rpb25UeXBlLCAiUFJPWFlfRklYRURfUFJPQkVTX1VOQVZBSUxBQkxFIikKICAgIHJldHVybiBtb2R1bGUK",
          "beforeSha256": "1c98f94a9c52361972583c9a67a365e24e635984cf585ceb78f423c8caeb3d90",
          "inputSha256": "686cdf11aec60857da68edb5357eeb3332b8510f2eb1cef722f647900db6235e",
          "offset": 153955,
          "outputSha256": "a60f134431c497ffda85a1825dab22ff903c388f4e8bce27972595573632f9ec",
          "removeSize": 7717,
          "removedSha256": "2ecd38a795d88a5c7fcec3f977c8c94003cc0d1c95bd266ab7c14bd4ad262890"
        },
        {
          "beforeBase64": "ICAgIFRoaXMgaXMgTk9UIHRoZSBjb21wbGV0ZWQgX0tlcm5lbFF1YWxpZmljYXRpb24gb3IgYW4gZXhlY3V0aW9uIHBlcm1pdC4KICAgIFBlZXIgY3VzdG9keSwgcGVyLUkvTyBjcm9zcy1yZWFkZXIgZmVuY2luZyBhbmQgZXh0ZXJuYWwgYnJva2VyIGVuZm9yY2VtZW50CiAgICByZW1haW4gc2VwYXJhdGUgb2JsaWdhdGlvbnMuIFRoZSBzZXJ2ZXIncyBjb250YWlubWVudCByZWZ1c2FsIGlzIHVuY2hhbmdlZC4K",
          "beforeSha256": "2b2d08462d1930774e187776d9a27114cc29def43d8fd50118c5f975ce6bc30f",
          "inputSha256": "a60f134431c497ffda85a1825dab22ff903c388f4e8bce27972595573632f9ec",
          "offset": 128080,
          "outputSha256": "9dece26281a10cb5795b91542f9ad1cb1146824a18c46b3ab83cedf44df05251",
          "removeSize": 222,
          "removedSha256": "c7ef3fc3373568abc5eb358d7e52048b60b17929b2b820cd1bdbb8fb45df160c"
        },
        {
          "beforeBase64": "ICAgIEJyb2tlclRyYW5zY3JpcHQsIGJyb2tlcl9kb2N1bWVudCwgX2NyZWF0ZV9yZWNvcmQpCg==",
          "beforeSha256": "e8e289fcaa35a1656844d47de8c9fa2437072e0ce6aa43cc4ece7cbdebbb4e33",
          "inputSha256": "9dece26281a10cb5795b91542f9ad1cb1146824a18c46b3ab83cedf44df05251",
          "offset": 1371,
          "outputSha256": "1e5e5f00d3098d519eaa8bdd5d28844790714030aceee2ded8c9ab9ef48c2127",
          "removeSize": 238,
          "removedSha256": "86eb2678efe0cca894c560fda2d49553b85ae7137275b0f69b5403ad77b40fc3"
        },
        {
          "beforeBase64": "ZnJvbSB0eXBlcyBpbXBvcnQgRnVuY3Rpb25UeXBlCg==",
          "beforeSha256": "8e492c072ecd5ce3390e89509bdfdcf8c455f73a0b5926e75fc4120ff9384522",
          "inputSha256": "1e5e5f00d3098d519eaa8bdd5d28844790714030aceee2ded8c9ab9ef48c2127",
          "offset": 605,
          "outputSha256": "ee5435b63d9dc515992cde29c7dd3cd0aeddd81de7b9c865643a8b8d3ffd5ae9",
          "removeSize": 0,
          "removedSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    },
    {
      "path": "src/harness_conformance/live_mutation_admission.py",
      "steps": [
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "e9b8d99e2930df1eff5c30d327e15450ba5d715c1003c05180e5a40747a048b1",
          "offset": 90836,
          "outputSha256": "adb80569943f4e94d1f269feab5ffd0d9a738a75c48accbaa44a6bec3112774f",
          "removeSize": 5484,
          "removedSha256": "80445cf461ecc30638f66c91e35901368e96b832867aed593f7c7be3a9a45502"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgIHNlbGYucG9pc29uZWQgPSBUcnVlCg==",
          "beforeSha256": "d62f4761d09e7a3acc66838158c0b99d3f69d26abbb918f087cc3d8724a2d128",
          "inputSha256": "adb80569943f4e94d1f269feab5ffd0d9a738a75c48accbaa44a6bec3112774f",
          "offset": 90755,
          "outputSha256": "4a095d8ee9787d4a6cf9ae97c1a283c138aa70c70cb540daaa47d33d716c6a15",
          "removeSize": 63,
          "removedSha256": "4cae29835afebfc13aab4a6deb346c4e7f0e1dfd156217e5ca3f2544a9fb0bcc"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "4a095d8ee9787d4a6cf9ae97c1a283c138aa70c70cb540daaa47d33d716c6a15",
          "offset": 90617,
          "outputSha256": "860a98375dc353be27d790947c6ac1b15eca3670a94b2832e4ac97d1585c3d28",
          "removeSize": 43,
          "removedSha256": "fe3d81f056f06c2e876c246db64205e65e64392d82299fe0a029bad31fd4a3a0"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "860a98375dc353be27d790947c6ac1b15eca3670a94b2832e4ac97d1585c3d28",
          "offset": 88788,
          "outputSha256": "ba417e0651d0b338bf9d0d9f94bc01d473c912b365aa71056921fafe274451c2",
          "removeSize": 135,
          "removedSha256": "e4c1993118e7219490e498b9e986abd2c253df40caf7498518a1ddfef9180c8c"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgZXhjZXB0IEJhc2VFeGNlcHRpb246CiAgICAgICAgICAgICAgICBzZWxmLnBvaXNvbmVkID0gVHJ1ZQogICAgICAgICAgICAgICAgcmFpc2UK",
          "beforeSha256": "3381ebb38d7adcd64c1857b29b1c070cf5a743e79ecdbe49392bc2261cc39263",
          "inputSha256": "ba417e0651d0b338bf9d0d9f94bc01d473c912b365aa71056921fafe274451c2",
          "offset": 88704,
          "outputSha256": "fa091ac1177f57947df8d3603d609657fc526b0217ed6e8eea656a1d9f1655f6",
          "removeSize": 43,
          "removedSha256": "fe3d81f056f06c2e876c246db64205e65e64392d82299fe0a029bad31fd4a3a0"
        },
        {
          "beforeBase64": "ICAgICAgICB3aXRoIHNlbGYuc3RvcmFnZS50cmFuc2FjdGlvbigpIGFzIGlvOgogICAgICAgICAgICBiZWZvcmUgPSBpby5yZWFkKCkKICAgICAgICAgICAgXywgcHJldmlvdXMsIGNvdW50ID0gcGFyc2VfcmVzZXJ2YXRpb25zKGJlZm9yZSkKICAgICAgICAgICAgcm93ID0geyJzZXF1ZW5jZSI6IGNvdW50ICsgMSwgInByZXZpb3VzRGlnZXN0IjogcHJldmlvdXMsICJiaW5kaW5nIjogYmluZGluZywKICAgICAgICAgICAgICAgICAgICJzdGF0ZSI6IHN0YXRlLCAib3BlcmF0aW9uIjogb3BlcmF0aW9uLCAib2JzZXJ2ZWRBdCI6IG5vdywgImNsZWFudXAiOiBjbGVhbnVwfQogICAgICAgICAgICBhZnRlciA9IGJlZm9yZSArIGNhbm9uaWNhbF9ieXRlcyhyb3cpICsgYiJcbiIKICAgICAgICAgICAgcGFyc2VfcmVzZXJ2YXRpb25zKGFmdGVyKQogICAgICAgICAgICB0cnk6Cg==",
          "beforeSha256": "53bd37a7c29a324a405f8e9692f1f3e7066b70e64289b150b140f3086174db34",
          "inputSha256": "fa091ac1177f57947df8d3603d609657fc526b0217ed6e8eea656a1d9f1655f6",
          "offset": 88040,
          "outputSha256": "6c3b8b3d21139eed660cc1b011f4d708d4736dfb330a8154584f988a402acdf5",
          "removeSize": 518,
          "removedSha256": "5786685e199a7ed577ad4dc9c4073a564f8b88de5c4e95001eb94ae0e03fef4c"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "6c3b8b3d21139eed660cc1b011f4d708d4736dfb330a8154584f988a402acdf5",
          "offset": 87801,
          "outputSha256": "1b0bc131d22e87a297c8d86e88d8232c134331d39f7ef2fac8271e3497021817",
          "removeSize": 104,
          "removedSha256": "af545a256c289a8e27ed3ef0a127b38bee5412ff61b7ebe5a73b79ce912e2925"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgIHByaW9yWyJjdXJyZW50Il0gPSBOb25lIGlmIHJlY2VpcHRbInN0YXRlIl0gPT0gIkNMRUFOIiBlbHNlIG9wZXJhdGlvbgogICAgICAgICAgICAgICAgIyBUaGUgcHJvY2VzcyByZW1haW5zIG9uZS1ydW4gZXhjbHVzaXZlLiBBbGwgdGVuIG9wZXJhdGlvbnMgYW5kCiAgICAgICAgICAgICAgICAjIGluZGVwZW5kZW50bHkgY29uZmlybWVkIENMRUFOIGFyZSBuZWVkZWQgdG8gcmVsZWFzZSBjYXBhY2l0eS4KICAgICAgICAgICAgICAgIHByaW9yWyJoZWxkIl0gPSBsZW4ocHJpb3JbImRvbmUiXSkgPCBsZW4oQ0FTRVMpIG9yIHJlY2VpcHRbInN0YXRlIl0gIT0gIkNMRUFOIgo=",
          "beforeSha256": "287bc1b9cf6200617031eeb956fb143798607724b62bd4a31c20e422748100ee",
          "inputSha256": "1b0bc131d22e87a297c8d86e88d8232c134331d39f7ef2fac8271e3497021817",
          "offset": 85555,
          "outputSha256": "83728e89a914cca4a430a43745968b76d60fc1a5d33d3468c365038fed5cde64",
          "removeSize": 1859,
          "removedSha256": "7b20cc0805e0799af3cb56363801a936a8b1c21bdabeadf8e61618b05b95beb4"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgICAgICAgICAgICAgID09IHt0dXBsZShyW2tdIGZvciBrIGluIGZpZWxkcykgZm9yIHIgaW4gcmVzb3VyY2VzfSwgIkFETUlTU0lPTl9SRVNPVVJDRV9OT1RfQ0xFQU4iKQo=",
          "beforeSha256": "63eab7783e911945e4b5b8e47981d3689f464b44b456e8f85b5104f135a6ae7c",
          "inputSha256": "83728e89a914cca4a430a43745968b76d60fc1a5d33d3468c365038fed5cde64",
          "offset": 85327,
          "outputSha256": "7d38c57e7530a08d76ca73c89692c6495f83aad11bda9e909e038c8431027868",
          "removeSize": 114,
          "removedSha256": "12f194cedd60f6c49d035cc2ee53b46ffa98ec4d3ba3c8c048a5a37849e10bff"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgICAgICByZXF1aXJlKGxlbihyZW1haW5pbmcpID09IGxlbihyZXNvdXJjZXMpCg==",
          "beforeSha256": "a1e04147c505cb69172950ddb1d83406eb502ae001539c21f389cfcdaa942659",
          "inputSha256": "7d38c57e7530a08d76ca73c89692c6495f83aad11bda9e909e038c8431027868",
          "offset": 85184,
          "outputSha256": "55453f22e8b25442fb4aaf5ec94cd24e1d8f9a8eb000e5c2bf531adb2f9dc38b",
          "removeSize": 62,
          "removedSha256": "6ed573caa5fca960c3cd3da862504edc490d21fe2df2dd44ec9c3d0bcea0db2b"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgICAgIGlmIHJlc291cmNlczoKICAgICAgICAgICAgICAgICAgICAjIFVudGlsIGluZGVwZW5kZW50IGFic2VuY2UgYWNjb3VudGluZyBpcyBpbXBsZW1lbnRlZCwgZXZlcnkKICAgICAgICAgICAgICAgICAgICAjIGludGVudC9jcmVhdGVkIGlkZW50aXR5IHJlbWFpbnMgaGVsZCwgaW5jbHVkaW5nIGEgbG9zdCByZXBseS4K",
          "beforeSha256": "ba88bec46f3d142cbd1dbd01de0f1b740fc510996a130e5b30f6494f32600616",
          "inputSha256": "55453f22e8b25442fb4aaf5ec94cd24e1d8f9a8eb000e5c2bf531adb2f9dc38b",
          "offset": 84726,
          "outputSha256": "b162532dc76aa70839f0efae00d1489248e53d87237c130cfe707cc02ba93378",
          "removeSize": 298,
          "removedSha256": "d80444e106087d1a4f2e5a8ecd5576cdb53de424fb4573cff6e90cb52d5cf329"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "b162532dc76aa70839f0efae00d1489248e53d87237c130cfe707cc02ba93378",
          "offset": 83872,
          "outputSha256": "37a399fd2c010248e0093ac0ab789fd71abc1d3f3df9067eeae26611f21d2457",
          "removeSize": 429,
          "removedSha256": "ea13b66696e03938714e4efca0c5a944488c4a5d61ffd493eca129bf832c21f1"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgZWxpZiByb3dbInN0YXRlIl0gPT0gIlJFQ09SREVEIjoK",
          "beforeSha256": "eae9ab470c6202798138573798a0e5f7e8313a972ce9763c354d2022a7144474",
          "inputSha256": "37a399fd2c010248e0093ac0ab789fd71abc1d3f3df9067eeae26611f21d2457",
          "offset": 83687,
          "outputSha256": "e9deece926131a4cf75fb8a7e23e58280ec203b78459ee45467ddb155a4c6ad0",
          "removeSize": 65,
          "removedSha256": "01d1bda623ec806c898515d75deb0d7f3bb4bd68fbad1b50bb59bf713a06f24b"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgaWYgcmVzb3VyY2Vfcm93Ogo=",
          "beforeSha256": "c3c1b96df4268692eca2eb75220050a7f4869e1707eba3629b98b8217b791800",
          "inputSha256": "e9deece926131a4cf75fb8a7e23e58280ec203b78459ee45467ddb155a4c6ad0",
          "offset": 82273,
          "outputSha256": "9501aefc15f0d07241837a1732d3bbb121b50db59f00065f0eb458e32aa5feac",
          "removeSize": 968,
          "removedSha256": "e79c3ee8c5e0cf11a6a8d1d3e5d6e1b3ff3ef8b93319cac42bf9c978999fc2c5"
        },
        {
          "beforeBase64": "ICAgICAgICByZXNvdXJjZV9yb3cgPSByb3cuZ2V0KCJzdGF0ZSIpIGluICgiQ1JFQVRFX0lOVEVOVCIsICJDUkVBVEVEIikKICAgICAgICBjbG9zZWQocm93LCBMRURHRVJfRklFTERTICsgKCJyZXNvdXJjZSIsKSBpZiByZXNvdXJjZV9yb3cgZWxzZSBMRURHRVJfRklFTERTKQo=",
          "beforeSha256": "62555fd80282aedfc9c28689669072a3cda06a4c983b03af3d747ce7a4271437",
          "inputSha256": "9501aefc15f0d07241837a1732d3bbb121b50db59f00065f0eb458e32aa5feac",
          "offset": 80188,
          "outputSha256": "74cb65d70fab3546448debc1fadc12d9771317e9e13a71aee417982ac8a95d18",
          "removeSize": 501,
          "removedSha256": "9756936884ead398b41389daf37de3c3257d3a40832a1e850e1d2c16088e4e8a"
        },
        {
          "beforeBase64": "ICAgIHByZXZpb3VzLCByZXNlcnZhdGlvbnMsIHJlY29yZGVkID0gWkVSTywge30sIHNldCgpCg==",
          "beforeSha256": "28c19b3e0ff98577911f11a7352b44841bab90a3adacf2bb236aed8dbd936944",
          "inputSha256": "74cb65d70fab3546448debc1fadc12d9771317e9e13a71aee417982ac8a95d18",
          "offset": 79978,
          "outputSha256": "9c258fc28cbd66201931a24e6072fdc96f892e340386d54d239186301a37af1f",
          "removeSize": 66,
          "removedSha256": "286b1c44f25b761db8b833b8d146a9d6bd16ac96e677613ac72d99dc8a74e5ab"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "9c258fc28cbd66201931a24e6072fdc96f892e340386d54d239186301a37af1f",
          "offset": 75972,
          "outputSha256": "71bcba0aa4358b73b2a87b62d966ee8e7ca9e353faa6cbc2a453f224d9090eeb",
          "removeSize": 3768,
          "removedSha256": "132057f65474f604d43940e3e54973f0761f07ebdba629b5aaa41c61dd844a15"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "71bcba0aa4358b73b2a87b62d966ee8e7ca9e353faa6cbc2a453f224d9090eeb",
          "offset": 74911,
          "outputSha256": "fa0484a8d2e4409f07c5e2728ae9f81e1046e098414990fdf80f37b34278cc8d",
          "removeSize": 166,
          "removedSha256": "3c4d89980e92af0c2b5598fd29fb4b3f55ae9316800235b9bc10964968f37192"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "fa0484a8d2e4409f07c5e2728ae9f81e1046e098414990fdf80f37b34278cc8d",
          "offset": 73064,
          "outputSha256": "b00bbc099321b2bc200ec20798e380da2b2557a603fc9ec55b66120dc4447cdf",
          "removeSize": 1345,
          "removedSha256": "f0c9f2b0d3a7413536bea1e89c0dba4a661915169053683075eb93430d96f186"
        },
        {
          "beforeBase64": "ICAgICIiIlJlcGxheSBvbmx5IGludGVudC9pZGVudGl0eSBmYWN0cy4gTmVpdGhlciBmYWN0IHBlcm1pdHMgY2xlYW51cCBvciByZWxlYXNlLiIiIgo=",
          "beforeSha256": "f4df82f5a60d05e378abee885c30a4207f11af43faedc01a7b9fe03c4bfee006",
          "inputSha256": "b00bbc099321b2bc200ec20798e380da2b2557a603fc9ec55b66120dc4447cdf",
          "offset": 72119,
          "outputSha256": "3158a28b3aecd81c2dbf80b2e8c4dbfe1973672d85199d4e1c498671e6f73264",
          "removeSize": 84,
          "removedSha256": "10613d5602cb23032280859e6fa0bbd573a855f88de785e8fcf7eb22e03e0842"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "3158a28b3aecd81c2dbf80b2e8c4dbfe1973672d85199d4e1c498671e6f73264",
          "offset": 70411,
          "outputSha256": "609c125604f3406bf9faf126346f22c54a47dbf522d4d8b74ee34ba6b6b2a6ce",
          "removeSize": 1670,
          "removedSha256": "63b85f085ce3d3a7c2cc66f8c79ee083985ed653e7a44fb6567e648e96205189"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "609c125604f3406bf9faf126346f22c54a47dbf522d4d8b74ee34ba6b6b2a6ce",
          "offset": 61985,
          "outputSha256": "2a5fd59a9cc75bc6afa709a11cecf0700e27ecd567c27ec1c3c3486ef02454fc",
          "removeSize": 4170,
          "removedSha256": "f4ebc8bc3fd2c7fd9887e1bd046f3434de13ee4e744d6977cc1175e795b84a80"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "2a5fd59a9cc75bc6afa709a11cecf0700e27ecd567c27ec1c3c3486ef02454fc",
          "offset": 45142,
          "outputSha256": "7a9b2170e99bb7b50ad5e17090a12f42876b7f463d661d8d2b0d83c7d27262fe",
          "removeSize": 504,
          "removedSha256": "e9816d07a888cac999c06454242677240b1ba796fcd9d13c6bf993565499377c"
        }
      ]
    },
    {
      "path": "tests/live_backend/test_proxy_server.py",
      "steps": [
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "7edcc67ae1f0463a0f2df9f2a06d6c9a0eda35290e30aa09099dd414f9369d81",
          "offset": 604281,
          "outputSha256": "42bbe09a06cfee6947cc690d83a3cac8ca564918f30e846a04fbfe564af520aa",
          "removeSize": 100574,
          "removedSha256": "18fff456fe6b11965a00fa1386012c2f2e1c53fac05729ff2e229daf034b2be3"
        },
        {
          "beforeBase64": "ICAgICAgICB3aXRoIHBhdGNoLm9iamVjdChzZXJ2ZXIsICJfZml4ZWRfcHJvYmVzIiwgc2lkZV9lZmZlY3Q9QXNzZXJ0aW9uRXJyb3IoIm5vIGxlZ2FjeSBvYnNlcnZlciBob29rIikpOgo=",
          "beforeSha256": "48a98007e23668345d403d405e2b77956b7adc6e76c060cc3a1b0ef9e23e2ab5",
          "inputSha256": "42bbe09a06cfee6947cc690d83a3cac8ca564918f30e846a04fbfe564af520aa",
          "offset": 598238,
          "outputSha256": "daf1b7e51aa7d7528c0e0c77973318327e255dddaf62ee750038670459d239bd",
          "removeSize": 120,
          "removedSha256": "5babd5971da8883c9eb2d8eb791633a8203d2b6ab6eb440d7e627803252d9340"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgKHNlcnZlciwgIl9maXhlZF9wcm9iZXMiLCBkaWN0KHJldHVybl92YWx1ZT1TaW1wbGVOYW1lc3BhY2UocmVxdWlyZV9vYnNlcnZlcl9jb250YWlubWVudD1zZWxmLmNvbnRhaW5tZW50KSkpLAo=",
          "beforeSha256": "fcc88b25a6100323b29022538dad2089662a75e7ac600d1d9fc9b277670386f0",
          "inputSha256": "daf1b7e51aa7d7528c0e0c77973318327e255dddaf62ee750038670459d239bd",
          "offset": 582894,
          "outputSha256": "732237476dff55643fa962e680fcb91e6601116729ed1ef313f28f7e4ec95b00",
          "removeSize": 135,
          "removedSha256": "b7c22c12f762177917cdcd58a4bbc89d20cd530ef6428c3c40624695e4e16470"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "732237476dff55643fa962e680fcb91e6601116729ed1ef313f28f7e4ec95b00",
          "offset": 549045,
          "outputSha256": "1ba0e89b27fe0e0cd7b0def5b06d9279a077d9422c3185eb25e7b6098d492b79",
          "removeSize": 30557,
          "removedSha256": "99ddb82895ea17def271bed4d475dd6ebc68d731a3c564df9fb3b879aa1de66c"
        },
        {
          "beforeBase64": "ICAgICAgICAgICAgJ3JlcXVpcmVfc2VydmVyX2NvbnRhaW5tZW50KHNlbGYpJywgJ3NlbGYub2JzZXJ2ZXIuX19pbml0X18oc2VsZiknLAo=",
          "beforeSha256": "1898add89b735eab31e7f3c0ee4bb36e0018af56bea96f1f60a604d121b6660d",
          "inputSha256": "1ba0e89b27fe0e0cd7b0def5b06d9279a077d9422c3185eb25e7b6098d492b79",
          "offset": 548599,
          "outputSha256": "81aa68eff589f2d012afa38e87fce2ddf30fa5bdbbf6d728f4f6feea498ec9bb",
          "removeSize": 81,
          "removedSha256": "297787b6c028811bc738e3cd9fecd6774ed487d540e7ef9b3ea393a5d5ea09d0"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "81aa68eff589f2d012afa38e87fce2ddf30fa5bdbbf6d728f4f6feea498ec9bb",
          "offset": 533990,
          "outputSha256": "60436d8250e99279528af85aafac663a8d81315c0f8689cdc5a8e05fb9315b45",
          "removeSize": 14242,
          "removedSha256": "0300a3b63df0755afdd470404142090d1dd29d8679fcf7326f502c66f47eb75f"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "60436d8250e99279528af85aafac663a8d81315c0f8689cdc5a8e05fb9315b45",
          "offset": 469150,
          "outputSha256": "e47b9af20b395d5b8f24b8d8d8aaf144fcc7b30f07fe412dd0762f4ba2bfbe66",
          "removeSize": 64239,
          "removedSha256": "a2129ee91c39d38ddc564f30760003bf81af69a0eb1205908c194fad645dec3d"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "e47b9af20b395d5b8f24b8d8d8aaf144fcc7b30f07fe412dd0762f4ba2bfbe66",
          "offset": 328512,
          "outputSha256": "ebfe3e5e10a911549402371121cfff8fe5171d120b36e2c764ebc45f6306b3f0",
          "removeSize": 939,
          "removedSha256": "5e57220d9194e730f7e31aad62ad11ce763e74db5ddbdd78a012654dc1495e79"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "ebfe3e5e10a911549402371121cfff8fe5171d120b36e2c764ebc45f6306b3f0",
          "offset": 312301,
          "outputSha256": "aab76e5b5f2ea18d8cfbdb63f4c5f83a377c5b6dbe4742626e00bb8d3ff99a0f",
          "removeSize": 184,
          "removedSha256": "9f77c49bdb458410265b76ffa113956337fce00e7543fb595d6243d7573a8c16"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "aab76e5b5f2ea18d8cfbdb63f4c5f83a377c5b6dbe4742626e00bb8d3ff99a0f",
          "offset": 310280,
          "outputSha256": "ef0df10570a8be6f68bf2094e58280407f34c2abb0d098f40a69ef7427148e13",
          "removeSize": 1451,
          "removedSha256": "613f4f4f8041058ea5255d07afa8941bdffb6746f0de670399c9f6a93f334cf0"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "ef0df10570a8be6f68bf2094e58280407f34c2abb0d098f40a69ef7427148e13",
          "offset": 43244,
          "outputSha256": "f7a66ba1c2efb9d781182d2fb1daa23963fe1688e3f8c760f0e0e7ad35095ec5",
          "removeSize": 63,
          "removedSha256": "489c30a8ea3a1763a8c3b2c73ba9472103c0fb7d869339b847303eb5ec156f39"
        },
        {
          "beforeBase64": "ICAgICAgICBzdGFnZXMgPSBbInNlbGYucXVhbGlmaWNhdGlvbl9iaW5kaW5nLl9faW5pdF9fKHNlbGYpIiwgInNlbGYuc2VsZl9pbnNwZWN0aW9uLl9faW5pdF9fKHNlbGYpIiwKICAgICAgICAgICAgICAgICAgIl9maXhlZF9wcm9iZXMoKS5yZXF1aXJlX3NlcnZlcl9jb250YWlubWVudChzZWxmKSIsICJzZWxmLnN0b3JhZ2UuX19pbml0X18oc2VsZikiLAo=",
          "beforeSha256": "14be7d016d44a8581e51fd3f10af1a2456f6a4968e487119c8a2cca015e788ff",
          "inputSha256": "f7a66ba1c2efb9d781182d2fb1daa23963fe1688e3f8c760f0e0e7ad35095ec5",
          "offset": 42914,
          "outputSha256": "eaae67c07737ee285dc0b23606c7f7adea6faab201e487bf70e40f6db5ad013c",
          "removeSize": 149,
          "removedSha256": "b858a449b1996fcb17d3eada5041c3d1690b0a90b7eeb636db995098f80dbe43"
        },
        {
          "beforeBase64": "ICAgICAgICBzdGFjay5jYWxsYmFjayhvd25lci5maWxlcy5jbG9zZSkKICAgICAgICByZXR1cm4gb3duZXIK",
          "beforeSha256": "dd75d2e1f01205834b2c491cccaf1c2e04dd9d4a641445aca5d285f833308004",
          "inputSha256": "eaae67c07737ee285dc0b23606c7f7adea6faab201e487bf70e40f6db5ad013c",
          "offset": 13520,
          "outputSha256": "08f0ae9a341d930351b1e835d656087a9c4bffe79e2c8009b6ab84238e70750a",
          "removeSize": 0,
          "removedSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        {
          "beforeBase64": "ICAgICAgICBzdGFjay5lbnRlcl9jb250ZXh0KHBhdGNoLm9iamVjdChzZXJ2ZXIsICJfQUNUSVZFIiwgb3duZXIpKQo=",
          "beforeSha256": "3f29f1a157c2dd99a3ec778f0927fbd33aed419d3ff15e924bbb7ab09d803bcb",
          "inputSha256": "08f0ae9a341d930351b1e835d656087a9c4bffe79e2c8009b6ab84238e70750a",
          "offset": 12510,
          "outputSha256": "ef0f2d913879b24909f311d9a976420d6de867423bdffa421e7a59d5f9d12519",
          "removeSize": 0,
          "removedSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "ef0f2d913879b24909f311d9a976420d6de867423bdffa421e7a59d5f9d12519",
          "offset": 11103,
          "outputSha256": "d86493b44c920683d46b06a23990011b941a164009d3bd3623a7f0b03207141b",
          "removeSize": 366,
          "removedSha256": "2da084f9f3ce6ad7039ed020f1c3bad2e202b54377d0e44169d9d994c733b1c9"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "d86493b44c920683d46b06a23990011b941a164009d3bd3623a7f0b03207141b",
          "offset": 298,
          "outputSha256": "05e715db5e27b4560dc397ad15f4522490a9122e8efd0daa52563db1cd8f4a3c",
          "removeSize": 20,
          "removedSha256": "3abf78b30b379289bae0e4a2e8e0f124f18e53dbf39eb2dc9dbe563133c23f8f"
        }
      ]
    },
    {
      "path": "tests/live_backend/test_mutation_admission.py",
      "steps": [
        {
          "beforeBase64": "ICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG9ic2VydmVkLCBfZG9jX2lkcyhzb3VyY2VzKSkKICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHN1bShtYXAobGVuLCBvYnNlcnZlZC52YWx1ZXMoKSkpLCAxMzA5KQogICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc3VtKGxlbihpZHMpIGZvciBwLCBpZHMgaW4gb2JzZXJ2ZWQuaXRlbXMoKSBpZiBwLnN0YXJ0c3dpdGgoInRlc3RzL2xpdmVfYmFja2VuZC8iKSksIDExMzkpCg==",
          "beforeSha256": "e95ce150957c9bae950a2d2dd5c0910326109d4d4f5d03e9f05f311664b4cd13",
          "inputSha256": "67e6c34885063a3a7d2a58914713243093509073624bab99999af7ccd55ce6dd",
          "offset": 106226,
          "outputSha256": "ecceb77f14f358f896ec378751d91a4964a7f0d54fe240011f91523d43e0c975",
          "removeSize": 17364,
          "removedSha256": "1ad86e6b4b1e2504ab50a6f0d9c00216380717e12b960a4c6aceda2916a517ac"
        },
        {
          "beforeBase64": "ICAgICMgUmV1c2Ugb25seSB0aGUgYWNjZXB0ZWQgY3VycmVudC1maWxlIHJlYWRlciwgbm90IGl0cyBhY2NlcHRhbmNlIHJlc3VsdC4KICAgIGZyb20gX2ludmVudG9yeSBpbXBvcnQgU1VDQ0VTU09SCiAgICByZXR1cm4gU1VDQ0VTU09SLnRyYWNrZWRfaW52ZW50b3J5KFJPT1QpCg==",
          "beforeSha256": "83461436395b1fe20f09aadbd68153d699eaff911ca8af2d3c5145c28aa4a169",
          "inputSha256": "ecceb77f14f358f896ec378751d91a4964a7f0d54fe240011f91523d43e0c975",
          "offset": 88392,
          "outputSha256": "e46eea8b048e5a40a9e16551b35e37fc5159ba6624de9030fbdcf95b1bb6e628",
          "removeSize": 242,
          "removedSha256": "e06a292957e0a71ae6ee9da1d71471488d9a0368a4b520e7eb9220315358d902"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "e46eea8b048e5a40a9e16551b35e37fc5159ba6624de9030fbdcf95b1bb6e628",
          "offset": 36732,
          "outputSha256": "22fc5bee77dba8d17e1aa8dedc3a7b666685bbd4953aa56558257117de7efa79",
          "removeSize": 46309,
          "removedSha256": "b9d0dbb2c9345fdd620a1fa93fc4b4b4a8eb36ae9d5e50bf705d313596e187b5"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "22fc5bee77dba8d17e1aa8dedc3a7b666685bbd4953aa56558257117de7efa79",
          "offset": 246,
          "outputSha256": "d91e957c0b18865e6702f574402de03a55734c1e04b5a9401f80ef9f2a13d30a",
          "removeSize": 32,
          "removedSha256": "cb7a187127ab8da0ce3a2254bddf0cbcafdb7db25850da760ff654fc6e5bc5e1"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "d91e957c0b18865e6702f574402de03a55734c1e04b5a9401f80ef9f2a13d30a",
          "offset": 175,
          "outputSha256": "6d8d0526ee2d5c47713aed4081eba41294fe1cd45cf231efe08457fb32b827b2",
          "removeSize": 10,
          "removedSha256": "a830333312c4c9c2233bb02762bd498203b1c3bf0527614735693b4b79f6d167"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "6d8d0526ee2d5c47713aed4081eba41294fe1cd45cf231efe08457fb32b827b2",
          "offset": 109,
          "outputSha256": "1754bed560ce691b8cdc41db288549c712428f2f2ada843c2a578088307bf1f1",
          "removeSize": 40,
          "removedSha256": "bd3698cb9f306b035e45c51278a2dfff864360ff5b22ba137ee373b0821704bb"
        }
      ]
    },
    {
      "path": "docs/live-backend/proxy.md",
      "steps": [
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "ab1025e21fbd78ab7ed212b313d3c285566d05528e523e81d418b7ec189d4c54",
          "offset": 262298,
          "outputSha256": "38ed88c77e29e2986926e069833dea0665c4922ba14799d3ac613abfa12d0fe5",
          "removeSize": 3066,
          "removedSha256": "01564463946b885f0658245c782d3ca6f65f1ae45838e1125f6016b15074cb21"
        },
        {
          "beforeBase64": "",
          "beforeSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "inputSha256": "38ed88c77e29e2986926e069833dea0665c4922ba14799d3ac613abfa12d0fe5",
          "offset": 48,
          "outputSha256": "e76fdcf46628e175bc641057e36a5daec1268c6bf55f4c1784c1b747d4710ad1",
          "removeSize": 30046,
          "removedSha256": "85fcb220edadb848633a573c4799f9957031be705958810a2776db801526bb9d"
        }
      ]
    }
  ]
}
<!-- CONF-FIX-008 SOURCE_DELTA_ONLY END -->
