# Retained feasibility screen

This is the research checkpoint preceding MET-ENFORCE-001. Its proposed owner
assignment is now selected for planning in [the amendment](ENFORCEMENT_INTEGRATION.md).
All unproven mechanisms and deployment limitations remain. The research pins are
citations, not release locks; no independent implementation review is claimed.

# Enforcement feasibility: reuse, integration gaps and proof obligations

Research checkpoint OBS-ENFORCE-FEAS-001; 2026-09-17. **DESIGN/RESEARCH ONLY**.
This document is not a runtime contract amendment, execution packet, installed
artifact inventory, independent security review or qualification receipt.

## 1. Scope and current authority

The accepted META tree is `983bcac33147b7a71b9b2f515519cefffb8b7eca` at main
`69dceab436cf16bcebade98ba4dd015505434215`. The normative inputs are:

| Input in harness-onion | SHA-256 |
|---|---|
| docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md | 44ceb7ef3a8e2c71b93cbaee695ee486c65b1be9d4e9fdd564473ec65681b1e6 |
| docs/alpha-2/OBSERVATION_ENFORCEMENT_DELTAS.md | 4260960e4e0e4f039de78226f23c651f06040b4bb3467498a59b5f91be8b9e6c |
| docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md | 60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595 |
| docs/alpha-2/BROKER_HANDOFF_READINESS.md | 2cc6ebef252efb33744208378b29248d89597e5a0be7c4a1a113adc9d63b9fc3 |
| docs/repositories/10-mas-harness-operator.md | d0d254b8795d5581e7e5fef8243f8bf73423568489a9fcb99d17befb18f30952 |
| task-packets/CONF-FIX-010.yaml | e4eea58d0f5c18444d23863a1f9179fa183491007f92ce2fa2b92cd2a5cc417f |

The observation design explicitly leaves the independent installed maintainer
and implementation UNSELECTED. Broker handoff requires a native ELF at the fixed
broker path, authenticated SOCK_SEQPACKET framing, original-parent worker
ownership, durable consumption, external per-effect generation admission and
independently authorized exact-UID cleanup. It is not a generic OCI protocol.

The R10 Kubernetes controller is nonroot and manages verified installations. It
is not already the privileged host broker just because both are called an
operator. Treating it as one would introduce an unreviewed privilege boundary.

## 2. Candidate assessment

Versions below identify **research references**, not selected supported releases.
No candidate was installed, benchmarked, vulnerability-cleared or qualified.

| Component | Reuse value | Gap against this project's fixed contract | Decision for the next design |
|---|---|---|---|
| Linux SELinux, fs-verity, cgroup v2/BPF, pidfds | Existing kernel mechanisms required by the native profile | Exact policy, program semantics, writer exclusion and process lifecycle still need implementation/proof; hashes alone do not supply them | Retain as the baseline primitives; select the actual pre-existing host and patched artifact set separately |
| systemd | Established process supervision and cgroup ownership/delegation | Ordinary managed/delegated paths differ from the four fixed root-level paths; network settings do not establish the complete prescribed hook ABI | Preferred supervision candidate, conditional on an explicit integration/profile decision |
| libseccomp | Existing userspace abstraction for syscall filters | Cannot establish path semantics, the broker protocol, Python object integrity or remote API admission; not a sandbox by itself | Evaluate for a separately scoped native host component, not as a dependency added to the stdlib-only reader |
| runc / OCI runtime | Established container creation/start/lifecycle boundary | An OCI launch is not proof of the required original broker parent, exact namespaces/FD3 custody or custom transcript | Not selected as a drop-in broker; retain only if a later explicit integration proves those properties |
| Tetragon | Actual inline kernel enforcement at supported hooks | Signal-only actions do not necessarily prevent the triggering effect; policy coverage and our exact ABI/generation protocol remain unproven | Supplementary candidate; neither dismiss as observer-only nor accept as complete fencing |
| Falco | Mature event detection and alerting | Detect/respond does not establish synchronous pre-effect denial | Optional observability, never the enforcement premise |
| Kubernetes admission | Request validation and policy rejection | Reads bypass admission; admitting a request does not guarantee persistence; callbacks do not by themselves serialize every policy writer with our generation | Defense-in-depth, not the sole operation/generation gate |

Primary-source support and bounded interpretation:

- fs-verity protects file data on read and exposes a distinct integrity digest.
  **Inference:** it does not, on its own, prove pathname custody, process identity,
  descriptor ownership or mutable interpreter state.
  [Linux 6.12 fs-verity](https://www.kernel.org/doc/html/v6.12/filesystems/fsverity.html)
- systemd documents exclusive ownership of each cgroup and delegation below a
  service/scope. Its normal unit paths carry `.slice`/`.service`/`.scope`
  components. **Inference:** independently creating the current
  `/sys/fs/cgroup/planeon-live/...` tree on a systemd-managed root is not a
  supported delegation plan.
  [Pinned delegation guide](https://github.com/systemd/systemd/blob/70bae7648f2c18010187c9cf20093155eaa26029/docs/CGROUP_DELEGATION.md)
- `IPAddressAllow` selects addresses; `SocketBindAllow` restricts `bind`, not
  outbound destination-port admission. **Inference:** these settings alone are
  not an implementation of our required seven-hook endpoint profile. This does
  not rule out separately reviewed BPF programs under a compatible hierarchy.
  [Pinned resource-control documentation](https://github.com/systemd/systemd/blob/70bae7648f2c18010187c9cf20093155eaa26029/man/systemd.resource-control.xml)
- libseccomp supplies a syscall-filter API; Linux describes seccomp as one
  confinement mechanism, not a complete sandbox.
  [Pinned libseccomp README](https://github.com/seccomp/libseccomp/blob/90d3f7dd6f52dbf0f4a38ebd0657032b6ef05e6a/README.md),
  [kernel seccomp guide](https://www.kernel.org/doc/html/v6.12/userspace-api/seccomp_filter.html)
- runc launches OCI containers. OCI separates creation from starting the payload.
  **Inference:** those useful lifecycle semantics are not evidence for our
  additional parent, transport, credential and cleanup requirements.
  [Pinned runc README](https://github.com/opencontainers/runc/blob/4ca628d1d4c974f92d24daccb901aa078aad748e/README.md),
  [pinned OCI lifecycle](https://github.com/opencontainers/runtime-spec/blob/36852b0d072a4b5da675300a9e73bc4b0853f5c6/runtime.md)
- Tetragon supports return-value override and signal actions; its documentation
  warns that killing a process alone may not prevent the triggering write.
  **Inference:** evaluate the precise hook and denial semantics for each protected
  operation, not the existence of a TracingPolicy.
  [Pinned enforcement documentation](https://github.com/cilium/tetragon/blob/602a62efbc9115b4f30bf9b58e08c65a26c82090/docs/content/en/docs/concepts/enforcement/_index.md)
- Falco describes its core as event monitoring/detection with alerts.
  **Inference:** an alert or downstream response is not our admission boundary.
  [Falco documentation](https://falco.org/docs/)
- Kubernetes GET/LIST/WATCH bypass admission, and webhook success does not
  establish storage completion. **Inference:** our fixed GET operation still
  needs the independent operation gate; mutation admission does not discharge
  durable intent/result reconciliation or full policy-writer exclusion.
  [Pinned admission overview](https://github.com/kubernetes/website/blob/829193727bd7ba724a19bee71887e79dde36739c/content/en/docs/reference/access-authn-authz/admission-controllers.md),
  [pinned webhook semantics](https://github.com/kubernetes/website/blob/829193727bd7ba724a19bee71887e79dde36739c/content/en/docs/reference/access-authn-authz/extensible-admission-controllers.md)

## 3. Three concrete integration decisions still required

### F01 — cgroup ownership and path compatibility

Existing readers admit exactly four cgroups beneath the fixed root-level
`planeon-live` path. Do not silently discover a systemd service path, alias it,
accept a caller-supplied prefix, or disable systemd ownership rules.

Two honest options remain: qualify a separately managed existing host hierarchy
that satisfies the original contract, or publish a versioned native-profile
successor that enrolls four exact canonical paths beneath a properly delegated
subtree. Prefer investigating the latter for conventional enterprise Linux.
It is a proposal, not an adopted reader change. An amendment must cover both
record validation and consumers, exact ancestors/inodes, namespace views,
single-writer ownership and a migration/refusal policy for the old profile.
It must not turn arbitrary paths into admissible inputs.

### F02 — exact BPF and role containment

Retain the current seven hook types, map-free programs, bounded translated
instruction identity and exact local/effective program requirements unless a
separate reviewed profile amendment explicitly changes them. A systemd, CNI or
Tetragon preset is not proof of those exact properties. Inspect actual ancestor
attachments for the required hooks rather than assuming every unrelated hook is
forbidden. Do not detach enterprise security controls to make the count pass.

Select or build only the narrow missing policy/loader integration after an exact
owner, pinned dependencies and native inspection plan exist. Lifecycle must
establish containment before role execution; no privileged loader is smuggled
into `_KernelQualification`, the worker, or the nonroot Kubernetes controller.

### F03 — broker / observer / API-effect enforcement

The custom fixed broker protocol and generation admission remain unimplemented
prerequisites in the inspected planning record. The reader's successful checks
cannot manufacture them. Specify three distinct implementation responsibilities:
host containment/lifecycle, independently current policy observation, and an
external gate on each admitted resource operation. These are not three newly
authorized daemons, sockets or signing identities.

The gate design must name its actual linearization point, durable intent before
forwarding, and how all policy writers are excluded or serialized. Include
RBAC/aggregation/impersonation, quota/network/namespace changes, control-plane
configuration, privileged administrative paths and already authenticated
connections. A watcher, lease, webhook acknowledgement or Python boolean does
not meet this requirement. The trusted-administrator/kernel boundary remains
the published one; do not expand the threat model to a hostile kernel or pretend
a cooperative administrator convention is independently enforced exclusion.

Existing fixed channels and server-only API credential ownership are the first
integration constraint. If insufficient, enumerate the exact additional private
interface and privileges in an amendment before implementation. Do not add a
header, public receipt field, callback or broad Kubernetes grant implicitly.
Already admitted remote work may complete after invalidation and must remain
recorded; new and queued operations cannot acquire permission from the old
generation. Fail closed without waiting for a stalled Python role.

## 4. Full obligation ledger — no closures claimed

Each row is **OPEN_UNPROVEN**. Candidate primitives are not evidence. The native
tests below are minimum evidence themes, not an exhaustive executable campaign.

| ID | Reuse / remaining implementation | Required proof before reduced observation | Accountable work |
|---|---|---|---|
| E01 | SELinux plus fs-verity; explicit ancestor/path/writer policy | Transient rename/restore, aliases, retained writers, relabel and mode changes denied or quiesced before change | External host maintainer; R10 integration; R12 verification |
| E02 | Retain reader-owned descriptors and checks | Close/dup/reuse/inheritance/ancillary injection; never close an unrelated reused FD | R12 |
| E03 | Kernel namespace/mount restrictions plus host update exclusion | Bind/overmount/propagation/setns bypass denied; enrolled roots remain exact | External host maintainer; R10; R12 |
| E04 | SELinux enforcing policy and exclusive update lifecycle | Policy/boolean/permissive/relabel changes; deny then quiesce; no stale policy snapshot or ABA | External host maintainer; R10; R12 |
| E05 | Cgroup v2 and exact BPF endpoint programs | Migration, ancestor/filter/link changes, finite limits; reconcile systemd ownership first | External host maintainer; R10; R12 |
| E06 | SELinux/seccomp and fixed native/code inventory | Loader versus sealed phase; COW/injection/mprotect/memfd/fork/exec and mapped dependency closure | External host maintainer; R10; R12 |
| E07 | pidfds, exact peer credentials and broker parentage | PID reuse, crash, replacement and channel loss deny; no reconnect or rebinding | External broker maintainer; R12 |
| E08 | Original clocks/deadlines plus independent expiry enforcement | Suspended/blocked roles and clock changes cannot extend authority | External broker maintainer; R12 |
| E09 | Existing private factory and dynamic guards | Reentrancy/wrong owner/partial construction/state corruption fail sticky; explicit trusted-code boundary | R12 |
| E10 | Explicit API-operation and policy-generation gate | Old connections, queued work and all policy-writer bypasses; read gating; exact admission and invalidation ordering | External admission maintainer; R10; R12 |
| E11 | Protected durable reservation/history and deny-on-restart | fsync/partial-write/host crash/history rollback/generation reuse; never resurrect ACTIVE from stale state | External broker maintainer; R10; R12 |
| E12 | Broker process ownership, reaping and exact-UID records | Descendant escape, hung termination, in-flight remote effects and denied cleanup retain uncertainty/capacity | External broker maintainer; R10; R12 |

The exhaustive old/new observation-window map is **not completed by this table**.
It must trace direct and indirect custody, clock and peer checks against the
exact product revision, including autonomous-event latency. Product source was
not opened or executed in this research turn. Retain all current checks and the
existing regression identities until a separately scoped successor proves each
permitted change. In-process mutable state and autonomous events cannot be
erased from the obligation list by proving only host policy stability.

## 5. Ownership and dependency decomposition

Keep 13 repositories, four planes and 16 harnesses. No new repository is proposed.
Research/source links do not authorize copying code from upstream or warm sources.

| Work order | Owner | Deliverable / exit condition |
|---|---|---|
| 1 — precise feasibility publication | R00 | Proposed MET-ENFORCE-001: resolve F01–F03 into explicit decisions, exact module owners, interface deltas, immutable predecessor inputs, packet paths and compatibility tests. No native grant or product implementation in this publication. |
| 2 — contracts, if affected | R01, then consumers | New version only where public record/install/evidence interfaces change; old/new refusal and migration vectors. Internal native ABI changes remain explicit even if R01 is not needed. |
| 3 — host prerequisite owner packets | R10 proposed, subject to architecture amendment | Separate native host-maintenance/broker/policy modules and release artifacts from the nonroot Kubernetes controller; no shared process, credentials or blanket privileges. Upstream primitives reused; exact build/license locks first. |
| 4 — independent enforcement tests | R12 | Separately scoped tests for actual host and admission enforcement. Reader observes evidence; it does not implement or self-certify the enforcement premise. |
| 5 — offline released artifacts | R11 | Artifact digests, signatures, SBOM, license obligations and offline dependency closure for the exact selected profile; no automatic downloads. |
| 6 — native enforcement premise | External installed authority + R12 campaign | Existing Linux target, exact preinstalled artifacts and independent signatures; native AMD64/ARM64 proof as declared. Source-only doubles never close this gate. |
| 7 — temporal reader successor | R12 after premise/design closure | Exhaustive direct/indirect trace mapping, preserved refusal semantics, exact packet/allowed paths/finite budget; full source acceptance and independent native integration afterwards. |

Order 3 is a **proposed ownership amendment**, not permission to place a root
service in R10 today. Its implementation language, maintainer, private state
locations and install interfaces need exact selection in order 1. If no bounded
implementation satisfies the contract, record that limitation and keep affected
live capability unavailable; do not expand into a general cluster controller or
quietly weaken the guarantee.

Dependency arrows remain consumer to provider. R12 consumes released interfaces
and exact evidence, never R10 implementation imports. R11 packages released
artifacts; later installation consumes the verified bundle. Independent testing
is not a source/build dependency cycle. Cross-repository changes use separate
owner packets and predecessor releases, not one broad implementation PR.

## 6. Deployment/version/license boundary

The local host reported `Darwin 25.6.0 arm64`. Read-only stat found no local
`/opt/planeon/bin/harness-capacity-broker`, broker manifest, or trusted live
campaign launcher. The root-owned macOS runner-maintenance policy exists. These
facts establish only this Mac's state, not the absence of Linux capacity elsewhere.
No remote host was contacted or inventoried and no VM/cluster was created.

Research references resolved through GitHub:

| Repository / reference | Exact research commit |
|---|---|
| torvalds/linux v6.12 | adc218676eef25575469234709c2d87185ca223a |
| systemd/systemd v257 | 70bae7648f2c18010187c9cf20093155eaa26029 |
| opencontainers/runc v1.3.0 | 4ca628d1d4c974f92d24daccb901aa078aad748e |
| opencontainers/runtime-spec v1.2.0 | 36852b0d072a4b5da675300a9e73bc4b0853f5c6 |
| cilium/tetragon main at observation | 602a62efbc9115b4f30bf9b58e08c65a26c82090 |
| falcosecurity/falco master at observation | eeb59cafca0e0419475a58018ec49f7b1cc67067 |
| kubernetes/website main at observation | 829193727bd7ba724a19bee71887e79dde36739c |
| seccomp/libseccomp main at observation | 90d3f7dd6f52dbf0f4a38ebd0657032b6ef05e6a |

These are citation pins, **not production locks or endorsed patch levels**. The
Falco website was consulted separately; no claim is made that its rendered bytes
correspond to the observed Falco code commit. Kernel 6.12 is the existing ABI
reference, not permission to deploy an unpatched kernel. Target distribution,
kernel build, package/container digests, supported architectures, CVE disposition
and license/SBOM closure remain unselected or unqualified.

Repository license metadata is not enough: for example, the systemd API metadata
reported GPL-2.0, while its versioned licensing guide distinguishes LGPL-licensed
core programs and GPL-licensed udev components. Shipping decisions need the exact
artifact and dependencies, not the repository badge.
[Pinned systemd licensing guide](https://github.com/systemd/systemd/blob/70bae7648f2c18010187c9cf20093155eaa26029/LICENSES/README.md)

Preserve no paid APIs, no billable provisioning, no hosted runner use, no runtime
downloads and no telemetry defaults. Existing-source evidence, code, CI, merge,
artifact, installed/native qualification and tenant acceptance stay separate.

## 7. Exit criteria for the next publication

Before an enforcement or reader implementation is runnable, the next amendment
must contain: exact owner modules and paths; selected interfaces and deployment
assumptions; reviewed threat/bypass model; exact artifact/license dependencies;
finite offline commands/budget; failure and migration behavior; exhaustive
observation-delta work ownership; independent review and native evidence gates.
It must explicitly resolve F01–F03 or retain them as blocking. Publishing this
dossier alone cannot satisfy that exit condition.
