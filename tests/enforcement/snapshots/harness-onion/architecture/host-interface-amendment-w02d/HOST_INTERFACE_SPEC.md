# W01 host interfaces — gate resolutions, candidate v2 with amendment W02D

Effective text of `HOST-INTERFACE-DRAFT-002` with amendment W02D (`HOST-INTERFACE-DRAFT-002-W02D`, section 11) applied.
The reviewed v2 file (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`) stays byte-identical;
`architecture/host-interface-amendment-w02d/amendment.json` lists every change.

Design label `HOST-INTERFACE-DRAFT-002`; owner R00 coordinating R10/R12.
Base: the independently reviewed corrected candidate `HOST-INTERFACE-DRAFT-001`
(`architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md`, SHA256
`1b0bee7e46e3cd730b3f878179ac36d0f062ce70ed6c843788ab634aead16ef0`, verdict
PASS_FOR_SOURCE_PUBLICATION with G04-G07 and G09 open). That file stays byte-identical.
This document resolves G04, G05, G06, G07 and G09 at design level. Everything in
the base that is not amended here stays in force, including its §1 boundary, §5
generation states, §8 reuse policy and §9 delivery order.

This is a specification, not an installed gate, adopted wire ABI, native result or
proof of any enforcement obligation. All E01-E12 remain OPEN_UNPROVEN. T01-T08 are
still unexecuted specifications. W02-W07 remain work labels until their own packets.

## 0. Disposition vocabulary

- **RESOLVED_DESIGN**: a concrete mechanism is selected; every property that only an
  installed host can show is named as a residual native or source evidence item.
  A RESOLVED_DESIGN gate no longer blocks W02 design work. It closes no E row,
  grants no installation, and makes no capability available.
- **UNRESOLVABLE_WITHOUT_NATIVE_EVIDENCE**: no design-level mechanism can settle the
  question. None of the five gates uses this disposition; the residual items in
  §8 are the parts that do need native evidence.

Kernel facts below cite Linux v6.12 source (the version the native profile already
references). They are reading notes for reviewers, not observations of a host.

## 1. Owner decisions (2026-10-05, authoring session)

| ID | Gate | Selected option |
|---|---|---|
| D1 | G04 | Dedicated sealed single-node qualification control plane on the enrolled Linux host. The effect gate is the only API path outside the control plane. Resource-bearing live qualification is UNAVAILABLE on tenant-managed clusters. |
| D2 | G05 | Versioned amendment of the accepted "before committing a mutation" wording into three named checks plus a drain fence (§3). |
| D3 | G07 | Reboot-only host maintenance. Host controls are locked until reboot; a reboot ends the generation. Kubernetes policy writes still go through the gate without a reboot. |
| D4 | G09 | Transport restriction ("connection stamping") on unchanged I04; mutations are also unique by construction. |

The owner chose among options the author offered; the choice is not a review.

## 2. G04 — concrete policy backend (I06) and complete writer mediation

### 2.1 Selected backend profile: `SEALED_SINGLE_NODE_CONTROL_PLANE_V1`

I06 is no longer an abstract interface. It is one Kubernetes control plane that
runs only on the enrolled qualification host, belongs to the external operator and
serves only qualification. No Kubernetes distribution, version or artifact is
selected here; W02 lists the selection criteria and W03 selects under license and
offline closure. Whatever is selected must meet all of P1-P10:

- P1 **Single node, local storage.** The datastore listens only on an AF_UNIX
  socket whose SELinux type allows `connectto` from the apiserver domain alone. No
  TCP datastore client or peer port, and no remote replica.
- P2 **Loopback apiserver, labelled port.** The apiserver secure port binds only
  to a loopback address. That port has a dedicated SELinux port type
  (`planeon_kubeapi_port_t`). `name_connect` to it is allowed for exactly: the effect
  gate, the policy observer and the enumerated control-plane components (§2.3).
  No other domain, including the root login domain, may connect.
- P3 **No authorization bypass reachable.** Anonymous authentication off; no static
  token file; authorization is Node+RBAC from a sealed structured configuration.
  The apiserver reloads that configuration automatically when the file changes
  (Kubernetes authorization documentation), so the file must be sealed (§5.5).
  No credential for `system:masters` or any group bound to `cluster-admin` is
  present on the host during INSPECTING/ACTIVE. Because of P2, even a stray copy
  cannot reach the apiserver from an unlisted domain.
- P4 **No credential minting.** The cluster CA private key is absent from the host
  during INSPECTING/ACTIVE. CSR signing and approving controllers are disabled.
  Kubelet client-certificate rotation is off; certificates are issued only during
  reboot maintenance (§5.5) with an off-host CA. The service-account token signing
  key is readable only by the apiserver and controller-manager domains. The
  `serviceaccounts/token` create permission is in the closure table (§2.3).
- P5 **Sealed control-plane configuration.** Apiserver flags/config, admission
  configuration, authorization configuration, encryption configuration, static
  component definitions, kubelet configuration and any auto-apply manifest
  directory are files with sealed SELinux types (§5.5). No domain can write them
  outside reboot maintenance. Auto-apply directories are empty and sealed.
- P6 **Closed admission chain.** Only an enumerated built-in admission plugin set
  is enabled. ValidatingWebhookConfiguration, MutatingWebhookConfiguration and
  mutating admission policy objects must be absent. ValidatingAdmissionPolicy
  objects and bindings are policy kinds written only through I07 (§2.4).
- P7 **No aggregation or extension path.** APIService objects other than the
  built-in local ones, CustomResourceDefinitions and webhook-backed conversion are
  absent. All are policy kinds, so creating one needs the I07 writer.
- P8 **Closed in-cluster clients.** Qualification Pods mount no service-account
  token (existing profile rule). Every non-Pod API client is enumerated in §2.3.
  The service proxy and network-policy agent, if the selected distribution needs
  them, run as enrolled host components with their own identities.
- P9 **Fixed container runtime access.** The container runtime's control socket
  allows `connectto` only from the kubelet domain. No CLI client domain can
  reach it, so no one can exec into or start privileged containers around the API.
- P10 **Zero-resource uniformity.** Zero-resource executions still need the same
  observer view of this backend. A missing or unqualified I06 backend makes the
  live capability unavailable in both modes (unchanged base rule).

For tenant-managed clusters the resource-bearing live qualification capability is
reported **UNAVAILABLE**. This is a qualification-profile limit, not a claim that
unrelated harnesses are air-gap incompatible. Tenants do not hand over
control-plane ownership: the sealed cluster belongs to the operator's qualification
host.

### 2.2 API-path closure

Every way to change an I06 policy fact maps to exactly one of these:

| Path | Disposition |
|---|---|
| Kubernetes API over the loopback port | Only domains allowed by P2. Effect actions go through the gate's effect identity; policy writes through the gate's writer identity (I07); observer reads with a read-only identity; control-plane components use their own identities (§2.3) |
| Datastore | AF_UNIX `connectto` for the apiserver domain only (P1); data directory writable only by the datastore domain; restore or replace only in reboot maintenance |
| Alternate API servers / aggregation | Absent (P7); creating one is a policy write through I07 |
| Container runtime | Kubelet only (P9) |
| Control-plane configuration files | Sealed (P5, §5.5) |
| Host network to the apiserver from other nodes | Loopback-only bind, single node (P1/P2) |

### 2.3 Identity and permission closure

Only these identities can reach the apiserver. For each, the effective
permission to create, update, patch or delete a **policy kind** is listed.
Policy kinds are: Namespace, ResourceQuota, LimitRange, ServiceAccount, Role,
RoleBinding, ClusterRole, ClusterRoleBinding, NetworkPolicy,
ValidatingAdmissionPolicy(Binding), Validating/MutatingWebhookConfiguration,
APIService, CustomResourceDefinition, CertificateSigningRequest approval, plus the
`impersonate`, `escalate`, `bind` and `serviceaccounts/token` create verbs.

| Identity | Domain | Policy-kind write permission | Notes |
|---|---|---|---|
| Gate effect identity | effect gate | None | Namespace-scoped create/get/delete of the signed Pod/ConfigMap/Service kinds only |
| Gate writer identity | effect gate (used only for I07) | Exactly the policy kinds above, scoped to the qualification namespace plus the named cluster-scoped objects | Used only while the generation is CLOSED for maintenance (§2.4) |
| Observer read identity | policy observer | None | get/list/watch on policy kinds and the namespace |
| Kubelet node identity | kubelet | None | Node authorizer + NodeRestriction; no static Pod definitions in the qualification namespace |
| Controller-manager per-controller identities | controller-manager | See §2.5; every controller with policy-kind writes is disabled or profile-excluded | Per-controller credentials required, so each controller's grants are distinct |
| Scheduler | scheduler | None | — |
| Service proxy / network-policy agent (if present) | enrolled host component | None | Read and status-only grants; distribution-specific custom resources enumerated in W02 |

The observer verifies this table from actual RBAC objects in every observation
(complete effective RBAC, as POLICY_OBSERVATION_READINESS already requires). A
subject not in the table that holds any policy-kind write permission, or any
`impersonate`/`escalate`/`bind` grant, makes the generation unavailable.

### 2.4 I07: policy writer to effect gate (new private interface)

Candidate path `/run/planeon/maintenance/policy-write.sock`, AF_UNIX/SOCK_SEQPACKET,
root:root 0600, with a socket type allowing `connectto` only from the policy-writer
domain. Same frame rules as I05 (canonical JSON, exact builtins, no floats, depth
<=16, <=16 KiB, sequence/hash chain). Exact schema is W02 work. Operations:

| Operation | Meaning |
|---|---|
| WRITE_BEGIN | Writer asks for maintenance. The gate runs CLOSE_GENERATION(normal drain) and replies only after the A3 drain fence (§3.2) holds. If any action is IO_AMBIGUOUS the reply is HELD and no write is possible |
| WRITE_OBJECT | One create/update/delete of one policy kind, with the expected prior projection digest. The gate forwards it with the writer identity and records the result durably. Non-policy kinds and every effect kind are refused |
| WRITE_END | Closes maintenance. The gate stays CLOSED. A new generation needs fresh observation and enrollment (base §5); the old generation never resumes |

The writer executable is a fixed enrolled artifact (§4). It never holds an
apiserver credential and cannot reach the apiserver port (P2). Operators run it
whenever they want; the only thing they can do during ACTIVE is ask for a normal
drain.

### 2.5 Control-plane autonomous writers

These are not "authorized writers" that a lock can exclude. Each has a disposition:

| Controller / component | Effect on policy facts | Disposition |
|---|---|---|
| ClusterRole aggregation | Rewrites rules of aggregated ClusterRoles | Profile rule: the effective RBAC closure of the qualification namespace contains no ClusterRole with an aggregationRule; observer refuses otherwise |
| ServiceAccount / token controllers | Recreate a deleted default ServiceAccount | Deletion is only possible through I07; the pinned ServiceAccount UID detects recreation |
| Namespace lifecycle | Deletes namespace contents on namespace deletion | Namespace deletion is only possible through I07 |
| ResourceQuota controller | Updates `status.used` | Usage, not policy. Quota admission is re-evaluated in the apiserver at persist time (§3.2); observer still checks headroom |
| Root-CA ConfigMap publisher | Keeps one ConfigMap per namespace | Counted in observed usage; content change requires CA rotation, which is reboot maintenance |
| CSR signing / approving | Could mint credentials | Disabled (P4) |
| Garbage collector, EndpointSlice and other workload controllers | Act on objects the gate admitted | Not policy kinds; their effects are bounded by admitted objects and existing cleanup rules |

Anything the selected distribution adds (for example an embedded network-policy
agent or a manifest-apply controller) must be listed here in W02, or it is disabled.

### 2.6 Writer-family coverage (amends base §7 dispositions)

| Writer family | Mechanism |
|---|---|
| Host files / credentials / trust | fs-verity on code; sealed SELinux types writable only by the maintenance domain, which has no runtime entry (§5.5) |
| Host policy and namespaces | `secure_mode_policyload` locks policy load, booleans and enforcing mode until reboot; namespace and mount changes denied to non-maintenance domains (§5.3) |
| Cgroups / BPF / process execution | BPF load and attach only in the one-shot containment domain; sealed systemd units with SELinux `service` permissions denied to login domains; `kernel.modules_disabled=1`; `lockdown=integrity` on the enrolled boot entry; Yama `ptrace_scope=3` (§5) |
| RBAC and identity | §2.3 closure plus I07 as the only writer |
| Namespace / quota / admission | I07 only; closed admission chain (P6) |
| Network and API path | P1/P2/P7/P9; loopback-only; reboot maintenance for configuration |
| Autonomous events | Base §5 deny-first handling plus §2.5 |

Every listed mechanism is a design selection. That it is complete on a real host
is E03, E04, E05 and E10 evidence, still OPEN_UNPROVEN (§8).

## 3. G05 — admission versus storage commit (versioned amendment)

### 3.1 Accepted wording and why it needs a version

POLICY_OBSERVATION_READINESS.md currently says: "Before committing a mutation, its
immutable admission guard rechecks current namespace/UID, effective RBAC, quotas,
network policy and actual post-mutation manifest under the broker's serialized
admission transaction." A gate outside the apiserver cannot make an upstream
storage commit atomic with unrelated policy changes. That sentence cannot be met
literally by any boundary this design has, and must not be met by pretending a
gate acknowledgement is a commit.

### 3.2 Amended semantics `POLICY-ADMISSION-SEMANTICS/v2` (decision D2)

"Before committing a mutation" becomes three named checks at named positions:

- **A1 Gate admission (pre-forward linearization point).** Under the gate's single
  generation lock: verify current generation ACTIVE, scope, deadline, observed
  policy generation and the stamped armed action (§6). Then consume that action
  exactly once, fsync and read back the durable record, then send the first byte
  upstream. Nothing earlier is the admission event: not socket accept, TLS,
  ARM_ACTION acknowledgement or a worker report (unchanged base rule).
- **A2 In-chain persist check (pre-persist).** Inside the sealed apiserver, after
  mutating admission and before persistence, a ValidatingAdmissionPolicy (in-process,
  failurePolicy Fail; stable since Kubernetes v1.30) checks the final object against
  the signed manifest. Allowed differences are an enumerated per-kind
  server-populated/defaulted field set fixed in W02. The built-in quota and
  LimitRange admission plugins re-evaluate usage in the same chain. Kubernetes
  runs mutating admission before validating admission (admission-controller
  documentation), so A2 sees the post-defaulting object. A2 replaces "actual
  post-mutation manifest" in the old sentence. Its policy objects are policy kinds
  (written only through I07) and are pinned by the existing admissionPolicy and
  mutationBroker digests.
- **A3 Drain fence for policy writers.** No I07 WRITE_OBJECT, and no other writer in
  §2, commits while any action admitted under the current generation lacks a
  durable terminal classification (DELIVERED_RESULT or NOT_FORWARDED). An
  IO_AMBIGUOUS action holds the generation HELD. A normal write then cannot
  proceed until independently authorized reconciliation classifies it.

Resulting guarantee for normal operation: if a mutation reached DELIVERED_RESULT,
no mediated policy write was committed between its A1 event and its upstream
response. The synchronous create/delete response comes after the apiserver's
persist step, so the object was persisted under the policy that A1 checked.
A Pod DELETE response starts graceful termination; absence is still confirmed by
the existing exact-UID cleanup observation, not by the response.

**A4 Urgent invalidation (explicitly weaker, recorded).** Revocation, peer death,
storage failure or observation loss closes A1 immediately and does not wait for
A3. An action already admitted may still be persisted after the invalidating
change. It is recorded ADMITTED_BEFORE_INVALIDATION with its terminal or ambiguous
outcome. It is never relabelled unadmitted, never retried, and its resources stay
owned for exact-UID cleanup. The old strict wording was not achievable in this
case; this amendment says so instead of implying it.

The accepted document's bytes are not changed by this candidate. W02 carries the
amended v2 text into the owning contract with old/new vectors. A consumer reading
the v1 sentence must not cite this candidate as having met it.

### 3.3 What G05 does not claim

No end-to-end distributed transaction, no proof that the apiserver persisted
before a lost response (that is IO_AMBIGUOUS), and no ordering guarantee for
controller side effects outside §2.5. The drain fence relies on the gate being
the only writer path, which is G04 evidence.

## 4. G06 — versioned native role and manifest enrollment

### 4.1 Record and profile versions

- New record `planeon.internal.native-qualification/v2`, profile
  `SELINUX_FSVERITY_CGROUP_BPF_V2`. v1 (`.../v1`, `SELINUX_FSVERITY_CGROUP_BPF_V1`)
  is unchanged.
- **Resident roles (closed set):** SERVER, OBSERVER, BROKER, WORKER, EFFECT_GATE.
  All five are required in every v2 record. In a zero-resource execution the gate
  is present and denies every action, so the parser has no mode-dependent branch.
- **Lifecycle subjects (closed set):** HOST_CONTAINMENT and POLICY_WRITER. They
  are recorded with artifact digest, SELinux domain and entry rule, but are not
  resident roles. HOST_CONTAINMENT must have no process during INSPECTING/ACTIVE
  (§5.2). POLICY_WRITER may run but can only request a normal drain through I07.
- **Backend components:** a closed `backendComponents` object whose keys are fixed
  by the selected I06 implementation profile version (§2.3 identities), each with
  artifact digest, SELinux domain, cgroup and API identity. Unknown or missing
  keys refuse.

### 4.2 Paths and manifests (candidates; exact values are W02 data)

- Cgroups under one systemd slice: `/sys/fs/cgroup/planeon.slice/` with one
  service per resident daemon role (`planeon-proxy-server.service`,
  `planeon-policy-observer.service`, `planeon-effect-gate.service`) and
  `planeon-capacity-broker.service`. Only the broker's service has `Delegate=yes`.
  It exclusively owns two leaves, `broker` and `probe-worker`, so it satisfies
  the no-internal-process rule. This refines MET-ENFORCE-001 decision 2 (one
  owned subtree) from a single service to a single slice; reviewers should check
  that refinement explicitly.
- Gate artifact `/opt/planeon/bin/harness-effect-gate` root:root 0555; manifest
  `/etc/planeon/harness-effect-gate-manifest.json` and `.json.sig`. It uses the
  existing closed root-manifest shape and detached Ed25519 under the existing
  pinned root public key. No new root key or signing role. The same applies to
  `/opt/planeon/bin/harness-policy-write` and
  `/opt/planeon/bin/harness-host-containment`.
- The gate's TLS listener identity is the existing signed KUBERNETES_API_PROXY
  endpoint identity. The server still pins the endpoint SPKI and keeps its own
  KUBERNETES_PROXY_SERVER_MTLS credential (base §2).

### 4.3 Who qualifies whom

- BROKER qualifies EFFECT_GATE as a peer (artifact, label, cgroup, pidfd/start,
  SO_PEERCRED) before BIND_EXECUTION. EFFECT_GATE qualifies the broker the same way
  on every I05 frame and the writer on every I07 frame.
- SERVER and OBSERVER do not talk to the gate except SERVER over I04 TLS. Their v1
  peer duties are unchanged.
- The gate's generation must equal the observer/broker generation carried in
  DISPATCH and BIND_EXECUTION; mismatch denies.

### 4.4 Rejection vectors (T08 additions)

v1 reader given a v2 record refuses. v2 reader given a v1 record refuses (no
fallback). A v2 record that is missing EFFECT_GATE, has an extra role, puts the
gate under the BROKER key or path, aliases a role path, or has a lifecycle subject
running inside a resident role cgroup refuses. A record with unknown
backendComponents keys refuses. Migration never reinterprets accepted v1 data and
never reuses a v1 generation or nonce.

## 5. G07 — syscall, capability, MAC, seal and original-parent lifecycle

### 5.1 Finding against the v1 inspection command set

The v1 readers use BPF_PROG_QUERY(16), BPF_PROG_GET_FD_BY_ID(13) and
BPF_OBJ_GET_INFO_BY_FD(15) and must not obtain CAP_SYS_ADMIN. In Linux v6.12
`kernel/bpf/syscall.c`:

- `bpf_prog_get_fd_by_id` requires `capable(CAP_SYS_ADMIN)`.
- `bpf_prog_query` requires `bpf_net_capable()` (CAP_NET_ADMIN or CAP_SYS_ADMIN).
- `bpf_prog_get_info_by_fd` zeroes `xlated_prog_len` without `bpf_capable()`
  (CAP_BPF or CAP_SYS_ADMIN). It withholds instructions of blinded programs
  without `bpf_dump_raw_ok`, and the dump zeroes helper-call immediates unless
  `bpf_dump_raw_ok` holds (`kallsyms_show_value`, which depends on `kptr_restrict`
  and CAP_SYSLOG).

So v1's command set needs CAP_SYS_ADMIN held from start. v2 resolves this without
CAP_SYS_ADMIN:

- Replace GET_FD_BY_ID with **BPF_OBJ_GET(7)** on bpffs pins that HOST_CONTAINMENT
  creates at fixed, sealed paths. The v6.12 `bpf_obj_get_user` path has no
  capability check; access is file permission plus SELinux `bpf` checks (to be
  confirmed in T04). Readers compare the pinned program's ID with the
  BPF_PROG_QUERY result in both local and effective views.
- Readers hold exactly CAP_NET_ADMIN (query) and CAP_BPF (unredacted translated
  instructions).
- Enrolled programs must be **helper-call-free** (no BPF_CALL in the translated
  image). Their dumps then need no `bpf_dump_raw_ok` and CAP_SYSLOG is not
  selected. `net.core.bpf_jit_harden` must be 0 or 1, so programs loaded with
  CAP_BPF are not blinded. Root-cgroup BPF filtering by cgroup ID would need a
  helper, so G04 uses SELinux `name_connect` (P2), not BPF, for the apiserver port.

**Attach and detach authority (author's reading of v6.12; T04 must confirm).**
For CGROUP_SOCK/SOCK_ADDR programs, `bpf_prog_attach` checks only the attach type
and `cgroup_bpf_prog_attach` takes the cgroup from a directory fd; neither checks a
capability. `bpf_prog_detach` → `cgroup_bpf_prog_detach` also checks none. In
`find_detach_entry`, an attachment made without BPF_F_ALLOW_MULTI can be detached
with no program fd at all ("legacy mode"). `cgroup_v1v2_get_from_fd` uses
`fdget_raw`, so an O_PATH directory fd is enough. SELinux `selinux_bpf` checks only
MAP_CREATE and PROG_LOAD. `unprivileged_bpf_disabled` applies only to map creation
and program load. So cgroup directory fds and program fds are themselves write
authority over endpoint enforcement. v2 therefore requires:

- enrolled programs attached with BPF_F_ALLOW_MULTI, so detaching needs that
  program's fd;
- planeon cgroup directories labelled with a dedicated type by containment (SELinux
  `cgroup_seclabel` policy capability), with `dir search` denied to every domain
  except planeon roles and `init_t`, so no other domain can even get an O_PATH fd;
- programs owned by `planeon_contain_t`, with `bpf { prog_run }` on them (checked in
  `bpf_prog_new_fd`) allowed only to reader domains; pins readable only by readers;
- every enrolled role's seccomp filter limits `bpf` to cmds {7, 15, 16}, so no
  attach (8), detach (9), pin (6), load (5), map create (0), link create/update/
  detach (28/29/34) or GET_FD_BY_ID (13).

### 5.2 Boot and seal sequence (enrolled boot entry)

S1. The kernel command line carries `lockdown=integrity`. SELinux is enforcing,
with the reviewed policy whose digest the record pins.
S2. systemd starts `planeon-host-containment.service` once, ordered before every
login and remote-access service, so no login session exists before S4. The unit has
`RefuseManualStart=yes` and its unit file is a sealed type. The domain transition
into `planeon_contain_t` is allowed only from `init_t` through the containment
entrypoint, and only while policy boolean `planeon_containment_enabled` is true.
S3. Containment creates or verifies role cgroups and limits, and labels the
planeon cgroup directories. It loads the helper-free map-free programs (CAP_BPF,
plus CAP_NET_ADMIN, which v6.12 `bpf_prog_load` requires for CGROUP_SOCK/SOCK_ADDR
types). It attaches them with BPF_F_ALLOW_MULTI to the seven hooks of each role
cgroup, pins and labels them in bpffs, and enables fs-verity on artifacts.
S4. Containment sets `planeon_containment_enabled=0`, then
`secure_mode_policyload=1`, both non-persistent. After this no domain can change
booleans, load policy or switch enforcing mode until reboot, and nothing can
enter `planeon_contain_t` again.
S5. Earlier in the same boot, sealed boot configuration has already loaded the
enumerated kernel module set the backend needs (for example overlay and
netfilter modules; exact list is W02 data). It has also applied the one-way
sysctls `kernel.modules_disabled=1`, `kernel.kexec_load_disabled=1`,
`kernel.yama.ptrace_scope=3` and `kernel.unprivileged_bpf_disabled=1`.
Containment only verifies these values and refuses to seal if any differs. It
then writes the seal marker to a sealed path and exits. A record from a boot
without the marker, or with any process in `planeon_contain_t`, refuses.
S6. Datastore, apiserver and other backend components start (sealed units), then
the gate (deny-default), observer, broker and server, in base §6 order.

`secure_mode_policyload` is enforced by the loaded policy's conditional rules, so
the pinned policy digest must contain them. That is reviewed with the binary
policy, not assumed from the boolean's name.

### 5.3 Per-role steady-state policy (after own seal step)

| Role | uid | Capabilities (permitted = effective; bounding equal; ambient empty) | Seccomp (mode 2, default KILL_PROCESS) | SELinux domain / key denials |
|---|---|---|---|---|
| SERVER | 0 | CAP_NET_ADMIN, CAP_BPF (inspection only); CAP_NET_BIND_SERVICE only if the signed listener port is below 1024 | Allowlist: I/O on held FDs, socket(AF_INET/AF_INET6 stream, AF_UNIX seqpacket), connect/accept4, memory and clock calls TLS needs, `bpf` with arg0 in {7,15,16}, memfd_create with flags exactly MFD_CLOEXEC and MFD_NOEXEC_SEAL for the sealed-credential path (the kernel clears the exec bits and sets F_SEAL_EXEC on every call, and further seals stay possible; the existing code passes MFD_CLOEXEC and MFD_ALLOW_SEALING and must change first, obligation O-SERVER-MEMFD), pidfd_open, inspection reads (read-only `openat`, `read`, `pread64`, `lseek`, `fstat`, `newfstatat`, `statx`, `fstatfs`, `getdents64` and `readlinkat`; `ioctl` only FS_IOC_MEASURE_VERITY; `membarrier` only cmd 0, 8 or 16 with flags 0 and cpu 0; W02d-QC). Seccomp checks only the open flags of these reads; which files they reach is set by the role's SELinux domain (`architecture/selinux-matrix-v2/`), exit. Denied: execve/execveat, clone3 (its flags are in a struct seccomp cannot read; it fails with ENOSYS rather than KILL_PROCESS, W02d-QB), clone without CLONE_THREAD, mount family, setns, unshare, ptrace, process_vm_*, init/finit_module, kexec_* | `planeon_server_t`: no execmem/execmod/execstack, no ptrace; `name_connect` only to the I04 gate port; `connectto` only to its existing observer/broker sockets; no `planeon_kubeapi_port_t` |
| OBSERVER | 0 | CAP_NET_ADMIN, CAP_BPF (inspection only) | As SERVER without listener; I06 read connection allowed | `planeon_observer_t`: `name_connect` to `planeon_kubeapi_port_t`; read-only to policy credential |
| BROKER | 0 | CAP_NET_ADMIN, CAP_BPF (inspection); CAP_SETUID and CAP_SETGID, which the pre-exec child inherits and gives up in W4. No CAP_KILL: termination uses `cgroup.kill` on its own delegated leaf | As SERVER plus clone3, setresuid/setresgid, close_range, and execveat with flags limited to AT_EMPTY_PATH. The child inherits this filter, so it must cover the child's pre-exec steps; the narrower worker filter is installed in W4 and stacks on it. The inherited broker filter stays after exec and the kernel applies the most restrictive action of the two, so the broker allowlist covers the worker's (W02d-QD). The broker runs under exactly one filter, its own (W03 adds none, W02d F10), so the worker shows `Seccomp_filters: 2`. clone3 cannot be argument-filtered, so its use is bounded by `pids.max`, SELinux transitions and the W1-W6 sequence, not by seccomp | `planeon_broker_t`: `execute` only on the worker executable type, with a forced transition to `planeon_worker_t`; no other entrypoint |
| EFFECT_GATE | 0 | None, except CAP_NET_BIND_SERVICE if the signed I04 port is below 1024. It reads root-owned 0400 credentials as owner, does no BPF inspection, and qualifies peers with pidfd, SO_PEERCRED and same-uid /proc reads its policy allows | Network I/O, fsync/fdatasync, flock, the AF_UNIX listeners for I05/I07 and the I04 TLS listener; no exec, no clone3 (it fails with ENOSYS, W02d-QB), clone only with CLONE_THREAD | `planeon_gate_t`: sole reader of the two upstream credential files; `name_connect` to `planeon_kubeapi_port_t` |
| WORKER | signed 10000..2147483647 | Empty | The W02d worker allowlist (`architecture/seccomp-allowlists-v2/`, W02d-Q1): its CPython 3.12 runtime base, FD3 seqpacket I/O on fd 3 only, reads of the read-only root and exit; `execveat` only with flags AT_EMPTY_PATH, for W5 (W02d-QA); `clone3` fails with ENOSYS (W02d-QB); no socket creation, no `bpf`. The inherited broker filter stays installed and covers it (W02d-QD) | `planeon_worker_t`: no network `name_connect`, no ptrace, read-only root; no `execute_no_trans` on any type (SELinux matrix v4 A60.18) and no `transition` or `nnp_transition` into any declared domain (A24-A32), and the host policy gives it none into any other domain (obligation O-W03-WORKER-EXEC), so a second exec that the worker filter admits is still refused |
| POLICY_WRITER | 0 | Empty | AF_UNIX connect to I07, I/O, exit | `planeon_policy_writer_t`: `connectto` I07 only |
| HOST_CONTAINMENT | 0 | CAP_BPF and CAP_NET_ADMIN (program load), plus any capability its cgroup labelling, pinning and fs-verity steps need, which W02 enumerates; one-shot | Allowlist for the S2-S5 steps only | `planeon_contain_t`: only domain with `bpf { prog_load }`, `security { setbool }` and relabel on planeon types; enterable once per boot (S2/S4) |

The syscall names above are the policy shape. The exact per-architecture
allowlists (x86_64 and aarch64 numbers, argument filters) are W02 data (W02d, `architecture/seccomp-allowlists-v2/`), generated
from these rows and reviewed. A syscall a role needs that is not derivable from
its row means the row is wrong and blocks implementation. It is not quietly
added to the allowlist. In every role except BROKER, `clone3` fails with ENOSYS rather than KILL_PROCESS (W02d-QB): in the CPython roles (SERVER, WORKER) glibc 2.34 and later then fall back to the thread-only `clone` rule, and the native roles' static musl runtime creates threads with `clone` only, never `clone3` (W01-AMEND-QW4). Every other call a role's allowlist does not name is KILL_PROCESS. For all roles: `no_new_privs=1` before the seccomp filter,
RLIMIT_CORE=0, no CAP_SYS_ADMIN, no CAP_SYS_PTRACE, no CAP_DAC_OVERRIDE, and no
unconfined or permissive domain anywhere on the host. Root logins map to a
confined administrator domain. That domain is denied writes to sealed types,
reads of planeon credential types, `bpf` permissions, `name_connect` to
`planeon_kubeapi_port_t`, `connectto` on runtime, datastore, I05 and I07 sockets
(I07 is reachable only by running the policy-writer entrypoint, which transitions
to `planeon_policy_writer_t`), and the `service { start stop reload }` permissions
on planeon unit types.

### 5.4 Worker pre-exec lifecycle (original parent preserved)

W1. The broker writes `cgroup.freeze=1` on its delegated `probe-worker` leaf,
which is empty, enrolled and has its limits and seven programs already present.
W2. The broker calls `clone3(CLONE_PIDFD | CLONE_INTO_CGROUP)` targeting that
leaf. In v6.12 `cgroup_post_fork` sets JOBCTL_TRAP_FREEZE on a non-kernel child of
a cgroup marked to freeze, so the child is frozen before it reaches user space.
The broker is the original parent and keeps the pidfd.
W3. While the child is frozen, the broker checks `/proc/<pid>` through the pidfd:
cgroup membership, credentials and label. It also checks the descriptor table:
only stdio and the broker-created FD3 socketpair end. The child holds no supplementary groups: the `Groups:` line
of `/proc/<pid>/status` lists none (the kernel writes `Groups:`, a tab and one space). W4's setresgid and setresuid
leave supplementary groups unchanged, so the broker must run with none (obligation O-W03-GROUPS), and neither filter
allows `setgroups`.
W4. The broker thaws the leaf. The child runs broker-owned pre-exec code only:
close_range above 3, setresgid/setresuid to the signed UID, drop all
capabilities, `no_new_privs=1`, install the worker seccomp filter (W02d). That filter admits W5's `execveat`
form and no other exec, and it stacks on the inherited broker filter.
W5. The child calls `execveat(fd, "", ..., AT_EMPTY_PATH)` on an O_PATH descriptor
of the fs-verity worker executable. The broker verified that descriptor's verity
digest before W2. The domain transition to `planeon_worker_t` happens on this
exec.
W6. The broker waits with `waitid(P_PIDFD)`. On expiry or invalidation it freezes
the leaf, kills through `cgroup.kill` (a pidfd signal needs CAP_KILL once the child runs as the signed uid, and
the broker holds none; the pidfd serves `waitid` and identity), waits until `cgroup.events`
reports `populated 0`, and only then releases the leaf. If it cannot show the leaf
is empty, it HOLDs (unchanged base rule).

No systemd child service, OCI runtime or subreaper adoption replaces W1-W6.

### 5.5 Reboot-only maintenance (decision D3)

**Sealed types** are the SELinux file types of planeon artifacts, configuration,
unit files, credentials, bpffs pins and the control-plane configuration (P5).
Only `planeon_maint_t` may write or relabel them. Entry to `planeon_maint_t` is
allowed only while policy boolean `planeon_maintenance_mode` is true. The enrolled
boot entry leaves it false and S4 freezes it with `secure_mode_policyload`. The
maintenance boot entry sets it true early in boot. Active booleans are already
pinned in the record (v1 rule), so an enrolled boot with the boolean true refuses,
and no planeon role can qualify in a maintenance boot.

M1. Any change to host policy, booleans, sealed files, BPF programs, units,
artifacts, the kernel or control-plane configuration needs a reboot into the
maintenance boot entry. In that entry `planeon_maint_t` is enterable and no planeon
role starts.
M2. Before rebooting, the operator runs I07 WRITE_BEGIN or an urgent
CLOSE_GENERATION. A reboot without it is an autonomous event: the gate starts
denied and HELD, and in-flight work is IO_AMBIGUOUS.
M3. After maintenance, the enrolled boot entry runs §5.2 again. The new boot ID
makes every prior generation unusable. Enrollment needs a fresh, non-reused
generation and fresh observation.
M4. Kubernetes policy changes do not need a reboot. They go through I07 with the
A3 drain fence.
M5. Credential issuance with the off-host CA (P4) happens only in the maintenance
entry.

## 6. G09 — request-to-action correlation by connection stamping

### 6.1 Rules (decision D4; I04 bytes unchanged)

C1. I04 already requires HTTP/1.1, one request per connection, no pipelining,
TLS 1.3 with no session resumption and no early data. The gate enforces these
rules itself; it does not rely on the client.
C2. **Flush on arm.** In the ARM_ACTION transaction for action X, under the
generation lock, the gate first closes, without forwarding, every connection of
this execution that has not yet consumed an action. It also accepts and closes
every connection pending in its listen backlog. Then it durably records ARM(X).
C3. **Stamp at accept.** Every connection the gate accepts afterwards gets the
action ID armed at that moment, or `none` if none is armed. The stamp is gate
state. Nothing from the client sets it or can change it.
C4. **Consume only the stamp.** A request may pass A1 only if its connection's stamp
equals the currently armed action, the connection's client certificate equals the
execution's bound run certificate, and the gate-derived canonical action for the
request equals X's request-template digest. Any mismatch closes the connection
without forwarding and records a correlation refusal.
C5. **One consumption per stamp.** After X is consumed, every other connection stamped
X is closed without forwarding. A connection stamped `none` never forwards.
C6. **Tombstones.** Consumed action keys stay in the gate's durable journal for the
execution's life. A gate restart starts denied (base §5) with no stamps, so it
cannot resume a connection.
C7. **Mutation uniqueness by construction.** CREATE uses signed names never reused,
and DELETE carries the recorded-UID precondition and is armed at most once per
UID. At ARM the gate refuses any mutation whose canonical key it has already
armed in this execution. GETs may repeat (status polling) because C2-C5 keep them
apart.

### 6.2 Argument against counterexample 17

Action A completes. A byte-identical duplicate of A is buffered in kernel, TLS or
parser state; then B, byte-identical to A, is armed. The duplicate's bytes sit on
some connection K that existed before ARM(B), because buffered bytes need an
existing connection. C2 closes K without forwarding (or K is A's connection and
already used, C1/C5). If K is still in the listen backlog, C2 accepts and closes
it. So the duplicate cannot reach A1 for B. By C7 the case only arises for GETs:
CREATE A and CREATE B can never be byte-identical, and DELETE is armed once per
UID.

### 6.3 Residual, stated rather than hidden

Suppose the server application opens a new connection after ARM(B) and sends bytes
identical to B. The gate cannot tell whether the server meant B or a stale resend
of A. In both cases the forwarded request is exactly the content the broker armed
as B, so no unarmed effect happens and B still happens at most once. A
misattributed result appears as gate/server disagreement in the existing
RESOURCE_RESULT agreement check (base §4 step 7) and becomes HELD. This residual
needs the server's own behaviour to cause it; transport buffering cannot. It
stays a T02 source case and a native case. The server is a reviewed component,
but its behaviour is not enforcement proof (unchanged base threat model).

No new header, field or caller-supplied action identifier is introduced.
A per-action correlation nonce (protocol amendment) stays a rejected alternative
for now. Adopting it later needs R01/R10/R12 versioning.

## 7. Amended I05 operation table (supersedes base §3 I05 table)

Unchanged fields stay as in the base. Additions:

| Operation | Addition in v2 |
|---|---|
| BIND_EXECUTION | Also binds the gate's own generation (must equal DISPATCH generation) and the broker peer qualification digest (§4.3) |
| ARM_ACTION | Runs C2 flush before recording; refuses a repeated mutation key (C7); refuses while a WRITE_BEGIN drain is pending |
| ACTION_OUTCOME | Adds ADMITTED_BEFORE_INVALIDATION as a qualifier on DELIVERED_RESULT/IO_AMBIGUOUS (A4); still maps to the existing RESOURCE_RESULT without overloading its enum. Mapping table is W02 work |
| CLOSE_GENERATION | Normal close waits for the A3 fence; urgent close does not (A4); both deny unconsumed actions first |
| GENERATION_STATUS | Adds stamp/consumption counters and correlation-refusal count; still observation only |

## 8. What stays open after this candidate

- **E01-E12 OPEN_UNPROVEN, all.** Gate-to-row map: G04 → E03, E04, E05, E10;
  G05 → E10, E11, E12; G06 → E07; G07 → E01, E03, E04, E05, E06, E07, E08, E12;
  G09 → E10. E02 and E09 are untouched and still apply.
- **Native items:** completeness of the §2 closure on a real host (E03-E05, E10);
  whether the §5.1 kernel facts hold on the enrolled kernel and policy
  (T04); `secure_mode_policyload` conditionals in the pinned binary policy (T04);
  freeze-before-user-space under CLONE_INTO_CGROUP on the enrolled kernel (T04/T05);
  C2/C3 flush/stamp behaviour under load and restart (T02/T03); A2 field
  allowlists against real defaulting (T06).
- **W02 work:** exact wire schemas for I05/I07, v2 record schema, per-architecture
  syscall allowlists, cgroup paths, admission field allowlists, the Kubernetes
  distribution selection criteria, and the amended contract text with old/new vectors.
- **Unchanged:** I01-I04 bytes, the reuse candidate `envoyproxy/envoy` (not
  selected; its connection-level stamping would need review), 13 repositories,
  four planes, 16 harnesses, typed graphs, budgets and failed evidence.

## 9. Counterexamples added (18-28)

18. Policy writer commits an RBAC change while an admitted CREATE is in flight.
    Required: A3 blocks the write until the CREATE is classified; urgent path
    records ADMITTED_BEFORE_INVALIDATION.
19. Operator restarts host containment at runtime to attach different programs.
    Required: `RefuseManualStart`, `planeon_containment_enabled=0` under
    `secure_mode_policyload` (S4), and sealed unit types refuse it.
20. A root login uses a leftover admin kubeconfig. Required: P2 `name_connect`
    denial, independent of the credential.
21. The gate restarts mid-execution with clients connected. Required: deny-first,
    HELD, no stamps restored (C6).
22. The server opens connection K while A is armed and sends on it after B is
    armed. Required: K's stamp is A, so C4 refuses.
23. An I07 WRITE_OBJECT carries a Pod or an unknown kind. Required: refusal; writer
    identity never forwards effect kinds.
24. The aggregation controller widens an aggregated ClusterRole. Required: profile
    excludes aggregated roles from the closure; observer refuses.
25. Datastore restore at runtime. Required: AF_UNIX `connectto` and data
    directory types allow it only in reboot maintenance.
26. CSR approval mints a privileged client certificate. Required: P4 controllers
    disabled and CA key absent; P2 still mediates the path.
27. A reader keeps CAP_SYS_ADMIN "because GET_FD_BY_ID needs it." Required: v2
    removes command 13 and uses BPF_OBJ_GET on sealed pins (§5.1).
28. A root login opens an O_PATH fd on a role cgroup and detaches its enrolled
    program in legacy mode. Required: MULTI attachment (detach needs the program
    fd), `dir search` denial on labelled planeon cgroups, and `prog_run` denial on
    containment-owned programs (§5.1).

## 10. Adoption meaning

If the independent review returns PASS_FOR_SOURCE_PUBLICATION and finds G04, G05,
G06, G07 and G09 each RESOLVED_DESIGN, W01 becomes DESIGN_RESOLVED_REVIEWED. That
adopts this v2 candidate as the design-level host interface W02 must formalize. It
is not an installed ABI, not native enforcement, not coding readiness for
W03-W07, and not tenant acceptance. If the review requires changes, this snapshot
stays as an immutable historical subject and a corrected snapshot is reviewed
separately. Both verdicts are kept.

References consulted 2026-10-05 (research notes, not release pins):
- Linux v6.12 `kernel/bpf/syscall.c`, `kernel/bpf/inode.c`, `kernel/cgroup/cgroup.c`,
  `include/linux/bpf.h`, `include/linux/capability.h`, `include/linux/filter.h`,
  `kernel/ksyms_common.c`
- https://docs.kernel.org/admin-guide/cgroup-v2.html
- https://docs.kernel.org/admin-guide/sysctl/kernel.html
- https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
- https://kubernetes.io/docs/reference/access-authn-authz/authorization/

## 11. Amendment W02D (2026-10-10)

W02d (`architecture/seccomp-allowlists/`, MET-ENFORCE-017) carried six items into this record. Amendment W02D applies them, restates W02d-QB's ENOSYS refusal where rows imply KILL_PROCESS, and points at
the W02d successor (`architecture/seccomp-allowlists-v2/`). Nothing else changes; `amendment.json` beside this file
gives every change and its reason.

| Item | Where | Decisions |
|---|---|---|
| A1 | 5.3 WORKER row, seccomp | W02d-Q1, W02d-QA, W02d-QB, W02d-QD |
| A2 | 5.3 WORKER row, SELinux | W02d-QA |
| A3 | 5.3 SERVER row, seccomp (OBSERVER and BROKER inherit it) | W02d-QC |
| A4 | 5.3 SERVER row, seccomp (memfd_create) | W01-AMEND-QW3 |
| A5 | 5.3 SERVER row, seccomp (clone3) | W02d-QB |
| A6 | 5.3 EFFECT_GATE row, seccomp | W02d-QB |
| A7 | 5.3 BROKER row, seccomp | W02d-QD |
| A8 | 5.3 note | W02d-Q1 |
| A9 | 5.3 note | W02d-QB, W01-AMEND-QW4 |
| A10 | 5.4 W3 | W01-AMEND-QW2 |
| A11 | 5.4 W4 | W02d-QA, W02d-QD |
| A12 | 5.4 W6 | W01-AMEND-QW1 |

Obligations: O-SERVER-MEMFD (the sealed-credential code's memfd flags), O-W03-WORKER-EXEC (the worker's domain
transitions), O-W03-GROUPS (the broker's groups) and
O-T04-AMEND (native confirmation). Every E01-E12 obligation stays OPEN_UNPROVEN.
