"""TG-02 to TG-05 and TG-08 case catalogs (TG-02/TG-03: W04-3, CONF-ENF-003; TG-04/TG-05: W04-4a, CONF-ENF-004; TG-08: W04-6,
CONF-ENF-007).

Every case of the plan's TG-02 (lifecycle) and TG-03 (persistence) groups that waits for W05's release set or for W06's
native hosts is fixed now to the adopted contract vectors that specify it. Each selection is a rule over the vectors'
own content, so a ledger cannot narrow it by data alone, and the expected results are those vectors' own outputs and
final snapshots. The executable source and the wire-level adapter that run these cases against W05's released build
come with W05's release set, together with TG-01's CODEC case; until then every such case is NOT_RUN_ENV_UNAVAILABLE.
TG-04 (host) and TG-05 (clocks) are native groups: every case waits for W06's enrolled hosts, and its catalog rows come
from several contract files (SELinux matrix v4 checks, seccomp v2 decisions, native v3 vectors and the reference model's
own rules, I05 v3 transcripts, W02D's items and spec steps), so each native row also names its source file.
TG-08 (compatibility, W04-6, CONF-ENF-007) follows TG-02/TG-03: vector-file rows only, in a SOURCE part and an INSTALLED
part kept apart; its offline case S44 lists one property per item of the plan's S44 case, W02D section 4.4's rejection
list (owner decision Q-T20).
Standard library only (owner decision Q-T1, 2026-10-11).
"""
from __future__ import annotations

import ast
import re

import _models
from tg01_contract import _replays

I05, I07, SUPPLEMENT, ADMISSION = _replays.I05, _replays.I07, _replays.I05_SUPPLEMENT, _replays.ADM
ARM_MISUSE = {"ACTION_ID_OUT_OF_ORDER", "ACTION_OUTSTANDING", "MANIFEST_OUTSIDE_CASE", "MUTATION_KEY_REUSED", "TEMPLATE_MISMATCH",
              "EXECUTION_NOT_BOUND"}
# The I07 writer's own analogues: a write with no open maintenance, out of order, outside its scope or generation.
WRITE_MISUSE = {"MAINTENANCE_NOT_OPEN", "MAINTENANCE_NOT_BEGUN", "MAINTENANCE_HELD", "WRITE_ID_OUT_OF_ORDER", "SCOPE_MISMATCH",
                "GENERATION_MISMATCH"}
WRITES = ("WRITE_BEGIN", "WRITE_OBJECT", "WRITE_END")
STORAGE_FAILURES = {"STORAGE_FAIL_NEXT", "STORAGE_FAIL_AFTER"}
MISATTRIBUTION = ("M01", "M06", "M07")


def _steps(row):
    return zip(row["events"], row["outputs"])


def _response(output):
    return output["response"] if type(output.get("response")) is dict else {}


def _refused(row, operation, reasons):
    return any(event.get("operation") == operation and _response(output).get("result") == "REFUSED"
               and _response(output).get("reason") in reasons for event, output in _steps(row))


def _closed_request(row, reasons):
    return any(event["type"] == "REQUEST" and output.get("decision") == "CLOSE" and output.get("reason") in reasons
               for event, output in _steps(row))


def _flushes(row):
    return any(event.get("operation") == "ARM_ACTION" and (_response(output).get("flushedConnections") or 0) > 0
               for event, output in _steps(row))


def _closes_for_reconciliation(row):
    return any(event.get("operation") == "CLOSE_GENERATION" and type(event.get("payload")) is dict
               and event["payload"].get("reason") == "RECONCILIATION_REQUIRED" for event in row["events"])


def _records(value, key):
    """Whether `value` (a final snapshot) holds `key` set to True anywhere."""
    if type(value) is dict:
        return value.get(key) is True or any(_records(item, key) for item in value.values())
    if type(value) is list:
        return any(_records(item, key) for item in value)
    return False


def _intent(prefix):
    return lambda row: row["intent"].startswith(prefix)


def _transcripts(rule):
    return lambda vectors: [row["id"] for row in vectors["transcripts"] if rule(row)]


def _unarmed(row):
    return (_closed_request(row, {"REQUEST_MISMATCH", "STAMP_NONE", "NOT_ACTIVE", "PROTOCOL_VIOLATION"})
            or _refused(row, "ARM_ACTION", ARM_MISUSE) or _refused(row, "ACTION_OUTCOME", {"UNKNOWN_ACTION"})
            or any(_refused(row, operation, WRITE_MISUSE) for operation in WRITES))


def _old_socket(row):
    return (_closed_request(row, {"CONNECTION_CLOSED"})
            or any("refusedChannel" in output or "refusedSession" in output for output in row["outputs"])
            or any(_refused(row, operation, {"MAINTENANCE_ENDED"}) for operation in WRITES))


def _queued(row):
    return (_flushes(row) or _refused(row, "ARM_ACTION", {"ACTION_OUTSTANDING", "DRAIN_PENDING"})
            or _refused(row, "BIND_EXECUTION", {"ACTION_OUTSTANDING"}))


def _mentions(value, text):
    """Whether `value` (a final snapshot) holds the string `text` anywhere."""
    if type(value) is dict:
        return any(_mentions(item, text) for item in value.values())
    if type(value) is list:
        return any(_mentions(item, text) for item in value)
    return value == text


def _ambiguous(row):
    return _closes_for_reconciliation(row) or _mentions(row["final"], "IO_AMBIGUOUS") or any(
        output.get("classification") == "IO_AMBIGUOUS" or _response(output).get("classification") == "IO_AMBIGUOUS"
        or "lateUpstream" in output for output in row["outputs"])


def _admitted_before_invalidation(row):
    return (row["intent"].startswith("Counterexample 18") or _records(row["final"], "admittedBeforeInvalidation") or any(
        event.get("operation") == "ACTION_OUTCOME" and _response(output).get("admittedBeforeInvalidation") is True
        for event, output in _steps(row)))


def _c2_c3(row):
    return _flushes(row) or any(event["type"] == "ACCEPT" and "stamp" in output and output["stamp"] is None
                                for event, output in _steps(row))


def _restart(row):
    return any(event["type"] == "GATE_RESTART" for event in row["events"])


def _storage_failure(row):
    return any(event["type"] in STORAGE_FAILURES for event in row["events"])


def _partial(row):
    return any((event["type"] == "STORAGE_FAIL_NEXT" and event.get("torn") is True) or event["type"] == "STORAGE_FAIL_AFTER"
               for event in row["events"])


def _writer_lost_mid_session(row):
    """The writer's channel lost before its session ended with WRITE_END (an orderly end is not a lost answer)."""
    last = None
    for event in row["events"]:
        if event["type"] == "W_FRAME":
            last = event.get("operation")
        elif event["type"] == "W_CHANNEL_LOST" and last != "WRITE_END":
            return True
    return False


def _lost_acknowledgement(row):
    return _writer_lost_mid_session(row) or any(
        event["type"] in ("UPSTREAM_LOST", "UPSTREAM_TIMEOUT") or "lateUpstream" in output
        or (event["type"] == "W_UPSTREAM" and event.get("upstream") in ("LOST", "TIMEOUT"))
        or (event["type"] == "CHANNEL_LOST" and "fatal" in output) for event, output in _steps(row))


def _rollback(row):
    return (_restart(row) or any(event["type"] == "MARKER_FAIL_NEXT" for event in row["events"])
            or _refused(row, "BIND_EXECUTION", {"EXECUTION_REPLAY", "MANIFEST_REUSED"}))


def _disagreement(vectors):
    return [row["id"] for row in vectors["agreement"] if row["expect"] is not None]


def _misattribution(vectors):
    # Sections 6.2-6.3: only a GET can be resent with identical bytes; a mutation's key is refused if repeated (C7).
    return [row["id"] for row in vectors["agreement"]
            if row["verb"] == "GET" and row["expect"] is not None and row["expect"].startswith(MISATTRIBUTION)]


def _stamp_not_armed(vectors):
    return [row["id"] for row in vectors["claims"] if row["claim"].get("check") == "A1"
            and type(row["claim"].get("evidence")) is dict and row["claim"]["evidence"].get("stampEqualsArmedAction") is False]


def _a3_a4(vectors):
    return [row["id"] for row in vectors["claims"] if row["claim"].get("check") in ("A3", "A4")]


UNARMED = ("a request closed as not matching the armed action, without a stamp, while the generation is not active or as a "
           "protocol violation (a second request on one connection); an ARM refused as out of order, outstanding, outside the case "
           "manifest set, a reused mutation key, a template mismatch or with no bound execution; an outcome refused for an "
           "unknown action; or a write refused with no open maintenance, out of order, or outside its scope or generation")
UNARMED_CLAIM = "an A1 admission claim whose stamp is not the armed action's"
OLD_SOCKET = ("a request on a connection closed because it was flushed or stamped for an earlier action; a gate channel or writer "
              "session refused as already used or existing; or a write refused because its maintenance session ended")
QUEUED = ("an ARM that flushes backlogged connections (C2), or an ARM or BIND refused while another action is outstanding, or an "
          "ARM refused while a drain is pending")
CONFLICT = ("an agreement check in which the server's resource result disagrees with the gate's outcome, or a transcript "
            "whose result is IO_AMBIGUOUS (in an output or the final snapshot) or arrives late, or whose generation the "
            "broker closes as RECONCILIATION_REQUIRED")
CONFLICT_AGREEMENT = "an agreement check in which the server's resource result disagrees with the gate's outcome"
CE17 = "the transcripts whose intent is Counterexample 17"
S63 = ("the GET agreement checks that refuse a result attributed to another action (M01 action identifiers, M06 object "
       "identity, M07 UID or resourceVersion differ): HOST_INTERFACE_SPEC sections 6.2-6.3 say only a GET can be resent with "
       "identical bytes and that the misattribution appears in this check")
S63_HELD = ("the transcripts whose generation the broker closes as RECONCILIATION_REQUIRED: section 6.3's disagreement that "
            "becomes HELD")
CE18 = ("the transcripts whose intent is Counterexample 18, every outcome reported ADMITTED_BEFORE_INVALIDATION and every final "
        "snapshot that records it")
CE18_CLAIM = "the A3 (policy write waits for the drain) and A4 (admitted before invalidation) admission claims"
CE21 = "the transcripts whose intent is Counterexample 21"
CE22 = "the transcripts whose intent is Counterexample 22"
C2C3 = "an ARM that flushes backlogged connections (C2), or a connection accepted with no stamp (C3)"
KILL = "a transcript in which the gate is restarted (GATE_RESTART), whatever boundary it stopped at"
ENOSPC = "a transcript with an injected storage failure (STORAGE_FAIL_NEXT or STORAGE_FAIL_AFTER)"
PARTIAL = ("a transcript with a torn storage write (STORAGE_FAIL_NEXT with torn) or a failure part way through a transition's "
           "records (STORAGE_FAIL_AFTER)")
LOST = ("an upstream answer lost, timed out or late (the gate's or the writer's upstream); the broker channel lost with a "
        "fatal answer from the gate; or the writer's channel lost before its session ended with WRITE_END")
ROLLBACK = ("a gate restart, a failed restart marker (MARKER_FAIL_NEXT), or a BIND refused as a replayed execution or a "
            "reused manifest")

# (tag, contract, vector set, vector file prefix, basis, rule) per test group, in the plan's case order.
RULES = {
    "TG-02": [
        ("MATRIX:unarmed/duplicate/cross-case action", "I05 gate channel v3", "transcripts", I05, UNARMED, _transcripts(_unarmed)),
        ("MATRIX:unarmed/duplicate/cross-case action", "I07 policy write v3", "transcripts", I07, UNARMED, _transcripts(_unarmed)),
        ("MATRIX:unarmed/duplicate/cross-case action", "Admission semantics v3", "claims", ADMISSION, UNARMED_CLAIM, _stamp_not_armed),
        ("MATRIX:old socket", "I05 gate channel v3", "transcripts", I05, OLD_SOCKET, _transcripts(_old_socket)),
        ("MATRIX:old socket", "I07 policy write v3", "transcripts", I07, OLD_SOCKET, _transcripts(_old_socket)),
        ("MATRIX:queued action", "I05 gate channel v3", "transcripts", I05, QUEUED, _transcripts(_queued)),
        ("MATRIX:queued action", "I07 policy write v3", "transcripts", I07, QUEUED, _transcripts(_queued)),
        ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "agreement", I05, CONFLICT_AGREEMENT, _disagreement),
        ("MATRIX:conflicting gate/server result", "I05 gate channel v3", "transcripts", I05, CONFLICT, _transcripts(_ambiguous)),
        ("MATRIX:conflicting gate/server result", "I07 policy write v3", "transcripts", I07, CONFLICT, _transcripts(_ambiguous)),
        ("MATRIX:same-generation delayed-identical-request across two armed actions", "I05 gate channel v3", "transcripts", I05,
         CE17, _transcripts(_intent("Counterexample 17"))),
        ("S63-SOURCE", "I05 gate channel v3", "agreement", I05, S63, _misattribution),
        ("S63-SOURCE", "I05 gate channel v3", "transcripts", I05, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("S63-SOURCE", "I07 policy write v3", "transcripts", I07, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("S63-NATIVE", "I05 gate channel v3", "agreement", I05, S63, _misattribution),
        ("S63-NATIVE", "I05 gate channel v3", "transcripts", I05, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("S63-NATIVE", "I07 policy write v3", "transcripts", I07, S63_HELD, _transcripts(_closes_for_reconciliation)),
        ("CE18", "I05 gate channel v3", "transcripts", I05, CE18, _transcripts(_admitted_before_invalidation)),
        ("CE18", "I07 policy write v3", "transcripts", I07, CE18, _transcripts(_admitted_before_invalidation)),
        ("CE18", "Admission semantics v3", "claims", ADMISSION, CE18_CLAIM, _a3_a4),
        ("CE22", "I05 gate channel v3", "transcripts", I05, CE22, _transcripts(_intent("Counterexample 22"))),
        ("S8-C2C3", "I05 gate channel v3", "transcripts", I05, C2C3, _transcripts(_c2_c3)),
        ("S8-C2C3", "I07 policy write v3", "transcripts", I07, C2C3, _transcripts(_c2_c3)),
    ],
    "TG-03": [
        ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "transcripts", I05, KILL, _transcripts(_restart)),
        ("MATRIX:kill at each fsync/send/result boundary", "I05 gate channel v3", "supplement", SUPPLEMENT, KILL, _transcripts(_restart)),
        ("MATRIX:kill at each fsync/send/result boundary", "I07 policy write v3", "transcripts", I07, KILL, _transcripts(_restart)),
        ("MATRIX:ENOSPC", "I05 gate channel v3", "transcripts", I05, ENOSPC, _transcripts(_storage_failure)),
        ("MATRIX:ENOSPC", "I05 gate channel v3", "supplement", SUPPLEMENT, ENOSPC, _transcripts(_storage_failure)),
        ("MATRIX:ENOSPC", "I07 policy write v3", "transcripts", I07, ENOSPC, _transcripts(_storage_failure)),
        ("MATRIX:partial records", "I05 gate channel v3", "transcripts", I05, PARTIAL, _transcripts(_partial)),
        ("MATRIX:partial records", "I05 gate channel v3", "supplement", SUPPLEMENT, PARTIAL, _transcripts(_partial)),
        ("MATRIX:partial records", "I07 policy write v3", "transcripts", I07, PARTIAL, _transcripts(_partial)),
        ("MATRIX:lost acknowledgements", "I05 gate channel v3", "transcripts", I05, LOST, _transcripts(_lost_acknowledgement)),
        ("MATRIX:lost acknowledgements", "I07 policy write v3", "transcripts", I07, LOST, _transcripts(_lost_acknowledgement)),
        ("MATRIX:restart/rollback", "I05 gate channel v3", "transcripts", I05, ROLLBACK, _transcripts(_rollback)),
        ("MATRIX:restart/rollback", "I05 gate channel v3", "supplement", SUPPLEMENT, ROLLBACK, _transcripts(_rollback)),
        ("MATRIX:restart/rollback", "I07 policy write v3", "transcripts", I07, ROLLBACK, _transcripts(_rollback)),
        ("CE21", "I05 gate channel v3", "transcripts", I05, CE21, _transcripts(_intent("Counterexample 21"))),
        ("S8-C2C3", "I05 gate channel v3", "transcripts", I05, C2C3, _transcripts(_c2_c3)),
        ("S8-C2C3", "I07 policy write v3", "transcripts", I07, C2C3, _transcripts(_c2_c3)),
    ],
}


# Native groups (TG-04 host, TG-05 clocks; W04-4a, CONF-ENF-004). Each row also names the contract file it reads.
SELINUX = "architecture/selinux-matrix-v2/vectors.json"
SECCOMP = "architecture/seccomp-allowlists-v2/vectors.json"
SYSCALL_TABLE = "architecture/seccomp-allowlists-v2/syscalls.json"
NATIVE = "architecture/native-profile-v3/vectors.json"
NATIVE_MODEL = "scripts/native_qualification_v3.py"
W02D = "architecture/host-interface-amendment-w02d/amendment.json"
W02D_SPEC = "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md"
I05_VECTORS = I05 + "vectors.json"
SELINUX_V4, SECCOMP_V2, NATIVE_V3, W02D_NAME, I05_V3 = ("SELinux matrix v4", "Seccomp allowlists v2",
                                                          "Native qualification profile v3", "W01 amendment W02D",
                                                          "I05 gate channel v3")
MOUNT_FAMILY = {"mount", "umount2", "move_mount", "open_tree", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
                "pivot_root", "setns", "unshare", "chroot"}
INJECTION = {"memfd_create", "ptrace", "process_vm_readv", "process_vm_writev", "execve", "execveat", "userfaultfd",
             "personality", "mprotect", "mmap", "mremap"}
PARENTAGE = {"pidfd_open", "pidfd_send_signal", "kill", "tgkill", "clone", "clone3", "waitid", "setgroups", "setresuid",
             "setresgid", "close_range"}
DESCRIPTORS = {"close", "close_range", "dup", "dup3", "fcntl", "sendmsg", "recvmsg", "socketpair", "pidfd_open"}
READER_ROLES = {"SERVER", "OBSERVER", "BROKER"}
PEER_FATALS = {"PEER_LOST", "PEER_CHANGED"}


def _assertion(row):
    """The matrix assertion a SELinux access check names at the head of its intent ("A12: ...")."""
    return row["intent"].split(":", 1)[0]


def _access(*assertions):
    """Access checks of the named assertions; a name ending in '.' takes every sub-assertion under it (A59.planeon_*)."""
    def rule(vectors):
        return [row["id"] for row in vectors["accessChecks"] if _assertion(row) in assertions
                or any(name.endswith(".") and _assertion(row).startswith(name) for name in assertions)]
    return rule


def _access_where(predicate):
    return lambda vectors: [row["id"] for row in vectors["accessChecks"] if predicate(row)]


def _matrix_mutations(*assertions):
    """Mutation checks whose expected failure names one of the assertions (or a sub-assertion of a name ending in '.')."""
    def rule(vectors):
        return [row["id"] for row in vectors["mutationChecks"] if any(
            failed in assertions or any(name.endswith(".") and failed.startswith(name) for name in assertions)
            for failed in row["expect"].get("failedAssertions", []))]
    return rule


def _syscall_names():
    table = _models.data(SYSCALL_TABLE)
    return {(arch, row[arch]["nr"]): name for name, row in table["syscalls"].items() for arch in ("x86_64", "aarch64")
            if row.get(arch)}


def _decisions(calls, roles=None):
    """Seccomp v2 decision checks of the named syscalls (by each architecture's own number), optionally for some roles."""
    def rule(vectors):
        names = _syscall_names()
        return [row["id"] for row in vectors["decisionChecks"] if names.get((row["arch"], row["nr"])) in calls
                and (roles is None or row["role"] in roles)]
    return rule


def _every_decision(vectors):
    return [row["id"] for row in vectors["decisionChecks"]]


def _policy_mutations(calls):
    """Seccomp v2 policy mutations that add a duty for one of the named syscalls."""
    return lambda vectors: [row["id"] for row in vectors["policyMutations"]
                            if {rule["name"] for rule in row["addDuty"]["rules"]} & calls]


def _worker_stack(vectors):
    return [row["id"] for row in vectors["workerStackChecks"]]


def _native(*refusals):
    """Native v3 negative vectors with one of the refusals (a refusal ending in '.' is a prefix, e.g. 'schema $.selinux.')."""
    return lambda vectors: [row["id"] for row in vectors["negative"] if row["refusal"] in refusals
                            or any(name.endswith(".") and row["refusal"].startswith(name) for name in refusals)]


def _listed(*ids):
    """A fixed list of identifiers whose existence the group's tests check against the source (model rules, spec steps)."""
    return lambda source: list(ids)


def _items(*ids):
    return lambda amendment: [row["id"] for row in amendment["items"] if row["id"] in ids]


def _obligations(*ids):
    return lambda amendment: [row["id"] for row in amendment["obligations"] if row["id"] in ids]


def _expire(row):
    return any(event["type"] == "EXPIRE" for event in row["events"])


def _peer_fatal(row):
    return any(output.get("fatal") in PEER_FATALS for output in row["outputs"])


def _bpf_detach_or_free(row):
    """The admin domain's denials counterexample 28 relies on: a containment program descriptor, the planeon cgroup
    directories and their files, and CAP_DAC_READ_SEARCH (open_by_handle_at)."""
    cgroup = row["target"].startswith("planeon_cgroup_")
    return row["source"] == "planeon_admin_t" and (
        (row["class"], row["perm"]) in {("bpf", "prog_run"), ("capability", "dac_read_search")}
        or (row["class"] == "dir" and row["perm"] in ("search", "open") and cgroup)
        or (row["class"] == "file" and row["perm"] == "write" and cgroup))


EXPIRE = "a transcript with an EXPIRE event: the bound execution's signed lifetime ends"
PEER_DEATH = ("a transcript whose gate answers a channel loss or a changed broker peer as fatal (PEER_LOST, PEER_CHANGED): "
              "the peer died or was replaced")
EXPIRED_CAPTURES = ("the native v3 model's window rules: a capture, lifecycle capture or backend observation outside the "
                    "record's signed validity window is refused")
NO_RENEWAL = ("the native v3 model's retained-capture rules: a later capture of the same role never starts before the "
              "previous one finished, never goes back in time and keeps the original deadline ('rollback or renewed "
              "lifetime'), and one inspection stays within its deadline ('inspection deadline')")
ORIGINAL_PARENT = ("W02D 5.4 W1-W3: the broker freezes the empty leaf, clone3 places the child frozen before user space, "
                   "and the broker inspects it through its pidfd before thawing; the original broker stays the parent")
W6_CLEANUP = ("W02D 5.4 W6: on expiry or invalidation the broker freezes the leaf, kills through cgroup.kill and waits for "
              "populated 0 before releasing it, or HOLDs; recorded in W06, no latency bound is claimed")
NOT_THE_ORIGINAL_BROKER = "native v3: a worker not started by the original broker is refused (Q06)"
POLICY_LOAD = ("SELinux matrix v4 assertions on booleans, policy load, enforcing mode and relabelling (A12, A13, A20-A23, A44, "
               "A62-A66), their access checks in every boot state and the mutations that break them")
HOST_LOCK = "native v3 vectors refused because the host lock state or the pinned booleans and hardening differ"
POLICY_LOAD_SPEC = ("W02D 5.2 S4 (containment clears its boolean and sets secure_mode_policyload until reboot) and 5.5 M1 "
                    "(any policy, boolean or relabel change needs the maintenance boot)")
POLICY_CHANGED = "the native v3 model's rule that the active policy must not change during an inspection ('active policy changed')"
MOUNTS = ("seccomp v2 decisions for the mount, namespace and root-changing syscalls every role is denied, on both "
          "architectures, and the policy mutation that grants one")
NAMESPACE_CUSTODY = "native v3 vectors refused because a role's process or kernel custody (namespaces, filter, labels) differs"
BPF_MATRIX = ("SELinux matrix v4 assertions on BPF program load and run, maps, planeon cgroup directories and files, and pins "
              "(A14-A19, A38, A39, A49-A51)")
BPF_SECCOMP = "seccomp v2 decisions for bpf (commands 7, 15 and 16 only), and the policy mutations that widen bpf"
BPF_NATIVE = ("native v3 vectors refused because the effective kernel filter differs, a program is effective outside the "
              "containment hooks or a pinned program field breaks its schema")
INJECTION_MATRIX = ("SELinux matrix v4 assertions on dynamic transitions, setexec, ptrace, executable memory, execmod and "
                    "execution without a transition (A32-A37 and each domain's A60 execute_no_trans)")
INJECTION_SECCOMP = ("seccomp v2 decisions for code-injection, mapping and exec syscalls (memfd_create, ptrace, process_vm_*, "
                     "execve, execveat, userfaultfd, personality, mprotect, mmap, mremap), and the mutations that grant one")
INJECTION_NATIVE = "native v3 vectors refused because the running image is not the role's executable or interpreter"
INJECTION_RULES = ("the native v3 model's mapping and code-closure rules without vectors ('missing or injected executable "
                   "map', 'file measurement differs', 'incomplete loaded-code closure')")
PARENT_MATRIX = ("SELinux matrix v4 assertions on who starts and signals the worker and the roles and who reads their /proc "
                 "(A29, A57, A58, A59 and its per-domain parts)")
PARENT_SECCOMP = ("seccomp v2 decisions for process creation, signalling, pidfd, credential and descriptor-closing syscalls, "
                  "and the mutations that grant one (BROKER pidfd_send_signal, setgroups)")
PARENT_NATIVE = ("native v3 vectors refused because a worker is not the original broker's child or descendant, or an "
                 "unenrolled process shares a role cgroup, or a capture is bound to the wrong role")
PARENT_W02D = "W02D items A10-A12 (W3 supplementary groups, W4 filter, W6 cgroup.kill instead of a pidfd signal)"
ALIASES_MATRIX = ("SELinux matrix v4 assertions on sealed types, cgroup writers, relabelling, pins, the seal marker, the "
                  "gate's journal and the datastore's data (A12, A13, A40-A44, A50-A55)")
ALIASES_NATIVE = "native v3 vectors refused because one file is reported at two inodes, one inode for two files, or a path is not canonical"
FD_SECCOMP = "seccomp v2 decisions for the descriptor syscalls (close, close_range, dup, dup3, fcntl, sendmsg, recvmsg, socketpair, pidfd_open)"
FD_SPEC = "W02D 5.4 W3: the broker checks the child's descriptor table holds only stdio and its FD3 socketpair end"
KERNEL_FACTS_SPEC = "W02D 5.1: the v6.12 kernel facts the readers' BPF command set and the attach and detach authority rest on"
KERNEL_FACTS_MATRIX = "SELinux matrix v4 assertions on maps and program descriptors (A16-A19)"
KERNEL_FACTS_NATIVE = ("native v3 record vectors refused because the inspection command set, a program's helper calls, attach "
                       "flags or maps, or the BPF hardening values break the schema")
POLICYLOAD_MATRIX = "SELinux matrix v4 assertions on booleans, policy load and enforcing mode (A20-A23, A62-A66)"
POLICYLOAD_NATIVE = "native v3 record vectors refused because a pinned boolean breaks the schema, and lifecycle captures with containment entry enabled"
POLICYLOAD_SPEC = "W02D 5.2 S4: containment clears its boolean and sets secure_mode_policyload, both until reboot"
FREEZE_SECCOMP = "seccomp v2 decisions for the BROKER's clone3 (the W2 call)"
FREEZE_MATRIX = "SELinux matrix v4 assertion A29: only the broker starts the worker"
CLOSURE_NATIVE = ("native v3 vectors refused for the cgroup census and residency rules: unenrolled or populated cgroups, "
                  "descendants of role cgroups, the delegated broker subtree, containment still resident")
CLOSURE_MATRIX = "SELinux matrix v4 closure assertions: no source reaches beyond its listed targets (A60) and only the readers search or read planeon cgroups (A38, A39)"
CLOSURE_SPEC = "W02D 2.2 and 2.3: the API-path and identity closure"
AMEND_SECCOMP = "every seccomp v2 decision check: per role and architecture, ALLOW, KILL_PROCESS or ENOSYS"
AMEND_STACK = "every seccomp v2 worker-stack check (the worker's own filter stacked on the inherited broker filter)"
AMEND_MUTATIONS = "the seccomp v2 policy mutations for the executable memfd, the broker's pidfd signal and setgroups"
AMEND_W02D = "W02D items A1-A12 and obligation O-T04-AMEND (native confirmation)"
CE19_MATRIX = ("SELinux matrix v4 assertions on entering containment, setting booleans and starting units (A20, A21, A24, "
               "A25, A56)")
CE19_SPEC = "W02D 9 (19), 5.2 S2 and S4"
CE25_MATRIX = "SELinux matrix v4 assertions on the datastore's socket and data (A05, A55)"
CE25_SPEC = "W02D 9 (25)"
CE27_MATRIX = "SELinux matrix v4 assertion A47: only systemd and the confined kubelet and runtime hold CAP_SYS_ADMIN"
CE27_SECCOMP = "seccomp v2 bpf decisions for the reader roles (commands 7, 15 and 16 only; GET_FD_BY_ID, 13, is not among them)"
CE27_NATIVE = "native v3 record vectors refused because the inspection command set breaks its schema"
CE27_SPEC = "W02D 9 (27) and 5.1"
CE28_MATRIX = ("SELinux matrix v4 access checks of the admin domain on program descriptors, planeon cgroup directories and "
               "files, and CAP_DAC_READ_SEARCH (the denials counterexample 28 relies on)")
CE28_NATIVE = "native v3 record vectors refused because a program's attach flags break the schema (MULTI attachment)"
CE28_SPEC = "W02D 9 (28) and 5.1"

# (tag, contract, vector set, source file, basis, rule) per native group, in the plan's case order.
NATIVE_RULES = {
    "TG-04": [
        ("MATRIX:policy/load/boolean/relabel", SELINUX_V4, "accessChecks", SELINUX, POLICY_LOAD,
         _access("A12", "A13", "A20", "A21", "A22", "A23", "A44", "A62", "A63", "A64", "A65", "A66")),
        ("MATRIX:policy/load/boolean/relabel", SELINUX_V4, "mutationChecks", SELINUX, POLICY_LOAD,
         _matrix_mutations("A12", "A13", "A20", "A21", "A22", "A23", "A44", "A62", "A63", "A64", "A65", "A66")),
        ("MATRIX:policy/load/boolean/relabel", NATIVE_V3, "negative", NATIVE, HOST_LOCK,
         _native("host lock state differs", "schema $.selinux.booleans.", "schema $.hardening.")),
        ("MATRIX:policy/load/boolean/relabel", NATIVE_V3, "modelRules", NATIVE_MODEL, POLICY_CHANGED, _listed("active policy changed")),
        ("MATRIX:policy/load/boolean/relabel", W02D_NAME, "specSections", W02D_SPEC, POLICY_LOAD_SPEC, _listed("5.2 S4", "5.5 M1")),
        ("MATRIX:namespaces/mount aliases", SECCOMP_V2, "decisionChecks", SECCOMP, MOUNTS, _decisions(MOUNT_FAMILY)),
        ("MATRIX:namespaces/mount aliases", SECCOMP_V2, "policyMutations", SECCOMP, MOUNTS, _policy_mutations(MOUNT_FAMILY)),
        ("MATRIX:namespaces/mount aliases", NATIVE_V3, "negative", NATIVE, NAMESPACE_CUSTODY, _native("process/kernel custody differs")),
        ("MATRIX:effective BPF ancestors", SELINUX_V4, "accessChecks", SELINUX, BPF_MATRIX,
         _access("A14", "A15", "A16", "A17", "A18", "A19", "A38", "A39", "A49", "A50", "A51")),
        ("MATRIX:effective BPF ancestors", SELINUX_V4, "mutationChecks", SELINUX, BPF_MATRIX,
         _matrix_mutations("A14", "A15", "A16", "A17", "A18", "A19", "A38", "A39", "A49", "A50", "A51")),
        ("MATRIX:effective BPF ancestors", SECCOMP_V2, "decisionChecks", SECCOMP, BPF_SECCOMP, _decisions({"bpf"})),
        ("MATRIX:effective BPF ancestors", SECCOMP_V2, "policyMutations", SECCOMP, BPF_SECCOMP, _policy_mutations({"bpf"})),
        ("MATRIX:effective BPF ancestors", NATIVE_V3, "negative", NATIVE, BPF_NATIVE,
         _native("effective kernel filter differs", "program effective on a role cgroup outside the containment hooks",
                 "schema $.effectiveCensus required", "schema $.roles.OBSERVER.bpfPrograms.")),
        ("MATRIX:mappings/injection", SELINUX_V4, "accessChecks", SELINUX, INJECTION_MATRIX,
         _access_where(lambda row: _assertion(row) in {"A32", "A33", "A34", "A35", "A36", "A37"}
                       or (_assertion(row).startswith("A60.") and _assertion(row).endswith(".execute_no_trans")))),
        ("MATRIX:mappings/injection", SELINUX_V4, "mutationChecks", SELINUX, INJECTION_MATRIX,
         _matrix_mutations("A32", "A33", "A34", "A35", "A36", "A37", "A60.15.execute_no_trans", "A60.16.execute_no_trans",
                           "A60.17.execute_no_trans", "A60.18.execute_no_trans", "A60.19.execute_no_trans",
                           "A60.20.execute_no_trans", "A60.21.execute_no_trans")),
        ("MATRIX:mappings/injection", SECCOMP_V2, "decisionChecks", SECCOMP, INJECTION_SECCOMP, _decisions(INJECTION)),
        ("MATRIX:mappings/injection", SECCOMP_V2, "policyMutations", SECCOMP, INJECTION_SECCOMP, _policy_mutations(INJECTION)),
        ("MATRIX:mappings/injection", NATIVE_V3, "negative", NATIVE, INJECTION_NATIVE,
         _native("running image is not the role's executable or interpreter")),
        ("MATRIX:mappings/injection", NATIVE_V3, "modelRules", NATIVE_MODEL, INJECTION_RULES,
         _listed("missing or injected executable map", "file measurement differs", "incomplete loaded-code closure")),
        ("MATRIX:parent/FD spoof", SELINUX_V4, "accessChecks", SELINUX, PARENT_MATRIX, _access("A29", "A57", "A58", "A59", "A59.")),
        ("MATRIX:parent/FD spoof", SELINUX_V4, "mutationChecks", SELINUX, PARENT_MATRIX,
         _matrix_mutations("A29", "A57", "A58", "A59", "A59.")),
        ("MATRIX:parent/FD spoof", SECCOMP_V2, "decisionChecks", SECCOMP, PARENT_SECCOMP, _decisions(PARENTAGE)),
        ("MATRIX:parent/FD spoof", SECCOMP_V2, "policyMutations", SECCOMP, PARENT_SECCOMP, _policy_mutations(PARENTAGE)),
        ("MATRIX:parent/FD spoof", NATIVE_V3, "negative", NATIVE, PARENT_NATIVE,
         _native("worker is not a child of the original broker", "worker member not descended from the inspected worker",
                 "unenrolled cgroup member", "capture binding")),
        ("MATRIX:parent/FD spoof", W02D_NAME, "items", W02D, PARENT_W02D, _items("A10", "A11", "A12")),
        ("MATRIX:parent/FD spoof", W02D_NAME, "specSections", W02D_SPEC, ORIGINAL_PARENT, _listed("5.4 W2", "5.4 W3", "5.4 W6")),
        ("LEDGER-E01", SELINUX_V4, "accessChecks", SELINUX, ALIASES_MATRIX,
         _access("A12", "A13", "A40", "A41", "A42", "A43", "A44", "A50", "A51", "A52", "A53", "A54", "A55")),
        ("LEDGER-E01", SELINUX_V4, "mutationChecks", SELINUX, ALIASES_MATRIX,
         _matrix_mutations("A12", "A13", "A40", "A41", "A42", "A43", "A44", "A50", "A51", "A52", "A53", "A54", "A55")),
        ("LEDGER-E01", NATIVE_V3, "negative", NATIVE, ALIASES_NATIVE,
         _native("one file reported at two inodes", "one inode reported for two files", "canonical installed path")),
        ("LEDGER-E02", SECCOMP_V2, "decisionChecks", SECCOMP, FD_SECCOMP, _decisions(DESCRIPTORS)),
        ("LEDGER-E02", W02D_NAME, "specSections", W02D_SPEC, FD_SPEC, _listed("5.4 W3")),
        ("S8-KERNEL-FACTS", W02D_NAME, "specSections", W02D_SPEC, KERNEL_FACTS_SPEC, _listed("5.1")),
        ("S8-KERNEL-FACTS", SELINUX_V4, "accessChecks", SELINUX, KERNEL_FACTS_MATRIX, _access("A16", "A17", "A18", "A19")),
        ("S8-KERNEL-FACTS", SECCOMP_V2, "decisionChecks", SECCOMP, BPF_SECCOMP, _decisions({"bpf"})),
        ("S8-KERNEL-FACTS", NATIVE_V3, "negative", NATIVE, KERNEL_FACTS_NATIVE,
         _native("schema $.inspection.bpfCommands const", "schema $.roles.OBSERVER.bpfPrograms.",
                 "schema $.hardening.bpfJitHarden enum", "schema $.hardening.unprivilegedBpfDisabled const")),
        ("S8-POLICYLOAD", SELINUX_V4, "accessChecks", SELINUX, POLICYLOAD_MATRIX,
         _access("A20", "A21", "A22", "A23", "A62", "A63", "A64", "A65", "A66")),
        ("S8-POLICYLOAD", NATIVE_V3, "negative", NATIVE, POLICYLOAD_NATIVE, _native("schema $.selinux.booleans.", "host lock state differs")),
        ("S8-POLICYLOAD", W02D_NAME, "specSections", W02D_SPEC, POLICYLOAD_SPEC, _listed("5.2 S4")),
        ("S8-FREEZE", W02D_NAME, "specSections", W02D_SPEC, ORIGINAL_PARENT, _listed("5.4 W1", "5.4 W2", "5.4 W3")),
        ("S8-FREEZE", NATIVE_V3, "negative", NATIVE, NOT_THE_ORIGINAL_BROKER, _native("worker is not a child of the original broker")),
        ("S8-FREEZE", SECCOMP_V2, "decisionChecks", SECCOMP, FREEZE_SECCOMP, _decisions({"clone3"}, {"BROKER"})),
        ("S8-FREEZE", SELINUX_V4, "accessChecks", SELINUX, FREEZE_MATRIX, _access("A29")),
        ("S8-CLOSURE", NATIVE_V3, "negative", NATIVE, CLOSURE_NATIVE,
         _native("census children of the delegated broker service differ", "census lists a cgroup below a role cgroup",
                 "census reports a cgroup with captured processes as unpopulated", "containment subject still resident",
                 "planeon slice census incomplete", "planeon slice census malformed", "planeon slice census omits a parent cgroup",
                 "process directly in the planeon slice", "role cgroup has descendants", "delegated broker subtree differs",
                 "unenrolled populated cgroup in the planeon slice", "slice descendants differ from the census",
                 "role-domain process outside its role cgroup")),
        ("S8-CLOSURE", SELINUX_V4, "accessChecks", SELINUX, CLOSURE_MATRIX,
         _access_where(lambda row: _assertion(row) in {"A38", "A39"} or _assertion(row).startswith("A60."))),
        ("S8-CLOSURE", W02D_NAME, "specSections", W02D_SPEC, CLOSURE_SPEC, _listed("2.2", "2.3")),
        ("O-T04-AMEND", SECCOMP_V2, "decisionChecks", SECCOMP, AMEND_SECCOMP, _every_decision),
        ("O-T04-AMEND", SECCOMP_V2, "workerStackChecks", SECCOMP, AMEND_STACK, _worker_stack),
        ("O-T04-AMEND", SECCOMP_V2, "policyMutations", SECCOMP, AMEND_MUTATIONS,
         _policy_mutations({"memfd_create", "pidfd_send_signal", "setgroups"})),
        ("O-T04-AMEND", W02D_NAME, "items", W02D, AMEND_W02D,
         _items("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12")),
        ("O-T04-AMEND", W02D_NAME, "obligations", W02D, AMEND_W02D, _obligations("O-T04-AMEND")),
        ("CE19", SELINUX_V4, "accessChecks", SELINUX, CE19_MATRIX, _access("A20", "A21", "A24", "A25", "A56")),
        ("CE19", W02D_NAME, "specSections", W02D_SPEC, CE19_SPEC, _listed("9 19", "5.2 S2", "5.2 S4")),
        ("CE25", SELINUX_V4, "accessChecks", SELINUX, CE25_MATRIX, _access("A05", "A55")),
        ("CE25", W02D_NAME, "specSections", W02D_SPEC, CE25_SPEC, _listed("9 25")),
        ("CE27", SELINUX_V4, "accessChecks", SELINUX, CE27_MATRIX, _access("A47")),
        ("CE27", SECCOMP_V2, "decisionChecks", SECCOMP, CE27_SECCOMP, _decisions({"bpf"}, READER_ROLES)),
        ("CE27", NATIVE_V3, "negative", NATIVE, CE27_NATIVE, _native("schema $.inspection.bpfCommands const")),
        ("CE27", W02D_NAME, "specSections", W02D_SPEC, CE27_SPEC, _listed("9 27", "5.1")),
        ("CE28", SELINUX_V4, "accessChecks", SELINUX, CE28_MATRIX, _access_where(_bpf_detach_or_free)),
        ("CE28", NATIVE_V3, "negative", NATIVE, CE28_NATIVE, _native("schema $.roles.OBSERVER.bpfPrograms.INET4_CONNECT.attachFlags const")),
        ("CE28", W02D_NAME, "specSections", W02D_SPEC, CE28_SPEC, _listed("9 28", "5.1")),
    ],
    "TG-05": [
        ("MATRIX:expiry with stalled Python", I05_V3, "transcripts", I05_VECTORS, EXPIRE, _transcripts(_expire)),
        ("MATRIX:expiry with stalled Python", W02D_NAME, "specSections", W02D_SPEC, W6_CLEANUP, _listed("5.4 W6")),
        ("MATRIX:suspend", I05_V3, "transcripts", I05_VECTORS, EXPIRE, _transcripts(_expire)),
        ("MATRIX:suspend", NATIVE_V3, "negative", NATIVE, EXPIRED_CAPTURES, _native("expired lifecycle capture")),
        ("MATRIX:suspend", NATIVE_V3, "modelRules", NATIVE_MODEL, EXPIRED_CAPTURES, _listed("expired capture", "expired backend capture")),
        ("MATRIX:wall-clock rollback", I05_V3, "transcripts", I05_VECTORS, EXPIRE, _transcripts(_expire)),
        ("MATRIX:wall-clock rollback", NATIVE_V3, "modelRules", NATIVE_MODEL, NO_RENEWAL, _listed("rollback or renewed lifetime")),
        ("MATRIX:peer death/restart", I05_V3, "transcripts", I05_VECTORS, PEER_DEATH, _transcripts(_peer_fatal)),
        ("MATRIX:peer death/restart", NATIVE_V3, "negative", NATIVE, NOT_THE_ORIGINAL_BROKER, _native("worker is not a child of the original broker")),
        ("MATRIX:peer death/restart", W02D_NAME, "specSections", W02D_SPEC, ORIGINAL_PARENT, _listed("5.4 W2", "5.4 W6")),
        ("MATRIX:original deadlines", I05_V3, "transcripts", I05_VECTORS, EXPIRE, _transcripts(_expire)),
        ("MATRIX:original deadlines", NATIVE_V3, "modelRules", NATIVE_MODEL, NO_RENEWAL,
         _listed("rollback or renewed lifetime", "inspection deadline")),
        ("S8-FREEZE", W02D_NAME, "specSections", W02D_SPEC, ORIGINAL_PARENT, _listed("5.4 W1", "5.4 W2", "5.4 W3")),
        ("S8-FREEZE", NATIVE_V3, "negative", NATIVE, NOT_THE_ORIGINAL_BROKER, _native("worker is not a child of the original broker")),
    ],
}


# TG-08 compatibility (W04-6, CONF-ENF-007). Like TG-02/TG-03 its rows come from vector files only. S44 is the one offline
# case: its properties are the items of the plan's S44 case (W02D section 4.4's rejection list), and each S44 row serves the
# property its basis starts with. 4.4's migration sentence is MATRIX:export/upgrade/rollback's, as the plan places it.
NAT, I06 = _replays.NAT, _replays.I06
GATE_AND_BROKER = {"EFFECT_GATE": "BROKER", "BROKER": "EFFECT_GATE"}
ALIASES = ("duplicate cgroup inode", "one inode reported for two files", "one file reported at two inodes")
LIFECYCLE_SCHEMA = ("schema $.lifecycleSubjects.HOST_CONTAINMENT.cgroupPath const", "schema $.lifecycleSubjects.POLICY_WRITER.placement const")
MISSING_PARTS = ("schema $.roles required", "schema $.backendComponents required", "schema $.backendComponents additionalProperties",
                 "backend components differ from the implementation profile", "schema $.backendProfile.componentKeys const",
                 "one capture per resident role", "one observation per backend component")
REUSE = {"EXECUTION_REPLAY", "MANIFEST_REUSED"}


def _every(key):
    return lambda vectors: [row["id"] for row in vectors[key]]


def _positive(vectors, row):
    return vectors["positive"][row["positive"]]["record"]


def _ops(vectors, target):
    """(row, op, the positive record) for every op of every native v3 negative aimed at `target`."""
    return [(row, op, _positive(vectors, row)) for row in vectors["negative"] if row["target"] == target for op in row["ops"]]


def _ids(pairs):
    return list(dict.fromkeys(row["id"] for row, *_ in pairs))


def _earlier_record(vectors):
    """Negatives refused as not a v3 record or whose intent names an earlier version (v1 or v2), as TG-01's
    role/version selection reads it (review D1-6): a v1 schema version, a v1 cgroup path, a v2 fixture label."""
    return [row["id"] for row in vectors["negative"]
            if row["refusal"] == "not a v3 record" or _replays.EARLIER_VERSION.search(row["intent"])]


def _gate_removed(vectors):
    return _ids((row, op) for row, op, record in _ops(vectors, "record")
                if op["op"] == "delete" and op["path"] == ["roles", "EFFECT_GATE"])


def _role_added(vectors):
    return _ids((row, op) for row, op, record in _ops(vectors, "record")
                if op["op"] == "set" and len(op["path"]) == 2 and op["path"][0] == "roles" and op["path"][1] not in record["roles"])


def _path_of_other_role(op, roles, pairs):
    """A role's path field (a string starting with '/') set to another role's value at the same field."""
    path, value = op["path"], op.get("value")
    return (op["op"] == "set" and len(path) >= 3 and path[0] == "roles" and path[1] in roles and type(value) is str
            and value.startswith("/") and any(_replays._at(roles[other], path[2:]) == value for other in pairs(path[1], roles)))


def _gate_under_broker(vectors):
    """The gate enrolled under the BROKER key, or at the broker's executable, cgroup or pin path (or the reverse)."""
    pairs = lambda name, roles: [GATE_AND_BROKER[name]] if name in GATE_AND_BROKER else []
    return _ids((row, op) for row, op, record in _ops(vectors, "record") if _path_of_other_role(op, record["roles"], pairs))


def _aliased_path(vectors):
    """The model's role-path aliasing refusals (one cgroup inode for two roles, one inode for two files, one file at two
    inodes), and every record negative that sets a role's path field to another role's value (review D1-5)."""
    pairs = lambda name, roles: [other for other in roles if other != name]
    by_refusal = [row["id"] for row in vectors["negative"] if row["refusal"] in ALIASES]
    by_value = _ids((row, op) for row, op, record in _ops(vectors, "record") if _path_of_other_role(op, record["roles"], pairs))
    return list(dict.fromkeys(by_refusal + by_value))


def _lifecycle_in_role_cgroup(vectors):
    """The lifecycle subjects' cgroup path and placement schema refusals, and every capture negative of a resident role
    whose cgroup gains a member, or whose inspected process takes a label, of a lifecycle subject (review D1-1)."""
    def lifecycle_label(op, record):
        labels = {subject["processLabel"] for subject in record["lifecycleSubjects"].values()}
        value = op.get("value")
        return ((op["op"] == "append" and op["path"] == ["cgroupMembers"] and type(value) is dict and value.get("processLabel") in labels)
                or (op["op"] == "set" and op["path"] == ["process", "processLabel"] and value in labels))
    by_schema = [row["id"] for row in vectors["negative"] if row["refusal"] in LIFECYCLE_SCHEMA]
    by_member = _ids((row, op) for row, op, record in _ops(vectors, "capture") if lifecycle_label(op, record))
    return by_schema + by_member


def _i06_components(vectors):
    """I06 v2 negatives refused because the backend's component set or component keys differ from its profile."""
    return [row["id"] for key in ("evidenceNegative", "snapshotNegative") for row in vectors[key]
            if re.search(r"componentKeys|component set differs", row["refusal"])]


# S44's properties: the items of the plan's S44 case, each the head of its rows' basis (review D1-4). The plan cites the
# resolved W01 spec; W02D's effective spec carries the same section 4.4 (the tests pin both).
S44_SOURCE = ("W02D 4.4: architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 4.4, the same section in "
              "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md")
S44_VERSION = "each reader refuses a record of another version with no fallback"
S44_GATE_MISSING = "a record missing EFFECT_GATE refuses"
S44_EXTRA_ROLE = "a record with an extra role refuses"
S44_GATE_BROKER = "a record with the gate under the BROKER key or path refuses"
S44_ALIAS = "a record with an aliased role path refuses"
S44_LIFECYCLE = "a record with a lifecycle subject inside a resident role cgroup refuses"
S44_BACKEND_KEYS = "a record with unknown backendComponents keys refuses"
S44_PROPERTIES = (S44_VERSION, S44_GATE_MISSING, S44_EXTRA_ROLE, S44_GATE_BROKER, S44_ALIAS, S44_LIFECYCLE, S44_BACKEND_KEYS)
CROSS_VERSION = (S44_VERSION + ": every native v3 cross-version case (records and captures of v2 under v3 and of v3 under "
                 "v2; native v3 carries 4.4's v1/v2 pair one version on, and the literal v1/v2 vectors are native v2's, not "
                 "snapshotted)")
EARLIER_NEGATIVES = (S44_VERSION + ": native v3 negatives refused as not a v3 record, or whose intent names an earlier "
                     "version (a v1 schema version, a v1 cgroup path, a v2 fixture label)")
GATE_MISSING = S44_GATE_MISSING + ": native v3 record negatives that delete the EFFECT_GATE role"
EXTRA_ROLE = S44_EXTRA_ROLE + ": native v3 record negatives that add a role name the positive record lacks"
GATE_BROKER = (S44_GATE_BROKER + ": native v3 record negatives that set a gate or broker path field to the other role's value "
               "at the same field")
ALIAS = (S44_ALIAS + ": native v3 negatives with the model's role-path aliasing refusals (one cgroup inode for two roles, one "
         "inode for two files, one file at two inodes), and record negatives that set a role's path field to another role's "
         "value (the gate and broker cases among them)")
LIFECYCLE = (S44_LIFECYCLE + ": native v3 negatives refused by the lifecycle subjects' cgroup path and placement schema, and "
             "capture negatives of a resident role whose cgroup gains a lifecycle subject's process or whose inspected "
             "process runs in a lifecycle subject's domain")
BACKEND_KEYS = S44_BACKEND_KEYS + ": native v3 negatives refused by the backendComponents additionalProperties schema"
OLD_RECORDS = ("a record, capture, frame or configuration of another contract version: every native v3 cross-version case and "
               "its negatives refused as not a v3 record or whose intent names an earlier version")
OLD_I06 = "an I06 v2 negative refused as another version or not a v3 record, and every cross-version case"
OLD_I05 = "an I05 v3 frame or configuration refusal whose intent names an earlier contract version (v1 or v2)"
MISSING = ("a record or qualification missing the gate role or a resident role's capture, or with a backend component "
           "missing, unknown or outside its implementation profile: native v3 negatives refused by the role-set, "
           "backend-component and one-capture rules")
MISSING_I06 = "an I06 v2 negative refused because the backend's component set or component keys differ from its profile"
MIGRATION = ("every native v3 migration case: a maintenance reboot between versions, no nonce reused or carried across "
             "versions, valid predecessors, and the attested empty history (W02D 4.4: migration never reinterprets accepted "
             "v1 data and never reuses a v1 generation or nonce)")
REUSED = ("the gate's half of 'never reuses a generation or nonce' across an upgrade, which runs in a fresh generation (W02D "
          "5.5): I05 v3 transcripts whose BIND_EXECUTION is refused as a replayed execution or a reused manifest "
          "(EXECUTION_REPLAY, MANIFEST_REUSED)")
REINTERPRET = ("the gate's half of 'never reinterprets accepted v1 data': an I05 v3 configuration refusal whose intent names an "
               "earlier contract version (a v1-shaped record)")
SOURCE_ROWS = [
    ("MATRIX:old profile rejection", "Native qualification profile v3", "crossVersion", NAT, OLD_RECORDS, _every("crossVersion")),
    ("MATRIX:old profile rejection", "Native qualification profile v3", "negative", NAT, OLD_RECORDS, _earlier_record),
    ("MATRIX:old profile rejection", "I06 backend profile v2", "vectors", I06, OLD_I06, _replays._i06_version),
    ("MATRIX:old profile rejection", "I05 gate channel v3", "frames", I05, OLD_I05, _replays._earlier_version("frames")),
    ("MATRIX:old profile rejection", "I05 gate channel v3", "configRefusals", I05, OLD_I05, _replays._earlier_version("configRefusals")),
    ("MATRIX:new profile missing gate/backend", "Native qualification profile v3", "negative", NAT, MISSING, _native(*MISSING_PARTS)),
    ("MATRIX:new profile missing gate/backend", "Native qualification profile v3", "negative", NAT, GATE_BROKER, _gate_under_broker),
    ("MATRIX:new profile missing gate/backend", "I06 backend profile v2", "vectors", I06, MISSING_I06, _i06_components),
    ("MATRIX:export/upgrade/rollback without nonce reuse", "Native qualification profile v3", "migration", NAT, MIGRATION,
     _every("migration")),
    ("MATRIX:export/upgrade/rollback without nonce reuse", "I05 gate channel v3", "transcripts", I05, REUSED,
     _transcripts(lambda row: _refused(row, "BIND_EXECUTION", REUSE))),
    ("MATRIX:export/upgrade/rollback without nonce reuse", "I05 gate channel v3", "configRefusals", I05, REINTERPRET,
     _replays._earlier_version("configRefusals")),
]
RULES["TG-08"] = [
    ("S44", "Native qualification profile v3", "crossVersion", NAT, CROSS_VERSION, _every("crossVersion")),
    ("S44", "Native qualification profile v3", "negative", NAT, EARLIER_NEGATIVES, _earlier_record),
    ("S44", "Native qualification profile v3", "negative", NAT, GATE_MISSING, _gate_removed),
    ("S44", "Native qualification profile v3", "negative", NAT, EXTRA_ROLE, _role_added),
    ("S44", "Native qualification profile v3", "negative", NAT, GATE_BROKER, _gate_under_broker),
    ("S44", "Native qualification profile v3", "negative", NAT, ALIAS, _aliased_path),
    ("S44", "Native qualification profile v3", "negative", NAT, LIFECYCLE, _lifecycle_in_role_cgroup),
    ("S44", "Native qualification profile v3", "negative", NAT, BACKEND_KEYS, _native("schema $.backendComponents additionalProperties")),
    *SOURCE_ROWS,
    # The plan's INSTALLED case: the same migrations on the installed host in W06, kept apart from the source cases.
    *[("INSTALLED",) + row[1:] for row in SOURCE_ROWS],
]


FEASIBILITY = "docs/alpha-2/ENFORCEMENT_FEASIBILITY.md"
FEASIBILITY_NAME = "Enforcement feasibility obligation rows (recorded addition, owner decision Q-T13)"
OBLIGATION_ROWS = ("the plan's obligation rows the case serves, section 4 of ENFORCEMENT_FEASIBILITY.md at harness-onion "
                   "a2eab93 (owner decision Q-T13, 2026-10-13): each row's required proof is the case's expected result "
                   "at the level of the obligation")


def obligation_row(text, ident):
    """The pinned table row of obligation `ident` (a line starting '| E08 |'), or None."""
    rows = [line for line in text.splitlines() if line.startswith("| %s |" % ident)]
    return rows[0] if len(rows) == 1 else None


def native_catalog(group):
    """The selected rows of each case of a native group, by the rules above over the pinned contract files, then each
    case's obligation rows (owner decision Q-T13)."""
    rows = []
    for tag, contract, vector_set, source, basis, rule in NATIVE_RULES[group]:
        raw = _models.snapshot_bytes(source)
        value = _models._strict(raw) if source.endswith(".json") else raw.decode("utf-8")
        rows.append({"case": tag, "contract": contract, "vectorSet": vector_set, "source": source, "basis": basis, "ids": rule(value)})
    text = _models.snapshot_bytes(FEASIBILITY).decode("utf-8")
    plan_group = next(row for row in _models.data(PLAN)["testGroups"] if row["id"] == group)
    for case in plan_group["cases"]:
        rows.append({"case": case["tag"], "contract": FEASIBILITY_NAME, "vectorSet": "obligationRows", "source": FEASIBILITY,
                     "basis": OBLIGATION_ROWS, "ids": [ident for ident in case["obligations"] if obligation_row(text, ident)]})
    return rows


def model_rule_messages(source):
    """Every message a model's checks can refuse with: the literal message argument of each `require(condition, message)`
    call, and the literal argument a helper passes on to require as its message (native v3's `_within`)."""
    tree = ast.parse(_models.snapshot_bytes(source).decode("utf-8"))
    forwarding = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            names = [argument.arg for argument in node.args.args]
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and getattr(call.func, "id", None) == "require" and len(call.args) == 2
                        and isinstance(call.args[1], ast.Name) and call.args[1].id in names):
                    forwarding[node.name] = names.index(call.args[1].id)
    messages = set()
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        name = getattr(call.func, "id", None)
        index = 1 if name == "require" else forwarding.get(name)
        if index is not None and len(call.args) > index and isinstance(call.args[index], ast.Constant) \
                and type(call.args[index].value) is str:
            messages.add(call.args[index].value)
    return messages


def spec_step(text, ident):
    """The pinned line a spec-step id names: '<section>' (a numbered heading) or '<section> <step>' (a line starting
    '<step>. ' inside that section, e.g. '5.4 W6', '9 19'). None if the id names nothing."""
    section, _, step = ident.partition(" ")
    lines = text.splitlines()
    heading = re.compile(r"^(#{2,3}) %s[. ]" % re.escape(section))
    for index, line in enumerate(lines):
        found = heading.match(line)
        if not found:
            continue
        if not step:
            return line
        level = len(found.group(1))
        for inner in lines[index + 1:]:
            deeper = re.match(r"^(#{2,6}) ", inner)
            if deeper and len(deeper.group(1)) <= level:
                return None
            if inner.startswith(step + ". "):
                return inner
        return None
    return None


def catalog(group):
    """The selected vectors of each gated case of `group`, by the rules above over the pinned vectors."""
    return [{"case": tag, "contract": contract, "vectorSet": vector_set, "basis": basis, "ids": rule(_models.data(prefix + "vectors.json"))}
            for tag, contract, vector_set, prefix, basis, rule in RULES[group]]


PLAN = "architecture/enforcement-test-plan/traceability.json"
SUBJECTS = {"W04_OFFLINE": "R12's reader, src/harness_conformance/live_proxy_server.py (owner decision Q-T9)",
            "AFTER_W05_RELEASE_SET": "W05's released build, through a wire-level adapter (owner decision Q-T8)",
            "W06_NATIVE_ONLY": "W05's released build on the enrolled AMD64 and ARM64 hosts in W06"}
REASONS = {"AFTER_W05_RELEASE_SET": "AFTER_W05_RELEASE_SET: the subject is W05's released build, which does not exist yet; the "
                                    "catalog fixes the contract vectors and expected results now, and the executable source and "
                                    "the wire-level adapter come with W05's release set (owner decision Q-T8)",
           "W06_NATIVE_ONLY": "W06_NATIVE_ONLY: native evidence on the enrolled hosts in W06; the catalog fixes the contract "
                              "vectors and expected results now (owner decision Q-T8)"}
RULE = ("Each plan case of the group, in plan order. A W04_OFFLINE case lists its properties (the obligation's and acceptance "
        "row's parts) with the tests that show each one in this run. A property that needs an environment this run lacks is "
        "NOT_RUN_ENV_UNAVAILABLE and names the plan's native cases that carry it; it is outside the case's own scope (owner "
        "decision Q-T11), so the case is PASS only when every property within its own scope is PASS. A case that waits for W05's release set "
        "or for W06's native hosts is NOT_RUN_ENV_UNAVAILABLE, never PASS (AGENTS rule 14), and its catalog names the contract "
        "vectors whose own outputs and final snapshots are its expected results.")
TG08_RULE = ("Each plan case of the group, in plan order, in two parts kept apart as the plan's SOURCE_AND_INSTALLED_MIGRATION "
             "evidence asks (`part`): the SOURCE cases are checked against source (S44 offline through the contracts' reference "
             "models, the three MATRIX cases as source tests of W05's released build), and the INSTALLED case repeats the same "
             "contract rows on the enrolled hosts in W06. S44 lists one property per item of the plan's S44 case (W02D section "
             "4.4's rejection list; 4.4's migration sentence is MATRIX:export/upgrade/rollback's, as the plan places it), and each "
             "S44 row serves the property its basis starts with. S44's subject is the native qualification v3 reference model "
             "the contract's vectors replay through, not a reader. A property is PASS only when every one of its "
             "vectors replayed and passed in this run, and NOT_RUN_ENV_UNAVAILABLE when its replay needs what the verifier "
             "profile lacks (owner decisions Q-T4 and Q-T20); S44 is PASS only when every property is. A case that waits for "
             "W05's release set or for W06's native hosts is NOT_RUN_ENV_UNAVAILABLE, never PASS (AGENTS rule 14), and its "
             "catalog names the contract vectors whose own expected results are its expected results (owner decision Q-T8).")
GROUP_RULES = {"TG-08": TG08_RULE}
# Review D1-2: S44 replays a contract's reference model; R12's reader (Q-T9) is LEDGER-E09's subject, not S44's.
CASE_SUBJECTS = {("TG-08", "S44"): ("the snapshotted native qualification v3 reference model, through which TG-01 replays the "
                                    "contract's vectors (owner decisions Q-T4 and Q-T20); the readers W02D 4.4 names are W05's "
                                    "roles, checked in TG-08's source and installed cases")}
# TG-08's two parts: the installed host's case (W06) apart from the source cases.
PARTS = {"TG-08": lambda case: "INSTALLED" if case["phase"] == "W06_NATIVE_ONLY" else "SOURCE"}
PROPERTY_FIELDS = ("property", "source", "result", "reason", "tests", "carriedBy")
PACKETS = {"TG-02": "CONF-ENF-003", "TG-03": "CONF-ENF-003", "TG-04": "CONF-ENF-004", "TG-05": "CONF-ENF-004",
           "TG-08": "CONF-ENF-007"}
NATIVE_RULE = ("Each plan case of the group, in plan order. Every case waits for W06's enrolled AMD64 and ARM64 hosts and is "
               "NOT_RUN_ENV_UNAVAILABLE until W06 runs it, never PASS before (AGENTS rule 14); D-PROBE-ROUTE (owner decision "
               "Q-T14) gates that run too, and `permissions` lists, in SELinux matrix v4 terms, what the case's probe needs "
               "beyond an enrolled host's policy. Its catalog names the contract "
               "rows (with the file each comes from) whose expected results W06 checks with the reference models while the "
               "case's probe runs. `probe` names the probe crate and case that inject the native fault, or `probeIn` the "
               "packet that brings them; a case with neither is judged by its catalog rows only. `verdicts` names the checks "
               "that judge the probe's timeline with W06's answer log, and `carries` the LEDGER-E09 properties the case "
               "carries (owner decision Q-T11) with the checks that observe each. In W06 a case is PASS only when its "
               "probe's faultResult is PASS in every run the case needs (one per peer for peer death/restart) and every verdict, "
               "catalog-row and carried-property check is PASS; it is FAIL "
               "when any of them fails, and NOT_RUN_ENV_UNAVAILABLE otherwise. A catalog row is checked in W06 when it is a "
               "vector (replayed through its reference model against the run's records) or a model rule (applied to the "
               "run's captures); spec-step and obligation rows are the basis the verdict and vector checks cite, not "
               "checks of their own. `harnessRestore` is what W06's harness does after every run, whether or not the "
               "probe ended.")
# Per native case: (probe crate, probe case) or None, the packet bringing a missing probe, the verdict checks, and the
# LEDGER-E09 properties it carries with the checks that observe each (Q-T11; authored here, checked against E09's own
# CARRIED table by the group tests).
FACTORIES = "fixed factories on an enrolled Linux host: construction and original deadlines over real kernel I/O"
PEER_RECHECKS = ("the peer's kernel rechecks on every inspection tick: its descriptors, SO_PEERCRED credentials, pidfd "
                 "liveness and the socket path")
INSPECTIONS = ("the inspections' construction past their first native read (kernel views, policy epoch retention, page "
               "size and the peer's role pins) and the BPF view's program ID recheck on cleanup")
NATIVE_CASES = {
    "TG-04": {
        "MATRIX:parent/FD spoof": (None, "CONF-ENF-005", [], {PEER_RECHECKS: [], INSPECTIONS: []}),
        "MATRIX:effective BPF ancestors": (None, "CONF-ENF-005", [], {INSPECTIONS: []}),
        "S8-KERNEL-FACTS": (None, "CONF-ENF-005", [], {INSPECTIONS: []}),
    },
    "TG-05": {
        "MATRIX:expiry with stalled Python": (("tg05_clocks", "expiry_with_stalled_python"), None, ["E08-STALLED"], {}),
        "MATRIX:suspend": (("tg05_clocks", "suspend"), None, ["E08-SUSPEND"], {}),
        "MATRIX:wall-clock rollback": (("tg05_clocks", "wall_clock_rollback"), None, ["E08-ROLLBACK"], {}),
        "MATRIX:peer death/restart": (("tg05_clocks", "peer_death_restart"), None,
                                      ["E07-GATE", "E07-READER-BROKER", "E09-INSPECTION-BROKER", "E07-READER-OBSERVER",
                                       "E09-INSPECTION-OBSERVER"],
                                      {PEER_RECHECKS: ["E07-READER-BROKER", "E07-READER-OBSERVER"],
                                       INSPECTIONS: ["E09-INSPECTION-BROKER", "E09-INSPECTION-OBSERVER"]}),
        "MATRIX:original deadlines": (("tg05_clocks", "original_deadlines"), None, ["E08-ORIGINAL", "E11-STALE", "E09-CONSTRUCTION"],
                                      {FACTORIES: ["E11-STALE", "E09-CONSTRUCTION"]}),
        "S8-FREEZE": (None, None, [], {}),
    },
}


NATIVE_REASON = ("W06_NATIVE_ONLY: native evidence on the enrolled AMD64 and ARM64 hosts in W06; the catalog fixes the "
                 "contract rows and obligation rows (owner decision Q-T13) whose expected results W06 checks")
PROBE_ROUTE = {"id": "D-PROBE-ROUTE", "decision": "Q-T14", "date": "2026-10-13",
               "text": "the W06 route by which the native probes inject their faults and observe under the enrolled policy "
                       "(decided in W06); it gates the W06 run of every TG-04 and TG-05 case, not the writing of its source. "
                       "Each report records the route and the policy digest; on an unmodified enrolled host the probes "
                       "report NOT_RUN with EACCES or EPERM."}
MATRIX = "architecture/selinux-matrix-v2/matrix.json"
# Per TG-05 probe case, what its probe needs, in SELinux matrix v4 terms: (class, permissions, target types or domains,
# the matrix assertions that decide it). A target "HOST_POLICY:<path>" is outside the matrix (host policy). The ledger adds
# `grantedTo`, the domains the matrix grants it to (an assertion's allow list, the process or capability table), so W06
# can see why an unmodified enrolled host refuses the probe. TG-04's come with its probes (CONF-ENF-005).
def _reads(cgroups, domains):
    """The path walks and reads every TG-05 probe makes: the cgroup files of `cgroups` and the /proc entries of
    `domains`, plus the host files outside the matrix (the cgroup root, the boot ID, the binding, the probe itself)."""
    return ([("dir", ["search"], ["HOST_POLICY:/sys/fs/cgroup", "HOST_POLICY:/proc", "HOST_POLICY:/proc/sys/kernel/random"], []),
             ("file", ["open", "read"], ["HOST_POLICY:/proc/sys/kernel/random/boot_id", "HOST_POLICY:the W06 binding file"], []),
             ("file", ["execute"], ["HOST_POLICY:the probe binary"], []),
             ("fd", ["use"], ["HOST_POLICY:the descriptors W06's harness passes the probe (its standard output)"], []),
             ("fifo_file", ["write", "append"], ["HOST_POLICY:the probe's standard output, when W06 pipes it"], []),
             ("file", ["write", "append"], ["HOST_POLICY:the probe's standard output, when W06 redirects it to a file"], []),
             ("dir", ["search"], ["planeon_cgroup_slice_t"] + cgroups, ["A38"]),
             ("file", ["open", "read"], cgroups, ["A39"])]
            + [row for domain in domains for row in (("dir", ["search"], [domain], []),
                                                     ("file", ["open", "read"], [domain], ["A59." + domain]))])


PERMISSIONS = {
    "MATRIX:expiry with stalled Python": _reads(["planeon_cgroup_delegate_t", "planeon_cgroup_server_t", "planeon_cgroup_worker_t"],
                                                ["planeon_server_t", "planeon_worker_t"])
        + [("process", ["sigstop", "signal"], ["planeon_server_t"], ["A57"]),
           ("process", ["sigstop", "signal"], ["planeon_worker_t"], []),
           ("capability", ["kill"], [], [])],
    "MATRIX:suspend": _reads(["planeon_cgroup_delegate_t", "planeon_cgroup_worker_t"], ["planeon_worker_t"])
        + [("dir", ["search"], ["HOST_POLICY:/sys", "HOST_POLICY:/sys/power", "HOST_POLICY:/sys/class", "HOST_POLICY:/sys/class/rtc",
                                "HOST_POLICY:the rtc0 device directory under /sys/devices"], []),
           ("lnk_file", ["read"], ["HOST_POLICY:/sys/class/rtc/rtc0"], []),
           ("file", ["open", "write"], ["HOST_POLICY:/sys/power/state", "HOST_POLICY:/sys/class/rtc/rtc0/wakealarm"], [])],
    "MATRIX:wall-clock rollback": _reads(["planeon_cgroup_delegate_t", "planeon_cgroup_worker_t"], ["planeon_worker_t"])
        + [("capability", ["sys_time"], [], [])],
    "MATRIX:peer death/restart": _reads(["planeon_cgroup_observer_t", "planeon_cgroup_delegate_t", "planeon_cgroup_broker_t",
                                         "planeon_cgroup_worker_t"], ["planeon_observer_t", "planeon_broker_t", "planeon_worker_t"])
        + [("process", ["sigkill"], ["planeon_observer_t", "planeon_broker_t"], ["A57"])],
    "MATRIX:original deadlines": _reads(["planeon_cgroup_server_t", "planeon_cgroup_delegate_t", "planeon_cgroup_worker_t"],
                                        ["planeon_server_t", "planeon_worker_t"])
        + [("process", ["sigkill"], ["planeon_server_t"], ["A57"])],
}
# CAP_KILL is listed only for the stalled case: SERVER, OBSERVER and BROKER run as uid 0 like the probe, so signalling them
# needs no capability; the worker runs as its signed uid (native v3 roles.WORKER.uid, minimum 10000), so stopping it does.
# What W06's harness must do after every run of a case, whether or not the probe ended (review D2-6).
HARNESS_RESTORE = {
    "MATRIX:expiry with stalled Python": "send SIGCONT to every process of the SERVER cgroup and the worker leaf",
    "MATRIX:suspend": "cancel the RTC wake alarm (write 0 to /sys/class/rtc/rtc0/wakealarm)",
    "MATRIX:wall-clock rollback": "set the wall clock again from the host's time source",
    "MATRIX:peer death/restart": "start the killed peer's unit again if it did not restart",
    "MATRIX:original deadlines": "start the SERVER unit again if it did not restart",
}


def granted_to(klass, perms, targets, assertions):
    """The domains SELinux matrix v4 grants a permission row to; None for a host-policy target outside the matrix."""
    if any(target.startswith("HOST_POLICY:") for target in targets):
        return None
    matrix = _models.data(MATRIX)
    if klass == "dir" and not assertions:
        # A domain's /proc entries: the procAccess pairs (the SELinux model reads them for file, dir and lnk_file).
        return sorted({row["domain"] for row in matrix["procAccess"] if row["target"] in targets})
    if assertions:
        rows = {row["id"]: row for row in matrix["assertions"]}
        return sorted(set().union(*(rows[ident]["allow"] for ident in assertions)))
    if klass == "process":
        return sorted({row["domain"] for perm in perms for row in matrix["process"][perm] if row["target"] in targets})
    if klass == "capability":
        return sorted(domain for domain, rows in matrix["capabilities"].items()
                      if all(any(row["capability"] == perm for row in rows) for perm in perms))
    raise ValueError("no grant table for " + klass)


def _native_case(group, tag):
    """A native case's probe fields; a TG-04 case not listed above gets its probe from CONF-ENF-005 and carries nothing."""
    default = (None, "CONF-ENF-005", [], {}) if group == "TG-04" else None
    probe, probe_in, verdicts, carries = NATIVE_CASES[group].get(tag, default)
    return {"probe": None if probe is None else {"crate": probe[0], "case": probe[1]}, "probeIn": probe_in,
            "verdicts": verdicts, "carries": [{"case": "LEDGER-E09", "property": name, "checks": checks}
                                              for name, checks in carries.items()],
            # Review D2-11: TG-04's permissions come with its probes, so they are not listed yet (null, not empty).
            "permissions": None if group == "TG-04" else [
                {"class": klass, "perms": perms, "targets": targets, "assertions": assertions,
                 "grantedTo": granted_to(klass, perms, targets, assertions)} for klass, perms, targets, assertions in PERMISSIONS.get(tag, [])],
            "permissionsIn": "CONF-ENF-005" if group == "TG-04" else None,
            "harnessRestore": HARNESS_RESTORE.get(tag)}


def ledger(group, offline):
    """The group's case ledger: the plan's cases with their phase, subject, result, properties, evidence and catalog.

    `offline` maps each W04_OFFLINE case's tag to its property table (fields PROPERTY_FIELDS).
    """
    plan_group = next(row for row in _models.data(PLAN)["testGroups"] if row["id"] == group)
    native = group in NATIVE_RULES
    selections = native_catalog(group) if native else catalog(group)
    fields = ("contract", "vectorSet", "source", "basis", "ids") if native else ("contract", "vectorSet", "basis", "ids")
    cases = []
    for case in plan_group["cases"]:
        mine = [{key: row[key] for key in fields} for row in selections if row["case"] == case["tag"]]
        properties = [{key: row[key] for key in PROPERTY_FIELDS} for row in offline.get(case["tag"], [])]
        if case["phase"] == "W04_OFFLINE":
            # Owner decision Q-T11 (2026-10-13): a property carried by named native cases of the plan is outside this
            # case's own scope; it stays NOT_RUN here and in the cases that carry it.
            gaps = [row for row in properties if row["result"] != "PASS" and not row["carriedBy"]]
            result = "PASS" if properties and not gaps else "NOT_RUN_ENV_UNAVAILABLE"
            # A gap is a property carried by no native case (TG-08's S44, owner decision Q-T20); gaps sharing a reason
            # state it once (review D1-12).
            reasons = {}
            for row in gaps:
                reasons.setdefault(row["reason"], []).append(row["property"])
            reason = None if result == "PASS" else ("partly not run: " if len(gaps) < len(properties) else "not run: ") + "; ".join(
                "%s (%s)" % ("; ".join(names), why) for why, names in reasons.items())
        else:
            result = "NOT_RUN_ENV_UNAVAILABLE"
            blockers = case["blockedBy"] + ([PROBE_ROUTE["id"]] if native else [])
            reason = (NATIVE_REASON if native else REASONS[case["phase"]]) + "".join("; blocked by " + blocker for blocker in blockers)
        evidence = sorted({test for row in properties if row["result"] == "PASS" for test in row["tests"]})
        row = {"tag": case["tag"], "phase": case["phase"], "obligations": case["obligations"],
               "blockedBy": case["blockedBy"] + ([PROBE_ROUTE["id"]] if native else []),
               "subject": CASE_SUBJECTS.get((group, case["tag"]), SUBJECTS[case["phase"]]), "result": result, "reason": reason, "properties": properties,
               "evidence": evidence, "catalog": mine, "vectors": sum(len(row["ids"]) for row in mine)}
        if native:
            row.update(_native_case(group, case["tag"]))
        if group in PARTS:
            row["part"] = PARTS[group](case)
        cases.append(row)
    value = {"schemaVersion": "r12.enforcement-tg-case-ledger/v1", "packet": PACKETS[group], "testGroup": group,
             "evidenceClass": plan_group["evidenceClass"], "rule": GROUP_RULES.get(group, NATIVE_RULE if native else RULE),
             "cases": cases}
    if native:
        value["blockers"] = [PROBE_ROUTE]
    return value
