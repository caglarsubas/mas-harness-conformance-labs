#!/usr/bin/env python3
"""SELinux domain, type, boolean and permission matrix v4 (W02e-F): closed data and its evaluator.

The W02e-F successor of `selinux_matrix` (matrix v3, adopted and frozen). The evaluator is unchanged; only the
matrix version differs. The v4 matrix answers the W02e round-3 findings K2, K3, K4 and K6 in its data and text.

DATA_CHECK_ONLY reference model for the planeon and qualification-backend SELinux policy the reviewed
W01 design selects (HOST-INTERFACE-DRAFT-002 sections 2.1 P1/P2/P4/P5/P9, 2.3, 4.1-4.3, 5.1-5.5) and
the W02a v2 record leaves to W02e (label slots and the confined backend types).

- `allowed` answers one access question (state, source domain, target, class, permission) from the
  matrix: True or False where the matrix is closed, None outside it.
- `check_matrix` checks that the matrix is closed and well formed: every domain, type, boolean, class
  and permission is declared, every reference resolves, and every label is a well-formed context.
- `failed_assertions` evaluates the deny properties derived from W01 in every listed boot state and
  returns the ones that do not hold.
- `w02a_slots` derives the label values the W02a v2 record leaves open.

It is not a policy module, a compiled policy or an observation of a host.
"""
from __future__ import annotations

import copy
import re
from typing import Any

MATRIX_VERSION = "planeon.internal.selinux-matrix/v4"
BOOLEANS = ("planeon_containment_enabled", "planeon_maintenance_mode", "secure_mode_policyload")
STATES = ("ENROLLED_CONTAINMENT", "ENROLLED_SEALED", "MAINTENANCE_BOOT")
DOMAIN_KINDS = ("RESIDENT_ROLE", "LIFECYCLE", "MAINTENANCE", "BACKEND", "CONTAINER", "ADMIN", "SYSTEM")
# Transitions into these kinds (the admin login, systemd) are outside the matrix: the host's login and boot
# policy (pam_selinux, kernel_t to init_t) defines them.
OPEN_ENTRY_KINDS = ("ADMIN", "SYSTEM")
TYPE_CATEGORIES = ("ENTRYPOINT", "INTERPRETER", "SEALED_CONFIG", "UNIT_FILE", "CREDENTIAL", "SOCKET_FILE",
                   "CGROUP", "BPF_PIN", "BOOLEAN_FILE", "SEAL_MARKER", "JOURNAL", "RUNTIME_DIR", "DATA", "CONTAINER_FILE")
# Types labelled by genfscon path rules: cgroup2, bpffs and selinuxfs. kernfs (cgroup2) supports security xattrs, but no
# planeon cgroup node carries one (the root has none and nothing relabels), so their labels come from the path rules,
# applied when a node is instantiated, and a named type transition under such a parent never fires (v6.12
# selinux_kernfs_init_security returns without labelling when the parent has no xattr; review K4).
GENFS_CATEGORIES = ("CGROUP", "BPF_PIN", "BOOLEAN_FILE")
GENFS_FILESYSTEMS = {"CGROUP": "cgroup2", "BPF_PIN": "bpf", "BOOLEAN_FILE": "selinuxfs"}
# Parents outside the matrix that a named type transition may use: the host's /run (refpolicy var_run_t, tmpfs).
EXTERNAL_PARENTS = ("var_run_t",)
PUBLIC_READ = ("ENTRYPOINT", "INTERPRETER", "SEALED_CONFIG", "UNIT_FILE", "BOOLEAN_FILE")
FILE_CLASSES = ("file", "dir", "sock_file", "lnk_file")
# Every file-class permission (Linux v6.12 security/selinux/include/classmap.h) in exactly one access group.
FILE_PERMS = {
    "READ": ("read", "open", "getattr", "map", "ioctl", "lock", "search", "watch", "watch_reads", "watch_mount",
             "watch_sb", "watch_with_perm", "audit_access"),
    "WRITE": ("write", "append", "create", "unlink", "link", "rename", "setattr", "add_name", "remove_name",
              "rmdir", "reparent", "mounton", "quotaon"),
    "RELABEL": ("relabelfrom", "relabelto"),
    "EXECUTE": ("execute",),
    "EXECUTE_NO_TRANS": ("execute_no_trans",),
    "EXECMOD": ("execmod",),
    "ENTRYPOINT": ("entrypoint",),
}
ACCESS_GROUPS = tuple(FILE_PERMS)
CAPABILITY = ("chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
              "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
              "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
              "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap")
CAPABILITY2 = ("mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
               "checkpoint_restore")
CAP_CLASSES = {"capability": CAPABILITY, "capability2": CAPABILITY2, "cap_userns": CAPABILITY, "cap2_userns": CAPABILITY2}
# The closed process permissions; every other process permission is outside the matrix.
PROCESS_PERMS = ("transition", "dyntransition", "setexec", "ptrace", "execmem", "execstack", "execheap", "setsockcreate",
                 "getattr", "sigkill", "sigstop", "signal")
PROCESS2_PERMS = ("nnp_transition", "nosuid_transition")
SOCKET_PERMS = ("connectto", "create", "bind", "listen", "accept")
PORT_PERMS = ("name_bind", "name_connect")
BPF_PERMS = ("prog_load", "prog_run", "map_create", "map_read", "map_write")
SECURITY_PERMS = ("setbool", "load_policy", "setenforce")
SERVICE_PERMS = ("start", "stop", "reload", "status", "enable", "disable")
SECURITY_OBJECT = "security_t"
OTHER_DOMAIN = "OTHER_DOMAIN"      # any domain the matrix does not declare
ANY_DOMAIN = "ANY_DOMAIN"          # a grant to every domain (public, non-secret reads only)
CONTEXT = re.compile(r"^system_u:(system_r|object_r):([a-z0-9_]+_t):s0$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def holds(when: dict | None, booleans: dict) -> bool:
    return when is None or all(booleans[name] == value for name, value in when.items())


def granted(entries: list, domain: str, booleans: dict) -> bool:
    return any(e["domain"] in (domain, ANY_DOMAIN) and holds(e.get("when"), booleans) for e in entries)


def _pair(entries: list, source: str, target: str, booleans: dict) -> bool:
    return any(e["domain"] == source and e["target"] == target and holds(e.get("when"), booleans) for e in entries)


def _index(matrix: dict) -> tuple[dict, dict, dict, dict]:
    domains = {d["name"]: d for d in matrix["domains"]}
    types = {t["name"]: t for t in matrix["types"]}
    sockets = {s["object"]: s for s in matrix["sockets"]}
    ports = {p["type"]: p for p in matrix["ports"]}
    return domains, types, sockets, ports


def _source_closed(matrix: dict, source: str, cls: str, perm: str) -> bool:
    return any(c["domain"] == source and c["class"] == cls and perm in c["perms"] for c in matrix["sourceClosures"])


def allowed(matrix: dict, state: str, source: str, target: str, cls: str, perm: str) -> bool | None:
    """One access decision: True or False where the matrix is closed, None outside it."""
    booleans = matrix["states"][state]
    domains, types, sockets, ports = _index(matrix)
    if cls in FILE_CLASSES:
        group = next((g for g, perms in FILE_PERMS.items() if perm in perms), None)
        if group is None:
            return None
        if target in domains:
            # /proc/<pid> of another process: its entries carry the target's label. A domain's own entries are
            # outside the matrix. Ptrace-gated entries (exe, fd, environ, mem) also need the kernel's commoncap and
            # uid rules, which no role can satisfy towards a more privileged or other-uid peer.
            if target == source:
                return None
            return group == "READ" and cls in ("file", "dir", "lnk_file") and _pair(matrix["procAccess"], source, target, booleans)
        if target not in types:
            return False if _source_closed(matrix, source, cls, perm) else None
        entry = types[target]
        return cls in entry["classes"] and granted(entry["access"].get(group, []), source, booleans)
    if cls in CAP_CLASSES:
        if perm not in CAP_CLASSES[cls]:
            return None
        if source not in domains:
            return None              # capabilities of undeclared host domains are outside the matrix
        return target == source and any(c["class"] == cls and c["capability"] == perm and holds(c.get("when"), booleans)
                                        for c in matrix["capabilities"].get(source, []))
    if cls == "process":
        if perm not in PROCESS_PERMS:
            return None
        if target not in domains:
            return None
        if perm == "transition":
            if domains[target]["kind"] in OPEN_ENTRY_KINDS:
                return None
            return any(_effective(matrix, t, booleans) for t in matrix["transitions"]
                       if t["from"] == source and t["to"] == target)
        if perm == "getattr":
            return None if target == source else _pair(matrix["procAccess"], source, target, booleans)
        if perm in ("setexec", "setsockcreate", "execmem", "execstack", "execheap"):
            # Checked on the caller itself; the destination of setexec is still bound by transition.
            return target == source and granted(matrix["process"][perm], source, booleans)
        return _pair(matrix["process"][perm], source, target, booleans)
    if cls == "process2":
        if perm not in PROCESS2_PERMS:
            return None
        return target in domains and _pair(matrix["process2"][perm], source, target, booleans)
    if cls == "unix_stream_socket":
        if perm not in SOCKET_PERMS:
            return None
        if target not in sockets:
            return False if perm == "connectto" and _source_closed(matrix, source, cls, perm) else None
        sock = sockets[target]
        if perm == "connectto":
            return granted(sock["connect"], source, booleans)
        return source == sock["listener"]
    if cls == "tcp_socket":
        if perm not in PORT_PERMS:
            return None
        if target not in ports:
            return False if _source_closed(matrix, source, cls, perm) else None
        entries = ports[target]["bind" if perm == "name_bind" else "connect"]
        if _source_closed(matrix, source, cls, perm):
            # A closed source needs an explicit grant; a grant to every domain does not reach it.
            entries = [e for e in entries if e["domain"] != ANY_DOMAIN]
        return granted(entries, source, booleans)
    if cls == "bpf":
        if perm not in BPF_PERMS:
            return None
        if perm == "prog_run":
            # A program carries its loader's label; even the loader needs prog_run on it to get the descriptor.
            return any(e["domain"] == source and e["object"] == target and holds(e.get("when"), booleans)
                       for e in matrix["bpf"]["prog_run"])
        return target == source and granted(matrix["bpf"][perm], source, booleans)
    if cls == "security":
        if perm not in SECURITY_PERMS:
            return None
        return target == SECURITY_OBJECT and granted(matrix["security"][perm], source, booleans)
    if cls == "service":
        if perm not in SERVICE_PERMS or target not in types or types[target]["category"] != "UNIT_FILE":
            return None
        return any(e["domain"] == source and target in e["units"] and holds(e.get("when"), booleans)
                   for e in matrix["service"][perm])
    return None


def _effective(matrix: dict, t: dict, booleans: dict) -> bool:
    """A transition needs the rule, file execute for the source, file entrypoint for the target, and, when the
    caller has set no_new_privs first, process2 nnp_transition (policy capability nnp_nosuid_transition)."""
    types = {x["name"]: x for x in matrix["types"]}
    entry = types[t["via"]]["access"]
    return (holds(t.get("when"), booleans) and granted(entry.get("EXECUTE", []), t["from"], booleans)
            and granted(entry.get("ENTRYPOINT", []), t["to"], booleans)
            and (not t.get("noNewPrivs") or _pair(matrix["process2"]["nnp_transition"], t["from"], t["to"], booleans)))


def check_matrix(matrix: dict) -> None:
    """Closed and well formed: every name declared once, every reference resolved, every label a context."""
    require(type(matrix) is dict and set(matrix) == {
        "schemaVersion", "policyCapabilities", "booleans", "states", "domains", "types", "transitions", "typeTransitions",
        "genfscon", "capabilities", "sockets", "ports", "bpf", "security", "process", "process2", "procAccess",
        "sourceClosures", "service", "assertions"} and matrix["schemaVersion"] == MATRIX_VERSION, "closed matrix")
    require(set(matrix["booleans"]) == set(BOOLEANS) and set(matrix["states"]) == set(STATES)
            and all(set(v) == set(BOOLEANS) and all(x in (0, 1) for x in v.values()) for v in matrix["states"].values()),
            "closed booleans and states")
    # A socket object is a type of its own (set by the listener with setsockcreate) or the listener's domain.
    names = [d["name"] for d in matrix["domains"]] + [t["name"] for t in matrix["types"]] + \
        [s["object"] for s in matrix["sockets"] if s["object"] != s["listener"]] + [p["type"] for p in matrix["ports"]]
    require(len(names) == len(set(names)) and not {OTHER_DOMAIN, ANY_DOMAIN} & set(names), "every domain and type declared once")
    domains, types, sockets, ports = _index(matrix)
    require(all(d["kind"] in DOMAIN_KINDS and set(d) == {"name", "kind", "subject", "label"} for d in matrix["domains"]),
            "closed domain rows")
    for d in matrix["domains"]:
        m = CONTEXT.match(d["label"])
        require(m is not None and m.group(1) == "system_r" and m.group(2) == d["name"], "process context of " + d["name"])
        # W02a round-2 N1: backend components and qualification Pods run only in the confined qualk8s types this
        # matrix defines; upstream unconfined or privileged types (kubelet_t, container_runtime_t, spc_t,
        # unconfined_t, ...) cannot appear, because every domain name is fixed by its kind.
        prefix = {"BACKEND": "qualk8s_", "CONTAINER": "qualk8s_"}.get(d["kind"], "planeon_")
        require(d["name"] == "init_t" if d["kind"] == "SYSTEM" else d["name"].startswith(prefix),
                "domain name fixed by its kind: " + d["name"])

    def known(entries, what, public=False):
        for e in entries:
            require((e["domain"] in domains or (public and e["domain"] == ANY_DOMAIN))
                    and set(e.get("when") or {}) <= set(BOOLEANS), what + ": " + str(e))

    for t in matrix["types"]:
        require(set(t) == {"name", "category", "label", "classes", "access"} and t["category"] in TYPE_CATEGORIES
                and set(t["classes"]) <= set(FILE_CLASSES) and t["classes"] and set(t["access"]) <= set(ACCESS_GROUPS),
                "closed type row " + t["name"])
        m = CONTEXT.match(t["label"])
        require(m is not None and m.group(1) == "object_r" and m.group(2) == t["name"], "object context of " + t["name"])
        for group, entries in t["access"].items():
            # Only READ of a non-secret type may be granted to every domain.
            known(entries, "type " + t["name"], public=group == "READ" and t["category"] in PUBLIC_READ)
        if t["category"] in GENFS_CATEGORIES:
            # No relabel on a genfs-only filesystem, and exactly one genfscon rule gives the type.
            require(not t["access"].get("RELABEL") and [g["type"] for g in matrix["genfscon"]].count(t["name"]) == 1,
                    "genfs-labelled type needs one genfscon rule and no relabel: " + t["name"])
    for s in matrix["sockets"]:
        require(set(s) == {"object", "listener", "file", "connect"} and s["listener"] in domains and s["file"] in types
                and types[s["file"]]["category"] == "SOCKET_FILE", "socket " + s["object"])
        known(s["connect"], "socket " + s["object"])
        if s["object"] != s["listener"]:
            require(granted(matrix["process"]["setsockcreate"], s["listener"], {b: 0 for b in BOOLEANS}),
                    "a socket type of its own needs the listener's setsockcreate: " + s["object"])
    for p in matrix["ports"]:
        require(set(p) == {"type", "label", "bind", "connect"} and CONTEXT.match(p["label"])
                and CONTEXT.match(p["label"]).group(2) == p["type"], "port context " + p["type"])
        known(p["bind"], "port " + p["type"])
        known(p["connect"], "port " + p["type"], public=True)   # a listener may accept connections from any domain
    for t in matrix["transitions"]:
        require(t["to"] not in domains or domains[t["to"]]["kind"] not in OPEN_ENTRY_KINDS,
                "transition into a host-policy domain is outside the matrix: %s -> %s" % (t["from"], t["to"]))
        require(set(t) <= {"from", "to", "via", "when", "noNewPrivs"} and t["from"] in domains and t["to"] in domains
                and t["via"] in types
                and types[t["via"]]["category"] in ("ENTRYPOINT", "CONTAINER_FILE") and set(t.get("when") or {}) <= set(BOOLEANS),
                "transition %s -> %s via %s needs an entrypoint type" % (t["from"], t["to"], t["via"]))
    for t in matrix["transitions"]:
        require(any(_effective(matrix, t, matrix["states"][state]) for state in STATES),
                "transition %s -> %s via %s is never effective" % (t["from"], t["to"], t["via"]))
    for r in matrix["typeTransitions"]:
        require(set(r) == {"source", "parent", "class", "name", "new"} and r["source"] in domains
                and r["new"] in types and r["class"] in FILE_CLASSES and r["class"] in types[r["new"]]["classes"]
                and types[r["new"]]["category"] not in GENFS_CATEGORIES, "type transition " + str(r))
        require(r["parent"] not in types or types[r["parent"]]["category"] not in GENFS_CATEGORIES,
                "type transition under a genfs-labelled parent never fires: " + str(r))
        # The parent is a declared xattr-labelled type the source may write, or the host's /run for systemd.
        require((r["parent"] in types and any(granted(types[r["parent"]]["access"].get("WRITE", []), r["source"],
                                                       matrix["states"][state]) for state in STATES))
                or (r["parent"] in EXTERNAL_PARENTS and domains[r["source"]]["kind"] == "SYSTEM"), "type transition " + str(r))
    paths = [(g["fs"], g["path"]) for g in matrix["genfscon"]]
    require(len(paths) == len(set(paths)), "genfscon paths unique")
    for g in matrix["genfscon"]:
        require(set(g) == {"fs", "path", "type"} and g["type"] in types and g["path"].startswith("/")
                and g["fs"] == GENFS_FILESYSTEMS.get(types[g["type"]]["category"]), "genfscon " + str(g))
    for domain, caps in matrix["capabilities"].items():
        require(domain in domains and all(set(c) <= {"class", "capability", "when"} and c["class"] in CAP_CLASSES
                                          and c["capability"] in CAP_CLASSES[c["class"]] for c in caps), "capabilities of " + domain)
    require(set(matrix["bpf"]) == set(BPF_PERMS) and set(matrix["security"]) == set(SECURITY_PERMS)
            and set(matrix["process"]) == set(PROCESS_PERMS) - {"transition", "getattr"}
            and set(matrix["process2"]) == set(PROCESS2_PERMS) and set(matrix["service"]) == set(SERVICE_PERMS),
            "closed class tables")
    for perm in BPF_PERMS:
        known(matrix["bpf"][perm], "bpf " + perm)
    for perm in SECURITY_PERMS:
        known(matrix["security"][perm], "security " + perm)
    for table in (matrix["process"], matrix["process2"]):
        for perm, entries in table.items():
            known(entries, "process " + perm)
            require(all(e.get("target", e["domain"]) in domains for e in entries), "process target " + perm)
    known(matrix["procAccess"], "procAccess")
    require(all(e["target"] in domains and e["target"] != e["domain"] for e in matrix["procAccess"]), "procAccess targets")
    for c in matrix["sourceClosures"]:
        require(set(c) == {"domain", "class", "perms"} and c["domain"] in domains
                and ((c["class"] == "tcp_socket" and set(c["perms"]) <= set(PORT_PERMS))
                     or (c["class"] == "unix_stream_socket" and c["perms"] == ["connectto"])
                     or (c["class"] == "file" and c["perms"] == ["execute_no_trans"])), "source closure " + str(c))
    for perm in SERVICE_PERMS:
        known(matrix["service"][perm], "service " + perm)
        require(all(set(e["units"]) <= {t for t in types if types[t]["category"] == "UNIT_FILE"} for e in matrix["service"][perm]),
                "service units " + perm)


def _sources(matrix: dict, spec: Any) -> list[str]:
    declared = [d["name"] for d in matrix["domains"]]
    if spec == "ALL":
        return declared + [OTHER_DOMAIN]
    if spec == "DECLARED":
        return declared
    return list(spec)


def failed_assertions(matrix: dict) -> list[str]:
    """Every assertion is a deny property: for each listed state, no listed source outside `allow` gets the
    access on any listed target. Returns the identifiers of assertions that do not hold."""
    failed = []
    for a in matrix["assertions"]:
        ok = True
        for state in a["states"]:
            for target in a["targets"]:
                for source in _sources(matrix, a["sources"]):
                    if source in a["allow"]:
                        continue
                    for perm in a["perms"]:
                        result = allowed(matrix, state, source, source if target == "SELF" else target, a["class"], perm)
                        # A domain's own /proc entries are outside the matrix by design, not a breach.
                        own_proc = (result is None and target == source and a["class"] in FILE_CLASSES)
                        if result is not False and not own_proc:
                            ok = False
        if not ok:
            failed.append(a["id"])
    return failed


def apply_ops(value: Any, ops: list) -> Any:
    """A copy of `value` with closed path operations applied (set, delete, append); used by mutation vectors."""
    value = copy.deepcopy(value)
    for op in ops:
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        elif op["op"] == "append":
            node[last].append(copy.deepcopy(op["value"]))
        else:
            require(op["op"] == "delete", "closed mutation operation")
            del node[last]
    return value


def w02a_slots(matrix: dict) -> dict:
    """The label values the W02a v2 record leaves open: role cgroups, bpffs pins and the seal marker."""
    types = {t["name"]: t for t in matrix["types"]}
    cgroup = {"SERVER": "planeon_cgroup_server_t", "OBSERVER": "planeon_cgroup_observer_t", "BROKER": "planeon_cgroup_broker_t",
              "WORKER": "planeon_cgroup_worker_t", "EFFECT_GATE": "planeon_cgroup_gate_t"}
    return {"roleCgroupLabels": {role: types[name]["label"] for role, name in cgroup.items()},
            "bpfPinLabel": types["planeon_bpf_pin_t"]["label"],
            "sealMarkerLabel": types["planeon_seal_t"]["label"]}
