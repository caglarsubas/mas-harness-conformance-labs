#!/usr/bin/env python3
"""v3 native qualification record: expected/native-capture DATA consistency only.

Reference model for `planeon.internal.native-qualification/v3` (profile
SELINUX_FSVERITY_CGROUP_BPF_V3), the W02a-F successor of the adopted v2 contract. It
never inspects a kernel, never mints a native handle and never grants authority; every
result is DATA_CHECK_ONLY. The v1 and v2 schemas, vectors and models are unchanged.

`check_*` functions raise with the first refused rule. A single check is NOT an
acceptance decision: only `check_qualification` combines the record, one capture per
resident role, the lifecycle capture (containment absence, planeon-slice census and own
members, host-wide planeon process counts), one observation per backend component and the
earlier-version (v1 and v2) migration rules for one boot and validity window. A record whose implementation
profile is test-only qualifies only when the caller asks for a test fixture.

Caller obligations (not checked here):
- `profile` is already valid under the pinned proxy profile contract
  (`scripts/validate_proxy_contract.py`, `validate_profile`); this model only adds the
  binding-nonce label rule and the earlier-version nonce scan;
- `v1_records` and `v2_records` are the host's complete retained v1 and v2 enrollment
  histories, or `no_earlier_history` is set because both are attested empty;
- inspectors report a per-process field only when it holds for every thread
  (`threadsUniform`), and read a role cgroup's members, thread counts and pids.current
  while it is frozen and holds no unreaped task. The inspector freezes through an ancestor
  it controls, or reads while the broker holds the probe-worker leaf frozen; it never
  writes the broker-owned leaf's cgroup.freeze.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Any

import jsonschema

SCHEMA_SHA256 = "1c7930351e58a12cdf8bf8ef0df1f971eddceb8d17268f73541425258e9657d2"
V1_SCHEMA_SHA256 = "8e184d60df63863bc627c1655887c32012490e3c7211f8f9a38baee67f64d4cf"
V2_SCHEMA_SHA256 = "fd1657c9a9ea437df2d48f03c69a1de62013a47a9fc62ad7776db2fc7029c0c5"
V3_RECORD = ("planeon.internal.native-qualification/v3", "SELINUX_FSVERITY_CGROUP_BPF_V3")
V3_CAPTURE = "planeon.internal.native-qualification-capture/v3"
V3_LIFECYCLE = "planeon.internal.native-qualification-lifecycle/v3"
V3_BACKEND = "planeon.internal.native-qualification-backend/v3"
SEAL_VERSION = "planeon.internal.containment-seal/v1"
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
SINGLE_PROCESS_ROLES = ("SERVER", "OBSERVER", "BROKER", "EFFECT_GATE")
LIFECYCLE = ("HOST_CONTAINMENT", "POLICY_WRITER")
HOOKS = ("INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT",
         "UDP4_SENDMSG", "UDP6_SENDMSG")
HOOK_DIRS = {hook: hook.lower().replace("_", "-") for hook in HOOKS}
ROLE_DIRS = {"SERVER": "proxy-server", "OBSERVER": "policy-observer", "BROKER": "capacity-broker",
             "WORKER": "probe-worker", "EFFECT_GATE": "effect-gate"}
DELEGATED_CHILDREN = ["broker", "probe-worker"]
BROKER_SERVICE = "/sys/fs/cgroup/planeon.slice/planeon-capacity-broker.service"
# Native-only roles may list nothing from the enrolled interpreter's installation tree (round 2, W4).
INTERPRETER_TREE = "/opt/planeon/python/"
# Closed kernel command-line grammar (rounds 5-6, R4-1, R5-1). Every word of the enrolled entry is one of these kernel
# parameters, none of which names, adds, masks or overrides a systemd unit or passes init arguments: "--" and every
# later word, systemd.*, rd.* and SYSTEMD_* words, runlevel words, root mount options (rootflags= carries
# x-systemd.* dependencies), console= (getty-generator adds a serial getty) and every other word are refused. The
# maintenance entry is the enrolled entry plus MAINTENANCE_UNIT once, so both boot the same initramfs and root. The
# grammar is widened only through a reviewed revision of this contract.
KERNEL_PARAMETERS = tuple(re.compile(pattern) for pattern in (
    r"initrd=[A-Za-z0-9_./\\+-]+", r"root=(UUID|PARTUUID|LABEL)=[A-Za-z0-9_.-]+", r"root=/dev/[A-Za-z0-9_/.-]+",
    r"ro", r"rw", r"security=selinux", r"selinux=1", r"enforcing=1", r"lockdown=integrity", r"quiet",
    r"loglevel=[0-7]"))
MAINTENANCE_UNIT = "systemd.unit=planeon-maintenance.target"
PIN_ROOT = "/sys/fs/bpf/planeon"
CGROUP_ROOT = "/sys/fs/cgroup"
SLICE = CGROUP_ROOT + "/planeon.slice"
REQUIRED_BACKEND = ("APISERVER", "DATASTORE", "CONTROLLER_MANAGER", "SCHEDULER", "KUBELET", "CONTAINER_RUNTIME")
NO_API_CLIENT = ("DATASTORE", "CONTAINER_RUNTIME")
ROLE_DOMAINS = {"SERVER": "planeon_server_t", "OBSERVER": "planeon_observer_t", "BROKER": "planeon_broker_t",
                "WORKER": "planeon_worker_t", "EFFECT_GATE": "planeon_gate_t"}
# Every cgroup BPF attach type of Linux v6.12 (to_cgroup_bpf_attach_type plus BPF_LSM_CGROUP); the seven containment
# hooks are observed per hook, and the effective census covers the rest.
HOOK_ATTACH_TYPES = tuple("BPF_CGROUP_" + hook for hook in HOOKS)
CENSUS_ATTACH_TYPES = ("BPF_CGROUP_INET_INGRESS", "BPF_CGROUP_INET_EGRESS", "BPF_CGROUP_SOCK_OPS", "BPF_CGROUP_DEVICE",
                       "BPF_CGROUP_UNIX_CONNECT", "BPF_CGROUP_INET4_POST_BIND", "BPF_CGROUP_INET6_POST_BIND",
                       "BPF_CGROUP_UNIX_SENDMSG", "BPF_CGROUP_SYSCTL", "BPF_CGROUP_UDP4_RECVMSG",
                       "BPF_CGROUP_UDP6_RECVMSG", "BPF_CGROUP_UNIX_RECVMSG", "BPF_CGROUP_GETSOCKOPT",
                       "BPF_CGROUP_SETSOCKOPT", "BPF_CGROUP_INET4_GETPEERNAME", "BPF_CGROUP_INET6_GETPEERNAME",
                       "BPF_CGROUP_UNIX_GETPEERNAME", "BPF_CGROUP_INET4_GETSOCKNAME", "BPF_CGROUP_INET6_GETSOCKNAME",
                       "BPF_CGROUP_UNIX_GETSOCKNAME", "BPF_CGROUP_INET_SOCK_RELEASE", "BPF_LSM_CGROUP")
MAX_BYTES = 262144
PLANEON_CODE_BYTES = 536870912
BACKEND_CODE_BYTES = 4294967296
TIME = "%Y-%m-%dT%H:%M:%SZ"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _bounded(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    budget = [MAX_BYTES] if budget is None else budget
    require(depth <= 16, "depth exceeded")
    kind = type(value)
    require(kind in (dict, list, str, int, bool, type(None)), "non-data value")
    budget[0] -= len(value) if kind is str else 1
    require(budget[0] >= 0, "size exceeded")
    if kind is int:
        require(abs(value) <= 9007199254740991, "integer overflow")
    elif kind is str:
        require(all(32 <= ord(char) <= 126 for char in value), "ASCII data required")
    elif kind is dict:
        for key, item in value.items():
            require(type(key) is str, "string key required")
            _bounded(key, depth + 1, budget)
            _bounded(item, depth + 1, budget)
    elif kind is list:
        for item in value:
            _bounded(item, depth + 1, budget)


def schema_errors(value: Any, schema: dict, variant: str) -> list:
    validator = jsonschema.Draft202012Validator({"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]})
    return list(validator.iter_errors(value))


def _shape(value: Any, variant: str, schema: dict) -> None:
    require(digest(canonical(schema)) == SCHEMA_SHA256, "unreviewed v3 qualification schema")
    _bounded(value)
    require(len(canonical(value)) <= MAX_BYTES, "bounded qualification data")
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    if error is not None:
        raise error


def _path(path: str) -> None:
    require(type(path) is str and path.startswith("/")
            and all(part not in ("", ".", "..") for part in path[1:].split("/")), "canonical installed path")


def _moment(value: str) -> datetime:
    moment = datetime.strptime(value, TIME)
    require(moment.strftime(TIME) == value, "canonical UTC time")
    return moment


def _within(record: dict, observed: str, message: str) -> None:
    now = _moment(observed)
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(start <= now < end, message)


def _strings(value: Any) -> list[str]:
    if type(value) is str:
        return [value]
    if type(value) is dict:
        return [s for key, item in value.items() for s in [key] + _strings(item)]
    if type(value) is list:
        return [s for item in value for s in _strings(item)]
    return []


def _same_set(observed: list, enrolled: list) -> bool:
    return len(set(observed)) == len(observed) and sorted(observed) == sorted(enrolled)


def _endpoint_rows(rows: list) -> dict:
    require(type(rows) is list and 1 <= len(rows) <= 16, "bounded signed endpoints")
    by_id, tuples = {}, set()
    for row in rows:
        require(type(row) is dict and set(row) == {"endpointId", "kind", "addressFamily", "ipAddress", "port"}
                and row["endpointId"] not in by_id, "unique closed endpoint tuples")
        ip = ipaddress.ip_address(row["ipAddress"])
        require(str(ip) == row["ipAddress"] and not ip.is_unspecified and not ip.is_multicast
                and not (ip.version == 6 and (ip.ipv4_mapped is not None or ip.scope_id is not None)),
                "fixed canonical numeric endpoint")
        require(row["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
                and row["kind"] in ("CAMPAIGN_PROXY", "KUBERNETES_API_PROXY")
                and type(row["port"]) is int and 1 <= row["port"] <= 65535, "endpoint family/type")
        require((row["ipAddress"], row["port"]) not in tuples, "duplicate signed endpoint tuple")
        tuples.add((row["ipAddress"], row["port"]))
        by_id[row["endpointId"]] = row
    return by_id


def expected_seal_digest(record: dict) -> str:
    """Marker content: boot, active policy, containment artifact and every (role, hook, program) assignment."""
    programs = sorted([role, hook, record["roles"][role]["bpfPrograms"][hook]["programId"],
                       record["roles"][role]["bpfPrograms"][hook]["translatedSha256"]] for role in ROLES for hook in HOOKS)
    content = {"schemaVersion": SEAL_VERSION, "bootId": record["host"]["bootId"],
               "policyDigest": record["selinux"]["policyDigest"],
               "containmentArtifactDigest": record["lifecycleSubjects"]["HOST_CONTAINMENT"]["artifactDigest"],
               "programs": programs}
    return "sha256:" + digest(canonical(content))


class _Owners:
    """Code ownership by path and by content digest; one owner class per byte string."""

    def __init__(self) -> None:
        self.by_path: dict[str, str] = {}
        self.by_sha256: dict[str, str] = {}
        self.by_verity: dict[str, str] = {}

    def own(self, paths: list, rows: dict, owner: str, executable: str, artifact: str, interpreter: str | None) -> None:
        require(set(paths) <= set(rows) and executable in paths and rows[executable]["sha256"] == artifact,
                "artifact custody")
        if interpreter is not None:
            require(interpreter in paths, "interpreter not enrolled")
        loaded = interpreter or executable
        require(rows[loaded]["mode"] == "0555" and rows[loaded]["executableSegments"], "actual executable missing")
        for path in paths:
            for table, key in ((self.by_path, path), (self.by_sha256, rows[path]["sha256"]),
                               (self.by_verity, rows[path]["verityDigest"])):
                previous = table.setdefault(key, owner)
                if previous != owner:
                    require(not {previous, owner} <= set(LIFECYCLE), "lifecycle subjects share code")
                    require(False, "code shared across owner classes")


def check_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> None:
    """Expected-data consistency of one v3 record; raises with the first refused rule."""
    require(type(record) is dict and (record.get("schemaVersion"), record.get("qualificationProfile")) == V3_RECORD,
            "not a v3 record")
    _shape(record, "record", schema)
    require(record["profileDigest"] == "sha256:" + digest(canonical(profile)), "profile substitution")
    entries = record["bootEntries"]
    require(entries["ENROLLED"]["entryId"] != entries["MAINTENANCE"]["entryId"]
            and entries["ENROLLED"]["kernelCmdline"] != entries["MAINTENANCE"]["kernelCmdline"],
            "enrolled and maintenance boot entries indistinguishable")
    enrolled, maintenance = (entries[name]["kernelCmdline"].split(" ") for name in ("ENROLLED", "MAINTENANCE"))
    require(all(_kernel_parameter(word) for word in enrolled), "enrolled boot entry outside the closed kernel parameters")
    require("lockdown=integrity" in enrolled, "enrolled boot entry without lockdown=integrity")
    require(all(_kernel_parameter(word) or word == MAINTENANCE_UNIT for word in maintenance),
            "maintenance boot entry outside the closed kernel parameters")
    require(MAINTENANCE_UNIT in maintenance, "maintenance boot entry does not select the maintenance target")
    require(maintenance.count(MAINTENANCE_UNIT) == 1, "maintenance boot entry names the maintenance target twice")
    require([word for word in maintenance if word != MAINTENANCE_UNIT] == enrolled,
            "maintenance boot entry differs from the enrolled entry beyond the maintenance unit")
    binding = profile["binding"]
    require(record["scope"] == {key: binding[key] for key in record["scope"]}, "scope substitution")
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(0 < (end - start).total_seconds() <= 900, "canonical half-open window")
    labels = {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}
    require(all(row["manifest"]["metadata"]["labels"] == labels for row in profile["resources"]),
            "profile resource labels differ from the binding")
    signed = _endpoint_rows(endpoints)
    require(record["endpointTuples"] == endpoints, "endpoint tuple substitution")
    proxy = signed.get(binding["endpointId"])
    api = signed.get(binding["apiEndpointId"]) if binding["apiEndpointId"] is not None else None
    resources = bool(profile["resources"])
    require(proxy is not None and proxy["kind"] == "CAMPAIGN_PROXY"
            and ((api is not None and api["kind"] == "KUBERNETES_API_PROXY") if resources
                 else binding["apiEndpointId"] is None), "profile endpoint kinds")
    internal = record["internalEndpoints"][0]
    ip = ipaddress.ip_address(internal["ipAddress"])
    require(ip.is_loopback and internal["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
            and internal["endpointId"] not in signed
            and all((row["ipAddress"], row["port"]) != (internal["ipAddress"], internal["port"])
                    for row in signed.values()), "loopback apiserver endpoint must stay internal")
    require(record["selinux"]["status"]["sequence"] % 2 == 0, "unstable policy epoch")

    def inventory(rows: list, bound: int) -> dict:
        files = {}
        for row in rows:
            _path(row["path"])
            require(row["path"] not in files and row["sha256"] != row["verityDigest"],
                    "duplicate file or conflated digest")
            files[row["path"]] = row
            occupied = set()
            for segment in row["executableSegments"]:
                key = (segment["offset"], segment["length"], segment["permissions"])
                require(key not in occupied and segment["offset"] + segment["length"]
                        <= ((row["size"] + 4095) // 4096) * 4096, "executable segment outside artifact")
                occupied.add(key)
        require(sum(row["size"] for row in files.values()) <= bound, "code inventory bound")
        return files

    files = inventory(record["files"], PLANEON_CODE_BYTES)
    backend_files = inventory(record["backendFiles"], BACKEND_CODE_BYTES)
    require(not set(files) & set(backend_files), "planeon and backend inventories overlap")
    owners = _Owners()

    program_ids: set[int] = set()
    inodes: set[int] = set()
    for role in ROLES:
        row = record["roles"][role]
        owners.own(row["filePaths"], files, "role", row["executable"], row["artifactDigest"], row["interpreterPath"])
        require(row["cgroup"]["inode"] not in inodes, "duplicate cgroup inode")
        inodes.add(row["cgroup"]["inode"])
        listen, outbound = row["listenEndpointIds"], row["outboundEndpointIds"]
        if role == "SERVER":
            require(listen == [binding["endpointId"]]
                    and outbound == ([binding["apiEndpointId"]] if resources else []), "server endpoints differ")
            bound_ports = [proxy["port"]]
        elif role == "EFFECT_GATE":
            require(listen == ([binding["apiEndpointId"]] if resources else [])
                    and outbound == [internal["endpointId"]], "gate endpoints differ")
            bound_ports = [api["port"]] if resources else []
        elif role == "OBSERVER":
            require(listen == [] and outbound == [internal["endpointId"]], "observer endpoints differ")
            bound_ports = []
        else:
            require(listen == [] and outbound == [], role.lower() + " network grant")
            bound_ports = []
        if role in ("SERVER", "EFFECT_GATE"):
            require(("CAP_NET_BIND_SERVICE" in row["capabilities"]) == any(port < 1024 for port in bound_ports),
                    "CAP_NET_BIND_SERVICE only for a signed port below 1024")
        for hook in HOOKS:
            program = row["bpfPrograms"][hook]
            require(program["programType"] == (9 if hook == "INET_SOCK_CREATE" else 18)
                    and program["instructionBytes"] % 8 == 0, "wrong kernel program type/length")
            require(program["pinPath"] == "%s/%s/%s" % (PIN_ROOT, ROLE_DIRS[role], HOOK_DIRS[hook]),
                    "program pin outside the sealed layout")
            require(program["programId"] not in program_ids, "program shared between hooks or roles")
            program_ids.add(program["programId"])

    executables: dict[tuple[str, str], str] = {}
    for role in ROLES:
        row = files[record["roles"][role]["executable"]]
        for key in (("sha256", row["sha256"]), ("verity", row["verityDigest"])):
            require(key not in executables, "role executables share content")
            executables[key] = role
    interpreters = {record["roles"][role]["interpreterPath"] for role in ROLES} - {None}
    for path in interpreters:
        require(("sha256", files[path]["sha256"]) not in executables
                and ("verity", files[path]["verityDigest"]) not in executables, "role executable equal to an interpreter")
    interpreter_content = {(key, files[path][field]) for path in interpreters
                           for key, field in (("sha256", "sha256"), ("verity", "verityDigest"))}
    tree_content = {(key, row[field]) for path, row in files.items() if path.startswith(INTERPRETER_TREE)
                    for key, field in (("sha256", "sha256"), ("verity", "verityDigest"))}
    for role in ROLES:
        row = record["roles"][role]
        for path in row["filePaths"]:
            content = {("sha256", files[path]["sha256"]), ("verity", files[path]["verityDigest"])}
            if path != row["executable"]:
                require(not any(executables.get(key) not in (None, role) for key in content)
                        and all(path != record["roles"][other]["executable"] for other in ROLES),
                        "role closure lists another role's executable")
            if row["interpreterPath"] is None:
                require(path not in interpreters and not content & interpreter_content
                        and not path.startswith(INTERPRETER_TREE) and not content & tree_content,
                        "native-only role closure lists an interpreter")

    lifecycle = record["lifecycleSubjects"]
    for name in LIFECYCLE:
        row = lifecycle[name]
        owners.own(row["filePaths"], files, name, row["executable"], row["artifactDigest"], None)
    require(set(owners.by_path) == set(files), "unowned planeon code")
    require(record["hardening"]["sealMarker"]["digest"] == expected_seal_digest(record),
            "seal marker does not bind this boot")

    components = record["backendComponents"]
    require(sorted(components) == sorted(record["backendProfile"]["componentKeys"])
            and set(REQUIRED_BACKEND) <= set(components), "backend components differ from the implementation profile")
    planeon_labels = {record["roles"][role]["processLabel"] for role in ROLES}
    planeon_labels |= {row["processLabel"] for row in lifecycle.values()}
    labels_seen, cgroups_seen, identities_seen = set(), set(), set()
    for name in sorted(components):
        row = components[name]
        owners.own(row["filePaths"], backend_files, "backend", row["executable"], row["artifactDigest"], None)
        domain = row["processLabel"].split(":")[2]
        require(row["processLabel"] not in planeon_labels and not domain.startswith("planeon_"),
                "backend component in a planeon domain")
        require(row["processLabel"] not in labels_seen, "backend components share a domain")
        labels_seen.add(row["processLabel"])
        _path(row["cgroupPath"])
        require(row["cgroupPath"].startswith(CGROUP_ROOT + "/"), "backend cgroup outside cgroupfs")
        require(row["cgroupPath"] != SLICE and not row["cgroupPath"].startswith(SLICE + "/"),
                "backend component inside the planeon slice")
        require(row["cgroupPath"] not in cgroups_seen, "backend components share a cgroup")
        require(not any(row["cgroupPath"].startswith(seen + "/") or seen.startswith(row["cgroupPath"] + "/")
                        for seen in cgroups_seen), "backend cgroup nested in another backend cgroup")
        require(sum(identity.startswith("system:node:") for identity in row["apiIdentities"]) <= 1,
                "more than one node identity")
        cgroups_seen.add(row["cgroupPath"])
        if name in NO_API_CLIENT:
            require(row["apiIdentities"] == [], "backend API identity")
        elif name != "APISERVER":
            require(row["apiIdentities"] != [], "backend API identity")
        require(not set(row["apiIdentities"]) & identities_seen, "backend components share an API identity")
        identities_seen |= set(row["apiIdentities"])
    require(set(owners.by_path) - set(files) == set(backend_files), "unowned backend code")


def check_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> None:
    """Detached model capture of one resident role. Production inspects the kernel through its own owner."""
    require(type(capture) is dict and capture.get("schemaVersion") == V3_CAPTURE, "not a v3 capture")
    _shape(record, "record", schema)
    _shape(capture, "capture", schema)
    require(type(role) is str and role in ROLES and capture["role"] == role
            and capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "capture binding")
    require(capture["host"] == record["host"], "wrong boot/kernel")
    status = record["selinux"]["status"]
    require(status["sequence"] % 2 == 0 and capture["selinuxBefore"] == status == capture["selinuxAfter"]
            and capture["kernelPolicyDigest"] == record["selinux"]["policyDigest"], "active policy changed")
    require(capture["booleansObserved"] == record["selinux"]["booleans"]
            and capture["hardeningObserved"] == record["hardening"], "host lock state differs")
    _boot_entry(record, capture["bootEntryObserved"])
    _within(record, capture["observedAt"], "expired capture")
    a, b, d = (capture[k] for k in ("inspectionStartedMs", "inspectionFinishedMs", "deadlineMs"))
    require(a <= b < d and b - a <= 2000 and d - a <= 900000, "inspection deadline")
    expected, actual = record["roles"][role], capture["process"]
    for field in ("uid", "gid", "processLabel", "namespaceInodes", "cgroup", "seccompMode", "seccompDefaultAction",
                  "seccompFilterDigest", "noNewPrivs", "rlimitCore"):
        require(actual[field] == expected[field], "process/kernel custody differs")
    require(actual["threadsUniform"] is True, "per-thread state not uniform")
    if role == "WORKER":
        # Owner decision D5 (2026-10-06): the bounding set may be any subset of the broker's
        # enrolled set (the broker cannot drop it without CAP_SETPCAP); every other set is empty
        # and no_new_privs keeps a leftover bounding set from granting anything.
        bounding = actual["capBounding"]
        require(actual["capPermitted"] == [] and actual["capEffective"] == [] and actual["capAmbient"] == []
                and actual["capInheritable"] == [] and len(set(bounding)) == len(bounding)
                and set(bounding) <= set(record["roles"]["BROKER"]["capabilities"]),
                "capability sets differ from the enrolled set")
    else:
        require(_same_set(actual["capPermitted"], expected["capabilities"])
                and _same_set(actual["capEffective"], expected["capabilities"])
                and _same_set(actual["capBounding"], expected["capabilities"])
                and actual["capAmbient"] == [] and actual["capInheritable"] == [],
                "capability sets differ from the enrolled set")
    me = {key: actual[key] for key in ("pid", "startTicks", "ppid", "uid", "processLabel", "noNewPrivs", "seccompMode",
                                       "threadCount", "exe")}
    members = capture["cgroupMembers"]
    if role in SINGLE_PROCESS_ROLES:
        require(members == [me], "unenrolled cgroup member")
    else:
        pids = {m["pid"]: m for m in members}
        require(me in members and len(pids) == len(members) <= expected["cgroup"]["pidsMax"]
                and all(m["processLabel"] == expected["processLabel"] and m["uid"] == expected["uid"]
                        and m["noNewPrivs"] == 1 and m["seccompMode"] == 2 for m in members), "unenrolled cgroup member")
        for member in members:
            seen, cursor = set(), member
            while cursor["pid"] != me["pid"]:
                require(cursor["pid"] not in seen and cursor["ppid"] in pids, "worker member not descended from the inspected worker")
                seen.add(cursor["pid"])
                cursor = pids[cursor["ppid"]]
    # pids.current counts tasks (threads) of the whole cgroup; a role cgroup has no descendants.
    require(capture["pidsCurrent"] == sum(m["threadCount"] for m in members) <= expected["cgroup"]["pidsMax"],
            "task count differs from pids.current or exceeds pids.max")
    require(capture["childCgroups"] == [] and capture["descendantCount"] == 0, "role cgroup has descendants")
    children, service = capture["delegatedChildren"], capture["delegatedServiceMembers"]
    if role == "BROKER":
        require(type(children) is list and sorted(children) == DELEGATED_CHILDREN and service == [],
                "delegated broker subtree differs")
    else:
        require(children is None and service is None, "delegated broker subtree differs")
    rows = {row["path"]: row for row in record["files"]}
    observed = {}
    for item in capture["files"]:
        path = item["entry"]["path"]
        require(path not in observed and path in expected["filePaths"] and item["entry"] == rows[path]
                and item["contentDigest"] == rows[path]["sha256"]
                and item["measuredVerity"] == rows[path]["verityDigest"], "file measurement differs")
        observed[path] = item
    require(set(observed) == set(expected["filePaths"]), "incomplete loaded-code closure")
    image = expected["interpreterPath"] or expected["executable"]
    require(actual["exe"] == {"path": image, "device": observed[image]["device"], "inode": observed[image]["inode"]}
            and all(m["exe"] == actual["exe"] for m in members), "running image is not the role's executable or interpreter")
    mappings = [dict(path=path, **segment, device=observed[path]["device"], inode=observed[path]["inode"])
                for path in expected["filePaths"] for segment in rows[path]["executableSegments"]]
    key = lambda m: (m["path"], m["offset"], m["length"], m["permissions"], m["device"], m["inode"])
    require(sorted(capture["executableMaps"], key=key) == sorted(mappings, key=key),
            "missing or injected executable map")
    for hook in HOOKS:
        item, pinned = capture["bpfPrograms"][hook], expected["bpfPrograms"][hook]
        require(item["program"] == pinned and item["pinPath"] == pinned["pinPath"]
                and item["pinLabel"] == pinned["pinLabel"]
                and item["localIds"] == [pinned["programId"]] and item["effectiveIds"] == item["localIds"],
                "effective kernel filter differs")
    require(all(capture["effectiveCensus"][name] == [] for name in CENSUS_ATTACH_TYPES),
            "program effective on a role cgroup outside the containment hooks")
    if previous is not None:
        require(explain(check_capture, record, previous, role, schema) is None, "invalid retained capture")
        for field in ("host", "process", "files", "executableMaps", "bpfPrograms", "selinuxBefore", "selinuxAfter",
                      "kernelPolicyDigest", "booleansObserved", "hardeningObserved", "cgroupMembers",
                      "childCgroups", "descendantCount", "delegatedChildren", "delegatedServiceMembers",
                      "pidsCurrent", "effectiveCensus", "bootEntryObserved"):
            require(capture[field] == previous[field], "retained native identity changed")
        require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                and capture["observedAt"] >= previous["observedAt"]
                and capture["deadlineMs"] == previous["deadlineMs"], "rollback or renewed lifetime")


def _kernel_parameter(word: str) -> bool:
    """One word of the closed kernel command-line grammar."""
    return any(pattern.fullmatch(word) for pattern in KERNEL_PARAMETERS)


def _boot_entry(record: dict, observed: dict) -> None:
    """The observation was taken on the enrolled boot entry, never the maintenance entry."""
    enrolled = record["bootEntries"]["ENROLLED"]
    require(observed == {"entryId": enrolled["entryId"],
                         "cmdlineSha256": "sha256:" + digest(enrolled["kernelCmdline"].encode("ascii"))},
            "observed on a boot entry other than the enrolled one")


def check_lifecycle_capture(record: Any, capture: Any, schema: dict) -> None:
    """Absence of the one-shot containment subject after its seal; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V3_LIFECYCLE, "not a v3 lifecycle capture")
    _shape(record, "record", schema)
    _shape(capture, "lifecycleCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "lifecycle capture binding")
    _within(record, capture["observedAt"], "expired lifecycle capture")
    require(capture["sealMarker"] == record["hardening"]["sealMarker"], "seal marker differs")
    require(capture["runFsType"] == record["hardening"]["runFsType"], "seal marker not on a per-boot filesystem")
    containment = record["lifecycleSubjects"]["HOST_CONTAINMENT"]["cgroupPath"]
    require(capture["cgroup"]["path"] == containment and capture["cgroup"]["state"] in ("ABSENT", "EMPTY")
            and capture["domainProcessCounts"]["planeon_contain_t"] == 0, "containment subject still resident")
    require(capture["booleansObserved"] == record["selinux"]["booleans"], "host lock state differs")
    _boot_entry(record, capture["bootEntryObserved"])
    # The slice root holds no process of its own (observed, not inferred from the no-internal-process rule).
    require(capture["sliceMembers"] == [], "process directly in the planeon slice")
    census = {row["path"]: row["populated"] for row in capture["sliceCgroups"]}
    for path in census:
        _path(path)
    require(len(census) == len(capture["sliceCgroups"])
            and all(path == SLICE or path.startswith(SLICE + "/") for path in census), "planeon slice census malformed")
    require(all(path == SLICE or path.rsplit("/", 1)[0] in census for path in census),
            "planeon slice census omits a parent cgroup")
    enrolled = {record["roles"][role]["cgroup"]["path"] for role in ROLES} | {SLICE, SLICE + "/planeon-capacity-broker.service"}
    require(enrolled <= set(census), "planeon slice census incomplete")
    require((containment in census) == (capture["cgroup"]["state"] == "EMPTY")
            and census.get(containment, 0) == 0, "containment subject still resident")
    require(all(populated == 0 for path, populated in census.items() if path not in enrolled),
            "unenrolled populated cgroup in the planeon slice")
    # cgroup.stat nr_descendants of the slice: the census lists every live descendant (round 2, W7).
    require(capture["sliceDescendants"] == len(census) - 1, "slice descendants differ from the census")


def check_backend_capture(record: Any, capture: Any, schema: dict) -> None:
    """Observation of one backend component's process against its record entry; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V3_BACKEND, "not a v3 backend capture")
    _shape(record, "record", schema)
    _shape(capture, "backendCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "backend capture binding")
    _within(record, capture["observedAt"], "expired backend capture")
    entry = record["backendComponents"].get(capture["component"])
    require(entry is not None, "backend capture for an unrecorded component")
    executable = {row["path"]: row for row in record["backendFiles"]}[entry["executable"]]
    require(capture["process"]["processLabel"] == entry["processLabel"]
            and capture["process"]["cgroupPath"] == entry["cgroupPath"]
            and capture["executable"] == {"path": entry["executable"], "contentDigest": executable["sha256"],
                                          "measuredVerity": executable["verityDigest"]}, "backend observation differs")


def check_migration(v1_records: Any, v2_records: Any, v3_record: Any, v3_profile: Any, v1_schema: dict,
                    v2_schema: dict, schema: dict, no_earlier_history: bool = False) -> None:
    """A v3 enrollment needs a maintenance reboot and fresh nonces against every earlier version.

    `v1_records` and `v2_records` must be the complete retained v1 and v2 histories (a caller
    obligation); a host whose histories are both attested empty passes `no_earlier_history=True`
    with two empty lists. Earlier data is never reinterpreted."""
    _shape(v3_record, "record", schema)
    require(v3_record["profileDigest"] == "sha256:" + digest(canonical(v3_profile)), "profile substitution")
    require(digest(canonical(v1_schema)) == V1_SCHEMA_SHA256, "unreviewed v1 schema")
    require(digest(canonical(v2_schema)) == V2_SCHEMA_SHA256, "unreviewed v2 schema")
    require(type(v1_records) is list and type(v2_records) is list and type(no_earlier_history) is bool, "migration inputs")
    if no_earlier_history:
        require(v1_records == [] and v2_records == [], "attested empty history with earlier records")
    require(no_earlier_history or v1_records or v2_records, "retained earlier records required")
    old_nonces: set[str] = set()
    for version, records, old_schema in (("v1", v1_records, v1_schema), ("v2", v2_records, v2_schema)):
        for old in records:
            require(type(old) is dict and old.get("schemaVersion") == "planeon.internal.native-qualification/" + version
                    and not schema_errors(old, old_schema, "record"), "predecessor is not a valid %s record" % version)
            require(old["host"]["bootId"] != v3_record["host"]["bootId"], "v3 enrollment without a maintenance reboot")
            old_nonces |= {old["scope"]["runNonce"], old["scope"]["capacityNonce"]}
    new_nonces = {v3_record["scope"]["runNonce"], v3_record["scope"]["capacityNonce"]}
    require(not new_nonces & old_nonces, "nonce reused across versions")
    require(not set(_strings(v3_profile)) & old_nonces and not set(_strings(v3_record)) & old_nonces,
            "earlier nonce carried into v3 data")


def check_qualification(record: Any, profile: Any, endpoints: Any, captures: Any, lifecycle: Any,
                        backend_captures: Any, v1_records: Any, v2_records: Any, v1_schema: dict, v2_schema: dict,
                        schema: dict, no_earlier_history: bool = False, test_fixture: bool = False) -> None:
    """The only acceptance-shaped check: everything for one boot and window, still DATA_CHECK_ONLY.

    Caller obligations: the profile passed the pinned proxy profile contract, and `v1_records`
    and `v2_records` are the complete retained earlier histories (see the module docstring). A
    test-only implementation profile qualifies only with `test_fixture=True`."""
    check_record(record, profile, endpoints, schema)
    require(type(test_fixture) is bool and (test_fixture or not record["backendProfile"]["testOnly"]),
            "test-only implementation profile")
    require(type(captures) is list and sorted(c.get("role") for c in captures) == sorted(ROLES),
            "one capture per resident role")
    for capture in captures:
        check_capture(record, capture, capture["role"], schema)
    check_lifecycle_capture(record, lifecycle, schema)
    require(type(backend_captures) is list
            and sorted(c.get("component") for c in backend_captures) == sorted(record["backendComponents"]),
            "one observation per backend component")
    for capture in backend_captures:
        check_backend_capture(record, capture, schema)
    processes = [(m["pid"], m["startTicks"]) for c in captures for m in c["cgroupMembers"]]
    processes += [(c["process"]["pid"], c["process"]["startTicks"]) for c in backend_captures]
    require(len(set(processes)) == len(processes), "one process reported twice")
    # One observed file per (device, inode) and one inode per path, across every role capture (round 2, W1).
    by_inode: dict[tuple, tuple] = {}
    by_path: dict[str, tuple] = {}
    for capture in captures:
        for item in capture["files"]:
            node = (item["device"], item["inode"])
            seen = (item["entry"]["path"], item["contentDigest"], item["measuredVerity"])
            require(by_inode.setdefault(node, seen) == seen, "one inode reported for two files")
            require(by_path.setdefault(seen[0], node) == node, "one file reported at two inodes")
    by_role = {c["role"]: c for c in captures}
    require(by_role["WORKER"]["process"]["ppid"] == by_role["BROKER"]["process"]["pid"],
            "worker is not a child of the original broker")
    counts = lifecycle["domainProcessCounts"]
    require(all(counts[ROLE_DOMAINS[role]] == len(by_role[role]["cgroupMembers"]) for role in ROLES),
            "role-domain process outside its role cgroup")
    # The slice census agrees with the role captures: role cgroups have no child cgroup, the delegated broker
    # service has exactly its two leaves, and every enrolled cgroup that holds a captured process is populated.
    census = {row["path"]: row["populated"] for row in lifecycle["sliceCgroups"]}
    role_cgroups = {record["roles"][role]["cgroup"]["path"] for role in ROLES}
    require(not any(path.startswith(cgroup + "/") for path in census for cgroup in role_cgroups),
            "census lists a cgroup below a role cgroup")
    require(sorted(path[len(BROKER_SERVICE) + 1:] for path in census if path.startswith(BROKER_SERVICE + "/")
                   and "/" not in path[len(BROKER_SERVICE) + 1:]) == DELEGATED_CHILDREN,
            "census children of the delegated broker service differ")
    require(all(census[path] == 1 for path in role_cgroups | {SLICE, BROKER_SERVICE}),
            "census reports a cgroup with captured processes as unpopulated")
    check_migration(v1_records, v2_records, record, profile, v1_schema, v2_schema, schema, no_earlier_history)


ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, jsonschema.ValidationError)


def explain(check: Any, *args: Any) -> str | None:
    """None when `check` accepts; otherwise the refused rule (schema refusals name the JSON path)."""
    try:
        check(*args)
    except jsonschema.ValidationError as exc:
        return "schema %s %s" % (exc.json_path, exc.validator)
    except ERRORS as exc:
        return str(exc) if type(exc) is ValueError else type(exc).__name__
    return None


def refusal_under(value: Any, schema: dict, variant: str) -> str | None:
    """Best-match schema refusal of `value` as `variant` of `schema` (any version), or None."""
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    return None if error is None else "schema %s %s" % (error.json_path, error.validator)


def _result(check: Any, message: str, *args: Any) -> list[str]:
    return [] if explain(check, *args) is None else [message]


def validate_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> list[str]:
    return _result(check_record, "invalid DATA_CHECK_ONLY v3 qualification record; no native authority",
                   record, profile, endpoints, schema)


def validate_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> list[str]:
    return _result(check_capture, "invalid DATA_CHECK_ONLY v3 capture; no native authority",
                   record, capture, role, schema, previous)


def validate_qualification(*args: Any) -> list[str]:
    """Empty list = accepted as data, given the caller obligations in the module docstring."""
    return _result(check_qualification, "invalid DATA_CHECK_ONLY v3 qualification; no native authority "
                   "(caller must also have validated the profile with the pinned proxy contract)", *args)
