"""TG-01 replays: each adopted contract's vectors through its snapshotted reference model (W04-2, CONF-ENF-002).

Expected results come only from the vectors; the models are the adopted contracts' reference models, never an
implementation. Every vector is replayed in full. A vector whose replay reaches the reference model's jsonschema import
(gap G-JSONSCHEMA) is counted NOT_RUN_ENV_UNAVAILABLE under owner decision Q-T4 (2026-10-11), never PASS; any other
difference raises Mismatch naming the vector. Each replay returns a Tally of the vector ids in each result.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import re

import _models

I05 = "architecture/i05-gate-channel-v3/"
I07 = "architecture/i07-policy-write-v3/"
ADM = "architecture/admission-semantics-v3/"
SEL = "architecture/selinux-matrix-v2/"
SEC = "architecture/seccomp-allowlists-v2/"
I06 = "architecture/i06-backend-profile-v2/"
NAT = "architecture/native-profile-v3/"
# I07's writer identity values, as the I07 v3 contract states them for the qualification namespace.
I07_NAMESPACE, I07_AUTHORITY = "planeon-qual", "127.0.0.1:6443"


class Mismatch(AssertionError):
    pass


class Tally:
    """Vector ids by result: PASS, or NOT_RUN_ENV_UNAVAILABLE when the replay needed jsonschema."""

    def __init__(self):
        self.ids = {"PASS": [], "NOT_RUN_ENV_UNAVAILABLE": []}

    def run(self, ident, check):
        try:
            check()
        except ModuleNotFoundError as exc:
            if exc.name != "jsonschema":
                raise
            self.ids["NOT_RUN_ENV_UNAVAILABLE"].append(ident)
            return
        self.ids["PASS"].append(ident)

    def whole(self, ident_list, check):
        """A set whose model cannot load without jsonschema: every vector is not run, or all pass together."""
        try:
            check()
        except ModuleNotFoundError as exc:
            if exc.name != "jsonschema":
                raise
            self.ids["NOT_RUN_ENV_UNAVAILABLE"].extend(ident_list)
            return self
        self.ids["PASS"].extend(ident_list)
        return self


def require(ok, message):
    if not ok:
        raise Mismatch(message)


def refusal(call):
    try:
        call()
    except ValueError as exc:
        return str(exc)
    return None


def apply_ops(value, ops):
    """Closed set/delete path operations on a copy (the admission vectors' operation form)."""
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete") and type(op.get("path")) is list and op["path"],
                "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        else:
            del node[last]
    return value


# SELinux matrix v4 -------------------------------------------------------------------------------------------------

def _selinux():
    model, matrix = _models.model("selinux_matrix_v2"), _models.data(SEL + "matrix.json")
    model.check_matrix(matrix)
    require(model.failed_assertions(matrix) == [], "every deny assertion holds on the adopted matrix")
    vectors = _models.data(SEL + "vectors.json")
    require(model.w02a_slots(matrix) == vectors["w02aSlots"], "the W02a label slots are the matrix's")
    return model, matrix, vectors


def selinux_access():
    model, matrix, vectors = _selinux()
    tally = Tally()
    for row in vectors["accessChecks"]:
        tally.run(row["id"], lambda: require(
            model.allowed(matrix, row["state"], row["source"], row["target"], row["class"], row["perm"]) is row["expect"],
            "SELinux access check " + row["id"]))
    return tally


def selinux_mutation():
    model, matrix, vectors = _selinux()
    tally = Tally()
    def check(row):
        mutated = model.apply_ops(matrix, row["ops"])
        try:
            model.check_matrix(mutated)
            ok = row["expect"] == {"failedAssertions": model.failed_assertions(mutated)} and row["expect"]["failedAssertions"] != []
        except ValueError as exc:
            ok = set(row["expect"]) == {"matrixError"} and row["expect"]["matrixError"] in (str(exc), str(exc).split(":", 1)[0])
        require(ok, "SELinux mutation check " + row["id"])
    for row in vectors["mutationChecks"]:
        tally.run(row["id"], lambda: check(row))
    return tally


# Seccomp allowlists v2 ---------------------------------------------------------------------------------------------

_SECCOMP = {}


def _seccomp():
    """The model, table, policy, vectors and the 14 compiled programs, built once per process."""
    if not _SECCOMP:
        model, table, policy = _models.model("seccomp_allowlists_v2"), _models.data(SEC + "syscalls.json"), _models.data(SEC + "allowlists.json")
        model.check_policy(policy, table)
        programs = {(role, arch): model.compile_filter(policy, table, role, arch) for role in model.ROLES for arch in model.ARCHES}
        _SECCOMP.update(model=model, table=table, policy=policy, vectors=_models.data(SEC + "vectors.json"), programs=programs)
    return _SECCOMP["model"], _SECCOMP["table"], copy.deepcopy(_SECCOMP["policy"]), _SECCOMP["vectors"], _SECCOMP["programs"]


def seccomp_programs():
    model, table, policy, vectors, programs = _seccomp()
    tally = Tally()
    for role in model.ROLES:
        for arch in model.ARCHES:
            tally.run("%s/%s" % (role, arch), lambda: require(
                vectors["filterDigests"][role][arch] == "sha256:" + hashlib.sha256(model.program_bytes(programs[role, arch])).hexdigest()
                and vectors["programLengths"][role][arch] == len(programs[role, arch]), "seccomp program %s/%s" % (role, arch)))
    require(set(vectors["filterDigests"]) == set(vectors["programLengths"]) == set(model.ROLES)
            and all(set(vectors[key][role]) == set(model.ARCHES) for key in ("filterDigests", "programLengths") for role in model.ROLES),
            "seccomp program tables are closed")
    return tally


def seccomp_decisions():
    model, table, policy, vectors, programs = _seccomp()
    tally = Tally()
    for row in vectors["decisionChecks"]:
        def check(row=row):
            reference = model.action_name(model.decide(policy, table, row["role"], row["arch"], row["auditArch"], row["nr"], row["args"]))
            compiled = model.action_name(model.run_filter(programs[row["role"], row["arch"]],
                                                          model.seccomp_data(row["nr"], row["auditArch"], row["args"])))
            require(reference == compiled == row["expect"], "seccomp decision check " + row["id"])
        tally.run(row["id"], check)
    return tally


def seccomp_worker_stack():
    model, table, policy, vectors, programs = _seccomp()
    by_id = {row["id"]: row for row in vectors["decisionChecks"]}
    tally = Tally()
    for row in vectors["workerStackChecks"]:
        base = by_id[row["decision"]]
        tally.run(row["id"], lambda: require(
            base["role"] == "WORKER" and row["expect"] == "SAME_AS_WORKER"
            and model.decide_stack(policy, table, ["BROKER", "WORKER"], base["arch"], base["auditArch"], base["nr"], base["args"])
            == model.decide(policy, table, "WORKER", base["arch"], base["auditArch"], base["nr"], base["args"]),
            "seccomp worker stack check " + row["id"]))
    return tally


def seccomp_policy_mutations():
    model, table, policy, vectors, programs = _seccomp()
    tally = Tally()
    for row in vectors["policyMutations"]:
        def check(row=row):
            changed = copy.deepcopy(policy)
            changed["roles"][row["role"]]["duties"].append(row["addDuty"])
            got = refusal(lambda: model.check_policy(changed, table))
            require(got is not None and got == row["expect"], "seccomp policy mutation " + row["id"])
        tally.run(row["id"], check)
    return tally


# Admission semantics v3 --------------------------------------------------------------------------------------------

def _admission():
    return _models.model("admission_semantics_v3"), _models.data(ADM + "vectors.json")


def admission_sealed():
    model, vectors = _admission()
    raw = _models.snapshot_bytes(ADM + "admission-manifests/planeon-a2.json")
    sealed = vectors["sealed"]
    tally = Tally()
    tally.run("rendering", lambda: require(raw == model.manifest_file_bytes(sealed), "the sealed A2 manifest file is the contract's rendering"))
    tally.run("objects", lambda: require(model.check_a2_objects(_models.data(ADM + "admission-manifests/planeon-a2.json")["items"], sealed) is None,
                                         "the sealed A2 objects pass"))
    tally.run("directoryHash", lambda: require(model.manifest_directory_hash({"planeon-a2.json": raw}) == vectors["pinned"]["manifestDirectoryHash"],
                                               "the pinned manifest directory hash"))
    for name, manifest in vectors["positives"].items():
        kind = "Pod" if name.startswith("Pod") else name
        tally.run("positive:" + name, lambda: require(model.check_manifest(kind, manifest, sealed["namespace"]) is None, "positive manifest " + name))
    return tally


def admission_manifest():
    model, vectors = _admission()
    tally = Tally()
    for row in vectors["manifest"]:
        tally.run(row["id"], lambda: require(
            model.check_manifest(row["kind"], apply_ops(vectors["positives"][row["positive"]], row["ops"]), vectors["sealed"]["namespace"])
            == row["expect"], "admission manifest vector " + row["id"]))
    return tally


def admission_end_to_end():
    model, vectors = _admission()
    tally = Tally()
    for row in vectors["endToEnd"]:
        def check(row=row):
            final = model.final_object(row["kind"], apply_ops(vectors["positives"][row["positive"]], row.get("manifestOps", [])),
                                       dict(vectors["server"], **row["serverFacts"]))
            require(final == row["finalObject"] and model.check_final(row["kind"], final, vectors["sealed"], row["username"]) == row["expect"],
                    "admission end-to-end vector " + row["id"])
        tally.run(row["id"], check)
    return tally


def admission_final_object():
    model, vectors = _admission()
    tally = Tally()
    for row in vectors["finalObject"]:
        tally.run(row["id"], lambda: require(model.check_final(row["kind"], row["object"], vectors["sealed"], row["username"]) == row["expect"],
                                             "admission final-object vector " + row["id"]))
    return tally


def admission_objects():
    model, vectors = _admission()
    tally = Tally()
    for row in vectors["objects"]:
        tally.run(row["id"], lambda: require(model.check_a2_objects(row["objects"], vectors["sealed"]) == row["expect"],
                                             "admission policy-object vector " + row["id"]))
    return tally


def admission_directory_hash():
    model, vectors = _admission()
    tally = Tally()
    for row in vectors["directoryHash"]:
        files = {name: text.encode("utf-8") for name, text in row["files"].items()}
        tally.run(row["id"], lambda: require(model.manifest_directory_hash(files) == row["expect"], "admission directory-hash vector " + row["id"]))
    return tally


def admission_claims():
    model, vectors = _admission()
    tally = Tally()
    for row in vectors["claims"]:
        tally.run(row["id"], lambda: require(model.check_claim(row["claim"], vectors["pinned"]) == row["expect"], "admission claim vector " + row["id"]))
    return tally


# I05 gate channel v3 -----------------------------------------------------------------------------------------------

def _i05():
    return _models.model("i05_gate_channel_v3"), _models.data(I05 + "channel.schema.json"), _models.data(I05 + "vectors.json")


def i05_agreement():
    model, schema, vectors = _i05()
    mapping = _models.data(I05 + "outcome-mapping.json")
    tally = Tally()
    for row in vectors["agreement"]:
        tally.run(row["id"], lambda: require(
            model.check_agreement(mapping, row["verb"], row["identity"], row["outcome"], row["resourceResult"]) == row["expect"],
            "I05 agreement " + row["id"]))
    return tally


def i05_config_refusals():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["configRefusals"]:
        def check(row=row):
            got = refusal(lambda: model.Gate(dict(vectors["configs"]["ACTIVE"], **row["override"])))
            require(got is not None and got == row["expect"], "I05 configuration refusal " + row["id"])
        tally.run(row["id"], check)
    return tally


def i05_frames():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["frames"]:
        tally.run(row["id"], lambda: require(refusal(lambda: model.check_frame(row["frame"], schema)) == row["expect"], "I05 frame " + row["id"]))
    return tally


INPUT_TYPES = {"bytes": bytes, "bytearray": bytearray, "str": lambda raw: raw.decode("ascii")}


def i05_byte_frames():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["byteFrames"]:
        raw = INPUT_TYPES[row["inputType"]](base64.b64decode(row["base64"], validate=True))
        tally.run(row["id"], lambda: require(refusal(lambda: model.decode_frame(raw, schema)) == row["expect"], "I05 byte frame " + row["id"]))
    require([row["id"] for row in vectors["byteFrames"]] == ["B%02d" % n for n in range(1, 15)], "I05 byte checks in order")
    return tally


def i05_transcripts():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["transcripts"]:
        def check(row=row):
            outputs, final = model.replay(vectors["configs"][row["config"]], row["events"], schema)
            require(outputs == row["outputs"] and final == row["final"], "I05 transcript " + row["id"])
        tally.run(row["id"], check)
    return tally


# I07 policy write v3 -----------------------------------------------------------------------------------------------

def _i07():
    return (_models.model("i07_policy_write_v3"), _models.data(I07 + "policy-kinds.json"), _models.data(I07 + "channel.schema.json"),
            _models.data(I07 + "vectors.json"))


def i07_kind_checks():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for row in vectors["kindChecks"]:
        tally.run(row["id"], lambda: require(model.check_write(kinds, I07_NAMESPACE, row["payload"]) == row["expect"], "I07 kind check " + row["id"]))
    return tally


def i07_render_checks():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for row in vectors["renderChecks"]:
        def check(row=row):
            entry, _ = model.classify_resource(kinds, row["payload"]["resource"])
            require(model.render_write(entry, row["payload"], I07_NAMESPACE, I07_AUTHORITY) == {"head": row["head"], "bodyDigest": row["bodyDigest"]},
                    "I07 render check " + row["id"])
        tally.run(row["id"], check)
    return tally


def i07_outcome_checks():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for index, row in enumerate(vectors["outcomeChecks"]):
        tally.run("O%02d" % (index + 1), lambda: require(model.write_outcome_is_final(row["operation"], row["httpStatus"]) is row["final"],
                                                         "I07 outcome check %d" % (index + 1)))
    return tally


def i07_frames():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for row in vectors["frames"]:
        def check(row=row):
            got = refusal(lambda: model.check_frame(row["frame"], schema))
            require((got.split(" ", 1)[0] if got else None) == row["expect"], "I07 frame check " + row["id"])
        tally.run(row["id"], check)
    return tally


def i07_byte_frames():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for row in vectors["byteFrames"]:
        def check(row=row):
            got = refusal(lambda: model.decode_frame(base64.b64decode(row["base64"], validate=True), schema))
            require((got.split(" ", 1)[0] if got else None) == row["expect"], "I07 byte frame check " + row["id"])
        tally.run(row["id"], check)
    return tally


def i07_transcripts():
    model, kinds, schema, vectors = _i07()
    schemas = {"i05": _models.data(I05 + "channel.schema.json"), "i07": schema}
    tally = Tally()
    for row in vectors["transcripts"]:
        def check(row=row):
            outputs, final = model.replay(vectors["configs"][row["config"]], row["events"], schemas, kinds)
            require(outputs == row["outputs"] and final == row["final"], "I07 transcript " + row["id"])
        tally.run(row["id"], check)
    return tally


# W01 amendment W02D ------------------------------------------------------------------------------------------------
# The model's check(read) validates the amendment record against W02d's carried items and rebuilds the published
# effective specification from the pinned W01 base. Its two inputs outside the plan's contract set (the W01 base and
# seccomp-allowlists/status.json) are snapshotted as recorded additions (owner decision Q-T7, 2026-10-11).

def w02d_amendment():
    model = _models.model("host_interface_amendment")
    inputs = (model.RECORD_PATH, model.BASE_PATH, model.EFFECTIVE_PATH, model.CARRIED_PATH)
    read = set()
    def reader(path):
        require(path in inputs, "the W02D check reads only its four snapshotted inputs, not " + path)
        read.add(path)
        return _models.snapshot_bytes(path)
    def check():
        try:
            record = model.check(reader)
        except ValueError as exc:
            raise Mismatch("W01 amendment W02D check: %s" % exc)
        require(read == set(inputs), "the W02D check read all four inputs")
        require(record == _models.data(model.RECORD_PATH), "the W02D check returns the snapshotted record")
    tally = Tally()
    tally.run("amendment", check)
    return tally


# I06 backend profile v2 and native qualification profile v3 --------------------------------------------------------
# Both models import jsonschema when they load (I06 v2 through native v3), so no vector can be replayed here. If the
# environment ever provides jsonschema, the load succeeds and these refuse until real replays are written (Q-T4). The
# replays also need inputs that are not snapshotted (gap G-REPLAY-INPUTS in toolchains.json, review R1-5).

def _unwritten(name):
    _models.model(name)
    raise Mismatch(name + " loaded: jsonschema is available, so write its vector replay (owner decision Q-T4) and snapshot"
                   " its missing inputs first (gap G-REPLAY-INPUTS)")


def i06_v2_vectors():
    vectors = _models.data(I06 + "vectors.json")
    ids = [row["id"] for key in ("evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative", "crossVersion")
           for row in vectors[key]]
    return Tally().whole(ids, lambda: _unwritten("i06_backend_profile_v2"))


def native_v3_vectors():
    vectors = _models.data(NAT + "vectors.json")
    ids = ["positive:%d" % index for index in range(len(vectors["positive"]))]
    ids += [row["id"] for key in ("negative", "accepted", "crossVersion", "migration") for row in vectors[key]]
    return Tally().whole(ids, lambda: _unwritten("native_qualification_v3"))


REPLAYS = {
    ("SELinux matrix v4", "accessChecks"): selinux_access,
    ("SELinux matrix v4", "mutationChecks"): selinux_mutation,
    ("Seccomp allowlists v2", "programs"): seccomp_programs,
    ("Seccomp allowlists v2", "decisionChecks"): seccomp_decisions,
    ("Seccomp allowlists v2", "workerStackChecks"): seccomp_worker_stack,
    ("Seccomp allowlists v2", "policyMutations"): seccomp_policy_mutations,
    ("Admission semantics v3", "sealed"): admission_sealed,
    ("Admission semantics v3", "manifest"): admission_manifest,
    ("Admission semantics v3", "endToEnd"): admission_end_to_end,
    ("Admission semantics v3", "finalObject"): admission_final_object,
    ("Admission semantics v3", "objects"): admission_objects,
    ("Admission semantics v3", "directoryHash"): admission_directory_hash,
    ("Admission semantics v3", "claims"): admission_claims,
    ("I05 gate channel v3", "agreement"): i05_agreement,
    ("I05 gate channel v3", "configRefusals"): i05_config_refusals,
    ("I05 gate channel v3", "frames"): i05_frames,
    ("I05 gate channel v3", "byteFrames"): i05_byte_frames,
    ("I05 gate channel v3", "transcripts"): i05_transcripts,
    ("I07 policy write v3", "kindChecks"): i07_kind_checks,
    ("I07 policy write v3", "renderChecks"): i07_render_checks,
    ("I07 policy write v3", "outcomeChecks"): i07_outcome_checks,
    ("I07 policy write v3", "frames"): i07_frames,
    ("I07 policy write v3", "byteFrames"): i07_byte_frames,
    ("I07 policy write v3", "transcripts"): i07_transcripts,
    ("W01 amendment W02D", "amendment"): w02d_amendment,
    ("I06 backend profile v2", "vectors"): i06_v2_vectors,
    ("Native qualification profile v3", "vectors"): native_v3_vectors,
}


# Case mapping (reviews R1-1, R2-1..R2-3) ---------------------------------------------------------------------------
# Whole vector sets carry the TG-01 plan cases they exemplify. Wrong peer, role/version mismatch and part of CE23 are a
# few vectors of mixed sets: each is selected by a rule over the vectors' own content, so the ledger must equal what
# these rules give on the pinned vectors and cannot narrow a case by data alone.

CASE_TAGS = {
    ("SELinux matrix v4", "accessChecks"): ["CONTRACT-DATA"],
    ("SELinux matrix v4", "mutationChecks"): ["CONTRACT-DATA", "MATRIX:exact fields"],
    ("Seccomp allowlists v2", "programs"): ["CONTRACT-DATA"],
    ("Seccomp allowlists v2", "decisionChecks"): ["CONTRACT-DATA"],
    ("Seccomp allowlists v2", "workerStackChecks"): ["CONTRACT-DATA"],
    ("Seccomp allowlists v2", "policyMutations"): ["CONTRACT-DATA", "MATRIX:exact fields"],
    ("Admission semantics v3", "sealed"): ["MATRIX:exact fields"],
    ("Admission semantics v3", "manifest"): ["MATRIX:exact fields"],
    ("Admission semantics v3", "endToEnd"): ["MATRIX:exact fields"],
    ("Admission semantics v3", "finalObject"): ["MATRIX:exact fields"],
    ("Admission semantics v3", "objects"): ["MATRIX:exact fields"],
    ("Admission semantics v3", "directoryHash"): ["MATRIX:exact fields"],
    ("Admission semantics v3", "claims"): ["MATRIX:exact fields"],
    ("I05 gate channel v3", "agreement"): ["MATRIX:exact fields"],
    ("I05 gate channel v3", "configRefusals"): ["MATRIX:exact fields"],
    ("I05 gate channel v3", "frames"): ["MATRIX:exact fields", "MATRIX:duplicate/unknown keys"],
    ("I05 gate channel v3", "byteFrames"): ["MATRIX:duplicate/unknown keys", "MATRIX:exact fields"],
    ("I05 gate channel v3", "transcripts"): ["MATRIX:transcript replay"],
    ("I07 policy write v3", "kindChecks"): ["CE23", "MATRIX:exact fields"],
    ("I07 policy write v3", "renderChecks"): ["MATRIX:exact fields"],
    ("I07 policy write v3", "outcomeChecks"): ["MATRIX:exact fields"],
    ("I07 policy write v3", "frames"): ["MATRIX:exact fields", "MATRIX:duplicate/unknown keys"],
    ("I07 policy write v3", "byteFrames"): ["MATRIX:duplicate/unknown keys", "MATRIX:exact fields"],
    ("I07 policy write v3", "transcripts"): ["MATRIX:transcript replay"],
    ("W01 amendment W02D", "amendment"): ["CONTRACT-DATA"],
    ("I06 backend profile v2", "vectors"): ["CONTRACT-DATA"],
    ("Native qualification profile v3", "vectors"): ["MATRIX:exact fields"],
}

PEER_FATALS = {"PEER_CHANGED", "PEER_LOST", "PEER_QUALIFICATION_MISMATCH"}
PEER_EVENTS = {"PEER_CHANGED", "W_PEER_CHANGED"}
EARLIER_VERSION = re.compile(r"\bv[12]\b")


def _fatals(row):
    return {output.get("fatal") for output in row["outputs"] if type(output) is dict}


def _wrong_peer(vectors):
    def peer(row):
        return bool(_fatals(row) & PEER_FATALS) or any(
            event.get("type") in PEER_EVENTS or (type(event.get("payload")) is dict and event["payload"].get("reason") == "PEER_FAILURE")
            for event in row["events"])
    return [row["id"] for row in vectors["transcripts"] if peer(row)]


def _direction(vectors):
    return [row["id"] for row in vectors["transcripts"] if "DIRECTION" in _fatals(row)]


def _earlier_version(key):
    return lambda vectors: [row["id"] for row in vectors[key] if EARLIER_VERSION.search(row["intent"])]


def _counterexample_23(vectors):
    return [row["id"] for row in vectors["transcripts"] if row["intent"].startswith("Counterexample 23")]


def _i06_version(vectors):
    ids = [row["id"] for key in ("evidenceNegative", "snapshotNegative") for row in vectors[key]
           if re.search(r"another version|not a v3 record", row["refusal"])]
    return ids + [row["id"] for row in vectors["crossVersion"]]


_MISSING = object()


def _at(value, path):
    for key in path:
        if type(value) is dict and key in value:
            value = value[key]
        elif type(value) is list and type(key) is int and 0 <= key < len(value):
            value = value[key]
        else:
            return _MISSING
    return value


def _native_role(row, roles):
    """Review R3-1: the plan's G06 and counterexample 14 put the native record's process roles in this case."""
    if "another role" in row["refusal"]:
        return True
    executables = {name: role.get("executable") for name, role in roles.items()}
    for op in row["ops"]:
        path, value = op["path"], op.get("value")
        if row["target"] == "record" and path[:1] == ["roles"]:
            if len(path) == 2:
                return True
            distinctive = (type(value) is str and value != "") or (type(value) is int and type(value) is not bool and value > 1)
            if op["op"] == "set" and distinctive and any(name != path[1] and _at(role, path[2:]) == value for name, role in roles.items()):
                return True
        if row["target"] == "capture":
            image = value.get("path") if type(value) is dict else value
            if path == ["role"] or any(name != row.get("role") and image == executable for name, executable in executables.items()):
                return True
    return False


def _native_role_version(vectors):
    ids = [row["id"] for row in vectors["negative"]
           if "not a v3 record" in row["refusal"] or EARLIER_VERSION.search(row["intent"])
           or _native_role(row, vectors["positive"][row["positive"]]["record"]["roles"])]
    return ids + [row["id"] for row in vectors["crossVersion"]]


PEER_BASIS = ("a transcript whose output is fatal PEER_CHANGED, PEER_LOST or PEER_QUALIFICATION_MISMATCH, or that carries a "
              "PEER_CHANGED or W_PEER_CHANGED event or a close with reason PEER_FAILURE")
ROLE_BASIS = "a transcript whose output is fatal DIRECTION: a frame sent in the other channel role's direction"
VERSION_BASIS = "a vector whose intent names an earlier contract version (v1 or v2): a frame or configuration of another version"
SELECTORS = [
    ("MATRIX:wrong peer", "I05 gate channel v3", "transcripts", I05, PEER_BASIS, _wrong_peer),
    ("MATRIX:wrong peer", "I07 policy write v3", "transcripts", I07, PEER_BASIS, _wrong_peer),
    ("MATRIX:role/version mismatch", "I05 gate channel v3", "configRefusals", I05, VERSION_BASIS, _earlier_version("configRefusals")),
    ("MATRIX:role/version mismatch", "I05 gate channel v3", "frames", I05, VERSION_BASIS, _earlier_version("frames")),
    ("MATRIX:role/version mismatch", "I05 gate channel v3", "transcripts", I05, ROLE_BASIS, _direction),
    ("MATRIX:role/version mismatch", "I07 policy write v3", "frames", I07, VERSION_BASIS, _earlier_version("frames")),
    ("MATRIX:role/version mismatch", "I07 policy write v3", "transcripts", I07, ROLE_BASIS, _direction),
    ("MATRIX:role/version mismatch", "I06 backend profile v2", "vectors", I06,
     "a negative refused as another version or not a v3 record, and every cross-version case", _i06_version),
    ("MATRIX:role/version mismatch", "Native qualification profile v3", "vectors", NAT,
     "a negative refused as not a v3 record or whose intent names v1 or v2; a negative on the record's process roles (the "
     "plan's G06 and counterexample 14): a role added or removed, a role given another role's distinctive value (a non-empty "
     "string or an integer above 1 at the same field), a capture rebound to another role or running another role's "
     "executable, or a refusal naming another role; and every cross-version case", _native_role_version),
    ("CE23", "I07 policy write v3", "transcripts", I07, "the transcript whose intent is Counterexample 23 (the channel-level refusals)",
     _counterexample_23),
]


def selections():
    """The selected vectors of each mixed-set case, by the rules above over the pinned vectors."""
    return [{"case": case, "contract": contract, "vectorSet": vector_set, "basis": basis,
             "ids": rule(_models.data(prefix + "vectors.json"))}
            for case, contract, vector_set, prefix, basis, rule in SELECTORS]
