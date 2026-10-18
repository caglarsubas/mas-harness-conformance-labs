"""TG-01 replays: each adopted contract's vectors through its snapshotted reference model (W04-2, CONF-ENF-002).

Expected results come only from the vectors; the models are the adopted contracts' reference models, never an
implementation. Every vector is replayed in full, and any difference raises Mismatch naming the vector. Each replay
returns a Tally of the vector ids in each result.

The nine vector sets whose models need jsonschema (CHILD_SETS) run in a child process on the pinned met-001 venv python
(CONF-ENF-009, owner decisions Q-LC-1..4, 2026-10-18; `_child.py`): in this interpreter, which stays standard library
only, each of them runs its standard-library pre-checks and then returns the child's verified tally. A replay that still
reaches a missing jsonschema import is counted NOT_RUN_ENV_UNAVAILABLE (owner decision Q-T4), and the parent refuses any
such id from the child, so no child set can be NOT_RUN.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import re

import _models

I05 = "architecture/i05-gate-channel-v3/"
I05_SUPPLEMENT = "architecture/i05-gate-channel-v3-supplement/"
I07 = "architecture/i07-policy-write-v3/"
ADM = "architecture/admission-semantics-v3/"
SEL = "architecture/selinux-matrix-v2/"
SEC = "architecture/seccomp-allowlists-v2/"
I06 = "architecture/i06-backend-profile-v2/"
NAT = "architecture/native-profile-v3/"
# I07's writer identity values, as the I07 v3 contract states them for the qualification namespace.
I07_NAMESPACE, I07_AUTHORITY = "planeon-qual", "127.0.0.1:6443"
I06_V1 = "architecture/i06-backend-profile/"
NAT_V2 = "architecture/native-profile-v2/"
NAT_V1 = "architecture/native-qualification-inputs/"
# True only inside the child process (set by child_report on this module), where the jsonschema replays run.
IN_CHILD = False


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


def _i05_frames():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["frames"]:
        tally.run(row["id"], lambda: require(refusal(lambda: model.check_frame(row["frame"], schema)) == row["expect"], "I05 frame " + row["id"]))
    return tally


INPUT_TYPES = {"bytes": bytes, "bytearray": bytearray, "str": lambda raw: raw.decode("ascii")}


def _i05_byte_frames():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["byteFrames"]:
        raw = INPUT_TYPES[row["inputType"]](base64.b64decode(row["base64"], validate=True))
        tally.run(row["id"], lambda: require(refusal(lambda: model.decode_frame(raw, schema)) == row["expect"], "I05 byte frame " + row["id"]))
    _i05_byte_frames_pre()
    return tally


def _i05_byte_frames_pre():
    vectors = _models.data(I05 + "vectors.json")
    require([row["id"] for row in vectors["byteFrames"]] == ["B%02d" % n for n in range(1, 15)], "I05 byte checks in order")


def _i05_transcripts():
    model, schema, vectors = _i05()
    tally = Tally()
    for row in vectors["transcripts"]:
        def check(row=row):
            outputs, final = model.replay(vectors["configs"][row["config"]], row["events"], schema)
            require(outputs == row["outputs"] and final == row["final"], "I05 transcript " + row["id"])
        tally.run(row["id"], check)
    return tally


# I05 v3 supplement (owner decision Q-T10, 2026-10-13) ---------------------------------------------------------------
# Six transcripts in the v3 transcript format from harness-onion 93d32e1, replayed by the pinned v3 model with the v3
# configuration they name by reference. A transcript with `equals` must also give, for every event that is not a
# storage or marker failure injection, the same output as the named transcript, and the same final snapshot.

INJECTIONS = {"STORAGE_FAIL_NEXT", "STORAGE_FAIL_AFTER", "MARKER_FAIL_NEXT"}


def _plain(row):
    return [output for event, output in zip(row["events"], row["outputs"]) if event["type"] not in INJECTIONS]


def _i05_supplement_checks(supplement, row, by_id):
    """The standard-library checks of one supplement transcript (Q-T10, review R1-10); they run before the model."""
    reference = supplement["configs"][row["config"]]
    require(set(reference) == {"vectorsPath", "key"} and reference["vectorsPath"] == I05 + "vectors.json"
            and reference["key"] == ["configs", row["config"]], "I05 supplement configuration " + row["id"])
    require(set(row) <= {"id", "intent", "config", "events", "outputs", "final", "equals"}
            and len(row["outputs"]) == len(row["events"]), "I05 supplement transcript shape " + row["id"])
    if "equals" in row:  # optional in the supplement format
        require(row["equals"] in by_id and row["equals"] != row["id"], "I05 supplement equals target " + row["id"])
        other = by_id[row["equals"]]
        require(_plain(row) == _plain(other) and row["final"] == other["final"], "I05 supplement equals " + row["id"])


def _i05_supplement_pre():
    """The supplement's whole standard-library part: its contract binding and every transcript's own checks."""
    supplement = _models.data(I05_SUPPLEMENT + "vectors.json")
    manifest = {row["path"]: row["sha256"] for row in _models._manifest()["files"]}
    require(supplement["contract"] == {"path": I05 + "vectors.json", "sha256": manifest[I05 + "vectors.json"],
                                       "model": {"path": "scripts/i05_gate_channel_v3.py",
                                                 "sha256": manifest["scripts/i05_gate_channel_v3.py"]}},
            "the supplement names the pinned v3 vectors and model")
    by_id = {row["id"]: row for row in supplement["transcripts"]}
    for row in supplement["transcripts"]:
        _i05_supplement_checks(supplement, row, by_id)
    return supplement, by_id


def _i05_supplement():
    supplement, by_id = _i05_supplement_pre()
    model, schema, vectors = _i05()
    tally = Tally()
    for row in supplement["transcripts"]:
        def check(row=row):
            _i05_supplement_checks(supplement, row, by_id)
            outputs, final = model.replay(vectors["configs"][row["config"]], row["events"], schema)
            require(outputs == row["outputs"] and final == row["final"], "I05 supplement transcript " + row["id"])
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


def _i07_frames():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for row in vectors["frames"]:
        def check(row=row):
            got = refusal(lambda: model.check_frame(row["frame"], schema))
            require((got.split(" ", 1)[0] if got else None) == row["expect"], "I07 frame check " + row["id"])
        tally.run(row["id"], check)
    return tally


def _i07_byte_frames():
    model, kinds, schema, vectors = _i07()
    tally = Tally()
    for row in vectors["byteFrames"]:
        def check(row=row):
            got = refusal(lambda: model.decode_frame(base64.b64decode(row["base64"], validate=True), schema))
            require((got.split(" ", 1)[0] if got else None) == row["expect"], "I07 byte frame check " + row["id"])
        tally.run(row["id"], check)
    return tally


def _i07_transcripts():
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


# The child sets (CONF-ENF-009, owner decisions Q-LC-1..4, 2026-10-18) ---------------------------------------------
# These nine vector sets need jsonschema: I05 and I07 through check_frame, I06 v2 and native v3 when their models load.
# In this interpreter each runs its standard-library pre-checks and returns the child's verified tally (_child.py); in
# the child process (IN_CHILD) each runs its full replay. Expected results come only from the vector files.

CHILD_SETS = (
    ("I05 gate channel v3", "frames"),
    ("I05 gate channel v3", "byteFrames"),
    ("I05 gate channel v3", "transcripts"),
    ("I05 gate channel v3", "supplement"),
    ("I07 policy write v3", "frames"),
    ("I07 policy write v3", "byteFrames"),
    ("I07 policy write v3", "transcripts"),
    ("I06 backend profile v2", "vectors"),
    ("Native qualification profile v3", "vectors"),
)


def _dispatch(key, replay, pre=None):
    if pre is not None:
        pre()
    if IN_CHILD:
        return replay()
    from tg01_contract import _child
    return _child.tally(key)


def i05_frames():
    return _dispatch(CHILD_SETS[0], _i05_frames)


def i05_byte_frames():
    return _dispatch(CHILD_SETS[1], _i05_byte_frames, _i05_byte_frames_pre)


def i05_transcripts():
    return _dispatch(CHILD_SETS[2], _i05_transcripts)


def i05_supplement():
    return _dispatch(CHILD_SETS[3], _i05_supplement, _i05_supplement_pre)


def i07_frames():
    return _dispatch(CHILD_SETS[4], _i07_frames)


def i07_byte_frames():
    return _dispatch(CHILD_SETS[5], _i07_byte_frames)


def i07_transcripts():
    return _dispatch(CHILD_SETS[6], _i07_transcripts)


def i06_v2_vectors():
    return _dispatch(CHILD_SETS[7], _i06_v2_replay)


def native_v3_vectors():
    return _dispatch(CHILD_SETS[8], _native_v3_replay)


# Closed vector operations, each the adopted layer's own (harness-onion a2eab93): I06 v2's admits a dict selector that
# must match exactly one list element; native v3's uses plain keys. Both add `append` to set and delete.

def _locate(node, key):
    if type(key) is dict:
        found = [index for index, item in enumerate(node) if type(item) is dict and all(item.get(k) == v for k, v in key.items())]
        require(len(found) == 1, "vector selector must match exactly one element")
        return found[0]
    return key


def apply_i06(value, ops):
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"], "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[_locate(node, key)]
        if op["op"] == "set":
            node[_locate(node, last)] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[_locate(node, last)]
        else:
            node[_locate(node, last)].append(copy.deepcopy(op["value"]))
    return value


def apply_native(value, ops):
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"], "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[last]
        else:
            node[last].append(copy.deepcopy(op["value"]))
    return value


def _loaded(name, ids, tally):
    """The model, or None after recording every id NOT_RUN when its load reaches a missing jsonschema (Q-T4)."""
    try:
        return _models.model(name)
    except ModuleNotFoundError as exc:
        if exc.name != "jsonschema":
            raise
        tally.ids["NOT_RUN_ENV_UNAVAILABLE"].extend(ids)
        return None


# I06 backend profile v2 ----------------------------------------------------------------------------------------------
# As a2eab93's validate_i06_v2_vectors replays each vector, without its contract-history sets (CHANGED_REPLAYS,
# MOVED_ACCEPTED, DISTINCTNESS), which check the contract's history rather than a vector's result.

I06_KEYS = ("evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative", "crossVersion")
I06_HEADER = {"evidenceClass", "kubernetesBaseline", "qualificationNamespace", "v1Vectors", "w02aBackend", "evidencePositive",
              "snapshotPositive", "evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative", "crossVersion"}
# The evidenceNegative rows that record the production refusal of a test-only backend; the positive pre-check takes
# its text from them (design review D2-7).
I06_PRODUCTION_ROWS = ("E35", "G12")


def _i06_ids(vectors):
    return [row["id"] for key in I06_KEYS for row in vectors[key]]


def _i06_v2_replay():
    vectors = _models.data(I06 + "vectors.json")
    ids = _i06_ids(vectors)
    tally = Tally()
    model = _loaded("i06_backend_profile_v2", ids, tally)
    if model is None:
        return tally
    v1_raw = _models.snapshot_bytes(I06_V1 + "vectors.json")
    v1_vectors = _models.data(I06_V1 + "vectors.json")
    inventory = _models.data(I06_V1 + "writer-inventory.json")
    closure = _models.data(I06_V1 + "identity-closure.json")
    bootstrap = _models.data(I06_V1 + "upstream-bootstrap-rbac-v1.37.1.json")
    w02a_vectors, w02a_schema = _models.data(NAT + "vectors.json"), _models.data(NAT + "qualification.schema.json")
    w02a_v2_vectors = _models.data(NAT_V2 + "vectors.json")
    require(type(vectors) is dict and set(vectors) == I06_HEADER and vectors["evidenceClass"] == "DATA_CHECK_ONLY"
            and vectors["kubernetesBaseline"] == "v1.37.1"
            and vectors["v1Vectors"] == {"path": I06_V1 + "vectors.json", "sha256": hashlib.sha256(v1_raw).hexdigest()}
            and vectors["w02aBackend"] == {"vectors": NAT + "vectors.json", "schema": NAT + "qualification.schema.json",
                                           "positive": 0}, "I06 v2 vectors header")
    namespace = vectors["qualificationNamespace"]
    evidence, snapshot = vectors["evidencePositive"], vectors["snapshotPositive"]
    positives = w02a_vectors["positive"]
    require(namespace == v1_vectors["qualificationNamespace"] and snapshot == v1_vectors["snapshotPositive"]
            and evidence["schemaVersion"] == model.EVIDENCE_VERSION
            and {key: value for key, value in evidence.items() if key not in ("schemaVersion", "w02aRecord")}
            == {key: value for key, value in v1_vectors["evidencePositive"].items() if key != "schemaVersion"}
            and evidence["w02aRecord"] == {"schemaVersion": model.W02A_VERSION,
                                           "qualificationDigest": model.record_digest(positives[0]["record"])},
            "I06 v2 positives are the v1 positives bound to W02a v3 positive 0")
    production = {row["refusal"] for row in vectors["evidenceNegative"] if row["id"] in I06_PRODUCTION_ROWS}
    require(len(production) == 1 and sum(row["id"] in I06_PRODUCTION_ROWS for row in vectors["evidenceNegative"]) == 2,
            "I06 v2 production refusal recorded by its vectors")

    def w02a(row):
        p = positives[row.get("w02aPositive", 0)]
        return apply_i06(p["record"], row["backendOps"]), p["profile"], p["endpoints"]

    def bound(record):
        base = copy.deepcopy(evidence)
        base["w02aRecord"]["qualificationDigest"] = model.record_digest(record)
        return base

    def evidence_result(row):
        record, profile, endpoints = w02a(row)
        return model.explain(model.check_evidence, apply_i06(bound(record), row["ops"]), inventory, record, profile,
                             endpoints, w02a_schema, row["testFixture"])

    def snapshot_result(row):
        return model.explain(model.check_rbac_snapshot, apply_i06(snapshot, row["ops"]), closure, inventory, bootstrap,
                             row.get("namespace", namespace))

    record, profile, endpoints = positives[0]["record"], positives[0]["profile"], positives[0]["endpoints"]
    require(model.explain(model.check_evidence, evidence, inventory, record, profile, endpoints, w02a_schema, True) is None
            and model.explain(model.check_evidence, evidence, inventory, record, profile, endpoints, w02a_schema, False)
            in production
            and model.explain(model.check_rbac_snapshot, snapshot, closure, inventory, bootstrap, namespace) is None,
            "I06 v2 positives: accepted as a fixture, refused in production, snapshot accepted")
    for row in vectors["evidenceAccepted"]:
        tally.run(row["id"], lambda row=row: require(row["testFixture"] is True and evidence_result(row) is None,
                                                     "I06 v2 evidenceAccepted vector " + row["id"]))
    for row in vectors["snapshotAccepted"]:
        tally.run(row["id"], lambda row=row: require(snapshot_result(row) is None, "I06 v2 snapshotAccepted vector " + row["id"]))
    for key, replay in (("evidenceNegative", evidence_result), ("snapshotNegative", snapshot_result)):
        for row in vectors[key]:
            def check(row=row, key=key, replay=replay):
                result = replay(row)
                require(result is not None and result == row["refusal"], "I06 v2 %s vector %s" % (key, row["id"]))
            tally.run(row["id"], check)
    old_record = w02a_v2_vectors["positive"][0]["record"]
    old_backend = {"backendProfile": old_record["backendProfile"], "backendComponents": old_record["backendComponents"]}
    for row in vectors["crossVersion"]:
        def cross(row=row):
            if row["subject"] == "snapshot":
                value = apply_i06(snapshot, row["ops"])
                v1 = model.v1.explain(model.v1.check_rbac_snapshot, value, closure, inventory, bootstrap, row["namespace"])
                v2 = snapshot_result({"ops": row["ops"], "namespace": row["namespace"]})
                require(v1 is None and row["v1Result"] == v1 and v2 is not None and row["v2Result"] == v2,
                        "I06 v2 crossVersion vector " + row["id"])
                return
            require(row["subject"] == "evidence" and row["v1Subject"] in ("v1", "v2") and row["v2Subject"] in ("v1", "v2"),
                    "I06 v2 closed cross-version vector " + row["id"])
            current, current_profile, current_endpoints = w02a(row)
            bases = {"v1": v1_vectors["evidencePositive"], "v2": bound(current)}
            v1 = model.v1.explain(model.v1.check_evidence, apply_i06(bases[row["v1Subject"]], row["ops"]), inventory,
                                  apply_i06(old_backend, row["backendOps"]), row["production"])
            v2 = model.explain(model.check_evidence, apply_i06(bases[row["v2Subject"]], row["ops"]), inventory, current,
                               current_profile, current_endpoints, w02a_schema, not row["production"])
            require(row["v1Result"] == v1 and row["v2Result"] == v2, "I06 v2 crossVersion vector " + row["id"])
        tally.run(row["id"], cross)
    require(len(ids) == len(set(ids)), "unique I06 v2 vector identifiers")
    return tally


# Native qualification profile v3 -------------------------------------------------------------------------------------
# As a2eab93's validate_v3_vectors replays each vector. Its validate_v3_schema and the schema's own label-slot and
# closure bindings are contract checks, not vector replays, and stay with the adopted packet (design review D2-4).

NAT_KEYS = ("negative", "accepted", "crossVersion", "migration")


def _native_ids(vectors):
    return ["positive:%d" % index for index in range(len(vectors["positive"]))] + [
        row["id"] for key in NAT_KEYS for row in vectors[key]]


def _native_v3_replay():
    vectors = _models.data(NAT + "vectors.json")
    ids = _native_ids(vectors)
    tally = Tally()
    model = _loaded("native_qualification_v3", ids, tally)
    if model is None:
        return tally
    schema = _models.data(NAT + "qualification.schema.json")
    v1_schema, v1_vectors = _models.data(NAT_V1 + "qualification.schema.json"), _models.data(NAT_V1 + "vectors.json")
    v2_schema, v2_vectors = _models.data(NAT_V2 + "qualification.schema.json"), _models.data(NAT_V2 + "vectors.json")

    def pin(value):
        return model.digest(model.canonical(value))

    require(vectors["schemaSha256"] == model.SCHEMA_SHA256 == pin(schema)
            and vectors["v1SchemaSha256"] == model.V1_SCHEMA_SHA256 == pin(v1_schema)
            and vectors["v2SchemaSha256"] == model.V2_SCHEMA_SHA256 == pin(v2_schema)
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
            and vectors["tenantAcceptance"] is False, "native v3 vectors bound to the pinned schemas")
    history1 = [row["record"] for row in v1_vectors["positive"]]
    history = [row["record"] for row in v2_vectors["positive"]]
    positives = vectors["positive"]

    def qualify(p, bundle, test_fixture=True):
        return model.explain(model.check_qualification, p["record"], p["profile"], p["endpoints"], bundle["captures"],
                             bundle["lifecycle"], bundle["backendCaptures"], history1, history, v1_schema, v2_schema,
                             schema, False, test_fixture)

    for index, p in enumerate(positives):
        tally.run("positive:%d" % index, lambda p=p, index=index: require(
            qualify(p, p) is None, "native v3 positive vector positive:%d" % index))
    for kind in ("negative", "accepted"):
        for row in vectors[kind]:
            def check(row=row, kind=kind):
                p = positives[row["positive"]]
                profile = apply_native(p["profile"], row.get("profileOps", []))
                endpoints = apply_native(p["endpoints"], row.get("endpointOps", []))
                target = row["target"]
                if target == "record":
                    record = apply_native(p["record"], row["ops"])
                    if row.get("rebindProfile"):
                        record["profileDigest"] = "sha256:" + pin(profile)
                    result = model.explain(model.check_record, record, profile, endpoints, schema)
                elif target == "capture":
                    capture = apply_native(next(c for c in p["captures"] if c["role"] == row["role"]), row["ops"])
                    result = model.explain(model.check_capture, p["record"], capture, row["role"], schema)
                elif target == "lifecycle":
                    result = model.explain(model.check_lifecycle_capture, p["record"], apply_native(p["lifecycle"], row["ops"]),
                                           schema)
                elif target == "backend":
                    capture = apply_native(next(c for c in p["backendCaptures"] if c["component"] == row["component"]),
                                           row["ops"])
                    result = model.explain(model.check_backend_capture, p["record"], capture, schema)
                else:
                    require(target == "qualification", "native v3 closed vector target " + row["id"])
                    bundle = apply_native({key: p[key] for key in ("captures", "lifecycle", "backendCaptures")}, row["ops"])
                    result = qualify(p, bundle, row.get("testFixture", True))
                require(result == (row["refusal"] if kind == "negative" else None), "native v3 %s vector %s" % (kind, row["id"]))
            tally.run(row["id"], check)
    under_v3 = {"V2_CAPTURE_UNDER_V3": lambda old: (old["captures"][0], model.check_capture, ("SERVER",)),
                "V2_LIFECYCLE_UNDER_V3": lambda old: (old["lifecycle"], model.check_lifecycle_capture, ()),
                "V2_BACKEND_CAPTURE_UNDER_V3": lambda old: (old["backendCaptures"][0], model.check_backend_capture, ())}
    under_v2 = {"V3_RECORD_UNDER_V2": lambda p: (p["record"], "record"),
                "V3_CAPTURE_UNDER_V2": lambda p: (p["captures"][0], "capture"),
                "V3_LIFECYCLE_UNDER_V2": lambda p: (p["lifecycle"], "lifecycleCapture"),
                "V3_BACKEND_CAPTURE_UNDER_V2": lambda p: (p["backendCaptures"][0], "backendCapture")}
    for row in vectors["crossVersion"]:
        def cross(row=row):
            p = positives[row["index"]]
            if row["kind"] == "V2_RECORD_UNDER_V3":
                result = model.explain(model.check_record, history[row["index"]], p["profile"], p["endpoints"], schema)
                require(result == row["expect"] and row["expect"] == "not a v3 record", "native v3 crossVersion vector " + row["id"])
            elif row["kind"] in under_v3:
                value, check_fn, args = under_v3[row["kind"]](v2_vectors["positive"][row["index"]])
                require(model.explain(check_fn, p["record"], value, *args, schema) == row["expect"],
                        "native v3 crossVersion vector " + row["id"])
            else:
                require(row["kind"] in under_v2, "native v3 closed cross-version kind " + row["id"])
                value, variant = under_v2[row["kind"]](p)
                errors = {(error.json_path, error.validator) for error in model.schema_errors(value, v2_schema, variant)}
                require(type(row["mustInclude"]) is list and row["mustInclude"] != []
                        and all(tuple(pair) in errors for pair in row["mustInclude"]), "native v3 crossVersion vector " + row["id"])
        tally.run(row["id"], cross)
    for row in vectors["migration"]:
        def migrate(row=row):
            p = positives[row["positive"]]
            profile = apply_native(p["profile"], row.get("profileOps", []))
            record = apply_native(p["record"], row.get("ops", []))
            if row.get("rebindProfile"):
                record["profileDigest"] = "sha256:" + pin(profile)
            old1 = [copy.deepcopy(history1[index]) for index in row["v1Positives"]]
            old2 = [copy.deepcopy(history[index]) for index in row["v2Positives"]]
            for key, olds in (("v1Ops", old1), ("v2Ops", old2)):
                for change in row.get(key, []):
                    olds[change["index"]] = apply_native(olds[change["index"]], change["ops"])
            result = model.explain(model.check_migration, old1, old2, record, profile, v1_schema, v2_schema, schema,
                                   row.get("noEarlierHistory", False))
            require(result == row["expect"], "native v3 migration vector " + row["id"])
        tally.run(row["id"], migrate)
    require(len(ids) == len(set(ids)), "unique native v3 vector identifiers")
    return tally


# The parent's own ids per child set, from the pinned vector files (design review D1-9), and the child's report ------

def expected_ids(key):
    contract, vector_set = key
    if key == CHILD_SETS[3]:
        return [row["id"] for row in _models.data(I05_SUPPLEMENT + "vectors.json")["transcripts"]]
    if key == CHILD_SETS[7]:
        return _i06_ids(_models.data(I06 + "vectors.json"))
    if key == CHILD_SETS[8]:
        return _native_ids(_models.data(NAT + "vectors.json"))
    require(key in CHILD_SETS, "not a child set")
    prefix = I05 if contract == "I05 gate channel v3" else I07
    return [row["id"] for row in _models.data(prefix + "vectors.json")[vector_set]]


# One pinned flip per child set (design review D2-2): the vector's expectation is replaced in memory by a sentinel, the
# set is replayed again, and Mismatch must name that vector. Each target reaches the jsonschema-dependent model call
# before its expectation is compared, and none is linked by `equals`.
FLIPS = {
    CHILD_SETS[0]: (I05 + "vectors.json", "frames", "G01", "expect"),
    CHILD_SETS[1]: (I05 + "vectors.json", "byteFrames", "B01", "expect"),
    CHILD_SETS[2]: (I05 + "vectors.json", "transcripts", "T01", "final"),
    CHILD_SETS[3]: (I05_SUPPLEMENT + "vectors.json", "transcripts", "S05", "final"),
    CHILD_SETS[4]: (I07 + "vectors.json", "frames", "G01", "expect"),
    CHILD_SETS[5]: (I07 + "vectors.json", "byteFrames", "B01", "expect"),
    CHILD_SETS[6]: (I07 + "vectors.json", "transcripts", "T01", "final"),
    CHILD_SETS[7]: (I06 + "vectors.json", "evidenceNegative", "E01", "refusal"),
    CHILD_SETS[8]: (NAT + "vectors.json", "negative", "R02", "refusal"),
}


def _flip(key):
    path, list_key, ident, field = FLIPS[key]
    original = _models.data

    def forged(relative):
        value = original(relative)
        if relative == path:
            rows = [row for row in value[list_key] if row["id"] == ident]
            require(len(rows) == 1, "flip target " + ident)
            rows[0][field] = {"flipped": True} if field == "final" else "FLIPPED"
        return value

    _models.data = forged
    try:
        REPLAYS[key]()
    except Mismatch as exc:
        return re.search(r"\b%s\b" % re.escape(ident), str(exc)) is not None
    finally:
        _models.data = original
    return False


def child_report():
    """Run inside the child: every child set's tally, then its pinned flip."""
    global IN_CHILD
    IN_CHILD = True
    tallies = {"|".join(key): REPLAYS[key]().ids for key in CHILD_SETS}
    flips = {"|".join(key): {"id": FLIPS[key][2], "field": FLIPS[key][3], "caught": _flip(key)} for key in CHILD_SETS}
    return tallies, flips


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
    ("I05 gate channel v3", "supplement"): i05_supplement,
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
    ("I05 gate channel v3", "supplement"): ["MATRIX:transcript replay"],
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
