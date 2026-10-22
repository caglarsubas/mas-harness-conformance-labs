"""Oracle tests for CONF-MAS-005, written outside the candidate (owner decision D5a).

These tests are black-box. They call only the interface the oracle brief names: ``_ledger.load_config()``,
``_ledger.run(config, cls, seed, bypass, arm, until_deadline, *, labels, scriptedEvents, policy)``,
``_ledger.ledger()``, ``_ledger.OVER_REVISION_READINGS``, ``_ledger.campaign_record()`` and ``_ledger.serialize()``.
Every expectation comes from DESIGN revision 3 (sections 2, 4 to 6 and 8 to 10), BUILD_NOTES' binding rules D3-1 to
D3-5 and its build-time additions, the candidate's declarative data files (classes.json, contracts.json,
attestation-p4.json, attestation-p5.json), and packet 4's ledger, campaign record and classes.json as committed at
2d7130a (tree 7b2190ef; the digests below). None is a snapshot of the candidate's output.

Each simulation run is made once and checked at once, so memory stays flat: C13 in every seed, defended, under each
of its 6 controls and 3 depth checks (320 runs); one defended run of each of C1 to C12 (12 runs); and 4 seeds of each
of the G6 bed's three points (12 runs, the survey bound). Then one in-process ledger and one campaign record.
"""

import hashlib
import json
import pathlib
import sys
import unittest

_HERE_PATH = pathlib.Path(__file__).resolve().parent
_HERE = str(_HERE_PATH)
if not sys.path or sys.path[0] != _HERE:
    sys.path.insert(0, _HERE)

import _ledger  # noqa: E402  (the candidate's run entry, used through its interface only)


# ---------------------------------------------------------------------------------------------
# Constants from packet 4's committed ledger, campaign record and classes.json at 2d7130a (tree 7b2190ef)

# sha256 of each ledger row and section as canonical JSON (sorted keys, separators "," and ":", ASCII), computed
# from 2d7130a's tests/mas/results.json. C1 to C10 and the arms equal packet 4's oracle's digests.
P4_ROW_SHA256 = {
    "C1": "b3ae188401761d30a75902c2c88fcf2924e6411ea8227c570242d4eb02642ce4",
    "C2": "aa6dc7c60a0e51f2e9e8dd3099b0d35dc9231195e8bd3fd1b65f79880c4e4565",
    "C3": "74a874d78e0c03186381e78766faf3912ce019622202e6532461b31ebdbd66d4",
    "C4": "ab21c9bb5d0692da48a6ec2d3f22c7070b0e1b81dce130c4b5a05eae3b7ec619",
    "C5": "2ee5ad5d482b77fee15925dda13763815bf4c57d91fcae530794e66d28189e10",
    "C6": "5a1988368aa2d212153ad7fc44f4427c8f70a447dfc715fd3e24126a84ea2ef3",
    "C7": "4439b7cd2675ee00a00ae406c559540029e93d894f455cae4b00b8aa2a491713",
    "C8": "92b999f15ddfdce224fd9f19a08e9eed9be3fa6dceb9ef83d3ced265d02e7ac3",
    "C9": "45fc3528881275d75974aad8adbcf2428d8197405163578bb180413c603a3832",
    "C10": "317d58dd0196053e36c2ffce47e5863f68c4b8b957ccd895db4950d808604df6",
    "C11": "1d254b2918578ff1fba9117d426f868fddaab556f81c61ed494a30ffad94000e",
    "C12": "36485582e47afa372475680f6ce423d310c03c50788446887e807593b63b3ae8",
}
P4_LEDGER_SECTION_SHA256 = {
    "arms": "fa1e7481fd20fb73fccc68950a822895c83192d295a7f6caa35e4095bbdd54f6",
    "scaling": "3ed7224c4189c2e9d4219d3d98a7f34d2da4009d7dd955bf195b483e15a97d08",
    "hardCoding": "3de3d420f2dc855ea39f8df292db80b4b667c7a2240f1a530474bff61eafe11f",
}
# sha256 of 2d7130a's results.json as committed (DESIGN section 8: the constant 7149f09d...).
P4_RESULTS_SHA256 = "7149f09d3585bd8c9a8cbf4ab075abd09e75a74b110fddbfdef5b8125470bb77"
# Packet 4's ledger rule (1405 ASCII characters), its profile and its eleven keys, from the same file.
P4_RULE_LEN = 1405
P4_RULE_SHA256 = "42724c42c843862e56eace260ffbe2ab4bb49bb18eefd888ffdbed42df638c20"
P4_PROFILE = "python-conformance-stdlib (Python 3.12, standard library only)"
P4_LEDGER_KEYS = {"arms", "classes", "classesSha256", "contractsCommit", "hardCoding", "packet", "profile", "rule",
                  "scaling", "schemaVersion", "seeds"}

# Canonical sha256 of 2d7130a's classes.json entries C1 to C12 and of its unchanged sections (section 1: byte-identical).
P4_CLASS_SHA256 = {
    "C1": "d2ea5396e46556c94143caf3ab0e62020737d300929a587ca19f376b3e26ee6a",
    "C2": "ec502133d35db381d87c23cc57c55c24bf3f608adca192d5d055fd763e754d4a",
    "C3": "5f558b9225e855d38349251354ad52e3784519ee55b4e97e1aa2caf0bf2492ff",
    "C4": "6265811bdd5967603dedd51806bd987dc1e98914cc492aa0e6f77390bbbcda6c",
    "C5": "98341ad1fc661f004e120cb2d2c0fd1d3a1b3012758aa2b3ffa679a8095b8dc2",
    "C6": "60d97f77c757582be46041dd8b624fa8ccbfe04c4d6315f59191d9556d342a03",
    "C7": "4d7983d7cc66caa5e98f46764c565b074361beb89494043c51f2030c3460b08f",
    "C8": "33ef99ae53d4914be46fffd1866de6d5e34a713205d6320b7161711809a6e74c",
    "C9": "53c5bead40727c6fade44e0608763a220336e7b84bcce4207af38803e5ac59c5",
    "C10": "5ed72c68cfe91f56753757573a1198153b11bc8fca4b5f5fee93c0480aad91cf",
    "C11": "dab5580009aa30489948a37fec140fc804da6c1ba09c0fce2e662ebc9b8f10d0",
    "C12": "8771ca6e7ad784b313f9f6bc64857aa82828e66849d77628150587ec3081c34f",
}
P4_CLASSES_SECTION_SHA256 = {
    "arms": "f22cf5291c98f446aa4effc79b552c0c0544d12351c8f6753c590b2f08c76e8d",
    "scaling": "d9aa29d7e583a2c45e6d7e103f4ff909ec0239434f86661d07ba23bad6b713d3",
    "hardCoding": "52205ef6a6b2214e8839e5dd4ae3ab09e0b5538441f7925683686a54a6443c1d",
    "manifest": "c00cad9694a8c3a57c8e4905519a63087221653ce36d1e4c2d75ac53ed9d41a0",
    "profiles": "4c3da2d3a1d3b5a2a1f75aaaf4bd22bbec92e5730883a7ead9a3c5764e7fc0b0",
    "inputSchemas": "0cbce80399de46cea661b79087cb32c25ba0a6fe61603f537a74a12cfc220d85",
    "instructions": "759e25c4094e3e1631bf59fd5e1b8ef1ce78c78e65bb520183d59b8a6a279cf0",
}
# The fourteen topologies at 2d7130a (every existing topology stays byte-identical), and the other top-level keys.
P4_TOPOLOGIES_SHA256 = "9cfde6a727be572f773e012cc68b705e5f341ac80c69e2b933810a0e22530957"
P4_REST_KEYS = ("arms", "bounds", "controlGate", "grantTicks", "hardCoding", "inputSchemas", "instructions",
                "manifest", "profiles", "scaling", "seeds", "shared", "unexercisedInvariants", "zeroTolerance")
P4_REST_SHA256 = "dc053ff8d07993b0fdf84284a1a5468b46a6704b8558073f6e0d5c98cbf569ef"
P4_CLASSES_KEYS = set(P4_REST_KEYS) | {"classes", "packet", "schemaVersion", "streams", "topologies"}
P4_STREAMS = ["lat-<agent>", "stall-<agent>", "poison-<agent>", "read-<agent>", "sched-c3", "sched-c7", "sched-c8",
              "task-problem", "perm-items"]

# 2d7130a's campaign record v2: packets 1 to 4's entries, and the canonical sha256 of its unchanged sections and of the
# prefixes that packet 5 extends.
P4_PACKETS = [
    {"commit": "05b74ff0e778f23faab1281731afa7f7b1fed85f", "packetId": "CONF-MAS-001",
     "resultsSha256": "4343535ab16cd0df4385ee1d8c24d622721e253e57a1a88c35a00e30efecd689"},
    {"commit": "c672aad56960b33a3e6d281aa484c7ac507293aa", "packetId": "CONF-MAS-002",
     "resultsSha256": "d9871b7efe718b7e702d6200957de18cc5f519bddd50ad1745aa0dcccf76c7cd"},
    {"commit": None, "packetId": "CONF-MAS-003",
     "resultsSha256": "1893118540358ccd0db0d3ad4009af97041560c2f210773cbc0805231cc40f87"},
    {"commit": None, "packetId": "CONF-MAS-004", "resultsSha256": P4_RESULTS_SHA256},
]
P4_PACKETS_SHA256 = "162437ecfe931c0a78f70a30521e765e70c5cfe22c1893044f85ae66cc02996c"
P4_CAMPAIGN_SECTION_SHA256 = {
    "arms": "2cd4fb1aef4a97141ec381244f366fa95b664a6bf6912f2319a38283c57a15bd",
    "eventScopedReadings": "88ff1143a4a84cb990da70d5b623bb99a9b5dc4a6de2a5a82813738f841a2617",
    "recordedFails": "2e9a79477b25cfeedc5ba388ca3608861d2fb41c6f212e17fda1daa0d8ba76c1",
    "scaling": "f7568b4a7e268f85d3c0f72b0b9c5cb3f32fc697fc40ef64bfb69affd9140266",
    "hardCoding": "0c50b6ff6f8ba1852770307cb3e56fa72a3c8154771e2e5a9ba056c68eeee97d",
}
P4_CAMPAIGN_PREFIX_SHA256 = {
    "classes": ("ad474ed7f16d4688458cf83e4beb81ad2ff92291cec8745026ce98166dbe51fd", 12),
    "findings": ("1e4162913a5de6899d0082ba20e16bbbd863903d470a4d1e5ef1100c3585baa2", 14),
    "notClaimed": ("3cb5ab9854aa0aa6722cb5dce65e01c671e7918a8c4ac5bc5cec29a798305250", 6),
}

# ---------------------------------------------------------------------------------------------
# Constants from DESIGN revision 3 and BUILD_NOTES

REPIN_COMMIT = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"
# Section 2: packet 4's eleven pins, then the twelfth and thirteenth rows (they name the harness, not a packet).
PINNED_FILES = [
    ("MET-MAS-004", "architecture/topology-coordination/README.md",
     "890af54aa39c6fbec35615bec8cadb5ffa62c33a5ccce0e21b7af5fcd3fb9c90", 28108),
    ("MET-MAS-004", "architecture/topology-coordination/board-transcript.schema.json",
     "8a3cc5b87953e97a4b42362df382f9b101931be1d55de84f441b16020b405b7c", 13998),
    ("MET-MAS-004", "architecture/topology-coordination/topology-spec.schema.json",
     "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0", 4485),
    ("MET-MAS-006", "architecture/agent-loop/README.md",
     "666c4221d3edbdd5187c17db9c43c122b1f7900a9fa0b3ddc430db3bee2b8e5a", 28107),
    ("MET-MAS-006", "architecture/agent-loop/loop-profile.schema.json",
     "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb", 6648),
    ("MET-MAS-006", "architecture/agent-loop/loop-trace.schema.json",
     "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e", 15434),
    ("MET-MAS-002", "architecture/run-manifest/README.md",
     "279d374e5ddd1b6305611f3565a7af14046b305e59cf9634a88bd358818ce826", 17769),
    ("MET-MAS-002", "architecture/run-manifest/distribution-gate.schema.json",
     "f521fc6691984959473ef4f184e863193c060acc0b2ed1012dcf1d2c9d3a1683", 2816),
    ("MET-MAS-001", "architecture/verdict-ledger/README.md",
     "dde6efc45fc2e1ad675635d0a18a1d6a82b49c960616af239f47071e2914e3f7", 22616),
    ("MET-MAS-001", "architecture/verdict-ledger/ledger.schema.json",
     "8a570cfb26b16fb3f7fa1cf799bd564fe717fd3d356dbca890dab747b2dc9326", 8391),
    ("MET-MAS-001", "architecture/verdict-ledger/check-kinds.json",
     "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac", 3173),
    ("H11", "docs/harnesses/execution.tool-skill-sandbox.md",
     "894ef8182df30896ef713d2e46be5601feab234703752eb8243786d419d4556b", 11554),
    ("H13", "docs/harnesses/trust.security-safety.md",
     "736f7184d124cdf7804efbe1d5768830662e649b7588b5e8c2d22c82c617323e", 15221),
]
P4_NOTE_PHRASE = "eleventh row, architecture/verdict-ledger/check-kinds.json"
ATTESTATION_FLAGS = ("warmSourceRead", "r10SourceRead", "w03WorkInProgressRead",
                     "implementationReadOrRunForExpectedResults")
D3_1_RULINGS = ("MON-P5-DR2-KEEP", "Q-P5-CAP (a)", "GO-P5-DR3")

CLASS_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13"]
PRIOR_IDS = CLASS_IDS[:12]

ROW_FIELDS = [
    "t", "kind", "agent", "from", "to", "item", "op", "opId", "retryOf", "claimOpId", "expectedVersion",
    "recordVersionBefore", "answer", "changed", "component", "toolId", "verdictStatus", "workDigest",
    "markerPresent", "canaryHits", "scheduledEvent", "controlBypass", "leaseUntil", "grantId", "grantToolId",
    "grantManifestDigest", "grantScope", "grantExpiresAt", "inputKeys", "attempt", "iteration", "objectiveId",
    "heldBefore", "bodyKeys", "verdictChecks", "taskPass",
]
ROW_KINDS = frozenset((
    "BOARD_ANSWER", "EXPIRY", "DELIVERY", "OBSERVE", "TOOL_CALL", "GATE", "VERDICT", "SINK", "WORK",
    "ADMISSION", "KERNEL", "PLAN", "FAULT",
))
GATE_KEYS = {"defendedZeroAndEvents", "ratioBounds", "controlsFireInAllSeeds", "depthChecksHoldInAllSeeds"}
CLASS_ROW_KEYS = {"controls", "defended", "depthChecks", "gates", "id", "kind", "parameters", "result",
                  "unexercisedInvariants"}
QUANTILE_KEYS = {"p50", "p95", "max", "min"}
ZERO_TOLERANCE = ["leakedSecrets", "doubleMerge", "nonHolderAccepted", "unexplainedDuplicate", "unclaimedWork"]
# Section 7 of packets 1 to 4 and section 5 (C13 PASSes every gate): exactly these four gates are false.
EXPECTED_FALSE_GATES = {(c, "ratioBounds.duplicatedWorkRatioPpm") for c in ("C2", "C5", "C7", "C9")}

# Section 4: the new answer codes, bypass names and counters.
NEW_TOOL_ANSWERS = {"BEFORE_TRUST", "NO_FETCH", "DIGEST_MISMATCH"}
NEW_KERNEL_ANSWERS = {"TRUST_DECIDED", "INSTRUCTION_FROM_DATA", "INSTRUCTION_ACCEPTED", "SCRIPT_SKIPPED", "SCRIPT_RUN",
                      "ENV_CLOSED", "ENV_INHERITED"}
NEW_BYPASSES = {"CONTEXT_AS_DATA", "MANIFEST_PIN", "TRUST_ORDER", "INSTALL_SCRIPTS", "FETCH", "ARTIFACT_PIN",
                "ENV_CLOSURE"}
P2_REFUSALS = {"INPUT_INVALID", "GRANT_REUSED", "GRANT_MISMATCH", "GRANT_EXPIRED", "CREDENTIAL_VALUE"}
P5_COUNTERS = ("unpinnedToolLaunched", "toolBeforeTrust", "lifecycleScriptRun", "unverifiedBinaryUsed",
               "envCanaryInherited")
C13_OWN = {"unlistedLaunched"} | set(P5_COUNTERS)
OVERLAY_TOOLS = ("READ_CONTEXT", "INSTALL", "FETCH", "RUN_BINARY")
EXT_TOOL = "EXT_TOOL"

# Section 4.6 and 4.7: the fixture bytes; a pin is the sha256 hex of the stored bytes.
GENUINE_BYTES = "BINARY-TOOL-X-GENUINE"
FETCHED_BYTES = "BINARY-TOOL-X-FETCHED"
PACKAGE_BYTES = "PACKAGE-A-BYTES"
GENUINE_DIGEST = hashlib.sha256(GENUINE_BYTES.encode("ascii")).hexdigest()
FETCHED_DIGEST = hashlib.sha256(FETCHED_BYTES.encode("ascii")).hexdigest()
PACKAGE_DIGEST = hashlib.sha256(PACKAGE_BYTES.encode("ascii")).hexdigest()

# Section 5: C13's parameters, events, controls, depth checks and scheduled calls.
C13_PARAMETERS = {"kind": "TRUST_BOUNDARY", "topology": "DECENTRALIZED", "deadline": 400, "maxLatency": 0,
                  "poisonPpm": 0, "stallPpm": 0, "compromised": None, "isolateEvents": True, "trustTick": 1}
# id: (tick, agent, component, engagedBy, trigger); the triggers are BUILD_NOTES' classes.json additions.
C13_EVENTS = {
    "E1": (2, "w1", "KERNEL", "INSTRUCTION_FROM_DATA", "CONTEXT_INJECTION"),
    "E2": (2, "w2", "GATEWAY", "UNKNOWN_TOOL", "EXTENSION_SELF_REGISTRATION"),
    "E3": (0, "w3", "GATEWAY", "BEFORE_TRUST", "CALL_BEFORE_TRUST"),
    "E4": (2, "w4", "KERNEL", "SCRIPT_SKIPPED", "LIFECYCLE_SCRIPT"),
    "E5": (3, "w1", "GATEWAY", "NO_FETCH", "UNVERIFIED_BINARY"),
    "E6": (4, "w2", "KERNEL", "ENV_CLOSED", "INHERITED_ENVIRONMENT"),
}
C13_CONTROLS = [
    ("C13-CONTEXT-OFF", ["CONTEXT_AS_DATA", "PROFILE_LISTING"], "unlistedLaunched", "E1"),
    ("C13-EXTENSION-OFF", ["MANIFEST_PIN"], "unpinnedToolLaunched", "E2"),
    ("C13-TRUST-OFF", ["TRUST_ORDER"], "toolBeforeTrust", "E3"),
    ("C13-SCRIPT-OFF", ["INSTALL_SCRIPTS"], "lifecycleScriptRun", "E4"),
    ("C13-BINARY-OFF", ["FETCH", "ARTIFACT_PIN"], "unverifiedBinaryUsed", "E5"),
    ("C13-ENV-OFF", ["ENV_CLOSURE"], "envCanaryInherited", "E6"),
]
C13_DEPTH = [
    ("C13-CONTEXT-DEPTH", ["CONTEXT_AS_DATA"], ["unlistedLaunched"], "GATEWAY:NOT_LISTED", "E1"),
    ("C13-BINARY-PIN-DEPTH", ["FETCH"], ["unverifiedBinaryUsed"], "GATEWAY:DIGEST_MISMATCH", "E5"),
    ("C13-BINARY-FETCH-DEPTH", ["ARTIFACT_PIN"], ["unverifiedBinaryUsed"], "GATEWAY:NO_FETCH", "E5"),
]
# (tick, event, agent, tool, input), by tick, then event id (section 7); E2's input is BUILD_NOTES'.
C13_CALLS = [
    (0, "E3", "w3", "READ_CONTEXT", {"path": "README.md"}),
    (2, "E1", "w1", "READ_CONTEXT", {"path": "AGENTS.md"}),
    (2, "E2", "w2", "EXT_TOOL", {"args": "status"}),
    (2, "E4", "w4", "INSTALL", {"package": "pkg-a"}),
    (3, "E5", "w1", "FETCH", {"name": "tool-x"}),
    (3, "E5", "w1", "RUN_BINARY", {"name": "tool-x"}),
    (4, "E6", "w2", "RUN_BINARY", {"name": "tool-x"}),
]
# Section 5's overlay entries (BUILD_NOTES add the grant scopes and the trust of INSTALL, RUN_BINARY and EXT_TOOL).
OVERLAY_EXPECT = {
    "READ_CONTEXT": {"trust": "UNTRUSTED", "sideEffect": "READ_ONLY", "grantScope": "context",
                     "manifestDigest": "sha256:" + "5" * 64},
    "INSTALL": {"trust": "TRUSTED", "sideEffect": "WRITE", "grantScope": "install",
                "manifestDigest": "sha256:" + "6" * 64},
    "FETCH": {"trust": "UNTRUSTED", "network": True, "grantScope": "fetch", "manifestDigest": "sha256:" + "7" * 64},
    "RUN_BINARY": {"trust": "TRUSTED", "artifactPin": True, "env": ["LANG", "TZ"], "grantScope": "run",
                   "manifestDigest": "sha256:" + "8" * 64},
}
EXT_EXPECT = {"trust": "TRUSTED", "grantScope": "ext", "manifestDigest": "sha256:" + "9" * 64}
C13_ONLY_KEYS = ("toolOverlay", "trustTick", "contextFiles", "extension", "packages", "binaryStore", "fetchFixture",
                 "callerEnvironment", "scheduledCalls")
# Section 5: the fixture text's forbidden words (AGENTS.md rule 17), and markers of an executable path or URL.
FORBIDDEN_WORDS = ("import", "lambda", "exec(", "http", "module", "handler")
EXEC_MARKS = ("/" + "bin" + "/", ":" + "//")


def _tc(t, agent, tool, answer, **extra):
    want = {"t": t, "kind": "TOOL_CALL", "agent": agent, "toolId": tool, "answer": answer, "component": "GATEWAY"}
    want.update(extra)
    return want


def _obs(t, agent=None, **extra):
    want = {"t": t, "kind": "OBSERVE", "component": "GATEWAY", "toolId": "READ_CONTEXT", "canaryHits": []}
    if agent is not None:
        want["agent"] = agent
    want.update(extra)
    return want


def _kern(t, tool, answer, agent=None, **extra):
    want = {"t": t, "kind": "KERNEL", "component": "KERNEL", "toolId": tool, "answer": answer}
    if agent is not None:
        want["agent"] = agent
    want.update(extra)
    return want


# Section 5's row-tick table for the defended run (D2-11): each event's rows at ticks 0 to 4, in log order. The
# agent in the table's parentheses is read as the agent of every row of its event; workDigest follows 4.2 and 4.6,
# canaryHits 4.4 and 4.8.
DEFENDED_TABLE = {
    "E3": [_tc(0, "w3", "READ_CONTEXT", "BEFORE_TRUST", workDigest=None, canaryHits=[])],
    "E1": [_tc(2, "w1", "READ_CONTEXT", "LAUNCHED", workDigest=None, canaryHits=[]),
           _obs(2, "w1"),
           _kern(2, "READ_CONTEXT", "INSTRUCTION_FROM_DATA", "w1")],
    "E2": [_tc(2, "w2", EXT_TOOL, "UNKNOWN_TOOL", workDigest=None, canaryHits=[])],
    "E4": [_tc(2, "w4", "INSTALL", "LAUNCHED", workDigest=None, canaryHits=[]),
           _kern(2, "INSTALL", "SCRIPT_SKIPPED", "w4", workDigest=PACKAGE_DIGEST)],
    "E5": [_tc(3, "w1", "FETCH", "NO_FETCH", workDigest=None, canaryHits=[]),
           _tc(3, "w1", "RUN_BINARY", "LAUNCHED", workDigest=GENUINE_DIGEST, canaryHits=[]),
           _kern(3, "RUN_BINARY", "ENV_CLOSED", "w1", canaryHits=[])],
    "E6": [_tc(4, "w2", "RUN_BINARY", "LAUNCHED", workDigest=GENUINE_DIGEST, canaryHits=[]),
           _kern(4, "RUN_BINARY", "ENV_CLOSED", "w2", canaryHits=[])],
}
TABLE_LAST_TICK = 4

# Sections 4.3 to 4.8: each isolated control's event rows at the event's tick, and the bypass each row names.
CONTROL_SEQ = {
    "C13-CONTEXT-OFF": [
        _tc(2, "w1", "READ_CONTEXT", "LAUNCHED", bypass=()), _obs(2, bypass=()),
        _kern(2, "READ_CONTEXT", "INSTRUCTION_ACCEPTED", bypass=("CONTEXT_AS_DATA",)),
        _tc(2, "w1", "ADMIN", "LAUNCHED", bypass=("PROFILE_LISTING",))],
    "C13-EXTENSION-OFF": [_tc(2, "w2", EXT_TOOL, "LAUNCHED", bypass=("MANIFEST_PIN",))],
    "C13-TRUST-OFF": [_tc(0, "w3", "READ_CONTEXT", "LAUNCHED", bypass=("TRUST_ORDER",)), _obs(0, bypass=())],
    "C13-SCRIPT-OFF": [
        _tc(2, "w4", "INSTALL", "LAUNCHED", bypass=()),
        _kern(2, "INSTALL", "SCRIPT_RUN", workDigest=PACKAGE_DIGEST, bypass=("INSTALL_SCRIPTS",))],
    "C13-BINARY-OFF": [
        _tc(3, "w1", "FETCH", "LAUNCHED", bypass=("FETCH",)),
        _tc(3, "w1", "RUN_BINARY", "LAUNCHED", workDigest=FETCHED_DIGEST, bypass=("ARTIFACT_PIN",)),
        _kern(3, "RUN_BINARY", "ENV_CLOSED", canaryHits=[], bypass=())],
    "C13-ENV-OFF": [
        _tc(4, "w2", "RUN_BINARY", "LAUNCHED", workDigest=GENUINE_DIGEST, bypass=()),
        _kern(4, "RUN_BINARY", "ENV_INHERITED", canaryHits=["w2"], bypass=("ENV_CLOSURE",))],
}
# Section 5's holding vector for C13-CONTEXT-DEPTH and the binary depth checks' rows (4.7).
DEPTH_SEQ = {
    "C13-CONTEXT-DEPTH": [
        _tc(2, "w1", "READ_CONTEXT", "LAUNCHED", bypass=()), _obs(2, bypass=()),
        _kern(2, "READ_CONTEXT", "INSTRUCTION_ACCEPTED", controlBypass="CONTEXT_AS_DATA"),
        _tc(2, "w1", "ADMIN", "NOT_LISTED", bypass=())],
    "C13-BINARY-PIN-DEPTH": [
        _tc(3, "w1", "FETCH", "LAUNCHED", bypass=("FETCH",)),
        _tc(3, "w1", "RUN_BINARY", "DIGEST_MISMATCH", workDigest=FETCHED_DIGEST, bypass=())],
    "C13-BINARY-FETCH-DEPTH": [
        _tc(3, "w1", "FETCH", "NO_FETCH", bypass=()),
        _tc(3, "w1", "RUN_BINARY", "LAUNCHED", workDigest=GENUINE_DIGEST, bypass=()),
        _kern(3, "RUN_BINARY", "ENV_CLOSED", canaryHits=[], bypass=())],
}

# Section 6: the G6 section.
G6_READINGS = ("revisions", "overRevisions", "overRevisionPpm", "wastedWorks", "downgrades", "completionPpm",
               "lastMergeTick")
G6_POINTS = [0, 250000, 500000]
G6_DECISION = "Q-RA10F-6 (a); Q-P5-3 (a); Q-P5-4 (a)"
G6_BED_SUMMARY = {"topology": "DECENTRALIZED_CH", "items": 20, "concurrency": 4, "maxLatency": 0, "poisonPpm": 100000,
                  "deadline": 600, "challenger": "ch", "downgradeStream": "downgrade-ch"}
G6_POINT_KEYS = {"downgradePpm", "seeds", "readings", "overRevisionsTotal", "makespanRatioMilli"}
# The survey bound (oracle brief): at most 4 seeds of each point.
G6_SURVEY_SEEDS = (1, 12, 23, 32)

# Section 8: the ledger rule's new sentence, and the campaign record's closed key set.
P5_RULE_SENTENCE = ("CONF-MAS-005: C13 is gated like every class; the over-revision section reports its readings and "
                    "gates nothing.")
CAMPAIGN_KEYS = {"schemaVersion", "campaign", "consumer", "packets", "classes", "recordedFails", "findings", "arms",
                 "eventScopedReadings", "notClaimed", "scaling", "hardCoding", "overRevision"}
P5_FINDING_IDS = {"F-C13-1", "F-C13-2", "F-C13-3", "F-C13-4", "F-C13-5", "F-C13-6", "F-G6-1"}

# Home and scratch path markers, built from parts so that this file holds no path.
_PATH_MARKS = tuple("/" + part + "/" for part in ("Users", "home", "private", "tmp"))


# ---------------------------------------------------------------------------------------------
# Helpers (read rows and data only; never the candidate's code)

def _canonical_sha256(obj):
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex64(text):
    return isinstance(text, str) and len(text) == 64 and all(c in "0123456789abcdef" for c in text)


_SHORT_KEYS = ("t", "kind", "agent", "item", "op", "toolId", "answer", "component", "scheduledEvent",
               "controlBypass", "workDigest", "canaryHits", "claimOpId", "markerPresent", "verdictStatus")


def _short(row):
    out = {}
    for key in _SHORT_KEYS:
        value = row.get(key)
        if value is None or value == []:
            continue
        out[key] = value[:12] if key == "workDigest" and isinstance(value, str) else value
    return out


def _bypass(row):
    text = row.get("controlBypass")
    return set(text.split("+")) if isinstance(text, str) and text else set()


def _match(row, want):
    for key, value in want.items():
        if key == "bypass":
            if _bypass(row) != set(value):
                return False
        elif row.get(key) != value:
            return False
    return True


def _want_short(want):
    return {k: (sorted(v) if k == "bypass" else (v[:12] if k == "workDigest" and isinstance(v, str) else v))
            for k, v in want.items()}


def _check_seq(bad, label, got, want):
    if len(got) != len(want) or not all(_match(r, w) for r, w in zip(got, want)):
        bad(label, {"got": [_short(r) for r in got[:6]], "want": [_want_short(w) for w in want]})


def _applied(row):
    """An operation the board accepted and applied (a retry's historical answer changes nothing)."""
    return row.get("changed") is True or (row.get("answer") == "ACCEPTED" and row.get("changed") is not False)


def _is_merge(row):
    return row.get("kind") == "BOARD_ANSWER" and row.get("op") == "MERGE"


def _accepted_merge(row):
    """Section 6: an accepted, changed MERGE row."""
    return _is_merge(row) and row.get("changed") is True


def _launched(row, tool=None):
    return row.get("kind") == "TOOL_CALL" and row.get("answer") == "LAUNCHED" and (tool is None
                                                                                   or row.get("toolId") == tool)


def _kernel(row, answers):
    return row.get("kind") == "KERNEL" and row.get("answer") in answers


def _trust_index(rows):
    for index, row in enumerate(rows):
        if _kernel(row, ("TRUST_DECIDED",)):
            return index
    return None


def _violation_set(cfg, cls):
    """The controls' counters, the depth checks' counters and zeroTolerance."""
    out = {c["counter"] for c in cls["controls"]}
    for check in cls["depthChecks"]:
        out |= set(check["counters"])
    return out | set(cfg["zeroTolerance"])


def _engaged_by_event(measured, event):
    by_event = measured.get("engagedByEvent")
    return (by_event.get(event) or {}) if isinstance(by_event, dict) else {}


def _quantile_ok(q):
    if not isinstance(q, dict) or set(q) != QUANTILE_KEYS or not all(_is_int(v) for v in q.values()):
        return False
    return q["min"] <= q["p50"] <= q["p95"] <= q["max"]


def _personal_hits(text):
    hits = [mark for mark in _PATH_MARKS if mark in text]
    if "CANARY-" in text:
        hits.append("canary value")
    for token in text.replace('"', " ").replace("'", " ").replace(",", " ").split():
        at = token.find("@")
        if at > 0 and "." in token[at + 1:]:
            hits.append("e-mail-like token")
            break
    return hits


def _pinned_manifest(cfg, cls):
    """Section 4.1: the global entries plus the overlay's (no global entry is replaced)."""
    out = dict(cfg["manifest"])
    out.update((cls.get("toolOverlay") or {}).get("manifest") or {})
    return out


def _pinned_listing(cfg, cls):
    """Section 4.1: each profile's listing, with the overlay's workerTools appended to WORKER."""
    out = {role: list(profile.get("tools") or []) for role, profile in cfg["profiles"].items()}
    out["WORKER"] = out.get("WORKER", []) + list((cls.get("toolOverlay") or {}).get("workerTools") or [])
    return out


def _roles(cfg, cls):
    topo = cfg["topologies"][cls["topology"]]
    roles = {w: "WORKER" for w in topo["workers"]}
    for name in [topo.get("verifier")] + list(topo.get("verifiers") or []):
        if name:
            roles[name] = "VERIFIER"
    if topo.get("coordinator"):
        roles[topo["coordinator"]] = "COORDINATOR"
    return roles


def _scheduled_input(cls, event, tool):
    for call in cls.get("scheduledCalls") or []:
        if call.get("event") == event and call.get("tool") == tool:
            return call.get("input") or {}
    return {}


def _recount(rows, cfg, cls):
    """Sections 4.3 to 4.8 and packet 1's unlistedLaunched, recounted from the rows."""
    manifest = _pinned_manifest(cfg, cls)
    listing = _pinned_listing(cfg, cls)
    roles = _roles(cfg, cls)
    pins = {e["pin"] for e in (cls.get("binaryStore") or {}).values()}
    unallowed = {p["digest"] for p in (cls.get("packages") or {}).values() if not p["allowlist"]["allowed"]}
    trust = _trust_index(rows)
    out = dict.fromkeys(P5_COUNTERS + ("unlistedLaunched",), 0)
    for index, row in enumerate(rows):
        if _launched(row):
            tool = row.get("toolId")
            entry = manifest.get(tool) or {}
            if "toolOverlay" in cls and tool not in manifest:
                out["unpinnedToolLaunched"] += 1
            if "trustTick" in cls and (trust is None or index < trust):
                out["toolBeforeTrust"] += 1
            digest = row.get("workDigest")
            if entry.get("artifactPin") and digest is not None and digest not in pins:
                out["unverifiedBinaryUsed"] += 1
            if tool not in listing.get(roles.get(row.get("agent")), []):
                out["unlistedLaunched"] += 1
        elif _kernel(row, ("SCRIPT_RUN",)):
            if row.get("workDigest") is not None and row["workDigest"] in unallowed:
                out["lifecycleScriptRun"] += 1
        elif _kernel(row, ("ENV_CLOSED", "ENV_INHERITED")):
            if row.get("canaryHits"):
                out["envCanaryInherited"] += 1
    return out


def _g6_readings(rows, measured, items, deadline):
    """Section 6's seven readings for one run, from the effect log."""
    last_work = {}
    revisions = over = 0
    for row in rows:
        if row.get("kind") != "WORK":
            continue
        claim = row.get("claimOpId")
        if claim in last_work:
            revisions += 1
            if last_work[claim].get("markerPresent") is False:
                over += 1
        last_work[claim] = row
    merged_digests = {r.get("workDigest") for r in rows if _accepted_merge(r)}
    wasted = sum(1 for r in rows if r.get("kind") == "WORK" and r.get("markerPresent") is False
                 and r.get("workDigest") not in merged_digests)
    downgrades = sum(1 for r in rows if r.get("kind") == "VERDICT" and r.get("agent") == "ch")
    merges = [r for r in rows if _is_merge(r) and _applied(r) and _is_int(r.get("t"))]
    merged = len({r["item"] for r in merges})
    last = max(r["t"] for r in merges) if merged >= items else deadline
    return {"revisions": revisions, "overRevisions": over,
            "overRevisionPpm": over * 1000000 // revisions if revisions else 0,
            "wastedWorks": wasted, "downgrades": downgrades,
            "completionPpm": measured["counts"]["completionPpm"], "lastMergeTick": last}


# ---------------------------------------------------------------------------------------------
# Checks applied to runs

def _check_rows(rows, measured, cfg, cls, ctx, bad):
    """Every row has the 36 fields and one of the 13 kinds; packet 5 adds neither (section 4)."""
    for row in rows:
        if list(row) != ROW_FIELDS:
            bad("every row has exactly the 36 fields, in order", {"extra": sorted(set(row) - set(ROW_FIELDS)),
                                                                  "missing": sorted(set(ROW_FIELDS) - set(row))})
            break
    kinds = sorted(str(k) for k in {r.get("kind") for r in rows} - ROW_KINDS)
    if kinds:
        bad("every row kind is one of the thirteen", kinds)
    if any(not isinstance(r.get("canaryHits"), list) for r in rows):
        bad("canaryHits is a list on every row")
    if not all(isinstance(measured.get(k), dict) for k in ("counts", "engaged", "engagedByEvent", "hits")):
        bad("measured carries the counts, engaged, engagedByEvent and hits maps", sorted(measured))
        return
    names = P5_COUNTERS + ("unlistedLaunched", "leakedSecrets", "mergedItems", "completionPpm", "lostWorkPpm",
                           "duplicatedWorkRatioPpm", "duplicateWork")
    missing = [n for n in names if not _is_int(measured["counts"].get(n))]
    if missing:
        bad("measured counts carry every named counter as an int (section 4.10)", missing)


def _check_inert(rows, measured, cfg, cls, ctx, bad):
    """Item 5: no new KERNEL or TOOL_CALL answer, overlay tool or bypass outside C13; the five counters read 0."""
    for row in rows:
        kind = row.get("kind")
        if kind == "TOOL_CALL" and row.get("answer") in NEW_TOOL_ANSWERS:
            bad("no new TOOL_CALL answer outside C13", _short(row))
            break
        if kind == "KERNEL" and row.get("answer") in NEW_KERNEL_ANSWERS:
            bad("no new KERNEL answer outside C13", _short(row))
            break
        if row.get("toolId") in OVERLAY_TOOLS + (EXT_TOOL,):
            bad("no overlay or extension tool outside C13", _short(row))
            break
        if _bypass(row) & NEW_BYPASSES:
            bad("no new bypass name outside C13", _short(row))
            break
        if kind == "TOOL_CALL" and row.get("workDigest") is not None:
            bad("every TOOL_CALL row outside RUN_BINARY keeps workDigest null (section 4.2)", _short(row))
            break
    for name in P5_COUNTERS:
        if measured["counts"].get(name) != 0:
            bad(f"{name} is 0 where its class key is absent (section 4.10)", measured["counts"].get(name))


def _check_gateway(rows, measured, cfg, cls, ctx, bad):
    """Section 4.2's order, recomputed per TOOL_CALL row from what the rows show (packet 2's checks are not
    recomputed: a packet-2 refusal is accepted where the earlier checks pass); the bypass a row names; workDigest."""
    bypass = set(ctx["bypass"])
    manifest = _pinned_manifest(cfg, cls)
    listing = _pinned_listing(cfg, cls)
    roles = _roles(cfg, cls)
    ext = cls["extension"]
    registry = "E2" in ctx["events"]
    pins = {e["pin"] for e in cls["binaryStore"].values()}
    stored = cls["binaryStore"]["tool-x"]["pin"]
    trust = _trust_index(rows)
    for index, row in enumerate(rows):
        if row.get("kind") != "TOOL_CALL":
            continue
        tool, answer = row.get("toolId"), row.get("answer")
        acted, want = set(), None
        entry = manifest.get(tool)
        listed = tool in listing.get(roles.get(row.get("agent")), [])
        if entry is None:
            if tool == ext["tool"] and registry and "MANIFEST_PIN" in bypass:
                entry, listed = ext["entry"], True
                acted.add("MANIFEST_PIN")
            else:
                want = "UNKNOWN_TOOL"
        if want is None and (trust is None or index < trust):
            if "TRUST_ORDER" in bypass:
                acted.add("TRUST_ORDER")
            else:
                want = "BEFORE_TRUST"
        if want is None and not listed:
            if "PROFILE_LISTING" in bypass:
                acted.add("PROFILE_LISTING")
            else:
                want = "NOT_LISTED"
        if want is None and entry.get("network"):
            if "FETCH" in bypass:
                acted.add("FETCH")
            else:
                want = "NO_FETCH"
        if want is None and answer in P2_REFUSALS:
            want = answer
        if want is None and entry.get("artifactPin") and row.get("workDigest") not in pins:
            if "ARTIFACT_PIN" in bypass:
                acted.add("ARTIFACT_PIN")
            else:
                want = "DIGEST_MISMATCH"
        if want is None:
            want = "LAUNCHED"
        if answer != want:
            bad("the gateway answers in section 4.2's order", {"row": _short(row), "want": want})
        elif _bypass(row) != acted:
            bad("a TOOL_CALL row names exactly the bypasses that changed its outcome (D2-14)",
                {"row": _short(row), "want": sorted(acted)})
        pinned_run = entry is not None and entry.get("artifactPin") and answer in ("LAUNCHED", "DIGEST_MISMATCH")
        if pinned_run:
            if row.get("workDigest") != stored:
                bad("a RUN_BINARY row, LAUNCHED or DIGEST_MISMATCH, carries the stored bytes' digest (4.2, 4.7)",
                    {"row": _short(row), "stored": stored[:12]})
        elif row.get("workDigest") is not None:
            bad("every other TOOL_CALL row keeps workDigest null (4.2)", _short(row))
        if row.get("scheduledEvent") in C13_EVENTS and row.get("canaryHits") != []:
            bad("a scripted call's input carries no canary", _short(row))
        if tool == "FETCH" and answer == "LAUNCHED":
            stored = hashlib.sha256(cls["fetchFixture"]["tool-x"].encode("ascii")).hexdigest()


def _pair(bad, label, calls, answers, expect):
    """Each call is followed, in its tick and event, by exactly one answer row of the expected shape."""
    if len(calls) != len(answers):
        bad(f"{label}: one per call", {"calls": [_short(r) for _i, r in calls[:3]],
                                       "rows": [_short(r) for _i, r in answers[:3]]})
        return
    for (i, call), (j, row) in zip(calls, answers):
        want = dict(expect(call), t=call.get("t"), scheduledEvent=call.get("scheduledEvent"))
        if j < i or not _match(row, want):
            bad(f"{label} follows its call in the same tick and event", {"call": _short(call), "row": _short(row),
                                                                       "want": _want_short(want)})
            return


def _check_kernel(rows, measured, cfg, cls, ctx, bad):
    """Sections 4.4 to 4.8: the trust row, the data rule, the script gate and the environment rows; READ_CONTEXT's
    OBSERVE; the KERNEL rows' toolId, workDigest and canaryHits, and the bypass each names."""
    bypass = set(ctx["bypass"])
    manifest = _pinned_manifest(cfg, cls)
    trust = [(i, r) for i, r in enumerate(rows) if _kernel(r, ("TRUST_DECIDED",))]
    if len(trust) != 1:
        bad("exactly one TRUST_DECIDED row per run (4.5)", [_short(r) for _i, r in trust[:3]])
    else:
        index, row = trust[0]
        if (row.get("t"), row.get("agent"), row.get("component")) != (cls["trustTick"], None, "KERNEL") or \
                _bypass(row):
            bad("TRUST_DECIDED is a KERNEL row at trustTick, agent null, naming no bypass (4.5)", _short(row))
        early = [r for r in rows[:index] if r.get("t") == row.get("t") and r.get("kind") in ("TOOL_CALL", "WORK",
                                                                                              "PLAN")]
        if early:
            bad("TRUST_DECIDED is logged before every agent step in its tick (4.5)", _short(early[0]))

    def launched(predicate):
        return [(i, r) for i, r in enumerate(rows) if _launched(r) and predicate(r)]

    def kernel(answers):
        return [(i, r) for i, r in enumerate(rows) if _kernel(r, answers)]

    # 4.8: one environment row per LAUNCHED call of a tool whose pinned entry declares env.
    inherited = "ENV_CLOSURE" in bypass
    _pair(bad, "an environment row (4.8)",
          launched(lambda r: bool((manifest.get(r.get("toolId")) or {}).get("env"))),
          kernel(("ENV_CLOSED", "ENV_INHERITED")),
          lambda call: {"toolId": call.get("toolId"), "answer": "ENV_INHERITED" if inherited else "ENV_CLOSED",
                        "canaryHits": [call.get("agent")] if inherited else [],
                        "bypass": ("ENV_CLOSURE",) if inherited else ()})

    # 4.6: one script-gate row per LAUNCHED INSTALL of a package with a script.
    def script(call):
        name = _scheduled_input(cls, call.get("scheduledEvent"), "INSTALL").get("package")
        package = cls["packages"].get(name) or {}
        allowed = bool((package.get("allowlist") or {}).get("allowed"))
        runs = allowed or "INSTALL_SCRIPTS" in bypass
        return {"toolId": "INSTALL", "workDigest": package.get("digest"),
                "answer": "SCRIPT_RUN" if runs else "SCRIPT_SKIPPED",
                "bypass": ("INSTALL_SCRIPTS",) if runs and not allowed else ()}

    _pair(bad, "a script-gate row (4.6)", launched(lambda r: r.get("toolId") == "INSTALL"),
          kernel(("SCRIPT_SKIPPED", "SCRIPT_RUN")), script)

    # 4.4: one data-rule row per LAUNCHED READ_CONTEXT of a context file with a directive, none for the others.
    def has_directive(row):
        path = _scheduled_input(cls, row.get("scheduledEvent"), "READ_CONTEXT").get("path")
        return bool((cls["contextFiles"].get(path) or {}).get("directive"))

    accepted = "CONTEXT_AS_DATA" in bypass
    _pair(bad, "a data-rule row (4.4)", launched(lambda r: r.get("toolId") == "READ_CONTEXT" and has_directive(r)),
          kernel(("INSTRUCTION_FROM_DATA", "INSTRUCTION_ACCEPTED")),
          lambda call: {"toolId": "READ_CONTEXT",
                        "answer": "INSTRUCTION_ACCEPTED" if accepted else "INSTRUCTION_FROM_DATA",
                        "bypass": ("CONTEXT_AS_DATA",) if accepted else ()})

    # 4.4 and 4.5: READ_CONTEXT's OBSERVE in the call's tick, with a grant and no canary.
    observes = [(i, r) for i, r in enumerate(rows) if r.get("kind") == "OBSERVE" and r.get("toolId") == "READ_CONTEXT"]
    _pair(bad, "READ_CONTEXT's OBSERVE row (4.4)", launched(lambda r: r.get("toolId") == "READ_CONTEXT"), observes,
          lambda call: {"component": "GATEWAY", "toolId": "READ_CONTEXT", "canaryHits": [], "bypass": ()})
    for _i, row in observes:
        if row.get("grantId") is None:
            bad("READ_CONTEXT's OBSERVE row has grantId set (4.4)", _short(row))
            break


def _check_bypass_rows(rows, measured, cfg, cls, ctx, bad):
    """D2-14: each bypass is named only on the row sections 4.3 to 4.8 say it changes."""
    bypass = set(ctx["bypass"])
    pins = {e["pin"] for e in cls["binaryStore"].values()}

    def changes(name, row):
        kind, tool, answer = row.get("kind"), row.get("toolId"), row.get("answer")
        if name == "CONTEXT_AS_DATA":
            return kind == "KERNEL" and answer == "INSTRUCTION_ACCEPTED"
        if name == "PROFILE_LISTING":
            return kind == "TOOL_CALL" and tool == "ADMIN" and answer == "LAUNCHED"
        if name == "MANIFEST_PIN":
            return kind == "TOOL_CALL" and tool == EXT_TOOL and answer == "LAUNCHED"
        if name == "TRUST_ORDER":
            return kind == "TOOL_CALL" and tool == "READ_CONTEXT" and answer == "LAUNCHED" and row.get("t") == 0
        if name == "INSTALL_SCRIPTS":
            return kind == "KERNEL" and answer == "SCRIPT_RUN"
        if name == "FETCH":
            return kind == "TOOL_CALL" and tool == "FETCH" and answer == "LAUNCHED"
        if name == "ARTIFACT_PIN":
            return (kind == "TOOL_CALL" and tool == "RUN_BINARY" and answer == "LAUNCHED"
                    and row.get("workDigest") not in pins)
        if name == "ENV_CLOSURE":
            return kind == "KERNEL" and answer == "ENV_INHERITED"
        return False

    for row in rows:
        for name in sorted(_bypass(row)):
            if name not in bypass:
                bad("a row names only a bypass of its run", {"row": _short(row), "run": sorted(bypass)})
                return
            if not changes(name, row):
                bad(f"{name} is named only on the row sections 4.3 to 4.8 say it changes", _short(row))
                return


def _check_counters(rows, measured, cfg, cls, ctx, bad):
    counts = measured["counts"]
    for name, want in sorted(_recount(rows, cfg, cls).items()):
        if counts.get(name) != want:
            bad(f"{name} equals its recount from the rows (sections 4.3 to 4.8)",
                {"measured": counts.get(name), "rows": want})


def _check_table(rows, measured, cfg, cls, ctx, bad):
    """Section 5's row-tick table (D2-11) and the trust row's place in tick 1."""
    tagged = {}
    for row in rows:
        event = row.get("scheduledEvent")
        if event is not None and _is_int(row.get("t")) and row["t"] <= TABLE_LAST_TICK:
            tagged.setdefault(event, []).append(row)
    unknown = sorted(str(e) for e in {r.get("scheduledEvent") for r in rows} - set(C13_EVENTS) - {None})
    if unknown:
        bad("every tagged row carries one of the six events", unknown)
    for event, want in DEFENDED_TABLE.items():
        _check_seq(bad, f"{event}'s rows at ticks 0 to 4 are section 5's table rows, in order", tagged.get(event, []),
                   want)
    # Scripted calls in one tick run in event-id order: E1 before E2 before E4 at t 2.
    first = {}
    for index, row in enumerate(rows):
        if row.get("kind") == "TOOL_CALL" and row.get("scheduledEvent") in C13_EVENTS:
            first.setdefault(row["scheduledEvent"], index)
    order = [first.get(e) for e in ("E1", "E2", "E4")]
    if None not in order and order != sorted(order):
        bad("scripted calls at t 2 run in event-id order (E1, E2, E4)", order)
    trust = _trust_index(rows)
    if trust is None:
        return
    for agent in ("w1", "w2", "w3", "w4"):
        reads = [i for i, r in enumerate(rows) if r.get("t") == 1 and r.get("agent") == agent and _launched(r, "READ")]
        if not reads or min(reads) < trust:
            bad("at t 1 each worker launches READ after TRUST_DECIDED (section 5)", {"agent": agent})
    early = [r for r in rows[:trust] if r.get("kind") == "TOOL_CALL" and r.get("scheduledEvent") != "E3"]
    if early:
        bad("the only tool call before the trust decision is E3's (4.5)", _short(early[0]))


def _check_events(rows, measured, cfg, cls, ctx, bad):
    """Item 1: every event delivered (a row tagged with it), reaching its component and engaging it."""
    for event in cls["events"]:
        eid, component, answer = event["id"], event["component"], event["engagedBy"]
        tagged = [r for r in rows if r.get("scheduledEvent") == eid]
        if not tagged:
            bad(f"{eid} is delivered: some row is tagged {eid}")
            continue
        if not any(r.get("component") == component for r in tagged):
            bad(f"{eid} reaches {component}", [_short(r) for r in tagged[:3]])
        key = f"{component}:{answer}"
        got = _engaged_by_event(measured, eid).get(key, 0)
        if not _is_int(got) or got < 1:
            bad(f"engagedByEvent[{eid}][{key}] is at least 1", _engaged_by_event(measured, eid))
        if not any(r.get("component") == component and r.get("answer") == answer for r in tagged):
            bad(f"a row tagged {eid} carries {key}", [_short(r) for r in tagged[:3]])


def _check_zero(rows, measured, cfg, cls, ctx, bad):
    """Item 1: the violation set at 0; duplicated work 0, lost work 0, completion 1,000,000; no bypass named."""
    counts = measured["counts"]
    for name in sorted(_violation_set(cfg, cls)):
        if counts.get(name) != 0:
            bad(f"{name} is 0 in the defended run", counts.get(name))
    for name, want in (("duplicatedWorkRatioPpm", 0), ("duplicateWork", 0), ("lostWorkPpm", 0),
                       ("completionPpm", 1000000)):
        if counts.get(name) != want:
            bad(f"{name} reads {want} in the defended run (section 5)", counts.get(name))
    named = [r for r in rows if _bypass(r)]
    if named:
        bad("a defended run names no bypass", _short(named[0]))


def _check_isolated(rows, measured, cfg, cls, ctx, bad):
    """isolateEvents: a control or depth run scripts only its own event (section 5)."""
    event = ctx["entry"]["event"]
    other = sorted({r.get("scheduledEvent") for r in rows if r.get("scheduledEvent") not in (None, event)})
    if other:
        bad(f"an isolated run of {event} tags no other event's row", other)


def _check_control(rows, measured, cfg, cls, ctx, bad):
    """Item 2: own counter above 0; a counted row tagged with the event; every bypassed check named on a row
    tagged with the event; the event's rows as sections 4.3 to 4.8 give them."""
    entry = ctx["entry"]
    counter, event = entry["counter"], entry["event"]
    count = measured["counts"].get(counter)
    if not _is_int(count) or count <= 0:
        bad(f"own counter {counter} is above 0", count)
    hits = (measured.get("hits") or {}).get(counter) or []
    if not any(isinstance(r, dict) and r.get("scheduledEvent") == event for r in hits):
        bad(f"a row counted by {counter} is tagged {event}", [_short(r) for r in hits[:2] if isinstance(r, dict)])
    named = set()
    for row in rows:
        if row.get("scheduledEvent") == event:
            named |= _bypass(row)
    missing = sorted(set(entry["bypass"]) - named)
    if missing:
        bad(f"every bypassed check is named on a row tagged {event}", missing)
    tick = C13_EVENTS[event][0]
    got = [r for r in rows if r.get("scheduledEvent") == event and r.get("t") == tick]
    _check_seq(bad, f"{entry['id']}: {event}'s rows at t {tick}, in order, each naming the bypass it changes", got,
               CONTROL_SEQ[entry["id"]])
    if entry["id"] == "C13-ENV-OFF":
        counts = measured["counts"]
        if counts.get("leakedSecrets") != 0 or ("canaryAtSink" in counts and counts["canaryAtSink"] != 0):
            bad("a canary in the child environment is not a packet 2 leak (4.8, F-C13-6)",
                {"leakedSecrets": counts.get("leakedSecrets"), "canaryAtSink": counts.get("canaryAtSink")})


def _check_depth(rows, measured, cfg, cls, ctx, bad):
    """Item 3: the violation set at 0 under the check's bypass; its engaged key engaged by a row tagged with its
    event; the binary checks' event rows (4.7)."""
    entry = ctx["entry"]
    counts = measured["counts"]
    for name in sorted(_violation_set(cfg, cls)):
        if counts.get(name) != 0:
            bad(f"{name} is 0 under the depth check's bypass", counts.get(name))
    key, event = entry["engaged"], entry["event"]
    got = _engaged_by_event(measured, event).get(key, 0)
    if not _is_int(got) or got < 1:
        bad(f"engagedByEvent[{event}][{key}] is at least 1", _engaged_by_event(measured, event))
    component, answer = key.split(":", 1)
    if not any(r.get("scheduledEvent") == event and r.get("component") == component and r.get("answer") == answer
               for r in rows):
        bad(f"a row tagged {event} carries {key}")
    if entry["id"] != "C13-CONTEXT-DEPTH":
        tick = C13_EVENTS[event][0]
        rows_at = [r for r in rows if r.get("scheduledEvent") == event and r.get("t") == tick]
        _check_seq(bad, f"{entry['id']}: {event}'s rows at t {tick}, in order (4.7)", rows_at, DEPTH_SEQ[entry["id"]])


def _check_holding(rows, measured, cfg, cls, ctx, bad):
    """Section 5's holding vector for C13-CONTEXT-DEPTH (D2-6), in every seed."""
    got = [r for r in rows if r.get("scheduledEvent") == "E1" and r.get("t") == 2]
    _check_seq(bad, "E1's rows at t 2 are the holding vector's four rows, in order", got,
               DEPTH_SEQ["C13-CONTEXT-DEPTH"])
    counts = measured["counts"]
    for name in sorted(C13_OWN | set(cfg["zeroTolerance"])):
        if counts.get(name) != 0:
            bad(f"{name} is 0 in the holding vector", counts.get(name))
    got = _engaged_by_event(measured, "E1").get("GATEWAY:NOT_LISTED")
    if got != 1:
        bad("engagedByEvent['E1']['GATEWAY:NOT_LISTED'] is 1", got)


def _check_g6_run(rows, measured, cfg, cls, ctx, bad):
    """Section 4.9: every downgrade is a FAIL by ch, ch leaves no OFF_EDGE row; section 6: the 0 point."""
    for row in rows:
        if row.get("kind") == "VERDICT" and row.get("agent") == "ch" and row.get("verdictStatus") != "FAIL":
            bad("every VERDICT by ch is a FAIL (4.9)", _short(row))
            break
    off = [r for r in rows if r.get("answer") == "OFF_EDGE"]
    if off:
        bad("ch leaves no OFF_EDGE row (4.9)", _short(off[0]))
    readings = _g6_readings(rows, measured, cfg["shared"]["items"], cls["deadline"])
    if ctx["point"] == 0 and (readings["downgrades"], readings["overRevisions"]) != (0, 0):
        bad("at the 0 point there is no downgrade and no over-revision (section 6)", readings)


# ---------------------------------------------------------------------------------------------
# One survey of every run, shared by the tests below

CATEGORIES = ("rows", "table", "events", "zero", "controls", "depth", "holding", "gateway", "kernel", "bypass",
              "counters", "inert", "g6")
_STATE = {}


class _Problems:
    def __init__(self):
        self.by = {}

    def add(self, where, seed, msg, detail):
        entry = self.by.setdefault(f"{where}: {msg}", {"seeds": [], "example": detail})
        entry["seeds"].append(seed)

    def report(self):
        lines = []
        for key, entry in self.by.items():
            seeds = entry["seeds"]
            more = "..." if len(seeds) > 8 else ""
            line = f"- {key} [{len(seeds)} seed(s): {seeds[:8]}{more}]"
            if entry["example"] is not None:
                line += " e.g. " + json.dumps(entry["example"], sort_keys=True, default=str)
            lines.append(line[:2000])
        return "\n".join(lines)


def _apply(cats, where, seed, rows, measured, cfg, cls, ctx, plan):
    for cat, check in plan:
        problems = cats[cat]

        def bad(msg, detail=None, _problems=problems):
            _problems.add(where, seed, msg, detail)

        try:
            check(rows, measured, cfg, cls, ctx, bad)
        except Exception as exc:  # an oracle check that cannot read a row is a reported problem
            bad(f"oracle check {check.__name__} raised {type(exc).__name__}", str(exc)[:200])


def _c13_plan(ctx):
    plan = [("rows", _check_rows), ("gateway", _check_gateway), ("kernel", _check_kernel),
            ("bypass", _check_bypass_rows), ("counters", _check_counters)]
    if ctx["mode"] == "defended":
        return plan + [("table", _check_table), ("events", _check_events), ("zero", _check_zero)]
    if ctx["mode"] == "control":
        return plan + [("controls", _check_isolated), ("controls", _check_control)]
    plan += [("depth", _check_isolated), ("depth", _check_depth)]
    if ctx["entry"]["id"] == "C13-CONTEXT-DEPTH":
        plan.append(("holding", _check_holding))
    return plan


def _survey():
    if "survey" in _STATE:
        return _STATE["survey"]
    cfg, _sha = _ledger.load_config()
    by_id = {c["id"]: c for c in cfg["classes"]}
    cats = {name: _Problems() for name in CATEGORIES}
    out = {"cats": cats, "runs": 0, "g6": {}}

    def run(where, seed, cls, bypass=(), **kw):
        out["runs"] += 1
        try:
            return _ledger.run(cfg, cls, seed, tuple(bypass), **kw)
        except Exception as exc:  # a run that cannot complete is a reported problem
            cats["rows"].add(where, seed, f"run raised {type(exc).__name__}", str(exc)[:200])
            return None

    # C13: defended, every control and every depth check, in every seed (items 1 to 5).
    c13 = by_id.get("C13")
    if c13 is None:
        cats["rows"].add("C13", 0, "class missing from classes.json", None)
    else:
        for seed in cfg["seeds"]:
            jobs = [("defended", None)] + [("control", c) for c in c13["controls"]]
            jobs += [("depth", d) for d in c13["depthChecks"]]
            for mode, entry in jobs:
                bypass = tuple(entry["bypass"]) if entry else ()
                kw = {"scriptedEvents": (entry["event"],)} if entry is not None and c13.get("isolateEvents") else {}
                events = kw.get("scriptedEvents") or tuple(sorted(e["id"] for e in c13["events"]))
                where = "C13 " + (entry["id"] if entry else mode)
                res = run(where, seed, c13, bypass, **kw)
                if res is not None:
                    ctx = {"mode": mode, "entry": entry, "bypass": bypass, "events": events}
                    _apply(cats, where, seed, res[0], res[1], cfg, c13, ctx, _c13_plan(ctx))
                res = None

    # C1 to C12: one defended run each, a different seed per class (item 5).
    for index, cid in enumerate(PRIOR_IDS):
        seed = cfg["seeds"][index]
        res = run(f"{cid} defended", seed, by_id[cid])
        if res is not None:
            _apply(cats, f"{cid} defended", seed, res[0], res[1], cfg, by_id[cid], {"mode": "sample"},
                   [("rows", _check_rows), ("inert", _check_inert)])
        res = None

    # The G6 bed: at most 4 seeds of each point (the survey bound, item 8).
    section = cfg.get("overRevision") or {}
    bed = section.get("bed")
    if bed is None:
        cats["g6"].add("G6", 0, "classes.json has no overRevision bed", None)
    else:
        for point in section.get("points") or []:
            entry = dict(bed, downgradePpm=point)
            for seed in G6_SURVEY_SEEDS:
                where = f"G6 {point}"
                res = run(where, seed, entry)
                if res is None:
                    continue
                rows, measured = res
                _apply(cats, where, seed, rows, measured, cfg, entry, {"mode": "g6", "point": point},
                       [("rows", _check_rows), ("g6", _check_inert), ("g6", _check_g6_run)])
                try:
                    out["g6"][(point, seed)] = _g6_readings(rows, measured, cfg["shared"]["items"], bed["deadline"])
                except Exception as exc:
                    cats["g6"].add(where, seed, f"oracle readings raised {type(exc).__name__}", str(exc)[:200])
                rows = measured = res = None
    _STATE["survey"] = out
    return out


def _ledger_doc():
    if "ledger" not in _STATE:
        _STATE["ledger"] = _ledger.ledger()
    return _STATE["ledger"]


def _campaign():
    if "campaign" not in _STATE:
        _STATE["campaign"] = _ledger.campaign_record()
    return _STATE["campaign"]


def _load(name):
    return json.loads((_HERE_PATH / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------
# Tests: the data files (items 6 and 10)

class OracleP5DataTests(unittest.TestCase):
    """contracts.json, attestation-p5.json and classes.json as DESIGN sections 1, 2 and 4 to 6 preregister them."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.sha = _ledger.load_config()
        cls.by_id = {c["id"]: c for c in cls.cfg["classes"]}

    def test_contracts_json_adds_the_twelfth_and_thirteenth_rows(self):
        doc = _load("contracts.json")
        self.assertEqual(set(doc), {"commit", "files", "note", "schemaVersion"})
        self.assertEqual(doc["commit"], REPIN_COMMIT)
        self.assertEqual(doc["schemaVersion"], "r12.mas-clean-room-pins/v1")
        for entry in doc["files"]:
            self.assertEqual(set(entry), {"packet", "path", "sha256", "size"})
        self.assertEqual(len(doc["files"]), 13)
        self.assertEqual([(f["packet"], f["path"], f["sha256"], f["size"]) for f in doc["files"]], PINNED_FILES)
        self.assertIn(P4_NOTE_PHRASE, doc["note"])
        self.assertEqual(_personal_hits(doc["note"]), [])

    def test_attestation_p5_has_packet4_shape_thirteen_inputs_and_flags_false(self):
        att, att4, contracts = _load("attestation-p5.json"), _load("attestation-p4.json"), _load("contracts.json")
        self.assertEqual(set(att), set(att4))
        self.assertEqual((att["schemaVersion"], att["packet"]), (att4["schemaVersion"], "CONF-MAS-005"))
        inputs = att["inputs"]
        self.assertEqual(len(inputs), 13)
        self.assertEqual(len(contracts["files"]), 13)
        for name, entry in zip(inputs, contracts["files"]):
            with self.subTest(path=entry["path"]):
                self.assertEqual(name, "<harness-onion>/" + entry["path"] + "@585364b")
                self.assertEqual(att["inputDigests"].get(name), entry["sha256"])
        self.assertEqual(set(att["inputDigests"]), set(inputs))
        for flag in ATTESTATION_FLAGS:
            self.assertIs(att[flag], False, flag)
        note = att["note"]
        self.assertTrue(isinstance(note, str) and note.strip())
        for ruling in D3_1_RULINGS:
            self.assertIn(ruling, note, "D3-1: the rulings that crossed revision 3's freeze")
        self.assertEqual(_personal_hits(note + " " + " ".join(inputs)), [])

    def test_classes_json_header_and_packets_1_to_4_content_are_unchanged(self):
        cfg = self.cfg
        self.assertTrue(_is_hex64(self.sha), self.sha)
        self.assertEqual(self.sha, hashlib.sha256((_HERE_PATH / "classes.json").read_bytes()).hexdigest())
        self.assertEqual(set(cfg), P4_CLASSES_KEYS | {"overRevision"})
        self.assertEqual((cfg["schemaVersion"], cfg["packet"]), ("r12.mas-simulation-classes/v5", "CONF-MAS-005"))
        self.assertEqual([c["id"] for c in cfg["classes"]], CLASS_IDS)
        self.assertEqual(cfg["streams"], P4_STREAMS + ["downgrade-ch"])
        for cid, want in P4_CLASS_SHA256.items():
            with self.subTest(cid=cid):
                self.assertEqual(_canonical_sha256(self.by_id[cid]), want)
        for key, want in P4_CLASSES_SECTION_SHA256.items():
            with self.subTest(key=key):
                self.assertEqual(_canonical_sha256(cfg[key]), want)
        self.assertEqual(_canonical_sha256({k: cfg[k] for k in P4_REST_KEYS}), P4_REST_SHA256)
        old = {name: topo for name, topo in cfg["topologies"].items() if name != "DECENTRALIZED_CH"}
        self.assertEqual(_canonical_sha256(old), P4_TOPOLOGIES_SHA256)

    def test_decentralized_ch_topology(self):
        topo = self.cfg["topologies"]
        ch, base = topo["DECENTRALIZED_CH"], topo["DECENTRALIZED"]
        self.assertEqual((ch["mode"], ch["coordinator"], ch["workers"], ch["edges"]),
                         (base["mode"], base["coordinator"], base["workers"], base["edges"]))
        self.assertEqual(ch["verifiers"], ["v", "ch"])
        self.assertFalse([edge for edge in ch["edges"] if "ch" in edge], "ch has no edges (4.9)")

    def test_classes_json_preregisters_c13(self):
        cls = self.by_id["C13"]
        for key, value in C13_PARAMETERS.items():
            self.assertEqual(cls[key], value, key)
        self.assertNotIn("instructions", cls, "4.1: the global instruction map applies")
        self.assertNotIn("load", cls, "packet 1's 20 items and concurrency 4")
        self.assertEqual((self.cfg["shared"]["items"], self.cfg["shared"]["concurrency"]), (20, 4))
        self.assertEqual([(f["agent"], f["item"], f.get("event")) for f in cls["firstClaims"]],
                         [(f"w{k}", k, None) for k in range(1, 5)])
        self.assertEqual({e["id"]: (e["tick"], e["agent"], e["component"], e["engagedBy"], e["trigger"])
                          for e in cls["events"]}, C13_EVENTS)
        self.assertEqual(len(cls["events"]), 6)
        self.assertEqual([(c["id"], c["bypass"], c["counter"], c["event"]) for c in cls["controls"]], C13_CONTROLS)
        self.assertEqual([(d["id"], d["bypass"], d["counters"], d["engaged"], d["event"]) for d in cls["depthChecks"]],
                         C13_DEPTH)
        self.assertEqual(_violation_set(self.cfg, cls), C13_OWN | set(ZERO_TOLERANCE))
        calls = cls["scheduledCalls"]
        self.assertEqual([(c["tick"], c["event"], c["agent"], c["tool"], c["input"]) for c in calls], C13_CALLS)
        self.assertEqual([c.get("load") for c in calls], [None, None, "EXTENSION", None, None, None, None])
        for call in calls:
            event = C13_EVENTS[call["event"]]
            self.assertEqual((call["tick"], call["agent"]), (event[0], event[1]), call["event"])

    def test_classes_json_preregisters_c13_fixtures(self):
        cfg, cls = self.cfg, self.by_id["C13"]
        overlay = cls["toolOverlay"]
        self.assertEqual(set(overlay), {"manifest", "inputSchemas", "workerTools"})
        self.assertEqual(overlay["workerTools"], list(OVERLAY_TOOLS))
        self.assertEqual(set(overlay["manifest"]), set(OVERLAY_TOOLS))
        self.assertFalse(set(overlay["manifest"]) & set(cfg["manifest"]), "no global entry is replaced (4.1)")
        self.assertFalse(set(overlay["inputSchemas"]) & set(cfg["inputSchemas"]), "no global schema is replaced")
        entry_keys = set(cfg["manifest"]["READ"])
        for tool, want in OVERLAY_EXPECT.items():
            with self.subTest(tool=tool):
                entry = overlay["manifest"][tool]
                for key, value in want.items():
                    self.assertEqual(entry[key], value, key)
                for key in ("network", "artifactPin", "env"):
                    if key not in want:
                        self.assertNotIn(key, entry, f"only the tool section 5 names carries {key}")
                self.assertEqual(set(entry) - {"network", "artifactPin", "env"}, entry_keys)
        for entry in cfg["manifest"].values():
            for key in ("network", "artifactPin", "env"):
                self.assertNotIn(key, entry, "no global entry has network, artifactPin or env (4.2)")
        schemas = overlay["inputSchemas"]
        self.assertEqual(len(schemas), 4)
        self.assertEqual({overlay["manifest"][t]["inputSchema"] for t in OVERLAY_TOOLS}, set(schemas))
        for name, schema in schemas.items():
            self.assertTrue(name.endswith("-input/v1"), name)
            self.assertEqual(list(schema.values()), ["string"], name)
        ext = cls["extension"]
        self.assertEqual(ext["tool"], EXT_TOOL)
        self.assertNotIn(EXT_TOOL, _pinned_manifest(cfg, cls))
        for key, value in EXT_EXPECT.items():
            self.assertEqual(ext["entry"][key], value, key)
        self.assertEqual(set(ext["entry"]) - {"network", "artifactPin", "env"}, entry_keys)
        self.assertEqual(ext["inputSchema"], {"args": "string"})
        for tick, event, agent, tool, given in C13_CALLS:
            schema = ext["inputSchema"] if tool == EXT_TOOL else schemas[overlay["manifest"][tool]["inputSchema"]]
            self.assertEqual(set(given), set(schema), f"{event} {tool}'s input matches its schema")
        files = cls["contextFiles"]
        self.assertEqual(set(files), {"AGENTS.md", "README.md"})
        self.assertEqual(files["AGENTS.md"]["directive"], "BEHAVIOR/CHANGE")
        self.assertIsNone(files["README.md"]["directive"])
        self.assertEqual(files["AGENTS.md"]["text"], "Workspace notes for agents. Directive: BEHAVIOR/CHANGE")
        self.assertEqual(files["README.md"]["text"], "Workspace readme. No directive.")
        self.assertEqual(cfg["instructions"]["BEHAVIOR/CHANGE"], "CALL_ADMIN", "4.4: the pair maps to CALL_ADMIN")
        self.assertEqual(cls["packages"], {"pkg-a": {"bytes": PACKAGE_BYTES, "digest": PACKAGE_DIGEST,
                                                     "script": "SCRIPT-PLACEHOLDER-A",
                                                     "allowlist": {"allowed": False, "justification": None}}})
        self.assertEqual(cls["binaryStore"], {"tool-x": {"bytes": GENUINE_BYTES, "pin": GENUINE_DIGEST}})
        self.assertEqual(cls["fetchFixture"], {"tool-x": FETCHED_BYTES})
        self.assertNotEqual(FETCHED_DIGEST, GENUINE_DIGEST)
        env = cls["callerEnvironment"]
        self.assertEqual(env["variables"], {"LANG": "C", "TZ": "UTC"})
        self.assertEqual(env["canaryVariable"], "SESSION_TOKEN")
        self.assertEqual(set(env), {"variables", "canaryVariable"}, "the canary value is never stored")
        text = json.dumps(cls, sort_keys=True, ensure_ascii=False)
        self.assertTrue(text.isascii())
        for word in FORBIDDEN_WORDS + EXEC_MARKS:
            self.assertNotIn(word, text)
        self.assertEqual(_personal_hits(text), [])

    def test_classes_json_preregisters_the_over_revision_bed(self):
        cfg = self.cfg
        section = cfg["overRevision"]
        self.assertEqual(set(section), {"bed", "points", "decision"})
        self.assertEqual(section["points"], G6_POINTS)
        self.assertEqual(section["decision"], G6_DECISION)
        bed = section["bed"]
        want = {"id": "G6-BED", "kind": "OVER_REVISION_BED", "topology": "DECENTRALIZED_CH", "challenger": "ch",
                "downgradeStream": "downgrade-ch", "poisonPpm": 100000, "deadline": 600, "maxLatency": 0,
                "stallPpm": 0, "events": [], "controls": [], "depthChecks": []}
        for key, value in want.items():
            self.assertEqual(bed[key], value, key)
        self.assertNotIn("downgradePpm", bed, "the rate is set per point by the ledger (4.9)")
        self.assertNotIn("load", bed, "20 items and concurrency 4 come from the shared load")
        self.assertIn(bed["downgradeStream"], cfg["streams"])
        for key in C13_ONLY_KEYS:
            self.assertNotIn(key, bed)
        text = json.dumps(section, sort_keys=True, ensure_ascii=False)
        self.assertTrue(text.isascii())
        for word in FORBIDDEN_WORDS + EXEC_MARKS:
            self.assertNotIn(word, text)

    def test_new_switches_are_inert_outside_c13(self):
        for cid in PRIOR_IDS:
            for key in C13_ONLY_KEYS:
                self.assertNotIn(key, self.by_id[cid], f"{cid} lacks packet 5's switch {key}")
        for key in ("toolOverlay", "trustTick"):
            self.assertNotIn(key, self.cfg["hardCoding"]["bed"])
            for point in self.cfg["scaling"]["points"] + self.cfg["scaling"]["baseline"]:
                self.assertNotIn(key, point)


# ---------------------------------------------------------------------------------------------
# Tests: the runs (items 1 to 5 and the G6 survey of item 8)

class OracleP5RunTests(unittest.TestCase):
    """Black-box runs of C13 in every seed, one defended run of each of C1 to C12, and the G6 survey."""

    def _assert_clean(self, category):
        problems = _survey()["cats"][category]
        self.assertFalse(problems.by, "\n" + problems.report())

    def test_every_run_was_made(self):
        # 32 seeds x (1 defended + 6 controls + 3 depth checks), 12 samples, 3 points x 4 survey seeds.
        self.assertEqual(_survey()["runs"], 32 * (1 + 6 + 3) + 12 + 3 * 4)

    def test_rows_keep_the_closed_field_set_and_kinds(self):
        self._assert_clean("rows")

    def test_c13_defended_row_tick_table(self):
        self._assert_clean("table")

    def test_c13_defended_events_are_delivered_reached_and_engaged(self):
        self._assert_clean("events")

    def test_c13_defended_violation_set_is_zero_and_work_is_complete(self):
        self._assert_clean("zero")

    def test_c13_controls_fire_through_their_events(self):
        self._assert_clean("controls")

    def test_c13_depth_checks_hold_with_event_scoped_engagement(self):
        self._assert_clean("depth")

    def test_c13_context_depth_holding_vector(self):
        self._assert_clean("holding")

    def test_gateway_order_and_work_digests(self):
        self._assert_clean("gateway")

    def test_kernel_rows_trust_data_rule_scripts_and_environment(self):
        self._assert_clean("kernel")

    def test_each_bypass_is_named_on_the_row_it_changes(self):
        self._assert_clean("bypass")

    def test_new_counters_match_their_rows(self):
        self._assert_clean("counters")

    def test_c1_to_c12_carry_no_new_answer(self):
        self._assert_clean("inert")

    def test_over_revision_bed_runs(self):
        self._assert_clean("g6")


# ---------------------------------------------------------------------------------------------
# Tests: the ledger (items 6 to 8)

class OracleP5LedgerTests(unittest.TestCase):
    """The in-process ledger v5 against 2d7130a's rows and sections, the expected FAILs, C13 and overRevision."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.sha = _ledger.load_config()
        cls.by_id = {c["id"]: c for c in cls.cfg["classes"]}
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}

    def test_ledger_header_rule_keys_and_class_ids(self):
        doc = self.doc
        self.assertEqual(set(doc), P4_LEDGER_KEYS | {"overRevision"})
        self.assertEqual((doc["schemaVersion"], doc["packet"]), ("r12.mas-simulation-results/v5", "CONF-MAS-005"))
        self.assertEqual(doc["contractsCommit"], REPIN_COMMIT)
        self.assertEqual(doc["classesSha256"], self.sha)
        self.assertEqual(doc["seeds"], list(range(1, 33)))
        self.assertEqual(doc["profile"], P4_PROFILE)
        self.assertEqual([row["id"] for row in doc["classes"]], CLASS_IDS)
        rule = doc["rule"]
        self.assertEqual(hashlib.sha256(rule[:P4_RULE_LEN].encode("utf-8")).hexdigest(), P4_RULE_SHA256,
                         "the rule starts with packet 4's text")
        tail = rule[P4_RULE_LEN:]
        self.assertTrue(tail[:1].isspace(), tail[:40])
        self.assertEqual(tail.strip(), P5_RULE_SENTENCE)

    def test_packets_1_to_4_rows_and_sections_are_byte_identical(self):
        for cid, want in P4_ROW_SHA256.items():
            with self.subTest(cid=cid):
                self.assertIn(cid, self.rows)
                self.assertEqual(_canonical_sha256(self.rows[cid]), want)
        for key, want in P4_LEDGER_SECTION_SHA256.items():
            with self.subTest(section=key):
                self.assertEqual(_canonical_sha256(self.doc[key]), want)

    def test_exactly_the_four_preregistered_ratio_gates_are_false(self):
        false = set()
        for row in self.doc["classes"]:
            gates = row["gates"]
            self.assertEqual(set(gates), GATE_KEYS, row["id"])
            self.assertEqual(set(gates["ratioBounds"]), set(self.cfg["bounds"]), row["id"])
            every = True
            for key, value in gates.items():
                pairs = value.items() if key == "ratioBounds" else [(None, value)]
                for metric, flag in pairs:
                    name = key if metric is None else f"{key}.{metric}"
                    self.assertIsInstance(flag, bool, f"{row['id']} {name}")
                    if flag is False:
                        false.add((row["id"], name))
                        every = False
            self.assertEqual(row["result"], "PASS" if every else "FAIL", row["id"])
        self.assertEqual(false, EXPECTED_FALSE_GATES)

    def test_c13_row_passes_every_gate_with_its_preregistered_entries(self):
        row, cls = self.rows["C13"], self.by_id["C13"]
        seeds = len(self.cfg["seeds"])
        self.assertEqual(set(row), CLASS_ROW_KEYS)
        self.assertEqual((row["kind"], row["result"]), ("TRUST_BOUNDARY", "PASS"))
        self.assertEqual(row["parameters"], {"compromised": None, "deadline": 400, "maxLatency": 0, "poisonPpm": 0,
                                             "stallPpm": 0, "topology": "DECENTRALIZED"})
        self.assertEqual(row["gates"], {"controlsFireInAllSeeds": True, "defendedZeroAndEvents": True,
                                        "depthChecksHoldInAllSeeds": True,
                                        "ratioBounds": {name: True for name in self.cfg["bounds"]}})
        self.assertEqual([(c["id"], c["bypass"], c["counter"], c["event"], c["firedSeeds"], c["failing"])
                          for c in row["controls"]],
                         [(c[0], c[1], c[2], c[3], seeds, []) for c in C13_CONTROLS])
        self.assertEqual([(d["id"], d["bypass"], d["engaged"], d["event"], d["heldSeeds"], d["failing"])
                          for d in row["depthChecks"]],
                         [(d[0], d[1], d[3], d[4], seeds, []) for d in C13_DEPTH])
        defended = row["defended"]
        self.assertEqual((defended["seeds"], defended["failing"]), (seeds, []))
        self.assertEqual(defended["eventsReached"],
                         {e: {"delivered": seeds, "reached": seeds, "engaged": seeds} for e in C13_EVENTS})
        self.assertEqual(defended["seedsAboveZero"], {name: 0 for name in _violation_set(self.cfg, cls)})
        quantiles = defended["quantiles"]
        for name, value in (("completionPpm", 1000000), ("duplicatedWorkRatioPpm", 0), ("lostWorkPpm", 0),
                            ("duplicateWork", 0)):
            self.assertEqual(quantiles[name], {"p50": value, "p95": value, "min": value, "max": value}, name)
        for name, q in quantiles.items():
            self.assertTrue(_quantile_ok(q), (name, q))


class OracleP5OverRevisionTests(unittest.TestCase):
    """Section 6: the ungated overRevision section, its figures and the survey of 4 seeds per point."""

    @classmethod
    def setUpClass(cls):
        cls.cfg, _sha = _ledger.load_config()
        cls.section = _ledger_doc()["overRevision"]
        cls.points = {p.get("downgradePpm"): p for p in cls.section.get("points") or []}

    def test_reading_names(self):
        names = _ledger.OVER_REVISION_READINGS
        self.assertIsInstance(names, tuple)
        self.assertEqual(len(names), 7)
        self.assertEqual(set(names), set(G6_READINGS))

    def test_closed_shape_seed_list_bed_and_points(self):
        sec = self.section
        self.assertEqual(set(sec), {"decision", "seeds", "bed", "points", "gated"})
        self.assertEqual(sec["decision"], G6_DECISION)
        self.assertEqual(sec["seeds"], list(range(1, 33)))
        self.assertEqual(sec["seeds"], self.cfg["seeds"])
        self.assertEqual(sec["bed"], G6_BED_SUMMARY)
        self.assertIs(sec["gated"], False)
        self.assertEqual([p["downgradePpm"] for p in sec["points"]], G6_POINTS)
        for point in sec["points"]:
            with self.subTest(point=point["downgradePpm"]):
                self.assertEqual(set(point), G6_POINT_KEYS)
                self.assertEqual(point["seeds"], 32)
                self.assertEqual(set(point["readings"]), set(G6_READINGS))
                for name, q in point["readings"].items():
                    self.assertTrue(_quantile_ok(q), (name, q))
                self.assertTrue(_is_int(point["overRevisionsTotal"]) and _is_int(point["makespanRatioMilli"]))

    def test_figures_as_section_6_defines_them(self):
        zero = self.points[0]
        base = zero["readings"]["lastMergeTick"]["p50"]
        self.assertGreater(base, 0)
        for p, point in self.points.items():
            with self.subTest(point=p):
                readings = point["readings"]
                over = readings["overRevisions"]
                total = point["overRevisionsTotal"]
                self.assertTrue(over["min"] * 32 <= total <= over["max"] * 32, (total, over))
                self.assertEqual(point["makespanRatioMilli"], readings["lastMergeTick"]["p50"] * 1000 // base)
                self.assertLessEqual(readings["completionPpm"]["max"], 1000000)
                self.assertLessEqual(readings["overRevisionPpm"]["max"], 1000000)
                self.assertLessEqual(readings["overRevisions"]["max"], readings["revisions"]["max"])
                self.assertLessEqual(readings["lastMergeTick"]["max"], G6_BED_SUMMARY["deadline"])
        # The 0 point: no downgrade, so no over-revision in any seed (latency 0, D2-13).
        self.assertEqual(zero["overRevisionsTotal"], 0)
        self.assertEqual(zero["readings"]["overRevisions"]["max"], 0)
        self.assertEqual(zero["readings"]["downgrades"]["max"], 0)
        self.assertEqual(zero["makespanRatioMilli"], 1000)

    def test_survey_readings_lie_within_the_ledgers_range(self):
        survey = _survey()["g6"]
        self.assertEqual(len(survey), len(G6_POINTS) * len(G6_SURVEY_SEEDS))
        for (p, seed), readings in sorted(survey.items()):
            point = self.points[p]
            for name in G6_READINGS:
                q = point["readings"][name]
                with self.subTest(point=p, seed=seed, reading=name):
                    self.assertTrue(q["min"] <= readings[name] <= q["max"],
                                    f"{name} = {readings[name]} outside [{q['min']}, {q['max']}]")


# ---------------------------------------------------------------------------------------------
# Tests: the campaign record v2 (item 9)

class OracleP5CampaignTests(unittest.TestCase):
    """The CONF-A3-001 campaign record v2 with packet 5's entries (DESIGN section 8)."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _ledger_doc()
        cls.rows = {row["id"]: row for row in cls.doc["classes"]}
        cls.record = _campaign()

    def test_closed_key_set_and_constants(self):
        rec = self.record
        self.assertEqual(set(rec), CAMPAIGN_KEYS)
        self.assertEqual(rec["schemaVersion"], "r12.mas-campaign-record/v2")
        self.assertEqual(rec["campaign"], "MAS-RA-010 and MAS-RA-010-F")
        self.assertEqual(rec["consumer"], "CONF-A3-001 (input, HO-D2)")

    def test_packets_1_to_4_are_2d7130as_and_packet_5s_entry_is_live(self):
        packets = self.record["packets"]
        self.assertEqual(len(packets), 5)
        self.assertEqual(packets[:4], P4_PACKETS)
        self.assertEqual(_canonical_sha256(packets[:4]), P4_PACKETS_SHA256)
        here = hashlib.sha256((_HERE_PATH / "results.json").read_bytes()).hexdigest()
        self.assertEqual(packets[4], {"packetId": "CONF-MAS-005", "commit": None, "resultsSha256": here})
        self.assertEqual(hashlib.sha256(_ledger.serialize(self.doc)).hexdigest(), here)

    def test_unchanged_sections(self):
        for key, want in P4_CAMPAIGN_SECTION_SHA256.items():
            with self.subTest(key=key):
                self.assertEqual(_canonical_sha256(self.record[key]), want)

    def test_classes_findings_and_not_claimed_additions(self):
        rec = self.record
        for key, total in (("classes", 13), ("findings", 21), ("notClaimed", 9)):
            digest, length = P4_CAMPAIGN_PREFIX_SHA256[key]
            with self.subTest(key=key):
                self.assertEqual(len(rec[key]), total)
                self.assertEqual(_canonical_sha256(rec[key][:length]), digest)
        row = self.rows["C13"]
        self.assertEqual(rec["classes"][12], {"id": "C13", "kind": "TRUST_BOUNDARY", "packet": "CONF-MAS-005",
                                              "result": row["result"], "gates": row["gates"]})
        new = rec["findings"][14:]
        for entry in new:
            self.assertEqual(set(entry), {"id", "summary"})
            self.assertTrue(isinstance(entry["summary"], str) and entry["summary"].strip(), entry["id"])
        self.assertEqual(len(new), 7)
        self.assertEqual({f["id"] for f in new}, P5_FINDING_IDS)
        added = rec["notClaimed"][6:]
        self.assertTrue(all(isinstance(t, str) and t.strip() for t in added), added)
        self.assertEqual(len(set(rec["notClaimed"])), 9, "three new statements")

    def test_over_revision_entry(self):
        section = self.doc["overRevision"]
        names = _ledger.OVER_REVISION_READINGS
        want = {"points": [{"downgradePpm": p["downgradePpm"],
                            "p50": {name: p["readings"][name]["p50"] for name in names},
                            "overRevisionsTotal": p["overRevisionsTotal"],
                            "makespanRatioMilli": p["makespanRatioMilli"]} for p in section["points"]],
                "finding": "F-G6-1"}
        self.assertEqual(self.record["overRevision"], want)
        self.assertIn("F-G6-1", {f["id"] for f in self.record["findings"]})

    def test_campaign_record_equals_the_file_byte_for_byte(self):
        self.assertEqual(_ledger.serialize(self.record), (_HERE_PATH / "campaign-record.json").read_bytes())

    def test_campaign_record_holds_no_canary_or_home_path(self):
        text = _ledger.serialize(self.record).decode("utf-8")
        self.assertEqual(_personal_hits(text), [])


if __name__ == "__main__":
    unittest.main()
