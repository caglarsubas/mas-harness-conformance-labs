"""CONF-MAS-005: the rules packet 5 adds (DESIGN revision 3, section 4) against hand-built cases and single calls, the
pinned view and its readers (section 4.1), the five counters and the null-field rule (sections 4.3 to 4.10), packets 1
to 4's rows and classes.json entries byte-identical, the data files, the attestation and the campaign record."""
from __future__ import annotations

import hashlib
import inspect
import json
import unittest
from pathlib import Path

import _classes
import _ledger
import _sim

HERE = Path(__file__).resolve().parent
CONFIG, _SHA = _ledger.load_config()
CLASSES = {c["id"]: c for c in CONFIG["classes"]}
PIN = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"

# Canonical JSON digests (sorted keys, compact separators, ASCII) of the 34 objects design review rounds 1 and 2 hashed
# (A2), taken from tests/mas/results.json and classes.json at 2d7130a (tree 7b2190ef, R12 e038772d's tree).
RESULTS_ROW_SHA256 = {
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
RESULTS_SECTION_SHA256 = {
    "arms": "fa1e7481fd20fb73fccc68950a822895c83192d295a7f6caa35e4095bbdd54f6",
    "scaling": "3ed7224c4189c2e9d4219d3d98a7f34d2da4009d7dd955bf195b483e15a97d08",
    "hardCoding": "3de3d420f2dc855ea39f8df292db80b4b667c7a2240f1a530474bff61eafe11f",
}
CLASSES_ENTRY_SHA256 = {
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
CLASSES_KEY_SHA256 = {
    "arms": "f22cf5291c98f446aa4effc79b552c0c0544d12351c8f6753c590b2f08c76e8d",
    "scaling": "d9aa29d7e583a2c45e6d7e103f4ff909ec0239434f86661d07ba23bad6b713d3",
    "hardCoding": "52205ef6a6b2214e8839e5dd4ae3ab09e0b5538441f7925683686a54a6443c1d",
    "manifest": "c00cad9694a8c3a57c8e4905519a63087221653ce36d1e4c2d75ac53ed9d41a0",
    "profiles": "4c3da2d3a1d3b5a2a1f75aaaf4bd22bbec92e5730883a7ead9a3c5764e7fc0b0",
    "inputSchemas": "0cbce80399de46cea661b79087cb32c25ba0a6fe61603f537a74a12cfc220d85",
    "instructions": "759e25c4094e3e1631bf59fd5e1b8ef1ce78c78e65bb520183d59b8a6a279cf0",
}
P4_RESULTS_SHA256 = "7149f09d3585bd8c9a8cbf4ab075abd09e75a74b110fddbfdef5b8125470bb77"
NEW_KEYS = ("toolOverlay", "trustTick", "contextFiles", "extension", "packages", "binaryStore", "fetchFixture",
            "callerEnvironment", "scheduledCalls")


def canonical(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def c13_sim(bypass: tuple[str, ...] = (), **changes) -> _sim.Sim:
    """A C13 sim that scripts no event (scriptedEvents ()), for calls made by hand; it is never run."""
    cls = dict(CLASSES["C13"], **changes)
    return _sim.Sim(CONFIG, cls, 1, bypass, _classes.scenario_for(cls), scripted_events=())


def last(sim: _sim.Sim, kind: str) -> dict:
    return [r for r in sim.log.rows if r["kind"] == kind][-1]


class PinnedViewTests(unittest.TestCase):
    def test_without_an_overlay_the_view_is_the_global_objects(self):
        entries = list(CONFIG["classes"][:12]) + CONFIG["scaling"]["points"] + CONFIG["scaling"]["baseline"] \
            + [CONFIG["hardCoding"]["bed"], CONFIG["overRevision"]["bed"]]
        for cls in entries:
            view = _sim.pinned_view(CONFIG, cls)
            self.assertIs(view["manifest"], CONFIG["manifest"], cls["id"])
            self.assertIs(view["profiles"], CONFIG["profiles"], cls["id"])
            self.assertIs(view["inputSchemas"], CONFIG["inputSchemas"], cls["id"])
        sim = _sim.Sim(CONFIG, CLASSES["C6"], 1, (), _classes.scenario_for(CLASSES["C6"]))
        self.assertIs(sim.pinned["manifest"], CONFIG["manifest"])
        self.assertIs(sim.tool_view(), sim.pinned)

    def test_the_overlay_adds_and_never_replaces(self):
        view = _sim.pinned_view(CONFIG, CLASSES["C13"])
        self.assertEqual(sorted(view["manifest"]), sorted(list(CONFIG["manifest"]) +
                                                          ["READ_CONTEXT", "INSTALL", "FETCH", "RUN_BINARY"]))
        self.assertEqual(view["profiles"]["WORKER"]["tools"],
                         CONFIG["profiles"]["WORKER"]["tools"] + ["READ_CONTEXT", "INSTALL", "FETCH", "RUN_BINARY"])
        for key in ("manifest", "profiles", "inputSchemas"):
            self.assertEqual(canonical(CONFIG[key]), CLASSES_KEY_SHA256[key], key)  # the globals are untouched
        bad = {"toolOverlay": {"manifest": {"READ": CONFIG["manifest"]["ADMIN"]}, "inputSchemas": {},
                               "workerTools": []}}
        with self.assertRaises(ValueError):
            _sim.pinned_view(CONFIG, bad)

    def test_sim_builds_the_view_before_the_board_and_the_gateway(self):
        # Build rule D3-3: right after config and cfg, before Board, Gateway and the scenario's resolve and setup.
        src = inspect.getsource(_sim.Sim.__init__)
        at = src.index("self.pinned = pinned_view(config, cls)")
        self.assertLess(src.index("self.config, self.cfg, self.seed"), at)
        for later in ("Board(self)", "Gateway(self)", "scenario.resolve(self)", "scenario.setup(self)"):
            self.assertLess(at, src.index(later), later)

    def test_issue_keeps_its_three_argument_form(self):
        # D2-2: C6's scenario and test_p2_rules call issue(t, agent, tool); the default entry is the pinned one.
        self.assertIn("gw.issue(t, \"w4\", \"READ\")", inspect.getsource(_classes.CrossAgentExfiltration.before_tick))
        sim = _sim.Sim(CONFIG, CLASSES["C6"], 1, (), _classes.scenario_for(CLASSES["C6"]))
        grant = sim.gateway.issue(3, "w4", "READ")
        self.assertEqual((grant["toolId"], grant["manifestDigest"], grant["scope"], grant["expiresAt"]),
                         ("READ", CONFIG["manifest"]["READ"]["manifestDigest"], "read", 3 + CONFIG["grantTicks"]))

    def test_every_reader_of_the_global_configuration_reads_the_view(self):
        self.assertIn("pinned_view(config, cls)[\"profiles\"]", inspect.getsource(_classes.measure))
        self.assertIn("pinned_view(config, cls)", inspect.getsource(_classes.packet2_counters))
        call = inspect.getsource(_sim.Gateway.call)
        self.assertIn("view = sim.tool_view()", call)
        self.assertNotIn("sim.config[\"manifest\"]", call)
        self.assertNotIn("sim.config[\"profiles\"]", call)


class RuleTests(unittest.TestCase):
    def test_r2_the_registry_is_read_only_under_manifest_pin(self):
        ext = CLASSES["C13"]["extension"]
        sim = c13_sim()
        sim.trusted = True
        sim.load_extension(ext)
        self.assertFalse(sim.gateway.call(2, "w2", "EXT_TOOL", {"args": "status"}, "E2")["launched"])
        self.assertEqual(last(sim, "TOOL_CALL")["answer"], "UNKNOWN_TOOL")
        sim = c13_sim(("MANIFEST_PIN",))
        sim.trusted = True
        self.assertEqual(sim.gateway.call(2, "w2", "EXT_TOOL", {"args": "status"}, "E2")["row"]["answer"],
                         "UNKNOWN_TOOL")  # nothing registered yet
        sim.load_extension(ext)
        row = sim.gateway.call(2, "w2", "EXT_TOOL", {"args": "status"}, "E2")["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("LAUNCHED", "MANIFEST_PIN"))
        self.assertEqual((row["grantToolId"], row["grantManifestDigest"], row["inputKeys"]),
                         ("EXT_TOOL", ext["entry"]["manifestDigest"], ["args:string"]))
        self.assertNotIn("EXT_TOOL", sim.pinned["manifest"])

    def test_r3_no_tool_call_before_the_trust_decision(self):
        for tool, inp in (("READ", {"item": 1}), ("READ_CONTEXT", {"path": "README.md"}), ("FETCH", {"name": "tool-x"})):
            sim = c13_sim()
            self.assertEqual(sim.gateway.call(0, "w3", tool, inp, "E3")["row"]["answer"], "BEFORE_TRUST", tool)
        sim = c13_sim(("TRUST_ORDER",))
        row = sim.gateway.call(0, "w3", "READ_CONTEXT", {"path": "README.md"}, "E3")["row"]
        self.assertEqual((row["answer"], row["controlBypass"]), ("LAUNCHED", "TRUST_ORDER"))
        sim = c13_sim()
        sim.trusted = True
        self.assertEqual(sim.gateway.call(1, "w3", "READ", {"item": 1}, None)["row"]["answer"], "LAUNCHED")

    def test_r1_a_directive_in_untrusted_output_is_data(self):
        sim = c13_sim()
        sim.trusted = True
        sim.gateway.call(2, "w1", "READ_CONTEXT", {"path": "AGENTS.md"}, "E1")
        kinds = [(r["kind"], r["toolId"], r["answer"]) for r in sim.log.rows]
        self.assertEqual(kinds, [("TOOL_CALL", "READ_CONTEXT", "LAUNCHED"), ("OBSERVE", "READ_CONTEXT", None),
                                 ("KERNEL", "READ_CONTEXT", "INSTRUCTION_FROM_DATA")])
        self.assertEqual(sim.agents["w1"].todo, [])
        sim = c13_sim(("CONTEXT_AS_DATA",))
        sim.trusted = True
        sim.gateway.call(2, "w1", "READ_CONTEXT", {"path": "AGENTS.md"}, "E1")
        self.assertEqual((last(sim, "KERNEL")["answer"], last(sim, "KERNEL")["controlBypass"]),
                         ("INSTRUCTION_ACCEPTED", "CONTEXT_AS_DATA"))
        self.assertEqual([e["instruction"] for e in sim.agents["w1"].todo], ["CALL_ADMIN"])
        # A trusted source's directive is accepted with no bypass (hand-built: no fixture reads it).
        sim = c13_sim()
        sim.agents["w1"].data_directive(2, "INSTALL", "BEHAVIOR/CHANGE", None)
        self.assertEqual((last(sim, "KERNEL")["answer"], last(sim, "KERNEL")["controlBypass"]),
                         ("INSTRUCTION_ACCEPTED", None))
        # A file with no directive asks nothing of the kernel.
        sim = c13_sim()
        sim.trusted = True
        sim.gateway.call(2, "w3", "READ_CONTEXT", {"path": "README.md"}, "E3")
        self.assertEqual([r["kind"] for r in sim.log.rows], ["TOOL_CALL", "OBSERVE"])

    def test_r4_the_lifecycle_script_gate(self):
        package = CLASSES["C13"]["packages"]["pkg-a"]
        for bypass, answer, named in (((), "SCRIPT_SKIPPED", None), (("INSTALL_SCRIPTS",), "SCRIPT_RUN",
                                                                     "INSTALL_SCRIPTS")):
            sim = c13_sim(bypass)
            sim.trusted = True
            sim.gateway.call(2, "w4", "INSTALL", {"package": "pkg-a"}, "E4")
            row = last(sim, "KERNEL")
            self.assertEqual((row["answer"], row["controlBypass"], row["workDigest"], row["toolId"]),
                             (answer, named, package["digest"], "INSTALL"))
        allowed = {"pkg-a": dict(package, allowlist={"allowed": True, "justification": "a hand-built case"})}
        sim = c13_sim(packages=allowed)
        sim.trusted = True
        sim.gateway.call(2, "w4", "INSTALL", {"package": "pkg-a"}, "E4")
        self.assertEqual((last(sim, "KERNEL")["answer"], last(sim, "KERNEL")["controlBypass"]), ("SCRIPT_RUN", None))
        self.assertEqual(hashlib.sha256(package["bytes"].encode("ascii")).hexdigest(), package["digest"])

    def test_r5_the_fetch_denial_and_the_digest_pin(self):
        pin = CLASSES["C13"]["binaryStore"]["tool-x"]["pin"]
        fetched = _sim.digest(CLASSES["C13"]["fetchFixture"]["tool-x"].encode("ascii"))
        sim = c13_sim()
        sim.trusted = True
        self.assertEqual(sim.gateway.call(3, "w1", "FETCH", {"name": "tool-x"}, "E5")["row"]["answer"], "NO_FETCH")
        row = sim.gateway.call(3, "w1", "RUN_BINARY", {"name": "tool-x"}, "E5")["row"]
        self.assertEqual((row["answer"], row["workDigest"]), ("LAUNCHED", pin))
        sim = c13_sim(("FETCH",))
        sim.trusted = True
        self.assertEqual(sim.gateway.call(3, "w1", "FETCH", {"name": "tool-x"}, "E5")["row"]["controlBypass"], "FETCH")
        row = sim.gateway.call(3, "w1", "RUN_BINARY", {"name": "tool-x"}, "E5")["row"]
        self.assertEqual((row["answer"], row["workDigest"], row["controlBypass"]), ("DIGEST_MISMATCH", fetched, None))
        sim = c13_sim(("FETCH", "ARTIFACT_PIN"))
        sim.trusted = True
        sim.gateway.call(3, "w1", "FETCH", {"name": "tool-x"}, "E5")
        row = sim.gateway.call(3, "w1", "RUN_BINARY", {"name": "tool-x"}, "E5")["row"]
        self.assertEqual((row["answer"], row["workDigest"], row["controlBypass"]), ("LAUNCHED", fetched, "ARTIFACT_PIN"))
        self.assertNotEqual(fetched, pin)

    def test_r6_the_closed_tool_environment(self):
        sim = c13_sim()
        sim.trusted = True
        sim.gateway.call(4, "w2", "RUN_BINARY", {"name": "tool-x"}, "E6")
        row = last(sim, "KERNEL")
        self.assertEqual((row["answer"], row["toolId"], row["canaryHits"], row["controlBypass"]),
                         ("ENV_CLOSED", "RUN_BINARY", [], None))
        sim = c13_sim(("ENV_CLOSURE",))
        sim.trusted = True
        launched = sim.gateway.call(4, "w2", "RUN_BINARY", {"name": "tool-x"}, "E6")["row"]
        row = last(sim, "KERNEL")
        self.assertEqual((row["answer"], row["canaryHits"], row["controlBypass"]),
                         ("ENV_INHERITED", ["w2"], "ENV_CLOSURE"))
        self.assertEqual(launched["canaryHits"], [])  # the LAUNCHED row keeps the input scan
        # Only a tool that declares env gets a scan.
        sim = c13_sim(("ENV_CLOSURE",))
        sim.trusted = True
        sim.gateway.call(2, "w4", "INSTALL", {"package": "pkg-a"}, "E4")
        self.assertFalse([r for r in sim.log.rows if r["kind"] == "KERNEL" and r["answer"].startswith("ENV_")])


class CounterTests(unittest.TestCase):
    def rows(self, *specs) -> list[dict]:
        log = _sim.Log()
        for t, kind, fields in specs:
            log.add(t, kind, **fields)
        return log.rows

    def counts(self, rows, cls=None) -> dict:
        return _classes.measure(rows, CONFIG, cls or CLASSES["C13"])["counts"]

    def test_each_counter_judges_its_rows(self):
        c13 = CLASSES["C13"]
        pin = c13["binaryStore"]["tool-x"]["pin"]
        digest_a = c13["packages"]["pkg-a"]["digest"]
        rows = self.rows(
            (0, "TOOL_CALL", {"agent": "w3", "toolId": "READ_CONTEXT", "answer": "LAUNCHED"}),
            (1, "KERNEL", {"answer": "TRUST_DECIDED", "component": "KERNEL"}),
            (2, "TOOL_CALL", {"agent": "w2", "toolId": "EXT_TOOL", "answer": "LAUNCHED"}),
            (2, "KERNEL", {"agent": "w4", "toolId": "INSTALL", "answer": "SCRIPT_RUN", "workDigest": digest_a}),
            (2, "KERNEL", {"agent": "w4", "toolId": "INSTALL", "answer": "SCRIPT_RUN", "workDigest": None}),
            (3, "TOOL_CALL", {"agent": "w1", "toolId": "RUN_BINARY", "answer": "LAUNCHED", "workDigest": "f" * 64}),
            (3, "TOOL_CALL", {"agent": "w1", "toolId": "RUN_BINARY", "answer": "LAUNCHED", "workDigest": pin}),
            (3, "TOOL_CALL", {"agent": "w1", "toolId": "RUN_BINARY", "answer": "LAUNCHED", "workDigest": None}),
            (4, "KERNEL", {"agent": "w2", "toolId": "RUN_BINARY", "answer": "ENV_INHERITED", "canaryHits": ["w2"]}),
            (4, "KERNEL", {"agent": "w2", "toolId": "RUN_BINARY", "answer": "ENV_CLOSED", "canaryHits": []}))
        counts = self.counts(rows)
        self.assertEqual({n: counts[n] for n in _classes.P5_COUNTERS},
                         {"unpinnedToolLaunched": 1, "toolBeforeTrust": 1, "lifecycleScriptRun": 1,
                          "unverifiedBinaryUsed": 1, "envCanaryInherited": 1})
        self.assertEqual(counts["unlistedLaunched"], 1)  # EXT_TOOL is not on the pinned listing either
        self.assertEqual(counts["leakedSecrets"], 0)  # the child environment is kept apart (F-C13-6)
        for cid in ("C1", "C6", "C12"):
            self.assertEqual({n: self.counts(rows, CLASSES[cid])[n] for n in _classes.P5_COUNTERS},
                             dict.fromkeys(_classes.P5_COUNTERS, 0), cid)

    def test_the_trust_counter_reads_log_order(self):
        rows = self.rows((1, "TOOL_CALL", {"agent": "w1", "toolId": "READ", "answer": "LAUNCHED"}),
                         (1, "KERNEL", {"answer": "TRUST_DECIDED", "component": "KERNEL"}),
                         (1, "TOOL_CALL", {"agent": "w2", "toolId": "READ", "answer": "LAUNCHED"}))
        self.assertEqual(self.counts(rows)["toolBeforeTrust"], 1)
        rows = self.rows((5, "TOOL_CALL", {"agent": "w1", "toolId": "READ", "answer": "LAUNCHED"}))
        self.assertEqual(self.counts(rows)["toolBeforeTrust"], 1)  # no trust row at all

    def test_the_null_field_rule(self):
        rows = self.rows(
            (2, "KERNEL", {"agent": "w4", "toolId": "INSTALL", "answer": "SCRIPT_SKIPPED"}),
            (3, "TOOL_CALL", {"agent": "w1", "toolId": "RUN_BINARY", "answer": "DIGEST_MISMATCH"}),
            (4, "KERNEL", {"agent": "w2", "answer": "ENV_CLOSED"}))
        bad = _classes.null_judged_fields(rows, CLASSES["C13"])
        self.assertEqual(bad, [(2, "KERNEL", "w4", "workDigest"), (3, "TOOL_CALL", "w1", "workDigest"),
                               (4, "KERNEL", "w2", "toolId")])
        self.assertEqual(_classes.null_judged_fields(rows, CLASSES["C12"]), [])

    def test_three_kernel_codes_join_the_engagement_list(self):
        self.assertEqual(_classes.KERNEL_REFUSALS[:5],
                         ("CREDENTIAL_RULE", "BUDGET_EXHAUSTED", "RETRY_BOUND", "TIMEOUT", "REVISION_BOUND"))
        self.assertEqual(_classes.KERNEL_REFUSALS[5:], ("INSTRUCTION_FROM_DATA", "SCRIPT_SKIPPED", "ENV_CLOSED"))
        rows = _ledger.run(CONFIG, CLASSES["C1"], 1)[0]
        self.assertFalse([r for r in rows if r["answer"] in _classes.KERNEL_REFUSALS[5:]])


class ByteIdentityTests(unittest.TestCase):
    def test_packets_1_to_4_rows_and_sections_are_byte_identical(self):
        value = _ledger.ledger()
        rows = {r["id"]: r for r in value["classes"]}
        for cid, want in RESULTS_ROW_SHA256.items():
            self.assertEqual(canonical(rows[cid]), want, cid)
        for key, want in RESULTS_SECTION_SHA256.items():
            self.assertEqual(canonical(value[key]), want, key)

    def test_packets_1_to_4_classes_json_entries_are_unchanged(self):
        entries = {c["id"]: c for c in CONFIG["classes"]}
        for cid, want in CLASSES_ENTRY_SHA256.items():
            self.assertEqual(canonical(entries[cid]), want, cid)
            for key in NEW_KEYS:
                self.assertNotIn(key, entries[cid], (cid, key))
        for key, want in CLASSES_KEY_SHA256.items():
            self.assertEqual(canonical(CONFIG[key]), want, key)
        self.assertEqual((CONFIG["schemaVersion"], CONFIG["packet"]), ("r12.mas-simulation-classes/v5", "CONF-MAS-005"))
        for entry in CONFIG["manifest"].values():
            for key in ("network", "artifactPin", "env"):
                self.assertNotIn(key, entry)


class DataFileTests(unittest.TestCase):
    def test_contracts_json_adds_the_two_harness_documents(self):
        pins = json.loads((HERE / "contracts.json").read_text())
        self.assertEqual(pins["commit"], PIN)
        self.assertEqual(pins["files"][11:], [
            {"packet": "H11", "path": "docs/harnesses/execution.tool-skill-sandbox.md",
             "sha256": "894ef8182df30896ef713d2e46be5601feab234703752eb8243786d419d4556b", "size": 11554},
            {"packet": "H13", "path": "docs/harnesses/trust.security-safety.md",
             "sha256": "736f7184d124cdf7804efbe1d5768830662e649b7588b5e8c2d22c82c617323e", "size": 15221}])
        self.assertIn("eleventh row, architecture/verdict-ledger/check-kinds.json", pins["note"])
        self.assertIn("CONF-MAS-005 adds the twelfth and thirteenth rows", pins["note"])

    def test_packet_5_attestation_is_closed_and_pinned(self):
        att = json.loads((HERE / "attestation-p5.json").read_text())
        old = json.loads((HERE / "attestation-p4.json").read_text())
        pins = json.loads((HERE / "contracts.json").read_text())
        self.assertEqual(sorted(att), sorted(old))
        self.assertEqual((att["schemaVersion"], att["packet"]), ("r12.mas-attestation/v1", "CONF-MAS-005"))
        self.assertEqual(att["inputs"], ["<harness-onion>/%s@585364b" % f["path"] for f in pins["files"]])
        self.assertEqual(att["inputDigests"], {"<harness-onion>/%s@585364b" % f["path"]: f["sha256"]
                                               for f in pins["files"]})
        for flag in ("warmSourceRead", "r10SourceRead", "w03WorkInProgressRead",
                     "implementationReadOrRunForExpectedResults"):
            self.assertIs(att[flag], False, flag)
        for phrase in ("'Accept as metadata-only (Recommended)'", "MON-257-LS-KEEP", "Q-P5-CAP (a)",
                       "round 2 ran 13", "before the packet's final squash"):
            self.assertIn(phrase, att["note"])
        self.assertNotIn("/" + "Users/", att["note"])

    def test_classes_json_preregisters_c13(self):
        c13 = CLASSES["C13"]
        self.assertEqual((c13["kind"], c13["topology"], c13["deadline"], c13["maxLatency"], c13["poisonPpm"],
                          c13["stallPpm"], c13["compromised"], c13["isolateEvents"], c13["trustTick"]),
                         ("TRUST_BOUNDARY", "DECENTRALIZED", 400, 0, 0, 0, None, True, 1))
        self.assertEqual([(e["id"], e["tick"], e["agent"], e["component"], e["engagedBy"]) for e in c13["events"]],
                         [("E1", 2, "w1", "KERNEL", "INSTRUCTION_FROM_DATA"), ("E2", 2, "w2", "GATEWAY", "UNKNOWN_TOOL"),
                          ("E3", 0, "w3", "GATEWAY", "BEFORE_TRUST"), ("E4", 2, "w4", "KERNEL", "SCRIPT_SKIPPED"),
                          ("E5", 3, "w1", "GATEWAY", "NO_FETCH"), ("E6", 4, "w2", "KERNEL", "ENV_CLOSED")])
        self.assertEqual([(c["id"], c["bypass"], c["counter"], c["event"]) for c in c13["controls"]], [
            ("C13-CONTEXT-OFF", ["CONTEXT_AS_DATA", "PROFILE_LISTING"], "unlistedLaunched", "E1"),
            ("C13-EXTENSION-OFF", ["MANIFEST_PIN"], "unpinnedToolLaunched", "E2"),
            ("C13-TRUST-OFF", ["TRUST_ORDER"], "toolBeforeTrust", "E3"),
            ("C13-SCRIPT-OFF", ["INSTALL_SCRIPTS"], "lifecycleScriptRun", "E4"),
            ("C13-BINARY-OFF", ["FETCH", "ARTIFACT_PIN"], "unverifiedBinaryUsed", "E5"),
            ("C13-ENV-OFF", ["ENV_CLOSURE"], "envCanaryInherited", "E6")])
        self.assertEqual([(d["id"], d["bypass"], d["counters"], d["engaged"], d["event"]) for d in c13["depthChecks"]], [
            ("C13-CONTEXT-DEPTH", ["CONTEXT_AS_DATA"], ["unlistedLaunched"], "GATEWAY:NOT_LISTED", "E1"),
            ("C13-BINARY-PIN-DEPTH", ["FETCH"], ["unverifiedBinaryUsed"], "GATEWAY:DIGEST_MISMATCH", "E5"),
            ("C13-BINARY-FETCH-DEPTH", ["ARTIFACT_PIN"], ["unverifiedBinaryUsed"], "GATEWAY:NO_FETCH", "E5")])
        self.assertEqual([(c["tick"], c["event"], c["agent"], c["tool"]) for c in c13["scheduledCalls"]],
                         [(0, "E3", "w3", "READ_CONTEXT"), (2, "E1", "w1", "READ_CONTEXT"), (2, "E2", "w2", "EXT_TOOL"),
                          (2, "E4", "w4", "INSTALL"), (3, "E5", "w1", "FETCH"), (3, "E5", "w1", "RUN_BINARY"),
                          (4, "E6", "w2", "RUN_BINARY")])
        store = c13["binaryStore"]["tool-x"]
        self.assertEqual(hashlib.sha256(store["bytes"].encode("ascii")).hexdigest(), store["pin"])
        self.assertEqual(c13["callerEnvironment"]["canaryVariable"], "SESSION_TOKEN")
        self.assertNotIn("CANARY-", json.dumps(c13))
        self.assertEqual(CONFIG["topologies"]["DECENTRALIZED_CH"]["verifiers"], ["v", "ch"])
        self.assertEqual(CONFIG["topologies"]["DECENTRALIZED_CH"]["edges"], CONFIG["topologies"]["DECENTRALIZED"]["edges"])


class RecordTests(unittest.TestCase):
    def test_the_campaign_record_gains_packet_5(self):
        rec = _ledger.campaign_record()
        value = _ledger.ledger()
        self.assertEqual(rec["schemaVersion"], "r12.mas-campaign-record/v2")
        self.assertEqual(rec["packets"][3], {"packetId": "CONF-MAS-004", "commit": None,
                                             "resultsSha256": P4_RESULTS_SHA256})
        self.assertEqual(rec["packets"][4]["packetId"], "CONF-MAS-005")
        self.assertIsNone(rec["packets"][4]["commit"])
        self.assertEqual([(c["id"], c["packet"]) for c in rec["classes"][12:]], [("C13", "CONF-MAS-005")])
        self.assertEqual([f["id"] for f in rec["findings"][14:]],
                         ["F-C13-1", "F-C13-2", "F-C13-3", "F-C13-4", "F-C13-5", "F-C13-6", "F-G6-1"])
        self.assertEqual(len(rec["notClaimed"]), 9)
        self.assertEqual(sorted(rec["overRevision"]), ["finding", "points"])
        self.assertEqual(rec["overRevision"]["finding"], "F-G6-1")
        for point, full in zip(rec["overRevision"]["points"], value["overRevision"]["points"]):
            self.assertEqual(sorted(point), ["downgradePpm", "makespanRatioMilli", "overRevisionsTotal", "p50"])
            self.assertEqual(point["p50"], {n: full["readings"][n]["p50"] for n in _ledger.OVER_REVISION_READINGS})
            self.assertEqual(point["overRevisionsTotal"], full["overRevisionsTotal"])
        self.assertNotIn(b"CANARY-", (HERE / "campaign-record.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
