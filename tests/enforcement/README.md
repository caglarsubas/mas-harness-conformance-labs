# Enforcement test area (W04)

W04 test source for the Harness-Onion enforcement work, per the adopted W04-0 plan
(`snapshots/harness-onion/architecture/enforcement-test-plan/traceability.json`). It is set up by CONF-ENF-001 (W04-1).

## Rules

- Independence: expected results come only from the adopted contracts' reference models and vectors in `snapshots/`,
  never from reading or running an implementation. No R10 source and no W03 work in progress is read. Every W04 packet
  adds `attestations/<packet>.json` with the plan's attestation fields, and its separate-agent reviewer checks it.
- Toolchain (owner decision Q-T1, 2026-10-11): Python 3.12 standard-library `unittest` only; no pytest and no
  dependency. The native probes are Rust, standard library only, under `probes/enforcement/` (owner decision Q-T2-B,
  2026-10-13): CI checks their source with the standard-library gates in `test_probes.py`; they compile only on the
  author's machine with the installed Rust 1.99.0 tree (Q-T2-TOOL), recorded in `probes/enforcement/BUILD_EVIDENCE.json`
  as author evidence, until the R12 Rust profile exists. `toolchains.json` records both, the open gaps G-JSONSCHEMA and
  G-REPLAY-INPUTS (the I06 v2 and native v3 replays' inputs outside the snapshots) and the closed gap G-I06-V1 (Q-T5).
- The stdlib-only R12 reader (`src/`) never imports this area, and this area's own test code imports only the standard
  library and this area. The one exception is `tg02_lifecycle/test_reader_guards.py`, which imports the R12 reader as
  LEDGER-E09's subject (owner decision Q-T9).
- Snapshots are byte-exact copies from harness-onion, pinned in `snapshots/manifest.json` by sha256 and size at each
  file's own source commit (manifest v2, owner decision Q-T10). A snapshot is never edited; a newer contract version
  comes in as a new snapshot set.
- History (owner decision Q-T3, 2026-10-11): each R12 packet from CONF-ENF-001 on adds one closed record
  `fixtures/ci/<packet>-checkpoint.json` and one entry in `fixtures/ci/checkpoints.json`, naming every path it deleted,
  changed or added with exact pins. Later W04 packets are data, tests and the native probe source under
  `probes/enforcement/`. That the registry is append-only and a merged record is never rewritten is checked by review of
  each packet's diff, not by code (review E1-2).

## Test groups

- `tg01_contract/` (TG-01, CONF-ENF-002): every adopted contract's vectors replayed through its snapshotted reference
  model, loaded only through `_models.py`. `tg01_contract/results.json` is the ledger each run must reproduce exactly:
  every vector PASS, or NOT_RUN_ENV_UNAVAILABLE where its replay needs jsonschema (owner decision Q-T4); CODEC waits
  for W05's release. Its `caseResults` give each plan case per contract: PASS only when every vector mapped to the
  case ran and passed, otherwise NOT_RUN_ENV_UNAVAILABLE with the counts. W02D's reference check also reads the W01 base and `seccomp-allowlists/status.json`, snapshotted
  as recorded additions (owner decision Q-T7). The I05 v3 supplement (S01-S06, harness-onion 93d32e1) is replayed as
  its own vector set (owner decisions Q-T6, Q-T10).
- `tg02_lifecycle/` and `tg03_persistence/` (TG-02, TG-03, CONF-ENF-003): each group's `results.json` lists the plan's
  cases. LEDGER-E09, the only case runnable now, is tested by `test_reader_guards.py`: the R12 reader's private factory
  and dynamic guards, with expected outcomes from E09, E07 and A02 only (owner decision Q-T9). Its ledger row lists each
  property with its tests. Three properties need the enrolled Linux host and are carried by named W06 native cases of the
  plan; the case is PASS when every property within its own scope ran (owner decision Q-T11). Every other case
  waits for W05's release set or for W06's native hosts and is NOT_RUN_ENV_UNAVAILABLE; `_catalog.py` fixes now, by
  rules over the vectors' own content, which contract vectors (and so which expected results) each one means (owner
  decision Q-T8).

- `tg04_host/` and `tg05_clocks/` (TG-04, TG-05, CONF-ENF-004): native groups. Each `results.json` lists the plan's
  cases, all W06_NATIVE_ONLY and NOT_RUN_ENV_UNAVAILABLE, blocked by D-W02A-F2 and by D-PROBE-ROUTE (the W06 route by
  which the probes inject faults and observe under the enrolled policy, owner decision Q-T14). Each case's catalog names
  its contract rows with their source file: SELinux matrix v4 checks, seccomp v2 decisions, native v3 vectors and model
  rules, I05 v3 transcripts, W02D items and spec steps, and its obligation rows from
  `snapshots/harness-onion/docs/alpha-2/ENFORCEMENT_FEASIBILITY.md` (recorded addition, owner decision Q-T13). The TG-04
  probes come with CONF-ENF-005. TG-05's probes (`probes/enforcement/tg05_clocks`) inject one fault each and write a
  timeline; `tg05_clocks/_verdicts.py` judges that timeline with W06's answer log, under the rules from E07, E08 and E11
  (the deadline is the signed expiresAt on CLOCK_BOOTTIME, suspended time counts, a wall-clock step neither renews nor
  shortens it: Q-T13). The LEDGER-E09 properties carried by TG-04/TG-05 cases (Q-T11) are listed in those rows with the
  reader checks that observe them.

- `tg08_compatibility/` (TG-08, CONF-ENF-007): `results.json` lists the plan's cases in two parts kept apart (`part`):
  SOURCE (S44 and the three MATRIX cases) and INSTALLED (the same contract rows on the enrolled hosts in W06, blocked by
  D-W02A-F2). S44's subject is the native qualification v3 reference model. It lists one property per item of the plan's
  S44 case (W02D section 4.4's rejection list), each served by the S44 rows whose catalog basis starts with it. A
  property is PASS only when every one of its vectors replayed and passed in the run, and the table is derived from that
  replay; the native v3 model imports jsonschema, so today every property is NOT_RUN_ENV_UNAVAILABLE (owner decisions Q-T4
  and Q-T20). S44 turns PASS once the jsonschema root bundle lands and TG-01's native v3 replay is written with its missing
  inputs (gaps G-JSONSCHEMA and G-REPLAY-INPUTS in `toolchains.json`); TG-08 then needs only its ledger regenerated. Until
  then a run that gains jsonschema fails here, so the ledger is redone, never stale. The MATRIX cases wait for W05's
  release set (owner decision Q-T8): old profile rejection (native v3, I06 v2 and I05 v3 vectors of another version), new
  profile missing gate/backend (the role-set and backend-component refusals and the gate under the broker's key or
  paths), and export/upgrade/rollback without nonce reuse (every native v3 migration case, the v3-under-v2 cross-version
  cases a rollback meets, the I05 v3 BIND refusals of a replayed execution or reused manifest, and the configuration
  refusal of v1-shaped data: 4.4's migration sentence; no adopted contract vector names an export, so its source test
  comes with W05's release set).

## For W05 and W06 (TG-05)

- W06's driver of W05's released build writes the answer log `r12.enforcement-answer-log/v1`: one line per exchange with
  the gate or the reader, with the boot ID, the BOOTTIME when the request was sent and when the answer came, the party
  (GATE or SERVER), the operation (for the gate HTTP_REQUEST, ARM_ACTION, BIND_EXECUTION, CHANNEL_OPEN, ACTION_OUTCOME or
  GENERATION_STATUS or CLOSE_GENERATION, every bind and channel opening included; for the reader REQUEST), the execution
  and generation, the request, the answer and the refusal reason. Every gate row names the generation it was sent in
  (review D6-1); a CHANNEL_OPEN or CLOSE_GENERATION row names its generation and the execution "-". Log one CHANNEL_OPEN
  row per channel a broker attempts for a generation: ALLOWED when the gate answers its opening GENERATION_STATUS frame,
  REFUSED with the gate's channel-level reason otherwise; a frame refused at the channel level gets no row of its own,
  and only later frames are logged under their own operation (D6-5). The verdicts judge by the two instants; the gate's
  own decision instant is not observed (a request sent before a deadline and decided after it is not judged). Each
  judged request uses a new connection opened after the fault, so a CONNECTION_CLOSED refusal is the fault's.
- Driver schedule per run: exercise the tested execution (an allowed gate exchange and a served reader request) within
  60 s before the fault; do not close or drain its generation before the judged requests (a close by the system itself
  is part of the subject: D6-6); send its requests during the case's window: after the resume (stalled Python, suspend),
  after the deadline (rollback; in original deadlines its gate requests after the deadline and its reader requests
  between the restart and the deadline: D6-2), and for peer death/restart after the peer's restart (they may also go
  between the kill and the restart), repeatedly until the fresh bind: in the BROKER run once the restarted broker has
  attempted its channel, in the OBSERVER run once the observer is back (D6-3, R1-8); only then bind a fresh execution
  (after the tested execution's deadline when it must stay bound, as in original deadlines; in a new generation after a
  broker restart, at least 2 s after the judged requests, which the 1 s margin needs: R5-3) and send its reader requests.
- In the BROKER run the restarted broker's channel attempts are logged as CHANNEL_OPEN rows, including any into the dead
  generation (the gate must refuse it, T38); without a logged attempt E07-GATE stays NOT_RUN (R1-2, R1-9). The tested
  execution's BIND_EXECUTION is logged too: the dead generation is the one that bind names. E07-GATE stays NOT_RUN unless
  the generation's channel opening is logged before that bind, the tested execution has exactly one allowed bind, its
  rows name the bind's generation, and a channel attempt of the restarted broker is logged before the deadline, with the
  judged requests after it (R2-1, R3-1, R4-3, R4-4). Every gate row names its generation as an I05 v3 id, 64 lowercase
  hex characters; any other label makes the log malformed (R4-2). A PASS shows no logged reconnect was allowed; it does
  not show the gate refused one unless the restarted broker attempted the dead generation (R2-5).
- Carried for W06: the original-deadlines window lasts as long as the reader is down (a restart faster than about 2 s
  leaves E08-ORIGINAL NOT_RUN: D6-4); a reader answer SERVED from 1 s after its peer's death counts as broken, which W06
  confirms against E09's per-tick rechecks before the first native run (R1-7).
- Before each run W06 compares each probe binary's sha256 with the build it reviewed, passes that build's probe-tree
  digest to the verdicts (`verdict(case, runs, probe_tree)`), and checks the binding's policy digest against the enrolled
  record; after each run its harness performs the case's `harnessRestore`, whether or not the probe ended. A case whose
  inputs are malformed is recorded NOT_RUN_ENV_UNAVAILABLE with the reason, never PASS.
- The peer death/restart case needs one run per peer (BROKER and OBSERVER). The owner's reading also says a forward
  wall-clock step does not shorten the deadline; no TG-05 case of the plan exercises a forward step.

## Running

    python3 -m unittest discover -s tests/enforcement -p "test_*.py"

Subdirectories holding tests (for example `tg01_contract/` from W04-2) are packages with an `__init__.py`.
