# Enforcement test area (W04)

W04 test source for the Harness-Onion enforcement work, per the adopted W04-0 plan
(`snapshots/harness-onion/architecture/enforcement-test-plan/traceability.json`). It is set up by CONF-ENF-001 (W04-1).

## Rules

- Independence: expected results come only from the adopted contracts' reference models and vectors in `snapshots/`,
  never from reading or running an implementation. No R10 source and no W03 work in progress is read. Every W04 packet
  adds `attestations/<packet>.json` with the plan's attestation fields, and its separate-agent reviewer checks it.
- Toolchain (owner decision Q-T1, 2026-10-11): Python 3.12 standard-library `unittest` only; no pytest and no
  dependency. Rust+musl native probes are deferred (Q-T2) to the first W04 packet that needs native probe source.
  `toolchains.json` records both, the open gaps G-JSONSCHEMA and G-REPLAY-INPUTS (the I06 v2 and native v3 replays'
  inputs outside the snapshots) and the closed gap G-I06-V1 (Q-T5).
- The stdlib-only R12 reader (`src/`) never imports this area, and this area's own test code imports only the standard
  library and this area. The one exception is `tg02_lifecycle/test_reader_guards.py`, which imports the R12 reader as
  LEDGER-E09's subject (owner decision Q-T9).
- Snapshots are byte-exact copies from harness-onion, pinned in `snapshots/manifest.json` by sha256 and size at each
  file's own source commit (manifest v2, owner decision Q-T10). A snapshot is never edited; a newer contract version
  comes in as a new snapshot set.
- History (owner decision Q-T3, 2026-10-11): each R12 packet from CONF-ENF-001 on adds one closed record
  `fixtures/ci/<packet>-checkpoint.json` and one entry in `fixtures/ci/checkpoints.json`, naming every path it deleted,
  changed or added with exact pins. Later W04 packets are data plus tests only. That the registry is append-only and a
  merged record is never rewritten is checked by review of each packet's diff, not by code (review E1-2).

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
  and dynamic guards, with expected outcomes from E09 and A02 only (owner decision Q-T9). Its ledger row lists each
  property with its tests. Two properties need the enrolled Linux host and are carried by named W06 native cases of the
  plan; the case is PASS when every property within its own scope ran (owner decision Q-T11). Every other case
  waits for W05's release set or for W06's native hosts and is NOT_RUN_ENV_UNAVAILABLE; `_catalog.py` fixes now, by
  rules over the vectors' own content, which contract vectors (and so which expected results) each one means (owner
  decision Q-T8).

## Running

    python3 -m unittest discover -s tests/enforcement -p "test_*.py"

Subdirectories holding tests (for example `tg01_contract/` from W04-2) are packages with an `__init__.py`.
