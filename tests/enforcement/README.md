# Enforcement test area (W04)

W04 test source for the Harness-Onion enforcement work, per the adopted W04-0 plan
(`snapshots/harness-onion/architecture/enforcement-test-plan/traceability.json`). It is set up by CONF-ENF-001 (W04-1).

## Rules

- Independence: expected results come only from the adopted contracts' reference models and vectors in `snapshots/`,
  never from reading or running an implementation. No R10 source and no W03 work in progress is read. Every W04 packet
  adds `attestations/<packet>.json` with the plan's attestation fields, and its separate-agent reviewer checks it.
- Toolchain (owner decision Q-T1, 2026-10-11): Python 3.12 standard-library `unittest` only; no pytest and no
  dependency. Rust+musl native probes are deferred (Q-T2) to the first W04 packet that needs native probe source.
  `toolchains.json` records both and the known gaps (G-JSONSCHEMA, G-I06-V1) in the snapshotted reference models.
- The stdlib-only R12 reader (`src/`) never imports this area, and this area's own test code imports only the standard
  library and this area.
- Snapshots are byte-exact copies from harness-onion, pinned in `snapshots/manifest.json` by sha256 and size at one
  source commit. A snapshot is never edited; a newer contract version comes in as a new snapshot set.
- History (owner decision Q-T3, 2026-10-11): each R12 packet from CONF-ENF-001 on adds one closed record
  `fixtures/ci/<packet>-checkpoint.json` and one entry in `fixtures/ci/checkpoints.json`, naming every path it deleted,
  changed or added with exact pins. Later W04 packets are data plus tests only. That the registry is append-only and a
  merged record is never rewritten is checked by review of each packet's diff, not by code (review E1-2).

## Running

    python3 -m unittest discover -s tests/enforcement -p "test_*.py"

Subdirectories holding tests (for example `tg01_contract/` from W04-2) are packages with an `__init__.py`.
