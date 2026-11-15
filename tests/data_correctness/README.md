# Data-correctness conformance cases (CONF-DATA-001)

This suite is roadmap item CONF-DATA-001: R12's cases for harness-onion's data-correctness contract (DATA-CORRECTNESS-001,
packet MET-007, the record `architecture/data-correctness/record.json`). It runs offline and uses only the Python 3.12
standard library. Pins are in `contracts.json`: the record, its schema, the reference model and the 13 golden vectors at
one harness-onion commit.

It has three layers:

- **Golden-vector parity.** `golden/` holds the record's 13 vectors, byte-identical to the pins. `_judge.py` restates the
  record's seven rule families in R12's own words; no bytes of the reference model are copied or imported. The judge
  returns each vector's expect, 13 of 13.
- **Deterministic simulation.** `_sim.py` runs each case of `cases.json` as a small world: actors, stores with guard
  modes, a lease store with fencing modes, fake monotonic and wall clocks with skew and jumps, process pauses,
  duplicate, reordered and lost deliveries, crashes at the five PAR-D1 points, a versioned record codec, derived stores
  fed by a change log, and a replay engine. A run is a pure function of (case, arm, seed); the random source is seeded
  by (case, seed) only, so a case's arms share the seed's schedule, and each CONTROL or NEGATIVE arm differs from the
  case's DEFENDED arm in the one switch that names it.
- **Obligation matrix.** `obligations.json` restates the record's 103 cells (24 deployables, each with the families that
  bind it). Each cell names the cases that test its rule on the simulation; every adapter is PENDING.

## Readings and gates

Each run gives three readings, made independently of the judge: the trace (vector shape `{id, family, setup, steps,
expect}`, where expect is a refusal when the run broke its family's rule), whether the run broke the rule, and whether
the business outcome read from the final state is wrong. An aborted RF-1 commit step carries an informational `aborted` marker; no
judge reads it. The ledger (`_ledger.py`, `results.json`) runs seeds 1 to 32
in every arm and checks:

- in every run, the judge returns the trace's expect, and no outcome violation happens without a broken rule;
- DEFENDED arms: no errored run, no broken rule, no violation;
- CONTROL and NEGATIVE arms: no errored run, every refusal carries the case's code, and violations reach the arm's
  floor (32 where the schedule forces the violation; 24 for OP-01, OP-03 and OP-04, because in one seed in four the first
  attempt never lands: the CP-3 seeds of OP-01 and OP-04 and the unapplied seeds of OP-03, and OP-01's 24 is a lower
  bound; 8 for OP-07, whose IRREVERSIBLE seeds are one in four);
- errored runs count in the denominator (HR-D1's denominator rule); each arm keeps the sha256 over its sorted per-seed
  trace digests, so a rerun regenerates `results.json` byte for byte.

`campaign-record.json` is this packet's entry for CONF-A3-001's campaign record: an input, not a gate (HO-D2).

## Cases

29 cases: WS-01 to WS-03 (RF-1 write skew), FN-01 to FN-03 (RF-2 fencing), CK-01 to CK-04 (RF-3 clocks), OP-01 to OP-07
(RF-4 operation IDs), CV-01 to CV-06 (RF-5 compatibility), DD-01 to DD-04 (RF-6 derived data), RS-01 and RS-02 (RF-7
replay state). The crash points sit in WS-01 and OP-01 (CP-1 pre-commit; in OP-01 it gives the same attempts as a lost answer), OP-02 (CP-2 post-commit, pre-acknowledgement),
OP-01 and OP-04 (CP-3 pre-effect), OP-03, OP-04 and OP-07 (CP-4 post-effect, pre-receipt), and FN-01, FN-02 and CK-02
(CP-5 approval and resume).

## R12 extensions (provisional)

CK-04 (host replacement, RF-3), CV-04 (opaque extension data that must stay inert, RF-5) and DD-04 (PAR-D1's restore
scenario, RF-6) use an op or field the reference model lacks. Under the visionary's ruling VIS-C15-SPLIT they are
R12-authored cases, labelled R12_EXTENSION here, in the packet record and in the campaign record, and never conformance
to the merged record's 13 vectors. Their expected arms are R12's until the record's successor rules; then the case
follows the record (HO-D2). DD-04 follows the PAR-D1 note: the deletion ledger is re-applied before the restored
installation serves, and its residuals are stated (backup copies until their retention ends, exports delivered before
the erasure, opaque references not disclosed by default). Their candidate vectors go to R00 through the lane monitor as
an input to the record's successor, never as a gate on this packet.

## Finding

F-CD-1: RF-1's reissue rule covers a retry after a serialization failure only. A process that dies between an effect
issued inside its transaction and the commit neither commits nor aborts, so its restart's reissue is not RF-1's refusal;
RF-4's operation IDs, deduplicated at the effect's store, cover it. WS-03 injects no crash for that reason.

F-CD-2: the reference model at the pinned commit forgets an abort when a retry reuses the aborted transaction's name,
and then accepts the reissued effect. R12's judge remembers it (packet review CD-P1-1). No simulated trace reuses a
name, so no case result depends on it. Both findings go to R00 through the lane monitor.

## Not claimed

No plane adapter is tested. No exactly-once delivery is claimed: applied once means at the effect's own store, under that
store's deduplication. The simulation shows that the rules are decidable and that the judge catches each one-switch
break; it is not evidence about the product.
