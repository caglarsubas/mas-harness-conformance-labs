# CONF-FIX-002 — quoted packet scalar compatibility

Phase: Alpha 2. This is source-only compatibility work, not Linux, live-backend,
deployment, runtime, assurance or tenant acceptance.

## Authority and exact scope

Consumes MET-REPAIR-007 at meta main
`c526ccaa293b2113032c5a5b4a037e35baacb196` (PR 101, required CI 34122702351,
1549 passed / ten retained nested-isolation skips in local/head, CI and separate
exact-main replay). Its exact-main log is
`1b4c47a23406390b60e7375a4d6a0dcedbf9a6a880c963a2c87e1aa2dd8c9ce2`.
The product baseline is accepted CONF-LINUX-001 main
`88de1d9b7272a25678b01129e51d5756dbe608ed`, 103 files and 120 test identities.
Its source kit is not native Linux qualification.

Packet SHA-256:
`c8639e527496660b8211f5bdcdb8f7470129b7d00f938c061d34630c797d8af4`.
Only the scalar branch in `ci/run_packet.py`, one exact assertion in
`test_linux_inventory.py`, and this packet's three new test/fixture/report files
may change. All original packet YAML bytes and all other product files remain
unchanged. No Make/dispatcher/wrapper, root policy/helper/key/sudoers, dependency,
workflow, warm-source, egress or billing change is authorized.

## Diagnosis and regression design

Published CONF-LIVE-001 through 006 have JSON-double-quoted identity strings.
The old product reader retained their quotes; identity validation then failed.
The approved correction decodes JSON-quoted strings or retains bare identifiers,
then requires bounded ASCII identifier grammar. It does not deserialize general
YAML or modify custody, command transport, digest rechecks, environment or canary
behavior. The legacy hash assertion must pin the exact corrected parser, not
exempt it or rewrite historical fixture hashes.

The new source fixture is inert data and pins the original 103-file/120-ID
baseline, exact transformations and all six published packet byte strings/views.
Thirty new tests use the real current parser and validator, test quoted/bare/
mixed forms, escapes, malformed/types/controls/indirection/duplicates, identity
and command restrictions, and prove complete source/discovery closure.
Mocked sessions exercise command order, digest checks and fail-fast cleanup on
both OS marker variants. These are unit cases, never native or live executions.
Valid argv order is preserved; changed order is a different digest-bound packet,
not silently normalized or accepted as the original signed authority.

The corrected whole-file hashes must be exactly:

| File | SHA-256 |
|---|---|
| `ci/run_packet.py` | `397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1` |
| `tests/platform/linux_baseline/test_linux_inventory.py` | `9111de6b6e167c2eca41801bffc5430b1af8c85f7da696c11a20cce577a1bb29` |

## Evidence checkpoint

This report records the red replay and is committed before the corrected replay.
No green result is inferred from inspection or test count declarations. Execute only the seven
packet-declared commands through the installed signed offline launcher: all five
suite roots, then the unchanged offline Linux campaign and evidence commands.
No direct acceptance command or live campaign may be run outside that boundary.

| Gate | Current checkpoint |
|---|---|
| New regressions on unchanged old parser | REPRODUCED — red checkpoint below; not acceptance |
| Corrected exact-head offline | PENDING |
| Required localhost PR CI | PENDING |
| Merge | PENDING |
| Separate local exact-main | PENDING |
| Native AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE |
| Live/backend/runtime/tenant acceptance | NOT_RUN_ENV_UNAVAILABLE |

The signed isolated test-only checkpoint
`a4f8c83131d8552f648cb14831acbe887b07f65d` retained both original files.
Activation 58 and fresh OS isolation succeeded. All five suite commands ran:
37 meta, 14 parity, nine Alpha-1, 23 runner-boundary and 67 Linux-baseline tests.
All 120 predecessor tests passed. New tests produced 237 failing subcases and
four error records: quoted identities were not decoded, malformed identifiers
were not rejected, and the two required source transformations were absent.
The independent inventory collected all 120 predecessor plus 30 new test IDs,
without skips. These are subcase/error counts, not 241 distinct test methods.
The fail-fast launcher exited 1; the final campaign and evidence commands were
NOT_RUN. The clean detached clone had no working-tree overlay or tracked edits.
Red log SHA-256:
`d1f8b7c6891051a7b91d0b50189d3448255f2a02074cd75713d5e42e92eaf6ef`.
Corrected head, PR CI, merge and exact-main evidence will be published in the PR
and retained operator records separately from this pre-green source checkpoint.

The earlier session draft PR 6 at `57ee9668e029b08310c57f502990e419b4a1c797`
remains untouched and blocked. Activation 53 established isolation, but exited 2
before any acceptance command or test; log SHA-256
`604f1ae0a94ed058d0243fd43e0268c5e524ad6a7259e9aa5f0b0b788aa02d39`.
Its queued CI 34115040866 / job 101719758135 was cancelled without a runner:
CANCELLED_NOT_PASS. Preserve that historical refusal separately from this
packet's new actual regression evidence.

## Remaining roadmap and rollback

Close this packet's source/local/required CI/merge/exact-main gates before
resuming CONF-LIVE-001. That successor must retain its original 103-file/120-ID
history and add exact corrective commit/hash/test inventory proof only within
its already-owned files. Do not reserialize signed packet YAML or import its
unaccepted session draft into this correction.

CONF-LIVE-002 through 006 remain separate source/backend steps. Independent
native AMD64 qualification still gates CTRL-INTEGRATE-001, MODEL-001, EXEC-001
and RUN-001; ARM64 requires separate qualification. Alpha 2 is not complete,
and no phase-end model-effort change is due.

Before downstream consumption, use a reviewed revert/corrective packet if
rollback is needed. After consumption, publish a reviewed successor instead of
rewriting signed authority or fixture history. Retain failed logs, source
inventories and operator replay records; do not alter tenant data or capacity.
