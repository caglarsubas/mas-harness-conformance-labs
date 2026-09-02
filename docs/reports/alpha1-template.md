# Alpha-1 foundation campaign report

This template records a tenant-local foundation campaign. It never turns a missing environment into a pass and it never records tenant acceptance.

## Immutable subject

- Organization ID: `org.marmara-thermal` (synthetic fixture only)
- Profile digest: pending tenant-local profile lock
- Bundle digest: `NOT_RUN_ENV_UNAVAILABLE`
- Release digest: `NOT_RUN_ENV_UNAVAILABLE`
- Target: tenant-controlled, pre-existing, zero-incremental-cost capacity only

## Journey ledger

| Stage | Expected evidence | Offline Phase-0 state |
| --- | --- | --- |
| Questionnaire | Complete declared answers | `FIXTURE_VALIDATED` |
| Business context | Owners, outcomes, KPI definitions | `FIXTURE_VALIDATED` |
| Domain context | Ontology, mapping, coverage digests | `FIXTURE_VALIDATED` |
| Data readiness | Ten ordered gates with evidence references | `FIXTURE_VALIDATED` |
| Profile lock | Exact five-harness selection and digest | `FIXTURE_VALIDATED` |
| Bundle build | Selected-only digest-addressed OCI closure | `NOT_RUN_ENV_UNAVAILABLE` |
| Signature/release | Tenant-scoped trust verification | `NOT_RUN_ENV_UNAVAILABLE` |
| Preflight | Platform, architecture, capacity, storage, network, sandbox | `NOT_RUN_ENV_UNAVAILABLE` |
| Apply | Server-side apply receipts and generation | `NOT_RUN_ENV_UNAVAILABLE` |
| Runtime health | Target-local probes | `NOT_RUN_ENV_UNAVAILABLE` |
| Evidence freshness | Current source cursors and assurance | `NOT_RUN_ENV_UNAVAILABLE` |

## Evidence boundary

Record SOURCE, CONTRACT_UNIT, PR_CHECK, MERGE, ARTIFACT_SBOM, SIGNATURE_RELEASE, DEPLOYMENT, RUNTIME, SECURITY, ASSURANCE, TENANT_ACCEPTANCE_CANDIDATE, and TENANT_ACCEPTANCE separately. Campaign output cannot sign or assert TENANT_ACCEPTANCE. A structural evidence-verification pass does not upgrade any unavailable runtime or assurance result.

## Manual authority required

Environment-facing execution is permitted only after the external trusted launcher validates the dual-signed envelope, exact endpoints, independent capacity authorization, server-side zero-cost admission, and target-local credentials. Otherwise preserve `NOT_RUN_ENV_UNAVAILABLE`.
