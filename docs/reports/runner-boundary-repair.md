# CONF-FIX-001 — Alpha 2 runner-boundary repair

Status at publication preparation: local source checks PASS; PR CI and merge
remain separate pending gates. No Linux PASS is inferred.
Authority: MET-REPAIR-003, meta main
`7047ec93170d5db8a148d1f6cfd34ad7877fb423`; packet SHA-256
`b02d7c6f2872c61fbde5be10451ac8de08e8336ee032e85b468e40dfaf8790ac`.
Product base: CONF-A1-001 main `30877d289d389b29d3da9eb9a3c083c9ebc33382`.
All inherited wrapper/runner/canary/live-adapter/parity pins matched the approved
source-inspection amendment. No warm-source or predecessor checkout was used
by product execution; sourceReuse is empty.

## Changes and boundaries

- R2: execute the packet's four independent unittest discovery roots: meta,
  parity, alpha1, runner-boundary. The inventory test compares recursive file
  and AST method inventories with actual collected TestCase instances, rejects
  zero/failed discovery, omitted or duplicate methods/modules, skip/xfail
  masking, and preserves all 60 legacy test IDs from eleven existing modules.
  Added modules are discovered dynamically; an unimportable nested module
  cannot become an unnoticed exclusion. Legacy imports/vectors are unchanged;
  the single allowed parity mock now explicitly models Darwin.
- R3: wrapper and executor match actual OS to exactly darwin-sandbox or
  linux-firejail. The new fixed run_packet_argv.py bridge delegates the same
  argv to run_packet.py without a shell string or additional process. The
  host launcher remains the only boundary-establishing authority.
- R3: packet children receive a closed environment allowlist, not caller copies.
  PYTHONPATH is derived solely from this checkout's src directory; caller
  import paths, unknown fields, credentials and authority paths are absent.
  Root-owned no-follow packet custody, bounded nonblocking reads, descriptor
  lifetime, phase ordering and post-command digest checks are retained/hardened.
- R3: only EPERM/EACCES at Firejail socket creation or Darwin connect proves
  the declared backend. Missing/mismatched markers, wrong-stage denial,
  successful socket/connect, route failure, DNS, timeout, and unsupported
  protocols/families fail. Real probes run only inside trusted OS isolation;
  cross-OS variants use fake sockets and are SOURCE_ONLY evidence.
- R4: repository live adapter always refuses DIRECT_LIVE_ADAPTER_FORBIDDEN.
  It imports no subprocess/OS/socket interface and never consumes a descriptor
  or opens credentials. Unit tests cover forged file/pipe descriptors, arbitrary
  argv and removed CI markers. memfd is exercised only where the OS supports
  it; Darwin does not supply native memfd evidence. No live command is executed.

Makefile, dispatcher, existing descriptors, workflow, toolchain, PORTING, public
schemas/models, campaign outputs and every other existing test remain unchanged.
No dependency, root code, key, live session protocol, capacity or billable API
was added. The unchanged Linux kit binds its three fixed transport paths and
the whole source tree; this bridge is not a native installation or qualification.

## Baseline reproduction and acceptance

The separately approved external OPERATOR-RUNNER-002 policy extension was
installed and freshly verified before this product run. Installed self-check,
safe retry, invalid request rejection and OS-denial probes passed. Routine
activation remains signed/data-only; this PR contains no privileged installer.

Exact-base replay under the new stdlib-only profile reached the original
canary and then failed meta-suite imports: 10 unittest entries, seven errors,
ModuleNotFoundError for harness_conformance. This reproduced missing own-source
import setup; it does not invalidate earlier differently configured packet
evidence. Baseline log SHA-256:
`7cce55a6c0fc59e02c7348631535907a24a945f56504eb9b4fdbd37d547323b5`.
The runner now provides its own derived source import path within isolation.

Acceptance is exclusively the signed external host launcher invoking the exact
packet wrapper and its four declared direct-argv commands in one deny-all
outbound process tree. Record test counts per root and retain failed attempts.
Inventory checks collect but do not execute another copy of predecessor tests.
Required self-hosted PR checks, merge and exact-main replay are separate gates.

First corrected signed source replay: `787b946e1bd3675a36e59eb4d44bf039aeb3186f`,
83 tests passed (meta 37, parity 14, alpha1 9, runner-boundary 23), no skips.
Every suite inventory closed and the replay's tracked files remained unchanged.
Log SHA-256: `de1d2fa4f22636b580c0d9ebfdf5abc0681e7e9f4d303fa425c5971dd7b7a7f9`.
Publication documentation is rechecked on the final candidate before PR dispatch.
The PR closure record must bind final head, accepted CI job/run, merge SHA and
exact-main replay separately; this pre-merge report cannot certify its own merge.

| Evidence axis | Current state |
| --- | --- |
| Source implementation | PASS at the source commit above |
| Local signed-head acceptance | PASS: 83 tests, full legacy inventory |
| Required self-hosted PR CI | WAITING |
| Merge / exact-main | WAITING / WAITING |
| Native Linux / usable external live backend | NOT_RUN_ENV_UNAVAILABLE / NOT_RUN_ENV_UNAVAILABLE |
| Artifact/release, deployment/runtime, assurance, tenant acceptance | NOT_RUN by this corrective packet |

## Roadmap and retained gaps

| Phase | ID | Status | Description |
| --- | --- | --- | --- |
| Operator prerequisite | OPERATOR-RUNNER-002 | DONE externally | Exact repository/profile admission and fresh installed verification |
| Alpha 2 correction | CONF-FIX-001 | ONGOING | This scoped runner/discovery/live-adapter correction |
| Alpha 2 qualification | CONF-LINUX-001 | WAITING | Corrective closure, test-authority repair, native Linux evidence |
| Alpha 1/2 integration | CTRL-INTEGRATE-001 / MODEL-001 / EXEC-001 / RUN-001 | WAITING | Fresh native AMD64 gate |
| Alpha 4 | Full conformance / tenant acceptance | WAITING | Independent release and tenant qualification |

CONF-LINUX-001 still needs bounded ownership for the existing exact handler-count
regression before its future handler addition. Main-branch protection was absent
in prior operator preflight; no repository setting is changed here. Neither
gap authorizes a change outside this packet. No phase/model-effort transition.

Rollback only unconsumed changes within this packet. Never restore the unsafe
live path as an operational fallback. Keep failed logs, signatures and evidence;
any installed-host recovery requires its own operator custody and fresh probes.
