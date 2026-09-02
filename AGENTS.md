# Sol-High Execution Rules

1. Implement exactly one task packet from the public `harness-onion` authority per coding run and pull request.
2. Touch only the packet's `allowedPaths`; `CONF-001` alone owns `Makefile`, `ci/run_make_target.py`, and the inert `PORTING.yaml` ledger.
3. Read and honor every predecessor contract and source lock before editing.
4. Never open or modify a warm-start repository during product implementation. Recorded warm-source paths are historical reference-only provenance unless a future authority explicitly grants `COPY_AUTHORIZED` with an exact mapping.
5. Do not introduce cloud provisioning, hosted runners, paid APIs, API-key requirements, runtime downloads, mutable artifact references, or external telemetry defaults.
6. Run acceptance only through the root-owned signed `/opt/planeon/bin/harness-offline-launch`, with a hash-pinned packet, direct argv, prefetch first, and OS-enforced deny-all outbound isolation in one process tree.
7. Preserve source, CI, merge, artifact, deployment, runtime, assurance, and tenant acceptance as separate evidence states.
8. Use a `codex/<packet-id>-<slug>` branch, open a pull request, monitor the required self-hosted checks, apply bounded fixes, and merge only when every required check is green.
9. Stop when a missing decision would change a public contract, tenant isolation, destructive-data behavior, licensing disposition, or billing boundary.
10. CI may use only the pinned credential-free checkout and the preinstalled trusted launcher. The ephemeral self-hosted runner must have no ambient cloud credentials, SSH agent, kubeconfig, container socket, or billable broker.
11. Never run a live campaign directly or from CI. Live execution is manual and post-merge through only the independently installed `/opt/planeon/bin/harness-live-campaign-launch` under its dual-signed envelope, trust, capacity, admission, and endpoint boundary.
12. The repository-side live adapter has no pre-boundary authority, cannot install or substitute the launcher, and must fail when invoked outside the externally established live session.
13. Only `CONF-001` may seed `Makefile`, `ci/run_make_target.py`, and `PORTING.yaml`; later packets add only their packet-owned descriptors or campaign paths.
14. A conformance result is exactly `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, or `NOT_RUN_ENV_UNAVAILABLE`. Missing authority or environment never becomes pass.
15. A campaign may emit an unsigned `TENANT_ACCEPTANCE_CANDIDATE`; it may never sign, originate, or claim `TENANT_ACCEPTANCE`.
