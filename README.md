# Planeon Harness Conformance Labs

This public repository is reserved for the Planeon multi-agent harness platform's reusable offline conformance kit and deployment-certification campaigns.

`CONF-001` provides the dependency-free `harness-conformance` CLI, deterministic declarative campaign engine, technical-evidence bundles, strict result semantics, and the reproducible candidate for the separately installed trusted live-campaign launcher. Later packets add parity and platform campaigns without changing the bootstrap dispatcher.

No hosted runtime, cloud resource, paid API, API key, remote telemetry, or billable package service is required. Missing local target authority or capacity is reported as `NOT_RUN_ENV_UNAVAILABLE`, never as a pass or an online fallback.

## Offline development

Use CPython 3.12 and the immutable local tool inventory declared in `toolchain.lock`. The lock has no third-party package dependency.

```text
make prefetch
make meta-conformance
make build-reproducible
make zero-bill
make acceptance-package-contract
```

GitHub acceptance is intentionally queued until a fresh credential-free self-hosted runner is attached. Repository code cannot install or directly invoke a live launcher.
