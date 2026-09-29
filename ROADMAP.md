# JOCKY roadmap and release boundaries

## Working prototype scope

- Rust DSL pipeline, interpreter, LLVM native entrypoint and forensic stdlib.
- Deterministic mock collection and cautious rule-based runtime findings.
- Authenticated case/job/evidence/report APIs and multi-machine scheduling.
- Hash-only Solidity registry, Web3 client, persistent mock registry.
- Custody ownership checks, findings CRUD, audit trail, PDF snapshots.
- Dashboard registry/custody/findings/case comparison and local Monaco editor.
- Isolated tamper-detection demo and automated integration tests.
- Agent-side process ancestry/path/command-line, network endpoint ports, loaded
  driver inventories, and bounded recent event-log collection for Windows/Linux.
- Automatic explainable triage findings at evidence intake, with optional
  operator-managed offline IP/hash/driver indicators.
- Versioned SHA-256 Merkle manifests, inclusion proofs, and registry-backed batch
  root verification; the Compose default is visibly labelled as simulation.
- CI release artifacts for Linux and Windows agents (unsigned development builds).

## Required before production

- Durable blockchain transaction intents, receipt reconciliation, confirmations
  and reorg recovery; production signer custody/HSM and registrar governance.
- Per-agent mTLS/enrollment, case access policies, tenant isolation and SSO/MFA.
- External append-only audit retention, encrypted evidence and retention policy.
- Shared rate limiting, request quotas, isolated editor workers and load testing.
- Independently audited contracts, dependency remediation and legal validation
  of acquisition/custody procedures. Production EVM operator instead of Ganache.
- Broader artifact parsers, signed collection manifests, evidence export bundles,
  native packaging, fuzzing and supported-platform release matrix.

No compiler or forensic product can be declared permanently finished. This
roadmap distinguishes a usable prototype from operational/security guarantees.
