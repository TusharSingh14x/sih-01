# SIH prototype walkthrough

## Live dashboard flow

1. Start the local stack and sign in with the development analyst account shown
   in the root README.
2. In **Agents**, confirm `demo-agent` is online. It is a Linux container for
   demonstrating the workflow; it is not the host Mac or a second real endpoint.
3. Create an investigation and select the demo agent. In **Jobs**, schedule
   system information, driver inventory, process list, network connections, and
   recent system logs. Some container log facilities may be unavailable; the
   job reports that as a collection error rather than inventing data.
4. After jobs complete, show evidence hashes in **Evidence** and review the
   rule-generated findings in **Findings**. Rules are triage indicators that
   require analyst review.
   Open an investigation for machine comparison, collection provenance, and its
   event timeline across jobs, evidence, and findings.
5. In **Blockchain**, register an individual evidence hash, then create and
   verify a Merkle batch. Explain whether the current registry is marked
   **MOCK / simulated** or **EVM**.
6. Generate and download the investigation PDF from **Reports**.

## Integrity demonstration

Run `python scripts/demo_e2e.py` from the repository root. This creates a
separate temporary workspace containing synthetic machines and evidence. It
shows automatic findings, valid Merkle inclusion proofs, successful verification
before a synthetic evidence change, and mismatch after the change. It writes a
PDF under `output/pdf/demo-report.pdf`; it does not modify the dashboard's data.

## Claims to make accurately

- JOCKY collects bounded, read-only host telemetry through named agent jobs and
  analyzes it with explainable local rules and offline indicators.
- SHA-256 establishes whether stored bytes still match their registered digest.
  A Merkle proof establishes membership in a committed evidence batch.
- These checks do not prove a host reported the truth or captured everything.
- A collection manifest hash binds the evidence digest to recorded endpoint,
  capability, version and time metadata; it is not an agent digital signature.
- Compose uses a persistent local **mock registry**. Call its results a
  simulation. EVM mode demonstrates the existing contract on local Ganache.
- The prototype detects selected suspicious indicators; it is not a full AV/EDR
  replacement, not a malware verdict engine, and not a production evidence
  acquisition product.
