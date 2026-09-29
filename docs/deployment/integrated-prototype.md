# Integrated local deployment

Requirements: Docker Compose, or Python 3.11+, Node 22+, Rust 1.88; clang for
native executable generation. Use the repository root as working directory.

```sh
docker compose up --build -d
```

Open http://localhost:5173 and log in with analyst@jocky.local / jocky-demo.
API: http://localhost:8000/docs. The backend image builds and installs the Rust
CLI, applies Alembic migrations and supports the web editor. Default registry
mode is mock. PostgreSQL, S3-compatible object storage and mock-chain state use
named volumes. Ganache RPC binds localhost:8545. Do not delete volumes containing
real evidence. Compose credentials are development-only.

The Compose agent collects system information, process inventory, network
connections, loaded drivers/kernel modules, and bounded recent platform logs.
Schedule `process.modules:<pid>` through the Jobs API when a specific process
needs module inventory. The agent accepts only these named read-only jobs; it
does not execute arbitrary scripts. Evidence intake runs the bounded triage rules
and optional local indicator file at `backend/config/iocs.json`. Keep the IOC
file operator-managed and offline.

In Blockchain, register an evidence item or create an investigation batch. The
batch page shows the SHA-256 Merkle root, inclusion proof checks, transaction
identifier, and whether the registry is a mock simulation or local EVM. Edit
`backend/config/iocs.json` with the schema in `backend/config/iocs.example.json`
and the backend reads updated contents when each evidence payload arrives.

## Without Docker

```sh
python -m pip install -r backend/requirements.txt
npm --prefix frontend ci
npm --prefix blockchain ci
cargo build -p jocky-cli
```

Set `JOCKY_CLI` to the absolute path of target/debug/jocky-cli (Windows: .exe).
For the backend set DATABASE_URL=sqlite:///./jocky.db, BLOCKCHAIN_MOCK=true and
STORAGE_BACKEND=local. Run `python -m uvicorn app.main:app --app-dir backend`
and `npm --prefix frontend run dev`. For existing deployments run
`cd backend` then `python -m alembic upgrade head` before startup. A compatibility
check also adds the nullable registry reference to old local SQLite schemas.

With the same DATABASE_URL, `python scripts/create_user.py recipient@example.test`
provisions another analyst for custody transfers. Add `--role admin` for the audit
viewer. Passwords are prompted, not passed in command-line arguments. Provisioning
requires local database access; there is no public self-registration endpoint.

## Demo and tests

`python scripts/demo_e2e.py` creates an isolated temporary workspace with
synthetic evidence across three machines. It demonstrates automatic process and
network findings, Merkle inclusion proofs, individual hash verification, batch
verification before and after a synthetic evidence change, and PDF generation.
It does not seed or alter your running server. Browser E2E tests use their own
mock records.

`make setup/test/lint/build/docker/demo` provides shortcuts (GNU Make required).
Without Make use the corresponding commands in the root Makefile. CI runs Rust
on Linux/Windows, native LLVM parity, Python tests/demo, frontend build/unit/E2E,
Solidity contract tests, and a Docker Compose smoke test.
