# Public Vercel showcase

The Vercel build is a static, read-only showcase. It ships synthetic Windows and
Ubuntu fixtures in the frontend bundle and has no backend URL, login, endpoint
agent, or real blockchain connection. Its integrity toggle is visual simulation
only; do not present it as an on-chain transaction or live host collection.

## Deploy

1. Import the repository into Vercel and set the project root to `frontend/`.
2. Use the Vite preset (the repository includes `frontend/vercel.json`).
3. Add the environment variable `VITE_DEMO_MODE=true` for Preview and Production.
4. Deploy. No RPC URL, wallet key, backend credential, or evidence secret belongs
   in Vercel frontend environment variables.

To build the same showcase locally:

```sh
cd frontend
VITE_DEMO_MODE=true npm run build
```

For the real local prototype, leave `VITE_DEMO_MODE` unset and run Docker
Compose. Do not expose the development Compose API or demo credentials publicly.
The backend, database, object store, and authorized endpoint agents require a
separately secured host if a live online backend is ever needed.

## Platform validation before judging

The showcase's Windows and Ubuntu endpoints are explicitly synthetic. Before
claiming operating-system support, run the signed/reproducible agent build in
isolated Windows and Ubuntu VMs with harmless known fixtures and record, for each
capability, the OS version, agent build, success/failure, collection duration,
and evidence digest. Never test on a third-party or production endpoint. Do not
describe the current Linux Docker agent as a Windows endpoint.

## Synthetic rules check

Run `python scripts/detection_benchmark.py` to check four tiny labeled fixtures.
The output is a rule regression check, not a precision/recall claim about real
systems. A credible performance evaluation needs a larger, independently
reviewed labeled dataset and documented false-positive analysis.
