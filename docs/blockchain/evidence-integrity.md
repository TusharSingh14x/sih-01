# Evidence integrity

The contract stores a hashed evidence identifier, SHA-256 evidence digest, hashed
custodian and block timestamps. It never receives filenames, file bytes, host
payloads, human-readable identities or report contents. Hash commitments are not
encryption and may permit guessing of low-entropy identifiers.

Registration hashes the actual stored bytes and compares the result with the
collection metadata before submitting. Duplicate successful API registrations
return the original record. The contract itself rejects duplicate identifiers.
Verification compares four values: current object bytes, contract/mock digest,
registration-row digest and collection digest. All must agree for VERIFIED.
Any difference produces MISMATCH. Missing storage/chain connectivity yields an
error, never VERIFIED or an invented mismatch. Verification records are dated.

Investigation batches use `jocky-merkle-sha256-v1`: manifest entries are sorted
by evidence ID and canonicalized JSON; leaves use SHA-256 with a `0x00` prefix,
parent nodes use a `0x01` prefix, and an unpaired final node is duplicated. Only
the root is registered under a batch identifier; bytes and the manifest remain
in storage. The API returns inclusion proofs and recomputes the full manifest
from current object bytes during batch verification. In mock mode this tests the
workflow only; it is not an independent blockchain attestation.

The downloaded JSON manifest can be checked without a running JOCKY backend:
`python scripts/verify_merkle_manifest.py manifest.json --root <registry-root>`.
To also compare a local evidence file, add `--evidence-id <id> --file <path>`.

The contract registrar is immutable. Only that address may register or transfer;
the contract checks the expected previous custodian. Backend identities, role
checks and registrar custody are part of the trust boundary. Ganache uses unlocked
development accounts; do not expose its RPC publicly or use it for real assets.

## Local EVM setup

1. Set `BLOCKCHAIN_RPC_URL=http://ganache:8545` for local Ganache or the
   provider's HTTPS endpoint for a testnet, and set the desired chain ID.
2. Run `docker compose up -d ganache` (skip this for a public testnet).
3. Run `npm --prefix blockchain ci` and `npm --prefix blockchain run deploy`
   with the same RPC and signer settings.
4. Set `BLOCKCHAIN_MOCK=false`, `BLOCKCHAIN_CONTRACT_ADDRESS` and
   `BLOCKCHAIN_ACCOUNT` to deployment output. Set `BLOCKCHAIN_ABI_PATH` to the
   deployment.json file for a non-Docker backend.
5. Run `docker compose up -d --build backend`.

Use separate workspaces/databases for mock and EVM evidence. Changing modes cannot
convert an existing mock commitment into real attestation. Tests use both the
Python mock and an in-process Ganache EVM with unauthorized/replay attempts.

## Public EVM testnet (for example, Sepolia)

The EVM adapter supports a locally held signing key for hosted RPC providers.
Copy `.env.example` to `.env` (never commit `.env`) and set `BLOCKCHAIN_MOCK=false`,
`BLOCKCHAIN_RPC_URL`, `BLOCKCHAIN_CHAIN_ID`, and `BLOCKCHAIN_PRIVATE_KEY`. Keep
the account address that corresponds to that key in `BLOCKCHAIN_ACCOUNT` if you
want an explicit mismatch check. Fund that testnet account with faucet test ETH
only. The key must belong to the contract registrar; otherwise registrations
will revert. The deployment script checks the RPC chain ID against the configured
one before deploying. Run `npm --prefix blockchain ci` and then
`npm --prefix blockchain run deploy` with the same testnet settings. Put the
printed contract address in `.env`, set `BLOCKCHAIN_ABI_PATH=/app/blockchain/deployment.json`
for Compose, and rebuild the backend. Verify a test evidence item and confirm
the dashboard labels the registry EVM. Do not use a mainnet key or real funds.

The backend signs transactions locally with the private key. Keep it only in the
ignored local `.env` or a secrets manager; never paste it into chat, source code,
logs, screenshots, or a video. Existing mock registry rows are not converted to
testnet records; create fresh evidence after switching modes.
