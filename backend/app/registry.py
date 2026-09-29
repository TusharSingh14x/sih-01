import os
from functools import lru_cache
from pathlib import Path
import sys

# Supports both `uvicorn --app-dir backend` and the root-context Docker image.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from blockchain.client import BlockchainClient, MockBlockchainClient


@lru_cache
def get_blockchain():
    if os.getenv("BLOCKCHAIN_MOCK", "true").lower() == "true":
        return MockBlockchainClient(os.getenv("BLOCKCHAIN_MOCK_DB", "./mock-chain.db"))
    return BlockchainClient(os.environ["BLOCKCHAIN_RPC_URL"], os.environ["BLOCKCHAIN_CONTRACT_ADDRESS"],
                            os.environ["BLOCKCHAIN_ABI_PATH"], os.getenv("BLOCKCHAIN_ACCOUNT"),
                            os.getenv("BLOCKCHAIN_PRIVATE_KEY"))
